//! Group commit of virtio-blk FLUSH requests for raw images.
//!
//! A write becomes stable once it has completed and a FLUSH sent after that
//! completion has completed (virtio-blk, "Device Operation"). A FLUSH is
//! therefore satisfied by any host sync that begins after the device popped
//! it, because every write the FLUSH must cover had already completed by then.
//!
//! The engine runs one host sync at a time on its own thread. Every FLUSH
//! handed to it while a sync is running waits for the next sync, which then
//! covers all of them. The length of the running sync is the batching window,
//! so no timer is involved.
//!
//! On macOS a durable sync (`F_FULLFSYNC`) of an image with dirty data costs
//! milliseconds while the writes themselves cost microseconds, and the device
//! used to stop serving its queue for that time. The engine syncs through its
//! own handle of the image file and takes neither the format lock nor the
//! storage lock, so the worker keeps serving reads and writes meanwhile. That
//! is only sound for raw images, whose format layer buffers no metadata that
//! would have to be written out before the sync.

use std::fs::File;
use std::io;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};

use utils::pollable_channel::{PollableChannelReciever, PollableChannelSender, pollable_channel};
use virtio_bindings::virtio_blk::{VIRTIO_BLK_S_IOERR, VIRTIO_BLK_S_OK};

/// How the host makes the image's completed writes stable, matching what the
/// image's storage layer does for a sync.
pub(crate) struct HostSync {
    file: File,
    /// `fsync(2)` instead of `F_FULLFSYNC`: the data reaches the drive, which
    /// is not asked to flush its own cache.
    #[cfg(target_os = "macos")]
    relaxed: bool,
}

impl HostSync {
    pub(crate) fn new(file: File, #[cfg(target_os = "macos")] relaxed: bool) -> Self {
        Self {
            file,
            #[cfg(target_os = "macos")]
            relaxed,
        }
    }

    fn sync(&self) -> io::Result<()> {
        #[cfg(target_os = "macos")]
        if self.relaxed {
            use std::os::fd::AsRawFd;
            loop {
                // SAFETY: the descriptor is owned by `self.file` and stays open for the call.
                if unsafe { libc::fsync(self.file.as_raw_fd()) } == 0 {
                    return Ok(());
                }
                let err = io::Error::last_os_error();
                if err.kind() != io::ErrorKind::Interrupted {
                    return Err(err);
                }
            }
        }
        // F_FULLFSYNC on macOS, fsync(2) on Linux, FlushFileBuffers on Windows.
        self.file.sync_all()
    }

    /// Starts an engine that syncs through a duplicate of this handle. A sync
    /// through any handle of the file covers writes made through the others.
    pub(crate) fn start(&self) -> io::Result<FlushEngine> {
        let host = Self {
            file: self.file.try_clone()?,
            #[cfg(target_os = "macos")]
            relaxed: self.relaxed,
        };
        FlushEngine::spawn(move || host.sync())
    }
}

/// FLUSH requests completed by one host sync, identified by the head index of
/// their descriptor chains, and the virtio status they complete with.
pub(crate) struct FlushCompletion {
    pub(crate) heads: Vec<u16>,
    pub(crate) status: u8,
}

/// The device side of a running flush engine.
pub(crate) struct FlushEngine {
    requests: mpsc::Sender<u16>,
    completions: PollableChannelReciever<FlushCompletion>,
    thread: JoinHandle<()>,
}

impl FlushEngine {
    fn spawn<S>(sync: S) -> io::Result<Self>
    where
        S: FnMut() -> io::Result<()> + Send + 'static,
    {
        let (requests, pending) = mpsc::channel();
        let (completed, completions) = pollable_channel()?;
        let thread = thread::Builder::new()
            .name("block flush".into())
            .spawn(move || run(pending, completed, sync))?;
        Ok(Self {
            requests,
            completions,
            thread,
        })
    }

    /// Hands a popped FLUSH to the engine. Returns the head back if the engine
    /// has exited, in which case nothing will ever complete it.
    pub(crate) fn submit(&self, head: u16) -> Result<(), u16> {
        self.requests.send(head).map_err(|err| err.0)
    }

    /// The channel of completed FLUSH requests, whose descriptor becomes
    /// readable when a completion is queued. A reader drains it fully on each
    /// wakeup, because one wakeup may stand for several completions.
    pub(crate) fn completions(&self) -> &PollableChannelReciever<FlushCompletion> {
        &self.completions
    }

    /// Stops accepting FLUSH requests and returns once the host sync in
    /// progress, if any, has returned. Completions not yet read are dropped.
    pub(crate) fn stop(self) {
        let Self {
            requests, thread, ..
        } = self;
        drop(requests);
        if thread.join().is_err() {
            error!("block flush thread panicked");
        }
    }
}

fn run<S>(
    pending: mpsc::Receiver<u16>,
    completed: PollableChannelSender<FlushCompletion>,
    mut sync: S,
) where
    S: FnMut() -> io::Result<()>,
{
    // `recv` fails once the device side has dropped its sender.
    while let Ok(first) = pending.recv() {
        let mut heads = vec![first];
        heads.extend(pending.try_iter());
        let status = match sync() {
            Ok(()) => VIRTIO_BLK_S_OK,
            Err(err) => {
                error!("host sync for {} FLUSH requests failed: {err}", heads.len());
                VIRTIO_BLK_S_IOERR
            }
        };
        let completion = FlushCompletion {
            heads,
            status: status.try_into().unwrap(),
        };
        if let Err(err) = completed.send(completion) {
            error!("failed to queue FLUSH completions: {err}");
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{Receiver, SyncSender};
    use std::time::{Duration, Instant};

    /// A host sync that reports each start and returns only when the test
    /// releases it with the result to return.
    fn gated_sync() -> (
        impl FnMut() -> io::Result<()> + Send + 'static,
        Receiver<()>,
        SyncSender<io::Result<()>>,
    ) {
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::sync_channel::<io::Result<()>>(0);
        let sync = move || {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap()
        };
        (sync, started_rx, release_tx)
    }

    fn next_completion(engine: &FlushEngine) -> FlushCompletion {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(completion) = engine.completions().try_recv().unwrap() {
                return completion;
            }
            assert!(Instant::now() < deadline, "no FLUSH completion within 5s");
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn assert_no_completion(engine: &FlushEngine) {
        thread::sleep(Duration::from_millis(20));
        assert!(engine.completions().try_recv().unwrap().is_none());
    }

    #[test]
    fn a_flush_submitted_during_a_sync_waits_for_the_next_one() {
        let (sync, started, release) = gated_sync();
        let engine = FlushEngine::spawn(sync).unwrap();

        engine.submit(1).unwrap();
        started.recv().unwrap();
        engine.submit(2).unwrap();
        release.send(Ok(())).unwrap();

        let first = next_completion(&engine);
        assert_eq!(first.heads, [1]);
        assert_eq!(first.status, VIRTIO_BLK_S_OK as u8);

        started.recv().unwrap();
        assert_no_completion(&engine);
        release.send(Ok(())).unwrap();
        assert_eq!(next_completion(&engine).heads, [2]);

        engine.stop();
    }

    #[test]
    fn flushes_queued_during_a_sync_share_the_next_one() {
        let (sync, started, release) = gated_sync();
        let engine = FlushEngine::spawn(sync).unwrap();

        engine.submit(1).unwrap();
        started.recv().unwrap();
        for head in [2, 3, 4] {
            engine.submit(head).unwrap();
        }
        release.send(Ok(())).unwrap();
        assert_eq!(next_completion(&engine).heads, [1]);

        started.recv().unwrap();
        release.send(Ok(())).unwrap();
        assert_eq!(next_completion(&engine).heads, [2, 3, 4]);

        // Two syncs covered four FLUSH requests.
        assert!(started.try_recv().is_err());
        engine.stop();
    }

    #[test]
    fn a_failed_sync_fails_every_flush_it_covers() {
        let (sync, started, release) = gated_sync();
        let engine = FlushEngine::spawn(sync).unwrap();

        engine.submit(1).unwrap();
        started.recv().unwrap();
        engine.submit(2).unwrap();
        engine.submit(3).unwrap();
        release.send(Ok(())).unwrap();
        next_completion(&engine);

        started.recv().unwrap();
        release.send(Err(io::Error::other("injected"))).unwrap();
        let failed = next_completion(&engine);
        assert_eq!(failed.heads, [2, 3]);
        assert_eq!(failed.status, VIRTIO_BLK_S_IOERR as u8);

        engine.stop();
    }

    #[test]
    fn stop_returns_after_the_running_sync() {
        let (sync, started, release) = gated_sync();
        let engine = FlushEngine::spawn(sync).unwrap();

        engine.submit(1).unwrap();
        started.recv().unwrap();
        let released = Arc::new(AtomicBool::new(false));
        let releaser = {
            let released = released.clone();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(50));
                released.store(true, Ordering::SeqCst);
                release.send(Ok(())).unwrap();
            })
        };
        engine.stop();
        // The running sync can only have returned after the releaser let it go.
        assert!(released.load(Ordering::SeqCst));
        releaser.join().unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn a_host_sync_through_a_duplicate_handle_completes_the_flush() {
        use std::io::{Read, Seek, Write};

        let backing = utils::tempfile::TempFile::new().unwrap();
        let host = HostSync::new(
            backing.as_file().try_clone().unwrap(),
            #[cfg(target_os = "macos")]
            false,
        );
        let engine = host.start().unwrap();

        let mut writer = backing.as_file().try_clone().unwrap();
        writer.write_all(b"stable").unwrap();
        engine.submit(7).unwrap();
        let completion = next_completion(&engine);
        assert_eq!(completion.heads, [7]);
        assert_eq!(completion.status, VIRTIO_BLK_S_OK as u8);

        let mut contents = String::new();
        let mut reader = backing.as_file().try_clone().unwrap();
        reader.rewind().unwrap();
        reader.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "stable");
        engine.stop();
    }
}
