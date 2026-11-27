use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::{io, thread};

use utils::eventfd::EventFd;
use vm_memory::{GuestMemoryBackend, GuestMemoryError, GuestMemoryMmap, GuestMemoryRegion};

use crate::virtio::console::port_io::PortOutput;
use crate::virtio::{DescriptorChain, InterruptTransport, Queue};

/// Outcome of a TX worker's run.
pub(crate) enum TxExit {
    /// Told to stop (real VM shutdown): the output was fully drained and
    /// the worker is exiting for good.
    Stopped(Queue),
    /// Told to pause (guest-initiated port close while the VM keeps
    /// running): the worker stopped promptly without draining further,
    /// handing back the queue so it can be held by the port and reused
    /// when the guest reopens it. At most the descriptor chain that was
    /// actively being written when the pause was requested may be
    /// incompletely written; every other queued descriptor is untouched.
    Paused(Queue),
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn process_tx(
    mem: GuestMemoryMmap,
    mut queue: Queue,
    interrupt: InterruptTransport,
    output: Arc<Mutex<Box<dyn PortOutput + Send>>>,
    stop: Arc<AtomicBool>,
    pausefd: EventFd,
    pause: Arc<AtomicBool>,
) -> TxExit {
    loop {
        let Some(head) = pop_head_blocking(&mut queue, &mem, &interrupt, &stop, &pause) else {
            return if stop.load(Ordering::Acquire) {
                TxExit::Stopped(queue)
            } else {
                TxExit::Paused(queue)
            };
        };

        let head_index = head.index;
        let mut bytes_written = 0;
        let mut paused = false;

        for desc in head.into_iter().readable() {
            let desc_len = desc.len as usize;
            match write_desc_to_output(
                desc,
                output.lock().unwrap().as_mut(),
                &interrupt,
                &pausefd,
                &pause,
            ) {
                // `Ok(0)` is only ever returned when `write_desc_to_output`
                // gave up because `pause` became true; fall through to the
                // pause check below instead of breaking blind to it, or the
                // descriptor gets pushed back via `undo_pop()` and popped
                // again forever (livelock, and `TxExit::Paused` never gets
                // returned so `pause()`'s `join()` hangs).
                Ok(0) => {}
                Ok(n) => {
                    assert_eq!(n, desc_len);
                    bytes_written += n;
                }
                Err(e) => {
                    log::error!("Failed to write output: {e}");
                    if matches!(e, GuestMemoryError::IOError(e) if e.kind() == io::ErrorKind::BrokenPipe)
                    {
                        // Errors could conceivably be spurious. Broken
                        // pipe is not and there is no point in attempting
                        // to write more.
                        return TxExit::Stopped(queue);
                    }
                }
            }

            if pause.load(Ordering::Acquire) {
                // The port is being paused and the output sink is still
                // not writable: don't keep blocking the caller trying to
                // drain the rest of this chain, drop whatever remains
                // unwritten in this descriptor instead. Real VM shutdown
                // never sets `pause`, so this cannot trigger during
                // shutdown draining.
                paused = true;
                break;
            }
        }

        if bytes_written == 0 {
            log::trace!("Tx Add used {bytes_written}");
            queue.undo_pop();
        } else {
            log::trace!("Tx add used {bytes_written}");
            if let Err(e) = queue.add_used(&mem, head_index, bytes_written as u32) {
                error!("failed to add used elements to the queue: {e:?}");
            }
        }

        if paused {
            return TxExit::Paused(queue);
        }
    }
}

fn pop_head_blocking<'mem>(
    queue: &mut Queue,
    mem: &'mem GuestMemoryMmap,
    interrupt: &InterruptTransport,
    stop: &AtomicBool,
    pause: &AtomicBool,
) -> Option<DescriptorChain<'mem>> {
    loop {
        match queue.pop(mem) {
            Some(descriptor) => break Some(descriptor),
            None => {
                interrupt.signal_used_queue();
                if stop.load(Ordering::Acquire) || pause.load(Ordering::Acquire) {
                    break None;
                }
                thread::park();
                log::trace!("tx unparked, queue len {}", queue.len(mem))
            }
        }
    }
}

fn write_desc_to_output(
    desc: DescriptorChain,
    output: &mut (dyn PortOutput + Send),
    interrupt: &InterruptTransport,
    pausefd: &EventFd,
    pause: &AtomicBool,
) -> Result<usize, GuestMemoryError> {
    // TODO: Switch to using `get_slices()` with the next vm-memory
    //       bump.
    #[allow(deprecated)]
    desc.mem
        .try_access(desc.len as usize, desc.addr, |_, len, addr, region| {
            let src = region.get_slice(addr, len).unwrap();
            loop {
                log::trace!("Tx {src:?}, write_volatile {len} bytes");
                // `pausefd` is the only cancellation signal passed here:
                // real VM shutdown must keep blocking until the sink
                // actually accepts the data, so that buffered output is
                // never silently dropped on exit.
                match output.write_volatile(&src, Some(pausefd)) {
                    // try_access seem to handle partial write for us (we will be invoked again with an offset)
                    Ok(n) => break Ok(n),
                    // We can't return an error otherwise we would not know how many bytes were processed before WouldBlock
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        log::trace!("Tx wait for output (would block)");
                        interrupt.signal_used_queue();
                        output.wait_until_writable(Some(pausefd));
                        if pause.load(Ordering::Acquire) {
                            // The port is being paused and the output is
                            // still not writable: give up on this
                            // descriptor rather than blocking indefinitely
                            // on a backpressured/non-responsive sink.
                            break Ok(0);
                        }
                    }
                    Err(e) => break Err(GuestMemoryError::IOError(e)),
                }
            }
        })
}
