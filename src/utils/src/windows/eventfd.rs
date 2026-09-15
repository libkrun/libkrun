//! Structure and wrapper functions emulating eventfd using a Windows manual-reset Event object.

use std::sync::{Arc, Mutex};
use std::{io, result};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{
    CreateEventW, INFINITE, ResetEvent, SetEvent, WaitForSingleObject,
};

use super::{AsRawFd, RawFd};

pub const EFD_NONBLOCK: i32 = 1;
pub const EFD_SEMAPHORE: i32 = 2;

#[derive(Debug)]
struct Inner {
    event: HANDLE,
    counter: Mutex<u64>,
    nonblock: bool,
    semaphore: bool,
}

// The HANDLE is a Windows kernel object usable from any thread.
unsafe impl Send for Inner {}
unsafe impl Sync for Inner {}

impl Drop for Inner {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.event);
        }
    }
}

#[derive(Clone, Debug)]
pub struct EventFd {
    inner: Arc<Inner>,
}

impl EventFd {
    pub fn new(flag: i32) -> result::Result<EventFd, io::Error> {
        let event = unsafe {
            CreateEventW(
                std::ptr::null(),
                1, // bManualReset = TRUE
                0, // bInitialState = FALSE (non-signaled)
                std::ptr::null(),
            )
        };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }

        Ok(EventFd {
            inner: Arc::new(Inner {
                event,
                counter: Mutex::new(0),
                nonblock: (flag & EFD_NONBLOCK) != 0,
                semaphore: (flag & EFD_SEMAPHORE) != 0,
            }),
        })
    }

    pub fn write(&self, v: u64) -> result::Result<(), io::Error> {
        let mut counter = self.inner.counter.lock().unwrap();

        let was_zero = *counter == 0;
        *counter = counter.saturating_add(v);

        // Only signal the event if it was not already signaled.
        if was_zero && unsafe { SetEvent(self.inner.event) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn read(&self) -> result::Result<u64, io::Error> {
        loop {
            {
                let mut counter = self.inner.counter.lock().unwrap();
                if *counter > 0 {
                    let result = if self.inner.semaphore {
                        // Semaphore mode: Decrement by 1
                        *counter -= 1;
                        1
                    } else {
                        // Standard mode: Drain the whole counter
                        let val = *counter;
                        *counter = 0;
                        val
                    };

                    if *counter == 0 {
                        unsafe {
                            ResetEvent(self.inner.event);
                        }
                    }
                    return Ok(result);
                }
                if self.inner.nonblock {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
            } // Lock is dropped here before blocking so writers can make progress!

            let ret = unsafe { WaitForSingleObject(self.inner.event, INFINITE) };
            if ret != WAIT_OBJECT_0 {
                return Err(io::Error::last_os_error());
            }
        }
    }

    pub fn try_clone(&self) -> result::Result<EventFd, io::Error> {
        Ok(EventFd {
            inner: Arc::clone(&self.inner),
        })
    }

    /// Waits up to `ms` milliseconds for the event to be signaled.
    ///
    /// Returns `true` if the event was signaled, `false` on timeout.
    /// On signal, consumes one unit (semaphore mode) or drains the counter
    /// (standard mode).  The kernel event is only reset when the counter
    /// reaches zero.
    pub fn wait_timeout(&self, ms: u32) -> bool {
        let result = unsafe { WaitForSingleObject(self.inner.event, ms) };
        if result == WAIT_OBJECT_0 {
            let mut counter = self.inner.counter.lock().unwrap();
            if *counter > 0 {
                if self.inner.semaphore {
                    *counter -= 1;
                } else {
                    *counter = 0;
                }
                if *counter == 0 {
                    unsafe {
                        ResetEvent(self.inner.event);
                    }
                }
            }
            true
        } else {
            false
        }
    }

    /// Returns `true` if the event is currently signaled (counter > 0)
    /// without consuming it.
    pub fn is_signaled(&self) -> bool {
        let counter = self.inner.counter.lock().unwrap();
        *counter > 0
    }
}

impl AsRawFd for EventFd {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.event
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_write() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        evt.write(55).unwrap();
        assert_eq!(evt.read().unwrap(), 55);
    }

    #[test]
    fn test_read_nothing_nonblock() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let res = evt.read();
        assert!(matches!(res, Err(err) if err.kind() == io::ErrorKind::WouldBlock));
    }

    #[test]
    fn test_multiple_writes_accumulate() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        evt.write(3).unwrap();
        evt.write(5).unwrap();
        assert_eq!(evt.read().unwrap(), 8);
    }

    /// After read() drains the counter to 0, the kernel event must be
    /// unsignaled.  If ResetEvent is missing, wait_timeout(0) would
    /// return true forever — the "infinite wakeup" bug.
    #[test]
    fn test_event_reset_after_read() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        evt.write(1).unwrap();
        assert_eq!(evt.read().unwrap(), 1);
        assert!(
            !evt.wait_timeout(0),
            "kernel event should be unsignaled after drain"
        );
    }

    /// Verify that writing after a full drain re-signals the event.
    #[test]
    fn test_write_read_cycle() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();

        evt.write(10).unwrap();
        assert_eq!(evt.read().unwrap(), 10);
        assert!(!evt.wait_timeout(0));

        evt.write(20).unwrap();
        assert_eq!(evt.read().unwrap(), 20);
        assert!(!evt.wait_timeout(0));
    }

    #[test]
    fn test_semaphore_mode() {
        let evt = EventFd::new(EFD_NONBLOCK | EFD_SEMAPHORE).unwrap();
        evt.write(3).unwrap();

        assert_eq!(evt.read().unwrap(), 1);
        assert_eq!(evt.read().unwrap(), 1);
        assert_eq!(evt.read().unwrap(), 1);

        let res = evt.read();
        assert!(matches!(res, Err(err) if err.kind() == io::ErrorKind::WouldBlock));
    }

    /// In semaphore mode, the kernel event must stay signaled as long as
    /// the counter is > 0, and only unsignal on the final decrement.
    #[test]
    fn test_semaphore_event_stays_signaled() {
        let evt = EventFd::new(EFD_NONBLOCK | EFD_SEMAPHORE).unwrap();
        evt.write(3).unwrap();

        assert_eq!(evt.read().unwrap(), 1); // counter: 3 -> 2
        assert!(
            evt.wait_timeout(0),
            "event should still be signaled with counter=2"
        );

        // wait_timeout consumed one (counter: 2 -> 1)
        assert!(
            evt.wait_timeout(0),
            "event should still be signaled with counter=1"
        );

        // wait_timeout consumed one (counter: 1 -> 0, ResetEvent)
        assert!(
            !evt.wait_timeout(0),
            "event should be unsignaled after full drain"
        );
    }

    #[test]
    fn test_wait_timeout_not_signaled() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        assert!(!evt.wait_timeout(0));
    }

    #[test]
    fn test_wait_timeout_signaled() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        evt.write(42).unwrap();
        assert!(evt.wait_timeout(0));
    }

    #[test]
    fn test_clone() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let evt_clone = evt.try_clone().unwrap();

        evt.write(923).unwrap();
        assert_eq!(evt_clone.read().unwrap(), 923);
    }
}
