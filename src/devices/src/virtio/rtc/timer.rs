// Copyright 2026 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The timer that wakes the device when an alarm expires.
//!
//! A single `timerfd` on `CLOCK_REALTIME` serves all alarms: it is armed
//! for the earliest enabled alarm, with an absolute time, and with
//! `TFD_TIMER_CANCEL_ON_SET`, so that a step of the realtime clock makes
//! reading it fail with `ECANCELED`. The device then compares the alarms
//! with the new time. The timer fd is registered with the event manager
//! like the queue events; no thread is involved.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const NSEC_PER_SEC: u64 = 1_000_000_000;

/// What reading the timer reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TimerEvent {
    /// The time that the timer was armed for was reached.
    Expired,
    /// The realtime clock was set while the timer was armed.
    Canceled,
}

#[derive(Debug)]
pub(crate) struct AlarmTimer {
    fd: OwnedFd,
}

impl AlarmTimer {
    pub fn new() -> io::Result<Self> {
        // SAFETY: timerfd_create has no memory safety requirements.
        let fd = unsafe {
            libc::timerfd_create(libc::CLOCK_REALTIME, libc::TFD_NONBLOCK | libc::TFD_CLOEXEC)
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a new, valid file descriptor that nothing else owns.
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    /// Arms the timer for the absolute `CLOCK_REALTIME` time `time_ns`.
    ///
    /// Fails with `ECANCELED` if the realtime clock was set while arming;
    /// the caller has to evaluate its alarms against the new time and try
    /// again.
    pub fn arm(&self, time_ns: u64) -> io::Result<()> {
        // A zero time would disarm the timer. Time 1 ns is long in the past.
        let time_ns = time_ns.max(1);
        let value = libc::timespec {
            tv_sec: (time_ns / NSEC_PER_SEC) as libc::time_t,
            tv_nsec: (time_ns % NSEC_PER_SEC) as _,
        };
        self.settime(
            value,
            libc::TFD_TIMER_ABSTIME | libc::TFD_TIMER_CANCEL_ON_SET,
        )
    }

    pub fn disarm(&self) -> io::Result<()> {
        let value = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        self.settime(value, 0)
    }

    fn settime(&self, value: libc::timespec, flags: libc::c_int) -> io::Result<()> {
        let spec = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: value,
        };
        // SAFETY: `spec` is valid for the duration of the call, and the old
        // value is not requested.
        let ret = unsafe {
            libc::timerfd_settime(self.fd.as_raw_fd(), flags, &spec, std::ptr::null_mut())
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Consumes a pending timer event. Returns `None` if there is none.
    pub fn read(&self) -> io::Result<Option<TimerEvent>> {
        let mut expirations: u64 = 0;
        // SAFETY: the buffer is valid for the 8 bytes that are read.
        let ret = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                (&mut expirations as *mut u64).cast(),
                size_of::<u64>(),
            )
        };
        if ret == size_of::<u64>() as isize {
            return Ok(Some(TimerEvent::Expired));
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EAGAIN) => Ok(None),
            Some(libc::ECANCELED) => Ok(Some(TimerEvent::Canceled)),
            _ => Err(err),
        }
    }
}

impl AsRawFd for AlarmTimer {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::*;

    fn now_ns() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    fn wait_readable(timer: &AlarmTimer, timeout: Duration) -> bool {
        let mut pfd = libc::pollfd {
            fd: timer.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pfd` is valid for the duration of the call.
        unsafe { libc::poll(&mut pfd, 1, timeout.as_millis() as libc::c_int) > 0 }
    }

    #[test]
    fn unarmed_timer_has_no_event() {
        let timer = AlarmTimer::new().unwrap();
        assert_eq!(timer.read().unwrap(), None);
    }

    #[test]
    fn timer_expires_at_the_absolute_time() {
        let timer = AlarmTimer::new().unwrap();
        timer.arm(now_ns() + 30_000_000).unwrap();
        assert_eq!(timer.read().unwrap(), None);
        assert!(wait_readable(&timer, Duration::from_secs(5)));
        assert_eq!(timer.read().unwrap(), Some(TimerEvent::Expired));
        assert_eq!(timer.read().unwrap(), None);
    }

    #[test]
    fn time_in_the_past_expires_at_once() {
        let timer = AlarmTimer::new().unwrap();
        timer.arm(1).unwrap();
        assert!(wait_readable(&timer, Duration::from_secs(5)));
        assert_eq!(timer.read().unwrap(), Some(TimerEvent::Expired));
    }

    #[test]
    fn time_zero_is_treated_as_the_past() {
        let timer = AlarmTimer::new().unwrap();
        timer.arm(0).unwrap();
        assert!(wait_readable(&timer, Duration::from_secs(5)));
        assert_eq!(timer.read().unwrap(), Some(TimerEvent::Expired));
    }

    #[test]
    fn disarmed_timer_does_not_expire() {
        let timer = AlarmTimer::new().unwrap();
        timer.arm(now_ns() + 30_000_000).unwrap();
        timer.disarm().unwrap();
        assert!(!wait_readable(&timer, Duration::from_millis(100)));
        assert_eq!(timer.read().unwrap(), None);
    }

    #[test]
    fn far_future_time_can_be_armed() {
        let timer = AlarmTimer::new().unwrap();
        timer.arm(u64::MAX).unwrap();
        assert_eq!(timer.read().unwrap(), None);
    }
}
