// Copyright 2021 Sergio Lopez. All rights reserved.
//
// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;
use std::sync::Arc;

use bitflags::bitflags;
use log::debug;

fn event_name(filter: i16, flags: u16) -> &'static str {
    let eof = flags & libc::EV_EOF != 0;
    match filter {
        libc::EVFILT_READ => {
            if eof {
                "READ+EOF"
            } else {
                "READ"
            }
        }
        libc::EVFILT_WRITE => {
            if eof {
                "WRITE+EOF"
            } else {
                "WRITE"
            }
        }
        libc::EVFILT_TIMER => "TIMER",
        _ => "UNKNOWN",
    }
}

#[repr(i32)]
pub enum ControlOperation {
    Add,
    Modify,
    Delete,
}

bitflags! {
    pub struct EventSet: u32 {
        const IN = 0b00000001;
        const OUT = 0b00000010;
        const HANG_UP = 0b00000100;
        const READ_HANG_UP = 0b00001000;
        const EDGE_TRIGGERED = 0b00010000;
    }
}

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Kevent(libc::kevent);

// Safety: udata is used as an integer tag (cast from u64), never dereferenced.
// Needed because libc::kevent contains *mut c_void which is !Send, making
// Vec<Kevent> !Send which in turn makes Epoll !Send which is unwanted.
unsafe impl Send for Kevent {}

impl std::fmt::Debug for Kevent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{ ident: {}, data: {} }}", self.ident(), self.data())
    }
}

impl Default for Kevent {
    fn default() -> Self {
        Kevent(libc::kevent {
            ident: 0,
            filter: 0,
            flags: 0,
            fflags: 0,
            data: 0,
            udata: ptr::null_mut(),
        })
    }
}

impl Kevent {
    pub fn new(ident: usize, filter: i16, flags: u16, udata: u64) -> Self {
        Kevent(libc::kevent {
            ident,
            filter,
            flags,
            fflags: 0,
            data: 0,
            udata: udata as *mut libc::c_void,
        })
    }

    pub fn ident(&self) -> usize {
        self.0.ident
    }

    pub fn data(&self) -> isize {
        self.0.data
    }

    pub fn udata(&self) -> u64 {
        self.0.udata as u64
    }
}

#[derive(Clone, Copy, Default)]
pub struct EpollEvent {
    pub events: u32,
    u64: u64,
}

impl std::fmt::Debug for EpollEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{ events: {}, data: {} }}", self.events(), self.data())
    }
}

impl EpollEvent {
    pub fn new(events: EventSet, data: u64) -> Self {
        debug!("EpollEvent new: {data}");
        EpollEvent {
            events: events.bits(),
            u64: data,
        }
    }

    pub fn events(&self) -> u32 {
        self.events
    }

    pub fn event_set(&self) -> EventSet {
        // This unwrap is safe because `epoll_events` can only be user created or
        // initialized by the kernel. We trust the kernel to only send us valid
        // events. The user can only initialize `epoll_events` using valid events.
        EventSet::from_bits(self.events()).unwrap()
    }

    pub fn data(&self) -> u64 {
        debug!("EpollEvent data: {}", self.u64);
        self.u64
    }

    pub fn fd(&self) -> RawFd {
        self.u64 as i32
    }
}

#[derive(Debug)]
pub struct Epoll {
    queue: Arc<OwnedFd>,
    kevs: Vec<Kevent>,
}

impl Clone for Epoll {
    fn clone(&self) -> Self {
        Epoll {
            queue: self.queue.clone(),
            kevs: Vec::new(),
        }
    }
}

impl Epoll {
    pub fn new() -> io::Result<Self> {
        let queue = unsafe { libc::kqueue() };
        if queue == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Epoll {
                // SAFETY: kqueue returned a new, exclusively owned descriptor.
                queue: Arc::new(unsafe { OwnedFd::from_raw_fd(queue) }),
                kevs: Vec::new(),
            })
        }
    }

    /// Register, modify, or remove interest in events for a file descriptor.
    ///
    /// Note: `READ_HANG_UP` (`EPOLLRDHUP`) is ignored. kqueue always
    /// reports `EV_EOF` without opt-in, so `wait()` reports
    /// `READ_HANG_UP` on read EOF regardless of registration.
    pub fn ctl(
        &self,
        operation: ControlOperation,
        fd: RawFd,
        event: &EpollEvent,
    ) -> io::Result<()> {
        let eset = EventSet::from_bits(event.events).unwrap();

        match operation {
            ControlOperation::Add | ControlOperation::Modify => {
                let mut kevs: Vec<Kevent> = Vec::new();
                let clear = if eset.contains(EventSet::EDGE_TRIGGERED) {
                    libc::EV_CLEAR
                } else {
                    0
                };
                if eset.contains(EventSet::IN) {
                    debug!("add fd in: {fd}");
                    kevs.push(Kevent::new(
                        fd as usize,
                        libc::EVFILT_READ,
                        libc::EV_ADD | clear,
                        event.u64,
                    ));
                }
                if eset.contains(EventSet::OUT) {
                    debug!("add fd out: {fd}");
                    kevs.push(Kevent::new(
                        fd as usize,
                        libc::EVFILT_WRITE,
                        libc::EV_ADD | clear,
                        event.u64,
                    ));
                }
                let ret = unsafe {
                    libc::kevent(
                        self.queue.as_raw_fd(),
                        kevs.as_ptr() as *const libc::kevent,
                        kevs.len() as i32,
                        ptr::null_mut(),
                        0,
                        ptr::null(),
                    )
                };
                if ret == -1 {
                    return Err(io::Error::last_os_error());
                }
            }
            ControlOperation::Delete => {
                let mut kevs: Vec<Kevent> = Vec::new();
                if eset.bits() == 0 {
                    debug!("remove fd in and out: {fd}");
                    kevs.push(Kevent::new(
                        fd as usize,
                        libc::EVFILT_READ,
                        libc::EV_DELETE,
                        event.u64,
                    ));
                    kevs.push(Kevent::new(
                        fd as usize,
                        libc::EVFILT_WRITE,
                        libc::EV_DELETE,
                        event.u64,
                    ));
                } else {
                    if eset.contains(EventSet::IN) {
                        debug!("remove fd in: {fd}");
                        kevs.push(Kevent::new(
                            fd as usize,
                            libc::EVFILT_READ,
                            libc::EV_DELETE,
                            event.u64,
                        ));
                    }
                    if eset.contains(EventSet::OUT) {
                        debug!("remove fd out: {fd}");
                        kevs.push(Kevent::new(
                            fd as usize,
                            libc::EVFILT_WRITE,
                            libc::EV_DELETE,
                            event.u64,
                        ));
                    }
                }
                // kevent() stops at the first change that fails, so each filter is deleted
                // on its own: an unregistered READ (ENOENT) must not keep WRITE registered.
                for kev in &kevs {
                    let ret = unsafe {
                        libc::kevent(
                            self.queue.as_raw_fd(),
                            &kev.0,
                            1,
                            ptr::null_mut(),
                            0,
                            ptr::null(),
                        )
                    };
                    if ret == -1 {
                        let err = io::Error::last_os_error();
                        if err.raw_os_error() != Some(libc::ENOENT) {
                            debug!("remove fd {fd}: {err}");
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn wait(
        &mut self,
        max_events: usize,
        timeout: i32,
        events: &mut [EpollEvent],
    ) -> io::Result<usize> {
        let max_events = events.len().min(max_events).min(i32::MAX as usize);

        // Convert millisecond timeout to timespec. For timeout = -1 (infinite),
        // use a 3-second periodic wakeup to avoid blocking the muxer thread
        // indefinitely — it needs periodic wakeups for housekeeping.
        let ts = if timeout >= 0 {
            libc::timespec {
                tv_sec: (timeout / 1000) as i64,
                tv_nsec: ((timeout % 1000) as i64) * 1_000_000,
            }
        } else {
            libc::timespec {
                tv_sec: 3,
                tv_nsec: 0,
            }
        };

        self.kevs.clear();
        self.kevs.reserve_exact(max_events);
        let spare = self.kevs.spare_capacity_mut();
        debug_assert!(spare.len() >= max_events);
        let ret = unsafe {
            libc::kevent(
                self.queue.as_raw_fd(),
                ptr::null(),
                0,
                spare.as_mut_ptr().cast::<libc::kevent>(),
                max_events as i32,
                &ts as *const libc::timespec,
            )
        };

        debug!("ret: {ret}");

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        let nevents = ret as usize;
        // Safety: kevent() initialized the first `nevents` elements of spare capacity.
        unsafe { self.kevs.set_len(nevents) };
        let kevs = &self.kevs;

        for i in 0..nevents {
            if kevs[i].0.filter == libc::EVFILT_READ {
                events[i].events = EventSet::IN.bits();
                if kevs[i].0.flags & libc::EV_EOF != 0 {
                    events[i].events |= EventSet::READ_HANG_UP.bits();
                }
            } else if kevs[i].0.filter == libc::EVFILT_WRITE {
                events[i].events = EventSet::OUT.bits();
                if kevs[i].0.flags & libc::EV_EOF != 0 {
                    events[i].events |= EventSet::HANG_UP.bits();
                }
            } else if kevs[i].0.filter == libc::EVFILT_TIMER {
                // No epoll equivalent; caller identifies timer by udata.
                events[i].events = EventSet::empty().bits();
            }
            events[i].u64 = kevs[i].udata();

            let fd = kevs[i].0.ident;
            let data = kevs[i].0.data;
            debug!(
                "kevent: {} fd={fd} data={data}",
                event_name(kevs[i].0.filter, kevs[i].0.flags)
            );
        }

        Ok(nevents)
    }

    /// Register a one-shot timer that fires after `delay_us` microseconds.
    /// The resulting event will have `data` set to `udata`.
    pub fn add_oneshot_timer(&self, delay_us: u64, udata: u64) {
        let kev = libc::kevent {
            ident: 0,
            filter: libc::EVFILT_TIMER,
            flags: libc::EV_ADD | libc::EV_ONESHOT,
            fflags: libc::NOTE_USECONDS,
            data: delay_us as isize,
            udata: udata as *mut libc::c_void,
        };
        let ret = unsafe {
            libc::kevent(
                self.queue.as_raw_fd(),
                &kev,
                1,
                ptr::null_mut(),
                0,
                ptr::null(),
            )
        };
        assert_eq!(ret, 0);
    }
}

impl AsRawFd for Epoll {
    fn as_raw_fd(&self) -> RawFd {
        self.queue.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::net::UnixStream;

    use crate::eventfd::{EFD_NONBLOCK, EventFd};

    #[test]
    fn test_ctl_invalid_fd_returns_error() {
        let epoll = Epoll::new().unwrap();
        let event = EpollEvent::new(EventSet::IN, 1);

        assert!(epoll.ctl(ControlOperation::Add, -1, &event).is_err());
        assert!(epoll.ctl(ControlOperation::Modify, -1, &event).is_err());
    }

    #[test]
    fn test_delete_removes_write_filter_when_read_is_not_registered() {
        let mut epoll = Epoll::new().unwrap();
        let (sock, peer) = UnixStream::pair().unwrap();
        let fd = sock.as_raw_fd();
        epoll
            .ctl(
                ControlOperation::Add,
                fd,
                &EpollEvent::new(EventSet::OUT, 7),
            )
            .unwrap();
        drop(peer);

        let mut events = vec![EpollEvent::default(); 4];
        assert_eq!(epoll.wait(4, 0, &mut events).unwrap(), 1);
        assert_eq!(events[0].event_set(), EventSet::OUT | EventSet::HANG_UP);
        assert_eq!(events[0].data(), 7);

        // A WRITE filter left behind would report EOF on every wait.
        epoll
            .ctl(ControlOperation::Delete, fd, &EpollEvent::default())
            .unwrap();
        assert_eq!(epoll.wait(4, 0, &mut events).unwrap(), 0);
    }

    #[test]
    fn test_event_ops() {
        let mut event = EpollEvent::default();
        assert_eq!(event.events(), 0);
        assert_eq!(event.data(), 0);

        event = EpollEvent::new(EventSet::IN, 2);
        assert_eq!(event.events(), 1);
        assert_eq!(event.event_set(), EventSet::IN);

        assert_eq!(event.data(), 2);
        assert_eq!(event.fd(), 2);
    }

    #[test]
    fn test_events_debug() {
        let events = EpollEvent::new(EventSet::IN, 42);
        assert_eq!(format!("{:?}", events), "{ events: 1, data: 42 }")
    }

    #[test]
    fn test_epoll() {
        const DEFAULT_TIMEOUT: i32 = 250;
        const EVENT_BUFFER_SIZE: usize = 128;
        const MAX_EVENTS: usize = 10;

        let mut epoll = Epoll::new().unwrap();
        assert_eq!(epoll.queue.as_raw_fd(), epoll.as_raw_fd());

        // Let's test different scenarios for `epoll_ctl()` and `epoll_wait()` functionality.

        let event_fd_1 = EventFd::new(EFD_NONBLOCK).unwrap();
        // For EPOLLOUT to be available it is enough only to be possible to write a value of
        // at least 1 to the eventfd counter without blocking.
        // If we write a value greater than 0 to this counter, the fd will be available for
        // EPOLLIN events too.
        event_fd_1.write(1).unwrap();

        let event_1 = EpollEvent::new(EventSet::IN, event_fd_1.as_raw_fd() as u64);

        // For EPOLL_CTL_ADD behavior we will try to add some fds with different event masks into
        // the interest list of epoll instance.
        assert!(
            epoll
                .ctl(ControlOperation::Add, event_fd_1.as_raw_fd(), &event_1)
                .is_ok()
        );

        let event_fd_2 = EventFd::new(EFD_NONBLOCK).unwrap();
        event_fd_2.write(1).unwrap();
        assert!(
            epoll
                .ctl(
                    ControlOperation::Add,
                    event_fd_2.as_raw_fd(),
                    // For this fd, we want an Event instance that has `data` field set to other
                    // value than the value of the fd and `events` without EPOLLIN type set.
                    &EpollEvent::new(EventSet::IN, 10)
                )
                .is_ok()
        );

        // Let's check `epoll_wait()` behavior for our epoll instance.
        let mut ready_events = vec![EpollEvent::default(); EVENT_BUFFER_SIZE];
        let mut ev_count = epoll
            .wait(MAX_EVENTS, DEFAULT_TIMEOUT, &mut ready_events[..])
            .unwrap();

        // We expect to have 3 fds in the ready list of epoll instance.
        assert_eq!(ev_count, 2);

        // Let's check also the Event values that are now returned in the ready list.
        assert_eq!(ready_events[0].data(), event_fd_1.as_raw_fd() as u64);
        assert_eq!(ready_events[1].data(), 10_u64);

        // EPOLLIN and EPOLLOUT should be available for this fd.
        assert_eq!(ready_events[0].events(), EventSet::IN.bits());
        // Only EPOLLOUT is expected because we didn't want to monitor EPOLLIN on this fd.
        assert_eq!(ready_events[1].events(), EventSet::IN.bits());

        // Let's also delete a fd from the interest list.
        assert!(
            epoll
                .ctl(
                    ControlOperation::Delete,
                    event_fd_2.as_raw_fd(),
                    &EpollEvent::default()
                )
                .is_ok()
        );

        // We expect to have only one fd remained in the ready list (event_fd_3).
        ev_count = epoll
            .wait(MAX_EVENTS, DEFAULT_TIMEOUT, &mut ready_events[..])
            .unwrap();

        assert_eq!(ev_count, 1);
        assert_eq!(ready_events[0].data(), event_fd_1.as_raw_fd() as u64);
        assert_eq!(ready_events[0].events(), EventSet::IN.bits());
    }
}

#[cfg(test)]
mod ownership_tests {
    use super::*;
    use std::net::UdpSocket;

    #[test]
    fn dropping_either_poll_owner_preserves_registered_socket_delivery() {
        for drop_original in [false, true] {
            let original = Epoll::new().unwrap();
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            original
                .ctl(
                    ControlOperation::Add,
                    socket.as_raw_fd(),
                    &EpollEvent::new(EventSet::IN, 37),
                )
                .unwrap();
            let cloned = original.clone();
            let mut remaining = if drop_original {
                drop(original);
                cloned
            } else {
                drop(cloned);
                original
            };
            let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
            sender
                .send_to(b"alive", socket.local_addr().unwrap())
                .unwrap();
            let mut events = [EpollEvent::default(); 1];
            assert_eq!(remaining.wait(1, 2000, &mut events).unwrap(), 1);
            assert_eq!(events[0].data(), 37);
        }
    }
}
