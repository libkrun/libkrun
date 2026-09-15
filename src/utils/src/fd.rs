// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! File descriptor utilities.

use std::io;
use std::os::fd::{AsFd, BorrowedFd, RawFd};

use nix::fcntl::{FcntlArg, OFlag, fcntl};

/// Set non-blocking mode on a file descriptor.
///
/// If `nonblock` is true, sets O_NONBLOCK. If false, clears it.
pub fn set_nonblocking(fd: impl AsFd, nonblock: bool) -> io::Result<()> {
    let fd = fd.as_fd();
    let flags = fcntl(fd, FcntlArg::F_GETFL)?;
    let old_flags = OFlag::from_bits_retain(flags);

    let new_flags = if nonblock {
        old_flags | OFlag::O_NONBLOCK
    } else {
        old_flags & !OFlag::O_NONBLOCK
    };

    if new_flags != old_flags {
        fcntl(fd, FcntlArg::F_SETFL(new_flags))?;
    }

    Ok(())
}

/// Set non-blocking mode on a raw file descriptor.
///
/// The caller must ensure `fd` is a valid file descriptor.
pub fn set_nonblocking_raw(fd: RawFd, nonblock: bool) -> io::Result<()> {
    // SAFETY: Caller guarantees fd is valid
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    set_nonblocking(borrowed, nonblock)
}

/// Extension trait for setting non-blocking mode on file descriptors.
pub trait SetNonblockingExt: AsFd {
    /// Set non-blocking mode on this file descriptor.
    ///
    /// If `nonblock` is true, sets O_NONBLOCK. If false, clears it.
    fn set_nonblocking(&self, nonblock: bool) -> io::Result<()> {
        set_nonblocking(self.as_fd(), nonblock)
    }
}

impl<T: AsFd> SetNonblockingExt for T {}
