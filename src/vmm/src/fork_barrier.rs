// Copyright 2026. SPDX-License-Identifier: Apache-2.0

//! Exclude forks while a transient writable mapping acquires MADV_DONTFORK.
//! The copy itself runs outside the barrier. Raw VMM forks use the same gate
//! as libc forks, without invoking unrelated embedding-library callbacks.

use std::io;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};

// 0 = unlocked, 1 = held without waiters, 2 = held with possible waiters.
// An atomic/futex gate keeps the raw-fork child's reset syscall/allocator-free.
static GATE: AtomicU32 = AtomicU32::new(0);

extern "C" fn acquire() {
    if GATE
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
    {
        return;
    }
    while GATE.swap(2, Ordering::Acquire) != 0 {
        // SAFETY: GATE is a live, aligned u32. EINTR and spurious wakeups simply
        // retry the atomic acquisition; EAGAIN means the owner already left.
        unsafe {
            libc::syscall(
                libc::SYS_futex,
                GATE.as_ptr(),
                libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
                2_u32,
                std::ptr::null::<libc::timespec>(),
            );
        }
    }
}

extern "C" fn release() {
    if GATE.swap(0, Ordering::Release) == 2 {
        // SAFETY: same live futex, waking one competing acquisition.
        unsafe {
            libc::syscall(
                libc::SYS_futex,
                GATE.as_ptr(),
                libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
                1,
            );
        }
    }
}

extern "C" fn release_child() {
    // No other parent thread survived in this address space; its waiters must
    // neither be inherited nor woken by a child that may itself fork later.
    GATE.store(0, Ordering::Release);
}

pub(crate) struct MappingSetup;

impl Drop for MappingSetup {
    fn drop(&mut self) {
        release();
    }
}

/// Hold only across mmap + madvise (and munmap on failure), never allocation,
/// guest copying, worker startup, callbacks, or a fork on this thread.
pub(crate) fn exclude_forks() -> io::Result<MappingSetup> {
    static REGISTERED: OnceLock<i32> = OnceLock::new();
    let result = *REGISTERED.get_or_init(|| unsafe {
        libc::pthread_atfork(Some(acquire), Some(release), Some(release_child))
    });
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result));
    }
    acquire();
    Ok(MappingSetup)
}

/// Fork without unrelated pthread-atfork handlers, excluding mapping setup.
///
/// # Safety
/// The child must use only syscall/atomic operations until exec or _exit.
pub(crate) unsafe fn raw_fork() -> libc::pid_t {
    acquire();
    // SIGCHLD alone gives fork semantics, including on Linux/aarch64 which
    // has no separate fork syscall. No new stack or shared address space.
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone,
            libc::SIGCHLD as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        ) as libc::pid_t
    };
    if pid == 0 {
        release_child();
    } else {
        // A futex wake may change errno; preserve the fork failure for callers.
        let errno = unsafe { *libc::__errno_location() };
        release();
        unsafe { *libc::__errno_location() = errno };
    }
    pid
}

#[test]
fn raw_fork_child_can_fork_again() {
    let child = unsafe { raw_fork() };
    assert!(child >= 0);
    if child == 0 {
        unsafe {
            libc::alarm(5);
            let grandchild = raw_fork();
            if grandchild == 0 {
                libc::_exit(0);
            }
            let mut status = 0;
            let waited = if grandchild > 0 {
                libc::waitpid(grandchild, &mut status, 0)
            } else {
                -1
            };
            libc::_exit(i32::from(waited <= 0 || status != 0));
        }
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert_eq!(status, 0);
}
