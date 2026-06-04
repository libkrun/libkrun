use nix::sys::socket::{self, AddressFamily, MsgFlags, SockFlag, SockType, VsockAddr};
use nix::sys::time::TimeSpec;
use nix::time::{self, ClockId};
use nix::unistd::{self, ForkResult};
use std::os::fd::AsRawFd;

const TSYNC_PORT: u32 = 123;
const NANOS_IN_SECOND: u64 = 1_000_000_000;
const DELTA_SYNC: u64 = 100_000_000; // 100ms — don't bother adjusting for smaller drifts

/// Spawn a child process that synchronises the guest clock from the host.
///
/// Uses fork() rather than a thread so the sync loop survives when the parent
/// calls execvp() in PID1 mode (a thread would be destroyed by exec; a
/// separate process is not).  Safe to call here because run() is invoked
/// before any other threads exist in the process.
pub fn run() {
    let Ok(sock) = socket::socket(
        AddressFamily::Vsock,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    ) else {
        return;
    };

    let addr = VsockAddr::new(libc::VMADDR_CID_ANY, TSYNC_PORT);
    if socket::bind(sock.as_raw_fd(), &addr).is_err() {
        return;
    }

    match unsafe { unistd::fork() } {
        Ok(ForkResult::Child) => {
            // Child: run the sync loop until the socket errors, then exit.
            clock_worker(sock.as_raw_fd());
            unsafe { libc::_exit(1) };
        }
        _ => {
            // Parent or fork error: sock drops here, closing the parent's copy.
            // The child retains its inherited fd.
        }
    }
}

fn clock_worker(sock: libc::c_int) {
    loop {
        let mut buf = [0u8; 8];
        let Ok(n) = socket::recv(sock, &mut buf, MsgFlags::empty()) else {
            break;
        };
        if n != 8 {
            continue;
        }

        let host_ns = u64::from_le_bytes(buf);

        let Ok(guest_ts) = time::clock_gettime(ClockId::CLOCK_REALTIME) else {
            break;
        };
        let guest_ns = guest_ts.tv_sec() as u64 * NANOS_IN_SECOND + guest_ts.tv_nsec() as u64;

        if host_ns.abs_diff(guest_ns) > DELTA_SYNC {
            let host_ts = TimeSpec::new(
                (host_ns / NANOS_IN_SECOND) as libc::time_t,
                (host_ns % NANOS_IN_SECOND) as libc::c_long,
            );
            let _ = time::clock_settime(ClockId::CLOCK_REALTIME, host_ts);
        }
    }
}
