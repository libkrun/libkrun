// Copyright 2026. SPDX-License-Identifier: Apache-2.0

//! A syscall-only Linux process that retains one immutable guest-RAM view.
//!
//! The guardian is forked only while the VMM and its devices are quiesced. It
//! inherits the exact address-space boundary through kernel COW, then serves
//! bounded page reads over a private Unix socket. The source VMM can resume and
//! mutate immediately without changing the guardian's view.

#![cfg(target_os = "linux")]

use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use vm_memory::{Address, GuestMemory, GuestMemoryRegion};

use crate::GuestMemoryMmap;
use crate::demand_paging::{DemandPageRegion, PageSource};

const PROTOCOL_MAGIC: u64 = 0x534d_4f4c_5041_4745; // "SMOLPAGE"
const PROTOCOL_VERSION: u32 = 1;
const TOKEN_BYTES: usize = 32;
const REQUEST_BYTES: usize = 64;
const RESPONSE_BYTES: usize = 16;
const MAX_READ_BYTES: usize = 2 * 1024 * 1024;
const MAX_WORKERS: usize = 1024;

/// Create a fork-like child without running libc's pthread-atfork handlers.
///
/// Linux/aarch64 does not expose a separate `fork` syscall. A raw `clone`
/// carrying only `SIGCHLD` has the same process semantics and is available on
/// every Linux architecture supported by libkrun.
unsafe fn raw_fork() -> libc::pid_t {
    unsafe {
        libc::syscall(
            libc::SYS_clone,
            libc::SIGCHLD as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        ) as libc::pid_t
    }
}

#[derive(Clone, Copy)]
struct GuardianRegion {
    source: *const u8,
    len: usize,
}

/// Connection information published with a guardian-backed RAM generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardianGenerationDesc {
    pub guardian_pid: libc::pid_t,
    pub guardian_start_time: u64,
    pub socket_path: PathBuf,
    pub token: [u8; TOKEN_BYTES],
    pub regions: Vec<DemandPageRegion>,
}

/// Owns a newly-created guardian until its manifest has been published.
///
/// Dropping an armed value kills the process and removes its socket. After an
/// atomic manifest publication, [`disarm`](Self::disarm) transfers lifecycle
/// responsibility to the snapshot owner.
pub struct GenerationGuardian {
    desc: GuardianGenerationDesc,
    armed: bool,
    reaper: Option<std::thread::JoinHandle<()>>,
}

impl GenerationGuardian {
    /// Fork an immutable RAM guardian. Call only at a fully quiesced snapshot
    /// boundary.
    pub fn start(memory: &GuestMemoryMmap, socket_path: &Path) -> io::Result<Self> {
        validate_private_memory_mappings(memory)?;
        if socket_path.as_os_str().len() > 100 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "RAM guardian socket path is too long",
            ));
        }
        let listener = UnixListener::bind(socket_path)?;
        fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))?;
        let mut token = [0_u8; TOKEN_BYTES];
        fill_random(&mut token)?;

        let mut regions = Vec::new();
        let mut public_regions = Vec::new();
        for region in memory.iter() {
            let len = usize::try_from(region.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "RAM region exceeds usize")
            })?;
            let source = memory
                .get_host_address(region.start_addr())
                .map_err(|error| io::Error::other(format!("guest RAM address: {error:?}")))?
                .cast_const();
            regions.push(GuardianRegion { source, len });
            public_regions.push(DemandPageRegion {
                gpa: region.start_addr().raw_value(),
                len: region.len(),
            });
        }
        if regions.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "guest RAM has no regions",
            ));
        }

        let mut status_pipe = [-1; 2];
        if unsafe { libc::pipe2(status_pipe.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let child_pid = unsafe { raw_fork() };
        if child_pid < 0 {
            let error = io::Error::last_os_error();
            unsafe {
                libc::close(status_pipe[0]);
                libc::close(status_pipe[1]);
            }
            return Err(error);
        }
        if child_pid == 0 {
            unsafe { libc::close(status_pipe[0]) };
            unsafe { close_all_fds_except(listener.as_raw_fd(), Some(status_pipe[1])) };
            let result =
                unsafe { guardian_loop(listener.as_raw_fd(), status_pipe[1], &regions, &token) };
            unsafe {
                libc::close(status_pipe[1]);
                libc::_exit(i32::from(result.is_err()));
            }
        }

        unsafe { libc::close(status_pipe[1]) };
        drop(listener);
        let child_status = read_child_status(status_pipe[0], child_pid);
        unsafe { libc::close(status_pipe[0]) };
        if let Err(error) = child_status {
            unsafe {
                libc::kill(child_pid, libc::SIGKILL);
                libc::waitpid(child_pid, std::ptr::null_mut(), 0);
            }
            let _ = fs::remove_file(socket_path);
            return Err(error);
        }
        let guardian_start_time = match process_start_time(child_pid) {
            Ok(start_time) => start_time,
            Err(error) => {
                unsafe {
                    libc::kill(child_pid, libc::SIGKILL);
                    libc::waitpid(child_pid, std::ptr::null_mut(), 0);
                }
                let _ = fs::remove_file(socket_path);
                return Err(error);
            }
        };

        let reaper = match std::thread::Builder::new()
            .name("smolvm-ram-guardian-reaper".to_string())
            .spawn(move || {
                loop {
                    let result = unsafe { libc::waitpid(child_pid, std::ptr::null_mut(), 0) };
                    if result == child_pid {
                        break;
                    }
                    if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
                    {
                        continue;
                    }
                    break;
                }
            }) {
            Ok(reaper) => reaper,
            Err(error) => {
                unsafe {
                    libc::kill(child_pid, libc::SIGKILL);
                    libc::waitpid(child_pid, std::ptr::null_mut(), 0);
                }
                let _ = fs::remove_file(socket_path);
                return Err(error);
            }
        };

        Ok(Self {
            desc: GuardianGenerationDesc {
                guardian_pid: child_pid,
                guardian_start_time,
                socket_path: socket_path.to_path_buf(),
                token,
                regions: public_regions,
            },
            armed: true,
            reaper: Some(reaper),
        })
    }

    pub fn description(&self) -> &GuardianGenerationDesc {
        &self.desc
    }

    pub fn disarm(mut self) -> GuardianGenerationDesc {
        self.armed = false;
        self.desc.clone()
    }
}

fn process_start_time(pid: libc::pid_t) -> io::Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let fields = stat
        .rsplit_once(") ")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed process stat"))?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    fields
        .get(19)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "process stat is truncated"))?
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid process start time"))
}

/// Verify that kernel fork will preserve every guest-RAM byte. `fork(2)` does
/// not isolate a `MAP_SHARED` mapping, so accepting one would let later source
/// writes silently mutate the supposedly immutable generation.
fn validate_private_memory_mappings(memory: &GuestMemoryMmap) -> io::Result<()> {
    let maps = fs::read_to_string("/proc/self/maps")?;
    for region in memory.iter() {
        let start = memory
            .get_host_address(region.start_addr())
            .map_err(|error| io::Error::other(format!("guest RAM address: {error:?}")))?
            as usize;
        let end = start
            .checked_add(region.len() as usize)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "RAM range overflow"))?;
        let mut covered_until = start;
        for line in maps.lines() {
            let mut fields = line.split_whitespace();
            let Some(range) = fields.next() else {
                continue;
            };
            let Some(perms) = fields.next() else {
                continue;
            };
            let Some((map_start, map_end)) = range.split_once('-') else {
                continue;
            };
            let Ok(map_start) = usize::from_str_radix(map_start, 16) else {
                continue;
            };
            let Ok(map_end) = usize::from_str_radix(map_end, 16) else {
                continue;
            };
            if map_end <= covered_until || map_start >= end {
                continue;
            }
            if map_start > covered_until {
                break;
            }
            if perms.as_bytes().get(3) != Some(&b'p') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "guest RAM mapping 0x{:x}-0x{:x} is shared; rebase it privately before guardian capture",
                        map_start.max(start),
                        map_end.min(end)
                    ),
                ));
            }
            covered_until = covered_until.max(map_end.min(end));
            if covered_until == end {
                break;
            }
        }
        if covered_until != end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "guest RAM mapping is not fully represented in /proc/self/maps",
            ));
        }
    }
    Ok(())
}

impl Drop for GenerationGuardian {
    fn drop(&mut self) {
        if self.armed {
            unsafe {
                libc::kill(self.desc.guardian_pid, libc::SIGKILL);
            }
            if let Some(reaper) = self.reaper.take() {
                let _ = reaper.join();
            }
            let _ = fs::remove_file(&self.desc.socket_path);
        }
    }
}

fn fill_random(destination: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < destination.len() {
        let result = unsafe {
            libc::getrandom(
                destination[filled..].as_mut_ptr().cast::<libc::c_void>(),
                destination.len() - filled,
                0,
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if result == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "getrandom returned no bytes",
            ));
        }
        filled += result as usize;
    }
    Ok(())
}

fn read_child_status(fd: RawFd, child_pid: libc::pid_t) -> io::Result<()> {
    let mut bytes = [0_u8; 4];
    let mut read = 0;
    while read < bytes.len() {
        let result = unsafe {
            libc::read(
                fd,
                bytes[read..].as_mut_ptr().cast::<libc::c_void>(),
                bytes.len() - read,
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if result == 0 {
            let mut status = 0;
            unsafe { libc::waitpid(child_pid, &mut status, 0) };
            return Err(io::Error::other(format!(
                "RAM guardian exited before readiness (status {status})"
            )));
        }
        read += result as usize;
    }
    let errno = i32::from_ne_bytes(bytes);
    if errno == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(errno))
    }
}

unsafe fn write_all_fd(fd: RawFd, source: *const u8, len: usize) -> bool {
    let mut written = 0;
    while written < len {
        let result = unsafe {
            libc::write(
                fd,
                source.add(written).cast::<libc::c_void>(),
                len - written,
            )
        };
        if result < 0 {
            if unsafe { *libc::__errno_location() } == libc::EINTR {
                continue;
            }
            return false;
        }
        if result == 0 {
            return false;
        }
        written += result as usize;
    }
    true
}

unsafe fn read_exact_fd(fd: RawFd, destination: *mut u8, len: usize) -> bool {
    let mut read = 0;
    while read < len {
        let result =
            unsafe { libc::read(fd, destination.add(read).cast::<libc::c_void>(), len - read) };
        if result < 0 {
            if unsafe { *libc::__errno_location() } == libc::EINTR {
                continue;
            }
            return false;
        }
        if result == 0 {
            return false;
        }
        read += result as usize;
    }
    true
}

unsafe fn close_range_segment(first: u32, last: u32) -> bool {
    if first > last {
        return true;
    }
    unsafe { libc::syscall(libc::SYS_close_range, first, last, 0) == 0 }
}

/// A raw-forked guardian must not keep the source VMM's disks, agent sockets,
/// control sockets, eventfds, or network connections alive. Use only syscalls
/// in the post-fork child; if `close_range(2)` is unavailable, fall back to a
/// bounded sequence of `close(2)` calls.
unsafe fn close_all_fds_except(first: RawFd, second: Option<RawFd>) {
    let (one, two) = match second.filter(|fd| *fd >= 0) {
        Some(second) if second < first => (second as u32, Some(first as u32)),
        Some(second) if second > first => (first as u32, Some(second as u32)),
        _ => (first as u32, None),
    };
    let before_one = one == 0 || unsafe { close_range_segment(0, one - 1) };
    let between = match two {
        None => true,
        Some(two) => two == one + 1 || unsafe { close_range_segment(one + 1, two - 1) },
    };
    let after = two.unwrap_or(one);
    let after_keep =
        after == u32::MAX || unsafe { close_range_segment(after.saturating_add(1), u32::MAX) };
    let close_range_ok = before_one && between && after_keep;
    if close_range_ok {
        return;
    }

    let mut limit = libc::rlimit {
        rlim_cur: 65_536,
        rlim_max: 65_536,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        limit.rlim_cur = 65_536;
    }
    let limit = limit.rlim_cur.min(i32::MAX as libc::rlim_t) as RawFd;
    for fd in 0..limit {
        if fd != first && second != Some(fd) {
            unsafe { libc::close(fd) };
        }
    }
}

fn request_token_matches(request: &[u8; REQUEST_BYTES], expected: &[u8; TOKEN_BYTES]) -> bool {
    request[32..64]
        .iter()
        .zip(expected)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

unsafe fn serve_client(client: RawFd, regions: &[GuardianRegion], token: &[u8; TOKEN_BYTES]) {
    let mut request = [0_u8; REQUEST_BYTES];
    loop {
        if !unsafe { read_exact_fd(client, request.as_mut_ptr(), request.len()) } {
            return;
        }
        let magic = u64::from_ne_bytes(request[0..8].try_into().unwrap());
        let version = u32::from_ne_bytes(request[8..12].try_into().unwrap());
        let region_index = u32::from_ne_bytes(request[12..16].try_into().unwrap()) as usize;
        let offset = u64::from_ne_bytes(request[16..24].try_into().unwrap());
        let length = u32::from_ne_bytes(request[24..28].try_into().unwrap()) as usize;
        let valid = magic == PROTOCOL_MAGIC
            && version == PROTOCOL_VERSION
            && request_token_matches(&request, token)
            && length > 0
            && length <= MAX_READ_BYTES
            && length.is_multiple_of(4096)
            && offset.is_multiple_of(4096)
            && regions.get(region_index).is_some_and(|region| {
                usize::try_from(offset)
                    .ok()
                    .and_then(|offset| offset.checked_add(length))
                    .is_some_and(|end| end <= region.len)
            });
        let status = if valid { 0_i32 } else { libc::EINVAL };
        let mut response = [0_u8; RESPONSE_BYTES];
        response[0..8].copy_from_slice(&PROTOCOL_MAGIC.to_ne_bytes());
        response[8..12].copy_from_slice(&status.to_ne_bytes());
        response[12..16].copy_from_slice(&(length as u32).to_ne_bytes());
        if !unsafe { write_all_fd(client, response.as_ptr(), response.len()) } || !valid {
            return;
        }
        let region = regions[region_index];
        if !unsafe { write_all_fd(client, region.source.add(offset as usize), length) } {
            return;
        }
    }
}

unsafe fn reap_workers(active: &mut usize) {
    loop {
        let result = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
        if result <= 0 {
            return;
        }
        *active = active.saturating_sub(1);
    }
}

/// Runs after raw `fork(2)` and must remain allocator- and lock-free.
unsafe fn guardian_loop(
    listener: RawFd,
    status_fd: RawFd,
    regions: &[GuardianRegion],
    token: &[u8; TOKEN_BYTES],
) -> Result<i32, i32> {
    // Mark readiness before accepting. The listener was fully bound before
    // fork, so clients can connect as soon as the manifest is visible.
    let ready = 0_i32.to_ne_bytes();
    if !unsafe { write_all_fd(status_fd, ready.as_ptr(), ready.len()) } {
        return Err(unsafe { *libc::__errno_location() });
    }
    unsafe { libc::close(status_fd) };
    let mut active_workers = 0_usize;
    loop {
        unsafe { reap_workers(&mut active_workers) };
        let client = unsafe {
            libc::accept4(
                listener,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if client < 0 {
            let errno = unsafe { *libc::__errno_location() };
            if errno == libc::EINTR {
                continue;
            }
            return Err(errno);
        }
        if active_workers >= MAX_WORKERS {
            unsafe { libc::close(client) };
            continue;
        }
        let guardian_pid = unsafe { libc::getpid() };
        let worker = unsafe { raw_fork() };
        if worker == 0 {
            unsafe {
                libc::close(listener);
                // Ensure a killed generation guardian cannot leave page-serving
                // workers holding its RAM alive indefinitely.
                libc::syscall(
                    libc::SYS_prctl,
                    libc::PR_SET_PDEATHSIG,
                    libc::SIGKILL,
                    0,
                    0,
                    0,
                );
                if libc::getppid() != guardian_pid {
                    libc::_exit(1);
                }
                close_all_fds_except(client, None);
                serve_client(client, regions, token);
                libc::close(client);
                libc::_exit(0);
            }
        }
        unsafe { libc::close(client) };
        if worker > 0 {
            active_workers += 1;
        }
    }
}

/// Page source backed by a generation guardian connection.
pub struct GuardianPageSource {
    stream: UnixStream,
    token: [u8; TOKEN_BYTES],
}

impl GuardianPageSource {
    pub fn connect(desc: &GuardianGenerationDesc) -> io::Result<Self> {
        let stream = UnixStream::connect(&desc.socket_path)?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
        let mut source = Self {
            stream,
            token: desc.token,
        };
        // Authenticate eagerly. A clone must fail before entering KVM rather
        // than discovering a stale or forged guardian on its first RAM fault.
        let probe_len = desc
            .regions
            .first()
            .map(|region| region.len.min(4096) as usize)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "guardian has no RAM"))?;
        let mut probe = [0_u8; 4096];
        source.read_exact_at(0, 0, &mut probe[..probe_len])?;
        Ok(source)
    }
}

impl PageSource for GuardianPageSource {
    fn read_exact_at(
        &mut self,
        region_index: usize,
        offset: u64,
        destination: &mut [u8],
    ) -> io::Result<()> {
        let region_index = u32::try_from(region_index).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "RAM region index exceeds u32")
        })?;
        let length = u32::try_from(destination.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "RAM read exceeds protocol limit",
            )
        })?;
        let mut request = [0_u8; REQUEST_BYTES];
        request[0..8].copy_from_slice(&PROTOCOL_MAGIC.to_ne_bytes());
        request[8..12].copy_from_slice(&PROTOCOL_VERSION.to_ne_bytes());
        request[12..16].copy_from_slice(&region_index.to_ne_bytes());
        request[16..24].copy_from_slice(&offset.to_ne_bytes());
        request[24..28].copy_from_slice(&length.to_ne_bytes());
        request[32..64].copy_from_slice(&self.token);
        self.stream.write_all(&request)?;
        let mut response = [0_u8; RESPONSE_BYTES];
        self.stream.read_exact(&mut response)?;
        let magic = u64::from_ne_bytes(response[0..8].try_into().unwrap());
        let status = i32::from_ne_bytes(response[8..12].try_into().unwrap());
        let response_length = u32::from_ne_bytes(response[12..16].try_into().unwrap()) as usize;
        if magic != PROTOCOL_MAGIC || response_length != destination.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid RAM guardian response",
            ));
        }
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
        self.stream.read_exact(destination)
    }
}

/// Terminate a published guardian after validating its private socket.
pub fn terminate_guardian(desc: &GuardianGenerationDesc) -> io::Result<()> {
    // A successful authenticated read proves the path and token still identify
    // the expected generation before acting on its manifest PID.
    let mut source = GuardianPageSource::connect(desc)?;
    let mut page = [0_u8; 4096];
    source.read_exact_at(0, 0, &mut page)?;
    if process_start_time(desc.guardian_pid)? != desc.guardian_start_time {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "RAM guardian PID was reused",
        ));
    }
    // The raw-forked process inherits the VMM's installed signal handlers, so
    // SIGTERM can be consumed without terminating it. Authentication plus the
    // exact PID start time above make SIGKILL both safe and deterministic.
    if unsafe { libc::kill(desc.guardian_pid, libc::SIGKILL) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let _ = fs::remove_file(&desc.socket_path);
    for _ in 0..100 {
        match process_start_time(desc.guardian_pid) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Ok(start_time) if start_time != desc.guardian_start_time => return Ok(()),
            _ => std::thread::sleep(std::time::Duration::from_millis(10)),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "RAM guardian did not exit after SIGKILL",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demand_paging::{UserfaultfdMode, create_demand_paged_memory};
    use std::os::unix::fs::FileExt;
    use vm_memory::{Bytes, FileOffset};

    fn test_dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "libkrun-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn guardian_preserves_capture_boundary_and_pages_multiple_clones() {
        let size = 4 * MAX_READ_BYTES;
        let backing = crate::builder::create_guest_ram_memfd(size).expect("memfd");
        let before = vec![0x3c_u8; size];
        backing.write_all_at(&before, 0).unwrap();
        let memory = crate::snapshot::open_cow_memory_from_pid(
            std::process::id() as i32,
            &[crate::snapshot::MemfdRegionDesc {
                gpa: 0,
                len: size as u64,
                fd: backing.as_raw_fd(),
                offset: 0,
                path: String::new(),
            }],
        )
        .unwrap();
        let dir = test_dir("guardian");
        let socket = dir.join("ram.sock");
        let guardian = GenerationGuardian::start(&memory, &socket).expect("start guardian");

        // The live source diverges immediately after the capture boundary.
        memory
            .write_slice(&vec![0xa7_u8; size], vm_memory::GuestAddress(0))
            .unwrap();
        for _ in 0..2 {
            let source = GuardianPageSource::connect(guardian.description()).unwrap();
            let clone = create_demand_paged_memory(
                &guardian.description().regions,
                Box::new(source),
                UserfaultfdMode::UserModeTest,
            )
            .expect("demand-paged clone");
            let mut actual = vec![0_u8; size];
            clone
                .memory
                .read_slice(&mut actual, vm_memory::GuestAddress(0))
                .unwrap();
            assert!(actual.iter().all(|byte| *byte == 0x3c));
            assert!(clone.pager.failure().is_none());
        }

        drop(guardian);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn guardian_rejects_shared_guest_ram() {
        let size = MAX_READ_BYTES;
        let backing = crate::builder::create_guest_ram_memfd(size).expect("memfd");
        let memory = GuestMemoryMmap::from_ranges_with_files([(
            vm_memory::GuestAddress(0),
            size,
            Some(FileOffset::new(backing, 0)),
        )])
        .unwrap();
        let dir = test_dir("guardian-shared");
        let socket = dir.join("ram.sock");
        let error = GenerationGuardian::start(&memory, &socket)
            .err()
            .expect("shared mapping must be rejected");
        assert!(error.to_string().contains("is shared"), "{error}");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn guardian_rejects_wrong_token() {
        let size = MAX_READ_BYTES;
        let memory = GuestMemoryMmap::from_ranges(&[(vm_memory::GuestAddress(0), size)]).unwrap();
        let dir = test_dir("guardian-token");
        let socket = dir.join("ram.sock");
        let guardian = GenerationGuardian::start(&memory, &socket).expect("start guardian");
        let mut wrong = guardian.description().clone();
        wrong.token[0] ^= 1;
        assert!(GuardianPageSource::connect(&wrong).is_err());
        drop(guardian);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn published_guardian_terminates_and_removes_its_socket() {
        let memory =
            GuestMemoryMmap::from_ranges(&[(vm_memory::GuestAddress(0), 2 * 4096)]).unwrap();
        let dir = test_dir("guardian-terminate");
        let socket = dir.join("ram.sock");
        let guardian = GenerationGuardian::start(&memory, &socket).expect("start guardian");
        let desc = guardian.disarm();

        terminate_guardian(&desc).expect("terminate guardian");

        assert!(!socket.exists());
        assert!(
            process_start_time(desc.guardian_pid).is_err(),
            "guardian PID must be gone"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn successive_guardians_keep_distinct_generations() {
        let size = MAX_READ_BYTES;
        let backing = crate::builder::create_guest_ram_memfd(size).expect("memfd");
        backing.write_all_at(&vec![0x11_u8; size], 0).unwrap();
        let memory = crate::snapshot::open_cow_memory_from_pid(
            std::process::id() as i32,
            &[crate::snapshot::MemfdRegionDesc {
                gpa: 0,
                len: size as u64,
                fd: backing.as_raw_fd(),
                offset: 0,
                path: String::new(),
            }],
        )
        .unwrap();
        let dir = test_dir("guardian-generations");
        let first = GenerationGuardian::start(&memory, &dir.join("first.sock")).unwrap();
        memory
            .write_slice(&vec![0x22_u8; size], vm_memory::GuestAddress(0))
            .unwrap();
        let second = GenerationGuardian::start(&memory, &dir.join("second.sock")).unwrap();
        memory
            .write_slice(&vec![0x33_u8; size], vm_memory::GuestAddress(0))
            .unwrap();

        for (guardian, expected) in [(&first, 0x11), (&second, 0x22)] {
            let mut source = GuardianPageSource::connect(guardian.description()).unwrap();
            let mut actual = vec![0_u8; size];
            source.read_exact_at(0, 0, &mut actual).unwrap();
            assert!(actual.iter().all(|byte| *byte == expected));
        }
        drop(second);
        drop(first);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn guardian_serves_concurrent_clone_readers() {
        let size = MAX_READ_BYTES;
        let memory = GuestMemoryMmap::from_ranges(&[(vm_memory::GuestAddress(0), size)]).unwrap();
        memory
            .write_slice(&vec![0x6e_u8; size], vm_memory::GuestAddress(0))
            .unwrap();
        let dir = test_dir("guardian-fanout");
        let guardian = GenerationGuardian::start(&memory, &dir.join("ram.sock")).unwrap();
        let desc = guardian.description().clone();
        let readers = (0..32)
            .map(|_| {
                let desc = desc.clone();
                std::thread::spawn(move || {
                    let mut source = GuardianPageSource::connect(&desc).unwrap();
                    let mut page = vec![0_u8; MAX_READ_BYTES];
                    source.read_exact_at(0, 0, &mut page).unwrap();
                    assert!(page.iter().all(|byte| *byte == 0x6e));
                })
            })
            .collect::<Vec<_>>();
        for reader in readers {
            reader.join().unwrap();
        }
        drop(guardian);
        let _ = fs::remove_dir_all(dir);
    }
}
