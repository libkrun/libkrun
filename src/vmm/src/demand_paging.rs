// Copyright 2026. SPDX-License-Identifier: Apache-2.0

//! Linux `userfaultfd` demand paging for immutable guest-RAM generations.
//!
//! This module deliberately does not define checkpoint ownership or lineage.
//! It maps clone RAM anonymously, registers every mapping for missing-page
//! faults, and asks a [`PageSource`] for bytes as the clone touches them. The
//! generation store remains the source of truth; `userfaultfd` is only the
//! delivery mechanism.

#![cfg(target_os = "linux")]

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use utils::eventfd::EventFd;
use vm_memory::mmap::MmapRegion;
use vm_memory::{GuestAddress, GuestMemoryMmap, GuestRegionMmap};

const PAGE_SIZE: usize = 4096;
const INITIAL_PREFETCH_BYTES: usize = 64 * 1024;
const MAX_PREFETCH_BYTES: usize = 2 * 1024 * 1024;
const UFFD_API: u64 = 0xaa;
#[cfg(test)]
const UFFD_USER_MODE_ONLY: libc::c_int = 1;
const UFFD_EVENT_PAGEFAULT: u8 = 0x12;
const UFFDIO_REGISTER_MODE_MISSING: u64 = 1;
/// Reserved by SmolVM's single-purpose boot subprocess before it drops host
/// privileges. All inherited descriptors have already been closed at that
/// point, and the descriptor remains private to this process.
pub const PREOPENED_USERFAULTFD_FD: RawFd = 198;

const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;
const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;
const UFFDIO_TYPE: u32 = 0xaa;

const fn iowr(nr: u32, size: usize) -> libc::c_ulong {
    (((IOC_READ | IOC_WRITE) << IOC_DIRSHIFT)
        | ((size as u32) << IOC_SIZESHIFT)
        | (UFFDIO_TYPE << IOC_TYPESHIFT)
        | (nr << IOC_NRSHIFT)) as libc::c_ulong
}

const UFFDIO_REGISTER: libc::c_ulong = iowr(0x00, std::mem::size_of::<UffdRegister>());
const UFFDIO_COPY: libc::c_ulong = iowr(0x03, std::mem::size_of::<UffdCopy>());
const UFFDIO_API: libc::c_ulong = iowr(0x3f, std::mem::size_of::<UffdApi>());

#[repr(C)]
struct UffdApi {
    api: u64,
    features: u64,
    ioctls: u64,
}

#[repr(C)]
struct UffdRange {
    start: u64,
    len: u64,
}

#[repr(C)]
struct UffdRegister {
    range: UffdRange,
    mode: u64,
    ioctls: u64,
}

#[repr(C)]
struct UffdCopy {
    dst: u64,
    src: u64,
    len: u64,
    mode: u64,
    copy: i64,
}

/// Guest-visible layout of one demand-paged RAM region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DemandPageRegion {
    pub gpa: u64,
    pub len: u64,
}

/// Supplies immutable bytes for a RAM generation.
///
/// Calls are serialized on the pager thread. Implementations may therefore
/// keep a persistent connection and need not synchronize internally.
pub trait PageSource: Send + 'static {
    fn read_exact_at(
        &mut self,
        region_index: usize,
        offset: u64,
        destination: &mut [u8],
    ) -> io::Result<()>;
}

#[derive(Clone, Copy)]
struct HostRegion {
    start: u64,
    len: u64,
}

/// Selects whether faults originating in kernel context are accepted.
///
/// KVM requires [`KernelFaults`](Self::KernelFaults). `UserModeTest` exists so
/// unprivileged unit tests can exercise the pager on hosts that intentionally
/// disable kernel-fault-capable userfaultfd.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserfaultfdMode {
    KernelFaults,
    #[cfg(test)]
    UserModeTest,
}

/// Owns the fault-handler thread for a demand-paged guest-memory mapping.
/// Drop wakes and joins the handler before the caller releases the mappings.
pub struct DemandPager {
    stop_fd: OwnedFd,
    handler: Option<JoinHandle<()>>,
    status: Arc<Mutex<PagerStatus>>,
}

struct PagerStatus {
    failure: Option<String>,
    notifier: Option<FailureNotifier>,
}

struct FailureNotifier {
    exit_evt: EventFd,
    exit_code: Arc<AtomicI32>,
}

impl FailureNotifier {
    fn notify(&self) {
        self.exit_code.store(
            i32::from(crate::FC_EXIT_CODE_GENERIC_ERROR),
            Ordering::SeqCst,
        );
        let _ = self.exit_evt.write(1);
    }
}

impl DemandPager {
    /// Return a fatal pager error, if page delivery has failed.
    pub fn failure(&self) -> Option<String> {
        self.status
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .failure
            .clone()
    }

    /// Arrange for a fatal page-delivery failure to stop the VMM with a
    /// non-zero exit code. Installing this after the handler starts is safe:
    /// an already-recorded failure is signalled before this method returns.
    pub(crate) fn install_failure_notifier(&self, exit_evt: EventFd, exit_code: Arc<AtomicI32>) {
        let mut status = self
            .status
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        status.notifier = Some(FailureNotifier {
            exit_evt,
            exit_code,
        });
        if status.failure.is_some() {
            status.notifier.as_ref().unwrap().notify();
        }
    }
}

impl Drop for DemandPager {
    fn drop(&mut self) {
        let value = 1_u64.to_ne_bytes();
        // A failed handler may already be gone. The join below is still needed
        // to guarantee it no longer references guest mappings.
        unsafe {
            libc::write(
                self.stop_fd.as_raw_fd(),
                value.as_ptr().cast::<libc::c_void>(),
                value.len(),
            );
        }
        if let Some(handler) = self.handler.take() {
            let _ = handler.join();
        }
    }
}

/// Demand-paged memory together with the handler that must outlive it.
pub struct DemandPagedMemory {
    // Declaration order is intentional: Rust drops fields in declaration
    // order, so the pager exits before its mappings are unmapped.
    pub pager: DemandPager,
    pub memory: GuestMemoryMmap,
}

fn create_userfaultfd(mode: UserfaultfdMode) -> io::Result<OwnedFd> {
    if mode == UserfaultfdMode::KernelFaults
        && unsafe { libc::fcntl(PREOPENED_USERFAULTFD_FD, libc::F_GETFD) } >= 0
    {
        // The boot process creates this descriptor solely for libkrun restore;
        // taking ownership here guarantees it is closed with the pager.
        let fd = unsafe { OwnedFd::from_raw_fd(PREOPENED_USERFAULTFD_FD) };
        return initialize_userfaultfd(fd);
    }
    let flags = libc::O_CLOEXEC
        | libc::O_NONBLOCK
        | match mode {
            UserfaultfdMode::KernelFaults => 0,
            #[cfg(test)]
            UserfaultfdMode::UserModeTest => UFFD_USER_MODE_ONLY,
        };
    let fd = unsafe { libc::syscall(libc::SYS_userfaultfd, flags) as libc::c_int };
    if fd < 0 {
        let error = io::Error::last_os_error();
        let context = if mode == UserfaultfdMode::KernelFaults
            && error.raw_os_error() == Some(libc::EPERM)
        {
            "kernel-fault-capable userfaultfd is unavailable; grant the VMM a pre-opened /dev/userfaultfd descriptor or enable the host policy"
        } else {
            "create userfaultfd"
        };
        return Err(io::Error::new(error.kind(), format!("{context}: {error}")));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    initialize_userfaultfd(fd)
}

fn initialize_userfaultfd(fd: OwnedFd) -> io::Result<OwnedFd> {
    let mut api = UffdApi {
        api: UFFD_API,
        features: 0,
        ioctls: 0,
    };
    if unsafe { libc::ioctl(fd.as_raw_fd(), UFFDIO_API, &mut api) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if api.api != UFFD_API {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("kernel returned unexpected userfaultfd API {}", api.api),
        ));
    }
    Ok(fd)
}

fn register_range(uffd: RawFd, start: u64, len: u64) -> io::Result<()> {
    let mut registration = UffdRegister {
        range: UffdRange { start, len },
        mode: UFFDIO_REGISTER_MODE_MISSING,
        ioctls: 0,
    };
    if unsafe { libc::ioctl(uffd, UFFDIO_REGISTER, &mut registration) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn read_fault_message(uffd: RawFd) -> io::Result<Option<u64>> {
    // `struct uffd_msg` is a packed 32-byte record. Reading bytes avoids
    // unaligned references to its union fields.
    let mut message = [0_u8; 32];
    let read = unsafe {
        libc::read(
            uffd,
            message.as_mut_ptr().cast::<libc::c_void>(),
            message.len(),
        )
    };
    if read < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            return Ok(None);
        }
        return Err(error);
    }
    if read == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "userfaultfd closed",
        ));
    }
    if read as usize != message.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("short userfaultfd message: {read} bytes"),
        ));
    }
    if message[0] != UFFD_EVENT_PAGEFAULT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected userfaultfd event {}", message[0]),
        ));
    }
    Ok(Some(u64::from_ne_bytes(
        message[16..24].try_into().unwrap(),
    )))
}

fn resolve_fault(
    uffd: RawFd,
    regions: &[HostRegion],
    materialized: &mut [Vec<bool>],
    source: &mut dyn PageSource,
    fault_address: u64,
    buffer: &mut [u8],
) -> io::Result<u64> {
    let page = fault_address & !(PAGE_SIZE as u64 - 1);
    let (region_index, region) = regions
        .iter()
        .copied()
        .enumerate()
        .find(|(_, region)| page >= region.start && page < region.start + region.len)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("fault address 0x{fault_address:x} is outside guest RAM"),
            )
        })?;
    let source_offset = page - region.start;
    let page_index = usize::try_from(source_offset / PAGE_SIZE as u64)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "page index exceeds usize"))?;
    let pages = materialized
        .get_mut(region_index)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing residency map"))?;
    if pages.get(page_index).copied().unwrap_or(false) {
        // A prefetched page can still have a queued fault event. Its blocked
        // vCPU was already woken by the earlier UFFDIO_COPY.
        return Ok(page + PAGE_SIZE as u64);
    }

    // Prefetch only the contiguous unresolved run. Extending across a page
    // populated by an earlier out-of-order fault makes UFFDIO_COPY copy a
    // prefix and return EAGAIN; the copy itself remains valid, but treating
    // that expected overlap as fatal would stop the VM during restore.
    let max_pages = (buffer.len() / PAGE_SIZE).min(pages.len() - page_index);
    let page_count = pages[page_index..page_index + max_pages]
        .iter()
        .take_while(|present| !**present)
        .count();
    let length = page_count * PAGE_SIZE;
    if length == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "faulting region has no complete page",
        ));
    }
    source.read_exact_at(region_index, source_offset, &mut buffer[..length])?;
    let mut copy = UffdCopy {
        dst: page,
        src: buffer.as_ptr() as u64,
        len: length as u64,
        mode: 0,
        copy: 0,
    };
    if unsafe { libc::ioctl(uffd, UFFDIO_COPY, &mut copy) } < 0 {
        let error = io::Error::last_os_error();
        // A page can be populated outside this pager only during teardown.
        // EEXIST still means the triggering fault is resolved and is safe to
        // acknowledge; all normal overlap is avoided by `materialized`.
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "UFFDIO_COPY region {region_index} offset {source_offset:#x} length {length} copied {}: {error}",
                    copy.copy
                ),
            ));
        }
        pages[page_index] = true;
        return Ok(page + PAGE_SIZE as u64);
    }
    pages[page_index..page_index + page_count].fill(true);
    Ok(page + length as u64)
}

fn pager_loop(
    uffd: OwnedFd,
    stop_fd: RawFd,
    regions: Vec<HostRegion>,
    mut source: Box<dyn PageSource>,
    status: Arc<Mutex<PagerStatus>>,
) {
    let mut buffer = vec![0_u8; MAX_PREFETCH_BYTES];
    let mut prefetch_bytes = INITIAL_PREFETCH_BYTES;
    let mut expected_sequential_fault = None;
    let mut materialized = regions
        .iter()
        .map(|region| vec![false; region.len as usize / PAGE_SIZE])
        .collect::<Vec<_>>();
    let mut poll_fds = [
        libc::pollfd {
            fd: uffd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: stop_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let result = 'run: loop {
        let ready = unsafe { libc::poll(poll_fds.as_mut_ptr(), poll_fds.len() as _, -1) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break 'run Err(error);
        }
        if poll_fds[1].revents & libc::POLLIN != 0 {
            break 'run Ok(());
        }
        if poll_fds[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            break 'run Err(io::Error::other("userfaultfd poll failure"));
        }
        if poll_fds[0].revents & libc::POLLIN == 0 {
            continue;
        }
        loop {
            match read_fault_message(uffd.as_raw_fd()) {
                Ok(Some(address)) => {
                    let page = address & !(PAGE_SIZE as u64 - 1);
                    if expected_sequential_fault == Some(page) {
                        prefetch_bytes = (prefetch_bytes * 2).min(MAX_PREFETCH_BYTES);
                    } else {
                        prefetch_bytes = INITIAL_PREFETCH_BYTES;
                    }
                    match resolve_fault(
                        uffd.as_raw_fd(),
                        &regions,
                        &mut materialized,
                        source.as_mut(),
                        address,
                        &mut buffer[..prefetch_bytes],
                    ) {
                        Ok(next) => expected_sequential_fault = Some(next),
                        Err(error) => break 'run Err(error),
                    }
                }
                Ok(None) => break,
                Err(error) => break 'run Err(error),
            }
        }
    };
    if let Err(error) = result {
        record_failure(&status, error.to_string());
    }
}

fn record_failure(status: &Arc<Mutex<PagerStatus>>, failure: String) {
    eprintln!("ERROR demand-paged guest RAM failed: {failure}");
    log::error!("demand-paged guest RAM failed: {failure}");
    let mut status = status
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    status.failure = Some(failure);
    if let Some(notifier) = &status.notifier {
        notifier.notify();
    }
}

/// Create anonymous clone RAM and resolve its missing pages from `source`.
pub fn create_demand_paged_memory(
    regions: &[DemandPageRegion],
    source: Box<dyn PageSource>,
    mode: UserfaultfdMode,
) -> io::Result<DemandPagedMemory> {
    if regions.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "demand-paged memory has no regions",
        ));
    }
    let uffd = create_userfaultfd(mode)?;
    let prot = libc::PROT_READ | libc::PROT_WRITE;
    let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE;
    let mut guest_regions = Vec::with_capacity(regions.len());
    let mut host_regions = Vec::with_capacity(regions.len());

    for region in regions {
        let size = usize::try_from(region.len)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "RAM region exceeds usize"))?;
        if size == 0 || !size.is_multiple_of(PAGE_SIZE) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "RAM regions must be non-empty and page-aligned",
            ));
        }
        let pointer = unsafe { libc::mmap(std::ptr::null_mut(), size, prot, flags, -1, 0) };
        if pointer == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        if let Err(error) = register_range(uffd.as_raw_fd(), pointer as u64, region.len) {
            unsafe { libc::munmap(pointer, size) };
            return Err(error);
        }
        let mapping = unsafe { MmapRegion::build_raw_owned(pointer.cast(), size, prot, flags) }
            .map_err(|error| io::Error::other(format!("own RAM mapping: {error:?}")))?;
        let guest_region =
            GuestRegionMmap::new(mapping, GuestAddress(region.gpa)).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "guest RAM address overflow")
            })?;
        host_regions.push(HostRegion {
            start: pointer as u64,
            len: region.len,
        });
        guest_regions.push(guest_region);
    }
    let memory = GuestMemoryMmap::from_regions(guest_regions)
        .map_err(|error| io::Error::other(format!("build guest memory: {error:?}")))?;
    let stop_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if stop_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let stop_fd = unsafe { OwnedFd::from_raw_fd(stop_fd) };
    let status = Arc::new(Mutex::new(PagerStatus {
        failure: None,
        notifier: None,
    }));
    let thread_status = status.clone();
    let thread_stop_fd = stop_fd.as_raw_fd();
    let handler = thread::Builder::new()
        .name("smolvm-ram-pager".to_string())
        .spawn(move || pager_loop(uffd, thread_stop_fd, host_regions, source, thread_status))?;

    Ok(DemandPagedMemory {
        pager: DemandPager {
            stop_fd,
            handler: Some(handler),
            status,
        },
        memory,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use vm_memory::Bytes;

    struct ByteSource(Vec<Vec<u8>>);

    #[test]
    fn fatal_failure_notifies_the_vmm_with_a_nonzero_exit() {
        let status = Arc::new(Mutex::new(PagerStatus {
            failure: None,
            notifier: None,
        }));
        let exit_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
        let exit_code = Arc::new(AtomicI32::new(i32::MAX));
        {
            let mut locked = status.lock().unwrap();
            locked.notifier = Some(FailureNotifier {
                exit_evt: exit_evt.try_clone().unwrap(),
                exit_code: exit_code.clone(),
            });
        }

        record_failure(&status, "guardian disconnected".to_string());

        assert_eq!(exit_evt.read().unwrap(), 1);
        assert_eq!(
            exit_code.load(Ordering::SeqCst),
            i32::from(crate::FC_EXIT_CODE_GENERIC_ERROR)
        );
        assert_eq!(
            status.lock().unwrap().failure.as_deref(),
            Some("guardian disconnected")
        );
    }

    impl PageSource for ByteSource {
        fn read_exact_at(
            &mut self,
            region_index: usize,
            offset: u64,
            destination: &mut [u8],
        ) -> io::Result<()> {
            let source = self.0.get(region_index).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "unknown source region")
            })?;
            let start = usize::try_from(offset).unwrap();
            let end = start + destination.len();
            destination.copy_from_slice(source.get(start..end).ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "source region truncated")
            })?);
            Ok(())
        }
    }

    #[test]
    fn demand_pages_multiple_regions_and_keeps_writes_private() {
        let mut first = vec![0_u8; 4 * INITIAL_PREFETCH_BYTES];
        let mut second = vec![0_u8; 2 * INITIAL_PREFETCH_BYTES];
        for (index, byte) in first.iter_mut().enumerate() {
            *byte = (index.wrapping_mul(17) ^ 0xa5) as u8;
        }
        for (index, byte) in second.iter_mut().enumerate() {
            *byte = (index.wrapping_mul(31) ^ 0x5a) as u8;
        }
        let expected_first = first.clone();
        let expected_second = second.clone();
        let regions = [
            DemandPageRegion {
                gpa: 0,
                len: first.len() as u64,
            },
            DemandPageRegion {
                gpa: 0x20_0000,
                len: second.len() as u64,
            },
        ];
        let demand = create_demand_paged_memory(
            &regions,
            Box::new(ByteSource(vec![first, second])),
            UserfaultfdMode::UserModeTest,
        )
        .expect("create demand-paged memory");

        let mut actual = vec![0_u8; expected_first.len()];
        demand
            .memory
            .read_slice(&mut actual, GuestAddress(0))
            .expect("read first region");
        assert_eq!(actual, expected_first);
        let mut actual = vec![0_u8; expected_second.len()];
        demand
            .memory
            .read_slice(&mut actual, GuestAddress(0x20_0000))
            .expect("read second region");
        assert_eq!(actual, expected_second);

        demand
            .memory
            .write_slice(b"private", GuestAddress(0x1234))
            .expect("write private clone RAM");
        assert!(demand.pager.failure().is_none());
    }

    #[test]
    fn out_of_order_faults_do_not_overlap_prefetched_pages() {
        let mut bytes = vec![0_u8; 32 * PAGE_SIZE];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = index.wrapping_mul(29) as u8;
        }
        let expected = bytes.clone();
        let demand = create_demand_paged_memory(
            &[DemandPageRegion {
                gpa: 0,
                len: bytes.len() as u64,
            }],
            Box::new(ByteSource(vec![bytes])),
            UserfaultfdMode::UserModeTest,
        )
        .expect("create demand-paged memory");

        // Resolve the middle prefetch window first, then fault an earlier page
        // whose old 64 KiB prefetch range would overlap that window.
        let mut actual = [0_u8; 1];
        demand
            .memory
            .read_slice(&mut actual, GuestAddress((8 * PAGE_SIZE) as u64))
            .unwrap();
        assert_eq!(actual[0], expected[8 * PAGE_SIZE]);
        demand
            .memory
            .read_slice(&mut actual, GuestAddress(0))
            .unwrap();
        assert_eq!(actual[0], expected[0]);
        assert!(demand.pager.failure().is_none());
    }

    #[test]
    fn kernel_fault_mode_fails_actionably_when_host_policy_denies_it() {
        if std::fs::read_to_string("/proc/sys/vm/unprivileged_userfaultfd")
            .is_ok_and(|value| value.trim() == "0")
            && unsafe { libc::geteuid() } != 0
        {
            let result = create_userfaultfd(UserfaultfdMode::KernelFaults);
            let error = result.expect_err("host policy should reject kernel-fault userfaultfd");
            assert!(error.to_string().contains("pre-opened /dev/userfaultfd"));
        }
    }
}
