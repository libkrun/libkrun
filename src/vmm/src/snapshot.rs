// Copyright 2026. SPDX-License-Identifier: Apache-2.0
//
//! Guest-memory checkpoint: serialize/restore guest RAM to a byte stream.
//!
//! Platform-neutral by design — it operates only on the `GuestMemoryMmap` host
//! mapping and `std::io`, so the same code serves both the KVM (Linux) and HVF
//! (macOS) snapshot paths. The CoW-clone fast path (Linux `memfd` /
//! macOS `vm_remap(copy=TRUE)`) layers on top of these same region descriptors;
//! this eager byte-copy path is the correctness baseline validated in
//! `experiments/fork-poc` (Experiment 2: persist -> release -> restore,
//! bit-identical continuation).
//!
//! A full VM checkpoint composes three parts: this guest-memory image, the
//! paused-vCPU register state (`vstate` save_state), and the virtio device
//! state (`devices::virtio::persist`). See [`SnapshotManifest`] for the layout.

#[cfg(unix)]
use std::fs::File;
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::io::{Seek, SeekFrom};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::FileExt;

use vm_memory::{Address, FileOffset, GuestAddress, GuestMemory, GuestMemoryRegion};

use crate::GuestMemoryMmap;

/// Magic at the head of a snapshot manifest: "SMOLSNAP".
pub const SNAPSHOT_MAGIC: u64 = 0x534d4f4c534e4150;
/// On-disk snapshot format version. Bumped on any layout change (no backward
/// compatibility is maintained — alpha project).
pub const SNAPSHOT_VERSION: u32 = 1;

/// Describes one guest-RAM region in a memory snapshot: where it maps in guest
/// physical address space and how many bytes it holds. The region bytes follow
/// in the memory stream in region order; the descriptors carry the lengths, so
/// the byte stream itself needs no per-region framing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryRegionDesc {
    /// Guest physical base address of the region.
    pub gpa: u64,
    /// Region length in bytes.
    pub len: u64,
}

/// A file writer that preserves zero guest-memory pages as filesystem holes.
///
/// Durable checkpoints have a fixed logical memory layout, so restore still
/// sees the exact byte stream described by [`MemoryRegionDesc`]. Avoiding
/// physical writes for zero pages keeps the intermediate image sparse and lets
/// the tar/zstd packer skip those pages instead of compressing configured RAM
/// that the guest never touched.
#[cfg(unix)]
pub struct SparseFileWriter<'a> {
    file: &'a mut File,
    logical_offset: u64,
}

#[cfg(unix)]
impl<'a> SparseFileWriter<'a> {
    const PAGE_SIZE: usize = 4096;

    /// Wrap a newly-created or otherwise positionable memory image.
    pub fn new(file: &'a mut File) -> io::Result<Self> {
        let logical_offset = file.stream_position()?;
        Ok(Self {
            file,
            logical_offset,
        })
    }

    /// Publish the final logical length, including a trailing run of holes.
    pub fn finish(self) -> io::Result<()> {
        self.file.set_len(self.logical_offset)
    }

    fn page_end(base_offset: u64, index: usize, len: usize) -> usize {
        let absolute = base_offset + index as u64;
        let remaining_in_page = Self::PAGE_SIZE - absolute as usize % Self::PAGE_SIZE;
        index.saturating_add(remaining_in_page).min(len)
    }

    fn is_zero(bytes: &[u8]) -> bool {
        static ZERO_PAGE: [u8; SparseFileWriter::PAGE_SIZE] = [0; SparseFileWriter::PAGE_SIZE];
        debug_assert!(bytes.len() <= ZERO_PAGE.len());
        bytes == &ZERO_PAGE[..bytes.len()]
    }
}

#[cfg(unix)]
impl Write for SparseFileWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let base_offset = self.logical_offset;
        let final_offset = base_offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "memory image too large"))?;
        let mut index = 0;

        while index < bytes.len() {
            let zero =
                Self::is_zero(&bytes[index..Self::page_end(base_offset, index, bytes.len())]);
            let run_start = index;
            index = Self::page_end(base_offset, index, bytes.len());

            while index < bytes.len() {
                let page_end = Self::page_end(base_offset, index, bytes.len());
                if Self::is_zero(&bytes[index..page_end]) != zero {
                    break;
                }
                index = page_end;
            }

            let run = &bytes[run_start..index];
            if zero {
                let distance = i64::try_from(run.len()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "memory hole too large")
                })?;
                self.file.seek(SeekFrom::Current(distance))?;
            } else {
                self.file.write_all(run)?;
            }
        }

        self.logical_offset = final_offset;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

/// Serialize all guest-memory regions to `out`, returning the region layout the
/// restore side needs (each region's guest address + length). Bytes are written
/// in region order with no per-region framing.
///
/// The caller must have paused the vCPUs (and drained device workers) first so
/// the bytes are captured at a stable, consistent boundary.
pub fn write_guest_memory<W: Write>(
    mem: &GuestMemoryMmap,
    out: &mut W,
) -> io::Result<Vec<MemoryRegionDesc>> {
    let mut descs = Vec::new();
    for region in mem.iter() {
        let gpa = region.start_addr();
        let len = region.len();
        let host = mem
            .get_host_address(gpa)
            .map_err(|e| io::Error::other(format!("get_host_address: {e:?}")))?;
        // Safety: `host` points to `len` bytes of live guest RAM owned by the
        // mmap region currently being iterated. The VM is paused, so the bytes
        // are stable for the duration of the copy.
        let bytes = unsafe { std::slice::from_raw_parts(host as *const u8, len as usize) };
        out.write_all(bytes)?;
        descs.push(MemoryRegionDesc {
            gpa: gpa.raw_value(),
            len,
        });
    }
    Ok(descs)
}

/// Serialize guest memory into a sparse file using backing-file extents when
/// they are available.
///
/// Forkable RAM is already backed by a sparse file. Reading only its allocated
/// extents avoids scanning untouched logical RAM while the VM is paused. An
/// anonymous region, or a filesystem without sparse-seek support, falls back to
/// the page-aware content writer so the output format remains identical.
#[cfg(unix)]
pub fn write_guest_memory_sparse(
    mem: &GuestMemoryMmap,
    out: &mut File,
) -> io::Result<Vec<MemoryRegionDesc>> {
    let mut descs = Vec::new();
    let mut output_offset = out.stream_position()?;

    for region in mem.iter() {
        let gpa = region.start_addr();
        let len = region.len();
        let copied_from_backing = copy_region_backing_extents(region, out, output_offset)?;
        if !copied_from_backing {
            out.seek(SeekFrom::Start(output_offset))?;
            let host = mem
                .get_host_address(gpa)
                .map_err(|e| io::Error::other(format!("get_host_address: {e:?}")))?;
            // Safety: identical to `write_guest_memory`: this region owns `len`
            // stable bytes and the caller has frozen the VM.
            let bytes = unsafe { std::slice::from_raw_parts(host as *const u8, len as usize) };
            let mut sparse = SparseFileWriter::new(out)?;
            sparse.write_all(bytes)?;
            sparse.finish()?;
        }
        descs.push(MemoryRegionDesc {
            gpa: gpa.raw_value(),
            len,
        });
        output_offset = output_offset
            .checked_add(len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "memory image too large"))?;
    }

    out.set_len(output_offset)?;
    out.seek(SeekFrom::Start(output_offset))?;
    Ok(descs)
}

#[cfg(target_os = "linux")]
fn copy_region_backing_extents(
    region: &vm_memory::GuestRegionMmap,
    out: &mut File,
    output_offset: u64,
) -> io::Result<bool> {
    let Some(file_offset) = region.file_offset() else {
        return Ok(false);
    };
    // A file-backed MAP_PRIVATE view may contain anonymous CoW pages that are
    // newer than the backing file. The live-fork rebase uses MAP_FIXED, so the
    // vm-memory wrapper can still report its original MAP_SHARED flags; a
    // write-sealed backing is the authoritative signal in that case. Falling
    // back to the mapped-byte writer preserves those private pages while still
    // producing a sparse checkpoint image.
    if region.flags() & libc::MAP_PRIVATE != 0
        || backing_is_immutable_fork_generation(file_offset.file())?
    {
        return Ok(false);
    }
    let backing = file_offset.file();
    let backing_start = file_offset.start();
    copy_file_extents(backing, backing_start, region.len(), out, output_offset)
}

#[cfg(target_os = "linux")]
fn backing_is_immutable_fork_generation(backing: &File) -> io::Result<bool> {
    let seals = unsafe { libc::fcntl(backing.as_raw_fd(), libc::F_GET_SEALS) };
    if seals >= 0 {
        return Ok(seals & libc::F_SEAL_WRITE != 0);
    }
    let error = io::Error::last_os_error();
    if unsupported_seal_query(&error) {
        return Ok(false);
    }
    Err(error)
}

#[cfg(target_os = "linux")]
fn unsupported_seal_query(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EINVAL) | Some(libc::ENOTTY) | Some(libc::EOPNOTSUPP)
    )
}

#[cfg(target_os = "linux")]
fn copy_file_extents(
    backing: &File,
    backing_start: u64,
    len: u64,
    out: &mut File,
    output_offset: u64,
) -> io::Result<bool> {
    let backing_end = backing_start
        .checked_add(len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "memory region too large"))?;
    let mut cursor = backing_start;
    let mut buffer = vec![0_u8; 1024 * 1024];

    while cursor < backing_end {
        let seek_offset = i64::try_from(cursor).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "memory backing offset exceeds the host off_t range",
            )
        })?;
        // Safety: the fd remains owned by the live guest-memory region and the
        // converted offset fits the platform off_t.
        let data_offset = unsafe { libc::lseek(backing.as_raw_fd(), seek_offset, libc::SEEK_DATA) };
        if data_offset < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENXIO) {
                break;
            }
            if error.raw_os_error() == Some(libc::EINVAL)
                || error.raw_os_error() == Some(libc::ENOTSUP)
            {
                return Ok(false);
            }
            return Err(error);
        }
        let data = data_offset as u64;
        if data >= backing_end {
            break;
        }
        if data < cursor {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "memory backing data extent moved backwards",
            ));
        }

        // Safety: `data` came from lseek and is therefore a valid off_t.
        let hole = unsafe { libc::lseek(backing.as_raw_fd(), data_offset, libc::SEEK_HOLE) };
        if hole < 0 {
            return Err(io::Error::last_os_error());
        }
        let extent_end = (hole as u64).min(backing_end);
        if extent_end <= data {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "memory backing extent did not advance",
            ));
        }

        let relative = data - backing_start;
        let destination = output_offset.checked_add(relative).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "memory image offset overflow")
        })?;
        out.seek(SeekFrom::Start(destination))?;
        let mut source_offset = data;
        while source_offset < extent_end {
            let wanted = (extent_end - source_offset).min(buffer.len() as u64) as usize;
            let read = backing.read_at(&mut buffer[..wanted], source_offset)?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "memory backing changed during checkpoint",
                ));
            }
            out.write_all(&buffer[..read])?;
            source_offset += read as u64;
        }
        cursor = extent_end;
    }

    Ok(true)
}

#[cfg(target_os = "linux")]
fn copy_file_range_sparse(
    source: &File,
    source_offset: u64,
    len: u64,
    destination: &mut File,
    destination_offset: u64,
) -> io::Result<()> {
    destination.seek(SeekFrom::Start(destination_offset))?;
    let mut writer = SparseFileWriter::new(destination)?;
    let mut copied = 0_u64;
    let mut buffer = vec![0_u8; 1024 * 1024];
    while copied < len {
        let wanted = (len - copied).min(buffer.len() as u64) as usize;
        let offset = source_offset.checked_add(copied).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "memory image offset overflow")
        })?;
        let read = source.read_at(&mut buffer[..wanted], offset)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "memory image ended during promotion",
            ));
        }
        writer.write_all(&buffer[..read])?;
        copied += read as u64;
    }
    writer.finish()
}

#[cfg(all(unix, not(target_os = "linux")))]
fn copy_region_backing_extents<R: GuestMemoryRegion>(
    _region: &R,
    _out: &mut File,
    _output_offset: u64,
) -> io::Result<bool> {
    Ok(false)
}

/// Load guest-memory bytes from `inp` back into `mem`, using the region layout
/// captured by [`write_guest_memory`]. Each region's bytes are read directly
/// into the live host mapping. `mem` must have been built with a layout that
/// covers every `desc.gpa..desc.gpa+desc.len` range (i.e. the same VM config).
///
/// Must be called before the restored vCPUs are resumed.
pub fn read_guest_memory_into<R: Read>(
    mem: &GuestMemoryMmap,
    descs: &[MemoryRegionDesc],
    inp: &mut R,
) -> io::Result<()> {
    for desc in descs {
        let host = mem
            .get_host_address(GuestAddress(desc.gpa))
            .map_err(|e| io::Error::other(format!("get_host_address: {e:?}")))?;
        // Safety: `host` points to `desc.len` bytes of guest RAM for this
        // region, and the VM is not yet running, so writing into it is sound.
        let dst = unsafe { std::slice::from_raw_parts_mut(host, desc.len as usize) };
        inp.read_exact(dst)?;
    }
    Ok(())
}

/// Allocate guest memory with the captured physical layout and eagerly load a
/// complete memory image into it.
///
/// This is the durable-checkpoint counterpart to the live CoW mapping helpers:
/// the returned mapping owns all bytes and has no dependency on the process
/// that produced the snapshot. The caller may later materialize it into
/// file-backed memory when the restored VM is promoted to a fork source.
pub fn load_guest_memory<R: Read>(
    descs: &[MemoryRegionDesc],
    inp: &mut R,
) -> io::Result<GuestMemoryMmap> {
    if descs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "snapshot contains no guest-memory regions",
        ));
    }
    let ranges = descs
        .iter()
        .map(|desc| {
            let len = usize::try_from(desc.len).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "guest-memory region does not fit host address space",
                )
            })?;
            if len == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "zero-length guest-memory region",
                ));
            }
            Ok((GuestAddress(desc.gpa), len))
        })
        .collect::<io::Result<Vec<_>>>()?;
    let memory = GuestMemoryMmap::from_ranges(&ranges)
        .map_err(|error| io::Error::other(format!("allocate guest memory: {error:?}")))?;
    read_guest_memory_into(&memory, descs, inp)?;

    let mut trailing = [0_u8; 1];
    if inp.read(&mut trailing)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "guest-memory image has trailing bytes",
        ));
    }
    Ok(memory)
}

/// Map a complete memory image as the writable backing for guest RAM.
///
/// Unlike [`load_guest_memory`], this does not touch every configured byte at
/// restore time. Sparse holes remain holes and pages enter the host working set
/// only when the resumed guest accesses them. Each region retains a
/// [`FileOffset`], allowing a Linux restore to become a fork source without an
/// additional full-RAM materialization pass.
#[cfg(unix)]
pub fn map_guest_memory_file(
    descs: &[MemoryRegionDesc],
    file: &File,
) -> io::Result<GuestMemoryMmap> {
    if descs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "snapshot contains no guest-memory regions",
        ));
    }

    let mut offset = 0_u64;
    let ranges = descs
        .iter()
        .map(|desc| {
            let len = usize::try_from(desc.len).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "guest-memory region does not fit host address space",
                )
            })?;
            if len == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "zero-length guest-memory region",
                ));
            }
            let region_offset = offset;
            offset = offset.checked_add(desc.len).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "guest-memory image offset overflow",
                )
            })?;
            Ok((
                GuestAddress(desc.gpa),
                len,
                Some(FileOffset::new(file.try_clone()?, region_offset)),
            ))
        })
        .collect::<io::Result<Vec<_>>>()?;

    GuestMemoryMmap::from_ranges_with_files(ranges)
        .map_err(|error| io::Error::other(format!("map guest memory image: {error:?}")))
}

/// Promote a portable sparse memory image into sealable Linux memfds without
/// scanning or allocating its holes.
///
/// Portable checkpoints are regular files. They are ideal for demand-mapped
/// leaf restores, but cannot be sealed into an immutable live-fork generation.
/// A restored machine that will itself be forkable therefore needs private
/// memfd backing. Copying only filesystem data extents keeps this promotion
/// proportional to resident checkpoint pages rather than configured RAM.
#[cfg(target_os = "linux")]
pub fn map_guest_memory_file_forkable(
    descs: &[MemoryRegionDesc],
    file: &File,
) -> io::Result<GuestMemoryMmap> {
    if descs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "snapshot contains no guest-memory regions",
        ));
    }

    let mut source_offset = 0_u64;
    let ranges = descs
        .iter()
        .map(|desc| {
            let len = usize::try_from(desc.len).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "guest-memory region does not fit host address space",
                )
            })?;
            if len == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "zero-length guest-memory region",
                ));
            }
            let destination =
                crate::builder::create_guest_ram_memfd(len).map_err(io::Error::other)?;
            let mut destination_copy = destination.try_clone()?;
            if !copy_file_extents(file, source_offset, desc.len, &mut destination_copy, 0)? {
                copy_file_range_sparse(file, source_offset, desc.len, &mut destination_copy, 0)?;
            }
            source_offset = source_offset.checked_add(desc.len).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "guest-memory image too large")
            })?;
            Ok((
                GuestAddress(desc.gpa),
                len,
                Some(FileOffset::new(destination, 0)),
            ))
        })
        .collect::<io::Result<Vec<_>>>()?;

    let actual = file.metadata()?.len();
    if source_offset != actual {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("guest-memory image length {actual} does not match manifest {source_offset}"),
        ));
    }
    GuestMemoryMmap::from_ranges_with_files(ranges)
        .map_err(|error| io::Error::other(format!("map forkable guest memory: {error:?}")))
}

/// Total byte length of all regions in a descriptor list (the size of the
/// memory image stream).
pub fn memory_image_len(descs: &[MemoryRegionDesc]) -> u64 {
    descs.iter().map(|d| d.len).sum()
}

/// Copy every region's bytes from `src` guest memory into `dst` (same layout).
/// Used to restore a VM from an in-memory CoW snapshot (`cow_clone_guest_memory`)
/// back into the live, KVM-registered guest memory — the bounded counterpart to
/// streaming through [`write_guest_memory`]/[`read_guest_memory_into`].
pub fn copy_guest_memory(src: &GuestMemoryMmap, dst: &GuestMemoryMmap) -> io::Result<()> {
    let io_err = |m: String| io::Error::other(m);
    for region in src.iter() {
        let gpa = region.start_addr();
        let len = region.len() as usize;
        let s = src
            .get_host_address(gpa)
            .map_err(|e| io_err(format!("src get_host_address: {e:?}")))?;
        let d = dst
            .get_host_address(gpa)
            .map_err(|e| io_err(format!("dst get_host_address: {e:?}")))?;
        // Safety: both point to `len` bytes of guest RAM for this region; the VM
        // is paused so the bytes are stable, and the regions don't overlap.
        unsafe { std::ptr::copy_nonoverlapping(s as *const u8, d, len) };
    }
    Ok(())
}

/// Copy the current contents of a restored clone into fresh file-backed guest
/// memory so that clone can become the source of another copy-on-write fork.
///
/// A restored clone is made from raw `MAP_PRIVATE` mappings. Those mappings
/// deliberately do not retain [`FileOffset`] metadata, so they cannot be
/// described by [`memfd_region_descs`] for another process. Promotion pays one
/// eager copy of the mapped address space; subsequent descendants are ordinary
/// cheap CoW mappings of these new backing files.
pub fn materialize_guest_memory(
    src: &GuestMemoryMmap,
    fork_backed_regions: &[bool],
) -> io::Result<GuestMemoryMmap> {
    if src.num_regions() != fork_backed_regions.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "guest-memory region count {} does not match fork backing mask {}",
                src.num_regions(),
                fork_backed_regions.len()
            ),
        ));
    }
    let ranges = src
        .iter()
        .zip(fork_backed_regions.iter().copied())
        .map(|(region, file_backed)| {
            let size = region.len() as usize;
            let file = if file_backed {
                Some(FileOffset::new(
                    crate::builder::create_guest_ram_memfd(size).map_err(io::Error::other)?,
                    0,
                ))
            } else {
                None
            };
            Ok((region.start_addr(), size, file))
        })
        .collect::<io::Result<Vec<_>>>()?;
    let dst = GuestMemoryMmap::from_ranges_with_files(ranges)
        .map_err(|error| io::Error::other(format!("materialize guest memory: {error:?}")))?;
    copy_guest_memory(src, &dst)?;
    Ok(dst)
}

/// Return whether a restored guest-memory mapping must be copied into fresh
/// fork backing before it can become a live fork source.
///
/// A local fork clone normally has raw `MAP_PRIVATE` regions with no retained
/// [`FileOffset`], so promotion is required. A portable checkpoint retains its
/// sparse regular-file backing, but Linux regular files report `F_SEAL_SEAL`
/// without `F_SEAL_WRITE`: they cannot be made into the immutable generation
/// required by [`rebase_guest_memory_private`]. Treat that shape as requiring
/// promotion too instead of letting the first descendant fail at the fork
/// boundary.
pub fn restored_memory_needs_fork_backing(
    memory: &GuestMemoryMmap,
    fork_backed_regions: &[bool],
) -> io::Result<bool> {
    if memory.num_regions() != fork_backed_regions.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "guest-memory region count {} does not match fork backing mask {}",
                memory.num_regions(),
                fork_backed_regions.len()
            ),
        ));
    }

    for (region, fork_backed) in memory.iter().zip(fork_backed_regions.iter().copied()) {
        if !fork_backed {
            continue;
        }
        let Some(file_offset) = region.file_offset() else {
            return Ok(true);
        };

        #[cfg(not(target_os = "linux"))]
        let _ = file_offset;

        #[cfg(target_os = "linux")]
        {
            let seals = unsafe { libc::fcntl(file_offset.file().as_raw_fd(), libc::F_GET_SEALS) };
            if seals < 0 {
                let error = io::Error::last_os_error();
                if unsupported_seal_query(&error) {
                    return Ok(true);
                }
                return Err(error);
            }
            if seals & libc::F_SEAL_SEAL != 0 && seals & libc::F_SEAL_WRITE == 0 {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Copy-on-write clone of a `memfd`-backed guest memory image — the core of
/// fast, dense VM **fork** (plan §4/§9a). Each `memfd`-backed RAM region is
/// re-mapped `MAP_PRIVATE`, so the clone shares the parent's clean physical
/// pages and only copies a page when it is written: fork latency is independent
/// of RAM size, and N clones of a golden browser-ready VM share one copy of the
/// (unwritten) working set → pool density. Anonymous regions (device SHM/GPU,
/// not part of the CoW image) get a fresh private copy.
///
/// The parent must be paused/frozen at the fork point (its live `memfd` is the
/// shared base; later parent writes to un-CoW'd pages would otherwise leak into
/// clones — see plan §4). Linux-only; the macOS analogue is
/// `vm_remap(copy=TRUE)` on the anonymous HVF region.
#[cfg(target_os = "linux")]
pub fn cow_clone_guest_memory(parent: &GuestMemoryMmap) -> std::io::Result<GuestMemoryMmap> {
    use std::os::fd::AsRawFd;
    use vm_memory::GuestRegionMmap;
    use vm_memory::mmap::MmapRegion;

    let prot = libc::PROT_READ | libc::PROT_WRITE;
    let io_err = |m: String| io::Error::other(m);

    let mut regions: Vec<GuestRegionMmap> = Vec::new();
    for region in parent.iter() {
        let gpa = region.start_addr();
        let size = region.len() as usize;

        let (ptr, flags) = match region.file_offset() {
            // memfd-backed RAM → CoW clone (MAP_PRIVATE of the same memfd).
            Some(fo) => {
                let flags = libc::MAP_PRIVATE;
                // Safety: mapping `size` bytes of the parent's memfd at its
                // region offset; ptr is checked against MAP_FAILED below.
                let ptr = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        size,
                        prot,
                        flags,
                        fo.file().as_raw_fd(),
                        fo.start() as libc::off_t,
                    )
                };
                if ptr == libc::MAP_FAILED {
                    return Err(io::Error::last_os_error());
                }
                (ptr, flags)
            }
            // Anonymous region (device SHM/GPU): fresh private map + byte copy.
            None => {
                let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
                let ptr = unsafe { libc::mmap(std::ptr::null_mut(), size, prot, flags, -1, 0) };
                if ptr == libc::MAP_FAILED {
                    return Err(io::Error::last_os_error());
                }
                let src = parent
                    .get_host_address(gpa)
                    .map_err(|e| io_err(format!("get_host_address: {e:?}")))?;
                // Safety: both regions are `size` bytes and non-overlapping
                // (fresh mapping); the parent is frozen during the clone.
                unsafe { std::ptr::copy_nonoverlapping(src as *const u8, ptr as *mut u8, size) };
                (ptr, flags)
            }
        };

        // Safety: `ptr` is a live mapping of `size` bytes we just created; the
        // resulting MmapRegion takes ownership and munmaps it on drop.
        let mmap_region = unsafe { MmapRegion::build_raw_owned(ptr as *mut u8, size, prot, flags) }
            .map_err(|e| io_err(format!("build_raw: {e:?}")))?;
        let guest_region = GuestRegionMmap::new(mmap_region, gpa)
            .ok_or_else(|| io_err("guest region address overflow".to_string()))?;
        regions.push(guest_region);
    }

    GuestMemoryMmap::from_regions(regions).map_err(|e| io_err(format!("from_regions: {e:?}")))
}

/// Turn the live Linux guest-RAM mappings into private views of their current
/// memfd contents, then seal those memfds as an immutable fork generation.
///
/// The mapping addresses do not change. KVM and every quiesced virtio worker
/// therefore keep referring to the same host virtual addresses, while future
/// guest writes are private CoW faults and cannot modify the generation that
/// restored clones map from `/proc/<pid>/fd/<fd>`.
///
/// The VM must be paused and all device workers must be quiesced. Callers must
/// treat a failure after rebasing begins as non-retryable for that generation;
/// the source mapping remains valid, but the complete immutable boundary was
/// not published.
#[cfg(target_os = "linux")]
pub fn rebase_guest_memory_private(parent: &GuestMemoryMmap) -> io::Result<()> {
    struct Backing {
        host_address: *mut libc::c_void,
        len: usize,
        fd: libc::c_int,
        offset: libc::off_t,
    }

    let mut backings = Vec::new();
    for region in parent.iter() {
        let Some(file_offset) = region.file_offset() else {
            continue;
        };
        let host_address = parent
            .get_host_address(region.start_addr())
            .map_err(|error| io::Error::other(format!("guest RAM host address: {error:?}")))?
            .cast();
        backings.push(Backing {
            host_address,
            len: region.len() as usize,
            fd: file_offset.file().as_raw_fd(),
            offset: file_offset.start() as libc::off_t,
        });
    }
    if backings.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "guest RAM has no file-backed regions",
        ));
    }

    // Reject old/non-sealable backing before changing any mapping. Forkable
    // RAM created by current libkrun uses MFD_ALLOW_SEALING.
    for backing in &backings {
        let seals = unsafe { libc::fcntl(backing.fd, libc::F_GET_SEALS) };
        if seals < 0 {
            return Err(io::Error::last_os_error());
        }
        if seals & libc::F_SEAL_SEAL != 0 && seals & libc::F_SEAL_WRITE == 0 {
            return Err(io::Error::other(
                "guest RAM memfd is sealed against adding the required write seal",
            ));
        }
    }

    // Prevent any new writable shared mapping or write(2) before removing the
    // source's existing MAP_SHARED views. Existing mappings remain writable
    // until the MAP_FIXED replacement immediately below.
    for backing in &backings {
        let seals = unsafe { libc::fcntl(backing.fd, libc::F_GET_SEALS) };
        if seals & libc::F_SEAL_FUTURE_WRITE == 0 {
            let result =
                unsafe { libc::fcntl(backing.fd, libc::F_ADD_SEALS, libc::F_SEAL_FUTURE_WRITE) };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }

    for backing in &backings {
        let mapped = unsafe {
            libc::mmap(
                backing.host_address,
                backing.len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_FIXED,
                backing.fd,
                backing.offset,
            )
        };
        if mapped == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        if mapped != backing.host_address {
            return Err(io::Error::other(
                "MAP_FIXED guest RAM rebase returned a different address",
            ));
        }
    }

    // No writable shared mapping remains. Make the fork generation immutable
    // even to accidental host-side pwrite/ftruncate calls.
    let immutable_seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;
    for backing in &backings {
        let seals = unsafe { libc::fcntl(backing.fd, libc::F_GET_SEALS) };
        let missing = immutable_seals & !seals;
        if missing != 0 {
            let result = unsafe { libc::fcntl(backing.fd, libc::F_ADD_SEALS, missing) };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    for backing in &backings {
        let seals = unsafe { libc::fcntl(backing.fd, libc::F_GET_SEALS) };
        if seals & libc::F_SEAL_SEAL == 0 {
            let result = unsafe { libc::fcntl(backing.fd, libc::F_ADD_SEALS, libc::F_SEAL_SEAL) };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }

    Ok(())
}

/// Return whether every file-backed RAM region is already an immutable fork
/// generation. This distinguishes the first zero-copy rebase from later
/// snapshots of the source's private COW view.
#[cfg(target_os = "linux")]
pub fn guest_memory_backing_is_immutable(parent: &GuestMemoryMmap) -> io::Result<bool> {
    let mut found = false;
    for region in parent.iter() {
        let Some(file_offset) = region.file_offset() else {
            continue;
        };
        found = true;
        let seals = unsafe { libc::fcntl(file_offset.file().as_raw_fd(), libc::F_GET_SEALS) };
        if seals < 0 {
            return Err(io::Error::last_os_error());
        }
        if seals & libc::F_SEAL_WRITE == 0 {
            return Ok(false);
        }
    }
    if !found {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "guest RAM has no file-backed regions",
        ));
    }
    Ok(true)
}

/// An exact RAM generation being materialized by a short-lived fork child.
///
/// The VMM starts this only while vCPUs and device workers are quiesced. The
/// child inherits that exact address-space boundary through Linux COW and uses
/// only async-signal-safe syscalls to copy bytes into fresh memfds. The parent
/// can resume immediately, then wait for [`Self::finish`] without extending the
/// guest-visible pause.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub struct ForkGenerationCopy {
    child_pid: libc::pid_t,
    status_fd: libc::c_int,
    files: Vec<File>,
    descs: Vec<MemfdRegionDesc>,
    finished: bool,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl ForkGenerationCopy {
    pub fn finish(mut self) -> io::Result<(Vec<MemfdRegionDesc>, Vec<File>)> {
        let mut child_errno = 0_i32;
        let mut read = 0_usize;
        while read < std::mem::size_of::<i32>() {
            let result = unsafe {
                libc::read(
                    self.status_fd,
                    (&mut child_errno as *mut i32)
                        .cast::<libc::c_void>()
                        .add(read),
                    std::mem::size_of::<i32>() - read,
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
                    "RAM generation worker exited without status",
                ));
            }
            read += result as usize;
        }
        unsafe { libc::close(self.status_fd) };
        self.status_fd = -1;

        let mut status = 0;
        loop {
            let result = unsafe { libc::waitpid(self.child_pid, &mut status, 0) };
            if result == self.child_pid {
                break;
            }
            if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(io::Error::last_os_error());
        }
        self.child_pid = -1;
        if child_errno != 0 || !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            return Err(if child_errno != 0 {
                io::Error::from_raw_os_error(child_errno)
            } else {
                io::Error::other("RAM generation worker failed")
            });
        }

        let immutable =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        for file in &self.files {
            let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, immutable) };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        self.finished = true;
        Ok((
            std::mem::take(&mut self.descs),
            std::mem::take(&mut self.files),
        ))
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl Drop for ForkGenerationCopy {
    fn drop(&mut self) {
        if self.status_fd >= 0 {
            unsafe { libc::close(self.status_fd) };
            self.status_fd = -1;
        }
        if !self.finished && self.child_pid > 0 {
            unsafe {
                libc::kill(self.child_pid, libc::SIGKILL);
                libc::waitpid(self.child_pid, std::ptr::null_mut(), 0);
            }
            self.child_pid = -1;
        }
    }
}

/// Begin materializing the source's current private RAM into a fresh immutable
/// generation. Call only at a fully quiesced snapshot boundary.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn start_fork_generation_copy(parent: &GuestMemoryMmap) -> io::Result<ForkGenerationCopy> {
    struct CopyRegion {
        source: *const u8,
        len: usize,
        destination_fd: libc::c_int,
    }

    unsafe fn is_zero(source: *const u8, len: usize) -> bool {
        let mut offset = 0_usize;
        while offset + std::mem::size_of::<u64>() <= len {
            if unsafe { std::ptr::read_unaligned(source.add(offset).cast::<u64>()) } != 0 {
                return false;
            }
            offset += std::mem::size_of::<u64>();
        }
        while offset < len {
            if unsafe { *source.add(offset) } != 0 {
                return false;
            }
            offset += 1;
        }
        true
    }

    let mut files = Vec::new();
    let mut descs = Vec::new();
    let mut copies = Vec::new();
    for region in parent.iter() {
        let len = region.len() as usize;
        let source = parent
            .get_host_address(region.start_addr())
            .map_err(|error| io::Error::other(format!("guest RAM host address: {error:?}")))?;
        let file = crate::builder::create_guest_ram_memfd(len).map_err(io::Error::other)?;
        descs.push(MemfdRegionDesc {
            gpa: region.start_addr().raw_value(),
            len: region.len(),
            fd: file.as_raw_fd(),
            offset: 0,
            path: String::new(),
        });
        copies.push(CopyRegion {
            source: source.cast_const(),
            len,
            destination_fd: file.as_raw_fd(),
        });
        files.push(file);
    }
    if copies.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "guest RAM has no regions",
        ));
    }

    let mut status_pipe = [-1; 2];
    if unsafe { libc::pipe2(status_pipe.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // Bypass pthread_atfork handlers: this multithreaded VMM deliberately uses
    // a syscall-only child, so inherited allocator/library locks are never
    // touched. Registered atfork callbacks would add unrelated deadlock risk.
    let child_pid = unsafe { libc::syscall(libc::SYS_fork) as libc::pid_t };
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
        let mut child_errno = 0_i32;
        const PAGE_SIZE: usize = 4096;
        const COPY_CHUNK: usize = 16 * 1024 * 1024;
        'regions: for copy in &copies {
            let mut offset = 0_usize;
            while offset < copy.len {
                let page_len = (copy.len - offset).min(PAGE_SIZE);
                if unsafe { is_zero(copy.source.add(offset), page_len) } {
                    offset += page_len;
                    continue;
                }

                let run_start = offset;
                offset += page_len;
                while offset < copy.len && offset - run_start < COPY_CHUNK {
                    let page_len = (copy.len - offset).min(PAGE_SIZE);
                    if unsafe { is_zero(copy.source.add(offset), page_len) } {
                        break;
                    }
                    offset += page_len;
                }
                let mut written = 0_usize;
                let wanted = offset - run_start;
                while written < wanted {
                    let result = unsafe {
                        libc::pwrite(
                            copy.destination_fd,
                            copy.source.add(run_start + written).cast::<libc::c_void>(),
                            wanted - written,
                            (run_start + written) as libc::off_t,
                        )
                    };
                    if result < 0 {
                        let error = io::Error::last_os_error();
                        if error.kind() == io::ErrorKind::Interrupted {
                            continue;
                        }
                        child_errno = error.raw_os_error().unwrap_or(libc::EIO);
                        break 'regions;
                    }
                    if result == 0 {
                        child_errno = libc::EIO;
                        break 'regions;
                    }
                    written += result as usize;
                }
            }
        }
        let status = child_errno.to_ne_bytes();
        let mut written = 0_usize;
        while written < status.len() {
            let result = unsafe {
                libc::write(
                    status_pipe[1],
                    status.as_ptr().add(written).cast::<libc::c_void>(),
                    status.len() - written,
                )
            };
            if result < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            if result == 0 {
                break;
            }
            written += result as usize;
        }
        unsafe { libc::_exit(i32::from(child_errno != 0)) };
    }

    unsafe { libc::close(status_pipe[1]) };
    Ok(ForkGenerationCopy {
        child_pid,
        status_fd: status_pipe[0],
        files,
        descs,
        finished: false,
    })
}

/// A point-in-time macOS guest-RAM generation being written after the source
/// VM has resumed. `mach_vm_remap(copy = TRUE)` creates each immutable COW
/// alias while the VM is quiesced; the worker only materializes those aliases
/// into files that independent clone processes can map.
#[cfg(target_os = "macos")]
pub struct MacForkGenerationCopy {
    worker: Option<std::thread::JoinHandle<io::Result<MacGenerationOutput>>>,
}

#[cfg(target_os = "macos")]
struct MacGenerationOutput {
    descs: Vec<MemfdRegionDesc>,
    paths: Vec<std::path::PathBuf>,
}

/// Files owned by one in-progress macOS generation. Keeping cleanup in a
/// drop guard covers construction failures, thread-spawn failures, partial
/// publication, and worker failures without ever unlinking a pre-existing
/// path.
#[cfg(target_os = "macos")]
struct MacGenerationArtifacts {
    paths: Vec<std::path::PathBuf>,
    keep: bool,
}

#[cfg(target_os = "macos")]
impl MacGenerationArtifacts {
    fn new() -> Self {
        Self {
            paths: Vec::new(),
            keep: false,
        }
    }

    fn own(&mut self, path: std::path::PathBuf) {
        self.paths.push(path);
    }

    fn renamed(&mut self, old: &std::path::Path, new: std::path::PathBuf) {
        let path = self
            .paths
            .iter_mut()
            .find(|path| path.as_path() == old)
            .expect("published macOS generation file must be owned");
        *path = new;
    }

    fn commit(&mut self) {
        self.keep = true;
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacGenerationArtifacts {
    fn drop(&mut self) {
        if !self.keep {
            for path in &self.paths {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

#[cfg(target_os = "macos")]
impl MacForkGenerationCopy {
    pub fn finish(mut self) -> io::Result<Vec<MemfdRegionDesc>> {
        let worker = self
            .worker
            .take()
            .ok_or_else(|| io::Error::other("macOS RAM generation worker already consumed"))?;
        let output = worker
            .join()
            .map_err(|_| io::Error::other("macOS RAM generation worker panicked"))??;
        Ok(output.descs)
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacForkGenerationCopy {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take()
            && let Ok(Ok(output)) = worker.join()
        {
            for path in output.paths {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
struct MachCowAlias {
    address: u64,
    len: usize,
}

#[cfg(target_os = "macos")]
impl Drop for MachCowAlias {
    fn drop(&mut self) {
        const KERN_SUCCESS: i32 = 0;
        let result = unsafe {
            mach_vm_deallocate(
                mach_task_self_,
                self.address,
                u64::try_from(self.len).unwrap_or(u64::MAX),
            )
        };
        debug_assert_eq!(result, KERN_SUCCESS, "mach_vm_deallocate failed: {result}");
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    static mach_task_self_: u32;
    fn mach_vm_remap(
        target_task: u32,
        target_address: *mut u64,
        size: u64,
        mask: u64,
        flags: i32,
        source_task: u32,
        source_address: u64,
        copy: i32,
        current_protection: *mut i32,
        maximum_protection: *mut i32,
        inheritance: i32,
    ) -> i32;
    fn mach_vm_deallocate(target_task: u32, address: u64, size: u64) -> i32;
}

#[cfg(target_os = "macos")]
fn macos_cow_alias(source: *mut u8, len: usize) -> io::Result<MachCowAlias> {
    const KERN_SUCCESS: i32 = 0;
    const VM_FLAGS_ANYWHERE: i32 = 1;
    const VM_INHERIT_NONE: i32 = 2;
    let mut address = 0_u64;
    let mut current_protection = 0_i32;
    let mut maximum_protection = 0_i32;
    let result = unsafe {
        mach_vm_remap(
            mach_task_self_,
            &mut address,
            len as u64,
            0,
            VM_FLAGS_ANYWHERE,
            mach_task_self_,
            source as u64,
            1,
            &mut current_protection,
            &mut maximum_protection,
            VM_INHERIT_NONE,
        )
    };
    if result != KERN_SUCCESS {
        return Err(io::Error::other(format!(
            "mach_vm_remap(copy=TRUE) failed with kern_return_t {result}"
        )));
    }
    if current_protection & libc::PROT_READ == 0 {
        unsafe {
            mach_vm_deallocate(mach_task_self_, address, len as u64);
        }
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "macOS RAM generation alias is not readable",
        ));
    }
    Ok(MachCowAlias { address, len })
}

/// Capture all file-backed guest RAM as immutable Mach COW aliases and begin
/// materializing those aliases into the snapshot directory. Anonymous device
/// SHM retains the established fork behavior and is represented as anonymous
/// clone memory; ordinary guest RAM is always file-backed for a forkable VM.
#[cfg(target_os = "macos")]
pub fn start_macos_fork_generation_copy(
    parent: &GuestMemoryMmap,
    generation_dir: &std::path::Path,
) -> io::Result<MacForkGenerationCopy> {
    struct CopyRegion {
        alias: MachCowAlias,
        file: File,
        partial_path: std::path::PathBuf,
        final_path: std::path::PathBuf,
        desc: MemfdRegionDesc,
    }

    let generation_dir = generation_dir.canonicalize()?;
    let mut copies = Vec::new();
    let mut anonymous = Vec::new();
    let mut artifacts = MacGenerationArtifacts::new();
    for (index, region) in parent.iter().enumerate() {
        let gpa = region.start_addr();
        let len = region.len() as usize;
        if region.file_offset().is_none() {
            anonymous.push(MemfdRegionDesc {
                gpa: gpa.raw_value(),
                len: region.len(),
                fd: -1,
                offset: 0,
                path: String::new(),
            });
            continue;
        }
        let source = parent
            .get_host_address(gpa)
            .map_err(|error| io::Error::other(format!("guest RAM host address: {error:?}")))?;
        let alias = macos_cow_alias(source, len)?;
        let final_path = generation_dir.join(format!("memory-{index}.bin"));
        let partial_path = generation_dir.join(format!("memory-{index}.bin.partial"));
        match std::fs::metadata(&final_path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "macOS RAM generation already exists: {}",
                        final_path.display()
                    ),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&partial_path)?;
        artifacts.own(partial_path.clone());
        file.set_len(region.len())?;
        let path = final_path
            .to_str()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "macOS RAM generation path is not UTF-8",
                )
            })?
            .to_string();
        copies.push(CopyRegion {
            alias,
            file,
            partial_path,
            final_path,
            desc: MemfdRegionDesc {
                gpa: gpa.raw_value(),
                len: region.len(),
                fd: 0,
                offset: 0,
                path,
            },
        });
    }
    if copies.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "guest RAM has no file-backed regions",
        ));
    }

    let worker = std::thread::Builder::new()
        .name("smolvm-macos-ram-generation".to_string())
        .spawn(move || {
            const PAGE_SIZE: usize = 16 * 1024;
            const COPY_CHUNK: usize = 16 * 1024 * 1024;
            (|| {
                for copy in &copies {
                    let source = copy.alias.address as *const u8;
                    let mut offset = 0_usize;
                    while offset < copy.alias.len {
                        let page_len = (copy.alias.len - offset).min(PAGE_SIZE);
                        let page =
                            unsafe { std::slice::from_raw_parts(source.add(offset), page_len) };
                        if page.iter().all(|byte| *byte == 0) {
                            offset += page_len;
                            continue;
                        }
                        let run_start = offset;
                        offset += page_len;
                        while offset < copy.alias.len && offset - run_start < COPY_CHUNK {
                            let page_len = (copy.alias.len - offset).min(PAGE_SIZE);
                            let page =
                                unsafe { std::slice::from_raw_parts(source.add(offset), page_len) };
                            if page.iter().all(|byte| *byte == 0) {
                                break;
                            }
                            offset += page_len;
                        }
                        let mut written = 0_usize;
                        let wanted = offset - run_start;
                        while written < wanted {
                            let count = unsafe {
                                libc::pwrite(
                                    copy.file.as_raw_fd(),
                                    source.add(run_start + written).cast(),
                                    wanted - written,
                                    (run_start + written) as libc::off_t,
                                )
                            };
                            if count < 0 {
                                let error = io::Error::last_os_error();
                                if error.kind() == io::ErrorKind::Interrupted {
                                    continue;
                                }
                                return Err(error);
                            }
                            if count == 0 {
                                return Err(io::Error::new(
                                    io::ErrorKind::WriteZero,
                                    "macOS RAM generation write returned zero",
                                ));
                            }
                            written += count as usize;
                        }
                    }
                    copy.file.sync_all()?;
                }
                for copy in &copies {
                    std::fs::rename(&copy.partial_path, &copy.final_path)?;
                    artifacts.renamed(&copy.partial_path, copy.final_path.clone());
                }
                File::open(&generation_dir)?.sync_all()?;
                let mut descs = copies
                    .iter()
                    .map(|copy| copy.desc.clone())
                    .collect::<Vec<_>>();
                descs.extend(anonymous);
                descs.sort_by_key(|desc| desc.gpa);
                let paths = copies.iter().map(|copy| copy.final_path.clone()).collect();
                artifacts.commit();
                Ok(MacGenerationOutput { descs, paths })
            })()
        })?;
    Ok(MacForkGenerationCopy {
        worker: Some(worker),
    })
}

/// Describes one guest-RAM region for cross-process CoW fork: its guest address,
/// length, and (for memfd-backed RAM) the owner process's fd number + offset so a
/// clone can open `/proc/<pid>/fd/<fd>` and `mmap(MAP_PRIVATE)` it. `fd < 0` marks
/// an anonymous region (device SHM/GPU) the clone cannot CoW-share — it gets a
/// fresh zeroed mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemfdRegionDesc {
    pub gpa: u64,
    pub len: u64,
    pub fd: i32,
    pub offset: u64,
    /// macOS only: filesystem path of the backing guest-RAM file (recovered via
    /// `F_GETPATH`), used by a clone to open + `mmap(MAP_PRIVATE)` it. Empty on
    /// Linux, where the clone instead reaches the backing memfd through
    /// `/proc/<owner_pid>/fd/<fd>`. Empty path == anonymous region (no CoW).
    pub path: String,
}

/// Enumerate the guest-memory regions of a (memfd-backed) VM for fork: returns
/// each region's gpa/len + the backing memfd fd (this process's fd number) and
/// offset, or `fd = -1` for anonymous regions. The owning process must stay
/// alive (frozen) so a clone can reach the fds via `/proc/<pid>/fd`.
#[cfg(target_os = "linux")]
pub fn memfd_region_descs(mem: &GuestMemoryMmap) -> Vec<MemfdRegionDesc> {
    use std::os::fd::AsRawFd;
    mem.iter()
        .map(|region| {
            let (fd, offset) = match region.file_offset() {
                Some(fo) => (fo.file().as_raw_fd(), fo.start()),
                None => (-1, 0),
            };
            MemfdRegionDesc {
                gpa: region.start_addr().raw_value(),
                len: region.len(),
                fd,
                offset,
                path: String::new(),
            }
        })
        .collect()
}

/// macOS variant of [`memfd_region_descs`]: records each region's backing-file
/// path (recovered via `F_GETPATH` on the open fd) so a clone can open + CoW-map
/// it. macOS has no `/proc/<pid>/fd`, so cross-process sharing goes through the
/// file path instead; the owner must stay alive (frozen) and the file must
/// remain on disk for the clone's lifetime. Anonymous regions get an empty path.
#[cfg(target_os = "macos")]
pub fn memfd_region_descs(mem: &GuestMemoryMmap) -> Vec<MemfdRegionDesc> {
    use std::os::fd::AsRawFd;
    mem.iter()
        .map(|region| {
            let (path, offset) = match region.file_offset() {
                Some(fo) => {
                    let mut buf = [0i8; libc::PATH_MAX as usize];
                    let rc = unsafe {
                        libc::fcntl(fo.file().as_raw_fd(), libc::F_GETPATH, buf.as_mut_ptr())
                    };
                    let path = if rc == 0 {
                        unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
                            .to_string_lossy()
                            .into_owned()
                    } else {
                        String::new()
                    };
                    (path, fo.start())
                }
                None => (String::new(), 0),
            };
            MemfdRegionDesc {
                gpa: region.start_addr().raw_value(),
                len: region.len(),
                fd: if path.is_empty() { -1 } else { 0 },
                offset,
                path,
            }
        })
        .collect()
}

/// Build a clone's guest memory as a CoW view of another process's memfd-backed
/// RAM: for each descriptor, open `/proc/<owner_pid>/fd/<fd>` and
/// `mmap(MAP_PRIVATE)` it (clean pages shared with the frozen owner → density;
/// writes copy on demand). Anonymous regions get a fresh zeroed private mapping.
/// The owner process must be alive and frozen for the duration.
#[cfg(target_os = "linux")]
pub fn open_cow_memory_from_pid(
    owner_pid: i32,
    descs: &[MemfdRegionDesc],
) -> io::Result<GuestMemoryMmap> {
    use std::os::fd::AsRawFd;
    use vm_memory::GuestRegionMmap;
    use vm_memory::mmap::MmapRegion;

    let prot = libc::PROT_READ | libc::PROT_WRITE;
    let io_err = |m: String| io::Error::other(m);
    let mut regions: Vec<GuestRegionMmap> = Vec::with_capacity(descs.len());

    for d in descs {
        let size = d.len as usize;
        let (ptr, flags) = if d.fd >= 0 {
            // Open the owner's memfd via /proc and CoW-map it.
            let path = format!("/proc/{owner_pid}/fd/{}", d.fd);
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .map_err(|e| io_err(format!("open {path}: {e}")))?;
            let flags = libc::MAP_PRIVATE;
            // Safety: mapping `size` bytes of the owner's memfd at `offset`; the
            // mapping holds its own reference, so `file` may be dropped after.
            let ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    size,
                    prot,
                    flags,
                    file.as_raw_fd(),
                    d.offset as libc::off_t,
                )
            };
            (ptr, flags)
        } else {
            let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
            let ptr = unsafe { libc::mmap(std::ptr::null_mut(), size, prot, flags, -1, 0) };
            (ptr, flags)
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let mmap_region = unsafe { MmapRegion::build_raw_owned(ptr as *mut u8, size, prot, flags) }
            .map_err(|e| io_err(format!("build_raw: {e:?}")))?;
        let guest_region = GuestRegionMmap::new(mmap_region, GuestAddress(d.gpa))
            .ok_or_else(|| io_err("guest region address overflow".to_string()))?;
        regions.push(guest_region);
    }

    GuestMemoryMmap::from_regions(regions).map_err(|e| io_err(format!("from_regions: {e:?}")))
}

/// macOS variant of [`open_cow_memory_from_pid`]: opens each region's backing
/// file *by path* and `mmap(MAP_PRIVATE)`s it (clean pages shared CoW with the
/// frozen owner → density; writes copy on demand). Anonymous regions (empty
/// path) get a fresh zeroed private mapping. The owner process must be alive and
/// frozen and the backing files must remain on disk for the clone's lifetime.
#[cfg(target_os = "macos")]
pub fn open_cow_memory_from_paths(descs: &[MemfdRegionDesc]) -> io::Result<GuestMemoryMmap> {
    use std::os::fd::AsRawFd;
    use vm_memory::GuestRegionMmap;
    use vm_memory::mmap::MmapRegion;

    let prot = libc::PROT_READ | libc::PROT_WRITE;
    let io_err = |m: String| io::Error::other(m);
    let mut regions: Vec<GuestRegionMmap> = Vec::with_capacity(descs.len());

    for d in descs {
        let size = d.len as usize;
        let (ptr, flags) = if !d.path.is_empty() {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&d.path)
                .map_err(|e| io_err(format!("open {}: {e}", d.path)))?;
            let flags = libc::MAP_PRIVATE;
            // Safety: mapping `size` bytes of the owner's guest-RAM file at
            // `offset`; the mapping holds its own reference, so `file` may drop.
            let ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    size,
                    prot,
                    flags,
                    file.as_raw_fd(),
                    d.offset as libc::off_t,
                )
            };
            (ptr, flags)
        } else {
            let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
            let ptr = unsafe { libc::mmap(std::ptr::null_mut(), size, prot, flags, -1, 0) };
            (ptr, flags)
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let mmap_region = unsafe { MmapRegion::build_raw_owned(ptr as *mut u8, size, prot, flags) }
            .map_err(|e| io_err(format!("build_raw: {e:?}")))?;
        let guest_region = GuestRegionMmap::new(mmap_region, GuestAddress(d.gpa))
            .ok_or_else(|| io_err("guest region address overflow".to_string()))?;
        regions.push(guest_region);
    }

    GuestMemoryMmap::from_regions(regions).map_err(|e| io_err(format!("from_regions: {e:?}")))
}

/// Windows variant of [`memfd_region_descs`]: records each region's backing-file
/// path (recovered via `GetFinalPathNameByHandleW` on the open handle) so a clone
/// can open it. Windows has no `/proc/<pid>/fd`, so cross-process sharing goes
/// through the file path (the macOS model); the owner must stay alive (frozen)
/// and the file must remain on disk for the clone's lifetime. Anonymous regions
/// get an empty path.
#[cfg(target_os = "windows")]
pub fn memfd_region_descs(mem: &GuestMemoryMmap) -> Vec<MemfdRegionDesc> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW,
    };
    use windows_sys::Win32::System::Memory::FlushViewOfFile;

    mem.iter()
        .map(|region| {
            // Flush the golden's mapped guest-RAM writes to the backing file so a
            // clone's freshly-created copy-on-write section reads coherent data
            // (a new file-mapping section is not guaranteed to observe another
            // section's not-yet-flushed dirty pages).
            if region.file_offset().is_some()
                && let Ok(host) = mem.get_host_address(region.start_addr())
            {
                // SAFETY: `host` is this region's live mapped view of `len` bytes.
                unsafe { FlushViewOfFile(host as *const core::ffi::c_void, region.len() as usize) };
            }
            let (path, offset) = match region.file_offset() {
                Some(fo) => {
                    let handle = fo.file().as_raw_handle();
                    let mut buf = vec![0u16; 32768];
                    // SAFETY: `handle` is an open file handle; `buf` is a valid,
                    // sized wide-char buffer.
                    let len = unsafe {
                        GetFinalPathNameByHandleW(
                            handle as *mut core::ffi::c_void,
                            buf.as_mut_ptr(),
                            buf.len() as u32,
                            FILE_NAME_NORMALIZED,
                        )
                    };
                    let path = if len > 0 && (len as usize) < buf.len() {
                        String::from_utf16_lossy(&buf[..len as usize])
                    } else {
                        String::new()
                    };
                    (path, fo.start())
                }
                None => (String::new(), 0),
            };
            MemfdRegionDesc {
                gpa: region.start_addr().raw_value(),
                len: region.len(),
                fd: if path.is_empty() { -1 } else { 0 },
                offset,
                path,
            }
        })
        .collect()
}

/// Windows variant of [`open_cow_memory_from_paths`]: builds the clone's guest
/// memory as **copy-on-write views** of the frozen golden VM's guest-RAM files.
/// For each region we open the golden's backing file and `MapViewOfFile`-map a
/// `FILE_MAP_COPY` view: clean pages are shared with the golden (dense,
/// size-independent), and the clone's writes copy on demand — the Windows
/// equivalent of the Linux/macOS `mmap(MAP_PRIVATE)` CoW path. The owner must be
/// frozen and its backing files present for the clone's lifetime. Anonymous
/// regions (empty path) get a fresh zeroed mapping.
#[cfg(target_os = "windows")]
pub fn open_cow_memory_from_paths(descs: &[MemfdRegionDesc]) -> io::Result<GuestMemoryMmap> {
    use std::os::windows::io::AsRawHandle;
    use vm_memory::GuestRegionMmap;
    use vm_memory::mmap::MmapRegion;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Memory::{
        CreateFileMappingW, FILE_MAP_COPY, MapViewOfFile, PAGE_WRITECOPY,
    };

    let io_err = |m: String| io::Error::other(m);
    let mut regions: Vec<GuestRegionMmap> = Vec::with_capacity(descs.len());

    for d in descs {
        let size = d.len as usize;
        let region = if !d.path.is_empty() {
            let file = std::fs::File::open(&d.path)
                .map_err(|e| io_err(format!("open {}: {e}", d.path)))?;
            // A copy-on-write section over the golden's RAM file. PAGE_WRITECOPY
            // (with a read-only file handle) backs FILE_MAP_COPY; CoW writes go to
            // the pagefile, never the shared file.
            // SAFETY: `file` is a valid open handle; a 0 max size maps the whole
            // file (each region has its own file).
            let mapping = unsafe {
                CreateFileMappingW(
                    file.as_raw_handle() as *mut core::ffi::c_void,
                    std::ptr::null(),
                    PAGE_WRITECOPY,
                    0,
                    0,
                    std::ptr::null(),
                )
            };
            if mapping.is_null() {
                return Err(io::Error::other(format!(
                    "CreateFileMapping {}: {}",
                    d.path,
                    io::Error::last_os_error()
                )));
            }
            let off = d.offset;
            // SAFETY: `mapping` is valid; mapping `size` bytes at `off` of it.
            let view = unsafe {
                MapViewOfFile(mapping, FILE_MAP_COPY, (off >> 32) as u32, off as u32, size)
            };
            // The view holds its own reference to the section, so the handle can
            // be closed now.
            unsafe { CloseHandle(mapping) };
            if view.Value.is_null() {
                return Err(io::Error::other(format!(
                    "MapViewOfFile {}: {}",
                    d.path,
                    io::Error::last_os_error()
                )));
            }
            // SAFETY: `view` is a live FILE_MAP_COPY mapping of `size` bytes;
            // ownership transfers to the MmapRegion (its Drop unmaps it).
            unsafe { MmapRegion::build_raw(view.Value as *mut u8, size, 0, 0) }
                .map_err(|e| io_err(format!("build_raw: {e:?}")))?
        } else {
            // Anonymous region (device SHM/GPU): fresh zeroed mapping.
            MmapRegion::new(size).map_err(|e| io_err(format!("anon mmap: {e:?}")))?
        };
        let guest_region = GuestRegionMmap::new(region, GuestAddress(d.gpa))
            .ok_or_else(|| io_err("guest region address overflow".to_string()))?;
        regions.push(guest_region);
    }

    GuestMemoryMmap::from_regions(regions).map_err(|e| io_err(format!("from_regions: {e:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::fs::{self, OpenOptions};
    #[cfg(unix)]
    use std::io::SeekFrom;
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    #[cfg(unix)]
    use std::time::{SystemTime, UNIX_EPOCH};
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    #[cfg(target_os = "macos")]
    #[test]
    fn mach_cow_worker_materializes_the_capture_boundary_after_source_writes() {
        const REGION_SIZE: usize = 4 * 1024 * 1024;
        let backing = crate::builder::create_guest_ram_memfd(REGION_SIZE).unwrap();
        let memory = GuestMemoryMmap::from_ranges_with_files(&[(
            GuestAddress(0),
            REGION_SIZE,
            Some(FileOffset::new(backing, 0)),
        )])
        .unwrap();
        memory
            .write_slice(&[0x11; 16 * 1024], GuestAddress(0x4000))
            .unwrap();

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "libkrun-macos-generation-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let generation = start_macos_fork_generation_copy(&memory, &directory).unwrap();
        memory
            .write_slice(&[0xAA; 16 * 1024], GuestAddress(0x4000))
            .unwrap();

        let descs = generation.finish().unwrap();
        let clone = open_cow_memory_from_paths(&descs).unwrap();
        let mut page = [0_u8; 16 * 1024];
        clone.read_slice(&mut page, GuestAddress(0x4000)).unwrap();
        assert_eq!(page, [0x11; 16 * 1024]);
        clone
            .write_slice(&[0x44; 16 * 1024], GuestAddress(0x4000))
            .unwrap();
        memory.read_slice(&mut page, GuestAddress(0x4000)).unwrap();
        assert_eq!(page, [0xAA; 16 * 1024]);

        drop(clone);
        drop(memory);
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn mach_cow_setup_failure_removes_only_generation_files_it_created() {
        const REGION_SIZE: usize = 4 * 1024 * 1024;
        let first = crate::builder::create_guest_ram_memfd(REGION_SIZE).unwrap();
        let second = crate::builder::create_guest_ram_memfd(REGION_SIZE).unwrap();
        let memory = GuestMemoryMmap::from_ranges_with_files(&[
            (
                GuestAddress(0),
                REGION_SIZE,
                Some(FileOffset::new(first, 0)),
            ),
            (
                GuestAddress(REGION_SIZE as u64),
                REGION_SIZE,
                Some(FileOffset::new(second, 0)),
            ),
        ])
        .unwrap();

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "libkrun-macos-generation-failure-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let collision = directory.join("memory-1.bin");
        fs::write(&collision, b"existing").unwrap();

        let error = start_macos_fork_generation_copy(&memory, &directory)
            .err()
            .expect("the second region must collide");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert!(!directory.join("memory-0.bin.partial").exists());
        assert_eq!(fs::read(&collision).unwrap(), b"existing");

        drop(memory);
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn dropping_mach_cow_generation_removes_materialized_files() {
        const REGION_SIZE: usize = 4 * 1024 * 1024;
        let backing = crate::builder::create_guest_ram_memfd(REGION_SIZE).unwrap();
        let memory = GuestMemoryMmap::from_ranges_with_files(&[(
            GuestAddress(0),
            REGION_SIZE,
            Some(FileOffset::new(backing, 0)),
        )])
        .unwrap();
        memory.write_obj(0xAA_u8, GuestAddress(0)).unwrap();

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "libkrun-macos-generation-drop-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();

        let generation = start_macos_fork_generation_copy(&memory, &directory).unwrap();
        drop(generation);
        assert!(!directory.join("memory-0.bin").exists());
        assert!(!directory.join("memory-0.bin.partial").exists());

        drop(memory);
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn fork_worker_materializes_an_exact_immutable_generation() {
        const REGION_SIZE: usize = 2 * 1024 * 1024;
        const HIGH_GPA: u64 = 0x40_0000;
        let memory = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0), REGION_SIZE),
            (GuestAddress(HIGH_GPA), REGION_SIZE),
        ])
        .unwrap();
        memory
            .write_slice(&[0x11; 4096], GuestAddress(0x1000))
            .unwrap();
        memory
            .write_slice(&[0x22; 4096], GuestAddress(HIGH_GPA + 0x2000))
            .unwrap();

        let generation = start_fork_generation_copy(&memory).unwrap();
        memory
            .write_slice(&[0xAA; 4096], GuestAddress(0x1000))
            .unwrap();
        memory
            .write_slice(&[0xBB; 4096], GuestAddress(HIGH_GPA + 0x2000))
            .unwrap();

        let (descs, files) = generation.finish().unwrap();
        let clone = open_cow_memory_from_pid(std::process::id() as i32, &descs).unwrap();
        let mut page = [0_u8; 4096];
        clone.read_slice(&mut page, GuestAddress(0x1000)).unwrap();
        assert_eq!(page, [0x11; 4096]);
        clone
            .read_slice(&mut page, GuestAddress(HIGH_GPA + 0x2000))
            .unwrap();
        assert_eq!(page, [0x22; 4096]);

        clone
            .write_slice(&[0x44; 4096], GuestAddress(0x1000))
            .unwrap();
        memory.read_slice(&mut page, GuestAddress(0x1000)).unwrap();
        assert_eq!(page, [0xAA; 4096]);
        for file in files {
            let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
            assert_eq!(
                seals & (libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK),
                libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn sparse_file_snapshot_preserves_multi_region_bytes_and_holes() {
        const REGION_SIZE: usize = 2 * 1024 * 1024;
        let regions = [
            (GuestAddress(0), REGION_SIZE),
            (GuestAddress(0x40_0000), REGION_SIZE),
        ];
        let src = GuestMemoryMmap::from_ranges(&regions).unwrap();
        src.write_slice(&[0xA5; 4096], GuestAddress(4096)).unwrap();
        src.write_slice(&[0x5A; 4096], GuestAddress(0x18_0000))
            .unwrap();

        let mut expected = Vec::new();
        let expected_descs = write_guest_memory(&src, &mut expected).unwrap();

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "libkrun-sparse-memory-{}-{nonce}",
            std::process::id()
        ));
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let descs = {
            let mut writer = SparseFileWriter::new(&mut file).unwrap();
            let descs = write_guest_memory(&src, &mut writer).unwrap();
            writer.finish().unwrap();
            descs
        };
        file.sync_all().unwrap();

        assert_eq!(descs, expected_descs);
        let metadata = file.metadata().unwrap();
        assert_eq!(metadata.len(), expected.len() as u64);
        assert!(
            metadata.blocks() * 512 < metadata.len() / 4,
            "sparse memory image allocated {} bytes for {} logical bytes",
            metadata.blocks() * 512,
            metadata.len()
        );

        file.seek(SeekFrom::Start(0)).unwrap();
        let mut actual = Vec::new();
        file.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, expected);

        let restored = GuestMemoryMmap::from_ranges(&regions).unwrap();
        read_guest_memory_into(&restored, &descs, &mut actual.as_slice()).unwrap();
        let mut low = vec![0; REGION_SIZE];
        let mut high = vec![0; REGION_SIZE];
        restored.read_slice(&mut low, GuestAddress(0)).unwrap();
        restored
            .read_slice(&mut high, GuestAddress(0x40_0000))
            .unwrap();
        assert_eq!(&low[4096..8192], &[0xA5; 4096]);
        assert_eq!(&low[0x18_0000..0x18_1000], &[0x5A; 4096]);
        assert!(high.iter().all(|byte| *byte == 0));

        drop(file);
        fs::remove_file(path).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sparse_snapshot_uses_file_backing_extents_and_anonymous_fallback() {
        use crate::builder::create_guest_ram_memfd;

        const FILE_REGION_SIZE: usize = 64 * 1024 * 1024;
        const ANON_REGION_SIZE: usize = 2 * 1024 * 1024;
        const ANON_GPA: u64 = 0x0800_0000;
        let backing = create_guest_ram_memfd(FILE_REGION_SIZE).unwrap();
        let memory = GuestMemoryMmap::from_ranges_with_files(&[
            (
                GuestAddress(0),
                FILE_REGION_SIZE,
                Some(FileOffset::new(backing, 0)),
            ),
            (GuestAddress(ANON_GPA), ANON_REGION_SIZE, None),
        ])
        .unwrap();
        memory
            .write_slice(&[0xA5; 4096], GuestAddress(4096))
            .unwrap();
        memory
            .write_slice(&[0x5A; 4096], GuestAddress(32 * 1024 * 1024))
            .unwrap();
        memory
            .write_slice(&[0xC3; 4096], GuestAddress(ANON_GPA + 8192))
            .unwrap();

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "libkrun-sparse-extents-{}-{nonce}",
            std::process::id()
        ));
        let mut output = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let descs = write_guest_memory_sparse(&memory, &mut output).unwrap();
        output.sync_all().unwrap();

        assert_eq!(descs.len(), 2);
        let metadata = output.metadata().unwrap();
        assert_eq!(metadata.len(), (FILE_REGION_SIZE + ANON_REGION_SIZE) as u64);
        assert!(
            metadata.blocks() * 512 < metadata.len() / 4,
            "extent copy allocated {} bytes for {} logical bytes",
            metadata.blocks() * 512,
            metadata.len()
        );

        output.seek(SeekFrom::Start(0)).unwrap();
        let restored = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0), FILE_REGION_SIZE),
            (GuestAddress(ANON_GPA), ANON_REGION_SIZE),
        ])
        .unwrap();
        read_guest_memory_into(&restored, &descs, &mut output).unwrap();
        let mut page = [0_u8; 4096];
        restored.read_slice(&mut page, GuestAddress(4096)).unwrap();
        assert_eq!(page, [0xA5; 4096]);
        restored
            .read_slice(&mut page, GuestAddress(32 * 1024 * 1024))
            .unwrap();
        assert_eq!(page, [0x5A; 4096]);
        restored
            .read_slice(&mut page, GuestAddress(ANON_GPA + 8192))
            .unwrap();
        assert_eq!(page, [0xC3; 4096]);

        drop(output);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_guest_memory_snapshot_roundtrip_single_region() {
        let size = 0x20000usize; // 128 KiB
        let src = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), size)]).unwrap();

        // Write a recognizable, non-trivial pattern across the whole region.
        let pattern: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        src.write_slice(&pattern, GuestAddress(0)).unwrap();

        // Dump to an in-memory stream.
        let mut buf = Vec::new();
        let descs = write_guest_memory(&src, &mut buf).unwrap();
        assert_eq!(descs.len(), 1);
        assert_eq!(descs[0].gpa, 0);
        assert_eq!(descs[0].len as usize, size);
        assert_eq!(buf.len(), size);
        assert_eq!(memory_image_len(&descs) as usize, size);

        // Restore into a fresh, zeroed guest memory.
        let dst = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), size)]).unwrap();
        read_guest_memory_into(&dst, &descs, &mut buf.as_slice()).unwrap();

        let mut got = vec![0u8; size];
        dst.read_slice(&mut got, GuestAddress(0)).unwrap();
        assert_eq!(got, pattern, "restored bytes must match the snapshot");
    }

    #[test]
    fn test_guest_memory_snapshot_roundtrip_multi_region() {
        // Two regions separated by a gap in guest physical space.
        let regions = [
            (GuestAddress(0), 0x10000usize),
            (GuestAddress(0x100000), 0x8000usize),
        ];
        let src = GuestMemoryMmap::from_ranges(&regions).unwrap();
        src.write_slice(&[0xAB; 0x10000], GuestAddress(0)).unwrap();
        src.write_slice(&[0xCD; 0x8000], GuestAddress(0x100000))
            .unwrap();

        let mut buf = Vec::new();
        let descs = write_guest_memory(&src, &mut buf).unwrap();
        assert_eq!(descs.len(), 2);
        assert_eq!(buf.len(), 0x10000 + 0x8000);

        let dst = GuestMemoryMmap::from_ranges(&regions).unwrap();
        read_guest_memory_into(&dst, &descs, &mut buf.as_slice()).unwrap();

        let mut got_lo = vec![0u8; 0x10000];
        let mut got_hi = vec![0u8; 0x8000];
        dst.read_slice(&mut got_lo, GuestAddress(0)).unwrap();
        dst.read_slice(&mut got_hi, GuestAddress(0x100000)).unwrap();
        assert_eq!(got_lo, vec![0xAB; 0x10000]);
        assert_eq!(got_hi, vec![0xCD; 0x8000]);
    }

    #[test]
    fn materialized_clone_can_source_another_cow_fork() {
        let regions = [
            (GuestAddress(0), 0x10000usize),
            (GuestAddress(0x20000), 0x8000usize),
        ];
        // Raw mappings mirror the metadata shape returned by the cross-process
        // restore path: bytes are present, but there is no FileOffset to expose
        // to a descendant process.
        let restored = GuestMemoryMmap::from_ranges(&regions).unwrap();
        restored
            .write_slice(&[0xA5; 0x10000], GuestAddress(0))
            .unwrap();
        restored
            .write_slice(&[0x5A; 0x8000], GuestAddress(0x20000))
            .unwrap();
        assert!(restored.iter().all(|region| region.file_offset().is_none()));

        let promoted =
            materialize_guest_memory(&restored, &[true, false]).expect("materialize clone");
        let promoted_regions = promoted.iter().collect::<Vec<_>>();
        assert!(promoted_regions[0].file_offset().is_some());
        assert!(promoted_regions[1].file_offset().is_none());
        let mut low = vec![0; 0x10000];
        let mut high = vec![0; 0x8000];
        promoted.read_slice(&mut low, GuestAddress(0)).unwrap();
        promoted
            .read_slice(&mut high, GuestAddress(0x20000))
            .unwrap();
        assert_eq!(low, vec![0xA5; 0x10000]);
        assert_eq!(high, vec![0x5A; 0x8000]);

        #[cfg(target_os = "linux")]
        {
            let child = cow_clone_guest_memory(&promoted).expect("descendant CoW clone");
            child.write_slice(&[0x11; 16], GuestAddress(0)).unwrap();
            let mut parent_bytes = [0; 16];
            promoted
                .read_slice(&mut parent_bytes, GuestAddress(0))
                .unwrap();
            assert_eq!(parent_bytes, [0xA5; 16]);
        }
    }

    // The CoW fork primitive: a clone shares the parent's clean pages but is
    // isolated on write, in both directions — the density + safety property
    // that makes fast fork sound (plan §4). Validated on the real memfd-backed
    // vm-memory abstraction, not just the standalone PoC.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_cow_clone_isolation_and_sharing() {
        use crate::builder::create_guest_ram_memfd;
        use vm_memory::FileOffset;

        let size = 0x10000usize; // 64 KiB
        let memfd = create_guest_ram_memfd(size).expect("memfd");
        let parent = GuestMemoryMmap::from_ranges_with_files([(
            GuestAddress(0),
            size,
            Some(FileOffset::new(memfd, 0)),
        )])
        .expect("memfd-backed parent");

        // Base pattern in the parent.
        parent
            .write_slice(&[0xAA; 0x10000], GuestAddress(0))
            .unwrap();

        // CoW clone shares the parent's pages → sees the same bytes.
        let clone = cow_clone_guest_memory(&parent).expect("cow clone");
        let mut buf = vec![0u8; 16];
        clone.read_slice(&mut buf, GuestAddress(0)).unwrap();
        assert_eq!(buf, vec![0xAA; 16], "clone shares parent's clean pages");

        // Writing the clone copies-on-write: the parent is unaffected.
        clone.write_slice(&[0xBB; 16], GuestAddress(0)).unwrap();
        let mut p = vec![0u8; 16];
        parent.read_slice(&mut p, GuestAddress(0)).unwrap();
        assert_eq!(p, vec![0xAA; 16], "parent unchanged by clone write (CoW)");
        let mut c = vec![0u8; 16];
        clone.read_slice(&mut c, GuestAddress(0)).unwrap();
        assert_eq!(c, vec![0xBB; 16], "clone holds its own copy");

        // And a later parent write does not leak into the clone's CoW'd page.
        parent.write_slice(&[0xCC; 16], GuestAddress(0)).unwrap();
        let mut c2 = vec![0u8; 16];
        clone.read_slice(&mut c2, GuestAddress(0)).unwrap();
        assert_eq!(
            c2,
            vec![0xBB; 16],
            "clone isolated from later parent writes"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn restored_unsealable_file_backing_requires_promotion() {
        use crate::builder::create_guest_ram_memfd;
        use std::os::fd::AsRawFd;
        use vm_memory::FileOffset;

        const SIZE: usize = 4 * 4096;
        let sealable = create_guest_ram_memfd(SIZE).expect("sealable memfd");
        let sealable_memory = GuestMemoryMmap::from_ranges_with_files([(
            GuestAddress(0),
            SIZE,
            Some(FileOffset::new(sealable, 0)),
        )])
        .expect("sealable memory");
        assert!(!restored_memory_needs_fork_backing(&sealable_memory, &[true]).unwrap());

        let unsealable = create_guest_ram_memfd(SIZE).expect("memfd");
        let result =
            unsafe { libc::fcntl(unsealable.as_raw_fd(), libc::F_ADD_SEALS, libc::F_SEAL_SEAL) };
        assert_eq!(
            result,
            0,
            "lock memfd seal set: {}",
            io::Error::last_os_error()
        );
        let unsealable_memory = GuestMemoryMmap::from_ranges_with_files([(
            GuestAddress(0),
            SIZE,
            Some(FileOffset::new(unsealable, 0)),
        )])
        .expect("unsealable memory");
        assert!(restored_memory_needs_fork_backing(&unsealable_memory, &[true]).unwrap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rebased_parent_can_continue_without_mutating_fork_generation() {
        use crate::builder::create_guest_ram_memfd;
        use std::os::unix::fs::FileExt;
        use vm_memory::FileOffset;

        const PAGE: usize = 4096;
        let size = 4 * PAGE;
        let memfd = create_guest_ram_memfd(size).expect("sealable memfd");
        let inspect_fd = memfd.try_clone().expect("inspection fd");
        let parent = GuestMemoryMmap::from_ranges_with_files([(
            GuestAddress(0),
            size,
            Some(FileOffset::new(memfd, 0)),
        )])
        .expect("memfd-backed parent");
        parent.write_slice(&[0x11; PAGE], GuestAddress(0)).unwrap();
        parent
            .write_slice(&[0x22; PAGE], GuestAddress(PAGE as u64))
            .unwrap();

        rebase_guest_memory_private(&parent).expect("private source rebase");
        let generation = cow_clone_guest_memory(&parent).expect("generation clone");

        // Continuing source writes must fault private pages instead of changing
        // either the immutable memfd generation or an untouched clone mapping.
        parent.write_slice(&[0xA1; PAGE], GuestAddress(0)).unwrap();
        parent
            .write_slice(&[0xA2; PAGE], GuestAddress(PAGE as u64))
            .unwrap();

        let mut bytes = [0_u8; 16];
        generation.read_slice(&mut bytes, GuestAddress(0)).unwrap();
        assert_eq!(bytes, [0x11; 16]);
        generation
            .read_slice(&mut bytes, GuestAddress(PAGE as u64))
            .unwrap();
        assert_eq!(bytes, [0x22; 16]);
        inspect_fd.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(bytes, [0x11; 16]);

        // Clone writes remain private in the other direction as well.
        generation
            .write_slice(&[0xC1; 16], GuestAddress(0))
            .unwrap();
        parent.read_slice(&mut bytes, GuestAddress(0)).unwrap();
        assert_eq!(bytes, [0xA1; 16]);

        let write_error = inspect_fd.write_all_at(&[0xFF], 0).unwrap_err();
        assert_eq!(write_error.raw_os_error(), Some(libc::EPERM));
        let truncate_error = inspect_fd.set_len(PAGE as u64).unwrap_err();
        assert_eq!(truncate_error.raw_os_error(), Some(libc::EPERM));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn seal_query_unsupported_errnos_are_distinct() {
        for errno in [libc::EINVAL, libc::ENOTTY, libc::EOPNOTSUPP] {
            assert!(unsupported_seal_query(&io::Error::from_raw_os_error(errno)));
        }
        assert!(!unsupported_seal_query(&io::Error::from_raw_os_error(
            libc::EPERM
        )));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sparse_snapshot_includes_private_pages_after_live_fork() {
        use crate::builder::create_guest_ram_memfd;

        const PAGE: usize = 4096;
        let size = 4 * PAGE;
        let memfd = create_guest_ram_memfd(size).expect("sealable memfd");
        let memory = GuestMemoryMmap::from_ranges_with_files([(
            GuestAddress(0),
            size,
            Some(FileOffset::new(memfd, 0)),
        )])
        .expect("memfd-backed memory");
        memory.write_slice(&[0x11; PAGE], GuestAddress(0)).unwrap();

        rebase_guest_memory_private(&memory).expect("private source rebase");
        memory.write_slice(&[0xA5; PAGE], GuestAddress(0)).unwrap();
        memory
            .write_slice(&[0x5A; PAGE], GuestAddress((2 * PAGE) as u64))
            .unwrap();

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "libkrun-private-sparse-{}-{nonce}",
            std::process::id()
        ));
        let mut output = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let descs = write_guest_memory_sparse(&memory, &mut output).unwrap();
        output.seek(SeekFrom::Start(0)).unwrap();
        let restored = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), size)]).unwrap();
        read_guest_memory_into(&restored, &descs, &mut output).unwrap();

        let mut page = [0_u8; PAGE];
        restored.read_slice(&mut page, GuestAddress(0)).unwrap();
        assert_eq!(page, [0xA5; PAGE]);
        restored
            .read_slice(&mut page, GuestAddress((2 * PAGE) as u64))
            .unwrap();
        assert_eq!(page, [0x5A; PAGE]);

        drop(output);
        fs::remove_file(path).unwrap();
    }

    // Pool density: N CoW clones of a faulted-in base must cost only the pages
    // each clone *writes*, not N full copies — the "extremely fast scaling"
    // property (plan §9a / PoC Exp 1), here on the real `cow_clone` primitive.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_cow_clone_density() {
        use crate::builder::create_guest_ram_memfd;
        use vm_memory::FileOffset;

        // Resident-set size of this process, in bytes (statm field 2 = pages).
        fn rss_bytes() -> u64 {
            let s = std::fs::read_to_string("/proc/self/statm").unwrap();
            let resident_pages: u64 = s.split_whitespace().nth(1).unwrap().parse().unwrap();
            resident_pages * 4096
        }

        let base = 64 * 1024 * 1024usize; // 64 MiB base image
        let memfd = create_guest_ram_memfd(base).expect("memfd");
        let parent = GuestMemoryMmap::from_ranges_with_files([(
            GuestAddress(0),
            base,
            Some(FileOffset::new(memfd, 0)),
        )])
        .expect("parent");
        // Fault the whole base in so it counts toward RSS.
        parent
            .write_slice(&vec![0x5A; base], GuestAddress(0))
            .unwrap();

        let rss_before = rss_bytes();

        // 8 clones; dirty 1 MiB in each (forces CoW of just those pages).
        const N: usize = 8;
        let mut clones = Vec::new();
        for _ in 0..N {
            let c = cow_clone_guest_memory(&parent).expect("clone");
            c.write_slice(&vec![0xA5; 1024 * 1024], GuestAddress(0))
                .unwrap();
            clones.push(c);
        }

        let added = rss_bytes().saturating_sub(rss_before);
        let naive = (N * base) as u64; // what 8 full copies would cost (512 MiB)
        // Clones should add only ~N MiB (their dirtied pages) + slop, far below
        // a naive 512 MiB. Generous bound to stay robust across machines.
        assert!(
            added < 64 * 1024 * 1024,
            "8 CoW clones of 64 MiB added {added} bytes (naive full copy = {naive}); \
             expected only the dirtied pages — pages are not being shared"
        );
        assert_eq!(clones.len(), N);
    }

    #[test]
    fn test_short_stream_is_an_error() {
        let size = 0x4000usize;
        let descs = [MemoryRegionDesc {
            gpa: 0,
            len: size as u64,
        }];
        let dst = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), size)]).unwrap();
        // Stream has fewer bytes than the descriptor claims -> read_exact errors.
        let truncated = vec![0u8; size - 1];
        let err = read_guest_memory_into(&dst, &descs, &mut truncated.as_slice()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_load_guest_memory_roundtrip_and_exact_length() {
        let descs = [
            MemoryRegionDesc {
                gpa: 0,
                len: 0x2000,
            },
            MemoryRegionDesc {
                gpa: 0x10_0000,
                len: 0x1000,
            },
        ];
        let image = (0..0x3000).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        let memory = load_guest_memory(&descs, &mut image.as_slice()).unwrap();
        let mut restored = vec![0_u8; image.len()];
        memory
            .read_slice(&mut restored[..0x2000], GuestAddress(0))
            .unwrap();
        memory
            .read_slice(&mut restored[0x2000..], GuestAddress(0x10_0000))
            .unwrap();
        assert_eq!(restored, image);

        let mut trailing = image.clone();
        trailing.push(0);
        assert_eq!(
            load_guest_memory(&descs, &mut trailing.as_slice())
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sparse_memory_image_promotes_into_independent_fork_backing() {
        use crate::builder::create_guest_ram_memfd;
        use std::os::unix::fs::FileExt;

        let descs = [
            MemoryRegionDesc {
                gpa: 0,
                len: 0x20_0000,
            },
            MemoryRegionDesc {
                gpa: 0x40_0000,
                len: 0x10_0000,
            },
        ];
        let file = create_guest_ram_memfd(0x30_0000).expect("sparse memory image");
        file.write_all_at(&[0xA5; 4096], 0x1000).unwrap();
        file.write_all_at(&[0x5A; 4096], 0x20_2000).unwrap();

        let memory = map_guest_memory_file_forkable(&descs, &file).expect("promote sparse image");
        assert!(!restored_memory_needs_fork_backing(&memory, &[true, true]).unwrap());

        let mut low = [0_u8; 16];
        let mut high = [0_u8; 16];
        memory.read_slice(&mut low, GuestAddress(0x1000)).unwrap();
        memory
            .read_slice(&mut high, GuestAddress(0x40_2000))
            .unwrap();
        assert_eq!(low, [0xA5; 16]);
        assert_eq!(high, [0x5A; 16]);

        file.write_all_at(&[0x11; 16], 0x1000).unwrap();
        memory.read_slice(&mut low, GuestAddress(0x1000)).unwrap();
        assert_eq!(low, [0xA5; 16], "promoted RAM must not alias the artifact");
        rebase_guest_memory_private(&memory).expect("promoted RAM supports live fork");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mapped_memory_image_is_file_backed_and_forkable() {
        use crate::builder::create_guest_ram_memfd;
        use std::os::unix::fs::FileExt;

        let descs = [
            MemoryRegionDesc {
                gpa: 0,
                len: 0x2000,
            },
            MemoryRegionDesc {
                gpa: 0x10_0000,
                len: 0x1000,
            },
        ];
        let file = create_guest_ram_memfd(0x3000).expect("memory image");
        file.write_all_at(&[0xA5; 0x2000], 0).unwrap();
        file.write_all_at(&[0x5A; 0x1000], 0x2000).unwrap();

        let memory = map_guest_memory_file(&descs, &file).expect("map memory image");
        let regions = memory.iter().collect::<Vec<_>>();
        assert_eq!(regions[0].file_offset().unwrap().start(), 0);
        assert_eq!(regions[1].file_offset().unwrap().start(), 0x2000);

        let mut low = [0_u8; 16];
        let mut high = [0_u8; 16];
        memory.read_slice(&mut low, GuestAddress(0)).unwrap();
        memory
            .read_slice(&mut high, GuestAddress(0x10_0000))
            .unwrap();
        assert_eq!(low, [0xA5; 16]);
        assert_eq!(high, [0x5A; 16]);

        memory.write_slice(&[0x11; 16], GuestAddress(0)).unwrap();
        let mut backing = [0_u8; 16];
        file.read_exact_at(&mut backing, 0).unwrap();
        assert_eq!(backing, [0x11; 16]);

        let child = cow_clone_guest_memory(&memory).expect("CoW child");
        child.read_slice(&mut low, GuestAddress(0)).unwrap();
        assert_eq!(low, [0x11; 16]);
        child.write_slice(&[0x22; 16], GuestAddress(0)).unwrap();
        memory.read_slice(&mut low, GuestAddress(0)).unwrap();
        assert_eq!(low, [0x11; 16]);
        file.read_exact_at(&mut backing, 0).unwrap();
        assert_eq!(backing, [0x11; 16]);
    }
}
