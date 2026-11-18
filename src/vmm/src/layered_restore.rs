// Copyright 2026. SPDX-License-Identifier: Apache-2.0
//! Immutable layered RAM generations for Linux restore and branching.
//! Complete immutable backing consists of a base plus sealed modified-page
//! extents. Every mapping is private and kernel-faultable without a pager thread.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
#[cfg(test)]
use vm_memory::Bytes;
use vm_memory::mmap::MmapRegion;
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap, GuestRegionMmap};

fn host_page_size() -> usize {
    static SIZE: std::sync::LazyLock<usize> = std::sync::LazyLock::new(|| {
        usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .expect("host page size must be positive")
    });
    *SIZE
}
/// Same-host live generation format, distinct from a portable checkpoint.
pub const MANIFEST_MAGIC: [u8; 8] = *b"SMOLLAY1";

/// A complete logical region, independent of the number of file extents.
#[derive(Clone, Debug)]
pub struct RegionDescription {
    pub gpa: u64,
    pub len: u64,
    pub extents: Vec<ExtentDescription>,
}

/// Borrowed file descriptor in the generation owner's process. The owner must
/// retain its generation until receivers have opened their own descriptors.
#[derive(Clone, Debug)]
pub struct ExtentDescription {
    pub start: u64,
    pub len: u64,
    pub fd: i32,
    pub offset: u64,
}

/// Owns every immutable backing needed to restore or export this generation.
/// Dropping ancestors or unlinking their paths cannot invalidate these handles.
#[derive(Clone)]
pub struct Generation {
    regions: Vec<Image>,
}

impl Generation {
    /// Prepare hot-added RAM without changing this generation or existing views.
    /// The caller publishes the returned generation only after KVM accepts the
    /// new region. Private writes can then be captured exactly like restored RAM.
    #[cfg(any(
        test,
        all(
            any(target_arch = "x86_64", target_arch = "aarch64"),
            not(feature = "tee")
        )
    ))]
    pub(crate) fn with_zero_region(
        &self,
        gpa: u64,
        len: usize,
    ) -> io::Result<(Self, Arc<GuestRegionMmap>)> {
        let end = gpa
            .checked_add(len as u64)
            .ok_or_else(|| invalid("RAM address overflow"))?;
        if self.regions.len() >= 256
            || len == 0
            || !len.is_multiple_of(host_page_size())
            || !gpa.is_multiple_of(host_page_size() as u64)
            || self
                .regions
                .iter()
                .any(|region| gpa < region.gpa + region.len as u64 && end > region.gpa)
        {
            return Err(invalid("invalid or overlapping added RAM region"));
        }
        let file = crate::builder::create_guest_ram_memfd(len).map_err(io::Error::other)?;
        let seals =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let added = Self::from_immutable_file(
            &[crate::snapshot::MemoryRegionDesc {
                gpa,
                len: len as u64,
            }],
            &file,
        )?;
        let memory = added.restore()?;
        let (_, region) = memory
            .remove_region(GuestAddress(gpa), len as u64)
            .map_err(|error| io::Error::other(format!("select added RAM: {error:?}")))?;
        let mut next = self.clone();
        next.regions.extend(added.regions);
        next.regions.sort_by_key(|region| region.gpa);
        next.check_limits()?;
        Ok((next, region))
    }

    pub fn publish_manifest(
        &self,
        socket: &std::path::Path,
    ) -> io::Result<(Vec<u8>, crate::retained_fds::RetainedFiles)> {
        use std::os::unix::ffi::OsStrExt;
        if !socket.is_absolute() || socket.as_os_str().len() >= libc::PATH_MAX as usize {
            return Err(invalid("invalid checkpoint handoff path"));
        }
        let mut bytes = self.encode_manifest()?;
        let mut files = std::collections::BTreeMap::new();
        for region in &self.regions {
            for extent in &region.extents {
                files.insert(extent.file.as_raw_fd(), extent.file.clone());
            }
        }
        let (service, token) = crate::retained_fds::RetainedFiles::start(socket, files)?;
        bytes[12..16].copy_from_slice(&1u32.to_le_bytes());
        let path = socket.as_os_str().as_bytes();
        bytes.extend_from_slice(&(path.len() as u16).to_le_bytes());
        bytes.extend_from_slice(path);
        bytes.extend_from_slice(&token);
        Ok((bytes, service))
    }
    /// Encode references to this process's retained immutable descriptors.
    /// Keep this generation alive until importers acquire their own handles.
    pub fn encode_manifest(&self) -> io::Result<Vec<u8>> {
        self.check_limits()?;
        let pid = std::process::id();
        let start = process_start_time(pid)?;
        let descriptions = self.descriptions();
        let mut output = Vec::new();
        output.extend_from_slice(&MANIFEST_MAGIC);
        output.extend_from_slice(&pid.to_le_bytes());
        output.extend_from_slice(&0_u32.to_le_bytes());
        output.extend_from_slice(&start.to_le_bytes());
        output.extend_from_slice(&(descriptions.len() as u32).to_le_bytes());
        for region in descriptions {
            output.extend_from_slice(&region.gpa.to_le_bytes());
            output.extend_from_slice(&region.len.to_le_bytes());
            output.extend_from_slice(&(region.extents.len() as u32).to_le_bytes());
            for extent in region.extents {
                output.extend_from_slice(&extent.start.to_le_bytes());
                output.extend_from_slice(&extent.len.to_le_bytes());
                output.extend_from_slice(&extent.fd.to_le_bytes());
                output.extend_from_slice(&extent.offset.to_le_bytes());
            }
        }
        Ok(output)
    }

    pub fn decode_manifest(input: &[u8]) -> io::Result<Self> {
        fn take<const N: usize>(input: &mut &[u8]) -> io::Result<[u8; N]> {
            let bytes = input
                .get(..N)
                .ok_or_else(|| invalid("truncated layered RAM manifest"))?;
            let value = bytes.try_into().unwrap();
            *input = &input[N..];
            Ok(value)
        }
        if input.len() > 2 * 1024 * 1024 {
            return Err(invalid("layered RAM manifest too large"));
        }
        let mut remaining = input;
        if take::<8>(&mut remaining)? != MANIFEST_MAGIC {
            return Err(invalid("invalid layered RAM manifest magic"));
        }
        let pid = u32::from_le_bytes(take(&mut remaining)?);
        let transport = u32::from_le_bytes(take(&mut remaining)?);
        if pid == 0 || pid > i32::MAX as u32 || transport > 1 {
            return Err(invalid("invalid layered RAM owner/header"));
        }
        let start = u64::from_le_bytes(take(&mut remaining)?);
        let count = u32::from_le_bytes(take(&mut remaining)?) as usize;
        if count == 0 || count > 256 {
            return Err(invalid("invalid RAM region count"));
        }
        let mut descriptions = Vec::with_capacity(count);
        let mut total = 0;
        for _ in 0..count {
            let gpa = u64::from_le_bytes(take(&mut remaining)?);
            let len = u64::from_le_bytes(take(&mut remaining)?);
            let count = u32::from_le_bytes(take(&mut remaining)?) as usize;
            total += count;
            if count == 0 || total > 65536 || count > remaining.len() / 28 {
                return Err(invalid("invalid layered RAM extent count"));
            }
            let mut extents = Vec::with_capacity(count);
            for _ in 0..count {
                extents.push(ExtentDescription {
                    start: u64::from_le_bytes(take(&mut remaining)?),
                    len: u64::from_le_bytes(take(&mut remaining)?),
                    fd: i32::from_le_bytes(take(&mut remaining)?),
                    offset: u64::from_le_bytes(take(&mut remaining)?),
                });
            }
            descriptions.push(RegionDescription { gpa, len, extents });
        }
        let handoff = if transport == 1 {
            use std::os::unix::ffi::OsStrExt;
            let len = u16::from_le_bytes(take(&mut remaining)?) as usize;
            if len == 0 || len >= libc::PATH_MAX as usize {
                return Err(invalid("invalid checkpoint handoff path length"));
            }
            let path = remaining
                .get(..len)
                .ok_or_else(|| invalid("truncated checkpoint handoff path"))?;
            let path = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(path));
            if !path.is_absolute() {
                return Err(invalid("checkpoint handoff path must be absolute"));
            }
            remaining = &remaining[len..];
            Some((path, take::<32>(&mut remaining)?))
        } else {
            None
        };
        if !remaining.is_empty() {
            return Err(invalid("trailing layered RAM manifest data"));
        }
        if process_start_time(pid)? != start {
            return Err(invalid("layered RAM owner identity changed"));
        }
        let generation = if let Some((path, token)) = handoff {
            let keys: Vec<_> = descriptions
                .iter()
                .flat_map(|region| region.extents.iter().map(|extent| extent.fd))
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            let files = crate::retained_fds::receive(&path, &token, pid, &keys)?;
            Self::from_descriptions_with_files(
                pid as i32,
                &descriptions,
                files.into_iter().collect(),
            )?
        } else {
            Self::from_descriptions(pid as i32, &descriptions)?
        };
        if process_start_time(pid)? != start {
            return Err(invalid("layered RAM owner changed during import"));
        }
        Ok(generation)
    }
    /// The caller must retain the immutable-file contract: a read-only handle
    /// prevents writes through this handle, not through other host handles.
    pub fn from_immutable_file(
        descs: &[crate::snapshot::MemoryRegionDesc],
        file: &File,
    ) -> io::Result<Self> {
        let mut descriptions = Vec::new();
        let mut offset = 0_u64;
        for desc in descs {
            descriptions.push(RegionDescription {
                gpa: desc.gpa,
                len: desc.len,
                extents: vec![ExtentDescription {
                    start: 0,
                    len: desc.len,
                    fd: file.as_raw_fd(),
                    offset,
                }],
            });
            offset = offset
                .checked_add(desc.len)
                .ok_or_else(|| invalid("RAM size overflow"))?;
        }
        if file.metadata()?.len() != offset {
            return Err(invalid("RAM file length mismatch"));
        }
        // Restore can run after the launcher has dropped to the VM's UID.
        // The validated, pre-opened snapshot remains readable through its fd,
        // but reopening /proc/self/fd would repeat pathname permission checks
        // against a cache inode owned by the service. Preserve that capability
        // rather than requiring broader access to the checkpoint cache.
        let files =
            std::collections::HashMap::from([(file.as_raw_fd(), Arc::new(file.try_clone()?))]);
        Self::from_descriptions_with_files(std::process::id() as i32, &descriptions, files)
    }

    /// Adopt a running source's own memfd regions as its first generation
    /// without copying a byte. Every region must map a file that already
    /// carries the write seal ([`crate::snapshot::rebase_guest_memory_private`]
    /// seals and remaps the source privately): from then on the files hold the
    /// generation and the mappings hold only private writes, which later
    /// captures copy as deltas.
    pub fn from_sealed_memory(memory: &GuestMemoryMmap) -> io::Result<Self> {
        use vm_memory::{Address, GuestMemoryRegion};
        let mut descriptions = Vec::new();
        let mut files = std::collections::HashMap::new();
        for region in memory.iter() {
            let Some(file_offset) = region.file_offset() else {
                return Err(invalid("guest RAM region has no file backing to adopt"));
            };
            let fd = file_offset.file().as_raw_fd();
            let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
            if seals < 0 {
                return Err(io::Error::last_os_error());
            }
            if seals & libc::F_SEAL_WRITE == 0 {
                return Err(invalid("guest RAM backing is not sealed against writes"));
            }
            if let std::collections::hash_map::Entry::Vacant(entry) = files.entry(fd) {
                entry.insert(Arc::new(file_offset.file().try_clone()?));
            }
            descriptions.push(RegionDescription {
                gpa: region.start_addr().raw_value(),
                len: region.len(),
                extents: vec![ExtentDescription {
                    start: 0,
                    len: region.len(),
                    fd,
                    offset: file_offset.start(),
                }],
            });
        }
        Self::from_descriptions_with_files(std::process::id() as i32, &descriptions, files)
    }

    /// Import immutable handles from a trusted, authenticated generation owner.
    /// Validate the complete layout before creating any guest mapping.
    pub fn from_descriptions(owner: i32, descriptions: &[RegionDescription]) -> io::Result<Self> {
        Self::from_descriptions_with_files(owner, descriptions, std::collections::HashMap::new())
    }

    fn from_descriptions_with_files(
        owner: i32,
        descriptions: &[RegionDescription],
        mut files: std::collections::HashMap<i32, Arc<File>>,
    ) -> io::Result<Self> {
        if owner <= 0 || descriptions.is_empty() || descriptions.len() > 256 {
            return Err(invalid("invalid layered RAM owner or region count"));
        }
        let mut regions = Vec::new();
        let mut previous_end = 0;
        let mut extent_count = 0_usize;
        let page_size = host_page_size() as u64;
        for region in descriptions {
            let end = region
                .gpa
                .checked_add(region.len)
                .ok_or_else(|| invalid("RAM address overflow"))?;
            if region.gpa < previous_end
                || !region.gpa.is_multiple_of(page_size)
                || region.len == 0
                || !region.len.is_multiple_of(page_size)
            {
                return Err(invalid("invalid or overlapping RAM region"));
            }
            let len = usize::try_from(region.len)
                .map_err(|_| invalid("RAM region exceeds address space"))?;
            let mut cursor = 0_u64;
            let mut extents = Vec::new();
            for extent in &region.extents {
                extent_count += 1;
                if extent_count > 65536 {
                    return Err(invalid("too many layered RAM extents"));
                }
                if extent.fd < 0
                    || extent.start != cursor
                    || extent.len == 0
                    || !extent.len.is_multiple_of(page_size)
                    || !extent.offset.is_multiple_of(page_size)
                {
                    return Err(invalid("invalid layered RAM extent"));
                }
                cursor = cursor
                    .checked_add(extent.len)
                    .ok_or_else(|| invalid("extent overflow"))?;
                let file_end = extent
                    .offset
                    .checked_add(extent.len)
                    .ok_or_else(|| invalid("file extent overflow"))?;
                if cursor > region.len || file_end > i64::MAX as u64 {
                    return Err(invalid("extent exceeds its region or file offset range"));
                }
                let file = if let Some(file) = files.get(&extent.fd) {
                    file.clone()
                } else {
                    if files.len() >= 1024 {
                        return Err(invalid("too many layered RAM files"));
                    }
                    let file = Arc::new(
                        File::open(format!("/proc/{owner}/fd/{}", extent.fd)).map_err(|error| {
                            io::Error::new(error.kind(), format!(
                                "open retained RAM descriptor {} from generation owner {owner}: {error}",
                                extent.fd
                            ))
                        })?,
                    );
                    files.insert(extent.fd, file.clone());
                    file
                };
                if !file.metadata()?.is_file() || file.metadata()?.len() < file_end {
                    return Err(invalid("layered RAM backing is truncated or not a file"));
                }
                extents.push(Extent {
                    start: extent.start as usize,
                    end: cursor as usize,
                    offset: extent.offset,
                    file,
                });
            }
            if cursor != region.len {
                return Err(invalid("layered RAM has uncovered pages"));
            }
            regions.push(Image {
                gpa: region.gpa,
                len,
                extents,
            });
            previous_end = end;
        }
        Ok(Self { regions })
    }

    pub fn descriptions(&self) -> Vec<RegionDescription> {
        self.regions
            .iter()
            .map(|region| RegionDescription {
                gpa: region.gpa,
                len: region.len as u64,
                extents: region
                    .extents
                    .iter()
                    .map(|extent| ExtentDescription {
                        start: extent.start as u64,
                        len: (extent.end - extent.start) as u64,
                        fd: extent.file.as_raw_fd(),
                        offset: extent.offset,
                    })
                    .collect(),
            })
            .collect()
    }

    fn check_limits(&self) -> io::Result<()> {
        let mut count = 0;
        let mut files = std::collections::HashSet::new();
        for image in &self.regions {
            count += image.extents.len();
            if count > 65536 {
                return Err(invalid("layered RAM extent budget exceeded"));
            }
            for extent in &image.extents {
                files.insert(extent.file.as_raw_fd());
                if files.len() > 1024 {
                    return Err(invalid("layered RAM file budget exceeded"));
                }
            }
        }
        Ok(())
    }

    /// Logical regions remain unchanged even when the backing has many extents;
    /// a KVM slot is not consumed for each extent.
    pub fn restore(&self) -> io::Result<GuestMemoryMmap> {
        let mut regions = Vec::new();
        for image in &self.regions {
            let instance = image.restore()?;
            let (_, region) = instance
                .memory
                .remove_region(GuestAddress(image.gpa), image.len as u64)
                .map_err(|error| io::Error::other(format!("extract RAM region: {error:?}")))?;
            regions.push(region);
        }
        GuestMemoryMmap::from_arc_regions(regions)
            .map_err(|error| io::Error::other(format!("assemble layered RAM: {error:?}")))
    }

    pub(crate) fn validate_memory(
        &self,
        memory: &GuestMemoryMmap,
        excluded: &[u64],
    ) -> io::Result<()> {
        use vm_memory::{Address, GuestMemoryRegion};
        if memory.num_regions() != self.regions.len()
            || memory.iter().zip(&self.regions).any(|(actual, expected)| {
                actual.start_addr().raw_value() != expected.gpa
                    || actual.len() != expected.len as u64
            })
        {
            return Err(invalid("layered RAM mapping/layout mismatch"));
        }
        let mut regions = Vec::new();
        for image in &self.regions {
            if !excluded.contains(&image.gpa) {
                let (_, region) = memory
                    .remove_region(GuestAddress(image.gpa), image.len as u64)
                    .map_err(|error| io::Error::other(format!("select private RAM: {error:?}")))?;
                regions.push(region);
            }
        }
        let private = GuestMemoryMmap::from_arc_regions(regions)
            .map_err(|error| io::Error::other(format!("private RAM regions: {error:?}")))?;
        crate::generation_guardian::validate_private_memory_mappings(&private)
    }

    /// All vCPUs and device writers must be quiesced for the entire operation.
    pub fn capture_quiesced(&self, memory: &GuestMemoryMmap) -> io::Result<(Self, usize)> {
        self.capture_quiesced_excluding(memory, &[])
    }

    /// Device-owned shared windows are restored by their device snapshot, not
    /// by inspecting their page-table entries as if they were private RAM.
    pub(crate) fn capture_quiesced_excluding(
        &self,
        memory: &GuestMemoryMmap,
        excluded: &[u64],
    ) -> io::Result<(Self, usize)> {
        self.capture_quiesced_within(memory, excluded, CompactLimits::DEFAULT)
    }

    /// Capture with each private region given its share of `limits`, in
    /// proportion to its size.
    fn capture_quiesced_within(
        &self,
        memory: &GuestMemoryMmap,
        excluded: &[u64],
        limits: CompactLimits,
    ) -> io::Result<(Self, usize)> {
        self.validate_memory(memory, excluded)?;
        let private_len: u128 = self
            .regions
            .iter()
            .filter(|image| !excluded.contains(&image.gpa))
            .map(|image| image.len as u128)
            .sum();
        let mut regions = Vec::new();
        let mut copied = 0_usize;
        for image in &self.regions {
            if excluded.contains(&image.gpa) {
                regions.push(image.clone());
                continue;
            }
            let instance = Instance {
                memory: memory.clone(),
                image: image.clone(),
            };
            let (next, bytes) =
                instance.capture_quiesced_within(limits.share(image.len, private_len))?;
            copied = copied
                .checked_add(bytes)
                .ok_or_else(|| invalid("copied RAM size overflow"))?;
            regions.push(next);
        }
        let next = Self { regions };
        next.check_limits()?;
        Ok((next, copied))
    }

    /// Call only while every writer is stopped. On error the caller MUST NOT
    /// resume without recovering the mapping; some extents may already change.
    pub fn rebase_quiesced(&self, memory: &GuestMemoryMmap) -> io::Result<()> {
        self.rebase_quiesced_excluding(memory, &[])
    }

    pub(crate) fn rebase_quiesced_excluding(
        &self,
        memory: &GuestMemoryMmap,
        excluded: &[u64],
    ) -> io::Result<()> {
        self.validate_memory(memory, excluded)?;
        for image in &self.regions {
            if excluded.contains(&image.gpa) {
                continue;
            }
            let mut instance = Instance {
                memory: memory.clone(),
                image: image.clone(),
            };
            instance.rebase_quiesced(image.clone())?;
        }
        Ok(())
    }

    /// Export logical bytes directly from retained backing, including explicit
    /// zero overwrites; never mistake a sparse delta file for a complete image.
    pub fn write_to<W: io::Write>(&self, output: &mut W) -> io::Result<()> {
        let mut buffer = vec![0; 64 * 1024];
        for image in &self.regions {
            for extent in &image.extents {
                let mut offset = 0;
                while offset < extent.end - extent.start {
                    let len = (extent.end - extent.start - offset).min(buffer.len());
                    extent
                        .file
                        .read_exact_at(&mut buffer[..len], extent.offset + offset as u64)?;
                    output.write_all(&buffer[..len])?;
                    offset += len;
                }
            }
        }
        Ok(())
    }

    /// Borrow the complete logical image in portable region order. The
    /// generation owns all immutable files until streaming has finished.
    pub(crate) fn memory_sources(&self) -> Vec<(&File, u64, u64)> {
        self.regions
            .iter()
            .flat_map(|image| &image.extents)
            .map(|extent| {
                (
                    extent.file.as_ref(),
                    extent.offset,
                    (extent.end - extent.start) as u64,
                )
            })
            .collect()
    }

    pub fn memory_regions(&self) -> Vec<crate::snapshot::MemoryRegionDesc> {
        self.regions
            .iter()
            .map(|image| crate::snapshot::MemoryRegionDesc {
                gpa: image.gpa,
                len: image.len as u64,
            })
            .collect()
    }

    pub fn write_sparse_to(&self, output: &mut File) -> io::Result<()> {
        use std::io::Seek;
        output.set_len(0)?;
        let mut buffer = vec![0; 64 * 1024];
        let mut logical = 0_u64;
        for image in &self.regions {
            for extent in &image.extents {
                let extent_len = extent.end - extent.start;
                // Read only the file's data ranges: a hole reads as zeros, and
                // a clone's checkpoint writes this while the guest is paused.
                for (data_from, data_to) in
                    file_data_ranges(&extent.file, extent.offset, extent_len)?
                {
                    let mut offset = data_from;
                    while offset < data_to {
                        let len = (data_to - offset).min(buffer.len());
                        extent
                            .file
                            .read_exact_at(&mut buffer[..len], extent.offset + offset as u64)?;
                        if buffer[..len].iter().any(|byte| *byte != 0) {
                            output.write_all_at(&buffer[..len], logical + offset as u64)?;
                        }
                        offset += len;
                    }
                }
                logical = logical
                    .checked_add(extent_len as u64)
                    .ok_or_else(|| invalid("RAM export size overflow"))?;
            }
        }
        output.set_len(logical)?;
        output.seek(io::SeekFrom::Start(logical))?;
        Ok(())
    }
}

/// The ranges of `[start, start + len)` in `file` that may hold data, relative
/// to `start`. The whole range when the file system cannot tell holes apart.
fn file_data_ranges(file: &File, start: u64, len: usize) -> io::Result<Vec<(usize, usize)>> {
    let end = start + len as u64;
    let mut ranges = Vec::new();
    let mut at = start;
    while at < end {
        // SAFETY: a plain lseek on a descriptor this generation owns.
        let data = unsafe { libc::lseek(file.as_raw_fd(), at as libc::off_t, libc::SEEK_DATA) };
        if data < 0 {
            let error = io::Error::last_os_error();
            return match error.raw_os_error() {
                Some(libc::ENXIO) => Ok(ranges),
                Some(libc::EINVAL) | Some(libc::EOPNOTSUPP) => Ok(vec![(0, len)]),
                _ => Err(error),
            };
        }
        let data = data as u64;
        if data >= end {
            break;
        }
        // SAFETY: as above.
        let hole = unsafe { libc::lseek(file.as_raw_fd(), data as libc::off_t, libc::SEEK_HOLE) };
        if hole < 0 {
            return Err(io::Error::last_os_error());
        }
        let hole = (hole as u64).min(end);
        ranges.push(((data - start) as usize, (hole - start) as usize));
        at = hole;
    }
    Ok(ranges)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn process_start_time(pid: u32) -> io::Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    stat.rsplit_once(") ")
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .ok_or_else(|| invalid("missing RAM owner identity"))?
        .parse()
        .map_err(|_| invalid("invalid RAM owner identity"))
}

#[derive(Clone)]
struct Extent {
    start: usize,
    end: usize,
    offset: u64,
    file: Arc<File>,
}

#[derive(Clone)]
struct Image {
    gpa: u64,
    len: usize,
    extents: Vec<Extent>,
}

struct Instance {
    memory: GuestMemoryMmap,
    image: Image,
}

impl Image {
    // The caller owns the immutability contract for the original snapshot.
    // Holding a descriptor protects against unlink, not in-place modification.
    #[cfg(test)]
    fn from_immutable_file(file: File, len: usize) -> io::Result<Self> {
        if len == 0 || !len.is_multiple_of(host_page_size()) || file.metadata()?.len() != len as u64
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "RAM image size mismatch",
            ));
        }
        Ok(Self {
            gpa: 0,
            len,
            extents: vec![Extent {
                start: 0,
                end: len,
                offset: 0,
                file: Arc::new(file),
            }],
        })
    }

    fn restore(&self) -> io::Result<Instance> {
        let prot = libc::PROT_READ | libc::PROT_WRITE;
        let region = MmapRegion::build(
            None,
            self.len,
            prot,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
        )
        .map_err(|error| io::Error::other(format!("reserve layered RAM: {error:?}")))?;
        let region = GuestRegionMmap::new(region, GuestAddress(self.gpa))
            .ok_or_else(|| io::Error::other("RAM address overflow"))?;
        let memory = GuestMemoryMmap::from_regions(vec![region])
            .map_err(|error| io::Error::other(format!("layered RAM regions: {error:?}")))?;
        let base = memory.get_host_address(GuestAddress(self.gpa)).unwrap();
        for extent in &self.extents {
            // SAFETY: each aligned extent lies exclusively inside the reserved
            // mapping owned above. On failure its RAII owner unmaps the whole
            // reservation, including already-installed file views.
            let result = unsafe {
                libc::mmap(
                    base.add(extent.start).cast(),
                    extent.end - extent.start,
                    prot,
                    libc::MAP_PRIVATE | libc::MAP_FIXED | libc::MAP_NORESERVE,
                    extent.file.as_raw_fd(),
                    extent.offset as libc::off_t,
                )
            };
            if result == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Instance {
            memory,
            image: self.clone(),
        })
    }
}

// Pagemap reveals file/shared-anon versus private pages without needing PFNs.
// Swapped entries are conservatively included and read back through the valid
// mapping, never interpreted as zero or silently omitted.
fn private_or_swapped(entry: u64) -> bool {
    entry & (1 << 62) != 0 || (entry & (1 << 63) != 0 && entry & (1 << 61) == 0)
}

fn private_page_ranges(
    pagemap: &File,
    base: u64,
    len: usize,
    page_size: usize,
) -> io::Result<Vec<(usize, usize)>> {
    let mut dirty = Vec::<(usize, usize)>::new();
    let mut entries = vec![0_u8; 8192 * 8];
    for first in (0..len / page_size).step_by(8192) {
        let count = (len / page_size - first).min(8192);
        pagemap.read_exact_at(
            &mut entries[..count * 8],
            (base / page_size as u64 + first as u64) * 8,
        )?;
        for index in 0..count {
            let entry = u64::from_ne_bytes(entries[index * 8..index * 8 + 8].try_into().unwrap());
            if private_or_swapped(entry) {
                let start = (first + index) * page_size;
                if let Some(last) = dirty.last_mut().filter(|last| last.1 == start) {
                    last.1 += page_size;
                } else {
                    dirty.push((start, start + page_size));
                }
            }
        }
    }
    Ok(dirty)
}

impl Instance {
    // Requires stopped vCPUs AND devices. Keep the original host addresses so
    // KVM slots stay valid. If a mapping fails the caller must NOT resume;
    // the VMM records that failure and refuses subsequent resume requests.
    fn rebase_quiesced(&mut self, image: Image) -> io::Result<()> {
        if image.len != self.image.len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "rebase size mismatch",
            ));
        }
        let base = self
            .memory
            .get_host_address(GuestAddress(self.image.gpa))
            .unwrap();
        for extent in &image.extents {
            // SAFETY: this instance owns the full reservation; all writers are
            // stopped and each backing contains the captured bytes for its run.
            let result = unsafe {
                libc::mmap(
                    base.add(extent.start).cast(),
                    extent.end - extent.start,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_FIXED | libc::MAP_NORESERVE,
                    extent.file.as_raw_fd(),
                    extent.offset as libc::off_t,
                )
            };
            if result == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
        }
        self.image = image;
        Ok(())
    }

    // Requires all writers to be quiesced. The caller validates private RAM
    // views and excludes device-owned mappings before scanning page state.
    #[cfg(test)]
    fn capture_quiesced(&self) -> io::Result<(Image, usize)> {
        self.capture_quiesced_within(CompactLimits::DEFAULT)
    }

    /// Capture this instance's private pages into a new sealed delta. Each
    /// capture splits older extents around the pages the guest wrote since the
    /// last one, so a machine that keeps branching fragments without bound;
    /// past `limits.trigger` extents the shortest unchanged runs are folded
    /// into the delta as well until at most `limits.goal` remain, and past
    /// `limits.files` backing files the whole region is consolidated.
    fn capture_quiesced_within(&self, limits: CompactLimits) -> io::Result<(Image, usize)> {
        // A hardened VMM is not dumpable and cannot open its own page map;
        // fall back to the descriptor the embedder opened before hardening.
        let pagemap = crate::snapshot::open_own_pagemap()?;
        let base = self
            .memory
            .get_host_address(GuestAddress(self.image.gpa))
            .unwrap() as u64;
        let dirty = private_page_ranges(&pagemap, base, self.image.len, host_page_size())?;
        if dirty.is_empty() && self.image.extents.len() <= limits.trigger {
            return Ok((self.image.clone(), 0));
        }
        let plan = plan_layout(&self.image.extents, &dirty);
        let mut folded = choose_folds(&plan, limits.trigger, limits.goal);
        release_superseded_deltas(&plan, &self.image.extents, &mut folded);
        let kept_files: std::collections::HashSet<_> = plan
            .iter()
            .zip(&folded)
            .filter_map(|(piece, folded)| piece.old.filter(|_| !folded))
            .map(|index| Arc::as_ptr(&self.image.extents[index].file))
            .collect();
        if kept_files.len() + 1 > limits.files {
            folded.fill(true);
        }
        let copy = copy_ranges(&plan, &folded);
        let delta = if copy.is_empty() {
            None
        } else {
            let delta =
                crate::builder::create_guest_ram_memfd(self.image.len).map_err(io::Error::other)?;
            // Folded runs are read through the current mapping, which shows the
            // backing file's bytes for pages the guest never wrote.
            copy_into_delta(&self.memory, self.image.gpa, &delta, &copy, COPY_CHUNK)?;
            let seals =
                libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
            if unsafe { libc::fcntl(delta.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Some(Arc::new(delta))
        };
        let copied: usize = copy.iter().map(|(start, end)| end - start).sum();
        // Flatten the mapping index now; a restore never walks a delta chain.
        let mut extents: Vec<Extent> = Vec::with_capacity(plan.len());
        for (piece, folded) in plan.iter().zip(&folded) {
            match piece.old.filter(|_| !folded) {
                Some(index) => {
                    let old = &self.image.extents[index];
                    extents.push(Extent {
                        start: piece.start,
                        end: piece.end,
                        offset: old.offset + (piece.start - old.start) as u64,
                        file: old.file.clone(),
                    });
                }
                None => {
                    let delta = delta.as_ref().expect("copied runs have a delta");
                    if let Some(last) = extents
                        .last_mut()
                        .filter(|last| Arc::ptr_eq(&last.file, delta) && last.end == piece.start)
                    {
                        last.end = piece.end;
                    } else {
                        extents.push(Extent {
                            start: piece.start,
                            end: piece.end,
                            offset: piece.start as u64,
                            file: delta.clone(),
                        });
                    }
                }
            }
        }
        let mut cursor = 0;
        for extent in &extents {
            assert_eq!(extent.start, cursor);
            cursor = extent.end;
        }
        assert_eq!(cursor, self.image.len);
        if copied > dirty.iter().map(|(start, end)| end - start).sum::<usize>() {
            log::info!(
                "compacted layered RAM at {:#x}: {} extents instead of {}, {copied} bytes copied",
                self.image.gpa,
                extents.len(),
                plan.len()
            );
        }
        Ok((
            Image {
                gpa: self.image.gpa,
                len: self.image.len,
                extents,
            },
            copied,
        ))
    }
}

/// Whether every byte of `bytes` is zero. Compares 256-byte blocks of whole
/// words, which the compiler vectorizes; a byte at a time took about 15 times
/// as long and dominated the capture of a mostly zero region.
fn is_zero(bytes: &[u8]) -> bool {
    // SAFETY: u128 has no invalid bit patterns.
    let (head, words, tail) = unsafe { bytes.align_to::<u128>() };
    head.iter().all(|byte| *byte == 0)
        && tail.iter().all(|byte| *byte == 0)
        && words
            .chunks(16)
            .all(|block| block.iter().fold(0, |any, word| any | word) == 0)
}

/// Bytes of guest RAM one capture worker copies at a time.
const COPY_CHUNK: usize = 64 << 20;

/// The most threads a capture copies with. A few threads reach the host's
/// memory bandwidth; more would only take CPU from the host's other VMs while
/// this one is paused.
const MAX_COPY_THREADS: usize = 8;

/// Copy the non-zero pages of `ranges` (offsets into the region at `gpa`) into
/// `delta` at the same offsets, `chunk` bytes at a time across up to
/// [`MAX_COPY_THREADS`] threads; a zero page stays a hole, which reads back as
/// zero without holding memory. The source stays paused for the whole copy, so
/// a branch that had written a few GB waited seconds on one thread. Workers
/// write through a shared mapping of `delta`: `pwrite` into a memfd holds its
/// inode lock, so writes from several threads would still run one at a time.
/// The mapping is gone when this returns, so the caller can seal `delta`.
fn copy_into_delta(
    memory: &GuestMemoryMmap,
    gpa: u64,
    delta: &File,
    ranges: &[(usize, usize)],
    chunk: usize,
) -> io::Result<()> {
    let len = usize::try_from(delta.metadata()?.len())
        .map_err(|_| invalid("RAM delta too large to map"))?;
    if ranges.iter().any(|&(start, end)| start > end || end > len) {
        return Err(invalid("RAM capture range outside its delta"));
    }
    let source = memory
        .get_host_address(GuestAddress(gpa))
        .map_err(|error| io::Error::other(format!("read private RAM: {error:?}")))?
        as usize;
    // MADV_DONTFORK alone leaves a fork window after mmap: an inherited
    // writable view would prevent F_SEAL_WRITE even after our view is gone.
    let mapping_setup = crate::fork_barrier::exclude_forks()?;
    // SAFETY: a new shared mapping of the whole delta, written only by the
    // workers below and unmapped before this returns.
    let target = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            delta.as_raw_fd(),
            0,
        )
    };
    if target == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    // A process forked while this writable mapping exists would keep one of
    // its own, and the kernel refuses the write seal for as long as any such
    // mapping lives. The VMM forks copy workers and guardians.
    // SAFETY: the mapping made above.
    if unsafe { libc::madvise(target, len, libc::MADV_DONTFORK) } < 0 {
        let error = io::Error::last_os_error();
        // SAFETY: the mapping made above, not yet shared with any worker.
        unsafe { libc::munmap(target, len) };
        return Err(error);
    }
    drop(mapping_setup);
    let target = target as usize;
    let chunks: Vec<(usize, usize)> = ranges
        .iter()
        .flat_map(|&(start, end)| {
            (start..end)
                .step_by(chunk)
                .map(move |from| (from, (from + chunk).min(end)))
        })
        .collect();
    let threads = thread::available_parallelism()
        .map_or(1, |n| n.get())
        .min(MAX_COPY_THREADS)
        .min(chunks.len())
        .max(1);
    let page = host_page_size();
    let next = AtomicUsize::new(0);
    let copied = thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                scope.spawn(|| {
                    while let Some(&(start, end)) = chunks.get(next.fetch_add(1, Ordering::Relaxed))
                    {
                        for offset in (start..end).step_by(page) {
                            let len = (end - offset).min(page);
                            // SAFETY: `offset + len` is inside both the guest
                            // region and the delta, the guest is paused, and
                            // the chunks are disjoint, so no two workers write
                            // the same bytes.
                            unsafe {
                                let from = (source + offset) as *const u8;
                                if !is_zero(std::slice::from_raw_parts(from, len)) {
                                    std::ptr::copy_nonoverlapping(
                                        from,
                                        (target + offset) as *mut u8,
                                        len,
                                    );
                                }
                            }
                        }
                    }
                })
            })
            .collect();
        workers.into_iter().try_for_each(|worker| {
            worker
                .join()
                .map_err(|_| io::Error::other("RAM capture worker panicked"))
        })
    });
    // SAFETY: the mapping made above; every worker has finished with it.
    if unsafe { libc::munmap(target as *mut libc::c_void, len) } < 0 {
        return Err(io::Error::last_os_error());
    }
    copied
}

/// When a capture compacts one region of a generation.
#[derive(Clone, Copy, Debug)]
struct CompactLimits {
    trigger: usize,
    goal: usize,
    files: usize,
}

impl CompactLimits {
    const DEFAULT: Self = Self {
        trigger: COMPACT_TRIGGER,
        goal: COMPACT_GOAL,
        files: COMPACT_FILES,
    };

    /// This region's share of the limits, in proportion to its size.
    fn share(self, len: usize, private_len: u128) -> Self {
        let share = |total: usize, floor: usize| {
            ((total as u128 * len as u128 / private_len.max(1)) as usize).max(floor)
        };
        Self {
            trigger: share(self.trigger, 1),
            goal: share(self.goal, 1),
            files: share(self.files, 2),
        }
    }
}

/// A capture that leaves more distinct backing files than this consolidates
/// the region into its new delta. A generation past 1024 files is refused.
const COMPACT_FILES: usize = 512;

/// A capture that would leave more extents than this compacts the generation
/// down to `COMPACT_GOAL`. Every extent is a separate mapping in each VMM that
/// runs the generation and is remapped on every capture, and a generation past
/// 65536 extents is refused outright, so stay well below both that limit and
/// the kernel's default per-process mapping limit.
const COMPACT_TRIGGER: usize = 32768;

/// Extents left after a compaction. The gap to `COMPACT_TRIGGER` lets a
/// machine branch several times before the next compaction copies anything.
const COMPACT_GOAL: usize = 16384;

/// One run of the next layout: either a piece of an existing extent (by
/// index) or pages the guest wrote, which always go to the new delta.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Piece {
    start: usize,
    end: usize,
    old: Option<usize>,
}

impl Piece {
    fn len(&self) -> usize {
        self.end - self.start
    }
}

/// Split `old` around the sorted, disjoint `dirty` runs, then merge neighbours
/// that are contiguous in the same backing. The result is the layout before
/// any compaction: one piece per extent the next generation would map.
fn plan_layout(old: &[Extent], dirty: &[(usize, usize)]) -> Vec<Piece> {
    let mut pieces = Vec::with_capacity(old.len() + 2 * dirty.len());
    let mut first_dirty = 0;
    for (index, extent) in old.iter().enumerate() {
        let mut cursor = extent.start;
        while first_dirty < dirty.len() && dirty[first_dirty].1 <= extent.start {
            first_dirty += 1;
        }
        for &(start, end) in &dirty[first_dirty..] {
            if start >= extent.end {
                break;
            }
            if start > cursor {
                pieces.push(Piece {
                    start: cursor,
                    end: start,
                    old: Some(index),
                });
            }
            cursor = cursor.max(end.min(extent.end));
            if cursor == extent.end {
                break;
            }
        }
        if cursor < extent.end {
            pieces.push(Piece {
                start: cursor,
                end: extent.end,
                old: Some(index),
            });
        }
    }
    for &(start, end) in dirty {
        pieces.push(Piece {
            start,
            end,
            old: None,
        });
    }
    pieces.sort_unstable_by_key(|piece| piece.start);
    let mut merged: Vec<Piece> = Vec::with_capacity(pieces.len());
    for piece in pieces {
        if let Some(last) = merged.last_mut() {
            let joins = last.end == piece.start
                && match (last.old, piece.old) {
                    (None, None) => true,
                    (Some(a), Some(b)) => {
                        let (a, b) = (&old[a], &old[b]);
                        Arc::ptr_eq(&a.file, &b.file)
                            && a.offset + (last.end - a.start) as u64
                                == b.offset + (piece.start - b.start) as u64
                    }
                    _ => false,
                };
            if joins {
                last.end = piece.end;
                continue;
            }
        }
        merged.push(piece);
    }
    merged
}

/// Number of extents mapped when the pieces `folded` marks are copied into the
/// delta: consecutive copied pieces become a single extent.
fn folded_extent_count(folded: &[bool]) -> usize {
    folded
        .iter()
        .enumerate()
        .filter(|&(index, &this)| !(this && index > 0 && folded[index - 1]))
        .count()
}

/// Choose which pieces of `plan` to copy into the new delta. Pages the guest
/// wrote always are. When that alone leaves more than `trigger` extents, the
/// shortest unchanged pieces are folded in as well until at most `goal`
/// remain: each fold merges a piece with its copied neighbours, so the
/// shortest pieces remove the most extents per byte copied.
fn choose_folds(plan: &[Piece], trigger: usize, goal: usize) -> Vec<bool> {
    let mut folded: Vec<bool> = plan.iter().map(|piece| piece.old.is_none()).collect();
    if plan.len() <= trigger {
        return folded;
    }
    let goal = goal.clamp(1, trigger);
    let mut lengths: Vec<usize> = plan
        .iter()
        .filter(|piece| piece.old.is_some())
        .map(Piece::len)
        .collect();
    lengths.sort_unstable();
    lengths.dedup();
    let fold_up_to = |limit: usize| -> Vec<bool> {
        plan.iter()
            .map(|piece| piece.old.is_none() || piece.len() <= limit)
            .collect()
    };
    // Folding more pieces never adds an extent, and folding every piece
    // leaves one, so the smallest sufficient length exists.
    let index = lengths.partition_point(|&limit| folded_extent_count(&fold_up_to(limit)) > goal);
    let Some(&limit) = lengths.get(index) else {
        return folded;
    };
    // Every shorter piece is needed; of the pieces exactly `limit` long, fold
    // only as many as it takes to reach the goal.
    for (flag, piece) in folded.iter_mut().zip(plan) {
        *flag |= piece.len() < limit;
    }
    let mut count = folded_extent_count(&folded);
    for index in 0..plan.len() {
        if count <= goal {
            break;
        }
        if folded[index] || plan[index].len() != limit {
            continue;
        }
        let left = index > 0 && folded[index - 1];
        let right = index + 1 < plan.len() && folded[index + 1];
        folded[index] = true;
        count -= usize::from(left) + usize::from(right);
    }
    folded
}

/// A delta stays resident as a whole while any of its pages is mapped. Fold
/// the rest of every delta that the next layout would use for less than half
/// of its resident bytes, so it can be released instead of pinning memory the
/// guest has since overwritten; every delta kept is then at least half live.
/// The restored base is a file on disk and is never folded this way.
fn release_superseded_deltas(plan: &[Piece], old: &[Extent], folded: &mut [bool]) {
    let mut live: std::collections::HashMap<*const File, (&Arc<File>, u64)> =
        std::collections::HashMap::new();
    for (piece, folded) in plan.iter().zip(folded.iter()) {
        if let Some(index) = piece.old.filter(|_| !folded) {
            let file = &old[index].file;
            live.entry(Arc::as_ptr(file)).or_insert((file, 0)).1 += piece.len() as u64;
        }
    }
    let superseded: std::collections::HashSet<*const File> = live
        .into_iter()
        .filter(|(_, (file, live))| {
            use std::os::unix::fs::MetadataExt;
            // Deltas are write-sealed memfds; a restore base is a file on disk.
            let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
            let delta = seals >= 0 && seals & libc::F_SEAL_WRITE != 0;
            delta
                && file
                    .metadata()
                    .is_ok_and(|metadata| metadata.blocks() * 512 > 2 * live)
        })
        .map(|(file, _)| file)
        .collect();
    if superseded.is_empty() {
        return;
    }
    for (piece, folded) in plan.iter().zip(folded.iter_mut()) {
        if let Some(index) = piece.old {
            *folded |= superseded.contains(&Arc::as_ptr(&old[index].file));
        }
    }
}

/// The coalesced runs copied into the new delta.
fn copy_ranges(plan: &[Piece], folded: &[bool]) -> Vec<(usize, usize)> {
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for (piece, _) in plan.iter().zip(folded).filter(|(_, folded)| **folded) {
        match ranges.last_mut() {
            Some(last) if last.1 == piece.start => last.1 = piece.end,
            _ => ranges.push((piece.start, piece.end)),
        }
    }
    ranges
}

#[test]
fn dirty_page_ranges_use_host_page_units() {
    for page_size in [4096, 16384, 65536] {
        let pagemap = crate::builder::create_guest_ram_memfd(10 * 8).unwrap();
        // The kernel exposes one entry per host page, not per guest page.
        let entries = [(1_u64 << 63) | (1_u64 << 61), 1_u64 << 63, 1_u64 << 62];
        for (index, entry) in entries.iter().enumerate() {
            pagemap
                .write_all_at(&entry.to_ne_bytes(), ((7 + index) * 8) as u64)
                .unwrap();
        }
        assert_eq!(
            private_page_ranges(&pagemap, (7 * page_size) as u64, 3 * page_size, page_size)
                .unwrap(),
            vec![(page_size, 3 * page_size)]
        );
    }
}

#[test]
fn capture_uses_the_embedder_pagemap_once_the_process_is_not_dumpable() {
    use crate::snapshot::MemoryRegionDesc;
    const NAME: &str = "capture_uses_the_embedder_pagemap_once_the_process_is_not_dumpable";
    // Becoming non-dumpable is irreversible, so run in a child test process.
    if std::env::var("KRUN_NONDUMPABLE_CAPTURE_TEST").as_deref() != Ok(NAME) {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &format!("layered_restore::{NAME}"),
                "--nocapture",
            ])
            .env("KRUN_NONDUMPABLE_CAPTURE_TEST", NAME)
            .status()
            .unwrap();
        assert!(status.success(), "non-dumpable capture test failed");
        return;
    }
    // Harden like the VMM: the embedder opens the page map first.
    let pagemap = File::open("/proc/self/pagemap").unwrap();
    // SAFETY: this child test process runs this test alone.
    unsafe { std::env::set_var("KRUN_PAGEMAP_FD", pagemap.as_raw_fd().to_string()) };
    assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) }, 0);
    if unsafe { libc::geteuid() } != 0 {
        assert_eq!(
            File::open("/proc/self/pagemap").unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
    let size = 4 * host_page_size();
    let file = crate::builder::create_guest_ram_memfd(size).unwrap();
    let generation = Generation::from_immutable_file(
        &[MemoryRegionDesc {
            gpa: 0,
            len: size as u64,
        }],
        &file,
    )
    .unwrap();
    let memory = generation.restore().unwrap();
    memory
        .write_slice(
            &vec![0x5a; host_page_size()],
            GuestAddress(host_page_size() as u64),
        )
        .unwrap();
    let (_, copied) = generation.capture_quiesced(&memory).unwrap();
    assert_eq!(copied, host_page_size());
    drop(pagemap);
}

#[test]
fn a_capture_split_across_threads_copies_every_range_exactly() {
    use crate::snapshot::MemoryRegionDesc;
    let page = host_page_size();
    let size = 64 * page;
    let file = crate::builder::create_guest_ram_memfd(size).unwrap();
    let generation = Generation::from_immutable_file(
        &[MemoryRegionDesc {
            gpa: 0,
            len: size as u64,
        }],
        &file,
    )
    .unwrap();
    let memory = generation.restore().unwrap();
    // Every page gets its own byte, except a zero page in each range.
    for index in 0..64 {
        let byte = if index % 9 == 4 { 0 } else { index as u8 + 1 };
        memory
            .write_slice(&vec![byte; page], GuestAddress((index * page) as u64))
            .unwrap();
    }
    let ranges = [
        (0, 7 * page),
        (10 * page, 11 * page),
        (20 * page, 63 * page),
    ];
    let delta = crate::builder::create_guest_ram_memfd(size).unwrap();
    // Two pages a chunk splits the ranges across many workers.
    copy_into_delta(&memory, 0, &delta, &ranges, 2 * page).unwrap();
    let mut got = vec![0; page];
    for index in 0..64 {
        delta
            .read_exact_at(&mut got, (index * page) as u64)
            .unwrap();
        let copied = ranges
            .iter()
            .any(|&(start, end)| (start..end).contains(&(index * page)));
        let want = if copied && index % 9 != 4 {
            index as u8 + 1
        } else {
            0
        };
        assert!(got.iter().all(|byte| *byte == want), "page {index}");
    }
    // The zero pages stay holes, and the delta can be sealed afterwards.
    let mut data = 0_u64;
    let mut offset = 0_i64;
    loop {
        let start = unsafe { libc::lseek(delta.as_raw_fd(), offset, libc::SEEK_DATA) };
        if start < 0 {
            break;
        }
        let end = unsafe { libc::lseek(delta.as_raw_fd(), start, libc::SEEK_HOLE) };
        data += (end - start) as u64;
        offset = end;
    }
    let nonzero = (0..64)
        .filter(|index| {
            index % 9 != 4
                && ranges
                    .iter()
                    .any(|&(start, end)| (start..end).contains(&(index * page)))
        })
        .count();
    assert_eq!(data, (nonzero * page) as u64);
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    assert_eq!(
        unsafe { libc::fcntl(delta.as_raw_fd(), libc::F_ADD_SEALS, seals) },
        0
    );
}

#[test]
fn zero_check_sees_one_set_byte_anywhere() {
    let buffer = vec![0_u8; 4096 + 64];
    // Unaligned starts and lengths exercise the head, words and tail.
    for start in 0..17 {
        for len in [0, 1, 15, 16, 255, 256, 257, 4096] {
            assert!(is_zero(&buffer[start..start + len]));
            for set in 0..len {
                let mut bytes = buffer[start..start + len].to_vec();
                bytes[set] = 1;
                assert!(!is_zero(&bytes), "start {start} len {len} byte {set}");
            }
        }
    }
}

#[test]
fn a_delta_copied_while_a_child_lives_can_still_be_sealed() {
    assert_delta_sealable_during_fork(false);
}

#[test]
fn a_delta_copied_while_a_libc_child_lives_can_still_be_sealed() {
    assert_delta_sealable_during_fork(true);
}

#[cfg(test)]
fn assert_delta_sealable_during_fork(libc_fork: bool) {
    use crate::snapshot::MemoryRegionDesc;
    let page = host_page_size();
    let size = 64 << 20;
    let file = crate::builder::create_guest_ram_memfd(size).unwrap();
    let generation = Generation::from_immutable_file(
        &[MemoryRegionDesc {
            gpa: 0,
            len: size as u64,
        }],
        &file,
    )
    .unwrap();
    let memory = generation.restore().unwrap();
    memory.write_slice(&vec![7; size], GuestAddress(0)).unwrap();
    let delta = crate::builder::create_guest_ram_memfd(size).unwrap();
    // Install the libc fork handlers before the competing thread can fork.
    drop(crate::fork_barrier::exclude_forks().unwrap());
    // A child forked mid-copy outlives it: one-page chunks keep the 64 MiB
    // copy running for tens of milliseconds, and the fork lands 2 ms in.
    let (ready_read, ready_write) = {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        (fds[0], fds[1])
    };
    let child = thread::scope(|scope| {
        let forker = scope.spawn(|| {
            let mut byte = 0_u8;
            unsafe { libc::read(ready_read, (&mut byte as *mut u8).cast(), 1) };
            thread::sleep(std::time::Duration::from_millis(2));
            let pid = unsafe {
                if libc_fork {
                    libc::fork()
                } else {
                    crate::fork_barrier::raw_fork()
                }
            };
            if pid == 0 {
                unsafe {
                    libc::sleep(5);
                    libc::_exit(0);
                }
            }
            pid
        });
        unsafe { libc::write(ready_write, [1_u8].as_ptr().cast(), 1) };
        copy_into_delta(&memory, 0, &delta, &[(0, size)], page).unwrap();
        forker.join().unwrap()
    });
    assert!(child > 0, "fork failed: {}", io::Error::last_os_error());
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    let sealed = unsafe { libc::fcntl(delta.as_raw_fd(), libc::F_ADD_SEALS, seals) };
    unsafe {
        libc::kill(child, libc::SIGKILL);
        libc::waitpid(child, std::ptr::null_mut(), 0);
        libc::close(ready_read);
        libc::close(ready_write);
    }
    assert_eq!(sealed, 0, "{}", io::Error::last_os_error());
}

#[test]
fn a_capture_range_past_the_delta_is_refused() {
    let page = host_page_size();
    let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4 * page)]).unwrap();
    let delta = crate::builder::create_guest_ram_memfd(2 * page).unwrap();
    assert!(copy_into_delta(&memory, 0, &delta, &[(page, 3 * page)], page).is_err());
}

#[test]
fn swapped_pages_are_not_discarded() {
    assert!(!private_or_swapped(0));
    assert!(!private_or_swapped((1 << 63) | (1 << 61)));
    assert!(private_or_swapped(1 << 63));
    assert!(private_or_swapped(1 << 62));
}

#[test]
#[ignore = "exhausts this process's VMA budget; run explicitly on an isolated QA host"]
fn mapping_exhaustion_during_restore_preserves_existing_instances() {
    let max_maps: usize = std::fs::read_to_string("/proc/sys/vm/max_map_count")
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(
        (1024..=2_000_000).contains(&max_maps),
        "unexpected host limit; refuse an unbounded stress run"
    );
    let file = crate::builder::create_guest_ram_memfd(2 * host_page_size()).unwrap();
    file.write_all_at(&vec![0x29; 2 * host_page_size()], 0)
        .unwrap();
    let base = Image::from_immutable_file(file, 2 * host_page_size()).unwrap();
    let source = base.restore().unwrap();
    source
        .memory
        .write_slice(&vec![0x61; host_page_size()], GuestAddress(0))
        .unwrap();
    // Reserve virtual addresses without allocating payload RAM. Alternating
    // protection splits VMAs; the kernel's existing per-process limit stops
    // this loop. No sysctl or other process's limits are changed.
    let arena = MmapRegion::<()>::build(
        None,
        max_maps * 2 * host_page_size(),
        libc::PROT_NONE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
    )
    .unwrap();
    let mut failure = None;
    let mut splits = 0;
    for index in 0..max_maps {
        let rc = unsafe {
            libc::mprotect(
                arena.as_ptr().add(index * 2 * host_page_size()).cast(),
                host_page_size(),
                libc::PROT_READ,
            )
        };
        if rc != 0 {
            failure = Some(io::Error::last_os_error());
            break;
        }
        splits += 1;
    }
    let result = base.restore();
    // Release pressure before formatting, allocating verification buffers,
    // or asserting. The RAII owner removes the entire split reservation.
    drop(arena);
    assert_eq!(failure.unwrap().raw_os_error(), Some(libc::ENOMEM));
    assert!(
        result.is_err(),
        "restore unexpectedly succeeded at the mapping limit"
    );
    println!("host_max_maps={max_maps} successful_splits={splits}");
    let mut actual = vec![0; 2 * host_page_size()];
    source
        .memory
        .read_slice(&mut actual, GuestAddress(0))
        .unwrap();
    assert_eq!(&actual[..host_page_size()], &vec![0x61; host_page_size()]);
    assert_eq!(&actual[host_page_size()..], &vec![0x29; host_page_size()]);
    let (saved, copied) = source.capture_quiesced().unwrap();
    assert_eq!(copied, host_page_size());
    saved
        .restore()
        .unwrap()
        .memory
        .read_slice(&mut actual, GuestAddress(0))
        .unwrap();
    assert_eq!(&actual[..host_page_size()], &vec![0x61; host_page_size()]);
    assert_eq!(&actual[host_page_size()..], &vec![0x29; host_page_size()]);
    base.restore()
        .unwrap()
        .memory
        .read_slice(&mut actual, GuestAddress(0))
        .unwrap();
    assert_eq!(actual, vec![0x29; 2 * host_page_size()]);
}

#[test]
#[ignore = "requires active host swap; run explicitly on an isolated QA host"]
fn capture_reads_back_actual_swapped_private_pages() {
    const SIZE: usize = 64 * 1024 * 1024;
    let file = crate::builder::create_guest_ram_memfd(SIZE).unwrap();
    let base = Image::from_immutable_file(file, SIZE).unwrap();
    let source = base.restore().unwrap();
    let address = source.memory.get_host_address(GuestAddress(0)).unwrap();
    assert_eq!(
        unsafe { libc::madvise(address.cast(), SIZE, libc::MADV_NOHUGEPAGE) },
        0
    );
    source
        .memory
        .write_slice(&vec![0x57; SIZE], GuestAddress(0))
        .unwrap();
    let pagemap = File::open("/proc/self/pagemap").unwrap();
    let mut entries = vec![0; SIZE / host_page_size() * 8];
    assert_eq!(
        unsafe { libc::madvise(address.cast(), SIZE, libc::MADV_PAGEOUT) },
        0
    );
    let mut swapped = 0;
    for _ in 0..40 {
        pagemap
            .read_exact_at(&mut entries, (address as u64 / host_page_size() as u64) * 8)
            .unwrap();
        swapped = entries
            .as_chunks::<8>()
            .0
            .iter()
            .filter(|entry| u64::from_ne_bytes(**entry) & (1 << 62) != 0)
            .count();
        if swapped != 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        swapped > 0,
        "no actual swapped pages observed; this is not swap coverage"
    );
    println!(
        "actual_swapped_pages={swapped} total_pages={}",
        SIZE / host_page_size()
    );
    let (saved, copied) = source.capture_quiesced().unwrap();
    assert_eq!(copied, SIZE);
    drop(source);
    let restored = saved.restore().unwrap();
    let mut actual = vec![0; SIZE];
    restored
        .memory
        .read_slice(&mut actual, GuestAddress(0))
        .unwrap();
    assert!(actual.iter().all(|byte| *byte == 0x57));
    let ancestor = base.restore().unwrap();
    ancestor
        .memory
        .read_slice(&mut actual, GuestAddress(0))
        .unwrap();
    assert!(actual.iter().all(|byte| *byte == 0));
}

#[test]
fn descriptor_pressure_before_capture_leaves_running_state_unchanged() {
    const CHILD: &str = "KRUN_LAYERED_FD_LIMIT_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "layered_restore::descriptor_pressure_before_capture_leaves_running_state_unchanged",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let file = crate::builder::create_guest_ram_memfd(2 * host_page_size()).unwrap();
    file.write_all_at(&vec![0x19; 2 * host_page_size()], 0)
        .unwrap();
    let base = Image::from_immutable_file(file, 2 * host_page_size()).unwrap();
    let source = base.restore().unwrap();
    source
        .memory
        .write_slice(&vec![0x43; host_page_size()], GuestAddress(0))
        .unwrap();
    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // This subprocess runs only this test; never change the parent test
    // runner's limits or affect another concurrently running VM/test.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) },
        0
    );
    let constrained = libc::rlimit {
        rlim_cur: 0,
        rlim_max: limits.rlim_max,
    };
    assert_eq!(
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &constrained) },
        0
    );
    let result = source.capture_quiesced();
    // Restore limits before assertions, formatting, or spawning any work.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limits) }, 0);
    assert_eq!(result.err().unwrap().raw_os_error(), Some(libc::EMFILE));
    let mut actual = vec![0; 2 * host_page_size()];
    source
        .memory
        .read_slice(&mut actual, GuestAddress(0))
        .unwrap();
    assert_eq!(&actual[..host_page_size()], &vec![0x43; host_page_size()]);
    assert_eq!(&actual[host_page_size()..], &vec![0x19; host_page_size()]);
    // This was a pre-installation failure, so a later capture can safely
    // retry without losing the still-private modifications.
    let (saved, copied) = source.capture_quiesced().unwrap();
    assert_eq!(copied, host_page_size());
    saved
        .restore()
        .unwrap()
        .memory
        .read_slice(&mut actual, GuestAddress(0))
        .unwrap();
    assert_eq!(&actual[..host_page_size()], &vec![0x43; host_page_size()]);
    assert_eq!(&actual[host_page_size()..], &vec![0x19; host_page_size()]);
}

#[test]
fn partial_remap_failure_keeps_complete_saved_generation_usable() {
    use std::os::unix::fs::OpenOptionsExt;
    let base_file = crate::builder::create_guest_ram_memfd(2 * host_page_size()).unwrap();
    base_file
        .write_all_at(&vec![0x11; 2 * host_page_size()], 0)
        .unwrap();
    let base = Image::from_immutable_file(base_file, 2 * host_page_size()).unwrap();
    let mut source = base.restore().unwrap();
    source
        .memory
        .write_slice(&vec![0x22; host_page_size()], GuestAddress(0))
        .unwrap();
    let (saved, _) = source.capture_quiesced().unwrap();
    assert_eq!(saved.extents.len(), 2);
    let mut unavailable = saved.clone();
    // O_PATH keeps a real, owned descriptor but cannot back mmap. The first
    // extent installs normally; the second deterministically returns EBADF.
    let path_only = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH)
        .open(format!(
            "/proc/self/fd/{}",
            saved.extents[1].file.as_raw_fd()
        ))
        .unwrap();
    unavailable.extents[1].file = Arc::new(path_only);
    let error = source.rebase_quiesced(unavailable).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::EBADF));
    // The first mapping really changed: it is now a clean file-backed view.
    // Recapturing against `base` would omit that page, so callers must latch
    // the failure instead of treating an already-paused VM as capture-ready.
    let (_, copied) = source.capture_quiesced().unwrap();
    assert_eq!(copied, 0);
    drop(source);
    let recovered = saved.restore().unwrap();
    let mut bytes = vec![0; 2 * host_page_size()];
    recovered
        .memory
        .read_slice(&mut bytes, GuestAddress(0))
        .unwrap();
    assert_eq!(&bytes[..host_page_size()], &vec![0x22; host_page_size()]);
    assert_eq!(&bytes[host_page_size()..], &vec![0x11; host_page_size()]);
    let ancestor = base.restore().unwrap();
    ancestor
        .memory
        .read_slice(&mut bytes, GuestAddress(0))
        .unwrap();
    assert_eq!(bytes, vec![0x11; 2 * host_page_size()]);
}

#[test]
fn fragmented_writes_then_dense_capture_preserve_ancestors() {
    use crate::snapshot::MemoryRegionDesc;
    const PAGES: usize = 4096;
    let file = crate::builder::create_guest_ram_memfd(PAGES * host_page_size()).unwrap();
    let mut generation = Generation::from_immutable_file(
        &[MemoryRegionDesc {
            gpa: 0,
            len: (PAGES * host_page_size()) as u64,
        }],
        &file,
    )
    .unwrap();
    let memory = generation.restore().unwrap();
    let mut ancestors = Vec::new();
    for round in 0..4 {
        for page in (round..PAGES).step_by(4) {
            memory
                .write_slice(
                    &vec![(round + 1) as u8; host_page_size()],
                    GuestAddress((page * host_page_size()) as u64),
                )
                .unwrap();
        }
        let (next, copied) = generation.capture_quiesced(&memory).unwrap();
        assert_eq!(copied, PAGES / 4 * host_page_size());
        next.rebase_quiesced(&memory).unwrap();
        ancestors.push(next.clone());
        generation = next;
    }
    assert_eq!(generation.regions[0].extents.len(), PAGES);
    // A dense overwrite should collapse the fragmented index without changing
    // any previously retained checkpoint, including untouched zero pages.
    memory
        .write_slice(&vec![0x71; PAGES * host_page_size()], GuestAddress(0))
        .unwrap();
    let (dense, copied) = generation.capture_quiesced(&memory).unwrap();
    assert_eq!(copied, PAGES * host_page_size());
    assert_eq!(dense.regions[0].extents.len(), 1);
    dense.rebase_quiesced(&memory).unwrap();
    for (round, ancestor) in ancestors.into_iter().enumerate() {
        let restored = ancestor.restore().unwrap();
        for page in 0..PAGES {
            let expected = if page % 4 <= round {
                (page % 4 + 1) as u8
            } else {
                0
            };
            let mut actual = vec![0; host_page_size()];
            restored
                .read_slice(&mut actual, GuestAddress((page * host_page_size()) as u64))
                .unwrap();
            assert_eq!(
                actual,
                vec![expected; host_page_size()],
                "round={round} page={page}"
            );
        }
    }
    let restored = dense.restore().unwrap();
    let mut actual = vec![0; PAGES * host_page_size()];
    restored.read_slice(&mut actual, GuestAddress(0)).unwrap();
    assert!(actual.iter().all(|byte| *byte == 0x71));
}

#[test]
fn compaction_folds_only_the_shortest_unchanged_runs() {
    let page = host_page_size();
    let file = Arc::new(crate::builder::create_guest_ram_memfd(16 * page).unwrap());
    let old = [Extent {
        start: 0,
        end: 16 * page,
        offset: 0,
        file,
    }];
    let pages = |runs: &[(usize, usize)]| -> Vec<(usize, usize)> {
        runs.iter().map(|&(s, e)| (s * page, e * page)).collect()
    };
    // old 0..1, dirty 1..2, old 2..3, dirty 3..4, old 4..8, dirty 8..9, old 9..16
    let plan = plan_layout(&old, &pages(&[(1, 2), (3, 4), (8, 9)]));
    assert_eq!(plan.len(), 7);
    let copied = |trigger, goal| {
        let folded = choose_folds(&plan, trigger, goal);
        (folded_extent_count(&folded), copy_ranges(&plan, &folded))
    };
    // Within the trigger only the written pages are copied.
    assert_eq!(copied(7, 2), (7, pages(&[(1, 2), (3, 4), (8, 9)])));
    // Folding the two one-page runs reaches five extents.
    assert_eq!(copied(6, 5), (4, pages(&[(0, 4), (8, 9)])));
    assert_eq!(copied(6, 3), (2, pages(&[(0, 9)])));
    assert_eq!(copied(6, 1), (1, pages(&[(0, 16)])));
}

#[test]
fn compaction_folds_only_as_many_equal_runs_as_needed() {
    let page = host_page_size();
    let file = Arc::new(crate::builder::create_guest_ram_memfd(10 * page).unwrap());
    let old = [Extent {
        start: 0,
        end: 10 * page,
        offset: 0,
        file,
    }];
    // Every other page written: ten one-page pieces, five of them unchanged.
    let dirty: Vec<_> = (1..10)
        .step_by(2)
        .map(|index| (index * page, (index + 1) * page))
        .collect();
    let plan = plan_layout(&old, &dirty);
    assert_eq!(plan.len(), 10);
    let folded = choose_folds(&plan, 8, 8);
    assert_eq!(folded_extent_count(&folded), 7);
    assert_eq!(
        copy_ranges(&plan, &folded),
        [(0, 4), (5, 6), (7, 8), (9, 10)]
            .iter()
            .map(|&(s, e)| (s * page, e * page))
            .collect::<Vec<_>>()
    );
}

#[test]
fn repeated_branches_stay_within_the_extent_budget_and_exact() {
    use crate::snapshot::MemoryRegionDesc;
    const PAGES: usize = 1024;
    const TRIGGER: usize = 32;
    const GOAL: usize = 16;
    let page = host_page_size();
    let file = crate::builder::create_guest_ram_memfd(PAGES * page).unwrap();
    // Distinct base bytes, so a folded unchanged run that copied the wrong
    // backing would not read back as zero by accident.
    let mut expected = vec![0_u8; PAGES * page];
    for (index, chunk) in expected.chunks_mut(page).enumerate() {
        chunk.fill((index % 251) as u8 + 1);
    }
    file.write_all_at(&expected, 0).unwrap();
    let mut generation = Generation::from_immutable_file(
        &[MemoryRegionDesc {
            gpa: 0,
            len: (PAGES * page) as u64,
        }],
        &file,
    )
    .unwrap();
    let memory = generation.restore().unwrap();
    let mut seed = 0x5eed_u64;
    let mut ancestors = Vec::new();
    let mut folded = false;
    for round in 0..24_usize {
        let mut written = std::collections::BTreeSet::new();
        for _ in 0..48 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let index = seed as usize % PAGES;
            written.insert(index);
            let value = if round % 5 == 4 {
                0
            } else {
                0x80 + round as u8
            };
            expected[index * page..(index + 1) * page].fill(value);
            memory
                .write_slice(
                    &expected[index * page..(index + 1) * page],
                    GuestAddress((index * page) as u64),
                )
                .unwrap();
        }
        let (next, copied) = generation
            .capture_quiesced_within(
                &memory,
                &[],
                CompactLimits {
                    trigger: TRIGGER,
                    goal: GOAL,
                    files: 8,
                },
            )
            .unwrap();
        assert!(copied >= written.len() * page);
        folded |= copied > written.len() * page;
        let files: std::collections::HashSet<_> = next.regions[0]
            .extents
            .iter()
            .map(|extent| Arc::as_ptr(&extent.file))
            .collect();
        assert!(files.len() <= 8, "round {round}: {} files", files.len());
        assert!(
            next.regions[0].extents.len() <= TRIGGER,
            "round {round}: {} extents",
            next.regions[0].extents.len()
        );
        next.rebase_quiesced(&memory).unwrap();
        ancestors.push((next.clone(), expected.clone()));
        generation = next;
    }
    assert!(folded, "the workload never needed compaction");
    let mut actual = vec![0; PAGES * page];
    memory.read_slice(&mut actual, GuestAddress(0)).unwrap();
    assert!(actual == expected, "running source diverged");
    for (round, (ancestor, model)) in ancestors.into_iter().enumerate() {
        ancestor
            .restore()
            .unwrap()
            .read_slice(&mut actual, GuestAddress(0))
            .unwrap();
        assert!(actual == model, "generation {round} diverged");
    }
}

#[test]
fn consolidation_preserves_contents_and_keeps_zero_pages_as_holes() {
    use crate::snapshot::MemoryRegionDesc;
    use std::os::unix::fs::MetadataExt;
    const PAGES: usize = 64;
    let page = host_page_size();
    let file = crate::builder::create_guest_ram_memfd(PAGES * page).unwrap();
    file.write_all_at(&vec![0x11; page], 0).unwrap();
    let generation = Generation::from_immutable_file(
        &[MemoryRegionDesc {
            gpa: 0,
            len: (PAGES * page) as u64,
        }],
        &file,
    )
    .unwrap();
    let memory = generation.restore().unwrap();
    memory
        .write_slice(&vec![0x22; page], GuestAddress((3 * page) as u64))
        .unwrap();
    // A private page that holds only zeros needs no backing either.
    memory
        .write_slice(&vec![0; page], GuestAddress((5 * page) as u64))
        .unwrap();
    // A one-file budget leaves no room for the old backing beside the delta.
    let limits = CompactLimits {
        trigger: COMPACT_TRIGGER,
        goal: COMPACT_GOAL,
        files: 1,
    };
    let instance = Instance {
        memory: memory.clone(),
        image: generation.regions[0].clone(),
    };
    let (image, copied) = instance.capture_quiesced_within(limits).unwrap();
    let next = Generation {
        regions: vec![image],
    };
    assert_eq!(copied, PAGES * page);
    assert_eq!(next.regions[0].extents.len(), 1);
    let delta = &next.regions[0].extents[0].file;
    assert!(!Arc::ptr_eq(delta, &generation.regions[0].extents[0].file));
    assert_eq!(delta.metadata().unwrap().blocks() * 512, 2 * page as u64);
    let mut expected = vec![0; PAGES * page];
    expected[..page].fill(0x11);
    expected[3 * page..4 * page].fill(0x22);
    let mut actual = vec![0; PAGES * page];
    next.restore()
        .unwrap()
        .read_slice(&mut actual, GuestAddress(0))
        .unwrap();
    assert!(actual == expected);
    // The ancestor generation is unchanged.
    generation
        .restore()
        .unwrap()
        .read_slice(&mut actual, GuestAddress(0))
        .unwrap();
    expected[3 * page..4 * page].fill(0);
    assert!(actual == expected);
}

#[test]
fn a_mostly_overwritten_delta_is_folded_away() {
    use crate::snapshot::MemoryRegionDesc;
    const PAGES: usize = 64;
    let page = host_page_size();
    let file = crate::builder::create_guest_ram_memfd(PAGES * page).unwrap();
    let generation = Generation::from_immutable_file(
        &[MemoryRegionDesc {
            gpa: 0,
            len: (PAGES * page) as u64,
        }],
        &file,
    )
    .unwrap();
    let memory = generation.restore().unwrap();
    memory
        .write_slice(&vec![0x31; 16 * page], GuestAddress(0))
        .unwrap();
    let (first, _) = generation.capture_quiesced(&memory).unwrap();
    first.rebase_quiesced(&memory).unwrap();
    let delta = first.regions[0].extents[0].file.clone();
    // Overwrite 12 of the delta's 16 pages: only a quarter stays live.
    memory
        .write_slice(&vec![0x42; 12 * page], GuestAddress(0))
        .unwrap();
    let (second, copied) = first.capture_quiesced(&memory).unwrap();
    assert_eq!(copied, 16 * page);
    assert!(
        second.regions[0]
            .extents
            .iter()
            .all(|extent| !Arc::ptr_eq(&extent.file, &delta))
    );
    let mut actual = vec![0; PAGES * page];
    second
        .restore()
        .unwrap()
        .read_slice(&mut actual, GuestAddress(0))
        .unwrap();
    assert!(actual[..12 * page].iter().all(|byte| *byte == 0x42));
    assert!(
        actual[12 * page..16 * page]
            .iter()
            .all(|byte| *byte == 0x31)
    );
    assert!(actual[16 * page..].iter().all(|byte| *byte == 0));
    // Half or more still live: the delta is kept and nothing extra is copied.
    second.rebase_quiesced(&memory).unwrap();
    memory
        .write_slice(&vec![0x53; 4 * page], GuestAddress(0))
        .unwrap();
    let (_, copied) = second.capture_quiesced(&memory).unwrap();
    assert_eq!(copied, 4 * page);
}

#[test]
fn scattered_writes_past_the_hard_limit_are_compacted_not_refused() {
    use crate::snapshot::MemoryRegionDesc;
    // Every other page written splits one extent into more than the 65536
    // a generation may hold: the shape that failed a restored machine's
    // branches and checkpoints.
    let pages = 2 * (65536 / 2 + 1);
    let page = host_page_size();
    let file = crate::builder::create_guest_ram_memfd(pages * page).unwrap();
    let generation = Generation::from_immutable_file(
        &[MemoryRegionDesc {
            gpa: 0,
            len: (pages * page) as u64,
        }],
        &file,
    )
    .unwrap();
    let memory = generation.restore().unwrap();
    for index in (0..pages).step_by(2) {
        memory
            .write_obj(0x5a_u8, GuestAddress((index * page) as u64))
            .unwrap();
    }
    let (next, _) = generation.capture_quiesced(&memory).unwrap();
    assert!(next.regions[0].extents.len() <= COMPACT_GOAL);
    next.encode_manifest().unwrap();
    next.rebase_quiesced(&memory).unwrap();
    let restored = next.restore().unwrap();
    for index in [0, 1, pages - 2, pages - 1] {
        assert_eq!(
            restored
                .read_obj::<u8>(GuestAddress((index * page) as u64))
                .unwrap(),
            if index % 2 == 0 { 0x5a } else { 0 }
        );
    }
}

#[test]
fn concurrent_siblings_capture_independent_generations() {
    use crate::snapshot::MemoryRegionDesc;
    use std::sync::Barrier;
    const PAGES: usize = 32;
    const SIBLINGS: usize = 8;
    let file = crate::builder::create_guest_ram_memfd(PAGES * host_page_size()).unwrap();
    file.write_all_at(&vec![0x59; PAGES * host_page_size()], 0)
        .unwrap();
    let base = Generation::from_immutable_file(
        &[MemoryRegionDesc {
            gpa: 0,
            len: (PAGES * host_page_size()) as u64,
        }],
        &file,
    )
    .unwrap();
    drop(file);
    let barrier = Arc::new(Barrier::new(SIBLINGS));
    let children: Vec<_> = (0..SIBLINGS)
        .map(|sibling| {
            let mut generation = base.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                // Synchronize before fallible work. A failed assertion in one
                // sibling must not strand the others at a later barrier.
                barrier.wait();
                let memory = generation.restore().unwrap();
                let mut expected = vec![0x59; PAGES * host_page_size()];
                for round in 0..4 {
                    // Every sibling first reads untouched backing concurrently,
                    // then modifies the same address with its own distinct bytes.
                    let offset = round * host_page_size();
                    assert_eq!(
                        memory.read_obj::<u8>(GuestAddress(offset as u64)).unwrap(),
                        0x59
                    );
                    let value = (sibling * 4 + round) as u8;
                    memory
                        .write_slice(&vec![value; host_page_size()], GuestAddress(offset as u64))
                        .unwrap();
                    expected[offset..offset + host_page_size()].fill(value);
                    let (next, copied) = generation.capture_quiesced(&memory).unwrap();
                    assert_eq!(copied, host_page_size());
                    next.rebase_quiesced(&memory).unwrap();
                    generation = next;
                }
                (generation, expected)
            })
        })
        .collect();
    drop(base);
    let children: Vec<_> = children
        .into_iter()
        .map(|child| child.join().unwrap())
        .collect();
    // No original mapping or parent is alive. Each independently captured
    // generation must still export its own state, including explicit zeros.
    for (generation, expected) in children {
        let mut actual = Vec::new();
        generation.write_to(&mut actual).unwrap();
        assert_eq!(actual, expected);
    }
}

#[test]
fn restore_keeps_preopened_descriptor_when_path_access_is_revoked() {
    use crate::snapshot::MemoryRegionDesc;
    use std::os::unix::fs::PermissionsExt;
    let file = crate::builder::create_guest_ram_memfd(host_page_size()).unwrap();
    file.write_all_at(&vec![0x6d; host_page_size()], 0).unwrap();
    let readonly = File::open(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
    file.set_permissions(std::fs::Permissions::from_mode(0o000))
        .unwrap();
    if unsafe { libc::geteuid() } != 0 {
        assert!(File::open(format!("/proc/self/fd/{}", readonly.as_raw_fd())).is_err());
    }
    let generation = Generation::from_immutable_file(
        &[MemoryRegionDesc {
            gpa: 0,
            len: host_page_size() as u64,
        }],
        &readonly,
    )
    .unwrap();
    drop(readonly);
    drop(file);
    let memory = generation.restore().unwrap();
    assert_eq!(memory.read_obj::<u8>(GuestAddress(0)).unwrap(), 0x6d);
}

#[test]
fn multi_region_import_capture_export_and_rebase() {
    use crate::snapshot::MemoryRegionDesc;
    use vm_memory::GuestMemoryRegion;
    let file = crate::builder::create_guest_ram_memfd(5 * host_page_size()).unwrap();
    file.write_all_at(&vec![0x11; 2 * host_page_size()], 0)
        .unwrap();
    file.write_all_at(
        &vec![0x73; 3 * host_page_size()],
        (2 * host_page_size()) as u64,
    )
    .unwrap();
    let descs = [
        MemoryRegionDesc {
            gpa: 0,
            len: (2 * host_page_size()) as u64,
        },
        MemoryRegionDesc {
            gpa: 1 << 32,
            len: (3 * host_page_size()) as u64,
        },
    ];
    let generation = Generation::from_immutable_file(&descs, &file).unwrap();
    drop(file);
    let memory = generation.restore().unwrap();
    assert_eq!(memory.num_regions(), 2);
    assert_eq!(
        memory.iter().map(|region| region.len()).collect::<Vec<_>>(),
        vec![(2 * host_page_size()) as u64, (3 * host_page_size()) as u64]
    );
    memory
        .write_slice(&vec![0; host_page_size()], GuestAddress(0))
        .unwrap();
    memory
        .write_slice(
            &vec![0x91; host_page_size()],
            GuestAddress((1 << 32) + (2 * host_page_size()) as u64),
        )
        .unwrap();
    let (captured, copied) = generation.capture_quiesced(&memory).unwrap();
    assert_eq!(copied, 2 * host_page_size());
    let descriptions = captured.descriptions();
    assert_eq!(
        descriptions
            .iter()
            .map(|region| region.extents.len())
            .sum::<usize>(),
        4
    );
    let imported = Generation::from_descriptions(std::process::id() as i32, &descriptions).unwrap();
    let mut bytes = Vec::new();
    imported.write_to(&mut bytes).unwrap();
    let mut expected = vec![0; host_page_size()];
    expected.extend_from_slice(&vec![0x11; host_page_size()]);
    expected.extend_from_slice(&vec![0x73; 2 * host_page_size()]);
    expected.extend_from_slice(&vec![0x91; host_page_size()]);
    assert_eq!(bytes, expected);
    captured.rebase_quiesced(&memory).unwrap();
    let (_, copied) = captured.capture_quiesced(&memory).unwrap();
    assert_eq!(copied, 0);
    drop(generation);
    drop(captured);
    drop(memory);
    let restored = imported.restore().unwrap();
    assert_eq!(restored.num_regions(), 2);
    assert_eq!(restored.read_obj::<u8>(GuestAddress(0)).unwrap(), 0);
    assert_eq!(
        restored.read_obj::<u8>(GuestAddress(1 << 32)).unwrap(),
        0x73
    );
    assert_eq!(
        restored
            .read_obj::<u8>(GuestAddress((1 << 32) + (2 * host_page_size()) as u64))
            .unwrap(),
        0x91
    );
}

#[test]
fn grown_layered_ram_captures_private_writes_and_keeps_siblings_independent() {
    let page = host_page_size();
    let file = crate::builder::create_guest_ram_memfd(page).unwrap();
    file.write_all_at(&vec![0x11; page], 0).unwrap();
    let base = Generation::from_immutable_file(
        &[crate::snapshot::MemoryRegionDesc {
            gpa: 0,
            len: page as u64,
        }],
        &file,
    )
    .unwrap();
    let memory = base.restore().unwrap().with_shared_growth();
    let added_gpa = 1 << 32;
    let (grown, added) = base.with_zero_region(added_gpa, 2 * page).unwrap();
    memory
        .append_shared_region_with(
            added,
            |_| Ok::<_, vm_memory::GuestRegionCollectionError>(()),
        )
        .unwrap();
    assert_eq!(memory.read_obj::<u8>(GuestAddress(added_gpa)).unwrap(), 0);
    // The old metadata reproduces the pre-integration failure deterministically.
    assert!(base.capture_quiesced(&memory).is_err());
    memory
        .write_slice(&vec![0x72; page], GuestAddress(added_gpa))
        .unwrap();
    memory
        .write_slice(&vec![0x33; page], GuestAddress(0))
        .unwrap();
    let (captured, copied) = grown.capture_quiesced(&memory).unwrap();
    assert_eq!(copied, 2 * page);
    captured.rebase_quiesced(&memory).unwrap();
    let child = captured.restore().unwrap();
    memory
        .write_slice(&vec![0x49; page], GuestAddress(added_gpa))
        .unwrap();
    child
        .write_slice(&vec![0x56; page], GuestAddress(added_gpa + page as u64))
        .unwrap();
    let (parent_next, _) = captured.capture_quiesced(&memory).unwrap();
    let (child_next, _) = captured.capture_quiesced(&child).unwrap();
    drop(memory);
    drop(child);
    drop(captured);
    let parent = parent_next.restore().unwrap();
    let child = child_next.restore().unwrap();
    assert_eq!(
        parent.read_obj::<u8>(GuestAddress(added_gpa)).unwrap(),
        0x49
    );
    assert_eq!(
        parent
            .read_obj::<u8>(GuestAddress(added_gpa + page as u64))
            .unwrap(),
        0
    );
    assert_eq!(child.read_obj::<u8>(GuestAddress(added_gpa)).unwrap(), 0x72);
    assert_eq!(
        child
            .read_obj::<u8>(GuestAddress(added_gpa + page as u64))
            .unwrap(),
        0x56
    );
    assert_eq!(
        base.restore()
            .unwrap()
            .read_obj::<u8>(GuestAddress(0))
            .unwrap(),
        0x11
    );
    assert!(grown.with_zero_region(added_gpa, page).is_err());
    assert!(grown.with_zero_region(1, page).is_err());
}

#[test]
fn manifest_handoff_retains_private_checkpoint_after_owner_drops() {
    use crate::snapshot::MemoryRegionDesc;
    use std::os::unix::fs::PermissionsExt;
    let file = crate::builder::create_guest_ram_memfd(3 * host_page_size()).unwrap();
    file.write_all_at(&vec![0x79; 3 * host_page_size()], 0)
        .unwrap();
    let readonly = File::open(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
    file.set_permissions(std::fs::Permissions::from_mode(0o000))
        .unwrap();
    let base = Generation::from_immutable_file(
        &[MemoryRegionDesc {
            gpa: 0,
            len: (3 * host_page_size()) as u64,
        }],
        &readonly,
    )
    .unwrap();
    let parent = base.restore().unwrap();
    parent
        .write_slice(
            &vec![0; host_page_size()],
            GuestAddress(host_page_size() as u64),
        )
        .unwrap();
    let (snapshot, copied) = base.capture_quiesced(&parent).unwrap();
    assert_eq!(copied, host_page_size());
    let directory =
        std::env::temp_dir().join(format!("krun-generation-fds-{}", std::process::id()));
    let deep = directory.join("generation-".repeat(12));
    std::fs::create_dir_all(&deep).unwrap();
    let socket = deep.join("f");
    let (manifest, service) = snapshot.publish_manifest(&socket).unwrap();
    let imported = Generation::decode_manifest(&manifest).unwrap();
    drop(service);
    drop(snapshot);
    drop(base);
    drop(parent);
    drop(file);
    drop(readonly);
    let child = imported.restore().unwrap();
    assert_eq!(child.read_obj::<u8>(GuestAddress(0)).unwrap(), 0x79);
    assert_eq!(
        child
            .read_obj::<u8>(GuestAddress(host_page_size() as u64))
            .unwrap(),
        0
    );
    assert_eq!(
        child
            .read_obj::<u8>(GuestAddress((2 * host_page_size()) as u64))
            .unwrap(),
        0x79
    );
    assert!(Generation::decode_manifest(&manifest).is_err());
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(target_arch = "x86_64")]
#[test]
fn deferred_checkpoint_preserves_boundary_after_source_continues() {
    use crate::snapshot::{DeferredMemorySave, MemoryRegionDesc};
    let file = crate::builder::create_guest_ram_memfd(3 * host_page_size()).unwrap();
    file.write_all_at(&vec![0x31; 3 * host_page_size()], 0)
        .unwrap();
    let base = Generation::from_immutable_file(
        &[MemoryRegionDesc {
            gpa: 0,
            len: (3 * host_page_size()) as u64,
        }],
        &file,
    )
    .unwrap();
    let source = base.restore().unwrap();
    source
        .write_slice(
            &vec![0; host_page_size()],
            GuestAddress(host_page_size() as u64),
        )
        .unwrap();
    let (saved, copied) = base.capture_quiesced(&source).unwrap();
    assert_eq!(copied, host_page_size());
    saved.rebase_quiesced(&source).unwrap();
    let stream = DeferredMemorySave::from_layered(saved.clone());
    let sparse = DeferredMemorySave::from_layered(saved);
    source
        .write_slice(&vec![0x99; 3 * host_page_size()], GuestAddress(0))
        .unwrap();
    drop(base);
    drop(file);
    let mut expected = vec![0x31; 3 * host_page_size()];
    expected[host_page_size()..2 * host_page_size()].fill(0);
    let mut wire = Vec::new();
    let regions = stream.finish_stream(&mut wire).unwrap();
    assert_eq!(regions.len(), 1);
    assert_eq!(&wire[..8], b"SMOLRAM1");
    assert_eq!(
        u64::from_le_bytes(wire[8..16].try_into().unwrap()),
        (3 * host_page_size()) as u64
    );
    assert_eq!(&wire[16..], expected);
    let mut output = crate::builder::create_guest_ram_memfd(4 * host_page_size()).unwrap();
    output
        .write_all_at(&vec![0x77; 4 * host_page_size()], 0)
        .unwrap();
    sparse.finish(&mut output).unwrap();
    assert_eq!(
        output.metadata().unwrap().len(),
        (3 * host_page_size()) as u64
    );
    let mut bytes = vec![0; 3 * host_page_size()];
    output.read_exact_at(&mut bytes, 0).unwrap();
    assert_eq!(bytes, expected);
    assert_eq!(source.read_obj::<u8>(GuestAddress(0)).unwrap(), 0x99);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn layered_sparse_checkpoint_keeps_header_and_complete_generation() {
    use crate::snapshot::{DeferredMemorySave, MemoryRegionDesc};
    use std::io::{Read, Write};

    let page = host_page_size();
    let file = crate::builder::create_guest_ram_memfd(4 * page).unwrap();
    file.write_all_at(&vec![0x31; 4 * page], 0).unwrap();
    let regions = [
        MemoryRegionDesc {
            gpa: 0,
            len: (2 * page) as u64,
        },
        MemoryRegionDesc {
            gpa: 1 << 32,
            len: (2 * page) as u64,
        },
    ];
    let base = Generation::from_immutable_file(&regions, &file).unwrap();
    let source = base.restore().unwrap();
    source
        .write_slice(&vec![0; page], GuestAddress(page as u64))
        .unwrap();
    source
        .write_slice(&vec![0x42; page], GuestAddress((1 << 32) + page as u64))
        .unwrap();
    let (saved, _) = base.capture_quiesced(&source).unwrap();
    saved.rebase_quiesced(&source).unwrap();
    source
        .write_slice(&vec![0x99; page], GuestAddress(0))
        .unwrap();
    drop((file, base));

    let mut expected = vec![0x31; 4 * page];
    expected[page..2 * page].fill(0);
    expected[3 * page..].fill(0x42);
    let mut wire = Vec::new();
    let mut headers = 0;
    DeferredMemorySave::from_layered(saved.clone())
        .finish_sparse_stream_with_header(&mut wire, |descs, out| {
            headers += 1;
            assert_eq!(descs.len(), 2);
            assert_eq!(descs[1].gpa, 1 << 32);
            out.write_all(b"outer")
        })
        .unwrap();
    assert_eq!(headers, 1, "checkpoint metadata must precede RAM");
    assert_eq!(&wire[..5], b"outer");
    assert_eq!(&wire[5..13], b"SMOLRSP1");
    assert_eq!(
        u64::from_le_bytes(wire[13..21].try_into().unwrap()),
        expected.len() as u64
    );
    let count = u32::from_le_bytes(wire[21..25].try_into().unwrap()) as usize;
    let mut decoded = vec![0; expected.len()];
    let mut payload = std::io::Cursor::new(&wire[25 + count * 16..]);
    for index in 0..count {
        let start = 25 + index * 16;
        let offset = u64::from_le_bytes(wire[start..start + 8].try_into().unwrap()) as usize;
        let len = u64::from_le_bytes(wire[start + 8..start + 16].try_into().unwrap()) as usize;
        payload
            .read_exact(&mut decoded[offset..offset + len])
            .unwrap();
    }
    assert_eq!(payload.position() as usize, payload.get_ref().len());
    assert_eq!(decoded, expected);
    assert_eq!(source.read_obj::<u8>(GuestAddress(0)).unwrap(), 0x99);

    let mut rejected = Vec::new();
    let error = DeferredMemorySave::from_layered(saved)
        .finish_sparse_stream_with_header(&mut rejected, |_, _| {
            Err(io::ErrorKind::BrokenPipe.into())
        })
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert!(rejected.is_empty());
}

#[test]
fn malformed_generation_descriptions_are_rejected_before_mapping() {
    use crate::snapshot::MemoryRegionDesc;
    let file = crate::builder::create_guest_ram_memfd(2 * host_page_size()).unwrap();
    let generation = Generation::from_immutable_file(
        &[MemoryRegionDesc {
            gpa: 0,
            len: (2 * host_page_size()) as u64,
        }],
        &file,
    )
    .unwrap();
    let valid = generation.descriptions();
    let mut cases = Vec::new();
    let mut bad = valid.clone();
    bad[0].extents[0].start = host_page_size() as u64;
    cases.push(bad);
    let mut bad = valid.clone();
    bad[0].extents[0].len = host_page_size() as u64;
    cases.push(bad);
    let mut bad = valid.clone();
    bad[0].extents[0].offset = host_page_size() as u64;
    cases.push(bad);
    let mut bad = valid.clone();
    bad[0].extents[0].fd = -1;
    cases.push(bad);
    let mut bad = valid.clone();
    bad[0].gpa = u64::MAX;
    cases.push(bad);
    let mut bad = valid.clone();
    bad.push(bad[0].clone());
    cases.push(bad);
    let mut bad = valid.clone();
    bad[0].extents.clear();
    cases.push(bad);
    let mut bad = valid.clone();
    bad[0].extents[0].len = 1;
    cases.push(bad);
    let mut bad = valid.clone();
    bad[0].extents[0].offset = 1;
    cases.push(bad);
    for bad in cases {
        assert!(Generation::from_descriptions(std::process::id() as i32, &bad).is_err());
    }
    assert!(Generation::from_descriptions(0, &valid).is_err());
    assert!(Generation::from_descriptions(std::process::id() as i32, &[]).is_err());
}

#[test]
fn manifest_rejects_truncation_trailing_data_and_stale_owner() {
    let file = crate::builder::create_guest_ram_memfd(host_page_size()).unwrap();
    let generation = Generation::from_immutable_file(
        &[crate::snapshot::MemoryRegionDesc {
            gpa: 0,
            len: host_page_size() as u64,
        }],
        &file,
    )
    .unwrap();
    let bytes = generation.encode_manifest().unwrap();
    for len in 0..bytes.len() {
        assert!(
            Generation::decode_manifest(&bytes[..len]).is_err(),
            "prefix {len}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(Generation::decode_manifest(&trailing).is_err());
    let mut stale = bytes.clone();
    stale[16] ^= 1;
    assert!(Generation::decode_manifest(&stale).is_err());
    let imported = Generation::decode_manifest(&bytes).unwrap();
    drop(generation);
    drop(file);
    assert_eq!(
        imported
            .restore()
            .unwrap()
            .read_obj::<u8>(GuestAddress(0))
            .unwrap(),
        0
    );
}

#[test]
fn manifest_imports_backing_in_an_independent_process() {
    const INPUT: &str = "LIBKRUN_LAYERED_TEST_MANIFEST";
    if let Some(path) = std::env::var_os(INPUT) {
        let bytes = std::fs::read(path).unwrap();
        let image = Generation::decode_manifest(&bytes).unwrap();
        let memory = image.restore().unwrap();
        assert_eq!(memory.read_obj::<u8>(GuestAddress(0)).unwrap(), 0x42);
        assert_eq!(
            memory
                .read_obj::<u8>(GuestAddress(host_page_size() as u64))
                .unwrap(),
            0x73
        );
        memory.write_slice(&[0x91], GuestAddress(0)).unwrap();
        let (next, _) = image.capture_quiesced(&memory).unwrap();
        let grandchild = next.restore().unwrap();
        assert_eq!(grandchild.read_obj::<u8>(GuestAddress(0)).unwrap(), 0x91);
        return;
    }
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let file = crate::builder::create_guest_ram_memfd(2 * host_page_size()).unwrap();
    file.write_all_at(&vec![0x73; host_page_size()], host_page_size() as u64)
        .unwrap();
    let image = Generation::from_immutable_file(
        &[crate::snapshot::MemoryRegionDesc {
            gpa: 0,
            len: (2 * host_page_size()) as u64,
        }],
        &file,
    )
    .unwrap();
    let memory = image.restore().unwrap();
    memory
        .write_slice(&vec![0x42; host_page_size()], GuestAddress(0))
        .unwrap();
    let (captured, _) = image.capture_quiesced(&memory).unwrap();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("layered-manifest-{}-{nonce}", std::process::id()));
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    output
        .write_all(&captured.encode_manifest().unwrap())
        .unwrap();
    drop(output);
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "layered_restore::manifest_imports_backing_in_an_independent_process",
            "--nocapture",
        ])
        .env(INPUT, &path)
        .status()
        .unwrap();
    std::fs::remove_file(path).unwrap();
    assert!(status.success());
    assert_eq!(memory.read_obj::<u8>(GuestAddress(0)).unwrap(), 0x42);
}

#[test]
fn unlinked_readonly_file_outlives_parents_and_generations() {
    use std::os::unix::fs::OpenOptionsExt;
    let len: usize = 32 * host_page_size();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("layered-ram-{}-{nonce}", std::process::id()));
    let file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    file.write_all_at(&vec![0x73; len], 0).unwrap();
    drop(file);
    let file = File::open(&path).unwrap();
    let image = Image::from_immutable_file(file, len).unwrap();
    let parent = image.restore().unwrap();
    std::fs::remove_file(&path).unwrap();
    parent
        .memory
        .write_slice(&vec![0x42; host_page_size()], GuestAddress(0))
        .unwrap();
    let (first, _) = parent.capture_quiesced().unwrap();
    let child = first.restore().unwrap();
    child
        .memory
        .write_slice(
            &vec![0; host_page_size()],
            GuestAddress(host_page_size() as u64),
        )
        .unwrap();
    let (second, _) = child.capture_quiesced().unwrap();
    drop(parent);
    drop(child);
    drop(image);
    drop(first);
    let grandchild = second.restore().unwrap();
    drop(second);
    assert_eq!(
        grandchild.memory.read_obj::<u8>(GuestAddress(0)).unwrap(),
        0x42
    );
    assert_eq!(
        grandchild
            .memory
            .read_obj::<u8>(GuestAddress(host_page_size() as u64))
            .unwrap(),
        0
    );
    assert_eq!(
        grandchild
            .memory
            .read_obj::<u8>(GuestAddress((len - host_page_size()) as u64))
            .unwrap(),
        0x73
    );
}

#[test]
fn repeated_capture_reuses_previous_private_pages() {
    let file = crate::builder::create_guest_ram_memfd(16 * host_page_size()).unwrap();
    let image = Image::from_immutable_file(file, 16 * host_page_size()).unwrap();
    let mut instance = image.restore().unwrap();
    instance
        .memory
        .write_slice(&vec![0x73; host_page_size()], GuestAddress(0))
        .unwrap();
    let (first, copied) = instance.capture_quiesced().unwrap();
    assert_eq!(copied, host_page_size());
    let address = instance.memory.get_host_address(GuestAddress(0)).unwrap();
    instance.rebase_quiesced(first.clone()).unwrap();
    assert_eq!(
        instance.memory.get_host_address(GuestAddress(0)).unwrap(),
        address
    );
    let (_, copied) = instance.capture_quiesced().unwrap();
    assert_eq!(copied, 0);
    instance
        .memory
        .write_slice(
            &vec![0x91; host_page_size()],
            GuestAddress(host_page_size() as u64),
        )
        .unwrap();
    let (second, copied) = instance.capture_quiesced().unwrap();
    assert_eq!(copied, host_page_size());
    instance.rebase_quiesced(second.clone()).unwrap();
    let before = first.restore().unwrap();
    let after = second.restore().unwrap();
    assert_eq!(before.memory.read_obj::<u8>(GuestAddress(0)).unwrap(), 0x73);
    assert_eq!(
        before
            .memory
            .read_obj::<u8>(GuestAddress(host_page_size() as u64))
            .unwrap(),
        0
    );
    assert_eq!(after.memory.read_obj::<u8>(GuestAddress(0)).unwrap(), 0x73);
    assert_eq!(
        after
            .memory
            .read_obj::<u8>(GuestAddress(host_page_size() as u64))
            .unwrap(),
        0x91
    );
}

#[test]
fn sixty_four_generations_match_full_memory_model() {
    let len: usize = 128 * host_page_size();
    let file = crate::builder::create_guest_ram_memfd(len).unwrap();
    let mut image = Image::from_immutable_file(file, len).unwrap();
    let mut expected = vec![0; len];
    let mut seed = 0x713_4179_u64;
    for generation in 0..64_u8 {
        let mut instance = image.restore().unwrap();
        for _ in 0..7 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let offset = (seed as usize % 128) * host_page_size();
            let value = if generation % 3 == 0 { 0 } else { generation };
            expected[offset..offset + host_page_size()].fill(value);
            instance
                .memory
                .write_slice(
                    &expected[offset..offset + host_page_size()],
                    GuestAddress(offset as u64),
                )
                .unwrap();
        }
        let (next, _) = instance.capture_quiesced().unwrap();
        instance.rebase_quiesced(next.clone()).unwrap();
        let mut actual = vec![0; len];
        instance
            .memory
            .read_slice(&mut actual, GuestAddress(0))
            .unwrap();
        assert_eq!(actual, expected, "generation {generation}");
        let restored = next.restore().unwrap();
        restored
            .memory
            .read_slice(&mut actual, GuestAddress(0))
            .unwrap();
        assert_eq!(actual, expected, "restored generation {generation}");
        image = next;
    }
}

#[test]
#[ignore = "8 GiB address-space test, not an 8 GiB resident application"]
fn eight_gib_address_space_branches_without_full_backing_copy() {
    use std::time::Instant;
    let len: usize = 8 * 1024 * 1024 * 1024;
    let file = crate::builder::create_guest_ram_memfd(len).unwrap();
    file.write_all_at(
        &vec![0x73; host_page_size()],
        (len - host_page_size()) as u64,
    )
    .unwrap();
    let image = Image::from_immutable_file(file, len).unwrap();
    let begin = Instant::now();
    let parent = image.restore().unwrap();
    let map_us = begin.elapsed().as_micros();
    parent
        .memory
        .write_slice(&vec![0x42; host_page_size()], GuestAddress(0))
        .unwrap();
    let begin = Instant::now();
    let (first, copied) = parent.capture_quiesced().unwrap();
    let capture_us = begin.elapsed().as_micros();
    assert_eq!(copied, host_page_size());
    let child = first.restore().unwrap();
    child
        .memory
        .write_slice(
            &vec![0x91; host_page_size()],
            GuestAddress(host_page_size() as u64),
        )
        .unwrap();
    let (second, nested_copied) = child.capture_quiesced().unwrap();
    assert_eq!(nested_copied, host_page_size());
    drop(parent);
    drop(child);
    drop(image);
    drop(first);
    let grandchild = second.restore().unwrap();
    for (offset, value) in [
        (0, 0x42),
        (host_page_size(), 0x91),
        (len - host_page_size(), 0x73),
    ] {
        assert_eq!(
            grandchild
                .memory
                .read_obj::<u8>(GuestAddress(offset as u64))
                .unwrap(),
            value
        );
    }
    println!(
        "layered_address_space bytes={len} map_us={map_us} capture_us={capture_us} copied={copied} nested_copied={nested_copied}"
    );
}

#[test]
fn nested_layers_preserve_modified_unread_and_zero_pages() {
    let len: usize = 32 * 1024 * 1024;
    let file = crate::builder::create_guest_ram_memfd(len).unwrap();
    file.write_all_at(
        &vec![0x73; host_page_size()],
        (len - host_page_size()) as u64,
    )
    .unwrap();
    file.write_all_at(&vec![0x11; host_page_size()], host_page_size() as u64)
        .unwrap();
    let image = Image::from_immutable_file(file, len).unwrap();
    let parent = image.restore().unwrap();
    parent
        .memory
        .write_slice(&vec![0x42; host_page_size()], GuestAddress(0))
        .unwrap();
    let (first, copied) = parent.capture_quiesced().unwrap();
    assert_eq!(copied, host_page_size());
    let child = first.restore().unwrap();
    let sibling = first.restore().unwrap();
    child
        .memory
        .write_slice(
            &vec![0; host_page_size()],
            GuestAddress(host_page_size() as u64),
        )
        .unwrap();
    child
        .memory
        .write_slice(&vec![0x91; host_page_size()], GuestAddress(0))
        .unwrap();
    let (second, copied) = child.capture_quiesced().unwrap();
    assert_eq!(copied, 2 * host_page_size());
    drop(parent);
    drop(child);
    drop(first);
    drop(image);
    let grandchild = second.restore().unwrap();
    let mut bytes = vec![0; host_page_size()];
    for (offset, value) in [
        (0, 0x91),
        (host_page_size(), 0),
        (len - host_page_size(), 0x73),
    ] {
        grandchild
            .memory
            .read_slice(&mut bytes, GuestAddress(offset as u64))
            .unwrap();
        assert_eq!(bytes, vec![value; host_page_size()]);
    }
    sibling
        .memory
        .read_slice(&mut bytes, GuestAddress(0))
        .unwrap();
    assert_eq!(bytes, vec![0x42; host_page_size()]);
    sibling
        .memory
        .read_slice(&mut bytes, GuestAddress(host_page_size() as u64))
        .unwrap();
    assert_eq!(bytes, vec![0x11; host_page_size()]);
    let (_, copied) = grandchild.capture_quiesced().unwrap();
    assert_eq!(copied, 0, "read-only faults must not become copied deltas");
}

#[cfg(target_arch = "x86_64")]
#[test]
fn kvm_writes_are_preserved_in_nested_layers() {
    use kvm_bindings::{kvm_regs, kvm_userspace_memory_region};
    use kvm_ioctls::{Kvm, VcpuExit};
    fn run(instance: &Instance, value: u8) {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        // SAFETY: the instance retains the full backing reservation until
        // after every vCPU exits and the VM descriptor is dropped.
        unsafe {
            vm.set_user_memory_region(kvm_userspace_memory_region {
                slot: 0,
                guest_phys_addr: 0,
                memory_size: instance.image.len as u64,
                userspace_addr: instance.memory.get_host_address(GuestAddress(0)).unwrap() as u64,
                flags: 0,
            })
        }
        .unwrap();
        std::thread::scope(|scope| {
            for id in 0..8 {
                let mut cpu = vm.create_vcpu(id).unwrap();
                let mut sregs = cpu.get_sregs().unwrap();
                sregs.cs.base = 0;
                sregs.cs.selector = 0;
                sregs.ds.base = 0;
                sregs.ds.selector = 0;
                cpu.set_sregs(&sregs).unwrap();
                cpu.set_regs(&kvm_regs {
                    rip: 0,
                    rflags: 2,
                    rax: value as u64,
                    rbx: 0x4000 + id * host_page_size() as u64,
                    ..Default::default()
                })
                .unwrap();
                scope.spawn(move || assert!(matches!(cpu.run().unwrap(), VcpuExit::Hlt)));
            }
        });
    }
    let file = crate::builder::create_guest_ram_memfd(2 * 1024 * 1024).unwrap();
    // 16-bit real mode: mov [bx], al; hlt. Code remains shared/read-only.
    file.write_all_at(&[0x88, 0x07, 0xf4], 0).unwrap();
    let image = Image::from_immutable_file(file, 2 * 1024 * 1024).unwrap();
    let first = image.restore().unwrap();
    run(&first, 0x5A);
    let (generation, copied) = first.capture_quiesced().unwrap();
    assert_eq!(copied, 8 * host_page_size());
    let second = generation.restore().unwrap();
    run(&second, 0x91);
    let (nested, copied) = second.capture_quiesced().unwrap();
    assert_eq!(copied, 8 * host_page_size());
    let third = nested.restore().unwrap();
    let sibling = generation.restore().unwrap();
    drop(image);
    drop(first);
    drop(second);
    drop(generation);
    drop(nested);
    for id in 0..8 {
        let address = GuestAddress(0x4000 + id * host_page_size() as u64);
        assert_eq!(third.memory.read_obj::<u8>(address).unwrap(), 0x91);
        assert_eq!(sibling.memory.read_obj::<u8>(address).unwrap(), 0x5A);
    }
}

#[cfg(target_arch = "aarch64")]
#[test]
fn arm_kvm_writes_are_preserved_in_nested_layers() {
    use kvm_bindings::{
        KVM_REG_ARM_CORE, KVM_REG_ARM64, KVM_REG_SIZE_U64, kvm_regs, kvm_userspace_memory_region,
        kvm_vcpu_init, user_pt_regs,
    };
    use kvm_ioctls::{Kvm, VcpuExit};
    use std::mem::{offset_of, size_of};

    const LEN: usize = 2 * 1024 * 1024;
    const CPUS: u64 = 2;
    fn run(instance: &Instance, value: u8) {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        // SAFETY: the instance owns the reservation until all vCPUs and
        // the VM descriptor are dropped, just as in the x86 KVM test.
        unsafe {
            vm.set_user_memory_region(kvm_userspace_memory_region {
                slot: 0,
                guest_phys_addr: 0,
                memory_size: LEN as u64,
                userspace_addr: instance.memory.get_host_address(GuestAddress(0)).unwrap() as u64,
                flags: 0,
            })
        }
        .unwrap();
        let mut target = kvm_vcpu_init::default();
        vm.get_preferred_target(&mut target).unwrap();
        let core = KVM_REG_ARM64 | KVM_REG_SIZE_U64 | u64::from(KVM_REG_ARM_CORE);
        let reg = |offset: usize| {
            core | ((offset_of!(kvm_regs, regs) + offset) / size_of::<u32>()) as u64
        };
        // Initialize all vCPUs before running any of them; ARM KVM freezes
        // parts of VM configuration on its first KVM_RUN.
        let cpus: Vec<_> = (0..CPUS)
            .map(|id| {
                let cpu = vm.create_vcpu(id).unwrap();
                cpu.vcpu_init(&target).unwrap();
                for (offset, value) in [
                    (offset_of!(user_pt_regs, pc), 0),
                    (offset_of!(user_pt_regs, pstate), 0x3c5), // EL1h, interrupts masked.
                    (
                        offset_of!(user_pt_regs, regs),
                        4 * host_page_size() as u64 + id * host_page_size() as u64,
                    ),
                    (
                        offset_of!(user_pt_regs, regs) + size_of::<u64>(),
                        u64::from(value),
                    ),
                    (
                        offset_of!(user_pt_regs, regs) + 2 * size_of::<u64>(),
                        LEN as u64,
                    ),
                ] {
                    cpu.set_one_reg(reg(offset), &value.to_le_bytes()).unwrap();
                }
                cpu
            })
            .collect();
        std::thread::scope(|scope| {
            for mut cpu in cpus {
                scope.spawn(move || match cpu.run().unwrap() {
                    VcpuExit::MmioWrite(address, bytes) => {
                        assert_eq!(address, LEN as u64);
                        assert_eq!(bytes, &[value]);
                    }
                    exit => panic!("unexpected guest completion: {exit:?}"),
                });
            }
        });
    }

    let file = crate::builder::create_guest_ram_memfd(LEN).unwrap();
    // strb w1, [x0]; strb w1, [x2]. The first instruction modifies RAM;
    // the second signals completion through an unmapped MMIO address.
    file.write_all_at(&[0x01, 0x00, 0x00, 0x39, 0x41, 0x00, 0x00, 0x39], 0)
        .unwrap();
    let image = Image::from_immutable_file(file, LEN).unwrap();
    let first = image.restore().unwrap();
    run(&first, 0x5a);
    let (generation, copied) = first.capture_quiesced().unwrap();
    assert_eq!(copied, CPUS as usize * host_page_size());
    let second = generation.restore().unwrap();
    run(&second, 0x91);
    let (nested, copied) = second.capture_quiesced().unwrap();
    assert_eq!(copied, CPUS as usize * host_page_size());
    let third = nested.restore().unwrap();
    let sibling = generation.restore().unwrap();
    drop((image, first, second, generation, nested));
    for id in 0..CPUS {
        let address = GuestAddress((4 + id) * host_page_size() as u64);
        assert_eq!(third.memory.read_obj::<u8>(address).unwrap(), 0x91);
        assert_eq!(sibling.memory.read_obj::<u8>(address).unwrap(), 0x5a);
    }
}

#[test]
fn sealed_memfd_source_adopts_its_files_without_copying() {
    use vm_memory::FileOffset;
    let page = host_page_size();
    let len = 8 * page;
    // Two memfd-backed regions on separate files, laid out like a branchable
    // source's RAM, and written through their shared mappings as a running
    // guest would write them.
    let files: Vec<File> = (0..2)
        .map(|_| crate::builder::create_guest_ram_memfd(len).unwrap())
        .collect();
    let memory = GuestMemoryMmap::from_ranges_with_files(vec![
        (
            GuestAddress(0),
            len,
            Some(FileOffset::new(files[0].try_clone().unwrap(), 0)),
        ),
        (
            GuestAddress(len as u64),
            len,
            Some(FileOffset::new(files[1].try_clone().unwrap(), 0)),
        ),
    ])
    .unwrap();
    memory
        .write_slice(&vec![0x11; page], GuestAddress(0))
        .unwrap();
    memory
        .write_slice(&vec![0x22; page], GuestAddress((len + page) as u64))
        .unwrap();
    // Shared, unsealed RAM is not a generation yet.
    assert!(Generation::from_sealed_memory(&memory).is_err());

    crate::snapshot::rebase_guest_memory_private(&memory).unwrap();
    let base = Generation::from_sealed_memory(&memory).unwrap();
    let (first, copied) = base.capture_quiesced(&memory).unwrap();
    assert_eq!(copied, 0, "adopting the source's own files copies nothing");
    first.rebase_quiesced(&memory).unwrap();
    let child = first.restore().unwrap();
    assert_eq!(child.read_obj::<u8>(GuestAddress(0)).unwrap(), 0x11);

    // A source that was already remapped privately by an earlier capture keeps
    // its private writes through a repeated rebase, and adopting it captures
    // exactly those writes.
    memory
        .write_slice(&vec![0x44; page], GuestAddress((2 * page) as u64))
        .unwrap();
    crate::snapshot::rebase_guest_memory_private(&memory).unwrap();
    assert_eq!(
        memory
            .read_obj::<u8>(GuestAddress((2 * page) as u64))
            .unwrap(),
        0x44
    );
    let (adopted_private, copied) = Generation::from_sealed_memory(&memory)
        .unwrap()
        .capture_quiesced(&memory)
        .unwrap();
    assert_eq!(copied, page);
    assert_eq!(
        adopted_private
            .restore()
            .unwrap()
            .read_obj::<u8>(GuestAddress((2 * page) as u64))
            .unwrap(),
        0x44
    );
    let (first, copied) = first.capture_quiesced(&memory).unwrap();
    assert_eq!(copied, page);
    first.rebase_quiesced(&memory).unwrap();
    assert_eq!(
        child
            .read_obj::<u8>(GuestAddress((len + page) as u64))
            .unwrap(),
        0x22
    );

    // The source keeps running on private pages. The next capture copies
    // exactly the page it wrote, the sealed base file never changes, and the
    // earlier child never sees the write.
    memory
        .write_slice(&vec![0x33; page], GuestAddress(page as u64))
        .unwrap();
    let (second, copied) = first.capture_quiesced(&memory).unwrap();
    assert_eq!(copied, page);
    second.rebase_quiesced(&memory).unwrap();
    let mut buffer = vec![0xff; page];
    files[0].read_exact_at(&mut buffer, page as u64).unwrap();
    assert!(buffer.iter().all(|byte| *byte == 0));
    assert_eq!(child.read_obj::<u8>(GuestAddress(page as u64)).unwrap(), 0);
    assert_eq!(
        memory.read_obj::<u8>(GuestAddress(page as u64)).unwrap(),
        0x33
    );
    let grandchild = second.restore().unwrap();
    assert_eq!(grandchild.read_obj::<u8>(GuestAddress(0)).unwrap(), 0x11);
    assert_eq!(
        grandchild
            .read_obj::<u8>(GuestAddress(page as u64))
            .unwrap(),
        0x33
    );
}

#[test]
#[ignore = "timing only: run explicitly to compare capture speed"]
fn capture_timing_bench() {
    use crate::snapshot::MemoryRegionDesc;
    let gib = 4_usize;
    let size = gib << 30;
    let page = host_page_size();
    let file = crate::builder::create_guest_ram_memfd(size).unwrap();
    let base = Generation::from_immutable_file(
        &[MemoryRegionDesc {
            gpa: 0,
            len: size as u64,
        }],
        &file,
    )
    .unwrap();
    let memory = base.restore().unwrap();
    // A branch that wrote every page: half data, half zero (freed guest memory).
    let data = vec![0x5a_u8; page];
    let zero = vec![0_u8; page];
    for index in 0..size / page {
        let bytes = if index % 2 == 0 { &data } else { &zero };
        memory
            .write_slice(bytes, GuestAddress((index * page) as u64))
            .unwrap();
    }
    let started = std::time::Instant::now();
    let (_next, copied) = base.capture_quiesced(&memory).unwrap();
    eprintln!(
        "CAPTURE {gib} GiB written, {copied} bytes copied in {:.3} s",
        started.elapsed().as_secs_f64()
    );
}

#[test]
fn data_ranges_skip_a_memfd_s_holes() {
    const MIB: u64 = 1024 * 1024;
    let file = crate::builder::create_guest_ram_memfd((8 * MIB) as usize).unwrap();
    file.write_all_at(&[1; 4096], MIB).unwrap();
    file.write_all_at(&[2; 4096], 5 * MIB).unwrap();
    let ranges = file_data_ranges(&file, 0, (8 * MIB) as usize).unwrap();
    assert_eq!(
        ranges,
        vec![
            (MIB as usize, MIB as usize + 4096),
            (5 * MIB as usize, 5 * MIB as usize + 4096)
        ]
    );
    // Offsets are relative to the start asked for, and clipped to its end.
    assert_eq!(file_data_ranges(&file, MIB, 2048).unwrap(), vec![(0, 2048)]);
    let empty = crate::builder::create_guest_ram_memfd(MIB as usize).unwrap();
    assert!(
        file_data_ranges(&empty, 0, MIB as usize)
            .unwrap()
            .is_empty()
    );
}
