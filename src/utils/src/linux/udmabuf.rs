use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::path::Path;

use kvm_bindings::__IncompleteArrayField;
use nix::fcntl;
use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use nix::unistd::SysconfVar;
use nix::unistd::sysconf;
use thiserror::Error;
use vm_memory::Address;
use vm_memory::GuestAddress;
use vm_memory::GuestMemoryBackend;
use vm_memory::GuestMemoryMmap;
use vm_memory::GuestMemoryRegion;
use vmm_sys_util::fam::{self, FamStruct, FamStructWrapper};
use vmm_sys_util::generate_fam_struct_impl;

#[derive(Error, Debug)]
pub enum UdmabufError {
    #[error("system call returned {0}")]
    NixError(nix::Error),

    #[error("could not create ioctl struct: {0}")]
    StructError(fam::Error),

    #[error("page size unavailable")]
    NoPageSize,

    #[error("could not find memory region")]
    RegionNotFound,

    #[error("memory region not backed by memfd")]
    RegionNotFileBacked,

    #[error("provided address and length are out of bounds for a region")]
    OutOfBounds,

    #[error("starting address or length not page aligned")]
    NotPageAligned,
}

pub type Result<T> = std::result::Result<T, UdmabufError>;

const UDMABUF_FLAGS_CLOEXEC: u32 = 1;

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
struct UdmabufCreateItem {
    memfd: i32,
    __pad: u32,
    offset: u64,
    size: u64,
}

#[repr(C)]
#[derive(Debug, Default)]
struct UdmabufCreateList {
    flags: u32,
    count: u32,
    list: __IncompleteArrayField<UdmabufCreateItem>,
}

generate_fam_struct_impl!(
    UdmabufCreateList,
    UdmabufCreateItem,
    list,
    u32,
    count,
    65535
);

type UdmabufCreateListWrapper = FamStructWrapper<UdmabufCreateList>;

nix::ioctl_write_ptr!(create_list, b'u', 0x43, UdmabufCreateList);

/// A convenience wrapper for the Linux kernel's udmabuf driver.
pub struct UdmabufDriver {
    driver_fd: OwnedFd,
    page_size: usize,
}

impl UdmabufDriver {
    pub fn new() -> Result<UdmabufDriver> {
        const UDMABUF_PATH: &str = "/dev/udmabuf";
        let path = Path::new(UDMABUF_PATH);
        let driver_fd =
            fcntl::open(path, OFlag::O_RDONLY, Mode::empty()).map_err(UdmabufError::NixError)?;

        let page_size = sysconf(SysconfVar::PAGE_SIZE)
            .map_err(UdmabufError::NixError)?
            .ok_or(UdmabufError::NoPageSize)? as usize;

        Ok(UdmabufDriver {
            driver_fd,
            page_size,
        })
    }

    pub fn create_udmabuf(
        &self,
        mem: &GuestMemoryMmap,
        iovecs: &[(GuestAddress, usize)],
    ) -> Result<OwnedFd> {
        log::warn!("create_udmabuf: {} iovecs", iovecs.len());
        let mut list = UdmabufCreateListWrapper::from_header(UdmabufCreateList {
            flags: UDMABUF_FLAGS_CLOEXEC,
            ..Default::default()
        })
        .map_err(UdmabufError::StructError)?;
        for &(addr, len) in iovecs.iter() {
            let region = mem.find_region(addr).ok_or(UdmabufError::RegionNotFound)?;

            let Some(file_offset) = region.file_offset() else {
                return Err(UdmabufError::RegionNotFileBacked);
            };

            let map_offset = addr
                .checked_sub(region.start_addr().0)
                .ok_or(UdmabufError::OutOfBounds)?;

            if map_offset.0 as usize + len > region.len() as usize {
                return Err(UdmabufError::OutOfBounds);
            }

            let offset = file_offset.start() + map_offset.0;

            if offset as usize % self.page_size != 0 || len % self.page_size != 0 {
                return Err(UdmabufError::NotPageAligned);
            }

            list.push(UdmabufCreateItem {
                memfd: file_offset.file().as_raw_fd(),
                __pad: 0,
                offset: offset,
                size: len as u64,
            })
            .map_err(UdmabufError::StructError)?;
        }

        // SAFETY: We have correctly allocated the structure above
        let fd = unsafe { create_list(self.driver_fd.as_raw_fd(), list.as_mut_fam_struct_ptr()) }
            .map_err(UdmabufError::NixError)?;

        // SAFETY: Returned i32 is a valid fd since it was positive
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}
