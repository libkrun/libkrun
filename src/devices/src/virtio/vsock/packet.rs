// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//

/// VSOCK headers occupy the beginning of a descriptor chain. Payload may be
/// inline after the header, in subsequent descriptors, or both. Contiguous
/// payloads use guest memory directly; scattered payloads use bounded staging.
use std::convert::TryInto;
use std::ffi::CStr;
use std::net::{Ipv4Addr, SocketAddrV4};
#[cfg(target_os = "macos")]
use std::net::{Ipv6Addr, SocketAddrV6};
use std::os::raw::c_char;
use std::result;
use std::{ptr, slice};

#[cfg(windows)]
use super::windows::sockaddr_storage::SockaddrStorage;
#[cfg(target_os = "linux")]
use nix::sys::socket::{AddressFamily, sockaddr};
#[cfg(unix)]
use nix::sys::socket::{SockaddrLike, SockaddrStorage};
use utils::byte_order;
use vm_memory::{self, Address, GuestAddress, GuestMemoryBackend, GuestMemoryError};

use super::super::DescriptorChain;
use super::defs;
use super::{Result, VsockError};

// The vsock packet header is defined by the C struct:
//
// ```C
// struct virtio_vsock_hdr {
//     le64 src_cid;
//     le64 dst_cid;
//     le32 src_port;
//     le32 dst_port;
//     le32 len;
//     le16 type;
//     le16 op;
//     le32 flags;
//     le32 buf_alloc;
//     le32 fwd_cnt;
// };
// ```
//
// This structed will occupy the buffer pointed to by the head descriptor. We'll be accessing it
// as a byte slice. To that end, we define below the offsets for each field struct, as well as the
// packed struct size, as a bunch of `usize` consts.
// Note that these offsets are only used privately by the `VsockPacket` struct, the public interface
// consisting of getter and setter methods, for each struct field, that will also handle the correct
// endianess.

/// The vsock packet header struct size (when packed).
pub const VSOCK_PKT_HDR_SIZE: usize = 44;

// Source CID.
const HDROFF_SRC_CID: usize = 0;

// Destination CID.
const HDROFF_DST_CID: usize = 8;

// Source port.
const HDROFF_SRC_PORT: usize = 16;

// Destination port.
const HDROFF_DST_PORT: usize = 20;

// Data length (in bytes) - may be 0, if there is no data buffer.
const HDROFF_LEN: usize = 24;

// Socket type. Currently, only connection-oriented streams are defined by the vsock protocol.
const HDROFF_TYPE: usize = 28;

// Operation ID - one of the VSOCK_OP_* values; e.g.
// - VSOCK_OP_RW: a data packet;
// - VSOCK_OP_REQUEST: connection request;
// - VSOCK_OP_RST: forcefull connection termination;
// etc (see `super::defs::uapi` for the full list).
const HDROFF_OP: usize = 30;

// Additional options (flags) associated with the current operation (`op`).
// Currently, only used with shutdown requests (VSOCK_OP_SHUTDOWN).
const HDROFF_FLAGS: usize = 32;

// Size (in bytes) of the packet sender receive buffer (for the connection to which this packet
// belongs).
const HDROFF_BUF_ALLOC: usize = 36;

// Number of bytes the sender has received and consumed (for the connection to which this packet
// belongs). For instance, for our Unix backend, this counter would be the total number of bytes
// we have successfully written to a backing Unix socket.
const HDROFF_FWD_CNT: usize = 40;

#[repr(C)]
pub struct TsiProxyCreate {
    pub peer_port: u32,
    pub family: u16,
    pub _type: u16,
    pub protocol: u32,
}

#[repr(C)]
pub struct TsiConnectReq {
    pub request_id: u64,
    pub peer_port: u32,
    pub addr: SockaddrStorage,
}

#[repr(C)]
pub struct TsiConnectRsp {
    pub result: i32,
}

#[repr(C)]
pub struct TsiGetnameReq {
    pub peer_port: u32,
    pub local_port: u32,
    pub peer: u32,
}

#[repr(C)]
#[derive(Debug)]
#[cfg_attr(feature = "tsi-fault-injection", derive(Clone))]
pub struct TsiGetnameRsp {
    pub result: i32,
    pub addr_len: u32,
    pub addr: SockaddrStorage,
}

impl Default for TsiGetnameRsp {
    fn default() -> Self {
        let addr: SockaddrStorage = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0).into();
        TsiGetnameRsp {
            result: -1,
            // It's fine to unwrap here sice we've just created the SocketAddrV4 above.
            addr_len: addr.as_sockaddr_in().unwrap().len(),
            addr,
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct TsiSendtoAddr {
    pub peer_port: u32,
    pub addr: SockaddrStorage,
}

#[repr(C)]
#[derive(Debug)]
pub struct TsiListenReq {
    pub peer_port: u32,
    pub vm_port: u32,
    pub backlog: i32,
    pub addr: SockaddrStorage,
    pub strict: bool,
}

impl TsiListenReq {
    pub fn response_flags(&self) -> u32 {
        #[cfg(unix)]
        let inet = self.addr.as_sockaddr_in().is_some() || self.addr.as_sockaddr_in6().is_some();
        #[cfg(windows)]
        let inet = matches!(
            self.addr.family(),
            defs::LINUX_AF_INET | defs::LINUX_AF_INET6
        );
        if self.strict && inet {
            defs::TSI_LISTEN_STRICT
        } else {
            0
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct TsiListenRsp {
    pub result: i32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct TsiAcceptReq {
    pub request_id: u64,
    pub peer_port: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct TsiAcceptRsp {
    pub result: i32,
}

#[repr(C)]
pub struct TsiReleaseReq {
    pub peer_port: u32,
    pub local_port: u32,
}

pub struct VsockPacket {
    hdr: *mut u8,
    buf: Option<*mut u8>,
    buf_size: usize,
    owned_buf: Option<Vec<u8>>,
    rx_regions: Vec<(*mut u8, usize)>,
}

fn get_host_address<T: GuestMemoryBackend>(
    mem: &T,
    guest_addr: GuestAddress,
    size: usize,
) -> result::Result<*mut u8, GuestMemoryError> {
    Ok(mem.get_slice(guest_addr, size)?.ptr_guard_mut().as_ptr())
}

fn data_regions(
    head: &DescriptorChain,
    writable: bool,
    limit: usize,
) -> Result<Vec<(*mut u8, usize)>> {
    let mut remaining = limit;
    let mut regions = Vec::new();
    for (i, desc) in head.clone().into_iter().enumerate() {
        if desc.is_write_only() != writable {
            return Err(if writable {
                VsockError::UnwritableDescriptor
            } else {
                VsockError::UnreadableDescriptor
            });
        }
        let offset = if i == 0 { VSOCK_PKT_HDR_SIZE } else { 0 };
        let count = (desc.len as usize - offset).min(remaining);
        if count > 0 {
            let addr = desc
                .addr
                .checked_add(offset as u64)
                .ok_or(VsockError::GuestMemoryBounds)?;
            let ptr =
                get_host_address(desc.mem, addr, count).map_err(VsockError::GuestMemoryMmap)?;
            regions.push((ptr, count));
            remaining -= count;
        }
        if remaining == 0 {
            break;
        }
    }
    Ok(regions)
}

impl VsockPacket {
    pub fn from_tx_virtq_head(head: &DescriptorChain) -> Result<Self> {
        if head.is_write_only() {
            return Err(VsockError::UnreadableDescriptor);
        }
        if head.len < VSOCK_PKT_HDR_SIZE as u32 {
            return Err(VsockError::HdrDescTooSmall(head.len));
        }
        let mut pkt = Self {
            hdr: get_host_address(head.mem, head.addr, VSOCK_PKT_HDR_SIZE)
                .map_err(VsockError::GuestMemoryMmap)?,
            buf: None,
            buf_size: 0,
            owned_buf: None,
            rx_regions: Vec::new(),
        };
        let len = pkt.len() as usize;
        if len > defs::MAX_PKT_BUF_SIZE {
            return Err(VsockError::InvalidPktLen(len as u32));
        }
        if len == 0 {
            return Ok(pkt);
        }
        let inline = head.len as usize - VSOCK_PKT_HDR_SIZE;
        if inline >= len {
            let addr = head
                .addr
                .checked_add(VSOCK_PKT_HDR_SIZE as u64)
                .ok_or(VsockError::GuestMemoryBounds)?;
            pkt.buf =
                Some(get_host_address(head.mem, addr, len).map_err(VsockError::GuestMemoryMmap)?);
            pkt.buf_size = len;
            return Ok(pkt);
        }
        if inline == 0 {
            let desc = head.next_descriptor().ok_or(VsockError::BufDescMissing)?;
            if desc.is_write_only() {
                return Err(VsockError::UnreadableDescriptor);
            }
            if desc.len as usize >= len {
                pkt.buf = Some(
                    get_host_address(desc.mem, desc.addr, len)
                        .map_err(VsockError::GuestMemoryMmap)?,
                );
                pkt.buf_size = len;
                return Ok(pkt);
            }
        }
        let regions = data_regions(head, false, len)?;
        if regions.iter().map(|(_, count)| count).sum::<usize>() != len {
            return Err(VsockError::BufDescTooSmall);
        }
        let mut data = Vec::with_capacity(len);
        for (ptr, count) in regions {
            data.extend_from_slice(unsafe { slice::from_raw_parts(ptr, count) });
        }
        pkt.buf_size = len;
        pkt.owned_buf = Some(data);
        Ok(pkt)
    }

    pub fn from_rx_virtq_head(head: &DescriptorChain) -> Result<Self> {
        if !head.is_write_only() {
            return Err(VsockError::UnwritableDescriptor);
        }
        if head.len < VSOCK_PKT_HDR_SIZE as u32 {
            return Err(VsockError::HdrDescTooSmall(head.len));
        }
        let mut pkt = Self {
            hdr: get_host_address(head.mem, head.addr, VSOCK_PKT_HDR_SIZE)
                .map_err(VsockError::GuestMemoryMmap)?,
            buf: None,
            buf_size: 0,
            owned_buf: None,
            rx_regions: Vec::new(),
        };
        if !head.has_next() && head.len as usize > VSOCK_PKT_HDR_SIZE {
            let addr = head
                .addr
                .checked_add(VSOCK_PKT_HDR_SIZE as u64)
                .ok_or(VsockError::GuestMemoryBounds)?;
            pkt.buf_size = (head.len as usize - VSOCK_PKT_HDR_SIZE).min(defs::MAX_PKT_BUF_SIZE);
            pkt.buf = Some(
                get_host_address(head.mem, addr, pkt.buf_size)
                    .map_err(VsockError::GuestMemoryMmap)?,
            );
            return Ok(pkt);
        }
        if head.len as usize == VSOCK_PKT_HDR_SIZE {
            let desc = head.next_descriptor().ok_or(VsockError::BufDescMissing)?;
            if !desc.is_write_only() {
                return Err(VsockError::UnwritableDescriptor);
            }
            if !desc.has_next() && desc.len > 0 {
                pkt.buf_size = (desc.len as usize).min(defs::MAX_PKT_BUF_SIZE);
                pkt.buf = Some(
                    get_host_address(desc.mem, desc.addr, pkt.buf_size)
                        .map_err(VsockError::GuestMemoryMmap)?,
                );
                return Ok(pkt);
            }
        }
        let mut regions = data_regions(head, true, defs::MAX_PKT_BUF_SIZE)?;
        pkt.buf_size = regions.iter().map(|(_, count)| count).sum();
        if pkt.buf_size == 0 {
            return Err(VsockError::BufDescMissing);
        }
        if regions.len() == 1 {
            pkt.buf = Some(regions.pop().unwrap().0);
        } else {
            pkt.owned_buf = Some(vec![0; pkt.buf_size]);
            pkt.rx_regions = regions;
        }
        Ok(pkt)
    }

    /// Scatter staged data before the caller publishes the used-ring entry.
    pub fn finish_rx(self) -> Result<u32> {
        let len = self.len() as usize;
        if len > self.buf_size {
            return Err(VsockError::BufDescTooSmall);
        }
        if !self.rx_regions.is_empty() {
            let data = self.owned_buf.as_ref().unwrap();
            let mut offset = 0;
            for (ptr, capacity) in self.rx_regions {
                let count = capacity.min(len - offset);
                unsafe {
                    ptr::copy_nonoverlapping(data.as_ptr().add(offset), ptr, count);
                }
                offset += count;
                if offset == len {
                    break;
                }
            }
        }
        Ok((VSOCK_PKT_HDR_SIZE + len) as u32)
    }

    /// Provides in-place, byte-slice, access to the vsock packet header.
    pub fn hdr(&self) -> &[u8] {
        // This is safe since bound checks have already been performed when creating the packet
        // from the virtq descriptor.
        unsafe { slice::from_raw_parts(self.hdr as *const u8, VSOCK_PKT_HDR_SIZE) }
    }

    /// Provides in-place, byte-slice, mutable access to the vsock packet header.
    pub fn hdr_mut(&mut self) -> &mut [u8] {
        // This is safe since bound checks have already been performed when creating the packet
        // from the virtq descriptor.
        unsafe { slice::from_raw_parts_mut(self.hdr, VSOCK_PKT_HDR_SIZE) }
    }

    /// Provides in-place, byte-slice access to the vsock packet data buffer.
    ///
    /// Note: control packets (e.g. connection request or reset) have no data buffer associated.
    ///       For those packets, this method will return `None`.
    /// Also note: calling `len()` on the returned slice will yield the buffer size, which may be
    ///            (and often is) larger than the length of the packet data. The packet data length
    ///            is stored in the packet header, and accessible via `VsockPacket::len()`.
    pub fn buf(&self) -> Option<&[u8]> {
        if let Some(ref owned) = self.owned_buf {
            Some(owned.as_slice())
        } else {
            self.buf.map(|ptr| {
                // This is safe since bound checks have already been performed when creating the
                // packet from the virtq descriptor.
                unsafe { slice::from_raw_parts(ptr as *const u8, self.buf_size) }
            })
        }
    }

    /// Provides in-place, byte-slice, mutable access to the vsock packet data buffer.
    ///
    /// Note: control packets (e.g. connection request or reset) have no data buffer associated.
    ///       For those packets, this method will return `None`.
    /// Also note: calling `len()` on the returned slice will yield the buffer size, which may be
    ///            (and often is) larger than the length of the packet data. The packet data length
    ///            is stored in the packet header, and accessible via `VsockPacket::len()`.
    pub fn buf_mut(&mut self) -> Option<&mut [u8]> {
        if let Some(ref mut owned) = self.owned_buf {
            Some(owned.as_mut_slice())
        } else {
            self.buf.map(|ptr| {
                // This is safe since bound checks have already been performed when creating the
                // packet from the virtq descriptor.
                unsafe { slice::from_raw_parts_mut(ptr, self.buf_size) }
            })
        }
    }

    pub fn src_cid(&self) -> u64 {
        byte_order::read_le_u64(&self.hdr()[HDROFF_SRC_CID..])
    }

    pub fn set_src_cid(&mut self, cid: u64) -> &mut Self {
        byte_order::write_le_u64(&mut self.hdr_mut()[HDROFF_SRC_CID..], cid);
        self
    }

    pub fn dst_cid(&self) -> u64 {
        byte_order::read_le_u64(&self.hdr()[HDROFF_DST_CID..])
    }

    pub fn set_dst_cid(&mut self, cid: u64) -> &mut Self {
        byte_order::write_le_u64(&mut self.hdr_mut()[HDROFF_DST_CID..], cid);
        self
    }

    pub fn src_port(&self) -> u32 {
        byte_order::read_le_u32(&self.hdr()[HDROFF_SRC_PORT..])
    }

    pub fn set_src_port(&mut self, port: u32) -> &mut Self {
        byte_order::write_le_u32(&mut self.hdr_mut()[HDROFF_SRC_PORT..], port);
        self
    }

    pub fn dst_port(&self) -> u32 {
        byte_order::read_le_u32(&self.hdr()[HDROFF_DST_PORT..])
    }

    pub fn set_dst_port(&mut self, port: u32) -> &mut Self {
        byte_order::write_le_u32(&mut self.hdr_mut()[HDROFF_DST_PORT..], port);
        self
    }

    pub fn len(&self) -> u32 {
        byte_order::read_le_u32(&self.hdr()[HDROFF_LEN..])
    }

    pub fn set_len(&mut self, len: u32) -> &mut Self {
        byte_order::write_le_u32(&mut self.hdr_mut()[HDROFF_LEN..], len);
        self
    }

    pub fn type_(&self) -> u16 {
        byte_order::read_le_u16(&self.hdr()[HDROFF_TYPE..])
    }

    pub fn set_type(&mut self, type_: u16) -> &mut Self {
        byte_order::write_le_u16(&mut self.hdr_mut()[HDROFF_TYPE..], type_);
        self
    }

    pub fn op(&self) -> u16 {
        byte_order::read_le_u16(&self.hdr()[HDROFF_OP..])
    }

    pub fn set_op(&mut self, op: u16) -> &mut Self {
        byte_order::write_le_u16(&mut self.hdr_mut()[HDROFF_OP..], op);
        self
    }

    pub fn flags(&self) -> u32 {
        byte_order::read_le_u32(&self.hdr()[HDROFF_FLAGS..])
    }

    pub fn set_flags(&mut self, flags: u32) -> &mut Self {
        byte_order::write_le_u32(&mut self.hdr_mut()[HDROFF_FLAGS..], flags);
        self
    }

    pub fn set_flag(&mut self, flag: u32) -> &mut Self {
        self.set_flags(self.flags() | flag);
        self
    }

    pub fn buf_alloc(&self) -> u32 {
        byte_order::read_le_u32(&self.hdr()[HDROFF_BUF_ALLOC..])
    }

    pub fn set_buf_alloc(&mut self, buf_alloc: u32) -> &mut Self {
        byte_order::write_le_u32(&mut self.hdr_mut()[HDROFF_BUF_ALLOC..], buf_alloc);
        self
    }

    pub fn fwd_cnt(&self) -> u32 {
        byte_order::read_le_u32(&self.hdr()[HDROFF_FWD_CNT..])
    }

    pub fn set_fwd_cnt(&mut self, fwd_cnt: u32) -> &mut Self {
        byte_order::write_le_u32(&mut self.hdr_mut()[HDROFF_FWD_CNT..], fwd_cnt);
        self
    }

    pub fn sa_family(&self) -> Option<u16> {
        if self.buf_size >= 2 {
            Some(byte_order::read_le_u16(&self.buf().unwrap()[0..]))
        } else {
            None
        }
    }

    pub fn inet_port(&self) -> Option<u16> {
        if self.buf_size >= 4 {
            Some(byte_order::read_be_u16(&self.buf().unwrap()[2..]))
        } else {
            None
        }
    }

    pub fn inet_addr(&self) -> Option<[u8; 4]> {
        if self.buf_size >= 8 {
            let ptr = &self.buf().unwrap()[4];
            let slice = unsafe { slice::from_raw_parts(ptr as *const u8, 4) };
            slice[0..4].try_into().ok()
        } else {
            None
        }
    }

    pub fn unix_path(&self) -> Option<&str> {
        if self.buf_size >= 108 {
            let cstr =
                unsafe { CStr::from_ptr(&self.buf().unwrap()[2] as *const _ as *const c_char) };
            cstr.to_str().ok()
        } else {
            None
        }
    }

    fn parse_address(buf: &[u8], addr_len: u32) -> Option<SockaddrStorage> {
        let len = addr_len as usize;
        if !(2..=128).contains(&len) || buf.len() < len {
            return None;
        }
        let family = byte_order::read_le_u16(buf);
        if !matches!((family, len), (2, 16) | (10, 28) | (1, 2..=110)) {
            return None;
        }
        Self::parse_host_address(&buf[..len], addr_len)
    }

    #[cfg(target_os = "linux")]
    fn parse_host_address(buf: &[u8], addr_len: u32) -> Option<SockaddrStorage> {
        let sockaddr: SockaddrStorage = unsafe {
            SockaddrStorage::from_raw(&buf[0] as *const _ as *const sockaddr, Some(addr_len))?
        };

        match sockaddr.family() {
            Some(AddressFamily::Inet) => debug!("parse_address: AF_INET"),
            Some(AddressFamily::Inet6) => debug!("parse_address: AF_INET6"),
            Some(AddressFamily::Unix) => debug!("parse_address: AF_UNIX"),
            _ => {
                if let Some(family) = sockaddr.family() {
                    warn!("parse_address: unsupported family {family:?}");
                } else {
                    warn!("parse_address: error parsing family");
                }
                return None;
            }
        }

        Some(sockaddr)
    }

    #[cfg(target_os = "macos")]
    fn parse_host_address(buf: &[u8], _addr_len: u32) -> Option<SockaddrStorage> {
        let family: u16 = byte_order::read_le_u16(&buf[0..2]);

        match family {
            defs::LINUX_AF_INET => {
                debug!("parse_address: AF_INET");
                let in_port: u16 = byte_order::read_be_u16(&buf[2..4]);
                let in_addr = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
                Some(SocketAddrV4::new(in_addr, in_port).into())
            }
            defs::LINUX_AF_INET6 => {
                debug!("parse_address: AF_INET6");
                let in_port: u16 = byte_order::read_be_u16(&buf[2..4]);
                let flowinfo: u32 = byte_order::read_be_u32(&buf[4..8]).to_be();
                let in6_addr = Ipv6Addr::new(
                    byte_order::read_be_u16(&buf[8..10]),
                    byte_order::read_be_u16(&buf[10..12]),
                    byte_order::read_be_u16(&buf[12..14]),
                    byte_order::read_be_u16(&buf[14..16]),
                    byte_order::read_be_u16(&buf[16..18]),
                    byte_order::read_be_u16(&buf[18..20]),
                    byte_order::read_be_u16(&buf[20..22]),
                    byte_order::read_be_u16(&buf[22..24]),
                );
                let scope_id: u32 = byte_order::read_le_u32(&buf[24..28]);
                Some(SocketAddrV6::new(in6_addr, in_port, flowinfo, scope_id).into())
            }
            defs::LINUX_AF_UNIX => {
                // On macOS, SockaddrStorage doesn't implement `from_raw` for
                // Unix sockets, nor a way to cast an UnixPath to it.
                error!("AF_UNIX sockets aren't yet supported on macOS");
                None
            }
            _ => None,
        }
    }

    #[cfg(target_os = "windows")]
    fn parse_host_address(buf: &[u8], addr_len: u32) -> Option<SockaddrStorage> {
        SockaddrStorage::from_linux_bytes(buf, addr_len)
    }

    pub fn control_request_id(&self) -> u64 {
        super::tsi_wire::control_id(self.buf().unwrap_or_default()).unwrap_or(0)
    }

    pub fn control_payload(&self) -> std::result::Result<&[u8], i32> {
        super::tsi_wire::decode_control(self.buf().unwrap_or_default(), self.dst_port())
    }

    fn control_response_buf(&mut self, request_id: u64, len: usize) -> Option<&mut [u8]> {
        let total = super::tsi_wire::CONTROL_HEADER_LEN + len;
        if self.buf_size < total {
            self.set_len(0);
            return None;
        }
        let operation = self.src_port();
        self.set_len(total as u32);
        let buf = self.buf_mut()?;
        super::tsi_wire::encode_control_reply(buf, operation, request_id, len);
        Some(&mut buf[super::tsi_wire::CONTROL_HEADER_LEN..total])
    }

    pub fn read_proxy_create(&self) -> Option<TsiProxyCreate> {
        let buf = self.control_payload().ok()?;
        Some(TsiProxyCreate {
            peer_port: byte_order::read_le_u32(buf),
            family: byte_order::read_le_u16(&buf[4..]),
            _type: byte_order::read_le_u16(&buf[6..]),
            protocol: byte_order::read_le_u32(&buf[8..]),
        })
    }

    pub(super) fn read_datagram(
        &self,
    ) -> Option<(
        SockaddrStorage,
        Option<super::tsi_wire::DatagramInfo>,
        &[u8],
    )> {
        let buf = self.buf()?.get(..self.len() as usize)?;
        let frame = super::tsi_wire::decode_datagram_send(buf)?;
        let addr = Self::parse_address(frame.address, frame.address.len() as u32)?;
        Some((addr, frame.info, frame.payload))
    }

    pub fn read_connect_req(&self) -> Option<TsiConnectReq> {
        let buf = self.control_payload().ok()?;
        let peer_port = byte_order::read_le_u32(buf);
        let addr_len = byte_order::read_le_u32(&buf[4..]);
        let addr = Self::parse_address(&buf[8..], addr_len)?;
        Some(TsiConnectReq {
            request_id: self.control_request_id(),
            peer_port,
            addr,
        })
    }

    pub fn write_connect_rsp(&mut self, rsp: TsiConnectRsp, request_id: u64) {
        if let Some(buf) = self.control_response_buf(request_id, 4) {
            byte_order::write_le_u32(buf, rsp.result as u32);
        }
    }

    pub fn write_sockopt_rsp(&mut self, result: i32, value: i32, request_id: u64) {
        if let Some(buf) = self.control_response_buf(request_id, 8) {
            byte_order::write_le_u32(buf, result as u32);
            byte_order::write_le_u32(&mut buf[4..], if result == 0 { value as u32 } else { 0 });
        }
    }

    pub fn read_getname_req(&self) -> Option<TsiGetnameReq> {
        let buf = self.control_payload().ok()?;
        let peer = byte_order::read_le_u32(&buf[8..]);
        if peer > 1 {
            return None;
        }
        Some(TsiGetnameReq {
            peer_port: byte_order::read_le_u32(buf),
            local_port: byte_order::read_le_u32(&buf[4..]),
            peer,
        })
    }

    pub fn write_getname_rsp(&mut self, rsp: TsiGetnameRsp, request_id: u64) {
        if let Some(buf) = self.control_response_buf(request_id, 136) {
            byte_order::write_le_u32(buf, rsp.result as u32);
            if rsp.result == 0 {
                let len = rsp.addr_len as usize;
                if !(2..=128).contains(&len) || len > rsp.addr.len() as usize {
                    byte_order::write_le_u32(buf, (-super::tsi_wire::EPROTO) as u32);
                    return;
                }
                let address = unsafe { slice::from_raw_parts(rsp.addr.as_ptr().cast::<u8>(), len) };
                byte_order::write_le_u32(&mut buf[4..], len as u32);
                buf[8..8 + len].copy_from_slice(address);
                #[cfg(target_os = "macos")]
                {
                    let family = match buf[9] as i32 {
                        libc::AF_INET => defs::LINUX_AF_INET,
                        libc::AF_INET6 => defs::LINUX_AF_INET6,
                        _ => 0,
                    };
                    buf[8..10].copy_from_slice(&family.to_le_bytes());
                }
            }
        }
    }

    pub fn read_sendto_addr(&self) -> Option<TsiSendtoAddr> {
        let buf = self.control_payload().ok()?;
        Some(TsiSendtoAddr {
            peer_port: byte_order::read_le_u32(buf),
            addr: Self::parse_address(&buf[8..], byte_order::read_le_u32(&buf[4..]))?,
        })
    }

    pub fn read_listen_req(&self) -> Option<TsiListenReq> {
        let buf = self.control_payload().ok()?;
        let backlog = byte_order::read_le_u32(&buf[8..]);
        if backlog > i32::MAX as u32 {
            return None;
        }
        Some(TsiListenReq {
            peer_port: byte_order::read_le_u32(buf),
            vm_port: byte_order::read_le_u32(&buf[4..]),
            backlog: backlog as i32,
            addr: Self::parse_address(&buf[16..], byte_order::read_le_u32(&buf[12..]))?,
            strict: false,
        })
    }

    pub fn write_listen_rsp(&mut self, rsp: TsiListenRsp, request_id: u64) {
        if let Some(buf) = self.control_response_buf(request_id, 8) {
            byte_order::write_le_u32(buf, rsp.result as u32);
            byte_order::write_le_u32(&mut buf[4..], rsp.flags);
        }
    }

    pub fn read_accept_req(&self) -> Option<TsiAcceptReq> {
        let buf = self.control_payload().ok()?;
        let flags = byte_order::read_le_u32(&buf[4..]);
        if flags != 0 {
            return None;
        }
        Some(TsiAcceptReq {
            request_id: self.control_request_id(),
            peer_port: byte_order::read_le_u32(buf),
            flags,
        })
    }

    pub fn write_accept_rsp(&mut self, rsp: TsiAcceptRsp, request_id: u64) {
        if let Some(buf) = self.control_response_buf(request_id, 4) {
            byte_order::write_le_u32(buf, rsp.result as u32);
        }
    }

    pub fn read_release_req(&self) -> Option<TsiReleaseReq> {
        let buf = self.control_payload().ok()?;
        Some(TsiReleaseReq {
            peer_port: byte_order::read_le_u32(buf),
            local_port: byte_order::read_le_u32(&buf[4..]),
        })
    }

    pub fn write_time_sync(&mut self, time: u64) {
        if self.buf_size >= 8
            && let Some(buf) = self.buf_mut()
        {
            byte_order::write_le_u64(&mut buf[0..], time);
        }
    }
}

#[cfg(test)]
mod descriptor_tests {
    use super::*;
    use crate::virtio::queue::{Descriptor, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use vm_memory::{Bytes, GuestMemoryMmap};

    const TABLE: GuestAddress = GuestAddress(0x1000);

    fn buffer(index: usize) -> GuestAddress {
        GuestAddress(0x10000 + index as u64 * 0x20000)
    }

    fn memory(layout: &[usize], writable: bool, data_len: u32) -> GuestMemoryMmap {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x100000)]).unwrap();
        for (i, &len) in layout.iter().enumerate() {
            let mut flags = if writable { VIRTQ_DESC_F_WRITE } else { 0 };
            if i + 1 < layout.len() {
                flags |= VIRTQ_DESC_F_NEXT;
            }
            let desc = Descriptor {
                addr: buffer(i).raw_value(),
                len: len as u32,
                flags,
                next: (i + 1) as u16,
            };
            mem.write_obj(desc, TABLE.checked_add(i as u64 * 16).unwrap())
                .unwrap();
            mem.write_slice(&vec![0xa5; len], buffer(i)).unwrap();
        }
        mem.write_obj(
            data_len.to_le(),
            buffer(0).checked_add(HDROFF_LEN as u64).unwrap(),
        )
        .unwrap();
        mem
    }

    fn head(mem: &GuestMemoryMmap) -> DescriptorChain<'_> {
        DescriptorChain::checked_new(mem, TABLE, 16, 0).unwrap()
    }

    #[test]
    fn rx_capacity_includes_inline_and_all_descriptors() {
        let mem = memory(&[VSOCK_PKT_HDR_SIZE + 2, 3, 4], true, 0);
        let pkt = VsockPacket::from_rx_virtq_head(&head(&mem)).unwrap();
        assert_eq!(pkt.buf().unwrap().len(), 9);
    }

    #[test]
    fn rx_large_packet_spans_descriptors() {
        let mem = memory(&[32768, 32768, 44], true, 0);
        let pkt = VsockPacket::from_rx_virtq_head(&head(&mem)).unwrap();
        assert_eq!(pkt.buf().unwrap().len(), defs::MAX_PKT_BUF_SIZE);
    }

    #[test]
    fn rx_rejects_read_only_data() {
        let mem = memory(&[VSOCK_PKT_HDR_SIZE, 8], true, 0);
        let mut desc: Descriptor = mem.read_obj(TABLE.checked_add(16).unwrap()).unwrap();
        desc.flags = 0;
        mem.write_obj(desc, TABLE.checked_add(16).unwrap()).unwrap();
        assert!(matches!(
            VsockPacket::from_rx_virtq_head(&head(&mem)),
            Err(VsockError::UnwritableDescriptor)
        ));
    }

    #[test]
    fn tx_exposes_declared_payload_only() {
        let mem = memory(&[VSOCK_PKT_HDR_SIZE, 16], false, 4);
        mem.write_slice(b"data", buffer(1)).unwrap();
        let pkt = VsockPacket::from_tx_virtq_head(&head(&mem)).unwrap();
        assert_eq!(pkt.buf().unwrap(), b"data");
    }
    fn write_payload(mem: &GuestMemoryMmap, layout: &[usize], data: &[u8]) {
        let mut offset = 0;
        for (i, &len) in layout.iter().enumerate() {
            let start = if i == 0 { VSOCK_PKT_HDR_SIZE } else { 0 };
            let count = (len - start).min(data.len() - offset);
            mem.write_slice(
                &data[offset..offset + count],
                buffer(i).checked_add(start as u64).unwrap(),
            )
            .unwrap();
            offset += count;
            if offset == data.len() {
                break;
            }
        }
        assert_eq!(offset, data.len());
    }

    fn read_payload(mem: &GuestMemoryMmap, layout: &[usize], len: usize) -> Vec<u8> {
        let mut data = vec![0; len];
        let mut offset = 0;
        for (i, &size) in layout.iter().enumerate() {
            let start = if i == 0 { VSOCK_PKT_HDR_SIZE } else { 0 };
            let count = (size - start).min(len - offset);
            mem.read_slice(
                &mut data[offset..offset + count],
                buffer(i).checked_add(start as u64).unwrap(),
            )
            .unwrap();
            offset += count;
            if offset == len {
                break;
            }
        }
        assert_eq!(offset, len);
        data
    }

    #[test]
    fn tx_layouts_preserve_packet_bytes() {
        for layout in [
            vec![VSOCK_PKT_HDR_SIZE + 12],
            vec![VSOCK_PKT_HDR_SIZE, 12],
            vec![VSOCK_PKT_HDR_SIZE + 2, 3, 7],
            vec![VSOCK_PKT_HDR_SIZE, 0, 4, 8],
        ] {
            let mem = memory(&layout, false, 9);
            write_payload(&mem, &layout, b"123456789");
            let pkt = VsockPacket::from_tx_virtq_head(&head(&mem)).unwrap();
            assert_eq!(pkt.buf().unwrap(), b"123456789");
        }
    }

    #[test]
    fn rx_layouts_write_back_packet_bytes() {
        for layout in [
            vec![VSOCK_PKT_HDR_SIZE + 9],
            vec![VSOCK_PKT_HDR_SIZE, 9],
            vec![VSOCK_PKT_HDR_SIZE + 2, 3, 4],
            vec![VSOCK_PKT_HDR_SIZE, 0, 4, 5],
        ] {
            let mem = memory(&layout, true, 0);
            let mut pkt = VsockPacket::from_rx_virtq_head(&head(&mem)).unwrap();
            pkt.buf_mut().unwrap().copy_from_slice(b"123456789");
            pkt.set_len(9);
            assert_eq!(pkt.finish_rx().unwrap(), VSOCK_PKT_HDR_SIZE as u32 + 9);
            assert_eq!(read_payload(&mem, &layout, 9), b"123456789");
        }
    }

    #[test]
    fn rx_writeback_does_not_overwrite_unused_capacity() {
        let layout = [VSOCK_PKT_HDR_SIZE + 4, 4];
        let mem = memory(&layout, true, 0);
        let mut pkt = VsockPacket::from_rx_virtq_head(&head(&mem)).unwrap();
        pkt.buf_mut().unwrap()[..5].copy_from_slice(b"hello");
        pkt.set_len(5);
        assert_eq!(pkt.finish_rx().unwrap(), VSOCK_PKT_HDR_SIZE as u32 + 5);
        assert_eq!(read_payload(&mem, &layout, 8), b"hello\xa5\xa5\xa5");
    }

    #[test]
    fn rx_large_writeback_is_complete() {
        let layout = [32768, 32768, 44];
        let mem = memory(&layout, true, 0);
        let data: Vec<_> = (0..defs::MAX_PKT_BUF_SIZE).map(|i| i as u8).collect();
        let mut pkt = VsockPacket::from_rx_virtq_head(&head(&mem)).unwrap();
        pkt.buf_mut().unwrap().copy_from_slice(&data);
        pkt.set_len(data.len() as u32);
        assert_eq!(
            pkt.finish_rx().unwrap() as usize,
            VSOCK_PKT_HDR_SIZE + data.len()
        );
        assert_eq!(read_payload(&mem, &layout, data.len()), data);
    }

    #[test]
    fn rx_capacity_is_bounded() {
        let mem = memory(&[VSOCK_PKT_HDR_SIZE, defs::MAX_PKT_BUF_SIZE], true, 0);
        let mut desc: Descriptor = mem.read_obj(TABLE.checked_add(16).unwrap()).unwrap();
        desc.len = u32::MAX;
        mem.write_obj(desc, TABLE.checked_add(16).unwrap()).unwrap();
        let mut pkt = VsockPacket::from_rx_virtq_head(&head(&mem)).unwrap();
        assert_eq!(pkt.buf_mut().unwrap().len(), defs::MAX_PKT_BUF_SIZE);
        pkt.set_len(defs::MAX_PKT_BUF_SIZE as u32 + 1);
        assert!(matches!(pkt.finish_rx(), Err(VsockError::BufDescTooSmall)));
    }

    #[test]
    fn tx_short_chain_and_wrong_direction_are_rejected() {
        let mem = memory(&[VSOCK_PKT_HDR_SIZE + 2, 2], false, 5);
        assert!(matches!(
            VsockPacket::from_tx_virtq_head(&head(&mem)),
            Err(VsockError::BufDescTooSmall)
        ));
        let mem = memory(&[VSOCK_PKT_HDR_SIZE + 2, 2, 1], false, 5);
        let mut desc: Descriptor = mem.read_obj(TABLE.checked_add(32).unwrap()).unwrap();
        desc.flags = VIRTQ_DESC_F_WRITE;
        mem.write_obj(desc, TABLE.checked_add(32).unwrap()).unwrap();
        assert!(matches!(
            VsockPacket::from_tx_virtq_head(&head(&mem)),
            Err(VsockError::UnreadableDescriptor)
        ));
    }

    #[test]
    fn rx_unmapped_tail_is_rejected() {
        let mem = memory(&[VSOCK_PKT_HDR_SIZE + 2, 2, 1], true, 0);
        let mut desc: Descriptor = mem.read_obj(TABLE.checked_add(32).unwrap()).unwrap();
        desc.addr = 0x200000;
        mem.write_obj(desc, TABLE.checked_add(32).unwrap()).unwrap();
        assert!(matches!(
            VsockPacket::from_rx_virtq_head(&head(&mem)),
            Err(VsockError::GuestMemoryMmap(_))
        ));
    }

    #[test]
    fn tx_unused_descriptor_padding_is_not_read() {
        let mem = memory(&[VSOCK_PKT_HDR_SIZE + 8, 8], false, 4);
        mem.write_slice(
            b"data",
            buffer(0).checked_add(VSOCK_PKT_HDR_SIZE as u64).unwrap(),
        )
        .unwrap();
        let mut desc: Descriptor = mem.read_obj(TABLE.checked_add(16).unwrap()).unwrap();
        desc.addr = u64::MAX;
        mem.write_obj(desc, TABLE.checked_add(16).unwrap()).unwrap();
        let pkt = VsockPacket::from_tx_virtq_head(&head(&mem)).unwrap();
        assert_eq!(pkt.buf().unwrap(), b"data");
    }

    #[test]
    fn truncated_control_requests_are_rejected() {
        for len in 0..16 {
            let mem = memory(&[VSOCK_PKT_HDR_SIZE + len], false, len as u32);
            let pkt = VsockPacket::from_tx_virtq_head(&head(&mem)).unwrap();
            if len < 8 {
                assert!(pkt.read_proxy_create().is_none());
            }
            assert!(pkt.read_connect_req().is_none());
            assert!(pkt.read_sendto_addr().is_none());
            assert!(pkt.read_listen_req().is_none());
        }
    }
    #[test]
    fn control_reply_uses_exact_length_and_preserves_id() {
        let layout = [VSOCK_PKT_HDR_SIZE + 5, 64, 128];
        let mem = memory(&layout, true, 0);
        let mut pkt = VsockPacket::from_rx_virtq_head(&head(&mem)).unwrap();
        pkt.set_src_port(1025);
        pkt.write_connect_rsp(TsiConnectRsp { result: -111 }, 0x123456789abcdef0);
        assert_eq!(pkt.len(), 28);
        assert_eq!(pkt.finish_rx().unwrap(), VSOCK_PKT_HDR_SIZE as u32 + 28);
        let data = read_payload(&mem, &layout, 29);
        assert_eq!(&data[8..16], &0x123456789abcdef0u64.to_le_bytes());
        assert_eq!(&data[16..24], &[4, 0, 0, 0, 1, 0, 0, 0]);
        assert_eq!(&data[24..28], &(-111i32).to_le_bytes());
        assert_eq!(data[28], 0xa5);
    }

    #[test]
    fn listen_reply_preserves_errno_and_strict_policy() {
        let layout = [VSOCK_PKT_HDR_SIZE + 5, 64, 128];
        let mem = memory(&layout, true, 0);
        let mut pkt = VsockPacket::from_rx_virtq_head(&head(&mem)).unwrap();
        pkt.set_src_port(defs::TSI_LISTEN);
        pkt.write_listen_rsp(
            TsiListenRsp {
                result: -98,
                flags: defs::TSI_LISTEN_STRICT,
            },
            41,
        );
        assert_eq!(pkt.len(), 32);
        assert_eq!(pkt.finish_rx().unwrap(), VSOCK_PKT_HDR_SIZE as u32 + 32);
        let data = read_payload(&mem, &layout, 33);
        assert_eq!(&data[8..16], &41u64.to_le_bytes());
        assert_eq!(&data[16..24], &[8, 0, 0, 0, 1, 0, 0, 0]);
        assert_eq!(&data[24..28], &(-98i32).to_le_bytes());
        assert_eq!(&data[28..32], &defs::TSI_LISTEN_STRICT.to_le_bytes());
        assert_eq!(data[32], 0xa5);
    }

    #[test]
    fn strict_listen_flags_only_apply_to_inet() {
        for (family, len) in [
            (defs::LINUX_AF_INET, 16),
            (defs::LINUX_AF_INET6, 28),
            (defs::LINUX_AF_UNIX, 11),
        ] {
            let mut raw = [0; 128];
            raw[..2].copy_from_slice(&family.to_le_bytes());
            if family == defs::LINUX_AF_UNIX {
                raw[2..11].copy_from_slice(b"/tmp/tsi\0");
            }
            let addr = VsockPacket::parse_address(&raw, len).unwrap();
            let mut request = TsiListenReq {
                peer_port: 1,
                vm_port: 2,
                backlog: 8,
                addr,
                strict: false,
            };
            assert_eq!(request.response_flags(), 0);
            request.strict = true;
            assert_eq!(
                request.response_flags(),
                if family == defs::LINUX_AF_UNIX {
                    0
                } else {
                    defs::TSI_LISTEN_STRICT
                }
            );
        }
    }

    #[test]
    fn short_control_reply_buffer_does_not_announce_partial_body() {
        let mem = memory(&[VSOCK_PKT_HDR_SIZE + 27], true, 0);
        let mut pkt = VsockPacket::from_rx_virtq_head(&head(&mem)).unwrap();
        pkt.set_src_port(1025);
        pkt.write_connect_rsp(TsiConnectRsp { result: 0 }, 1);
        assert_eq!(pkt.len(), 0);
    }
    #[test]
    fn getname_uses_typed_address_length() {
        for (address, len) in [
            (SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345).into(), 16u32),
            (
                std::net::SocketAddrV6::new(std::net::Ipv6Addr::LOCALHOST, 12345, 0, 0).into(),
                28u32,
            ),
        ] {
            let mem = memory(&[VSOCK_PKT_HDR_SIZE + 256], true, 0);
            let mut pkt = VsockPacket::from_rx_virtq_head(&head(&mem)).unwrap();
            pkt.set_src_port(1026);
            pkt.write_getname_rsp(
                TsiGetnameRsp {
                    result: 0,
                    addr_len: len,
                    addr: address,
                },
                1,
            );
            assert_eq!(pkt.len(), 160);
            let body = &pkt.buf().unwrap()[24..160];
            assert_eq!(byte_order::read_le_u32(&body[4..]), len);
            assert!(body[8 + len as usize..].iter().all(|b| *b == 0));
        }
    }
}
