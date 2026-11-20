use std::collections::HashMap;
use std::fmt;

#[cfg(unix)]
pub(super) use std::os::fd::OwnedFd;
#[cfg(unix)]
pub(super) use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(windows)]
pub(super) use std::os::windows::io::OwnedSocket as OwnedFd;
#[cfg(windows)]
pub(super) use utils::windows::{AsRawFd, RawFd};

#[cfg(target_os = "macos")]
use super::super::linux_errno::linux_errno_raw;
#[cfg(windows)]
use super::super::linux_errno::wsa_errno_to_linux;
use super::muxer::MuxerRx;
use super::packet::{
    TsiAcceptReq, TsiBindReq, TsiConnectReq, TsiDatagram, TsiListenReq, VsockPacket,
};
use super::tsi_wire;
#[cfg(unix)]
pub(super) use nix::sys::socket::AddressFamily;
/// On Windows, reuse the WinSock `ADDRESS_FAMILY` type (a `u16`) directly so
/// that converted values are already native WinSock constants (AF_INET, …).
#[cfg(windows)]
pub(super) use windows_sys::Win32::Networking::WinSock::{
    ADDRESS_FAMILY as AddressFamily, AF_INET, AF_INET6, AF_UNIX,
};

use utils::epoll::EventSet;
#[cfg(windows)]
use utils::epoll::{Epoll, EpollEvent};

#[derive(Debug)]
pub enum RecvPkt {
    BadBuffer,
    Close,
    Error,
    Read(usize),
    WaitForCredit,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum ProxyError {
    CreatingSocket(std::io::Error),
    InvalidFamily,
    SettingReuseAddr(std::io::Error),
    SettingReusePort(std::io::Error),
}

impl ProxyError {
    pub fn linux_errno(&self) -> i32 {
        let error = match self {
            Self::CreatingSocket(e) | Self::SettingReuseAddr(e) | Self::SettingReusePort(e) => e,
            Self::InvalidFamily => return tsi_wire::EAFNOSUPPORT,
        };
        let code = error.raw_os_error().unwrap_or(tsi_wire::EIO);
        #[cfg(target_os = "linux")]
        {
            code
        }
        #[cfg(target_os = "macos")]
        {
            linux_errno_raw(code)
        }
        #[cfg(windows)]
        {
            wsa_errno_to_linux(code)
        }
    }
}

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub enum ProxyStatus {
    Idle,
    Connecting,
    AwaitingRequest,
    Connected,
    Listening,
    Closed,
    WaitingCreditUpdate,
    ReverseInit,
    WaitingOnAccept,
}

#[derive(Default)]
pub enum ProxyRemoval {
    #[default]
    Keep,
    Immediate,
    Deferred,
}

#[derive(Default)]
pub enum NewProxyType {
    #[default]
    Tcp,
    Unix,
}

#[derive(Default)]
pub struct ProxyUpdate {
    pub signal_queue: bool,
    pub remove_proxy: ProxyRemoval,
    pub polling: Option<(u64, RawFd, EventSet)>,
    pub new_proxy: Option<(u32, OwnedFd, AddressFamily, NewProxyType)>,
    pub push_accept: Option<(u64, u64)>,
    pub push_credit_req: Option<MuxerRx>,
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

pub trait Proxy: Send + AsRawFd {
    fn is_tsi(&self) -> bool {
        self.tsi_socket().is_some()
    }
    fn tsi_socket(&self) -> Option<(u16, AddressFamily)> {
        None
    }
    fn activate(&mut self, features: u64) -> Result<u64, i32> {
        if features == 0 {
            Ok(0)
        } else {
            Err(-tsi_wire::EOPNOTSUPP)
        }
    }
    #[allow(dead_code)]
    fn id(&self) -> u64;
    #[allow(dead_code)]
    fn status(&self) -> ProxyStatus;
    fn connect(
        &mut self,
        pkt: &VsockPacket,
        req: TsiConnectReq,
        #[cfg(windows)] epoll: &Epoll,
    ) -> ProxyUpdate;
    fn confirm_connect(&mut self, _pkt: &VsockPacket) -> Option<ProxyUpdate> {
        None
    }
    fn disconnect(&mut self, _pkt: &VsockPacket) -> Option<ProxyUpdate> {
        None
    }
    fn bind_datagram(
        &mut self,
        _req: TsiBindReq,
        _host_port_map: &Option<HashMap<u16, u16>>,
    ) -> Option<Result<ProxyUpdate, i32>> {
        None
    }
    fn socket_option(&self, _level: u32, _name: u32, _value: Option<i32>) -> Result<i32, i32> {
        Err(-tsi_wire::ENOPROTOOPT)
    }
    fn getname(&mut self, pkt: &VsockPacket, peer: bool);
    fn sendmsg(&mut self, _pkt: &VsockPacket) -> ProxyUpdate {
        ProxyUpdate::default()
    }
    fn send_datagram(&mut self, _datagram: TsiDatagram<'_>) -> ProxyUpdate {
        ProxyUpdate::default()
    }
    fn record_datagram_error(&self, _errno: i32) {}
    fn listen(
        &mut self,
        _pkt: &VsockPacket,
        _req: TsiListenReq,
        _host_port_map: &Option<HashMap<u16, u16>>,
    ) -> ProxyUpdate {
        ProxyUpdate::default()
    }
    fn accept(&mut self, req: TsiAcceptReq) -> ProxyUpdate;
    fn update_peer_credit(&mut self, pkt: &VsockPacket) -> ProxyUpdate;
    /// Announce a reverse connection to the guest. Returns whether the
    /// announcement was delivered or queued; a proxy whose announcement
    /// was dropped cannot be released by the guest.
    fn push_op_request(&self) -> bool {
        false
    }
    fn process_op_response(&mut self, pkt: &VsockPacket) -> ProxyUpdate;
    fn enqueue_accept(&mut self) {}
    fn push_accept_rsp(&self, _result: i32) {}
    fn shutdown(&mut self, _pkt: &VsockPacket) -> ProxyUpdate {
        ProxyUpdate::default()
    }
    fn release(&mut self) -> ProxyUpdate;
    fn reset(&mut self) -> ProxyUpdate {
        self.release()
    }
    fn process_event(&mut self, evset: EventSet) -> ProxyUpdate;
    #[cfg(windows)]
    fn process_windows_event(&mut self, event: &EpollEvent) -> ProxyUpdate {
        self.process_event(event.event_set())
    }
}

#[cfg(windows)]
pub fn address_family_from_linux(family: u16) -> Option<AddressFamily> {
    match family {
        super::defs::LINUX_AF_INET => Some(AF_INET),
        super::defs::LINUX_AF_INET6 => Some(AF_INET6),
        super::defs::LINUX_AF_UNIX => Some(AF_UNIX),
        _ => None,
    }
}
