use std::collections::HashMap;
use std::fmt;
use std::os::fd::OwnedFd;
use std::os::unix::io::{AsRawFd, RawFd};

use super::muxer::MuxerRx;
use super::packet::{TsiAcceptReq, TsiConnectReq, TsiListenReq, TsiSendtoAddr, VsockPacket};
use nix::sys::socket::AddressFamily;
use utils::epoll::EventSet;

#[derive(Debug)]
pub enum RecvPkt {
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

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub enum ProxyStatus {
    Idle,
    Connecting,
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
    #[allow(dead_code)]
    fn id(&self) -> u64;
    #[allow(dead_code)]
    fn status(&self) -> ProxyStatus;
    fn connect(&mut self, pkt: &VsockPacket, req: TsiConnectReq) -> ProxyUpdate;
    fn confirm_connect(&mut self, _pkt: &VsockPacket) -> Option<ProxyUpdate> {
        None
    }
    fn getpeername(&mut self, pkt: &VsockPacket);
    fn sendmsg(&mut self, pkt: &VsockPacket) -> ProxyUpdate;
    fn sendto_addr(&mut self, req: TsiSendtoAddr) -> ProxyUpdate;
    fn sendto_data(&mut self, _pkt: &VsockPacket) {}
    fn listen(
        &mut self,
        pkt: &VsockPacket,
        req: TsiListenReq,
        host_port_map: &Option<HashMap<u16, u16>>,
    ) -> ProxyUpdate;
    fn accept(&mut self, req: TsiAcceptReq) -> ProxyUpdate;
    fn update_peer_credit(&mut self, pkt: &VsockPacket) -> ProxyUpdate;
    fn push_op_request(&self) {}
    fn process_op_response(&mut self, pkt: &VsockPacket) -> ProxyUpdate;
    fn enqueue_accept(&mut self) {}
    fn push_accept_rsp(&self, _result: i32) {}
    fn shutdown(&mut self, _pkt: &VsockPacket) {}
    fn release(&mut self) -> ProxyUpdate;
    fn process_event(&mut self, evset: EventSet) -> ProxyUpdate;
}
