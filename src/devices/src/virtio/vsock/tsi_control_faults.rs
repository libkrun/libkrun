// SPDX-License-Identifier: Apache-2.0

use super::defs::uapi;
use super::muxer::MuxerRx;
use super::muxer_rxq::rx_to_pkt;
use super::packet::VsockPacket;

pub(super) const PORT: u32 = 0x5453_4946;

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u32)]
pub enum Fault {
    Version = 1,
    Operation,
    Flags,
    ShortHeader,
    ShortBody,
    Trailing,
    PayloadLength,
    PositiveResult,
    InvalidError,
    Oversized,
    WrongId,
    WrongPort,
    WrongCid,
    Duplicate,
    Drop,
    Hold,
    ListenFlags,
    AddressLength,
    AddressFamily,
    WrongIdOnly,
    WrongPortOnly,
    WrongCidOnly,
}

#[derive(Default)]
pub(super) struct Injector {
    operation: u32,
    fault: Option<Fault>,
    skip: u32,
    seen: u32,
    injected: u32,
    held: Option<Box<MuxerRx>>,
}

fn identity(rx: &MuxerRx) -> Option<(u32, u32)> {
    match rx {
        MuxerRx::ConnResponse {
            local_port,
            peer_port,
            ..
        }
        | MuxerRx::SockoptResponse {
            local_port,
            peer_port,
            ..
        }
        | MuxerRx::GetnameResponse {
            local_port,
            peer_port,
            ..
        }
        | MuxerRx::ListenResponse {
            local_port,
            peer_port,
            ..
        }
        | MuxerRx::AcceptResponse {
            local_port,
            peer_port,
            ..
        } => Some((*local_port, *peer_port)),
        _ => None,
    }
}

impl Injector {
    // This endpoint exists only in an explicitly instrumented host build.
    pub(super) fn request(&mut self, buf: &[u8], proxies: u32) -> ([u32; 5], Option<MuxerRx>) {
        if buf.len() == 16 {
            let words: Vec<_> = buf
                .as_chunks::<4>()
                .0
                .iter()
                .map(|word| u32::from_le_bytes(*word))
                .collect();
            if words[0] == 1 && matches!(words[2], 23 | 24) {
                if words[1] != 0 || words[3] != 0 || self.held.is_none() {
                    return ([1, 22, self.seen, self.injected, proxies], None);
                }
                let reply = if words[2] == 23 {
                    *self.held.take().unwrap()
                } else {
                    MuxerRx::FaultPacket {
                        response: self.held.as_ref().unwrap().clone(),
                        fault: Fault::Version,
                        peer_port: None,
                    }
                };
                self.injected += 1;
                return ([1, 0, self.seen, self.injected, proxies], Some(reply));
            }
        }
        (self.command(buf, proxies), None)
    }

    fn command(&mut self, buf: &[u8], proxies: u32) -> [u32; 5] {
        let words: Vec<_> = buf
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| u32::from_le_bytes(*word))
            .collect();
        let mut status = 0;
        if buf.len() != 16 || words[0] != 1 {
            status = 22;
        } else if words[2] != 0 {
            let fault = match words[2] {
                1 => Fault::Version,
                2 => Fault::Operation,
                3 => Fault::Flags,
                4 => Fault::ShortHeader,
                5 => Fault::ShortBody,
                6 => Fault::Trailing,
                7 => Fault::PayloadLength,
                8 => Fault::PositiveResult,
                9 => Fault::InvalidError,
                10 => Fault::Oversized,
                11 => Fault::WrongId,
                12 => Fault::WrongPort,
                13 => Fault::WrongCid,
                14 => Fault::Duplicate,
                15 => Fault::Drop,
                16 => Fault::Hold,
                17 => Fault::ListenFlags,
                18 => Fault::AddressLength,
                19 => Fault::AddressFamily,
                20 => Fault::WrongIdOnly,
                21 => Fault::WrongPortOnly,
                22 => Fault::WrongCidOnly,
                _ => return [1, 22, self.seen, self.injected, proxies],
            };
            if !matches!(words[1], 1024..=1026 | 1029..=1030 | 1033..=1036) {
                status = 22;
            } else {
                *self = Self {
                    operation: words[1],
                    fault: Some(fault),
                    skip: words[3],
                    ..Self::default()
                };
            }
        }
        [1, status, self.seen, self.injected, proxies]
    }

    pub(super) fn filter(&mut self, rx: MuxerRx) -> Vec<MuxerRx> {
        let Some((operation, peer_port)) = identity(&rx) else {
            return vec![rx];
        };
        if operation != self.operation {
            return vec![rx];
        }
        self.seen += 1;
        if let Some(held) = self.held.take() {
            self.injected += 1;
            // Retargeting models a late reply reaching a reused private port.
            return vec![
                MuxerRx::FaultPacket {
                    response: held,
                    fault: Fault::WrongId,
                    peer_port: Some(peer_port),
                },
                rx,
            ];
        }
        if self.skip != 0 {
            self.skip -= 1;
            return vec![rx];
        }
        let Some(fault) = self.fault.take() else {
            return vec![rx];
        };
        self.injected += 1;
        match fault {
            Fault::Drop => vec![],
            Fault::Hold => {
                self.held = Some(Box::new(rx));
                vec![]
            }
            Fault::WrongId | Fault::WrongPort | Fault::WrongCid => vec![
                MuxerRx::FaultPacket {
                    response: Box::new(rx.clone()),
                    fault,
                    peer_port: None,
                },
                rx,
            ],
            Fault::Duplicate => vec![
                rx.clone(),
                MuxerRx::FaultPacket {
                    response: Box::new(rx),
                    fault,
                    peer_port: None,
                },
            ],
            _ => vec![MuxerRx::FaultPacket {
                response: Box::new(rx),
                fault,
                peer_port: None,
            }],
        }
    }
}

pub(super) fn packet(
    cid: u64,
    response: MuxerRx,
    fault: Fault,
    peer_port: Option<u32>,
    pkt: &mut VsockPacket,
) {
    rx_to_pkt(cid, response, pkt);
    if let Some(port) = peer_port {
        pkt.set_dst_port(port);
    }
    let len = pkt.len();
    match fault {
        Fault::ShortHeader => {
            pkt.set_len(23);
        }
        Fault::ShortBody => {
            pkt.set_len(len - 1);
        }
        Fault::Trailing => {
            pkt.set_len(len + 1);
        }
        Fault::Oversized => {
            pkt.set_len(200);
        }
        Fault::WrongPort | Fault::WrongPortOnly => {
            pkt.set_src_port(PORT);
        }
        Fault::WrongCid | Fault::WrongCidOnly => {
            pkt.set_src_cid(99);
        }
        _ => {}
    }
    let buf = pkt.buf_mut().unwrap();
    let end = 200.min(buf.len());
    match fault {
        Fault::Version => buf[0..4].copy_from_slice(&3u32.to_le_bytes()),
        Fault::Operation => buf[4..8].copy_from_slice(&0u32.to_le_bytes()),
        Fault::Flags => buf[20..24].copy_from_slice(&3u32.to_le_bytes()),
        Fault::PayloadLength => buf[16..20].copy_from_slice(&0u32.to_le_bytes()),
        Fault::PositiveResult => buf[24..28].copy_from_slice(&1i32.to_le_bytes()),
        Fault::InvalidError => buf[24..28].copy_from_slice(&(-4096i32).to_le_bytes()),
        Fault::WrongIdOnly => buf[8..16].copy_from_slice(&0u64.to_le_bytes()),
        Fault::WrongId => {
            if peer_port.is_none() {
                buf[8..16].copy_from_slice(&0u64.to_le_bytes());
            }
            buf[24..28].copy_from_slice(&(-13i32).to_le_bytes());
        }
        Fault::WrongPort | Fault::WrongCid | Fault::Duplicate => {
            buf[24..28].copy_from_slice(&(-13i32).to_le_bytes())
        }
        Fault::ListenFlags => buf[28..32].copy_from_slice(&2u32.to_le_bytes()),
        Fault::AddressLength => buf[28..32].copy_from_slice(&129u32.to_le_bytes()),
        Fault::AddressFamily => buf[32..34].copy_from_slice(&1u16.to_le_bytes()),
        Fault::Trailing | Fault::Oversized => buf[len as usize..end].fill(0),
        _ => {}
    }
}

pub(super) fn ack(cid: u64, peer_port: u32, words: [u32; 5], pkt: &mut VsockPacket) {
    pkt.set_op(uapi::VSOCK_OP_RW)
        .set_src_cid(uapi::VSOCK_HOST_CID)
        .set_dst_cid(cid)
        .set_src_port(PORT)
        .set_dst_port(peer_port)
        .set_type(uapi::VSOCK_TYPE_DGRAM)
        .set_len(20);
    for (word, bytes) in words
        .iter()
        .zip(pkt.buf_mut().unwrap().as_chunks_mut::<4>().0.iter_mut())
    {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
}
