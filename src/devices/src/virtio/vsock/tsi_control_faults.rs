// SPDX-License-Identifier: Apache-2.0
use super::defs;
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
    StaleShort = 25,
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
            operation,
            peer_port,
            ..
        }
        | MuxerRx::SockoptResponse {
            operation,
            peer_port,
            ..
        }
        | MuxerRx::GetnameResponse {
            operation,
            peer_port,
            ..
        }
        | MuxerRx::ListenResponse {
            operation,
            peer_port,
            ..
        }
        | MuxerRx::AcceptResponse {
            operation,
            peer_port,
            ..
        }
        | MuxerRx::FeatureResponse {
            operation,
            peer_port,
            ..
        } => Some((*operation, *peer_port)),
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
                25 => Fault::StaleShort,
                _ => return [1, 22, self.seen, self.injected, proxies],
            };
            if !matches!(words[1], defs::TSI_OP_CREATE..=defs::TSI_OP_ACCEPT | defs::TSI_OP_DISCONNECT..=defs::TSI_OP_ACTIVATE)
            {
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
            Fault::WrongId | Fault::WrongPort | Fault::WrongCid | Fault::StaleShort => vec![
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
        Fault::StaleShort => {
            pkt.set_len(16);
        }
        Fault::ShortBody => {
            // An empty reply means the guest buffer was too small to hold
            // it: there is no body left to shorten.
            pkt.set_len(len.saturating_sub(1));
        }
        Fault::Trailing => {
            pkt.set_len(len.saturating_add(1));
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
        Fault::Version => overwrite(buf, 0, &3u32.to_le_bytes()),
        Fault::Operation => overwrite(buf, 4, &0u32.to_le_bytes()),
        Fault::Flags => overwrite(buf, 20, &3u32.to_le_bytes()),
        Fault::PayloadLength => overwrite(buf, 16, &0u32.to_le_bytes()),
        Fault::PositiveResult => overwrite(buf, 24, &1i32.to_le_bytes()),
        Fault::InvalidError => overwrite(buf, 24, &(-4096i32).to_le_bytes()),
        Fault::WrongIdOnly => overwrite(buf, 8, &0u64.to_le_bytes()),
        Fault::StaleShort => overwrite(buf, 8, &0u64.to_le_bytes()),
        Fault::WrongId => {
            if peer_port.is_none() {
                overwrite(buf, 8, &0u64.to_le_bytes());
            }
            overwrite(buf, 24, &(-13i32).to_le_bytes());
        }
        Fault::WrongPort | Fault::WrongCid | Fault::Duplicate => {
            overwrite(buf, 24, &(-13i32).to_le_bytes())
        }
        Fault::ListenFlags => overwrite(buf, 28, &2u32.to_le_bytes()),
        Fault::AddressLength => overwrite(buf, 28, &129u32.to_le_bytes()),
        Fault::AddressFamily => overwrite(buf, 32, &1u16.to_le_bytes()),
        Fault::Trailing | Fault::Oversized => {
            let start = (len as usize).min(end);
            buf[start..end].fill(0);
        }
        _ => {}
    }
}

/// Corrupt only what the guest-supplied buffer can hold: a fault aimed
/// beyond a short buffer is skipped instead of panicking.
fn overwrite(buf: &mut [u8], at: usize, bytes: &[u8]) {
    if let Some(target) = buf.get_mut(at..at + bytes.len()) {
        target.copy_from_slice(bytes);
    }
}

pub(super) fn ack(cid: u64, peer_port: u32, words: [u32; 5], pkt: &mut VsockPacket) {
    pkt.set_op(uapi::VSOCK_OP_RW)
        .set_src_cid(uapi::VSOCK_HOST_CID)
        .set_dst_cid(cid)
        .set_src_port(PORT)
        .set_dst_port(peer_port)
        .set_type(uapi::VSOCK_TYPE_DGRAM)
        .set_flags(uapi::VSOCK_DGRAM_START | uapi::VSOCK_DGRAM_EOM)
        .set_len(20);
    for (word, bytes) in words
        .iter()
        .zip(pkt.buf_mut().unwrap().as_chunks_mut::<4>().0.iter_mut())
    {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryMmap};

    use super::*;
    use crate::virtio::queue::{Descriptor, DescriptorChain, VIRTQ_DESC_F_WRITE};
    use crate::virtio::vsock::packet::VSOCK_PKT_HDR_SIZE;

    const TABLE: GuestAddress = GuestAddress(0x1000);
    const BUFFER: GuestAddress = GuestAddress(0x10000);

    fn connect_response() -> MuxerRx {
        MuxerRx::ConnResponse {
            request_id: 7,
            operation: defs::TSI_OP_CREATE,
            peer_port: 4000,
            result: 0,
        }
    }

    fn rx_packet(mem: &GuestMemoryMmap, data_len: usize) -> VsockPacket {
        mem.write_obj(
            Descriptor {
                addr: BUFFER.raw_value(),
                len: (VSOCK_PKT_HDR_SIZE + data_len) as u32,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
            TABLE,
        )
        .unwrap();
        let chain = DescriptorChain::checked_new(mem, TABLE, 16, 0).unwrap();
        VsockPacket::from_rx_virtq_head(&chain).unwrap()
    }

    fn mem() -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x100000)]).unwrap()
    }

    #[test]
    fn short_body_fault_on_unfit_reply_is_inert() {
        // The buffer cannot hold the 28-byte connect reply, so the reply is
        // written empty and there is no body left to shorten.
        let mem = mem();
        let mut pkt = rx_packet(&mem, 1);
        packet(3, connect_response(), Fault::ShortBody, None, &mut pkt);
        assert_eq!(pkt.len(), 0);
    }

    #[test]
    fn field_faults_skip_buffers_too_short_to_corrupt() {
        let mem = mem();
        let mut pkt = rx_packet(&mem, 2);
        mem.write_slice(
            &[0xa5, 0xa5],
            BUFFER.unchecked_add(VSOCK_PKT_HDR_SIZE as u64),
        )
        .unwrap();
        packet(3, connect_response(), Fault::Version, None, &mut pkt);
        packet(3, connect_response(), Fault::AddressFamily, None, &mut pkt);
        let buf = pkt.buf().unwrap();
        assert_eq!(buf, &[0xa5, 0xa5]);
    }

    #[test]
    fn trailing_fault_with_exact_fit_buffer_degrades_to_empty() {
        let mem = mem();
        let mut pkt = rx_packet(&mem, 28);
        packet(3, connect_response(), Fault::Trailing, None, &mut pkt);
        assert_eq!(pkt.len(), 29);
        // The used-ring entry degrades to zero length, not a panic.
        assert!(pkt.finish_rx().is_err());
    }

    #[test]
    fn field_faults_still_corrupt_roomy_buffers() {
        let mem = mem();
        let mut pkt = rx_packet(&mem, 256);
        packet(3, connect_response(), Fault::Version, None, &mut pkt);
        assert_eq!(pkt.len(), 28);
        let buf = pkt.buf().unwrap();
        assert_eq!(&buf[0..4], &3u32.to_le_bytes());
        assert_eq!(&buf[4..8], &defs::TSI_OP_CREATE.to_le_bytes());
        assert_eq!(&buf[24..28], &0u32.to_le_bytes());

        let mut pkt = rx_packet(&mem, 256);
        packet(3, connect_response(), Fault::Trailing, None, &mut pkt);
        assert_eq!(pkt.len(), 29);
        assert_eq!(&pkt.buf().unwrap()[28..200], &[0; 172]);

        let mut pkt = rx_packet(&mem, 256);
        packet(3, connect_response(), Fault::Oversized, None, &mut pkt);
        assert_eq!(pkt.len(), 200);
        assert_eq!(&pkt.buf().unwrap()[28..200], &[0; 172]);
    }
}
