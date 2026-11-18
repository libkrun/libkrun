// SPDX-License-Identifier: Apache-2.0

//! Host-bound UDP receive framing for cooperating TSI guests.
//!
//! Each frame begins with four little-endian u32s: datagram sequence, total
//! payload length, fragment offset, and sockaddr length. A zero-padded Linux
//! sockaddr occupies the next 28 bytes. Payload follows at byte 44. Sequence,
//! total and sender stay identical across fragments; offset zero starts a new
//! datagram. A zero-byte datagram is one header-only frame. This keeps even a
//! maximum-size UDP datagram intact across the guest's small virtio buffers.
//!
//! Storage is allocated only on first receive, reused, and bounded to one
//! in-flight datagram plus eight queued synthetic DNS replies per host-bound
//! socket. Legacy TSI sockets do not use this framing.

use std::collections::VecDeque;
use std::io;
use std::mem::MaybeUninit;

use socket2::Socket;

use super::vsock_addr::VsockAddr;

pub const FRAME_HEADER: usize = 44;
pub const MAX_DATAGRAM: usize = 65_535;

#[derive(Default)]
pub struct HostDatagramRx {
    payload: Vec<u8>,
    sender: Option<VsockAddr>,
    len: usize,
    offset: usize,
    sequence: u32,
    injected: VecDeque<(VsockAddr, Vec<u8>)>,
}

impl HostDatagramRx {
    /// Synthetic replies share framing and sequence state with real packets.
    /// Bound queued DNS replies like a UDP receive buffer; overload drops the
    /// newest reply so a resolver can retry, without discarding a partial frame.
    pub fn enqueue(&mut self, sender: VsockAddr, payload: Vec<u8>) -> bool {
        if payload.len() > MAX_DATAGRAM || self.injected.len() == 8 {
            return false;
        }
        self.injected.push_back((sender, payload));
        true
    }

    pub fn receive_frame(&mut self, sock: &Socket, buf: &mut [u8]) -> io::Result<usize> {
        self.receive_frame_with(buf, |uninit| {
            #[cfg(unix)]
            let (len, addr) = sock.recv_from_with_flags(uninit, libc::MSG_DONTWAIT)?;
            #[cfg(windows)]
            let (len, addr) = sock.recv_from(uninit)?;
            let addr = addr
                .as_socket()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "non-INET UDP sender"))?;
            Ok((len, addr.into()))
        })
    }

    pub fn receive_frame_with(
        &mut self,
        buf: &mut [u8],
        mut receive: impl FnMut(&mut [MaybeUninit<u8>]) -> io::Result<(usize, VsockAddr)>,
    ) -> io::Result<usize> {
        // Leave the host datagram untouched if this descriptor cannot carry
        // any payload. Do not confuse a short descriptor with UDP truncation.
        if buf.len() <= FRAME_HEADER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "short UDP frame buffer",
            ));
        }
        if self.sender.is_none() {
            self.payload.resize(MAX_DATAGRAM, 0);
            let (len, sender) = if let Some((sender, payload)) = self.injected.pop_front() {
                self.payload[..payload.len()].copy_from_slice(&payload);
                (payload.len(), sender)
            } else {
                // SAFETY: recv_from initializes only the returned prefix; the
                // backing bytes were initialized already and remain owned here.
                let uninit = unsafe {
                    std::slice::from_raw_parts_mut(
                        self.payload.as_mut_ptr().cast::<MaybeUninit<u8>>(),
                        self.payload.len(),
                    )
                };
                receive(uninit)?
            };
            self.sender = Some(sender);
            self.len = len;
            self.offset = 0;
            self.sequence = self.sequence.wrapping_add(1);
        }
        let sender = self.sender.as_ref().unwrap().to_linux_bytes();
        let count = (self.len - self.offset).min(buf.len() - FRAME_HEADER);
        buf[..FRAME_HEADER].fill(0);
        buf[0..4].copy_from_slice(&self.sequence.to_le_bytes());
        buf[4..8].copy_from_slice(&(self.len as u32).to_le_bytes());
        buf[8..12].copy_from_slice(&(self.offset as u32).to_le_bytes());
        buf[12..16].copy_from_slice(&(sender.len() as u32).to_le_bytes());
        buf[16..16 + sender.len()].copy_from_slice(&sender);
        buf[FRAME_HEADER..FRAME_HEADER + count]
            .copy_from_slice(&self.payload[self.offset..self.offset + count]);
        self.offset += count;
        if self.offset == self.len {
            self.sender = None;
        }
        Ok(FRAME_HEADER + count)
    }
}

#[cfg(test)]
pub(super) fn wait_readable(fd: super::proxy::ProxyRawHandle) {
    use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
    let mut poll = Epoll::new().unwrap();
    poll.ctl(ControlOperation::Add, fd, &EpollEvent::new(EventSet::IN, 1))
        .unwrap();
    let mut events = [EpollEvent::default(); 1];
    assert_eq!(
        poll.wait(1, 2000, &mut events).unwrap(),
        1,
        "socket receive readiness timed out"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
    use std::time::Duration;

    #[test]
    fn udp_framing_preserves_senders_empty_messages_and_large_payloads() {
        for ip in [Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()] {
            let server = UdpSocket::bind(SocketAddr::new(ip, 0)).unwrap();
            server
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            socket2::SockRef::from(&server)
                .set_recv_buffer_size(128 * 1024)
                .unwrap();
            let address = server.local_addr().unwrap();
            let sock: Socket = server.into();
            let clients: Vec<_> = (0..2)
                .map(|_| UdpSocket::bind(SocketAddr::new(ip, 0)).unwrap())
                .collect();
            let mut rx = HostDatagramRx::default();
            let mut previous_seq = None;
            for (index, len) in [0, 1, 4096, 65_507, 0, 17].into_iter().enumerate() {
                let client = &clients[index % 2];
                socket2::SockRef::from(client)
                    .set_send_buffer_size(128 * 1024)
                    .unwrap();
                let original: Vec<_> = (0..len).map(|i| (i % 251) as u8).collect();
                client.send_to(&original, address).unwrap();
                wait_readable(super::super::proxy::raw_handle(&sock));
                let mut recovered = Vec::new();
                let mut seq = None;
                loop {
                    let mut frame = [0xa5; 1024];
                    let n = rx.receive_frame(&sock, &mut frame).unwrap();
                    let word = |at| u32::from_le_bytes(frame[at..at + 4].try_into().unwrap());
                    assert_eq!(word(4) as usize, len);
                    assert_eq!(word(8) as usize, recovered.len());
                    let source =
                        VsockAddr::parse_linux(&frame[16..FRAME_HEADER], word(12)).unwrap();
                    assert_eq!(source.inet(), Some(client.local_addr().unwrap()));
                    if let Some(seq) = seq {
                        assert_eq!(word(0), seq);
                    } else {
                        seq = Some(word(0));
                    }
                    assert!(frame[n..].iter().all(|b| *b == 0xa5));
                    recovered.extend_from_slice(&frame[FRAME_HEADER..n]);
                    if recovered.len() == len {
                        break;
                    }
                }
                assert_ne!(seq, previous_seq);
                previous_seq = seq;
                assert_eq!(recovered, original);
                assert!(rx.payload.capacity() <= MAX_DATAGRAM);
            }
        }
    }

    #[test]
    fn injected_replies_do_not_interrupt_fragments_and_the_queue_is_bounded() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        client
            .send_to(&[7; 1024], server.local_addr().unwrap())
            .unwrap();
        let sock: Socket = server.into();
        wait_readable(super::super::proxy::raw_handle(&sock));
        let mut rx = HostDatagramRx::default();
        let mut frame = [0; FRAME_HEADER + 256];
        assert_eq!(rx.receive_frame(&sock, &mut frame).unwrap(), frame.len());
        let sequence = u32::from_le_bytes(frame[..4].try_into().unwrap());
        let dns: VsockAddr = SocketAddr::from((Ipv4Addr::LOCALHOST, 53)).into();
        for i in 0..8 {
            assert!(rx.enqueue(dns.clone(), vec![i; i as usize]));
        }
        assert!(!rx.enqueue(dns.clone(), b"full".to_vec()));
        assert!(!rx.enqueue(dns, vec![0; MAX_DATAGRAM + 1]));
        for offset in [256u32, 512, 768] {
            assert_eq!(rx.receive_frame(&sock, &mut frame).unwrap(), frame.len());
            assert_eq!(u32::from_le_bytes(frame[..4].try_into().unwrap()), sequence);
            assert_eq!(u32::from_le_bytes(frame[8..12].try_into().unwrap()), offset);
            assert_eq!(frame[FRAME_HEADER..], [7; 256]);
        }
        for i in 0..8 {
            let count = rx.receive_frame(&sock, &mut frame).unwrap();
            assert_eq!(count, FRAME_HEADER + i);
            assert_eq!(frame[FRAME_HEADER..count], vec![i as u8; i]);
            assert_eq!(
                u32::from_le_bytes(frame[..4].try_into().unwrap()),
                sequence + 1 + i as u32
            );
        }
        assert_eq!(
            rx.receive_frame(&sock, &mut frame).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(rx.payload.capacity() <= MAX_DATAGRAM);
    }

    #[test]
    fn a_short_buffer_does_not_consume_a_host_datagram() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        client
            .send_to(b"retained", server.local_addr().unwrap())
            .unwrap();
        let sock: Socket = server.into();
        let mut rx = HostDatagramRx::default();
        assert!(rx.receive_frame(&sock, &mut [0; FRAME_HEADER]).is_err());
        wait_readable(super::super::proxy::raw_handle(&sock));
        let mut frame = [0; 128];
        let n = rx.receive_frame(&sock, &mut frame).unwrap();
        assert_eq!(&frame[FRAME_HEADER..n], b"retained");
    }
}
