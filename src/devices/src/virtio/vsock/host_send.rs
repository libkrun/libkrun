// SPDX-License-Identifier: Apache-2.0

//! Acknowledged host UDP sends. Address control (opcode 1033) contains a
//! little-endian peer port, address length and sequence, then a Linux sockaddr.
//! The following TSI_SENDTO_DATA carries only the payload, preserving the full
//! UDP size limit. A 12-byte reply contains sequence and Linux send result.

use super::vsock_addr::VsockAddr;

pub struct HostSendRequest {
    pub peer_port: u32,
    pub sequence: u64,
    pub destination: Result<VsockAddr, i32>,
}

impl HostSendRequest {
    pub fn parse(data: &[u8]) -> Option<Self> {
        let header = data.get(..16)?;
        let peer_port = u32::from_le_bytes(header[..4].try_into().ok()?);
        let addr_len = u32::from_le_bytes(header[4..8].try_into().ok()?);
        let sequence = u64::from_le_bytes(header[8..16].try_into().ok()?);
        let destination = VsockAddr::parse_linux(&data[16..], addr_len)
            .filter(|addr| addr.inet().is_some() && addr.linux_len() == addr_len)
            .ok_or(-22);
        Some(Self {
            peer_port,
            sequence,
            destination,
        })
    }
}

pub struct PendingHostSend {
    pub control_port: u32,
    pub sequence: u64,
    pub destination: Result<VsockAddr, i32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_addresses_keep_the_reply_sequence_and_never_select_a_destination() {
        let mut data = Vec::from(7000u32.to_le_bytes());
        data.extend(16u32.to_le_bytes());
        data.extend(91u64.to_le_bytes());
        for end in 0..16 {
            assert!(HostSendRequest::parse(&data[..end]).is_none());
        }
        for length in [0u32, 2, 16, 28, u32::MAX] {
            data[4..8].copy_from_slice(&length.to_le_bytes());
            let request = HostSendRequest::parse(&data).unwrap();
            assert_eq!(request.peer_port, 7000);
            assert_eq!(request.sequence, 91);
            assert_eq!(request.destination, Err(-22));
        }
    }
}
