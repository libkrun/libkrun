pub(super) const EPERM: i32 = 1;
pub(super) const EIO: i32 = 5;
pub(super) const EPROTO: i32 = 71;
pub(super) const EPROTONOSUPPORT: i32 = 93;
pub(super) const ESOCKTNOSUPPORT: i32 = 94;
pub(super) const EAFNOSUPPORT: i32 = 97;
pub(super) const EINVAL: i32 = 22;
pub(super) const ENOPROTOOPT: i32 = 92;
pub(super) const EADDRINUSE: i32 = 98;
pub(super) const ECONNREFUSED: i32 = 111;
pub(super) const EOPNOTSUPP: i32 = 95;
pub(super) const VERSION: u32 = 4;
pub(super) const DGRAM_HEADER_LEN: usize = 168;
pub(super) const DGRAM_MAX_SIZE: usize = 65536;
pub(super) const DGRAM_TRUNC: u32 = 1;
pub(super) const DGRAM_PKTINFO: u32 = 2;
pub(super) const DGRAM_HOPLIMIT: u32 = 4;

pub(super) const CONTROL_HEADER_LEN: usize = 24;
pub(super) const CONTROL_REPLY: u32 = 1;
pub(super) const CONTROL_ONEWAY: u32 = 2;

pub(super) fn control_id(buf: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(buf.get(8..16)?.try_into().ok()?))
}

pub(super) fn decode_control(buf: &[u8], operation: u32) -> Result<&[u8], i32> {
    if buf.len() < CONTROL_HEADER_LEN {
        return Err(-EPROTO);
    }
    if u32::from_le_bytes(buf[0..4].try_into().unwrap()) != VERSION {
        return Err(-EPROTONOSUPPORT);
    }
    let op = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    let len = u32::from_le_bytes(buf[16..20].try_into().unwrap()) as usize;
    let flags = u32::from_le_bytes(buf[20..24].try_into().unwrap());
    let (body_len, expected_flags) = match operation {
        1024 | 1026 => (12, 0),
        1025 | 1036 => (136, 0),
        1027 => (136, CONTROL_ONEWAY),
        1029 => (144, 0),
        1030 => (8, 0),
        1031 => (8, CONTROL_ONEWAY),
        1033 => (4, 0),
        1034 => (20, 0),
        1035 => (16, 0),
        _ => return Err(-EPROTO),
    };
    if op != operation
        || control_id(buf) == Some(0)
        || flags != expected_flags
        || len != body_len
        || buf.len() != CONTROL_HEADER_LEN + len
    {
        return Err(-EPROTO);
    }
    Ok(&buf[CONTROL_HEADER_LEN..])
}

pub(super) fn encode_control_reply(buf: &mut [u8], operation: u32, id: u64, len: usize) {
    buf[..CONTROL_HEADER_LEN + len].fill(0);
    buf[0..4].copy_from_slice(&VERSION.to_le_bytes());
    buf[4..8].copy_from_slice(&operation.to_le_bytes());
    buf[8..16].copy_from_slice(&id.to_le_bytes());
    buf[16..20].copy_from_slice(&(len as u32).to_le_bytes());
    buf[20..24].copy_from_slice(&CONTROL_REPLY.to_le_bytes());
}

pub(super) fn check_protocol(family: u16, socket_type: u16, protocol: u32) -> Result<(), i32> {
    match (family, socket_type, protocol) {
        (1, 1 | 2, 0) | (2 | 10, 1, 0 | 6) | (2 | 10, 2, 0 | 17) => Ok(()),
        (2, 2, 1) | (10, 2, 58) if cfg!(any(target_os = "linux", target_os = "macos")) => Ok(()),
        (1 | 2 | 10, 1 | 2, _) => Err(-EPROTONOSUPPORT),
        (1 | 2 | 10, _, _) => Err(-ESOCKTNOSUPPORT),
        _ => Err(-EAFNOSUPPORT),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DatagramInfo {
    pub address: [u8; 16],
    pub ifindex: u32,
    pub hop_limit: Option<u8>,
}

pub(super) struct Datagram<'a> {
    pub address: &'a [u8],
    pub payload: &'a [u8],
    pub flags: u32,
    pub info: Option<DatagramInfo>,
}

pub(super) fn decode_datagram(buf: &[u8]) -> Option<Datagram<'_>> {
    if !(DGRAM_HEADER_LEN..=DGRAM_MAX_SIZE).contains(&buf.len()) {
        return None;
    }
    let version = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    let addr_len = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
    let data_len = u32::from_le_bytes(buf[8..12].try_into().unwrap()) as usize;
    let flags = u32::from_le_bytes(buf[12..16].try_into().unwrap());
    let family = u16::from_le_bytes(buf[16..18].try_into().unwrap());
    let address_valid = matches!((family, addr_len), (2, 16) | (10, 28));
    let payload = &buf[DGRAM_HEADER_LEN..];
    let info_address: [u8; 16] = buf[152..168].try_into().unwrap();
    let ifindex = u32::from_le_bytes(buf[144..148].try_into().unwrap());
    let has_info = flags & DGRAM_PKTINFO != 0;
    let has_hop_limit = flags & DGRAM_HOPLIMIT != 0;
    let hop_limit = u32::from_le_bytes(buf[148..152].try_into().unwrap());
    let info_valid = if has_info {
        info_address != [0; 16] && (family != 2 || info_address[4..] == [0; 12])
    } else {
        ifindex == 0 && info_address == [0; 16]
    };
    if version != VERSION
        || !address_valid
        || flags & !(DGRAM_TRUNC | DGRAM_PKTINFO | DGRAM_HOPLIMIT) != 0
        || !info_valid
        || (has_hop_limit && (!has_info || hop_limit > 255))
        || (!has_hop_limit && hop_limit != 0)
        || data_len > 65535
        || payload.len() > data_len
        || (flags & DGRAM_TRUNC == 0 && payload.len() != data_len)
    {
        return None;
    }
    Some(Datagram {
        address: &buf[16..16 + addr_len],
        payload,
        flags,
        info: has_info.then_some(DatagramInfo {
            address: info_address,
            ifindex,
            hop_limit: has_hop_limit.then_some(hop_limit as u8),
        }),
    })
}

pub(super) fn decode_datagram_send(buf: &[u8]) -> Option<Datagram<'_>> {
    let frame = decode_datagram(buf)?;
    if frame.flags & (DGRAM_TRUNC | DGRAM_HOPLIMIT) != 0
        || frame.info.is_some_and(|info| info.ifindex != 0)
    {
        return None;
    }
    Some(frame)
}

pub(super) fn encode_header(
    buf: &mut [u8],
    addr: &[u8],
    data_len: usize,
    truncated: bool,
    info: Option<DatagramInfo>,
) {
    buf[..DGRAM_HEADER_LEN].fill(0);
    buf[0..4].copy_from_slice(&VERSION.to_le_bytes());
    buf[4..8].copy_from_slice(&(addr.len() as u32).to_le_bytes());
    buf[8..12].copy_from_slice(&(data_len as u32).to_le_bytes());
    let flags = if truncated { DGRAM_TRUNC } else { 0 }
        | if info.is_some() { DGRAM_PKTINFO } else { 0 }
        | if info.is_some_and(|info| info.hop_limit.is_some()) {
            DGRAM_HOPLIMIT
        } else {
            0
        };
    buf[12..16].copy_from_slice(&flags.to_le_bytes());
    if let Some(info) = info {
        buf[144..148].copy_from_slice(&info.ifindex.to_le_bytes());
        buf[148..152].copy_from_slice(&u32::from(info.hop_limit.unwrap_or(0)).to_le_bytes());
        buf[152..168].copy_from_slice(&info.address);
    }
    buf[16..16 + addr.len()].copy_from_slice(addr);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet() -> Vec<u8> {
        let mut addr = [0u8; 16];
        addr[..2].copy_from_slice(&2u16.to_le_bytes());
        addr[2..4].copy_from_slice(&5353u16.to_be_bytes());
        addr[4..8].copy_from_slice(&[127, 0, 0, 1]);
        let mut buf = vec![0; DGRAM_HEADER_LEN + 2];
        encode_header(&mut buf, &addr, 2, false, None);
        buf[DGRAM_HEADER_LEN..].copy_from_slice(b"hi");
        buf
    }

    #[test]
    fn udp_bind_control_layout() {
        let mut frame = vec![0; CONTROL_HEADER_LEN + 136];
        encode_control_reply(&mut frame, 1036, 19, 136);
        frame[20..24].fill(0);
        assert_eq!(decode_control(&frame, 1036).unwrap().len(), 136);
        assert_eq!(decode_control(&frame, 1025), Err(-EPROTO));
        frame.push(0);
        assert_eq!(decode_control(&frame, 1036), Err(-EPROTO));
        frame.pop();
        frame[16..20].copy_from_slice(&135u32.to_le_bytes());
        assert_eq!(decode_control(&frame, 1036), Err(-EPROTO));
    }

    #[test]
    fn datagram_wire_layout() {
        let buf = packet();
        assert_eq!(
            &buf[..16],
            &[4, 0, 0, 0, 16, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0]
        );
        let decoded = decode_datagram(&buf).unwrap();
        assert_eq!(&decoded.address[2..4], &5353u16.to_be_bytes());
        assert_eq!(decoded.payload, b"hi");
        assert_eq!(decoded.flags, 0);
        assert!(buf[32..DGRAM_HEADER_LEN].iter().all(|b| *b == 0));
    }

    #[test]
    fn packet_info_roundtrip_and_reserved_fields() {
        let mut buf = packet();
        let address = [127, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let info = DatagramInfo {
            address,
            ifindex: 0x10203,
            hop_limit: None,
        };
        let peer = buf[16..32].to_vec();
        encode_header(&mut buf, &peer, 2, false, Some(info));
        assert_eq!(decode_datagram(&buf).unwrap().info, Some(info));
        assert_eq!(&buf[144..148], &0x10203u32.to_le_bytes());
        for offset in [148, 151, 156, 167] {
            let mut bad = buf.clone();
            bad[offset] = 1;
            assert!(decode_datagram(&bad).is_none(), "offset {offset}");
        }
        buf[12..16].fill(0);
        assert!(decode_datagram(&buf).is_none());
        buf[144..168].fill(0);
        assert!(decode_datagram(&buf).is_some());
        buf[12] = DGRAM_PKTINFO as u8;
        assert!(decode_datagram(&buf).is_none());
    }

    #[test]
    fn ipv6_packet_info_preserves_all_address_bytes() {
        let mut peer = [0; 28];
        peer[..2].copy_from_slice(&10u16.to_le_bytes());
        peer[23] = 1;
        let mut address = [0; 16];
        address[0] = 0xfd;
        address[15] = 2;
        let info = DatagramInfo {
            address,
            ifindex: 99,
            hop_limit: None,
        };
        let mut buf = vec![0; DGRAM_HEADER_LEN];
        encode_header(&mut buf, &peer, 0, false, Some(info));
        assert_eq!(decode_datagram(&buf).unwrap().info, Some(info));
    }

    #[test]
    fn guest_source_selection_cannot_supply_host_interfaces_or_truncation() {
        let mut buf = packet();
        let peer = buf[16..32].to_vec();
        let info = DatagramInfo {
            address: [127, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ifindex: 0,
            hop_limit: None,
        };
        encode_header(&mut buf, &peer, 2, false, Some(info));
        assert_eq!(decode_datagram_send(&buf).unwrap().info, Some(info));
        buf[144..148].copy_from_slice(&3u32.to_le_bytes());
        assert!(decode_datagram(&buf).is_some());
        assert!(decode_datagram_send(&buf).is_none());
        buf[144..148].fill(0);
        buf[12] |= DGRAM_TRUNC as u8;
        assert!(decode_datagram_send(&buf).is_none());
    }

    #[test]
    fn empty_datagram_is_a_packet() {
        let mut buf = packet();
        buf.truncate(DGRAM_HEADER_LEN);
        buf[8..12].fill(0);
        assert!(decode_datagram(&buf).unwrap().payload.is_empty());
    }

    #[test]
    fn reject_bad_datagram_fields() {
        let valid = packet();
        for (offset, value) in [(0, 3), (4, 129), (8, 1), (12, 2), (12, 4), (16, 1)] {
            let mut buf = valid.clone();
            buf[offset] = value;
            assert!(decode_datagram(&buf).is_none(), "offset {offset}");
        }
        for len in 0..DGRAM_HEADER_LEN {
            assert!(decode_datagram(&valid[..len]).is_none());
        }
    }

    #[test]
    fn truncated_frame_needs_a_flag() {
        let mut buf = packet();
        buf[8..12].copy_from_slice(&3u32.to_le_bytes());
        assert!(decode_datagram(&buf).is_none());
        buf[12..16].copy_from_slice(&DGRAM_TRUNC.to_le_bytes());
        assert_eq!(decode_datagram(&buf).unwrap().payload, b"hi");
    }
    fn control_request() -> Vec<u8> {
        let mut buf = vec![0; CONTROL_HEADER_LEN + 12];
        encode_control_reply(&mut buf, 1024, 0x123456789abcdef0, 12);
        buf[20..24].fill(0);
        buf
    }

    #[test]
    fn control_request_checks_entire_envelope() {
        let buf = control_request();
        assert_eq!(decode_control(&buf, 1024).unwrap().len(), 12);
        assert_eq!(control_id(&buf), Some(0x123456789abcdef0));
        for len in 0..buf.len() {
            assert!(decode_control(&buf[..len], 1024).is_err());
        }
        for (offset, value) in [(4, 1), (16, 11), (20, 1), (23, 128)] {
            let mut bad = buf.clone();
            bad[offset] = value;
            assert_eq!(decode_control(&bad, 1024), Err(-EPROTO));
        }
        let mut bad = buf.clone();
        bad[8..16].fill(0);
        assert_eq!(decode_control(&bad, 1024), Err(-EPROTO));
        let mut bad = buf.clone();
        bad[0] = 3;
        assert_eq!(decode_control(&bad, 1024), Err(-EPROTONOSUPPORT));
        let mut bad = buf;
        bad.push(0);
        assert_eq!(decode_control(&bad, 1024), Err(-EPROTO));
    }

    #[test]
    fn control_release_is_oneway_and_exact() {
        let mut buf = vec![0; CONTROL_HEADER_LEN + 8];
        encode_control_reply(&mut buf, 1031, 1, 8);
        assert!(decode_control(&buf, 1031).is_err());
        buf[20..24].copy_from_slice(&CONTROL_ONEWAY.to_le_bytes());
        assert_eq!(decode_control(&buf, 1031).unwrap().len(), 8);
    }

    #[test]
    fn reply_hop_limit_is_validated_and_not_a_send_option() {
        let mut buf = packet();
        let address = buf[16..32].to_vec();
        let info = DatagramInfo {
            address: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ifindex: 1,
            hop_limit: Some(64),
        };
        encode_header(&mut buf, &address, 2, false, Some(info));
        assert_eq!(decode_datagram(&buf).unwrap().info, Some(info));
        assert!(decode_datagram_send(&buf).is_none());
        buf[148..152].copy_from_slice(&256u32.to_le_bytes());
        assert!(decode_datagram(&buf).is_none());
        buf[148..152].copy_from_slice(&64u32.to_le_bytes());
        buf[12..16].copy_from_slice(&DGRAM_HOPLIMIT.to_le_bytes());
        assert!(decode_datagram(&buf).is_none());
        buf[12..16].copy_from_slice(&DGRAM_PKTINFO.to_le_bytes());
        assert!(decode_datagram(&buf).is_none());
    }

    #[test]
    fn supported_protocols_are_explicit() {
        for family in [2, 10] {
            for (kind, protocol) in [(1, 0), (1, 6), (2, 0), (2, 17)] {
                assert_eq!(check_protocol(family, kind, protocol), Ok(()));
            }
            for (kind, protocol) in [(1, 17), (2, 6), (2, 132)] {
                assert_eq!(
                    check_protocol(family, kind, protocol),
                    Err(-EPROTONOSUPPORT)
                );
            }
        }
        for (family, protocol) in [(2, 1), (10, 58)] {
            let expected = if cfg!(any(target_os = "linux", target_os = "macos")) {
                Ok(())
            } else {
                Err(-EPROTONOSUPPORT)
            };
            assert_eq!(check_protocol(family, 2, protocol), expected);
        }
        assert_eq!(check_protocol(2, 2, 58), Err(-EPROTONOSUPPORT));
        assert_eq!(check_protocol(10, 2, 1), Err(-EPROTONOSUPPORT));
        assert_eq!(check_protocol(1, 2, 0), Ok(()));
        assert_eq!(check_protocol(1, 2, 17), Err(-EPROTONOSUPPORT));
        assert_eq!(check_protocol(2, 3, 0), Err(-ESOCKTNOSUPPORT));
        assert_eq!(check_protocol(0, 2, 0), Err(-EAFNOSUPPORT));
    }
    #[test]
    fn disconnect_control_has_exact_port_body() {
        let mut buf = vec![0; CONTROL_HEADER_LEN + 4];
        encode_control_reply(&mut buf, 1033, 5, 4);
        buf[20..24].fill(0);
        assert_eq!(decode_control(&buf, 1033).unwrap().len(), 4);
        buf.push(0);
        assert_eq!(decode_control(&buf, 1033), Err(-EPROTO));
        buf.pop();
        buf[16..20].copy_from_slice(&8u32.to_le_bytes());
        assert_eq!(decode_control(&buf, 1033), Err(-EPROTO));
    }
}
