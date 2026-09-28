//! Minimal L3/L4 parsing for dispatching TUN packets, plus builders for the
//! few packets vigil synthesises itself (UDP replies and TCP resets).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_ICMPV6: u8 = 58;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

/// Length of the fixed IPv6 header.
pub const IPV6_HEADER_LEN: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpInfo {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    /// Offset of the transport header.
    pub l4_offset: usize,
    /// End of the IP payload (excludes link padding).
    pub end: usize,
    /// Packet is a (non-first or non-last) fragment.
    pub fragment: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpInfo {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub payload_len: usize,
}

impl TcpInfo {
    pub fn is_initial_syn(&self) -> bool {
        self.flags & TCP_SYN != 0 && self.flags & (TCP_ACK | TCP_RST) == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpInfo {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub payload_offset: usize,
    pub payload_end: usize,
}

pub fn parse_ip(p: &[u8]) -> Option<IpInfo> {
    match p.first()? >> 4 {
        4 => {
            if p.len() < 20 {
                return None;
            }
            let ihl = ((p[0] & 0x0f) as usize) * 4;
            let total = u16::from_be_bytes([p[2], p[3]]) as usize;
            if ihl < 20 || total < ihl || total > p.len() {
                return None;
            }
            let frag = u16::from_be_bytes([p[6], p[7]]);
            let more_fragments = frag & 0x2000 != 0;
            let offset = frag & 0x1fff;
            Some(IpInfo {
                src: IpAddr::V4(Ipv4Addr::new(p[12], p[13], p[14], p[15])),
                dst: IpAddr::V4(Ipv4Addr::new(p[16], p[17], p[18], p[19])),
                proto: p[9],
                l4_offset: ihl,
                end: total,
                fragment: more_fragments || offset != 0,
            })
        }
        6 => {
            if p.len() < 40 {
                return None;
            }
            let plen = u16::from_be_bytes([p[4], p[5]]) as usize;
            let end = 40 + plen;
            if end > p.len() {
                return None;
            }
            let mut src = [0u8; 16];
            let mut dst = [0u8; 16];
            src.copy_from_slice(&p[8..24]);
            dst.copy_from_slice(&p[24..40]);
            let mut next = p[6];
            let mut off = 40;
            let mut fragment = false;
            // Walk extension headers we know how to skip.
            for _ in 0..8 {
                match next {
                    0 | 43 | 60 => {
                        let h = p.get(off..off + 2)?;
                        next = h[0];
                        off += (h[1] as usize + 1) * 8;
                    }
                    44 => {
                        let h = p.get(off..off + 8)?;
                        next = h[0];
                        // An "atomic fragment" (offset 0, M = 0, RFC 6946)
                        // is a whole packet and is processed as one.
                        let offset_and_m = u16::from_be_bytes([h[2], h[3]]);
                        let offset = offset_and_m >> 3;
                        let more = offset_and_m & 1 != 0;
                        fragment |= offset != 0 || more;
                        off += 8;
                    }
                    _ => break,
                }
            }
            if off > end {
                return None;
            }
            Some(IpInfo {
                src: IpAddr::V6(Ipv6Addr::from(src)),
                dst: IpAddr::V6(Ipv6Addr::from(dst)),
                proto: next,
                l4_offset: off,
                end,
                fragment,
            })
        }
        _ => None,
    }
}

/// Rewrites an IPv6 packet whose fixed header is directly followed by an
/// atomic fragment header into the equivalent packet without it, for the
/// user-space TCP stack, which does not implement fragment headers. Returns
/// `None` if the packet has no such header or is a real fragment.
pub fn strip_atomic_fragment_v6(p: &[u8], ip: &IpInfo) -> Option<Vec<u8>> {
    if ip.fragment || p.first()? >> 4 != 6 || *p.get(6)? != 44 || ip.end < 48 {
        return None;
    }
    let h = p.get(40..48)?;
    let mut out = Vec::with_capacity(ip.end - 8);
    out.extend_from_slice(&p[..40]);
    out[6] = h[0];
    out[4..6].copy_from_slice(&((ip.end - 48) as u16).to_be_bytes());
    out.extend_from_slice(&p[48..ip.end]);
    Some(out)
}

pub fn parse_tcp(p: &[u8], ip: &IpInfo) -> Option<TcpInfo> {
    let t = p.get(ip.l4_offset..ip.end)?;
    if t.len() < 20 {
        return None;
    }
    let data_off = ((t[12] >> 4) as usize) * 4;
    if data_off < 20 || data_off > t.len() {
        return None;
    }
    Some(TcpInfo {
        src: SocketAddr::new(ip.src, u16::from_be_bytes([t[0], t[1]])),
        dst: SocketAddr::new(ip.dst, u16::from_be_bytes([t[2], t[3]])),
        seq: u32::from_be_bytes([t[4], t[5], t[6], t[7]]),
        ack: u32::from_be_bytes([t[8], t[9], t[10], t[11]]),
        flags: t[13],
        payload_len: t.len() - data_off,
    })
}

pub fn parse_udp(p: &[u8], ip: &IpInfo) -> Option<UdpInfo> {
    let u = p.get(ip.l4_offset..ip.end)?;
    if u.len() < 8 {
        return None;
    }
    let len = u16::from_be_bytes([u[4], u[5]]) as usize;
    if len < 8 || len > u.len() {
        return None;
    }
    Some(UdpInfo {
        src: SocketAddr::new(ip.src, u16::from_be_bytes([u[0], u[1]])),
        dst: SocketAddr::new(ip.dst, u16::from_be_bytes([u[2], u[3]])),
        payload_offset: ip.l4_offset + 8,
        payload_end: ip.l4_offset + len,
    })
}

fn sum16(data: &[u8], mut acc: u32) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        acc += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [b] = chunks.remainder() {
        acc += (*b as u32) << 8;
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

fn pseudo_header_sum(src: IpAddr, dst: IpAddr, proto: u8, len: usize) -> u32 {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let acc = sum16(&s.octets(), 0);
            let acc = sum16(&d.octets(), acc);
            acc + proto as u32 + len as u32
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let acc = sum16(&s.octets(), 0);
            let acc = sum16(&d.octets(), acc);
            acc + (len as u32 >> 16) + (len as u32 & 0xffff) + proto as u32
        }
        _ => 0,
    }
}

fn ip_header(src: IpAddr, dst: IpAddr, proto: u8, l4_len: usize) -> Option<Vec<u8>> {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = 20 + l4_len;
            if total > u16::MAX as usize {
                return None;
            }
            let mut h = vec![0u8; 20];
            h[0] = 0x45;
            h[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            h[6] = 0x40; // DF
            h[8] = 64;
            h[9] = proto;
            h[12..16].copy_from_slice(&s.octets());
            h[16..20].copy_from_slice(&d.octets());
            let c = fold(sum16(&h, 0));
            h[10..12].copy_from_slice(&c.to_be_bytes());
            Some(h)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            if l4_len > u16::MAX as usize {
                return None;
            }
            let mut h = vec![0u8; 40];
            h[0] = 0x60;
            h[4..6].copy_from_slice(&(l4_len as u16).to_be_bytes());
            h[6] = proto;
            h[7] = 64;
            h[8..24].copy_from_slice(&s.octets());
            h[24..40].copy_from_slice(&d.octets());
            Some(h)
        }
        _ => None,
    }
}

/// Builds an IP/UDP packet from `src` to `dst` carrying `payload`.
pub fn build_udp(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let l4_len = 8 + payload.len();
    let mut pkt = ip_header(src.ip(), dst.ip(), PROTO_UDP, l4_len)?;
    let off = pkt.len();
    pkt.extend_from_slice(&src.port().to_be_bytes());
    pkt.extend_from_slice(&dst.port().to_be_bytes());
    pkt.extend_from_slice(&(l4_len as u16).to_be_bytes());
    pkt.extend_from_slice(&[0, 0]);
    pkt.extend_from_slice(payload);
    let mut c = fold(sum16(
        &pkt[off..],
        pseudo_header_sum(src.ip(), dst.ip(), PROTO_UDP, l4_len),
    ));
    if c == 0 {
        c = 0xffff;
    }
    pkt[off + 6..off + 8].copy_from_slice(&c.to_be_bytes());
    Some(pkt)
}

/// Builds the RST|ACK a closed port would send in reply to `syn`.
pub fn build_rst_for(syn: &TcpInfo) -> Option<Vec<u8>> {
    let ack = syn
        .seq
        .wrapping_add(syn.payload_len as u32)
        .wrapping_add(if syn.flags & TCP_SYN != 0 { 1 } else { 0 });
    let seq = if syn.flags & TCP_ACK != 0 { syn.ack } else { 0 };
    build_tcp(syn.dst, syn.src, seq, ack, TCP_RST | TCP_ACK, &[])
}

/// Builds an IP/TCP segment without options (window 0 for RSTs, else
/// 65535).
pub fn build_tcp(
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let l4_len = 20 + payload.len();
    let mut pkt = ip_header(src.ip(), dst.ip(), PROTO_TCP, l4_len)?;
    let off = pkt.len();
    let window: u16 = if flags & TCP_RST != 0 { 0 } else { 65535 };
    pkt.extend_from_slice(&src.port().to_be_bytes());
    pkt.extend_from_slice(&dst.port().to_be_bytes());
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&ack.to_be_bytes());
    pkt.push(5 << 4);
    pkt.push(flags);
    pkt.extend_from_slice(&window.to_be_bytes());
    pkt.extend_from_slice(&[0, 0, 0, 0]);
    pkt.extend_from_slice(payload);
    let c = fold(sum16(
        &pkt[off..],
        pseudo_header_sum(src.ip(), dst.ip(), PROTO_TCP, l4_len),
    ));
    pkt[off + 16..off + 18].copy_from_slice(&c.to_be_bytes());
    Some(pkt)
}

/// Verifies an L4 checksum; used by tests.
pub fn l4_checksum_ok(p: &[u8], ip: &IpInfo) -> bool {
    let seg = &p[ip.l4_offset..ip.end];
    fold(sum16(
        seg,
        pseudo_header_sum(ip.src, ip.dst, ip.proto, seg.len()),
    )) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn udp_roundtrip_v4_v6() {
        for (s, d) in [
            ("10.0.0.1:53", "10.0.0.2:40000"),
            ("[fd00::1]:53", "[fd00::2]:40000"),
        ] {
            let pkt = build_udp(sa(s), sa(d), b"hello").unwrap();
            let ip = parse_ip(&pkt).unwrap();
            assert_eq!(ip.proto, PROTO_UDP);
            assert!(!ip.fragment);
            let u = parse_udp(&pkt, &ip).unwrap();
            assert_eq!(u.src, sa(s));
            assert_eq!(u.dst, sa(d));
            assert_eq!(&pkt[u.payload_offset..u.payload_end], b"hello");
            assert!(l4_checksum_ok(&pkt, &ip));
            if ip.src.is_ipv4() {
                assert_eq!(fold(sum16(&pkt[..20], 0)), 0, "ipv4 header checksum");
            }
        }
    }

    #[test]
    fn rst_for_syn() {
        let syn = TcpInfo {
            src: sa("10.0.0.2:5555"),
            dst: sa("93.184.216.34:443"),
            seq: 1000,
            ack: 0,
            flags: TCP_SYN,
            payload_len: 0,
        };
        assert!(syn.is_initial_syn());
        let pkt = build_rst_for(&syn).unwrap();
        let ip = parse_ip(&pkt).unwrap();
        let t = parse_tcp(&pkt, &ip).unwrap();
        assert_eq!(t.src, syn.dst);
        assert_eq!(t.dst, syn.src);
        assert_eq!(t.ack, 1001);
        assert_eq!(t.flags, TCP_RST | TCP_ACK);
        assert!(l4_checksum_ok(&pkt, &ip));
    }

    #[test]
    fn detects_v4_fragments_and_bad_lengths() {
        let mut pkt = build_udp(sa("10.0.0.1:1"), sa("10.0.0.2:2"), b"x").unwrap();
        pkt[6] = 0x20; // MF
        assert!(parse_ip(&pkt).unwrap().fragment);
        pkt[2] = 0xff; // total length beyond buffer
        assert!(parse_ip(&pkt).is_none());
        assert!(parse_ip(&[]).is_none());
        assert!(parse_ip(&[0x45; 10]).is_none());
    }

    /// Inserts an IPv6 fragment header (offset, M flag) after the fixed header.
    fn with_frag_header(pkt: &[u8], offset: u16, more: bool) -> Vec<u8> {
        let mut out = pkt[..40].to_vec();
        let next = out[6];
        out[6] = 44;
        let plen = u16::from_be_bytes([out[4], out[5]]) + 8;
        out[4..6].copy_from_slice(&plen.to_be_bytes());
        out.extend_from_slice(&[next, 0]);
        out.extend_from_slice(&((offset << 3) | more as u16).to_be_bytes());
        out.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        out.extend_from_slice(&pkt[40..]);
        out
    }

    #[test]
    fn ipv6_atomic_fragments_are_whole_packets() {
        let plain = build_udp(sa("[fd00::1]:5000"), sa("[2001:db8::1]:53"), b"query").unwrap();
        let atomic = with_frag_header(&plain, 0, false);
        let ip = parse_ip(&atomic).unwrap();
        assert!(!ip.fragment);
        assert_eq!(ip.proto, PROTO_UDP);
        let u = parse_udp(&atomic, &ip).unwrap();
        assert_eq!(&atomic[u.payload_offset..u.payload_end], b"query");
        // Stripping yields the original packet.
        assert_eq!(strip_atomic_fragment_v6(&atomic, &ip).unwrap(), plain);
        assert!(strip_atomic_fragment_v6(&plain, &parse_ip(&plain).unwrap()).is_none());
        // Real fragments stay fragments.
        for (off, more) in [(0, true), (8, false), (8, true)] {
            let f = with_frag_header(&plain, off, more);
            let ip = parse_ip(&f).unwrap();
            assert!(ip.fragment, "offset {off} more {more}");
            assert!(strip_atomic_fragment_v6(&f, &ip).is_none());
        }
    }
}
