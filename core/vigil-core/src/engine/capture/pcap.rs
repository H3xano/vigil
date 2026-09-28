//! Capture file formats: PCAPng (export) and classic PCAP (PCAP-over-IP),
//! both with link type RAW (101: the packet starts with the IPv4 or IPv6
//! header), plus a lenient header parser for possibly truncated packets.

use super::ring::Dir;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// LINKTYPE_RAW: raw IPv4/IPv6.
pub const LINKTYPE_RAW: u16 = 101;

const SHB: u32 = 0x0A0D_0D0A;
const IDB: u32 = 0x0000_0001;
const EPB: u32 = 0x0000_0006;
const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;

const OPT_END: u16 = 0;
const OPT_COMMENT: u16 = 1;
const SHB_OS: u16 = 3;
const SHB_USERAPPL: u16 = 4;
const IF_NAME: u16 = 2;
const IF_DESCRIPTION: u16 = 3;
const IF_TSRESOL: u16 = 9;
const EPB_FLAGS: u16 = 2;

fn pad4(n: usize) -> usize {
    (4 - n % 4) % 4
}

fn option_len(value_len: usize) -> usize {
    4 + value_len + pad4(value_len)
}

fn put_option(b: &mut Vec<u8>, code: u16, value: &[u8]) {
    b.extend_from_slice(&code.to_le_bytes());
    b.extend_from_slice(&(value.len() as u16).to_le_bytes());
    b.extend_from_slice(value);
    b.resize(b.len() + pad4(value.len()), 0);
}

/// Finishes a block: fills in the total length at offset 4 and appends it.
fn close_block(b: &mut Vec<u8>) {
    let total = (b.len() + 4) as u32;
    b[4..8].copy_from_slice(&total.to_le_bytes());
    b.extend_from_slice(&total.to_le_bytes());
}

/// Writes a PCAPng section with one RAW interface. Little-endian, as the
/// byte-order magic declares.
pub struct PcapngWriter<W: Write> {
    out: W,
    block: Vec<u8>,
}

impl<W: Write> PcapngWriter<W> {
    /// Writes the section header and the interface description.
    pub fn new(mut out: W, snaplen: u32, application: &str) -> io::Result<Self> {
        let mut b = Vec::with_capacity(256);
        b.extend_from_slice(&SHB.to_le_bytes());
        b.extend_from_slice(&[0; 4]);
        b.extend_from_slice(&BYTE_ORDER_MAGIC.to_le_bytes());
        b.extend_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&(-1i64).to_le_bytes());
        put_option(&mut b, SHB_OS, std::env::consts::OS.as_bytes());
        put_option(&mut b, SHB_USERAPPL, application.as_bytes());
        put_option(&mut b, OPT_END, &[]);
        close_block(&mut b);
        out.write_all(&b)?;

        b.clear();
        b.extend_from_slice(&IDB.to_le_bytes());
        b.extend_from_slice(&[0; 4]);
        b.extend_from_slice(&LINKTYPE_RAW.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&snaplen.to_le_bytes());
        put_option(&mut b, IF_NAME, b"vigil");
        put_option(
            &mut b,
            IF_DESCRIPTION,
            b"vigil VPN interface (packets as apps sent and received them)",
        );
        put_option(&mut b, IF_TSRESOL, &[6]);
        put_option(&mut b, OPT_END, &[]);
        close_block(&mut b);
        out.write_all(&b)?;
        Ok(Self { out, block: b })
    }

    /// Writes one Enhanced Packet Block. `dir` sets `epb_flags` (packets
    /// apps sent are outbound, packets to apps inbound).
    pub fn packet(
        &mut self,
        ts_us: u64,
        orig_len: u32,
        data: &[u8],
        dir: Dir,
        comment: Option<&str>,
    ) -> io::Result<()> {
        let b = &mut self.block;
        b.clear();
        let comment = comment.map(|c| &c.as_bytes()[..c.len().min(u16::MAX as usize - 3)]);
        let opts = option_len(4) + comment.map_or(0, |c| option_len(c.len())) + 4;
        b.reserve(32 + data.len() + 3 + opts);
        b.extend_from_slice(&EPB.to_le_bytes());
        b.extend_from_slice(&[0; 4]);
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&((ts_us >> 32) as u32).to_le_bytes());
        b.extend_from_slice(&(ts_us as u32).to_le_bytes());
        b.extend_from_slice(&(data.len() as u32).to_le_bytes());
        b.extend_from_slice(&orig_len.max(data.len() as u32).to_le_bytes());
        b.extend_from_slice(data);
        b.resize(b.len() + pad4(data.len()), 0);
        if let Some(c) = comment {
            put_option(b, OPT_COMMENT, c);
        }
        let flags: u32 = match dir {
            Dir::ToApp => 1,
            Dir::FromApp => 2,
        };
        put_option(b, EPB_FLAGS, &flags.to_le_bytes());
        put_option(b, OPT_END, &[]);
        close_block(b);
        self.out.write_all(b)
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.out.flush()?;
        Ok(self.out)
    }
}

/// Classic PCAP global header (microsecond timestamps, little-endian).
pub fn pcap_global_header(snaplen: u32) -> [u8; 24] {
    let mut h = [0u8; 24];
    h[0..4].copy_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    h[4..6].copy_from_slice(&2u16.to_le_bytes());
    h[6..8].copy_from_slice(&4u16.to_le_bytes());
    // thiszone, sigfigs: 0
    h[16..20].copy_from_slice(&snaplen.to_le_bytes());
    h[20..24].copy_from_slice(&(LINKTYPE_RAW as u32).to_le_bytes());
    h
}

/// One classic PCAP record (header and data).
pub fn pcap_record(ts_us: u64, orig_len: u32, data: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(16 + data.len());
    r.extend_from_slice(&((ts_us / 1_000_000) as u32).to_le_bytes());
    r.extend_from_slice(&((ts_us % 1_000_000) as u32).to_le_bytes());
    r.extend_from_slice(&(data.len() as u32).to_le_bytes());
    r.extend_from_slice(&orig_len.max(data.len() as u32).to_le_bytes());
    r.extend_from_slice(data);
    r
}

/// Transport 5-tuple of a (possibly truncated) captured packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketKey {
    pub proto: u8,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    /// A TCP SYN without ACK: opens a connection.
    pub initial_syn: bool,
}

/// Reads the addresses, protocol and ports without requiring the whole
/// packet (it may be cut at the snap length). None for non-TCP/UDP packets
/// and fragments after the first.
pub fn packet_key(p: &[u8]) -> Option<PacketKey> {
    let (src, dst, proto, l4) = match p.first()? >> 4 {
        4 => {
            let h = p.get(..20)?;
            let ihl = ((h[0] & 0x0f) as usize) * 4;
            let frag_offset = u16::from_be_bytes([h[6], h[7]]) & 0x1fff;
            if ihl < 20 || frag_offset != 0 {
                return None;
            }
            let src = IpAddr::V4(Ipv4Addr::new(h[12], h[13], h[14], h[15]));
            let dst = IpAddr::V4(Ipv4Addr::new(h[16], h[17], h[18], h[19]));
            (src, dst, h[9], ihl)
        }
        6 => {
            let h = p.get(..40)?;
            let src: [u8; 16] = h[8..24].try_into().ok()?;
            let dst: [u8; 16] = h[24..40].try_into().ok()?;
            let mut next = h[6];
            let mut off = 40;
            for _ in 0..8 {
                match next {
                    0 | 43 | 60 => {
                        let e = p.get(off..off + 2)?;
                        next = e[0];
                        off += (e[1] as usize + 1) * 8;
                    }
                    44 => {
                        let e = p.get(off..off + 8)?;
                        if u16::from_be_bytes([e[2], e[3]]) >> 3 != 0 {
                            return None;
                        }
                        next = e[0];
                        off += 8;
                    }
                    _ => break,
                }
            }
            (
                IpAddr::V6(Ipv6Addr::from(src)),
                IpAddr::V6(Ipv6Addr::from(dst)),
                next,
                off,
            )
        }
        _ => return None,
    };
    if proto != crate::packet::PROTO_TCP && proto != crate::packet::PROTO_UDP {
        return None;
    }
    let t = p.get(l4..l4 + 4)?;
    let sport = u16::from_be_bytes([t[0], t[1]]);
    let dport = u16::from_be_bytes([t[2], t[3]]);
    let initial_syn = proto == crate::packet::PROTO_TCP
        && p.get(l4 + 13).is_some_and(|f| {
            f & crate::packet::TCP_SYN != 0
                && f & (crate::packet::TCP_ACK | crate::packet::TCP_RST) == 0
        });
    Some(PacketKey {
        proto,
        src: SocketAddr::new(src, sport),
        dst: SocketAddr::new(dst, dport),
        initial_syn,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::packet;

    /// A block of a PCAPng file: type, body (between the length fields).
    pub(crate) fn blocks(file: &[u8]) -> Vec<(u32, Vec<u8>)> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < file.len() {
            let ty = u32::from_le_bytes(file[pos..pos + 4].try_into().unwrap());
            let len = u32::from_le_bytes(file[pos + 4..pos + 8].try_into().unwrap()) as usize;
            assert!(len >= 12 && len % 4 == 0, "block length {len}");
            let trailer =
                u32::from_le_bytes(file[pos + len - 4..pos + len].try_into().unwrap()) as usize;
            assert_eq!(len, trailer, "trailing length");
            out.push((ty, file[pos + 8..pos + len - 4].to_vec()));
            pos += len;
        }
        assert_eq!(pos, file.len());
        out
    }

    /// Options of a block body starting at `offset`: (code, value).
    pub(crate) fn options(body: &[u8], mut offset: usize) -> Vec<(u16, Vec<u8>)> {
        let mut out = Vec::new();
        loop {
            let code = u16::from_le_bytes(body[offset..offset + 2].try_into().unwrap());
            let len = u16::from_le_bytes(body[offset + 2..offset + 4].try_into().unwrap()) as usize;
            if code == 0 {
                assert_eq!(offset + 4, body.len(), "end of options ends the block");
                return out;
            }
            out.push((code, body[offset + 4..offset + 4 + len].to_vec()));
            offset += 4 + len + pad4(len);
        }
    }

    pub(crate) type Options = Vec<(u16, Vec<u8>)>;

    /// An EPB body: (ts_us, captured data, original length, options).
    pub(crate) fn epb(body: &[u8]) -> (u64, Vec<u8>, u32, Options) {
        let u = |o: usize| u32::from_le_bytes(body[o..o + 4].try_into().unwrap());
        assert_eq!(u(0), 0, "interface id");
        let ts = ((u(4) as u64) << 32) | u(8) as u64;
        let cap = u(12) as usize;
        let data = body[20..20 + cap].to_vec();
        let opts = options(body, 20 + cap + pad4(cap));
        (ts, data, u(16), opts)
    }

    #[test]
    fn pcapng_block_structure() {
        let a = packet::build_udp(
            "10.111.222.1:40000".parse().unwrap(),
            "10.111.222.2:53".parse().unwrap(),
            b"hello",
        )
        .unwrap();
        let mut w = PcapngWriter::new(Vec::new(), 65535, "vigil 0.0.0").unwrap();
        w.packet(
            1_700_000_000_123_456,
            a.len() as u32,
            &a,
            Dir::FromApp,
            Some("uid=10123 flow=7"),
        )
        .unwrap();
        w.packet(1_700_000_000_223_456, 1500, &a[..30], Dir::ToApp, None)
            .unwrap();
        let file = w.finish().unwrap();
        let b = blocks(&file);
        assert_eq!(
            b.iter().map(|(t, _)| *t).collect::<Vec<_>>(),
            vec![SHB, IDB, EPB, EPB]
        );
        let shb = &b[0].1;
        assert_eq!(
            u32::from_le_bytes(shb[0..4].try_into().unwrap()),
            BYTE_ORDER_MAGIC
        );
        assert_eq!(&shb[4..8], &[1, 0, 0, 0]);
        let shb_opts = options(shb, 16);
        assert!(shb_opts.contains(&(SHB_USERAPPL, b"vigil 0.0.0".to_vec())));
        let idb = &b[1].1;
        assert_eq!(u16::from_le_bytes(idb[0..2].try_into().unwrap()), 101);
        assert_eq!(u32::from_le_bytes(idb[4..8].try_into().unwrap()), 65535);
        assert!(options(idb, 8).contains(&(IF_TSRESOL, vec![6])));
        let (ts, data, orig, opts) = epb(&b[2].1);
        assert_eq!(
            (ts, data.as_slice(), orig),
            (1_700_000_000_123_456, &a[..], a.len() as u32)
        );
        assert_eq!(
            opts,
            vec![
                (OPT_COMMENT, b"uid=10123 flow=7".to_vec()),
                (EPB_FLAGS, 2u32.to_le_bytes().to_vec())
            ]
        );
        let (_, data, orig, opts) = epb(&b[3].1);
        assert_eq!((data.len(), orig), (30, 1500));
        assert_eq!(opts, vec![(EPB_FLAGS, 1u32.to_le_bytes().to_vec())]);
    }

    #[test]
    fn classic_pcap() {
        let h = pcap_global_header(65535);
        assert_eq!(&h[0..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
        assert_eq!(u32::from_le_bytes(h[20..24].try_into().unwrap()), 101);
        let r = pcap_record(3_000_001, 100, &[1, 2, 3]);
        assert_eq!(&r[0..4], &3u32.to_le_bytes());
        assert_eq!(&r[4..8], &1u32.to_le_bytes());
        assert_eq!(&r[8..12], &3u32.to_le_bytes());
        assert_eq!(&r[12..16], &100u32.to_le_bytes());
        assert_eq!(&r[16..], &[1, 2, 3]);
    }

    #[test]
    fn keys_of_truncated_packets() {
        let syn = packet::build_tcp(
            "[fd76:6967:696c::1]:40001".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
            1,
            0,
            packet::TCP_SYN,
            &[],
        )
        .unwrap();
        let k = packet_key(&syn[..54]).unwrap();
        assert_eq!(k.proto, packet::PROTO_TCP);
        assert_eq!(k.dst, "[2001:db8::1]:443".parse().unwrap());
        assert!(k.initial_syn);
        // Cut before the flags: still keyed, not a SYN.
        assert!(!packet_key(&syn[..44]).unwrap().initial_syn);
        let udp = packet::build_udp(
            "10.0.0.2:5000".parse().unwrap(),
            "192.0.2.1:53".parse().unwrap(),
            &[0; 100],
        )
        .unwrap();
        let k = packet_key(&udp[..24]).unwrap();
        assert_eq!((k.src.port(), k.dst.port()), (5000, 53));
        assert!(packet_key(&udp[..22]).is_none());
        assert!(packet_key(&[0x45]).is_none());
        assert!(packet_key(&[]).is_none());
    }
}
