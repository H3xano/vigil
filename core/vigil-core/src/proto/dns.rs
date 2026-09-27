//! RFC 1035 DNS message parsing and synthesis of sinkhole responses.

use super::Reader;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_MX: u16 = 15;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_SVCB: u16 = 64;
pub const TYPE_HTTPS: u16 = 65;
pub const TYPE_ANY: u16 = 255;

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;

const HEADER_LEN: usize = 12;
const MAX_POINTER_JUMPS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    /// Addresses advertised through SVCB/HTTPS `ipv4hint`/`ipv6hint`.
    Hints(Vec<IpAddr>),
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub data: RData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub truncated: bool,
    pub rcode: u8,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
}

impl Message {
    pub fn first_question(&self) -> Option<&Question> {
        self.questions.first()
    }

    /// All IP addresses carried in the answer section (A, AAAA and
    /// SVCB/HTTPS address hints).
    pub fn answer_ips(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.answers.iter().flat_map(|r| match &r.data {
            RData::A(a) => vec![IpAddr::V4(*a)],
            RData::Aaaa(a) => vec![IpAddr::V6(*a)],
            RData::Hints(h) => h.clone(),
            _ => Vec::new(),
        })
    }

    /// Minimum TTL across address answers, used to bound cache lifetimes.
    pub fn min_ttl(&self) -> Option<u32> {
        self.answers
            .iter()
            .filter(|r| matches!(r.data, RData::A(_) | RData::Aaaa(_) | RData::Hints(_)))
            .map(|r| r.ttl)
            .min()
    }
}

pub fn qtype_name(t: u16) -> String {
    match t {
        TYPE_A => "A".into(),
        TYPE_NS => "NS".into(),
        TYPE_CNAME => "CNAME".into(),
        TYPE_SOA => "SOA".into(),
        TYPE_PTR => "PTR".into(),
        TYPE_MX => "MX".into(),
        TYPE_TXT => "TXT".into(),
        TYPE_AAAA => "AAAA".into(),
        TYPE_SRV => "SRV".into(),
        TYPE_SVCB => "SVCB".into(),
        TYPE_HTTPS => "HTTPS".into(),
        TYPE_ANY => "ANY".into(),
        other => format!("TYPE{other}"),
    }
}

pub fn rcode_name(r: u8) -> &'static str {
    match r {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "OTHER",
    }
}

/// Reads a possibly-compressed domain name starting at the reader position.
/// The reader is advanced past the name as it appears in-line (i.e. just past
/// the first compression pointer, if any).
fn read_name(msg: &[u8], r: &mut Reader<'_>) -> Option<String> {
    let mut out = String::new();
    let mut pos = r.pos();
    let mut jumped = false;
    let mut jumps = 0;
    loop {
        let len = *msg.get(pos)? as usize;
        match len & 0xc0 {
            0x00 => {
                pos += 1;
                if len == 0 {
                    if !jumped {
                        r.skip(pos - r.pos())?;
                    }
                    break;
                }
                let label = msg.get(pos..pos + len)?;
                if !out.is_empty() {
                    out.push('.');
                }
                for &b in label {
                    let c = b.to_ascii_lowercase();
                    if c.is_ascii_graphic() && c != b'.' {
                        out.push(c as char);
                    } else {
                        // Escape unprintable bytes rather than dropping them so
                        // distinct names never collide.
                        out.push_str(&format!("\\{b:03}"));
                    }
                }
                if out.len() > 1024 {
                    return None;
                }
                pos += len;
            }
            0xc0 => {
                let ptr = (u16::from_be_bytes([*msg.get(pos)?, *msg.get(pos + 1)?]) & 0x3fff) as usize;
                if !jumped {
                    r.skip(pos + 2 - r.pos())?;
                    jumped = true;
                }
                jumps += 1;
                if jumps > MAX_POINTER_JUMPS || ptr >= msg.len() {
                    return None;
                }
                pos = ptr;
            }
            _ => return None,
        }
    }
    Some(out)
}

fn parse_svcb_hints(rdata: &[u8], msg: &[u8], rdata_offset: usize) -> Option<Vec<IpAddr>> {
    let mut r = Reader::new(msg);
    r.skip(rdata_offset)?;
    let end = rdata_offset + rdata.len();
    let _priority = r.u16()?;
    read_name(msg, &mut r)?;
    let mut out = Vec::new();
    while r.pos() + 4 <= end {
        let key = r.u16()?;
        let val = r.vec16()?;
        match key {
            4 => out.extend(val.chunks_exact(4).map(|c| IpAddr::V4(Ipv4Addr::new(c[0], c[1], c[2], c[3])))),
            6 => out.extend(val.chunks_exact(16).map(|c| {
                let mut a = [0u8; 16];
                a.copy_from_slice(c);
                IpAddr::V6(Ipv6Addr::from(a))
            })),
            _ => {}
        }
    }
    Some(out)
}

pub fn parse(msg: &[u8]) -> Option<Message> {
    let mut r = Reader::new(msg);
    let id = r.u16()?;
    let flags = r.u16()?;
    let qd = r.u16()?;
    let an = r.u16()?;
    let _ns = r.u16()?;
    let _ar = r.u16()?;
    if qd > 32 {
        return None;
    }
    let mut questions = Vec::with_capacity(qd as usize);
    for _ in 0..qd {
        let name = read_name(msg, &mut r)?;
        let qtype = r.u16()?;
        let qclass = r.u16()?;
        questions.push(Question { name, qtype, qclass });
    }
    let mut answers = Vec::new();
    for _ in 0..an.min(256) {
        let Some(name) = read_name(msg, &mut r) else { break };
        let (Some(rtype), Some(_class), Some(ttl), Some(rdlen)) = (r.u16(), r.u16(), r.u32(), r.u16()) else {
            break;
        };
        let rdata_offset = r.pos();
        let Some(rdata) = r.bytes(rdlen as usize) else { break };
        let data = match (rtype, rdata.len()) {
            (TYPE_A, 4) => RData::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
            (TYPE_AAAA, 16) => {
                let mut a = [0u8; 16];
                a.copy_from_slice(rdata);
                RData::Aaaa(Ipv6Addr::from(a))
            }
            (TYPE_CNAME, _) => {
                let mut rr = Reader::new(msg);
                rr.skip(rdata_offset)?;
                read_name(msg, &mut rr).map(RData::Cname).unwrap_or(RData::Other)
            }
            (TYPE_HTTPS | TYPE_SVCB, _) => parse_svcb_hints(rdata, msg, rdata_offset)
                .filter(|h| !h.is_empty())
                .map(RData::Hints)
                .unwrap_or(RData::Other),
            _ => RData::Other,
        };
        answers.push(Record { name, rtype, ttl, data });
    }
    Some(Message {
        id,
        is_response: flags & 0x8000 != 0,
        opcode: ((flags >> 11) & 0x0f) as u8,
        truncated: flags & 0x0200 != 0,
        rcode: (flags & 0x000f) as u8,
        questions,
        answers,
    })
}

/// How blocked names are answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SinkholeMode {
    /// `A 0.0.0.0` / `AAAA ::` for address queries, empty NOERROR otherwise.
    /// Apps fail fast without retrying other resolvers.
    #[default]
    NullIp,
    /// NXDOMAIN for every query type.
    Nxdomain,
}

/// Returns the byte range of the header + first question of a query.
fn first_question_span(query: &[u8]) -> Option<(usize, u16)> {
    let mut r = Reader::new(query);
    r.skip(4)?;
    let qd = r.u16()?;
    if qd == 0 {
        return None;
    }
    r.skip(6)?;
    read_name(query, &mut r)?;
    let qtype = r.u16()?;
    r.skip(2)?;
    Some((r.pos(), qtype))
}

fn response_header(query: &[u8], rcode: u8, ancount: u16) -> Option<Vec<u8>> {
    if query.len() < HEADER_LEN {
        return None;
    }
    let qflags = u16::from_be_bytes([query[2], query[3]]);
    // QR=1, keep opcode and RD, RA=1, AA=0, TC=0.
    let flags = 0x8000 | (qflags & 0x7800) | (qflags & 0x0100) | 0x0080 | rcode as u16;
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(&query[0..2]);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&ancount.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    Some(out)
}

/// Builds a sinkhole answer for `query`.
pub fn sinkhole_response(query: &[u8], mode: SinkholeMode, ttl: u32) -> Option<Vec<u8>> {
    let (qend, qtype) = first_question_span(query)?;
    let (rcode, answer): (u8, Option<(u16, &[u8])>) = match mode {
        SinkholeMode::Nxdomain => (RCODE_NXDOMAIN, None),
        SinkholeMode::NullIp => match qtype {
            TYPE_A => (RCODE_NOERROR, Some((TYPE_A, &[0u8; 4][..]))),
            TYPE_AAAA => (RCODE_NOERROR, Some((TYPE_AAAA, &[0u8; 16][..]))),
            _ => (RCODE_NOERROR, None),
        },
    };
    let mut out = response_header(query, rcode, answer.is_some() as u16)?;
    out.extend_from_slice(&query[HEADER_LEN..qend]);
    if let Some((rtype, rdata)) = answer {
        out.extend_from_slice(&[0xc0, 0x0c]);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
    }
    Some(out)
}

/// Builds a SERVFAIL answer, used when every upstream resolver failed.
pub fn servfail_response(query: &[u8]) -> Option<Vec<u8>> {
    let (qend, _) = first_question_span(query)?;
    let mut out = response_header(query, RCODE_SERVFAIL, 0)?;
    out.extend_from_slice(&query[HEADER_LEN..qend]);
    Some(out)
}

/// Encodes a standard recursive query. Used by tests and the CLI.
pub fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_query() {
        let q = build_query(0xbeef, "Tracker.Example.com", TYPE_AAAA);
        let m = parse(&q).unwrap();
        assert_eq!(m.id, 0xbeef);
        assert!(!m.is_response);
        assert_eq!(m.questions[0].name, "tracker.example.com");
        assert_eq!(m.questions[0].qtype, TYPE_AAAA);
    }

    #[test]
    fn parses_compressed_response_with_cname_chain() {
        // Response for www.example.com: CNAME -> edge.example.net, A 93.184.216.34
        let mut m = build_query(7, "www.example.com", TYPE_A);
        m[2] = 0x81;
        m[3] = 0x80;
        m[7] = 2; // ancount
        // answer 1: www.example.com CNAME edge.example.net
        m.extend_from_slice(&[0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60]);
        let cname: Vec<u8> = [&[4u8][..], b"edge", &[7], b"example", &[3], b"net", &[0]].concat();
        m.extend_from_slice(&(cname.len() as u16).to_be_bytes());
        let cname_off = m.len();
        m.extend_from_slice(&cname);
        // answer 2: edge.example.net A 93.184.216.34 (name is a pointer to the cname rdata)
        m.extend_from_slice(&[0xc0 | (cname_off >> 8) as u8, cname_off as u8, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 93, 184, 216, 34]);
        let p = parse(&m).unwrap();
        assert!(p.is_response);
        assert_eq!(p.answers.len(), 2);
        assert_eq!(p.answers[0].data, RData::Cname("edge.example.net".into()));
        assert_eq!(p.answers[1].name, "edge.example.net");
        assert_eq!(p.answer_ips().collect::<Vec<_>>(), vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
        assert_eq!(p.min_ttl(), Some(30));
    }

    #[test]
    fn rejects_pointer_loops() {
        let mut m = build_query(1, "a.b", TYPE_A);
        m[5] = 1;
        m.truncate(12);
        m.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        assert!(parse(&m).is_none());
    }

    #[test]
    fn sinkhole_null_ip() {
        let q = build_query(42, "ads.example.com", TYPE_A);
        let r = sinkhole_response(&q, SinkholeMode::NullIp, 60).unwrap();
        let p = parse(&r).unwrap();
        assert_eq!(p.id, 42);
        assert!(p.is_response);
        assert_eq!(p.rcode, RCODE_NOERROR);
        assert_eq!(p.answers[0].data, RData::A(Ipv4Addr::UNSPECIFIED));
        let q6 = build_query(43, "ads.example.com", TYPE_AAAA);
        let p6 = parse(&sinkhole_response(&q6, SinkholeMode::NullIp, 60).unwrap()).unwrap();
        assert_eq!(p6.answers[0].data, RData::Aaaa(Ipv6Addr::UNSPECIFIED));
        let qh = build_query(44, "ads.example.com", TYPE_HTTPS);
        let ph = parse(&sinkhole_response(&qh, SinkholeMode::NullIp, 60).unwrap()).unwrap();
        assert!(ph.answers.is_empty());
        assert_eq!(ph.rcode, RCODE_NOERROR);
    }

    #[test]
    fn sinkhole_nxdomain_and_servfail() {
        let q = build_query(9, "c2.bad.example", TYPE_A);
        let p = parse(&sinkhole_response(&q, SinkholeMode::Nxdomain, 60).unwrap()).unwrap();
        assert_eq!(p.rcode, RCODE_NXDOMAIN);
        assert_eq!(p.questions[0].name, "c2.bad.example");
        let s = parse(&servfail_response(&q).unwrap()).unwrap();
        assert_eq!(s.rcode, RCODE_SERVFAIL);
    }

    #[test]
    fn never_panics_on_garbage() {
        let mut seed: u32 = 0x1234_5678;
        for len in 0..600 {
            let buf: Vec<u8> = (0..len)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    seed as u8
                })
                .collect();
            let _ = parse(&buf);
            let _ = sinkhole_response(&buf, SinkholeMode::NullIp, 1);
        }
    }
}
