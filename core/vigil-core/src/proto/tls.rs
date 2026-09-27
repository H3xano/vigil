//! TLS ClientHello extraction (SNI, ALPN, versions, ECH) and JA4 fingerprints.
//!
//! Two entry points:
//! * [`parse_records`] consumes the start of a TLS-over-TCP byte stream. A
//!   ClientHello frequently spans several TCP segments *and* several TLS
//!   records (post-quantum key shares push it past 1.7 KB), so callers keep
//!   feeding a growing buffer until the result is not [`Sniff::NeedMore`].
//! * [`parse_handshake`] consumes raw handshake bytes, as carried in QUIC
//!   CRYPTO frames (no record layer).

use super::Reader;
use sha2::{Digest, Sha256};

/// Upper bound on a ClientHello we are willing to buffer.
pub const MAX_HELLO_LEN: usize = 64 * 1024;

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_ECH: u16 = 0xfe0d;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sniff<T> {
    /// More bytes are required to reach a verdict.
    NeedMore,
    /// The data is definitely not what we were looking for.
    NotMatched,
    Found(T),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientHello {
    pub legacy_version: u16,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub supported_versions: Vec<u16>,
    pub ciphers: Vec<u16>,
    /// Extension types in wire order (GREASE included, as seen).
    pub extensions: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    /// An `encrypted_client_hello` extension was offered. When true the SNI
    /// above is the *outer* (public) name, not the real destination.
    pub ech: bool,
}

pub fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff)
}

fn version_code(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        0xfeff => "d1",
        0xfefd => "d2",
        0xfefc => "d3",
        _ => "00",
    }
}

pub fn version_name(v: u16) -> &'static str {
    match v {
        0x0304 => "TLS1.3",
        0x0303 => "TLS1.2",
        0x0302 => "TLS1.1",
        0x0301 => "TLS1.0",
        0x0300 => "SSL3",
        _ => "unknown",
    }
}

fn truncated_sha256(s: &str) -> String {
    if s.is_empty() {
        return "000000000000".into();
    }
    let digest = Sha256::digest(s.as_bytes());
    digest.iter().take(6).map(|b| format!("{b:02x}")).collect()
}

fn hex_list(items: impl Iterator<Item = u16>) -> String {
    items.map(|v| format!("{v:04x}")).collect::<Vec<_>>().join(",")
}

impl ClientHello {
    /// Highest non-GREASE version offered (supported_versions if present,
    /// otherwise the legacy record version).
    pub fn max_version(&self) -> u16 {
        self.supported_versions
            .iter()
            .copied()
            .filter(|v| !is_grease(*v))
            .max()
            .unwrap_or(self.legacy_version)
    }

    fn alpn_code(&self) -> String {
        let Some(first) = self.alpn.first().filter(|a| !a.is_empty()) else {
            return "00".into();
        };
        let bytes = first.as_bytes();
        let (f, l) = (bytes[0], bytes[bytes.len() - 1]);
        if f.is_ascii_alphanumeric() && l.is_ascii_alphanumeric() {
            format!("{}{}", f as char, l as char)
        } else {
            let fh = format!("{f:02x}");
            let lh = format!("{l:02x}");
            format!("{}{}", &fh[..1], &lh[1..])
        }
    }

    /// JA4 TLS client fingerprint (FoxIO JA4 specification).
    /// `transport` is `'t'` for TCP and `'q'` for QUIC.
    pub fn ja4(&self, transport: char) -> String {
        let ciphers: Vec<u16> = self.ciphers.iter().copied().filter(|c| !is_grease(*c)).collect();
        let exts: Vec<u16> = self.extensions.iter().copied().filter(|e| !is_grease(*e)).collect();
        let a = format!(
            "{}{}{}{:02}{:02}{}",
            transport,
            version_code(self.max_version()),
            if self.sni.is_some() { 'd' } else { 'i' },
            ciphers.len().min(99),
            exts.len().min(99),
            self.alpn_code()
        );
        let mut sorted_ciphers = ciphers.clone();
        sorted_ciphers.sort_unstable();
        let b = truncated_sha256(&hex_list(sorted_ciphers.into_iter()));

        let mut sorted_exts: Vec<u16> =
            exts.into_iter().filter(|e| *e != EXT_SERVER_NAME && *e != EXT_ALPN).collect();
        sorted_exts.sort_unstable();
        let c = if sorted_exts.is_empty() {
            "000000000000".to_string()
        } else {
            let mut s = hex_list(sorted_exts.into_iter());
            let sigs: Vec<u16> = self.signature_algorithms.iter().copied().filter(|v| !is_grease(*v)).collect();
            if !sigs.is_empty() {
                s.push('_');
                s.push_str(&hex_list(sigs.into_iter()));
            }
            truncated_sha256(&s)
        };
        format!("{a}_{b}_{c}")
    }
}

/// Parses the beginning of a TLS byte stream (record layer).
pub fn parse_records(stream: &[u8]) -> Sniff<ClientHello> {
    let mut handshake = Vec::new();
    let mut r = Reader::new(stream);
    loop {
        if r.remaining() < 5 {
            return if handshake.is_empty() && !plausible_record_prefix(&stream[r.pos()..]) {
                Sniff::NotMatched
            } else {
                Sniff::NeedMore
            };
        }
        let ctype = r.u8().unwrap();
        let major = r.u8().unwrap();
        let _minor = r.u8().unwrap();
        let len = r.u16().unwrap() as usize;
        if ctype != 0x16 || major != 3 || len == 0 || len > 16_384 + 2048 {
            return Sniff::NotMatched;
        }
        let Some(frag) = r.bytes(len) else {
            // Partial record: parse what we have so far only if it may already
            // contain the complete handshake message (it cannot, since the
            // record isn't complete), so ask for more.
            return if handshake.len() + r.remaining() > MAX_HELLO_LEN { Sniff::NotMatched } else { Sniff::NeedMore };
        };
        handshake.extend_from_slice(frag);
        match parse_handshake(&handshake) {
            Sniff::NeedMore if handshake.len() > MAX_HELLO_LEN => return Sniff::NotMatched,
            Sniff::NeedMore => continue,
            other => return other,
        }
    }
}

fn plausible_record_prefix(b: &[u8]) -> bool {
    match b {
        [] => true,
        [0x16] => true,
        [0x16, 3, ..] => true,
        _ => false,
    }
}

/// Parses a handshake message sequence that should start with a ClientHello.
pub fn parse_handshake(msg: &[u8]) -> Sniff<ClientHello> {
    let mut r = Reader::new(msg);
    let Some(htype) = r.u8() else { return Sniff::NeedMore };
    if htype != 0x01 {
        return Sniff::NotMatched;
    }
    let Some(len) = r.u24() else { return Sniff::NeedMore };
    let len = len as usize;
    if len > MAX_HELLO_LEN {
        return Sniff::NotMatched;
    }
    let Some(body) = r.bytes(len) else { return Sniff::NeedMore };
    match parse_client_hello_body(body) {
        Some(ch) => Sniff::Found(ch),
        None => Sniff::NotMatched,
    }
}

fn parse_client_hello_body(body: &[u8]) -> Option<ClientHello> {
    let mut r = Reader::new(body);
    let mut ch = ClientHello { legacy_version: r.u16()?, ..Default::default() };
    r.skip(32)?; // random
    r.vec8()?; // legacy_session_id
    let suites = r.vec16()?;
    ch.ciphers = suites.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
    r.vec8()?; // legacy_compression_methods
    if r.is_empty() {
        return Some(ch);
    }
    let mut ext = Reader::new(r.vec16()?);
    while !ext.is_empty() {
        let etype = ext.u16()?;
        let data = ext.vec16()?;
        ch.extensions.push(etype);
        let mut d = Reader::new(data);
        match etype {
            EXT_SERVER_NAME => {
                let mut list = Reader::new(d.vec16()?);
                while !list.is_empty() {
                    let name_type = list.u8()?;
                    let name = list.vec16()?;
                    if name_type == 0 && ch.sni.is_none() {
                        ch.sni = std::str::from_utf8(name).ok().and_then(super::normalize_host);
                    }
                }
            }
            EXT_ALPN => {
                let mut list = Reader::new(d.vec16()?);
                while !list.is_empty() {
                    let p = list.vec8()?;
                    ch.alpn.push(String::from_utf8_lossy(p).into_owned());
                }
            }
            EXT_SUPPORTED_VERSIONS => {
                let v = d.vec8()?;
                ch.supported_versions = v.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
            }
            EXT_SIGNATURE_ALGORITHMS => {
                let v = d.vec16()?;
                ch.signature_algorithms = v.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
            }
            EXT_ECH => ch.ech = true,
            _ => {}
        }
    }
    Some(ch)
}

/// Test helper: builds a ClientHello handshake message.
#[doc(hidden)]
pub fn build_client_hello(sni: Option<&str>, alpn: &[&str], extra_padding: usize) -> Vec<u8> {
    let mut exts = Vec::new();
    let mut push_ext = |t: u16, data: &[u8]| {
        exts.extend_from_slice(&t.to_be_bytes());
        exts.extend_from_slice(&(data.len() as u16).to_be_bytes());
        exts.extend_from_slice(data);
    };
    push_ext(0x0a0a, &[]); // GREASE
    if let Some(name) = sni {
        let mut entry = vec![0u8];
        entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
        entry.extend_from_slice(name.as_bytes());
        let mut list = (entry.len() as u16).to_be_bytes().to_vec();
        list.extend_from_slice(&entry);
        push_ext(EXT_SERVER_NAME, &list);
    }
    if !alpn.is_empty() {
        let mut inner = Vec::new();
        for p in alpn {
            inner.push(p.len() as u8);
            inner.extend_from_slice(p.as_bytes());
        }
        let mut list = (inner.len() as u16).to_be_bytes().to_vec();
        list.extend_from_slice(&inner);
        push_ext(EXT_ALPN, &list);
    }
    push_ext(EXT_SUPPORTED_VERSIONS, &[4, 0x0a, 0x0a, 0x03, 0x04]);
    push_ext(EXT_SIGNATURE_ALGORITHMS, &[0, 4, 0x04, 0x03, 0x08, 0x04]);
    push_ext(0x0015, &vec![0u8; extra_padding]); // padding extension
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[7u8; 32]);
    body.push(0);
    body.extend_from_slice(&[0, 6, 0x1a, 0x1a, 0x13, 0x01, 0x13, 0x02]);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);
    let mut msg = vec![0x01];
    msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    msg.extend_from_slice(&body);
    msg
}

/// Test helper: wraps handshake bytes into TLS records of at most `max_frag`.
#[doc(hidden)]
pub fn wrap_records(handshake: &[u8], max_frag: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in handshake.chunks(max_frag) {
        out.extend_from_slice(&[0x16, 0x03, 0x01]);
        out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        out.extend_from_slice(chunk);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_sni_alpn_and_versions() {
        let hs = build_client_hello(Some("Analytics.OEM.com"), &["h2", "http/1.1"], 0);
        let stream = wrap_records(&hs, 16384);
        let Sniff::Found(ch) = parse_records(&stream) else { panic!("not parsed") };
        assert_eq!(ch.sni.as_deref(), Some("analytics.oem.com"));
        assert_eq!(ch.alpn, vec!["h2", "http/1.1"]);
        assert_eq!(ch.max_version(), 0x0304);
        assert!(!ch.ech);
    }

    #[test]
    fn handles_hello_split_across_records_and_segments() {
        // A post-quantum sized hello (~1.9 KB) split into 3 records.
        let hs = build_client_hello(Some("pq.example.org"), &["h2"], 1800);
        let stream = wrap_records(&hs, 700);
        for cut in [0, 1, 5, 600, 705, 1500, stream.len() - 1] {
            assert_eq!(parse_records(&stream[..cut]), Sniff::NeedMore, "cut at {cut}");
        }
        let Sniff::Found(ch) = parse_records(&stream) else { panic!() };
        assert_eq!(ch.sni.as_deref(), Some("pq.example.org"));
    }

    #[test]
    fn rejects_non_tls() {
        assert_eq!(parse_records(b"GET / HTTP/1.1\r\n"), Sniff::NotMatched);
        assert_eq!(parse_records(b"SSH-2.0-OpenSSH"), Sniff::NotMatched);
        assert_eq!(parse_records(&[0x17, 3, 3, 0, 5, 1, 2, 3, 4, 5]), Sniff::NotMatched);
    }

    #[test]
    fn ja4_structure() {
        let hs = build_client_hello(Some("example.com"), &["h2"], 0);
        let Sniff::Found(ch) = parse_handshake(&hs) else { panic!() };
        let ja4 = ch.ja4('t');
        // 2 non-GREASE ciphers; SNI, ALPN, supported_versions, sig_algs, padding = 5 extensions.
        assert!(ja4.starts_with("t13d0205h2_"), "{ja4}");
        let parts: Vec<&str> = ja4.split('_').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[1], truncated_sha256("1301,1302"));
        assert_eq!(parts[2], truncated_sha256("000d,0015,002b_0403,0804"));
        let no_sni = build_client_hello(None, &[], 0);
        let Sniff::Found(ch) = parse_handshake(&no_sni) else { panic!() };
        assert!(ch.ja4('q').starts_with("q13i020300_"));
    }

    #[test]
    fn grease_detection() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x0a1a));
        assert!(!is_grease(0x1301));
    }

    #[test]
    fn never_panics_on_garbage() {
        let hs = build_client_hello(Some("x.example"), &["h2"], 64);
        let stream = wrap_records(&hs, 100);
        for i in 0..stream.len() {
            let mut m = stream.clone();
            m[i] ^= 0xff;
            let _ = parse_records(&m);
            let _ = parse_records(&m[..i]);
        }
    }
}
