//! QUIC Initial packet decryption (RFC 9001 §5, RFC 9369) to recover the TLS
//! ClientHello — and therefore the SNI — of HTTP/3 connections.
//!
//! Initial packets are encrypted, but with keys derived from the client's
//! Destination Connection ID, which travels in clear text. Any on-path
//! observer can therefore decrypt them; no secrets are involved.
//!
//! Modern clients split the ClientHello over several Initial packets and
//! shuffle CRYPTO frames, so [`QuicSniffer`] reassembles the CRYPTO stream by
//! offset across datagrams.

use super::tls::{self, ClientHello, Sniff};
use super::Reader;
use aes::cipher::{generic_array::GenericArray, BlockEncrypt};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::BTreeMap;

pub const VERSION_1: u32 = 0x0000_0001;
pub const VERSION_2: u32 = 0x6b33_43cf;

const SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

/// Maximum number of Initial datagrams we inspect per flow before giving up.
pub const MAX_SNIFF_DATAGRAMS: usize = 6;
const MAX_CRYPTO_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialKeys {
    pub key: [u8; 16],
    pub iv: [u8; 12],
    pub hp: [u8; 16],
}

fn hkdf_expand_label(prk: &Hkdf<Sha256>, label: &str, out: &mut [u8]) {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(4 + full.len());
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(0);
    prk.expand(&info, out).expect("valid HKDF output length");
}

/// Derives the client Initial keys for `version` and `dcid`.
pub fn client_initial_keys(version: u32, dcid: &[u8]) -> Option<InitialKeys> {
    let (salt, prefix) = match version {
        VERSION_1 => (&SALT_V1, "quic"),
        VERSION_2 => (&SALT_V2, "quicv2"),
        _ => return None,
    };
    let (_, initial) = Hkdf::<Sha256>::extract(Some(salt), dcid);
    let mut client_secret = [0u8; 32];
    hkdf_expand_label(&initial, "client in", &mut client_secret);
    let client = Hkdf::<Sha256>::from_prk(&client_secret).ok()?;
    let mut keys = InitialKeys {
        key: [0; 16],
        iv: [0; 12],
        hp: [0; 16],
    };
    hkdf_expand_label(&client, &format!("{prefix} key"), &mut keys.key);
    hkdf_expand_label(&client, &format!("{prefix} iv"), &mut keys.iv);
    hkdf_expand_label(&client, &format!("{prefix} hp"), &mut keys.hp);
    Some(keys)
}

fn is_initial_type(first: u8, version: u32) -> bool {
    let ptype = (first >> 4) & 0x03;
    match version {
        VERSION_1 => ptype == 0,
        VERSION_2 => ptype == 1,
        _ => false,
    }
}

/// Cheap check: does this datagram start with a QUIC v1/v2 Initial packet?
pub fn looks_like_initial(d: &[u8]) -> bool {
    if d.len() < 7 || d[0] & 0xc0 != 0xc0 {
        return false;
    }
    let version = u32::from_be_bytes([d[1], d[2], d[3], d[4]]);
    is_initial_type(d[0], version)
}

fn header_protection_mask(hp: &[u8; 16], sample: &[u8]) -> [u8; 16] {
    let cipher = aes::Aes128::new(GenericArray::from_slice(hp));
    let mut block = GenericArray::clone_from_slice(sample);
    cipher.encrypt_block(&mut block);
    block.into()
}

fn nonce_for(iv: &[u8; 12], pn: u64) -> [u8; 12] {
    let mut n = *iv;
    for (i, b) in pn.to_be_bytes().iter().enumerate() {
        n[4 + i] ^= b;
    }
    n
}

/// Decrypts the first (Initial) packet of a datagram and returns its
/// plaintext frames payload.
pub fn decrypt_initial(datagram: &[u8]) -> Option<Vec<u8>> {
    if !looks_like_initial(datagram) {
        return None;
    }
    let mut r = Reader::new(datagram);
    r.skip(1)?;
    let version = r.u32()?;
    let dcid = r.vec8()?;
    if dcid.len() > 20 {
        return None;
    }
    let scid = r.vec8()?;
    if scid.len() > 20 {
        return None;
    }
    let token_len = varint_usize(&mut r)?;
    r.skip(token_len)?;
    let length = varint_usize(&mut r)?;
    let pn_offset = r.pos();
    let end = pn_offset.checked_add(length)?;
    if end > datagram.len() || length < 20 {
        return None;
    }
    let keys = client_initial_keys(version, dcid)?;
    let sample = datagram.get(pn_offset + 4..pn_offset + 20)?;
    let mask = header_protection_mask(&keys.hp, sample);

    let mut header = datagram[..pn_offset + 4].to_vec();
    header[0] ^= mask[0] & 0x0f;
    let pn_len = (header[0] & 0x03) as usize + 1;
    let mut pn: u64 = 0;
    for i in 0..pn_len {
        header[pn_offset + i] ^= mask[1 + i];
        pn = (pn << 8) | header[pn_offset + i] as u64;
    }
    header.truncate(pn_offset + pn_len);
    let ciphertext = &datagram[pn_offset + pn_len..end];
    let cipher = Aes128Gcm::new_from_slice(&keys.key).ok()?;
    let nonce = nonce_for(&keys.iv, pn);
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &header,
            },
        )
        .ok()
}

/// A varint used as a length: `None` if it does not fit `usize` (a plain
/// cast would truncate on 32-bit targets such as armv7).
fn varint_usize(r: &mut Reader) -> Option<usize> {
    usize::try_from(r.varint()?).ok()
}

/// Walks QUIC frames and yields `(offset, data)` for every CRYPTO frame.
fn crypto_frames(plain: &[u8]) -> Vec<(u64, &[u8])> {
    let mut out = Vec::new();
    let mut r = Reader::new(plain);
    while !r.is_empty() {
        let Some(ftype) = r.varint() else { break };
        match ftype {
            0x00 | 0x01 => {}
            0x02 | 0x03 => {
                let ok = (|| {
                    r.varint()?;
                    r.varint()?;
                    let ranges = r.varint()?;
                    r.varint()?;
                    for _ in 0..ranges.min(1024) {
                        r.varint()?;
                        r.varint()?;
                    }
                    if ftype == 0x03 {
                        r.varint()?;
                        r.varint()?;
                        r.varint()?;
                    }
                    Some(())
                })();
                if ok.is_none() {
                    break;
                }
            }
            0x06 => {
                let (Some(off), Some(len)) = (r.varint(), varint_usize(&mut r)) else {
                    break;
                };
                let Some(data) = r.bytes(len) else {
                    break;
                };
                out.push((off, data));
            }
            0x1c => {
                let _ = (r.varint(), r.varint());
                let Some(n) = varint_usize(&mut r) else {
                    break;
                };
                if r.skip(n).is_none() {
                    break;
                }
            }
            _ => break,
        }
    }
    out
}

/// Per-flow CRYPTO stream reassembler.
#[derive(Default)]
pub struct QuicSniffer {
    chunks: BTreeMap<u64, Vec<u8>>,
    datagrams: usize,
    done: bool,
}

impl QuicSniffer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds one client→server datagram. Returns `NotMatched` once it is
    /// clear no ClientHello will be recovered.
    pub fn feed(&mut self, datagram: &[u8]) -> Sniff<ClientHello> {
        if self.done {
            return Sniff::NotMatched;
        }
        self.datagrams += 1;
        let Some(plain) = decrypt_initial(datagram) else {
            return self.give_up_if_exhausted(self.datagrams == 1);
        };
        for (off, data) in crypto_frames(&plain) {
            if off + data.len() as u64 > MAX_CRYPTO_BYTES {
                continue;
            }
            let slot = self.chunks.entry(off).or_default();
            if data.len() > slot.len() {
                *slot = data.to_vec();
            }
        }
        let stream = self.contiguous_prefix();
        match tls::parse_handshake(&stream) {
            Sniff::Found(ch) => {
                self.done = true;
                Sniff::Found(ch)
            }
            Sniff::NotMatched if !stream.is_empty() => {
                self.done = true;
                Sniff::NotMatched
            }
            _ => self.give_up_if_exhausted(false),
        }
    }

    fn give_up_if_exhausted(&mut self, now: bool) -> Sniff<ClientHello> {
        if now || self.datagrams >= MAX_SNIFF_DATAGRAMS {
            self.done = true;
            Sniff::NotMatched
        } else {
            Sniff::NeedMore
        }
    }

    fn contiguous_prefix(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        for (&off, data) in &self.chunks {
            let have = out.len() as u64;
            if off > have {
                break;
            }
            let skip = (have - off) as usize;
            if skip < data.len() {
                out.extend_from_slice(&data[skip..]);
            }
        }
        out
    }
}

/// Test/tooling helper: builds a protected client Initial packet carrying the
/// given CRYPTO frames, padded to 1200 bytes as clients do.
#[doc(hidden)]
pub fn seal_initial(version: u32, dcid: &[u8], pn: u32, frames: &[(u64, &[u8])]) -> Vec<u8> {
    let keys = client_initial_keys(version, dcid).expect("supported version");
    let mut payload = Vec::new();
    for (off, data) in frames {
        payload.push(0x06);
        push_varint(&mut payload, *off);
        push_varint(&mut payload, data.len() as u64);
        payload.extend_from_slice(data);
    }
    let pn_len = 4usize;
    let type_bits = if version == VERSION_2 { 0x10 } else { 0x00 };
    let mut header = vec![0xc0 | type_bits | (pn_len as u8 - 1)];
    header.extend_from_slice(&version.to_be_bytes());
    header.push(dcid.len() as u8);
    header.extend_from_slice(dcid);
    header.push(0); // empty SCID
    header.push(0); // no token
    let min_payload = 1200usize.saturating_sub(header.len() + 2 + pn_len + 16);
    if payload.len() < min_payload {
        payload.resize(min_payload, 0); // PADDING frames
    }
    let length = pn_len + payload.len() + 16;
    header.push(0x40 | (length >> 8) as u8);
    header.push(length as u8);
    let pn_offset = header.len();
    header.extend_from_slice(&pn.to_be_bytes());
    let cipher = Aes128Gcm::new_from_slice(&keys.key).unwrap();
    let nonce = nonce_for(&keys.iv, pn as u64);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &payload,
                aad: &header,
            },
        )
        .unwrap();
    let mut pkt = header;
    pkt.extend_from_slice(&ct);
    let mask = header_protection_mask(&keys.hp, &pkt[pn_offset + 4..pn_offset + 20]);
    pkt[0] ^= mask[0] & 0x0f;
    for i in 0..pn_len {
        pkt[pn_offset + i] ^= mask[1 + i];
    }
    pkt
}

fn push_varint(out: &mut Vec<u8>, v: u64) {
    if v < 0x40 {
        out.push(v as u8);
    } else if v < 0x4000 {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else {
        out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc9001_appendix_a1_keys() {
        let k = client_initial_keys(VERSION_1, &hex("8394c8f03e515708")).unwrap();
        assert_eq!(k.key.to_vec(), hex("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(k.iv.to_vec(), hex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(k.hp.to_vec(), hex("9f50449e04a0e810283a1e9933adedd2"));
    }

    #[test]
    fn rfc9369_appendix_a1_keys() {
        let k = client_initial_keys(VERSION_2, &hex("8394c8f03e515708")).unwrap();
        assert_eq!(k.key.to_vec(), hex("8b1a0bc121284290a29e0971b5cd045d"));
        assert_eq!(k.iv.to_vec(), hex("91f73e2351d8fa91660e909f"));
        assert_eq!(k.hp.to_vec(), hex("45b95e15235d6f45a6b19cbcb0294ba9"));
    }

    #[test]
    fn recovers_sni_from_single_initial() {
        for version in [VERSION_1, VERSION_2] {
            let hello = tls::build_client_hello(Some("quic.example.com"), &["h3"], 0);
            let pkt = seal_initial(version, &[1, 2, 3, 4, 5, 6, 7, 8], 0, &[(0, &hello)]);
            assert!(looks_like_initial(&pkt));
            let mut s = QuicSniffer::new();
            let Sniff::Found(ch) = s.feed(&pkt) else {
                panic!("version {version:#x}")
            };
            assert_eq!(ch.sni.as_deref(), Some("quic.example.com"));
            assert!(ch.ja4('q').starts_with("q13d"));
        }
    }

    #[test]
    fn reassembles_shuffled_crypto_across_datagrams() {
        let hello = tls::build_client_hello(Some("split.example.net"), &["h3"], 1500);
        let (a, rest) = hello.split_at(400);
        let (b, c) = rest.split_at(700);
        let dcid = [9u8; 8];
        // Datagram 1 carries the *tail* and the head out of order; datagram 2 the middle.
        let d1 = seal_initial(VERSION_1, &dcid, 0, &[(1100, c), (0, a)]);
        let d2 = seal_initial(VERSION_1, &dcid, 1, &[(400, b)]);
        let mut s = QuicSniffer::new();
        assert_eq!(s.feed(&d1), Sniff::NeedMore);
        let Sniff::Found(ch) = s.feed(&d2) else {
            panic!()
        };
        assert_eq!(ch.sni.as_deref(), Some("split.example.net"));
    }

    #[test]
    fn ignores_non_quic() {
        let mut s = QuicSniffer::new();
        assert_eq!(s.feed(b"\x00\x01garbage-datagram"), Sniff::NotMatched);
        assert!(!looks_like_initial(&[0x40, 1, 2, 3, 4, 5, 6, 7]));
    }

    #[test]
    fn oversized_varint_lengths_are_rejected() {
        // 8-byte varint 2^32 + 4: a truncating cast on 32-bit made it 4.
        let huge = [0xc0, 0, 0, 0x01, 0, 0, 0, 0x04];
        let fits = usize::try_from((1u64 << 32) + 4).ok();
        assert_eq!(varint_usize(&mut Reader::new(&huge)), fits);
        let mut frame = vec![0x06, 0x00];
        frame.extend_from_slice(&huge);
        frame.extend_from_slice(b"abcd");
        assert!(crypto_frames(&frame).is_empty());
        let mut frame = vec![0x1c, 0x00, 0x00];
        frame.extend_from_slice(&huge);
        frame.extend_from_slice(&[0x06, 0x00, 0x01, b'z']);
        assert!(crypto_frames(&frame).is_empty());
        // An Initial whose token length overflows is dropped, not misparsed.
        let hello = tls::build_client_hello(Some("x.example"), &[], 0);
        let pkt = seal_initial(VERSION_1, &[1; 8], 0, &[(0, &hello)]);
        let token_at = 1 + 4 + 1 + 8 + 1;
        assert_eq!(pkt[token_at], 0, "empty token");
        let mut bad = pkt[..token_at].to_vec();
        bad.extend_from_slice(&huge);
        bad.extend_from_slice(&pkt[token_at + 1..]);
        assert!(decrypt_initial(&bad).is_none());
        assert!(decrypt_initial(&pkt).is_some());
    }

    #[test]
    fn corrupted_packets_do_not_panic() {
        let hello = tls::build_client_hello(Some("x.example"), &[], 0);
        let pkt = seal_initial(VERSION_1, &[1; 8], 0, &[(0, &hello)]);
        for i in 0..pkt.len().min(80) {
            let mut m = pkt.clone();
            m[i] ^= 0x5a;
            let _ = decrypt_initial(&m);
            let _ = QuicSniffer::new().feed(&m[..i]);
        }
    }
}
