//! Wire-protocol parsers. Everything here is pure (no I/O), bounds-checked and
//! operates on borrowed byte slices so it can be fuzzed and unit tested on the
//! host.

pub mod dns;
pub mod http;
pub mod quic;
pub mod tls;

/// Minimal bounds-checked big-endian reader over a byte slice.
#[derive(Clone)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn u8(&mut self) -> Option<u8> {
        let v = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }

    pub fn u16(&mut self) -> Option<u16> {
        let b = self.bytes(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u24(&mut self) -> Option<u32> {
        let b = self.bytes(3)?;
        Some(u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }

    pub fn u32(&mut self) -> Option<u32> {
        let b = self.bytes(4)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    pub fn skip(&mut self, n: usize) -> Option<()> {
        self.bytes(n).map(|_| ())
    }

    /// Reads a u8-length-prefixed vector.
    pub fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()? as usize;
        self.bytes(n)
    }

    /// Reads a u16-length-prefixed vector.
    pub fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()? as usize;
        self.bytes(n)
    }

    /// QUIC variable-length integer (RFC 9000 §16).
    pub fn varint(&mut self) -> Option<u64> {
        let first = self.u8()?;
        let len = 1usize << (first >> 6);
        let mut v = (first & 0x3f) as u64;
        for _ in 1..len {
            v = (v << 8) | self.u8()? as u64;
        }
        Some(v)
    }
}

/// Normalises a hostname for matching: lowercase ASCII, no trailing dot.
/// Returns `None` if the name is empty or contains bytes that cannot appear in
/// a DNS hostname presentation form we care about.
pub fn normalize_host(raw: &str) -> Option<String> {
    let s = raw.trim().trim_end_matches('.');
    if s.is_empty() || s.len() > 253 {
        return None;
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            'A'..='Z' => out.push(c.to_ascii_lowercase()),
            'a'..='z' | '0'..='9' | '-' | '.' | '_' | '*' => out.push(c),
            _ => return None,
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_decoding() {
        // RFC 9000 appendix A.1 examples.
        let cases: &[(&[u8], u64)] = &[
            (
                &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
                151_288_809_941_952_652,
            ),
            (&[0x9d, 0x7f, 0x3e, 0x7d], 494_878_333),
            (&[0x7b, 0xbd], 15_293),
            (&[0x25], 37),
            (&[0x40, 0x25], 37),
        ];
        for (bytes, want) in cases {
            assert_eq!(Reader::new(bytes).varint(), Some(*want));
        }
        assert_eq!(Reader::new(&[0x40]).varint(), None);
    }

    #[test]
    fn host_normalisation() {
        assert_eq!(
            normalize_host("WWW.Example.COM.").as_deref(),
            Some("www.example.com")
        );
        assert_eq!(normalize_host(""), None);
        assert_eq!(normalize_host("bad host"), None);
    }
}
