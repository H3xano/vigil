//! DNS-over-HTTPS (RFC 8484) wire format over HTTP/1.1: the POST request and
//! an incremental parser for the response. Pure; the engine does the I/O.

/// Largest response head accepted.
pub const MAX_HEAD: usize = 16 * 1024;
/// Largest DNS message (and so response body) accepted.
pub const MAX_BODY: usize = 65_535;

pub const DNS_MESSAGE: &str = "application/dns-message";

/// Encodes a keep-alive `POST` of `body` (a DNS message) to `target` on
/// `authority` (the `Host` header).
pub fn build_post(authority: &str, target: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "POST {target} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: vigil\r\n\
         Content-Type: {DNS_MESSAGE}\r\nAccept: {DNS_MESSAGE}\r\n\
         Content-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHead {
    pub status: u16,
    pub content_length: Option<usize>,
    pub chunked: bool,
    /// The server will close the connection after this response.
    pub close: bool,
    pub content_type: Option<String>,
}

impl ResponseHead {
    /// Bodyless informational response (e.g. `100 Continue`), to be skipped.
    pub fn is_informational(&self) -> bool {
        (100..200).contains(&self.status)
    }
}

/// Parses a response head from the start of `buf`. `Ok(None)` means more
/// bytes are needed; `Ok(Some((head, len)))` gives the head's length.
pub fn parse_head(buf: &[u8]) -> Result<Option<(ResponseHead, usize)>, String> {
    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return if buf.len() > MAX_HEAD {
            Err("response head too large".into())
        } else {
            Ok(None)
        };
    };
    if end > MAX_HEAD {
        return Err("response head too large".into());
    }
    let text = std::str::from_utf8(&buf[..end]).map_err(|_| "response head is not UTF-8")?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(format!("not an HTTP/1.x response: {status_line:.40?}"));
    }
    let status = parts
        .next()
        .filter(|s| s.len() == 3)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("bad status line {status_line:.40?}"))?;
    let mut head = ResponseHead {
        status,
        content_length: None,
        chunked: false,
        close: version == "HTTP/1.0",
        content_type: None,
    };
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err("malformed header line".into());
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => {
                let n: usize = value.parse().map_err(|_| "bad Content-Length")?;
                if head.content_length.is_some_and(|m| m != n) {
                    return Err("conflicting Content-Length".into());
                }
                head.content_length = Some(n);
            }
            "transfer-encoding" => {
                let last = value.rsplit(',').next().unwrap_or_default().trim();
                if last.eq_ignore_ascii_case("chunked") {
                    head.chunked = true;
                } else {
                    return Err(format!("unsupported Transfer-Encoding {value:.40?}"));
                }
            }
            "connection" => {
                for tok in value.split(',') {
                    let tok = tok.trim();
                    if tok.eq_ignore_ascii_case("close") {
                        head.close = true;
                    } else if tok.eq_ignore_ascii_case("keep-alive") && version == "HTTP/1.0" {
                        head.close = false;
                    }
                }
            }
            "content-type" => {
                let media = value.split(';').next().unwrap_or_default().trim();
                head.content_type = Some(media.to_ascii_lowercase());
            }
            _ => {}
        }
    }
    if head.chunked {
        // RFC 9112 §6.3: Transfer-Encoding overrides Content-Length.
        head.content_length = None;
    }
    if head.content_length.is_some_and(|n| n > MAX_BODY) {
        return Err("response body too large".into());
    }
    Ok(Some((head, end + 4)))
}

/// Decodes a complete chunked body from the start of `buf` (after the head).
/// `Ok(None)` means more bytes are needed; otherwise returns the body and
/// the number of bytes consumed, trailers included.
pub fn decode_chunked(buf: &[u8]) -> Result<Option<(Vec<u8>, usize)>, String> {
    let mut body = Vec::new();
    let mut pos = 0;
    loop {
        let Some(eol) = find_crlf(&buf[pos..]) else {
            return if buf.len() - pos > 1024 {
                Err("chunk size line too long".into())
            } else {
                Ok(None)
            };
        };
        let line = std::str::from_utf8(&buf[pos..pos + eol]).map_err(|_| "bad chunk size")?;
        let size_hex = line.split(';').next().unwrap_or_default().trim();
        if size_hex.is_empty() || size_hex.len() > 8 {
            return Err("bad chunk size".into());
        }
        let size = usize::from_str_radix(size_hex, 16).map_err(|_| "bad chunk size")?;
        pos += eol + 2;
        if size == 0 {
            // Trailer section: header lines up to an empty line.
            loop {
                let Some(eol) = find_crlf(&buf[pos..]) else {
                    return if buf.len() - pos > MAX_HEAD {
                        Err("trailers too large".into())
                    } else {
                        Ok(None)
                    };
                };
                pos += eol + 2;
                if eol == 0 {
                    return Ok(Some((body, pos)));
                }
            }
        }
        if body.len() + size > MAX_BODY {
            return Err("response body too large".into());
        }
        if buf.len() < pos + size + 2 {
            return Ok(None);
        }
        body.extend_from_slice(&buf[pos..pos + size]);
        if &buf[pos + size..pos + size + 2] != b"\r\n" {
            return Err("chunk not terminated by CRLF".into());
        }
        pos += size + 2;
    }
}

fn find_crlf(b: &[u8]) -> Option<usize> {
    b.windows(2).position(|w| w == b"\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_request_encoding() {
        let req = build_post("dns.example:8443", "/dns-query", &[1, 2, 3]);
        let text = String::from_utf8_lossy(&req);
        assert!(text.starts_with("POST /dns-query HTTP/1.1\r\nHost: dns.example:8443\r\n"));
        assert!(text.contains("\r\nContent-Type: application/dns-message\r\n"));
        assert!(text.contains("\r\nAccept: application/dns-message\r\n"));
        assert!(text.contains("\r\nContent-Length: 3\r\n\r\n"));
        assert!(req.ends_with(b"\r\n\r\n\x01\x02\x03"));
    }

    #[test]
    fn head_parsing() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message; charset=x\r\n\
                    content-length: 42\r\nCache-Control: max-age=60\r\n\r\nBODY";
        let (h, n) = parse_head(raw).unwrap().unwrap();
        assert_eq!(n, raw.len() - 4);
        assert_eq!(h.status, 200);
        assert_eq!(h.content_length, Some(42));
        assert!(!h.chunked && !h.close);
        assert_eq!(h.content_type.as_deref(), Some(DNS_MESSAGE));
        // Incomplete heads wait for more data.
        assert_eq!(parse_head(&raw[..20]).unwrap(), None);
        let (h, _) = parse_head(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(h.status, 400);
        assert!(h.close);
        let (h, _) = parse_head(b"HTTP/1.0 200 OK\r\n\r\n").unwrap().unwrap();
        assert!(h.close, "HTTP/1.0 closes by default");
        let (h, _) = parse_head(b"HTTP/1.1 100 Continue\r\n\r\n")
            .unwrap()
            .unwrap();
        assert!(h.is_informational());
        let (h, _) = parse_head(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n",
        )
        .unwrap()
        .unwrap();
        assert!(h.chunked);
        assert_eq!(h.content_length, None);
    }

    #[test]
    fn bad_heads_rejected() {
        for raw in [
            &b"SSH-2.0-OpenSSH\r\n\r\n"[..],
            b"HTTP/1.1 2x0 OK\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nno colon\r\n\r\n",
        ] {
            assert!(
                parse_head(raw).is_err(),
                "{:?}",
                String::from_utf8_lossy(raw)
            );
        }
        assert!(parse_head(&vec![b'a'; MAX_HEAD + 1]).is_err());
    }

    #[test]
    fn chunked_bodies() {
        let raw = b"4\r\nabcd\r\n3;ext=1\r\nefg\r\n0\r\nX-Trailer: 1\r\n\r\nNEXT";
        let (body, used) = decode_chunked(raw).unwrap().unwrap();
        assert_eq!(body, b"abcdefg");
        assert_eq!(&raw[used..], b"NEXT");
        for cut in 0..raw.len() - 4 {
            assert_eq!(decode_chunked(&raw[..cut]).unwrap(), None, "cut {cut}");
        }
        assert!(decode_chunked(b"zz\r\n").is_err());
        assert!(decode_chunked(b"2\r\nabX\r\n").is_err());
        assert!(decode_chunked(b"10000\r\n").is_err());
    }

    #[test]
    fn garbage_never_panics() {
        const ALPHABET: &[u8] = b"HTP/1.0 2\r\n:;chunkedx0a";
        let mut seed = 7u32;
        for _ in 0..2000 {
            let len = (seed % 300) as usize;
            let buf: Vec<u8> = (0..len)
                .map(|_| {
                    seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
                    ALPHABET[(seed >> 16) as usize % ALPHABET.len()]
                })
                .collect();
            let _ = parse_head(&buf);
            let _ = decode_chunked(&buf);
        }
    }
}
