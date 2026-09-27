//! Plain-text HTTP/1.x request sniffing (method + Host header).
//!
//! Only the request line and the `Host` header are extracted: paths and other
//! headers can carry personal data and are deliberately not recorded.

use super::tls::Sniff;

const METHODS: &[&str] = &["GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE"];
/// Give up if the header block is larger than this.
pub const MAX_HEADER_LEN: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub host: Option<String>,
}

pub fn parse_request(buf: &[u8]) -> Sniff<HttpRequest> {
    // Decide early whether this can be HTTP at all.
    let prefix_len = buf.len().min(8);
    let plausible = METHODS.iter().any(|m| {
        let m = m.as_bytes();
        let n = prefix_len.min(m.len() + 1);
        let want: Vec<u8> = m.iter().copied().chain(std::iter::once(b' ')).take(n).collect();
        buf.starts_with(&want)
    });
    if !plausible {
        return Sniff::NotMatched;
    }
    let Some(end) = find(buf, b"\r\n\r\n") else {
        return if buf.len() > MAX_HEADER_LEN { Sniff::NotMatched } else { Sniff::NeedMore };
    };
    let Ok(head) = std::str::from_utf8(&buf[..end]) else {
        return Sniff::NotMatched;
    };
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default();
    if !parts.next().is_some_and(|v| v.starts_with("HTTP/1.")) {
        return Sniff::NotMatched;
    }
    let mut host = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("host"))
        .map(|(_, v)| strip_port(v.trim()).to_string());
    if host.is_none() && method == "CONNECT" {
        host = Some(strip_port(target).to_string());
    }
    Sniff::Found(HttpRequest { method, host: host.and_then(|h| super::normalize_host(&h)) })
}

fn strip_port(hostport: &str) -> &str {
    if let Some(rest) = hostport.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match hostport.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => h,
        _ => hostport,
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host() {
        let r = parse_request(b"GET /track?id=1 HTTP/1.1\r\nUser-Agent: x\r\nHost: Telemetry.Example.com:8080\r\n\r\n");
        assert_eq!(
            r,
            Sniff::Found(HttpRequest { method: "GET".into(), host: Some("telemetry.example.com".into()) })
        );
    }

    #[test]
    fn incremental() {
        assert_eq!(parse_request(b"PO"), Sniff::NeedMore);
        assert_eq!(parse_request(b"POST / HTTP/1.1\r\nHost: a"), Sniff::NeedMore);
        assert_eq!(parse_request(b"\x16\x03\x01"), Sniff::NotMatched);
        assert_eq!(parse_request(b"GETX"), Sniff::NotMatched);
    }

    #[test]
    fn connect_target() {
        let Sniff::Found(r) = parse_request(b"CONNECT proxy.example:443 HTTP/1.1\r\n\r\n") else { panic!() };
        assert_eq!(r.host.as_deref(), Some("proxy.example"));
    }
}
