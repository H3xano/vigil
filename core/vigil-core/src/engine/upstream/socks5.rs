//! SOCKS5 client: RFC 1928 CONNECT and UDP ASSOCIATE, RFC 1929
//! username/password authentication.

use super::super::sock;
use super::ProxyUnavailable;
use crate::config::upstream::{literal_socket_addr, split_host_port, Socks5Config, Socks5Udp};
use crate::platform::Platform;
use crate::proto::{http, tls};
use parking_lot::Mutex;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU8, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const VERSION: u8 = 5;
const METHOD_NONE: u8 = 0x00;
const METHOD_USERPASS: u8 = 0x02;
const METHOD_UNACCEPTABLE: u8 = 0xff;
pub(crate) const CMD_CONNECT: u8 = 0x01;
pub(crate) const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_V4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_V6: u8 = 0x04;
#[cfg(test)]
/// Reply code "command not supported".
const REP_CMD_UNSUPPORTED: u8 = 0x07;

/// Time allowed to reach the proxy itself. Kept short so that fail-open
/// mode can still fall back within the connect timeout.
const PROXY_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Time allowed for the SOCKS negotiation (the CONNECT reply can take a few
/// seconds through Tor).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Where a CONNECT goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Target {
    Ip(SocketAddr),
    /// A host name, resolved by the proxy.
    Domain(String, u16),
}

/// Greeting offering "no authentication" and, with credentials, RFC 1929.
pub(crate) fn encode_greeting(with_auth: bool) -> Vec<u8> {
    if with_auth {
        vec![VERSION, 2, METHOD_NONE, METHOD_USERPASS]
    } else {
        vec![VERSION, 1, METHOD_NONE]
    }
}

/// RFC 1929 sub-negotiation. Credentials are at most 255 bytes each
/// (checked by config validation; longer ones are truncated here).
pub(crate) fn encode_auth(user: &str, pass: &str) -> Vec<u8> {
    let (u, p) = (
        &user.as_bytes()[..user.len().min(255)],
        &pass.as_bytes()[..pass.len().min(255)],
    );
    let mut out = Vec::with_capacity(3 + u.len() + p.len());
    out.push(1);
    out.push(u.len() as u8);
    out.extend_from_slice(u);
    out.push(p.len() as u8);
    out.extend_from_slice(p);
    out
}

fn encode_addr(out: &mut Vec<u8>, target: &Target) {
    match target {
        Target::Ip(SocketAddr::V4(a)) => {
            out.push(ATYP_V4);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        Target::Ip(SocketAddr::V6(a)) => {
            out.push(ATYP_V6);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        Target::Domain(name, port) => {
            let n = &name.as_bytes()[..name.len().min(255)];
            out.push(ATYP_DOMAIN);
            out.push(n.len() as u8);
            out.extend_from_slice(n);
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
}

/// A request (`CMD_CONNECT` or `CMD_UDP_ASSOCIATE`).
pub(crate) fn encode_request(cmd: u8, target: &Target) -> Vec<u8> {
    let mut out = vec![VERSION, cmd, 0];
    encode_addr(&mut out, target);
    out
}

/// The header in front of every datagram exchanged with the UDP relay.
pub(crate) fn encode_udp_header(dst: SocketAddr) -> Vec<u8> {
    let mut out = vec![0, 0, 0];
    encode_addr(&mut out, &Target::Ip(dst));
    out
}

/// Parses a relayed datagram: the sender and the payload. Fragments
/// (FRAG != 0) and domain-addressed replies are rejected.
pub(crate) fn parse_udp_datagram(d: &[u8]) -> Option<(SocketAddr, &[u8])> {
    if d.len() < 4 || d[0] != 0 || d[1] != 0 || d[2] != 0 {
        return None;
    }
    match d[3] {
        ATYP_V4 if d.len() >= 10 => {
            let ip = Ipv4Addr::new(d[4], d[5], d[6], d[7]);
            let port = u16::from_be_bytes([d[8], d[9]]);
            Some((SocketAddr::new(ip.into(), port), &d[10..]))
        }
        ATYP_V6 if d.len() >= 22 => {
            let b: [u8; 16] = d[4..20].try_into().ok()?;
            let port = u16::from_be_bytes([d[20], d[21]]);
            Some((SocketAddr::new(Ipv6Addr::from(b).into(), port), &d[22..]))
        }
        _ => None,
    }
}

/// Maps a non-zero reply code to an error, phrased like the equivalent
/// socket error so flow events read naturally.
pub(crate) fn reply_error(rep: u8) -> io::Error {
    use io::ErrorKind::*;
    let (kind, msg) = match rep {
        0x01 => (Other, "general SOCKS server failure"),
        0x02 => (PermissionDenied, "connection not allowed by ruleset"),
        0x03 => (Other, "network unreachable"),
        0x04 => (Other, "host unreachable"),
        0x05 => (ConnectionRefused, "connection refused"),
        0x06 => (TimedOut, "TTL expired"),
        0x07 => (Unsupported, "command not supported"),
        0x08 => (Unsupported, "address type not supported"),
        _ => (Other, "unknown reply"),
    };
    io::Error::new(kind, format!("socks5: {msg} (reply {rep})"))
}

fn protocol_error(msg: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        ProxyUnavailable(format!("socks5: {msg}")),
    )
}

/// Reads a reply's bound address (after VER, REP and RSV were checked).
async fn read_bound_addr<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<Option<SocketAddr>> {
    let atyp = s.read_u8().await?;
    let ip: Option<IpAddr> = match atyp {
        ATYP_V4 => {
            let mut b = [0u8; 4];
            s.read_exact(&mut b).await?;
            Some(Ipv4Addr::from(b).into())
        }
        ATYP_V6 => {
            let mut b = [0u8; 16];
            s.read_exact(&mut b).await?;
            Some(Ipv6Addr::from(b).into())
        }
        ATYP_DOMAIN => {
            let n = s.read_u8().await? as usize;
            let mut b = vec![0u8; n];
            s.read_exact(&mut b).await?;
            None
        }
        _ => return Err(protocol_error("bad address type in reply")),
    };
    let port = s.read_u16().await?;
    Ok(ip.map(|ip| SocketAddr::new(ip, port)))
}

/// Runs the method negotiation, authentication and one request on an open
/// connection to the proxy. Returns the bound address from the reply.
pub(crate) async fn negotiate<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    user: &str,
    pass: &str,
    cmd: u8,
    target: &Target,
) -> io::Result<Option<SocketAddr>> {
    let with_auth = !user.is_empty();
    s.write_all(&encode_greeting(with_auth)).await?;
    let mut sel = [0u8; 2];
    s.read_exact(&mut sel).await?;
    if sel[0] != VERSION {
        return Err(protocol_error("not a SOCKS5 server"));
    }
    match sel[1] {
        METHOD_NONE => {}
        METHOD_USERPASS if with_auth => {
            s.write_all(&encode_auth(user, pass)).await?;
            let mut r = [0u8; 2];
            s.read_exact(&mut r).await?;
            if r[1] != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    ProxyUnavailable("socks5: authentication failed".into()),
                ));
            }
        }
        METHOD_UNACCEPTABLE => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                ProxyUnavailable("socks5: no acceptable authentication method".into()),
            ))
        }
        _ => return Err(protocol_error("unexpected authentication method")),
    }
    s.write_all(&encode_request(cmd, target)).await?;
    let mut head = [0u8; 3];
    s.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(protocol_error("bad reply version"));
    }
    if head[1] != 0 {
        // Drain the rest of the reply so the error is the proxy's, not EOF.
        let _ = read_bound_addr(s).await;
        return Err(reply_error(head[1]));
    }
    read_bound_addr(s).await
}

/// The name to hand to the proxy for a relayed connection: the TLS SNI or
/// HTTP Host in the app's first bytes, else the IP address.
pub(crate) fn target_from_first_bytes(first: &[u8], dst: SocketAddr) -> Target {
    let name = match tls::parse_records(first) {
        tls::Sniff::Found(ch) => ch.sni,
        _ => match http::parse_request(first) {
            tls::Sniff::Found(req) => req.host.map(|h| strip_port(&h).to_string()),
            _ => None,
        },
    };
    match name {
        Some(n) if is_domain(&n) => Target::Domain(n.to_ascii_lowercase(), dst.port()),
        _ => Target::Ip(dst),
    }
}

fn strip_port(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match host.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => host,
    }
}

/// A plausible DNS name (not an IP literal).
fn is_domain(s: &str) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    !s.is_empty()
        && s.len() <= 253
        && s.parse::<IpAddr>().is_err()
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

const UDP_UNKNOWN: u8 = 0;
const UDP_SUPPORTED: u8 = 1;
const UDP_UNSUPPORTED: u8 = 2;

#[derive(Default)]
struct Health {
    /// Some(true) after a successful exchange with the proxy, Some(false)
    /// after it could not be reached.
    reachable: Option<bool>,
    last_error: Option<String>,
}

/// Dials through one SOCKS5 proxy.
pub(crate) struct Socks5Dialer {
    cfg: Socks5Config,
    health: Mutex<Health>,
    udp: AtomicU8,
}

impl Socks5Dialer {
    pub fn new(cfg: Socks5Config) -> Self {
        Self {
            cfg,
            health: Mutex::new(Health::default()),
            udp: AtomicU8::new(UDP_UNKNOWN),
        }
    }

    pub fn send_domain(&self) -> bool {
        self.cfg.send_domain
    }

    pub fn server(&self) -> &str {
        &self.cfg.server
    }

    fn note(&self, result: Result<(), &io::Error>) {
        let mut h = self.health.lock();
        match result {
            Ok(()) => h.reachable = Some(true),
            Err(e) => {
                if super::is_proxy_unavailable(e) {
                    h.reachable = Some(false);
                }
                h.last_error = Some(e.to_string());
            }
        }
    }

    /// "up", "down" or "idle" (nothing tried yet), and the last error.
    pub fn health(&self) -> (&'static str, Option<String>) {
        let h = self.health.lock();
        let state = match h.reachable {
            Some(true) => "up",
            Some(false) => "down",
            None => "idle",
        };
        (state, h.last_error.clone())
    }

    pub fn udp_state(&self) -> &'static str {
        if self.cfg.udp == Socks5Udp::Block {
            return "blocked";
        }
        match self.udp.load(Relaxed) {
            UDP_SUPPORTED => "supported",
            UDP_UNSUPPORTED => "unsupported",
            _ => "unknown",
        }
    }

    /// Whether UDP flows can be relayed at all (known so far).
    pub fn udp_possible(&self) -> bool {
        self.cfg.udp != Socks5Udp::Block && self.udp.load(Relaxed) != UDP_UNSUPPORTED
    }

    /// Opens a (protected) TCP connection to the proxy itself.
    async fn open(&self, platform: &Arc<dyn Platform>) -> io::Result<TcpStream> {
        let unavailable = |e: io::Error| {
            io::Error::new(
                e.kind(),
                ProxyUnavailable(format!("socks5 proxy {}: {e}", self.cfg.server)),
            )
        };
        let addr = match literal_socket_addr(&self.cfg.server) {
            Some(a) => a,
            None => {
                let (host, port) = split_host_port(&self.cfg.server)
                    .ok_or_else(|| unavailable(io::Error::other("bad address")))?;
                let mut addrs = tokio::net::lookup_host((host.as_str(), port))
                    .await
                    .map_err(unavailable)?;
                addrs
                    .next()
                    .ok_or_else(|| unavailable(io::Error::other("no address")))?
            }
        };
        match tokio::time::timeout(
            PROXY_CONNECT_TIMEOUT,
            sock::connect_tcp(platform.clone(), addr),
        )
        .await
        {
            Ok(r) => r.map_err(unavailable),
            Err(_) => Err(unavailable(io::Error::new(
                io::ErrorKind::TimedOut,
                "connect timed out",
            ))),
        }
    }

    /// Opens a connection to the proxy and runs one request on it.
    async fn request(
        &self,
        platform: &Arc<dyn Platform>,
        cmd: u8,
        target: &Target,
    ) -> io::Result<(TcpStream, Option<SocketAddr>)> {
        let result = async {
            let mut s = self.open(platform).await?;
            let bound = tokio::time::timeout(
                HANDSHAKE_TIMEOUT,
                negotiate(&mut s, &self.cfg.username, &self.cfg.password, cmd, target),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "socks5: no reply"))?
            .map_err(|e| match e.kind() {
                // EOF in the middle of the negotiation: not a working proxy.
                io::ErrorKind::UnexpectedEof => protocol_error("proxy closed the connection"),
                _ => e,
            })?;
            Ok((s, bound))
        }
        .await;
        self.note(result.as_ref().map(|_| ()));
        result
    }

    /// CONNECT to `target`.
    pub async fn connect(
        &self,
        platform: &Arc<dyn Platform>,
        target: &Target,
    ) -> io::Result<TcpStream> {
        let (s, _) = self.request(platform, CMD_CONNECT, target).await?;
        Ok(s)
    }

    /// UDP ASSOCIATE for datagrams to `dst`.
    pub async fn associate(
        &self,
        platform: &Arc<dyn Platform>,
        dst: SocketAddr,
    ) -> io::Result<Socks5UdpFlow> {
        if !self.udp_possible() {
            return Err(udp_blocked());
        }
        // The client's own UDP address is not known before binding; 0.0.0.0:0
        // asks the proxy to accept datagrams from the connection's address.
        let any: SocketAddr = if dst.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let (ctrl, bound) = match self
            .request(platform, CMD_UDP_ASSOCIATE, &Target::Ip(any))
            .await
        {
            Ok(r) => r,
            Err(e) => {
                if !super::is_proxy_unavailable(&e) {
                    // The proxy answered but refused: remember that UDP is out.
                    self.udp.store(UDP_UNSUPPORTED, Relaxed);
                    log::info!("SOCKS5 proxy refused UDP ASSOCIATE ({e}); UDP is blocked");
                    return Err(udp_blocked());
                }
                return Err(e);
            }
        };
        self.udp.store(UDP_SUPPORTED, Relaxed);
        let proxy_ip = ctrl.peer_addr()?.ip();
        let relay = match bound {
            Some(a) if !a.ip().is_unspecified() => a,
            Some(a) => SocketAddr::new(proxy_ip, a.port()),
            None => return Err(protocol_error("UDP relay given as a name")),
        };
        let sock = sock::connect_udp(platform.clone(), relay).await?;
        Ok(Socks5UdpFlow {
            ctrl,
            sock,
            dst,
            header: encode_udp_header(dst),
        })
    }
}

/// The error for UDP that the proxy cannot carry.
pub(crate) fn udp_blocked() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        super::UdpBlocked("the SOCKS5 proxy does not relay UDP"),
    )
}

/// One UDP flow through a SOCKS5 UDP association. The control connection
/// is held open for the association's lifetime.
pub(crate) struct Socks5UdpFlow {
    ctrl: TcpStream,
    sock: UdpSocket,
    dst: SocketAddr,
    header: Vec<u8>,
}

impl Socks5UdpFlow {
    pub async fn send(&self, data: &[u8]) -> io::Result<usize> {
        let mut pkt = Vec::with_capacity(self.header.len() + data.len());
        pkt.extend_from_slice(&self.header);
        pkt.extend_from_slice(data);
        self.sock.send(&pkt).await?;
        Ok(data.len())
    }

    pub async fn recv_with<T>(&self, mut f: impl FnMut(&[u8]) -> T) -> io::Result<T> {
        let dst = self.dst;
        loop {
            tokio::select! {
                r = sock::recv_with(&self.sock, |d| match parse_udp_datagram(d) {
                    Some((from, payload)) if from == dst => Some(f(payload)),
                    _ => None,
                }) => {
                    if let Some(v) = r? {
                        return Ok(v);
                    }
                }
                r = self.ctrl.readable() => {
                    r?;
                    let mut b = [0u8; 64];
                    match self.ctrl.try_read(&mut b) {
                        Ok(0) => return Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "socks5: UDP association closed by the proxy",
                        )),
                        Err(e) if e.kind() != io::ErrorKind::WouldBlock => return Err(e),
                        _ => {}
                    }
                }
            }
        }
    }

    pub fn drain(&self) {
        sock::drain(&self.sock);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::NullPlatform;
    use tokio::net::TcpListener;

    #[test]
    fn encodes_requests() {
        assert_eq!(encode_greeting(false), [5, 1, 0]);
        assert_eq!(encode_greeting(true), [5, 2, 0, 2]);
        assert_eq!(
            encode_auth("ab", "xyz"),
            [1, 2, b'a', b'b', 3, b'x', b'y', b'z']
        );
        assert_eq!(
            encode_request(CMD_CONNECT, &Target::Ip("1.2.3.4:443".parse().unwrap())),
            [5, 1, 0, 1, 1, 2, 3, 4, 1, 187]
        );
        let v6 = encode_request(
            CMD_CONNECT,
            &Target::Ip("[2001:db8::1]:80".parse().unwrap()),
        );
        assert_eq!(&v6[..4], [5, 1, 0, 4]);
        assert_eq!(v6.len(), 4 + 16 + 2);
        assert_eq!(&v6[20..], [0, 80]);
        assert_eq!(
            encode_request(CMD_CONNECT, &Target::Domain("a.io".into(), 443)),
            [5, 1, 0, 3, 4, b'a', b'.', b'i', b'o', 1, 187]
        );
        assert_eq!(
            encode_request(CMD_UDP_ASSOCIATE, &Target::Ip("0.0.0.0:0".parse().unwrap())),
            [5, 3, 0, 1, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn udp_datagrams_roundtrip() {
        for dst in ["9.9.9.9:53", "[2606:4700::1111]:443"] {
            let dst: SocketAddr = dst.parse().unwrap();
            let mut d = encode_udp_header(dst);
            d.extend_from_slice(b"payload");
            assert_eq!(parse_udp_datagram(&d), Some((dst, &b"payload"[..])));
        }
        assert_eq!(
            parse_udp_datagram(&[0, 0, 1, 1, 1, 2, 3, 4, 0, 53]),
            None,
            "fragment"
        );
        assert_eq!(parse_udp_datagram(&[0, 0, 0, 1, 1, 2]), None, "short");
        assert_eq!(
            parse_udp_datagram(&[0, 0, 0, 3, 1, b'a', 0, 53]),
            None,
            "domain"
        );
        assert_eq!(parse_udp_datagram(&[]), None);
    }

    #[test]
    fn reply_codes_map_to_errors() {
        assert_eq!(reply_error(5).kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(reply_error(2).kind(), io::ErrorKind::PermissionDenied);
        assert!(reply_error(4).to_string().contains("host unreachable"));
        assert!(!super::super::is_proxy_unavailable(&reply_error(1)));
    }

    #[test]
    fn domain_target_from_sniffed_bytes() {
        let dst: SocketAddr = "93.184.215.14:443".parse().unwrap();
        let hello = tls::build_client_hello(Some("Example.COM"), &["h2"], 0);
        let mut rec = vec![0x16, 3, 1];
        rec.extend_from_slice(&(hello.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hello);
        assert_eq!(
            target_from_first_bytes(&rec, dst),
            Target::Domain("example.com".into(), 443)
        );
        let http = b"GET / HTTP/1.1\r\nHost: www.example.org:8080\r\n\r\n";
        assert_eq!(
            target_from_first_bytes(http, dst),
            Target::Domain("www.example.org".into(), 443)
        );
        let ip_host = b"GET / HTTP/1.1\r\nHost: 1.2.3.4\r\n\r\n";
        assert_eq!(target_from_first_bytes(ip_host, dst), Target::Ip(dst));
        assert_eq!(
            target_from_first_bytes(b"SSH-2.0-x\r\n", dst),
            Target::Ip(dst)
        );
        assert_eq!(strip_port("[::1]:80"), "::1");
        assert!(!is_domain("bad name"));
    }

    /// A scripted proxy: checks each client message and sends each reply.
    async fn fake_proxy(script: Vec<(Vec<u8>, Vec<u8>)>) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            for (expect, reply) in script {
                let mut got = vec![0u8; expect.len()];
                s.read_exact(&mut got).await.unwrap();
                assert_eq!(got, expect);
                s.write_all(&reply).await.unwrap();
            }
            // Echo afterwards, as a connected tunnel would.
            let mut b = [0u8; 64];
            while let Ok(n) = s.read(&mut b).await {
                if n == 0 || s.write_all(&b[..n]).await.is_err() {
                    break;
                }
            }
        });
        addr
    }

    fn dialer(server: SocketAddr, user: &str, pass: &str) -> Socks5Dialer {
        Socks5Dialer::new(Socks5Config {
            server: server.to_string(),
            username: user.into(),
            password: pass.into(),
            ..Default::default()
        })
    }

    #[tokio::test]
    async fn connect_with_auth() {
        let target = Target::Domain("example.com".into(), 443);
        let proxy = fake_proxy(vec![
            (vec![5, 2, 0, 2], vec![5, 2]),
            (encode_auth("u", "p"), vec![1, 0]),
            (
                encode_request(CMD_CONNECT, &target),
                vec![5, 0, 0, 1, 10, 0, 0, 1, 0x1f, 0x90],
            ),
        ])
        .await;
        let d = dialer(proxy, "u", "p");
        let platform: Arc<dyn Platform> = Arc::new(NullPlatform);
        let mut s = d.connect(&platform, &target).await.unwrap();
        s.write_all(b"ping").await.unwrap();
        let mut b = [0u8; 4];
        s.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"ping");
        assert_eq!(d.health().0, "up");
    }

    #[tokio::test]
    async fn refused_destination_is_not_a_proxy_failure() {
        let target = Target::Ip("192.0.2.1:80".parse().unwrap());
        let proxy = fake_proxy(vec![
            (vec![5, 1, 0], vec![5, 0]),
            (
                encode_request(CMD_CONNECT, &target),
                vec![5, 5, 0, 1, 0, 0, 0, 0, 0, 0],
            ),
        ])
        .await;
        let d = dialer(proxy, "", "");
        let platform: Arc<dyn Platform> = Arc::new(NullPlatform);
        let e = d.connect(&platform, &target).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused);
        assert!(!super::super::is_proxy_unavailable(&e));
    }

    #[tokio::test]
    async fn auth_failure_and_dead_proxy_are_proxy_failures() {
        let proxy = fake_proxy(vec![
            (vec![5, 2, 0, 2], vec![5, 2]),
            (encode_auth("u", "bad"), vec![1, 1]),
        ])
        .await;
        let platform: Arc<dyn Platform> = Arc::new(NullPlatform);
        let target = Target::Ip("192.0.2.1:80".parse().unwrap());
        let e = dialer(proxy, "u", "bad")
            .connect(&platform, &target)
            .await
            .unwrap_err();
        assert!(super::super::is_proxy_unavailable(&e), "{e}");
        // Nothing listens on the port any more.
        let closed = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let d = dialer(closed, "", "");
        let e = d.connect(&platform, &target).await.unwrap_err();
        assert!(super::super::is_proxy_unavailable(&e), "{e}");
        assert_eq!(d.health().0, "down");
    }

    #[tokio::test]
    async fn udp_associate_refusal_blocks_udp() {
        let any = Target::Ip("0.0.0.0:0".parse().unwrap());
        let proxy = fake_proxy(vec![
            (vec![5, 1, 0], vec![5, 0]),
            (
                encode_request(CMD_UDP_ASSOCIATE, &any),
                vec![5, REP_CMD_UNSUPPORTED, 0, 1, 0, 0, 0, 0, 0, 0],
            ),
        ])
        .await;
        let d = dialer(proxy, "", "");
        let platform: Arc<dyn Platform> = Arc::new(NullPlatform);
        let e = d
            .associate(&platform, "9.9.9.9:53".parse().unwrap())
            .await
            .err()
            .unwrap();
        assert!(super::super::is_udp_blocked(&e));
        assert_eq!(d.udp_state(), "unsupported");
        assert!(!d.udp_possible());
    }
}
