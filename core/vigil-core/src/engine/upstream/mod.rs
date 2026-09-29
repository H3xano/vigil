//! The upstream dialer: how vigil's own sockets reach the internet.
//!
//! Every upstream socket the engine opens goes through here: TCP relay
//! connects (`tcp.rs`), UDP flows (`udp.rs`) and plain DNS to the configured
//! or hard-coded resolvers (`dns.rs`). The path is chosen by
//! [`UpstreamConfig`]: `direct` (protected sockets on the underlying network,
//! exactly as before this module existed), `wireguard` (a user-space
//! WireGuard tunnel, [`wireguard`]) or `socks5` (a SOCKS5 proxy, [`socks5`]).
//! Inspection is identical in every mode.
//!
//! # Calling it
//!
//! ```ignore
//! // A TCP connection to `addr` over the configured path. `shared: &Shared`
//! // (an `&Arc<Shared>` coerces). The stream is
//! // AsyncRead + AsyncWrite + Unpin + Send + 'static, so generic TLS code
//! // (tokio-rustls, etc.) can wrap it directly.
//! let stream: UpstreamTcp = upstream::connect_tcp(&shared, addr).await?;
//! ```
//!
//! `connect_tcp` never falls back to a direct connection when the tunnel or
//! proxy is unavailable and `fail_closed` is set (the default): it returns
//! the error instead. It resolves once the connection is established end to
//! end (for WireGuard, the tunnelled three-way handshake; for SOCKS5, the
//! CONNECT reply), so wrap it in your own timeout. `UpstreamTcp::via()`
//! tells which path was taken.
//!
//! # Runtime changes
//!
//! A config update that changes the path builds a new dialer; connections
//! and UDP flows already open keep the path they were opened on until they
//! end (a replaced WireGuard tunnel lives on until its last connection
//! closes). Pooled DNS sockets from the old path are not reused (nor, with
//! WireGuard and `fail_closed: false`, ones from before the tunnel went
//! down or came back: see [`Upstream::generation`]). A change of
//! `network_id` alone makes WireGuard re-create its socket and re-resolve
//! the endpoint, keeping the session (roaming).

mod socks5;
mod wireguard;

use super::sock;
use crate::config::upstream::{literal_socket_addr, split_host_port, UpstreamConfig, UpstreamMode};
use crate::event::UpstreamStatus;
use crate::platform::Platform;
use parking_lot::RwLock;
use socks5::{Socks5Dialer, Socks5UdpFlow, Target};
use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpStream, UdpSocket};
use wireguard::{WgTcpStream, WgTunnel, WgUdp};

pub(crate) const VIA_DIRECT: &str = "direct";
pub(crate) const VIA_WIREGUARD: &str = "wireguard";
pub(crate) const VIA_SOCKS5: &str = "socks5";

/// Marks errors meaning "the proxy itself could not be used" (as opposed to
/// the proxy reporting that the destination failed). Only these trigger
/// the fallback to direct when `fail_closed` is off.
#[derive(Debug)]
pub(crate) struct ProxyUnavailable(pub String);

impl fmt::Display for ProxyUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ProxyUnavailable {}

/// Marks errors meaning "this path cannot carry UDP".
#[derive(Debug)]
pub(crate) struct UdpBlocked(pub &'static str);

impl fmt::Display for UdpBlocked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for UdpBlocked {}

pub(crate) fn is_proxy_unavailable(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|i| i.is::<ProxyUnavailable>())
}

/// The path refuses UDP by design (SOCKS5 without UDP ASSOCIATE): the flow
/// should be absorbed like a blocked one rather than retried.
pub(crate) fn is_udp_blocked(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|i| i.is::<UdpBlocked>())
}

enum Path {
    Direct,
    Socks5(Arc<Socks5Dialer>),
    Wireguard(Arc<WgTunnel>),
    /// The configured path could not be set up; every connect fails.
    Broken(UpstreamMode, String),
}

/// One configured path. Replaced as a whole when the config changes.
pub(crate) struct Dialer {
    path: Path,
    fail_closed: bool,
    generation: u64,
}

struct State {
    dialer: Arc<Dialer>,
    cfg: UpstreamConfig,
}

/// The engine's current dialer (in `Shared`).
pub(crate) struct Upstream {
    state: RwLock<State>,
}

impl Default for Upstream {
    fn default() -> Self {
        Self {
            state: RwLock::new(State {
                dialer: Arc::new(Dialer {
                    path: Path::Direct,
                    fail_closed: true,
                    generation: 0,
                }),
                cfg: UpstreamConfig::default(),
            }),
        }
    }
}

impl Upstream {
    pub fn dialer(&self) -> Arc<Dialer> {
        self.state.read().dialer.clone()
    }

    /// Identifies the current dialer; changes whenever the path does, and
    /// in fail-open WireGuard mode whenever the tunnel goes down or comes
    /// back (pooled DNS connections opened direct while it was down are
    /// then not reused through the tunnel's recovery, nor tunnelled ones
    /// while it is down).
    pub fn generation(&self) -> u64 {
        let st = self.state.read();
        let d = &st.dialer;
        let epoch = match &d.path {
            Path::Wireguard(t) if !d.fail_closed => t.health_epoch(),
            _ => 0,
        };
        (d.generation << 32) | (epoch & 0xffff_ffff)
    }

    /// Installs `cfg` (validated). Must run inside the engine's runtime:
    /// a WireGuard tunnel spawns its driver task.
    pub fn apply(&self, cfg: &UpstreamConfig, platform: &Arc<dyn Platform>) {
        let mut st = self.state.write();
        if st.cfg.same_path(cfg) {
            if st.cfg.network_id != cfg.network_id {
                if let Path::Wireguard(t) = &st.dialer.path {
                    log::info!("underlying network changed; WireGuard roams");
                    t.roam();
                }
                st.cfg.network_id = cfg.network_id.clone();
            }
            return;
        }
        let path = match cfg.mode {
            UpstreamMode::Direct => Path::Direct,
            UpstreamMode::Socks5 => Path::Socks5(Arc::new(Socks5Dialer::new(
                cfg.socks5.clone().unwrap_or_default(),
            ))),
            UpstreamMode::Wireguard => {
                let started = cfg
                    .wireguard
                    .as_ref()
                    .ok_or_else(|| io::Error::other("no wireguard section"))
                    .and_then(|w| WgTunnel::start(w, platform.clone()));
                match started {
                    Ok(t) => Path::Wireguard(t),
                    Err(e) => {
                        log::error!("wireguard: {e}");
                        Path::Broken(cfg.mode, format!("wireguard: {e}"))
                    }
                }
            }
        };
        log::info!(
            "upstream: {} (fail_closed: {})",
            cfg.mode.as_str(),
            cfg.fail_closed
        );
        st.dialer = Arc::new(Dialer {
            path,
            fail_closed: cfg.fail_closed,
            generation: st.dialer.generation + 1,
        });
        st.cfg = cfg.clone();
    }

    /// Plain DNS must use TCP (SOCKS5: DNS goes through the proxy as DNS
    /// over TCP, whatever the proxy's UDP support).
    pub fn dns_over_tcp(&self) -> bool {
        matches!(self.state.read().dialer.path, Path::Socks5(_))
    }

    /// The path new connections take (for events of failed connects).
    pub fn via(&self) -> &'static str {
        self.state.read().dialer.via()
    }

    pub fn status(&self) -> UpstreamStatus {
        let d = self.dialer();
        let mut s = UpstreamStatus {
            mode: d.via(),
            state: "up",
            fail_closed: d.fail_closed,
            ..Default::default()
        };
        match &d.path {
            Path::Direct => {}
            Path::Broken(_, e) => {
                s.state = "down";
                s.last_error = Some(e.clone());
            }
            Path::Socks5(p) => {
                let (state, err) = p.health();
                s.state = state;
                s.last_error = err;
                s.endpoint = Some(p.server().to_string());
                s.udp = Some(p.udp_state());
            }
            Path::Wireguard(t) => {
                let w = t.status();
                s.state = w.state;
                s.endpoint = w.endpoint.map(|e| e.to_string());
                s.handshake_age_s = w.handshake_age_s;
                s.tx_bytes = Some(w.tx_bytes);
                s.rx_bytes = Some(w.rx_bytes);
                s.last_error = w.last_error;
            }
        }
        s
    }
}

/// Looks up `host:port` (no lookup for an IP literal) within `timeout`.
/// The result is never empty.
async fn resolve(spec: &str, timeout: Duration) -> io::Result<Vec<SocketAddr>> {
    if let Some(a) = literal_socket_addr(spec) {
        return Ok(vec![a]);
    }
    let (host, port) = split_host_port(spec).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("bad address {spec}"))
    })?;
    let addrs: Vec<SocketAddr> =
        tokio::time::timeout(timeout, tokio::net::lookup_host((host.as_str(), port)))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("resolve {host}: timed out"),
                )
            })?
            .map_err(|e| io::Error::new(e.kind(), format!("resolve {host}: {e}")))?
            .collect();
    if addrs.is_empty() {
        return Err(io::Error::other(format!("resolve {host}: no address")));
    }
    Ok(addrs)
}

async fn direct_tcp(platform: &Arc<dyn Platform>, dst: SocketAddr) -> io::Result<UpstreamTcp> {
    sock::connect_tcp(platform.clone(), dst)
        .await
        .map(UpstreamTcp::Direct)
}

async fn direct_udp(platform: &Arc<dyn Platform>, dst: SocketAddr) -> io::Result<UpstreamUdp> {
    sock::connect_udp(platform.clone(), dst)
        .await
        .map(UpstreamUdp::Direct)
}

impl Dialer {
    pub fn via(&self) -> &'static str {
        match &self.path {
            Path::Direct => VIA_DIRECT,
            Path::Socks5(_) => VIA_SOCKS5,
            Path::Wireguard(_) => VIA_WIREGUARD,
            Path::Broken(m, _) => m.as_str(),
        }
    }

    /// Whether traffic to `dst` bypasses the tunnel: outside AllowedIPs, or
    /// the tunnel is down and fail-open. With fail_closed, a destination
    /// whose whole address family AllowedIPs leave out (e.g. IPv6 with only
    /// `0.0.0.0/0`) is refused instead of leaking under the real address;
    /// only a split tunnel within a routed family bypasses.
    fn wg_bypass(&self, t: &WgTunnel, dst: SocketAddr) -> io::Result<bool> {
        if t.routes(dst.ip()) {
            return Ok(!self.fail_closed && t.is_down());
        }
        if self.fail_closed && !t.routes_family(dst.ip()) {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!(
                    "wireguard: AllowedIPs route no IPv{} (fail_closed)",
                    if dst.ip().to_canonical().is_ipv4() {
                        4
                    } else {
                        6
                    }
                ),
            ));
        }
        Ok(true)
    }

    async fn connect_tcp(
        &self,
        platform: &Arc<dyn Platform>,
        dst: SocketAddr,
        relay: bool,
    ) -> io::Result<UpstreamTcp> {
        match &self.path {
            Path::Direct => direct_tcp(platform, dst).await,
            Path::Broken(_, e) => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                ProxyUnavailable(e.clone()),
            )),
            Path::Socks5(s) => {
                if relay && s.send_domain() {
                    // Reach the proxy now; only the CONNECT waits for the
                    // name in the app's first bytes.
                    return match s.handshake(platform).await {
                        Ok(conn) => Ok(UpstreamTcp::Lazy(Box::new(LazySocks::new(
                            s.clone(),
                            conn,
                            dst,
                        )))),
                        Err(e) if !self.fail_closed && is_proxy_unavailable(&e) => {
                            direct_tcp(platform, dst).await
                        }
                        Err(e) => Err(e),
                    };
                }
                match s.connect(platform, &Target::Ip(dst)).await {
                    Ok(t) => Ok(UpstreamTcp::Socks5(t)),
                    Err(e) if !self.fail_closed && is_proxy_unavailable(&e) => {
                        direct_tcp(platform, dst).await
                    }
                    Err(e) => Err(e),
                }
            }
            Path::Wireguard(t) => {
                if self.wg_bypass(t, dst)? {
                    return direct_tcp(platform, dst).await;
                }
                t.connect_tcp(dst).await.map(UpstreamTcp::Wireguard)
            }
        }
    }

    async fn connect_udp(
        &self,
        platform: &Arc<dyn Platform>,
        dst: SocketAddr,
    ) -> io::Result<UpstreamUdp> {
        match &self.path {
            Path::Direct => direct_udp(platform, dst).await,
            Path::Broken(_, e) => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                ProxyUnavailable(e.clone()),
            )),
            Path::Socks5(s) => match s.associate(platform, dst).await {
                Ok(f) => Ok(UpstreamUdp::Socks5(Box::new(f))),
                Err(e) if !self.fail_closed && is_proxy_unavailable(&e) => {
                    direct_udp(platform, dst).await
                }
                Err(e) => Err(e),
            },
            Path::Wireguard(t) => {
                if self.wg_bypass(t, dst)? {
                    return direct_udp(platform, dst).await;
                }
                t.connect_udp(dst).map(UpstreamUdp::Wireguard)
            }
        }
    }
}

/// Opens a TCP connection to `dst` over the configured upstream path.
///
/// This is the entry point for any engine code that needs its own upstream
/// connection (e.g. DNS over TLS/HTTPS to a resolver): see the module docs.
pub(crate) async fn connect_tcp(
    shared: &super::Shared,
    dst: SocketAddr,
) -> io::Result<UpstreamTcp> {
    let d = shared.upstream.dialer();
    d.connect_tcp(&shared.platform, dst, false).await
}

/// Like [`connect_tcp`], for relayed app connections: with SOCKS5 and
/// `send_domain`, the connection is made lazily, by the name found in the
/// app's first bytes (TLS SNI / HTTP Host).
pub(crate) async fn connect_relay(
    shared: &super::Shared,
    dst: SocketAddr,
) -> io::Result<UpstreamTcp> {
    let d = shared.upstream.dialer();
    d.connect_tcp(&shared.platform, dst, true).await
}

/// A UDP "connection" to `dst` over the configured upstream path. Errors
/// for which [`is_udp_blocked`] is true mean the path cannot carry UDP.
pub(crate) async fn connect_udp(
    shared: &super::Shared,
    dst: SocketAddr,
) -> io::Result<UpstreamUdp> {
    let d = shared.upstream.dialer();
    d.connect_udp(&shared.platform, dst).await
}

/// An upstream TCP connection over any path.
pub(crate) enum UpstreamTcp {
    Direct(TcpStream),
    /// Connected through the SOCKS5 proxy (the stream is to the proxy).
    Socks5(TcpStream),
    Wireguard(WgTcpStream),
    /// SOCKS5 CONNECT by name, made on the first write.
    Lazy(Box<LazySocks>),
}

impl UpstreamTcp {
    /// The path this connection uses: "direct", "wireguard" or "socks5".
    pub fn via(&self) -> &'static str {
        match self {
            UpstreamTcp::Direct(_) => VIA_DIRECT,
            UpstreamTcp::Socks5(_) | UpstreamTcp::Lazy(_) => VIA_SOCKS5,
            UpstreamTcp::Wireguard(_) => VIA_WIREGUARD,
        }
    }

    /// Makes the close (drop) abort the connection: a RST on a direct
    /// socket or inside the tunnel, an aborted connection to the proxy.
    pub fn set_reset_on_close(&mut self) {
        match self {
            UpstreamTcp::Direct(s) | UpstreamTcp::Socks5(s) => sock::set_reset_on_close(s),
            UpstreamTcp::Wireguard(s) => s.set_reset_on_close(),
            UpstreamTcp::Lazy(l) => l.set_reset_on_close(),
        }
    }

    /// Splits into independently usable halves. Socket-backed paths use
    /// tokio's lock-free owned halves, as the relay always did.
    pub fn into_split(self) -> (UpstreamRead, UpstreamWrite) {
        match self {
            UpstreamTcp::Direct(s) => {
                let (r, w) = s.into_split();
                (UpstreamRead::Tcp(r), UpstreamWrite::Tcp(w, VIA_DIRECT))
            }
            UpstreamTcp::Socks5(s) => {
                let (r, w) = s.into_split();
                (UpstreamRead::Tcp(r), UpstreamWrite::Tcp(w, VIA_SOCKS5))
            }
            other => {
                let (r, w) = tokio::io::split(other);
                (UpstreamRead::Other(r), UpstreamWrite::Other(w))
            }
        }
    }
}

macro_rules! delegate_read {
    ($self:ident, $cx:ident, $buf:ident; $($v:path),+) => {
        match $self.get_mut() {
            $($v(s) => Pin::new(s).poll_read($cx, $buf),)+
        }
    };
}

/// Runs `$body` with `$s` bound to the inner stream of any variant.
macro_rules! each_tcp {
    ($e:expr, $s:ident => $body:expr) => {
        match $e {
            UpstreamTcp::Direct($s) | UpstreamTcp::Socks5($s) => $body,
            UpstreamTcp::Wireguard($s) => $body,
            UpstreamTcp::Lazy($s) => $body,
        }
    };
}

impl AsyncRead for UpstreamTcp {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        each_tcp!(self.get_mut(), s => Pin::new(s).poll_read(cx, buf))
    }
}

impl AsyncWrite for UpstreamTcp {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        each_tcp!(self.get_mut(), s => Pin::new(s).poll_write(cx, buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        each_tcp!(self.get_mut(), s => Pin::new(s).poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        each_tcp!(self.get_mut(), s => Pin::new(s).poll_shutdown(cx))
    }
}

/// Read half of an [`UpstreamTcp`].
pub(crate) enum UpstreamRead {
    Tcp(OwnedReadHalf),
    Other(ReadHalf<UpstreamTcp>),
}

/// Write half of an [`UpstreamTcp`].
pub(crate) enum UpstreamWrite {
    Tcp(OwnedWriteHalf, &'static str),
    Other(WriteHalf<UpstreamTcp>),
}

impl UpstreamRead {
    /// Puts the halves back together (None if they do not belong together).
    pub fn reunite(self, w: UpstreamWrite) -> Option<UpstreamTcp> {
        match (self, w) {
            (UpstreamRead::Tcp(r), UpstreamWrite::Tcp(w, via)) => {
                let s = r.reunite(w).ok()?;
                Some(if via == VIA_SOCKS5 {
                    UpstreamTcp::Socks5(s)
                } else {
                    UpstreamTcp::Direct(s)
                })
            }
            (UpstreamRead::Other(r), UpstreamWrite::Other(w)) if r.is_pair_of(&w) => {
                Some(r.unsplit(w))
            }
            _ => None,
        }
    }
}

impl AsyncRead for UpstreamRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        delegate_read!(self, cx, buf; UpstreamRead::Tcp, UpstreamRead::Other)
    }
}

impl AsyncWrite for UpstreamWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            UpstreamWrite::Tcp(s, _) => Pin::new(s).poll_write(cx, buf),
            UpstreamWrite::Other(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            UpstreamWrite::Tcp(s, _) => Pin::new(s).poll_flush(cx),
            UpstreamWrite::Other(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            UpstreamWrite::Tcp(s, _) => Pin::new(s).poll_shutdown(cx),
            UpstreamWrite::Other(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// How long a lazily connected relay waits for the app's first bytes
/// before connecting by address (just beyond the relay's 3 s sniff window,
/// so server-speaks-first protocols still work).
const LAZY_WAIT: Duration = Duration::from_millis(3500);

type ConnectFuture = Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>>;

enum LazyState {
    Waiting,
    Connecting(ConnectFuture),
    Ready(TcpStream),
    Failed(io::ErrorKind, String),
}

/// A SOCKS5 connection whose CONNECT is sent on the first write, by the
/// name in the written bytes (TLS SNI or HTTP Host), or by address after
/// [`LAZY_WAIT`]. The connection to the proxy (with its authentication) is
/// made beforehand, at the SYN gate: an unusable proxy is refused there, or
/// bypassed there with `fail_closed: false`. So a lazy connection never
/// goes direct, and its `via` is always `socks5`.
pub(crate) struct LazySocks {
    dialer: Arc<Socks5Dialer>,
    dst: SocketAddr,
    /// The negotiated connection to the proxy, until the CONNECT is sent.
    conn: Option<TcpStream>,
    state: LazyState,
    deadline: Pin<Box<tokio::time::Sleep>>,
    read_waker: Option<Waker>,
    reset_on_close: bool,
}

impl LazySocks {
    fn new(dialer: Arc<Socks5Dialer>, conn: TcpStream, dst: SocketAddr) -> Self {
        Self {
            dialer,
            dst,
            conn: Some(conn),
            state: LazyState::Waiting,
            deadline: Box::pin(tokio::time::sleep(LAZY_WAIT)),
            read_waker: None,
            reset_on_close: false,
        }
    }

    fn set_reset_on_close(&mut self) {
        self.reset_on_close = true;
        if let Some(s) = &self.conn {
            sock::set_reset_on_close(s);
        }
        if let LazyState::Ready(s) = &self.state {
            sock::set_reset_on_close(s);
        }
    }

    fn start(&mut self, target: Target) {
        log::debug!("socks5: connecting to {target:?} for {}", self.dst);
        let d = self.dialer.clone();
        self.state = match self.conn.take() {
            Some(mut s) => LazyState::Connecting(Box::pin(async move {
                d.request_on(&mut s, socks5::CMD_CONNECT, &target).await?;
                Ok(s)
            })),
            None => LazyState::Failed(io::ErrorKind::NotConnected, "socks5: no connection".into()),
        };
        if let Some(w) = self.read_waker.take() {
            w.wake();
        }
    }

    fn poll_connected(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<&mut TcpStream>> {
        if let LazyState::Connecting(f) = &mut self.state {
            let done = match f.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(r) => r,
            };
            self.state = match done {
                Ok(s) => {
                    if self.reset_on_close {
                        sock::set_reset_on_close(&s);
                    }
                    LazyState::Ready(s)
                }
                Err(e) => LazyState::Failed(e.kind(), e.to_string()),
            };
            if let Some(w) = self.read_waker.take() {
                w.wake();
            }
        }
        match &mut self.state {
            LazyState::Ready(s) => Poll::Ready(Ok(s)),
            LazyState::Failed(k, m) => Poll::Ready(Err(io::Error::new(*k, m.clone()))),
            _ => Poll::Pending,
        }
    }
}

impl AsyncRead for LazySocks {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if matches!(me.state, LazyState::Waiting) {
            if me.deadline.as_mut().poll(cx).is_ready() {
                me.start(Target::Ip(me.dst));
            } else {
                me.read_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
        }
        if matches!(me.state, LazyState::Connecting(_)) {
            me.read_waker = Some(cx.waker().clone());
        }
        match me.poll_connected(cx) {
            Poll::Ready(Ok(s)) => Pin::new(s).poll_read(cx, buf),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for LazySocks {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if matches!(me.state, LazyState::Waiting) {
            let target = socks5::target_from_first_bytes(buf, me.dst);
            me.start(target);
        }
        match me.poll_connected(cx) {
            Poll::Ready(Ok(s)) => Pin::new(s).poll_write(cx, buf),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().state {
            LazyState::Ready(s) => Pin::new(s).poll_flush(cx),
            _ => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if matches!(me.state, LazyState::Waiting) {
            me.start(Target::Ip(me.dst));
        }
        match me.poll_connected(cx) {
            Poll::Ready(Ok(s)) => Pin::new(s).poll_shutdown(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// An upstream UDP "connection" (datagrams to and from one destination).
pub(crate) enum UpstreamUdp {
    Direct(UdpSocket),
    Socks5(Box<Socks5UdpFlow>),
    Wireguard(WgUdp),
}

impl UpstreamUdp {
    pub fn via(&self) -> &'static str {
        match self {
            UpstreamUdp::Direct(_) => VIA_DIRECT,
            UpstreamUdp::Socks5(_) => VIA_SOCKS5,
            UpstreamUdp::Wireguard(_) => VIA_WIREGUARD,
        }
    }

    pub async fn send(&self, data: &[u8]) -> io::Result<usize> {
        match self {
            UpstreamUdp::Direct(s) => s.send(data).await,
            UpstreamUdp::Socks5(f) => f.send(data).await,
            UpstreamUdp::Wireguard(w) => w.send(data),
        }
    }

    /// Receives one datagram from the destination and passes it to `f`
    /// (without a per-socket buffer, see `sock::recv_with`).
    pub async fn recv_with<T>(&self, f: impl FnMut(&[u8]) -> T) -> io::Result<T> {
        match self {
            UpstreamUdp::Direct(s) => sock::recv_with(s, f).await,
            UpstreamUdp::Socks5(flow) => flow.recv_with(f).await,
            UpstreamUdp::Wireguard(w) => w.recv_with(f).await,
        }
    }

    /// Discards datagrams already queued (stale replies on a reused socket).
    pub fn drain(&self) {
        match self {
            UpstreamUdp::Direct(s) => sock::drain(s),
            UpstreamUdp::Socks5(f) => f.drain(),
            UpstreamUdp::Wireguard(w) => w.drain(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::upstream::Socks5Config;
    use crate::config::Config;
    use crate::engine::tests::test_shared;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn assert_generic_stream<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>() {}

    #[test]
    fn upstream_tcp_is_a_generic_stream() {
        // Contract for TLS wrappers (encrypted DNS).
        assert_generic_stream::<UpstreamTcp>();
    }

    fn socks_cfg(server: SocketAddr, fail_closed: bool) -> UpstreamConfig {
        UpstreamConfig {
            mode: UpstreamMode::Socks5,
            fail_closed,
            socks5: Some(Socks5Config {
                server: server.to_string(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn direct_is_the_default_and_fail_closed_never_falls_back() {
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dst = server.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = server.accept().await {
                let _ = s.write_all(b"hi").await;
            }
        });
        let shared = test_shared(Config::default());
        let mut s = connect_tcp(&shared, dst).await.unwrap();
        assert_eq!(s.via(), "direct");
        let mut b = [0u8; 2];
        s.read_exact(&mut b).await.unwrap();
        assert_eq!(shared.upstream.status().mode, "direct");

        // A proxy that is not there.
        let dead = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        shared
            .upstream
            .apply(&socks_cfg(dead, true), &shared.platform);
        let gen = shared.upstream.generation();
        assert!(shared.upstream.dns_over_tcp());
        let e = connect_tcp(&shared, dst).await.err().unwrap();
        assert!(is_proxy_unavailable(&e), "{e}");
        let e = connect_udp(&shared, "127.0.0.1:9".parse().unwrap())
            .await
            .err()
            .unwrap();
        assert!(is_proxy_unavailable(&e), "{e}");
        assert_eq!(shared.upstream.status().state, "down");

        // Fail-open falls back to direct.
        shared
            .upstream
            .apply(&socks_cfg(dead, false), &shared.platform);
        assert_ne!(shared.upstream.generation(), gen);
        let s = connect_tcp(&shared, dst).await.unwrap();
        assert_eq!(s.via(), "direct");

        // Only network_id changed: same dialer.
        let gen = shared.upstream.generation();
        let mut cfg = socks_cfg(dead, false);
        cfg.network_id = "net-2".into();
        shared.upstream.apply(&cfg, &shared.platform);
        assert_eq!(shared.upstream.generation(), gen);
    }

    fn wg_cfg(allowed: &[&str], fail_closed: bool) -> UpstreamConfig {
        use crate::config::upstream::{keypair_from, WireGuardConfig};
        let (private, _) = keypair_from([3; 32]);
        let (_, peer) = keypair_from([9; 32]);
        UpstreamConfig {
            mode: UpstreamMode::Wireguard,
            fail_closed,
            wireguard: Some(WireGuardConfig {
                private_key: private,
                peer_public_key: peer,
                // Nobody answers: only the routing decision matters here.
                endpoint: "127.0.0.1:9".into(),
                addresses: vec!["10.9.0.2/32".into()],
                allowed_ips: allowed.iter().map(|s| s.to_string()).collect(),
                mtu: 1420,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn wireguard_fail_closed_refuses_unrouted_address_families() {
        let v6 = TcpListener::bind("[::1]:0").await.unwrap();
        let v6_dst = v6.local_addr().unwrap();
        let v4 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let v4_dst = v4.local_addr().unwrap();
        tokio::spawn(async move { while v6.accept().await.is_ok() {} });
        tokio::spawn(async move { while v4.accept().await.is_ok() {} });
        let shared = test_shared(Config::default());

        // A provider config: all IPv4, no IPv6 at all. IPv6 would leak under
        // the real address; fail_closed refuses it (TCP, UDP, and so DNS).
        shared
            .upstream
            .apply(&wg_cfg(&["0.0.0.0/0"], true), &shared.platform);
        assert_eq!(shared.upstream.via(), "wireguard");
        let e = connect_tcp(&shared, v6_dst).await.err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::AddrNotAvailable, "{e}");
        assert!(e.to_string().contains("IPv6"), "{e}");
        let e = connect_relay(&shared, v6_dst).await.err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::AddrNotAvailable, "{e}");
        let e = connect_udp(&shared, "[::1]:53".parse().unwrap())
            .await
            .err()
            .unwrap();
        assert_eq!(e.kind(), io::ErrorKind::AddrNotAvailable, "{e}");

        // Fail-open: the unrouted family goes direct, as before.
        shared
            .upstream
            .apply(&wg_cfg(&["0.0.0.0/0"], false), &shared.platform);
        assert_eq!(connect_tcp(&shared, v6_dst).await.unwrap().via(), "direct");

        // A split tunnel within a routed family keeps bypassing, also with
        // fail_closed: 127.0.0.1 is outside 10.0.0.0/8.
        shared
            .upstream
            .apply(&wg_cfg(&["10.0.0.0/8"], true), &shared.platform);
        assert_eq!(connect_tcp(&shared, v4_dst).await.unwrap().via(), "direct");
        let u = connect_udp(&shared, "127.0.0.1:9".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(u.via(), "direct");
        // ... but IPv6, which it does not route at all, is refused.
        let e = connect_tcp(&shared, v6_dst).await.err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::AddrNotAvailable, "{e}");

        // Both families routed (split within each): bypass both.
        shared
            .upstream
            .apply(&wg_cfg(&["10.0.0.0/8", "fd00::/8"], true), &shared.platform);
        assert_eq!(connect_tcp(&shared, v6_dst).await.unwrap().via(), "direct");
    }

    #[tokio::test]
    async fn split_halves_reunite() {
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dst = server.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = server.accept().await;
        });
        let shared = test_shared(Config::default());
        let s = connect_tcp(&shared, dst).await.unwrap();
        let (r, w) = s.into_split();
        let mut s = r.reunite(w).unwrap();
        assert_eq!(s.via(), "direct");
        s.set_reset_on_close();
    }
}
