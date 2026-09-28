//! Encrypted upstream DNS for the virtual resolver: DNS over TLS (RFC 7858)
//! and DNS over HTTPS (RFC 8484, HTTP/2 or HTTP/1.1).
//!
//! Only the transport to the upstream changes; inspection (policy,
//! sinkhole, CNAME cloaking, events) stays in `dns.rs`, which calls
//! [`forward`] instead of plain forwarding for the virtual resolver.
//!
//! - **DoT:** at most [`DOT_CONNS`] long-lived TLS connections per server
//!   address, each carrying many queries at once. Queries get a
//!   connection-unique ID and answers are matched on ID and question, then
//!   given the client's ID back. A connection closes after [`IDLE`] without
//!   queries, when the server closes it, or when a query times out without
//!   anything arriving on it; queries caught by a close are retried once.
//! - **DoH:** `POST` with DNS ID 0. ALPN offers `h2` and `http/1.1`; with
//!   HTTP/2 (all presets; Quad9 and Mullvad refuse HTTP/1.1) one
//!   multiplexed connection per server address carries every query. A
//!   server that picks HTTP/1.1 gets a small pool of keep-alive connections
//!   instead (one request at a time each, at most [`DOH_CONNS`]). A
//!   connection lost under a request is replaced and the request retried
//!   once.
//!
//! Servers are tried in order, skipping ones that failed recently. With
//! `fallback_plain` off nothing ever leaves in cleartext: a failure is
//! SERVFAIL.
//!
//! Every socket comes from [`connect_encrypted_upstream`], and the TLS and
//! HTTP code is generic over the stream, so upstream chaining (proxy,
//! WireGuard) only has to change that function and [`UpstreamStream`].

use super::{dns, sock, Shared};
use crate::config::{parse_root_pem, EncryptedDnsConfig, EncryptedDnsMode, EncryptedTarget};
use crate::event::now_ms;
use crate::proto::{dns as dns_proto, doh, Reader};
use parking_lot::Mutex;
use rustls::pki_types::ServerName;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::time::Instant;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

/// The byte stream TLS runs over. Upstream chaining swaps this (e.g. for a
/// boxed `AsyncRead + AsyncWrite` stream) together with
/// [`connect_encrypted_upstream`].
pub(crate) type UpstreamStream = tokio::net::TcpStream;

/// Opens the transport connection to an encrypted resolver. **All** sockets
/// of this module are created here.
pub(crate) async fn connect_encrypted_upstream(
    shared: &Shared,
    addr: SocketAddr,
) -> io::Result<UpstreamStream> {
    sock::connect_tcp(shared.platform.clone(), addr).await
}

/// TCP connect plus TLS handshake.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
/// One query on one server (including connecting).
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(4);
/// All attempts for one query.
const QUERY_DEADLINE: Duration = Duration::from_secs(8);
/// Server addresses tried per query.
const MAX_ATTEMPTS: usize = 3;
/// A failed server is tried after the others for this long.
const PENALTY: Duration = Duration::from_secs(30);
/// Idle connections are closed after this long.
const IDLE: Duration = Duration::from_secs(30);
/// DoT connections per server address.
const DOT_CONNS: usize = 2;
/// Queries on one DoT connection before another one is opened.
const DOT_SOFT_INFLIGHT: usize = 32;
/// Hard cap of queries on one DoT connection.
const DOT_MAX_INFLIGHT: usize = 1024;
/// Concurrent DoH connections (= requests) per server address.
const DOH_CONNS: usize = 6;
/// Idle DoH connections kept per server address.
const DOH_IDLE_CONNS: usize = 4;
/// Requests per DoH connection before it is retired.
const DOH_MAX_REQUESTS: u32 = 1000;
/// Bootstrap lookups (fallback_plain without addrs) are cached this long at most.
const BOOTSTRAP_MAX_TTL: u32 = 3600;

/// Counters reported in `stats` events.
#[derive(Default)]
pub(crate) struct EncryptedStats {
    pub ok: AtomicU64,
    pub failed: AtomicU64,
    pub fallback: AtomicU64,
    pub last_ok_ts: AtomicU64,
    /// Time (ms) and text of the last failure.
    pub last_error: Mutex<Option<(u64, String)>>,
}

impl EncryptedStats {
    /// The `encrypted_dns_*` fields of a `stats` event.
    pub fn snapshot(&self) -> crate::event::StatsEvent {
        let (err_ts, err) = self.last_error.lock().clone().unzip();
        crate::event::StatsEvent {
            encrypted_dns_ok: self.ok.load(Relaxed),
            encrypted_dns_failed: self.failed.load(Relaxed),
            encrypted_dns_fallback: self.fallback.load(Relaxed),
            encrypted_dns_last_ok_ts: self.last_ok_ts.load(Relaxed),
            encrypted_dns_last_error_ts: err_ts.unwrap_or(0),
            encrypted_dns_last_error: err,
            ..Default::default()
        }
    }
}

/// Engine-wide state, rebuilt when `encrypted_dns` changes.
#[derive(Default)]
pub(crate) struct EncryptedUpstream {
    session: Mutex<Option<Arc<Session>>>,
    pub stats: EncryptedStats,
}

impl EncryptedUpstream {
    /// The session for `cfg`, (re)built when the configuration changed;
    /// `None` when encrypted DNS is off.
    fn session(&self, cfg: &EncryptedDnsConfig) -> Result<Option<Arc<Session>>, String> {
        let mut cur = self.session.lock();
        if cfg.mode == EncryptedDnsMode::Off {
            *cur = None;
            return Ok(None);
        }
        if let Some(s) = cur.as_ref().filter(|s| s.config == *cfg) {
            return Ok(Some(s.clone()));
        }
        let s = Arc::new(Session::new(cfg)?);
        *cur = Some(s.clone());
        Ok(Some(s))
    }

    /// Closes idle DoH connections (DoT connections close themselves).
    pub fn expire(&self) {
        let Some(s) = self.session.lock().clone() else {
            return;
        };
        for ep in s.endpoints.lock().values() {
            let mut h2 = ep.h2.lock();
            if h2
                .as_ref()
                .is_some_and(|c| c.driver.is_finished() || c.last_used.lock().elapsed() >= IDLE)
            {
                *h2 = None;
            }
            drop(h2);
            ep.doh_idle
                .lock()
                .retain(|c| c.last_used.elapsed() < IDLE && c.requests < DOH_MAX_REQUESTS);
        }
    }
}

/// Answers `query` for the virtual resolver: encrypted when configured,
/// otherwise (or as the configured fallback) plain. Returns the answer and
/// the transport that produced it (`udp`, `tcp`, `dot`, `doh`), or the
/// transport tried and why it failed. `transport` is the client's: UDP
/// clients get answers that do not fit their payload size truncated (TC).
pub(crate) async fn forward(
    shared: &Shared,
    query: &[u8],
    transport: &'static str,
) -> Result<(Vec<u8>, &'static str), (&'static str, String)> {
    let cfg = shared.config();
    let session = match shared.encrypted_dns.session(&cfg.encrypted_dns) {
        Ok(s) => s,
        Err(e) => {
            // Validation makes this unreachable; never fall back silently.
            log::error!("encrypted DNS: {e}");
            return Err((cfg.encrypted_dns.mode.as_str(), e));
        }
    };
    let Some(session) = session else {
        return plain(shared, query, &cfg.upstream_dns, transport).await;
    };
    let label = session.mode.as_str();
    let stats = &shared.encrypted_dns.stats;
    match session.query(shared, query).await {
        Ok(resp) => {
            stats.ok.fetch_add(1, Relaxed);
            stats.last_ok_ts.store(now_ms(), Relaxed);
            let resp = if transport == "udp" {
                fit_udp(query, resp)
            } else {
                resp
            };
            Ok((resp, label))
        }
        Err(e) => {
            stats.failed.fetch_add(1, Relaxed);
            *stats.last_error.lock() = Some((now_ms(), e.clone()));
            log::debug!("encrypted DNS failed: {e}");
            if session.fallback_plain {
                stats.fallback.fetch_add(1, Relaxed);
                plain(shared, query, &cfg.upstream_dns, transport).await
            } else {
                Err((label, format!("upstream unreachable ({label}: {e})")))
            }
        }
    }
}

async fn plain(
    shared: &Shared,
    query: &[u8],
    servers: &[SocketAddr],
    transport: &'static str,
) -> Result<(Vec<u8>, &'static str), (&'static str, String)> {
    dns::forward(shared, query, servers, transport)
        .await
        .ok_or(("udp", "upstream unreachable".to_string()))
}

/// One `encrypted_dns` configuration's servers and connections.
struct Session {
    config: EncryptedDnsConfig,
    mode: EncryptedDnsMode,
    fallback_plain: bool,
    targets: Vec<Arc<EncryptedTarget>>,
    tls: TlsConnector,
    endpoints: Mutex<HashMap<(usize, SocketAddr), Arc<Endpoint>>>,
    /// (target index, address) → tried after the others until.
    penalty: Mutex<HashMap<(usize, IpAddr), Instant>>,
    /// Host → looked-up addresses and expiry (fallback_plain only).
    bootstrap: Mutex<HashMap<String, (Vec<IpAddr>, Instant)>>,
}

impl Session {
    fn new(cfg: &EncryptedDnsConfig) -> Result<Self, String> {
        let targets = cfg.targets()?.into_iter().map(Arc::new).collect();
        let alpn: &[&[u8]] = match cfg.mode {
            EncryptedDnsMode::Doh => &[b"h2", b"http/1.1"],
            _ => &[],
        };
        Ok(Self {
            config: cfg.clone(),
            mode: cfg.mode,
            fallback_plain: cfg.fallback_plain,
            targets,
            tls: TlsConnector::from(tls_config(cfg.extra_root_ca_pem.as_deref(), alpn)?),
            endpoints: Mutex::new(HashMap::new()),
            penalty: Mutex::new(HashMap::new()),
            bootstrap: Mutex::new(HashMap::new()),
        })
    }

    /// Tries the servers in order (recently failed ones last) until one
    /// answers, within [`QUERY_DEADLINE`] and [`MAX_ATTEMPTS`].
    async fn query(&self, shared: &Shared, query: &[u8]) -> Result<Vec<u8>, String> {
        if query.len() < 12 {
            return Err("short query".into());
        }
        let deadline = Instant::now() + QUERY_DEADLINE;
        let order = {
            let now = Instant::now();
            let mut penalty = self.penalty.lock();
            penalty.retain(|_, until| *until > now);
            let mut order: Vec<usize> = (0..self.targets.len()).collect();
            // Servers whose every address failed recently go last.
            order.sort_by_key(|&i| {
                let t = &self.targets[i];
                !t.addrs.is_empty() && t.addrs.iter().all(|a| penalty.contains_key(&(i, *a)))
            });
            order
        };
        let mut attempts = 0;
        let mut last_err = String::from("no server address");
        for ti in order {
            let target = self.targets[ti].clone();
            let mut addrs = if target.addrs.is_empty() {
                match self.bootstrap(shared, &target.host).await {
                    Ok(a) => a,
                    Err(e) => {
                        last_err = format!("{}: {e}", target.host);
                        continue;
                    }
                }
            } else {
                target.addrs.clone()
            };
            {
                let penalty = self.penalty.lock();
                addrs.sort_by_key(|a| penalty.contains_key(&(ti, *a)));
            }
            for ip in addrs {
                if attempts >= MAX_ATTEMPTS {
                    return Err(last_err);
                }
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(last_err);
                }
                attempts += 1;
                let addr = SocketAddr::new(ip, target.port);
                let ep = self.endpoint(ti, addr, &target);
                let r = tokio::time::timeout(
                    left.min(ATTEMPT_TIMEOUT),
                    ep.query(shared, &self.tls, self.mode, query),
                )
                .await
                .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "timed out")));
                match r {
                    Ok(resp) => {
                        self.penalty.lock().remove(&(ti, ip));
                        return Ok(resp);
                    }
                    Err(e) => {
                        log::debug!("{} {}: {e}", self.mode.as_str(), addr);
                        last_err = format!("{} ({addr}): {e}", target.host);
                        self.penalty
                            .lock()
                            .insert((ti, ip), Instant::now() + PENALTY);
                    }
                }
            }
        }
        Err(last_err)
    }

    fn endpoint(
        &self,
        ti: usize,
        addr: SocketAddr,
        target: &Arc<EncryptedTarget>,
    ) -> Arc<Endpoint> {
        self.endpoints
            .lock()
            .entry((ti, addr))
            .or_insert_with(|| {
                Arc::new(Endpoint {
                    target: target.clone(),
                    addr,
                    dot: tokio::sync::Mutex::new(Vec::new()),
                    http1: Default::default(),
                    h2: Mutex::new(None),
                    h2_connect: tokio::sync::Mutex::new(()),
                    doh_idle: Mutex::new(Vec::new()),
                    doh_slots: Semaphore::new(DOH_CONNS),
                })
            })
            .clone()
    }

    /// Looks `host` up over plain DNS (only reachable with fallback_plain).
    async fn bootstrap(&self, shared: &Shared, host: &str) -> Result<Vec<IpAddr>, String> {
        if let Some((a, until)) = self.bootstrap.lock().get(host) {
            if *until > Instant::now() {
                return Ok(a.clone());
            }
        }
        let servers = shared.config().upstream_dns.clone();
        let mut addrs = Vec::new();
        let mut ttl = BOOTSTRAP_MAX_TTL;
        for qtype in [dns_proto::TYPE_A, dns_proto::TYPE_AAAA] {
            let q = dns_proto::build_query(rand_id(), host, qtype);
            if let Some((resp, _)) = dns::forward(shared, &q, &servers, "tcp").await {
                if let Some(m) = dns_proto::parse(&resp) {
                    ttl = ttl.min(m.min_ttl().unwrap_or(300).max(30));
                    addrs.extend(m.answer_ips());
                }
            }
        }
        if addrs.is_empty() {
            return Err("bootstrap lookup failed".into());
        }
        addrs.truncate(4);
        self.bootstrap.lock().insert(
            host.to_string(),
            (
                addrs.clone(),
                Instant::now() + Duration::from_secs(ttl as u64),
            ),
        );
        Ok(addrs)
    }
}

/// A pseudo-random DNS ID (bootstrap queries only).
fn rand_id() -> u16 {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    (t.subsec_nanos() ^ (t.as_secs() as u32).rotate_left(16)) as u16
}

/// Rustls client configuration: ring provider, Mozilla roots (plus
/// `extra_pem`), TLS 1.2 and 1.3, in-memory session resumption.
pub(crate) fn tls_config(
    extra_pem: Option<&str>,
    alpn: &[&[u8]],
) -> Result<Arc<rustls::ClientConfig>, String> {
    let mut roots =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(pem) = extra_pem {
        roots.roots.extend(parse_root_pem(pem)?.roots);
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut c = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    c.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(Arc::new(c))
}

/// TLS handshake over `stream`, verifying the certificate for `host`
/// (sent as SNI unless it is an IP address).
pub(crate) async fn tls_handshake<S>(
    tls: &TlsConnector,
    host: &str,
    stream: S,
) -> io::Result<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let name = ServerName::try_from(host.to_string())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    tls.connect(name, stream).await
}

/// Connections to one address of one server.
struct Endpoint {
    target: Arc<EncryptedTarget>,
    addr: SocketAddr,
    /// Held while choosing or opening a connection, so a burst of queries
    /// opens one connection, not one each.
    dot: tokio::sync::Mutex<Vec<Arc<DotConn>>>,
    /// The server did not negotiate HTTP/2: use the HTTP/1.1 pool.
    http1: std::sync::atomic::AtomicBool,
    h2: Mutex<Option<H2Conn>>,
    /// Held while opening the HTTP/2 connection.
    h2_connect: tokio::sync::Mutex<()>,
    doh_idle: Mutex<Vec<DohConn<TlsStream<UpstreamStream>>>>,
    /// HTTP/1.1 connections (= requests) in use.
    doh_slots: Semaphore,
}

impl Endpoint {
    async fn connect(
        &self,
        shared: &Shared,
        tls: &TlsConnector,
    ) -> io::Result<TlsStream<UpstreamStream>> {
        tokio::time::timeout(CONNECT_TIMEOUT, async {
            let tcp = connect_encrypted_upstream(shared, self.addr).await?;
            tls_handshake(tls, &self.target.host, tcp).await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))?
    }

    async fn query(
        &self,
        shared: &Shared,
        tls: &TlsConnector,
        mode: EncryptedDnsMode,
        query: &[u8],
    ) -> io::Result<Vec<u8>> {
        match mode {
            EncryptedDnsMode::Doh => self.query_doh(shared, tls, query).await,
            _ => self.query_dot(shared, tls, query).await,
        }
    }

    async fn dot_conn(&self, shared: &Shared, tls: &TlsConnector) -> io::Result<Arc<DotConn>> {
        let mut conns = self.dot.lock().await;
        conns.retain(|c| c.is_open());
        if let Some(c) = conns.iter().find(|c| c.inflight() < DOT_SOFT_INFLIGHT) {
            return Ok(c.clone());
        }
        if conns.len() < DOT_CONNS {
            let c = DotConn::spawn(self.connect(shared, tls).await?);
            conns.push(c.clone());
            return Ok(c);
        }
        conns
            .iter()
            .min_by_key(|c| c.inflight())
            .cloned()
            .ok_or_else(|| io::Error::other("no connection"))
    }

    async fn query_dot(
        &self,
        shared: &Shared,
        tls: &TlsConnector,
        query: &[u8],
    ) -> io::Result<Vec<u8>> {
        // A connection the server closed just as the query went out is
        // retried once on a new one (queries are idempotent).
        let mut tries = 0;
        loop {
            tries += 1;
            let conn = self.dot_conn(shared, tls).await?;
            match conn.query(query).await {
                Err(e) if tries < 2 && e.kind() == io::ErrorKind::ConnectionAborted => continue,
                r => return r,
            }
        }
    }

    async fn query_doh(
        &self,
        shared: &Shared,
        tls: &TlsConnector,
        query: &[u8],
    ) -> io::Result<Vec<u8>> {
        // RFC 8484 §4.1: ID 0 makes answers cacheable by HTTP caches.
        let mut wire = query.to_vec();
        wire[..2].copy_from_slice(&[0, 0]);
        let mut resp = if self.http1.load(Relaxed) {
            self.doh_http1(shared, tls, &wire, None).await?
        } else {
            self.doh_h2(shared, tls, &wire).await?
        };
        if !dns_proto::answers_query(&wire, &resp) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "answer does not match the query",
            ));
        }
        resp[..2].copy_from_slice(&query[..2]);
        Ok(resp)
    }

    /// The live HTTP/2 connection's request handle, if any.
    fn h2_sender(&self) -> Option<h2::client::SendRequest<bytes::Bytes>> {
        let mut h2 = self.h2.lock();
        if h2.as_ref().is_some_and(|c| c.driver.is_finished()) {
            *h2 = None;
        }
        h2.as_ref().map(|c| {
            *c.last_used.lock() = Instant::now();
            c.send.clone()
        })
    }

    /// DoH over the endpoint's multiplexed HTTP/2 connection, opened on
    /// first use. A server that does not negotiate `h2` (ALPN) is switched
    /// to HTTP/1.1 for good, starting with the connection just opened.
    async fn doh_h2(
        &self,
        shared: &Shared,
        tls: &TlsConnector,
        wire: &[u8],
    ) -> io::Result<Vec<u8>> {
        let uri = format!("https://{}{}", self.target.authority(), self.target.path);
        for attempt in 0..2 {
            let send = match self.h2_sender() {
                Some(s) => s,
                None => {
                    let _connecting = self.h2_connect.lock().await;
                    match self.h2_sender() {
                        Some(s) => s,
                        None => {
                            let stream = self.connect(shared, tls).await?;
                            if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
                                self.http1.store(true, Relaxed);
                                drop(_connecting);
                                let first = DohConn::new(stream);
                                return self.doh_http1(shared, tls, wire, Some(first)).await;
                            }
                            let conn = H2Conn::handshake(stream).await?;
                            let send = conn.send.clone();
                            *self.h2.lock() = Some(conn);
                            send
                        }
                    }
                }
            };
            match h2_exchange(send, &uri, wire).await {
                Ok(resp) => return Ok(resp),
                Err((e, broken)) => {
                    if broken {
                        // GOAWAY, reset or closed: reconnect (once).
                        *self.h2.lock() = None;
                        if attempt == 0 {
                            log::debug!("doh {}: h2 connection lost: {e}", self.addr);
                            continue;
                        }
                    }
                    return Err(e);
                }
            }
        }
        Err(io::Error::other("h2 connection lost"))
    }

    /// DoH over a pool of kept-alive HTTP/1.1 connections. `first` is a
    /// fresh connection to use first.
    async fn doh_http1(
        &self,
        shared: &Shared,
        tls: &TlsConnector,
        wire: &[u8],
        mut first: Option<DohConn<TlsStream<UpstreamStream>>>,
    ) -> io::Result<Vec<u8>> {
        let _slot = self
            .doh_slots
            .acquire()
            .await
            .map_err(|_| io::Error::other("closed"))?;
        let req = doh::build_post(&self.target.authority(), &self.target.path, wire);
        loop {
            let pooled = {
                let mut idle = self.doh_idle.lock();
                loop {
                    match idle.pop() {
                        Some(c) if c.last_used.elapsed() < IDLE => break Some(c),
                        Some(_) => continue,
                        None => break None,
                    }
                }
            };
            let mut conn = match (first.take(), pooled) {
                (Some(fresh), pooled) => {
                    if let Some(p) = pooled {
                        self.doh_idle.lock().push(p);
                    }
                    fresh
                }
                (None, Some(c)) => c,
                (None, None) => DohConn::new(self.connect(shared, tls).await?),
            };
            // Only a kept-alive connection may have been closed by the server.
            let reused = conn.requests > 0;
            match conn.exchange(&req).await {
                Ok((resp, reusable)) => {
                    if reusable && conn.requests < DOH_MAX_REQUESTS {
                        let mut idle = self.doh_idle.lock();
                        if idle.len() < DOH_IDLE_CONNS {
                            idle.push(conn);
                        }
                    }
                    return Ok(resp);
                }
                // The server may have closed a kept-alive connection.
                Err(e) if reused && e.kind() != io::ErrorKind::InvalidData => {
                    log::debug!("doh {}: stale connection: {e}", self.addr);
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

// ---- DoH over HTTP/2 -----------------------------------------------------

/// A multiplexed HTTP/2 connection; its driver task runs until the
/// connection ends or this handle is dropped.
struct H2Conn {
    send: h2::client::SendRequest<bytes::Bytes>,
    driver: tokio::task::AbortHandle,
    last_used: Mutex<Instant>,
}

impl Drop for H2Conn {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl H2Conn {
    async fn handshake<S>(stream: S) -> io::Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (send, conn) = h2::client::Builder::new()
            .enable_push(false)
            .initial_window_size(doh::MAX_BODY as u32)
            .handshake::<_, bytes::Bytes>(stream)
            .await
            .map_err(h2_io)?;
        let driver = tokio::spawn(async move {
            if let Err(e) = conn.await {
                log::debug!("doh h2 connection: {e}");
            }
        });
        Ok(Self {
            send,
            driver: driver.abort_handle(),
            last_used: Mutex::new(Instant::now()),
        })
    }
}

fn h2_io(e: h2::Error) -> io::Error {
    if e.is_io() {
        e.into_io()
            .unwrap_or_else(|| io::Error::other("h2 i/o error"))
    } else {
        io::Error::other(e)
    }
}

/// One `POST` on an HTTP/2 connection. The flag in the error says whether
/// the connection is unusable (the request may be retried on a new one).
pub(crate) async fn h2_exchange(
    send: h2::client::SendRequest<bytes::Bytes>,
    uri: &str,
    wire: &[u8],
) -> Result<Vec<u8>, (io::Error, bool)> {
    let invalid = |m: String| (io::Error::new(io::ErrorKind::InvalidData, m), false);
    let broken = |e: h2::Error| {
        let lost = e.is_go_away() || e.is_io() || e.reason() == Some(h2::Reason::REFUSED_STREAM);
        (h2_io(e), lost)
    };
    let req = http::Request::post(uri)
        .header(http::header::CONTENT_TYPE, doh::DNS_MESSAGE)
        .header(http::header::ACCEPT, doh::DNS_MESSAGE)
        .header(http::header::CONTENT_LENGTH, wire.len())
        .body(())
        .map_err(|e| invalid(e.to_string()))?;
    let mut send = send.ready().await.map_err(|e| (h2_io(e), true))?;
    let (resp, mut body_tx) = send
        .send_request(req, false)
        .map_err(|e| (h2_io(e), true))?;
    body_tx
        .send_data(bytes::Bytes::copy_from_slice(wire), true)
        .map_err(broken)?;
    let resp = resp.await.map_err(broken)?;
    if resp.status() != http::StatusCode::OK {
        return Err(invalid(format!("HTTP {}", resp.status().as_u16())));
    }
    let ctype = resp
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
        });
    if ctype.as_deref().is_some_and(|t| t != doh::DNS_MESSAGE) {
        return Err(invalid(format!(
            "unexpected content type {}",
            ctype.unwrap_or_default()
        )));
    }
    let mut body = resp.into_body();
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(broken)?;
        let _ = body.flow_control().release_capacity(chunk.len());
        if out.len() + chunk.len() > doh::MAX_BODY {
            return Err(invalid("response body too large".into()));
        }
        out.extend_from_slice(&chunk);
    }
    if out.len() < 12 {
        return Err(invalid("short DNS answer".into()));
    }
    Ok(out)
}

// ---- DoT ---------------------------------------------------------------

struct Waiter {
    /// The query as sent (connection-unique ID), to check the answer.
    wire: Vec<u8>,
    tx: oneshot::Sender<Vec<u8>>,
}

#[derive(Default)]
struct Pending {
    waiters: HashMap<u16, Waiter>,
    next_id: u16,
    closed: bool,
    last_used: Option<Instant>,
    last_rx: Option<Instant>,
}

impl Pending {
    fn close(&mut self) {
        self.closed = true;
        // Dropping the senders wakes every waiting query with an error.
        self.waiters.clear();
    }
}

/// One DoT connection: a writer and a reader task around a TLS stream,
/// shared by concurrent queries.
pub(crate) struct DotConn {
    out: mpsc::Sender<Vec<u8>>,
    pending: Arc<Mutex<Pending>>,
    tasks: [tokio::task::AbortHandle; 2],
}

impl Drop for DotConn {
    fn drop(&mut self) {
        self.close();
    }
}

impl DotConn {
    /// Starts the connection's tasks on an established (TLS) stream.
    pub(crate) fn spawn<S>(stream: S) -> Arc<Self>
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (rd, wr) = tokio::io::split(stream);
        let pending = Arc::new(Mutex::new(Pending::default()));
        let (out, rx) = mpsc::channel::<Vec<u8>>(64);
        let reader = tokio::spawn(dot_read_loop(rd, pending.clone()));
        let writer = tokio::spawn(dot_write_loop(wr, rx, pending.clone()));
        Arc::new(Self {
            out,
            pending,
            tasks: [reader.abort_handle(), writer.abort_handle()],
        })
    }

    pub(crate) fn is_open(&self) -> bool {
        !self.pending.lock().closed
    }

    fn inflight(&self) -> usize {
        self.pending.lock().waiters.len()
    }

    fn close(&self) {
        self.pending.lock().close();
        for t in &self.tasks {
            t.abort();
        }
    }

    /// Sends `query` and waits for its answer, which carries the query's ID.
    /// `ConnectionAborted` means the connection closed before answering.
    pub(crate) async fn query(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        if query.len() < 12 || query.len() > u16::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad query"));
        }
        let aborted = || io::Error::new(io::ErrorKind::ConnectionAborted, "connection closed");
        let (tx, rx) = oneshot::channel();
        let (id, sent_at, frame) = {
            let mut p = self.pending.lock();
            if p.closed {
                return Err(aborted());
            }
            if p.waiters.len() >= DOT_MAX_INFLIGHT {
                return Err(io::Error::other("too many queries on connection"));
            }
            let mut id = p.next_id;
            while p.waiters.contains_key(&id) {
                id = id.wrapping_add(1);
            }
            p.next_id = id.wrapping_add(1);
            let mut wire = query.to_vec();
            wire[..2].copy_from_slice(&id.to_be_bytes());
            let mut frame = Vec::with_capacity(wire.len() + 2);
            frame.extend_from_slice(&(wire.len() as u16).to_be_bytes());
            frame.extend_from_slice(&wire);
            p.waiters.insert(id, Waiter { wire, tx });
            let now = Instant::now();
            p.last_used = Some(now);
            (id, now, frame)
        };
        // Removes the waiter however this future ends (answer, error,
        // timeout or cancellation).
        struct Forget<'a>(&'a Mutex<Pending>, u16);
        impl Drop for Forget<'_> {
            fn drop(&mut self) {
                self.0.lock().waiters.remove(&self.1);
            }
        }
        let _forget = Forget(&self.pending, id);
        if self.out.send(frame).await.is_err() {
            return Err(aborted());
        }
        match tokio::time::timeout(ATTEMPT_TIMEOUT, rx).await {
            Ok(Ok(mut resp)) => {
                resp[..2].copy_from_slice(&query[..2]);
                Ok(resp)
            }
            Ok(Err(_)) => Err(aborted()),
            Err(_) => {
                // Nothing at all arrived since this query was sent: the
                // connection is dead (e.g. a silently dropped NAT mapping).
                let dead = !matches!(self.pending.lock().last_rx, Some(t) if t >= sent_at);
                if dead {
                    self.close();
                }
                Err(io::Error::new(io::ErrorKind::TimedOut, "timed out"))
            }
        }
    }
}

async fn dot_write_loop<W: AsyncWrite + Unpin>(
    mut wr: W,
    mut rx: mpsc::Receiver<Vec<u8>>,
    pending: Arc<Mutex<Pending>>,
) {
    while let Some(frame) = rx.recv().await {
        if wr.write_all(&frame).await.is_err() || wr.flush().await.is_err() {
            break;
        }
    }
    pending.lock().close();
    let _ = wr.shutdown().await;
}

/// Reads length-prefixed answers and hands them to their waiters. Reads are
/// cancel-safe (`read` into a buffer), so the idle check can interrupt them.
async fn dot_read_loop<R: AsyncRead + Unpin>(mut rd: R, pending: Arc<Mutex<Pending>>) {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = vec![0u8; 16 * 1024];
    let started = Instant::now();
    loop {
        while buf.len() >= 2 {
            let n = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            if buf.len() < 2 + n {
                break;
            }
            let msg = buf[2..2 + n].to_vec();
            buf.drain(..2 + n);
            deliver(&pending, msg);
        }
        match tokio::time::timeout(Duration::from_secs(1), rd.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&chunk[..n]);
                pending.lock().last_rx = Some(Instant::now());
            }
            Err(_) => {
                let p = pending.lock();
                if p.closed {
                    break;
                }
                let idle_since = p.last_used.unwrap_or(started);
                if p.waiters.is_empty() && idle_since.elapsed() >= IDLE {
                    break;
                }
            }
        }
    }
    pending.lock().close();
}

fn deliver(pending: &Mutex<Pending>, msg: Vec<u8>) {
    if msg.len() < 12 {
        return;
    }
    let id = u16::from_be_bytes([msg[0], msg[1]]);
    let mut p = pending.lock();
    // Answers for unknown IDs (timed-out queries) or other questions are
    // dropped.
    if p.waiters
        .get(&id)
        .is_some_and(|w| dns_proto::answers_query(&w.wire, &msg))
    {
        if let Some(w) = p.waiters.remove(&id) {
            let _ = w.tx.send(msg);
        }
    }
}

// ---- DoH ---------------------------------------------------------------

/// A kept-alive HTTP/1.1 connection.
pub(crate) struct DohConn<S> {
    io: S,
    last_used: Instant,
    requests: u32,
}

impl<S: AsyncRead + AsyncWrite + Unpin> DohConn<S> {
    pub(crate) fn new(io: S) -> Self {
        Self {
            io,
            last_used: Instant::now(),
            requests: 0,
        }
    }

    /// Sends one request and reads the whole response. Returns the body and
    /// whether the connection can carry another request. HTTP errors and
    /// wrong content types are `InvalidData`.
    pub(crate) async fn exchange(&mut self, req: &[u8]) -> io::Result<(Vec<u8>, bool)> {
        let invalid = |m: String| io::Error::new(io::ErrorKind::InvalidData, m);
        self.requests += 1;
        self.last_used = Instant::now();
        self.io.write_all(req).await?;
        self.io.flush().await?;
        let mut buf = Vec::with_capacity(1024);
        let (head, head_len) = loop {
            if let Some((head, n)) = doh::parse_head(&buf).map_err(invalid)? {
                if head.is_informational() {
                    buf.drain(..n);
                    continue;
                }
                break (head, n);
            }
            self.read_more(&mut buf).await?;
        };
        buf.drain(..head_len);
        let (body, reusable) = if head.chunked {
            loop {
                if let Some((body, used)) = doh::decode_chunked(&buf).map_err(invalid)? {
                    break (body, used == buf.len());
                }
                self.read_more(&mut buf).await?;
            }
        } else if let Some(len) = head.content_length {
            while buf.len() < len {
                self.read_more(&mut buf).await?;
            }
            let extra = buf.len() > len;
            buf.truncate(len);
            (buf, !extra)
        } else {
            // Delimited by the end of the connection.
            loop {
                match self.io.read_buf(&mut buf).await? {
                    0 => break,
                    _ if buf.len() > doh::MAX_BODY => {
                        return Err(invalid("response body too large".into()))
                    }
                    _ => {}
                }
            }
            (buf, false)
        };
        self.last_used = Instant::now();
        if head.status != 200 {
            return Err(invalid(format!("HTTP {}", head.status)));
        }
        if head
            .content_type
            .as_deref()
            .is_some_and(|t| t != doh::DNS_MESSAGE)
        {
            return Err(invalid(format!(
                "unexpected content type {}",
                head.content_type.unwrap_or_default()
            )));
        }
        if body.len() < 12 {
            return Err(invalid("short DNS answer".into()));
        }
        Ok((body, reusable && !head.close))
    }

    async fn read_more(&mut self, buf: &mut Vec<u8>) -> io::Result<()> {
        if buf.len() > doh::MAX_HEAD + doh::MAX_BODY + 4096 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "response too large",
            ));
        }
        let mut chunk = [0u8; 4096];
        match self.io.read(&mut chunk).await? {
            0 => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed mid-response",
            )),
            n => {
                buf.extend_from_slice(&chunk[..n]);
                Ok(())
            }
        }
    }
}

// ---- UDP size limit -----------------------------------------------------

/// The largest answer a UDP client accepts: its EDNS payload size, or 512.
pub(crate) fn udp_payload_limit(query: &[u8]) -> usize {
    edns_payload_size(query).map_or(512, |n| (n as usize).max(512))
}

/// The UDP payload size from the query's OPT record, if any.
fn edns_payload_size(msg: &[u8]) -> Option<u16> {
    let mut r = Reader::new(msg);
    r.skip(4)?;
    let qd = r.u16()?;
    let an = r.u16()?;
    let ns = r.u16()?;
    let ar = r.u16()?;
    for _ in 0..qd {
        skip_name(&mut r)?;
        r.skip(4)?;
    }
    for i in 0..(an as u32 + ns as u32 + ar as u32) {
        skip_name(&mut r)?;
        let rtype = r.u16()?;
        let class = r.u16()?;
        r.skip(4)?;
        r.vec16()?;
        if rtype == 41 && i >= an as u32 + ns as u32 {
            return Some(class);
        }
    }
    None
}

fn skip_name(r: &mut Reader) -> Option<()> {
    loop {
        let len = r.u8()?;
        match len {
            0 => return Some(()),
            l if l & 0xc0 == 0xc0 => return r.skip(1),
            l if l & 0xc0 == 0 => r.skip(l as usize)?,
            _ => return None,
        }
    }
}

/// Returns `resp` if it fits the client's UDP limit, otherwise a truncated
/// (TC) answer with only the question, so the client retries over TCP.
pub(crate) fn fit_udp(query: &[u8], resp: Vec<u8>) -> Vec<u8> {
    if resp.len() <= udp_payload_limit(query) {
        return resp;
    }
    truncated(&resp).unwrap_or(resp)
}

fn truncated(resp: &[u8]) -> Option<Vec<u8>> {
    let mut r = Reader::new(resp);
    r.skip(4)?;
    let qd = r.u16()?;
    r.skip(6)?;
    for _ in 0..qd {
        skip_name(&mut r)?;
        r.skip(4)?;
    }
    let mut out = resp[..r.pos()].to_vec();
    out[2] |= 0x02;
    out[6..12].fill(0);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, DuplexStream};

    fn answer_for(query: &[u8], ip: [u8; 4]) -> Vec<u8> {
        let mut r =
            dns_proto::sinkhole_response(query, dns_proto::SinkholeMode::NullIp, 60).unwrap();
        let n = r.len();
        r[n - 4..].copy_from_slice(&ip);
        r
    }

    /// Reads DoT frames from `srv` and answers them in reverse order of
    /// arrival once `batch` queries are in, each with an address derived
    /// from the query name's first label length (so mix-ups are visible).
    async fn dot_server(mut srv: DuplexStream, batch: usize) {
        let mut got = Vec::new();
        loop {
            let mut len = [0u8; 2];
            if srv.read_exact(&mut len).await.is_err() {
                return;
            }
            let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
            srv.read_exact(&mut q).await.unwrap();
            got.push(q);
            if got.len() == batch {
                for q in got.drain(..).rev() {
                    let a = answer_for(&q, [192, 0, 2, q[12]]);
                    let mut f = (a.len() as u16).to_be_bytes().to_vec();
                    f.extend_from_slice(&a);
                    // Split frames across writes to exercise reassembly.
                    let (x, y) = f.split_at(f.len() / 2);
                    srv.write_all(x).await.unwrap();
                    srv.flush().await.unwrap();
                    srv.write_all(y).await.unwrap();
                }
            }
        }
    }

    #[tokio::test]
    async fn dot_pipelines_and_matches_by_id() {
        let (cli, srv) = duplex(64 * 1024);
        tokio::spawn(dot_server(srv, 8));
        let conn = DotConn::spawn(cli);
        // Eight concurrent queries, all with the same client ID 7, for
        // names of different lengths: IDs are rewritten per connection and
        // restored in the answers.
        let mut tasks = Vec::new();
        for i in 1..=8usize {
            let conn = conn.clone();
            tasks.push(tokio::spawn(async move {
                let name = format!("{}.example", "a".repeat(i));
                let q = dns_proto::build_query(7, &name, dns_proto::TYPE_A);
                let r = conn.query(&q).await.unwrap();
                (i, q, r)
            }));
        }
        for t in tasks {
            let (i, q, r) = t.await.unwrap();
            assert!(dns_proto::answers_query(&q, &r), "ID and question restored");
            let ips: Vec<_> = dns_proto::parse(&r).unwrap().answer_ips().collect();
            assert_eq!(ips, vec![IpAddr::from([192, 0, 2, i as u8])]);
        }
        assert_eq!(conn.inflight(), 0);
        assert!(conn.is_open());
    }

    #[tokio::test]
    async fn dot_ignores_mismatched_answers_and_fails_on_close() {
        let (cli, mut srv) = duplex(64 * 1024);
        let conn = DotConn::spawn(cli);
        let q = dns_proto::build_query(1, "a.example", dns_proto::TYPE_A);
        let c2 = conn.clone();
        let task = tokio::spawn(async move { c2.query(&q).await });
        let mut len = [0u8; 2];
        srv.read_exact(&mut len).await.unwrap();
        let mut wire = vec![0u8; u16::from_be_bytes(len) as usize];
        srv.read_exact(&mut wire).await.unwrap();
        // Same ID, other question: must not be delivered.
        let mut other = dns_proto::build_query(0, "b.example", dns_proto::TYPE_A);
        other[..2].copy_from_slice(&wire[..2]);
        let bad = answer_for(&other, [192, 0, 2, 1]);
        let mut f = (bad.len() as u16).to_be_bytes().to_vec();
        f.extend_from_slice(&bad);
        srv.write_all(&f).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!task.is_finished());
        drop(srv); // server closes
        let err = task.await.unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!conn.is_open());
        let q = dns_proto::build_query(2, "a.example", dns_proto::TYPE_A);
        assert_eq!(
            conn.query(&q).await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
    }

    #[tokio::test(start_paused = true)]
    async fn dot_closes_when_idle_and_on_dead_timeouts() {
        let (cli, _srv) = duplex(1024);
        let conn = DotConn::spawn(cli);
        let q = dns_proto::build_query(3, "a.example", dns_proto::TYPE_A);
        // The server never answers: the query times out and, since nothing
        // arrived at all, the connection is considered dead.
        let err = conn.query(&q).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(!conn.is_open());

        let (cli, _srv2) = duplex(1024);
        let conn = DotConn::spawn(cli);
        tokio::time::sleep(IDLE + Duration::from_secs(2)).await;
        assert!(!conn.is_open(), "idle connection closed");
    }

    /// Serves one HTTP exchange per call of `respond`.
    async fn http_server(mut srv: DuplexStream, responses: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        let mut requests = Vec::new();
        for resp in responses {
            let mut buf = Vec::new();
            let mut b = [0u8; 1];
            // Head, then Content-Length bytes.
            while !buf.ends_with(b"\r\n\r\n") {
                if srv.read_exact(&mut b).await.is_err() {
                    return requests;
                }
                buf.push(b[0]);
            }
            let head = String::from_utf8_lossy(&buf).to_string();
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("Content-Length: "))
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            let mut body = vec![0u8; len];
            srv.read_exact(&mut body).await.unwrap();
            buf.extend_from_slice(&body);
            requests.push(buf);
            srv.write_all(&resp).await.unwrap();
        }
        requests
    }

    fn http_ok(body: &[u8], extra: &str) -> Vec<u8> {
        let mut r = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n{extra}Content-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        r.extend_from_slice(body);
        r
    }

    #[tokio::test]
    async fn doh_exchange_keeps_alive_and_decodes() {
        let (cli, srv) = duplex(64 * 1024);
        let q = dns_proto::build_query(0, "a.example", dns_proto::TYPE_A);
        let a = answer_for(&q, [192, 0, 2, 9]);
        let mut chunked =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n"
                .to_vec();
        let (x, y) = a.split_at(5);
        chunked.extend_from_slice(format!("{:x}\r\n", x.len()).as_bytes());
        chunked.extend_from_slice(x);
        chunked.extend_from_slice(format!("\r\n{:x}\r\n", y.len()).as_bytes());
        chunked.extend_from_slice(y);
        chunked.extend_from_slice(b"\r\n0\r\n\r\n");
        let responses = vec![
            http_ok(&a, ""),
            chunked,
            b"HTTP/1.1 100 Continue\r\n\r\n"
                .iter()
                .chain(http_ok(&a, "Connection: close\r\n").iter())
                .copied()
                .collect(),
        ];
        let server = tokio::spawn(http_server(srv, responses));
        let mut conn = DohConn::new(cli);
        let req = doh::build_post("dns.example", "/dns-query", &q);
        assert_eq!(conn.exchange(&req).await.unwrap(), (a.clone(), true));
        assert_eq!(conn.exchange(&req).await.unwrap(), (a.clone(), true));
        assert_eq!(conn.exchange(&req).await.unwrap(), (a.clone(), false));
        let requests = server.await.unwrap();
        assert_eq!(requests.len(), 3);
        assert!(requests[0].ends_with(&q));
    }

    #[tokio::test]
    async fn doh_http_errors_are_invalid_data() {
        let html = String::from_utf8_lossy(&http_ok(&[0u8; 12], ""))
            .replace("application/dns-message", "text/html")
            .into_bytes();
        for resp in [
            b"HTTP/1.1 500 Oops\r\nContent-Length: 0\r\n\r\n".to_vec(),
            html,
        ] {
            let (cli, srv) = duplex(64 * 1024);
            tokio::spawn(http_server(srv, vec![resp]));
            let mut conn = DohConn::new(cli);
            let req = doh::build_post("dns.example", "/dns-query", &[0u8; 12]);
            let e = conn.exchange(&req).await.unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{e}");
        }
        // Closed mid-response.
        let (cli, srv) = duplex(64 * 1024);
        tokio::spawn(async move {
            let mut srv = srv;
            let mut b = [0u8; 256];
            let _ = srv.read(&mut b).await;
            srv.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\nabc")
                .await
                .unwrap();
        });
        let mut conn = DohConn::new(cli);
        let e = conn.exchange(b"POST / HTTP/1.1\r\n\r\n").await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn udp_limit_and_truncation() {
        let plain = dns_proto::build_query(5, "big.example", dns_proto::TYPE_TXT);
        assert_eq!(udp_payload_limit(&plain), 512);
        // Same query with an OPT record advertising 1232 bytes.
        let mut edns = plain.clone();
        edns[11] = 1; // ARCOUNT
        edns.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(udp_payload_limit(&edns), 1232);
        let mut small = edns.clone();
        small[plain.len() + 3] = 0; // payload 0x00d0 = 208 → at least 512
        assert_eq!(udp_payload_limit(&small), 512);

        let mut big =
            dns_proto::sinkhole_response(&plain, dns_proto::SinkholeMode::NullIp, 1).unwrap();
        big.resize(900, 0);
        let t = fit_udp(&plain, big.clone());
        assert!(dns_proto::is_truncated(&t));
        assert!(dns_proto::answers_query(&plain, &t));
        let m = dns_proto::parse(&t).unwrap();
        assert!(m.answers.is_empty());
        assert_eq!(fit_udp(&edns, big.clone()), big, "fits the EDNS size");
    }
}

/// End-to-end over real TLS on loopback, with the committed test CA
/// (`testdata/edns`, test-only keys) as an extra root.
#[cfg(test)]
mod tls_tests {
    use super::super::tests::test_shared;
    use super::*;
    use crate::config::{Config, EncryptedDnsServer};
    use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
    use std::sync::atomic::AtomicUsize;
    use tokio_rustls::TlsAcceptor;

    const CA: &str = include_str!("../../testdata/edns/ca.pem");
    const CERT: &str = include_str!("../../testdata/edns/server.pem");
    const KEY: &str = include_str!("../../testdata/edns/server.key");
    const HOST: &str = "dns.vigil.test";
    const ANSWER_IP: [u8; 4] = [192, 0, 2, 53];

    fn acceptor(alpn: &[&[u8]]) -> TlsAcceptor {
        let certs: Vec<_> = CertificateDer::pem_slice_iter(CERT.as_bytes())
            .collect::<Result<_, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_slice(KEY.as_bytes()).unwrap();
        let mut c = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
        c.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        TlsAcceptor::from(Arc::new(c))
    }

    fn answer(q: &[u8]) -> Vec<u8> {
        let mut r = dns_proto::sinkhole_response(q, dns_proto::SinkholeMode::NullIp, 60).unwrap();
        let n = r.len();
        if dns_proto::parse(q).unwrap().questions[0].qtype == dns_proto::TYPE_A {
            r[n - 4..].copy_from_slice(&ANSWER_IP);
        }
        r
    }

    /// A DoT or DoH server on loopback; returns its address and a counter
    /// of accepted TCP connections.
    async fn server(kind: Kind) -> (SocketAddr, Arc<AtomicUsize>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let n = accepted.clone();
        let tls = acceptor(match kind {
            Kind::Dot => &[],
            Kind::Http1 => &[b"http/1.1"],
            Kind::H2 => &[b"h2"],
        });
        tokio::spawn(async move {
            while let Ok((tcp, _)) = l.accept().await {
                n.fetch_add(1, Relaxed);
                let tls = tls.clone();
                tokio::spawn(async move {
                    let Ok(s) = tls.accept(tcp).await else {
                        return;
                    };
                    match kind {
                        Kind::Dot => serve_dot(s).await,
                        Kind::Http1 => serve_doh(s).await,
                        Kind::H2 => serve_h2(s).await,
                    }
                });
            }
        });
        (addr, accepted)
    }

    #[derive(Clone, Copy)]
    enum Kind {
        Dot,
        Http1,
        H2,
    }

    async fn serve_h2<S: AsyncRead + AsyncWrite + Unpin>(s: S) {
        let Ok(mut conn) = h2::server::handshake(s).await else {
            return;
        };
        while let Some(Ok((req, mut respond))) = conn.accept().await {
            tokio::spawn(async move {
                assert_eq!(req.method(), http::Method::POST);
                assert_eq!(req.uri().path(), "/dns-query");
                assert_eq!(req.headers()[http::header::CONTENT_TYPE], doh::DNS_MESSAGE);
                let mut body = req.into_body();
                let mut q = Vec::new();
                while let Some(Ok(c)) = body.data().await {
                    let _ = body.flow_control().release_capacity(c.len());
                    q.extend_from_slice(&c);
                }
                assert_eq!(&q[..2], &[0, 0], "DoH queries use ID 0");
                let a = answer(&q);
                let resp = http::Response::builder()
                    .header(http::header::CONTENT_TYPE, doh::DNS_MESSAGE)
                    .body(())
                    .unwrap();
                let mut tx = respond.send_response(resp, false).unwrap();
                tx.send_data(bytes::Bytes::from(a), true).unwrap();
            });
        }
    }

    async fn serve_dot<S: AsyncRead + AsyncWrite + Unpin>(mut s: S) {
        loop {
            let mut len = [0u8; 2];
            if s.read_exact(&mut len).await.is_err() {
                return;
            }
            let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
            if s.read_exact(&mut q).await.is_err() {
                return;
            }
            let a = answer(&q);
            let mut f = (a.len() as u16).to_be_bytes().to_vec();
            f.extend_from_slice(&a);
            if s.write_all(&f).await.is_err() {
                return;
            }
        }
    }

    async fn serve_doh<S: AsyncRead + AsyncWrite + Unpin>(mut s: S) {
        let mut buf = Vec::new();
        loop {
            let head_end = loop {
                if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break p + 4;
                }
                let mut b = [0u8; 1024];
                match s.read(&mut b).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&b[..n]),
                }
            };
            let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
            assert!(head.starts_with("POST /dns-query HTTP/1.1\r\n"), "{head}");
            assert!(head.contains(&format!("Host: {HOST}:")), "{head}");
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("Content-Length: "))
                .unwrap()
                .parse()
                .unwrap();
            while buf.len() < head_end + len {
                let mut b = [0u8; 1024];
                match s.read(&mut b).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&b[..n]),
                }
            }
            let q: Vec<u8> = buf[head_end..head_end + len].to_vec();
            buf.drain(..head_end + len);
            assert_eq!(&q[..2], &[0, 0], "DoH queries use ID 0");
            let a = answer(&q);
            let mut r = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
                a.len()
            )
            .into_bytes();
            r.extend_from_slice(&a);
            if s.write_all(&r).await.is_err() {
                return;
            }
        }
    }

    /// A plain resolver that counts the queries it gets (leak detector).
    async fn plain_resolver() -> (SocketAddr, Arc<AtomicUsize>) {
        let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = s.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok((n, from)) = s.recv_from(&mut buf).await {
                h.fetch_add(1, Relaxed);
                let _ = s.send_to(&answer(&buf[..n]), from).await;
            }
        });
        (addr, hits)
    }

    fn config(
        mode: EncryptedDnsMode,
        servers: Vec<(String, SocketAddr)>,
        plain: SocketAddr,
        fallback_plain: bool,
        with_ca: bool,
    ) -> Config {
        let servers = servers
            .into_iter()
            .map(|(host, addr)| match mode {
                EncryptedDnsMode::Doh => EncryptedDnsServer {
                    url: Some(format!("https://{host}:{}/dns-query", addr.port())),
                    addrs: vec![addr.ip()],
                    ..Default::default()
                },
                _ => EncryptedDnsServer {
                    host: Some(host),
                    addrs: vec![addr.ip()],
                    port: Some(addr.port()),
                    ..Default::default()
                },
            })
            .collect();
        let c = Config {
            upstream_dns: vec![plain],
            encrypted_dns: EncryptedDnsConfig {
                mode,
                servers,
                fallback_plain,
                extra_root_ca_pem: with_ca.then(|| CA.to_string()),
            },
            ..Default::default()
        };
        c.validate().unwrap();
        c
    }

    fn a_ips(resp: &[u8]) -> Vec<IpAddr> {
        dns_proto::parse(resp).unwrap().answer_ips().collect()
    }

    #[tokio::test]
    async fn dot_over_tls_reuses_one_connection() {
        let (addr, accepted) = server(Kind::Dot).await;
        let (plain, leaks) = plain_resolver().await;
        let shared = test_shared(config(
            EncryptedDnsMode::Dot,
            vec![(HOST.into(), addr)],
            plain,
            false,
            true,
        ));
        let mut tasks = Vec::new();
        for id in 0..20u16 {
            let s = shared.clone();
            tasks.push(tokio::spawn(async move {
                let q = dns_proto::build_query(id, &format!("n{id}.example"), dns_proto::TYPE_A);
                // The first query opens the connection, the rest share it.
                let wait = if id == 0 { 0 } else { 300 };
                tokio::time::sleep(Duration::from_millis(wait)).await;
                let (r, via) = forward(&s, &q, "udp").await.unwrap();
                assert_eq!(via, "dot");
                assert!(dns_proto::answers_query(&q, &r));
                assert_eq!(a_ips(&r), vec![IpAddr::from(ANSWER_IP)]);
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        assert_eq!(accepted.load(Relaxed), 1, "one pipelined connection");
        assert_eq!(leaks.load(Relaxed), 0, "nothing in cleartext");
        let st = shared.encrypted_dns.stats.snapshot();
        assert_eq!(st.encrypted_dns_ok, 20);
        assert!(st.encrypted_dns_last_ok_ts > 0);
    }

    #[tokio::test]
    async fn doh_over_tls_keeps_alive() {
        let (addr, accepted) = server(Kind::Http1).await;
        let (plain, leaks) = plain_resolver().await;
        let shared = test_shared(config(
            EncryptedDnsMode::Doh,
            vec![(HOST.into(), addr)],
            plain,
            false,
            true,
        ));
        for id in 0..5u16 {
            let q = dns_proto::build_query(1000 + id, "a.example", dns_proto::TYPE_A);
            let (r, via) = forward(&shared, &q, "tcp").await.unwrap();
            assert_eq!(via, "doh");
            assert!(dns_proto::answers_query(&q, &r), "client ID restored");
            assert_eq!(a_ips(&r), vec![IpAddr::from(ANSWER_IP)]);
        }
        assert_eq!(accepted.load(Relaxed), 1, "keep-alive");
        assert_eq!(leaks.load(Relaxed), 0);
    }

    #[tokio::test]
    async fn doh_over_h2_multiplexes_one_connection() {
        let (addr, accepted) = server(Kind::H2).await;
        let (plain, leaks) = plain_resolver().await;
        let shared = test_shared(config(
            EncryptedDnsMode::Doh,
            vec![(HOST.into(), addr)],
            plain,
            false,
            true,
        ));
        let q = dns_proto::build_query(77, "first.example", dns_proto::TYPE_A);
        assert_eq!(forward(&shared, &q, "udp").await.unwrap().1, "doh");
        let mut tasks = Vec::new();
        for id in 0..20u16 {
            let s = shared.clone();
            tasks.push(tokio::spawn(async move {
                let q = dns_proto::build_query(id, &format!("n{id}.example"), dns_proto::TYPE_A);
                let (r, via) = forward(&s, &q, "udp").await.unwrap();
                assert_eq!(via, "doh");
                assert!(dns_proto::answers_query(&q, &r), "client ID restored");
                assert_eq!(a_ips(&r), vec![IpAddr::from(ANSWER_IP)]);
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        assert_eq!(accepted.load(Relaxed), 1, "one multiplexed connection");
        assert_eq!(leaks.load(Relaxed), 0);
        // Idle connections are closed by housekeeping.
        let session = shared.encrypted_dns.session.lock().clone().unwrap();
        let ep = session.endpoints.lock().values().next().unwrap().clone();
        assert!(ep.h2.lock().is_some() && !ep.http1.load(Relaxed));
        *ep.h2.lock().as_ref().unwrap().last_used.lock() -= IDLE;
        shared.encrypted_dns.expire();
        assert!(ep.h2.lock().is_none());
    }

    #[tokio::test]
    async fn certificate_must_match_and_nothing_leaks() {
        let (addr, _) = server(Kind::Dot).await;
        let (plain, leaks) = plain_resolver().await;
        let q = dns_proto::build_query(9, "a.example", dns_proto::TYPE_A);
        // Wrong name, and right name without the test CA: both fail closed.
        for (host, ca) in [("other.vigil.test", true), (HOST, false)] {
            let shared = test_shared(config(
                EncryptedDnsMode::Dot,
                vec![(host.into(), addr)],
                plain,
                false,
                ca,
            ));
            let (via, why) = forward(&shared, &q, "udp").await.unwrap_err();
            assert_eq!(via, "dot");
            assert!(why.contains("upstream unreachable"), "{why}");
            let st = shared.encrypted_dns.stats.snapshot();
            assert_eq!(st.encrypted_dns_failed, 1);
            assert!(st.encrypted_dns_last_error.is_some());
        }
        assert_eq!(
            leaks.load(Relaxed),
            0,
            "no cleartext without fallback_plain"
        );
        // With fallback_plain the answer comes from the plain resolver.
        let shared = test_shared(config(
            EncryptedDnsMode::Dot,
            vec![("other.vigil.test".into(), addr)],
            plain,
            true,
            true,
        ));
        let (_, via) = forward(&shared, &q, "udp").await.unwrap();
        assert_eq!(via, "udp");
        assert_eq!(leaks.load(Relaxed), 1);
        assert_eq!(
            shared.encrypted_dns.stats.snapshot().encrypted_dns_fallback,
            1
        );
    }

    #[tokio::test]
    async fn fails_over_to_the_next_server() {
        let (addr, _) = server(Kind::H2).await;
        let (plain, _) = plain_resolver().await;
        // Nothing listens on the first server's port.
        let dead = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        let shared = test_shared(config(
            EncryptedDnsMode::Doh,
            vec![(HOST.into(), dead), (HOST.into(), addr)],
            plain,
            false,
            true,
        ));
        let q = dns_proto::build_query(4, "a.example", dns_proto::TYPE_A);
        let (_, via) = forward(&shared, &q, "udp").await.unwrap();
        assert_eq!(via, "doh");
        // The dead server is now tried last.
        let session = shared.encrypted_dns.session.lock().clone().unwrap();
        assert!(session.penalty.lock().contains_key(&(0, dead.ip())));
        assert_eq!(session.penalty.lock().len(), 1);
    }

    #[tokio::test]
    async fn config_change_rebuilds_the_session() {
        let (plain, _) = plain_resolver().await;
        let (addr, _) = server(Kind::Dot).await;
        let shared = test_shared(config(
            EncryptedDnsMode::Dot,
            vec![(HOST.into(), addr)],
            plain,
            false,
            true,
        ));
        let q = dns_proto::build_query(4, "a.example", dns_proto::TYPE_A);
        assert_eq!(forward(&shared, &q, "udp").await.unwrap().1, "dot");
        *shared.config.write() = Arc::new(Config {
            upstream_dns: vec![plain],
            ..Default::default()
        });
        assert_eq!(forward(&shared, &q, "udp").await.unwrap().1, "udp");
        assert!(shared.encrypted_dns.session.lock().is_none());
    }
}
