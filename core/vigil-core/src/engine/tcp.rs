//! TCP: the SYN gate, the relay and stream sniffing.
//!
//! A new connection is held at the gate while vigil attributes it to an app,
//! checks the IP-level policy and connects to the real destination. Only if
//! the upstream connect succeeds is the SYN handed to the user-space stack
//! (which completes the handshake with the app); otherwise the app receives a
//! RST, so refused/unreachable destinations look to the app exactly as they
//! would without vigil in the path.

use super::{dns, FlowCounters, FlowKey, GaugeGuard, Shared};
use crate::event::{now_ms, Event, FlowEndEvent, FlowEvent, Severity, Verdict};
use crate::packet::{self, TcpInfo, PROTO_TCP};
use crate::policy::{Decision, Policy, DOT_PORT};
use crate::proto::http::{self, HttpRequest};
use crate::proto::tls::{self, ClientHello, Sniff};
use futures::StreamExt;
use parking_lot::Mutex;
use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

const SNIFF_WINDOW: Duration = Duration::from_secs(3);
const SNIFF_MAX: usize = 32 * 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(2 * 3600);
const COPY_BUF: usize = 16 * 1024;

pub(crate) enum MetaKind {
    Relay {
        upstream: tokio::net::TcpStream,
        event: Box<FlowEvent>,
    },
    LocalDns,
}

pub(crate) struct FlowMeta {
    pub uid: Option<u32>,
    pub admitted: Instant,
    pub kind: MetaKind,
}

pub(crate) struct Gate {
    shared: Arc<Shared>,
    stack_in: mpsc::Sender<Vec<u8>>,
    pending: Arc<Mutex<HashSet<FlowKey>>>,
}

enum GateResult {
    Admit(Box<FlowMeta>),
    Reject,
}

impl Gate {
    pub fn new(shared: Arc<Shared>, stack_in: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            shared,
            stack_in,
            pending: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn on_syn(&self, pkt: Vec<u8>, syn: TcpInfo) {
        let key = (syn.src, syn.dst);
        if !self.pending.lock().insert(key) {
            return; // retransmitted SYN while we are still deciding
        }
        let shared = self.shared.clone();
        let stack_in = self.stack_in.clone();
        let pending = self.pending.clone();
        tokio::spawn(async move {
            match gate(&shared, &syn).await {
                GateResult::Admit(meta) => {
                    shared.tcp_meta.lock().insert(key, *meta);
                    let _ = stack_in.send(pkt).await;
                }
                GateResult::Reject => {
                    if let Some(rst) = packet::build_rst_for(&syn) {
                        shared.send_to_tun(rst);
                    }
                }
            }
            pending.lock().remove(&key);
        });
    }
}

fn base_event(
    shared: &Shared,
    id: u64,
    uid: Option<u32>,
    src: SocketAddr,
    dst: SocketAddr,
    proto: &'static str,
) -> FlowEvent {
    let mut ev = FlowEvent {
        id,
        ts: now_ms(),
        proto,
        uid,
        src: src.to_string(),
        dst_ip: dst.ip().to_string(),
        dst_port: dst.port(),
        ..Default::default()
    };
    if let Some(name) = shared.dns_cache.lookup(dst.ip(), Instant::now()) {
        ev.domain = Some(name);
        ev.domain_source = Some("dns");
    }
    ev
}

/// Emits a flow that ends immediately (blocked or failed).
pub(crate) fn emit_closed_flow(shared: &Shared, ev: FlowEvent, error: Option<String>) {
    let id = ev.id;
    shared.emit(Event::Flow(ev));
    shared.emit(Event::FlowEnd(FlowEndEvent {
        id,
        ts: now_ms(),
        error,
        ..Default::default()
    }));
}

/// Applies a block decision to an event, raising threat alerts.
pub(crate) fn mark_blocked(
    shared: &Shared,
    ev: &mut FlowEvent,
    reason: &crate::policy::BlockReason,
) {
    ev.verdict = Some(Verdict::Block);
    ev.reason = Some(reason.describe());
    shared.stats.blocked.fetch_add(1, Relaxed);
    if reason.is_threat() {
        let target = ev.domain.clone().unwrap_or_else(|| ev.dst_ip.clone());
        let kind = if reason.rule.as_deref() == Some(ev.dst_ip.as_str()) {
            "threat_ip"
        } else {
            "threat_domain"
        };
        shared.alert(
            kind,
            Severity::High,
            ev.uid,
            &target,
            format!("Connection to {target} blocked: listed by {}", reason.describe()),
            serde_json::json!({ "dst": format!("{}:{}", ev.dst_ip, ev.dst_port), "category": reason.category.map(|c| c.as_str()) }),
        );
    }
}

async fn gate(shared: &Arc<Shared>, syn: &TcpInfo) -> GateResult {
    let cfg = shared.config();
    let (src, dst) = (syn.src, syn.dst);
    let uid = shared.lookup_uid(PROTO_TCP, src, dst).await;
    if cfg.is_virtual_dns(dst.ip()) {
        // DNS over TCP is answered locally; anything else (notably the
        // Private DNS probe on 853) is refused so the OS falls back to UDP.
        return if dst.port() == 53 {
            GateResult::Admit(Box::new(FlowMeta {
                uid,
                admitted: Instant::now(),
                kind: MetaKind::LocalDns,
            }))
        } else {
            GateResult::Reject
        };
    }
    shared.stats.flows_total.fetch_add(1, Relaxed);
    let mut ev = base_event(shared, shared.next_flow_id(), uid, src, dst, "tcp");
    let mut decision = shared.policy.read().check_ip(uid, dst.ip());
    if dst.port() == DOT_PORT {
        ev.tags.push("encrypted_dns");
        ev.app_proto = Some("dot");
        if decision == Decision::Allow && shared.policy.read().block_encrypted_dns {
            decision = Decision::Block(Policy::encrypted_dns_block());
        }
    }
    if let Decision::Block(reason) = decision {
        mark_blocked(shared, &mut ev, &reason);
        emit_closed_flow(shared, ev, None);
        return GateResult::Reject;
    }
    let connect = connect_protected(shared, dst);
    match tokio::time::timeout(Duration::from_millis(cfg.tcp_connect_timeout_ms), connect).await {
        Ok(Ok(upstream)) => GateResult::Admit(Box::new(FlowMeta {
            uid,
            admitted: Instant::now(),
            kind: MetaKind::Relay {
                upstream,
                event: Box::new(ev),
            },
        })),
        Ok(Err(e)) => {
            ev.verdict = Some(Verdict::Allow);
            emit_closed_flow(shared, ev, Some(format!("connect: {e}")));
            GateResult::Reject
        }
        Err(_) => {
            ev.verdict = Some(Verdict::Allow);
            emit_closed_flow(shared, ev, Some("connect: timed out".into()));
            GateResult::Reject
        }
    }
}

pub(crate) async fn connect_protected(
    shared: &Shared,
    dst: SocketAddr,
) -> io::Result<tokio::net::TcpStream> {
    let sock = if dst.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    if !shared.platform.protect(sock.as_raw_fd()) {
        return Err(io::Error::other("could not protect socket"));
    }
    let stream = sock.connect(dst).await?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

pub(crate) async fn accept_loop(shared: Arc<Shared>, mut listener: netstack_smoltcp::TcpListener) {
    while let Some((stream, src, dst)) = listener.next().await {
        let meta = shared.tcp_meta.lock().remove(&(src, dst));
        let Some(meta) = meta else {
            // Duplicate stream for a retransmitted SYN, or an unknown flow.
            continue;
        };
        let s = shared.clone();
        tokio::spawn(async move {
            match meta.kind {
                MetaKind::LocalDns => dns::serve_tcp(&s, stream, meta.uid).await,
                MetaKind::Relay { upstream, event } => relay(&s, stream, upstream, *event).await,
            }
        });
    }
}

enum Sniffed {
    Tls(ClientHello),
    Http(HttpRequest),
    Other,
}

/// Reads the start of the client stream until the protocol is identified.
/// Everything read is left in `buf` to be forwarded afterwards.
async fn sniff<R: AsyncRead + Unpin>(r: &mut R, buf: &mut Vec<u8>) -> (Sniffed, bool) {
    let deadline = tokio::time::Instant::now() + SNIFF_WINDOW;
    let mut chunk = vec![0u8; 4096];
    loop {
        let t = tls::parse_records(buf);
        let h = http::parse_request(buf);
        match (t, h) {
            (Sniff::Found(ch), _) => return (Sniffed::Tls(ch), false),
            (_, Sniff::Found(req)) => return (Sniffed::Http(req), false),
            (Sniff::NotMatched, Sniff::NotMatched) => return (Sniffed::Other, false),
            _ if buf.len() >= SNIFF_MAX => return (Sniffed::Other, false),
            _ => {}
        }
        match tokio::time::timeout_at(deadline, r.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return (Sniffed::Other, true),
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return (Sniffed::Other, false),
        }
    }
}

async fn copy_counting<R, W>(
    r: &mut R,
    w: &mut W,
    counter: &AtomicU64,
    last: &AtomicU64,
    epoch: Instant,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; COPY_BUF];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        w.write_all(&buf[..n]).await?;
        counter.fetch_add(n as u64, Relaxed);
        last.store(epoch.elapsed().as_secs(), Relaxed);
    }
}

fn apply_sniffed(shared: &Shared, ev: &mut FlowEvent, sniffed: &Sniffed) {
    match sniffed {
        Sniffed::Tls(ch) => {
            ev.app_proto = Some("tls");
            if let Some(sni) = &ch.sni {
                ev.domain = Some(sni.clone());
                ev.domain_source = Some("sni");
            }
            ev.alpn = ch.alpn.first().cloned();
            ev.tls_version = Some(tls::version_name(ch.max_version()));
            ev.ja4 = Some(ch.ja4('t'));
            ev.ech = ch.ech_active();
            if ch.ech_active() {
                ev.tags.push("ech");
            }
        }
        Sniffed::Http(req) => {
            ev.app_proto = Some("http");
            ev.http_method = Some(req.method.clone());
            if let Some(h) = &req.host {
                ev.domain = Some(h.clone());
                ev.domain_source = Some("http");
            }
            ev.tags.push("plaintext_http");
        }
        Sniffed::Other => {}
    }
    let _ = shared;
}

/// Policy decision once the destination name is known. Returns the block
/// reason, if any.
pub(crate) fn decide_named(
    shared: &Shared,
    ev: &mut FlowEvent,
) -> Option<crate::policy::BlockReason> {
    let authoritative = matches!(ev.domain_source, Some("sni" | "http" | "quic"));
    let policy = shared.policy.read();
    if let (true, Some(domain)) = (authoritative, ev.domain.as_deref()) {
        if policy.is_doh_host(domain) {
            if !ev.tags.contains(&"encrypted_dns") {
                ev.tags.push("encrypted_dns");
            }
            if policy.block_encrypted_dns {
                return Some(Policy::encrypted_dns_block());
            }
        }
        if let Decision::Block(r) = policy.check_domain(ev.uid, domain) {
            return Some(r);
        }
    }
    None
}

/// Post-decision bookkeeping shared by TCP and UDP flows.
pub(crate) fn observe_allowed(shared: &Shared, ev: &FlowEvent) {
    let target = ev.domain.clone().unwrap_or_else(|| ev.dst_ip.clone());
    if ev.tags.contains(&"encrypted_dns") {
        shared.alert(
            "encrypted_dns",
            Severity::Low,
            ev.uid,
            &target,
            format!("App uses encrypted DNS ({target}); its lookups are invisible to vigil"),
            serde_json::json!({ "dst": format!("{}:{}", ev.dst_ip, ev.dst_port) }),
        );
    }
    let cfg = shared.config();
    if let Some(hit) = shared
        .beacon
        .observe(&cfg.beacon, ev.uid, &target, Instant::now())
    {
        shared.alert(
            "beacon",
            Severity::Medium,
            ev.uid,
            &target,
            format!("Periodic connections to {target} every {:.0}s (jitter {:.0}%)", hit.mean_interval_s, hit.jitter * 100.0),
            serde_json::json!({ "interval_s": hit.mean_interval_s, "jitter": hit.jitter, "samples": hit.samples, "proto": ev.proto }),
        );
    }
}

async fn relay(
    shared: &Arc<Shared>,
    client: netstack_smoltcp::TcpStream,
    upstream: tokio::net::TcpStream,
    mut ev: FlowEvent,
) {
    let _active = GaugeGuard::new(&shared.stats.tcp_active);
    let started = Instant::now();
    let id = ev.id;
    let counters = FlowCounters::new();
    let last = AtomicU64::new(0);
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut ur, mut uw) = upstream.into_split();

    let s2c = async {
        let r = copy_counting(&mut ur, &mut cw, &counters.rx, &last, started).await;
        let _ = cw.shutdown().await;
        r
    };
    let c2s = async {
        let mut buf = Vec::with_capacity(4096);
        let (sniffed, eof) = sniff(&mut cr, &mut buf).await;
        apply_sniffed(shared, &mut ev, &sniffed);
        if let Some(reason) = decide_named(shared, &mut ev) {
            mark_blocked(shared, &mut ev, &reason);
            shared.open_flow(ev.clone(), &counters);
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "blocked"));
        }
        ev.verdict = Some(Verdict::Allow);
        shared.open_flow(ev.clone(), &counters);
        observe_allowed(shared, &ev);
        if !buf.is_empty() {
            uw.write_all(&buf).await?;
            counters.tx.fetch_add(buf.len() as u64, Relaxed);
        }
        let r = if eof {
            Ok(())
        } else {
            copy_counting(&mut cr, &mut uw, &counters.tx, &last, started).await
        };
        let _ = uw.shutdown().await;
        r
    };
    tokio::pin!(s2c, c2s);
    let (mut c2s_done, mut s2c_done) = (false, false);
    let mut error: Option<String> = None;
    let mut idle_check = tokio::time::interval(Duration::from_secs(60));
    while !(c2s_done && s2c_done) {
        tokio::select! {
            r = &mut c2s, if !c2s_done => {
                c2s_done = true;
                if let Err(e) = r {
                    if e.kind() == io::ErrorKind::PermissionDenied {
                        break;
                    }
                    error.get_or_insert_with(|| e.to_string());
                    // A reset in one direction tears down the connection.
                    if e.kind() == io::ErrorKind::ConnectionReset {
                        break;
                    }
                }
            }
            r = &mut s2c, if !s2c_done => {
                s2c_done = true;
                if let Err(e) = r {
                    error.get_or_insert_with(|| e.to_string());
                    if e.kind() == io::ErrorKind::ConnectionReset {
                        break;
                    }
                }
            }
            _ = idle_check.tick() => {
                let idle = started.elapsed().as_secs().saturating_sub(last.load(Relaxed));
                if idle >= IDLE_TIMEOUT.as_secs() {
                    error = Some("idle timeout".into());
                    break;
                }
            }
        }
    }
    shared.finish_flow(id, error);
}
