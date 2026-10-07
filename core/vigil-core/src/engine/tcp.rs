//! TCP: the SYN gate, the relay and stream sniffing.
//!
//! A new connection is held at the gate while vigil attributes it to an app,
//! checks the IP-level policy and connects to the real destination. Only if
//! the upstream connect succeeds is the SYN handed to the user-space stack
//! (which completes the handshake with the app); otherwise the app receives a
//! RST, so refused/unreachable destinations look to the app exactly as they
//! would without vigil in the path.

use super::upstream::{self, UpstreamTcp};
use super::{dns, FlowCounters, FlowCut, FlowKey, GaugeGuard, Shared};
use crate::event::{now_ms, Event, FlowEndEvent, FlowEvent, Severity, Verdict};
use crate::packet::{self, TcpInfo, PROTO_TCP};
use crate::policy::{is_doh_ip, Decision, Policy, DOT_PORT};
use crate::proto::http::{self, HttpRequest};
use crate::proto::tls::{self, ClientHello, Sniff};
use futures::StreamExt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, OwnedSemaphorePermit};

const SNIFF_WINDOW: Duration = Duration::from_secs(3);
/// Bytes buffered while sniffing: the largest ClientHello parsed plus room
/// for its handshake and record headers (64 records of 5 bytes, e.g.
/// 16 KiB records or fragments down to about 1 KiB). Held only until the
/// sniffed bytes are forwarded.
const SNIFF_MAX: usize = tls::MAX_HELLO_LEN + 4 + 64 * 5;
const IDLE_TIMEOUT: Duration = Duration::from_secs(2 * 3600);
const COPY_BUF: usize = 16 * 1024;

pub(crate) enum MetaKind {
    Relay {
        upstream: UpstreamTcp,
        event: Box<FlowEvent>,
    },
    /// DNS over TCP, answered by vigil's resolver: `upstream` is `None` for
    /// the virtual resolver, or the server the app addressed directly.
    LocalDns { upstream: Option<SocketAddr> },
}

/// A TCP connection's place in the engine: its key in `Shared::tcp_keys`
/// (so retransmitted SYNs are ignored) and its `max_tcp_flows` permit. Both
/// are released when the slot is dropped, i.e. when the connection ends.
pub(crate) struct FlowSlot {
    shared: Weak<Shared>,
    key: FlowKey,
    _permit: OwnedSemaphorePermit,
}

impl Drop for FlowSlot {
    fn drop(&mut self) {
        if let Some(s) = self.shared.upgrade() {
            s.tcp_keys.lock().remove(&self.key);
        }
    }
}

pub(crate) struct FlowMeta {
    pub uid: Option<u32>,
    pub admitted: Instant,
    pub kind: MetaKind,
    slot: FlowSlot,
}

pub(crate) struct Gate {
    shared: Arc<Shared>,
    stack_in: mpsc::Sender<Vec<u8>>,
}

enum GateResult {
    Admit(Option<u32>, MetaKind),
    Reject,
}

impl Gate {
    pub fn new(shared: Arc<Shared>, stack_in: mpsc::Sender<Vec<u8>>) -> Self {
        Self { shared, stack_in }
    }

    pub fn on_syn(&self, pkt: Vec<u8>, syn: TcpInfo) {
        let key = (syn.src, syn.dst);
        if !self.shared.tcp_keys.lock().insert(key) {
            // A retransmitted SYN for a connection being decided, parked or
            // relayed. smoltcp retransmits its own SYN-ACK; passing this on
            // would create a duplicate socket (and, after the metadata was
            // taken, a second upstream connection).
            //
            // Unless the app had already closed its side of that connection:
            // then it reuses the port for a new one. End the old relay; its
            // key is released and the app's retransmitted SYN is admitted.
            if let Some(old) = self.shared.tcp_half_closed.lock().remove(&key) {
                log::debug!("new SYN on half-closed {} -> {}", syn.src, syn.dst);
                old.abort();
            }
            return;
        }
        let refuse = |why: &str| {
            log::debug!("refusing {} -> {}: {why}", syn.src, syn.dst);
            self.shared.tcp_keys.lock().remove(&key);
            if let Some(rst) = packet::build_rst_for(&syn) {
                self.shared.send_to_tun(rst);
            }
        };
        let Ok(pending) = self.shared.limits.gate.clone().try_acquire_owned() else {
            return refuse("too many connections pending");
        };
        let Ok(permit) = self.shared.limits.tcp.clone().try_acquire_owned() else {
            return refuse("too many TCP connections");
        };
        let slot = FlowSlot {
            shared: Arc::downgrade(&self.shared),
            key,
            _permit: permit,
        };
        let shared = self.shared.clone();
        let stack_in = self.stack_in.clone();
        tokio::spawn(async move {
            let _pending = pending;
            match gate(&shared, &syn).await {
                GateResult::Admit(uid, kind) => {
                    let meta = FlowMeta {
                        uid,
                        admitted: Instant::now(),
                        kind,
                        slot,
                    };
                    shared.tcp_meta.lock().insert(key, meta);
                    let _ = stack_in.send(pkt).await;
                }
                GateResult::Reject => {
                    drop(slot);
                    if let Some(rst) = packet::build_rst_for(&syn) {
                        shared.send_to_tun(rst);
                    }
                }
            }
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
        asn: shared.policy.read().asn_lookup(dst.ip()),
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
        let (kind, target) = if reason.ip_match {
            // For NAT64 addresses the rule is the embedded IPv4 address.
            let ip = reason.rule.clone().unwrap_or_else(|| ev.dst_ip.clone());
            ("threat_ip", ip)
        } else {
            let name = ev.domain.clone().unwrap_or_else(|| ev.dst_ip.clone());
            ("threat_domain", name)
        };
        shared.alert(
            kind,
            Severity::High,
            ev.uid,
            &reason.alert_key(),
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
            GateResult::Admit(uid, MetaKind::LocalDns { upstream: None })
        } else {
            GateResult::Reject
        };
    }
    if dst.port() == 53 {
        // DNS over TCP to a hard-coded resolver: inspected like UDP queries
        // to it (policy, sinkholing, alert) and forwarded to that server.
        // The server itself is checked first, like any destination (app
        // block, IP feeds), so a blocked app cannot use it as a channel.
        let decision = shared.policy.read().check_ip(uid, dst.ip());
        if let Decision::Block(reason) = decision {
            shared.stats.flows_total.fetch_add(1, Relaxed);
            let mut ev = base_event(shared, shared.next_flow_id(), uid, src, dst, "tcp");
            mark_blocked(shared, &mut ev, &reason);
            emit_closed_flow(shared, ev, None);
            return GateResult::Reject;
        }
        return GateResult::Admit(
            uid,
            MetaKind::LocalDns {
                upstream: Some(dst),
            },
        );
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
    ev.via = Some(shared.upstream.via());
    let connect = upstream::connect_relay(shared, dst);
    match tokio::time::timeout(Duration::from_millis(cfg.tcp_connect_timeout_ms), connect).await {
        Ok(Ok(upstream)) => {
            ev.via = Some(upstream.via());
            GateResult::Admit(
                uid,
                MetaKind::Relay {
                    upstream,
                    event: Box::new(ev),
                },
            )
        }
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

pub(crate) async fn accept_loop(shared: Arc<Shared>, mut listener: netstack_smoltcp::TcpListener) {
    while let Some((stream, src, dst)) = listener.next().await {
        let meta = shared.tcp_meta.lock().remove(&(src, dst));
        let Some(meta) = meta else {
            // Unknown flow (e.g. its metadata expired).
            continue;
        };
        let s = shared.clone();
        tokio::spawn(async move {
            let FlowMeta {
                uid, kind, slot, ..
            } = meta;
            match kind {
                MetaKind::LocalDns { upstream } => dns::serve_tcp(&s, stream, uid, upstream).await,
                MetaKind::Relay { upstream, event } => relay(&s, stream, upstream, *event).await,
            }
            drop(slot);
        });
    }
}

enum Sniffed {
    Tls(ClientHello),
    Http(HttpRequest),
    Other,
}

/// How the client stream stood when sniffing stopped.
enum SniffEnd {
    /// More data may follow.
    Open,
    /// The client finished sending (EOF).
    Eof,
    /// Reading failed (e.g. the client reset the connection).
    Failed(io::Error),
}

/// Reads the start of the client stream until the protocol is identified.
/// Everything read is left in `buf` to be forwarded afterwards.
async fn sniff<R: AsyncRead + Unpin>(r: &mut R, buf: &mut Vec<u8>) -> (Sniffed, SniffEnd) {
    let deadline = tokio::time::Instant::now() + SNIFF_WINDOW;
    let mut chunk = vec![0u8; 4096];
    loop {
        let t = tls::parse_records(buf);
        let h = http::parse_request(buf);
        match (t, h) {
            (Sniff::Found(ch), _) => return (Sniffed::Tls(ch), SniffEnd::Open),
            (_, Sniff::Found(req)) => return (Sniffed::Http(req), SniffEnd::Open),
            (Sniff::NotMatched, Sniff::NotMatched) => return (Sniffed::Other, SniffEnd::Open),
            _ if buf.len() >= SNIFF_MAX => return (Sniffed::Other, SniffEnd::Open),
            _ => {}
        }
        match tokio::time::timeout_at(deadline, r.read(&mut chunk)).await {
            Ok(Ok(0)) => return (Sniffed::Other, SniffEnd::Eof),
            Ok(Err(e)) => return (Sniffed::Other, SniffEnd::Failed(e)),
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return (Sniffed::Other, SniffEnd::Open),
        }
    }
}

/// Which end of a relayed connection failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    Client,
    Upstream,
}

struct RelayError {
    side: Side,
    err: io::Error,
}

impl RelayError {
    fn on(side: Side) -> impl FnOnce(io::Error) -> Self {
        move |err| Self { side, err }
    }
}

/// Copies `r` to `w` until EOF. Errors are attributed to the side whose
/// socket failed: `rs` for reads, `ws` for writes.
async fn copy_counting<R, W>(
    r: &mut R,
    w: &mut W,
    (rs, ws): (Side, Side),
    counter: &AtomicU64,
    last: &AtomicU64,
    epoch: Instant,
) -> Result<(), RelayError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; COPY_BUF];
    loop {
        let n = r.read(&mut buf).await.map_err(RelayError::on(rs))?;
        if n == 0 {
            return Ok(());
        }
        w.write_all(&buf[..n]).await.map_err(RelayError::on(ws))?;
        counter.fetch_add(n as u64, Relaxed);
        last.store(epoch.elapsed().as_secs(), Relaxed);
    }
}

fn apply_sniffed(ev: &mut FlowEvent, sniffed: &Sniffed) {
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
}

/// Policy decision once the destination name is known. Returns the block
/// reason, if any. Without a name the app sent, a connection to port 443 of
/// a well-known DoH resolver address counts as encrypted DNS (DoH to an IP
/// literal sends no SNI).
pub(crate) fn decide_named(
    shared: &Shared,
    ev: &mut FlowEvent,
) -> Option<crate::policy::BlockReason> {
    let authoritative = matches!(ev.domain_source, Some("sni" | "http" | "quic"));
    let policy = shared.policy.read();
    let name = ev.domain.as_deref().filter(|_| authoritative);
    let doh = match name {
        Some(domain) => policy.is_doh_host(domain),
        None => {
            ev.dst_port == 443
                && ev.dst_ip.parse().is_ok_and(|ip: IpAddr| {
                    is_doh_ip(policy.nat64_v4(ip).map(IpAddr::V4).unwrap_or(ip))
                })
        }
    };
    if doh {
        if !ev.tags.contains(&"encrypted_dns") {
            ev.tags.push("encrypted_dns");
        }
        if policy.block_encrypted_dns {
            return Some(Policy::encrypted_dns_block());
        }
    }
    if let Some(domain) = name {
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
            &target,
            format!("App uses encrypted DNS ({target}); its lookups are invisible to vigil"),
            serde_json::json!({ "dst": format!("{}:{}", ev.dst_ip, ev.dst_port) }),
        );
    }
    let cfg = shared.config();
    // Known push/keep-alive services (by a name the app sent) are exempt.
    let ignored = matches!(ev.domain_source, Some("sni" | "http" | "quic"))
        && ev
            .domain
            .as_deref()
            .is_some_and(|d| cfg.beacon.is_ignored(d));
    if ignored {
        return;
    }
    if let Some(hit) = shared
        .beacon
        .observe(&cfg.beacon, ev.uid, &target, Instant::now())
    {
        shared.alert(
            "beacon",
            Severity::Medium,
            ev.uid,
            &target,
            &target,
            format!("Periodic connections to {target} every {:.0}s (jitter {:.0}%)", hit.mean_interval_s, hit.jitter * 100.0),
            serde_json::json!({ "kind": "connections", "interval_s": hit.mean_interval_s, "jitter": hit.jitter, "samples": hit.samples, "proto": ev.proto }),
        );
    }
}

/// Matches the flow's JA4 fingerprint against the loaded feeds. On a hit it
/// records `ja4_match` on the event and raises a `threat_ja4` alert (one per
/// fingerprint and app per hour). Returns a block reason when
/// `block_ja4_matches` is on and the (SNI/QUIC/Host) name is not on the user
/// allowlist (or the app's own allow rules). Called before any client byte is forwarded, so a block resets
/// the connection before the handshake reaches the server.
pub(crate) fn check_ja4(shared: &Shared, ev: &mut FlowEvent) -> Option<crate::policy::BlockReason> {
    let ja4 = ev.ja4.as_deref()?;
    let (m, block) = {
        let policy = shared.policy.read();
        let m = policy.match_ja4(ja4)?;
        let authoritative = matches!(ev.domain_source, Some("sni" | "http" | "quic"));
        let allowlisted = authoritative
            && ev
                .domain
                .as_deref()
                .is_some_and(|d| policy.is_allowlisted_for(ev.uid, d));
        (m, policy.block_ja4 && !allowlisted)
    };
    let dst = format!("{}:{}", ev.dst_ip, ev.dst_port);
    let target = ev.domain.clone().unwrap_or_else(|| dst.clone());
    let what = m.label.as_deref().unwrap_or("a listed client");
    shared.alert(
        "threat_ja4",
        Severity::High,
        ev.uid,
        ja4,
        ja4,
        format!(
            "TLS fingerprint of {what} (JA4 {ja4}, feed {}) in a connection to {target}{}",
            m.feed,
            if block { "; blocked" } else { "" }
        ),
        serde_json::json!({
            "ja4": ja4,
            "rule": m.rule,
            "label": m.label,
            "feed": m.feed,
            "dst": dst,
            "domain": ev.domain,
            "proto": ev.app_proto.unwrap_or(ev.proto),
            "blocked": block,
        }),
    );
    let reason = block.then(|| Policy::ja4_block(&m));
    ev.ja4_match = Some(m);
    reason
}

/// Why a relay ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayEnd {
    /// Both directions finished normally.
    Closed,
    /// The name was blocked after sniffing.
    Blocked,
    /// One side failed (typically: reset); the other side is reset too.
    Failed(Side),
    IdleTimeout,
}

async fn relay(
    shared: &Arc<Shared>,
    client: netstack_smoltcp::TcpStream,
    upstream: UpstreamTcp,
    mut ev: FlowEvent,
) {
    let _active = GaugeGuard::new(&shared.stats.tcp_active);
    let started = Instant::now();
    let id = ev.id;
    let counters = FlowCounters::new();
    let last = AtomicU64::new(0);
    let opened = AtomicBool::new(false);
    let cut = FlowCut::new();
    let client_abort = client.abort_handle();
    let key = (*client.local_addr(), *client.remote_addr());
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut ur, mut uw) = upstream.into_split();
    let mut error: Option<String> = None;

    let end = {
        let s2c = async {
            let dirs = (Side::Upstream, Side::Client);
            copy_counting(&mut ur, &mut cw, dirs, &counters.rx, &last, started).await?;
            let _ = cw.shutdown().await;
            Ok::<_, RelayError>(())
        };
        let c2s = async {
            let mut buf = Vec::with_capacity(4096);
            let (sniffed, sniff_end) = sniff(&mut cr, &mut buf).await;
            apply_sniffed(&mut ev, &sniffed);
            let ja4_block = check_ja4(shared, &mut ev);
            if let Some(reason) = decide_named(shared, &mut ev).or(ja4_block) {
                mark_blocked(shared, &mut ev, &reason);
                shared.open_flow(ev.clone(), &counters);
                opened.store(true, Relaxed);
                return Ok(false);
            }
            ev.verdict = Some(Verdict::Allow);
            shared.open_cuttable_flow(ev.clone(), &counters, &cut);
            opened.store(true, Relaxed);
            if cut.cut_error_now().is_some() {
                // Cut at once (e.g. the app went to the background while
                // the connection was set up): no client byte is forwarded,
                // so nothing is learnt or alerted on either.
                return Ok(false);
            }
            observe_allowed(shared, &ev);
            if let SniffEnd::Failed(err) = sniff_end {
                return Err(RelayError {
                    side: Side::Client,
                    err,
                });
            }
            if !buf.is_empty() {
                uw.write_all(&buf)
                    .await
                    .map_err(RelayError::on(Side::Upstream))?;
                counters.tx.fetch_add(buf.len() as u64, Relaxed);
            }
            // Not kept for the connection's lifetime (up to SNIFF_MAX).
            drop(buf);
            if matches!(sniff_end, SniffEnd::Open) {
                let dirs = (Side::Client, Side::Upstream);
                copy_counting(&mut cr, &mut uw, dirs, &counters.tx, &last, started).await?;
            }
            let _ = uw.shutdown().await;
            Ok(true)
        };
        // Once the app has finished sending, nothing reads its side any
        // more: this notices when it is reset (or replaced, see on_syn)
        // while the server side is still open.
        let client_gone = client_abort.closed();
        // A per-app rule came to block the app (or this name for it).
        let cut_off = cut.cut_error();
        tokio::pin!(s2c, c2s, client_gone, cut_off);
        let (mut c2s_done, mut s2c_done) = (false, false);
        let mut idle_check = tokio::time::interval(Duration::from_secs(60));
        loop {
            if c2s_done && s2c_done {
                break RelayEnd::Closed;
            }
            // Biased: s2c's completion wins over the socket's final close.
            tokio::select! {
                biased;
                r = &mut c2s, if !c2s_done => {
                    c2s_done = true;
                    match r {
                        Ok(true) => {
                            if !s2c_done {
                                shared.tcp_half_closed.lock().insert(key, client_abort.clone());
                            }
                        }
                        Ok(false) => {
                            // Cut before forwarding: report the cut reason.
                            if let Some(e) = cut.cut_error_now() {
                                error = Some(e);
                            }
                            break RelayEnd::Blocked;
                        }
                        Err(e) => {
                            error.get_or_insert_with(|| e.err.to_string());
                            break RelayEnd::Failed(e.side);
                        }
                    }
                }
                r = &mut s2c, if !s2c_done => {
                    s2c_done = true;
                    if let Err(e) = r {
                        error.get_or_insert_with(|| e.err.to_string());
                        break RelayEnd::Failed(e.side);
                    }
                }
                _ = &mut client_gone, if c2s_done => {
                    let replaced = !shared.tcp_half_closed.lock().contains_key(&key);
                    let reason = if client_abort.is_reset() {
                        io::Error::from(io::ErrorKind::ConnectionReset).to_string()
                    } else if replaced {
                        "app reused the port for a new connection".to_string()
                    } else {
                        "client closed".to_string()
                    };
                    error.get_or_insert(reason);
                    break RelayEnd::Failed(Side::Client);
                }
                e = &mut cut_off => {
                    error = Some(e);
                    break RelayEnd::Blocked;
                }
                _ = idle_check.tick() => {
                    let idle = started.elapsed().as_secs().saturating_sub(last.load(Relaxed));
                    if idle >= IDLE_TIMEOUT.as_secs() {
                        error = Some("idle timeout".into());
                        break RelayEnd::IdleTimeout;
                    }
                }
            }
        }
    };

    shared.tcp_half_closed.lock().remove(&key);
    // Propagate aborts: whichever side failed, the other side is reset too,
    // as it would be end to end without vigil in the path.
    let reset_client = matches!(
        end,
        RelayEnd::Failed(Side::Upstream) | RelayEnd::Blocked | RelayEnd::IdleTimeout
    );
    let reset_upstream = matches!(
        end,
        RelayEnd::Failed(Side::Client) | RelayEnd::Blocked | RelayEnd::IdleTimeout
    );
    if reset_client {
        client_abort.abort();
    }
    if let Some(mut upstream) = ur.reunite(uw) {
        if reset_upstream {
            upstream.set_reset_on_close();
        }
        drop(upstream);
    }
    if !opened.load(Relaxed) {
        // Ended before the flow was reported (e.g. the server reset the
        // connection during the sniff window): report it now.
        ev.verdict = Some(Verdict::Allow);
        shared.open_flow(ev, &counters);
    }
    shared.finish_flow(id, error);
}

#[cfg(test)]
mod tests {
    use super::super::tests::test_shared_with_tun;
    use super::*;

    #[tokio::test]
    async fn sniffs_client_hellos_up_to_the_parser_limit() {
        // Post-quantum key shares and padding make hellos of tens of KiB.
        for (padding, frag) in [(40_000, 16_384), (60_000, 16_384), (40_000, 1_000)] {
            let hello = tls::build_client_hello(Some("big.example"), &["h2"], padding);
            assert!(hello.len() > 32 * 1024 && hello.len() <= tls::MAX_HELLO_LEN);
            let wire = tls::wrap_records(&hello, frag);
            let mut r: &[u8] = &wire;
            let mut buf = Vec::new();
            let (sniffed, end) = sniff(&mut r, &mut buf).await;
            let Sniffed::Tls(ch) = sniffed else {
                panic!("{padding}/{frag}: not sniffed as TLS");
            };
            assert_eq!(ch.sni.as_deref(), Some("big.example"));
            assert!(matches!(end, SniffEnd::Open));
            // Everything read is kept for forwarding.
            assert_eq!(buf, wire);
        }
    }
    use crate::config::Config;
    use crate::event::Event;
    use crate::packet::{TCP_RST, TCP_SYN};

    fn syn(src_port: u16, dst: &str) -> (Vec<u8>, TcpInfo) {
        let info = TcpInfo {
            src: format!("10.111.222.1:{src_port}").parse().unwrap(),
            dst: dst.parse().unwrap(),
            seq: 1,
            ack: 0,
            flags: TCP_SYN,
            payload_len: 0,
        };
        // The gate only forwards the packet bytes; their content is opaque.
        (vec![0x45; 40], info)
    }

    fn is_rst(pkt: &[u8]) -> bool {
        let ip = packet::parse_ip(pkt).unwrap();
        packet::parse_tcp(pkt, &ip).unwrap().flags & TCP_RST != 0
    }

    #[tokio::test]
    async fn retransmitted_syns_are_gated_once() {
        let (shared, mut tun) = test_shared_with_tun(Config::default());
        let (stack_tx, mut stack_rx) = mpsc::channel(16);
        let gate = Gate::new(shared.clone(), stack_tx);
        // DNS over TCP to the virtual resolver: admitted without upstream.
        let (pkt, info) = syn(40000, "10.111.222.2:53");
        gate.on_syn(pkt.clone(), info);
        gate.on_syn(pkt.clone(), info); // retransmit while deciding
        assert!(stack_rx.recv().await.is_some());
        assert_eq!(shared.tcp_meta.lock().len(), 1);
        gate.on_syn(pkt.clone(), info); // retransmit after admission
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            stack_rx.try_recv().is_err(),
            "SYN passed to the stack twice"
        );
        assert!(tun.try_recv().is_err());
        // Once the connection is gone the same 4-tuple may be reused.
        drop(shared.tcp_meta.lock().remove(&(info.src, info.dst)));
        assert!(shared.tcp_keys.lock().is_empty());
        gate.on_syn(pkt, info);
        assert!(stack_rx.recv().await.is_some());
    }

    #[tokio::test]
    async fn pending_connect_cap_resets_excess_syns() {
        let (shared, mut tun) = test_shared_with_tun(Config {
            max_pending_connects: 1,
            ..Default::default()
        });
        let (stack_tx, _stack_rx) = mpsc::channel(16);
        let gate = Gate::new(shared.clone(), stack_tx);
        let (p1, s1) = syn(40001, "10.111.222.2:853");
        let (p2, s2) = syn(40002, "10.111.222.2:853");
        gate.on_syn(p1, s1);
        gate.on_syn(p2, s2); // first still pending: over the cap
        let first = tun.recv().await.unwrap();
        assert!(is_rst(&first));
        let ip = packet::parse_ip(&first).unwrap();
        assert_eq!(packet::parse_tcp(&first, &ip).unwrap().dst, s2.src);
        // The first SYN is still decided (and refused: port 853 there).
        let second = tun.recv().await.unwrap();
        let ip = packet::parse_ip(&second).unwrap();
        assert_eq!(packet::parse_tcp(&second, &ip).unwrap().dst, s1.src);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(shared.tcp_keys.lock().is_empty());
        assert_eq!(shared.limits.gate.available_permits(), 1);
        assert_eq!(shared.limits.tcp.available_permits(), 4096);
    }

    #[test]
    fn ja4_matches_alert_and_optionally_block() {
        use crate::event::Event;
        use crate::intel::parse_feed;
        use crate::policy::{FeedCategory, LoadedFeed};
        const JA4: &str = "t13d190900_9dc949149365_97f8aa674fd9";
        let (shared, _tun) = test_shared_with_tun(Config {
            allow_domains: vec!["trusted.example".into()],
            ..Default::default()
        });
        shared.policy.write().set_feed(
            "ja4-test",
            LoadedFeed {
                category: FeedCategory::Ja4,
                feed: parse_feed(&format!("{JA4}  Sliver\n")),
            },
        );
        let flow = |ja4: &str, domain: &str| FlowEvent {
            uid: Some(10200),
            dst_ip: "192.0.2.7".into(),
            dst_port: 443,
            domain: Some(domain.into()),
            domain_source: Some("sni"),
            ja4: Some(ja4.into()),
            ..Default::default()
        };
        let mut other = flow("t13d1516h2_8daaf6152771_02713d6af862", "c2.example");
        assert!(check_ja4(&shared, &mut other).is_none());
        assert!(other.ja4_match.is_none());

        // Alert only by default; one alert per fingerprint and app.
        let mut ev = flow(JA4, "c2.example");
        assert!(check_ja4(&shared, &mut ev).is_none());
        let m = ev.ja4_match.clone().unwrap();
        assert_eq!(
            (m.feed.as_str(), m.rule.as_str(), m.label.as_deref()),
            ("ja4-test", JA4, Some("Sliver"))
        );
        assert!(check_ja4(&shared, &mut flow(JA4, "other.example")).is_none());
        let alerts: Vec<_> = shared
            .events
            .poll(100, Duration::ZERO)
            .into_iter()
            .filter_map(|e| match e {
                Event::Alert(a) => Some(a),
                _ => None,
            })
            .collect();
        assert_eq!(alerts.len(), 1, "{alerts:?}");
        let a = &alerts[0];
        assert_eq!(
            (a.kind, a.severity, a.target.as_str()),
            ("threat_ja4", Severity::High, JA4)
        );
        assert_eq!(a.detail["label"], "Sliver");
        assert_eq!(a.detail["dst"], "192.0.2.7:443");
        assert_eq!(a.detail["blocked"], false);
        let json = serde_json::to_value(Event::Flow(ev)).unwrap();
        assert_eq!(json["ja4_match"]["label"], "Sliver");
        assert_eq!(json["ja4_match"]["feed"], "ja4-test");

        // Block mode; the user allowlist still wins.
        shared.policy.write().block_ja4 = true;
        let mut ev = flow(JA4, "c2.example");
        let reason = check_ja4(&shared, &mut ev).expect("blocked");
        assert_eq!(reason.describe(), format!("ja4:ja4-test ({JA4})"));
        let mut trusted = flow(JA4, "api.trusted.example");
        assert!(check_ja4(&shared, &mut trusted).is_none());
        assert!(trusted.ja4_match.is_some());
    }

    /// A relay between a netstack connection from `app` and a loopback
    /// server, after the app has sent its FIN: half-closed, the server side
    /// still open. Returns the stack input, the relay task, the server's
    /// end, and the app's next sequence and acknowledgement numbers.
    async fn half_closed_relay(
        shared: &Arc<Shared>,
        app: SocketAddr,
        dst: SocketAddr,
    ) -> (
        mpsc::Sender<Vec<u8>>,
        tokio::task::JoinHandle<()>,
        tokio::net::TcpStream,
        (u32, u32),
    ) {
        use super::super::tests::{next_segment, test_stack};
        use crate::packet::{build_tcp, TCP_ACK, TCP_FIN};
        let (input, mut out, mut listener) = test_stack();
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = tokio::net::TcpStream::connect(server.local_addr().unwrap())
            .await
            .unwrap();
        let (mut server_end, _) = server.accept().await.unwrap();
        let send = |p: Vec<u8>| {
            let input = input.clone();
            async move { input.send(p).await.unwrap() }
        };
        send(build_tcp(app, dst, 1000, 0, TCP_SYN, &[]).unwrap()).await;
        let (stream, _, _) = listener.next().await.unwrap();
        let isn = next_segment(&mut out, app).await.seq;
        let ack = isn.wrapping_add(1);
        send(build_tcp(app, dst, 1001, ack, TCP_ACK, &[]).unwrap()).await;
        tokio::spawn(async move { while out.next().await.is_some() {} });
        let ev = FlowEvent {
            id: shared.next_flow_id(),
            ..Default::default()
        };
        let s = shared.clone();
        let relay = tokio::spawn(async move {
            relay(&s, stream, UpstreamTcp::Direct(upstream), ev).await;
        });
        send(build_tcp(app, dst, 1001, ack, TCP_FIN | TCP_ACK, &[]).unwrap()).await;
        // The server sees the app's FIN; its side stays open.
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(2), server_end.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0);
        for _ in 0..100 {
            if shared.tcp_half_closed.lock().contains_key(&(app, dst)) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(shared.tcp_half_closed.lock().contains_key(&(app, dst)));
        assert!(!relay.is_finished());
        (input, relay, server_end, (1002, ack))
    }

    fn flow_end_error(shared: &Shared) -> Option<String> {
        shared
            .events
            .poll(100, Duration::ZERO)
            .into_iter()
            .find_map(|e| match e {
                Event::FlowEnd(f) => Some(f.error),
                _ => None,
            })
            .flatten()
    }

    #[tokio::test]
    async fn half_closed_relay_ends_when_the_app_resets() {
        let (shared, _tun) = test_shared_with_tun(Config::default());
        let (app, dst) = (
            "10.0.0.2:40000".parse().unwrap(),
            "192.0.2.1:443".parse().unwrap(),
        );
        let (input, relay, mut server_end, (seq, _)) = half_closed_relay(&shared, app, dst).await;
        input
            .send(packet::build_tcp(app, dst, seq, 0, TCP_RST, &[]).unwrap())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), relay)
            .await
            .expect("relay still running after the app's reset")
            .unwrap();
        assert!(shared.tcp_half_closed.lock().is_empty());
        let err = flow_end_error(&shared).unwrap();
        assert!(err.contains("reset"), "{err}");
        // The server side is reset too: it already read the FIN, and after
        // an orderly close its first write would still succeed.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let w = server_end.write_all(b"late reply").await;
        assert!(matches!(
            w.unwrap_err().kind(),
            io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
        ));
    }

    #[tokio::test]
    async fn new_syn_on_half_closed_connection_replaces_it() {
        let (shared, _tun) = test_shared_with_tun(Config::default());
        let (stack_tx, _stack_rx) = mpsc::channel(16);
        let gate = Gate::new(shared.clone(), stack_tx);
        let (app, dst): (SocketAddr, SocketAddr) = (
            "10.0.0.2:40001".parse().unwrap(),
            "192.0.2.1:443".parse().unwrap(),
        );
        let (_input, relay, _server_end, _) = half_closed_relay(&shared, app, dst).await;
        // As accept_loop would have it: the connection's key is registered.
        shared.tcp_keys.lock().insert((app, dst));
        let syn = TcpInfo {
            src: app,
            dst,
            seq: 777,
            ack: 0,
            flags: TCP_SYN,
            payload_len: 0,
        };
        gate.on_syn(Vec::new(), syn);
        tokio::time::timeout(Duration::from_secs(2), relay)
            .await
            .expect("old relay still running")
            .unwrap();
        assert!(shared.tcp_half_closed.lock().is_empty());
        let err = flow_end_error(&shared).unwrap();
        assert_eq!(err, "app reused the port for a new connection");
    }

    #[tokio::test]
    async fn tcp_dns_to_a_listed_resolver_is_refused_at_the_gate() {
        use crate::intel::parse_feed;
        use crate::policy::{FeedCategory, LoadedFeed};
        let (shared, mut tun) = test_shared_with_tun(Config::default());
        shared.policy.write().set_feed(
            "c2ips",
            LoadedFeed {
                category: FeedCategory::C2,
                feed: parse_feed("192.0.2.53\n"),
            },
        );
        let (stack_tx, mut stack_rx) = mpsc::channel(16);
        let gate = Gate::new(shared.clone(), stack_tx);
        let (pkt, info) = syn(40010, "192.0.2.53:53");
        gate.on_syn(pkt.clone(), info);
        assert!(is_rst(&tun.recv().await.unwrap()));
        assert!(stack_rx.try_recv().is_err());
        let events = shared.events.poll(100, Duration::ZERO);
        assert!(events.iter().any(|e| matches!(e,
            Event::Flow(f) if f.verdict == Some(Verdict::Block) && f.dst_port == 53)));
        assert!(events
            .iter()
            .any(|e| matches!(e, Event::Alert(a) if a.kind == "threat_ip")));
        // Other resolvers are still admitted into vigil's resolver.
        let (pkt, info) = syn(40011, "192.0.2.54:53");
        gate.on_syn(pkt, info);
        assert!(stack_rx.recv().await.is_some());
        assert!(matches!(
            shared
                .tcp_meta
                .lock()
                .get(&(info.src, info.dst))
                .map(|m| &m.kind),
            Some(MetaKind::LocalDns { upstream: Some(_) })
        ));
    }

    #[tokio::test]
    async fn tcp_flow_cap_resets_excess_syns() {
        let (shared, mut tun) = test_shared_with_tun(Config {
            max_tcp_flows: 1,
            ..Default::default()
        });
        let (stack_tx, mut stack_rx) = mpsc::channel(16);
        let gate = Gate::new(shared.clone(), stack_tx);
        let (p1, s1) = syn(40003, "10.111.222.2:53");
        let (p2, s2) = syn(40004, "10.111.222.2:53");
        gate.on_syn(p1, s1);
        assert!(stack_rx.recv().await.is_some()); // admitted, holds the slot
        gate.on_syn(p2, s2);
        assert!(is_rst(&tun.recv().await.unwrap()));
    }

    #[tokio::test]
    async fn a_device_state_change_cuts_open_relays_of_the_app() {
        use super::super::tests::{next_segment, test_stack};
        use crate::config::{AppRule, DeviceState};
        use crate::packet::{build_tcp, TCP_ACK};
        let (shared, _tun) = test_shared_with_tun(Config {
            app_rules: vec![AppRule {
                uid: 10123,
                block_background: true,
                ..Default::default()
            }],
            device_state: Some(DeviceState {
                foreground_uids: Some(vec![10123]),
                ..Default::default()
            }),
            ..Default::default()
        });
        let (app, dst): (SocketAddr, SocketAddr) = (
            "10.0.0.2:40100".parse().unwrap(),
            "192.0.2.1:80".parse().unwrap(),
        );
        let (input, mut out, mut listener) = test_stack();
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = tokio::net::TcpStream::connect(server.local_addr().unwrap())
            .await
            .unwrap();
        let (mut server_end, _) = server.accept().await.unwrap();
        input
            .send(build_tcp(app, dst, 1000, 0, TCP_SYN, &[]).unwrap())
            .await
            .unwrap();
        let (stream, _, _) = listener.next().await.unwrap();
        let ack = next_segment(&mut out, app).await.seq.wrapping_add(1);
        let req = b"GET / HTTP/1.1\r\nHost: api.example\r\n\r\n";
        input
            .send(build_tcp(app, dst, 1001, ack, TCP_ACK, &[]).unwrap())
            .await
            .unwrap();
        input
            .send(build_tcp(app, dst, 1001, ack, TCP_ACK, req).unwrap())
            .await
            .unwrap();
        let (seen_tx, mut seen_rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(Ok(p)) = out.next().await {
                let ip = packet::parse_ip(&p).unwrap();
                let _ = seen_tx.send(packet::parse_tcp(&p, &ip).unwrap().flags);
            }
        });
        let ev = FlowEvent {
            id: shared.next_flow_id(),
            uid: Some(10123),
            ..Default::default()
        };
        let s = shared.clone();
        let relay = tokio::spawn(async move {
            relay(&s, stream, UpstreamTcp::Direct(upstream), ev).await;
        });
        // In the foreground: the request is relayed.
        let mut buf = vec![0u8; req.len()];
        tokio::time::timeout(Duration::from_secs(2), server_end.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..], &req[..]);
        let flow = shared
            .events
            .poll(100, Duration::ZERO)
            .into_iter()
            .find_map(|e| match e {
                Event::Flow(f) => Some(f),
                _ => None,
            })
            .unwrap();
        assert_eq!(flow.verdict, Some(Verdict::Allow));
        assert_eq!(flow.domain.as_deref(), Some("api.example"));
        // Another app's state change leaves the relay alone.
        shared.policy.write().set_state(&DeviceState {
            foreground_uids: Some(vec![10123, 10200]),
            ..Default::default()
        });
        shared.recheck_open_flows();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!relay.is_finished());
        // The app goes to the background: both sides are reset.
        shared.policy.write().set_state(&DeviceState {
            foreground_uids: Some(vec![10200]),
            ..Default::default()
        });
        shared.recheck_open_flows();
        tokio::time::timeout(Duration::from_secs(2), relay)
            .await
            .expect("relay still running after its app was blocked")
            .unwrap();
        assert_eq!(
            flow_end_error(&shared).as_deref(),
            Some("blocked: app rule: background")
        );
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let f = tokio::time::timeout_at(deadline, seen_rx.recv())
                .await
                .expect("no RST to the app")
                .unwrap();
            if f & TCP_RST != 0 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut rest = [0u8; 8];
        let r = server_end.read(&mut rest).await;
        assert!(
            matches!(&r, Err(e) if e.kind() == io::ErrorKind::ConnectionReset),
            "server side not reset: {r:?}"
        );
    }

    #[test]
    fn flows_opened_in_a_blocking_state_are_cut_before_forwarding() {
        use crate::config::{AppRule, DeviceState};
        // The app went to the background after its connection was decided
        // (`decide_named`) but before the relay opened: the relay and UDP
        // flows check `cut_error_now` before forwarding their first bytes.
        let (shared, _tun) = test_shared_with_tun(Config {
            app_rules: vec![AppRule {
                uid: 10123,
                block_background: true,
                ..Default::default()
            }],
            device_state: Some(DeviceState {
                foreground_uids: Some(vec![10200]),
                ..Default::default()
            }),
            ..Default::default()
        });
        let open = |uid: u32| {
            let cut = FlowCut::new();
            let ev = FlowEvent {
                id: shared.next_flow_id(),
                uid: Some(uid),
                verdict: Some(Verdict::Allow),
                ..Default::default()
            };
            shared.open_cuttable_flow(ev, &FlowCounters::new(), &cut);
            cut.cut_error_now()
        };
        assert_eq!(
            open(10123).as_deref(),
            Some("blocked: app rule: background")
        );
        assert_eq!(open(10200), None);
    }

    #[test]
    fn doh_to_resolver_addresses_counts_as_encrypted_dns() {
        let shared = super::super::tests::test_shared(Config {
            block_encrypted_dns: true,
            ..Default::default()
        });
        let ev = |ip: &str, port: u16, sni: Option<&str>| FlowEvent {
            dst_ip: ip.into(),
            dst_port: port,
            domain: sni.map(str::to_string).or(Some("dns.example".into())),
            domain_source: Some(if sni.is_some() { "sni" } else { "dns" }),
            ..Default::default()
        };
        let decide = |mut e: FlowEvent| {
            let r = decide_named(&shared, &mut e).map(|r| r.describe());
            (r, e.tags.contains(&"encrypted_dns"))
        };
        let doh = (Some("encrypted_dns".to_string()), true);
        // No name the app sent (DoH to an IP literal): by address.
        assert_eq!(decide(ev("1.1.1.1", 443, None)), doh);
        assert_eq!(decide(ev("2620:fe::fe", 443, None)), doh);
        // NAT64: the embedded IPv4 address.
        assert_eq!(decide(ev("64:ff9b::808:808", 443, None)), doh);
        // Other ports and addresses are not.
        assert_eq!(decide(ev("1.1.1.1", 80, None)), (None, false));
        assert_eq!(decide(ev("192.0.2.1", 443, None)), (None, false));
        // A name that is not a DoH host wins over the address...
        assert_eq!(
            decide(ev("1.1.1.1", 443, Some("www.example.com"))),
            (None, false)
        );
        // ...and a DoH host is one at any address.
        assert_eq!(decide(ev("192.0.2.1", 443, Some("dns.google"))), doh);
        // Tagged only when blocking is off.
        shared.policy.write().block_encrypted_dns = false;
        assert_eq!(decide(ev("8.8.8.8", 443, None)), (None, true));
    }
}
