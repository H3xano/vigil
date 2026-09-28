//! The engine: TUN packet dispatch, the user-space TCP stack, the UDP NAT and
//! the DNS resolver, wired together on a small Tokio runtime.
//!
//! ```text
//!             ┌────────────── TUN fd ──────────────┐
//!   read loop │                                    ▲ writer task
//!             ▼                                    │
//!   parse IP ─┬─ TCP SYN ──► gate (uid, policy, connect upstream) ──┐
//!             ├─ TCP other ─────────────────────────────────► netstack (smoltcp)
//!             │                                         accepted streams ──► relay + sniff (SNI/HTTP)
//!             ├─ UDP :53 ──► DNS (policy, sinkhole, upstream, cache)
//!             ├─ UDP other ─► per-flow NAT task (QUIC SNI sniff) ──► protected UDP socket
//!             └─ other ─────► dropped (counted)
//! ```

mod dns;
mod dns_upstream;
mod sock;
mod tcp;
mod udp;
pub(crate) mod upstream;

use crate::config::{Config, ConfigError};
use crate::detect::{AlertLimiter, BeaconDetector, FlowBurstDetector, FlowSample};
use crate::dnscache::DnsCache;
use crate::event::{
    now_ms, AlertEvent, EngineEvent, Event, EventQueue, FlowEndEvent, FlowEvent, FlowUpdateEvent,
    Severity, StatsEvent, Verdict,
};
use crate::intel::parse_feed_reader_kind;
use crate::packet::{self, PROTO_TCP, PROTO_UDP};
use crate::platform::Platform;
use crate::policy::{FeedCategory, LoadedFeed, Policy};
use crate::tun::TunDevice;
use futures::StreamExt;
use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Semaphore};

const TUN_QUEUE: usize = 4096;
const STACK_QUEUE: usize = 2048;
const TCP_WINDOW: u32 = 64 * 1024;
const EVENT_QUEUE: usize = 20_000;
/// Consecutive transient TUN read errors tolerated before giving up.
const TUN_MAX_TRANSIENT_ERRORS: u32 = 100;

#[derive(Default)]
pub(crate) struct Stats {
    pub packets_in: AtomicU64,
    pub packets_out: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub tcp_active: AtomicU64,
    pub udp_active: AtomicU64,
    pub flows_total: AtomicU64,
    pub dns_queries: AtomicU64,
    pub blocked: AtomicU64,
    pub dropped_packets: AtomicU64,
}

/// Decrements a gauge when dropped.
pub(crate) struct GaugeGuard<'a>(&'a AtomicU64);

impl<'a> GaugeGuard<'a> {
    pub fn new(g: &'a AtomicU64) -> Self {
        g.fetch_add(1, Relaxed);
        Self(g)
    }
}

impl Drop for GaugeGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Relaxed);
    }
}

pub(crate) type FlowKey = (SocketAddr, SocketAddr);

/// Live byte counters of an open flow.
pub(crate) struct FlowCounters {
    pub tx: AtomicU64,
    pub rx: AtomicU64,
    started: Instant,
    reported: AtomicU64,
}

impl FlowCounters {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            tx: AtomicU64::new(0),
            rx: AtomicU64::new(0),
            started: Instant::now(),
            reported: AtomicU64::new(0),
        })
    }

    fn end_event(&self, id: u64, error: Option<String>) -> FlowEndEvent {
        FlowEndEvent {
            id,
            ts: now_ms(),
            tx: self.tx.load(Relaxed),
            rx: self.rx.load(Relaxed),
            duration_ms: self.started.elapsed().as_millis() as u64,
            error,
        }
    }
}

/// Resource caps (see [`Config`]); fixed when the engine starts.
pub(crate) struct Limits {
    /// Connections held at the SYN gate.
    pub gate: Arc<Semaphore>,
    /// TCP connections admitted or relaying.
    pub tcp: Arc<Semaphore>,
    /// DNS queries being answered.
    pub dns: Arc<Semaphore>,
    pub udp_flows: usize,
    /// UDP flows looking up their UID or creating their socket.
    pub udp_setup: Semaphore,
}

impl Limits {
    fn new(cfg: &Config) -> Self {
        Self {
            gate: Arc::new(Semaphore::new(cfg.max_pending_connects)),
            tcp: Arc::new(Semaphore::new(cfg.max_tcp_flows)),
            dns: Arc::new(Semaphore::new(cfg.max_dns_inflight)),
            udp_flows: cfg.max_udp_flows,
            udp_setup: Semaphore::new(udp::UDP_SETUP_CONCURRENCY),
        }
    }
}

const SHUTDOWN_REASON: &str = "engine stopped";

/// What the in-flow beacon detector reports about an allowed flow.
struct BeaconMeta {
    uid: Option<u32>,
    /// Domain, or the destination address when there is none.
    target: String,
    domain: Option<String>,
    dst: String,
    proto: &'static str,
}

struct OpenFlow {
    counters: Arc<FlowCounters>,
    /// Set for allowed flows that may be watched for in-flow beaconing
    /// (not to an ignored or allowlisted name).
    beacon: Option<Box<BeaconMeta>>,
}

#[derive(Default)]
struct OpenFlows {
    flows: HashMap<u64, OpenFlow>,
    /// The engine has shut down: flows opened from now on end at once.
    closed: bool,
}

pub(crate) struct Shared {
    config: RwLock<Arc<Config>>,
    pub policy: RwLock<Policy>,
    pub platform: Arc<dyn Platform>,
    pub events: Arc<EventQueue>,
    pub dns_cache: DnsCache,
    pub beacon: BeaconDetector,
    /// Periodic bursts inside long-lived flows (sampled by housekeeping).
    flow_beacon: FlowBurstDetector,
    pub limiter: AlertLimiter,
    pub stats: Stats,
    pub limits: Limits,
    next_id: AtomicU64,
    epoch: Instant,
    pub tun_tx: mpsc::Sender<Vec<u8>>,
    pub tcp_meta: Mutex<HashMap<FlowKey, tcp::FlowMeta>>,
    /// TCP connections the gate knows (deciding, parked or relaying).
    /// Retransmitted SYNs for these are dropped instead of re-gated.
    pub tcp_keys: Mutex<HashSet<FlowKey>>,
    /// Relays whose app side has finished sending (FIN) while the server
    /// side still runs. A new SYN on such a 4-tuple means the app has moved
    /// on: the old relay is aborted so the retransmitted SYN gets through.
    pub tcp_half_closed: Mutex<HashMap<FlowKey, netstack_smoltcp::TcpAbortHandle>>,
    pub udp_flows: Mutex<udp::FlowTable>,
    pub dns_upstreams: dns::UpstreamPool,
    pub encrypted_dns: dns_upstream::EncryptedUpstream,
    /// How upstream sockets reach the internet (direct, WireGuard, SOCKS5).
    pub upstream: upstream::Upstream,
    open_flows: Mutex<OpenFlows>,
    shut_down: AtomicBool,
}

impl Shared {
    fn new(config: Config, platform: Arc<dyn Platform>, tun_tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            policy: RwLock::new(Policy::new(&config)),
            limits: Limits::new(&config),
            config: RwLock::new(Arc::new(config)),
            platform,
            events: Arc::new(EventQueue::new(EVENT_QUEUE)),
            dns_cache: DnsCache::new(50_000),
            beacon: BeaconDetector::new(),
            flow_beacon: FlowBurstDetector::new(),
            limiter: AlertLimiter::new(Duration::from_secs(3600)),
            stats: Stats::default(),
            next_id: AtomicU64::new(1),
            epoch: Instant::now(),
            tun_tx,
            tcp_meta: Mutex::new(HashMap::new()),
            tcp_keys: Mutex::new(HashSet::new()),
            tcp_half_closed: Mutex::new(HashMap::new()),
            udp_flows: Mutex::new(udp::FlowTable::default()),
            dns_upstreams: dns::UpstreamPool::default(),
            encrypted_dns: dns_upstream::EncryptedUpstream::default(),
            upstream: upstream::Upstream::default(),
            open_flows: Mutex::new(OpenFlows::default()),
            shut_down: AtomicBool::new(false),
        }
    }

    pub fn config(&self) -> Arc<Config> {
        self.config.read().clone()
    }

    pub fn next_flow_id(&self) -> u64 {
        self.next_id.fetch_add(1, Relaxed)
    }

    /// Milliseconds since the engine started (a cheap monotonic clock).
    pub fn ticks(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    pub fn emit(&self, e: Event) {
        self.events.push(e);
    }

    /// Emits a `flow` event and tracks the flow until [`finish_flow`]. After
    /// shutdown the flow is ended immediately, so every `flow` still gets
    /// its `flow_end`.
    pub fn open_flow(&self, ev: FlowEvent, counters: &Arc<FlowCounters>) {
        let id = ev.id;
        let beacon = self.beacon_meta(&ev);
        // Emitting under the lock orders `flow` before any `flow_end`
        // emitted by `close_all_flows`.
        let mut open = self.open_flows.lock();
        self.emit(Event::Flow(ev));
        if open.closed {
            self.emit(Event::FlowEnd(
                counters.end_event(id, Some(SHUTDOWN_REASON.into())),
            ));
        } else {
            open.flows.insert(
                id,
                OpenFlow {
                    counters: counters.clone(),
                    beacon,
                },
            );
        }
    }

    /// The in-flow beacon detector's view of a flow, or None if the flow
    /// is never to be watched: blocked, or to a name (sent by the app) on
    /// `beacon.ignore_domains` or the user allowlist.
    fn beacon_meta(&self, ev: &FlowEvent) -> Option<Box<BeaconMeta>> {
        if ev.verdict != Some(Verdict::Allow) {
            return None;
        }
        if let (Some("sni" | "http" | "quic"), Some(d)) = (ev.domain_source, ev.domain.as_deref()) {
            if self.config().beacon.is_ignored(d) || self.policy.read().is_allowlisted(d) {
                return None;
            }
        }
        Some(Box::new(BeaconMeta {
            uid: ev.uid,
            target: ev.domain.clone().unwrap_or_else(|| ev.dst_ip.clone()),
            domain: ev.domain.clone(),
            dst: format!("{}:{}", ev.dst_ip, ev.dst_port),
            proto: ev.app_proto.unwrap_or(ev.proto),
        }))
    }

    /// Emits the `flow_end` for an open flow (exactly once).
    pub fn finish_flow(&self, id: u64, error: Option<String>) {
        let o = self.open_flows.lock().flows.remove(&id);
        if let Some(o) = o {
            if o.beacon.is_some() {
                self.flow_beacon.forget(id);
            }
            self.emit(Event::FlowEnd(o.counters.end_event(id, error)));
        }
    }

    fn close_all_flows(&self, reason: &str) {
        let mut open = self.open_flows.lock();
        open.closed = true;
        let mut flows: Vec<_> = open.flows.drain().collect();
        flows.sort_by_key(|(id, _)| *id);
        for (id, o) in flows {
            self.emit(Event::FlowEnd(
                o.counters.end_event(id, Some(reason.to_string())),
            ));
        }
        self.flow_beacon.clear();
    }

    /// One sampling pass of the in-flow beacon detector over the open flows'
    /// byte counters (no work on the packet path). Raises a `beacon` alert
    /// with `detail.kind = "intra_flow"` for each flow found periodic.
    fn sample_flow_bursts(&self) {
        let cfg = self.config();
        let now = Instant::now();
        let hits = {
            let open = self.open_flows.lock();
            let samples = open
                .flows
                .iter()
                .filter(|(_, o)| o.beacon.is_some())
                .map(|(id, o)| {
                    let c = &o.counters;
                    FlowSample {
                        id: *id,
                        bytes: c.tx.load(Relaxed).wrapping_add(c.rx.load(Relaxed)),
                        age: now.saturating_duration_since(c.started),
                    }
                });
            let hits = self.flow_beacon.sample(&cfg.beacon, samples, now);
            // Copy what the alerts need while the flows are known to be open.
            hits.into_iter()
                .filter_map(|(id, hit)| {
                    let o = open.flows.get(&id)?;
                    let m = o.beacon.as_deref()?;
                    let age_s = now.saturating_duration_since(o.counters.started).as_secs();
                    Some((
                        id,
                        hit,
                        m.uid,
                        m.target.clone(),
                        serde_json::json!({
                            "kind": "intra_flow",
                            "flow_id": id,
                            "dst": m.dst,
                            "domain": m.domain,
                            "proto": m.proto,
                            "age_s": age_s,
                        }),
                    ))
                })
                .collect::<Vec<_>>()
        };
        for (_, hit, uid, target, mut detail) in hits {
            if let Some(d) = detail.as_object_mut() {
                d.insert("interval_s".into(), hit.mean_interval_s.into());
                d.insert("jitter".into(), hit.jitter.into());
                d.insert("samples".into(), hit.samples.into());
                d.insert("burst_bytes".into(), hit.burst_bytes.into());
            }
            // Same finding as a connection beacon to the same target: one
            // alert per app and target per hour, whichever detector saw it.
            self.alert(
                "beacon",
                Severity::Medium,
                uid,
                &target,
                &target,
                format!(
                    "Small bursts of data (about {} bytes) every {:.0}s (jitter {:.0}%) inside one open connection to {target}",
                    hit.burst_bytes,
                    hit.mean_interval_s,
                    hit.jitter * 100.0
                ),
                detail,
            );
        }
    }

    fn emit_flow_updates(&self) {
        let flows: Vec<_> = self
            .open_flows
            .lock()
            .flows
            .iter()
            .map(|(id, o)| (*id, o.counters.clone()))
            .collect();
        for (id, c) in flows {
            let (tx, rx) = (c.tx.load(Relaxed), c.rx.load(Relaxed));
            let sum = tx.wrapping_add(rx);
            if c.reported.swap(sum, Relaxed) != sum {
                self.emit(Event::FlowUpdate(FlowUpdateEvent {
                    id,
                    ts: now_ms(),
                    tx,
                    rx,
                }));
            }
        }
    }

    /// Raises an alert unless one with the same kind, app and `dedup` key
    /// was raised within the last hour (or the global budget is spent).
    /// `dedup` identifies the finding, e.g. the matched list entry, so
    /// thousands of generated names under one listed domain are one alert.
    #[allow(clippy::too_many_arguments)]
    pub fn alert(
        &self,
        kind: &'static str,
        severity: Severity,
        uid: Option<u32>,
        dedup: &str,
        target: &str,
        message: String,
        detail: serde_json::Value,
    ) {
        let key = format!("{kind}|{uid:?}|{dedup}");
        if !self.limiter.allow(&key, Instant::now()) {
            return;
        }
        self.emit(Event::Alert(AlertEvent {
            ts: now_ms(),
            kind,
            severity,
            uid,
            target: target.to_string(),
            message,
            detail,
        }));
    }

    /// Resolves the owning UID off the async workers (Binder IPC may block).
    pub async fn lookup_uid(
        self: &Arc<Self>,
        proto: u8,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Option<u32> {
        let me = self.clone();
        tokio::task::spawn_blocking(move || me.platform.owner_uid(proto, src, dst))
            .await
            .ok()
            .flatten()
    }

    /// Queues a packet for the TUN writer, dropping it if the queue is full.
    pub fn send_to_tun(&self, pkt: Vec<u8>) {
        if self.tun_tx.try_send(pkt).is_err() {
            self.stats.dropped_packets.fetch_add(1, Relaxed);
        }
    }

    fn snapshot(&self) -> StatsEvent {
        let s = &self.stats;
        StatsEvent {
            ts: now_ms(),
            packets_in: s.packets_in.load(Relaxed),
            packets_out: s.packets_out.load(Relaxed),
            bytes_in: s.bytes_in.load(Relaxed),
            bytes_out: s.bytes_out.load(Relaxed),
            tcp_active: s.tcp_active.load(Relaxed),
            udp_active: s.udp_active.load(Relaxed),
            flows_total: s.flows_total.load(Relaxed),
            dns_queries: s.dns_queries.load(Relaxed),
            blocked: s.blocked.load(Relaxed),
            dropped_packets: s.dropped_packets.load(Relaxed),
            dropped_events: self.events.dropped(),
            dns_cache_size: self.dns_cache.len() as u64,
            upstream: self.upstream.status(),
            ..self.encrypted_dns.stats.snapshot()
        }
    }
}

/// Waits for the engine's main task and reports how it ended: an error or a
/// panic becomes an `engine` event with `state: error` (the app restarts
/// the session on it). Without this a panic in `run` was swallowed by
/// tokio, leaving the TUN unread with the routes up: every app black-holed.
/// Cancellation (at shutdown) is not reported.
async fn supervise(shared: Arc<Shared>, main: tokio::task::JoinHandle<io::Result<()>>) {
    let message = match main.await {
        Ok(Ok(())) => "engine loop ended".to_string(),
        Ok(Err(e)) => e.to_string(),
        Err(e) if e.is_panic() => format!("engine panicked: {}", panic_message(e.into_panic())),
        Err(_) => return,
    };
    log::error!("engine stopped: {message}");
    shared.emit(Event::Engine(EngineEvent {
        ts: now_ms(),
        state: "error",
        message,
    }));
}

fn panic_message(p: Box<dyn std::any::Any + Send>) -> String {
    match p.downcast::<String>() {
        Ok(s) => *s,
        Err(p) => p
            .downcast_ref::<&str>()
            .map_or_else(|| "(no message)".to_string(), |s| s.to_string()),
    }
}

/// The engine's long-running tasks. Aborted when dropped, so they do not
/// outlive `run` when it fails.
struct EngineTasks {
    tasks: Vec<(&'static str, tokio::task::JoinHandle<io::Result<()>>)>,
    aborts: Vec<tokio::task::AbortHandle>,
}

impl EngineTasks {
    fn new() -> Self {
        Self {
            tasks: Vec::new(),
            aborts: Vec::new(),
        }
    }

    fn spawn<F>(&mut self, name: &'static str, f: F)
    where
        F: std::future::Future<Output = io::Result<()>> + Send + 'static,
    {
        let h = tokio::spawn(f);
        self.aborts.push(h.abort_handle());
        self.tasks.push((name, h));
    }

    /// Resolves when the first task ends (none should while the engine
    /// runs), with an error saying which one and how.
    async fn first_exit(&mut self) -> io::Error {
        let tasks = std::mem::take(&mut self.tasks);
        if tasks.is_empty() {
            return std::future::pending().await;
        }
        let (names, handles): (Vec<_>, Vec<_>) = tasks.into_iter().unzip();
        let (r, i, _rest) = futures::future::select_all(handles).await;
        let name = names[i];
        io::Error::other(match r {
            Ok(Ok(())) => format!("{name} task ended"),
            Ok(Err(e)) => format!("{name}: {e}"),
            Err(e) if e.is_panic() => {
                format!("{name} task panicked: {}", panic_message(e.into_panic()))
            }
            Err(_) => format!("{name} task cancelled"),
        })
    }
}

impl Drop for EngineTasks {
    fn drop(&mut self) {
        for a in &self.aborts {
            a.abort();
        }
    }
}

/// Result of loading a threat/tracker feed.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FeedSummary {
    pub id: String,
    pub domains: usize,
    pub ip_ranges: usize,
    /// JA4 fingerprints (exact and wildcard entries).
    pub ja4: usize,
    pub rejected_lines: usize,
    pub memory_bytes: usize,
}

/// A running engine. Dropping it stops the engine.
pub struct Engine {
    shared: Arc<Shared>,
    runtime: Mutex<Option<tokio::runtime::Runtime>>,
}

impl Engine {
    /// Starts the engine on a duplicate of `tun_fd`.
    pub fn start(tun_fd: RawFd, config: Config, platform: Arc<dyn Platform>) -> io::Result<Engine> {
        config
            .validate()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(config.worker_threads.clamp(1, 8))
            .max_blocking_threads(16)
            .thread_name("vigil-worker")
            .enable_all()
            .build()?;
        let tun = {
            let _guard = runtime.enter();
            Arc::new(TunDevice::from_raw_fd_dup(tun_fd)?)
        };
        let (tun_tx, tun_rx) = mpsc::channel(TUN_QUEUE);
        let upstream = config.upstream.clone();
        let shared = Arc::new(Shared::new(config, platform, tun_tx));
        {
            // A WireGuard tunnel spawns its driver on the runtime.
            let _guard = runtime.enter();
            shared.upstream.apply(&upstream, &shared.platform);
        }
        let main = runtime.spawn(run(shared.clone(), tun, tun_rx));
        runtime.spawn(supervise(shared.clone(), main));
        shared.emit(Event::Engine(EngineEvent {
            ts: now_ms(),
            state: "started",
            message: String::new(),
        }));
        Ok(Engine {
            shared,
            runtime: Mutex::new(Some(runtime)),
        })
    }

    pub fn events(&self) -> Arc<EventQueue> {
        self.shared.events.clone()
    }

    pub fn config(&self) -> Arc<Config> {
        self.shared.config()
    }

    /// Installs a new configuration. Resource caps keep their start values.
    /// A changed upstream path applies to connections opened from now on;
    /// open ones keep theirs (see `engine/upstream`).
    pub fn update_config(&self, config: Config) -> Result<(), ConfigError> {
        config.validate()?;
        if let Some(rt) = self.runtime.lock().as_ref() {
            let _guard = rt.enter();
            self.shared
                .upstream
                .apply(&config.upstream, &self.shared.platform);
        }
        self.shared.policy.write().apply_config(&config);
        *self.shared.config.write() = Arc::new(config);
        Ok(())
    }

    /// Parses and installs (or replaces) a feed. CPU-heavy for large lists;
    /// call from a background thread.
    pub fn load_feed(&self, id: &str, category: FeedCategory, text: &str) -> FeedSummary {
        let feed = parse_feed_reader_kind(text.as_bytes(), category.feed_kind())
            .expect("reading from memory cannot fail");
        install_feed(&self.shared.policy, id, category, feed)
    }

    /// Streams a feed from a file (bounded memory for multi-million entry lists).
    pub fn load_feed_file(
        &self,
        id: &str,
        category: FeedCategory,
        path: &std::path::Path,
    ) -> io::Result<FeedSummary> {
        let file = std::io::BufReader::with_capacity(64 * 1024, std::fs::File::open(path)?);
        Ok(install_feed(
            &self.shared.policy,
            id,
            category,
            parse_feed_reader_kind(file, category.feed_kind())?,
        ))
    }

    pub fn remove_feed(&self, id: &str) -> bool {
        self.shared.policy.write().remove_feed(id)
    }

    pub fn stats(&self) -> StatsEvent {
        self.shared.snapshot()
    }

    /// Stops the engine but keeps its event queue readable: every task is
    /// stopped, every open flow gets its `flow_end`, then a `stopped` engine
    /// event is queued and the queue is closed (polls stop waiting).
    /// Idempotent; must not be called from inside the engine's runtime.
    ///
    /// Blocks for up to about 2 s (the runtime's shutdown timeout, waiting
    /// for blocking-pool work such as a UID lookup or `protect()` upcall),
    /// with the runtime lock held, so a concurrent call waits as long.
    /// Callers must not call it on the Android main (UI) thread.
    pub fn shutdown(&self) {
        // Held throughout, so a concurrent call returns only when done.
        let mut rt = self.runtime.lock();
        let Some(runtime) = rt.take() else {
            return;
        };
        self.shared.shut_down.store(true, Relaxed);
        runtime.shutdown_timeout(Duration::from_secs(2));
        // Only now, with no task left to open one, end the open flows.
        self.shared.close_all_flows(SHUTDOWN_REASON);
        self.shared.emit(Event::Engine(EngineEvent {
            ts: now_ms(),
            state: "stopped",
            message: String::new(),
        }));
        self.shared.events.close();
    }

    /// Whether [`shutdown`](Self::shutdown) has run.
    pub fn is_shut_down(&self) -> bool {
        self.shared.shut_down.load(Relaxed)
    }

    /// Stops all tasks and closes the engine's TUN descriptor.
    pub fn stop(self) {
        self.shutdown();
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn install_feed(
    policy: &RwLock<Policy>,
    id: &str,
    category: FeedCategory,
    feed: crate::intel::Feed,
) -> FeedSummary {
    let summary = FeedSummary {
        id: id.to_string(),
        domains: feed.domains.len(),
        ip_ranges: feed.ip_range_count(),
        ja4: feed.ja4.len(),
        rejected_lines: feed.rejected,
        memory_bytes: feed.memory_bytes(),
    };
    policy.write().set_feed(id, LoadedFeed { category, feed });
    summary
}

async fn run(
    shared: Arc<Shared>,
    tun: Arc<TunDevice>,
    mut tun_rx: mpsc::Receiver<Vec<u8>>,
) -> io::Result<()> {
    let cfg = shared.config();
    let (stack, runner, _udp, listener) = netstack_smoltcp::StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(false)
        .enable_icmp(false)
        .mtu(cfg.mtu as usize)
        .stack_buffer_size(STACK_QUEUE)
        // The only queue between the TUN reader and smoltcp (there used to
        // be two of STACK_QUEUE each).
        .tcp_buffer_size(2 * STACK_QUEUE)
        .tcp_recv_buffer_size(TCP_WINDOW)
        .tcp_send_buffer_size(TCP_WINDOW)
        .build()?;
    let listener = listener.ok_or_else(|| io::Error::other("tcp listener missing"))?;
    let runner = runner.ok_or_else(|| io::Error::other("tcp stack runner missing"))?;
    // Every task below must run as long as the engine: if one ends (or
    // panics), `run` fails and the session is restarted.
    let mut tasks = EngineTasks::new();
    tasks.spawn("tcp stack", runner);
    // Packets for the TCP stack go straight into its input queue, and the
    // TUN writer drains the stack's output itself: no forwarding tasks.
    let stack_in = stack
        .tcp_sender()
        .ok_or_else(|| io::Error::other("tcp stack input missing"))?;
    let mut stack_out = stack;

    // TUN writer: packets from the TCP stack and from vigil (UDP, DNS, RSTs).
    let s = shared.clone();
    let writer_tun = tun.clone();
    tasks.spawn("tun writer", async move {
        let mut stack_open = true;
        loop {
            let p = tokio::select! {
                p = stack_out.next(), if stack_open => match p {
                    Some(Ok(p)) => p,
                    Some(Err(e)) => {
                        log::warn!("stack stream: {e}");
                        continue;
                    }
                    None => {
                        stack_open = false;
                        continue;
                    }
                },
                p = tun_rx.recv() => match p {
                    Some(p) => p,
                    None => break,
                },
            };
            s.stats.packets_in.fetch_add(1, Relaxed);
            s.stats.bytes_in.fetch_add(p.len() as u64, Relaxed);
            if let Err(e) = writer_tun.send(&p).await {
                log::warn!("tun write ({} bytes): {e}", p.len());
            }
        }
        Ok(())
    });

    let s = shared.clone();
    tasks.spawn("tcp accept", async move {
        tcp::accept_loop(s, listener).await;
        Ok(())
    });
    let s = shared.clone();
    tasks.spawn("housekeeping", async move {
        housekeeping(s).await;
        Ok(())
    });

    tokio::select! {
        r = read_tun(&shared, &tun, &stack_in) => r,
        e = tasks.first_exit() => Err(e),
    }
}

/// The TUN read loop; returns only on a fatal read error.
async fn read_tun(
    shared: &Arc<Shared>,
    tun: &TunDevice,
    stack_in: &mpsc::Sender<Vec<u8>>,
) -> io::Result<()> {
    let gate = tcp::Gate::new(shared.clone(), stack_in.clone());
    let mut buf = vec![0u8; 65_536];
    let mut transient = 0u32;
    loop {
        let n = match tun.recv(&mut buf).await {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "tun closed")),
            Ok(n) => n,
            Err(e) => {
                let Some(delay) = tun_retry_delay(&e, transient) else {
                    return Err(io::Error::new(e.kind(), format!("tun read: {e}")));
                };
                transient += 1;
                if delay > Duration::ZERO {
                    log::warn!("tun read: {e}; retrying in {delay:?}");
                    tokio::time::sleep(delay).await;
                }
                continue;
            }
        };
        transient = 0;
        let pkt = &buf[..n];
        shared.stats.packets_out.fetch_add(1, Relaxed);
        shared.stats.bytes_out.fetch_add(n as u64, Relaxed);
        dispatch(shared, &gate, stack_in, pkt);
    }
}

/// How long to wait before retrying a failed TUN read, or `None` if the
/// error is fatal. Interrupted reads retry at once; resource shortages
/// (ENOBUFS, ENOMEM) back off exponentially up to 1 s, a bounded number of
/// times in a row.
fn tun_retry_delay(e: &io::Error, consecutive: u32) -> Option<Duration> {
    if consecutive >= TUN_MAX_TRANSIENT_ERRORS {
        return None;
    }
    match e.raw_os_error() {
        Some(libc::EINTR) => Some(Duration::ZERO),
        Some(libc::ENOBUFS | libc::ENOMEM) => {
            Some(Duration::from_millis(10u64 << consecutive.min(7)).min(Duration::from_secs(1)))
        }
        _ if e.kind() == io::ErrorKind::Interrupted => Some(Duration::ZERO),
        _ => None,
    }
}

fn dispatch(shared: &Arc<Shared>, gate: &tcp::Gate, stack_in: &mpsc::Sender<Vec<u8>>, pkt: &[u8]) {
    let drop_it = || {
        shared.stats.dropped_packets.fetch_add(1, Relaxed);
    };
    let Some(ip) = packet::parse_ip(pkt) else {
        return drop_it();
    };
    if ip.fragment {
        return drop_it();
    }
    match ip.proto {
        PROTO_TCP => {
            // smoltcp does not parse fragment headers: hand it IPv6 atomic
            // fragments without theirs.
            let stripped;
            let (pkt, ip) = match packet::strip_atomic_fragment_v6(pkt, &ip) {
                Some(p) => {
                    stripped = p;
                    let Some(ip) = packet::parse_ip(&stripped) else {
                        return drop_it();
                    };
                    (&stripped[..], ip)
                }
                None => (pkt, ip),
            };
            let Some(t) = packet::parse_tcp(pkt, &ip) else {
                return drop_it();
            };
            if t.flags & packet::TCP_SYN != 0 && t.flags & packet::TCP_RST != 0 {
                // Invalid. The gate would not see it (not an initial SYN),
                // but the stack would take it for one and replace the live
                // socket of that 4-tuple.
                return drop_it();
            }
            if ip.dst.is_ipv6() && ip.l4_offset != packet::IPV6_HEADER_LEN {
                // Extension headers (hop-by-hop, routing, destination
                // options): smoltcp would parse them as the TCP header, so a
                // gated SYN would hang after vigil connected upstream. Refuse
                // new connections at once; drop anything else.
                if t.is_initial_syn() {
                    if let Some(rst) = packet::build_rst_for(&t) {
                        shared.send_to_tun(rst);
                    }
                }
                return drop_it();
            }
            if !stack_accepts(&ip) {
                // The netstack's own filter (its default IpFilters) drops
                // these; it is bypassed now that packets skip its Sink.
                return;
            }
            if t.is_initial_syn() {
                gate.on_syn(pkt[..ip.end].to_vec(), t);
            } else if stack_in.try_send(pkt[..ip.end].to_vec()).is_err() {
                drop_it();
            }
        }
        PROTO_UDP => {
            let Some(u) = packet::parse_udp(pkt, &ip) else {
                return drop_it();
            };
            udp::on_packet(shared, u, &pkt[u.payload_offset..u.payload_end]);
        }
        _ => drop_it(),
    }
}

/// Whether the TCP stack takes packets between these addresses (no
/// broadcast, multicast or unspecified address; netstack-smoltcp's
/// `IpFilters::with_non_broadcast`).
fn stack_accepts(ip: &packet::IpInfo) -> bool {
    let ok = |a: &std::net::IpAddr| match a {
        std::net::IpAddr::V4(a) => !(a.is_broadcast() || a.is_multicast() || a.is_unspecified()),
        std::net::IpAddr::V6(a) => !(a.is_multicast() || a.is_unspecified()),
    };
    ok(&ip.src) && ok(&ip.dst)
}

async fn housekeeping(shared: Arc<Shared>) {
    let mut last_stats = Instant::now();
    loop {
        let interval = Duration::from_millis(shared.config().stats_interval_ms.max(250));
        tokio::time::sleep(interval.min(Duration::from_secs(1))).await;
        if last_stats.elapsed() >= interval {
            last_stats = Instant::now();
            shared.emit_flow_updates();
            shared.emit(Event::Stats(shared.snapshot()));
        }
        shared.sample_flow_bursts();
        // Admitted SYNs whose stream never materialised (e.g. the client
        // gave up). Dropping the metadata releases its slot and key.
        let stale: Vec<tcp::FlowMeta> = {
            let mut meta = shared.tcp_meta.lock();
            let keys: Vec<FlowKey> = meta
                .iter()
                .filter(|(_, m)| m.admitted.elapsed() >= Duration::from_secs(60))
                .map(|(k, _)| *k)
                .collect();
            keys.iter().filter_map(|k| meta.remove(k)).collect()
        };
        drop(stale);
        shared.dns_upstreams.expire();
        shared.encrypted_dns.expire();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::NullPlatform;

    pub(crate) fn test_shared(config: Config) -> Arc<Shared> {
        test_shared_with_tun(config).0
    }

    /// A `Shared` plus the receiving end of its TUN writer queue.
    pub(crate) fn test_shared_with_tun(config: Config) -> (Arc<Shared>, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel(64);
        (
            Arc::new(Shared::new(config, Arc::new(NullPlatform), tx)),
            rx,
        )
    }

    fn flow_ids(events: &[Event]) -> (Vec<u64>, Vec<u64>) {
        let mut opened = Vec::new();
        let mut ended = Vec::new();
        for e in events {
            match e {
                Event::Flow(f) => opened.push(f.id),
                Event::FlowEnd(f) => ended.push(f.id),
                _ => {}
            }
        }
        (opened, ended)
    }

    #[test]
    fn flows_opened_after_close_still_end() {
        let s = test_shared(Config::default());
        let c = FlowCounters::new();
        s.open_flow(
            FlowEvent {
                id: 1,
                ..Default::default()
            },
            &c,
        );
        s.close_all_flows(SHUTDOWN_REASON);
        s.open_flow(
            FlowEvent {
                id: 2,
                ..Default::default()
            },
            &c,
        );
        s.finish_flow(1, None); // already ended: no second flow_end
        let events = s.events.poll(100, Duration::ZERO);
        let (opened, ended) = flow_ids(&events);
        assert_eq!(opened, vec![1, 2]);
        assert_eq!(ended, vec![1, 2]);
    }

    #[test]
    fn in_flow_beacon_skips_blocked_ignored_and_allowlisted() {
        let s = test_shared(Config {
            allow_domains: vec!["trusted.example".into()],
            ..Default::default()
        });
        let flow = |id, domain: &str, source, verdict| FlowEvent {
            id,
            domain: Some(domain.into()),
            domain_source: Some(source),
            dst_ip: "192.0.2.1".into(),
            dst_port: 443,
            verdict: Some(verdict),
            ..Default::default()
        };
        let watched = |ev: &FlowEvent| s.beacon_meta(ev).is_some();
        assert!(watched(&flow(1, "c2.example", "sni", Verdict::Allow)));
        assert!(!watched(&flow(2, "c2.example", "sni", Verdict::Block)));
        assert!(!watched(&flow(
            3,
            "mtalk.google.com",
            "sni",
            Verdict::Allow
        )));
        assert!(!watched(&flow(
            4,
            "api.trusted.example",
            "quic",
            Verdict::Allow
        )));
        // A DNS-derived name is only a hint: it never exempts a flow.
        assert!(watched(&flow(5, "mtalk.google.com", "dns", Verdict::Allow)));
        let m = s
            .beacon_meta(&FlowEvent {
                dst_ip: "192.0.2.9".into(),
                dst_port: 8443,
                proto: "tcp",
                verdict: Some(Verdict::Allow),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            (m.target.as_str(), m.dst.as_str()),
            ("192.0.2.9", "192.0.2.9:8443")
        );
        // Ending a flow stops its tracking.
        let c = FlowCounters::new();
        s.open_flow(flow(6, "c2.example", "sni", Verdict::Allow), &c);
        let mut beacon = Config::default().beacon;
        beacon.flow_min_age_s = 0.0;
        s.flow_beacon.sample(
            &beacon,
            [FlowSample {
                id: 6,
                bytes: 0,
                age: Duration::from_secs(1),
            }],
            Instant::now(),
        );
        assert_eq!(s.flow_beacon.len(), 1);
        s.finish_flow(6, None);
        assert!(s.flow_beacon.is_empty());
    }

    #[test]
    fn alerts_deduplicated_by_key_not_target() {
        let s = test_shared(Config::default());
        for i in 0..1000 {
            s.alert(
                "threat_domain",
                Severity::High,
                Some(10123),
                "feed:x|dga.example",
                &format!("q{i}.dga.example"),
                String::new(),
                serde_json::Value::Null,
            );
        }
        s.alert(
            "threat_domain",
            Severity::High,
            Some(10124),
            "feed:x|dga.example",
            "q.dga.example",
            String::new(),
            serde_json::Value::Null,
        );
        let n = s
            .events
            .poll(10_000, Duration::ZERO)
            .iter()
            .filter(|e| matches!(e, Event::Alert(_)))
            .count();
        assert_eq!(n, 2, "one alert per app and listed entry");
    }

    #[test]
    fn tun_errors_classified() {
        let err = |c| io::Error::from_raw_os_error(c);
        assert_eq!(tun_retry_delay(&err(libc::EINTR), 0), Some(Duration::ZERO));
        assert_eq!(
            tun_retry_delay(&err(libc::ENOBUFS), 0),
            Some(Duration::from_millis(10))
        );
        assert_eq!(
            tun_retry_delay(&err(libc::ENOMEM), 20),
            Some(Duration::from_secs(1))
        );
        assert_eq!(
            tun_retry_delay(&err(libc::ENOBUFS), TUN_MAX_TRANSIENT_ERRORS),
            None
        );
        assert_eq!(tun_retry_delay(&err(libc::EBADF), 0), None);
        assert_eq!(tun_retry_delay(&err(libc::EIO), 0), None);
    }

    /// Inserts an IPv6 hop-by-hop options header (PadN only).
    fn with_hop_by_hop(pkt: &[u8]) -> Vec<u8> {
        let mut out = pkt[..40].to_vec();
        let next = out[6];
        out[6] = 0;
        let plen = u16::from_be_bytes([out[4], out[5]]) + 8;
        out[4..6].copy_from_slice(&plen.to_be_bytes());
        out.extend_from_slice(&[next, 0, 1, 4, 0, 0, 0, 0]);
        out.extend_from_slice(&pkt[40..]);
        out
    }

    #[tokio::test]
    async fn dispatch_drops_syn_rst_and_ipv6_extension_headers() {
        use packet::{TCP_RST, TCP_SYN};
        let (shared, mut tun) = test_shared_with_tun(Config::default());
        let (stack_tx, mut stack_rx) = mpsc::channel(16);
        let gate = tcp::Gate::new(shared.clone(), stack_tx.clone());
        let dropped = || shared.stats.dropped_packets.load(Relaxed);
        let (src4, dns4) = ("10.111.222.1:40000", "10.111.222.2:53");
        let tcp = |src: &str, dst: &str, flags| {
            packet::build_tcp(src.parse().unwrap(), dst.parse().unwrap(), 1, 0, flags, &[]).unwrap()
        };

        // SYN|RST: neither gated nor passed to the stack.
        dispatch(
            &shared,
            &gate,
            &stack_tx,
            &tcp(src4, dns4, TCP_SYN | TCP_RST),
        );
        assert_eq!(dropped(), 1);
        assert!(shared.tcp_keys.lock().is_empty());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(stack_rx.try_recv().is_err());

        // IPv6 SYN behind a hop-by-hop header: refused with a RST.
        let (src6, dns6) = ("[fd76:6967:696c::1]:40001", "[fd76:6967:696c::2]:53");
        let syn6 = with_hop_by_hop(&tcp(src6, dns6, TCP_SYN));
        let ip = packet::parse_ip(&syn6).unwrap();
        assert_eq!((ip.proto, ip.l4_offset), (packet::PROTO_TCP, 48));
        dispatch(&shared, &gate, &stack_tx, &syn6);
        assert_eq!(dropped(), 2);
        assert!(shared.tcp_keys.lock().is_empty());
        let rst = tun.try_recv().expect("RST to the app");
        let rip = packet::parse_ip(&rst).unwrap();
        let t = packet::parse_tcp(&rst, &rip).unwrap();
        assert_eq!(t.dst, src6.parse().unwrap());
        assert_ne!(t.flags & TCP_RST, 0);
        // Other segments with extension headers are dropped silently.
        let ack6 = with_hop_by_hop(&tcp(src6, dns6, packet::TCP_ACK));
        dispatch(&shared, &gate, &stack_tx, &ack6);
        assert_eq!(dropped(), 3);
        assert!(tun.try_recv().is_err());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(stack_rx.try_recv().is_err());

        // The same SYNs without the oddities are gated and admitted.
        dispatch(&shared, &gate, &stack_tx, &tcp(src4, dns4, TCP_SYN));
        dispatch(&shared, &gate, &stack_tx, &tcp(src6, dns6, TCP_SYN));
        for _ in 0..2 {
            let p = tokio::time::timeout(Duration::from_secs(2), stack_rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(packet::parse_ip(&p).is_some());
        }
        assert_eq!(dropped(), 3);
    }

    /// The TCP half of the netstack as `run` builds it: its input, its
    /// output stream and the listener.
    pub(crate) fn test_stack() -> (
        mpsc::Sender<Vec<u8>>,
        netstack_smoltcp::Stack,
        netstack_smoltcp::TcpListener,
    ) {
        let (stack, runner, _udp, listener) = netstack_smoltcp::StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(false)
            .enable_icmp(false)
            .build()
            .unwrap();
        tokio::spawn(runner.unwrap());
        (stack.tcp_sender().unwrap(), stack, listener.unwrap())
    }

    /// The next TCP segment the stack sends to `to`.
    pub(crate) async fn next_segment(
        out: &mut netstack_smoltcp::Stack,
        to: SocketAddr,
    ) -> packet::TcpInfo {
        loop {
            let p = tokio::time::timeout(Duration::from_secs(2), out.next())
                .await
                .expect("stack output")
                .unwrap()
                .unwrap();
            let ip = packet::parse_ip(&p).unwrap();
            let t = packet::parse_tcp(&p, &ip).unwrap();
            if t.dst == to {
                return t;
            }
        }
    }

    #[tokio::test]
    async fn netstack_reaps_sockets_reset_during_handshake() {
        use packet::{build_tcp, TCP_ACK, TCP_RST, TCP_SYN};
        use tokio::io::AsyncReadExt;
        let (input, mut out, mut listener) = test_stack();
        let app: SocketAddr = "10.0.0.2:40000".parse().unwrap();
        let dst: SocketAddr = "192.0.2.1:443".parse().unwrap();
        input
            .send(build_tcp(app, dst, 1000, 0, TCP_SYN, &[]).unwrap())
            .await
            .unwrap();
        let (mut stream, src, _) = listener.next().await.unwrap();
        assert_eq!(src, app);
        let syn_ack = next_segment(&mut out, app).await;
        assert_eq!(syn_ack.flags, TCP_SYN | TCP_ACK);
        // The app gave up; its kernel resets the late SYN-ACK. smoltcp puts
        // the socket back into LISTEN, which must count as a reset.
        input
            .send(build_tcp(app, dst, 1001, 0, TCP_RST, &[]).unwrap())
            .await
            .unwrap();
        let mut buf = [0u8; 16];
        let r = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
            .await
            .expect("stream still open: zombie LISTEN socket");
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::ConnectionReset);

        // A later SYN to the same destination from another app socket gets
        // its own connection (the zombie would have taken it).
        let other: SocketAddr = "10.0.0.3:50000".parse().unwrap();
        input
            .send(build_tcp(other, dst, 5000, 0, TCP_SYN, &[]).unwrap())
            .await
            .unwrap();
        let (_stream2, src2, _) = listener.next().await.unwrap();
        assert_eq!(src2, other);
        let syn_ack = next_segment(&mut out, other).await;
        assert_eq!((syn_ack.flags, syn_ack.ack), (TCP_SYN | TCP_ACK, 5001));
    }

    fn engine_errors(s: &Shared) -> Vec<String> {
        s.events
            .poll(100, Duration::ZERO)
            .into_iter()
            .filter_map(|e| match e {
                Event::Engine(e) if e.state == "error" => Some(e.message),
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn supervisor_reports_errors_and_panics() {
        let s = test_shared(Config::default());
        let main = tokio::spawn(async { Err(io::Error::other("tun read: boom")) });
        supervise(s.clone(), main).await;
        assert_eq!(engine_errors(&s), vec!["tun read: boom".to_string()]);

        let main = tokio::spawn(async {
            if true {
                panic!("bug in dispatch");
            }
            Ok(())
        });
        supervise(s.clone(), main).await;
        assert_eq!(
            engine_errors(&s),
            vec!["engine panicked: bug in dispatch".to_string()]
        );

        // Cancelled at shutdown: nothing to report.
        let main = tokio::spawn(std::future::pending::<io::Result<()>>());
        main.abort();
        supervise(s.clone(), main).await;
        assert!(engine_errors(&s).is_empty());
    }

    #[tokio::test]
    async fn engine_tasks_fail_when_any_task_ends() {
        let mut tasks = EngineTasks::new();
        tasks.spawn("forever", std::future::pending());
        tasks.spawn("writer", async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            panic!("writer bug {}", 7);
        });
        let e = tokio::time::timeout(Duration::from_secs(2), tasks.first_exit())
            .await
            .unwrap();
        assert_eq!(e.to_string(), "writer task panicked: writer bug 7");
        let forever = tasks.aborts[0].clone();
        assert!(!forever.is_finished());
        drop(tasks);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(forever.is_finished(), "remaining tasks are aborted");

        let mut tasks = EngineTasks::new();
        tasks.spawn("tcp stack", async { Err(io::Error::other("closed")) });
        assert_eq!(tasks.first_exit().await.to_string(), "tcp stack: closed");
        let mut tasks = EngineTasks::new();
        tasks.spawn("tcp accept", async { Ok(()) });
        assert_eq!(
            tasks.first_exit().await.to_string(),
            "tcp accept task ended"
        );
    }

    /// A datagram socket pair stands in for the TUN device.
    fn fake_tun() -> (std::os::fd::OwnedFd, std::os::fd::OwnedFd) {
        use std::os::fd::FromRawFd;
        let mut fds = [0; 2];
        let r = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        assert_eq!(r, 0);
        unsafe {
            (
                std::os::fd::OwnedFd::from_raw_fd(fds[0]),
                std::os::fd::OwnedFd::from_raw_fd(fds[1]),
            )
        }
    }

    fn write_packet(fd: &std::os::fd::OwnedFd, pkt: &[u8]) {
        use std::os::fd::AsRawFd;
        let n = unsafe { libc::write(fd.as_raw_fd(), pkt.as_ptr().cast(), pkt.len()) };
        assert_eq!(n as usize, pkt.len());
    }

    #[test]
    fn shutdown_ends_every_flow_and_keeps_queue_readable() {
        use std::os::fd::AsRawFd;
        let (engine_end, host_end) = fake_tun();
        let engine = Engine::start(
            engine_end.as_raw_fd(),
            Config::default(),
            Arc::new(NullPlatform),
        )
        .unwrap();
        drop(engine_end);
        // A few UDP flows to a documentation address; they stay open (or
        // fail at once without a route) until shutdown.
        for port in 0..5u16 {
            let pkt = packet::build_udp(
                format!("10.111.222.1:{}", 40_000 + port).parse().unwrap(),
                "192.0.2.1:9999".parse().unwrap(),
                b"hello",
            )
            .unwrap();
            write_packet(&host_end, &pkt);
        }
        let events = engine.events();
        let mut seen = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        while flow_ids(&seen).0.len() < 5 && Instant::now() < deadline {
            seen.extend(events.poll(100, Duration::from_millis(50)));
        }
        assert_eq!(flow_ids(&seen).0.len(), 5, "{seen:?}");
        engine.shutdown();
        engine.shutdown(); // idempotent
        assert!(engine.is_shut_down());
        let t = Instant::now();
        seen.extend(events.poll(10_000, Duration::from_secs(5)));
        assert!(events.poll(10, Duration::from_secs(5)).is_empty());
        assert!(t.elapsed() < Duration::from_secs(2), "polls must not wait");
        let (mut opened, mut ended) = flow_ids(&seen);
        opened.sort_unstable();
        ended.sort_unstable();
        assert_eq!(opened, ended, "every flow has exactly one flow_end");
        assert!(matches!(
            seen.last(),
            Some(Event::Engine(e)) if e.state == "stopped"
        ));
        engine.stop();
    }
}
