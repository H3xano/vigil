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
mod tcp;
mod udp;

use crate::config::Config;
use crate::detect::{AlertLimiter, BeaconDetector};
use crate::dnscache::DnsCache;
use crate::event::{
    now_ms, AlertEvent, EngineEvent, Event, EventQueue, FlowEndEvent, FlowEvent, FlowUpdateEvent,
    Severity, StatsEvent,
};
use crate::intel::{parse_feed, parse_feed_reader};
use crate::packet::{self, PROTO_TCP, PROTO_UDP};
use crate::platform::Platform;
use crate::policy::{FeedCategory, LoadedFeed, Policy};
use crate::tun::TunDevice;
use futures::{SinkExt, StreamExt};
use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const TUN_QUEUE: usize = 4096;
const STACK_QUEUE: usize = 2048;
const TCP_WINDOW: u32 = 64 * 1024;
const EVENT_QUEUE: usize = 20_000;

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

pub(crate) struct Shared {
    config: RwLock<Arc<Config>>,
    pub policy: RwLock<Policy>,
    pub platform: Arc<dyn Platform>,
    pub events: Arc<EventQueue>,
    pub dns_cache: DnsCache,
    pub beacon: BeaconDetector,
    pub limiter: AlertLimiter,
    pub stats: Stats,
    next_id: AtomicU64,
    pub tun_tx: mpsc::Sender<Vec<u8>>,
    pub tcp_meta: Mutex<HashMap<FlowKey, tcp::FlowMeta>>,
    pub udp_flows: Mutex<HashMap<FlowKey, mpsc::Sender<Vec<u8>>>>,
    open_flows: Mutex<HashMap<u64, Arc<FlowCounters>>>,
}

impl Shared {
    pub fn config(&self) -> Arc<Config> {
        self.config.read().clone()
    }

    pub fn next_flow_id(&self) -> u64 {
        self.next_id.fetch_add(1, Relaxed)
    }

    pub fn emit(&self, e: Event) {
        self.events.push(e);
    }

    /// Emits a `flow` event and tracks the flow until [`finish_flow`].
    pub fn open_flow(&self, ev: FlowEvent, counters: &Arc<FlowCounters>) {
        self.open_flows.lock().insert(ev.id, counters.clone());
        self.emit(Event::Flow(ev));
    }

    /// Emits the `flow_end` for an open flow (exactly once).
    pub fn finish_flow(&self, id: u64, error: Option<String>) {
        if let Some(c) = self.open_flows.lock().remove(&id) {
            self.emit(Event::FlowEnd(c.end_event(id, error)));
        }
    }

    fn close_all_flows(&self, reason: &str) {
        let flows: Vec<_> = self.open_flows.lock().drain().collect();
        for (id, c) in flows {
            self.emit(Event::FlowEnd(c.end_event(id, Some(reason.to_string()))));
        }
    }

    fn emit_flow_updates(&self) {
        let flows: Vec<_> = self
            .open_flows
            .lock()
            .iter()
            .map(|(id, c)| (*id, c.clone()))
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
        }
    }
}

/// Result of loading a threat/tracker feed.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FeedSummary {
    pub id: String,
    pub domains: usize,
    pub ip_ranges: usize,
    pub rejected_lines: usize,
    pub memory_bytes: usize,
}

/// A running engine. Dropping it stops the engine.
pub struct Engine {
    shared: Arc<Shared>,
    runtime: Option<tokio::runtime::Runtime>,
}

impl Engine {
    /// Starts the engine on a duplicate of `tun_fd`.
    pub fn start(tun_fd: RawFd, config: Config, platform: Arc<dyn Platform>) -> io::Result<Engine> {
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
        let shared = Arc::new(Shared {
            policy: RwLock::new(Policy::new(&config)),
            config: RwLock::new(Arc::new(config)),
            platform,
            events: Arc::new(EventQueue::new(EVENT_QUEUE)),
            dns_cache: DnsCache::new(50_000),
            beacon: BeaconDetector::new(),
            limiter: AlertLimiter::new(Duration::from_secs(3600)),
            stats: Stats::default(),
            next_id: AtomicU64::new(1),
            tun_tx,
            tcp_meta: Mutex::new(HashMap::new()),
            udp_flows: Mutex::new(HashMap::new()),
            open_flows: Mutex::new(HashMap::new()),
        });
        let s = shared.clone();
        runtime.spawn(async move {
            if let Err(e) = run(s.clone(), tun, tun_rx).await {
                log::error!("engine stopped: {e}");
                s.emit(Event::Engine(EngineEvent {
                    ts: now_ms(),
                    state: "error",
                    message: e.to_string(),
                }));
            }
        });
        shared.emit(Event::Engine(EngineEvent {
            ts: now_ms(),
            state: "started",
            message: String::new(),
        }));
        Ok(Engine {
            shared,
            runtime: Some(runtime),
        })
    }

    pub fn events(&self) -> Arc<EventQueue> {
        self.shared.events.clone()
    }

    pub fn config(&self) -> Arc<Config> {
        self.shared.config()
    }

    pub fn update_config(&self, config: Config) {
        self.shared.policy.write().apply_config(&config);
        *self.shared.config.write() = Arc::new(config);
    }

    /// Parses and installs (or replaces) a feed. CPU-heavy for large lists;
    /// call from a background thread.
    pub fn load_feed(&self, id: &str, category: FeedCategory, text: &str) -> FeedSummary {
        install_feed(&self.shared.policy, id, category, parse_feed(text))
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
            parse_feed_reader(file)?,
        ))
    }

    pub fn remove_feed(&self, id: &str) -> bool {
        self.shared.policy.write().remove_feed(id)
    }

    pub fn stats(&self) -> StatsEvent {
        self.shared.snapshot()
    }

    /// Stops all tasks and closes the engine's TUN descriptor.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        if let Some(rt) = self.runtime.take() {
            self.shared.close_all_flows("engine stopped");
            rt.shutdown_timeout(Duration::from_secs(2));
            self.shared.emit(Event::Engine(EngineEvent {
                ts: now_ms(),
                state: "stopped",
                message: String::new(),
            }));
            self.shared.events.wake();
        }
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
        ip_ranges: feed.ips.len(),
        rejected_lines: feed.rejected,
        memory_bytes: feed.domains.memory_bytes(),
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
        .tcp_buffer_size(STACK_QUEUE)
        .tcp_recv_buffer_size(TCP_WINDOW)
        .tcp_send_buffer_size(TCP_WINDOW)
        .build()?;
    let listener = listener.ok_or_else(|| io::Error::other("tcp listener missing"))?;
    if let Some(runner) = runner {
        tokio::spawn(async move {
            if let Err(e) = runner.await {
                log::error!("tcp stack runner exited: {e}");
            }
        });
    }
    let (mut stack_sink, mut stack_stream) = stack.split();

    // Packets destined for the TCP stack.
    let (stack_in_tx, mut stack_in_rx) = mpsc::channel::<Vec<u8>>(STACK_QUEUE);
    tokio::spawn(async move {
        while let Some(p) = stack_in_rx.recv().await {
            if let Err(e) = stack_sink.send(p).await {
                log::warn!("stack sink: {e}");
                if e.kind() == io::ErrorKind::BrokenPipe {
                    break;
                }
            }
        }
    });

    // Packets produced by the TCP stack.
    let s = shared.clone();
    tokio::spawn(async move {
        while let Some(p) = stack_stream.next().await {
            match p {
                Ok(p) => {
                    if s.tun_tx.send(p).await.is_err() {
                        break;
                    }
                }
                Err(e) => log::warn!("stack stream: {e}"),
            }
        }
    });

    // TUN writer.
    let s = shared.clone();
    let writer_tun = tun.clone();
    tokio::spawn(async move {
        while let Some(p) = tun_rx.recv().await {
            s.stats.packets_in.fetch_add(1, Relaxed);
            s.stats.bytes_in.fetch_add(p.len() as u64, Relaxed);
            if let Err(e) = writer_tun.send(&p).await {
                log::warn!("tun write ({} bytes): {e}", p.len());
            }
        }
    });

    tokio::spawn(tcp::accept_loop(shared.clone(), listener));
    tokio::spawn(housekeeping(shared.clone()));

    let gate = tcp::Gate::new(shared.clone(), stack_in_tx.clone());
    let mut buf = vec![0u8; 65_536];
    loop {
        let n = tun.recv(&mut buf).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "tun closed"));
        }
        let pkt = &buf[..n];
        shared.stats.packets_out.fetch_add(1, Relaxed);
        shared.stats.bytes_out.fetch_add(n as u64, Relaxed);
        dispatch(&shared, &gate, &stack_in_tx, pkt);
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
        // Admitted SYNs whose stream never materialised (e.g. the client gave up).
        shared
            .tcp_meta
            .lock()
            .retain(|_, m| m.admitted.elapsed() < Duration::from_secs(60));
    }
}
