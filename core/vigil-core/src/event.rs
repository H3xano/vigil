//! Structured events streamed from the engine to the host.
//!
//! Every event serialises to one JSON object with a `type` discriminator.
//! Contract: each `flow` event is eventually followed by exactly one
//! `flow_end` with the same `id`.

use parking_lot::{Condvar, Mutex};
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Flow(FlowEvent),
    FlowEnd(FlowEndEvent),
    /// Running byte counters of a long-lived flow (emitted when they change).
    FlowUpdate(FlowUpdateEvent),
    Dns(DnsEvent),
    Alert(AlertEvent),
    Stats(StatsEvent),
    Engine(EngineEvent),
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Block,
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
pub struct FlowEvent {
    pub id: u64,
    pub ts: u64,
    /// "tcp" or "udp".
    pub proto: &'static str,
    pub uid: Option<u32>,
    pub src: String,
    pub dst_ip: String,
    pub dst_port: u16,
    pub domain: Option<String>,
    /// Where `domain` came from: "sni", "quic", "http" or "dns" (reverse
    /// lookup in the DNS cache; least reliable).
    pub domain_source: Option<&'static str>,
    pub app_proto: Option<&'static str>,
    pub alpn: Option<String>,
    pub tls_version: Option<&'static str>,
    pub ja4: Option<String>,
    /// The JA4 fingerprint is listed by a JA4 feed.
    pub ja4_match: Option<crate::policy::Ja4Match>,
    /// Real Encrypted Client Hello in use: `domain` is only the provider's
    /// public name. (GREASE ECH, sent by browsers on every handshake, is not
    /// reported.)
    pub ech: bool,
    pub http_method: Option<String>,
    pub verdict: Option<Verdict>,
    pub reason: Option<String>,
    pub tags: Vec<&'static str>,
    /// Upstream path of the flow's connection: "direct", "wireguard" or
    /// "socks5". None when no upstream connection was attempted (blocked
    /// before connecting).
    pub via: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
pub struct FlowEndEvent {
    pub id: u64,
    pub ts: u64,
    /// Bytes sent by the app.
    pub tx: u64,
    /// Bytes received by the app.
    pub rx: u64,
    pub duration_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
pub struct FlowUpdateEvent {
    pub id: u64,
    pub ts: u64,
    pub tx: u64,
    pub rx: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DnsEvent {
    pub ts: u64,
    pub uid: Option<u32>,
    pub qname: String,
    pub qtype: String,
    pub rcode: String,
    pub answers: Vec<String>,
    pub verdict: Verdict,
    pub reason: Option<String>,
    pub latency_ms: u64,
    /// Resolver the app addressed (`virtual` for vigil's own resolver).
    pub server: String,
    pub transport: &'static str,
    /// How vigil reached the upstream resolver: `udp`, `tcp`, `dot` or
    /// `doh` (the one that answered, or the one that failed). `None` when
    /// no upstream was asked (sinkholed, refused).
    pub upstream: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AlertEvent {
    pub ts: u64,
    /// "beacon", "threat_domain", "threat_ip", "threat_ja4", "encrypted_dns",
    /// "hardcoded_dns".
    pub kind: &'static str,
    pub severity: Severity,
    pub uid: Option<u32>,
    pub target: String,
    pub message: String,
    pub detail: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
pub struct StatsEvent {
    pub ts: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub tcp_active: u64,
    pub udp_active: u64,
    pub flows_total: u64,
    pub dns_queries: u64,
    pub blocked: u64,
    pub dropped_packets: u64,
    pub dropped_events: u64,
    pub dns_cache_size: u64,
    /// Queries answered over DoT/DoH.
    pub encrypted_dns_ok: u64,
    /// Queries for which every encrypted server failed.
    pub encrypted_dns_failed: u64,
    /// Of those, answered in cleartext (`fallback_plain`).
    pub encrypted_dns_fallback: u64,
    /// Time (ms) of the last encrypted answer, 0 if none.
    pub encrypted_dns_last_ok_ts: u64,
    /// Time (ms) and text of the last encrypted failure.
    pub encrypted_dns_last_error_ts: u64,
    pub encrypted_dns_last_error: Option<String>,
    pub upstream: UpstreamStatus,
}

/// State of the upstream path (in `stats` events).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct UpstreamStatus {
    /// "direct", "wireguard" or "socks5".
    pub mode: &'static str,
    /// "up"; "connecting" (WireGuard handshake in progress); "idle" (no
    /// session or proxy contact yet, nothing pending); "down" (handshakes
    /// failing, proxy unreachable or the path could not be set up).
    pub state: &'static str,
    pub fail_closed: bool,
    /// WireGuard peer address in use, or the SOCKS5 server as configured.
    pub endpoint: Option<String>,
    /// Seconds since the last completed WireGuard handshake.
    pub handshake_age_s: Option<u64>,
    /// WireGuard payload bytes sent / received through the tunnel.
    pub tx_bytes: Option<u64>,
    pub rx_bytes: Option<u64>,
    pub last_error: Option<String>,
    /// SOCKS5 UDP relaying: "unknown", "supported", "unsupported", "blocked".
    pub udp: Option<&'static str>,
}

impl Default for UpstreamStatus {
    fn default() -> Self {
        Self {
            mode: "direct",
            state: "up",
            fail_closed: true,
            endpoint: None,
            handshake_age_s: None,
            tx_bytes: None,
            rx_bytes: None,
            last_error: None,
            udp: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct EngineEvent {
    pub ts: u64,
    pub state: &'static str,
    pub message: String,
}

/// How far from the front [`EventQueue::push`] looks for a low-value event
/// to drop before giving up and dropping the oldest event.
const DROP_SCAN: usize = 64;

impl Event {
    /// Periodic snapshots that a later event supersedes. Dropped first when
    /// the queue is full, to keep `flow`/`flow_end` pairs intact.
    fn is_superseded_later(&self) -> bool {
        matches!(self, Event::Stats(_) | Event::FlowUpdate(_))
    }
}

/// Bounded multi-producer event queue. When full, an old event is dropped
/// (and counted) so a stalled consumer can never exhaust memory: preferably
/// a `stats` or `flow_update` near the front, otherwise the oldest event.
/// How long a [`EventQueue::poll`] that had to wait keeps collecting after
/// the first event, so a busy engine wakes its consumer (on Android a JVM
/// thread that parses and stores every batch) at most about 50 times a
/// second instead of once per event.
const POLL_BATCH_WINDOW: Duration = Duration::from_millis(20);

struct Queue {
    events: VecDeque<Event>,
    /// Queue length at which `push` wakes the consumer: 1 while a poll
    /// waits for its first event, its `max` while it collects a batch,
    /// `usize::MAX` when no poll is waiting.
    wake_at: usize,
}

pub struct EventQueue {
    inner: Mutex<Queue>,
    cv: Condvar,
    capacity: usize,
    dropped: AtomicU64,
    /// Set once the engine has shut down: polls no longer wait.
    closed: AtomicBool,
}

impl EventQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Queue {
                events: VecDeque::with_capacity(1024),
                wake_at: usize::MAX,
            }),
            cv: Condvar::new(),
            capacity: capacity.max(1),
            dropped: AtomicU64::new(0),
            closed: AtomicBool::new(false),
        }
    }

    pub fn push(&self, e: Event) {
        let mut guard = self.inner.lock();
        let Queue { events: q, wake_at } = &mut *guard;
        if q.len() >= self.capacity {
            let victim = q
                .iter()
                .take(DROP_SCAN)
                .position(Event::is_superseded_later)
                .unwrap_or(0);
            q.remove(victim);
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        q.push_back(e);
        if q.len() >= *wake_at {
            *wake_at = usize::MAX;
            drop(guard);
            self.cv.notify_one();
        }
    }

    /// Waits up to `timeout` for at least one event, then drains up to `max`.
    /// If it had to wait, it keeps collecting for up to 20 ms more (within
    /// `timeout`) unless `max` events arrive first, so a steady trickle of
    /// events is delivered in batches. Returns immediately once the queue
    /// is [closed](Self::close).
    pub fn poll(&self, max: usize, timeout: Duration) -> Vec<Event> {
        let max = max.max(1);
        let mut q = self.inner.lock();
        if q.events.is_empty() && !self.closed.load(Ordering::Acquire) {
            let start = Instant::now();
            q.wake_at = 1;
            self.cv.wait_for(&mut q, timeout);
            let waited = start.elapsed();
            if !q.events.is_empty()
                && q.events.len() < max
                && waited < timeout
                && !self.closed.load(Ordering::Acquire)
            {
                q.wake_at = max;
                self.cv
                    .wait_for(&mut q, POLL_BATCH_WINDOW.min(timeout - waited));
            }
            q.wake_at = usize::MAX;
        }
        let n = q.events.len().min(max);
        q.events.drain(..n).collect()
    }

    /// Wakes a blocked [`poll`](Self::poll) call.
    pub fn wake(&self) {
        self.cv.notify_all();
    }

    /// Marks the queue as final: queued events can still be drained, but
    /// polls on an empty queue return at once instead of waiting.
    pub fn close(&self) {
        let q = self.inner.lock();
        self.closed.store(true, Ordering::Release);
        drop(q);
        self.cv.notify_all();
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn len(&self) -> usize {
        self.inner.lock().events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialises_with_type_tag() {
        let e = Event::FlowEnd(FlowEndEvent {
            id: 3,
            ts: 1,
            tx: 10,
            rx: 20,
            duration_ms: 5,
            error: None,
        });
        let j = serde_json::to_value(&e).unwrap();
        assert_eq!(j["type"], "flow_end");
        assert_eq!(j["rx"], 20);
        let f = Event::Flow(FlowEvent {
            verdict: Some(Verdict::Block),
            ..Default::default()
        });
        assert_eq!(serde_json::to_value(&f).unwrap()["verdict"], "block");
    }

    #[test]
    fn queue_drops_oldest() {
        let q = EventQueue::new(2);
        for i in 0..5 {
            q.push(Event::FlowEnd(FlowEndEvent {
                id: i,
                ..Default::default()
            }));
        }
        assert_eq!(q.dropped(), 3);
        let got = q.poll(10, Duration::from_millis(1));
        assert_eq!(got.len(), 2);
        assert!(matches!(&got[0], Event::FlowEnd(f) if f.id == 3));
        assert!(q.poll(10, Duration::from_millis(1)).is_empty());
    }

    #[test]
    fn queue_drops_snapshots_before_flow_events() {
        let q = EventQueue::new(3);
        q.push(Event::Flow(FlowEvent {
            id: 1,
            ..Default::default()
        }));
        q.push(Event::Stats(StatsEvent::default()));
        q.push(Event::FlowUpdate(FlowUpdateEvent::default()));
        q.push(Event::FlowEnd(FlowEndEvent {
            id: 1,
            ..Default::default()
        }));
        q.push(Event::FlowEnd(FlowEndEvent {
            id: 2,
            ..Default::default()
        }));
        assert_eq!(q.dropped(), 2);
        let got = q.poll(10, Duration::ZERO);
        assert!(matches!(&got[0], Event::Flow(f) if f.id == 1));
        assert!(matches!(&got[1], Event::FlowEnd(f) if f.id == 1));
        // With nothing cheaper to drop, the oldest goes.
        q.push(Event::FlowEnd(FlowEndEvent::default()));
        q.push(Event::FlowEnd(FlowEndEvent::default()));
        q.push(Event::FlowEnd(FlowEndEvent::default()));
        q.push(Event::FlowEnd(FlowEndEvent::default()));
        assert_eq!(q.dropped(), 3);
    }

    #[test]
    fn waiting_poll_collects_a_batch() {
        use std::sync::Arc;
        let q = Arc::new(EventQueue::new(100));
        let producer = {
            let q = q.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(50));
                for id in 0..5 {
                    q.push(Event::FlowEnd(FlowEndEvent {
                        id,
                        ..Default::default()
                    }));
                    std::thread::sleep(Duration::from_millis(1));
                }
            })
        };
        let t = Instant::now();
        let got = q.poll(100, Duration::from_secs(5));
        let took = t.elapsed();
        producer.join().unwrap();
        assert_eq!(got.len(), 5, "one batch, not one event per wake-up");
        assert!(took < Duration::from_secs(1), "{took:?}");
        // A full batch is returned without waiting for the window, and the
        // window never extends a poll past its timeout.
        let t = Instant::now();
        let feeder = {
            let q = q.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                for _ in 0..3 {
                    q.push(Event::FlowEnd(FlowEndEvent::default()));
                }
            })
        };
        assert_eq!(q.poll(3, Duration::from_secs(5)).len(), 3);
        feeder.join().unwrap();
        assert!(t.elapsed() < Duration::from_secs(1));
        q.push(Event::FlowEnd(FlowEndEvent::default()));
        assert_eq!(q.poll(3, Duration::ZERO).len(), 1);
    }

    #[test]
    fn closed_queue_drains_without_waiting() {
        let q = EventQueue::new(10);
        q.push(Event::FlowEnd(FlowEndEvent::default()));
        q.close();
        assert!(q.is_closed());
        assert_eq!(q.poll(10, Duration::from_secs(5)).len(), 1);
        let t = std::time::Instant::now();
        assert!(q.poll(10, Duration::from_secs(5)).is_empty());
        assert!(t.elapsed() < Duration::from_secs(1));
    }
}
