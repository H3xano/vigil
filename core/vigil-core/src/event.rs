//! Structured events streamed from the engine to the host.
//!
//! Every event serialises to one JSON object with a `type` discriminator.
//! Contract: each `flow` event is eventually followed by exactly one
//! `flow_end` with the same `id`.

use parking_lot::{Condvar, Mutex};
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
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
    pub ech: bool,
    pub http_method: Option<String>,
    pub verdict: Option<Verdict>,
    pub reason: Option<String>,
    pub tags: Vec<&'static str>,
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
    /// "beacon", "threat_domain", "threat_ip", "encrypted_dns", "hardcoded_dns".
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
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct EngineEvent {
    pub ts: u64,
    pub state: &'static str,
    pub message: String,
}

/// Bounded multi-producer event queue. When full the oldest events are
/// dropped (and counted) so a stalled consumer can never exhaust memory.
pub struct EventQueue {
    inner: Mutex<VecDeque<Event>>,
    cv: Condvar,
    capacity: usize,
    dropped: AtomicU64,
}

impl EventQueue {
    pub fn new(capacity: usize) -> Self {
        Self { inner: Mutex::new(VecDeque::with_capacity(1024)), cv: Condvar::new(), capacity, dropped: AtomicU64::new(0) }
    }

    pub fn push(&self, e: Event) {
        let mut q = self.inner.lock();
        if q.len() >= self.capacity {
            q.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        q.push_back(e);
        drop(q);
        self.cv.notify_one();
    }

    /// Waits up to `timeout` for at least one event, then drains up to `max`.
    pub fn poll(&self, max: usize, timeout: Duration) -> Vec<Event> {
        let mut q = self.inner.lock();
        if q.is_empty() {
            self.cv.wait_for(&mut q, timeout);
        }
        let n = q.len().min(max);
        q.drain(..n).collect()
    }

    /// Wakes a blocked [`poll`](Self::poll) call.
    pub fn wake(&self) {
        self.cv.notify_all();
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn len(&self) -> usize {
        self.inner.lock().len()
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
        let e = Event::FlowEnd(FlowEndEvent { id: 3, ts: 1, tx: 10, rx: 20, duration_ms: 5, error: None });
        let j = serde_json::to_value(&e).unwrap();
        assert_eq!(j["type"], "flow_end");
        assert_eq!(j["rx"], 20);
        let f = Event::Flow(FlowEvent { verdict: Some(Verdict::Block), ..Default::default() });
        assert_eq!(serde_json::to_value(&f).unwrap()["verdict"], "block");
    }

    #[test]
    fn queue_drops_oldest() {
        let q = EventQueue::new(2);
        for i in 0..5 {
            q.push(Event::FlowEnd(FlowEndEvent { id: i, ..Default::default() }));
        }
        assert_eq!(q.dropped(), 3);
        let got = q.poll(10, Duration::from_millis(1));
        assert_eq!(got.len(), 2);
        assert!(matches!(&got[0], Event::FlowEnd(f) if f.id == 3));
        assert!(q.poll(10, Duration::from_millis(1)).is_empty());
    }
}
