//! Packet capture: the raw IP packets crossing the TUN, as apps sent them
//! and as vigil wrote them back, in a bounded in-memory ring. Exported on
//! request as PCAPng (filtered by flow, app and time), and optionally
//! streamed live as PCAP-over-IP.
//!
//! Off by default. While off, the packet path pays one relaxed atomic load
//! per packet. While on, a packet costs a clock read, a mutex and a copy
//! into the ring (no allocation), plus one allocation shared by all
//! PCAP-over-IP clients when any is connected.
//!
//! Packets are attributed to flows and apps lazily, at export: the engine
//! records *bindings* of 5-tuples to UIDs (at every UID lookup) and to flow
//! ids (at every `flow` event), and the exporter matches each packet's
//! 5-tuple and time against them. The packet path does no lookups.

mod pcap;
mod ring;
mod stream;

pub use pcap::{packet_key, PacketKey, PcapngWriter, LINKTYPE_RAW};
pub use ring::Dir;
pub use stream::StreamStats;

use crate::config::CaptureConfig;
use crate::platform::Platform;
use parking_lot::Mutex;
use ring::{RecordHeader, Ring};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::{self, BufWriter};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// 5-tuples with bindings kept at most (new ones are not recorded beyond).
const MAX_BINDING_KEYS: usize = 65_536;
/// Bindings kept per 5-tuple (the oldest are dropped).
const MAX_BINDINGS_PER_KEY: usize = 8;
/// A flow binding completes the UID-only binding of the same 5-tuple made
/// this recently (the UID lookup at the SYN gate or a UDP flow's start).
const MERGE_WINDOW_US: u64 = 120_000_000;
/// Bindings are kept this long before the oldest packet in the ring.
const BINDING_SLACK_US: u64 = 60_000_000;
/// Bytes of the ring an export copies out per hold of the ring's lock.
const EXPORT_CHUNK: usize = 1 << 20;

fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

/// Key of a binding: protocol, the app's socket address, the remote one.
type BindingKey = (u8, SocketAddr, SocketAddr);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Binding {
    ts_us: u64,
    flow: Option<u64>,
    uid: Option<u32>,
}

#[derive(Default)]
struct Bindings {
    map: HashMap<BindingKey, Vec<Binding>>,
}

impl Bindings {
    fn bind(&mut self, key: BindingKey, b: Binding) {
        if !self.map.contains_key(&key) && self.map.len() >= MAX_BINDING_KEYS {
            return;
        }
        let v = self.map.entry(key).or_default();
        if let Some(last) = v.last_mut() {
            if b.flow.is_some()
                && last.flow.is_none()
                && b.ts_us.saturating_sub(last.ts_us) <= MERGE_WINDOW_US
            {
                last.flow = b.flow;
                last.uid = b.uid.or(last.uid);
                return;
            }
            if b.flow.is_none() && last.flow.is_none() && last.uid == b.uid {
                // Another lookup for the same socket (DNS queries).
                return;
            }
            if b.flow.is_some() && b.flow == last.flow {
                return;
            }
        }
        if v.len() >= MAX_BINDINGS_PER_KEY {
            v.remove(0);
        }
        v.push(b);
    }

    /// The binding of a packet of `key` seen at `ts_us`: the latest one
    /// made before it; for a connection-opening SYN (sent before the flow
    /// exists) or packets before any binding, the first one after it.
    fn resolve(&self, key: &BindingKey, ts_us: u64, opening: bool) -> Option<Binding> {
        let v = self.map.get(key)?;
        let after = v.iter().find(|b| b.ts_us >= ts_us);
        let before = v.iter().rev().find(|b| b.ts_us <= ts_us);
        if opening {
            after.or(before).copied()
        } else {
            before.or(after).copied()
        }
    }

    /// Forgets 5-tuples whose newest binding is older than `before_us`.
    fn prune(&mut self, before_us: u64) {
        self.map
            .retain(|_, v| v.last().is_some_and(|b| b.ts_us >= before_us));
    }
}

/// Which packets to export (all conditions AND-combined; empty or absent
/// means no condition).
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct CaptureFilter {
    pub flow_ids: Vec<u64>,
    pub uids: Vec<u32>,
    /// Inclusive bounds on the packet time (ms since the epoch).
    pub since_ms: Option<u64>,
    pub until_ms: Option<u64>,
}

/// Result of an export (the JSON returned by `nativeExportPcap`).
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct ExportSummary {
    pub packets: u64,
    /// Captured bytes of the exported packets (IP headers included).
    pub bytes: u64,
    /// Time of the first and last exported packet (ms), null if none.
    pub first_ts: Option<u64>,
    pub last_ts: Option<u64>,
    /// Packets that would have matched may already have been overwritten:
    /// the ring has dropped packets, and the requested window (or the
    /// requested flows) starts before the oldest packet still held.
    pub truncated_by_ring: bool,
}

/// `stats.capture` (see docs/EVENTS.md).
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct CaptureStats {
    pub enabled: bool,
    /// Packets and bytes recorded since capture was enabled.
    pub packets: u64,
    pub bytes: u64,
    /// Packets overwritten in the ring (the oldest) to make room.
    pub dropped: u64,
    /// What the ring holds now, and its size.
    pub buffered_packets: u64,
    pub buffered_bytes: u64,
    pub buffer_bytes: u64,
    /// PCAP-over-IP; null while it is off.
    pub stream: Option<StreamStats>,
}

pub(crate) struct Capture {
    /// The only thing the packet path reads while capture is off.
    on: AtomicBool,
    snaplen: AtomicU32,
    ring: Mutex<Option<Ring>>,
    bindings: Mutex<Bindings>,
    packets: AtomicU64,
    bytes: AtomicU64,
    /// Packets overwritten by earlier rings of this session (resizes).
    dropped_before: AtomicU64,
    stream: Arc<stream::Hub>,
    stream_on: AtomicBool,
    /// A resize is between its two steps (see [`Capture::apply`]).
    resizing: AtomicBool,
    /// Serialises [`Capture::apply`], so two resizes never overlap.
    applying: Mutex<()>,
}

impl Default for Capture {
    fn default() -> Self {
        Self {
            on: AtomicBool::new(false),
            snaplen: AtomicU32::new(crate::config::capture::DEFAULT_SNAPLEN),
            ring: Mutex::new(None),
            bindings: Mutex::new(Bindings::default()),
            packets: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            dropped_before: AtomicU64::new(0),
            stream: Arc::new(stream::Hub::default()),
            stream_on: AtomicBool::new(false),
            resizing: AtomicBool::new(false),
            applying: Mutex::new(()),
        }
    }
}

impl Capture {
    #[inline]
    pub fn is_on(&self) -> bool {
        self.on.load(Relaxed)
    }

    /// Records a packet crossing the TUN (a no-op while capture is off).
    #[inline]
    pub fn record(&self, pkt: &[u8], dir: Dir) {
        if self.on.load(Relaxed) {
            self.record_slow(pkt, dir);
        }
    }

    #[cold]
    fn record_slow(&self, pkt: &[u8], dir: Dir) {
        let snaplen = self.snaplen.load(Relaxed) as usize;
        let data = &pkt[..pkt.len().min(snaplen).min(u16::MAX as usize)];
        // The clock is read and the stream fed under the ring's lock, so
        // the ring and the stream are in time order across threads.
        let mut ring = self.ring.lock();
        let Some(r) = ring.as_mut() else {
            return;
        };
        let h = RecordHeader {
            ts_us: now_us(),
            orig_len: pkt.len() as u32,
            cap_len: data.len() as u16,
            dir,
        };
        if r.push(h, data).is_none() {
            return;
        }
        if self.stream.has_clients() {
            self.stream.send(bytes::Bytes::from(pcap::pcap_record(
                h.ts_us, h.orig_len, data,
            )));
        }
        drop(ring);
        self.packets.fetch_add(1, Relaxed);
        self.bytes.fetch_add(pkt.len() as u64, Relaxed);
    }

    /// Notes that the socket `app → remote` belongs to `uid` (called at
    /// every UID lookup; no-op while off).
    pub fn bind_uid(&self, proto: u8, app: SocketAddr, remote: SocketAddr, uid: Option<u32>) {
        if self.is_on() {
            self.bindings.lock().bind(
                (proto, app, remote),
                Binding {
                    ts_us: now_us(),
                    flow: None,
                    uid,
                },
            );
        }
    }

    /// Notes that `app → remote` carries flow `id` (called for every `flow`
    /// event; no-op while off).
    pub fn bind_flow(
        &self,
        proto: u8,
        app: SocketAddr,
        remote: SocketAddr,
        id: u64,
        uid: Option<u32>,
    ) {
        if self.is_on() {
            self.bind_flow_at(proto, app, remote, id, uid, now_us());
        }
    }

    fn bind_flow_at(
        &self,
        proto: u8,
        app: SocketAddr,
        remote: SocketAddr,
        id: u64,
        uid: Option<u32>,
        ts_us: u64,
    ) {
        self.bindings.lock().bind(
            (proto, app, remote),
            Binding {
                ts_us,
                flow: Some(id),
                uid,
            },
        );
    }

    /// Applies `capture` from the configuration. Enabling allocates the
    /// ring and returns true (the caller then binds the flows already
    /// open); disabling frees it and discards what it held; a new size
    /// keeps the newest packets that fit. Starts or stops the stream server
    /// (call inside the runtime).
    pub fn apply(&self, cfg: &CaptureConfig, platform: &Arc<dyn Platform>) -> bool {
        let _applying = self.applying.lock();
        let mut newly_on = false;
        let mut resize = None;
        {
            let mut ring = self.ring.lock();
            let size = cfg.buffer_bytes as usize;
            if !cfg.enabled {
                self.on.store(false, Relaxed);
                *ring = None;
                *self.bindings.lock() = Bindings::default();
            } else {
                self.snaplen.store(cfg.snaplen, Relaxed);
                match ring.as_mut() {
                    None => {
                        *ring = Some(Ring::new(size));
                        self.packets.store(0, Relaxed);
                        self.bytes.store(0, Relaxed);
                        self.dropped_before.store(0, Relaxed);
                        newly_on = true;
                    }
                    Some(cur) if cur.capacity() != size => {
                        // Recording goes on into a fresh ring while the old
                        // one is cut down outside the lock (finish_resize).
                        self.resizing.store(true, Relaxed);
                        let fresh = Ring::new(size);
                        let fresh_id = fresh.id();
                        resize = Some((std::mem::replace(cur, fresh), fresh_id, size));
                    }
                    Some(_) => {}
                }
                self.on.store(true, Relaxed);
            }
        }
        if let Some((old, fresh_id, size)) = resize {
            self.finish_resize(old, fresh_id, size);
        }
        let stream = cfg.enabled && cfg.stream.enabled;
        self.stream_on.store(stream, Relaxed);
        self.stream.apply(stream.then_some(&cfg.stream), platform);
        newly_on
    }

    /// Second half of a resize: keeps the newest packets of `old` that fit
    /// (in place when shrinking, while the packet path records into the
    /// fresh ring `fresh_id`), then puts them in front of what was recorded
    /// meanwhile. Discarded if capture was turned off or resized again in
    /// between.
    fn finish_resize(&self, old: Ring, fresh_id: u64, size: usize) {
        let old_evicted = old.evicted();
        let mut merged = old.resized(size);
        {
            let mut ring = self.ring.lock();
            if let Some(fresh) = ring.as_mut().filter(|r| r.id() == fresh_id) {
                fresh.for_each(|h, d| {
                    merged.push(h, d);
                });
                self.dropped_before
                    .fetch_add(old_evicted + fresh.evicted(), Relaxed);
                *fresh = merged;
            }
        }
        self.resizing.store(false, Relaxed);
    }

    /// Stops the stream server (engine shutdown). The ring is kept, so it
    /// can still be exported.
    pub fn stop_stream(&self) {
        self.stream.stop();
    }

    /// Housekeeping: forgets bindings older than every packet held.
    pub fn prune(&self) {
        // Mid-resize the ring holds only the newest packets: their age
        // would prune bindings the older ones still need.
        if !self.is_on() || self.resizing.load(Relaxed) {
            return;
        }
        let oldest = self.ring.lock().as_ref().and_then(|r| r.oldest_ts());
        let horizon = oldest
            .unwrap_or_else(now_us)
            .saturating_sub(BINDING_SLACK_US);
        self.bindings.lock().prune(horizon);
    }

    pub fn stats(&self) -> CaptureStats {
        let ring = self.ring.lock();
        let Some(r) = ring.as_ref() else {
            return CaptureStats::default();
        };
        CaptureStats {
            enabled: self.is_on(),
            packets: self.packets.load(Relaxed),
            bytes: self.bytes.load(Relaxed),
            dropped: self.dropped_before.load(Relaxed) + r.evicted(),
            buffered_packets: r.records() as u64,
            buffered_bytes: r.used() as u64,
            buffer_bytes: r.capacity() as u64,
            stream: self.stream_on.load(Relaxed).then(|| self.stream.stats()),
        }
    }

    /// Writes the packets matching `filter` to `path` as PCAPng, in one
    /// pass over the ring: records are copied out in chunks of at most
    /// [`EXPORT_CHUNK`] bytes under the ring's lock (so the packet path
    /// waits for one short copy at a time, and memory stays bounded), then
    /// matched and written without it. The export covers what the ring
    /// held when it started; packets overwritten while it runs are missing
    /// (and reported as `truncated_by_ring`). With capture off the file
    /// holds no packets.
    pub fn export(&self, filter: &CaptureFilter, path: &Path) -> io::Result<ExportSummary> {
        let since_us = filter.since_ms.map(|m| m.saturating_mul(1000));
        let until_us = filter
            .until_ms
            .map(|m| m.saturating_mul(1000).saturating_add(999));
        let flows: HashSet<u64> = filter.flow_ids.iter().copied().collect();
        let uids: HashSet<u32> = filter.uids.iter().copied().collect();
        let attribute = !flows.is_empty() || !uids.is_empty();

        // The ring's id, the next position to read and where to stop.
        let (mut cursor, evicted, oldest, snaplen) = {
            let ring = self.ring.lock();
            let snaplen = self.snaplen.load(Relaxed);
            match ring.as_ref() {
                Some(r) => (
                    Some((r.id(), r.head(), r.tail())),
                    r.evicted() + self.dropped_before.load(Relaxed),
                    r.oldest_ts(),
                    // Records taken before the snap length was lowered are
                    // longer: the declared one must cover them all.
                    snaplen.max(r.max_cap_len() as u32),
                ),
                None => (None, 0, None, snaplen),
            }
        };
        let earliest_flow_binding = if flows.is_empty() {
            None
        } else {
            self.bindings
                .lock()
                .map
                .values()
                .flatten()
                .filter(|b| b.flow.is_some_and(|f| flows.contains(&f)))
                .map(|b| b.ts_us)
                .min()
        };

        let file = std::fs::File::create(path)?;
        let app = format!("vigil {}", env!("CARGO_PKG_VERSION"));
        let mut w = PcapngWriter::new(BufWriter::with_capacity(256 * 1024, file), snaplen, &app)?;
        let mut sum = ExportSummary::default();
        let mut comment = String::new();
        let mut chunk = Vec::new();
        let mut lost = false;
        while let Some((id, pos, end)) = cursor {
            {
                let ring = self.ring.lock();
                let Some(r) = ring.as_ref().filter(|r| r.id() == id) else {
                    // Turned off or resized meanwhile.
                    lost = true;
                    break;
                };
                // Overwritten since the export started.
                lost |= pos < r.head();
                let pos = pos.max(r.head());
                if pos >= end {
                    break;
                }
                cursor = Some((id, r.read_records(pos, end, EXPORT_CHUNK, &mut chunk), end));
            }
            for (h, data) in ring::records(&chunk) {
                if since_us.is_some_and(|s| h.ts_us < s) || until_us.is_some_and(|u| h.ts_us > u) {
                    continue;
                }
                let binding = packet_key(data).and_then(|k| {
                    let (app, remote) = match h.dir {
                        Dir::FromApp => (k.src, k.dst),
                        Dir::ToApp => (k.dst, k.src),
                    };
                    let opening = k.initial_syn && h.dir == Dir::FromApp;
                    self.bindings
                        .lock()
                        .resolve(&(k.proto, app, remote), h.ts_us, opening)
                });
                if attribute {
                    let Some(b) = binding else { continue };
                    if !flows.is_empty() && !b.flow.is_some_and(|f| flows.contains(&f)) {
                        continue;
                    }
                    if !uids.is_empty() && !b.uid.is_some_and(|u| uids.contains(&u)) {
                        continue;
                    }
                }
                comment.clear();
                if let Some(b) = binding {
                    use std::fmt::Write as _;
                    if let Some(u) = b.uid {
                        let _ = write!(comment, "uid={u}");
                    }
                    if let Some(f) = b.flow {
                        let _ = write!(
                            comment,
                            "{}flow={f}",
                            if comment.is_empty() { "" } else { " " }
                        );
                    }
                }
                w.packet(
                    h.ts_us,
                    h.orig_len,
                    data,
                    h.dir,
                    (!comment.is_empty()).then_some(comment.as_str()),
                )?;
                sum.packets += 1;
                sum.bytes += data.len() as u64;
                sum.first_ts.get_or_insert(h.ts_us / 1000);
                sum.last_ts = Some(h.ts_us / 1000);
            }
        }
        let file = w.finish()?.into_inner().map_err(|e| e.into_error())?;
        file.sync_all()?;
        // The window starts before what the ring still holds, and the ring
        // has overwritten packets: some matching ones may be gone.
        let start = since_us.or(earliest_flow_binding).unwrap_or(0);
        sum.truncated_by_ring = lost || (evicted > 0 && oldest.map_or(true, |o| start < o));
        Ok(sum)
    }
}

#[cfg(test)]
mod tests {
    use super::pcap::tests::{blocks, epb};
    use super::*;
    use crate::packet::{self, PROTO_TCP, PROTO_UDP};

    fn null() -> Arc<dyn Platform> {
        Arc::new(crate::platform::NullPlatform)
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn on(buffer: u64) -> Capture {
        let c = Capture::default();
        assert!(c.apply(
            &CaptureConfig {
                enabled: true,
                buffer_bytes: buffer,
                ..Default::default()
            },
            &null()
        ));
        c
    }

    fn export_file(c: &Capture, f: &CaptureFilter) -> (ExportSummary, Vec<u8>) {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "vigil-capture-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Relaxed)
        ));
        let sum = c.export(f, &dir).unwrap();
        let file = std::fs::read(&dir).unwrap();
        std::fs::remove_file(&dir).unwrap();
        (sum, file)
    }

    fn export(c: &Capture, f: &CaptureFilter) -> (ExportSummary, Vec<(u64, Vec<u8>, String)>) {
        let (sum, file) = export_file(c, f);
        let pkts = blocks(&file)
            .into_iter()
            .filter(|(t, _)| *t == 6)
            .map(|(_, body)| {
                let (ts, data, _, opts) = epb(&body);
                let comment = opts
                    .iter()
                    .find(|(c, _)| *c == 1)
                    .map(|(_, v)| String::from_utf8(v.clone()).unwrap())
                    .unwrap_or_default();
                (ts, data, comment)
            })
            .collect();
        (sum, pkts)
    }

    #[test]
    fn off_records_nothing() {
        let c = Capture::default();
        let p = packet::build_udp(sa("10.0.0.2:1000"), sa("192.0.2.1:53"), b"x").unwrap();
        c.record(&p, Dir::FromApp);
        c.bind_uid(PROTO_UDP, sa("10.0.0.2:1000"), sa("192.0.2.1:53"), Some(1));
        assert_eq!(c.stats(), CaptureStats::default());
        assert!(c.bindings.lock().map.is_empty());
        let (sum, pkts) = export(&c, &CaptureFilter::default());
        assert_eq!(
            (sum.packets, pkts.len(), sum.truncated_by_ring),
            (0, 0, false)
        );
    }

    #[test]
    fn attributes_packets_to_flows_and_apps() {
        let c = on(1 << 20);
        let (app, web, app2, dns) = (
            sa("10.111.222.1:40000"),
            sa("192.0.2.10:443"),
            sa("10.111.222.1:40001"),
            sa("10.111.222.2:53"),
        );
        // The SYN arrives before the gate's UID lookup and the flow event.
        let syn = packet::build_tcp(app, web, 1, 0, packet::TCP_SYN, &[]).unwrap();
        c.record(&syn, Dir::FromApp);
        c.bind_uid(PROTO_TCP, app, web, Some(10123));
        let syn_ack =
            packet::build_tcp(web, app, 9, 2, packet::TCP_SYN | packet::TCP_ACK, &[]).unwrap();
        c.bind_flow(PROTO_TCP, app, web, 7, Some(10123));
        c.record(&syn_ack, Dir::ToApp);
        let data = packet::build_tcp(app, web, 2, 10, packet::TCP_ACK, b"GET /").unwrap();
        c.record(&data, Dir::FromApp);
        // A DNS query of another app (UID binding only, no flow).
        let q = packet::build_udp(app2, dns, b"query").unwrap();
        c.record(&q, Dir::FromApp);
        c.bind_uid(PROTO_UDP, app2, dns, Some(10200));
        c.bind_uid(PROTO_UDP, app2, dns, Some(10200));
        let a = packet::build_udp(dns, app2, b"answer").unwrap();
        c.record(&a, Dir::ToApp);
        // Unattributed traffic.
        let other = packet::build_udp(sa("10.111.222.1:5000"), sa("198.51.100.1:9"), b"?").unwrap();
        c.record(&other, Dir::FromApp);

        let (sum, all) = export(&c, &CaptureFilter::default());
        assert_eq!(sum.packets, 6);
        assert_eq!(
            all.iter().map(|p| p.2.as_str()).collect::<Vec<_>>(),
            vec![
                "uid=10123 flow=7",
                "uid=10123 flow=7",
                "uid=10123 flow=7",
                "uid=10200",
                "uid=10200",
                ""
            ]
        );
        assert_eq!(all[0].1, syn);
        assert!(!sum.truncated_by_ring);

        let (sum, flow) = export(
            &c,
            &CaptureFilter {
                flow_ids: vec![7],
                ..Default::default()
            },
        );
        assert_eq!(sum.packets, 3);
        assert_eq!(flow[2].1, data);
        assert_eq!(sum.bytes, (syn.len() + syn_ack.len() + data.len()) as u64);
        let (_, by_uid) = export(
            &c,
            &CaptureFilter {
                uids: vec![10200],
                ..Default::default()
            },
        );
        assert_eq!(
            by_uid.iter().map(|p| &p.1).collect::<Vec<_>>(),
            vec![&q, &a]
        );
        // AND-combined: flow 7 of another app matches nothing.
        let (sum, _) = export(
            &c,
            &CaptureFilter {
                flow_ids: vec![7],
                uids: vec![10200],
                ..Default::default()
            },
        );
        assert_eq!(sum.packets, 0);
        assert_eq!((sum.first_ts, sum.last_ts), (None, None));
        // Time window.
        let t_q = all[3].0;
        let (sum, win) = export(
            &c,
            &CaptureFilter {
                since_ms: Some(t_q / 1000),
                ..Default::default()
            },
        );
        assert!(win.iter().all(|p| p.0 / 1000 >= t_q / 1000));
        assert!(sum.packets >= 3 && sum.first_ts.unwrap() >= t_q / 1000);
        let (sum, _) = export(
            &c,
            &CaptureFilter {
                until_ms: Some(1),
                ..Default::default()
            },
        );
        assert_eq!(sum.packets, 0);
    }

    #[test]
    fn port_reuse_starts_a_new_binding() {
        let c = on(1 << 20);
        let (app, srv) = (sa("10.0.0.2:5000"), sa("192.0.2.1:443"));
        let mut b = c.bindings.lock();
        b.bind(
            (PROTO_TCP, app, srv),
            Binding {
                ts_us: 1_000,
                flow: None,
                uid: Some(1),
            },
        );
        b.bind(
            (PROTO_TCP, app, srv),
            Binding {
                ts_us: 2_000,
                flow: Some(1),
                uid: Some(1),
            },
        );
        // Much later: a new connection on the same 4-tuple.
        let later = 1_000 + MERGE_WINDOW_US * 2;
        b.bind(
            (PROTO_TCP, app, srv),
            Binding {
                ts_us: later,
                flow: None,
                uid: Some(1),
            },
        );
        b.bind(
            (PROTO_TCP, app, srv),
            Binding {
                ts_us: later + 10,
                flow: Some(2),
                uid: Some(1),
            },
        );
        let key = (PROTO_TCP, app, srv);
        assert_eq!(b.resolve(&key, 500, true).unwrap().flow, Some(1));
        assert_eq!(b.resolve(&key, 5_000, false).unwrap().flow, Some(1));
        assert_eq!(b.resolve(&key, later - 1, true).unwrap().flow, Some(2));
        assert_eq!(b.resolve(&key, later + 50, false).unwrap().flow, Some(2));
        assert!(b.resolve(&(PROTO_UDP, app, srv), 5_000, false).is_none());
        b.prune(later);
        assert_eq!(b.map.len(), 1);
        b.prune(later + 11);
        assert!(b.map.is_empty());
    }

    #[test]
    fn ring_eviction_reported_and_resize_keeps_newest() {
        let c = on(64 * 1024);
        let p = packet::build_udp(sa("10.0.0.2:1000"), sa("192.0.2.1:9"), &[0u8; 972]).unwrap();
        assert_eq!(p.len(), 1000);
        for _ in 0..200 {
            c.record(&p, Dir::FromApp);
        }
        let s = c.stats();
        assert_eq!((s.packets, s.bytes), (200, 200_000));
        assert_eq!(s.buffered_packets, 64 * 1024 / 1016);
        assert_eq!(s.dropped, 200 - s.buffered_packets);
        assert_eq!(s.buffer_bytes, 64 * 1024);
        assert!(s.stream.is_none());
        let (sum, _) = export(&c, &CaptureFilter::default());
        assert!(sum.truncated_by_ring);
        assert_eq!(sum.packets, s.buffered_packets);
        let (sum, _) = export(
            &c,
            &CaptureFilter {
                since_ms: Some(now_us() / 1000 + 1000),
                ..Default::default()
            },
        );
        assert!(!sum.truncated_by_ring && sum.packets == 0);
        // Bigger ring: everything held is kept.
        c.apply(
            &CaptureConfig {
                enabled: true,
                buffer_bytes: 1 << 20,
                ..Default::default()
            },
            &null(),
        );
        let s2 = c.stats();
        assert_eq!(s2.buffered_packets, s.buffered_packets);
        assert_eq!(s2.dropped, s.dropped);
        // Smaller snap length: packets are cut, the original length kept.
        c.apply(
            &CaptureConfig {
                enabled: true,
                buffer_bytes: 1 << 20,
                snaplen: 100,
                ..Default::default()
            },
            &null(),
        );
        c.record(&p, Dir::ToApp);
        let (_, pkts) = export(&c, &CaptureFilter::default());
        assert_eq!(pkts.last().unwrap().1, p[..100].to_vec());
        // Off: the ring and bindings are discarded.
        assert!(!c.apply(&CaptureConfig::default(), &null()));
        assert_eq!(c.stats(), CaptureStats::default());
        c.record(&p, Dir::FromApp);
        assert_eq!(export(&c, &CaptureFilter::default()).0.packets, 0);
    }

    fn udp(fill: u8, len: usize) -> Vec<u8> {
        packet::build_udp(sa("10.0.0.2:1000"), sa("192.0.2.1:9"), &vec![fill; len]).unwrap()
    }

    fn with(buffer: u64, snaplen: u32) -> CaptureConfig {
        CaptureConfig {
            enabled: true,
            buffer_bytes: buffer,
            snaplen,
            ..Default::default()
        }
    }

    #[test]
    fn export_declares_a_snaplen_covering_every_record() {
        let c = on(1 << 20);
        let p = udp(1, 972);
        c.record(&p, Dir::FromApp);
        // Lowered at runtime: the packet already held stays 1000 bytes.
        c.apply(&with(1 << 20, 100), &null());
        c.record(&p, Dir::ToApp);
        let (sum, file) = export_file(&c, &CaptureFilter::default());
        assert_eq!(sum.bytes, 1100);
        let idb = blocks(&file).into_iter().find(|(t, _)| *t == 1).unwrap().1;
        let snaplen = u32::from_le_bytes(idb[4..8].try_into().unwrap());
        assert_eq!(snaplen, 1000);
        // Nothing longer than the snap length held: it is declared as is.
        let c = on(1 << 20);
        c.apply(&with(1 << 20, 200), &null());
        c.record(&p, Dir::FromApp);
        let idb = blocks(&export_file(&c, &CaptureFilter::default()).1)
            .into_iter()
            .find(|(t, _)| *t == 1)
            .unwrap()
            .1;
        assert_eq!(u32::from_le_bytes(idb[4..8].try_into().unwrap()), 200);
    }

    #[test]
    fn export_spans_several_chunks_in_order() {
        let c = on(4 << 20);
        let n = 3 * EXPORT_CHUNK / 1016 + 7;
        for i in 0..n {
            c.record(&udp(i as u8, 972), Dir::FromApp);
        }
        let (sum, pkts) = export(&c, &CaptureFilter::default());
        assert_eq!((sum.packets as usize, pkts.len()), (n, n));
        assert!(!sum.truncated_by_ring);
        for (i, p) in pkts.iter().enumerate() {
            assert_eq!(p.1, udp(i as u8, 972));
        }
        assert!(pkts.windows(2).all(|w| w[0].0 <= w[1].0));
    }

    #[test]
    fn resize_merges_packets_recorded_meanwhile() {
        let c = on(64 * 1024);
        for i in 0..3 {
            c.record(&udp(i, 100), Dir::FromApp);
        }
        // The first half of a resize, as apply does it.
        let take = |size: usize| {
            let mut ring = c.ring.lock();
            let fresh = Ring::new(size);
            let id = fresh.id();
            c.resizing.store(true, Relaxed);
            (std::mem::replace(ring.as_mut().unwrap(), fresh), id)
        };
        let (old, fresh_id) = take(128 * 1024);
        c.record(&udp(3, 100), Dir::FromApp);
        c.prune(); // a no-op while resizing
        c.finish_resize(old, fresh_id, 128 * 1024);
        assert!(!c.resizing.load(Relaxed));
        let s = c.stats();
        assert_eq!(
            (s.buffered_packets, s.buffer_bytes, s.dropped),
            (4, 128 * 1024, 0)
        );
        let (_, pkts) = export(&c, &CaptureFilter::default());
        let got: Vec<_> = pkts.into_iter().map(|p| p.1).collect();
        assert_eq!(got, (0..4).map(|i| udp(i, 100)).collect::<Vec<_>>());

        // Shrinking drops the oldest; turned off in between, it is dropped.
        let (old, fresh_id) = take(300);
        c.finish_resize(old, fresh_id, 300);
        let s = c.stats();
        assert_eq!((s.buffered_packets, s.dropped), (2, 2));
        let (old, fresh_id) = take(1 << 20);
        c.apply(&CaptureConfig::default(), &null());
        c.finish_resize(old, fresh_id, 1 << 20);
        assert_eq!(c.stats(), CaptureStats::default());
    }

    #[test]
    fn filter_json() {
        let f: CaptureFilter =
            serde_json::from_str(r#"{"flow_ids":[3,4],"uids":[10123],"since_ms":1,"until_ms":2}"#)
                .unwrap();
        assert_eq!(f.flow_ids, vec![3, 4]);
        assert_eq!((f.since_ms, f.until_ms), (Some(1), Some(2)));
        assert_eq!(
            serde_json::from_str::<CaptureFilter>("{}").unwrap(),
            CaptureFilter::default()
        );
        let s = serde_json::to_value(ExportSummary::default()).unwrap();
        assert_eq!(
            s,
            serde_json::json!({"packets":0,"bytes":0,"first_ts":null,"last_ts":null,"truncated_by_ring":false})
        );
    }

    #[test]
    fn verified_by_capinfos_if_installed() {
        let Ok(out) = std::process::Command::new("capinfos").arg("-v").output() else {
            eprintln!("capinfos not installed; skipped");
            return;
        };
        if !out.status.success() {
            return;
        }
        let c = on(1 << 20);
        for i in 0..10u16 {
            let p = packet::build_udp(
                sa("10.0.0.2:1000"),
                sa("192.0.2.1:53"),
                &vec![1; i as usize],
            )
            .unwrap();
            c.record(&p, if i % 2 == 0 { Dir::FromApp } else { Dir::ToApp });
        }
        c.bind_uid(
            PROTO_UDP,
            sa("10.0.0.2:1000"),
            sa("192.0.2.1:53"),
            Some(10123),
        );
        let path =
            std::env::temp_dir().join(format!("vigil-capinfos-{}.pcapng", std::process::id()));
        c.export(&CaptureFilter::default(), &path).unwrap();
        let out = std::process::Command::new("capinfos")
            .args(["-c", "-E", "-T", "-r"])
            .arg(&path)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        std::fs::remove_file(&path).unwrap();
        assert!(
            out.status.success(),
            "{text} {}",
            String::from_utf8_lossy(&out.stderr)
        );
        // Tab-separated: file, encapsulation, packets.
        assert!(text.contains("\t10"), "{text}");
        let lower = text.to_lowercase();
        assert!(
            lower.contains("rawip") || lower.contains("raw ip"),
            "{text}"
        );
    }
}
