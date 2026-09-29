//! Behavioural detectors.
//!
//! [`BeaconDetector`] flags apps that contact the same destination at a
//! near-constant interval — the signature of C2 check-ins and of telemetry
//! heartbeats. For each (uid, destination) it keeps the most recent
//! connection times and computes the coefficient of variation (stddev/mean)
//! of the intervals. Bursts (several connections within a second, as
//! browsers and HTTP clients open in parallel) count as one event.
//!
//! [`FlowBurstDetector`] applies the same test to the activity bursts inside
//! one long-lived connection, sampled from the flow byte counters.

use crate::config::BeaconConfig;
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

const WINDOW: usize = 12;
const BURST_GAP: Duration = Duration::from_secs(1);
const REALERT_AFTER: Duration = Duration::from_secs(3600);
const MAX_SERIES: usize = 20_000;
/// Minimum time between two prunes of a full beacon table.
const PRUNE_EVERY: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq)]
pub struct BeaconHit {
    pub mean_interval_s: f64,
    pub jitter: f64,
    pub samples: usize,
}

struct Series {
    times: VecDeque<Instant>,
    last_alert: Option<Instant>,
}

struct SeriesMap {
    map: HashMap<(Option<u32>, String), Series>,
    last_prune: Option<Instant>,
}

pub struct BeaconDetector {
    series: Mutex<SeriesMap>,
    max_series: usize,
}

impl Default for BeaconDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BeaconDetector {
    pub fn new() -> Self {
        Self::with_capacity(MAX_SERIES)
    }

    pub fn with_capacity(max_series: usize) -> Self {
        Self {
            series: Mutex::new(SeriesMap {
                map: HashMap::new(),
                last_prune: None,
            }),
            max_series,
        }
    }

    pub fn len(&self) -> usize {
        self.series.lock().map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn observe(
        &self,
        cfg: &BeaconConfig,
        uid: Option<u32>,
        target: &str,
        now: Instant,
    ) -> Option<BeaconHit> {
        if !cfg.enabled {
            return None;
        }
        let mut guard = self.series.lock();
        let sm = &mut *guard;
        let key = (uid, target.to_string());
        if sm.map.len() >= self.max_series && !sm.map.contains_key(&key) {
            // Full: prune stale series, but at most once per PRUNE_EVERY so a
            // stream of new targets cannot make every call O(n). Until then
            // new targets are simply not tracked.
            let due = sm
                .last_prune
                .map_or(true, |t| now.saturating_duration_since(t) >= PRUNE_EVERY);
            if !due {
                return None;
            }
            sm.last_prune = Some(now);
            // A series is stale once it could no longer continue: its last
            // connection is older than the largest interval considered.
            let horizon = Duration::try_from_secs_f64(cfg.max_interval_s * 2.0)
                .unwrap_or(Duration::MAX)
                .max(BURST_GAP);
            sm.map.retain(|_, s| {
                s.times
                    .back()
                    .is_some_and(|t| now.saturating_duration_since(*t) < horizon)
            });
            if sm.map.len() >= self.max_series {
                return None;
            }
        }
        let s = sm.map.entry(key).or_insert_with(|| Series {
            times: VecDeque::with_capacity(WINDOW),
            last_alert: None,
        });
        if let Some(last) = s.times.back() {
            let gap = now.saturating_duration_since(*last);
            if gap < BURST_GAP {
                return None;
            }
            // A gap far above the maximum interval restarts the series.
            if gap.as_secs_f64() > cfg.max_interval_s * 3.0 {
                s.times.clear();
            }
        }
        s.times.push_back(now);
        if s.times.len() > WINDOW {
            s.times.pop_front();
        }
        if s.times.len() < cfg.min_events.max(3) {
            return None;
        }
        if s.last_alert
            .is_some_and(|t| now.duration_since(t) < REALERT_AFTER)
        {
            return None;
        }
        let (mean, jitter) = periodicity(cfg, s.times.iter().copied())?;
        s.last_alert = Some(now);
        Some(BeaconHit {
            mean_interval_s: mean,
            jitter,
            samples: s.times.len(),
        })
    }
}

/// Mean interval (s) and coefficient of variation of the intervals between
/// consecutive `times`, if the series is periodic by `cfg`: the mean lies in
/// `[min_interval_s, max_interval_s]` and the jitter is at most `max_jitter`.
fn periodicity(cfg: &BeaconConfig, times: impl Iterator<Item = Instant>) -> Option<(f64, f64)> {
    let mut prev: Option<Instant> = None;
    let intervals: Vec<f64> = times
        .filter_map(|t| {
            let d = prev.map(|p| t.saturating_duration_since(p).as_secs_f64());
            prev = Some(t);
            d
        })
        .collect();
    if intervals.is_empty() {
        return None;
    }
    let n = intervals.len() as f64;
    let mean = intervals.iter().sum::<f64>() / n;
    if mean <= 0.0 || mean < cfg.min_interval_s || mean > cfg.max_interval_s {
        return None;
    }
    let var = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    let jitter = var.sqrt() / mean;
    (jitter <= cfg.max_jitter).then_some((mean, jitter))
}

/// A periodic series of bursts inside one flow.
#[derive(Debug, Clone, PartialEq)]
pub struct FlowBeaconHit {
    pub mean_interval_s: f64,
    pub jitter: f64,
    /// Bursts in the series.
    pub samples: usize,
    /// Mean size of the completed bursts (bytes, both directions).
    pub burst_bytes: u64,
}

/// One sample of an open flow's counters, as seen by [`FlowBurstDetector`].
#[derive(Debug, Clone, Copy)]
pub struct FlowSample {
    pub id: u64,
    /// Bytes moved so far, both directions.
    pub bytes: u64,
    /// Flow age.
    pub age: Duration,
}

struct Burst {
    start: Instant,
    bytes: u64,
}

struct Timeline {
    last_bytes: u64,
    last_change: Instant,
    bursts: VecDeque<Burst>,
    alerted: bool,
    /// Sampling pass that last saw the flow (to drop ended flows).
    seen: u64,
}

struct Timelines {
    map: HashMap<u64, Timeline>,
    pass: u64,
}

/// Periodic activity bursts inside long-lived flows: the heartbeat of an
/// implant that keeps one TLS or QUIC connection open instead of
/// reconnecting (which [`BeaconDetector`] would see).
///
/// It costs nothing on the packet path: it reads the flows' existing byte
/// counters once per housekeeping tick (`stats_interval_ms`, at most 1 s).
/// A *burst* starts when bytes move after at least `flow_idle_gap_s` of
/// silence; its start times are judged like connection times (mean interval
/// and jitter), and the mean size of the completed bursts must be within
/// `flow_min_burst_bytes..=flow_max_burst_bytes`. Timing resolution is one
/// tick, which adds about 0.4 × tick of noise to each interval.
///
/// Only flows older than `flow_min_age_s` whose lifetime average stays at or
/// below `flow_max_avg_bps` are watched, at most `flow_max_tracked` at once,
/// each keeping the last [`WINDOW`] bursts: memory is bounded by
/// `flow_max_tracked × ~400 bytes`.
pub struct FlowBurstDetector {
    state: Mutex<Timelines>,
}

impl Default for FlowBurstDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowBurstDetector {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(Timelines {
                map: HashMap::new(),
                pass: 0,
            }),
        }
    }

    /// Flows being watched.
    pub fn len(&self) -> usize {
        self.state.lock().map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Stops watching a flow (it ended).
    pub fn forget(&self, id: u64) {
        self.state.lock().map.remove(&id);
    }

    pub fn clear(&self) {
        self.state.lock().map.clear();
    }

    /// Folds one sampling pass over the eligible open flows (not ignored,
    /// allowed) into the timelines and returns the flows whose bursts just
    /// became periodic (once per flow). Flows absent from the pass are
    /// forgotten.
    pub fn sample(
        &self,
        cfg: &BeaconConfig,
        flows: impl IntoIterator<Item = FlowSample>,
        now: Instant,
    ) -> Vec<(u64, FlowBeaconHit)> {
        let mut guard = self.state.lock();
        let st = &mut *guard;
        if !cfg.enabled || !cfg.flow_enabled {
            st.map.clear();
            return Vec::new();
        }
        st.pass += 1;
        let pass = st.pass;
        let idle_gap = Duration::try_from_secs_f64(cfg.flow_idle_gap_s).unwrap_or(Duration::MAX);
        let restart_after = cfg.max_interval_s * 3.0;
        let mut hits = Vec::new();
        for f in flows {
            let age = f.age.as_secs_f64();
            let busy = age > 0.0 && f.bytes as f64 / age > cfg.flow_max_avg_bps;
            let len = st.map.len();
            let Some(t) = st.map.get_mut(&f.id) else {
                if busy || age < cfg.flow_min_age_s || len >= cfg.flow_max_tracked {
                    continue;
                }
                // Starts in an active state: the first burst needs a gap first.
                st.map.insert(
                    f.id,
                    Timeline {
                        last_bytes: f.bytes,
                        last_change: now,
                        bursts: VecDeque::with_capacity(WINDOW),
                        alerted: false,
                        seen: pass,
                    },
                );
                continue;
            };
            t.seen = pass;
            if busy {
                // Bulk transfer: stop watching (it may come back once idle).
                st.map.remove(&f.id);
                continue;
            }
            let delta = f.bytes.saturating_sub(t.last_bytes);
            if delta == 0 {
                continue;
            }
            let quiet = now.saturating_duration_since(t.last_change);
            t.last_bytes = f.bytes;
            t.last_change = now;
            if quiet < idle_gap {
                if let Some(b) = t.bursts.back_mut() {
                    b.bytes = b.bytes.saturating_add(delta);
                }
                continue;
            }
            if quiet.as_secs_f64() > restart_after {
                t.bursts.clear();
            }
            t.bursts.push_back(Burst {
                start: now,
                bytes: delta,
            });
            if t.bursts.len() > WINDOW {
                t.bursts.pop_front();
            }
            if t.alerted || t.bursts.len() < cfg.min_events.max(3) {
                continue;
            }
            // Sizes of the completed bursts (the newest may still grow).
            let done = t.bursts.len() - 1;
            let burst_bytes =
                t.bursts.iter().take(done).map(|b| b.bytes).sum::<u64>() / done as u64;
            if burst_bytes < cfg.flow_min_burst_bytes || burst_bytes > cfg.flow_max_burst_bytes {
                continue;
            }
            let Some((mean, jitter)) = periodicity(cfg, t.bursts.iter().map(|b| b.start)) else {
                continue;
            };
            t.alerted = true;
            hits.push((
                f.id,
                FlowBeaconHit {
                    mean_interval_s: mean,
                    jitter,
                    samples: t.bursts.len(),
                    burst_bytes,
                },
            ));
        }
        st.map.retain(|_, t| t.seen == pass);
        hits
    }
}

/// Default bound on remembered alert keys.
pub const ALERT_KEYS: usize = 10_000;
/// Default budget of alerts per minute across all keys, for each class
/// ([`AlertClass`]): high-severity alerts have their own, so a flood of
/// low-severity ones cannot suppress them.
pub const ALERTS_PER_MINUTE: u32 = 120;
/// Bound on remembered groups (see [`AlertLimiter::admit`]); groups whose
/// minute is over are forgotten first.
const ALERT_GROUPS: usize = 4096;

/// Which per-minute budget an alert draws from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertClass {
    /// Info to medium severity.
    Normal,
    /// High severity (threat feed matches).
    High,
}

struct Group {
    minute_start: Instant,
    count: u32,
    /// Alerts of the group held back by its cap since its last admitted one.
    held: u64,
}

struct LimiterState {
    /// Key → time it last raised an alert.
    seen: HashMap<String, Instant>,
    /// Keys in the order they were (re-)admitted. An entry is stale when the
    /// map holds a newer time for its key.
    order: VecDeque<(String, Instant)>,
    minute_start: Option<Instant>,
    /// Alerts admitted this minute, per class (normal, high).
    minute_count: [u32; 2],
    groups: HashMap<String, Group>,
    suppressed: u64,
}

/// Suppresses repeats of the same alert key within a window, remembers at
/// most `max_keys` keys (the oldest are forgotten first) and caps the number
/// of alerts per minute, separately for each [`AlertClass`] and optionally
/// per group. Every operation is amortised O(1).
pub struct AlertLimiter {
    state: Mutex<LimiterState>,
    window: Duration,
    max_keys: usize,
    per_minute: u32,
}

impl AlertLimiter {
    pub fn new(window: Duration) -> Self {
        Self::with_limits(window, ALERT_KEYS, ALERTS_PER_MINUTE)
    }

    pub fn with_limits(window: Duration, max_keys: usize, per_minute: u32) -> Self {
        Self {
            state: Mutex::new(LimiterState {
                seen: HashMap::new(),
                order: VecDeque::new(),
                minute_start: None,
                minute_count: [0; 2],
                groups: HashMap::new(),
                suppressed: 0,
            }),
            window,
            max_keys: max_keys.max(1),
            per_minute,
        }
    }

    /// [`Self::admit`] for a normal alert without a group.
    pub fn allow(&self, key: &str, now: Instant) -> bool {
        self.admit(key, AlertClass::Normal, None, now).is_some()
    }

    /// Whether an alert with `key` may be raised now: not raised within the
    /// window, its class's budget for this minute not spent, and, with
    /// `group` = `(name, cap)`, fewer than `cap` alerts of that group this
    /// minute. Returns how many alerts of the group were held back by its cap
    /// since its last admitted one (0 without a group).
    pub fn admit(
        &self,
        key: &str,
        class: AlertClass,
        group: Option<(&str, u32)>,
        now: Instant,
    ) -> Option<u64> {
        let mut guard = self.state.lock();
        let st = &mut *guard;
        // Forget keys whose window has passed, oldest first.
        while let Some((k, t)) = st.order.front() {
            if now.saturating_duration_since(*t) < self.window {
                break;
            }
            if st.seen.get(k) == Some(t) {
                st.seen.remove(k);
            }
            st.order.pop_front();
        }
        if st.seen.contains_key(key) {
            // Still inside its window (expired keys were removed above).
            return None;
        }
        let minute = Duration::from_secs(60);
        let minute_over = st
            .minute_start
            .map_or(true, |t| now.saturating_duration_since(t) >= minute);
        if minute_over {
            st.minute_start = Some(now);
            st.minute_count = [0; 2];
        }
        let group = match group {
            Some((name, cap)) => {
                if !st.groups.contains_key(name) && st.groups.len() >= ALERT_GROUPS {
                    st.groups.retain(|_, g| {
                        now.saturating_duration_since(g.minute_start) < minute || g.held > 0
                    });
                    if st.groups.len() >= ALERT_GROUPS {
                        st.groups.clear();
                    }
                }
                let g = st.groups.entry(name.to_string()).or_insert(Group {
                    minute_start: now,
                    count: 0,
                    held: 0,
                });
                if now.saturating_duration_since(g.minute_start) >= minute {
                    g.minute_start = now;
                    g.count = 0;
                }
                if g.count >= cap {
                    g.held += 1;
                    st.suppressed += 1;
                    return None;
                }
                Some(g)
            }
            None => None,
        };
        let c = &mut st.minute_count[class as usize];
        if *c >= self.per_minute {
            if let Some(g) = group {
                g.held += 1;
            }
            st.suppressed += 1;
            return None;
        }
        *c += 1;
        let held = group.map_or(0, |g| {
            g.count += 1;
            std::mem::take(&mut g.held)
        });
        // Hard bound: forget the oldest keys (they may alert again early).
        while st.seen.len() >= self.max_keys {
            let Some((k, t)) = st.order.pop_front() else {
                break;
            };
            if st.seen.get(&k) == Some(&t) {
                st.seen.remove(&k);
            }
        }
        st.seen.insert(key.to_string(), now);
        st.order.push_back((key.to_string(), now));
        Some(held)
    }

    /// Number of remembered keys.
    pub fn len(&self) -> usize {
        self.state.lock().seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Alerts dropped because the per-minute budget was exhausted.
    pub fn suppressed(&self) -> u64 {
        self.state.lock().suppressed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> BeaconConfig {
        BeaconConfig {
            enabled: true,
            min_events: 6,
            max_jitter: 0.15,
            min_interval_s: 10.0,
            max_interval_s: 3600.0,
            ..BeaconConfig::default()
        }
    }

    #[test]
    fn detects_regular_beacon_once() {
        let d = BeaconDetector::new();
        let t0 = Instant::now();
        let jitter = [0.0, 1.5, -1.0, 0.5, -0.8, 1.2, 0.0, 0.3];
        let mut hits = Vec::new();
        for (i, j) in jitter.iter().enumerate() {
            let t = t0 + Duration::from_secs_f64(60.0 * i as f64 + j + 5.0);
            if let Some(h) = d.observe(&cfg(), Some(10100), "c2.example", t) {
                hits.push((i, h));
            }
            // A parallel connection in the same burst must not skew intervals.
            assert!(d
                .observe(
                    &cfg(),
                    Some(10100),
                    "c2.example",
                    t + Duration::from_millis(50)
                )
                .is_none());
        }
        assert_eq!(hits.len(), 1, "{hits:?}");
        let (i, h) = &hits[0];
        assert_eq!(*i, 5);
        assert!((h.mean_interval_s - 60.0).abs() < 2.0);
        assert!(h.jitter < 0.1);
    }

    #[test]
    fn ignores_irregular_traffic() {
        let d = BeaconDetector::new();
        let t0 = Instant::now();
        let offsets = [0u64, 12, 200, 215, 900, 1000, 1400, 2900, 3000];
        for o in offsets {
            assert!(d
                .observe(&cfg(), Some(1), "news.example", t0 + Duration::from_secs(o))
                .is_none());
        }
    }

    #[test]
    fn ignores_fast_polling_below_min_interval() {
        let d = BeaconDetector::new();
        let t0 = Instant::now();
        for i in 0..20 {
            assert!(d
                .observe(
                    &cfg(),
                    Some(1),
                    "poll.example",
                    t0 + Duration::from_secs(2 * i)
                )
                .is_none());
        }
    }

    #[test]
    fn limiter() {
        let l = AlertLimiter::new(Duration::from_secs(60));
        let t = Instant::now();
        assert!(l.allow("a", t));
        assert!(!l.allow("a", t + Duration::from_secs(30)));
        assert!(l.allow("b", t));
        assert!(l.allow("a", t + Duration::from_secs(61)));
    }

    #[test]
    fn limiter_is_bounded_and_forgets_oldest() {
        let l = AlertLimiter::with_limits(Duration::from_secs(3600), 100, u32::MAX);
        let t = Instant::now();
        for i in 0..10_000 {
            assert!(l.allow(&format!("k{i}"), t + Duration::from_millis(i)));
        }
        assert_eq!(l.len(), 100);
        // The newest keys are still suppressed, the oldest were forgotten.
        let later = t + Duration::from_secs(20);
        assert!(!l.allow("k9999", later));
        assert!(l.allow("k0", later));
        // Expired keys are dropped as time passes.
        assert!(l.allow("fresh", t + Duration::from_secs(7200)));
        assert_eq!(l.len(), 1);
    }

    #[test]
    fn limiter_global_budget() {
        let l = AlertLimiter::with_limits(Duration::from_secs(3600), 1000, 5);
        let t = Instant::now();
        let allowed = (0..50).filter(|i| l.allow(&format!("k{i}"), t)).count();
        assert_eq!(allowed, 5);
        assert_eq!(l.suppressed(), 45);
        // Suppressed keys were not remembered, so they can alert next minute.
        assert!(l.allow("k10", t + Duration::from_secs(61)));
    }

    #[test]
    fn limiter_classes_and_groups() {
        let l = AlertLimiter::with_limits(Duration::from_secs(3600), 1000, 5);
        let t = Instant::now();
        let normal = |k: &str, t| l.admit(k, AlertClass::Normal, None, t);
        let high = |k: &str, t| l.admit(k, AlertClass::High, None, t);
        let grouped = |k: &str, t| l.admit(k, AlertClass::Normal, Some(("g", 2)), t);
        // The group's cap: 2 a minute; the rest are held back and counted.
        assert_eq!(grouped("g1", t), Some(0));
        assert_eq!(grouped("g2", t), Some(0));
        for i in 3..10 {
            assert_eq!(grouped(&format!("g{i}"), t), None);
        }
        // Repeats of an admitted key are not "held back".
        assert_eq!(grouped("g1", t), None);
        // The normal budget (5) is not spent by what the group held back.
        for i in 0..3 {
            assert_eq!(normal(&format!("n{i}"), t), Some(0));
        }
        assert_eq!(normal("n3", t), None);
        // High severity has its own budget.
        for i in 0..5 {
            assert_eq!(high(&format!("h{i}"), t), Some(0));
        }
        assert_eq!(high("h5", t), None);
        // Next minute: the group's next alert reports the 7 held back.
        let t2 = t + Duration::from_secs(61);
        assert_eq!(grouped("g3", t2), Some(7));
        assert_eq!(grouped("g4", t2), Some(0));
        assert!(l.allow("n3", t2));
    }

    #[test]
    fn beacon_table_bounded_without_per_call_scans() {
        let d = BeaconDetector::with_capacity(10);
        let t0 = Instant::now();
        for i in 0..10 {
            d.observe(&cfg(), Some(1), &format!("t{i}"), t0);
        }
        assert_eq!(d.len(), 10);
        // Full of fresh series: new targets are ignored, nothing pruned.
        assert!(d.observe(&cfg(), Some(1), "new", t0).is_none());
        assert_eq!(d.len(), 10);
        // Past the horizon (2 × max interval) the next miss prunes.
        let later = t0 + Duration::from_secs(7201);
        d.observe(&cfg(), Some(1), "new", later);
        assert_eq!(d.len(), 1);
    }

    /// Replays one flow's byte schedule (`(second, bytes)` events) through
    /// the detector, sampling every `tick` seconds for `secs` seconds.
    /// Returns (sample time, hit) for each hit.
    fn replay(
        d: &FlowBurstDetector,
        c: &BeaconConfig,
        events: &[(f64, u64)],
        tick: f64,
        secs: f64,
    ) -> Vec<(f64, FlowBeaconHit)> {
        let t0 = Instant::now();
        let mut out = Vec::new();
        let mut t = tick;
        while t <= secs {
            let bytes = events.iter().filter(|(s, _)| *s <= t).map(|(_, b)| b).sum();
            let sample = FlowSample {
                id: 7,
                bytes,
                age: Duration::from_secs_f64(t),
            };
            for (_, h) in d.sample(c, [sample], t0 + Duration::from_secs_f64(t)) {
                out.push((t, h));
            }
            t += tick;
        }
        out
    }

    /// A heartbeat of `size` bytes every `every` s from `from` to `to`,
    /// with a small deterministic jitter (up to 3 % of the interval).
    fn heartbeat(from: f64, to: f64, every: f64, size: u64) -> Vec<(f64, u64)> {
        let wobble = [0.0, 0.8, -0.6, 0.3, -0.9, 0.5, -0.2, 0.7];
        let mut v = Vec::new();
        let mut t = from;
        let mut i = 0;
        while t < to {
            let at = t + wobble[i % wobble.len()] * every / 30.0;
            // Request, then the response a moment later.
            v.push((at, size / 2));
            v.push((at + 0.1, size - size / 2));
            t += every;
            i += 1;
        }
        v
    }

    #[test]
    fn flow_heartbeat_detected_once() {
        let d = FlowBurstDetector::new();
        let c = cfg();
        // An implant keeps one connection open and checks in every 30 s.
        let hits = replay(&d, &c, &heartbeat(5.0, 900.0, 30.0, 400), 1.0, 900.0);
        assert_eq!(hits.len(), 1, "{hits:?}");
        let (t, h) = &hits[0];
        // Watched from 60 s; the first burst after that opens the series.
        assert!(*t > 200.0 && *t < 300.0, "at {t}");
        assert!((h.mean_interval_s - 30.0).abs() < 1.0, "{h:?}");
        assert!(h.jitter < 0.1);
        assert_eq!(h.samples, 6);
        assert_eq!(h.burst_bytes, 400);
    }

    #[test]
    fn flow_irregular_browsing_ignored() {
        let d = FlowBurstDetector::new();
        let c = cfg();
        // A kept-alive HTTP/2 connection used by a person: irregular gaps
        // and sizes.
        let times = [
            70.0, 83.0, 140.0, 151.0, 260.0, 300.0, 305.0, 420.0, 431.0, 600.0, 620.0, 700.0, 880.0,
        ];
        let sizes = [
            900, 30_000, 2_000, 700, 12_000, 400, 5_000, 800, 45_000, 1_200, 600, 9_000, 300,
        ];
        let events: Vec<_> = times.iter().copied().zip(sizes).collect();
        assert!(replay(&d, &c, &events, 1.0, 1000.0).is_empty());
    }

    #[test]
    fn flow_keepalive_pings_and_bulk_periodic_ignored() {
        let c = cfg();
        // WebSocket / HTTP/2 pings: periodic but tiny.
        let d = FlowBurstDetector::new();
        assert!(replay(&d, &c, &heartbeat(0.0, 900.0, 30.0, 80), 1.0, 900.0).is_empty());
        // Periodic 1 MB syncs: above the burst size bound.
        let d = FlowBurstDetector::new();
        let mut c2 = c.clone();
        c2.flow_max_avg_bps = f64::MAX;
        assert!(replay(&d, &c2, &heartbeat(0.0, 900.0, 30.0, 1 << 20), 1.0, 900.0).is_empty());
    }

    #[test]
    fn flow_continuous_upload_ignored() {
        // 50 kB every second for 15 minutes: one endless burst.
        let events: Vec<_> = (1..900).map(|s| (s as f64, 50_000)).collect();
        let mut c = cfg();
        // Watched despite its rate, to exercise the burst logic itself.
        c.flow_max_avg_bps = f64::MAX;
        let d = FlowBurstDetector::new();
        assert!(replay(&d, &c, &events, 1.0, 900.0).is_empty());
        // With the default rate cap it is not even watched.
        let d = FlowBurstDetector::new();
        assert!(replay(&d, &cfg(), &events, 1.0, 900.0).is_empty());
        assert!(d.is_empty());
    }

    #[test]
    fn flow_long_idle_restarts_series() {
        let d = FlowBurstDetector::new();
        let c = cfg();
        // Four check-ins, silence for 4 h (beyond 3 × max_interval_s), then
        // regular check-ins again: only the new series counts.
        let mut events = heartbeat(60.0, 300.0, 60.0, 500);
        let resume = 300.0 + 4.0 * 3600.0;
        events.extend(heartbeat(resume, resume + 700.0, 60.0, 500));
        let hits = replay(&d, &c, &events, 1.0, resume + 700.0);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].0 > resume + 290.0, "series restarted: {hits:?}");
        assert_eq!(hits[0].1.samples, 6);
        assert!((hits[0].1.mean_interval_s - 60.0).abs() < 1.5);
    }

    #[test]
    fn flow_fast_ticks_resolve_short_intervals() {
        // The e2e setup: 2 s heartbeats sampled every 250 ms.
        let d = FlowBurstDetector::new();
        let mut c = cfg();
        c.min_interval_s = 1.0;
        c.max_jitter = 0.25;
        c.flow_min_age_s = 2.0;
        c.flow_idle_gap_s = 1.0;
        let hits = replay(&d, &c, &heartbeat(0.5, 40.0, 2.0, 300), 0.25, 40.0);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!((hits[0].1.mean_interval_s - 2.0).abs() < 0.3);
    }

    #[test]
    fn flow_tracking_is_bounded() {
        let d = FlowBurstDetector::new();
        let mut c = cfg();
        c.flow_max_tracked = 10;
        let t0 = Instant::now();
        let young = (0..50).map(|id| FlowSample {
            id,
            bytes: 100,
            age: Duration::from_secs(5),
        });
        d.sample(&c, young, t0);
        assert!(
            d.is_empty(),
            "flows younger than flow_min_age_s are not watched"
        );
        let old = |n: u64| {
            (0..n).map(|id| FlowSample {
                id,
                bytes: 100,
                age: Duration::from_secs(120),
            })
        };
        d.sample(&c, old(1000), t0);
        assert_eq!(d.len(), 10);
        // Ended flows (absent from a pass) are dropped, freeing slots.
        d.sample(&c, old(3), t0 + Duration::from_secs(1));
        assert_eq!(d.len(), 3);
        d.forget(0);
        assert_eq!(d.len(), 2);
        c.flow_enabled = false;
        d.sample(&c, old(3), t0 + Duration::from_secs(2));
        assert!(d.is_empty());
    }

    #[test]
    fn beacon_survives_huge_interval_config() {
        let d = BeaconDetector::with_capacity(1);
        let mut c = cfg();
        c.max_interval_s = f64::MAX;
        let t0 = Instant::now();
        d.observe(&c, None, "a", t0);
        // Would panic with Duration::from_secs_f64.
        assert!(d.observe(&c, None, "b", t0).is_none());
    }
}
