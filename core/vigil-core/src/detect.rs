//! Behavioural detectors.
//!
//! [`BeaconDetector`] flags apps that contact the same destination at a
//! near-constant interval — the signature of C2 check-ins and of telemetry
//! heartbeats. For each (uid, destination) it keeps the most recent
//! connection times and computes the coefficient of variation (stddev/mean)
//! of the intervals. Bursts (several connections within a second, as
//! browsers and HTTP clients open in parallel) count as one event.

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
        let intervals: Vec<f64> = s
            .times
            .iter()
            .zip(s.times.iter().skip(1))
            .map(|(a, b)| b.duration_since(*a).as_secs_f64())
            .collect();
        let n = intervals.len() as f64;
        let mean = intervals.iter().sum::<f64>() / n;
        if mean < cfg.min_interval_s || mean > cfg.max_interval_s {
            return None;
        }
        let var = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
        let jitter = var.sqrt() / mean;
        if jitter > cfg.max_jitter {
            return None;
        }
        s.last_alert = Some(now);
        Some(BeaconHit {
            mean_interval_s: mean,
            jitter,
            samples: s.times.len(),
        })
    }
}

/// Default bound on remembered alert keys.
pub const ALERT_KEYS: usize = 10_000;
/// Default budget of alerts per minute across all keys.
pub const ALERTS_PER_MINUTE: u32 = 120;

struct LimiterState {
    /// Key → time it last raised an alert.
    seen: HashMap<String, Instant>,
    /// Keys in the order they were (re-)admitted. An entry is stale when the
    /// map holds a newer time for its key.
    order: VecDeque<(String, Instant)>,
    minute_start: Option<Instant>,
    minute_count: u32,
    suppressed: u64,
}

/// Suppresses repeats of the same alert key within a window, remembers at
/// most `max_keys` keys (the oldest are forgotten first) and caps the total
/// number of alerts per minute. Every operation is amortised O(1).
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
                minute_count: 0,
                suppressed: 0,
            }),
            window,
            max_keys: max_keys.max(1),
            per_minute,
        }
    }

    pub fn allow(&self, key: &str, now: Instant) -> bool {
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
            return false;
        }
        let minute_over = st.minute_start.map_or(true, |t| {
            now.saturating_duration_since(t) >= Duration::from_secs(60)
        });
        if minute_over {
            st.minute_start = Some(now);
            st.minute_count = 0;
        }
        if st.minute_count >= self.per_minute {
            st.suppressed += 1;
            return false;
        }
        st.minute_count += 1;
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
        true
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
