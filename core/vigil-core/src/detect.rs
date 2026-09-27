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

pub struct BeaconDetector {
    series: Mutex<HashMap<(Option<u32>, String), Series>>,
}

impl Default for BeaconDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BeaconDetector {
    pub fn new() -> Self {
        Self { series: Mutex::new(HashMap::new()) }
    }

    pub fn observe(&self, cfg: &BeaconConfig, uid: Option<u32>, target: &str, now: Instant) -> Option<BeaconHit> {
        if !cfg.enabled {
            return None;
        }
        let mut map = self.series.lock();
        if map.len() >= MAX_SERIES && !map.contains_key(&(uid, target.to_string())) {
            let horizon = Duration::from_secs_f64(cfg.max_interval_s * 2.0);
            map.retain(|_, s| s.times.back().is_some_and(|t| now.duration_since(*t) < horizon));
            if map.len() >= MAX_SERIES {
                return None;
            }
        }
        let s = map
            .entry((uid, target.to_string()))
            .or_insert_with(|| Series { times: VecDeque::with_capacity(WINDOW), last_alert: None });
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
        if s.last_alert.is_some_and(|t| now.duration_since(t) < REALERT_AFTER) {
            return None;
        }
        let intervals: Vec<f64> =
            s.times.iter().zip(s.times.iter().skip(1)).map(|(a, b)| b.duration_since(*a).as_secs_f64()).collect();
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
        Some(BeaconHit { mean_interval_s: mean, jitter, samples: s.times.len() })
    }
}

/// Suppresses repeats of the same alert key within a window.
pub struct AlertLimiter {
    seen: Mutex<HashMap<String, Instant>>,
    window: Duration,
}

impl AlertLimiter {
    pub fn new(window: Duration) -> Self {
        Self { seen: Mutex::new(HashMap::new()), window }
    }

    pub fn allow(&self, key: &str, now: Instant) -> bool {
        let mut m = self.seen.lock();
        if m.len() > 10_000 {
            let w = self.window;
            m.retain(|_, t| now.duration_since(*t) < w);
        }
        match m.get(key) {
            Some(t) if now.duration_since(*t) < self.window => false,
            _ => {
                m.insert(key.to_string(), now);
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> BeaconConfig {
        BeaconConfig { enabled: true, min_events: 6, max_jitter: 0.15, min_interval_s: 10.0, max_interval_s: 3600.0 }
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
            assert!(d.observe(&cfg(), Some(10100), "c2.example", t + Duration::from_millis(50)).is_none());
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
            assert!(d.observe(&cfg(), Some(1), "news.example", t0 + Duration::from_secs(o)).is_none());
        }
    }

    #[test]
    fn ignores_fast_polling_below_min_interval() {
        let d = BeaconDetector::new();
        let t0 = Instant::now();
        for i in 0..20 {
            assert!(d.observe(&cfg(), Some(1), "poll.example", t0 + Duration::from_secs(2 * i)).is_none());
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
}
