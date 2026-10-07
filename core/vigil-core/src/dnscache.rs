//! IP → hostname attribution learned from DNS answers.
//!
//! When an app resolves `graph.example.com` and then connects to one of the
//! returned addresses, the connection can be labelled with the name the app
//! *asked for* even when the protocol carries no SNI. The mapping is a hint:
//! CDN addresses are shared by many names, so it is never used for blocking.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

const MIN_TTL: Duration = Duration::from_secs(300);
const MAX_TTL: Duration = Duration::from_secs(6 * 3600);

/// Minimum time between two expiry sweeps of a full cache. In between, a
/// full cache drops half its entries instead, so a stream of new addresses
/// cannot make every insert scan the whole map under the lock.
const SWEEP_EVERY: Duration = Duration::from_secs(60);
/// Names kept per address (CDN addresses serve many), newest first.
const NAMES_PER_IP: usize = 4;

struct Inner {
    /// Names per address, newest first, each with its expiry.
    map: HashMap<IpAddr, Vec<(String, Instant)>>,
    last_sweep: Option<Instant>,
}

pub struct DnsCache {
    inner: Mutex<Inner>,
    capacity: usize,
}

impl DnsCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                map: HashMap::with_capacity(1024),
                last_sweep: None,
            }),
            capacity,
        }
    }

    pub fn insert(&self, ip: IpAddr, name: &str, ttl_s: u32, now: Instant) {
        if ip.is_unspecified() {
            return;
        }
        let ttl = Duration::from_secs(ttl_s as u64).clamp(MIN_TTL, MAX_TTL);
        let mut inner = self.inner.lock();
        let inner = &mut *inner;
        let m = &mut inner.map;
        if m.len() >= self.capacity && !m.contains_key(&ip) {
            let due = inner
                .last_sweep
                .map_or(true, |t| now.saturating_duration_since(t) >= SWEEP_EVERY);
            if due {
                inner.last_sweep = Some(now);
                m.retain(|_, names| names.iter().any(|(_, exp)| *exp > now));
            }
            if m.len() >= self.capacity {
                // Still full (of live entries, or no sweep was due): drop an
                // arbitrary half. That makes room for capacity/2 inserts, so
                // the scan costs O(1) per insert amortised.
                let mut keep = false;
                m.retain(|_, _| {
                    keep = !keep;
                    keep
                });
            }
        }
        let names = m.entry(ip).or_default();
        names.retain(|(n, exp)| *exp > now && n != name);
        names.truncate(NAMES_PER_IP - 1);
        names.insert(0, (name.to_string(), now + ttl));
    }

    /// The name most recently resolved to `ip` (a label for flows).
    pub fn lookup(&self, ip: IpAddr, now: Instant) -> Option<String> {
        let inner = self.inner.lock();
        inner
            .map
            .get(&ip)?
            .iter()
            .find(|(_, exp)| *exp > now)
            .map(|(n, _)| n.clone())
    }

    /// Every live name recently resolved to `ip`, newest first.
    pub fn names(&self, ip: IpAddr, now: Instant) -> Vec<String> {
        let inner = self.inner.lock();
        inner.map.get(&ip).map_or_else(Vec::new, |names| {
            names
                .iter()
                .filter(|(_, exp)| *exp > now)
                .map(|(n, _)| n.clone())
                .collect()
        })
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_and_capacity() {
        let c = DnsCache::new(4);
        let t0 = Instant::now();
        let ip = |n: u8| IpAddr::from([10, 0, 0, n]);
        c.insert(ip(1), "a.example", 10, t0);
        assert_eq!(c.lookup(ip(1), t0).as_deref(), Some("a.example"));
        // TTL is clamped up to five minutes.
        assert!(c.lookup(ip(1), t0 + Duration::from_secs(299)).is_some());
        assert!(c.lookup(ip(1), t0 + Duration::from_secs(301)).is_none());
        for n in 2..=10 {
            c.insert(ip(n), "b.example", 60, t0);
        }
        assert!(c.len() <= 4);
        assert_eq!(c.lookup(ip(10), t0).as_deref(), Some("b.example"));
        c.insert(IpAddr::from([0, 0, 0, 0]), "sink", 60, t0);
        assert!(c.lookup(IpAddr::from([0, 0, 0, 0]), t0).is_none());
    }

    #[test]
    fn expiry_sweeps_are_rate_limited() {
        let c = DnsCache::new(100);
        let t0 = Instant::now();
        let ip = |n: u32| IpAddr::from((0x0a00_0000 + n).to_be_bytes());
        for n in 0..100 {
            c.insert(ip(n), "old.example", 0, t0);
        }
        // All expired: the first insert into the full cache sweeps them.
        let t1 = t0 + MIN_TTL + Duration::from_secs(1);
        c.insert(ip(1000), "new.example", 3600, t1);
        assert_eq!(c.len(), 1);
        for n in 0..99 {
            c.insert(ip(2000 + n), "live.example", 3600, t1);
        }
        assert_eq!(c.len(), 100);
        // Full of live entries: halved, with no sweep due for a minute.
        c.insert(ip(5000), "x.example", 3600, t1);
        assert_eq!(c.len(), 51);
        assert!(c.inner.lock().last_sweep == Some(t1));
        // Each overflowing insert costs one halving, so the table stays
        // bounded and most inserts do no scan at all.
        for n in 0..1000 {
            c.insert(
                ip(10_000 + n),
                "y.example",
                3600,
                t1 + Duration::from_secs(1),
            );
            assert!(c.len() <= 100);
        }
        assert_eq!(c.inner.lock().last_sweep, Some(t1));
        assert_eq!(c.lookup(ip(10_999), t1).as_deref(), Some("y.example"));
    }

    #[test]
    fn shared_addresses_keep_several_names() {
        let c = DnsCache::new(16);
        let t0 = Instant::now();
        let ip = IpAddr::from([104, 16, 0, 1]);
        for n in [
            "a.example",
            "b.example",
            "c.example",
            "a.example",
            "d.example",
            "e.example",
        ] {
            c.insert(ip, n, 600, t0);
        }
        // Newest first, re-resolving moves a name to the front, at most four.
        assert_eq!(c.lookup(ip, t0).as_deref(), Some("e.example"));
        assert_eq!(
            c.names(ip, t0),
            ["e.example", "d.example", "a.example", "c.example"]
        );
        // Expired names are not returned.
        c.insert(ip, "short.example", 0, t0);
        let later = t0 + MIN_TTL + Duration::from_secs(1);
        assert_eq!(c.names(ip, later), ["e.example", "d.example", "a.example"]);
        assert_eq!(c.lookup(ip, later).as_deref(), Some("e.example"));
        assert!(c.names(IpAddr::from([10, 0, 0, 1]), t0).is_empty());
    }
}
