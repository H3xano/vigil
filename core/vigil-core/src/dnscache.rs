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

pub struct DnsCache {
    map: Mutex<HashMap<IpAddr, (String, Instant)>>,
    capacity: usize,
}

impl DnsCache {
    pub fn new(capacity: usize) -> Self {
        Self { map: Mutex::new(HashMap::with_capacity(1024)), capacity }
    }

    pub fn insert(&self, ip: IpAddr, name: &str, ttl_s: u32, now: Instant) {
        if ip.is_unspecified() {
            return;
        }
        let ttl = Duration::from_secs(ttl_s as u64).clamp(MIN_TTL, MAX_TTL);
        let mut m = self.map.lock();
        if m.len() >= self.capacity && !m.contains_key(&ip) {
            m.retain(|_, (_, exp)| *exp > now);
            if m.len() >= self.capacity {
                // Still full of live entries: drop an arbitrary half.
                let mut keep = false;
                m.retain(|_, _| {
                    keep = !keep;
                    keep
                });
            }
        }
        m.insert(ip, (name.to_string(), now + ttl));
    }

    pub fn lookup(&self, ip: IpAddr, now: Instant) -> Option<String> {
        let m = self.map.lock();
        m.get(&ip).filter(|(_, exp)| *exp > now).map(|(n, _)| n.clone())
    }

    pub fn len(&self) -> usize {
        self.map.lock().len()
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
}
