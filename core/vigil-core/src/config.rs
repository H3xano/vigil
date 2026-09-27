//! Engine configuration, supplied as JSON by the host (Android app or CLI).

use crate::proto::dns::SinkholeMode;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Config {
    /// Addresses of the virtual resolver advertised to the OS via
    /// `VpnService.Builder.addDnsServer`. Queries to these are answered by
    /// vigil itself.
    pub virtual_dns: Vec<IpAddr>,
    /// Real resolvers used to answer queries sent to the virtual resolver.
    pub upstream_dns: Vec<SocketAddr>,
    pub sinkhole: SinkholeMode,
    /// TTL of synthesised sinkhole answers.
    pub sinkhole_ttl: u32,
    /// Block DNS-over-TLS (port 853) and well-known DNS-over-HTTPS endpoints
    /// so that apps fall back to plain DNS, which vigil can inspect.
    pub block_encrypted_dns: bool,
    /// Linux UIDs whose traffic is blocked entirely.
    pub blocked_uids: Vec<u32>,
    /// User allowlist; overrides feeds and the custom denylist.
    pub allow_domains: Vec<String>,
    /// User denylist.
    pub deny_domains: Vec<String>,
    pub beacon: BeaconConfig,
    pub mtu: u16,
    pub tcp_connect_timeout_ms: u64,
    pub udp_idle_timeout_s: u64,
    /// Period of `stats` events.
    pub stats_interval_ms: u64,
    /// Worker threads for the async runtime.
    pub worker_threads: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct BeaconConfig {
    pub enabled: bool,
    /// Number of connections needed before a series is judged.
    pub min_events: usize,
    /// Maximum coefficient of variation (stddev / mean) of the intervals.
    pub max_jitter: f64,
    pub min_interval_s: f64,
    pub max_interval_s: f64,
}

impl Default for BeaconConfig {
    fn default() -> Self {
        Self { enabled: true, min_events: 6, max_jitter: 0.15, min_interval_s: 10.0, max_interval_s: 3600.0 }
    }
}

pub const DEFAULT_VIRTUAL_DNS_V4: Ipv4Addr = Ipv4Addr::new(10, 111, 222, 2);

impl Default for Config {
    fn default() -> Self {
        Self {
            virtual_dns: vec![
                IpAddr::V4(DEFAULT_VIRTUAL_DNS_V4),
                "fd76:6967:696c::2".parse().expect("valid literal"),
            ],
            upstream_dns: vec!["1.1.1.1:53".parse().unwrap(), "9.9.9.9:53".parse().unwrap()],
            sinkhole: SinkholeMode::NullIp,
            sinkhole_ttl: 60,
            block_encrypted_dns: false,
            blocked_uids: Vec::new(),
            allow_domains: Vec::new(),
            deny_domains: Vec::new(),
            beacon: BeaconConfig::default(),
            mtu: 1500,
            tcp_connect_timeout_ms: 15_000,
            udp_idle_timeout_s: 60,
            stats_interval_ms: 2_000,
            worker_threads: 2,
        }
    }
}

impl Config {
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    pub fn is_virtual_dns(&self, ip: IpAddr) -> bool {
        self.virtual_dns.contains(&ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_json_uses_defaults() {
        let c = Config::from_json(r#"{"sinkhole":"nxdomain","blocked_uids":[10123],"beacon":{"min_events":4}}"#).unwrap();
        assert_eq!(c.sinkhole, SinkholeMode::Nxdomain);
        assert_eq!(c.blocked_uids, vec![10123]);
        assert_eq!(c.beacon.min_events, 4);
        assert!(c.beacon.enabled);
        assert_eq!(c.mtu, 1500);
        let back = Config::from_json(&serde_json::to_string(&c).unwrap()).unwrap();
        assert_eq!(back, c);
    }
}
