//! Engine configuration, supplied as JSON by the host (Android app or CLI).

pub mod upstream;

use crate::proto::dns::SinkholeMode;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
pub use upstream::{UpstreamConfig, UpstreamMode};

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
    /// NAT64 prefixes of the current network (CIDR strings such as
    /// `64:ff9b::/96`). Addresses inside them embed an IPv4 address, which
    /// is what IP feeds are matched against. The well-known prefix
    /// `64:ff9b::/96` is always included; only /96 prefixes are supported.
    pub nat64_prefixes: Vec<String>,
    /// Maximum concurrent UDP flows (NAT entries). When full, the flow idle
    /// for longest is evicted.
    pub max_udp_flows: usize,
    /// Maximum concurrent TCP connections (admitted or relaying). SYNs
    /// beyond it are answered with a RST.
    pub max_tcp_flows: usize,
    /// Maximum TCP connections held at the SYN gate (UID lookup and upstream
    /// connect). SYNs beyond it are answered with a RST.
    pub max_pending_connects: usize,
    /// Maximum DNS queries being answered concurrently. Queries beyond it
    /// get SERVFAIL.
    pub max_dns_inflight: usize,
    /// How relayed traffic leaves the device (direct, WireGuard, SOCKS5).
    pub upstream: UpstreamConfig,
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
        Self {
            enabled: true,
            min_events: 6,
            max_jitter: 0.15,
            min_interval_s: 10.0,
            max_interval_s: 3600.0,
        }
    }
}

pub const DEFAULT_VIRTUAL_DNS_V4: Ipv4Addr = Ipv4Addr::new(10, 111, 222, 2);

/// Well-known NAT64 prefix (RFC 6052), always treated as NAT64.
pub const NAT64_WELL_KNOWN: Ipv6Addr = Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0);

/// Accepted MTU range (576 is the IPv4 minimum reassembly size).
pub const MTU_RANGE: std::ops::RangeInclusive<u16> = 576..=65535;

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
            nat64_prefixes: Vec::new(),
            max_udp_flows: 2048,
            max_tcp_flows: 4096,
            max_pending_connects: 256,
            max_dns_inflight: 256,
            upstream: UpstreamConfig::default(),
        }
    }
}

/// Why a configuration was rejected.
#[derive(Debug)]
pub enum ConfigError {
    Json(serde_json::Error),
    Invalid(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Json(e) => write!(f, "{e}"),
            ConfigError::Invalid(m) => write!(f, "invalid config: {m}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Parses and validates a configuration.
    pub fn from_json(s: &str) -> Result<Self, ConfigError> {
        let c: Config = serde_json::from_str(s).map_err(ConfigError::Json)?;
        c.validate()?;
        Ok(c)
    }

    /// Rejects values that would make the engine misbehave or panic.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let bad = |m: String| Err(ConfigError::Invalid(m));
        let b = &self.beacon;
        for (name, v) in [
            ("beacon.max_jitter", b.max_jitter),
            ("beacon.min_interval_s", b.min_interval_s),
            ("beacon.max_interval_s", b.max_interval_s),
        ] {
            if !v.is_finite() || v < 0.0 {
                return bad(format!(
                    "{name} must be a finite, non-negative number (got {v})"
                ));
            }
        }
        if b.min_interval_s > b.max_interval_s {
            return bad(format!(
                "beacon.min_interval_s ({}) exceeds beacon.max_interval_s ({})",
                b.min_interval_s, b.max_interval_s
            ));
        }
        if !MTU_RANGE.contains(&self.mtu) {
            return bad(format!("mtu {} outside {MTU_RANGE:?}", self.mtu));
        }
        if self.tcp_connect_timeout_ms == 0 {
            return bad("tcp_connect_timeout_ms must be positive".into());
        }
        if self.udp_idle_timeout_s == 0 {
            return bad("udp_idle_timeout_s must be positive".into());
        }
        if self.upstream_dns.is_empty() {
            return bad("upstream_dns is empty".into());
        }
        for (name, v) in [
            ("max_udp_flows", self.max_udp_flows),
            ("max_tcp_flows", self.max_tcp_flows),
            ("max_pending_connects", self.max_pending_connects),
            ("max_dns_inflight", self.max_dns_inflight),
        ] {
            if v == 0 {
                return bad(format!("{name} must be positive"));
            }
        }
        self.upstream.validate().map_err(ConfigError::Invalid)?;
        Ok(())
    }

    pub fn is_virtual_dns(&self, ip: IpAddr) -> bool {
        self.virtual_dns.contains(&ip)
    }

    /// The NAT64 /96 prefixes in effect: the well-known prefix plus every
    /// valid /96 entry of `nat64_prefixes`. Other entries are logged and
    /// ignored instead of failing the configuration, because they come from
    /// the network, not from the user.
    pub fn nat64_prefixes(&self) -> Vec<Ipv6Addr> {
        let mut out = vec![NAT64_WELL_KNOWN];
        for p in &self.nat64_prefixes {
            match parse_nat64_prefix(p) {
                Some(a) if !out.contains(&a) => out.push(a),
                Some(_) => {}
                None => log::warn!("ignoring NAT64 prefix {p:?}: only IPv6 /96 is supported"),
            }
        }
        out
    }
}

/// Parses `addr/96` into the prefix address (low 32 bits cleared).
fn parse_nat64_prefix(s: &str) -> Option<Ipv6Addr> {
    let (addr, len) = s.trim().split_once('/')?;
    if len.trim() != "96" {
        return None;
    }
    let a: Ipv6Addr = addr.trim().parse().ok()?;
    Some(Ipv6Addr::from(u128::from(a) & !0xffff_ffffu128))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_json_uses_defaults() {
        let c = Config::from_json(
            r#"{"sinkhole":"nxdomain","blocked_uids":[10123],"beacon":{"min_events":4}}"#,
        )
        .unwrap();
        assert_eq!(c.sinkhole, SinkholeMode::Nxdomain);
        assert_eq!(c.blocked_uids, vec![10123]);
        assert_eq!(c.beacon.min_events, 4);
        assert!(c.beacon.enabled);
        assert_eq!(c.mtu, 1500);
        assert_eq!(c.max_udp_flows, 2048);
        assert!(c.nat64_prefixes.is_empty());
        let back = Config::from_json(&serde_json::to_string(&c).unwrap()).unwrap();
        assert_eq!(back, c);
    }

    fn rejected(json: &str) -> bool {
        matches!(Config::from_json(json), Err(ConfigError::Invalid(_)))
    }

    #[test]
    fn validation_rejects_bad_values() {
        assert!(rejected(r#"{"beacon":{"max_jitter":-0.1}}"#));
        assert!(rejected(r#"{"beacon":{"min_interval_s":-1}}"#));
        assert!(rejected(
            r#"{"beacon":{"min_interval_s":100,"max_interval_s":10}}"#
        ));
        assert!(rejected(r#"{"mtu":575}"#));
        assert!(rejected(r#"{"mtu":0}"#));
        assert!(rejected(r#"{"tcp_connect_timeout_ms":0}"#));
        assert!(rejected(r#"{"udp_idle_timeout_s":0}"#));
        assert!(rejected(r#"{"upstream_dns":[]}"#));
        assert!(rejected(r#"{"max_udp_flows":0}"#));
        assert!(rejected(r#"{"max_tcp_flows":0}"#));
        assert!(rejected(r#"{"max_pending_connects":0}"#));
        assert!(rejected(r#"{"max_dns_inflight":0}"#));
        assert!(rejected(r#"{"upstream":{"mode":"socks5"}}"#));
        assert!(rejected(
            r#"{"upstream":{"mode":"socks5","socks5":{"server":"nope"}}}"#
        ));
        assert!(rejected(
            r#"{"upstream":{"mode":"wireguard","wireguard":{"private_key":"AAAA"}}}"#
        ));
        assert!(Config::from_json(r#"{"upstream":{"mode":"tor"}}"#).is_err());
        assert!(matches!(
            Config::from_json("{not json"),
            Err(ConfigError::Json(_))
        ));
        // Out-of-range numbers never reach validation from JSON.
        assert!(Config::from_json(r#"{"beacon":{"max_interval_s":1e999}}"#).is_err());
        // Non-finite values can still come from code.
        let mut c = Config::default();
        c.beacon.max_interval_s = f64::INFINITY;
        assert!(c.validate().is_err());
        c.beacon.max_interval_s = f64::NAN;
        assert!(c.validate().is_err());
    }

    #[test]
    fn validation_accepts_what_the_app_sends() {
        // Shape of ConfigFactory.kt output (EngineConfig.kt, encodeDefaults).
        let app = r#"{"virtual_dns":["10.111.222.2","fd76:6967:696c::2"],
            "upstream_dns":["192.168.1.1:53","[2001:db8::1]:53"],"sinkhole":"null_ip",
            "sinkhole_ttl":60,"block_encrypted_dns":false,"blocked_uids":[10123],
            "allow_domains":[],"deny_domains":["x.example"],
            "beacon":{"enabled":true,"min_events":5,"max_jitter":0.25,
                      "min_interval_s":10.0,"max_interval_s":3600.0},
            "mtu":1500,"tcp_connect_timeout_ms":15000,"udp_idle_timeout_s":60,
            "stats_interval_ms":2000,"worker_threads":2,
            "nat64_prefixes":["64:ff9b:1::/96"]}"#;
        let c = Config::from_json(app).unwrap();
        assert_eq!(c.max_tcp_flows, 4096);
        assert!(Config::from_json(r#"{"mtu":576}"#).is_ok());
        assert!(Config::from_json(r#"{"mtu":65535}"#).is_ok());
        assert!(Config::from_json(r#"{"beacon":{"min_interval_s":0,"max_interval_s":0}}"#).is_ok());
        Config::default().validate().unwrap();
        assert_eq!(Config::default().upstream.mode, UpstreamMode::Direct);
        assert!(Config::default().upstream.fail_closed);
    }

    #[test]
    fn upstream_json_contract() {
        // Shape of ConfigFactory.kt output for the two proxy modes.
        let c = Config::from_json(
            r#"{"upstream":{"mode":"socks5","fail_closed":true,"network_id":"100",
                "socks5":{"server":"127.0.0.1:9050","username":"","password":"",
                          "send_domain":true,"udp":"block"}}}"#,
        )
        .unwrap();
        let s = c.upstream.socks5.as_ref().unwrap();
        assert!(s.send_domain);
        assert_eq!(s.udp, upstream::Socks5Udp::Block);
        let key = "YAnz4CFg6SqZkWpBHQ3K3G3oN6bT9x5cyTqQyzQ8bVE=";
        let c = Config::from_json(&format!(
            r#"{{"upstream":{{"mode":"wireguard","fail_closed":false,
                "wireguard":{{"private_key":"{key}","peer_public_key":"{key}",
                "preshared_key":null,"endpoint":"[2001:db8::1]:51820",
                "addresses":["10.2.0.2/32","fd00::2/128"],"allowed_ips":["0.0.0.0/0","::/0"],
                "mtu":1280,"persistent_keepalive":25}}}}}}"#
        ))
        .unwrap();
        assert_eq!(c.upstream.mode, UpstreamMode::Wireguard);
        assert!(!c.upstream.fail_closed);
        assert_eq!(c.upstream.wireguard.as_ref().unwrap().mtu, 1280);
        let back = Config::from_json(&serde_json::to_string(&c).unwrap()).unwrap();
        assert_eq!(back, c);
        // Verbatim from ConfigFactoryTest.kt (nulls omitted, as the app sends).
        for app in [
            r#"{"upstream":{"mode":"direct","fail_closed":true,"network_id":"100"}}"#,
            r#"{"upstream":{"mode":"wireguard","fail_closed":true,"wireguard":{"private_key":"YAnz4CFg6SqZkWpBHQ3K3G3oN6bT9x5cyTqQyzQ8bVE=","peer_public_key":"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=","endpoint":"vpn.example.com:51820","addresses":["10.64.0.2/32","fd00::2/128"],"allowed_ips":["0.0.0.0/0","::/0"],"mtu":1280,"persistent_keepalive":25},"network_id":"101"}}"#,
            r#"{"upstream":{"mode":"socks5","fail_closed":false,"socks5":{"server":"[::1]:9050","username":"u","password":"secret","send_domain":true,"udp":"block"},"network_id":""}}"#,
        ] {
            Config::from_json(app).unwrap();
        }
    }

    #[test]
    fn nat64_prefixes_parsed() {
        let c = Config {
            nat64_prefixes: vec![
                "64:ff9b:1::/96".into(),
                "64:ff9b::/96".into(),
                "2001:db8:64::/64".into(),
                "garbage".into(),
                " 2001:db8:1:2:3:4:5:6/96 ".into(),
            ],
            ..Default::default()
        };
        let want: Vec<Ipv6Addr> = vec![
            NAT64_WELL_KNOWN,
            "64:ff9b:1::".parse().unwrap(),
            "2001:db8:1:2:3:4::".parse().unwrap(),
        ];
        assert_eq!(c.nat64_prefixes(), want);
        assert_eq!(Config::default().nat64_prefixes(), vec![NAT64_WELL_KNOWN]);
    }
}
