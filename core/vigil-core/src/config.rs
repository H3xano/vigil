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
    /// Reset connections whose JA4 fingerprint is on a JA4 feed. Off by
    /// default: benign clients can share a fingerprint with malware (JA4
    /// identifies the TLS library, not the program), so matches only alert.
    pub block_ja4_matches: bool,
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
    /// Forwarding of the virtual resolver's queries over DNS-over-TLS or
    /// DNS-over-HTTPS instead of plain DNS to `upstream_dns`.
    pub encrypted_dns: EncryptedDnsConfig,
    /// How relayed traffic leaves the device (direct, WireGuard, SOCKS5).
    pub upstream: UpstreamConfig,
}

/// Transport used to forward the virtual resolver's queries.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum EncryptedDnsMode {
    /// Plain DNS to `upstream_dns` (UDP, TCP when truncated).
    #[default]
    Off,
    /// DNS over TLS (RFC 7858).
    Dot,
    /// DNS over HTTPS (RFC 8484), HTTP/1.1 POST.
    Doh,
}

impl EncryptedDnsMode {
    pub fn as_str(self) -> &'static str {
        match self {
            EncryptedDnsMode::Off => "off",
            EncryptedDnsMode::Dot => "dot",
            EncryptedDnsMode::Doh => "doh",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct EncryptedDnsConfig {
    pub mode: EncryptedDnsMode,
    /// Tried in order (a failing server is skipped for a while).
    pub servers: Vec<EncryptedDnsServer>,
    /// When every encrypted server fails, answer from `upstream_dns` in
    /// cleartext instead of SERVFAIL. Also allows servers without `addrs`
    /// (their name is then looked up in cleartext).
    pub fallback_plain: bool,
    /// Extra trusted root certificates (PEM), added to the built-in Mozilla
    /// roots. For private resolvers and tests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_root_ca_pem: Option<String>,
}

/// One encrypted resolver. DoH: `url` (`https://host[:port]/path`). DoT:
/// `host` (the TLS name, or an IP literal) and optional `port` (853).
/// `addrs` are the bootstrap addresses to connect to; they are required
/// unless `host` is an IP literal or `fallback_plain` is set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct EncryptedDnsServer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    pub addrs: Vec<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

/// A validated [`EncryptedDnsServer`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EncryptedTarget {
    /// TLS server name (SNI and certificate check) and HTTP `Host`.
    pub host: String,
    pub port: u16,
    /// DoH request target (path and query); empty for DoT.
    pub path: String,
    /// Bootstrap addresses; empty means "look `host` up in cleartext".
    pub addrs: Vec<IpAddr>,
}

impl EncryptedTarget {
    /// The `Host` header value (with the port when not 443, IPv6 bracketed).
    pub fn authority(&self) -> String {
        let h = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == 443 {
            h
        } else {
            format!("{h}:{}", self.port)
        }
    }
}

/// Limits on the `encrypted_dns` object.
pub const MAX_ENCRYPTED_SERVERS: usize = 8;
pub const MAX_SERVER_ADDRS: usize = 8;

impl EncryptedDnsServer {
    /// Validates this server for `mode` and returns the connection target.
    pub fn target(
        &self,
        mode: EncryptedDnsMode,
        fallback_plain: bool,
    ) -> Result<EncryptedTarget, String> {
        let (host, port, path) = match mode {
            EncryptedDnsMode::Doh => {
                let url = self.url.as_deref().ok_or("DoH server needs a url")?;
                let (host, port, path) = parse_https_url(url)?;
                if let Some(h) = &self.host {
                    if !h.trim_end_matches('.').eq_ignore_ascii_case(&host) {
                        return Err(format!("host {h:?} does not match the url"));
                    }
                }
                if self.port.is_some_and(|p| p != port) {
                    return Err("port does not match the url".into());
                }
                (host, port, path)
            }
            EncryptedDnsMode::Dot | EncryptedDnsMode::Off => {
                if self.url.is_some() {
                    return Err("DoT server takes host/port, not a url".into());
                }
                let host = self.host.as_deref().ok_or("DoT server needs a host")?;
                (check_host(host)?, self.port.unwrap_or(853), String::new())
            }
        };
        if port == 0 {
            return Err("port must be positive".into());
        }
        let mut addrs = self.addrs.clone();
        if addrs.len() > MAX_SERVER_ADDRS {
            return Err(format!("more than {MAX_SERVER_ADDRS} addrs"));
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            if !addrs.contains(&ip) {
                addrs.insert(0, ip);
            }
        }
        if let Some(a) = addrs
            .iter()
            .find(|a| a.is_unspecified() || a.is_multicast())
        {
            return Err(format!("unusable address {a}"));
        }
        if addrs.is_empty() && !fallback_plain {
            return Err(format!(
                "{host}: bootstrap addrs are required (or enable fallback_plain)"
            ));
        }
        Ok(EncryptedTarget {
            host,
            port,
            path,
            addrs,
        })
    }
}

impl EncryptedDnsConfig {
    /// The validated servers (empty when off).
    pub fn targets(&self) -> Result<Vec<EncryptedTarget>, String> {
        if self.mode == EncryptedDnsMode::Off {
            return Ok(Vec::new());
        }
        self.servers
            .iter()
            .enumerate()
            .map(|(i, s)| {
                s.target(self.mode, self.fallback_plain)
                    .map_err(|e| format!("encrypted_dns.servers[{i}]: {e}"))
            })
            .collect()
    }

    fn validate(&self) -> Result<(), String> {
        if self.servers.len() > MAX_ENCRYPTED_SERVERS {
            return Err(format!(
                "encrypted_dns: more than {MAX_ENCRYPTED_SERVERS} servers"
            ));
        }
        if self.mode != EncryptedDnsMode::Off && self.servers.is_empty() {
            return Err("encrypted_dns: no servers".into());
        }
        self.targets()?;
        if let Some(pem) = &self.extra_root_ca_pem {
            parse_root_pem(pem).map_err(|e| format!("encrypted_dns.extra_root_ca_pem: {e}"))?;
        }
        Ok(())
    }
}

/// Parses PEM certificates into trust anchors (at least one).
pub(crate) fn parse_root_pem(pem: &str) -> Result<rustls::RootCertStore, String> {
    use rustls::pki_types::{pem::PemObject, CertificateDer};
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
        let cert = cert.map_err(|e| format!("bad PEM: {e}"))?;
        roots
            .add(cert)
            .map_err(|e| format!("bad certificate: {e}"))?;
    }
    if roots.is_empty() {
        return Err("no certificate found".into());
    }
    Ok(roots)
}

/// A DNS hostname (LDH labels, at least two) or an IP literal, lowercased.
fn check_host(raw: &str) -> Result<String, String> {
    let h = raw.trim_end_matches('.').to_ascii_lowercase();
    if h.parse::<IpAddr>().is_ok() {
        return Ok(h);
    }
    let ok = h.len() <= 253
        && h.contains('.')
        && h.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if ok {
        Ok(h)
    } else {
        Err(format!("invalid host name {raw:?}"))
    }
}

/// Splits `https://host[:port][/path][?query]` into host, port and request
/// target. An empty path becomes `/dns-query`.
pub fn parse_https_url(url: &str) -> Result<(String, u16, String), String> {
    let bad = |why: &str| Err(format!("invalid DoH url {url:?}: {why}"));
    if url.len() > 512 || url.bytes().any(|b| !b.is_ascii_graphic()) {
        return bad("must be printable ASCII without spaces");
    }
    let Some(rest) = url
        .get(..8)
        .filter(|p| p.eq_ignore_ascii_case("https://"))
        .map(|_| &url[8..])
    else {
        return bad("must start with https://");
    };
    if rest.contains('#') {
        return bad("fragments are not allowed");
    }
    let split = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, target) = rest.split_at(split);
    if authority.contains('@') {
        return bad("credentials are not allowed");
    }
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let Some((h, after)) = v6.split_once(']') else {
            return bad("unclosed [");
        };
        if h.parse::<Ipv6Addr>().is_err() {
            return bad("invalid IPv6 literal");
        }
        match after {
            "" => (h, None),
            a => match a.strip_prefix(':') {
                Some(p) => (h, Some(p)),
                None => return bad("junk after ]"),
            },
        }
    } else {
        match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    let port = match port {
        None => 443,
        Some(p) => match p.parse::<u16>() {
            Ok(p) if p > 0 => p,
            _ => return bad("invalid port"),
        },
    };
    let Ok(host) = check_host(host) else {
        return bad("invalid host");
    };
    let target = match target {
        "" => "/dns-query".to_string(),
        t if t.starts_with('?') => format!("/{t}"),
        t => t.to_string(),
    };
    Ok((host, port, target))
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
            block_ja4_matches: false,
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
            encrypted_dns: EncryptedDnsConfig::default(),
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
        self.encrypted_dns
            .validate()
            .map_err(ConfigError::Invalid)?;
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
            "nat64_prefixes":["64:ff9b:1::/96"],
            "encrypted_dns":{"mode":"dot","servers":[{"host":"dns.quad9.net",
                "addrs":["9.9.9.9","149.112.112.112"],"port":853}],"fallback_plain":false}}"#;
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
        // Encrypted DNS together with a tunnel (ConfigFactoryTest's
        // COMBINED_EDNS plus the WireGuard section): both are kept.
        let c = Config::from_json(
            r#"{"encrypted_dns":{"mode":"dot","servers":[{"host":"dns.quad9.net","addrs":["9.9.9.9","149.112.112.112","2620:fe::fe","2620:fe::9"]}],"fallback_plain":false},
                "upstream_dns":["10.64.0.1:53","[fd00::1]:53"],
                "upstream":{"mode":"wireguard","fail_closed":true,"wireguard":{"private_key":"YAnz4CFg6SqZkWpBHQ3K3G3oN6bT9x5cyTqQyzQ8bVE=","peer_public_key":"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=","endpoint":"vpn.example.com:51820","addresses":["10.64.0.2/32","fd00::2/128"],"allowed_ips":["0.0.0.0/0","::/0"],"mtu":1280,"persistent_keepalive":25},"network_id":"101"}}"#,
        )
        .unwrap();
        assert_eq!(c.encrypted_dns.mode, EncryptedDnsMode::Dot);
        assert_eq!(c.upstream.mode, UpstreamMode::Wireguard);
        assert_eq!(c.upstream_dns.len(), 2);
    }

    #[test]
    fn encrypted_dns_config_validated() {
        let ok = |j: &str| {
            Config::from_json(&format!(r#"{{"encrypted_dns":{j}}}"#))
                .unwrap_or_else(|e| panic!("{j}: {e}"))
        };
        let bad = |j: &str| rejected(&format!(r#"{{"encrypted_dns":{j}}}"#));
        assert_eq!(Config::default().encrypted_dns.mode, EncryptedDnsMode::Off);
        ok(r#"{"mode":"off"}"#);
        let c = ok(
            r#"{"mode":"doh","servers":[{"url":"https://dns.quad9.net/dns-query",
            "addrs":["9.9.9.9","2620:fe::fe"]}]}"#,
        );
        let t = c.encrypted_dns.targets().unwrap();
        assert_eq!(t[0].host, "dns.quad9.net");
        assert_eq!((t[0].port, t[0].path.as_str()), (443, "/dns-query"));
        assert_eq!(t[0].authority(), "dns.quad9.net");
        let c = ok(
            r#"{"mode":"dot","servers":[{"host":"Dns.Quad9.Net.","addrs":["9.9.9.9"]},
            {"host":"1.1.1.1"}]}"#,
        );
        let t = c.encrypted_dns.targets().unwrap();
        assert_eq!((t[0].host.as_str(), t[0].port), ("dns.quad9.net", 853));
        assert_eq!(t[1].addrs, vec!["1.1.1.1".parse::<IpAddr>().unwrap()]);
        // No addresses: only allowed with fallback_plain.
        ok(r#"{"mode":"doh","fallback_plain":true,"servers":[{"url":"https://dns.google"}]}"#);
        assert!(bad(
            r#"{"mode":"doh","servers":[{"url":"https://dns.google"}]}"#
        ));
        assert!(bad(r#"{"mode":"dot","servers":[]}"#));
        assert!(Config::from_json(r#"{"encrypted_dns":{"mode":"tls"}}"#).is_err());
        assert!(Config::from_json(
            r#"{"encrypted_dns":{"mode":"dot","servers":[{"host":"x.example","addrs":["nope"]}]}}"#
        )
        .is_err());
        for s in [
            r#"{"url":"http://dns.example/dns-query","addrs":["192.0.2.1"]}"#,
            r#"{"url":"https://user@dns.example/","addrs":["192.0.2.1"]}"#,
            r#"{"url":"https://dns.example:0/","addrs":["192.0.2.1"]}"#,
            r#"{"url":"https://dns.example:99999/","addrs":["192.0.2.1"]}"#,
            r#"{"url":"https://dns example/","addrs":["192.0.2.1"]}"#,
            r#"{"url":"https://dns.example/#x","addrs":["192.0.2.1"]}"#,
            r#"{"url":"https://-bad.example/","addrs":["192.0.2.1"]}"#,
            r#"{"url":"https://[::1/","addrs":["192.0.2.1"]}"#,
            r#"{"url":"https://dns.example/","host":"other.example","addrs":["192.0.2.1"]}"#,
            r#"{"url":"https://dns.example/","addrs":["0.0.0.0"]}"#,
            r#"{"host":"dns.example","addrs":["192.0.2.1"]}"#,
        ] {
            assert!(
                bad(&format!(r#"{{"mode":"doh","servers":[{s}]}}"#)),
                "doh {s}"
            );
        }
        for s in [
            r#"{"url":"https://dns.example/","addrs":["192.0.2.1"]}"#,
            r#"{"host":"dns..example","addrs":["192.0.2.1"]}"#,
            r#"{"host":"localhost","addrs":["192.0.2.1"]}"#,
            r#"{"host":"dns.example","port":0,"addrs":["192.0.2.1"]}"#,
            r#"{"host":"dns.example","addrs":["224.0.0.1"]}"#,
            r#"{"addrs":["192.0.2.1"]}"#,
        ] {
            assert!(
                bad(&format!(r#"{{"mode":"dot","servers":[{s}]}}"#)),
                "dot {s}"
            );
        }
        let many = [r#"{"host":"1.1.1.1"}"#; MAX_ENCRYPTED_SERVERS + 1].join(",");
        assert!(bad(&format!(r#"{{"mode":"dot","servers":[{many}]}}"#)));
        // IPv6 literals and ports in URLs.
        let (h, p, path) = parse_https_url("https://[2620:fe::fe]:8443?x=1").unwrap();
        assert_eq!(
            (h.as_str(), p, path.as_str()),
            ("2620:fe::fe", 8443, "/?x=1")
        );
        let t = EncryptedTarget {
            host: h,
            port: p,
            path,
            addrs: vec![],
        };
        assert_eq!(t.authority(), "[2620:fe::fe]:8443");
        // Extra roots must be real certificates.
        assert!(bad(
            r#"{"mode":"dot","servers":[{"host":"1.1.1.1"}],"extra_root_ca_pem":"junk"}"#
        ));
        let ca = include_str!("../testdata/edns/ca.pem");
        let c = Config {
            encrypted_dns: EncryptedDnsConfig {
                mode: EncryptedDnsMode::Dot,
                servers: vec![EncryptedDnsServer {
                    host: Some("1.1.1.1".into()),
                    ..Default::default()
                }],
                extra_root_ca_pem: Some(ca.into()),
                ..Default::default()
            },
            ..Default::default()
        };
        c.validate().unwrap();
        let back = Config::from_json(&serde_json::to_string(&c).unwrap()).unwrap();
        assert_eq!(back, c);
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
