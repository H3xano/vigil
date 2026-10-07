//! Upstream path configuration: how vigil's own relay sockets reach the
//! internet (directly, through a WireGuard peer or through a SOCKS5 proxy).
//! Inspection is the same in every mode; only the egress path changes.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamMode {
    /// Protected sockets on the underlying network (the default).
    #[default]
    Direct,
    Wireguard,
    Socks5,
}

impl UpstreamMode {
    pub fn as_str(self) -> &'static str {
        match self {
            UpstreamMode::Direct => "direct",
            UpstreamMode::Wireguard => "wireguard",
            UpstreamMode::Socks5 => "socks5",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct UpstreamConfig {
    pub mode: UpstreamMode,
    /// When the tunnel or proxy is unavailable, fail connections (the app
    /// sees a reset, DNS gets SERVFAIL) instead of falling back to direct.
    pub fail_closed: bool,
    pub wireguard: Option<WireGuardConfig>,
    pub socks5: Option<Socks5Config>,
    /// Opaque identifier of the underlying network, set by the host. When
    /// only this changes, the WireGuard socket is re-created and the
    /// endpoint re-resolved (roaming) without rebuilding the tunnel.
    pub network_id: String,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            mode: UpstreamMode::Direct,
            fail_closed: true,
            wireguard: None,
            socks5: None,
            network_id: String::new(),
        }
    }
}

impl UpstreamConfig {
    /// Whether `other` selects the same path (everything but `network_id`).
    pub fn same_path(&self, other: &UpstreamConfig) -> bool {
        self.mode == other.mode
            && self.fail_closed == other.fail_closed
            && self.wireguard == other.wireguard
            && self.socks5 == other.socks5
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct WireGuardConfig {
    /// Base64 X25519 private key ([Interface] PrivateKey).
    pub private_key: String,
    /// Base64 public key of the peer ([Peer] PublicKey).
    pub peer_public_key: String,
    /// Optional base64 pre-shared key ([Peer] PresharedKey).
    pub preshared_key: Option<String>,
    /// `host:port` or `[v6]:port` of the peer ([Peer] Endpoint). A host name
    /// is resolved when the tunnel starts and again after network changes.
    pub endpoint: String,
    /// Tunnel addresses in CIDR form ([Interface] Address): at most one IPv4
    /// and one IPv6 address.
    pub addresses: Vec<String>,
    /// Destinations routed through the peer ([Peer] AllowedIPs). Empty means
    /// everything. Other destinations go direct, as with wg-quick.
    pub allowed_ips: Vec<String>,
    /// Tunnel MTU ([Interface] MTU).
    pub mtu: u16,
    /// Seconds between keepalives ([Peer] PersistentKeepalive); 0 is off.
    pub persistent_keepalive: u16,
}

impl Default for WireGuardConfig {
    fn default() -> Self {
        Self {
            private_key: String::new(),
            peer_public_key: String::new(),
            preshared_key: None,
            endpoint: String::new(),
            addresses: Vec::new(),
            allowed_ips: Vec::new(),
            mtu: 1420,
            persistent_keepalive: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Socks5Udp {
    /// UDP ASSOCIATE per UDP flow; if the proxy refuses it, UDP is blocked.
    #[default]
    Auto,
    /// Never relay UDP (DNS still works, over TCP through the proxy).
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct Socks5Config {
    /// `host:port` or `[v6]:port` of the proxy, e.g. `127.0.0.1:9050`.
    pub server: String,
    /// RFC 1929 credentials; both empty means no authentication.
    pub username: String,
    pub password: String,
    /// Connect by the sniffed TLS SNI or HTTP Host name instead of the IP
    /// address (the proxy resolves it; useful for Tor). The upstream connect
    /// then happens after the app's first bytes, not before the handshake.
    pub send_domain: bool,
    pub udp: Socks5Udp,
}

/// A parsed `address/prefix`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    /// Parses `addr/prefix` (or a bare address as a host route).
    pub fn parse(s: &str) -> Option<Cidr> {
        let s = s.trim();
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = a.trim().parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            Some(p) => p.trim().parse::<u8>().ok().filter(|&p| p <= max)?,
            None => max,
        };
        Some(Cidr { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - self.prefix as u32).unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX.checked_shl(128 - self.prefix as u32).unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// Decodes a base64 WireGuard key (32 bytes).
pub fn decode_key(s: &str) -> Option<[u8; 32]> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .ok()?;
    bytes.try_into().ok()
}

/// A WireGuard key pair (base64 private, base64 public) from 32 random
/// bytes (clamped as X25519 requires).
pub fn keypair_from(random: [u8; 32]) -> (String, String) {
    let secret = boringtun::x25519::StaticSecret::from(random);
    let public = boringtun::x25519::PublicKey::from(&secret);
    let b64 = |k: &[u8; 32]| base64::engine::general_purpose::STANDARD.encode(k);
    (b64(&secret.to_bytes()), b64(public.as_bytes()))
}

/// Splits `host:port` / `[v6]:port` / `v4:port`. The host is returned
/// without brackets.
pub fn split_host_port(s: &str) -> Option<(String, u16)> {
    let s = s.trim();
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, p) = rest.split_once(']')?;
        (h, p.strip_prefix(':')?)
    } else {
        let (h, p) = s.rsplit_once(':')?;
        if h.contains(':') {
            return None; // bare IPv6 without brackets is ambiguous
        }
        (h, p)
    };
    let port: u16 = port.parse().ok().filter(|&p| p > 0)?;
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    let is_ip = host.parse::<IpAddr>().is_ok();
    let valid_name = host.split('.').all(|l| {
        !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    if !is_ip && !valid_name {
        return None;
    }
    Some((host.to_string(), port))
}

/// The socket address of `host:port` if the host is an IP literal.
pub fn literal_socket_addr(s: &str) -> Option<SocketAddr> {
    let (h, p) = split_host_port(s)?;
    Some(SocketAddr::new(h.parse().ok()?, p))
}

impl UpstreamConfig {
    pub fn validate(&self) -> Result<(), String> {
        match self.mode {
            UpstreamMode::Direct => Ok(()),
            UpstreamMode::Socks5 => self
                .socks5
                .as_ref()
                .ok_or_else(|| "upstream.mode socks5 needs upstream.socks5".to_string())?
                .validate(),
            UpstreamMode::Wireguard => self
                .wireguard
                .as_ref()
                .ok_or_else(|| "upstream.mode wireguard needs upstream.wireguard".to_string())?
                .validate(),
        }
    }
}

impl Socks5Config {
    pub fn validate(&self) -> Result<(), String> {
        if split_host_port(&self.server).is_none() {
            return Err(format!(
                "upstream.socks5.server {:?} is not host:port",
                self.server
            ));
        }
        // RFC 1929: one length byte each.
        if self.username.len() > 255 || self.password.len() > 255 {
            return Err("upstream.socks5 username/password longer than 255 bytes".into());
        }
        if self.username.is_empty() && !self.password.is_empty() {
            return Err("upstream.socks5.password set without a username".into());
        }
        Ok(())
    }
}

/// Smallest accepted WireGuard tunnel MTU.
pub const MIN_WG_MTU: u16 = 576;
/// Largest accepted WireGuard tunnel MTU: a full packet plus WireGuard's 32
/// bytes must fit one UDP datagram over IPv4 (65507 bytes of payload).
pub const MAX_WG_MTU: u16 = 65_400;

/// Neither unspecified, multicast nor the IPv4 broadcast address.
fn is_unicast(ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    !ip.is_unspecified() && !ip.is_multicast() && ip != IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
}

impl WireGuardConfig {
    pub fn validate(&self) -> Result<(), String> {
        if decode_key(&self.private_key).is_none() {
            return Err("upstream.wireguard.private_key is not a base64 32-byte key".into());
        }
        if decode_key(&self.peer_public_key).is_none() {
            return Err("upstream.wireguard.peer_public_key is not a base64 32-byte key".into());
        }
        if let Some(psk) = &self.preshared_key {
            if !psk.trim().is_empty() && decode_key(psk).is_none() {
                return Err("upstream.wireguard.preshared_key is not a base64 32-byte key".into());
            }
        }
        if split_host_port(&self.endpoint).is_none() {
            return Err(format!(
                "upstream.wireguard.endpoint {:?} is not host:port",
                self.endpoint
            ));
        }
        let addrs = self.tunnel_addresses()?;
        if addrs.is_empty() {
            return Err("upstream.wireguard.addresses is empty".into());
        }
        if addrs.iter().filter(|c| c.addr.is_ipv4()).count() > 1
            || addrs.iter().filter(|c| c.addr.is_ipv6()).count() > 1
        {
            return Err(
                "upstream.wireguard.addresses: at most one IPv4 and one IPv6 address".into(),
            );
        }
        // The tunnel's own addresses must be unicast (the user-space stack
        // refuses anything else at start).
        if let Some(c) = addrs.iter().find(|c| !is_unicast(c.addr)) {
            return Err(format!(
                "upstream.wireguard.addresses: {} is not a unicast address",
                c.addr
            ));
        }
        self.allowed()?;
        if !(MIN_WG_MTU..=MAX_WG_MTU).contains(&self.mtu) {
            return Err(format!(
                "upstream.wireguard.mtu {} outside {MIN_WG_MTU}..={MAX_WG_MTU}",
                self.mtu
            ));
        }
        Ok(())
    }

    pub fn tunnel_addresses(&self) -> Result<Vec<Cidr>, String> {
        self.addresses
            .iter()
            .map(|a| {
                Cidr::parse(a)
                    .ok_or_else(|| format!("upstream.wireguard.addresses: bad CIDR {a:?}"))
            })
            .collect()
    }

    /// AllowedIPs; empty means everything.
    pub fn allowed(&self) -> Result<Vec<Cidr>, String> {
        self.allowed_ips
            .iter()
            .map(|a| {
                Cidr::parse(a)
                    .ok_or_else(|| format!("upstream.wireguard.allowed_ips: bad CIDR {a:?}"))
            })
            .collect()
    }

    pub fn preshared(&self) -> Option<[u8; 32]> {
        self.preshared_key
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .and_then(decode_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "YAnz4CFg6SqZkWpBHQ3K3G3oN6bT9x5cyTqQyzQ8bVE=";

    fn wg() -> WireGuardConfig {
        WireGuardConfig {
            private_key: KEY.into(),
            peer_public_key: KEY.into(),
            endpoint: "vpn.example.com:51820".into(),
            addresses: vec!["10.64.0.2/32".into(), "fd00::2/128".into()],
            ..Default::default()
        }
    }

    #[test]
    fn keys_and_endpoints() {
        assert!(decode_key(KEY).is_some());
        assert!(decode_key("AAAA").is_none());
        assert!(decode_key("not base64!").is_none());
        assert_eq!(
            split_host_port("[2001:db8::1]:51820"),
            Some(("2001:db8::1".into(), 51820))
        );
        assert_eq!(split_host_port("1.2.3.4:1"), Some(("1.2.3.4".into(), 1)));
        assert_eq!(
            split_host_port("a-b.example:9050"),
            Some(("a-b.example".into(), 9050))
        );
        for bad in [
            "",
            "host",
            "host:0",
            "host:70000",
            "2001:db8::1:53",
            ":53",
            "a b:1",
            "[::1]53",
        ] {
            assert_eq!(split_host_port(bad), None, "{bad}");
        }
        assert_eq!(
            literal_socket_addr("127.0.0.1:9050"),
            Some("127.0.0.1:9050".parse().unwrap())
        );
        assert_eq!(literal_socket_addr("localhost:9050"), None);
    }

    #[test]
    fn cidrs() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains("10.1.2.3".parse().unwrap()));
        assert!(!c.contains("11.0.0.1".parse().unwrap()));
        assert!(!c.contains("::1".parse().unwrap()));
        assert!(Cidr::parse("0.0.0.0/0")
            .unwrap()
            .contains("1.2.3.4".parse().unwrap()));
        assert!(Cidr::parse("::/0")
            .unwrap()
            .contains("2001:db8::1".parse().unwrap()));
        assert_eq!(Cidr::parse("fd00::2").unwrap().prefix, 128);
        assert!(Cidr::parse("10.0.0.1/33").is_none());
        assert!(Cidr::parse("x/8").is_none());
    }

    #[test]
    fn wireguard_validation() {
        wg().validate().unwrap();
        let bad = |f: fn(&mut WireGuardConfig)| {
            let mut c = wg();
            f(&mut c);
            c.validate().is_err()
        };
        assert!(bad(|c| c.private_key = "short".into()));
        assert!(bad(|c| c.peer_public_key = String::new()));
        assert!(bad(|c| c.preshared_key = Some("AAAA".into())));
        assert!(bad(|c| c.endpoint = "nohost".into()));
        assert!(bad(|c| c.addresses.clear()));
        assert!(bad(
            |c| c.addresses = vec!["10.0.0.1/32".into(), "10.0.0.2/32".into()]
        ));
        assert!(bad(|c| c.addresses = vec!["garbage".into()]));
        assert!(bad(|c| c.allowed_ips = vec!["0.0.0.0/99".into()]));
        assert!(bad(|c| c.mtu = 100));
        assert!(bad(|c| c.mtu = 65_535));
        assert!(bad(|c| c.mtu = MAX_WG_MTU + 1));
        assert!(!bad(|c| c.mtu = MAX_WG_MTU));
        assert!(!bad(|c| c.mtu = MIN_WG_MTU));
        for a in [
            "0.0.0.0/32",
            "224.0.0.1/32",
            "255.255.255.255/32",
            "::/128",
            "ff02::1/128",
        ] {
            let mut c = wg();
            c.addresses = vec![a.into()];
            let e = c.validate().unwrap_err();
            assert!(e.contains("not a unicast address"), "{a}: {e}");
        }
        assert!(!bad(
            |c| c.addresses = vec!["10.9.0.2/24".into(), "fd00::2/64".into()]
        ));
        let mut ok = wg();
        ok.preshared_key = Some(KEY.into());
        ok.allowed_ips = vec!["0.0.0.0/0".into(), "::/0".into()];
        ok.validate().unwrap();
        assert!(ok.preshared().is_some());
        ok.preshared_key = Some(String::new());
        ok.validate().unwrap();
        assert!(ok.preshared().is_none());
    }

    #[test]
    fn socks5_validation() {
        let ok = Socks5Config {
            server: "127.0.0.1:9050".into(),
            ..Default::default()
        };
        ok.validate().unwrap();
        let mut c = ok.clone();
        c.server = "127.0.0.1".into();
        assert!(c.validate().is_err());
        let mut c = ok.clone();
        c.password = "x".into();
        assert!(c.validate().is_err());
        let mut c = ok.clone();
        c.username = "u".repeat(256);
        assert!(c.validate().is_err());
        let mut c = ok;
        c.username = "user".into();
        c.password = "pass".into();
        c.validate().unwrap();
    }

    #[test]
    fn mode_needs_its_section() {
        let mut u = UpstreamConfig {
            mode: UpstreamMode::Socks5,
            ..Default::default()
        };
        assert!(u.validate().is_err());
        u.mode = UpstreamMode::Wireguard;
        assert!(u.validate().is_err());
        u.wireguard = Some(wg());
        u.validate().unwrap();
        u.mode = UpstreamMode::Direct;
        u.validate().unwrap();
        let mut v = u.clone();
        v.network_id = "wifi-2".into();
        assert!(u.same_path(&v));
        v.fail_closed = false;
        assert!(!u.same_path(&v));
    }
}
