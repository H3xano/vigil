//! Packet capture configuration: an in-memory ring of the raw IP packets
//! seen on the TUN (exported as PCAPng on request) and an optional
//! PCAP-over-IP server for live viewing in Wireshark.

use super::upstream::Cidr;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Default ring size (16 MiB).
pub const DEFAULT_BUFFER_BYTES: u64 = 16 * 1024 * 1024;
/// Largest accepted ring (128 MiB).
pub const MAX_BUFFER_BYTES: u64 = 128 * 1024 * 1024;
/// Smallest accepted ring (64 KiB).
pub const MIN_BUFFER_BYTES: u64 = 64 * 1024;
pub const DEFAULT_SNAPLEN: u32 = 65_535;
/// Smallest accepted snap length: enough for the IP and transport headers.
pub const MIN_SNAPLEN: u32 = 64;
/// Default PCAP-over-IP port (PCAPdroid's default is 57012 too).
pub const DEFAULT_STREAM_PORT: u16 = 57_012;
/// Largest client allowlist.
pub const MAX_STREAM_ALLOW: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct CaptureConfig {
    /// Record packets (and serve `stream`). Off by default.
    pub enabled: bool,
    /// Memory for recorded packets (packet data plus 16 bytes per packet);
    /// the oldest packets are overwritten when it is full.
    pub buffer_bytes: u64,
    /// Bytes kept of each packet (the rest is cut; the original length is
    /// recorded).
    pub snaplen: u32,
    pub stream: StreamConfig,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            buffer_bytes: DEFAULT_BUFFER_BYTES,
            snaplen: DEFAULT_SNAPLEN,
            stream: StreamConfig::default(),
        }
    }
}

/// PCAP-over-IP: a TCP server that sends a classic PCAP header and then
/// every captured packet to each connected client (Wireshark's
/// "PCAP-over-IP" remote interface, or `nc host port | wireshark -k -i -`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct StreamConfig {
    /// Needs `capture.enabled` too.
    pub enabled: bool,
    pub port: u16,
    /// Local address to listen on, chosen by the host (the Wi-Fi address,
    /// `0.0.0.0` or `127.0.0.1`). Empty: not listening (e.g. no Wi-Fi).
    pub bind: String,
    /// Client addresses or CIDR ranges allowed to connect; empty allows any
    /// client that can reach the port.
    pub allow: Vec<String>,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: DEFAULT_STREAM_PORT,
            bind: String::new(),
            allow: Vec::new(),
        }
    }
}

impl StreamConfig {
    /// The listen address, or None when `bind` is empty.
    pub fn bind_addr(&self) -> Option<IpAddr> {
        self.bind.trim().parse().ok()
    }

    pub fn allowlist(&self) -> Vec<Cidr> {
        self.allow.iter().filter_map(|a| Cidr::parse(a)).collect()
    }
}

impl CaptureConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !(MIN_BUFFER_BYTES..=MAX_BUFFER_BYTES).contains(&self.buffer_bytes) {
            return Err(format!(
                "capture.buffer_bytes {} outside {MIN_BUFFER_BYTES}..={MAX_BUFFER_BYTES}",
                self.buffer_bytes
            ));
        }
        if !(MIN_SNAPLEN..=DEFAULT_SNAPLEN).contains(&self.snaplen) {
            return Err(format!(
                "capture.snaplen {} outside {MIN_SNAPLEN}..={DEFAULT_SNAPLEN}",
                self.snaplen
            ));
        }
        let s = &self.stream;
        if s.enabled && s.port == 0 {
            return Err("capture.stream.port must be positive".into());
        }
        let bind = s.bind.trim();
        if !bind.is_empty() && bind.parse::<IpAddr>().is_err() {
            return Err(format!("capture.stream.bind {bind:?} is not an IP address"));
        }
        if s.allow.len() > MAX_STREAM_ALLOW {
            return Err(format!(
                "capture.stream.allow: more than {MAX_STREAM_ALLOW} entries"
            ));
        }
        if let Some(a) = s.allow.iter().find(|a| Cidr::parse(a).is_none()) {
            return Err(format!(
                "capture.stream.allow: {a:?} is not an address or CIDR"
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{Config, ConfigError};

    #[test]
    fn capture_json_contract() {
        let c = Config::default();
        assert!(!c.capture.enabled);
        assert_eq!(c.capture.buffer_bytes, 16 * 1024 * 1024);
        assert_eq!(c.capture.snaplen, 65535);
        assert!(!c.capture.stream.enabled);
        assert_eq!(c.capture.stream.port, 57012);
        // CAPTURE_JSON and CAPTURE_OFF_JSON in ConfigFactoryTest.kt, verbatim.
        let c = Config::from_json(
            r#"{"capture":{"enabled":true,"buffer_bytes":33554432,"snaplen":65535,"stream":{"enabled":true,"port":57012,"bind":"192.168.1.23","allow":["192.168.1.10","10.0.0.0/8"]}}}"#,
        )
        .unwrap();
        assert!(c.capture.enabled);
        assert_eq!(c.capture.buffer_bytes, 32 * 1024 * 1024);
        let s = &c.capture.stream;
        assert!(s.enabled);
        assert_eq!(s.bind_addr(), Some("192.168.1.23".parse().unwrap()));
        assert_eq!(s.allowlist().len(), 2);
        assert!(s.allowlist()[1].contains("10.1.2.3".parse().unwrap()));
        let back = Config::from_json(&serde_json::to_string(&c).unwrap()).unwrap();
        assert_eq!(back, c);
        let c = Config::from_json(
            r#"{"capture":{"enabled":false,"buffer_bytes":16777216,"snaplen":65535,"stream":{"enabled":false,"port":57012,"bind":"","allow":[]}}}"#,
        )
        .unwrap();
        assert_eq!(c.capture, Default::default());
        assert_eq!(c.capture.stream.bind_addr(), None);
    }

    #[test]
    fn capture_validation() {
        let rejected = |j: &str| {
            matches!(
                Config::from_json(&format!(r#"{{"capture":{j}}}"#)),
                Err(ConfigError::Invalid(_))
            )
        };
        assert!(rejected(r#"{"buffer_bytes":0}"#));
        assert!(rejected(r#"{"buffer_bytes":134217729}"#));
        assert!(!rejected(r#"{"buffer_bytes":134217728}"#));
        assert!(rejected(r#"{"snaplen":10}"#));
        assert!(rejected(r#"{"snaplen":65536}"#));
        assert!(rejected(r#"{"stream":{"enabled":true,"port":0}}"#));
        assert!(!rejected(r#"{"stream":{"enabled":false,"port":0}}"#));
        assert!(rejected(r#"{"stream":{"bind":"wlan0"}}"#));
        assert!(!rejected(r#"{"stream":{"bind":"::"}}"#));
        assert!(rejected(r#"{"stream":{"allow":["nope"]}}"#));
        assert!(rejected(r#"{"stream":{"allow":["10.0.0.0/33"]}}"#));
        assert!(Config::from_json(r#"{"capture":{"stream":{"port":70000}}}"#).is_err());
    }
}
