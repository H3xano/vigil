//! Per-app firewall rules: blocking conditions (on Wi-Fi, on mobile data,
//! in the background, while the screen is off) and domain rules that apply
//! to one app only, plus the device state the conditions are evaluated
//! against. The rules are part of the configuration; the device state is
//! pushed separately by the host whenever it changes
//! ([`crate::Engine::set_device_state`]), because it changes far more often
//! (every app switch) than anything else in the configuration.

use serde::{Deserialize, Serialize};

/// Conditional blocking of one app (Linux UID). Blocking an app at all
/// times stays in `Config::blocked_uids`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct AppRule {
    pub uid: u32,
    /// Block while the device's underlying network is Wi-Fi.
    pub block_wifi: bool,
    /// Block while the underlying network is mobile data.
    pub block_cellular: bool,
    /// Block while the app is not in the foreground. Applies only when the
    /// host knows the foreground apps (`DeviceState::foreground_uids`).
    pub block_background: bool,
    /// Block while the screen is off.
    pub block_screen_off: bool,
}

impl AppRule {
    /// Whether the rule has any condition set (rules without one are inert).
    pub fn is_active(&self) -> bool {
        self.block_wifi || self.block_cellular || self.block_background || self.block_screen_off
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DomainAction {
    #[default]
    Allow,
    Block,
}

/// A domain rule for one app. Matches the domain and its subdomains, like
/// the global `allow_domains` / `deny_domains`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct AppDomainRule {
    pub uid: u32,
    pub domain: String,
    pub action: DomainAction,
}

/// Limits on the rule lists (a phone has at most a few thousand apps).
pub const MAX_APP_RULES: usize = 10_000;
pub const MAX_APP_DOMAIN_RULES: usize = 100_000;

pub(crate) fn validate(rules: &[AppRule], domain_rules: &[AppDomainRule]) -> Result<(), String> {
    if rules.len() > MAX_APP_RULES {
        return Err(format!("more than {MAX_APP_RULES} app_rules"));
    }
    if domain_rules.len() > MAX_APP_DOMAIN_RULES {
        return Err(format!("more than {MAX_APP_DOMAIN_RULES} app_domain_rules"));
    }
    if let Some((i, _)) = domain_rules
        .iter()
        .enumerate()
        .find(|(_, r)| normalize_domain(&r.domain).is_empty())
    {
        return Err(format!("app_domain_rules[{i}]: empty domain"));
    }
    Ok(())
}

/// Lowercase, without a trailing dot or a leading `*.`.
pub(crate) fn normalize_domain(d: &str) -> String {
    d.trim()
        .trim_start_matches("*.")
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

/// Type of the device's underlying (non-VPN) network.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum NetworkType {
    Wifi,
    Cellular,
    /// Ethernet, Bluetooth tethering, unknown: neither Wi-Fi nor mobile rules apply.
    #[default]
    Other,
    /// No network.
    None,
}

impl NetworkType {
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkType::Wifi => "wifi",
            NetworkType::Cellular => "cellular",
            NetworkType::Other => "other",
            NetworkType::None => "none",
        }
    }
}

/// What app conditions are evaluated against. The default (before the
/// host pushes a state) blocks nothing conditionally: network `other`,
/// screen on, foreground apps unknown.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct DeviceState {
    pub network: NetworkType,
    pub screen_on: bool,
    /// UIDs of the apps in the foreground. `null` (or absent) means unknown,
    /// e.g. without Android's usage access: `block_background` then never
    /// applies. An empty list means no app is in the foreground.
    pub foreground_uids: Option<Vec<u32>>,
}

impl Default for DeviceState {
    fn default() -> Self {
        Self {
            network: NetworkType::Other,
            screen_on: true,
            foreground_uids: None,
        }
    }
}

impl DeviceState {
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, ConfigError};

    #[test]
    fn app_rules_json_contract() {
        // "{" + APP_RULES_JSON + "}" from ConfigFactoryTest.kt, verbatim.
        let c = Config::from_json(
            r#"{"app_rules":[{"uid":10123,"block_wifi":true,"block_cellular":false,"block_background":true,"block_screen_off":false},{"uid":10124,"block_wifi":false,"block_cellular":true,"block_background":false,"block_screen_off":true}],"app_domain_rules":[{"uid":10123,"domain":"ads.example.com","action":"block"},{"uid":10124,"domain":"tracker.example","action":"allow"}]}"#,
        )
        .unwrap();

        assert_eq!(c.app_rules.len(), 2);
        assert_eq!(
            c.app_rules[0],
            AppRule {
                uid: 10123,
                block_wifi: true,
                block_background: true,
                ..Default::default()
            }
        );
        assert!(c.app_rules[1].block_cellular && c.app_rules[1].block_screen_off);
        assert_eq!(c.app_domain_rules[0].action, DomainAction::Block);
        assert_eq!(c.app_domain_rules[1].domain, "tracker.example");
        assert_eq!(c.app_domain_rules[1].action, DomainAction::Allow);
        let back = Config::from_json(&serde_json::to_string(&c).unwrap()).unwrap();
        assert_eq!(back, c);
        // DEVICE_STATE_JSON in ConfigFactoryTest.kt (nativeSetDeviceState), verbatim.
        let s = DeviceState::from_json(
            r#"{"network":"wifi","screen_on":false,"foreground_uids":[10123,10200]}"#,
        )
        .unwrap();
        assert_eq!(s.network, NetworkType::Wifi);
        assert!(!s.screen_on);
        assert_eq!(s.foreground_uids, Some(vec![10123, 10200]));
        // Without usage access the app omits foreground_uids (DEVICE_STATE_UNKNOWN_FG_JSON);
        // null works too.
        for json in [
            r#"{"network":"cellular","screen_on":true}"#,
            r#"{"network":"cellular","screen_on":true,"foreground_uids":null}"#,
        ] {
            let s = DeviceState::from_json(json).unwrap();
            assert_eq!(s.network, NetworkType::Cellular);
            assert_eq!(s.foreground_uids, None);
        }
        // The start config carries the state as `device_state`.
        let c = Config::from_json(
            r#"{"device_state":{"network":"none","screen_on":true,"foreground_uids":[]}}"#,
        )
        .unwrap();
        assert_eq!(c.device_state.unwrap().foreground_uids, Some(vec![]));
        let s = DeviceState::from_json("{}").unwrap();
        assert_eq!(s, DeviceState::default());
        assert!(DeviceState::from_json(r#"{"network":"satellite"}"#).is_err());
        // Old configurations (no per-app rules) still parse.
        let c = Config::from_json(r#"{"blocked_uids":[1]}"#).unwrap();
        assert!(c.app_rules.is_empty() && c.app_domain_rules.is_empty());
        assert!(c.device_state.is_none());
    }

    #[test]
    fn app_rules_validated() {
        let bad = |json: &str| matches!(Config::from_json(json), Err(ConfigError::Invalid(_)));
        assert!(bad(
            r#"{"app_domain_rules":[{"uid":1,"domain":" ","action":"block"}]}"#
        ));
        assert!(bad(
            r#"{"app_domain_rules":[{"uid":1,"domain":"*.","action":"allow"}]}"#
        ));
        assert!(Config::from_json(
            r#"{"app_domain_rules":[{"uid":1,"domain":"x.example","action":"deny"}]}"#
        )
        .is_err());
        assert!(Config::from_json(r#"{"app_rules":[{"uid":-1}]}"#).is_err());
        assert_eq!(normalize_domain(" *.Ads.Example.COM. "), "ads.example.com");
        assert!(!AppRule::default().is_active());
    }
}
