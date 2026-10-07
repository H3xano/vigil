//! Blocking policy: per-app blocks and conditions, per-app domain rules,
//! threat/tracker feeds, user allow/deny lists and encrypted-DNS handling.
//!
//! Precedence, first match wins:
//!
//! 1. The app is blocked: always (`blocked_uids`, reason `app`) or by one of
//!    its conditions in the current device state (`app rule: wifi`,
//!    `app rule: cellular`, `app rule: screen off`, `app rule: background`).
//!    Applies to every connection and lookup of the app, before any name is
//!    known, so per-app allow rules do not punch holes into it.
//! 2. A per-app allow rule for the name: allowed, whatever the global lists
//!    and feeds (threat feeds included) say, for that app only.
//! 3. A per-app block rule for the name (`app domain rule (<rule>)`).
//! 4. The global allowlist: allowed (overrides the denylist and every feed).
//! 5. The global denylist (`custom`).
//! 6. Feeds, threat categories first (`feed:<id>`).
//!
//! Addresses (before a name is known) only see 1 and the IP entries of
//! feeds, as before; name rules apply once the name is.

use crate::asn::{AsnInfo, AsnTable};
use crate::config::{AppRule, Config, DeviceState, DomainAction, NetworkType};
use crate::intel::{nat64_embedded, DomainSet, Feed, FeedKind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FeedCategory {
    Ads,
    #[default]
    Tracking,
    Malware,
    Phishing,
    C2,
    Custom,
    /// JA4 fingerprints only (see [`crate::intel::FeedKind::Ja4`]). Matches
    /// raise `threat_ja4` alerts; they block only with `block_ja4_matches`.
    Ja4,
    /// An IP → ASN table (see [`crate::asn`]): enriches `flow` events with
    /// the destination's autonomous system; never blocks.
    Asn,
}

impl FeedCategory {
    /// Threat categories raise alerts in addition to blocking.
    pub fn is_threat(self) -> bool {
        matches!(
            self,
            FeedCategory::Malware | FeedCategory::Phishing | FeedCategory::C2
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            FeedCategory::Ads => "ads",
            FeedCategory::Tracking => "tracking",
            FeedCategory::Malware => "malware",
            FeedCategory::Phishing => "phishing",
            FeedCategory::C2 => "c2",
            FeedCategory::Custom => "custom",
            FeedCategory::Ja4 => "ja4",
            FeedCategory::Asn => "asn",
        }
    }

    /// What a feed of this category may contain.
    pub fn feed_kind(self) -> FeedKind {
        match self {
            FeedCategory::Ja4 => FeedKind::Ja4,
            FeedCategory::Asn => FeedKind::Asn,
            _ => FeedKind::Mixed,
        }
    }
}

/// A flow's JA4 fingerprint matched a feed entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Ja4Match {
    /// Id of the feed that lists the fingerprint.
    pub feed: String,
    /// The listed entry (the fingerprint, or `a_b_*` for a wildcard entry).
    pub rule: String,
    /// The feed's label for the entry, e.g. a malware family.
    pub label: Option<String>,
}

pub struct LoadedFeed {
    pub category: FeedCategory,
    pub feed: Feed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Block(BlockReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockReason {
    /// Machine-readable reason, e.g. `feed:urlhaus`, `app`, `custom`.
    pub code: String,
    /// The list entry that matched, if any.
    pub rule: Option<String>,
    pub category: Option<FeedCategory>,
    /// The match was on the destination address (an IP feed), not a name.
    pub ip_match: bool,
}

impl BlockReason {
    fn simple(code: &str) -> Self {
        Self {
            code: code.into(),
            rule: None,
            category: None,
            ip_match: false,
        }
    }

    /// Identity of the list entry that matched, used to deduplicate alerts:
    /// many names under one listed suffix (DGA, DNS tunnelling) are one
    /// finding.
    pub fn alert_key(&self) -> String {
        format!("{}|{}", self.code, self.rule.as_deref().unwrap_or(""))
    }

    pub fn describe(&self) -> String {
        match &self.rule {
            Some(r) => format!("{} ({r})", self.code),
            None => self.code.clone(),
        }
    }

    pub fn is_threat(&self) -> bool {
        self.category.is_some_and(FeedCategory::is_threat)
    }

    /// A decision about one app (app block, app condition, per-app domain
    /// rule) rather than about the destination for everyone.
    pub fn is_per_app(&self) -> bool {
        self.code == APP_BLOCK || self.code.starts_with(APP_RULE) || self.code == APP_DOMAIN_RULE
    }

    /// A block by an app condition, which may lift when the device state
    /// changes.
    pub fn is_conditional(&self) -> bool {
        self.code.starts_with(APP_RULE)
    }
}

/// Reason codes of per-app decisions.
pub const APP_BLOCK: &str = "app";
pub const APP_RULE: &str = "app rule: ";
pub const APP_DOMAIN_RULE: &str = "app domain rule";

/// A condition of an [`AppRule`] that currently holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppCondition {
    Wifi,
    Cellular,
    ScreenOff,
    Background,
}

impl AppCondition {
    pub fn as_str(self) -> &'static str {
        match self {
            AppCondition::Wifi => "wifi",
            AppCondition::Cellular => "cellular",
            AppCondition::ScreenOff => "screen off",
            AppCondition::Background => "background",
        }
    }

    fn reason(self) -> BlockReason {
        BlockReason::simple(&format!("{APP_RULE}{}", self.as_str()))
    }
}

/// Per-app domain rules of one app.
#[derive(Default)]
struct AppDomains {
    allow: DomainSet,
    block: DomainSet,
}

/// The device state as the conditions need it.
struct State {
    network: NetworkType,
    screen_on: bool,
    foreground: Option<HashSet<u32>>,
}

impl From<&DeviceState> for State {
    fn from(s: &DeviceState) -> Self {
        Self {
            network: s.network,
            screen_on: s.screen_on,
            foreground: s
                .foreground_uids
                .as_ref()
                .map(|v| v.iter().copied().collect()),
        }
    }
}

/// Well-known DNS-over-HTTPS endpoints (matched as suffixes).
const DOH_HOSTS: &[&str] = &[
    "dns.google",
    "dns.google.com",
    "dns64.dns.google",
    "cloudflare-dns.com",
    "one.one.one.one",
    "1dot1dot1dot1.cloudflare-dns.com",
    "dns.quad9.net",
    "dns9.quad9.net",
    "dns10.quad9.net",
    "dns11.quad9.net",
    "doh.opendns.com",
    "doh.familyshield.opendns.com",
    "dns.nextdns.io",
    "doh.cleanbrowsing.org",
    "dns.adguard.com",
    "dns.adguard-dns.com",
    "unfiltered.adguard-dns.com",
    "family.adguard-dns.com",
    "doh.dns.sb",
    "dns.alidns.com",
    "doh.pub",
    "dns.controld.com",
    "freedns.controld.com",
    "dns.mullvad.net",
    "doh.mullvad.net",
    "dns0.eu",
    "doh.libredns.gr",
    "dns.switch.ch",
    "ordns.he.net",
    "doh.xfinity.com",
    "doh.applied-privacy.net",
    "dns.njal.la",
    "rethinkdns.com",
    "doh.ffmuc.net",
    "dns.digitale-gesellschaft.ch",
];

pub const DOT_PORT: u16 = 853;

/// Addresses of well-known public resolvers that serve DNS over HTTPS on
/// port 443 to clients that connect by address (no SNI): Cloudflare,
/// Google, Quad9 and AdGuard.
const DOH_IPS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
    IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
    IpAddr::V4(Ipv4Addr::new(149, 112, 112, 112)),
    IpAddr::V4(Ipv4Addr::new(94, 140, 14, 14)),
    IpAddr::V4(Ipv4Addr::new(94, 140, 15, 15)),
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844)),
    IpAddr::V6(Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0xfe)),
    IpAddr::V6(Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0x9)),
];

/// Whether `ip` is a well-known DoH resolver address (see [`DOH_IPS`]).
/// IPv4-mapped IPv6 addresses count; for NAT64 pass the embedded IPv4
/// address (`Policy::nat64_v4`).
pub fn is_doh_ip(ip: IpAddr) -> bool {
    DOH_IPS.contains(&ip.to_canonical())
}

#[cfg(test)]
mod doh_ip_tests {
    use super::*;

    #[test]
    fn well_known_doh_addresses() {
        for ip in [
            "1.1.1.1",
            "8.8.4.4",
            "94.140.15.15",
            "2606:4700:4700::1001",
            "2620:fe::9",
            "::ffff:9.9.9.9",
        ] {
            assert!(is_doh_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.2", "8.8.8.9", "2606:4700:4700::1112", "192.0.2.1"] {
            assert!(!is_doh_ip(ip.parse().unwrap()), "{ip}");
        }
    }
}

pub struct Policy {
    blocked_uids: HashSet<u32>,
    /// Conditional app rules with at least one condition, by UID.
    app_rules: HashMap<u32, AppRule>,
    app_domains: HashMap<u32, AppDomains>,
    /// Every name with a per-app domain rule (for any app): answers for them
    /// differ between apps, so they must not be cached by the OS resolver.
    app_ruled_names: DomainSet,
    state: State,
    allow: DomainSet,
    deny: DomainSet,
    feeds: BTreeMap<String, Arc<LoadedFeed>>,
    /// ASN tables (category `asn`) by feed id; normally at most one.
    asn: BTreeMap<String, Arc<AsnTable>>,
    doh: DomainSet,
    nat64: Vec<Ipv6Addr>,
    pub block_encrypted_dns: bool,
    /// Block connections whose JA4 fingerprint is listed (otherwise alert only).
    pub block_ja4: bool,
}

impl Policy {
    pub fn new(cfg: &Config) -> Self {
        let mut p = Self {
            blocked_uids: HashSet::new(),
            app_rules: HashMap::new(),
            app_domains: HashMap::new(),
            app_ruled_names: DomainSet::default(),
            state: State::from(&DeviceState::default()),
            allow: DomainSet::default(),
            deny: DomainSet::default(),
            feeds: BTreeMap::new(),
            asn: BTreeMap::new(),
            doh: DomainSet::from_names(DOH_HOSTS),
            nat64: Vec::new(),
            block_encrypted_dns: false,
            block_ja4: false,
        };
        p.apply_config(cfg);
        p
    }

    pub fn apply_config(&mut self, cfg: &Config) {
        self.blocked_uids = cfg.blocked_uids.iter().copied().collect();
        self.app_rules = cfg
            .app_rules
            .iter()
            .filter(|r| r.is_active())
            .map(|r| (r.uid, *r))
            .collect();
        let mut by_uid: HashMap<u32, (Vec<String>, Vec<String>)> = HashMap::new();
        let mut names = Vec::with_capacity(cfg.app_domain_rules.len());
        for r in &cfg.app_domain_rules {
            let d = crate::config::app_rules::normalize_domain(&r.domain);
            let e = by_uid.entry(r.uid).or_default();
            match r.action {
                DomainAction::Allow => e.0.push(d.clone()),
                DomainAction::Block => e.1.push(d.clone()),
            }
            names.push(d);
        }
        self.app_domains = by_uid
            .into_iter()
            .map(|(uid, (allow, block))| {
                let sets = AppDomains {
                    allow: DomainSet::from_names(&allow),
                    block: DomainSet::from_names(&block),
                };
                (uid, sets)
            })
            .collect();
        self.app_ruled_names = DomainSet::from_names(&names);
        if let Some(state) = &cfg.device_state {
            self.set_state(state);
        }
        self.allow = DomainSet::from_names(&cfg.allow_domains);
        self.deny = DomainSet::from_names(&cfg.deny_domains);
        self.block_encrypted_dns = cfg.block_encrypted_dns;
        self.block_ja4 = cfg.block_ja4_matches;
        self.nat64 = cfg.nat64_prefixes();
    }

    /// The IPv4 address behind a NAT64-synthesised IPv6 address.
    pub fn nat64_v4(&self, ip: IpAddr) -> Option<Ipv4Addr> {
        nat64_embedded(ip, &self.nat64)
    }

    pub fn set_feed(&mut self, id: &str, feed: LoadedFeed) {
        if feed.category == FeedCategory::Asn {
            self.feeds.remove(id);
            self.asn.insert(id.to_string(), Arc::new(feed.feed.asn));
            return;
        }
        self.asn.remove(id);
        self.feeds.insert(id.to_string(), Arc::new(feed));
    }

    pub fn remove_feed(&mut self, id: &str) -> bool {
        let asn = self.asn.remove(id).is_some();
        self.feeds.remove(id).is_some() || asn
    }

    pub fn feed_ids(&self) -> Vec<String> {
        self.feeds.keys().chain(self.asn.keys()).cloned().collect()
    }

    /// The autonomous system of a destination, from the loaded ASN tables.
    /// NAT64 addresses resolve through their embedded IPv4 address.
    pub fn asn_lookup(&self, ip: IpAddr) -> Option<AsnInfo> {
        if self.asn.is_empty() {
            return None;
        }
        let ip = self.nat64_v4(ip).map(IpAddr::V4).unwrap_or(ip);
        self.asn.values().find_map(|t| t.lookup(ip))
    }

    pub fn is_app_blocked(&self, uid: Option<u32>) -> bool {
        uid.is_some_and(|u| self.blocked_uids.contains(&u))
    }

    /// Installs a new device state for the app conditions.
    pub fn set_state(&mut self, state: &DeviceState) {
        self.state = State::from(state);
    }

    /// Whether any per-app rule (block list, condition or domain rule)
    /// exists; if not, open connections never need re-checking.
    pub fn has_app_rules(&self) -> bool {
        !self.blocked_uids.is_empty() || !self.app_rules.is_empty() || !self.app_domains.is_empty()
    }

    /// The first condition of `uid`'s rule that holds in the current state:
    /// network, then screen, then background.
    pub fn app_condition(&self, uid: u32) -> Option<AppCondition> {
        let r = self.app_rules.get(&uid)?;
        let st = &self.state;
        if r.block_wifi && st.network == NetworkType::Wifi {
            return Some(AppCondition::Wifi);
        }
        if r.block_cellular && st.network == NetworkType::Cellular {
            return Some(AppCondition::Cellular);
        }
        if r.block_screen_off && !st.screen_on {
            return Some(AppCondition::ScreenOff);
        }
        if r.block_background {
            // With the screen off no app is in the foreground, whether or
            // not the host can tell which one is while it is on.
            let background = match &st.foreground {
                _ if !st.screen_on => true,
                None => false,
                Some(fg) => !fg.contains(&uid),
            };
            if background {
                return Some(AppCondition::Background);
            }
        }
        None
    }

    /// Why all traffic of `uid` is blocked right now, if it is: always
    /// (`app`) or by a condition (`app rule: …`).
    pub fn app_block(&self, uid: Option<u32>) -> Option<BlockReason> {
        let uid = uid?;
        if self.blocked_uids.contains(&uid) {
            return Some(BlockReason::simple(APP_BLOCK));
        }
        self.app_condition(uid).map(AppCondition::reason)
    }

    /// Per-app domain rules of `uid` for `domain`: `Some(Allow)` or a block
    /// reason; `None` when the app has no rule for the name.
    fn app_domain_decision(&self, uid: Option<u32>, domain: &str) -> Option<Decision> {
        let rules = self.app_domains.get(&uid?)?;
        if rules.allow.match_suffix(domain).is_some() {
            return Some(Decision::Allow);
        }
        let rule = rules.block.match_suffix(domain)?;
        Some(Decision::Block(BlockReason {
            code: APP_DOMAIN_RULE.into(),
            rule: Some(rule.to_string()),
            category: None,
            ip_match: false,
        }))
    }

    /// Whether some app has a domain rule covering `domain`: answers for it
    /// differ between apps, so they must not be cached by the OS resolver
    /// (Android's cache is per network, shared by every app).
    pub fn has_app_domain_rule(&self, domain: &str) -> bool {
        !self.app_ruled_names.is_empty() && self.app_ruled_names.match_suffix(domain).is_some()
    }

    /// Re-check of an open connection after the device state or the rules
    /// changed: the app-level block and the app's own domain rules for the
    /// name it sent (`domain`, only an authoritative one). Global lists and
    /// feeds apply to new connections only.
    pub fn recheck_open(&self, uid: Option<u32>, domain: Option<&str>) -> Option<BlockReason> {
        if let Some(r) = self.app_block(uid) {
            return Some(r);
        }
        match self.app_domain_decision(uid, domain?) {
            Some(Decision::Block(r)) => Some(r),
            _ => None,
        }
    }

    pub fn is_doh_host(&self, domain: &str) -> bool {
        self.doh.match_suffix(domain).is_some()
    }

    /// Decision for a connection before any hostname is known. Addresses
    /// inside a NAT64 prefix are also matched by their embedded IPv4
    /// address (reported as the rule).
    pub fn check_ip(&self, uid: Option<u32>, ip: IpAddr) -> Decision {
        if let Some(r) = self.app_block(uid) {
            return Decision::Block(r);
        }
        let embedded = self.nat64_v4(ip).map(IpAddr::V4);
        for (id, lf) in &self.feeds {
            let hit = embedded
                .filter(|v4| lf.feed.ips.contains(*v4))
                .or_else(|| lf.feed.ips.contains(ip).then_some(ip));
            if let Some(hit) = hit {
                return Decision::Block(BlockReason {
                    code: format!("feed:{id}"),
                    rule: Some(hit.to_string()),
                    category: Some(lf.category),
                    ip_match: true,
                });
            }
        }
        Decision::Allow
    }

    /// Decision for a named destination (DNS query, SNI, HTTP Host).
    pub fn check_domain(&self, uid: Option<u32>, domain: &str) -> Decision {
        if let Some(r) = self.app_block(uid) {
            return Decision::Block(r);
        }
        if let Some(d) = self.app_domain_decision(uid, domain) {
            return d;
        }
        if self.allow.match_suffix(domain).is_some() {
            return Decision::Allow;
        }
        if let Some(rule) = self.deny.match_suffix(domain) {
            return Decision::Block(BlockReason {
                code: "custom".into(),
                rule: Some(rule.to_string()),
                category: Some(FeedCategory::Custom),
                ip_match: false,
            });
        }
        // Threat feeds take precedence so hits are reported with the most
        // severe category.
        let mut hit: Option<BlockReason> = None;
        for (id, lf) in &self.feeds {
            if let Some(rule) = lf.feed.domains.match_suffix(domain) {
                let reason = BlockReason {
                    code: format!("feed:{id}"),
                    rule: Some(rule.to_string()),
                    category: Some(lf.category),
                    ip_match: false,
                };
                if lf.category.is_threat() {
                    return Decision::Block(reason);
                }
                hit.get_or_insert(reason);
            }
        }
        match hit {
            Some(r) => Decision::Block(r),
            None => Decision::Allow,
        }
    }

    /// Whether `domain` is on the user allowlist.
    pub fn is_allowlisted(&self, domain: &str) -> bool {
        self.allow.match_suffix(domain).is_some()
    }

    /// Whether `domain` is allowed for `uid` by a user rule: the global
    /// allowlist or one of the app's own allow rules.
    pub fn is_allowlisted_for(&self, uid: Option<u32>, domain: &str) -> bool {
        self.is_allowlisted(domain)
            || matches!(self.app_domain_decision(uid, domain), Some(Decision::Allow))
    }

    /// Looks up a JA4 fingerprint in every loaded feed. Labelled entries win
    /// over unlabelled ones; otherwise feeds are searched in id order.
    pub fn match_ja4(&self, ja4: &str) -> Option<Ja4Match> {
        let mut found: Option<Ja4Match> = None;
        for (id, lf) in &self.feeds {
            let Some(hit) = lf.feed.ja4.lookup(ja4) else {
                continue;
            };
            let m = Ja4Match {
                feed: id.clone(),
                rule: hit.rule.to_string(),
                label: hit.label.map(str::to_string),
            };
            if m.label.is_some() {
                return Some(m);
            }
            found.get_or_insert(m);
        }
        found
    }

    /// Block reason for a listed JA4 fingerprint (`block_ja4_matches`).
    pub fn ja4_block(m: &Ja4Match) -> BlockReason {
        BlockReason {
            code: format!("ja4:{}", m.feed),
            rule: Some(m.rule.clone()),
            category: Some(FeedCategory::Ja4),
            ip_match: false,
        }
    }

    pub fn encrypted_dns_block() -> BlockReason {
        BlockReason::simple("encrypted_dns")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intel::parse_feed;

    fn policy() -> Policy {
        let cfg = Config {
            blocked_uids: vec![10500],
            allow_domains: vec!["good.tracker.com".into()],
            deny_domains: vec!["annoying.example".into()],
            ..Default::default()
        };
        let mut p = Policy::new(&cfg);
        p.set_feed(
            "easyprivacy",
            LoadedFeed {
                category: FeedCategory::Tracking,
                feed: parse_feed("tracker.com\nbad.example\n"),
            },
        );
        p.set_feed(
            "urlhaus",
            LoadedFeed {
                category: FeedCategory::Malware,
                feed: parse_feed("bad.example\n203.0.113.0/24\n"),
            },
        );
        p
    }

    #[test]
    fn decisions() {
        let p = policy();
        assert_eq!(p.check_domain(Some(1), "news.example"), Decision::Allow);
        let Decision::Block(r) = p.check_domain(Some(1), "x.tracker.com") else {
            panic!()
        };
        assert_eq!(r.code, "feed:easyprivacy");
        assert_eq!(r.rule.as_deref(), Some("tracker.com"));
        assert!(!r.is_threat());
        assert_eq!(p.check_domain(Some(1), "good.tracker.com"), Decision::Allow);
        // Threat categories win over tracking lists regardless of order.
        let Decision::Block(r) = p.check_domain(None, "cdn.bad.example") else {
            panic!()
        };
        assert_eq!(r.code, "feed:urlhaus");
        assert!(r.is_threat());
        let Decision::Block(r) = p.check_domain(Some(1), "annoying.example") else {
            panic!()
        };
        assert_eq!(r.code, "custom");
        let Decision::Block(r) = p.check_domain(Some(10500), "news.example") else {
            panic!()
        };
        assert_eq!(r.code, "app");
        assert!(matches!(
            p.check_ip(Some(1), "203.0.113.9".parse().unwrap()),
            Decision::Block(_)
        ));
        assert_eq!(
            p.check_ip(Some(1), "198.51.100.1".parse().unwrap()),
            Decision::Allow
        );
    }

    fn reason(d: Decision) -> Option<String> {
        match d {
            Decision::Allow => None,
            Decision::Block(r) => Some(r.describe()),
        }
    }

    fn state(network: NetworkType, screen_on: bool, fg: Option<Vec<u32>>) -> DeviceState {
        DeviceState {
            network,
            screen_on,
            foreground_uids: fg,
        }
    }

    #[test]
    fn app_conditions() {
        use crate::config::AppRule;
        let rule = |uid, f: fn(&mut AppRule)| {
            let mut r = AppRule {
                uid,
                ..Default::default()
            };
            f(&mut r);
            r
        };
        let mut p = policy();
        p.apply_config(&Config {
            blocked_uids: vec![10500],
            app_rules: vec![
                rule(1, |r| r.block_wifi = true),
                rule(2, |r| r.block_cellular = true),
                rule(3, |r| r.block_background = true),
                rule(4, |r| r.block_screen_off = true),
                rule(5, |r| {
                    r.block_wifi = true;
                    r.block_background = true;
                }),
                rule(6, |_| {}), // no condition: inert
            ],
            ..Default::default()
        });
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        let why = |p: &Policy, uid| reason(p.check_ip(Some(uid), ip));
        // Default state: network "other", screen on, foreground unknown.
        for uid in 1..=6 {
            assert_eq!(why(&p, uid), None, "uid {uid}");
        }
        assert_eq!(why(&p, 10500).as_deref(), Some("app"));
        assert_eq!(reason(p.check_ip(None, ip)), None);

        p.set_state(&state(NetworkType::Wifi, true, Some(vec![3, 5])));
        assert_eq!(why(&p, 1).as_deref(), Some("app rule: wifi"));
        assert_eq!(why(&p, 2), None);
        assert_eq!(why(&p, 3), None, "in the foreground");
        assert_eq!(why(&p, 5).as_deref(), Some("app rule: wifi"));
        assert_eq!(why(&p, 6), None);

        p.set_state(&state(NetworkType::Cellular, true, Some(vec![5])));
        assert_eq!(why(&p, 1), None);
        assert_eq!(why(&p, 2).as_deref(), Some("app rule: cellular"));
        assert_eq!(why(&p, 3).as_deref(), Some("app rule: background"));
        assert_eq!(why(&p, 4), None);
        assert_eq!(why(&p, 5), None);

        // Foreground unknown (no usage access): background rules cannot apply...
        p.set_state(&state(NetworkType::None, true, None));
        assert_eq!(why(&p, 3), None);
        // ...except with the screen off, when no app is in the foreground.
        p.set_state(&state(NetworkType::None, false, None));
        assert_eq!(why(&p, 3).as_deref(), Some("app rule: background"));
        assert_eq!(why(&p, 4).as_deref(), Some("app rule: screen off"));
        p.set_state(&state(NetworkType::Other, false, Some(vec![3])));
        assert_eq!(why(&p, 3).as_deref(), Some("app rule: background"));
        // Several conditions: network first, then screen, then background.
        p.set_state(&state(NetworkType::Wifi, false, Some(vec![])));
        assert_eq!(why(&p, 5).as_deref(), Some("app rule: wifi"));
        // Names follow the same app block, before any allow rule.
        let Decision::Block(r) = p.check_domain(Some(5), "good.tracker.com") else {
            panic!()
        };
        assert!(r.is_per_app() && r.is_conditional() && !r.is_threat());
        assert_eq!(p.app_block(Some(10500)).unwrap().code, "app");
        assert!(!p.app_block(Some(10500)).unwrap().is_conditional());
        // A configuration update carrying a state installs it; one without
        // keeps the current state.
        p.apply_config(&Config {
            app_rules: vec![rule(1, |r| r.block_wifi = true)],
            ..Default::default()
        });
        assert_eq!(why(&p, 1).as_deref(), Some("app rule: wifi"));
        p.apply_config(&Config {
            app_rules: vec![rule(1, |r| r.block_wifi = true)],
            device_state: Some(DeviceState::default()),
            ..Default::default()
        });
        assert_eq!(why(&p, 1), None);
        assert!(p.has_app_rules());
        p.apply_config(&Config::default());
        assert!(!p.has_app_rules());
    }

    #[test]
    fn per_app_domain_rules_and_precedence() {
        use crate::config::AppDomainRule;
        let r = |uid, domain: &str, action| AppDomainRule {
            uid,
            domain: domain.into(),
            action,
        };
        let mut p = policy();
        p.apply_config(&Config {
            blocked_uids: vec![10500],
            allow_domains: vec!["good.tracker.com".into()],
            deny_domains: vec!["annoying.example".into()],
            app_domain_rules: vec![
                // App 1 may use a tracker, a threat-listed name and a denied one.
                r(1, "tracker.com", DomainAction::Allow),
                r(1, "bad.example", DomainAction::Allow),
                r(1, "annoying.example", DomainAction::Allow),
                // App 2 may not use a name everybody else may (even allowlisted).
                r(2, "*.News.Example.", DomainAction::Block),
                r(2, "good.tracker.com", DomainAction::Block),
                // Allow wins over block for the same app.
                r(3, "cdn.example", DomainAction::Allow),
                r(3, "example", DomainAction::Block),
                // An always-blocked app stays blocked.
                r(10500, "news.example", DomainAction::Allow),
            ],
            ..Default::default()
        });
        let why = |uid, d| reason(p.check_domain(Some(uid), d));
        assert_eq!(why(1, "x.tracker.com"), None);
        assert_eq!(
            why(1, "cdn.bad.example"),
            None,
            "per-app allow beats threat feeds"
        );
        assert_eq!(why(1, "annoying.example"), None);
        assert_eq!(
            why(9, "x.tracker.com").as_deref(),
            Some("feed:easyprivacy (tracker.com)")
        );
        assert_eq!(
            why(9, "cdn.bad.example").as_deref(),
            Some("feed:urlhaus (bad.example)")
        );
        assert_eq!(
            why(9, "annoying.example").as_deref(),
            Some("custom (annoying.example)")
        );
        assert_eq!(
            why(2, "www.news.example").as_deref(),
            Some("app domain rule (news.example)")
        );
        assert_eq!(
            why(2, "news.example").as_deref(),
            Some("app domain rule (news.example)")
        );
        assert_eq!(
            why(2, "good.tracker.com").as_deref(),
            Some("app domain rule (good.tracker.com)"),
            "per-app block beats the global allowlist"
        );
        assert_eq!(why(9, "www.news.example"), None);
        assert_eq!(why(3, "img.cdn.example"), None);
        assert_eq!(
            why(3, "other.example").as_deref(),
            Some("app domain rule (example)")
        );
        assert_eq!(why(10500, "news.example").as_deref(), Some("app"));
        assert_eq!(reason(p.check_domain(None, "www.news.example")), None);
        // Address checks are unaffected by name rules.
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        assert!(reason(p.check_ip(Some(1), ip)).is_some());
        // Allowlisting (JA4 blocking, beacon exemption) includes per-app allows.
        assert!(p.is_allowlisted_for(Some(1), "x.tracker.com"));
        assert!(!p.is_allowlisted_for(Some(9), "x.tracker.com"));
        assert!(p.is_allowlisted_for(Some(9), "good.tracker.com"));
        // Names answered differently per app.
        assert!(p.has_app_domain_rule("a.b.tracker.com"));
        assert!(p.has_app_domain_rule("news.example"));
        assert!(!p.has_app_domain_rule("unrelated.org"));
        // Re-checks of open connections: app blocks and the app's own block rules.
        assert_eq!(
            p.recheck_open(Some(2), Some("www.news.example"))
                .unwrap()
                .code,
            "app domain rule"
        );
        assert!(p.recheck_open(Some(2), None).is_none());
        assert!(
            p.recheck_open(Some(9), Some("annoying.example")).is_none(),
            "global lists: new connections only"
        );
        assert!(p.recheck_open(Some(3), Some("img.cdn.example")).is_none());
        assert_eq!(p.recheck_open(Some(10500), None).unwrap().code, "app");
        assert!(p.recheck_open(None, Some("www.news.example")).is_none());
    }

    #[test]
    fn nat64_addresses_match_ipv4_feeds() {
        let mut p = policy();
        let ip: IpAddr = "64:ff9b::203.0.113.9".parse().unwrap();
        let Decision::Block(r) = p.check_ip(Some(1), ip) else {
            panic!("well-known prefix must always apply")
        };
        assert_eq!(r.rule.as_deref(), Some("203.0.113.9"));
        assert!(r.ip_match && r.is_threat());
        assert_eq!(r.alert_key(), "feed:urlhaus|203.0.113.9");
        let local: IpAddr = "2001:db8:64::cb00:7109".parse().unwrap();
        assert_eq!(p.check_ip(Some(1), local), Decision::Allow);
        p.apply_config(&Config {
            nat64_prefixes: vec!["2001:db8:64::/96".into()],
            ..Default::default()
        });
        assert!(matches!(p.check_ip(Some(1), local), Decision::Block(_)));
        assert_eq!(p.nat64_v4(local), Some(Ipv4Addr::new(203, 0, 113, 9)));
        // Plain IPv4-mapped and unrelated IPv6 addresses keep working.
        assert!(matches!(
            p.check_ip(Some(1), "::ffff:203.0.113.9".parse().unwrap()),
            Decision::Block(_)
        ));
        assert_eq!(
            p.check_ip(Some(1), "2001:db8::1".parse().unwrap()),
            Decision::Allow
        );
    }

    #[test]
    fn ja4_matching() {
        let mut p = policy();
        assert_eq!(p.match_ja4("t13d190900_9dc949149365_97f8aa674fd9"), None);
        let text = "t13d190900_9dc949149365_97f8aa674fd9\nq13d0312h3_55b375c5d22e_*\n";
        p.set_feed(
            "a-unlabelled",
            LoadedFeed {
                category: FeedCategory::Ja4,
                feed: parse_feed(text),
            },
        );
        p.set_feed(
            "b-labelled",
            LoadedFeed {
                category: FeedCategory::C2,
                feed: parse_feed("t13d190900_9dc949149365_97f8aa674fd9 Sliver\n"),
            },
        );
        let m = p.match_ja4("t13d190900_9dc949149365_97f8aa674fd9").unwrap();
        assert_eq!(m.feed, "b-labelled");
        assert_eq!(m.label.as_deref(), Some("Sliver"));
        let q = p.match_ja4("q13d0312h3_55b375c5d22e_06cda9e17597").unwrap();
        assert_eq!(
            (q.feed.as_str(), q.rule.as_str()),
            ("a-unlabelled", "q13d0312h3_55b375c5d22e_*")
        );
        assert_eq!(q.label, None);
        let r = Policy::ja4_block(&q);
        assert_eq!(r.describe(), "ja4:a-unlabelled (q13d0312h3_55b375c5d22e_*)");
        assert!(!r.is_threat(), "the JA4 alert is raised separately");
        // JA4 entries never block by name or address.
        assert_eq!(p.check_domain(Some(1), "news.example"), Decision::Allow);
        assert!(!p.block_ja4);
        p.apply_config(&Config {
            block_ja4_matches: true,
            allow_domains: vec!["trusted.example".into()],
            ..Default::default()
        });
        assert!(p.block_ja4);
        assert!(p.is_allowlisted("api.trusted.example"));
        assert!(!p.is_allowlisted("news.example"));
        assert_eq!(FeedCategory::Ja4.feed_kind(), FeedKind::Ja4);
        let cat: FeedCategory = serde_json::from_str("\"ja4\"").unwrap();
        assert_eq!(cat, FeedCategory::Ja4);
    }

    #[test]
    fn asn_tables_are_lookups_not_blocklists() {
        let mut p = policy();
        let ip: IpAddr = "192.0.2.9".parse().unwrap();
        assert_eq!(p.asn_lookup(ip), None);
        let text = "192.0.2.0\t192.0.2.255\t64500\tNL\tEXAMPLE-NET\n\
                    2001:db8::\t2001:db8::ffff\t64501\tDE\tEXAMPLE-V6\n";
        let feed = crate::intel::parse_feed_reader_kind(text.as_bytes(), FeedKind::Asn).unwrap();
        assert_eq!(feed.ip_range_count(), 2);
        assert!(feed.domains.is_empty() && feed.ips.is_empty());
        p.set_feed(
            "iptoasn",
            LoadedFeed {
                category: FeedCategory::Asn,
                feed,
            },
        );
        assert!(p.feed_ids().contains(&"iptoasn".to_string()));
        let a = p.asn_lookup(ip).unwrap();
        assert_eq!((a.number, a.name.as_str()), (64500, "EXAMPLE-NET"));
        assert_eq!(a.country.as_deref(), Some("NL"));
        // NAT64 (well-known prefix) and IPv4-mapped addresses use the IPv4 table.
        for v6 in ["64:ff9b::192.0.2.9", "::ffff:192.0.2.9"] {
            assert_eq!(p.asn_lookup(v6.parse().unwrap()).unwrap().number, 64500);
        }
        assert_eq!(
            p.asn_lookup("2001:db8::1".parse().unwrap()).unwrap().number,
            64501
        );
        assert_eq!(p.asn_lookup("198.51.100.1".parse().unwrap()), None);
        // The ASN "feed" neither blocks nor alerts.
        assert_eq!(
            p.check_ip(Some(1), "192.0.2.10".parse().unwrap()),
            Decision::Allow
        );
        assert!(p.remove_feed("iptoasn"));
        assert_eq!(p.asn_lookup(ip), None);
        let cat: FeedCategory = serde_json::from_str("\"asn\"").unwrap();
        assert_eq!(cat.feed_kind(), FeedKind::Asn);
        assert!(!cat.is_threat());
    }

    #[test]
    fn doh_hosts() {
        let p = policy();
        assert!(p.is_doh_host("dns.google"));
        assert!(p.is_doh_host("mozilla.cloudflare-dns.com"));
        assert!(!p.is_doh_host("google.com"));
    }
}
