//! Blocking policy: per-app blocks, threat/tracker feeds, user allow/deny
//! lists and encrypted-DNS handling.

use crate::config::Config;
use crate::intel::{DomainSet, Feed};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
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
}

impl FeedCategory {
    /// Threat categories raise alerts in addition to blocking.
    pub fn is_threat(self) -> bool {
        matches!(self, FeedCategory::Malware | FeedCategory::Phishing | FeedCategory::C2)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            FeedCategory::Ads => "ads",
            FeedCategory::Tracking => "tracking",
            FeedCategory::Malware => "malware",
            FeedCategory::Phishing => "phishing",
            FeedCategory::C2 => "c2",
            FeedCategory::Custom => "custom",
        }
    }
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
}

impl BlockReason {
    fn simple(code: &str) -> Self {
        Self { code: code.into(), rule: None, category: None }
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

pub struct Policy {
    blocked_uids: HashSet<u32>,
    allow: DomainSet,
    deny: DomainSet,
    feeds: BTreeMap<String, Arc<LoadedFeed>>,
    doh: DomainSet,
    pub block_encrypted_dns: bool,
}

impl Policy {
    pub fn new(cfg: &Config) -> Self {
        let mut p = Self {
            blocked_uids: HashSet::new(),
            allow: DomainSet::default(),
            deny: DomainSet::default(),
            feeds: BTreeMap::new(),
            doh: DomainSet::from_names(DOH_HOSTS),
            block_encrypted_dns: false,
        };
        p.apply_config(cfg);
        p
    }

    pub fn apply_config(&mut self, cfg: &Config) {
        self.blocked_uids = cfg.blocked_uids.iter().copied().collect();
        self.allow = DomainSet::from_names(&cfg.allow_domains);
        self.deny = DomainSet::from_names(&cfg.deny_domains);
        self.block_encrypted_dns = cfg.block_encrypted_dns;
    }

    pub fn set_feed(&mut self, id: &str, feed: LoadedFeed) {
        self.feeds.insert(id.to_string(), Arc::new(feed));
    }

    pub fn remove_feed(&mut self, id: &str) -> bool {
        self.feeds.remove(id).is_some()
    }

    pub fn feed_ids(&self) -> Vec<String> {
        self.feeds.keys().cloned().collect()
    }

    pub fn is_app_blocked(&self, uid: Option<u32>) -> bool {
        uid.is_some_and(|u| self.blocked_uids.contains(&u))
    }

    pub fn is_doh_host(&self, domain: &str) -> bool {
        self.doh.match_suffix(domain).is_some()
    }

    /// Decision for a connection before any hostname is known.
    pub fn check_ip(&self, uid: Option<u32>, ip: IpAddr) -> Decision {
        if self.is_app_blocked(uid) {
            return Decision::Block(BlockReason::simple("app"));
        }
        for (id, lf) in &self.feeds {
            if lf.feed.ips.contains(ip) {
                return Decision::Block(BlockReason {
                    code: format!("feed:{id}"),
                    rule: Some(ip.to_string()),
                    category: Some(lf.category),
                });
            }
        }
        Decision::Allow
    }

    /// Decision for a named destination (DNS query, SNI, HTTP Host).
    pub fn check_domain(&self, uid: Option<u32>, domain: &str) -> Decision {
        if self.is_app_blocked(uid) {
            return Decision::Block(BlockReason::simple("app"));
        }
        if self.allow.match_suffix(domain).is_some() {
            return Decision::Allow;
        }
        if let Some(rule) = self.deny.match_suffix(domain) {
            return Decision::Block(BlockReason {
                code: "custom".into(),
                rule: Some(rule.to_string()),
                category: Some(FeedCategory::Custom),
            });
        }
        // Threat feeds take precedence so hits are reported with the most
        // severe category.
        let mut hit: Option<BlockReason> = None;
        for (id, lf) in &self.feeds {
            if let Some(rule) = lf.feed.domains.match_suffix(domain) {
                let reason =
                    BlockReason { code: format!("feed:{id}"), rule: Some(rule.to_string()), category: Some(lf.category) };
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
        p.set_feed("easyprivacy", LoadedFeed { category: FeedCategory::Tracking, feed: parse_feed("tracker.com\nbad.example\n") });
        p.set_feed("urlhaus", LoadedFeed { category: FeedCategory::Malware, feed: parse_feed("bad.example\n203.0.113.0/24\n") });
        p
    }

    #[test]
    fn decisions() {
        let p = policy();
        assert_eq!(p.check_domain(Some(1), "news.example"), Decision::Allow);
        let Decision::Block(r) = p.check_domain(Some(1), "x.tracker.com") else { panic!() };
        assert_eq!(r.code, "feed:easyprivacy");
        assert_eq!(r.rule.as_deref(), Some("tracker.com"));
        assert!(!r.is_threat());
        assert_eq!(p.check_domain(Some(1), "good.tracker.com"), Decision::Allow);
        // Threat categories win over tracking lists regardless of order.
        let Decision::Block(r) = p.check_domain(None, "cdn.bad.example") else { panic!() };
        assert_eq!(r.code, "feed:urlhaus");
        assert!(r.is_threat());
        let Decision::Block(r) = p.check_domain(Some(1), "annoying.example") else { panic!() };
        assert_eq!(r.code, "custom");
        let Decision::Block(r) = p.check_domain(Some(10500), "news.example") else { panic!() };
        assert_eq!(r.code, "app");
        assert!(matches!(p.check_ip(Some(1), "203.0.113.9".parse().unwrap()), Decision::Block(_)));
        assert_eq!(p.check_ip(Some(1), "198.51.100.1".parse().unwrap()), Decision::Allow);
    }

    #[test]
    fn doh_hosts() {
        let p = policy();
        assert!(p.is_doh_host("dns.google"));
        assert!(p.is_doh_host("mozilla.cloudflare-dns.com"));
        assert!(!p.is_doh_host("google.com"));
    }
}
