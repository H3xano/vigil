//! Blocking policy: per-app blocks, threat/tracker feeds, user allow/deny
//! lists and encrypted-DNS handling.

use crate::asn::{AsnInfo, AsnTable};
use crate::config::Config;
use crate::intel::{nat64_embedded, DomainSet, Feed, FeedKind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
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

    pub fn is_doh_host(&self, domain: &str) -> bool {
        self.doh.match_suffix(domain).is_some()
    }

    /// Decision for a connection before any hostname is known. Addresses
    /// inside a NAT64 prefix are also matched by their embedded IPv4
    /// address (reported as the rule).
    pub fn check_ip(&self, uid: Option<u32>, ip: IpAddr) -> Decision {
        if self.is_app_blocked(uid) {
            return Decision::Block(BlockReason::simple("app"));
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
