//! Threat-intelligence data structures and feed parsers.
//!
//! Blocklists can contain millions of entries, so both sets are built once
//! and then frozen into compact sorted arrays:
//! * [`DomainSet`] stores all names in one string arena plus a sorted offset
//!   table (≈ name bytes + 8 bytes per entry) and answers suffix queries
//!   ("is `a.b.tracker.com` covered by `tracker.com`?") with one binary search
//!   per label.
//! * [`IpSet`] stores merged, sorted IPv4/IPv6 ranges.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Default, Debug, Clone)]
pub struct DomainSet {
    arena: String,
    /// (start, len) into `arena`, sorted by the referenced string.
    index: Vec<(u32, u32)>,
}

impl DomainSet {
    pub fn from_names<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut b = DomainSetBuilder::default();
        for n in names {
            b.push(n.as_ref());
        }
        b.build()
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    fn get(&self, i: usize) -> &str {
        let (s, l) = self.index[i];
        &self.arena[s as usize..(s + l) as usize]
    }

    pub fn contains_exact(&self, name: &str) -> bool {
        self.index
            .binary_search_by(|&(s, l)| self.arena[s as usize..(s + l) as usize].cmp(name))
            .is_ok()
    }

    /// Returns the most specific listed suffix covering `name` (which must
    /// already be normalised), e.g. `ads.tracker.com` → `tracker.com`.
    pub fn match_suffix<'a>(&'a self, name: &str) -> Option<&'a str> {
        let mut candidate = name;
        loop {
            if let Ok(i) = self
                .index
                .binary_search_by(|&(s, l)| self.arena[s as usize..(s + l) as usize].cmp(candidate))
            {
                return Some(self.get(i));
            }
            let dot = candidate.find('.')?;
            candidate = &candidate[dot + 1..];
        }
    }

    pub fn memory_bytes(&self) -> usize {
        self.arena.capacity() + self.index.capacity() * 8
    }
}

/// Builds a [`DomainSet`] without allocating per name: names are normalised
/// straight into the arena, then only the (offset, len) index is sorted.
#[derive(Default)]
pub struct DomainSetBuilder {
    arena: String,
    index: Vec<(u32, u32)>,
}

impl DomainSetBuilder {
    pub fn push(&mut self, raw: &str) -> bool {
        let s = raw.trim().trim_end_matches('.');
        if s.is_empty() || s.len() > 253 || self.arena.len() + s.len() > u32::MAX as usize {
            return false;
        }
        let start = self.arena.len();
        for c in s.chars() {
            match c {
                'A'..='Z' => self.arena.push(c.to_ascii_lowercase()),
                'a'..='z' | '0'..='9' | '-' | '.' | '_' => self.arena.push(c),
                _ => {
                    self.arena.truncate(start);
                    return false;
                }
            }
        }
        self.index.push((start as u32, s.len() as u32));
        true
    }

    pub fn build(mut self) -> DomainSet {
        let arena = &self.arena;
        let get = |&(s, l): &(u32, u32)| &arena[s as usize..(s + l) as usize];
        self.index.sort_unstable_by(|a, b| get(a).cmp(get(b)));
        self.index.dedup_by(|a, b| get(a) == get(b));
        self.index.shrink_to_fit();
        self.arena.shrink_to_fit();
        DomainSet {
            arena: self.arena,
            index: self.index,
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct IpSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

fn merge<T: Ord + Copy + num_like::One>(mut v: Vec<(T, T)>) -> Vec<(T, T)> {
    v.sort_unstable();
    let mut out: Vec<(T, T)> = Vec::with_capacity(v.len());
    for (s, e) in v {
        if let Some(last) = out.last_mut() {
            if s <= last.1 || last.1.succ() == Some(s) {
                if e > last.1 {
                    last.1 = e;
                }
                continue;
            }
        }
        out.push((s, e));
    }
    out
}

mod num_like {
    pub trait One: Sized {
        fn succ(self) -> Option<Self>;
    }
    impl One for u32 {
        fn succ(self) -> Option<Self> {
            self.checked_add(1)
        }
    }
    impl One for u128 {
        fn succ(self) -> Option<Self> {
            self.checked_add(1)
        }
    }
}

fn find_range<T: Ord + Copy>(ranges: &[(T, T)], x: T) -> bool {
    let i = ranges.partition_point(|&(s, _)| s <= x);
    i > 0 && ranges[i - 1].1 >= x
}

/// Parses `a.b.c.d`, `a.b.c.d/nn`, `v6`, `v6/nn` into an inclusive range.
pub fn parse_cidr(s: &str) -> Option<IpRange> {
    let (addr, prefix) = match s.split_once('/') {
        Some((a, p)) => (a, Some(p.parse::<u8>().ok()?)),
        None => (s, None),
    };
    match addr.parse::<IpAddr>().ok()? {
        IpAddr::V4(a) => {
            let p = prefix.unwrap_or(32);
            if p > 32 {
                return None;
            }
            let base = u32::from(a);
            let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
            Some(IpRange::V4(base & mask, (base & mask) | !mask))
        }
        IpAddr::V6(a) => {
            let p = prefix.unwrap_or(128);
            if p > 128 {
                return None;
            }
            let base = u128::from(a);
            let mask = if p == 0 { 0 } else { u128::MAX << (128 - p) };
            Some(IpRange::V6(base & mask, (base & mask) | !mask))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpRange {
    V4(u32, u32),
    V6(u128, u128),
}

impl IpSet {
    pub fn from_ranges(ranges: impl IntoIterator<Item = IpRange>) -> Self {
        let (mut v4, mut v6) = (Vec::new(), Vec::new());
        for r in ranges {
            match r {
                IpRange::V4(s, e) => v4.push((s, e)),
                IpRange::V6(s, e) => v6.push((s, e)),
            }
        }
        Self {
            v4: merge(v4),
            v6: merge(v6),
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(a) => find_range(&self.v4, u32::from(a)),
            IpAddr::V6(a) => match a.to_ipv4_mapped() {
                Some(v4) => find_range(&self.v4, u32::from(v4)),
                None => find_range(&self.v6, u128::from(a)),
            },
        }
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A parsed feed: domains and IP ranges.
#[derive(Default, Debug, Clone)]
pub struct Feed {
    pub domains: DomainSet,
    pub ips: IpSet,
    /// Lines that could not be interpreted.
    pub rejected: usize,
}

impl Feed {
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty() && self.ips.is_empty()
    }
}

fn is_sink_address(s: &str) -> bool {
    matches!(s, "0.0.0.0" | "127.0.0.1" | "::" | "::1" | "0" | "::0")
}

/// Parses a blocklist in any of the common formats, auto-detected per line:
/// * hosts files: `0.0.0.0 tracker.example.com` (multiple names allowed)
/// * AdGuard / uBlock network rules: `||tracker.example.com^` (rules with
///   paths, modifiers other than `$important`/`$all`, or exceptions are skipped)
/// * plain domain lists: `tracker.example.com`, wildcard `*.example.com`
/// * IP / CIDR lists (abuse.ch, Spamhaus DROP, FireHOL): `192.0.2.0/24 ; comment`
///
/// Comments start with `#`, `!` or `;`.
pub fn parse_feed(text: &str) -> Feed {
    parse_feed_lines(text.lines())
}

/// Streams a feed from a reader line by line, so the file never has to be
/// held in memory in full. Invalid UTF-8 is replaced, not fatal.
pub fn parse_feed_reader<R: std::io::BufRead>(mut r: R) -> std::io::Result<Feed> {
    let mut buf = Vec::with_capacity(256);
    let mut builder = FeedBuilder::default();
    loop {
        buf.clear();
        if r.read_until(b'\n', &mut buf)? == 0 {
            break;
        }
        let line = String::from_utf8_lossy(&buf);
        builder.line(line.trim_end_matches(['\n', '\r']));
    }
    Ok(builder.finish())
}

pub fn parse_feed_lines<'a>(lines: impl Iterator<Item = &'a str>) -> Feed {
    let mut b = FeedBuilder::default();
    for l in lines {
        b.line(l);
    }
    b.finish()
}

#[derive(Default)]
struct FeedBuilder {
    domains: DomainSetBuilder,
    ranges: Vec<IpRange>,
    rejected: usize,
}

impl FeedBuilder {
    fn finish(self) -> Feed {
        Feed {
            domains: self.domains.build(),
            ips: IpSet::from_ranges(self.ranges),
            rejected: self.rejected,
        }
    }

    fn line(&mut self, raw: &str) {
        parse_line(raw, &mut self.domains, &mut self.ranges, &mut self.rejected);
    }
}

fn parse_line(
    raw: &str,
    domains: &mut DomainSetBuilder,
    ranges: &mut Vec<IpRange>,
    rejected: &mut usize,
) {
    // Cosmetic (element-hiding) rules contain '#' and must be recognised
    // before comment stripping.
    if raw.contains("##") || raw.contains("#@#") || raw.contains("#?#") || raw.contains("#$#") {
        if !raw.trim_start().starts_with('#') {
            *rejected += 1;
        }
        return;
    }
    let line = raw.split(['#', ';']).next().unwrap_or("").trim();
    if line.is_empty() || line.starts_with('!') || line.starts_with('[') {
        return;
    }
    if let Some(rule) = line.strip_prefix("||") {
        let (body, modifiers) = rule.split_once('$').unwrap_or((rule, ""));
        let modifiers_ok =
            modifiers.is_empty() || modifiers.split(',').all(|m| m == "important" || m == "all");
        match body.strip_suffix('^') {
            Some(d) if modifiers_ok && !d.contains('/') && !d.contains('*') && domains.push(d) => {}
            _ => *rejected += 1,
        }
        return;
    }
    if line.starts_with("@@") {
        *rejected += 1;
        return;
    }
    let mut fields = line.split_whitespace();
    let first = fields.next().unwrap_or_default();
    let mut rest = fields.peekable();
    if rest.peek().is_some() && first.parse::<IpAddr>().is_ok() {
        // hosts-file entry; sink addresses precede the blocked names.
        if is_sink_address(first) {
            for h in rest.filter(|h| *h != "localhost" && !h.ends_with(".localdomain")) {
                domains.push(h);
            }
        } else {
            *rejected += 1;
        }
        return;
    }
    if let Some(r) = parse_cidr(first) {
        ranges.push(r);
        return;
    }
    let name = first.strip_prefix("*.").unwrap_or(first);
    if !(name.contains('.') && !name.contains('*') && domains.push(name)) {
        *rejected += 1;
    }
}

/// Whether an address is in a range that must never leave the device or be
/// treated as an internet destination (loopback, link-local, multicast...).
pub fn is_special(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            a.is_loopback()
                || a.is_link_local()
                || a.is_multicast()
                || a.is_broadcast()
                || a.is_unspecified()
        }
        IpAddr::V6(a) => {
            a.is_loopback()
                || a.is_multicast()
                || a.is_unspecified()
                || (a.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// The IPv4 address embedded in `ip` if it lies inside one of the NAT64 /96
/// `prefixes` (RFC 6052: the IPv4 address is the last 32 bits).
pub fn nat64_embedded(ip: IpAddr, prefixes: &[Ipv6Addr]) -> Option<Ipv4Addr> {
    let IpAddr::V6(a) = ip else {
        return None;
    };
    let bits = u128::from(a);
    prefixes
        .iter()
        .any(|p| u128::from(*p) >> 32 == bits >> 32)
        .then(|| Ipv4Addr::from(bits as u32))
}

pub fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

pub fn v6(s: &str) -> IpAddr {
    IpAddr::V6(s.parse::<Ipv6Addr>().expect("valid v6 literal"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nat64_extraction() {
        let wk: Ipv6Addr = "64:ff9b::".parse().unwrap();
        let local: Ipv6Addr = "2001:db8:64:ff9b::".parse().unwrap();
        let p = [wk, local];
        assert_eq!(
            nat64_embedded(v6("64:ff9b::203.0.113.9"), &p),
            Some(Ipv4Addr::new(203, 0, 113, 9))
        );
        assert_eq!(
            nat64_embedded(v6("2001:db8:64:ff9b::c000:0201"), &p),
            Some(Ipv4Addr::new(192, 0, 2, 1))
        );
        assert_eq!(nat64_embedded(v6("64:ff9b:1::203.0.113.9"), &p), None);
        assert_eq!(nat64_embedded(v6("2001:db8::1"), &p), None);
        assert_eq!(nat64_embedded(v4(203, 0, 113, 9), &p), None);
    }

    #[test]
    fn domain_suffix_matching() {
        let s = DomainSet::from_names(["tracker.com", "Ads.Example.org.", "tracker.com", "x.y.z"]);
        assert_eq!(s.len(), 3);
        assert_eq!(s.match_suffix("tracker.com"), Some("tracker.com"));
        assert_eq!(s.match_suffix("a.b.tracker.com"), Some("tracker.com"));
        assert_eq!(s.match_suffix("nottracker.com"), None);
        assert_eq!(s.match_suffix("ads.example.org"), Some("ads.example.org"));
        assert_eq!(s.match_suffix("example.org"), None);
        assert_eq!(s.match_suffix("com"), None);
        assert!(s.contains_exact("x.y.z"));
    }

    #[test]
    fn ip_ranges() {
        let set = IpSet::from_ranges(
            [
                "10.0.0.0/8",
                "192.0.2.1",
                "192.0.2.2",
                "2001:db8::/32",
                "11.0.0.0/8",
            ]
            .iter()
            .map(|s| parse_cidr(s).unwrap()),
        );
        // 10/8 and 11/8 merge; 192.0.2.1 and .2 merge.
        assert_eq!(set.len(), 3);
        assert!(set.contains(v4(10, 200, 1, 1)));
        assert!(set.contains(v4(11, 255, 255, 255)));
        assert!(!set.contains(v4(12, 0, 0, 0)));
        assert!(set.contains(v4(192, 0, 2, 2)));
        assert!(!set.contains(v4(192, 0, 2, 3)));
        assert!(set.contains(v6("2001:db8:1::5")));
        assert!(set.contains(v6("::ffff:10.1.2.3")));
        assert!(!set.contains(v6("2001:db9::1")));
        assert!(parse_cidr("1.2.3.4/33").is_none());
        assert!(parse_cidr("0.0.0.0/0").is_some());
    }

    #[test]
    fn feed_formats() {
        let text = "\
# hosts
0.0.0.0 ads.example.com tracker.example.com
127.0.0.1 localhost
192.168.1.1 router.lan
! adblock
||metrics.example.net^
||cdn.example.net^$third-party
||example.org/path^
@@||allowed.example^
example.com##.banner
plain.example.io
*.wild.example
198.51.100.0/24 ; SBL123
203.0.113.7
2001:db8::/48
not_a_domain
";
        let f = parse_feed(text);
        for d in [
            "ads.example.com",
            "tracker.example.com",
            "metrics.example.net",
            "plain.example.io",
            "wild.example",
        ] {
            assert!(f.domains.contains_exact(d), "{d}");
        }
        assert_eq!(f.domains.len(), 5);
        assert!(f.ips.contains(v4(198, 51, 100, 9)));
        assert!(f.ips.contains(v4(203, 0, 113, 7)));
        assert!(f.ips.contains(v6("2001:db8::1")));
        assert_eq!(f.rejected, 6);
        let streamed = parse_feed_reader(std::io::Cursor::new(text.as_bytes())).unwrap();
        assert_eq!(streamed.domains.len(), f.domains.len());
        assert_eq!(streamed.ips.len(), f.ips.len());
        assert_eq!(streamed.rejected, f.rejected);
    }
}
