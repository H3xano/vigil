//! Threat-intelligence data structures and feed parsers.
//!
//! Blocklists can contain millions of entries, so both sets are built once
//! and then frozen into compact sorted arrays:
//! * [`DomainSet`] stores all names in one string arena plus a sorted offset
//!   table (≈ name bytes + 8 bytes per entry) and answers suffix queries
//!   ("is `a.b.tracker.com` covered by `tracker.com`?") with one binary search
//!   per label.
//! * [`IpSet`] stores merged, sorted IPv4/IPv6 ranges.
//! * [`Ja4Set`] stores JA4 TLS client fingerprints (fixed-size keys in a
//!   sorted array) with optional labels, for threat matching.

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
        // `.example.com` (a suffix-rule spelling) is the same as `example.com`.
        let s = raw.trim().trim_end_matches('.').trim_start_matches('.');
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

/// Length of a JA4 fingerprint: `a` (10) `_` `b` (12) `_` `c` (12).
pub const JA4_LEN: usize = 36;
/// Length of the `a_b` prefix of a JA4 fingerprint.
const JA4_AB_LEN: usize = 23;
const NO_LABEL: u32 = u32::MAX;
/// Labels longer than this are cut (at a character boundary).
const MAX_LABEL: usize = 80;

/// A validated JA4 feed entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ja4Pattern {
    /// A complete fingerprint (normalised).
    Exact([u8; JA4_LEN]),
    /// `a_b_*`: any `c` section (any extension / signature-algorithm set).
    AnyC([u8; JA4_AB_LEN]),
}

fn is_hex_lower(b: &[u8]) -> bool {
    b.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// Validates and normalises a JA4 TLS client fingerprint (FoxIO
/// specification): `a_b_c` where
/// * `a` is 10 characters: protocol (`t` TCP, `q` QUIC, `d` DTLS), TLS
///   version (`13`, `12`, `11`, `10`, `s3`, `s2`, `d1`, `d2`, `d3`, `00`),
///   SNI (`d` domain, `i` IP / none), two-digit cipher count, two-digit
///   extension count and the two ALPN characters;
/// * `b` and `c` are 12 lowercase hex digits (truncated SHA-256).
///
/// `a` (except the ALPN characters, which are case-sensitive) and the hashes
/// are lower-cased. With `a_b_*` the `c` section is a wildcard. Raw
/// (`ja4_r`) and original-order (`ja4_o`) forms are not accepted.
pub fn parse_ja4(s: &str) -> Option<Ja4Pattern> {
    let b = s.as_bytes();
    let wildcard = b.len() == JA4_AB_LEN + 2 && b.ends_with(b"_*");
    if !(b.len() == JA4_LEN || wildcard) || b[10] != b'_' || b[JA4_AB_LEN] != b'_' {
        return None;
    }
    let mut out = [0u8; JA4_LEN];
    let n = if wildcard { JA4_AB_LEN } else { JA4_LEN };
    out[..n].copy_from_slice(&b[..n]);
    // Everything but the ALPN characters (a[8..10]) is case-insensitive.
    out[..8].make_ascii_lowercase();
    out[11..n].make_ascii_lowercase();
    let a = &out[..10];
    let version_ok = matches!(
        &a[1..3],
        b"13" | b"12" | b"11" | b"10" | b"s3" | b"s2" | b"d1" | b"d2" | b"d3" | b"00"
    );
    let ok = matches!(a[0], b't' | b'q' | b'd')
        && version_ok
        && matches!(a[3], b'd' | b'i')
        && a[4..8].iter().all(u8::is_ascii_digit)
        && a[8..10].iter().all(u8::is_ascii_alphanumeric)
        && is_hex_lower(&out[11..JA4_AB_LEN])
        && (wildcard || is_hex_lower(&out[JA4_AB_LEN + 1..]));
    if !ok {
        return None;
    }
    Some(if wildcard {
        let mut ab = [0u8; JA4_AB_LEN];
        ab.copy_from_slice(&out[..JA4_AB_LEN]);
        Ja4Pattern::AnyC(ab)
    } else {
        Ja4Pattern::Exact(out)
    })
}

/// If `raw` is a JA4 feed line (`<ja4>[ separator label]`), returns the
/// pattern and the label. Separators: whitespace, `#`, `,`, `;`, `|`.
pub fn parse_ja4_line(raw: &str) -> Option<(Ja4Pattern, Option<&str>)> {
    let line = raw.trim();
    // Cheap pre-check: most lines of large domain feeds end here.
    if line.len() < JA4_AB_LEN + 2 || line.as_bytes()[10] != b'_' {
        return None;
    }
    let is_sep = |c: char| c.is_whitespace() || matches!(c, '#' | ',' | ';' | '|');
    let (token, rest) = match line.find(is_sep) {
        Some(i) => line.split_at(i),
        None => (line, ""),
    };
    let pattern = parse_ja4(token)?;
    let label = rest.trim_matches(|c: char| is_sep(c) || c == '"');
    let label = (!label.is_empty()).then(|| {
        let mut end = label.len().min(MAX_LABEL);
        while !label.is_char_boundary(end) {
            end -= 1;
        }
        label[..end].trim_end()
    });
    Some((pattern, label))
}

/// A JA4 feed hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ja4Hit<'a> {
    /// The listed entry: the fingerprint, or `a_b_*` for a wildcard entry.
    pub rule: &'a str,
    pub label: Option<&'a str>,
}

/// JA4 fingerprints with optional labels: exact entries and `a_b_*`
/// wildcard entries, each a sorted array of fixed-size keys (≈ 40 bytes per
/// entry plus the distinct labels).
#[derive(Default, Debug, Clone)]
pub struct Ja4Set {
    exact: Vec<([u8; JA4_LEN], u32)>,
    any_c: Vec<([u8; JA4_AB_LEN + 2], u32)>,
    labels: Vec<Box<str>>,
}

impl Ja4Set {
    pub fn len(&self) -> usize {
        self.exact.len() + self.any_c.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn hit<'a>(&'a self, key: &'a [u8], label: u32) -> Ja4Hit<'a> {
        Ja4Hit {
            // Keys are validated ASCII.
            rule: std::str::from_utf8(key).unwrap_or_default(),
            label: (label != NO_LABEL).then(|| &*self.labels[label as usize]),
        }
    }

    /// Looks up an observed fingerprint (as computed by the engine, i.e.
    /// already normalised). Exact entries win over wildcards.
    pub fn lookup(&self, ja4: &str) -> Option<Ja4Hit<'_>> {
        let b = ja4.as_bytes();
        if b.len() != JA4_LEN {
            return None;
        }
        if let Ok(i) = self.exact.binary_search_by(|(k, _)| k[..].cmp(b)) {
            let (k, l) = &self.exact[i];
            return Some(self.hit(k, *l));
        }
        let ab = &b[..JA4_AB_LEN];
        let i = self
            .any_c
            .binary_search_by(|(k, _)| k[..JA4_AB_LEN].cmp(ab))
            .ok()?;
        let (k, l) = &self.any_c[i];
        Some(self.hit(k, *l))
    }

    pub fn memory_bytes(&self) -> usize {
        self.exact.capacity() * std::mem::size_of::<([u8; JA4_LEN], u32)>()
            + self.any_c.capacity() * std::mem::size_of::<([u8; JA4_AB_LEN + 2], u32)>()
            + self.labels.iter().map(|l| l.len() + 16).sum::<usize>()
    }
}

/// Builds a [`Ja4Set`]; each distinct label is stored once.
#[derive(Default)]
pub struct Ja4SetBuilder {
    set: Ja4Set,
    label_ids: std::collections::HashMap<Box<str>, u32>,
}

impl Ja4SetBuilder {
    pub fn push(&mut self, pattern: Ja4Pattern, label: Option<&str>) {
        let l = match label {
            None => NO_LABEL,
            Some(l) => match self.label_ids.get(l) {
                Some(i) => *i,
                None => {
                    let i = self.set.labels.len() as u32;
                    self.set.labels.push(l.into());
                    self.label_ids.insert(l.into(), i);
                    i
                }
            },
        };
        match pattern {
            Ja4Pattern::Exact(k) => self.set.exact.push((k, l)),
            Ja4Pattern::AnyC(ab) => {
                let mut k = [0u8; JA4_AB_LEN + 2];
                k[..JA4_AB_LEN].copy_from_slice(&ab);
                k[JA4_AB_LEN..].copy_from_slice(b"_*");
                self.set.any_c.push((k, l));
            }
        }
    }

    pub fn build(self) -> Ja4Set {
        let mut s = self.set;
        // Stable sort + dedup keeps the first label seen for a fingerprint.
        s.exact.sort_by_key(|a| a.0);
        s.exact.dedup_by(|a, b| a.0 == b.0);
        s.exact.shrink_to_fit();
        s.any_c.sort_by_key(|a| a.0);
        s.any_c.dedup_by(|a, b| a.0 == b.0);
        s.any_c.shrink_to_fit();
        s.labels.shrink_to_fit();
        s
    }
}

/// A parsed feed: domains, IP ranges and JA4 fingerprints.
#[derive(Default, Debug, Clone)]
pub struct Feed {
    pub domains: DomainSet,
    pub ips: IpSet,
    pub ja4: Ja4Set,
    /// IP → AS table (feeds of kind [`FeedKind::Asn`] only).
    pub asn: crate::asn::AsnTable,
    /// Lines that could not be interpreted.
    pub rejected: usize,
}

impl Feed {
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty() && self.ips.is_empty() && self.ja4.is_empty() && self.asn.is_empty()
    }

    /// IP ranges of an IP feed, or ranges mapped to an AS in an ASN table.
    pub fn ip_range_count(&self) -> usize {
        self.ips.len() + self.asn.len()
    }

    pub fn memory_bytes(&self) -> usize {
        self.domains.memory_bytes() + self.ja4.memory_bytes() + self.asn.memory_bytes()
    }
}

/// What a feed may contain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FeedKind {
    /// Domains, IP ranges and JA4 fingerprints, recognised per line.
    #[default]
    Mixed,
    /// JA4 fingerprints only; any other non-comment line is rejected.
    Ja4,
    /// An IP → ASN table (iptoasn.com TSV, see [`crate::asn`]).
    Asn,
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
/// * JA4 fingerprints with an optional label:
///   `t13d190900_9dc949149365_97f8aa674fd9  Sliver` (see [`parse_ja4_line`])
///
/// Comments start with `#`, `!` or `;`.
pub fn parse_feed(text: &str) -> Feed {
    parse_feed_lines(text.lines())
}

/// Streams a feed from a reader line by line, so the file never has to be
/// held in memory in full. Invalid UTF-8 is replaced, not fatal.
pub fn parse_feed_reader<R: std::io::BufRead>(r: R) -> std::io::Result<Feed> {
    parse_feed_reader_kind(r, FeedKind::Mixed)
}

/// Like [`parse_feed_reader`], restricted to the entries of `kind`.
pub fn parse_feed_reader_kind<R: std::io::BufRead>(
    mut r: R,
    kind: FeedKind,
) -> std::io::Result<Feed> {
    if kind == FeedKind::Asn {
        let (asn, rejected) = crate::asn::parse_asn_reader(r)?;
        return Ok(Feed {
            asn,
            rejected,
            ..Default::default()
        });
    }
    let mut buf = Vec::with_capacity(256);
    let mut builder = FeedBuilder {
        kind,
        ..Default::default()
    };
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
    kind: FeedKind,
    domains: DomainSetBuilder,
    ranges: Vec<IpRange>,
    ja4: Ja4SetBuilder,
    rejected: usize,
}

impl FeedBuilder {
    fn finish(self) -> Feed {
        Feed {
            domains: self.domains.build(),
            ips: IpSet::from_ranges(self.ranges),
            ja4: self.ja4.build(),
            asn: Default::default(),
            rejected: self.rejected,
        }
    }

    fn line(&mut self, raw: &str) {
        if let Some((pattern, label)) = parse_ja4_line(raw) {
            self.ja4.push(pattern, label);
            return;
        }
        match self.kind {
            FeedKind::Mixed => {
                parse_line(raw, &mut self.domains, &mut self.ranges, &mut self.rejected)
            }
            // Handled by parse_feed_reader_kind; never reached.
            FeedKind::Ja4 | FeedKind::Asn => {
                let t = raw.trim();
                if !(t.is_empty() || t.starts_with(['#', '!', ';']) || t.starts_with("//")) {
                    self.rejected += 1;
                }
            }
        }
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
        // Standard header lines (`127.0.0.1 localhost`, `255.255.255.255
        // broadcasthost`, `::1 ip6-localhost`, `0.0.0.0 0.0.0.0`) are skipped.
        let names: Vec<&str> = rest.filter(|h| !is_hosts_boilerplate(h)).collect();
        if names.is_empty() {
            return;
        }
        if !is_sink_address(first) {
            *rejected += 1;
            return;
        }
        for h in names {
            if !(is_list_name(h) && domains.push(h)) {
                *rejected += 1;
            }
        }
        return;
    }
    if let Some(r) = parse_cidr(first) {
        ranges.push(r);
        return;
    }
    let name = first.strip_prefix("*.").unwrap_or(first);
    if !(is_list_name(name) && domains.push(name)) {
        *rejected += 1;
    }
}

/// Whether a blocklist entry can be a domain name: dotted, no wildcard,
/// not an IP literal. Single labels (`local`, `lan`) would block a whole
/// namespace by suffix match.
fn is_list_name(name: &str) -> bool {
    let core = name.trim_matches('.');
    core.contains('.') && !name.contains('*') && core.parse::<IpAddr>().is_err()
}

/// Names on the standard hosts-file header lines, never blocklist entries.
fn is_hosts_boilerplate(name: &str) -> bool {
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    is_sink_address(&n)
        || matches!(
            n.as_str(),
            "localhost" | "local" | "broadcasthost" | "localhost.localdomain" | "localdomain"
        )
        || n.starts_with("ip6-")
        || n.ends_with(".localdomain")
        || n.ends_with(".localhost")
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

    #[test]
    fn hosts_header_does_not_block_namespaces() {
        let text = "\
127.0.0.1 localhost
127.0.0.1 localhost.localdomain
127.0.0.1 local
255.255.255.255 broadcasthost
::1 localhost
::1 ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff02::1 ip6-allnodes
0.0.0.0 0.0.0.0
0.0.0.0 ads.example.com lan 192.0.2.1 .dot.example.org
";
        let f = parse_feed(text);
        assert_eq!(f.domains.len(), 2);
        assert!(f.domains.contains_exact("ads.example.com"));
        assert!(f.domains.contains_exact("dot.example.org"));
        assert_eq!(f.domains.match_suffix("printer.local"), None);
        assert_eq!(f.domains.match_suffix("box.lan"), None);
        // `lan` (single label) and `192.0.2.1` (IP literal) are rejected.
        assert_eq!(f.rejected, 2);
        assert!(f.ips.is_empty());
        // A leading dot is a suffix-rule spelling in plain lists too.
        let p = parse_feed(".lead.example\n.\n");
        assert!(p.domains.contains_exact("lead.example"));
        assert_eq!(
            p.domains.match_suffix("x.lead.example"),
            Some("lead.example")
        );
        assert_eq!(p.rejected, 1);
        let set = DomainSet::from_names([".from.example", "..", "UPPER.Example."]);
        assert!(set.contains_exact("from.example"));
        assert!(set.contains_exact("upper.example"));
        assert_eq!(set.len(), 2);
    }

    const SLIVER: &str = "t13d190900_9dc949149365_97f8aa674fd9";

    #[test]
    fn ja4_grammar() {
        assert!(matches!(parse_ja4(SLIVER), Some(Ja4Pattern::Exact(_))));
        for ok in [
            "q13d0312h3_55b375c5d22e_06cda9e17597",
            "t12i210700_76e208dd3e22_16bbda4055b2",
            "d13d1516h2_8daaf6152771_02713d6af862",
            "t00i000000_000000000000_000000000000",
            "ts3i0203c9_aaaaaaaaaaaa_bbbbbbbbbbbb",
        ] {
            assert!(parse_ja4(ok).is_some(), "{ok}");
        }
        // Upper case is normalised, except the ALPN characters.
        let Some(Ja4Pattern::Exact(k)) = parse_ja4("T13D1516H2_8DAAF6152771_02713D6AF862") else {
            panic!()
        };
        assert_eq!(&k[..], b"t13d1516H2_8daaf6152771_02713d6af862");
        assert_eq!(
            parse_ja4("t13d1516h2_8daaf6152771_*"),
            Some(Ja4Pattern::AnyC(*b"t13d1516h2_8daaf6152771"))
        );
        for bad in [
            "",
            "t13d190900_9dc949149365",
            "t13d190900_9dc949149365_97f8aa674fd",
            "t13d190900_9dc949149365_97f8aa674fd9x",
            "x13d190900_9dc949149365_97f8aa674fd9", // protocol
            "t14d190900_9dc949149365_97f8aa674fd9", // version
            "t13x190900_9dc949149365_97f8aa674fd9", // SNI flag
            "t13d1a0900_9dc949149365_97f8aa674fd9", // counts
            "t13d1909-0_9dc949149365_97f8aa674fd9", // ALPN
            "t13d190900_9dc94914936g_97f8aa674fd9", // hex
            "t13d190900-9dc949149365-97f8aa674fd9",
            "t13d190900_*_97f8aa674fd9",
            "*_9dc949149365_97f8aa674fd9",
            "t13d190900_9dc949149365_97f8aa*",
            "t13d190900_9dc949149365_97f8aa674fd9_extra",
            "t13d190900_002f,0035_0005,000a_0403", // ja4_r
            "t13d190900_9dc949149365_97f8aa674f€",
        ] {
            assert!(parse_ja4(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn ja4_lines_and_labels() {
        let line = format!("  {SLIVER}   Sliver agent  ");
        let (p, l) = parse_ja4_line(&line).unwrap();
        assert_eq!(p, parse_ja4(SLIVER).unwrap());
        assert_eq!(l, Some("Sliver agent"));
        for sep in ["#", " # ", ",", ";", "|", "\t", ",\""] {
            let line = format!("{SLIVER}{sep}Sliver\"");
            assert_eq!(parse_ja4_line(&line).unwrap().1, Some("Sliver"), "{line:?}");
        }
        assert_eq!(parse_ja4_line(SLIVER).unwrap().1, None);
        assert_eq!(parse_ja4_line(&format!("{SLIVER} #")).unwrap().1, None);
        let long = format!("{SLIVER} {}", "é".repeat(100));
        assert!(parse_ja4_line(&long).unwrap().1.unwrap().len() <= MAX_LABEL);
        assert!(parse_ja4_line(&format!("# {SLIVER}")).is_none());
        assert!(parse_ja4_line("example.com").is_none());
        assert!(parse_ja4_line("0.0.0.0 tracker.example.com").is_none());
        assert!(parse_ja4_line("0.0.0.0 tracker-with-long-name.example.com").is_none());
    }

    #[test]
    fn ja4_feed_parsing_and_matching() {
        let text = format!(
            "# JA4 feed\n{SLIVER}  Sliver\n{up}\n\
             t12i210700_76e208dd3e22_16bbda4055b2 # Cobalt Strike\n\
             {SLIVER} duplicate keeps the first label\n\
             q13d0312h3_55b375c5d22e_*  QUIC wildcard\n\
             evil.example\n203.0.113.0/24\nnot a fingerprint\n\n! comment\n",
            up = SLIVER.to_uppercase()
        );
        let mixed = parse_feed(&text);
        assert_eq!(mixed.ja4.len(), 3);
        assert_eq!(mixed.domains.len(), 1);
        assert_eq!(mixed.ips.len(), 1);
        assert_eq!(mixed.rejected, 1);
        let strict =
            parse_feed_reader_kind(std::io::Cursor::new(text.as_bytes()), FeedKind::Ja4).unwrap();
        assert_eq!(strict.ja4.len(), 3);
        assert!(strict.domains.is_empty() && strict.ips.is_empty());
        assert_eq!(strict.rejected, 3);
        let set = &strict.ja4;
        let hit = set.lookup(SLIVER).unwrap();
        assert_eq!(hit.rule, SLIVER);
        assert_eq!(hit.label, Some("Sliver"));
        let cs = set.lookup("t12i210700_76e208dd3e22_16bbda4055b2").unwrap();
        assert_eq!(cs.label, Some("Cobalt Strike"));
        let q = set.lookup("q13d0312h3_55b375c5d22e_0123456789ab").unwrap();
        assert_eq!(q.rule, "q13d0312h3_55b375c5d22e_*");
        assert_eq!(q.label, Some("QUIC wildcard"));
        assert!(set.lookup("t13d0312h3_55b375c5d22e_0123456789ab").is_none());
        assert!(set.lookup("t13d190900_9dc949149365_97f8aa674fd8").is_none());
        assert!(set.lookup("short").is_none());
        assert!(set.memory_bytes() > 0);
    }
}
