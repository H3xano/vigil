//! Offline IP → autonomous system (ASN) table.
//!
//! Built by streaming an iptoasn.com style TSV file
//! (`range_start<TAB>range_end<TAB>AS_number<TAB>country_code<TAB>AS_description`,
//! IPv4 and IPv6 rows in one file) from disk. The table is frozen into
//! compact sorted arrays:
//! * IPv4: the start address of every range (`u32`) and the index of its AS
//!   (`u32`), 8 bytes per range;
//! * IPv6: the same with `u128` starts, 20 bytes per range;
//! * the distinct ASes (number, country, name offset) and one string arena
//!   for their names.
//!
//! Each range extends to the next start, so the arrays hold boundaries, not
//! (start, end) pairs: gaps and "not routed" rows (AS 0) become boundaries
//! with no AS, and adjacent ranges of the same AS are merged. A lookup is
//! one binary search. With the full iptoasn.com file (≈ 720 k rows) the
//! table takes about 9 MB.

use serde::Serialize;
use std::collections::HashMap;
use std::io::BufRead;
use std::net::IpAddr;

/// Index value for "no AS" (unrouted space, gaps between ranges).
const NONE: u32 = u32::MAX;
/// AS names longer than this are cut (at a character boundary).
pub const MAX_NAME: usize = 120;

/// The AS of an address, as reported in `flow` events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AsnInfo {
    pub number: u32,
    pub name: String,
    /// ISO 3166 country code of the AS registration, if known.
    pub country: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct AsEntry {
    number: u32,
    name_start: u32,
    name_len: u16,
    /// ASCII upper-case country code; `[0, 0]` when unknown.
    country: [u8; 2],
}

/// Boundaries of one address family: `starts[i]..starts[i+1]` belongs to
/// `idx[i]` (an index into the AS entries, or [`NONE`]).
#[derive(Debug, Clone, Default)]
struct Ranges<T> {
    starts: Vec<T>,
    idx: Vec<u32>,
}

impl<T: Ord + Copy> Ranges<T> {
    fn find(&self, x: T) -> Option<u32> {
        let i = self.starts.partition_point(|&s| s <= x);
        let idx = *self.idx.get(i.checked_sub(1)?)?;
        (idx != NONE).then_some(idx)
    }

    fn push_boundary(&mut self, start: T, idx: u32) {
        if self.idx.last() == Some(&idx) {
            return;
        }
        // Several rows starting at the same address: the last one wins
        // (only when an earlier row was empty after clipping).
        if self.starts.last() == Some(&start) {
            self.starts.pop();
            self.idx.pop();
            if self.idx.last() == Some(&idx) {
                return;
            }
        }
        self.starts.push(start);
        self.idx.push(idx);
    }

    /// Number of ranges that belong to an AS.
    fn routed(&self) -> usize {
        self.idx.iter().filter(|&&i| i != NONE).count()
    }

    fn memory_bytes(&self) -> usize {
        self.starts.capacity() * std::mem::size_of::<T>() + self.idx.capacity() * 4
    }
}

trait Addr: Ord + Copy + Default {
    const MAX: Self;
    fn succ(self) -> Option<Self>;
    fn pred(self) -> Option<Self>;
}

impl Addr for u32 {
    const MAX: Self = u32::MAX;
    fn succ(self) -> Option<Self> {
        self.checked_add(1)
    }
    fn pred(self) -> Option<Self> {
        self.checked_sub(1)
    }
}

impl Addr for u128 {
    const MAX: Self = u128::MAX;
    fn succ(self) -> Option<Self> {
        self.checked_add(1)
    }
    fn pred(self) -> Option<Self> {
        self.checked_sub(1)
    }
}

/// Streams rows into [`Ranges`]. Sorted input (the normal case) goes
/// straight into the final arrays; rows that arrive out of order are kept
/// aside and merged by a sort at the end. Overlaps are clipped: the range
/// that starts first keeps the overlapping addresses.
#[derive(Debug, Default)]
struct RangeBuilder<T> {
    out: Ranges<T>,
    /// First address not covered yet (None once the top address is covered).
    next: Option<T>,
    started: bool,
    last_row_start: T,
    spill: Vec<(T, T, u32)>,
}

impl<T: Addr> RangeBuilder<T> {
    fn push(&mut self, start: T, end: T, idx: u32) {
        if self.started && (start < self.last_row_start || !self.spill.is_empty()) {
            self.spill.push((start, end, idx));
            return;
        }
        self.last_row_start = start;
        self.append(start, end, idx);
    }

    fn append(&mut self, start: T, end: T, idx: u32) {
        let mut start = start;
        if self.started {
            let Some(next) = self.next else {
                return; // everything up to the top address is covered
            };
            if end < next {
                return;
            }
            if start > next {
                self.out.push_boundary(next, NONE);
            }
            start = start.max(next);
        }
        self.out.push_boundary(start, idx);
        self.next = end.succ();
        self.started = true;
    }

    fn build(mut self) -> Ranges<T> {
        if !self.spill.is_empty() {
            // Rare: re-run the whole family sorted by start (stable, so
            // equal starts keep file order).
            let mut rows = std::mem::take(&mut self.spill);
            let out = std::mem::take(&mut self.out);
            // The last boundary (no trailing NONE yet) ends where coverage ends.
            let last_end = match self.next {
                Some(n) => n.pred().unwrap_or_default(),
                None => T::MAX,
            };
            for (i, &s) in out.starts.iter().enumerate() {
                if out.idx[i] == NONE {
                    continue;
                }
                let e = match out.starts.get(i + 1) {
                    Some(n) => n.pred().unwrap_or_default(),
                    None => last_end,
                };
                rows.push((s, e, out.idx[i]));
            }
            rows.sort_by_key(|r| r.0);
            let mut b = RangeBuilder::<T>::default();
            for (s, e, i) in rows {
                b.append(s, e, i);
            }
            return b.build();
        }
        if let Some(next) = self.next {
            if self.started {
                self.out.push_boundary(next, NONE);
            }
        }
        self.out.starts.shrink_to_fit();
        self.out.idx.shrink_to_fit();
        self.out
    }
}

/// IP ranges mapped to autonomous systems. See the module docs.
#[derive(Debug, Clone, Default)]
pub struct AsnTable {
    v4: Ranges<u32>,
    v6: Ranges<u128>,
    entries: Vec<AsEntry>,
    names: String,
}

impl AsnTable {
    /// The AS announcing `ip`, if the table knows one. IPv4-mapped IPv6
    /// addresses are looked up as IPv4 (NAT64 is the caller's business,
    /// see [`crate::policy::Policy::asn_lookup`]).
    pub fn lookup(&self, ip: IpAddr) -> Option<AsnInfo> {
        let idx = match ip {
            IpAddr::V4(a) => self.v4.find(u32::from(a)),
            IpAddr::V6(a) => match a.to_ipv4_mapped() {
                Some(v4) => self.v4.find(u32::from(v4)),
                None => self.v6.find(u128::from(a)),
            },
        }?;
        let e = self.entries.get(idx as usize)?;
        let s = e.name_start as usize;
        Some(AsnInfo {
            number: e.number,
            name: self.names[s..s + e.name_len as usize].to_string(),
            country: (e.country != [0, 0])
                .then(|| String::from_utf8_lossy(&e.country).into_owned()),
        })
    }

    /// Ranges that belong to an AS (after merging adjacent ranges of one AS).
    pub fn len(&self) -> usize {
        self.v4.routed() + self.v6.routed()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Distinct autonomous systems.
    pub fn as_count(&self) -> usize {
        self.entries.len()
    }

    pub fn memory_bytes(&self) -> usize {
        self.v4.memory_bytes()
            + self.v6.memory_bytes()
            + self.entries.capacity() * std::mem::size_of::<AsEntry>()
            + self.names.capacity()
    }
}

/// Builds an [`AsnTable`] row by row; each AS is stored once (the first
/// name and country seen for a number win).
#[derive(Debug, Default)]
pub struct AsnTableBuilder {
    v4: RangeBuilder<u32>,
    v6: RangeBuilder<u128>,
    entries: Vec<AsEntry>,
    names: String,
    by_number: HashMap<u32, u32>,
    /// Lines that could not be interpreted.
    pub rejected: usize,
}

impl AsnTableBuilder {
    /// Adds one line of the TSV file. Comments (`#`) and blank lines are
    /// skipped; malformed rows are counted in [`Self::rejected`].
    pub fn line(&mut self, raw: &str) {
        let line = raw.trim_end_matches(['\n', '\r']);
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            return;
        }
        if !self.row(line) {
            self.rejected += 1;
        }
    }

    fn row(&mut self, line: &str) -> bool {
        let mut f = line.split('\t');
        let (Some(start), Some(end), Some(asn)) = (f.next(), f.next(), f.next()) else {
            return false;
        };
        let country = f.next().unwrap_or("").trim();
        let name = f.next().unwrap_or("").trim();
        let Ok(number) = asn
            .trim()
            .trim_start_matches(['A', 'S', 'a', 's'])
            .parse::<u32>()
        else {
            return false;
        };
        let (Ok(start), Ok(end)) = (start.trim().parse::<IpAddr>(), end.trim().parse::<IpAddr>())
        else {
            return false;
        };
        let idx = if number == 0 {
            NONE
        } else {
            self.entry(number, country, name)
        };
        match (start, end) {
            (IpAddr::V4(s), IpAddr::V4(e)) if s <= e => {
                self.v4.push(u32::from(s), u32::from(e), idx);
            }
            (IpAddr::V6(s), IpAddr::V6(e)) if s <= e => {
                self.v6.push(u128::from(s), u128::from(e), idx);
            }
            _ => return false,
        }
        true
    }

    fn entry(&mut self, number: u32, country: &str, name: &str) -> u32 {
        if let Some(&i) = self.by_number.get(&number) {
            return i;
        }
        let mut end = name.len().min(MAX_NAME);
        while !name.is_char_boundary(end) {
            end -= 1;
        }
        let name = &name[..end];
        let cc = country.as_bytes();
        let country = if cc.len() == 2 && cc.iter().all(u8::is_ascii_alphabetic) {
            [cc[0].to_ascii_uppercase(), cc[1].to_ascii_uppercase()]
        } else {
            [0, 0] // "None", "ZZ"-style placeholders longer than 2, empty
        };
        let i = self.entries.len() as u32;
        self.entries.push(AsEntry {
            number,
            name_start: self.names.len() as u32,
            name_len: name.len() as u16,
            country,
        });
        self.names.push_str(name);
        self.by_number.insert(number, i);
        i
    }

    pub fn build(self) -> AsnTable {
        let mut entries = self.entries;
        let mut names = self.names;
        entries.shrink_to_fit();
        names.shrink_to_fit();
        AsnTable {
            v4: self.v4.build(),
            v6: self.v6.build(),
            entries,
            names,
        }
    }
}

/// Streams an ASN file from a reader. Returns the table and the number of
/// rejected lines. Invalid UTF-8 is replaced, not fatal.
pub fn parse_asn_reader<R: BufRead>(mut r: R) -> std::io::Result<(AsnTable, usize)> {
    let mut b = AsnTableBuilder::default();
    let mut buf = Vec::with_capacity(256);
    loop {
        buf.clear();
        if r.read_until(b'\n', &mut buf)? == 0 {
            break;
        }
        b.line(&String::from_utf8_lossy(&buf));
    }
    let rejected = b.rejected;
    Ok((b.build(), rejected))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intel::{v4, v6};

    const SAMPLE: &str = "\
1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET
1.0.1.0\t1.0.3.255\t0\tNone\tNot routed
1.0.4.0\t1.0.7.255\t38803\tAU\tGTELECOM-AS-AP Gtelecom Pty Ltd
1.0.8.0\t1.0.8.255\t38803\tAU\tGTELECOM-AS-AP Gtelecom Pty Ltd
1.1.1.0\t1.1.1.255\t13335\tUS\tCLOUDFLARENET
10.0.0.0\t10.255.255.255\t0\tNone\tNot routed
# comment

2606:4700::\t2606:4700:ffff:ffff:ffff:ffff:ffff:ffff\t13335\tUS\tCLOUDFLARENET
2a00:1450::\t2a00:1450:ffff:ffff:ffff:ffff:ffff:ffff\t15169\tUS\tGOOGLE
";

    fn table(text: &str) -> (AsnTable, usize) {
        parse_asn_reader(std::io::Cursor::new(text.as_bytes())).unwrap()
    }

    #[test]
    fn lookup_with_edges() {
        let (t, rejected) = table(SAMPLE);
        assert_eq!(rejected, 0);
        assert_eq!(t.as_count(), 3);
        let cf = t.lookup(v4(1, 0, 0, 0)).unwrap();
        assert_eq!(
            cf,
            AsnInfo {
                number: 13335,
                name: "CLOUDFLARENET".into(),
                country: Some("US".into())
            }
        );
        assert_eq!(t.lookup(v4(1, 0, 0, 255)).unwrap().number, 13335);
        assert_eq!(t.lookup(v4(1, 0, 1, 0)), None); // not routed
        assert_eq!(t.lookup(v4(1, 0, 3, 255)), None);
        assert_eq!(t.lookup(v4(1, 0, 4, 0)).unwrap().number, 38803);
        // Adjacent ranges of one AS are merged into one boundary.
        assert_eq!(t.lookup(v4(1, 0, 8, 255)).unwrap().number, 38803);
        assert_eq!(t.v4.starts.len(), 6); // 1.0.0.0 1.0.1.0 1.0.4.0 1.0.9.0 1.1.1.0 1.1.2.0
        assert_eq!(t.lookup(v4(1, 0, 9, 0)), None); // gap
        assert_eq!(t.lookup(v4(1, 1, 0, 255)), None);
        assert_eq!(t.lookup(v4(1, 1, 1, 1)).unwrap().number, 13335);
        assert_eq!(t.lookup(v4(1, 1, 2, 0)), None);
        assert_eq!(t.lookup(v4(0, 0, 0, 0)), None); // below the first range
        assert_eq!(t.lookup(v4(10, 1, 2, 3)), None);
        assert_eq!(t.lookup(v4(255, 255, 255, 255)), None);
        assert_eq!(t.lookup(v6("::ffff:1.1.1.1")).unwrap().number, 13335);
        let g = t.lookup(v6("2a00:1450:4001:80b::200e")).unwrap();
        assert_eq!((g.number, g.name.as_str()), (15169, "GOOGLE"));
        assert_eq!(t.lookup(v6("2606:4700::6810:85e5")).unwrap().number, 13335);
        assert_eq!(t.lookup(v6("2606:4701::1")), None);
        assert_eq!(t.lookup(v6("::1")), None);
        assert_eq!(t.lookup(v6("ffff::1")), None);
        assert_eq!(t.len(), 5);
    }

    #[test]
    fn malformed_lines_are_counted() {
        let text = "\
1.2.3.0\t1.2.3.255\t64500\tDE\tEXAMPLE
1.2.4.0\t1.2.4.255
1.2.5.0\tnot-an-ip\t64501\tDE\tX
1.2.6.0\t1.2.6.255\tASX\tDE\tX
1.2.8.0\t1.2.7.0\t64502\tDE\tbackwards
1.2.9.0\t2001:db8::\t64503\tDE\tmixed families
<html>captive portal</html>
1.2.10.0\t1.2.10.255\tAS64504\tzz\tprefixed number, lower-case country
1.2.11.0\t1.2.11.255\t64505\t\t
";
        let (t, rejected) = table(text);
        assert_eq!(rejected, 6);
        assert_eq!(t.lookup(v4(1, 2, 3, 4)).unwrap().number, 64500);
        let p = t.lookup(v4(1, 2, 10, 1)).unwrap();
        assert_eq!((p.number, p.country.as_deref()), (64504, Some("ZZ")));
        let bare = t.lookup(v4(1, 2, 11, 1)).unwrap();
        assert_eq!((bare.name.as_str(), bare.country), ("", None));
        assert_eq!(t.lookup(v4(1, 2, 8, 0)), None);
    }

    #[test]
    fn unsorted_and_overlapping_rows() {
        let text = "\
9.0.0.0\t9.255.255.255\t3\t\tC
1.0.0.0\t1.255.255.255\t1\t\tA
1.128.0.0\t2.0.0.255\t2\t\tB
255.255.255.0\t255.255.255.255\t4\t\tTop
";
        let (t, _) = table(text);
        assert_eq!(t.lookup(v4(1, 200, 0, 0)).unwrap().number, 1); // first start wins
        assert_eq!(t.lookup(v4(2, 0, 0, 1)).unwrap().number, 2); // clipped remainder
        assert_eq!(t.lookup(v4(2, 0, 1, 0)), None);
        assert_eq!(t.lookup(v4(9, 1, 1, 1)).unwrap().number, 3);
        assert_eq!(t.lookup(v4(10, 0, 0, 0)), None);
        assert_eq!(t.lookup(v4(255, 255, 255, 255)).unwrap().number, 4);
        // Sorted input with a range reaching the top address.
        let (t, _) = table("255.0.0.0\t255.255.255.255\t7\t\tTop\n");
        assert_eq!(t.lookup(v4(255, 255, 255, 255)).unwrap().number, 7);
        assert_eq!(t.lookup(v4(254, 255, 255, 255)), None);
    }

    #[test]
    fn duplicate_numbers_share_one_entry_and_names_are_capped() {
        let long = "N".repeat(300);
        let text =
            format!("1.0.0.0\t1.0.0.255\t5\tUS\t{long}\n2.0.0.0\t2.0.0.255\t5\tDE\tOther name\n");
        let (t, _) = table(&text);
        assert_eq!(t.as_count(), 1);
        let a = t.lookup(v4(2, 0, 0, 1)).unwrap();
        assert_eq!(a.name.len(), MAX_NAME);
        assert_eq!(a.country.as_deref(), Some("US"));
    }

    #[test]
    fn empty_input() {
        let (t, rejected) = table("# nothing\n\n");
        assert!(t.is_empty());
        assert_eq!(rejected, 0);
        assert_eq!(t.lookup(v4(1, 1, 1, 1)), None);
        assert_eq!(t.lookup(v6("2001:db8::1")), None);
    }

    /// Memory of a table shaped like the real iptoasn.com file: ≈ 540 k
    /// IPv4 and 180 k IPv6 rows over ≈ 87 k ASes (names ≈ 20 bytes).
    #[test]
    fn memory_for_a_full_sized_table() {
        let mut b = AsnTableBuilder::default();
        for i in 0..540_000u32 {
            let s = (i + 1) << 12; // /20 slots
            let idx = b_entry(&mut b, 1 + (u64::from(i) * 7919 % 87_000) as u32);
            b.v4.push(s, s + 0xfff, idx);
        }
        for i in 0..180_000u128 {
            let s = (0x2000u128 << 112) | ((i + 1) << 80);
            let asn = 1 + (i * 104_729 % 87_000) as u32;
            let idx = b_entry(&mut b, asn);
            b.v6.push(s, s + (1u128 << 80) - 1, idx);
        }
        let t = b.build();
        assert_eq!(t.as_count(), 87_000);
        let mb = t.memory_bytes() as f64 / 1e6;
        assert!(mb < 15.0, "{mb} MB");
        assert!(t.lookup(v4(0, 0, 16, 1)).is_some());
    }

    fn b_entry(b: &mut AsnTableBuilder, asn: u32) -> u32 {
        b.entry(asn, "US", &format!("AS-NAME-{asn:08}-EXAMPLE"))
    }
}
