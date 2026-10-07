//! A byte ring of variable-length packet records, oldest overwritten first.
//!
//! Each record is a 16-byte header (timestamp in µs, original length,
//! captured length, direction) followed by the captured bytes, stored
//! contiguously modulo the buffer size (a record may wrap around the end).
//! Memory is exactly the buffer: no per-packet allocation and no separate
//! index.

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// Bytes of a record header.
pub(crate) const HDR: usize = 16;

/// Which way a packet crossed the TUN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Dir {
    /// Sent by an app (read from the TUN by vigil).
    FromApp = 1,
    /// Written to the TUN by vigil (to an app).
    ToApp = 2,
}

impl Dir {
    fn from_u8(b: u8) -> Dir {
        if b == Dir::ToApp as u8 {
            Dir::ToApp
        } else {
            Dir::FromApp
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecordHeader {
    pub ts_us: u64,
    pub orig_len: u32,
    pub cap_len: u16,
    pub dir: Dir,
}

impl RecordHeader {
    fn encode(&self) -> [u8; HDR] {
        let mut h = [0u8; HDR];
        h[0..8].copy_from_slice(&self.ts_us.to_le_bytes());
        h[8..12].copy_from_slice(&self.orig_len.to_le_bytes());
        h[12..14].copy_from_slice(&self.cap_len.to_le_bytes());
        h[14] = self.dir as u8;
        h
    }

    fn decode(h: &[u8; HDR]) -> Self {
        RecordHeader {
            ts_us: u64::from_le_bytes(h[0..8].try_into().unwrap()),
            orig_len: u32::from_le_bytes(h[8..12].try_into().unwrap()),
            cap_len: u16::from_le_bytes(h[12..14].try_into().unwrap()),
            dir: Dir::from_u8(h[14]),
        }
    }
}

/// Source of [`Ring::id`].
static NEXT_RING_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) struct Ring {
    /// Unique per ring (a resized ring gets a new one): positions read
    /// from one ring are only meaningful for that ring.
    id: u64,
    buf: Vec<u8>,
    /// Absolute byte positions (never wrap in practice): the oldest record
    /// starts at `head`, the next one is written at `tail`.
    head: u64,
    tail: u64,
    records: usize,
    /// Records overwritten to make room since the ring was created.
    evicted: u64,
    /// Largest captured length ever recorded (the snap length declared on
    /// export must cover every record, also ones taken before the snap
    /// length was lowered).
    max_cap_len: u16,
}

impl Ring {
    /// A ring of `capacity` bytes. The memory is zero-initialised by the
    /// allocator (fresh pages for large sizes), so it is only committed as
    /// packets fill it.
    pub fn new(capacity: usize) -> Self {
        Ring {
            id: NEXT_RING_ID.fetch_add(1, Relaxed),
            buf: vec![0u8; capacity.max(HDR + 1)],
            head: 0,
            tail: 0,
            records: 0,
            evicted: 0,
            max_cap_len: 0,
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    /// Absolute position of the oldest record (records before it are gone).
    pub fn head(&self) -> u64 {
        self.head
    }

    /// Absolute position after the newest record.
    pub fn tail(&self) -> u64 {
        self.tail
    }

    pub fn max_cap_len(&self) -> u16 {
        self.max_cap_len
    }

    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    pub fn records(&self) -> usize {
        self.records
    }

    /// Bytes in use (headers included).
    pub fn used(&self) -> usize {
        (self.tail - self.head) as usize
    }

    pub fn evicted(&self) -> u64 {
        self.evicted
    }

    fn write_at(&mut self, pos: u64, data: &[u8]) {
        let cap = self.buf.len();
        let start = (pos % cap as u64) as usize;
        let first = data.len().min(cap - start);
        self.buf[start..start + first].copy_from_slice(&data[..first]);
        self.buf[..data.len() - first].copy_from_slice(&data[first..]);
    }

    fn read_at(&self, pos: u64, out: &mut [u8]) {
        let cap = self.buf.len();
        let start = (pos % cap as u64) as usize;
        let first = out.len().min(cap - start);
        out[..first].copy_from_slice(&self.buf[start..start + first]);
        let n = out.len();
        out[first..].copy_from_slice(&self.buf[..n - first]);
    }

    fn header_at(&self, pos: u64) -> RecordHeader {
        let mut h = [0u8; HDR];
        self.read_at(pos, &mut h);
        RecordHeader::decode(&h)
    }

    /// Timestamp of the oldest record.
    pub fn oldest_ts(&self) -> Option<u64> {
        (self.records > 0).then(|| self.header_at(self.head).ts_us)
    }

    fn pop(&mut self) {
        let h = self.header_at(self.head);
        self.head += (HDR + h.cap_len as usize) as u64;
        self.records -= 1;
        self.evicted += 1;
    }

    /// Appends a record, overwriting the oldest ones as needed. Returns how
    /// many were overwritten, or None if the record can never fit.
    pub fn push(&mut self, h: RecordHeader, data: &[u8]) -> Option<u64> {
        debug_assert_eq!(h.cap_len as usize, data.len());
        let need = HDR + data.len();
        if need > self.buf.len() {
            return None;
        }
        let before = self.evicted;
        while self.used() + need > self.buf.len() {
            self.pop();
        }
        let tail = self.tail;
        self.write_at(tail, &h.encode());
        self.write_at(tail + HDR as u64, data);
        self.tail += need as u64;
        self.records += 1;
        self.max_cap_len = self.max_cap_len.max(h.cap_len);
        Some(self.evicted - before)
    }

    /// Copies whole records from `from` (a record boundary at or after
    /// [`Self::head`]) up to `end` (at most [`Self::tail`]) into `out`
    /// (cleared first), stopping before `max_bytes` would be exceeded but
    /// always taking at least one record. Returns the position after the
    /// last record copied. Parse `out` with [`records`].
    pub fn read_records(&self, from: u64, end: u64, max_bytes: usize, out: &mut Vec<u8>) -> u64 {
        debug_assert!(from >= self.head && end <= self.tail);
        let end = end.min(self.tail);
        let mut pos = from.max(self.head);
        let start = pos;
        while pos < end {
            let len = (HDR + self.header_at(pos).cap_len as usize) as u64;
            if pos > start && pos + len - start > max_bytes as u64 {
                break;
            }
            pos += len;
        }
        out.clear();
        out.resize((pos - start) as usize, 0);
        self.read_at(start, out);
        pos
    }

    /// Turns the ring into one of `capacity` bytes holding its newest
    /// records that fit (the others are counted in the new ring's
    /// `evicted`). Works in place when shrinking, so the old and the new
    /// buffer are not both held in full; a larger ring is a fresh
    /// allocation (committed only as it fills) that receives the records.
    pub fn resized(mut self, capacity: usize) -> Ring {
        let capacity = capacity.max(HDR + 1);
        let mut keep_from = self.head;
        let mut dropped = 0u64;
        while self.tail - keep_from > capacity as u64 {
            keep_from += (HDR + self.header_at(keep_from).cap_len as usize) as u64;
            dropped += 1;
        }
        let kept = (self.tail - keep_from) as usize;
        let buf = if capacity <= self.buf.len() {
            // Rotate the kept records to the front, then cut the buffer.
            let cap = self.buf.len();
            self.buf.rotate_left((keep_from % cap as u64) as usize);
            self.buf.truncate(capacity);
            self.buf.shrink_to_fit();
            std::mem::take(&mut self.buf)
        } else {
            let mut buf = vec![0u8; capacity];
            self.read_at(keep_from, &mut buf[..kept]);
            buf
        };
        Ring {
            id: NEXT_RING_ID.fetch_add(1, Relaxed),
            buf,
            head: 0,
            tail: kept as u64,
            records: self.records - dropped as usize,
            evicted: dropped,
            max_cap_len: self.max_cap_len,
        }
    }

    /// Visits every record, oldest first.
    pub fn for_each(&self, mut f: impl FnMut(RecordHeader, &[u8])) {
        let mut pos = self.head;
        let mut data = Vec::new();
        while pos < self.tail {
            let h = self.header_at(pos);
            data.resize(h.cap_len as usize, 0);
            self.read_at(pos + HDR as u64, &mut data);
            f(h, &data);
            pos += (HDR + h.cap_len as usize) as u64;
        }
    }
}

/// Iterates the records copied out by [`Ring::read_records`].
pub(crate) fn records(snapshot: &[u8]) -> impl Iterator<Item = (RecordHeader, &[u8])> {
    let mut pos = 0usize;
    std::iter::from_fn(move || {
        let h: &[u8; HDR] = snapshot.get(pos..pos + HDR)?.try_into().ok()?;
        let h = RecordHeader::decode(h);
        let start = pos + HDR;
        let data = snapshot.get(start..start + h.cap_len as usize)?;
        pos = start + h.cap_len as usize;
        Some((h, data))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(ts: u64, len: usize) -> RecordHeader {
        RecordHeader {
            ts_us: ts,
            orig_len: len as u32,
            cap_len: len as u16,
            dir: if ts % 2 == 0 {
                Dir::FromApp
            } else {
                Dir::ToApp
            },
        }
    }

    fn collect(r: &Ring) -> Vec<(u64, Vec<u8>)> {
        let mut out = Vec::new();
        r.for_each(|h, d| out.push((h.ts_us, d.to_vec())));
        // Copied out in small chunks, as the exporter does.
        let mut via_chunks = Vec::new();
        let (mut pos, mut chunk) = (r.head(), Vec::new());
        while pos < r.tail() {
            pos = r.read_records(pos, r.tail(), 40, &mut chunk);
            assert!(!chunk.is_empty());
            via_chunks.extend(records(&chunk).map(|(h, d)| (h.ts_us, d.to_vec())));
        }
        assert_eq!(out, via_chunks);
        out
    }

    #[test]
    fn evicts_oldest_and_wraps() {
        // 100 bytes: three records of 16 + 14 = 30 bytes fit, the fourth
        // evicts the first and wraps around the end.
        let mut r = Ring::new(100);
        for ts in 1..=3u64 {
            assert_eq!(r.push(hdr(ts, 14), &[ts as u8; 14]), Some(0));
        }
        assert_eq!((r.records(), r.used(), r.oldest_ts()), (3, 90, Some(1)));
        assert_eq!(r.push(hdr(4, 14), &[4; 14]), Some(1));
        assert_eq!((r.records(), r.evicted(), r.oldest_ts()), (3, 1, Some(2)));
        let got = collect(&r);
        assert_eq!(
            got.iter().map(|(t, _)| *t).collect::<Vec<_>>(),
            vec![2, 3, 4]
        );
        assert!(got.iter().all(|(t, d)| d.iter().all(|b| *b == *t as u8)));
        // A large record evicts several at once; the header itself wraps.
        assert_eq!(r.push(hdr(5, 50), &[5; 50]), Some(2));
        assert_eq!(
            collect(&r)
                .iter()
                .map(|(t, d)| (*t, d.len()))
                .collect::<Vec<_>>(),
            vec![(4, 14), (5, 50)]
        );
        // Many rounds: the contents stay consistent.
        for ts in 6..500u64 {
            let len = (ts % 37) as usize;
            r.push(hdr(ts, len), &vec![ts as u8; len]).unwrap();
            let got = collect(&r);
            assert_eq!(got.last().unwrap().0, ts);
            assert!(r.used() <= r.capacity());
            for (t, d) in got.into_iter().filter(|(t, _)| *t >= 6) {
                assert_eq!(d.len(), (t % 37) as usize);
                assert!(d.iter().all(|b| *b == t as u8));
            }
        }
        // Too large for the ring at all.
        assert_eq!(r.push(hdr(1000, 85), &[0; 85]), None);
    }

    #[test]
    fn empty_ring() {
        let r = Ring::new(1024);
        assert_eq!(r.oldest_ts(), None);
        assert_eq!(collect(&r).len(), 0);
        let mut chunk = vec![1u8];
        assert_eq!(r.read_records(0, 0, 100, &mut chunk), 0);
        assert!(chunk.is_empty());
    }

    #[test]
    fn read_records_respects_the_budget_and_the_end() {
        let mut r = Ring::new(1000);
        for ts in 1..=5u64 {
            r.push(hdr(ts, 14), &[ts as u8; 14]).unwrap();
        }
        let mut chunk = Vec::new();
        // 30-byte records: a 65-byte budget takes two.
        let next = r.read_records(r.head(), r.tail(), 65, &mut chunk);
        assert_eq!((next, chunk.len()), (60, 60));
        // A budget smaller than one record still takes one.
        assert_eq!(r.read_records(next, r.tail(), 1, &mut chunk), 90);
        // The end bounds the copy.
        assert_eq!(r.read_records(90, 120, 1000, &mut chunk), 120);
        assert_eq!(
            records(&chunk).map(|(h, _)| h.ts_us).collect::<Vec<_>>(),
            vec![4]
        );
        assert_eq!(r.max_cap_len(), 14);
    }

    #[test]
    fn resize_keeps_the_newest_records_that_fit() {
        let ts_of = |r: &Ring| collect(r).iter().map(|(t, _)| *t).collect::<Vec<_>>();
        for wrapped in [false, true] {
            let mut r = Ring::new(100);
            let n = if wrapped { 7u64 } else { 3 };
            for ts in 1..=n {
                r.push(hdr(ts, 14), &[ts as u8; 14]).unwrap();
            }
            r.push(hdr(100, 4), &[100; 4]).unwrap();
            let id = r.id();
            let before = ts_of(&r);
            // Shrinking keeps what fits (in place).
            let small = r.resized(55);
            assert_ne!(small.id(), id);
            assert_eq!(small.capacity(), 55);
            assert_eq!(ts_of(&small), vec![n, 100]);
            assert_eq!(small.records(), 2);
            assert_eq!(small.evicted(), before.len() as u64 - 2);
            assert_eq!(small.max_cap_len(), 14);
            for (t, d) in collect(&small) {
                assert!(d.iter().all(|b| *b == t as u8));
            }
            // Growing keeps everything, and the ring works on.
            let mut big = small.resized(1000);
            assert_eq!((big.capacity(), big.evicted()), (1000, 0));
            assert_eq!(ts_of(&big), vec![n, 100]);
            big.push(hdr(101, 30), &[101; 30]).unwrap();
            assert_eq!(ts_of(&big), vec![n, 100, 101]);
            assert_eq!(big.max_cap_len(), 30);
            // Only the newest record fits; then none does.
            let tiny = big.resized(50);
            assert_eq!((tiny.records(), tiny.used(), tiny.evicted()), (1, 46, 2));
            assert_eq!(ts_of(&tiny), vec![101]);
            let empty = tiny.resized(20);
            assert_eq!((empty.records(), empty.used(), empty.evicted()), (0, 0, 1));
            assert_eq!(empty.oldest_ts(), None);
        }
    }
}
