//! A byte ring of variable-length packet records, oldest overwritten first.
//!
//! Each record is a 16-byte header (timestamp in µs, original length,
//! captured length, direction) followed by the captured bytes, stored
//! contiguously modulo the buffer size (a record may wrap around the end).
//! Memory is exactly the buffer: no per-packet allocation and no separate
//! index.

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

pub(crate) struct Ring {
    buf: Vec<u8>,
    /// Absolute byte positions (never wrap in practice): the oldest record
    /// starts at `head`, the next one is written at `tail`.
    head: u64,
    tail: u64,
    records: usize,
    /// Records overwritten to make room since the ring was created.
    evicted: u64,
}

impl Ring {
    /// A ring of `capacity` bytes. The memory is zero-initialised by the
    /// allocator (fresh pages for large sizes), so it is only committed as
    /// packets fill it.
    pub fn new(capacity: usize) -> Self {
        Ring {
            buf: vec![0u8; capacity.max(HDR + 1)],
            head: 0,
            tail: 0,
            records: 0,
            evicted: 0,
        }
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
        Some(self.evicted - before)
    }

    /// Copies the used region out (oldest record first), so it can be read
    /// without holding the ring.
    pub fn snapshot(&self) -> Vec<u8> {
        let mut out = vec![0u8; self.used()];
        self.read_at(self.head, &mut out);
        out
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

/// Iterates the records of a [`Ring::snapshot`].
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
        let snap = r.snapshot();
        let via_snapshot: Vec<_> = records(&snap).map(|(h, d)| (h.ts_us, d.to_vec())).collect();
        assert_eq!(out, via_snapshot);
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
        assert!(r.snapshot().is_empty());
        assert_eq!(collect(&r).len(), 0);
    }
}
