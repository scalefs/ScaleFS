use crate::error::{Result, ScaleFsError};
use crate::format::{Expect, RECORD_HEADER_LEN};
use crate::fs::FILE_DATA_CHUNK;
use crate::layout::{Extent, decode_extent, encode_extent};
use crate::wire::{Cursor, put_u16, put_u32, put_u64};

pub const MAX_RUN_RECORDS: usize = 33;

pub const MAX_STRIPE_RUN_RECORDS: usize = crate::rs::MAX_DATA;

pub const MAX_RUN_SPAN: u64 = (if MAX_RUN_RECORDS > MAX_STRIPE_RUN_RECORDS {
    MAX_RUN_RECORDS
} else {
    MAX_STRIPE_RUN_RECORDS
} * FILE_DATA_CHUNK) as u64;

const HEADER: u64 = RECORD_HEADER_LEN as u64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRun {
    pub copies: Vec<Extent>,
    pub stride: u64,
    pub last_len: u64,
    pub tx: u64,
    pub crcs: Vec<u32>,
    pub data_offset: u64,
    pub logical_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StripedRun {
    pub pieces: Vec<Extent>,
    pub crcs: Vec<u32>,
    pub tx: u64,
    pub parity: Vec<Extent>,
    pub parity_crcs: Vec<u32>,
    pub parity_tx: u64,
    pub data_offset: u64,
    pub logical_len: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordWindow {
    pub first: usize,
    pub last: usize,
    pub at: u64,
}

fn window(full_payload: u64, data_offset: u64, skip: u64, len: u64) -> RecordWindow {
    debug_assert!(len >= 1 && full_payload >= 1);
    let start = data_offset + skip;
    let first = start / full_payload;
    let last = (start + len - 1) / full_payload;
    RecordWindow {
        first: first as usize,
        last: last as usize,
        at: start - first * full_payload,
    }
}

fn validate_window(
    count: usize,
    full_payload: u64,
    last_payload: u64,
    data_offset: u64,
    logical_len: u64,
) -> Result<()> {
    let total = (count as u64 - 1)
        .checked_mul(full_payload)
        .and_then(|head| head.checked_add(last_payload))
        .ok_or(ScaleFsError::Corrupt("run payload overflows"))?;
    let end = data_offset.checked_add(logical_len);
    if logical_len == 0 || end.is_none_or(|end| end > total) {
        return Err(ScaleFsError::Corrupt(
            "file run references bytes outside its records",
        ));
    }
    let end = end.expect("checked");
    if data_offset >= full_payload.min(total) || end <= (count as u64 - 1) * full_payload {
        return Err(ScaleFsError::Corrupt(
            "file run names records it does not reference",
        ));
    }
    Ok(())
}

fn record_len_ok(len: u64) -> bool {
    len > HEADER && len - HEADER <= FILE_DATA_CHUNK as u64
}

impl FileRun {
    pub fn count(&self) -> usize {
        self.crcs.len()
    }

    pub fn record_len(&self, k: usize) -> u64 {
        if k + 1 == self.count() {
            self.last_len
        } else {
            self.copies[0].length
        }
    }

    pub fn full_payload(&self) -> u64 {
        self.copies[0].length - HEADER
    }

    pub fn record_copies(&self, k: usize) -> Vec<Extent> {
        let length = self.record_len(k);
        self.copies
            .iter()
            .map(|copy| Extent {
                device_index: copy.device_index,
                offset: copy.offset + k as u64 * self.stride,
                length,
            })
            .collect()
    }

    pub fn expect(&self, k: usize) -> Expect {
        Expect {
            crc: self.crcs[k],
            tx: self.tx,
        }
    }

    pub fn spans(&self) -> Vec<Extent> {
        let length = (self.count() as u64 - 1) * self.stride + self.last_len;
        self.copies
            .iter()
            .map(|copy| Extent {
                device_index: copy.device_index,
                offset: copy.offset,
                length,
            })
            .collect()
    }

    pub fn window(&self, skip: u64, len: u64) -> RecordWindow {
        window(self.full_payload(), self.data_offset, skip, len)
    }

    pub fn slice(&self, skip: u64, len: u64) -> FileRun {
        let w = self.window(skip, len);
        let last_len = self.record_len(w.last);
        let length = if w.first == w.last {
            last_len
        } else {
            self.copies[0].length
        };
        FileRun {
            copies: self
                .copies
                .iter()
                .map(|copy| Extent {
                    device_index: copy.device_index,
                    offset: copy.offset + w.first as u64 * self.stride,
                    length,
                })
                .collect(),
            stride: self.stride,
            last_len,
            tx: self.tx,
            crcs: self.crcs[w.first..=w.last].to_vec(),
            data_offset: w.at,
            logical_len: len,
        }
    }

    pub fn validate(&self) -> Result<()> {
        let Some(first) = self.copies.first() else {
            return Err(ScaleFsError::Corrupt("file run has no copies"));
        };
        if self.copies.len() > usize::from(u8::MAX) {
            return Err(ScaleFsError::Corrupt("file run has too many copies"));
        }
        let mut members = std::collections::HashSet::new();
        for copy in &self.copies {
            if copy.length != first.length {
                return Err(ScaleFsError::Corrupt(
                    "file run copies must have equal lengths",
                ));
            }
            if !members.insert(copy.device_index) {
                return Err(ScaleFsError::Corrupt(
                    "file run copies must live on distinct members",
                ));
            }
        }
        let count = self.count();
        if count == 0 || count > MAX_RUN_RECORDS {
            return Err(ScaleFsError::Corrupt(
                "file run record count is out of range",
            ));
        }
        if self.tx == 0 {
            return Err(ScaleFsError::Corrupt("file run names transaction zero"));
        }
        if !record_len_ok(first.length) || !record_len_ok(self.last_len) {
            return Err(ScaleFsError::Corrupt(
                "file run record length is out of range",
            ));
        }
        if (count == 1 && self.last_len != first.length)
            || self.last_len > first.length
            || self.stride < first.length
            || self.stride > u64::from(u32::MAX)
        {
            return Err(ScaleFsError::Corrupt("file run layout is inconsistent"));
        }
        let span = (count as u64 - 1)
            .checked_mul(self.stride)
            .and_then(|head| head.checked_add(self.last_len));
        for copy in &self.copies {
            if span
                .and_then(|span| copy.offset.checked_add(span))
                .is_none()
            {
                return Err(ScaleFsError::Corrupt(
                    "file run overflows the address space",
                ));
            }
        }
        validate_window(
            count,
            self.full_payload(),
            self.last_len - HEADER,
            self.data_offset,
            self.logical_len,
        )
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.copies.len() as u8);
        for copy in &self.copies {
            encode_extent(out, *copy);
        }
        put_u32(out, self.stride as u32);
        put_u16(out, self.count() as u16);
        put_u32(out, self.last_len as u32);
        put_u64(out, self.tx);
        for crc in &self.crcs {
            put_u32(out, *crc);
        }
        put_u64(out, self.data_offset);
        put_u64(out, self.logical_len);
    }

    pub(crate) fn decode(cursor: &mut Cursor<'_>) -> Result<FileRun> {
        let copy_count = cursor.take_u8()?;
        let mut copies = Vec::with_capacity(usize::from(copy_count));
        for _ in 0..copy_count {
            copies.push(decode_extent(cursor)?);
        }
        let stride = u64::from(cursor.take_u32()?);
        let count = usize::from(cursor.take_u16()?);
        if count > MAX_RUN_RECORDS {
            return Err(ScaleFsError::Corrupt(
                "file run record count is out of range",
            ));
        }
        let last_len = u64::from(cursor.take_u32()?);
        let tx = cursor.take_u64()?;
        let mut crcs = Vec::with_capacity(count);
        for _ in 0..count {
            crcs.push(cursor.take_u32()?);
        }
        Ok(FileRun {
            copies,
            stride,
            last_len,
            tx,
            crcs,
            data_offset: cursor.take_u64()?,
            logical_len: cursor.take_u64()?,
        })
    }
}

impl StripedRun {
    pub fn count(&self) -> usize {
        self.pieces.len()
    }

    pub fn full_payload(&self) -> u64 {
        self.pieces[0].length - HEADER
    }

    pub fn expect(&self, k: usize) -> Expect {
        Expect {
            crc: self.crcs[k],
            tx: self.tx,
        }
    }

    pub fn parity_expect(&self, row: usize) -> Expect {
        Expect {
            crc: self.parity_crcs[row],
            tx: self.parity_tx,
        }
    }

    pub fn window(&self, skip: u64, len: u64) -> RecordWindow {
        window(self.full_payload(), self.data_offset, skip, len)
    }

    pub fn slice(&self, skip: u64, len: u64) -> StripedRun {
        let w = self.window(skip, len);
        StripedRun {
            pieces: self.pieces[w.first..=w.last].to_vec(),
            crcs: self.crcs[w.first..=w.last].to_vec(),
            tx: self.tx,
            parity: self.parity.clone(),
            parity_crcs: self.parity_crcs.clone(),
            parity_tx: self.parity_tx,
            data_offset: w.at,
            logical_len: len,
        }
    }

    pub fn validate(&self) -> Result<()> {
        let count = self.count();
        if count == 0 || count > MAX_STRIPE_RUN_RECORDS || self.crcs.len() != count {
            return Err(ScaleFsError::Corrupt(
                "striped run piece count is out of range",
            ));
        }
        if self.parity.is_empty()
            || self.parity.len() > crate::rs::MAX_PARITY
            || self.parity_crcs.len() != self.parity.len()
        {
            return Err(ScaleFsError::Corrupt(
                "striped run parity count is out of range",
            ));
        }
        if self.tx == 0 || self.parity_tx == 0 {
            return Err(ScaleFsError::Corrupt("striped run names transaction zero"));
        }
        let full = self.pieces[0].length;
        for (k, piece) in self.pieces.iter().enumerate() {
            let shape_ok = if k + 1 == count {
                piece.length <= full
            } else {
                piece.length == full
            };
            if !record_len_ok(piece.length) || !shape_ok {
                return Err(ScaleFsError::Corrupt(
                    "striped run piece lengths are inconsistent",
                ));
            }
        }
        let mut members = std::collections::HashSet::new();
        for extent in self.pieces.iter().chain(&self.parity) {
            if !members.insert(extent.device_index) {
                return Err(ScaleFsError::Corrupt(
                    "striped run pieces must live on distinct members",
                ));
            }
            if extent.end_offset().is_none() {
                return Err(ScaleFsError::Corrupt(
                    "striped run overflows the address space",
                ));
            }
        }
        for parity in &self.parity {
            if parity.length == 0 || parity.length != self.parity[0].length {
                return Err(ScaleFsError::Corrupt(
                    "striped run parity records must have equal lengths",
                ));
            }
        }
        validate_window(
            count,
            full - HEADER,
            self.pieces[count - 1].length - HEADER,
            self.data_offset,
            self.logical_len,
        )
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.pieces.len() as u8);
        for piece in &self.pieces {
            encode_extent(out, *piece);
        }
        for crc in &self.crcs {
            put_u32(out, *crc);
        }
        put_u64(out, self.tx);
        out.push(self.parity.len() as u8);
        for parity in &self.parity {
            encode_extent(out, *parity);
        }
        for crc in &self.parity_crcs {
            put_u32(out, *crc);
        }
        put_u64(out, self.parity_tx);
        put_u64(out, self.data_offset);
        put_u64(out, self.logical_len);
    }

    pub(crate) fn decode(cursor: &mut Cursor<'_>) -> Result<StripedRun> {
        let count = usize::from(cursor.take_u8()?);
        let mut pieces = Vec::with_capacity(count);
        for _ in 0..count {
            pieces.push(decode_extent(cursor)?);
        }
        let mut crcs = Vec::with_capacity(count);
        for _ in 0..count {
            crcs.push(cursor.take_u32()?);
        }
        let tx = cursor.take_u64()?;
        let parity_count = usize::from(cursor.take_u8()?);
        let mut parity = Vec::with_capacity(parity_count);
        for _ in 0..parity_count {
            parity.push(decode_extent(cursor)?);
        }
        let mut parity_crcs = Vec::with_capacity(parity_count);
        for _ in 0..parity_count {
            parity_crcs.push(cursor.take_u32()?);
        }
        Ok(StripedRun {
            pieces,
            crcs,
            tx,
            parity,
            parity_crcs,
            parity_tx: cursor.take_u64()?,
            data_offset: cursor.take_u64()?,
            logical_len: cursor.take_u64()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: u64 = HEADER + FILE_DATA_CHUNK as u64;

    fn run(count: usize, last_payload: u64) -> FileRun {
        let last_len = HEADER + last_payload;
        let first_len = if count == 1 { last_len } else { FULL };
        FileRun {
            copies: vec![
                Extent {
                    device_index: 0,
                    offset: 1 << 20,
                    length: first_len,
                },
                Extent {
                    device_index: 1,
                    offset: 2 << 20,
                    length: first_len,
                },
            ],
            stride: 32768,
            last_len,
            tx: 7,
            crcs: (0..count as u32).map(|k| 0xC000 + k).collect(),
            data_offset: 0,
            logical_len: (count as u64 - 1) * FILE_DATA_CHUNK as u64 + last_payload,
        }
    }

    #[test]
    fn records_lie_at_the_stride_on_every_copy() {
        let run = run(3, 100);
        run.validate().unwrap();
        assert_eq!(run.count(), 3);
        let copies = run.record_copies(2);
        assert_eq!(copies[0].offset, (1 << 20) + 2 * 32768);
        assert_eq!(copies[1].offset, (2 << 20) + 2 * 32768);
        assert_eq!(copies[0].length, HEADER + 100);
        assert_eq!(run.record_copies(1)[0].length, FULL);
        assert_eq!(run.expect(1), Expect { crc: 0xC001, tx: 7 });
        assert_eq!(run.spans()[1].length, 2 * 32768 + HEADER + 100);
    }

    #[test]
    fn slices_keep_exactly_the_records_they_reference() {
        let chunk = FILE_DATA_CHUNK as u64;
        let whole = run(3, 100);
        assert_eq!(whole.slice(0, whole.logical_len), whole);
        let head = whole.slice(0, chunk);
        head.validate().unwrap();
        assert_eq!(head.count(), 1);
        assert_eq!(head.copies[0].length, FULL);
        assert_eq!(head.last_len, FULL);
        let head = whole.slice(0, chunk + 1);
        head.validate().unwrap();
        assert_eq!(head.count(), 2);
        assert_eq!(head.crcs, vec![0xC000, 0xC001]);
        let tail = whole.slice(chunk + 5, whole.logical_len - chunk - 5);
        tail.validate().unwrap();
        assert_eq!(tail.count(), 2);
        assert_eq!(tail.data_offset, 5);
        assert_eq!(tail.copies[0].offset, (1 << 20) + 32768);
        assert_eq!(tail.crcs, vec![0xC001, 0xC002]);
        assert_eq!(tail.last_len, HEADER + 100);
        let last = whole.slice(whole.logical_len - 1, 1);
        last.validate().unwrap();
        assert_eq!(last.count(), 1);
        assert_eq!(last.copies[0].length, HEADER + 100);
        assert_eq!(last.data_offset, 99);
        let middle = whole.slice(chunk + 10, 20);
        middle.validate().unwrap();
        assert_eq!((middle.count(), middle.data_offset), (1, 10));
        assert_eq!(middle.copies[0].length, FULL);
        let twice = whole.slice(7, whole.logical_len - 7).slice(chunk, 50);
        assert_eq!(twice, whole.slice(chunk + 7, 50));
    }

    #[test]
    fn runs_round_trip_and_refuse_bad_shapes() {
        let good = run(4, 1000);
        let mut bytes = Vec::new();
        good.encode(&mut bytes);
        let decoded = FileRun::decode(&mut Cursor::new(&bytes)).unwrap();
        assert_eq!(decoded, good);

        let refuse = |name: &str, f: &dyn Fn(&mut FileRun)| {
            let mut bad = run(4, 1000);
            f(&mut bad);
            assert!(bad.validate().is_err(), "{name}");
        };
        refuse("no records", &|r| r.crcs.clear());
        refuse("too many records", &|r| {
            r.crcs = vec![1; MAX_RUN_RECORDS + 1]
        });
        refuse("zero tx", &|r| r.tx = 0);
        refuse("stride below the record", &|r| r.stride = FULL - 1);
        refuse("last longer than the rest", &|r| r.last_len = FULL + 1);
        refuse("payload over a chunk", &|r| {
            for copy in &mut r.copies {
                copy.length = FULL + 1;
            }
        });
        refuse("unequal copies", &|r| r.copies[1].length -= 1);
        refuse("one member twice", &|r| r.copies[1].device_index = 0);
        refuse("window past the end", &|r| r.logical_len += 1);
        refuse("empty window", &|r| r.logical_len = 0);
        refuse("unreferenced first record", &|r| {
            r.data_offset = FILE_DATA_CHUNK as u64;
            r.logical_len -= FILE_DATA_CHUNK as u64;
        });
        refuse("unreferenced last record", &|r| r.logical_len -= 1000);
        refuse("a single record whose copies say another length", &|r| {
            r.crcs.truncate(1);
            r.logical_len = 10;
        });
    }

    fn striped(count: usize) -> StripedRun {
        StripedRun {
            pieces: (0..count)
                .map(|k| Extent {
                    device_index: k as u16,
                    offset: 1 << 20,
                    length: if k + 1 == count { HEADER + 10 } else { FULL },
                })
                .collect(),
            crcs: (0..count as u32).collect(),
            tx: 3,
            parity: vec![Extent {
                device_index: 9,
                offset: 1 << 20,
                length: 40_000,
            }],
            parity_crcs: vec![0xAB],
            parity_tx: 4,
            data_offset: 0,
            logical_len: (count as u64 - 1) * FILE_DATA_CHUNK as u64 + 10,
        }
    }

    #[test]
    fn striped_runs_slice_by_piece_and_round_trip() {
        let row = striped(3);
        row.validate().unwrap();
        let mut bytes = Vec::new();
        row.encode(&mut bytes);
        assert_eq!(StripedRun::decode(&mut Cursor::new(&bytes)).unwrap(), row);
        let tail = row.slice(
            FILE_DATA_CHUNK as u64 + 1,
            row.logical_len - FILE_DATA_CHUNK as u64 - 1,
        );
        tail.validate().unwrap();
        assert_eq!(tail.pieces, row.pieces[1..].to_vec());
        assert_eq!(tail.crcs, vec![1, 2]);
        assert_eq!(tail.data_offset, 1);
        assert_eq!(tail.parity, row.parity);

        let mut bad = striped(3);
        bad.pieces[0].length -= 1;
        assert!(bad.validate().is_err(), "a short piece before the last");
        let mut bad = striped(3);
        bad.parity[0].device_index = 1;
        assert!(bad.validate().is_err(), "parity on a data member");
        let mut bad = striped(3);
        bad.parity_tx = 0;
        assert!(bad.validate().is_err(), "parity transaction zero");
    }
}
