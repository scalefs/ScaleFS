
use crate::error::{Result, ScaleFsError};
use crate::format::{RECORD_HEADER_LEN, RecordKind, decode_record, encode_record};
use crate::layout::{Extent, decode_extent, encode_extent};
use crate::rs::{MAX_DATA, MAX_PARITY};
use crate::wire::{Cursor, put_u32, put_u64};

pub const STRIPE_HEADER_LEN: usize = 16;

pub fn parity_record_len(data_count: usize, parity_count: usize, coverage_len: u64) -> u64 {
    (RECORD_HEADER_LEN + STRIPE_HEADER_LEN + 20 * (data_count + parity_count)) as u64 + coverage_len
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParityRecord {
    pub parity_index: u8,
    pub coverage_len: u64,
    pub data_pieces: Vec<Extent>,
    pub parity_pieces: Vec<Extent>,
    pub parity: Vec<u8>,
}

impl ParityRecord {
    pub fn validate(&self) -> Result<()> {
        let data_count = self.data_pieces.len();
        let parity_count = self.parity_pieces.len();
        if data_count == 0 || data_count > MAX_DATA {
            return Err(ScaleFsError::Corrupt(
                "stripe data piece count is out of range",
            ));
        }
        if parity_count == 0 || parity_count > MAX_PARITY {
            return Err(ScaleFsError::Corrupt(
                "stripe parity piece count is out of range",
            ));
        }
        if usize::from(self.parity_index) >= parity_count {
            return Err(ScaleFsError::Corrupt("stripe parity index is out of range"));
        }
        if self.parity.len() as u64 != self.coverage_len {
            return Err(ScaleFsError::Corrupt(
                "stripe parity bytes do not match the coverage length",
            ));
        }
        let mut members = std::collections::HashSet::new();
        let mut longest = 0u64;
        for extent in &self.data_pieces {
            if extent.length == 0 || extent.length > self.coverage_len {
                return Err(ScaleFsError::Corrupt(
                    "stripe data piece length is outside the coverage",
                ));
            }
            longest = longest.max(extent.length);
            if !members.insert(extent.device_index) {
                return Err(ScaleFsError::Corrupt(
                    "stripe pieces must live on distinct members",
                ));
            }
        }
        if longest != self.coverage_len {
            return Err(ScaleFsError::Corrupt(
                "stripe coverage must equal the longest data piece",
            ));
        }
        let own_len = parity_record_len(data_count, parity_count, self.coverage_len);
        for extent in &self.parity_pieces {
            if extent.length != own_len {
                return Err(ScaleFsError::Corrupt(
                    "stripe parity extents must match the parity record length",
                ));
            }
            if !members.insert(extent.device_index) {
                return Err(ScaleFsError::Corrupt(
                    "stripe pieces must live on distinct members",
                ));
            }
        }
        Ok(())
    }
}

pub fn encode_parity_record(record: &ParityRecord) -> Result<Vec<u8>> {
    record.validate()?;
    let mut payload = Vec::with_capacity(
        STRIPE_HEADER_LEN
            + 20 * (record.data_pieces.len() + record.parity_pieces.len())
            + record.parity.len(),
    );
    payload.push(record.parity_index);
    payload.push(record.data_pieces.len() as u8);
    payload.push(record.parity_pieces.len() as u8);
    payload.push(0);
    put_u32(&mut payload, 0);
    put_u64(&mut payload, record.coverage_len);
    for extent in &record.data_pieces {
        encode_extent(&mut payload, *extent);
    }
    for extent in &record.parity_pieces {
        encode_extent(&mut payload, *extent);
    }
    payload.extend_from_slice(&record.parity);
    let bytes = encode_record(RecordKind::Parity, &payload);
    debug_assert_eq!(
        bytes.len() as u64,
        parity_record_len(
            record.data_pieces.len(),
            record.parity_pieces.len(),
            record.coverage_len
        )
    );
    Ok(bytes)
}

pub fn decode_parity_record(bytes: &[u8]) -> Result<ParityRecord> {
    let record = decode_record(bytes)?;
    if record.kind != RecordKind::Parity {
        return Err(ScaleFsError::Corrupt("expected a parity record"));
    }
    let mut cursor = Cursor::new(&record.payload);
    let parity_index = cursor.take_u8()?;
    let data_count = usize::from(cursor.take_u8()?);
    let parity_count = usize::from(cursor.take_u8()?);
    if cursor.take_u8()? != 0 || cursor.take_u32()? != 0 {
        return Err(ScaleFsError::Corrupt(
            "nonzero reserved field in parity record",
        ));
    }
    let coverage_len = cursor.take_u64()?;
    if data_count == 0 || data_count > MAX_DATA || parity_count == 0 || parity_count > MAX_PARITY {
        return Err(ScaleFsError::Corrupt(
            "stripe piece counts are out of range",
        ));
    }
    let mut data_pieces = Vec::with_capacity(data_count);
    for _ in 0..data_count {
        data_pieces.push(decode_extent(&mut cursor)?);
    }
    let mut parity_pieces = Vec::with_capacity(parity_count);
    for _ in 0..parity_count {
        parity_pieces.push(decode_extent(&mut cursor)?);
    }
    let parity_len = usize::try_from(coverage_len)
        .map_err(|_| ScaleFsError::Corrupt("stripe coverage exceeds the address space"))?;
    let parity = cursor.take(parity_len)?.to_vec();
    cursor.expect_end("parity record has trailing bytes")?;
    let record = ParityRecord {
        parity_index,
        coverage_len,
        data_pieces,
        parity_pieces,
        parity,
    };
    record.validate()?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn extent(member: u16, offset: u64, length: u64) -> Extent {
        Extent {
            device_index: member,
            offset,
            length,
        }
    }

    fn fixture() -> ParityRecord {
        let coverage = 96u64;
        let own_len = parity_record_len(3, 2, coverage);
        ParityRecord {
            parity_index: 1,
            coverage_len: coverage,
            data_pieces: vec![
                extent(0, 1 << 20, 96),
                extent(2, 1 << 21, 64),
                extent(4, 1 << 22, 80),
            ],
            parity_pieces: vec![extent(1, 1 << 23, own_len), extent(3, 1 << 24, own_len)],
            parity: (0..96).map(|i| (i as u8).wrapping_mul(37) ^ 0x5A).collect(),
        }
    }

    #[test]
    fn round_trips_and_lengths_agree() {
        let record = fixture();
        let encoded = encode_parity_record(&record).unwrap();
        assert_eq!(
            encoded.len() as u64,
            parity_record_len(3, 2, record.coverage_len)
        );
        assert_eq!(decode_parity_record(&encoded).unwrap(), record);
    }

    #[test]
    fn validation_rejects_malformed_stripes() {
        let corrupt = |mutate: &dyn Fn(&mut ParityRecord)| {
            let mut record = fixture();
            mutate(&mut record);
            encode_parity_record(&record)
        };
        for (name, mutation) in [
            (
                "parity index out of range",
                &(|r: &mut ParityRecord| r.parity_index = 2) as &dyn Fn(&mut ParityRecord),
            ),
            ("no data pieces", &|r: &mut ParityRecord| {
                r.data_pieces.clear()
            }),
            ("no parity pieces", &|r: &mut ParityRecord| {
                r.parity_pieces.clear()
            }),
            ("duplicate member", &|r: &mut ParityRecord| {
                r.data_pieces[1].device_index = r.data_pieces[0].device_index
            }),
            ("parity on a data member", &|r: &mut ParityRecord| {
                r.parity_pieces[0].device_index = r.data_pieces[0].device_index
            }),
            ("empty data piece", &|r: &mut ParityRecord| {
                r.data_pieces[1].length = 0
            }),
            (
                "data piece longer than coverage",
                &|r: &mut ParityRecord| r.data_pieces[1].length = r.coverage_len + 1,
            ),
            ("no piece reaches the coverage", &|r: &mut ParityRecord| {
                r.data_pieces[0].length = 90
            }),
            ("parity extent length mismatch", &|r: &mut ParityRecord| {
                r.parity_pieces[1].length -= 1
            }),
            (
                "parity bytes shorter than coverage",
                &|r: &mut ParityRecord| {
                    r.parity.pop();
                },
            ),
        ] {
            assert!(
                matches!(corrupt(mutation), Err(ScaleFsError::Corrupt(_))),
                "{name}"
            );
        }
    }

    #[test]
    fn decode_rejects_reserved_and_structural_violations() {
        let encoded = encode_parity_record(&fixture()).unwrap();
        let corrupt = |mutate: &dyn Fn(&mut Vec<u8>)| {
            let record = decode_record(&encoded).unwrap();
            let mut payload = record.payload;
            mutate(&mut payload);
            decode_parity_record(&encode_record(RecordKind::Parity, &payload))
        };
        assert!(corrupt(&|p| p[3] = 1).is_err());
        assert!(corrupt(&|p| p[5] = 1).is_err());
        assert!(corrupt(&|p| p[1] = 0).is_err());
        assert!(corrupt(&|p| p[2] = (MAX_PARITY + 1) as u8).is_err());
        assert!(corrupt(&|p| p.push(0)).is_err());
        let commit_shaped = encode_record(RecordKind::Commit, b"x");
        assert!(decode_parity_record(&commit_shaped).is_err());
    }

    #[test]
    fn golden_parity_record_fixture_is_stable() {
        let mut record = fixture();
        record.parity = (0..96u8).collect();
        let encoded = encode_parity_record(&record).unwrap();
        assert_eq!(
            hex(&encoded),
            "5363616c654653000100000008000000d400000000000000c54d55f40000000001030200000000006000000000000000000000000000100000000000600000000000000002000000000020000000000040000000000000000400000000004000000000005000000000000000010000000000800000000000f400000000000000030000000000000100000000f400000000000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
        );
        assert_eq!(decode_parity_record(&encoded).unwrap(), record);
    }
}
