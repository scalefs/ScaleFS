use crate::checksum::Crc32c;
use crate::error::{Result, ScaleFsError};
use crate::wire::{Cursor, put_u32, put_u64};

pub const SCALEFS_MAGIC: [u8; 8] = *b"ScaleFS\0";

pub const FORMAT_VERSION: u32 = 2;

pub const RECORD_HEADER_LEN: usize = 32;

const CRC_RANGE: std::ops::Range<usize> = 20..24;
const TX_RANGE: std::ops::Range<usize> = 24..32;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RecordKind {
    Superblock = 1,
    Commit = 2,
    MetadataLeaf = 3,
    MetadataInternal = 4,
    ZoneSummary = 5,
    FileData = 6,
    Topology = 7,
    Parity = 8,
}

impl RecordKind {
    fn from_u16(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::Superblock),
            2 => Ok(Self::Commit),
            3 => Ok(Self::MetadataLeaf),
            4 => Ok(Self::MetadataInternal),
            5 => Ok(Self::ZoneSummary),
            6 => Ok(Self::FileData),
            7 => Ok(Self::Topology),
            8 => Ok(Self::Parity),
            _ => Err(ScaleFsError::Corrupt("unknown record kind")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRecord {
    pub kind: RecordKind,
    pub tx: u64,
    pub crc: u32,
    pub payload: Vec<u8>,
}

impl DecodedRecord {
    pub fn expect(&self) -> Expect {
        Expect {
            crc: self.crc,
            tx: self.tx,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct Expect {
    pub crc: u32,
    pub tx: u64,
}

impl Expect {
    pub const ENCODED_LEN: usize = 12;

    pub fn of(record: &[u8]) -> Expect {
        debug_assert!(record.len() >= RECORD_HEADER_LEN);
        Expect {
            crc: u32::from_le_bytes(record[CRC_RANGE].try_into().expect("4 bytes")),
            tx: u64::from_le_bytes(record[TX_RANGE].try_into().expect("8 bytes")),
        }
    }

    pub fn check(&self, record: &DecodedRecord) -> Result<()> {
        if record.crc == self.crc && record.tx == self.tx {
            Ok(())
        } else {
            Err(ScaleFsError::Corrupt(STALE_COPY))
        }
    }

    pub fn verify(&self, bytes: &[u8]) -> Result<DecodedRecord> {
        let record = decode_record(bytes)?;
        self.check(&record)?;
        Ok(record)
    }

    pub fn verify_in_place(&self, bytes: &[u8]) -> Result<(RecordKind, std::ops::Range<usize>)> {
        let header = check_record(bytes)?;
        if header.crc != self.crc || header.tx != self.tx {
            return Err(ScaleFsError::Corrupt(STALE_COPY));
        }
        Ok((header.kind, header.payload))
    }
}

pub const STALE_COPY: &str =
    "stale copy: the record verifies but is not the one its parent recorded";

pub fn is_stale(error: &ScaleFsError) -> bool {
    matches!(error, ScaleFsError::Corrupt(reason) if *reason == STALE_COPY)
}

pub(crate) fn encode_expect(out: &mut Vec<u8>, expect: Expect) {
    put_u32(out, expect.crc);
    put_u64(out, expect.tx);
}

pub(crate) fn decode_expect(cursor: &mut Cursor<'_>) -> Result<Expect> {
    let crc = cursor.take_u32()?;
    let tx = cursor.take_u64()?;
    if tx == 0 {
        return Err(ScaleFsError::Corrupt("reference names transaction zero"));
    }
    Ok(Expect { crc, tx })
}

pub fn encode_record(kind: RecordKind, tx: u64, payload: &[u8]) -> Vec<u8> {
    debug_assert!(tx != 0, "records are written under a nonzero transaction");
    let len = u32::try_from(payload.len()).expect("record payloads are far below 4 GiB");
    let mut record = Vec::with_capacity(RECORD_HEADER_LEN + payload.len());
    record.extend_from_slice(&SCALEFS_MAGIC);
    record.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    record.extend_from_slice(&(kind as u16).to_le_bytes());
    record.extend_from_slice(&0u16.to_le_bytes());
    record.extend_from_slice(&len.to_le_bytes());
    record.extend_from_slice(&0u32.to_le_bytes());
    record.extend_from_slice(&tx.to_le_bytes());
    debug_assert_eq!(record.len(), RECORD_HEADER_LEN);

    let mut crc = Crc32c::new();
    crc.update(&record);
    crc.update(payload);
    record[CRC_RANGE].copy_from_slice(&crc.finalize().to_le_bytes());

    record.extend_from_slice(payload);
    record
}

pub(crate) struct RecordHeader {
    pub kind: RecordKind,
    pub tx: u64,
    pub crc: u32,
    pub payload: std::ops::Range<usize>,
}

pub fn decode_record(bytes: &[u8]) -> Result<DecodedRecord> {
    let header = check_record(bytes)?;
    Ok(DecodedRecord {
        kind: header.kind,
        tx: header.tx,
        crc: header.crc,
        payload: bytes[header.payload].to_vec(),
    })
}

pub(crate) fn check_record(bytes: &[u8]) -> Result<RecordHeader> {
    if bytes.len() < RECORD_HEADER_LEN {
        return Err(ScaleFsError::Corrupt("record shorter than header"));
    }
    let header = &bytes[..RECORD_HEADER_LEN];

    if header[0..8] != SCALEFS_MAGIC {
        return Err(ScaleFsError::Corrupt("bad magic"));
    }
    let version = u32::from_le_bytes(header[8..12].try_into().expect("4 bytes"));
    if version != FORMAT_VERSION {
        return Err(match version {
            1 => ScaleFsError::EarlierFormat { version },
            v if v > FORMAT_VERSION => {
                ScaleFsError::Unsupported("the on-disk format is newer than this build")
            }
            _ => ScaleFsError::Corrupt("unsupported format version"),
        });
    }
    let kind_raw = u16::from_le_bytes(header[12..14].try_into().expect("2 bytes"));
    let flags = u16::from_le_bytes(header[14..16].try_into().expect("2 bytes"));
    if flags != 0 {
        return Err(ScaleFsError::Corrupt("nonzero record flags"));
    }
    let payload_len = u32::from_le_bytes(header[16..20].try_into().expect("4 bytes")) as usize;
    let stored_crc = u32::from_le_bytes(header[CRC_RANGE].try_into().expect("4 bytes"));
    let tx = u64::from_le_bytes(header[TX_RANGE].try_into().expect("8 bytes"));

    let payload_end = RECORD_HEADER_LEN
        .checked_add(payload_len)
        .ok_or(ScaleFsError::Corrupt("payload length overflows"))?;
    if bytes.len() < payload_end {
        return Err(ScaleFsError::Corrupt("record payload truncated"));
    }
    let payload = &bytes[RECORD_HEADER_LEN..payload_end];

    let mut zeroed_header = [0u8; RECORD_HEADER_LEN];
    zeroed_header.copy_from_slice(header);
    zeroed_header[CRC_RANGE].fill(0);
    let mut crc = Crc32c::new();
    crc.update(&zeroed_header);
    crc.update(payload);
    if crc.finalize() != stored_crc {
        return Err(ScaleFsError::Corrupt("checksum mismatch"));
    }
    if tx == 0 {
        return Err(ScaleFsError::Corrupt("record names transaction zero"));
    }

    let kind = RecordKind::from_u16(kind_raw)?;

    Ok(RecordHeader {
        kind,
        tx,
        crc: stored_crc,
        payload: RECORD_HEADER_LEN..payload_end,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn round_trips_payload() {
        let record = encode_record(RecordKind::Commit, 7, b"payload bytes");
        let decoded = decode_record(&record).unwrap();
        assert_eq!(decoded.kind, RecordKind::Commit);
        assert_eq!(decoded.tx, 7);
        assert_eq!(decoded.payload, b"payload bytes");
        assert_eq!(decoded.expect(), Expect::of(&record));
    }

    #[test]
    fn round_trips_empty_payload() {
        let record = encode_record(RecordKind::Superblock, 1, b"");
        let decoded = decode_record(&record).unwrap();
        assert_eq!(decoded.kind, RecordKind::Superblock);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn tolerates_trailing_slack() {
        let mut record = encode_record(RecordKind::Commit, 3, b"abc");
        record.extend_from_slice(&[0u8; 100]);
        assert_eq!(decode_record(&record).unwrap().payload, b"abc");
    }

    #[test]
    fn every_single_byte_flip_is_detected() {
        for payload in [
            b"".as_slice(),
            b"x".as_slice(),
            b"golden fixture payload".as_slice(),
        ] {
            let record = encode_record(RecordKind::Superblock, 0x0102_0304_0506_0708, payload);
            for i in 0..record.len() {
                for bit in 0..8 {
                    let mut corrupted = record.clone();
                    corrupted[i] ^= 1 << bit;
                    assert!(
                        decode_record(&corrupted).is_err(),
                        "flip of byte {i} bit {bit} went undetected"
                    );
                }
            }
        }
    }

    #[test]
    fn rejects_truncation_at_every_length() {
        let record = encode_record(RecordKind::Commit, 9, b"some payload");
        for len in 0..record.len() {
            assert!(decode_record(&record[..len]).is_err(), "len {len}");
        }
    }

    #[test]
    fn refuses_newer_versions() {
        let mut record = encode_record(RecordKind::Commit, 1, b"p");
        record[8..12].copy_from_slice(&(FORMAT_VERSION + 1).to_le_bytes());
        assert!(matches!(
            decode_record(&record),
            Err(ScaleFsError::Unsupported(_))
        ));
    }

    #[test]
    fn version_one_records_are_refused_with_the_recreate_message() {
        let v1 = hex_bytes(VERSION_ONE_SUPERBLOCK);
        let err = decode_record(&v1).unwrap_err();
        assert!(
            matches!(err, ScaleFsError::EarlierFormat { version: 1 }),
            "{err:?}"
        );
        let message = err.to_string();
        assert!(
            message.contains("created by an earlier preview of ScaleFS"),
            "{message}"
        );
        assert!(
            message.contains("create a new pool and move the files"),
            "{message}"
        );
    }

    pub(crate) const VERSION_ONE_SUPERBLOCK: &str = concat!(
        "5363616c6546530001000000010000008e000000000000008ca8e6f700000000",
        "1111111111111111111111111111111122222222222222222222222222222222",
        "00002a36fe9c9717070000000000000000000000000000000000000000000000",
        "0000000000000000001000000010000000000004000000000004000000000000",
        "0100000001010000110001000df0fecaed5e0100000000000000040000000000",
        "1000000000000000040074616e6b",
    );

    pub(crate) fn hex_bytes(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn transaction_zero_is_refused() {
        let mut record = encode_record(RecordKind::Commit, 5, b"p");
        record[24..32].fill(0);
        record[20..24].fill(0);
        let mut crc = Crc32c::new();
        crc.update(&record[..RECORD_HEADER_LEN]);
        crc.update(&record[RECORD_HEADER_LEN..]);
        let sealed = crc.finalize();
        record[20..24].copy_from_slice(&sealed.to_le_bytes());
        assert!(matches!(
            decode_record(&record),
            Err(ScaleFsError::Corrupt("record names transaction zero"))
        ));
    }

    #[test]
    fn expectations_tell_a_stale_copy_from_the_current_one() {
        let current = encode_record(RecordKind::FileData, 12, b"new bytes");
        let older = encode_record(RecordKind::FileData, 11, b"old bytes");
        let replayed = encode_record(RecordKind::FileData, 11, b"new bytes");
        let expect = Expect::of(&current);
        assert!(expect.verify(&current).is_ok());
        for stale in [&older, &replayed] {
            let err = expect.verify(stale).unwrap_err();
            assert!(is_stale(&err), "{err:?}");
        }
    }

    #[test]
    fn golden_record_fixture_is_stable() {
        let record = encode_record(
            RecordKind::Superblock,
            0x0000_0001_0000_0002,
            b"scalefs golden fixture v2",
        );
        assert_eq!(
            hex(&record),
            "5363616c65465300020000000100000019000000fa082e0f02000000010000007363616c65667320676f6c64656e2066697874757265207632"
        );
        assert_eq!(
            decode_record(&record).unwrap().payload,
            b"scalefs golden fixture v2"
        );
    }
}
