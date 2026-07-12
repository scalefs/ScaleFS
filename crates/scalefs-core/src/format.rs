
use crate::checksum::Crc32c;
use crate::error::{Result, ScaleFsError};

pub const SCALEFS_MAGIC: [u8; 8] = *b"ScaleFS\0";

pub const FORMAT_VERSION: u32 = 1;

pub const RECORD_HEADER_LEN: usize = 32;

const CRC_RANGE: std::ops::Range<usize> = 24..28;

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
    MetadataInternalMirrored = 9,
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
            9 => Ok(Self::MetadataInternalMirrored),
            _ => Err(ScaleFsError::Corrupt("unknown record kind")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRecord {
    pub kind: RecordKind,
    pub payload: Vec<u8>,
}

pub fn encode_record(kind: RecordKind, payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(RECORD_HEADER_LEN + payload.len());
    record.extend_from_slice(&SCALEFS_MAGIC);
    record.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    record.extend_from_slice(&(kind as u16).to_le_bytes());
    record.extend_from_slice(&0u16.to_le_bytes());
    record.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    record.extend_from_slice(&0u32.to_le_bytes());
    record.extend_from_slice(&0u32.to_le_bytes());
    debug_assert_eq!(record.len(), RECORD_HEADER_LEN);

    let mut crc = Crc32c::new();
    crc.update(&record);
    crc.update(payload);
    record[CRC_RANGE].copy_from_slice(&crc.finalize().to_le_bytes());

    record.extend_from_slice(payload);
    record
}

pub fn decode_record(bytes: &[u8]) -> Result<DecodedRecord> {
    if bytes.len() < RECORD_HEADER_LEN {
        return Err(ScaleFsError::Corrupt("record shorter than header"));
    }
    let header = &bytes[..RECORD_HEADER_LEN];

    if header[0..8] != SCALEFS_MAGIC {
        return Err(ScaleFsError::Corrupt("bad magic"));
    }
    let version = u32::from_le_bytes(header[8..12].try_into().expect("4 bytes"));
    if version != FORMAT_VERSION {
        return Err(ScaleFsError::Corrupt("unsupported format version"));
    }
    let kind_raw = u16::from_le_bytes(header[12..14].try_into().expect("2 bytes"));
    let flags = u16::from_le_bytes(header[14..16].try_into().expect("2 bytes"));
    if flags != 0 {
        return Err(ScaleFsError::Corrupt("nonzero flags in version-1 record"));
    }
    let payload_len_raw = u64::from_le_bytes(header[16..24].try_into().expect("8 bytes"));
    let payload_len = usize::try_from(payload_len_raw)
        .map_err(|_| ScaleFsError::Corrupt("payload length exceeds address space"))?;
    let stored_crc = u32::from_le_bytes(header[24..28].try_into().expect("4 bytes"));
    let reserved = u32::from_le_bytes(header[28..32].try_into().expect("4 bytes"));
    if reserved != 0 {
        return Err(ScaleFsError::Corrupt("nonzero reserved field"));
    }

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

    let kind = RecordKind::from_u16(kind_raw)?;

    Ok(DecodedRecord {
        kind,
        payload: payload.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn round_trips_payload() {
        let record = encode_record(RecordKind::Commit, b"payload bytes");
        let decoded = decode_record(&record).unwrap();
        assert_eq!(decoded.kind, RecordKind::Commit);
        assert_eq!(decoded.payload, b"payload bytes");
    }

    #[test]
    fn round_trips_empty_payload() {
        let record = encode_record(RecordKind::Superblock, b"");
        let decoded = decode_record(&record).unwrap();
        assert_eq!(decoded.kind, RecordKind::Superblock);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn tolerates_trailing_slack() {
        let mut record = encode_record(RecordKind::Commit, b"abc");
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
            let record = encode_record(RecordKind::Superblock, payload);
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
        let record = encode_record(RecordKind::Commit, b"some payload");
        for len in 0..record.len() {
            assert!(decode_record(&record[..len]).is_err(), "len {len}");
        }
    }

    #[test]
    fn rejects_future_version() {
        let mut record = encode_record(RecordKind::Commit, b"p");
        record[8..12].copy_from_slice(&(FORMAT_VERSION + 1).to_le_bytes());
        assert!(matches!(
            decode_record(&record),
            Err(ScaleFsError::Corrupt("unsupported format version"))
        ));
    }

    #[test]
    fn golden_record_fixture_is_stable() {
        let record = encode_record(RecordKind::Superblock, b"scalefs golden fixture v1");
        assert_eq!(
            hex(&record),
            "5363616c654653000100000001000000190000000000000082d2b012000000007363616c65667320676f6c64656e2066697874757265207631"
        );
        assert_eq!(
            decode_record(&record).unwrap().payload,
            b"scalefs golden fixture v1"
        );
    }
}
