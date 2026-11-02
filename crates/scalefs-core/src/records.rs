use crate::error::{Result, ScaleFsError};
use crate::format::{DecodedRecord, RecordKind, decode_record, encode_record};
use crate::layout::{
    CaseSensitivity, DeviceId, Extent, Geometry, PoolId, decode_extent, decode_geometry,
    encode_extent, encode_geometry,
};
use crate::unicode::UnicodeVersion;
use crate::wire::{Cursor, put_i64, put_u16, put_u32, put_u64};

pub const MAX_LABEL_LEN: usize = 256;

pub const FEATURE_COMPAT_KNOWN: u64 = 0;
pub const FEATURE_RO_COMPAT_SPECIAL_FILES: u64 = 1 << 0;
pub const FEATURE_RO_COMPAT_HARDLINKS: u64 = 1 << 1;
pub const FEATURE_RO_COMPAT_XATTRS: u64 = 1 << 2;
pub const FEATURE_RO_COMPAT_KNOWN: u64 =
    FEATURE_RO_COMPAT_SPECIAL_FILES | FEATURE_RO_COMPAT_HARDLINKS | FEATURE_RO_COMPAT_XATTRS;
pub const FEATURE_INCOMPAT_MULTI_DEVICE: u64 = 1 << 0;
pub const FEATURE_INCOMPAT_PARITY: u64 = 1 << 1;
pub const FEATURE_INCOMPAT_THIN_METADATA: u64 = 1 << 2;
pub const FEATURE_INCOMPAT_KNOWN: u64 =
    FEATURE_INCOMPAT_MULTI_DEVICE | FEATURE_INCOMPAT_PARITY | FEATURE_INCOMPAT_THIN_METADATA;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Superblock {
    pub pool_id: PoolId,
    pub device_id: DeviceId,
    pub created_at_ns: i64,
    pub topology_generation: u64,
    pub feature_compat: u64,
    pub feature_ro_compat: u64,
    pub feature_incompat: u64,
    pub geometry: Geometry,
    pub case_sensitivity: CaseSensitivity,
    pub unicode_version: UnicodeVersion,
    pub dirent_hash_seed: u64,
    pub newest_commit: Option<Extent>,
    pub aux_record: Option<Extent>,
    pub label: String,
}

impl Superblock {
    pub fn unknown_ro_compat(&self) -> u64 {
        self.feature_ro_compat & !FEATURE_RO_COMPAT_KNOWN
    }

    pub fn unknown_incompat(&self) -> u64 {
        self.feature_incompat & !FEATURE_INCOMPAT_KNOWN
    }

    pub fn require_supported_unicode_version(&self) -> Result<()> {
        if crate::unicode::is_supported(self.unicode_version) {
            Ok(())
        } else {
            Err(ScaleFsError::UnsupportedUnicodeVersion {
                pool: self.unicode_version,
                newest: crate::unicode::NEWEST_SUPPORTED_UNICODE_VERSION,
            })
        }
    }
}

pub fn encode_superblock(superblock: &Superblock) -> Result<Vec<u8>> {
    if superblock.label.len() > MAX_LABEL_LEN {
        return Err(ScaleFsError::InvalidArgument("pool label is too long"));
    }
    superblock.geometry.validate()?;

    let mut payload = Vec::new();
    payload.extend_from_slice(&superblock.pool_id.0);
    payload.extend_from_slice(&superblock.device_id.0);
    put_i64(&mut payload, superblock.created_at_ns);
    put_u64(&mut payload, superblock.topology_generation);
    put_u64(&mut payload, superblock.feature_compat);
    put_u64(&mut payload, superblock.feature_ro_compat);
    put_u64(&mut payload, superblock.feature_incompat);
    encode_geometry(&mut payload, superblock.geometry);
    payload.push(superblock.case_sensitivity.to_u8());
    put_u32(&mut payload, superblock.unicode_version.to_u32());
    put_u64(&mut payload, superblock.dirent_hash_seed);
    match superblock.newest_commit {
        None => payload.push(0),
        Some(extent) => {
            payload.push(1);
            encode_extent(&mut payload, extent);
        }
    }
    match superblock.aux_record {
        None => payload.push(0),
        Some(extent) => {
            if extent.length == 0 {
                return Err(ScaleFsError::InvalidArgument(
                    "auxiliary record extent is empty",
                ));
            }
            payload.push(1);
            encode_extent(&mut payload, extent);
        }
    }
    put_u16(&mut payload, superblock.label.len() as u16);
    payload.extend_from_slice(superblock.label.as_bytes());

    Ok(encode_record(RecordKind::Superblock, &payload))
}

pub fn decode_superblock(bytes: &[u8]) -> Result<Superblock> {
    let record = decode_record(bytes)?;
    if record.kind != RecordKind::Superblock {
        return Err(ScaleFsError::Corrupt("expected a superblock record"));
    }

    let mut cursor = Cursor::new(&record.payload);
    let pool_id = PoolId(cursor.take_array::<16>()?);
    let device_id = DeviceId(cursor.take_array::<16>()?);
    let created_at_ns = cursor.take_i64()?;
    let topology_generation = cursor.take_u64()?;
    let feature_compat = cursor.take_u64()?;
    let feature_ro_compat = cursor.take_u64()?;
    let feature_incompat = cursor.take_u64()?;
    let geometry = decode_geometry(&mut cursor)?;
    let case_sensitivity = CaseSensitivity::from_u8(cursor.take_u8()?)?;
    let unicode_version = UnicodeVersion::from_u32(cursor.take_u32()?);
    let dirent_hash_seed = cursor.take_u64()?;
    let newest_commit = match cursor.take_u8()? {
        0 => None,
        1 => Some(decode_extent(&mut cursor)?),
        _ => return Err(ScaleFsError::Corrupt("invalid newest-commit flag")),
    };
    let aux_record = match cursor.take_u8()? {
        0 => None,
        1 => {
            let extent = decode_extent(&mut cursor)?;
            if extent.length == 0 {
                return Err(ScaleFsError::Corrupt("auxiliary record extent is empty"));
            }
            Some(extent)
        }
        _ => return Err(ScaleFsError::Corrupt("invalid auxiliary-record flag")),
    };
    let label_len = usize::from(cursor.take_u16()?);
    if label_len > MAX_LABEL_LEN {
        return Err(ScaleFsError::Corrupt("pool label is too long"));
    }
    let label = String::from_utf8(cursor.take(label_len)?.to_vec())
        .map_err(|_| ScaleFsError::Corrupt("pool label is not UTF-8"))?;
    cursor.expect_end("superblock payload has trailing bytes")?;

    Ok(Superblock {
        pool_id,
        device_id,
        created_at_ns,
        topology_generation,
        feature_compat,
        feature_ro_compat,
        feature_incompat,
        geometry,
        case_sensitivity,
        unicode_version,
        dirent_hash_seed,
        newest_commit,
        aux_record,
        label,
    })
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Commit {
    pub tx_id: u64,
    pub supersedes: u64,
    pub created_at_ns: i64,
    pub metadata_root: Extent,
    pub allocator_summary: Extent,
    pub aux_root: Option<Extent>,
}

pub fn encode_commit(commit: &Commit) -> Result<Vec<u8>> {
    validate_commit(commit)?;
    let mut payload = Vec::new();
    put_u64(&mut payload, commit.tx_id);
    put_u64(&mut payload, commit.supersedes);
    put_i64(&mut payload, commit.created_at_ns);
    encode_extent(&mut payload, commit.metadata_root);
    encode_extent(&mut payload, commit.allocator_summary);
    match commit.aux_root {
        None => payload.push(0),
        Some(extent) => {
            payload.push(1);
            encode_extent(&mut payload, extent);
        }
    }
    Ok(encode_record(RecordKind::Commit, &payload))
}

pub fn decode_commit(bytes: &[u8]) -> Result<Commit> {
    let record = decode_record(bytes)?;
    if record.kind != RecordKind::Commit {
        return Err(ScaleFsError::Corrupt("expected a commit record"));
    }

    let mut cursor = Cursor::new(&record.payload);
    let commit = Commit {
        tx_id: cursor.take_u64()?,
        supersedes: cursor.take_u64()?,
        created_at_ns: cursor.take_i64()?,
        metadata_root: decode_extent(&mut cursor)?,
        allocator_summary: decode_extent(&mut cursor)?,
        aux_root: match cursor.take_u8()? {
            0 => None,
            1 => Some(decode_extent(&mut cursor)?),
            _ => return Err(ScaleFsError::Corrupt("invalid auxiliary-root flag")),
        },
    };
    cursor.expect_end("commit payload has trailing bytes")?;
    validate_commit(&commit)?;
    Ok(commit)
}

fn validate_commit(commit: &Commit) -> Result<()> {
    if commit.tx_id == 0 {
        return Err(ScaleFsError::Corrupt("commit transaction id is zero"));
    }
    if commit.supersedes >= commit.tx_id {
        return Err(ScaleFsError::Corrupt(
            "commit must supersede an older transaction",
        ));
    }
    if commit.metadata_root.length == 0 {
        return Err(ScaleFsError::Corrupt("commit metadata root is empty"));
    }
    if commit.allocator_summary.length == 0 {
        return Err(ScaleFsError::Corrupt("commit allocator summary is empty"));
    }
    if let Some(aux_root) = commit.aux_root
        && aux_root.length == 0
    {
        return Err(ScaleFsError::Corrupt("commit auxiliary root is empty"));
    }
    Ok(())
}

pub fn encode_file_data(data: &[u8]) -> Vec<u8> {
    encode_record(RecordKind::FileData, data)
}

pub fn decode_file_data(bytes: &[u8]) -> Result<Vec<u8>> {
    let record = decode_record(bytes)?;
    if record.kind != RecordKind::FileData {
        return Err(ScaleFsError::Corrupt("expected a file data record"));
    }
    let DecodedRecord { payload, .. } = record;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn fixture_geometry() -> Geometry {
        Geometry {
            logical_block_size: 4096,
            physical_block_size: 4096,
            zone_size: 1 << 26,
            zone_count: 1024,
            erase_granularity_zones: 1,
            sequential_write_required: true,
        }
    }

    fn fixture_superblock() -> Superblock {
        Superblock {
            pool_id: PoolId([0x11; 16]),
            device_id: DeviceId([0x22; 16]),
            created_at_ns: 1_700_000_000_000_000_000,
            topology_generation: 7,
            feature_compat: 0,
            feature_ro_compat: 0,
            feature_incompat: 0,
            geometry: fixture_geometry(),
            case_sensitivity: CaseSensitivity::InsensitivePreserving,
            unicode_version: crate::unicode::V17_0_0,
            dirent_hash_seed: 0x5EED_CAFE_F00D_0001,
            newest_commit: Some(Extent {
                device_index: 0,
                offset: 1 << 26,
                length: 4096,
            }),
            aux_record: None,
            label: "tank".to_string(),
        }
    }

    fn fixture_commit() -> Commit {
        Commit {
            tx_id: 5,
            supersedes: 4,
            created_at_ns: 1_700_000_000_000_000_000,
            metadata_root: Extent {
                device_index: 0,
                offset: (1 << 26) + 4096,
                length: 8192,
            },
            allocator_summary: Extent {
                device_index: 0,
                offset: (1 << 26) + 12288,
                length: 4096,
            },
            aux_root: None,
        }
    }

    #[test]
    fn superblock_round_trips() {
        let encoded = encode_superblock(&fixture_superblock()).unwrap();
        assert_eq!(decode_superblock(&encoded).unwrap(), fixture_superblock());
    }

    #[test]
    fn superblock_round_trips_without_newest_commit_and_empty_label() {
        let mut superblock = fixture_superblock();
        superblock.newest_commit = None;
        superblock.label = String::new();
        let encoded = encode_superblock(&superblock).unwrap();
        assert_eq!(decode_superblock(&encoded).unwrap(), superblock);
    }

    #[test]
    fn superblock_aux_record_round_trips_and_validates() {
        let mut superblock = fixture_superblock();
        superblock.aux_record = Some(Extent {
            device_index: 0,
            offset: 2 << 26,
            length: 4096,
        });
        let encoded = encode_superblock(&superblock).unwrap();
        assert_eq!(decode_superblock(&encoded).unwrap(), superblock);

        superblock.aux_record = Some(Extent {
            device_index: 0,
            offset: 2 << 26,
            length: 0,
        });
        assert!(encode_superblock(&superblock).is_err());
    }

    #[test]
    fn superblock_fits_the_smallest_slot_at_max_label() {
        let mut superblock = fixture_superblock();
        superblock.label = "x".repeat(MAX_LABEL_LEN);
        let encoded = encode_superblock(&superblock).unwrap();
        assert!(
            encoded.len() <= 512,
            "superblock record ({} bytes) must fit a 512-byte block",
            encoded.len()
        );
    }

    #[test]
    fn superblock_rejects_oversized_label() {
        let mut superblock = fixture_superblock();
        superblock.label = "x".repeat(MAX_LABEL_LEN + 1);
        assert!(encode_superblock(&superblock).is_err());
    }

    #[test]
    fn superblock_rejects_non_utf8_label_bytes() {
        let mut encoded = encode_superblock(&fixture_superblock()).unwrap();
        let len = encoded.len();
        encoded[len - 4..].copy_from_slice(&[0xFF, 0xFE, 0xFD, 0xFC]);
        let payload = encoded[crate::format::RECORD_HEADER_LEN..].to_vec();
        let reencoded = crate::format::encode_record(RecordKind::Superblock, &payload);
        assert!(matches!(
            decode_superblock(&reencoded),
            Err(ScaleFsError::Corrupt("pool label is not UTF-8"))
        ));
    }

    #[test]
    fn superblock_rejects_trailing_payload_bytes() {
        let encoded = encode_superblock(&fixture_superblock()).unwrap();
        let mut payload = encoded[crate::format::RECORD_HEADER_LEN..].to_vec();
        payload.push(0);
        let reencoded = crate::format::encode_record(RecordKind::Superblock, &payload);
        assert!(matches!(
            decode_superblock(&reencoded),
            Err(ScaleFsError::Corrupt(
                "superblock payload has trailing bytes"
            ))
        ));
    }

    #[test]
    fn superblock_decode_rejects_wrong_kind() {
        let commit = encode_commit(&fixture_commit()).unwrap();
        assert!(decode_superblock(&commit).is_err());
    }

    #[test]
    fn commit_round_trips() {
        let encoded = encode_commit(&fixture_commit()).unwrap();
        assert_eq!(decode_commit(&encoded).unwrap(), fixture_commit());
    }

    #[test]
    fn commit_aux_root_round_trips_and_validates() {
        let mut commit = fixture_commit();
        commit.aux_root = Some(Extent {
            device_index: 0,
            offset: (1 << 26) + 16384,
            length: 4096,
        });
        let encoded = encode_commit(&commit).unwrap();
        assert_eq!(decode_commit(&encoded).unwrap(), commit);

        commit.aux_root = Some(Extent {
            device_index: 0,
            offset: (1 << 26) + 16384,
            length: 0,
        });
        assert!(encode_commit(&commit).is_err());
    }

    #[test]
    fn commit_rejects_bad_transaction_chains() {
        let mut commit = fixture_commit();
        commit.tx_id = 0;
        commit.supersedes = 0;
        assert!(encode_commit(&commit).is_err());

        let mut commit = fixture_commit();
        commit.supersedes = commit.tx_id;
        assert!(encode_commit(&commit).is_err());

        let mut commit = fixture_commit();
        commit.metadata_root.length = 0;
        assert!(encode_commit(&commit).is_err());

        let mut commit = fixture_commit();
        commit.allocator_summary.length = 0;
        assert!(encode_commit(&commit).is_err());
    }

    #[test]
    fn file_data_round_trips() {
        let encoded = encode_file_data(b"file contents");
        assert_eq!(decode_file_data(&encoded).unwrap(), b"file contents");
        let superblock = encode_superblock(&fixture_superblock()).unwrap();
        assert!(decode_file_data(&superblock).is_err());
    }

    #[test]
    fn golden_superblock_fixture_is_stable() {
        let encoded = encode_superblock(&fixture_superblock()).unwrap();
        assert_eq!(
            hex(&encoded),
            "5363616c6546530001000000010000008e000000000000008ca8e6f700000000111111111111111111111111111111112222222222222222222222222222222200002a36fe9c971707000000000000000000000000000000000000000000000000000000000000000010000000100000000000040000000000040000000000000100000001010000110001000df0fecaed5e01000000000000000400000000001000000000000000040074616e6b"
        );
        assert_eq!(decode_superblock(&encoded).unwrap(), fixture_superblock());
    }

    #[test]
    fn golden_commit_fixture_is_stable() {
        let encoded = encode_commit(&fixture_commit()).unwrap();
        assert_eq!(
            hex(&encoded),
            "5363616c6546530001000000020000004100000000000000e39c8bf5000000000500000000000000040000000000000000002a36fe9c97170000000000100004000000000020000000000000000000000030000400000000001000000000000000"
        );
        assert_eq!(decode_commit(&encoded).unwrap(), fixture_commit());
    }

    #[test]
    fn unicode_version_round_trips_any_value() {
        let mut superblock = fixture_superblock();
        superblock.unicode_version = UnicodeVersion::new(99, 0, 0);
        let encoded = encode_superblock(&superblock).unwrap();
        assert_eq!(decode_superblock(&encoded).unwrap(), superblock);
    }

    #[test]
    fn refuses_unsupported_unicode_version_with_upgrade_message() {
        fixture_superblock()
            .require_supported_unicode_version()
            .unwrap();

        let mut superblock = fixture_superblock();
        superblock.unicode_version = UnicodeVersion::new(99, 0, 0);
        let err = superblock.require_supported_unicode_version().unwrap_err();
        assert!(matches!(
            err,
            ScaleFsError::UnsupportedUnicodeVersion { pool, newest }
                if pool == UnicodeVersion::new(99, 0, 0)
                    && newest == crate::unicode::NEWEST_SUPPORTED_UNICODE_VERSION
        ));
        let message = err.to_string();
        assert!(message.contains("99.0.0"), "{message}");
        assert!(message.contains("17.0.0"), "{message}");
        assert!(
            message.contains("upgrade ScaleFS to mount this pool"),
            "{message}"
        );
    }
}
