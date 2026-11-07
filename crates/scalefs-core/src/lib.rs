#[cfg(test)]
mod chaos;
pub mod checksum;
pub mod device;
pub mod dirent;
pub mod discovery;
pub mod error;
pub mod format;
pub mod fs;
pub mod gpt;
pub mod layout;
pub mod perftrace;
pub mod pool;
pub mod raw;
pub mod records;
pub mod rng;
pub mod rs;
pub mod runs;
pub mod salvage;
pub mod snapshots;
pub mod stripes;
pub mod topology;
pub mod torture;
pub mod tree;
pub mod unicode;
pub mod wire;
pub mod zones;

pub use checksum::{Crc32c, crc32c};
pub use device::{
    BlockDevice, FileBlockDevice, MemoryBlockDevice, PartitionView, ReadOnly, SharedDevice,
};
pub use dirent::HashedEntry;
pub use discovery::{
    BLANK_SAMPLE_LEN, Contents, DeviceAttachment, DeviceIdentity, DiscoveredDevice, ImportPlan,
    PlanError, PoolChoice, PoolProbe, attachment_of_path, classify_attachment, discovered_pools,
    list_devices, plan_import, probe_path, same_spindle,
};
pub use error::{Result, ScaleFsError};
pub use format::{
    DecodedRecord, Expect, FORMAT_VERSION, RECORD_HEADER_LEN, RecordKind, SCALEFS_MAGIC,
    STALE_COPY, decode_record, encode_record, is_stale,
};
pub use fs::FILE_DATA_CHUNK;
pub use fs::LINK_MAX;
pub use fs::MAX_SYMLINK_TARGET;
pub use fs::{XATTR_SET_CREATE, XATTR_SET_EITHER, XATTR_SET_REPLACE};
pub use gpt::{
    MEMBER_PARTITION_START, MemberPartition, SCALEFS_PART_TYPE_GUID, SCALEFS_PART_TYPE_GUID_TEXT,
    find_member_partition, guid_text, member_image_len, member_view, member_view_forensic,
    usable_len, write_member_gpt,
};
pub use layout::{
    CaseSensitivity, DeviceId, Extent, Geometry, PoolId, superblock_slots, zone_summary_len,
};
pub use pool::{
    AbortedCommit, CommitTicket, CompactReport, CreateParams, ExecutedCommit, MemberSpec, Pool,
    PoolParams, RebuildReport, ReclaimReport, ScrubReport, TreeCensus,
};
pub use raw::{AnyBlockDevice, RawBlockDevice, is_device_path};
pub use records::{
    Commit, FEATURE_COMPAT_KNOWN, FEATURE_INCOMPAT_KNOWN, FEATURE_INCOMPAT_MULTI_DEVICE,
    FEATURE_INCOMPAT_PARITY, FEATURE_INCOMPAT_THIN_METADATA, FEATURE_RO_COMPAT_HARDLINKS,
    FEATURE_RO_COMPAT_KNOWN, FEATURE_RO_COMPAT_SPECIAL_FILES, FEATURE_RO_COMPAT_XATTRS,
    MAX_LABEL_LEN, RecordRef, Superblock, decode_commit, decode_file_data, decode_superblock,
    encode_commit, encode_file_data, encode_superblock,
};
pub use rs::generate_parity;
pub use runs::{FileRun, MAX_RUN_RECORDS, MAX_RUN_SPAN, RecordWindow, StripedRun};
pub use salvage::{AssemblyReport, DeviceRole, Rung, Salvage, SalvageOptions};
pub use snapshots::{Snapshot, SnapshotInfo};
pub use stripes::{
    ParityRecord, STRIPE_HEADER_LEN, decode_parity_record, encode_parity_record, parity_record_len,
};
pub use topology::{MemberState, Topology, TopologyMember, decode_topology, encode_topology};
pub use torture::{FaultDevice, FaultMode, FaultSwitch, TortureBlockDevice};
pub use tree::{
    CacheStats, DEFAULT_METADATA_CACHE_BYTES, DirEntry, EntryKind, FILE_ATTR_ARCHIVE,
    FILE_ATTR_HIDDEN, FILE_ATTR_READONLY, FILE_ATTR_SYSTEM, ITEM_DIRENT, ITEM_FILE_EXTENT,
    ITEM_INODE, ITEM_POOL_STATE, ITEM_RETAINED_ROOT, ITEM_SPECIAL, ITEM_XATTR, InodeAttrs, Leaves,
    MAX_NAME_LEN, MAX_VALUE_LEN, MODE_BLOCK_DEVICE, MODE_CHAR_DEVICE, MODE_DIRECTORY, MODE_FIFO,
    MODE_FILE, MODE_SOCKET, MODE_SYMLINK, MODE_TYPE_MASK, MetadataKey, MetadataTree, MetadataValue,
    NoPages, PagePlan, PageRef, PageSource, ROOT_INODE, TreeItem, TreeMut, TreeRef, XATTR_TAG,
    XATTR_VALUE_MAX, XattrEntry, default_metadata_cache, set_default_metadata_cache,
};
pub use unicode::{
    NEWEST_SUPPORTED_UNICODE_VERSION, SUPPORTED_UNICODE_VERSIONS, UnicodeVersion, V17_0_0,
    is_supported as is_supported_unicode_version,
};
pub use zones::{AllocPurpose, Allocation, ZoneAllocator, ZoneClass, ZoneView};
