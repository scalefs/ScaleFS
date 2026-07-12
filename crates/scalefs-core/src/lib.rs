
#[cfg(test)]
mod chaos;
pub mod checksum;
pub mod device;
pub mod dirent;
pub mod discovery;
pub mod error;
pub mod format;
pub mod fs;
pub mod layout;
pub mod pool;
pub mod raw;
pub mod records;
pub mod rng;
pub mod rs;
pub mod salvage;
pub mod snapshots;
pub mod stripes;
pub mod topology;
pub mod torture;
pub mod tree;
pub mod wire;
pub mod zones;

pub use checksum::{Crc32c, crc32c};
pub use device::{BlockDevice, FileBlockDevice, MemoryBlockDevice, ReadOnly, SharedDevice};
pub use discovery::{
    Contents, DeviceIdentity, DiscoveredDevice, ImportPlan, PlanError, PoolChoice, PoolProbe,
    discovered_pools, list_devices, plan_import, probe_path, same_spindle,
};
pub use error::{Result, ScaleFsError};
pub use format::{
    DecodedRecord, FORMAT_VERSION, RECORD_HEADER_LEN, RecordKind, SCALEFS_MAGIC, decode_record,
    encode_record,
};
pub use fs::FILE_DATA_CHUNK;
pub use fs::LINK_MAX;
pub use fs::MAX_SYMLINK_TARGET;
pub use fs::{XATTR_SET_CREATE, XATTR_SET_EITHER, XATTR_SET_REPLACE};
pub use layout::{CaseSensitivity, DeviceId, Extent, Geometry, PoolId, superblock_slots};
pub use pool::{
    AbortedCommit, CommitTicket, CompactReport, CreateParams, ExecutedCommit, MemberSpec, Pool,
    PoolParams, RebuildReport, ReclaimReport, ScrubReport,
};
pub use raw::{AnyBlockDevice, RawBlockDevice, is_device_path};
pub use records::{
    Commit, FEATURE_COMPAT_KNOWN, FEATURE_INCOMPAT_KNOWN, FEATURE_INCOMPAT_MULTI_DEVICE,
    FEATURE_INCOMPAT_PARITY, FEATURE_RO_COMPAT_HARDLINKS, FEATURE_RO_COMPAT_KNOWN,
    FEATURE_RO_COMPAT_SPECIAL_FILES, FEATURE_RO_COMPAT_XATTRS, MAX_LABEL_LEN, Superblock,
    decode_commit, decode_file_data, decode_superblock, encode_commit, encode_file_data,
    encode_superblock,
};
pub use rs::generate_parity;
pub use salvage::{AssemblyReport, DeviceRole, Rung, Salvage, SalvageOptions};
pub use snapshots::{Snapshot, SnapshotInfo};
pub use stripes::{
    ParityRecord, STRIPE_HEADER_LEN, decode_parity_record, encode_parity_record, parity_record_len,
};
pub use topology::{MemberState, Topology, TopologyMember, decode_topology, encode_topology};
pub use torture::{FaultDevice, FaultMode, FaultSwitch, TortureBlockDevice};
pub use tree::{
    DirEntry, EntryKind, FILE_ATTR_ARCHIVE, FILE_ATTR_HIDDEN, FILE_ATTR_READONLY, FILE_ATTR_SYSTEM,
    ITEM_DIRENT, ITEM_FILE_EXTENT, ITEM_INODE, ITEM_POOL_STATE, ITEM_RETAINED_ROOT, ITEM_SPECIAL,
    ITEM_XATTR, InodeAttrs, MAX_NAME_LEN, MAX_VALUE_LEN, MODE_BLOCK_DEVICE, MODE_CHAR_DEVICE,
    MODE_DIRECTORY, MODE_FIFO, MODE_FILE, MODE_SOCKET, MODE_SYMLINK, MODE_TYPE_MASK, MetadataKey,
    MetadataTree, MetadataValue, PagePlan, ROOT_INODE, XATTR_TAG, XATTR_VALUE_MAX, XattrEntry,
};
pub use zones::{AllocPurpose, Allocation, ZoneAllocator, ZoneClass, ZoneView};
