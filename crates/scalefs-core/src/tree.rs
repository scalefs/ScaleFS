
use crate::error::{Result, ScaleFsError};
use crate::format::{RECORD_HEADER_LEN, RecordKind, decode_record, encode_record};
use crate::layout::{Extent, decode_extent, encode_extent};
use crate::wire::{Cursor, put_i64, put_u16, put_u32, put_u64};

pub const ROOT_INODE: u64 = 1;

pub const ITEM_POOL_STATE: u8 = 0;
pub const ITEM_INODE: u8 = 1;
pub const ITEM_DIRENT: u8 = 2;
pub const ITEM_FILE_EXTENT: u8 = 3;
pub const ITEM_RETAINED_ROOT: u8 = 4;
pub const ITEM_SPECIAL: u8 = 5;
pub const ITEM_XATTR: u8 = 6;

pub const MAX_NAME_LEN: usize = 255;
pub const MAX_VALUE_LEN: usize = 4096;

pub const TOLERATED_RANGE_MIN: u8 = 128;

pub const SPECIAL_TAG: u8 = 128;

pub const XATTR_TAG: u8 = 129;

pub const XATTR_VALUE_MAX: usize = 3800;

pub const FILE_ATTR_READONLY: u32 = 0x0001;
pub const FILE_ATTR_HIDDEN: u32 = 0x0002;
pub const FILE_ATTR_SYSTEM: u32 = 0x0004;
pub const FILE_ATTR_ARCHIVE: u32 = 0x0020;

const LEAF_SPLIT_BYTES: usize = 16 * 1024;
const INTERNAL_MAX_CHILDREN: usize = 128;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MetadataKey {
    pub object_id: u64,
    pub item_type: u8,
    pub offset: u64,
}

impl MetadataKey {
    pub const MIN: Self = Self {
        object_id: 0,
        item_type: 0,
        offset: 0,
    };

    pub const MAX: Self = Self {
        object_id: u64::MAX,
        item_type: u8::MAX,
        offset: u64::MAX,
    };
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
    Fifo,
    Socket,
    CharDevice,
    BlockDevice,
    Unknown(u8),
}

pub const DEFINED_ENTRY_KIND_MAX: u8 = 132;

impl EntryKind {
    fn to_u8(self) -> u8 {
        match self {
            Self::File => 1,
            Self::Directory => 2,
            Self::Symlink => 128,
            Self::Fifo => 129,
            Self::Socket => 130,
            Self::CharDevice => 131,
            Self::BlockDevice => 132,
            Self::Unknown(kind) => kind,
        }
    }

    fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::File),
            2 => Ok(Self::Directory),
            128 => Ok(Self::Symlink),
            129 => Ok(Self::Fifo),
            130 => Ok(Self::Socket),
            131 => Ok(Self::CharDevice),
            132 => Ok(Self::BlockDevice),
            kind if kind >= TOLERATED_RANGE_MIN => Ok(Self::Unknown(kind)),
            _ => Err(ScaleFsError::Corrupt("unknown directory entry kind")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub inode: u64,
    pub kind: EntryKind,
    pub name: String,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct InodeAttrs {
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub attrs: u32,
    pub crtime_ns: i64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    pub atime_ns: i64,
}

impl InodeAttrs {
    pub fn is_dir(&self) -> bool {
        self.mode & MODE_TYPE_MASK == MODE_DIRECTORY
    }

    pub fn is_symlink(&self) -> bool {
        self.mode & MODE_TYPE_MASK == MODE_SYMLINK
    }

    pub fn is_device(&self) -> bool {
        matches!(
            self.mode & MODE_TYPE_MASK,
            MODE_CHAR_DEVICE | MODE_BLOCK_DEVICE
        )
    }

    pub fn entry_kind(&self) -> EntryKind {
        match self.mode & MODE_TYPE_MASK {
            MODE_DIRECTORY => EntryKind::Directory,
            MODE_SYMLINK => EntryKind::Symlink,
            MODE_FIFO => EntryKind::Fifo,
            MODE_SOCKET => EntryKind::Socket,
            MODE_CHAR_DEVICE => EntryKind::CharDevice,
            MODE_BLOCK_DEVICE => EntryKind::BlockDevice,
            _ => EntryKind::File,
        }
    }
}

pub const MODE_TYPE_MASK: u32 = 0o170000;
pub const MODE_DIRECTORY: u32 = 0o040000;
pub const MODE_FILE: u32 = 0o100000;
pub const MODE_SYMLINK: u32 = 0o120000;
pub const MODE_FIFO: u32 = 0o010000;
pub const MODE_SOCKET: u32 = 0o140000;
pub const MODE_CHAR_DEVICE: u32 = 0o020000;
pub const MODE_BLOCK_DEVICE: u32 = 0o060000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataValue {
    PoolState {
        next_object_id: u64,
    },
    Inode(InodeAttrs),
    DirEntries(Vec<DirEntry>),
    FileExtent {
        extents: Vec<Extent>,
        data_offset: u64,
        logical_len: u64,
    },
    StripedExtent {
        extent: Extent,
        parity_extents: Vec<Extent>,
        data_offset: u64,
        logical_len: u64,
    },
    RetainedRoot {
        tx_id: u64,
        metadata_roots: Vec<Extent>,
        created_at_ns: i64,
        name: String,
    },
    Special {
        data: Vec<u8>,
    },
    XattrEntries(Vec<XattrEntry>),
    Opaque {
        tag: u8,
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XattrEntry {
    pub name: String,
    pub value: Vec<u8>,
}

impl MetadataValue {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::PoolState { next_object_id } => {
                if *next_object_id < 2 {
                    return Err(ScaleFsError::Corrupt("pool state next object id below 2"));
                }
            }
            Self::Inode(_) => {}
            Self::DirEntries(entries) => {
                if entries.is_empty() {
                    return Err(ScaleFsError::Corrupt("empty directory entry bucket"));
                }
                for entry in entries {
                    if let EntryKind::Unknown(kind) = entry.kind
                        && kind <= DEFINED_ENTRY_KIND_MAX
                    {
                        return Err(ScaleFsError::Corrupt(
                            "unknown entry kind collides with a defined kind",
                        ));
                    }
                    validate_stored_name(&entry.name)?;
                }
            }
            Self::FileExtent {
                extents,
                data_offset,
                logical_len,
            } => {
                let Some(first) = extents.first() else {
                    return Err(ScaleFsError::Corrupt("file extent has no copies"));
                };
                let mut members = std::collections::HashSet::new();
                for extent in extents {
                    if extent.length != first.length {
                        return Err(ScaleFsError::Corrupt(
                            "file extent copies must have equal lengths",
                        ));
                    }
                    if !members.insert(extent.device_index) {
                        return Err(ScaleFsError::Corrupt(
                            "file extent copies must live on distinct members",
                        ));
                    }
                }
                let payload = first.length.saturating_sub(RECORD_HEADER_LEN as u64);
                let end = data_offset.checked_add(*logical_len);
                if *logical_len == 0 || end.is_none() || end.unwrap() > payload {
                    return Err(ScaleFsError::Corrupt(
                        "file extent references bytes outside its record",
                    ));
                }
                if *logical_len > crate::fs::FILE_DATA_CHUNK as u64 {
                    return Err(ScaleFsError::Corrupt(
                        "file extent runs longer than one data chunk",
                    ));
                }
            }
            Self::StripedExtent {
                extent,
                parity_extents,
                data_offset,
                logical_len,
            } => {
                if parity_extents.is_empty() || parity_extents.len() > crate::rs::MAX_PARITY {
                    return Err(ScaleFsError::Corrupt(
                        "striped extent parity count is out of range",
                    ));
                }
                let mut members = std::collections::HashSet::new();
                members.insert(extent.device_index);
                for parity in parity_extents {
                    if parity.length == 0 || parity.length != parity_extents[0].length {
                        return Err(ScaleFsError::Corrupt(
                            "striped extent parity records must have equal lengths",
                        ));
                    }
                    if !members.insert(parity.device_index) {
                        return Err(ScaleFsError::Corrupt(
                            "striped extent pieces must live on distinct members",
                        ));
                    }
                }
                let payload = extent.length.saturating_sub(RECORD_HEADER_LEN as u64);
                let end = data_offset.checked_add(*logical_len);
                if *logical_len == 0 || end.is_none() || end.unwrap() > payload {
                    return Err(ScaleFsError::Corrupt(
                        "striped extent references bytes outside its record",
                    ));
                }
                if *logical_len > crate::fs::FILE_DATA_CHUNK as u64 {
                    return Err(ScaleFsError::Corrupt(
                        "striped extent runs longer than one data chunk",
                    ));
                }
            }
            Self::RetainedRoot {
                tx_id,
                metadata_roots,
                name,
                ..
            } => {
                if *tx_id == 0 {
                    return Err(ScaleFsError::Corrupt("retained root transaction is zero"));
                }
                if metadata_roots.is_empty() {
                    return Err(ScaleFsError::Corrupt("retained root has no copies"));
                }
                let mut members = std::collections::HashSet::new();
                for root in metadata_roots {
                    if root.length == 0 {
                        return Err(ScaleFsError::Corrupt("retained root extent is empty"));
                    }
                    if root.length != metadata_roots[0].length {
                        return Err(ScaleFsError::Corrupt(
                            "retained root copies must have equal lengths",
                        ));
                    }
                    if !members.insert(root.device_index) {
                        return Err(ScaleFsError::Corrupt(
                            "retained root copies must live on distinct members",
                        ));
                    }
                }
                validate_stored_name(name)?;
            }
            Self::Special { .. } => {}
            Self::XattrEntries(entries) => {
                if entries.is_empty() {
                    return Err(ScaleFsError::Corrupt("empty xattr bucket"));
                }
                for pair in entries.windows(2) {
                    if pair[0].name >= pair[1].name {
                        return Err(ScaleFsError::Corrupt(
                            "xattr bucket names must be unique and sorted",
                        ));
                    }
                }
                for entry in entries {
                    if entry.name.is_empty() || entry.name.len() > 255 {
                        return Err(ScaleFsError::Corrupt("xattr name length"));
                    }
                    if entry.value.len() > XATTR_VALUE_MAX {
                        return Err(ScaleFsError::Corrupt("xattr value length"));
                    }
                }
            }
            Self::Opaque { tag, .. } => {
                if *tag < TOLERATED_RANGE_MIN || *tag == SPECIAL_TAG || *tag == XATTR_TAG {
                    return Err(ScaleFsError::Corrupt(
                        "opaque value tag collides with a defined tag",
                    ));
                }
            }
        }
        Ok(())
    }
}

fn validate_stored_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(ScaleFsError::Corrupt("directory entry name length"));
    }
    if name == "." || name == ".." {
        return Err(ScaleFsError::Corrupt("directory entry name is . or .."));
    }
    if name.bytes().any(|b| b == 0 || b == b'/') {
        return Err(ScaleFsError::Corrupt(
            "directory entry name contains a separator or NUL",
        ));
    }
    Ok(())
}

pub(crate) fn encode_key(out: &mut Vec<u8>, key: MetadataKey) {
    put_u64(out, key.object_id);
    out.push(key.item_type);
    put_u64(out, key.offset);
}

pub(crate) fn decode_key(cursor: &mut Cursor<'_>) -> Result<MetadataKey> {
    Ok(MetadataKey {
        object_id: cursor.take_u64()?,
        item_type: cursor.take_u8()?,
        offset: cursor.take_u64()?,
    })
}

pub(crate) fn encode_value(out: &mut Vec<u8>, value: &MetadataValue) {
    match value {
        MetadataValue::PoolState { next_object_id } => {
            out.push(1);
            put_u64(out, *next_object_id);
        }
        MetadataValue::Inode(inode) => {
            out.push(2);
            put_u64(out, inode.size);
            put_u32(out, inode.mode);
            put_u32(out, inode.uid);
            put_u32(out, inode.gid);
            put_u32(out, inode.nlink);
            put_u32(out, inode.attrs);
            put_i64(out, inode.crtime_ns);
            put_i64(out, inode.mtime_ns);
            put_i64(out, inode.ctime_ns);
            put_i64(out, inode.atime_ns);
        }
        MetadataValue::DirEntries(entries) => {
            out.push(3);
            put_u16(out, entries.len() as u16);
            for entry in entries {
                put_u64(out, entry.inode);
                out.push(entry.kind.to_u8());
                put_u16(out, entry.name.len() as u16);
                out.extend_from_slice(entry.name.as_bytes());
            }
        }
        MetadataValue::FileExtent {
            extents,
            data_offset,
            logical_len,
        } => {
            if let [extent] = extents.as_slice() {
                out.push(4);
                encode_extent(out, *extent);
            } else {
                out.push(6);
                out.push(extents.len() as u8);
                for extent in extents {
                    encode_extent(out, *extent);
                }
            }
            put_u64(out, *data_offset);
            put_u64(out, *logical_len);
        }
        MetadataValue::StripedExtent {
            extent,
            parity_extents,
            data_offset,
            logical_len,
        } => {
            out.push(8);
            encode_extent(out, *extent);
            out.push(parity_extents.len() as u8);
            for parity in parity_extents {
                encode_extent(out, *parity);
            }
            put_u64(out, *data_offset);
            put_u64(out, *logical_len);
        }
        MetadataValue::RetainedRoot {
            tx_id,
            metadata_roots,
            created_at_ns,
            name,
        } => {
            if let [root] = metadata_roots.as_slice() {
                out.push(5);
                put_u64(out, *tx_id);
                encode_extent(out, *root);
            } else {
                out.push(7);
                put_u64(out, *tx_id);
                out.push(metadata_roots.len() as u8);
                for root in metadata_roots {
                    encode_extent(out, *root);
                }
            }
            put_i64(out, *created_at_ns);
            put_u16(out, name.len() as u16);
            out.extend_from_slice(name.as_bytes());
        }
        MetadataValue::Special { data } => {
            out.push(SPECIAL_TAG);
            out.extend_from_slice(data);
        }
        MetadataValue::XattrEntries(entries) => {
            out.push(XATTR_TAG);
            put_u16(out, entries.len() as u16);
            for entry in entries {
                out.push(entry.name.len() as u8);
                out.extend_from_slice(entry.name.as_bytes());
                put_u16(out, entry.value.len() as u16);
                out.extend_from_slice(&entry.value);
            }
        }
        MetadataValue::Opaque { tag, data } => {
            out.push(*tag);
            out.extend_from_slice(data);
        }
    }
}

pub(crate) fn decode_value(cursor: &mut Cursor<'_>) -> Result<MetadataValue> {
    let value = match cursor.take_u8()? {
        1 => MetadataValue::PoolState {
            next_object_id: cursor.take_u64()?,
        },
        2 => MetadataValue::Inode(InodeAttrs {
            size: cursor.take_u64()?,
            mode: cursor.take_u32()?,
            uid: cursor.take_u32()?,
            gid: cursor.take_u32()?,
            nlink: cursor.take_u32()?,
            attrs: cursor.take_u32()?,
            crtime_ns: cursor.take_i64()?,
            mtime_ns: cursor.take_i64()?,
            ctime_ns: cursor.take_i64()?,
            atime_ns: cursor.take_i64()?,
        }),
        3 => {
            let count = cursor.take_u16()?;
            let mut entries = Vec::with_capacity(usize::from(count));
            for _ in 0..count {
                let inode = cursor.take_u64()?;
                let kind = EntryKind::from_u8(cursor.take_u8()?)?;
                let name_len = usize::from(cursor.take_u16()?);
                if name_len > MAX_NAME_LEN {
                    return Err(ScaleFsError::Corrupt("directory entry name length"));
                }
                let name = String::from_utf8(cursor.take(name_len)?.to_vec())
                    .map_err(|_| ScaleFsError::Corrupt("directory entry name is not UTF-8"))?;
                entries.push(DirEntry { inode, kind, name });
            }
            MetadataValue::DirEntries(entries)
        }
        4 => MetadataValue::FileExtent {
            extents: vec![decode_extent(cursor)?],
            data_offset: cursor.take_u64()?,
            logical_len: cursor.take_u64()?,
        },
        6 => {
            let copies = cursor.take_u8()?;
            if copies < 2 {
                return Err(ScaleFsError::Corrupt(
                    "mirrored file extent needs at least two copies",
                ));
            }
            let mut extents = Vec::with_capacity(usize::from(copies));
            for _ in 0..copies {
                extents.push(decode_extent(cursor)?);
            }
            MetadataValue::FileExtent {
                extents,
                data_offset: cursor.take_u64()?,
                logical_len: cursor.take_u64()?,
            }
        }
        8 => {
            let extent = decode_extent(cursor)?;
            let parity_count = cursor.take_u8()?;
            if parity_count == 0 {
                return Err(ScaleFsError::Corrupt(
                    "striped extent has no parity records",
                ));
            }
            let mut parity_extents = Vec::with_capacity(usize::from(parity_count));
            for _ in 0..parity_count {
                parity_extents.push(decode_extent(cursor)?);
            }
            MetadataValue::StripedExtent {
                extent,
                parity_extents,
                data_offset: cursor.take_u64()?,
                logical_len: cursor.take_u64()?,
            }
        }
        tag @ (5 | 7) => {
            let tx_id = cursor.take_u64()?;
            let copies = if tag == 7 {
                let copies = cursor.take_u8()?;
                if copies < 2 {
                    return Err(ScaleFsError::Corrupt(
                        "mirrored retained root needs at least two copies",
                    ));
                }
                usize::from(copies)
            } else {
                1
            };
            let mut metadata_roots = Vec::with_capacity(copies);
            for _ in 0..copies {
                metadata_roots.push(decode_extent(cursor)?);
            }
            let created_at_ns = cursor.take_i64()?;
            let name_len = usize::from(cursor.take_u16()?);
            if name_len > MAX_NAME_LEN {
                return Err(ScaleFsError::Corrupt("retained root name length"));
            }
            let name = String::from_utf8(cursor.take(name_len)?.to_vec())
                .map_err(|_| ScaleFsError::Corrupt("retained root name is not UTF-8"))?;
            MetadataValue::RetainedRoot {
                tx_id,
                metadata_roots,
                created_at_ns,
                name,
            }
        }
        SPECIAL_TAG => MetadataValue::Special {
            data: cursor.take(cursor.remaining())?.to_vec(),
        },
        XATTR_TAG => {
            let count = cursor.take_u16()?;
            let mut entries = Vec::with_capacity(usize::from(count));
            for _ in 0..count {
                let name_len = cursor.take_u8()?;
                let name = std::str::from_utf8(cursor.take(usize::from(name_len))?)
                    .map_err(|_| ScaleFsError::Corrupt("xattr name is not UTF-8"))?
                    .to_string();
                let value_len = cursor.take_u16()?;
                let value = cursor.take(usize::from(value_len))?.to_vec();
                entries.push(XattrEntry { name, value });
            }
            MetadataValue::XattrEntries(entries)
        }
        tag if tag >= TOLERATED_RANGE_MIN => MetadataValue::Opaque {
            tag,
            data: cursor.take(cursor.remaining())?.to_vec(),
        },
        _ => return Err(ScaleFsError::Corrupt("unknown metadata value tag")),
    };
    value.validate()?;
    Ok(value)
}

fn value_encoded_len(value: &MetadataValue) -> usize {
    let mut scratch = Vec::new();
    encode_value(&mut scratch, value);
    scratch.len()
}

pub(crate) fn encode_leaf_record(items: &[(MetadataKey, MetadataValue)]) -> Vec<u8> {
    let mut payload = Vec::new();
    put_u16(&mut payload, items.len() as u16);
    for (key, value) in items {
        encode_key(&mut payload, *key);
        let mut bytes = Vec::new();
        encode_value(&mut bytes, value);
        put_u16(&mut payload, bytes.len() as u16);
        payload.extend_from_slice(&bytes);
    }
    encode_record(RecordKind::MetadataLeaf, &payload)
}

pub(crate) fn decode_leaf_record(bytes: &[u8]) -> Result<Vec<(MetadataKey, MetadataValue)>> {
    let record = decode_record(bytes)?;
    if record.kind != RecordKind::MetadataLeaf {
        return Err(ScaleFsError::Corrupt("expected a metadata leaf record"));
    }
    let mut cursor = Cursor::new(&record.payload);
    let count = usize::from(cursor.take_u16()?);
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        let key = decode_key(&mut cursor)?;
        if let Some((previous, _)) = items.last()
            && *previous >= key
        {
            return Err(ScaleFsError::Corrupt("leaf keys are not strictly sorted"));
        }
        let value_len = usize::from(cursor.take_u16()?);
        if value_len > MAX_VALUE_LEN {
            return Err(ScaleFsError::Corrupt(
                "metadata value exceeds the size limit",
            ));
        }
        let value_bytes = cursor.take(value_len)?;
        let mut value_cursor = Cursor::new(value_bytes);
        let value = decode_value(&mut value_cursor)?;
        value_cursor.expect_end("metadata value has trailing bytes")?;
        items.push((key, value));
    }
    cursor.expect_end("leaf page has trailing bytes")?;
    Ok(items)
}

pub(crate) fn encode_internal_record(entries: &[(MetadataKey, Vec<Extent>)]) -> Vec<u8> {
    let mirrored = entries.iter().any(|(_, copies)| copies.len() > 1);
    let mut payload = Vec::new();
    put_u16(&mut payload, entries.len() as u16);
    for (separator, copies) in entries {
        encode_key(&mut payload, *separator);
        if mirrored {
            payload.push(copies.len() as u8);
        }
        for extent in copies {
            encode_extent(&mut payload, *extent);
        }
    }
    let kind = if mirrored {
        RecordKind::MetadataInternalMirrored
    } else {
        RecordKind::MetadataInternal
    };
    encode_record(kind, &payload)
}

pub(crate) fn decode_internal_record(bytes: &[u8]) -> Result<Vec<(MetadataKey, Vec<Extent>)>> {
    let record = decode_record(bytes)?;
    let mirrored = match record.kind {
        RecordKind::MetadataInternal => false,
        RecordKind::MetadataInternalMirrored => true,
        _ => return Err(ScaleFsError::Corrupt("expected a metadata internal record")),
    };
    let mut cursor = Cursor::new(&record.payload);
    let count = usize::from(cursor.take_u16()?);
    if count < 2 {
        return Err(ScaleFsError::Corrupt(
            "internal page has fewer than two children",
        ));
    }
    let mut entries: Vec<(MetadataKey, Vec<Extent>)> = Vec::with_capacity(count);
    for _ in 0..count {
        let separator = decode_key(&mut cursor)?;
        if let Some((previous, _)) = entries.last()
            && *previous >= separator
        {
            return Err(ScaleFsError::Corrupt(
                "internal separators are not strictly sorted",
            ));
        }
        let copy_count = if mirrored {
            let copies = cursor.take_u8()?;
            if copies == 0 {
                return Err(ScaleFsError::Corrupt("child has no copies"));
            }
            usize::from(copies)
        } else {
            1
        };
        let mut copies = Vec::with_capacity(copy_count);
        let mut members = std::collections::HashSet::new();
        for _ in 0..copy_count {
            let extent = decode_extent(&mut cursor)?;
            if extent.length == 0 {
                return Err(ScaleFsError::Corrupt("internal child extent is empty"));
            }
            if copies
                .first()
                .is_some_and(|f: &Extent| f.length != extent.length)
            {
                return Err(ScaleFsError::Corrupt(
                    "child copies must have equal lengths",
                ));
            }
            if !members.insert(extent.device_index) {
                return Err(ScaleFsError::Corrupt(
                    "child copies must live on distinct members",
                ));
            }
            copies.push(extent);
        }
        entries.push((separator, copies));
    }
    cursor.expect_end("internal page has trailing bytes")?;
    Ok(entries)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PagePlan {
    pub extents: Vec<Extent>,
    pub bytes: Vec<u8>,
}

#[derive(Debug)]
enum Node {
    Leaf {
        items: Vec<(MetadataKey, MetadataValue)>,
        disk: Option<Vec<Extent>>,
    },
    Internal {
        children: Vec<(MetadataKey, Node)>,
        disk: Option<Vec<Extent>>,
    },
}

impl Node {
    fn empty_leaf() -> Self {
        Node::Leaf {
            items: Vec::new(),
            disk: None,
        }
    }

    fn min_key(&self) -> Option<MetadataKey> {
        match self {
            Node::Leaf { items, .. } => items.first().map(|(k, _)| *k),
            Node::Internal { children, .. } => children.first().map(|(k, _)| *k),
        }
    }

    fn max_key(&self) -> Option<MetadataKey> {
        match self {
            Node::Leaf { items, .. } => items.last().map(|(k, _)| *k),
            Node::Internal { children, .. } => children.last().and_then(|(_, c)| c.max_key()),
        }
    }

    fn is_empty(&self) -> bool {
        match self {
            Node::Leaf { items, .. } => items.is_empty(),
            Node::Internal { children, .. } => children.is_empty(),
        }
    }

    fn mark_dirty(&mut self) {
        match self {
            Node::Leaf { disk, .. } | Node::Internal { disk, .. } => *disk = None,
        }
    }
}

fn child_index(children: &[(MetadataKey, Node)], key: MetadataKey) -> usize {
    children
        .partition_point(|(separator, _)| *separator <= key)
        .saturating_sub(1)
}

fn leaf_encoded_payload_len(items: &[(MetadataKey, MetadataValue)]) -> usize {
    2 + items
        .iter()
        .map(|(_, v)| 17 + 2 + value_encoded_len(v))
        .sum::<usize>()
}

#[derive(Debug)]
pub struct MetadataTree {
    root: Node,
}

impl Default for MetadataTree {
    fn default() -> Self {
        Self::new()
    }
}

impl MetadataTree {
    pub fn new() -> Self {
        Self {
            root: Node::empty_leaf(),
        }
    }

    pub fn get(&self, key: MetadataKey) -> Option<&MetadataValue> {
        let mut node = &self.root;
        loop {
            match node {
                Node::Leaf { items, .. } => {
                    return items
                        .binary_search_by(|(k, _)| k.cmp(&key))
                        .ok()
                        .map(|i| &items[i].1);
                }
                Node::Internal { children, .. } => {
                    node = &children[child_index(children, key)].1;
                }
            }
        }
    }

    pub fn insert(&mut self, key: MetadataKey, value: MetadataValue) -> Result<()> {
        value.validate()?;
        if value_encoded_len(&value) > MAX_VALUE_LEN {
            return Err(ScaleFsError::InvalidArgument(
                "metadata value exceeds the size limit",
            ));
        }
        if let Some((split_key, right)) = Self::insert_into(&mut self.root, key, value) {
            let old_root = std::mem::replace(&mut self.root, Node::empty_leaf());
            let left_key = old_root.min_key().expect("split left half is nonempty");
            self.root = Node::Internal {
                children: vec![(left_key, old_root), (split_key, right)],
                disk: None,
            };
        }
        Ok(())
    }

    fn insert_into(
        node: &mut Node,
        key: MetadataKey,
        value: MetadataValue,
    ) -> Option<(MetadataKey, Node)> {
        node.mark_dirty();
        match node {
            Node::Leaf { items, .. } => {
                match items.binary_search_by(|(k, _)| k.cmp(&key)) {
                    Ok(i) => items[i].1 = value,
                    Err(i) => items.insert(i, (key, value)),
                }
                if leaf_encoded_payload_len(items) <= LEAF_SPLIT_BYTES || items.len() < 2 {
                    return None;
                }
                let total: usize = leaf_encoded_payload_len(items);
                let mut running = 2;
                let mut split_at = 1;
                for (i, (_, v)) in items.iter().enumerate() {
                    running += 17 + 2 + value_encoded_len(v);
                    if running >= total / 2 {
                        split_at = (i + 1).clamp(1, items.len() - 1);
                        break;
                    }
                }
                let right_items = items.split_off(split_at);
                let split_key = right_items[0].0;
                Some((
                    split_key,
                    Node::Leaf {
                        items: right_items,
                        disk: None,
                    },
                ))
            }
            Node::Internal { children, .. } => {
                let idx = child_index(children, key);
                let spawned = Self::insert_into(&mut children[idx].1, key, value);
                children[idx].0 = children[idx].1.min_key().expect("child is nonempty");
                if let Some((split_key, right)) = spawned {
                    children.insert(idx + 1, (split_key, right));
                }
                if children.len() <= INTERNAL_MAX_CHILDREN {
                    return None;
                }
                let right_children = children.split_off(children.len() / 2);
                let split_key = right_children[0].0;
                Some((
                    split_key,
                    Node::Internal {
                        children: right_children,
                        disk: None,
                    },
                ))
            }
        }
    }

    pub fn remove(&mut self, key: MetadataKey) -> Option<MetadataValue> {
        let removed = Self::remove_from(&mut self.root, key);
        loop {
            match &mut self.root {
                Node::Internal { children, .. } if children.len() == 1 => {
                    let (_, child) = children.pop().expect("length checked");
                    self.root = child;
                }
                Node::Internal { children, .. } if children.is_empty() => {
                    self.root = Node::empty_leaf();
                }
                _ => break,
            }
        }
        removed
    }

    fn remove_from(node: &mut Node, key: MetadataKey) -> Option<MetadataValue> {
        match node {
            Node::Leaf { items, disk } => match items.binary_search_by(|(k, _)| k.cmp(&key)) {
                Ok(i) => {
                    *disk = None;
                    Some(items.remove(i).1)
                }
                Err(_) => None,
            },
            Node::Internal { children, disk } => {
                let idx = child_index(children, key);
                let removed = Self::remove_from(&mut children[idx].1, key)?;
                *disk = None;
                if children[idx].1.is_empty() {
                    children.remove(idx);
                } else {
                    let lifted = match &mut children[idx].1 {
                        Node::Internal {
                            children: grand, ..
                        } if grand.len() == 1 => Some(grand.pop().expect("length checked")),
                        _ => None,
                    };
                    if let Some((k, n)) = lifted {
                        children[idx] = (k, n);
                    }
                    children[idx].0 = children[idx].1.min_key().expect("child is nonempty");
                }
                Some(removed)
            }
        }
    }

    pub fn range(
        &self,
        start: MetadataKey,
        end: MetadataKey,
    ) -> Vec<(MetadataKey, &MetadataValue)> {
        let mut out = Vec::new();
        Self::collect_range(&self.root, start, end, &mut out);
        out
    }

    fn collect_range<'a>(
        node: &'a Node,
        start: MetadataKey,
        end: MetadataKey,
        out: &mut Vec<(MetadataKey, &'a MetadataValue)>,
    ) {
        match node {
            Node::Leaf { items, .. } => {
                let from = items.partition_point(|(k, _)| *k < start);
                for (key, value) in &items[from..] {
                    if *key > end {
                        break;
                    }
                    out.push((*key, value));
                }
            }
            Node::Internal { children, .. } => {
                let from = child_index(children, start);
                for (separator, child) in &children[from..] {
                    if *separator > end {
                        break;
                    }
                    Self::collect_range(child, start, end, out);
                }
            }
        }
    }

    pub(crate) fn mark_all_dirty(&mut self) {
        fn walk(node: &mut Node) {
            node.mark_dirty();
            if let Node::Internal { children, .. } = node {
                for (_, child) in children {
                    walk(child);
                }
            }
        }
        walk(&mut self.root);
    }

    pub fn item_count(&self) -> usize {
        fn count(node: &Node) -> usize {
            match node {
                Node::Leaf { items, .. } => items.len(),
                Node::Internal { children, .. } => children.iter().map(|(_, c)| count(c)).sum(),
            }
        }
        count(&self.root)
    }

    pub fn plan_commit(
        &mut self,
        place: &mut dyn FnMut(u64) -> Result<Vec<(u16, u64)>>,
    ) -> Result<(Vec<Extent>, Vec<PagePlan>)> {
        let mut pages = Vec::new();
        let root = Self::plan_node(&mut self.root, place, &mut pages)?;
        Ok((root, pages))
    }

    fn plan_node(
        node: &mut Node,
        place: &mut dyn FnMut(u64) -> Result<Vec<(u16, u64)>>,
        pages: &mut Vec<PagePlan>,
    ) -> Result<Vec<Extent>> {
        match node {
            Node::Leaf { items, disk } => {
                if let Some(extents) = disk {
                    return Ok(extents.clone());
                }
                let bytes = encode_leaf_record(items);
                let extents = place_copies(place, bytes.len() as u64)?;
                *disk = Some(extents.clone());
                pages.push(PagePlan {
                    extents: extents.clone(),
                    bytes,
                });
                Ok(extents)
            }
            Node::Internal { children, disk } => {
                if let Some(extents) = disk {
                    return Ok(extents.clone());
                }
                let mut entries = Vec::with_capacity(children.len());
                for (separator, child) in children.iter_mut() {
                    let child_extents = Self::plan_node(child, place, pages)?;
                    *separator = child.min_key().expect("child is nonempty");
                    entries.push((*separator, child_extents));
                }
                let bytes = encode_internal_record(&entries);
                let extents = place_copies(place, bytes.len() as u64)?;
                *disk = Some(extents.clone());
                pages.push(PagePlan {
                    extents: extents.clone(),
                    bytes,
                });
                Ok(extents)
            }
        }
    }

    pub fn load(
        root: &[Extent],
        read: &mut dyn FnMut(&[Extent]) -> Result<Vec<u8>>,
    ) -> Result<MetadataTree> {
        let root = Self::load_node(root, read, true)?;
        Ok(MetadataTree { root })
    }

    fn load_node(
        extents: &[Extent],
        read: &mut dyn FnMut(&[Extent]) -> Result<Vec<u8>>,
        is_root: bool,
    ) -> Result<Node> {
        let bytes = read(extents)?;
        let record = decode_record(&bytes)?;
        match record.kind {
            RecordKind::MetadataLeaf => {
                let items = decode_leaf_record(&bytes)?;
                if items.is_empty() && !is_root {
                    return Err(ScaleFsError::Corrupt("empty leaf below the root"));
                }
                Ok(Node::Leaf {
                    items,
                    disk: Some(extents.to_vec()),
                })
            }
            RecordKind::MetadataInternal | RecordKind::MetadataInternalMirrored => {
                let entries = decode_internal_record(&bytes)?;
                let mut children = Vec::with_capacity(entries.len());
                for (i, (separator, child_extents)) in entries.iter().enumerate() {
                    let child = Self::load_node(child_extents, read, false)?;
                    if child.min_key() != Some(*separator) {
                        return Err(ScaleFsError::Corrupt(
                            "child page does not start at its separator",
                        ));
                    }
                    if let Some(next) = entries.get(i + 1)
                        && child.max_key() >= Some(next.0)
                    {
                        return Err(ScaleFsError::Corrupt(
                            "child page overlaps the next separator",
                        ));
                    }
                    children.push((*separator, child));
                }
                Ok(Node::Internal {
                    children,
                    disk: Some(extents.to_vec()),
                })
            }
            _ => Err(ScaleFsError::Corrupt("expected a metadata page record")),
        }
    }
}

fn place_copies(
    place: &mut dyn FnMut(u64) -> Result<Vec<(u16, u64)>>,
    len: u64,
) -> Result<Vec<Extent>> {
    let placements = place(len)?;
    debug_assert!(!placements.is_empty(), "placement must return a copy");
    Ok(placements
        .into_iter()
        .map(|(device_index, offset)| Extent {
            device_index,
            offset,
            length: len,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::XorShift64;
    use std::collections::HashMap;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn inode_key(object_id: u64) -> MetadataKey {
        MetadataKey {
            object_id,
            item_type: ITEM_INODE,
            offset: 0,
        }
    }

    fn fixture_inode(size: u64) -> MetadataValue {
        MetadataValue::Inode(InodeAttrs {
            size,
            mode: 0o100644,
            uid: 1000,
            gid: 1000,
            nlink: 1,
            attrs: FILE_ATTR_ARCHIVE,
            crtime_ns: 1_700_000_000_000_000_000,
            mtime_ns: 1_700_000_000_000_000_000,
            ctime_ns: 1_700_000_000_000_000_000,
            atime_ns: 1_700_000_000_000_000_000,
        })
    }

    struct PageStore {
        pages: HashMap<(u16, u64), Vec<u8>>,
        next_offset: u64,
    }

    impl PageStore {
        fn new() -> Self {
            Self {
                pages: HashMap::new(),
                next_offset: 4096,
            }
        }

        fn write_plan(&mut self, pages: &[PagePlan]) {
            for page in pages {
                for extent in &page.extents {
                    self.pages
                        .insert((extent.device_index, extent.offset), page.bytes.clone());
                }
            }
        }

        fn read(&self) -> impl FnMut(&[Extent]) -> Result<Vec<u8>> {
            let pages = self.pages.clone();
            move |copies| {
                let extent = copies[0];
                pages
                    .get(&(extent.device_index, extent.offset))
                    .cloned()
                    .ok_or(ScaleFsError::Corrupt("missing page"))
            }
        }
    }

    fn commit(tree: &mut MetadataTree, store: &mut PageStore) -> (Vec<Extent>, usize) {
        let mut place = {
            let next = &mut store.next_offset;
            move |len: u64| {
                let offset = *next;
                *next += len.div_ceil(4096) * 4096;
                Ok(vec![(0u16, offset)])
            }
        };
        let (root, pages) = tree.plan_commit(&mut place).unwrap();
        store.write_plan(&pages);
        (root, pages.len())
    }

    #[test]
    fn insert_get_overwrite_remove() {
        let mut tree = MetadataTree::new();
        tree.insert(inode_key(5), fixture_inode(100)).unwrap();
        assert_eq!(tree.get(inode_key(5)), Some(&fixture_inode(100)));
        tree.insert(inode_key(5), fixture_inode(200)).unwrap();
        assert_eq!(tree.get(inode_key(5)), Some(&fixture_inode(200)));
        assert_eq!(tree.remove(inode_key(5)), Some(fixture_inode(200)));
        assert_eq!(tree.get(inode_key(5)), None);
        assert_eq!(tree.remove(inode_key(5)), None);
    }

    #[test]
    fn thousands_of_items_stay_sorted_through_splits() {
        let mut tree = MetadataTree::new();
        let mut rng = XorShift64::new(7);
        let mut ids: Vec<u64> = (1..=3000).collect();
        for i in (1..ids.len()).rev() {
            let j = (rng.next_u64() % (i as u64 + 1)) as usize;
            ids.swap(i, j);
        }
        for &id in &ids {
            tree.insert(inode_key(id), fixture_inode(id)).unwrap();
        }
        assert_eq!(tree.item_count(), 3000);
        let all = tree.range(MetadataKey::MIN, MetadataKey::MAX);
        assert_eq!(all.len(), 3000);
        for (i, (key, value)) in all.iter().enumerate() {
            assert_eq!(key.object_id, i as u64 + 1);
            assert_eq!(**value, fixture_inode(i as u64 + 1));
        }
        assert_eq!(tree.get(inode_key(1)), Some(&fixture_inode(1)));
        assert_eq!(tree.get(inode_key(2999)), Some(&fixture_inode(2999)));
    }

    #[test]
    fn removals_shrink_back_to_an_empty_root() {
        let mut tree = MetadataTree::new();
        for id in 1..=2000 {
            tree.insert(inode_key(id), fixture_inode(id)).unwrap();
        }
        for id in 1..=2000 {
            assert!(tree.remove(inode_key(id)).is_some(), "id {id}");
        }
        assert_eq!(tree.item_count(), 0);
        tree.insert(inode_key(1), fixture_inode(1)).unwrap();
        assert_eq!(tree.get(inode_key(1)), Some(&fixture_inode(1)));
    }

    #[test]
    fn range_scans_are_bounded() {
        let mut tree = MetadataTree::new();
        for id in 1..=100 {
            tree.insert(inode_key(id), fixture_inode(id)).unwrap();
        }
        let some = tree.range(inode_key(10), inode_key(19));
        assert_eq!(some.len(), 10);
        assert_eq!(some[0].0.object_id, 10);
        assert_eq!(some[9].0.object_id, 19);
    }

    #[test]
    fn commit_writes_only_dirty_pages() {
        let mut tree = MetadataTree::new();
        for id in 1..=3000 {
            tree.insert(inode_key(id), fixture_inode(id)).unwrap();
        }
        let mut store = PageStore::new();
        let (root1, first_pages) = commit(&mut tree, &mut store);
        assert!(first_pages > 10, "expected a multi-page tree");

        let (root2, second_pages) = commit(&mut tree, &mut store);
        assert_eq!(second_pages, 0);
        assert_eq!(root2, root1);

        tree.insert(inode_key(1500), fixture_inode(9999)).unwrap();
        let (root3, third_pages) = commit(&mut tree, &mut store);
        assert_ne!(root3, root1);
        assert!(
            (2..=4).contains(&third_pages),
            "path copy should touch the leaf and its ancestors, wrote {third_pages}"
        );

        let loaded = MetadataTree::load(&root3, &mut store.read()).unwrap();
        assert_eq!(loaded.item_count(), 3000);
        assert_eq!(loaded.get(inode_key(1500)), Some(&fixture_inode(9999)));
        assert_eq!(loaded.get(inode_key(42)), Some(&fixture_inode(42)));
    }

    #[test]
    fn loaded_trees_continue_with_incremental_commits() {
        let mut tree = MetadataTree::new();
        for id in 1..=3000 {
            tree.insert(inode_key(id), fixture_inode(id)).unwrap();
        }
        let mut store = PageStore::new();
        let (root, _) = commit(&mut tree, &mut store);

        let mut reloaded = MetadataTree::load(&root, &mut store.read()).unwrap();
        let (same_root, pages) = commit(&mut reloaded, &mut store);
        assert_eq!(pages, 0);
        assert_eq!(same_root, root);
        reloaded.insert(inode_key(7), fixture_inode(7000)).unwrap();
        let (_, pages) = commit(&mut reloaded, &mut store);
        assert!((2..=4).contains(&pages), "wrote {pages}");
    }

    #[test]
    fn empty_tree_commits_and_loads() {
        let mut tree = MetadataTree::new();
        let mut store = PageStore::new();
        let (root, pages) = commit(&mut tree, &mut store);
        assert_eq!(pages, 1);
        let loaded = MetadataTree::load(&root, &mut store.read()).unwrap();
        assert_eq!(loaded.item_count(), 0);
    }

    #[test]
    fn corrupted_pages_fail_to_load() {
        let mut tree = MetadataTree::new();
        for id in 1..=3000 {
            tree.insert(inode_key(id), fixture_inode(id)).unwrap();
        }
        let mut store = PageStore::new();
        let (root, _) = commit(&mut tree, &mut store);

        let keys: Vec<(u16, u64)> = store.pages.keys().copied().collect();
        for key in keys {
            let mut corrupted = store.pages.clone();
            let page = corrupted.get_mut(&key).unwrap();
            let mid = page.len() / 2;
            page[mid] ^= 0xFF;
            let mut read = move |copies: &[Extent]| {
                let extent = copies[0];
                corrupted
                    .get(&(extent.device_index, extent.offset))
                    .cloned()
                    .ok_or(ScaleFsError::Corrupt("missing page"))
            };
            assert!(MetadataTree::load(&root, &mut read).is_err());
        }
    }

    #[test]
    fn oversized_values_are_rejected() {
        let mut tree = MetadataTree::new();
        let entries: Vec<DirEntry> = (0..20)
            .map(|i| DirEntry {
                inode: i + 2,
                kind: EntryKind::File,
                name: format!("{}{i}", "x".repeat(250)),
            })
            .collect();
        let value = MetadataValue::DirEntries(entries);
        let key = MetadataKey {
            object_id: 1,
            item_type: ITEM_DIRENT,
            offset: 1,
        };
        assert!(matches!(
            tree.insert(key, value),
            Err(ScaleFsError::InvalidArgument(_))
        ));
    }

    #[test]
    fn value_validation_rejects_bad_contents() {
        for value in [
            MetadataValue::PoolState { next_object_id: 1 },
            MetadataValue::DirEntries(vec![]),
            MetadataValue::DirEntries(vec![DirEntry {
                inode: 2,
                kind: EntryKind::File,
                name: "bad/name".into(),
            }]),
            MetadataValue::DirEntries(vec![DirEntry {
                inode: 2,
                kind: EntryKind::File,
                name: "..".into(),
            }]),
            MetadataValue::FileExtent {
                extents: vec![Extent {
                    device_index: 0,
                    offset: 0,
                    length: 100,
                }],
                data_offset: 0,
                logical_len: 0,
            },
            MetadataValue::FileExtent {
                extents: vec![Extent {
                    device_index: 0,
                    offset: 0,
                    length: 100,
                }],
                data_offset: 0,
                logical_len: 69,
            },
            MetadataValue::FileExtent {
                extents: vec![Extent {
                    device_index: 0,
                    offset: 0,
                    length: 100,
                }],
                data_offset: 60,
                logical_len: 20,
            },
            MetadataValue::FileExtent {
                extents: vec![
                    Extent {
                        device_index: 0,
                        offset: 0,
                        length: 100,
                    },
                    Extent {
                        device_index: 0,
                        offset: 4096,
                        length: 100,
                    },
                ],
                data_offset: 0,
                logical_len: 20,
            },
            MetadataValue::FileExtent {
                extents: vec![
                    Extent {
                        device_index: 0,
                        offset: 0,
                        length: 100,
                    },
                    Extent {
                        device_index: 1,
                        offset: 0,
                        length: 132,
                    },
                ],
                data_offset: 0,
                logical_len: 20,
            },
        ] {
            assert!(value.validate().is_err(), "{value:?}");
        }
    }

    fn fixture_striped(parity_members: &[u16]) -> MetadataValue {
        MetadataValue::StripedExtent {
            extent: Extent {
                device_index: 2,
                offset: 1 << 20,
                length: 100,
            },
            parity_extents: parity_members
                .iter()
                .map(|&member| Extent {
                    device_index: member,
                    offset: 1 << 21,
                    length: 4096,
                })
                .collect(),
            data_offset: 4,
            logical_len: 32,
        }
    }

    #[test]
    fn striped_extents_round_trip_and_validate() {
        let key = MetadataKey {
            object_id: 5,
            item_type: ITEM_FILE_EXTENT,
            offset: 0,
        };
        let value = fixture_striped(&[0, 4]);
        let record = encode_leaf_record(&[(key, value.clone())]);
        assert_eq!(decode_leaf_record(&record).unwrap(), vec![(key, value)]);

        let mutate = |f: &dyn Fn(&mut MetadataValue)| {
            let mut value = fixture_striped(&[0, 4]);
            f(&mut value);
            value.validate()
        };
        for (name, mutation) in [
            (
                "no parity records",
                &(|v: &mut MetadataValue| {
                    if let MetadataValue::StripedExtent { parity_extents, .. } = v {
                        parity_extents.clear();
                    }
                }) as &dyn Fn(&mut MetadataValue),
            ),
            ("too many parity records", &|v: &mut MetadataValue| {
                if let MetadataValue::StripedExtent { parity_extents, .. } = v {
                    for member in 5..=6 {
                        let mut extra = parity_extents[0];
                        extra.device_index = member;
                        parity_extents.push(extra);
                    }
                }
            }),
            ("unequal parity lengths", &|v: &mut MetadataValue| {
                if let MetadataValue::StripedExtent { parity_extents, .. } = v {
                    parity_extents[1].length += 1;
                }
            }),
            ("parity on the data member", &|v: &mut MetadataValue| {
                if let MetadataValue::StripedExtent {
                    extent,
                    parity_extents,
                    ..
                } = v
                {
                    parity_extents[0].device_index = extent.device_index;
                }
            }),
            ("duplicate parity members", &|v: &mut MetadataValue| {
                if let MetadataValue::StripedExtent { parity_extents, .. } = v {
                    parity_extents[1].device_index = parity_extents[0].device_index;
                }
            }),
            ("zero logical length", &|v: &mut MetadataValue| {
                if let MetadataValue::StripedExtent { logical_len, .. } = v {
                    *logical_len = 0;
                }
            }),
            ("range outside the record", &|v: &mut MetadataValue| {
                if let MetadataValue::StripedExtent {
                    data_offset,
                    logical_len,
                    ..
                } = v
                {
                    *data_offset = 60;
                    *logical_len = 20;
                }
            }),
        ] {
            assert!(
                matches!(mutate(mutation), Err(ScaleFsError::Corrupt(_))),
                "{name}"
            );
        }
    }

    #[test]
    fn golden_striped_leaf_fixture_is_stable() {
        let key = MetadataKey {
            object_id: 5,
            item_type: ITEM_FILE_EXTENT,
            offset: 32768,
        };
        let record = encode_leaf_record(&[(key, fixture_striped(&[0, 4]))]);
        assert_eq!(
            hex(&record),
            "5363616c654653000100000003000000630000000000000074317a7600000000010005000000000000000300800000000000004e00080200000000001000000000006400000000000000020000000000002000000000000010000000000000040000000000200000000000001000000000000004000000000000002000000000000000"
        );
    }

    #[test]
    fn leaf_decode_rejects_unsorted_keys_and_unknown_tags() {
        let a = (inode_key(2), fixture_inode(1));
        let b = (inode_key(1), fixture_inode(1));
        let mut payload = Vec::new();
        put_u16(&mut payload, 2);
        for (key, value) in [&a, &b] {
            encode_key(&mut payload, *key);
            let mut bytes = Vec::new();
            encode_value(&mut bytes, value);
            put_u16(&mut payload, bytes.len() as u16);
            payload.extend_from_slice(&bytes);
        }
        let record = encode_record(RecordKind::MetadataLeaf, &payload);
        assert!(decode_leaf_record(&record).is_err());

        let mut payload = Vec::new();
        put_u16(&mut payload, 1);
        encode_key(&mut payload, inode_key(1));
        put_u16(&mut payload, 1);
        payload.push(100);
        let record = encode_record(RecordKind::MetadataLeaf, &payload);
        assert!(decode_leaf_record(&record).is_err());
    }

    #[test]
    fn tolerated_tags_decode_as_opaque_values() {
        let opaque = MetadataValue::Opaque {
            tag: 200,
            data: b"future feature bytes".to_vec(),
        };
        let key = MetadataKey {
            object_id: 7,
            item_type: 9,
            offset: 0,
        };
        let record = encode_leaf_record(&[(key, opaque.clone())]);
        assert_eq!(decode_leaf_record(&record).unwrap(), vec![(key, opaque)]);

        let record = encode_leaf_record(&[(
            inode_key(1),
            MetadataValue::Opaque {
                tag: 130,
                data: Vec::new(),
            },
        )]);
        assert!(decode_leaf_record(&record).is_ok());

        assert!(
            MetadataValue::Opaque {
                tag: 5,
                data: Vec::new(),
            }
            .validate()
            .is_err()
        );

        let bucket = MetadataValue::XattrEntries(vec![
            XattrEntry {
                name: "security.capability".to_string(),
                value: vec![1, 2, 3],
            },
            XattrEntry {
                name: "user.origin".to_string(),
                value: Vec::new(),
            },
        ]);
        let record = encode_leaf_record(&[(inode_key(2), bucket.clone())]);
        assert_eq!(
            decode_leaf_record(&record).unwrap(),
            vec![(inode_key(2), bucket)]
        );
        assert!(
            MetadataValue::XattrEntries(vec![
                XattrEntry {
                    name: "user.b".to_string(),
                    value: Vec::new(),
                },
                XattrEntry {
                    name: "user.a".to_string(),
                    value: Vec::new(),
                },
            ])
            .validate()
            .is_err(),
            "unsorted bucket names must refuse"
        );
        assert!(
            MetadataValue::XattrEntries(vec![XattrEntry {
                name: "user.big".to_string(),
                value: vec![0u8; XATTR_VALUE_MAX + 1],
            }])
            .validate()
            .is_err(),
            "an oversized value must refuse"
        );
    }

    #[test]
    fn tolerated_entry_kinds_are_preserved() {
        let bucket = MetadataValue::DirEntries(vec![DirEntry {
            inode: 9,
            kind: EntryKind::Unknown(200),
            name: "made-by-the-future".into(),
        }]);
        let key = MetadataKey {
            object_id: 1,
            item_type: ITEM_DIRENT,
            offset: 42,
        };
        let record = encode_leaf_record(&[(key, bucket.clone())]);
        assert_eq!(decode_leaf_record(&record).unwrap(), vec![(key, bucket)]);

        let mut payload = Vec::new();
        put_u16(&mut payload, 1);
        encode_key(&mut payload, inode_key(1));
        let mut value = Vec::new();
        value.push(3);
        put_u16(&mut value, 1);
        put_u64(&mut value, 9);
        value.push(3);
        put_u16(&mut value, 1);
        value.push(b'x');
        put_u16(&mut payload, value.len() as u16);
        payload.extend_from_slice(&value);
        let record = encode_record(RecordKind::MetadataLeaf, &payload);
        assert!(decode_leaf_record(&record).is_err());

        assert!(
            MetadataValue::DirEntries(vec![DirEntry {
                inode: 9,
                kind: EntryKind::Unknown(2),
                name: "x".into(),
            }])
            .validate()
            .is_err()
        );
    }

    #[test]
    fn special_file_entry_kinds_round_trip() {
        for (kind, byte) in [
            (EntryKind::Symlink, 128u8),
            (EntryKind::Fifo, 129),
            (EntryKind::Socket, 130),
            (EntryKind::CharDevice, 131),
            (EntryKind::BlockDevice, 132),
        ] {
            assert_eq!(kind.to_u8(), byte);
            assert_eq!(EntryKind::from_u8(byte).unwrap(), kind);
        }
        assert_eq!(EntryKind::from_u8(133).unwrap(), EntryKind::Unknown(133));
        assert!(
            MetadataValue::DirEntries(vec![DirEntry {
                inode: 9,
                kind: EntryKind::Unknown(130),
                name: "x".into(),
            }])
            .validate()
            .is_err()
        );
    }

    #[test]
    fn special_value_round_trips_and_stays_tolerated() {
        let key = MetadataKey {
            object_id: 42,
            item_type: ITEM_SPECIAL,
            offset: 0,
        };
        let target = MetadataValue::Special {
            data: b"../elsewhere".to_vec(),
        };
        let record = encode_leaf_record(&[(key, target.clone())]);
        assert_eq!(decode_leaf_record(&record).unwrap(), vec![(key, target)]);

        let mut value = Vec::new();
        encode_value(
            &mut value,
            &MetadataValue::Special {
                data: b"../elsewhere".to_vec(),
            },
        );
        assert_eq!(value[0], SPECIAL_TAG);
        assert_eq!(&value[1..], b"../elsewhere");

        let dev = MetadataValue::Special {
            data: 0x0000_0100_0000_0003u64.to_le_bytes().to_vec(),
        };
        let dev_key = MetadataKey {
            object_id: 10,
            item_type: ITEM_SPECIAL,
            offset: 0,
        };
        let record = encode_leaf_record(&[(dev_key, dev.clone())]);
        assert_eq!(decode_leaf_record(&record).unwrap(), vec![(dev_key, dev)]);
    }

    #[test]
    fn golden_special_fixture_is_stable() {
        let record = encode_leaf_record(&[(
            MetadataKey {
                object_id: 9,
                item_type: ITEM_SPECIAL,
                offset: 0,
            },
            MetadataValue::Special {
                data: b"../b".to_vec(),
            },
        )]);
        assert_eq!(
            hex(&record),
            "5363616c6546530001000000030000001a00000000000000\
             c7ce0bf800000000010009000000000000000500000000000000000500802e2e2f62"
        );
    }

    #[test]
    fn leaf_decode_rejects_oversized_values() {
        let mut payload = Vec::new();
        put_u16(&mut payload, 1);
        encode_key(&mut payload, inode_key(1));
        let oversized = MAX_VALUE_LEN + 1;
        put_u16(&mut payload, oversized as u16);
        payload.push(200);
        payload.extend_from_slice(&vec![0u8; oversized - 1]);
        let record = encode_record(RecordKind::MetadataLeaf, &payload);
        assert!(matches!(
            decode_leaf_record(&record),
            Err(ScaleFsError::Corrupt(
                "metadata value exceeds the size limit"
            ))
        ));
    }

    #[test]
    fn golden_opaque_fixture_is_stable() {
        let record = encode_leaf_record(&[(
            MetadataKey {
                object_id: 7,
                item_type: 9,
                offset: 0,
            },
            MetadataValue::Opaque {
                tag: 0xC8,
                data: b"ext".to_vec(),
            },
        )]);
        assert_eq!(
            hex(&record),
            "5363616c6546530001000000030000001900000000000000df5cdf2b00000000010007000000000000000900000000000000000400c8657874"
        );
        let decoded = decode_leaf_record(&record).unwrap();
        assert_eq!(
            decoded[0].1,
            MetadataValue::Opaque {
                tag: 0xC8,
                data: b"ext".to_vec(),
            }
        );
    }

    #[test]
    fn internal_decode_rejects_undersized_and_unsorted_pages() {
        let extent = Extent {
            device_index: 0,
            offset: 4096,
            length: 100,
        };
        let record = encode_internal_record(&[(inode_key(1), vec![extent])]);
        assert!(decode_internal_record(&record).is_err());
        let record =
            encode_internal_record(&[(inode_key(2), vec![extent]), (inode_key(1), vec![extent])]);
        assert!(decode_internal_record(&record).is_err());
    }

    #[test]
    fn golden_leaf_fixture_is_stable() {
        let items = vec![
            (
                MetadataKey {
                    object_id: 0,
                    item_type: ITEM_POOL_STATE,
                    offset: 0,
                },
                MetadataValue::PoolState { next_object_id: 3 },
            ),
            (
                MetadataKey {
                    object_id: 0,
                    item_type: ITEM_RETAINED_ROOT,
                    offset: 42,
                },
                MetadataValue::RetainedRoot {
                    tx_id: 3,
                    metadata_roots: vec![Extent {
                        device_index: 0,
                        offset: 67_117_056,
                        length: 4128,
                    }],
                    created_at_ns: 1_700_000_000_000_000_000,
                    name: "before-upgrade".into(),
                },
            ),
            (
                inode_key(ROOT_INODE),
                MetadataValue::Inode(InodeAttrs {
                    size: 0,
                    mode: 0o040755,
                    uid: 0,
                    gid: 0,
                    nlink: 1,
                    attrs: 0,
                    crtime_ns: 1_700_000_000_000_000_000,
                    mtime_ns: 1_700_000_000_000_000_000,
                    ctime_ns: 1_700_000_000_000_000_000,
                    atime_ns: 1_700_000_000_000_000_000,
                }),
            ),
            (
                MetadataKey {
                    object_id: 1,
                    item_type: ITEM_DIRENT,
                    offset: 0x0102_0304_0506_0708,
                },
                MetadataValue::DirEntries(vec![DirEntry {
                    inode: 2,
                    kind: EntryKind::File,
                    name: "hello.txt".into(),
                }]),
            ),
            (inode_key(2), fixture_inode(4000)),
            (
                MetadataKey {
                    object_id: 2,
                    item_type: ITEM_FILE_EXTENT,
                    offset: 0,
                },
                MetadataValue::FileExtent {
                    extents: vec![Extent {
                        device_index: 0,
                        offset: 134_217_728,
                        length: 4128,
                    }],
                    data_offset: 0,
                    logical_len: 4000,
                },
            ),
        ];
        let record = encode_leaf_record(&items);
        assert_eq!(
            hex(&record),
            "5363616c65465300010000000300000068010000000000003af6a74d000000000600000000000000000000000000000000000009000103000000000000000000000000000000042a000000000000003500050300000000000000000000000020000400000000201000000000000000002a36fe9c97170e006265666f72652d7570677261646501000000000000000100000000000000003d00020000000000000000ed4100000000000000000000010000000000000000002a36fe9c971700002a36fe9c971700002a36fe9c971700002a36fe9c971701000000000000000208070605040302011700030100020000000000000001090068656c6c6f2e74787402000000000000000100000000000000003d0002a00f000000000000a4810000e8030000e8030000010000002000000000002a36fe9c971700002a36fe9c971700002a36fe9c971700002a36fe9c9717020000000000000003000000000000000025000400000000000000080000000020100000000000000000000000000000a00f000000000000"
        );
        assert_eq!(decode_leaf_record(&record).unwrap(), items);
    }

    #[test]
    fn golden_mirrored_fixtures_are_stable() {
        let copies = |offset: u64, length: u64| {
            vec![
                Extent {
                    device_index: 0,
                    offset,
                    length,
                },
                Extent {
                    device_index: 1,
                    offset: offset + 4096,
                    length,
                },
            ]
        };
        let items = vec![
            (
                MetadataKey {
                    object_id: 0,
                    item_type: ITEM_RETAINED_ROOT,
                    offset: 42,
                },
                MetadataValue::RetainedRoot {
                    tx_id: 3,
                    metadata_roots: copies(67_117_056, 4128),
                    created_at_ns: 1_700_000_000_000_000_000,
                    name: "pinned".into(),
                },
            ),
            (
                MetadataKey {
                    object_id: 2,
                    item_type: ITEM_FILE_EXTENT,
                    offset: 0,
                },
                MetadataValue::FileExtent {
                    extents: copies(134_217_728, 4128),
                    data_offset: 0,
                    logical_len: 4000,
                },
            ),
        ];
        let record = encode_leaf_record(&items);
        assert_eq!(
            hex(&record),
            "5363616c654653000100000003000000a40000000000000028e212170000000002000000000000000000042a000000000000004200070300000000000000020000000000200004000000002010000000000000010000000030000400000000201000000000000000002a36fe9c9717060070696e6e656402000000000000000300000000000000003a000602000000000000000800000000201000000000000001000000001000080000000020100000000000000000000000000000a00f000000000000"
        );
        assert_eq!(decode_leaf_record(&record).unwrap(), items);

        let entries = vec![
            (MetadataKey::MIN, copies(67_108_864, 1000)),
            (inode_key(2), copies(67_112_960, 2000)),
        ];
        let record = encode_internal_record(&entries);
        assert_eq!(
            hex(&record),
            "5363616c65465300010000000900000076000000000000001d4c688d000000000200000000000000000000000000000000000002000000000000000400000000e803000000000000010000000010000400000000e803000000000000020000000000000001000000000000000002000000000010000400000000d007000000000000010000000020000400000000d007000000000000"
        );
        assert_eq!(decode_internal_record(&record).unwrap(), entries);
    }

    #[test]
    fn mixed_copy_counts_round_trip_in_mirrored_pages() {
        let entries = vec![
            (
                MetadataKey::MIN,
                vec![Extent {
                    device_index: 0,
                    offset: 67_108_864,
                    length: 1000,
                }],
            ),
            (
                inode_key(2),
                vec![
                    Extent {
                        device_index: 1,
                        offset: 67_112_960,
                        length: 2000,
                    },
                    Extent {
                        device_index: 2,
                        offset: 67_117_056,
                        length: 2000,
                    },
                ],
            ),
        ];
        let record = encode_internal_record(&entries);
        assert_eq!(decode_internal_record(&record).unwrap(), entries);
    }

    #[test]
    fn golden_internal_fixture_is_stable() {
        let entries = vec![
            (
                MetadataKey::MIN,
                vec![Extent {
                    device_index: 0,
                    offset: 67_108_864,
                    length: 1000,
                }],
            ),
            (
                inode_key(2),
                vec![Extent {
                    device_index: 0,
                    offset: 67_112_960,
                    length: 2000,
                }],
            ),
        ];
        let record = encode_internal_record(&entries);
        assert_eq!(
            hex(&record),
            "5363616c6546530001000000040000004c00000000000000a6ca0ee80000000002000000000000000000000000000000000000000000000000000400000000e8030000000000000200000000000000010000000000000000000000000010000400000000d007000000000000"
        );
        assert_eq!(decode_internal_record(&record).unwrap(), entries);
    }
}
