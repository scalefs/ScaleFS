use crate::error::{Result, ScaleFsError};
use crate::format::{
    Expect, RecordKind, decode_expect, decode_record, encode_expect, encode_record,
};
use crate::layout::{Extent, decode_extent, encode_extent};
use crate::runs::{FileRun, StripedRun};
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

const MAX_LOAD_DEPTH: u32 = 64;

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
    pub bsd_flags: u32,
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
    FileRun(FileRun),
    StripedRun(StripedRun),
    RetainedRoot {
        tx_id: u64,
        root: PageRef,
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
            Self::FileRun(run) => run.validate()?,
            Self::StripedRun(run) => run.validate()?,
            Self::RetainedRoot {
                tx_id, root, name, ..
            } => {
                if *tx_id == 0 {
                    return Err(ScaleFsError::Corrupt("retained root transaction is zero"));
                }
                let metadata_roots = &root.copies;
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
            put_u32(out, inode.bsd_flags);
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
        MetadataValue::FileRun(run) => {
            out.push(4);
            run.encode(out);
        }
        MetadataValue::StripedRun(run) => {
            out.push(8);
            run.encode(out);
        }
        MetadataValue::RetainedRoot {
            tx_id,
            root,
            created_at_ns,
            name,
        } => {
            out.push(5);
            put_u64(out, *tx_id);
            encode_page_ref(out, root);
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
            bsd_flags: cursor.take_u32()?,
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
        4 => MetadataValue::FileRun(FileRun::decode(cursor)?),
        8 => MetadataValue::StripedRun(StripedRun::decode(cursor)?),
        5 => {
            let tx_id = cursor.take_u64()?;
            let root = decode_page_ref(cursor)?;
            let created_at_ns = cursor.take_i64()?;
            let name_len = usize::from(cursor.take_u16()?);
            if name_len > MAX_NAME_LEN {
                return Err(ScaleFsError::Corrupt("retained root name length"));
            }
            let name = String::from_utf8(cursor.take(name_len)?.to_vec())
                .map_err(|_| ScaleFsError::Corrupt("retained root name is not UTF-8"))?;
            MetadataValue::RetainedRoot {
                tx_id,
                root,
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

pub(crate) fn encode_leaf_record(items: &[(MetadataKey, MetadataValue)], tx: u64) -> Vec<u8> {
    let mut payload = Vec::new();
    put_u16(&mut payload, items.len() as u16);
    for (key, value) in items {
        encode_key(&mut payload, *key);
        let mut bytes = Vec::new();
        encode_value(&mut bytes, value);
        put_u16(&mut payload, bytes.len() as u16);
        payload.extend_from_slice(&bytes);
    }
    encode_record(RecordKind::MetadataLeaf, tx, &payload)
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

pub(crate) fn encode_page_ref(out: &mut Vec<u8>, page: &PageRef) {
    out.push(page.copies.len() as u8);
    for extent in &page.copies {
        encode_extent(out, *extent);
    }
    encode_expect(out, page.expect);
}

pub(crate) fn decode_page_ref(cursor: &mut Cursor<'_>) -> Result<PageRef> {
    let count = cursor.take_u8()?;
    if count == 0 {
        return Err(ScaleFsError::Corrupt("page reference has no copies"));
    }
    let mut copies: Vec<Extent> = Vec::with_capacity(usize::from(count));
    let mut members = std::collections::HashSet::new();
    for _ in 0..count {
        let extent = decode_extent(cursor)?;
        if extent.length == 0 {
            return Err(ScaleFsError::Corrupt("page reference extent is empty"));
        }
        if copies.first().is_some_and(|f| f.length != extent.length) {
            return Err(ScaleFsError::Corrupt(
                "page reference copies must have equal lengths",
            ));
        }
        if !members.insert(extent.device_index) {
            return Err(ScaleFsError::Corrupt(
                "page reference copies must live on distinct members",
            ));
        }
        copies.push(extent);
    }
    let expect = decode_expect(cursor)?;
    Ok(PageRef { copies, expect })
}

pub(crate) fn encode_internal_record(entries: &[(MetadataKey, PageRef)], tx: u64) -> Vec<u8> {
    let mut payload = Vec::new();
    put_u16(&mut payload, entries.len() as u16);
    for (separator, child) in entries {
        encode_key(&mut payload, *separator);
        encode_page_ref(&mut payload, child);
    }
    encode_record(RecordKind::MetadataInternal, tx, &payload)
}

pub(crate) fn decode_internal_record(bytes: &[u8]) -> Result<Vec<(MetadataKey, PageRef)>> {
    let record = decode_record(bytes)?;
    if record.kind != RecordKind::MetadataInternal {
        return Err(ScaleFsError::Corrupt("expected a metadata internal record"));
    }
    let mut cursor = Cursor::new(&record.payload);
    let count = usize::from(cursor.take_u16()?);
    if count < 2 {
        return Err(ScaleFsError::Corrupt(
            "internal page has fewer than two children",
        ));
    }
    let mut entries: Vec<(MetadataKey, PageRef)> = Vec::with_capacity(count);
    for _ in 0..count {
        let separator = decode_key(&mut cursor)?;
        if let Some((previous, _)) = entries.last()
            && *previous >= separator
        {
            return Err(ScaleFsError::Corrupt(
                "internal separators are not strictly sorted",
            ));
        }
        entries.push((separator, decode_page_ref(&mut cursor)?));
    }
    cursor.expect_end("internal page has trailing bytes")?;
    Ok(entries)
}

pub type TreeItem = (MetadataKey, MetadataValue);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PageRef {
    pub copies: Vec<Extent>,
    pub expect: Expect,
}

impl PageRef {
    pub fn location(&self) -> Option<(u16, u64)> {
        location(&self.copies)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PagePlan {
    pub extents: Vec<Extent>,
    pub bytes: Vec<u8>,
}

pub trait PageSource {
    fn read_page(&self, page: &PageRef) -> Result<Vec<u8>>;
}

impl<F> PageSource for F
where
    F: Fn(&PageRef) -> Result<Vec<u8>>,
{
    fn read_page(&self, page: &PageRef) -> Result<Vec<u8>> {
        self(page)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NoPages;

impl PageSource for NoPages {
    fn read_page(&self, _page: &PageRef) -> Result<Vec<u8>> {
        Err(ScaleFsError::Unsupported(
            "the tree page is not in memory and the tree has no page source",
        ))
    }
}

static NO_PAGES: NoPages = NoPages;

pub const DEFAULT_METADATA_CACHE_BYTES: usize = 256 << 20;

static DEFAULT_CACHE_BUDGET: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(DEFAULT_METADATA_CACHE_BYTES);

pub fn set_default_metadata_cache(bytes: usize) {
    DEFAULT_CACHE_BUDGET.store(bytes, std::sync::atomic::Ordering::Relaxed);
}

pub fn default_metadata_cache() -> usize {
    DEFAULT_CACHE_BUDGET.load(std::sync::atomic::Ordering::Relaxed)
}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub budget_bytes: u64,
    pub clean_bytes: u64,
    pub loaded_pages: u64,
    pub pinned_pages: u64,
    pub page_reads: u64,
    pub pages_evicted: u64,
}

#[derive(Debug)]
struct PageMeta {
    disk: Option<PageRef>,
    used: u64,
    cost: usize,
    planned: u64,
}

impl PageMeta {
    fn dirty(stamp: u64) -> Self {
        Self {
            disk: None,
            used: stamp,
            cost: 0,
            planned: 0,
        }
    }
}

#[derive(Debug)]
enum Node {
    Leaf {
        items: Vec<(MetadataKey, MetadataValue)>,
        meta: PageMeta,
    },
    Internal {
        children: Vec<(MetadataKey, Child)>,
        meta: PageMeta,
    },
}

#[derive(Debug)]
enum Child {
    OnDisk(PageRef),
    Loaded(Box<Node>),
}

impl Node {
    fn empty_leaf(stamp: u64) -> Self {
        Node::Leaf {
            items: Vec::new(),
            meta: PageMeta::dirty(stamp),
        }
    }

    fn meta(&self) -> &PageMeta {
        match self {
            Node::Leaf { meta, .. } | Node::Internal { meta, .. } => meta,
        }
    }

    fn meta_mut(&mut self) -> &mut PageMeta {
        match self {
            Node::Leaf { meta, .. } | Node::Internal { meta, .. } => meta,
        }
    }

    fn min_key(&self) -> Option<MetadataKey> {
        match self {
            Node::Leaf { items, .. } => items.first().map(|(k, _)| *k),
            Node::Internal { children, .. } => children.first().map(|(k, _)| *k),
        }
    }

    fn is_empty(&self) -> bool {
        match self {
            Node::Leaf { items, .. } => items.is_empty(),
            Node::Internal { children, .. } => children.is_empty(),
        }
    }
}

fn child_index(children: &[(MetadataKey, Child)], key: MetadataKey) -> usize {
    children
        .partition_point(|(separator, _)| *separator <= key)
        .saturating_sub(1)
}

fn child_hi(
    children: &[(MetadataKey, Child)],
    idx: usize,
    hi: Option<MetadataKey>,
) -> Option<MetadataKey> {
    children
        .get(idx + 1)
        .map(|(separator, _)| *separator)
        .or(hi)
}

fn leaf_encoded_payload_len(items: &[(MetadataKey, MetadataValue)]) -> usize {
    2 + items
        .iter()
        .map(|(_, v)| 17 + 2 + value_encoded_len(v))
        .sum::<usize>()
}

fn heap_bytes(len: usize) -> usize {
    if len == 0 {
        0
    } else {
        len.div_ceil(16) * 16 + 16
    }
}

fn value_heap_bytes(value: &MetadataValue) -> usize {
    let extents = |list: &Vec<Extent>| heap_bytes(list.capacity() * size_of::<Extent>());
    match value {
        MetadataValue::PoolState { .. } | MetadataValue::Inode(_) => 0,
        MetadataValue::DirEntries(entries) => {
            heap_bytes(entries.capacity() * size_of::<DirEntry>())
                + entries
                    .iter()
                    .map(|entry| heap_bytes(entry.name.capacity()))
                    .sum::<usize>()
        }
        MetadataValue::FileRun(run) => {
            extents(&run.copies) + heap_bytes(run.crcs.capacity() * size_of::<u32>())
        }
        MetadataValue::StripedRun(run) => {
            extents(&run.pieces)
                + extents(&run.parity)
                + heap_bytes(run.crcs.capacity() * size_of::<u32>())
                + heap_bytes(run.parity_crcs.capacity() * size_of::<u32>())
        }
        MetadataValue::RetainedRoot { root, name, .. } => {
            extents(&root.copies) + heap_bytes(name.capacity())
        }
        MetadataValue::Special { data } | MetadataValue::Opaque { data, .. } => {
            heap_bytes(data.capacity())
        }
        MetadataValue::XattrEntries(entries) => {
            heap_bytes(entries.capacity() * size_of::<XattrEntry>())
                + entries
                    .iter()
                    .map(|entry| {
                        heap_bytes(entry.name.capacity()) + heap_bytes(entry.value.capacity())
                    })
                    .sum::<usize>()
        }
    }
}

fn node_cost(node: &Node) -> usize {
    let own = heap_bytes(size_of::<Node>());
    match node {
        Node::Leaf { items, .. } => {
            own + heap_bytes(items.capacity() * size_of::<(MetadataKey, MetadataValue)>())
                + items
                    .iter()
                    .map(|(_, value)| value_heap_bytes(value))
                    .sum::<usize>()
        }
        Node::Internal { children, .. } => {
            own + heap_bytes(children.capacity() * size_of::<(MetadataKey, Child)>())
                + children.len() * heap_bytes(2 * size_of::<Extent>())
        }
    }
}

fn location(copies: &[Extent]) -> Option<(u16, u64)> {
    copies
        .first()
        .map(|extent| (extent.device_index, extent.offset))
}

#[derive(Clone, Copy)]
struct Above<'p> {
    here: Option<&'p [Extent]>,
    up: Option<&'p Above<'p>>,
}

impl Above<'_> {
    const TOP: Above<'static> = Above {
        here: None,
        up: None,
    };

    fn contains(&self, at: (u16, u64)) -> bool {
        let mut cursor = Some(self);
        while let Some(above) = cursor {
            if above.here.and_then(location) == Some(at) {
                return true;
            }
            cursor = above.up;
        }
        false
    }
}

fn decode_page(
    bytes: &[u8],
    page: &PageRef,
    lo: Option<MetadataKey>,
    hi: Option<MetadataKey>,
    depth: u32,
    is_above: &dyn Fn((u16, u64)) -> bool,
    stamp: u64,
) -> Result<Node> {
    if depth > MAX_LOAD_DEPTH {
        return Err(ScaleFsError::Corrupt("tree deeper than any writer builds"));
    }
    let record = decode_record(bytes)?;
    let meta = PageMeta {
        disk: Some(page.clone()),
        used: stamp,
        cost: 0,
        planned: 0,
    };
    let mut node = match record.kind {
        RecordKind::MetadataLeaf => {
            let items = decode_leaf_record(bytes)?;
            if items.is_empty() && depth > 0 {
                return Err(ScaleFsError::Corrupt("empty leaf below the root"));
            }
            if let (Some(lo), Some((first, _))) = (lo, items.first())
                && *first != lo
            {
                return Err(ScaleFsError::Corrupt(
                    "child page does not start at its separator",
                ));
            }
            if let (Some(hi), Some((last, _))) = (hi, items.last())
                && *last >= hi
            {
                return Err(ScaleFsError::Corrupt(
                    "child page overlaps the next separator",
                ));
            }
            Node::Leaf { items, meta }
        }
        RecordKind::MetadataInternal => {
            let entries = decode_internal_record(bytes)?;
            if let Some(lo) = lo
                && entries[0].0 != lo
            {
                return Err(ScaleFsError::Corrupt(
                    "child page does not start at its separator",
                ));
            }
            if let Some(hi) = hi
                && entries[entries.len() - 1].0 >= hi
            {
                return Err(ScaleFsError::Corrupt(
                    "child page overlaps the next separator",
                ));
            }
            let own = page.location();
            let mut named = std::collections::HashSet::with_capacity(entries.len());
            for (_, child) in &entries {
                let at = child
                    .location()
                    .ok_or(ScaleFsError::Corrupt("tree page has no copies"))?;
                if Some(at) == own || is_above(at) || !named.insert(at) {
                    return Err(ScaleFsError::Corrupt("tree page reachable twice"));
                }
            }
            Node::Internal {
                children: entries
                    .into_iter()
                    .map(|(separator, child)| (separator, Child::OnDisk(child)))
                    .collect(),
                meta,
            }
        }
        _ => return Err(ScaleFsError::Corrupt("expected a metadata page record")),
    };
    let cost = node_cost(&node);
    node.meta_mut().cost = cost;
    Ok(node)
}

#[derive(Debug)]
struct Cache {
    budget: usize,
    clean_bytes: usize,
    clock: u64,
    plan_epoch: u64,
    in_flight: Option<u64>,
    page_reads: u64,
    pages_evicted: u64,
}

impl Cache {
    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    fn pending(&self, meta: &PageMeta) -> bool {
        self.in_flight.is_some_and(|epoch| meta.planned == epoch)
    }

    fn pinned(&self, meta: &PageMeta) -> bool {
        meta.disk.is_none() || self.pending(meta)
    }

    fn dirty(&mut self, meta: &mut PageMeta) {
        let pending = self.pending(meta);
        if meta.disk.take().is_some() && !pending {
            self.clean_bytes -= meta.cost;
        }
    }
}

#[derive(Debug)]
struct TreeState {
    root: Node,
    cache: Cache,
}

struct PageRequest {
    key: MetadataKey,
    page: PageRef,
    lo: MetadataKey,
    hi: Option<MetadataKey>,
    depth: u32,
    above: Vec<(u16, u64)>,
}

impl TreeState {
    fn visit_leaf<R>(
        &mut self,
        key: MetadataKey,
        stamp: u64,
        visit: &mut impl FnMut(&[(MetadataKey, MetadataValue)], Option<MetadataKey>) -> R,
    ) -> std::result::Result<R, Box<PageRequest>> {
        let mut node = &mut self.root;
        let mut hi = None;
        let mut depth = 0;
        loop {
            match node {
                Node::Leaf { items, meta } => {
                    meta.used = stamp;
                    return Ok(visit(items, hi));
                }
                Node::Internal { children, meta } => {
                    meta.used = stamp;
                    let idx = child_index(children, key);
                    let lo = children[idx].0;
                    let below = child_hi(children, idx, hi);
                    depth += 1;
                    if let Child::OnDisk(page) = &children[idx].1 {
                        return Err(Box::new(PageRequest {
                            key,
                            page: page.clone(),
                            lo,
                            hi: below,
                            depth,
                            above: Vec::new(),
                        }));
                    }
                    let Child::Loaded(child) = &mut children[idx].1 else {
                        unreachable!("checked above");
                    };
                    node = &mut **child;
                    hi = below;
                }
            }
        }
    }

    fn above_of(&self, key: MetadataKey, depth: u32) -> Vec<(u16, u64)> {
        let mut out = Vec::new();
        let mut node = &self.root;
        for _ in 0..depth {
            let Node::Internal { children, meta } = node else {
                break;
            };
            if let Some(at) = meta.disk.as_ref().and_then(PageRef::location) {
                out.push(at);
            }
            match &children[child_index(children, key)].1 {
                Child::Loaded(child) => node = child,
                Child::OnDisk(_) => break,
            }
        }
        out
    }

    fn install(&mut self, request: &PageRequest, node: Node) -> bool {
        let TreeState { root, cache } = self;
        let mut slot = root;
        loop {
            let Node::Internal { children, .. } = slot else {
                return false;
            };
            let idx = child_index(children, request.key);
            if let Child::OnDisk(page) = &children[idx].1 {
                let waiting = *page == request.page;
                if waiting {
                    cache.clean_bytes += node.meta().cost;
                    children[idx].1 = Child::Loaded(Box::new(node));
                }
                return waiting;
            }
            let Child::Loaded(child) = &mut children[idx].1 else {
                unreachable!("checked above");
            };
            slot = &mut **child;
        }
    }

    fn evict_over_budget(&mut self) {
        let cache = &mut self.cache;
        if cache.clean_bytes <= cache.budget {
            return;
        }
        let low = cache.budget - cache.budget / 8;
        let need = cache.clean_bytes - low;
        let mut candidates: Vec<(u64, usize)> = Vec::new();
        collect_evictable(&self.root, cache, &mut candidates);
        if candidates.is_empty() {
            return;
        }
        candidates.sort_unstable_by_key(|&(used, _)| used);
        let mut freed = 0usize;
        let mut threshold = 0u64;
        for (used, cost) in candidates {
            threshold = used;
            freed += cost;
            if freed >= need {
                break;
            }
        }
        evict_up_to(&mut self.root, threshold, cache);
    }
}

fn collect_evictable(node: &Node, cache: &Cache, out: &mut Vec<(u64, usize)>) {
    if let Node::Internal { children, .. } = node {
        for (_, child) in children {
            if let Child::Loaded(child) = child {
                if !cache.pinned(child.meta()) {
                    out.push((child.meta().used, child.meta().cost));
                }
                collect_evictable(child, cache, out);
            }
        }
    }
}

fn evict_up_to(node: &mut Node, threshold: u64, cache: &mut Cache) {
    let Node::Internal { children, .. } = node else {
        return;
    };
    for (_, child) in children.iter_mut() {
        let Child::Loaded(loaded) = child else {
            continue;
        };
        if !cache.pinned(loaded.meta()) && loaded.meta().used <= threshold {
            let (bytes, pages) = clean_subtree(loaded, cache);
            cache.clean_bytes -= bytes;
            cache.pages_evicted += pages;
            let page = loaded
                .meta_mut()
                .disk
                .take()
                .expect("a clean page has a location");
            *child = Child::OnDisk(page);
        } else {
            evict_up_to(loaded, threshold, cache);
        }
    }
}

fn clean_subtree(node: &Node, cache: &Cache) -> (usize, u64) {
    debug_assert!(!cache.pinned(node.meta()), "only clean pages are evicted");
    let mut bytes = node.meta().cost;
    let mut pages = 1;
    if let Node::Internal { children, .. } = node {
        for (_, child) in children {
            if let Child::Loaded(child) = child {
                let (b, p) = clean_subtree(child, cache);
                bytes += b;
                pages += p;
            }
        }
    }
    (bytes, pages)
}

struct Descent<'a> {
    cache: &'a mut Cache,
    pages: &'a dyn PageSource,
    stamp: u64,
}

fn load_child<'n>(
    children: &'n mut [(MetadataKey, Child)],
    idx: usize,
    hi: Option<MetadataKey>,
    depth: u32,
    descent: &mut Descent<'_>,
    above: &Above<'_>,
) -> Result<&'n mut Node> {
    if let Child::OnDisk(page) = &children[idx].1 {
        let bytes = descent.pages.read_page(page)?;
        let node = decode_page(
            &bytes,
            page,
            Some(children[idx].0),
            child_hi(children, idx, hi),
            depth,
            &|at| above.contains(at),
            descent.stamp,
        )?;
        descent.cache.page_reads += 1;
        descent.cache.clean_bytes += node.meta().cost;
        children[idx].1 = Child::Loaded(Box::new(node));
    }
    let Child::Loaded(node) = &mut children[idx].1 else {
        unreachable!("the child was loaded above");
    };
    node.meta_mut().used = descent.stamp;
    Ok(node)
}

fn insert_into(
    node: &mut Node,
    key: MetadataKey,
    value: MetadataValue,
    descent: &mut Descent<'_>,
    above: &Above<'_>,
    hi: Option<MetadataKey>,
    depth: u32,
) -> Result<Option<(MetadataKey, Node)>> {
    match node {
        Node::Leaf { items, meta } => {
            meta.used = descent.stamp;
            descent.cache.dirty(meta);
            match items.binary_search_by(|(k, _)| k.cmp(&key)) {
                Ok(i) => items[i].1 = value,
                Err(i) => items.insert(i, (key, value)),
            }
            if leaf_encoded_payload_len(items) <= LEAF_SPLIT_BYTES || items.len() < 2 {
                return Ok(None);
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
            Ok(Some((
                split_key,
                Node::Leaf {
                    items: right_items,
                    meta: PageMeta::dirty(descent.stamp),
                },
            )))
        }
        Node::Internal { children, meta } => {
            meta.used = descent.stamp;
            let idx = child_index(children, key);
            let below = child_hi(children, idx, hi);
            let here = Above {
                here: meta.disk.as_ref().map(|page| page.copies.as_slice()),
                up: Some(above),
            };
            let child = load_child(children, idx, hi, depth + 1, descent, &here)?;
            let spawned = insert_into(child, key, value, descent, &here, below, depth + 1)?;
            descent.cache.dirty(meta);
            if let Child::Loaded(child) = &children[idx].1 {
                children[idx].0 = child.min_key().expect("child is nonempty");
            }
            if let Some((split_key, right)) = spawned {
                children.insert(idx + 1, (split_key, Child::Loaded(Box::new(right))));
            }
            if children.len() <= INTERNAL_MAX_CHILDREN {
                return Ok(None);
            }
            let right_children = children.split_off(children.len() / 2);
            let split_key = right_children[0].0;
            Ok(Some((
                split_key,
                Node::Internal {
                    children: right_children,
                    meta: PageMeta::dirty(descent.stamp),
                },
            )))
        }
    }
}

fn remove_from(
    node: &mut Node,
    key: MetadataKey,
    descent: &mut Descent<'_>,
    above: &Above<'_>,
    hi: Option<MetadataKey>,
    depth: u32,
) -> Result<Option<MetadataValue>> {
    match node {
        Node::Leaf { items, meta } => {
            meta.used = descent.stamp;
            match items.binary_search_by(|(k, _)| k.cmp(&key)) {
                Ok(i) => {
                    descent.cache.dirty(meta);
                    Ok(Some(items.remove(i).1))
                }
                Err(_) => Ok(None),
            }
        }
        Node::Internal { children, meta } => {
            meta.used = descent.stamp;
            let idx = child_index(children, key);
            let below = child_hi(children, idx, hi);
            let here = Above {
                here: meta.disk.as_ref().map(|page| page.copies.as_slice()),
                up: Some(above),
            };
            let child = load_child(children, idx, hi, depth + 1, descent, &here)?;
            let Some(removed) = remove_from(child, key, descent, &here, below, depth + 1)? else {
                return Ok(None);
            };
            descent.cache.dirty(meta);
            let emptied = matches!(&children[idx].1, Child::Loaded(child) if child.is_empty());
            if emptied {
                children.remove(idx);
            } else {
                let lifted = match &mut children[idx].1 {
                    Child::Loaded(child) => match &mut **child {
                        Node::Internal {
                            children: grand, ..
                        } if grand.len() == 1 => grand.pop(),
                        _ => None,
                    },
                    Child::OnDisk(_) => None,
                };
                if let Some(entry) = lifted {
                    children[idx] = entry;
                }
                if let Child::Loaded(child) = &children[idx].1 {
                    children[idx].0 = child.min_key().expect("child is nonempty");
                }
            }
            Ok(Some(removed))
        }
    }
}

fn dirty_leaf(
    node: &mut Node,
    key: MetadataKey,
    descent: &mut Descent<'_>,
    above: &Above<'_>,
    hi: Option<MetadataKey>,
    depth: u32,
) -> Result<(Option<MetadataKey>, usize)> {
    match node {
        Node::Leaf { meta, .. } => {
            meta.used = descent.stamp;
            descent.cache.dirty(meta);
            let cost = node_cost(node);
            Ok((hi, cost))
        }
        Node::Internal { children, meta } => {
            meta.used = descent.stamp;
            let idx = child_index(children, key);
            let below = child_hi(children, idx, hi);
            let here = Above {
                here: meta.disk.as_ref().map(|page| page.copies.as_slice()),
                up: Some(above),
            };
            let child = load_child(children, idx, hi, depth + 1, descent, &here)?;
            let found = dirty_leaf(child, key, descent, &here, below, depth + 1)?;
            descent.cache.dirty(meta);
            Ok(found)
        }
    }
}

fn plan_node(
    node: &mut Node,
    tx: u64,
    place: &mut dyn FnMut(u64) -> Result<Vec<(u16, u64)>>,
    pages: &mut Vec<PagePlan>,
    epoch: u64,
) -> Result<PageRef> {
    if let Some(page) = &node.meta().disk {
        return Ok(page.clone());
    }
    node.meta_mut().planned = epoch;
    let bytes = match node {
        Node::Leaf { items, .. } => encode_leaf_record(items, tx),
        Node::Internal { children, .. } => {
            let mut entries = Vec::with_capacity(children.len());
            for (separator, child) in children.iter_mut() {
                let page = match child {
                    Child::OnDisk(page) => page.clone(),
                    Child::Loaded(child) => {
                        let page = plan_node(child, tx, place, pages, epoch)?;
                        *separator = child.min_key().expect("child is nonempty");
                        page
                    }
                };
                entries.push((*separator, page));
            }
            encode_internal_record(&entries, tx)
        }
    };
    let extents = place_copies(place, bytes.len() as u64)?;
    let page = PageRef {
        copies: extents.clone(),
        expect: Expect::of(&bytes),
    };
    let cost = node_cost(node);
    let meta = node.meta_mut();
    meta.disk = Some(page.clone());
    meta.cost = cost;
    pages.push(PagePlan { extents, bytes });
    Ok(page)
}

fn for_each_planned(node: &mut Node, epoch: u64, visit: &mut dyn FnMut(&mut PageMeta)) {
    if node.meta().planned != epoch {
        return;
    }
    visit(node.meta_mut());
    if let Node::Internal { children, .. } = node {
        for (_, child) in children {
            if let Child::Loaded(child) = child {
                for_each_planned(child, epoch, visit);
            }
        }
    }
}

pub struct MetadataTree {
    state: std::sync::Mutex<TreeState>,
}

impl std::fmt::Debug for MetadataTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.state.try_lock() {
            Ok(state) => f
                .debug_struct("MetadataTree")
                .field("cache", &stats_of(&state))
                .finish(),
            Err(_) => f.write_str("MetadataTree { .. }"),
        }
    }
}

impl Default for MetadataTree {
    fn default() -> Self {
        Self::new()
    }
}

fn stats_of(state: &TreeState) -> CacheStats {
    fn walk(node: &Node, cache: &Cache, loaded: &mut u64, pinned: &mut u64) {
        *loaded += 1;
        if cache.pinned(node.meta()) {
            *pinned += 1;
        }
        if let Node::Internal { children, .. } = node {
            for (_, child) in children {
                if let Child::Loaded(child) = child {
                    walk(child, cache, loaded, pinned);
                }
            }
        }
    }
    let (mut loaded, mut pinned) = (0, 0);
    walk(&state.root, &state.cache, &mut loaded, &mut pinned);
    CacheStats {
        budget_bytes: state.cache.budget as u64,
        clean_bytes: state.cache.clean_bytes as u64,
        loaded_pages: loaded,
        pinned_pages: pinned,
        page_reads: state.cache.page_reads,
        pages_evicted: state.cache.pages_evicted,
    }
}

impl MetadataTree {
    fn with_root(root: Node, clean_bytes: usize, page_reads: u64) -> Self {
        Self {
            state: std::sync::Mutex::new(TreeState {
                root,
                cache: Cache {
                    budget: default_metadata_cache(),
                    clean_bytes,
                    clock: 1,
                    plan_epoch: 0,
                    in_flight: None,
                    page_reads,
                    pages_evicted: 0,
                },
            }),
        }
    }

    pub fn new() -> Self {
        Self::with_root(Node::empty_leaf(1), 0, 0)
    }

    pub fn load(root: &PageRef, pages: &dyn PageSource) -> Result<MetadataTree> {
        let bytes = pages.read_page(root)?;
        let node = decode_page(&bytes, root, None, None, 0, &|_| false, 1)?;
        let cost = node.meta().cost;
        Ok(Self::with_root(node, cost, 1))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, TreeState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn state_mut(&mut self) -> &mut TreeState {
        self.state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn view<'a>(&'a self, pages: &'a dyn PageSource) -> TreeRef<'a> {
        TreeRef { tree: self, pages }
    }

    pub fn edit<'a>(&'a mut self, pages: &'a dyn PageSource) -> TreeMut<'a> {
        TreeMut(TreeRef { tree: self, pages })
    }

    pub fn in_memory(&mut self) -> TreeMut<'_> {
        self.edit(&NO_PAGES)
    }

    pub(crate) fn edit_shared<'a>(&'a self, pages: &'a dyn PageSource) -> TreeMut<'a> {
        TreeMut(TreeRef { tree: self, pages })
    }

    fn with_leaf<R>(
        &self,
        pages: &dyn PageSource,
        key: MetadataKey,
        visit: &mut impl FnMut(&[(MetadataKey, MetadataValue)], Option<MetadataKey>) -> R,
    ) -> Result<R> {
        let read = |request: &PageRequest| -> Result<Node> {
            let bytes = pages.read_page(&request.page)?;
            decode_page(
                &bytes,
                &request.page,
                Some(request.lo),
                request.hi,
                request.depth,
                &|at| request.above.contains(&at),
                0,
            )
        };
        let mut state = self.lock();
        let mut lost = 0u32;
        loop {
            let stamp = state.cache.tick();
            let mut request = match state.visit_leaf(key, stamp, visit) {
                Ok(out) => {
                    state.evict_over_budget();
                    return Ok(out);
                }
                Err(request) => request,
            };
            request.above = state.above_of(request.key, request.depth);
            let node = if lost < 4 {
                drop(state);
                let node = read(&request);
                state = self.lock();
                node?
            } else {
                read(&request)?
            };
            state.cache.page_reads += 1;
            if !state.install(&request, node) {
                lost += 1;
            }
        }
    }

    pub fn plan_commit(
        &mut self,
        tx: u64,
        place: &mut dyn FnMut(u64) -> Result<Vec<(u16, u64)>>,
    ) -> Result<(PageRef, Vec<PagePlan>)> {
        let state = self.state_mut();
        debug_assert!(
            state.cache.in_flight.is_none(),
            "a plan is concluded before the next is made"
        );
        state.cache.plan_epoch += 1;
        let epoch = state.cache.plan_epoch;
        state.cache.in_flight = Some(epoch);
        let mut pages = Vec::new();
        let root = plan_node(&mut state.root, tx, place, &mut pages, epoch)?;
        Ok((root, pages))
    }

    pub fn plan_published(&mut self) {
        let state = self.state_mut();
        let Some(epoch) = state.cache.in_flight else {
            return;
        };
        let mut joined = 0usize;
        for_each_planned(&mut state.root, epoch, &mut |meta| {
            if meta.disk.is_some() {
                joined += meta.cost;
            }
        });
        state.cache.in_flight = None;
        state.cache.clean_bytes += joined;
        state.evict_over_budget();
    }

    pub fn plan_abandoned(&mut self) {
        let state = self.state_mut();
        let Some(epoch) = state.cache.in_flight else {
            return;
        };
        for_each_planned(&mut state.root, epoch, &mut |meta| {
            meta.disk = None;
        });
        state.cache.in_flight = None;
    }

    pub fn cache_budget(&self) -> usize {
        self.lock().cache.budget
    }

    pub fn set_cache_budget(&self, bytes: usize) {
        let mut state = self.lock();
        state.cache.budget = bytes;
        state.evict_over_budget();
    }

    pub fn cache_stats(&self) -> CacheStats {
        stats_of(&self.lock())
    }
}

#[derive(Clone, Copy)]
pub struct TreeRef<'a> {
    tree: &'a MetadataTree,
    pages: &'a dyn PageSource,
}

impl std::fmt::Debug for TreeRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("TreeRef").field(self.tree).finish()
    }
}

impl<'a> TreeRef<'a> {
    pub fn new(tree: &'a MetadataTree, pages: &'a dyn PageSource) -> Self {
        Self { tree, pages }
    }

    pub fn get(&self, key: MetadataKey) -> Result<Option<MetadataValue>> {
        self.get_with(key, |value| value.cloned())
    }

    pub(crate) fn get_with<R>(
        &self,
        key: MetadataKey,
        mut read: impl FnMut(Option<&MetadataValue>) -> R,
    ) -> Result<R> {
        self.tree.with_leaf(self.pages, key, &mut |items, _| {
            read(
                items
                    .binary_search_by(|(k, _)| k.cmp(&key))
                    .ok()
                    .map(|i| &items[i].1),
            )
        })
    }

    pub fn last_in(&self, lo: MetadataKey, hi: MetadataKey) -> Result<Option<TreeItem>> {
        let found = self.tree.with_leaf(self.pages, hi, &mut |items, _| {
            let upto = items.partition_point(|(key, _)| *key <= hi);
            match upto.checked_sub(1).map(|index| &items[index]) {
                Some((key, value)) if *key >= lo => Some(Some((*key, value.clone()))),
                Some(_) => Some(None),
                None => None,
            }
        })?;
        match found {
            Some(answer) => Ok(answer),
            None => Ok(self.range(lo, hi)?.pop()),
        }
    }

    pub fn range(
        &self,
        start: MetadataKey,
        end: MetadataKey,
    ) -> Result<Vec<(MetadataKey, MetadataValue)>> {
        let mut out = Vec::new();
        self.scan(start, end, &mut |items| {
            out.extend(items.iter().map(|(key, value)| (*key, value.clone())));
        })?;
        Ok(out)
    }

    pub fn keys(&self, start: MetadataKey, end: MetadataKey) -> Result<Vec<MetadataKey>> {
        let mut out = Vec::new();
        self.scan(start, end, &mut |items| {
            out.extend(items.iter().map(|(key, _)| *key));
        })?;
        Ok(out)
    }

    pub(crate) fn scan(
        &self,
        start: MetadataKey,
        end: MetadataKey,
        visit: &mut dyn FnMut(&[TreeItem]),
    ) -> Result<()> {
        let mut from = start;
        loop {
            let next = self.tree.with_leaf(self.pages, from, &mut |items, hi| {
                let first = items.partition_point(|(key, _)| *key < from);
                let last = items.partition_point(|(key, _)| *key <= end);
                if first < last {
                    visit(&items[first..last]);
                }
                hi
            })?;
            match next {
                Some(next) if next <= end => from = next,
                _ => return Ok(()),
            }
        }
    }

    pub fn leaf_from(&self, from: MetadataKey) -> Result<(Vec<TreeItem>, Option<MetadataKey>)> {
        self.tree.with_leaf(self.pages, from, &mut |items, hi| {
            let first = items.partition_point(|(key, _)| *key < from);
            (items[first..].to_vec(), hi)
        })
    }

    pub fn leaves(&self) -> Leaves<'a> {
        Leaves {
            tree: *self,
            cursor: Some(MetadataKey::MIN),
        }
    }

    pub fn for_each(&self, visit: &mut dyn FnMut(&MetadataKey, &MetadataValue)) -> Result<()> {
        for leaf in self.leaves() {
            for (key, value) in &leaf? {
                visit(key, value);
            }
        }
        Ok(())
    }

    pub fn item_count(&self) -> Result<usize> {
        let mut count = 0usize;
        self.scan(MetadataKey::MIN, MetadataKey::MAX, &mut |items| {
            count += items.len();
        })?;
        Ok(count)
    }
}

#[derive(Debug)]
pub struct Leaves<'a> {
    tree: TreeRef<'a>,
    cursor: Option<MetadataKey>,
}

impl Iterator for Leaves<'_> {
    type Item = Result<Vec<(MetadataKey, MetadataValue)>>;

    fn next(&mut self) -> Option<Self::Item> {
        let from = self.cursor?;
        match self.tree.leaf_from(from) {
            Ok((items, next)) => {
                self.cursor = next;
                Some(Ok(items))
            }
            Err(error) => {
                self.cursor = None;
                Some(Err(error))
            }
        }
    }
}

#[derive(Clone, Copy)]
pub struct TreeMut<'a>(TreeRef<'a>);

impl<'a> std::ops::Deref for TreeMut<'a> {
    type Target = TreeRef<'a>;

    fn deref(&self) -> &TreeRef<'a> {
        &self.0
    }
}

impl std::fmt::Debug for TreeMut<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("TreeMut").field(self.0.tree).finish()
    }
}

impl TreeMut<'_> {
    pub fn insert(&self, key: MetadataKey, value: MetadataValue) -> Result<()> {
        value.validate()?;
        if value_encoded_len(&value) > MAX_VALUE_LEN {
            return Err(ScaleFsError::InvalidArgument(
                "metadata value exceeds the size limit",
            ));
        }
        let mut state = self.0.tree.lock();
        let TreeState { root, cache } = &mut *state;
        let stamp = cache.tick();
        let mut descent = Descent {
            cache,
            pages: self.0.pages,
            stamp,
        };
        let spawned = insert_into(root, key, value, &mut descent, &Above::TOP, None, 0);
        if let Some((split_key, right)) = spawned? {
            let old_root = std::mem::replace(root, Node::empty_leaf(stamp));
            let left_key = old_root.min_key().expect("split left half is nonempty");
            *root = Node::Internal {
                children: vec![
                    (left_key, Child::Loaded(Box::new(old_root))),
                    (split_key, Child::Loaded(Box::new(right))),
                ],
                meta: PageMeta::dirty(stamp),
            };
        }
        state.evict_over_budget();
        Ok(())
    }

    pub fn remove(&self, key: MetadataKey) -> Result<Option<MetadataValue>> {
        let mut state = self.0.tree.lock();
        let TreeState { root, cache } = &mut *state;
        let stamp = cache.tick();
        let mut descent = Descent {
            cache,
            pages: self.0.pages,
            stamp,
        };
        if let Node::Internal { children, meta } = root
            && children.len() == 2
        {
            let here = Above {
                here: meta.disk.as_ref().map(|page| page.copies.as_slice()),
                up: None,
            };
            for idx in 0..2 {
                load_child(children, idx, None, 1, &mut descent, &here)?;
            }
        }
        let removed = remove_from(root, key, &mut descent, &Above::TOP, None, 0)?;
        loop {
            match root {
                Node::Internal { children, .. } if children.len() == 1 => {
                    let (_, child) = children.pop().expect("length checked");
                    let Child::Loaded(child) = child else {
                        unreachable!("a two-child root reads both children before a removal");
                    };
                    *root = *child;
                }
                Node::Internal { children, .. } if children.is_empty() => {
                    *root = Node::empty_leaf(stamp);
                }
                _ => break,
            }
        }
        state.evict_over_budget();
        Ok(removed)
    }

    pub fn mark_dirty_from(
        &self,
        from: MetadataKey,
        budget: usize,
    ) -> Result<(Option<MetadataKey>, usize)> {
        let mut state = self.0.tree.lock();
        let TreeState { root, cache } = &mut *state;
        let stamp = cache.tick();
        let mut descent = Descent {
            cache,
            pages: self.0.pages,
            stamp,
        };
        let mut cursor = from;
        let mut marked = 0usize;
        let next = loop {
            let (next, cost) = dirty_leaf(root, cursor, &mut descent, &Above::TOP, None, 0)?;
            marked += cost;
            match next {
                Some(next) if marked < budget => cursor = next,
                other => break other,
            }
        };
        state.evict_over_budget();
        Ok((next, marked))
    }

    pub fn mark_all_dirty(&self) -> Result<()> {
        self.mark_dirty_from(MetadataKey::MIN, usize::MAX)?;
        Ok(())
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
impl MetadataTree {
    pub(crate) fn check_invariants(&self) {
        fn walk(node: &Node, cache: &Cache, parent: Option<&PageMeta>, clean: &mut usize) {
            let meta = node.meta();
            if !cache.pinned(meta) {
                *clean += meta.cost;
            }
            if let Some(parent) = parent {
                assert!(
                    !cache.pinned(meta) || cache.pinned(parent),
                    "a pinned page's parent is pinned"
                );
                assert!(
                    meta.used <= parent.used,
                    "a page is never newer than its parent"
                );
            }
            if let Node::Internal { children, .. } = node {
                assert!(!children.is_empty(), "an internal page has children");
                for (separator, child) in children {
                    if let Child::Loaded(child) = child {
                        assert_eq!(
                            child.min_key(),
                            Some(*separator),
                            "a loaded child starts at its separator"
                        );
                        walk(child, cache, Some(meta), clean);
                    }
                }
            }
        }
        let state = self.lock();
        let mut clean = 0usize;
        walk(&state.root, &state.cache, None, &mut clean);
        assert_eq!(clean, state.cache.clean_bytes, "clean bytes add up");
    }

    pub(crate) fn dirty_pages(&self) -> usize {
        fn walk(node: &Node) -> usize {
            let own = usize::from(node.meta().disk.is_none());
            own + match node {
                Node::Internal { children, .. } => children
                    .iter()
                    .map(|(_, child)| match child {
                        Child::Loaded(child) => walk(child),
                        Child::OnDisk(_) => 0,
                    })
                    .sum(),
                Node::Leaf { .. } => 0,
            }
        }
        walk(&self.lock().root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::XorShift64;
    use std::collections::HashMap;

    fn leaf(items: &[(MetadataKey, MetadataValue)]) -> Vec<u8> {
        encode_leaf_record(items, 1)
    }

    fn internal(entries: &[(MetadataKey, PageRef)]) -> Vec<u8> {
        encode_internal_record(entries, 1)
    }

    fn page(copies: Vec<Extent>, crc: u32, tx: u64) -> PageRef {
        PageRef {
            copies,
            expect: Expect { crc, tx },
        }
    }

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
            bsd_flags: 0,
            crtime_ns: 1_700_000_000_000_000_000,
            mtime_ns: 1_700_000_000_000_000_000,
            ctime_ns: 1_700_000_000_000_000_000,
            atime_ns: 1_700_000_000_000_000_000,
        })
    }

    struct PageStore {
        pages: HashMap<(u16, u64), Vec<u8>>,
        next_offset: u64,
        next_tx: u64,
        reads: std::cell::RefCell<Vec<(u16, u64)>>,
    }

    impl PageStore {
        fn new() -> Self {
            Self {
                pages: HashMap::new(),
                next_offset: 4096,
                next_tx: 1,
                reads: std::cell::RefCell::new(Vec::new()),
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

        fn take_reads(&self) -> Vec<(u16, u64)> {
            std::mem::take(&mut self.reads.borrow_mut())
        }
    }

    impl PageSource for PageStore {
        fn read_page(&self, page: &PageRef) -> Result<Vec<u8>> {
            let extent = page.copies[0];
            self.reads
                .borrow_mut()
                .push((extent.device_index, extent.offset));
            let bytes = self
                .pages
                .get(&(extent.device_index, extent.offset))
                .cloned()
                .ok_or(ScaleFsError::Corrupt("missing page"))?;
            page.expect.verify(&bytes)?;
            Ok(bytes)
        }
    }

    fn commit(tree: &mut MetadataTree, store: &mut PageStore) -> (PageRef, usize) {
        let tx = store.next_tx;
        store.next_tx += 1;
        let mut place = {
            let next = &mut store.next_offset;
            move |len: u64| {
                let offset = *next;
                *next += len.div_ceil(4096) * 4096;
                Ok(vec![(0u16, offset)])
            }
        };
        let (root, pages) = tree.plan_commit(tx, &mut place).unwrap();
        store.write_plan(&pages);
        tree.plan_published();
        (root, pages.len())
    }

    fn committed_tree(count: u64, store: &mut PageStore) -> PageRef {
        let mut tree = MetadataTree::new();
        let edit = tree.in_memory();
        for id in 1..=count {
            edit.insert(inode_key(id), fixture_inode(id)).unwrap();
        }
        commit(&mut tree, store).0
    }

    fn path_to(store: &PageStore, root: &PageRef, key: MetadataKey) -> Vec<(u16, u64)> {
        let mut path = Vec::new();
        let mut copies = root.copies.clone();
        loop {
            let at = (copies[0].device_index, copies[0].offset);
            path.push(at);
            let bytes = &store.pages[&at];
            if decode_record(bytes).unwrap().kind == RecordKind::MetadataLeaf {
                return path;
            }
            let entries = decode_internal_record(bytes).unwrap();
            let idx = entries
                .partition_point(|(separator, _)| *separator <= key)
                .saturating_sub(1);
            copies = entries[idx].1.copies.clone();
        }
    }

    #[test]
    fn insert_get_overwrite_remove() {
        let mut tree = MetadataTree::new();
        let t = tree.in_memory();
        t.insert(inode_key(5), fixture_inode(100)).unwrap();
        assert_eq!(t.get(inode_key(5)).unwrap(), Some(fixture_inode(100)));
        t.insert(inode_key(5), fixture_inode(200)).unwrap();
        assert_eq!(t.get(inode_key(5)).unwrap(), Some(fixture_inode(200)));
        assert_eq!(t.remove(inode_key(5)).unwrap(), Some(fixture_inode(200)));
        assert_eq!(t.get(inode_key(5)).unwrap(), None);
        assert_eq!(t.remove(inode_key(5)).unwrap(), None);
    }

    #[test]
    fn thousands_of_items_stay_sorted_through_splits() {
        let mut tree = MetadataTree::new();
        let t = tree.in_memory();
        let mut rng = XorShift64::new(7);
        let mut ids: Vec<u64> = (1..=3000).collect();
        for i in (1..ids.len()).rev() {
            let j = (rng.next_u64() % (i as u64 + 1)) as usize;
            ids.swap(i, j);
        }
        for &id in &ids {
            t.insert(inode_key(id), fixture_inode(id)).unwrap();
        }
        assert_eq!(t.item_count().unwrap(), 3000);
        let all = t.range(MetadataKey::MIN, MetadataKey::MAX).unwrap();
        assert_eq!(all.len(), 3000);
        for (i, (key, value)) in all.iter().enumerate() {
            assert_eq!(key.object_id, i as u64 + 1);
            assert_eq!(*value, fixture_inode(i as u64 + 1));
        }
        assert_eq!(t.get(inode_key(1)).unwrap(), Some(fixture_inode(1)));
        assert_eq!(t.get(inode_key(2999)).unwrap(), Some(fixture_inode(2999)));
    }

    #[test]
    fn removals_shrink_back_to_an_empty_root() {
        let mut tree = MetadataTree::new();
        let t = tree.in_memory();
        for id in 1..=2000 {
            t.insert(inode_key(id), fixture_inode(id)).unwrap();
        }
        for id in 1..=2000 {
            assert!(t.remove(inode_key(id)).unwrap().is_some(), "id {id}");
        }
        assert_eq!(t.item_count().unwrap(), 0);
        t.insert(inode_key(1), fixture_inode(1)).unwrap();
        assert_eq!(t.get(inode_key(1)).unwrap(), Some(fixture_inode(1)));
    }

    #[test]
    fn range_scans_are_bounded() {
        let mut tree = MetadataTree::new();
        let t = tree.in_memory();
        for id in 1..=100 {
            t.insert(inode_key(id), fixture_inode(id)).unwrap();
        }
        let some = t.range(inode_key(10), inode_key(19)).unwrap();
        assert_eq!(some.len(), 10);
        assert_eq!(some[0].0.object_id, 10);
        assert_eq!(some[9].0.object_id, 19);
    }

    #[test]
    fn commit_writes_only_dirty_pages() {
        let mut tree = MetadataTree::new();
        for id in 1..=3000 {
            tree.in_memory()
                .insert(inode_key(id), fixture_inode(id))
                .unwrap();
        }
        let mut store = PageStore::new();
        let (root1, first_pages) = commit(&mut tree, &mut store);
        assert!(first_pages > 10, "expected a multi-page tree");

        let (root2, second_pages) = commit(&mut tree, &mut store);
        assert_eq!(second_pages, 0);
        assert_eq!(root2, root1);

        tree.edit(&store)
            .insert(inode_key(1500), fixture_inode(9999))
            .unwrap();
        let (root3, third_pages) = commit(&mut tree, &mut store);
        assert_ne!(root3, root1);
        assert!(
            (2..=4).contains(&third_pages),
            "path copy should touch the leaf and its ancestors, wrote {third_pages}"
        );

        let loaded = MetadataTree::load(&root3, &store).unwrap();
        let view = loaded.view(&store);
        assert_eq!(view.item_count().unwrap(), 3000);
        assert_eq!(
            view.get(inode_key(1500)).unwrap(),
            Some(fixture_inode(9999))
        );
        assert_eq!(view.get(inode_key(42)).unwrap(), Some(fixture_inode(42)));
    }

    #[test]
    fn loaded_trees_continue_with_incremental_commits() {
        let mut store = PageStore::new();
        let root = committed_tree(3000, &mut store);

        let mut reloaded = MetadataTree::load(&root, &store).unwrap();
        let (same_root, pages) = commit(&mut reloaded, &mut store);
        assert_eq!(pages, 0);
        assert_eq!(same_root, root);
        reloaded
            .edit(&store)
            .insert(inode_key(7), fixture_inode(7000))
            .unwrap();
        let (_, pages) = commit(&mut reloaded, &mut store);
        assert!((2..=4).contains(&pages), "wrote {pages}");
    }

    #[test]
    fn empty_tree_commits_and_loads() {
        let mut tree = MetadataTree::new();
        let mut store = PageStore::new();
        let (root, pages) = commit(&mut tree, &mut store);
        assert_eq!(pages, 1);
        let loaded = MetadataTree::load(&root, &store).unwrap();
        assert_eq!(loaded.view(&store).item_count().unwrap(), 0);
    }

    #[test]
    fn corrupted_pages_fail_to_load_or_to_walk() {
        let mut store = PageStore::new();
        let root = committed_tree(3000, &mut store);

        let keys: Vec<(u16, u64)> = store.pages.keys().copied().collect();
        for key in keys {
            let mut corrupted = store.pages.clone();
            let page = corrupted.get_mut(&key).unwrap();
            let mid = page.len() / 2;
            page[mid] ^= 0xFF;
            let read = move |page: &PageRef| {
                let extent = page.copies[0];
                corrupted
                    .get(&(extent.device_index, extent.offset))
                    .cloned()
                    .ok_or(ScaleFsError::Corrupt("missing page"))
            };
            let walked =
                MetadataTree::load(&root, &read).and_then(|tree| tree.view(&read).item_count());
            assert!(walked.is_err(), "page {key:?}");
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
            tree.in_memory().insert(key, value),
            Err(ScaleFsError::InvalidArgument(_))
        ));
    }

    #[test]
    fn opening_a_tree_reads_only_its_root() {
        let mut store = PageStore::new();
        let root = committed_tree(20_000, &mut store);
        assert!(store.pages.len() > 100, "a tree of many pages");
        let tree = MetadataTree::load(&root, &store).unwrap();
        assert_eq!(
            store.take_reads(),
            vec![(root.copies[0].device_index, root.copies[0].offset)]
        );
        let stats = tree.cache_stats();
        assert_eq!(stats.loaded_pages, 1);
        assert_eq!(stats.page_reads, 1);
    }

    #[test]
    fn a_cold_descent_reads_the_pages_on_its_path_and_nothing_else() {
        let mut store = PageStore::new();
        let root = committed_tree(20_000, &mut store);
        let tree = MetadataTree::load(&root, &store).unwrap();
        tree.set_cache_budget(64 << 20);
        store.take_reads();
        let view = tree.view(&store);
        for (n, id) in [1u64, 7_777, 20_000].into_iter().enumerate() {
            let expected = path_to(&store, &root, inode_key(id));
            assert!(expected.len() >= 3, "a tree at least three levels deep");
            assert_eq!(view.get(inode_key(id)).unwrap(), Some(fixture_inode(id)));
            let reads = store.take_reads();
            assert!(
                reads.iter().all(|page| expected.contains(page)),
                "{reads:?} vs {expected:?}"
            );
            let unique: std::collections::HashSet<_> = reads.iter().collect();
            assert_eq!(unique.len(), reads.len(), "no page is read twice");
            if n == 0 {
                assert_eq!(reads, expected[1..].to_vec());
            }
            assert_eq!(view.get(inode_key(id)).unwrap(), Some(fixture_inode(id)));
            assert!(store.take_reads().is_empty());
        }
        assert_eq!(view.get(MetadataKey::MIN).unwrap(), None);
        assert!(store.take_reads().is_empty(), "the leftmost path is warm");
        tree.check_invariants();
    }

    #[test]
    fn a_tree_larger_than_its_cache_stays_correct() {
        let mut store = PageStore::new();
        let mut tree = MetadataTree::new();
        tree.set_cache_budget(48 << 10);
        let mut oracle = std::collections::BTreeMap::new();
        let mut rng = XorShift64::new(0x5CA1E);
        for step in 0..30_000u64 {
            let id = rng.next_u64() % 4_000 + 1;
            match rng.next_u64() % 10 {
                0..=4 => {
                    let value = fixture_inode(rng.next_u64() % 1_000_000);
                    tree.edit(&store)
                        .insert(inode_key(id), value.clone())
                        .unwrap();
                    oracle.insert(id, value);
                }
                5 | 6 => {
                    let removed = tree.edit(&store).remove(inode_key(id)).unwrap();
                    assert_eq!(removed, oracle.remove(&id), "remove {id}");
                }
                7 | 8 => {
                    let found = tree.view(&store).get(inode_key(id)).unwrap();
                    assert_eq!(found.as_ref(), oracle.get(&id), "get {id}");
                }
                _ => {
                    let end = id + rng.next_u64() % 300;
                    let scanned: Vec<(u64, MetadataValue)> = tree
                        .view(&store)
                        .range(inode_key(id), inode_key(end))
                        .unwrap()
                        .into_iter()
                        .map(|(key, value)| (key.object_id, value))
                        .collect();
                    let expected: Vec<(u64, MetadataValue)> = oracle
                        .range(id..=end)
                        .map(|(id, value)| (*id, value.clone()))
                        .collect();
                    assert_eq!(scanned, expected, "range {id}..={end}");
                }
            }
            if step % 400 == 399 {
                commit(&mut tree, &mut store);
                tree.check_invariants();
            }
        }
        let stats = tree.cache_stats();
        assert!(
            stats.pages_evicted > 0,
            "the cache was too small to hold the tree"
        );
        assert!(stats.page_reads > 0, "evicted pages were read back");
        let (root, _) = commit(&mut tree, &mut store);
        let all: Vec<(u64, MetadataValue)> = oracle.into_iter().collect();
        let through = |tree: &MetadataTree| -> Vec<(u64, MetadataValue)> {
            tree.view(&store)
                .range(MetadataKey::MIN, MetadataKey::MAX)
                .unwrap()
                .into_iter()
                .map(|(key, value)| (key.object_id, value))
                .collect()
        };
        assert_eq!(through(&tree), all);
        let reopened = MetadataTree::load(&root, &store).unwrap();
        reopened.set_cache_budget(48 << 10);
        assert_eq!(through(&reopened), all);
        assert!(reopened.cache_stats().clean_bytes <= 48 << 10);
    }

    #[test]
    fn eviction_never_drops_a_dirty_page_or_an_ancestor_of_one() {
        let mut store = PageStore::new();
        let root = committed_tree(20_000, &mut store);
        let mut tree = MetadataTree::load(&root, &store).unwrap();
        assert_eq!(tree.view(&store).item_count().unwrap(), 20_000);
        let changed = [3u64, 4_444, 9_999, 15_000, 19_998];
        for id in changed {
            tree.edit(&store)
                .insert(inode_key(id), fixture_inode(id * 10))
                .unwrap();
        }
        let dirty = tree.dirty_pages();
        assert!(
            dirty >= changed.len(),
            "each change dirties a leaf and its path"
        );
        tree.set_cache_budget(0);
        tree.check_invariants();
        let stats = tree.cache_stats();
        assert!(stats.pages_evicted > 0);
        assert_eq!(tree.dirty_pages(), dirty, "no dirty page was evicted");
        assert_eq!(stats.clean_bytes, 0, "only the pinned set is left");
        assert_eq!(stats.loaded_pages, stats.pinned_pages);
        store.take_reads();
        for id in changed {
            assert_eq!(
                tree.view(&store).get(inode_key(id)).unwrap(),
                Some(fixture_inode(id * 10))
            );
        }
        assert!(
            store.take_reads().is_empty(),
            "the dirty paths stayed in memory"
        );
        let (root, written) = commit(&mut tree, &mut store);
        assert_eq!(written, dirty);
        let reopened = MetadataTree::load(&root, &store).unwrap();
        let view = reopened.view(&store);
        assert_eq!(view.item_count().unwrap(), 20_000);
        for id in changed {
            assert_eq!(
                view.get(inode_key(id)).unwrap(),
                Some(fixture_inode(id * 10))
            );
        }
        assert_eq!(view.get(inode_key(5)).unwrap(), Some(fixture_inode(5)));
    }

    #[test]
    fn a_plan_in_flight_is_pinned_and_an_abandoned_one_rewrites_exactly_its_pages() {
        let mut store = PageStore::new();
        let root = committed_tree(20_000, &mut store);
        let mut tree = MetadataTree::load(&root, &store).unwrap();
        for id in [10u64, 12_000] {
            tree.edit(&store)
                .insert(inode_key(id), fixture_inode(1))
                .unwrap();
        }
        let dirty = tree.dirty_pages();
        let mut next = 1 << 30;
        let mut place = |len: u64| {
            let offset = next;
            next += len.div_ceil(4096) * 4096;
            Ok(vec![(0u16, offset)])
        };
        let (_, pages) = tree.plan_commit(9, &mut place).unwrap();
        assert_eq!(pages.len(), dirty);
        assert_eq!(tree.dirty_pages(), 0, "planned pages count as clean");
        tree.set_cache_budget(0);
        assert_eq!(tree.cache_stats().pinned_pages, dirty as u64);
        tree.check_invariants();
        tree.plan_abandoned();
        assert_eq!(tree.dirty_pages(), dirty);
        tree.check_invariants();
        let (root, written) = commit(&mut tree, &mut store);
        assert_eq!(written, dirty);
        tree.set_cache_budget(0);
        assert_eq!(tree.cache_stats().pinned_pages, 0);
        let reopened = MetadataTree::load(&root, &store).unwrap();
        assert_eq!(
            reopened.view(&store).get(inode_key(12_000)).unwrap(),
            Some(fixture_inode(1))
        );
    }

    #[test]
    fn a_whole_tree_rewrite_in_batches_replaces_every_page() {
        let mut store = PageStore::new();
        let root = committed_tree(20_000, &mut store);
        let before: std::collections::HashSet<(u16, u64)> = store.pages.keys().copied().collect();
        let mut tree = MetadataTree::load(&root, &store).unwrap();
        tree.set_cache_budget(64 << 10);
        let mut cursor = Some(MetadataKey::MIN);
        let mut batches = 0;
        let mut root = root;
        while let Some(from) = cursor {
            let (next, marked) = tree.edit(&store).mark_dirty_from(from, 32 << 10).unwrap();
            assert!(marked > 0);
            assert!(
                tree.cache_stats().pinned_pages < 40,
                "{:?}",
                tree.cache_stats()
            );
            root = commit(&mut tree, &mut store).0;
            tree.check_invariants();
            batches += 1;
            cursor = next;
        }
        assert!(batches > 3, "the rewrite took several commits ({batches})");
        let mut live = Vec::new();
        let mut stack = vec![root.clone()];
        while let Some(page) = stack.pop() {
            let at = (page.copies[0].device_index, page.copies[0].offset);
            live.push(at);
            let bytes = &store.pages[&at];
            if let Ok(entries) = decode_internal_record(bytes) {
                stack.extend(entries.into_iter().map(|(_, child)| child));
            }
        }
        assert!(
            live.iter().all(|page| !before.contains(page)),
            "no page survived the rewrite"
        );
        let reopened = MetadataTree::load(&root, &store).unwrap();
        assert_eq!(reopened.view(&store).item_count().unwrap(), 20_000);
    }

    #[test]
    fn crafted_child_pointers_are_refused_on_the_way_down() {
        let mut store = PageStore::new();
        let root = committed_tree(20_000, &mut store);
        let root_at = (root.copies[0].device_index, root.copies[0].offset);
        let entries = decode_internal_record(&store.pages[&root_at]).unwrap();
        let reseal = |store: &mut PageStore, entries: &[(MetadataKey, PageRef)]| -> PageRef {
            let bytes = internal(entries);
            let resealed = PageRef {
                copies: root.copies.clone(),
                expect: Expect::of(&bytes),
            };
            store.pages.insert(root_at, bytes);
            resealed
        };

        let mut looped = entries.clone();
        looped[1].1 = root.clone();
        let root = reseal(&mut store, &looped);
        assert!(matches!(
            MetadataTree::load(&root, &store),
            Err(ScaleFsError::Corrupt(_))
        ));

        let mut shared = entries.clone();
        shared[1].1 = shared[0].1.clone();
        let root = reseal(&mut store, &shared);
        assert!(matches!(
            MetadataTree::load(&root, &store),
            Err(ScaleFsError::Corrupt(_))
        ));

        let mut swapped = entries.clone();
        let (first, second) = (swapped[0].1.clone(), swapped[1].1.clone());
        swapped[0].1 = second;
        swapped[1].1 = first;
        let root = reseal(&mut store, &swapped);
        let tree = MetadataTree::load(&root, &store).unwrap();
        let view = tree.view(&store);
        assert!(matches!(
            view.get(inode_key(1)),
            Err(ScaleFsError::Corrupt(_))
        ));
        let untouched = entries[entries.len() - 1].0;
        if entries.len() > 2 {
            assert!(view.get(untouched).unwrap().is_some());
        }
        assert!(view.item_count().is_err());
    }

    #[test]
    fn concurrent_readers_share_one_cold_tree() {
        struct Frozen(HashMap<(u16, u64), Vec<u8>>);
        impl PageSource for Frozen {
            fn read_page(&self, page: &PageRef) -> Result<Vec<u8>> {
                let extent = page.copies[0];
                self.0
                    .get(&(extent.device_index, extent.offset))
                    .cloned()
                    .ok_or(ScaleFsError::Corrupt("missing page"))
            }
        }
        let mut store = PageStore::new();
        let root = committed_tree(20_000, &mut store);
        let frozen = Frozen(store.pages.clone());
        let tree = MetadataTree::load(&root, &frozen).unwrap();
        tree.set_cache_budget(64 << 10);
        std::thread::scope(|scope| {
            for seed in 1..=4u64 {
                let (tree, frozen) = (&tree, &frozen);
                scope.spawn(move || {
                    let view = tree.view(frozen);
                    let mut rng = XorShift64::new(seed);
                    for _ in 0..3_000 {
                        let id = rng.next_u64() % 20_000 + 1;
                        assert_eq!(view.get(inode_key(id)).unwrap(), Some(fixture_inode(id)));
                    }
                });
            }
        });
        tree.check_invariants();
        assert!(tree.cache_stats().clean_bytes <= 64 << 10);
    }

    fn small_run(data_offset: u64, logical_len: u64) -> FileRun {
        FileRun {
            copies: vec![Extent {
                device_index: 0,
                offset: 0,
                length: 100,
            }],
            stride: 4096,
            last_len: 100,
            tx: 1,
            crcs: vec![0xFEED],
            data_offset,
            logical_len,
        }
    }

    #[test]
    fn value_validation_rejects_bad_contents() {
        let mut same_member = small_run(0, 20);
        same_member.copies.push(Extent {
            device_index: 0,
            offset: 4096,
            length: 100,
        });
        let mut unequal = small_run(0, 20);
        unequal.copies.push(Extent {
            device_index: 1,
            offset: 0,
            length: 132,
        });
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
            MetadataValue::FileRun(small_run(0, 0)),
            MetadataValue::FileRun(small_run(0, 69)),
            MetadataValue::FileRun(small_run(60, 20)),
            MetadataValue::FileRun(same_member),
            MetadataValue::FileRun(unequal),
        ] {
            assert!(value.validate().is_err(), "{value:?}");
        }
        assert!(MetadataValue::FileRun(small_run(4, 64)).validate().is_ok());
    }

    fn fixture_striped(parity_members: &[u16]) -> MetadataValue {
        MetadataValue::StripedRun(StripedRun {
            pieces: vec![
                Extent {
                    device_index: 2,
                    offset: 1 << 20,
                    length: 32 * 1024,
                },
                Extent {
                    device_index: 3,
                    offset: 1 << 20,
                    length: 100,
                },
            ],
            crcs: vec![0xAAAA_0001, 0xAAAA_0002],
            tx: 6,
            parity: parity_members
                .iter()
                .map(|&member| Extent {
                    device_index: member,
                    offset: 1 << 21,
                    length: 32 * 1024 + 4096,
                })
                .collect(),
            parity_crcs: parity_members
                .iter()
                .map(|&member| 0xBBBB_0000 | u32::from(member))
                .collect(),
            parity_tx: 6,
            data_offset: 4,
            logical_len: crate::fs::FILE_DATA_CHUNK as u64 + 60,
        })
    }

    #[test]
    fn striped_runs_round_trip_and_validate() {
        let key = MetadataKey {
            object_id: 5,
            item_type: ITEM_FILE_EXTENT,
            offset: 0,
        };
        let value = fixture_striped(&[0, 4]);
        let record = leaf(&[(key, value.clone())]);
        assert_eq!(decode_leaf_record(&record).unwrap(), vec![(key, value)]);

        let mutate = |f: &dyn Fn(&mut StripedRun)| {
            let MetadataValue::StripedRun(mut run) = fixture_striped(&[0, 4]) else {
                unreachable!()
            };
            f(&mut run);
            MetadataValue::StripedRun(run).validate()
        };
        for (name, mutation) in [
            (
                "no parity records",
                &(|r: &mut StripedRun| {
                    r.parity.clear();
                    r.parity_crcs.clear();
                }) as &dyn Fn(&mut StripedRun),
            ),
            ("unequal parity lengths", &|r: &mut StripedRun| {
                r.parity[1].length += 1;
            }),
            ("parity on a data member", &|r: &mut StripedRun| {
                r.parity[0].device_index = r.pieces[0].device_index;
            }),
            (
                "a parity row without its checksum",
                &|r: &mut StripedRun| {
                    r.parity_crcs.pop();
                },
            ),
            ("zero logical length", &|r: &mut StripedRun| {
                r.logical_len = 0;
            }),
            ("range outside the records", &|r: &mut StripedRun| {
                r.logical_len += 100;
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
        let record = leaf(&[(key, fixture_striped(&[0, 4]))]);
        assert_eq!(
            hex(&record),
            "5363616c6546530002000000030000009800000013e6368f01000000000000000100050000000000000003008000000000000083000802020000000000100000000000008000000000000003000000000010000000000064000000000000000100aaaa0200aaaa060000000000000002000000000000200000000000009000000000000004000000000020000000000000900000000000000000bbbb0400bbbb060000000000000004000000000000001c80000000000000"
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
        let record = encode_record(RecordKind::MetadataLeaf, 1, &payload);
        assert!(decode_leaf_record(&record).is_err());

        let mut payload = Vec::new();
        put_u16(&mut payload, 1);
        encode_key(&mut payload, inode_key(1));
        put_u16(&mut payload, 1);
        payload.push(100);
        let record = encode_record(RecordKind::MetadataLeaf, 1, &payload);
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
        let record = leaf(&[(key, opaque.clone())]);
        assert_eq!(decode_leaf_record(&record).unwrap(), vec![(key, opaque)]);

        let record = leaf(&[(
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
        let record = leaf(&[(inode_key(2), bucket.clone())]);
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
        let record = leaf(&[(key, bucket.clone())]);
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
        let record = encode_record(RecordKind::MetadataLeaf, 1, &payload);
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
        let record = leaf(&[(key, target.clone())]);
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
        let record = leaf(&[(dev_key, dev.clone())]);
        assert_eq!(decode_leaf_record(&record).unwrap(), vec![(dev_key, dev)]);
    }

    #[test]
    fn golden_special_fixture_is_stable() {
        let record = leaf(&[(
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
            "5363616c6546530002000000030000001a0000003c2916a10100000000000000010009000000000000000500000000000000000500802e2e2f62"
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
        let record = encode_record(RecordKind::MetadataLeaf, 1, &payload);
        assert!(matches!(
            decode_leaf_record(&record),
            Err(ScaleFsError::Corrupt(
                "metadata value exceeds the size limit"
            ))
        ));
    }

    #[test]
    fn golden_opaque_fixture_is_stable() {
        let record = leaf(&[(
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
            "5363616c6546530002000000030000001900000007c3813c0100000000000000010007000000000000000900000000000000000400c8657874"
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
        let record = internal(&[(inode_key(1), page(vec![extent], 1, 1))]);
        assert!(decode_internal_record(&record).is_err());
        let record = internal(&[
            (inode_key(2), page(vec![extent], 1, 1)),
            (inode_key(1), page(vec![extent], 2, 1)),
        ]);
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
                    root: page(
                        vec![Extent {
                            device_index: 0,
                            offset: 67_117_056,
                            length: 4128,
                        }],
                        0xA1A2_A3A4,
                        2,
                    ),
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
                    bsd_flags: 0,
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
                MetadataValue::FileRun(FileRun {
                    copies: vec![Extent {
                        device_index: 0,
                        offset: 134_217_728,
                        length: 4128,
                    }],
                    stride: 8192,
                    last_len: 4128,
                    tx: 2,
                    crcs: vec![0xC1C1_0001],
                    data_offset: 0,
                    logical_len: 4000,
                }),
            ),
        ];
        let record = leaf(&items);
        assert_eq!(
            hex(&record),
            "5363616c65465300020000000300000094010000626de5e701000000000000000600000000000000000000000000000000000009000103000000000000000000000000000000042a000000000000004200050300000000000000010000000000200004000000002010000000000000a4a3a2a1020000000000000000002a36fe9c97170e006265666f72652d7570677261646501000000000000000100000000000000004100020000000000000000ed410000000000000000000001000000000000000000000000002a36fe9c971700002a36fe9c971700002a36fe9c971700002a36fe9c971701000000000000000208070605040302011700030100020000000000000001090068656c6c6f2e7478740200000000000000010000000000000000410002a00f000000000000a4810000e8030000e803000001000000200000000000000000002a36fe9c971700002a36fe9c971700002a36fe9c971700002a36fe9c971702000000000000000300000000000000003c00040100000000000000080000000020100000000000000020000001002010000002000000000000000100c1c10000000000000000a00f000000000000"
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
                    root: page(copies(67_117_056, 4128), 0xB1B2_B3B4, 3),
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
                MetadataValue::FileRun(FileRun {
                    copies: copies(134_217_728, 32 * 1024),
                    stride: 32 * 1024,
                    last_len: 4128,
                    tx: 3,
                    crcs: vec![0xD1D1_0001, 0xD1D1_0002, 0xD1D1_0003],
                    data_offset: 100,
                    logical_len: 2 * crate::fs::FILE_DATA_CHUNK as u64 + 3000,
                }),
            ),
        ];
        let record = leaf(&items);
        assert_eq!(
            hex(&record),
            "5363616c654653000200000003000000ce000000c2d5fb24010000000000000002000000000000000000042a000000000000004e000503000000000000000200000000002000040000000020100000000000000100000000300004000000002010000000000000b4b3b2b1030000000000000000002a36fe9c9717060070696e6e6564020000000000000003000000000000000058000402000000000000000800000000008000000000000001000000001000080000000000800000000000000080000003002010000003000000000000000100d1d10200d1d10300d1d16400000000000000780b010000000000"
        );
        assert_eq!(decode_leaf_record(&record).unwrap(), items);

        let entries = vec![
            (
                MetadataKey::MIN,
                page(copies(67_108_864, 1000), 0xC1C2_C3C4, 4),
            ),
            (inode_key(2), page(copies(67_112_960, 2000), 0xD1D2_D3D4, 5)),
        ];
        let record = internal(&entries);
        assert_eq!(
            hex(&record),
            "5363616c6546530002000000040000008e000000c299d58701000000000000000200000000000000000000000000000000000002000000000000000400000000e803000000000000010000000010000400000000e803000000000000c4c3c2c10400000000000000020000000000000001000000000000000002000000000010000400000000d007000000000000010000000020000400000000d007000000000000d4d3d2d10500000000000000"
        );
        assert_eq!(decode_internal_record(&record).unwrap(), entries);
    }

    #[test]
    fn mixed_copy_counts_round_trip_in_internal_pages() {
        let entries = vec![
            (
                MetadataKey::MIN,
                page(
                    vec![Extent {
                        device_index: 0,
                        offset: 67_108_864,
                        length: 1000,
                    }],
                    11,
                    1,
                ),
            ),
            (
                inode_key(2),
                page(
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
                    12,
                    2,
                ),
            ),
        ];
        let record = internal(&entries);
        assert_eq!(decode_internal_record(&record).unwrap(), entries);
    }

    #[test]
    fn golden_internal_fixture_is_stable() {
        let entries = vec![
            (
                MetadataKey::MIN,
                page(
                    vec![Extent {
                        device_index: 0,
                        offset: 67_108_864,
                        length: 1000,
                    }],
                    0xE1E2_E3E4,
                    6,
                ),
            ),
            (
                inode_key(2),
                page(
                    vec![Extent {
                        device_index: 0,
                        offset: 67_112_960,
                        length: 2000,
                    }],
                    0xF1F2_F3F4,
                    7,
                ),
            ),
        ];
        let record = internal(&entries);
        assert_eq!(
            hex(&record),
            "5363616c654653000200000004000000660000005fac987501000000000000000200000000000000000000000000000000000001000000000000000400000000e803000000000000e4e3e2e10600000000000000020000000000000001000000000000000001000000000010000400000000d007000000000000f4f3f2f10700000000000000"
        );
        assert_eq!(decode_internal_record(&record).unwrap(), entries);
    }
}
