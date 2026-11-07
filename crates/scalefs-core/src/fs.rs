use crate::device::BlockDevice;
use crate::dirent;
use crate::error::{Result, ScaleFsError};
use crate::format::Expect;
use crate::layout::{CaseSensitivity, Extent};
use crate::pool::Pool;
use crate::records::{
    FEATURE_RO_COMPAT_HARDLINKS, FEATURE_RO_COMPAT_SPECIAL_FILES, FEATURE_RO_COMPAT_XATTRS,
    encode_file_data,
};
use crate::rs::ParityEncoder;
use crate::runs::{FileRun, MAX_RUN_RECORDS, MAX_RUN_SPAN, StripedRun};
use crate::stripes::{ParityRecord, encode_parity_record, parity_record_len};
use crate::tree::{
    DirEntry, EntryKind, FILE_ATTR_ARCHIVE, ITEM_FILE_EXTENT, ITEM_INODE, ITEM_POOL_STATE,
    ITEM_SPECIAL, ITEM_XATTR, InodeAttrs, MAX_VALUE_LEN, MODE_BLOCK_DEVICE, MODE_CHAR_DEVICE,
    MODE_DIRECTORY, MODE_FIFO, MODE_FILE, MODE_SOCKET, MODE_SYMLINK, MODE_TYPE_MASK, MetadataKey,
    MetadataValue, TreeRef, XATTR_VALUE_MAX, XattrEntry,
};
use crate::unicode::UnicodeVersion;
use crate::zones::{AllocPurpose, ZoneClass};

pub const FILE_DATA_CHUNK: usize = 32 * 1024 - crate::format::RECORD_HEADER_LEN;

fn inode_key(object_id: u64) -> MetadataKey {
    MetadataKey {
        object_id,
        item_type: ITEM_INODE,
        offset: 0,
    }
}

fn extent_key(object_id: u64, offset: u64) -> MetadataKey {
    MetadataKey {
        object_id,
        item_type: ITEM_FILE_EXTENT,
        offset,
    }
}

fn xattr_key(object_id: u64, hash: u64) -> MetadataKey {
    MetadataKey {
        object_id,
        item_type: ITEM_XATTR,
        offset: hash,
    }
}

fn special_key(object_id: u64) -> MetadataKey {
    MetadataKey {
        object_id,
        item_type: ITEM_SPECIAL,
        offset: 0,
    }
}

pub const MAX_SYMLINK_TARGET: usize = MAX_VALUE_LEN - 1;

pub const LINK_MAX: u32 = 65_000;

pub const XATTR_SET_EITHER: u32 = 0;
pub const XATTR_SET_CREATE: u32 = 1;
pub const XATTR_SET_REPLACE: u32 = 2;

#[derive(Debug, Clone)]
pub(crate) enum LiveRun {
    Mirrored(FileRun),
    Striped(StripedRun),
}

impl LiveRun {
    fn logical_len(&self) -> u64 {
        match self {
            LiveRun::Mirrored(run) => run.logical_len,
            LiveRun::Striped(run) => run.logical_len,
        }
    }

    fn slice(&self, skip: u64, len: u64) -> MetadataValue {
        match self {
            LiveRun::Mirrored(run) => MetadataValue::FileRun(run.slice(skip, len)),
            LiveRun::Striped(run) => MetadataValue::StripedRun(run.slice(skip, len)),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct LiveExtent {
    start: u64,
    run: LiveRun,
}

impl LiveExtent {
    fn end(&self) -> u64 {
        self.start + self.run.logical_len()
    }

    fn of(key: MetadataKey, value: MetadataValue) -> Option<LiveExtent> {
        let run = match value {
            MetadataValue::FileRun(run) => LiveRun::Mirrored(run),
            MetadataValue::StripedRun(run) => LiveRun::Striped(run),
            _ => return None,
        };
        Some(LiveExtent {
            start: key.offset,
            run,
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct EmittedStripe {
    pub placed: usize,
    pub pieces: Vec<Extent>,
    pub crcs: Vec<u32>,
    pub parity: Vec<Extent>,
    pub parity_crcs: Vec<u32>,
    pub parity_tx: u64,
}

pub(crate) fn getattr_in(tree: TreeRef<'_>, object_id: u64) -> Result<InodeAttrs> {
    tree.get_with(inode_key(object_id), |value| match value {
        Some(MetadataValue::Inode(attrs)) => Ok(*attrs),
        Some(_) => Err(ScaleFsError::Corrupt("non-inode value at an inode key")),
        None => Err(ScaleFsError::NotFound),
    })?
}

pub(crate) fn live_extents_overlapping(
    tree: TreeRef<'_>,
    object_id: u64,
    start: u64,
    end: u64,
) -> Result<Vec<LiveExtent>> {
    if start >= end {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let lookback = extent_key(object_id, start.saturating_sub(MAX_RUN_SPAN - 1));
    if let Some((key, value)) = tree.last_in(lookback, extent_key(object_id, start))?
        && let Some(live) = LiveExtent::of(key, value)
        && live.end() > start
    {
        out.push(live);
    }
    if start + 1 < end {
        for (key, value) in tree.range(
            extent_key(object_id, start + 1),
            extent_key(object_id, end - 1),
        )? {
            out.extend(LiveExtent::of(key, value));
        }
    }
    Ok(out)
}

pub(crate) fn read_in<D: BlockDevice>(
    pool: &Pool<D>,
    tree: TreeRef<'_>,
    object_id: u64,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>> {
    let attrs = getattr_in(tree, object_id)?;
    if attrs.is_dir() {
        return Err(ScaleFsError::IsDirectory);
    }
    if attrs.mode & MODE_TYPE_MASK != MODE_FILE {
        return Err(ScaleFsError::InvalidArgument(
            "not a regular file; special files hold no file data",
        ));
    }
    if offset >= attrs.size {
        return Ok(Vec::new());
    }
    let read_len = (attrs.size - offset).min(len as u64) as usize;
    let end = offset + read_len as u64;
    let mut out = vec![0u8; read_len];

    for live in live_extents_overlapping(tree, object_id, offset, end)? {
        let from = live.start.max(offset);
        let to = live.end().min(end);
        if from >= to {
            continue;
        }
        let skip = from - live.start;
        let dst = &mut out[(from - offset) as usize..(to - offset) as usize];
        match &live.run {
            LiveRun::Mirrored(run) => {
                pool.read_run_window(run, run.window(skip, to - from), dst)?;
            }
            LiveRun::Striped(run) => {
                pool.read_striped_window(run, run.window(skip, to - from), dst)?;
            }
        }
    }
    Ok(out)
}

struct RunBuilder {
    start: u64,
    zones: Vec<(u16, u64)>,
    run: FileRun,
}

impl RunBuilder {
    fn continues(&self, len: u64, placements: &[(u16, crate::zones::Allocation)]) -> bool {
        let run = &self.run;
        let count = run.count() as u64;
        run.count() < MAX_RUN_RECORDS
            && run.last_len == run.copies[0].length
            && len <= run.copies[0].length
            && placements.len() == run.copies.len()
            && run.copies.iter().all(|copy| {
                placements.iter().any(|(member, allocation)| {
                    *member == copy.device_index
                        && allocation.offset == copy.offset + count * run.stride
                        && self.zones.contains(&(*member, allocation.zone_index))
                })
            })
    }
}

impl<D: BlockDevice> Pool<D> {
    pub(crate) fn naming(&self) -> (u64, UnicodeVersion, CaseSensitivity) {
        (
            self.superblocks[0].dirent_hash_seed,
            self.superblocks[0].unicode_version,
            self.superblocks[0].case_sensitivity,
        )
    }

    pub fn getattr(&self, object_id: u64) -> Result<InodeAttrs> {
        getattr_in(self.tree(), object_id)
    }

    fn put_attrs(&mut self, object_id: u64, attrs: InodeAttrs) -> Result<()> {
        self.tree_mut()
            .insert(inode_key(object_id), MetadataValue::Inode(attrs))
    }

    pub fn update_attrs(
        &mut self,
        object_id: u64,
        mutate: impl FnOnce(&mut InodeAttrs),
    ) -> Result<()> {
        self.ensure_mutable()?;
        let mut attrs = self.getattr(object_id)?;
        let size_before = attrs.size;
        let type_before = attrs.mode & MODE_TYPE_MASK;
        let nlink_before = attrs.nlink;
        mutate(&mut attrs);
        attrs.size = size_before;
        attrs.mode = (attrs.mode & !MODE_TYPE_MASK) | type_before;
        attrs.nlink = nlink_before;
        self.put_attrs(object_id, attrs)
    }

    fn require_dir(&self, object_id: u64) -> Result<InodeAttrs> {
        let attrs = self.getattr(object_id)?;
        if !attrs.is_dir() {
            return Err(ScaleFsError::NotDirectory);
        }
        Ok(attrs)
    }

    fn require_file(&self, object_id: u64) -> Result<InodeAttrs> {
        let attrs = self.getattr(object_id)?;
        if attrs.is_dir() {
            return Err(ScaleFsError::IsDirectory);
        }
        if attrs.mode & MODE_TYPE_MASK != MODE_FILE {
            return Err(ScaleFsError::InvalidArgument(
                "not a regular file; special files hold no file data",
            ));
        }
        Ok(attrs)
    }

    pub(crate) fn allocate_object_id(&mut self) -> Result<u64> {
        let key = MetadataKey {
            object_id: 0,
            item_type: ITEM_POOL_STATE,
            offset: 0,
        };
        let next = match self.tree().get(key)? {
            Some(MetadataValue::PoolState { next_object_id }) => next_object_id,
            _ => return Err(ScaleFsError::Corrupt("pool state item is missing")),
        };
        self.tree_mut().insert(
            key,
            MetadataValue::PoolState {
                next_object_id: next + 1,
            },
        )?;
        Ok(next)
    }

    fn touch_modified(&mut self, object_id: u64, now_ns: i64) -> Result<()> {
        let mut attrs = self.getattr(object_id)?;
        attrs.mtime_ns = now_ns;
        attrs.ctime_ns = now_ns;
        self.put_attrs(object_id, attrs)
    }

    pub fn lookup(&self, parent: u64, name: &str) -> Result<DirEntry> {
        self.require_dir(parent)?;
        let (seed, version, case) = self.naming();
        dirent::lookup_entry(self.tree(), seed, version, case, parent, name)?
            .ok_or(ScaleFsError::NotFound)
    }

    pub fn readdir(&self, dir: u64) -> Result<Vec<DirEntry>> {
        self.require_dir(dir)?;
        dirent::list_entries(self.tree(), dir)
    }

    pub fn readdir_hashed(&self, dir: u64) -> Result<Vec<dirent::HashedEntry>> {
        self.require_dir(dir)?;
        dirent::list_entries_hashed(self.tree(), dir)
    }

    pub fn create_file(&mut self, parent: u64, name: &str, mode: u32, now_ns: i64) -> Result<u64> {
        self.create_object(parent, name, mode, EntryKind::File, now_ns)
    }

    pub fn mkdir(&mut self, parent: u64, name: &str, mode: u32, now_ns: i64) -> Result<u64> {
        self.create_object(parent, name, mode, EntryKind::Directory, now_ns)
    }

    fn create_object(
        &mut self,
        parent: u64,
        name: &str,
        mode: u32,
        kind: EntryKind,
        now_ns: i64,
    ) -> Result<u64> {
        self.ensure_mutable()?;
        self.require_dir(parent)?;
        dirent::validate_name(name)?;
        let (seed, version, case) = self.naming();
        if dirent::lookup_entry(self.tree(), seed, version, case, parent, name)?.is_some() {
            return Err(ScaleFsError::AlreadyExists);
        }

        let object_id = self.allocate_object_id()?;
        let (type_bits, attrs) = match kind {
            EntryKind::File => (MODE_FILE, FILE_ATTR_ARCHIVE),
            EntryKind::Directory => (MODE_DIRECTORY, 0),
            EntryKind::Symlink => (MODE_SYMLINK, 0),
            EntryKind::Fifo => (MODE_FIFO, 0),
            EntryKind::Socket => (MODE_SOCKET, 0),
            EntryKind::CharDevice => (MODE_CHAR_DEVICE, 0),
            EntryKind::BlockDevice => (MODE_BLOCK_DEVICE, 0),
            EntryKind::Unknown(_) => {
                return Err(ScaleFsError::InvalidArgument(
                    "entries of an unknown kind cannot be created",
                ));
            }
        };
        self.put_attrs(
            object_id,
            InodeAttrs {
                size: 0,
                mode: type_bits | (mode & !MODE_TYPE_MASK),
                uid: 0,
                gid: 0,
                nlink: 1,
                attrs,
                bsd_flags: 0,
                crtime_ns: now_ns,
                mtime_ns: now_ns,
                ctime_ns: now_ns,
                atime_ns: now_ns,
            },
        )?;
        if let Err(error) = dirent::add_entry(
            self.tree_mut(),
            seed,
            version,
            case,
            parent,
            name,
            object_id,
            kind,
        ) {
            self.tree_mut().remove(inode_key(object_id))?;
            return Err(error);
        }
        self.touch_modified(parent, now_ns)?;
        Ok(object_id)
    }

    pub fn symlink(&mut self, parent: u64, name: &str, target: &[u8], now_ns: i64) -> Result<u64> {
        if target.is_empty() || target.len() > MAX_SYMLINK_TARGET {
            return Err(ScaleFsError::InvalidArgument("symlink target length"));
        }
        let object_id = self.create_object(parent, name, 0o777, EntryKind::Symlink, now_ns)?;
        self.tree_mut().insert(
            special_key(object_id),
            MetadataValue::Special {
                data: target.to_vec(),
            },
        )?;
        let mut attrs = self.getattr(object_id)?;
        attrs.size = target.len() as u64;
        self.put_attrs(object_id, attrs)?;
        self.mark_special_files_feature();
        Ok(object_id)
    }

    pub fn mknod(
        &mut self,
        parent: u64,
        name: &str,
        mode: u32,
        rdev: u64,
        now_ns: i64,
    ) -> Result<u64> {
        let kind = match mode & MODE_TYPE_MASK {
            0 | MODE_FILE => EntryKind::File,
            MODE_FIFO => EntryKind::Fifo,
            MODE_SOCKET => EntryKind::Socket,
            MODE_CHAR_DEVICE => EntryKind::CharDevice,
            MODE_BLOCK_DEVICE => EntryKind::BlockDevice,
            _ => {
                return Err(ScaleFsError::InvalidArgument(
                    "mknod: unsupported file type",
                ));
            }
        };
        let object_id = self.create_object(parent, name, mode, kind, now_ns)?;
        match kind {
            EntryKind::File => {}
            EntryKind::CharDevice | EntryKind::BlockDevice => {
                self.tree_mut().insert(
                    special_key(object_id),
                    MetadataValue::Special {
                        data: rdev.to_le_bytes().to_vec(),
                    },
                )?;
                self.mark_special_files_feature();
            }
            _ => self.mark_special_files_feature(),
        }
        Ok(object_id)
    }

    pub fn readlink(&self, object_id: u64) -> Result<Vec<u8>> {
        if !self.getattr(object_id)?.is_symlink() {
            return Err(ScaleFsError::InvalidArgument("not a symbolic link"));
        }
        match self.tree().get(special_key(object_id))? {
            Some(MetadataValue::Special { data }) => Ok(data),
            _ => Err(ScaleFsError::Corrupt("symbolic link has no target")),
        }
    }

    pub fn device_rdev(&self, object_id: u64) -> Result<u64> {
        if !self.getattr(object_id)?.is_device() {
            return Err(ScaleFsError::InvalidArgument("not a device node"));
        }
        match self.tree().get(special_key(object_id))? {
            Some(MetadataValue::Special { data }) if data.len() == 8 => {
                Ok(u64::from_le_bytes(data.as_slice().try_into().unwrap()))
            }
            _ => Err(ScaleFsError::Corrupt("device node has no rdev")),
        }
    }

    fn mark_special_files_feature(&mut self) {
        for superblock in &mut self.superblocks {
            superblock.feature_ro_compat |= FEATURE_RO_COMPAT_SPECIAL_FILES;
        }
        self.note_superblock_change();
    }

    fn mark_hardlinks_feature(&mut self) {
        for superblock in &mut self.superblocks {
            superblock.feature_ro_compat |= FEATURE_RO_COMPAT_HARDLINKS;
        }
        self.note_superblock_change();
    }

    fn mark_xattrs_feature(&mut self) {
        for superblock in &mut self.superblocks {
            superblock.feature_ro_compat |= FEATURE_RO_COMPAT_XATTRS;
        }
        self.note_superblock_change();
    }

    fn xattr_hash(&self, name: &str) -> u64 {
        let (seed, _, _) = self.naming();
        dirent::dirent_hash(seed, name)
    }

    pub fn set_xattr(
        &mut self,
        object: u64,
        name: &str,
        value: &[u8],
        flags: u32,
        now_ns: i64,
    ) -> Result<()> {
        self.ensure_mutable()?;
        let mut attrs = self.getattr(object)?;
        if name.is_empty() || name.len() > 255 {
            return Err(ScaleFsError::InvalidArgument("xattr name length"));
        }
        if value.len() > XATTR_VALUE_MAX {
            return Err(ScaleFsError::OutOfSpace);
        }
        let key = xattr_key(object, self.xattr_hash(name));
        let mut entries = match self.tree().get(key)? {
            Some(MetadataValue::XattrEntries(entries)) => entries,
            Some(_) => return Err(ScaleFsError::Corrupt("non-bucket value at an xattr key")),
            None => Vec::new(),
        };
        match entries.binary_search_by(|entry| entry.name.as_str().cmp(name)) {
            Ok(at) => {
                if flags == XATTR_SET_CREATE {
                    return Err(ScaleFsError::AlreadyExists);
                }
                entries[at].value = value.to_vec();
            }
            Err(at) => {
                if flags == XATTR_SET_REPLACE {
                    return Err(ScaleFsError::NotFound);
                }
                entries.insert(
                    at,
                    XattrEntry {
                        name: name.to_string(),
                        value: value.to_vec(),
                    },
                );
            }
        }
        self.mark_xattrs_feature();
        self.tree_mut()
            .insert(key, MetadataValue::XattrEntries(entries))
            .map_err(|err| match err {
                ScaleFsError::InvalidArgument(_) => ScaleFsError::OutOfSpace,
                other => other,
            })?;
        attrs.ctime_ns = now_ns;
        self.put_attrs(object, attrs)
    }

    pub fn get_xattr(&self, object: u64, name: &str) -> Result<Vec<u8>> {
        self.getattr(object)?;
        let key = xattr_key(object, self.xattr_hash(name));
        self.tree().get_with(key, |value| {
            if let Some(MetadataValue::XattrEntries(entries)) = value
                && let Ok(at) = entries.binary_search_by(|entry| entry.name.as_str().cmp(name))
            {
                return Ok(entries[at].value.clone());
            }
            Err(ScaleFsError::NotFound)
        })?
    }

    pub fn list_xattrs(&self, object: u64) -> Result<Vec<String>> {
        self.getattr(object)?;
        let mut names = Vec::new();
        for (_, value) in self
            .tree()
            .range(xattr_key(object, 0), xattr_key(object, u64::MAX))?
        {
            if let MetadataValue::XattrEntries(entries) = value {
                names.extend(entries.into_iter().map(|entry| entry.name));
            }
        }
        Ok(names)
    }

    pub fn remove_xattr(&mut self, object: u64, name: &str, now_ns: i64) -> Result<()> {
        self.ensure_mutable()?;
        let mut attrs = self.getattr(object)?;
        let key = xattr_key(object, self.xattr_hash(name));
        let Some(MetadataValue::XattrEntries(mut entries)) = self.tree().get(key)? else {
            return Err(ScaleFsError::NotFound);
        };
        let Ok(at) = entries.binary_search_by(|entry| entry.name.as_str().cmp(name)) else {
            return Err(ScaleFsError::NotFound);
        };
        entries.remove(at);
        if entries.is_empty() {
            self.tree_mut().remove(key)?;
        } else {
            self.tree_mut()
                .insert(key, MetadataValue::XattrEntries(entries))?;
        }
        attrs.ctime_ns = now_ns;
        self.put_attrs(object, attrs)
    }

    pub fn link(
        &mut self,
        object: u64,
        new_parent: u64,
        new_name: &str,
        now_ns: i64,
    ) -> Result<()> {
        self.ensure_mutable()?;
        self.require_dir(new_parent)?;
        let mut attrs = self.getattr(object)?;
        if attrs.is_dir() {
            return Err(ScaleFsError::IsDirectory);
        }
        if attrs.nlink >= LINK_MAX {
            return Err(ScaleFsError::TooManyLinks);
        }
        let (seed, version, case) = self.naming();
        dirent::add_entry(
            self.tree_mut(),
            seed,
            version,
            case,
            new_parent,
            new_name,
            object,
            attrs.entry_kind(),
        )?;
        self.mark_hardlinks_feature();
        attrs.nlink += 1;
        attrs.ctime_ns = now_ns;
        self.put_attrs(object, attrs)?;
        self.touch_modified(new_parent, now_ns)
    }

    pub fn unlink(&mut self, parent: u64, name: &str, now_ns: i64) -> Result<()> {
        self.ensure_mutable()?;
        self.require_dir(parent)?;
        let (seed, version, case) = self.naming();
        let entry = dirent::lookup_entry(self.tree(), seed, version, case, parent, name)?
            .ok_or(ScaleFsError::NotFound)?;
        if entry.kind == EntryKind::Directory {
            return Err(ScaleFsError::IsDirectory);
        }

        let attrs = self.getattr(entry.inode).ok();
        dirent::remove_entry(self.tree_mut(), seed, version, case, parent, name)?;
        match attrs {
            Some(mut attrs) if attrs.nlink > 1 => {
                attrs.nlink -= 1;
                attrs.ctime_ns = now_ns;
                self.put_attrs(entry.inode, attrs)?;
            }
            _ => self.remove_object(entry.inode)?,
        }
        self.touch_modified(parent, now_ns)
    }

    pub fn rmdir(&mut self, parent: u64, name: &str, now_ns: i64) -> Result<()> {
        self.ensure_mutable()?;
        self.require_dir(parent)?;
        let (seed, version, case) = self.naming();
        let entry = dirent::lookup_entry(self.tree(), seed, version, case, parent, name)?
            .ok_or(ScaleFsError::NotFound)?;
        if entry.kind != EntryKind::Directory {
            return Err(ScaleFsError::NotDirectory);
        }
        if dirent::entry_count(self.tree(), entry.inode)? != 0 {
            return Err(ScaleFsError::DirectoryNotEmpty);
        }

        dirent::remove_entry(self.tree_mut(), seed, version, case, parent, name)?;
        self.remove_object(entry.inode)?;
        self.touch_modified(parent, now_ns)
    }

    fn remove_object(&mut self, object_id: u64) -> Result<()> {
        let xattrs = self
            .tree()
            .keys(xattr_key(object_id, 0), xattr_key(object_id, u64::MAX))?;
        let extents = self
            .tree()
            .keys(extent_key(object_id, 0), extent_key(object_id, u64::MAX))?;
        let tree = self.tree_mut();
        for key in xattrs.into_iter().chain(extents) {
            tree.remove(key)?;
        }
        tree.remove(special_key(object_id))?;
        tree.remove(inode_key(object_id))?;
        Ok(())
    }

    pub fn rename(
        &mut self,
        old_parent: u64,
        old_name: &str,
        new_parent: u64,
        new_name: &str,
        now_ns: i64,
    ) -> Result<()> {
        self.ensure_mutable()?;
        self.require_dir(old_parent)?;
        self.require_dir(new_parent)?;
        dirent::validate_name(new_name)?;
        let (seed, version, case) = self.naming();
        let entry = dirent::lookup_entry(self.tree(), seed, version, case, old_parent, old_name)?
            .ok_or(ScaleFsError::NotFound)?;
        let same_place = old_parent == new_parent
            && dirent::fold_name(version, case, old_name)
                == dirent::fold_name(version, case, new_name);
        if !same_place
            && dirent::lookup_entry(self.tree(), seed, version, case, new_parent, new_name)?
                .is_some()
        {
            return Err(ScaleFsError::AlreadyExists);
        }
        if entry.kind == EntryKind::Directory
            && old_parent != new_parent
            && (entry.inode == new_parent || self.subtree_contains(entry.inode, new_parent)?)
        {
            return Err(ScaleFsError::InvalidArgument(
                "cannot move a directory into its own subtree",
            ));
        }

        let bucket = |dir: u64, name: &str| MetadataKey {
            object_id: dir,
            item_type: crate::tree::ITEM_DIRENT,
            offset: dirent::dirent_hash(seed, &dirent::fold_name(version, case, name)),
        };
        let mut saved: Vec<(MetadataKey, Option<MetadataValue>)> = Vec::with_capacity(2);
        for key in [bucket(old_parent, old_name), bucket(new_parent, new_name)] {
            saved.push((key, self.tree().get(key)?));
        }
        let tree = self.tree_mut();
        let moved =
            dirent::remove_entry(tree, seed, version, case, old_parent, old_name).and_then(|_| {
                dirent::add_entry(
                    tree,
                    seed,
                    version,
                    case,
                    new_parent,
                    new_name,
                    entry.inode,
                    entry.kind,
                )
            });
        if let Err(error) = moved {
            for (key, value) in saved {
                match value {
                    Some(value) => tree.insert(key, value)?,
                    None => {
                        tree.remove(key)?;
                    }
                }
            }
            return Err(error);
        }
        self.touch_modified(old_parent, now_ns)?;
        if new_parent != old_parent {
            self.touch_modified(new_parent, now_ns)?;
        }
        let mut attrs = self.getattr(entry.inode)?;
        attrs.ctime_ns = now_ns;
        self.put_attrs(entry.inode, attrs)
    }

    pub fn would_cycle(&self, source: u64, new_parent: u64) -> bool {
        source == new_parent || self.subtree_contains(source, new_parent).unwrap_or(true)
    }

    fn subtree_contains(&self, dir: u64, needle: u64) -> Result<bool> {
        let mut seen = std::collections::HashSet::from([dir]);
        let mut stack = vec![dir];
        while let Some(current) = stack.pop() {
            for entry in dirent::list_entries(self.tree(), current)? {
                if entry.kind == EntryKind::Directory {
                    if entry.inode == needle {
                        return Ok(true);
                    }
                    if !seen.insert(entry.inode) {
                        return Err(ScaleFsError::Corrupt(
                            "a directory is reachable twice: the tree loops",
                        ));
                    }
                    stack.push(entry.inode);
                }
            }
        }
        Ok(false)
    }

    #[cfg(test)]
    fn live_extents(&self, object_id: u64) -> Vec<LiveExtent> {
        live_extents_overlapping(self.tree(), object_id, 0, u64::MAX).unwrap()
    }

    fn clear_range(&mut self, object_id: u64, start: u64, end: u64) -> Result<()> {
        if start >= end {
            return Ok(());
        }
        let tree = self.tree_mut();
        for live in live_extents_overlapping(*tree, object_id, start, end)? {
            if live.end() <= start || live.start >= end {
                continue;
            }
            tree.remove(extent_key(object_id, live.start))?;
            if live.start < start {
                tree.insert(
                    extent_key(object_id, live.start),
                    live.run.slice(0, start - live.start),
                )?;
            }
            if live.end() > end {
                tree.insert(
                    extent_key(object_id, end),
                    live.run.slice(end - live.start, live.end() - end),
                )?;
            }
        }
        Ok(())
    }

    pub fn write(&mut self, object_id: u64, offset: u64, data: &[u8], now_ns: i64) -> Result<()> {
        if self.read_only() {
            return Err(ScaleFsError::Unsupported(
                "pool is read-only: writes are not permitted",
            ));
        }
        if self.wounded() {
            return Err(ScaleFsError::Unsupported(
                "a commit failed while writing: reopen the pool before writing again",
            ));
        }
        let mut attrs = self.require_file(object_id)?;
        if data.is_empty() {
            return Ok(());
        }
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(ScaleFsError::InvalidArgument(
                "write reaches past the address space",
            ))?;

        let staged: Vec<(MetadataKey, MetadataValue)> = if self.parity_width() > 0 {
            self.stage_striped(object_id, offset, data)?
        } else {
            self.stage_mirrored(object_id, offset, data)?
        };

        self.clear_range(object_id, offset, end)?;
        let tree = self.tree_mut();
        for (key, value) in staged {
            tree.insert(key, value)?;
        }

        attrs.size = attrs.size.max(end);
        attrs.mtime_ns = now_ns;
        attrs.ctime_ns = now_ns;
        attrs.attrs |= FILE_ATTR_ARCHIVE;
        self.put_attrs(object_id, attrs)
    }

    fn stage_mirrored(
        &mut self,
        object_id: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<Vec<(MetadataKey, MetadataValue)>> {
        let tx = self.committed_tx + 1;
        let mut staged = Vec::new();
        let mut building: Option<RunBuilder> = None;
        let mut written = 0usize;
        while written < data.len() {
            let chunk = &data[written..(written + FILE_DATA_CHUNK).min(data.len())];
            let record = encode_file_data(tx, chunk);
            let len = record.len() as u64;
            let placements = self.place_mirrored(ZoneClass::Data, len, AllocPurpose::Normal)?;
            for (member, allocation) in &placements {
                let slot = self
                    .member_slot(*member)
                    .expect("data is placed on present members");
                self.write_record_padded(slot, allocation.offset, &record)?;
            }
            let crc = Expect::of(&record).crc;
            match &mut building {
                Some(builder) if builder.continues(len, &placements) => {
                    builder.run.crcs.push(crc);
                    builder.run.last_len = len;
                    builder.run.logical_len += chunk.len() as u64;
                }
                _ => {
                    if let Some(done) = building.take() {
                        staged.push((
                            extent_key(object_id, done.start),
                            MetadataValue::FileRun(done.run),
                        ));
                    }
                    building = Some(RunBuilder {
                        start: offset + written as u64,
                        zones: placements
                            .iter()
                            .map(|(member, allocation)| (*member, allocation.zone_index))
                            .collect(),
                        run: FileRun {
                            copies: placements
                                .iter()
                                .map(|(member, allocation)| Extent {
                                    device_index: *member,
                                    offset: allocation.offset,
                                    length: len,
                                })
                                .collect(),
                            stride: placements[0].1.length,
                            last_len: len,
                            tx,
                            crcs: vec![crc],
                            data_offset: 0,
                            logical_len: chunk.len() as u64,
                        },
                    });
                }
            }
            written += chunk.len();
        }
        if let Some(done) = building {
            staged.push((
                extent_key(object_id, done.start),
                MetadataValue::FileRun(done.run),
            ));
        }
        Ok(staged)
    }

    fn stage_striped(
        &mut self,
        object_id: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<Vec<(MetadataKey, MetadataValue)>> {
        let target_width = usize::from(self.data_width()).max(1);
        let chunks: Vec<&[u8]> = data.chunks(FILE_DATA_CHUNK).collect();
        let mut staged = Vec::new();
        let mut consumed = 0usize;
        while consumed < chunks.len() {
            let request = (chunks.len() - consumed).min(target_width);
            let group = &chunks[consumed..consumed + request];
            let tx = self.committed_tx + 1;
            let records: Vec<Vec<u8>> = group
                .iter()
                .map(|chunk| encode_file_data(tx, chunk))
                .collect();
            let stripe = self.emit_stripe(&records)?;
            let placed = stripe.placed;
            let logical_len = group[..placed].iter().map(|chunk| chunk.len() as u64).sum();
            staged.push((
                extent_key(object_id, offset + (consumed * FILE_DATA_CHUNK) as u64),
                MetadataValue::StripedRun(StripedRun {
                    pieces: stripe.pieces,
                    crcs: stripe.crcs,
                    tx,
                    parity: stripe.parity,
                    parity_crcs: stripe.parity_crcs,
                    parity_tx: stripe.parity_tx,
                    data_offset: 0,
                    logical_len,
                }),
            ));
            consumed += placed;
        }
        Ok(staged)
    }

    pub(crate) fn emit_stripe(&mut self, records: &[Vec<u8>]) -> Result<EmittedStripe> {
        let parity_width = usize::from(self.parity_width());
        let lens: Vec<u64> = records.iter().map(|record| record.len() as u64).collect();

        let (data_places, parity_places) = self.place_stripe(&lens, AllocPurpose::Normal)?;
        let placed = data_places.len();
        let records = &records[..placed];
        let coverage = records
            .iter()
            .map(Vec::len)
            .max()
            .expect("a stripe has a piece");
        let parity_len = parity_record_len(placed, parity_width, coverage as u64);

        let mut encoder = ParityEncoder::new(parity_width, coverage)?;
        for (column, record) in records.iter().enumerate() {
            encoder.add_piece(column, record)?;
        }
        let rows = encoder.finish();

        let data_extents: Vec<Extent> = data_places
            .iter()
            .zip(records)
            .map(|((member, allocation), record)| Extent {
                device_index: *member,
                offset: allocation.offset,
                length: record.len() as u64,
            })
            .collect();
        let parity_extents: Vec<Extent> = parity_places
            .iter()
            .map(|(member, allocation)| Extent {
                device_index: *member,
                offset: allocation.offset,
                length: parity_len,
            })
            .collect();

        for ((member, allocation), record) in data_places.iter().zip(records) {
            let slot = self
                .member_slot(*member)
                .expect("stripes are placed on present members");
            self.write_record_padded(slot, allocation.offset, record)?;
        }
        let crcs: Vec<u32> = records
            .iter()
            .map(|record| Expect::of(record).crc)
            .collect();
        let parity_tx = self.committed_tx + 1;
        let mut parity_crcs = Vec::with_capacity(parity_places.len());
        for (row, ((member, allocation), parity)) in parity_places.iter().zip(rows).enumerate() {
            let record = ParityRecord {
                parity_index: row as u8,
                coverage_len: coverage as u64,
                data_pieces: data_extents.clone(),
                data_crcs: crcs.clone(),
                parity_pieces: parity_extents.clone(),
                parity,
            };
            let bytes = encode_parity_record(&record, parity_tx)?;
            debug_assert_eq!(bytes.len() as u64, parity_len);
            parity_crcs.push(Expect::of(&bytes).crc);
            let slot = self
                .member_slot(*member)
                .expect("stripes are placed on present members");
            self.write_record_padded(slot, allocation.offset, &bytes)?;
        }
        Ok(EmittedStripe {
            placed,
            pieces: data_extents,
            crcs,
            parity: parity_extents,
            parity_crcs,
            parity_tx,
        })
    }

    pub fn read(&self, object_id: u64, offset: u64, len: usize) -> Result<Vec<u8>> {
        read_in(self, self.tree(), object_id, offset, len)
    }

    pub fn truncate(&mut self, object_id: u64, new_size: u64, now_ns: i64) -> Result<()> {
        self.ensure_mutable()?;
        let mut attrs = self.require_file(object_id)?;
        if new_size < attrs.size {
            self.clear_range(object_id, new_size, attrs.size)?;
        }
        attrs.size = new_size;
        attrs.mtime_ns = now_ns;
        attrs.ctime_ns = now_ns;
        self.put_attrs(object_id, attrs)
    }

    pub fn punch_hole(&mut self, object_id: u64, offset: u64, len: u64, now_ns: i64) -> Result<()> {
        self.ensure_mutable()?;
        self.require_file(object_id)?;
        let end = offset
            .checked_add(len)
            .ok_or(ScaleFsError::InvalidArgument(
                "hole reaches past the address space",
            ))?;
        self.clear_range(object_id, offset, end)?;
        self.touch_modified(object_id, now_ns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::MemoryBlockDevice;
    use crate::layout::{DeviceId, Geometry, PoolId};
    use crate::pool::CreateParams;
    use crate::torture::{Op, RecordingBlockDevice, TortureBlockDevice};
    use crate::tree::ROOT_INODE;

    const NOW: i64 = 1_700_000_000_000_000_000;
    const LATER: i64 = NOW + 1_000_000_000;

    fn geometry() -> Geometry {
        Geometry {
            logical_block_size: 4096,
            physical_block_size: 4096,
            zone_size: 65536,
            zone_count: 16,
            erase_granularity_zones: 1,
            sequential_write_required: true,
        }
    }

    fn new_pool() -> Pool<MemoryBlockDevice> {
        pool_with(geometry())
    }

    fn pool_with(geometry: Geometry) -> Pool<MemoryBlockDevice> {
        let device = MemoryBlockDevice::new(
            crate::gpt::member_image_len(geometry.capacity_bytes()) as usize,
        );
        Pool::create(
            device,
            CreateParams {
                pool_id: PoolId([0x11; 16]),
                device_id: DeviceId([0x22; 16]),
                geometry,
                case_sensitivity: CaseSensitivity::InsensitivePreserving,
                dirent_hash_seed: 0x5EED_CAFE_F00D_0001,
                label: "tank".to_string(),
                created_at_ns: NOW,
            },
        )
        .unwrap()
    }

    fn pattern(len: usize, salt: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31) ^ salt)
            .collect()
    }

    struct FailAfter {
        inner: MemoryBlockDevice,
        allow: std::sync::atomic::AtomicI64,
    }
    impl BlockDevice for FailAfter {
        fn len(&self) -> u64 {
            self.inner.len()
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.inner.read_at(offset, buf)
        }
        fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
            use std::sync::atomic::Ordering;
            if self.allow.fetch_sub(1, Ordering::Relaxed) <= 0 {
                return Err(ScaleFsError::Io(std::io::Error::other("armed failure")));
            }
            self.inner.write_at(offset, data)
        }
        fn flush(&self) -> Result<()> {
            self.inner.flush()
        }
    }

    fn failing_pool() -> (std::sync::Arc<FailAfter>, Pool<std::sync::Arc<FailAfter>>) {
        let device = std::sync::Arc::new(FailAfter {
            inner: MemoryBlockDevice::new(
                crate::gpt::member_image_len(geometry().capacity_bytes()) as usize,
            ),
            allow: std::sync::atomic::AtomicI64::new(i64::MAX),
        });
        let pool = Pool::create(
            std::sync::Arc::clone(&device),
            CreateParams {
                pool_id: PoolId([0x11; 16]),
                device_id: DeviceId([0x22; 16]),
                geometry: geometry(),
                case_sensitivity: CaseSensitivity::InsensitivePreserving,
                dirent_hash_seed: 0x5EED_CAFE_F00D_0001,
                label: "tank".to_string(),
                created_at_ns: NOW,
            },
        )
        .unwrap();
        (device, pool)
    }

    #[test]
    fn a_failed_overwrite_leaves_the_old_bytes() {
        use std::sync::atomic::Ordering;
        let (device, mut pool) = failing_pool();
        let file = pool.create_file(ROOT_INODE, "f", 0o644, NOW).unwrap();
        let old = pattern(2 * FILE_DATA_CHUNK, 5);
        pool.write(file, 0, &old, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        device.allow.store(1, Ordering::Relaxed);
        let new = pattern(2 * FILE_DATA_CHUNK, 9);
        assert!(pool.write(file, 0, &new, LATER).is_err());
        device.allow.store(i64::MAX, Ordering::Relaxed);

        assert_eq!(pool.read(file, 0, 2 * FILE_DATA_CHUNK).unwrap(), old);
        assert_eq!(pool.getattr(file).unwrap().size, 2 * FILE_DATA_CHUNK as u64);
        assert_eq!(pool.live_extents(file).len(), 1);
        pool.commit(AllocPurpose::Normal, LATER).unwrap();
        drop(pool);
        let device = std::sync::Arc::into_inner(device).expect("sole owner");
        let pool = Pool::open(MemoryBlockDevice::from_bytes(device.inner.bytes())).unwrap();
        assert_eq!(pool.read(file, 0, 2 * FILE_DATA_CHUNK).unwrap(), old);
    }

    #[test]
    fn a_failed_append_strands_no_runs_past_the_size() {
        use std::sync::atomic::Ordering;
        let (device, mut pool) = failing_pool();
        let file = pool.create_file(ROOT_INODE, "f", 0o644, NOW).unwrap();
        pool.write(file, 0, &pattern(100, 5), NOW).unwrap();

        device.allow.store(1, Ordering::Relaxed);
        assert!(
            pool.write(file, 100, &pattern(2 * FILE_DATA_CHUNK, 9), LATER)
                .is_err()
        );
        device.allow.store(i64::MAX, Ordering::Relaxed);

        assert_eq!(pool.getattr(file).unwrap().size, 100);
        assert_eq!(pool.live_extents(file).len(), 1);
        pool.truncate(file, 100 + 2 * FILE_DATA_CHUNK as u64, LATER)
            .unwrap();
        let exposed = pool.read(file, 100, 2 * FILE_DATA_CHUNK).unwrap();
        assert!(exposed.iter().all(|b| *b == 0));
    }

    #[test]
    fn create_lookup_readdir_and_attrs() {
        let mut pool = new_pool();
        let file = pool
            .create_file(ROOT_INODE, "hello.txt", 0o644, NOW)
            .unwrap();
        assert_eq!(file, 2);
        let dir = pool.mkdir(ROOT_INODE, "sub", 0o755, NOW).unwrap();
        assert_eq!(dir, 3);

        let entry = pool.lookup(ROOT_INODE, "hello.txt").unwrap();
        assert_eq!(entry.inode, file);
        assert_eq!(entry.kind, EntryKind::File);
        assert_eq!(pool.lookup(ROOT_INODE, "HELLO.TXT").unwrap().inode, file);

        let names: Vec<String> = pool
            .readdir(ROOT_INODE)
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, ["hello.txt", "sub"]);

        let attrs = pool.getattr(file).unwrap();
        assert_eq!(attrs.mode, MODE_FILE | 0o644);
        assert_eq!(attrs.attrs, FILE_ATTR_ARCHIVE);
        assert_eq!(attrs.crtime_ns, NOW);
        assert!(pool.getattr(dir).unwrap().is_dir());

        assert!(matches!(
            pool.create_file(ROOT_INODE, "Hello.TXT", 0o644, NOW),
            Err(ScaleFsError::AlreadyExists)
        ));
        assert!(matches!(
            pool.create_file(file, "x", 0o644, NOW),
            Err(ScaleFsError::NotDirectory)
        ));
        assert!(matches!(
            pool.lookup(ROOT_INODE, "absent"),
            Err(ScaleFsError::NotFound)
        ));
    }

    #[test]
    fn write_read_round_trips_with_sparse_holes() {
        let mut pool = new_pool();
        let file = pool.create_file(ROOT_INODE, "f", 0o644, NOW).unwrap();

        let data = pattern(5000, 7);
        pool.write(file, 100_000, &data, LATER).unwrap();

        let attrs = pool.getattr(file).unwrap();
        assert_eq!(attrs.size, 105_000);
        assert_eq!(attrs.mtime_ns, LATER);

        assert_eq!(pool.read(file, 0, 100).unwrap(), vec![0u8; 100]);
        assert_eq!(pool.read(file, 100_000, 5000).unwrap(), data);
        let straddle = pool.read(file, 99_990, 20).unwrap();
        assert_eq!(&straddle[..10], &[0u8; 10]);
        assert_eq!(&straddle[10..], &data[..10]);
        assert_eq!(pool.read(file, 104_990, 1000).unwrap(), &data[4990..]);
        assert!(pool.read(file, 200_000, 10).unwrap().is_empty());
    }

    fn run_counts(pool: &Pool<MemoryBlockDevice>, file: u64) -> Vec<usize> {
        pool.live_extents(file)
            .iter()
            .map(|live| match &live.run {
                LiveRun::Mirrored(run) => run.count(),
                LiveRun::Striped(run) => run.count(),
            })
            .collect()
    }

    #[test]
    fn large_writes_become_runs_of_chunked_records() {
        let records = 100_000usize.div_ceil(FILE_DATA_CHUNK);
        let data = pattern(100_000, 3);

        let mut roomy = pool_with(Geometry {
            zone_size: 4 << 20,
            ..geometry()
        });
        let file = roomy.create_file(ROOT_INODE, "big", 0o644, NOW).unwrap();
        roomy.write(file, 0, &data, NOW).unwrap();
        assert_eq!(run_counts(&roomy, file), vec![records]);
        let extents = roomy.live_extents(file);
        let LiveRun::Mirrored(run) = &extents[0].run else {
            panic!("a mirrored run");
        };
        assert_eq!(run.copies[0].length, 32 * 1024);
        assert_eq!(run.stride, 32 * 1024);
        assert_eq!(roomy.read(file, 0, 100_000).unwrap(), data);

        let big = pattern(MAX_RUN_RECORDS * FILE_DATA_CHUNK + 5000, 4);
        let file = roomy.create_file(ROOT_INODE, "bigger", 0o644, NOW).unwrap();
        roomy.write(file, 0, &big, NOW).unwrap();
        assert_eq!(run_counts(&roomy, file), vec![MAX_RUN_RECORDS, 1]);
        assert_eq!(roomy.read(file, 0, big.len()).unwrap(), big);
        let mib = pattern(1 << 20, 6);
        let file = roomy.create_file(ROOT_INODE, "mib", 0o644, NOW).unwrap();
        roomy.write(file, 0, &mib, NOW).unwrap();
        assert_eq!(run_counts(&roomy, file).len(), 1);

        let mut pool = new_pool();
        let file = pool.create_file(ROOT_INODE, "big", 0o644, NOW).unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        assert_eq!(run_counts(&pool, file), vec![2, 2]);
        assert_eq!(pool.read(file, 0, 100_000).unwrap(), data);
        assert_eq!(
            pool.read(file, FILE_DATA_CHUNK as u64 - 10, 20).unwrap(),
            &data[FILE_DATA_CHUNK - 10..FILE_DATA_CHUNK + 10]
        );
    }

    fn oracle_sweep<D: BlockDevice>(pool: &mut Pool<D>) {
        let chunk = FILE_DATA_CHUNK;
        let file = pool.create_file(ROOT_INODE, "oracle", 0o644, NOW).unwrap();
        let len = 5 * chunk;
        let data = pattern(len, 7);
        pool.write(file, 0, &data, NOW).unwrap();
        let mut oracle = data;

        let hole_at = chunk / 2;
        pool.punch_hole(file, hole_at as u64, 1000, LATER).unwrap();
        oracle[hole_at..hole_at + 1000].fill(0);
        let straddle_at = 2 * chunk - 500;
        let fresh = pattern(1000, 42);
        pool.write(file, straddle_at as u64, &fresh, LATER).unwrap();
        oracle[straddle_at..straddle_at + 1000].copy_from_slice(&fresh);
        let tail_at = len - 700;
        let fresh = pattern(700, 99);
        pool.write(file, tail_at as u64, &fresh, LATER).unwrap();
        oracle[tail_at..].copy_from_slice(&fresh);
        let cut = len - 1500;
        pool.truncate(file, cut as u64, LATER).unwrap();
        pool.truncate(file, len as u64, LATER).unwrap();
        oracle[cut..].fill(0);

        let mut probes: Vec<usize> = Vec::new();
        for boundary in (0..=5).map(|run| run * chunk).chain([
            hole_at,
            hole_at + 1000,
            straddle_at,
            straddle_at + 1000,
            tail_at,
            cut,
            len,
        ]) {
            for delta in -2i64..=2 {
                let probe = boundary as i64 + delta;
                if probe >= 0 {
                    probes.push(probe as usize);
                }
            }
        }
        for &offset in &probes {
            for read_len in [1, 3, 4096, chunk - 1, chunk, chunk + 1, 3 * chunk] {
                let got = pool.read(file, offset as u64, read_len).unwrap();
                let from = offset.min(oracle.len());
                let to = (offset + read_len).min(oracle.len());
                assert_eq!(
                    got,
                    &oracle[from..to],
                    "window offset={offset} len={read_len}"
                );
            }
        }
    }

    #[test]
    fn reads_match_an_oracle_across_every_window() {
        oracle_sweep(&mut new_pool());
    }

    type Edit = fn(&mut dyn FnMut(EditOp), u64);

    enum EditOp {
        Write(u64, Vec<u8>),
        Truncate(u64),
        Punch(u64, u64),
    }

    fn run_boundaries<D: BlockDevice>(pool: &mut Pool<D>) -> Vec<Vec<usize>> {
        let chunk = FILE_DATA_CHUNK as u64;
        let len = 6 * chunk + 1234;
        let edits: Vec<(&str, Edit)> = vec![
            ("run start", |apply, _| {
                apply(EditOp::Write(0, pattern(10, 1)))
            }),
            ("mid-record", |apply, chunk| {
                apply(EditOp::Write(chunk / 2, pattern(100, 2)))
            }),
            ("one record exactly", |apply, chunk| {
                apply(EditOp::Write(chunk, pattern(chunk as usize, 3)))
            }),
            ("run end", |apply, chunk| {
                apply(EditOp::Write(6 * chunk + 1224, pattern(10, 4)))
            }),
            ("trim to one record", |apply, chunk| {
                apply(EditOp::Truncate(chunk / 3))
            }),
            ("split in the middle", |apply, chunk| {
                apply(EditOp::Punch(2 * chunk + 100, 2 * chunk - 200))
            }),
            ("truncate on a record boundary", |apply, chunk| {
                apply(EditOp::Truncate(3 * chunk))
            }),
            ("across several records", |apply, chunk| {
                apply(EditOp::Write(
                    chunk - 7,
                    pattern(4 * chunk as usize + 16, 5),
                ))
            }),
        ];
        let mut shapes = Vec::new();
        for (name, edit) in edits {
            let file = pool.create_file(ROOT_INODE, name, 0o644, NOW).unwrap();
            let data = pattern(len as usize, 9);
            pool.write(file, 0, &data, NOW).unwrap();
            let mut oracle = data;
            edit(
                &mut |op| match op {
                    EditOp::Write(at, bytes) => {
                        pool.write(file, at, &bytes, LATER).unwrap();
                        let end = at as usize + bytes.len();
                        if oracle.len() < end {
                            oracle.resize(end, 0);
                        }
                        oracle[at as usize..end].copy_from_slice(&bytes);
                    }
                    EditOp::Truncate(to) => {
                        pool.truncate(file, to, LATER).unwrap();
                        oracle.truncate(to as usize);
                    }
                    EditOp::Punch(at, n) => {
                        pool.punch_hole(file, at, n, LATER).unwrap();
                        oracle[at as usize..(at + n) as usize].fill(0);
                    }
                },
                chunk,
            );
            for round in 0..2 {
                assert_eq!(
                    pool.read(file, 0, oracle.len() + 10).unwrap(),
                    oracle,
                    "{name}: whole file (round {round})"
                );
                let boundaries = (0..=7).map(|k| k * chunk).chain([chunk / 2, len - 10]);
                for boundary in boundaries {
                    for delta in [-2i64, -1, 0, 1, 2] {
                        let Ok(at) = u64::try_from(boundary as i64 + delta) else {
                            continue;
                        };
                        for read_len in [1usize, 7, chunk as usize, 2 * chunk as usize + 3] {
                            let from = (at as usize).min(oracle.len());
                            let to = (at as usize + read_len).min(oracle.len());
                            assert_eq!(
                                pool.read(file, at, read_len).unwrap(),
                                &oracle[from..to],
                                "{name}: window {at}+{read_len} (round {round})"
                            );
                        }
                    }
                }
                pool.commit(AllocPurpose::Normal, LATER).unwrap();
            }
            shapes.push(
                pool.live_extents(file)
                    .iter()
                    .map(|live| match &live.run {
                        LiveRun::Mirrored(run) => run.count(),
                        LiveRun::Striped(run) => run.count(),
                    })
                    .collect(),
            );
        }
        shapes
    }

    #[test]
    fn runs_trim_and_split_at_every_boundary() {
        let shapes = run_boundaries(&mut pool_with(Geometry {
            zone_size: 4 << 20,
            ..geometry()
        }));
        assert_eq!(
            shapes,
            vec![
                vec![1, 7],
                vec![1, 1, 7],
                vec![1, 1, 5],
                vec![7, 1],
                vec![1],
                vec![3, 4],
                vec![3],
                vec![1, 5, 2],
            ]
        );
        run_boundaries(&mut pool_with(Geometry {
            zone_count: 128,
            ..geometry()
        }));
    }

    #[test]
    fn striped_runs_trim_and_split_at_every_boundary() {
        use crate::pool::{MemberSpec, PoolParams};
        let geometry = Geometry {
            zone_size: 1 << 20,
            ..geometry()
        };
        let members: Vec<MemberSpec<MemoryBlockDevice>> = (0..6)
            .map(|i| MemberSpec {
                device: MemoryBlockDevice::new(crate::gpt::member_image_len(
                    geometry.capacity_bytes(),
                ) as usize),
                device_id: DeviceId([0x50 + i as u8; 16]),
                geometry,
            })
            .collect();
        let mut pool = Pool::create_multi(
            members,
            PoolParams {
                pool_id: PoolId([0x13; 16]),
                case_sensitivity: CaseSensitivity::InsensitivePreserving,
                dirent_hash_seed: 3,
                label: "rows".to_string(),
                created_at_ns: NOW,
                mirror_width: 2,
                data_width: 4,
                parity_width: 1,
            },
        )
        .unwrap();
        let shapes = run_boundaries(&mut pool);
        assert_eq!(shapes[4], vec![1], "trim to one piece");
        assert_eq!(shapes[6], vec![3], "three pieces of the first row");
    }

    #[test]
    fn striped_reads_match_the_same_oracle() {
        use crate::pool::{MemberSpec, PoolParams};
        let members: Vec<MemberSpec<MemoryBlockDevice>> = (0..4)
            .map(|i| MemberSpec {
                device: MemoryBlockDevice::new(crate::gpt::member_image_len(
                    geometry().capacity_bytes(),
                ) as usize),
                device_id: DeviceId([0x40 + i as u8; 16]),
                geometry: geometry(),
            })
            .collect();
        let mut pool = Pool::create_multi(
            members,
            PoolParams {
                pool_id: PoolId([0x12; 16]),
                case_sensitivity: CaseSensitivity::InsensitivePreserving,
                dirent_hash_seed: 0x5EED_CAFE_F00D_0002,
                label: "striped".to_string(),
                created_at_ns: NOW,
                mirror_width: 2,
                data_width: 2,
                parity_width: 1,
            },
        )
        .unwrap();
        oracle_sweep(&mut pool);
    }

    #[test]
    fn overwrites_trim_split_and_layer_correctly() {
        let mut pool = new_pool();
        let file = pool.create_file(ROOT_INODE, "f", 0o644, NOW).unwrap();
        let base = pattern(10_000, 1);
        pool.write(file, 0, &base, NOW).unwrap();

        let mid = pattern(2000, 2);
        pool.write(file, 4000, &mid, NOW).unwrap();
        let mut expected = base.clone();
        expected[4000..6000].copy_from_slice(&mid);
        assert_eq!(pool.read(file, 0, 10_000).unwrap(), expected);
        assert_eq!(pool.live_extents(file).len(), 3);

        let head = pattern(1000, 4);
        pool.write(file, 0, &head, NOW).unwrap();
        expected[..1000].copy_from_slice(&head);
        assert_eq!(pool.read(file, 0, 10_000).unwrap(), expected);

        let tail = pattern(3000, 5);
        pool.write(file, 9000, &tail, NOW).unwrap();
        expected.truncate(9000);
        expected.extend_from_slice(&tail);
        assert_eq!(pool.read(file, 0, 12_000).unwrap(), expected);
        assert_eq!(pool.getattr(file).unwrap().size, 12_000);

        let fresh = pattern(12_000, 6);
        pool.write(file, 0, &fresh, NOW).unwrap();
        assert_eq!(pool.read(file, 0, 12_000).unwrap(), fresh);
        assert_eq!(pool.live_extents(file).len(), 1);
    }

    #[test]
    fn truncate_and_punch_hole_adjust_metadata_only() {
        let mut pool = new_pool();
        let file = pool.create_file(ROOT_INODE, "f", 0o644, NOW).unwrap();
        let data = pattern(8000, 9);
        pool.write(file, 0, &data, NOW).unwrap();

        pool.truncate(file, 5000, LATER).unwrap();
        assert_eq!(pool.getattr(file).unwrap().size, 5000);
        assert_eq!(pool.read(file, 0, 8000).unwrap(), &data[..5000]);

        pool.truncate(file, 7000, LATER).unwrap();
        let grown = pool.read(file, 0, 7000).unwrap();
        assert_eq!(&grown[..5000], &data[..5000]);
        assert_eq!(&grown[5000..], &[0u8; 2000]);

        pool.punch_hole(file, 1000, 2000, LATER).unwrap();
        let holed = pool.read(file, 0, 7000).unwrap();
        assert_eq!(&holed[..1000], &data[..1000]);
        assert_eq!(&holed[1000..3000], &[0u8; 2000]);
        assert_eq!(&holed[3000..5000], &data[3000..5000]);
        assert_eq!(pool.getattr(file).unwrap().size, 7000);
    }

    #[test]
    fn unlink_and_rmdir_enforce_kinds_and_emptiness() {
        let mut pool = new_pool();
        let file = pool.create_file(ROOT_INODE, "f", 0o644, NOW).unwrap();
        pool.write(file, 0, &pattern(1000, 1), NOW).unwrap();
        let dir = pool.mkdir(ROOT_INODE, "d", 0o755, NOW).unwrap();
        pool.create_file(dir, "inner", 0o644, NOW).unwrap();

        assert!(matches!(
            pool.unlink(ROOT_INODE, "d", NOW),
            Err(ScaleFsError::IsDirectory)
        ));
        assert!(matches!(
            pool.rmdir(ROOT_INODE, "f", NOW),
            Err(ScaleFsError::NotDirectory)
        ));
        assert!(matches!(
            pool.rmdir(ROOT_INODE, "d", NOW),
            Err(ScaleFsError::DirectoryNotEmpty)
        ));

        pool.unlink(ROOT_INODE, "f", NOW).unwrap();
        assert!(matches!(pool.getattr(file), Err(ScaleFsError::NotFound)));
        assert!(pool.live_extents(file).is_empty());

        pool.unlink(dir, "inner", NOW).unwrap();
        pool.rmdir(ROOT_INODE, "d", NOW).unwrap();
        assert!(pool.readdir(ROOT_INODE).unwrap().is_empty());
    }

    #[test]
    fn rename_moves_entries_and_blocks_cycles() {
        let mut pool = new_pool();
        let file = pool.create_file(ROOT_INODE, "a.txt", 0o644, NOW).unwrap();
        let outer = pool.mkdir(ROOT_INODE, "outer", 0o755, NOW).unwrap();
        let inner = pool.mkdir(outer, "inner", 0o755, NOW).unwrap();

        pool.rename(ROOT_INODE, "a.txt", ROOT_INODE, "b.txt", LATER)
            .unwrap();
        assert!(matches!(
            pool.lookup(ROOT_INODE, "a.txt"),
            Err(ScaleFsError::NotFound)
        ));
        assert_eq!(pool.lookup(ROOT_INODE, "b.txt").unwrap().inode, file);

        pool.rename(ROOT_INODE, "b.txt", inner, "c.txt", LATER)
            .unwrap();
        assert_eq!(pool.lookup(inner, "c.txt").unwrap().inode, file);

        pool.create_file(ROOT_INODE, "taken", 0o644, NOW).unwrap();
        pool.create_file(ROOT_INODE, "src", 0o644, NOW).unwrap();
        assert!(matches!(
            pool.rename(ROOT_INODE, "src", ROOT_INODE, "TAKEN", NOW),
            Err(ScaleFsError::AlreadyExists)
        ));

        assert!(matches!(
            pool.rename(ROOT_INODE, "outer", inner, "loop", NOW),
            Err(ScaleFsError::InvalidArgument(_))
        ));
        pool.rename(outer, "inner", ROOT_INODE, "inner", NOW)
            .unwrap();
        assert_eq!(pool.lookup(ROOT_INODE, "inner").unwrap().inode, inner);
    }

    #[test]
    fn object_ids_are_sequential_and_persist() {
        let mut pool = new_pool();
        assert_eq!(pool.create_file(ROOT_INODE, "a", 0o644, NOW).unwrap(), 2);
        assert_eq!(pool.mkdir(ROOT_INODE, "b", 0o755, NOW).unwrap(), 3);
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        let mut pool = Pool::open(pool.into_device()).unwrap();
        assert_eq!(pool.create_file(ROOT_INODE, "c", 0o644, NOW).unwrap(), 4);
    }

    #[test]
    fn contents_persist_across_commit_and_reopen() {
        let mut pool = new_pool();
        let file = pool
            .create_file(ROOT_INODE, "keep.bin", 0o600, NOW)
            .unwrap();
        let data = pattern(50_000, 11);
        pool.write(file, 0, &data, NOW).unwrap();
        pool.truncate(file, 40_000, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        let pool = Pool::open(pool.into_device()).unwrap();
        assert_eq!(pool.getattr(file).unwrap().size, 40_000);
        assert_eq!(pool.read(file, 0, 50_000).unwrap(), &data[..40_000]);
        assert_eq!(pool.lookup(ROOT_INODE, "keep.bin").unwrap().inode, file);
    }

    #[test]
    fn wrong_kind_operations_are_rejected() {
        let mut pool = new_pool();
        let file = pool.create_file(ROOT_INODE, "f", 0o644, NOW).unwrap();
        let dir = pool.mkdir(ROOT_INODE, "d", 0o755, NOW).unwrap();

        assert!(matches!(
            pool.write(dir, 0, b"x", NOW),
            Err(ScaleFsError::IsDirectory)
        ));
        assert!(matches!(
            pool.read(dir, 0, 1),
            Err(ScaleFsError::IsDirectory)
        ));
        assert!(matches!(
            pool.readdir(file),
            Err(ScaleFsError::NotDirectory)
        ));
        assert!(matches!(pool.getattr(99), Err(ScaleFsError::NotFound)));
        assert!(matches!(
            pool.write(99, 0, b"x", NOW),
            Err(ScaleFsError::NotFound)
        ));
    }

    #[test]
    fn file_writes_are_transactional_across_crashes() {
        let pool = new_pool();
        let base = pool.devices[0].inner().bytes().to_vec();

        let mut pool = Pool::open(RecordingBlockDevice::new(pool.into_device())).unwrap();
        let file = pool.create_file(ROOT_INODE, "tx.bin", 0o644, NOW).unwrap();
        let data = pattern(9000, 13);
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let ops = pool.devices[0].inner().ops().to_vec();

        let mut states = 0usize;
        for prefix in 0..=ops.len() {
            let device = TortureBlockDevice::from_image(base.clone(), 4096);
            for op in &ops[..prefix] {
                match op {
                    Op::Write { offset, data } => device.write_at(*offset, data).unwrap(),
                    Op::Flush => device.flush().unwrap(),
                }
            }
            for image in device.all_crash_images() {
                let pool = Pool::open(image).unwrap_or_else(|err| {
                    panic!("crash state at prefix {prefix} failed to open: {err}")
                });
                match pool.committed_tx() {
                    1 => assert!(matches!(
                        pool.lookup(ROOT_INODE, "tx.bin"),
                        Err(ScaleFsError::NotFound)
                    )),
                    2 => {
                        assert_eq!(pool.read(file, 0, 9000).unwrap(), data);
                    }
                    other => panic!("recovered impossible transaction {other}"),
                }
                states += 1;
            }
        }
        assert!(states > ops.len());
    }

    #[test]
    fn symlinks_create_read_and_persist() {
        let mut pool = new_pool();
        let link = pool
            .symlink(ROOT_INODE, "link", b"../target/path", NOW)
            .unwrap();
        assert_eq!(pool.readlink(link).unwrap(), b"../target/path");
        let attrs = pool.getattr(link).unwrap();
        assert!(attrs.is_symlink());
        assert_eq!(attrs.size, 14);
        assert_eq!(
            pool.lookup(ROOT_INODE, "link").unwrap().kind,
            EntryKind::Symlink
        );
        assert_ne!(
            pool.superblocks[0].feature_ro_compat & FEATURE_RO_COMPAT_SPECIAL_FILES,
            0
        );
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        assert_eq!(pool.readlink(link).unwrap(), b"../target/path");
        let file = pool.create_file(ROOT_INODE, "f", 0o644, NOW).unwrap();
        assert!(pool.readlink(file).is_err());
        assert!(pool.symlink(ROOT_INODE, "empty", b"", NOW).is_err());
        assert!(
            pool.symlink(ROOT_INODE, "long", &vec![b'x'; MAX_SYMLINK_TARGET + 1], NOW)
                .is_err()
        );
    }

    #[test]
    fn update_attrs_preserves_the_object_type() {
        let mut pool = new_pool();
        let link = pool.symlink(ROOT_INODE, "l", b"target", NOW).unwrap();
        pool.update_attrs(link, |a| a.mode = MODE_FILE | 0o600)
            .unwrap();
        let attrs = pool.getattr(link).unwrap();
        assert_eq!(
            attrs.mode & MODE_TYPE_MASK,
            MODE_SYMLINK,
            "the type bits are fixed at creation"
        );
        assert_eq!(attrs.mode & 0o777, 0o600, "permission bits still change");
        assert_eq!(pool.readlink(link).unwrap(), b"target");
        assert!(matches!(
            pool.read(link, 0, 4),
            Err(ScaleFsError::InvalidArgument(_))
        ));
    }

    #[test]
    fn mknod_makes_fifos_sockets_and_devices() {
        let mut pool = new_pool();
        let fifo = pool
            .mknod(ROOT_INODE, "pipe", MODE_FIFO | 0o644, 0, NOW)
            .unwrap();
        assert_eq!(
            pool.lookup(ROOT_INODE, "pipe").unwrap().kind,
            EntryKind::Fifo
        );
        assert_eq!(pool.getattr(fifo).unwrap().mode & MODE_TYPE_MASK, MODE_FIFO);

        let sock = pool
            .mknod(ROOT_INODE, "sock", MODE_SOCKET | 0o644, 0, NOW)
            .unwrap();
        assert_eq!(
            pool.lookup(ROOT_INODE, "sock").unwrap().kind,
            EntryKind::Socket
        );
        assert!(pool.readlink(sock).is_err());

        let rdev = 0x0000_0100_0000_0003u64;
        let dev = pool
            .mknod(ROOT_INODE, "zero", MODE_CHAR_DEVICE | 0o666, rdev, NOW)
            .unwrap();
        assert_eq!(
            pool.lookup(ROOT_INODE, "zero").unwrap().kind,
            EntryKind::CharDevice
        );
        assert!(pool.getattr(dev).unwrap().is_device());
        assert_eq!(pool.device_rdev(dev).unwrap(), rdev);
        let blk = pool
            .mknod(ROOT_INODE, "disk", MODE_BLOCK_DEVICE | 0o660, 0x0802, NOW)
            .unwrap();
        assert_eq!(pool.device_rdev(blk).unwrap(), 0x0802);

        assert_ne!(
            pool.superblocks[0].feature_ro_compat & FEATURE_RO_COMPAT_SPECIAL_FILES,
            0
        );
        assert!(pool.device_rdev(fifo).is_err());

        let mut plain = new_pool();
        plain
            .mknod(ROOT_INODE, "reg", MODE_FILE | 0o644, 0, NOW)
            .unwrap();
        assert_eq!(
            plain.superblocks[0].feature_ro_compat & FEATURE_RO_COMPAT_SPECIAL_FILES,
            0
        );
        assert!(
            plain
                .mknod(ROOT_INODE, "d", MODE_DIRECTORY, 0, NOW)
                .is_err()
        );
    }

    #[test]
    fn special_files_hold_no_file_data() {
        let mut pool = new_pool();
        let link = pool.symlink(ROOT_INODE, "l", b"somewhere", NOW).unwrap();
        let fifo = pool
            .mknod(ROOT_INODE, "p", MODE_FIFO | 0o644, 0, NOW)
            .unwrap();
        for id in [link, fifo] {
            assert!(matches!(
                pool.read(id, 0, 16),
                Err(ScaleFsError::InvalidArgument(_))
            ));
            assert!(matches!(
                pool.write(id, 0, b"x", NOW),
                Err(ScaleFsError::InvalidArgument(_))
            ));
            assert!(matches!(
                pool.truncate(id, 0, NOW),
                Err(ScaleFsError::InvalidArgument(_))
            ));
        }
    }

    #[test]
    fn removing_a_special_file_drops_its_content() {
        let mut pool = new_pool();
        let link = pool.symlink(ROOT_INODE, "link", b"somewhere", NOW).unwrap();
        pool.unlink(ROOT_INODE, "link", LATER).unwrap();
        assert!(matches!(pool.getattr(link), Err(ScaleFsError::NotFound)));
        assert!(pool.tree().get(special_key(link)).unwrap().is_none());
    }

    #[test]
    fn link_serves_the_same_bytes_under_both_names_and_counts_references() {
        let mut pool = new_pool();
        let file = pool.create_file(ROOT_INODE, "a", 0o644, NOW).unwrap();
        let content = pattern(40_000, 7);
        pool.write(file, 0, &content, NOW).unwrap();

        pool.link(file, ROOT_INODE, "b", LATER).unwrap();
        assert_eq!(pool.getattr(file).unwrap().nlink, 2);
        let a = pool.lookup(ROOT_INODE, "a").unwrap();
        let b = pool.lookup(ROOT_INODE, "b").unwrap();
        assert_eq!(a.inode, b.inode);
        assert_eq!(b.kind, EntryKind::File);
        assert_eq!(pool.read(b.inode, 0, content.len()).unwrap(), content);

        pool.write(file, 0, b"rewritten", LATER).unwrap();
        assert_eq!(
            pool.read(pool.lookup(ROOT_INODE, "a").unwrap().inode, 0, 9)
                .unwrap(),
            b"rewritten"
        );
    }

    #[test]
    fn unlink_of_one_name_keeps_the_object_through_commit_and_reopen() {
        let mut pool = new_pool();
        let file = pool.create_file(ROOT_INODE, "a", 0o644, NOW).unwrap();
        let content = pattern(50_000, 3);
        pool.write(file, 0, &content, NOW).unwrap();
        pool.link(file, ROOT_INODE, "b", NOW).unwrap();
        pool.commit(crate::zones::AllocPurpose::Normal, NOW)
            .unwrap();

        pool.unlink(ROOT_INODE, "a", LATER).unwrap();
        assert_eq!(pool.getattr(file).unwrap().nlink, 1);
        assert!(matches!(
            pool.lookup(ROOT_INODE, "a"),
            Err(ScaleFsError::NotFound)
        ));
        pool.commit(crate::zones::AllocPurpose::Normal, LATER)
            .unwrap();

        let mut pool = Pool::open(pool.into_device()).unwrap();
        let b = pool.lookup(ROOT_INODE, "b").unwrap();
        assert_eq!(pool.read(b.inode, 0, content.len()).unwrap(), content);
        assert_eq!(pool.getattr(b.inode).unwrap().nlink, 1);

        pool.unlink(ROOT_INODE, "b", LATER).unwrap();
        assert!(matches!(pool.getattr(file), Err(ScaleFsError::NotFound)));
        assert!(
            pool.tree()
                .range(extent_key(file, 0), extent_key(file, u64::MAX))
                .unwrap()
                .is_empty(),
            "the last unlink must release the extents"
        );
    }

    #[test]
    fn link_refuses_directories_missing_objects_and_collisions() {
        let mut pool = new_pool();
        let dir = pool.mkdir(ROOT_INODE, "d", 0o755, NOW).unwrap();
        let file = pool.create_file(ROOT_INODE, "f", 0o644, NOW).unwrap();

        assert!(matches!(
            pool.link(dir, ROOT_INODE, "d2", NOW),
            Err(ScaleFsError::IsDirectory)
        ));
        assert!(matches!(
            pool.link(9999, ROOT_INODE, "ghost", NOW),
            Err(ScaleFsError::NotFound)
        ));
        assert!(matches!(
            pool.link(file, ROOT_INODE, "F", NOW),
            Err(ScaleFsError::AlreadyExists)
        ));
        assert_eq!(pool.getattr(file).unwrap().nlink, 1);
    }

    #[test]
    fn link_max_is_a_hard_ceiling() {
        let mut pool = new_pool();
        let file = pool.create_file(ROOT_INODE, "f", 0o644, NOW).unwrap();
        let mut attrs = pool.getattr(file).unwrap();
        attrs.nlink = LINK_MAX;
        pool.tree_mut()
            .insert(inode_key(file), MetadataValue::Inode(attrs))
            .unwrap();
        assert!(matches!(
            pool.link(file, ROOT_INODE, "one-too-many", NOW),
            Err(ScaleFsError::TooManyLinks)
        ));
    }

    #[test]
    fn hardlinks_set_the_ro_compat_bit_lazily_and_persist_it() {
        let mut pool = new_pool();
        let file = pool.create_file(ROOT_INODE, "f", 0o644, NOW).unwrap();
        pool.write(file, 0, b"payload", NOW).unwrap();
        pool.unlink(ROOT_INODE, "f", NOW).unwrap();
        assert_eq!(
            pool.superblocks[0].feature_ro_compat & FEATURE_RO_COMPAT_HARDLINKS,
            0,
            "ordinary create/write/unlink must not claim the feature"
        );

        let file = pool.create_file(ROOT_INODE, "g", 0o644, NOW).unwrap();
        pool.link(file, ROOT_INODE, "h", NOW).unwrap();
        assert_ne!(
            pool.superblocks[0].feature_ro_compat & FEATURE_RO_COMPAT_HARDLINKS,
            0
        );
        pool.commit(crate::zones::AllocPurpose::Normal, NOW)
            .unwrap();
        let pool = Pool::open(pool.into_device()).unwrap();
        assert_ne!(
            pool.superblocks[0].feature_ro_compat & FEATURE_RO_COMPAT_HARDLINKS,
            0,
            "the bit must persist the reopen"
        );
    }

    #[test]
    fn update_attrs_cannot_clobber_the_link_count() {
        let mut pool = new_pool();
        let file = pool.create_file(ROOT_INODE, "f", 0o644, NOW).unwrap();
        pool.link(file, ROOT_INODE, "g", NOW).unwrap();
        pool.update_attrs(file, |attrs| {
            attrs.nlink = 77;
            attrs.mode = 0o600 | MODE_FILE;
        })
        .unwrap();
        let attrs = pool.getattr(file).unwrap();
        assert_eq!(attrs.nlink, 2, "the link count is engine-owned");
        assert_eq!(attrs.mode & 0o777, 0o600, "the mode edit still lands");
    }

    #[test]
    fn special_files_can_carry_hard_links() {
        let mut pool = new_pool();
        let sym = pool.symlink(ROOT_INODE, "s", b"target", NOW).unwrap();
        let fifo = pool
            .mknod(ROOT_INODE, "p", MODE_FIFO | 0o644, 0, NOW)
            .unwrap();
        pool.link(sym, ROOT_INODE, "s2", NOW).unwrap();
        pool.link(fifo, ROOT_INODE, "p2", NOW).unwrap();

        let s2 = pool.lookup(ROOT_INODE, "s2").unwrap();
        assert_eq!(s2.kind, EntryKind::Symlink);
        assert_eq!(pool.readlink(s2.inode).unwrap(), b"target");
        assert_eq!(pool.lookup(ROOT_INODE, "p2").unwrap().kind, EntryKind::Fifo);
        assert_eq!(pool.getattr(sym).unwrap().nlink, 2);

        pool.unlink(ROOT_INODE, "s", LATER).unwrap();
        assert_eq!(pool.readlink(sym).unwrap(), b"target");
        pool.unlink(ROOT_INODE, "s2", LATER).unwrap();
        assert!(pool.tree().get(special_key(sym)).unwrap().is_none());
    }

    #[test]
    fn xattrs_round_trip_and_die_with_the_object() {
        let mut pool = new_pool();
        let file = pool.create_file(ROOT_INODE, "f", 0o644, NOW).unwrap();
        pool.set_xattr(
            file,
            "user.origin",
            b"https://example",
            XATTR_SET_EITHER,
            NOW,
        )
        .unwrap();
        pool.set_xattr(
            file,
            "security.capability",
            &[1, 2, 3],
            XATTR_SET_EITHER,
            NOW,
        )
        .unwrap();
        assert_eq!(
            pool.get_xattr(file, "user.origin").unwrap(),
            b"https://example"
        );
        let mut names = pool.list_xattrs(file).unwrap();
        names.sort();
        assert_eq!(names, vec!["security.capability", "user.origin"]);

        pool.set_xattr(file, "user.origin", b"replaced", XATTR_SET_REPLACE, NOW)
            .unwrap();
        assert_eq!(pool.get_xattr(file, "user.origin").unwrap(), b"replaced");
        pool.remove_xattr(file, "security.capability", NOW).unwrap();
        assert!(matches!(
            pool.get_xattr(file, "security.capability"),
            Err(ScaleFsError::NotFound)
        ));

        pool.unlink(ROOT_INODE, "f", LATER).unwrap();
        assert!(
            pool.tree()
                .range(xattr_key(file, 0), xattr_key(file, u64::MAX))
                .unwrap()
                .is_empty(),
            "xattr keys must die with their object"
        );
    }

    #[test]
    fn xattr_set_flags_follow_the_linux_contract() {
        let mut pool = new_pool();
        let file = pool.create_file(ROOT_INODE, "f", 0o644, NOW).unwrap();
        pool.set_xattr(file, "user.a", b"1", XATTR_SET_CREATE, NOW)
            .unwrap();
        assert!(matches!(
            pool.set_xattr(file, "user.a", b"2", XATTR_SET_CREATE, NOW),
            Err(ScaleFsError::AlreadyExists)
        ));
        assert!(matches!(
            pool.set_xattr(file, "user.missing", b"2", XATTR_SET_REPLACE, NOW),
            Err(ScaleFsError::NotFound)
        ));
        assert!(matches!(
            pool.remove_xattr(file, "user.missing", NOW),
            Err(ScaleFsError::NotFound)
        ));
    }

    #[test]
    fn xattrs_set_the_ro_compat_bit_lazily_and_survive_reopen() {
        let mut pool = new_pool();
        let file = pool.create_file(ROOT_INODE, "f", 0o644, NOW).unwrap();
        assert_eq!(
            pool.superblocks[0].feature_ro_compat & FEATURE_RO_COMPAT_XATTRS,
            0
        );
        pool.set_xattr(file, "user.tag", b"kept", XATTR_SET_EITHER, LATER)
            .unwrap();
        assert_ne!(
            pool.superblocks[0].feature_ro_compat & FEATURE_RO_COMPAT_XATTRS,
            0
        );
        assert_eq!(pool.getattr(file).unwrap().ctime_ns, LATER);
        pool.commit(crate::zones::AllocPurpose::Normal, NOW)
            .unwrap();
        let pool = Pool::open(pool.into_device()).unwrap();
        assert_eq!(pool.get_xattr(file, "user.tag").unwrap(), b"kept");
        assert_ne!(
            pool.superblocks[0].feature_ro_compat & FEATURE_RO_COMPAT_XATTRS,
            0
        );
    }

    #[test]
    fn oversized_xattr_values_answer_the_capacity_refusal() {
        let mut pool = new_pool();
        let file = pool.create_file(ROOT_INODE, "f", 0o644, NOW).unwrap();
        let too_big = vec![7u8; XATTR_VALUE_MAX + 1];
        assert!(matches!(
            pool.set_xattr(file, "user.big", &too_big, XATTR_SET_EITHER, NOW),
            Err(ScaleFsError::OutOfSpace)
        ));
        let exactly = vec![7u8; XATTR_VALUE_MAX];
        pool.set_xattr(file, "user.big", &exactly, XATTR_SET_EITHER, NOW)
            .unwrap();
        assert_eq!(pool.get_xattr(file, "user.big").unwrap(), exactly);
    }

    #[test]
    fn xattrs_live_on_every_object_kind() {
        let mut pool = new_pool();
        let dir = pool.mkdir(ROOT_INODE, "d", 0o755, NOW).unwrap();
        let sym = pool.symlink(ROOT_INODE, "s", b"target", NOW).unwrap();
        for object in [dir, sym] {
            pool.set_xattr(object, "user.mark", b"x", XATTR_SET_EITHER, NOW)
                .unwrap();
            assert_eq!(pool.get_xattr(object, "user.mark").unwrap(), b"x");
        }
    }

    #[test]
    fn xattrs_follow_the_object_across_its_names() {
        let mut pool = new_pool();
        let file = pool.create_file(ROOT_INODE, "a", 0o644, NOW).unwrap();
        pool.set_xattr(file, "user.tag", b"shared", XATTR_SET_EITHER, NOW)
            .unwrap();
        pool.link(file, ROOT_INODE, "b", NOW).unwrap();
        pool.unlink(ROOT_INODE, "a", NOW).unwrap();
        assert_eq!(pool.get_xattr(file, "user.tag").unwrap(), b"shared");
    }

    #[test]
    fn link_and_unlink_bump_the_right_times() {
        let mut pool = new_pool();
        let file = pool.create_file(ROOT_INODE, "f", 0o644, NOW).unwrap();

        pool.link(file, ROOT_INODE, "g", LATER).unwrap();
        assert_eq!(pool.getattr(file).unwrap().ctime_ns, LATER);
        assert_eq!(pool.getattr(ROOT_INODE).unwrap().mtime_ns, LATER);

        let even_later = LATER + 1_000_000_000;
        pool.unlink(ROOT_INODE, "g", even_later).unwrap();
        assert_eq!(
            pool.getattr(file).unwrap().ctime_ns,
            even_later,
            "a non-last unlink is a ctime event on the object"
        );
        assert_eq!(pool.getattr(file).unwrap().nlink, 1);
    }
}
