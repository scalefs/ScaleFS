use crate::fuse::fs::Filesystem;
use crate::fuse::wire::{
    Attr, AttrOut, EntryOut, OpenOut, SetattrIn, StatfsOut, dirent_type, errno, push_dirent,
    setattr_flags,
};
use crate::mountcore::{MountAttr, MountCore, MountError, SetAttr, TimeChange};
use scalefs_core::{EntryKind, MAX_NAME_LEN, Pool, SharedDevice};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

const CACHE_SECONDS: u64 = 1;

pub struct PoolFilesystem<D: SharedDevice> {
    core: Arc<MountCore<D>>,
    surface_read_only: bool,
    handles: Mutex<BTreeMap<u64, Handle>>,
    next_fh: AtomicU64,
}

struct Handle {
    inode: u64,
    wrote: bool,
}

impl<D: SharedDevice> PoolFilesystem<D> {
    pub fn read_only(pool: Arc<RwLock<Pool<D>>>) -> Self {
        Self::over(Arc::new(MountCore::read_only(pool)))
    }

    pub fn read_write(pool: Arc<RwLock<Pool<D>>>) -> Self
    where
        D: Send + Sync + 'static,
    {
        Self::over(Arc::new(MountCore::read_write(pool)))
    }

    pub fn over(core: Arc<MountCore<D>>) -> Self {
        PoolFilesystem {
            core,
            surface_read_only: false,
            handles: Mutex::new(BTreeMap::new()),
            next_fh: AtomicU64::new(0),
        }
    }

    pub fn over_read_only(core: Arc<MountCore<D>>) -> Self {
        PoolFilesystem {
            core,
            surface_read_only: true,
            handles: Mutex::new(BTreeMap::new()),
            next_fh: AtomicU64::new(0),
        }
    }

    fn is_read_only(&self) -> bool {
        self.surface_read_only || self.core.is_read_only()
    }

    pub fn shutdown(&self) -> Result<(), i32> {
        self.release_all();
        self.core.commit_if_dirty().map_err(errno_of)
    }

    fn release_all(&self) {
        let handles = match self.handles.lock() {
            Ok(mut handles) => std::mem::take(&mut *handles),
            Err(_) => return,
        };
        for handle in handles.into_values() {
            self.core.release(handle.inode);
        }
    }

    fn allocate_fh(&self, inode: u64) -> u64 {
        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed) + 1;
        if let Ok(mut handles) = self.handles.lock() {
            handles.insert(
                fh,
                Handle {
                    inode,
                    wrote: false,
                },
            );
        }
        fh
    }
}

impl<D: SharedDevice> Drop for PoolFilesystem<D> {
    fn drop(&mut self) {
        self.release_all();
    }
}

fn errno_of(error: MountError) -> i32 {
    match error {
        MountError::NotFound => errno::ENOENT,
        MountError::NotDirectory => errno::ENOTDIR,
        MountError::IsDirectory => errno::EISDIR,
        MountError::Exists => errno::EEXIST,
        MountError::NotEmpty => errno::ENOTEMPTY,
        MountError::NoSpace => errno::ENOSPC,
        MountError::TooManyLinks => errno::EMLINK,
        MountError::NotSupported => errno::EOPNOTSUPP,
        MountError::NameTooLong => errno::ENAMETOOLONG,
        MountError::InvalidName | MountError::Invalid => errno::EINVAL,
        MountError::ReadOnly => errno::EROFS,
        MountError::Denied => errno::EPERM,
        MountError::Io => errno::EIO,
    }
}

fn split_time(ns: i64) -> (u64, u32) {
    let ns = ns.max(0) as u64;
    (ns / 1_000_000_000, (ns % 1_000_000_000) as u32)
}

fn join_time(secs: u64, nsec: u32) -> i64 {
    (secs as i64)
        .saturating_mul(1_000_000_000)
        .saturating_add(i64::from(nsec))
}

fn fuse_split_dev(dev: u32) -> u64 {
    let major = u64::from((dev & 0x000f_ff00) >> 8);
    let minor = u64::from((dev & 0xff) | ((dev >> 12) & 0x000f_ff00));
    major | (minor << 32)
}

fn fuse_pack_dev(dev: u64) -> u32 {
    let major = dev as u32;
    let minor = (dev >> 32) as u32;
    (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12)
}

fn attr_of(m: &MountAttr, apply_deferred: bool) -> Attr {
    let attrs = &m.attrs;
    let (atime, atime_nsec) = split_time(attrs.atime_ns);
    let (mtime, mtime_nsec) = split_time(attrs.mtime_ns);
    let (ctime, ctime_nsec) = split_time(attrs.ctime_ns);
    Attr {
        ino: m.inode,
        size: attrs.size,
        blocks: attrs.size.div_ceil(512),
        atime,
        mtime,
        ctime,
        atime_nsec,
        mtime_nsec,
        ctime_nsec,
        mode: attrs.mode,
        nlink: if apply_deferred && m.deferred {
            0
        } else {
            attrs.nlink
        },
        uid: attrs.uid,
        gid: attrs.gid,
        rdev: fuse_pack_dev(m.rdev),
        blksize: m.blksize,
    }
}

fn attr_out(m: &MountAttr, apply_deferred: bool) -> AttrOut {
    AttrOut {
        attr_valid: CACHE_SECONDS,
        attr_valid_nsec: 0,
        attr: attr_of(m, apply_deferred),
    }
}

fn entry_out(m: &MountAttr) -> EntryOut {
    EntryOut {
        nodeid: m.inode,
        generation: 0,
        entry_valid: CACHE_SECONDS,
        attr_valid: CACHE_SECONDS,
        entry_valid_nsec: 0,
        attr_valid_nsec: 0,
        attr: attr_of(m, false),
    }
}

fn kind_bits(kind: &EntryKind) -> u32 {
    match kind {
        EntryKind::Directory => dirent_type::DIRECTORY,
        EntryKind::File => dirent_type::REGULAR,
        EntryKind::Symlink => dirent_type::SYMLINK,
        EntryKind::Fifo => dirent_type::FIFO,
        EntryKind::Socket => dirent_type::SOCKET,
        EntryKind::CharDevice => dirent_type::CHAR_DEVICE,
        EntryKind::BlockDevice => dirent_type::BLOCK_DEVICE,
        EntryKind::Unknown(_) => 0,
    }
}

fn utf8_name(name: &[u8], missing: MountError) -> Result<&str, MountError> {
    if name.len() > MAX_NAME_LEN {
        return Err(MountError::NameTooLong);
    }
    if name.contains(&b'/') {
        return Err(MountError::InvalidName);
    }
    std::str::from_utf8(name).map_err(|_| missing)
}

fn set_attr_from(change: &SetattrIn) -> SetAttr {
    let valid = change.valid;
    let time = |set: u32, now: u32, value: i64| -> Option<TimeChange> {
        if valid & now != 0 {
            Some(TimeChange::Now)
        } else if valid & set != 0 {
            Some(TimeChange::Set(value))
        } else {
            None
        }
    };
    SetAttr {
        size: (valid & setattr_flags::SIZE != 0).then_some(change.size),
        mode: (valid & setattr_flags::MODE != 0).then_some(change.mode),
        uid: (valid & setattr_flags::UID != 0).then_some(change.uid),
        gid: (valid & setattr_flags::GID != 0).then_some(change.gid),
        atime: time(
            setattr_flags::ATIME,
            setattr_flags::ATIME_NOW,
            join_time(change.atime, change.atime_nsec),
        ),
        mtime: time(
            setattr_flags::MTIME,
            setattr_flags::MTIME_NOW,
            join_time(change.mtime, change.mtime_nsec),
        ),
        ctime: (valid & setattr_flags::CTIME != 0)
            .then(|| join_time(change.ctime, change.ctime_nsec)),
        attributes: None,
        bsd_flags: None,
        crtime: None,
    }
}

impl<D: SharedDevice> Filesystem for PoolFilesystem<D> {
    fn getattr(&self, nodeid: u64) -> Result<AttrOut, i32> {
        let m = self.core.getattr(nodeid).map_err(errno_of)?;
        Ok(attr_out(&m, true))
    }

    fn lookup(&self, parent: u64, name: &[u8]) -> Result<EntryOut, i32> {
        let name = utf8_name(name, MountError::NotFound).map_err(errno_of)?;
        let m = self.core.lookup(parent, name).map_err(errno_of)?;
        Ok(entry_out(&m))
    }

    fn readdir(&self, nodeid: u64, offset: u64, size: u32) -> Result<Vec<u8>, i32> {
        let entries = self.core.readdir_hashed(nodeid).map_err(errno_of)?;
        let mut out = Vec::new();
        let capacity = size as usize;
        if offset < 1 && !push_dirent(&mut out, capacity, nodeid, 1, dirent_type::DIRECTORY, b".") {
            return Ok(out);
        }
        if offset < 2 && !push_dirent(&mut out, capacity, nodeid, 2, dirent_type::DIRECTORY, b"..")
        {
            return Ok(out);
        }
        for (index, hashed) in entries.iter().enumerate() {
            let after = entries[index + 1..]
                .iter()
                .take_while(|next| next.hash == hashed.hash)
                .count() as u64;
            let d_off = hashed.hash.saturating_add(3).saturating_sub(after).max(3);
            if d_off <= offset {
                continue;
            }
            if !push_dirent(
                &mut out,
                capacity,
                hashed.entry.inode,
                d_off,
                kind_bits(&hashed.entry.kind),
                hashed.entry.name.as_bytes(),
            ) {
                break;
            }
        }
        Ok(out)
    }

    fn open(&self, nodeid: u64, _flags: u32) -> Result<OpenOut, i32> {
        self.core.getattr(nodeid).map_err(errno_of)?;
        let fh = self.allocate_fh(nodeid);
        self.core.retain(nodeid);
        Ok(OpenOut { fh, open_flags: 0 })
    }

    fn read(&self, nodeid: u64, _fh: u64, offset: u64, size: u32) -> Result<Vec<u8>, i32> {
        self.core
            .read(nodeid, offset, size as usize)
            .map_err(errno_of)
    }

    fn release(&self, _nodeid: u64, fh: u64) {
        let handle = match self.handles.lock() {
            Ok(mut handles) => handles.remove(&fh),
            Err(_) => None,
        };
        if let Some(handle) = handle {
            self.core.release(handle.inode);
        }
    }

    fn statfs(&self) -> Result<StatfsOut, i32> {
        let s = self.core.statfs().map_err(errno_of)?;
        Ok(StatfsOut {
            blocks: s.blocks,
            bfree: s.bfree,
            bavail: s.bavail,
            files: 0,
            ffree: 0,
            bsize: s.bsize,
            namelen: s.namelen,
            frsize: s.bsize,
        })
    }

    fn setattr(&self, nodeid: u64, change: &SetattrIn) -> Result<AttrOut, i32> {
        if self.is_read_only() {
            return Err(errno::EROFS);
        }
        let m = self
            .core
            .setattr(nodeid, set_attr_from(change))
            .map_err(errno_of)?;
        Ok(attr_out(&m, true))
    }

    fn mkdir(
        &self,
        parent: u64,
        name: &[u8],
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<EntryOut, i32> {
        if self.is_read_only() {
            return Err(errno::EROFS);
        }
        let name = utf8_name(name, MountError::Invalid).map_err(errno_of)?;
        let m = self
            .core
            .mkdir(parent, name, mode, uid, gid)
            .map_err(errno_of)?;
        Ok(entry_out(&m))
    }

    fn readlink(&self, nodeid: u64) -> Result<Vec<u8>, i32> {
        self.core.readlink(nodeid).map_err(errno_of)
    }

    fn symlink(
        &self,
        parent: u64,
        name: &[u8],
        target: &[u8],
        uid: u32,
        gid: u32,
    ) -> Result<EntryOut, i32> {
        if self.is_read_only() {
            return Err(errno::EROFS);
        }
        let name = utf8_name(name, MountError::Invalid).map_err(errno_of)?;
        let m = self
            .core
            .symlink(parent, name, target, uid, gid)
            .map_err(errno_of)?;
        Ok(entry_out(&m))
    }

    fn mknod(
        &self,
        parent: u64,
        name: &[u8],
        mode: u32,
        rdev: u32,
        uid: u32,
        gid: u32,
    ) -> Result<EntryOut, i32> {
        if self.is_read_only() {
            return Err(errno::EROFS);
        }
        let name = utf8_name(name, MountError::Invalid).map_err(errno_of)?;
        let m = self
            .core
            .mknod(parent, name, mode, fuse_split_dev(rdev), uid, gid)
            .map_err(errno_of)?;
        Ok(entry_out(&m))
    }

    fn link(&self, source: u64, new_parent: u64, name: &[u8]) -> Result<EntryOut, i32> {
        if self.is_read_only() {
            return Err(errno::EROFS);
        }
        let name = utf8_name(name, MountError::Invalid).map_err(errno_of)?;
        let m = self.core.link(source, new_parent, name).map_err(errno_of)?;
        Ok(entry_out(&m))
    }

    fn setxattr(&self, inode: u64, name: &[u8], value: &[u8], flags: u32) -> Result<(), i32> {
        if self.is_read_only() {
            return Err(errno::EROFS);
        }
        let name = utf8_name(name, MountError::Invalid).map_err(errno_of)?;
        self.core
            .setxattr(inode, name, value, flags)
            .map_err(errno_of)
    }

    fn getxattr(&self, inode: u64, name: &[u8]) -> Result<Vec<u8>, i32> {
        let name = utf8_name(name, MountError::Invalid).map_err(errno_of)?;
        self.core.getxattr(inode, name).map_err(|e| match e {
            MountError::NotFound => errno::ENODATA,
            other => errno_of(other),
        })
    }

    fn listxattr(&self, inode: u64) -> Result<Vec<u8>, i32> {
        let names = self.core.listxattr(inode).map_err(errno_of)?;
        let mut blob = Vec::new();
        for name in names {
            blob.extend_from_slice(name.as_bytes());
            blob.push(0);
        }
        Ok(blob)
    }

    fn removexattr(&self, inode: u64, name: &[u8]) -> Result<(), i32> {
        if self.is_read_only() {
            return Err(errno::EROFS);
        }
        let name = utf8_name(name, MountError::Invalid).map_err(errno_of)?;
        self.core.removexattr(inode, name).map_err(|e| match e {
            MountError::NotFound => errno::ENODATA,
            other => errno_of(other),
        })
    }

    fn create(
        &self,
        parent: u64,
        name: &[u8],
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<(EntryOut, OpenOut), i32> {
        if self.is_read_only() {
            return Err(errno::EROFS);
        }
        let name = utf8_name(name, MountError::Invalid).map_err(errno_of)?;
        let m = self
            .core
            .create(parent, name, mode, uid, gid)
            .map_err(errno_of)?;
        let fh = self.allocate_fh(m.inode);
        self.core.retain(m.inode);
        Ok((entry_out(&m), OpenOut { fh, open_flags: 0 }))
    }

    fn write(&self, nodeid: u64, fh: u64, offset: u64, data: &[u8]) -> Result<u32, i32> {
        if self.is_read_only() {
            return Err(errno::EROFS);
        }
        let written = self.core.write(nodeid, offset, data).map_err(errno_of)?;
        if let Ok(mut handles) = self.handles.lock()
            && let Some(handle) = handles.get_mut(&fh)
        {
            handle.wrote = true;
        }
        Ok(written)
    }

    fn unlink(&self, parent: u64, name: &[u8]) -> Result<(), i32> {
        if self.is_read_only() {
            return Err(errno::EROFS);
        }
        let name = utf8_name(name, MountError::NotFound).map_err(errno_of)?;
        self.core.unlink(parent, name).map_err(errno_of)
    }

    fn rmdir(&self, parent: u64, name: &[u8]) -> Result<(), i32> {
        if self.is_read_only() {
            return Err(errno::EROFS);
        }
        let name = utf8_name(name, MountError::NotFound).map_err(errno_of)?;
        self.core.rmdir(parent, name).map_err(errno_of)
    }

    fn rename(
        &self,
        old_parent: u64,
        old_name: &[u8],
        new_parent: u64,
        new_name: &[u8],
        replace: bool,
    ) -> Result<(), i32> {
        if self.is_read_only() {
            return Err(errno::EROFS);
        }
        let old_name = utf8_name(old_name, MountError::NotFound).map_err(errno_of)?;
        let new_name = utf8_name(new_name, MountError::Invalid).map_err(errno_of)?;
        self.core
            .rename(old_parent, old_name, new_parent, new_name, replace)
            .map_err(errno_of)
    }

    fn flush(&self, _nodeid: u64, fh: u64) -> Result<(), i32> {
        let wrote = self
            .handles
            .lock()
            .map(|handles| handles.get(&fh).map(|h| h.wrote).unwrap_or(false))
            .unwrap_or(false);
        if wrote {
            self.core.commit_if_dirty().map_err(errno_of)
        } else {
            Ok(())
        }
    }

    fn fsync(&self, _nodeid: u64, _fh: u64, _datasync: bool) -> Result<(), i32> {
        self.core.commit().map_err(errno_of)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mountcore::{DEBOUNCE_QUIET, ORPHANAGE, now_ns};
    use scalefs_core::{
        AllocPurpose, CaseSensitivity, CreateParams, DeviceId, Geometry, MemoryBlockDevice, PoolId,
        ROOT_INODE,
    };
    use std::time::{Duration, Instant};

    const NOW: i64 = 1_700_000_000_123_456_789;

    fn test_geometry() -> Geometry {
        Geometry {
            logical_block_size: 4096,
            physical_block_size: 4096,
            zone_size: 64 * 1024,
            zone_count: 64,
            erase_granularity_zones: 1,
            sequential_write_required: false,
        }
    }

    fn test_params() -> CreateParams {
        CreateParams {
            geometry: test_geometry(),
            pool_id: PoolId([0x77; 16]),
            device_id: DeviceId([0x78; 16]),
            case_sensitivity: CaseSensitivity::InsensitivePreserving,
            dirent_hash_seed: 5,
            label: "mounted".to_string(),
            created_at_ns: NOW,
        }
    }

    fn test_pool() -> Pool<Arc<MemoryBlockDevice>> {
        Pool::create(
            Arc::new(MemoryBlockDevice::new(scalefs_core::member_image_len(
                test_geometry().capacity_bytes(),
            ) as usize)),
            test_params(),
        )
        .unwrap()
    }

    fn seeded() -> (PoolFilesystem<Arc<MemoryBlockDevice>>, u64, u64, u64) {
        let mut pool = test_pool();
        let docs = pool.mkdir(ROOT_INODE, "docs", 0o755, NOW).unwrap();
        let notes = pool.create_file(docs, "notes.txt", 0o644, NOW).unwrap();
        let payload: Vec<u8> = (0..20_000usize).map(|i| (i % 251) as u8).collect();
        pool.write(notes, 0, &payload, NOW).unwrap();
        let empty = pool
            .create_file(ROOT_INODE, "empty.bin", 0o600, NOW)
            .unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        (
            PoolFilesystem::read_only(Arc::new(RwLock::new(pool))),
            docs,
            notes,
            empty,
        )
    }

    type SharedTestPool = Arc<RwLock<Pool<Arc<MemoryBlockDevice>>>>;

    fn seeded_rw() -> (PoolFilesystem<Arc<MemoryBlockDevice>>, SharedTestPool) {
        let mut pool = test_pool();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let shared = Arc::new(RwLock::new(pool));
        (PoolFilesystem::read_write(Arc::clone(&shared)), shared)
    }

    fn committed_tx<D: SharedDevice>(shared: &Arc<RwLock<Pool<D>>>) -> u64 {
        shared.read().unwrap().committed_tx()
    }

    fn plain_setattr(valid: u32) -> SetattrIn {
        SetattrIn {
            valid,
            fh: 0,
            size: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
            atime_nsec: 0,
            mtime_nsec: 0,
            ctime_nsec: 0,
            mode: 0,
            uid: 0,
            gid: 0,
        }
    }

    #[test]
    fn getattr_translates_engine_attributes() {
        let (fs, docs, notes, empty) = seeded();
        let root = fs.getattr(ROOT_INODE).unwrap().attr;
        assert_eq!(root.ino, ROOT_INODE);
        assert_eq!(root.mode & 0o170000, 0o040000, "root is a directory");
        assert_eq!(root.blksize, 4096);

        let dir = fs.getattr(docs).unwrap().attr;
        assert_eq!(dir.mode & 0o170000, 0o040000);

        let file = fs.getattr(notes).unwrap().attr;
        assert_eq!(file.mode & 0o170000, 0o100000, "a regular file");
        assert_eq!(file.mode & 0o777, 0o644);
        assert_eq!(file.size, 20_000);
        assert_eq!(file.blocks, 20_000u64.div_ceil(512));
        assert_eq!(file.mtime, (NOW / 1_000_000_000) as u64);
        assert_eq!(file.mtime_nsec, (NOW % 1_000_000_000) as u32);

        assert_eq!(fs.getattr(empty).unwrap().attr.size, 0);
        assert_eq!(fs.getattr(999_999), Err(errno::ENOENT));
    }

    #[test]
    fn lookup_follows_engine_naming() {
        let (fs, docs, notes, _) = seeded();
        let entry = fs.lookup(ROOT_INODE, b"docs").unwrap();
        assert_eq!(entry.nodeid, docs);
        assert_eq!(fs.lookup(docs, b"NOTES.TXT").unwrap().nodeid, notes);
        assert_eq!(fs.lookup(ROOT_INODE, b"absent"), Err(errno::ENOENT));
        assert_eq!(fs.lookup(notes, b"x"), Err(errno::ENOTDIR));
        assert_eq!(fs.lookup(ROOT_INODE, b"\xFF\xFE"), Err(errno::ENOENT));
    }

    #[test]
    fn readdir_pages_exactly_once() {
        let (fs, ..) = seeded();
        let full = fs.readdir(ROOT_INODE, 0, 4096).unwrap();
        let names = dirent_names(&full);
        assert_eq!(&names[..2], &[".", ".."], "dots come first");
        let mut rest = names[2..].to_vec();
        rest.sort();
        assert_eq!(rest, vec!["docs", "empty.bin"], "every entry, once");

        let mut seen = Vec::new();
        let mut offset = 0u64;
        loop {
            let page = fs.readdir(ROOT_INODE, offset, 64).unwrap();
            if page.is_empty() {
                break;
            }
            let entries = parse_dirents(&page);
            offset = entries.last().unwrap().1;
            seen.extend(entries.into_iter().map(|(name, _)| name));
        }
        assert_eq!(seen, names, "the paged walk reproduces the full listing");

        assert_eq!(fs.readdir(999_999, 0, 4096), Err(errno::ENOENT));
    }

    #[test]
    fn readdir_survives_mutation_between_pages() {
        let (fs, _shared) = seeded_rw();
        for i in 0..50 {
            fs.create(ROOT_INODE, format!("f-{i:03}").as_bytes(), 0o644, 0, 0)
                .unwrap();
        }

        let mut counts = std::collections::BTreeMap::<String, u32>::new();
        let mut offset = 0u64;
        let mut mutated = false;
        let mut emitted = 0usize;
        loop {
            let page = fs.readdir(ROOT_INODE, offset, 96).unwrap();
            if page.is_empty() {
                break;
            }
            let entries = parse_dirents(&page);
            offset = entries.last().unwrap().1;
            for (name, _) in &entries {
                *counts.entry(name.clone()).or_default() += 1;
                emitted += 1;
            }
            if !mutated && emitted >= 12 {
                mutated = true;
                for i in 0..5 {
                    let _ = fs.unlink(ROOT_INODE, format!("f-{i:03}").as_bytes());
                    fs.create(ROOT_INODE, format!("g-{i:03}").as_bytes(), 0o644, 0, 0)
                        .unwrap();
                }
            }
        }
        assert!(mutated, "the walk paged enough to mutate mid-flight");

        for i in 5..50 {
            let name = format!("f-{i:03}");
            assert_eq!(counts.get(&name), Some(&1), "{name} returned exactly once");
        }
        for (name, count) in &counts {
            assert!(*count <= 1, "{name} duplicated ({count} times)");
        }
    }

    #[test]
    fn reads_behave_like_a_file() {
        let (fs, docs, notes, empty) = seeded();
        let payload: Vec<u8> = (0..20_000usize).map(|i| (i % 251) as u8).collect();
        assert_eq!(fs.read(notes, 0, 0, 20_000).unwrap(), payload);
        assert_eq!(
            fs.read(notes, 0, 4_000, 100).unwrap(),
            payload[4_000..4_100]
        );
        assert_eq!(
            fs.read(notes, 0, 19_990, 100).unwrap(),
            payload[19_990..],
            "EOF clamps"
        );
        assert!(fs.read(notes, 0, 40_000, 100).unwrap().is_empty());
        assert!(fs.read(empty, 0, 0, 100).unwrap().is_empty());
        assert_eq!(fs.read(docs, 0, 0, 100), Err(errno::EISDIR));
        assert!(fs.open(notes, 0).is_ok());
        assert!(fs.open(docs, 0).is_ok());
        let statfs = fs.statfs().unwrap();
        assert_eq!(statfs.bsize, 4096);
        assert!(statfs.blocks > 0);
        assert!(statfs.bfree <= statfs.blocks);
    }

    #[test]
    fn handles_are_tracked_per_open() {
        let (fs, _, notes, empty) = seeded();
        let first = fs.open(notes, 0).unwrap().fh;
        let second = fs.open(empty, 0).unwrap().fh;
        assert_ne!(first, second);
        assert!(fs.handles.lock().unwrap().contains_key(&first));
        fs.release(notes, first);
        assert!(!fs.handles.lock().unwrap().contains_key(&first));
        assert!(fs.handles.lock().unwrap().contains_key(&second));
    }

    #[test]
    fn read_only_refuses_mutation() {
        let (fs, docs, notes, _) = seeded();
        assert_eq!(
            fs.mkdir(ROOT_INODE, b"new", 0o755, 0, 0).unwrap_err(),
            errno::EROFS
        );
        assert_eq!(
            fs.create(ROOT_INODE, b"new.txt", 0o644, 0, 0).unwrap_err(),
            errno::EROFS
        );
        assert_eq!(fs.write(notes, 1, 0, b"x").unwrap_err(), errno::EROFS);
        assert_eq!(fs.unlink(docs, b"notes.txt").unwrap_err(), errno::EROFS);
        assert_eq!(fs.rmdir(ROOT_INODE, b"docs").unwrap_err(), errno::EROFS);
        assert_eq!(
            fs.rename(ROOT_INODE, b"docs", ROOT_INODE, b"stuff", true)
                .unwrap_err(),
            errno::EROFS
        );
        assert_eq!(
            fs.setattr(notes, &plain_setattr(setattr_flags::MODE))
                .unwrap_err(),
            errno::EROFS
        );
        assert_eq!(fs.flush(notes, 1), Ok(()));
        assert_eq!(fs.fsync(notes, 1, false), Ok(()));
        assert_eq!(fs.shutdown(), Ok(()));
    }

    #[test]
    fn writes_commit_and_survive_reopen() {
        use scalefs_core::FileBlockDevice;
        let image = std::env::temp_dir().join(format!(
            "scalefs-poolfs-rw-{}-{}.img",
            std::process::id(),
            now_ns() & 0xFFFF_FFFF,
        ));
        let device = Arc::new(
            FileBlockDevice::create(
                &image,
                scalefs_core::member_image_len(test_geometry().capacity_bytes()),
            )
            .unwrap(),
        );
        let mut pool = Pool::create(device, test_params()).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let shared = Arc::new(RwLock::new(pool));
        let fs = PoolFilesystem::read_write(Arc::clone(&shared));

        let (entry, open) = fs.create(ROOT_INODE, b"story.txt", 0o644, 0, 0).unwrap();
        let inode = entry.nodeid;
        assert_eq!(entry.attr.mode & 0o777, 0o644);
        let payload: Vec<u8> = (0..50_000usize).map(|i| (i * 13 % 251) as u8).collect();
        assert_eq!(
            fs.write(inode, open.fh, 0, &payload).unwrap(),
            payload.len() as u32
        );
        assert_eq!(fs.write(inode, open.fh, 10_000, &[0xAA; 64]).unwrap(), 64);
        assert_eq!(fs.write(inode, open.fh, 80_000, b"tail").unwrap(), 4);

        let before = committed_tx(&shared);
        fs.fsync(inode, open.fh, false).unwrap();
        let after = committed_tx(&shared);
        assert!(after > before, "fsync commits");
        fs.fsync(inode, open.fh, false).unwrap();
        assert_eq!(committed_tx(&shared), after);

        let mut expected = payload.clone();
        expected[10_000..10_064].fill(0xAA);
        expected.resize(80_000, 0);
        expected.extend_from_slice(b"tail");
        assert_eq!(fs.read(inode, open.fh, 0, 100_000).unwrap(), expected);

        drop(fs);
        drop(Arc::into_inner(shared).expect("all clones dropped"));
        let reopened = Pool::open(Arc::new(FileBlockDevice::open(&image).unwrap())).unwrap();
        let found = reopened.lookup(ROOT_INODE, "story.txt").unwrap();
        assert_eq!(reopened.read(found.inode, 0, 100_000).unwrap(), expected);
        drop(reopened);
        let _ = std::fs::remove_file(&image);
    }

    #[test]
    fn flush_commits_written_handles_only() {
        let (fs, shared) = seeded_rw();
        let (entry, open) = fs.create(ROOT_INODE, b"a.txt", 0o644, 0, 0).unwrap();
        fs.write(entry.nodeid, open.fh, 0, b"hello").unwrap();

        let reader = fs.open(entry.nodeid, 0).unwrap().fh;
        let before = committed_tx(&shared);
        fs.flush(entry.nodeid, reader).unwrap();
        assert_eq!(committed_tx(&shared), before, "read-only close is free");

        fs.flush(entry.nodeid, open.fh).unwrap();
        assert!(committed_tx(&shared) > before, "written close commits");

        let settled = committed_tx(&shared);
        fs.flush(entry.nodeid, open.fh).unwrap();
        assert_eq!(committed_tx(&shared), settled);
        fs.release(entry.nodeid, open.fh);
        fs.release(entry.nodeid, reader);
    }

    #[test]
    fn debounce_commits_after_quiet() {
        let (fs, shared) = seeded_rw();
        let before = committed_tx(&shared);
        let (entry, open) = fs.create(ROOT_INODE, b"lazy.txt", 0o644, 0, 0).unwrap();
        fs.write(entry.nodeid, open.fh, 0, b"never synced").unwrap();

        let deadline = Instant::now() + Duration::from_secs(10);
        while committed_tx(&shared) == before {
            assert!(
                Instant::now() < deadline,
                "debounce did not commit within 10 s"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        let settled = committed_tx(&shared);
        std::thread::sleep(DEBOUNCE_QUIET * 3);
        assert_eq!(committed_tx(&shared), settled, "clean pool stays quiet");
    }

    #[test]
    fn shutdown_commits_stragglers() {
        let (fs, shared) = seeded_rw();
        let (entry, open) = fs.create(ROOT_INODE, b"last.txt", 0o600, 0, 0).unwrap();
        fs.write(entry.nodeid, open.fh, 0, b"going down").unwrap();
        let before = committed_tx(&shared);
        fs.shutdown().unwrap();
        assert!(committed_tx(&shared) > before, "unmount commits");
        let pool = shared.read().unwrap();
        let found = pool.lookup(ROOT_INODE, "last.txt").unwrap();
        assert_eq!(pool.read(found.inode, 0, 100).unwrap(), b"going down");
    }

    #[test]
    fn directory_mutations_translate() {
        let (fs, _) = seeded_rw();
        let dir = fs.mkdir(ROOT_INODE, b"nest", 0o755, 0, 0).unwrap();
        assert_eq!(dir.attr.mode & 0o170000, 0o040000);
        let (file, kid_open) = fs.create(dir.nodeid, b"kid.txt", 0o644, 0, 0).unwrap();
        fs.release(file.nodeid, kid_open.fh);

        assert_eq!(
            fs.rmdir(ROOT_INODE, b"nest").unwrap_err(),
            errno::ENOTEMPTY,
            "occupied directories stay"
        );
        assert_eq!(
            fs.unlink(ROOT_INODE, b"nest").unwrap_err(),
            errno::EISDIR,
            "unlink refuses directories"
        );
        assert_eq!(
            fs.rmdir(dir.nodeid, b"kid.txt").unwrap_err(),
            errno::ENOTDIR,
            "rmdir refuses files"
        );
        fs.unlink(dir.nodeid, b"kid.txt").unwrap();
        assert_eq!(fs.lookup(dir.nodeid, b"kid.txt"), Err(errno::ENOENT));
        assert_eq!(fs.getattr(file.nodeid), Err(errno::ENOENT), "data freed");
        fs.rmdir(ROOT_INODE, b"nest").unwrap();
        assert_eq!(fs.lookup(ROOT_INODE, b"nest"), Err(errno::ENOENT));
        fs.mkdir(ROOT_INODE, b"nest", 0o755, 0, 0).unwrap();
    }

    #[test]
    fn rename_follows_posix_replacement() {
        let (fs, _) = seeded_rw();
        let (a, a_open) = fs.create(ROOT_INODE, b"a.txt", 0o644, 0, 0).unwrap();
        fs.write(a.nodeid, a_open.fh, 0, b"contents of a").unwrap();
        fs.release(a.nodeid, a_open.fh);
        let (b, b_open) = fs.create(ROOT_INODE, b"b.txt", 0o644, 0, 0).unwrap();
        fs.release(b.nodeid, b_open.fh);
        let dir = fs.mkdir(ROOT_INODE, b"dir", 0o755, 0, 0).unwrap();
        let empty = fs.mkdir(ROOT_INODE, b"empty", 0o755, 0, 0).unwrap();

        fs.rename(ROOT_INODE, b"b.txt", dir.nodeid, b"b.txt", true)
            .unwrap();
        assert_eq!(fs.lookup(dir.nodeid, b"b.txt").unwrap().nodeid, b.nodeid);

        assert_eq!(
            fs.rename(dir.nodeid, b"b.txt", ROOT_INODE, b"a.txt", false)
                .unwrap_err(),
            errno::EEXIST
        );
        fs.rename(dir.nodeid, b"b.txt", ROOT_INODE, b"a.txt", true)
            .unwrap();
        assert_eq!(fs.lookup(ROOT_INODE, b"a.txt").unwrap().nodeid, b.nodeid);
        assert_eq!(fs.getattr(a.nodeid), Err(errno::ENOENT));

        assert_eq!(
            fs.rename(ROOT_INODE, b"a.txt", ROOT_INODE, b"dir", true)
                .unwrap_err(),
            errno::EISDIR
        );
        assert_eq!(
            fs.rename(ROOT_INODE, b"dir", ROOT_INODE, b"a.txt", true)
                .unwrap_err(),
            errno::ENOTDIR
        );
        let (_, _) = fs.create(dir.nodeid, b"inner.txt", 0o644, 0, 0).unwrap();
        assert_eq!(
            fs.rename(ROOT_INODE, b"empty", ROOT_INODE, b"dir", true)
                .unwrap_err(),
            errno::ENOTEMPTY,
            "a full directory is not replaced"
        );
        fs.unlink(dir.nodeid, b"inner.txt").unwrap();
        fs.rename(ROOT_INODE, b"empty", ROOT_INODE, b"dir", true)
            .unwrap();
        assert_eq!(fs.lookup(ROOT_INODE, b"dir").unwrap().nodeid, empty.nodeid);
        assert_eq!(fs.lookup(ROOT_INODE, b"empty"), Err(errno::ENOENT));

        fs.rename(ROOT_INODE, b"a.txt", ROOT_INODE, b"A.TXT", false)
            .unwrap();
        let entries = fs.readdir(ROOT_INODE, 0, 4096).unwrap();
        assert!(dirent_names(&entries).contains(&"A.TXT".to_string()));

        assert_eq!(
            fs.rename(ROOT_INODE, b"ghost", ROOT_INODE, b"x", true)
                .unwrap_err(),
            errno::ENOENT
        );
    }

    #[test]
    fn setattr_translates_each_field() {
        let (fs, _) = seeded_rw();
        let (entry, open) = fs.create(ROOT_INODE, b"attrs.bin", 0o644, 0, 0).unwrap();
        let inode = entry.nodeid;
        fs.write(inode, open.fh, 0, &[7u8; 9000]).unwrap();

        let mut change = plain_setattr(setattr_flags::MODE);
        change.mode = 0o100_0755;
        let out = fs.setattr(inode, &change).unwrap();
        assert_eq!(out.attr.mode & 0o170000, 0o100000, "still a file");
        assert_eq!(out.attr.mode & 0o7777, 0o755);

        let mut change = plain_setattr(setattr_flags::UID | setattr_flags::GID);
        change.uid = 1000;
        change.gid = 100;
        let out = fs.setattr(inode, &change).unwrap();
        assert_eq!((out.attr.uid, out.attr.gid), (1000, 100));

        let mut change = plain_setattr(setattr_flags::ATIME | setattr_flags::MTIME);
        change.atime = 1_600_000_000;
        change.atime_nsec = 11;
        change.mtime = 1_600_000_001;
        change.mtime_nsec = 22;
        let out = fs.setattr(inode, &change).unwrap();
        assert_eq!(out.attr.atime, 1_600_000_000);
        assert_eq!(out.attr.atime_nsec, 11);
        assert_eq!(out.attr.mtime, 1_600_000_001);
        assert_eq!(out.attr.mtime_nsec, 22);
        assert!(
            out.attr.ctime >= (NOW / 1_000_000_000) as u64,
            "setattr advances ctime"
        );

        let out = fs
            .setattr(
                inode,
                &plain_setattr(
                    setattr_flags::ATIME
                        | setattr_flags::ATIME_NOW
                        | setattr_flags::MTIME
                        | setattr_flags::MTIME_NOW,
                ),
            )
            .unwrap();
        assert!(out.attr.mtime > 1_600_000_001);

        let mut change = plain_setattr(setattr_flags::SIZE);
        change.size = 5000;
        assert_eq!(fs.setattr(inode, &change).unwrap().attr.size, 5000);
        let mut change = plain_setattr(setattr_flags::SIZE);
        change.size = 7000;
        assert_eq!(fs.setattr(inode, &change).unwrap().attr.size, 7000);
        let bytes = fs.read(inode, open.fh, 0, 10_000).unwrap();
        assert_eq!(bytes.len(), 7000);
        assert!(bytes[..5000].iter().all(|&b| b == 7));
        assert!(bytes[5000..].iter().all(|&b| b == 0));

        let dir = fs.mkdir(ROOT_INODE, b"d", 0o755, 0, 0).unwrap();
        let mut change = plain_setattr(setattr_flags::SIZE);
        change.size = 0;
        assert_eq!(fs.setattr(dir.nodeid, &change).unwrap_err(), errno::EISDIR);
        let mut change = plain_setattr(setattr_flags::MODE);
        change.mode = 0o700;
        assert_eq!(
            fs.setattr(dir.nodeid, &change).unwrap().attr.mode & 0o7777,
            0o700
        );
    }

    #[test]
    fn unlink_while_open_defers_the_free() {
        let (fs, shared) = seeded_rw();
        let (entry, open) = fs.create(ROOT_INODE, b"temp.bin", 0o600, 0, 0).unwrap();
        fs.write(entry.nodeid, open.fh, 0, b"still here").unwrap();
        fs.unlink(ROOT_INODE, b"temp.bin").unwrap();

        assert_eq!(fs.lookup(ROOT_INODE, b"temp.bin"), Err(errno::ENOENT));
        assert_eq!(
            fs.read(entry.nodeid, open.fh, 0, 100).unwrap(),
            b"still here"
        );
        assert_eq!(fs.getattr(entry.nodeid).unwrap().attr.nlink, 0);
        assert_eq!(
            fs.lookup(ROOT_INODE, ORPHANAGE.as_bytes()),
            Err(errno::ENOENT),
            "the orphanage is invisible"
        );
        let names = dirent_names(&fs.readdir(ROOT_INODE, 0, 4096).unwrap());
        assert!(!names.contains(&ORPHANAGE.to_string()), "{names:?}");
        assert_eq!(
            fs.mkdir(ROOT_INODE, ORPHANAGE.as_bytes(), 0o755, 0, 0)
                .unwrap_err(),
            errno::EPERM,
            "and cannot be claimed"
        );

        let second = fs.open(entry.nodeid, 0).unwrap().fh;
        fs.release(entry.nodeid, open.fh);
        assert_eq!(
            fs.read(entry.nodeid, second, 0, 100).unwrap(),
            b"still here"
        );
        fs.release(entry.nodeid, second);
        assert_eq!(fs.getattr(entry.nodeid), Err(errno::ENOENT));
        fs.shutdown().unwrap();
        drop(fs);
        let pool = shared.read().unwrap();
        assert!(pool.lookup(ROOT_INODE, ORPHANAGE).is_err());
    }

    #[test]
    fn rename_over_open_target_defers() {
        let (fs, _) = seeded_rw();
        let (victim, victim_open) = fs.create(ROOT_INODE, b"old.txt", 0o644, 0, 0).unwrap();
        fs.write(victim.nodeid, victim_open.fh, 0, b"victim bytes")
            .unwrap();
        fs.create(ROOT_INODE, b"new.txt", 0o644, 0, 0).unwrap();
        fs.rename(ROOT_INODE, b"new.txt", ROOT_INODE, b"old.txt", true)
            .unwrap();
        assert_eq!(
            fs.read(victim.nodeid, victim_open.fh, 0, 100).unwrap(),
            b"victim bytes",
            "the replaced object answers its open handle"
        );
        fs.release(victim.nodeid, victim_open.fh);
        assert_eq!(fs.getattr(victim.nodeid), Err(errno::ENOENT));
    }

    #[test]
    fn rmdir_of_open_directory_leaves_a_husk() {
        let (fs, _) = seeded_rw();
        let dir = fs.mkdir(ROOT_INODE, b"watched", 0o755, 0, 0).unwrap();
        let dh = fs.open(dir.nodeid, 0).unwrap().fh;
        let (_, kid_open) = fs.create(dir.nodeid, b"kid", 0o644, 0, 0).unwrap();
        fs.release(0, kid_open.fh);
        assert_eq!(
            fs.rmdir(ROOT_INODE, b"watched").unwrap_err(),
            errno::ENOTEMPTY,
            "open or not, a full directory stays"
        );
        fs.unlink(dir.nodeid, b"kid").unwrap();
        fs.rmdir(ROOT_INODE, b"watched").unwrap();
        assert_eq!(fs.lookup(ROOT_INODE, b"watched"), Err(errno::ENOENT));
        let names = dirent_names(&fs.readdir(dir.nodeid, 0, 4096).unwrap());
        assert_eq!(names, vec![".", ".."], "an empty husk");
        fs.release(dir.nodeid, dh);
        assert_eq!(fs.getattr(dir.nodeid), Err(errno::ENOENT));
    }

    #[test]
    fn dropped_filesystem_releases_shared_handles() {
        let mut pool = test_pool();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let core = Arc::new(crate::mountcore::MountCore::read_write(Arc::new(
            RwLock::new(pool),
        )));
        let fs = PoolFilesystem::over(Arc::clone(&core));

        let (entry, _open) = fs.create(ROOT_INODE, b"held.bin", 0o644, 0, 0).unwrap();
        core.retain(entry.nodeid);
        core.unlink(ROOT_INODE, "held.bin").unwrap();
        assert!(core.getattr(entry.nodeid).is_ok(), "parked while open");

        drop(fs);
        assert!(
            core.getattr(entry.nodeid).is_ok(),
            "a surface drop must not free what another surface holds"
        );
        core.release(entry.nodeid);
        assert!(
            core.getattr(entry.nodeid).is_err(),
            "the dropped filesystem leaked its handle into the shared core"
        );
    }

    #[test]
    fn intermediate_surface_teardown_never_sweeps() {
        let mut pool = test_pool();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let shared = Arc::new(RwLock::new(pool));
        let core = Arc::new(crate::mountcore::MountCore::read_write(Arc::clone(&shared)));

        let file = core.create(ROOT_INODE, "kept.bin", 0o600, 0, 0).unwrap();
        core.retain(file.inode);
        core.unlink(ROOT_INODE, "kept.bin").unwrap();

        let clone = Arc::clone(&core);
        drop(clone);
        assert!(core.getattr(file.inode).is_ok(), "an Arc drop swept");

        let fs = PoolFilesystem::over(Arc::clone(&core));
        fs.shutdown().unwrap();
        drop(fs);
        assert!(
            core.getattr(file.inode).is_ok(),
            "a surface shutdown swept the shared orphanage"
        );

        core.release(file.inode);
        assert!(core.getattr(file.inode).is_err());
        drop(core);
        assert!(
            shared
                .read()
                .unwrap()
                .lookup(ROOT_INODE, ORPHANAGE)
                .is_err(),
            "the final drop sweeps"
        );
    }

    #[test]
    fn read_only_surface_over_a_shared_core() {
        let mut pool = test_pool();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let core = Arc::new(crate::mountcore::MountCore::read_write(Arc::new(
            RwLock::new(pool),
        )));
        let rw = PoolFilesystem::over(Arc::clone(&core));
        let ro = PoolFilesystem::over_read_only(Arc::clone(&core));

        let (entry, rw_open) = rw.create(ROOT_INODE, b"shared.txt", 0o644, 0, 0).unwrap();
        rw.write(entry.nodeid, rw_open.fh, 0, b"visible").unwrap();
        rw.release(entry.nodeid, rw_open.fh);
        let ro_open = ro.open(entry.nodeid, 0).unwrap();
        assert_eq!(
            ro.read(entry.nodeid, ro_open.fh, 0, 16).unwrap(),
            b"visible"
        );

        assert_eq!(
            ro.create(ROOT_INODE, b"nope", 0o644, 0, 0).unwrap_err(),
            errno::EROFS
        );
        assert_eq!(
            ro.mkdir(ROOT_INODE, b"nope", 0o755, 0, 0).unwrap_err(),
            errno::EROFS
        );
        assert_eq!(
            ro.write(entry.nodeid, ro_open.fh, 0, b"x").unwrap_err(),
            errno::EROFS
        );
        assert_eq!(
            ro.unlink(ROOT_INODE, b"shared.txt").unwrap_err(),
            errno::EROFS
        );
        assert_eq!(ro.rmdir(ROOT_INODE, b"docs").unwrap_err(), errno::EROFS);
        assert_eq!(
            ro.rename(ROOT_INODE, b"shared.txt", ROOT_INODE, b"moved", true)
                .unwrap_err(),
            errno::EROFS
        );
        assert_eq!(
            ro.setattr(entry.nodeid, &plain_setattr(setattr_flags::MODE))
                .unwrap_err(),
            errno::EROFS
        );
        assert_eq!(
            ro.symlink(ROOT_INODE, b"ln", b"t", 0, 0).unwrap_err(),
            errno::EROFS
        );
        assert_eq!(
            ro.mknod(ROOT_INODE, b"p", 0o010644, 0, 0, 0).unwrap_err(),
            errno::EROFS
        );

        rw.unlink(ROOT_INODE, b"shared.txt").unwrap();
        assert_eq!(ro.lookup(ROOT_INODE, b"shared.txt"), Err(errno::ENOENT));
        assert_eq!(
            ro.read(entry.nodeid, ro_open.fh, 0, 16).unwrap(),
            b"visible",
            "the read-only holder kept the object alive"
        );
        ro.release(entry.nodeid, ro_open.fh);
        assert_eq!(
            ro.getattr(entry.nodeid),
            Err(errno::ENOENT),
            "the read-only surface's release reaped the deferred object"
        );
    }

    #[test]
    fn stranded_orphans_are_swept_at_mount() {
        let mut pool = test_pool();
        let orphanage = pool.mkdir(ROOT_INODE, ORPHANAGE, 0o700, NOW).unwrap();
        pool.create_file(orphanage, "o-99", 0o600, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let shared = Arc::new(RwLock::new(pool));
        let fs = PoolFilesystem::read_write(Arc::clone(&shared));
        assert!(
            shared
                .read()
                .unwrap()
                .lookup(ROOT_INODE, ORPHANAGE)
                .is_err(),
            "the stranded orphanage is gone"
        );
        fs.shutdown().unwrap();
    }

    #[test]
    fn creations_belong_to_the_caller() {
        let (fs, _) = seeded_rw();
        let (file, _) = fs
            .create(ROOT_INODE, b"mine.txt", 0o644, 1000, 100)
            .unwrap();
        assert_eq!((file.attr.uid, file.attr.gid), (1000, 100));
        let dir = fs.mkdir(ROOT_INODE, b"mine", 0o755, 1000, 100).unwrap();
        assert_eq!((dir.attr.uid, dir.attr.gid), (1000, 100));

        let mut change = plain_setattr(setattr_flags::MODE | setattr_flags::GID);
        change.mode = 0o2775;
        change.gid = 555;
        fs.setattr(dir.nodeid, &change).unwrap();
        let (kid, _) = fs.create(dir.nodeid, b"kid.txt", 0o644, 1000, 100).unwrap();
        assert_eq!((kid.attr.uid, kid.attr.gid), (1000, 555));
        assert_eq!(kid.attr.mode & 0o2000, 0, "files do not take the bit");
        let subdir = fs.mkdir(dir.nodeid, b"sub", 0o755, 1000, 100).unwrap();
        assert_eq!((subdir.attr.uid, subdir.attr.gid), (1000, 555));
        assert_eq!(subdir.attr.mode & 0o2000, 0o2000, "directories do");
    }

    #[test]
    fn overlong_names_answer_enametoolong() {
        let (fs, _) = seeded_rw();
        let long = vec![b'x'; MAX_NAME_LEN + 1];
        assert_eq!(fs.lookup(ROOT_INODE, &long), Err(errno::ENAMETOOLONG));
        assert_eq!(
            fs.mkdir(ROOT_INODE, &long, 0o755, 0, 0).unwrap_err(),
            errno::ENAMETOOLONG
        );
        assert_eq!(
            fs.create(ROOT_INODE, &long, 0o644, 0, 0).unwrap_err(),
            errno::ENAMETOOLONG
        );
        assert_eq!(
            fs.unlink(ROOT_INODE, &long).unwrap_err(),
            errno::ENAMETOOLONG
        );
        assert_eq!(
            fs.rmdir(ROOT_INODE, &long).unwrap_err(),
            errno::ENAMETOOLONG
        );
        fs.create(ROOT_INODE, b"src.txt", 0o644, 0, 0).unwrap();
        assert_eq!(
            fs.rename(ROOT_INODE, b"src.txt", ROOT_INODE, &long, true)
                .unwrap_err(),
            errno::ENAMETOOLONG
        );
        assert_eq!(
            fs.rename(ROOT_INODE, &long, ROOT_INODE, b"dst.txt", true)
                .unwrap_err(),
            errno::ENAMETOOLONG
        );
        let edge = vec![b'y'; MAX_NAME_LEN];
        assert!(fs.create(ROOT_INODE, &edge, 0o644, 0, 0).is_ok());
        assert_eq!(
            fs.create(ROOT_INODE, b"a/b", 0o644, 0, 0).unwrap_err(),
            errno::EINVAL
        );
    }

    #[test]
    fn non_utf8_names_are_rejected_at_the_gateway() {
        let (fs, _shared) = seeded_rw();
        let bad: &[u8] = &[0xFF, 0xFE];

        assert_eq!(
            fs.create(ROOT_INODE, bad, 0o644, 0, 0).unwrap_err(),
            errno::EINVAL
        );
        assert_eq!(
            fs.symlink(ROOT_INODE, bad, b"target", 0, 0).unwrap_err(),
            errno::EINVAL
        );
        fs.create(ROOT_INODE, b"real.txt", 0o644, 0, 0).unwrap();
        assert_eq!(
            fs.rename(ROOT_INODE, b"real.txt", ROOT_INODE, bad, true)
                .unwrap_err(),
            errno::EINVAL,
            "rename target"
        );

        assert_eq!(fs.lookup(ROOT_INODE, bad).unwrap_err(), errno::ENOENT);
        assert_eq!(fs.unlink(ROOT_INODE, bad).unwrap_err(), errno::ENOENT);
        assert_eq!(fs.rmdir(ROOT_INODE, bad).unwrap_err(), errno::ENOENT);
        assert_eq!(
            fs.rename(ROOT_INODE, bad, ROOT_INODE, b"dst.txt", true)
                .unwrap_err(),
            errno::ENOENT,
            "rename source"
        );
    }

    #[test]
    fn times_join_and_split_at_the_edges() {
        assert_eq!(join_time(100, 5), 100_000_000_005);
        let minus_one_second = (-1i64) as u64;
        assert_eq!(join_time(minus_one_second, 0), -1_000_000_000);
        assert_eq!(split_time(-5), (0, 0), "the wire clamps pre-1970");
        assert_eq!(split_time(1_500_000_000_000_000_007), (1_500_000_000, 7));
        assert_eq!(join_time(u64::MAX / 2, 0), i64::MAX, "saturates, not wraps");
    }

    fn parse_dirents(bytes: &[u8]) -> Vec<(String, u64)> {
        let mut out = Vec::new();
        let mut at = 0usize;
        while at + 24 <= bytes.len() {
            let next = u64::from_le_bytes(bytes[at + 8..at + 16].try_into().unwrap());
            let namelen = u32::from_le_bytes(bytes[at + 16..at + 20].try_into().unwrap()) as usize;
            let name = String::from_utf8(bytes[at + 24..at + 24 + namelen].to_vec()).unwrap();
            out.push((name, next));
            at += (24 + namelen).div_ceil(8) * 8;
        }
        out
    }

    fn dirent_names(bytes: &[u8]) -> Vec<String> {
        parse_dirents(bytes)
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    }

    #[test]
    fn symlinks_and_special_files_serve_through_the_surface() {
        let (fs, shared) = seeded_rw();

        let entry = fs
            .symlink(ROOT_INODE, b"ln", b"docs/notes.txt", 1000, 100)
            .unwrap();
        assert_eq!(entry.attr.mode & 0o170000, 0o120000, "S_IFLNK");
        assert_eq!(entry.attr.size, 14, "st_size is the target length");
        assert_eq!((entry.attr.uid, entry.attr.gid), (1000, 100));
        assert_eq!(fs.readlink(entry.nodeid).unwrap(), b"docs/notes.txt");

        assert_eq!(fs.readlink(ROOT_INODE), Err(errno::EINVAL));
        assert_eq!(fs.readlink(999_999), Err(errno::ENOENT));

        let fifo = fs
            .mknod(ROOT_INODE, b"pipe", 0o010600, 0, 1000, 100)
            .unwrap();
        assert_eq!(fifo.attr.mode & 0o170000, 0o010000, "S_IFIFO");
        assert_eq!(fifo.attr.rdev, 0);
        let dev = fs
            .mknod(ROOT_INODE, b"null", 0o020666, 0x0103, 1000, 100)
            .unwrap();
        assert_eq!(dev.attr.mode & 0o170000, 0o020000, "S_IFCHR");
        assert_eq!(dev.attr.rdev, 0x0103, "the FUSE dev_t round-trips");
        assert_eq!(fs.getattr(dev.nodeid).unwrap().attr.rdev, 0x0103);
        assert_eq!(
            shared.read().unwrap().device_rdev(dev.nodeid).unwrap(),
            1 | (3u64 << 32),
            "stored major=1, minor=3 per docs/format.md"
        );

        let listing = fs.readdir(ROOT_INODE, 0, 4096).unwrap();
        let types: std::collections::BTreeMap<String, u32> = parse_dirents(&listing)
            .iter()
            .map(|(name, _)| name.clone())
            .zip({
                let mut kinds = Vec::new();
                let mut at = 0usize;
                while at + 24 <= listing.len() {
                    let namelen =
                        u32::from_le_bytes(listing[at + 16..at + 20].try_into().unwrap()) as usize;
                    kinds.push(u32::from_le_bytes(
                        listing[at + 20..at + 24].try_into().unwrap(),
                    ));
                    at += (24 + namelen).div_ceil(8) * 8;
                }
                kinds
            })
            .collect();
        assert_eq!(types["ln"], dirent_type::SYMLINK);
        assert_eq!(types["pipe"], dirent_type::FIFO);
        assert_eq!(types["null"], dirent_type::CHAR_DEVICE);

        let before = committed_tx(&shared);
        fs.fsync(ROOT_INODE, 0, false).unwrap();
        assert_eq!(committed_tx(&shared), before + 1);
        fs.unlink(ROOT_INODE, b"ln").unwrap();
        fs.unlink(ROOT_INODE, b"pipe").unwrap();
        assert_eq!(fs.lookup(ROOT_INODE, b"ln"), Err(errno::ENOENT));

        let (ro, _, _, _) = seeded();
        assert_eq!(ro.symlink(ROOT_INODE, b"ln", b"t", 0, 0), Err(errno::EROFS));
        assert_eq!(
            ro.mknod(ROOT_INODE, b"p", 0o010644, 0, 0, 0),
            Err(errno::EROFS)
        );
    }
}
