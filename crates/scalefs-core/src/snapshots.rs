use crate::device::BlockDevice;
use crate::dirent;
use crate::error::{Result, ScaleFsError};
use crate::fs::{getattr_in, read_in};
use crate::pool::Pool;
use crate::tree::{
    DirEntry, ITEM_RETAINED_ROOT, InodeAttrs, MetadataKey, MetadataTree, MetadataValue, PageRef,
    TreeRef,
};
use crate::zones::AllocPurpose;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotInfo {
    pub id: u64,
    pub name: String,
    pub tx_id: u64,
    pub created_at_ns: i64,
    pub root: PageRef,
}

fn retained_key(id: u64) -> MetadataKey {
    MetadataKey {
        object_id: 0,
        item_type: ITEM_RETAINED_ROOT,
        offset: id,
    }
}

impl<D: BlockDevice> Pool<D> {
    pub fn snapshot_create(&mut self, name: &str, now_ns: i64) -> Result<u64> {
        self.ensure_mutable()?;
        dirent::validate_name(name)?;
        if self.snapshot_list()?.iter().any(|s| s.name == name) {
            return Err(ScaleFsError::AlreadyExists);
        }

        self.commit(AllocPurpose::Normal, now_ns)?;
        let retained = MetadataValue::RetainedRoot {
            tx_id: self.committed_tx(),
            root: self.last_metadata_root.clone(),
            created_at_ns: now_ns,
            name: name.to_string(),
        };
        let id = self.allocate_object_id()?;
        self.tree_mut().insert(retained_key(id), retained)?;
        self.commit(AllocPurpose::Normal, now_ns)?;
        Ok(id)
    }

    pub fn snapshot_list(&self) -> Result<Vec<SnapshotInfo>> {
        Ok(self
            .tree()
            .range(retained_key(0), retained_key(u64::MAX))?
            .into_iter()
            .filter_map(|(key, value)| match value {
                MetadataValue::RetainedRoot {
                    tx_id,
                    root,
                    created_at_ns,
                    name,
                } => Some(SnapshotInfo {
                    id: key.offset,
                    name,
                    tx_id,
                    created_at_ns,
                    root,
                }),
                _ => None,
            })
            .collect())
    }

    pub fn snapshot_release(&mut self, name: &str) -> Result<SnapshotInfo> {
        self.ensure_mutable()?;
        let info = self
            .snapshot_list()?
            .into_iter()
            .find(|s| s.name == name)
            .ok_or(ScaleFsError::NotFound)?;
        self.tree_mut().remove(retained_key(info.id))?;
        Ok(info)
    }

    pub fn snapshot_open(&self, name: &str) -> Result<Snapshot<'_, D>> {
        let info = self
            .snapshot_list()?
            .into_iter()
            .find(|s| s.name == name)
            .ok_or(ScaleFsError::NotFound)?;
        let tree = MetadataTree::load(&info.root, self)?;
        Ok(Snapshot {
            pool: self,
            tree,
            info,
        })
    }
}

#[derive(Debug)]
pub struct Snapshot<'p, D: BlockDevice> {
    pool: &'p Pool<D>,
    tree: MetadataTree,
    info: SnapshotInfo,
}

impl<D: BlockDevice> Snapshot<'_, D> {
    pub fn info(&self) -> &SnapshotInfo {
        &self.info
    }

    fn view(&self) -> TreeRef<'_> {
        self.tree.view(self.pool)
    }

    pub fn getattr(&self, object_id: u64) -> Result<InodeAttrs> {
        getattr_in(self.view(), object_id)
    }

    pub fn lookup(&self, parent: u64, name: &str) -> Result<DirEntry> {
        if !getattr_in(self.view(), parent)?.is_dir() {
            return Err(ScaleFsError::NotDirectory);
        }
        let (seed, version, case) = self.pool.naming();
        dirent::lookup_entry(self.view(), seed, version, case, parent, name)?
            .ok_or(ScaleFsError::NotFound)
    }

    pub fn readdir(&self, dir: u64) -> Result<Vec<DirEntry>> {
        if !getattr_in(self.view(), dir)?.is_dir() {
            return Err(ScaleFsError::NotDirectory);
        }
        dirent::list_entries(self.view(), dir)
    }

    pub fn read(&self, object_id: u64, offset: u64, len: usize) -> Result<Vec<u8>> {
        read_in(self.pool, self.view(), object_id, offset, len)
    }

    pub fn item_count(&self) -> Result<usize> {
        self.view().item_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::MemoryBlockDevice;
    use crate::layout::{CaseSensitivity, DeviceId, Geometry, PoolId};
    use crate::pool::CreateParams;
    use crate::tree::ROOT_INODE;

    const NOW: i64 = 1_700_000_000_000_000_000;

    fn new_pool() -> Pool<MemoryBlockDevice> {
        let geometry = Geometry {
            logical_block_size: 4096,
            physical_block_size: 4096,
            zone_size: 65536,
            zone_count: 16,
            erase_granularity_zones: 1,
            sequential_write_required: true,
        };
        Pool::create(
            MemoryBlockDevice::new(crate::gpt::member_image_len(geometry.capacity_bytes()) as usize),
            CreateParams {
                pool_id: PoolId([0x11; 16]),
                device_id: DeviceId([0x22; 16]),
                geometry,
                case_sensitivity: CaseSensitivity::InsensitivePreserving,
                dirent_hash_seed: 7,
                label: "tank".to_string(),
                created_at_ns: NOW,
            },
        )
        .unwrap()
    }

    #[test]
    fn snapshots_preserve_contents_while_the_pool_moves_on() {
        let mut pool = new_pool();
        let keep = pool
            .create_file(ROOT_INODE, "keep.txt", 0o644, NOW)
            .unwrap();
        pool.write(keep, 0, b"original contents", NOW).unwrap();
        let doomed = pool
            .create_file(ROOT_INODE, "doomed.txt", 0o644, NOW)
            .unwrap();
        pool.write(doomed, 0, b"short lived", NOW).unwrap();

        let id = pool.snapshot_create("before", NOW).unwrap();
        assert!(id >= 2);

        pool.write(keep, 0, b"REWRITTEN CONTENTS!!", NOW).unwrap();
        pool.truncate(keep, 20, NOW).unwrap();
        pool.unlink(ROOT_INODE, "doomed.txt", NOW).unwrap();
        pool.create_file(ROOT_INODE, "new.txt", 0o644, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        assert_eq!(pool.read(keep, 0, 64).unwrap(), b"REWRITTEN CONTENTS!!");
        assert!(pool.lookup(ROOT_INODE, "doomed.txt").is_err());

        let snap = pool.snapshot_open("before").unwrap();
        assert_eq!(snap.info().name, "before");
        assert_eq!(snap.read(keep, 0, 64).unwrap(), b"original contents");
        let entry = snap.lookup(ROOT_INODE, "doomed.txt").unwrap();
        assert_eq!(snap.read(entry.inode, 0, 64).unwrap(), b"short lived");
        let names: Vec<String> = snap
            .readdir(ROOT_INODE)
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, ["doomed.txt", "keep.txt"]);
        assert!(snap.lookup(ROOT_INODE, "new.txt").is_err());
    }

    #[test]
    fn snapshot_names_are_unique_and_releasable() {
        let mut pool = new_pool();
        pool.snapshot_create("s1", NOW).unwrap();
        assert!(matches!(
            pool.snapshot_create("s1", NOW),
            Err(ScaleFsError::AlreadyExists)
        ));
        pool.snapshot_create("s2", NOW + 1).unwrap();

        let names: Vec<String> = pool
            .snapshot_list()
            .unwrap()
            .into_iter()
            .map(|s| s.name)
            .collect();
        assert_eq!(names, ["s1", "s2"]);

        let released = pool.snapshot_release("s1").unwrap();
        assert_eq!(released.name, "s1");
        pool.commit(AllocPurpose::Reclaim, NOW).unwrap();
        assert_eq!(pool.snapshot_list().unwrap().len(), 1);
        assert!(matches!(
            pool.snapshot_open("s1"),
            Err(ScaleFsError::NotFound)
        ));
        assert!(matches!(
            pool.snapshot_release("s1"),
            Err(ScaleFsError::NotFound)
        ));
    }

    #[test]
    fn snapshots_survive_reopen() {
        let mut pool = new_pool();
        let file = pool.create_file(ROOT_INODE, "f", 0o644, NOW).unwrap();
        pool.write(file, 0, b"snapshotted", NOW).unwrap();
        pool.snapshot_create("persisted", NOW).unwrap();
        pool.write(file, 0, b"newer bytes", NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        let pool = Pool::open(pool.into_device()).unwrap();
        let list = pool.snapshot_list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "persisted");
        let snap = pool.snapshot_open("persisted").unwrap();
        assert_eq!(snap.read(file, 0, 64).unwrap(), b"snapshotted");
        assert_eq!(pool.read(file, 0, 64).unwrap(), b"newer bytes");
    }

    #[test]
    fn snapshot_ids_share_the_object_id_space() {
        let mut pool = new_pool();
        let file = pool.create_file(ROOT_INODE, "f", 0o644, NOW).unwrap();
        let snap_id = pool.snapshot_create("s", NOW).unwrap();
        let later_file = pool.create_file(ROOT_INODE, "g", 0o644, NOW).unwrap();
        assert!(file < snap_id);
        assert!(snap_id < later_file);
    }

    #[test]
    fn invalid_snapshot_names_are_rejected() {
        let mut pool = new_pool();
        for bad in ["", ".", "..", "a/b"] {
            assert!(pool.snapshot_create(bad, NOW).is_err(), "{bad:?}");
        }
    }
}
