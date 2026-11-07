use crate::fuse::fs::Filesystem;
use crate::mountcore::{MountCore, MountError, ORPHANAGE};
use crate::poolfs::PoolFilesystem;
use scalefs_core::{
    AllocPurpose, CaseSensitivity, CreateParams, DeviceId, Geometry, ITEM_DIRENT,
    MemoryBlockDevice, MetadataKey, MetadataValue, Pool, PoolId, ROOT_INODE,
};
use std::sync::{Arc, RwLock};

const NOW: i64 = 1_700_000_000_000_000_000;

type TestPool = Pool<Arc<MemoryBlockDevice>>;

fn pool() -> TestPool {
    let geometry = Geometry {
        logical_block_size: 4096,
        physical_block_size: 4096,
        zone_size: 64 * 1024,
        zone_count: 64,
        erase_granularity_zones: 1,
        sequential_write_required: false,
    };
    let mut pool = Pool::create(
        Arc::new(MemoryBlockDevice::new(
            scalefs_core::member_image_len(geometry.capacity_bytes()) as usize,
        )),
        CreateParams {
            pool_id: PoolId([0x3C; 16]),
            device_id: DeviceId([0x3D; 16]),
            geometry,
            case_sensitivity: CaseSensitivity::InsensitivePreserving,
            dirent_hash_seed: 0x5EED_0003,
            label: "surface".to_string(),
            created_at_ns: NOW,
        },
    )
    .unwrap();
    pool.commit(AllocPurpose::Normal, NOW).unwrap();
    pool
}

fn bucket_key(pool: &TestPool, dir: u64, name: &str) -> MetadataKey {
    let superblock = pool.superblock();
    let folded = scalefs_core::dirent::fold_name(
        superblock.unicode_version,
        superblock.case_sensitivity,
        name,
    );
    MetadataKey {
        object_id: dir,
        item_type: ITEM_DIRENT,
        offset: scalefs_core::dirent::dirent_hash(superblock.dirent_hash_seed, &folded),
    }
}

fn parse_dirents(bytes: &[u8]) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + 24 <= bytes.len() {
        let next = u64::from_le_bytes(bytes[at + 8..at + 16].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[at + 16..at + 20].try_into().unwrap()) as usize;
        out.push((
            String::from_utf8(bytes[at + 24..at + 24 + len].to_vec()).unwrap(),
            next,
        ));
        at += (24 + len).div_ceil(8) * 8;
    }
    out
}

#[test]
fn fuse_readdir_pages_through_a_bucket_holding_two_names() {
    let mut pool = pool();
    for name in ["alpha", "beta", "gamma"] {
        pool.create_file(ROOT_INODE, name, 0o644, NOW).unwrap();
    }
    let alpha = bucket_key(&pool, ROOT_INODE, "alpha");
    let beta = bucket_key(&pool, ROOT_INODE, "beta");
    let tree = pool.tree_mut();
    let Some(MetadataValue::DirEntries(moved)) = tree.remove(beta).unwrap() else {
        panic!("beta has its own bucket");
    };
    let Some(MetadataValue::DirEntries(mut shared)) = tree.get(alpha).unwrap() else {
        panic!("alpha has its own bucket");
    };
    shared.extend(moved);
    tree.insert(alpha, MetadataValue::DirEntries(shared))
        .unwrap();
    pool.commit(AllocPurpose::Normal, NOW).unwrap();

    let fs = PoolFilesystem::read_only(Arc::new(RwLock::new(pool)));
    let mut names = Vec::new();
    let mut offset = 0u64;
    loop {
        let page = parse_dirents(&fs.readdir(ROOT_INODE, offset, 32).unwrap());
        let Some((_, next)) = page.last() else {
            break;
        };
        offset = *next;
        names.extend(page.into_iter().map(|(name, _)| name));
        assert!(names.len() <= 16, "the listing never ends: {names:?}");
    }
    names.sort();
    assert_eq!(names, [".", "..", "alpha", "beta", "gamma"]);
}

#[test]
fn renaming_one_hard_link_onto_another_of_the_same_file_succeeds() {
    let core = MountCore::read_write(Arc::new(RwLock::new(pool())));
    let file = core.create(ROOT_INODE, "a", 0o644, 0, 0).unwrap();
    core.link(file.inode, ROOT_INODE, "b").unwrap();
    let renamed = core.rename(ROOT_INODE, "a", ROOT_INODE, "b", true);
    assert!(
        renamed.is_ok(),
        "rename between links of one file: {renamed:?}"
    );
    assert_eq!(core.lookup(ROOT_INODE, "a").unwrap().inode, file.inode);
    assert_eq!(core.lookup(ROOT_INODE, "b").unwrap().inode, file.inode);
}

#[test]
fn the_orphanage_stays_hidden_under_every_spelling_that_folds_to_it() {
    let shared = Arc::new(RwLock::new(pool()));
    let core = MountCore::read_write(Arc::clone(&shared));
    let file = core
        .create(ROOT_INODE, "held-open.txt", 0o600, 0, 0)
        .unwrap();
    core.retain(file.inode);
    core.unlink(ROOT_INODE, "held-open.txt").unwrap();
    assert!(
        shared.read().unwrap().lookup(ROOT_INODE, ORPHANAGE).is_ok(),
        "setup: the open-unlinked file parks in the orphanage"
    );
    for spelling in [ORPHANAGE, ".SCALEFS-ORPHANS", ".\u{17F}calefs-orphans"] {
        let seen = core.lookup(ROOT_INODE, spelling);
        assert!(
            matches!(seen, Err(MountError::NotFound)),
            "{spelling:?} resolved through the mount: {:?}",
            seen.map(|attr| attr.inode)
        );
    }
    core.release(file.inode);
}

#[cfg(target_os = "linux")]
#[test]
fn a_fuse_mount_lands_on_a_mountpoint_whose_name_is_not_utf8() {
    use std::os::unix::ffi::OsStrExt;
    let base = std::env::temp_dir().join(format!("scalefs-mount-bytes-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let target = base.join(std::ffi::OsStr::from_bytes(b"mnt-\xff"));
    std::fs::create_dir(&target).unwrap();

    let mounted = crate::fuse::device::FuseMount::mount(&target, true);
    if let Err(error) = &mounted
        && error.raw_os_error() == Some(1)
    {
        eprintln!("skipping: mounting needs root ({error})");
        let _ = std::fs::remove_dir_all(&base);
        return;
    }
    let table = std::fs::read("/proc/self/mountinfo").unwrap_or_default();
    let wanted = target.as_os_str().as_bytes();
    let landed = table.windows(wanted.len()).any(|window| window == wanted);
    let error = mounted.as_ref().err().map(ToString::to_string);
    drop(mounted);
    let _ = std::fs::remove_dir_all(&base);
    assert!(
        error.is_none(),
        "mounting at a non-UTF-8 path failed: {error:?}"
    );
    assert!(landed, "the mount did not land on the requested directory");
}
