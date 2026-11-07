use super::*;
use crate::device::{FileBlockDevice, MemoryBlockDevice, SharedDevice};
use crate::format::{Expect, decode_record};
use crate::tree::{ITEM_FILE_EXTENT, PageRef, decode_internal_record};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};

const SEED: u64 = 0x5EED_FA17_0000_0001;
const NOW: i64 = 1_700_000_000_000_000_000;

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "scalefs-faults-{}-{tag}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the scratch directory");
        Scratch(dir)
    }

    fn image(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn geometry() -> Geometry {
    Geometry {
        logical_block_size: 4096,
        physical_block_size: 4096,
        zone_size: 64 * 1024,
        zone_count: 64,
        erase_granularity_zones: 1,
        sequential_write_required: false,
    }
}

fn image_len() -> u64 {
    crate::gpt::member_image_len(geometry().capacity_bytes())
}

fn mirror_params(mirror_width: u16) -> PoolParams {
    PoolParams {
        pool_id: PoolId([0xFA; 16]),
        case_sensitivity: CaseSensitivity::InsensitivePreserving,
        dirent_hash_seed: SEED,
        label: "faults".to_string(),
        created_at_ns: NOW,
        mirror_width,
        data_width: 1,
        parity_width: 0,
    }
}

fn member<D>(device: D, id: u8) -> MemberSpec<D> {
    MemberSpec {
        device,
        device_id: DeviceId([id; 16]),
        geometry: geometry(),
    }
}

#[derive(Debug)]
struct Pullable {
    image: FileBlockDevice,
    writes_left: AtomicI64,
    pulled: AtomicBool,
}

impl Pullable {
    fn create(path: &Path) -> Arc<Pullable> {
        Arc::new(Pullable {
            image: FileBlockDevice::create(path, image_len()).expect("create a member image"),
            writes_left: AtomicI64::new(-1),
            pulled: AtomicBool::new(false),
        })
    }

    fn pull_after_writes(&self, writes: i64) {
        self.writes_left.store(writes, Ordering::SeqCst);
    }

    fn gone() -> ScaleFsError {
        ScaleFsError::Io(std::io::Error::other("member pulled"))
    }
}

impl BlockDevice for Pullable {
    fn len(&self) -> u64 {
        self.image.len()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if self.pulled.load(Ordering::SeqCst) {
            return Err(Self::gone());
        }
        self.image.read_at(offset, buf)
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
        if self.pulled.load(Ordering::SeqCst) {
            return Err(Self::gone());
        }
        match self.writes_left.load(Ordering::SeqCst) {
            0 => {
                self.pulled.store(true, Ordering::SeqCst);
                return Err(Self::gone());
            }
            left if left > 0 => self.writes_left.store(left - 1, Ordering::SeqCst),
            _ => {}
        }
        self.image.write_at(offset, data)
    }

    fn flush(&self) -> Result<()> {
        if self.pulled.load(Ordering::SeqCst) {
            return Err(Self::gone());
        }
        self.image.flush()
    }
}

fn reopen(path: &Path) -> Arc<FileBlockDevice> {
    Arc::new(FileBlockDevice::open(path).expect("reopen a member image"))
}

fn durability_commit<D: SharedDevice>(pool: &mut Pool<D>) -> Result<CommitOutcome> {
    let ticket = pool.commit_plan(AllocPurpose::Normal, NOW)?;
    match ticket.execute() {
        Ok(done) => Ok(CommitOutcome::Committed {
            tx_id: pool.commit_publish(done),
        }),
        Err(aborted) => pool.commit_abandon(aborted),
    }
}

fn pattern(len: usize, salt: u64) -> Vec<u8> {
    let mut rng = crate::rng::XorShift64::new(0x9E37_79B9_7F4A_7C15 ^ salt);
    (0..len).map(|_| rng.next_u64() as u8).collect()
}

fn write_named(pool: &mut Pool<impl BlockDevice>, name: &str, data: &[u8]) {
    let inode = pool
        .create_file(ROOT_INODE, name, 0o644, NOW)
        .unwrap_or_else(|error| panic!("create {name}: {error:?}"));
    pool.write(inode, 0, data, NOW)
        .unwrap_or_else(|error| panic!("write {name}: {error:?}"));
}

fn read_named(pool: &Pool<impl BlockDevice>, name: &str) -> Result<Vec<u8>> {
    let inode = pool.lookup(ROOT_INODE, name)?.inode;
    let size = pool.getattr(inode)?.size;
    pool.read(
        inode,
        0,
        usize::try_from(size).expect("test files are small"),
    )
}

fn copies_agree(pool: &Pool<impl BlockDevice>, name: &str) -> std::result::Result<usize, String> {
    let inode = pool
        .lookup(ROOT_INODE, name)
        .map_err(|error| format!("{name}: {error:?}"))?
        .inode;
    let runs = pool.tree().range(
        MetadataKey {
            object_id: inode,
            item_type: ITEM_FILE_EXTENT,
            offset: 0,
        },
        MetadataKey {
            object_id: inode,
            item_type: ITEM_FILE_EXTENT,
            offset: u64::MAX,
        },
    );
    let runs = runs.map_err(|error| format!("{name}: {error:?}"))?;
    let mut checked = 0;
    for (key, value) in runs {
        let MetadataValue::FileRun(run) = value else {
            continue;
        };
        for k in 0..run.count() {
            let mut reference: Option<Vec<u8>> = None;
            for copy in run.record_copies(k) {
                let bytes = pool.read_extent(copy).map_err(|error| {
                    format!(
                        "{name} at {}: copy {copy:?} unreadable: {error:?}",
                        key.offset
                    )
                })?;
                run.expect(k).verify(&bytes).map_err(|error| {
                    format!("{name} at {}: copy {copy:?} corrupt: {error:?}", key.offset)
                })?;
                match &reference {
                    None => reference = Some(bytes),
                    Some(sibling) if *sibling != bytes => {
                        return Err(format!(
                            "{name} at {}: copy {copy:?} holds different bytes from its sibling",
                            key.offset
                        ));
                    }
                    Some(_) => {}
                }
                checked += 1;
            }
        }
    }
    Ok(checked)
}

fn tree_pages(pool: &Pool<impl BlockDevice>) -> Vec<PageRef> {
    let mut pages = Vec::new();
    let mut stack = vec![pool.last_metadata_root.clone()];
    while let Some(page) = stack.pop() {
        let bytes = pool
            .read_record(&page.copies, page.expect)
            .expect("read a tree page");
        if let Ok(children) = decode_internal_record(&bytes) {
            stack.extend(children.into_iter().map(|(_, child)| child));
        }
        pages.push(page);
    }
    pages
}

fn reseal_root<D: BlockDevice>(view: &D, root_bytes: &[u8]) {
    let commit_at = reseal_slots_target(view);
    let mut commit_bytes = vec![0u8; commit_at.length as usize];
    view.read_at(commit_at.offset, &mut commit_bytes).unwrap();
    let mut commit = decode_commit(&commit_bytes).unwrap();
    commit.metadata_root.expect = Expect::of(root_bytes);
    reseal_commit(view, &encode_commit(&commit).unwrap());
}

fn reseal_commit<D: BlockDevice>(view: &D, commit_bytes: &[u8]) {
    let commit_at = reseal_slots_target(view);
    view.write_at(commit_at.offset, commit_bytes).unwrap();
    for offset in superblock_slots(view.len()) {
        let mut block = vec![0u8; 4096];
        view.read_at(offset, &mut block).unwrap();
        let Ok(mut superblock) = decode_superblock(&block) else {
            continue;
        };
        let mut reference = superblock.newest_commit.expect("a committed pool");
        reference.expect = Expect::of(commit_bytes);
        superblock.newest_commit = Some(reference);
        let bytes = encode_superblock(&superblock, reference.expect.tx).unwrap();
        view.write_at(offset, &bytes).unwrap();
    }
    view.flush().unwrap();
}

fn reseal_slots_target<D: BlockDevice>(view: &D) -> Extent {
    let mut block = vec![0u8; 4096];
    view.read_at(0, &mut block).unwrap();
    decode_superblock(&block)
        .unwrap()
        .newest_commit
        .expect("a committed pool")
        .extent
}

fn thin_flag_set(pool: &Pool<impl BlockDevice>) -> bool {
    pool.superblocks()
        .iter()
        .any(|superblock| superblock.feature_incompat & FEATURE_INCOMPAT_THIN_METADATA != 0)
}

#[test]
fn a_member_returning_after_a_live_degrade_never_overwrites_acknowledged_data() {
    let scratch = Scratch::new("returning-member");
    let (a_path, x_path) = (scratch.image("a.img"), scratch.image("x.img"));
    let committed = pattern(70_000, 7);
    let acknowledged = pattern(70_000, 13);
    let later = pattern(70_000, 29);

    {
        let a = Pullable::create(&a_path);
        let x = Pullable::create(&x_path);
        let mut pool = Pool::create_multi(
            vec![member(Arc::clone(&a), 0xA0), member(Arc::clone(&x), 0xA1)],
            mirror_params(2),
        )
        .unwrap();
        write_named(&mut pool, "committed.bin", &committed);
        let outcome = durability_commit(&mut pool).unwrap();
        assert!(
            matches!(outcome, CommitOutcome::Committed { .. }),
            "{outcome:?}"
        );

        write_named(&mut pool, "ack.bin", &acknowledged);
        x.pull_after_writes(1);
        let outcome = durability_commit(&mut pool).expect("the commit lands on the survivor");
        assert!(
            matches!(
                outcome,
                CommitOutcome::Degraded(LiveDegrade { member: 1, .. })
            ),
            "the setup needs a live degrade, got {outcome:?}"
        );
    }

    let claimed_whole = {
        let mut pool = Pool::open_multi(vec![reopen(&a_path), reopen(&x_path)]).unwrap();
        assert_eq!(read_named(&pool, "ack.bin").unwrap(), acknowledged);
        let writable = !pool.read_only();
        if writable {
            write_named(&mut pool, "later.bin", &later);
            durability_commit(&mut pool).unwrap();
        }
        for name in ["committed.bin", "ack.bin"] {
            copies_agree(&pool, name).unwrap_or_else(|why| {
                panic!("acknowledged data damaged after the member returned: {why}")
            });
        }
        writable && !pool.is_degraded()
    };

    if claimed_whole {
        let pool = Pool::open_multi_degraded(vec![reopen(&x_path)]).unwrap();
        assert_eq!(
            read_named(&pool, "ack.bin").unwrap(),
            acknowledged,
            "the returning member serves acknowledged data intact"
        );
        assert_eq!(read_named(&pool, "committed.bin").unwrap(), committed);
        assert_eq!(read_named(&pool, "later.bin").unwrap(), later);
    }
}

#[test]
fn metadata_thinned_by_a_live_degrade_is_mirrored_again_before_the_pool_reports_full_width() {
    let scratch = Scratch::new("thin-metadata");
    let (a_path, x_path) = (scratch.image("a.img"), scratch.image("x.img"));
    let names: Vec<String> = (0..300).map(|i| format!("file-{i:04}.txt")).collect();
    let body = |i: usize| format!("contents of file {i}").into_bytes();

    {
        let a = Pullable::create(&a_path);
        let x = Pullable::create(&x_path);
        let mut pool = Pool::create_multi(
            vec![member(Arc::clone(&a), 0xB0), member(Arc::clone(&x), 0xB1)],
            mirror_params(2),
        )
        .unwrap();
        for (i, name) in names.iter().enumerate() {
            write_named(&mut pool, name, &body(i));
        }
        durability_commit(&mut pool).unwrap();
        let pages = tree_pages(&pool);
        assert!(
            pages.len() >= 4,
            "the setup needs a multi-page tree, got {}",
            pages.len()
        );
        assert!(pages.iter().all(|page| page.copies.len() == 2));

        write_named(&mut pool, "ack.txt", b"acknowledged");
        x.pull_after_writes(1);
        let outcome = durability_commit(&mut pool).unwrap();
        assert!(
            matches!(
                outcome,
                CommitOutcome::Degraded(LiveDegrade { member: 1, .. })
            ),
            "the setup needs a live degrade, got {outcome:?}"
        );
        assert!(thin_flag_set(&pool));
    }

    let claimed_full_width = {
        let mut pool = Pool::open_multi(vec![reopen(&a_path), reopen(&x_path)]).unwrap();
        if !pool.read_only() {
            write_named(&mut pool, "after.txt", b"after the member returned");
            durability_commit(&mut pool).unwrap();
        }
        let full_width = !thin_flag_set(&pool) && !pool.is_degraded();
        if full_width {
            let thin: Vec<PageRef> = tree_pages(&pool)
                .into_iter()
                .filter(|page| page.copies.len() < 2)
                .collect();
            assert!(
                thin.is_empty(),
                "the superblocks claim full-width metadata, but {} page(s) still have one copy: {:?}",
                thin.len(),
                &thin[..thin.len().min(4)]
            );
        }
        full_width
    };

    if claimed_full_width {
        let pool = Pool::open_multi_degraded(vec![reopen(&x_path)])
            .expect("the returning member holds a copy of every page");
        for (i, name) in names.iter().enumerate() {
            assert_eq!(read_named(&pool, name).unwrap(), body(i), "{name}");
        }
        assert_eq!(read_named(&pool, "ack.txt").unwrap(), b"acknowledged");
    }
}

#[derive(Debug)]
struct BadSectors {
    image: FileBlockDevice,
    bad: std::ops::Range<u64>,
}

impl BadSectors {
    fn open(path: &Path, bad: std::ops::Range<u64>) -> Arc<BadSectors> {
        Arc::new(BadSectors {
            image: FileBlockDevice::open(path).expect("open a member image"),
            bad,
        })
    }
}

impl BlockDevice for BadSectors {
    fn len(&self) -> u64 {
        self.image.len()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if offset < self.bad.end && offset + buf.len() as u64 > self.bad.start {
            return Err(ScaleFsError::Io(std::io::Error::other(
                "unrecoverable read error",
            )));
        }
        self.image.read_at(offset, buf)
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
        self.image.write_at(offset, data)
    }

    fn flush(&self) -> Result<()> {
        self.image.flush()
    }
}

fn flip_byte(path: &Path, offset: u64) {
    use std::io::{Read, Seek, SeekFrom, Write};
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open the image to damage it");
    let mut byte = [0u8; 1];
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 0xFF;
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(&byte).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn one_damaged_chain_record_never_rolls_a_multi_device_import_back() {
    let mut failures = Vec::new();
    for unreadable in [false, true] {
        let what = if unreadable {
            "an unreadable"
        } else {
            "a corrupt"
        };
        let scratch = Scratch::new("rollback");
        let paths: Vec<PathBuf> = ["a.img", "b.img", "c.img"]
            .iter()
            .map(|name| scratch.image(name))
            .collect();
        let acknowledged = pattern(20_000, 41);
        let (newest_tx, a_commit) = {
            let members = paths
                .iter()
                .enumerate()
                .map(|(i, path)| {
                    let mut geometry = geometry();
                    if i == 2 {
                        geometry.zone_count = 40;
                    }
                    let len = crate::gpt::member_image_len(geometry.capacity_bytes());
                    MemberSpec {
                        device: Arc::new(FileBlockDevice::create(path, len).unwrap()),
                        device_id: DeviceId([0xC0 + i as u8; 16]),
                        geometry,
                    }
                })
                .collect();
            let mut pool = Pool::create_multi(members, mirror_params(2)).unwrap();
            pool.probe_staleness = std::time::Duration::from_secs(3600);
            write_named(&mut pool, "acknowledged.bin", &acknowledged);
            let tx = pool.commit(AllocPurpose::Normal, NOW).unwrap();
            let roster = &pool.last_roster_members;
            assert_eq!(
                (roster[0].newest_tx, roster[1].newest_tx),
                (tx, tx),
                "setup: A and B carry the commit"
            );
            assert!(
                roster[2].newest_tx < tx,
                "setup: C sat the commit out, so its roster is older"
            );
            (tx, roster[0].newest_commit)
        };

        let raw = crate::gpt::MEMBER_PARTITION_START + a_commit.offset;
        let bad = if unreadable {
            raw..raw + 512
        } else {
            flip_byte(&paths[0], raw + 40);
            0..0
        };
        let devices = || {
            vec![
                BadSectors::open(&paths[0], bad.clone()),
                BadSectors::open(&paths[1], 0..0),
                BadSectors::open(&paths[2], 0..0),
            ]
        };
        if let Ok(pool) = Pool::open_multi(devices())
            && pool.committed_tx() != newest_tx
        {
            failures.push(format!(
                "with {what} chain record on A, a whole import opened tx {} of {newest_tx} (read-only: {})",
                pool.committed_tx(),
                pool.read_only()
            ));
        }
        match Pool::open_multi_degraded(devices()) {
            Ok(pool) if pool.committed_tx() != newest_tx => failures.push(format!(
                "with {what} chain record on A, a degraded import opened tx {} of {newest_tx}",
                pool.committed_tx()
            )),
            Ok(pool) => {
                if read_named(&pool, "acknowledged.bin").ok() != Some(acknowledged.clone()) {
                    failures.push(format!("with {what} chain record on A, data lost"));
                }
            }
            Err(error) => failures.push(format!(
                "with {what} chain record on A, the newest view did not open degraded: {error:?}"
            )),
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

fn diverged_mirror(scratch: &Scratch) -> (Pool<Arc<FileBlockDevice>>, Vec<u8>, Vec<u8>) {
    let victim = pattern(70_000, 51);
    let intruder = pattern(70_000, 52);
    let members = ["a.img", "x.img"]
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let device = FileBlockDevice::create(&scratch.image(name), image_len()).unwrap();
            member(Arc::new(device), 0xD0 + i as u8)
        })
        .collect();
    let mut pool = Pool::create_multi(members, mirror_params(2)).unwrap();
    write_named(&mut pool, "victim.bin", &victim);
    write_named(&mut pool, "intruder.bin", &intruder);
    pool.commit(AllocPurpose::Normal, NOW).unwrap();

    let first_run_on_member_1 = |pool: &Pool<Arc<FileBlockDevice>>, name: &str| {
        let inode = pool.lookup(ROOT_INODE, name).unwrap().inode;
        let key = MetadataKey {
            object_id: inode,
            item_type: ITEM_FILE_EXTENT,
            offset: 0,
        };
        let Some(MetadataValue::FileRun(run)) = pool.tree().get(key).unwrap() else {
            panic!("{name} has no first run");
        };
        run.record_copies(0)
            .into_iter()
            .find(|copy| copy.device_index == 1)
            .expect("a copy on member 1")
    };
    let target = first_run_on_member_1(&pool, "victim.bin");
    let source = first_run_on_member_1(&pool, "intruder.bin");
    assert_eq!(target.length, source.length, "setup: equal-length records");
    let misdirected = pool.read_extent(source).unwrap();
    let slot = pool.member_slot(1).unwrap();
    pool.devices[slot]
        .write_at(target.offset, &misdirected)
        .unwrap();
    pool.devices[slot].flush().unwrap();
    (pool, victim, intruder)
}

#[test]
fn scrub_reports_mirror_copies_that_disagree() {
    let scratch = Scratch::new("diverged-scrub");
    let (mut pool, _, _) = diverged_mirror(&scratch);
    let report = pool.scrub(false).unwrap();
    assert!(
        !report.healthy(),
        "two copies of one record disagree, yet scrub reported {report:?}"
    );
}

#[test]
fn a_stale_but_valid_copy_is_never_served_as_current() {
    let scratch = Scratch::new("diverged-read");
    let (pool, victim, intruder) = diverged_mirror(&scratch);
    drop(pool);
    let survivor = Pool::open_multi_degraded(vec![reopen(&scratch.image("x.img"))]).unwrap();
    match read_named(&survivor, "victim.bin") {
        Ok(bytes) => {
            assert!(
                bytes[..32768] != intruder[..32768],
                "another file's bytes were served as victim.bin"
            );
            assert!(bytes == victim, "victim.bin read back wrong");
        }
        Err(error) => assert!(matches!(error, ScaleFsError::Corrupt(_)), "{error:?}"),
    }
}

const CHILD: &str = "SCALEFS_FAULT_TESTS_CHILD";

fn in_child() -> bool {
    std::env::var_os(CHILD).is_some()
}

fn run_in_child(name: &str, budget: std::time::Duration) -> std::result::Result<(), String> {
    run_in_child_with(name, budget, &[])
}

fn run_in_child_with(
    name: &str,
    budget: std::time::Duration,
    env: &[(&str, &std::ffi::OsStr)],
) -> std::result::Result<(), String> {
    let scratch = Scratch::new("child");
    let log = scratch.image("output.txt");
    let output = std::fs::File::create(&log).expect("create the child's log");
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            format!("pool::fault_tests::{name}").as_str(),
            "--exact",
            "--include-ignored",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env(CHILD, "1")
        .envs(env.iter().copied())
        .stdin(std::process::Stdio::null())
        .stdout(output.try_clone().unwrap())
        .stderr(output)
        .spawn()
        .expect("spawn the child test");
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() >= budget {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("still running after {budget:?}; killed"));
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    };
    let output = std::fs::read_to_string(&log).unwrap_or_default();
    if status.success() && output.contains("test result: ok. 1 passed") {
        Ok(())
    } else {
        let tail: Vec<&str> = output.lines().rev().take(12).collect();
        let tail: Vec<&str> = tail.into_iter().rev().collect();
        Err(format!(
            "exited with {status}:
{}",
            tail.join(
                "
"
            )
        ))
    }
}

fn single_params() -> CreateParams {
    CreateParams {
        pool_id: PoolId([0xEE; 16]),
        device_id: DeviceId([0xE1; 16]),
        geometry: geometry(),
        case_sensitivity: CaseSensitivity::InsensitivePreserving,
        dirent_hash_seed: SEED,
        label: "crafted".to_string(),
        created_at_ns: NOW,
    }
}

fn pool_with_looping_root(path: &Path, children: u64) {
    let device = Arc::new(FileBlockDevice::create(path, image_len()).unwrap());
    let mut pool = Pool::create(Arc::clone(&device), single_params()).unwrap();
    write_named(&mut pool, "a.txt", b"a");
    pool.commit(AllocPurpose::Normal, NOW).unwrap();
    let root = pool.last_metadata_root.clone();
    let entries: Vec<(MetadataKey, PageRef)> = (0..children)
        .map(|i| {
            let separator = MetadataKey {
                object_id: i,
                item_type: 0,
                offset: 0,
            };
            (separator, root.clone())
        })
        .collect();
    let page = crate::tree::encode_internal_record(&entries, pool.committed_tx());
    assert!(
        page.len() as u64 <= root.copies[0].length,
        "the crafted page fits"
    );
    pool.devices[0]
        .write_at(root.copies[0].offset, &page)
        .unwrap();
    reseal_root(&pool.devices[0], &page);
}

#[test]
fn a_tree_page_pointing_at_itself_is_refused_not_followed_until_the_stack_overflows() {
    if in_child() {
        let scratch = Scratch::new("self-page");
        let path = scratch.image("pool.img");
        pool_with_looping_root(&path, 2);
        let opened = Pool::open(Arc::new(FileBlockDevice::open(&path).unwrap()));
        assert!(
            matches!(opened, Err(ScaleFsError::Corrupt(_))),
            "{:?}",
            opened.err()
        );
        return;
    }
    let end = run_in_child(
        "a_tree_page_pointing_at_itself_is_refused_not_followed_until_the_stack_overflows",
        std::time::Duration::from_secs(60),
    );
    if let Err(why) = end {
        panic!("the child run failed: {why}");
    }
}

#[test]
fn the_salvage_walk_of_a_page_whose_children_point_back_at_it_terminates() {
    if in_child() {
        let scratch = Scratch::new("salvage-loop");
        let path = scratch.image("pool.img");
        pool_with_looping_root(&path, 2);
        let device = FileBlockDevice::open(&path).unwrap();
        let salvage = crate::salvage::Salvage::assemble(vec![device]).unwrap();
        let mut lost = 0u64;
        salvage
            .walk(&mut |event| {
                if matches!(event, crate::salvage::WalkEvent::Lost(_)) {
                    lost += 1;
                }
            })
            .unwrap();
        assert!(lost >= 1, "the loop is reported as damage");
        salvage.survey().unwrap();
        return;
    }
    let end = run_in_child(
        "the_salvage_walk_of_a_page_whose_children_point_back_at_it_terminates",
        std::time::Duration::from_secs(30),
    );
    if let Err(why) = end {
        panic!("the child run failed: {why}");
    }
}

#[derive(Debug)]
struct Sparse {
    len: u64,
    blocks: std::sync::Mutex<std::collections::BTreeMap<u64, Vec<u8>>>,
}

const SPARSE_BLOCK: u64 = 4096;

impl Sparse {
    fn new(len: u64) -> Arc<Sparse> {
        Arc::new(Sparse {
            len,
            blocks: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        })
    }

    fn check(&self, offset: u64, len: usize) -> Result<()> {
        match offset.checked_add(len as u64) {
            Some(end) if end <= self.len => Ok(()),
            _ => Err(ScaleFsError::InvalidArgument("access past the device end")),
        }
    }
}

impl BlockDevice for Sparse {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.check(offset, buf.len())?;
        let blocks = self.blocks.lock().unwrap();
        let mut done = 0;
        while done < buf.len() {
            let at = offset + done as u64;
            let within = (at % SPARSE_BLOCK) as usize;
            let take = (SPARSE_BLOCK as usize - within).min(buf.len() - done);
            match blocks.get(&(at / SPARSE_BLOCK)) {
                Some(block) => {
                    buf[done..done + take].copy_from_slice(&block[within..within + take])
                }
                None => buf[done..done + take].fill(0),
            }
            done += take;
        }
        Ok(())
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
        self.check(offset, data.len())?;
        let mut blocks = self.blocks.lock().unwrap();
        let mut done = 0;
        while done < data.len() {
            let at = offset + done as u64;
            let within = (at % SPARSE_BLOCK) as usize;
            let take = (SPARSE_BLOCK as usize - within).min(data.len() - done);
            let block = blocks
                .entry(at / SPARSE_BLOCK)
                .or_insert_with(|| vec![0; SPARSE_BLOCK as usize]);
            block[within..within + take].copy_from_slice(&data[done..done + take]);
            done += take;
        }
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        Ok(())
    }
}

#[test]
fn an_absurd_extent_length_is_refused_before_it_is_allocated() {
    if in_child() {
        let device = Sparse::new(1 << 46);
        let mut pool = Pool::create(Arc::clone(&device), single_params()).unwrap();
        write_named(&mut pool, "a.txt", b"a");
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let at = pool.superblock().newest_commit.expect("a committed pool");
        let mut commit = decode_commit(&pool.read_extent(at.extent).unwrap()).unwrap();
        commit.allocator_summary.extent.length = 1 << 45;
        let crafted = encode_commit(&commit).unwrap();
        reseal_commit(&pool.devices[0], &crafted);
        drop(pool);
        let opened = Pool::open(Arc::clone(&device));
        assert!(
            matches!(opened, Err(ScaleFsError::Corrupt(_))),
            "{:?}",
            opened.err()
        );
        return;
    }
    let end = run_in_child(
        "an_absurd_extent_length_is_refused_before_it_is_allocated",
        std::time::Duration::from_secs(60),
    );
    if let Err(why) = end {
        panic!("the child run failed: {why}");
    }
}

#[test]
fn moving_a_directory_whose_subtree_loops_back_terminates() {
    if in_child() {
        let device = Arc::new(MemoryBlockDevice::new(image_len() as usize));
        let mut pool = Pool::create(device, single_params()).unwrap();
        let d1 = pool.mkdir(ROOT_INODE, "d1", 0o755, NOW).unwrap();
        let d2 = pool.mkdir(d1, "d2", 0o755, NOW).unwrap();
        let elsewhere = pool.mkdir(ROOT_INODE, "elsewhere", 0o755, NOW).unwrap();
        let (version, case) = (
            pool.superblock().unicode_version,
            pool.superblock().case_sensitivity,
        );
        crate::dirent::add_entry(
            pool.tree_mut(),
            SEED,
            version,
            case,
            d2,
            "back",
            d1,
            crate::tree::EntryKind::Directory,
        )
        .unwrap();
        let moved = pool.rename(ROOT_INODE, "d1", elsewhere, "d1", NOW);
        assert!(
            moved.is_err(),
            "a move through a directory cycle is refused"
        );
        return;
    }
    let end = run_in_child(
        "moving_a_directory_whose_subtree_loops_back_terminates",
        std::time::Duration::from_secs(30),
    );
    if let Err(why) = end {
        panic!("the child run failed: {why}");
    }
}

fn reseal(record: &mut [u8]) {
    let header_len = crate::format::RECORD_HEADER_LEN;
    if record.len() < header_len {
        return;
    }
    let payload_len = u32::from_le_bytes(record[16..20].try_into().expect("4 bytes"));
    let end = (header_len as u64)
        .saturating_add(u64::from(payload_len))
        .min(record.len() as u64) as usize;
    let mut header = [0u8; 32];
    header.copy_from_slice(&record[..header_len]);
    header[20..24].fill(0);
    let mut crc = crate::checksum::Crc32c::new();
    crc.update(&header);
    crc.update(&record[header_len..end]);
    record[20..24].copy_from_slice(&crc.finalize().to_le_bytes());
}

fn fuzz_budget(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn fuzz_seed() -> u64 {
    fuzz_budget("SCALEFS_FUZZ_SEED", 0x00C0_FFEE_D15C_0001)
}

fn pick(rng: &mut crate::rng::XorShift64, len: usize) -> usize {
    (rng.next_u64() % len as u64) as usize
}

fn mutate_record(rng: &mut crate::rng::XorShift64, input: &[u8]) -> Vec<u8> {
    const INTERESTING_U64: [u64; 8] = [0, 1, 2, 0xFF, 1 << 16, 1 << 32, 1 << 40, u64::MAX];
    let mut bytes = input.to_vec();
    for _ in 0..1 + rng.next_u64() % 4 {
        if bytes.is_empty() {
            bytes.push(0);
        }
        let at = pick(rng, bytes.len());
        match rng.next_u64() % 8 {
            0 => bytes[at] ^= 1 << (rng.next_u64() % 8),
            1 => bytes[at] = [0u8, 1, 0x7F, 0x80, 0xFF][pick(rng, 5)],
            2 if at + 2 <= bytes.len() => {
                let value = [0u16, 1, 2, 0xFF, 0x8000, 0xFFFF][pick(rng, 6)];
                bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
            }
            3 if at + 4 <= bytes.len() => {
                let value = [0u32, 1, 0x8000_0000, u32::MAX][pick(rng, 4)];
                bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
            }
            4 if at + 8 <= bytes.len() => {
                let value = INTERESTING_U64[pick(rng, 8)];
                bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
            }
            5 => bytes.truncate(at),
            6 => {
                for _ in 0..1 + rng.next_u64() % 64 {
                    bytes.push(rng.next_u64() as u8);
                }
            }
            _ => {
                let len = 1 + pick(rng, 32);
                let from = pick(rng, bytes.len());
                let chunk: Vec<u8> = bytes[from..(from + len).min(bytes.len())].to_vec();
                let to = pick(rng, bytes.len());
                for (i, byte) in chunk.into_iter().enumerate() {
                    if let Some(slot) = bytes.get_mut(to + i) {
                        *slot = byte;
                    }
                }
            }
        }
    }
    let header_len = crate::format::RECORD_HEADER_LEN;
    if bytes.len() >= header_len && rng.next_u64().is_multiple_of(2) {
        let payload = (bytes.len() - header_len) as u32;
        bytes[16..20].copy_from_slice(&payload.to_le_bytes());
    }
    if !rng.next_u64().is_multiple_of(8) {
        reseal(&mut bytes);
    }
    bytes
}

fn record_corpus() -> Vec<Vec<u8>> {
    let mut corpus = Vec::new();
    let members = (0..3)
        .map(|i| {
            member(
                Arc::new(MemoryBlockDevice::new(image_len() as usize)),
                0x70 + i,
            )
        })
        .collect();
    let mut pool = Pool::create_multi(members, mirror_params(2)).unwrap();
    for i in 0..300 {
        write_named(
            &mut pool,
            &format!("f{i:03}"),
            &pattern(64 + i * 7, i as u64),
        );
    }
    write_named(&mut pool, "big.bin", &pattern(70_000, 9));
    pool.commit(AllocPurpose::Normal, NOW).unwrap();
    corpus.push(encode_superblock(pool.superblock(), pool.committed_tx()).unwrap());
    let local = |extent: Extent| Extent {
        device_index: 0,
        ..extent
    };
    let at = pool.superblock().newest_commit.unwrap();
    let commit_bytes = read_extent_from_set(&pool.devices[..1], local(at.extent)).unwrap();
    let commit = decode_commit(&commit_bytes).unwrap();
    corpus.push(commit_bytes);
    corpus.push(
        read_extent_from_set(&pool.devices[..1], local(commit.allocator_summary.extent)).unwrap(),
    );
    corpus.push(
        read_extent_from_set(&pool.devices[..1], local(commit.aux_root.unwrap().extent)).unwrap(),
    );
    for page in tree_pages(&pool) {
        corpus.push(pool.read_record(&page.copies, page.expect).unwrap());
    }
    let big = pool.lookup(ROOT_INODE, "big.bin").unwrap().inode;
    if let Some(MetadataValue::FileRun(run)) = pool
        .tree()
        .get(MetadataKey {
            object_id: big,
            item_type: ITEM_FILE_EXTENT,
            offset: 0,
        })
        .unwrap()
    {
        corpus.push(
            pool.read_record(&run.record_copies(0), run.expect(0))
                .unwrap(),
        );
    }

    let members = (0..3)
        .map(|i| {
            member(
                Arc::new(MemoryBlockDevice::new(image_len() as usize)),
                0x78 + i,
            )
        })
        .collect();
    let mut parity = Pool::create_multi(
        members,
        PoolParams {
            data_width: 2,
            parity_width: 1,
            ..mirror_params(2)
        },
    )
    .unwrap();
    write_named(&mut parity, "striped.bin", &pattern(100_000, 11));
    parity.commit(AllocPurpose::Normal, NOW).unwrap();
    let striped = parity.lookup(ROOT_INODE, "striped.bin").unwrap().inode;
    if let Some(MetadataValue::StripedRun(run)) = parity
        .tree()
        .get(MetadataKey {
            object_id: striped,
            item_type: ITEM_FILE_EXTENT,
            offset: 0,
        })
        .unwrap()
    {
        corpus.push(
            parity
                .read_record(&run.parity[..1], run.parity_expect(0))
                .unwrap(),
        );
    }
    assert!(corpus.len() >= 9, "the corpus covers every record kind");
    corpus
}

#[test]
fn record_decoders_never_panic_on_mutated_records() {
    let corpus = record_corpus();
    let iterations = fuzz_budget("SCALEFS_FUZZ_ITERATIONS", 4_000);
    let seed = fuzz_seed();
    let mut rng = crate::rng::XorShift64::new(seed);
    type Decoder = fn(&[u8]) -> bool;
    let decoders: [(&str, Decoder); 9] = [
        ("record", |b| decode_record(b).is_ok()),
        ("superblock", |b| decode_superblock(b).is_ok()),
        ("commit", |b| decode_commit(b).is_ok()),
        ("topology", |b| decode_topology(b).is_ok()),
        ("leaf", |b| crate::tree::decode_leaf_record(b).is_ok()),
        ("internal", |b| decode_internal_record(b).is_ok()),
        ("summary", |b| ZoneAllocator::decode(geometry(), b).is_ok()),
        ("parity", |b| decode_parity_record(b).is_ok()),
        ("file data", |b| crate::records::decode_file_data(b).is_ok()),
    ];
    let mut panics = Vec::new();
    for iteration in 0..iterations {
        let input = &corpus[pick(&mut rng, corpus.len())];
        let mutated = mutate_record(&mut rng, input);
        for (name, decode) in &decoders {
            let bytes = mutated.clone();
            let outcome = std::panic::catch_unwind(move || decode(&bytes));
            if outcome.is_err() && panics.len() < 8 {
                panics.push(format!(
                    "{name} decoder panicked (seed {seed:#x}, iteration {iteration})"
                ));
            }
        }
    }
    assert!(panics.is_empty(), "{panics:#?}");
}

impl Sparse {
    fn save(&self, path: &Path) {
        let blocks = self.blocks.lock().unwrap();
        let mut out = Vec::with_capacity(blocks.len() * (8 + SPARSE_BLOCK as usize));
        for (index, block) in blocks.iter() {
            out.extend_from_slice(&index.to_le_bytes());
            out.extend_from_slice(block);
        }
        std::fs::write(path, out).expect("save a sparse image");
    }

    fn load(path: &Path, len: u64) -> Arc<Sparse> {
        let bytes = std::fs::read(path).expect("load a sparse image");
        let device = Sparse::new(len);
        {
            let mut blocks = device.blocks.lock().unwrap();
            for record in bytes.chunks_exact(8 + SPARSE_BLOCK as usize) {
                let index = u64::from_le_bytes(record[..8].try_into().unwrap());
                blocks.insert(index, record[8..].to_vec());
            }
        }
        device
    }
}

const FUZZ_IMAGE: &str = "SCALEFS_FAULT_TESTS_IMAGE";

const FUZZ_DEVICE_LEN: u64 = 1 << 46;

type CraftedPage = (Extent, usize, Option<usize>);

fn crafted_base() -> (Arc<Sparse>, Vec<CraftedPage>, Extent, Commit) {
    let device = Sparse::new(FUZZ_DEVICE_LEN);
    let mut pool = Pool::create(Arc::clone(&device), single_params()).unwrap();
    let dir = pool.mkdir(ROOT_INODE, "dir", 0o755, NOW).unwrap();
    for i in 0..400 {
        let parent = if i % 3 == 0 { dir } else { ROOT_INODE };
        let inode = pool
            .create_file(parent, &format!("file-{i:04}"), 0o644, NOW)
            .unwrap();
        pool.write(inode, 0, &pattern(40 + i, i as u64), NOW)
            .unwrap();
    }
    pool.commit(AllocPurpose::Normal, NOW).unwrap();
    let mut pages: Vec<CraftedPage> = Vec::new();
    let mut stack = vec![(pool.last_metadata_root.copies[0], 0usize, None)];
    while let Some((extent, depth, parent)) = stack.pop() {
        let bytes = pool.read_extent(extent).unwrap();
        let index = pages.len();
        if let Ok(children) = decode_internal_record(&bytes) {
            stack.extend(
                children
                    .into_iter()
                    .map(|(_, child)| (child.copies[0], depth + 1, Some(index))),
            );
        }
        pages.push((extent, depth, parent));
    }
    assert!(
        pages.iter().any(|(_, depth, _)| *depth > 0),
        "the base tree has an internal page"
    );
    let at = pool.superblock().newest_commit.unwrap();
    let commit = decode_commit(&pool.read_extent(at.extent).unwrap()).unwrap();
    drop(pool);
    (device, pages, at.extent, commit)
}

fn reseal_chain<D: BlockDevice>(view: &D, pages: &[CraftedPage], index: usize) {
    let read = |extent: Extent| {
        let mut bytes = vec![0u8; extent.length as usize];
        view.read_at(extent.offset, &mut bytes).unwrap();
        bytes
    };
    let mut child = index;
    loop {
        let (child_extent, _, parent) = pages[child];
        let child_bytes = read(child_extent);
        let child_expect = Expect::of(&child_bytes);
        let Some(parent) = parent else {
            reseal_root(view, &child_bytes);
            return;
        };
        let parent_extent = pages[parent].0;
        let parent_bytes = read(parent_extent);
        let Ok(mut entries) = decode_internal_record(&parent_bytes) else {
            return;
        };
        for (_, entry) in &mut entries {
            if entry.copies[0] == child_extent {
                entry.expect = child_expect;
            }
        }
        let tx = Expect::of(&parent_bytes).tx;
        let bytes = crate::tree::encode_internal_record(&entries, tx);
        if bytes.len() as u64 > parent_extent.length {
            return;
        }
        view.write_at(parent_extent.offset, &bytes).unwrap();
        child = parent;
    }
}

fn craft_case(
    rng: &mut crate::rng::XorShift64,
    device: &Arc<Sparse>,
    pages: &[CraftedPage],
    commit_at: Extent,
    commit: &Commit,
) -> Vec<String> {
    let view = crate::gpt::member_view(Arc::clone(device)).unwrap();
    let read = |extent: Extent| {
        let mut bytes = vec![0u8; extent.length as usize];
        view.read_at(extent.offset, &mut bytes).unwrap();
        bytes
    };
    let internal: Vec<usize> = (0..pages.len())
        .filter(|&index| decode_internal_record(&read(pages[index].0)).is_ok())
        .collect();
    let mut edits = Vec::new();
    for _ in 0..1 + rng.next_u64() % 2 {
        let kind = rng.next_u64() % 6;
        if kind == 5 {
            let mut crafted = *commit;
            let (what, reference) = if rng.next_u64().is_multiple_of(2) {
                ("root", &mut crafted.metadata_root)
            } else {
                ("summary", &mut crafted.allocator_summary)
            };
            let extent = &mut reference.extent;
            extent.length = match rng.next_u64() % 3 {
                0 => view.len() - extent.offset,
                1 => extent.length * 64,
                _ => extent.length + 1,
            };
            let length = extent.length;
            let bytes = encode_commit(&crafted).unwrap();
            if bytes.len() as u64 <= commit_at.length {
                view.write_at(commit_at.offset, &bytes).unwrap();
                reseal_commit(&view, &bytes);
            }
            edits.push(format!("commit {what} length -> {length}"));
            continue;
        }
        if kind == 4 || internal.is_empty() {
            let index = pick(rng, pages.len());
            let page = pages[index].0;
            let mutated = mutate_record(rng, &read(page));
            let len = mutated.len().min(page.length as usize);
            view.write_at(page.offset, &mutated[..len]).unwrap();
            if len >= crate::format::RECORD_HEADER_LEN {
                reseal_chain(&view, pages, index);
            }
            edits.push(format!("payload of page at {} mutated", page.offset));
            continue;
        }
        let index = internal[pick(rng, internal.len())];
        let page = pages[index].0;
        let Ok(mut entries) = decode_internal_record(&read(page)) else {
            continue;
        };
        let child = pick(rng, entries.len());
        let what = match kind {
            0 => {
                let target = if rng.next_u64().is_multiple_of(2) {
                    page
                } else {
                    pages[pick(rng, pages.len())].0
                };
                entries[child].1 = PageRef {
                    copies: vec![target],
                    expect: Expect::of(&read(target)),
                };
                format!(
                    "child {child} of page at {} -> page at {}",
                    page.offset, target.offset
                )
            }
            1 => {
                let offset = (rng.next_u64() % (view.len() / 4096 / 1024)) * 4096;
                entries[child].1.copies[0].offset = offset;
                format!(
                    "child {child} of page at {} -> offset {offset}",
                    page.offset
                )
            }
            _ => {
                let at = entries[child].1.copies[0];
                let length = match rng.next_u64() % 3 {
                    0 => view.len() - at.offset,
                    1 => at.length * 64,
                    _ => 1 << 20,
                };
                entries[child].1.copies[0].length = length;
                format!(
                    "child {child} of page at {} length -> {length}",
                    page.offset
                )
            }
        };
        let tx = Expect::of(&read(page)).tx;
        let bytes = crate::tree::encode_internal_record(&entries, tx);
        if bytes.len() as u64 <= page.length {
            view.write_at(page.offset, &bytes).unwrap();
            reseal_chain(&view, pages, index);
            edits.push(what);
        }
    }
    edits
}

fn exercise_crafted_image(device: Arc<Sparse>) {
    if let Ok(pool) = Pool::open(Arc::clone(&device)) {
        let mut seen = HashSet::new();
        let mut stack = vec![ROOT_INODE];
        while let Some(dir) = stack.pop() {
            if !seen.insert(dir) || seen.len() > 10_000 {
                continue;
            }
            for entry in pool.readdir(dir).unwrap_or_default() {
                match entry.kind {
                    crate::tree::EntryKind::Directory => stack.push(entry.inode),
                    _ => {
                        if let Ok(attrs) = pool.getattr(entry.inode) {
                            let _ = pool.read(entry.inode, 0, attrs.size.min(1 << 20) as usize);
                        }
                    }
                }
            }
        }
    }
    if let Ok(salvage) = crate::salvage::Salvage::assemble(vec![device]) {
        let _ = salvage.walk(&mut |_| {});
        let _ = salvage.survey();
    }
}

#[test]
fn crafted_images_are_refused_or_served_within_bounds() {
    if let Some(image) = std::env::var_os(FUZZ_IMAGE) {
        exercise_crafted_image(Sparse::load(Path::new(&image), FUZZ_DEVICE_LEN));
        return;
    }
    let scratch = Scratch::new("crafted");
    let (base, pages, commit_at, commit) = crafted_base();
    let base_path = scratch.image("base.blocks");
    base.save(&base_path);
    let cases = fuzz_budget("SCALEFS_FUZZ_CASES", 32);
    let seed = fuzz_seed();
    let mut rng = crate::rng::XorShift64::new(seed);
    let mut answered = 0u64;
    let mut failures: std::collections::BTreeMap<&str, (u64, Vec<String>)> =
        std::collections::BTreeMap::new();
    for case in 0..cases {
        let device = Sparse::load(&base_path, FUZZ_DEVICE_LEN);
        let edits = craft_case(&mut rng, &device, &pages, commit_at, &commit);
        let image = scratch.image(&format!("case-{case}.blocks"));
        device.save(&image);
        let end = run_in_child_with(
            "crafted_images_are_refused_or_served_within_bounds",
            std::time::Duration::from_secs(20),
            &[(FUZZ_IMAGE, image.as_os_str())],
        );
        let _ = std::fs::remove_file(&image);
        let Err(why) = end else {
            answered += 1;
            continue;
        };
        let class = if why.contains("overflowed its stack") {
            "stack overflow"
        } else if why.contains("memory allocation of") {
            "allocation abort"
        } else if why.contains("killed") {
            "hang"
        } else if why.contains("panicked") {
            "panic"
        } else {
            "other failure"
        };
        let (count, examples) = failures.entry(class).or_default();
        *count += 1;
        if examples.len() < 2 {
            let detail = why
                .lines()
                .find(|line| line.contains("allocation of") || line.contains("panicked at"))
                .unwrap_or_default()
                .trim()
                .to_string();
            examples.push(format!("case {case} {edits:?} {detail}"));
        }
    }
    let report: Vec<String> = failures
        .iter()
        .map(|(class, (count, examples))| format!("{class}: {count} case(s), e.g. {examples:#?}"))
        .collect();
    assert!(
        failures.is_empty(),
        "seed {seed:#x}: {answered} of {cases} crafted pools answered; the rest did not:\n{}",
        report.join("\n")
    );
}

#[test]
fn a_rename_that_cannot_add_the_new_name_keeps_the_old_one() {
    let device = Arc::new(MemoryBlockDevice::new(image_len() as usize));
    let mut pool = Pool::create(device, single_params()).unwrap();
    pool.create_file(ROOT_INODE, "draft.tmp", 0o644, NOW)
        .unwrap();
    let superblock = pool.superblock().clone();
    let full = MetadataKey {
        object_id: ROOT_INODE,
        item_type: crate::tree::ITEM_DIRENT,
        offset: crate::dirent::dirent_hash(
            superblock.dirent_hash_seed,
            &crate::dirent::fold_name(
                superblock.unicode_version,
                superblock.case_sensitivity,
                "report.pdf",
            ),
        ),
    };
    let mut bucket: Vec<crate::tree::DirEntry> = Vec::new();
    let long = (0..64u64).map(|i| format!("{i:02}-{}", "x".repeat(200)));
    let short = (0..256u64).map(|i| format!("s{i:03}"));
    for (i, name) in long.chain(short).enumerate() {
        let mut grown = bucket.clone();
        grown.push(crate::tree::DirEntry {
            inode: 1_000 + i as u64,
            kind: crate::tree::EntryKind::File,
            name,
        });
        if pool
            .tree_mut()
            .insert(full, MetadataValue::DirEntries(grown.clone()))
            .is_ok()
        {
            bucket = grown;
        }
    }
    pool.tree_mut()
        .insert(full, MetadataValue::DirEntries(bucket))
        .unwrap();

    let renamed = pool.rename(ROOT_INODE, "draft.tmp", ROOT_INODE, "report.pdf", NOW);
    assert!(renamed.is_err(), "setup: the destination bucket is full");
    assert!(
        pool.lookup(ROOT_INODE, "draft.tmp").is_ok(),
        "the failed rename ({renamed:?}) removed the old name, leaving the file nameless"
    );
}
