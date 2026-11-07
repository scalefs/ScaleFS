use super::*;
use scalefs_core::{CaseSensitivity, DeviceId, FileBlockDevice, PoolId, PoolParams};
use std::time::{Duration, Instant};

struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "scalefsd-faults-{}-{tag}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the scratch directory");
        Scratch(dir)
    }

    fn path(&self, name: &str) -> String {
        self.0.join(name).to_string_lossy().into_owned()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn attached_pool(
    scratch: &Scratch,
    name: &str,
    zone_count: u64,
    data_bytes: usize,
) -> (Registry, Vec<String>) {
    let geometry = Geometry {
        logical_block_size: 4096,
        physical_block_size: 4096,
        zone_size: 1 << 20,
        zone_count,
        erase_granularity_zones: 1,
        sequential_write_required: false,
    };
    let images = vec![scratch.path("a.img"), scratch.path("b.img")];
    let members = images
        .iter()
        .zip([0xA7u8, 0xB7])
        .map(|(path, id)| MemberSpec {
            device: FileBlockDevice::create(
                Path::new(path),
                scalefs_core::member_image_len(geometry.capacity_bytes()),
            )
            .unwrap(),
            device_id: DeviceId([id; 16]),
            geometry,
        })
        .collect();
    let mut pool = Pool::create_multi(
        members,
        PoolParams {
            pool_id: PoolId([0x5A; 16]),
            case_sensitivity: CaseSensitivity::InsensitivePreserving,
            dirent_hash_seed: 11,
            label: name.to_string(),
            created_at_ns: now_ns(),
            mirror_width: 2,
            data_width: 1,
            parity_width: 0,
        },
    )
    .unwrap();
    if data_bytes > 0 {
        let file = pool
            .create_file(scalefs_core::ROOT_INODE, "data.bin", 0o644, now_ns())
            .unwrap();
        let chunk: Vec<u8> = (0..1 << 20).map(|i: u32| (i % 251) as u8).collect();
        let mut written = 0usize;
        while written < data_bytes {
            let len = chunk.len().min(data_bytes - written);
            pool.write(file, written as u64, &chunk[..len], now_ns())
                .unwrap();
            written += len;
        }
    }
    pool.commit(scalefs_core::AllocPurpose::Normal, now_ns())
        .unwrap();
    drop(pool);

    let registry = Registry::default();
    registry
        .attach(&object(vec![
            ("name", Value::Str(name.into())),
            (
                "members",
                Value::Array(images.iter().cloned().map(Value::Str).collect()),
            ),
        ]))
        .unwrap();
    (registry, images)
}

fn running(registry: &Registry, id: u64) -> bool {
    let status = registry
        .job_status(&object(vec![("id", Value::Int(i128::from(id)))]))
        .unwrap();
    status.get("state").and_then(Value::as_str) == Some("running")
}

#[test]
fn mount_requests_keep_answering_while_a_scrub_job_runs() {
    let scratch = Scratch::new("scrub-latency");
    let (registry, _) = attached_pool(&scratch, "load", 400, 256 << 20);
    let core = registry
        .share_handle("load")
        .unwrap()
        .core
        .clone()
        .expect("a writable attachment has a mount core");

    let stop = Arc::new(AtomicBool::new(false));
    let reader = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut worst = Duration::ZERO;
            let mut samples = 0u64;
            while !stop.load(Ordering::SeqCst) {
                let asked = Instant::now();
                core.getattr(scalefs_core::ROOT_INODE).unwrap();
                worst = worst.max(asked.elapsed());
                samples += 1;
                std::thread::sleep(Duration::from_millis(2));
            }
            (worst, samples)
        })
    };
    std::thread::sleep(Duration::from_millis(50));

    let started = Instant::now();
    let job = registry
        .scrub(&object(vec![("name", Value::Str("load".into()))]))
        .unwrap();
    let id = job.get("job").and_then(Value::as_u64).unwrap();
    while running(&registry, id) {
        std::thread::sleep(Duration::from_millis(5));
    }
    let scrub_took = started.elapsed();
    stop.store(true, Ordering::SeqCst);
    let (worst, samples) = reader.join().unwrap();

    assert!(
        scrub_took >= Duration::from_millis(200),
        "inconclusive: the scrub finished in {scrub_took:?}; the pool is too small to measure"
    );
    assert!(
        worst < scrub_took / 4,
        "a stat waited {worst:?} during a {scrub_took:?} scrub ({samples} stats answered)"
    );
    registry
        .detach(&object(vec![("name", Value::Str("load".into()))]))
        .unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn a_daemon_stop_waits_for_the_final_commit_of_a_slow_mount() {
    use std::io::Write as _;
    let scratch = Scratch::new("slow-stop");
    let (registry, images) = attached_pool(&scratch, "slow", 32, 0);
    let mountpoint = scratch.path("mnt");
    std::fs::create_dir_all(&mountpoint).unwrap();
    if let Err((_, message)) = registry.mount(&object(vec![
        ("name", Value::Str("slow".into())),
        ("mountpoint", Value::Str(mountpoint.clone())),
    ])) {
        eprintln!("skipping: mounting needs root ({message})");
        let _ = registry.detach(&object(vec![("name", Value::Str("slow".into()))]));
        return;
    }
    let entry = registry
        .pools
        .lock()
        .unwrap()
        .get("slow")
        .map(Arc::clone)
        .unwrap();

    let mut open = std::fs::File::create(Path::new(&mountpoint).join("late.txt")).unwrap();
    open.write_all(b"acknowledged by write(2), awaiting the final commit")
        .unwrap();

    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let staller = {
        let pool = Arc::clone(&entry.pool);
        std::thread::spawn(move || {
            let guard = pool.read().unwrap();
            held_tx.send(Instant::now()).unwrap();
            std::thread::sleep(Duration::from_secs(7));
            drop(guard);
            Instant::now()
        })
    };
    let stalled_at = held_rx.recv().unwrap();

    registry.unmount_all();
    let returned_at = Instant::now();
    let on_disk: Vec<Arc<scalefs_core::MemoryBlockDevice>> = images
        .iter()
        .map(|path| {
            Arc::new(scalefs_core::MemoryBlockDevice::from_bytes(
                std::fs::read(path).unwrap(),
            ))
        })
        .collect();
    let released_at = staller.join().unwrap();
    drop(open);

    let survived = Pool::open_multi(on_disk)
        .ok()
        .and_then(|pool| pool.lookup(scalefs_core::ROOT_INODE, "late.txt").ok())
        .is_some();
    let _ = registry.detach(&object(vec![("name", Value::Str("slow".into()))]));
    assert!(
        survived,
        "shutdown's unmount step returned {:?} after it began, {:?} before the stalled \
         commit could run, and the written file is not on disk",
        returned_at - stalled_at,
        released_at.saturating_duration_since(returned_at)
    );
}

#[test]
fn the_provisioning_guard_refuses_a_device_it_could_not_read() {
    let path = if cfg!(windows) {
        r"\\.\ScaleFSReviewNoSuchDevice"
    } else {
        "/dev/scalefs-review-no-such-device"
    };
    assert!(scalefs_core::is_device_path(Path::new(path)));
    assert!(
        refuse_accidental_overwrite(path, false).is_err(),
        "an unreadable device was cleared for formatting without force"
    );
    assert!(refuse_accidental_overwrite(path, true).is_ok());
}
