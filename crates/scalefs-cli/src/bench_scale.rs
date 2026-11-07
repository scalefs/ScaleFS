use std::sync::Arc;
use std::time::{Duration, Instant};

use scalefs_core::{
    AllocPurpose, AnyBlockDevice, EntryKind, Pool, ROOT_INODE, ScaleFsError, ZoneClass,
};

use crate::util::{Opts, now_ns, parse_size};

type Dev = Arc<AnyBlockDevice>;

const USAGE: &str = "usage: scalefs bench-scale fill <image[,image...]> --files <n> --size <bytes> \
    [--start <k>] [--fanout <n>] [--commit-every <n>] | bench-scale open <image[,image...]> \
    [--cache <MiB>] [--walk] [--lookups <n> --files <n> [--fanout <n>]] | \
    bench-scale leak <image[,image...]> --file-size <bytes> [--min <bytes>] [--max <bytes>] \
    [--commit-every <n>] [--seed <n>] | bench-scale reclaim <image[,image...]>";

const MIB: usize = 1 << 20;
const PROGRESS: Duration = Duration::from_secs(30);

fn open_pool(images: &str) -> Result<Pool<Dev>, String> {
    let mut devices = Vec::new();
    for path in images.split(',') {
        devices.push(Arc::new(
            AnyBlockDevice::open(std::path::Path::new(path))
                .map_err(|err| format!("cannot open {path}: {err}"))?,
        ));
    }
    Pool::open_multi(devices).map_err(|err| format!("{images}: {err}"))
}

pub fn cmd_bench_scale(args: &[String]) -> Result<(), String> {
    let Some((verb, rest)) = args.split_first() else {
        return Err(USAGE.to_string());
    };
    let opts = Opts::parse(
        rest,
        &["walk"],
        &[
            "files",
            "size",
            "start",
            "fanout",
            "commit-every",
            "file-size",
            "min",
            "max",
            "seed",
            "cache",
            "lookups",
        ],
    )?;
    let [images] = opts.positional.as_slice() else {
        return Err(USAGE.to_string());
    };
    let number = |name: &str, default: u64| -> Result<u64, String> {
        match opts.value(name) {
            None => Ok(default),
            Some(text) => parse_size(text).map_err(|e| format!("--{name}: {e}")),
        }
    };
    match verb.as_str() {
        "fill" => fill(
            images,
            number("files", 0)?,
            number("size", 0)? as usize,
            number("start", 0)?,
            number("fanout", 1000)?.max(1),
            number("commit-every", 1000)?.max(1),
        ),
        "open" => {
            if let Some(text) = opts.value("cache") {
                let mib: usize = text
                    .parse()
                    .map_err(|_| format!("--cache: '{text}' is not a whole number of MiB"))?;
                scalefs_core::set_default_metadata_cache(mib << 20);
            }
            open(
                images,
                opts.flag("walk"),
                number("lookups", 0)?,
                number("files", 0)?,
                number("fanout", 1000)?.max(1),
            )
        }
        "leak" => leak(
            images,
            number("file-size", 0)?,
            number("min", 4096)? as usize,
            number("max", 65536)? as usize,
            number("commit-every", 1000)?.max(1),
            number("seed", 20261103)?,
        ),
        "reclaim" => reclaim(images),
        _ => Err(USAGE.to_string()),
    }
}

fn reclaim(images: &str) -> Result<(), String> {
    let mut pool = open_pool(images)?;
    let (capacity, before) = space(&pool);
    let t0 = Instant::now();
    let outcome = pool.reclaim(now_ns());
    let seconds = t0.elapsed().as_secs_f64();
    let (_, after) = space(&pool);
    match outcome {
        Ok(report) => println!(
            "RECLAIM ok seconds={seconds:.1} zones_reset={} stripes_reset={} \
             bytes_reclaimed={} capacity_bytes={capacity} allocated_before_bytes={before} \
             allocated_after_bytes={after} tx={}",
            report.zones_reset, report.stripes_reset, report.bytes_reclaimed, report.tx_id
        ),
        Err(error) => println!(
            "RECLAIM failed seconds={seconds:.1} error={:?} capacity_bytes={capacity} \
             allocated_before_bytes={before} allocated_after_bytes={after}",
            error.to_string()
        ),
    }
    Ok(())
}

fn rss_kib() -> (u64, u64) {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let field = |key: &str| {
            status
                .lines()
                .find(|line| line.starts_with(key))
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0)
        };
        (field("VmRSS:"), field("VmHWM:"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        (0, 0)
    }
}

fn ensure_dir(pool: &mut Pool<Dev>, parent: u64, name: &str) -> Result<u64, String> {
    match pool.lookup(parent, name) {
        Ok(entry) if entry.kind == EntryKind::Directory => Ok(entry.inode),
        Ok(_) => Err(format!("{name} exists and is not a directory")),
        Err(ScaleFsError::NotFound) => pool
            .mkdir(parent, name, 0o755, now_ns())
            .map_err(|e| format!("mkdir {name}: {e}")),
        Err(e) => Err(format!("lookup {name}: {e}")),
    }
}

fn space(pool: &Pool<Dev>) -> (u64, u64) {
    let mut capacity = 0u64;
    let mut free = 0u64;
    for allocator in pool.allocators() {
        capacity += allocator.geometry().capacity_bytes();
        let zone_size = allocator.geometry().zone_size;
        for zone in allocator.zones() {
            if zone.class.is_none() && allocator.is_usable_zone(zone.zone_index) {
                free += zone_size;
            }
        }
    }
    (capacity, capacity - free)
}

fn class_bytes(pool: &Pool<Dev>) -> (u64, u64, u64) {
    let (mut data, mut metadata, mut parity) = (0u64, 0u64, 0u64);
    for allocator in pool.allocators() {
        for zone in allocator.zones() {
            match zone.class {
                Some(ZoneClass::Data) => data += zone.write_pointer,
                Some(ZoneClass::Metadata) => metadata += zone.write_pointer,
                Some(ZoneClass::Parity) => parity += zone.write_pointer,
                None => {}
            }
        }
    }
    (data, metadata, parity)
}

fn fill(
    images: &str,
    files: u64,
    size: usize,
    start: u64,
    fanout: u64,
    commit_every: u64,
) -> Result<(), String> {
    let t_open = Instant::now();
    let mut pool = open_pool(images)?;
    let opened = t_open.elapsed().as_secs_f64();
    let top = ensure_dir(&mut pool, ROOT_INODE, "scale")?;
    let mut data = vec![0x5Au8; size];
    let t0 = Instant::now();
    let mut last = Instant::now();
    let mut dir = 0u64;
    let mut dir_index = u64::MAX;
    let mut since_commit = 0u64;
    let mut commit_seconds = 0f64;
    let mut commits = 0u64;
    for i in start..files {
        let d = i / fanout;
        if d != dir_index {
            dir = ensure_dir(&mut pool, top, &format!("d{d:07}"))?;
            dir_index = d;
        }
        let inode = pool
            .create_file(dir, &format!("f{i:010}"), 0o644, now_ns())
            .map_err(|e| format!("create file {i}: {e}"))?;
        if size > 0 {
            let stamp = i.to_le_bytes();
            let n = stamp.len().min(size);
            data[..n].copy_from_slice(&stamp[..n]);
            pool.write(inode, 0, &data, now_ns())
                .map_err(|e| format!("write file {i}: {e}"))?;
        }
        since_commit += 1;
        if since_commit >= commit_every {
            let tc = Instant::now();
            pool.commit(AllocPurpose::Normal, now_ns())
                .map_err(|e| format!("commit after file {i}: {e}"))?;
            commit_seconds += tc.elapsed().as_secs_f64();
            commits += 1;
            since_commit = 0;
        }
        if last.elapsed() >= PROGRESS {
            last = Instant::now();
            let done = i + 1 - start;
            let seconds = t0.elapsed().as_secs_f64();
            let (rss, _) = rss_kib();
            println!(
                "progress files={} written_gib={:.1} files_per_s={:.0} mib_per_s={:.0} rss_mib={}",
                i + 1,
                (done as f64 * size as f64) / (1u64 << 30) as f64,
                done as f64 / seconds,
                done as f64 * size as f64 / MIB as f64 / seconds,
                rss / 1024
            );
        }
    }
    let tc = Instant::now();
    pool.commit(AllocPurpose::Normal, now_ns())
        .map_err(|e| format!("final commit: {e}"))?;
    commit_seconds += tc.elapsed().as_secs_f64();
    commits += 1;
    let seconds = t0.elapsed().as_secs_f64();
    let done = files.saturating_sub(start);
    let (capacity, allocated) = space(&pool);
    let (rss, peak) = rss_kib();
    println!(
        "FILL files={files} added={done} size={size} seconds={seconds:.1} open_seconds={opened:.2} \
         files_per_s={:.0} mib_per_s={:.0} commits={commits} commit_seconds={commit_seconds:.1} \
         capacity_bytes={capacity} allocated_bytes={allocated} rss_kib={rss} peak_kib={peak} tx={}",
        done as f64 / seconds.max(1e-9),
        done as f64 * size as f64 / MIB as f64 / seconds.max(1e-9),
        pool.committed_tx()
    );
    Ok(())
}

fn cache_fields(pool: &Pool<Dev>) -> String {
    let stats = pool.metadata_cache();
    format!(
        "cache_budget_kib={} cache_clean_kib={} pages_loaded={} pages_pinned={} page_reads={} \
         pages_evicted={}",
        stats.budget_bytes >> 10,
        stats.clean_bytes >> 10,
        stats.loaded_pages,
        stats.pinned_pages,
        stats.page_reads,
        stats.pages_evicted
    )
}

fn open(images: &str, walk: bool, lookups: u64, files: u64, fanout: u64) -> Result<(), String> {
    let before = rss_kib();
    let t0 = Instant::now();
    let pool = open_pool(images)?;
    let seconds = t0.elapsed().as_secs_f64();
    let after = rss_kib();
    let (capacity, allocated) = space(&pool);
    println!(
        "OPEN seconds={seconds:.3} rss_before_kib={} rss_after_kib={} peak_kib={} \
         capacity_bytes={capacity} allocated_bytes={allocated} tx={} {}",
        before.0,
        after.0,
        after.1,
        pool.committed_tx(),
        cache_fields(&pool)
    );
    if walk {
        let t0 = Instant::now();
        let items = pool.tree().item_count().map_err(|e| format!("walk: {e}"))?;
        let seconds = t0.elapsed().as_secs_f64();
        let (rss, peak) = rss_kib();
        println!(
            "WALK items={items} seconds={seconds:.1} rss_kib={rss} peak_kib={peak} {}",
            cache_fields(&pool)
        );
        let census = pool.tree_census().map_err(|e| format!("census: {e}"))?;
        println!(
            "TREE items={} leaf_pages={} internal_pages={} page_bytes={} page_disk_bytes={} \
             runs={} run_records={}",
            census.items,
            census.leaf_pages,
            census.internal_pages,
            census.page_bytes,
            census.page_disk_bytes,
            census.runs,
            census.run_records
        );
        let (data, metadata, parity) = class_bytes(&pool);
        println!(
            "SPACE data_bytes={data} metadata_bytes={metadata} parity_bytes={parity} \
             allocated_bytes={allocated}"
        );
    }
    if lookups > 0 && files > 0 {
        let top = pool
            .lookup(ROOT_INODE, "scale")
            .map_err(|e| format!("lookup /scale: {e}"))?
            .inode;
        let mut rng = Rng(0x5CA1_E5EE_D000_0001);
        let mut samples = Vec::with_capacity(lookups as usize);
        let t0 = Instant::now();
        for _ in 0..lookups {
            let i = rng.next() % files;
            let t = Instant::now();
            let dir = pool
                .lookup(top, &format!("d{:07}", i / fanout))
                .map_err(|e| format!("lookup directory of file {i}: {e}"))?
                .inode;
            let file = pool
                .lookup(dir, &format!("f{i:010}"))
                .map_err(|e| format!("lookup file {i}: {e}"))?
                .inode;
            pool.getattr(file)
                .map_err(|e| format!("getattr file {i}: {e}"))?;
            samples.push(t.elapsed().as_secs_f64() * 1e6);
        }
        let seconds = t0.elapsed().as_secs_f64();
        samples.sort_by(f64::total_cmp);
        let at = |q: f64| samples[((samples.len() - 1) as f64 * q) as usize];
        let (rss, peak) = rss_kib();
        println!(
            "LOOKUPS n={lookups} seconds={seconds:.1} p50_us={:.1} p99_us={:.1} max_us={:.1} \
             rss_kib={rss} peak_kib={peak} {}",
            at(0.5),
            at(0.99),
            at(1.0),
            cache_fields(&pool)
        );
    }
    Ok(())
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

fn out_of_space(error: &ScaleFsError) -> bool {
    matches!(error, ScaleFsError::OutOfSpace)
}

fn leak(
    images: &str,
    file_size: u64,
    min: usize,
    max: usize,
    commit_every: u64,
    seed: u64,
) -> Result<(), String> {
    if file_size == 0 || min == 0 || max < min || max as u64 > file_size {
        return Err("leak needs --file-size and 0 < --min <= --max <= --file-size".to_string());
    }
    let mut pool = open_pool(images)?;
    let file = pool
        .create_file(ROOT_INODE, "leak.bin", 0o644, now_ns())
        .map_err(|e| format!("create: {e}"))?;
    let chunk = vec![0x5Au8; MIB];
    let t0 = Instant::now();
    let mut last = Instant::now();
    let mut offset = 0u64;
    while offset < file_size {
        let len = (file_size - offset).min(MIB as u64) as usize;
        pool.write(file, offset, &chunk[..len], now_ns())
            .map_err(|e| format!("fill at {offset}: {e}"))?;
        offset += len as u64;
        if offset.is_multiple_of(1 << 30) {
            pool.commit(AllocPurpose::Normal, now_ns())
                .map_err(|e| format!("fill commit at {offset}: {e}"))?;
        }
        if last.elapsed() >= PROGRESS {
            last = Instant::now();
            println!(
                "progress filled_gib={:.1} mib_per_s={:.0}",
                offset as f64 / (1u64 << 30) as f64,
                offset as f64 / MIB as f64 / t0.elapsed().as_secs_f64()
            );
        }
    }
    pool.commit(AllocPurpose::Normal, now_ns())
        .map_err(|e| format!("fill commit: {e}"))?;
    let filled_seconds = t0.elapsed().as_secs_f64();
    let (capacity, allocated_full) = space(&pool);
    println!(
        "LEAK-FILLED file_bytes={file_size} seconds={filled_seconds:.1} capacity_bytes={capacity} \
         allocated_bytes={allocated_full}"
    );
    let mut rng = Rng(seed | 1);
    let span = (max - min + 1) as u64;
    let mut overwrites = 0u64;
    let mut overwritten = 0u64;
    let mut since_commit = 0u64;
    let t1 = Instant::now();
    let mut last = Instant::now();
    let stopped_by = loop {
        let len = min + (rng.next() % span) as usize;
        let at = rng.next() % (file_size - len as u64 + 1);
        match pool.write(file, at, &chunk[..len], now_ns()) {
            Ok(()) => {}
            Err(error) if out_of_space(&error) => break format!("write: {error}"),
            Err(error) => return Err(format!("overwrite {overwrites}: {error}")),
        }
        overwrites += 1;
        overwritten += len as u64;
        since_commit += 1;
        if since_commit >= commit_every {
            since_commit = 0;
            match pool.commit(AllocPurpose::Normal, now_ns()) {
                Ok(_) => {}
                Err(error) if out_of_space(&error) => break format!("commit: {error}"),
                Err(error) => return Err(format!("commit after {overwrites}: {error}")),
            }
        }
        if last.elapsed() >= PROGRESS {
            last = Instant::now();
            let (_, allocated) = space(&pool);
            println!(
                "progress overwrites={overwrites} overwritten_gib={:.1} allocated_gib={:.1}",
                overwritten as f64 / (1u64 << 30) as f64,
                allocated as f64 / (1u64 << 30) as f64
            );
        }
    };
    let (capacity, allocated) = space(&pool);
    let attrs = pool.getattr(file).map_err(|e| format!("getattr: {e}"))?;
    let (rss, peak) = rss_kib();
    println!(
        "LEAK stopped_by={stopped_by:?} overwrites={overwrites} overwritten_bytes={overwritten} \
         seconds={:.1} file_bytes={} capacity_bytes={capacity} allocated_bytes={allocated} \
         allocated_after_fill_bytes={allocated_full} rss_kib={rss} peak_kib={peak} tx={}",
        t1.elapsed().as_secs_f64(),
        attrs.size,
        pool.committed_tx()
    );
    Ok(())
}
