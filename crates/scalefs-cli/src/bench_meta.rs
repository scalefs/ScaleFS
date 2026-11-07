use std::sync::Arc;
use std::time::Instant;

use scalefs_core::{AllocPurpose, AnyBlockDevice, EntryKind, Pool, ROOT_INODE, ScaleFsError};

use crate::util::{Opts, now_ns, parse_size};

type Dev = Arc<AnyBlockDevice>;

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

const USAGE: &str = "usage: scalefs bench-meta <image[,image...]> [--shape flat|tree] \
    [--entries <n>] [--step <n>] [--fanout <n>] [--commit-every <n>] [--samples <n>] \
    [--name <ascii|long|unicode>] [--reopen] [--keep] [--no-unlink] [--no-paged] \
    [--paged-max <n>] [--cache <MiB>] | bench-meta --open-only <image[,image...]>";

const DP_BATCH: usize = 2048;

struct Params {
    images: String,
    tree: bool,
    entries: u64,
    step: u64,
    fanout: u64,
    commit_every: u64,
    samples: usize,
    name_style: String,
    reopen: bool,
    keep: bool,
    unlink: bool,
    paged: bool,
    paged_max: u64,
}

pub fn cmd_bench_meta(args: &[String]) -> Result<(), String> {
    if args.first().map(String::as_str) == Some("--open-only") {
        let [_, images] = args else {
            return Err(USAGE.to_string());
        };
        return open_only(images);
    }
    let opts = Opts::parse(
        args,
        &["reopen", "keep", "no-unlink", "no-paged"],
        &[
            "shape",
            "entries",
            "step",
            "fanout",
            "commit-every",
            "samples",
            "name",
            "paged-max",
            "cache",
        ],
    )?;
    let [images] = opts.positional.as_slice() else {
        return Err(USAGE.to_string());
    };
    if let Some(text) = opts.value("cache") {
        let mib: usize = text
            .parse()
            .map_err(|_| format!("--cache: '{text}' is not a whole number of MiB"))?;
        scalefs_core::set_default_metadata_cache(mib << 20);
    }
    let number = |name: &str, default: u64| -> Result<u64, String> {
        match opts.value(name) {
            None => Ok(default),
            Some(text) => parse_size(text).and_then(|v| {
                if v == 0 {
                    Err(format!("--{name} must be at least 1"))
                } else {
                    Ok(v)
                }
            }),
        }
    };
    let params = Params {
        images: images.clone(),
        tree: match opts.value("shape").unwrap_or("flat") {
            "flat" => false,
            "tree" => true,
            other => return Err(format!("unknown shape '{other}'")),
        },
        entries: number("entries", 100_000)?,
        step: number("step", 10_000)?,
        fanout: number("fanout", 1000)?,
        commit_every: number("commit-every", 1000)?,
        samples: number("samples", 2000)? as usize,
        name_style: opts.value("name").unwrap_or("ascii").to_string(),
        reopen: opts.flag("reopen"),
        keep: opts.flag("keep"),
        unlink: !opts.flag("no-unlink"),
        paged: !opts.flag("no-paged"),
        paged_max: number("paged-max", u64::MAX)?,
    };
    run(&params)
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
    #[cfg(windows)]
    {
        win_mem::working_set_kib()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        (0, 0)
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod win_mem {
    #[repr(C)]
    #[derive(Default)]
    struct Counters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set: usize,
        working_set: usize,
        quota_peak_paged: usize,
        quota_paged: usize,
        quota_peak_nonpaged: usize,
        quota_nonpaged: usize,
        pagefile: usize,
        peak_pagefile: usize,
    }
    #[link(name = "kernel32", kind = "raw-dylib")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> isize;
        fn K32GetProcessMemoryInfo(process: isize, counters: *mut Counters, cb: u32) -> i32;
    }
    pub fn working_set_kib() -> (u64, u64) {
        let mut counters = Counters {
            cb: core::mem::size_of::<Counters>() as u32,
            ..Default::default()
        };
        let ok =
            unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, counters.cb) };
        if ok == 0 {
            return (0, 0);
        }
        (
            (counters.working_set / 1024) as u64,
            (counters.peak_working_set / 1024) as u64,
        )
    }
}

fn name_of(style: &str, index: u64) -> String {
    match style {
        "long" => format!(
            "IMG_20261102_{:06}_{:08}_final-edit.jpg",
            index % 1_000_000,
            index
        ),
        "unicode" => format!("Résumé-Ångström-Ωmega-{index:08}.txt"),
        _ => format!("document-{index:08}.txt"),
    }
}

fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

fn pct(sorted_us: &[f64], q: f64) -> f64 {
    if sorted_us.is_empty() {
        return 0.0;
    }
    sorted_us[((sorted_us.len() - 1) as f64 * q).round() as usize]
}

fn summary(mut v: Vec<f64>) -> (f64, f64, f64) {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    (pct(&v, 0.5), pct(&v, 0.99), pct(&v, 1.0))
}

#[derive(Default)]
struct CommitStats {
    count: u64,
    seconds: f64,
    bytes: u64,
    writes: u64,
    max_seconds: f64,
}

fn commit(pool: &mut Pool<Dev>, stats: &mut CommitStats) -> Result<(), String> {
    let t0 = Instant::now();
    let ticket = pool
        .commit_plan(AllocPurpose::Normal, now_ns())
        .map_err(|e| format!("commit plan: {e}"))?;
    let (writes, bytes) = ticket.planned_io();
    match ticket.execute() {
        Ok(done) => {
            pool.commit_publish(done);
        }
        Err(aborted) => {
            let error = aborted.error().to_string();
            let _ = pool.commit_abandon(aborted);
            return Err(format!("commit execute: {error}"));
        }
    }
    let seconds = t0.elapsed().as_secs_f64();
    stats.count += 1;
    stats.seconds += seconds;
    stats.bytes += bytes;
    stats.writes += writes;
    stats.max_seconds = stats.max_seconds.max(seconds);
    Ok(())
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

fn paged_listing(pool: &Pool<Dev>, dir: u64) -> Result<(u64, u64, f64), String> {
    let t0 = Instant::now();
    let mut cookie = 0u64;
    let mut total = 0u64;
    let mut batches = 0u64;
    loop {
        let entries = pool
            .readdir_hashed(dir)
            .map_err(|e| format!("readdir_hashed: {e}"))?;
        batches += 1;
        let mut emitted = 0usize;
        let mut next = 0u64;
        let mut current: Option<u64> = None;
        for hashed in entries.iter().filter(|h| h.hash >= cookie) {
            let new_bucket = current != Some(hashed.hash);
            if new_bucket && emitted >= DP_BATCH {
                next = hashed.hash;
                break;
            }
            let _ = pool.getattr(hashed.entry.inode);
            emitted += 1;
            current = Some(hashed.hash);
        }
        total += emitted as u64;
        if next == 0 {
            break;
        }
        cookie = next;
    }
    Ok((total, batches, t0.elapsed().as_secs_f64()))
}

fn open_only(images: &str) -> Result<(), String> {
    let before = rss_kib();
    let t0 = Instant::now();
    let pool = open_pool(images)?;
    let seconds = t0.elapsed().as_secs_f64();
    let after = rss_kib();
    println!(
        "OPEN seconds={seconds:.3} rss_before_kib={} rss_after_kib={} peak_kib={} tx={}",
        before.0,
        after.0,
        after.1,
        pool.committed_tx()
    );
    Ok(())
}

fn reopen_cost(images: &str) -> String {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(e) => return format!("reopen_error={e}"),
    };
    match std::process::Command::new(exe)
        .args(["bench-meta", "--open-only", images])
        .output()
    {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            match text.lines().find(|l| l.starts_with("OPEN ")) {
                Some(line) => line
                    .trim_start_matches("OPEN ")
                    .split_whitespace()
                    .map(|kv| format!("reopen_{kv}"))
                    .collect::<Vec<_>>()
                    .join(" "),
                None => format!(
                    "reopen_error={}",
                    String::from_utf8_lossy(&out.stderr)
                        .trim()
                        .replace(' ', "_")
                ),
            }
        }
        Err(e) => format!("reopen_error={e}"),
    }
}

fn run(params: &Params) -> Result<(), String> {
    let t_open = Instant::now();
    let mut pool = open_pool(&params.images)?;
    println!(
        "BENCH-META shape={} entries={} step={} fanout={} commit_every={} samples={} name={} open_s={:.3} rss_kib={}",
        if params.tree { "tree" } else { "flat" },
        params.entries,
        params.step,
        params.fanout,
        params.commit_every,
        params.samples,
        params.name_style,
        t_open.elapsed().as_secs_f64(),
        rss_kib().0
    );
    let root_dir = ensure_dir(&mut pool, ROOT_INODE, "benchmeta")?;
    let mut cstats = CommitStats::default();
    commit(&mut pool, &mut cstats)?;

    let mut dirs: Vec<(u64, u64)> = Vec::new();
    let mut created = 0u64;
    let mut since_commit = 0u64;
    while created < params.entries {
        let step_end = (created + params.step).min(params.entries);
        let step_start = created;
        let mut create_us = Vec::with_capacity((step_end - created) as usize);
        let mut step_commits = CommitStats::default();
        let t_step = Instant::now();
        while created < step_end {
            let dir = if params.tree {
                if dirs.last().is_none_or(|(_, n)| *n >= params.fanout) {
                    let name = format!("d{:06}", dirs.len());
                    let inode = pool
                        .mkdir(root_dir, &name, 0o755, now_ns())
                        .map_err(|e| format!("mkdir {name}: {e}"))?;
                    dirs.push((inode, 0));
                }
                let last = dirs.last_mut().expect("pushed above");
                last.1 += 1;
                last.0
            } else {
                root_dir
            };
            let name = name_of(&params.name_style, created);
            let t0 = Instant::now();
            pool.create_file(dir, &name, 0o644, now_ns())
                .map_err(|e| format!("create {name}: {e}"))?;
            create_us.push(t0.elapsed().as_secs_f64() * 1e6);
            created += 1;
            since_commit += 1;
            if since_commit >= params.commit_every {
                commit(&mut pool, &mut step_commits)?;
                since_commit = 0;
            }
        }
        if since_commit > 0 {
            commit(&mut pool, &mut step_commits)?;
            since_commit = 0;
        }
        let step_seconds = t_step.elapsed().as_secs_f64();
        let (c50, c99, cmax) = summary(create_us);

        let n = created;
        let dir_of = |i: u64| -> u64 {
            if params.tree {
                dirs[(i / params.fanout) as usize].0
            } else {
                root_dir
            }
        };
        let mut hit_us = Vec::with_capacity(params.samples);
        let mut miss_us = Vec::with_capacity(params.samples);
        let mut stat_us = Vec::with_capacity(params.samples);
        let mut inodes = Vec::with_capacity(params.samples);
        for s in 0..params.samples as u64 {
            let i = mix(s ^ (n << 20)) % n;
            let name = name_of(&params.name_style, i);
            let parent = dir_of(i);
            let t0 = Instant::now();
            let entry = pool
                .lookup(parent, &name)
                .map_err(|e| format!("lookup {name}: {e}"))?;
            hit_us.push(t0.elapsed().as_secs_f64() * 1e6);
            inodes.push(entry.inode);
            let missing = format!("missing-{:08}.txt", mix(s) % 100_000_000);
            let t0 = Instant::now();
            let _ = pool.lookup(parent, &missing);
            miss_us.push(t0.elapsed().as_secs_f64() * 1e6);
        }
        for inode in &inodes {
            let t0 = Instant::now();
            pool.getattr(*inode).map_err(|e| format!("getattr: {e}"))?;
            stat_us.push(t0.elapsed().as_secs_f64() * 1e6);
        }
        let (l50, l99, _) = summary(hit_us);
        let (m50, m99, _) = summary(miss_us);
        let (s50, s99, _) = summary(stat_us);

        let list_dir = if params.tree {
            dirs.last().map(|(inode, _)| *inode).unwrap_or(root_dir)
        } else {
            root_dir
        };
        let t0 = Instant::now();
        let sorted = pool
            .readdir(list_dir)
            .map_err(|e| format!("readdir: {e}"))?;
        let readdir_s = t0.elapsed().as_secs_f64();
        let t0 = Instant::now();
        let hashed = pool
            .readdir_hashed(list_dir)
            .map_err(|e| format!("readdir_hashed: {e}"))?;
        let hashed_s = t0.elapsed().as_secs_f64();
        let listed = sorted.len();
        drop(sorted);
        drop(hashed);
        let paged = if params.paged && (listed as u64) <= params.paged_max {
            let (entries, batches, seconds) = paged_listing(&pool, list_dir)?;
            format!("paged_entries={entries} paged_batches={batches} paged_s={seconds:.4}")
        } else {
            "paged=skipped".to_string()
        };
        let (rss, peak) = rss_kib();
        let reopen = if params.reopen {
            drop(pool);
            let child = reopen_cost(&params.images);
            let t0 = Instant::now();
            pool = open_pool(&params.images)?;
            format!("{child} parent_reopen_s={:.3}", t0.elapsed().as_secs_f64())
        } else {
            String::new()
        };
        println!(
            "STEP n={n} step_s={step_seconds:.3} create_per_s={:.0} create_us_p50={c50:.1} \
             create_us_p99={c99:.1} create_us_max={cmax:.0} commits={} commit_ms_avg={:.2} \
             commit_ms_max={:.1} commit_kib_avg={:.1} commit_writes_avg={:.1} \
             lookup_us_p50={l50:.2} lookup_us_p99={l99:.2} miss_us_p50={m50:.2} miss_us_p99={m99:.2} \
             getattr_us_p50={s50:.2} getattr_us_p99={s99:.2} list_entries={listed} \
             readdir_s={readdir_s:.4} readdir_hashed_s={hashed_s:.4} {paged} \
             rss_kib={rss} peak_kib={peak} dirs={} {reopen}",
            (step_end - step_start) as f64 / step_seconds.max(1e-9),
            step_commits.count,
            step_commits.seconds * 1e3 / step_commits.count.max(1) as f64,
            step_commits.max_seconds * 1e3,
            step_commits.bytes as f64 / 1024.0 / step_commits.count.max(1) as f64,
            step_commits.writes as f64 / step_commits.count.max(1) as f64,
            dirs.len(),
        );
    }

    if params.unlink {
        let t0 = Instant::now();
        let mut unlink_us = Vec::with_capacity(created as usize);
        let mut ustats = CommitStats::default();
        let mut since = 0u64;
        for i in 0..created {
            let parent = if params.tree {
                dirs[(i / params.fanout) as usize].0
            } else {
                root_dir
            };
            let name = name_of(&params.name_style, i);
            let t = Instant::now();
            pool.unlink(parent, &name, now_ns())
                .map_err(|e| format!("unlink {name}: {e}"))?;
            unlink_us.push(t.elapsed().as_secs_f64() * 1e6);
            since += 1;
            if since >= params.commit_every {
                commit(&mut pool, &mut ustats)?;
                since = 0;
            }
        }
        if since > 0 {
            commit(&mut pool, &mut ustats)?;
        }
        let seconds = t0.elapsed().as_secs_f64();
        let (u50, u99, umax) = summary(unlink_us);
        println!(
            "UNLINK n={created} seconds={seconds:.3} unlink_per_s={:.0} unlink_us_p50={u50:.1} \
             unlink_us_p99={u99:.1} unlink_us_max={umax:.0} commits={} commit_ms_avg={:.2} commit_kib_avg={:.1}",
            created as f64 / seconds.max(1e-9),
            ustats.count,
            ustats.seconds * 1e3 / ustats.count.max(1) as f64,
            ustats.bytes as f64 / 1024.0 / ustats.count.max(1) as f64,
        );
        if !params.keep {
            for d in 0..dirs.len() {
                let _ = pool.rmdir(root_dir, &format!("d{d:06}"), now_ns());
            }
            let _ = pool.rmdir(ROOT_INODE, "benchmeta", now_ns());
            commit(&mut pool, &mut ustats)?;
        }
    }
    Ok(())
}
