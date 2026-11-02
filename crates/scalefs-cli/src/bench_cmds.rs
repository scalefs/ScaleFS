use std::time::Instant;

use scalefs_core::{AllocPurpose, AnyBlockDevice, EntryKind, Pool, ROOT_INODE, ScaleFsError};
use scalefs_ipc::json::Value;

use crate::pool_cmds::open_pool;
use crate::util::{Opts, format_size, now_ns, parse_size};

const MAX_CHUNK: u64 = 64 << 20;

const USAGE: &str = "usage: scalefs bench <image[,image...]> \
    [--suite all|write-files|read-files|write-stream|read-stream|commit] \
    [--files <n>] [--file-size <bytes>] [--stream-size <bytes>] \
    [--chunk <bytes>] [--commits <n>] [--dir <name>] [--keep] \
    [--label <s>] [--json]";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Suite {
    WriteFiles,
    ReadFiles,
    WriteStream,
    ReadStream,
    Commit,
}

impl Suite {
    fn writes(self) -> bool {
        matches!(self, Suite::WriteFiles | Suite::WriteStream | Suite::Commit)
    }
}

#[derive(Debug)]
struct Params {
    image: String,
    suites: Vec<Suite>,
    files: u64,
    file_size: u64,
    stream_size: u64,
    chunk: u64,
    commits: u64,
    dir: String,
    keep: bool,
    label: Option<String>,
    json: bool,
}

fn parse_params(args: &[String]) -> Result<Params, String> {
    let opts = Opts::parse(
        args,
        &["keep", "json"],
        &[
            "suite",
            "files",
            "file-size",
            "stream-size",
            "chunk",
            "commits",
            "dir",
            "label",
        ],
    )?;
    let [image] = opts.positional.as_slice() else {
        return Err(USAGE.to_string());
    };
    let suites = match opts.value("suite").unwrap_or("all") {
        "all" => vec![
            Suite::WriteFiles,
            Suite::ReadFiles,
            Suite::WriteStream,
            Suite::ReadStream,
            Suite::Commit,
        ],
        "write-files" => vec![Suite::WriteFiles],
        "read-files" => vec![Suite::ReadFiles],
        "write-stream" => vec![Suite::WriteStream],
        "read-stream" => vec![Suite::ReadStream],
        "commit" => vec![Suite::Commit],
        other => return Err(format!("unknown suite '{other}' ({USAGE})")),
    };
    let number = |name: &str, default: u64| -> Result<u64, String> {
        match opts.value(name) {
            None => Ok(default),
            Some(text) => {
                let value = parse_size(text)?;
                if value == 0 {
                    return Err(format!("--{name} must be at least 1"));
                }
                Ok(value)
            }
        }
    };
    let chunk = number("chunk", 128 << 10)?;
    if chunk > MAX_CHUNK {
        return Err(format!(
            "--chunk {} exceeds the {} limit",
            format_size(chunk),
            format_size(MAX_CHUNK)
        ));
    }
    let dir = opts.value("dir").unwrap_or("bench").to_string();
    if !dir.starts_with("bench") || dir.contains('/') {
        return Err("--dir must be a root-level name starting with 'bench'".to_string());
    }
    Ok(Params {
        image: image.clone(),
        suites,
        files: number("files", 200)?,
        file_size: number("file-size", 1 << 20)?,
        stream_size: number("stream-size", 256 << 20)?,
        chunk,
        commits: number("commits", 100)?,
        dir,
        keep: opts.flag("keep"),
        label: opts.value("label").map(str::to_string),
        json: opts.flag("json"),
    })
}

#[derive(Debug, Default)]
struct SuiteResult {
    ops: u64,
    bytes: u64,
    seconds: f64,
    per_op_ms: Option<(f64, f64, f64)>,
    commit_ms: Option<f64>,
}

impl SuiteResult {
    fn mib_per_sec(&self) -> f64 {
        if self.seconds <= 0.0 {
            return 0.0;
        }
        self.bytes as f64 / (1 << 20) as f64 / self.seconds
    }

    fn ops_per_sec(&self) -> f64 {
        if self.seconds <= 0.0 {
            return 0.0;
        }
        self.ops as f64 / self.seconds
    }
}

#[derive(Debug)]
struct BenchReport {
    pool_label: String,
    members: usize,
    mirror: u16,
    block_size: u64,
    tx_before: u64,
    tx_after: u64,
    results: Vec<(Suite, SuiteResult)>,
    cleanup: Option<(u64, f64)>,
}

pub fn cmd_bench(args: &[String]) -> Result<(), String> {
    let params = parse_params(args)?;
    let mut pool = open_pool(&params.image)?;

    let needs_write = !params.keep || params.suites.iter().any(|suite| suite.writes());
    if pool.read_only() && needs_write {
        return Err(
            "the pool is read-only; only read suites with --keep can run against it".to_string(),
        );
    }

    let report = run_bench(&mut pool, &params)?;
    if params.json {
        println!("{}", report_value(&report, &params).encode());
    } else {
        print_human(&report, &params);
    }
    Ok(())
}

fn run_bench(pool: &mut Pool<AnyBlockDevice>, params: &Params) -> Result<BenchReport, String> {
    let tx_before = pool.committed_tx();
    let dir = bench_dir(pool, &params.dir, params.suites.iter().any(|s| s.writes()))?;

    let mut payload = vec![0u8; params.chunk as usize];
    fill_pattern(&mut payload, 0x5ca1ef5b);

    let mut results = Vec::new();
    for suite in &params.suites {
        let result = match suite {
            Suite::WriteFiles => suite_write_files(pool, dir, params, &payload)?,
            Suite::ReadFiles => suite_read_files(pool, dir, params)?,
            Suite::WriteStream => suite_write_stream(pool, dir, params, &payload)?,
            Suite::ReadStream => suite_read_stream(pool, dir, params)?,
            Suite::Commit => suite_commit(pool, dir, params)?,
        };
        results.push((*suite, result));
    }

    let cleanup = if params.keep {
        None
    } else {
        Some(cleanup(pool, dir, &params.dir)?)
    };

    Ok(BenchReport {
        pool_label: pool.superblock().label.clone(),
        members: pool.member_count(),
        mirror: pool.mirror_width(),
        block_size: u64::from(pool.superblock().geometry.logical_block_size),
        tx_before,
        tx_after: pool.committed_tx(),
        results,
        cleanup,
    })
}

fn bench_dir(pool: &mut Pool<AnyBlockDevice>, name: &str, may_create: bool) -> Result<u64, String> {
    match pool.lookup(ROOT_INODE, name) {
        Ok(entry) if entry.kind == EntryKind::Directory => Ok(entry.inode),
        Ok(_) => Err(format!("/{name} exists and is not a directory")),
        Err(ScaleFsError::NotFound) if may_create => {
            let now = now_ns();
            let inode = pool
                .mkdir(ROOT_INODE, name, 0o755, now)
                .map_err(|err| format!("mkdir /{name}: {err}"))?;
            pool.commit(AllocPurpose::Normal, now)
                .map_err(|err| err.to_string())?;
            Ok(inode)
        }
        Err(ScaleFsError::NotFound) => Err(format!(
            "/{name} does not exist — read suites need a prior --keep run (or run write suites first)"
        )),
        Err(err) => Err(format!("lookup /{name}: {err}")),
    }
}

fn put_file(
    pool: &mut Pool<AnyBlockDevice>,
    dir: u64,
    name: &str,
    size: u64,
    payload: &[u8],
) -> Result<u64, String> {
    let now = now_ns();
    let object = match pool.lookup(dir, name) {
        Ok(entry) if entry.kind == EntryKind::Directory => {
            return Err(format!("{name}: is a directory"));
        }
        Ok(entry) => {
            pool.truncate(entry.inode, 0, now)
                .map_err(|err| format!("truncate {name}: {err}"))?;
            entry.inode
        }
        Err(ScaleFsError::NotFound) => pool
            .create_file(dir, name, 0o644, now)
            .map_err(|err| format!("create {name}: {err}"))?,
        Err(err) => return Err(format!("lookup {name}: {err}")),
    };
    let mut offset = 0u64;
    while offset < size {
        let take = payload.len().min((size - offset) as usize);
        pool.write(object, offset, &payload[..take], now)
            .map_err(|err| format!("write {name}: {err}"))?;
        offset += take as u64;
    }
    Ok(object)
}

fn drain_file(
    pool: &Pool<AnyBlockDevice>,
    object: u64,
    size: u64,
    chunk: u64,
) -> Result<u64, String> {
    let mut offset = 0u64;
    while offset < size {
        let take = chunk.min(size - offset) as usize;
        let data = pool
            .read(object, offset, take)
            .map_err(|err| format!("read: {err}"))?;
        if data.is_empty() {
            break;
        }
        offset += data.len() as u64;
    }
    Ok(offset)
}

fn stats(samples: &[f64]) -> Option<(f64, f64, f64)> {
    if samples.is_empty() {
        return None;
    }
    let sum: f64 = samples.iter().sum();
    let min = samples.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = samples.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    Some((sum / samples.len() as f64, min, max))
}

fn suite_write_files(
    pool: &mut Pool<AnyBlockDevice>,
    dir: u64,
    params: &Params,
    payload: &[u8],
) -> Result<SuiteResult, String> {
    let mut samples = Vec::with_capacity(params.files as usize);
    let start = Instant::now();
    for index in 0..params.files {
        let t0 = Instant::now();
        put_file(pool, dir, &file_name(index), params.file_size, payload)?;
        pool.commit(AllocPurpose::Normal, now_ns())
            .map_err(|err| err.to_string())?;
        samples.push(t0.elapsed().as_secs_f64() * 1e3);
    }
    Ok(SuiteResult {
        ops: params.files,
        bytes: params.files * params.file_size,
        seconds: start.elapsed().as_secs_f64(),
        per_op_ms: stats(&samples),
        commit_ms: None,
    })
}

fn suite_read_files(
    pool: &mut Pool<AnyBlockDevice>,
    dir: u64,
    params: &Params,
) -> Result<SuiteResult, String> {
    let entries: Vec<(u64, u64)> = pool
        .readdir(dir)
        .map_err(|err| format!("readdir: {err}"))?
        .into_iter()
        .filter(|entry| entry.kind == EntryKind::File && entry.name.starts_with("f-"))
        .map(|entry| {
            let size = pool.getattr(entry.inode).map(|attrs| attrs.size);
            size.map(|size| (entry.inode, size))
        })
        .collect::<Result<_, _>>()
        .map_err(|err| format!("getattr: {err}"))?;
    if entries.is_empty() {
        return Err("read-files: no f-* files present (run write-files first)".to_string());
    }
    let mut samples = Vec::with_capacity(entries.len());
    let mut bytes = 0u64;
    let start = Instant::now();
    for (object, size) in &entries {
        let t0 = Instant::now();
        bytes += drain_file(pool, *object, *size, params.chunk)?;
        samples.push(t0.elapsed().as_secs_f64() * 1e3);
    }
    Ok(SuiteResult {
        ops: entries.len() as u64,
        bytes,
        seconds: start.elapsed().as_secs_f64(),
        per_op_ms: stats(&samples),
        commit_ms: None,
    })
}

fn suite_write_stream(
    pool: &mut Pool<AnyBlockDevice>,
    dir: u64,
    params: &Params,
    payload: &[u8],
) -> Result<SuiteResult, String> {
    let start = Instant::now();
    put_file(pool, dir, "stream.bin", params.stream_size, payload)?;
    let write_seconds = start.elapsed().as_secs_f64();
    let t0 = Instant::now();
    pool.commit(AllocPurpose::Normal, now_ns())
        .map_err(|err| err.to_string())?;
    Ok(SuiteResult {
        ops: 1,
        bytes: params.stream_size,
        seconds: write_seconds,
        per_op_ms: None,
        commit_ms: Some(t0.elapsed().as_secs_f64() * 1e3),
    })
}

fn suite_read_stream(
    pool: &mut Pool<AnyBlockDevice>,
    dir: u64,
    params: &Params,
) -> Result<SuiteResult, String> {
    let entry = match pool.lookup(dir, "stream.bin") {
        Ok(entry) => entry,
        Err(ScaleFsError::NotFound) => {
            return Err("read-stream: no stream.bin (run write-stream first)".to_string());
        }
        Err(err) => return Err(format!("lookup stream.bin: {err}")),
    };
    let size = pool
        .getattr(entry.inode)
        .map_err(|err| format!("getattr: {err}"))?
        .size;
    let start = Instant::now();
    let bytes = drain_file(pool, entry.inode, size, params.chunk)?;
    Ok(SuiteResult {
        ops: 1,
        bytes,
        seconds: start.elapsed().as_secs_f64(),
        per_op_ms: None,
        commit_ms: None,
    })
}

fn suite_commit(
    pool: &mut Pool<AnyBlockDevice>,
    dir: u64,
    params: &Params,
) -> Result<SuiteResult, String> {
    let mut samples = Vec::with_capacity(params.commits as usize);
    let start = Instant::now();
    for index in 0..params.commits {
        let now = now_ns();
        let name = format!("c-{index:04}");
        match pool.lookup(dir, &name) {
            Ok(_) => {}
            Err(ScaleFsError::NotFound) => {
                pool.create_file(dir, &name, 0o644, now)
                    .map_err(|err| format!("create {name}: {err}"))?;
            }
            Err(err) => return Err(format!("lookup {name}: {err}")),
        }
        let t0 = Instant::now();
        pool.commit(AllocPurpose::Normal, now)
            .map_err(|err| err.to_string())?;
        samples.push(t0.elapsed().as_secs_f64() * 1e3);
    }
    Ok(SuiteResult {
        ops: params.commits,
        bytes: 0,
        seconds: start.elapsed().as_secs_f64(),
        per_op_ms: stats(&samples),
        commit_ms: None,
    })
}

fn cleanup(
    pool: &mut Pool<AnyBlockDevice>,
    dir: u64,
    dir_name: &str,
) -> Result<(u64, f64), String> {
    let start = Instant::now();
    let victims: Vec<String> = pool
        .readdir(dir)
        .map_err(|err| format!("readdir: {err}"))?
        .into_iter()
        .filter(|entry| {
            entry.kind == EntryKind::File
                && (entry.name.starts_with("f-")
                    || entry.name.starts_with("c-")
                    || entry.name == "stream.bin")
        })
        .map(|entry| entry.name)
        .collect();
    let now = now_ns();
    for name in &victims {
        pool.unlink(dir, name, now)
            .map_err(|err| format!("unlink {name}: {err}"))?;
    }
    let empty = pool
        .readdir(dir)
        .map_err(|err| format!("readdir: {err}"))?
        .is_empty();
    if empty {
        pool.rmdir(ROOT_INODE, dir_name, now)
            .map_err(|err| format!("rmdir /{dir_name}: {err}"))?;
    }
    pool.commit(AllocPurpose::Reclaim, now)
        .map_err(|err| err.to_string())?;
    Ok((victims.len() as u64, start.elapsed().as_secs_f64()))
}

fn file_name(index: u64) -> String {
    format!("f-{index:05}")
}

fn fill_pattern(buf: &mut [u8], seed: u64) {
    let mut state = seed | 1;
    for chunk in buf.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
    }
}

fn suite_name(suite: Suite) -> &'static str {
    match suite {
        Suite::WriteFiles => "write-files",
        Suite::ReadFiles => "read-files",
        Suite::WriteStream => "write-stream",
        Suite::ReadStream => "read-stream",
        Suite::Commit => "commit",
    }
}

fn print_human(report: &BenchReport, params: &Params) {
    let mirror = if report.mirror > 1 {
        format!(", {}-way mirror", report.mirror)
    } else {
        String::new()
    };
    println!(
        "bench: pool '{}' — {} member(s){mirror}, block {}, tx {} → {}",
        report.pool_label,
        report.members,
        format_size(report.block_size),
        report.tx_before,
        report.tx_after,
    );
    for (suite, result) in &report.results {
        let name = suite_name(*suite);
        match suite {
            Suite::WriteFiles | Suite::ReadFiles => {
                let (mean, min, max) = result.per_op_ms.unwrap_or((0.0, 0.0, 0.0));
                println!(
                    "  {name:<12} {} × {} (chunk {}) — {:.1} MiB/s, {:.1} files/s, {mean:.1} ms/file (min {min:.1}, max {max:.1})",
                    result.ops,
                    format_size(result.bytes / result.ops.max(1)),
                    format_size(params.chunk),
                    result.mib_per_sec(),
                    result.ops_per_sec(),
                );
            }
            Suite::WriteStream => {
                println!(
                    "  {name:<12} {} (chunk {}) — {:.1} MiB/s write + {:.1} ms commit",
                    format_size(result.bytes),
                    format_size(params.chunk),
                    result.mib_per_sec(),
                    result.commit_ms.unwrap_or(0.0),
                );
            }
            Suite::ReadStream => {
                println!(
                    "  {name:<12} {} (chunk {}) — {:.1} MiB/s",
                    format_size(result.bytes),
                    format_size(params.chunk),
                    result.mib_per_sec(),
                );
            }
            Suite::Commit => {
                let (mean, min, max) = result.per_op_ms.unwrap_or((0.0, 0.0, 0.0));
                println!(
                    "  {name:<12} {} × create+commit — {mean:.1} ms/commit (min {min:.1}, max {max:.1})",
                    result.ops,
                );
            }
        }
    }
    match report.cleanup {
        Some((files, seconds)) => {
            println!("  cleanup: {files} file(s) reclaimed in {seconds:.1} s")
        }
        None => println!("  kept: bench files left in place (--keep)"),
    }
}

fn micros(ms: f64) -> Value {
    Value::Int((ms * 1e3).round() as i128)
}

fn report_value(report: &BenchReport, params: &Params) -> Value {
    let mut suites = Vec::new();
    for (suite, result) in &report.results {
        let mut fields = vec![
            ("ops".to_string(), Value::Int(i128::from(result.ops))),
            ("bytes".to_string(), Value::Int(i128::from(result.bytes))),
            (
                "seconds_us".to_string(),
                Value::Int((result.seconds * 1e6).round() as i128),
            ),
            (
                "bytes_per_sec".to_string(),
                Value::Int(if result.seconds > 0.0 {
                    (result.bytes as f64 / result.seconds).round() as i128
                } else {
                    0
                }),
            ),
        ];
        if let Some((mean, min, max)) = result.per_op_ms {
            fields.push(("per_op_mean_us".to_string(), micros(mean)));
            fields.push(("per_op_min_us".to_string(), micros(min)));
            fields.push(("per_op_max_us".to_string(), micros(max)));
        }
        if let Some(commit) = result.commit_ms {
            fields.push(("commit_us".to_string(), micros(commit)));
        }
        suites.push((suite_name(*suite).to_string(), Value::Object(fields)));
    }
    let cleanup = match report.cleanup {
        Some((files, seconds)) => Value::Object(vec![
            ("files".to_string(), Value::Int(i128::from(files))),
            (
                "seconds_us".to_string(),
                Value::Int((seconds * 1e6).round() as i128),
            ),
        ]),
        None => Value::Null,
    };
    Value::Object(vec![
        ("tool".to_string(), Value::Str("scalefs-bench".to_string())),
        (
            "version".to_string(),
            Value::Str(env!("CARGO_PKG_VERSION").to_string()),
        ),
        ("date_ns".to_string(), Value::Int(i128::from(now_ns()))),
        ("image".to_string(), Value::Str(params.image.clone())),
        (
            "label".to_string(),
            match &params.label {
                Some(label) => Value::Str(label.clone()),
                None => Value::Null,
            },
        ),
        (
            "pool".to_string(),
            Value::Object(vec![
                ("label".to_string(), Value::Str(report.pool_label.clone())),
                ("members".to_string(), Value::Int(report.members as i128)),
                ("mirror".to_string(), Value::Int(i128::from(report.mirror))),
                (
                    "block_size".to_string(),
                    Value::Int(i128::from(report.block_size)),
                ),
                (
                    "tx_before".to_string(),
                    Value::Int(i128::from(report.tx_before)),
                ),
                (
                    "tx_after".to_string(),
                    Value::Int(i128::from(report.tx_after)),
                ),
            ]),
        ),
        (
            "params".to_string(),
            Value::Object(vec![
                ("files".to_string(), Value::Int(i128::from(params.files))),
                (
                    "file_size".to_string(),
                    Value::Int(i128::from(params.file_size)),
                ),
                (
                    "stream_size".to_string(),
                    Value::Int(i128::from(params.stream_size)),
                ),
                ("chunk".to_string(), Value::Int(i128::from(params.chunk))),
                (
                    "commits".to_string(),
                    Value::Int(i128::from(params.commits)),
                ),
                ("dir".to_string(), Value::Str(params.dir.clone())),
                ("keep".to_string(), Value::Bool(params.keep)),
            ]),
        ),
        ("suites".to_string(), Value::Object(suites)),
        ("cleanup".to_string(), cleanup),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn params_parse_defaults_and_refusals() {
        let params = parse_params(&strings(&["pool.img"])).unwrap();
        assert_eq!(params.files, 200);
        assert_eq!(params.file_size, 1 << 20);
        assert_eq!(params.stream_size, 256 << 20);
        assert_eq!(params.chunk, 128 << 10);
        assert_eq!(params.commits, 100);
        assert_eq!(params.dir, "bench");
        assert_eq!(params.suites.len(), 5);
        assert!(!params.keep);
        assert!(!params.json);

        let params = parse_params(&strings(&[
            "a.img,b.img",
            "--suite",
            "read-stream",
            "--chunk",
            "1M",
            "--keep",
            "--json",
        ]))
        .unwrap();
        assert_eq!(params.image, "a.img,b.img");
        assert_eq!(params.suites, vec![Suite::ReadStream]);
        assert_eq!(params.chunk, 1 << 20);
        assert!(params.keep && params.json);

        assert!(parse_params(&strings(&[])).is_err());
        assert!(parse_params(&strings(&["x.img", "--suite", "nope"])).is_err());
        assert!(parse_params(&strings(&["x.img", "--files", "0"])).is_err());
        assert!(parse_params(&strings(&["x.img", "--chunk", "128M"])).is_err());
        assert!(parse_params(&strings(&["x.img", "--dir", "ingest"])).is_err());
        assert!(parse_params(&strings(&["x.img", "--dir", "bench/sub"])).is_err());
    }

    #[test]
    fn pattern_fill_is_deterministic_and_nonzero() {
        let mut a = vec![0u8; 4096];
        let mut b = vec![0u8; 4096];
        fill_pattern(&mut a, 7);
        fill_pattern(&mut b, 7);
        assert_eq!(a, b);
        assert!(a.iter().any(|&byte| byte != 0));
        fill_pattern(&mut b, 8);
        assert_ne!(a, b);
    }

    #[test]
    fn bench_smoke_all_suites_and_cleanup() {
        let dir = std::env::temp_dir().join(format!("scalefs-bench-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let image = dir.join("bench.img").to_string_lossy().into_owned();
        crate::pool_cmds::cmd_pool(&strings(&[
            "create",
            &image,
            "--size",
            "67108864",
            "--label",
            "bench-test",
        ]))
        .unwrap();

        let params = parse_params(&strings(&[
            &image,
            "--files",
            "3",
            "--file-size",
            "64K",
            "--stream-size",
            "1M",
            "--chunk",
            "64K",
            "--commits",
            "3",
        ]))
        .unwrap();
        let mut pool = open_pool(&image).unwrap();
        let report = run_bench(&mut pool, &params).unwrap();
        drop(pool);

        assert_eq!(report.results.len(), 5);
        for (suite, result) in &report.results {
            assert!(result.seconds >= 0.0, "{suite:?}");
            match suite {
                Suite::WriteFiles | Suite::ReadFiles => {
                    assert_eq!(result.ops, 3);
                    assert_eq!(result.bytes, 3 * (64 << 10));
                    assert!(result.per_op_ms.is_some());
                }
                Suite::WriteStream => {
                    assert_eq!(result.bytes, 1 << 20);
                    assert!(result.commit_ms.is_some());
                }
                Suite::ReadStream => assert_eq!(result.bytes, 1 << 20),
                Suite::Commit => assert_eq!(result.ops, 3),
            }
        }
        let (reclaimed, _) = report.cleanup.expect("cleanup ran");
        assert_eq!(reclaimed, 3 + 3 + 1);
        assert!(report.tx_after > report.tx_before);

        let encoded = report_value(&report, &params).encode();
        for needle in [
            "\"tool\":\"scalefs-bench\"",
            "\"write-files\"",
            "\"read-stream\"",
            "\"bytes_per_sec\"",
            "\"per_op_mean_us\"",
            "\"commit_us\"",
            "\"cleanup\"",
        ] {
            assert!(encoded.contains(needle), "{needle} missing in {encoded}");
        }

        let pool = open_pool(&image).unwrap();
        assert!(matches!(
            pool.lookup(ROOT_INODE, "bench"),
            Err(ScaleFsError::NotFound)
        ));
        drop(pool);
        assert_eq!(
            crate::pool_cmds::cmd_fsck(std::slice::from_ref(&image)),
            Ok(true)
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn bench_keep_then_read_suites_standalone() {
        let dir = std::env::temp_dir().join(format!("scalefs-bench-keep-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let image = dir.join("keep.img").to_string_lossy().into_owned();
        crate::pool_cmds::cmd_pool(&strings(&[
            "create",
            &image,
            "--size",
            "67108864",
            "--label",
            "bench-keep",
        ]))
        .unwrap();

        let write = parse_params(&strings(&[
            &image,
            "--suite",
            "write-files",
            "--files",
            "2",
            "--file-size",
            "64K",
            "--chunk",
            "64K",
            "--keep",
        ]))
        .unwrap();
        let mut pool = open_pool(&image).unwrap();
        let report = run_bench(&mut pool, &write).unwrap();
        assert!(report.cleanup.is_none());
        drop(pool);

        let read = parse_params(&strings(&[
            &image,
            "--suite",
            "read-files",
            "--chunk",
            "64K",
            "--keep",
        ]))
        .unwrap();
        let mut pool = open_pool(&image).unwrap();
        let report = run_bench(&mut pool, &read).unwrap();
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].1.ops, 2);
        drop(pool);

        let missing =
            parse_params(&strings(&[&image, "--suite", "read-stream", "--keep"])).unwrap();
        let mut pool = open_pool(&image).unwrap();
        let err = run_bench(&mut pool, &missing).unwrap_err();
        assert!(err.contains("write-stream"), "{err}");

        std::fs::remove_dir_all(&dir).ok();
    }
}
