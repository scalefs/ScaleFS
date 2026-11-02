use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("scalefs-cli-{}-{tag}-{n}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self, name: &str) -> String {
        self.0.join(name).to_string_lossy().into_owned()
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scalefs(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_scalefs"))
        .args(args)
        .output()
        .expect("failed to run scalefs")
}

fn ok(args: &[&str]) -> String {
    let output = scalefs(args);
    assert!(
        output.status.success(),
        "scalefs {args:?} failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8(output.stdout).unwrap()
}

fn fails(args: &[&str]) -> (Option<i32>, String) {
    let output = scalefs(args);
    assert!(
        !output.status.success(),
        "scalefs {args:?} unexpectedly succeeded"
    );
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn version_and_help_run() {
    assert!(ok(&["version"]).contains("on-disk format v1"));
    assert!(ok(&["help"]).contains("pool create"));
    let (code, _) = fails(&["frobnicate"]);
    assert_eq!(code, Some(2));
}

#[test]
fn pool_lifecycle_end_to_end() {
    let scratch = ScratchDir::new("lifecycle");
    let image = scratch.path("pool.img");

    let created = ok(&[
        "pool",
        "create",
        &image,
        "--size",
        "8M",
        "--zone-size",
        "64K",
        "--label",
        "tank",
    ]);
    assert!(created.contains("tank"), "{created}");

    let (code, stderr) = fails(&["pool", "create", &image, "--size", "8M"]);
    assert_eq!(code, Some(2));
    assert!(stderr.contains("already exists"), "{stderr}");

    let status = ok(&["pool", "status", &image]);
    assert!(status.contains("Label:        tank"), "{status}");
    assert!(status.contains("Transaction:  1"), "{status}");
    assert!(status.contains("read-write"), "{status}");

    let inspect = ok(&["pool", "inspect", &image]);
    assert!(inspect.contains("metadata items"), "{inspect}");

    let fsck = ok(&["fsck", &image]);
    assert!(fsck.contains("clean"), "{fsck}");
}

#[test]
fn files_round_trip_through_the_pool() {
    let scratch = ScratchDir::new("files");
    let image = scratch.path("pool.img");
    ok(&[
        "pool",
        "create",
        &image,
        "--size",
        "8M",
        "--zone-size",
        "64K",
    ]);

    let local_in = scratch.path("in.bin");
    let payload: Vec<u8> = (0..50_000u32).map(|i| (i * 31 % 251) as u8).collect();
    std::fs::write(&local_in, &payload).unwrap();

    ok(&["fs", "mkdir", &image, "/docs"]);
    ok(&["fs", "put", &image, &local_in, "/docs/data.bin"]);

    let local_out = scratch.path("out.bin");
    ok(&["fs", "get", &image, "/docs/data.bin", &local_out]);
    assert_eq!(std::fs::read(&local_out).unwrap(), payload);

    let listing = ok(&["fs", "ls", &image, "/docs"]);
    assert!(listing.contains("data.bin"), "{listing}");

    let stat = ok(&["fs", "stat", &image, "/docs/data.bin"]);
    assert!(stat.contains("50000 bytes"), "{stat}");

    let smaller = scratch.path("small.bin");
    std::fs::write(&smaller, b"tiny").unwrap();
    ok(&["fs", "put", &image, &smaller, "/docs/data.bin"]);
    ok(&["fs", "get", &image, "/docs/data.bin", &local_out]);
    assert_eq!(std::fs::read(&local_out).unwrap(), b"tiny");

    ok(&["fs", "mv", &image, "/docs/data.bin", "/data.bin"]);
    let (_, stderr) = fails(&["fs", "get", &image, "/docs/data.bin", &local_out]);
    assert!(stderr.contains("not found"), "{stderr}");
    let (_, stderr) = fails(&["fs", "rmdir", &image, "/docs2"]);
    assert!(stderr.contains("not found"), "{stderr}");
    ok(&["fs", "rmdir", &image, "/docs"]);
    ok(&["fs", "rm", &image, "/data.bin"]);
    let listing = ok(&["fs", "ls", &image]);
    assert!(!listing.contains("data.bin"), "{listing}");

    assert!(ok(&["fsck", &image]).contains("clean"));
}

#[test]
fn snapshots_preserve_and_restore_file_contents() {
    let scratch = ScratchDir::new("snap");
    let image = scratch.path("pool.img");
    ok(&[
        "pool",
        "create",
        &image,
        "--size",
        "8M",
        "--zone-size",
        "64K",
    ]);

    let v1 = scratch.path("v1.bin");
    let v2 = scratch.path("v2.bin");
    std::fs::write(&v1, b"the first version of the file").unwrap();
    std::fs::write(&v2, b"v2").unwrap();

    ok(&["fs", "put", &image, &v1, "/notes.txt"]);
    ok(&["snapshot", "create", &image, "before-edit"]);
    ok(&["fs", "put", &image, &v2, "/notes.txt"]);

    let out = scratch.path("out.bin");
    ok(&["fs", "get", &image, "/notes.txt", &out]);
    assert_eq!(std::fs::read(&out).unwrap(), b"v2");
    ok(&["snapshot", "get", &image, "before-edit", "/notes.txt", &out]);
    assert_eq!(
        std::fs::read(&out).unwrap(),
        b"the first version of the file"
    );

    let listing = ok(&["snapshot", "ls", &image, "before-edit"]);
    assert!(listing.contains("notes.txt"), "{listing}");
    let list = ok(&["snapshot", "list", &image]);
    assert!(list.contains("before-edit"), "{list}");
    assert!(ok(&["fsck", &image]).contains("1 snapshot(s)"));

    ok(&["snapshot", "release", &image, "before-edit"]);
    let list = ok(&["snapshot", "list", &image]);
    assert!(list.contains("no snapshots"), "{list}");
    assert!(ok(&["fsck", &image]).contains("clean"));
}

#[test]
fn fsck_detects_a_corrupted_data_record() {
    let scratch = ScratchDir::new("fsck");
    let image = scratch.path("pool.img");
    ok(&[
        "pool",
        "create",
        &image,
        "--size",
        "8M",
        "--zone-size",
        "64K",
    ]);

    let local_in = scratch.path("in.bin");
    std::fs::write(&local_in, vec![0xABu8; 5000]).unwrap();
    ok(&["fs", "put", &image, &local_in, "/f.bin"]);
    assert!(ok(&["fsck", &image]).contains("clean"));

    let mut bytes = std::fs::read(&image).unwrap();
    let target = (scalefs_core::MEMBER_PARTITION_START as usize) + 2 * 65536 + 100;
    bytes[target] ^= 0xFF;
    std::fs::write(&image, &bytes).unwrap();

    let output = scalefs(&["fsck", &image]);
    assert_eq!(output.status.code(), Some(1), "fsck must report problems");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("fails verification"), "{stderr}");
}

#[test]
fn multi_device_pools_work_end_to_end() {
    let scratch = ScratchDir::new("multi");
    let a = scratch.path("a.img");
    let b = scratch.path("b.img");
    let c = scratch.path("c.img");
    let members = format!("{a},{b},{c}");

    let created = ok(&[
        "pool",
        "create",
        &members,
        "--size",
        "8M,8M,16M",
        "--zone-size",
        "64K",
        "--label",
        "span",
    ]);
    assert!(created.contains("across 3 members"), "{created}");

    let local = scratch.path("payload.bin");
    let payload: Vec<u8> = (0..150_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&local, &payload).unwrap();
    ok(&["fs", "put", &members, &local, "/payload.bin"]);
    let shuffled = format!("{c},{a},{b}");
    let out = scratch.path("out.bin");
    ok(&["fs", "get", &shuffled, "/payload.bin", &out]);
    assert_eq!(std::fs::read(&out).unwrap(), payload);

    let status = ok(&["pool", "status", &members]);
    assert!(status.contains("Label:        span"), "{status}");
    assert!(status.contains("Members:      3"), "{status}");

    let fsck = ok(&["fsck", &members]);
    assert!(fsck.contains("clean"), "{fsck}");

    let partial = format!("{a},{c}");
    let (code, stderr) = fails(&["pool", "status", &partial]);
    assert_eq!(code, Some(2));
    assert!(stderr.contains("missing"), "{stderr}");

    let (_, stderr) = fails(&["pool", "status", &a]);
    assert!(stderr.contains("missing"), "{stderr}");
}

#[test]
fn reclaim_returns_space_end_to_end() {
    let scratch = ScratchDir::new("reclaim");
    let a = scratch.path("a.img");
    let b = scratch.path("b.img");
    let members = format!("{a},{b}");
    ok(&[
        "pool",
        "create",
        &members,
        "--size",
        "8M",
        "--zone-size",
        "64K",
        "--label",
        "rc",
    ]);

    let local = scratch.path("bulk.bin");
    let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&local, &payload).unwrap();
    ok(&["fs", "put", &members, &local, "/bulk.bin"]);
    ok(&["snapshot", "create", &members, "pin"]);
    ok(&["fs", "rm", &members, "/bulk.bin"]);
    ok(&["pool", "reclaim", &members]);
    let out = scratch.path("pinned.bin");
    ok(&["snapshot", "get", &members, "pin", "/bulk.bin", &out]);
    assert_eq!(std::fs::read(&out).unwrap(), payload);

    ok(&["snapshot", "release", &members, "pin"]);
    let freed = ok(&["pool", "reclaim", &members]);
    assert!(freed.contains("reclaimed"), "{freed}");

    let fsck = ok(&["fsck", &members]);
    assert!(fsck.contains("clean"), "{fsck}");
}

#[test]
fn mirrored_pool_survives_deleting_a_member_image() {
    let scratch = ScratchDir::new("mirror");
    let a = scratch.path("a.img");
    let b = scratch.path("b.img");
    let c = scratch.path("c.img");
    let members = format!("{a},{b},{c}");
    let created = ok(&[
        "pool",
        "create",
        &members,
        "--size",
        "8M",
        "--zone-size",
        "64K",
        "--mirror",
        "2",
        "--label",
        "mirrored",
    ]);
    assert!(created.contains("across 3 members"), "{created}");

    let local = scratch.path("payload.bin");
    let payload: Vec<u8> = (0..200_000u32).map(|i| (i * 7 % 251) as u8).collect();
    std::fs::write(&local, &payload).unwrap();
    ok(&["fs", "put", &members, &local, "/payload.bin"]);
    ok(&["snapshot", "create", &members, "pin"]);

    let status = ok(&["pool", "status", &members]);
    assert!(status.contains("Protection:   2-way mirror"), "{status}");

    std::fs::remove_file(&b).unwrap();
    let survivors = format!("{a},{c}");

    let (_, stderr) = fails(&["pool", "status", &survivors]);
    assert!(stderr.contains("missing"), "{stderr}");

    let status = ok(&["--degraded", "pool", "status", &survivors]);
    assert!(status.contains("DEGRADED"), "{status}");
    assert!(status.contains("MISSING"), "{status}");
    let out = scratch.path("out.bin");
    ok(&["--degraded", "fs", "get", &survivors, "/payload.bin", &out]);
    assert_eq!(std::fs::read(&out).unwrap(), payload);
    ok(&[
        "--degraded",
        "snapshot",
        "get",
        &survivors,
        "pin",
        "/payload.bin",
        &out,
    ]);
    assert_eq!(std::fs::read(&out).unwrap(), payload);
    let fsck = ok(&["--degraded", "fsck", &survivors]);
    assert!(fsck.contains("clean"), "{fsck}");

    let (_, stderr) = fails(&["--degraded", "fs", "rm", &survivors, "/payload.bin"]);
    assert!(stderr.contains("read-only"), "{stderr}");
}

#[test]
fn scrub_finds_and_heals_silent_corruption() {
    let scratch = ScratchDir::new("scrub");
    let a = scratch.path("a.img");
    let b = scratch.path("b.img");
    let members = format!("{a},{b}");
    ok(&[
        "pool",
        "create",
        &members,
        "--size",
        "8M",
        "--zone-size",
        "64K",
        "--mirror",
        "2",
    ]);
    let local = scratch.path("f.bin");
    let payload: Vec<u8> = (0..50_000u32).map(|i| (i * 3 % 251) as u8).collect();
    std::fs::write(&local, &payload).unwrap();
    ok(&["fs", "put", &members, &local, "/f.bin"]);
    assert!(ok(&["scrub", &members]).contains("healthy"));

    let mut bytes = std::fs::read(&b).unwrap();
    let target = (scalefs_core::MEMBER_PARTITION_START as usize) + 2 * 65536 + 100;
    bytes[target] ^= 0xFF;
    std::fs::write(&b, &bytes).unwrap();

    let output = scalefs(&["scrub", &members]);
    assert_eq!(output.status.code(), Some(1), "scrub must flag the damage");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--repair"), "{stdout}");

    let repaired = ok(&["scrub", &members, "--repair"]);
    assert!(repaired.contains("1 repaired"), "{repaired}");
    assert!(ok(&["scrub", &members]).contains("healthy"));

    let out = scratch.path("out.bin");
    ok(&["fs", "get", &members, "/f.bin", &out]);
    assert_eq!(std::fs::read(&out).unwrap(), payload);
    assert!(ok(&["fsck", &members]).contains("clean"));
}

#[test]
fn a_pool_grows_by_adding_members() {
    let scratch = ScratchDir::new("grow");
    let a = scratch.path("a.img");
    let b = scratch.path("b.img");
    ok(&[
        "pool",
        "create",
        &a,
        "--size",
        "8M",
        "--zone-size",
        "64K",
        "--label",
        "grower",
    ]);

    let local = scratch.path("f.bin");
    let payload: Vec<u8> = (0..80_000u32).map(|i| (i * 5 % 251) as u8).collect();
    std::fs::write(&local, &payload).unwrap();
    ok(&["fs", "put", &a, &local, "/f.bin"]);

    let added = ok(&["pool", "add", &a, &b, "--size", "16M", "--zone-size", "64K"]);
    assert!(added.contains("member 1"), "{added}");

    let members = format!("{a},{b}");
    let status = ok(&["pool", "status", &members]);
    assert!(status.contains("Members:      2"), "{status}");
    assert!(status.contains("Capacity:     21.8 MiB"), "{status}");

    let (_, stderr) = fails(&["fs", "ls", &a]);
    assert!(
        stderr.contains("multiple devices") || stderr.contains("missing"),
        "{stderr}"
    );
    let out = scratch.path("out.bin");
    ok(&["fs", "get", &members, "/f.bin", &out]);
    assert_eq!(std::fs::read(&out).unwrap(), payload);
    assert!(ok(&["fsck", &members]).contains("clean"));
    assert!(ok(&["scrub", &members]).contains("healthy"));
}

#[test]
fn a_lost_member_is_replaced_and_the_pool_rebuilds() {
    let scratch = ScratchDir::new("replace");
    let a = scratch.path("a.img");
    let b = scratch.path("b.img");
    let c = scratch.path("c.img");
    let d = scratch.path("d.img");
    let members = format!("{a},{b},{c}");
    ok(&[
        "pool",
        "create",
        &members,
        "--size",
        "8M",
        "--zone-size",
        "64K",
        "--mirror",
        "2",
    ]);
    let local = scratch.path("f.bin");
    let payload: Vec<u8> = (0..150_000u32).map(|i| (i * 11 % 251) as u8).collect();
    std::fs::write(&local, &payload).unwrap();
    ok(&["fs", "put", &members, &local, "/f.bin"]);
    ok(&["snapshot", "create", &members, "pin"]);

    std::fs::remove_file(&b).unwrap();
    let survivors = format!("{a},{c}");
    let replaced = ok(&[
        "pool",
        "replace",
        &survivors,
        &d,
        "--size",
        "8M",
        "--zone-size",
        "64K",
    ]);
    assert!(replaced.contains("rebuilt"), "{replaced}");

    let repaired = format!("{a},{c},{d}");
    assert!(ok(&["scrub", &repaired]).contains("healthy"));
    let status = ok(&["pool", "status", &repaired]);
    assert!(status.contains("Members:      3"), "{status}");
    assert!(!status.contains("DEGRADED"), "{status}");
    let out = scratch.path("out.bin");
    ok(&["fs", "get", &repaired, "/f.bin", &out]);
    assert_eq!(std::fs::read(&out).unwrap(), payload);

    std::fs::remove_file(&c).unwrap();
    let survivors = format!("{a},{d}");
    ok(&["--degraded", "fs", "get", &survivors, "/f.bin", &out]);
    assert_eq!(std::fs::read(&out).unwrap(), payload);
    ok(&[
        "--degraded",
        "snapshot",
        "get",
        &survivors,
        "pin",
        "/f.bin",
        &out,
    ]);
    assert_eq!(std::fs::read(&out).unwrap(), payload);
}

#[test]
fn losing_two_members_takes_two_replacements() {
    let scratch = ScratchDir::new("replace2");
    let a = scratch.path("a.img");
    let b = scratch.path("b.img");
    let c = scratch.path("c.img");
    let d = scratch.path("d.img");
    let e = scratch.path("e.img");
    let f = scratch.path("f.img");
    let members = format!("{a},{b},{c},{d}");
    ok(&[
        "pool",
        "create",
        &members,
        "--size",
        "8M",
        "--zone-size",
        "64K",
        "--mirror",
        "3",
    ]);
    let local = scratch.path("f.bin");
    let payload: Vec<u8> = (0..150_000u32).map(|i| (i * 13 % 251) as u8).collect();
    std::fs::write(&local, &payload).unwrap();
    ok(&["fs", "put", &members, &local, "/f.bin"]);

    std::fs::remove_file(&c).unwrap();
    std::fs::remove_file(&d).unwrap();
    let survivors = format!("{a},{b}");

    let first = ok(&[
        "pool",
        "replace",
        &survivors,
        &e,
        "--size",
        "8M",
        "--zone-size",
        "64K",
    ]);
    assert!(first.contains("still missing"), "{first}");
    assert!(!first.contains("rebuilt"), "{first}");
    let partial = format!("{a},{b},{e}");
    assert!(ok(&["--degraded", "pool", "status", &partial]).contains("DEGRADED"));

    let second = ok(&[
        "pool",
        "replace",
        &partial,
        &f,
        "--size",
        "8M",
        "--zone-size",
        "64K",
    ]);
    assert!(second.contains("rebuilt"), "{second}");
    let repaired = format!("{a},{b},{e},{f}");
    assert!(ok(&["scrub", &repaired]).contains("healthy"));
    let status = ok(&["pool", "status", &repaired]);
    assert!(!status.contains("DEGRADED"), "{status}");
    let out = scratch.path("out.bin");
    ok(&["fs", "get", &repaired, "/f.bin", &out]);
    assert_eq!(std::fs::read(&out).unwrap(), payload);
}

#[test]
fn a_member_is_removed_after_evacuation() {
    let scratch = ScratchDir::new("remove");
    let a = scratch.path("a.img");
    let b = scratch.path("b.img");
    let c = scratch.path("c.img");
    let members = format!("{a},{b},{c}");
    ok(&[
        "pool",
        "create",
        &members,
        "--size",
        "8M",
        "--zone-size",
        "64K",
        "--mirror",
        "2",
    ]);
    let local = scratch.path("f.bin");
    let payload: Vec<u8> = (0..120_000u32).map(|i| (i * 13 % 251) as u8).collect();
    std::fs::write(&local, &payload).unwrap();
    ok(&["fs", "put", &members, &local, "/f.bin"]);
    ok(&["snapshot", "create", &members, "pin"]);

    let removed = ok(&["pool", "remove", &members, &b]);
    assert!(removed.contains("2 active member(s)"), "{removed}");

    let survivors = format!("{a},{c}");
    let out = scratch.path("out.bin");
    ok(&["fs", "get", &survivors, "/f.bin", &out]);
    assert_eq!(std::fs::read(&out).unwrap(), payload);
    ok(&["snapshot", "get", &survivors, "pin", "/f.bin", &out]);
    assert_eq!(std::fs::read(&out).unwrap(), payload);
    assert!(ok(&["scrub", &survivors]).contains("healthy"));
    assert!(ok(&["fsck", &survivors]).contains("clean"));
    let (_, stderr) = fails(&["pool", "status", &b]);
    assert!(!stderr.is_empty(), "{stderr}");

    std::fs::remove_file(&c).unwrap();
    ok(&["--degraded", "fs", "get", &a, "/f.bin", &out]);
    assert_eq!(std::fs::read(&out).unwrap(), payload);
}

#[test]
fn daemon_commands_reach_a_running_scalefsd() {
    let name = format!("scalefs-cli-test-{}", std::process::id());
    let endpoint_text = if cfg!(windows) {
        name
    } else {
        std::env::temp_dir()
            .join(format!("{name}.sock"))
            .to_string_lossy()
            .into_owned()
    };
    let endpoint = scalefs_ipc::endpoint::Endpoint::new(&endpoint_text);
    let server = std::thread::spawn(move || scalefs_daemon::serve(&endpoint));

    let pinged = ok(&["daemon", "ping", "--endpoint", &endpoint_text]);
    assert!(pinged.contains("answers"), "{pinged}");
    let version = ok(&["daemon", "version", "--endpoint", &endpoint_text]);
    assert!(version.contains("protocol 1"), "{version}");
    assert!(version.contains("format v1"), "{version}");

    let stopped = ok(&["daemon", "shutdown", "--endpoint", &endpoint_text]);
    assert!(stopped.contains("shutting down"), "{stopped}");
    server.join().unwrap().unwrap();

    let (code, stderr) = fails(&["daemon", "ping", "--endpoint", &endpoint_text]);
    assert_eq!(code, Some(2));
    assert!(stderr.contains("cannot reach the daemon"), "{stderr}");
}

#[test]
fn daemon_pool_commands_manage_attached_pools() {
    let scratch = ScratchDir::new("daemon-pools");
    let a = scratch.path("a.img");
    let b = scratch.path("b.img");
    let members = format!("{a},{b}");
    ok(&[
        "pool",
        "create",
        &members,
        "--size",
        "8M",
        "--zone-size",
        "64K",
        "--mirror",
        "2",
        "--label",
        "vault",
    ]);

    let name = format!("scalefs-cli-pools-{}", std::process::id());
    let endpoint_text = if cfg!(windows) {
        name
    } else {
        std::env::temp_dir()
            .join(format!("{name}.sock"))
            .to_string_lossy()
            .into_owned()
    };
    let endpoint = scalefs_ipc::endpoint::Endpoint::new(&endpoint_text);
    let server = std::thread::spawn(move || scalefs_daemon::serve(&endpoint));

    let attached = ok(&[
        "daemon",
        "attach",
        "vault",
        &members,
        "--endpoint",
        &endpoint_text,
    ]);
    assert!(attached.contains("label 'vault'"), "{attached}");
    assert!(attached.contains("2-way mirror"), "{attached}");

    let pools = ok(&["daemon", "pools", "--endpoint", &endpoint_text]);
    assert!(pools.contains("vault:"), "{pools}");

    let status = ok(&["daemon", "status", "vault", "--endpoint", &endpoint_text]);
    assert!(status.contains("Label:        vault"), "{status}");
    assert!(status.contains("Protection:   2-way mirror"), "{status}");
    assert!(status.contains("active"), "{status}");

    let (_, stderr) = fails(&["daemon", "status", "nothing", "--endpoint", &endpoint_text]);
    assert!(stderr.contains("not_found"), "{stderr}");

    let scrubbed = ok(&["daemon", "scrub", "vault", "--endpoint", &endpoint_text]);
    assert!(scrubbed.contains("healthy"), "{scrubbed}");
    let reclaimed = ok(&["daemon", "reclaim", "vault", "--endpoint", &endpoint_text]);
    assert!(reclaimed.contains("0 zone(s) reset"), "{reclaimed}");
    let jobs = ok(&["daemon", "jobs", "--endpoint", &endpoint_text]);
    assert!(jobs.contains("scrub on 'vault'"), "{jobs}");
    assert!(jobs.contains("done"), "{jobs}");

    ok(&["daemon", "detach", "vault", "--endpoint", &endpoint_text]);
    let pools = ok(&["daemon", "pools", "--endpoint", &endpoint_text]);
    assert!(pools.contains("no pools attached"), "{pools}");

    ok(&["daemon", "shutdown", "--endpoint", &endpoint_text]);
    server.join().unwrap().unwrap();
}

#[test]
fn device_list_runs_anywhere() {
    ok(&["device", "list"]);
    let (code, _) = fails(&["device", "frobnicate"]);
    assert_eq!(code, Some(2));
}

#[test]
fn pools_import_from_candidates() {
    let scratch = ScratchDir::new("import");
    let a = scratch.path("a.img");
    let b = scratch.path("b.img");
    let c = scratch.path("c.img");
    ok(&[
        "pool",
        "create",
        &format!("{a},{b},{c}"),
        "--size",
        "8M",
        "--zone-size",
        "64K",
        "--mirror",
        "2",
        "--label",
        "tank",
    ]);
    let d = scratch.path("d.img");
    ok(&[
        "pool",
        "create",
        &d,
        "--size",
        "8M",
        "--zone-size",
        "64K",
        "--label",
        "spare",
    ]);
    let junk = scratch.path("junk.bin");
    std::fs::write(&junk, vec![0x99u8; 1 << 20]).unwrap();
    let blank = scratch.path("blank.bin");
    std::fs::write(&blank, vec![0u8; 1 << 20]).unwrap();

    let everything = [&a, &b, &c, &d, &junk, &blank];
    let ambiguous: Vec<&str> = ["pool", "import"]
        .into_iter()
        .chain(everything.iter().map(|path| path.as_str()))
        .collect();
    let (code, stderr) = fails(&ambiguous);
    assert_eq!(code, Some(2));
    assert!(
        stderr.contains("tank") && stderr.contains("spare"),
        "{stderr}"
    );

    let mut by_label = ambiguous.clone();
    by_label.extend(["--pool", "tank"]);
    let imported = ok(&by_label);
    assert!(imported.contains("3 member device(s)"), "{imported}");
    assert!(imported.contains("Label:        tank"), "{imported}");
    assert!(imported.contains("read-write"), "{imported}");

    let mut nothing = ambiguous.clone();
    nothing.extend(["--pool", "nope"]);
    let (_, stderr) = fails(&nothing);
    assert!(stderr.contains("no discovered pool"), "{stderr}");

    std::fs::remove_file(&b).unwrap();
    let (_, stderr) = fails(&["pool", "import", &a, &c, "--pool", "tank"]);
    assert!(stderr.contains("missing"), "{stderr}");
    let degraded = ok(&["--degraded", "pool", "import", &a, &c, "--pool", "tank"]);
    assert!(degraded.contains("DEGRADED"), "{degraded}");
    assert!(degraded.contains("read-only"), "{degraded}");
}

#[test]
fn daemon_import_discovers_and_attaches() {
    let scratch = ScratchDir::new("daemon-import");
    let a = scratch.path("a.img");
    let b = scratch.path("b.img");
    ok(&[
        "pool",
        "create",
        &format!("{a},{b}"),
        "--size",
        "8M",
        "--zone-size",
        "64K",
        "--mirror",
        "2",
        "--label",
        "found",
    ]);
    let junk = scratch.path("junk.bin");
    std::fs::write(&junk, vec![0x42u8; 1 << 20]).unwrap();

    let name = format!("scalefs-cli-import-{}", std::process::id());
    let endpoint_text = if cfg!(windows) {
        name
    } else {
        std::env::temp_dir()
            .join(format!("{name}.sock"))
            .to_string_lossy()
            .into_owned()
    };
    let endpoint = scalefs_ipc::endpoint::Endpoint::new(&endpoint_text);
    let server = std::thread::spawn(move || scalefs_daemon::serve(&endpoint));

    let candidates = format!("{a},{junk},{b}");
    let imported = ok(&[
        "daemon",
        "import",
        &candidates,
        "--endpoint",
        &endpoint_text,
    ]);
    assert!(imported.contains("imported 'found'"), "{imported}");
    assert!(imported.contains("2 member(s)"), "{imported}");

    let status = ok(&["daemon", "status", "found", "--endpoint", &endpoint_text]);
    assert!(status.contains("Label:        found"), "{status}");

    ok(&["daemon", "devices", "--endpoint", &endpoint_text]);

    ok(&["daemon", "shutdown", "--endpoint", &endpoint_text]);
    server.join().unwrap().unwrap();
}
