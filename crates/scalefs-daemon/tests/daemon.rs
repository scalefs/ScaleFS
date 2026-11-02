use scalefs_ipc::client::{CallError, Client};
use scalefs_ipc::endpoint::Endpoint;
use scalefs_ipc::frame::{read_frame, write_frame};
use scalefs_ipc::json::{Value, object};
use std::io::BufReader;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

struct DaemonUnderTest {
    child: Child,
    endpoint: Endpoint,
}

impl DaemonUnderTest {
    fn spawn(tag: &str) -> DaemonUnderTest {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!("scalefsd-test-{}-{tag}-{n}", std::process::id());
        let endpoint = if cfg!(windows) {
            Endpoint::new(&name)
        } else {
            Endpoint::new(
                &std::env::temp_dir()
                    .join(format!("{name}.sock"))
                    .to_string_lossy(),
            )
        };
        let child = Command::new(env!("CARGO_BIN_EXE_scalefsd"))
            .args(["serve", "--endpoint", endpoint.as_str()])
            .spawn()
            .expect("failed to run scalefsd");
        DaemonUnderTest { child, endpoint }
    }

    fn client(&self) -> Client {
        Client::connect(&self.endpoint, CONNECT_TIMEOUT).expect("connect to scalefsd")
    }

    fn shutdown(mut self) {
        let mut client = self.client();
        client.call("shutdown", Value::Null).expect("shutdown");
        let status = self.child.wait().expect("wait for scalefsd");
        assert!(status.success(), "scalefsd exited with {status}");
        std::mem::forget(self);
    }
}

impl Drop for DaemonUnderTest {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn sessions_negotiate_and_answer() {
    let daemon = DaemonUnderTest::spawn("basic");
    let mut client = daemon.client();
    assert_eq!(client.daemon_version(), env!("CARGO_PKG_VERSION"));

    let pong = client.call("ping", Value::Null).unwrap();
    assert_eq!(pong.get("pong"), Some(&Value::Bool(true)));

    let version = client.call("version", Value::Null).unwrap();
    assert_eq!(version.get("protocol").unwrap().as_u64(), Some(1));
    assert_eq!(version.get("format").unwrap().as_u64(), Some(1));
    assert_eq!(
        version.get("daemon").unwrap().as_str(),
        Some(env!("CARGO_PKG_VERSION"))
    );

    for _ in 0..3 {
        client.call("ping", Value::Null).unwrap();
    }
    daemon.shutdown();
}

#[test]
fn unknown_operations_answer_unsupported_and_keep_the_session() {
    let daemon = DaemonUnderTest::spawn("unknown");
    let mut client = daemon.client();
    match client.call("frobnicate", Value::Null) {
        Err(CallError::Daemon { code, message }) => {
            assert_eq!(code, "unsupported");
            assert!(message.contains("frobnicate"), "{message}");
        }
        other => panic!("expected an unsupported error, got {other:?}"),
    }
    client.call("ping", Value::Null).unwrap();
    daemon.shutdown();
}

#[test]
fn malformed_traffic_is_answered_with_bad_request() {
    let daemon = DaemonUnderTest::spawn("malformed");

    {
        let stream = scalefs_ipc::endpoint::connect(&daemon.endpoint, CONNECT_TIMEOUT).unwrap();
        let mut reader = BufReader::new(stream);
        write_frame(reader.get_mut(), &scalefs_ipc::proto::client_hello()).unwrap();
        read_frame(&mut reader).unwrap().unwrap();
        write_frame(reader.get_mut(), &object(vec![("id", Value::Int(4))])).unwrap();
        let refusal = read_frame(&mut reader).unwrap().unwrap();
        assert_eq!(refusal.get("ok"), Some(&Value::Bool(false)));
        assert_eq!(refusal.get("id").unwrap().as_u64(), Some(4));
        assert_eq!(
            refusal.get("error").unwrap().get("code").unwrap().as_str(),
            Some("bad_request")
        );
        write_frame(
            reader.get_mut(),
            &object(vec![
                ("id", Value::Int(5)),
                ("op", Value::Str("ping".into())),
            ]),
        )
        .unwrap();
        let pong = read_frame(&mut reader).unwrap().unwrap();
        assert_eq!(pong.get("ok"), Some(&Value::Bool(true)));
    }

    {
        let stream = scalefs_ipc::endpoint::connect(&daemon.endpoint, CONNECT_TIMEOUT).unwrap();
        let mut reader = BufReader::new(stream);
        write_frame(reader.get_mut(), &scalefs_ipc::proto::client_hello()).unwrap();
        read_frame(&mut reader).unwrap().unwrap();
        std::io::Write::write_all(reader.get_mut(), b"this is not json\n").unwrap();
        std::io::Write::flush(reader.get_mut()).unwrap();
        let refusal = read_frame(&mut reader).unwrap().unwrap();
        assert_eq!(refusal.get("id"), Some(&Value::Null));
        assert_eq!(refusal.get("ok"), Some(&Value::Bool(false)));
        assert_eq!(read_frame(&mut reader).unwrap(), None);
    }

    {
        let stream = scalefs_ipc::endpoint::connect(&daemon.endpoint, CONNECT_TIMEOUT).unwrap();
        let mut reader = BufReader::new(stream);
        write_frame(
            reader.get_mut(),
            &object(vec![
                ("id", Value::Int(1)),
                ("op", Value::Str("ping".into())),
            ]),
        )
        .unwrap();
        let refusal = read_frame(&mut reader).unwrap().unwrap();
        assert_eq!(refusal.get("ok"), Some(&Value::Bool(false)));
        assert_eq!(read_frame(&mut reader).unwrap(), None);
    }

    daemon.shutdown();
}

#[test]
fn concurrent_sessions_are_independent() {
    let daemon = DaemonUnderTest::spawn("concurrent");
    let mut clients: Vec<Client> = (0..4).map(|_| daemon.client()).collect();
    for client in &mut clients {
        let pong = client.call("ping", Value::Null).unwrap();
        assert_eq!(pong.get("pong"), Some(&Value::Bool(true)));
    }
    for client in &mut clients {
        client.call("version", Value::Null).unwrap();
    }
    daemon.shutdown();
}

#[test]
fn the_endpoint_is_single_owner() {
    let daemon = DaemonUnderTest::spawn("owner");
    daemon.client();
    let contender = Command::new(env!("CARGO_BIN_EXE_scalefsd"))
        .args(["serve", "--endpoint", daemon.endpoint.as_str()])
        .output()
        .expect("failed to run scalefsd");
    assert!(!contender.status.success());
    let stderr = String::from_utf8_lossy(&contender.stderr);
    assert!(stderr.contains("cannot bind"), "{stderr}");
    daemon.shutdown();
}

fn scratch_pool(tag: &str) -> (std::path::PathBuf, String, String) {
    scratch_pool_sized(tag, 16)
}

fn scratch_pool_sized(tag: &str, zone_count: u64) -> (std::path::PathBuf, String, String) {
    use scalefs_core::{
        CaseSensitivity, DeviceId, FileBlockDevice, Geometry, MemberSpec, Pool, PoolId, PoolParams,
    };
    let dir = std::env::temp_dir().join(format!(
        "scalefsd-pool-{}-{tag}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos(),
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let geometry = Geometry {
        logical_block_size: 4096,
        physical_block_size: 4096,
        zone_size: 64 * 1024,
        zone_count,
        erase_granularity_zones: 1,
        sequential_write_required: false,
    };
    let a = dir.join("a.img");
    let b = dir.join("b.img");
    let members = vec![
        MemberSpec {
            device: FileBlockDevice::create(
                &a,
                scalefs_core::member_image_len(geometry.capacity_bytes()),
            )
            .unwrap(),
            device_id: DeviceId([0xA1; 16]),
            geometry,
        },
        MemberSpec {
            device: FileBlockDevice::create(
                &b,
                scalefs_core::member_image_len(geometry.capacity_bytes()),
            )
            .unwrap(),
            device_id: DeviceId([0xB2; 16]),
            geometry,
        },
    ];
    let params = PoolParams {
        pool_id: PoolId([0x77; 16]),
        case_sensitivity: CaseSensitivity::InsensitivePreserving,
        dirent_hash_seed: 42,
        label: "tank".to_string(),
        created_at_ns: 1_700_000_000_000_000_000,
        mirror_width: 2,
        data_width: 1,
        parity_width: 0,
    };
    Pool::create_multi(members, params).unwrap();
    (
        dir.clone(),
        a.to_string_lossy().into_owned(),
        b.to_string_lossy().into_owned(),
    )
}

fn attach_params(name: &str, members: &[&str], degraded: bool) -> Value {
    let mut entries = vec![
        ("name", Value::Str(name.to_string())),
        (
            "members",
            Value::Array(
                members
                    .iter()
                    .map(|path| Value::Str(path.to_string()))
                    .collect(),
            ),
        ),
    ];
    if degraded {
        entries.push(("degraded", Value::Bool(true)));
    }
    object(entries)
}

#[test]
fn pools_attach_report_status_and_detach() {
    let (dir, a, b) = scratch_pool("attach");
    let daemon = DaemonUnderTest::spawn("pools");
    let mut client = daemon.client();

    let attached = client
        .call("pool.attach", attach_params("tank", &[&a, &b], false))
        .unwrap();
    assert_eq!(attached.get("label").unwrap().as_str(), Some("tank"));
    assert_eq!(attached.get("members").unwrap().as_u64(), Some(2));
    assert_eq!(attached.get("mirror").unwrap().as_u64(), Some(2));
    assert_eq!(attached.get("read_only"), Some(&Value::Bool(false)));
    assert_eq!(attached.get("degraded"), Some(&Value::Bool(false)));
    assert!(attached.get("tx").unwrap().as_u64().unwrap() >= 1);

    match client.call("pool.attach", attach_params("tank", &[&a, &b], false)) {
        Err(CallError::Daemon { code, .. }) => assert_eq!(code, "conflict"),
        other => panic!("expected conflict, got {other:?}"),
    }

    let listed = client.call("pool.list", Value::Null).unwrap();
    let pools = listed.get("pools").unwrap().as_array().unwrap();
    assert_eq!(pools.len(), 1);
    assert_eq!(pools[0].get("name").unwrap().as_str(), Some("tank"));

    let status = client
        .call(
            "pool.status",
            object(vec![("name", Value::Str("tank".into()))]),
        )
        .unwrap();
    let detail = status.get("members_detail").unwrap().as_array().unwrap();
    assert_eq!(detail.len(), 2);
    for row in detail {
        assert_eq!(row.get("state").unwrap().as_str(), Some("active"));
    }
    assert_eq!(status.get("orphans").unwrap().as_array().unwrap().len(), 0);

    client
        .call(
            "pool.detach",
            object(vec![("name", Value::Str("tank".into()))]),
        )
        .unwrap();
    match client.call(
        "pool.status",
        object(vec![("name", Value::Str("tank".into()))]),
    ) {
        Err(CallError::Daemon { code, .. }) => assert_eq!(code, "not_found"),
        other => panic!("expected not_found, got {other:?}"),
    }
    match client.call(
        "pool.detach",
        object(vec![("name", Value::Str("tank".into()))]),
    ) {
        Err(CallError::Daemon { code, .. }) => assert_eq!(code, "not_found"),
        other => panic!("expected not_found, got {other:?}"),
    }

    daemon.shutdown();
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn attach_failures_carry_protocol_codes() {
    let (dir, a, b) = scratch_pool("attach-err");
    let daemon = DaemonUnderTest::spawn("pool-errors");
    let mut client = daemon.client();

    match client.call("pool.attach", attach_params("half", &[&a], false)) {
        Err(CallError::Daemon { code, message }) => {
            assert_eq!(code, "conflict");
            assert!(message.contains("missing"), "{message}");
        }
        other => panic!("expected conflict, got {other:?}"),
    }

    let ghost = format!("{a}.ghost");
    match client.call("pool.attach", attach_params("ghost", &[&ghost, &b], false)) {
        Err(CallError::Daemon { code, message }) => {
            assert_eq!(code, "io");
            assert!(message.contains(".ghost"), "{message}");
        }
        other => panic!("expected io, got {other:?}"),
    }

    for params in [
        Value::Null,
        object(vec![("name", Value::Str("x".into()))]),
        attach_params("", &[&a, &b], false),
    ] {
        match client.call("pool.attach", params) {
            Err(CallError::Daemon { code, .. }) => assert_eq!(code, "bad_request"),
            other => panic!("expected bad_request, got {other:?}"),
        }
    }

    daemon.shutdown();
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn degraded_pools_attach_read_only() {
    let (dir, a, b) = scratch_pool("degraded");
    std::fs::remove_file(&b).unwrap();
    let daemon = DaemonUnderTest::spawn("degraded");
    let mut client = daemon.client();

    let attached = client
        .call("pool.attach", attach_params("wounded", &[&a], true))
        .unwrap();
    assert_eq!(attached.get("read_only"), Some(&Value::Bool(true)));
    assert_eq!(attached.get("degraded"), Some(&Value::Bool(true)));
    assert_eq!(
        attached.get("missing").unwrap().as_array().unwrap().len(),
        1
    );

    let status = client
        .call(
            "pool.status",
            object(vec![("name", Value::Str("wounded".into()))]),
        )
        .unwrap();
    let detail = status.get("members_detail").unwrap().as_array().unwrap();
    let states: Vec<&str> = detail
        .iter()
        .map(|row| row.get("state").unwrap().as_str().unwrap())
        .collect();
    assert!(states.contains(&"active"), "{states:?}");
    assert!(states.contains(&"missing"), "{states:?}");

    daemon.shutdown();
    let _ = std::fs::remove_dir_all(dir);
}

fn wait_for_job(client: &mut Client, id: u64) -> Value {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let status = client
            .call(
                "job.status",
                object(vec![("id", Value::Int(i128::from(id)))]),
            )
            .unwrap();
        match status.get("state").and_then(Value::as_str) {
            Some("running") => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "job {id} never settled"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            Some("done") => return status.get("result").cloned().unwrap_or(Value::Null),
            other => panic!("job {id} ended {other:?}: {status:?}"),
        }
    }
}

#[test]
fn maintenance_runs_as_jobs() {
    let (dir, a, b) = scratch_pool("jobs");
    let daemon = DaemonUnderTest::spawn("jobs");
    let mut client = daemon.client();
    client
        .call("pool.attach", attach_params("tank", &[&a, &b], false))
        .unwrap();

    let started = client
        .call(
            "pool.scrub",
            object(vec![("name", Value::Str("tank".into()))]),
        )
        .unwrap();
    let scrub_id = started.get("job").unwrap().as_u64().unwrap();
    let report = wait_for_job(&mut client, scrub_id);
    assert_eq!(report.get("healthy"), Some(&Value::Bool(true)));
    assert!(report.get("copies_checked").unwrap().as_u64().unwrap() > 0);

    let started = client
        .call(
            "pool.reclaim",
            object(vec![("name", Value::Str("tank".into()))]),
        )
        .unwrap();
    let reclaim_id = started.get("job").unwrap().as_u64().unwrap();
    let report = wait_for_job(&mut client, reclaim_id);
    assert_eq!(report.get("zones_reset").unwrap().as_u64(), Some(0));

    let started = client
        .call(
            "pool.rebuild",
            object(vec![("name", Value::Str("tank".into()))]),
        )
        .unwrap();
    let rebuild_id = started.get("job").unwrap().as_u64().unwrap();
    let report = wait_for_job(&mut client, rebuild_id);
    assert_eq!(report.get("records_rebuilt").unwrap().as_u64(), Some(0));

    let listed = client.call("job.list", Value::Null).unwrap();
    let jobs = listed.get("jobs").unwrap().as_array().unwrap();
    assert_eq!(jobs.len(), 3);
    let kinds: Vec<&str> = jobs
        .iter()
        .map(|job| job.get("kind").unwrap().as_str().unwrap())
        .collect();
    assert_eq!(kinds, vec!["scrub", "reclaim", "rebuild"]);
    for job in jobs {
        assert_eq!(job.get("pool").unwrap().as_str(), Some("tank"));
        assert_eq!(job.get("state").unwrap().as_str(), Some("done"));
    }

    match client.call("job.status", object(vec![("id", Value::Int(999))])) {
        Err(CallError::Daemon { code, .. }) => assert_eq!(code, "not_found"),
        other => panic!("expected not_found, got {other:?}"),
    }
    match client.call(
        "pool.scrub",
        object(vec![("name", Value::Str("nothing".into()))]),
    ) {
        Err(CallError::Daemon { code, .. }) => assert_eq!(code, "not_found"),
        other => panic!("expected not_found, got {other:?}"),
    }

    daemon.shutdown();
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn pools_import_by_discovery() {
    let (dir, a, b) = scratch_pool("import");
    let junk = dir.join("junk.bin").to_string_lossy().into_owned();
    std::fs::write(&junk, vec![0x33u8; 1 << 20]).unwrap();
    let daemon = DaemonUnderTest::spawn("import");
    let mut client = daemon.client();

    let candidates = |paths: &[&str]| {
        Value::Array(
            paths
                .iter()
                .map(|path| Value::Str(path.to_string()))
                .collect(),
        )
    };
    let params = object(vec![("candidates", candidates(&[&a, &junk, &b]))]);
    let imported = client.call("pool.import", params.clone()).unwrap();
    assert_eq!(imported.get("name").unwrap().as_str(), Some("tank"));
    assert_eq!(imported.get("label").unwrap().as_str(), Some("tank"));
    assert_eq!(imported.get("members").unwrap().as_u64(), Some(2));
    assert_eq!(imported.get("read_only"), Some(&Value::Bool(false)));
    let media = imported.get("media").unwrap().as_array().unwrap();
    assert_eq!(media.len(), 2);
    for row in media {
        assert!(row.get("path").unwrap().as_str().is_some());
    }

    match client.call("pool.import", params) {
        Err(CallError::Daemon { code, .. }) => assert_eq!(code, "conflict"),
        other => panic!("expected conflict, got {other:?}"),
    }

    match client.call(
        "pool.import",
        object(vec![
            ("candidates", candidates(&[&a, &b])),
            ("pool", Value::Str("nope".into())),
        ]),
    ) {
        Err(CallError::Daemon { code, .. }) => assert_eq!(code, "not_found"),
        other => panic!("expected not_found, got {other:?}"),
    }
    match client.call(
        "pool.import",
        object(vec![("candidates", candidates(&[&junk]))]),
    ) {
        Err(CallError::Daemon { code, .. }) => assert_eq!(code, "not_found"),
        other => panic!("expected not_found, got {other:?}"),
    }

    let listed = client.call("device.list", Value::Null).unwrap();
    for row in listed.get("devices").unwrap().as_array().unwrap() {
        assert!(row.get("path").unwrap().as_str().is_some());
        assert!(row.get("contents").unwrap().as_str().is_some());
    }

    client
        .call(
            "pool.detach",
            object(vec![("name", Value::Str("tank".into()))]),
        )
        .unwrap();
    std::fs::remove_file(&b).unwrap();
    match client.call(
        "pool.import",
        object(vec![("candidates", candidates(&[&a, &junk]))]),
    ) {
        Err(CallError::Daemon { code, .. }) => assert_eq!(code, "conflict"),
        other => panic!("expected conflict, got {other:?}"),
    }
    let hurt = client
        .call(
            "pool.import",
            object(vec![
                ("candidates", candidates(&[&a, &junk])),
                ("degraded", Value::Bool(true)),
                ("name", Value::Str("hurt".into())),
            ]),
        )
        .unwrap();
    assert_eq!(hurt.get("name").unwrap().as_str(), Some("hurt"));
    assert_eq!(hurt.get("degraded"), Some(&Value::Bool(true)));
    assert_eq!(hurt.get("read_only"), Some(&Value::Bool(true)));

    if cfg!(target_os = "linux") {
        match client.call(
            "pool.mount",
            object(vec![
                ("name", Value::Str("hurt".into())),
                ("mountpoint", Value::Str(dir.to_string_lossy().into_owned())),
            ]),
        ) {
            Err(CallError::Daemon { code, message }) => {
                assert_eq!(code, "conflict");
                assert!(message.contains("read-only"), "{message}");
            }
            other => panic!("expected a read-only refusal, got {other:?}"),
        }
    }

    daemon.shutdown();
    let _ = std::fs::remove_dir_all(dir);
}

fn smb_negotiate_probe(port: u16) -> Vec<u8> {
    smb_negotiate_stream(port).1
}

fn smb_negotiate_stream(port: u16) -> (std::net::TcpStream, Vec<u8>) {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect to share");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let message = [0xFFu8, b'S', b'M', b'B', 0x72];
    let mut frame = vec![0u8, 0, 0, message.len() as u8];
    frame.extend_from_slice(&message);
    stream.write_all(&frame).unwrap();

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).unwrap();
    let len = ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | header[3] as usize;
    let mut response = vec![0u8; len];
    stream.read_exact(&mut response).unwrap();
    (stream, response)
}

fn share_params(pool: &str, name: &str, port: u16, read_only: bool) -> Value {
    let mut entries = vec![
        ("pool", Value::Str(pool.to_string())),
        ("name", Value::Str(name.to_string())),
        ("user", Value::Str("backup".into())),
        ("password", Value::Str("s3cret-pass".into())),
        ("port", Value::Int(i128::from(port))),
    ];
    if read_only {
        entries.push(("read_only", Value::Bool(true)));
    }
    object(entries)
}

#[test]
fn smb_shares_serve_and_guard_detach() {
    let (dir, a, b) = scratch_pool("smb");
    let daemon = DaemonUnderTest::spawn("smb");
    let mut client = daemon.client();
    client
        .call("pool.attach", attach_params("tank", &[&a, &b], false))
        .unwrap();

    let port = 45001;
    let added = client
        .call("share.add", share_params("tank", "vault", port, false))
        .unwrap();
    assert_eq!(added.get("name").unwrap().as_str(), Some("vault"));
    assert_eq!(added.get("pool").unwrap().as_str(), Some("tank"));
    assert_eq!(added.get("port").unwrap().as_u64(), Some(u64::from(port)));
    assert_eq!(added.get("read_only"), Some(&Value::Bool(false)));
    assert!(
        added
            .get("address")
            .unwrap()
            .as_str()
            .unwrap()
            .contains("vault"),
        "{added:?}"
    );

    let listed = client.call("share.list", Value::Null).unwrap();
    let shares = listed.get("shares").unwrap().as_array().unwrap();
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].get("name").unwrap().as_str(), Some("vault"));
    assert_eq!(shares[0].get("read_only"), Some(&Value::Bool(false)));

    let reply = smb_negotiate_probe(port);
    assert!(
        reply.starts_with(&[0xFE, b'S', b'M', b'B']),
        "expected an SMB2 reply, got {:02x?}",
        &reply[..reply.len().min(8)]
    );

    match client.call("share.add", share_params("tank", "vault", 45009, false)) {
        Err(CallError::Daemon { code, .. }) => assert_eq!(code, "conflict"),
        other => panic!("expected a name conflict, got {other:?}"),
    }
    match client.call("share.add", share_params("tank", "other", port, false)) {
        Err(CallError::Daemon { code, message }) => {
            assert_eq!(code, "conflict");
            assert!(message.contains("port"), "{message}");
        }
        other => panic!("expected a port conflict, got {other:?}"),
    }

    match client.call(
        "pool.detach",
        object(vec![("name", Value::Str("tank".into()))]),
    ) {
        Err(CallError::Daemon { code, message }) => {
            assert_eq!(code, "conflict");
            assert!(message.contains("share"), "{message}");
        }
        other => panic!("expected a share conflict, got {other:?}"),
    }

    client
        .call(
            "share.remove",
            object(vec![("name", Value::Str("vault".into()))]),
        )
        .unwrap();
    assert_eq!(
        client
            .call("share.list", Value::Null)
            .unwrap()
            .get("shares")
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        0
    );
    match client.call(
        "share.remove",
        object(vec![("name", Value::Str("vault".into()))]),
    ) {
        Err(CallError::Daemon { code, .. }) => assert_eq!(code, "not_found"),
        other => panic!("expected not_found, got {other:?}"),
    }
    client
        .call(
            "pool.detach",
            object(vec![("name", Value::Str("tank".into()))]),
        )
        .unwrap();

    daemon.shutdown();
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn two_rw_shares_serve_one_pool() {
    let (dir, a, b) = scratch_pool("smb-two");
    let daemon = DaemonUnderTest::spawn("smb-two");
    let mut client = daemon.client();
    client
        .call("pool.attach", attach_params("tank", &[&a, &b], false))
        .unwrap();
    client
        .call("share.add", share_params("tank", "first", 45021, false))
        .unwrap();
    client
        .call("share.add", share_params("tank", "second", 45022, false))
        .unwrap();
    assert!(smb_negotiate_probe(45021).starts_with(&[0xFE, b'S', b'M', b'B']));
    assert!(smb_negotiate_probe(45022).starts_with(&[0xFE, b'S', b'M', b'B']));
    match client.call(
        "pool.detach",
        object(vec![("name", Value::Str("tank".into()))]),
    ) {
        Err(CallError::Daemon { code, message }) => {
            assert_eq!(code, "conflict");
            assert!(message.contains("2 SMB shares"), "{message}");
        }
        other => panic!("expected a two-share conflict, got {other:?}"),
    }
    client
        .call(
            "share.remove",
            object(vec![("name", Value::Str("first".into()))]),
        )
        .unwrap();
    match client.call(
        "pool.detach",
        object(vec![("name", Value::Str("tank".into()))]),
    ) {
        Err(CallError::Daemon { code, message }) => {
            assert_eq!(code, "conflict");
            assert!(message.contains("share"), "{message}");
        }
        other => panic!("expected a share conflict, got {other:?}"),
    }
    client
        .call(
            "share.remove",
            object(vec![("name", Value::Str("second".into()))]),
        )
        .unwrap();
    client
        .call(
            "pool.detach",
            object(vec![("name", Value::Str("tank".into()))]),
        )
        .unwrap();
    daemon.shutdown();
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn share_remove_terminates_connections() {
    use std::io::Read;

    let (dir, a, b) = scratch_pool("smb-conn");
    let daemon = DaemonUnderTest::spawn("smb-conn");
    let mut client = daemon.client();
    client
        .call("pool.attach", attach_params("tank", &[&a, &b], false))
        .unwrap();
    client
        .call("share.add", share_params("tank", "vault", 45023, false))
        .unwrap();

    let (mut stream, reply) = smb_negotiate_stream(45023);
    assert!(reply.starts_with(&[0xFE, b'S', b'M', b'B']));

    let removal = std::time::Instant::now();
    client
        .call(
            "share.remove",
            object(vec![("name", Value::Str("vault".into()))]),
        )
        .unwrap();
    assert!(
        removal.elapsed() < Duration::from_secs(30),
        "share.remove took {:?} — a connection did not notice the stop",
        removal.elapsed()
    );
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut probe = [0u8; 1];
    match stream.read(&mut probe) {
        Ok(0) => {}
        Err(error)
            if error.kind() != std::io::ErrorKind::WouldBlock
                && error.kind() != std::io::ErrorKind::TimedOut => {}
        other => panic!("the connection survived share.remove: {other:?}"),
    }

    client
        .call(
            "pool.detach",
            object(vec![("name", Value::Str("tank".into()))]),
        )
        .unwrap();
    daemon.shutdown();
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn smb_shares_respect_pool_state() {
    let (dir, a, b) = scratch_pool("smb-ro");
    std::fs::remove_file(&b).unwrap();
    let daemon = DaemonUnderTest::spawn("smb-ro");
    let mut client = daemon.client();

    match client.call("share.add", share_params("ghost", "vault", 45002, false)) {
        Err(CallError::Daemon { code, .. }) => assert_eq!(code, "not_found"),
        other => panic!("expected not_found, got {other:?}"),
    }

    client
        .call("pool.attach", attach_params("wounded", &[&a], true))
        .unwrap();

    match client.call("share.add", share_params("wounded", "vault", 45002, false)) {
        Err(CallError::Daemon { code, message }) => {
            assert_eq!(code, "conflict");
            assert!(message.contains("read-only"), "{message}");
        }
        other => panic!("expected a read-only refusal, got {other:?}"),
    }

    let added = client
        .call("share.add", share_params("wounded", "vault", 45002, true))
        .unwrap();
    assert_eq!(added.get("read_only"), Some(&Value::Bool(true)));
    let reply = smb_negotiate_probe(45002);
    assert!(
        reply.starts_with(&[0xFE, b'S', b'M', b'B']),
        "served read-only"
    );

    client
        .call(
            "share.remove",
            object(vec![("name", Value::Str("vault".into()))]),
        )
        .unwrap();
    daemon.shutdown();
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(target_os = "linux")]
#[test]
fn pools_mount_and_serve_through_the_kernel() {
    if !std::path::Path::new("/dev/fuse").exists() {
        eprintln!("skipping: /dev/fuse absent");
        return;
    }
    let (dir, a, b) = scratch_pool("mount");
    let payload: Vec<u8> = (0..30_000usize).map(|i| (i * 7 % 251) as u8).collect();
    {
        use scalefs_core::{AnyBlockDevice, Pool};
        let devices = vec![
            AnyBlockDevice::open(std::path::Path::new(&a)).unwrap(),
            AnyBlockDevice::open(std::path::Path::new(&b)).unwrap(),
        ];
        let mut pool = Pool::open_multi(devices).unwrap();
        let docs = pool
            .mkdir(
                scalefs_core::ROOT_INODE,
                "docs",
                0o755,
                1_700_000_000_000_000_000,
            )
            .unwrap();
        let notes = pool
            .create_file(docs, "notes.txt", 0o644, 1_700_000_000_000_000_000)
            .unwrap();
        pool.write(notes, 0, &payload, 1_700_000_000_000_000_000)
            .unwrap();
        pool.commit(
            scalefs_core::AllocPurpose::Normal,
            1_700_000_000_000_000_000,
        )
        .unwrap();
    }

    let daemon = DaemonUnderTest::spawn("mount");
    let mut client = daemon.client();
    client
        .call("pool.attach", attach_params("tank", &[&a, &b], false))
        .unwrap();

    let mountpoint = dir.join("mnt");
    std::fs::create_dir_all(&mountpoint).unwrap();
    let mount_params = object(vec![
        ("name", Value::Str("tank".into())),
        (
            "mountpoint",
            Value::Str(mountpoint.to_string_lossy().into_owned()),
        ),
        ("read_only", Value::Bool(true)),
    ]);
    let mounted = match client.call("pool.mount", mount_params) {
        Ok(mounted) => mounted,
        Err(CallError::Daemon { code, message })
            if code == "io"
                && (message.contains("Operation not permitted")
                    || message.contains("Permission denied")) =>
        {
            eprintln!("skipping: mounting needs root ({message})");
            daemon.shutdown();
            let _ = std::fs::remove_dir_all(dir);
            return;
        }
        other => panic!("mount failed: {other:?}"),
    };
    assert_eq!(mounted.get("read_only"), Some(&Value::Bool(true)));

    match client.call(
        "pool.detach",
        object(vec![("name", Value::Str("tank".into()))]),
    ) {
        Err(CallError::Daemon { code, message }) => {
            assert_eq!(code, "conflict");
            assert!(message.contains("unmount"), "{message}");
        }
        other => panic!("expected conflict, got {other:?}"),
    }

    let names: Vec<String> = std::fs::read_dir(&mountpoint)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["docs".to_string()]);
    let file = mountpoint.join("docs").join("notes.txt");
    let metadata = std::fs::metadata(&file).unwrap();
    assert_eq!(metadata.len(), payload.len() as u64);
    assert_eq!(std::fs::read(&file).unwrap(), payload);
    assert!(std::fs::write(mountpoint.join("nope.txt"), b"x").is_err());
    let status = client
        .call(
            "pool.status",
            object(vec![("name", Value::Str("tank".into()))]),
        )
        .unwrap();
    assert_eq!(
        status.get("mounted_at").and_then(Value::as_str),
        Some(mountpoint.to_string_lossy().as_ref()),
    );

    client
        .call(
            "pool.unmount",
            object(vec![("name", Value::Str("tank".into()))]),
        )
        .unwrap();
    assert_eq!(std::fs::read_dir(&mountpoint).unwrap().count(), 0);
    client
        .call(
            "pool.detach",
            object(vec![("name", Value::Str("tank".into()))]),
        )
        .unwrap();

    daemon.shutdown();
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(target_os = "linux")]
#[test]
fn pools_mount_read_write_and_persist() {
    use std::os::unix::fs::PermissionsExt;

    if !std::path::Path::new("/dev/fuse").exists() {
        eprintln!("skipping: /dev/fuse absent");
        return;
    }
    let (dir, a, b) = scratch_pool_sized("rw", 64);
    let daemon = DaemonUnderTest::spawn("rw-mount");
    let mut client = daemon.client();
    let attached = client
        .call("pool.attach", attach_params("tank", &[&a, &b], false))
        .unwrap();
    let tx_at_attach = attached.get("tx").unwrap().as_u64().unwrap();

    let mountpoint = dir.join("mnt");
    std::fs::create_dir_all(&mountpoint).unwrap();
    let mount_params = || {
        object(vec![
            ("name", Value::Str("tank".into())),
            (
                "mountpoint",
                Value::Str(mountpoint.to_string_lossy().into_owned()),
            ),
        ])
    };
    let mounted = match client.call("pool.mount", mount_params()) {
        Ok(mounted) => mounted,
        Err(CallError::Daemon { code, message })
            if code == "io"
                && (message.contains("Operation not permitted")
                    || message.contains("Permission denied")) =>
        {
            eprintln!("skipping: mounting needs root ({message})");
            daemon.shutdown();
            let _ = std::fs::remove_dir_all(dir);
            return;
        }
        other => panic!("mount failed: {other:?}"),
    };
    assert_eq!(mounted.get("read_only"), Some(&Value::Bool(false)));

    let docs = mountpoint.join("docs");
    std::fs::create_dir(&docs).unwrap();
    let payload: Vec<u8> = (0..48_000usize).map(|i| (i * 31 % 251) as u8).collect();
    std::fs::write(docs.join("report.bin"), &payload).unwrap();
    std::fs::write(mountpoint.join("draft.txt"), b"first thoughts").unwrap();
    std::fs::write(mountpoint.join("scrap.txt"), b"disposable").unwrap();

    {
        use std::io::{Seek, Write};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(docs.join("report.bin"))
            .unwrap();
        file.seek(std::io::SeekFrom::Start(1000)).unwrap();
        file.write_all(&[0xEE; 128]).unwrap();
        file.sync_all().unwrap();
    }
    let mut expected = payload.clone();
    expected[1000..1128].fill(0xEE);

    std::fs::rename(mountpoint.join("draft.txt"), mountpoint.join("final.txt")).unwrap();
    std::fs::remove_file(mountpoint.join("scrap.txt")).unwrap();
    std::fs::set_permissions(
        mountpoint.join("final.txt"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let truncated = std::fs::OpenOptions::new()
        .write(true)
        .open(mountpoint.join("final.txt"))
        .unwrap();
    truncated.set_len(5).unwrap();
    drop(truncated);

    assert_eq!(std::fs::read(docs.join("report.bin")).unwrap(), expected);
    assert_eq!(
        std::fs::read(mountpoint.join("final.txt")).unwrap(),
        b"first"
    );
    assert!(!mountpoint.join("scrap.txt").exists());
    assert!(!mountpoint.join("draft.txt").exists());
    let mode = std::fs::metadata(mountpoint.join("final.txt"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o7777, 0o600);
    let status = client
        .call(
            "pool.status",
            object(vec![("name", Value::Str("tank".into()))]),
        )
        .unwrap();
    assert_eq!(
        status.get("mounted_at").and_then(Value::as_str),
        Some(mountpoint.to_string_lossy().as_ref()),
    );
    assert!(status.get("mounted_read_only").is_none());

    client
        .call(
            "pool.unmount",
            object(vec![("name", Value::Str("tank".into()))]),
        )
        .unwrap();
    let status = client
        .call(
            "pool.status",
            object(vec![("name", Value::Str("tank".into()))]),
        )
        .unwrap();
    assert!(
        status.get("tx").unwrap().as_u64().unwrap() > tx_at_attach,
        "unmount refreshes the settled-state snapshot"
    );
    client.call("pool.mount", mount_params()).unwrap();
    assert_eq!(std::fs::read(docs.join("report.bin")).unwrap(), expected);
    assert_eq!(
        std::fs::read(mountpoint.join("final.txt")).unwrap(),
        b"first"
    );
    assert!(!mountpoint.join("scrap.txt").exists());

    client
        .call(
            "pool.unmount",
            object(vec![("name", Value::Str("tank".into()))]),
        )
        .unwrap();
    client
        .call(
            "pool.detach",
            object(vec![("name", Value::Str("tank".into()))]),
        )
        .unwrap();
    client
        .call("pool.attach", attach_params("tank", &[&a, &b], false))
        .unwrap();
    client.call("pool.mount", mount_params()).unwrap();
    assert_eq!(std::fs::read(docs.join("report.bin")).unwrap(), expected);
    let names: Vec<String> = std::fs::read_dir(&mountpoint)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names.len(), 2, "docs and final.txt: {names:?}");

    client
        .call(
            "pool.unmount",
            object(vec![("name", Value::Str("tank".into()))]),
        )
        .unwrap();
    client
        .call(
            "pool.detach",
            object(vec![("name", Value::Str("tank".into()))]),
        )
        .unwrap();
    daemon.shutdown();
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn pool_serve_sessions_and_fencing() {
    use std::io::{Read, Write};

    let (dir, a, b) = scratch_pool("serve");
    let daemon = DaemonUnderTest::spawn("serve");
    let mut client = daemon.client();
    client
        .call("pool.attach", attach_params("tank", &[&a, &b], false))
        .unwrap();

    let served = client
        .call(
            "pool.serve",
            object(vec![("pool", Value::Str("tank".into()))]),
        )
        .unwrap();
    let endpoint = served
        .get("endpoint")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let token = served.get("token").unwrap().as_str().unwrap().to_string();
    assert_eq!(served.get("read_only"), Some(&Value::Bool(false)));

    let refused = client.call(
        "pool.serve",
        object(vec![("pool", Value::Str("tank".into()))]),
    );
    assert!(refused.is_err());
    let listing = client.call("serve.list", Value::Null).unwrap();
    let rows = listing.get("serving").unwrap().as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].get("endpoint").unwrap().as_str(),
        Some(endpoint.as_str())
    );

    let mut stream = std::net::TcpStream::connect(&endpoint).unwrap();
    let mut req_id = 0u32;
    let mut call = |stream: &mut std::net::TcpStream, op: u16, body: &[u8]| -> (i16, Vec<u8>) {
        req_id += 1;
        let mut frame = Vec::new();
        frame.extend_from_slice(&((8 + body.len()) as u32).to_le_bytes());
        frame.extend_from_slice(&req_id.to_le_bytes());
        frame.extend_from_slice(&op.to_le_bytes());
        frame.extend_from_slice(&0u16.to_le_bytes());
        frame.extend_from_slice(body);
        stream.write_all(&frame).unwrap();
        let mut len = [0u8; 4];
        stream.read_exact(&mut len).unwrap();
        let mut reply = vec![0u8; u32::from_le_bytes(len) as usize];
        stream.read_exact(&mut reply).unwrap();
        (
            i16::from_le_bytes(reply[4..6].try_into().unwrap()),
            reply[8..].to_vec(),
        )
    };
    let bytes_field = |payload: &[u8]| -> Vec<u8> {
        let mut out = (payload.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(payload);
        out
    };
    let mut hello = 1u16.to_le_bytes().to_vec();
    hello.extend_from_slice(&[0x77; 16]);
    hello.extend_from_slice(&bytes_field(token.as_bytes()));
    let (code, reply) = call(&mut stream, 1, &hello);
    assert_eq!(code, 0, "HELLO refused");
    assert_eq!(reply[6], 0, "writable pool advertised read-write");

    let mut mkdir = 1u64.to_le_bytes().to_vec();
    mkdir.extend_from_slice(&bytes_field(b"native"));
    mkdir.extend_from_slice(&0o755u32.to_le_bytes());
    mkdir.extend_from_slice(&[0u8; 8]);
    let (code, attr) = call(&mut stream, 10, &mkdir);
    assert_eq!(code, 0, "MKDIR failed");
    let dir_inode = u64::from_le_bytes(attr[0..8].try_into().unwrap());

    let mut lookup = 1u64.to_le_bytes().to_vec();
    lookup.extend_from_slice(&bytes_field(b"native"));
    let (code, found) = call(&mut stream, 3, &lookup);
    assert_eq!(code, 0);
    assert_eq!(
        u64::from_le_bytes(found[0..8].try_into().unwrap()),
        dir_inode
    );

    let refused = client.call(
        "pool.detach",
        object(vec![("name", Value::Str("tank".into()))]),
    );
    assert!(refused.is_err(), "detach must refuse while served");

    let (code, _) = call(&mut stream, 26, &[]);
    assert_eq!(code, 0);
    drop(stream);

    client
        .call(
            "pool.serve_stop",
            object(vec![("pool", Value::Str("tank".into()))]),
        )
        .unwrap();
    client
        .call(
            "pool.detach",
            object(vec![("name", Value::Str("tank".into()))]),
        )
        .unwrap();

    let reattached = client
        .call("pool.attach", attach_params("tank", &[&a, &b], false))
        .unwrap();
    assert_eq!(reattached.get("name").unwrap().as_str(), Some("tank"));
    let status = client
        .call(
            "pool.status",
            object(vec![("name", Value::Str("tank".into()))]),
        )
        .unwrap();
    assert!(status.get("tx").unwrap().as_u64().unwrap() >= 2);
    client
        .call(
            "pool.detach",
            object(vec![("name", Value::Str("tank".into()))]),
        )
        .unwrap();
    daemon.shutdown();
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(unix)]
#[test]
fn pool_serve_over_a_unix_socket() {
    use std::io::{Read, Write};

    let (dir, a, b) = scratch_pool("serveuds");
    let daemon = DaemonUnderTest::spawn("serveuds");
    let mut client = daemon.client();
    client
        .call("pool.attach", attach_params("tank", &[&a, &b], false))
        .unwrap();

    let socket_path = dir.join("dataplane.sock");
    let served = client
        .call(
            "pool.serve",
            object(vec![
                ("pool", Value::Str("tank".into())),
                (
                    "unix_socket",
                    Value::Str(socket_path.to_string_lossy().into_owned()),
                ),
            ]),
        )
        .unwrap();
    let endpoint = served
        .get("endpoint")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    assert!(endpoint.starts_with("unix:"), "{endpoint}");
    let token = served.get("token").unwrap().as_str().unwrap().to_string();

    let mut stream = std::os::unix::net::UnixStream::connect(&socket_path).unwrap();
    let mut hello = Vec::new();
    let mut body = 1u16.to_le_bytes().to_vec();
    body.extend_from_slice(&[0x77; 16]);
    body.extend_from_slice(&(token.len() as u32).to_le_bytes());
    body.extend_from_slice(token.as_bytes());
    hello.extend_from_slice(&((8 + body.len()) as u32).to_le_bytes());
    hello.extend_from_slice(&1u32.to_le_bytes());
    hello.extend_from_slice(&1u16.to_le_bytes());
    hello.extend_from_slice(&0u16.to_le_bytes());
    hello.extend_from_slice(&body);
    stream.write_all(&hello).unwrap();
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).unwrap();
    let mut reply = vec![0u8; u32::from_le_bytes(len) as usize];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(i16::from_le_bytes(reply[4..6].try_into().unwrap()), 0);
    drop(stream);

    client
        .call(
            "pool.serve_stop",
            object(vec![("pool", Value::Str("tank".into()))]),
        )
        .unwrap();
    assert!(!socket_path.exists(), "the socket file is removed on stop");
    client
        .call(
            "pool.detach",
            object(vec![("name", Value::Str("tank".into()))]),
        )
        .unwrap();
    daemon.shutdown();
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn pool_serve_kernel_device_validation() {
    let (dir, a, b) = scratch_pool("servek");
    let daemon = DaemonUnderTest::spawn("servek");
    let mut client = daemon.client();
    client
        .call("pool.attach", attach_params("tank", &[&a, &b], false))
        .unwrap();

    let both = client.call(
        "pool.serve",
        object(vec![
            ("pool", Value::Str("tank".into())),
            ("unix_socket", Value::Str("/tmp/never-bound.sock".into())),
            ("kernel_device", Value::Str(r"\\.\ScaleFsCtl".into())),
        ]),
    );
    assert!(both.is_err(), "unix_socket + kernel_device must be refused");

    let mount_alone = client.call(
        "pool.serve",
        object(vec![
            ("pool", Value::Str("tank".into())),
            ("mount", Value::Str("Z:".into())),
        ]),
    );
    assert!(mount_alone.is_err(), "mount without kernel_device refused");
    for bad in ["Z", "Z:\\", "ZZ:", "5:", ""] {
        let shape = client.call(
            "pool.serve",
            object(vec![
                ("pool", Value::Str("tank".into())),
                ("kernel_device", Value::Str(r"\\.\ScaleFsCtl".into())),
                ("mount", Value::Str(bad.into())),
            ]),
        );
        assert!(shape.is_err(), "mount letter {bad:?} must be refused");
    }
    let auto = client.call(
        "pool.serve",
        object(vec![
            ("pool", Value::Str("tank".into())),
            ("kernel_device", Value::Str(r"\\.\ScaleFsCtl".into())),
            ("mount", Value::Str("auto".into())),
        ]),
    );
    match auto {
        Ok(_) => {
            client
                .call(
                    "pool.serve_stop",
                    object(vec![("pool", Value::Str("tank".into()))]),
                )
                .unwrap();
        }
        Err(error) => {
            let text = format!("{error}");
            assert!(
                !text.contains("must be"),
                "mount \"auto\" was shape-rejected: {text}"
            );
        }
    }
    {
        let listing = client.call("serve.list", Value::Null).unwrap();
        let rows = listing.get("serving").unwrap().as_array().unwrap();
        assert!(rows.is_empty(), "refused mounts must not register");
    }

    let kernel = client.call(
        "pool.serve",
        object(vec![
            ("pool", Value::Str("tank".into())),
            ("kernel_device", Value::Str(r"\\.\ScaleFsCtl".into())),
        ]),
    );
    match kernel {
        Ok(served) => {
            let endpoint = served.get("endpoint").unwrap().as_str().unwrap();
            assert!(endpoint.starts_with("kernel:"), "{endpoint}");
            client
                .call(
                    "pool.serve_stop",
                    object(vec![("pool", Value::Str("tank".into()))]),
                )
                .unwrap();
        }
        Err(_) => {
            let listing = client.call("serve.list", Value::Null).unwrap();
            let rows = listing.get("serving").unwrap().as_array().unwrap();
            assert!(rows.is_empty(), "a failed serve must not register");
        }
    }

    client
        .call(
            "pool.detach",
            object(vec![("name", Value::Str("tank".into()))]),
        )
        .unwrap();
    daemon.shutdown();
    let _ = std::fs::remove_dir_all(dir);
}
