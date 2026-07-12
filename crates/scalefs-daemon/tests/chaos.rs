
use scalefs_ipc::client::Client;
use scalefs_ipc::endpoint::Endpoint;
use scalefs_ipc::json::{Value, object};
use scalefs_mount::smb::testclient::TcpSmbClient;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SMB_TIMEOUT: Duration = Duration::from_secs(15);
const USER: &str = "backup";
const PASSWORD: &str = "s3cret-pass";
const SHARE: &str = "vault";

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique(tag: &str) -> (Endpoint, u16, PathBuf) {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = format!("scalefsd-chaos-{}-{tag}-{n}", std::process::id());
    let endpoint = if cfg!(windows) {
        Endpoint::new(&name)
    } else {
        Endpoint::new(
            &std::env::temp_dir()
                .join(format!("{name}.sock"))
                .to_string_lossy(),
        )
    };
    let port = 47_000 + (n as u16 % 2000);
    let dir = std::env::temp_dir().join(format!(
        "scalefsd-chaos-work-{}-{tag}-{n}",
        std::process::id(),
    ));
    (endpoint, port, dir)
}

struct Daemon {
    child: Child,
    endpoint: Endpoint,
}

impl Daemon {
    fn spawn(endpoint: &Endpoint, state_dir: &std::path::Path) -> Daemon {
        let child = Command::new(env!("CARGO_BIN_EXE_scalefsd"))
            .args([
                "serve",
                "--endpoint",
                endpoint.as_str(),
                "--state-dir",
                &state_dir.to_string_lossy(),
            ])
            .spawn()
            .expect("run scalefsd");
        let daemon = Daemon {
            child,
            endpoint: endpoint.clone(),
        };
        daemon.await_up();
        daemon
    }

    fn await_up(&self) {
        for _ in 0..100 {
            if let Ok(mut client) = Client::connect(&self.endpoint, Duration::from_millis(200))
                && client.call("ping", Value::Null).is_ok()
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("daemon did not come up on {}", self.endpoint.as_str());
    }

    fn client(&self) -> Client {
        Client::connect(&self.endpoint, CONNECT_TIMEOUT).expect("connect to scalefsd")
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn shutdown(mut self) {
        if let Ok(mut client) = Client::connect(&self.endpoint, CONNECT_TIMEOUT) {
            let _ = client.call("shutdown", object(vec![("force", Value::Bool(true))]));
        }
        let _ = self.child.wait();
        std::mem::forget(self);
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const ZONE_COUNT: u64 = 256;

fn geometry() -> scalefs_core::Geometry {
    scalefs_core::Geometry {
        logical_block_size: 4096,
        physical_block_size: 4096,
        zone_size: 64 * 1024,
        zone_count: ZONE_COUNT,
        erase_granularity_zones: 1,
        sequential_write_required: false,
    }
}

fn create_pool(dir: &std::path::Path, count: usize) -> Vec<String> {
    use scalefs_core::{
        CaseSensitivity, DeviceId, FileBlockDevice, MemberSpec, Pool, PoolId, PoolParams,
    };
    std::fs::create_dir_all(dir).unwrap();
    let geometry = geometry();
    let paths: Vec<PathBuf> = (0..count).map(|i| dir.join(format!("m{i}.img"))).collect();
    let members = paths
        .iter()
        .enumerate()
        .map(|(i, path)| MemberSpec {
            device: FileBlockDevice::create(path, geometry.capacity_bytes()).unwrap(),
            device_id: DeviceId([0xA0 + i as u8; 16]),
            geometry,
        })
        .collect();
    Pool::create_multi(
        members,
        PoolParams {
            pool_id: PoolId([0x77; 16]),
            case_sensitivity: CaseSensitivity::InsensitivePreserving,
            dirent_hash_seed: 42,
            label: "tank".to_string(),
            created_at_ns: 1_700_000_000_000_000_000,
            mirror_width: 2,
            data_width: 1,
            parity_width: 0,
        },
    )
    .unwrap();
    paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect()
}

fn member_size() -> u64 {
    geometry().capacity_bytes()
}

fn attach(client: &mut Client, name: &str, members: &[String]) {
    let params = object(vec![
        ("name", Value::Str(name.to_string())),
        (
            "members",
            Value::Array(members.iter().cloned().map(Value::Str).collect()),
        ),
    ]);
    client.call("pool.attach", params).expect("attach");
}

fn add_share(client: &mut Client, pool: &str, port: u16) {
    let params = object(vec![
        ("pool", Value::Str(pool.to_string())),
        ("name", Value::Str(SHARE.to_string())),
        ("user", Value::Str(USER.to_string())),
        ("password", Value::Str(PASSWORD.to_string())),
        ("port", Value::Int(i128::from(port))),
    ]);
    client.call("share.add", params).expect("share.add");
}

fn smb_addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn content(n: u64, revision: u64, len: usize) -> Vec<u8> {
    let mut seed = n
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(revision.wrapping_mul(0xD1B5_4A32_D192_ED03));
    (0..len)
        .map(|_| {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (seed >> 33) as u8
        })
        .collect()
}

fn run_job(client: &mut Client, op: &str, params: Value) -> Value {
    let started = client.call(op, params).expect("start job");
    let id = started.get("job").and_then(Value::as_u64).expect("job id");
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let status = client
            .call(
                "job.status",
                object(vec![("id", Value::Int(i128::from(id)))]),
            )
            .expect("job status");
        match status.get("state").and_then(Value::as_str) {
            Some("running") => {
                assert!(std::time::Instant::now() < deadline, "job {op} hung");
                std::thread::sleep(Duration::from_millis(20));
            }
            Some("done") => return status.get("result").cloned().unwrap_or(Value::Null),
            other => panic!("job {op} ended {other:?}: {status:?}"),
        }
    }
}

#[derive(Default)]
struct Durable {
    files: std::collections::BTreeMap<String, Vec<u8>>,
}

fn write_durable_batch(
    port: u16,
    durable: &mut Durable,
    names: &[String],
    revision: u64,
    len: usize,
) {
    let mut smb = TcpSmbClient::connect(smb_addr(port), USER, PASSWORD, SHARE, SMB_TIMEOUT)
        .expect("SMB connect for a write batch");
    for (n, name) in names.iter().enumerate() {
        let data = content(n as u64, revision, len);
        let file = smb.create(name).expect("create");
        smb.write(file, 0, &data).expect("write");
        smb.flush(file).expect("flush");
        smb.close(file).expect("close");
        durable.files.insert(name.clone(), data);
    }
}

fn verify_offline(members: &[String], durable: &Durable) {
    use scalefs_core::{AnyBlockDevice, Pool};
    let mut last_err = None;
    let mut pool = None;
    for _ in 0..50 {
        let devices: Result<Vec<_>, _> = members
            .iter()
            .map(|p| AnyBlockDevice::open(std::path::Path::new(p)).map(std::sync::Arc::new))
            .collect();
        match devices.and_then(Pool::open_multi) {
            Ok(p) => {
                pool = Some(p);
                break;
            }
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(Duration::from_millis(40));
            }
        }
    }
    let mut pool = pool.unwrap_or_else(|| panic!("offline reopen failed: {last_err:?}"));

    let report = pool.scrub(false).expect("offline scrub");
    assert!(
        report.healthy(),
        "offline scrub unhealthy: {} bad / {} unrepairable",
        report.copies_bad,
        report.copies_unrepairable,
    );
    for (name, expected) in &durable.files {
        let entry = pool
            .lookup(scalefs_core::tree::ROOT_INODE, name)
            .unwrap_or_else(|e| panic!("durable file '{name}' gone after crash: {e:?}"));
        let got = pool
            .read(entry.inode, 0, expected.len())
            .unwrap_or_else(|e| panic!("durable file '{name}' unreadable after crash: {e:?}"));
        assert_eq!(
            &got, expected,
            "durable file '{name}' changed across a crash"
        );
    }
}

fn verify_over_smb(port: u16, durable: &Durable) {
    let mut smb = TcpSmbClient::connect(smb_addr(port), USER, PASSWORD, SHARE, SMB_TIMEOUT)
        .expect("SMB connect for verification");
    for (name, expected) in &durable.files {
        let file = smb
            .create(name)
            .unwrap_or_else(|e| panic!("open '{name}': {e:?}"));
        let got = smb
            .read(file, 0, expected.len() as u32)
            .unwrap_or_else(|e| panic!("read '{name}': {e:?}"));
        assert_eq!(&got, expected, "SMB read of '{name}' differs after restart");
        smb.close(file).expect("close");
    }
}

#[test]
fn smb_tcp_client_round_trips_a_file_through_the_daemon() {
    let (endpoint, port, dir) = unique("smoke");
    let members = create_pool(&dir, 2);
    let daemon = Daemon::spawn(&endpoint, &dir.join("state"));
    {
        let mut client = daemon.client();
        attach(&mut client, "tank", &members);
        add_share(&mut client, "tank", port);
    }

    let mut smb = TcpSmbClient::connect(smb_addr(port), USER, PASSWORD, SHARE, SMB_TIMEOUT)
        .expect("SMB connect + login + tree-connect");
    let data = content(0, 0, 40_000);
    let file = smb.create("round.bin").expect("create");
    let written = smb.write(file, 0, &data).expect("write");
    assert_eq!(written as usize, data.len(), "short write");
    smb.flush(file).expect("flush");
    let read = smb.read(file, 0, data.len() as u32).expect("read");
    assert_eq!(read, data, "SMB read did not match the write");
    smb.close(file).expect("close");
    drop(smb);

    daemon.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}

fn batch_names(count: usize) -> Vec<String> {
    (0..count).map(|i| format!("f{i:03}")).collect()
}

#[test]
fn daemon_survives_crashes_and_membership_verbs() {
    let (endpoint, port, dir) = unique("chaos");
    let state = dir.join("state");
    let mut members = create_pool(&dir, 3);
    let mut durable = Durable::default();
    let names = batch_names(8);

    let mut daemon = Daemon::spawn(&endpoint, &state);
    {
        let mut client = daemon.client();
        attach(&mut client, "tank", &members);
        add_share(&mut client, "tank", port);
    }
    write_durable_batch(port, &mut durable, &names, 0, 30_000);
    {
        let mut client = daemon.client();
        let report = run_job(
            &mut client,
            "pool.scrub",
            object(vec![("name", Value::Str("tank".into()))]),
        );
        assert_eq!(report.get("healthy"), Some(&Value::Bool(true)));
    }
    daemon.kill();
    verify_offline(&members, &durable);

    let mut daemon = Daemon::spawn(&endpoint, &state);
    {
        let mut client = daemon.client();
        let status = client
            .call(
                "pool.status",
                object(vec![("name", Value::Str("tank".into()))]),
            )
            .expect("reassembled pool present");
        assert_eq!(status.get("name").and_then(Value::as_str), Some("tank"));
        let shares = client.call("share.list", Value::Null).expect("share.list");
        let restored = shares
            .get("shares")
            .and_then(Value::as_array)
            .is_some_and(|rows| {
                rows.iter().any(|row| {
                    row.get("name").and_then(Value::as_str) == Some(SHARE)
                        && row.get("port").and_then(Value::as_u64) == Some(u64::from(port))
                })
            });
        assert!(
            restored,
            "the share must restore from the state dir: {shares:?}",
        );
    }
    verify_over_smb(port, &durable);
    write_durable_batch(port, &mut durable, &names[..4], 1, 45_000);
    let more = batch_names(12);
    write_durable_batch(port, &mut durable, &more[8..], 0, 20_000);

    let target = dir.join("m3.img");
    let target_path = target.to_string_lossy().into_owned();
    {
        let mut client = daemon.client();
        let added = run_job(
            &mut client,
            "pool.add",
            object(vec![
                ("name", Value::Str("tank".into())),
                ("target", Value::Str(target_path.clone())),
                ("size", Value::Int(i128::from(member_size()))),
                ("zone_size", Value::Int(64 * 1024)),
            ]),
        );
        let member = added
            .get("member")
            .and_then(Value::as_u64)
            .expect("added member index");
        members.push(target_path.clone());
        write_durable_batch(port, &mut durable, &batch_names(16)[12..], 0, 25_000);
        run_job(
            &mut client,
            "pool.remove",
            object(vec![
                ("name", Value::Str("tank".into())),
                ("member", Value::Int(i128::from(member))),
            ]),
        );
        members.retain(|m| m != &target_path);
    }
    verify_over_smb(port, &durable);

    write_durable_batch(port, &mut durable, &batch_names(20)[16..], 0, 18_000);
    daemon.kill();
    verify_offline(&members, &durable);

    let daemon = Daemon::spawn(&endpoint, &state);
    daemon.shutdown();
    let pools_record = std::fs::read_to_string(state.join("pools.json")).expect("pools.json");
    assert!(pools_record.contains("tank"), "{pools_record}");
    let shares_record = std::fs::read_to_string(state.join("shares.json")).expect("shares.json");
    assert!(shares_record.contains(SHARE), "{shares_record}");
    verify_offline(&members, &durable);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn removed_shares_stay_removed_and_missing_pools_skip() {
    let (endpoint, port, dir) = unique("persist-neg");
    let state = dir.join("state");
    let members = create_pool(&dir, 2);

    let share_row_count = |client: &mut Client| -> usize {
        client
            .call("share.list", Value::Null)
            .expect("share.list")
            .get("shares")
            .and_then(Value::as_array)
            .map_or(0, <[Value]>::len)
    };
    let pool_row_count = |client: &mut Client| -> usize {
        client
            .call("pool.list", Value::Null)
            .expect("pool.list")
            .get("pools")
            .and_then(Value::as_array)
            .map_or(0, <[Value]>::len)
    };

    {
        let daemon = Daemon::spawn(&endpoint, &state);
        {
            let mut client = daemon.client();
            attach(&mut client, "tank", &members);
            add_share(&mut client, "tank", port);
            client
                .call(
                    "share.remove",
                    object(vec![("name", Value::Str(SHARE.into()))]),
                )
                .expect("share.remove");
        }
        daemon.shutdown();
    }
    let mut daemon = Daemon::spawn(&endpoint, &state);
    {
        let mut client = daemon.client();
        assert_eq!(pool_row_count(&mut client), 1, "the pool restores");
        assert_eq!(
            share_row_count(&mut client),
            0,
            "the removed share stays removed"
        );
        add_share(&mut client, "tank", port);
    }
    daemon.kill();

    let hidden = PathBuf::from(&members[0]).with_extension("hidden");
    std::fs::rename(&members[0], &hidden).expect("hide member");
    let mut daemon = Daemon::spawn(&endpoint, &state);
    {
        let mut client = daemon.client();
        assert_eq!(
            pool_row_count(&mut client),
            0,
            "a half-missing pool is never attached"
        );
        assert_eq!(share_row_count(&mut client), 0, "its share skips with it");
    }
    daemon.kill();

    std::fs::rename(&hidden, &members[0]).expect("return member");
    let daemon = Daemon::spawn(&endpoint, &state);
    {
        let mut client = daemon.client();
        assert_eq!(pool_row_count(&mut client), 1, "the pool is back");
        assert_eq!(share_row_count(&mut client), 1, "the share is back");
    }
    daemon.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}
