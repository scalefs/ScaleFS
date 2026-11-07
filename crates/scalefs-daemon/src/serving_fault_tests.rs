use super::*;
use crate::pools::Registry;
use scalefs_core::{
    CaseSensitivity, DeviceId, FileBlockDevice, Geometry, MemberSpec, Pool, PoolId, PoolParams,
};
use std::time::{Duration, Instant};

fn served_pool(tag: &str) -> (Registry, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("scalefsd-listener-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let geometry = Geometry {
        logical_block_size: 4096,
        physical_block_size: 4096,
        zone_size: 64 * 1024,
        zone_count: 16,
        erase_granularity_zones: 1,
        sequential_write_required: false,
    };
    let image = dir.join("a.img");
    let member = MemberSpec {
        device: FileBlockDevice::create(
            &image,
            scalefs_core::member_image_len(geometry.capacity_bytes()),
        )
        .unwrap(),
        device_id: DeviceId([0xD1; 16]),
        geometry,
    };
    Pool::create_multi(
        vec![member],
        PoolParams {
            pool_id: PoolId([0xD0; 16]),
            case_sensitivity: CaseSensitivity::InsensitivePreserving,
            dirent_hash_seed: 3,
            label: "listener".to_string(),
            created_at_ns: 1_700_000_000_000_000_000,
            mirror_width: 1,
            data_width: 1,
            parity_width: 0,
        },
    )
    .unwrap();
    let registry = Registry::default();
    registry
        .attach(&object(vec![
            ("name", Value::Str("listener".into())),
            (
                "members",
                Value::Array(vec![Value::Str(image.to_string_lossy().into_owned())]),
            ),
        ]))
        .unwrap();
    (registry, dir)
}

#[test]
fn a_dataplane_connection_that_never_authenticates_is_dropped() {
    let (registry, dir) = served_pool("idle");
    let core = registry
        .share_handle("listener")
        .unwrap()
        .core
        .clone()
        .expect("a writable attachment has a mount core");
    let stop = Arc::new(AtomicBool::new(false));
    let connections = Arc::new(Mutex::new(Vec::new()));
    let session = SessionParams {
        pool_id: [0xD0; 16],
        token: b"session-token".to_vec(),
        read_only: false,
        close_durability: CloseDurability::default(),
    };
    let (endpoint, accept) = bind_tcp(&stop, &connections, &core, &session).unwrap();

    let mut idle = std::net::TcpStream::connect(endpoint.as_str()).unwrap();
    idle.set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let started = Instant::now();
    let mut byte = [0u8; 1];
    let outcome = idle.read(&mut byte);
    let waited = started.elapsed();

    stop.store(true, Ordering::SeqCst);
    accept.join().unwrap();
    let sessions: Vec<_> = connections.lock().unwrap().drain(..).collect();
    for session in sessions {
        session.join().unwrap();
    }
    drop(idle);
    drop(core);
    let _ = registry.detach(&object(vec![("name", Value::Str("listener".into()))]));
    let _ = std::fs::remove_dir_all(dir);

    let still_open = matches!(
        &outcome,
        Err(error) if matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        )
    );
    assert!(
        !still_open,
        "after {waited:?} the server still held a connection that never sent HELLO"
    );
    assert!(
        waited < HELLO_DEADLINE + Duration::from_secs(2),
        "it took {waited:?} to drop (the handshake deadline is {HELLO_DEADLINE:?})"
    );
}

#[test]
fn the_handshake_cap_counts_only_the_unauthenticated() {
    let handshakes = Handshakes::default();
    let held: Vec<Admission> = (0..MAX_PENDING_HANDSHAKES)
        .map(|_| {
            handshakes
                .admit(MAX_PENDING_HANDSHAKES)
                .expect("under the cap")
        })
        .collect();
    assert!(
        handshakes.admit(MAX_PENDING_HANDSHAKES).is_none(),
        "the cap refuses the next connection"
    );
    drop(held.into_iter().next());
    let next = handshakes.admit(MAX_PENDING_HANDSHAKES);
    assert!(next.is_some(), "a freed slot admits the next connection");
}
