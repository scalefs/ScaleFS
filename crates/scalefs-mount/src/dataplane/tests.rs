use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, RwLock};

use scalefs_core::layout::{CaseSensitivity, DeviceId, PoolId};
use scalefs_core::pool::{CreateParams, Pool};
use scalefs_core::{Geometry, MemoryBlockDevice};

use super::wire::{op, setattr_mask, status};
use super::{SessionEnd, SessionParams, serve_connection};
use crate::mountcore::MountCore;

const NOW: i64 = 1_700_000_000_000_000_000;
const POOL_ID: [u8; 16] = [0x77; 16];
const TOKEN: &[u8] = b"test-session-token";

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

fn new_core() -> Arc<MountCore<Arc<MemoryBlockDevice>>> {
    let device = Arc::new(MemoryBlockDevice::new(scalefs_core::member_image_len(
        geometry().capacity_bytes(),
    ) as usize));
    let pool = Pool::create(
        device,
        CreateParams {
            pool_id: PoolId(POOL_ID),
            device_id: DeviceId([0x78; 16]),
            geometry: geometry(),
            case_sensitivity: CaseSensitivity::InsensitivePreserving,
            dirent_hash_seed: 5,
            label: "plane".to_string(),
            created_at_ns: NOW,
        },
    )
    .unwrap();
    Arc::new(MountCore::read_write(Arc::new(RwLock::new(pool))))
}

fn serve(
    core: Arc<MountCore<Arc<MemoryBlockDevice>>>,
    read_only: bool,
) -> (TcpStream, std::thread::JoinHandle<SessionEnd>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let session = SessionParams {
        pool_id: POOL_ID,
        token: TOKEN.to_vec(),
        read_only,
    };
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        serve_connection(&mut stream, &core, &session, None)
    });
    (TcpStream::connect(addr).unwrap(), server)
}

struct Client {
    stream: TcpStream,
    next_id: u32,
}

impl Client {
    fn new(stream: TcpStream) -> Self {
        Client { stream, next_id: 1 }
    }

    fn call(&mut self, op_code: u16, body: &[u8]) -> (i16, Vec<u8>) {
        let req_id = self.next_id;
        self.next_id += 1;
        let mut frame = Vec::with_capacity(12 + body.len());
        frame.extend_from_slice(&((8 + body.len()) as u32).to_le_bytes());
        frame.extend_from_slice(&req_id.to_le_bytes());
        frame.extend_from_slice(&op_code.to_le_bytes());
        frame.extend_from_slice(&0u16.to_le_bytes());
        frame.extend_from_slice(body);
        self.stream.write_all(&frame).unwrap();

        let mut len = [0u8; 4];
        self.stream.read_exact(&mut len).unwrap();
        let mut reply = vec![0u8; u32::from_le_bytes(len) as usize];
        self.stream.read_exact(&mut reply).unwrap();
        assert_eq!(
            u32::from_le_bytes(reply[0..4].try_into().unwrap()),
            req_id,
            "req_id echo"
        );
        let status = i16::from_le_bytes(reply[4..6].try_into().unwrap());
        (status, reply[8..].to_vec())
    }

    fn ok(&mut self, op_code: u16, body: &[u8]) -> Vec<u8> {
        let (status_code, reply) = self.call(op_code, body);
        assert_eq!(status_code, status::OK, "op {op_code} failed");
        reply
    }

    fn hello(&mut self) {
        let mut body = Vec::new();
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&POOL_ID);
        body.extend_from_slice(&(TOKEN.len() as u32).to_le_bytes());
        body.extend_from_slice(TOKEN);
        let reply = self.ok(op::HELLO, &body);
        assert_eq!(u16::from_le_bytes(reply[0..2].try_into().unwrap()), 1);
    }

    fn bye(mut self) {
        let (status_code, _) = self.call(op::BYE, &[]);
        assert_eq!(status_code, status::OK);
    }
}

fn bytes_field(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

fn attr_inode(attr: &[u8]) -> u64 {
    u64::from_le_bytes(attr[0..8].try_into().unwrap())
}
fn attr_mode(attr: &[u8]) -> u32 {
    u32::from_le_bytes(attr[8..12].try_into().unwrap())
}
fn attr_nlink(attr: &[u8]) -> u32 {
    u32::from_le_bytes(attr[12..16].try_into().unwrap())
}
fn attr_size(attr: &[u8]) -> u64 {
    u64::from_le_bytes(attr[24..32].try_into().unwrap())
}
fn attr_attrflags(attr: &[u8]) -> u32 {
    u32::from_le_bytes(attr[76..80].try_into().unwrap())
}
fn attr_bsd_flags(attr: &[u8]) -> u32 {
    u32::from_le_bytes(attr[80..84].try_into().unwrap())
}

#[derive(Default)]
struct RecordingBarrier {
    prepares: std::sync::Mutex<Vec<[u8; 16]>>,
    aborts: std::sync::Mutex<Vec<u64>>,
    commits: std::sync::Mutex<Vec<u64>>,
}

const SCRIPTED_GENERATION: u64 = 0x0102_0304_0506_0708;

impl super::EjectBarrier for RecordingBarrier {
    fn prepare(&self, pool_id: &[u8; 16]) -> super::PrepareOutcome {
        self.prepares.lock().unwrap().push(*pool_id);
        super::PrepareOutcome {
            verdict: super::PrepareVerdict::Ack,
            generation: SCRIPTED_GENERATION,
        }
    }

    fn abort(&self, _pool_id: &[u8; 16], generation: u64) {
        self.aborts.lock().unwrap().push(generation);
    }

    fn commit(&self, _pool_id: &[u8; 16], generation: u64) -> super::PrepareVerdict {
        self.commits.lock().unwrap().push(generation);
        super::PrepareVerdict::Ack
    }
}

fn serve_with_barrier(
    core: Arc<MountCore<Arc<MemoryBlockDevice>>>,
    barrier: Arc<RecordingBarrier>,
) -> (TcpStream, std::thread::JoinHandle<SessionEnd>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let session = SessionParams {
        pool_id: POOL_ID,
        token: TOKEN.to_vec(),
        read_only: false,
    };
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        serve_connection(&mut stream, &core, &session, Some(barrier.as_ref()))
    });
    (TcpStream::connect(addr).unwrap(), server)
}

fn eject_body(generation: Option<u64>) -> Vec<u8> {
    let mut body = POOL_ID.to_vec();
    body.extend_from_slice(&0u32.to_le_bytes());
    if let Some(generation) = generation {
        body.extend_from_slice(&generation.to_le_bytes());
    }
    body
}

#[test]
fn the_eject_frames_are_byte_exact() {
    use super::wire::eject;
    let barrier = Arc::new(RecordingBarrier::default());
    let (stream, server) = serve_with_barrier(new_core(), Arc::clone(&barrier));
    let mut client = Client::new(stream);
    client.hello();

    let reply = client.ok(op::EJECT_PREPARE, &eject_body(None));
    assert_eq!(reply.len(), eject::PREPARE_REPLY_LEN);
    assert_eq!(reply[0], eject::ACK);
    assert_eq!(
        u64::from_le_bytes(reply[1..9].try_into().unwrap()),
        SCRIPTED_GENERATION,
    );
    assert_eq!(&barrier.prepares.lock().unwrap()[..], &[POOL_ID]);

    let reply = client.ok(op::EJECT_ABORT, &eject_body(Some(SCRIPTED_GENERATION)));
    assert_eq!(reply, vec![eject::ACK]);
    let reply = client.ok(op::EJECT_ABORT, &eject_body(None));
    assert_eq!(reply, vec![eject::ACK]);
    assert_eq!(
        &barrier.aborts.lock().unwrap()[..],
        &[SCRIPTED_GENERATION, eject::BLIND_GENERATION],
    );

    let reply = client.ok(op::EJECT_COMMIT, &eject_body(Some(SCRIPTED_GENERATION)));
    assert_eq!(reply, vec![eject::ACK]);
    assert_eq!(&barrier.commits.lock().unwrap()[..], &[SCRIPTED_GENERATION]);

    for (op_code, body) in [
        (op::EJECT_COMMIT, eject_body(None)),
        (op::EJECT_PREPARE, eject_body(Some(1))),
        (op::EJECT_ABORT, POOL_ID.to_vec()),
        (op::EJECT_COMMIT, Vec::new()),
    ] {
        let (code, _) = client.call(op_code, &body);
        assert_eq!(
            code,
            status::PROTOCOL,
            "op {op_code:#x} must not be guessed"
        );
    }
    let mut reserved_set = POOL_ID.to_vec();
    reserved_set.extend_from_slice(&1u32.to_le_bytes());
    let (code, _) = client.call(op::EJECT_PREPARE, &reserved_set);
    assert_eq!(code, status::PROTOCOL);

    client.bye();
    assert_eq!(server.join().unwrap(), SessionEnd::Bye);
}

#[test]
fn eject_frames_fail_closed_without_a_barrier() {
    use super::wire::eject;
    let (stream, server) = serve(new_core(), false);
    let mut client = Client::new(stream);
    client.hello();

    let reply = client.ok(op::EJECT_PREPARE, &eject_body(None));
    assert_eq!(reply.len(), eject::PREPARE_REPLY_LEN);
    assert_eq!(reply[0], eject::UNSUPPORTED);
    assert_eq!(u64::from_le_bytes(reply[1..9].try_into().unwrap()), 0);
    assert_eq!(
        client.ok(op::EJECT_ABORT, &eject_body(None)),
        vec![eject::UNSUPPORTED],
    );
    assert_eq!(
        client.ok(op::EJECT_COMMIT, &eject_body(Some(9))),
        vec![eject::UNSUPPORTED],
    );

    client.bye();
    assert_eq!(server.join().unwrap(), SessionEnd::Bye);
}

#[test]
fn handshake_gates_the_session() {
    let (stream, server) = serve(new_core(), false);
    let mut client = Client::new(stream);
    let mut body = Vec::new();
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&POOL_ID);
    body.extend_from_slice(&bytes_field(b"wrong"));
    let (code, _) = client.call(op::HELLO, &body);
    assert_eq!(code, status::BAD_TOKEN);
    assert_eq!(server.join().unwrap(), SessionEnd::Error);

    let (stream, server) = serve(new_core(), false);
    let mut client = Client::new(stream);
    let mut body = Vec::new();
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&POOL_ID);
    body.extend_from_slice(&bytes_field(TOKEN));
    let (code, _) = client.call(op::HELLO, &body);
    assert_eq!(code, status::BAD_VERSION);
    server.join().unwrap();

    let (stream, server) = serve(new_core(), false);
    let mut client = Client::new(stream);
    let (code, _) = client.call(op::STATFS, &[]);
    assert_eq!(code, status::PROTOCOL);
    server.join().unwrap();
}

#[test]
fn the_full_surface_over_loopback() {
    let core = new_core();
    let (stream, server) = serve(Arc::clone(&core), false);
    let mut client = Client::new(stream);
    client.hello();

    let statfs = client.ok(op::STATFS, &[]);
    assert!(u64::from_le_bytes(statfs[0..8].try_into().unwrap()) > 0);

    let mut body = 1u64.to_le_bytes().to_vec();
    body.extend_from_slice(&bytes_field(b"dir"));
    body.extend_from_slice(&0o755u32.to_le_bytes());
    body.extend_from_slice(&501u32.to_le_bytes());
    body.extend_from_slice(&20u32.to_le_bytes());
    let dir_attr = client.ok(op::MKDIR, &body);
    let dir = attr_inode(&dir_attr);

    let mut body = dir.to_le_bytes().to_vec();
    body.extend_from_slice(&bytes_field(b"file.bin"));
    body.extend_from_slice(&0o644u32.to_le_bytes());
    body.extend_from_slice(&501u32.to_le_bytes());
    body.extend_from_slice(&20u32.to_le_bytes());
    let file_attr = client.ok(op::CREATE, &body);
    let file = attr_inode(&file_attr);

    let payload: Vec<u8> = (0..1_500_000usize).map(|i| (i % 251) as u8).collect();
    let mut written = 0usize;
    while written < payload.len() {
        let chunk = (payload.len() - written).min(1 << 20);
        let mut body = file.to_le_bytes().to_vec();
        body.extend_from_slice(&(written as u64).to_le_bytes());
        body.extend_from_slice(&bytes_field(&payload[written..written + chunk]));
        let reply = client.ok(op::WRITE, &body);
        written += u32::from_le_bytes(reply[0..4].try_into().unwrap()) as usize;
    }
    let mut read_back = Vec::new();
    while read_back.len() < payload.len() {
        let mut body = file.to_le_bytes().to_vec();
        body.extend_from_slice(&(read_back.len() as u64).to_le_bytes());
        body.extend_from_slice(&(1u32 << 20).to_le_bytes());
        let reply = client.ok(op::READ, &body);
        let len = u32::from_le_bytes(reply[0..4].try_into().unwrap()) as usize;
        if len == 0 {
            break;
        }
        read_back.extend_from_slice(&reply[4..4 + len]);
    }
    assert_eq!(read_back, payload, "chunked round trip");

    let mut body = file.to_le_bytes().to_vec();
    body.extend_from_slice(
        &(setattr_mask::MODE | setattr_mask::BSD_FLAGS | setattr_mask::MTIME_NOW).to_le_bytes(),
    );
    body.extend_from_slice(&0u64.to_le_bytes());
    body.extend_from_slice(&0o600u32.to_le_bytes());
    body.extend_from_slice(&[0u8; 8]);
    body.extend_from_slice(&[0u8; 32]);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0x8000u32.to_le_bytes());
    let changed = client.ok(op::SETATTR, &body);
    assert_eq!(attr_mode(&changed) & 0o777, 0o600);
    assert_eq!(attr_bsd_flags(&changed), 0x8000);
    assert_eq!(attr_size(&changed), 1_500_000);

    let mut body = file.to_le_bytes().to_vec();
    body.extend_from_slice(&bytes_field(b"com.apple.FinderInfo"));
    body.extend_from_slice(&bytes_field(&[0xAB; 32]));
    body.extend_from_slice(&0u32.to_le_bytes());
    client.ok(op::SETXATTR, &body);
    let mut body = file.to_le_bytes().to_vec();
    body.extend_from_slice(&bytes_field(b"com.apple.FinderInfo"));
    let value = client.ok(op::GETXATTR, &body);
    assert_eq!(&value[4..], &[0xAB; 32]);
    let mut body = file.to_le_bytes().to_vec();
    body.extend_from_slice(&bytes_field(b"system.posix_acl_access"));
    body.extend_from_slice(&bytes_field(b"x"));
    body.extend_from_slice(&0u32.to_le_bytes());
    let (code, _) = client.call(op::SETXATTR, &body);
    assert_eq!(code, status::NOT_SUPPORTED);

    let mut body = dir.to_le_bytes().to_vec();
    body.extend_from_slice(&bytes_field(b"ln"));
    body.extend_from_slice(&bytes_field(b"file.bin"));
    body.extend_from_slice(&501u32.to_le_bytes());
    body.extend_from_slice(&20u32.to_le_bytes());
    let link_attr = client.ok(op::SYMLINK, &body);
    let mut body = attr_inode(&link_attr).to_le_bytes().to_vec();
    let target = client.ok(op::READLINK, &body);
    assert_eq!(&target[4..], b"file.bin");
    body.clear();

    let mut body = file.to_le_bytes().to_vec();
    body.extend_from_slice(&dir.to_le_bytes());
    body.extend_from_slice(&bytes_field(b"second-name"));
    let linked = client.ok(op::LINK, &body);
    assert_eq!(attr_nlink(&linked), 2);

    let mut body = dir.to_le_bytes().to_vec();
    body.extend_from_slice(&0u64.to_le_bytes());
    let full = client.ok(op::READDIR, &body);
    let full_next = u64::from_le_bytes(full[0..8].try_into().unwrap());
    let full_names = parse_readdir(&full, false);
    assert_eq!(full_names.len(), 3, "{full_names:?}");
    assert_eq!(full_next, 0, "one page delivers the whole directory");
    let mut body = dir.to_le_bytes().to_vec();
    body.extend_from_slice(&u64::MAX.to_le_bytes());
    let past = client.ok(op::READDIR, &body);
    assert!(
        parse_readdir(&past, false).is_empty(),
        "resuming past every hash is empty"
    );

    let mut body = dir.to_le_bytes().to_vec();
    body.extend_from_slice(&0u64.to_le_bytes());
    let plus = client.ok(op::READDIR_PLUS, &body);
    let plus_names = parse_readdir(&plus, true);
    assert_eq!(plus_names, full_names);

    let mut body = dir.to_le_bytes().to_vec();
    body.extend_from_slice(&bytes_field(b"second-name"));
    body.extend_from_slice(&dir.to_le_bytes());
    body.extend_from_slice(&bytes_field(b"ln"));
    body.push(0);
    let (code, _) = client.call(op::RENAME, &body);
    assert_eq!(code, status::EXISTS);
    let len = body.len();
    body[len - 1] = 1;
    client.ok(op::RENAME, &body);

    let body = file.to_le_bytes().to_vec();
    client.ok(op::OPEN, &body);
    let mut unlink = dir.to_le_bytes().to_vec();
    unlink.extend_from_slice(&bytes_field(b"file.bin"));
    client.ok(op::UNLINK, &unlink);
    let mut unlink2 = dir.to_le_bytes().to_vec();
    unlink2.extend_from_slice(&bytes_field(b"ln"));
    client.ok(op::UNLINK, &unlink2);
    let attr = client.ok(op::GETATTR, &body);
    assert_eq!(attr_attrflags(&attr) & 1, 1, "deferred bit");
    client.ok(op::CLOSE, &body);
    let (code, _) = client.call(op::GETATTR, &body);
    assert_eq!(code, status::NOT_FOUND, "last close reaps");

    let mut body = dir.to_le_bytes().to_vec();
    body.push(0);
    client.ok(op::FSYNC, &body);
    let (code, _) = client.call(200, &[]);
    assert_eq!(code, status::UNKNOWN_OP);

    client.bye();
    assert_eq!(server.join().unwrap(), SessionEnd::Bye);

    assert!(core.getattr(dir).is_ok());
}

fn parse_readdir(reply: &[u8], plus: bool) -> Vec<String> {
    let count = u32::from_le_bytes(reply[8..12].try_into().unwrap());
    let mut names = Vec::new();
    let mut at = 12usize;
    for _ in 0..count {
        at += 8;
        at += 1;
        let len = u32::from_le_bytes(reply[at..at + 4].try_into().unwrap()) as usize;
        at += 4;
        names.push(String::from_utf8(reply[at..at + len].to_vec()).unwrap());
        at += len;
        if plus {
            at += super::wire::ATTR_LEN;
        }
    }
    assert_eq!(at, reply.len(), "no trailing bytes");
    names
}

#[test]
fn read_only_sessions_advertise_and_refuse() {
    let device = Arc::new(MemoryBlockDevice::new(scalefs_core::member_image_len(
        geometry().capacity_bytes(),
    ) as usize));
    let pool = Pool::create(
        Arc::clone(&device),
        CreateParams {
            pool_id: PoolId(POOL_ID),
            device_id: DeviceId([0x78; 16]),
            geometry: geometry(),
            case_sensitivity: CaseSensitivity::InsensitivePreserving,
            dirent_hash_seed: 5,
            label: "plane".to_string(),
            created_at_ns: NOW,
        },
    )
    .unwrap();
    let core = Arc::new(MountCore::read_only(Arc::new(RwLock::new(pool))));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let session = SessionParams {
        pool_id: POOL_ID,
        token: TOKEN.to_vec(),
        read_only: true,
    };
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        serve_connection(&mut stream, &core, &session, None)
    });
    let mut client = Client::new(TcpStream::connect(addr).unwrap());

    let mut body = Vec::new();
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&POOL_ID);
    body.extend_from_slice(&bytes_field(TOKEN));
    let reply = client.ok(op::HELLO, &body);
    assert_eq!(reply[6], 1, "read_only advertised");

    let mut body = 1u64.to_le_bytes().to_vec();
    body.extend_from_slice(&bytes_field(b"nope"));
    body.extend_from_slice(&0o755u32.to_le_bytes());
    body.extend_from_slice(&[0u8; 8]);
    let (code, _) = client.call(op::MKDIR, &body);
    assert_eq!(code, status::READ_ONLY);

    client.bye();
    server.join().unwrap();
}

#[test]
fn hostile_bodies_answer_protocol_errors() {
    let (stream, server) = serve(new_core(), false);
    let mut client = Client::new(stream);
    client.hello();
    let (code, _) = client.call(op::LOOKUP, &[1, 2, 3]);
    assert_eq!(code, status::PROTOCOL);
    let mut body = 1u64.to_le_bytes().to_vec();
    body.extend_from_slice(&1000u32.to_le_bytes());
    body.extend_from_slice(b"short");
    let (code, _) = client.call(op::LOOKUP, &body);
    assert_eq!(code, status::PROTOCOL);
    let mut body = 1u64.to_le_bytes().to_vec();
    body.extend_from_slice(&0u64.to_le_bytes());
    body.extend_from_slice(&(2u32 << 20).to_le_bytes());
    let (code, _) = client.call(op::READ, &body);
    assert_eq!(code, status::PROTOCOL);
    let (code, _) = client.call(op::HELLO, &[]);
    assert_eq!(code, status::PROTOCOL);
    client.bye();
    server.join().unwrap();
}
