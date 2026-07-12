
use crate::pools::{PoolHandle, ShareGuard};
use scalefs_core::AnyBlockDevice;
use scalefs_ipc::json::{Value, object};
use scalefs_ipc::proto::ErrorCode;
use scalefs_mount::mountcore::MountCore;
use scalefs_mount::smb::ntlm::Credential;
use scalefs_mount::smb::session::{
    Connection, Handler, Route, frame_parallel_reply, verify_parallel,
};
use scalefs_mount::smb::share::{ConnectionNonces, ShareConfig, SmbShare};
use scalefs_mount::smb::wire::{self, parse_transport_header};
use std::collections::{BTreeMap, VecDeque};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

type ShareCore = Arc<MountCore<Arc<AnyBlockDevice>>>;

type Conn = (TcpStream, std::thread::JoinHandle<()>);

const DEFAULT_PORT: u16 = 4450;

const MAX_MESSAGE: usize = 2 << 20;

const STOP_POLL: std::time::Duration = std::time::Duration::from_millis(500);

const IN_FLIGHT_CAP: usize = 256;
const IN_FLIGHT_BYTES_CAP: usize = 32 << 20;

enum IoEnd {
    Done,
    Over,
}

fn is_idle_tick(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::Interrupted
    )
}

fn read_full(stream: &mut TcpStream, buf: &mut [u8], halt: &dyn Fn() -> bool) -> IoEnd {
    let mut at = 0;
    while at < buf.len() {
        if halt() {
            return IoEnd::Over;
        }
        match stream.read(&mut buf[at..]) {
            Ok(0) => return IoEnd::Over,
            Ok(n) => at += n,
            Err(error) if is_idle_tick(&error) => {}
            Err(_) => return IoEnd::Over,
        }
    }
    IoEnd::Done
}

fn write_full(stream: &mut TcpStream, buf: &[u8], halt: &dyn Fn() -> bool) -> IoEnd {
    let mut at = 0;
    while at < buf.len() {
        if halt() {
            return IoEnd::Over;
        }
        match stream.write(&buf[at..]) {
            Ok(0) => return IoEnd::Over,
            Ok(n) => at += n,
            Err(error) if is_idle_tick(&error) => {}
            Err(_) => return IoEnd::Over,
        }
    }
    IoEnd::Done
}

fn smb_worker_count() -> usize {
    if let Some(value) = std::env::var_os("SCALEFS_SMB_WORKERS")
        && let Some(n) = value.to_str().and_then(|v| v.parse::<usize>().ok())
    {
        return n.min(64);
    }
    std::thread::available_parallelism().map_or(2, |n| n.get().min(4))
}

struct ConnWriter {
    stream: Mutex<TcpStream>,
    stop: Arc<AtomicBool>,
    dead: AtomicBool,
    in_flight: Mutex<(usize, usize)>,
    settled: Condvar,
}

impl ConnWriter {
    fn halted(&self) -> bool {
        self.stop.load(Ordering::SeqCst) || self.dead.load(Ordering::SeqCst)
    }

    fn kill(&self) {
        self.dead.store(true, Ordering::SeqCst);
        if let Ok(stream) = self.stream.lock() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }

    fn send(&self, reply: &[u8]) {
        if self.halted() {
            return;
        }
        let over = {
            let mut stream = self.stream.lock().expect("smb write half");
            matches!(
                write_full(&mut stream, reply, &|| self.halted()),
                IoEnd::Over
            )
        };
        if over {
            self.kill();
        }
    }

    fn begin(&self, bytes: usize) {
        let mut in_flight = self.in_flight.lock().expect("smb in-flight count");
        in_flight.0 += 1;
        in_flight.1 += bytes;
    }

    fn has_capacity(&self) -> bool {
        let in_flight = self.in_flight.lock().expect("smb in-flight count");
        in_flight.0 < IN_FLIGHT_CAP && in_flight.1 < IN_FLIGHT_BYTES_CAP
    }

    fn settle(&self, bytes: usize) {
        let mut in_flight = self.in_flight.lock().expect("smb in-flight count");
        in_flight.0 -= 1;
        in_flight.1 -= bytes;
        if in_flight.0 == 0 {
            self.settled.notify_all();
        }
    }

    fn drain(&self) {
        let mut in_flight = self.in_flight.lock().expect("smb in-flight count");
        while in_flight.0 > 0 {
            in_flight = self.settled.wait(in_flight).expect("smb in-flight count");
        }
    }
}

struct SmbWork {
    header: wire::Header,
    message: Vec<u8>,
    key: [u8; 16],
    session_id: u64,
    share: Arc<SmbShare<Arc<AnyBlockDevice>>>,
    writer: Arc<ConnWriter>,
    conn_id: u64,
    trace: bool,
}

struct SmbDispatchPool {
    queue: Mutex<VecDeque<SmbWork>>,
    available: Condvar,
    stop: AtomicBool,
    workers: Mutex<Vec<std::thread::JoinHandle<()>>>,
}

impl SmbDispatchPool {
    fn start(worker_count: usize) -> Arc<SmbDispatchPool> {
        let pool = Arc::new(SmbDispatchPool {
            queue: Mutex::new(VecDeque::new()),
            available: Condvar::new(),
            stop: AtomicBool::new(false),
            workers: Mutex::new(Vec::new()),
        });
        {
            let mut workers = pool.workers.lock().expect("smb dispatch workers");
            for index in 0..worker_count {
                let pool = Arc::clone(&pool);
                if let Ok(handle) = std::thread::Builder::new()
                    .name(format!("scalefs-smb-dispatch-{index}"))
                    .spawn(move || dispatch_worker(&pool))
                {
                    workers.push(handle);
                }
            }
        }
        pool
    }

    fn active(&self) -> bool {
        !self
            .workers
            .lock()
            .expect("smb dispatch workers")
            .is_empty()
    }

    fn submit(&self, work: SmbWork) {
        work.writer.begin(work.message.len());
        self.queue
            .lock()
            .expect("smb dispatch queue")
            .push_back(work);
        self.available.notify_one();
    }

    fn next(&self) -> Option<SmbWork> {
        let mut queue = self.queue.lock().expect("smb dispatch queue");
        loop {
            if let Some(work) = queue.pop_front() {
                return Some(work);
            }
            if self.stop.load(Ordering::SeqCst) {
                return None;
            }
            queue = self.available.wait(queue).expect("smb dispatch queue");
        }
    }

    fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.available.notify_all();
        let workers: Vec<_> = {
            let mut workers = self.workers.lock().expect("smb dispatch workers");
            workers.drain(..).collect()
        };
        for worker in workers {
            let _ = worker.join();
        }
    }
}

fn dispatch_worker(pool: &SmbDispatchPool) {
    while let Some(work) = pool.next() {
        let writer = Arc::clone(&work.writer);
        let bytes = work.message.len();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| serve_routed(work)));
        if outcome.is_err() {
            eprintln!("scalefsd smb: a dispatch worker caught a panic; its connection is dropped");
            writer.kill();
        }
        writer.settle(bytes);
    }
}

fn serve_routed(work: SmbWork) {
    if work.writer.halted() {
        return;
    }
    if !verify_parallel(&work.message, &work.key) {
        if work.trace {
            eprintln!(
                "scalefsd smb: [c{}] dropping connection (bad signature on a routed request)",
                work.conn_id
            );
        }
        work.writer.kill();
        return;
    }
    let body = &work.message[wire::HEADER_LEN..];
    let response = work.share.dispatch(&work.header, body);
    let reply = frame_parallel_reply(&work.header, response, &work.key, work.session_id);
    if work.trace && reply.len() > 4 {
        trace_message(work.conn_id, "send", &reply[4..]);
    }
    work.writer.send(&reply);
}

pub type OpError = (ErrorCode, String);

#[derive(Default)]
pub struct Shares {
    shares: Mutex<BTreeMap<String, Arc<ActiveShare>>>,
    state: Option<Arc<crate::state::SharesStore>>,
}

struct ActiveShare {
    name: String,
    pool: String,
    port: u16,
    user: String,
    nt_hash: [u8; 16],
    read_only: bool,
    core: ShareCore,
    _guard: ShareGuard,
    stop: Arc<AtomicBool>,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
    connections: Arc<Mutex<Vec<Conn>>>,
    dispatch: Arc<SmbDispatchPool>,
}

impl Shares {
    pub fn with_state(state: Option<Arc<crate::state::SharesStore>>) -> Shares {
        Shares {
            state,
            ..Shares::default()
        }
    }

    pub fn add(
        &self,
        params: &Value,
        resolve_pool: impl Fn(&str) -> Result<PoolHandle, OpError>,
    ) -> Result<Value, OpError> {
        let name = required_str(params, "name")?;
        let pool = required_str(params, "pool")?;
        let user = required_str(params, "user")?;
        let password = required_str(params, "password")?;
        let port = match params.get("port") {
            None => DEFAULT_PORT,
            Some(value) => value
                .as_u64()
                .filter(|p| (1..=65535).contains(p))
                .ok_or((ErrorCode::BadRequest, "port must be 1-65535".to_string()))?
                as u16,
        };
        let requested_read_only = match params.get("read_only") {
            None => false,
            Some(Value::Bool(flag)) => *flag,
            Some(_) => {
                return Err((
                    ErrorCode::BadRequest,
                    "read_only must be a boolean".to_string(),
                ));
            }
        };
        let credential = Credential::new(&user, &password);
        let summary = self.start_share(
            name,
            pool,
            port,
            credential,
            requested_read_only,
            resolve_pool,
        )?;
        self.persist();
        Ok(summary)
    }

    pub fn restore(
        &self,
        store: &crate::state::SharesStore,
        resolve_pool: impl Fn(&str) -> Result<PoolHandle, OpError>,
    ) {
        for recorded in store.load() {
            let Some(nt_hash) = hash_from_hex(&recorded.nt_hash) else {
                eprintln!(
                    "scalefsd: could not restore share '{}' (pool '{}'): \
                     malformed credential record",
                    recorded.name, recorded.pool,
                );
                continue;
            };
            let credential = Credential::from_nt_hash(&recorded.user, nt_hash);
            match self.start_share(
                recorded.name.clone(),
                recorded.pool.clone(),
                recorded.port,
                credential,
                recorded.read_only,
                &resolve_pool,
            ) {
                Ok(_) => println!(
                    "scalefsd: restored share '{}' on 127.0.0.1:{} (pool '{}')",
                    recorded.name, recorded.port, recorded.pool,
                ),
                Err((_code, why)) => eprintln!(
                    "scalefsd: could not restore share '{}' (pool '{}'): {why}",
                    recorded.name, recorded.pool,
                ),
            }
        }
    }

    fn start_share(
        &self,
        name: String,
        pool: String,
        port: u16,
        credential: Credential,
        requested_read_only: bool,
        resolve_pool: impl Fn(&str) -> Result<PoolHandle, OpError>,
    ) -> Result<Value, OpError> {
        if !valid_name(&name) {
            return Err((
                ErrorCode::BadRequest,
                "share name must be 1-64 bytes with no control characters".to_string(),
            ));
        }
        if port == 0 {
            return Err((ErrorCode::BadRequest, "port must be 1-65535".to_string()));
        }
        let user = credential.user.clone();
        let nt_hash = credential.nt_hash;

        let PoolHandle {
            pool: pool_arc,
            core: canonical,
            guard,
        } = resolve_pool(&pool)?;
        let read_only = requested_read_only;
        let core: ShareCore = match (canonical, read_only) {
            (Some(core), _) => core,
            (None, true) => Arc::new(MountCore::read_only(pool_arc)),
            (None, false) => {
                return Err((
                    ErrorCode::Conflict,
                    format!(
                        "pool '{pool}' is read-only (degraded or feature-limited); \
                         add the share with read_only"
                    ),
                ));
            }
        };

        let config = ShareConfig {
            name: name.clone(),
            credential,
            server_guid: random_bytes::<16>(),
            target: "SCALEFS".to_string(),
            read_only,
            throttle: Arc::new(scalefs_mount::smb::ntlm::AuthThrottle::default()),
        };

        let claim_check = |shares: &BTreeMap<String, Arc<ActiveShare>>| -> Result<(), OpError> {
            if shares.contains_key(&name) {
                return Err((
                    ErrorCode::Conflict,
                    format!("a share named '{name}' already exists"),
                ));
            }
            for existing in shares.values() {
                if existing.port == port {
                    return Err((
                        ErrorCode::Conflict,
                        format!("port {port} is already served by share '{}'", existing.name),
                    ));
                }
            }
            Ok(())
        };
        claim_check(&self.shares.lock().expect("shares lock"))?;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).map_err(|error| {
            (
                ErrorCode::Io,
                format!("cannot bind 127.0.0.1:{port}: {error}"),
            )
        })?;
        listener
            .set_nonblocking(true)
            .map_err(|error| (ErrorCode::Io, format!("cannot arm the listener: {error}")))?;

        let stop = Arc::new(AtomicBool::new(false));
        let connections: Arc<Mutex<Vec<Conn>>> = Arc::new(Mutex::new(Vec::new()));
        let dispatch = SmbDispatchPool::start(smb_worker_count());

        let mut shares = self.shares.lock().expect("shares lock");
        if let Err(error) = claim_check(&shares) {
            dispatch.stop();
            return Err(error);
        }
        let spawned = {
            let stop = Arc::clone(&stop);
            let config = config.clone();
            let core = Arc::clone(&core);
            let connections = Arc::clone(&connections);
            let dispatch = Arc::clone(&dispatch);
            std::thread::Builder::new()
                .name(format!("scalefs-smb-{name}"))
                .spawn(move || accept_loop(listener, config, core, stop, connections, dispatch))
        };
        let worker = match spawned {
            Ok(worker) => worker,
            Err(error) => {
                dispatch.stop();
                return Err((
                    ErrorCode::Internal,
                    format!("cannot start listener: {error}"),
                ));
            }
        };

        let active = Arc::new(ActiveShare {
            name: name.clone(),
            pool: pool.clone(),
            port,
            user: user.clone(),
            nt_hash,
            read_only,
            core,
            _guard: guard,
            stop,
            worker: Mutex::new(Some(worker)),
            connections,
            dispatch,
        });
        shares.insert(name.clone(), active);
        Ok(object(vec![
            ("name", Value::Str(name.clone())),
            ("pool", Value::Str(pool)),
            ("port", Value::Int(i128::from(port))),
            ("user", Value::Str(user)),
            ("read_only", Value::Bool(read_only)),
            ("address", Value::Str(format!("\\\\127.0.0.1\\{name}"))),
        ]))
    }

    pub fn remove(&self, params: &Value) -> Result<Value, OpError> {
        let name = required_str(params, "name")?;
        let active = {
            let mut shares = self.shares.lock().expect("shares lock");
            shares.remove(&name)
        }
        .ok_or((ErrorCode::NotFound, format!("no share named '{name}'")))?;
        self.persist();
        active.stop();
        Ok(Value::Null)
    }

    fn persist(&self) {
        let Some(store) = &self.state else { return };
        let snapshot: Vec<crate::state::RecordedShare> = {
            let shares = self.shares.lock().expect("shares lock");
            shares
                .values()
                .map(|share| crate::state::RecordedShare {
                    pool: share.pool.clone(),
                    name: share.name.clone(),
                    port: share.port,
                    user: share.user.clone(),
                    nt_hash: crate::pools::hex(&share.nt_hash),
                    read_only: share.read_only,
                })
                .collect()
        };
        if let Err(error) = store.save(&snapshot) {
            eprintln!("scalefsd: could not persist the share record: {error}");
        }
    }

    pub fn list(&self) -> Result<Value, OpError> {
        let shares = self.shares.lock().expect("shares lock");
        let rows: Vec<Value> = shares
            .values()
            .map(|share| {
                object(vec![
                    ("name", Value::Str(share.name.clone())),
                    ("pool", Value::Str(share.pool.clone())),
                    ("port", Value::Int(i128::from(share.port))),
                    ("user", Value::Str(share.user.clone())),
                    ("read_only", Value::Bool(share.read_only)),
                ])
            })
            .collect();
        Ok(object(vec![("shares", Value::Array(rows))]))
    }

    pub fn stop_all(&self) {
        loop {
            let drained: Vec<Arc<ActiveShare>> = {
                let mut shares = self.shares.lock().expect("shares lock");
                if shares.is_empty() {
                    return;
                }
                std::mem::take(&mut *shares).into_values().collect()
            };
            for share in drained {
                share.stop();
            }
        }
    }
}

impl ActiveShare {
    fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.lock().expect("worker").take() {
            let _ = worker.join();
        }
        let connections: Vec<Conn> = {
            let mut connections = self.connections.lock().expect("connection registry");
            connections.drain(..).collect()
        };
        for (stream, _) in &connections {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        for (_, worker) in connections {
            let _ = worker.join();
        }
        self.dispatch.stop();
        if let Err(error) = self.core.commit_if_dirty() {
            eprintln!(
                "scalefsd smb: the flush for removed share '{}' failed ({error:?}); \
                 the staged changes stay with the pool attachment for retry",
                self.name,
            );
        }
    }
}

fn accept_loop(
    listener: TcpListener,
    config: ShareConfig,
    core: ShareCore,
    stop: Arc<AtomicBool>,
    connections: Arc<Mutex<Vec<Conn>>>,
    dispatch: Arc<SmbDispatchPool>,
) {
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                let Ok(shutdown_handle) = stream.try_clone() else {
                    continue;
                };
                let config = config.clone();
                let core = Arc::clone(&core);
                let stop = Arc::clone(&stop);
                let dispatch = Arc::clone(&dispatch);
                let spawned = std::thread::Builder::new()
                    .name("scalefs-smb-conn".to_string())
                    .spawn(move || serve_smb_connection(stream, config, core, stop, dispatch));
                if let Ok(worker) = spawned {
                    let mut connections = connections.lock().expect("connection registry");
                    connections.retain(|(_, worker)| !worker.is_finished());
                    connections.push((shutdown_handle, worker));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
        }
    }
}

fn serve_smb_connection(
    mut stream: TcpStream,
    config: ShareConfig,
    core: ShareCore,
    stop: Arc<AtomicBool>,
    dispatch: Arc<SmbDispatchPool>,
) {
    static CONN_COUNTER: AtomicU64 = AtomicU64::new(0);
    let conn_id = CONN_COUNTER.fetch_add(1, Ordering::Relaxed);
    let trace = std::env::var_os("SCALEFS_SMB_TRACE").is_some();
    if trace {
        eprintln!("scalefsd smb: [c{conn_id}] new connection");
    }
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(STOP_POLL));
    let _ = stream.set_write_timeout(Some(STOP_POLL));
    let _ = stream.set_nodelay(true);
    let mut connection = Connection::new();
    let (Some(salt), Some(challenge)) = (try_random_bytes::<32>(), try_random_bytes::<8>()) else {
        return;
    };
    let nonces = ConnectionNonces {
        salt,
        challenge,
        system_time: filetime_now(),
    };
    let share = Arc::new(SmbShare::new(config, nonces, core));
    let writer = stream.try_clone().ok().map(|write_half| {
        Arc::new(ConnWriter {
            stream: Mutex::new(write_half),
            stop: Arc::clone(&stop),
            dead: AtomicBool::new(false),
            in_flight: Mutex::new((0, 0)),
            settled: Condvar::new(),
        })
    });
    let routing = dispatch.active() && writer.is_some();

    loop {
        let halt = || {
            stop.load(Ordering::SeqCst)
                || writer
                    .as_ref()
                    .is_some_and(|writer| writer.dead.load(Ordering::SeqCst))
        };
        if halt() {
            break;
        }
        let mut header = [0u8; 4];
        if matches!(read_full(&mut stream, &mut header, &halt), IoEnd::Over) {
            if trace {
                eprintln!("scalefsd smb: connection closed (no more requests)");
            }
            break;
        }
        let Ok(len) = parse_transport_header(&header) else {
            break;
        };
        if len == 0 || len > MAX_MESSAGE {
            break;
        }
        let mut message = vec![0u8; len];
        if matches!(read_full(&mut stream, &mut message, &halt), IoEnd::Over) {
            if trace {
                eprintln!("scalefsd smb: connection closed mid-message");
            }
            break;
        }
        if trace {
            trace_message(conn_id, "recv", &message);
        }
        if routing
            && writer.as_ref().is_some_and(|writer| writer.has_capacity())
            && let Route::Parallel(request) = connection.route(&message)
        {
            dispatch.submit(SmbWork {
                header: request.header,
                message,
                key: request.key,
                session_id: request.session_id,
                share: Arc::clone(&share),
                writer: Arc::clone(writer.as_ref().expect("routing requires a write half")),
                conn_id,
                trace,
            });
            continue;
        }
        if routing && let Some(writer) = &writer {
            writer.drain();
        }
        match connection.handle(&message, share.as_ref()) {
            Some(reply) => {
                if trace && reply.len() > 4 {
                    trace_message(conn_id, "send", &reply[4..]);
                }
                match &writer {
                    Some(writer) if routing => {
                        writer.send(&reply);
                        if writer.dead.load(Ordering::SeqCst) {
                            break;
                        }
                    }
                    _ => {
                        if matches!(write_full(&mut stream, &reply, &halt), IoEnd::Over) {
                            break;
                        }
                    }
                }
            }
            None => {
                if trace {
                    eprintln!("scalefsd smb: dropping connection (garbage or bad signature)");
                }
                break;
            }
        }
    }
    if let Some(writer) = &writer {
        writer.kill();
        writer.drain();
    }
}

fn trace_message(conn_id: u64, direction: &str, message: &[u8]) {
    if message.len() < 16 {
        eprintln!(
            "scalefsd smb: [c{conn_id}] {direction} runt ({} bytes)",
            message.len()
        );
        return;
    }
    let magic: String = message[..4].iter().map(|b| format!("{b:02x}")).collect();
    if message[..4] != [0xFE, b'S', b'M', b'B'] {
        eprintln!(
            "scalefsd smb: [c{conn_id}] {direction} non-SMB2 magic {magic} ({} bytes)",
            message.len()
        );
        return;
    }
    let mut base = 0usize;
    let mut chained = false;
    loop {
        trace_pdu(conn_id, direction, message, base, chained);
        let next = message
            .get(base + 20..base + 24)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .unwrap_or(0) as usize;
        if next == 0 {
            return;
        }
        base += next;
        chained = true;
        if base + 64 > message.len() {
            return;
        }
    }
}

fn trace_pdu(conn_id: u64, direction: &str, message: &[u8], base: usize, chained: bool) {
    let at = |offset: usize| message.get(base + offset).copied().unwrap_or(0);
    let u16_at = |offset: usize| u16::from_le_bytes([at(offset), at(offset + 1)]);
    let u32_at = |offset: usize| {
        u32::from_le_bytes([at(offset), at(offset + 1), at(offset + 2), at(offset + 3)])
    };
    let utf16_at = |offset: usize, byte_len: usize| -> String {
        let start = base.saturating_add(offset);
        let end = start.saturating_add(byte_len).min(message.len());
        let mut text = String::new();
        let mut i = start;
        while i + 1 < end {
            let unit = u16::from_le_bytes([message[i], message[i + 1]]);
            if let Some(c) = char::from_u32(u32::from(unit)) {
                text.push(c);
            }
            i += 2;
        }
        text
    };
    let command = u16_at(12);
    let status = u32_at(8);
    let marker = if chained { "+" } else { " " };
    let name = match command {
        0x0000 => "NEGOTIATE",
        0x0001 => "SESSION_SETUP",
        0x0002 => "LOGOFF",
        0x0003 => "TREE_CONNECT",
        0x0004 => "TREE_DISCONNECT",
        0x0005 => "CREATE",
        0x0006 => "CLOSE",
        0x0007 => "FLUSH",
        0x0008 => "READ",
        0x0009 => "WRITE",
        0x000A => "LOCK",
        0x000B => "IOCTL",
        0x000C => "CANCEL",
        0x000D => "ECHO",
        0x000E => "QUERY_DIRECTORY",
        0x000F => "CHANGE_NOTIFY",
        0x0010 => "QUERY_INFO",
        0x0011 => "SET_INFO",
        0x0012 => "OPLOCK_BREAK",
        other => {
            eprintln!(
                "scalefsd smb: [c{conn_id}] {direction}{marker}cmd 0x{other:04x} \
                 status 0x{status:08x}"
            );
            return;
        }
    };
    let detail = if direction == "recv" {
        match command {
            0x0005 => format!(
                " disp {} opl 0x{:02x} acc 0x{:08x} name '{}'",
                u32_at(64 + 36),
                at(64 + 3),
                u32_at(64 + 24),
                utf16_at(u16_at(64 + 44) as usize, u16_at(64 + 46) as usize),
            ),
            0x0009 => format!(" len {} at {}", u32_at(64 + 4), u64::from(u32_at(64 + 8))),
            0x000B => format!(" ctl 0x{:08x}", u32_at(64 + 4)),
            0x000E => format!(
                " class 0x{:02x} flags 0x{:02x} outlen {}",
                at(64 + 2),
                at(64 + 3),
                u32_at(64 + 28),
            ),
            0x0010 | 0x0011 => {
                format!(" type 0x{:02x} class 0x{:02x}", at(64 + 2), at(64 + 3))
            }
            _ => String::new(),
        }
    } else {
        match command {
            0x000E | 0x0010 => format!(" outbytes {}", u32_at(64 + 4)),
            _ => String::new(),
        }
    };
    eprintln!("scalefsd smb: [c{conn_id}] {direction}{marker}{name}{detail} status 0x{status:08x}");
}

fn filetime_now() -> u64 {
    const EPOCH_DIFFERENCE_SECS: u64 = 11_644_473_600;
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(since) => {
            let unix_100ns = since.as_nanos() / 100;
            let epoch_100ns = u128::from(EPOCH_DIFFERENCE_SECS) * 10_000_000;
            u64::try_from(unix_100ns + epoch_100ns).unwrap_or(u64::MAX)
        }
        Err(_) => 0,
    }
}

pub(crate) fn try_random_bytes<const N: usize>() -> Option<[u8; N]> {
    let mut buf = [0u8; N];
    os_random(&mut buf).ok().map(|()| buf)
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    if os_random(&mut buf).is_err() {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15);
        let mut rng = scalefs_core::rng::XorShift64::new(seed);
        for byte in &mut buf {
            *byte = rng.next_u64() as u8;
        }
    }
    buf
}

#[cfg(unix)]
fn os_random(buf: &mut [u8]) -> std::io::Result<()> {
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(buf))
}

#[cfg(windows)]
fn os_random(buf: &mut [u8]) -> std::io::Result<()> {
    #[allow(unsafe_code)]
    mod ffi {
        #[link(name = "bcryptprimitives", kind = "raw-dylib")]
        unsafe extern "system" {
            pub fn ProcessPrng(pb_data: *mut u8, cb_data: usize) -> i32;
        }
    }
    #[allow(unsafe_code)]
    let ok = unsafe { ffi::ProcessPrng(buf.as_mut_ptr(), buf.len()) };
    if ok == 1 {
        Ok(())
    } else {
        Err(std::io::Error::other("ProcessPrng failed"))
    }
}

fn required_str(params: &Value, key: &str) -> Result<String, OpError> {
    match params.get(key).and_then(Value::as_str) {
        Some(value) if !value.is_empty() => Ok(value.to_string()),
        _ => Err((
            ErrorCode::BadRequest,
            format!("params need a non-empty '{key}'"),
        )),
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && name.chars().all(|c| !c.is_control())
}

fn hash_from_hex(text: &str) -> Option<[u8; 16]> {
    let bytes = text.as_bytes();
    if bytes.len() != 32 {
        return None;
    }
    let nibble = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    };
    let mut hash = [0u8; 16];
    for (i, pair) in bytes.chunks(2).enumerate() {
        hash[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(hash)
}

#[cfg(test)]
mod dispatch_tests {
    use super::*;
    use scalefs_core::{
        AllocPurpose, CaseSensitivity, CreateParams, DeviceId, FileBlockDevice, Geometry, Pool,
        PoolId,
    };
    use scalefs_mount::smb::sign;
    use scalefs_mount::smb::wire::{Header, command, flags};
    use std::sync::RwLock;

    fn temp_core(tag: &str) -> ShareCore {
        let geometry = Geometry {
            logical_block_size: 4096,
            physical_block_size: 4096,
            zone_size: 64 * 1024,
            zone_count: 64,
            erase_granularity_zones: 1,
            sequential_write_required: false,
        };
        let path = std::env::temp_dir().join(format!(
            "scalefs-smb-dispatch-{tag}-{}.img",
            std::process::id(),
        ));
        let _ = std::fs::remove_file(&path);
        let device = FileBlockDevice::create(&path, geometry.capacity_bytes()).unwrap();
        let mut pool = Pool::create(
            Arc::new(AnyBlockDevice::File(device)),
            CreateParams {
                geometry,
                pool_id: PoolId([0x31; 16]),
                device_id: DeviceId([0x32; 16]),
                case_sensitivity: CaseSensitivity::InsensitivePreserving,
                dirent_hash_seed: 5,
                label: tag.to_string(),
                created_at_ns: 1_700_000_000_000_000_000,
            },
        )
        .unwrap();
        pool.commit(AllocPurpose::Normal, 1_700_000_000_000_000_000)
            .unwrap();
        Arc::new(MountCore::read_write(Arc::new(RwLock::new(pool))))
    }

    fn share_over(core: ShareCore) -> Arc<SmbShare<Arc<AnyBlockDevice>>> {
        Arc::new(SmbShare::new(
            ShareConfig {
                name: "p5".to_string(),
                credential: Credential::new("probe", "pr0be"),
                server_guid: [0xCD; 16],
                target: "SCALEFS".to_string(),
                read_only: false,
                throttle: Arc::new(scalefs_mount::smb::ntlm::AuthThrottle::default()),
            },
            ConnectionNonces {
                salt: [0x5A; 32],
                challenge: [0x11; 8],
                system_time: 0,
            },
            core,
        ))
    }

    fn writer_pair() -> (Arc<ConnWriter>, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        let (server, _) = listener.accept().unwrap();
        server.set_read_timeout(Some(STOP_POLL)).unwrap();
        server.set_write_timeout(Some(STOP_POLL)).unwrap();
        let writer = Arc::new(ConnWriter {
            stream: Mutex::new(server),
            stop: Arc::new(AtomicBool::new(false)),
            dead: AtomicBool::new(false),
            in_flight: Mutex::new((0, 0)),
            settled: Condvar::new(),
        });
        (writer, client)
    }

    fn signed_flush(message_id: u64, key: &[u8; 16]) -> (Header, Vec<u8>) {
        let header = Header {
            command: command::FLUSH,
            message_id,
            credits: 1,
            flags: flags::SIGNED,
            ..Header::default()
        };
        let mut message = Vec::new();
        header.encode(&mut message);
        scalefs_core::wire::put_u16(&mut message, 24);
        scalefs_core::wire::put_u16(&mut message, 0);
        scalefs_core::wire::put_u32(&mut message, 0);
        message.extend_from_slice(&[0x11; 16]);
        sign::sign(&mut message, key);
        (header, message)
    }

    fn work(
        pieces: (Header, Vec<u8>),
        key: [u8; 16],
        share: &Arc<SmbShare<Arc<AnyBlockDevice>>>,
        writer: &Arc<ConnWriter>,
    ) -> SmbWork {
        SmbWork {
            header: pieces.0,
            message: pieces.1,
            key,
            session_id: 0x4653_0000_0000_0001,
            share: Arc::clone(share),
            writer: Arc::clone(writer),
            conn_id: 0,
            trace: false,
        }
    }

    #[test]
    fn workers_serve_verify_and_settle() {
        let pool = SmbDispatchPool::start(2);
        assert!(pool.active());
        let share = share_over(temp_core("serve"));
        let key = [7u8; 16];
        let (writer, mut client) = writer_pair();

        pool.submit(work(signed_flush(9, &key), key, &share, &writer));

        let mut transport = [0u8; 4];
        client.read_exact(&mut transport).unwrap();
        let len = parse_transport_header(&transport).unwrap();
        let mut reply = vec![0u8; len];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(
            u32::from_le_bytes(reply[8..12].try_into().unwrap()),
            0,
            "FLUSH answers SUCCESS"
        );
        assert_eq!(
            u64::from_le_bytes(reply[24..32].try_into().unwrap()),
            9,
            "the reply echoes the request's MessageId"
        );
        assert!(sign::verify(&reply, &key), "the reply is signed");
        writer.drain();
        assert!(!writer.dead.load(Ordering::SeqCst));

        let (header, mut message) = signed_flush(10, &key);
        *message.last_mut().unwrap() ^= 1;
        pool.submit(work((header, message), key, &share, &writer));
        writer.drain();
        assert!(writer.dead.load(Ordering::SeqCst));

        pool.stop();
    }

    #[test]
    fn dead_connection_work_settles_without_writes() {
        let pool = SmbDispatchPool::start(1);
        let share = share_over(temp_core("dead"));
        let key = [7u8; 16];
        let (writer, mut client) = writer_pair();
        writer.kill();
        for mid in 0..8 {
            pool.submit(work(signed_flush(mid, &key), key, &share, &writer));
        }
        writer.drain();
        let mut byte = [0u8; 1];
        assert!(matches!(client.read(&mut byte), Ok(0) | Err(_)));
        pool.stop();
    }

    #[test]
    fn a_zero_worker_pool_is_inert() {
        let pool = SmbDispatchPool::start(0);
        assert!(!pool.active());
        pool.stop();
    }

    #[test]
    fn stored_hashes_round_trip_and_reject_garbage() {
        let hash: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        assert_eq!(hash_from_hex(&crate::pools::hex(&hash)), Some(hash));
        assert_eq!(hash_from_hex(""), None);
        assert_eq!(hash_from_hex("00112233445566778899aabbccddeef"), None);
        assert_eq!(hash_from_hex("00112233445566778899AABBCCDDEEFF"), None);
        assert_eq!(hash_from_hex("zz112233445566778899aabbccddeeff"), None);
    }

    #[test]
    fn restore_skips_broken_records_and_never_persists() {
        let dir = std::env::temp_dir().join(format!(
            "scalefs-share-restore-{}-{:?}",
            std::process::id(),
            std::thread::current().id(),
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let store = crate::state::SharesStore::open(&dir).unwrap();
        store
            .save(&[
                crate::state::RecordedShare {
                    pool: "gone".to_string(),
                    name: "a".to_string(),
                    port: 4451,
                    user: "u".to_string(),
                    nt_hash: "00112233445566778899aabbccddeeff".to_string(),
                    read_only: false,
                },
                crate::state::RecordedShare {
                    pool: "tank".to_string(),
                    name: "b".to_string(),
                    port: 4452,
                    user: "u".to_string(),
                    nt_hash: "not hex at all".to_string(),
                    read_only: false,
                },
            ])
            .unwrap();
        let shares = Shares::with_state(Some(Arc::new(
            crate::state::SharesStore::open(&dir).unwrap(),
        )));
        shares.restore(&store, |name| {
            Err((
                ErrorCode::NotFound,
                format!("no pool is attached as '{name}'"),
            ))
        });
        assert!(shares.shares.lock().unwrap().is_empty());
        assert_eq!(store.load().len(), 2, "restore never rewrites the record");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
