use std::cell::Cell;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use scalefs_mount::dataplane::{self, CloseDurability, SessionParams};

use scalefs_ipc::json::{Value, object};
use scalefs_ipc::proto::ErrorCode;

use crate::pools::{OpError, PoolCore, PoolHandle, PoolPresentation};

const STOP_POLL: std::time::Duration = std::time::Duration::from_millis(500);

const HELLO_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

const MAX_PENDING_HANDSHAKES: usize = 64;

#[derive(Clone, Default)]
struct Handshakes(Arc<AtomicUsize>);

struct Admission(Arc<AtomicUsize>);

impl Handshakes {
    fn admit(&self, cap: usize) -> Option<Admission> {
        let taken = self
            .0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                (count < cap).then_some(count + 1)
            });
        taken.ok().map(|_| Admission(Arc::clone(&self.0)))
    }
}

impl Drop for Admission {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct Handshake {
    deadline: Instant,
    done: Rc<Cell<bool>>,
}

#[cfg(windows)]
const ERROR_BUSY: i32 = 170;

#[cfg(windows)]
const BLIND_GENERATION: u64 = scalefs_mount::dataplane::eject::BLIND_GENERATION;

pub type EjectReconciler = Arc<dyn Fn(&str, u64) -> EjectClaim + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EjectClaim {
    Won,
    NotYetPublished,
    Superseded,
}

#[derive(Clone)]
#[cfg_attr(not(windows), allow(dead_code))]
pub enum EjectGateOp {
    Prepare {
        preparer: crate::pools::GuardWitness,
    },
    Abort(u64),
    Commit {
        generation: u64,
        committer: crate::pools::GuardWitness,
    },
}

pub type EjectGate =
    Arc<dyn Fn(&str, EjectGateOp) -> scalefs_mount::dataplane::PrepareOutcome + Send + Sync>;

#[cfg(windows)]
struct PoolEjectBarrier {
    gate: EjectGate,
    pool: String,
    pool_id: [u8; 16],
    own_guard: crate::pools::GuardWitness,
}

#[cfg(windows)]
impl scalefs_mount::dataplane::EjectBarrier for PoolEjectBarrier {
    fn prepare(&self, pool_id: &[u8; 16]) -> scalefs_mount::dataplane::PrepareOutcome {
        if pool_id != &self.pool_id {
            return scalefs_mount::dataplane::PrepareOutcome::nak(
                scalefs_mount::dataplane::PrepareVerdict::Unsupported,
            );
        }
        (self.gate)(
            &self.pool,
            EjectGateOp::Prepare {
                preparer: self.own_guard.clone(),
            },
        )
    }

    fn abort(&self, pool_id: &[u8; 16], generation: u64) {
        if pool_id != &self.pool_id {
            return;
        }
        let _ = (self.gate)(&self.pool, EjectGateOp::Abort(generation));
    }

    fn commit(
        &self,
        pool_id: &[u8; 16],
        generation: u64,
    ) -> scalefs_mount::dataplane::PrepareVerdict {
        if pool_id != &self.pool_id {
            return scalefs_mount::dataplane::PrepareVerdict::Unsupported;
        }
        (self.gate)(
            &self.pool,
            EjectGateOp::Commit {
                generation,
                committer: self.own_guard.clone(),
            },
        )
        .verdict
    }
}

#[cfg(windows)]
struct StartGate {
    open: Mutex<bool>,
    wake: std::sync::Condvar,
}

#[cfg(windows)]
impl StartGate {
    fn new() -> StartGate {
        StartGate {
            open: Mutex::new(false),
            wake: std::sync::Condvar::new(),
        }
    }

    fn open(&self) {
        *self.open.lock().expect("start gate") = true;
        self.wake.notify_all();
    }

    fn wait(&self, stop: &AtomicBool) {
        let mut open = self.open.lock().expect("start gate");
        while !*open && !stop.load(Ordering::SeqCst) {
            let (guard, _timeout) = self
                .wake
                .wait_timeout(open, std::time::Duration::from_millis(100))
                .expect("start gate");
            open = guard;
        }
    }
}

struct ActiveServe {
    pool: String,
    pool_id: String,
    endpoint: String,
    read_only: bool,
    close_durability: CloseDurability,
    generation: u64,
    stop: Arc<AtomicBool>,
    #[cfg(windows)]
    watcher_disarm: Arc<AtomicBool>,
    #[cfg(windows)]
    watcher_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    accept_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    connections: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
    socket_path: Option<String>,
    kernel_device: Option<String>,
    mount_letter: Option<String>,
    volume_guid: Option<String>,
    presentation: Option<PoolPresentation>,
    #[cfg(windows)]
    reconciler: EjectReconciler,
    #[cfg(windows)]
    eject_gate: EjectGate,
    _guard: crate::pools::ShareGuard,
}

enum Claimed {
    Won(Arc<ActiveServe>),
    NotYetPublished,
    Superseded,
}

#[derive(Default)]
pub struct ServingRegistry {
    served: Mutex<BTreeMap<String, Arc<ActiveServe>>>,
    next_generation: std::sync::atomic::AtomicU64,
}

#[cfg_attr(not(windows), allow(dead_code))]
enum MountMode {
    Letter(char),
    Auto,
}

#[cfg_attr(not(windows), allow(dead_code))]
fn present_external(rollup: PoolPresentation, knob: Option<&std::ffi::OsStr>) -> bool {
    match knob {
        Some(value) if value == std::ffi::OsStr::new("1") => true,
        Some(value) if value == std::ffi::OsStr::new("0") => false,
        _ => rollup == PoolPresentation::External,
    }
}

#[cfg(windows)]
fn detach_with_drain(device: &str, attempts: u32) -> std::io::Result<()> {
    let mut last: Option<std::io::Error> = None;
    for attempt in 0..attempts {
        match crate::kernel_pump::volume_detach(device, true) {
            Ok(()) => return Ok(()),
            Err(error) if error.raw_os_error() == Some(ERROR_BUSY) => {
                eprintln!(
                    "scalefsd: force-detach unexpectedly refused BUSY (force must not \
                     refuse — the kernel's active-op drain has not quiesced); retrying"
                );
                last = Some(error);
                if attempt + 1 < attempts {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            }
            Err(error) => return Err(error),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("volume busy")))
}

#[cfg(windows)]
fn guid_string(guid: &[u8; 16]) -> String {
    format!(
        "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
        u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]),
        u16::from_le_bytes([guid[4], guid[5]]),
        u16::from_le_bytes([guid[6], guid[7]]),
        guid[8],
        guid[9],
        guid[10],
        guid[11],
        guid[12],
        guid[13],
        guid[14],
        guid[15],
    )
}

impl ServingRegistry {
    pub fn serve(
        &self,
        params: &Value,
        resolve_pool: impl Fn(&str) -> Result<PoolHandle, OpError>,
        on_external_eject: EjectReconciler,
        eject_gate: EjectGate,
    ) -> Result<Value, OpError> {
        #[cfg(not(windows))]
        let _ = (&on_external_eject, &eject_gate);
        let pool_name = required_str(params, "pool")?;
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
        {
            let served = self.served.lock().expect("serving lock");
            if served.contains_key(&pool_name) {
                return Err((
                    ErrorCode::Conflict,
                    format!("pool '{pool_name}' is already served; stop it first"),
                ));
            }
        }

        let PoolHandle {
            pool: pool_arc,
            core: canonical,
            presentation,
            guard,
        } = resolve_pool(&pool_name)?;
        #[cfg(not(windows))]
        let _ = presentation;
        let (core, read_only) = match (canonical, requested_read_only) {
            (Some(core), read_only) => (core, read_only),
            (None, true) => (
                Arc::new(scalefs_mount::mountcore::MountCore::read_only(Arc::clone(
                    &pool_arc,
                ))),
                true,
            ),
            (None, false) => {
                return Err((
                    ErrorCode::Conflict,
                    format!(
                        "pool '{pool_name}' is read-only (degraded or feature-limited); \
                         serve it with read_only"
                    ),
                ));
            }
        };
        let pool_id = {
            let engine = pool_arc.read().expect("pool lock");
            engine.superblock().pool_id.0
        };
        let unix_socket = match params.get("unix_socket") {
            None => None,
            Some(Value::Str(path)) if !path.is_empty() => Some(path.clone()),
            Some(_) => {
                return Err((
                    ErrorCode::BadRequest,
                    "unix_socket must be a nonempty path".to_string(),
                ));
            }
        };
        #[cfg(not(unix))]
        if unix_socket.is_some() {
            return Err((
                ErrorCode::Unsupported,
                "unix_socket endpoints exist on Unix builds only".to_string(),
            ));
        }
        let kernel_device = match params.get("kernel_device") {
            None => None,
            Some(Value::Str(path)) if !path.is_empty() => Some(path.clone()),
            Some(_) => {
                return Err((
                    ErrorCode::BadRequest,
                    "kernel_device must be a nonempty device path".to_string(),
                ));
            }
        };
        if kernel_device.is_some() && unix_socket.is_some() {
            return Err((
                ErrorCode::BadRequest,
                "choose one endpoint kind: unix_socket or kernel_device".to_string(),
            ));
        }
        #[cfg(not(windows))]
        if kernel_device.is_some() {
            return Err((
                ErrorCode::Unsupported,
                "kernel_device endpoints exist on Windows builds only".to_string(),
            ));
        }
        let mount = match params.get("mount") {
            None => None,
            Some(Value::Str(word)) if word.eq_ignore_ascii_case("auto") => Some(MountMode::Auto),
            Some(Value::Str(letter)) => {
                let bytes = letter.as_bytes();
                if bytes.len() != 2 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' {
                    return Err((
                        ErrorCode::BadRequest,
                        "mount must be \"auto\" or a drive letter like \"Z:\"".to_string(),
                    ));
                }
                Some(MountMode::Letter(bytes[0].to_ascii_uppercase() as char))
            }
            Some(_) => {
                return Err((
                    ErrorCode::BadRequest,
                    "mount must be \"auto\" or a drive letter like \"Z:\"".to_string(),
                ));
            }
        };
        if mount.is_some() && kernel_device.is_none() {
            return Err((
                ErrorCode::BadRequest,
                "mount requires a kernel_device endpoint".to_string(),
            ));
        }

        let close_durability = close_durability_param(params)?;

        let token = hex(&crate::shares::random_bytes::<32>());
        let generation = self
            .next_generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        let stop = Arc::new(AtomicBool::new(false));
        #[cfg(windows)]
        let watcher_disarm = Arc::new(AtomicBool::new(false));
        let connections: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>> =
            Arc::new(Mutex::new(Vec::new()));
        let session = SessionParams {
            pool_id,
            token: token.as_bytes().to_vec(),
            read_only,
            close_durability,
        };

        #[cfg(unix)]
        let (endpoint, accept_thread, socket_path) = if let Some(path) = unix_socket {
            let _ = std::fs::remove_file(&path);
            let listener =
                std::os::unix::net::UnixListener::bind(&path).map_err(|error| -> OpError {
                    (ErrorCode::Io, format!("cannot bind {path}: {error}"))
                })?;
            listener.set_nonblocking(true).map_err(|error| -> OpError {
                (ErrorCode::Io, format!("cannot arm the listener: {error}"))
            })?;
            let thread = {
                let stop = Arc::clone(&stop);
                let connections = Arc::clone(&connections);
                let core = Arc::clone(&core);
                let session = session.clone();
                std::thread::spawn(move || {
                    accept_loop_unix(listener, stop, connections, core, session);
                })
            };
            (format!("unix:{path}"), thread, Some(path))
        } else {
            let (endpoint, thread) = bind_tcp(&stop, &connections, &core, &session)?;
            (endpoint, thread, None)
        };
        #[cfg(windows)]
        let (endpoint, accept_thread) = if let Some(device) = &kernel_device {
            let first =
                crate::kernel_pump::KernelPumpStream::open(device).map_err(|error| -> OpError {
                    (
                        ErrorCode::Io,
                        format!("cannot open the pump device {device}: {error}"),
                    )
                })?;
            let endpoint = format!("kernel:{device}");
            let barrier: Arc<dyn scalefs_mount::dataplane::EjectBarrier> =
                Arc::new(PoolEjectBarrier {
                    gate: Arc::clone(&eject_gate),
                    pool: pool_name.clone(),
                    pool_id,
                    own_guard: guard.witness(),
                });
            let thread = {
                let device = device.clone();
                let stop = Arc::clone(&stop);
                let core = Arc::clone(&core);
                let session = session.clone();
                std::thread::spawn(move || {
                    pump_loop(device, first, stop, core, session, barrier);
                })
            };
            (endpoint, thread)
        } else {
            bind_tcp(&stop, &connections, &core, &session)?
        };
        #[cfg(all(not(unix), not(windows)))]
        let (endpoint, accept_thread) = bind_tcp(&stop, &connections, &core, &session)?;
        #[cfg(not(unix))]
        let socket_path: Option<String> = None;

        #[cfg(windows)]
        let (mount_letter, volume_guid, presented) = if let Some(mode) = &mount {
            let device = kernel_device
                .as_deref()
                .expect("mount was validated to require kernel_device");
            let external = present_external(
                presentation,
                std::env::var_os("SCALEFS_EXTERNAL_PRESENTATION").as_deref(),
            );
            let request = crate::kernel_pump::MountRequest {
                letter: match mode {
                    MountMode::Letter(letter) => Some(*letter),
                    MountMode::Auto => None,
                },
                external,
            };
            enum AttachOutcome {
                Io(std::io::Error),
                Conflict(String),
            }
            let attach = (|| {
                let mut last = crate::kernel_pump::volume_attach(
                    device,
                    &pool_id,
                    token.as_bytes(),
                    Some(&request),
                );
                for _ in 0..10 {
                    match &last {
                        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                            let holder = self
                                .served
                                .lock()
                                .expect("serving lock")
                                .values()
                                .find(|other| {
                                    other.kernel_device.as_deref() == Some(device)
                                        && other.mount_letter.is_some()
                                })
                                .map(|other| other.pool.clone());
                            if let Some(holder) = holder {
                                return Err(AttachOutcome::Conflict(format!(
                                    "device {device} is already mounted by pool \
                                     '{holder}'; stop it first"
                                )));
                            }
                            eprintln!(
                                "scalefsd: a prior kernel volume is in the way (stale or \
                                 draining); clearing and retrying"
                            );
                            match detach_with_drain(device, 10) {
                                Ok(()) => {}
                                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                                Err(error) => return Err(AttachOutcome::Io(error)),
                            }
                            std::thread::sleep(std::time::Duration::from_millis(500));
                            last = crate::kernel_pump::volume_attach(
                                device,
                                &pool_id,
                                token.as_bytes(),
                                Some(&request),
                            );
                        }
                        _ => break,
                    }
                }
                last.map_err(AttachOutcome::Io)
            })();
            match attach {
                Ok(reply) => (
                    reply.letter.map(|letter| format!("{letter}:")),
                    Some(guid_string(&reply.volume_guid)),
                    Some(PoolPresentation::from_external(external)),
                ),
                Err(outcome) => {
                    stop.store(true, Ordering::SeqCst);
                    let _ = accept_thread.join();
                    return Err(match outcome {
                        AttachOutcome::Conflict(why) => (ErrorCode::Conflict, why),
                        AttachOutcome::Io(error) => {
                            let asked = match mode {
                                MountMode::Letter(letter) => format!("{letter}:"),
                                MountMode::Auto => "auto".to_string(),
                            };
                            (
                                ErrorCode::Io,
                                format!("cannot mount {asked} from {device}: {error}"),
                            )
                        }
                    });
                }
            }
        } else {
            (None, None, None)
        };
        #[cfg(not(windows))]
        let (mount_letter, volume_guid, presented): (
            Option<String>,
            Option<String>,
            Option<PoolPresentation>,
        ) = (None, None, None);

        #[cfg(windows)]
        let start_gate = Arc::new(StartGate::new());
        #[cfg(windows)]
        let watcher_thread: Option<std::thread::JoinHandle<()>> =
            match (&kernel_device, &mount_letter) {
                (Some(device), Some(_letter)) => {
                    let device = device.clone();
                    let pool = pool_name.clone();
                    let stop = Arc::clone(&stop);
                    let disarm = Arc::clone(&watcher_disarm);
                    let on_eject = Arc::clone(&on_external_eject);
                    let gate = Arc::clone(&start_gate);
                    Some(std::thread::spawn(move || {
                        gate.wait(&stop);
                        eject_watch(device, pool, generation, stop, disarm, on_eject);
                    }))
                }
                _ => None,
            };

        let serve = Arc::new(ActiveServe {
            pool: pool_name.clone(),
            pool_id: hex(&pool_id),
            endpoint: endpoint.clone(),
            read_only,
            close_durability,
            generation,
            stop,
            #[cfg(windows)]
            watcher_disarm,
            #[cfg(windows)]
            watcher_thread: Mutex::new(watcher_thread),
            accept_thread: Mutex::new(Some(accept_thread)),
            connections,
            socket_path,
            kernel_device,
            mount_letter: mount_letter.clone(),
            volume_guid: volume_guid.clone(),
            presentation: presented,
            #[cfg(windows)]
            reconciler: Arc::clone(&on_external_eject),
            #[cfg(windows)]
            eject_gate: Arc::clone(&eject_gate),
            _guard: guard,
        });
        self.served
            .lock()
            .expect("serving lock")
            .insert(pool_name, serve);
        #[cfg(windows)]
        start_gate.open();
        #[cfg(windows)]
        if let Some(letter) = &mount_letter {
            crate::session_notify::announce(letter, crate::session_notify::Change::Arrival);
        }

        let mut reply = vec![
            ("endpoint", Value::Str(endpoint)),
            ("token", Value::Str(token)),
            ("read_only", Value::Bool(read_only)),
        ];
        reply.extend(close_durability_fields(close_durability));
        if let Some(letter) = mount_letter {
            reply.push(("mount", Value::Str(letter)));
        }
        if let Some(guid) = volume_guid {
            reply.push(("volume_guid", Value::Str(guid)));
        }
        if let Some(presented) = presented {
            reply.push(("presentation", Value::Str(presented.word().to_string())));
        }
        Ok(object(reply))
    }

    pub fn stop(&self, params: &Value) -> Result<Value, OpError> {
        let pool = required_str(params, "pool")?;
        let force = match params.get("force") {
            None => false,
            Some(Value::Bool(flag)) => *flag,
            Some(_) => {
                return Err((ErrorCode::BadRequest, "force must be a boolean".to_string()));
            }
        };
        let serve = {
            let served = self.served.lock().expect("serving lock");
            match served.get(&pool) {
                Some(serve) => Arc::clone(serve),
                None => {
                    return Err((
                        ErrorCode::NotFound,
                        format!("pool '{pool}' is not being served"),
                    ));
                }
            }
        };
        if force && serve.kernel_device.is_none() {
            return Err((
                ErrorCode::BadRequest,
                format!("force applies only to a Windows kernel serving; '{pool}' is not one"),
            ));
        }
        #[cfg(windows)]
        serve.watcher_disarm.store(true, Ordering::SeqCst);
        #[allow(clippy::question_mark)]
        if let Err(error) = unmount_volume(&serve, force) {
            #[cfg(windows)]
            {
                if !force && volume_is_gone(&serve) {
                    let reconciler = Arc::clone(&serve.reconciler);
                    let generation = serve.generation;
                    let watcher = drop_watcher_handle(&serve);
                    drop(serve);
                    let _ = reconciler(&pool, generation);
                    if let Some(watcher) = watcher {
                        let _ = watcher.join();
                    }
                    return Ok(object(vec![
                        ("stopped", Value::Str(pool)),
                        (
                            "note",
                            Value::Str("reconciled an external eject".to_string()),
                        ),
                    ]));
                }
                serve.watcher_disarm.store(false, Ordering::SeqCst);
            }
            return Err(error);
        }
        let Some(serve) = self.remove_serving(&pool, serve.generation) else {
            return Err((
                ErrorCode::NotFound,
                format!("pool '{pool}' is not being served"),
            ));
        };
        stop_serve(&serve);
        #[cfg(windows)]
        join_watcher(&serve);
        #[cfg(windows)]
        let _ = (serve.eject_gate)(&pool, EjectGateOp::Abort(BLIND_GENERATION));
        #[cfg(windows)]
        announce_removal(&serve);
        Ok(object(vec![("stopped", Value::Str(pool))]))
    }

    pub fn list(&self) -> Result<Value, OpError> {
        let served = self.served.lock().expect("serving lock");
        let rows = served
            .values()
            .map(|serve| {
                let mut row = vec![
                    ("pool", Value::Str(serve.pool.clone())),
                    ("pool_id", Value::Str(serve.pool_id.clone())),
                    ("endpoint", Value::Str(serve.endpoint.clone())),
                    ("read_only", Value::Bool(serve.read_only)),
                ];
                row.extend(close_durability_fields(serve.close_durability));
                if let Some(letter) = &serve.mount_letter {
                    row.push(("mount", Value::Str(letter.clone())));
                }
                if let Some(guid) = &serve.volume_guid {
                    row.push(("volume_guid", Value::Str(guid.clone())));
                }
                if let Some(presentation) = &serve.presentation {
                    row.push(("presentation", Value::Str(presentation.word().to_string())));
                }
                object(row)
            })
            .collect();
        Ok(object(vec![("serving", Value::Array(rows))]))
    }

    fn remove_serving(&self, pool: &str, generation: u64) -> Option<Arc<ActiveServe>> {
        match self.claim_serving(pool, generation) {
            Claimed::Won(serve) => Some(serve),
            _ => None,
        }
    }

    fn claim_serving(&self, pool: &str, generation: u64) -> Claimed {
        let mut served = self.served.lock().expect("serving lock");
        match served.get(pool) {
            Some(serve) if serve.generation == generation => {
                Claimed::Won(served.remove(pool).expect("checked present"))
            }
            Some(_) => Claimed::Superseded,
            None => Claimed::NotYetPublished,
        }
    }

    pub fn eject_claim(&self, pool: &str, generation: u64) -> EjectClaim {
        let serve = match self.claim_serving(pool, generation) {
            Claimed::Won(serve) => serve,
            Claimed::Superseded => return EjectClaim::Superseded,
            Claimed::NotYetPublished => return EjectClaim::NotYetPublished,
        };
        eprintln!(
            "scalefsd: external eject detected on '{pool}' — the kernel volume was \
             dismounted out from under the serving; reconciling"
        );
        stop_serve(&serve);
        #[cfg(windows)]
        announce_removal(&serve);
        drop(serve);
        EjectClaim::Won
    }

    pub fn stop_all(&self) {
        let drained: Vec<Arc<ActiveServe>> = {
            let mut served = self.served.lock().expect("serving lock");
            std::mem::take(&mut *served).into_values().collect()
        };
        for serve in drained {
            #[cfg(windows)]
            serve.watcher_disarm.store(true, Ordering::SeqCst);
            let _ = unmount_volume(&serve, true);
            stop_serve(&serve);
            #[cfg(windows)]
            join_watcher(&serve);
            #[cfg(windows)]
            let _ = (serve.eject_gate)(&serve.pool, EjectGateOp::Abort(BLIND_GENERATION));
            #[cfg(windows)]
            if let Some(letter) = &serve.mount_letter {
                crate::session_notify::announce_and_wait(
                    letter,
                    crate::session_notify::Change::Removal,
                );
            }
        }
    }
}

#[cfg(windows)]
fn announce_removal(serve: &ActiveServe) {
    if let Some(letter) = &serve.mount_letter {
        crate::session_notify::announce(letter, crate::session_notify::Change::Removal);
    }
}

#[cfg_attr(not(windows), allow(unused_variables))]
fn unmount_volume(serve: &ActiveServe, force: bool) -> Result<(), OpError> {
    let (Some(letter), Some(device)) = (&serve.mount_letter, &serve.kernel_device) else {
        return Ok(());
    };
    #[cfg(not(windows))]
    {
        Ok(())
    }
    #[cfg(windows)]
    {
        let result = if force {
            detach_with_drain(device, 10)
        } else {
            crate::kernel_pump::volume_detach(device, false)
        };
        match result {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) if force => {
                if error.raw_os_error() == Some(ERROR_BUSY) {
                    eprintln!(
                        "scalefsd: force-detach of {letter} did not quiesce (active-op \
                         drain timed out: {error}); the volume stays mounted — serving \
                         stopped, the dismount can be retried"
                    );
                } else {
                    eprintln!(
                        "scalefsd: force-detach of {letter} did not complete ({error}); \
                         serving stopped, volume contained until driver unload"
                    );
                }
                Ok(())
            }
            Err(error) => Err((
                ErrorCode::Conflict,
                format!("volume {letter} is in use ({error}); close open files first"),
            )),
        }
    }
}

fn stop_serve(serve: &ActiveServe) {
    serve.stop.store(true, Ordering::SeqCst);
    if let Some(handle) = serve.accept_thread.lock().expect("accept lock").take() {
        let _ = handle.join();
    }
    let drained: Vec<std::thread::JoinHandle<()>> = {
        let mut connections = serve.connections.lock().expect("connections lock");
        connections.drain(..).collect()
    };
    for connection in drained {
        let _ = connection.join();
    }
    if let Some(path) = &serve.socket_path {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(windows)]
fn join_watcher(serve: &ActiveServe) {
    if let Some(handle) = serve.watcher_thread.lock().expect("watcher lock").take() {
        let _ = handle.join();
    }
}

#[cfg(windows)]
fn drop_watcher_handle(serve: &ActiveServe) -> Option<std::thread::JoinHandle<()>> {
    serve.watcher_thread.lock().expect("watcher lock").take()
}

#[cfg(windows)]
fn volume_is_gone(serve: &ActiveServe) -> bool {
    let Some(device) = &serve.kernel_device else {
        return false;
    };
    match crate::kernel_pump::volume_query(device) {
        Ok((0, _)) => true,
        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
        Ok(_) => false,
    }
}

#[cfg(windows)]
fn eject_watch(
    device: String,
    pool: String,
    generation: u64,
    stop: Arc<AtomicBool>,
    disarm: Arc<AtomicBool>,
    on_external_eject: EjectReconciler,
) {
    loop {
        if watcher_terminated(&stop) {
            return;
        }
        let query = crate::kernel_pump::volume_query(&device);
        match watch_step(
            &query,
            watcher_terminated(&stop),
            disarm.load(Ordering::SeqCst),
        ) {
            WatchStep::Fire => match on_external_eject(&pool, generation) {
                EjectClaim::Won => return,
                EjectClaim::Superseded => return,
                EjectClaim::NotYetPublished => {}
            },
            WatchStep::Exit => return,
            WatchStep::Continue => {}
        }
        for _ in 0..10 {
            if watcher_terminated(&stop) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
}

#[cfg(windows)]
#[derive(Debug, PartialEq, Eq)]
enum WatchStep {
    Fire,
    Exit,
    Continue,
}

#[cfg(windows)]
fn watch_step(query: &std::io::Result<(u32, bool)>, stop: bool, disarm: bool) -> WatchStep {
    let ejected = match query {
        Ok((0, _)) => true,
        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
        Ok(_) => false,
    };
    if !ejected {
        WatchStep::Continue
    } else if stop {
        WatchStep::Exit
    } else if disarm {
        WatchStep::Continue
    } else {
        WatchStep::Fire
    }
}

#[cfg(windows)]
fn watcher_terminated(stop: &AtomicBool) -> bool {
    stop.load(Ordering::SeqCst)
}

fn bind_tcp(
    stop: &Arc<AtomicBool>,
    connections: &Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
    core: &PoolCore,
    session: &SessionParams,
) -> Result<(String, std::thread::JoinHandle<()>), OpError> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|error| -> OpError {
        (
            ErrorCode::Io,
            format!("cannot bind a loopback endpoint: {error}"),
        )
    })?;
    let endpoint = listener
        .local_addr()
        .map_err(|error| -> OpError { (ErrorCode::Io, format!("endpoint address: {error}")) })?
        .to_string();
    listener.set_nonblocking(true).map_err(|error| -> OpError {
        (ErrorCode::Io, format!("cannot arm the listener: {error}"))
    })?;
    let thread = {
        let stop = Arc::clone(stop);
        let connections = Arc::clone(connections);
        let core = Arc::clone(core);
        let session = session.clone();
        std::thread::spawn(move || {
            accept_loop(listener, stop, connections, core, session);
        })
    };
    Ok((endpoint, thread))
}

fn accept_loop(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    connections: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
    core: PoolCore,
    session: SessionParams,
) {
    let handshakes = Handshakes::default();
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                let Some(admission) = handshakes.admit(MAX_PENDING_HANDSHAKES) else {
                    continue;
                };
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(STOP_POLL));
                let _ = stream.set_write_timeout(Some(STOP_POLL));
                spawn_session(stream, &stop, &connections, &core, &session, admission);
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(_) => break,
        }
    }
}

#[cfg(unix)]
fn accept_loop_unix(
    listener: std::os::unix::net::UnixListener,
    stop: Arc<AtomicBool>,
    connections: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
    core: PoolCore,
    session: SessionParams,
) {
    let handshakes = Handshakes::default();
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                let Some(admission) = handshakes.admit(MAX_PENDING_HANDSHAKES) else {
                    continue;
                };
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(STOP_POLL));
                let _ = stream.set_write_timeout(Some(STOP_POLL));
                spawn_session(stream, &stop, &connections, &core, &session, admission);
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(_) => break,
        }
    }
}

#[cfg(windows)]
fn pump_loop(
    device: String,
    first: crate::kernel_pump::KernelPumpStream,
    stop: Arc<AtomicBool>,
    core: PoolCore,
    session: SessionParams,
    barrier: Arc<dyn scalefs_mount::dataplane::EjectBarrier>,
) {
    let mut live = Some(first);
    while !stop.load(Ordering::SeqCst) {
        let stream = match live.take() {
            Some(stream) => stream,
            None => match crate::kernel_pump::KernelPumpStream::open(&device) {
                Ok(stream) => stream,
                Err(_) => {
                    std::thread::sleep(STOP_POLL);
                    continue;
                }
            },
        };
        let mut transport = StopPollStream::new(stream, Arc::clone(&stop));
        let end =
            dataplane::serve_connection(&mut transport, &core, &session, Some(&*barrier), None);
        let _ = core.commit_if_dirty();
        match end {
            dataplane::SessionEnd::Bye => live = Some(transport.stream),
            dataplane::SessionEnd::Disconnected | dataplane::SessionEnd::Error => {
                if !stop.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }
    }
}

fn spawn_session<S: Read + Write + Send + 'static>(
    stream: S,
    stop: &Arc<AtomicBool>,
    connections: &Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
    core: &PoolCore,
    session: &SessionParams,
    admission: Admission,
) {
    let core = Arc::clone(core);
    let session = session.clone();
    let stop = Arc::clone(stop);
    let handle = std::thread::spawn(move || {
        let mut transport = StopPollStream::new(stream, stop);
        let done = Rc::new(Cell::new(false));
        transport.handshake = Some(Handshake {
            deadline: Instant::now() + HELLO_DEADLINE,
            done: Rc::clone(&done),
        });
        let admission = std::cell::RefCell::new(Some(admission));
        let authenticated = || {
            done.set(true);
            admission.borrow_mut().take();
        };
        let _ = dataplane::serve_connection(
            &mut transport,
            &core,
            &session,
            None,
            Some(&authenticated),
        );
        let _ = core.commit_if_dirty();
        drop(admission);
    });
    connections.lock().expect("connections lock").push(handle);
}

struct StopPollStream<S> {
    stream: S,
    stop: Arc<AtomicBool>,
    handshake: Option<Handshake>,
}

impl<S> StopPollStream<S> {
    fn new(stream: S, stop: Arc<AtomicBool>) -> StopPollStream<S> {
        StopPollStream {
            stream,
            stop,
            handshake: None,
        }
    }
}

impl<S: Read> Read for StopPollStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.stop.load(Ordering::SeqCst) {
                return Ok(0);
            }
            if let Some(handshake) = &self.handshake
                && !handshake.done.get()
                && Instant::now() >= handshake.deadline
            {
                return Ok(0);
            }
            match self.stream.read(buf) {
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || error.kind() == std::io::ErrorKind::TimedOut =>
                {
                    continue;
                }
                other => return other,
            }
        }
    }
}

impl<S: Write> Write for StopPollStream<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        loop {
            let stopping = self.stop.load(Ordering::SeqCst);
            match self.stream.write(buf) {
                Err(error)
                    if !stopping
                        && (error.kind() == std::io::ErrorKind::WouldBlock
                            || error.kind() == std::io::ErrorKind::TimedOut) =>
                {
                    continue;
                }
                other => return other,
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

fn required_str(params: &Value, key: &str) -> Result<String, OpError> {
    match params.get(key) {
        Some(Value::Str(text)) if !text.is_empty() => Ok(text.clone()),
        _ => Err((
            ErrorCode::BadRequest,
            format!("'{key}' (a nonempty string) is required"),
        )),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn close_durability_param(params: &Value) -> Result<CloseDurability, OpError> {
    let commit_on_close = match params.get("close_durability") {
        None => false,
        Some(Value::Str(word)) if word == "bounded" => false,
        Some(Value::Str(word)) if word == "commit-on-close" => true,
        Some(_) => {
            return Err((
                ErrorCode::BadRequest,
                "close_durability must be \"bounded\" or \"commit-on-close\"".to_string(),
            ));
        }
    };
    let (min, max) = (
        CloseDurability::MIN_BOUND.as_millis() as u64,
        CloseDurability::MAX_BOUND.as_millis() as u64,
    );
    match (commit_on_close, params.get("close_bound_ms")) {
        (true, None) => Ok(CloseDurability::CommitOnClose),
        (true, Some(_)) => Err((
            ErrorCode::BadRequest,
            "close_bound_ms applies only to a bounded serving".to_string(),
        )),
        (false, None) => Ok(CloseDurability::Bounded(CloseDurability::DEFAULT_BOUND)),
        (false, Some(value)) => value
            .as_u64()
            .filter(|ms| (min..=max).contains(ms))
            .map(|ms| CloseDurability::Bounded(std::time::Duration::from_millis(ms)))
            .ok_or((
                ErrorCode::BadRequest,
                format!("close_bound_ms must be {min}-{max}"),
            )),
    }
}

#[cfg(any(windows, test))]
pub(crate) fn requested_close_durability(params: &Value) -> Option<CloseDurability> {
    if params.get("close_durability").is_none() && params.get("close_bound_ms").is_none() {
        return None;
    }
    close_durability_param(params).ok()
}

pub(crate) fn close_durability_fields(policy: CloseDurability) -> Vec<(&'static str, Value)> {
    match policy {
        CloseDurability::CommitOnClose => {
            vec![(
                "close_durability",
                Value::Str("commit-on-close".to_string()),
            )]
        }
        CloseDurability::Bounded(bound) => vec![
            ("close_durability", Value::Str("bounded".to_string())),
            ("close_bound_ms", Value::Int(bound.as_millis() as i128)),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn presentation_knob_overrides_the_rollup_both_ways() {
        assert!(present_external(PoolPresentation::External, None));
        assert!(!present_external(PoolPresentation::Fixed, None));
        assert!(present_external(
            PoolPresentation::External,
            Some(OsStr::new("yes")),
        ));
        assert!(!present_external(
            PoolPresentation::Fixed,
            Some(OsStr::new("yes"))
        ));
        assert!(present_external(
            PoolPresentation::Fixed,
            Some(OsStr::new("1"))
        ));
        assert!(!present_external(
            PoolPresentation::External,
            Some(OsStr::new("0")),
        ));
    }

    #[test]
    fn the_close_policy_parses_and_refuses_what_it_does_not_know() {
        use std::time::Duration;
        let with = |entries: Vec<(&str, Value)>| close_durability_param(&object(entries));
        assert_eq!(
            with(vec![]).unwrap(),
            CloseDurability::Bounded(Duration::from_secs(1))
        );
        assert_eq!(with(vec![]).unwrap(), CloseDurability::default());
        assert_eq!(
            with(vec![(
                "close_durability",
                Value::Str("commit-on-close".into())
            )])
            .unwrap(),
            CloseDurability::CommitOnClose
        );
        assert_eq!(
            with(vec![("close_durability", Value::Str("bounded".into()))]).unwrap(),
            CloseDurability::Bounded(Duration::from_secs(1))
        );
        for ms in [1000, 2500, 5000] {
            assert_eq!(
                with(vec![
                    ("close_durability", Value::Str("bounded".into())),
                    ("close_bound_ms", Value::Int(ms)),
                ])
                .unwrap(),
                CloseDurability::Bounded(Duration::from_millis(ms as u64))
            );
            assert_eq!(
                with(vec![("close_bound_ms", Value::Int(ms))]).unwrap(),
                CloseDurability::Bounded(Duration::from_millis(ms as u64)),
                "a window alone is a bounded serving"
            );
        }
        let refused = [
            vec![("close_durability", Value::Str("sometimes".into()))],
            vec![("close_durability", Value::Bool(true))],
            vec![
                ("close_durability", Value::Str("bounded".into())),
                ("close_bound_ms", Value::Int(999)),
            ],
            vec![
                ("close_durability", Value::Str("bounded".into())),
                ("close_bound_ms", Value::Int(5001)),
            ],
            vec![
                ("close_durability", Value::Str("bounded".into())),
                ("close_bound_ms", Value::Str("2000".into())),
            ],
            vec![("close_bound_ms", Value::Int(60_000))],
            vec![
                ("close_durability", Value::Str("commit-on-close".into())),
                ("close_bound_ms", Value::Int(2000)),
            ],
        ];
        for entries in refused {
            match with(entries) {
                Err((ErrorCode::BadRequest, _)) => {}
                other => panic!("expected a BadRequest, got {other:?}"),
            }
        }
        assert_eq!(
            object(close_durability_fields(CloseDurability::Bounded(
                Duration::from_millis(2500)
            ))),
            object(vec![
                ("close_durability", Value::Str("bounded".into())),
                ("close_bound_ms", Value::Int(2500)),
            ])
        );
        let named = |entries: Vec<(&str, Value)>| requested_close_durability(&object(entries));
        assert_eq!(named(vec![("pool", Value::Str("tank".into()))]), None);
        assert_eq!(
            named(vec![(
                "close_durability",
                Value::Str("commit-on-close".into())
            )]),
            Some(CloseDurability::CommitOnClose)
        );
        assert_eq!(
            named(vec![("close_bound_ms", Value::Int(5000))]),
            Some(CloseDurability::Bounded(Duration::from_secs(5)))
        );
    }

    #[test]
    fn serve_stop_force_is_validated_as_a_boolean() {
        let registry = ServingRegistry::default();
        let (code, _why) = registry
            .stop(&object(vec![
                ("pool", Value::Str("p".into())),
                ("force", Value::Int(5)),
            ]))
            .expect_err("non-boolean force must be refused");
        assert_eq!(code, ErrorCode::BadRequest);
        for flag in [true, false] {
            let (code, _why) = registry
                .stop(&object(vec![
                    ("pool", Value::Str("p".into())),
                    ("force", Value::Bool(flag)),
                ]))
                .expect_err("no such serving");
            assert_eq!(code, ErrorCode::NotFound, "force={flag}");
        }
        let (code, _why) = registry
            .stop(&object(vec![("pool", Value::Str("p".into()))]))
            .expect_err("no such serving");
        assert_eq!(code, ErrorCode::NotFound);
    }

    #[test]
    fn a_claim_before_publication_retries_rather_than_ending_the_watcher() {
        let registry = ServingRegistry::default();
        assert_eq!(
            registry.eject_claim("unpublished", 1),
            EjectClaim::NotYetPublished,
        );
        assert_eq!(
            registry.eject_claim("unpublished", 2),
            EjectClaim::NotYetPublished,
        );
    }

    #[cfg(windows)]
    #[test]
    fn the_start_gate_holds_the_watcher_until_publication() {
        let gate = Arc::new(StartGate::new());
        let stop = Arc::new(AtomicBool::new(false));
        let waiter = {
            let gate = Arc::clone(&gate);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                gate.wait(&stop);
                *gate.open.lock().expect("start gate")
            })
        };
        gate.open();
        assert!(waiter.join().expect("the gate must release"));

        let gate = Arc::new(StartGate::new());
        let stop = Arc::new(AtomicBool::new(false));
        let waiter = {
            let gate = Arc::clone(&gate);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                gate.wait(&stop);
                *gate.open.lock().expect("start gate")
            })
        };
        stop.store(true, Ordering::SeqCst);
        assert!(
            !waiter.join().expect("a stop must release the gate"),
            "the gate never opened — the wait ended on the stop",
        );
    }

    #[test]
    fn a_stopping_stream_still_writes_the_reply_it_owes() {
        let stop = Arc::new(AtomicBool::new(true));
        let mut delivered =
            StopPollStream::new(std::io::Cursor::new(Vec::new()), Arc::clone(&stop));
        std::io::Write::write_all(&mut delivered, b"ack").expect("the owed reply goes out");
        assert_eq!(delivered.stream.get_ref().as_slice(), b"ack");
        assert_eq!(
            std::io::Read::read(&mut delivered, &mut [0u8; 4]).unwrap(),
            0
        );

        struct Refusing;
        impl Write for Refusing {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::TimedOut))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut refused = StopPollStream::new(Refusing, stop);
        assert_eq!(
            std::io::Write::write(&mut refused, b"ack")
                .expect_err("one attempt, then the stream's answer")
                .kind(),
            std::io::ErrorKind::TimedOut,
        );
    }

    #[cfg(windows)]
    #[test]
    fn watch_step_exits_only_on_stop_and_retries_on_a_bare_disarm() {
        use std::io::{Error, ErrorKind};
        let ejected = |stop, disarm| watch_step(&Ok((0, false)), stop, disarm);
        let gone = |stop, disarm| watch_step(&Err(Error::from(ErrorKind::NotFound)), stop, disarm);
        assert_eq!(ejected(false, false), WatchStep::Fire);
        assert_eq!(gone(false, false), WatchStep::Fire);
        assert_eq!(ejected(true, false), WatchStep::Exit);
        assert_eq!(gone(true, false), WatchStep::Exit);
        assert_eq!(ejected(true, true), WatchStep::Exit);
        assert_eq!(ejected(false, true), WatchStep::Continue);
        assert_eq!(gone(false, true), WatchStep::Continue);
        assert_eq!(
            watch_step(&Ok((1, false)), false, false),
            WatchStep::Continue
        );
        assert_eq!(
            watch_step(&Ok((1, false)), false, true),
            WatchStep::Continue
        );
        assert_eq!(watch_step(&Ok((1, true)), true, true), WatchStep::Continue);
        assert_eq!(
            watch_step(&Err(Error::from(ErrorKind::TimedOut)), false, false),
            WatchStep::Continue
        );
        assert_eq!(
            watch_step(&Err(Error::from(ErrorKind::PermissionDenied)), false, false),
            WatchStep::Continue
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_refused_polite_stop_leaves_the_watcher_live() {
        let stop = AtomicBool::new(false);
        let disarm = AtomicBool::new(false);
        assert!(!watcher_terminated(&stop));
        disarm.store(true, Ordering::SeqCst);
        assert!(
            !watcher_terminated(&stop),
            "a transient disarm must not terminate the watcher"
        );
        disarm.store(false, Ordering::SeqCst);
        assert!(
            !watcher_terminated(&stop),
            "a re-armed watcher after a refused polite stop must stay live"
        );
        stop.store(true, Ordering::SeqCst);
        assert!(watcher_terminated(&stop));
    }
}

#[cfg(test)]
#[path = "serving_fault_tests.rs"]
mod fault_tests;
