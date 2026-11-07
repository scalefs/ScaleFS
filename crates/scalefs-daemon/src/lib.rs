#[cfg(windows)]
mod kernel_pump;
mod pools;
pub mod service;
mod serving;
#[cfg(windows)]
mod session_notify;
mod shares;
#[cfg(windows)]
mod shell_companion;
mod state;

use scalefs_ipc::endpoint::{Endpoint, Listener, Stream};
use scalefs_ipc::frame::{FrameError, read_frame, write_frame};
use scalefs_ipc::json::{Value, object};
use scalefs_ipc::proto::{
    ErrorCode, Request, check_client_hello, daemon_hello, error_response, ok_response,
};
use std::io::BufReader;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

#[cfg(target_os = "linux")]
const CAPABILITIES: &[&str] = &["pools", "jobs", "devices", "mounts", "smb", "serve"];
#[cfg(not(target_os = "linux"))]
const CAPABILITIES: &[&str] = &["pools", "jobs", "devices", "smb", "serve"];

struct Daemon {
    endpoint: Endpoint,
    shutdown: AtomicBool,
    closing: AtomicBool,
    trust: TrustPolicy,
    pools: pools::Registry,
    shares: shares::Shares,
    serving: serving::ServingRegistry,
    weak_self: Weak<Daemon>,
}

fn reconcile_external_eject(
    weak: &Weak<Daemon>,
    pool: &str,
    generation: u64,
) -> serving::EjectClaim {
    let Some(daemon) = weak.upgrade() else {
        return serving::EjectClaim::Superseded;
    };
    let claim = daemon.serving.eject_claim(pool, generation);
    if claim != serving::EjectClaim::Won {
        return claim;
    }
    match daemon.pools.detach_quiesce(pool) {
        Ok(()) => println!(
            "scalefsd: external eject of '{pool}' — serving stopped and pool detached; \
             the disk is quiesced and safe to unplug"
        ),
        Err((code, why)) => {
            eprintln!(
                "scalefsd: external eject of '{pool}' — serving stopped, but the pool is \
                 STILL attached ({code:?}: {why}); another surface holds it"
            );
            daemon
                .pools
                .eject_abort(pool, scalefs_mount::dataplane::eject::BLIND_GENERATION);
        }
    }
    serving::EjectClaim::Won
}

fn eject_reconciler(daemon: &Daemon) -> serving::EjectReconciler {
    let weak = daemon.weak_self.clone();
    Arc::new(move |pool: &str, generation: u64| reconcile_external_eject(&weak, pool, generation))
}

fn eject_gate(daemon: &Daemon) -> serving::EjectGate {
    let weak = daemon.weak_self.clone();
    Arc::new(move |pool: &str, op: serving::EjectGateOp| {
        use scalefs_mount::dataplane::{PrepareOutcome, PrepareVerdict};
        let Some(daemon) = weak.upgrade() else {
            return PrepareOutcome::nak(PrepareVerdict::Unsupported);
        };
        match op {
            serving::EjectGateOp::Prepare { preparer } => {
                daemon.pools.eject_prepare(pool, Some(&preparer))
            }
            serving::EjectGateOp::Abort(generation) => {
                daemon.pools.eject_abort(pool, generation);
                PrepareOutcome {
                    verdict: PrepareVerdict::Ack,
                    generation: 0,
                }
            }
            serving::EjectGateOp::Commit {
                generation,
                committer,
            } => PrepareOutcome {
                verdict: daemon
                    .pools
                    .eject_commit(pool, generation, Some(&committer)),
                generation,
            },
        }
    })
}

#[derive(Debug, Clone, Copy)]
struct TrustPolicy {
    enforce: bool,
}

const READ_VERBS: &[&str] = &[
    "ping",
    "version",
    "pool.list",
    "pool.status",
    "job.status",
    "job.list",
    "device.list",
    "share.list",
    "serve.list",
    "pool.eject_record",
    "shell.volume",
];

#[cfg_attr(not(windows), allow(dead_code))]
const SHELL_VERBS: &[&str] = &["ping", "version", "shell.volume"];

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Surface {
    Management,
    #[cfg_attr(not(windows), allow(dead_code))]
    Shell,
}

const MUTATE_VERBS: &[&str] = &[
    "shutdown",
    "pool.attach",
    "pool.import",
    "pool.detach",
    "pool.mount",
    "pool.unmount",
    "pool.scrub",
    "pool.reclaim",
    "pool.rebuild",
    "pool.replace",
    "pool.add",
    "pool.remove",
    "pool.retire",
    "share.add",
    "share.remove",
    "pool.serve",
    "pool.serve_stop",
];

enum PeerGate {
    Live(Option<bool>),
    #[cfg(test)]
    Fixed(bool),
}

impl PeerGate {
    fn allowed(&mut self, stream: &Stream) -> std::io::Result<bool> {
        match self {
            PeerGate::Live(Some(verdict)) => Ok(*verdict),
            PeerGate::Live(memo) => {
                let verdict = stream.peer_is_privileged()?;
                *memo = Some(verdict);
                Ok(verdict)
            }
            #[cfg(test)]
            PeerGate::Fixed(verdict) => Ok(*verdict),
        }
    }
}

pub struct ServeOptions {
    pub endpoint: Endpoint,
    pub state_dir: Option<std::path::PathBuf>,
    pub trust_enforce: bool,
    pub on_ready: Option<Box<dyn FnOnce() + Send>>,
}

impl ServeOptions {
    pub fn new(endpoint: &Endpoint) -> ServeOptions {
        ServeOptions {
            endpoint: endpoint.clone(),
            state_dir: None,
            trust_enforce: false,
            on_ready: None,
        }
    }
}

pub fn serve(endpoint: &Endpoint) -> Result<(), String> {
    serve_with(ServeOptions::new(endpoint))
}

pub fn serve_with(options: ServeOptions) -> Result<(), String> {
    let endpoint = options.endpoint.clone();
    let mut listener = Listener::bind(&endpoint)
        .map_err(|error| format!("cannot bind {}: {error}", endpoint.as_str()))?;
    let state = match &options.state_dir {
        Some(dir) => Some(Arc::new(state::StateStore::open(dir)?)),
        None => None,
    };
    let shares_state = match &options.state_dir {
        Some(dir) => Some(Arc::new(state::SharesStore::open(dir)?)),
        None => None,
    };
    let trust = TrustPolicy {
        enforce: options.trust_enforce || scalefs_ipc::trust::process_is_privileged(),
    };
    println!(
        "scalefsd {} serving on {}{}",
        env!("CARGO_PKG_VERSION"),
        endpoint.as_str(),
        if trust.enforce {
            " (mutations require a privileged caller)"
        } else {
            ""
        },
    );
    let daemon = Arc::new_cyclic(|weak| Daemon {
        endpoint: endpoint.clone(),
        shutdown: AtomicBool::new(false),
        closing: AtomicBool::new(false),
        trust,
        pools: pools::Registry::with_state(state.clone()),
        shares: shares::Shares::with_state(shares_state.clone()),
        serving: serving::ServingRegistry::default(),
        weak_self: weak.clone(),
    });
    if let Some(store) = &state {
        state::reassemble(&daemon.pools, store);
    }
    if let Some(store) = &shares_state {
        daemon
            .shares
            .restore(store, |name| daemon.pools.share_handle(name));
    }
    #[cfg(windows)]
    if let Some(store) = &state {
        restore_serves(&daemon, store);
    }
    #[cfg(windows)]
    shell_companion::spawn(&daemon);
    if let Some(ready) = options.on_ready {
        ready();
    }
    const ACCEPT_BACKOFF_MAX: std::time::Duration = std::time::Duration::from_secs(5);
    let mut backoff = std::time::Duration::from_millis(50);
    let mut reported = false;
    loop {
        match listener.accept() {
            Ok(stream) => {
                backoff = std::time::Duration::from_millis(50);
                if reported {
                    eprintln!("scalefsd: the management listener is accepting again");
                    reported = false;
                }
                if daemon.shutdown.load(Ordering::SeqCst) {
                    return Ok(());
                }
                let daemon = Arc::clone(&daemon);
                let _ = std::thread::Builder::new()
                    .name("scalefsd-session".to_string())
                    .spawn(move || serve_connection(stream, &daemon));
            }
            Err(error) => {
                if daemon.shutdown.load(Ordering::SeqCst) {
                    return Ok(());
                }
                if !reported {
                    eprintln!(
                        "scalefsd: the management listener cannot accept ({error}); retrying \
                         (mounts and shares stay up)"
                    );
                    reported = true;
                }
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(ACCEPT_BACKOFF_MAX);
            }
        }
    }
}

#[cfg(windows)]
fn restore_serves(daemon: &Daemon, store: &state::StateStore) {
    use scalefs_ipc::json::{Value, object};
    for recorded in store.load() {
        if recorded.eject.is_some() {
            continue;
        }
        for mount in &recorded.mounts {
            let Some(device) = &mount.kernel_device else {
                continue;
            };
            let mut params = vec![
                ("pool", Value::Str(recorded.name.clone())),
                ("kernel_device", Value::Str(device.clone())),
                ("mount", Value::Str(mount.mountpoint.clone())),
            ];
            if mount.read_only {
                params.push(("read_only", Value::Bool(true)));
            }
            if let Some(policy) = mount.close_durability {
                params.extend(crate::serving::close_durability_fields(policy));
            }
            match daemon.serving.serve(
                &object(params),
                |name| daemon.pools.share_handle(name),
                eject_reconciler(daemon),
                eject_gate(daemon),
            ) {
                Ok(_) => println!(
                    "scalefsd: restored the serve of '{}' at {}",
                    recorded.name, mount.mountpoint,
                ),
                Err((_code, why)) => eprintln!(
                    "scalefsd: could not restore the serve of '{}' at {}: {why}",
                    recorded.name, mount.mountpoint,
                ),
            }
        }
    }
}

fn serve_connection(stream: Stream, daemon: &Daemon) {
    let mut reader = BufReader::new(stream);

    let hello = match read_frame(&mut reader) {
        Ok(Some(frame)) => frame,
        Ok(None) => return,
        Err(_) => {
            let refusal = error_response(None, ErrorCode::BadRequest, "malformed hello frame");
            let _ = write_frame(reader.get_mut(), &refusal);
            return;
        }
    };
    let negotiated = match check_client_hello(&hello) {
        Ok(version) => version,
        Err(why) => {
            let refusal = error_response(None, ErrorCode::BadRequest, why);
            let _ = write_frame(reader.get_mut(), &refusal);
            return;
        }
    };
    if write_frame(
        reader.get_mut(),
        &daemon_hello(negotiated, CAPABILITIES, env!("CARGO_PKG_VERSION")),
    )
    .is_err()
    {
        return;
    }

    let mut gate = PeerGate::Live(None);

    loop {
        let frame = match read_frame(&mut reader) {
            Ok(Some(frame)) => frame,
            Ok(None) => return,
            Err(error) => {
                let kind = match error {
                    FrameError::Io(_) => return,
                    FrameError::TooLong | FrameError::NotUtf8 | FrameError::Json(_) => error,
                };
                let refusal = error_response(None, ErrorCode::BadRequest, &kind.to_string());
                let _ = write_frame(reader.get_mut(), &refusal);
                return;
            }
        };
        let request = match Request::decode(&frame) {
            Ok(request) => request,
            Err(message) => {
                let id = frame.get("id").and_then(Value::as_u64);
                let refusal = error_response(id, ErrorCode::BadRequest, message);
                if write_frame(reader.get_mut(), &refusal).is_err() {
                    return;
                }
                continue;
            }
        };
        let (response, hang_up) = dispatch(
            &request,
            daemon,
            reader.get_ref(),
            &mut gate,
            Surface::Management,
        );
        if write_frame(reader.get_mut(), &response).is_err() {
            return;
        }
        if hang_up {
            let _ = scalefs_ipc::endpoint::connect(
                &daemon.endpoint,
                std::time::Duration::from_millis(200),
            );
            return;
        }
    }
}

fn dispatch(
    request: &Request,
    daemon: &Daemon,
    stream: &Stream,
    gate: &mut PeerGate,
    surface: Surface,
) -> (Value, bool) {
    if daemon.closing.load(Ordering::SeqCst) && !matches!(request.op.as_str(), "ping" | "version") {
        return (
            error_response(
                Some(request.id),
                ErrorCode::Busy,
                "the daemon is shutting down",
            ),
            false,
        );
    }
    debug_assert!(
        !(READ_VERBS.contains(&request.op.as_str()) && MUTATE_VERBS.contains(&request.op.as_str())),
        "a verb must sit in exactly one trust class",
    );
    if daemon.trust.enforce && MUTATE_VERBS.contains(&request.op.as_str()) {
        match gate.allowed(stream) {
            Ok(true) => {}
            Ok(false) => {
                return (
                    error_response(
                        Some(request.id),
                        ErrorCode::Forbidden,
                        &format!(
                            "'{}' requires a privileged caller: run the client {}",
                            request.op,
                            if cfg!(windows) {
                                "elevated (as an administrator)"
                            } else {
                                "as root"
                            },
                        ),
                    ),
                    false,
                );
            }
            Err(error) => {
                return (
                    error_response(
                        Some(request.id),
                        ErrorCode::Forbidden,
                        &format!(
                            "cannot verify the caller's identity for '{}': {error}",
                            request.op,
                        ),
                    ),
                    false,
                );
            }
        }
    }
    match request.op.as_str() {
        "ping" => (
            ok_response(request.id, object(vec![("pong", Value::Bool(true))])),
            false,
        ),
        "version" => (
            ok_response(
                request.id,
                object(vec![
                    ("daemon", Value::Str(env!("CARGO_PKG_VERSION").to_string())),
                    (
                        "protocol",
                        Value::Int(i128::from(scalefs_ipc::proto::PROTOCOL_VERSION)),
                    ),
                    (
                        "format",
                        Value::Int(i128::from(scalefs_core::FORMAT_VERSION)),
                    ),
                ]),
            ),
            false,
        ),
        "shutdown" => {
            let force = matches!(request.params.get("force"), Some(Value::Bool(true)));
            if !force && let Some((job, pool)) = daemon.pools.running_job() {
                return (
                    error_response(
                        Some(request.id),
                        ErrorCode::Busy,
                        &format!(
                            "job {job} is still running on '{pool}'; \
                             wait for it or shut down with force"
                        ),
                    ),
                    false,
                );
            }
            daemon.closing.store(true, Ordering::SeqCst);
            daemon.pools.unmount_all();
            daemon.serving.stop_all();
            daemon.shares.stop_all();
            daemon.shutdown.store(true, Ordering::SeqCst);
            (ok_response(request.id, Value::Null), true)
        }
        "pool.attach" => answer(request.id, daemon.pools.attach(&request.params)),
        "pool.import" => answer(request.id, daemon.pools.import(&request.params)),
        "pool.detach" => answer(request.id, daemon.pools.detach(&request.params)),
        #[cfg(target_os = "linux")]
        "pool.mount" => answer(request.id, daemon.pools.mount(&request.params)),
        #[cfg(target_os = "linux")]
        "pool.unmount" => answer(request.id, daemon.pools.unmount(&request.params)),
        #[cfg(not(target_os = "linux"))]
        "pool.mount" | "pool.unmount" => (
            error_response(
                Some(request.id),
                ErrorCode::Unsupported,
                "kernel mounts are Linux-only in this build",
            ),
            false,
        ),
        "pool.list" => answer(request.id, daemon.pools.list()),
        "pool.status" => answer(request.id, daemon.pools.status(&request.params)),
        "pool.scrub" => answer(request.id, daemon.pools.scrub(&request.params)),
        "pool.reclaim" => answer(request.id, daemon.pools.reclaim(&request.params)),
        "pool.rebuild" => answer(request.id, daemon.pools.rebuild(&request.params)),
        "pool.replace" => answer(request.id, daemon.pools.replace(&request.params)),
        "pool.add" => answer(request.id, daemon.pools.add(&request.params)),
        "pool.remove" => answer(request.id, daemon.pools.remove(&request.params)),
        "pool.retire" => answer(request.id, daemon.pools.retire(&request.params)),
        "job.status" => answer(request.id, daemon.pools.job_status(&request.params)),
        "job.list" => answer(request.id, daemon.pools.job_list()),
        "device.list" => answer(request.id, daemon.pools.device_list()),
        "pool.serve" => {
            let served = daemon.serving.serve(
                &request.params,
                |name| daemon.pools.share_handle(name),
                eject_reconciler(daemon),
                eject_gate(daemon),
            );
            #[cfg(windows)]
            if let Ok(reply) = &served
                && let Some(scalefs_ipc::json::Value::Str(pool)) = request.params.get("pool")
            {
                let record = match reply.get("mount") {
                    Some(scalefs_ipc::json::Value::Str(letter)) => {
                        Some(crate::state::RecordedMount {
                            mountpoint: letter.clone(),
                            read_only: reply.get("read_only")
                                == Some(&scalefs_ipc::json::Value::Bool(true)),
                            kernel_device: match request.params.get("kernel_device") {
                                Some(scalefs_ipc::json::Value::Str(device)) => Some(device.clone()),
                                _ => None,
                            },
                            close_durability: crate::serving::requested_close_durability(
                                &request.params,
                            ),
                        })
                    }
                    _ => None,
                };
                daemon.pools.record_serve_mount(pool, record);
            }
            answer(request.id, served)
        }
        "pool.serve_stop" => {
            let stopped = daemon.serving.stop(&request.params);
            #[cfg(windows)]
            if stopped.is_ok()
                && let Some(scalefs_ipc::json::Value::Str(pool)) = request.params.get("pool")
            {
                daemon.pools.record_serve_mount(pool, None);
            }
            answer(request.id, stopped)
        }
        "serve.list" => answer(request.id, daemon.serving.list()),
        "pool.eject_record" => answer(request.id, daemon.pools.eject_record(&request.params)),
        "shell.volume" => answer(request.id, shell_volume(daemon, &request.params, surface)),
        "share.add" => answer(
            request.id,
            daemon
                .shares
                .add(&request.params, |name| daemon.pools.share_handle(name)),
        ),
        "share.remove" => answer(request.id, daemon.shares.remove(&request.params)),
        "share.list" => answer(request.id, daemon.shares.list()),
        _ => (
            error_response(
                Some(request.id),
                ErrorCode::Unsupported,
                &format!("unknown operation '{}'", request.op),
            ),
            false,
        ),
    }
}

fn shell_volume(
    daemon: &Daemon,
    params: &Value,
    surface: Surface,
) -> Result<Value, pools::OpError> {
    let letter = match params.get("letter") {
        None => None,
        Some(value) => Some(value.as_str().and_then(drive_letter).ok_or_else(
            || -> pools::OpError {
                (
                    ErrorCode::BadRequest,
                    "'letter' must be a drive letter (\"P:\")".to_string(),
                )
            },
        )?),
    };
    let by_id = match params.get("pool_id") {
        None => None,
        Some(value) => Some(value.as_str().filter(|id| is_pool_id(id)).ok_or_else(
            || -> pools::OpError {
                (
                    ErrorCode::BadRequest,
                    "'pool_id' must be 32 lowercase hex digits".to_string(),
                )
            },
        )?),
    };
    let rows = daemon.serving.list()?;
    let serving = rows
        .get("serving")
        .and_then(Value::as_array)
        .unwrap_or_default();
    let row = match (letter, by_id) {
        (Some(letter), _) => {
            let want = format!("{letter}:");
            Some(
                serving
                    .iter()
                    .find(|row| {
                        row.get("mount")
                            .and_then(Value::as_str)
                            .is_some_and(|mount| mount.eq_ignore_ascii_case(&want))
                    })
                    .ok_or_else(|| -> pools::OpError {
                        (
                            ErrorCode::NotFound,
                            format!("no serving is mounted at {want}"),
                        )
                    })?,
            )
        }
        (None, Some(pool_id)) => serving.iter().find(|row| {
            row.get("pool_id")
                .and_then(Value::as_str)
                .is_some_and(|id| id.eq_ignore_ascii_case(pool_id))
        }),
        (None, None) => {
            return Err((
                ErrorCode::BadRequest,
                "'letter' or 'pool_id' is required".to_string(),
            ));
        }
    };
    let pool_id = row
        .and_then(|row| row.get("pool_id").and_then(Value::as_str))
        .or(by_id)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let record = daemon
        .pools
        .eject_record(&object(vec![("pool_id", Value::Str(pool_id.clone()))]))?;
    let serving = row.map(|row| {
        let pool = row
            .get("pool")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let holders = holders(daemon, &pool);
        (pool, row.get("mount").cloned(), holders)
    });
    Ok(shell_volume_reply(surface, pool_id, &record, serving))
}

fn shell_volume_reply(
    surface: Surface,
    pool_id: String,
    record: &Value,
    serving: Option<(String, Option<Value>, Vec<Value>)>,
) -> Value {
    let mut reply = vec![
        ("pool_id", Value::Str(pool_id)),
        ("phase", record.get("phase").cloned().unwrap_or(Value::Null)),
        (
            "generation",
            record.get("generation").cloned().unwrap_or(Value::Int(0)),
        ),
    ];
    if let Some((pool, mount, holders)) = serving {
        reply.push(("holders", Value::Array(holders)));
        if surface == Surface::Management {
            if let Some(mount) = mount {
                reply.push(("mount", mount));
            }
            reply.push(("pool", Value::Str(pool)));
        }
    }
    object(reply)
}

fn drive_letter(text: &str) -> Option<char> {
    let mut chars = text.chars();
    let letter = chars.next().filter(char::is_ascii_alphabetic)?;
    matches!(chars.as_str(), "" | ":" | ":\\").then(|| letter.to_ascii_uppercase())
}

fn is_pool_id(text: &str) -> bool {
    text.len() == 32
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn holders(daemon: &Daemon, pool: &str) -> Vec<Value> {
    let mut found = Vec::new();
    if let Ok(shares) = daemon.shares.list() {
        for share in shares
            .get("shares")
            .and_then(Value::as_array)
            .unwrap_or_default()
        {
            if share.get("pool").and_then(Value::as_str) == Some(pool)
                && let Some(name) = share.get("name")
            {
                found.push(object(vec![
                    ("kind", Value::Str("share".to_string())),
                    ("name", name.clone()),
                ]));
            }
        }
    }
    found
}

fn answer(id: u64, result: Result<Value, pools::OpError>) -> (Value, bool) {
    match result {
        Ok(value) => (ok_response(id, value), false),
        Err((code, message)) => (error_response(Some(id), code, &message), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(op: &str) -> Request {
        Request::decode(&object(vec![
            ("id", Value::Int(7)),
            ("op", Value::Str(op.to_string())),
        ]))
        .expect("valid request envelope")
    }

    fn daemon(closing: bool, enforce: bool) -> Daemon {
        Daemon {
            closing: AtomicBool::new(closing),
            trust: TrustPolicy { enforce },
            ..daemon_at(Endpoint::new("dispatch-test"))
        }
    }

    pub(crate) fn daemon_at(endpoint: Endpoint) -> Daemon {
        Daemon {
            endpoint,
            shutdown: AtomicBool::new(false),
            closing: AtomicBool::new(false),
            trust: TrustPolicy { enforce: false },
            pools: pools::Registry::default(),
            shares: shares::Shares::default(),
            serving: serving::ServingRegistry::default(),
            weak_self: Weak::new(),
        }
    }

    fn stream_pair(tag: &str) -> (Stream, Stream) {
        let name = format!("scalefsd-dispatch-{}-{tag}", std::process::id());
        let endpoint = {
            #[cfg(windows)]
            {
                Endpoint::new(&name)
            }
            #[cfg(unix)]
            {
                Endpoint::new(
                    &std::env::temp_dir()
                        .join(format!("{name}.sock"))
                        .to_string_lossy(),
                )
            }
        };
        let mut listener = Listener::bind(&endpoint).unwrap();
        let client_endpoint = endpoint.clone();
        let client = std::thread::spawn(move || {
            scalefs_ipc::endpoint::connect(&client_endpoint, std::time::Duration::from_secs(5))
                .unwrap()
        });
        let server = listener.accept().unwrap();
        (server, client.join().unwrap())
    }

    fn error_code(response: &Value) -> Option<String> {
        response
            .get("error")?
            .get("code")?
            .as_str()
            .map(str::to_string)
    }

    #[test]
    fn the_closing_barrier_gates_dispatch() {
        let daemon = daemon(true, false);
        let (server, _client) = stream_pair("barrier");
        let mut gate = PeerGate::Fixed(true);
        for probe in ["ping", "version"] {
            let (response, hang_up) = dispatch(
                &request(probe),
                &daemon,
                &server,
                &mut gate,
                Surface::Management,
            );
            assert_eq!(response.get("ok"), Some(&Value::Bool(true)), "{probe}");
            assert!(!hang_up, "{probe}");
        }
        for refused in [
            "pool.attach",
            "pool.list",
            "pool.mount",
            "share.add",
            "share.remove",
            "pool.detach",
            "shutdown",
        ] {
            let (response, hang_up) = dispatch(
                &request(refused),
                &daemon,
                &server,
                &mut gate,
                Surface::Management,
            );
            assert_eq!(response.get("ok"), Some(&Value::Bool(false)), "{refused}");
            assert_eq!(error_code(&response).as_deref(), Some("busy"), "{refused}");
            assert!(!hang_up, "{refused}");
        }
    }

    #[test]
    fn every_dispatched_verb_is_classified_exactly_once() {
        let (server, _client) = stream_pair("classified");
        let mut gate = PeerGate::Fixed(true);
        for verb in READ_VERBS.iter().chain(MUTATE_VERBS) {
            assert!(
                !MUTATE_VERBS.contains(verb) || !READ_VERBS.contains(verb),
                "'{verb}' must appear in exactly one class",
            );
            let fresh = daemon(false, false);
            let (response, _) = dispatch(
                &request(verb),
                &fresh,
                &server,
                &mut gate,
                Surface::Management,
            );
            let unknown = error_code(&response).as_deref() == Some("unsupported")
                && response
                    .get("error")
                    .and_then(|error| error.get("message"))
                    .and_then(Value::as_str)
                    .is_some_and(|message| message.starts_with("unknown operation"));
            assert!(
                !unknown,
                "'{verb}' is classified but not dispatched — stale table entry",
            );
        }
        let fresh = daemon(false, false);
        let (response, _) = dispatch(
            &request("pool.evaporate"),
            &fresh,
            &server,
            &mut gate,
            Surface::Management,
        );
        assert_eq!(error_code(&response).as_deref(), Some("unsupported"));
    }

    #[test]
    fn enforcement_forbids_unprivileged_mutations_and_frees_reads() {
        let enforcing = daemon(false, true);
        let (server, _client) = stream_pair("enforce");
        let mut unprivileged = PeerGate::Fixed(false);
        for verb in MUTATE_VERBS {
            let (response, hang_up) = dispatch(
                &request(verb),
                &enforcing,
                &server,
                &mut unprivileged,
                Surface::Management,
            );
            assert_eq!(
                error_code(&response).as_deref(),
                Some("forbidden"),
                "{verb} must be forbidden to an unprivileged caller",
            );
            assert!(!hang_up, "{verb} must not act (or hang up) when refused");
        }
        for verb in READ_VERBS {
            let (response, _) = dispatch(
                &request(verb),
                &enforcing,
                &server,
                &mut unprivileged,
                Surface::Management,
            );
            assert_ne!(
                error_code(&response).as_deref(),
                Some("forbidden"),
                "{verb} is read-class and must not require privilege",
            );
        }
        let mut privileged = PeerGate::Fixed(true);
        let (response, _) = dispatch(
            &request("pool.attach"),
            &enforcing,
            &server,
            &mut privileged,
            Surface::Management,
        );
        assert_eq!(error_code(&response).as_deref(), Some("bad_request"));
    }

    #[test]
    fn shell_volume_checks_its_parameters_first() {
        let daemon = daemon(false, false);
        let (server, _client) = stream_pair("shell-volume");
        let mut gate = PeerGate::Fixed(false);
        let mut ask = |params: Vec<(&str, Value)>| {
            let request = Request {
                id: 7,
                op: "shell.volume".to_string(),
                params: object(params),
            };
            error_code(&dispatch(&request, &daemon, &server, &mut gate, Surface::Management).0)
        };
        let hex32 = "0123456789abcdef0123456789abcdef";
        for bad in [
            Value::Str("x".into()),
            Value::Str(hex32[1..].into()),
            Value::Str(format!("{hex32}0")),
            Value::Str(hex32.to_ascii_uppercase()),
            Value::Str("../0123456789abcdef0123456789ab".into()),
            Value::Int(5),
        ] {
            assert_eq!(
                ask(vec![("pool_id", bad.clone())]).as_deref(),
                Some("bad_request"),
                "{bad:?}"
            );
        }
        for bad in ["PP", "1:", "", "P:\\x", "P::"] {
            assert_eq!(
                ask(vec![("letter", Value::Str(bad.into()))]).as_deref(),
                Some("bad_request"),
                "{bad:?}"
            );
        }
        assert_eq!(ask(vec![]).as_deref(), Some("bad_request"));
        assert_eq!(
            ask(vec![("letter", Value::Str("p:".into()))]).as_deref(),
            Some("not_found")
        );
        assert_eq!(ask(vec![("pool_id", Value::Str(hex32.into()))]), None);
    }

    #[test]
    fn the_companion_reply_omits_the_pool_and_mount() {
        let record = object(vec![
            ("phase", Value::Str("none".into())),
            ("generation", Value::Int(0)),
        ]);
        let pool_id = "0123456789abcdef0123456789abcdef".to_string();
        let serving = Some((
            "dl".to_string(),
            Some(Value::Str("P:".into())),
            vec![object(vec![
                ("kind", Value::Str("share".into())),
                ("name", Value::Str("dlshare".into())),
            ])],
        ));
        let shell = shell_volume_reply(Surface::Shell, pool_id.clone(), &record, serving.clone());
        let management = shell_volume_reply(Surface::Management, pool_id.clone(), &record, serving);
        for reply in [&shell, &management] {
            assert_eq!(
                reply.get("pool_id").and_then(Value::as_str),
                Some(pool_id.as_str())
            );
            assert_eq!(reply.get("phase").and_then(Value::as_str), Some("none"));
            assert!(reply.get("generation").is_some());
            assert!(
                reply
                    .get("holders")
                    .and_then(Value::as_array)
                    .is_some_and(|h| h.len() == 1),
                "both surfaces name the share"
            );
        }
        assert_eq!(shell.get("pool"), None, "the companion drops the pool name");
        assert_eq!(shell.get("mount"), None, "the companion drops the mount");
        assert_eq!(management.get("pool").and_then(Value::as_str), Some("dl"));
        assert_eq!(management.get("mount").and_then(Value::as_str), Some("P:"));
        let bare = shell_volume_reply(Surface::Shell, pool_id, &record, None);
        assert_eq!(bare.get("holders"), None);
    }

    #[test]
    fn an_unprivileged_daemon_keeps_the_dev_loop_open() {
        let open = daemon(false, false);
        let (server, _client) = stream_pair("open");
        let mut unprivileged = PeerGate::Fixed(false);
        let (response, _) = dispatch(
            &request("pool.attach"),
            &open,
            &server,
            &mut unprivileged,
            Surface::Management,
        );
        assert_eq!(error_code(&response).as_deref(), Some("bad_request"));
    }

    #[test]
    fn the_live_seam_answers_by_real_identity() {
        let endpoint = {
            let name = format!("scalefsd-live-seam-{}", std::process::id());
            #[cfg(windows)]
            {
                Endpoint::new(&name)
            }
            #[cfg(unix)]
            {
                Endpoint::new(
                    &std::env::temp_dir()
                        .join(format!("{name}.sock"))
                        .to_string_lossy(),
                )
            }
        };
        let mut listener = Listener::bind(&endpoint).unwrap();
        let daemon = daemon(false, true);
        let client_endpoint = endpoint.clone();
        let client = std::thread::spawn(move || {
            let mut client = scalefs_ipc::client::Client::connect(
                &client_endpoint,
                std::time::Duration::from_secs(5),
            )
            .unwrap();
            client.call("ping", Value::Null).expect("reads are free");
            client.call(
                "pool.attach",
                object(vec![("name", Value::Str("x".into()))]),
            )
        });
        let stream = listener.accept().unwrap();
        serve_connection(stream, &daemon);

        let expected = if scalefs_ipc::trust::process_is_privileged() {
            "bad_request"
        } else {
            "forbidden"
        };
        match client.join().unwrap() {
            Err(scalefs_ipc::client::CallError::Daemon { code, .. }) => {
                assert_eq!(code, expected);
            }
            other => panic!("expected a daemon error, got {other:?}"),
        }
    }
}
