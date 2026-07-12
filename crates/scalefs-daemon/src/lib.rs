
mod pools;
pub mod service;
mod shares;
mod state;

use scalefs_ipc::endpoint::{Endpoint, Listener, Stream};
use scalefs_ipc::frame::{FrameError, read_frame, write_frame};
use scalefs_ipc::json::{Value, object};
use scalefs_ipc::proto::{
    ErrorCode, Request, check_client_hello, daemon_hello, error_response, ok_response,
};
use std::io::BufReader;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(target_os = "linux")]
const CAPABILITIES: &[&str] = &["pools", "jobs", "devices", "mounts", "smb"];
#[cfg(not(target_os = "linux"))]
const CAPABILITIES: &[&str] = &["pools", "jobs", "devices", "smb"];

struct Daemon {
    endpoint: Endpoint,
    shutdown: AtomicBool,
    closing: AtomicBool,
    trust: TrustPolicy,
    pools: pools::Registry,
    shares: shares::Shares,
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
];

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
    "share.add",
    "share.remove",
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
    let daemon = Arc::new(Daemon {
        endpoint: endpoint.clone(),
        shutdown: AtomicBool::new(false),
        closing: AtomicBool::new(false),
        trust,
        pools: pools::Registry::with_state(state.clone()),
        shares: shares::Shares::with_state(shares_state.clone()),
    });
    if let Some(store) = &state {
        state::reassemble(&daemon.pools, store);
    }
    if let Some(store) = &shares_state {
        daemon
            .shares
            .restore(store, |name| daemon.pools.share_handle(name));
    }
    if let Some(ready) = options.on_ready {
        ready();
    }
    let mut consecutive_failures = 0;
    loop {
        match listener.accept() {
            Ok(stream) => {
                consecutive_failures = 0;
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
                consecutive_failures += 1;
                if consecutive_failures >= 64 {
                    daemon.closing.store(true, Ordering::SeqCst);
                    daemon.pools.unmount_all();
                    daemon.shares.stop_all();
                    return Err(format!("listener failed: {error}"));
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
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
        let (response, hang_up) = dispatch(&request, daemon, reader.get_ref(), &mut gate);
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
        "job.status" => answer(request.id, daemon.pools.job_status(&request.params)),
        "job.list" => answer(request.id, daemon.pools.job_list()),
        "device.list" => answer(request.id, daemon.pools.device_list()),
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
            endpoint: Endpoint::new("dispatch-test"),
            shutdown: AtomicBool::new(false),
            closing: AtomicBool::new(closing),
            trust: TrustPolicy { enforce },
            pools: pools::Registry::default(),
            shares: shares::Shares::default(),
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
            let (response, hang_up) = dispatch(&request(probe), &daemon, &server, &mut gate);
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
            let (response, hang_up) = dispatch(&request(refused), &daemon, &server, &mut gate);
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
            let (response, _) = dispatch(&request(verb), &fresh, &server, &mut gate);
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
        let (response, _) = dispatch(&request("pool.evaporate"), &fresh, &server, &mut gate);
        assert_eq!(error_code(&response).as_deref(), Some("unsupported"));
    }

    #[test]
    fn enforcement_forbids_unprivileged_mutations_and_frees_reads() {
        let enforcing = daemon(false, true);
        let (server, _client) = stream_pair("enforce");
        let mut unprivileged = PeerGate::Fixed(false);
        for verb in MUTATE_VERBS {
            let (response, hang_up) =
                dispatch(&request(verb), &enforcing, &server, &mut unprivileged);
            assert_eq!(
                error_code(&response).as_deref(),
                Some("forbidden"),
                "{verb} must be forbidden to an unprivileged caller",
            );
            assert!(!hang_up, "{verb} must not act (or hang up) when refused");
        }
        for verb in READ_VERBS {
            let (response, _) = dispatch(&request(verb), &enforcing, &server, &mut unprivileged);
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
        );
        assert_eq!(error_code(&response).as_deref(), Some("bad_request"));
    }

    #[test]
    fn an_unprivileged_daemon_keeps_the_dev_loop_open() {
        let open = daemon(false, false);
        let (server, _client) = stream_pair("open");
        let mut unprivileged = PeerGate::Fixed(false);
        let (response, _) = dispatch(&request("pool.attach"), &open, &server, &mut unprivileged);
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
