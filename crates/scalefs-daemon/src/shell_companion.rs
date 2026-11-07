use crate::{CAPABILITIES, Daemon, PeerGate, SHELL_VERBS, Surface, dispatch};
use scalefs_ipc::endpoint::{Listener, Readiness, Stream};
use scalefs_ipc::frame::{read_frame, write_frame};
use scalefs_ipc::json::Value;
use scalefs_ipc::proto::{ErrorCode, Request, check_client_hello, daemon_hello, error_response};
use std::collections::VecDeque;
use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    pub workers: usize,
    pub waiting: usize,
    pub hello: Duration,
    pub request: Duration,
    pub frame: usize,
    pub tick: Duration,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            workers: 8,
            waiting: 64,
            hello: Duration::from_secs(2),
            request: Duration::from_secs(5),
            frame: 16 * 1024,
            tick: Duration::from_millis(5),
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct Stats {
    pub dispatched: AtomicUsize,
    pub closed_full: AtomicUsize,
    pub closed_late: AtomicUsize,
    pub peak_waiting: AtomicUsize,
    pub peak_workers: AtomicUsize,
}

fn raise(peak: &AtomicUsize, value: usize) {
    peak.fetch_max(value, Ordering::SeqCst);
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Retry {
    pub initial: Duration,
    pub max: Duration,
    pub report_every: Duration,
}

impl Default for Retry {
    fn default() -> Retry {
        Retry {
            initial: Duration::from_millis(100),
            max: Duration::from_secs(5),
            report_every: Duration::from_secs(60),
        }
    }
}

struct Backoff {
    retry: Retry,
    next: Duration,
}

impl Backoff {
    fn new(retry: Retry) -> Backoff {
        Backoff {
            retry,
            next: retry.initial,
        }
    }

    fn wait(&mut self) {
        std::thread::sleep(self.next);
        self.next = (self.next * 2).min(self.retry.max);
    }

    fn reset(&mut self) {
        self.next = self.retry.initial;
    }
}

struct Throttle {
    every: Duration,
    last: Option<Instant>,
}

impl Throttle {
    fn new(every: Duration) -> Throttle {
        Throttle { every, last: None }
    }

    fn due(&mut self) -> bool {
        let now = Instant::now();
        if self
            .last
            .is_some_and(|last| now.duration_since(last) < self.every)
        {
            return false;
        }
        self.last = Some(now);
        true
    }

    fn clear(&mut self) -> bool {
        self.last.take().is_some()
    }
}

pub(crate) fn spawn(daemon: &Arc<Daemon>) {
    let daemon = Arc::clone(daemon);
    let started = std::thread::Builder::new()
        .name("scalefsd-shell".to_string())
        .spawn(move || {
            run(
                &daemon,
                Retry::default(),
                Limits::default(),
                Arc::new(Stats::default()),
            )
        });
    if let Err(error) = started {
        eprintln!(
            "scalefsd: cannot start the shell endpoint ({error}); Explorer's Eject command \
             cannot reach this daemon"
        );
    }
}

pub(crate) fn run(daemon: &Arc<Daemon>, retry: Retry, limits: Limits, stats: Arc<Stats>) {
    let (to_gate, incoming) = std::sync::mpsc::sync_channel(limits.waiting);
    let gate_daemon = Arc::clone(daemon);
    let started = std::thread::Builder::new()
        .name("scalefsd-shell-gate".to_string())
        .spawn(move || gate(&gate_daemon, incoming, limits, &stats));
    if let Err(error) = started {
        eprintln!(
            "scalefsd: cannot start the shell endpoint ({error}); Explorer's Eject command \
             cannot reach this daemon"
        );
        return;
    }
    let companion = daemon.endpoint.shell_companion();
    let mut backoff = Backoff::new(retry);
    let mut taken = Throttle::new(retry.report_every);
    while !daemon.shutdown.load(Ordering::SeqCst) {
        let listener = match Listener::bind_for_interactive_users(&companion) {
            Ok(listener) => listener,
            Err(error) => {
                if taken.due() {
                    eprintln!(
                        "scalefsd: the shell endpoint {} is unavailable ({error}); retrying \
                         until it is free — Explorer's Eject command cannot reach this daemon \
                         meanwhile",
                        companion.as_str()
                    );
                }
                backoff.wait();
                continue;
            }
        };
        if taken.clear() {
            eprintln!(
                "scalefsd: the shell endpoint {} is bound",
                companion.as_str()
            );
        }
        backoff.reset();
        if !serve(daemon, listener, retry, &to_gate) {
            return;
        }
    }
}

fn serve(
    daemon: &Arc<Daemon>,
    mut listener: Listener,
    retry: Retry,
    to_gate: &SyncSender<(Stream, Instant)>,
) -> bool {
    let mut backoff = Backoff::new(retry);
    let mut failing = Throttle::new(retry.report_every);
    while !daemon.shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok(stream) => {
                backoff.reset();
                failing.clear();
                if to_gate.send((stream, Instant::now())).is_err() {
                    return false;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                eprintln!(
                    "scalefsd: the shell endpoint {} is held by another process now ({error}); \
                     binding it again",
                    daemon.endpoint.shell_companion().as_str()
                );
                return true;
            }
            Err(error) => {
                if failing.due() {
                    eprintln!(
                        "scalefsd: the shell endpoint {} cannot accept ({error}); retrying",
                        daemon.endpoint.shell_companion().as_str()
                    );
                }
                backoff.wait();
            }
        }
    }
    true
}

enum Stage {
    Hello,
    Request,
    Ready(Request),
}

struct Waiting {
    stream: Stream,
    accepted: Instant,
    buffer: Vec<u8>,
    stage: Stage,
}

enum Next {
    Keep,
    Close { late: bool },
}

fn gate(
    daemon: &Arc<Daemon>,
    incoming: Receiver<(Stream, Instant)>,
    limits: Limits,
    stats: &Stats,
) {
    let workers = Arc::new(AtomicUsize::new(0));
    let mut waiting: VecDeque<Waiting> = VecDeque::new();
    loop {
        if daemon.shutdown.load(Ordering::SeqCst) {
            return;
        }
        let wait = if waiting.is_empty() {
            Duration::from_secs(1)
        } else {
            limits.tick
        };
        match incoming.recv_timeout(wait) {
            Ok((stream, accepted)) => admit(&mut waiting, stream, accepted, &limits, stats),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        while let Ok((stream, accepted)) = incoming.try_recv() {
            admit(&mut waiting, stream, accepted, &limits, stats);
        }
        let now = Instant::now();
        let mut kept = VecDeque::with_capacity(waiting.len());
        while let Some(mut connection) = waiting.pop_front() {
            match look(&mut connection, &limits, now) {
                Next::Close { late } => {
                    if late {
                        stats.closed_late.fetch_add(1, Ordering::SeqCst);
                    }
                }
                Next::Keep => match connection.stage {
                    Stage::Ready(request) if workers.load(Ordering::SeqCst) < limits.workers => {
                        start_worker(daemon, connection.stream, request, &workers, stats);
                    }
                    stage => kept.push_back(Waiting {
                        stage,
                        ..connection
                    }),
                },
            }
        }
        waiting = kept;
    }
}

fn admit(
    waiting: &mut VecDeque<Waiting>,
    stream: Stream,
    accepted: Instant,
    limits: &Limits,
    stats: &Stats,
) {
    if waiting.len() >= limits.waiting {
        stats.closed_full.fetch_add(1, Ordering::SeqCst);
        match waiting
            .iter()
            .position(|connection| matches!(connection.stage, Stage::Hello))
        {
            Some(oldest) => drop(waiting.remove(oldest)),
            None => return,
        }
    }
    waiting.push_back(Waiting {
        stream,
        accepted,
        buffer: Vec::new(),
        stage: Stage::Hello,
    });
    raise(&stats.peak_waiting, waiting.len());
}

fn look(connection: &mut Waiting, limits: &Limits, now: Instant) -> Next {
    let allowed = match connection.stage {
        Stage::Hello => limits.hello,
        Stage::Request | Stage::Ready(_) => limits.request,
    };
    if now.duration_since(connection.accepted) >= allowed {
        return Next::Close { late: true };
    }
    if matches!(connection.stage, Stage::Ready(_)) {
        return Next::Keep;
    }
    match connection.stream.readiness() {
        Readiness::Closed => return Next::Close { late: false },
        Readiness::Waiting => return Next::Keep,
        Readiness::Ready(available) => {
            let room = (limits.frame + 1).saturating_sub(connection.buffer.len());
            let start = connection.buffer.len();
            connection.buffer.resize(start + available.min(room), 0);
            match connection.stream.read(&mut connection.buffer[start..]) {
                Ok(0) | Err(_) => return Next::Close { late: false },
                Ok(read) => connection.buffer.truncate(start + read),
            }
        }
    }
    loop {
        let Some(end) = connection.buffer.iter().position(|byte| *byte == b'\n') else {
            if connection.buffer.len() > limits.frame {
                refuse(
                    &mut connection.stream,
                    None,
                    "frame exceeds this endpoint's limit",
                );
                return Next::Close { late: false };
            }
            return Next::Keep;
        };
        if end >= limits.frame {
            refuse(
                &mut connection.stream,
                None,
                "frame exceeds this endpoint's limit",
            );
            return Next::Close { late: false };
        }
        let line: Vec<u8> = connection.buffer.drain(..=end).collect();
        match connection.stage {
            Stage::Hello => {
                if !hello(&mut connection.stream, &line) {
                    return Next::Close { late: false };
                }
                connection.stage = Stage::Request;
            }
            Stage::Request => match request(&mut connection.stream, &line) {
                Some(request) => {
                    connection.stage = Stage::Ready(request);
                    return Next::Keep;
                }
                None => return Next::Close { late: false },
            },
            Stage::Ready(_) => return Next::Keep,
        }
    }
}

fn frame(line: &[u8]) -> Result<Value, String> {
    let mut reader = line;
    match read_frame(&mut reader) {
        Ok(Some(value)) => Ok(value),
        Ok(None) => Err("empty frame".to_string()),
        Err(error) => Err(error.to_string()),
    }
}

fn hello(stream: &mut Stream, line: &[u8]) -> bool {
    let negotiated =
        frame(line).and_then(|hello| check_client_hello(&hello).map_err(|why| why.to_string()));
    match negotiated {
        Ok(version) => write_frame(
            stream,
            &daemon_hello(version, CAPABILITIES, env!("CARGO_PKG_VERSION")),
        )
        .is_ok(),
        Err(why) => {
            refuse(stream, None, &why);
            false
        }
    }
}

fn request(stream: &mut Stream, line: &[u8]) -> Option<Request> {
    let value = match frame(line) {
        Ok(value) => value,
        Err(why) => {
            refuse(stream, None, &why);
            return None;
        }
    };
    let request = match Request::decode(&value) {
        Ok(request) => request,
        Err(why) => {
            refuse(stream, value.get("id").and_then(Value::as_u64), why);
            return None;
        }
    };
    if !SHELL_VERBS.contains(&request.op.as_str()) {
        let refusal = error_response(
            Some(request.id),
            ErrorCode::Forbidden,
            &format!("'{}' is not answered on the shell endpoint", request.op),
        );
        let _ = write_frame(stream, &refusal);
        return None;
    }
    Some(request)
}

fn refuse(stream: &mut Stream, id: Option<u64>, why: &str) {
    let _ = write_frame(stream, &error_response(id, ErrorCode::BadRequest, why));
}

struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn start_worker(
    daemon: &Arc<Daemon>,
    mut stream: Stream,
    request: Request,
    workers: &Arc<AtomicUsize>,
    stats: &Stats,
) {
    let running = workers.fetch_add(1, Ordering::SeqCst) + 1;
    raise(&stats.peak_workers, running);
    stats.dispatched.fetch_add(1, Ordering::SeqCst);
    let slot = Slot(Arc::clone(workers));
    let daemon = Arc::clone(daemon);
    let _ = std::thread::Builder::new()
        .name("scalefsd-shell-session".to_string())
        .spawn(move || {
            let _slot = slot;
            let (response, _) = dispatch(
                &request,
                &daemon,
                &stream,
                &mut PeerGate::Live(None),
                Surface::Shell,
            );
            let _ = write_frame(&mut stream, &response);
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use scalefs_ipc::client::Client;
    use scalefs_ipc::endpoint::Endpoint;
    use scalefs_ipc::json::Value;
    use scalefs_ipc::trust::{ServerIdentity, own_account};
    use std::io::Write;

    fn quick() -> Retry {
        Retry {
            initial: Duration::from_millis(20),
            max: Duration::from_millis(100),
            report_every: Duration::from_secs(60),
        }
    }

    pub(crate) fn companion_daemon(tag: &str) -> Arc<Daemon> {
        let name = format!("scalefsd-companion-{}-{tag}", std::process::id());
        Arc::new(crate::tests::daemon_at(Endpoint::new(&name)))
    }

    fn ping(daemon: &Daemon) -> Result<Value, String> {
        let mut client = Client::connect_limited(
            &daemon.endpoint.shell_companion(),
            Duration::from_millis(500),
            &ServerIdentity::Account(own_account().unwrap()),
        )?;
        client
            .call("ping", Value::Null)
            .map_err(|error| error.to_string())
    }

    #[test]
    fn the_companion_binds_once_a_squatter_lets_go() {
        let daemon = companion_daemon("squatter");
        let squatter = Listener::bind(&daemon.endpoint.shell_companion()).unwrap();
        let runner = Arc::clone(&daemon);
        std::thread::spawn(move || {
            run(
                &runner,
                quick(),
                Limits::default(),
                Arc::new(Stats::default()),
            )
        });
        std::thread::sleep(Duration::from_millis(300));
        drop(squatter);
        let answer = ping_until_bound(&daemon);
        assert_eq!(answer.get("pong"), Some(&Value::Bool(true)));
        stop(&daemon);
    }

    fn ping_until_bound(daemon: &Daemon) -> Value {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match ping(daemon) {
                Ok(answer) => return answer,
                Err(error) if Instant::now() >= deadline => {
                    panic!("the companion never answered: {error}")
                }
                Err(_) => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    }

    fn serving(tag: &str, limits: Limits) -> (Arc<Daemon>, Arc<Stats>) {
        let daemon = companion_daemon(tag);
        let stats = Arc::new(Stats::default());
        let (runner, counters) = (Arc::clone(&daemon), Arc::clone(&stats));
        std::thread::spawn(move || run(&runner, quick(), limits, counters));
        ping_until_bound(&daemon);
        (daemon, stats)
    }

    fn stop(daemon: &Daemon) {
        daemon.shutdown.store(true, Ordering::SeqCst);
        let _ = ping(daemon);
    }

    fn connect(daemon: &Daemon) -> Stream {
        scalefs_ipc::endpoint::connect_limited(
            &daemon.endpoint.shell_companion(),
            Duration::from_secs(5),
        )
        .expect("a connection to the companion")
    }

    fn read_all_lines(stream: Stream) -> Vec<String> {
        let mut text = String::new();
        let mut stream = stream;
        let _ = stream.read_to_string(&mut text);
        text.lines().map(str::to_string).collect()
    }

    #[test]
    fn idle_connections_never_stop_a_genuine_request() {
        let limits = Limits::default();
        let (daemon, stats) = serving("idle", limits);
        let idle: Vec<Stream> = (0..255).map(|_| connect(&daemon)).collect();
        let started = Instant::now();
        let answer = ping(&daemon).expect("answered beside the idle connections");
        let took = started.elapsed();
        assert_eq!(answer.get("pong"), Some(&Value::Bool(true)));
        assert!(took < Duration::from_secs(1), "answered after {took:?}");
        assert!(stats.peak_waiting.load(Ordering::SeqCst) <= limits.waiting);
        assert!(stats.peak_workers.load(Ordering::SeqCst) <= limits.workers);
        assert!(
            stats.closed_full.load(Ordering::SeqCst) + stats.closed_late.load(Ordering::SeqCst)
                >= 255 - limits.waiting,
            "the idle connections beyond the waiting set were closed"
        );
        drop(idle);
        assert_eq!(
            ping(&daemon).expect("still serving").get("pong"),
            Some(&Value::Bool(true))
        );
        stop(&daemon);
    }

    #[test]
    fn silent_connections_are_closed_at_their_deadlines() {
        let limits = Limits {
            hello: Duration::from_millis(300),
            request: Duration::from_millis(900),
            ..Limits::default()
        };
        let (daemon, stats) = serving("deadline", limits);
        let started = Instant::now();
        assert!(read_all_lines(connect(&daemon)).is_empty());
        let silent = started.elapsed();
        assert!(
            silent >= Duration::from_millis(250) && silent < Duration::from_secs(3),
            "closed after {silent:?}"
        );
        let mut greeted = connect(&daemon);
        let started = Instant::now();
        greeted
            .write_all(b"{\"type\":\"hello\",\"protocol\":1}\n")
            .unwrap();
        let lines = read_all_lines(greeted);
        let quiet = started.elapsed();
        assert_eq!(lines.len(), 1, "only the hello reply: {lines:?}");
        assert!(
            quiet >= Duration::from_millis(800) && quiet < Duration::from_secs(4),
            "closed after {quiet:?}"
        );
        assert!(stats.closed_late.load(Ordering::SeqCst) >= 2);
        stop(&daemon);
    }

    #[test]
    fn a_connection_gets_one_answer() {
        let (daemon, _stats) = serving("one", Limits::default());
        let mut stream = connect(&daemon);
        stream
            .write_all(
                b"{\"type\":\"hello\",\"protocol\":1}\n\
                  {\"id\":1,\"op\":\"ping\"}\n{\"id\":2,\"op\":\"ping\"}\n",
            )
            .unwrap();
        let lines = read_all_lines(stream);
        assert_eq!(lines.len(), 2, "the hello reply and one answer: {lines:?}");
        assert!(lines[1].contains("\"id\":1") && lines[1].contains("pong"));
        let mut client = Client::connect_limited(
            &daemon.endpoint.shell_companion(),
            Duration::from_secs(2),
            &ServerIdentity::Account(own_account().unwrap()),
        )
        .unwrap();
        match client.call("pool.list", Value::Null) {
            Err(scalefs_ipc::client::CallError::Daemon { code, .. }) => {
                assert_eq!(code, "forbidden")
            }
            other => panic!("expected forbidden, got {other:?}"),
        }
        stop(&daemon);
    }
}
