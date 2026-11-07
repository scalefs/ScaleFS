use scalefs_core::{AnyBlockDevice, BlockDevice, Geometry, MemberSpec, Pool, ScaleFsError};
use scalefs_ipc::json::{Value, object};
use scalefs_ipc::proto::ErrorCode;
use scalefs_mount::mountcore::MountCore;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

pub type OpError = (ErrorCode, String);

type ServedDevice = Arc<AnyBlockDevice>;
pub(crate) type PoolCore = Arc<MountCore<ServedDevice>>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PoolPresentation {
    External,
    Fixed,
}

impl PoolPresentation {
    pub(crate) fn from_external(external: bool) -> Self {
        if external {
            PoolPresentation::External
        } else {
            PoolPresentation::Fixed
        }
    }

    pub(crate) fn word(self) -> &'static str {
        match self {
            PoolPresentation::External => "external",
            PoolPresentation::Fixed => "fixed",
        }
    }
}

pub struct PoolHandle {
    pub pool: Arc<RwLock<Pool<ServedDevice>>>,
    pub core: Option<PoolCore>,
    pub presentation: PoolPresentation,
    pub guard: ShareGuard,
}

pub struct ShareGuard {
    served: Arc<AtomicUsize>,
    held: Arc<AtomicBool>,
}

impl ShareGuard {
    fn claim(served: &Arc<AtomicUsize>) -> ShareGuard {
        served.fetch_add(1, Ordering::SeqCst);
        ShareGuard {
            served: Arc::clone(served),
            held: Arc::new(AtomicBool::new(true)),
        }
    }

    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn witness(&self) -> GuardWitness {
        GuardWitness {
            held: Arc::clone(&self.held),
        }
    }
}

impl Drop for ShareGuard {
    fn drop(&mut self) {
        self.held.store(false, Ordering::SeqCst);
        self.served.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Clone)]
#[cfg_attr(not(windows), allow(dead_code))]
pub struct GuardWitness {
    held: Arc<AtomicBool>,
}

impl GuardWitness {
    pub fn held(&self) -> bool {
        self.held.load(Ordering::SeqCst)
    }
}

#[derive(Default)]
pub struct Registry {
    pools: Arc<Mutex<BTreeMap<String, Arc<Attached>>>>,
    jobs: Mutex<BTreeMap<u64, Arc<Job>>>,
    next_job: AtomicU64,
    state: Option<Arc<crate::state::StateStore>>,
}

fn persist_pools(
    pools: &Mutex<BTreeMap<String, Arc<Attached>>>,
    state: &Option<Arc<crate::state::StateStore>>,
) -> std::io::Result<()> {
    let Some(store) = state else { return Ok(()) };
    let _persist = store.persist_guard();
    let stored = match store.load_suppressed() {
        Ok(stored) => stored,
        Err(error) => {
            eprintln!(
                "scalefsd: could not persist the pool record: the safe-removal records \
                 already on disk cannot be read ({error})"
            );
            return Err(error);
        }
    };
    let (rows, tombstones) = {
        let pools = pools.lock().expect("registry lock");
        let mut rows = Vec::new();
        let mut tombstones = Vec::new();
        for entry in pools.values() {
            let record = crate::state::RecordedPool {
                name: entry.name.clone(),
                pool_id: entry.pool_id.clone(),
                members: entry.members.lock().expect("member paths").clone(),
                mounts: recorded_mounts(entry),
                eject: *entry.eject_state.lock().expect("eject state"),
            };
            if record.eject.is_some() {
                tombstones.push(record);
            } else {
                rows.push(record);
            }
        }
        tombstones.extend(stored.into_iter().filter(|tombstone| {
            !pools
                .values()
                .any(|entry| entry.pool_id.eq_ignore_ascii_case(&tombstone.pool_id))
        }));
        (rows, tombstones)
    };
    if let Err(error) = store.save(&rows, &tombstones) {
        eprintln!("scalefsd: could not persist the pool record: {error}");
        return Err(error);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn recorded_mounts(entry: &Arc<Attached>) -> Vec<crate::state::RecordedMount> {
    let slot = entry.mounted.lock().expect("mount slot");
    match &*slot {
        MountSlot::Mounted(_, active) => vec![crate::state::RecordedMount {
            mountpoint: active.mountpoint.display().to_string(),
            read_only: active.read_only,
            kernel_device: None,
            close_durability: None,
        }],
        _ => Vec::new(),
    }
}

#[cfg(windows)]
fn recorded_mounts(entry: &Arc<Attached>) -> Vec<crate::state::RecordedMount> {
    entry
        .serve_mount
        .lock()
        .expect("serve mount")
        .clone()
        .into_iter()
        .collect()
}

#[cfg(not(any(target_os = "linux", windows)))]
fn recorded_mounts(_entry: &Arc<Attached>) -> Vec<crate::state::RecordedMount> {
    Vec::new()
}

#[cfg(windows)]
fn reactivated_letter(
    tombstone: &crate::state::RecordedPool,
) -> Option<crate::state::RecordedMount> {
    tombstone
        .mounts
        .iter()
        .find(|mount| mount.kernel_device.is_some())
        .cloned()
}

fn report_reactivation(name: &str, tombstone: &crate::state::RecordedPool) {
    let (phase, generation) = tombstone.eject.map_or(("prepared", 0), |eject| {
        (eject.phase.word(), eject.generation)
    });
    #[cfg(windows)]
    let letter = match reactivated_letter(tombstone) {
        Some(mount) => format!("; its drive letter {} is kept", mount.mountpoint),
        None => String::new(),
    };
    #[cfg(not(windows))]
    let letter = "";
    println!(
        "scalefsd: pool '{name}' was ejected ({phase}, generation {generation}); the operator \
         attached it again — clearing the safe-removal record{letter}"
    );
}

impl Registry {
    pub fn with_state(state: Option<Arc<crate::state::StateStore>>) -> Registry {
        Registry {
            state,
            ..Registry::default()
        }
    }

    fn persist(&self) {
        let _ = persist_pools(&self.pools, &self.state);
    }

    fn persist_checked(&self) -> std::io::Result<()> {
        persist_pools(&self.pools, &self.state)
    }

    #[cfg(windows)]
    pub fn record_serve_mount(&self, pool: &str, record: Option<crate::state::RecordedMount>) {
        let entry = {
            let pools = self.pools.lock().expect("registry lock");
            let Some(entry) = pools.get(pool) else { return };
            Arc::clone(entry)
        };
        *entry.serve_mount.lock().expect("serve mount") = record;
        self.persist();
    }

    pub(crate) fn attach_recorded(
        &self,
        name: String,
        members: &[String],
    ) -> Result<Value, OpError> {
        self.attach_paths(name, members, false, AttachBy::BootRestore)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AttachBy {
    Operator,
    BootRestore,
}

struct Attached {
    name: String,
    members: Mutex<Vec<String>>,
    media: Mutex<Vec<Value>>,
    pool_id: String,
    pool: Arc<RwLock<Pool<ServedDevice>>>,
    core: OnceLock<PoolCore>,
    #[cfg(target_os = "linux")]
    mounted: Mutex<MountSlot>,
    #[cfg(target_os = "linux")]
    mount_generation: AtomicU64,
    #[cfg(target_os = "linux")]
    last_mount_exit: Mutex<Option<String>>,
    #[cfg(windows)]
    serve_mount: Mutex<Option<crate::state::RecordedMount>>,
    shares_served: Arc<AtomicUsize>,
    busy: AtomicU64,
    status: Mutex<Value>,
    wrecked: std::sync::atomic::AtomicBool,
    presents_external: std::sync::atomic::AtomicBool,
    eject_state: Mutex<Option<crate::state::EjectState>>,
    next_eject_generation: AtomicU64,
    eject_pending: std::sync::atomic::AtomicBool,
    commits_in_flight: std::sync::atomic::AtomicUsize,
}

struct CommitInFlight {
    entry: Arc<Attached>,
}

impl CommitInFlight {
    fn begin(entry: Arc<Attached>) -> CommitInFlight {
        entry.commits_in_flight.fetch_add(1, Ordering::SeqCst);
        CommitInFlight { entry }
    }
}

impl Drop for CommitInFlight {
    fn drop(&mut self) {
        self.entry.commits_in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(target_os = "linux")]
struct ActiveMount {
    mountpoint: std::path::PathBuf,
    read_only: bool,
    worker: std::thread::JoinHandle<()>,
    stop: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(target_os = "linux")]
enum MountSlot {
    Empty,
    Mounting(u64),
    Mounted(u64, ActiveMount),
    Unmounting(u64),
    Draining(u64),
    Ended(#[allow(dead_code)] u64, std::thread::JoinHandle<()>),
}

#[cfg(target_os = "linux")]
fn park_ended(entry: &Attached, generation: u64) {
    if let Ok(mut slot) = entry.mounted.lock()
        && matches!(&*slot, MountSlot::Mounted(g, _) if *g == generation)
    {
        let MountSlot::Mounted(_, state) = std::mem::replace(&mut *slot, MountSlot::Empty) else {
            unreachable!()
        };
        *slot = MountSlot::Ended(generation, state.worker);
    }
}

#[cfg(target_os = "linux")]
fn park_drained(entry: &Attached, generation: u64) {
    if let Ok(mut slot) = entry.mounted.lock()
        && matches!(&*slot, MountSlot::Draining(g) if *g == generation)
    {
        *slot = MountSlot::Empty;
    }
}

#[cfg(target_os = "linux")]
fn drain_off_thread(entry: &Arc<Attached>, generation: u64, state: ActiveMount) {
    state.stop.store(true, Ordering::SeqCst);
    let _ = scalefs_mount::fuse::device::detach_mountpoint(&state.mountpoint);
    *entry.mounted.lock().expect("mount state") = MountSlot::Draining(generation);
    let entry = Arc::clone(entry);
    let worker = state.worker;
    std::thread::spawn(move || {
        let _ = worker.join();
        park_drained(&entry, generation);
    });
}

#[cfg(target_os = "linux")]
const SHUTDOWN_DRAIN_DEADLINE: std::time::Duration = std::time::Duration::from_secs(150);

#[cfg(target_os = "linux")]
fn bounded_join_all(handles: Vec<std::thread::JoinHandle<()>>, deadline: std::time::Duration) {
    if handles.is_empty() {
        return;
    }
    let (done, finished) = std::sync::mpsc::channel();
    let count = handles.len();
    for handle in handles {
        let done = done.clone();
        std::thread::spawn(move || {
            let _ = handle.join();
            let _ = done.send(());
        });
    }
    drop(done);
    let start = std::time::Instant::now();
    for _ in 0..count {
        let remaining = deadline.saturating_sub(start.elapsed());
        if remaining.is_zero() || finished.recv_timeout(remaining).is_err() {
            break;
        }
    }
}

#[cfg(target_os = "linux")]
enum UnmountRefusal {
    NotMounted,
    InProgress,
    Busy(std::path::PathBuf),
}

#[cfg(target_os = "linux")]
struct SlotReset {
    entry: Arc<Attached>,
    generation: u64,
    armed: bool,
}

#[cfg(target_os = "linux")]
impl SlotReset {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(target_os = "linux")]
impl Drop for SlotReset {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(mut slot) = self.entry.mounted.lock() {
            match &*slot {
                MountSlot::Mounting(generation) | MountSlot::Unmounting(generation)
                    if *generation == self.generation =>
                {
                    *slot = MountSlot::Empty;
                }
                _ => {}
            }
        }
    }
}

struct Job {
    id: u64,
    kind: &'static str,
    pool_name: String,
    state: Mutex<JobState>,
}

struct JobSettle {
    job: Arc<Job>,
    entry: Arc<Attached>,
}

impl Drop for JobSettle {
    fn drop(&mut self) {
        if let Ok(mut state) = self.job.state.lock()
            && matches!(*state, JobState::Running)
        {
            *state = JobState::Failed(
                ErrorCode::Internal,
                "the job worker crashed while settling its result".to_string(),
            );
        }
        self.entry.busy.store(0, Ordering::SeqCst);
    }
}

enum JobState {
    Running,
    Done(Value),
    Failed(ErrorCode, String),
}

fn now_ns() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(since) => i64::try_from(since.as_nanos()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

impl Registry {
    pub fn attach(&self, params: &Value) -> Result<Value, OpError> {
        let name = required_name(params)?;
        let members = match params.get("members").and_then(Value::as_array) {
            Some(paths) if !paths.is_empty() => paths
                .iter()
                .map(|path| {
                    path.as_str()
                        .map(str::to_string)
                        .ok_or_else(bad("members must be an array of image paths"))
                })
                .collect::<Result<Vec<String>, OpError>>()?,
            _ => return Err(bad("members must be a non-empty array of image paths")()),
        };
        let degraded = degraded_flag(params)?;
        let summary = self.attach_paths(name, &members, degraded, AttachBy::Operator)?;
        self.persist();
        Ok(summary)
    }

    fn stored_tombstone(&self, pool_id: &str) -> Option<crate::state::RecordedPool> {
        let store = self.state.as_ref()?;
        match store.load_suppressed() {
            Ok(tombstones) => tombstones
                .into_iter()
                .find(|tombstone| tombstone.pool_id.eq_ignore_ascii_case(pool_id)),
            Err(error) => {
                eprintln!(
                    "scalefsd: cannot read the safe-removal records ({error}); attaching \
                     without them"
                );
                None
            }
        }
    }

    pub fn import(&self, params: &Value) -> Result<Value, OpError> {
        let degraded = degraded_flag(params)?;
        let selector = match params.get("pool") {
            None => None,
            Some(Value::Str(selector)) if !selector.is_empty() => Some(selector.clone()),
            Some(_) => return Err(bad("pool must be a non-empty string")()),
        };
        let candidates = match params.get("candidates") {
            None => scalefs_core::list_devices(),
            Some(Value::Array(paths)) if !paths.is_empty() => paths
                .iter()
                .map(|path| {
                    path.as_str()
                        .map(|path| scalefs_core::probe_path(Path::new(path)))
                        .ok_or_else(bad("candidates must be an array of paths"))
                })
                .collect::<Result<Vec<_>, OpError>>()?,
            Some(_) => return Err(bad("candidates must be a non-empty array of paths")()),
        };
        let plan =
            scalefs_core::plan_import(&candidates, selector.as_deref()).map_err(|error| {
                match &error {
                    scalefs_core::PlanError::NoPools | scalefs_core::PlanError::NoMatch(_) => {
                        (ErrorCode::NotFound, error.to_string())
                    }
                    scalefs_core::PlanError::EarlierFormat(_) => {
                        (ErrorCode::Unsupported, error.to_string())
                    }
                    _ => (ErrorCode::Conflict, error.to_string()),
                }
            })?;
        let name = match params.get("name") {
            Some(_) => required_name(params)?,
            None if valid_name(&plan.label) => plan.label.clone(),
            None => hex(&plan.pool_id.0[..6]),
        };
        let mut result = self.attach_paths(name, &plan.members, degraded, AttachBy::Operator)?;
        self.persist();
        if !plan.duplicates.is_empty()
            && let Value::Object(entries) = &mut result
        {
            entries.push((
                "duplicates".to_string(),
                Value::Array(plan.duplicates.into_iter().map(Value::Str).collect()),
            ));
        }
        Ok(result)
    }

    fn attach_paths(
        &self,
        name: String,
        members: &[String],
        degraded: bool,
        by: AttachBy,
    ) -> Result<Value, OpError> {
        {
            let pools = self.pools.lock().expect("registry lock");
            if pools.contains_key(&name) {
                return Err((
                    ErrorCode::Conflict,
                    format!("a pool is already attached as '{name}'"),
                ));
            }
            for entry in pools.values() {
                if let Some(shared) = entry.holds_any_of(members) {
                    return Err((
                        ErrorCode::Conflict,
                        format!(
                            "{shared} already belongs to the attachment '{}'",
                            entry.name
                        ),
                    ));
                }
            }
        }
        let media: Vec<Value> = members.iter().map(|path| probe_medium(path)).collect();
        let presents_external = media_presents_external(&media);

        let mut devices = Vec::with_capacity(members.len());
        for path in members {
            devices.push(Arc::new(
                AnyBlockDevice::open(Path::new(path)).map_err(|error| annotate(path, error))?,
            ));
        }
        let pool = if degraded {
            Pool::open_multi_degraded(devices)
        } else {
            Pool::open_multi(devices)
        }
        .map_err(map_error)?;

        let engine_read_only = pool.read_only();
        let pool_id = hex(&pool.superblock().pool_id.0);
        let tombstone = match by {
            AttachBy::Operator => self.stored_tombstone(&pool_id),
            AttachBy::BootRestore => None,
        };
        let attached = Attached {
            name: name.clone(),
            members: Mutex::new(members.to_vec()),
            media: Mutex::new(media),
            pool_id,
            pool: Arc::new(RwLock::new(pool)),
            core: OnceLock::new(),
            #[cfg(target_os = "linux")]
            mounted: Mutex::new(MountSlot::Empty),
            #[cfg(target_os = "linux")]
            mount_generation: AtomicU64::new(0),
            #[cfg(target_os = "linux")]
            last_mount_exit: Mutex::new(None),
            #[cfg(windows)]
            serve_mount: Mutex::new(tombstone.as_ref().and_then(reactivated_letter)),
            shares_served: Arc::new(AtomicUsize::new(0)),
            busy: AtomicU64::new(0),
            status: Mutex::new(Value::Null),
            wrecked: std::sync::atomic::AtomicBool::new(false),
            presents_external: std::sync::atomic::AtomicBool::new(presents_external),
            eject_state: Mutex::new(None),
            next_eject_generation: AtomicU64::new(0),
            eject_pending: std::sync::atomic::AtomicBool::new(false),
            commits_in_flight: std::sync::atomic::AtomicUsize::new(0),
        };
        {
            let pool = attached.pool.read().expect("pool lock");
            *attached.status.lock().expect("status cache") = full_status(&attached, &pool);
        }

        let mut pools = self.pools.lock().expect("registry lock");
        if pools.contains_key(&name) {
            return Err((
                ErrorCode::Conflict,
                format!("a pool is already attached as '{name}'"),
            ));
        }
        for entry in pools.values() {
            if entry.pool_id == attached.pool_id {
                return Err((
                    ErrorCode::Conflict,
                    format!(
                        "that pool is already attached as '{}' (pool id {})",
                        entry.name, entry.pool_id,
                    ),
                ));
            }
            if let Some(shared) = entry.holds_any_of(members) {
                return Err((
                    ErrorCode::Conflict,
                    format!(
                        "{shared} already belongs to the attachment '{}'",
                        entry.name
                    ),
                ));
            }
        }
        if !engine_read_only {
            attached
                .core
                .get_or_init(|| Arc::new(MountCore::read_write(Arc::clone(&attached.pool))));
        }
        let summary = attached.status.lock().expect("status cache").clone();
        pools.insert(name.clone(), Arc::new(attached));
        drop(pools);
        if let Some(tombstone) = &tombstone {
            report_reactivation(&name, tombstone);
        }
        Ok(summary)
    }

    #[cfg(target_os = "linux")]
    pub fn mount(&self, params: &Value) -> Result<Value, OpError> {
        let name = required_name(params)?;
        let mountpoint = match params.get("mountpoint").and_then(Value::as_str) {
            Some(path) if !path.is_empty() => std::path::PathBuf::from(path),
            _ => return Err(bad("params need a mountpoint path")()),
        };
        let read_only = match params.get("read_only") {
            None => false,
            Some(Value::Bool(flag)) => *flag,
            Some(_) => return Err(bad("read_only must be a boolean")()),
        };
        let result = self.mount_at(&name, mountpoint, read_only)?;
        self.persist();
        Ok(result)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn mount_at(
        &self,
        name: &str,
        mountpoint: std::path::PathBuf,
        read_only: bool,
    ) -> Result<Value, OpError> {
        if !mountpoint.is_absolute() {
            return Err(bad("the mountpoint must be an absolute path")());
        }
        if scalefs_mount::fuse::device::clear_stale_mount(&mountpoint) {
            eprintln!(
                "scalefsd: cleared a dead FUSE mount at {} before mounting",
                mountpoint.display(),
            );
        }
        match std::fs::metadata(&mountpoint) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => {
                return Err((
                    ErrorCode::NotFound,
                    format!("{} is not a directory", mountpoint.display()),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err((
                    ErrorCode::NotFound,
                    format!("{} does not exist", mountpoint.display()),
                ));
            }
            Err(error) => {
                return Err((
                    ErrorCode::Io,
                    format!(
                        "cannot use {} as a mountpoint: {error}",
                        mountpoint.display()
                    ),
                ));
            }
        }
        let (entry, generation, core) = {
            let pools = self.pools.lock().expect("registry lock");
            let entry = pools.get(name).map(Arc::clone).ok_or_else(|| {
                (
                    ErrorCode::NotFound,
                    format!("no pool is attached as '{name}'"),
                )
            })?;
            if entry.wrecked.load(Ordering::SeqCst) {
                return Err((
                    ErrorCode::Internal,
                    format!(
                        "pool '{name}' was fenced off by a crashed job; \
                         detach and import it again"
                    ),
                ));
            }
            if entry.eject_pending.load(Ordering::SeqCst) {
                return Err((
                    ErrorCode::Conflict,
                    format!("pool '{name}' is being ejected; it cannot be mounted"),
                ));
            }
            let core = match (entry.core.get(), read_only) {
                (Some(core), _) => Some(Arc::clone(core)),
                (None, true) => None,
                (None, false) => {
                    return Err((
                        ErrorCode::Conflict,
                        format!(
                            "pool '{name}' is read-only (degraded or feature-limited); \
                             mount it with read_only"
                        ),
                    ));
                }
            };
            let generation = entry.mount_generation.fetch_add(1, Ordering::SeqCst) + 1;
            {
                let mut slot = entry.mounted.lock().expect("mount state");
                match &*slot {
                    MountSlot::Empty => {}
                    MountSlot::Ended(..) => {
                        let MountSlot::Ended(_, worker) =
                            std::mem::replace(&mut *slot, MountSlot::Empty)
                        else {
                            unreachable!()
                        };
                        let _ = worker.join();
                    }
                    MountSlot::Mounting(_) | MountSlot::Unmounting(_) => {
                        return Err((
                            ErrorCode::Conflict,
                            format!("pool '{name}' has a mount operation in progress"),
                        ));
                    }
                    MountSlot::Draining(_) => {
                        return Err((
                            ErrorCode::Conflict,
                            format!(
                                "pool '{name}' has a forced unmount still draining; \
                                 try again shortly"
                            ),
                        ));
                    }
                    MountSlot::Mounted(_, state) => {
                        return Err((
                            ErrorCode::Conflict,
                            format!(
                                "pool '{name}' is already mounted at {}",
                                state.mountpoint.display(),
                            ),
                        ));
                    }
                }
                *slot = MountSlot::Mounting(generation);
            }
            (entry, generation, core)
        };
        let mut claim = SlotReset {
            entry: Arc::clone(&entry),
            generation,
            armed: true,
        };
        let core = core.unwrap_or_else(|| Arc::new(MountCore::read_only(Arc::clone(&entry.pool))));
        let fuse = scalefs_mount::fuse::device::FuseMount::mount(&mountpoint, read_only).map_err(
            |error| {
                (
                    ErrorCode::Io,
                    format!("cannot mount at {}: {error}", mountpoint.display()),
                )
            },
        )?;
        let stop = fuse.stop_handle();
        let worker_entry = Arc::clone(&entry);
        let worker_name = name.to_string();
        let mut slot = entry.mounted.lock().expect("mount state");
        let spawned = std::thread::Builder::new()
            .name(format!("scalefs-mount-{name}"))
            .spawn(move || {
                let mut mount = fuse;
                let filesystem = if read_only {
                    scalefs_mount::poolfs::PoolFilesystem::over_read_only(core)
                } else {
                    scalefs_mount::poolfs::PoolFilesystem::over(core)
                };
                let workers = std::env::var("SCALEFS_FUSE_WORKERS")
                    .ok()
                    .and_then(|v| v.parse::<usize>().ok())
                    .filter(|&n| n >= 1)
                    .unwrap_or_else(|| {
                        std::thread::available_parallelism()
                            .map(|n| n.get().min(4))
                            .unwrap_or(1)
                    });
                let session_exit =
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        scalefs_mount::fuse::session::serve(&mount, &filesystem, workers)
                    })) {
                        Ok(Ok(())) => None,
                        Ok(Err(error)) => {
                            Some(format!("the mount session ended with an error: {error}"))
                        }
                        Err(_) => Some("the mount worker panicked".to_string()),
                    };
                if let Some(reason) = &session_exit {
                    eprintln!("scalefsd: the mount of '{worker_name}' ended — {reason}");
                }
                if let Err(errno) = filesystem.shutdown() {
                    eprintln!(
                        "scalefsd: the flush for the ending mount of '{worker_name}' \
                         failed (errno {errno}); the staged changes stay with the \
                         pool attachment for retry"
                    );
                }
                drop(filesystem);
                if let (Ok(pool), Ok(mut status)) =
                    (worker_entry.pool.read(), worker_entry.status.lock())
                {
                    *status = full_status(&worker_entry, &pool);
                }
                *worker_entry.last_mount_exit.lock().expect("mount exit") = session_exit;
                mount.unmount();
                park_ended(&worker_entry, generation);
            });
        match spawned {
            Ok(worker) => {
                let shown = mountpoint.to_string_lossy().into_owned();
                *slot = MountSlot::Mounted(
                    generation,
                    ActiveMount {
                        mountpoint,
                        read_only,
                        worker,
                        stop,
                    },
                );
                *entry.last_mount_exit.lock().expect("mount exit") = None;
                claim.disarm();
                drop(slot);
                Ok(object(vec![
                    ("mounted_at", Value::Str(shown)),
                    ("read_only", Value::Bool(read_only)),
                ]))
            }
            Err(error) => Err((
                ErrorCode::Internal,
                format!("could not start the mount worker: {error}"),
            )),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn unmount(&self, params: &Value) -> Result<Value, OpError> {
        let name = required_name(params)?;
        let force = force_flag(params)?;
        let entry = {
            let pools = self.pools.lock().expect("registry lock");
            pools.get(&name).map(Arc::clone)
        }
        .ok_or_else(|| {
            (
                ErrorCode::NotFound,
                format!("no pool is attached as '{name}'"),
            )
        })?;
        match Self::unmount_entry(&entry, force) {
            Ok(()) => {
                self.persist();
                Ok(Value::Null)
            }
            Err(UnmountRefusal::NotMounted) => {
                Err((ErrorCode::NotFound, format!("pool '{name}' is not mounted")))
            }
            Err(UnmountRefusal::InProgress) => Err((
                ErrorCode::Conflict,
                format!("pool '{name}' has a mount operation in progress"),
            )),
            Err(UnmountRefusal::Busy(mountpoint)) => Err((
                ErrorCode::Conflict,
                format!(
                    "pool '{name}' is mounted at {} and busy (files are open on it, \
                     or a working directory is inside it); close them, or unmount \
                     with force",
                    mountpoint.display(),
                ),
            )),
        }
    }

    #[cfg(target_os = "linux")]
    fn unmount_entry(entry: &Arc<Attached>, force: bool) -> Result<(), UnmountRefusal> {
        let (generation, state) = {
            let mut slot = entry.mounted.lock().expect("mount state");
            match &*slot {
                MountSlot::Empty => return Err(UnmountRefusal::NotMounted),
                MountSlot::Mounting(_) | MountSlot::Unmounting(_) | MountSlot::Draining(_) => {
                    return Err(UnmountRefusal::InProgress);
                }
                MountSlot::Ended(..) => {
                    let MountSlot::Ended(_, worker) =
                        std::mem::replace(&mut *slot, MountSlot::Empty)
                    else {
                        unreachable!()
                    };
                    drop(slot);
                    let _ = worker.join();
                    return Ok(());
                }
                MountSlot::Mounted(generation, _) => {
                    let generation = *generation;
                    let MountSlot::Mounted(_, state) =
                        std::mem::replace(&mut *slot, MountSlot::Unmounting(generation))
                    else {
                        unreachable!()
                    };
                    (generation, state)
                }
            }
        };
        let mut reopen = SlotReset {
            entry: Arc::clone(entry),
            generation,
            armed: true,
        };

        if force {
            reopen.disarm();
            drain_off_thread(entry, generation, state);
            return Ok(());
        }

        match scalefs_mount::fuse::device::unmount_mountpoint(&state.mountpoint) {
            Ok(()) => {
                let _ = state.worker.join();
                reopen.disarm();
                *entry.mounted.lock().expect("mount state") = MountSlot::Empty;
                Ok(())
            }
            Err(error) if scalefs_mount::fuse::device::is_busy(&error) => {
                let mountpoint = state.mountpoint.clone();
                reopen.disarm();
                *entry.mounted.lock().expect("mount state") = MountSlot::Mounted(generation, state);
                Err(UnmountRefusal::Busy(mountpoint))
            }
            Err(_) => {
                reopen.disarm();
                drain_off_thread(entry, generation, state);
                Ok(())
            }
        }
    }

    pub fn unmount_all(&self) {
        #[cfg(target_os = "linux")]
        {
            let entries: Vec<Arc<Attached>> = {
                let pools = self.pools.lock().expect("registry lock");
                pools.values().map(Arc::clone).collect()
            };
            let mut workers = Vec::new();
            for entry in &entries {
                let mut slot = entry.mounted.lock().expect("mount state");
                match std::mem::replace(&mut *slot, MountSlot::Empty) {
                    MountSlot::Mounted(_, state) => {
                        state.stop.store(true, Ordering::SeqCst);
                        let _ = scalefs_mount::fuse::device::detach_mountpoint(&state.mountpoint);
                        workers.push(state.worker);
                    }
                    MountSlot::Ended(_, worker) => workers.push(worker),
                    other => *slot = other,
                }
            }
            bounded_join_all(workers, SHUTDOWN_DRAIN_DEADLINE);
        }
    }

    pub fn device_list(&self) -> Result<Value, OpError> {
        let attached_paths: BTreeMap<String, String> = {
            let pools = self.pools.lock().expect("registry lock");
            pools
                .iter()
                .flat_map(|(name, entry)| {
                    let members = entry.members.lock().expect("member paths");
                    members
                        .iter()
                        .map(|path| (path.clone(), name.clone()))
                        .collect::<Vec<_>>()
                })
                .collect()
        };
        let rows: Vec<Value> = scalefs_core::list_devices()
            .into_iter()
            .map(|device| {
                let mut entries = vec![("path", Value::Str(device.path.clone()))];
                if let Some(size) = device.size {
                    entries.push(("size", Value::Int(i128::from(size))));
                }
                if let Some(model) = device.identity.model {
                    entries.push(("model", Value::Str(model)));
                }
                if let Some(serial) = device.identity.serial {
                    entries.push(("serial", Value::Str(serial)));
                }
                if device.actuators >= 2 {
                    entries.push(("actuators", Value::Int(device.actuators as i128)));
                }
                let kind = match &device.contents {
                    scalefs_core::Contents::Pool(_) => "pool",
                    scalefs_core::Contents::Partitioned => "partitioned",
                    scalefs_core::Contents::Blank => "blank",
                    scalefs_core::Contents::Foreign => "foreign",
                    scalefs_core::Contents::Unreadable => "unreadable",
                };
                entries.push(("contents", Value::Str(kind.to_string())));
                if let scalefs_core::Contents::Pool(probe) = &device.contents {
                    entries.push(("pool_id", Value::Str(hex(&probe.pool_id.0))));
                    entries.push(("label", Value::Str(probe.label.clone())));
                    entries.push(("device_id", Value::Str(hex(&probe.device_id.0))));
                    if probe.unknown_incompat {
                        entries.push(("unsupported", Value::Bool(true)));
                    }
                }
                if let Some(name) = attached_paths.get(&device.path) {
                    entries.push(("attached_as", Value::Str(name.clone())));
                }
                if let Some(error) = device.error {
                    entries.push(("error", Value::Str(error)));
                }
                object(entries)
            })
            .collect();
        Ok(object(vec![("devices", Value::Array(rows))]))
    }

    pub fn detach(&self, params: &Value) -> Result<Value, OpError> {
        let name = required_name(params)?;
        self.detach_named(&name, true)?;
        Ok(Value::Null)
    }

    pub fn detach_quiesce(&self, name: &str) -> Result<(), OpError> {
        self.detach_named(name, false)
    }

    fn detach_named(&self, name: &str, persist: bool) -> Result<(), OpError> {
        let entry = {
            let mut pools = self.pools.lock().expect("registry lock");
            let Some(entry) = pools.get(name) else {
                return Err((
                    ErrorCode::NotFound,
                    format!("no pool is attached as '{name}'"),
                ));
            };
            let job = entry.busy.load(Ordering::SeqCst);
            if job != 0 {
                return Err((
                    ErrorCode::Busy,
                    format!("pool '{name}' is busy with job {job}"),
                ));
            }
            #[cfg(target_os = "linux")]
            {
                let mut slot = entry.mounted.lock().expect("mount state");
                match &*slot {
                    MountSlot::Empty => {}
                    MountSlot::Ended(..) => {
                        let MountSlot::Ended(_, worker) =
                            std::mem::replace(&mut *slot, MountSlot::Empty)
                        else {
                            unreachable!()
                        };
                        let _ = worker.join();
                    }
                    MountSlot::Mounting(_) | MountSlot::Unmounting(_) | MountSlot::Draining(_) => {
                        return Err((
                            ErrorCode::Conflict,
                            format!(
                                "pool '{name}' has a mount operation in progress; \
                                 let it settle first"
                            ),
                        ));
                    }
                    MountSlot::Mounted(_, state) => {
                        return Err((
                            ErrorCode::Conflict,
                            format!(
                                "pool '{name}' is mounted at {}; unmount it first",
                                state.mountpoint.display(),
                            ),
                        ));
                    }
                }
            }
            let serving = entry.shares_served.load(Ordering::SeqCst);
            if serving != 0 {
                let plural = if serving == 1 { "share" } else { "shares" };
                return Err((
                    ErrorCode::Conflict,
                    format!("pool '{name}' is served by {serving} SMB {plural}; remove them first"),
                ));
            }
            pools.remove(name).expect("checked present")
        };
        if persist {
            self.persist();
        }
        if let Some(core) = entry.core.get()
            && let Err(error) = core.shutdown()
        {
            return Err((
                ErrorCode::Io,
                format!(
                    "pool '{name}' was detached, but its final commit failed \
                     ({error:?}); uncommitted changes were lost"
                ),
            ));
        }
        Ok(())
    }

    pub fn eject_prepare(
        &self,
        name: &str,
        preparer: Option<&GuardWitness>,
    ) -> scalefs_mount::dataplane::PrepareOutcome {
        use scalefs_mount::dataplane::{PrepareOutcome, PrepareVerdict};
        let (entry, already) = {
            let pools = self.pools.lock().expect("registry lock");
            let Some(entry) = pools.get(name) else {
                return PrepareOutcome::nak(PrepareVerdict::Unsupported);
            };
            let entry = Arc::clone(entry);
            let already = entry.eject_pending.load(Ordering::SeqCst);
            entry.eject_pending.store(true, Ordering::SeqCst);
            if entry.busy.load(Ordering::SeqCst) != 0 {
                if !already {
                    entry.eject_pending.store(false, Ordering::SeqCst);
                }
                return PrepareOutcome::nak(PrepareVerdict::NakBusyWithJob);
            }
            let served = entry.shares_served.load(Ordering::SeqCst);
            let own = usize::from(preparer.is_some_and(GuardWitness::held));
            let foreign_share = served.saturating_sub(own) > 0;
            #[cfg(target_os = "linux")]
            let foreign_mount = !matches!(
                &*entry.mounted.lock().expect("mount slot"),
                MountSlot::Empty
            );
            #[cfg(not(target_os = "linux"))]
            let foreign_mount = false;
            if foreign_share || foreign_mount {
                if !already {
                    entry.eject_pending.store(false, Ordering::SeqCst);
                }
                return PrepareOutcome::nak(PrepareVerdict::NakFenceHeld);
            }
            (entry, already)
        };
        if let Some(core) = entry.core.get()
            && let Err(error) = core.commit()
        {
            eprintln!(
                "scalefsd: eject prepare of '{name}' — the pool-wide FSYNC failed: {error:?}"
            );
            if !already {
                entry.eject_pending.store(false, Ordering::SeqCst);
            }
            return PrepareOutcome::nak(PrepareVerdict::NakFsyncFailed);
        }
        let (generation, needs_write) = {
            let mut state = entry.eject_state.lock().expect("eject state");
            match (*state, already) {
                (Some(standing), true) => (standing.generation, false),
                (None, true) => {
                    let generation = entry.next_eject_generation.fetch_add(1, Ordering::SeqCst) + 1;
                    eprintln!(
                        "scalefsd: eject prepare of '{name}' — a freeze was standing with no \
                         durable safe-removal state; recording prepared(generation {generation}) \
                         now"
                    );
                    *state = Some(crate::state::EjectState {
                        phase: crate::state::EjectPhase::Prepared,
                        generation,
                    });
                    (generation, true)
                }
                (Some(standing), false) => (standing.generation, false),
                (None, false) => {
                    let generation = entry.next_eject_generation.fetch_add(1, Ordering::SeqCst) + 1;
                    *state = Some(crate::state::EjectState {
                        phase: crate::state::EjectPhase::Prepared,
                        generation,
                    });
                    (generation, true)
                }
            }
        };
        if needs_write && let Err(error) = self.persist_checked() {
            eprintln!(
                "scalefsd: eject prepare of '{name}' — the safe-removal state could not be \
                 recorded ({error}); refusing the eject rather than granting one this daemon \
                 would forget"
            );
            *entry.eject_state.lock().expect("eject state") = None;
            if !already {
                entry.eject_pending.store(false, Ordering::SeqCst);
            }
            return PrepareOutcome::nak(PrepareVerdict::NakStateWriteFailed);
        }
        PrepareOutcome {
            verdict: PrepareVerdict::Ack,
            generation,
        }
    }

    pub fn eject_abort(&self, name: &str, generation: u64) {
        let cleared = {
            let pools = self.pools.lock().expect("registry lock");
            let Some(entry) = pools.get(name) else { return };
            if entry.commits_in_flight.load(Ordering::SeqCst) != 0 {
                eprintln!(
                    "scalefsd: eject abort of '{name}' (generation {generation}) IGNORED — a \
                     commit of the removal is being evaluated; its verdict settles the barrier"
                );
                return;
            }
            let mut state = entry.eject_state.lock().expect("eject state");
            let standing_now = *state;
            match standing_now {
                Some(standing) if standing.phase == crate::state::EjectPhase::Ejected => {
                    eprintln!(
                        "scalefsd: eject abort of '{name}' (generation {generation}) IGNORED — \
                         the removal already committed (generation {}); the freeze stands until \
                         the pool is detached and reattached",
                        standing.generation,
                    );
                    false
                }
                Some(standing) if generation != 0 && standing.generation != generation => {
                    eprintln!(
                        "scalefsd: eject abort of '{name}' names generation {generation} but \
                         generation {} is standing; ignoring the stale abort",
                        standing.generation,
                    );
                    false
                }
                _ => {
                    entry.eject_pending.store(false, Ordering::SeqCst);
                    state.take().is_some()
                }
            }
        };
        if cleared {
            self.persist();
        }
    }

    pub fn eject_commit(
        &self,
        name: &str,
        generation: u64,
        committer: Option<&GuardWitness>,
    ) -> scalefs_mount::dataplane::PrepareVerdict {
        match self.eject_commit_close(name, generation, committer) {
            Ok(commit) => self.eject_commit_record(commit, name, generation),
            Err(answered) => answered,
        }
    }

    fn eject_commit_close(
        &self,
        name: &str,
        generation: u64,
        committer: Option<&GuardWitness>,
    ) -> Result<CommitInFlight, scalefs_mount::dataplane::PrepareVerdict> {
        use scalefs_mount::dataplane::PrepareVerdict;
        let pools = self.pools.lock().expect("registry lock");
        let Some(entry) = pools.get(name) else {
            println!(
                "scalefsd: eject commit of '{name}' (generation {generation}) — the pool is \
                 already detached; the removal stands"
            );
            return Err(PrepareVerdict::Ack);
        };
        let commit = CommitInFlight::begin(Arc::clone(entry));
        let entry = &commit.entry;
        entry.eject_pending.store(true, Ordering::SeqCst);
        let job = entry.busy.load(Ordering::SeqCst);
        if job != 0 {
            eprintln!(
                "scalefsd: eject commit of '{name}' (generation {generation}) REFUSED — job \
                 {job} was started while the eject barrier was down; the volume is gone but \
                 the removal is NOT confirmed"
            );
            return Err(PrepareVerdict::NakBusyWithJob);
        }
        let served = entry.shares_served.load(Ordering::SeqCst);
        let own = usize::from(committer.is_some_and(GuardWitness::held));
        let foreign_shares = served.saturating_sub(own);
        #[cfg(target_os = "linux")]
        let foreign_mount = !matches!(
            &*entry.mounted.lock().expect("mount slot"),
            MountSlot::Empty
        );
        #[cfg(not(target_os = "linux"))]
        let foreign_mount = false;
        if foreign_shares != 0 || foreign_mount {
            eprintln!(
                "scalefsd: eject commit of '{name}' (generation {generation}) REFUSED — \
                 another surface ({foreign_shares} share guard(s){}) holds the pool, \
                 admitted while the eject barrier was down; the volume is gone but the \
                 removal is NOT confirmed",
                if foreign_mount {
                    ", a kernel mount"
                } else {
                    ""
                },
            );
            return Err(PrepareVerdict::NakFenceHeld);
        }
        Ok(commit)
    }

    fn eject_commit_record(
        &self,
        commit: CommitInFlight,
        name: &str,
        generation: u64,
    ) -> scalefs_mount::dataplane::PrepareVerdict {
        use scalefs_mount::dataplane::PrepareVerdict;
        let entry = &commit.entry;
        if let Some(core) = entry.core.get()
            && let Err(error) = core.commit()
        {
            eprintln!(
                "scalefsd: eject commit of '{name}' (generation {generation}) REFUSED — the \
                 pool-wide commit failed ({error:?}); the volume is gone but the removal is \
                 NOT confirmed"
            );
            return PrepareVerdict::NakFsyncFailed;
        }
        *entry.eject_state.lock().expect("eject state") = Some(crate::state::EjectState {
            phase: crate::state::EjectPhase::Ejected,
            generation,
        });
        if let Err(error) = self.persist_checked() {
            eprintln!(
                "scalefsd: eject commit of '{name}' (generation {generation}) — the safe-removal \
                 state could not be recorded ({error}); the dismount stands but the eject is \
                 reported FAILED so it is not mistaken for confirmed"
            );
            return PrepareVerdict::NakStateWriteFailed;
        }
        println!(
            "scalefsd: eject commit of '{name}' — safe removal recorded (generation \
             {generation}); the pool will not come back until it is reattached"
        );
        PrepareVerdict::Ack
    }

    pub fn share_handle(&self, name: &str) -> Result<PoolHandle, OpError> {
        let pools = self.pools.lock().expect("registry lock");
        let entry = pools.get(name).ok_or_else(|| {
            (
                ErrorCode::NotFound,
                format!("no pool is attached as '{name}'"),
            )
        })?;
        if entry.wrecked.load(Ordering::SeqCst) {
            return Err((
                ErrorCode::Internal,
                format!(
                    "pool '{name}' was fenced off by a crashed job; \
                     detach and import it again"
                ),
            ));
        }
        if entry.eject_pending.load(Ordering::SeqCst) {
            return Err((
                ErrorCode::Conflict,
                format!("pool '{name}' is being ejected; it cannot take a new surface"),
            ));
        }
        Ok(PoolHandle {
            pool: Arc::clone(&entry.pool),
            core: entry.core.get().cloned(),
            presentation: PoolPresentation::from_external(
                entry.presents_external.load(Ordering::SeqCst),
            ),
            guard: ShareGuard::claim(&entry.shares_served),
        })
    }

    pub fn list(&self) -> Result<Value, OpError> {
        let attached: Vec<Arc<Attached>> = {
            let pools = self.pools.lock().expect("registry lock");
            pools.values().map(Arc::clone).collect()
        };
        let summaries = attached.iter().map(|entry| entry.snapshot()).collect();
        Ok(object(vec![("pools", Value::Array(summaries))]))
    }

    pub fn status(&self, params: &Value) -> Result<Value, OpError> {
        let name = required_name(params)?;
        let entry = {
            let pools = self.pools.lock().expect("registry lock");
            pools.get(&name).map(Arc::clone)
        }
        .ok_or_else(|| {
            (
                ErrorCode::NotFound,
                format!("no pool is attached as '{name}'"),
            )
        })?;
        Ok(entry.snapshot())
    }

    pub fn eject_record(&self, params: &Value) -> Result<Value, OpError> {
        let pool_id = match params.get("pool_id").and_then(Value::as_str) {
            Some(id) if !id.is_empty() => id.to_string(),
            _ => return Err(bad("'pool_id' (a nonempty string) is required")()),
        };
        let reply = |attached: bool, eject: Option<crate::state::EjectState>, known: bool| {
            let (phase, generation) = match eject {
                Some(state) => (state.phase.word(), state.generation),
                None if known => ("none", 0),
                None => ("unknown", 0),
            };
            object(vec![
                ("pool_id", Value::Str(pool_id.to_ascii_lowercase())),
                ("attached", Value::Bool(attached)),
                ("phase", Value::Str(phase.to_string())),
                ("generation", Value::Int(i128::from(generation))),
            ])
        };
        let live = {
            let pools = self.pools.lock().expect("registry lock");
            pools
                .values()
                .find(|entry| entry.pool_id.eq_ignore_ascii_case(&pool_id))
                .map(|entry| *entry.eject_state.lock().expect("eject state"))
        };
        if let Some(eject) = live {
            return Ok(reply(true, eject, true));
        }
        let stored = match &self.state {
            Some(store) => store.load_suppressed().map_err(|error| -> OpError {
                (
                    ErrorCode::Io,
                    format!("cannot read the safe-removal records: {error}"),
                )
            })?,
            None => Vec::new(),
        };
        Ok(
            match stored
                .iter()
                .find(|tombstone| tombstone.pool_id.eq_ignore_ascii_case(&pool_id))
            {
                Some(tombstone) => reply(
                    false,
                    Some(tombstone.eject.unwrap_or(crate::state::EjectState {
                        phase: crate::state::EjectPhase::Prepared,
                        generation: 0,
                    })),
                    true,
                ),
                None => reply(false, None, false),
            },
        )
    }

    pub fn scrub(&self, params: &Value) -> Result<Value, OpError> {
        let repair = match params.get("repair") {
            None => false,
            Some(Value::Bool(flag)) => *flag,
            Some(_) => return Err(bad("repair must be a boolean")()),
        };
        self.start_online_job(params, "scrub", move |entry| {
            let report = scrub_in_steps(entry, repair)?;
            Ok(object(vec![
                ("healthy", Value::Bool(report.healthy())),
                (
                    "records_checked",
                    Value::Int(i128::from(report.records_checked)),
                ),
                (
                    "copies_checked",
                    Value::Int(i128::from(report.copies_checked)),
                ),
                ("copies_bad", Value::Int(i128::from(report.copies_bad))),
                (
                    "copies_repaired",
                    Value::Int(i128::from(report.copies_repaired)),
                ),
                (
                    "copies_unrepairable",
                    Value::Int(i128::from(report.copies_unrepairable)),
                ),
                (
                    "copies_missing",
                    Value::Int(i128::from(report.copies_missing)),
                ),
                ("copies_stale", Value::Int(i128::from(report.copies_stale))),
            ]))
        })
    }

    pub fn reclaim(&self, params: &Value) -> Result<Value, OpError> {
        self.start_job(params, "reclaim", |pool, _entry| {
            let report = pool.reclaim(now_ns())?;
            Ok(object(vec![
                (
                    "stripes_reset",
                    Value::Int(i128::from(report.stripes_reset)),
                ),
                ("zones_reset", Value::Int(i128::from(report.zones_reset))),
                (
                    "bytes_reclaimed",
                    Value::Int(i128::from(report.bytes_reclaimed)),
                ),
            ]))
        })
    }

    pub fn rebuild(&self, params: &Value) -> Result<Value, OpError> {
        self.start_job(params, "rebuild", |pool, _entry| {
            let report = pool.rebuild(now_ns())?;
            Ok(object(vec![
                (
                    "records_rebuilt",
                    Value::Int(i128::from(report.records_rebuilt)),
                ),
                (
                    "copies_written",
                    Value::Int(i128::from(report.copies_written)),
                ),
                (
                    "snapshots_rewritten",
                    Value::Int(i128::from(report.snapshots_rewritten)),
                ),
                ("tx", Value::Int(i128::from(report.tx_id))),
            ]))
        })
    }

    pub fn replace(&self, params: &Value) -> Result<Value, OpError> {
        let target = target_param(params)?;
        let member = member_param(params)?;
        let spec = member_geometry_params(params)?;
        self.admit_target(params, &target)?;
        let identity = TargetIdentity::probe(&target);
        let persist = (Arc::clone(&self.pools), self.state.clone());
        self.start_job(params, "replace", move |pool, entry| {
            let missing = pool.missing_members();
            let member = match member {
                Some(selector) => resolve_member(pool, &selector)?,
                None => *missing.first().ok_or(ScaleFsError::InvalidArgument(
                    "no members are missing; name a member or grow with pool.add",
                ))?,
            };
            if !missing.contains(&member) {
                return Err(ScaleFsError::InvalidArgument(
                    "that member is present; pool.replace serves missing members",
                ));
            }
            let (device, geometry) = open_target(&target, &spec)?;
            let device_id = fresh_device_id()?;
            pool.replace_member(
                member,
                MemberSpec {
                    device: Arc::new(device),
                    device_id,
                    geometry,
                },
                now_ns(),
            )?;
            entry.adopt_member_path(&target, &identity, device_id);
            let _ = persist_pools(&persist.0, &persist.1);
            let mut result = vec![
                ("replaced", Value::Int(i128::from(member))),
                ("target", Value::Str(target.clone())),
            ];
            if pool.is_degraded() {
                result.push((
                    "still_missing",
                    Value::Array(
                        pool.missing_members()
                            .iter()
                            .map(|index| Value::Int(i128::from(*index)))
                            .collect(),
                    ),
                ));
                result.push(("rebuilt", Value::Bool(false)));
            } else {
                let report = pool.rebuild(now_ns())?;
                result.push(("rebuilt", Value::Bool(true)));
                result.push((
                    "records_rebuilt",
                    Value::Int(i128::from(report.records_rebuilt)),
                ));
                result.push((
                    "copies_written",
                    Value::Int(i128::from(report.copies_written)),
                ));
                result.push((
                    "snapshots_rewritten",
                    Value::Int(i128::from(report.snapshots_rewritten)),
                ));
                result.push(("tx", Value::Int(i128::from(report.tx_id))));
            }
            Ok(object(result))
        })
    }

    pub fn add(&self, params: &Value) -> Result<Value, OpError> {
        let target = target_param(params)?;
        let spec = member_geometry_params(params)?;
        self.admit_target(params, &target)?;
        let identity = TargetIdentity::probe(&target);
        let persist = (Arc::clone(&self.pools), self.state.clone());
        self.start_job(params, "add", move |pool, entry| {
            let (device, geometry) = open_target(&target, &spec)?;
            let device_id = fresh_device_id()?;
            let capacity = geometry.capacity_bytes();
            let member = pool.add_member(
                MemberSpec {
                    device: Arc::new(device),
                    device_id,
                    geometry,
                },
                now_ns(),
            )?;
            entry.adopt_member_path(&target, &identity, device_id);
            let _ = persist_pools(&persist.0, &persist.1);
            Ok(object(vec![
                ("member", Value::Int(i128::from(member))),
                ("target", Value::Str(target.clone())),
                ("capacity", Value::Int(i128::from(capacity))),
                ("members", Value::Int(pool.member_count() as i128)),
            ]))
        })
    }

    pub fn remove(&self, params: &Value) -> Result<Value, OpError> {
        let member = member_param(params)?.ok_or_else(bad(
            "params need a member (an index, or a device id in hex)",
        ))?;
        let persist = (Arc::clone(&self.pools), self.state.clone());
        self.start_job(params, "remove", move |pool, entry| {
            let member = resolve_member(pool, &member)?;
            let device_id = member_device_id(pool, member);
            let removed = pool.remove_member(member, now_ns())?;
            drop(removed);
            if let Some(id) = &device_id {
                entry.drop_member_path(id);
            }
            let _ = persist_pools(&persist.0, &persist.1);
            let mut result = vec![
                ("removed", Value::Int(i128::from(member))),
                ("members", Value::Int(pool.member_count() as i128)),
            ];
            if let Some(id) = device_id {
                result.push(("device_id", Value::Str(id)));
            }
            Ok(object(result))
        })
    }

    pub fn retire(&self, params: &Value) -> Result<Value, OpError> {
        let member = member_param(params)?.ok_or_else(bad(
            "params need a member (an index, or a device id in hex)",
        ))?;
        let persist = (Arc::clone(&self.pools), self.state.clone());
        self.start_job(params, "retire", move |pool, entry| {
            let member = resolve_member(pool, &member)?;
            let device_id = member_device_id(pool, member);
            let report = pool.retire_member(member, now_ns())?;
            if let Some(id) = &device_id {
                entry.drop_member_path(id);
            }
            let _ = persist_pools(&persist.0, &persist.1);
            let mut result = vec![
                ("retired", Value::Int(i128::from(member))),
                (
                    "records_rebuilt",
                    Value::Int(report.records_rebuilt as i128),
                ),
                ("copies_written", Value::Int(report.copies_written as i128)),
                (
                    "snapshots_rewritten",
                    Value::Int(report.snapshots_rewritten as i128),
                ),
                ("tx", Value::Int(report.tx_id as i128)),
                ("members", Value::Int(pool.member_count() as i128)),
            ];
            if let Some(id) = device_id {
                result.push(("device_id", Value::Str(id)));
            }
            Ok(object(result))
        })
    }

    fn admit_target(&self, params: &Value, target: &str) -> Result<(), OpError> {
        let force = force_flag(params)?;
        {
            let candidates = [target.to_string()];
            let pools = self.pools.lock().expect("registry lock");
            for entry in pools.values() {
                if entry.holds_any_of(&candidates).is_some() {
                    return Err((
                        ErrorCode::Conflict,
                        format!(
                            "{target} already belongs to the attachment '{}'",
                            entry.name
                        ),
                    ));
                }
            }
            if !force
                && let Ok(name) = required_name(params)
                && let Some(entry) = pools.get(&name)
            {
                let members = entry.members.lock().expect("member paths").clone();
                for member in &members {
                    if scalefs_core::same_spindle(Path::new(target), Path::new(member)) {
                        return Err((
                            ErrorCode::Conflict,
                            format!(
                                "{target} lives on the same physical disk as member \
                                 {member}: one spindle is one failure domain (the engine \
                                 already uses both actuators of a dual-actuator drive \
                                 within one member; force if you really mean it)"
                            ),
                        ));
                    }
                }
            }
        }
        refuse_accidental_overwrite(target, force)
    }

    pub fn job_status(&self, params: &Value) -> Result<Value, OpError> {
        let id = params
            .get("id")
            .and_then(Value::as_u64)
            .ok_or_else(bad("params need an integer job id"))?;
        let job = {
            let jobs = self.jobs.lock().expect("jobs lock");
            jobs.get(&id).map(Arc::clone)
        }
        .ok_or((ErrorCode::NotFound, format!("no job {id}")))?;
        Ok(job.describe())
    }

    pub fn job_list(&self) -> Result<Value, OpError> {
        const LISTED: usize = 1000;
        let jobs: Vec<Arc<Job>> = {
            let jobs = self.jobs.lock().expect("jobs lock");
            jobs.values().rev().take(LISTED).map(Arc::clone).collect()
        };
        Ok(object(vec![(
            "jobs",
            Value::Array(jobs.iter().rev().map(|job| job.describe()).collect()),
        )]))
    }

    fn start_job(
        &self,
        params: &Value,
        kind: &'static str,
        work: impl FnOnce(&mut Pool<ServedDevice>, &Attached) -> scalefs_core::Result<Value>
        + Send
        + 'static,
    ) -> Result<Value, OpError> {
        let (id, job, entry) = self.claim_job(params, kind)?;

        let worker_job = Arc::clone(&job);
        let worker_entry = Arc::clone(&entry);
        let spawned = std::thread::Builder::new()
            .name(format!("scalefsd-job-{id}"))
            .spawn(move || {
                let entry = worker_entry;
                let _settle = JobSettle {
                    job: Arc::clone(&worker_job),
                    entry: Arc::clone(&entry),
                };
                let outcome = {
                    let _hold = entry.core.get().map(|core| core.maintenance_hold());
                    let Ok(mut pool) = entry.pool.write() else {
                        *worker_job.state.lock().expect("job state") = JobState::Failed(
                            ErrorCode::Internal,
                            "the pool's state was damaged earlier; \
                             detach and import it again"
                                .to_string(),
                        );
                        return;
                    };
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                        || -> scalefs_core::Result<(Value, bool)> {
                            let result = work(&mut pool, &entry)?;
                            *entry.status.lock().expect("status cache") =
                                full_status(&entry, &pool);
                            let healed_writable = entry.core.get().is_none() && !pool.read_only();
                            Ok((result, healed_writable))
                        },
                    ));
                    if outcome.is_err() {
                        if let Some(core) = entry.core.get() {
                            core.poison();
                        }
                        entry.wrecked.store(true, Ordering::SeqCst);
                    }
                    outcome
                };
                let (outcome, healed_writable) = match outcome {
                    Ok(Ok((result, healed))) => (Ok(Ok(result)), healed),
                    Ok(Err(error)) => (Ok(Err(error)), false),
                    Err(panic) => (Err(panic), false),
                };
                if healed_writable {
                    entry.restore_core();
                }
                *worker_job.state.lock().expect("job state") = match outcome {
                    Ok(Ok(result)) => JobState::Done(result),
                    Ok(Err(error)) => {
                        let (code, message) = code_for(&error);
                        JobState::Failed(code, message)
                    }
                    Err(_) => JobState::Failed(
                        ErrorCode::Internal,
                        "the job crashed; the pool is fenced off — \
                         detach and import it again"
                            .to_string(),
                    ),
                };
            });
        if spawned.is_err() {
            *job.state.lock().expect("job state") = JobState::Failed(
                ErrorCode::Internal,
                "could not start a worker thread".to_string(),
            );
            entry.busy.store(0, Ordering::SeqCst);
            return Err((
                ErrorCode::Internal,
                "could not start a worker thread".to_string(),
            ));
        }
        Ok(object(vec![("job", Value::Int(i128::from(id)))]))
    }

    fn claim_job(
        &self,
        params: &Value,
        kind: &'static str,
    ) -> Result<(u64, Arc<Job>, Arc<Attached>), OpError> {
        let name = required_name(params)?;
        let id = self.next_job.fetch_add(1, Ordering::SeqCst) + 1;
        let job = Arc::new(Job {
            id,
            kind,
            pool_name: name.clone(),
            state: Mutex::new(JobState::Running),
        });

        let entry = {
            let pools = self.pools.lock().expect("registry lock");
            let entry = pools.get(&name).map(Arc::clone).ok_or_else(|| {
                (
                    ErrorCode::NotFound,
                    format!("no pool is attached as '{name}'"),
                )
            })?;
            if entry.wrecked.load(Ordering::SeqCst) {
                return Err((
                    ErrorCode::Internal,
                    format!(
                        "pool '{name}' was fenced off by a crashed job; \
                         detach and import it again"
                    ),
                ));
            }
            if entry.eject_pending.load(Ordering::SeqCst) {
                return Err((
                    ErrorCode::Conflict,
                    format!("pool '{name}' is being ejected; no new job can start"),
                ));
            }
            if let Err(owner) =
                entry
                    .busy
                    .compare_exchange(0, id, Ordering::SeqCst, Ordering::SeqCst)
            {
                return Err((
                    ErrorCode::Busy,
                    format!("pool '{name}' is busy with job {owner}"),
                ));
            }
            self.jobs
                .lock()
                .expect("jobs lock")
                .insert(id, Arc::clone(&job));
            entry
        };
        Ok((id, job, entry))
    }

    fn start_online_job(
        &self,
        params: &Value,
        kind: &'static str,
        work: impl FnOnce(&Attached) -> Result<Value, OpError> + Send + 'static,
    ) -> Result<Value, OpError> {
        let (id, job, entry) = self.claim_job(params, kind)?;
        let worker_job = Arc::clone(&job);
        let spawned = std::thread::Builder::new()
            .name(format!("scalefsd-job-{id}"))
            .spawn(move || {
                let _settle = JobSettle {
                    job: Arc::clone(&worker_job),
                    entry: Arc::clone(&entry),
                };
                let outcome = work(&entry);
                if outcome.is_ok()
                    && let (Ok(pool), Ok(mut status)) = (entry.pool.read(), entry.status.lock())
                {
                    *status = full_status(&entry, &pool);
                }
                *worker_job.state.lock().expect("job state") = match outcome {
                    Ok(result) => JobState::Done(result),
                    Err((code, message)) => JobState::Failed(code, message),
                };
            });
        if spawned.is_err() {
            *job.state.lock().expect("job state") = JobState::Failed(
                ErrorCode::Internal,
                "could not start a worker thread".to_string(),
            );
            if let Some(entry) = self
                .pools
                .lock()
                .expect("registry lock")
                .get(&job.pool_name)
            {
                entry.busy.store(0, Ordering::SeqCst);
            }
            return Err((
                ErrorCode::Internal,
                "could not start a worker thread".to_string(),
            ));
        }
        Ok(object(vec![("job", Value::Int(i128::from(id)))]))
    }

    pub fn running_job(&self) -> Option<(u64, String)> {
        let pools = self.pools.lock().expect("registry lock");
        pools
            .values()
            .find_map(|entry| match entry.busy.load(Ordering::SeqCst) {
                0 => None,
                id => Some((id, entry.name.clone())),
            })
    }
}

impl Attached {
    fn holds_any_of(&self, candidates: &[String]) -> Option<String> {
        let members = self.members.lock().expect("member paths");
        members
            .iter()
            .find(|path| paths_overlap(path, candidates))
            .cloned()
    }

    fn adopt_member_path(
        &self,
        path: &str,
        identity: &TargetIdentity,
        device_id: scalefs_core::DeviceId,
    ) {
        self.members
            .lock()
            .expect("member paths")
            .push(path.to_string());
        self.media
            .lock()
            .expect("media rows")
            .push(identity.media_row(path, device_id));
    }

    fn drop_member_path(&self, device_id: &str) {
        let mut media = self.media.lock().expect("media rows");
        let Some(at) = media
            .iter()
            .position(|row| row.get("device_id").and_then(Value::as_str) == Some(device_id))
        else {
            return;
        };
        let row = media.remove(at);
        if let Some(path) = row.get("path").and_then(Value::as_str) {
            let mut members = self.members.lock().expect("member paths");
            if let Some(at) = members.iter().position(|held| held == path) {
                members.remove(at);
            }
        }
    }

    fn restore_core(&self) {
        let core: PoolCore = Arc::new(MountCore::read_write(Arc::clone(&self.pool)));
        if let Err(extra) = self.core.set(core) {
            let _ = extra.shutdown();
        }
    }

    fn snapshot(&self) -> Value {
        let mut status = self.status.lock().expect("status cache").clone();
        if let Value::Object(entries) = &mut status {
            let busy = self.busy.load(Ordering::SeqCst);
            if busy != 0 {
                entries.push(("busy_with_job".to_string(), Value::Int(i128::from(busy))));
            }
            if self.wrecked.load(std::sync::atomic::Ordering::SeqCst) {
                entries.push(("wrecked".to_string(), Value::Bool(true)));
            }
            if let Ok(pool) = self.pool.try_read()
                && pool.wounded()
            {
                match entries.iter_mut().find(|(key, _)| key == "wounded") {
                    Some((_, value)) => *value = Value::Bool(true),
                    None => entries.push(("wounded".to_string(), Value::Bool(true))),
                }
            }
            #[cfg(target_os = "linux")]
            if let MountSlot::Mounted(_, state) = &*self.mounted.lock().expect("mount state") {
                entries.push((
                    "mounted_at".to_string(),
                    Value::Str(state.mountpoint.to_string_lossy().into_owned()),
                ));
                if state.read_only {
                    entries.push(("mounted_read_only".to_string(), Value::Bool(true)));
                }
            }
            #[cfg(target_os = "linux")]
            if let Some(reason) = &*self.last_mount_exit.lock().expect("mount exit") {
                entries.push(("last_mount_exit".to_string(), Value::Str(reason.clone())));
            }
        }
        status
    }
}

impl Job {
    fn describe(&self) -> Value {
        let mut entries = vec![
            ("id", Value::Int(i128::from(self.id))),
            ("kind", Value::Str(self.kind.to_string())),
            ("pool", Value::Str(self.pool_name.clone())),
        ];
        match &*self.state.lock().expect("job state") {
            JobState::Running => entries.push(("state", Value::Str("running".into()))),
            JobState::Done(result) => {
                entries.push(("state", Value::Str("done".into())));
                entries.push(("result", result.clone()));
            }
            JobState::Failed(code, message) => {
                entries.push(("state", Value::Str("failed".into())));
                entries.push((
                    "error",
                    Value::Str(format!("{message} ({})", code.as_str())),
                ));
            }
        }
        object(entries)
    }
}

fn full_status(entry: &Attached, pool: &Pool<ServedDevice>) -> Value {
    let superblock = pool.superblock();
    let capacity: u64 = pool
        .allocators()
        .iter()
        .map(|allocator| allocator.geometry().capacity_bytes())
        .sum();
    let used: u64 = pool
        .allocators()
        .iter()
        .map(|allocator| {
            allocator
                .zones()
                .map(|zone| zone.write_pointer)
                .sum::<u64>()
        })
        .sum();
    let missing = pool.missing_members();
    let member_rows = match pool.member_rosters() {
        Ok(rosters) => match rosters.first() {
            Some(roster) => roster
                .members
                .iter()
                .enumerate()
                .map(|(index, member)| {
                    let state = match member.state {
                        scalefs_core::MemberState::Active if missing.contains(&(index as u16)) => {
                            "missing"
                        }
                        scalefs_core::MemberState::Active => "active",
                        scalefs_core::MemberState::Removed => "removed",
                    };
                    object(vec![
                        ("index", Value::Int(index as i128)),
                        ("device_id", Value::Str(hex(&member.device_id.0))),
                        ("state", Value::Str(state.to_string())),
                    ])
                })
                .collect(),
            None => vec![object(vec![
                ("index", Value::Int(0)),
                ("device_id", Value::Str(hex(&superblock.device_id.0))),
                ("state", Value::Str("active".to_string())),
            ])],
        },
        Err(_) => Vec::new(),
    };
    let orphans: Vec<Value> = pool
        .orphaned_members()
        .iter()
        .map(|id| Value::Str(hex(&id.0)))
        .collect();
    let presents_external = media_presents_external(&entry.media.lock().expect("media rows"));
    entry
        .presents_external
        .store(presents_external, Ordering::SeqCst);
    object(vec![
        ("name", Value::Str(entry.name.clone())),
        ("label", Value::Str(superblock.label.clone())),
        ("pool_id", Value::Str(hex(&superblock.pool_id.0))),
        ("tx", Value::Int(i128::from(pool.committed_tx()))),
        ("mirror", Value::Int(i128::from(pool.mirror_width()))),
        ("data", Value::Int(i128::from(pool.data_width()))),
        ("parity", Value::Int(i128::from(pool.parity_width()))),
        (
            "naming",
            object(vec![
                (
                    "case_sensitivity",
                    Value::Str(
                        match superblock.case_sensitivity {
                            scalefs_core::CaseSensitivity::Sensitive => "sensitive",
                            scalefs_core::CaseSensitivity::InsensitivePreserving => {
                                "insensitive_preserving"
                            }
                        }
                        .to_string(),
                    ),
                ),
                (
                    "unicode_version",
                    Value::Str(superblock.unicode_version.to_string()),
                ),
            ]),
        ),
        ("members", Value::Int(pool.member_count() as i128)),
        (
            "images",
            Value::Array(
                entry
                    .members
                    .lock()
                    .expect("member paths")
                    .iter()
                    .map(|path| Value::Str(path.clone()))
                    .collect(),
            ),
        ),
        (
            "media",
            Value::Array(entry.media.lock().expect("media rows").clone()),
        ),
        (
            "attachment",
            Value::Str(
                PoolPresentation::from_external(presents_external)
                    .word()
                    .to_string(),
            ),
        ),
        ("capacity", Value::Int(i128::from(capacity))),
        ("used", Value::Int(i128::from(used))),
        ("read_only", Value::Bool(pool.read_only())),
        ("wounded", Value::Bool(pool.wounded())),
        ("degraded", Value::Bool(pool.is_degraded())),
        (
            "degraded_live",
            match pool.live_degrade() {
                Some(degrade) => object(vec![
                    ("member", Value::Int(i128::from(degrade.member))),
                    ("device_id", Value::Str(hex(&degrade.device_id.0))),
                    ("tx", Value::Int(i128::from(degrade.tx_id))),
                ]),
                None => Value::Null,
            },
        ),
        (
            "missing",
            Value::Array(
                missing
                    .iter()
                    .map(|index| Value::Int(i128::from(*index)))
                    .collect(),
            ),
        ),
        ("members_detail", Value::Array(member_rows)),
        ("orphans", Value::Array(orphans)),
    ])
}

fn probe_medium(path: &str) -> Value {
    let probed = scalefs_core::probe_path(Path::new(path));
    let mut entries = vec![("path", Value::Str(path.to_string()))];
    if let Some(serial) = probed.identity.serial {
        entries.push(("serial", Value::Str(serial)));
    }
    if let Some(model) = probed.identity.model {
        entries.push(("model", Value::Str(model)));
    }
    if let scalefs_core::Contents::Pool(probe) = &probed.contents {
        entries.push(("device_id", Value::Str(hex(&probe.device_id.0))));
    }
    entries.push((
        "attachment",
        Value::Str(attachment_word(scalefs_core::attachment_of_path(Path::new(path))).to_string()),
    ));
    object(entries)
}

fn attachment_word(attachment: scalefs_core::DeviceAttachment) -> &'static str {
    match attachment {
        scalefs_core::DeviceAttachment::External => "external",
        scalefs_core::DeviceAttachment::Internal => "internal",
        scalefs_core::DeviceAttachment::Unknown => "unknown",
    }
}

fn media_presents_external(media: &[Value]) -> bool {
    !media
        .iter()
        .any(|row| row.get("attachment").and_then(Value::as_str) == Some("internal"))
}

struct TargetIdentity {
    serial: Option<String>,
    model: Option<String>,
    attachment: scalefs_core::DeviceAttachment,
}

impl TargetIdentity {
    fn probe(path: &str) -> TargetIdentity {
        let probed = scalefs_core::probe_path(Path::new(path));
        TargetIdentity {
            serial: probed.identity.serial,
            model: probed.identity.model,
            attachment: scalefs_core::attachment_of_path(Path::new(path)),
        }
    }

    fn media_row(&self, path: &str, device_id: scalefs_core::DeviceId) -> Value {
        let mut entries = vec![("path", Value::Str(path.to_string()))];
        if let Some(serial) = &self.serial {
            entries.push(("serial", Value::Str(serial.clone())));
        }
        if let Some(model) = &self.model {
            entries.push(("model", Value::Str(model.clone())));
        }
        entries.push(("device_id", Value::Str(hex(&device_id.0))));
        entries.push((
            "attachment",
            Value::Str(attachment_word(self.attachment).to_string()),
        ));
        object(entries)
    }
}

enum MemberSelector {
    Index(u16),
    DeviceId(String),
}

fn member_param(params: &Value) -> Result<Option<MemberSelector>, OpError> {
    match params.get("member") {
        None => Ok(None),
        Some(Value::Int(_)) => {
            let index = params
                .get("member")
                .and_then(Value::as_u64)
                .and_then(|index| u16::try_from(index).ok())
                .ok_or_else(bad("member index must be a small non-negative integer"))?;
            Ok(Some(MemberSelector::Index(index)))
        }
        Some(Value::Str(id)) if !id.is_empty() && id.chars().all(|c| c.is_ascii_hexdigit()) => {
            Ok(Some(MemberSelector::DeviceId(id.to_ascii_lowercase())))
        }
        Some(_) => Err(bad("member must be an index or a device id in hex")()),
    }
}

fn target_param(params: &Value) -> Result<String, OpError> {
    match params.get("target").and_then(Value::as_str) {
        Some(path) if !path.is_empty() => Ok(path.to_string()),
        _ => Err(bad("params need a target path")()),
    }
}

fn force_flag(params: &Value) -> Result<bool, OpError> {
    match params.get("force") {
        None => Ok(false),
        Some(Value::Bool(flag)) => Ok(*flag),
        Some(_) => Err(bad("force must be a boolean")()),
    }
}

struct GeometrySpec {
    size: Option<u64>,
    zone_size: Option<u64>,
    block_size: Option<u32>,
}

fn member_geometry_params(params: &Value) -> Result<GeometrySpec, OpError> {
    let positive = |key: &str| -> Result<Option<u64>, OpError> {
        match params.get(key) {
            None => Ok(None),
            Some(value) => value.as_u64().filter(|&n| n > 0).map(Some).ok_or_else(|| {
                (
                    ErrorCode::BadRequest,
                    format!("{key} must be a positive integer"),
                )
            }),
        }
    };
    Ok(GeometrySpec {
        size: positive("size")?,
        zone_size: positive("zone_size")?,
        block_size: match positive("block_size")? {
            None => None,
            Some(block) => Some(
                u32::try_from(block)
                    .map_err(|_| (ErrorCode::BadRequest, "block_size too large".to_string()))?,
            ),
        },
    })
}

fn resolve_member(
    pool: &Pool<ServedDevice>,
    selector: &MemberSelector,
) -> scalefs_core::Result<u16> {
    match selector {
        MemberSelector::Index(index) => {
            if usize::from(*index) >= pool.member_count() {
                return Err(ScaleFsError::InvalidArgument("no member has that index"));
            }
            Ok(*index)
        }
        MemberSelector::DeviceId(wanted) => {
            if let Some(roster) = pool.member_rosters()?.first() {
                for (index, member) in roster.members.iter().enumerate() {
                    if hex(&member.device_id.0) == *wanted {
                        return Ok(index as u16);
                    }
                }
            } else if hex(&pool.superblock().device_id.0) == *wanted {
                return Ok(0);
            }
            Err(ScaleFsError::InvalidArgument(
                "no member has that device id",
            ))
        }
    }
}

fn member_device_id(pool: &Pool<ServedDevice>, member: u16) -> Option<String> {
    match pool.member_rosters() {
        Ok(rosters) => match rosters.first() {
            Some(roster) => roster
                .members
                .get(usize::from(member))
                .map(|entry| hex(&entry.device_id.0)),
            None if member == 0 => Some(hex(&pool.superblock().device_id.0)),
            None => None,
        },
        Err(_) => None,
    }
}

fn fresh_device_id() -> scalefs_core::Result<scalefs_core::DeviceId> {
    match crate::shares::try_random_bytes::<16>() {
        Some(bytes) => Ok(scalefs_core::DeviceId(bytes)),
        None => Err(ScaleFsError::Io(std::io::Error::other(
            "no OS entropy source for a device id",
        ))),
    }
}

fn default_zone_size(size: u64) -> u64 {
    let target = (size / 64).max(1);
    let zone = 1u64 << (63 - target.leading_zeros());
    zone.clamp(64 << 10, 256 << 20)
}

fn member_geometry(size: u64, spec: &GeometrySpec, block: u32) -> scalefs_core::Result<Geometry> {
    let zone_size = spec.zone_size.unwrap_or_else(|| default_zone_size(size));
    let zone_count = size / zone_size;
    if zone_count < 3 {
        return Err(ScaleFsError::InvalidArgument(
            "the size gives fewer than three zones; raise size or lower zone_size",
        ));
    }
    Ok(Geometry {
        logical_block_size: block,
        physical_block_size: block,
        zone_size,
        zone_count,
        erase_granularity_zones: 1,
        sequential_write_required: false,
    })
}

fn open_target(
    target: &str,
    spec: &GeometrySpec,
) -> scalefs_core::Result<(AnyBlockDevice, Geometry)> {
    let block = spec.block_size.unwrap_or(4096);
    if scalefs_core::is_device_path(Path::new(target)) {
        let device = scalefs_core::RawBlockDevice::open(Path::new(target))?;
        let size = spec.size.unwrap_or_else(|| device.len());
        if device.len() < size {
            return Err(ScaleFsError::InvalidArgument(
                "the device is smaller than the requested size",
            ));
        }
        if block < device.sector_size() {
            return Err(ScaleFsError::InvalidArgument(
                "block_size is smaller than the device's sectors",
            ));
        }
        let usable = scalefs_core::usable_len(size, device.sector_size());
        let geometry = member_geometry(usable, spec, block)?;
        Ok((AnyBlockDevice::Raw(device), geometry))
    } else {
        let size = spec.size.ok_or(ScaleFsError::InvalidArgument(
            "size is required to create an image member",
        ))?;
        let geometry = member_geometry(scalefs_core::usable_len(size, 512), spec, block)?;
        let device = scalefs_core::FileBlockDevice::create(
            Path::new(target),
            scalefs_core::member_image_len(geometry.capacity_bytes()),
        )?;
        Ok((AnyBlockDevice::File(device), geometry))
    }
}

fn refuse_accidental_overwrite(path: &str, force: bool) -> Result<(), OpError> {
    if force {
        return Ok(());
    }
    if !scalefs_core::is_device_path(Path::new(path)) {
        if Path::new(path).exists() {
            return Err((
                ErrorCode::Conflict,
                format!("{path} already exists (pass force to overwrite it)"),
            ));
        }
        return Ok(());
    }
    let probed = scalefs_core::probe_path(Path::new(path));
    let holds = match probed.contents {
        scalefs_core::Contents::Blank => return Ok(()),
        scalefs_core::Contents::Unreadable => format!(
            "contents that could not be read ({})",
            probed
                .error
                .unwrap_or_else(|| "no detail from the probe".to_string())
        ),
        scalefs_core::Contents::Pool(probe) => format!(
            "a ScaleFS pool ('{}', {})",
            probe.label,
            hex(&probe.pool_id.0)
        ),
        scalefs_core::Contents::Partitioned => "a partition table".to_string(),
        scalefs_core::Contents::Foreign => probed
            .error
            .unwrap_or_else(|| "unrecognized data".to_string()),
    };
    Err((
        ErrorCode::Conflict,
        format!("{path} holds {holds}; pass force to overwrite it"),
    ))
}

fn paths_overlap(held: &str, candidates: &[String]) -> bool {
    let held_canonical = std::fs::canonicalize(held).ok();
    candidates.iter().any(|candidate| {
        if candidate == held {
            return true;
        }
        match (&held_canonical, std::fs::canonicalize(candidate).ok()) {
            (Some(a), Some(b)) => *a == b,
            _ => false,
        }
    })
}

fn degraded_flag(params: &Value) -> Result<bool, OpError> {
    match params.get("degraded") {
        None => Ok(false),
        Some(Value::Bool(flag)) => Ok(*flag),
        Some(_) => Err(bad("degraded must be a boolean")()),
    }
}

fn required_name(params: &Value) -> Result<String, OpError> {
    match params.get("name").and_then(Value::as_str) {
        Some(name) if valid_name(name) => Ok(name.to_string()),
        Some(_) => Err(bad("name must be 1-64 bytes with no control characters")()),
        None => Err(bad("params need a string name")()),
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && name.chars().all(|c| !c.is_control())
}

fn bad(message: &'static str) -> impl Fn() -> OpError {
    move || (ErrorCode::BadRequest, message.to_string())
}

fn annotate(path: &str, error: ScaleFsError) -> OpError {
    let (code, text) = code_for(&error);
    (code, format!("{path}: {text}"))
}

fn map_error(error: ScaleFsError) -> OpError {
    let (code, text) = code_for(&error);
    (code, text)
}

const SCRUB_STEP: std::time::Duration = std::time::Duration::from_millis(20);
const SCRUB_PAUSE: std::time::Duration = std::time::Duration::from_millis(2);

fn scrub_in_steps(entry: &Attached, repair: bool) -> Result<scalefs_core::ScrubReport, OpError> {
    let damaged = || -> OpError {
        (
            ErrorCode::Internal,
            "the pool's state was damaged earlier; detach and import it again".to_string(),
        )
    };
    let mut cursor = entry.pool.read().map_err(|_| damaged())?.scrub_start();
    loop {
        let mut pool = entry.pool.write().map_err(|_| damaged())?;
        let deadline = std::time::Instant::now() + SCRUB_STEP;
        let step = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pool.scrub_step(&mut cursor, repair, Some(deadline))
        }));
        let done = match step {
            Ok(result) => result.map_err(|error| code_for(&error))?,
            Err(_) => {
                if let Some(core) = entry.core.get() {
                    core.poison();
                }
                entry.wrecked.store(true, Ordering::SeqCst);
                return Err((
                    ErrorCode::Internal,
                    "the job crashed; the pool is fenced off — detach and import it again"
                        .to_string(),
                ));
            }
        };
        if done {
            return pool.scrub_finish(cursor).map_err(|error| code_for(&error));
        }
        drop(pool);
        std::thread::sleep(SCRUB_PAUSE);
    }
}

fn code_for(error: &ScaleFsError) -> (ErrorCode, String) {
    let code = match error {
        ScaleFsError::Corrupt(_) => ErrorCode::Corrupt,
        ScaleFsError::InvalidArgument(_) => ErrorCode::BadRequest,
        ScaleFsError::NotFound => ErrorCode::NotFound,
        ScaleFsError::Unsupported(_) => ErrorCode::Unsupported,
        ScaleFsError::UnsupportedUnicodeVersion { .. } => ErrorCode::Unsupported,
        ScaleFsError::EarlierFormat { .. } => ErrorCode::Unsupported,
        ScaleFsError::MissingMembers { .. } => ErrorCode::Conflict,
        ScaleFsError::Io(_) => ErrorCode::Io,
        ScaleFsError::AlreadyExists
        | ScaleFsError::OutOfSpace
        | ScaleFsError::DirectoryNotEmpty
        | ScaleFsError::TooManyLinks => ErrorCode::Conflict,
        ScaleFsError::OutOfBounds { .. }
        | ScaleFsError::NotDirectory
        | ScaleFsError::IsDirectory => ErrorCode::Internal,
    };
    (code, error.to_string())
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use scalefs_core::{
        CaseSensitivity, DeviceId, FileBlockDevice, Geometry, MemberSpec, PoolId, PoolParams,
    };

    fn registry_with_pool(tag: &str) -> (Registry, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "scalefsd-fence-{}-{tag}-{}",
            std::process::id(),
            now_ns() & 0xFFFF_FFFF,
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let geometry = Geometry {
            logical_block_size: 4096,
            physical_block_size: 4096,
            zone_size: 64 * 1024,
            zone_count: 16,
            erase_granularity_zones: 1,
            sequential_write_required: false,
        };
        let images: Vec<String> = [("a.img", 0xA1u8), ("b.img", 0xB2)]
            .iter()
            .map(|(file, _)| dir.join(file).to_string_lossy().into_owned())
            .collect();
        let members = images
            .iter()
            .zip([0xA1u8, 0xB2])
            .map(|(path, id)| MemberSpec {
                device: FileBlockDevice::create(
                    Path::new(path),
                    scalefs_core::member_image_len(geometry.capacity_bytes()),
                )
                .unwrap(),
                device_id: DeviceId([id; 16]),
                geometry,
            })
            .collect();
        Pool::create_multi(
            members,
            PoolParams {
                pool_id: PoolId([0x55; 16]),
                case_sensitivity: CaseSensitivity::InsensitivePreserving,
                dirent_hash_seed: 7,
                label: "fence".to_string(),
                created_at_ns: now_ns(),
                mirror_width: 2,
                data_width: 1,
                parity_width: 0,
            },
        )
        .unwrap();

        let registry = Registry::default();
        let params = object(vec![
            ("name", Value::Str("fence".into())),
            (
                "members",
                Value::Array(images.into_iter().map(Value::Str).collect()),
            ),
        ]);
        registry.attach(&params).unwrap();
        (registry, dir)
    }

    fn name_params() -> Value {
        object(vec![("name", Value::Str("fence".into()))])
    }

    fn job_state(registry: &Registry, id: u64) -> String {
        let status = registry
            .job_status(&object(vec![("id", Value::Int(i128::from(id)))]))
            .unwrap();
        status.get("state").unwrap().as_str().unwrap().to_string()
    }

    const BLIND: u64 = scalefs_mount::dataplane::eject::BLIND_GENERATION;

    fn acked(registry: &Registry, pool: &str) -> scalefs_mount::dataplane::PrepareVerdict {
        registry.eject_prepare(pool, None).verdict
    }

    fn recorded_eject(
        store: &crate::state::StateStore,
        pool: &str,
    ) -> Option<crate::state::EjectState> {
        let text = std::fs::read_to_string(store.path()).expect("the record exists");
        let value = scalefs_ipc::json::parse(&text).expect("the record parses");
        let named = |list: &str| -> usize {
            value
                .get(list)
                .and_then(Value::as_array)
                .unwrap_or_default()
                .iter()
                .filter(|entry| entry.get("name").and_then(Value::as_str) == Some(pool))
                .count()
        };
        let state = store
            .load_suppressed()
            .expect("the tombstones read")
            .into_iter()
            .find(|tombstone| tombstone.name == pool)
            .and_then(|tombstone| tombstone.eject);
        if state.is_some() {
            assert_eq!(
                named("pools"),
                0,
                "a tombstoned pool has no restore row: {text}"
            );
            assert_eq!(named("suppressed"), 1, "{text}");
        } else {
            assert_eq!(named("suppressed"), 0, "no stray tombstone: {text}");
        }
        state
    }

    fn released_witness(registry: &Registry, pool: &str) -> GuardWitness {
        let guard = registry.share_handle(pool).expect("a guard to witness");
        let witness = guard.guard.witness();
        drop(guard);
        assert!(!witness.held(), "the witness follows its guard");
        witness
    }

    fn registry_with_recorded_pool(
        tag: &str,
    ) -> (Registry, Arc<crate::state::StateStore>, std::path::PathBuf) {
        let (registry, dir) = registry_with_pool(tag);
        let members = {
            let pools = registry.pools.lock().expect("registry lock");
            pools["fence"].members.lock().expect("members").clone()
        };
        registry.detach(&name_params()).expect("detach the scratch");
        drop(registry);
        let store = Arc::new(crate::state::StateStore::open(&dir.join("state")).unwrap());
        let registry = Registry::with_state(Some(Arc::clone(&store)));
        registry
            .attach(&object(vec![
                ("name", Value::Str("fence".into())),
                (
                    "members",
                    Value::Array(members.into_iter().map(Value::Str).collect()),
                ),
            ]))
            .expect("attach with state");
        (registry, store, dir)
    }

    #[test]
    fn eject_prepare_allocates_a_generation_and_records_it_before_acking() {
        use scalefs_mount::dataplane::PrepareVerdict;
        let (registry, store, dir) = registry_with_recorded_pool("ejectgen");
        assert_eq!(recorded_eject(&store, "fence"), None, "clean to start");

        let first = registry.eject_prepare("fence", None);
        assert_eq!(first.verdict, PrepareVerdict::Ack);
        assert_ne!(first.generation, BLIND, "an ACK never carries generation 0");
        assert_eq!(
            recorded_eject(&store, "fence"),
            Some(crate::state::EjectState {
                phase: crate::state::EjectPhase::Prepared,
                generation: first.generation,
            }),
        );

        let again = registry.eject_prepare("fence", None);
        assert_eq!(
            again, first,
            "a re-prepare is idempotent, generation and all"
        );
        assert_eq!(
            recorded_eject(&store, "fence").map(|state| state.generation),
            Some(first.generation),
        );

        registry.eject_abort("fence", first.generation);
        assert_eq!(recorded_eject(&store, "fence"), None, "abort clears it");
        let second = registry.eject_prepare("fence", None);
        assert_eq!(second.verdict, PrepareVerdict::Ack);
        assert!(
            second.generation > first.generation,
            "{} must follow {}",
            second.generation,
            first.generation,
        );
        registry.eject_abort("fence", BLIND);
        registry.detach(&name_params()).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn eject_commit_establishes_ejected_with_nothing_prepared() {
        use scalefs_mount::dataplane::PrepareVerdict;
        let (registry, store, dir) = registry_with_recorded_pool("ejectcommit");
        assert_eq!(recorded_eject(&store, "fence"), None);
        drop(
            registry
                .share_handle("fence")
                .expect("unfrozen before the commit"),
        );

        assert_eq!(
            registry.eject_commit("fence", 42, None),
            PrepareVerdict::Ack
        );
        assert_eq!(
            recorded_eject(&store, "fence"),
            Some(crate::state::EjectState {
                phase: crate::state::EjectPhase::Ejected,
                generation: 42,
            }),
        );
        match registry.share_handle("fence") {
            Err((ErrorCode::Conflict, m)) => assert!(m.contains("ejected"), "{m}"),
            Err((code, m)) => panic!("expected the eject refusal, got {code:?}: {m}"),
            Ok(_) => panic!("a committed removal must refuse new surfaces"),
        }
        registry.detach(&name_params()).unwrap();
        assert_eq!(
            registry.eject_commit("fence", 42, None),
            PrepareVerdict::Ack
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_committed_eject_dominates_every_racing_abort() {
        use scalefs_mount::dataplane::PrepareVerdict;
        let (registry, store, dir) = registry_with_recorded_pool("ejectdominates");
        let prepared = registry.eject_prepare("fence", None);
        assert_eq!(prepared.verdict, PrepareVerdict::Ack);
        assert_eq!(
            registry.eject_commit("fence", prepared.generation, None),
            PrepareVerdict::Ack,
        );
        let committed = Some(crate::state::EjectState {
            phase: crate::state::EjectPhase::Ejected,
            generation: prepared.generation,
        });

        for abort in [prepared.generation, BLIND, prepared.generation + 5] {
            registry.eject_abort("fence", abort);
            assert_eq!(
                recorded_eject(&store, "fence"),
                committed,
                "abort({abort}) must not undo a committed removal",
            );
            match registry.share_handle("fence") {
                Err((ErrorCode::Conflict, m)) => assert!(m.contains("ejected"), "{m}"),
                Err((code, m)) => panic!("abort({abort}): unexpected {code:?}: {m}"),
                Ok(_) => panic!("abort({abort}) must not release the freeze"),
            }
        }
        registry.detach(&name_params()).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_blind_abort_clears_any_uncommitted_prepare() {
        use scalefs_mount::dataplane::PrepareVerdict;
        let (registry, store, dir) = registry_with_recorded_pool("ejectblind");
        let prepared = registry.eject_prepare("fence", None);
        assert_eq!(prepared.verdict, PrepareVerdict::Ack);

        registry.eject_abort("fence", prepared.generation + 1);
        assert!(
            recorded_eject(&store, "fence").is_some(),
            "a stale abort must not clear a standing prepare",
        );
        assert!(registry.share_handle("fence").is_err(), "still frozen");

        registry.eject_abort("fence", BLIND);
        assert_eq!(recorded_eject(&store, "fence"), None);
        drop(
            registry
                .share_handle("fence")
                .expect("unfrozen after blind"),
        );
        registry.eject_abort("fence", BLIND);
        assert_eq!(recorded_eject(&store, "fence"), None);
        registry.detach(&name_params()).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_operator_attach_clears_the_safe_removal_state() {
        use scalefs_mount::dataplane::PrepareVerdict;
        let (registry, store, dir) = registry_with_recorded_pool("ejectreattach");
        #[cfg(windows)]
        let letter = crate::state::RecordedMount {
            mountpoint: "S:".to_string(),
            read_only: false,
            kernel_device: Some(r"\\.\ScaleFsCtl".to_string()),
            close_durability: Some(scalefs_mount::dataplane::CloseDurability::CommitOnClose),
        };
        #[cfg(windows)]
        registry.record_serve_mount("fence", Some(letter.clone()));
        let prepared = registry.eject_prepare("fence", None);
        assert_eq!(prepared.verdict, PrepareVerdict::Ack);
        assert_eq!(
            registry.eject_commit("fence", prepared.generation, None),
            PrepareVerdict::Ack,
        );
        let members = {
            let pools = registry.pools.lock().expect("registry lock");
            pools["fence"].members.lock().expect("members").clone()
        };
        registry.detach_quiesce("fence").unwrap();
        assert!(
            recorded_eject(&store, "fence").is_some(),
            "the marker must outlive the eject teardown",
        );
        #[cfg(windows)]
        assert_eq!(
            store.load_suppressed().unwrap()[0].mounts,
            vec![letter.clone()],
            "the tombstone keeps the letter",
        );

        registry
            .attach(&object(vec![
                ("name", Value::Str("fence".into())),
                (
                    "members",
                    Value::Array(members.into_iter().map(Value::Str).collect()),
                ),
            ]))
            .expect("the operator reattaches");
        assert_eq!(
            recorded_eject(&store, "fence"),
            None,
            "an operator attach clears the safe-removal state",
        );
        let rows = store.load();
        assert_eq!(rows.len(), 1, "the pool is a restorable row again");
        assert_eq!(rows[0].name, "fence");
        #[cfg(windows)]
        assert_eq!(rows[0].mounts, vec![letter], "the letter carried over");
        drop(
            registry
                .share_handle("fence")
                .expect("a reattached pool serves again"),
        );
        registry.detach(&name_params()).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn eject_commit_naks_a_job_admitted_while_the_barrier_was_down() {
        use scalefs_mount::dataplane::PrepareVerdict;
        let (registry, store, dir) = registry_with_recorded_pool("commitbusy");
        let serving = registry.share_handle("fence").unwrap();
        let own = serving.guard.witness();
        let prepared = registry.eject_prepare("fence", Some(&own));
        assert_eq!(prepared.verdict, PrepareVerdict::Ack);
        registry.eject_abort("fence", prepared.generation);
        assert_eq!(recorded_eject(&store, "fence"), None);

        let (release, released) = std::sync::mpsc::channel::<()>();
        let started = registry
            .start_job(&name_params(), "hold", move |_pool, _entry| {
                let _ = released.recv();
                Ok(Value::Null)
            })
            .expect("admitted while the barrier is down");
        let id = started.get("job").unwrap().as_u64().unwrap();

        for generation in [prepared.generation, BLIND] {
            assert_eq!(
                registry.eject_commit("fence", generation, Some(&own)),
                PrepareVerdict::NakBusyWithJob,
                "COMMIT({generation}) must not confirm a removal under a running job",
            );
        }
        assert_eq!(recorded_eject(&store, "fence"), None);
        assert_eq!(job_state(&registry, id), "running", "the job is untouched");
        assert!(matches!(
            registry.share_handle("fence"),
            Err((ErrorCode::Conflict, _))
        ));

        release.send(()).unwrap();
        while job_state(&registry, id) == "running" {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let mut verdict = registry.eject_commit("fence", prepared.generation, Some(&own));
        while verdict == PrepareVerdict::NakBusyWithJob {
            std::thread::sleep(std::time::Duration::from_millis(5));
            verdict = registry.eject_commit("fence", prepared.generation, Some(&own));
        }
        assert_eq!(verdict, PrepareVerdict::Ack);
        assert_eq!(
            recorded_eject(&store, "fence"),
            Some(crate::state::EjectState {
                phase: crate::state::EjectPhase::Ejected,
                generation: prepared.generation,
            }),
        );
        drop(serving);
        registry.detach(&name_params()).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn eject_commit_naks_a_share_admitted_after_a_same_generation_abort() {
        use scalefs_mount::dataplane::PrepareVerdict;
        let (registry, store, dir) = registry_with_recorded_pool("commitfence");
        let serving = registry.share_handle("fence").unwrap();
        let own = serving.guard.witness();
        let prepared = registry.eject_prepare("fence", Some(&own));
        assert_eq!(prepared.verdict, PrepareVerdict::Ack);
        registry.eject_abort("fence", prepared.generation);
        let foreign = registry
            .share_handle("fence")
            .expect("admitted while the barrier is down");

        for generation in [prepared.generation, BLIND] {
            assert_eq!(
                registry.eject_commit("fence", generation, Some(&own)),
                PrepareVerdict::NakFenceHeld,
                "COMMIT({generation}) must not confirm a removal under a live share",
            );
        }
        assert_eq!(recorded_eject(&store, "fence"), None, "nothing recorded");
        assert!(
            store.load().iter().any(|row| row.name == "fence"),
            "still a restorable row",
        );
        assert!(matches!(
            registry.share_handle("fence"),
            Err((ErrorCode::Conflict, _))
        ));

        drop(foreign);
        assert_eq!(
            registry.eject_commit("fence", prepared.generation, Some(&own)),
            PrepareVerdict::Ack,
        );
        assert_eq!(
            recorded_eject(&store, "fence"),
            Some(crate::state::EjectState {
                phase: crate::state::EjectPhase::Ejected,
                generation: prepared.generation,
            }),
        );
        drop(serving);
        registry.detach(&name_params()).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn eject_prepare_counts_foreign_fences_exactly() {
        use scalefs_mount::dataplane::PrepareVerdict;
        let (registry, store, dir) = registry_with_recorded_pool("prepareexact");
        let own = released_witness(&registry, "fence");
        let lone = registry.share_handle("fence").unwrap();
        assert_eq!(
            registry.eject_prepare("fence", Some(&own)).verdict,
            PrepareVerdict::NakFenceHeld,
            "a released guard is not subtracted",
        );
        assert_eq!(
            registry.eject_prepare("fence", None).verdict,
            PrepareVerdict::NakFenceHeld,
        );
        assert_eq!(recorded_eject(&store, "fence"), None);
        drop(
            registry
                .share_handle("fence")
                .expect("not frozen after a NAK"),
        );
        let witness = lone.guard.witness();
        let prepared = registry.eject_prepare("fence", Some(&witness));
        assert_eq!(prepared.verdict, PrepareVerdict::Ack);
        assert_eq!(
            recorded_eject(&store, "fence").map(|state| state.phase),
            Some(crate::state::EjectPhase::Prepared),
        );
        registry.eject_abort("fence", prepared.generation);
        drop(lone);
        assert!(!witness.held());
        let other = registry.share_handle("fence").unwrap();
        assert_eq!(
            registry.eject_prepare("fence", Some(&witness)).verdict,
            PrepareVerdict::NakFenceHeld,
        );
        drop(other);
        registry.detach(&name_params()).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn eject_commit_counts_foreign_fences_exactly() {
        use scalefs_mount::dataplane::PrepareVerdict;
        let (registry, store, dir) = registry_with_recorded_pool("commitexact");
        let own = released_witness(&registry, "fence");
        let lone = registry.share_handle("fence").unwrap();
        assert_eq!(
            registry.eject_commit("fence", 7, Some(&own)),
            PrepareVerdict::NakFenceHeld,
            "a released guard is not subtracted",
        );
        assert_eq!(
            registry.eject_commit("fence", 7, None),
            PrepareVerdict::NakFenceHeld,
        );
        assert_eq!(recorded_eject(&store, "fence"), None);
        let witness = lone.guard.witness();
        assert_eq!(
            registry.eject_commit("fence", 7, Some(&witness)),
            PrepareVerdict::Ack,
        );
        assert_eq!(
            recorded_eject(&store, "fence").map(|state| state.phase),
            Some(crate::state::EjectPhase::Ejected),
        );
        drop(lone);
        registry.detach(&name_params()).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_eject_commits_a_close_a_bounded_serving_deferred() {
        use scalefs_mount::dataplane::PrepareVerdict;
        for attempt in 0..5 {
            let (registry, _store, dir) =
                registry_with_recorded_pool(&format!("ejectbounded{attempt}"));
            let serving = registry.share_handle("fence").unwrap();
            let core = serving.core.clone().expect("a writable pool's core");
            let committed = || serving.pool.read().unwrap().committed_tx();
            let started = std::time::Instant::now();
            let before = committed();
            let file = core
                .create(scalefs_core::ROOT_INODE, "closed", 0o644, 0, 0)
                .unwrap();
            core.write(file.inode, 0, b"written, then closed").unwrap();
            core.commit_within(std::time::Duration::from_secs(5))
                .unwrap();
            let deferred = committed() == before;
            let witness = serving.guard.witness();
            let verdict = registry.eject_commit("fence", 9, Some(&witness));
            let after = committed();
            let span = started.elapsed();
            drop(serving);
            registry.detach(&name_params()).unwrap();
            let _ = std::fs::remove_dir_all(dir);
            if span >= std::time::Duration::from_millis(400) {
                continue;
            }
            assert!(deferred, "the bounded close committed by itself");
            assert_eq!(verdict, PrepareVerdict::Ack);
            assert!(
                after > before,
                "the eject was confirmed before the deferred close was committed"
            );
            return;
        }
        panic!("five attempts in a row overran the debounce quiet window");
    }

    #[test]
    fn an_abort_during_a_commit_does_not_lower_the_barrier() {
        use scalefs_mount::dataplane::PrepareVerdict;
        let (registry, store, dir) = registry_with_recorded_pool("commitabort");
        let serving = registry.share_handle("fence").unwrap();
        let own = serving.guard.witness();
        let prepared = registry.eject_prepare("fence", Some(&own));
        assert_eq!(prepared.verdict, PrepareVerdict::Ack);

        let in_flight = registry
            .eject_commit_close("fence", prepared.generation, Some(&own))
            .unwrap_or_else(|answered| panic!("phase 1 must pass, answered {answered:?}"));
        for generation in [prepared.generation, BLIND] {
            registry.eject_abort("fence", generation);
            assert!(
                matches!(
                    registry.share_handle("fence"),
                    Err((ErrorCode::Conflict, _))
                ),
                "ABORT({generation}) during the commit must leave admission closed",
            );
        }
        assert_eq!(
            recorded_eject(&store, "fence").map(|state| state.phase),
            Some(crate::state::EjectPhase::Prepared),
            "the standing marker is untouched",
        );
        assert_eq!(
            registry.eject_commit_record(in_flight, "fence", prepared.generation),
            PrepareVerdict::Ack,
        );
        assert_eq!(
            recorded_eject(&store, "fence"),
            Some(crate::state::EjectState {
                phase: crate::state::EjectPhase::Ejected,
                generation: prepared.generation,
            }),
        );
        registry.eject_abort("fence", BLIND);
        assert!(matches!(
            registry.share_handle("fence"),
            Err((ErrorCode::Conflict, _))
        ));
        drop(serving);
        registry.detach(&name_params()).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn overlapping_commit_spans_keep_the_barrier_until_the_last_ends() {
        use scalefs_mount::dataplane::PrepareVerdict;
        let (registry, store, dir) = registry_with_recorded_pool("commitnest");
        let serving = registry.share_handle("fence").unwrap();
        let own = serving.guard.witness();
        let prepared = registry.eject_prepare("fence", Some(&own));
        assert_eq!(prepared.verdict, PrepareVerdict::Ack);

        let first = registry
            .eject_commit_close("fence", prepared.generation, Some(&own))
            .unwrap_or_else(|answered| panic!("phase 1 must pass, answered {answered:?}"));
        let second = registry
            .eject_commit_close("fence", prepared.generation, Some(&own))
            .unwrap_or_else(|answered| panic!("phase 1 must pass twice, answered {answered:?}"));
        drop(first);
        registry.eject_abort("fence", BLIND);
        assert!(
            matches!(
                registry.share_handle("fence"),
                Err((ErrorCode::Conflict, _))
            ),
            "the barrier must stand while the second evaluation is in flight",
        );
        assert_eq!(
            recorded_eject(&store, "fence").map(|state| state.phase),
            Some(crate::state::EjectPhase::Prepared),
        );
        assert_eq!(
            registry.eject_commit_record(second, "fence", prepared.generation),
            PrepareVerdict::Ack,
        );
        assert_eq!(
            recorded_eject(&store, "fence").map(|state| state.phase),
            Some(crate::state::EjectPhase::Ejected),
        );
        drop(serving);
        registry.detach(&name_params()).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_refused_commit_ends_the_span_and_the_next_abort_is_honoured() {
        use scalefs_mount::dataplane::PrepareVerdict;
        let (registry, store, dir) = registry_with_recorded_pool("commitspan");
        let serving = registry.share_handle("fence").unwrap();
        let own = serving.guard.witness();
        let prepared = registry.eject_prepare("fence", Some(&own));
        assert_eq!(prepared.verdict, PrepareVerdict::Ack);
        registry.eject_abort("fence", prepared.generation);
        let foreign = registry
            .share_handle("fence")
            .expect("admitted while the barrier is down");
        assert_eq!(
            registry
                .eject_commit_close("fence", prepared.generation, Some(&own))
                .err(),
            Some(PrepareVerdict::NakFenceHeld),
        );
        assert!(matches!(
            registry.share_handle("fence"),
            Err((ErrorCode::Conflict, _))
        ));
        registry.eject_abort("fence", BLIND);
        drop(
            registry
                .share_handle("fence")
                .expect("the abort after a refused commit is honoured"),
        );
        assert_eq!(recorded_eject(&store, "fence"), None);
        drop(foreign);
        drop(serving);
        registry.detach(&name_params()).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_detached_ejected_pool_keeps_its_tombstone_across_other_persists() {
        use scalefs_mount::dataplane::PrepareVerdict;
        let (registry, store, dir) = registry_with_recorded_pool("tombkeep");
        let prepared = registry.eject_prepare("fence", None);
        assert_eq!(
            registry.eject_commit("fence", prepared.generation, None),
            PrepareVerdict::Ack,
        );
        registry.detach_quiesce("fence").unwrap();
        let committed = Some(crate::state::EjectState {
            phase: crate::state::EjectPhase::Ejected,
            generation: prepared.generation,
        });
        assert_eq!(recorded_eject(&store, "fence"), committed);

        let (other_dir, other) = membership_pool("tombkeep-other");
        registry
            .attach(&attach_params("other", &other, false))
            .unwrap();
        assert_eq!(
            recorded_eject(&store, "fence"),
            committed,
            "survives another attach"
        );
        assert_eq!(
            store
                .load()
                .iter()
                .map(|row| row.name.as_str())
                .collect::<Vec<_>>(),
            ["other"],
        );
        registry
            .detach(&object(vec![("name", Value::Str("other".into()))]))
            .unwrap();
        assert_eq!(
            recorded_eject(&store, "fence"),
            committed,
            "survives another detach"
        );
        assert!(store.load().is_empty());
        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(other_dir);
    }

    #[test]
    fn boot_restore_leaves_a_tombstoned_pool_alone() {
        use scalefs_mount::dataplane::PrepareVerdict;
        let (registry, store, dir) = registry_with_recorded_pool("tombboot");
        let prepared = registry.eject_prepare("fence", None);
        assert_eq!(
            registry.eject_commit("fence", prepared.generation, None),
            PrepareVerdict::Ack,
        );
        let members = {
            let pools = registry.pools.lock().expect("registry lock");
            pools["fence"].members.lock().expect("members").clone()
        };
        registry.detach_quiesce("fence").unwrap();
        drop(registry);

        let restarted = Registry::with_state(Some(Arc::clone(&store)));
        crate::state::reassemble(&restarted, &store);
        assert_eq!(
            restarted.list().unwrap().get("pools"),
            Some(&Value::Array(Vec::new())),
            "a tombstoned pool is not reassembled, members present or not",
        );
        assert!(
            recorded_eject(&store, "fence").is_some(),
            "boot restore never clears a tombstone",
        );
        restarted
            .attach(&attach_params("fence", &members, false))
            .expect("the members were never opened by the restore");
        assert_eq!(recorded_eject(&store, "fence"), None);
        restarted.detach(&name_params()).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_unwritable_record_fails_the_barrier_closed() {
        use scalefs_mount::dataplane::PrepareVerdict;
        let (registry, store, dir) = registry_with_recorded_pool("unwritable");
        let blocker = store.path().with_extension("json.tmp");
        std::fs::create_dir(&blocker).unwrap();

        assert_eq!(
            registry.eject_prepare("fence", None).verdict,
            PrepareVerdict::NakStateWriteFailed,
        );
        drop(
            registry
                .share_handle("fence")
                .expect("the failed PREPARE left no freeze behind"),
        );
        assert_eq!(
            registry.eject_commit("fence", 3, None),
            PrepareVerdict::NakStateWriteFailed,
        );
        std::fs::remove_dir(&blocker).unwrap();
        assert_eq!(recorded_eject(&store, "fence"), None, "nothing on disk");
        registry.detach(&name_params()).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn eject_prepare_freezes_then_the_lifecycle_clears() {
        use scalefs_mount::dataplane::PrepareVerdict;
        let (registry, dir) = registry_with_pool("ejectgate");
        assert_eq!(acked(&registry, "fence"), PrepareVerdict::Ack);
        match registry.share_handle("fence") {
            Err((ErrorCode::Conflict, m)) => assert!(m.contains("ejected"), "{m}"),
            Err((code, m)) => panic!("a new surface must refuse with Conflict, got {code:?}: {m}"),
            Ok(_) => panic!("a new surface must refuse while ejecting"),
        }
        match registry.scrub(&name_params()) {
            Err((ErrorCode::Conflict, m)) => assert!(m.contains("ejected"), "{m}"),
            other => panic!("a new job must refuse while ejecting: {other:?}"),
        }
        assert_eq!(acked(&registry, "fence"), PrepareVerdict::Ack);
        registry.eject_abort("fence", BLIND);
        drop(registry.share_handle("fence").expect("share after abort"));
        registry.detach(&name_params()).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn eject_prepare_naks_a_foreign_fence_and_a_running_job() {
        use scalefs_mount::dataplane::PrepareVerdict;
        let (registry, dir) = registry_with_pool("ejectnak");
        let serving = registry.share_handle("fence").unwrap();
        let own = serving.guard.witness();
        assert_eq!(
            registry.eject_prepare("fence", Some(&own)).verdict,
            PrepareVerdict::Ack
        );
        registry.eject_abort("fence", BLIND);
        let foreign = registry.share_handle("fence").unwrap();
        assert_eq!(
            registry.eject_prepare("fence", Some(&own)).verdict,
            PrepareVerdict::NakFenceHeld
        );
        drop(foreign);
        drop(serving);
        let (release, released) = std::sync::mpsc::channel::<()>();
        let started = registry
            .start_job(&name_params(), "hold", move |_pool, _entry| {
                let _ = released.recv();
                Ok(Value::Null)
            })
            .unwrap();
        let id = started.get("job").unwrap().as_u64().unwrap();
        assert_eq!(acked(&registry, "fence"), PrepareVerdict::NakBusyWithJob);
        release.send(()).unwrap();
        while job_state(&registry, id) == "running" {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(acked(&registry, "fence"), PrepareVerdict::Ack);
        registry.eject_abort("fence", BLIND);
        registry.detach(&name_params()).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn eject_freeze_persists_until_explicitly_cleared() {
        use scalefs_mount::dataplane::PrepareVerdict;
        let (registry, dir) = registry_with_pool("ejectpersist");
        assert_eq!(acked(&registry, "fence"), PrepareVerdict::Ack);
        assert!(registry.list().is_ok());
        assert!(registry.status(&name_params()).is_ok());
        match registry.share_handle("fence") {
            Err((ErrorCode::Conflict, m)) => assert!(m.contains("ejected"), "{m}"),
            Err((code, m)) => panic!("the freeze must persist (Conflict), got {code:?}: {m}"),
            Ok(_) => panic!("the freeze must persist"),
        }
        registry.eject_abort("fence", BLIND);
        registry.detach(&name_params()).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn jobs_fence_the_pool_until_they_finish() {
        let (registry, dir) = registry_with_pool("fence");
        let (release, released) = std::sync::mpsc::channel::<()>();

        let started = registry
            .start_job(&name_params(), "hold", move |_pool, _entry| {
                released.recv().expect("test releases the job");
                Ok(Value::Null)
            })
            .unwrap();
        let id = started.get("job").unwrap().as_u64().unwrap();
        assert_eq!(job_state(&registry, id), "running");

        for refused in [
            registry.scrub(&name_params()),
            registry.rebuild(&name_params()),
            registry.detach(&name_params()),
        ] {
            match refused {
                Err((ErrorCode::Busy, message)) => {
                    assert!(message.contains(&format!("job {id}")), "{message}");
                }
                other => panic!("expected busy, got {other:?}"),
            }
        }

        release.send(()).unwrap();
        while job_state(&registry, id) == "running" {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(job_state(&registry, id), "done");
        let mut detached = registry.detach(&name_params());
        while matches!(detached, Err((ErrorCode::Busy, _))) {
            std::thread::sleep(std::time::Duration::from_millis(5));
            detached = registry.detach(&name_params());
        }
        detached.unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn failed_jobs_report_and_release() {
        let (registry, dir) = registry_with_pool("fail");
        let started = registry
            .start_job(&name_params(), "explode", |_pool, _entry| {
                Err(ScaleFsError::Unsupported("this job always fails"))
            })
            .unwrap();
        let id = started.get("job").unwrap().as_u64().unwrap();
        while job_state(&registry, id) == "running" {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let status = registry
            .job_status(&object(vec![("id", Value::Int(i128::from(id)))]))
            .unwrap();
        assert_eq!(status.get("state").unwrap().as_str(), Some("failed"));
        let error = status.get("error").unwrap().as_str().unwrap();
        assert!(error.contains("unsupported"), "{error}");

        let mut detached = registry.detach(&name_params());
        while matches!(detached, Err((ErrorCode::Busy, _))) {
            std::thread::sleep(std::time::Duration::from_millis(5));
            detached = registry.detach(&name_params());
        }
        detached.unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn status_reports_the_naming_rules() {
        let (registry, dir) = registry_with_pool("naming");
        let status = registry.status(&name_params()).unwrap();
        let naming = status.get("naming").expect("naming block in status");
        assert_eq!(
            naming.get("case_sensitivity").unwrap().as_str(),
            Some("insensitive_preserving"),
        );
        assert_eq!(
            naming.get("unicode_version").unwrap().as_str(),
            Some("17.0.0"),
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn presentation_rollup_leans_permissive() {
        let row = |word: &str| object(vec![("attachment", Value::Str(word.to_string()))]);
        assert!(media_presents_external(&[]));
        assert!(media_presents_external(&[row("external"), row("external")]));
        assert!(!media_presents_external(&[
            row("external"),
            row("internal")
        ]));
        assert!(!media_presents_external(&[row("internal")]));
        assert!(media_presents_external(&[row("external"), row("unknown")]));
        assert!(media_presents_external(&[row("unknown")]));
        assert!(media_presents_external(&[object(vec![(
            "path",
            Value::Str("x".into()),
        )])]));
    }

    #[test]
    fn status_reports_attachment() {
        let (registry, dir) = registry_with_pool("attach-status");
        let status = registry.status(&name_params()).unwrap();
        let rollup = status.get("attachment").and_then(Value::as_str).unwrap();
        assert!(matches!(rollup, "external" | "fixed"), "rollup {rollup}");
        let media = status.get("media").and_then(Value::as_array).unwrap();
        assert!(!media.is_empty());
        for member in media {
            let word = member.get("attachment").and_then(Value::as_str).unwrap();
            assert!(
                matches!(word, "external" | "internal" | "unknown"),
                "member attachment {word}",
            );
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn status_answers_while_a_job_runs() {
        let (registry, dir) = registry_with_pool("busy-status");
        let (release, released) = std::sync::mpsc::channel::<()>();
        let started = registry
            .start_job(&name_params(), "hold", move |_pool, _entry| {
                released.recv().expect("test releases the job");
                Ok(Value::Null)
            })
            .unwrap();
        let id = started.get("job").unwrap().as_u64().unwrap();
        assert_eq!(registry.running_job().map(|(id, _)| id), Some(id));

        let (result_tx, result_rx) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let _ = result_tx.send(registry.status(&name_params()));
            });
            match result_rx.recv_timeout(std::time::Duration::from_secs(10)) {
                Ok(status) => {
                    let status = status.unwrap();
                    assert_eq!(status.get("busy_with_job").unwrap().as_u64(), Some(id));
                    assert_eq!(status.get("label").unwrap().as_str(), Some("fence"));
                    assert!(status.get("members_detail").is_some());
                }
                Err(_) => {
                    release.send(()).unwrap();
                    panic!("pool.status blocked behind the running job");
                }
            }
        });
        let listed = registry.list().unwrap();
        let rows = listed.get("pools").unwrap().as_array().unwrap();
        assert_eq!(rows[0].get("busy_with_job").unwrap().as_u64(), Some(id));

        release.send(()).unwrap();
        while job_state(&registry, id) == "running" {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let status = registry.status(&name_params()).unwrap();
        assert!(status.get("busy_with_job").is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn overlapping_attachments_are_refused() {
        let (registry, dir) = registry_with_pool("overlap");
        let images: Vec<String> = ["a.img", "b.img"]
            .iter()
            .map(|file| dir.join(file).to_string_lossy().into_owned())
            .collect();
        let params = |name: &str, members: &[String]| {
            object(vec![
                ("name", Value::Str(name.to_string())),
                (
                    "members",
                    Value::Array(members.iter().cloned().map(Value::Str).collect()),
                ),
            ])
        };
        match registry.attach(&params("second", &images)) {
            Err((ErrorCode::Conflict, message)) => {
                assert!(message.contains("fence"), "{message}");
            }
            other => panic!("expected conflict, got {other:?}"),
        }
        let copies: Vec<String> = images
            .iter()
            .enumerate()
            .map(|(index, path)| {
                let copy = dir.join(format!("copy-{index}.img"));
                std::fs::copy(path, &copy).unwrap();
                copy.to_string_lossy().into_owned()
            })
            .collect();
        match registry.attach(&params("clone", &copies)) {
            Err((ErrorCode::Conflict, message)) => {
                assert!(message.contains("pool id"), "{message}");
            }
            other => panic!("expected conflict, got {other:?}"),
        }
        registry.detach(&name_params()).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn panicking_jobs_wreck_and_release() {
        let (registry, dir) = registry_with_pool("panic");
        let started = registry
            .start_job(
                &name_params(),
                "explode",
                |_pool, _entry| -> scalefs_core::Result<Value> { panic!("simulated engine bug") },
            )
            .unwrap();
        let id = started.get("job").unwrap().as_u64().unwrap();
        while job_state(&registry, id) == "running" {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let status = registry
            .job_status(&object(vec![("id", Value::Int(i128::from(id)))]))
            .unwrap();
        assert_eq!(status.get("state").unwrap().as_str(), Some("failed"));
        let error = status.get("error").unwrap().as_str().unwrap();
        assert!(error.contains("crashed"), "{error}");
        match registry.scrub(&name_params()) {
            Err((ErrorCode::Internal, message)) => {
                assert!(message.contains("fenced"), "{message}");
            }
            other => panic!("expected internal, got {other:?}"),
        }
        assert_eq!(
            registry.status(&name_params()).unwrap().get("wrecked"),
            Some(&Value::Bool(true)),
        );
        let mut detached = registry.detach(&name_params());
        while matches!(detached, Err((ErrorCode::Busy, _))) {
            std::thread::sleep(std::time::Duration::from_millis(5));
            detached = registry.detach(&name_params());
        }
        detached.unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn detach_and_job_start_cannot_both_win() {
        for round in 0..100 {
            let (registry, dir) = registry_with_pool(&format!("race{round}"));
            let registry = std::sync::Arc::new(registry);
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let (release, released) = std::sync::mpsc::channel::<()>();

            let starter = {
                let registry = std::sync::Arc::clone(&registry);
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    registry
                        .start_job(&name_params(), "hold", move |_pool, _entry| {
                            let _ = released.recv();
                            Ok(Value::Null)
                        })
                        .is_ok()
                })
            };
            let detacher = {
                let registry = std::sync::Arc::clone(&registry);
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    registry.detach(&name_params()).is_ok()
                })
            };
            let job_started = starter.join().unwrap();
            let detach_won = detacher.join().unwrap();
            assert!(
                !(job_started && detach_won),
                "round {round}: a job started on a pool that was just detached"
            );
            let _ = release.send(());
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn a_crashed_worker_still_settles_and_releases() {
        let (registry, dir) = registry_with_pool("settle");
        let entry = registry
            .pools
            .lock()
            .unwrap()
            .get("fence")
            .map(Arc::clone)
            .unwrap();
        let job = Arc::new(Job {
            id: 42,
            kind: "test",
            pool_name: "fence".into(),
            state: Mutex::new(JobState::Running),
        });
        entry.busy.store(42, Ordering::SeqCst);
        let settle = JobSettle {
            job: Arc::clone(&job),
            entry: Arc::clone(&entry),
        };
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _settle = settle;
            panic!("simulated settlement crash");
        }));
        assert!(unwound.is_err());
        assert!(
            matches!(&*job.state.lock().unwrap(), JobState::Failed(..)),
            "the job settled as failed"
        );
        assert_eq!(entry.busy.load(Ordering::SeqCst), 0, "the fence released");
        drop(entry);
        registry.detach(&name_params()).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn canonical_core_is_single_and_shared() {
        let (registry, dir) = registry_with_pool("one-core");
        let first = registry.share_handle("fence").unwrap();
        let second = registry.share_handle("fence").unwrap();
        let core_a = first.core.as_ref().expect("a writable pool has a core");
        let core_b = second.core.as_ref().expect("same pool, same verdict");
        assert!(
            Arc::ptr_eq(core_a, core_b),
            "two handles must share one core: the pool has ONE canonical core"
        );
        {
            let pools = registry.pools.lock().unwrap();
            let entry = pools.get("fence").unwrap();
            assert!(
                Arc::ptr_eq(core_a, entry.core.get().unwrap()),
                "the registry holds the same canonical core"
            );
        }
        drop(first);
        drop(second);
        registry.detach(&name_params()).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn read_only_pools_have_no_canonical_core() {
        let (registry, dir) = registry_with_pool("ro-core");
        registry.detach(&name_params()).unwrap();
        std::fs::remove_file(dir.join("b.img")).unwrap();
        let params = object(vec![
            ("name", Value::Str("hurt".into())),
            (
                "members",
                Value::Array(vec![Value::Str(
                    dir.join("a.img").to_string_lossy().into_owned(),
                )]),
            ),
            ("degraded", Value::Bool(true)),
        ]);
        let attached = registry.attach(&params).unwrap();
        assert_eq!(attached.get("read_only"), Some(&Value::Bool(true)));
        let handle = registry.share_handle("hurt").unwrap();
        assert!(
            handle.core.is_none(),
            "a read-only pool must not carry a read-write core"
        );
        drop(handle);
        registry
            .detach(&object(vec![("name", Value::Str("hurt".into()))]))
            .unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn detach_commits_synchronously_before_returning() {
        let (registry, dir) = registry_with_pool("sync-commit");
        let handle = registry.share_handle("fence").unwrap();
        let core = Arc::clone(handle.core.as_ref().expect("writable"));
        let pool = Arc::clone(&handle.pool);
        drop(handle);
        let before = pool.read().unwrap().committed_tx();
        core.create(scalefs_core::ROOT_INODE, "late.txt", 0o644, 0, 0)
            .unwrap();

        registry.detach(&name_params()).unwrap();
        assert!(
            pool.read().unwrap().committed_tx() > before,
            "detach must commit synchronously, not at the last Arc's drop"
        );
        let settled = pool.read().unwrap().committed_tx();
        drop(core);
        assert_eq!(
            pool.read().unwrap().committed_tx(),
            settled,
            "a straggler's late drop must not commit again"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn refused_attach_touches_nothing() {
        use scalefs_core::AllocPurpose;
        use scalefs_mount::mountcore::ORPHANAGE;

        let dir = std::env::temp_dir().join(format!(
            "scalefsd-refused-{}-{}",
            std::process::id(),
            now_ns() & 0xFFFF_FFFF,
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let geometry = Geometry {
            logical_block_size: 4096,
            physical_block_size: 4096,
            zone_size: 64 * 1024,
            zone_count: 16,
            erase_granularity_zones: 1,
            sequential_write_required: false,
        };
        let images: Vec<String> = ["a.img", "b.img"]
            .iter()
            .map(|file| dir.join(file).to_string_lossy().into_owned())
            .collect();
        let members = images
            .iter()
            .zip([0xA1u8, 0xB2])
            .map(|(path, id)| MemberSpec {
                device: FileBlockDevice::create(
                    Path::new(path),
                    scalefs_core::member_image_len(geometry.capacity_bytes()),
                )
                .unwrap(),
                device_id: DeviceId([id; 16]),
                geometry,
            })
            .collect();
        Pool::create_multi(
            members,
            PoolParams {
                pool_id: PoolId([0x66; 16]),
                case_sensitivity: CaseSensitivity::InsensitivePreserving,
                dirent_hash_seed: 7,
                label: "refused".to_string(),
                created_at_ns: now_ns(),
                mirror_width: 2,
                data_width: 1,
                parity_width: 0,
            },
        )
        .unwrap();
        let last_good = {
            let devices = images
                .iter()
                .map(|path| AnyBlockDevice::open(Path::new(path)).unwrap())
                .collect();
            let mut pool = Pool::open_multi(devices).unwrap();
            let orphanage = pool
                .mkdir(scalefs_core::ROOT_INODE, ORPHANAGE, 0o700, now_ns())
                .unwrap();
            pool.create_file(orphanage, "o-9", 0o600, now_ns()).unwrap();
            pool.commit(AllocPurpose::Normal, now_ns()).unwrap();
            pool.committed_tx()
        };
        let copies: Vec<String> = images
            .iter()
            .enumerate()
            .map(|(index, path)| {
                let copy = dir.join(format!("copy-{index}.img"));
                std::fs::copy(path, &copy).unwrap();
                copy.to_string_lossy().into_owned()
            })
            .collect();
        let params = |name: &str, members: &[String]| {
            object(vec![
                ("name", Value::Str(name.to_string())),
                (
                    "members",
                    Value::Array(members.iter().cloned().map(Value::Str).collect()),
                ),
            ])
        };

        let registry = Registry::default();
        registry.attach(&params("kept", &images)).unwrap();
        match registry.attach(&params("clone", &copies)) {
            Err((ErrorCode::Conflict, message)) => {
                assert!(message.contains("pool id"), "{message}");
            }
            other => panic!("expected conflict, got {other:?}"),
        }

        let devices = copies
            .iter()
            .map(|path| AnyBlockDevice::open(Path::new(path)).unwrap())
            .collect();
        let reopened = Pool::open_multi(devices).unwrap();
        assert_eq!(
            reopened.committed_tx(),
            last_good,
            "the refused attach committed to the images"
        );
        assert!(
            reopened.lookup(scalefs_core::ROOT_INODE, ORPHANAGE).is_ok(),
            "the refused attach swept the orphanage"
        );
        drop(reopened);
        registry
            .detach(&object(vec![("name", Value::Str("kept".into()))]))
            .unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn wrecked_detach_commits_nothing() {
        let (registry, dir) = registry_with_pool("wrecked");
        let handle = registry.share_handle("fence").unwrap();
        let core = Arc::clone(handle.core.as_ref().expect("writable"));
        let pool = Arc::clone(&handle.pool);
        drop(handle);
        let last_good = pool.read().unwrap().committed_tx();

        let started = registry
            .start_job(
                &name_params(),
                "explode",
                |_pool, _entry| -> scalefs_core::Result<Value> {
                    panic!("simulated mid-surgery crash")
                },
            )
            .unwrap();
        let id = started.get("job").unwrap().as_u64().unwrap();
        while job_state(&registry, id) == "running" {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        let _ = core.create(scalefs_core::ROOT_INODE, "garbage.txt", 0o644, 0, 0);

        let mut detached = registry.detach(&name_params());
        while matches!(detached, Err((ErrorCode::Busy, _))) {
            std::thread::sleep(std::time::Duration::from_millis(5));
            detached = registry.detach(&name_params());
        }
        detached.unwrap();
        assert_eq!(
            pool.read().unwrap().committed_tx(),
            last_good,
            "a wrecked detach committed"
        );
        drop(core);
        drop(pool);

        let devices = ["a.img", "b.img"]
            .iter()
            .map(|file| AnyBlockDevice::open(&dir.join(file)).unwrap())
            .collect();
        let reopened = Pool::open_multi(devices).unwrap();
        assert_eq!(reopened.committed_tx(), last_good);
        assert!(
            reopened
                .lookup(scalefs_core::ROOT_INODE, "garbage.txt")
                .is_err(),
            "the wrecked tree reached disk"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stale_worker_parting_never_clobbers() {
        let (registry, dir) = registry_with_pool("stale-gen");
        let entry = registry
            .pools
            .lock()
            .unwrap()
            .get("fence")
            .map(Arc::clone)
            .unwrap();
        let dummy = std::thread::spawn(|| {});
        *entry.mounted.lock().unwrap() = MountSlot::Mounted(
            2,
            ActiveMount {
                mountpoint: std::path::PathBuf::from("/tmp/fence-mnt"),
                read_only: false,
                worker: dummy,
                stop: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            },
        );
        park_ended(&entry, 1);
        assert!(
            matches!(&*entry.mounted.lock().unwrap(), MountSlot::Mounted(2, _)),
            "a stale worker clobbered a live mount's slot"
        );
        park_ended(&entry, 2);
        assert!(matches!(
            &*entry.mounted.lock().unwrap(),
            MountSlot::Ended(..)
        ));
        drop(entry);
        registry.detach(&name_params()).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detach_honors_the_mount_slot() {
        let (registry, dir) = registry_with_pool("slot-fence");
        let entry = registry
            .pools
            .lock()
            .unwrap()
            .get("fence")
            .map(Arc::clone)
            .unwrap();
        for transitional in [
            MountSlot::Mounting(7),
            MountSlot::Unmounting(7),
            MountSlot::Draining(7),
        ] {
            *entry.mounted.lock().unwrap() = transitional;
            match registry.detach(&name_params()) {
                Err((ErrorCode::Conflict, message)) => {
                    assert!(message.contains("in progress"), "{message}");
                }
                other => panic!("expected conflict, got {other:?}"),
            }
        }
        let dummy = std::thread::spawn(|| {});
        *entry.mounted.lock().unwrap() = MountSlot::Ended(7, dummy);
        drop(entry);
        registry.detach(&name_params()).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn park_drained_respects_the_generation() {
        let (registry, dir) = registry_with_pool("drained-gen");
        let entry = registry
            .pools
            .lock()
            .unwrap()
            .get("fence")
            .map(Arc::clone)
            .unwrap();
        *entry.mounted.lock().unwrap() = MountSlot::Draining(5);
        park_drained(&entry, 4);
        assert!(matches!(
            &*entry.mounted.lock().unwrap(),
            MountSlot::Draining(5)
        ));
        park_drained(&entry, 5);
        assert!(matches!(&*entry.mounted.lock().unwrap(), MountSlot::Empty));
        drop(entry);
        registry.detach(&name_params()).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_join_all_abandons_stragglers() {
        let quick1 = std::thread::spawn(|| {});
        let quick2 = std::thread::spawn(|| {});
        let (release, held) = std::sync::mpsc::channel::<()>();
        let straggler = std::thread::spawn(move || {
            let _ = held.recv();
        });
        let start = std::time::Instant::now();
        bounded_join_all(
            vec![quick1, quick2, straggler],
            std::time::Duration::from_millis(300),
        );
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "hung: {elapsed:?}"
        );
        assert!(
            elapsed >= std::time::Duration::from_millis(200),
            "returned before the deadline: {elapsed:?}",
        );
        let _ = release.send(());
    }

    fn membership_pool(tag: &str) -> (std::path::PathBuf, Vec<String>) {
        let dir = std::env::temp_dir().join(format!(
            "scalefsd-member-{}-{tag}-{}",
            std::process::id(),
            now_ns() & 0xFFFF_FFFF,
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let geometry = Geometry {
            logical_block_size: 4096,
            physical_block_size: 4096,
            zone_size: 64 * 1024,
            zone_count: 64,
            erase_granularity_zones: 1,
            sequential_write_required: false,
        };
        let images: Vec<String> = ["a.img", "b.img"]
            .iter()
            .map(|file| dir.join(file).to_string_lossy().into_owned())
            .collect();
        let members = images
            .iter()
            .zip([0xC1u8, 0xC2])
            .map(|(path, id)| MemberSpec {
                device: FileBlockDevice::create(
                    Path::new(path),
                    scalefs_core::member_image_len(geometry.capacity_bytes()),
                )
                .unwrap(),
                device_id: DeviceId([id; 16]),
                geometry,
            })
            .collect();
        let mut pool = Pool::create_multi(
            members,
            PoolParams {
                pool_id: PoolId([0x66; 16]),
                case_sensitivity: CaseSensitivity::InsensitivePreserving,
                dirent_hash_seed: 7,
                label: "memb".to_string(),
                created_at_ns: now_ns(),
                mirror_width: 2,
                data_width: 1,
                parity_width: 0,
            },
        )
        .unwrap();
        let file = pool
            .create_file(
                scalefs_core::tree::ROOT_INODE,
                "payload.bin",
                0o644,
                now_ns(),
            )
            .unwrap();
        pool.write(file, 0, &membership_payload(), now_ns())
            .unwrap();
        pool.commit(scalefs_core::AllocPurpose::Normal, now_ns())
            .unwrap();
        drop(pool);
        (dir, images)
    }

    fn membership_payload() -> Vec<u8> {
        (0..200_000u32).map(|i| (i * 31 % 251) as u8).collect()
    }

    fn membership_pool_three(tag: &str) -> (std::path::PathBuf, Vec<String>) {
        let dir = std::env::temp_dir().join(format!(
            "scalefsd-member-{}-{tag}-{}",
            std::process::id(),
            now_ns() & 0xFFFF_FFFF,
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let geometry = Geometry {
            logical_block_size: 4096,
            physical_block_size: 4096,
            zone_size: 64 * 1024,
            zone_count: 64,
            erase_granularity_zones: 1,
            sequential_write_required: false,
        };
        let images: Vec<String> = ["a.img", "b.img", "c.img"]
            .iter()
            .map(|file| dir.join(file).to_string_lossy().into_owned())
            .collect();
        let members = images
            .iter()
            .zip([0xC1u8, 0xC2, 0xC3])
            .map(|(path, id)| MemberSpec {
                device: FileBlockDevice::create(
                    Path::new(path),
                    scalefs_core::member_image_len(geometry.capacity_bytes()),
                )
                .unwrap(),
                device_id: DeviceId([id; 16]),
                geometry,
            })
            .collect();
        let mut pool = Pool::create_multi(
            members,
            PoolParams {
                pool_id: PoolId([0x67; 16]),
                case_sensitivity: CaseSensitivity::InsensitivePreserving,
                dirent_hash_seed: 7,
                label: "memb".to_string(),
                created_at_ns: now_ns(),
                mirror_width: 2,
                data_width: 1,
                parity_width: 0,
            },
        )
        .unwrap();
        let file = pool
            .create_file(
                scalefs_core::tree::ROOT_INODE,
                "payload.bin",
                0o644,
                now_ns(),
            )
            .unwrap();
        pool.write(file, 0, &membership_payload(), now_ns())
            .unwrap();
        pool.commit(scalefs_core::AllocPurpose::Normal, now_ns())
            .unwrap();
        drop(pool);
        (dir, images)
    }

    #[test]
    fn retire_returns_a_degraded_pool_to_service() {
        let (dir, images) = membership_pool_three("retire");
        std::fs::remove_file(&images[2]).unwrap();
        let registry = Registry::default();
        registry
            .attach(&attach_params("memb", &images[..2], true))
            .unwrap();
        let before = registry
            .status(&object(vec![("name", Value::Str("memb".into()))]))
            .unwrap();
        assert_eq!(before.get("degraded"), Some(&Value::Bool(true)));
        assert_eq!(before.get("read_only"), Some(&Value::Bool(true)));

        let started = registry
            .retire(&object(vec![
                ("name", Value::Str("memb".into())),
                ("member", Value::Int(2)),
            ]))
            .unwrap();
        let result = finished_job(&registry, started);
        assert_eq!(result.get("retired").and_then(Value::as_u64), Some(2));
        assert!(result.get("records_rebuilt").and_then(Value::as_u64) >= Some(1));

        let handle = registry.share_handle("memb").unwrap();
        let core = Arc::clone(
            handle
                .core
                .as_ref()
                .expect("a healed pool regains its read-write core without re-attach"),
        );
        core.create(scalefs_core::ROOT_INODE, "after-heal.txt", 0o644, 0, 0)
            .unwrap();
        core.commit().unwrap();
        drop(core);
        drop(handle);

        let status = registry
            .status(&object(vec![("name", Value::Str("memb".into()))]))
            .unwrap();
        assert_eq!(status.get("degraded"), Some(&Value::Bool(false)));
        assert_eq!(status.get("read_only"), Some(&Value::Bool(false)));
        assert_eq!(status.get("wounded"), Some(&Value::Bool(false)));
        assert_eq!(
            status
                .get("missing")
                .and_then(Value::as_array)
                .map(|missing| missing.len()),
            Some(0),
        );

        let scrubbed = finished_job(
            &registry,
            registry
                .scrub(&object(vec![("name", Value::Str("memb".into()))]))
                .unwrap(),
        );
        assert_eq!(scrubbed.get("healthy"), Some(&Value::Bool(true)));
        registry
            .detach(&object(vec![("name", Value::Str("memb".into()))]))
            .unwrap();
        registry
            .attach(&attach_params("memb", &images[..2], false))
            .unwrap();
        let strict = registry
            .status(&object(vec![("name", Value::Str("memb".into()))]))
            .unwrap();
        assert_eq!(strict.get("degraded"), Some(&Value::Bool(false)));
        assert_eq!(strict.get("read_only"), Some(&Value::Bool(false)));
        registry
            .detach(&object(vec![("name", Value::Str("memb".into()))]))
            .unwrap();

        let healed = Pool::open_multi(
            images[..2]
                .iter()
                .map(|path| Arc::new(AnyBlockDevice::open(Path::new(path)).unwrap()))
                .collect(),
        )
        .unwrap();
        assert!(
            healed
                .lookup(scalefs_core::ROOT_INODE, "after-heal.txt")
                .is_ok(),
            "the post-heal write must have committed through the restored core"
        );
        drop(healed);
        let _ = std::fs::remove_dir_all(dir);
    }

    fn attach_params(name: &str, images: &[String], degraded: bool) -> Value {
        let mut params = vec![
            ("name", Value::Str(name.into())),
            (
                "members",
                Value::Array(images.iter().cloned().map(Value::Str).collect()),
            ),
        ];
        if degraded {
            params.push(("degraded", Value::Bool(true)));
        }
        object(params)
    }

    fn finished_job(registry: &Registry, started: Value) -> Value {
        let id = started.get("job").unwrap().as_u64().unwrap();
        while job_state(registry, id) == "running" {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let status = registry
            .job_status(&object(vec![("id", Value::Int(i128::from(id)))]))
            .unwrap();
        assert_eq!(
            status.get("state").unwrap().as_str(),
            Some("done"),
            "job must succeed: {status:?}",
        );
        status.get("result").cloned().unwrap_or(Value::Null)
    }

    #[test]
    fn replace_heals_a_degraded_pool_and_rebuilds() {
        let (dir, images) = membership_pool("replace");
        std::fs::remove_file(&images[1]).unwrap();
        let registry = Registry::default();
        registry
            .attach(&attach_params("memb", &images[..1], true))
            .unwrap();
        let before = registry
            .status(&object(vec![("name", Value::Str("memb".into()))]))
            .unwrap();
        assert_eq!(before.get("degraded"), Some(&Value::Bool(true)));

        let target = dir.join("c.img").to_string_lossy().into_owned();
        let started = registry
            .replace(&object(vec![
                ("name", Value::Str("memb".into())),
                ("target", Value::Str(target.clone())),
                ("size", Value::Int(4 << 20)),
            ]))
            .unwrap();
        let result = finished_job(&registry, started);
        assert_eq!(result.get("rebuilt"), Some(&Value::Bool(true)));
        assert_eq!(result.get("replaced").and_then(Value::as_u64), Some(1));
        assert!(result.get("records_rebuilt").and_then(Value::as_u64) >= Some(1));

        let handle = registry.share_handle("memb").unwrap();
        let core = Arc::clone(
            handle
                .core
                .as_ref()
                .expect("a replaced-and-rebuilt pool regains its read-write core"),
        );
        core.create(scalefs_core::ROOT_INODE, "after-heal.txt", 0o644, 0, 0)
            .unwrap();
        core.commit().unwrap();
        drop(core);
        drop(handle);

        let status = registry
            .status(&object(vec![("name", Value::Str("memb".into()))]))
            .unwrap();
        assert_eq!(status.get("degraded"), Some(&Value::Bool(false)));
        assert_eq!(status.get("read_only"), Some(&Value::Bool(false)));
        assert_eq!(
            status
                .get("missing")
                .and_then(Value::as_array)
                .map(|missing| missing.len()),
            Some(0),
        );
        let images_now = status.get("images").and_then(Value::as_array).unwrap();
        assert!(
            images_now.iter().any(|path| path.as_str() == Some(&target)),
            "the images list must adopt the replacement",
        );
        let media = status.get("media").and_then(Value::as_array).unwrap();
        assert!(
            media.iter().any(|row| {
                row.get("path").and_then(Value::as_str) == Some(&target)
                    && row.get("device_id").and_then(Value::as_str).is_some()
            }),
            "the media rows must carry the new member's device id",
        );

        let scrubbed = finished_job(
            &registry,
            registry
                .scrub(&object(vec![("name", Value::Str("memb".into()))]))
                .unwrap(),
        );
        assert_eq!(scrubbed.get("healthy"), Some(&Value::Bool(true)));
        registry
            .detach(&object(vec![("name", Value::Str("memb".into()))]))
            .unwrap();

        let healed = Pool::open_multi(vec![
            Arc::new(AnyBlockDevice::open(Path::new(&images[0])).unwrap()),
            Arc::new(AnyBlockDevice::open(Path::new(&target)).unwrap()),
        ])
        .unwrap();
        let entry = healed
            .lookup(scalefs_core::tree::ROOT_INODE, "payload.bin")
            .unwrap();
        let bytes = healed
            .read(entry.inode, 0, membership_payload().len())
            .unwrap();
        assert_eq!(bytes, membership_payload(), "healed bytes must match");
        assert!(
            healed
                .lookup(scalefs_core::ROOT_INODE, "after-heal.txt")
                .is_ok(),
            "the post-heal write must have committed through the restored core"
        );
        drop(healed);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn add_grows_and_remove_evacuates() {
        let (dir, images) = membership_pool("addrm");
        let registry = Registry::default();
        registry
            .attach(&attach_params("memb", &images, false))
            .unwrap();

        let target = dir.join("c.img").to_string_lossy().into_owned();
        let added = finished_job(
            &registry,
            registry
                .add(&object(vec![
                    ("name", Value::Str("memb".into())),
                    ("target", Value::Str(target.clone())),
                    ("size", Value::Int(4 << 20)),
                ]))
                .unwrap(),
        );
        let new_member = added.get("member").and_then(Value::as_u64).unwrap();
        assert_eq!(new_member, 2);
        let status = registry
            .status(&object(vec![("name", Value::Str("memb".into()))]))
            .unwrap();
        assert_eq!(status.get("members").and_then(Value::as_u64), Some(3));
        let detail = status
            .get("members_detail")
            .and_then(Value::as_array)
            .unwrap();
        let added_id = detail
            .iter()
            .find(|row| row.get("index").and_then(Value::as_u64) == Some(new_member))
            .and_then(|row| row.get("device_id"))
            .and_then(Value::as_str)
            .unwrap()
            .to_string();

        let removed = finished_job(
            &registry,
            registry
                .remove(&object(vec![
                    ("name", Value::Str("memb".into())),
                    ("member", Value::Str(added_id.clone())),
                ]))
                .unwrap(),
        );
        assert_eq!(removed.get("removed").and_then(Value::as_u64), Some(2));
        assert_eq!(
            removed.get("device_id").and_then(Value::as_str),
            Some(added_id.as_str()),
        );
        let status = registry
            .status(&object(vec![("name", Value::Str("memb".into()))]))
            .unwrap();
        let detail = status
            .get("members_detail")
            .and_then(Value::as_array)
            .unwrap();
        assert!(
            detail
                .iter()
                .any(|row| row.get("state").and_then(Value::as_str) == Some("removed")),
            "the roster must show the retirement",
        );
        let images_now = status.get("images").and_then(Value::as_array).unwrap();
        assert!(
            !images_now.iter().any(|path| path.as_str() == Some(&target)),
            "the images list must drop the removed member",
        );
        registry
            .detach(&object(vec![("name", Value::Str("memb".into()))]))
            .unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn membership_targets_need_consent_and_freedom() {
        let (dir, images) = membership_pool("consent");
        let registry = Registry::default();
        registry
            .attach(&attach_params("memb", &images, false))
            .unwrap();

        let taken = dir.join("taken.img").to_string_lossy().into_owned();
        std::fs::write(&taken, b"not yours").unwrap();
        match registry.add(&object(vec![
            ("name", Value::Str("memb".into())),
            ("target", Value::Str(taken.clone())),
            ("size", Value::Int(4 << 20)),
        ])) {
            Err((ErrorCode::Conflict, message)) => {
                assert!(message.contains("force"), "{message}");
            }
            other => panic!("expected conflict, got {other:?}"),
        }

        match registry.replace(&object(vec![
            ("name", Value::Str("memb".into())),
            ("target", Value::Str(images[0].clone())),
            ("force", Value::Bool(true)),
        ])) {
            Err((ErrorCode::Conflict, message)) => {
                assert!(message.contains("memb"), "{message}");
            }
            other => panic!("expected conflict, got {other:?}"),
        }

        let added = finished_job(
            &registry,
            registry
                .add(&object(vec![
                    ("name", Value::Str("memb".into())),
                    ("target", Value::Str(taken)),
                    ("size", Value::Int(4 << 20)),
                    ("force", Value::Bool(true)),
                ]))
                .unwrap(),
        );
        assert_eq!(added.get("member").and_then(Value::as_u64), Some(2));

        match registry.remove(&object(vec![("name", Value::Str("memb".into()))])) {
            Err((ErrorCode::BadRequest, message)) => {
                assert!(message.contains("member"), "{message}");
            }
            other => panic!("expected bad_request, got {other:?}"),
        }
        registry
            .detach(&object(vec![("name", Value::Str("memb".into()))]))
            .unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn membership_changes_update_the_recorded_state() {
        let (dir, images) = membership_pool("state");
        let store = Arc::new(crate::state::StateStore::open(&dir.join("state")).unwrap());
        let registry = Registry::with_state(Some(Arc::clone(&store)));
        registry
            .attach(&attach_params("memb", &images, false))
            .unwrap();
        assert_eq!(store.load()[0].members, images);

        let target = dir.join("c.img").to_string_lossy().into_owned();
        finished_job(
            &registry,
            registry
                .add(&object(vec![
                    ("name", Value::Str("memb".into())),
                    ("target", Value::Str(target.clone())),
                    ("size", Value::Int(4 << 20)),
                ]))
                .unwrap(),
        );
        let recorded = store.load();
        assert!(
            recorded[0].members.contains(&target),
            "the record must adopt the new member",
        );
        registry
            .detach(&object(vec![("name", Value::Str("memb".into()))]))
            .unwrap();
        assert!(store.load().is_empty(), "detach must clear the record");
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[cfg(test)]
#[path = "pools_fault_tests.rs"]
mod fault_tests;
