use std::io::Write;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

macro_rules! counters {
    ($($id:ident),* $(,)?) => {
        #[derive(Clone, Copy, Debug)]
        #[repr(usize)]
        #[allow(missing_docs)]
        pub enum C { $($id),* }
        const NAMES: &[&str] = &[$(stringify!($id)),*];
    };
}

counters!(
    DevRead,
    DevWrite,
    DevFlush,
    FlushGroup,
    PoolReadWait,
    PoolWriteWait,
    Getattr,
    Lookup,
    Readdir,
    Read,
    Write,
    Create,
    Mkdir,
    Unlink,
    Rmdir,
    Rename,
    UnlinkHandle,
    Setattr,
    Release,
    Statfs,
    Walk,
    OtherMut,
    CommitGroup,
    CommitPlan,
    CommitExecute,
    CommitPublish,
    CommitIo,
);

const N: usize = NAMES.len();

#[derive(Clone, Copy, Debug)]
#[repr(usize)]
pub enum Surface {
    Dataplane = 0,
    Fuse = 1,
    Smb = 2,
}

const SURFACE_NAMES: [&str; 3] = ["dp", "fuse", "smb"];
const OPS: usize = 256;

struct Slot {
    calls: AtomicU64,
    nanos: AtomicU64,
    bytes: AtomicU64,
}

impl Slot {
    const fn new() -> Slot {
        Slot {
            calls: AtomicU64::new(0),
            nanos: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
        }
    }
}

static STATE: AtomicU8 = AtomicU8::new(0);
static SLOTS: [Slot; N] = [const { Slot::new() }; N];
static OP_SLOTS: [[Slot; OPS]; 3] = [const { [const { Slot::new() }; OPS] }; 3];
static LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());

#[inline]
pub fn enabled() -> bool {
    match STATE.load(Ordering::Relaxed) {
        2 => true,
        1 => false,
        _ => init(),
    }
}

#[cold]
fn init() -> bool {
    static ONCE: OnceLock<bool> = OnceLock::new();
    *ONCE.get_or_init(|| {
        let on = match std::env::var_os("SCALEFS_PERF_TRACE") {
            Some(path) if !path.is_empty() => {
                match std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                {
                    Ok(file) => std::thread::Builder::new()
                        .name("scalefs-perftrace".to_string())
                        .spawn(move || flusher(file))
                        .is_ok(),
                    Err(_) => false,
                }
            }
            _ => false,
        };
        STATE.store(if on { 2 } else { 1 }, Ordering::Relaxed);
        on
    })
}

#[inline]
pub fn add(counter: C, nanos: u64, bytes: u64) {
    if !enabled() {
        return;
    }
    let slot = &SLOTS[counter as usize];
    slot.calls.fetch_add(1, Ordering::Relaxed);
    slot.nanos.fetch_add(nanos, Ordering::Relaxed);
    slot.bytes.fetch_add(bytes, Ordering::Relaxed);
}

#[must_use]
pub struct Timer(Option<(C, Instant, u64)>);

impl Timer {
    pub fn set_bytes(&mut self, bytes: u64) {
        if let Some((_, _, b)) = &mut self.0 {
            *b = bytes;
        }
    }
}

#[inline]
pub fn start(counter: C, bytes: u64) -> Timer {
    if enabled() {
        Timer(Some((counter, Instant::now(), bytes)))
    } else {
        Timer(None)
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        if let Some((counter, started, bytes)) = self.0.take() {
            add(counter, started.elapsed().as_nanos() as u64, bytes);
        }
    }
}

#[must_use]
pub struct OpTimer(Option<(Surface, usize, Instant)>);

#[inline]
pub fn op(surface: Surface, code: u32) -> OpTimer {
    if enabled() {
        OpTimer(Some((
            surface,
            (code as usize).min(OPS - 1),
            Instant::now(),
        )))
    } else {
        OpTimer(None)
    }
}

impl Drop for OpTimer {
    fn drop(&mut self) {
        if let Some((surface, code, started)) = self.0.take() {
            let slot = &OP_SLOTS[surface as usize][code];
            slot.calls.fetch_add(1, Ordering::Relaxed);
            slot.nanos
                .fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
        }
    }
}

pub fn line(build: impl FnOnce() -> String) {
    if !enabled() {
        return;
    }
    let text = build();
    if let Ok(mut lines) = LINES.lock() {
        lines.push(text);
    }
}

pub fn unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

fn snapshot() -> (u64, String) {
    let mut total = 0u64;
    let mut out = String::new();
    for (index, name) in NAMES.iter().enumerate() {
        let slot = &SLOTS[index];
        let calls = slot.calls.load(Ordering::Relaxed);
        if calls == 0 {
            continue;
        }
        total = total.wrapping_add(calls);
        out.push_str(&format!(
            " {name}={calls}/{}/{}",
            slot.nanos.load(Ordering::Relaxed),
            slot.bytes.load(Ordering::Relaxed)
        ));
    }
    for (surface, slots) in OP_SLOTS.iter().enumerate() {
        for (code, slot) in slots.iter().enumerate() {
            let calls = slot.calls.load(Ordering::Relaxed);
            if calls == 0 {
                continue;
            }
            total = total.wrapping_add(calls);
            out.push_str(&format!(
                " {}.{code}={calls}/{}",
                SURFACE_NAMES[surface],
                slot.nanos.load(Ordering::Relaxed)
            ));
        }
    }
    (total, out)
}

fn flusher(file: std::fs::File) {
    let mut out = std::io::BufWriter::new(file);
    let _ = writeln!(
        out,
        "# scalefs perftrace pid {} start {}",
        std::process::id(),
        unix_ns()
    );
    let _ = out.flush();
    let mut last_total = u64::MAX;
    let mut last_write = Instant::now();
    loop {
        std::thread::sleep(Duration::from_millis(200));
        let lines = LINES
            .lock()
            .map(|mut lines| std::mem::take(&mut *lines))
            .unwrap_or_default();
        for text in &lines {
            let _ = writeln!(out, "{text}");
        }
        let (total, body) = snapshot();
        if total != last_total || last_write.elapsed() >= Duration::from_secs(5) {
            let _ = writeln!(out, "S {}{body}", unix_ns());
            last_total = total;
            last_write = Instant::now();
        }
        let _ = out.flush();
    }
}
