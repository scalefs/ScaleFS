use crate::device::{BlockDevice, MemoryBlockDevice, check_bounds};
use crate::error::{Result, ScaleFsError};
use crate::rng::XorShift64;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, Ordering};

pub const DEFAULT_ATOMIC_UNIT: usize = 4096;

#[derive(Debug, Clone)]
struct PendingChunk {
    offset: u64,
    data: Vec<u8>,
}

#[derive(Debug, Clone)]
struct TortureState {
    committed: Vec<u8>,
    pending: Vec<PendingChunk>,
}

#[derive(Debug)]
pub struct TortureBlockDevice {
    state: Mutex<TortureState>,
    atomic_unit: usize,
}

impl Clone for TortureBlockDevice {
    fn clone(&self) -> Self {
        Self {
            state: Mutex::new(self.state.lock().expect("torture device lock").clone()),
            atomic_unit: self.atomic_unit,
        }
    }
}

impl TortureBlockDevice {
    pub fn new(len: usize) -> Self {
        Self::with_atomic_unit(len, DEFAULT_ATOMIC_UNIT)
    }

    pub fn with_atomic_unit(len: usize, atomic_unit: usize) -> Self {
        Self::from_image(vec![0; len], atomic_unit)
    }

    pub fn from_image(image: Vec<u8>, atomic_unit: usize) -> Self {
        assert!(atomic_unit > 0, "atomic unit must be nonzero");
        Self {
            state: Mutex::new(TortureState {
                committed: image,
                pending: Vec::new(),
            }),
            atomic_unit,
        }
    }

    pub fn pending_chunks(&self) -> usize {
        self.state
            .lock()
            .expect("torture device lock")
            .pending
            .len()
    }

    pub fn crash_image(&self, seed: u64) -> MemoryBlockDevice {
        let state = self.state.lock().expect("torture device lock");
        let mut rng = XorShift64::new(seed);
        let mut image = state.committed.clone();
        for chunk in &state.pending {
            if rng.next_bool() {
                apply(&mut image, chunk);
            }
        }
        MemoryBlockDevice::from_bytes(image)
    }

    pub fn all_crash_images(&self) -> Vec<MemoryBlockDevice> {
        let state = self.state.lock().expect("torture device lock");
        let n = state.pending.len();
        assert!(
            n <= 16,
            "{n} pending chunks is too many for exhaustive enumeration; \
             use crash_image(seed) sampling instead"
        );
        (0u32..1 << n)
            .map(|mask| {
                let mut image = state.committed.clone();
                for (i, chunk) in state.pending.iter().enumerate() {
                    if mask & (1 << i) != 0 {
                        apply(&mut image, chunk);
                    }
                }
                MemoryBlockDevice::from_bytes(image)
            })
            .collect()
    }
}

fn apply(image: &mut [u8], chunk: &PendingChunk) {
    let start = chunk.offset as usize;
    image[start..start + chunk.data.len()].copy_from_slice(&chunk.data);
}

impl BlockDevice for TortureBlockDevice {
    fn len(&self) -> u64 {
        self.state
            .lock()
            .expect("torture device lock")
            .committed
            .len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_bounds(offset, buf.len(), self.len())?;
        let state = self.state.lock().expect("torture device lock");
        let start = offset as usize;
        buf.copy_from_slice(&state.committed[start..start + buf.len()]);
        let (req_start, req_end) = (offset, offset + buf.len() as u64);
        for chunk in &state.pending {
            let (c_start, c_end) = (chunk.offset, chunk.offset + chunk.data.len() as u64);
            let overlap_start = req_start.max(c_start);
            let overlap_end = req_end.min(c_end);
            if overlap_start < overlap_end {
                let dst = (overlap_start - req_start) as usize;
                let src = (overlap_start - c_start) as usize;
                let len = (overlap_end - overlap_start) as usize;
                buf[dst..dst + len].copy_from_slice(&chunk.data[src..src + len]);
            }
        }
        Ok(())
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
        check_bounds(offset, data.len(), self.len())?;
        let mut state = self.state.lock().expect("torture device lock");
        let unit = self.atomic_unit as u64;
        let mut pos = 0usize;
        while pos < data.len() {
            let abs = offset + pos as u64;
            let unit_end = (abs / unit + 1) * unit;
            let piece_len = ((unit_end - abs) as usize).min(data.len() - pos);
            state.pending.push(PendingChunk {
                offset: abs,
                data: data[pos..pos + piece_len].to_vec(),
            });
            pos += piece_len;
        }
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        let mut state = self.state.lock().expect("torture device lock");
        let pending = std::mem::take(&mut state.pending);
        for chunk in &pending {
            apply(&mut state.committed, chunk);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Write { offset: u64, data: Vec<u8> },
    Flush,
}

#[derive(Debug)]
pub struct RecordingBlockDevice<D: BlockDevice> {
    inner: D,
    recorded: Mutex<Vec<(Op, u64)>>,
    sequence: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl<D: BlockDevice> RecordingBlockDevice<D> {
    pub fn new(inner: D) -> Self {
        Self::with_shared_sequence(inner, std::sync::Arc::default())
    }

    pub fn with_shared_sequence(
        inner: D,
        sequence: std::sync::Arc<std::sync::atomic::AtomicU64>,
    ) -> Self {
        Self {
            inner,
            recorded: Mutex::new(Vec::new()),
            sequence,
        }
    }

    pub fn ops(&self) -> Vec<Op> {
        self.recorded
            .lock()
            .expect("recording device lock")
            .iter()
            .map(|(op, _)| op.clone())
            .collect()
    }

    pub fn sequenced_ops(&self) -> Vec<(u64, Op)> {
        self.recorded
            .lock()
            .expect("recording device lock")
            .iter()
            .map(|(op, seq)| (*seq, op.clone()))
            .collect()
    }

    pub fn into_inner(self) -> D {
        self.inner
    }

    fn stamp(&self, op: Op) {
        let seq = self
            .sequence
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.recorded
            .lock()
            .expect("recording device lock")
            .push((op, seq));
    }
}

impl<D: BlockDevice> BlockDevice for RecordingBlockDevice<D> {
    fn len(&self) -> u64 {
        self.inner.len()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.inner.read_at(offset, buf)
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
        self.inner.write_at(offset, data)?;
        self.stamp(Op::Write {
            offset,
            data: data.to_vec(),
        });
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        self.inner.flush()?;
        self.stamp(Op::Flush);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct FaultDevice {
    backing: Arc<MemoryBlockDevice>,
    mode: Arc<AtomicU8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultMode {
    Healthy,
    Failing,
}

impl FaultMode {
    fn code(self) -> u8 {
        match self {
            FaultMode::Healthy => 0,
            FaultMode::Failing => 1,
        }
    }

    fn from_code(code: u8) -> FaultMode {
        match code {
            0 => FaultMode::Healthy,
            _ => FaultMode::Failing,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FaultSwitch {
    mode: Arc<AtomicU8>,
}

impl FaultSwitch {
    pub fn set(&self, mode: FaultMode) {
        self.mode.store(mode.code(), Ordering::SeqCst);
    }

    pub fn get(&self) -> FaultMode {
        FaultMode::from_code(self.mode.load(Ordering::SeqCst))
    }

    pub fn fail(&self) {
        self.set(FaultMode::Failing);
    }

    pub fn heal(&self) {
        self.set(FaultMode::Healthy);
    }

    pub fn is_failing(&self) -> bool {
        self.get() == FaultMode::Failing
    }
}

impl FaultDevice {
    pub fn new(len: usize) -> FaultDevice {
        FaultDevice::over(Arc::new(MemoryBlockDevice::new(len)))
    }

    pub fn over(backing: Arc<MemoryBlockDevice>) -> FaultDevice {
        FaultDevice {
            backing,
            mode: Arc::new(AtomicU8::new(FaultMode::Healthy.code())),
        }
    }

    pub fn switch(&self) -> FaultSwitch {
        FaultSwitch {
            mode: Arc::clone(&self.mode),
        }
    }

    pub fn backing(&self) -> Arc<MemoryBlockDevice> {
        Arc::clone(&self.backing)
    }

    fn failing(&self) -> bool {
        self.mode.load(Ordering::SeqCst) != FaultMode::Healthy.code()
    }

    fn offline() -> ScaleFsError {
        ScaleFsError::Io(std::io::Error::other("fault-injected: member offline"))
    }
}

impl BlockDevice for FaultDevice {
    fn len(&self) -> u64 {
        self.backing.len()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if self.failing() {
            return Err(Self::offline());
        }
        self.backing.read_at(offset, buf)
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
        if self.failing() {
            return Err(Self::offline());
        }
        self.backing.write_at(offset, data)
    }

    fn flush(&self) -> Result<()> {
        if self.failing() {
            return Err(Self::offline());
        }
        self.backing.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read4(dev: &MemoryBlockDevice, offset: u64) -> [u8; 4] {
        let mut buf = [0u8; 4];
        dev.read_at(offset, &mut buf).unwrap();
        buf
    }

    #[test]
    fn flushed_writes_survive_every_crash() {
        let dev = TortureBlockDevice::with_atomic_unit(64, 16);
        dev.write_at(0, b"AAAA").unwrap();
        dev.flush().unwrap();
        assert_eq!(dev.pending_chunks(), 0);
        for image in dev.all_crash_images() {
            assert_eq!(&read4(&image, 0), b"AAAA");
        }
        assert_eq!(&read4(&dev.crash_image(7), 0), b"AAAA");
    }

    #[test]
    fn unbarriered_dependent_writes_can_tear() {
        let dev = TortureBlockDevice::with_atomic_unit(64, 16);
        dev.write_at(0, b"DATA").unwrap();
        dev.write_at(16, b"CMMT").unwrap();
        let images = dev.all_crash_images();
        assert_eq!(images.len(), 4);
        let torn = images
            .iter()
            .any(|img| &read4(img, 16) == b"CMMT" && &read4(img, 0) != b"DATA");
        assert!(torn, "harness must produce the commit-without-data state");
    }

    #[test]
    fn barrier_prevents_commit_without_data() {
        let dev = TortureBlockDevice::with_atomic_unit(64, 16);
        dev.write_at(0, b"DATA").unwrap();
        dev.flush().unwrap();
        dev.write_at(16, b"CMMT").unwrap();
        for image in dev.all_crash_images() {
            if &read4(&image, 16) == b"CMMT" {
                assert_eq!(&read4(&image, 0), b"DATA");
            }
        }
    }

    #[test]
    fn writes_spanning_atomic_units_can_tear_mid_write() {
        let dev = TortureBlockDevice::with_atomic_unit(64, 4);
        dev.write_at(2, b"XXXX").unwrap();
        assert_eq!(dev.pending_chunks(), 2);
        let images = dev.all_crash_images();
        let front_only = images.iter().any(|img| {
            let mut buf = [0u8; 4];
            img.read_at(2, &mut buf).unwrap();
            buf == *b"XX\0\0"
        });
        assert!(front_only, "torn front half must be reachable");
    }

    #[test]
    fn later_write_wins_when_both_persist() {
        let dev = TortureBlockDevice::with_atomic_unit(64, 16);
        dev.write_at(0, b"XXXX").unwrap();
        dev.write_at(0, b"YYYY").unwrap();
        let images = dev.all_crash_images();
        assert_eq!(&read4(&images[0b11], 0), b"YYYY");
        let mut buf = [0u8; 4];
        dev.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"YYYY");
    }

    #[test]
    fn live_reads_see_pending_writes() {
        let dev = TortureBlockDevice::new(8192);
        dev.write_at(4090, b"spanning").unwrap();
        let mut buf = [0u8; 8];
        dev.read_at(4090, &mut buf).unwrap();
        assert_eq!(&buf, b"spanning");
    }
}
