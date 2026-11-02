use std::fs::{File, OpenOptions};
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::error::{Result, ScaleFsError};

pub trait BlockDevice {
    fn len(&self) -> u64;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()>;

    fn write_at(&self, offset: u64, data: &[u8]) -> Result<()>;

    fn flush(&self) -> Result<()>;

    fn flush_group(devices: &[&Self]) -> Result<()>
    where
        Self: Sized,
    {
        for device in devices {
            device.flush()?;
        }
        Ok(())
    }

    fn actuator_ranges(&self) -> Vec<std::ops::Range<u64>> {
        Vec::new()
    }

    fn sector_size(&self) -> u32 {
        512
    }
}

impl<D: BlockDevice + ?Sized> BlockDevice for &D {
    fn len(&self) -> u64 {
        (**self).len()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        (**self).read_at(offset, buf)
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
        (**self).write_at(offset, data)
    }

    fn flush(&self) -> Result<()> {
        (**self).flush()
    }

    fn actuator_ranges(&self) -> Vec<std::ops::Range<u64>> {
        (**self).actuator_ranges()
    }

    fn sector_size(&self) -> u32 {
        (**self).sector_size()
    }
}

impl<D: BlockDevice + ?Sized> BlockDevice for &mut D {
    fn len(&self) -> u64 {
        (**self).len()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        (**self).read_at(offset, buf)
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
        (**self).write_at(offset, data)
    }

    fn flush(&self) -> Result<()> {
        (**self).flush()
    }

    fn actuator_ranges(&self) -> Vec<std::ops::Range<u64>> {
        (**self).actuator_ranges()
    }

    fn sector_size(&self) -> u32 {
        (**self).sector_size()
    }
}

impl<D: BlockDevice> BlockDevice for Arc<D> {
    fn len(&self) -> u64 {
        (**self).len()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        (**self).read_at(offset, buf)
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
        (**self).write_at(offset, data)
    }

    fn flush(&self) -> Result<()> {
        (**self).flush()
    }

    fn flush_group(devices: &[&Self]) -> Result<()> {
        let inner: Vec<&D> = devices.iter().map(|device| &***device).collect();
        D::flush_group(&inner)
    }

    fn actuator_ranges(&self) -> Vec<std::ops::Range<u64>> {
        (**self).actuator_ranges()
    }

    fn sector_size(&self) -> u32 {
        (**self).sector_size()
    }
}

pub trait SharedDevice: BlockDevice + Clone {}

impl<D: BlockDevice> SharedDevice for Arc<D> {}

pub struct ReadOnly<D>(D);

impl<D: BlockDevice> ReadOnly<D> {
    pub fn new(device: D) -> ReadOnly<D> {
        ReadOnly(device)
    }
}

impl<D: BlockDevice> BlockDevice for ReadOnly<D> {
    fn len(&self) -> u64 {
        self.0.len()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.0.read_at(offset, buf)
    }

    fn write_at(&self, _offset: u64, _data: &[u8]) -> Result<()> {
        Err(ScaleFsError::Unsupported("this handle is read-only"))
    }

    fn flush(&self) -> Result<()> {
        Err(ScaleFsError::Unsupported("this handle is read-only"))
    }

    fn actuator_ranges(&self) -> Vec<std::ops::Range<u64>> {
        self.0.actuator_ranges()
    }

    fn sector_size(&self) -> u32 {
        self.0.sector_size()
    }
}

#[derive(Debug, Clone)]
pub struct PartitionView<D> {
    inner: D,
    start: u64,
    len: u64,
}

impl<D: BlockDevice> PartitionView<D> {
    pub fn new(inner: D, start: u64, len: u64) -> Result<Self> {
        let end = start
            .checked_add(len)
            .ok_or(ScaleFsError::Corrupt("partition overflows the device"))?;
        if end > inner.len() {
            return Err(ScaleFsError::Corrupt(
                "partition reaches past the device end",
            ));
        }
        Ok(Self { inner, start, len })
    }

    pub fn into_inner(self) -> D {
        self.inner
    }

    pub fn inner(&self) -> &D {
        &self.inner
    }

    pub fn start(&self) -> u64 {
        self.start
    }
}

impl<D: BlockDevice> BlockDevice for PartitionView<D> {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_bounds(offset, buf.len(), self.len)?;
        self.inner.read_at(self.start + offset, buf)
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
        check_bounds(offset, data.len(), self.len)?;
        self.inner.write_at(self.start + offset, data)
    }

    fn flush(&self) -> Result<()> {
        self.inner.flush()
    }

    fn flush_group(devices: &[&Self]) -> Result<()> {
        let inner: Vec<&D> = devices.iter().map(|view| &view.inner).collect();
        D::flush_group(&inner)
    }

    fn actuator_ranges(&self) -> Vec<std::ops::Range<u64>> {
        self.inner
            .actuator_ranges()
            .into_iter()
            .filter_map(|range| {
                let start = range.start.max(self.start) - self.start;
                let end = range
                    .end
                    .min(self.start + self.len)
                    .saturating_sub(self.start);
                (start < end).then_some(start..end)
            })
            .collect()
    }

    fn sector_size(&self) -> u32 {
        self.inner.sector_size()
    }
}

impl<D: SharedDevice> SharedDevice for PartitionView<D> {}

pub(crate) fn check_bounds(offset: u64, len: usize, device_len: u64) -> Result<()> {
    let len = len as u64;
    let end = offset.checked_add(len).ok_or(ScaleFsError::OutOfBounds {
        offset,
        len,
        device_len,
    })?;
    if end > device_len {
        return Err(ScaleFsError::OutOfBounds {
            offset,
            len,
            device_len,
        });
    }
    Ok(())
}

#[derive(Debug)]
pub struct MemoryBlockDevice {
    bytes: Mutex<Vec<u8>>,
    len: u64,
}

impl Clone for MemoryBlockDevice {
    fn clone(&self) -> Self {
        Self::from_bytes(self.bytes())
    }
}

impl MemoryBlockDevice {
    pub fn new(len: usize) -> Self {
        Self::from_bytes(vec![0; len])
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let len = bytes.len() as u64;
        Self {
            bytes: Mutex::new(bytes),
            len,
        }
    }

    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.lock().expect("memory device lock").clone()
    }
}

impl BlockDevice for MemoryBlockDevice {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_bounds(offset, buf.len(), self.len())?;
        let bytes = self.bytes.lock().expect("memory device lock");
        let start = offset as usize;
        buf.copy_from_slice(&bytes[start..start + buf.len()]);
        Ok(())
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
        check_bounds(offset, data.len(), self.len())?;
        let mut bytes = self.bytes.lock().expect("memory device lock");
        let start = offset as usize;
        bytes[start..start + data.len()].copy_from_slice(data);
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
pub struct FileBlockDevice {
    file: File,
    len: u64,
    _claim: File,
}

impl FileBlockDevice {
    pub fn create(path: &Path, len: u64) -> Result<Self> {
        let claim = claim_image(path)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.set_len(len)?;
        Ok(Self {
            file,
            len,
            _claim: claim,
        })
    }

    pub fn open(path: &Path) -> Result<Self> {
        let claim = claim_image(path)?;
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let len = file.metadata()?.len();
        Ok(Self {
            file,
            len,
            _claim: claim,
        })
    }
}

fn claim_image(path: &Path) -> Result<File> {
    let mut lock_path = path.as_os_str().to_owned();
    lock_path.push(".lock");
    let claim = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;
    claim.try_lock().map_err(|error| {
        ScaleFsError::Io(match error {
            std::fs::TryLockError::WouldBlock => std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                format!("{} is in use by another scalefs process", path.display()),
            ),
            std::fs::TryLockError::Error(error) => error,
        })
    })?;
    Ok(claim)
}

impl Drop for FileBlockDevice {
    fn drop(&mut self) {
        let _ = self._claim.unlock();
    }
}

impl BlockDevice for FileBlockDevice {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_bounds(offset, buf.len(), self.len)?;
        read_exact_at(&self.file, offset, buf)
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
        check_bounds(offset, data.len(), self.len)?;
        write_all_at(&self.file, offset, data)
    }

    fn flush(&self) -> Result<()> {
        self.file.sync_all()?;
        Ok(())
    }
}

#[cfg(unix)]
pub(crate) fn read_exact_at(file: &File, offset: u64, buf: &mut [u8]) -> Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset)?;
    Ok(())
}

#[cfg(unix)]
pub(crate) fn write_all_at(file: &File, offset: u64, data: &[u8]) -> Result<()> {
    use std::os::unix::fs::FileExt;
    file.write_all_at(data, offset)?;
    Ok(())
}

#[cfg(windows)]
pub(crate) fn read_exact_at(file: &File, mut offset: u64, mut buf: &mut [u8]) -> Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let n = file.seek_read(buf, offset)?;
        if n == 0 {
            return Err(ScaleFsError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected end of file",
            )));
        }
        offset += n as u64;
        buf = &mut buf[n..];
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn write_all_at(file: &File, mut offset: u64, mut data: &[u8]) -> Result<()> {
    use std::os::windows::fs::FileExt;
    while !data.is_empty() {
        let n = file.seek_write(data, offset)?;
        if n == 0 {
            return Err(ScaleFsError::Io(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "wrote zero bytes",
            )));
        }
        offset += n as u64;
        data = &data[n..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TempPath(PathBuf);

    impl TempPath {
        fn new(tag: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("scalefs-test-{}-{tag}-{n}.bin", std::process::id()));
            Self(path)
        }
    }

    impl Drop for TempPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            let mut lock = self.0.as_os_str().to_owned();
            lock.push(".lock");
            let _ = std::fs::remove_file(&lock);
        }
    }

    #[test]
    fn images_take_a_single_writer_claim() {
        let temp = TempPath::new("claim");
        let held = FileBlockDevice::create(&temp.0, 4096).unwrap();
        held.write_at(100, b"keep").unwrap();
        held.flush().unwrap();

        assert!(
            matches!(FileBlockDevice::open(&temp.0), Err(ScaleFsError::Io(_))),
            "a second writable open must refuse"
        );
        assert!(
            matches!(
                FileBlockDevice::create(&temp.0, 4096),
                Err(ScaleFsError::Io(_))
            ),
            "a second create must refuse"
        );
        let mut buf = [0u8; 4];
        held.read_at(100, &mut buf).unwrap();
        assert_eq!(&buf, b"keep", "the refused create truncated a held image");

        drop(held);
        let reopened = FileBlockDevice::open(&temp.0).unwrap();
        let mut buf = [0u8; 4];
        reopened.read_at(100, &mut buf).unwrap();
        assert_eq!(&buf, b"keep");
    }

    #[test]
    fn memory_device_round_trips() {
        let dev = MemoryBlockDevice::new(1024);
        dev.write_at(100, b"hello").unwrap();
        let mut buf = [0u8; 5];
        dev.read_at(100, &mut buf).unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn out_of_bounds_is_rejected() {
        let dev = MemoryBlockDevice::new(16);
        assert!(matches!(
            dev.write_at(12, b"12345"),
            Err(ScaleFsError::OutOfBounds { .. })
        ));
        let mut buf = [0u8; 1];
        assert!(matches!(
            dev.read_at(16, &mut buf),
            Err(ScaleFsError::OutOfBounds { .. })
        ));
        assert!(matches!(
            dev.write_at(u64::MAX, b"x"),
            Err(ScaleFsError::OutOfBounds { .. })
        ));
    }

    #[test]
    fn file_device_persists_across_reopen() {
        let temp = TempPath::new("persist");
        {
            let dev = FileBlockDevice::create(&temp.0, 4096).unwrap();
            dev.write_at(1000, b"durable").unwrap();
            dev.flush().unwrap();
        }
        {
            let dev = FileBlockDevice::open(&temp.0).unwrap();
            assert_eq!(dev.len(), 4096);
            let mut buf = [0u8; 7];
            dev.read_at(1000, &mut buf).unwrap();
            assert_eq!(&buf, b"durable");
        }
    }
}
