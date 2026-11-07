use crate::device::{BlockDevice, check_bounds, read_exact_at, write_all_at};
use crate::discovery::DeviceIdentity;
use crate::error::{Result, ScaleFsError};
use std::fs::File;
use std::path::Path;

trait SectorIo {
    fn sector_size(&self) -> u32;
    fn len(&self) -> u64;
    fn read_sectors(&self, offset: u64, buf: &mut [u8]) -> Result<()>;
    fn write_sectors(&self, offset: u64, data: &[u8]) -> Result<()>;
    fn flush_media(&self) -> Result<()>;
}

struct Aligned<T> {
    inner: T,
}

impl<T: SectorIo> Aligned<T> {
    fn sector(&self) -> u64 {
        u64::from(self.inner.sector_size())
    }
}

impl<T: SectorIo> BlockDevice for Aligned<T> {
    fn len(&self) -> u64 {
        self.inner.len()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_bounds(offset, buf.len(), self.inner.len())?;
        if buf.is_empty() {
            return Ok(());
        }
        let sector = self.sector();
        if offset.is_multiple_of(sector) && (buf.len() as u64).is_multiple_of(sector) {
            return self.inner.read_sectors(offset, buf);
        }
        let start = offset - offset % sector;
        let end = (offset + buf.len() as u64).div_ceil(sector) * sector;
        let mut span = vec![0u8; (end - start) as usize];
        self.inner.read_sectors(start, &mut span)?;
        let skip = (offset - start) as usize;
        buf.copy_from_slice(&span[skip..skip + buf.len()]);
        Ok(())
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
        check_bounds(offset, data.len(), self.inner.len())?;
        if data.is_empty() {
            return Ok(());
        }
        let sector = self.sector();
        if offset.is_multiple_of(sector) && (data.len() as u64).is_multiple_of(sector) {
            return self.inner.write_sectors(offset, data);
        }
        let end = offset + data.len() as u64;
        let head_start = offset - offset % sector;
        let tail_end = end.div_ceil(sector) * sector;

        let middle_start = offset.div_ceil(sector) * sector;
        let middle_end = end - end % sector;
        if middle_end <= middle_start {
            let mut span = vec![0u8; (tail_end - head_start) as usize];
            self.inner.read_sectors(head_start, &mut span)?;
            let skip = (offset - head_start) as usize;
            span[skip..skip + data.len()].copy_from_slice(data);
            return self.inner.write_sectors(head_start, &span);
        }

        let mut cursor = data;
        if head_start < offset {
            let mut head = vec![0u8; sector as usize];
            self.inner.read_sectors(head_start, &mut head)?;
            let skip = (offset - head_start) as usize;
            let take = (middle_start - offset) as usize;
            head[skip..].copy_from_slice(&cursor[..take]);
            self.inner.write_sectors(head_start, &head)?;
            cursor = &cursor[take..];
        }
        let middle_len = (middle_end - middle_start) as usize;
        if middle_len > 0 {
            self.inner
                .write_sectors(middle_start, &cursor[..middle_len])?;
            cursor = &cursor[middle_len..];
        }
        if !cursor.is_empty() {
            let mut tail = vec![0u8; sector as usize];
            self.inner.read_sectors(middle_end, &mut tail)?;
            tail[..cursor.len()].copy_from_slice(cursor);
            self.inner.write_sectors(middle_end, &tail)?;
        }
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        self.inner.flush_media()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Barrier {
    SyncAll,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    FullSync,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OpenMode {
    Exclusive,
    Probe,
}

struct RawSectorFile {
    file: File,
    sector_size: u32,
    len: u64,
    barrier: Barrier,
    read_only: bool,
    identity: DeviceIdentity,
    actuators: Vec<std::ops::Range<u64>>,
    _holds: Vec<File>,
}

impl SectorIo for RawSectorFile {
    fn sector_size(&self) -> u32 {
        self.sector_size
    }

    fn len(&self) -> u64 {
        self.len
    }

    fn read_sectors(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let _t = crate::perftrace::start(crate::perftrace::C::DevRead, buf.len() as u64);
        read_exact_at(&self.file, offset, buf)
    }

    fn write_sectors(&self, offset: u64, data: &[u8]) -> Result<()> {
        if self.read_only {
            return Err(ScaleFsError::Unsupported(
                "this handle was opened read-only, for probing",
            ));
        }
        let _t = crate::perftrace::start(crate::perftrace::C::DevWrite, data.len() as u64);
        write_all_at(&self.file, offset, data)
    }

    fn flush_media(&self) -> Result<()> {
        if self.read_only {
            return Ok(());
        }
        let _t = crate::perftrace::start(crate::perftrace::C::DevFlush, 0);
        match self.barrier {
            Barrier::SyncAll => self.file.sync_all()?,
            #[cfg(target_os = "macos")]
            Barrier::FullSync => platform::full_sync(&self.file)?,
            #[cfg(not(target_os = "macos"))]
            Barrier::FullSync => self.file.sync_all()?,
        }
        Ok(())
    }
}

pub struct RawBlockDevice {
    aligned: Aligned<RawSectorFile>,
    sector_size: u32,
}

impl RawBlockDevice {
    pub fn open(path: &Path) -> Result<Self> {
        let probed = platform::open(path, OpenMode::Exclusive)?;
        if !probed.len.is_multiple_of(u64::from(probed.sector_size)) {
            return Err(ScaleFsError::InvalidArgument(
                "device capacity is not sector-aligned",
            ));
        }
        if probed.sector_size > 4096 {
            return Err(ScaleFsError::Unsupported(
                "devices with sectors larger than 4 KiB are not supported",
            ));
        }
        Ok(Self::wrap(probed))
    }

    pub fn open_probe(path: &Path) -> Result<Self> {
        let mut probed = platform::open(path, OpenMode::Probe)?;
        probed.len -= probed.len % u64::from(probed.sector_size);
        Ok(Self::wrap(probed))
    }

    fn wrap(probed: RawSectorFile) -> Self {
        let sector_size = probed.sector_size;
        Self {
            aligned: Aligned { inner: probed },
            sector_size,
        }
    }

    pub fn sector_size(&self) -> u32 {
        self.sector_size
    }

    pub fn identity(&self) -> &DeviceIdentity {
        &self.aligned.inner.identity
    }
}

impl BlockDevice for RawBlockDevice {
    fn len(&self) -> u64 {
        self.aligned.len()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.aligned.read_at(offset, buf)
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
        self.aligned.write_at(offset, data)
    }

    fn flush(&self) -> Result<()> {
        self.aligned.flush()
    }

    fn actuator_ranges(&self) -> Vec<std::ops::Range<u64>> {
        self.aligned.inner.actuators.clone()
    }

    fn sector_size(&self) -> u32 {
        self.sector_size
    }
}

pub enum AnyBlockDevice {
    File(crate::device::FileBlockDevice),
    Raw(RawBlockDevice),
}

impl BlockDevice for AnyBlockDevice {
    fn len(&self) -> u64 {
        match self {
            AnyBlockDevice::File(device) => device.len(),
            AnyBlockDevice::Raw(device) => device.len(),
        }
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        match self {
            AnyBlockDevice::File(device) => device.read_at(offset, buf),
            AnyBlockDevice::Raw(device) => device.read_at(offset, buf),
        }
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
        match self {
            AnyBlockDevice::File(device) => device.write_at(offset, data),
            AnyBlockDevice::Raw(device) => device.write_at(offset, data),
        }
    }

    fn flush(&self) -> Result<()> {
        match self {
            AnyBlockDevice::File(device) => device.flush(),
            AnyBlockDevice::Raw(device) => device.flush(),
        }
    }

    fn actuator_ranges(&self) -> Vec<std::ops::Range<u64>> {
        match self {
            AnyBlockDevice::File(_) => Vec::new(),
            AnyBlockDevice::Raw(device) => device.actuator_ranges(),
        }
    }

    fn sector_size(&self) -> u32 {
        match self {
            AnyBlockDevice::File(device) => device.sector_size(),
            AnyBlockDevice::Raw(device) => BlockDevice::sector_size(device),
        }
    }

    fn flush_group(devices: &[&Self]) -> Result<()> {
        let _t = crate::perftrace::start(crate::perftrace::C::FlushGroup, devices.len() as u64);
        if devices.len() <= 1 {
            return devices.iter().try_for_each(|device| device.flush());
        }
        std::thread::scope(|scope| {
            let handles: Vec<_> = devices
                .iter()
                .map(|device| {
                    std::thread::Builder::new()
                        .spawn_scoped(scope, move || device.flush())
                        .ok()
                })
                .collect();
            let outcomes: Vec<Result<()>> = handles
                .into_iter()
                .zip(devices)
                .map(|(handle, device)| match handle {
                    Some(handle) => handle
                        .join()
                        .unwrap_or_else(|panic| std::panic::resume_unwind(panic)),
                    None => device.flush(),
                })
                .collect();
            outcomes.into_iter().find(Result::is_err).unwrap_or(Ok(()))
        })
    }
}

#[cfg(windows)]
pub(crate) use platform::{
    IOCTL_STORAGE_QUERY_PROPERTY, device_io, volume_guid_name, volume_path_name,
};

#[cfg(windows)]
mod platform {
    use super::{Barrier, OpenMode, RawSectorFile};
    use crate::error::{Result, ScaleFsError};
    use std::fs::{File, OpenOptions};
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;

    #[allow(unsafe_code)]
    mod ffi {
        #[link(name = "kernel32", kind = "raw-dylib")]
        unsafe extern "system" {
            pub fn DeviceIoControl(
                device: isize,
                control_code: u32,
                in_buffer: *const core::ffi::c_void,
                in_size: u32,
                out_buffer: *mut core::ffi::c_void,
                out_size: u32,
                bytes_returned: *mut u32,
                overlapped: *mut core::ffi::c_void,
            ) -> i32;
            pub fn FindFirstVolumeW(volume_name: *mut u16, length: u32) -> isize;
            pub fn FindNextVolumeW(handle: isize, volume_name: *mut u16, length: u32) -> i32;
            pub fn FindVolumeClose(handle: isize) -> i32;
            pub fn GetVolumePathNameW(
                file_name: *const u16,
                volume_path_name: *mut u16,
                length: u32,
            ) -> i32;
            pub fn GetVolumeNameForVolumeMountPointW(
                volume_mount_point: *const u16,
                volume_name: *mut u16,
                length: u32,
            ) -> i32;
        }
    }

    const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x0007_405C;
    pub(crate) const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D_1400;
    const IOCTL_STORAGE_GET_DEVICE_NUMBER: u32 = 0x002D_1080;
    const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: u32 = 0x0056_0000;
    const FSCTL_LOCK_VOLUME: u32 = 0x0009_0018;
    const FSCTL_DISMOUNT_VOLUME: u32 = 0x0009_0020;
    const ERROR_MORE_DATA: i32 = 234;
    const STORAGE_ACCESS_ALIGNMENT_PROPERTY: u32 = 6;
    const FILE_DEVICE_DISK: u32 = 0x0000_0007;
    const FILE_SHARE_READ: u32 = 1;
    const FILE_SHARE_WRITE: u32 = 2;
    const FILE_SHARE_DELETE: u32 = 4;

    pub(crate) fn device_io(
        file: &std::fs::File,
        code: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> std::io::Result<()> {
        let mut returned: u32 = 0;
        #[allow(unsafe_code)]
        let ok = unsafe {
            ffi::DeviceIoControl(
                file.as_raw_handle() as isize,
                code,
                input.as_ptr().cast(),
                input.len() as u32,
                output.as_mut_ptr().cast(),
                output.len() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn open(path: &Path, mode: OpenMode) -> Result<RawSectorFile> {
        let mut options = OpenOptions::new();
        options.read(true);
        match mode {
            OpenMode::Exclusive => {
                options.write(true).share_mode(0);
            }
            OpenMode::Probe => {
                options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
            }
        }
        let file = options.open(path)?;
        let read_only = mode == OpenMode::Probe;
        let identity = crate::discovery::identity_of(&file, path);

        let mut length = [0u8; 8];
        match device_io(&file, IOCTL_DISK_GET_LENGTH_INFO, &[], &mut length) {
            Ok(()) => {
                let len = u64::from_le_bytes(length);
                let mut query = [0u8; 12];
                query[..4].copy_from_slice(&STORAGE_ACCESS_ALIGNMENT_PROPERTY.to_le_bytes());
                let mut descriptor = [0u8; 28];
                let sector_size =
                    match device_io(&file, IOCTL_STORAGE_QUERY_PROPERTY, &query, &mut descriptor) {
                        Ok(()) => {
                            let logical = u32::from_le_bytes(
                                descriptor[16..20].try_into().expect("fixed slice"),
                            );
                            if logical.is_power_of_two() && (512..=65536).contains(&logical) {
                                logical
                            } else {
                                512
                            }
                        }
                        Err(_) => 512,
                    };
                let holds = match mode {
                    OpenMode::Exclusive => lock_disk_volumes(&file)?,
                    OpenMode::Probe => Vec::new(),
                };
                Ok(RawSectorFile {
                    file,
                    sector_size,
                    len,
                    barrier: Barrier::SyncAll,
                    read_only,
                    identity,
                    actuators: Vec::new(),
                    _holds: holds,
                })
            }
            Err(_) => {
                let len = file.metadata()?.len();
                Ok(RawSectorFile {
                    file,
                    sector_size: 512,
                    len,
                    barrier: Barrier::SyncAll,
                    read_only,
                    identity,
                    actuators: Vec::new(),
                    _holds: Vec::new(),
                })
            }
        }
    }

    fn lock_disk_volumes(disk: &File) -> Result<Vec<File>> {
        let mut number = [0u8; 12];
        if device_io(disk, IOCTL_STORAGE_GET_DEVICE_NUMBER, &[], &mut number).is_err() {
            return Ok(Vec::new());
        }
        let Some((device_type, disk_number, partition)) =
            crate::discovery::parse_storage_device_number(&number)
        else {
            return Ok(Vec::new());
        };
        if device_type != FILE_DEVICE_DISK {
            return Ok(Vec::new());
        }
        if partition != 0 && partition != 0xFFFF_FFFF {
            device_io(disk, FSCTL_LOCK_VOLUME, &[], &mut []).map_err(|error| {
                ScaleFsError::Io(std::io::Error::new(
                    error.kind(),
                    format!(
                        "the volume is in use ({error}); \
                         close whatever uses it or dismount it first"
                    ),
                ))
            })?;
            let _ = device_io(disk, FSCTL_DISMOUNT_VOLUME, &[], &mut []);
            return Ok(Vec::new());
        }

        let mut holds = Vec::new();
        for name in enumerate_volumes() {
            let trimmed = name.trim_end_matches('\\');
            let Ok(query) = OpenOptions::new()
                .access_mode(0)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .open(trimmed)
            else {
                continue;
            };
            let mut extents = vec![0u8; 4096];
            let mut answered = device_io(
                &query,
                IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                &[],
                &mut extents,
            );
            if let Err(error) = &answered
                && error.raw_os_error() == Some(ERROR_MORE_DATA)
            {
                extents = vec![0u8; 64 * 1024];
                answered = device_io(
                    &query,
                    IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                    &[],
                    &mut extents,
                );
            }
            drop(query);
            match answered {
                Ok(()) => {}
                Err(error) if error.raw_os_error() == Some(ERROR_MORE_DATA) => {
                    return Err(ScaleFsError::Io(std::io::Error::other(format!(
                        "volume {name} spans more extents than can be checked; \
                         refusing to write a disk it might live on"
                    ))));
                }
                Err(_) => continue,
            }
            let Some(disks) = crate::discovery::parse_volume_disk_extents(&extents) else {
                continue;
            };
            if !disks.contains(&disk_number) {
                continue;
            }
            let locked: std::io::Result<File> = (|| {
                let handle = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                    .open(trimmed)?;
                device_io(&handle, FSCTL_LOCK_VOLUME, &[], &mut [])?;
                device_io(&handle, FSCTL_DISMOUNT_VOLUME, &[], &mut [])?;
                Ok(handle)
            })();
            match locked {
                Ok(handle) => holds.push(handle),
                Err(error) => {
                    return Err(ScaleFsError::Io(std::io::Error::new(
                        error.kind(),
                        format!(
                            "volume {name} on the target disk is in use ({error}); \
                             close whatever uses it or dismount it first"
                        ),
                    )));
                }
            }
        }
        Ok(holds)
    }

    pub(super) fn enumerate_volumes() -> Vec<String> {
        let mut names = Vec::new();
        let mut buffer = [0u16; 260];
        #[allow(unsafe_code)]
        let handle = unsafe { ffi::FindFirstVolumeW(buffer.as_mut_ptr(), buffer.len() as u32) };
        if handle == -1isize {
            return names;
        }
        loop {
            let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
            names.push(String::from_utf16_lossy(&buffer[..len]));
            #[allow(unsafe_code)]
            let more =
                unsafe { ffi::FindNextVolumeW(handle, buffer.as_mut_ptr(), buffer.len() as u32) };
            if more == 0 {
                break;
            }
        }
        #[allow(unsafe_code)]
        unsafe {
            ffi::FindVolumeClose(handle)
        };
        names
    }

    pub(crate) fn volume_path_name(path: &Path) -> Option<String> {
        use std::os::windows::ffi::OsStrExt;
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut buffer = [0u16; 261];
        #[allow(unsafe_code)]
        let ok = unsafe {
            ffi::GetVolumePathNameW(wide.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32)
        };
        if ok == 0 {
            return None;
        }
        let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
        Some(String::from_utf16_lossy(&buffer[..len]))
    }

    pub(crate) fn volume_guid_name(mount_point: &str) -> Option<String> {
        use std::os::windows::ffi::OsStrExt;
        let with_slash = if mount_point.ends_with('\\') {
            mount_point.to_string()
        } else {
            format!("{mount_point}\\")
        };
        let wide: Vec<u16> = std::ffi::OsStr::new(&with_slash)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut buffer = [0u16; 64];
        #[allow(unsafe_code)]
        let ok = unsafe {
            ffi::GetVolumeNameForVolumeMountPointW(
                wide.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
            )
        };
        if ok == 0 {
            return None;
        }
        let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
        Some(String::from_utf16_lossy(&buffer[..len]))
    }
}

#[cfg(unix)]
mod platform {
    use super::{Barrier, OpenMode, RawSectorFile};
    use crate::error::Result;
    use std::fs::OpenOptions;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::FileTypeExt;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;

    #[allow(unsafe_code)]
    mod ffi {
        unsafe extern "C" {
            pub fn ioctl(
                fd: core::ffi::c_int,
                request: core::ffi::c_ulong,
                ...
            ) -> core::ffi::c_int;
            #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
            pub fn fcntl(fd: core::ffi::c_int, cmd: core::ffi::c_int, ...) -> core::ffi::c_int;
            #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
            pub fn fsync(fd: core::ffi::c_int) -> core::ffi::c_int;
        }
    }

    fn ioctl_u64(file: &std::fs::File, request: u64, value: &mut u64) -> std::io::Result<()> {
        #[allow(unsafe_code)]
        let rc = unsafe {
            ffi::ioctl(
                file.as_raw_fd(),
                request as core::ffi::c_ulong,
                std::ptr::from_mut(value).cast::<core::ffi::c_void>(),
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    pub(super) fn full_sync(file: &std::fs::File) -> std::io::Result<()> {
        const F_FULLFSYNC: core::ffi::c_int = 51;
        const ENOTTY: i32 = 25;
        const ENOTSUP: i32 = 45;
        #[allow(unsafe_code)]
        let rc = unsafe { ffi::fcntl(file.as_raw_fd(), F_FULLFSYNC, 0) };
        if rc != -1 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(ENOTTY) | Some(ENOTSUP)) {
            return Err(error);
        }
        #[allow(unsafe_code)]
        let rc = unsafe { ffi::fsync(file.as_raw_fd()) };
        if rc == -1 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn open(path: &Path, mode: OpenMode) -> Result<RawSectorFile> {
        let read_only = mode == OpenMode::Probe;
        let metadata = std::fs::metadata(path)?;
        let file_type = metadata.file_type();

        #[cfg(target_os = "linux")]
        if file_type.is_block_device() {
            let mut options = OpenOptions::new();
            options.read(true);
            if mode == OpenMode::Exclusive {
                options.write(true).custom_flags(libc_o_excl());
            }
            let file = options.open(path)?;
            const BLKGETSIZE64: u64 = 0x8008_1272;
            const BLKSSZGET: u64 = 0x1268;
            let mut len = 0u64;
            ioctl_u64(&file, BLKGETSIZE64, &mut len)?;
            let mut sector = 0u64;
            ioctl_u64(&file, BLKSSZGET, &mut sector)?;
            let sector = (sector & 0xFFFF_FFFF) as u32;
            let sector_size = if sector.is_power_of_two() && (512..=65536).contains(&sector) {
                sector
            } else {
                512
            };
            let identity = crate::discovery::identity_of(&file, path);
            let actuators = crate::raw::actuator::discover(&file, len, sector_size);
            return Ok(RawSectorFile {
                file,
                sector_size,
                len,
                barrier: Barrier::SyncAll,
                read_only,
                identity,
                actuators,
                _holds: Vec::new(),
            });
        }

        #[cfg(target_os = "macos")]
        if file_type.is_char_device() || file_type.is_block_device() {
            let mut options = OpenOptions::new();
            options.read(true);
            if mode == OpenMode::Exclusive {
                options.write(true);
            }
            let file = options.open(path)?;
            const DKIOCGETBLOCKSIZE: u64 = 0x4004_6418;
            const DKIOCGETBLOCKCOUNT: u64 = 0x4008_6419;
            let mut sector = 0u64;
            ioctl_u64(&file, DKIOCGETBLOCKSIZE, &mut sector)?;
            let sector = (sector & 0xFFFF_FFFF) as u32;
            let mut blocks = 0u64;
            ioctl_u64(&file, DKIOCGETBLOCKCOUNT, &mut blocks)?;
            let sector_size = if sector.is_power_of_two() && (512..=65536).contains(&sector) {
                sector
            } else {
                512
            };
            let identity = crate::discovery::identity_of(&file, path);
            return Ok(RawSectorFile {
                file,
                sector_size,
                len: blocks * u64::from(sector_size),
                barrier: Barrier::FullSync,
                read_only,
                identity,
                actuators: Vec::new(),
                _holds: Vec::new(),
            });
        }

        let mut options = OpenOptions::new();
        options.read(true);
        if mode == OpenMode::Exclusive {
            options.write(true);
        }
        let file = options.open(path)?;
        let identity = crate::discovery::identity_of(&file, path);
        let _ = &file_type;
        Ok(RawSectorFile {
            file,
            sector_size: 512,
            len: metadata.len(),
            barrier: if cfg!(target_os = "macos") {
                Barrier::FullSync
            } else {
                Barrier::SyncAll
            },
            read_only,
            identity,
            actuators: Vec::new(),
            _holds: Vec::new(),
        })
    }

    #[cfg(target_os = "linux")]
    fn libc_o_excl() -> i32 {
        0o200
    }
}

pub fn is_device_path(path: &Path) -> bool {
    let text = path.to_string_lossy();
    text.starts_with("\\\\.\\") || text.starts_with("/dev/")
}

pub(crate) mod actuator {
    use std::ops::Range;

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    const CPR_LOG: u8 = 0x47;

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn read_cpr_log_cdb() -> [u8; 16] {
        let mut cdb = [0u8; 16];
        cdb[0] = 0x85;
        cdb[1] = (4 << 1) | 1;
        cdb[2] = 0x0E;
        cdb[6] = 1;
        cdb[8] = CPR_LOG;
        cdb[14] = 0x2F;
        cdb
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn parse_cpr_log(page: &[u8], sector_size: u64, capacity: u64) -> Vec<Range<u64>> {
        if page.len() < 64 {
            return Vec::new();
        }
        let count = usize::from(page[0]);
        if !(2..=8).contains(&count) {
            return Vec::new();
        }
        let mut ranges = Vec::with_capacity(count);
        for index in 0..count {
            let at = 64 + index * 32;
            let Some(descriptor) = page.get(at..at + 32) else {
                return Vec::new();
            };
            let start = u64::from_le_bytes(descriptor[8..16].try_into().expect("8 bytes"));
            let lbas = u64::from_le_bytes(descriptor[16..24].try_into().expect("8 bytes"));
            let (Some(begin), Some(end_lba)) =
                (start.checked_mul(sector_size), start.checked_add(lbas))
            else {
                return Vec::new();
            };
            let Some(end) = end_lba.checked_mul(sector_size) else {
                return Vec::new();
            };
            ranges.push(begin..end.min(capacity));
        }
        sanitize(ranges, capacity)
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn sanitize(mut ranges: Vec<Range<u64>>, capacity: u64) -> Vec<Range<u64>> {
        ranges.sort_by_key(|range| range.start);
        let sound = ranges.len() >= 2
            && ranges
                .iter()
                .all(|range| range.start < range.end && range.end <= capacity)
            && ranges.windows(2).all(|pair| pair[0].end <= pair[1].start);
        if sound { ranges } else { Vec::new() }
    }

    #[cfg(target_os = "linux")]
    pub(super) fn discover(
        file: &std::fs::File,
        capacity: u64,
        sector_size: u32,
    ) -> Vec<Range<u64>> {
        if std::env::var_os("SCALEFS_NO_ACTUATOR").is_some() {
            return Vec::new();
        }
        let found = sysfs_ranges(file, capacity);
        if !found.is_empty() {
            return found;
        }
        ata_cpr_ranges(file, capacity, u64::from(sector_size))
    }

    #[cfg(target_os = "linux")]
    fn sysfs_ranges(file: &std::fs::File, capacity: u64) -> Vec<Range<u64>> {
        use std::os::unix::fs::MetadataExt;
        let Ok(metadata) = file.metadata() else {
            return Vec::new();
        };
        let rdev = metadata.rdev();
        let major = ((rdev >> 32) & 0xFFFF_F000) | ((rdev >> 8) & 0xFFF);
        let minor = ((rdev >> 12) & 0xFFFF_FF00) | (rdev & 0xFF);
        let base = format!("/sys/dev/block/{major}:{minor}/queue/independent_access_ranges");
        let Ok(entries) = std::fs::read_dir(&base) else {
            return Vec::new();
        };
        let read_u64 = |path: std::path::PathBuf| -> Option<u64> {
            std::fs::read_to_string(path).ok()?.trim().parse().ok()
        };
        let mut ranges = Vec::new();
        for entry in entries.flatten() {
            let dir = entry.path();
            let (Some(sector), Some(count)) = (
                read_u64(dir.join("sector")),
                read_u64(dir.join("nr_sectors")),
            ) else {
                continue;
            };
            if count == 0 {
                continue;
            }
            ranges.push((sector * 512)..((sector + count) * 512).min(capacity));
        }
        sanitize(ranges, capacity)
    }

    #[cfg(target_os = "linux")]
    fn ata_cpr_ranges(file: &std::fs::File, capacity: u64, sector_size: u64) -> Vec<Range<u64>> {
        use std::os::fd::AsRawFd;

        const SG_IO: core::ffi::c_ulong = 0x2285;
        const SG_DXFER_FROM_DEV: i32 = -3;

        #[repr(C)]
        struct SgIoHdr {
            interface_id: i32,
            dxfer_direction: i32,
            cmd_len: u8,
            mx_sb_len: u8,
            iovec_count: u16,
            dxfer_len: u32,
            dxferp: *mut core::ffi::c_void,
            cmdp: *mut u8,
            sbp: *mut u8,
            timeout: u32,
            flags: u32,
            pack_id: i32,
            usr_ptr: *mut core::ffi::c_void,
            status: u8,
            masked_status: u8,
            msg_status: u8,
            sb_len_wr: u8,
            host_status: u16,
            driver_status: u16,
            resid: i32,
            duration: u32,
            info: u32,
        }

        #[allow(unsafe_code)]
        mod ffi {
            unsafe extern "C" {
                pub fn ioctl(
                    fd: core::ffi::c_int,
                    request: core::ffi::c_ulong,
                    ...
                ) -> core::ffi::c_int;
            }
        }

        let mut page = [0u8; 512];
        let mut sense = [0u8; 32];
        let mut cdb = read_cpr_log_cdb();
        let mut header = SgIoHdr {
            interface_id: i32::from(b'S'),
            dxfer_direction: SG_DXFER_FROM_DEV,
            cmd_len: cdb.len() as u8,
            mx_sb_len: sense.len() as u8,
            iovec_count: 0,
            dxfer_len: page.len() as u32,
            dxferp: page.as_mut_ptr().cast(),
            cmdp: cdb.as_mut_ptr(),
            sbp: sense.as_mut_ptr(),
            timeout: 5_000,
            flags: 0,
            pack_id: 0,
            usr_ptr: std::ptr::null_mut(),
            status: 0,
            masked_status: 0,
            msg_status: 0,
            sb_len_wr: 0,
            host_status: 0,
            driver_status: 0,
            resid: 0,
            duration: 0,
            info: 0,
        };
        #[allow(unsafe_code)]
        let rc = unsafe {
            ffi::ioctl(
                file.as_raw_fd(),
                SG_IO,
                std::ptr::from_mut(&mut header).cast::<core::ffi::c_void>(),
            )
        };
        if rc != 0 || header.status != 0 || header.host_status != 0 || header.driver_status != 0 {
            return Vec::new();
        }
        parse_cpr_log(&page, sector_size, capacity)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn the_read_log_cdb_is_pinned() {
            assert_eq!(
                read_cpr_log_cdb(),
                [
                    0x85, 0x09, 0x0E, 0, 0, 0, 1, 0, 0x47, 0, 0, 0, 0, 0, 0x2F, 0
                ],
            );
        }

        #[test]
        fn the_exos_2x18_page_parses_to_its_half_split() {
            let mut page = [0u8; 512];
            page[0] = 2;
            page[65] = 1;
            page[80..88].copy_from_slice(&17_578_328_064u64.to_le_bytes());
            page[96] = 1;
            page[97] = 1;
            page[104..112].copy_from_slice(&17_578_328_064u64.to_le_bytes());
            page[112..120].copy_from_slice(&17_578_328_064u64.to_le_bytes());
            let capacity = 2 * 17_578_328_064 * 512;
            let ranges = parse_cpr_log(&page, 512, capacity);
            let half = 17_578_328_064 * 512;
            assert_eq!(ranges, vec![0..half, half..2 * half]);
        }

        #[test]
        fn malformed_pages_parse_to_empty() {
            let capacity = 1 << 40;
            assert_eq!(parse_cpr_log(&[0u8; 512], 512, capacity), Vec::new());
            let mut single = [0u8; 512];
            single[0] = 1;
            single[80..88].copy_from_slice(&100u64.to_le_bytes());
            assert_eq!(parse_cpr_log(&single, 512, capacity), Vec::new());
            let mut runt = [0u8; 512];
            runt[0] = 9;
            assert_eq!(parse_cpr_log(&runt, 512, capacity), Vec::new());
            let overlapping = vec![0u64..1000, 500..2000];
            assert_eq!(sanitize(overlapping, capacity), Vec::new());
            let inverted = vec![0u64..1000, 5000..5000];
            assert_eq!(sanitize(inverted, capacity), Vec::new());
        }
    }
}

impl AnyBlockDevice {
    pub fn open(path: &Path) -> Result<Self> {
        if is_device_path(path) {
            RawBlockDevice::open(path).map(AnyBlockDevice::Raw)
        } else {
            crate::device::FileBlockDevice::open(path).map(AnyBlockDevice::File)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::MemoryBlockDevice;

    struct StrictSectors {
        bytes: std::sync::Mutex<Vec<u8>>,
        sector: u32,
    }

    impl SectorIo for StrictSectors {
        fn sector_size(&self) -> u32 {
            self.sector
        }

        fn len(&self) -> u64 {
            self.bytes.lock().expect("strict sector lock").len() as u64
        }

        fn read_sectors(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            assert_eq!(offset % u64::from(self.sector), 0, "unaligned read offset");
            assert_eq!(buf.len() % self.sector as usize, 0, "unaligned read length");
            let start = offset as usize;
            let bytes = self.bytes.lock().expect("strict sector lock");
            buf.copy_from_slice(&bytes[start..start + buf.len()]);
            Ok(())
        }

        fn write_sectors(&self, offset: u64, data: &[u8]) -> Result<()> {
            assert_eq!(offset % u64::from(self.sector), 0, "unaligned write offset");
            assert_eq!(
                data.len() % self.sector as usize,
                0,
                "unaligned write length"
            );
            let start = offset as usize;
            self.bytes.lock().expect("strict sector lock")[start..start + data.len()]
                .copy_from_slice(data);
            Ok(())
        }

        fn flush_media(&self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn alignment_layer_matches_a_byte_model() {
        let sector = 512usize;
        let len = sector * 8;
        let model = MemoryBlockDevice::new(len);
        let aligned = Aligned {
            inner: StrictSectors {
                bytes: std::sync::Mutex::new(vec![0; len]),
                sector: sector as u32,
            },
        };

        let mut seed = 0x9E37_79B9u64;
        let mut next = move |bound: usize| {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (seed >> 33) as usize % bound
        };
        for round in 0..500 {
            let offset = next(len - 1);
            let max_len = (len - offset).min(sector * 3);
            let length = 1 + next(max_len);
            let data: Vec<u8> = (0..length)
                .map(|i| ((round * 31 + i * 7 + offset) % 251) as u8)
                .collect();
            aligned.write_at(offset as u64, &data).unwrap();
            model.write_at(offset as u64, &data).unwrap();

            let check_offset = next(len - 1);
            let check_len = 1 + next((len - check_offset).min(sector * 3));
            let mut ours = vec![0u8; check_len];
            let mut reference = vec![0u8; check_len];
            aligned.read_at(check_offset as u64, &mut ours).unwrap();
            model.read_at(check_offset as u64, &mut reference).unwrap();
            assert_eq!(ours, reference, "round {round}");
        }
        let mut ours = vec![0u8; len];
        aligned.read_at(0, &mut ours).unwrap();
        assert_eq!(ours, model.bytes());
    }

    #[test]
    fn alignment_layer_handles_edges() {
        let sector = 512u64;
        let aligned = Aligned {
            inner: StrictSectors {
                bytes: std::sync::Mutex::new(vec![0xAA; 4096]),
                sector: 512,
            },
        };
        for (offset, len) in [
            (0u64, 512usize),
            (0, 4096),
            (511, 1),
            (512, 1),
            (511, 2),
            (100, 312),
            (300, 1024),
            (512, 700),
            (300, 724),
        ] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            aligned.write_at(offset, &data).unwrap();
            let mut back = vec![0u8; len];
            aligned.read_at(offset, &mut back).unwrap();
            assert_eq!(back, data, "offset {offset} len {len}");
        }
        let _ = sector;
    }

    #[test]
    fn pools_run_on_raw_devices() {
        use crate::layout::{CaseSensitivity, PoolId};
        use crate::pool::{CreateParams, Pool};

        let dir = std::env::temp_dir().join(format!(
            "scalefs-raw-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("raw.img");
        let geometry = crate::layout::Geometry {
            logical_block_size: 4096,
            physical_block_size: 4096,
            zone_size: 64 * 1024,
            zone_count: 16,
            erase_granularity_zones: 1,
            sequential_write_required: false,
        };
        {
            let image = std::fs::File::create(&path).unwrap();
            image
                .set_len(crate::gpt::member_image_len(geometry.capacity_bytes()))
                .unwrap();
        }

        let device = RawBlockDevice::open(&path).unwrap();
        assert_eq!(device.sector_size(), 512);
        assert_eq!(
            device.len(),
            crate::gpt::member_image_len(geometry.capacity_bytes())
        );

        let params = CreateParams {
            geometry,
            pool_id: PoolId([0x42; 16]),
            device_id: crate::layout::DeviceId([0x43; 16]),
            case_sensitivity: CaseSensitivity::InsensitivePreserving,
            dirent_hash_seed: 9,
            label: "raw".to_string(),
            created_at_ns: 1_700_000_000_000_000_000,
        };
        let mut pool = Pool::create(device, params).unwrap();
        let data: Vec<u8> = (0..50_000usize).map(|i| (i * 13 % 251) as u8).collect();
        let file = pool
            .create_file(crate::ROOT_INODE, "raw.bin", 0o644, 1)
            .unwrap();
        pool.write(file, 0, &data, 1).unwrap();
        pool.commit(crate::zones::AllocPurpose::Normal, 1).unwrap();
        drop(pool);

        let reopened = Pool::open(RawBlockDevice::open(&path).unwrap()).unwrap();
        let entry = reopened.lookup(crate::ROOT_INODE, "raw.bin").unwrap();
        assert_eq!(reopened.read(entry.inode, 0, data.len()).unwrap(), data);
        drop(reopened);

        if cfg!(windows) {
            let first = RawBlockDevice::open(&path).unwrap();
            assert!(RawBlockDevice::open(&path).is_err());
            drop(first);
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn flush_group_flushes_every_member() {
        let dir = std::env::temp_dir().join(format!(
            "scalefs-flushgroup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let devices: Vec<AnyBlockDevice> = (0..5)
            .map(|i| {
                let path = dir.join(format!("m{i}.img"));
                {
                    let file = std::fs::File::create(&path).unwrap();
                    file.set_len(1 << 20).unwrap();
                }
                AnyBlockDevice::open(&path).unwrap()
            })
            .collect();
        for (i, device) in devices.iter().enumerate() {
            device.write_at(4096, &[i as u8 + 1; 4096]).unwrap();
        }

        AnyBlockDevice::flush_group(&[]).unwrap();
        let refs: Vec<&AnyBlockDevice> = devices.iter().take(1).collect();
        AnyBlockDevice::flush_group(&refs).unwrap();
        let refs: Vec<&AnyBlockDevice> = devices.iter().collect();
        AnyBlockDevice::flush_group(&refs).unwrap();

        let refs: Vec<&AnyBlockDevice> = devices
            .iter()
            .enumerate()
            .filter_map(|(i, d)| (i % 2 == 0).then_some(d))
            .collect();
        AnyBlockDevice::flush_group(&refs).unwrap();

        drop(devices);
        for i in 0..5u8 {
            let device = AnyBlockDevice::open(&dir.join(format!("m{i}.img"))).unwrap();
            let mut back = vec![0u8; 4096];
            device.read_at(4096, &mut back).unwrap();
            assert!(back.iter().all(|&b| b == i + 1));
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn probe_opens_are_read_only_and_tolerant() {
        let dir = std::env::temp_dir().join(format!(
            "scalefs-probe-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let odd = dir.join("odd.bin");
        std::fs::write(&odd, vec![0xEE; 1000]).unwrap();
        let probe = RawBlockDevice::open_probe(&odd).unwrap();
        assert_eq!(probe.len(), 512, "odd lengths round down to sectors");
        let mut bytes = vec![0u8; 512];
        probe.read_at(0, &mut bytes).unwrap();
        assert!(bytes.iter().all(|&byte| byte == 0xEE));
        assert!(probe.write_at(0, &[1, 2, 3]).is_err());
        assert!(probe.write_at(0, &vec![0u8; 512]).is_err());
        assert_eq!(
            probe.identity(),
            &crate::discovery::DeviceIdentity::default()
        );

        if cfg!(windows) {
            let claimed = dir.join("claimed.bin");
            std::fs::write(&claimed, vec![0u8; 4096]).unwrap();
            let exclusive = RawBlockDevice::open(&claimed).unwrap();
            assert!(RawBlockDevice::open_probe(&claimed).is_err());
            drop(exclusive);
            assert!(RawBlockDevice::open_probe(&claimed).is_ok());
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(windows)]
    #[test]
    fn volume_enumeration_is_shape_safe() {
        for name in super::platform::enumerate_volumes() {
            assert!(name.starts_with(r"\\?\Volume{"), "{name}");
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod loop_device_tests {
    use super::*;

    #[test]
    fn pools_run_on_a_real_block_device() {
        let dev = match std::env::var("SCALEFS_RAW_TEST_DEV") {
            Ok(dev) if !dev.is_empty() => dev,
            _ => return,
        };
        use crate::layout::{CaseSensitivity, DeviceId, PoolId};
        use crate::pool::{CreateParams, Pool};

        let device = RawBlockDevice::open(Path::new(&dev)).unwrap();
        let sector = device.sector_size();
        assert!(sector >= 512, "probed sector size {sector}");
        assert!(device.len() >= 1 << 20, "device too small");

        assert!(RawBlockDevice::open(Path::new(&dev)).is_err());

        let geometry = crate::layout::Geometry {
            logical_block_size: 4096,
            physical_block_size: sector.max(4096),
            zone_size: 64 * 1024,
            zone_count: device.len() / (64 * 1024),
            erase_granularity_zones: 1,
            sequential_write_required: false,
        };
        let mut pool = Pool::create(
            device,
            CreateParams {
                geometry,
                pool_id: PoolId([0x51; 16]),
                device_id: DeviceId([0x52; 16]),
                case_sensitivity: CaseSensitivity::InsensitivePreserving,
                dirent_hash_seed: 3,
                label: "loop".to_string(),
                created_at_ns: 1_700_000_000_000_000_000,
            },
        )
        .unwrap();
        let data: Vec<u8> = (0..200_000usize).map(|i| (i * 17 % 251) as u8).collect();
        let file = pool
            .create_file(crate::ROOT_INODE, "loop.bin", 0o644, 1)
            .unwrap();
        pool.write(file, 0, &data, 1).unwrap();
        pool.commit(crate::zones::AllocPurpose::Normal, 1).unwrap();
        drop(pool);

        let reopened = Pool::open(RawBlockDevice::open(Path::new(&dev)).unwrap()).unwrap();
        let entry = reopened.lookup(crate::ROOT_INODE, "loop.bin").unwrap();
        assert_eq!(reopened.read(entry.inode, 0, data.len()).unwrap(), data);
    }
}

#[cfg(test)]
mod path_tests {
    use super::*;

    #[test]
    fn device_paths_are_recognized() {
        assert!(is_device_path(Path::new(r"\\.\PhysicalDrive3")));
        assert!(is_device_path(Path::new("/dev/sdb")));
        assert!(is_device_path(Path::new("/dev/rdisk4")));
        assert!(!is_device_path(Path::new("pool.img")));
        assert!(!is_device_path(Path::new(r"C:\pools\a.img")));
        assert!(!is_device_path(Path::new("/home/dev/pool.img")));
    }
}
