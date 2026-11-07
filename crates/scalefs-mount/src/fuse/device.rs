use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[allow(unsafe_code)]
mod ffi {
    #[repr(C)]
    pub struct PollFd {
        pub fd: core::ffi::c_int,
        pub events: core::ffi::c_short,
        pub revents: core::ffi::c_short,
    }

    unsafe extern "C" {
        pub fn mount(
            source: *const core::ffi::c_char,
            target: *const core::ffi::c_char,
            fstype: *const core::ffi::c_char,
            flags: core::ffi::c_ulong,
            data: *const core::ffi::c_void,
        ) -> core::ffi::c_int;
        pub fn umount2(
            target: *const core::ffi::c_char,
            flags: core::ffi::c_int,
        ) -> core::ffi::c_int;
        pub fn poll(
            fds: *mut PollFd,
            nfds: core::ffi::c_ulong,
            timeout: core::ffi::c_int,
        ) -> core::ffi::c_int;
        pub fn fcntl(fd: core::ffi::c_int, cmd: core::ffi::c_int, ...) -> core::ffi::c_int;
    }
}

const MS_RDONLY: core::ffi::c_ulong = 0x1;
const MS_NOSUID: core::ffi::c_ulong = 0x2;
const MS_NODEV: core::ffi::c_ulong = 0x4;
const MNT_DETACH: i32 = 0x2;
const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;
const O_NONBLOCK: i32 = 0o4000;
const POLLIN: i16 = 0x1;
const EBUSY: i32 = 16;
const ENOTCONN: i32 = 107;
const STOP_POLL_MS: i32 = 500;

pub const REQUEST_BUFFER: usize = (1 << 20) + 4096;

fn c_path(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    if bytes.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path contains a NUL byte",
        ));
    }
    let mut out = bytes.to_vec();
    out.push(0);
    Ok(out)
}

fn c_string(text: &str) -> std::io::Result<Vec<u8>> {
    if text.as_bytes().contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path contains a NUL byte",
        ));
    }
    let mut bytes = text.as_bytes().to_vec();
    bytes.push(0);
    Ok(bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestRead {
    Ready(usize),
    NotReady,
    Unmounted,
}

pub struct FuseMount {
    device: File,
    mountpoint: PathBuf,
    detached: bool,
    stop: Arc<AtomicBool>,
}

impl FuseMount {
    pub fn mount(mountpoint: &Path, read_only: bool) -> std::io::Result<FuseMount> {
        let device = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/fuse")?;
        let target = c_path(mountpoint)?;
        let source = c_string("scalefs")?;
        let fstype = c_string("fuse")?;
        let data = c_string(&format!(
            "fd={},rootmode=40755,user_id=0,group_id=0,default_permissions,allow_other",
            device.as_raw_fd(),
        ))?;
        let mut mount_flags = MS_NOSUID | MS_NODEV;
        if read_only {
            mount_flags |= MS_RDONLY;
        }
        #[allow(unsafe_code)]
        let rc = unsafe {
            ffi::mount(
                source.as_ptr().cast(),
                target.as_ptr().cast(),
                fstype.as_ptr().cast(),
                mount_flags,
                data.as_ptr().cast(),
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(FuseMount {
            device,
            mountpoint: mountpoint.to_path_buf(),
            detached: false,
            stop: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
    }

    pub fn stop_requested(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    pub fn read_request(&self, buffer: &mut [u8]) -> std::io::Result<Option<usize>> {
        loop {
            match (&self.device).read(buffer) {
                Ok(len) => return Ok(Some(len)),
                Err(error) => match error.raw_os_error() {
                    Some(4) => continue,
                    Some(2) => continue,
                    Some(19) => return Ok(None),
                    _ => return Err(error),
                },
            }
        }
    }

    pub fn write_reply(&self, frame: &[u8]) -> std::io::Result<()> {
        loop {
            match (&self.device).write(frame) {
                Ok(_) => return Ok(()),
                Err(error) if matches!(error.raw_os_error(), Some(2) | Some(19)) => {
                    return Ok(());
                }
                Err(error) if error.raw_os_error() == Some(4) => continue,
                Err(error) => return Err(error),
            }
        }
    }

    pub fn set_nonblocking(&self) -> std::io::Result<()> {
        let fd = self.device.as_raw_fd();
        #[allow(unsafe_code)]
        let flags = unsafe { ffi::fcntl(fd, F_GETFL, 0) };
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }
        #[allow(unsafe_code)]
        let rc = unsafe { ffi::fcntl(fd, F_SETFL, flags | O_NONBLOCK) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn wait_readable(&self) -> std::io::Result<()> {
        let mut pollfd = ffi::PollFd {
            fd: self.device.as_raw_fd(),
            events: POLLIN,
            revents: 0,
        };
        loop {
            #[allow(unsafe_code)]
            let rc = unsafe { ffi::poll(&mut pollfd, 1, STOP_POLL_MS) };
            if rc >= 0 {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(4) {
                return Err(error);
            }
        }
    }

    pub fn read_request_nonblocking(&self, buffer: &mut [u8]) -> std::io::Result<RequestRead> {
        loop {
            match (&self.device).read(buffer) {
                Ok(len) => return Ok(RequestRead::Ready(len)),
                Err(error) => match error.raw_os_error() {
                    Some(4) => continue,
                    Some(2) => continue,
                    Some(11) => return Ok(RequestRead::NotReady),
                    Some(19) => return Ok(RequestRead::Unmounted),
                    _ => return Err(error),
                },
            }
        }
    }

    pub fn unmount(&mut self) {
        if self.detached {
            return;
        }
        self.detached = true;
        if let Ok(target) = c_path(&self.mountpoint) {
            #[allow(unsafe_code)]
            unsafe {
                ffi::umount2(target.as_ptr().cast(), MNT_DETACH)
            };
        }
    }

    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }
}

pub fn detach_mountpoint(mountpoint: &Path) -> std::io::Result<()> {
    let target = c_path(mountpoint)?;
    #[allow(unsafe_code)]
    let rc = unsafe { ffi::umount2(target.as_ptr().cast(), MNT_DETACH) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

pub fn unmount_mountpoint(mountpoint: &Path) -> std::io::Result<()> {
    let target = c_path(mountpoint)?;
    #[allow(unsafe_code)]
    let rc = unsafe { ffi::umount2(target.as_ptr().cast(), 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

pub fn is_busy(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(EBUSY)
}

pub fn clear_stale_mount(mountpoint: &Path) -> bool {
    match std::fs::metadata(mountpoint) {
        Err(error) if error.raw_os_error() == Some(ENOTCONN) => {
            let _ = detach_mountpoint(mountpoint);
            true
        }
        _ => false,
    }
}

impl Drop for FuseMount {
    fn drop(&mut self) {
        self.unmount();
    }
}
