use std::io::{Read, Write};

const FETCH_BUF: usize = (1 << 20) + 128;

const POLL_MS: u32 = 500;

const RESPOND_MS: u32 = 60_000;

const IOCTL_FETCH: u32 = 0x0022_2004;
const IOCTL_RESPOND: u32 = 0x0022_2008;
const IOCTL_VOLUME_ATTACH: u32 = 0x0022_2040;
const IOCTL_VOLUME_DETACH: u32 = 0x0022_2044;
const IOCTL_VOLUME_QUERY: u32 = 0x0022_2048;

const FORCE_DISMOUNT: u32 = 0b1;

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const OPEN_EXISTING: u32 = 3;
const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
const INVALID_HANDLE: isize = -1;
const ERROR_IO_PENDING: u32 = 997;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 0x102;

#[allow(unsafe_code)]
mod ffi {
    use core::ffi::c_void;
    #[link(name = "kernel32", kind = "raw-dylib")]
    unsafe extern "system" {
        pub fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            security: *mut c_void,
            disposition: u32,
            flags: u32,
            template: isize,
        ) -> isize;
        pub fn DeviceIoControl(
            device: isize,
            code: u32,
            in_buf: *const c_void,
            in_len: u32,
            out_buf: *mut c_void,
            out_len: u32,
            returned: *mut u32,
            overlapped: *mut super::Overlapped,
        ) -> i32;
        pub fn CloseHandle(handle: isize) -> i32;
        pub fn GetLastError() -> u32;
        pub fn CreateEventW(
            security: *mut c_void,
            manual_reset: i32,
            initial_state: i32,
            name: *const u16,
        ) -> isize;
        pub fn ResetEvent(event: isize) -> i32;
        pub fn WaitForSingleObject(handle: isize, timeout_ms: u32) -> u32;
        pub fn GetOverlappedResult(
            device: isize,
            overlapped: *mut super::Overlapped,
            transferred: *mut u32,
            wait: i32,
        ) -> i32;
        pub fn CancelIoEx(device: isize, overlapped: *mut super::Overlapped) -> i32;
    }
}

#[repr(C)]
struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    event: isize,
}

impl Overlapped {
    fn for_event(event: isize) -> Self {
        Overlapped {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            event,
        }
    }
}

fn last_error() -> std::io::Error {
    #[allow(unsafe_code)]
    let code = unsafe { ffi::GetLastError() };
    std::io::Error::from_raw_os_error(code as i32)
}

fn open_control(path: &str) -> std::io::Result<isize> {
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    #[allow(unsafe_code)]
    let device = unsafe {
        ffi::CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            core::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            0,
        )
    };
    if device == INVALID_HANDLE || device == 0 {
        return Err(last_error());
    }
    Ok(device)
}

fn control_ioctl(
    device: isize,
    code: u32,
    input: &[u8],
    output: &mut [u8],
) -> std::io::Result<usize> {
    let mut returned = 0u32;
    #[allow(unsafe_code)]
    let ok = unsafe {
        ffi::DeviceIoControl(
            device,
            code,
            input.as_ptr().cast(),
            input.len() as u32,
            if output.is_empty() {
                core::ptr::null_mut()
            } else {
                output.as_mut_ptr().cast()
            },
            output.len() as u32,
            &mut returned,
            core::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(returned as usize)
}

pub struct MountRequest {
    pub letter: Option<char>,
    pub external: bool,
}

pub struct AttachReply {
    pub letter: Option<char>,
    pub volume_guid: [u8; 16],
}

pub fn volume_attach(
    device_path: &str,
    pool_id: &[u8; 16],
    token: &[u8],
    mount: Option<&MountRequest>,
) -> std::io::Result<AttachReply> {
    if token.len() > 64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "token too long",
        ));
    }
    let mut flags = 0u32;
    let mut letter_unit = 0u16;
    if let Some(request) = mount {
        flags |= 0b01;
        if request.external {
            flags |= 0b10;
        }
        if let Some(letter) = request.letter {
            letter_unit = u16::from(letter.to_ascii_uppercase() as u8);
        }
    }
    let mut input = Vec::with_capacity(28 + token.len());
    input.extend_from_slice(pool_id);
    input.extend_from_slice(&flags.to_le_bytes());
    input.extend_from_slice(&letter_unit.to_le_bytes());
    input.extend_from_slice(&0u16.to_le_bytes());
    input.extend_from_slice(&(token.len() as u32).to_le_bytes());
    input.extend_from_slice(token);
    let mut output = [0u8; 20];
    let device = open_control(device_path)?;
    let result = control_ioctl(device, IOCTL_VOLUME_ATTACH, &input, &mut output);
    #[allow(unsafe_code)]
    unsafe {
        ffi::CloseHandle(device);
    }
    let produced = result?;
    if produced < 20 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "short VOLUME_ATTACH reply (driver/daemon version mismatch?)",
        ));
    }
    let bound = u16::from_le_bytes([output[0], output[1]]);
    let mut volume_guid = [0u8; 16];
    volume_guid.copy_from_slice(&output[4..20]);
    Ok(AttachReply {
        letter: (bound != 0)
            .then(|| u8::try_from(bound).ok().map(char::from))
            .flatten(),
        volume_guid,
    })
}

pub fn volume_detach(device_path: &str, force: bool) -> std::io::Result<()> {
    let device = open_control(device_path)?;
    let flags = FORCE_DISMOUNT.to_le_bytes();
    let input: &[u8] = if force { &flags } else { &[] };
    let result = control_ioctl(device, IOCTL_VOLUME_DETACH, input, &mut []);
    #[allow(unsafe_code)]
    unsafe {
        ffi::CloseHandle(device);
    }
    result.map(|_| ())
}

pub fn volume_query(device_path: &str) -> std::io::Result<(u32, bool)> {
    let device = open_control(device_path)?;
    let mut output = [0u8; 8];
    let result = control_ioctl(device, IOCTL_VOLUME_QUERY, &[], &mut output);
    #[allow(unsafe_code)]
    unsafe {
        ffi::CloseHandle(device);
    }
    let produced = result?;
    if produced < 8 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "short VOLUME_QUERY reply (driver/daemon version mismatch?)",
        ));
    }
    let state = u32::from_le_bytes([output[0], output[1], output[2], output[3]]);
    let flags = u32::from_le_bytes([output[4], output[5], output[6], output[7]]);
    Ok((state, flags & 1 != 0))
}

struct FetchInFlight {
    overlapped: Box<Overlapped>,
    buf: Vec<u8>,
}

pub struct KernelPumpStream {
    device: isize,
    fetch: FetchInFlight,
    fetch_armed: bool,
    respond_event: isize,
    read_buf: Vec<u8>,
    read_pos: usize,
    write_buf: Vec<u8>,
}

#[allow(unsafe_code)]
unsafe impl Send for KernelPumpStream {}

impl KernelPumpStream {
    pub fn open(path: &str) -> std::io::Result<Self> {
        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        #[allow(unsafe_code)]
        let device = unsafe {
            ffi::CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                core::ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                0,
            )
        };
        if device == INVALID_HANDLE || device == 0 {
            return Err(last_error());
        }
        let event = |label: &str| -> std::io::Result<isize> {
            #[allow(unsafe_code)]
            let handle =
                unsafe { ffi::CreateEventW(core::ptr::null_mut(), 1, 0, core::ptr::null()) };
            if handle == 0 {
                let error = last_error();
                Err(std::io::Error::new(
                    error.kind(),
                    format!("cannot create the {label} event: {error}"),
                ))
            } else {
                Ok(handle)
            }
        };
        let fetch_event = event("fetch").inspect_err(|_| {
            #[allow(unsafe_code)]
            unsafe {
                ffi::CloseHandle(device);
            }
        })?;
        let respond_event = event("respond").inspect_err(|_| {
            #[allow(unsafe_code)]
            unsafe {
                ffi::CloseHandle(fetch_event);
                ffi::CloseHandle(device);
            }
        })?;
        Ok(KernelPumpStream {
            device,
            fetch: FetchInFlight {
                overlapped: Box::new(Overlapped::for_event(fetch_event)),
                buf: vec![0u8; FETCH_BUF],
            },
            fetch_armed: false,
            respond_event,
            read_buf: Vec::new(),
            read_pos: 0,
            write_buf: Vec::new(),
        })
    }

    fn arm_fetch(&mut self) -> std::io::Result<()> {
        #[allow(unsafe_code)]
        unsafe {
            ffi::ResetEvent(self.fetch.overlapped.event)
        };
        let mut returned = 0u32;
        #[allow(unsafe_code)]
        let ok = unsafe {
            ffi::DeviceIoControl(
                self.device,
                IOCTL_FETCH,
                core::ptr::null(),
                0,
                self.fetch.buf.as_mut_ptr().cast(),
                FETCH_BUF as u32,
                &mut returned,
                &mut *self.fetch.overlapped,
            )
        };
        #[allow(unsafe_code)]
        if ok == 0 && unsafe { ffi::GetLastError() } != ERROR_IO_PENDING {
            return Err(last_error());
        }
        self.fetch_armed = true;
        Ok(())
    }

    fn finish_fetch(&mut self) -> std::io::Result<usize> {
        self.fetch_armed = false;
        let mut transferred = 0u32;
        #[allow(unsafe_code)]
        let ok = unsafe {
            ffi::GetOverlappedResult(
                self.device,
                &mut *self.fetch.overlapped,
                &mut transferred,
                0,
            )
        };
        if ok == 0 {
            return Err(last_error());
        }
        Ok(transferred as usize)
    }

    fn respond(&mut self, frame: &[u8]) -> std::io::Result<()> {
        #[allow(unsafe_code)]
        unsafe {
            ffi::ResetEvent(self.respond_event)
        };
        let mut overlapped = Overlapped::for_event(self.respond_event);
        let mut returned = 0u32;
        #[allow(unsafe_code)]
        let ok = unsafe {
            ffi::DeviceIoControl(
                self.device,
                IOCTL_RESPOND,
                frame.as_ptr().cast(),
                frame.len() as u32,
                core::ptr::null_mut(),
                0,
                &mut returned,
                &mut overlapped,
            )
        };
        #[allow(unsafe_code)]
        if ok == 0 && unsafe { ffi::GetLastError() } != ERROR_IO_PENDING {
            return Err(last_error());
        }
        #[allow(unsafe_code)]
        let wait = unsafe { ffi::WaitForSingleObject(self.respond_event, RESPOND_MS) };
        if wait != WAIT_OBJECT_0 {
            #[allow(unsafe_code)]
            unsafe {
                ffi::CancelIoEx(self.device, &mut overlapped);
                let mut transferred = 0u32;
                ffi::GetOverlappedResult(self.device, &mut overlapped, &mut transferred, 1);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the pump's RESPOND did not complete",
            ));
        }
        let mut transferred = 0u32;
        #[allow(unsafe_code)]
        let ok =
            unsafe { ffi::GetOverlappedResult(self.device, &mut overlapped, &mut transferred, 0) };
        if ok == 0 {
            return Err(last_error());
        }
        Ok(())
    }
}

impl Read for KernelPumpStream {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.read_pos < self.read_buf.len() {
                let available = &self.read_buf[self.read_pos..];
                let n = available.len().min(out.len());
                out[..n].copy_from_slice(&available[..n]);
                self.read_pos += n;
                return Ok(n);
            }
            if out.is_empty() {
                return Ok(0);
            }
            if !self.fetch_armed {
                self.arm_fetch()?;
            }
            #[allow(unsafe_code)]
            let wait = unsafe { ffi::WaitForSingleObject(self.fetch.overlapped.event, POLL_MS) };
            match wait {
                WAIT_OBJECT_0 => {
                    let n = self.finish_fetch()?;
                    if n == 0 {
                        return Ok(0);
                    }
                    self.read_buf.clear();
                    self.read_buf.extend_from_slice(&self.fetch.buf[..n]);
                    self.read_pos = 0;
                }
                WAIT_TIMEOUT => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "no request frame yet",
                    ));
                }
                _ => return Err(last_error()),
            }
        }
    }
}

impl Write for KernelPumpStream {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.write_buf.extend_from_slice(data);
        while let Some(total) = complete_frame_len(&self.write_buf) {
            let frame: Vec<u8> = self.write_buf.drain(..total).collect();
            self.respond(&frame)?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for KernelPumpStream {
    fn drop(&mut self) {
        if self.fetch_armed {
            #[allow(unsafe_code)]
            unsafe {
                ffi::CancelIoEx(self.device, &mut *self.fetch.overlapped);
                let mut transferred = 0u32;
                ffi::GetOverlappedResult(
                    self.device,
                    &mut *self.fetch.overlapped,
                    &mut transferred,
                    1,
                );
            }
        }
        #[allow(unsafe_code)]
        unsafe {
            ffi::CloseHandle(self.respond_event);
            ffi::CloseHandle(self.fetch.overlapped.event);
            ffi::CloseHandle(self.device);
        }
    }
}

fn complete_frame_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    let body_len = u32::from_le_bytes(buf[0..4].try_into().expect("4 bytes")) as usize;
    let total = 4usize.saturating_add(body_len);
    (buf.len() >= total).then_some(total)
}

#[cfg(test)]
mod tests {
    use super::complete_frame_len;

    fn frame(req_id: u32, status: i16, body: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&((8 + body.len()) as u32).to_le_bytes());
        f.extend_from_slice(&req_id.to_le_bytes());
        f.extend_from_slice(&status.to_le_bytes());
        f.extend_from_slice(&0u16.to_le_bytes());
        f.extend_from_slice(body);
        f
    }

    #[test]
    fn splitter_finds_frame_edges() {
        let a = frame(7, 0, b"alpha");
        let b = frame(8, 3, b"");

        assert_eq!(complete_frame_len(&a[..3]), None);
        assert_eq!(complete_frame_len(&a[..a.len() - 1]), None);
        assert_eq!(complete_frame_len(&a), Some(a.len()));

        let mut both = a.clone();
        both.extend_from_slice(&b);
        assert_eq!(complete_frame_len(&both), Some(a.len()));
        assert_eq!(complete_frame_len(&both[a.len()..]), Some(b.len()));

        let mut ragged = b.clone();
        ragged.extend_from_slice(&a[..5]);
        assert_eq!(complete_frame_len(&ragged), Some(b.len()));
    }
}
