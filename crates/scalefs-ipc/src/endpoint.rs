
use std::io::{Read, Write};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint(String);

impl Endpoint {
    pub fn new(text: &str) -> Endpoint {
        Endpoint(text.to_string())
    }

    pub fn default_endpoint() -> Endpoint {
        #[cfg(windows)]
        {
            Endpoint(r"\\.\pipe\scalefs".to_string())
        }
        #[cfg(target_os = "macos")]
        {
            Endpoint("/var/run/scalefs.sock".to_string())
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            Endpoint("/run/scalefs.sock".to_string())
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn address(&self) -> String {
        #[cfg(windows)]
        {
            if self.0.starts_with(r"\\") {
                self.0.clone()
            } else {
                format!(r"\\.\pipe\{}", self.0)
            }
        }
        #[cfg(unix)]
        {
            self.0.clone()
        }
    }
}

pub struct Stream(StreamImp);

enum StreamImp {
    #[cfg(windows)]
    Pipe(std::fs::File),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let result = match &mut self.0 {
            #[cfg(windows)]
            StreamImp::Pipe(file) => file.read(buf),
            #[cfg(unix)]
            StreamImp::Unix(socket) => socket.read(buf),
        };
        match result {
            #[cfg(windows)]
            Err(error) if error.raw_os_error() == Some(109) => Ok(0),
            other => other,
        }
    }
}

impl Stream {
    #[cfg(windows)]
    pub(crate) fn raw_handle(&self) -> isize {
        match &self.0 {
            StreamImp::Pipe(file) => {
                std::os::windows::io::AsRawHandle::as_raw_handle(file) as isize
            }
        }
    }

    #[cfg(unix)]
    pub(crate) fn raw_fd(&self) -> i32 {
        match &self.0 {
            StreamImp::Unix(socket) => std::os::fd::AsRawFd::as_raw_fd(socket),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match &mut self.0 {
            #[cfg(windows)]
            StreamImp::Pipe(file) => file.write(buf),
            #[cfg(unix)]
            StreamImp::Unix(socket) => socket.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match &mut self.0 {
            #[cfg(windows)]
            StreamImp::Pipe(file) => file.flush(),
            #[cfg(unix)]
            StreamImp::Unix(socket) => socket.flush(),
        }
    }
}

pub struct Listener(ListenerImp);

enum ListenerImp {
    #[cfg(windows)]
    Pipe(windows::PipeListener),
    #[cfg(unix)]
    Unix(UnixListenerImp),
}

impl Listener {
    pub fn bind(endpoint: &Endpoint) -> std::io::Result<Listener> {
        #[cfg(windows)]
        {
            Ok(Listener(ListenerImp::Pipe(windows::PipeListener::bind(
                &endpoint.address(),
            )?)))
        }
        #[cfg(unix)]
        {
            Ok(Listener(ListenerImp::Unix(UnixListenerImp::bind(
                &endpoint.address(),
            )?)))
        }
    }

    pub fn accept(&mut self) -> std::io::Result<Stream> {
        match &mut self.0 {
            #[cfg(windows)]
            ListenerImp::Pipe(listener) => {
                listener.accept().map(|file| Stream(StreamImp::Pipe(file)))
            }
            #[cfg(unix)]
            ListenerImp::Unix(listener) => listener
                .inner
                .accept()
                .map(|(socket, _)| Stream(StreamImp::Unix(socket))),
        }
    }
}

pub fn connect(endpoint: &Endpoint, timeout: Duration) -> std::io::Result<Stream> {
    let address = endpoint.address();
    let deadline = Instant::now() + timeout;
    loop {
        let attempt: std::io::Result<Stream> = {
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;
                std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .security_qos_flags(SECURITY_IDENTIFICATION)
                    .open(&address)
                    .map(|file| Stream(StreamImp::Pipe(file)))
            }
            #[cfg(unix)]
            {
                std::os::unix::net::UnixStream::connect(&address)
                    .map(|socket| Stream(StreamImp::Unix(socket)))
            }
        };
        match attempt {
            Ok(stream) => return Ok(stream),
            Err(error) => {
                let transient = error.raw_os_error() == Some(231)
                    || matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                    );
                if !transient || Instant::now() >= deadline {
                    return Err(error);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

#[cfg(unix)]
struct UnixListenerImp {
    inner: std::os::unix::net::UnixListener,
    path: std::path::PathBuf,
    _lock: std::fs::File,
}

#[cfg(unix)]
impl UnixListenerImp {
    fn bind(path: &str) -> std::io::Result<UnixListenerImp> {
        use std::os::unix::fs::OpenOptionsExt;
        let lock_path = format!("{path}.lock");
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .open(&lock_path)?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!("another scalefsd is already serving {path}"),
                ));
            }
            Err(std::fs::TryLockError::Error(error)) => return Err(error),
        }
        let bound = match std::os::unix::net::UnixListener::bind(path) {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                match std::os::unix::net::UnixStream::connect(path) {
                    Ok(_) => return Err(error),
                    Err(probe) if probe.kind() == std::io::ErrorKind::ConnectionRefused => {
                        std::fs::remove_file(path)?;
                        std::os::unix::net::UnixListener::bind(path)?
                    }
                    Err(_) => return Err(error),
                }
            }
            Err(error) => return Err(error),
        };
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(UnixListenerImp {
            inner: bound,
            path: std::path::PathBuf::from(path),
            _lock: lock,
        })
    }
}

#[cfg(unix)]
impl Drop for UnixListenerImp {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(windows)]
mod windows {
    use std::os::windows::io::{FromRawHandle, OwnedHandle};

    #[allow(unsafe_code)]
    mod ffi {
        #[link(name = "kernel32", kind = "raw-dylib")]
        unsafe extern "system" {
            pub fn CreateNamedPipeW(
                name: *const u16,
                open_mode: u32,
                pipe_mode: u32,
                max_instances: u32,
                out_buffer_size: u32,
                in_buffer_size: u32,
                default_time_out: u32,
                security_attributes: *mut core::ffi::c_void,
            ) -> isize;
            pub fn ConnectNamedPipe(pipe: isize, overlapped: *mut core::ffi::c_void) -> i32;
            pub fn LocalFree(mem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
        }
        #[link(name = "advapi32", kind = "raw-dylib")]
        unsafe extern "system" {
            pub fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
                string_security_descriptor: *const u16,
                revision: u32,
                security_descriptor: *mut *mut core::ffi::c_void,
                security_descriptor_size: *mut u32,
            ) -> i32;
        }
    }

    const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)";
    const SDDL_REVISION_1: u32 = 1;
    const ERROR_ACCESS_DENIED: i32 = 5;

    struct SecurityDescriptor(*mut core::ffi::c_void);

    impl SecurityDescriptor {
        fn from_sddl(sddl: &str) -> std::io::Result<SecurityDescriptor> {
            let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
            let mut descriptor: *mut core::ffi::c_void = std::ptr::null_mut();
            #[allow(unsafe_code)]
            let ok = unsafe {
                ffi::ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(SecurityDescriptor(descriptor))
        }

        fn as_ptr(&self) -> *mut core::ffi::c_void {
            self.0
        }
    }

    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {
            #[allow(unsafe_code)]
            unsafe {
                ffi::LocalFree(self.0);
            }
        }
    }

    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        security_descriptor: *mut core::ffi::c_void,
        inherit_handle: i32,
    }

    const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
    const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
    const PIPE_MODE_BYTE_BLOCKING: u32 = 0;
    const PIPE_UNLIMITED_INSTANCES: u32 = 255;
    const INVALID_HANDLE_VALUE: isize = -1;
    const ERROR_PIPE_CONNECTED: i32 = 535;
    const ERROR_NO_DATA: i32 = 232;
    const BUFFER_SIZE: u32 = 64 * 1024;

    pub struct PipeListener {
        name: Vec<u16>,
        next: Option<OwnedHandle>,
        security: SecurityDescriptor,
    }

    impl PipeListener {
        pub fn bind(address: &str) -> std::io::Result<PipeListener> {
            let name: Vec<u16> = address.encode_utf16().chain(std::iter::once(0)).collect();
            let security = SecurityDescriptor::from_sddl(PIPE_SDDL)?;
            let first = match create_instance(&name, true, security.as_ptr()) {
                Ok(handle) => handle,
                Err(error) if error.raw_os_error() == Some(ERROR_ACCESS_DENIED) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AddrInUse,
                        format!("another scalefsd is already serving {address}"),
                    ));
                }
                Err(error) => return Err(error),
            };
            Ok(PipeListener {
                name,
                next: Some(first),
                security,
            })
        }

        pub fn accept(&mut self) -> std::io::Result<std::fs::File> {
            loop {
                let instance = match self.next.take() {
                    Some(instance) => instance,
                    None => create_instance(&self.name, false, self.security.as_ptr())?,
                };
                let raw = std::os::windows::io::AsRawHandle::as_raw_handle(&instance);
                #[allow(unsafe_code)]
                let connected =
                    unsafe { ffi::ConnectNamedPipe(raw as isize, std::ptr::null_mut()) };
                if connected == 0 {
                    let error = std::io::Error::last_os_error();
                    match error.raw_os_error() {
                        Some(ERROR_PIPE_CONNECTED) => {}
                        Some(ERROR_NO_DATA) => continue,
                        _ => return Err(error),
                    }
                }
                self.next = create_instance(&self.name, false, self.security.as_ptr()).ok();
                return Ok(std::fs::File::from(instance));
            }
        }
    }

    fn create_instance(
        name: &[u16],
        first: bool,
        security: *mut core::ffi::c_void,
    ) -> std::io::Result<OwnedHandle> {
        let mut open_mode = PIPE_ACCESS_DUPLEX;
        if first {
            open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        let mut attributes = SecurityAttributes {
            length: core::mem::size_of::<SecurityAttributes>() as u32,
            security_descriptor: security,
            inherit_handle: 0,
        };
        #[allow(unsafe_code)]
        let handle = unsafe {
            ffi::CreateNamedPipeW(
                name.as_ptr(),
                open_mode,
                PIPE_MODE_BYTE_BLOCKING,
                PIPE_UNLIMITED_INSTANCES,
                BUFFER_SIZE,
                BUFFER_SIZE,
                0,
                std::ptr::addr_of_mut!(attributes) as *mut core::ffi::c_void,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        #[allow(unsafe_code)]
        Ok(unsafe { OwnedHandle::from_raw_handle(handle as *mut core::ffi::c_void) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{read_frame, write_frame};
    use crate::json::{Value, object};
    use std::io::BufReader;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn private_endpoint(tag: &str) -> Endpoint {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!("scalefs-test-{}-{tag}-{n}", std::process::id());
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
    }

    #[test]
    fn streams_carry_frames_both_ways() {
        let endpoint = private_endpoint("basic");
        let mut listener = Listener::bind(&endpoint).unwrap();
        let client_endpoint = endpoint.clone();
        let client = std::thread::spawn(move || {
            let stream = connect(&client_endpoint, Duration::from_secs(5)).unwrap();
            let mut reader = BufReader::new(stream);
            let hello = object(vec![("hi", Value::Bool(true))]);
            write_frame(reader.get_mut(), &hello).unwrap();
            read_frame(&mut reader).unwrap().unwrap()
        });

        let stream = listener.accept().unwrap();
        let mut reader = BufReader::new(stream);
        let received = read_frame(&mut reader).unwrap().unwrap();
        assert_eq!(received.get("hi"), Some(&Value::Bool(true)));
        let reply = object(vec![("ack", Value::Int(1))]);
        write_frame(reader.get_mut(), &reply).unwrap();
        assert_eq!(client.join().unwrap(), reply);

        assert_eq!(read_frame(&mut reader).unwrap(), None);
    }

    #[test]
    fn clients_queue_behind_each_other() {
        let endpoint = private_endpoint("serial");
        let mut listener = Listener::bind(&endpoint).unwrap();
        let mut clients = Vec::new();
        for n in 0..3u64 {
            let client_endpoint = endpoint.clone();
            clients.push(std::thread::spawn(move || {
                let stream = connect(&client_endpoint, Duration::from_secs(5)).unwrap();
                let mut reader = BufReader::new(stream);
                write_frame(reader.get_mut(), &object(vec![("n", Value::Int(n.into()))])).unwrap();
                read_frame(&mut reader).unwrap().unwrap()
            }));
        }
        let mut seen = Vec::new();
        for _ in 0..3 {
            let stream = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let frame = read_frame(&mut reader).unwrap().unwrap();
            let n = frame.get("n").unwrap().as_u64().unwrap();
            seen.push(n);
            write_frame(
                reader.get_mut(),
                &object(vec![("echo", Value::Int(n.into()))]),
            )
            .unwrap();
        }
        for client in clients {
            client.join().unwrap();
        }
        seen.sort_unstable();
        assert_eq!(seen, vec![0, 1, 2]);
    }

    #[test]
    fn double_bind_is_refused() {
        let endpoint = private_endpoint("dup");
        let _listener = Listener::bind(&endpoint).unwrap();
        assert!(Listener::bind(&endpoint).is_err());
    }

    #[test]
    fn endpoint_is_exclusive_and_reclaimable() {
        let endpoint = private_endpoint("exclusive");
        let first = Listener::bind(&endpoint).unwrap();
        assert!(
            Listener::bind(&endpoint).is_err(),
            "a live server must keep the endpoint"
        );
        drop(first);
        let mut second = Listener::bind(&endpoint).expect("endpoint should be reclaimable");
        let client_endpoint = endpoint.clone();
        let client =
            std::thread::spawn(move || connect(&client_endpoint, Duration::from_secs(5)).is_ok());
        let _stream = second.accept().unwrap();
        assert!(client.join().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn the_lock_file_holds_the_endpoint() {
        let endpoint = private_endpoint("locked");
        let held = Listener::bind(&endpoint).unwrap();
        std::fs::remove_file(endpoint.as_str()).unwrap();
        let refused = Listener::bind(&endpoint);
        assert_eq!(
            refused.err().map(|error| error.kind()),
            Some(std::io::ErrorKind::AddrInUse)
        );
        drop(held);
        assert!(Listener::bind(&endpoint).is_ok(), "the lock frees on drop");
    }

    #[test]
    fn connecting_nowhere_times_out() {
        let endpoint = private_endpoint("absent");
        let started = std::time::Instant::now();
        assert!(connect(&endpoint, Duration::from_millis(50)).is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[cfg(unix)]
    #[test]
    fn stale_sockets_are_reclaimed() {
        let endpoint = private_endpoint("stale");
        drop(std::os::unix::net::UnixListener::bind(endpoint.as_str()).unwrap());
        assert!(std::fs::metadata(endpoint.as_str()).is_ok());

        let mut listener = Listener::bind(&endpoint).unwrap();
        let client_endpoint = endpoint.clone();
        let client =
            std::thread::spawn(move || connect(&client_endpoint, Duration::from_secs(5)).is_ok());
        let _stream = listener.accept().unwrap();
        assert!(client.join().unwrap());
    }
}
