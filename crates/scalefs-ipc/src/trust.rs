
use crate::endpoint::Stream;

pub fn process_is_privileged() -> bool {
    #[cfg(windows)]
    {
        windows::process_is_privileged().unwrap_or(false)
    }
    #[cfg(unix)]
    {
        unix::geteuid() == 0
    }
}

impl Stream {
    pub fn peer_is_privileged(&self) -> std::io::Result<bool> {
        #[cfg(windows)]
        {
            windows::pipe_peer_is_privileged(self.raw_handle())
        }
        #[cfg(unix)]
        {
            Ok(unix::peer_euid(self.raw_fd())? == 0)
        }
    }

    pub fn server_is_trusted(&self) -> std::io::Result<bool> {
        #[cfg(windows)]
        {
            windows::pipe_server_is_trusted(self.raw_handle())
        }
        #[cfg(unix)]
        {
            let peer = unix::peer_euid(self.raw_fd())?;
            Ok(peer == 0 || peer == unix::geteuid())
        }
    }
}

#[cfg(unix)]
mod unix {
    #[allow(unsafe_code)]
    mod ffi {
        unsafe extern "C" {
            pub fn geteuid() -> u32;
            #[cfg(target_os = "linux")]
            pub fn getsockopt(
                socket: i32,
                level: i32,
                name: i32,
                value: *mut core::ffi::c_void,
                len: *mut u32,
            ) -> i32;
            #[cfg(target_os = "macos")]
            pub fn getpeereid(socket: i32, euid: *mut u32, egid: *mut u32) -> i32;
        }
    }

    pub fn geteuid() -> u32 {
        #[allow(unsafe_code)]
        unsafe {
            ffi::geteuid()
        }
    }

    #[cfg(target_os = "linux")]
    pub fn peer_euid(fd: i32) -> std::io::Result<u32> {
        const SOL_SOCKET: i32 = 1;
        const SO_PEERCRED: i32 = 17;
        #[repr(C)]
        struct Ucred {
            pid: i32,
            uid: u32,
            gid: u32,
        }
        let mut cred = Ucred {
            pid: 0,
            uid: u32::MAX,
            gid: u32::MAX,
        };
        let mut len = size_of::<Ucred>() as u32;
        #[allow(unsafe_code)]
        let rc = unsafe {
            ffi::getsockopt(
                fd,
                SOL_SOCKET,
                SO_PEERCRED,
                std::ptr::addr_of_mut!(cred).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(cred.uid)
    }

    #[cfg(target_os = "macos")]
    pub fn peer_euid(fd: i32) -> std::io::Result<u32> {
        let mut euid = u32::MAX;
        let mut egid = u32::MAX;
        #[allow(unsafe_code)]
        let rc = unsafe { ffi::getpeereid(fd, &mut euid, &mut egid) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(euid)
    }
}

#[cfg(windows)]
mod windows {
    #[allow(unsafe_code)]
    mod ffi {
        use core::ffi::c_void;
        #[link(name = "kernel32", kind = "raw-dylib")]
        unsafe extern "system" {
            pub fn GetCurrentThread() -> isize;
            pub fn GetCurrentProcess() -> isize;
            pub fn CloseHandle(handle: isize) -> i32;
            pub fn LocalFree(mem: *mut c_void) -> *mut c_void;
        }
        #[link(name = "advapi32", kind = "raw-dylib")]
        unsafe extern "system" {
            pub fn ImpersonateNamedPipeClient(pipe: isize) -> i32;
            pub fn RevertToSelf() -> i32;
            pub fn OpenThreadToken(
                thread: isize,
                desired_access: u32,
                open_as_self: i32,
                token: *mut isize,
            ) -> i32;
            pub fn OpenProcessToken(process: isize, desired_access: u32, token: *mut isize) -> i32;
            pub fn DuplicateToken(
                token: isize,
                impersonation_level: u32,
                duplicate: *mut isize,
            ) -> i32;
            pub fn GetTokenInformation(
                token: isize,
                information_class: u32,
                information: *mut c_void,
                information_length: u32,
                return_length: *mut u32,
            ) -> i32;
            pub fn CheckTokenMembership(
                token: isize,
                sid_to_check: *mut c_void,
                is_member: *mut i32,
            ) -> i32;
            pub fn CreateWellKnownSid(
                sid_type: u32,
                domain_sid: *const c_void,
                sid: *mut c_void,
                sid_size: *mut u32,
            ) -> i32;
            pub fn EqualSid(sid1: *const c_void, sid2: *const c_void) -> i32;
            pub fn GetSecurityInfo(
                handle: isize,
                object_type: u32,
                security_info: u32,
                owner: *mut *mut c_void,
                group: *mut *mut c_void,
                dacl: *mut *mut c_void,
                sacl: *mut *mut c_void,
                security_descriptor: *mut *mut c_void,
            ) -> u32;
        }
    }

    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_DUPLICATE: u32 = 0x0002;
    const TOKEN_USER: u32 = 1;
    const TOKEN_ELEVATION: u32 = 20;
    const SECURITY_IDENTIFICATION: u32 = 1;
    const WIN_LOCAL_SYSTEM_SID: u32 = 22;
    const WIN_BUILTIN_ADMINISTRATORS_SID: u32 = 26;
    const MAX_SID_SIZE: usize = 68;
    const SE_KERNEL_OBJECT: u32 = 6;
    const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;

    struct Handle(isize);

    impl Drop for Handle {
        fn drop(&mut self) {
            #[allow(unsafe_code)]
            unsafe {
                ffi::CloseHandle(self.0);
            }
        }
    }

    struct Impersonation;

    impl Drop for Impersonation {
        fn drop(&mut self) {
            #[allow(unsafe_code)]
            let reverted = unsafe { ffi::RevertToSelf() };
            if reverted == 0 {
                std::process::abort();
            }
        }
    }

    struct Sid([u8; MAX_SID_SIZE]);

    impl Sid {
        fn well_known(kind: u32) -> std::io::Result<Sid> {
            let mut buffer = [0u8; MAX_SID_SIZE];
            let mut size = MAX_SID_SIZE as u32;
            #[allow(unsafe_code)]
            let ok = unsafe {
                ffi::CreateWellKnownSid(
                    kind,
                    std::ptr::null(),
                    buffer.as_mut_ptr().cast(),
                    &mut size,
                )
            };
            if ok == 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(Sid(buffer))
        }

        fn as_ptr(&self) -> *mut core::ffi::c_void {
            self.0.as_ptr() as *mut core::ffi::c_void
        }
    }

    fn token_is_admin(token: isize) -> std::io::Result<bool> {
        let admins = Sid::well_known(WIN_BUILTIN_ADMINISTRATORS_SID)?;
        let mut member: i32 = 0;
        #[allow(unsafe_code)]
        let ok = unsafe { ffi::CheckTokenMembership(token, admins.as_ptr(), &mut member) };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if member != 0 {
            return Ok(true);
        }
        token_is_elevated(token)
    }

    fn token_is_elevated(token: isize) -> std::io::Result<bool> {
        let mut elevation: u32 = 0;
        let mut returned: u32 = 0;
        #[allow(unsafe_code)]
        let ok = unsafe {
            ffi::GetTokenInformation(
                token,
                TOKEN_ELEVATION,
                std::ptr::addr_of_mut!(elevation).cast(),
                size_of::<u32>() as u32,
                &mut returned,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(elevation != 0)
    }

    pub fn pipe_peer_is_privileged(pipe: isize) -> std::io::Result<bool> {
        #[allow(unsafe_code)]
        let impersonated = unsafe { ffi::ImpersonateNamedPipeClient(pipe) };
        if impersonated == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let token = {
            let _revert = Impersonation;
            let mut token: isize = 0;
            #[allow(unsafe_code)]
            let ok = unsafe {
                ffi::OpenThreadToken(
                    ffi::GetCurrentThread(),
                    TOKEN_QUERY | TOKEN_DUPLICATE,
                    1,
                    &mut token,
                )
            };
            if ok == 0 {
                return Err(std::io::Error::last_os_error());
            }
            Handle(token)
        };
        token_is_admin(token.0)
    }

    pub fn process_is_privileged() -> std::io::Result<bool> {
        let mut process_token: isize = 0;
        #[allow(unsafe_code)]
        let ok = unsafe {
            ffi::OpenProcessToken(
                ffi::GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE,
                &mut process_token,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let process_token = Handle(process_token);
        let mut identification: isize = 0;
        #[allow(unsafe_code)]
        let ok = unsafe {
            ffi::DuplicateToken(
                process_token.0,
                SECURITY_IDENTIFICATION,
                &mut identification,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let identification = Handle(identification);
        token_is_admin(identification.0)
    }

    fn own_user_sid() -> std::io::Result<Vec<u8>> {
        let mut token: isize = 0;
        #[allow(unsafe_code)]
        let ok =
            unsafe { ffi::OpenProcessToken(ffi::GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let token = Handle(token);
        let mut buffer = vec![0u8; 256];
        let mut returned: u32 = 0;
        #[allow(unsafe_code)]
        let ok = unsafe {
            ffi::GetTokenInformation(
                token.0,
                TOKEN_USER,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut returned,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(buffer)
    }

    fn token_user_sid(buffer: &[u8]) -> *mut core::ffi::c_void {
        let mut sid_ptr_bytes = [0u8; size_of::<usize>()];
        sid_ptr_bytes.copy_from_slice(&buffer[..size_of::<usize>()]);
        usize::from_ne_bytes(sid_ptr_bytes) as *mut core::ffi::c_void
    }

    pub fn pipe_server_is_trusted(pipe: isize) -> std::io::Result<bool> {
        let mut owner: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut descriptor: *mut core::ffi::c_void = std::ptr::null_mut();
        #[allow(unsafe_code)]
        let status = unsafe {
            ffi::GetSecurityInfo(
                pipe,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status as i32));
        }
        struct Descriptor(*mut core::ffi::c_void);
        impl Drop for Descriptor {
            fn drop(&mut self) {
                #[allow(unsafe_code)]
                unsafe {
                    ffi::LocalFree(self.0);
                }
            }
        }
        let _descriptor = Descriptor(descriptor);

        let equals = |sid: *mut core::ffi::c_void| -> bool {
            #[allow(unsafe_code)]
            unsafe {
                ffi::EqualSid(owner, sid) != 0
            }
        };
        if equals(Sid::well_known(WIN_LOCAL_SYSTEM_SID)?.as_ptr())
            || equals(Sid::well_known(WIN_BUILTIN_ADMINISTRATORS_SID)?.as_ptr())
        {
            return Ok(true);
        }
        let own = own_user_sid()?;
        Ok(equals(token_user_sid(&own)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::{Endpoint, Listener, connect};
    use std::io::{Read, Write};
    use std::time::Duration;

    fn private_endpoint(tag: &str) -> Endpoint {
        let name = format!("scalefs-trust-{}-{tag}", std::process::id());
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
    fn same_process_peer_matches_own_privilege() {
        let endpoint = private_endpoint("peer");
        let mut listener = Listener::bind(&endpoint).unwrap();
        let client_endpoint = endpoint.clone();
        let client = std::thread::spawn(move || {
            let mut stream = connect(&client_endpoint, Duration::from_secs(5)).unwrap();
            stream.write_all(b"x").unwrap();
            let mut ack = [0u8; 1];
            stream.read_exact(&mut ack).unwrap();
        });
        let mut stream = listener.accept().unwrap();
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).unwrap();
        assert_eq!(
            stream.peer_is_privileged().unwrap(),
            process_is_privileged(),
            "a same-process client must carry our own privilege"
        );
        stream.write_all(b"y").unwrap();
        client.join().unwrap();
    }

    #[test]
    fn own_server_is_trusted() {
        let endpoint = private_endpoint("server");
        let mut listener = Listener::bind(&endpoint).unwrap();
        let client_endpoint = endpoint.clone();
        let client = std::thread::spawn(move || {
            let stream = connect(&client_endpoint, Duration::from_secs(5)).unwrap();
            stream.server_is_trusted().unwrap()
        });
        let _server_side = listener.accept().unwrap();
        assert!(
            client.join().unwrap(),
            "a client must trust a server running as its own account"
        );
    }

    #[test]
    fn process_privilege_probe_answers() {
        let _ = process_is_privileged();
    }
}
