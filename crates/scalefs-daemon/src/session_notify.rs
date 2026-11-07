pub use scalefs_shell::announce::Change;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[allow(unsafe_code)]
mod ffi {
    use core::ffi::c_void;

    #[repr(C)]
    pub struct SessionInfo {
        pub session_id: u32,
        pub station_name: *mut u16,
        pub state: i32,
    }

    #[repr(C)]
    pub struct StartupInfo {
        pub cb: u32,
        pub reserved: *mut u16,
        pub desktop: *mut u16,
        pub title: *mut u16,
        pub x: u32,
        pub y: u32,
        pub x_size: u32,
        pub y_size: u32,
        pub x_count_chars: u32,
        pub y_count_chars: u32,
        pub fill_attribute: u32,
        pub flags: u32,
        pub show_window: u16,
        pub reserved2_len: u16,
        pub reserved2: *mut u8,
        pub std_input: isize,
        pub std_output: isize,
        pub std_error: isize,
    }

    #[repr(C)]
    pub struct ProcessInformation {
        pub process: isize,
        pub thread: isize,
        pub process_id: u32,
        pub thread_id: u32,
    }

    #[link(name = "wtsapi32", kind = "raw-dylib")]
    unsafe extern "system" {
        pub fn WTSEnumerateSessionsW(
            server: isize,
            reserved: u32,
            version: u32,
            sessions: *mut *mut SessionInfo,
            count: *mut u32,
        ) -> i32;
        pub fn WTSQueryUserToken(session_id: u32, token: *mut isize) -> i32;
        pub fn WTSFreeMemory(memory: *mut c_void);
    }

    #[link(name = "advapi32", kind = "raw-dylib")]
    unsafe extern "system" {
        pub fn CreateProcessAsUserW(
            token: isize,
            application: *const u16,
            command_line: *mut u16,
            process_attributes: *const c_void,
            thread_attributes: *const c_void,
            inherit_handles: i32,
            creation_flags: u32,
            environment: *const c_void,
            current_directory: *const u16,
            startup_info: *const StartupInfo,
            process_information: *mut ProcessInformation,
        ) -> i32;
    }

    #[link(name = "kernel32", kind = "raw-dylib")]
    unsafe extern "system" {
        pub fn ProcessIdToSessionId(process_id: u32, session_id: *mut u32) -> i32;
        pub fn GetCurrentProcessId() -> u32;
        pub fn CloseHandle(handle: isize) -> i32;
        pub fn GetDriveTypeW(root: *const u16) -> u32;
        pub fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
    }

    #[link(name = "userenv", kind = "raw-dylib")]
    unsafe extern "system" {
        pub fn CreateEnvironmentBlock(
            environment: *mut *mut c_void,
            token: isize,
            inherit: i32,
        ) -> i32;
        pub fn DestroyEnvironmentBlock(environment: *mut c_void) -> i32;
    }
}

const WTS_ACTIVE: i32 = 0;
const WTS_CONNECTED: i32 = 1;
const WTS_DISCONNECTED: i32 = 4;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;
const DRIVE_NO_ROOT_DIR: u32 = 1;
const ERROR_NO_TOKEN: i32 = 1008;

const UNBIND_WAIT: Duration = Duration::from_secs(3);

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn announce(letter: &str, change: Change) {
    let Some(letter) = drive_letter(letter) else {
        return;
    };
    let _ = std::thread::Builder::new()
        .name("scalefsd-announce".to_string())
        .spawn(move || announce_now(letter, change));
}

pub fn announce_and_wait(letter: &str, change: Change) {
    if let Some(letter) = drive_letter(letter) {
        announce_now(letter, change);
    }
}

fn drive_letter(text: &str) -> Option<char> {
    text.chars()
        .next()
        .filter(char::is_ascii_alphabetic)
        .map(|letter| letter.to_ascii_uppercase())
}

fn letter_bound(letter: char) -> bool {
    let root = wide(&format!("{letter}:\\"));
    #[allow(unsafe_code)]
    let kind = unsafe { ffi::GetDriveTypeW(root.as_ptr()) };
    kind != DRIVE_NO_ROOT_DIR
}

fn own_session() -> u32 {
    let mut session = 0u32;
    #[allow(unsafe_code)]
    unsafe {
        ffi::ProcessIdToSessionId(ffi::GetCurrentProcessId(), &mut session)
    };
    session
}

fn announce_now(letter: char, change: Change) {
    let deadline = Instant::now() + UNBIND_WAIT;
    while letter_bound(letter) != (change == Change::Arrival) {
        if Instant::now() >= deadline {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if own_session() != 0 {
        scalefs_shell::announce::announce_here(letter, change);
        return;
    }
    for session in user_sessions() {
        if let Err(error) = announce_in(session, letter, change) {
            if error.raw_os_error() == Some(ERROR_NO_TOKEN) {
                continue;
            }
            static REPORTED: AtomicBool = AtomicBool::new(false);
            if !REPORTED.swap(true, Ordering::SeqCst) {
                eprintln!(
                    "scalefsd: cannot announce drive {letter}: to session {session} ({error}); \
                     Explorer windows there are not told when a drive comes or goes (a \
                     service running as LocalSystem can)"
                );
            }
        }
    }
}

fn user_sessions() -> Vec<u32> {
    let mut sessions: *mut ffi::SessionInfo = std::ptr::null_mut();
    let mut count = 0u32;
    #[allow(unsafe_code)]
    let ok = unsafe { ffi::WTSEnumerateSessionsW(0, 0, 1, &mut sessions, &mut count) };
    if ok == 0 || sessions.is_null() {
        return Vec::new();
    }
    #[allow(unsafe_code)]
    let found = unsafe { std::slice::from_raw_parts(sessions, count as usize) }
        .iter()
        .filter(|info| {
            info.session_id != 0
                && matches!(info.state, WTS_ACTIVE | WTS_CONNECTED | WTS_DISCONNECTED)
        })
        .map(|info| info.session_id)
        .collect();
    #[allow(unsafe_code)]
    unsafe {
        ffi::WTSFreeMemory(sessions.cast())
    };
    found
}

struct UserToken(isize);

impl Drop for UserToken {
    fn drop(&mut self) {
        #[cfg(test)]
        tests::record_close(self.0);
        #[allow(unsafe_code)]
        unsafe {
            ffi::CloseHandle(self.0)
        };
    }
}

fn user_token(session: u32) -> std::io::Result<UserToken> {
    let mut token = 0isize;
    #[allow(unsafe_code)]
    if unsafe { ffi::WTSQueryUserToken(session, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(UserToken(token))
}

struct Environment(*mut core::ffi::c_void);

impl Environment {
    fn of(token: &UserToken) -> std::io::Result<Environment> {
        let mut block: *mut core::ffi::c_void = std::ptr::null_mut();
        #[allow(unsafe_code)]
        if unsafe { ffi::CreateEnvironmentBlock(&mut block, token.0, 0) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Environment(block))
    }
}

impl Drop for Environment {
    fn drop(&mut self) {
        #[allow(unsafe_code)]
        unsafe {
            ffi::DestroyEnvironmentBlock(self.0)
        };
    }
}

fn system_directory() -> std::io::Result<Vec<u16>> {
    let mut buffer = vec![0u16; 260];
    #[allow(unsafe_code)]
    let len = unsafe { ffi::GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if len == 0 || len as usize >= buffer.len() {
        return Err(std::io::Error::last_os_error());
    }
    buffer.truncate(len as usize + 1);
    Ok(buffer)
}

fn announce_in(session: u32, letter: char, change: Change) -> std::io::Result<()> {
    let token = user_token(session)?;
    start_helper(token, letter, change, std::env::current_exe)
}

fn start_helper(
    token: UserToken,
    letter: char,
    change: Change,
    exe: impl FnOnce() -> std::io::Result<std::path::PathBuf>,
) -> std::io::Result<()> {
    let exe = exe()?;
    let environment = Environment::of(&token)?;
    let directory = system_directory()?;
    let application = wide(&exe.display().to_string());
    let mut command_line = wide(&format!(
        "\"{}\" session-announce {} {letter}:",
        exe.display(),
        change.word()
    ));
    let mut desktop = wide("winsta0\\default");
    let startup = ffi::StartupInfo {
        cb: std::mem::size_of::<ffi::StartupInfo>() as u32,
        reserved: std::ptr::null_mut(),
        desktop: desktop.as_mut_ptr(),
        title: std::ptr::null_mut(),
        x: 0,
        y: 0,
        x_size: 0,
        y_size: 0,
        x_count_chars: 0,
        y_count_chars: 0,
        fill_attribute: 0,
        flags: 0,
        show_window: 0,
        reserved2_len: 0,
        reserved2: std::ptr::null_mut(),
        std_input: 0,
        std_output: 0,
        std_error: 0,
    };
    let mut process = ffi::ProcessInformation {
        process: 0,
        thread: 0,
        process_id: 0,
        thread_id: 0,
    };
    #[allow(unsafe_code)]
    let started = unsafe {
        ffi::CreateProcessAsUserW(
            token.0,
            application.as_ptr(),
            command_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            environment.0,
            directory.as_ptr(),
            &startup,
            &mut process,
        )
    };
    let error = std::io::Error::last_os_error();
    #[allow(unsafe_code)]
    unsafe {
        for handle in [process.thread, process.process] {
            if handle != 0 {
                ffi::CloseHandle(handle);
            }
        }
    }
    if started == 0 {
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static CLOSED: Mutex<Vec<isize>> = Mutex::new(Vec::new());

    pub(super) fn record_close(raw: isize) {
        CLOSED.lock().unwrap().push(raw);
    }

    #[allow(unsafe_code)]
    mod probe {
        #[link(name = "kernel32", kind = "raw-dylib")]
        unsafe extern "system" {
            pub fn GetCurrentProcess() -> isize;
        }
        #[link(name = "advapi32", kind = "raw-dylib")]
        unsafe extern "system" {
            pub fn OpenProcessToken(process: isize, access: u32, token: *mut isize) -> i32;
        }
    }

    #[allow(unsafe_code)]
    fn variables(environment: &Environment) -> Vec<String> {
        let mut out = Vec::new();
        let mut at = environment.0 as *const u16;
        loop {
            let mut len = 0usize;
            while unsafe { *at.add(len) } != 0 {
                len += 1;
            }
            if len == 0 {
                return out;
            }
            out.push(String::from_utf16_lossy(unsafe {
                std::slice::from_raw_parts(at, len)
            }));
            at = unsafe { at.add(len + 1) };
        }
    }

    #[test]
    fn a_failed_start_closes_the_session_token() {
        use std::os::windows::io::IntoRawHandle;
        let stand_in = std::fs::File::open(std::env::current_exe().unwrap())
            .unwrap()
            .into_raw_handle() as isize;
        let started = start_helper(UserToken(stand_in), 'P', Change::Removal, || {
            Err(std::io::Error::other("injected: no helper path"))
        });
        assert!(started.is_err());
        assert!(
            CLOSED.lock().unwrap().contains(&stand_in),
            "the token was closed on the early return"
        );
    }

    #[test]
    #[allow(unsafe_code)]
    fn the_helper_environment_is_the_users_own() {
        const TOKEN_QUERY: u32 = 0x0008;
        const TOKEN_DUPLICATE: u32 = 0x0002;
        const TOKEN_IMPERSONATE: u32 = 0x0004;
        let mut raw = 0isize;
        let opened = unsafe {
            probe::OpenProcessToken(
                probe::GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                &mut raw,
            )
        };
        assert_ne!(opened, 0, "{}", std::io::Error::last_os_error());
        let token = UserToken(raw);
        let environment = Environment::of(&token).unwrap();
        let variables = variables(&environment);
        let get = |name: &str| {
            variables.iter().find_map(|line| {
                let (key, value) = line.split_once('=')?;
                key.eq_ignore_ascii_case(name).then(|| value.to_string())
            })
        };
        assert_eq!(get("USERNAME"), std::env::var("USERNAME").ok());
        assert_eq!(get("USERPROFILE"), std::env::var("USERPROFILE").ok());
        assert!(std::env::var("CARGO").is_ok(), "cargo sets this for tests");
        assert_eq!(get("CARGO"), None, "nothing of this process's environment");
        assert!(
            system_directory()
                .map(|units| ffi_text(&units)
                    .to_ascii_lowercase()
                    .ends_with("\\system32"))
                .unwrap_or(false)
        );
    }

    fn ffi_text(units: &[u16]) -> String {
        let end = units
            .iter()
            .position(|&unit| unit == 0)
            .unwrap_or(units.len());
        String::from_utf16_lossy(&units[..end])
    }
}
