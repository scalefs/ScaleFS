use scalefs_ipc::endpoint::Endpoint;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ServiceOptions {
    pub endpoint: Endpoint,
    pub state_dir: Option<PathBuf>,
}

pub fn default_state_dir() -> PathBuf {
    #[cfg(windows)]
    {
        let program_data =
            std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into());
        PathBuf::from(program_data).join("ScaleFS")
    }
    #[cfg(unix)]
    {
        PathBuf::from("/var/lib/scalefs")
    }
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellTrust {
    Service,
    RegisteringUser,
}

#[cfg(windows)]
pub fn shell_register(endpoint: &Endpoint, trust: ShellTrust, replace: bool) -> Result<(), String> {
    let exe = std::env::current_exe()
        .map_err(|error| format!("cannot resolve this executable's path: {error}"))?;
    let dll = exe.with_file_name(scalefs_shell::register::DLL_NAME);
    if !dll.is_file() {
        return Err(format!(
            "{} is not installed next to scalefsd ({})",
            scalefs_shell::register::DLL_NAME,
            dll.display()
        ));
    }
    let account = match trust {
        ShellTrust::Service => scalefs_ipc::trust::LOCAL_SYSTEM_SID.to_string(),
        ShellTrust::RegisteringUser => scalefs_ipc::trust::own_account()
            .map_err(|error| format!("cannot read this account's identity: {error}"))?,
    };
    let recorded = (*endpoint != Endpoint::default_endpoint()).then(|| endpoint.as_str());
    scalefs_shell::register::register(&scalefs_shell::register::Registration {
        dll: &dll,
        endpoint: recorded,
        account: &account,
        replace,
    })?;
    println!(
        "registered Explorer's Eject command for ScaleFS volumes ({})",
        dll.display()
    );
    if trust == ShellTrust::RegisteringUser {
        eprintln!(
            "warning: the command trusts a daemon running as this account ({account}), not \
             the service: any program running as this account could stand in for the \
             daemon. Use this only for a daemon you run yourself as this account."
        );
    }
    Ok(())
}

#[cfg(windows)]
pub fn shell_unregister() -> Result<(), String> {
    scalefs_shell::register::unregister()?;
    println!("removed Explorer's Eject command for ScaleFS volumes");
    Ok(())
}

fn shutdown_via_self_client(endpoint: &Endpoint) {
    use scalefs_ipc::json::{Value, object};
    if let Ok(mut client) =
        scalefs_ipc::client::Client::connect(endpoint, std::time::Duration::from_secs(3))
    {
        let _ = client.call("shutdown", object(vec![("force", Value::Bool(true))]));
    }
}

fn serve_arguments(endpoint: &Endpoint, state_dir: Option<&std::path::Path>) -> String {
    let mut arguments = String::from("serve");
    if *endpoint != Endpoint::default_endpoint() {
        arguments.push_str(" --endpoint ");
        arguments.push_str(endpoint.as_str());
    }
    if let Some(dir) = state_dir {
        arguments.push_str(" --state-dir \"");
        arguments.push_str(&dir.display().to_string());
        arguments.push('"');
    }
    arguments
}

#[cfg(target_os = "linux")]
fn systemd_unit(exe: &std::path::Path, endpoint: &Endpoint, state_dir: &std::path::Path) -> String {
    format!(
        "[Unit]\n\
         Description=ScaleFS management daemon\n\
         Documentation=https://github.com/scalefs/scalefs\n\
         After=local-fs.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={} {}\n\
         Restart=on-failure\n\
         # A stop flushes and commits every attachment (the durability\n\
         # point); give large pools time before the kill escalates.\n\
         TimeoutStopSec=180\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        exe.display(),
        serve_arguments(endpoint, Some(state_dir)),
    )
}

pub fn install(options: &ServiceOptions) -> Result<(), String> {
    let state_dir = options.state_dir.clone().unwrap_or_else(default_state_dir);
    #[cfg(windows)]
    {
        windows::install(&options.endpoint, &state_dir)
    }
    #[cfg(target_os = "linux")]
    {
        linux_install(&options.endpoint, &state_dir)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = state_dir;
        Err(
            "service packaging on macOS arrives with the macOS milestone; \
             run `scalefsd serve` directly for now"
                .to_string(),
        )
    }
}

pub fn uninstall() -> Result<(), String> {
    #[cfg(windows)]
    {
        windows::uninstall()
    }
    #[cfg(target_os = "linux")]
    {
        if !scalefs_ipc::trust::process_is_privileged() {
            return Err("removing the systemd unit requires root".to_string());
        }
        let unit = std::path::Path::new("/etc/systemd/system/scalefsd.service");
        match std::fs::remove_file(unit) {
            Ok(()) => {
                println!("removed {}", unit.display());
                println!("next: systemctl daemon-reload");
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Err(format!("{} is not installed", unit.display()))
            }
            Err(error) => Err(format!("cannot remove {}: {error}", unit.display())),
        }
    }
    #[cfg(target_os = "macos")]
    {
        Err("service packaging on macOS arrives with the macOS milestone".to_string())
    }
}

pub fn run(options: ServiceOptions) -> Result<(), String> {
    #[cfg(windows)]
    {
        windows::run(options)
    }
    #[cfg(unix)]
    {
        let _ = options;
        Err("`service run` is the Windows service entry point; \
             on this platform run `scalefsd serve` (under systemd, after \
             `scalefsd service install`)"
            .to_string())
    }
}

#[cfg(target_os = "linux")]
fn linux_install(endpoint: &Endpoint, state_dir: &std::path::Path) -> Result<(), String> {
    if !scalefs_ipc::trust::process_is_privileged() {
        return Err("installing the systemd unit requires root".to_string());
    }
    let exe = std::env::current_exe()
        .map_err(|error| format!("cannot resolve this executable's path: {error}"))?;
    std::fs::create_dir_all(state_dir)
        .map_err(|error| format!("cannot create {}: {error}", state_dir.display()))?;
    let unit_path = std::path::Path::new("/etc/systemd/system/scalefsd.service");
    let unit = systemd_unit(&exe, endpoint, state_dir);
    std::fs::write(unit_path, unit.as_bytes())
        .map_err(|error| format!("cannot write {}: {error}", unit_path.display()))?;
    println!("installed {}", unit_path.display());
    println!("state directory: {}", state_dir.display());
    println!("next: systemctl daemon-reload && systemctl enable --now scalefsd");
    Ok(())
}

#[cfg(unix)]
pub fn arm_termination_signals(endpoint: &Endpoint) {
    #[allow(unsafe_code)]
    mod ffi {
        #[repr(C, align(8))]
        pub struct SigSet(pub [u8; 128]);
        unsafe extern "C" {
            pub fn sigemptyset(set: *mut SigSet) -> i32;
            pub fn sigaddset(set: *mut SigSet, signal: i32) -> i32;
            pub fn pthread_sigmask(how: i32, set: *const SigSet, old: *mut SigSet) -> i32;
            pub fn sigwait(set: *const SigSet, signal: *mut i32) -> i32;
        }
    }
    const SIGINT: i32 = 2;
    const SIGTERM: i32 = 15;
    #[cfg(target_os = "linux")]
    const SIG_BLOCK: i32 = 0;
    #[cfg(target_os = "macos")]
    const SIG_BLOCK: i32 = 1;

    let mut set = ffi::SigSet([0u8; 128]);
    #[allow(unsafe_code)]
    {
        unsafe {
            ffi::sigemptyset(&mut set);
            ffi::sigaddset(&mut set, SIGINT);
            ffi::sigaddset(&mut set, SIGTERM);
            if ffi::pthread_sigmask(SIG_BLOCK, &set, std::ptr::null_mut()) != 0 {
                return;
            }
        }
    }
    let endpoint = endpoint.clone();
    let spawned = std::thread::Builder::new()
        .name("scalefsd-signals".to_string())
        .spawn(move || {
            let mut signal: i32 = 0;
            #[allow(unsafe_code)]
            let rc = unsafe { ffi::sigwait(&set, &mut signal) };
            if rc != 0 {
                return;
            }
            eprintln!(
                "scalefsd: received signal {signal}; shutting down \
                 (signal again to force-quit)"
            );
            shutdown_via_self_client(&endpoint);
            #[allow(unsafe_code)]
            let rc = unsafe { ffi::sigwait(&set, &mut signal) };
            if rc == 0 {
                std::process::exit(1);
            }
        });
    drop(spawned);
}

#[cfg(windows)]
pub fn arm_console_handler(endpoint: &Endpoint) {
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicBool, Ordering};

    static ENDPOINT: OnceLock<Endpoint> = OnceLock::new();
    static FIRED: AtomicBool = AtomicBool::new(false);

    #[allow(unsafe_code)]
    mod ffi {
        pub type HandlerRoutine = unsafe extern "system" fn(u32) -> i32;
        #[link(name = "kernel32", kind = "raw-dylib")]
        unsafe extern "system" {
            pub fn SetConsoleCtrlHandler(handler: HandlerRoutine, add: i32) -> i32;
        }
    }

    extern "system" fn on_console_event(_event: u32) -> i32 {
        if FIRED.swap(true, Ordering::SeqCst) {
            return 0;
        }
        if let Some(endpoint) = ENDPOINT.get() {
            shutdown_via_self_client(endpoint);
        }
        1
    }

    let _ = ENDPOINT.set(endpoint.clone());
    #[allow(unsafe_code)]
    unsafe {
        ffi::SetConsoleCtrlHandler(on_console_event, 1);
    }
}

#[cfg(windows)]
mod windows {
    use super::{ServiceOptions, shutdown_via_self_client};
    use crate::ServeOptions;
    use core::ffi::c_void;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicIsize, AtomicU32, Ordering};

    #[allow(unsafe_code)]
    mod ffi {
        use core::ffi::c_void;
        pub type ServiceMainFn = unsafe extern "system" fn(u32, *mut *mut u16);
        pub type HandlerExFn = unsafe extern "system" fn(u32, u32, *mut c_void, *mut c_void) -> u32;

        #[repr(C)]
        pub struct ServiceTableEntry {
            pub name: *const u16,
            pub main: Option<ServiceMainFn>,
        }

        #[repr(C)]
        pub struct ServiceStatus {
            pub service_type: u32,
            pub current_state: u32,
            pub controls_accepted: u32,
            pub win32_exit_code: u32,
            pub service_specific_exit_code: u32,
            pub check_point: u32,
            pub wait_hint: u32,
        }

        #[link(name = "advapi32", kind = "raw-dylib")]
        unsafe extern "system" {
            pub fn OpenSCManagerW(
                machine: *const u16,
                database: *const u16,
                desired_access: u32,
            ) -> isize;
            pub fn CreateServiceW(
                scm: isize,
                name: *const u16,
                display_name: *const u16,
                desired_access: u32,
                service_type: u32,
                start_type: u32,
                error_control: u32,
                binary_path: *const u16,
                load_order_group: *const u16,
                tag_id: *mut u32,
                dependencies: *const u16,
                account: *const u16,
                password: *const u16,
            ) -> isize;
            pub fn OpenServiceW(scm: isize, name: *const u16, desired_access: u32) -> isize;
            pub fn DeleteService(service: isize) -> i32;
            pub fn CloseServiceHandle(handle: isize) -> i32;
            pub fn StartServiceCtrlDispatcherW(table: *const ServiceTableEntry) -> i32;
            pub fn RegisterServiceCtrlHandlerExW(
                name: *const u16,
                handler: HandlerExFn,
                context: *mut c_void,
            ) -> isize;
            pub fn SetServiceStatus(handle: isize, status: *mut ServiceStatus) -> i32;
        }
    }

    const SERVICE_NAME: &str = "scalefsd";
    const DISPLAY_NAME: &str = "ScaleFS Daemon";

    const SC_MANAGER_CONNECT: u32 = 0x0001;
    const SC_MANAGER_CREATE_SERVICE: u32 = 0x0002;
    const SERVICE_ALL_ACCESS: u32 = 0x000F_01FF;
    const DELETE: u32 = 0x0001_0000;
    const SERVICE_WIN32_OWN_PROCESS: u32 = 0x0000_0010;
    const SERVICE_AUTO_START: u32 = 0x0000_0002;
    const SERVICE_ERROR_NORMAL: u32 = 0x0000_0001;

    const SERVICE_STOPPED: u32 = 1;
    const SERVICE_START_PENDING: u32 = 2;
    const SERVICE_STOP_PENDING: u32 = 3;
    const SERVICE_RUNNING: u32 = 4;

    const SERVICE_ACCEPT_STOP: u32 = 0x0001;
    const SERVICE_ACCEPT_SHUTDOWN: u32 = 0x0004;
    const SERVICE_ACCEPT_PRESHUTDOWN: u32 = 0x0100;

    const SERVICE_CONTROL_STOP: u32 = 1;
    const SERVICE_CONTROL_INTERROGATE: u32 = 4;
    const SERVICE_CONTROL_SHUTDOWN: u32 = 5;
    const SERVICE_CONTROL_PRESHUTDOWN: u32 = 0x0F;

    const NO_ERROR: u32 = 0;
    const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;
    const ERROR_ACCESS_DENIED: i32 = 5;
    const ERROR_SERVICE_EXISTS: i32 = 1073;
    const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
    const ERROR_SERVICE_MARKED_FOR_DELETE: i32 = 1072;
    const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: i32 = 1063;
    const ERROR_SERVICE_SPECIFIC_ERROR: u32 = 1066;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    struct ScHandle(isize);
    impl Drop for ScHandle {
        fn drop(&mut self) {
            #[allow(unsafe_code)]
            unsafe {
                ffi::CloseServiceHandle(self.0);
            }
        }
    }

    static STATUS_HANDLE: AtomicIsize = AtomicIsize::new(0);
    static CHECK_POINT: AtomicU32 = AtomicU32::new(0);
    static OPTIONS: OnceLock<ServiceOptions> = OnceLock::new();

    fn set_status(state: u32, accepted: u32, wait_hint_ms: u32, exit_code: u32) {
        let handle = STATUS_HANDLE.load(Ordering::SeqCst);
        if handle == 0 {
            return;
        }
        let pending = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING;
        let mut status = ffi::ServiceStatus {
            service_type: SERVICE_WIN32_OWN_PROCESS,
            current_state: state,
            controls_accepted: accepted,
            win32_exit_code: if exit_code == 0 {
                NO_ERROR
            } else {
                ERROR_SERVICE_SPECIFIC_ERROR
            },
            service_specific_exit_code: exit_code,
            check_point: if pending {
                CHECK_POINT.fetch_add(1, Ordering::SeqCst) + 1
            } else {
                0
            },
            wait_hint: wait_hint_ms,
        };
        #[allow(unsafe_code)]
        unsafe {
            ffi::SetServiceStatus(handle, &mut status);
        }
    }

    pub fn install(
        endpoint: &scalefs_ipc::endpoint::Endpoint,
        state_dir: &std::path::Path,
    ) -> Result<(), String> {
        let exe = std::env::current_exe()
            .map_err(|error| format!("cannot resolve this executable's path: {error}"))?;
        let binary_path = format!(
            "\"{}\" service run {}",
            exe.display(),
            super::serve_arguments(endpoint, Some(state_dir))
                .strip_prefix("serve")
                .map(str::trim_start)
                .unwrap_or_default(),
        );
        #[allow(unsafe_code)]
        let scm = unsafe {
            ffi::OpenSCManagerW(
                std::ptr::null(),
                std::ptr::null(),
                SC_MANAGER_CREATE_SERVICE,
            )
        };
        if scm == 0 {
            return Err(scm_error("cannot open the service control manager"));
        }
        let scm = ScHandle(scm);
        let name = wide(SERVICE_NAME);
        let display = wide(DISPLAY_NAME);
        let path = wide(&binary_path);
        #[allow(unsafe_code)]
        let service = unsafe {
            ffi::CreateServiceW(
                scm.0,
                name.as_ptr(),
                display.as_ptr(),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                path.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if service == 0 {
            return Err(match std::io::Error::last_os_error().raw_os_error() {
                Some(ERROR_SERVICE_EXISTS) => {
                    "the scalefsd service is already installed (uninstall it first to \
                     change its configuration)"
                        .to_string()
                }
                _ => scm_error("cannot create the service"),
            });
        }
        drop(ScHandle(service));
        if let Err(error) = std::fs::create_dir_all(state_dir) {
            eprintln!(
                "warning: cannot create {} yet ({error}); the service will create it",
                state_dir.display(),
            );
        }
        println!("installed service '{SERVICE_NAME}' ({DISPLAY_NAME})");
        println!("  runs: {binary_path}");
        println!("  account: LocalSystem, start: automatic (boot)");
        if let Err(why) = super::shell_register(endpoint, super::ShellTrust::Service, false) {
            println!("  Explorer's Eject command not registered: {why}");
        }
        println!("start it now with: net start {SERVICE_NAME}");
        Ok(())
    }

    pub fn uninstall() -> Result<(), String> {
        #[allow(unsafe_code)]
        let scm =
            unsafe { ffi::OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
        if scm == 0 {
            return Err(scm_error("cannot open the service control manager"));
        }
        let scm = ScHandle(scm);
        let name = wide(SERVICE_NAME);
        #[allow(unsafe_code)]
        let service = unsafe { ffi::OpenServiceW(scm.0, name.as_ptr(), DELETE) };
        if service == 0 {
            return Err(match std::io::Error::last_os_error().raw_os_error() {
                Some(ERROR_SERVICE_DOES_NOT_EXIST) => {
                    "the scalefsd service is not installed".to_string()
                }
                _ => scm_error("cannot open the service"),
            });
        }
        let service = ScHandle(service);
        #[allow(unsafe_code)]
        let deleted = unsafe { ffi::DeleteService(service.0) };
        if deleted == 0 {
            return Err(match std::io::Error::last_os_error().raw_os_error() {
                Some(ERROR_SERVICE_MARKED_FOR_DELETE) => {
                    "the service is already marked for deletion; it disappears once \
                     it is stopped and every handle to it closes"
                        .to_string()
                }
                _ => scm_error("cannot delete the service"),
            });
        }
        println!(
            "removed service '{SERVICE_NAME}' (if it was running, stop it with: \
             net stop {SERVICE_NAME})"
        );
        if let Err(why) = super::shell_unregister() {
            eprintln!("warning: Explorer's Eject command was not removed: {why}");
        }
        Ok(())
    }

    fn scm_error(what: &str) -> String {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_ACCESS_DENIED) {
            format!("{what}: access denied — run this from an elevated (administrator) prompt")
        } else {
            format!("{what}: {error}")
        }
    }

    pub fn run(options: ServiceOptions) -> Result<(), String> {
        let _ = OPTIONS.set(options);
        let name = wide(SERVICE_NAME);
        let table = [
            ffi::ServiceTableEntry {
                name: name.as_ptr(),
                main: Some(service_main as ffi::ServiceMainFn),
            },
            ffi::ServiceTableEntry {
                name: std::ptr::null(),
                main: None,
            },
        ];
        #[allow(unsafe_code)]
        let dispatched = unsafe { ffi::StartServiceCtrlDispatcherW(table.as_ptr()) };
        if dispatched == 0 {
            let error = std::io::Error::last_os_error();
            return Err(
                if error.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
                    "`service run` must be started by the service control manager \
                     (install with `scalefsd service install`, start with `net start \
                     scalefsd`); to run in this console use `scalefsd serve`"
                        .to_string()
                } else {
                    format!("cannot connect to the service control manager: {error}")
                },
            );
        }
        Ok(())
    }

    extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
        let name = wide(SERVICE_NAME);
        #[allow(unsafe_code)]
        let handle = unsafe {
            ffi::RegisterServiceCtrlHandlerExW(name.as_ptr(), service_handler, std::ptr::null_mut())
        };
        if handle == 0 {
            return;
        }
        STATUS_HANDLE.store(handle, Ordering::SeqCst);
        set_status(SERVICE_START_PENDING, 0, 120_000, 0);

        let Some(options) = OPTIONS.get() else {
            set_status(SERVICE_STOPPED, 0, 0, 1);
            return;
        };
        let mut serve = ServeOptions::new(&options.endpoint);
        serve.state_dir = options.state_dir.clone();
        serve.on_ready = Some(Box::new(|| {
            set_status(
                SERVICE_RUNNING,
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PRESHUTDOWN,
                0,
                0,
            );
        }));
        match crate::serve_with(serve) {
            Ok(()) => set_status(SERVICE_STOPPED, 0, 0, 0),
            Err(message) => {
                eprintln!("scalefsd: {message}");
                set_status(SERVICE_STOPPED, 0, 0, 1);
            }
        }
    }

    extern "system" fn service_handler(
        control: u32,
        _event_type: u32,
        _event_data: *mut c_void,
        _context: *mut c_void,
    ) -> u32 {
        match control {
            SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN | SERVICE_CONTROL_PRESHUTDOWN => {
                set_status(SERVICE_STOP_PENDING, 0, 180_000, 0);
                if let Some(options) = OPTIONS.get() {
                    let endpoint = options.endpoint.clone();
                    let _ = std::thread::Builder::new()
                        .name("scalefsd-service-stop".to_string())
                        .spawn(move || shutdown_via_self_client(&endpoint));
                }
                NO_ERROR
            }
            SERVICE_CONTROL_INTERROGATE => NO_ERROR,
            _ => ERROR_CALL_NOT_IMPLEMENTED,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serve_arguments_carry_only_what_differs() {
        let default = Endpoint::default_endpoint();
        assert_eq!(serve_arguments(&default, None), "serve");
        let with_state = serve_arguments(&default, Some(std::path::Path::new("/var/lib/scalefs")));
        assert!(with_state.starts_with("serve --state-dir \""));
        assert!(with_state.contains("scalefs"));
        let custom = Endpoint::new("side-by-side");
        let all = serve_arguments(&custom, Some(std::path::Path::new("C:\\Program Data\\X")));
        assert!(all.contains("--endpoint side-by-side"));
        assert!(all.contains("\"C:\\Program Data\\X\""));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_systemd_unit_names_the_essentials() {
        let unit = systemd_unit(
            std::path::Path::new("/usr/local/bin/scalefsd"),
            &Endpoint::default_endpoint(),
            std::path::Path::new("/var/lib/scalefs"),
        );
        assert!(
            unit.contains(
                "ExecStart=/usr/local/bin/scalefsd serve --state-dir \"/var/lib/scalefs\""
            )
        );
        assert!(unit.contains("WantedBy=multi-user.target"));
        assert!(unit.contains("TimeoutStopSec=180"));
        assert!(unit.contains("Restart=on-failure"));
    }

    #[test]
    fn the_default_state_dir_is_platform_conventional() {
        let dir = default_state_dir();
        #[cfg(windows)]
        assert!(dir.ends_with("ScaleFS"));
        #[cfg(unix)]
        assert_eq!(dir, std::path::PathBuf::from("/var/lib/scalefs"));
    }
}
