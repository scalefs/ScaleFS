use core::ffi::c_void;

pub type Hresult = i32;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Guid {
        Guid {
            data1,
            data2,
            data3,
            data4,
        }
    }
}

#[repr(C)]
pub struct DevPropKey {
    pub fmtid: Guid,
    pub pid: u32,
}

pub type Hstring = *mut c_void;

pub type EnumResNameProc = unsafe extern "system" fn(isize, *const u16, *mut u16, isize) -> i32;

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "system" {
    pub fn GetDriveTypeW(root: *const u16) -> u32;
    pub fn GetVolumeInformationW(
        root: *const u16,
        volume_name: *mut u16,
        volume_name_len: u32,
        serial: *mut u32,
        max_component: *mut u32,
        flags: *mut u32,
        fs_name: *mut u16,
        fs_name_len: u32,
    ) -> i32;
    pub fn OutputDebugStringW(text: *const u16);
    pub fn GetModuleHandleW(name: *const u16) -> isize;
    pub fn GetModuleHandleExW(flags: u32, module_name: *const u16, module: *mut isize) -> i32;
    pub fn FreeLibrary(module: isize) -> i32;
    pub fn FreeLibraryAndExitThread(module: isize, exit_code: u32) -> !;
    pub fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        security: *const c_void,
        disposition: u32,
        flags: u32,
        template: isize,
    ) -> isize;
    pub fn DeviceIoControl(
        device: isize,
        code: u32,
        input: *const c_void,
        input_len: u32,
        output: *mut c_void,
        output_len: u32,
        returned: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
    pub fn CloseHandle(handle: isize) -> i32;
    pub fn GetLastError() -> u32;
    pub fn EnumResourceNamesW(
        module: isize,
        kind: *const u16,
        callback: EnumResNameProc,
        param: isize,
    ) -> i32;
}

#[link(name = "user32", kind = "raw-dylib")]
unsafe extern "system" {
    pub fn MessageBoxW(owner: isize, text: *const u16, caption: *const u16, kind: u32) -> i32;
    pub fn LoadMenuW(module: isize, name: *const u16) -> isize;
    pub fn DestroyMenu(menu: isize) -> i32;
    pub fn GetMenuItemCount(menu: isize) -> i32;
    pub fn GetMenuStringW(menu: isize, item: u32, text: *mut u16, max: i32, flags: u32) -> i32;
    pub fn GetSubMenu(menu: isize, position: i32) -> isize;
}

#[link(name = "ole32", kind = "raw-dylib")]
unsafe extern "system" {
    pub fn CoTaskMemFree(memory: *mut c_void);
}

#[link(name = "shlwapi", kind = "raw-dylib")]
unsafe extern "system" {
    pub fn SHLoadIndirectString(
        source: *const u16,
        out: *mut u16,
        out_len: u32,
        reserved: *mut c_void,
    ) -> Hresult;
    pub fn SHStrDupW(source: *const u16, out: *mut *mut u16) -> Hresult;
}

#[link(name = "shell32", kind = "raw-dylib")]
unsafe extern "system" {
    pub fn SHChangeNotify(event: i32, flags: u32, item1: *const c_void, item2: *const c_void);
}

#[link(name = "cfgmgr32", kind = "raw-dylib")]
unsafe extern "system" {
    pub fn CM_Locate_DevNodeW(devinst: *mut u32, device_id: *const u16, flags: u32) -> u32;
    pub fn CM_Request_Device_EjectW(
        devinst: u32,
        veto_type: *mut i32,
        veto_name: *mut u16,
        veto_name_len: u32,
        flags: u32,
    ) -> u32;
    pub fn CM_Get_DevNode_PropertyW(
        devinst: u32,
        key: *const DevPropKey,
        kind: *mut u32,
        buffer: *mut u8,
        size: *mut u32,
        flags: u32,
    ) -> u32;
}

#[link(name = "combase", kind = "raw-dylib")]
unsafe extern "system" {
    pub fn RoInitialize(init_type: u32) -> Hresult;
    pub fn RoUninitialize();
    pub fn RoGetActivationFactory(
        class: Hstring,
        iid: *const Guid,
        factory: *mut *mut c_void,
    ) -> Hresult;
    pub fn RoActivateInstance(class: Hstring, instance: *mut *mut c_void) -> Hresult;
    pub fn WindowsCreateString(source: *const u16, len: u32, out: *mut Hstring) -> Hresult;
    pub fn WindowsDeleteString(string: Hstring) -> Hresult;
}

#[link(name = "advapi32", kind = "raw-dylib")]
unsafe extern "system" {
    pub fn RegCreateKeyExW(
        key: isize,
        subkey: *const u16,
        reserved: u32,
        class: *const u16,
        options: u32,
        desired: u32,
        security: *const c_void,
        result: *mut isize,
        disposition: *mut u32,
    ) -> i32;
    pub fn RegSetValueExW(
        key: isize,
        name: *const u16,
        reserved: u32,
        kind: u32,
        data: *const u8,
        len: u32,
    ) -> i32;
    pub fn RegDeleteTreeW(key: isize, subkey: *const u16) -> i32;
    pub fn RegDeleteValueW(key: isize, value_name: *const u16) -> i32;
    pub fn RegCloseKey(key: isize) -> i32;
    pub fn RegOpenKeyExW(
        key: isize,
        subkey: *const u16,
        options: u32,
        desired: u32,
        result: *mut isize,
    ) -> i32;
    pub fn RegQueryValueExW(
        key: isize,
        value_name: *const u16,
        reserved: *mut u32,
        kind: *mut u32,
        data: *mut u8,
        len: *mut u32,
    ) -> i32;
    pub fn RegQueryInfoKeyW(
        key: isize,
        class: *mut u16,
        class_len: *mut u32,
        reserved: *mut u32,
        subkeys: *mut u32,
        max_subkey_len: *mut u32,
        max_class_len: *mut u32,
        values: *mut u32,
        max_value_name_len: *mut u32,
        max_value_len: *mut u32,
        security_descriptor_len: *mut u32,
        last_write: *mut c_void,
    ) -> i32;
    pub fn RegCopyTreeW(source: isize, subkey: *const u16, destination: isize) -> i32;
}

pub const HKEY_LOCAL_MACHINE: isize = 0x8000_0002_u32 as i32 as isize;
#[cfg(test)]
pub const HKEY_CURRENT_USER: isize = 0x8000_0001_u32 as i32 as isize;

pub fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn from_wide(buffer: &[u16]) -> String {
    let end = buffer
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..end])
}

pub unsafe fn from_wide_ptr(text: *const u16) -> String {
    if text.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while unsafe { *text.add(len) } != 0 {
        len += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) })
}

pub fn debug_line(text: &str) {
    let line = wide(&format!("{text}\n"));
    unsafe { OutputDebugStringW(line.as_ptr()) };
}
