use crate::ffi::{self, HKEY_LOCAL_MACHINE, wide};
use core::ffi::c_void;
use std::path::Path;

pub const CLSID_TEXT: &str = "{858CF4EC-8CF3-4F38-BD79-5CA41D175237}";
pub const DLL_NAME: &str = "scalefs_shell.dll";
pub const APP_ID: &str = "ScaleFS";

const CLASS_KEY: &str = "SOFTWARE\\Classes\\CLSID\\{858CF4EC-8CF3-4F38-BD79-5CA41D175237}";
const VERB_KEY: &str = "SOFTWARE\\Classes\\Drive\\shell\\eject";
const APP_ID_KEY: &str = "SOFTWARE\\Classes\\AppUserModelId\\ScaleFS";
const APP_DISPLAY_NAME: &str = "ScaleFS";

const KEY_WRITE: u32 = 0x0002_0006;
const REG_SZ: u32 = 1;
const RRF_RT_REG_SZ: u32 = 0x0000_0002;
const ERROR_SUCCESS: i32 = 0;
const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_ACCESS_DENIED: i32 = 5;
const SHCNE_ASSOCCHANGED: i32 = 0x0800_0000;

struct Key(isize);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe { ffi::RegCloseKey(self.0) };
    }
}

fn status(what: &str, code: i32) -> String {
    if code == ERROR_ACCESS_DENIED {
        format!("{what}: access denied — run this from an elevated (administrator) prompt")
    } else {
        format!("{what}: {}", std::io::Error::from_raw_os_error(code))
    }
}

fn create(path: &str) -> Result<Key, String> {
    let path_w = wide(path);
    let mut key = 0isize;
    let code = unsafe {
        ffi::RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            path_w.as_ptr(),
            0,
            std::ptr::null(),
            0,
            KEY_WRITE,
            std::ptr::null(),
            &mut key,
            std::ptr::null_mut(),
        )
    };
    if code != ERROR_SUCCESS {
        return Err(status(&format!("cannot create HKLM\\{path}"), code));
    }
    Ok(Key(key))
}

fn set(key: &Key, name: Option<&str>, value: &str) -> Result<(), String> {
    let name_w = name.map(wide);
    let data = wide(value);
    let code = unsafe {
        ffi::RegSetValueExW(
            key.0,
            name_w
                .as_ref()
                .map_or(std::ptr::null(), |name| name.as_ptr()),
            0,
            REG_SZ,
            data.as_ptr() as *const u8,
            (data.len() * 2) as u32,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(status(
            &format!("cannot write {}", name.unwrap_or("(default)")),
            code,
        ));
    }
    Ok(())
}

fn read(path: &str, name: &str) -> Option<String> {
    let path_w = wide(path);
    let name_w = wide(name);
    let mut buffer = vec![0u16; 1024];
    let mut len = (buffer.len() * 2) as u32;
    let code = unsafe {
        ffi::RegGetValueW(
            HKEY_LOCAL_MACHINE,
            path_w.as_ptr(),
            name_w.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buffer.as_mut_ptr() as *mut c_void,
            &mut len,
        )
    };
    (code == ERROR_SUCCESS).then(|| ffi::from_wide(&buffer))
}

fn delete_tree(path: &str) -> Result<(), String> {
    let path_w = wide(path);
    let code = unsafe { ffi::RegDeleteTreeW(HKEY_LOCAL_MACHINE, path_w.as_ptr()) };
    match code {
        ERROR_SUCCESS | ERROR_FILE_NOT_FOUND => Ok(()),
        other => Err(status(&format!("cannot remove HKLM\\{path}"), other)),
    }
}

fn notify_associations_changed() {
    unsafe { ffi::SHChangeNotify(SHCNE_ASSOCCHANGED, 0, std::ptr::null(), std::ptr::null()) };
}

pub fn recorded_endpoint() -> Option<String> {
    read(CLASS_KEY, "Endpoint").filter(|text| !text.is_empty())
}

pub fn register(dll: &Path, endpoint: Option<&str>) -> Result<(), String> {
    let class = create(CLASS_KEY)?;
    set(&class, None, "ScaleFS Eject")?;
    set(&class, Some("Endpoint"), endpoint.unwrap_or(""))?;
    let server = create(&format!("{CLASS_KEY}\\InprocServer32"))?;
    set(&server, None, &dll.display().to_string())?;
    set(&server, Some("ThreadingModel"), "Apartment")?;
    let identity = create(APP_ID_KEY)?;
    set(&identity, Some("DisplayName"), APP_DISPLAY_NAME)?;
    let verb = create(VERB_KEY)?;
    set(&verb, Some("ExplorerCommandHandler"), CLSID_TEXT)?;
    set(&verb, Some("CommandStateSync"), "")?;
    notify_associations_changed();
    Ok(())
}

pub fn unregister() -> Result<(), String> {
    if read(VERB_KEY, "ExplorerCommandHandler")
        .is_some_and(|handler| handler.eq_ignore_ascii_case(CLSID_TEXT))
    {
        delete_tree(VERB_KEY)?;
    }
    delete_tree(CLASS_KEY)?;
    delete_tree(APP_ID_KEY)?;
    notify_associations_changed();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_identity_key_is_named_by_the_app_id() {
        assert_eq!(
            APP_ID_KEY,
            format!("SOFTWARE\\Classes\\AppUserModelId\\{APP_ID}")
        );
    }
}
