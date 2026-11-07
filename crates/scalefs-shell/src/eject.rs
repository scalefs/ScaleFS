use crate::ffi::{self, DevPropKey, Guid, from_wide, wide};
use crate::outcome::{self, Outcome, Record};
use crate::{notice, text};
use core::ffi::c_void;
use scalefs_ipc::client::Client;
use scalefs_ipc::endpoint::Endpoint;
use scalefs_ipc::json::{Value, object};
use scalefs_ipc::trust::ServerIdentity;
use std::time::{Duration, Instant};

const FILE_SYSTEM_NAME: &str = "ScaleFS";
const DRIVE_REMOVABLE: u32 = 2;
const DRIVE_FIXED: u32 = 3;

const FILE_SHARE_READ: u32 = 0x1;
const FILE_SHARE_WRITE: u32 = 0x2;
const OPEN_EXISTING: u32 = 3;
const INVALID_HANDLE_VALUE: isize = -1;
const ERROR_MORE_DATA: u32 = 234;
const IOCTL_MOUNTDEV_QUERY_DEVICE_NAME: u32 = 0x004D_0008;
const CM_LOCATE_DEVNODE_NORMAL: u32 = 0;

const DEVPKEY_NAME: DevPropKey = DevPropKey {
    fmtid: Guid::new(
        0xb725_f130,
        0x47ef,
        0x101a,
        [0xa5, 0xf1, 0x02, 0x60, 0x8c, 0x9e, 0xeb, 0xac],
    ),
    pid: 10,
};
const DEVPROP_TYPE_STRING: u32 = 0x12;
const CR_BUFFER_SMALL: u32 = 0x1a;

const RECORD_WAIT: Duration = Duration::from_secs(3);

pub fn is_ejectable_scalefs_volume(letter: char) -> bool {
    is_local_disk(letter)
        && file_system_is_scalefs(letter)
        && volume_device_name(letter)
            .and_then(|name| outcome::pool_id_from_device_name(&name))
            .is_some_and(|pool_id| locate(&outcome::instance_id(&pool_id)).is_ok())
}

fn is_local_disk(letter: char) -> bool {
    let root = wide(&format!("{letter}:\\"));
    let kind = unsafe { ffi::GetDriveTypeW(root.as_ptr()) };
    matches!(kind, DRIVE_REMOVABLE | DRIVE_FIXED)
}

fn locate(instance: &str) -> Result<u32, u32> {
    let instance_w = wide(instance);
    let mut devinst = 0u32;
    let cr = unsafe {
        ffi::CM_Locate_DevNodeW(&mut devinst, instance_w.as_ptr(), CM_LOCATE_DEVNODE_NORMAL)
    };
    if cr == outcome::CR_SUCCESS {
        Ok(devinst)
    } else {
        Err(cr)
    }
}

struct Handle(isize);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { ffi::CloseHandle(self.0) };
    }
}

fn volume_device_name(letter: char) -> Option<String> {
    query_device_name(letter, 1 + 128)
}

fn query_device_name(letter: char, initial_units: usize) -> Option<String> {
    let path = wide(&format!("\\\\.\\{letter}:"));
    let raw = unsafe {
        ffi::CreateFileW(
            path.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            0,
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return None;
    }
    let volume = Handle(raw);
    let mut buffer = vec![0u16; initial_units.max(2)];
    for _ in 0..2 {
        let mut returned = 0u32;
        let ok = unsafe {
            ffi::DeviceIoControl(
                volume.0,
                IOCTL_MOUNTDEV_QUERY_DEVICE_NAME,
                std::ptr::null(),
                0,
                buffer.as_mut_ptr() as *mut c_void,
                (buffer.len() * 2) as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        let name_bytes = usize::from(buffer[0]);
        if ok != 0 {
            let units =
                (name_bytes.min((returned as usize).saturating_sub(2)) / 2).min(buffer.len() - 1);
            return Some(String::from_utf16_lossy(&buffer[1..1 + units]));
        }
        let error = unsafe { ffi::GetLastError() };
        if error != ERROR_MORE_DATA || name_bytes.div_ceil(2) < buffer.len() {
            return None;
        }
        buffer = vec![0u16; 1 + name_bytes.div_ceil(2)];
    }
    None
}

fn file_system_is_scalefs(letter: char) -> bool {
    let root = wide(&format!("{letter}:\\"));
    let mut fs_name = [0u16; 32];
    let ok = unsafe {
        ffi::GetVolumeInformationW(
            root.as_ptr(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            fs_name.as_mut_ptr(),
            fs_name.len() as u32,
        )
    };
    ok != 0 && from_wide(&fs_name) == FILE_SYSTEM_NAME
}

fn companion() -> (Endpoint, ServerIdentity) {
    let endpoint = crate::register::recorded_endpoint()
        .map(|text| Endpoint::new(&text))
        .unwrap_or_else(Endpoint::default_endpoint)
        .shell_companion();
    let account = outcome::companion_account(crate::register::recorded_account());
    (endpoint, ServerIdentity::Account(account))
}

fn volume(params: Value) -> Result<Value, String> {
    let (endpoint, server) = companion();
    let mut client = Client::connect_limited(&endpoint, Duration::from_secs(2), &server)?;
    client
        .call("shell.volume", params)
        .map_err(|error| format!("shell.volume failed: {error}"))
}

fn by_letter(letter: char) -> Result<Value, String> {
    volume(object(vec![("letter", Value::Str(format!("{letter}:")))]))
}

fn by_pool(pool_id: &str) -> Option<Record> {
    volume(object(vec![("pool_id", Value::Str(pool_id.to_string()))]))
        .and_then(|reply| outcome::for_pool(reply, pool_id))
        .ok()
        .map(|reply| Record::from_reply(&reply))
}

fn device_name(devinst: u32) -> Option<String> {
    let mut buffer = vec![0u16; 256];
    for _ in 0..2 {
        let mut kind = 0u32;
        let mut size = (buffer.len() * 2) as u32;
        let cr = unsafe {
            ffi::CM_Get_DevNode_PropertyW(
                devinst,
                &DEVPKEY_NAME,
                &mut kind,
                buffer.as_mut_ptr() as *mut u8,
                &mut size,
                0,
            )
        };
        match cr {
            outcome::CR_SUCCESS if kind == DEVPROP_TYPE_STRING => {
                let name = from_wide(&buffer);
                return (!name.trim().is_empty()).then_some(name);
            }
            CR_BUFFER_SMALL if (size as usize) > buffer.len() * 2 && size <= 0x1_0000 => {
                buffer = vec![0u16; (size as usize).div_ceil(2)];
            }
            _ => return None,
        }
    }
    None
}

struct Attempt {
    outcome: Outcome,
    device: Option<String>,
}

pub fn run(letter: char, display: &str) {
    match attempt(letter) {
        Ok(Attempt {
            outcome: Outcome::Ejected,
            device,
        }) => notice::safe_to_remove(device.as_deref()),
        Ok(Attempt { outcome, .. }) => present(&Ok(outcome), display),
        Err(why) => present(&Err(why), display),
    }
}

fn attempt(letter: char) -> Result<Attempt, String> {
    let pool_id = volume_device_name(letter)
        .and_then(|name| outcome::pool_id_from_device_name(&name))
        .ok_or_else(|| format!("{letter}: is not a ScaleFS volume"))?;
    let reply = by_letter(letter)?;
    let plan = outcome::plan(&pool_id, reply).inspect_err(|why| {
        ffi::debug_line(&format!(
            "scalefs-shell: eject {letter}: not attempted: {why}"
        ));
    })?;
    let before = Some(plan.before);
    let instance = plan.instance;
    let devinst = match locate(&instance) {
        Ok(devinst) => devinst,
        Err(located) => {
            ffi::debug_line(&format!(
                "scalefs-shell: eject {letter}: pool {pool_id} has no device {instance} \
                 (CR 0x{located:x})"
            ));
            return Ok(Attempt {
                outcome: Outcome::Failed { cr: located },
                device: None,
            });
        }
    };
    let device = device_name(devinst);
    let mut veto_type = 0i32;
    let mut veto_name = [0u16; 512];
    let cr = unsafe {
        ffi::CM_Request_Device_EjectW(
            devinst,
            &mut veto_type,
            veto_name.as_mut_ptr(),
            veto_name.len() as u32,
            0,
        )
    };
    let mut after = None;
    let mut holders = Vec::new();
    if cr == outcome::CR_SUCCESS {
        let deadline = Instant::now() + RECORD_WAIT;
        loop {
            after = by_pool(&pool_id);
            if after.is_some_and(|record| record.is_new_removal(before))
                || Instant::now() >= deadline
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(150));
        }
    } else if cr == outcome::CR_REMOVE_VETOED {
        holders = outcome::holders(
            by_letter(letter)
                .and_then(|reply| outcome::for_pool(reply, &pool_id))
                .ok()
                .as_ref(),
        );
    }
    let outcome = outcome::classify(cr, before, after, holders);
    ffi::debug_line(&format!(
        "scalefs-shell: eject {letter}: pool {pool_id} {instance} -> CR 0x{cr:x} veto type \
         {veto_type} [{}]; record before {before:?} after {after:?} -> {outcome:?}",
        from_wide(&veto_name),
    ));
    Ok(Attempt { outcome, device })
}

fn present(outcome: &Result<Outcome, String>, display: &str) {
    let title = text::indirect(text::PROBLEM_TITLE)
        .map(|template| text::fill(&template, display))
        .unwrap_or_else(|| display.to_string());
    let failed = || {
        text::indirect(text::EJECT_FAILED)
            .map(|template| text::fill(&template, display))
            .unwrap_or_else(|| format!("{display}: the eject failed."))
    };
    let body = match outcome {
        Ok(Outcome::Ejected) => return,
        Ok(Outcome::Unconfirmed) => {
            format!("{display} was removed, but its safe removal could not be confirmed.")
        }
        Ok(Outcome::Vetoed { holders }) => {
            let mut body = text::indirect(text::IN_USE)
                .unwrap_or_else(|| "This device is currently in use.".to_string());
            if let Some(sentence) = crate::outcome::holders_sentence(holders) {
                body.push_str("\n\n");
                body.push_str(&sentence);
            }
            body
        }
        Ok(Outcome::NotRemoved) | Ok(Outcome::Failed { .. }) => failed(),
        Err(why) => {
            ffi::debug_line(&format!(
                "scalefs-shell: eject of {display} not attempted: {why}"
            ));
            failed()
        }
    };
    const MB_ICONWARNING: u32 = 0x30;
    const MB_SETFOREGROUND: u32 = 0x1_0000;
    let body = wide(&body);
    let title = wide(&title);
    unsafe {
        ffi::MessageBoxW(
            0,
            body.as_ptr(),
            title.as_ptr(),
            MB_ICONWARNING | MB_SETFOREGROUND,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn system_drive() -> char {
        std::env::var("SystemDrive")
            .ok()
            .and_then(|drive| drive.chars().next())
            .unwrap_or('C')
    }

    #[test]
    fn a_volume_names_its_device_over_a_zero_access_handle() {
        let letter = system_drive();
        let name = volume_device_name(letter).expect("the system volume answers");
        assert!(name.starts_with("\\Device\\"), "{name}");
        assert_eq!(query_device_name(letter, 2).as_deref(), Some(name.as_str()));
        assert_eq!(outcome::pool_id_from_device_name(&name), None);
    }

    #[test]
    fn another_file_system_never_shows_the_command() {
        assert!(is_local_disk(system_drive()));
        assert!(!file_system_is_scalefs(system_drive()));
        assert!(!is_ejectable_scalefs_volume(system_drive()));
        assert!(volume_device_name('!').is_none());
    }
}
