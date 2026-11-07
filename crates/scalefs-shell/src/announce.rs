use crate::ffi;
use core::ffi::c_void;

#[link(name = "user32", kind = "raw-dylib")]
unsafe extern "system" {
    fn BroadcastSystemMessageW(
        flags: u32,
        recipients: *mut u32,
        message: u32,
        wparam: usize,
        lparam: isize,
    ) -> i32;
}

#[repr(C)]
struct DevBroadcastVolume {
    size: u32,
    device_type: u32,
    reserved: u32,
    unit_mask: u32,
    flags: u16,
}

const WM_DEVICECHANGE: u32 = 0x0219;
const DBT_DEVICEARRIVAL: usize = 0x8000;
const DBT_DEVICEREMOVECOMPLETE: usize = 0x8004;
const DBT_DEVTYP_VOLUME: u32 = 2;
const BSF_FORCEIFHUNG: u32 = 0x20;
const BSF_NOHANG: u32 = 0x08;
const BSF_NOTIMEOUTIFNOTHUNG: u32 = 0x40;
const BSM_APPLICATIONS: u32 = 0x08;
const SHCNE_DRIVEREMOVED: i32 = 0x80;
const SHCNE_DRIVEADD: i32 = 0x100;
const SHCNF_PATHW: u32 = 0x0005;
const SHCNF_FLUSH: u32 = 0x1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Arrival,
    Removal,
}

impl Change {
    pub fn word(self) -> &'static str {
        match self {
            Change::Arrival => "arrival",
            Change::Removal => "removal",
        }
    }

    pub fn from_word(word: &str) -> Option<Change> {
        match word {
            "arrival" => Some(Change::Arrival),
            "removal" => Some(Change::Removal),
            _ => None,
        }
    }
}

pub fn announce_from_helper(letter: char, change: Change) {
    announce_here(letter, change);
    let user = std::env::var("USERNAME").unwrap_or_default();
    let profile = std::env::var("USERPROFILE").unwrap_or_default();
    ffi::debug_line(&format!(
        "scalefsd session-announce: {} {}: announced (user {user}, profile {profile})",
        change.word(),
        letter.to_ascii_uppercase()
    ));
}

pub fn announce_here(letter: char, change: Change) {
    let letter = letter.to_ascii_uppercase();
    if !letter.is_ascii_uppercase() {
        return;
    }
    let volume = DevBroadcastVolume {
        size: std::mem::size_of::<DevBroadcastVolume>() as u32,
        device_type: DBT_DEVTYP_VOLUME,
        reserved: 0,
        unit_mask: 1 << (letter as u32 - 'A' as u32),
        flags: 0,
    };
    let mut recipients = BSM_APPLICATIONS;
    let event = match change {
        Change::Arrival => DBT_DEVICEARRIVAL,
        Change::Removal => DBT_DEVICEREMOVECOMPLETE,
    };
    unsafe {
        BroadcastSystemMessageW(
            BSF_FORCEIFHUNG | BSF_NOHANG | BSF_NOTIMEOUTIFNOTHUNG,
            &mut recipients,
            WM_DEVICECHANGE,
            event,
            &volume as *const DevBroadcastVolume as isize,
        );
    }
    let root = ffi::wide(&format!("{letter}:\\"));
    let shell_event = match change {
        Change::Arrival => SHCNE_DRIVEADD,
        Change::Removal => SHCNE_DRIVEREMOVED,
    };
    unsafe {
        ffi::SHChangeNotify(
            shell_event,
            SHCNF_PATHW | SHCNF_FLUSH,
            root.as_ptr() as *const c_void,
            std::ptr::null(),
        );
    }
}
