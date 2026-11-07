use crate::ffi::{self, HKEY_LOCAL_MACHINE, wide};
use std::path::Path;

pub const CLSID_TEXT: &str = "{858CF4EC-8CF3-4F38-BD79-5CA41D175237}";
pub const DLL_NAME: &str = "scalefs_shell.dll";
pub const APP_ID: &str = "ScaleFS";

const CLASS_KEY: &str = "SOFTWARE\\Classes\\CLSID\\{858CF4EC-8CF3-4F38-BD79-5CA41D175237}";
const SERVER_KEY: &str =
    "SOFTWARE\\Classes\\CLSID\\{858CF4EC-8CF3-4F38-BD79-5CA41D175237}\\InprocServer32";
const VERB_KEY: &str = "SOFTWARE\\Classes\\Drive\\shell\\eject";
const APP_ID_KEY: &str = "SOFTWARE\\Classes\\AppUserModelId\\ScaleFS";
const DISPLACED_KEY: &str =
    "SOFTWARE\\Classes\\CLSID\\{858CF4EC-8CF3-4F38-BD79-5CA41D175237}\\DisplacedVerb";
const APP_DISPLAY_NAME: &str = "ScaleFS";

const ENDPOINT_VALUE: &str = "Endpoint";
const ACCOUNT_VALUE: &str = "DaemonAccount";
const HANDLER_VALUE: &str = "ExplorerCommandHandler";
const STATE_SYNC_VALUE: &str = "CommandStateSync";

const KEY_READ: u32 = 0x0002_0019;
const KEY_WRITE: u32 = 0x0002_0006;
const KEY_ALL_ACCESS: u32 = 0x000F_003F;
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const ERROR_SUCCESS: i32 = 0;
const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_ACCESS_DENIED: i32 = 5;
const ERROR_MORE_DATA: i32 = 234;
const SHCNE_ASSOCCHANGED: i32 = 0x0800_0000;

#[derive(Debug, Clone, Copy)]
pub struct Registration<'a> {
    pub dll: &'a Path,
    pub endpoint: Option<&'a str>,
    pub account: &'a str,
    pub replace: bool,
}

pub fn register(registration: &Registration) -> Result<(), String> {
    let result = register_in(&Hive::machine(), registration);
    notify_associations_changed();
    result
}

pub fn unregister() -> Result<(), String> {
    let result = unregister_in(&Hive::machine());
    notify_associations_changed();
    result
}

pub fn recorded_endpoint() -> Option<String> {
    recorded_text(ENDPOINT_VALUE).filter(|text| !text.is_empty())
}

pub fn recorded_account() -> Option<String> {
    recorded_text(ACCOUNT_VALUE)
}

fn recorded_text(name: &str) -> Option<String> {
    Hive::machine()
        .get(CLASS_KEY, Some(name))
        .ok()
        .flatten()
        .and_then(|value| value.text())
}

fn notify_associations_changed() {
    unsafe { ffi::SHChangeNotify(SHCNE_ASSOCCHANGED, 0, std::ptr::null(), std::ptr::null()) };
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Stored {
    kind: u32,
    data: Vec<u8>,
}

impl Stored {
    fn text(&self) -> Option<String> {
        if !matches!(self.kind, REG_SZ | REG_EXPAND_SZ) {
            return None;
        }
        let units: Vec<u16> = self
            .data
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        Some(ffi::from_wide(&units))
    }
}

fn text(value: &str) -> Stored {
    Stored {
        kind: REG_SZ,
        data: wide(value)
            .into_iter()
            .flat_map(|unit| unit.to_le_bytes())
            .collect(),
    }
}

trait Store {
    fn exists(&self, path: &str) -> Result<bool, String>;
    fn is_empty(&self, path: &str) -> Result<bool, String>;
    fn get(&self, path: &str, name: Option<&str>) -> Result<Option<Stored>, String>;
    fn put(&self, path: &str, name: Option<&str>, value: &Stored) -> Result<(), String>;
    fn remove_value(&self, path: &str, name: Option<&str>) -> Result<(), String>;
    fn remove_tree(&self, path: &str) -> Result<(), String>;
    fn copy_tree(&self, from: &str, to: &str) -> Result<(), String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Verb {
    Absent,
    Empty,
    Ours,
    Foreign(String),
}

fn verb(store: &dyn Store) -> Result<Verb, String> {
    if !store.exists(VERB_KEY)? {
        return Ok(Verb::Absent);
    }
    let handler = store
        .get(VERB_KEY, Some(HANDLER_VALUE))?
        .and_then(|value| value.text());
    if handler
        .as_deref()
        .is_some_and(|handler| handler.eq_ignore_ascii_case(CLSID_TEXT))
    {
        return Ok(Verb::Ours);
    }
    if store.is_empty(VERB_KEY)? {
        return Ok(Verb::Empty);
    }
    Ok(Verb::Foreign(match handler {
        Some(handler) => format!("command handler {handler}"),
        None => "another program's verb".to_string(),
    }))
}

enum Change {
    Put(&'static str, Option<&'static str>, Stored),
    Displace,
}

fn changes(registration: &Registration, displace: bool) -> Vec<Change> {
    let mut changes = vec![
        Change::Put(CLASS_KEY, None, text("ScaleFS Eject")),
        Change::Put(
            CLASS_KEY,
            Some(ENDPOINT_VALUE),
            text(registration.endpoint.unwrap_or("")),
        ),
        Change::Put(CLASS_KEY, Some(ACCOUNT_VALUE), text(registration.account)),
        Change::Put(
            SERVER_KEY,
            None,
            text(&registration.dll.display().to_string()),
        ),
        Change::Put(SERVER_KEY, Some("ThreadingModel"), text("Apartment")),
        Change::Put(APP_ID_KEY, Some("DisplayName"), text(APP_DISPLAY_NAME)),
    ];
    if displace {
        changes.push(Change::Displace);
    }
    changes.push(Change::Put(VERB_KEY, Some(STATE_SYNC_VALUE), text("")));
    changes.push(Change::Put(VERB_KEY, Some(HANDLER_VALUE), text(CLSID_TEXT)));
    changes
}

struct Before {
    created: Vec<String>,
    values: Vec<Option<Stored>>,
}

fn created_by(store: &dyn Store, path: &str) -> Result<Option<String>, String> {
    if store.exists(path)? {
        return Ok(None);
    }
    let mut created = path;
    while let Some((parent, _)) = created.rsplit_once('\\') {
        if store.exists(parent)? {
            break;
        }
        created = parent;
    }
    Ok(Some(created.to_string()))
}

fn before(store: &dyn Store, changes: &[Change]) -> Result<Before, String> {
    let mut created: Vec<String> = Vec::new();
    for key in [CLASS_KEY, SERVER_KEY, DISPLACED_KEY, APP_ID_KEY, VERB_KEY] {
        if let Some(root) = created_by(store, key)?
            && !created.contains(&root)
        {
            created.push(root);
        }
    }
    let mut values = Vec::new();
    for change in changes {
        values.push(match change {
            Change::Put(path, name, _) => store.get(path, *name)?,
            Change::Displace => None,
        });
    }
    Ok(Before { created, values })
}

fn apply(store: &dyn Store, change: &Change) -> Result<(), String> {
    match change {
        Change::Put(path, name, value) => store.put(path, *name, value),
        Change::Displace => {
            store.copy_tree(VERB_KEY, DISPLACED_KEY)?;
            if let Err(why) = store.remove_tree(VERB_KEY) {
                let _ = store.copy_tree(DISPLACED_KEY, VERB_KEY);
                return Err(why);
            }
            Ok(())
        }
    }
}

fn roll_back(
    store: &dyn Store,
    changes: &[Change],
    before: &Before,
    applied: usize,
) -> Result<(), String> {
    let mut first_failure = None;
    let mut attempt = |result: Result<(), String>| {
        if let Err(why) = result {
            first_failure.get_or_insert(why);
        }
    };
    for (change, prior) in changes[..applied].iter().zip(&before.values).rev() {
        match change {
            Change::Put(path, name, _) => attempt(match prior {
                Some(value) => store.put(path, *name, value),
                None => store.remove_value(path, *name),
            }),
            Change::Displace => {
                attempt(store.remove_tree(VERB_KEY));
                attempt(store.copy_tree(DISPLACED_KEY, VERB_KEY));
            }
        }
    }
    for key in &before.created {
        attempt(store.remove_tree(key));
    }
    first_failure.map_or(Ok(()), Err)
}

fn verify(store: &dyn Store, changes: &[Change]) -> Result<(), String> {
    for change in changes {
        match change {
            Change::Put(path, name, value) => {
                if store.get(path, *name)?.as_ref() != Some(value) {
                    return Err(format!(
                        "HKLM\\{path} {} does not read back as written",
                        name.unwrap_or("(default)")
                    ));
                }
            }
            Change::Displace => {}
        }
    }
    Ok(())
}

fn register_in(store: &dyn Store, registration: &Registration) -> Result<(), String> {
    let displace = match verb(store)? {
        Verb::Absent | Verb::Empty | Verb::Ours => false,
        Verb::Foreign(what) if !registration.replace => {
            return Err(format!(
                "HKLM\\{VERB_KEY} already holds another program's Eject ({what}); nothing was \
                 changed — register with --replace to take its place (unregistering puts it back)"
            ));
        }
        Verb::Foreign(_) => {
            if store.exists(DISPLACED_KEY)? {
                return Err(format!(
                    "HKLM\\{VERB_KEY} holds another program's Eject and a verb this command \
                     displaced earlier is still kept; nothing was changed — unregister first"
                ));
            }
            true
        }
    };
    let changes = changes(registration, displace);
    let before = before(store, &changes)?;
    for (applied, change) in changes.iter().enumerate() {
        if let Err(why) = apply(store, change) {
            return Err(match roll_back(store, &changes, &before, applied) {
                Ok(()) => format!("{why}; the previous registration state was restored"),
                Err(also) => format!(
                    "{why}; restoring the previous registration state also failed ({also}) — \
                     the registration may be incomplete"
                ),
            });
        }
    }
    verify(store, &changes)
}

fn unregister_in(store: &dyn Store) -> Result<(), String> {
    let verb = verb(store)?;
    if verb == Verb::Ours {
        store.remove_tree(VERB_KEY)?;
    }
    if matches!(verb, Verb::Ours | Verb::Absent | Verb::Empty) && store.exists(DISPLACED_KEY)? {
        store.copy_tree(DISPLACED_KEY, VERB_KEY)?;
    }
    store.remove_tree(CLASS_KEY)?;
    store.remove_tree(APP_ID_KEY)
}

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

struct Hive {
    root: isize,
    base: String,
}

impl Hive {
    fn machine() -> Hive {
        Hive {
            root: HKEY_LOCAL_MACHINE,
            base: String::new(),
        }
    }

    fn full(&self, path: &str) -> String {
        match (self.base.is_empty(), path.is_empty()) {
            (true, _) => path.to_string(),
            (false, true) => self.base.clone(),
            (false, false) => format!("{}\\{path}", self.base),
        }
    }

    fn open(&self, path: &str, access: u32) -> Result<Option<Key>, String> {
        let full = wide(&self.full(path));
        let mut key = 0isize;
        let code = unsafe { ffi::RegOpenKeyExW(self.root, full.as_ptr(), 0, access, &mut key) };
        match code {
            ERROR_SUCCESS => Ok(Some(Key(key))),
            ERROR_FILE_NOT_FOUND => Ok(None),
            other => Err(status(&format!("cannot open HKLM\\{path}"), other)),
        }
    }

    fn create(&self, path: &str) -> Result<Key, String> {
        self.create_with(path, KEY_READ | KEY_WRITE)
    }

    fn create_with(&self, path: &str, access: u32) -> Result<Key, String> {
        let full = wide(&self.full(path));
        let mut key = 0isize;
        let code = unsafe {
            ffi::RegCreateKeyExW(
                self.root,
                full.as_ptr(),
                0,
                std::ptr::null(),
                0,
                access,
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
}

fn value_name(name: Option<&str>) -> Option<Vec<u16>> {
    name.map(wide)
}

fn name_ptr(name: &Option<Vec<u16>>) -> *const u16 {
    name.as_ref().map_or(std::ptr::null(), |name| name.as_ptr())
}

impl Store for Hive {
    fn exists(&self, path: &str) -> Result<bool, String> {
        Ok(self.open(path, KEY_READ)?.is_some())
    }

    fn is_empty(&self, path: &str) -> Result<bool, String> {
        let Some(key) = self.open(path, KEY_READ)? else {
            return Ok(true);
        };
        let (mut subkeys, mut values) = (0u32, 0u32);
        let code = unsafe {
            ffi::RegQueryInfoKeyW(
                key.0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut subkeys,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut values,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if code != ERROR_SUCCESS {
            return Err(status(&format!("cannot read HKLM\\{path}"), code));
        }
        Ok(subkeys == 0 && values == 0)
    }

    fn get(&self, path: &str, name: Option<&str>) -> Result<Option<Stored>, String> {
        let Some(key) = self.open(path, KEY_READ)? else {
            return Ok(None);
        };
        let name = value_name(name);
        let mut data = vec![0u8; 512];
        loop {
            let mut kind = 0u32;
            let mut len = data.len() as u32;
            let code = unsafe {
                ffi::RegQueryValueExW(
                    key.0,
                    name_ptr(&name),
                    std::ptr::null_mut(),
                    &mut kind,
                    data.as_mut_ptr(),
                    &mut len,
                )
            };
            match code {
                ERROR_SUCCESS => {
                    data.truncate(len as usize);
                    return Ok(Some(Stored { kind, data }));
                }
                ERROR_FILE_NOT_FOUND => return Ok(None),
                ERROR_MORE_DATA if (len as usize) > data.len() && len <= 1 << 20 => {
                    data = vec![0u8; len as usize];
                }
                other => return Err(status(&format!("cannot read HKLM\\{path}"), other)),
            }
        }
    }

    fn put(&self, path: &str, name: Option<&str>, value: &Stored) -> Result<(), String> {
        let key = self.create(path)?;
        let name_w = value_name(name);
        let code = unsafe {
            ffi::RegSetValueExW(
                key.0,
                name_ptr(&name_w),
                0,
                value.kind,
                value.data.as_ptr(),
                value.data.len() as u32,
            )
        };
        if code != ERROR_SUCCESS {
            return Err(status(
                &format!("cannot write HKLM\\{path} {}", name.unwrap_or("(default)")),
                code,
            ));
        }
        Ok(())
    }

    fn remove_value(&self, path: &str, name: Option<&str>) -> Result<(), String> {
        let Some(key) = self.open(path, KEY_READ | KEY_WRITE)? else {
            return Ok(());
        };
        let name_w = value_name(name);
        let code = unsafe { ffi::RegDeleteValueW(key.0, name_ptr(&name_w)) };
        match code {
            ERROR_SUCCESS | ERROR_FILE_NOT_FOUND => Ok(()),
            other => Err(status(
                &format!("cannot remove HKLM\\{path} {}", name.unwrap_or("(default)")),
                other,
            )),
        }
    }

    fn remove_tree(&self, path: &str) -> Result<(), String> {
        let full = wide(&self.full(path));
        let code = unsafe { ffi::RegDeleteTreeW(self.root, full.as_ptr()) };
        match code {
            ERROR_SUCCESS | ERROR_FILE_NOT_FOUND => Ok(()),
            other => Err(status(&format!("cannot remove HKLM\\{path}"), other)),
        }
    }

    fn copy_tree(&self, from: &str, to: &str) -> Result<(), String> {
        let Some(source) = self.open(from, KEY_ALL_ACCESS)? else {
            return Err(format!("HKLM\\{from} is gone"));
        };
        let destination = self.create_with(to, KEY_ALL_ACCESS)?;
        let code = unsafe { ffi::RegCopyTreeW(source.0, std::ptr::null(), destination.0) };
        if code != ERROR_SUCCESS {
            return Err(status(&format!("cannot copy HKLM\\{from} to {to}"), code));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "register_tests.rs"]
mod tests;
