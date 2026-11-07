use super::*;
use core::ffi::c_void;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

#[link(name = "advapi32", kind = "raw-dylib")]
unsafe extern "system" {
    fn RegEnumKeyExW(
        key: isize,
        index: u32,
        name: *mut u16,
        name_len: *mut u32,
        reserved: *mut u32,
        class: *mut u16,
        class_len: *mut u32,
        last_write: *mut c_void,
    ) -> i32;
    fn RegEnumValueW(
        key: isize,
        index: u32,
        name: *mut u16,
        name_len: *mut u32,
        reserved: *mut u32,
        kind: *mut u32,
        data: *mut u8,
        data_len: *mut u32,
    ) -> i32;
}

const ERROR_NO_MORE_ITEMS: i32 = 259;
const REG_DWORD: u32 = 4;

struct Scratch(Hive);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let hive = Hive {
            root: ffi::HKEY_CURRENT_USER,
            base: format!(
                "Software\\ScaleFS-RegistrationTest-{}-{tag}-{n}",
                std::process::id()
            ),
        };
        hive.remove_tree("").unwrap();
        hive.create("").unwrap();
        Scratch(hive)
    }
}

fn under(dump: &Dump, prefix: &str) -> Dump {
    dump.iter()
        .filter(|(path, _)| path.starts_with(prefix))
        .map(|(path, values)| (path.clone(), values.clone()))
        .collect()
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = self.0.remove_tree("");
    }
}

struct Faulty<'a> {
    inner: &'a Hive,
    fail_at: usize,
    changes: Cell<usize>,
}

impl Faulty<'_> {
    fn change(&self) -> Result<(), String> {
        let n = self.changes.get() + 1;
        self.changes.set(n);
        if n == self.fail_at {
            Err(format!("injected failure at change {n}"))
        } else {
            Ok(())
        }
    }
}

impl Store for Faulty<'_> {
    fn exists(&self, path: &str) -> Result<bool, String> {
        self.inner.exists(path)
    }
    fn is_empty(&self, path: &str) -> Result<bool, String> {
        self.inner.is_empty(path)
    }
    fn get(&self, path: &str, name: Option<&str>) -> Result<Option<Stored>, String> {
        self.inner.get(path, name)
    }
    fn put(&self, path: &str, name: Option<&str>, value: &Stored) -> Result<(), String> {
        self.change()?;
        self.inner.put(path, name, value)
    }
    fn remove_value(&self, path: &str, name: Option<&str>) -> Result<(), String> {
        self.change()?;
        self.inner.remove_value(path, name)
    }
    fn remove_tree(&self, path: &str) -> Result<(), String> {
        self.change()?;
        self.inner.remove_tree(path)
    }
    fn copy_tree(&self, from: &str, to: &str) -> Result<(), String> {
        self.change()?;
        self.inner.copy_tree(from, to)
    }
}

type Dump = BTreeMap<String, BTreeMap<String, Stored>>;

fn dump(hive: &Hive) -> Dump {
    let mut out = Dump::new();
    walk(hive, "", &mut out);
    out
}

fn walk(hive: &Hive, path: &str, out: &mut Dump) {
    let Some(key) = hive.open(path, KEY_READ).unwrap() else {
        return;
    };
    let mut values = BTreeMap::new();
    for index in 0.. {
        let mut name = vec![0u16; 16_384];
        let mut name_len = name.len() as u32;
        let mut data = vec![0u8; 64 * 1024];
        let mut data_len = data.len() as u32;
        let mut kind = 0u32;
        let code = unsafe {
            RegEnumValueW(
                key.0,
                index,
                name.as_mut_ptr(),
                &mut name_len,
                std::ptr::null_mut(),
                &mut kind,
                data.as_mut_ptr(),
                &mut data_len,
            )
        };
        if code == ERROR_NO_MORE_ITEMS {
            break;
        }
        assert_eq!(code, ERROR_SUCCESS, "enumerating values of {path}");
        data.truncate(data_len as usize);
        values.insert(
            String::from_utf16_lossy(&name[..name_len as usize]),
            Stored { kind, data },
        );
    }
    let mut subkeys = Vec::new();
    for index in 0.. {
        let mut name = vec![0u16; 256];
        let mut name_len = name.len() as u32;
        let code = unsafe {
            RegEnumKeyExW(
                key.0,
                index,
                name.as_mut_ptr(),
                &mut name_len,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if code == ERROR_NO_MORE_ITEMS {
            break;
        }
        assert_eq!(code, ERROR_SUCCESS, "enumerating keys of {path}");
        subkeys.push(String::from_utf16_lossy(&name[..name_len as usize]));
    }
    out.insert(path.to_string(), values);
    for subkey in subkeys {
        let child = if path.is_empty() {
            subkey
        } else {
            format!("{path}\\{subkey}")
        };
        walk(hive, &child, out);
    }
}

fn registration<'a>(dll: &'a Path, replace: bool) -> Registration<'a> {
    Registration {
        dll,
        endpoint: Some("scalefs-dev"),
        account: "S-1-5-18",
        replace,
    }
}

fn dword(value: u32) -> Stored {
    Stored {
        kind: REG_DWORD,
        data: value.to_le_bytes().to_vec(),
    }
}

fn foreign_verb(hive: &Hive) {
    let handler = "{11111111-2222-3333-4444-555555555555}";
    hive.put(VERB_KEY, Some(HANDLER_VALUE), &text(handler))
        .unwrap();
    hive.put(VERB_KEY, Some("MUIVerb"), &text("Their Eject"))
        .unwrap();
    hive.put(VERB_KEY, Some("Position"), &dword(7)).unwrap();
    hive.put(
        &format!("{VERB_KEY}\\command"),
        None,
        &text("C:\\Tools\\their-eject.exe \"%1\""),
    )
    .unwrap();
}

fn half_written(hive: &Hive) {
    hive.put(CLASS_KEY, None, &text("ScaleFS Eject")).unwrap();
    hive.put(CLASS_KEY, Some(ENDPOINT_VALUE), &text("old-endpoint"))
        .unwrap();
    hive.put(CLASS_KEY, Some("Kept"), &dword(42)).unwrap();
    hive.put(SERVER_KEY, None, &text("C:\\Old\\scalefs_shell.dll"))
        .unwrap();
    hive.put(SERVER_KEY, Some("ThreadingModel"), &text("Both"))
        .unwrap();
    hive.put(VERB_KEY, Some(HANDLER_VALUE), &text(CLSID_TEXT))
        .unwrap();
    hive.put(VERB_KEY, Some(STATE_SYNC_VALUE), &text(""))
        .unwrap();
}

fn change_count(fixture: fn(&Hive), replace: bool) -> usize {
    let scratch = Scratch::new("count");
    fixture(&scratch.0);
    let counting = Faulty {
        inner: &scratch.0,
        fail_at: 0,
        changes: Cell::new(0),
    };
    let dll = Path::new("C:\\Program Files\\ScaleFS\\scalefs_shell.dll");
    register_in(&counting, &registration(dll, replace)).unwrap();
    counting.changes.get()
}

fn every_failure_restores(fixture: fn(&Hive), replace: bool) {
    let dll = Path::new("C:\\Program Files\\ScaleFS\\scalefs_shell.dll");
    let total = change_count(fixture, replace);
    assert!(total >= 8, "the registration makes {total} changes");
    for fail_at in 1..=total {
        let scratch = Scratch::new("fail");
        fixture(&scratch.0);
        let prior = dump(&scratch.0);
        let faulty = Faulty {
            inner: &scratch.0,
            fail_at,
            changes: Cell::new(0),
        };
        let refused = register_in(&faulty, &registration(dll, replace))
            .expect_err("an injected failure fails the registration");
        assert!(refused.contains("restored"), "{refused}");
        assert_eq!(
            dump(&scratch.0),
            prior,
            "a failure at change {fail_at} of {total} left the hive changed"
        );
    }
}

fn nothing(_: &Hive) {}

#[test]
fn the_identity_key_is_named_by_the_app_id() {
    assert_eq!(
        APP_ID_KEY,
        format!("SOFTWARE\\Classes\\AppUserModelId\\{APP_ID}")
    );
}

#[test]
fn a_registration_reads_back_and_unregisters_to_nothing() {
    let scratch = Scratch::new("fresh");
    let dll = Path::new("C:\\Program Files\\ScaleFS\\scalefs_shell.dll");
    register_in(&scratch.0, &registration(dll, false)).unwrap();
    let hive = &scratch.0;
    let read =
        |path: &str, name: Option<&str>| hive.get(path, name).unwrap().and_then(|v| v.text());
    assert_eq!(
        read(VERB_KEY, Some(HANDLER_VALUE)).as_deref(),
        Some(CLSID_TEXT)
    );
    assert_eq!(read(VERB_KEY, Some(STATE_SYNC_VALUE)).as_deref(), Some(""));
    assert_eq!(
        read(CLASS_KEY, Some(ACCOUNT_VALUE)).as_deref(),
        Some("S-1-5-18")
    );
    assert_eq!(
        read(CLASS_KEY, Some(ENDPOINT_VALUE)).as_deref(),
        Some("scalefs-dev")
    );
    assert_eq!(
        read(SERVER_KEY, None).as_deref(),
        Some("C:\\Program Files\\ScaleFS\\scalefs_shell.dll")
    );
    assert_eq!(
        read(SERVER_KEY, Some("ThreadingModel")).as_deref(),
        Some("Apartment")
    );
    assert_eq!(
        read(APP_ID_KEY, Some("DisplayName")).as_deref(),
        Some("ScaleFS")
    );
    let last = change_count(nothing, false);
    let clean = Scratch::new("last");
    let faulty = Faulty {
        inner: &clean.0,
        fail_at: last,
        changes: Cell::new(0),
    };
    assert!(register_in(&faulty, &registration(dll, false)).is_err());
    assert_eq!(clean.0.get(VERB_KEY, Some(HANDLER_VALUE)).unwrap(), None);
    unregister_in(hive).unwrap();
    for key in [CLASS_KEY, VERB_KEY, APP_ID_KEY] {
        assert!(!hive.exists(key).unwrap(), "{key} is gone");
    }
    assert!(
        dump(hive).values().all(BTreeMap::is_empty),
        "nothing of the registration is left"
    );
}

#[test]
fn a_failed_first_registration_leaves_nothing() {
    every_failure_restores(nothing, false);
}

#[test]
fn a_failure_restores_a_half_written_registration_exactly() {
    every_failure_restores(half_written, false);
    let scratch = Scratch::new("upgrade");
    half_written(&scratch.0);
    let dll = Path::new("C:\\Program Files\\ScaleFS\\scalefs_shell.dll");
    register_in(&scratch.0, &registration(dll, false)).unwrap();
    assert_eq!(
        scratch.0.get(VERB_KEY, Some(STATE_SYNC_VALUE)).unwrap(),
        Some(text(""))
    );
    assert_eq!(
        scratch.0.get(CLASS_KEY, Some("Kept")).unwrap(),
        Some(dword(42))
    );
}

#[test]
fn a_foreign_verb_is_refused_kept_and_restored() {
    let dll = Path::new("C:\\Program Files\\ScaleFS\\scalefs_shell.dll");
    let scratch = Scratch::new("foreign");
    foreign_verb(&scratch.0);
    let theirs = dump(&scratch.0);
    let refused = register_in(&scratch.0, &registration(dll, false)).unwrap_err();
    assert!(refused.contains("--replace"), "{refused}");
    assert_eq!(dump(&scratch.0), theirs, "a refusal changes nothing");

    register_in(&scratch.0, &registration(dll, true)).unwrap();
    assert_eq!(
        scratch
            .0
            .get(VERB_KEY, Some(HANDLER_VALUE))
            .unwrap()
            .and_then(|v| v.text())
            .as_deref(),
        Some(CLSID_TEXT)
    );
    assert_eq!(
        scratch
            .0
            .get(&format!("{VERB_KEY}\\command"), None)
            .unwrap(),
        None,
        "the command's verb is the command's alone"
    );
    register_in(&scratch.0, &registration(dll, false)).unwrap();
    unregister_in(&scratch.0).unwrap();
    assert_eq!(
        under(&dump(&scratch.0), VERB_KEY),
        under(&theirs, VERB_KEY),
        "the other program's verb is back exactly"
    );
    assert!(!scratch.0.exists(CLASS_KEY).unwrap());

    every_failure_restores(foreign_verb, true);
}

#[test]
fn unregistering_leaves_another_programs_verb_alone() {
    let scratch = Scratch::new("leave");
    foreign_verb(&scratch.0);
    scratch
        .0
        .put(CLASS_KEY, None, &text("ScaleFS Eject"))
        .unwrap();
    let mut theirs = dump(&scratch.0);
    unregister_in(&scratch.0).unwrap();
    theirs.retain(|path, _| !path.starts_with("SOFTWARE\\Classes\\CLSID"));
    let mut after = dump(&scratch.0);
    after.retain(|path, _| !path.starts_with("SOFTWARE\\Classes\\CLSID"));
    assert_eq!(after, theirs);
    assert!(!scratch.0.exists(CLASS_KEY).unwrap());
}
