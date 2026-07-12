
use scalefs_core::RawBlockDevice;
use scalefs_core::salvage::{
    AssemblyReport, CandidateKind, DeviceRole, DirListing, ExtentVerdict, FileReport, PathOutcome,
    ReadFailure, Rung, Salvage, SalvageOptions, SlotHealth, SnapshotCandidate, StatOutcome, Survey,
};
use scalefs_ipc::json::{Value, object};
use std::ffi::{CStr, CString, c_char};
use std::sync::Mutex;

pub const SCALEFS_ABI_VERSION: u32 = 1;

#[unsafe(no_mangle)]
pub extern "C" fn scalefs_abi_version() -> u32 {
    SCALEFS_ABI_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn scalefs_format_version() -> u32 {
    scalefs_core::FORMAT_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn scalefs_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}


std::thread_local! {
    static LAST_ERROR: std::cell::RefCell<Option<CString>> =
        const { std::cell::RefCell::new(None) };
}

fn set_last_error(message: String) {
    let stored = CString::new(message)
        .unwrap_or_else(|_| CString::new("error message contained a NUL byte").expect("static"));
    LAST_ERROR.with(|slot| *slot.borrow_mut() = Some(stored));
}

#[unsafe(no_mangle)]
pub extern "C" fn scalefs_last_error() -> *mut c_char {
    LAST_ERROR.with(|slot| match &*slot.borrow() {
        Some(message) => message.clone().into_raw(),
        None => std::ptr::null_mut(),
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn scalefs_string_free(text: *mut c_char) {
    if text.is_null() {
        return;
    }
    #[allow(unsafe_code)]
    drop(unsafe { CString::from_raw(text) });
}

fn guarded<T>(fallback: T, body: impl FnOnce() -> T) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(value) => value,
        Err(_) => {
            set_last_error("internal panic (a bug in ScaleFS — please report it)".to_string());
            fallback
        }
    }
}


pub struct ScalefsSalvage {
    session: Mutex<Salvage<RawBlockDevice>>,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn scalefs_salvage_open(
    paths: *const *const c_char,
    count: usize,
    view_tx: u64,
) -> *mut ScalefsSalvage {
    if paths.is_null() || count == 0 {
        set_last_error("scalefs_salvage_open needs at least one path".to_string());
        return std::ptr::null_mut();
    }
    #[allow(unsafe_code)]
    let supplied: Vec<String> = unsafe {
        std::slice::from_raw_parts(paths, count)
            .iter()
            .map(|&path| {
                if path.is_null() {
                    String::new()
                } else {
                    CStr::from_ptr(path).to_string_lossy().into_owned()
                }
            })
            .collect()
    };
    guarded(std::ptr::null_mut(), move || {
        let mut devices = Vec::with_capacity(supplied.len());
        for path in &supplied {
            if path.is_empty() {
                set_last_error("a supplied path was null or empty".to_string());
                return std::ptr::null_mut();
            }
            match RawBlockDevice::open_probe(std::path::Path::new(path)) {
                Ok(device) => devices.push(device),
                Err(error) => {
                    set_last_error(format!("cannot probe '{path}': {error}"));
                    return std::ptr::null_mut();
                }
            }
        }
        let options = SalvageOptions {
            view_tx: (view_tx != 0).then_some(view_tx),
        };
        match Salvage::assemble_with(devices, &options) {
            Ok(session) => Box::into_raw(Box::new(ScalefsSalvage {
                session: Mutex::new(session),
            })),
            Err(error) => {
                set_last_error(format!("nothing to salvage: {error}"));
                std::ptr::null_mut()
            }
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn scalefs_salvage_close(session: *mut ScalefsSalvage) {
    if session.is_null() {
        return;
    }
    #[allow(unsafe_code)]
    drop(unsafe { Box::from_raw(session) });
}

fn with_session<T>(
    session: *mut ScalefsSalvage,
    fallback: T,
    body: impl FnOnce(&mut Salvage<RawBlockDevice>) -> T,
) -> T {
    if session.is_null() {
        set_last_error("null session handle".to_string());
        return fallback;
    }
    let outcome = guarded(None, move || {
        #[allow(unsafe_code)]
        let holder = unsafe { &*session };
        let mut guard = match holder.session.lock() {
            Ok(guard) => guard,
            Err(_) => {
                set_last_error("the session was poisoned by an earlier panic".to_string());
                return None;
            }
        };
        Some(body(&mut guard))
    });
    outcome.unwrap_or(fallback)
}

fn json_out(value: Value) -> *mut c_char {
    match CString::new(value.encode()) {
        Ok(text) => text.into_raw(),
        Err(_) => {
            set_last_error("the result contained a NUL byte".to_string());
            std::ptr::null_mut()
        }
    }
}


fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn rung_name(rung: Rung) -> &'static str {
    match rung {
        Rung::StrictEquivalent => "strict-equivalent",
        Rung::PartialRoster => "partial-roster",
        Rung::CommitRoot => "commit-root",
    }
}

fn slot_value(slot: &SlotHealth) -> Value {
    Value::Str(match slot {
        SlotHealth::Valid => "valid".to_string(),
        SlotHealth::Corrupt(reason) => format!("corrupt: {reason}"),
        SlotHealth::Unreadable(error) => format!("unreadable: {error}"),
    })
}

fn report_value(report: &AssemblyReport) -> Value {
    let mut entries = Vec::new();
    if let Some(pool_id) = &report.pool_id {
        entries.push(("pool_id", Value::Str(hex(&pool_id.0))));
    }
    if let Some(label) = &report.label {
        entries.push(("label", Value::Str(label.clone())));
    }
    entries.push((
        "features",
        object(vec![
            ("compat", Value::Int(i128::from(report.feature_compat))),
            (
                "ro_compat",
                Value::Int(i128::from(report.feature_ro_compat)),
            ),
            ("incompat", Value::Int(i128::from(report.feature_incompat))),
            ("unknown_incompat", Value::Bool(report.unknown_incompat)),
            ("unknown_ro_compat", Value::Bool(report.unknown_ro_compat)),
        ]),
    ));
    entries.push((
        "rung",
        match report.rung {
            Some(rung) => Value::Str(rung_name(rung).to_string()),
            None => Value::Null,
        },
    ));
    if let Some(view_tx) = report.view_tx {
        entries.push(("view_tx", Value::Int(i128::from(view_tx))));
    }
    let devices: Vec<Value> = report
        .devices
        .iter()
        .enumerate()
        .map(|(index, device)| {
            let mut row = vec![("index", Value::Int(index as i128))];
            if let Some(pool_id) = &device.pool_id {
                row.push(("pool_id", Value::Str(hex(&pool_id.0))));
            }
            if let Some(device_id) = &device.device_id {
                row.push(("device_id", Value::Str(hex(&device_id.0))));
            }
            row.push((
                "slots",
                Value::Array(device.slots.iter().map(slot_value).collect()),
            ));
            if let Some(newest_tx) = device.newest_tx {
                row.push(("newest_tx", Value::Int(i128::from(newest_tx))));
            }
            let role = match device.role {
                DeviceRole::Member(member) => {
                    row.push(("member", Value::Int(i128::from(member))));
                    "member"
                }
                DeviceRole::Orphan => "orphan",
                DeviceRole::Shadowed => "shadowed",
                DeviceRole::Foreign => "foreign",
                DeviceRole::Unidentified => "unidentified",
            };
            row.push(("role", Value::Str(role.to_string())));
            if !device.notes.is_empty() {
                row.push((
                    "notes",
                    Value::Array(device.notes.iter().cloned().map(Value::Str).collect()),
                ));
            }
            object(row)
        })
        .collect();
    entries.push(("devices", Value::Array(devices)));
    entries.push((
        "missing",
        Value::Array(
            report
                .missing
                .iter()
                .map(|member| {
                    object(vec![
                        ("member", Value::Int(i128::from(member.member_index))),
                        ("device_id", Value::Str(hex(&member.device_id.0))),
                        ("newest_tx", Value::Int(i128::from(member.newest_tx))),
                    ])
                })
                .collect(),
        ),
    ));
    entries.push((
        "candidates",
        Value::Array(
            report
                .candidates
                .iter()
                .map(|candidate| {
                    let mut row = vec![
                        ("tx", Value::Int(i128::from(candidate.tx))),
                        (
                            "kind",
                            Value::Str(
                                match candidate.kind {
                                    CandidateKind::Roster => "roster",
                                    CandidateKind::Commit => "commit",
                                }
                                .to_string(),
                            ),
                        ),
                        ("adopted", Value::Bool(candidate.adopted)),
                    ];
                    if let Some(note) = &candidate.note {
                        row.push(("note", Value::Str(note.clone())));
                    }
                    object(row)
                })
                .collect(),
        ),
    ));
    if !report.notes.is_empty() {
        entries.push((
            "notes",
            Value::Array(report.notes.iter().cloned().map(Value::Str).collect()),
        ));
    }
    object(entries)
}

fn verdict_entries(verdict: &ExtentVerdict) -> Vec<(&'static str, Value)> {
    match verdict {
        ExtentVerdict::Intact => vec![("verdict", Value::Str("intact".to_string()))],
        ExtentVerdict::HealedFromCopy { copy } => vec![
            ("verdict", Value::Str("healed-from-copy".to_string())),
            ("copy", Value::Int(*copy as i128)),
        ],
        ExtentVerdict::ReconstructedFromParity => vec![(
            "verdict",
            Value::Str("reconstructed-from-parity".to_string()),
        )],
        ExtentVerdict::Lost { reasons } => vec![
            ("verdict", Value::Str("lost".to_string())),
            ("reasons", failure_list(reasons)),
        ],
        ExtentVerdict::MapLost => vec![("verdict", Value::Str("map-lost".to_string()))],
    }
}

fn failure_list(reasons: &[ReadFailure]) -> Value {
    Value::Array(
        reasons
            .iter()
            .map(|reason| Value::Str(reason.to_string()))
            .collect(),
    )
}

fn file_report_value(report: &FileReport) -> Value {
    let mut rollup = verdict_entries(&report.rollup());
    rollup.truncate(1);
    object(vec![
        ("size", Value::Int(i128::from(report.size))),
        ("bytes_lost", Value::Int(i128::from(report.bytes_lost))),
        (
            "rollup",
            rollup.pop().map(|(_, value)| value).unwrap_or(Value::Null),
        ),
        (
            "ranges",
            Value::Array(
                report
                    .ranges
                    .iter()
                    .map(|range| {
                        let mut row = vec![
                            ("offset", Value::Int(i128::from(range.offset))),
                            ("len", Value::Int(i128::from(range.len))),
                        ];
                        row.extend(verdict_entries(&range.verdict));
                        object(row)
                    })
                    .collect(),
            ),
        ),
        ("map_damage", Value::Int(report.map_damage.len() as i128)),
    ])
}

fn survey_value(survey: &Survey) -> Value {
    object(vec![
        ("items", Value::Int(i128::from(survey.items))),
        ("files", Value::Int(i128::from(survey.files))),
        ("directories", Value::Int(i128::from(survey.directories))),
        ("damage", Value::Int(survey.damage.len() as i128)),
        (
            "disconnected",
            Value::Array(
                survey
                    .disconnected
                    .iter()
                    .map(|inode| Value::Int(i128::from(*inode)))
                    .collect(),
            ),
        ),
    ])
}

fn listing_value(path: &str, listing: &DirListing) -> Value {
    object(vec![
        ("path", Value::Str(path.to_string())),
        (
            "entries",
            Value::Array(
                listing
                    .entries
                    .iter()
                    .map(|entry| {
                        let kind = match entry.kind {
                            scalefs_core::EntryKind::File => "file",
                            scalefs_core::EntryKind::Directory => "directory",
                            scalefs_core::EntryKind::Symlink => "symlink",
                            _ => "special",
                        };
                        object(vec![
                            ("name", Value::Str(entry.name.clone())),
                            ("kind", Value::Str(kind.to_string())),
                            ("inode", Value::Int(i128::from(entry.inode))),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("complete", Value::Bool(listing.damage.is_empty())),
    ])
}

fn resolve(session: &Salvage<RawBlockDevice>, path: &str) -> Result<u64, String> {
    match session.resolve_path(path) {
        Ok(PathOutcome::Found(object)) => Ok(object),
        Ok(PathOutcome::Missing) => Err(format!("'{path}' does not exist in the salvaged view")),
        Ok(PathOutcome::Lost(damage)) => Err(format!(
            "'{path}' cannot be resolved: {} lost tree region(s) overlap the lookup",
            damage.len(),
        )),
        Err(error) => Err(format!("resolving '{path}': {error}")),
    }
}


#[unsafe(no_mangle)]
pub unsafe extern "C" fn scalefs_salvage_report_json(session: *mut ScalefsSalvage) -> *mut c_char {
    with_session(session, std::ptr::null_mut(), |salvage| {
        json_out(report_value(salvage.report()))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn scalefs_salvage_survey_json(session: *mut ScalefsSalvage) -> *mut c_char {
    with_session(session, std::ptr::null_mut(), |salvage| {
        match salvage.survey() {
            Ok(survey) => json_out(survey_value(&survey)),
            Err(error) => {
                set_last_error(format!("survey failed: {error}"));
                std::ptr::null_mut()
            }
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn scalefs_salvage_ls_json(
    session: *mut ScalefsSalvage,
    path: *const c_char,
) -> *mut c_char {
    let Some(path) = cstr_arg(path, "path") else {
        return std::ptr::null_mut();
    };
    with_session(session, std::ptr::null_mut(), move |salvage| {
        let object_id = match resolve(salvage, &path) {
            Ok(object_id) => object_id,
            Err(message) => {
                set_last_error(message);
                return std::ptr::null_mut();
            }
        };
        match salvage.read_dir(object_id) {
            Ok(listing) => json_out(listing_value(&path, &listing)),
            Err(error) => {
                set_last_error(format!("listing '{path}': {error}"));
                std::ptr::null_mut()
            }
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn scalefs_salvage_stat_json(
    session: *mut ScalefsSalvage,
    path: *const c_char,
) -> *mut c_char {
    let Some(path) = cstr_arg(path, "path") else {
        return std::ptr::null_mut();
    };
    with_session(session, std::ptr::null_mut(), move |salvage| {
        let object_id = match resolve(salvage, &path) {
            Ok(object_id) => object_id,
            Err(message) => {
                set_last_error(message);
                return std::ptr::null_mut();
            }
        };
        match salvage.stat(object_id) {
            Ok(StatOutcome::Found(attrs)) => json_out(object(vec![
                ("outcome", Value::Str("found".to_string())),
                ("inode", Value::Int(i128::from(object_id))),
                ("size", Value::Int(i128::from(attrs.size))),
                ("mode", Value::Int(i128::from(attrs.mode))),
                ("uid", Value::Int(i128::from(attrs.uid))),
                ("gid", Value::Int(i128::from(attrs.gid))),
            ])),
            Ok(StatOutcome::Missing) => {
                json_out(object(vec![("outcome", Value::Str("missing".to_string()))]))
            }
            Ok(StatOutcome::Lost(damage)) => json_out(object(vec![
                ("outcome", Value::Str("lost".to_string())),
                ("damage", Value::Int(damage.len() as i128)),
            ])),
            Err(error) => {
                set_last_error(format!("stat '{path}': {error}"));
                std::ptr::null_mut()
            }
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn scalefs_salvage_copy_file(
    session: *mut ScalefsSalvage,
    source_path: *const c_char,
    dest_path: *const c_char,
) -> *mut c_char {
    let (Some(source), Some(dest)) = (
        cstr_arg(source_path, "source_path"),
        cstr_arg(dest_path, "dest_path"),
    ) else {
        return std::ptr::null_mut();
    };
    with_session(session, std::ptr::null_mut(), move |salvage| {
        let object_id = match resolve(salvage, &source) {
            Ok(object_id) => object_id,
            Err(message) => {
                set_last_error(message);
                return std::ptr::null_mut();
            }
        };
        let mut sink = match std::fs::File::create(&dest) {
            Ok(file) => file,
            Err(error) => {
                set_last_error(format!("cannot create '{dest}': {error}"));
                return std::ptr::null_mut();
            }
        };
        match salvage.salvage_file(object_id, &mut sink) {
            Ok(report) => json_out(file_report_value(&report)),
            Err(error) => {
                set_last_error(format!("salvaging '{source}': {error}"));
                std::ptr::null_mut()
            }
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn scalefs_salvage_snapshots_json(
    session: *mut ScalefsSalvage,
) -> *mut c_char {
    with_session(session, std::ptr::null_mut(), |salvage| {
        match salvage.snapshots() {
            Ok((snapshots, damage)) => json_out(object(vec![
                (
                    "snapshots",
                    Value::Array(
                        snapshots
                            .iter()
                            .map(|snapshot| {
                                object(vec![
                                    ("tx", Value::Int(i128::from(snapshot.tx_id))),
                                    ("name", Value::Str(snapshot.name.clone())),
                                    (
                                        "created_at_ns",
                                        Value::Int(i128::from(snapshot.created_at_ns)),
                                    ),
                                ])
                            })
                            .collect(),
                    ),
                ),
                ("damage", Value::Int(damage.len() as i128)),
            ])),
            Err(error) => {
                set_last_error(format!("listing snapshots: {error}"));
                std::ptr::null_mut()
            }
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn scalefs_salvage_enter_snapshot(
    session: *mut ScalefsSalvage,
    tx: u64,
) -> i32 {
    with_session(session, -1, move |salvage| {
        let candidate: Option<SnapshotCandidate> = match salvage.snapshots() {
            Ok((snapshots, _)) => snapshots.into_iter().find(|snapshot| snapshot.tx_id == tx),
            Err(error) => {
                set_last_error(format!("listing snapshots: {error}"));
                return -1;
            }
        };
        let Some(candidate) = candidate else {
            set_last_error(format!("no recoverable snapshot has transaction id {tx}"));
            return -1;
        };
        match salvage.enter_snapshot(&candidate) {
            Ok(()) => 0,
            Err(error) => {
                set_last_error(format!("entering snapshot {tx}: {error}"));
                -1
            }
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn scalefs_salvage_enter_live(session: *mut ScalefsSalvage) -> i32 {
    with_session(session, -1, |salvage| {
        salvage.enter_live();
        0
    })
}

fn cstr_arg(text: *const c_char, what: &str) -> Option<String> {
    if text.is_null() {
        set_last_error(format!("{what} must not be null"));
        return None;
    }
    #[allow(unsafe_code)]
    Some(
        unsafe { CStr::from_ptr(text) }
            .to_string_lossy()
            .into_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use scalefs_core::{
        AllocPurpose, BlockDevice, CaseSensitivity, DeviceId, FileBlockDevice, Geometry,
        MemberSpec, Pool, PoolId, PoolParams,
    };
    use std::path::Path;

    fn now_ns() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos() as i64)
            .unwrap_or(0)
    }

    fn payload() -> Vec<u8> {
        (0..150_000u32).map(|i| (i * 17 % 249) as u8).collect()
    }

    fn damaged_pool(tag: &str) -> (std::path::PathBuf, Vec<String>) {
        let dir = std::env::temp_dir().join(format!(
            "scalefs-ffi-{}-{tag}-{}",
            std::process::id(),
            now_ns() & 0xFFFF_FFFF,
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let geometry = Geometry {
            logical_block_size: 4096,
            physical_block_size: 4096,
            zone_size: 64 * 1024,
            zone_count: 64,
            erase_granularity_zones: 1,
            sequential_write_required: false,
        };
        let images: Vec<String> = ["a.img", "b.img"]
            .iter()
            .map(|file| dir.join(file).to_string_lossy().into_owned())
            .collect();
        let members = images
            .iter()
            .zip([0xD1u8, 0xD2])
            .map(|(path, id)| MemberSpec {
                device: FileBlockDevice::create(Path::new(path), geometry.capacity_bytes())
                    .unwrap(),
                device_id: DeviceId([id; 16]),
                geometry,
            })
            .collect();
        let mut pool = Pool::create_multi(
            members,
            PoolParams {
                pool_id: PoolId([0x99; 16]),
                case_sensitivity: CaseSensitivity::InsensitivePreserving,
                dirent_hash_seed: 3,
                label: "ffi".to_string(),
                created_at_ns: now_ns(),
                mirror_width: 2,
                data_width: 1,
                parity_width: 0,
            },
        )
        .unwrap();
        let file = pool
            .create_file(scalefs_core::tree::ROOT_INODE, "hello.bin", 0o644, now_ns())
            .unwrap();
        pool.write(file, 0, &payload(), now_ns()).unwrap();
        pool.commit(AllocPurpose::Normal, now_ns()).unwrap();
        drop(pool);

        let device = FileBlockDevice::open(Path::new(&images[1])).unwrap();
        device.write_at(0, &vec![0u8; 4096]).unwrap();
        device.flush().unwrap();
        drop(device);
        (dir, images)
    }

    fn open_session(images: &[String], view_tx: u64) -> *mut ScalefsSalvage {
        let holders: Vec<CString> = images
            .iter()
            .map(|path| CString::new(path.as_str()).unwrap())
            .collect();
        let pointers: Vec<*const c_char> = holders.iter().map(|text| text.as_ptr()).collect();
        #[allow(unsafe_code)]
        unsafe {
            scalefs_salvage_open(pointers.as_ptr(), pointers.len(), view_tx)
        }
    }

    fn take_json(raw: *mut c_char) -> Value {
        assert!(!raw.is_null(), "expected JSON, got null: {}", last_error());
        #[allow(unsafe_code)]
        let text = unsafe { CStr::from_ptr(raw) }.to_str().unwrap().to_string();
        #[allow(unsafe_code)]
        unsafe {
            scalefs_string_free(raw)
        };
        scalefs_ipc::json::parse(&text).expect("the ABI must emit valid JSON")
    }

    fn last_error() -> String {
        let raw = scalefs_last_error();
        if raw.is_null() {
            return "(no error recorded)".to_string();
        }
        #[allow(unsafe_code)]
        let text = unsafe { CStr::from_ptr(raw) }.to_str().unwrap().to_string();
        #[allow(unsafe_code)]
        unsafe {
            scalefs_string_free(raw)
        };
        text
    }

    #[test]
    fn abi_version_is_stable() {
        assert_eq!(scalefs_abi_version(), 1);
    }

    #[test]
    fn format_version_matches_core() {
        assert_eq!(scalefs_format_version(), scalefs_core::FORMAT_VERSION);
    }

    #[test]
    fn version_is_a_static_string() {
        let raw = scalefs_version();
        assert!(!raw.is_null());
        #[allow(unsafe_code)]
        let text = unsafe { CStr::from_ptr(raw) }.to_str().unwrap();
        assert_eq!(text, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn the_c_surface_salvages_a_damaged_pool_without_writing() {
        let (dir, images) = damaged_pool("surface");
        let fingerprint = |paths: &[String]| -> Vec<Vec<u8>> {
            paths
                .iter()
                .map(|path| {
                    let bytes = std::fs::read(path).unwrap();
                    scalefs_core::crc32c(&bytes).to_le_bytes().to_vec()
                })
                .collect()
        };
        let before = fingerprint(&images);

        let session = open_session(&images, 0);
        assert!(!session.is_null(), "open failed: {}", last_error());

        let report = take_json(
            #[allow(unsafe_code)]
            unsafe {
                scalefs_salvage_report_json(session)
            },
        );
        assert_eq!(
            report.get("rung").and_then(Value::as_str),
            Some("strict-equivalent"),
            "mirrored slots survive a one-slot kill: {report:?}",
        );
        assert_eq!(report.get("label").and_then(Value::as_str), Some("ffi"));
        let devices = report.get("devices").and_then(Value::as_array).unwrap();
        assert_eq!(devices.len(), 2);
        let damaged_slots = devices[1].get("slots").and_then(Value::as_array).unwrap();
        assert!(
            damaged_slots[0]
                .as_str()
                .is_some_and(|slot| slot.starts_with("corrupt")),
            "the zeroed head slot must be reported: {damaged_slots:?}",
        );

        let survey = take_json(
            #[allow(unsafe_code)]
            unsafe {
                scalefs_salvage_survey_json(session)
            },
        );
        assert_eq!(survey.get("files").and_then(Value::as_u64), Some(1));
        assert_eq!(
            survey
                .get("disconnected")
                .and_then(Value::as_array)
                .map(|list| list.len()),
            Some(0),
        );

        let root = CString::new("/").unwrap();
        let listing = take_json(
            #[allow(unsafe_code)]
            unsafe {
                scalefs_salvage_ls_json(session, root.as_ptr())
            },
        );
        assert_eq!(listing.get("complete"), Some(&Value::Bool(true)));
        let entries = listing.get("entries").and_then(Value::as_array).unwrap();
        assert!(
            entries.iter().any(|entry| {
                entry.get("name").and_then(Value::as_str) == Some("hello.bin")
                    && entry.get("kind").and_then(Value::as_str) == Some("file")
            }),
            "{entries:?}",
        );

        let hello = CString::new("/hello.bin").unwrap();
        let stat = take_json(
            #[allow(unsafe_code)]
            unsafe {
                scalefs_salvage_stat_json(session, hello.as_ptr())
            },
        );
        assert_eq!(stat.get("outcome").and_then(Value::as_str), Some("found"));
        assert_eq!(
            stat.get("size").and_then(Value::as_u64),
            Some(payload().len() as u64),
        );

        let out = dir.join("recovered.bin");
        let dest = CString::new(out.to_string_lossy().as_bytes()).unwrap();
        let verdicts = take_json(
            #[allow(unsafe_code)]
            unsafe {
                scalefs_salvage_copy_file(session, hello.as_ptr(), dest.as_ptr())
            },
        );
        assert_eq!(
            verdicts.get("rollup").and_then(Value::as_str),
            Some("intact"),
            "{verdicts:?}",
        );
        assert_eq!(verdicts.get("bytes_lost").and_then(Value::as_u64), Some(0));
        assert_eq!(std::fs::read(&out).unwrap(), payload(), "byte-identical");

        let absent = CString::new("/nope.bin").unwrap();
        #[allow(unsafe_code)]
        let missing = unsafe { scalefs_salvage_stat_json(session, absent.as_ptr()) };
        assert!(missing.is_null());
        assert!(last_error().contains("nope.bin"));

        #[allow(unsafe_code)]
        unsafe {
            scalefs_salvage_close(session)
        };

        assert_eq!(before, fingerprint(&images), "salvage must never write");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn snapshots_round_trip_through_the_c_surface() {
        let (dir, images) = damaged_pool("snap");
        let devices = images
            .iter()
            .map(|path| FileBlockDevice::open(Path::new(path)).unwrap())
            .collect::<Vec<_>>();
        let mut pool = Pool::open_multi(devices).unwrap();
        pool.snapshot_create("keep", now_ns()).unwrap();
        let entry = pool
            .lookup(scalefs_core::tree::ROOT_INODE, "hello.bin")
            .unwrap();
        pool.write(entry.inode, 0, b"CHANGED!", now_ns()).unwrap();
        pool.commit(AllocPurpose::Normal, now_ns()).unwrap();
        drop(pool);

        let session = open_session(&images, 0);
        assert!(!session.is_null(), "open failed: {}", last_error());
        let snapshots = take_json(
            #[allow(unsafe_code)]
            unsafe {
                scalefs_salvage_snapshots_json(session)
            },
        );
        let list = snapshots
            .get("snapshots")
            .and_then(Value::as_array)
            .unwrap();
        assert_eq!(list.len(), 1, "{snapshots:?}");
        let tx = list[0].get("tx").and_then(Value::as_u64).unwrap();

        #[allow(unsafe_code)]
        let entered = unsafe { scalefs_salvage_enter_snapshot(session, tx) };
        assert_eq!(entered, 0, "{}", last_error());

        let hello = CString::new("/hello.bin").unwrap();
        let out = dir.join("snap.bin");
        let dest = CString::new(out.to_string_lossy().as_bytes()).unwrap();
        take_json(
            #[allow(unsafe_code)]
            unsafe {
                scalefs_salvage_copy_file(session, hello.as_ptr(), dest.as_ptr())
            },
        );
        assert_eq!(
            std::fs::read(&out).unwrap(),
            payload(),
            "the snapshot serves the pre-overwrite bytes",
        );

        #[allow(unsafe_code)]
        let live = unsafe { scalefs_salvage_enter_live(session) };
        assert_eq!(live, 0);
        let out_live = dir.join("live.bin");
        let dest_live = CString::new(out_live.to_string_lossy().as_bytes()).unwrap();
        take_json(
            #[allow(unsafe_code)]
            unsafe {
                scalefs_salvage_copy_file(session, hello.as_ptr(), dest_live.as_ptr())
            },
        );
        let live_bytes = std::fs::read(&out_live).unwrap();
        assert_eq!(&live_bytes[..8], b"CHANGED!");

        #[allow(unsafe_code)]
        unsafe {
            scalefs_salvage_close(session)
        };
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn errors_are_reported_never_thrown() {
        #[allow(unsafe_code)]
        unsafe {
            assert!(scalefs_salvage_open(std::ptr::null(), 0, 0).is_null());
            assert!(last_error().contains("at least one path"));
            let bogus = CString::new("/definitely/not/here.img").unwrap();
            let paths = [bogus.as_ptr()];
            assert!(scalefs_salvage_open(paths.as_ptr(), 1, 0).is_null());
            assert!(last_error().contains("cannot probe"));
            assert!(scalefs_salvage_report_json(std::ptr::null_mut()).is_null());
            assert_eq!(scalefs_salvage_enter_live(std::ptr::null_mut()), -1);
            scalefs_salvage_close(std::ptr::null_mut());
            scalefs_string_free(std::ptr::null_mut());
        }
    }
}
