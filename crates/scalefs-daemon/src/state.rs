use scalefs_ipc::json::{Value, object, parse};
use scalefs_mount::dataplane::CloseDurability;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedPool {
    pub name: String,
    pub pool_id: String,
    pub members: Vec<String>,
    pub mounts: Vec<RecordedMount>,
    pub eject: Option<EjectState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EjectState {
    pub phase: EjectPhase,
    pub generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EjectPhase {
    Prepared,
    Ejected,
}

impl EjectPhase {
    pub fn word(self) -> &'static str {
        match self {
            EjectPhase::Prepared => "prepared",
            EjectPhase::Ejected => "ejected",
        }
    }

    fn from_word(word: Option<&str>) -> EjectPhase {
        match word {
            Some("ejected") => EjectPhase::Ejected,
            _ => EjectPhase::Prepared,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedMount {
    pub mountpoint: String,
    pub read_only: bool,
    pub kernel_device: Option<String>,
    pub close_durability: Option<CloseDurability>,
}

fn recorded_close_durability(row: &Value) -> Option<CloseDurability> {
    if row.get("close_durability").is_none() && row.get("close_bound_ms").is_none() {
        return None;
    }
    Some(crate::serving::close_durability_param(row).unwrap_or(CloseDurability::CommitOnClose))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedShare {
    pub pool: String,
    pub name: String,
    pub port: u16,
    pub user: String,
    pub nt_hash: String,
    pub read_only: bool,
}

pub struct StateStore {
    file: PathBuf,
    persist_lock: std::sync::Mutex<()>,
}

#[derive(Default)]
struct Records {
    restorable: Vec<RecordedPool>,
    suppressed: Vec<RecordedPool>,
}

impl StateStore {
    pub fn persist_guard(&self) -> std::sync::MutexGuard<'_, ()> {
        self.persist_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn open(dir: &Path) -> Result<StateStore, String> {
        std::fs::create_dir_all(dir)
            .map_err(|error| format!("cannot create state directory {}: {error}", dir.display()))?;
        tighten_dir(dir);
        require_posix_rename(dir)?;
        Ok(StateStore {
            file: dir.join("pools.json"),
            persist_lock: std::sync::Mutex::new(()),
        })
    }

    pub fn load(&self) -> Vec<RecordedPool> {
        match self.read_records() {
            Ok(records) => records.restorable,
            Err(error) => {
                eprintln!(
                    "scalefsd: cannot read {}: {error}; starting with no recorded pools",
                    self.file.display(),
                );
                Vec::new()
            }
        }
    }

    pub fn load_suppressed(&self) -> std::io::Result<Vec<RecordedPool>> {
        self.read_records().map(|records| records.suppressed)
    }

    fn read_records(&self) -> std::io::Result<Records> {
        let text = match std::fs::read_to_string(&self.file) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Records::default());
            }
            Err(error) => return Err(error),
        };
        let value = match parse(&text) {
            Ok(value) => value,
            Err(error) => {
                eprintln!(
                    "scalefsd: cannot parse {}: {error:?}; reading it as an empty record",
                    self.file.display(),
                );
                return Ok(Records::default());
            }
        };
        let suppressed_entries = value
            .get("suppressed")
            .and_then(Value::as_array)
            .unwrap_or_default();
        let pool_entries = value
            .get("pools")
            .and_then(Value::as_array)
            .unwrap_or_default();
        let suppressed_ids: Vec<&str> = suppressed_entries
            .iter()
            .chain(pool_entries.iter().filter(|row| row.get("eject").is_some()))
            .filter_map(|entry| entry.get("pool_id").and_then(Value::as_str))
            .collect();
        let mut records = Records::default();
        for entry in suppressed_entries {
            if let Some(tombstone) = parse_record(entry, true) {
                push_tombstone(&mut records.suppressed, tombstone);
            }
        }
        for entry in pool_entries {
            match parse_record(entry, false) {
                Some(row) if row.eject.is_some() => push_tombstone(&mut records.suppressed, row),
                Some(row)
                    if !suppressed_ids
                        .iter()
                        .any(|id| id.eq_ignore_ascii_case(&row.pool_id)) =>
                {
                    records.restorable.push(row);
                }
                Some(_) | None => {}
            }
        }
        Ok(records)
    }

    pub fn save(&self, pools: &[RecordedPool], suppressed: &[RecordedPool]) -> std::io::Result<()> {
        let mut rows = Vec::new();
        let mut tombstones = Vec::new();
        for pool in pools {
            if pool.eject.is_some() {
                tombstones.push(record_value(pool, true));
            } else {
                rows.push(record_value(pool, false));
            }
        }
        tombstones.extend(suppressed.iter().map(|pool| record_value(pool, true)));
        let mut file = vec![("pools", Value::Array(rows))];
        if !tombstones.is_empty() {
            file.push(("suppressed", Value::Array(tombstones)));
        }
        write_private(&self.file, object(file).encode().as_bytes())
    }

    #[cfg(test)]
    pub(crate) fn path(&self) -> &Path {
        &self.file
    }
}

fn parse_record(entry: &Value, tombstone: bool) -> Option<RecordedPool> {
    let members = match entry.get("members").and_then(Value::as_array) {
        Some(paths) => paths
            .iter()
            .filter_map(|path| path.as_str().map(str::to_string))
            .collect(),
        None if tombstone => Vec::new(),
        None => return None,
    };
    let eject = match entry.get("eject") {
        Some(row) => Some(EjectState {
            phase: EjectPhase::from_word(row.get("phase").and_then(Value::as_str)),
            generation: row.get("generation").and_then(Value::as_u64).unwrap_or(0),
        }),
        None if tombstone => Some(EjectState {
            phase: EjectPhase::Prepared,
            generation: 0,
        }),
        None => None,
    };
    Some(RecordedPool {
        name: entry.get("name")?.as_str()?.to_string(),
        pool_id: entry.get("pool_id")?.as_str()?.to_string(),
        members,
        mounts: entry
            .get("mounts")
            .and_then(Value::as_array)
            .map(|rows| {
                rows.iter()
                    .filter_map(|row| {
                        Some(RecordedMount {
                            mountpoint: row.get("mountpoint")?.as_str()?.to_string(),
                            read_only: row
                                .get("read_only")
                                .and_then(Value::as_bool)
                                .unwrap_or(false),
                            kernel_device: row
                                .get("kernel_device")
                                .and_then(Value::as_str)
                                .map(str::to_string),
                            close_durability: recorded_close_durability(row),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default(),
        eject,
    })
}

fn push_tombstone(tombstones: &mut Vec<RecordedPool>, tombstone: RecordedPool) {
    if !tombstones
        .iter()
        .any(|listed| listed.pool_id.eq_ignore_ascii_case(&tombstone.pool_id))
    {
        tombstones.push(tombstone);
    }
}

fn record_value(pool: &RecordedPool, tombstone: bool) -> Value {
    let mut row = vec![
        ("name", Value::Str(pool.name.clone())),
        ("pool_id", Value::Str(pool.pool_id.clone())),
        (
            "members",
            Value::Array(pool.members.iter().cloned().map(Value::Str).collect()),
        ),
        (
            "mounts",
            Value::Array(
                pool.mounts
                    .iter()
                    .map(|mount| {
                        let mut row = vec![
                            ("mountpoint", Value::Str(mount.mountpoint.clone())),
                            ("read_only", Value::Bool(mount.read_only)),
                        ];
                        if let Some(device) = &mount.kernel_device {
                            row.push(("kernel_device", Value::Str(device.clone())));
                        }
                        if let Some(policy) = mount.close_durability {
                            row.extend(crate::serving::close_durability_fields(policy));
                        }
                        object(row)
                    })
                    .collect(),
            ),
        ),
    ];
    if tombstone {
        let eject = pool.eject.unwrap_or(EjectState {
            phase: EjectPhase::Prepared,
            generation: 0,
        });
        row.push((
            "eject",
            object(vec![
                ("phase", Value::Str(eject.phase.word().to_string())),
                ("generation", Value::Int(i128::from(eject.generation))),
            ]),
        ));
    }
    object(row)
}

pub struct SharesStore {
    file: PathBuf,
    persist_lock: std::sync::Mutex<()>,
}

impl SharesStore {
    pub fn open(dir: &Path) -> Result<SharesStore, String> {
        std::fs::create_dir_all(dir)
            .map_err(|error| format!("cannot create state directory {}: {error}", dir.display()))?;
        tighten_dir(dir);
        require_posix_rename(dir)?;
        Ok(SharesStore {
            file: dir.join("shares.json"),
            persist_lock: std::sync::Mutex::new(()),
        })
    }

    pub fn persist_guard(&self) -> std::sync::MutexGuard<'_, ()> {
        self.persist_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn load(&self) -> Vec<RecordedShare> {
        let text = match std::fs::read_to_string(&self.file) {
            Ok(text) => text,
            Err(_) => return Vec::new(),
        };
        let Ok(value) = parse(&text) else {
            eprintln!(
                "scalefsd: cannot parse {}; starting with no recorded shares",
                self.file.display(),
            );
            return Vec::new();
        };
        let Some(shares) = value.get("shares").and_then(Value::as_array) else {
            return Vec::new();
        };
        shares
            .iter()
            .filter_map(|row| {
                Some(RecordedShare {
                    pool: row.get("pool")?.as_str()?.to_string(),
                    name: row.get("name")?.as_str()?.to_string(),
                    port: u16::try_from(row.get("port")?.as_u64()?).ok()?,
                    user: row.get("user")?.as_str()?.to_string(),
                    nt_hash: row.get("nt_hash")?.as_str()?.to_string(),
                    read_only: row
                        .get("read_only")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                })
            })
            .collect()
    }

    pub fn save(&self, shares: &[RecordedShare]) -> std::io::Result<()> {
        let rows: Vec<Value> = shares
            .iter()
            .map(|share| {
                object(vec![
                    ("pool", Value::Str(share.pool.clone())),
                    ("name", Value::Str(share.name.clone())),
                    ("port", Value::Int(i128::from(share.port))),
                    ("user", Value::Str(share.user.clone())),
                    ("nt_hash", Value::Str(share.nt_hash.clone())),
                    ("read_only", Value::Bool(share.read_only)),
                ])
            })
            .collect();
        let text = object(vec![("shares", Value::Array(rows))]).encode();
        write_private(&self.file, text.as_bytes())
    }
}

fn tighten_dir(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(windows)]
    if let Err(error) = windows_acl::protect(dir) {
        eprintln!(
            "scalefsd: cannot restrict the state directory {}: {error}",
            dir.display()
        );
    }
    #[cfg(not(any(unix, windows)))]
    let _ = dir;
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows_acl {
    use core::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::{null, null_mut};

    mod ffi {
        use core::ffi::c_void;
        #[link(name = "advapi32", kind = "raw-dylib")]
        unsafe extern "system" {
            pub fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
                string_security_descriptor: *const u16,
                revision: u32,
                security_descriptor: *mut *mut c_void,
                size: *mut u32,
            ) -> i32;
            pub fn GetSecurityDescriptorDacl(
                security_descriptor: *mut c_void,
                dacl_present: *mut i32,
                dacl: *mut *mut c_void,
                dacl_defaulted: *mut i32,
            ) -> i32;
            pub fn SetNamedSecurityInfoW(
                object_name: *const u16,
                object_type: u32,
                security_info: u32,
                owner: *const c_void,
                group: *const c_void,
                dacl: *const c_void,
                sacl: *const c_void,
            ) -> u32;
        }
        #[link(name = "kernel32", kind = "raw-dylib")]
        unsafe extern "system" {
            pub fn LocalFree(mem: *mut c_void) -> *mut c_void;
        }
    }

    const SDDL_REVISION_1: u32 = 1;
    const SE_FILE_OBJECT: u32 = 1;
    const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
    const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
    const DACL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)";

    pub fn protect(dir: &Path) -> Result<(), String> {
        let sddl: Vec<u16> = DACL.encode_utf16().chain(std::iter::once(0)).collect();
        let path: Vec<u16> = dir
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut descriptor: *mut c_void = null_mut();
        let converted = unsafe {
            ffi::ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if converted == 0 || descriptor.is_null() {
            return Err(format!(
                "the DACL text did not convert: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut present = 0i32;
        let mut defaulted = 0i32;
        let mut dacl: *mut c_void = null_mut();
        let got = unsafe {
            ffi::GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)
        };
        let result = if got == 0 || present == 0 || dacl.is_null() {
            Err(format!(
                "the converted descriptor carries no DACL: {}",
                std::io::Error::last_os_error()
            ))
        } else {
            let status = unsafe {
                ffi::SetNamedSecurityInfoW(
                    path.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    null(),
                    null(),
                    dacl,
                    null(),
                )
            };
            if status == 0 {
                Ok(())
            } else {
                Err(format!("SetNamedSecurityInfoW failed with error {status}"))
            }
        };
        unsafe {
            ffi::LocalFree(descriptor);
        }
        result
    }
}

fn write_private(file: &Path, bytes: &[u8]) -> std::io::Result<()> {
    durable_replace(file, bytes, |_step, outcome| outcome)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    WriteTemp,
    FlushTemp,
    Replace,
    FlushEntry,
}

fn durable_replace(
    file: &Path,
    bytes: &[u8],
    mut check: impl FnMut(Step, std::io::Result<()>) -> std::io::Result<()>,
) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = file.with_extension("json.tmp");
    let mut temp = open_private_temp(&tmp)?;
    check(Step::WriteTemp, temp.write_all(bytes))?;
    check(Step::FlushTemp, temp.sync_all())?;
    check(Step::Replace, replace(&temp, &tmp, file))?;
    drop(temp);
    check(Step::FlushEntry, flush_entry(file))
}

fn open_private_temp(tmp: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.access_mode(windows_rename::GENERIC_WRITE | windows_rename::DELETE);
    }
    let temp = options.open(tmp)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temp.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(temp)
}

#[cfg(windows)]
fn replace(temp: &std::fs::File, _tmp: &Path, target: &Path) -> std::io::Result<()> {
    windows_rename::posix_replace(temp, target).map_err(|error| {
        if windows_rename::lacks_posix_rename(&error) {
            std::io::Error::new(
                error.kind(),
                format!(
                    "the state directory's file system has no POSIX rename (not NTFS or                      ReFS?): refusing to write the record rather than guess at its                      durability ({error})"
                ),
            )
        } else {
            error
        }
    })
}

#[cfg(windows)]
fn require_posix_rename(dir: &Path) -> Result<(), String> {
    let probe = dir.join(".scalefs-rename-probe.tmp");
    let target = dir.join(".scalefs-rename-probe");
    let outcome = (|| -> std::io::Result<()> {
        let file = open_private_temp(&probe)?;
        windows_rename::posix_replace(&file, &target)?;
        drop(file);
        std::fs::remove_file(&target)
    })();
    let _ = std::fs::remove_file(&probe);
    let _ = std::fs::remove_file(&target);
    match outcome {
        Err(error) if windows_rename::lacks_posix_rename(&error) => Err(format!(
            "state directory {} is on a file system without POSIX rename semantics (FAT,              exFAT, or a network share?): the daemon's records need NTFS or ReFS ({error})",
            dir.display()
        )),
        _ => Ok(()),
    }
}

#[cfg(not(windows))]
fn require_posix_rename(_dir: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(not(windows))]
fn replace(_temp: &std::fs::File, tmp: &Path, target: &Path) -> std::io::Result<()> {
    std::fs::rename(tmp, target)
}

#[cfg(windows)]
fn flush_entry(target: &Path) -> std::io::Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .open(target)?
        .sync_all()
}

#[cfg(not(windows))]
fn flush_entry(target: &Path) -> std::io::Result<()> {
    let parent = match target.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    std::fs::File::open(parent)?.sync_all()
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows_rename {
    use core::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;

    mod ffi {
        use core::ffi::c_void;
        #[link(name = "kernel32", kind = "raw-dylib")]
        unsafe extern "system" {
            pub fn SetFileInformationByHandle(
                file: std::os::windows::io::RawHandle,
                information_class: u32,
                information: *const c_void,
                size: u32,
            ) -> i32;
        }
    }

    pub const GENERIC_WRITE: u32 = 0x4000_0000;
    pub const DELETE: u32 = 0x0001_0000;
    const FILE_RENAME_INFO_EX: u32 = 22;
    const FILE_RENAME_FLAG_REPLACE_IF_EXISTS: u32 = 0x0000_0001;
    const FILE_RENAME_FLAG_POSIX_SEMANTICS: u32 = 0x0000_0002;
    const ERROR_NOT_SUPPORTED: i32 = 50;
    const ERROR_INVALID_PARAMETER: i32 = 87;

    #[repr(C)]
    #[allow(dead_code)]
    struct FileRenameInfo {
        flags: u32,
        root_directory: isize,
        file_name_length: u32,
        file_name: [u16; 1],
    }

    pub fn lacks_posix_rename(error: &std::io::Error) -> bool {
        matches!(
            error.raw_os_error(),
            Some(ERROR_INVALID_PARAMETER | ERROR_NOT_SUPPORTED)
        )
    }

    pub fn posix_replace(file: &std::fs::File, target: &Path) -> std::io::Result<()> {
        let target = std::path::absolute(target)?;
        let name: Vec<u16> = target
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let name_at = core::mem::offset_of!(FileRenameInfo, file_name);
        let size = core::mem::size_of::<FileRenameInfo>().max(name_at + 2 * name.len());
        let too_long = || std::io::Error::new(std::io::ErrorKind::InvalidInput, "path too long");
        let name_bytes = u32::try_from(2 * (name.len() - 1)).map_err(|_| too_long())?;
        let mut info = vec![0u8; size];
        let flags_at = core::mem::offset_of!(FileRenameInfo, flags);
        info[flags_at..flags_at + 4].copy_from_slice(
            &(FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS).to_ne_bytes(),
        );
        let length_at = core::mem::offset_of!(FileRenameInfo, file_name_length);
        info[length_at..length_at + 4].copy_from_slice(&name_bytes.to_ne_bytes());
        for (unit, slot) in name.iter().zip(info[name_at..].chunks_exact_mut(2)) {
            slot.copy_from_slice(&unit.to_ne_bytes());
        }
        let words: Vec<u64> = info
            .chunks(8)
            .map(|chunk| {
                let mut word = [0u8; 8];
                word[..chunk.len()].copy_from_slice(chunk);
                u64::from_ne_bytes(word)
            })
            .collect();
        let size = u32::try_from(size).map_err(|_| too_long())?;
        let renamed = unsafe {
            ffi::SetFileInformationByHandle(
                file.as_raw_handle(),
                FILE_RENAME_INFO_EX,
                words.as_ptr().cast::<c_void>(),
                size,
            )
        };
        if renamed == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

pub fn reassemble(registry: &crate::pools::Registry, store: &StateStore) {
    match store.load_suppressed() {
        Ok(tombstones) => {
            for tombstone in &tombstones {
                let (phase, generation) = tombstone.eject.map_or(("prepared", 0), |eject| {
                    (eject.phase.word(), eject.generation)
                });
                eprintln!(
                    "scalefsd: pool '{}' ({}) was ejected ({phase}, generation {generation}) and \
                     is NOT being reassembled — its members stay closed and no surface is \
                     restored. Reattach it explicitly (`scalefs pool attach {} ...`) once the \
                     disk is back; that clears the safe-removal state.",
                    tombstone.name, tombstone.pool_id, tombstone.name,
                );
            }
        }
        Err(error) => eprintln!(
            "scalefsd: cannot read the safe-removal records in {}: {error}",
            store.file.display(),
        ),
    }
    for recorded in store.load() {
        let outcome = reassemble_one(registry, &recorded);
        match outcome {
            Ok(members) => {
                println!(
                    "scalefsd: reassembled pool '{}' from {} member(s)",
                    recorded.name, members,
                );
                restore_mounts(registry, &recorded);
            }
            Err(why) => eprintln!(
                "scalefsd: could not reassemble pool '{}' ({}): {why}",
                recorded.name, recorded.pool_id,
            ),
        }
    }
}

#[cfg(target_os = "linux")]
fn restore_mounts(registry: &crate::pools::Registry, recorded: &RecordedPool) {
    for mount in &recorded.mounts {
        if mount.kernel_device.is_some() {
            eprintln!(
                "scalefsd: mount record for '{}' at {} is a Windows kernel serve; \
                 not restorable on this platform",
                recorded.name, mount.mountpoint,
            );
            continue;
        }
        let mode = if mount.read_only { " (read-only)" } else { "" };
        match registry.mount_at(
            &recorded.name,
            std::path::PathBuf::from(&mount.mountpoint),
            mount.read_only,
        ) {
            Ok(_) => println!(
                "scalefsd: restored the mount of '{}' at {}{mode}",
                recorded.name, mount.mountpoint,
            ),
            Err((_code, why)) => eprintln!(
                "scalefsd: could not restore the mount of '{}' at {}: {why}",
                recorded.name, mount.mountpoint,
            ),
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn restore_mounts(_registry: &crate::pools::Registry, recorded: &RecordedPool) {
    for mount in &recorded.mounts {
        if mount.kernel_device.is_some() {
            continue;
        }
        eprintln!(
            "scalefsd: cannot restore the mount of '{}' at {}: \
             kernel mounts are Linux-only in this build",
            recorded.name, mount.mountpoint,
        );
    }
}

fn reassemble_one(
    registry: &crate::pools::Registry,
    recorded: &RecordedPool,
) -> Result<usize, String> {
    if recorded.eject.is_some() {
        return Err("the pool was ejected; reattach it explicitly".to_string());
    }
    let paths_hold_the_pool = !recorded.members.is_empty()
        && recorded.members.iter().all(|path| {
            matches!(
                &scalefs_core::probe_path(Path::new(path)).contents,
                scalefs_core::Contents::Pool(probe)
                    if crate::pools::hex(&probe.pool_id.0) == recorded.pool_id
            )
        });
    if paths_hold_the_pool
        && registry
            .attach_recorded(recorded.name.clone(), &recorded.members)
            .is_ok()
    {
        return Ok(recorded.members.len());
    }
    let devices = scalefs_core::list_devices();
    let plan = scalefs_core::plan_import(&devices, Some(&recorded.pool_id))
        .map_err(|error| error.to_string())?;
    let members = plan.members.len();
    registry
        .attach_recorded(recorded.name.clone(), &plan.members)
        .map_err(|(_code, message)| message)?;
    Ok(members)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "scalefsd-state-{}-{tag}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(windows)]
    #[test]
    fn windows_state_dir_inherits_nothing() {
        fn icacls(path: &Path) -> String {
            let listing = std::process::Command::new("icacls")
                .arg(path)
                .output()
                .expect("icacls runs");
            let text = String::from_utf8_lossy(&listing.stdout).into_owned();
            assert!(listing.status.success(), "{text}");
            text
        }
        let dir = scratch_dir("acl");
        let store = SharesStore::open(&dir).unwrap();
        store.save(&[]).unwrap();

        let directory = icacls(&dir);
        assert!(
            !directory.contains("(I)"),
            "the directory inherits:\n{directory}"
        );
        assert_eq!(directory.matches("(F)").count(), 3, "{directory}");

        let file = icacls(&dir.join("shares.json"));
        assert_eq!(file.matches("(F)").count(), 3, "{file}");
        assert_eq!(file.matches("(I)").count(), 3, "{file}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn row(name: &str, pool_id: &str) -> RecordedPool {
        RecordedPool {
            name: name.to_string(),
            pool_id: pool_id.to_string(),
            members: vec![format!("/dev/{name}")],
            mounts: Vec::new(),
            eject: None,
        }
    }

    fn tombstone(name: &str, pool_id: &str, phase: EjectPhase, generation: u64) -> RecordedPool {
        RecordedPool {
            eject: Some(EjectState { phase, generation }),
            ..row(name, pool_id)
        }
    }

    fn raw_lists(store: &StateStore) -> (Vec<String>, Vec<String>) {
        let text = std::fs::read_to_string(store.path()).expect("the record exists");
        let value = parse(&text).expect("the record parses");
        let names = |list: &str| -> Vec<String> {
            value
                .get(list)
                .and_then(Value::as_array)
                .unwrap_or_default()
                .iter()
                .map(|entry| {
                    entry
                        .get("name")
                        .and_then(Value::as_str)
                        .expect("every entry is named")
                        .to_string()
                })
                .collect()
        };
        (names("pools"), names("suppressed"))
    }

    #[test]
    fn records_round_trip() {
        let dir = scratch_dir("roundtrip");
        let store = StateStore::open(&dir).unwrap();
        assert_eq!(store.load(), Vec::new(), "a fresh store is empty");
        assert_eq!(store.load_suppressed().unwrap(), Vec::new());
        let pools = vec![RecordedPool {
            name: "tank".to_string(),
            pool_id: "aa55".to_string(),
            members: vec!["/dev/sdb".to_string(), "/dev/sdc".to_string()],
            mounts: vec![RecordedMount {
                mountpoint: "/mnt/tank".to_string(),
                read_only: false,
                kernel_device: None,
                close_durability: None,
            }],
            eject: None,
        }];
        let suppressed = vec![RecordedPool {
            name: "images".to_string(),
            pool_id: "0102".to_string(),
            members: vec!["E:\\pool\\a.img".to_string()],
            mounts: vec![RecordedMount {
                mountpoint: "D:".to_string(),
                read_only: false,
                kernel_device: Some(r"\\.\ScaleFsCtl".to_string()),
                close_durability: Some(CloseDurability::CommitOnClose),
            }],
            eject: Some(EjectState {
                phase: EjectPhase::Ejected,
                generation: 7,
            }),
        }];
        store.save(&pools, &suppressed).unwrap();
        assert_eq!(store.load(), pools);
        assert_eq!(store.load_suppressed().unwrap(), suppressed);
        store.save(&pools, &[]).unwrap();
        assert_eq!(store.load(), pools);
        assert_eq!(store.load_suppressed().unwrap(), Vec::new());
        assert!(
            !std::fs::read_to_string(store.path())
                .unwrap()
                .contains("suppressed"),
            "no safe removal, no suppressed list",
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_serves_close_policy_round_trips_with_its_letter() {
        let dir = scratch_dir("close-policy");
        let store = StateStore::open(&dir).unwrap();
        let letter = |mountpoint: &str, close_durability| RecordedMount {
            mountpoint: mountpoint.to_string(),
            read_only: false,
            kernel_device: Some(r"\\.\ScaleFsCtl".to_string()),
            close_durability,
        };
        let pools = vec![RecordedPool {
            name: "tank".to_string(),
            pool_id: "aa55".to_string(),
            members: vec!["E:\\pool\\a.img".to_string()],
            mounts: vec![
                letter("P:", Some(CloseDurability::CommitOnClose)),
                letter(
                    "Q:",
                    Some(CloseDurability::Bounded(std::time::Duration::from_millis(
                        2500,
                    ))),
                ),
                letter("R:", None),
            ],
            eject: None,
        }];
        store.save(&pools, &[]).unwrap();
        assert_eq!(store.load(), pools);

        std::fs::write(
            store.path(),
            br#"{"pools":[{"name":"old","pool_id":"beef","members":["/dev/sdz"],"mounts":[
                {"mountpoint":"E:","read_only":false,"kernel_device":"\\\\.\\ScaleFsCtl"},
                {"mountpoint":"F:","read_only":false,"kernel_device":"\\\\.\\ScaleFsCtl",
                 "close_durability":"sometimes"},
                {"mountpoint":"G:","read_only":false,"kernel_device":"\\\\.\\ScaleFsCtl",
                 "close_durability":"bounded","close_bound_ms":60000}]}]}"#,
        )
        .unwrap();
        let loaded = store.load();
        let policies: Vec<_> = loaded[0]
            .mounts
            .iter()
            .map(|mount| mount.close_durability)
            .collect();
        assert_eq!(
            policies,
            vec![
                None,
                Some(CloseDurability::CommitOnClose),
                Some(CloseDurability::CommitOnClose),
            ],
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_tombstoned_pool_has_no_row_in_the_restore_list() {
        let dir = scratch_dir("tombstone-shape");
        let store = StateStore::open(&dir).unwrap();
        let live = row("live", "aa01");
        let gone = tombstone("gone", "bb02", EjectPhase::Ejected, 3);
        let frozen = tombstone("frozen", "cc03", EjectPhase::Prepared, 4);
        store
            .save(&[live.clone(), frozen.clone()], std::slice::from_ref(&gone))
            .unwrap();
        let (rows, tombstones) = raw_lists(&store);
        assert_eq!(
            rows,
            vec!["live".to_string()],
            "only the live pool is a row"
        );
        assert!(tombstones.contains(&"gone".to_string()), "{tombstones:?}");
        assert!(tombstones.contains(&"frozen".to_string()), "{tombstones:?}");
        assert_eq!(store.load(), vec![live.clone()]);
        let loaded = store.load_suppressed().unwrap();
        assert!(
            loaded.contains(&gone) && loaded.contains(&frozen),
            "{loaded:?}"
        );

        std::fs::write(
            store.path(),
            br#"{"pools":[{"name":"both","pool_id":"DD04","members":["/dev/x"]},
                          {"name":"live","pool_id":"aa01","members":["/dev/live"]}],
                 "suppressed":[{"name":"both","pool_id":"dd04","members":["/dev/x"],
                                "eject":{"phase":"ejected","generation":9}}]}"#,
        )
        .unwrap();
        assert_eq!(
            store.load(),
            vec![live],
            "a pool any tombstone names is never restorable",
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_legacy_in_row_eject_loads_as_a_tombstone() {
        let dir = scratch_dir("legacy-eject");
        let store = StateStore::open(&dir).unwrap();
        std::fs::write(
            store.path(),
            br#"{"pools":[
                {"name":"old","pool_id":"beef","members":["/dev/sdz"],
                 "mounts":[{"mountpoint":"E:","read_only":false,"kernel_device":"\\\\.\\ScaleFsCtl"}],
                 "eject":{"phase":"ejected","generation":4}},
                {"name":"live","pool_id":"f00d","members":["/dev/sdy"]}]}"#,
        )
        .unwrap();
        assert_eq!(store.load(), vec![row_with("live", "f00d", "/dev/sdy")]);
        let tombstones = store.load_suppressed().unwrap();
        assert_eq!(tombstones.len(), 1, "{tombstones:?}");
        assert_eq!(tombstones[0].name, "old");
        assert_eq!(
            tombstones[0].eject,
            Some(EjectState {
                phase: EjectPhase::Ejected,
                generation: 4,
            }),
        );
        assert_eq!(tombstones[0].mounts[0].mountpoint, "E:");

        store.save(&store.load(), &tombstones).unwrap();
        let (rows, suppressed) = raw_lists(&store);
        assert_eq!(rows, vec!["live".to_string()]);
        assert_eq!(suppressed, vec!["old".to_string()]);
        let text = std::fs::read_to_string(store.path()).unwrap();
        let value = parse(&text).unwrap();
        assert!(
            value
                .get("pools")
                .and_then(Value::as_array)
                .unwrap()
                .iter()
                .all(|entry| entry.get("eject").is_none()),
            "no restore-list row carries an eject state: {text}",
        );
        assert_eq!(store.load_suppressed().unwrap(), tombstones);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn row_with(name: &str, pool_id: &str, member: &str) -> RecordedPool {
        RecordedPool {
            members: vec![member.to_string()],
            ..row(name, pool_id)
        }
    }

    #[test]
    fn legacy_records_load_without_mounts() {
        let dir = scratch_dir("legacy");
        let store = StateStore::open(&dir).unwrap();
        std::fs::write(
            dir.join("pools.json"),
            br#"{"pools":[{"name":"old","pool_id":"beef","members":["/dev/sdz"]}]}"#,
        )
        .unwrap();
        let loaded = store.load();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "old");
        assert_eq!(loaded[0].mounts, Vec::new());
        assert_eq!(loaded[0].eject, None, "no eject field = no safe removal");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unknown_eject_phase_loads_closed() {
        let dir = scratch_dir("phase");
        let store = StateStore::open(&dir).unwrap();
        for (field, why, expected) in [
            (
                r#""eject":{"phase":"quantum","generation":9}"#,
                "an unknown phase",
                EjectPhase::Prepared,
            ),
            (
                r#""eject":{"generation":9}"#,
                "a missing phase",
                EjectPhase::Prepared,
            ),
            (
                r#""eject":{"phase":"ejected"}"#,
                "a missing generation",
                EjectPhase::Ejected,
            ),
            (
                r#""eject":{"phase":"prepared","generation":"twelve"}"#,
                "an unreadable generation",
                EjectPhase::Prepared,
            ),
            (
                r#""eject":"gone""#,
                "a non-object eject",
                EjectPhase::Prepared,
            ),
        ] {
            let entry =
                format!(r#"{{"name":"p","pool_id":"beef","members":["/dev/sdz"],{field}}}"#);
            for (shape, file) in [
                ("in-row", format!(r#"{{"pools":[{entry}]}}"#)),
                (
                    "suppressed",
                    format!(r#"{{"pools":[],"suppressed":[{entry}]}}"#),
                ),
            ] {
                std::fs::write(dir.join("pools.json"), file.as_bytes()).unwrap();
                assert_eq!(
                    store.load(),
                    Vec::new(),
                    "{why} ({shape}): never restorable"
                );
                let loaded = store.load_suppressed().unwrap();
                assert_eq!(
                    loaded.len(),
                    1,
                    "{why} ({shape}): the tombstone must survive"
                );
                let eject = loaded[0]
                    .eject
                    .unwrap_or_else(|| panic!("{why} ({shape}): the marker must NOT be dropped"));
                assert_eq!(eject.phase, expected, "{why} ({shape})");
            }
        }
        std::fs::write(
            dir.join("pools.json"),
            br#"{"pools":[],"suppressed":[{"name":"p","pool_id":"beef"}]}"#,
        )
        .unwrap();
        assert_eq!(store.load(), Vec::new());
        assert_eq!(
            store.load_suppressed().unwrap()[0].eject,
            Some(EjectState {
                phase: EjectPhase::Prepared,
                generation: 0,
            }),
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_ejected_record_is_never_reassembled() {
        let registry = crate::pools::Registry::default();
        for phase in [EjectPhase::Prepared, EjectPhase::Ejected] {
            let recorded = RecordedPool {
                name: "ejected".to_string(),
                pool_id: "beef".to_string(),
                members: vec!["/definitely/not/here".to_string()],
                mounts: Vec::new(),
                eject: Some(EjectState {
                    phase,
                    generation: 3,
                }),
            };
            let why = reassemble_one(&registry, &recorded)
                .expect_err("an ejected record must never reassemble");
            assert!(why.contains("ejected"), "{why}");
        }
    }

    #[test]
    fn the_share_restore_cannot_bring_an_ejected_pool_back() {
        let dir = scratch_dir("shares-vs-eject");
        let pools = StateStore::open(&dir).unwrap();
        pools
            .save(
                &[],
                &[RecordedPool {
                    name: "ejected".to_string(),
                    pool_id: "beef".to_string(),
                    members: vec!["/definitely/not/here".to_string()],
                    mounts: Vec::new(),
                    eject: Some(EjectState {
                        phase: EjectPhase::Prepared,
                        generation: 1,
                    }),
                }],
            )
            .unwrap();
        let shares_store = SharesStore::open(&dir).unwrap();
        shares_store
            .save(&[RecordedShare {
                pool: "ejected".to_string(),
                name: "media".to_string(),
                port: 0,
                user: "backup".to_string(),
                nt_hash: "0123456789abcdef0123456789abcdef".to_string(),
                read_only: false,
            }])
            .unwrap();

        let registry = crate::pools::Registry::default();
        reassemble(&registry, &pools);
        let shares = crate::shares::Shares::default();
        shares.restore(&shares_store, |name| registry.share_handle(name));

        let attached = registry.list().expect("list").get("pools").cloned();
        assert_eq!(
            attached,
            Some(Value::Array(Vec::new())),
            "an ejected pool must not be attached by ANY restore path",
        );
        let serving = shares.list().expect("share list").get("shares").cloned();
        assert_eq!(
            serving,
            Some(Value::Array(Vec::new())),
            "and its share must not come up over it",
        );
        shares.stop_all();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shares_round_trip() {
        let dir = scratch_dir("shares");
        let store = SharesStore::open(&dir).unwrap();
        assert_eq!(store.load(), Vec::new());
        let shares = vec![RecordedShare {
            pool: "tank".to_string(),
            name: "media".to_string(),
            port: 4450,
            user: "backup".to_string(),
            nt_hash: "0123456789abcdef0123456789abcdef".to_string(),
            read_only: true,
        }];
        store.save(&shares).unwrap();
        assert_eq!(store.load(), shares);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn garbage_loads_as_empty() {
        let dir = scratch_dir("garbage");
        let store = StateStore::open(&dir).unwrap();
        std::fs::write(dir.join("pools.json"), b"not json at all").unwrap();
        assert_eq!(store.load(), Vec::new());
        assert_eq!(store.load_suppressed().unwrap(), Vec::new());
        let pools = vec![RecordedPool {
            name: "t".to_string(),
            pool_id: "00".to_string(),
            members: vec![],
            mounts: vec![],
            eject: None,
        }];
        store.save(&pools, &[]).unwrap();
        assert_eq!(store.load(), pools);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn every_failed_persistence_step_is_an_error() {
        let dir = scratch_dir("faults");
        let file = dir.join("pools.json");
        for failing in [
            Step::WriteTemp,
            Step::FlushTemp,
            Step::Replace,
            Step::FlushEntry,
        ] {
            std::fs::write(&file, b"old").unwrap();
            let mut reached = Vec::new();
            let outcome = durable_replace(&file, b"new", |step, outcome| {
                reached.push(step);
                outcome.expect("the real step succeeds");
                if step == failing {
                    Err(std::io::Error::other(format!("injected {step:?} failure")))
                } else {
                    Ok(())
                }
            });
            let error = outcome.expect_err("a failed step must surface as Err");
            assert!(
                error.to_string().contains("injected"),
                "{failing:?}: {error}"
            );
            assert_eq!(
                reached.last(),
                Some(&failing),
                "{failing:?}: nothing runs after the failed step",
            );
            let on_disk = std::fs::read(&file).unwrap();
            match failing {
                Step::WriteTemp | Step::FlushTemp => {
                    assert_eq!(on_disk, b"old", "{failing:?}: the record is untouched");
                }
                Step::Replace | Step::FlushEntry => {
                    assert_eq!(on_disk, b"new", "{failing:?}: swapped, yet an error");
                }
            }
        }
        let mut reached = Vec::new();
        durable_replace(&file, b"newer", |step, outcome| {
            reached.push(step);
            outcome
        })
        .unwrap();
        assert_eq!(
            reached,
            [
                Step::WriteTemp,
                Step::FlushTemp,
                Step::Replace,
                Step::FlushEntry
            ]
        );
        assert_eq!(std::fs::read(&file).unwrap(), b"newer");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_save_that_cannot_write_is_an_error() {
        let dir = scratch_dir("unwritable");
        let store = StateStore::open(&dir).unwrap();
        store.save(&[row("kept", "aa01")], &[]).unwrap();
        std::fs::create_dir(dir.join("pools.json.tmp")).unwrap();
        store
            .save(&[row("lost", "bb02")], &[])
            .expect_err("an unwritable temp must fail the save");
        assert_eq!(store.load(), vec![row("kept", "aa01")]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn a_reader_holding_the_record_open_does_not_fail_a_save() {
        use std::io::Read;
        let dir = scratch_dir("open-reader");
        let store = StateStore::open(&dir).unwrap();
        store.save(&[row("before", "aa01")], &[]).unwrap();
        let mut reader = std::fs::File::open(store.path()).unwrap();
        store
            .save(&[row("after", "bb02")], &[])
            .expect("an open reader must not fail the save");
        assert_eq!(store.load(), vec![row("after", "bb02")]);
        let mut held = String::new();
        reader.read_to_string(&mut held).unwrap();
        assert!(held.contains("before"), "the reader keeps its file: {held}");
        drop(reader);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn the_posix_rename_is_available_and_replaces_under_a_reader() {
        let dir = scratch_dir("posix-rename");
        let target = dir.join("pools.json");
        std::fs::write(&target, b"old").unwrap();
        let reader = std::fs::File::open(&target).unwrap();
        let tmp = dir.join("pools.json.tmp");
        let temp = open_private_temp(&tmp).unwrap();
        {
            use std::io::Write;
            (&temp).write_all(b"new").unwrap();
        }
        windows_rename::posix_replace(&temp, &target)
            .expect("FileRenameInfoEx with POSIX semantics, not a fallback");
        drop(temp);
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
        assert!(!tmp.exists(), "the temp name is gone");
        drop(reader);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn the_record_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch_dir("mode");
        let store = StateStore::open(&dir).unwrap();
        let leftover = dir.join("pools.json.tmp");
        std::fs::write(&leftover, b"stale").unwrap();
        std::fs::set_permissions(&leftover, std::fs::Permissions::from_mode(0o644)).unwrap();
        store.save(&[row("p", "aa01")], &[]).unwrap();
        let mode = std::fs::metadata(store.path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "mode {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
