
use scalefs_ipc::json::{Value, object, parse};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedPool {
    pub name: String,
    pub pool_id: String,
    pub members: Vec<String>,
    pub mounts: Vec<RecordedMount>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedMount {
    pub mountpoint: String,
    pub read_only: bool,
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
}

impl StateStore {
    pub fn open(dir: &Path) -> Result<StateStore, String> {
        std::fs::create_dir_all(dir)
            .map_err(|error| format!("cannot create state directory {}: {error}", dir.display()))?;
        tighten_dir(dir);
        Ok(StateStore {
            file: dir.join("pools.json"),
        })
    }

    pub fn load(&self) -> Vec<RecordedPool> {
        let text = match std::fs::read_to_string(&self.file) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
            Err(error) => {
                eprintln!(
                    "scalefsd: cannot read {}: {error}; starting with no recorded pools",
                    self.file.display(),
                );
                return Vec::new();
            }
        };
        let value = match parse(&text) {
            Ok(value) => value,
            Err(error) => {
                eprintln!(
                    "scalefsd: cannot parse {}: {error:?}; starting with no recorded pools",
                    self.file.display(),
                );
                return Vec::new();
            }
        };
        let Some(pools) = value.get("pools").and_then(Value::as_array) else {
            return Vec::new();
        };
        pools
            .iter()
            .filter_map(|entry| {
                Some(RecordedPool {
                    name: entry.get("name")?.as_str()?.to_string(),
                    pool_id: entry.get("pool_id")?.as_str()?.to_string(),
                    members: entry
                        .get("members")?
                        .as_array()?
                        .iter()
                        .filter_map(|path| path.as_str().map(str::to_string))
                        .collect(),
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
                                    })
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                })
            })
            .collect()
    }

    pub fn save(&self, pools: &[RecordedPool]) -> std::io::Result<()> {
        let rows: Vec<Value> = pools
            .iter()
            .map(|pool| {
                object(vec![
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
                                    object(vec![
                                        ("mountpoint", Value::Str(mount.mountpoint.clone())),
                                        ("read_only", Value::Bool(mount.read_only)),
                                    ])
                                })
                                .collect(),
                        ),
                    ),
                ])
            })
            .collect();
        let text = object(vec![("pools", Value::Array(rows))]).encode();
        write_private(&self.file, text.as_bytes())
    }
}

pub struct SharesStore {
    file: PathBuf,
}

impl SharesStore {
    pub fn open(dir: &Path) -> Result<SharesStore, String> {
        std::fs::create_dir_all(dir)
            .map_err(|error| format!("cannot create state directory {}: {error}", dir.display()))?;
        tighten_dir(dir);
        Ok(SharesStore {
            file: dir.join("shares.json"),
        })
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
    #[cfg(not(unix))]
    let _ = dir;
}

fn write_private(file: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = file.with_extension("json.tmp");
    std::fs::write(&tmp, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, file)
}

pub fn reassemble(registry: &crate::pools::Registry, store: &StateStore) {
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

    #[test]
    fn records_round_trip() {
        let dir = scratch_dir("roundtrip");
        let store = StateStore::open(&dir).unwrap();
        assert_eq!(store.load(), Vec::new(), "a fresh store is empty");
        let pools = vec![
            RecordedPool {
                name: "tank".to_string(),
                pool_id: "aa55".to_string(),
                members: vec!["/dev/sdb".to_string(), "/dev/sdc".to_string()],
                mounts: vec![RecordedMount {
                    mountpoint: "/mnt/tank".to_string(),
                    read_only: false,
                }],
            },
            RecordedPool {
                name: "images".to_string(),
                pool_id: "0102".to_string(),
                members: vec!["E:\\pool\\a.img".to_string()],
                mounts: Vec::new(),
            },
        ];
        store.save(&pools).unwrap();
        assert_eq!(store.load(), pools);
        store.save(&pools[..1]).unwrap();
        assert_eq!(store.load(), pools[..1]);
        let _ = std::fs::remove_dir_all(&dir);
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
        let pools = vec![RecordedPool {
            name: "t".to_string(),
            pool_id: "00".to_string(),
            members: vec![],
            mounts: vec![],
        }];
        store.save(&pools).unwrap();
        assert_eq!(store.load(), pools);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
