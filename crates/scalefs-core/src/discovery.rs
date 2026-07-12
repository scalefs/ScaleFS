
use crate::device::BlockDevice;
#[cfg(windows)]
use crate::error::ScaleFsError;
use crate::layout::{DeviceId, PoolId, superblock_slots};
use crate::raw::RawBlockDevice;
use crate::records::decode_superblock;
use std::path::Path;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub serial: Option<String>,
    pub model: Option<String>,
}

#[derive(Clone, Debug)]
pub struct PoolProbe {
    pub pool_id: PoolId,
    pub device_id: DeviceId,
    pub label: String,
    pub topology_generation: u64,
    pub tx: u64,
    pub unknown_incompat: bool,
}

#[derive(Clone, Debug)]
pub enum Contents {
    Pool(PoolProbe),
    Partitioned,
    Blank,
    Foreign,
    Unreadable,
}

#[derive(Clone, Debug)]
pub struct DiscoveredDevice {
    pub path: String,
    pub size: Option<u64>,
    pub identity: DeviceIdentity,
    pub actuators: usize,
    pub contents: Contents,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ImportPlan {
    pub pool_id: PoolId,
    pub label: String,
    pub members: Vec<String>,
    pub duplicates: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct PoolChoice {
    pub pool_id: PoolId,
    pub label: String,
    pub members_visible: usize,
}

#[derive(Clone, Debug)]
pub enum PlanError {
    NoPools,
    SeveralPools(Vec<PoolChoice>),
    NoMatch(String),
    AmbiguousSelector(String, Vec<PoolChoice>),
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let list = |f: &mut std::fmt::Formatter<'_>, choices: &[PoolChoice]| {
            for choice in choices {
                write!(
                    f,
                    "\n  {}  '{}'  {} member(s) visible",
                    hex_id(&choice.pool_id.0),
                    choice.label,
                    choice.members_visible,
                )?;
            }
            Ok(())
        };
        match self {
            PlanError::NoPools => {
                write!(f, "no ScaleFS pools found among the candidate devices")
            }
            PlanError::SeveralPools(choices) => {
                write!(
                    f,
                    "several pools were found; choose one with --pool <label|id-prefix>:"
                )?;
                list(f, choices)
            }
            PlanError::NoMatch(selector) => {
                write!(f, "no discovered pool matches '{selector}'")
            }
            PlanError::AmbiguousSelector(selector, choices) => {
                write!(f, "'{selector}' matches more than one pool:")?;
                list(f, choices)
            }
        }
    }
}

pub fn hex_id(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn same_spindle(a: &Path, b: &Path) -> bool {
    #[cfg(target_os = "linux")]
    {
        match (spindle_key(a), spindle_key(b)) {
            (Some(key_a), Some(key_b)) => key_a == key_b,
            _ => false,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (a, b);
        false
    }
}

#[cfg(target_os = "linux")]
fn spindle_key(path: &Path) -> Option<std::path::PathBuf> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.file_type().is_block_device() {
        return None;
    }
    let rdev = metadata.rdev();
    let major = ((rdev >> 32) & 0xFFFF_F000) | ((rdev >> 8) & 0xFFF);
    let minor = ((rdev >> 12) & 0xFFFF_FF00) | (rdev & 0xFF);
    let node = std::fs::canonicalize(format!("/sys/dev/block/{major}:{minor}")).ok()?;
    Some(if node.join("partition").exists() {
        node.parent()?.to_path_buf()
    } else {
        node
    })
}

pub fn probe_path(path: &Path) -> DiscoveredDevice {
    let text = path.to_string_lossy().into_owned();
    match RawBlockDevice::open_probe(path) {
        Ok(device) => probed(text, &device),
        Err(error) => DiscoveredDevice {
            path: text,
            size: None,
            identity: DeviceIdentity::default(),
            actuators: 0,
            contents: Contents::Unreadable,
            error: Some(error.to_string()),
        },
    }
}

fn probed(path: String, device: &RawBlockDevice) -> DiscoveredDevice {
    let (contents, error) = classify(device);
    DiscoveredDevice {
        path,
        size: Some(device.len()),
        identity: device.identity().clone(),
        actuators: device.actuator_ranges().len(),
        contents,
        error,
    }
}

fn classify<D: BlockDevice>(device: &D) -> (Contents, Option<String>) {
    let mut samples: Vec<Vec<u8>> = Vec::new();
    for (index, offset) in superblock_slots(device.len()).into_iter().enumerate() {
        let want = if index == 0 { 4104 } else { 4096 };
        let available = device.len().saturating_sub(offset).min(want);
        if available == 0 {
            continue;
        }
        let mut bytes = vec![0u8; available as usize];
        if let Err(error) = device.read_at(offset, &mut bytes) {
            return (Contents::Unreadable, Some(error.to_string()));
        }
        samples.push(bytes);
    }
    for bytes in &samples {
        if let Ok(superblock) = decode_superblock(bytes) {
            let tx = superblock
                .newest_commit
                .filter(|extent| extent.length <= 64 * 1024)
                .and_then(|extent| {
                    let mut bytes = vec![0u8; extent.length as usize];
                    device.read_at(extent.offset, &mut bytes).ok()?;
                    crate::records::decode_commit(&bytes).ok()
                })
                .map_or(0, |commit| commit.tx_id);
            return (
                Contents::Pool(PoolProbe {
                    pool_id: superblock.pool_id,
                    device_id: superblock.device_id,
                    label: superblock.label.clone(),
                    topology_generation: superblock.topology_generation,
                    tx,
                    unknown_incompat: superblock.unknown_incompat() != 0,
                }),
                None,
            );
        }
    }
    if let Some(head) = samples.first() {
        let mbr = head.len() >= 512 && head[510] == 0x55 && head[511] == 0xAA;
        let gpt_512 = head.len() >= 520 && &head[512..520] == b"EFI PART";
        let gpt_4096 = head.len() >= 4104 && &head[4096..4104] == b"EFI PART";
        if mbr || gpt_512 || gpt_4096 {
            return (Contents::Partitioned, None);
        }
        if samples
            .iter()
            .all(|bytes| bytes.iter().all(|&byte| byte == 0))
        {
            return (Contents::Blank, None);
        }
    }
    if samples.is_empty() {
        return (
            Contents::Unreadable,
            Some("the device is empty".to_string()),
        );
    }
    (Contents::Foreign, None)
}

pub fn plan_import(
    devices: &[DiscoveredDevice],
    selector: Option<&str>,
) -> Result<ImportPlan, PlanError> {
    struct Candidate {
        path: String,
        device_id: DeviceId,
        freshness: (u64, u64),
    }
    struct Group {
        pool_id: PoolId,
        label: String,
        members: Vec<Candidate>,
        duplicates: Vec<String>,
    }
    let mut groups: Vec<Group> = Vec::new();
    for device in devices {
        let Contents::Pool(probe) = &device.contents else {
            continue;
        };
        let candidate = Candidate {
            path: device.path.clone(),
            device_id: probe.device_id,
            freshness: (probe.topology_generation, probe.tx),
        };
        match groups
            .iter_mut()
            .find(|group| group.pool_id == probe.pool_id)
        {
            Some(group) => {
                match group
                    .members
                    .iter_mut()
                    .find(|held| held.device_id == probe.device_id)
                {
                    Some(held) if candidate.freshness > held.freshness => {
                        group
                            .duplicates
                            .push(std::mem::replace(held, candidate).path);
                    }
                    Some(_) => group.duplicates.push(candidate.path),
                    None => group.members.push(candidate),
                }
            }
            None => groups.push(Group {
                pool_id: probe.pool_id,
                label: probe.label.clone(),
                members: vec![candidate],
                duplicates: Vec::new(),
            }),
        }
    }
    let choices = |groups: &[&Group]| {
        groups
            .iter()
            .map(|group| PoolChoice {
                pool_id: group.pool_id,
                label: group.label.clone(),
                members_visible: group.members.len(),
            })
            .collect()
    };
    let chosen = match selector {
        None => match groups.len() {
            0 => return Err(PlanError::NoPools),
            1 => &groups[0],
            _ => {
                let all: Vec<&Group> = groups.iter().collect();
                return Err(PlanError::SeveralPools(choices(&all)));
            }
        },
        Some(selector) => {
            let matches: Vec<&Group> = groups
                .iter()
                .filter(|group| selector_matches(selector, &group.pool_id, &group.label))
                .collect();
            match matches.len() {
                0 => return Err(PlanError::NoMatch(selector.to_string())),
                1 => matches[0],
                _ => {
                    return Err(PlanError::AmbiguousSelector(
                        selector.to_string(),
                        choices(&matches),
                    ));
                }
            }
        }
    };
    Ok(ImportPlan {
        pool_id: chosen.pool_id,
        label: chosen.label.clone(),
        members: chosen
            .members
            .iter()
            .map(|candidate| candidate.path.clone())
            .collect(),
        duplicates: chosen.duplicates.clone(),
    })
}

pub fn discovered_pools(devices: &[DiscoveredDevice]) -> Vec<PoolChoice> {
    let mut pools: Vec<(PoolChoice, Vec<DeviceId>)> = Vec::new();
    for device in devices {
        let Contents::Pool(probe) = &device.contents else {
            continue;
        };
        match pools
            .iter_mut()
            .find(|(choice, _)| choice.pool_id == probe.pool_id)
        {
            Some((choice, seen)) => {
                if !seen.contains(&probe.device_id) {
                    seen.push(probe.device_id);
                    choice.members_visible += 1;
                }
            }
            None => pools.push((
                PoolChoice {
                    pool_id: probe.pool_id,
                    label: probe.label.clone(),
                    members_visible: 1,
                },
                vec![probe.device_id],
            )),
        }
    }
    pools.into_iter().map(|(choice, _)| choice).collect()
}

fn selector_matches(selector: &str, pool_id: &PoolId, label: &str) -> bool {
    if !label.is_empty() && selector == label {
        return true;
    }
    let lowered = selector.to_ascii_lowercase();
    !lowered.is_empty() && hex_id(&pool_id.0).starts_with(&lowered)
}

pub fn list_devices() -> Vec<DiscoveredDevice> {
    platform_list()
}

#[cfg(windows)]
fn platform_list() -> Vec<DiscoveredDevice> {
    let mut devices = Vec::new();
    for number in 0..64u32 {
        let path = format!(r"\\.\PhysicalDrive{number}");
        match RawBlockDevice::open_probe(Path::new(&path)) {
            Ok(device) => devices.push(probed(path, &device)),
            Err(ScaleFsError::Io(error))
                if error.kind() == std::io::ErrorKind::NotFound
                    || error.kind() == std::io::ErrorKind::InvalidInput =>
            {
                continue;
            }
            Err(error) => devices.push(DiscoveredDevice {
                path,
                size: None,
                identity: DeviceIdentity::default(),
                actuators: 0,
                contents: Contents::Unreadable,
                error: Some(error.to_string()),
            }),
        }
    }
    devices
}

#[cfg(target_os = "linux")]
fn platform_list() -> Vec<DiscoveredDevice> {
    let mut names: Vec<String> = match std::fs::read_dir("/sys/block") {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect(),
        Err(_) => return Vec::new(),
    };
    names.sort();
    let mut devices = Vec::new();
    for name in names {
        if ["ram", "zram", "dm-", "md", "sr"]
            .iter()
            .any(|skip| name.starts_with(skip))
        {
            continue;
        }
        let sectors: u64 = read_sysfs(&format!("/sys/block/{name}/size"))
            .and_then(|text| text.parse().ok())
            .unwrap_or(0);
        if sectors == 0 {
            continue;
        }
        devices.push(probe_path(Path::new(&format!("/dev/{name}"))));
    }
    devices
}

#[cfg(target_os = "macos")]
fn platform_list() -> Vec<DiscoveredDevice> {
    let mut numbers: Vec<u32> = match std::fs::read_dir("/dev") {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .strip_prefix("rdisk")
                    .filter(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
                    .and_then(|rest| rest.parse().ok())
            })
            .collect(),
        Err(_) => return Vec::new(),
    };
    numbers.sort_unstable();
    numbers
        .into_iter()
        .map(|number| probe_path(Path::new(&format!("/dev/rdisk{number}"))))
        .collect()
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn platform_list() -> Vec<DiscoveredDevice> {
    Vec::new()
}

#[cfg(windows)]
pub(crate) fn identity_of(file: &std::fs::File, _path: &Path) -> DeviceIdentity {
    let query = [0u8; 12];
    let mut descriptor = [0u8; 4096];
    match crate::raw::device_io(
        file,
        crate::raw::IOCTL_STORAGE_QUERY_PROPERTY,
        &query,
        &mut descriptor,
    ) {
        Ok(()) => parse_storage_device_descriptor(&descriptor),
        Err(_) => DeviceIdentity::default(),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn identity_of(file: &std::fs::File, _path: &Path) -> DeviceIdentity {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let Ok(metadata) = file.metadata() else {
        return DeviceIdentity::default();
    };
    if !metadata.file_type().is_block_device() {
        return DeviceIdentity::default();
    }
    let (major, minor) = split_dev(metadata.rdev());
    identity_from_sysfs(&format!("/sys/dev/block/{major}:{minor}"))
}

#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) fn identity_of(_file: &std::fs::File, _path: &Path) -> DeviceIdentity {
    DeviceIdentity::default()
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn identity_from_sysfs(base: &str) -> DeviceIdentity {
    let base = if Path::new(&format!("{base}/partition")).exists() {
        format!("{base}/..")
    } else {
        base.to_string()
    };
    let model = read_sysfs(&format!("{base}/device/model")).or_else(|| {
        read_sysfs(&format!("{base}/loop/backing_file")).map(|file| format!("loop: {file}"))
    });
    let serial = read_sysfs(&format!("{base}/device/serial"))
        .or_else(|| {
            std::fs::read(format!("{base}/device/vpd_pg80"))
                .ok()
                .and_then(|bytes| parse_vpd_page80(&bytes))
        })
        .or_else(|| read_sysfs(&format!("{base}/device/wwid")))
        .or_else(|| read_sysfs(&format!("{base}/wwid")));
    DeviceIdentity { serial, model }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn read_sysfs(path: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let text = text.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn split_dev(rdev: u64) -> (u32, u32) {
    let major = ((rdev >> 32) & 0xFFFF_F000) | ((rdev >> 8) & 0xFFF);
    let minor = ((rdev >> 12) & 0xFFFF_FF00) | (rdev & 0xFF);
    (major as u32, minor as u32)
}

fn parse_vpd_page80(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 4 || bytes[1] != 0x80 {
        return None;
    }
    let length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    printable(bytes.get(4..4 + length)?)
}

#[cfg_attr(not(windows), allow(dead_code))]
fn parse_storage_device_descriptor(bytes: &[u8]) -> DeviceIdentity {
    let offset_at = |at: usize| {
        bytes
            .get(at..at + 4)
            .map(|field| u32::from_le_bytes(field.try_into().expect("fixed slice")))
    };
    let string_at = |offset: u32| {
        if offset == 0 {
            return None;
        }
        let tail = bytes.get(offset as usize..)?;
        let end = tail
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(tail.len());
        printable(&tail[..end])
    };
    let vendor = offset_at(12).and_then(string_at);
    let product = offset_at(16).and_then(string_at);
    let serial = offset_at(24).and_then(string_at);
    let model = match (vendor, product) {
        (Some(vendor), Some(product)) => Some(format!("{vendor} {product}")),
        (vendor, product) => vendor.or(product),
    };
    DeviceIdentity { serial, model }
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn parse_volume_disk_extents(bytes: &[u8]) -> Option<Vec<u32>> {
    let count = bytes
        .get(0..4)
        .map(|field| u32::from_le_bytes(field.try_into().expect("fixed slice")))?;
    let mut disks = Vec::with_capacity(count as usize);
    for index in 0..count as usize {
        let at = 8 + index * 24;
        let field = bytes.get(at..at + 4)?;
        disks.push(u32::from_le_bytes(field.try_into().expect("fixed slice")));
    }
    Some(disks)
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn parse_storage_device_number(bytes: &[u8]) -> Option<(u32, u32, u32)> {
    if bytes.len() < 12 {
        return None;
    }
    let at = |index: usize| {
        u32::from_le_bytes(
            bytes[index..index + 4]
                .try_into()
                .expect("length checked above"),
        )
    };
    Some((at(0), at(4), at(8)))
}

fn printable(bytes: &[u8]) -> Option<String> {
    let text: String = bytes
        .iter()
        .map(|&byte| byte as char)
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .collect();
    let text = text.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::{CaseSensitivity, Geometry};
    use crate::pool::{CreateParams, MemberSpec, Pool, PoolParams};

    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "scalefs-discovery-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn small_geometry() -> Geometry {
        Geometry {
            logical_block_size: 4096,
            physical_block_size: 4096,
            zone_size: 64 * 1024,
            zone_count: 16,
            erase_granularity_zones: 1,
            sequential_write_required: false,
        }
    }

    #[test]
    fn probing_classifies_pool_members_and_strangers() {
        let dir = scratch_dir("classify");
        let geometry = small_geometry();

        let solo = dir.join("solo.img");
        Pool::create(
            crate::device::FileBlockDevice::create(&solo, geometry.capacity_bytes()).unwrap(),
            CreateParams {
                geometry,
                pool_id: PoolId([0xAB; 16]),
                device_id: DeviceId([0x01; 16]),
                case_sensitivity: CaseSensitivity::InsensitivePreserving,
                dirent_hash_seed: 1,
                label: "solo".to_string(),
                created_at_ns: 1_700_000_000_000_000_000,
            },
        )
        .unwrap();

        let mirror_a = dir.join("mirror-a.img");
        let mirror_b = dir.join("mirror-b.img");
        Pool::create_multi(
            [(&mirror_a, 0x11u8), (&mirror_b, 0x12u8)]
                .iter()
                .map(|(path, id)| MemberSpec {
                    device: crate::device::FileBlockDevice::create(path, geometry.capacity_bytes())
                        .unwrap(),
                    device_id: DeviceId([*id; 16]),
                    geometry,
                })
                .collect(),
            PoolParams {
                pool_id: PoolId([0xCD; 16]),
                case_sensitivity: CaseSensitivity::InsensitivePreserving,
                dirent_hash_seed: 2,
                label: "tank".to_string(),
                created_at_ns: 1_700_000_000_000_000_000,
                mirror_width: 2,
                data_width: 1,
                parity_width: 0,
            },
        )
        .unwrap();

        let solo_probe = probe_path(&solo);
        match &solo_probe.contents {
            Contents::Pool(probe) => {
                assert_eq!(probe.pool_id, PoolId([0xAB; 16]));
                assert_eq!(probe.device_id, DeviceId([0x01; 16]));
                assert_eq!(probe.label, "solo");
                assert!(!probe.unknown_incompat);
            }
            other => panic!("expected a pool, got {other:?}"),
        }
        assert_eq!(solo_probe.size, Some(geometry.capacity_bytes()));

        for (path, device_id) in [(&mirror_a, 0x11u8), (&mirror_b, 0x12)] {
            match &probe_path(path).contents {
                Contents::Pool(probe) => {
                    assert_eq!(probe.pool_id, PoolId([0xCD; 16]));
                    assert_eq!(probe.device_id, DeviceId([device_id; 16]));
                    assert_eq!(probe.label, "tank");
                }
                other => panic!("expected a pool member, got {other:?}"),
            }
        }

        let mbr = dir.join("mbr.img");
        let mut bytes = vec![0u8; 1 << 20];
        bytes[510] = 0x55;
        bytes[511] = 0xAA;
        std::fs::write(&mbr, &bytes).unwrap();
        assert!(matches!(probe_path(&mbr).contents, Contents::Partitioned));

        for (name, at) in [("gpt-512.img", 512usize), ("gpt-4096.img", 4096)] {
            let path = dir.join(name);
            let mut bytes = vec![0u8; 1 << 20];
            bytes[at..at + 8].copy_from_slice(b"EFI PART");
            std::fs::write(&path, &bytes).unwrap();
            assert!(
                matches!(probe_path(&path).contents, Contents::Partitioned),
                "{name}"
            );
        }

        let blank = dir.join("blank.img");
        std::fs::write(&blank, vec![0u8; 1 << 20]).unwrap();
        assert!(matches!(probe_path(&blank).contents, Contents::Blank));

        let junk = dir.join("junk.img");
        std::fs::write(&junk, vec![0x5Au8; 1 << 20]).unwrap();
        assert!(matches!(probe_path(&junk).contents, Contents::Foreign));

        let tiny = dir.join("tiny.img");
        std::fs::write(&tiny, vec![0x5Au8; 100]).unwrap();
        let tiny_probe = probe_path(&tiny);
        assert!(
            !matches!(tiny_probe.contents, Contents::Pool(_)),
            "a 100-byte file cannot be a pool"
        );

        let missing = probe_path(&dir.join("no-such-file"));
        assert!(matches!(missing.contents, Contents::Unreadable));
        assert!(missing.error.is_some());
        assert_eq!(missing.size, None);

        let _ = std::fs::remove_dir_all(dir);
    }

    fn pool_device(path: &str, pool: u8, device: u8, label: &str) -> DiscoveredDevice {
        pool_device_at(path, pool, device, label, 1, 1)
    }

    fn pool_device_at(
        path: &str,
        pool: u8,
        device: u8,
        label: &str,
        generation: u64,
        tx: u64,
    ) -> DiscoveredDevice {
        DiscoveredDevice {
            path: path.to_string(),
            size: Some(1 << 20),
            identity: DeviceIdentity::default(),
            actuators: 0,
            contents: Contents::Pool(PoolProbe {
                pool_id: PoolId([pool; 16]),
                device_id: DeviceId([device; 16]),
                label: label.to_string(),
                topology_generation: generation,
                tx,
                unknown_incompat: false,
            }),
            error: None,
        }
    }

    fn stranger(path: &str) -> DiscoveredDevice {
        DiscoveredDevice {
            path: path.to_string(),
            size: Some(1 << 20),
            identity: DeviceIdentity::default(),
            actuators: 0,
            contents: Contents::Foreign,
            error: None,
        }
    }

    #[test]
    fn plans_group_select_and_refuse_correctly() {
        let one = [
            stranger("noise"),
            pool_device("a", 0xAA, 1, "tank"),
            pool_device("b", 0xAA, 2, "tank"),
        ];
        let plan = plan_import(&one, None).unwrap();
        assert_eq!(plan.pool_id, PoolId([0xAA; 16]));
        assert_eq!(plan.label, "tank");
        assert_eq!(plan.members, vec!["a".to_string(), "b".to_string()]);

        let doubled = [
            pool_device("first", 0xAA, 1, "tank"),
            pool_device("second", 0xAA, 1, "tank"),
            pool_device("b", 0xAA, 2, "tank"),
        ];
        let plan = plan_import(&doubled, None).unwrap();
        assert_eq!(plan.members, vec!["first".to_string(), "b".to_string()]);
        assert_eq!(plan.duplicates, vec!["second".to_string()]);

        let cloned = [
            pool_device_at("stale-clone", 0xAA, 1, "tank", 1, 100),
            pool_device_at("original", 0xAA, 1, "tank", 1, 250),
        ];
        let plan = plan_import(&cloned, None).unwrap();
        assert_eq!(plan.members, vec!["original".to_string()]);
        assert_eq!(plan.duplicates, vec!["stale-clone".to_string()]);
        let regrown = [
            pool_device_at("old-gen", 0xAA, 1, "tank", 2, 900),
            pool_device_at("new-gen", 0xAA, 1, "tank", 3, 500),
        ];
        let plan = plan_import(&regrown, None).unwrap();
        assert_eq!(plan.members, vec!["new-gen".to_string()]);

        assert!(matches!(
            plan_import(&[stranger("x")], None),
            Err(PlanError::NoPools)
        ));

        let two = [
            pool_device("a", 0xAA, 1, "tank"),
            pool_device("c", 0xBB, 3, "spare"),
        ];
        match plan_import(&two, None) {
            Err(PlanError::SeveralPools(choices)) => {
                assert_eq!(choices.len(), 2);
                let text = PlanError::SeveralPools(choices).to_string();
                assert!(text.contains("tank") && text.contains("spare"), "{text}");
            }
            other => panic!("expected SeveralPools, got {other:?}"),
        }

        let plan = plan_import(&two, Some("spare")).unwrap();
        assert_eq!(plan.members, vec!["c".to_string()]);
        let plan = plan_import(&two, Some("aaaa")).unwrap();
        assert_eq!(plan.label, "tank");
        let plan = plan_import(&two, Some("BBBB")).unwrap();
        assert_eq!(plan.label, "spare", "selectors are case-insensitive hex");

        assert!(matches!(
            plan_import(&two, Some("nope")),
            Err(PlanError::NoMatch(_))
        ));
        let twins = [
            pool_device("a", 0xAA, 1, "tank"),
            pool_device("c", 0xBB, 3, "tank"),
        ];
        assert!(matches!(
            plan_import(&twins, Some("tank")),
            Err(PlanError::AmbiguousSelector(..))
        ));
        let plan = plan_import(&twins, Some("bb")).unwrap();
        assert_eq!(plan.members, vec!["c".to_string()]);
    }

    #[test]
    fn identity_parsers_handle_real_and_hostile_bytes() {
        let mut vpd = vec![0x00, 0x80, 0x00, 0x0F];
        vpd.extend_from_slice(b"  WD-WX12AB34  ");
        assert_eq!(parse_vpd_page80(&vpd).as_deref(), Some("WD-WX12AB34"));
        assert_eq!(parse_vpd_page80(&[0x00, 0x80, 0xFF, 0xFF, b'a']), None);
        assert_eq!(parse_vpd_page80(&[0x00, 0x7F, 0x00, 0x01, b'a']), None);
        assert_eq!(parse_vpd_page80(&[0x00, 0x80, 0x00, 0x00]), None);

        let mut descriptor = vec![0u8; 64];
        descriptor[12..16].copy_from_slice(&40u32.to_le_bytes());
        descriptor[16..20].copy_from_slice(&48u32.to_le_bytes());
        descriptor[24..28].copy_from_slice(&56u32.to_le_bytes());
        descriptor[40..47].copy_from_slice(b"ACME  \0");
        descriptor[48..55].copy_from_slice(b"DISK9\0\0");
        descriptor[56..63].copy_from_slice(b"SN0042\0");
        let identity = parse_storage_device_descriptor(&descriptor);
        assert_eq!(identity.model.as_deref(), Some("ACME DISK9"));
        assert_eq!(identity.serial.as_deref(), Some("SN0042"));
        let empty = parse_storage_device_descriptor(&[0u8; 64]);
        assert_eq!(empty, DeviceIdentity::default());
        let mut hostile = vec![0u8; 64];
        hostile[24..28].copy_from_slice(&9999u32.to_le_bytes());
        assert_eq!(parse_storage_device_descriptor(&hostile).serial, None);

        let mut extents = vec![0u8; 8 + 2 * 24];
        extents[0..4].copy_from_slice(&2u32.to_le_bytes());
        extents[8..12].copy_from_slice(&2u32.to_le_bytes());
        extents[32..36].copy_from_slice(&5u32.to_le_bytes());
        assert_eq!(parse_volume_disk_extents(&extents), Some(vec![2, 5]));
        extents[0..4].copy_from_slice(&40u32.to_le_bytes());
        assert_eq!(parse_volume_disk_extents(&extents), None);

        let mut number = vec![0u8; 12];
        number[0..4].copy_from_slice(&7u32.to_le_bytes());
        number[4..8].copy_from_slice(&3u32.to_le_bytes());
        number[8..12].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert_eq!(
            parse_storage_device_number(&number),
            Some((7, 3, 0xFFFF_FFFF))
        );
        assert_eq!(parse_storage_device_number(&[0u8; 4]), None);

        assert_eq!(split_dev(0x0000_0800), (8, 0));
        assert_eq!(split_dev(0x0000_0811), (8, 17));
        assert_eq!(split_dev(0x0001_0300), (259, 0));
        assert_eq!(split_dev(0x1230_0045), (0, 0x12345));
    }

    #[test]
    fn listing_devices_is_shape_safe() {
        for device in list_devices() {
            assert!(!device.path.is_empty());
            if matches!(device.contents, Contents::Unreadable) {
                assert!(device.error.is_some(), "{}", device.path);
            }
        }
    }
}
