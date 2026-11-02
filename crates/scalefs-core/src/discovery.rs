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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DeviceAttachment {
    External,
    Internal,
    #[default]
    Unknown,
}

pub fn classify_attachment(
    bus_type: u32,
    device_hotplug: bool,
    removable_media: bool,
) -> DeviceAttachment {
    if device_hotplug || removable_media {
        return DeviceAttachment::External;
    }
    match bus_type {
        7 | 4 | 12 | 13 | 19 => DeviceAttachment::External,
        1 | 2 | 3 | 6 | 8 | 9 | 10 | 11 | 16 | 17 | 18 => DeviceAttachment::Internal,
        _ => DeviceAttachment::Unknown,
    }
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
    let partition = match crate::gpt::find_member_partition(device) {
        Ok(partition) => partition,
        Err(crate::error::ScaleFsError::Io(error)) => {
            return (Contents::Unreadable, Some(error.to_string()));
        }
        Err(error) => return (Contents::Partitioned, Some(error.to_string())),
    };
    if let Some(partition) = partition {
        let view = match crate::device::PartitionView::new(device, partition.start, partition.len) {
            Ok(view) => view,
            Err(error) => return (Contents::Partitioned, Some(error.to_string())),
        };
        let mut freshest: Option<PoolProbe> = None;
        for offset in superblock_slots(view.len()) {
            let available = view.len().saturating_sub(offset).min(4096);
            if available == 0 {
                continue;
            }
            let mut bytes = vec![0u8; available as usize];
            if let Err(error) = view.read_at(offset, &mut bytes) {
                return (Contents::Unreadable, Some(error.to_string()));
            }
            let Ok(superblock) = decode_superblock(&bytes) else {
                continue;
            };
            let tx = superblock
                .newest_commit
                .filter(|extent| extent.length <= 64 * 1024)
                .and_then(|extent| {
                    let mut bytes = vec![0u8; extent.length as usize];
                    view.read_at(extent.offset, &mut bytes).ok()?;
                    crate::records::decode_commit(&bytes).ok()
                })
                .map_or(0, |commit| commit.tx_id);
            let probe = PoolProbe {
                pool_id: superblock.pool_id,
                device_id: superblock.device_id,
                label: superblock.label.clone(),
                topology_generation: superblock.topology_generation,
                tx,
                unknown_incompat: superblock.unknown_incompat() != 0,
            };
            if freshest.as_ref().is_none_or(|best| {
                (probe.topology_generation, probe.tx) > (best.topology_generation, best.tx)
            }) {
                freshest = Some(probe);
            }
        }
        if let Some(probe) = freshest {
            return (Contents::Pool(probe), None);
        }
        return (
            Contents::Partitioned,
            Some("a ScaleFS-typed partition with no readable superblock".to_string()),
        );
    }

    let len = device.len();
    if len == 0 {
        return (
            Contents::Unreadable,
            Some("the device is empty".to_string()),
        );
    }
    let mut head = vec![0u8; len.min(BLANK_SAMPLE_LEN) as usize];
    if let Err(error) = device.read_at(0, &mut head) {
        return (Contents::Unreadable, Some(error.to_string()));
    }
    let tail_start = len.saturating_sub(BLANK_SAMPLE_LEN).max(head.len() as u64);
    let mut tail = vec![0u8; (len - tail_start) as usize];
    if !tail.is_empty()
        && let Err(error) = device.read_at(tail_start, &mut tail)
    {
        return (Contents::Unreadable, Some(error.to_string()));
    }
    let mbr = head.len() >= 512 && head[510] == 0x55 && head[511] == 0xAA;
    let gpt_512 = head.len() >= 520 && &head[512..520] == b"EFI PART";
    let gpt_4096 = head.len() >= 4104 && &head[4096..4104] == b"EFI PART";
    if mbr || gpt_512 || gpt_4096 {
        return (Contents::Partitioned, None);
    }
    if let Some(what) = foreign_signature(&head) {
        return (Contents::Foreign, Some(what.to_string()));
    }
    if head.iter().chain(tail.iter()).all(|&byte| byte == 0) {
        return (Contents::Blank, None);
    }
    (Contents::Foreign, None)
}

pub const BLANK_SAMPLE_LEN: u64 = 1 << 20;

fn foreign_signature(head: &[u8]) -> Option<&'static str> {
    const SIGNATURES: &[(usize, &[u8], &str)] = &[
        (0x10040, b"_BHRfS_M", "a Btrfs filesystem"),
        (0, b"XFSB", "an XFS filesystem"),
        (1080, &[0x53, 0xEF], "an ext2/3/4 filesystem"),
        (1024, &[0x10, 0x20, 0xF5, 0xF2], "an F2FS filesystem"),
        (0, b"LUKS\xba\xbe", "a LUKS encrypted volume"),
        (512, b"LABELONE", "an LVM physical volume"),
        (0, &[0xFC, 0x4E, 0x2B, 0xA9], "a Linux RAID (mdadm) member"),
        (
            4096,
            &[0xFC, 0x4E, 0x2B, 0xA9],
            "a Linux RAID (mdadm) member",
        ),
        (
            0x20000,
            &[0x0C, 0xB1, 0xBA, 0x00, 0, 0, 0, 0],
            "a ZFS pool member",
        ),
        (
            0x20000,
            &[0, 0, 0, 0, 0x00, 0xBA, 0xB1, 0x0C],
            "a ZFS pool member",
        ),
        (4086, b"SWAPSPACE2", "a Linux swap area"),
        (32, b"NXSB", "an APFS container"),
        (32769, b"CD001", "an ISO 9660 image"),
    ];
    SIGNATURES
        .iter()
        .find(|(offset, magic, _)| head.get(*offset..offset + magic.len()) == Some(*magic))
        .map(|(_, _, what)| *what)
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

pub fn attachment_of_path(path: &Path) -> DeviceAttachment {
    attachment_of(path)
}

#[cfg(windows)]
const IOCTL_STORAGE_GET_HOTPLUG_INFO: u32 = 0x002D_0C14;
#[cfg(windows)]
const IOCTL_STORAGE_GET_DEVICE_NUMBER: u32 = 0x002D_1080;
#[cfg(windows)]
const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: u32 = 0x0056_0000;
#[cfg(windows)]
const FILE_SHARE_READ: u32 = 1;
#[cfg(windows)]
const FILE_SHARE_WRITE: u32 = 2;
#[cfg(windows)]
const FILE_SHARE_DELETE: u32 = 4;
#[cfg(windows)]
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;

#[cfg(windows)]
fn attachment_of(path: &Path) -> DeviceAttachment {
    if crate::raw::is_device_path(path) {
        device_attachment(path)
    } else {
        file_host_attachment(path)
    }
}

#[cfg(windows)]
fn device_attachment(path: &Path) -> DeviceAttachment {
    use std::os::windows::fs::OpenOptionsExt;
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    for access in [0u32, FILE_READ_ATTRIBUTES] {
        let Ok(file) = std::fs::OpenOptions::new()
            .access_mode(access)
            .share_mode(share)
            .open(path)
        else {
            continue;
        };
        let query = [0u8; 12];
        let mut descriptor = [0u8; 4096];
        if crate::raw::device_io(
            &file,
            crate::raw::IOCTL_STORAGE_QUERY_PROPERTY,
            &query,
            &mut descriptor,
        )
        .is_err()
        {
            continue;
        }
        let (bus, removable) = descriptor_attachment_fields(&descriptor);
        let mut hotplug = [0u8; 8];
        let device_hotplug =
            crate::raw::device_io(&file, IOCTL_STORAGE_GET_HOTPLUG_INFO, &[], &mut hotplug).is_ok()
                && hotplug_is_device_hotplug(&hotplug);
        return classify_attachment(bus, device_hotplug, removable);
    }
    DeviceAttachment::Unknown
}

#[cfg(windows)]
fn file_host_attachment(path: &Path) -> DeviceAttachment {
    use std::os::windows::fs::OpenOptionsExt;
    let Some(mount) = crate::raw::volume_path_name(path) else {
        return DeviceAttachment::Unknown;
    };
    let Some(volume_guid) = crate::raw::volume_guid_name(&mount) else {
        return DeviceAttachment::Unknown;
    };
    let volume = volume_guid.trim_end_matches('\\').to_string();
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    let Ok(handle) = std::fs::OpenOptions::new()
        .access_mode(0)
        .share_mode(share)
        .open(&volume)
    else {
        return DeviceAttachment::Unknown;
    };
    let mut number = [0u8; 12];
    if crate::raw::device_io(&handle, IOCTL_STORAGE_GET_DEVICE_NUMBER, &[], &mut number).is_ok()
        && let Some((_, disk, _)) = parse_storage_device_number(&number)
    {
        return device_attachment(Path::new(&format!(r"\\.\PhysicalDrive{disk}")));
    }
    let mut extents = vec![0u8; 4096];
    if crate::raw::device_io(
        &handle,
        IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
        &[],
        &mut extents,
    )
    .is_err()
    {
        return DeviceAttachment::Unknown;
    }
    let Some(disks) = parse_volume_disk_extents(&extents) else {
        return DeviceAttachment::Unknown;
    };
    if disks.is_empty() {
        return DeviceAttachment::Unknown;
    }
    let mut rollup = DeviceAttachment::External;
    for disk in disks {
        match device_attachment(Path::new(&format!(r"\\.\PhysicalDrive{disk}"))) {
            DeviceAttachment::Internal => return DeviceAttachment::Internal,
            DeviceAttachment::Unknown => rollup = DeviceAttachment::Unknown,
            DeviceAttachment::External => {}
        }
    }
    rollup
}

#[cfg(target_os = "linux")]
fn attachment_of(path: &Path) -> DeviceAttachment {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let Ok(metadata) = std::fs::metadata(path) else {
        return DeviceAttachment::Unknown;
    };
    let file_type = metadata.file_type();
    if file_type.is_block_device() {
        let (major, minor) = split_dev(metadata.rdev());
        sysfs_attachment("/sys", major, minor)
    } else if file_type.is_file() {
        let (major, minor) = split_dev(metadata.dev());
        sysfs_attachment("/sys", major, minor)
    } else {
        DeviceAttachment::Unknown
    }
}

#[cfg(target_os = "linux")]
fn sysfs_attachment(root: &str, major: u32, minor: u32) -> DeviceAttachment {
    let node = std::path::PathBuf::from(format!("{root}/dev/block/{major}:{minor}"));
    let canonical = std::fs::canonicalize(&node).unwrap_or(node);
    let backing_file = canonical.join("loop/backing_file");
    if let Some(backing) = read_sysfs(&backing_file.to_string_lossy()) {
        use std::os::unix::fs::MetadataExt;
        return match std::fs::metadata(&backing) {
            Ok(meta) => {
                let (major, minor) = split_dev(meta.dev());
                sysfs_transport(root, major, minor)
            }
            Err(_) => DeviceAttachment::Unknown,
        };
    }
    sysfs_transport_at(&canonical)
}

#[cfg(target_os = "linux")]
fn sysfs_transport(root: &str, major: u32, minor: u32) -> DeviceAttachment {
    let node = std::path::PathBuf::from(format!("{root}/dev/block/{major}:{minor}"));
    let canonical = std::fs::canonicalize(&node).unwrap_or(node);
    sysfs_transport_at(&canonical)
}

#[cfg(target_os = "linux")]
fn sysfs_transport_at(canonical: &Path) -> DeviceAttachment {
    let disk = if canonical.join("partition").exists() {
        canonical
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| canonical.to_path_buf())
    } else {
        canonical.to_path_buf()
    };
    if read_sysfs(&disk.join("removable").to_string_lossy()).as_deref() == Some("1") {
        return DeviceAttachment::External;
    }
    let text = disk.to_string_lossy();
    if path_has_segment(&text, "usb") {
        return DeviceAttachment::External;
    }
    if ["nvme", "ata", "sas", "scsi", "target", "virtio"]
        .iter()
        .any(|marker| path_has_segment(&text, marker))
    {
        return DeviceAttachment::Internal;
    }
    DeviceAttachment::Unknown
}

#[cfg(target_os = "linux")]
fn path_has_segment(path: &str, prefix: &str) -> bool {
    path.split('/').any(|segment| segment.starts_with(prefix))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn attachment_of(_path: &Path) -> DeviceAttachment {
    DeviceAttachment::Unknown
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
fn descriptor_attachment_fields(bytes: &[u8]) -> (u32, bool) {
    let bus = bytes
        .get(28..32)
        .map(|field| u32::from_le_bytes(field.try_into().expect("fixed slice")))
        .unwrap_or(0);
    let removable = bytes.get(10).is_some_and(|&byte| byte != 0);
    (bus, removable)
}

#[cfg_attr(not(windows), allow(dead_code))]
fn hotplug_is_device_hotplug(bytes: &[u8]) -> bool {
    bytes.get(6).is_some_and(|&byte| byte != 0)
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
            crate::device::FileBlockDevice::create(
                &solo,
                crate::gpt::member_image_len(geometry.capacity_bytes()),
            )
            .unwrap(),
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
                    device: crate::device::FileBlockDevice::create(
                        path,
                        crate::gpt::member_image_len(geometry.capacity_bytes()),
                    )
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
        assert_eq!(
            solo_probe.size,
            Some(crate::gpt::member_image_len(geometry.capacity_bytes()))
        );

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

        let btrfs = dir.join("btrfs.img");
        let mut bytes = vec![0u8; 4 << 20];
        bytes[0x10040..0x10048].copy_from_slice(b"_BHRfS_M");
        std::fs::write(&btrfs, &bytes).unwrap();
        let btrfs_probe = probe_path(&btrfs);
        assert!(
            matches!(btrfs_probe.contents, Contents::Foreign),
            "{btrfs_probe:?}"
        );
        assert!(
            btrfs_probe
                .error
                .as_deref()
                .is_some_and(|what| what.contains("Btrfs")),
            "{btrfs_probe:?}"
        );

        let zfs = dir.join("zfs.img");
        let mut bytes = vec![0u8; 4 << 20];
        bytes[0x20000..0x20004].copy_from_slice(&[0x0C, 0xB1, 0xBA, 0x00]);
        std::fs::write(&zfs, &bytes).unwrap();
        let zfs_probe = probe_path(&zfs);
        assert!(
            zfs_probe
                .error
                .as_deref()
                .is_some_and(|what| what.contains("ZFS")),
            "{zfs_probe:?}"
        );

        for (name, at) in [
            ("late-head.img", 700 * 1024),
            ("late-tail.img", (4 << 20) - 300 * 1024),
        ] {
            let path = dir.join(name);
            let mut bytes = vec![0u8; 4 << 20];
            bytes[at] = 1;
            std::fs::write(&path, &bytes).unwrap();
            let probe = probe_path(&path);
            assert!(
                matches!(probe.contents, Contents::Foreign) && probe.error.is_none(),
                "{name}: {probe:?}"
            );
        }

        let big_blank = dir.join("big-blank.img");
        std::fs::write(&big_blank, vec![0u8; 4 << 20]).unwrap();
        assert!(matches!(probe_path(&big_blank).contents, Contents::Blank));

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

    #[test]
    fn attachment_classifier_covers_every_bus() {
        use DeviceAttachment::*;
        for bus in [7u32, 4, 12, 13, 19] {
            assert_eq!(
                classify_attachment(bus, false, false),
                External,
                "bus {bus}"
            );
        }
        for bus in [1u32, 2, 3, 6, 8, 9, 10, 11, 16, 17, 18] {
            assert_eq!(
                classify_attachment(bus, false, false),
                Internal,
                "bus {bus}"
            );
        }
        for bus in [0u32, 14, 15, 999] {
            assert_eq!(classify_attachment(bus, false, false), Unknown, "bus {bus}");
        }
        assert_eq!(classify_attachment(11, true, false), External, "hotplug");
        assert_eq!(classify_attachment(11, false, true), External, "removable");
        assert_eq!(classify_attachment(7, true, true), External);
    }

    #[test]
    fn attachment_fields_are_bounds_safe() {
        use DeviceAttachment::*;
        let mut descriptor = vec![0u8; 64];
        descriptor[28..32].copy_from_slice(&7u32.to_le_bytes());
        descriptor[10] = 1;
        assert_eq!(descriptor_attachment_fields(&descriptor), (7, true));
        let (bus, removable) = descriptor_attachment_fields(&[0u8; 8]);
        assert_eq!((bus, removable), (0, false));
        assert_eq!(classify_attachment(bus, false, removable), Unknown);
        let mut hotplug = vec![0u8; 8];
        hotplug[6] = 1;
        assert!(hotplug_is_device_hotplug(&hotplug));
        assert!(!hotplug_is_device_hotplug(&[0u8; 4]));
        assert!(!hotplug_is_device_hotplug(&hotplug[..6]));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sysfs_attachment_classifies_a_fake_tree() {
        use std::os::unix::fs::{MetadataExt, symlink};
        let root = scratch_dir("sysfs-attach");
        let sys = root.join("sys");
        let dev_block = sys.join("dev/block");
        std::fs::create_dir_all(&dev_block).unwrap();
        let sys_str = sys.to_string_lossy().into_owned();

        let plant = |rel: &str, major: u32, minor: u32| -> std::path::PathBuf {
            let node = sys.join("devices").join(rel);
            std::fs::create_dir_all(&node).unwrap();
            let link = dev_block.join(format!("{major}:{minor}"));
            let _ = std::fs::remove_file(&link);
            symlink(Path::new("../..").join("devices").join(rel), &link).unwrap();
            node
        };

        plant(
            "pci0000:00/usb1/1-1/host6/target6:0:0/6:0:0:0/block/sdb",
            8,
            16,
        );
        assert_eq!(
            sysfs_attachment(&sys_str, 8, 16),
            DeviceAttachment::External
        );

        plant("pci0000:00/0000:00:1d.0/nvme/nvme0/nvme0n1", 259, 0);
        assert_eq!(
            sysfs_attachment(&sys_str, 259, 0),
            DeviceAttachment::Internal
        );

        let bay = plant("pci0000:00/ata3/host2/target2:0:0/2:0:0:0/block/sdc", 8, 32);
        std::fs::write(bay.join("removable"), "1\n").unwrap();
        assert_eq!(
            sysfs_attachment(&sys_str, 8, 32),
            DeviceAttachment::External
        );

        let sata = plant("pci0000:00/ata4/host3/target3:0:0/3:0:0:0/block/sdd", 8, 48);
        std::fs::write(sata.join("removable"), "0\n").unwrap();
        assert_eq!(
            sysfs_attachment(&sys_str, 8, 48),
            DeviceAttachment::Internal
        );

        let part = sys.join("devices/pci0000:00/0000:00:1d.0/nvme/nvme0/nvme0n1/nvme0n1p1");
        std::fs::create_dir_all(&part).unwrap();
        std::fs::write(part.join("partition"), "1\n").unwrap();
        let link = dev_block.join("259:1");
        let _ = std::fs::remove_file(&link);
        symlink(
            Path::new("../../devices/pci0000:00/0000:00:1d.0/nvme/nvme0/nvme0n1/nvme0n1p1"),
            &link,
        )
        .unwrap();
        assert_eq!(
            sysfs_attachment(&sys_str, 259, 1),
            DeviceAttachment::Internal
        );

        let backing = root.join("backing.img");
        std::fs::write(&backing, b"backing").unwrap();
        let (bmaj, bmin) = split_dev(std::fs::metadata(&backing).unwrap().dev());
        let (lmaj, lmin) = if (bmaj, bmin) == (7, 0) {
            (7, 1)
        } else {
            (7, 0)
        };
        plant("pci0000:00/0000:00:1d.0/nvme/nvme9/nvme9n1", bmaj, bmin);
        let loop_node = plant("virtual/block/loop0", lmaj, lmin);
        std::fs::create_dir_all(loop_node.join("loop")).unwrap();
        std::fs::write(
            loop_node.join("loop/backing_file"),
            format!("{}\n", backing.display()),
        )
        .unwrap();
        assert_eq!(
            sysfs_attachment(&sys_str, lmaj, lmin),
            DeviceAttachment::Internal
        );

        assert_eq!(
            sysfs_attachment(&sys_str, 123, 45),
            DeviceAttachment::Unknown
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
