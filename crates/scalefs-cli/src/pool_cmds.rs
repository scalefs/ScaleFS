
use std::collections::BTreeMap;
use std::path::Path;

use scalefs_core::{
    AnyBlockDevice, BlockDevice, CaseSensitivity, Contents, CreateParams, DeviceId,
    DiscoveredDevice, EntryKind, Extent, FEATURE_INCOMPAT_PARITY, FileBlockDevice, Geometry,
    ITEM_DIRENT, ITEM_FILE_EXTENT, ITEM_INODE, ITEM_POOL_STATE, ITEM_SPECIAL, ITEM_XATTR,
    InodeAttrs, MODE_BLOCK_DEVICE, MODE_CHAR_DEVICE, MODE_DIRECTORY, MODE_FIFO, MODE_FILE,
    MODE_SOCKET, MODE_SYMLINK, MODE_TYPE_MASK, MemberSpec, MetadataKey, MetadataValue,
    ParityRecord, Pool, PoolId, PoolParams, ROOT_INODE, ZoneClass, decode_file_data,
    decode_parity_record, generate_parity,
};

use crate::util::{Opts, fill_random, format_size, format_time, now_ns, parse_size};

pub fn cmd_pool(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("create") => pool_create(&args[1..]),
        Some("import") => pool_import(&args[1..]),
        Some("status") => pool_status(&args[1..]),
        Some("inspect") => pool_inspect(&args[1..]),
        Some("reclaim") => pool_reclaim(&args[1..]),
        Some("compact") => pool_compact(&args[1..]),
        Some("add") => pool_add(&args[1..]),
        Some("replace") => pool_replace(&args[1..]),
        Some("rebuild") => pool_rebuild(&args[1..]),
        Some("remove") => pool_remove(&args[1..]),
        _ => Err(
            "usage: scalefs pool <create|import|status|inspect|reclaim|compact|add|replace|\
             rebuild|remove> ..."
                .to_string(),
        ),
    }
}

fn pool_compact(args: &[String]) -> Result<(), String> {
    let [images] = args else {
        return Err("usage: scalefs pool compact <image[,image...]>".to_string());
    };
    let mut pool = open_pool(images)?;
    let report = pool
        .compact(now_ns())
        .map_err(|err| format!("cannot compact: {err}"))?;
    println!(
        "compacted {} stripe(s), rewriting {} record(s); reclaimed {} in {} zone(s)",
        report.stripes_compacted,
        report.records_rewritten,
        format_size(report.reclaim.bytes_reclaimed),
        report.reclaim.zones_reset,
    );
    Ok(())
}

fn pool_import(args: &[String]) -> Result<(), String> {
    let opts = Opts::parse(args, &[], &["pool"])?;
    let candidates: Vec<DiscoveredDevice> = if opts.positional.is_empty() {
        scalefs_core::list_devices()
    } else {
        opts.positional
            .iter()
            .map(|path| scalefs_core::probe_path(Path::new(path)))
            .collect()
    };
    let plan = scalefs_core::plan_import(&candidates, opts.value("pool"))
        .map_err(|error| error.to_string())?;
    println!(
        "importing pool '{}' ({}) from {} member device(s):",
        plan.label,
        hex(&plan.pool_id.0),
        plan.members.len(),
    );
    for path in &plan.members {
        println!("  {path}");
    }
    for path in &plan.duplicates {
        eprintln!(
            "warning: {path} presents the same member as another candidate \
             (a clone or a second spelling) and was left out"
        );
    }
    let pool = open_pool_paths(&plan.members)?;
    println!();
    print_pool_status(&pool, &serials_from_probes(&candidates))
}

fn serials_from_probes(devices: &[DiscoveredDevice]) -> BTreeMap<String, String> {
    devices
        .iter()
        .filter_map(|device| match (&device.contents, &device.identity.serial) {
            (Contents::Pool(probe), Some(serial)) => {
                Some((hex(&probe.device_id.0), serial.clone()))
            }
            _ => None,
        })
        .collect()
}

fn probe_serials(paths: &[String]) -> BTreeMap<String, String> {
    let probes: Vec<DiscoveredDevice> = paths
        .iter()
        .filter(|path| scalefs_core::is_device_path(Path::new(path.as_str())))
        .map(|path| scalefs_core::probe_path(Path::new(path)))
        .collect();
    serials_from_probes(&probes)
}

fn pool_remove(args: &[String]) -> Result<(), String> {
    let [images, leaving] = args else {
        return Err("usage: scalefs pool remove <image[,image...]> <leaving-image>".to_string());
    };
    if !images.split(',').any(|image| image == leaving) {
        return Err(format!("{leaving} is not among the supplied members"));
    }
    let mut pool = open_pool(images)?;
    let leaving_device = scalefs_core::RawBlockDevice::open_probe(Path::new(leaving))
        .map_err(|err| format!("cannot open {leaving}: {err}"))?;
    let leaving_id = scalefs_core::decode_superblock(
        &read_first_block(&leaving_device).map_err(|err| format!("{leaving}: {err}"))?,
    )
    .map_err(|err| format!("{leaving}: {err}"))?
    .device_id;
    drop(leaving_device);
    let member = (0..pool.member_count() as u16)
        .find(|&m| {
            pool.superblock_for_member(m)
                .is_some_and(|superblock| superblock.device_id == leaving_id)
        })
        .ok_or_else(|| format!("{leaving} is not a member of this pool"))?;
    pool.remove_member(member, now_ns())
        .map_err(|err| format!("cannot remove member {member}: {err}"))?;
    println!(
        "removed {leaving} (member {member}); the pool now has {} active member(s)",
        pool.superblocks().len(),
    );
    Ok(())
}

fn create_member(path: &str, capacity: u64, block_size: u32) -> Result<AnyBlockDevice, String> {
    if scalefs_core::is_device_path(Path::new(path)) {
        let device = scalefs_core::RawBlockDevice::open(Path::new(path))
            .map_err(|err| format!("cannot open {path}: {err}"))?;
        if device.len() < capacity {
            return Err(format!(
                "{path}: the device holds {} but the pool needs {}",
                format_size(device.len()),
                format_size(capacity),
            ));
        }
        if block_size < device.sector_size() {
            return Err(format!(
                "{path}: --block-size {} is smaller than the device's {}-byte sectors",
                format_size(u64::from(block_size)),
                device.sector_size(),
            ));
        }
        Ok(AnyBlockDevice::Raw(device))
    } else {
        FileBlockDevice::create(Path::new(path), capacity)
            .map(AnyBlockDevice::File)
            .map_err(|err| format!("cannot create {path}: {err}"))
    }
}

fn refuse_accidental_overwrite(path: &str, force: bool) -> Result<(), String> {
    if force {
        return Ok(());
    }
    if !scalefs_core::is_device_path(Path::new(path)) {
        if Path::new(path).exists() {
            return Err(format!("{path} already exists (use --force to overwrite)"));
        }
        return Ok(());
    }
    let holds = match scalefs_core::probe_path(Path::new(path)).contents {
        scalefs_core::Contents::Blank => return Ok(()),
        scalefs_core::Contents::Pool(probe) => {
            format!(
                "a ScaleFS pool ('{}', {})",
                probe.label,
                hex(&probe.pool_id.0)
            )
        }
        scalefs_core::Contents::Partitioned => "a partition table".to_string(),
        scalefs_core::Contents::Foreign => "unrecognized data".to_string(),
        scalefs_core::Contents::Unreadable => return Ok(()),
    };
    Err(format!("{path} holds {holds}; use --force to overwrite it"))
}

fn read_first_block<D: scalefs_core::BlockDevice>(device: &D) -> Result<Vec<u8>, String> {
    let len = device.len().min(4096);
    let mut bytes = vec![0u8; len as usize];
    device
        .read_at(0, &mut bytes)
        .map_err(|err| err.to_string())?;
    Ok(bytes)
}

fn pool_replace(args: &[String]) -> Result<(), String> {
    let opts = Opts::parse(args, &["force"], &["size", "zone-size", "block-size"])?;
    let [images, new_image] = opts.positional.as_slice() else {
        return Err(
            "usage: scalefs pool replace <surviving-image[,image...]> <new-image> \
             --size <bytes> [--zone-size <bytes>] [--block-size <bytes>] [--force]"
                .to_string(),
        );
    };
    refuse_accidental_overwrite(new_image, opts.flag("force"))?;
    let size = parse_size(opts.value("size").ok_or("--size is required")?)?;
    let block_size = match opts.value("block-size") {
        Some(text) => u32::try_from(parse_size(text)?).map_err(|_| "block size too large")?,
        None => 4096,
    };
    let zone_size = match opts.value("zone-size") {
        Some(text) => parse_size(text)?,
        None => default_zone_size(size),
    };
    let zone_count = size / zone_size;
    if zone_count < 3 {
        return Err(format!(
            "{new_image}: size {} gives only {zone_count} zones of {}",
            format_size(size),
            format_size(zone_size),
        ));
    }
    let geometry = Geometry {
        logical_block_size: block_size,
        physical_block_size: block_size,
        zone_size,
        zone_count,
        erase_granularity_zones: 1,
        sequential_write_required: false,
    };

    let mut devices = Vec::new();
    for image in images.split(',') {
        devices.push(
            AnyBlockDevice::open(Path::new(image))
                .map_err(|err| format!("cannot open {image}: {err}"))?,
        );
    }
    let mut pool = Pool::open_multi_degraded(devices).map_err(|err| format!("{images}: {err}"))?;
    let missing = pool.missing_members();
    let Some(member) = missing.first().copied() else {
        return Err("no members are missing; use 'pool add' to grow the pool".to_string());
    };

    let mut device_id = [0u8; 16];
    fill_random(&mut device_id)?;
    let device = create_member(
        new_image,
        geometry.capacity_bytes(),
        geometry.logical_block_size,
    )?;
    pool.replace_member(
        member,
        MemberSpec {
            device,
            device_id: DeviceId(device_id),
            geometry,
        },
        now_ns(),
    )
    .map_err(|err| format!("cannot replace member {member}: {err}"))?;
    if pool.is_degraded() {
        println!(
            "replaced member {member} with {new_image}; still missing member(s) {:?} — \
             replace them, then run 'pool rebuild'",
            pool.missing_members(),
        );
        return Ok(());
    }
    println!("replaced member {member} with {new_image}; rebuilding mirrors ...");
    let report = pool
        .rebuild(now_ns())
        .map_err(|err| format!("rebuild failed (rerun 'pool rebuild'): {err}"))?;
    println!(
        "rebuilt {} record(s) ({} new cop(ies)), {} snapshot(s) rewritten (transaction {})",
        report.records_rebuilt, report.copies_written, report.snapshots_rewritten, report.tx_id,
    );
    Ok(())
}

fn pool_rebuild(args: &[String]) -> Result<(), String> {
    let [images] = args else {
        return Err("usage: scalefs pool rebuild <image[,image...]>".to_string());
    };
    let mut pool = open_pool(images)?;
    let report = pool
        .rebuild(now_ns())
        .map_err(|err| format!("{images}: {err}"))?;
    println!(
        "rebuilt {} record(s) ({} new cop(ies)), {} snapshot(s) rewritten (transaction {})",
        report.records_rebuilt, report.copies_written, report.snapshots_rewritten, report.tx_id,
    );
    Ok(())
}

fn pool_add(args: &[String]) -> Result<(), String> {
    let opts = Opts::parse(args, &["force"], &["size", "zone-size", "block-size"])?;
    let [images, new_image] = opts.positional.as_slice() else {
        return Err(
            "usage: scalefs pool add <image[,image...]> <new-image> --size <bytes> \
             [--zone-size <bytes>] [--block-size <bytes>] [--force]"
                .to_string(),
        );
    };
    refuse_accidental_overwrite(new_image, opts.flag("force"))?;
    let size = parse_size(opts.value("size").ok_or("--size is required")?)?;
    let block_size = match opts.value("block-size") {
        Some(text) => u32::try_from(parse_size(text)?).map_err(|_| "block size too large")?,
        None => 4096,
    };
    let zone_size = match opts.value("zone-size") {
        Some(text) => parse_size(text)?,
        None => default_zone_size(size),
    };
    let zone_count = size / zone_size;
    if zone_count < 3 {
        return Err(format!(
            "{new_image}: size {} gives only {zone_count} zones of {}",
            format_size(size),
            format_size(zone_size),
        ));
    }
    let geometry = Geometry {
        logical_block_size: block_size,
        physical_block_size: block_size,
        zone_size,
        zone_count,
        erase_granularity_zones: 1,
        sequential_write_required: false,
    };

    let mut pool = open_pool(images)?;
    let mut device_id = [0u8; 16];
    fill_random(&mut device_id)?;
    let device = create_member(
        new_image,
        geometry.capacity_bytes(),
        geometry.logical_block_size,
    )?;
    let member = pool
        .add_member(
            MemberSpec {
                device,
                device_id: DeviceId(device_id),
                geometry,
            },
            now_ns(),
        )
        .map_err(|err| format!("cannot grow the pool: {err}"))?;
    println!(
        "added {new_image} as member {member}: pool is now {} member(s), {} added",
        pool.member_count(),
        format_size(geometry.capacity_bytes()),
    );
    Ok(())
}

fn pool_reclaim(args: &[String]) -> Result<(), String> {
    let [images] = args else {
        return Err("usage: scalefs pool reclaim <image[,image...]>".to_string());
    };
    let mut pool = open_pool(images)?;
    let report = pool
        .reclaim(now_ns())
        .map_err(|err| format!("{images}: {err}"))?;
    if report.zones_reset == 0 {
        println!("nothing to reclaim (transaction {})", report.tx_id);
    } else {
        println!(
            "reclaimed {} in {} zone(s) across {} stripe(s) (transaction {})",
            format_size(report.bytes_reclaimed),
            report.zones_reset,
            report.stripes_reset,
            report.tx_id,
        );
    }
    Ok(())
}

fn default_zone_size(size: u64) -> u64 {
    let target = (size / 64).max(1);
    let mut zone = 1u64 << (63 - target.leading_zeros());
    zone = zone.clamp(64 << 10, 256 << 20);
    zone
}

fn pool_create(args: &[String]) -> Result<(), String> {
    let opts = Opts::parse(
        args,
        &["case-sensitive", "force"],
        &[
            "size",
            "label",
            "zone-size",
            "block-size",
            "mirror",
            "parity",
            "data",
        ],
    )?;
    let [images] = opts.positional.as_slice() else {
        return Err(
            "usage: scalefs pool create <image[,image...]> --size <bytes[,bytes...]> \
             [--label <name>] [--zone-size <bytes>] [--block-size <bytes>] \
             [--mirror <m>] [--parity <p> [--data <k>]] [--case-sensitive] [--force]"
                .to_string(),
        );
    };
    let images: Vec<&str> = images.split(',').collect();
    for image in &images {
        refuse_accidental_overwrite(image, opts.flag("force"))?;
    }
    if !opts.flag("force") {
        for (i, a) in images.iter().enumerate() {
            for b in &images[i + 1..] {
                if scalefs_core::same_spindle(Path::new(a), Path::new(b)) {
                    return Err(format!(
                        "{a} and {b} live on the same physical disk: one spindle is one \
                         failure domain, so two members there protect nothing (the engine \
                         already spreads work across a dual-actuator drive's heads within \
                         one member; use --force if you really mean it)"
                    ));
                }
            }
        }
    }
    let sizes: Vec<u64> = opts
        .value("size")
        .ok_or("--size is required")?
        .split(',')
        .map(parse_size)
        .collect::<Result<_, _>>()?;
    let sizes: Vec<u64> = match sizes.len() {
        1 => vec![sizes[0]; images.len()],
        n if n == images.len() => sizes,
        _ => return Err("--size needs one value, or one per image".to_string()),
    };
    let block_size = match opts.value("block-size") {
        Some(text) => u32::try_from(parse_size(text)?).map_err(|_| "block size too large")?,
        None => 4096,
    };

    let mut geometries = Vec::with_capacity(images.len());
    for (image, &size) in images.iter().zip(&sizes) {
        let zone_size = match opts.value("zone-size") {
            Some(text) => parse_size(text)?,
            None => default_zone_size(size),
        };
        let zone_count = size / zone_size;
        if zone_count < 3 {
            return Err(format!(
                "{image}: size {} gives only {zone_count} zones of {}; \
                 use a larger --size or smaller --zone-size",
                format_size(size),
                format_size(zone_size),
            ));
        }
        geometries.push(Geometry {
            logical_block_size: block_size,
            physical_block_size: block_size,
            zone_size,
            zone_count,
            erase_granularity_zones: 1,
            sequential_write_required: false,
        });
    }

    let parity_width: u16 = match opts.value("parity") {
        Some(text) => {
            let parity: u16 = text
                .parse()
                .map_err(|_| format!("invalid --parity '{text}'"))?;
            if !(1..=3).contains(&parity) {
                return Err("--parity takes 1, 2, or 3".to_string());
            }
            if images.len() <= usize::from(parity) {
                return Err(format!(
                    "--parity {parity} needs at least {} members",
                    parity + 1
                ));
            }
            parity
        }
        None => 0,
    };
    let data_width: u16 = match opts.value("data") {
        Some(text) => {
            if parity_width == 0 {
                return Err("--data needs --parity".to_string());
            }
            let data: u16 = text
                .parse()
                .map_err(|_| format!("invalid --data '{text}'"))?;
            if !(2..=64).contains(&data) {
                return Err("--data takes 2 through 64".to_string());
            }
            data
        }
        None if parity_width > 0 => (images.len() as u16)
            .saturating_sub(parity_width)
            .clamp(2, 8),
        None => 1,
    };
    let mut pool_id = [0u8; 16];
    let mut seed = [0u8; 8];
    fill_random(&mut pool_id)?;
    fill_random(&mut seed)?;
    let params = PoolParams {
        pool_id: PoolId(pool_id),
        case_sensitivity: if opts.flag("case-sensitive") {
            CaseSensitivity::Sensitive
        } else {
            CaseSensitivity::InsensitivePreserving
        },
        dirent_hash_seed: u64::from_le_bytes(seed),
        label: opts.value("label").unwrap_or("").to_string(),
        created_at_ns: now_ns(),
        mirror_width: match opts.value("mirror") {
            Some(text) => text
                .parse()
                .map_err(|_| format!("invalid --mirror '{text}'"))?,
            None if parity_width > 0 => parity_width + 1,
            None => 1,
        },
        data_width,
        parity_width,
    };

    let mut members = Vec::with_capacity(images.len());
    for (image, geometry) in images.iter().zip(&geometries) {
        let mut device_id = [0u8; 16];
        fill_random(&mut device_id)?;
        let device = create_member(
            image,
            geometry.capacity_bytes(),
            geometry.logical_block_size,
        )?;
        members.push(MemberSpec {
            device,
            device_id: DeviceId(device_id),
            geometry: *geometry,
        });
    }

    let pool = if members.len() == 1 {
        let member = members.into_iter().next().expect("length checked");
        Pool::create(
            member.device,
            CreateParams {
                pool_id: params.pool_id,
                device_id: member.device_id,
                geometry: member.geometry,
                case_sensitivity: params.case_sensitivity,
                dirent_hash_seed: params.dirent_hash_seed,
                label: params.label,
                created_at_ns: params.created_at_ns,
            },
        )
    } else {
        Pool::create_multi(members, params)
    }
    .map_err(|err| format!("cannot format: {err}"))?;

    let total: u64 = geometries.iter().map(|g| g.capacity_bytes()).sum();
    if pool.member_count() == 1 {
        println!(
            "created pool '{}' on {}: {} in {} zones of {}",
            pool.superblock().label,
            images[0],
            format_size(total),
            geometries[0].zone_count,
            format_size(geometries[0].zone_size),
        );
    } else {
        println!(
            "created pool '{}' across {} members: {} total",
            pool.superblock().label,
            pool.member_count(),
            format_size(total),
        );
        for (index, (image, geometry)) in images.iter().zip(&geometries).enumerate() {
            println!(
                "  [{index}] {image}: {} in {} zones of {}",
                format_size(geometry.capacity_bytes()),
                geometry.zone_count,
                format_size(geometry.zone_size),
            );
        }
    }
    Ok(())
}

static DEGRADED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn set_degraded() {
    DEGRADED.store(true, std::sync::atomic::Ordering::Relaxed);
}

fn degraded() -> bool {
    DEGRADED.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn open_pool(images: &str) -> Result<Pool<AnyBlockDevice>, String> {
    let paths: Vec<String> = images.split(',').map(str::to_string).collect();
    open_pool_paths(&paths)
}

pub fn open_pool_paths(paths: &[String]) -> Result<Pool<AnyBlockDevice>, String> {
    let mut devices = Vec::new();
    for path in paths {
        devices.push(
            AnyBlockDevice::open(Path::new(path))
                .map_err(|err| format!("cannot open {path}: {err}"))?,
        );
    }
    let result = if degraded() {
        Pool::open_multi_degraded(devices)
    } else {
        Pool::open_multi(devices)
    };
    result.map_err(|err| format!("{}: {err}", paths.join(",")))
}

fn pool_status(args: &[String]) -> Result<(), String> {
    let [images] = args else {
        return Err("usage: scalefs pool status <image[,image...]>".to_string());
    };
    let paths: Vec<String> = images.split(',').map(str::to_string).collect();
    let serials = probe_serials(&paths);
    let pool = open_pool_paths(&paths)?;
    print_pool_status(&pool, &serials)
}

fn estimated_usable_bytes(pool: &Pool<AnyBlockDevice>) -> u64 {
    let data_width = usize::from(pool.data_width()).max(1);
    let parity_width = usize::from(pool.parity_width());
    let mut remaining: Vec<(u64, u64)> = pool
        .allocators()
        .iter()
        .map(|allocator| {
            let zones = allocator
                .free_usable_zone_count()
                .saturating_sub(allocator.reserve_zone_count());
            (
                zones * allocator.geometry().zone_size,
                allocator.geometry().zone_size,
            )
        })
        .collect();
    let mut usable = 0u64;
    loop {
        remaining.sort_by_key(|&(bytes, _)| std::cmp::Reverse(bytes));
        let with_space = remaining.iter().filter(|&&(bytes, _)| bytes > 0).count();
        if with_space < parity_width + 1 {
            break;
        }
        let width = (with_space - parity_width).min(data_width);
        for (index, (bytes, quantum)) in remaining.iter_mut().enumerate() {
            if index >= width + parity_width {
                break;
            }
            let step = (*quantum).min(*bytes);
            *bytes -= step;
            if index < width {
                usable += step;
            }
        }
    }
    usable
}

fn print_pool_status(
    pool: &Pool<AnyBlockDevice>,
    serials: &BTreeMap<String, String>,
) -> Result<(), String> {
    let superblock = pool.superblock();

    let per_member: Vec<(u64, u64, u64)> = pool
        .allocators()
        .iter()
        .map(|allocator| {
            let mut free_zones = 0u64;
            let mut used_bytes = 0u64;
            for zone in allocator.zones() {
                if zone.class.is_none() && allocator.is_usable_zone(zone.zone_index) {
                    free_zones += 1;
                }
                used_bytes += zone.write_pointer;
            }
            (
                allocator.geometry().capacity_bytes(),
                free_zones,
                used_bytes,
            )
        })
        .collect();
    let capacity: u64 = per_member.iter().map(|(c, _, _)| c).sum();
    let used_bytes: u64 = per_member.iter().map(|(_, _, u)| u).sum();

    println!("Label:        {}", superblock.label);
    println!("Pool id:      {}", hex(&superblock.pool_id.0));
    if pool.member_count() == 1 {
        println!("Device id:    {}", hex(&superblock.device_id.0));
        if let Some(serial) = serials.get(&hex(&superblock.device_id.0)) {
            println!("Serial:       {serial}");
        }
    }
    println!("Created:      {}", format_time(superblock.created_at_ns));
    println!("Transaction:  {}", pool.committed_tx());
    println!(
        "Mode:         {}",
        if pool.read_only() {
            "read-only"
        } else {
            "read-write"
        }
    );
    println!(
        "Names:        {}",
        match superblock.case_sensitivity {
            CaseSensitivity::Sensitive => "case-sensitive",
            CaseSensitivity::InsensitivePreserving => "case-insensitive (preserving)",
        }
    );
    if pool.parity_width() > 0 {
        println!(
            "Protection:   {} data + {} parity (RS) · metadata {}-way mirror",
            pool.data_width(),
            pool.parity_width(),
            pool.mirror_width(),
        );
        println!(
            "Usable (est.): {} of free space for file data after parity",
            format_size(estimated_usable_bytes(pool)),
        );
    } else if pool.mirror_width() > 1 {
        println!("Protection:   {}-way mirror", pool.mirror_width());
    }
    if pool.is_degraded() {
        println!(
            "State:        DEGRADED — {} member(s) missing",
            pool.missing_members().len()
        );
    }
    if !pool.orphaned_members().is_empty() {
        println!(
            "Orphans:      {} supplied device(s) not in the pool's current membership",
            pool.orphaned_members().len()
        );
    }
    println!("Capacity:     {}", format_size(capacity));
    if pool.member_count() == 1 {
        let geometry = superblock.geometry;
        let allocator = pool.allocator();
        println!(
            "Zones:        {} of {} ({} free of {} usable)",
            format_size(geometry.zone_size),
            geometry.zone_count,
            per_member[0].1,
            (0..geometry.zone_count)
                .filter(|&z| allocator.is_usable_zone(z))
                .count(),
        );
    } else {
        println!("Members:      {}", pool.member_count());
        let mut slot = 0usize;
        for index in 0..pool.member_count() {
            match pool.superblock_for_member(index as u16) {
                Some(member) => {
                    let serial = serials
                        .get(&hex(&member.device_id.0))
                        .map(|serial| format!("  serial {serial}"))
                        .unwrap_or_default();
                    let actuators = pool
                        .allocator_for_member(index as u16)
                        .map(|allocator| allocator.actuator_range_count())
                        .filter(|&count| count >= 2)
                        .map(|count| format!("  {count} actuators"))
                        .unwrap_or_default();
                    println!(
                        "  [{index}] {}  {} ({} free zones){serial}{actuators}",
                        hex(&member.device_id.0),
                        format_size(per_member[slot].0),
                        per_member[slot].1,
                    );
                    slot += 1;
                }
                None => println!("  [{index}] MISSING"),
            }
        }
    }
    println!("Written:      {}", format_size(used_bytes));
    Ok(())
}

fn pool_inspect(args: &[String]) -> Result<(), String> {
    let [images] = args else {
        return Err("usage: scalefs pool inspect <image[,image...]>".to_string());
    };
    let pool = open_pool(images)?;

    for (index, superblock) in pool.superblocks().iter().enumerate() {
        if pool.member_count() == 1 {
            println!("Superblock:");
        } else {
            println!("Member {index}:");
        }
        println!("  label            {}", superblock.label);
        println!("  pool id          {}", hex(&superblock.pool_id.0));
        println!("  device id        {}", hex(&superblock.device_id.0));
        println!("  topology gen     {}", superblock.topology_generation);
        println!(
            "  features         compat={:#x} ro-compat={:#x} incompat={:#x}",
            superblock.feature_compat, superblock.feature_ro_compat, superblock.feature_incompat,
        );
        println!(
            "  geometry         block {} / zone {} x {} / erase {} zone(s){}",
            format_size(u64::from(superblock.geometry.logical_block_size)),
            format_size(superblock.geometry.zone_size),
            superblock.geometry.zone_count,
            superblock.geometry.erase_granularity_zones,
            if superblock.geometry.sequential_write_required {
                " / sequential"
            } else {
                ""
            },
        );
    }
    println!("  newest tx        {}", pool.committed_tx());
    println!("  metadata items   {}", pool.tree().item_count());

    for (index, allocator) in pool.allocators().iter().enumerate() {
        if pool.member_count() == 1 {
            println!("Zones:");
        } else {
            println!("Zones (member {index}):");
        }
        let mut shown = 0;
        for zone in allocator.zones() {
            let describe = match zone.class {
                None => continue,
                Some(ZoneClass::Metadata) => "metadata",
                Some(ZoneClass::Data) => "data",
                Some(ZoneClass::Parity) => "parity",
            };
            println!(
                "  zone {:>4}  {describe:<8} {:<6}  wp {:>10}  erases {}",
                zone.zone_index,
                if zone.open { "open" } else { "closed" },
                format_size(zone.write_pointer),
                zone.erase_count,
            );
            shown += 1;
            if shown >= 64 {
                println!("  ... (remaining zones elided)");
                break;
            }
        }
        if shown == 0 {
            println!("  (no allocated zones)");
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn cmd_scrub(args: &[String]) -> Result<bool, String> {
    let opts = Opts::parse(args, &["repair"], &[])?;
    let [images] = opts.positional.as_slice() else {
        return Err("usage: scalefs scrub <image[,image...]> [--repair]".to_string());
    };
    let mut pool = open_pool(images)?;
    let report = pool
        .scrub(opts.flag("repair"))
        .map_err(|err| format!("{images}: {err}"))?;
    println!(
        "checked {} record(s), {} cop(ies): {} bad, {} repaired, {} unrepairable{}",
        report.records_checked,
        report.copies_checked,
        report.copies_bad,
        report.copies_repaired,
        report.copies_unrepairable,
        if report.copies_missing > 0 {
            format!(", {} on absent members", report.copies_missing)
        } else {
            String::new()
        },
    );
    if report.healthy() {
        println!("{images}: healthy");
    } else if !opts.flag("repair") && report.copies_unrepairable == 0 {
        println!("{images}: damaged copies found — run with --repair to heal them");
    } else {
        eprintln!(
            "{images}: {} cop(ies) beyond repair",
            report.copies_unrepairable
        );
    }
    Ok(report.healthy())
}

fn known_type(attrs: &InodeAttrs) -> bool {
    matches!(
        attrs.mode & MODE_TYPE_MASK,
        MODE_DIRECTORY
            | MODE_FILE
            | MODE_SYMLINK
            | MODE_FIFO
            | MODE_SOCKET
            | MODE_CHAR_DEVICE
            | MODE_BLOCK_DEVICE
    )
}

fn kind_name(attrs: &InodeAttrs) -> &'static str {
    match attrs.mode & MODE_TYPE_MASK {
        MODE_DIRECTORY => "directory",
        MODE_FILE => "file",
        MODE_SYMLINK => "symlink",
        MODE_FIFO => "fifo",
        MODE_SOCKET => "socket",
        MODE_CHAR_DEVICE | MODE_BLOCK_DEVICE => "device node",
        _ => "inode",
    }
}

fn check_zone_placement(
    pool: &Pool<AnyBlockDevice>,
    problems: &mut Vec<String>,
    owner: u64,
    offset: u64,
    extent: &Extent,
    class: ZoneClass,
) {
    let member = usize::from(extent.device_index);
    let Some(allocator) = pool.allocator_for_member(extent.device_index) else {
        if !pool.is_degraded() || member >= pool.member_count() {
            problems.push(format!(
                "inode {owner}: extent at {offset} names absent member {member}"
            ));
        }
        return;
    };
    let geometry = allocator.geometry();
    let zone_index = extent.offset / geometry.zone_size;
    let class_name = match class {
        ZoneClass::Metadata => "metadata",
        ZoneClass::Data => "data",
        ZoneClass::Parity => "parity",
    };
    match allocator.zone(zone_index) {
        Some(zone) if zone.class == Some(class) => {
            let zone_start = zone_index * geometry.zone_size;
            if extent.offset + extent.length > zone_start + zone.write_pointer {
                problems.push(format!(
                    "inode {owner}: extent at {offset} lies past member {member} \
                     zone {zone_index}'s write pointer"
                ));
            }
        }
        _ => problems.push(format!(
            "inode {owner}: extent at {offset} is not in a {class_name} zone"
        )),
    }
}

fn stripe_math_problem(pool: &Pool<AnyBlockDevice>, parity_extents: &[Extent]) -> Option<String> {
    let records: Vec<Option<ParityRecord>> = parity_extents
        .iter()
        .enumerate()
        .map(|(row, extent)| {
            pool.read_extent(*extent)
                .ok()
                .and_then(|bytes| decode_parity_record(&bytes).ok())
                .filter(|record| usize::from(record.parity_index) == row)
        })
        .collect();
    let descriptor = records.iter().flatten().next()?;
    let coverage = usize::try_from(descriptor.coverage_len).ok()?;
    let mut pieces: Vec<Vec<u8>> = Vec::with_capacity(descriptor.data_pieces.len());
    for piece in &descriptor.data_pieces {
        let Ok(bytes) = pool.read_extent(*piece) else {
            if pool.is_degraded() {
                return None;
            }
            return Some(format!(
                "stripe with parity at member {} offset {}: descriptor-named data piece at \
                 member {} offset {} is unreadable (reconstruction margin spent; scrub heals it)",
                parity_extents[0].device_index,
                parity_extents[0].offset,
                piece.device_index,
                piece.offset
            ));
        };
        if decode_file_data(&bytes).is_err() {
            return Some(format!(
                "stripe with parity at member {} offset {}: descriptor-named data piece at \
                 member {} offset {} fails verification",
                parity_extents[0].device_index,
                parity_extents[0].offset,
                piece.device_index,
                piece.offset
            ));
        }
        pieces.push(bytes);
    }
    let refs: Vec<&[u8]> = pieces.iter().map(Vec::as_slice).collect();
    let rows = generate_parity(&refs, parity_extents.len(), coverage).ok()?;
    for (row, record) in records.iter().enumerate() {
        if let Some(record) = record
            && record.parity != rows[row]
        {
            return Some(format!(
                "stripe with parity at member {} offset {}: parity row {row} \
                 disagrees with the data",
                parity_extents[row].device_index, parity_extents[row].offset
            ));
        }
    }
    None
}

pub fn cmd_fsck(args: &[String]) -> Result<bool, String> {
    let [image] = args else {
        return Err("usage: scalefs fsck <image[,image...]>".to_string());
    };
    let pool = open_pool(image)?;
    let (inode_count, problems) = fsck_problems(&pool);
    if problems.is_empty() {
        println!(
            "{image}: clean ({inode_count} inode(s), {} snapshot(s), transaction {})",
            pool.snapshot_list().len(),
            pool.committed_tx()
        );
        Ok(true)
    } else {
        for problem in &problems {
            eprintln!("{image}: {problem}");
        }
        eprintln!("{image}: {} problem(s) found", problems.len());
        Ok(false)
    }
}

fn fsck_problems(pool: &Pool<AnyBlockDevice>) -> (usize, Vec<String>) {
    let mut problems: Vec<String> = Vec::new();

    let all = pool.tree().range(MetadataKey::MIN, MetadataKey::MAX);
    let mut inodes: Vec<(u64, InodeAttrs)> = Vec::new();
    let mut specials: Vec<(u64, usize)> = Vec::new();
    let mut next_object_id = None;
    for (key, value) in &all {
        match (key.item_type, value) {
            (ITEM_POOL_STATE, MetadataValue::PoolState { next_object_id: n }) => {
                next_object_id = Some(*n);
            }
            (ITEM_INODE, MetadataValue::Inode(attrs)) => inodes.push((key.object_id, *attrs)),
            (ITEM_SPECIAL, MetadataValue::Special { data }) => {
                specials.push((key.object_id, data.len()));
            }
            _ => {}
        }
    }
    let inode = |id: u64| inodes.iter().find(|(i, _)| *i == id).map(|(_, a)| *a);

    match inode(ROOT_INODE) {
        None => problems.push("root directory inode is missing".to_string()),
        Some(attrs) if !attrs.is_dir() => {
            problems.push("root inode is not a directory".to_string());
        }
        _ => {}
    }
    match next_object_id {
        None => problems.push("pool state item is missing".to_string()),
        Some(next) => {
            if let Some((id, _)) = inodes.iter().find(|(id, _)| *id >= next) {
                problems.push(format!(
                    "inode {id} is at or above the next object id {next}"
                ));
            }
        }
    }

    let mut references: std::collections::HashMap<u64, u32> = std::collections::HashMap::new();
    for (key, value) in &all {
        if key.item_type != ITEM_DIRENT {
            continue;
        }
        let MetadataValue::DirEntries(entries) = value else {
            continue;
        };
        for entry in entries {
            match inode(entry.inode) {
                None => problems.push(format!(
                    "entry '{}' in directory {} references missing inode {}",
                    entry.name, key.object_id, entry.inode
                )),
                Some(attrs) => {
                    let known_mode = known_type(&attrs);
                    let known_entry = !matches!(entry.kind, EntryKind::Unknown(_));
                    if known_mode && known_entry && attrs.entry_kind() != entry.kind {
                        problems.push(format!(
                            "entry '{}' in directory {} disagrees with inode {} about its kind",
                            entry.name, key.object_id, entry.inode
                        ));
                    }
                }
            }
            *references.entry(entry.inode).or_insert(0) += 1;
        }
    }
    for (id, attrs) in &inodes {
        let count = references.get(id).copied().unwrap_or(0) + u32::from(*id == ROOT_INODE);
        if count == 0 {
            problems.push(format!("inode {id} is unreachable from any directory"));
            continue;
        }
        if attrs.is_dir() {
            if count != 1 {
                problems.push(format!("directory {id} is referenced by {count} entries"));
            }
        } else if count != attrs.nlink {
            problems.push(format!(
                "inode {id} is referenced by {count} entr(ies) but its link count says {}",
                attrs.nlink
            ));
        }
    }

    for (owner, data_len) in &specials {
        match inode(*owner) {
            None => problems.push(format!("special item belongs to missing inode {owner}")),
            Some(attrs) if attrs.is_symlink() => {
                if *data_len == 0 {
                    problems.push(format!("symlink {owner} has an empty target"));
                }
            }
            Some(attrs) if attrs.is_device() => {
                if *data_len != 8 {
                    problems.push(format!(
                        "device node {owner} stores {data_len} bytes where its \
                         8-byte device number belongs"
                    ));
                }
            }
            Some(attrs) => {
                if known_type(&attrs) {
                    problems.push(format!(
                        "{} {owner} carries a special item it must not have",
                        kind_name(&attrs)
                    ));
                }
            }
        }
    }
    for (id, attrs) in &inodes {
        if (attrs.is_symlink() || attrs.is_device())
            && !specials.iter().any(|(owner, _)| owner == id)
        {
            problems.push(format!(
                "{} {id} is missing its special item",
                kind_name(attrs)
            ));
        }
    }

    let xattr_seed = pool.superblock().dirent_hash_seed;
    for (key, value) in &all {
        if key.item_type != ITEM_XATTR {
            continue;
        }
        let MetadataValue::XattrEntries(entries) = value else {
            problems.push(format!(
                "non-bucket value at an xattr key of inode {}",
                key.object_id
            ));
            continue;
        };
        if inode(key.object_id).is_none() {
            problems.push(format!(
                "xattr bucket belongs to missing inode {}",
                key.object_id
            ));
        }
        for entry in entries {
            if scalefs_core::dirent::dirent_hash(xattr_seed, &entry.name) != key.offset {
                problems.push(format!(
                    "xattr '{}' of inode {} sits in the wrong hash slot",
                    entry.name, key.object_id
                ));
            }
        }
    }

    let parity_pool = pool.superblock().feature_incompat & FEATURE_INCOMPAT_PARITY != 0;
    if parity_pool != (pool.parity_width() > 0) {
        problems.push(format!(
            "the parity feature bit ({}) disagrees with the roster's parity width ({})",
            parity_pool,
            pool.parity_width(),
        ));
    }
    if !parity_pool {
        for (slot, allocator) in pool.allocators().iter().enumerate() {
            if allocator
                .zones()
                .any(|zone| zone.class == Some(ZoneClass::Parity))
            {
                problems.push(format!(
                    "member slot {slot} has parity zones on a pool without the parity feature"
                ));
            }
        }
    }

    let mut verified_stripes: std::collections::HashSet<(u16, u64)> =
        std::collections::HashSet::new();
    for (key, value) in &all {
        if key.item_type != ITEM_FILE_EXTENT {
            continue;
        }
        let MetadataValue::StripedExtent {
            extent,
            parity_extents,
            data_offset,
            logical_len,
        } = value
        else {
            continue;
        };
        let owner = key.object_id;
        if !parity_pool {
            problems.push(format!(
                "inode {owner}: striped extent at {} on a pool without the parity feature",
                key.offset
            ));
        }
        match inode(owner) {
            None => {
                problems.push(format!(
                    "striped extent at {} belongs to missing inode {owner}",
                    key.offset
                ));
                continue;
            }
            Some(attrs) if known_type(&attrs) && attrs.entry_kind() != EntryKind::File => {
                problems.push(format!("{} {owner} has file extents", kind_name(&attrs)));
                continue;
            }
            Some(attrs) => {
                if key.offset + logical_len > attrs.size {
                    problems.push(format!(
                        "inode {owner}: extent at {} runs past the file size",
                        key.offset
                    ));
                }
                if *logical_len > scalefs_core::fs::FILE_DATA_CHUNK as u64 {
                    problems.push(format!(
                        "inode {owner}: extent at {} runs longer than one data chunk — \
                         the bounded extent lookup would miss it silently",
                        key.offset
                    ));
                }
            }
        }
        check_zone_placement(
            pool,
            &mut problems,
            owner,
            key.offset,
            extent,
            ZoneClass::Data,
        );
        if pool.allocator_for_member(extent.device_index).is_some() {
            match pool
                .read_extent(*extent)
                .and_then(|bytes| decode_file_data(&bytes))
            {
                Ok(payload) => {
                    if data_offset + logical_len > payload.len() as u64 {
                        problems.push(format!(
                            "inode {owner}: extent at {} references bytes outside its record",
                            key.offset
                        ));
                    }
                }
                Err(err) => problems.push(format!(
                    "inode {owner}: stripe piece on member {} at {} fails verification: {err}",
                    extent.device_index, key.offset
                )),
            }
        }
        for (row, parity) in parity_extents.iter().enumerate() {
            check_zone_placement(
                pool,
                &mut problems,
                owner,
                key.offset,
                parity,
                ZoneClass::Parity,
            );
            if pool.allocator_for_member(parity.device_index).is_none() {
                continue;
            }
            match pool
                .read_extent(*parity)
                .and_then(|bytes| decode_parity_record(&bytes))
            {
                Ok(record) => {
                    if usize::from(record.parity_index) != row {
                        problems.push(format!(
                            "inode {owner}: parity record at {} holds row {} where row {row} belongs",
                            key.offset, record.parity_index
                        ));
                    }
                    if !record.data_pieces.contains(extent) {
                        problems.push(format!(
                            "inode {owner}: stripe descriptor at {} does not name the piece",
                            key.offset
                        ));
                    }
                    if record.parity_pieces != *parity_extents {
                        problems.push(format!(
                            "inode {owner}: stripe descriptor at {} disagrees with the \
                             reference's parity list",
                            key.offset
                        ));
                    }
                }
                Err(err) => problems.push(format!(
                    "inode {owner}: parity record on member {} at {} fails verification: {err}",
                    parity.device_index, key.offset
                )),
            }
        }
        if let Some(first) = parity_extents.first()
            && verified_stripes.insert((first.device_index, first.offset))
            && let Some(problem) = stripe_math_problem(pool, parity_extents)
        {
            problems.push(problem);
        }
    }

    for (key, value) in &all {
        if key.item_type != ITEM_FILE_EXTENT {
            continue;
        }
        let MetadataValue::FileExtent {
            extents,
            data_offset,
            logical_len,
        } = value
        else {
            continue;
        };
        let owner = key.object_id;
        match inode(owner) {
            None => {
                problems.push(format!(
                    "extent at {} belongs to missing inode {owner}",
                    key.offset
                ));
                continue;
            }
            Some(attrs) if known_type(&attrs) && attrs.entry_kind() != EntryKind::File => {
                problems.push(format!("{} {owner} has file extents", kind_name(&attrs)));
                continue;
            }
            Some(attrs) => {
                if key.offset + logical_len > attrs.size {
                    problems.push(format!(
                        "inode {owner}: extent at {} runs past the file size",
                        key.offset
                    ));
                }
                if *logical_len > scalefs_core::fs::FILE_DATA_CHUNK as u64 {
                    problems.push(format!(
                        "inode {owner}: extent at {} runs longer than one data chunk — \
                         the bounded extent lookup would miss it silently",
                        key.offset
                    ));
                }
            }
        }
        for extent in extents {
            let member = usize::from(extent.device_index);
            let Some(allocator) = pool.allocator_for_member(extent.device_index) else {
                if !pool.is_degraded() || member >= pool.member_count() {
                    problems.push(format!(
                        "inode {owner}: extent at {} names absent member {member}",
                        key.offset
                    ));
                }
                continue;
            };
            let geometry = allocator.geometry();
            let zone_index = extent.offset / geometry.zone_size;
            match allocator.zone(zone_index) {
                Some(zone) if zone.class == Some(ZoneClass::Data) => {
                    let zone_start = zone_index * geometry.zone_size;
                    if extent.offset + extent.length > zone_start + zone.write_pointer {
                        problems.push(format!(
                            "inode {owner}: extent at {} lies past member {member} \
                             zone {zone_index}'s write pointer",
                            key.offset
                        ));
                    }
                }
                _ => problems.push(format!(
                    "inode {owner}: extent at {} is not in a data zone",
                    key.offset
                )),
            }
            match pool
                .read_extent(*extent)
                .and_then(|bytes| decode_file_data(&bytes))
            {
                Ok(payload) => {
                    if data_offset + logical_len > payload.len() as u64 {
                        problems.push(format!(
                            "inode {owner}: extent at {} references bytes outside its record",
                            key.offset
                        ));
                    }
                }
                Err(err) => problems.push(format!(
                    "inode {owner}: copy on member {member} at {} fails verification: {err}",
                    key.offset
                )),
            }
        }
    }

    for snapshot in pool.snapshot_list() {
        if let Err(err) = pool.snapshot_open(&snapshot.name) {
            problems.push(format!(
                "snapshot '{}' fails verification: {err}",
                snapshot.name
            ));
        }
    }

    if pool.is_multi() {
        match pool.member_rosters() {
            Err(err) => problems.push(format!("member rosters fail verification: {err}")),
            Ok(rosters) => {
                let reference: Vec<_> = rosters
                    .first()
                    .map(|roster| {
                        roster
                            .members
                            .iter()
                            .map(|member| member.device_id)
                            .collect()
                    })
                    .unwrap_or_default();
                for (index, (roster, superblock)) in
                    rosters.iter().zip(pool.superblocks()).enumerate()
                {
                    let ids: Vec<_> = roster
                        .members
                        .iter()
                        .map(|member| member.device_id)
                        .collect();
                    if ids != reference {
                        problems.push(format!(
                            "present member {index}'s roster disagrees about the member set"
                        ));
                    }
                    if !ids.contains(&superblock.device_id) {
                        problems.push(format!(
                            "present member {index} is not named by its own roster"
                        ));
                    }
                    if roster.topology_generation != superblock.topology_generation {
                        problems.push(format!(
                            "present member {index}'s roster disagrees about the \
                             configuration generation"
                        ));
                    }
                    if roster.tx_id > pool.committed_tx() {
                        problems.push(format!(
                            "present member {index}'s roster is newer than the pool's \
                             newest transaction"
                        ));
                    }
                }
            }
        }
    }

    (inodes.len(), problems)
}

#[cfg(test)]
mod tests {
    use super::*;
    use scalefs_core::AllocPurpose;
    use std::path::PathBuf;

    const NOW: i64 = 1_700_000_000_000_000_000;

    fn special_pool(tag: &str) -> (PathBuf, String, u64, u64, u64, u64) {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("scalefs-fsck-{}-{tag}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let image = dir.join("a.img");
        let geometry = Geometry {
            logical_block_size: 4096,
            physical_block_size: 4096,
            zone_size: 64 * 1024,
            zone_count: 16,
            erase_granularity_zones: 1,
            sequential_write_required: false,
        };
        let mut pool = Pool::create(
            FileBlockDevice::create(&image, geometry.capacity_bytes()).unwrap(),
            CreateParams {
                geometry,
                pool_id: PoolId([0x44; 16]),
                device_id: DeviceId([0x45; 16]),
                case_sensitivity: CaseSensitivity::InsensitivePreserving,
                dirent_hash_seed: 11,
                label: "fsck".to_string(),
                created_at_ns: NOW,
            },
        )
        .unwrap();
        let link = pool.symlink(ROOT_INODE, "ln", b"elsewhere", NOW).unwrap();
        let device = pool
            .mknod(
                ROOT_INODE,
                "null",
                MODE_CHAR_DEVICE | 0o666,
                1 | (3 << 32),
                NOW,
            )
            .unwrap();
        let fifo = pool
            .mknod(ROOT_INODE, "pipe", MODE_FIFO | 0o644, 0, NOW)
            .unwrap();
        let file = pool.create_file(ROOT_INODE, "plain", 0o644, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        drop(pool);
        (
            dir,
            image.to_string_lossy().into_owned(),
            link,
            device,
            fifo,
            file,
        )
    }

    fn corrupt(image: &str, surgery: impl FnOnce(&mut Pool<FileBlockDevice>)) {
        let mut pool = Pool::open(FileBlockDevice::open(Path::new(image)).unwrap()).unwrap();
        surgery(&mut pool);
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
    }

    fn special_key(id: u64) -> MetadataKey {
        MetadataKey {
            object_id: id,
            item_type: ITEM_SPECIAL,
            offset: 0,
        }
    }

    fn fsck(image: &str) -> bool {
        cmd_fsck(std::slice::from_ref(&image.to_string())).unwrap()
    }

    fn parity_pool(tag: &str) -> (PathBuf, String, u64) {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "scalefs-parityfsck-{}-{tag}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let geometry = Geometry {
            logical_block_size: 4096,
            physical_block_size: 4096,
            zone_size: 64 * 1024,
            zone_count: 16,
            erase_granularity_zones: 1,
            sequential_write_required: false,
        };
        let members: Vec<MemberSpec<FileBlockDevice>> = (0..3)
            .map(|i| MemberSpec {
                device: FileBlockDevice::create(
                    &dir.join(format!("{i}.img")),
                    geometry.capacity_bytes(),
                )
                .unwrap(),
                device_id: DeviceId([0x50 + i as u8; 16]),
                geometry,
            })
            .collect();
        let mut pool = Pool::create_multi(
            members,
            PoolParams {
                pool_id: PoolId([0x4F; 16]),
                case_sensitivity: CaseSensitivity::InsensitivePreserving,
                dirent_hash_seed: 12,
                label: "stripes".to_string(),
                created_at_ns: NOW,
                mirror_width: 2,
                data_width: 2,
                parity_width: 1,
            },
        )
        .unwrap();
        let file = pool.create_file(ROOT_INODE, "striped", 0o644, NOW).unwrap();
        let data: Vec<u8> = (0..70_000usize).map(|i| (i * 7 % 251) as u8).collect();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        drop(pool);
        let spec = (0..3)
            .map(|i| dir.join(format!("{i}.img")).to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(",");
        (dir, spec, file)
    }

    fn striped_runs_of(pool: &Pool<FileBlockDevice>, object: u64) -> Vec<(Extent, Vec<Extent>)> {
        pool.tree()
            .range(
                MetadataKey {
                    object_id: object,
                    item_type: ITEM_FILE_EXTENT,
                    offset: 0,
                },
                MetadataKey {
                    object_id: object,
                    item_type: ITEM_FILE_EXTENT,
                    offset: u64::MAX,
                },
            )
            .iter()
            .filter_map(|(_, value)| match value {
                MetadataValue::StripedExtent {
                    extent,
                    parity_extents,
                    ..
                } => Some((*extent, parity_extents.clone())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn fsck_verifies_stripe_parity_math() {
        let (dir, spec, file) = parity_pool("math");
        assert!(fsck(&spec), "a healthy parity pool must be clean");

        let members: Vec<FileBlockDevice> = spec
            .split(',')
            .map(|path| FileBlockDevice::open(Path::new(path)).unwrap())
            .collect();
        let pool = Pool::open_multi(members).unwrap();
        let runs = striped_runs_of(&pool, file);
        let parity_extent = runs[0].1[0];
        let mut record =
            scalefs_core::decode_parity_record(&pool.read_extent(parity_extent).unwrap()).unwrap();
        record.parity[3] ^= 0x5A;
        let forged = scalefs_core::encode_parity_record(&record).unwrap();
        drop(pool);
        let image = dir.join(format!("{}.img", parity_extent.device_index));
        let file_handle = std::fs::OpenOptions::new()
            .write(true)
            .open(&image)
            .unwrap();
        use std::io::{Seek, SeekFrom, Write};
        let mut file_handle = file_handle;
        file_handle
            .seek(SeekFrom::Start(parity_extent.offset))
            .unwrap();
        file_handle.write_all(&forged).unwrap();
        drop(file_handle);

        assert!(!fsck(&spec), "inconsistent parity must be flagged");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn fsck_accepts_a_degraded_parity_pool() {
        let (dir, spec, _file) = parity_pool("degraded");
        let paths: Vec<String> = spec.split(',').map(str::to_string).collect();
        for withheld in 0..paths.len() {
            let members: Vec<AnyBlockDevice> = paths
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != withheld)
                .map(|(_, path)| AnyBlockDevice::open(Path::new(path)).unwrap())
                .collect();
            let pool = Pool::open_multi_degraded(members).unwrap();
            let (_, problems) = fsck_problems(&pool);
            assert!(
                problems.is_empty(),
                "degraded fsck with member {withheld} absent must be clean: {problems:?}"
            );
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    fn hardlink_pool(tag: &str) -> (PathBuf, String, u64, u64) {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("scalefs-hlfsck-{}-{tag}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let image = dir.join("a.img");
        let geometry = Geometry {
            logical_block_size: 4096,
            physical_block_size: 4096,
            zone_size: 64 * 1024,
            zone_count: 16,
            erase_granularity_zones: 1,
            sequential_write_required: false,
        };
        let mut pool = Pool::create(
            FileBlockDevice::create(&image, geometry.capacity_bytes()).unwrap(),
            CreateParams {
                geometry,
                pool_id: PoolId([0x46; 16]),
                device_id: DeviceId([0x47; 16]),
                case_sensitivity: CaseSensitivity::InsensitivePreserving,
                dirent_hash_seed: 13,
                label: "links".to_string(),
                created_at_ns: NOW,
            },
        )
        .unwrap();
        let file = pool.create_file(ROOT_INODE, "plain", 0o644, NOW).unwrap();
        pool.write(file, 0, b"shared bytes", NOW).unwrap();
        pool.link(file, ROOT_INODE, "extra", NOW).unwrap();
        let subdir = pool.mkdir(ROOT_INODE, "d", 0o755, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        drop(pool);
        (dir, image.to_string_lossy().into_owned(), file, subdir)
    }

    #[test]
    fn fsck_accepts_hard_links() {
        let (dir, image, _, _) = hardlink_pool("clean");
        assert!(fsck(&image), "a healthy hard-linked pool must be clean");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn fsck_flags_a_link_count_disagreeing_with_the_entries() {
        let (dir, image, file, _) = hardlink_pool("mismatch");
        corrupt(&image, |pool| {
            let mut attrs = pool.getattr(file).unwrap();
            attrs.nlink = 3;
            pool.tree_mut()
                .insert(
                    MetadataKey {
                        object_id: file,
                        item_type: ITEM_INODE,
                        offset: 0,
                    },
                    MetadataValue::Inode(attrs),
                )
                .unwrap();
        });
        assert!(!fsck(&image), "count 2 vs stored 3 must be flagged");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn fsck_flags_a_multiply_referenced_directory() {
        let (dir, image, _, subdir) = hardlink_pool("dirref");
        corrupt(&image, |pool| {
            let seed = pool.superblock().dirent_hash_seed;
            let case = pool.superblock().case_sensitivity;
            scalefs_core::dirent::add_entry(
                pool.tree_mut(),
                seed,
                case,
                ROOT_INODE,
                "d-again",
                subdir,
                EntryKind::Directory,
            )
            .unwrap();
        });
        assert!(
            !fsck(&image),
            "a twice-referenced directory must be flagged"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn fsck_checks_xattr_buckets() {
        let (dir, image, file, _) = hardlink_pool("xattr");
        corrupt(&image, |pool| {
            pool.set_xattr(file, "user.tag", b"v", scalefs_core::XATTR_SET_EITHER, NOW)
                .unwrap();
        });
        assert!(fsck(&image), "a healthy xattr pool must be clean");

        corrupt(&image, |pool| {
            pool.tree_mut()
                .insert(
                    MetadataKey {
                        object_id: 7777,
                        item_type: ITEM_XATTR,
                        offset: 42,
                    },
                    MetadataValue::XattrEntries(vec![scalefs_core::XattrEntry {
                        name: "user.orphan".to_string(),
                        value: b"stranded".to_vec(),
                    }]),
                )
                .unwrap();
        });
        assert!(!fsck(&image), "a stranded xattr bucket must be flagged");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn fsck_flags_striped_material_without_the_feature() {
        let (dir, image, .., file) = special_pool("no-parity-bit");
        corrupt(&image, |pool| {
            pool.tree_mut()
                .insert(
                    MetadataKey {
                        object_id: file,
                        item_type: ITEM_FILE_EXTENT,
                        offset: 0,
                    },
                    MetadataValue::StripedExtent {
                        extent: Extent {
                            device_index: 0,
                            offset: 65536,
                            length: 100,
                        },
                        parity_extents: vec![Extent {
                            device_index: 1,
                            offset: 65536,
                            length: 4096,
                        }],
                        data_offset: 0,
                        logical_len: 20,
                    },
                )
                .unwrap();
        });
        assert!(
            !fsck(&image),
            "a striped extent without the parity bit must be flagged"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn fsck_checks_special_file_invariants() {
        let (dir, image, ..) = special_pool("clean");
        assert!(fsck(&image), "a healthy special-file pool must be clean");
        let _ = std::fs::remove_dir_all(dir);

        let (dir, image, link, ..) = special_pool("no-target");
        corrupt(&image, |pool| {
            pool.tree_mut().remove(special_key(link));
        });
        assert!(!fsck(&image), "a target-less symlink must be flagged");
        let _ = std::fs::remove_dir_all(dir);

        let (dir, image, _, device, ..) = special_pool("bad-rdev");
        corrupt(&image, |pool| {
            pool.tree_mut()
                .insert(
                    special_key(device),
                    MetadataValue::Special {
                        data: vec![1, 2, 3],
                    },
                )
                .unwrap();
        });
        assert!(!fsck(&image), "a malformed device number must be flagged");
        let _ = std::fs::remove_dir_all(dir);

        let (dir, image, _, _, _, file) = special_pool("squatter");
        corrupt(&image, |pool| {
            pool.tree_mut()
                .insert(
                    special_key(file),
                    MetadataValue::Special {
                        data: b"stray".to_vec(),
                    },
                )
                .unwrap();
        });
        assert!(!fsck(&image), "a special item on a file must be flagged");
        let _ = std::fs::remove_dir_all(dir);

        let (dir, image, _, _, fifo, _) = special_pool("kind-flip");
        corrupt(&image, |pool| {
            let mut attrs = pool.getattr(fifo).unwrap();
            attrs.mode = MODE_FILE | (attrs.mode & !MODE_TYPE_MASK);
            pool.tree_mut()
                .insert(
                    MetadataKey {
                        object_id: fifo,
                        item_type: ITEM_INODE,
                        offset: 0,
                    },
                    MetadataValue::Inode(attrs),
                )
                .unwrap();
        });
        assert!(!fsck(&image), "a kind disagreement must be flagged");
        let _ = std::fs::remove_dir_all(dir);

        let (dir, image, link, ..) = special_pool("extents");
        corrupt(&image, |pool| {
            pool.tree_mut()
                .insert(
                    MetadataKey {
                        object_id: link,
                        item_type: ITEM_FILE_EXTENT,
                        offset: 0,
                    },
                    MetadataValue::FileExtent {
                        extents: vec![scalefs_core::Extent {
                            device_index: 0,
                            offset: 65536,
                            length: 4096,
                        }],
                        data_offset: 0,
                        logical_len: 100,
                    },
                )
                .unwrap();
        });
        assert!(!fsck(&image), "extents on a symlink must be flagged");
        let _ = std::fs::remove_dir_all(dir);
    }
}
