use std::path::Path;

use crate::util::{Opts, format_size};
use scalefs_core::{
    AnyBlockDevice, BLANK_SAMPLE_LEN, BlockDevice, Contents, DiscoveredDevice, superblock_slots,
};

pub fn cmd_device(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("list") if args.len() == 1 => device_list(),
        Some("wipe") => device_wipe(&args[1..]),
        _ => Err("usage: scalefs device <list|wipe> ...".to_string()),
    }
}

fn device_wipe(args: &[String]) -> Result<(), String> {
    let opts = Opts::parse(args, &["force"], &[])?;
    let [path] = opts.positional.as_slice() else {
        return Err("usage: scalefs device wipe <path> [--force]".to_string());
    };
    let probed = scalefs_core::probe_path(Path::new(path));
    let holds = match probed.contents {
        Contents::Blank => {
            println!("{path} is already blank");
            return Ok(());
        }
        Contents::Pool(probe) => {
            format!(
                "a ScaleFS pool ('{}', {})",
                probe.label,
                hex(&probe.pool_id.0)
            )
        }
        Contents::Partitioned => "a partition table".to_string(),
        Contents::Foreign => probed
            .error
            .unwrap_or_else(|| "unrecognized data".to_string()),
        Contents::Unreadable => "unreadable contents".to_string(),
    };
    if !opts.flag("force") {
        return Err(format!(
            "{path} holds {holds}; wiping is irreversible — re-run with --force to blank it"
        ));
    }

    let device = AnyBlockDevice::open(Path::new(path))
        .map_err(|err| format!("cannot open {path} for writing: {err}"))?;
    let len = device.len();
    if len == 0 {
        return Err(format!("{path} is empty"));
    }
    let zero = |offset: u64, span: u64, what: &str| -> Result<(), String> {
        let span = span.min(len.saturating_sub(offset));
        if span == 0 {
            return Ok(());
        }
        device
            .write_at(offset, &vec![0u8; span as usize])
            .map_err(|err| format!("cannot wipe {what} of {path}: {err}"))
    };
    let view = scalefs_core::member_view_forensic(&device);
    if view.start() > 0 {
        let [head_slot, tail_slot] = superblock_slots(view.len());
        for (offset, what) in [(head_slot, "the head slot"), (tail_slot, "the tail slot")] {
            let span = 8192u64.min(view.len().saturating_sub(offset));
            if span > 0 {
                view.write_at(offset, &vec![0u8; span as usize])
                    .map_err(|err| format!("cannot wipe {what} of {path}: {err}"))?;
            }
        }
    }
    zero(0, BLANK_SAMPLE_LEN, "the head")?;
    let tail = len.saturating_sub(BLANK_SAMPLE_LEN) & !4095;
    zero(tail, len - tail, "the tail")?;
    device
        .flush()
        .map_err(|err| format!("cannot flush {path}: {err}"))?;
    println!("wiped {path} (was {holds})");
    Ok(())
}

fn device_list() -> Result<(), String> {
    let devices = scalefs_core::list_devices();
    if devices.is_empty() {
        println!("no devices found (device scans may need elevation)");
        return Ok(());
    }
    let path_width = devices
        .iter()
        .map(|device| device.path.len())
        .max()
        .unwrap_or(0)
        .max(4);
    for device in &devices {
        let size = device.size.map_or_else(|| "?".to_string(), format_size);
        println!(
            "{:<path_width$}  {:>10}  {}",
            device.path,
            size,
            describe(device),
        );
    }
    let pools = scalefs_core::discovered_pools(&devices);
    if !pools.is_empty() {
        println!();
        println!("Pools visible:");
        for pool in &pools {
            println!(
                "  {}  '{}'  {} member(s)",
                hex(&pool.pool_id.0),
                pool.label,
                pool.members_visible,
            );
        }
        println!("(assemble one with: scalefs pool import [--pool <label|id-prefix>])");
    }
    Ok(())
}

fn describe(device: &DiscoveredDevice) -> String {
    let mut text = match &device.contents {
        Contents::Pool(probe) => {
            let mut text = format!("pool '{}' {}", probe.label, hex(&probe.pool_id.0));
            if probe.unknown_incompat {
                text.push_str(" (needs a newer scalefs)");
            }
            text
        }
        Contents::Partitioned => "partitioned".to_string(),
        Contents::Blank => "blank".to_string(),
        Contents::Foreign => match &device.error {
            Some(what) => format!("foreign ({what})"),
            None => "foreign".to_string(),
        },
        Contents::Unreadable => match &device.error {
            Some(error) => format!("unreadable ({error})"),
            None => "unreadable".to_string(),
        },
    };
    let hardware: Vec<String> = device
        .identity
        .model
        .iter()
        .cloned()
        .chain(
            device
                .identity
                .serial
                .iter()
                .map(|serial| format!("serial {serial}")),
        )
        .chain((device.actuators >= 2).then(|| format!("{} actuators", device.actuators)))
        .collect();
    if !hardware.is_empty() {
        text.push_str("  — ");
        text.push_str(&hardware.join(", "));
    }
    text
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(6)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use scalefs_core::probe_path;

    #[test]
    fn wipe_blanks_a_device() {
        let dir = std::env::temp_dir().join(format!("scalefs-wipe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let image = dir.join("junk.img");
        std::fs::write(&image, vec![0x5Au8; 1 << 20]).unwrap();
        let path = image.to_string_lossy().into_owned();
        assert!(matches!(probe_path(&image).contents, Contents::Foreign));

        assert!(device_wipe(std::slice::from_ref(&path)).is_err());
        assert!(matches!(probe_path(&image).contents, Contents::Foreign));

        device_wipe(&[path, "--force".to_string()]).unwrap();
        assert!(matches!(probe_path(&image).contents, Contents::Blank));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn wipe_refuses_a_held_image() {
        use scalefs_core::{BlockDevice, FileBlockDevice};
        let dir = std::env::temp_dir().join(format!("scalefs-wipe-held-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let image = dir.join("held.img");
        let held = FileBlockDevice::create(&image, 1 << 20).unwrap();
        held.write_at(0, &[0x5A; 8192]).unwrap();
        held.flush().unwrap();
        let path = image.to_string_lossy().into_owned();

        let refused = device_wipe(&[path.clone(), "--force".to_string()]);
        let message = refused.expect_err("a held image must refuse the wipe");
        assert!(message.contains("in use"), "{message}");
        assert!(
            matches!(probe_path(&image).contents, Contents::Foreign),
            "the refused wipe must not have touched the image"
        );

        drop(held);
        device_wipe(&[path, "--force".to_string()]).unwrap();
        assert!(matches!(probe_path(&image).contents, Contents::Blank));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn wiping_a_blank_device_is_a_noop() {
        let dir = std::env::temp_dir().join(format!("scalefs-wipe-blank-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let image = dir.join("blank.img");
        std::fs::write(&image, vec![0u8; 1 << 20]).unwrap();
        let path = image.to_string_lossy().into_owned();
        assert!(device_wipe(std::slice::from_ref(&path)).is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }
}
