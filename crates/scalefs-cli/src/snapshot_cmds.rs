
use scalefs_core::{AllocPurpose, AnyBlockDevice, EntryKind, ROOT_INODE, Snapshot};

use crate::pool_cmds::open_pool;
use crate::util::{format_size, format_time, now_ns};

pub fn cmd_snapshot(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("create") => snapshot_create(&args[1..]),
        Some("list") => snapshot_list(&args[1..]),
        Some("release") => snapshot_release(&args[1..]),
        Some("ls") => snapshot_ls(&args[1..]),
        Some("get") => snapshot_get(&args[1..]),
        _ => Err("usage: scalefs snapshot <create|list|release|ls|get> <image> ...".to_string()),
    }
}

fn snapshot_create(args: &[String]) -> Result<(), String> {
    let [image, name] = args else {
        return Err("usage: scalefs snapshot create <image> <name>".to_string());
    };
    let mut pool = open_pool(image)?;
    pool.snapshot_create(name, now_ns())
        .map_err(|err| format!("{name}: {err}"))?;
    println!(
        "created snapshot '{name}' at transaction {}",
        pool.committed_tx()
    );
    Ok(())
}

fn snapshot_list(args: &[String]) -> Result<(), String> {
    let [image] = args else {
        return Err("usage: scalefs snapshot list <image>".to_string());
    };
    let pool = open_pool(image)?;
    let snapshots = pool.snapshot_list();
    if snapshots.is_empty() {
        println!("(no snapshots)");
        return Ok(());
    }
    for snapshot in snapshots {
        println!(
            "{:<24}  tx {:>6}  {}",
            snapshot.name,
            snapshot.tx_id,
            format_time(snapshot.created_at_ns)
        );
    }
    Ok(())
}

fn snapshot_release(args: &[String]) -> Result<(), String> {
    let [image, name] = args else {
        return Err("usage: scalefs snapshot release <image> <name>".to_string());
    };
    let mut pool = open_pool(image)?;
    pool.snapshot_release(name)
        .map_err(|err| format!("{name}: {err}"))?;
    pool.commit(AllocPurpose::Reclaim, now_ns())
        .map_err(|err| err.to_string())?;
    println!("released snapshot '{name}'");
    Ok(())
}

fn resolve_in_snapshot(snapshot: &Snapshot<'_, AnyBlockDevice>, path: &str) -> Result<u64, String> {
    if !path.starts_with('/') {
        return Err(format!(
            "pool paths are absolute: '{path}' must start with /"
        ));
    }
    let mut current = ROOT_INODE;
    for part in path.split('/').filter(|part| !part.is_empty()) {
        current = snapshot
            .lookup(current, part)
            .map_err(|err| format!("{path}: {err}"))?
            .inode;
    }
    Ok(current)
}

fn snapshot_ls(args: &[String]) -> Result<(), String> {
    let (image, name, path) = match args {
        [image, name] => (image, name, "/"),
        [image, name, path] => (image, name, path.as_str()),
        _ => return Err("usage: scalefs snapshot ls <image> <name> [path]".to_string()),
    };
    let pool = open_pool(image)?;
    let snapshot = pool
        .snapshot_open(name)
        .map_err(|err| format!("{name}: {err}"))?;
    let dir = resolve_in_snapshot(&snapshot, path)?;
    for entry in snapshot
        .readdir(dir)
        .map_err(|err| format!("{path}: {err}"))?
    {
        let attrs = snapshot
            .getattr(entry.inode)
            .map_err(|err| format!("{}: {err}", entry.name))?;
        let kind = match entry.kind {
            EntryKind::Directory => "dir ",
            EntryKind::File => "file",
            EntryKind::Symlink => "link",
            EntryKind::Fifo => "fifo",
            EntryKind::Socket => "sock",
            EntryKind::CharDevice => "chr ",
            EntryKind::BlockDevice => "blk ",
            EntryKind::Unknown(_) => "unk ",
        };
        println!("{kind}  {:>12}  {}", format_size(attrs.size), entry.name);
    }
    Ok(())
}

fn snapshot_get(args: &[String]) -> Result<(), String> {
    let [image, name, path, local] = args else {
        return Err("usage: scalefs snapshot get <image> <name> <path> <local-file>".to_string());
    };
    let pool = open_pool(image)?;
    let snapshot = pool
        .snapshot_open(name)
        .map_err(|err| format!("{name}: {err}"))?;
    let object = resolve_in_snapshot(&snapshot, path)?;
    let attrs = snapshot
        .getattr(object)
        .map_err(|err| format!("{path}: {err}"))?;
    if attrs.is_dir() {
        return Err(format!("{path}: is a directory"));
    }
    let size = usize::try_from(attrs.size).map_err(|_| "file too large to read")?;
    let data = snapshot
        .read(object, 0, size)
        .map_err(|err| format!("{path}: {err}"))?;
    std::fs::write(local, &data).map_err(|err| format!("cannot write {local}: {err}"))?;
    println!(
        "read {} from snapshot '{name}' {path}",
        format_size(data.len() as u64)
    );
    Ok(())
}
