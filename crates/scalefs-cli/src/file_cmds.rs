use scalefs_core::{
    AllocPurpose, AnyBlockDevice, EntryKind, MODE_TYPE_MASK, Pool, ROOT_INODE, ScaleFsError,
};

use crate::pool_cmds::open_pool;
use crate::util::{format_size, format_time, now_ns};

pub fn cmd_fs(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("ls") => fs_ls(&args[1..]),
        Some("stat") => fs_stat(&args[1..]),
        Some("put") => fs_put(&args[1..]),
        Some("get") => fs_get(&args[1..]),
        Some("mkdir") => fs_mkdir(&args[1..]),
        Some("mv") => fs_mv(&args[1..]),
        Some("ln") => fs_ln(&args[1..]),
        Some("rm") => fs_rm(&args[1..]),
        Some("rmdir") => fs_rmdir(&args[1..]),
        _ => {
            Err("usage: scalefs fs <ls|stat|put|get|mkdir|mv|ln|rm|rmdir> <image> ...".to_string())
        }
    }
}

fn components(path: &str) -> Result<Vec<&str>, String> {
    if !path.starts_with('/') {
        return Err(format!(
            "pool paths are absolute: '{path}' must start with /"
        ));
    }
    Ok(path.split('/').filter(|part| !part.is_empty()).collect())
}

fn resolve(pool: &Pool<AnyBlockDevice>, path: &str) -> Result<u64, String> {
    let mut current = ROOT_INODE;
    for part in components(path)? {
        current = pool
            .lookup(current, part)
            .map_err(|err| format!("{path}: {err}"))?
            .inode;
    }
    Ok(current)
}

fn resolve_parent<'p>(
    pool: &Pool<AnyBlockDevice>,
    path: &'p str,
) -> Result<(u64, &'p str), String> {
    let parts = components(path)?;
    let Some((leaf, ancestors)) = parts.split_last() else {
        return Err(format!("'{path}' has no name component"));
    };
    let mut current = ROOT_INODE;
    for part in ancestors {
        current = pool
            .lookup(current, part)
            .map_err(|err| format!("{path}: {err}"))?
            .inode;
    }
    Ok((current, leaf))
}

fn fs_ls(args: &[String]) -> Result<(), String> {
    let (image, path) = match args {
        [image] => (image, "/"),
        [image, path] => (image, path.as_str()),
        _ => return Err("usage: scalefs fs ls <image> [path]".to_string()),
    };
    let pool = open_pool(image)?;
    let dir = resolve(&pool, path)?;
    for entry in pool.readdir(dir).map_err(|err| format!("{path}: {err}"))? {
        let attrs = pool
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

fn fs_stat(args: &[String]) -> Result<(), String> {
    let [image, path] = args else {
        return Err("usage: scalefs fs stat <image> <path>".to_string());
    };
    let pool = open_pool(image)?;
    let object = resolve(&pool, path)?;
    let attrs = pool
        .getattr(object)
        .map_err(|err| format!("{path}: {err}"))?;
    println!("Path:      {path}");
    println!("Inode:     {object}");
    println!(
        "Type:      {}",
        if attrs.is_dir() { "directory" } else { "file" }
    );
    println!(
        "Size:      {} ({} bytes)",
        format_size(attrs.size),
        attrs.size
    );
    println!("Mode:      {:04o}", attrs.mode & !MODE_TYPE_MASK);
    println!("Links:     {}", attrs.nlink);
    println!("Owner:     {}:{}", attrs.uid, attrs.gid);
    println!("Attrs:     {:#06x}", attrs.attrs);
    println!("Created:   {}", format_time(attrs.crtime_ns));
    println!("Modified:  {}", format_time(attrs.mtime_ns));
    println!("Changed:   {}", format_time(attrs.ctime_ns));
    Ok(())
}

fn fs_put(args: &[String]) -> Result<(), String> {
    let [image, local, path] = args else {
        return Err("usage: scalefs fs put <image> <local-file> <path>".to_string());
    };
    let data = std::fs::read(local).map_err(|err| format!("cannot read {local}: {err}"))?;
    let mut pool = open_pool(image)?;
    let (parent, name) = resolve_parent(&pool, path)?;
    let now = now_ns();

    let object = match pool.lookup(parent, name) {
        Ok(entry) if entry.kind == EntryKind::Directory => {
            return Err(format!("{path}: is a directory"));
        }
        Ok(entry) => {
            pool.truncate(entry.inode, 0, now)
                .map_err(|err| err.to_string())?;
            entry.inode
        }
        Err(ScaleFsError::NotFound) => pool
            .create_file(parent, name, 0o644, now)
            .map_err(|err| format!("{path}: {err}"))?,
        Err(err) => return Err(format!("{path}: {err}")),
    };
    pool.write(object, 0, &data, now)
        .map_err(|err| format!("{path}: {err}"))?;
    pool.commit(AllocPurpose::Normal, now)
        .map_err(|err| err.to_string())?;
    println!("wrote {} to {path}", format_size(data.len() as u64));
    Ok(())
}

fn fs_get(args: &[String]) -> Result<(), String> {
    let [image, path, local] = args else {
        return Err("usage: scalefs fs get <image> <path> <local-file>".to_string());
    };
    let pool = open_pool(image)?;
    let object = resolve(&pool, path)?;
    let attrs = pool
        .getattr(object)
        .map_err(|err| format!("{path}: {err}"))?;
    if attrs.is_dir() {
        return Err(format!("{path}: is a directory"));
    }
    let size = usize::try_from(attrs.size).map_err(|_| "file too large to read")?;
    let data = pool
        .read(object, 0, size)
        .map_err(|err| format!("{path}: {err}"))?;
    std::fs::write(local, &data).map_err(|err| format!("cannot write {local}: {err}"))?;
    println!("read {} from {path}", format_size(data.len() as u64));
    Ok(())
}

fn fs_mkdir(args: &[String]) -> Result<(), String> {
    let [image, path] = args else {
        return Err("usage: scalefs fs mkdir <image> <path>".to_string());
    };
    let mut pool = open_pool(image)?;
    let (parent, name) = resolve_parent(&pool, path)?;
    let now = now_ns();
    pool.mkdir(parent, name, 0o755, now)
        .map_err(|err| format!("{path}: {err}"))?;
    pool.commit(AllocPurpose::Normal, now)
        .map_err(|err| err.to_string())?;
    Ok(())
}

fn fs_mv(args: &[String]) -> Result<(), String> {
    let [image, from, to] = args else {
        return Err("usage: scalefs fs mv <image> <from> <to>".to_string());
    };
    let mut pool = open_pool(image)?;
    let (old_parent, old_name) = resolve_parent(&pool, from)?;
    let (new_parent, new_name) = resolve_parent(&pool, to)?;
    let now = now_ns();
    pool.rename(old_parent, old_name, new_parent, new_name, now)
        .map_err(|err| format!("{from} -> {to}: {err}"))?;
    pool.commit(AllocPurpose::Normal, now)
        .map_err(|err| err.to_string())?;
    Ok(())
}

fn fs_ln(args: &[String]) -> Result<(), String> {
    let [image, existing, new_path] = args else {
        return Err("usage: scalefs fs ln <image> <existing> <new-path>".to_string());
    };
    let mut pool = open_pool(image)?;
    let object = resolve(&pool, existing)?;
    let (new_parent, new_name) = resolve_parent(&pool, new_path)?;
    let now = now_ns();
    pool.link(object, new_parent, new_name, now)
        .map_err(|err| format!("{existing} -> {new_path}: {err}"))?;
    pool.commit(AllocPurpose::Normal, now)
        .map_err(|err| err.to_string())?;
    Ok(())
}

fn fs_rm(args: &[String]) -> Result<(), String> {
    let [image, path] = args else {
        return Err("usage: scalefs fs rm <image> <path>".to_string());
    };
    let mut pool = open_pool(image)?;
    let (parent, name) = resolve_parent(&pool, path)?;
    let now = now_ns();
    pool.unlink(parent, name, now)
        .map_err(|err| format!("{path}: {err}"))?;
    pool.commit(AllocPurpose::Reclaim, now)
        .map_err(|err| err.to_string())?;
    Ok(())
}

fn fs_rmdir(args: &[String]) -> Result<(), String> {
    let [image, path] = args else {
        return Err("usage: scalefs fs rmdir <image> <path>".to_string());
    };
    let mut pool = open_pool(image)?;
    let (parent, name) = resolve_parent(&pool, path)?;
    let now = now_ns();
    pool.rmdir(parent, name, now)
        .map_err(|err| format!("{path}: {err}"))?;
    pool.commit(AllocPurpose::Reclaim, now)
        .map_err(|err| err.to_string())?;
    Ok(())
}
