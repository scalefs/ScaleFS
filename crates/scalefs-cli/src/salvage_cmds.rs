use crate::util::Opts;
use scalefs_core::salvage::{
    AssemblyReport, CandidateKind, Damage, DeviceRole, ExtentVerdict, FileReport, PathOutcome,
    Rung, Salvage, SalvageOptions, SlotHealth, StatOutcome,
};
use scalefs_core::tree::EntryKind;
use scalefs_core::{Geometry, ROOT_INODE, RawBlockDevice};
use scalefs_ipc::json::{Value, object};
use std::borrow::Cow;
use std::io::Write;

const USAGE: &str = "usage: scalefs salvage <scan|ls|get|copy-out> <device[,device...]> ... \
                     (see 'scalefs help')";

pub fn cmd_salvage(args: &[String]) -> Result<bool, String> {
    match args.first().map(String::as_str) {
        Some("scan") => cmd_scan(&args[1..]),
        Some("ls") => cmd_ls(&args[1..]),
        Some("get") => cmd_get(&args[1..]),
        Some("copy-out") => cmd_copy_out(&args[1..]),
        Some(other) => Err(format!("unknown salvage command '{other}' ({USAGE})")),
        None => Err(USAGE.to_string()),
    }
}

fn enter_named_snapshot(session: &mut Salvage<RawBlockDevice>, name: &str) -> Result<(), String> {
    let (snapshots, _) = session
        .snapshots()
        .map_err(|error| format!("snapshot listing failed: {error:?}"))?;
    let snapshot = snapshots
        .iter()
        .find(|snapshot| snapshot.name == name)
        .ok_or_else(|| format!("no snapshot named '{name}'"))?;
    session
        .enter_snapshot(snapshot)
        .map_err(|error| format!("cannot enter snapshot '{name}': {error:?}"))
}

fn rollup_text(verdict: &ExtentVerdict) -> String {
    match verdict {
        ExtentVerdict::Intact => "intact".to_string(),
        ExtentVerdict::HealedFromCopy { copy } => format!("healed-from-copy({copy})"),
        ExtentVerdict::ReconstructedFromParity => "reconstructed-from-parity".to_string(),
        ExtentVerdict::Lost { .. } => "LOST".to_string(),
        ExtentVerdict::MapLost => "LOST(extent-map)".to_string(),
    }
}

fn print_file_report(report: &FileReport) {
    let mut shown = 0;
    for range in &report.ranges {
        if range.verdict == ExtentVerdict::Intact {
            continue;
        }
        if shown == 20 {
            println!("    ... (more ranges; --json for the full inventory)");
            break;
        }
        shown += 1;
        println!(
            "    bytes {}..{}: {}",
            range.offset,
            range.offset + range.len,
            rollup_text(&range.verdict),
        );
        if let ExtentVerdict::Lost { reasons } = &range.verdict {
            for reason in reasons {
                println!("      {reason}");
            }
        }
    }
    for damage in &report.map_damage {
        print_damage(damage);
    }
}

fn cmd_get(args: &[String]) -> Result<bool, String> {
    let opts = Opts::parse(args, &[], &["view", "snapshot"])?;
    let [list, path, local] = &opts.positional[..] else {
        return Err(
            "usage: scalefs salvage get <devices> <path> <local-file> [--view <tx>] \
             [--snapshot <name>]"
                .to_string(),
        );
    };
    let (_, mut session) = open_session(list, &parse_view(&opts)?)?;
    if !session.has_view() {
        return Err(
            "no view could be adopted (run 'salvage scan' for the damage report)".to_string(),
        );
    }
    if let Some(name) = opts.value("snapshot") {
        enter_named_snapshot(&mut session, name)?;
    }
    let object = match session
        .resolve_path(path)
        .map_err(|error| format!("resolve failed: {error:?}"))?
    {
        PathOutcome::Found(object) => object,
        PathOutcome::Missing => return Err(format!("no such path: {path}")),
        PathOutcome::Lost(_) => {
            return Err(format!("the range that would name '{path}' is lost"));
        }
    };
    let mut sink = std::io::BufWriter::new(
        std::fs::File::create(local).map_err(|error| format!("cannot create {local}: {error}"))?,
    );
    let report = session
        .salvage_file(object, &mut sink)
        .map_err(|error| format!("salvage failed: {error:?}"))?;
    sink.flush().map_err(|error| error.to_string())?;
    let rollup = report.rollup();
    println!(
        "salvaged {path} ({} bytes): {}{}",
        report.size,
        rollup_text(&rollup),
        if report.bytes_lost > 0 {
            format!(" — {} byte(s) LOST (zero-filled)", report.bytes_lost)
        } else {
            String::new()
        },
    );
    print_file_report(&report);
    Ok(rollup == ExtentVerdict::Intact)
}

#[derive(Default)]
struct CopyTally {
    files: u64,
    intact: u64,
    healed: u64,
    reconstructed: u64,
    lost: u64,
    bytes_lost: u64,
    notes: u64,
}

fn cmd_copy_out(args: &[String]) -> Result<bool, String> {
    let opts = Opts::parse(args, &["snapshots", "force"], &["view", "manifest"])?;
    let [list, dest] = &opts.positional[..] else {
        return Err(
            "usage: scalefs salvage copy-out <devices> <dest-dir> [--view <tx>] \
             [--snapshots] [--manifest <file>] [--force]"
                .to_string(),
        );
    };
    let (_, session) = open_session(list, &parse_view(&opts)?)?;
    if !session.has_view() {
        return Err(
            "no view could be adopted (run 'salvage scan' for the damage report)".to_string(),
        );
    }
    let dest = std::path::Path::new(dest);
    std::fs::create_dir_all(dest).map_err(|error| format!("cannot create {dest:?}: {error}"))?;
    if !opts.flag("force")
        && dest
            .read_dir()
            .map_err(|error| format!("cannot list {dest:?}: {error}"))?
            .next()
            .is_some()
    {
        return Err(format!(
            "{dest:?} is not empty; use --force to copy into it anyway (existing files are kept)"
        ));
    }
    let mut manifest: Box<dyn Write> = match opts.value("manifest") {
        Some(path) => Box::new(
            std::fs::File::create(path)
                .map_err(|error| format!("cannot create {path}: {error}"))?,
        ),
        None => Box::new(std::io::stdout()),
    };
    let mut session = session;
    let mut tally = CopyTally::default();
    copy_dir(&session, ROOT_INODE, dest, "", &mut manifest, &mut tally)?;
    if opts.flag("snapshots") {
        let (snapshots, damage) = session
            .snapshots()
            .map_err(|error| format!("snapshot listing failed: {error:?}"))?;
        for lost in &damage {
            tally.notes += 1;
            let _ = lost;
            writeln!(
                manifest,
                "# the snapshot list may be incomplete (lost tree range)"
            )
            .map_err(|error| error.to_string())?;
        }
        for snapshot in &snapshots {
            let saved = host_safe_component(&snapshot.name);
            let sub = dest.join(".snapshots").join(saved.as_ref());
            std::fs::create_dir_all(&sub)
                .map_err(|error| format!("cannot create {sub:?}: {error}"))?;
            match session.enter_snapshot(snapshot) {
                Ok(()) => {
                    writeln!(
                        manifest,
                        "# snapshot '{}' (tx {}){}",
                        manifest_text(&snapshot.name),
                        snapshot.tx_id,
                        saved_as_note(&snapshot.name, &saved),
                    )
                    .map_err(|error| error.to_string())?;
                    let prefix = format!(".snapshots/{}", snapshot.name);
                    copy_dir(
                        &session,
                        ROOT_INODE,
                        &sub,
                        &prefix,
                        &mut manifest,
                        &mut tally,
                    )?;
                }
                Err(error) => {
                    tally.notes += 1;
                    writeln!(
                        manifest,
                        "# snapshot '{}': no root replica decodes ({})",
                        manifest_text(&snapshot.name),
                        manifest_text(&format!("{error:?}")),
                    )
                    .map_err(|error| error.to_string())?;
                }
            }
        }
        session.enter_live();
    }

    let survey = session
        .survey()
        .map_err(|error| format!("survey failed: {error:?}"))?;
    for damage in &survey.damage {
        writeln!(
            manifest,
            "# LOST tree range: keys ({},{},{:#x})..=({},{},{:#x})",
            damage.first_key.object_id,
            damage.first_key.item_type,
            damage.first_key.offset,
            damage.last_key.object_id,
            damage.last_key.item_type,
            damage.last_key.offset,
        )
        .map_err(|error| error.to_string())?;
    }
    if !survey.disconnected.is_empty() {
        writeln!(
            manifest,
            "# disconnected objects (no reachable name): {}",
            survey
                .disconnected
                .iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        )
        .map_err(|error| error.to_string())?;
    }
    manifest.flush().map_err(|error| error.to_string())?;
    eprintln!(
        "copied {} file(s): {} intact, {} healed, {} reconstructed, {} with losses \
         ({} byte(s) zero-filled), {} note(s); {} lost tree range(s), {} disconnected",
        tally.files,
        tally.intact,
        tally.healed,
        tally.reconstructed,
        tally.lost,
        tally.bytes_lost,
        tally.notes,
        survey.damage.len(),
        survey.disconnected.len(),
    );
    Ok(tally.lost == 0
        && tally.healed == 0
        && tally.reconstructed == 0
        && tally.notes == 0
        && survey.damage.is_empty()
        && survey.disconnected.is_empty())
}

fn copy_dir(
    session: &Salvage<RawBlockDevice>,
    dir: u64,
    dest: &std::path::Path,
    prefix: &str,
    manifest: &mut dyn Write,
    tally: &mut CopyTally,
) -> Result<(), String> {
    let listing = session
        .read_dir(dir)
        .map_err(|error| format!("list failed: {error:?}"))?;
    for damage in &listing.damage {
        tally.notes += 1;
        writeln!(
            manifest,
            "# /{prefix}: the listing may be missing entries (lost keys \
             ({},{},{:#x})..=({},{},{:#x}))",
            damage.first_key.object_id,
            damage.first_key.item_type,
            damage.first_key.offset,
            damage.last_key.object_id,
            damage.last_key.item_type,
            damage.last_key.offset,
        )
        .map_err(|error| error.to_string())?;
    }
    for entry in &listing.entries {
        let rel = if prefix.is_empty() {
            entry.name.clone()
        } else {
            format!("{prefix}/{}", entry.name)
        };
        let shown = manifest_text(&rel);
        let saved = host_safe_component(&entry.name);
        if saved != entry.name {
            tally.notes += 1;
            writeln!(manifest, "# /{shown} saved as {saved:?}")
                .map_err(|error| error.to_string())?;
        }
        let target = dest.join(saved.as_ref());
        match entry.kind {
            EntryKind::Directory => {
                match std::fs::create_dir(&target) {
                    Ok(()) => {}
                    Err(error)
                        if error.kind() == std::io::ErrorKind::AlreadyExists
                            && std::fs::symlink_metadata(&target)
                                .is_ok_and(|existing| existing.is_dir()) => {}
                    Err(error) => return Err(format!("cannot create {target:?}: {error}")),
                }
                writeln!(manifest, "dir\t-\t/{shown}").map_err(|error| error.to_string())?;
                copy_dir(session, entry.inode, &target, &rel, manifest, tally)?;
            }
            EntryKind::File => {
                let created = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&target);
                let file = match created {
                    Ok(file) => file,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        tally.notes += 1;
                        writeln!(manifest, "SKIPPED(exists)\t-\t/{shown}")
                            .map_err(|error| error.to_string())?;
                        continue;
                    }
                    Err(error) => return Err(format!("cannot create {target:?}: {error}")),
                };
                tally.files += 1;
                let mut sink = std::io::BufWriter::new(file);
                match session.salvage_file(entry.inode, &mut sink) {
                    Ok(report) => {
                        sink.flush().map_err(|error| error.to_string())?;
                        let rollup = report.rollup();
                        match rollup {
                            ExtentVerdict::Intact => tally.intact += 1,
                            ExtentVerdict::HealedFromCopy { .. } => tally.healed += 1,
                            ExtentVerdict::ReconstructedFromParity => tally.reconstructed += 1,
                            ExtentVerdict::Lost { .. } | ExtentVerdict::MapLost => {
                                tally.lost += 1;
                                tally.bytes_lost += report.bytes_lost;
                            }
                        }
                        writeln!(
                            manifest,
                            "{}\t{}\t/{shown}",
                            rollup_text(&rollup),
                            report.size,
                        )
                        .map_err(|error| error.to_string())?;
                    }
                    Err(error) => {
                        tally.lost += 1;
                        writeln!(
                            manifest,
                            "UNREADABLE\t-\t/{shown}\t{}",
                            manifest_text(&format!("{error:?}"))
                        )
                        .map_err(|error| error.to_string())?;
                    }
                }
            }
            EntryKind::Symlink => {
                tally.notes += 1;
                let note = match session.read_special(entry.inode) {
                    Ok(Some(bytes)) => String::from_utf8_lossy(&bytes).to_string(),
                    _ => "?".to_string(),
                };
                writeln!(
                    manifest,
                    "symlink\t-\t/{shown}\t-> {}",
                    manifest_text(&note)
                )
                .map_err(|error| error.to_string())?;
            }
            other => {
                tally.notes += 1;
                writeln!(manifest, "special({other:?})\t-\t/{shown}")
                    .map_err(|error| error.to_string())?;
            }
        }
    }
    Ok(())
}

fn host_safe_component(name: &str) -> Cow<'_, str> {
    if cfg!(windows) {
        windows_safe_component(name)
    } else {
        Cow::Borrowed(name)
    }
}

fn windows_safe_component(name: &str) -> Cow<'_, str> {
    const DEVICES: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "COM0", "COM1", "COM2", "COM3", "COM4",
        "COM5", "COM6", "COM7", "COM8", "COM9", "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5",
        "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    fn reserved_char(c: char) -> bool {
        matches!(
            c,
            '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | '%'
        ) || c.is_control()
    }
    let stem = name.split('.').next().unwrap_or(name);
    let device = DEVICES
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved));
    let chars: Vec<char> = name.chars().collect();
    let last_kept = chars.iter().rposition(|c| !matches!(c, '.' | ' '));
    let clean = !device
        && last_kept == chars.len().checked_sub(1)
        && !chars.iter().any(|&c| reserved_char(c));
    if clean {
        return Cow::Borrowed(name);
    }
    let mut out = String::with_capacity(name.len() + 8);
    for (index, &c) in chars.iter().enumerate() {
        let trailing = last_kept.is_none_or(|kept| index > kept);
        if reserved_char(c) || trailing || (device && index == 0) {
            let mut utf8 = [0u8; 4];
            for byte in c.encode_utf8(&mut utf8).bytes() {
                out.push_str(&format!("%{byte:02X}"));
            }
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

fn saved_as_note(stored: &str, saved: &str) -> String {
    if stored == saved {
        String::new()
    } else {
        format!(" (saved as {saved:?})")
    }
}

fn manifest_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => out.push_str(&format!("\\x{:02X}", u32::from(c))),
            c => out.push(c),
        }
    }
    out
}

fn open_session(
    list: &str,
    options: &SalvageOptions,
) -> Result<(Vec<String>, Salvage<RawBlockDevice>), String> {
    let paths: Vec<String> = list
        .split(',')
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect();
    if paths.is_empty() {
        return Err("no devices given".to_string());
    }
    let mut devices = Vec::new();
    for path in &paths {
        let device = RawBlockDevice::open_probe(std::path::Path::new(path))
            .map_err(|error| format!("cannot probe '{path}': {error:?}"))?;
        devices.push(device);
    }
    let session = Salvage::assemble_with(devices, options)
        .map_err(|error| format!("nothing to salvage: {error:?}"))?;
    Ok((paths, session))
}

fn parse_view(opts: &Opts) -> Result<SalvageOptions, String> {
    let view_tx = match opts.value("view") {
        None => None,
        Some(text) => Some(
            text.parse::<u64>()
                .map_err(|_| "--view takes a transaction id".to_string())?,
        ),
    };
    Ok(SalvageOptions { view_tx })
}

fn cmd_scan(args: &[String]) -> Result<bool, String> {
    let opts = Opts::parse(args, &["json"], &["view"])?;
    let [list] = &opts.positional[..] else {
        return Err(USAGE.to_string());
    };
    let (paths, session) = open_session(list, &parse_view(&opts)?)?;
    let report = session.report();
    if opts.flag("json") {
        println!("{}", report_value(&paths, report).encode());
    } else {
        print_report(&paths, report);
    }
    Ok(session.has_view())
}

fn cmd_ls(args: &[String]) -> Result<bool, String> {
    let opts = Opts::parse(args, &["all"], &["view", "snapshot"])?;
    let (list, path) = match &opts.positional[..] {
        [list] => (list, "/"),
        [list, path] => (list, path.as_str()),
        _ => return Err(USAGE.to_string()),
    };
    let (_, mut session) = open_session(list, &parse_view(&opts)?)?;
    if !session.has_view() {
        return Err(
            "no view could be adopted (run 'salvage scan' for the damage report)".to_string(),
        );
    }
    if let Some(name) = opts.value("snapshot") {
        enter_named_snapshot(&mut session, name)?;
    }
    let mut clean = true;
    if opts.flag("all") {
        list_all(
            &session,
            ROOT_INODE,
            path.trim_matches(['/', '\\']),
            &mut clean,
            0,
        )?;
        let survey = session
            .survey()
            .map_err(|error| format!("survey failed: {error:?}"))?;
        for damage in &survey.damage {
            clean = false;
            print_damage(damage);
        }
        if !survey.disconnected.is_empty() {
            clean = false;
            println!(
                "  disconnected objects (inodes no reachable name points at): {}",
                survey
                    .disconnected
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        println!(
            "  {} file(s), {} directorie(s), {} lost range(s), {} disconnected",
            survey.files,
            survey.directories,
            survey.damage.len(),
            survey.disconnected.len(),
        );
        return Ok(clean);
    }
    let object = match session
        .resolve_path(path)
        .map_err(|error| format!("resolve failed: {error:?}"))?
    {
        PathOutcome::Found(object) => object,
        PathOutcome::Missing => return Err(format!("no such path: {path}")),
        PathOutcome::Lost(damage) => {
            for lost in &damage {
                print_damage(lost);
            }
            return Err(format!(
                "the range that would name '{path}' is lost ({} dead subtree(s))",
                damage.len()
            ));
        }
    };
    let listing = session
        .read_dir(object)
        .map_err(|error| format!("list failed: {error:?}"))?;
    for entry in &listing.entries {
        let (kind, size) = match session.stat(entry.inode) {
            Ok(StatOutcome::Found(attrs)) => (
                kind_char(entry.kind),
                if attrs.is_dir() {
                    "-".to_string()
                } else {
                    attrs.size.to_string()
                },
            ),
            Ok(StatOutcome::Missing) => (kind_char(entry.kind), "MISSING".to_string()),
            Ok(StatOutcome::Lost(_)) => {
                clean = false;
                (kind_char(entry.kind), "LOST".to_string())
            }
            Err(_) => (kind_char(entry.kind), "?".to_string()),
        };
        println!("{kind} {size:>12}  {}", entry.name);
    }
    for damage in &listing.damage {
        clean = false;
        print_damage(damage);
        println!("  (the listing above may be missing entries)");
    }
    Ok(clean)
}

fn list_all(
    session: &Salvage<RawBlockDevice>,
    dir: u64,
    prefix: &str,
    clean: &mut bool,
    depth: u32,
) -> Result<(), String> {
    if depth > 128 {
        return Ok(());
    }
    let listing = session
        .read_dir(dir)
        .map_err(|error| format!("list failed: {error:?}"))?;
    if !listing.damage.is_empty() {
        *clean = false;
    }
    for entry in &listing.entries {
        let path = if prefix.is_empty() {
            format!("/{}", entry.name)
        } else {
            format!("/{prefix}/{}", entry.name)
        };
        println!("{} {path}", kind_char(entry.kind));
        if entry.kind == EntryKind::Directory {
            let child_prefix = path.trim_start_matches('/');
            list_all(session, entry.inode, child_prefix, clean, depth + 1)?;
        }
    }
    Ok(())
}

fn kind_char(kind: EntryKind) -> char {
    match kind {
        EntryKind::File => '-',
        EntryKind::Directory => 'd',
        EntryKind::Symlink => 'l',
        EntryKind::Fifo => 'p',
        EntryKind::Socket => 's',
        EntryKind::CharDevice => 'c',
        EntryKind::BlockDevice => 'b',
        EntryKind::Unknown(_) => '?',
    }
}

fn print_damage(damage: &Damage) {
    println!(
        "  LOST: keys ({}, {}, {:#x}) ..= ({}, {}, {:#x})",
        damage.first_key.object_id,
        damage.first_key.item_type,
        damage.first_key.offset,
        damage.last_key.object_id,
        damage.last_key.item_type,
        damage.last_key.offset,
    );
    for reason in &damage.reasons {
        println!("    {reason}");
    }
}

fn rung_name(rung: Rung) -> &'static str {
    match rung {
        Rung::StrictEquivalent => "strict-equivalent",
        Rung::PartialRoster => "partial-roster",
        Rung::CommitRoot => "commit-root",
    }
}

fn slot_text(slot: &SlotHealth) -> String {
    match slot {
        SlotHealth::Valid => "ok".to_string(),
        SlotHealth::Corrupt(reason) => format!("BAD({reason})"),
        SlotHealth::Unreadable(error) => format!("UNREADABLE({error})"),
    }
}

fn role_text(role: &DeviceRole) -> String {
    match role {
        DeviceRole::Member(index) => format!("member {index}"),
        DeviceRole::Orphan => "orphan".to_string(),
        DeviceRole::Shadowed => "shadowed duplicate".to_string(),
        DeviceRole::Foreign => "foreign pool".to_string(),
        DeviceRole::Unidentified => "UNIDENTIFIED".to_string(),
    }
}

fn geometry_text(geometry: &Geometry) -> String {
    format!(
        "{} zones x {} KiB",
        geometry.zone_count,
        geometry.zone_size / 1024
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn print_report(paths: &[String], report: &AssemblyReport) {
    let label = report.label.as_deref().unwrap_or("?");
    let id = report
        .pool_id
        .map(|id| hex(&id.0))
        .unwrap_or_else(|| "?".to_string());
    match report.rung {
        Some(rung) => println!(
            "salvage: pool '{label}' {id}\n  view: transaction {} via {}",
            report.view_tx.unwrap_or(0),
            rung_name(rung),
        ),
        None => println!("salvage: pool '{label}' {id}\n  view: NONE (see notes)"),
    }
    println!(
        "  features: compat {:#x}, ro-compat {:#x}, incompat {:#x}",
        report.feature_compat, report.feature_ro_compat, report.feature_incompat,
    );
    println!("  devices:");
    for (index, device) in report.devices.iter().enumerate() {
        let path = paths.get(index).map(String::as_str).unwrap_or("?");
        let tx = device
            .newest_tx
            .map(|tx| format!("tx {tx}"))
            .unwrap_or_else(|| "tx ?".to_string());
        println!(
            "    {path}: {}, {tx}, slots {}/{}",
            role_text(&device.role),
            slot_text(&device.slots[0]),
            slot_text(&device.slots[1]),
        );
        for note in &device.notes {
            println!("      note: {note}");
        }
    }
    if !report.missing.is_empty() {
        println!("  missing members:");
        for missing in &report.missing {
            println!(
                "    member {} ({}), last committed tx {}, {}",
                missing.member_index,
                hex(&missing.device_id.0),
                missing.newest_tx,
                geometry_text(&missing.geometry),
            );
        }
    }
    if !report.candidates.is_empty() {
        println!("  candidate views:");
        for candidate in &report.candidates {
            let kind = match candidate.kind {
                CandidateKind::Roster => "roster",
                CandidateKind::Commit => "commit",
            };
            let status = if candidate.adopted {
                "ADOPTED"
            } else {
                "passed over"
            };
            match &candidate.note {
                Some(note) => println!("    tx {} ({kind}): {status} — {note}", candidate.tx),
                None => println!("    tx {} ({kind}): {status}", candidate.tx),
            }
        }
    }
    for note in &report.notes {
        println!("  note: {note}");
    }
    if report.rung == Some(Rung::StrictEquivalent) {
        println!(
            "  this member set would import cleanly; salvage is optional \
             ('scalefs pool import' serves it in full)"
        );
    }
}

fn report_value(paths: &[String], report: &AssemblyReport) -> Value {
    let devices: Vec<Value> = report
        .devices
        .iter()
        .enumerate()
        .map(|(index, device)| {
            object(vec![
                (
                    "path",
                    Value::Str(paths.get(index).cloned().unwrap_or_default()),
                ),
                (
                    "device_id",
                    device
                        .device_id
                        .map(|id| Value::Str(hex(&id.0)))
                        .unwrap_or(Value::Null),
                ),
                ("role", Value::Str(role_text(&device.role))),
                (
                    "newest_tx",
                    device
                        .newest_tx
                        .map(|tx| Value::Int(i128::from(tx)))
                        .unwrap_or(Value::Null),
                ),
                (
                    "slots",
                    Value::Array(
                        device
                            .slots
                            .iter()
                            .map(|s| Value::Str(slot_text(s)))
                            .collect(),
                    ),
                ),
            ])
        })
        .collect();
    let missing: Vec<Value> = report
        .missing
        .iter()
        .map(|missing| {
            object(vec![
                ("member_index", Value::Int(i128::from(missing.member_index))),
                ("device_id", Value::Str(hex(&missing.device_id.0))),
                ("newest_tx", Value::Int(i128::from(missing.newest_tx))),
            ])
        })
        .collect();
    let candidates: Vec<Value> = report
        .candidates
        .iter()
        .map(|candidate| {
            object(vec![
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
                (
                    "note",
                    candidate
                        .note
                        .clone()
                        .map(Value::Str)
                        .unwrap_or(Value::Null),
                ),
            ])
        })
        .collect();
    object(vec![
        ("tool", Value::Str("scalefs-salvage".to_string())),
        (
            "pool_id",
            report
                .pool_id
                .map(|id| Value::Str(hex(&id.0)))
                .unwrap_or(Value::Null),
        ),
        (
            "label",
            report.label.clone().map(Value::Str).unwrap_or(Value::Null),
        ),
        (
            "rung",
            report
                .rung
                .map(|rung| Value::Str(rung_name(rung).to_string()))
                .unwrap_or(Value::Null),
        ),
        (
            "view_tx",
            report
                .view_tx
                .map(|tx| Value::Int(i128::from(tx)))
                .unwrap_or(Value::Null),
        ),
        (
            "feature_incompat",
            Value::Int(i128::from(report.feature_incompat)),
        ),
        ("unknown_incompat", Value::Bool(report.unknown_incompat)),
        ("devices", Value::Array(devices)),
        ("missing", Value::Array(missing)),
        ("candidates", Value::Array(candidates)),
        (
            "notes",
            Value::Array(report.notes.iter().cloned().map(Value::Str).collect()),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use scalefs_core::{
        AllocPurpose, CaseSensitivity, CreateParams, DeviceId, FileBlockDevice, Pool, PoolId,
        member_image_len,
    };

    #[test]
    fn windows_components_cannot_leave_the_destination() {
        let hostile = [
            "..\\evil.txt",
            "C:\\Windows\\win.ini",
            "\\\\server\\share\\x",
            "name:stream",
            "con",
            "NUL.txt",
            "Com1",
            "trailing.",
            "trailing ",
            "tab\tname",
            "new\nline",
            "percent%sign",
            "q?mark",
            "...",
        ];
        for name in hostile {
            let safe = windows_safe_component(name);
            assert!(
                !safe.contains(['\\', ':', '*', '?', '"', '<', '>', '|']),
                "{name:?} -> {safe:?}"
            );
            assert!(!safe.ends_with(['.', ' ']), "{name:?} -> {safe:?}");
            assert!(!safe.chars().any(char::is_control), "{name:?} -> {safe:?}");
            let stem = safe.split('.').next().unwrap_or(&safe);
            assert!(
                !["CON", "NUL", "COM1"]
                    .iter()
                    .any(|device| stem.eq_ignore_ascii_case(device)),
                "{name:?} -> {safe:?}"
            );
            let components: Vec<_> = std::path::Path::new(safe.as_ref()).components().collect();
            assert!(
                matches!(components[..], [std::path::Component::Normal(_)]),
                "{name:?} -> {safe:?} is not one ordinary component"
            );
        }
        assert_eq!(
            windows_safe_component("report (final).pdf"),
            "report (final).pdf"
        );
        assert_ne!(
            windows_safe_component("a%5Cb"),
            windows_safe_component("a\\b")
        );
    }

    #[test]
    fn manifest_fields_cannot_forge_lines() {
        assert_eq!(manifest_text("plain name.txt"), "plain name.txt");
        assert_eq!(manifest_text("a\tb\nc\rd\\e"), "a\\tb\\nc\\rd\\\\e");
        assert_eq!(manifest_text("bell\u{7}"), "bell\\x07");
    }

    #[test]
    fn copy_out_keeps_hostile_names_inside_the_destination() {
        let scratch =
            std::env::temp_dir().join(format!("scalefs-salvage-copy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let image = scratch.join("pool.img");
        let geometry = Geometry {
            logical_block_size: 4096,
            physical_block_size: 4096,
            zone_size: 64 * 1024,
            zone_count: 64,
            erase_granularity_zones: 1,
            sequential_write_required: false,
        };
        let now = 1_700_000_000_000_000_000;
        {
            let device =
                FileBlockDevice::create(&image, member_image_len(geometry.capacity_bytes()))
                    .unwrap();
            let mut pool = Pool::create(
                device,
                CreateParams {
                    pool_id: PoolId([0x5A; 16]),
                    device_id: DeviceId([0x01; 16]),
                    geometry,
                    case_sensitivity: CaseSensitivity::InsensitivePreserving,
                    dirent_hash_seed: 1,
                    label: "hostile".to_string(),
                    created_at_ns: now,
                },
            )
            .unwrap();
            let file = pool
                .create_file(ROOT_INODE, "..\\evil.txt", 0o644, now)
                .unwrap();
            pool.write(file, 0, b"payload", now).unwrap();
            let dir = pool.mkdir(ROOT_INODE, "con", 0o755, now).unwrap();
            let inner = pool.create_file(dir, "inner\ttab.txt", 0o644, now).unwrap();
            pool.write(inner, 0, b"inner", now).unwrap();
            pool.commit(AllocPurpose::Normal, now).unwrap();
        }

        let dest = scratch.join("out");
        let manifest_path = scratch.join("manifest.txt");
        let image_arg = image.to_string_lossy().into_owned();
        let dest_arg = dest.to_string_lossy().into_owned();
        cmd_copy_out(&[
            image_arg.clone(),
            dest_arg.clone(),
            "--manifest".to_string(),
            manifest_path.to_string_lossy().into_owned(),
        ])
        .unwrap();

        assert!(!scratch.join("evil.txt").exists());
        let top: Vec<std::fs::DirEntry> = std::fs::read_dir(&dest)
            .unwrap()
            .map(|entry| entry.unwrap())
            .collect();
        assert_eq!(top.len(), 2, "{top:?}");
        let file_entry = top
            .iter()
            .find(|entry| entry.file_type().unwrap().is_file())
            .expect("the file landed in the destination");
        let dir_entry = top
            .iter()
            .find(|entry| entry.file_type().unwrap().is_dir())
            .expect("the directory landed in the destination");
        assert_eq!(std::fs::read(file_entry.path()).unwrap(), b"payload");
        assert_eq!(std::fs::read_dir(dir_entry.path()).unwrap().count(), 1);
        let manifest = std::fs::read_to_string(&manifest_path).unwrap();
        assert!(manifest.contains("inner\\ttab.txt"), "{manifest}");
        if cfg!(windows) {
            assert!(manifest.contains("saved as"), "{manifest}");
            let names: Vec<String> = top
                .iter()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect();
            assert!(names.iter().any(|name| name.contains("%5C")), "{names:?}");
            assert!(
                names.iter().any(|name| name.eq_ignore_ascii_case("%63on")),
                "{names:?}"
            );
        }

        assert!(cmd_copy_out(&[image_arg.clone(), dest_arg.clone()]).is_err());
        cmd_copy_out(&[image_arg, dest_arg, "--force".to_string()]).unwrap();
        assert_eq!(std::fs::read(file_entry.path()).unwrap(), b"payload");
        let _ = std::fs::remove_dir_all(&scratch);
    }
}
