
use crate::util::{Opts, format_size, parse_size};
use scalefs_ipc::client::Client;
use scalefs_ipc::endpoint::Endpoint;
use scalefs_ipc::json::{Value, object};
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub fn cmd_daemon(args: &[String]) -> Result<(), String> {
    let usage = "usage: scalefs daemon \
                 <ping|version|shutdown|pools|attach|import|devices|detach|status|\
                 mount|unmount|share|unshare|shares|scrub|reclaim|rebuild|\
                 replace|add|remove|jobs> ... \
                 [--endpoint <name-or-path>]";
    let Some((verb, rest)) = args.split_first() else {
        return Err(usage.to_string());
    };
    let opts = Opts::parse(
        rest,
        &["degraded", "repair", "force", "read-only"],
        &[
            "endpoint",
            "pool",
            "name",
            "user",
            "password",
            "port",
            "member",
            "size",
            "zone-size",
            "block-size",
        ],
    )?;
    let endpoint = match opts.value("endpoint") {
        Some(name) => Endpoint::new(name),
        None => Endpoint::default_endpoint(),
    };
    let mut client = Client::connect(&endpoint, CONNECT_TIMEOUT)?;
    match (verb.as_str(), opts.positional.as_slice()) {
        ("ping", []) => {
            client
                .call("ping", Value::Null)
                .map_err(|error| error.to_string())?;
            println!(
                "scalefsd {} answers on {}",
                client.daemon_version(),
                endpoint.as_str(),
            );
            Ok(())
        }
        ("version", []) => {
            let version = client
                .call("version", Value::Null)
                .map_err(|error| error.to_string())?;
            let field = |key: &str| {
                version
                    .get(key)
                    .and_then(Value::as_u64)
                    .map_or("?".to_string(), |value| value.to_string())
            };
            println!(
                "scalefsd {} (protocol {}, on-disk format v{})",
                version.get("daemon").and_then(Value::as_str).unwrap_or("?"),
                field("protocol"),
                field("format"),
            );
            Ok(())
        }
        ("shutdown", []) => {
            let params = if opts.flag("force") {
                object(vec![("force", Value::Bool(true))])
            } else {
                Value::Null
            };
            client
                .call("shutdown", params)
                .map_err(|error| error.to_string())?;
            println!("scalefsd on {} is shutting down", endpoint.as_str());
            Ok(())
        }
        ("attach", [name, images]) => {
            let members: Vec<Value> = images
                .split(',')
                .map(|path| Value::Str(path.to_string()))
                .collect();
            let mut params = vec![
                ("name", Value::Str(name.clone())),
                ("members", Value::Array(members)),
            ];
            if opts.flag("degraded") {
                params.push(("degraded", Value::Bool(true)));
            }
            let attached = client
                .call("pool.attach", object(params))
                .map_err(|error| error.to_string())?;
            println!("attached '{name}': {}", summary_line(&attached));
            Ok(())
        }
        ("import", candidates) => {
            let mut params = Vec::new();
            if !candidates.is_empty() {
                let paths: Vec<Value> = candidates
                    .iter()
                    .flat_map(|list| list.split(','))
                    .map(|path| Value::Str(path.to_string()))
                    .collect();
                params.push(("candidates", Value::Array(paths)));
            }
            if let Some(selector) = opts.value("pool") {
                params.push(("pool", Value::Str(selector.to_string())));
            }
            if let Some(name) = opts.value("name") {
                params.push(("name", Value::Str(name.to_string())));
            }
            if opts.flag("degraded") {
                params.push(("degraded", Value::Bool(true)));
            }
            let attached = client
                .call("pool.import", object(params))
                .map_err(|error| error.to_string())?;
            let name = attached.get("name").and_then(Value::as_str).unwrap_or("?");
            println!("imported '{name}': {}", summary_line(&attached));
            for path in attached
                .get("images")
                .and_then(Value::as_array)
                .unwrap_or_default()
            {
                if let Some(path) = path.as_str() {
                    println!("  {path}");
                }
            }
            Ok(())
        }
        ("devices", []) => {
            let listed = client
                .call("device.list", Value::Null)
                .map_err(|error| error.to_string())?;
            let devices = listed
                .get("devices")
                .and_then(Value::as_array)
                .unwrap_or_default();
            if devices.is_empty() {
                println!("no devices found (device scans may need elevation)");
            }
            for device in devices {
                let text = |key: &str| device.get(key).and_then(Value::as_str);
                let mut line = format!(
                    "{}  {}  {}",
                    text("path").unwrap_or("?"),
                    device
                        .get("size")
                        .and_then(Value::as_u64)
                        .map_or_else(|| "?".to_string(), format_size),
                    text("contents").unwrap_or("?"),
                );
                if let Some(label) = text("label") {
                    line.push_str(&format!(
                        " '{label}' {}",
                        text("pool_id")
                            .map(|id| &id[..id.len().min(12)])
                            .unwrap_or("?"),
                    ));
                }
                if let Some(name) = text("attached_as") {
                    line.push_str(&format!("  [attached as '{name}']"));
                }
                if let Some(model) = text("model") {
                    line.push_str(&format!("  — {model}"));
                }
                if let Some(serial) = text("serial") {
                    line.push_str(&format!(", serial {serial}"));
                }
                if let Some(error) = text("error") {
                    line.push_str(&format!("  ({error})"));
                }
                println!("{line}");
            }
            Ok(())
        }
        ("mount", [name, mountpoint]) => {
            let mut params = vec![
                ("name", Value::Str(name.clone())),
                ("mountpoint", Value::Str(mountpoint.clone())),
            ];
            if opts.flag("read-only") {
                params.push(("read_only", Value::Bool(true)));
            }
            let mounted = client
                .call("pool.mount", object(params))
                .map_err(|error| error.to_string())?;
            println!(
                "mounted '{name}' at {} ({})",
                mounted
                    .get("mounted_at")
                    .and_then(Value::as_str)
                    .unwrap_or(mountpoint),
                if mounted.get("read_only").and_then(Value::as_bool) == Some(true) {
                    "read-only"
                } else {
                    "read-write"
                },
            );
            Ok(())
        }
        ("unmount", [name]) => {
            client
                .call(
                    "pool.unmount",
                    object(vec![("name", Value::Str(name.clone()))]),
                )
                .map_err(|error| error.to_string())?;
            println!("unmounted '{name}'");
            Ok(())
        }
        ("share", [pool, name]) => {
            let user = opts
                .value("user")
                .ok_or("share needs --user <name>")?
                .to_string();
            let password = opts
                .value("password")
                .ok_or("share needs --password <password>")?
                .to_string();
            let mut params = vec![
                ("pool", Value::Str(pool.clone())),
                ("name", Value::Str(name.clone())),
                ("user", Value::Str(user.clone())),
                ("password", Value::Str(password)),
            ];
            if let Some(port) = opts.value("port") {
                let port: u64 = port
                    .parse()
                    .map_err(|_| format!("port must be a number, not '{port}'"))?;
                params.push(("port", Value::Int(i128::from(port))));
            }
            if opts.flag("read-only") {
                params.push(("read_only", Value::Bool(true)));
            }
            let shared = client
                .call("share.add", object(params))
                .map_err(|error| error.to_string())?;
            let port = shared.get("port").and_then(Value::as_u64).unwrap_or(4450);
            let address = shared
                .get("address")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| format!("\\\\127.0.0.1\\{name}"));
            let mode = if shared.get("read_only") == Some(&Value::Bool(true)) {
                " (read-only)"
            } else {
                ""
            };
            println!("sharing '{pool}' as '{name}' on 127.0.0.1:{port}{mode}");
            println!("  map it with:  net use X: {address} /TCPPORT:{port} /user:{user} *");
            Ok(())
        }
        ("unshare", [name]) => {
            client
                .call(
                    "share.remove",
                    object(vec![("name", Value::Str(name.clone()))]),
                )
                .map_err(|error| error.to_string())?;
            println!("stopped sharing '{name}'");
            Ok(())
        }
        ("shares", []) => {
            let listed = client
                .call("share.list", Value::Null)
                .map_err(|error| error.to_string())?;
            let shares = listed
                .get("shares")
                .and_then(Value::as_array)
                .unwrap_or_default();
            if shares.is_empty() {
                println!("no shares");
            }
            for share in shares {
                let text = |key: &str| share.get(key).and_then(Value::as_str).unwrap_or("?");
                let mode = if share.get("read_only") == Some(&Value::Bool(true)) {
                    " (read-only)"
                } else {
                    ""
                };
                println!(
                    "{}: pool '{}' on 127.0.0.1:{} (user {}){mode}",
                    text("name"),
                    text("pool"),
                    share.get("port").and_then(Value::as_u64).unwrap_or(0),
                    text("user"),
                );
            }
            Ok(())
        }
        ("detach", [name]) => {
            client
                .call(
                    "pool.detach",
                    object(vec![("name", Value::Str(name.clone()))]),
                )
                .map_err(|error| error.to_string())?;
            println!("detached '{name}'");
            Ok(())
        }
        ("pools", []) => {
            let listed = client
                .call("pool.list", Value::Null)
                .map_err(|error| error.to_string())?;
            let pools = listed
                .get("pools")
                .and_then(Value::as_array)
                .unwrap_or_default();
            if pools.is_empty() {
                println!("no pools attached");
            }
            for pool in pools {
                println!(
                    "{}: {}",
                    pool.get("name").and_then(Value::as_str).unwrap_or("?"),
                    summary_line(pool),
                );
            }
            Ok(())
        }
        ("status", [name]) => {
            let status = client
                .call(
                    "pool.status",
                    object(vec![("name", Value::Str(name.clone()))]),
                )
                .map_err(|error| error.to_string())?;
            print_status(&status);
            Ok(())
        }
        ("scrub", [name]) => {
            let mut params = vec![("name", Value::Str(name.clone()))];
            if opts.flag("repair") {
                params.push(("repair", Value::Bool(true)));
            }
            let report = run_job(&mut client, "pool.scrub", object(params))?;
            let field = |key: &str| report.get(key).and_then(Value::as_u64).unwrap_or(0);
            println!(
                "scrubbed '{name}': {} record(s), {} cop(ies) checked — {}",
                field("records_checked"),
                field("copies_checked"),
                if report.get("healthy").and_then(Value::as_bool) == Some(true) {
                    "healthy".to_string()
                } else {
                    format!(
                        "{} bad ({} repaired, {} unrepairable, {} missing)",
                        field("copies_bad"),
                        field("copies_repaired"),
                        field("copies_unrepairable"),
                        field("copies_missing"),
                    )
                },
            );
            Ok(())
        }
        ("reclaim", [name]) => {
            let params = object(vec![("name", Value::Str(name.clone()))]);
            let report = run_job(&mut client, "pool.reclaim", params)?;
            let field = |key: &str| report.get(key).and_then(Value::as_u64).unwrap_or(0);
            println!(
                "reclaimed on '{name}': {} zone(s) reset, {} freed",
                field("zones_reset"),
                format_size(field("bytes_reclaimed")),
            );
            Ok(())
        }
        ("rebuild", [name]) => {
            let params = object(vec![("name", Value::Str(name.clone()))]);
            let report = run_job(&mut client, "pool.rebuild", params)?;
            let field = |key: &str| report.get(key).and_then(Value::as_u64).unwrap_or(0);
            println!(
                "rebuilt on '{name}': {} record(s) healed, {} new cop(ies)",
                field("records_rebuilt"),
                field("copies_written"),
            );
            Ok(())
        }
        ("replace", [pool, target]) => {
            let mut params = vec![
                ("name", Value::Str(pool.clone())),
                ("target", Value::Str(target.clone())),
            ];
            push_member(&mut params, &opts)?;
            push_geometry(&mut params, &opts)?;
            if opts.flag("force") {
                params.push(("force", Value::Bool(true)));
            }
            let report = run_job(&mut client, "pool.replace", object(params))?;
            let field = |key: &str| report.get(key).and_then(Value::as_u64).unwrap_or(0);
            if report.get("rebuilt").and_then(Value::as_bool) == Some(true) {
                println!(
                    "replaced member {} of '{pool}' with {target}; rebuilt {} record(s) \
                     ({} new cop(ies))",
                    field("replaced"),
                    field("records_rebuilt"),
                    field("copies_written"),
                );
            } else {
                let still: Vec<String> = report
                    .get("still_missing")
                    .and_then(Value::as_array)
                    .map(|missing| {
                        missing
                            .iter()
                            .filter_map(Value::as_u64)
                            .map(|index| index.to_string())
                            .collect()
                    })
                    .unwrap_or_default();
                println!(
                    "replaced member {} of '{pool}' with {target}; still missing \
                     member(s) {} — replace them, then rebuild",
                    field("replaced"),
                    still.join(", "),
                );
            }
            Ok(())
        }
        ("add", [pool, target]) => {
            let mut params = vec![
                ("name", Value::Str(pool.clone())),
                ("target", Value::Str(target.clone())),
            ];
            push_geometry(&mut params, &opts)?;
            if opts.flag("force") {
                params.push(("force", Value::Bool(true)));
            }
            let report = run_job(&mut client, "pool.add", object(params))?;
            let field = |key: &str| report.get(key).and_then(Value::as_u64).unwrap_or(0);
            println!(
                "added {target} to '{pool}' as member {} ({}): now {} member(s)",
                field("member"),
                format_size(field("capacity")),
                field("members"),
            );
            Ok(())
        }
        ("remove", [pool]) => {
            let mut params = vec![("name", Value::Str(pool.clone()))];
            push_member(&mut params, &opts)?;
            if !params.iter().any(|(key, _)| *key == "member") {
                return Err(
                    "remove needs --member <index-or-device-id> (see 'daemon status')".to_string(),
                );
            }
            let report = run_job(&mut client, "pool.remove", object(params))?;
            let field = |key: &str| report.get(key).and_then(Value::as_u64).unwrap_or(0);
            println!(
                "removed member {} from '{pool}': now {} member(s)",
                field("removed"),
                field("members"),
            );
            Ok(())
        }
        ("jobs", []) => {
            let listed = client
                .call("job.list", Value::Null)
                .map_err(|error| error.to_string())?;
            let jobs = listed
                .get("jobs")
                .and_then(Value::as_array)
                .unwrap_or_default();
            if jobs.is_empty() {
                println!("no jobs");
            }
            for job in jobs {
                let mut line = format!(
                    "job {}: {} on '{}' — {}",
                    job.get("id").and_then(Value::as_u64).unwrap_or(0),
                    job.get("kind").and_then(Value::as_str).unwrap_or("?"),
                    job.get("pool").and_then(Value::as_str).unwrap_or("?"),
                    job.get("state").and_then(Value::as_str).unwrap_or("?"),
                );
                if let Some(error) = job.get("error").and_then(Value::as_str) {
                    line.push_str(&format!(" ({error})"));
                }
                println!("{line}");
            }
            Ok(())
        }
        _ => Err(format!("unknown daemon command or arguments ({usage})")),
    }
}

fn push_member(params: &mut Vec<(&str, Value)>, opts: &Opts) -> Result<(), String> {
    let Some(member) = opts.value("member") else {
        return Ok(());
    };
    if let Ok(index) = member.parse::<u16>() {
        params.push(("member", Value::Int(i128::from(index))));
    } else if !member.is_empty() && member.chars().all(|c| c.is_ascii_hexdigit()) {
        params.push(("member", Value::Str(member.to_ascii_lowercase())));
    } else {
        return Err("--member takes a roster index or a device id in hex".to_string());
    }
    Ok(())
}

fn push_geometry(params: &mut Vec<(&str, Value)>, opts: &Opts) -> Result<(), String> {
    for (flag, key) in [
        ("size", "size"),
        ("zone-size", "zone_size"),
        ("block-size", "block_size"),
    ] {
        if let Some(text) = opts.value(flag) {
            params.push((key, Value::Int(i128::from(parse_size(text)?))));
        }
    }
    Ok(())
}

fn run_job(client: &mut Client, op: &str, params: Value) -> Result<Value, String> {
    let started = client.call(op, params).map_err(|error| error.to_string())?;
    let id = started
        .get("job")
        .and_then(Value::as_u64)
        .ok_or("the daemon did not return a job id")?;
    let deadline = std::time::Instant::now() + Duration::from_secs(24 * 60 * 60);
    loop {
        let status = client
            .call(
                "job.status",
                object(vec![("id", Value::Int(i128::from(id)))]),
            )
            .map_err(|error| error.to_string())?;
        match status.get("state").and_then(Value::as_str) {
            Some("running") => {
                if std::time::Instant::now() >= deadline {
                    return Err(format!("job {id} is still running; see 'daemon jobs'"));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Some("done") => return Ok(status.get("result").cloned().unwrap_or(Value::Null)),
            Some("failed") => {
                return Err(status
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("the job failed")
                    .to_string());
            }
            _ => return Err(format!("job {id} reported an unknown state")),
        }
    }
}

fn protection_phrase(pool: &Value) -> Option<String> {
    let mirror = pool.get("mirror").and_then(Value::as_u64).unwrap_or(1);
    let parity = pool.get("parity").and_then(Value::as_u64).unwrap_or(0);
    let data = pool.get("data").and_then(Value::as_u64).unwrap_or(1);
    if parity > 0 {
        Some(format!("{data} data + {parity} parity (RS)"))
    } else if mirror > 1 {
        Some(format!("{mirror}-way mirror"))
    } else {
        None
    }
}

fn summary_line(pool: &Value) -> String {
    let label = pool.get("label").and_then(Value::as_str).unwrap_or("?");
    let members = pool.get("members").and_then(Value::as_u64).unwrap_or(0);
    let tx = pool.get("tx").and_then(Value::as_u64).unwrap_or(0);
    let capacity = pool.get("capacity").and_then(Value::as_u64).unwrap_or(0);
    let mut line = format!(
        "label '{label}', {members} member(s), {}, transaction {tx}",
        format_size(capacity),
    );
    if let Some(protection) = protection_phrase(pool) {
        line.push_str(&format!(", {protection}"));
    }
    if pool.get("degraded").and_then(Value::as_bool) == Some(true) {
        line.push_str(", DEGRADED");
    } else if pool.get("read_only").and_then(Value::as_bool) == Some(true) {
        line.push_str(", read-only");
    }
    line
}

fn print_status(status: &Value) {
    println!(
        "Name:         {}",
        status.get("name").and_then(Value::as_str).unwrap_or("?"),
    );
    println!(
        "Label:        {}",
        status.get("label").and_then(Value::as_str).unwrap_or("?"),
    );
    println!(
        "Pool id:      {}",
        status.get("pool_id").and_then(Value::as_str).unwrap_or("?"),
    );
    println!(
        "Transaction:  {}",
        status.get("tx").and_then(Value::as_u64).unwrap_or(0),
    );
    println!(
        "Mode:         {}",
        if status.get("read_only").and_then(Value::as_bool) == Some(true) {
            "read-only"
        } else {
            "read-write"
        },
    );
    if let Some(capacity) = status.get("capacity").and_then(Value::as_u64) {
        println!("Capacity:     {}", format_size(capacity));
    }
    let mirror = status.get("mirror").and_then(Value::as_u64).unwrap_or(1);
    let parity = status.get("parity").and_then(Value::as_u64).unwrap_or(0);
    if parity > 0 {
        println!(
            "Protection:   {} data + {parity} parity (RS) · metadata {mirror}-way mirror",
            status.get("data").and_then(Value::as_u64).unwrap_or(1),
        );
    } else if mirror > 1 {
        println!("Protection:   {mirror}-way mirror");
    }
    if status.get("degraded").and_then(Value::as_bool) == Some(true) {
        let missing = status
            .get("missing")
            .and_then(Value::as_array)
            .map_or(0, <[Value]>::len);
        println!("State:        DEGRADED — {missing} member(s) missing");
    }
    if let Some(orphans) = status.get("orphans").and_then(Value::as_array)
        && !orphans.is_empty()
    {
        println!(
            "Orphans:      {} supplied device(s) not in the pool's current membership",
            orphans.len(),
        );
    }
    if let Some(members) = status.get("members_detail").and_then(Value::as_array) {
        println!("Members:");
        for member in members {
            println!(
                "  {:>3}  {}  {}",
                member.get("index").and_then(Value::as_u64).unwrap_or(0),
                member
                    .get("device_id")
                    .and_then(Value::as_str)
                    .unwrap_or("?"),
                member.get("state").and_then(Value::as_str).unwrap_or("?"),
            );
        }
    }
}
