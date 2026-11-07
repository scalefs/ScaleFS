mod bench_cmds;
mod bench_meta;
mod bench_scale;
mod daemon_cmds;
mod device_cmds;
mod file_cmds;
mod pool_cmds;
mod salvage_cmds;
mod snapshot_cmds;
mod util;

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--degraded") {
        pool_cmds::set_degraded();
        args.remove(0);
    }
    let result = match args.first().map(String::as_str) {
        None | Some("help" | "--help" | "-h") => {
            print!("{}", help_text());
            return ExitCode::SUCCESS;
        }
        Some("version" | "--version" | "-V") => {
            println!("{}", version_text());
            return ExitCode::SUCCESS;
        }
        Some("pool") => pool_cmds::cmd_pool(&args[1..]),
        Some("bench") => bench_cmds::cmd_bench(&args[1..]),
        Some("bench-meta") => bench_meta::cmd_bench_meta(&args[1..]),
        Some("bench-scale") => bench_scale::cmd_bench_scale(&args[1..]),
        Some("device") => device_cmds::cmd_device(&args[1..]),
        Some("fs") => file_cmds::cmd_fs(&args[1..]),
        Some("snapshot") => snapshot_cmds::cmd_snapshot(&args[1..]),
        Some("daemon") => daemon_cmds::cmd_daemon(&args[1..]),
        Some("fsck") => {
            return match pool_cmds::cmd_fsck(&args[1..]) {
                Ok(true) => ExitCode::SUCCESS,
                Ok(false) => ExitCode::FAILURE,
                Err(message) => {
                    eprintln!("scalefs: {message}");
                    ExitCode::from(2)
                }
            };
        }
        Some("scrub") => {
            return match pool_cmds::cmd_scrub(&args[1..]) {
                Ok(true) => ExitCode::SUCCESS,
                Ok(false) => ExitCode::FAILURE,
                Err(message) => {
                    eprintln!("scalefs: {message}");
                    ExitCode::from(2)
                }
            };
        }
        Some("salvage") => {
            return match salvage_cmds::cmd_salvage(&args[1..]) {
                Ok(true) => ExitCode::SUCCESS,
                Ok(false) => ExitCode::FAILURE,
                Err(message) => {
                    eprintln!("scalefs: {message}");
                    ExitCode::from(2)
                }
            };
        }
        Some(other) => Err(format!("unknown command '{other}' (try 'scalefs help')")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("scalefs: {message}");
            ExitCode::from(2)
        }
    }
}

fn version_text() -> String {
    format!(
        "scalefs {} (on-disk format v{})",
        env!("CARGO_PKG_VERSION"),
        scalefs_core::FORMAT_VERSION
    )
}

fn help_text() -> String {
    concat!(
        "scalefs — ScaleFS command-line tool\n",
        "\n",
        "Usage: scalefs <command> ...\n",
        "\n",
        "Pool commands (on file-backed pool images; <image> may be a\n",
        "comma-separated member list for multi-device pools, in any order;\n",
        "a leading --degraded opens a pool missing up to mirror-1 members,\n",
        "read-only, serving every byte from surviving copies):\n",
        "  pool create <image>[,<image>...] --size <n>[,<n>...]\n",
        "              [--mirror <m>] [--label <s>] [--zone-size <n>]\n",
        "              [--block-size <n>] [--case-sensitive] [--force]\n",
        "  pool add <image> <new> --size <n>   Grow the pool by a member\n",
        "  pool replace <survivors> <new> --size <n>   Replace a lost member\n",
        "  pool rebuild <image>         Finish re-mirroring after a replace\n",
        "  pool remove <images> <leaving>   Evacuate and remove a member\n",
        "  pool retire <survivors> <member>   Retire a LOST member onto the survivors\n",
        "  pool status <image>          Summarize a pool\n",
        "  pool inspect <image>         Detailed superblock and zone state\n",
        "  pool reclaim <image>         Return dead space to the free pool\n",
        "  fsck <image>                 Verify pool consistency (read-only)\n",
        "  scrub <image> [--repair]     Verify every copy; heal from mirrors\n",
        "  bench <image> [--suite all|write-files|read-files|write-stream|\n",
        "        read-stream|commit] [--files <n>] [--file-size <b>]\n",
        "        [--stream-size <b>] [--chunk <b>] [--commits <n>]\n",
        "        [--dir <name>] [--keep] [--label <s>] [--json]\n",
        "                               Engine-layer performance suites\n",
        "\n",
        "Device commands (paths like \\\\.\\PhysicalDriveN or /dev/sdX open\n",
        "raw devices anywhere an image is accepted):\n",
        "  device list                  Scan disks: size, serial, contents\n",
        "  device wipe <path> [--force]   Blank a device's ScaleFS\n",
        "                               superblocks so it can be reused\n",
        "  pool import [<path>...] [--pool <label|id-prefix>]\n",
        "                               Find a pool's members and open it\n",
        "                               (explicit candidate paths, or a scan)\n",
        "\n",
        "File commands (paths inside the pool are absolute, e.g. /dir/file):\n",
        "  fs ls <image> [path]         List a directory\n",
        "  fs stat <image> <path>       Show attributes\n",
        "  fs put <image> <local> <path>   Copy a local file into the pool\n",
        "  fs get <image> <path> <local>   Copy a file out of the pool\n",
        "  fs mkdir <image> <path>      Create a directory\n",
        "  fs mv <image> <from> <to>    Rename or move\n",
        "  fs ln <image> <existing> <new-path>   Create a hard link\n",
        "  fs rm <image> <path>         Remove a file (one name of it)\n",
        "  fs rmdir <image> <path>      Remove an empty directory\n",
        "\n",
        "Salvage commands (forensic recovery, strictly read-only: every\n",
        "device is probe-opened — no locks taken, no byte ever written —\n",
        "and damaged pools assemble best-effort instead of being refused):\n",
        "  salvage scan <device[,device...]> [--view <tx>] [--json]\n",
        "                               Identify members, damage, and the\n",
        "                               best recoverable view\n",
        "  salvage ls <devices> [path] [--all] [--view <tx>]\n",
        "                               List what still decodes (--all walks\n",
        "                               everything: damage + disconnected too)\n",
        "  salvage get <devices> <path> <local-file> [--view <tx>]\n",
        "                               Recover one file with per-range\n",
        "                               verdicts (intact / healed / recon-\n",
        "                               structed from parity / lost=zeros)\n",
        "  salvage copy-out <devices> <dest-dir> [--view <tx>]\n",
        "                               [--manifest <file>]\n",
        "                               Recover the whole reachable tree with\n",
        "                               a per-file verdict manifest\n",
        "\n",
        "Snapshot commands:\n",
        "  snapshot create <image> <name>   Snapshot the pool's current state\n",
        "  snapshot list <image>            List snapshots\n",
        "  snapshot release <image> <name>  Release a snapshot\n",
        "  snapshot ls <image> <name> [path]   List a directory in a snapshot\n",
        "  snapshot get <image> <name> <path> <local-file>   Copy a file out\n",
        "\n",
        "Daemon commands (against a running scalefsd; --endpoint overrides\n",
        "the platform default):\n",
        "  daemon ping                  Check the daemon answers\n",
        "  daemon version               Ask the daemon its versions\n",
        "  daemon attach <name> <image[,image...]> [--degraded]\n",
        "                               Open a pool and hold it under a name\n",
        "  daemon import [<path>,...] [--pool <sel>] [--name <n>] [--degraded]\n",
        "                               Scan (or probe the given paths),\n",
        "                               then attach the discovered pool\n",
        "  daemon devices               Scan disks, noting attached pools\n",
        "  daemon detach <name>         Release an attached pool\n",
        "  daemon mount <name> <dir> [--read-only]\n",
        "                               Serve the pool at a mountpoint (Linux)\n",
        "  daemon unmount <name> [--force]\n",
        "                               Unmount the pool (busy mounts refuse;\n",
        "                               --force detaches and aborts open files)\n",
        "  daemon share <pool> <name> --user <u> (--password <p> | --password-stdin) [--port <n>]\n",
        "                               Serve the pool over SMB on a loopback port\n",
        "  daemon unshare <name>        Stop an SMB share\n",
        "  daemon shares                List SMB shares\n",
        "  daemon serve <pool> [--read-only] [--unix-socket <path>] [--kernel-device <dev>] [--mount <letter>:|auto]\n",
        "               [--close-durability bounded|commit-on-close] [--close-bound-ms <1000-5000>]\n",
        "                               Serve the pool's data plane (native-volume\n",
        "                               gateways; loopback TCP by default). A written\n",
        "                               close is committed within the bound (1000 ms\n",
        "                               by default); commit-on-close commits it before\n",
        "                               the close returns\n",
        "  daemon serve-stop <pool> [--force]\n",
        "                               Stop serving the pool's data plane\n",
        "                               (--force dismounts a busy kernel volume)\n",
        "  daemon serves                List served pools\n",
        "  daemon pools                 List attached pools\n",
        "  daemon status <name>         Detailed status of an attached pool\n",
        "  daemon scrub <name> [--repair]   Verify every copy, as a job\n",
        "  daemon reclaim <name>        Return dead space, as a job\n",
        "  daemon rebuild <name>        Re-mirror after repairs, as a job\n",
        "  daemon jobs                  List jobs and their outcomes\n",
        "  daemon shutdown [--force]    Ask the daemon to stop (running\n",
        "                               jobs refuse it unless forced)\n",
        "\n",
        "Other:\n",
        "  version                      Print version information\n",
        "  help                         Show this help\n",
    )
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_text_names_the_format_version() {
        let text = version_text();
        assert!(text.starts_with("scalefs "));
        assert!(text.contains(&format!("format v{}", scalefs_core::FORMAT_VERSION)));
    }

    #[test]
    fn help_lists_commands() {
        for needle in [
            "pool create",
            "fsck",
            "fs put",
            "fs mv",
            "device wipe",
            "bench",
        ] {
            assert!(help_text().contains(needle), "{needle}");
        }
    }
}
