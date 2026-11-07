# ScaleFS&trade;
ScaleFS is an open-source file system and volume manager.

# Overview
ScaleFS is designed to provide reliable and dynamically-resizable 
data storage.

# Status: v1.0 Preview 1

This is the first public release: **ScaleFS v1.0 Preview 1**, for
Linux, with full-featured command-line tools. The daemon also builds and
serves on Windows and macOS today through a loopback SMB path.

This is a preview release; users should use it for evaluation of ScaleFS;
as with any storage solution, it should not serve as the only copy of the 
user's data.

If you encounter any software bugs, please report them via the Issues tab; 
please note that we cannot accept pull requests at this time.

# Features shipped in this release:

- **Copy-on-write engine, crash-safe by construction** — every update
  is transactional; pulling the power cord mid-write recovers to a
  consistent tree with every acknowledged write intact and every in-flight
  file either complete or cleanly absent.
- **Protection as policy, not RAID mode** — n-way mirrors or
  Reed-Solomon parity (up to 3 simultaneous drive failures), chosen
  per pool and rebalanced live. Mixed-size disks fill completely:
  parity stripes narrow automatically instead of stranding the big
  drives.
- **Dynamic membership** — add, remove, and replace disks on a live
  pool; a replacement heals automatically. Pools move between
  machines by import: identity lives on the disks, not in device
  paths or a config file.
- **A real POSIX file system** — hard links, symlinks, special files,
  extended attributes (a `setcap` capability round-trips through the
  mount), and snapshots.
- **Dual-actuator drives, understood** — ScaleFS discovers the
  independent actuator ranges of drives like Seagate's MACH.2 series
  spreads placement across both head assemblies, and — most importantly
  —  never mistakes two actuators for two disks in the failure math.
- **Every acknowledged write means it** — `fsync`, written-close, and
  SMB FLUSH acknowledgements are durability promises the crash tests
  hold us to.
- **Scrub, fsck, and salvage** — online scrubbing verifies every copy
  and repairs from redundancy; a read-only salvage engine (also
  exported as a C library for recovery tooling) assembles the best
  available view of damaged or partial member sets without writing a
  byte.
- **Serving that survives reboots** — a service daemon reassembles
  its pools at boot and restores their mounts and shares exactly as
  they were serving.
- **Audited cryptography** where it matters: the SMB server's signing
  and hashing use [aws-lc-rs](https://github.com/aws/aws-lc-rs).

# Features planned for future preview releases:

- Graphical management apps.
- Optional automatic re-protection onto surviving disks after a
  failure.
- Explicit zoned and host-managed SMR media support.
- Dedicated cache drives for enhanced read/write speeds
- Additional documentation for researchers and IT professionals

# Building from source

ScaleFS's source is written in Rust and builds on Linux, Windows, and macOS.

Prerequisites:
- A Rust toolchain (the version is pinned in `rust-toolchain.toml`; install via [rustup](https://rustup.rs) and the workspace selects it automatically).
- A C toolchain and CMake, needed by the vendored AES/SHA cryptography the SMB server links (`aws-lc-rs`, the one external dependency, confined to `scalefs-mount`):
  - **Linux**: `cc`, `make`, and `cmake` (e.g. `apt install build-essential cmake`).
  - **macOS**: the Xcode command-line tools (`xcode-select --install`) plus `cmake`.
  - **Windows**: the Visual Studio C++ build tools and CMake; the build uses prebuilt assembly, so no separate assembler is required.

Build and test the whole workspace:

```
cargo build --release
cargo test --workspace
```

The release binaries are `target/release/scalefs` (the command-line tool) and `target/release/scalefsd` (the daemon). The full local gate — formatting, lints, and tests — runs via `scripts/validate.sh` (Linux, macOS) or `scripts/validate.ps1` (Windows).

# Running ScaleFS

The `scalefs` command-line tool operates directly on pool images or disks for offline tasks; the `scalefsd` daemon owns pools at runtime and serves them as mounts and network shares. A pool is a set of one or more member images or block devices.

Create a pool and put a file into it, entirely offline:

```
scalefs pool create /path/to/pool.img --size 1G --label demo
scalefs fs put /path/to/pool.img ./notes.txt /notes.txt
scalefs fs ls  /path/to/pool.img /
scalefs fsck   /path/to/pool.img
```

Multi-disk pools take a comma-separated member list and a protection policy — a mirror width (how many disks may fail), or Reed-Solomon parity for better capacity at the same tolerance; members can be images or raw devices (`/dev/sdb`, `\\.\PhysicalDrive1`):

```
scalefs pool create /dev/sdb,/dev/sdc --size 4T --mirror 2 --label tank
scalefs pool create /dev/sdb,/dev/sdc,/dev/sdd,/dev/sde --size 4T --parity 1 --data 3 --label tank
scalefs pool status /dev/sdb,/dev/sdc
```

On parity pools, file data is striped `--data` + `--parity` disks wide (any `--parity` of them may fail; stripes narrow automatically so unequal disks fill completely), metadata stays mirrored, and `pool compact` rewrites short or partially-deleted stripes to reclaim their space.

To mount or share a pool, run the daemon and attach the pool to it:

```
scalefsd serve &                            # a background daemon
scalefs daemon attach tank /dev/sdb,/dev/sdc
```

- **Linux** mounts the pool natively through the kernel's FUSE interface — the pool becomes an ordinary local file system, in the mount table and `df`:

  ```
  scalefs daemon mount tank /mnt/tank
  ```

- **Windows and macOS** reach the pool through a loopback SMB share the daemon serves — a pure user-mode path with no third-party drivers, mounted by the built-in SMB client:

  ```
  scalefs daemon share tank tank --user backup --password s3cret --port 4455
  # Windows:
  net use Z: \\127.0.0.1\tank /TCPPORT:4455 /user:backup s3cret
  # macOS:
  mount_smbfs //backup:s3cret@127.0.0.1:4455/tank /Volumes/tank
  ```

  `scalefs daemon share` prints the exact mapping command to run.

# Legal notice
ScaleFS is a trademark of ScaleFS LLC, the organization that maintains the ScaleFS open source project.

This software is dual-licensed under permissive open-source licenses: you may use it under the terms of either the [MIT license](LICENSE-MIT) or the [Apache License 2.0](LICENSE-APACHE), at your option. These licenses do not grant license to trademarks.

You may use the project's trademark(s) as reasonably required for customary use in describing the origin of the original work. Thank you for respecting the project's trademark(s).
