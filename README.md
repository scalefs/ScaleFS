# ScaleFS&trade;
ScaleFS is an open-source file system framework and volume manager.

# Goal
ScaleFS is designed to provide reliable and dynamically-resizable data storage.

A ScaleFS deployment is essentially a configurable file system.  A principal goal is to allow live migrations to revised file system configurations.

# Status
- ScaleFS is in active development (pre-production)
- Please watch this project to be notified of milestone releases

# Feature goals
- Copy-on-write file system with parity ensures stored data is always consistent
- Optional real-time parity checks on every read
- Dynamically add, remove and replace physical disks
- Increase or decrease the capacity of a disk pool at any time
- Both single-disk and multiple-disk pool deployments are supported (and live migration between the two)
- Use internal drives or external single- and multi-drive stations
- Disk pools can be moved between computers
- C-compatible libraries to enable the creation of additional data recovery tools
- Support for shielded magnetic recording (SMR) hard disks
- Initial file system driver and management applications run on Windows

# Usage overview
- Configuration options for multi-disk pools
  - Choose the number of failover disks (0 to n-1)
  - Optimize for storage space or performance (or choose an in-between balance)
  - Modify the configuration at any time
- Additional disks can be added to increase pool capacity
- Smaller-capacity disks can be replaced with larger-capacity disks to increase pool capacity
- Disks can be removed from the pool at any time (either reducing the capacity of the pool or its number of failover disks)
- If a disk fails, a user can choose to replace the disk or reduce the capacity of the disk pool
- Support for dedicated caches and dedicated metadata volumes is planned for the future

# Legal notice
ScaleFS is a trademark of ScaleFS LLC, the organization that maintains the ScaleFS open source project.

This software is licensed under a permissive open-source license (MIT). This license does not grant license to trademarks.

You may use the project's trademark(s) as reasonably required for customary use in describing the origin of the original work. Thank you for respecting the project's trademark(s).
