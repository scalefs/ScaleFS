use scalefs_core::{
    AllocPurpose, BlockDevice, DirEntry, EntryKind, HashedEntry, InodeAttrs, MAX_NAME_LEN,
    MODE_TYPE_MASK, Pool, ROOT_INODE, ScaleFsError, SharedDevice,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};

const _: () = assert!(ROOT_INODE == 1);

pub(crate) const DEBOUNCE_QUIET: Duration = Duration::from_millis(500);
const STALL_RETRY: Duration = Duration::from_secs(1);
const DEBOUNCE_BYTES: u64 = 64 * 1024 * 1024;
const DEBOUNCE_MAX_AGE: Duration = Duration::from_secs(5);
const METADATA_CHARGE: u64 = 4096;
const MODE_SETGID: u32 = 0o2000;

pub const ORPHANAGE: &str = ".scalefs-orphans";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountError {
    NotFound,
    NotDirectory,
    IsDirectory,
    Exists,
    NotEmpty,
    NoSpace,
    TooManyLinks,
    NotSupported,
    NameTooLong,
    InvalidName,
    Invalid,
    ReadOnly,
    Denied,
    Io,
}

#[derive(Debug, Clone, Copy)]
pub struct MountAttr {
    pub inode: u64,
    pub attrs: InodeAttrs,
    pub blksize: u32,
    pub deferred: bool,
    pub rdev: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct StatFs {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub bsize: u32,
    pub namelen: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum TimeChange {
    Now,
    Set(i64),
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SetAttr {
    pub size: Option<u64>,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub atime: Option<TimeChange>,
    pub mtime: Option<TimeChange>,
    pub ctime: Option<i64>,
    pub attributes: Option<u32>,
    pub crtime: Option<i64>,
    pub bsd_flags: Option<u32>,
}

pub struct MountCore<D: SharedDevice> {
    pool: Arc<RwLock<Pool<D>>>,
    writes: Option<WriteSide>,
    state: Mutex<MountState>,
}

#[derive(Default)]
struct MountState {
    open_counts: BTreeMap<u64, u32>,
    deferred: BTreeSet<u64>,
}

struct WriteSide {
    durability: Arc<Durability>,
    timer: Mutex<Option<std::thread::JoinHandle<()>>>,
}

struct Durability {
    dirt: Mutex<Dirt>,
    signal: Condvar,
}

struct Dirt {
    dirty: bool,
    staged_bytes: u64,
    last_write: Instant,
    first_dirty: Option<Instant>,
    stalled: bool,
    shutdown: bool,
    poisoned: bool,
    epoch: u64,
    committed: u64,
    committing: bool,
}

impl Durability {
    fn new() -> Self {
        Durability {
            dirt: Mutex::new(Dirt {
                dirty: false,
                staged_bytes: 0,
                last_write: Instant::now(),
                first_dirty: None,
                stalled: false,
                shutdown: false,
                poisoned: false,
                epoch: 0,
                committed: 0,
                committing: false,
            }),
            signal: Condvar::new(),
        }
    }

    fn mark(&self, bytes: u64) {
        if let Ok(mut dirt) = self.dirt.lock() {
            if !dirt.dirty {
                dirt.first_dirty = Some(Instant::now());
            }
            dirt.dirty = true;
            dirt.stalled = false;
            dirt.staged_bytes = dirt.staged_bytes.saturating_add(bytes);
            dirt.last_write = Instant::now();
            dirt.epoch += 1;
        }
        self.signal.notify_all();
    }
}

pub(crate) fn now_ns() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(since) => i64::try_from(since.as_nanos()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

fn mount_error(error: &ScaleFsError) -> MountError {
    match error {
        ScaleFsError::NotFound => MountError::NotFound,
        ScaleFsError::NotDirectory => MountError::NotDirectory,
        ScaleFsError::IsDirectory => MountError::IsDirectory,
        ScaleFsError::InvalidArgument(_) => MountError::Invalid,
        ScaleFsError::AlreadyExists => MountError::Exists,
        ScaleFsError::DirectoryNotEmpty => MountError::NotEmpty,
        ScaleFsError::TooManyLinks => MountError::TooManyLinks,
        ScaleFsError::OutOfSpace => MountError::NoSpace,
        ScaleFsError::Unsupported(_) => MountError::ReadOnly,
        _ => MountError::Io,
    }
}

fn commit_ticketed<D: SharedDevice>(
    pool: &RwLock<Pool<D>>,
    durability: &Durability,
) -> Result<(), MountError> {
    let (ticket, covers, staged_at_plan) = {
        let mut pool = pool.write().map_err(|_| MountError::Io)?;
        let (covers, staged_at_plan) = {
            let dirt = durability.dirt.lock().map_err(|_| MountError::Io)?;
            if dirt.poisoned {
                return Err(MountError::Io);
            }
            if !dirt.dirty {
                return Ok(());
            }
            (dirt.epoch, dirt.staged_bytes)
        };
        match pool.commit_plan(AllocPurpose::Normal, now_ns()) {
            Ok(ticket) => (ticket, covers, staged_at_plan),
            Err(error) => {
                if let Ok(mut dirt) = durability.dirt.lock() {
                    dirt.stalled = true;
                }
                durability.signal.notify_all();
                return Err(mount_error(&error));
            }
        }
    };
    let executed = ticket.execute();
    let result = {
        let mut pool = pool.write().map_err(|_| MountError::Io)?;
        let settle = |durability: &Durability| {
            if let Ok(mut dirt) = durability.dirt.lock() {
                dirt.committed = dirt.committed.max(covers);
                dirt.dirty = dirt.epoch > covers;
                dirt.staged_bytes = dirt.staged_bytes.saturating_sub(staged_at_plan);
                dirt.stalled = false;
                dirt.first_dirty = dirt.dirty.then(Instant::now);
            }
        };
        match executed {
            Ok(done) => {
                pool.commit_publish(done);
                settle(durability);
                Ok(())
            }
            Err(aborted) => match pool.commit_abandon(aborted) {
                Ok(outcome) => {
                    if let scalefs_core::pool::CommitOutcome::Degraded(degrade) = &outcome {
                        eprintln!(
                            "scalefs-mount: member {} failed while committing; the pending \
                                 writes were committed onto the surviving members (tx {}) and the \
                                 pool is now DEGRADED and READ-ONLY — replace or retire the member \
                                 to restore writes",
                            degrade.member, degrade.tx_id,
                        );
                    }
                    settle(durability);
                    Ok(())
                }
                Err(error) => {
                    if let Ok(mut dirt) = durability.dirt.lock() {
                        dirt.stalled = true;
                    }
                    Err(mount_error(&error))
                }
            },
        }
    };
    durability.signal.notify_all();
    result
}

fn commit_group<D: SharedDevice>(
    pool: &RwLock<Pool<D>>,
    durability: &Durability,
) -> Result<(), MountError> {
    {
        let mut dirt = durability.dirt.lock().map_err(|_| MountError::Io)?;
        let needed = dirt.epoch;
        loop {
            if dirt.poisoned {
                return Err(MountError::Io);
            }
            if dirt.committed >= needed {
                return Ok(());
            }
            if !dirt.committing {
                break;
            }
            dirt = durability.signal.wait(dirt).map_err(|_| MountError::Io)?;
        }
        dirt.committing = true;
    }
    let _ticket = TicketRelease(durability);
    commit_ticketed(pool, durability)
}

struct TicketRelease<'a>(&'a Durability);

impl Drop for TicketRelease<'_> {
    fn drop(&mut self) {
        if let Ok(mut dirt) = self.0.dirt.lock() {
            dirt.committing = false;
        }
        self.0.signal.notify_all();
    }
}

fn debounce_loop<D: SharedDevice>(pool: &Arc<RwLock<Pool<D>>>, durability: &Arc<Durability>) {
    loop {
        {
            let Ok(mut dirt) = durability.dirt.lock() else {
                return;
            };
            loop {
                if dirt.shutdown || dirt.poisoned {
                    return;
                }
                if dirt.dirty && !dirt.stalled {
                    if dirt.staged_bytes >= DEBOUNCE_BYTES {
                        break;
                    }
                    if dirt
                        .first_dirty
                        .is_some_and(|first| first.elapsed() >= DEBOUNCE_MAX_AGE)
                    {
                        break;
                    }
                    let since = dirt.last_write.elapsed();
                    if since >= DEBOUNCE_QUIET {
                        break;
                    }
                    let quiet_left = DEBOUNCE_QUIET - since;
                    let nap = match dirt.first_dirty {
                        Some(first) => {
                            quiet_left.min(DEBOUNCE_MAX_AGE.saturating_sub(first.elapsed()))
                        }
                        None => quiet_left,
                    };
                    let Ok(waited) = durability.signal.wait_timeout(dirt, nap) else {
                        return;
                    };
                    dirt = waited.0;
                } else if dirt.dirty {
                    let Ok((waited, timed_out)) = durability.signal.wait_timeout(dirt, STALL_RETRY)
                    else {
                        return;
                    };
                    dirt = waited;
                    if timed_out.timed_out() {
                        break;
                    }
                } else {
                    let Ok(waited) = durability.signal.wait(dirt) else {
                        return;
                    };
                    dirt = waited;
                }
            }
        }
        if commit_group(pool, durability).is_err() && pool.is_poisoned() {
            return;
        }
    }
}

fn sweep_orphanage<D: BlockDevice>(pool: &mut Pool<D>) -> bool {
    let Ok(entry) = pool.lookup(ROOT_INODE, ORPHANAGE) else {
        return false;
    };
    let mut changed = false;
    if let Ok(entries) = pool.readdir(entry.inode) {
        for child in entries {
            changed |= reap_orphan(pool, entry.inode, &child.name);
        }
    }
    changed |= pool.rmdir(ROOT_INODE, ORPHANAGE, now_ns()).is_ok();
    changed
}

fn reap_orphan<D: BlockDevice>(pool: &mut Pool<D>, orphanage: u64, name: &str) -> bool {
    let now = now_ns();
    pool.unlink(orphanage, name, now).is_ok() || pool.rmdir(orphanage, name, now).is_ok()
}

fn orphan_object<D: BlockDevice>(
    pool: &mut Pool<D>,
    parent: u64,
    name: &str,
    inode: u64,
) -> Result<(), MountError> {
    let now = now_ns();
    if pool.lookup(ROOT_INODE, ORPHANAGE).is_err() {
        pool.mkdir(ROOT_INODE, ORPHANAGE, 0o700, now)
            .map_err(|e| mount_error(&e))?;
    }
    let orphanage = pool
        .lookup(ROOT_INODE, ORPHANAGE)
        .map_err(|e| mount_error(&e))?
        .inode;
    pool.rename(parent, name, orphanage, &format!("o-{inode}"), now)
        .map_err(|e| mount_error(&e))
}

fn claim_ownership<D: BlockDevice>(
    pool: &mut Pool<D>,
    parent: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    is_dir: bool,
) -> Result<(), MountError> {
    let parent_attrs = pool.getattr(parent).map_err(|e| mount_error(&e))?;
    let setgid_parent = parent_attrs.mode & MODE_SETGID != 0;
    pool.update_attrs(inode, |attrs| {
        attrs.uid = uid;
        attrs.gid = if setgid_parent { parent_attrs.gid } else { gid };
        if setgid_parent && is_dir {
            attrs.mode |= MODE_SETGID;
        }
    })
    .map_err(|e| mount_error(&e))
}

fn is_orphanage_name(name: &str) -> bool {
    name.eq_ignore_ascii_case(ORPHANAGE)
}

pub fn is_reserved(parent: u64, name: &str) -> bool {
    parent == ROOT_INODE && is_orphanage_name(name)
}

fn xattr_namespace_allowed(name: &str) -> bool {
    name.starts_with("user.")
        || name.starts_with("security.")
        || name.starts_with("trusted.")
        || name.starts_with("com.apple.")
}

impl<D: SharedDevice> MountCore<D> {
    pub fn read_only(pool: Arc<RwLock<Pool<D>>>) -> Self {
        MountCore {
            pool,
            writes: None,
            state: Mutex::new(MountState::default()),
        }
    }

    pub fn read_write(pool: Arc<RwLock<Pool<D>>>) -> Self
    where
        D: Send + Sync + 'static,
    {
        let durability = Arc::new(Durability::new());
        if let Ok(mut pool) = pool.write()
            && sweep_orphanage(&mut pool)
        {
            durability.mark(METADATA_CHARGE);
        }
        let timer = {
            let pool = Arc::clone(&pool);
            let durability = Arc::clone(&durability);
            std::thread::Builder::new()
                .name("scalefs-debounce".to_string())
                .spawn(move || {
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        debounce_loop(&pool, &durability)
                    }));
                    if outcome.is_err() {
                        if let Ok(mut dirt) = durability.dirt.lock() {
                            dirt.poisoned = true;
                        }
                        durability.signal.notify_all();
                        eprintln!(
                            "scalefs-mount: the debounce timer panicked; \
                             the core is poisoned and serves nothing further"
                        );
                    }
                })
                .ok()
        };
        MountCore {
            pool,
            writes: Some(WriteSide {
                durability,
                timer: Mutex::new(timer),
            }),
            state: Mutex::new(MountState::default()),
        }
    }

    pub fn is_read_only(&self) -> bool {
        self.writes.is_none()
    }

    pub fn poison(&self) {
        let Some(writes) = &self.writes else {
            return;
        };
        if let Ok(mut dirt) = writes.durability.dirt.lock() {
            dirt.poisoned = true;
        }
        writes.durability.signal.notify_all();
    }

    pub fn shutdown(&self) -> Result<(), MountError> {
        let Some(writes) = &self.writes else {
            return Ok(());
        };
        let poisoned = match writes.durability.dirt.lock() {
            Ok(mut dirt) => {
                dirt.shutdown = true;
                dirt.poisoned
            }
            Err(_) => return Err(MountError::Io),
        };
        writes.durability.signal.notify_all();
        if let Some(timer) = writes.timer.lock().ok().and_then(|mut t| t.take()) {
            let _ = timer.join();
        }
        if let Ok(mut state) = self.state.lock() {
            state.deferred.clear();
            state.open_counts.clear();
        }
        if poisoned {
            return Ok(());
        }
        {
            let mut pool = self.pool.write().map_err(|_| MountError::Io)?;
            if sweep_orphanage(&mut pool) {
                writes.durability.mark(METADATA_CHARGE);
            }
        }
        commit_group(&self.pool, &writes.durability)
    }

    fn durability(&self) -> Result<&Arc<Durability>, MountError> {
        self.writes
            .as_ref()
            .map(|w| &w.durability)
            .ok_or(MountError::ReadOnly)
    }

    fn poisoned(&self) -> bool {
        let Some(writes) = &self.writes else {
            return false;
        };
        match writes.durability.dirt.lock() {
            Ok(dirt) => dirt.poisoned,
            Err(_) => true,
        }
    }

    fn with_pool<R>(&self, op: impl FnOnce(&Pool<D>) -> R) -> Result<R, MountError> {
        if self.poisoned() {
            return Err(MountError::Io);
        }
        match self.pool.read() {
            Ok(pool) => Ok(op(&pool)),
            Err(_) => Err(MountError::Io),
        }
    }

    fn with_pool_mut<R>(&self, op: impl FnOnce(&mut Pool<D>) -> R) -> Result<R, MountError> {
        if self.poisoned() {
            return Err(MountError::Io);
        }
        match self.pool.write() {
            Ok(mut pool) => Ok(op(&mut pool)),
            Err(_) => Err(MountError::Io),
        }
    }

    fn is_deferred(&self, inode: u64) -> bool {
        self.state
            .lock()
            .map(|s| s.deferred.contains(&inode))
            .unwrap_or(false)
    }

    fn make_attr(&self, pool: &Pool<D>, inode: u64) -> Result<MountAttr, MountError> {
        let attrs = pool.getattr(inode).map_err(|e| mount_error(&e))?;
        let rdev = if attrs.is_device() {
            pool.device_rdev(inode).map_err(|e| mount_error(&e))?
        } else {
            0
        };
        Ok(MountAttr {
            inode,
            attrs,
            blksize: pool.superblock().geometry.logical_block_size,
            deferred: self.is_deferred(inode),
            rdev,
        })
    }

    pub fn getattr(&self, inode: u64) -> Result<MountAttr, MountError> {
        self.with_pool(|pool| self.make_attr(pool, inode))?
    }

    pub fn lookup(&self, parent: u64, name: &str) -> Result<MountAttr, MountError> {
        if is_reserved(parent, name) {
            return Err(MountError::NotFound);
        }
        self.with_pool(|pool| {
            let entry = pool.lookup(parent, name).map_err(|e| mount_error(&e))?;
            self.make_attr(pool, entry.inode)
        })?
    }

    pub fn readdir(&self, inode: u64) -> Result<Vec<DirEntry>, MountError> {
        self.with_pool(|pool| {
            let entries = pool.readdir(inode).map_err(|e| mount_error(&e))?;
            Ok(entries
                .into_iter()
                .filter(|entry| !(inode == ROOT_INODE && is_orphanage_name(&entry.name)))
                .collect())
        })?
    }

    pub fn readdir_hashed(&self, inode: u64) -> Result<Vec<HashedEntry>, MountError> {
        self.with_pool(|pool| {
            let entries = pool.readdir_hashed(inode).map_err(|e| mount_error(&e))?;
            Ok(entries
                .into_iter()
                .filter(|hashed| !(inode == ROOT_INODE && is_orphanage_name(&hashed.entry.name)))
                .collect())
        })?
    }

    pub fn read(&self, inode: u64, offset: u64, len: usize) -> Result<Vec<u8>, MountError> {
        self.with_pool(|pool| pool.read(inode, offset, len).map_err(|e| mount_error(&e)))?
    }

    pub fn statfs(&self) -> Result<StatFs, MountError> {
        self.with_pool(|pool| {
            let block = u64::from(pool.superblock().geometry.logical_block_size);
            let mut capacity = 0u64;
            let mut free = 0u64;
            for allocator in pool.allocators() {
                capacity += allocator.geometry().capacity_bytes();
                let zone_size = allocator.geometry().zone_size;
                for zone in allocator.zones() {
                    if zone.class.is_none() && allocator.is_usable_zone(zone.zone_index) {
                        free += zone_size;
                    }
                }
            }
            StatFs {
                blocks: capacity / block,
                bfree: free / block,
                bavail: free / block,
                bsize: block as u32,
                namelen: MAX_NAME_LEN as u32,
            }
        })
    }

    pub fn walk(&self, path: &str) -> Result<u64, MountError> {
        self.with_pool(|pool| {
            let mut inode = ROOT_INODE;
            for component in path.split(['\\', '/']).filter(|c| !c.is_empty()) {
                if component.len() > MAX_NAME_LEN {
                    return Err(MountError::NameTooLong);
                }
                if is_reserved(inode, component) {
                    return Err(MountError::NotFound);
                }
                inode = pool
                    .lookup(inode, component)
                    .map_err(|e| mount_error(&e))?
                    .inode;
            }
            Ok(inode)
        })?
    }

    pub fn retain(&self, inode: u64) {
        if let Ok(mut state) = self.state.lock() {
            *state.open_counts.entry(inode).or_insert(0) += 1;
        }
    }

    pub fn release(&self, inode: u64) {
        let free = {
            let Ok(mut state) = self.state.lock() else {
                return;
            };
            let Some(count) = state.open_counts.get_mut(&inode) else {
                return;
            };
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.open_counts.remove(&inode);
                state.deferred.remove(&inode)
            } else {
                false
            }
        };
        if !free {
            return;
        }
        if let Ok(durability) = self.durability() {
            let _ = self.with_pool_mut(|pool| {
                if let Ok(orphanage) = pool.lookup(ROOT_INODE, ORPHANAGE)
                    && reap_orphan(pool, orphanage.inode, &format!("o-{inode}"))
                {
                    durability.mark(METADATA_CHARGE);
                }
            });
        }
    }

    pub fn create(
        &self,
        parent: u64,
        name: &str,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<MountAttr, MountError> {
        let durability = self.durability()?;
        if is_reserved(parent, name) {
            return Err(MountError::Denied);
        }
        self.with_pool_mut(|pool| {
            let inode = pool
                .create_file(parent, name, mode & !MODE_TYPE_MASK, now_ns())
                .map_err(|e| mount_error(&e))?;
            claim_ownership(pool, parent, inode, uid, gid, false)?;
            durability.mark(METADATA_CHARGE);
            self.make_attr(pool, inode)
        })?
    }

    pub fn mkdir(
        &self,
        parent: u64,
        name: &str,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<MountAttr, MountError> {
        let durability = self.durability()?;
        if is_reserved(parent, name) {
            return Err(MountError::Denied);
        }
        self.with_pool_mut(|pool| {
            let inode = pool
                .mkdir(parent, name, mode & !MODE_TYPE_MASK, now_ns())
                .map_err(|e| mount_error(&e))?;
            claim_ownership(pool, parent, inode, uid, gid, true)?;
            durability.mark(METADATA_CHARGE);
            self.make_attr(pool, inode)
        })?
    }

    pub fn symlink(
        &self,
        parent: u64,
        name: &str,
        target: &[u8],
        uid: u32,
        gid: u32,
    ) -> Result<MountAttr, MountError> {
        let durability = self.durability()?;
        if is_reserved(parent, name) {
            return Err(MountError::Denied);
        }
        self.with_pool_mut(|pool| {
            let inode = pool
                .symlink(parent, name, target, now_ns())
                .map_err(|e| mount_error(&e))?;
            claim_ownership(pool, parent, inode, uid, gid, false)?;
            durability.mark(METADATA_CHARGE);
            self.make_attr(pool, inode)
        })?
    }

    pub fn readlink(&self, inode: u64) -> Result<Vec<u8>, MountError> {
        self.with_pool(|pool| pool.readlink(inode).map_err(|e| mount_error(&e)))?
    }

    pub fn mknod(
        &self,
        parent: u64,
        name: &str,
        mode: u32,
        rdev: u64,
        uid: u32,
        gid: u32,
    ) -> Result<MountAttr, MountError> {
        let durability = self.durability()?;
        if is_reserved(parent, name) {
            return Err(MountError::Denied);
        }
        self.with_pool_mut(|pool| {
            let inode = pool
                .mknod(parent, name, mode, rdev, now_ns())
                .map_err(|e| mount_error(&e))?;
            claim_ownership(pool, parent, inode, uid, gid, false)?;
            durability.mark(METADATA_CHARGE);
            self.make_attr(pool, inode)
        })?
    }

    pub fn device_rdev(&self, inode: u64) -> Result<u64, MountError> {
        self.with_pool(|pool| pool.device_rdev(inode).map_err(|e| mount_error(&e)))?
    }

    pub fn setxattr(
        &self,
        inode: u64,
        name: &str,
        value: &[u8],
        flags: u32,
    ) -> Result<(), MountError> {
        let durability = self.durability()?;
        if !xattr_namespace_allowed(name) {
            return Err(MountError::NotSupported);
        }
        self.with_pool_mut(|pool| {
            pool.set_xattr(inode, name, value, flags, now_ns())
                .map_err(|e| mount_error(&e))?;
            durability.mark(METADATA_CHARGE);
            Ok(())
        })?
    }

    pub fn getxattr(&self, inode: u64, name: &str) -> Result<Vec<u8>, MountError> {
        if !xattr_namespace_allowed(name) {
            return Err(MountError::NotSupported);
        }
        self.with_pool(|pool| pool.get_xattr(inode, name).map_err(|e| mount_error(&e)))?
    }

    pub fn listxattr(&self, inode: u64) -> Result<Vec<String>, MountError> {
        self.with_pool(|pool| pool.list_xattrs(inode).map_err(|e| mount_error(&e)))?
    }

    pub fn removexattr(&self, inode: u64, name: &str) -> Result<(), MountError> {
        let durability = self.durability()?;
        if !xattr_namespace_allowed(name) {
            return Err(MountError::NotSupported);
        }
        self.with_pool_mut(|pool| {
            pool.remove_xattr(inode, name, now_ns())
                .map_err(|e| mount_error(&e))?;
            durability.mark(METADATA_CHARGE);
            Ok(())
        })?
    }

    pub fn link(
        &self,
        source: u64,
        new_parent: u64,
        new_name: &str,
    ) -> Result<MountAttr, MountError> {
        let durability = self.durability()?;
        if is_reserved(new_parent, new_name) {
            return Err(MountError::Denied);
        }
        self.with_pool_mut(|pool| {
            {
                let state = self.state.lock().map_err(|_| MountError::Io)?;
                if state.deferred.contains(&source) {
                    return Err(MountError::NotFound);
                }
            }
            pool.link(source, new_parent, new_name, now_ns())
                .map_err(|e| mount_error(&e))?;
            durability.mark(METADATA_CHARGE);
            self.make_attr(pool, source)
        })?
    }

    pub fn write(&self, inode: u64, offset: u64, data: &[u8]) -> Result<u32, MountError> {
        let durability = self.durability()?;
        self.with_pool_mut(|pool| {
            pool.write(inode, offset, data, now_ns())
                .map_err(|e| mount_error(&e))?;
            durability.mark(data.len() as u64);
            Ok::<u32, MountError>(data.len() as u32)
        })?
    }

    pub fn unlink(&self, parent: u64, name: &str) -> Result<(), MountError> {
        let durability = self.durability()?;
        if is_reserved(parent, name) {
            return Err(MountError::NotFound);
        }
        self.with_pool_mut(|pool| {
            let entry = pool.lookup(parent, name).map_err(|e| mount_error(&e))?;
            if entry.kind == EntryKind::Directory {
                return Err(MountError::IsDirectory);
            }
            let mut state = self.state.lock().map_err(|_| MountError::Io)?;
            let last_name = pool
                .getattr(entry.inode)
                .map(|attrs| attrs.nlink <= 1)
                .unwrap_or(true);
            if last_name && state.open_counts.get(&entry.inode).copied().unwrap_or(0) > 0 {
                orphan_object(pool, parent, name, entry.inode)?;
                state.deferred.insert(entry.inode);
            } else {
                pool.unlink(parent, name, now_ns())
                    .map_err(|e| mount_error(&e))?;
            }
            durability.mark(METADATA_CHARGE);
            Ok(())
        })?
    }

    pub fn rmdir(&self, parent: u64, name: &str) -> Result<(), MountError> {
        let durability = self.durability()?;
        if is_reserved(parent, name) {
            return Err(MountError::NotFound);
        }
        self.with_pool_mut(|pool| {
            let entry = pool.lookup(parent, name).map_err(|e| mount_error(&e))?;
            let mut state = self.state.lock().map_err(|_| MountError::Io)?;
            if entry.kind == EntryKind::Directory
                && state.open_counts.get(&entry.inode).copied().unwrap_or(0) > 0
            {
                let empty = pool
                    .readdir(entry.inode)
                    .map_err(|e| mount_error(&e))?
                    .is_empty();
                if !empty {
                    return Err(MountError::NotEmpty);
                }
                orphan_object(pool, parent, name, entry.inode)?;
                state.deferred.insert(entry.inode);
            } else {
                pool.rmdir(parent, name, now_ns())
                    .map_err(|e| mount_error(&e))?;
            }
            durability.mark(METADATA_CHARGE);
            Ok(())
        })?
    }

    pub fn rename(
        &self,
        old_parent: u64,
        old_name: &str,
        new_parent: u64,
        new_name: &str,
        replace: bool,
    ) -> Result<(), MountError> {
        let durability = self.durability()?;
        if is_reserved(old_parent, old_name) {
            return Err(MountError::NotFound);
        }
        if is_reserved(new_parent, new_name) {
            return Err(MountError::Denied);
        }
        self.with_pool_mut(|pool| {
            let now = now_ns();
            let source = pool
                .lookup(old_parent, old_name)
                .map_err(|e| mount_error(&e))?;
            if source.kind == EntryKind::Directory
                && old_parent != new_parent
                && pool.would_cycle(source.inode, new_parent)
            {
                return Err(MountError::Invalid);
            }
            let mut state = self.state.lock().map_err(|_| MountError::Io)?;
            match pool.lookup(new_parent, new_name) {
                Ok(existing) if existing.inode == source.inode => {}
                Ok(_) if !replace => return Err(MountError::Exists),
                Ok(existing) => {
                    let source_is_dir = source.kind == EntryKind::Directory;
                    let target_is_dir = existing.kind == EntryKind::Directory;
                    let target_open =
                        state.open_counts.get(&existing.inode).copied().unwrap_or(0) > 0;
                    match (source_is_dir, target_is_dir) {
                        (false, true) => return Err(MountError::IsDirectory),
                        (true, false) => return Err(MountError::NotDirectory),
                        (true, true) => {
                            if target_open {
                                if !pool
                                    .readdir(existing.inode)
                                    .map_err(|e| mount_error(&e))?
                                    .is_empty()
                                {
                                    return Err(MountError::NotEmpty);
                                }
                                orphan_object(pool, new_parent, new_name, existing.inode)?;
                                state.deferred.insert(existing.inode);
                            } else {
                                pool.rmdir(new_parent, new_name, now)
                                    .map_err(|e| mount_error(&e))?;
                            }
                        }
                        (false, false) => {
                            let last_name = pool
                                .getattr(existing.inode)
                                .map(|attrs| attrs.nlink <= 1)
                                .unwrap_or(true);
                            if target_open && last_name {
                                orphan_object(pool, new_parent, new_name, existing.inode)?;
                                state.deferred.insert(existing.inode);
                            } else {
                                pool.unlink(new_parent, new_name, now)
                                    .map_err(|e| mount_error(&e))?;
                            }
                        }
                    }
                }
                Err(_) => {}
            }
            pool.rename(old_parent, old_name, new_parent, new_name, now)
                .map_err(|e| mount_error(&e))?;
            durability.mark(METADATA_CHARGE);
            Ok(())
        })?
    }

    pub fn unlink_handle(
        &self,
        parent: u64,
        name: &str,
        inode: u64,
        is_dir: bool,
    ) -> Result<(), MountError> {
        let durability = self.durability()?;
        if is_reserved(parent, name) {
            return Ok(());
        }
        self.with_pool_mut(|pool| {
            let Ok(entry) = pool.lookup(parent, name) else {
                return Ok(());
            };
            if entry.inode != inode {
                return Ok(());
            }
            if is_dir && !pool.readdir(inode).map_err(|e| mount_error(&e))?.is_empty() {
                return Err(MountError::NotEmpty);
            }
            let mut state = self.state.lock().map_err(|_| MountError::Io)?;
            let last_name = pool
                .getattr(inode)
                .map(|attrs| attrs.nlink <= 1)
                .unwrap_or(true);
            if last_name && state.open_counts.get(&inode).copied().unwrap_or(0) > 0 {
                orphan_object(pool, parent, name, inode)?;
                state.deferred.insert(inode);
            } else if is_dir {
                pool.rmdir(parent, name, now_ns())
                    .map_err(|e| mount_error(&e))?;
            } else {
                pool.unlink(parent, name, now_ns())
                    .map_err(|e| mount_error(&e))?;
            }
            durability.mark(METADATA_CHARGE);
            Ok(())
        })?
    }

    pub fn setattr(&self, inode: u64, change: SetAttr) -> Result<MountAttr, MountError> {
        let durability = self.durability()?;
        self.with_pool_mut(|pool| {
            let now = now_ns();
            if let Some(size) = change.size {
                pool.truncate(inode, size, now)
                    .map_err(|e| mount_error(&e))?;
            }
            let touches_metadata = change.mode.is_some()
                || change.uid.is_some()
                || change.gid.is_some()
                || change.atime.is_some()
                || change.mtime.is_some()
                || change.ctime.is_some()
                || change.attributes.is_some()
                || change.crtime.is_some()
                || change.bsd_flags.is_some();
            if touches_metadata {
                pool.update_attrs(inode, |attrs| {
                    if let Some(mode) = change.mode {
                        attrs.mode = (attrs.mode & MODE_TYPE_MASK) | (mode & !MODE_TYPE_MASK);
                    }
                    if let Some(uid) = change.uid {
                        attrs.uid = uid;
                    }
                    if let Some(gid) = change.gid {
                        attrs.gid = gid;
                    }
                    if let Some(bits) = change.attributes {
                        attrs.attrs = bits;
                    }
                    if let Some(flags) = change.bsd_flags {
                        attrs.bsd_flags = flags;
                    }
                    if let Some(crtime) = change.crtime {
                        attrs.crtime_ns = crtime;
                    }
                    if let Some(atime) = change.atime {
                        attrs.atime_ns = resolve_time(atime, now);
                    }
                    if let Some(mtime) = change.mtime {
                        attrs.mtime_ns = resolve_time(mtime, now);
                    }
                    attrs.ctime_ns = change.ctime.unwrap_or(now);
                })
                .map_err(|e| mount_error(&e))?;
            }
            if change.size.is_some() || touches_metadata {
                durability.mark(METADATA_CHARGE);
            }
            self.make_attr(pool, inode)
        })?
    }

    pub fn maintenance_hold(&self) -> MaintenanceHold {
        let Some(writes) = &self.writes else {
            return MaintenanceHold { durability: None };
        };
        let Ok(mut dirt) = writes.durability.dirt.lock() else {
            return MaintenanceHold { durability: None };
        };
        while dirt.committing {
            let Ok(waited) = writes.durability.signal.wait(dirt) else {
                return MaintenanceHold { durability: None };
            };
            dirt = waited;
        }
        dirt.committing = true;
        drop(dirt);
        MaintenanceHold {
            durability: Some(Arc::clone(&writes.durability)),
        }
    }

    pub fn commit_if_dirty(&self) -> Result<(), MountError> {
        let Some(writes) = &self.writes else {
            return Ok(());
        };
        commit_group(&self.pool, &writes.durability)
    }

    pub fn commit(&self) -> Result<(), MountError> {
        self.commit_if_dirty()
    }
}

impl<D: SharedDevice> Drop for MountCore<D> {
    fn drop(&mut self) {
        if let Err(error) = self.shutdown() {
            eprintln!(
                "scalefs: the final commit of a dropped mount core failed \
                 ({error:?}); uncommitted changes were lost"
            );
        }
    }
}

pub struct MaintenanceHold {
    durability: Option<Arc<Durability>>,
}

impl Drop for MaintenanceHold {
    fn drop(&mut self) {
        if let Some(durability) = &self.durability {
            if let Ok(mut dirt) = durability.dirt.lock() {
                dirt.committing = false;
            }
            durability.signal.notify_all();
        }
    }
}

fn resolve_time(change: TimeChange, now: i64) -> i64 {
    match change {
        TimeChange::Now => now,
        TimeChange::Set(value) => value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scalefs_core::{
        CaseSensitivity, CreateParams, DeviceId, Geometry, MemoryBlockDevice, PoolId,
    };

    const NOW: i64 = 1_700_000_000_123_456_789;

    fn geometry() -> Geometry {
        Geometry {
            logical_block_size: 4096,
            physical_block_size: 4096,
            zone_size: 64 * 1024,
            zone_count: 64,
            erase_granularity_zones: 1,
            sequential_write_required: false,
        }
    }

    fn fresh_rw() -> MountCore<Arc<MemoryBlockDevice>> {
        let mut pool = Pool::create(
            Arc::new(MemoryBlockDevice::new(scalefs_core::member_image_len(
                geometry().capacity_bytes(),
            ) as usize)),
            CreateParams {
                geometry: geometry(),
                pool_id: PoolId([0x77; 16]),
                device_id: DeviceId([0x78; 16]),
                case_sensitivity: CaseSensitivity::InsensitivePreserving,
                dirent_hash_seed: 5,
                label: "core".to_string(),
                created_at_ns: NOW,
            },
        )
        .unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        MountCore::read_write(Arc::new(RwLock::new(pool)))
    }

    #[test]
    fn walk_resolves_paths() {
        let core = fresh_rw();
        let dir = core.mkdir(ROOT_INODE, "docs", 0o755, 0, 0).unwrap();
        let file = core.create(dir.inode, "notes.txt", 0o644, 0, 0).unwrap();

        assert_eq!(core.walk("").unwrap(), ROOT_INODE);
        assert_eq!(core.walk("\\").unwrap(), ROOT_INODE);
        assert_eq!(core.walk("docs").unwrap(), dir.inode);
        assert_eq!(core.walk("\\docs\\notes.txt").unwrap(), file.inode);
        assert_eq!(core.walk("docs/notes.txt").unwrap(), file.inode);
        assert_eq!(core.walk("docs\\missing"), Err(MountError::NotFound));
        assert_eq!(
            core.walk("docs\\notes.txt\\deeper"),
            Err(MountError::NotDirectory)
        );
        assert_eq!(core.walk(ORPHANAGE), Err(MountError::NotFound));
        let long = "x".repeat(MAX_NAME_LEN + 1);
        assert_eq!(core.walk(&long), Err(MountError::NameTooLong));
    }

    #[test]
    fn concurrent_durability_points_collapse() {
        let core = Arc::new(fresh_rw());
        let mut inodes = Vec::new();
        for i in 0..8 {
            let file = core
                .create(ROOT_INODE, &format!("f{i}"), 0o644, 0, 0)
                .unwrap();
            core.write(file.inode, 0, format!("payload {i}").as_bytes())
                .unwrap();
            inodes.push(file.inode);
        }
        let before = core.with_pool(|pool| pool.committed_tx()).unwrap();

        let barrier = Arc::new(std::sync::Barrier::new(8));
        let mut joins = Vec::new();
        for _ in 0..8 {
            let core = Arc::clone(&core);
            let barrier = Arc::clone(&barrier);
            joins.push(std::thread::spawn(move || {
                barrier.wait();
                core.commit_if_dirty()
            }));
        }
        for join in joins {
            join.join().expect("no panics").expect("commit succeeds");
        }

        let after = core.with_pool(|pool| pool.committed_tx()).unwrap();
        assert_eq!(after, before + 1, "eight durability points, one commit");
        for (i, inode) in inodes.iter().enumerate() {
            assert_eq!(
                core.read(*inode, 0, 64).unwrap(),
                format!("payload {i}").into_bytes()
            );
        }
        core.commit_if_dirty().unwrap();
        assert_eq!(core.with_pool(|pool| pool.committed_tx()).unwrap(), after);
    }

    #[test]
    fn maintenance_hold_excludes_committers() {
        let core = Arc::new(fresh_rw());
        let file = core.create(ROOT_INODE, "held", 0o644, 0, 0).unwrap();
        core.write(file.inode, 0, b"payload").unwrap();
        let before = core.with_pool(|pool| pool.committed_tx()).unwrap();

        let hold = core.maintenance_hold();
        let committer = {
            let core = Arc::clone(&core);
            std::thread::spawn(move || core.commit_if_dirty())
        };
        std::thread::sleep(Duration::from_millis(700));
        assert_eq!(
            core.with_pool(|pool| pool.committed_tx()).unwrap(),
            before,
            "the hold excludes every committer"
        );
        drop(hold);
        committer
            .join()
            .expect("no panic")
            .expect("commit succeeds");
        assert_eq!(
            core.with_pool(|pool| pool.committed_tx()).unwrap(),
            before + 1
        );
    }

    #[test]
    fn neutral_errors_map() {
        let core = fresh_rw();
        assert_eq!(core.getattr(999_999).unwrap_err(), MountError::NotFound);
        core.mkdir(ROOT_INODE, "d", 0o755, 0, 0).unwrap();
        assert_eq!(
            core.mkdir(ROOT_INODE, "d", 0o755, 0, 0).unwrap_err(),
            MountError::Exists
        );
        let file = core.create(ROOT_INODE, "f", 0o644, 0, 0).unwrap();
        assert_eq!(core.read(file.inode, 0, 4).unwrap().len(), 0);
        for spelling in [ORPHANAGE, ".SCALEFS-Orphans", ".Scalefs-Orphans"] {
            assert_eq!(
                core.mkdir(ROOT_INODE, spelling, 0o755, 0, 0).unwrap_err(),
                MountError::Denied,
                "{spelling}"
            );
            assert_eq!(
                core.lookup(ROOT_INODE, spelling).unwrap_err(),
                MountError::NotFound,
                "{spelling}"
            );
        }
    }

    #[test]
    fn one_core_coordinates_deferred_delete_across_surfaces() {
        let core = Arc::new(fresh_rw());
        let file = core.create(ROOT_INODE, "f", 0o644, 0, 0).unwrap();

        let surface_a = Arc::clone(&core);
        let surface_b = Arc::clone(&core);
        surface_a.retain(file.inode);
        surface_b.retain(file.inode);

        surface_a.unlink(ROOT_INODE, "f").unwrap();
        assert!(core.lookup(ROOT_INODE, "f").is_err(), "unlinked");
        assert!(core.getattr(file.inode).is_ok(), "parked, not freed");

        surface_a.release(file.inode);
        assert!(
            core.getattr(file.inode).is_ok(),
            "the other surface still holds it"
        );

        surface_b.release(file.inode);
        assert!(
            core.getattr(file.inode).is_err(),
            "reaped at the last release across surfaces"
        );
    }

    #[test]
    fn unlink_handle_only_removes_the_named_inode() {
        let core = fresh_rw();
        let original = core.create(ROOT_INODE, "a", 0o644, 0, 0).unwrap();
        core.rename(ROOT_INODE, "a", ROOT_INODE, "b", false)
            .unwrap();
        let rebound = core.create(ROOT_INODE, "a", 0o644, 0, 0).unwrap();
        assert_ne!(original.inode, rebound.inode);

        core.unlink_handle(ROOT_INODE, "a", original.inode, false)
            .unwrap();
        assert_eq!(
            core.lookup(ROOT_INODE, "a").unwrap().inode,
            rebound.inode,
            "the innocent same-named file survives"
        );
        core.unlink_handle(ROOT_INODE, "a", rebound.inode, false)
            .unwrap();
        assert!(core.lookup(ROOT_INODE, "a").is_err());
    }

    #[test]
    fn unlink_handle_refuses_a_non_empty_directory() {
        let core = fresh_rw();
        let dir = core.mkdir(ROOT_INODE, "d", 0o755, 0, 0).unwrap();
        let child = core.create(dir.inode, "f", 0o644, 0, 0).unwrap();

        assert!(
            matches!(
                core.unlink_handle(ROOT_INODE, "d", dir.inode, true),
                Err(MountError::NotEmpty)
            ),
            "a non-empty directory must refuse with NotEmpty"
        );
        assert_eq!(
            core.lookup(ROOT_INODE, "d").unwrap().inode,
            dir.inode,
            "the directory survives the refusal"
        );
        assert_eq!(
            core.lookup(dir.inode, "f").unwrap().inode,
            child.inode,
            "the child survives — never orphaned"
        );

        core.unlink_handle(dir.inode, "f", child.inode, false)
            .unwrap();
        core.unlink_handle(ROOT_INODE, "d", dir.inode, true)
            .unwrap();
        assert!(
            core.lookup(ROOT_INODE, "d").is_err(),
            "an empty directory still removes cleanly"
        );
    }

    #[test]
    fn a_poisoned_core_serves_nothing() {
        let core = fresh_rw();
        let file = core.create(ROOT_INODE, "f", 0o644, 0, 0).unwrap();
        core.poison();
        assert_eq!(
            core.getattr(file.inode).unwrap_err(),
            MountError::Io,
            "reads are fenced"
        );
        assert_eq!(core.lookup(ROOT_INODE, "f").unwrap_err(), MountError::Io);
        assert_eq!(
            core.write(file.inode, 0, b"x").unwrap_err(),
            MountError::Io,
            "writes are fenced"
        );
        assert_eq!(
            core.create(ROOT_INODE, "g", 0o644, 0, 0).unwrap_err(),
            MountError::Io
        );
    }

    #[test]
    fn poison_disarms_every_commit_path() {
        let mut pool = Pool::create(
            Arc::new(MemoryBlockDevice::new(scalefs_core::member_image_len(
                geometry().capacity_bytes(),
            ) as usize)),
            CreateParams {
                geometry: geometry(),
                pool_id: PoolId([0x21; 16]),
                device_id: DeviceId([0x22; 16]),
                case_sensitivity: CaseSensitivity::InsensitivePreserving,
                dirent_hash_seed: 9,
                label: "poison".to_string(),
                created_at_ns: NOW,
            },
        )
        .unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let shared = Arc::new(RwLock::new(pool));
        let last_good = shared.read().unwrap().committed_tx();
        let core = MountCore::read_write(Arc::clone(&shared));

        let file = core.create(ROOT_INODE, "doomed", 0o644, 0, 0).unwrap();
        core.retain(file.inode);
        core.unlink(ROOT_INODE, "doomed").unwrap();

        core.poison();
        assert_eq!(core.commit(), Err(MountError::Io), "fsync refuses");
        assert_eq!(core.commit_if_dirty(), Err(MountError::Io));
        std::thread::sleep(DEBOUNCE_QUIET * 2);
        assert_eq!(
            shared.read().unwrap().committed_tx(),
            last_good,
            "the timer committed after poison"
        );

        assert_eq!(core.shutdown(), Ok(()));
        assert_eq!(shared.read().unwrap().committed_tx(), last_good);
        assert!(
            shared.read().unwrap().lookup(ROOT_INODE, ORPHANAGE).is_ok(),
            "a poisoned shutdown must not sweep"
        );
        drop(core);
        assert_eq!(shared.read().unwrap().committed_tx(), last_good);

        let ro = MountCore::read_only(shared);
        ro.poison();
        assert_eq!(ro.shutdown(), Ok(()));
    }

    #[test]
    fn a_steady_writer_commits_within_the_max_age() {
        let mut pool = Pool::create(
            Arc::new(MemoryBlockDevice::new(scalefs_core::member_image_len(
                geometry().capacity_bytes(),
            ) as usize)),
            CreateParams {
                geometry: geometry(),
                pool_id: PoolId([0x2A; 16]),
                device_id: DeviceId([0x2B; 16]),
                case_sensitivity: CaseSensitivity::InsensitivePreserving,
                dirent_hash_seed: 9,
                label: "steady".to_string(),
                created_at_ns: NOW,
            },
        )
        .unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let shared = Arc::new(RwLock::new(pool));
        let baseline = shared.read().unwrap().committed_tx();
        let core = MountCore::read_write(Arc::clone(&shared));

        let file = core.create(ROOT_INODE, "log", 0o644, 0, 0).unwrap();
        let start = Instant::now();
        let deadline = start + DEBOUNCE_MAX_AGE + Duration::from_secs(3);
        let mut offset = 0u64;
        let mut committed_at = None;
        while Instant::now() < deadline {
            core.write(file.inode, offset, b"x").unwrap();
            offset += 1;
            std::thread::sleep(Duration::from_millis(200));
            if shared.read().unwrap().committed_tx() > baseline {
                committed_at = Some(start.elapsed());
                break;
            }
        }
        let elapsed = committed_at.expect(
            "a steady sub-quiet writer was never committed — the max-age backstop is missing",
        );
        assert!(
            elapsed >= DEBOUNCE_QUIET * 3,
            "committed suspiciously early ({elapsed:?}) — not via the max-age path",
        );
        core.shutdown().unwrap();
    }

    #[test]
    fn separate_cores_do_not_share_the_open_table() {
        let mut pool = Pool::create(
            Arc::new(MemoryBlockDevice::new(scalefs_core::member_image_len(
                geometry().capacity_bytes(),
            ) as usize)),
            CreateParams {
                geometry: geometry(),
                pool_id: PoolId([0x31; 16]),
                device_id: DeviceId([0x32; 16]),
                case_sensitivity: CaseSensitivity::InsensitivePreserving,
                dirent_hash_seed: 3,
                label: "mixed".to_string(),
                created_at_ns: NOW,
            },
        )
        .unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let shared = Arc::new(RwLock::new(pool));
        let rw = MountCore::read_write(Arc::clone(&shared));
        let ro = MountCore::read_only(shared);

        let file = rw.create(ROOT_INODE, "seen.txt", 0o644, 0, 0).unwrap();
        ro.retain(file.inode);
        rw.unlink(ROOT_INODE, "seen.txt").unwrap();
        assert!(
            rw.getattr(file.inode).is_err(),
            "freed at once — the documented gap"
        );
        assert_eq!(ro.read(file.inode, 0, 4).unwrap_err(), MountError::NotFound);
        ro.release(file.inode);
        rw.shutdown().unwrap();
    }

    #[test]
    fn read_only_refuses_mutation() {
        let mut pool = Pool::create(
            Arc::new(MemoryBlockDevice::new(scalefs_core::member_image_len(
                geometry().capacity_bytes(),
            ) as usize)),
            CreateParams {
                geometry: geometry(),
                pool_id: PoolId([0x11; 16]),
                device_id: DeviceId([0x12; 16]),
                case_sensitivity: CaseSensitivity::InsensitivePreserving,
                dirent_hash_seed: 1,
                label: "ro".to_string(),
                created_at_ns: NOW,
            },
        )
        .unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let core = MountCore::read_only(Arc::new(RwLock::new(pool)));
        assert!(core.is_read_only());
        assert_eq!(
            core.create(ROOT_INODE, "x", 0o644, 0, 0).unwrap_err(),
            MountError::ReadOnly
        );
        assert_eq!(core.commit(), Ok(()));
        assert_eq!(core.commit_if_dirty(), Ok(()));
        assert_eq!(core.shutdown(), Ok(()));
    }

    #[test]
    fn deferred_delete_through_the_core() {
        let core = fresh_rw();
        let file = core.create(ROOT_INODE, "temp", 0o600, 0, 0).unwrap();
        core.retain(file.inode);
        core.write(file.inode, 0, b"alive").unwrap();
        core.unlink(ROOT_INODE, "temp").unwrap();
        assert_eq!(
            core.lookup(ROOT_INODE, "temp").unwrap_err(),
            MountError::NotFound
        );
        assert_eq!(core.read(file.inode, 0, 8).unwrap(), b"alive");
        assert!(core.getattr(file.inode).unwrap().deferred);
        core.release(file.inode);
        assert_eq!(core.getattr(file.inode).unwrap_err(), MountError::NotFound);
    }

    #[test]
    fn hard_links_serve_one_object_under_two_names() {
        let core = fresh_rw();
        let file = core.create(ROOT_INODE, "orig", 0o644, 0, 0).unwrap();
        core.write(file.inode, 0, b"shared").unwrap();

        let linked = core.link(file.inode, ROOT_INODE, "extra").unwrap();
        assert_eq!(linked.inode, file.inode);
        assert_eq!(linked.attrs.nlink, 2);
        assert!(!linked.deferred);
        assert_eq!(
            core.lookup(ROOT_INODE, "extra").unwrap().inode,
            core.lookup(ROOT_INODE, "orig").unwrap().inode
        );

        core.unlink(ROOT_INODE, "orig").unwrap();
        let attr = core.getattr(file.inode).unwrap();
        assert_eq!(attr.attrs.nlink, 1);
        assert!(!attr.deferred, "a still-named object is not deferred");
        assert_eq!(core.read(file.inode, 0, 6).unwrap(), b"shared");
    }

    #[test]
    fn only_the_last_name_of_an_open_object_parks() {
        let core = fresh_rw();
        let file = core.create(ROOT_INODE, "a", 0o644, 0, 0).unwrap();
        core.write(file.inode, 0, b"held").unwrap();
        core.link(file.inode, ROOT_INODE, "b").unwrap();
        core.retain(file.inode);

        core.unlink(ROOT_INODE, "a").unwrap();
        let attr = core.getattr(file.inode).unwrap();
        assert!(!attr.deferred, "one name remains: nothing to defer");
        assert_eq!(attr.attrs.nlink, 1);
        assert_eq!(core.lookup(ROOT_INODE, "b").unwrap().inode, file.inode);

        core.unlink(ROOT_INODE, "b").unwrap();
        assert!(
            core.getattr(file.inode).unwrap().deferred,
            "the LAST name's unlink parks the open object"
        );
        assert_eq!(core.read(file.inode, 0, 4).unwrap(), b"held");
        core.release(file.inode);
        assert_eq!(core.getattr(file.inode).unwrap_err(), MountError::NotFound);
    }

    #[test]
    fn parked_objects_refuse_new_links() {
        let core = fresh_rw();
        let file = core.create(ROOT_INODE, "temp", 0o600, 0, 0).unwrap();
        core.retain(file.inode);
        core.unlink(ROOT_INODE, "temp").unwrap();
        assert_eq!(
            core.link(file.inode, ROOT_INODE, "back").unwrap_err(),
            MountError::NotFound
        );
        core.release(file.inode);
    }

    #[test]
    fn xattrs_round_trip_and_the_namespace_policy_holds() {
        let core = fresh_rw();
        let file = core.create(ROOT_INODE, "f", 0o644, 0, 0).unwrap();

        core.setxattr(file.inode, "user.origin", b"here", 0)
            .unwrap();
        core.setxattr(file.inode, "security.capability", &[9], 0)
            .unwrap();
        core.setxattr(file.inode, "trusted.mark", b"t", 0).unwrap();
        assert_eq!(core.getxattr(file.inode, "user.origin").unwrap(), b"here");
        let mut names = core.listxattr(file.inode).unwrap();
        names.sort();
        assert_eq!(
            names,
            vec!["security.capability", "trusted.mark", "user.origin"]
        );
        core.removexattr(file.inode, "trusted.mark").unwrap();
        assert_eq!(core.listxattr(file.inode).unwrap().len(), 2);

        for name in ["system.posix_acl_access", "system.anything"] {
            assert_eq!(
                core.setxattr(file.inode, name, b"x", 0).unwrap_err(),
                MountError::NotSupported
            );
            assert_eq!(
                core.getxattr(file.inode, name).unwrap_err(),
                MountError::NotSupported
            );
            assert_eq!(
                core.removexattr(file.inode, name).unwrap_err(),
                MountError::NotSupported
            );
        }
        assert_eq!(
            core.getxattr(file.inode, "user.absent").unwrap_err(),
            MountError::NotFound
        );
    }

    #[test]
    fn rename_replacement_over_a_multilink_target_keeps_the_object() {
        let core = fresh_rw();
        let target = core.create(ROOT_INODE, "t", 0o644, 0, 0).unwrap();
        core.write(target.inode, 0, b"keep me").unwrap();
        core.link(target.inode, ROOT_INODE, "t2").unwrap();
        core.retain(target.inode);
        let _source = core.create(ROOT_INODE, "s", 0o644, 0, 0).unwrap();

        core.rename(ROOT_INODE, "s", ROOT_INODE, "t", true).unwrap();
        let attr = core.getattr(target.inode).unwrap();
        assert!(!attr.deferred, "a multi-named replaced target never parks");
        assert_eq!(attr.attrs.nlink, 1);
        assert_eq!(core.lookup(ROOT_INODE, "t2").unwrap().inode, target.inode);
        assert_eq!(core.read(target.inode, 0, 7).unwrap(), b"keep me");
        core.release(target.inode);
        assert_eq!(core.read(target.inode, 0, 7).unwrap(), b"keep me");
    }
}
