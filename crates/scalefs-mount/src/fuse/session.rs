
use super::fs::Filesystem;
use super::wire::{
    self, AttrOut, CreateIn, EntryOut, FlushIn, FsyncIn, GetattrIn, GetxattrIn, InitIn, InitOut,
    LinkIn, MkdirIn, MknodIn, OpenIn, ReadIn, ReleaseIn, Rename2In, RenameIn, SetattrIn,
    SetxattrIn, WriteIn, errno, name_from, opcode, rename_flags, two_names_from,
};
use scalefs_core::wire::Cursor;

const MAX_TRANSFER: u32 = 2 << 20;

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Reply(Vec<u8>),
    Silent,
    Farewell(Vec<u8>),
}

pub struct Session {
    negotiated: std::sync::atomic::AtomicBool,
}

impl Default for Session {
    fn default() -> Self {
        Session::new()
    }
}

impl Session {
    pub fn new() -> Session {
        Session {
            negotiated: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn handle(&self, frame: &[u8], filesystem: &dyn Filesystem) -> Outcome {
        let Ok((header, body)) = wire::split_request(frame) else {
            return Outcome::Silent;
        };
        let reply = match header.opcode {
            opcode::INIT => {
                return Outcome::Reply(match InitIn::decode(&mut Cursor::new(body)) {
                    Ok(init) if init.major == wire::KERNEL_VERSION => {
                        let minor = init.minor.min(wire::WANTED_MINOR);
                        let flags = init.flags & (wire::flags::BIG_WRITES | wire::flags::MAX_PAGES);
                        let max_write = if flags & wire::flags::MAX_PAGES != 0 {
                            1 << 20
                        } else {
                            1 << 17
                        };
                        self.negotiated
                            .store(true, std::sync::atomic::Ordering::Release);
                        wire::reply_init(
                            header.unique,
                            &InitOut {
                                major: wire::KERNEL_VERSION,
                                minor,
                                max_readahead: 1 << 17,
                                flags,
                                max_write,
                                max_pages: 256,
                            },
                        )
                    }
                    Ok(init) if init.major > wire::KERNEL_VERSION => wire::reply_init(
                        header.unique,
                        &InitOut {
                            major: wire::KERNEL_VERSION,
                            minor: wire::WANTED_MINOR,
                            max_readahead: 0,
                            flags: 0,
                            max_write: 1 << 17,
                            max_pages: 0,
                        },
                    ),
                    _ => wire::reply_error(header.unique, errno::EIO),
                });
            }
            opcode::DESTROY => {
                return Outcome::Farewell(wire::reply_payload(header.unique, &[]));
            }
            opcode::FORGET | opcode::BATCH_FORGET => return Outcome::Silent,
            opcode::INTERRUPT => return Outcome::Silent,
            _ if !self.negotiated.load(std::sync::atomic::Ordering::Acquire) => {
                wire::reply_error(header.unique, errno::EIO)
            }
            opcode::GETATTR => match GetattrIn::decode(&mut Cursor::new(body)) {
                Ok(_) => answer_attr(header.unique, filesystem.getattr(header.nodeid)),
                Err(_) => wire::reply_error(header.unique, errno::EINVAL),
            },
            opcode::SETATTR => match SetattrIn::decode(&mut Cursor::new(body)) {
                Ok(change) => {
                    answer_attr(header.unique, filesystem.setattr(header.nodeid, &change))
                }
                Err(_) => wire::reply_error(header.unique, errno::EINVAL),
            },
            opcode::LOOKUP => match name_from(body) {
                Some(name) => answer_entry(header.unique, filesystem.lookup(header.nodeid, name)),
                None => wire::reply_error(header.unique, errno::EINVAL),
            },
            opcode::READLINK => match filesystem.readlink(header.nodeid) {
                Ok(target) => wire::reply_payload(header.unique, &target),
                Err(errno) => wire::reply_error(header.unique, errno),
            },
            opcode::SYMLINK => match two_names_from(body) {
                Some((name, target)) => answer_entry(
                    header.unique,
                    filesystem.symlink(header.nodeid, name, target, header.uid, header.gid),
                ),
                None => wire::reply_error(header.unique, errno::EINVAL),
            },
            opcode::MKNOD => match parse_struct_then_name(body, MknodIn::SIZE, MknodIn::decode) {
                Some((mknod, name)) => answer_entry(
                    header.unique,
                    filesystem.mknod(
                        header.nodeid,
                        name,
                        mknod.mode,
                        mknod.rdev,
                        header.uid,
                        header.gid,
                    ),
                ),
                None => wire::reply_error(header.unique, errno::EINVAL),
            },
            opcode::MKDIR => match parse_struct_then_name(body, MkdirIn::SIZE, MkdirIn::decode) {
                Some((mkdir, name)) => answer_entry(
                    header.unique,
                    filesystem.mkdir(header.nodeid, name, mkdir.mode, header.uid, header.gid),
                ),
                None => wire::reply_error(header.unique, errno::EINVAL),
            },
            opcode::CREATE => {
                match parse_struct_then_name(body, CreateIn::SIZE, CreateIn::decode) {
                    Some((create, name)) => {
                        match filesystem.create(
                            header.nodeid,
                            name,
                            create.mode,
                            header.uid,
                            header.gid,
                        ) {
                            Ok((entry, open)) => wire::reply_create(header.unique, &entry, &open),
                            Err(errno) => wire::reply_error(header.unique, errno),
                        }
                    }
                    None => wire::reply_error(header.unique, errno::EINVAL),
                }
            }
            opcode::UNLINK => match name_from(body) {
                Some(name) => answer_empty(header.unique, filesystem.unlink(header.nodeid, name)),
                None => wire::reply_error(header.unique, errno::EINVAL),
            },
            opcode::RMDIR => match name_from(body) {
                Some(name) => answer_empty(header.unique, filesystem.rmdir(header.nodeid, name)),
                None => wire::reply_error(header.unique, errno::EINVAL),
            },
            opcode::LINK => match parse_struct_then_name(body, LinkIn::SIZE, LinkIn::decode) {
                Some((link, name)) => answer_entry(
                    header.unique,
                    filesystem.link(link.oldnodeid, header.nodeid, name),
                ),
                None => wire::reply_error(header.unique, errno::EINVAL),
            },
            opcode::RENAME => match parse_rename(body, RenameIn::SIZE, |cursor| {
                RenameIn::decode(cursor).map(|rename| (rename.newdir, 0))
            }) {
                Some((newdir, _, old_name, new_name)) => answer_empty(
                    header.unique,
                    filesystem.rename(header.nodeid, old_name, newdir, new_name, true),
                ),
                None => wire::reply_error(header.unique, errno::EINVAL),
            },
            opcode::RENAME2 => match parse_rename(body, Rename2In::SIZE, |cursor| {
                Rename2In::decode(cursor).map(|rename| (rename.newdir, rename.flags))
            }) {
                Some((newdir, flags, old_name, new_name)) => match flags {
                    0 | rename_flags::NOREPLACE => answer_empty(
                        header.unique,
                        filesystem.rename(
                            header.nodeid,
                            old_name,
                            newdir,
                            new_name,
                            flags & rename_flags::NOREPLACE == 0,
                        ),
                    ),
                    _ => wire::reply_error(header.unique, errno::EINVAL),
                },
                None => wire::reply_error(header.unique, errno::EINVAL),
            },
            opcode::OPENDIR | opcode::OPEN => match OpenIn::decode(&mut Cursor::new(body)) {
                Ok(open) => match filesystem.open(header.nodeid, open.flags) {
                    Ok(out) => wire::reply_open(header.unique, &out),
                    Err(errno) => wire::reply_error(header.unique, errno),
                },
                Err(_) => wire::reply_error(header.unique, errno::EINVAL),
            },
            opcode::READDIR => match ReadIn::decode(&mut Cursor::new(body)) {
                Ok(read) if read.size <= MAX_TRANSFER => {
                    match filesystem.readdir(header.nodeid, read.offset, read.size) {
                        Ok(payload) => wire::reply_payload(header.unique, &payload),
                        Err(errno) => wire::reply_error(header.unique, errno),
                    }
                }
                Ok(_) => wire::reply_error(header.unique, errno::EINVAL),
                Err(_) => wire::reply_error(header.unique, errno::EINVAL),
            },
            opcode::READ => match ReadIn::decode(&mut Cursor::new(body)) {
                Ok(read) if read.size <= MAX_TRANSFER => {
                    match filesystem.read(header.nodeid, read.fh, read.offset, read.size) {
                        Ok(payload) => wire::reply_payload(header.unique, &payload),
                        Err(errno) => wire::reply_error(header.unique, errno),
                    }
                }
                Ok(_) => wire::reply_error(header.unique, errno::EINVAL),
                Err(_) => wire::reply_error(header.unique, errno::EINVAL),
            },
            opcode::WRITE => match WriteIn::decode(&mut Cursor::new(body)) {
                Ok(write) => match body.get(WriteIn::SIZE..) {
                    Some(data) if data.len() == write.size as usize => {
                        match filesystem.write(header.nodeid, write.fh, write.offset, data) {
                            Ok(written) => wire::reply_write(header.unique, written),
                            Err(errno) => wire::reply_error(header.unique, errno),
                        }
                    }
                    _ => wire::reply_error(header.unique, errno::EINVAL),
                },
                Err(_) => wire::reply_error(header.unique, errno::EINVAL),
            },
            opcode::RELEASE | opcode::RELEASEDIR => {
                if let Ok(release) = ReleaseIn::decode(&mut Cursor::new(body)) {
                    filesystem.release(header.nodeid, release.fh);
                }
                wire::reply_payload(header.unique, &[])
            }
            opcode::STATFS => match filesystem.statfs() {
                Ok(out) => wire::reply_statfs(header.unique, &out),
                Err(errno) => wire::reply_error(header.unique, errno),
            },
            opcode::FLUSH => match FlushIn::decode(&mut Cursor::new(body)) {
                Ok(flush) => answer_empty(header.unique, filesystem.flush(header.nodeid, flush.fh)),
                Err(_) => wire::reply_error(header.unique, errno::EINVAL),
            },
            opcode::FSYNC | opcode::FSYNCDIR => match FsyncIn::decode(&mut Cursor::new(body)) {
                Ok(fsync) => answer_empty(
                    header.unique,
                    filesystem.fsync(header.nodeid, fsync.fh, fsync.flags & 1 != 0),
                ),
                Err(_) => wire::reply_error(header.unique, errno::EINVAL),
            },
            opcode::SETXATTR => match parse_setxattr(body) {
                Some((set, name, value)) => answer_empty(
                    header.unique,
                    filesystem.setxattr(header.nodeid, name, value, set.flags),
                ),
                None => wire::reply_error(header.unique, errno::EINVAL),
            },
            opcode::GETXATTR => {
                match parse_struct_then_name(body, GetxattrIn::SIZE, GetxattrIn::decode) {
                    Some((get, name)) => match filesystem.getxattr(header.nodeid, name) {
                        Ok(bytes) => answer_sized(header.unique, get.size, &bytes),
                        Err(errno) => wire::reply_error(header.unique, errno),
                    },
                    None => wire::reply_error(header.unique, errno::EINVAL),
                }
            }
            opcode::LISTXATTR => match GetxattrIn::decode(&mut Cursor::new(body)) {
                Ok(get) => match filesystem.listxattr(header.nodeid) {
                    Ok(blob) => answer_sized(header.unique, get.size, &blob),
                    Err(errno) => wire::reply_error(header.unique, errno),
                },
                Err(_) => wire::reply_error(header.unique, errno::EINVAL),
            },
            opcode::REMOVEXATTR => match name_from(body) {
                Some(name) => {
                    answer_empty(header.unique, filesystem.removexattr(header.nodeid, name))
                }
                None => wire::reply_error(header.unique, errno::EINVAL),
            },
            opcode::ACCESS => wire::reply_payload(header.unique, &[]),
            _ => wire::reply_error(header.unique, errno::ENOSYS),
        };
        Outcome::Reply(reply)
    }
}

#[cfg(target_os = "linux")]
pub fn serve(
    mount: &super::device::FuseMount,
    filesystem: &(dyn Filesystem + Sync),
    workers: usize,
) -> std::io::Result<()> {
    use super::device::RequestRead;

    let session = Session::new();
    if workers <= 1 {
        let mut buffer = vec![0u8; super::device::REQUEST_BUFFER];
        while let Some(len) = mount.read_request(&mut buffer)? {
            match session.handle(&buffer[..len], filesystem) {
                Outcome::Reply(reply) => mount.write_reply(&reply)?,
                Outcome::Silent => {}
                Outcome::Farewell(reply) => {
                    mount.write_reply(&reply)?;
                    return Ok(());
                }
            }
        }
        return Ok(());
    }

    mount.set_nonblocking()?;
    let pool = DispatchPool::new();
    std::thread::scope(|scope| {
        for _ in 0..workers - 1 {
            let pool = &pool;
            let session = &session;
            scope.spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    dispatch_worker(mount, filesystem, session, pool);
                }));
                if let Err(payload) = outcome {
                    pool.record_error(std::io::Error::other("a FUSE dispatch worker panicked"));
                    pool.stop();
                    let _ = super::device::detach_mountpoint(mount.mountpoint());
                    std::panic::resume_unwind(payload);
                }
            });
        }

        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> std::io::Result<()> {
                loop {
                    if pool.stopped() {
                        return pool.take_error();
                    }
                    mount.wait_readable()?;
                    let mut lone: Option<(Vec<u8>, usize)> = None;
                    loop {
                        let mut buffer = pool.take_buffer();
                        match mount.read_request_nonblocking(&mut buffer) {
                            Ok(RequestRead::Ready(len)) => {
                                if let Some(earlier) = lone.take() {
                                    pool.submit(earlier);
                                    pool.submit((buffer, len));
                                } else if pool.idle() {
                                    lone = Some((buffer, len));
                                } else {
                                    pool.submit((buffer, len));
                                }
                            }
                            Ok(RequestRead::NotReady) => {
                                pool.recycle(buffer);
                                break;
                            }
                            Ok(RequestRead::Unmounted) => {
                                pool.recycle(buffer);
                                if let Some((held, _)) = lone.take() {
                                    pool.recycle(held);
                                }
                                return Ok(());
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    if let Some((buffer, len)) = lone.take() {
                        match session.handle(&buffer[..len], filesystem) {
                            Outcome::Reply(reply) => mount.write_reply(&reply)?,
                            Outcome::Silent => {}
                            Outcome::Farewell(reply) => {
                                mount.write_reply(&reply)?;
                                pool.recycle(buffer);
                                return Ok(());
                            }
                        }
                        pool.recycle(buffer);
                    }
                }
            }));
        pool.stop();
        let _ = super::device::detach_mountpoint(mount.mountpoint());
        match result {
            Ok(Ok(())) => pool.take_error(),
            Ok(Err(error)) => Err(error),
            Err(payload) => std::panic::resume_unwind(payload),
        }
    })
}

#[cfg(target_os = "linux")]
struct DispatchPool {
    queue: std::sync::Mutex<std::collections::VecDeque<(Vec<u8>, usize)>>,
    available: std::sync::Condvar,
    buffers: std::sync::Mutex<Vec<Vec<u8>>>,
    stop: std::sync::atomic::AtomicBool,
    error: std::sync::Mutex<Option<std::io::Error>>,
    in_flight: std::sync::atomic::AtomicUsize,
}

#[cfg(target_os = "linux")]
const IDLE_BUFFERS: usize = 8;

#[cfg(target_os = "linux")]
impl DispatchPool {
    fn new() -> Self {
        DispatchPool {
            queue: std::sync::Mutex::new(std::collections::VecDeque::new()),
            available: std::sync::Condvar::new(),
            buffers: std::sync::Mutex::new(Vec::new()),
            stop: std::sync::atomic::AtomicBool::new(false),
            error: std::sync::Mutex::new(None),
            in_flight: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn idle(&self) -> bool {
        self.in_flight.load(std::sync::atomic::Ordering::Acquire) == 0
    }

    fn take_buffer(&self) -> Vec<u8> {
        let recycled = self.buffers.lock().ok().and_then(|mut b| b.pop());
        recycled.unwrap_or_else(|| vec![0u8; super::device::REQUEST_BUFFER])
    }

    fn recycle(&self, buffer: Vec<u8>) {
        if let Ok(mut buffers) = self.buffers.lock()
            && buffers.len() < IDLE_BUFFERS
        {
            buffers.push(buffer);
        }
    }

    fn submit(&self, item: (Vec<u8>, usize)) {
        self.in_flight
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        if let Ok(mut queue) = self.queue.lock() {
            queue.push_back(item);
        }
        self.available.notify_one();
    }

    fn settle(&self) {
        self.in_flight
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }

    fn next(&self) -> Option<(Vec<u8>, usize)> {
        let mut queue = self.queue.lock().ok()?;
        loop {
            if let Some(item) = queue.pop_front() {
                return Some(item);
            }
            if self.stopped() {
                return None;
            }
            queue = self.available.wait(queue).ok()?;
        }
    }

    fn stopped(&self) -> bool {
        self.stop.load(std::sync::atomic::Ordering::Acquire)
    }

    fn stop(&self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        self.available.notify_all();
    }

    fn record_error(&self, error: std::io::Error) {
        if let Ok(mut slot) = self.error.lock()
            && slot.is_none()
        {
            *slot = Some(error);
        }
    }

    fn take_error(&self) -> std::io::Result<()> {
        match self.error.lock() {
            Ok(mut slot) => match slot.take() {
                Some(error) => Err(error),
                None => Ok(()),
            },
            Err(_) => Err(std::io::Error::other("the dispatch pool was poisoned")),
        }
    }
}

#[cfg(target_os = "linux")]
fn dispatch_worker(
    mount: &super::device::FuseMount,
    filesystem: &(dyn Filesystem + Sync),
    session: &Session,
    pool: &DispatchPool,
) {
    while let Some((buffer, len)) = pool.next() {
        let outcome = session.handle(&buffer[..len], filesystem);
        pool.recycle(buffer);
        match outcome {
            Outcome::Reply(reply) => {
                let sent = mount.write_reply(&reply);
                pool.settle();
                if let Err(error) = sent {
                    pool.record_error(error);
                    pool.stop();
                    let _ = super::device::detach_mountpoint(mount.mountpoint());
                    return;
                }
            }
            Outcome::Silent => {
                pool.settle();
            }
            Outcome::Farewell(reply) => {
                if let Err(error) = mount.write_reply(&reply) {
                    pool.record_error(error);
                }
                pool.settle();
                pool.stop();
                let _ = super::device::detach_mountpoint(mount.mountpoint());
                return;
            }
        }
    }
}

fn parse_struct_then_name<T>(
    body: &[u8],
    size: usize,
    decode: impl FnOnce(&mut Cursor<'_>) -> scalefs_core::error::Result<T>,
) -> Option<(T, &[u8])> {
    let decoded = decode(&mut Cursor::new(body)).ok()?;
    let name = name_from(body.get(size..)?)?;
    Some((decoded, name))
}

fn parse_setxattr(body: &[u8]) -> Option<(SetxattrIn, &[u8], &[u8])> {
    let set = SetxattrIn::decode(&mut Cursor::new(body)).ok()?;
    let tail = body.get(SetxattrIn::SIZE..)?;
    let end = tail.iter().position(|&byte| byte == 0)?;
    if end == 0 {
        return None;
    }
    let value = tail.get(end + 1..)?;
    if value.len() != set.size as usize {
        return None;
    }
    Some((set, &tail[..end], value))
}

fn answer_sized(unique: u64, capacity: u32, bytes: &[u8]) -> Vec<u8> {
    if capacity == 0 {
        wire::reply_getxattr_size(unique, bytes.len() as u32)
    } else if bytes.len() > capacity as usize {
        wire::reply_error(unique, errno::ERANGE)
    } else {
        wire::reply_payload(unique, bytes)
    }
}

fn parse_rename(
    body: &[u8],
    size: usize,
    decode: impl FnOnce(&mut Cursor<'_>) -> scalefs_core::error::Result<(u64, u32)>,
) -> Option<(u64, u32, &[u8], &[u8])> {
    let (newdir, flags) = decode(&mut Cursor::new(body)).ok()?;
    let (old_name, new_name) = two_names_from(body.get(size..)?)?;
    Some((newdir, flags, old_name, new_name))
}

fn answer_attr(unique: u64, result: Result<AttrOut, i32>) -> Vec<u8> {
    match result {
        Ok(attr) => wire::reply_attr(unique, &attr),
        Err(errno) => wire::reply_error(unique, errno),
    }
}

fn answer_entry(unique: u64, result: Result<EntryOut, i32>) -> Vec<u8> {
    match result {
        Ok(entry) => wire::reply_entry(unique, &entry),
        Err(errno) => wire::reply_error(unique, errno),
    }
}

fn answer_empty(unique: u64, result: Result<(), i32>) -> Vec<u8> {
    match result {
        Ok(()) => wire::reply_payload(unique, &[]),
        Err(errno) => wire::reply_error(unique, errno),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuse::wire::{InHeader, OpenOut, StatfsOut};
    use scalefs_core::wire::{put_u32, put_u64};

    #[derive(Default)]
    struct Probe {
        calls: std::cell::RefCell<Vec<String>>,
    }

    impl Probe {
        fn called(&self) -> String {
            self.calls.borrow().join(",")
        }
    }

    fn canned_attr() -> AttrOut {
        AttrOut {
            attr_valid: 1,
            attr_valid_nsec: 0,
            attr: crate::fuse::wire::Attr {
                ino: 7,
                mode: 0o100644,
                nlink: 1,
                blksize: 4096,
                ..Default::default()
            },
        }
    }

    fn canned_entry() -> EntryOut {
        EntryOut {
            nodeid: 7,
            generation: 0,
            entry_valid: 1,
            attr_valid: 1,
            entry_valid_nsec: 0,
            attr_valid_nsec: 0,
            attr: canned_attr().attr,
        }
    }

    impl Filesystem for Probe {
        fn getattr(&self, nodeid: u64) -> Result<AttrOut, i32> {
            self.calls.borrow_mut().push(format!("getattr({nodeid})"));
            Ok(canned_attr())
        }
        fn lookup(&self, parent: u64, name: &[u8]) -> Result<EntryOut, i32> {
            self.calls.borrow_mut().push(format!(
                "lookup({parent},{})",
                String::from_utf8_lossy(name)
            ));
            Ok(canned_entry())
        }
        fn readdir(&self, nodeid: u64, offset: u64, size: u32) -> Result<Vec<u8>, i32> {
            self.calls
                .borrow_mut()
                .push(format!("readdir({nodeid},{offset},{size})"));
            Ok(Vec::new())
        }
        fn open(&self, nodeid: u64, _flags: u32) -> Result<OpenOut, i32> {
            self.calls.borrow_mut().push(format!("open({nodeid})"));
            Ok(OpenOut {
                fh: 9,
                open_flags: 0,
            })
        }
        fn read(&self, nodeid: u64, fh: u64, offset: u64, size: u32) -> Result<Vec<u8>, i32> {
            self.calls
                .borrow_mut()
                .push(format!("read({nodeid},{fh},{offset},{size})"));
            Ok(vec![0xAB; 4])
        }
        fn release(&self, nodeid: u64, fh: u64) {
            self.calls
                .borrow_mut()
                .push(format!("release({nodeid},{fh})"));
        }
        fn statfs(&self) -> Result<StatfsOut, i32> {
            self.calls.borrow_mut().push("statfs".into());
            Ok(StatfsOut::default())
        }
        fn setattr(&self, nodeid: u64, change: &SetattrIn) -> Result<AttrOut, i32> {
            self.calls
                .borrow_mut()
                .push(format!("setattr({nodeid},valid={:#x})", change.valid));
            Ok(canned_attr())
        }
        fn mkdir(
            &self,
            parent: u64,
            name: &[u8],
            mode: u32,
            uid: u32,
            gid: u32,
        ) -> Result<EntryOut, i32> {
            self.calls.borrow_mut().push(format!(
                "mkdir({parent},{},{mode:o},{uid}:{gid})",
                String::from_utf8_lossy(name)
            ));
            Ok(canned_entry())
        }
        fn create(
            &self,
            parent: u64,
            name: &[u8],
            mode: u32,
            uid: u32,
            gid: u32,
        ) -> Result<(EntryOut, OpenOut), i32> {
            self.calls.borrow_mut().push(format!(
                "create({parent},{},{mode:o},{uid}:{gid})",
                String::from_utf8_lossy(name)
            ));
            Ok((
                canned_entry(),
                OpenOut {
                    fh: 11,
                    open_flags: 0,
                },
            ))
        }
        fn write(&self, nodeid: u64, fh: u64, offset: u64, data: &[u8]) -> Result<u32, i32> {
            self.calls
                .borrow_mut()
                .push(format!("write({nodeid},{fh},{offset},{})", data.len()));
            Ok(data.len() as u32)
        }
        fn unlink(&self, parent: u64, name: &[u8]) -> Result<(), i32> {
            self.calls.borrow_mut().push(format!(
                "unlink({parent},{})",
                String::from_utf8_lossy(name)
            ));
            Ok(())
        }
        fn rmdir(&self, parent: u64, name: &[u8]) -> Result<(), i32> {
            self.calls
                .borrow_mut()
                .push(format!("rmdir({parent},{})", String::from_utf8_lossy(name)));
            Ok(())
        }
        fn rename(
            &self,
            old_parent: u64,
            old_name: &[u8],
            new_parent: u64,
            new_name: &[u8],
            replace: bool,
        ) -> Result<(), i32> {
            self.calls.borrow_mut().push(format!(
                "rename({old_parent},{},{new_parent},{},{replace})",
                String::from_utf8_lossy(old_name),
                String::from_utf8_lossy(new_name)
            ));
            Ok(())
        }
        fn flush(&self, nodeid: u64, fh: u64) -> Result<(), i32> {
            self.calls
                .borrow_mut()
                .push(format!("flush({nodeid},{fh})"));
            Ok(())
        }
        fn fsync(&self, nodeid: u64, fh: u64, datasync: bool) -> Result<(), i32> {
            self.calls
                .borrow_mut()
                .push(format!("fsync({nodeid},{fh},{datasync})"));
            Ok(())
        }
        fn readlink(&self, nodeid: u64) -> Result<Vec<u8>, i32> {
            self.calls.borrow_mut().push(format!("readlink({nodeid})"));
            Ok(b"../target".to_vec())
        }
        fn symlink(
            &self,
            parent: u64,
            name: &[u8],
            target: &[u8],
            uid: u32,
            gid: u32,
        ) -> Result<EntryOut, i32> {
            self.calls.borrow_mut().push(format!(
                "symlink({parent},{},{},{uid}:{gid})",
                String::from_utf8_lossy(name),
                String::from_utf8_lossy(target)
            ));
            Ok(canned_entry())
        }
        fn mknod(
            &self,
            parent: u64,
            name: &[u8],
            mode: u32,
            rdev: u32,
            uid: u32,
            gid: u32,
        ) -> Result<EntryOut, i32> {
            self.calls.borrow_mut().push(format!(
                "mknod({parent},{},{mode:o},{rdev},{uid}:{gid})",
                String::from_utf8_lossy(name)
            ));
            Ok(canned_entry())
        }

        fn link(&self, source: u64, new_parent: u64, name: &[u8]) -> Result<EntryOut, i32> {
            self.calls.borrow_mut().push(format!(
                "link({source},{new_parent},{})",
                String::from_utf8_lossy(name)
            ));
            Ok(canned_entry())
        }

        fn setxattr(&self, inode: u64, name: &[u8], value: &[u8], flags: u32) -> Result<(), i32> {
            self.calls.borrow_mut().push(format!(
                "setxattr({inode},{},{},{flags})",
                String::from_utf8_lossy(name),
                value.len()
            ));
            Ok(())
        }

        fn getxattr(&self, inode: u64, name: &[u8]) -> Result<Vec<u8>, i32> {
            self.calls.borrow_mut().push(format!(
                "getxattr({inode},{})",
                String::from_utf8_lossy(name)
            ));
            Ok(b"attr-bytes".to_vec())
        }

        fn listxattr(&self, inode: u64) -> Result<Vec<u8>, i32> {
            self.calls.borrow_mut().push(format!("listxattr({inode})"));
            Ok(b"user.a\0user.b\0".to_vec())
        }

        fn removexattr(&self, inode: u64, name: &[u8]) -> Result<(), i32> {
            self.calls.borrow_mut().push(format!(
                "removexattr({inode},{})",
                String::from_utf8_lossy(name)
            ));
            Ok(())
        }
    }

    fn frame(opcode: u32, nodeid: u64, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        put_u32(&mut out, (InHeader::SIZE + body.len()) as u32);
        put_u32(&mut out, opcode);
        put_u64(&mut out, 0x42);
        put_u64(&mut out, nodeid);
        put_u32(&mut out, 1000);
        put_u32(&mut out, 100);
        put_u32(&mut out, 0);
        put_u32(&mut out, 0);
        out.extend_from_slice(body);
        out
    }

    fn init_body() -> Vec<u8> {
        let mut body = Vec::new();
        put_u32(&mut body, wire::KERNEL_VERSION);
        put_u32(&mut body, 39);
        put_u32(&mut body, 1 << 17);
        put_u32(&mut body, wire::flags::BIG_WRITES | wire::flags::MAX_PAGES);
        body
    }

    fn negotiated(fs: &Probe) -> Session {
        let session = Session::new();
        let outcome = session.handle(&frame(opcode::INIT, 0, &init_body()), fs);
        assert!(matches!(outcome, Outcome::Reply(_)));
        session
    }

    fn errno_of(outcome: &Outcome) -> i32 {
        let reply = match outcome {
            Outcome::Reply(reply) | Outcome::Farewell(reply) => reply,
            Outcome::Silent => panic!("expected a reply"),
        };
        -(i32::from_le_bytes(reply[4..8].try_into().unwrap()))
    }

    #[test]
    fn opcodes_dispatch_to_the_trait() {
        let fs = Probe::default();
        let session = negotiated(&fs);

        let mut body = Vec::new();
        put_u32(&mut body, 0o755);
        put_u32(&mut body, 0o022);
        body.extend_from_slice(b"nest\0");
        assert_eq!(
            errno_of(&session.handle(&frame(opcode::MKDIR, 1, &body), &fs)),
            0
        );

        let mut body = Vec::new();
        put_u32(&mut body, 0);
        put_u32(&mut body, 0o100644);
        put_u32(&mut body, 0);
        put_u32(&mut body, 0);
        body.extend_from_slice(b"file.txt\0");
        assert_eq!(
            errno_of(&session.handle(&frame(opcode::CREATE, 1, &body), &fs)),
            0
        );

        let mut body = Vec::new();
        put_u64(&mut body, 11);
        put_u64(&mut body, 4096);
        put_u32(&mut body, 5);
        put_u32(&mut body, 0);
        put_u64(&mut body, 0);
        put_u32(&mut body, 0);
        put_u32(&mut body, 0);
        body.extend_from_slice(b"hello");
        assert_eq!(
            errno_of(&session.handle(&frame(opcode::WRITE, 7, &body), &fs)),
            0
        );

        assert_eq!(
            errno_of(&session.handle(&frame(opcode::UNLINK, 1, b"gone\0"), &fs)),
            0
        );
        assert_eq!(
            errno_of(&session.handle(&frame(opcode::RMDIR, 1, b"nest\0"), &fs)),
            0
        );

        let mut body = Vec::new();
        put_u64(&mut body, 2);
        body.extend_from_slice(b"old\0new\0");
        assert_eq!(
            errno_of(&session.handle(&frame(opcode::RENAME, 1, &body), &fs)),
            0
        );

        let mut body = Vec::new();
        put_u64(&mut body, 2);
        put_u32(&mut body, rename_flags::NOREPLACE);
        put_u32(&mut body, 0);
        body.extend_from_slice(b"a\0b\0");
        assert_eq!(
            errno_of(&session.handle(&frame(opcode::RENAME2, 1, &body), &fs)),
            0
        );

        let mut body = vec![0u8; 88];
        body[0] = 0x08;
        assert_eq!(
            errno_of(&session.handle(&frame(opcode::SETATTR, 7, &body), &fs)),
            0
        );

        let mut body = Vec::new();
        put_u64(&mut body, 11);
        put_u32(&mut body, 0);
        put_u32(&mut body, 0);
        put_u64(&mut body, 0);
        assert_eq!(
            errno_of(&session.handle(&frame(opcode::FLUSH, 7, &body), &fs)),
            0
        );

        let mut body = Vec::new();
        put_u64(&mut body, 11);
        put_u32(&mut body, 1);
        put_u32(&mut body, 0);
        assert_eq!(
            errno_of(&session.handle(&frame(opcode::FSYNC, 7, &body), &fs)),
            0
        );

        assert_eq!(
            errno_of(&session.handle(&frame(opcode::SYMLINK, 1, b"ln\0../t\0"), &fs)),
            0
        );
        assert_eq!(
            errno_of(&session.handle(&frame(opcode::READLINK, 7, &[]), &fs)),
            0
        );

        let mut body = Vec::new();
        put_u32(&mut body, 0o010644);
        put_u32(&mut body, 0x0103);
        put_u32(&mut body, 0);
        put_u32(&mut body, 0);
        body.extend_from_slice(b"pipe\0");
        assert_eq!(
            errno_of(&session.handle(&frame(opcode::MKNOD, 1, &body), &fs)),
            0
        );

        let mut body = Vec::new();
        put_u64(&mut body, 7);
        body.extend_from_slice(b"hard\0");
        assert_eq!(
            errno_of(&session.handle(&frame(opcode::LINK, 1, &body), &fs)),
            0
        );

        let mut body = Vec::new();
        put_u32(&mut body, 5);
        put_u32(&mut body, 1);
        body.extend_from_slice(b"user.tag\0hello");
        assert_eq!(
            errno_of(&session.handle(&frame(opcode::SETXATTR, 7, &body), &fs)),
            0
        );

        let mut body = Vec::new();
        put_u32(&mut body, 64);
        put_u32(&mut body, 0);
        body.extend_from_slice(b"user.tag\0");
        assert_eq!(
            errno_of(&session.handle(&frame(opcode::GETXATTR, 7, &body), &fs)),
            0
        );
        let mut body = Vec::new();
        put_u32(&mut body, 4);
        put_u32(&mut body, 0);
        body.extend_from_slice(b"user.tag\0");
        assert_eq!(
            errno_of(&session.handle(&frame(opcode::GETXATTR, 7, &body), &fs)),
            errno::ERANGE
        );
        let mut body = Vec::new();
        put_u32(&mut body, 0);
        put_u32(&mut body, 0);
        body.extend_from_slice(b"user.tag\0");
        assert_eq!(
            errno_of(&session.handle(&frame(opcode::GETXATTR, 7, &body), &fs)),
            0
        );

        let mut body = Vec::new();
        put_u32(&mut body, 64);
        put_u32(&mut body, 0);
        assert_eq!(
            errno_of(&session.handle(&frame(opcode::LISTXATTR, 7, &body), &fs)),
            0
        );

        assert_eq!(
            errno_of(&session.handle(&frame(opcode::REMOVEXATTR, 7, b"user.tag\0"), &fs)),
            0
        );

        assert_eq!(
            fs.called(),
            "mkdir(1,nest,755,1000:100),create(1,file.txt,100644,1000:100),\
             write(7,11,4096,5),unlink(1,gone),rmdir(1,nest),\
             rename(1,old,2,new,true),rename(1,a,2,b,false),\
             setattr(7,valid=0x8),flush(7,11),fsync(7,11,true),\
             symlink(1,ln,../t,1000:100),readlink(7),\
             mknod(1,pipe,10644,259,1000:100),link(7,1,hard),\
             setxattr(7,user.tag,5,1),getxattr(7,user.tag),\
             getxattr(7,user.tag),getxattr(7,user.tag),listxattr(7),\
             removexattr(7,user.tag)"
        );
    }

    #[test]
    fn hostile_bodies_are_refused_before_the_filesystem() {
        let fs = Probe::default();
        let session = negotiated(&fs);

        let mut body = Vec::new();
        put_u64(&mut body, 11);
        put_u64(&mut body, 0);
        put_u32(&mut body, 500);
        put_u32(&mut body, 0);
        put_u64(&mut body, 0);
        put_u32(&mut body, 0);
        put_u32(&mut body, 0);
        body.extend_from_slice(b"short");
        assert_eq!(
            errno_of(&session.handle(&frame(opcode::WRITE, 7, &body), &fs)),
            errno::EINVAL
        );

        assert_eq!(
            errno_of(&session.handle(&frame(opcode::WRITE, 7, &[0u8; 12]), &fs)),
            errno::EINVAL
        );

        assert_eq!(
            errno_of(&session.handle(&frame(opcode::LINK, 1, &[0u8; 4]), &fs)),
            errno::EINVAL
        );
        assert_eq!(
            errno_of(&session.handle(&frame(opcode::LINK, 1, &[0u8; 8]), &fs)),
            errno::EINVAL
        );

        let mut body = Vec::new();
        put_u32(&mut body, 500);
        put_u32(&mut body, 0);
        body.extend_from_slice(b"user.tag\0short");
        assert_eq!(
            errno_of(&session.handle(&frame(opcode::SETXATTR, 7, &body), &fs)),
            errno::EINVAL
        );
        assert_eq!(
            errno_of(&session.handle(&frame(opcode::SETXATTR, 7, &[0u8; 8]), &fs)),
            errno::EINVAL
        );
        assert_eq!(
            errno_of(&session.handle(&frame(opcode::GETXATTR, 7, &[0u8; 4]), &fs)),
            errno::EINVAL
        );

        assert_eq!(
            errno_of(&session.handle(&frame(opcode::SYMLINK, 1, b"only-name\0"), &fs)),
            errno::EINVAL
        );
        assert_eq!(
            errno_of(&session.handle(&frame(opcode::MKNOD, 1, &[0u8; 8]), &fs)),
            errno::EINVAL
        );
        assert_eq!(
            errno_of(&session.handle(&frame(opcode::MKNOD, 1, &[0u8; 16]), &fs)),
            errno::EINVAL
        );

        for body in [b"".as_slice(), b"\0", b"unterminated"] {
            assert_eq!(
                errno_of(&session.handle(&frame(opcode::UNLINK, 1, body), &fs)),
                errno::EINVAL
            );
        }
        let mut body = Vec::new();
        put_u64(&mut body, 2);
        body.extend_from_slice(b"only\0");
        assert_eq!(
            errno_of(&session.handle(&frame(opcode::RENAME, 1, &body), &fs)),
            errno::EINVAL
        );

        assert_eq!(
            errno_of(&session.handle(&frame(opcode::MKDIR, 1, &[0u8; 4]), &fs)),
            errno::EINVAL
        );

        assert_eq!(
            errno_of(&session.handle(&frame(opcode::SETATTR, 7, &[0u8; 87]), &fs)),
            errno::EINVAL
        );

        let mut body = Vec::new();
        put_u64(&mut body, 2);
        put_u32(&mut body, rename_flags::EXCHANGE);
        put_u32(&mut body, 0);
        body.extend_from_slice(b"a\0b\0");
        assert_eq!(
            errno_of(&session.handle(&frame(opcode::RENAME2, 1, &body), &fs)),
            errno::EINVAL
        );

        for op in [opcode::READ, opcode::READDIR] {
            let mut body = Vec::new();
            put_u64(&mut body, 9);
            put_u64(&mut body, 0);
            put_u32(&mut body, u32::MAX);
            put_u32(&mut body, 0);
            put_u64(&mut body, 0);
            put_u32(&mut body, 0);
            put_u32(&mut body, 0);
            assert_eq!(
                errno_of(&session.handle(&frame(op, 7, &body), &fs)),
                errno::EINVAL
            );
        }

        let mut lying = frame(opcode::GETATTR, 1, &[0u8; 16]);
        lying[0] = 0xFF;
        assert_eq!(session.handle(&lying, &fs), Outcome::Silent);
        assert_eq!(session.handle(&[0u8; 10], &fs), Outcome::Silent);

        assert_eq!(fs.called(), "");
    }

    #[test]
    fn session_lifecycle_is_enforced() {
        let fs = Probe::default();
        let session = Session::new();

        let getattr = frame(opcode::GETATTR, 1, &[0u8; 16]);
        assert_eq!(errno_of(&session.handle(&getattr, &fs)), errno::EIO);
        assert_eq!(fs.called(), "");

        assert_eq!(
            session.handle(&frame(opcode::FORGET, 1, &[0u8; 8]), &fs),
            Outcome::Silent
        );
        assert_eq!(
            session.handle(&frame(opcode::INTERRUPT, 0, &[0u8; 8]), &fs),
            Outcome::Silent
        );

        let outcome = session.handle(&frame(opcode::INIT, 0, &init_body()), &fs);
        assert!(matches!(outcome, Outcome::Reply(_)));
        assert_eq!(errno_of(&session.handle(&getattr, &fs)), 0);

        assert_eq!(
            errno_of(&session.handle(&frame(9999, 1, &[]), &fs)),
            errno::ENOSYS
        );

        assert!(matches!(
            session.handle(&frame(opcode::DESTROY, 0, &[]), &fs),
            Outcome::Farewell(_)
        ));
    }
}
