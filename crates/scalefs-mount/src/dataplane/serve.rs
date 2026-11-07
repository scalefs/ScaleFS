use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

use scalefs_core::SharedDevice;
use scalefs_core::tree::EntryKind;
use scalefs_core::wire::Cursor;

use super::wire::{
    self, ATTR_LEN, INTERFACE_VERSION, MAX_BODY, Request, eject, op, put_attr, put_bytes,
    request_flags, setattr_mask, status, status_of, take_bytes,
};
use crate::mountcore::{MountCore, SetAttr, TimeChange};

pub trait EjectBarrier: Send + Sync {
    fn prepare(&self, pool_id: &[u8; 16]) -> PrepareOutcome;
    fn abort(&self, pool_id: &[u8; 16], generation: u64);
    fn commit(&self, pool_id: &[u8; 16], generation: u64) -> PrepareVerdict;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrepareVerdict {
    Ack,
    NakFenceHeld,
    NakBusyWithJob,
    NakFsyncFailed,
    Unsupported,
    NakStateWriteFailed,
}

impl PrepareVerdict {
    pub fn wire(self) -> u8 {
        match self {
            PrepareVerdict::Ack => eject::ACK,
            PrepareVerdict::NakFenceHeld => eject::NAK_FENCE_HELD,
            PrepareVerdict::NakBusyWithJob => eject::NAK_BUSY_WITH_JOB,
            PrepareVerdict::NakFsyncFailed => eject::NAK_FSYNC_FAILED,
            PrepareVerdict::Unsupported => eject::UNSUPPORTED,
            PrepareVerdict::NakStateWriteFailed => eject::NAK_STATE_WRITE_FAILED,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrepareOutcome {
    pub verdict: PrepareVerdict,
    pub generation: u64,
}

impl PrepareOutcome {
    pub fn nak(verdict: PrepareVerdict) -> PrepareOutcome {
        PrepareOutcome {
            verdict,
            generation: 0,
        }
    }

    pub fn wire(self) -> [u8; eject::PREPARE_REPLY_LEN] {
        let mut out = [0u8; eject::PREPARE_REPLY_LEN];
        out[0] = self.verdict.wire();
        out[1..].copy_from_slice(&self.generation.to_le_bytes());
        out
    }
}

#[derive(Clone)]
pub struct SessionParams {
    pub pool_id: [u8; 16],
    pub token: Vec<u8>,
    pub read_only: bool,
    pub close_durability: CloseDurability,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseDurability {
    CommitOnClose,
    Bounded(Duration),
}

impl Default for CloseDurability {
    fn default() -> Self {
        CloseDurability::Bounded(CloseDurability::DEFAULT_BOUND)
    }
}

impl CloseDurability {
    pub const MIN_BOUND: Duration = Duration::from_secs(1);
    pub const MAX_BOUND: Duration = Duration::from_secs(5);
    pub const DEFAULT_BOUND: Duration = Duration::from_secs(1);

    fn deferral(self, flags: u16) -> Option<Duration> {
        match self {
            CloseDurability::Bounded(bound) if flags & request_flags::FSYNC_ON_CLOSE != 0 => {
                Some(bound)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    Bye,
    Disconnected,
    Error,
}

const READDIR_BATCH: usize = 2048;

pub fn serve_connection<D: SharedDevice, T: Read + Write>(
    transport: &mut T,
    core: &Arc<MountCore<D>>,
    session: &SessionParams,
    barrier: Option<&dyn EjectBarrier>,
    on_authenticated: Option<&dyn Fn()>,
) -> SessionEnd {
    let trace = std::env::var_os("SCALEFS_DATAPLANE_TRACE").is_some_and(|v| v == "1");
    let perf = scalefs_core::perftrace::enabled();
    let mut hello_done = false;
    loop {
        let waited_from = perf.then(|| {
            (
                scalefs_core::perftrace::unix_ns(),
                std::time::Instant::now(),
            )
        });
        let request = match wire::read_request(transport) {
            Ok(Some(request)) => request,
            Ok(None) => return SessionEnd::Disconnected,
            Err(_) => return SessionEnd::Error,
        };
        let got_at = perf.then(std::time::Instant::now);
        let op_timer = scalefs_core::perftrace::op(
            scalefs_core::perftrace::Surface::Dataplane,
            u32::from(request.op),
        );
        if trace {
            eprintln!(
                "[dataplane] req {} op {} body {}B",
                request.req_id,
                request.op,
                request.body.len()
            );
        }
        let (status, body) = if !hello_done {
            match handle_hello(&request, session) {
                Ok(body) => {
                    hello_done = true;
                    if let Some(on_authenticated) = on_authenticated {
                        on_authenticated();
                    }
                    (status::OK, body)
                }
                Err(code) => {
                    let _ = wire::write_response(transport, request.req_id, code, &[]);
                    return SessionEnd::Error;
                }
            }
        } else if request.op == op::BYE {
            let _ = wire::write_response(transport, request.req_id, status::OK, &[]);
            return SessionEnd::Bye;
        } else if matches!(
            request.op,
            op::EJECT_PREPARE | op::EJECT_ABORT | op::EJECT_COMMIT
        ) {
            match handle_eject(&request, barrier) {
                Ok(reply) => (status::OK, reply),
                Err(code) => (code, Vec::new()),
            }
        } else {
            let close = session.close_durability.deferral(request.flags);
            match dispatch(core, request.op, &request.body, close) {
                Ok(body) => (status::OK, body),
                Err(code) => (code, Vec::new()),
            }
        };
        drop(op_timer);
        let dispatched_at = perf.then(std::time::Instant::now);
        if wire::write_response(transport, request.req_id, status, &body).is_err() {
            return SessionEnd::Error;
        }
        if let (Some((wall, from)), Some(got), Some(dispatched)) =
            (waited_from, got_at, dispatched_at)
        {
            let responded = std::time::Instant::now();
            scalefs_core::perftrace::line(|| {
                format!(
                    "R {} {} {} {} {} {} {} {} {}",
                    request.op,
                    wall,
                    (got - from).as_nanos(),
                    (dispatched - got).as_nanos(),
                    (responded - dispatched).as_nanos(),
                    request.body.len(),
                    body.len(),
                    status,
                    request.flags
                )
            });
        }
    }
}

fn handle_eject(request: &Request, barrier: Option<&dyn EjectBarrier>) -> Result<Vec<u8>, i16> {
    let generation = match (request.op, request.body.len()) {
        (op::EJECT_PREPARE, eject::REQUEST_BODY_LEN) => eject::BLIND_GENERATION,
        (op::EJECT_ABORT, eject::REQUEST_BODY_LEN) => eject::BLIND_GENERATION,
        (op::EJECT_ABORT | op::EJECT_COMMIT, eject::GENERATION_BODY_LEN) => {
            u64::from_le_bytes(request.body[20..28].try_into().expect("8 bytes"))
        }
        _ => return Err(status::PROTOCOL),
    };
    let mut pool_id = [0u8; 16];
    pool_id.copy_from_slice(&request.body[0..16]);
    let reserved = u32::from_le_bytes(request.body[16..20].try_into().expect("4 bytes"));
    if reserved != 0 {
        return Err(status::PROTOCOL);
    }
    let Some(barrier) = barrier else {
        return Ok(match request.op {
            op::EJECT_PREPARE => PrepareOutcome::nak(PrepareVerdict::Unsupported)
                .wire()
                .to_vec(),
            _ => vec![eject::UNSUPPORTED],
        });
    };
    match request.op {
        op::EJECT_PREPARE => Ok(barrier.prepare(&pool_id).wire().to_vec()),
        op::EJECT_COMMIT => Ok(vec![barrier.commit(&pool_id, generation).wire()]),
        _ => {
            barrier.abort(&pool_id, generation);
            Ok(vec![eject::ACK])
        }
    }
}

fn handle_hello(request: &Request, session: &SessionParams) -> Result<Vec<u8>, i16> {
    if request.op != op::HELLO {
        return Err(status::PROTOCOL);
    }
    let mut cursor = Cursor::new(&request.body);
    let client_version = cursor.take_u16().map_err(|_| status::PROTOCOL)?;
    let pool_id: [u8; 16] = cursor.take_array().map_err(|_| status::PROTOCOL)?;
    let token = take_bytes(&mut cursor).map_err(|_| status::PROTOCOL)?;
    if client_version == 0 {
        return Err(status::BAD_VERSION);
    }
    if pool_id != session.pool_id || token != session.token.as_slice() {
        return Err(status::BAD_TOKEN);
    }
    let mut body = Vec::with_capacity(7);
    body.extend_from_slice(&INTERFACE_VERSION.min(client_version).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.push(u8::from(session.read_only));
    Ok(body)
}

fn dispatch<D: SharedDevice>(
    core: &Arc<MountCore<D>>,
    op_code: u16,
    body: &[u8],
    close: Option<Duration>,
) -> Result<Vec<u8>, i16> {
    let mut c = Cursor::new(body);
    match op_code {
        op::STATFS => {
            let statfs = core.statfs().map_err(status_of)?;
            let mut out = Vec::with_capacity(32);
            out.extend_from_slice(&statfs.blocks.to_le_bytes());
            out.extend_from_slice(&statfs.bfree.to_le_bytes());
            out.extend_from_slice(&statfs.bavail.to_le_bytes());
            out.extend_from_slice(&statfs.bsize.to_le_bytes());
            out.extend_from_slice(&statfs.namelen.to_le_bytes());
            Ok(out)
        }
        op::LOOKUP => {
            let parent = take_u64(&mut c)?;
            let name = take_name(&mut c)?;
            attr_reply(core.lookup(parent, name).map_err(status_of)?)
        }
        op::GETATTR => {
            let inode = take_u64(&mut c)?;
            attr_reply(core.getattr(inode).map_err(status_of)?)
        }
        op::SETATTR => {
            let inode = take_u64(&mut c)?;
            let mask = take_u32(&mut c)?;
            let size = take_u64(&mut c)?;
            let mode = take_u32(&mut c)?;
            let uid = take_u32(&mut c)?;
            let gid = take_u32(&mut c)?;
            let atime = take_i64(&mut c)?;
            let mtime = take_i64(&mut c)?;
            let ctime = take_i64(&mut c)?;
            let crtime = take_i64(&mut c)?;
            let attrs = take_u32(&mut c)?;
            let bsd_flags = take_u32(&mut c)?;
            let time_change = |set_bit: u32, now_bit: u32, value: i64| -> Option<TimeChange> {
                if mask & now_bit != 0 {
                    Some(TimeChange::Now)
                } else if mask & set_bit != 0 {
                    Some(TimeChange::Set(value))
                } else {
                    None
                }
            };
            let change = SetAttr {
                size: (mask & setattr_mask::SIZE != 0).then_some(size),
                mode: (mask & setattr_mask::MODE != 0).then_some(mode),
                uid: (mask & setattr_mask::UID != 0).then_some(uid),
                gid: (mask & setattr_mask::GID != 0).then_some(gid),
                atime: time_change(setattr_mask::ATIME, setattr_mask::ATIME_NOW, atime),
                mtime: time_change(setattr_mask::MTIME, setattr_mask::MTIME_NOW, mtime),
                ctime: (mask & setattr_mask::CTIME != 0).then_some(ctime),
                crtime: (mask & setattr_mask::CRTIME != 0).then_some(crtime),
                attributes: (mask & setattr_mask::ATTRS != 0).then_some(attrs),
                bsd_flags: (mask & setattr_mask::BSD_FLAGS != 0).then_some(bsd_flags),
            };
            attr_reply(core.setattr(inode, change).map_err(status_of)?)
        }
        op::READDIR | op::READDIR_PLUS => {
            let inode = take_u64(&mut c)?;
            let cookie = take_u64(&mut c)?;
            let entries = core.readdir_hashed(inode).map_err(status_of)?;
            let mut out = Vec::new();
            let mut emitted = 0u32;
            let mut next = 0u64;
            out.extend_from_slice(&[0u8; 12]);
            let mut current_bucket: Option<u64> = None;
            for hashed in entries.iter().filter(|h| h.hash >= cookie) {
                let new_bucket = current_bucket != Some(hashed.hash);
                if new_bucket
                    && emitted > 0
                    && (emitted as usize >= READDIR_BATCH || out.len() + 320 + ATTR_LEN > MAX_BODY)
                {
                    next = hashed.hash;
                    break;
                }
                let attr = if op_code == op::READDIR_PLUS {
                    match core.getattr(hashed.entry.inode) {
                        Ok(attr) => Some(attr),
                        Err(_) => continue,
                    }
                } else {
                    None
                };
                out.extend_from_slice(&hashed.entry.inode.to_le_bytes());
                out.push(wire_kind(hashed.entry.kind));
                put_bytes(&mut out, hashed.entry.name.as_bytes());
                if let Some(attr) = attr {
                    put_attr(&mut out, &attr);
                }
                emitted += 1;
                current_bucket = Some(hashed.hash);
            }
            out[0..8].copy_from_slice(&next.to_le_bytes());
            out[8..12].copy_from_slice(&emitted.to_le_bytes());
            Ok(out)
        }
        op::READ => {
            let inode = take_u64(&mut c)?;
            let offset = take_u64(&mut c)?;
            let len = take_u32(&mut c)? as usize;
            if len > MAX_BODY {
                return Err(status::PROTOCOL);
            }
            let data = core.read(inode, offset, len).map_err(status_of)?;
            let mut out = Vec::with_capacity(4 + data.len());
            put_bytes(&mut out, &data);
            Ok(out)
        }
        op::WRITE => {
            let inode = take_u64(&mut c)?;
            let offset = take_u64(&mut c)?;
            let data = take_bytes(&mut c).map_err(|_| status::PROTOCOL)?;
            let written = core.write(inode, offset, data).map_err(status_of)?;
            Ok(written.to_le_bytes().to_vec())
        }
        op::CREATE => {
            let parent = take_u64(&mut c)?;
            let name = take_name(&mut c)?;
            let mode = take_u32(&mut c)?;
            let uid = take_u32(&mut c)?;
            let gid = take_u32(&mut c)?;
            attr_reply(
                core.create(parent, name, mode, uid, gid)
                    .map_err(status_of)?,
            )
        }
        op::MKDIR => {
            let parent = take_u64(&mut c)?;
            let name = take_name(&mut c)?;
            let mode = take_u32(&mut c)?;
            let uid = take_u32(&mut c)?;
            let gid = take_u32(&mut c)?;
            attr_reply(
                core.mkdir(parent, name, mode, uid, gid)
                    .map_err(status_of)?,
            )
        }
        op::MKNOD => {
            let parent = take_u64(&mut c)?;
            let name = take_name(&mut c)?;
            let mode = take_u32(&mut c)?;
            let rdev = take_u64(&mut c)?;
            let uid = take_u32(&mut c)?;
            let gid = take_u32(&mut c)?;
            attr_reply(
                core.mknod(parent, name, mode, rdev, uid, gid)
                    .map_err(status_of)?,
            )
        }
        op::SYMLINK => {
            let parent = take_u64(&mut c)?;
            let name = take_name(&mut c)?;
            let target = take_bytes(&mut c).map_err(|_| status::PROTOCOL)?;
            let uid = take_u32(&mut c)?;
            let gid = take_u32(&mut c)?;
            attr_reply(
                core.symlink(parent, name, target, uid, gid)
                    .map_err(status_of)?,
            )
        }
        op::READLINK => {
            let inode = take_u64(&mut c)?;
            let target = core.readlink(inode).map_err(status_of)?;
            let mut out = Vec::with_capacity(4 + target.len());
            put_bytes(&mut out, &target);
            Ok(out)
        }
        op::LINK => {
            let source = take_u64(&mut c)?;
            let new_parent = take_u64(&mut c)?;
            let new_name = take_name(&mut c)?;
            attr_reply(core.link(source, new_parent, new_name).map_err(status_of)?)
        }
        op::UNLINK => {
            let parent = take_u64(&mut c)?;
            let name = take_name(&mut c)?;
            core.unlink(parent, name).map_err(status_of)?;
            Ok(Vec::new())
        }
        op::RMDIR => {
            let parent = take_u64(&mut c)?;
            let name = take_name(&mut c)?;
            core.rmdir(parent, name).map_err(status_of)?;
            Ok(Vec::new())
        }
        op::RENAME => {
            let old_parent = take_u64(&mut c)?;
            let old_name = take_name(&mut c)?.to_string();
            let new_parent = take_u64(&mut c)?;
            let new_name = take_name(&mut c)?;
            let replace = take_bool(&mut c)?;
            core.rename(old_parent, &old_name, new_parent, new_name, replace)
                .map_err(status_of)?;
            Ok(Vec::new())
        }
        op::UNLINK_HANDLE => {
            let parent = take_u64(&mut c)?;
            let name = take_name(&mut c)?;
            let inode = take_u64(&mut c)?;
            let is_dir = take_bool(&mut c)?;
            core.unlink_handle(parent, name, inode, is_dir)
                .map_err(status_of)?;
            Ok(Vec::new())
        }
        op::OPEN => {
            let inode = take_u64(&mut c)?;
            core.retain(inode);
            Ok(Vec::new())
        }
        op::CLOSE => {
            let inode = take_u64(&mut c)?;
            core.release(inode);
            Ok(Vec::new())
        }
        op::GETXATTR => {
            let inode = take_u64(&mut c)?;
            let name = take_name(&mut c)?;
            let value = core.getxattr(inode, name).map_err(status_of)?;
            let mut out = Vec::with_capacity(4 + value.len());
            put_bytes(&mut out, &value);
            Ok(out)
        }
        op::SETXATTR => {
            let inode = take_u64(&mut c)?;
            let name = take_name(&mut c)?.to_string();
            let value = take_bytes(&mut c).map_err(|_| status::PROTOCOL)?;
            let flags = take_u32(&mut c)?;
            core.setxattr(inode, &name, value, flags)
                .map_err(status_of)?;
            Ok(Vec::new())
        }
        op::LISTXATTR => {
            let inode = take_u64(&mut c)?;
            let names = core.listxattr(inode).map_err(status_of)?;
            let mut out = Vec::new();
            out.extend_from_slice(&(names.len() as u32).to_le_bytes());
            for name in &names {
                put_bytes(&mut out, name.as_bytes());
            }
            Ok(out)
        }
        op::REMOVEXATTR => {
            let inode = take_u64(&mut c)?;
            let name = take_name(&mut c)?;
            core.removexattr(inode, name).map_err(status_of)?;
            Ok(Vec::new())
        }
        op::FSYNC => {
            let _inode = take_u64(&mut c)?;
            let _datasync = take_bool(&mut c)?;
            match close {
                Some(bound) => core.commit_within(bound),
                None => core.commit(),
            }
            .map_err(status_of)?;
            Ok(Vec::new())
        }
        op::HELLO => Err(status::PROTOCOL),
        _ => Err(status::UNKNOWN_OP),
    }
}

fn attr_reply(attr: crate::mountcore::MountAttr) -> Result<Vec<u8>, i16> {
    let mut out = Vec::with_capacity(ATTR_LEN);
    put_attr(&mut out, &attr);
    Ok(out)
}

fn wire_kind(kind: EntryKind) -> u8 {
    match kind {
        EntryKind::File => 1,
        EntryKind::Directory => 2,
        EntryKind::Symlink => 3,
        EntryKind::Fifo => 4,
        EntryKind::Socket => 5,
        EntryKind::CharDevice => 6,
        EntryKind::BlockDevice => 7,
        EntryKind::Unknown(_) => 1,
    }
}

fn take_u32(c: &mut Cursor<'_>) -> Result<u32, i16> {
    c.take_u32().map_err(|_| status::PROTOCOL)
}

fn take_u64(c: &mut Cursor<'_>) -> Result<u64, i16> {
    c.take_u64().map_err(|_| status::PROTOCOL)
}

fn take_i64(c: &mut Cursor<'_>) -> Result<i64, i16> {
    c.take_i64().map_err(|_| status::PROTOCOL)
}

fn take_bool(c: &mut Cursor<'_>) -> Result<bool, i16> {
    match c.take_u8().map_err(|_| status::PROTOCOL)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(status::PROTOCOL),
    }
}

fn take_name<'a>(c: &mut Cursor<'a>) -> Result<&'a str, i16> {
    let bytes = take_bytes(c).map_err(|_| status::PROTOCOL)?;
    std::str::from_utf8(bytes).map_err(|_| status::INVALID_NAME)
}
