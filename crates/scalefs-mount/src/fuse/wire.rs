
use scalefs_core::error::{Result, ScaleFsError};
use scalefs_core::wire::{Cursor, put_u16, put_u32, put_u64};

pub const KERNEL_VERSION: u32 = 7;
pub const WANTED_MINOR: u32 = 31;

pub mod opcode {
    pub const LOOKUP: u32 = 1;
    pub const FORGET: u32 = 2;
    pub const GETATTR: u32 = 3;
    pub const SETATTR: u32 = 4;
    pub const READLINK: u32 = 5;
    pub const SYMLINK: u32 = 6;
    pub const MKNOD: u32 = 8;
    pub const MKDIR: u32 = 9;
    pub const UNLINK: u32 = 10;
    pub const RMDIR: u32 = 11;
    pub const RENAME: u32 = 12;
    pub const LINK: u32 = 13;
    pub const OPEN: u32 = 14;
    pub const READ: u32 = 15;
    pub const WRITE: u32 = 16;
    pub const STATFS: u32 = 17;
    pub const RELEASE: u32 = 18;
    pub const FSYNC: u32 = 20;
    pub const SETXATTR: u32 = 21;
    pub const GETXATTR: u32 = 22;
    pub const LISTXATTR: u32 = 23;
    pub const REMOVEXATTR: u32 = 24;
    pub const FLUSH: u32 = 25;
    pub const INIT: u32 = 26;
    pub const OPENDIR: u32 = 27;
    pub const READDIR: u32 = 28;
    pub const RELEASEDIR: u32 = 29;
    pub const FSYNCDIR: u32 = 30;
    pub const ACCESS: u32 = 34;
    pub const CREATE: u32 = 35;
    pub const INTERRUPT: u32 = 36;
    pub const DESTROY: u32 = 38;
    pub const BATCH_FORGET: u32 = 42;
    pub const RENAME2: u32 = 45;
}

pub mod errno {
    pub const EPERM: i32 = 1;
    pub const ENOENT: i32 = 2;
    pub const EIO: i32 = 5;
    pub const EACCES: i32 = 13;
    pub const EEXIST: i32 = 17;
    pub const ENOTDIR: i32 = 20;
    pub const EISDIR: i32 = 21;
    pub const EINVAL: i32 = 22;
    pub const ENOSPC: i32 = 28;
    pub const EROFS: i32 = 30;
    pub const EMLINK: i32 = 31;
    pub const ENAMETOOLONG: i32 = 36;
    pub const ENOSYS: i32 = 38;
    pub const ENOTEMPTY: i32 = 39;
    pub const ERANGE: i32 = 34;
    pub const ENODATA: i32 = 61;
    pub const EOPNOTSUPP: i32 = 95;
}

pub mod flags {
    pub const BIG_WRITES: u32 = 1 << 5;
    pub const MAX_PAGES: u32 = 1 << 22;
}

pub mod setattr_flags {
    pub const MODE: u32 = 1 << 0;
    pub const UID: u32 = 1 << 1;
    pub const GID: u32 = 1 << 2;
    pub const SIZE: u32 = 1 << 3;
    pub const ATIME: u32 = 1 << 4;
    pub const MTIME: u32 = 1 << 5;
    pub const ATIME_NOW: u32 = 1 << 7;
    pub const MTIME_NOW: u32 = 1 << 8;
    pub const CTIME: u32 = 1 << 10;
}

pub mod rename_flags {
    pub const NOREPLACE: u32 = 1 << 0;
    pub const EXCHANGE: u32 = 1 << 1;
    pub const WHITEOUT: u32 = 1 << 2;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InHeader {
    pub len: u32,
    pub opcode: u32,
    pub unique: u64,
    pub nodeid: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

impl InHeader {
    pub const SIZE: usize = 40;

    pub fn decode(cursor: &mut Cursor<'_>) -> Result<InHeader> {
        let header = InHeader {
            len: cursor.take_u32()?,
            opcode: cursor.take_u32()?,
            unique: cursor.take_u64()?,
            nodeid: cursor.take_u64()?,
            uid: cursor.take_u32()?,
            gid: cursor.take_u32()?,
            pid: cursor.take_u32()?,
        };
        cursor.take_u32()?;
        Ok(header)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Attr {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atime_nsec: u32,
    pub mtime_nsec: u32,
    pub ctime_nsec: u32,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub blksize: u32,
}

impl Attr {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u64(out, self.ino);
        put_u64(out, self.size);
        put_u64(out, self.blocks);
        put_u64(out, self.atime);
        put_u64(out, self.mtime);
        put_u64(out, self.ctime);
        put_u32(out, self.atime_nsec);
        put_u32(out, self.mtime_nsec);
        put_u32(out, self.ctime_nsec);
        put_u32(out, self.mode);
        put_u32(out, self.nlink);
        put_u32(out, self.uid);
        put_u32(out, self.gid);
        put_u32(out, self.rdev);
        put_u32(out, self.blksize);
        put_u32(out, 0);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitIn {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
}

impl InitIn {
    pub fn decode(cursor: &mut Cursor<'_>) -> Result<InitIn> {
        Ok(InitIn {
            major: cursor.take_u32()?,
            minor: cursor.take_u32()?,
            max_readahead: cursor.take_u32()?,
            flags: cursor.take_u32()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitOut {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
    pub max_write: u32,
    pub max_pages: u16,
}

impl InitOut {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u32(out, self.major);
        put_u32(out, self.minor);
        if self.minor < 5 {
            return;
        }
        put_u32(out, self.max_readahead);
        put_u32(out, self.flags);
        put_u16(out, 0);
        put_u16(out, 0);
        put_u32(out, self.max_write);
        if self.minor < 23 {
            return;
        }
        put_u32(out, 1);
        put_u16(out, self.max_pages);
        put_u16(out, 0);
        put_u32(out, 0);
        for _ in 0..7 {
            put_u32(out, 0);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryOut {
    pub nodeid: u64,
    pub generation: u64,
    pub entry_valid: u64,
    pub attr_valid: u64,
    pub entry_valid_nsec: u32,
    pub attr_valid_nsec: u32,
    pub attr: Attr,
}

impl EntryOut {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u64(out, self.nodeid);
        put_u64(out, self.generation);
        put_u64(out, self.entry_valid);
        put_u64(out, self.attr_valid);
        put_u32(out, self.entry_valid_nsec);
        put_u32(out, self.attr_valid_nsec);
        self.attr.encode(out);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttrOut {
    pub attr_valid: u64,
    pub attr_valid_nsec: u32,
    pub attr: Attr,
}

impl AttrOut {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u64(out, self.attr_valid);
        put_u32(out, self.attr_valid_nsec);
        put_u32(out, 0);
        self.attr.encode(out);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetattrIn {
    pub flags: u32,
    pub fh: u64,
}

impl GetattrIn {
    pub fn decode(cursor: &mut Cursor<'_>) -> Result<GetattrIn> {
        let flags = cursor.take_u32()?;
        cursor.take_u32()?;
        let fh = cursor.take_u64()?;
        Ok(GetattrIn { flags, fh })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenIn {
    pub flags: u32,
}

impl OpenIn {
    pub fn decode(cursor: &mut Cursor<'_>) -> Result<OpenIn> {
        let flags = cursor.take_u32()?;
        cursor.take_u32()?;
        Ok(OpenIn { flags })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenOut {
    pub fh: u64,
    pub open_flags: u32,
}

impl OpenOut {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u64(out, self.fh);
        put_u32(out, self.open_flags);
        put_u32(out, 0);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadIn {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
}

impl ReadIn {
    pub fn decode(cursor: &mut Cursor<'_>) -> Result<ReadIn> {
        let fh = cursor.take_u64()?;
        let offset = cursor.take_u64()?;
        let size = cursor.take_u32()?;
        cursor.take_u32()?;
        cursor.take_u64()?;
        cursor.take_u32()?;
        cursor.take_u32()?;
        Ok(ReadIn { fh, offset, size })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseIn {
    pub fh: u64,
}

impl ReleaseIn {
    pub fn decode(cursor: &mut Cursor<'_>) -> Result<ReleaseIn> {
        let fh = cursor.take_u64()?;
        cursor.take_u32()?;
        cursor.take_u32()?;
        cursor.take_u64()?;
        Ok(ReleaseIn { fh })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteIn {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
}

impl WriteIn {
    pub const SIZE: usize = 40;

    pub fn decode(cursor: &mut Cursor<'_>) -> Result<WriteIn> {
        let fh = cursor.take_u64()?;
        let offset = cursor.take_u64()?;
        let size = cursor.take_u32()?;
        cursor.take_u32()?;
        cursor.take_u64()?;
        cursor.take_u32()?;
        cursor.take_u32()?;
        Ok(WriteIn { fh, offset, size })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetattrIn {
    pub valid: u32,
    pub fh: u64,
    pub size: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atime_nsec: u32,
    pub mtime_nsec: u32,
    pub ctime_nsec: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

impl SetattrIn {
    pub fn decode(cursor: &mut Cursor<'_>) -> Result<SetattrIn> {
        let valid = cursor.take_u32()?;
        cursor.take_u32()?;
        let fh = cursor.take_u64()?;
        let size = cursor.take_u64()?;
        cursor.take_u64()?;
        let atime = cursor.take_u64()?;
        let mtime = cursor.take_u64()?;
        let ctime = cursor.take_u64()?;
        let atime_nsec = cursor.take_u32()?;
        let mtime_nsec = cursor.take_u32()?;
        let ctime_nsec = cursor.take_u32()?;
        let mode = cursor.take_u32()?;
        cursor.take_u32()?;
        let uid = cursor.take_u32()?;
        let gid = cursor.take_u32()?;
        cursor.take_u32()?;
        Ok(SetattrIn {
            valid,
            fh,
            size,
            atime,
            mtime,
            ctime,
            atime_nsec,
            mtime_nsec,
            ctime_nsec,
            mode,
            uid,
            gid,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateIn {
    pub flags: u32,
    pub mode: u32,
}

impl CreateIn {
    pub const SIZE: usize = 16;

    pub fn decode(cursor: &mut Cursor<'_>) -> Result<CreateIn> {
        let flags = cursor.take_u32()?;
        let mode = cursor.take_u32()?;
        cursor.take_u32()?;
        cursor.take_u32()?;
        Ok(CreateIn { flags, mode })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MkdirIn {
    pub mode: u32,
}

impl MkdirIn {
    pub const SIZE: usize = 8;

    pub fn decode(cursor: &mut Cursor<'_>) -> Result<MkdirIn> {
        let mode = cursor.take_u32()?;
        cursor.take_u32()?;
        Ok(MkdirIn { mode })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MknodIn {
    pub mode: u32,
    pub rdev: u32,
}

impl MknodIn {
    pub const SIZE: usize = 16;

    pub fn decode(cursor: &mut Cursor<'_>) -> Result<MknodIn> {
        let mode = cursor.take_u32()?;
        let rdev = cursor.take_u32()?;
        cursor.take_u32()?;
        cursor.take_u32()?;
        Ok(MknodIn { mode, rdev })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetxattrIn {
    pub size: u32,
    pub flags: u32,
}

impl SetxattrIn {
    pub const SIZE: usize = 8;

    pub fn decode(cursor: &mut Cursor<'_>) -> Result<SetxattrIn> {
        Ok(SetxattrIn {
            size: cursor.take_u32()?,
            flags: cursor.take_u32()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetxattrIn {
    pub size: u32,
}

impl GetxattrIn {
    pub const SIZE: usize = 8;

    pub fn decode(cursor: &mut Cursor<'_>) -> Result<GetxattrIn> {
        let size = cursor.take_u32()?;
        cursor.take_u32()?;
        Ok(GetxattrIn { size })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkIn {
    pub oldnodeid: u64,
}

impl LinkIn {
    pub const SIZE: usize = 8;

    pub fn decode(cursor: &mut Cursor<'_>) -> Result<LinkIn> {
        Ok(LinkIn {
            oldnodeid: cursor.take_u64()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenameIn {
    pub newdir: u64,
}

impl RenameIn {
    pub const SIZE: usize = 8;

    pub fn decode(cursor: &mut Cursor<'_>) -> Result<RenameIn> {
        Ok(RenameIn {
            newdir: cursor.take_u64()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rename2In {
    pub newdir: u64,
    pub flags: u32,
}

impl Rename2In {
    pub const SIZE: usize = 16;

    pub fn decode(cursor: &mut Cursor<'_>) -> Result<Rename2In> {
        let newdir = cursor.take_u64()?;
        let flags = cursor.take_u32()?;
        cursor.take_u32()?;
        Ok(Rename2In { newdir, flags })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlushIn {
    pub fh: u64,
}

impl FlushIn {
    pub fn decode(cursor: &mut Cursor<'_>) -> Result<FlushIn> {
        let fh = cursor.take_u64()?;
        cursor.take_u32()?;
        cursor.take_u32()?;
        cursor.take_u64()?;
        Ok(FlushIn { fh })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsyncIn {
    pub fh: u64,
    pub flags: u32,
}

impl FsyncIn {
    pub fn decode(cursor: &mut Cursor<'_>) -> Result<FsyncIn> {
        let fh = cursor.take_u64()?;
        let flags = cursor.take_u32()?;
        cursor.take_u32()?;
        Ok(FsyncIn { fh, flags })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StatfsOut {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub bsize: u32,
    pub namelen: u32,
    pub frsize: u32,
}

impl StatfsOut {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u64(out, self.blocks);
        put_u64(out, self.bfree);
        put_u64(out, self.bavail);
        put_u64(out, self.files);
        put_u64(out, self.ffree);
        put_u32(out, self.bsize);
        put_u32(out, self.namelen);
        put_u32(out, self.frsize);
        put_u32(out, 0);
        for _ in 0..6 {
            put_u32(out, 0);
        }
    }
}

pub mod dirent_type {
    pub const FIFO: u32 = 1;
    pub const CHAR_DEVICE: u32 = 2;
    pub const DIRECTORY: u32 = 4;
    pub const BLOCK_DEVICE: u32 = 6;
    pub const REGULAR: u32 = 8;
    pub const SYMLINK: u32 = 10;
    pub const SOCKET: u32 = 12;
}

pub fn push_dirent(
    out: &mut Vec<u8>,
    capacity: usize,
    ino: u64,
    next_offset: u64,
    kind: u32,
    name: &[u8],
) -> bool {
    let record = 24 + name.len();
    let padded = record.div_ceil(8) * 8;
    if out.len() + padded > capacity {
        return false;
    }
    put_u64(out, ino);
    put_u64(out, next_offset);
    put_u32(out, name.len() as u32);
    put_u32(out, kind);
    out.extend_from_slice(name);
    out.resize(out.len() + (padded - record), 0);
    true
}

pub fn reply_payload(unique: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + payload.len());
    put_u32(&mut out, (16 + payload.len()) as u32);
    put_u32(&mut out, 0i32 as u32);
    put_u64(&mut out, unique);
    out.extend_from_slice(payload);
    out
}

pub fn reply_error(unique: u64, errno: i32) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    put_u32(&mut out, 16);
    put_u32(&mut out, (-errno) as u32);
    put_u64(&mut out, unique);
    out
}

pub fn reply_init(unique: u64, init: &InitOut) -> Vec<u8> {
    let mut payload = Vec::with_capacity(64);
    init.encode(&mut payload);
    reply_payload(unique, &payload)
}

pub fn reply_entry(unique: u64, entry: &EntryOut) -> Vec<u8> {
    let mut payload = Vec::with_capacity(128);
    entry.encode(&mut payload);
    reply_payload(unique, &payload)
}

pub fn reply_attr(unique: u64, attr: &AttrOut) -> Vec<u8> {
    let mut payload = Vec::with_capacity(104);
    attr.encode(&mut payload);
    reply_payload(unique, &payload)
}

pub fn reply_open(unique: u64, open: &OpenOut) -> Vec<u8> {
    let mut payload = Vec::with_capacity(16);
    open.encode(&mut payload);
    reply_payload(unique, &payload)
}

pub fn reply_statfs(unique: u64, statfs: &StatfsOut) -> Vec<u8> {
    let mut payload = Vec::with_capacity(80);
    statfs.encode(&mut payload);
    reply_payload(unique, &payload)
}

pub fn reply_write(unique: u64, written: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8);
    put_u32(&mut payload, written);
    put_u32(&mut payload, 0);
    reply_payload(unique, &payload)
}

pub fn reply_getxattr_size(unique: u64, size: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8);
    put_u32(&mut payload, size);
    put_u32(&mut payload, 0);
    reply_payload(unique, &payload)
}

pub fn reply_create(unique: u64, entry: &EntryOut, open: &OpenOut) -> Vec<u8> {
    let mut payload = Vec::with_capacity(144);
    entry.encode(&mut payload);
    open.encode(&mut payload);
    reply_payload(unique, &payload)
}

pub fn name_from(body: &[u8]) -> Option<&[u8]> {
    let end = body.iter().position(|&byte| byte == 0)?;
    if end == 0 {
        return None;
    }
    Some(&body[..end])
}

pub fn two_names_from(body: &[u8]) -> Option<(&[u8], &[u8])> {
    let first = name_from(body)?;
    let second = name_from(&body[first.len() + 1..])?;
    Some((first, second))
}

pub fn split_request(frame: &[u8]) -> Result<(InHeader, &[u8])> {
    if frame.len() < InHeader::SIZE {
        return Err(ScaleFsError::Corrupt("short fuse request"));
    }
    let mut cursor = Cursor::new(&frame[..InHeader::SIZE]);
    let header = InHeader::decode(&mut cursor)?;
    if header.len as usize != frame.len() {
        return Err(ScaleFsError::Corrupt(
            "fuse request length disagrees with the frame",
        ));
    }
    Ok((header, &frame[InHeader::SIZE..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn in_header_golden() {
        let mut frame = Vec::new();
        put_u32(&mut frame, 48);
        put_u32(&mut frame, opcode::GETATTR);
        put_u64(&mut frame, 0x1122_3344_5566_7788);
        put_u64(&mut frame, 1);
        put_u32(&mut frame, 1000);
        put_u32(&mut frame, 1000);
        put_u32(&mut frame, 4242);
        put_u32(&mut frame, 0);
        frame.extend_from_slice(&[0u8; 8]);
        let (header, body) = split_request(&frame).unwrap();
        assert_eq!(header.opcode, opcode::GETATTR);
        assert_eq!(header.unique, 0x1122_3344_5566_7788);
        assert_eq!(header.nodeid, 1);
        assert_eq!(header.pid, 4242);
        assert_eq!(body.len(), 8);
        assert!(split_request(&frame[..frame.len() - 1]).is_err());
    }

    #[test]
    fn reply_goldens() {
        assert_eq!(
            hex(&reply_error(7, errno::ENOENT)),
            "10000000feffffff0700000000000000",
        );
        let attr = Attr {
            ino: 2,
            size: 20,
            blocks: 1,
            mtime: 0x5F5E100,
            mode: 0o100644,
            nlink: 1,
            blksize: 4096,
            ..Attr::default()
        };
        let out = reply_attr(
            9,
            &AttrOut {
                attr_valid: 1,
                attr_valid_nsec: 0,
                attr,
            },
        );
        assert_eq!(out.len(), 16 + 104);
        assert_eq!(
            hex(&out[..32]),
            "7800000000000000090000000000000001000000000000000000000000000000",
            "header + attr_valid + nsec + dummy",
        );
        assert_eq!(hex(&out[32..48]), "02000000000000001400000000000000");
        assert_eq!(hex(&out[32 + 60..32 + 64]), "a4810000");

        let entry = reply_entry(
            3,
            &EntryOut {
                nodeid: 2,
                generation: 0,
                entry_valid: 1,
                attr_valid: 1,
                entry_valid_nsec: 0,
                attr_valid_nsec: 0,
                attr,
            },
        );
        assert_eq!(entry.len(), 16 + 128);

        let open = reply_open(
            4,
            &OpenOut {
                fh: 77,
                open_flags: 0,
            },
        );
        assert_eq!(hex(&open[16..]), "4d000000000000000000000000000000");
    }

    #[test]
    fn init_out_widths_follow_the_minor() {
        let base = InitOut {
            major: 7,
            minor: 31,
            max_readahead: 65536,
            flags: flags::BIG_WRITES | flags::MAX_PAGES,
            max_write: 1 << 20,
            max_pages: 256,
        };
        assert_eq!(reply_init(1, &base).len(), 16 + 64);
        let old = InitOut { minor: 21, ..base };
        assert_eq!(reply_init(1, &old).len(), 16 + 24);
        let ancient = InitOut { minor: 4, ..base };
        assert_eq!(reply_init(1, &ancient).len(), 16 + 8);
        let full = reply_init(1, &base);
        assert_eq!(hex(&full[16 + 20..16 + 24]), "00001000", "max_write");
        assert_eq!(hex(&full[16 + 28..16 + 30]), "0001", "max_pages");
    }

    #[test]
    fn dirents_align_and_fit() {
        let mut out = Vec::new();
        assert!(push_dirent(
            &mut out,
            4096,
            1,
            1,
            dirent_type::DIRECTORY,
            b"."
        ));
        assert_eq!(out.len(), 32, "24 + 1, padded to 8");
        assert!(push_dirent(
            &mut out,
            4096,
            2,
            2,
            dirent_type::REGULAR,
            b"hello.txt"
        ));
        assert_eq!(out.len(), 32 + 40, "24 + 9, padded to 40");
        assert_eq!(hex(&out[48..56]), "0900000008000000");
        let mut tight = Vec::new();
        assert!(!push_dirent(
            &mut tight,
            16,
            3,
            3,
            dirent_type::REGULAR,
            b"nope"
        ));
        assert!(tight.is_empty());
    }

    #[test]
    fn request_bodies_decode() {
        let mut body = Vec::new();
        put_u64(&mut body, 0xFEED);
        put_u64(&mut body, 4096);
        put_u32(&mut body, 8192);
        put_u32(&mut body, 0);
        put_u64(&mut body, 0);
        put_u32(&mut body, 0);
        put_u32(&mut body, 0);
        let read = ReadIn::decode(&mut Cursor::new(&body)).unwrap();
        assert_eq!(
            read,
            ReadIn {
                fh: 0xFEED,
                offset: 4096,
                size: 8192
            }
        );

        let mut body = Vec::new();
        put_u32(&mut body, 7);
        put_u32(&mut body, 39);
        put_u32(&mut body, 131072);
        put_u32(&mut body, 0xFFFF_FFFF);
        put_u64(&mut body, 0xDEAD_BEEF);
        let init = InitIn::decode(&mut Cursor::new(&body)).unwrap();
        assert_eq!(init.major, 7);
        assert_eq!(init.minor, 39);
    }

    #[test]
    fn write_request_bodies_decode() {
        let mut body = Vec::new();
        put_u64(&mut body, 42);
        put_u64(&mut body, 1 << 30);
        put_u32(&mut body, 4096);
        put_u32(&mut body, 1);
        put_u64(&mut body, 0xABCD);
        put_u32(&mut body, 0);
        put_u32(&mut body, 0);
        assert_eq!(body.len(), WriteIn::SIZE);
        let write = WriteIn::decode(&mut Cursor::new(&body)).unwrap();
        assert_eq!(
            write,
            WriteIn {
                fh: 42,
                offset: 1 << 30,
                size: 4096
            }
        );
        assert!(WriteIn::decode(&mut Cursor::new(&body[..24])).is_err());

        let mut body = Vec::new();
        put_u32(&mut body, setattr_flags::MODE | setattr_flags::SIZE);
        put_u32(&mut body, 0);
        put_u64(&mut body, 7);
        put_u64(&mut body, 12_345);
        put_u64(&mut body, 0);
        put_u64(&mut body, 100);
        put_u64(&mut body, 200);
        put_u64(&mut body, 300);
        put_u32(&mut body, 11);
        put_u32(&mut body, 22);
        put_u32(&mut body, 33);
        put_u32(&mut body, 0o644);
        put_u32(&mut body, 0);
        put_u32(&mut body, 1000);
        put_u32(&mut body, 1001);
        put_u32(&mut body, 0);
        assert_eq!(body.len(), 88);
        let setattr = SetattrIn::decode(&mut Cursor::new(&body)).unwrap();
        assert_eq!(setattr.valid, setattr_flags::MODE | setattr_flags::SIZE);
        assert_eq!(setattr.size, 12_345);
        assert_eq!(setattr.mtime, 200);
        assert_eq!(setattr.ctime_nsec, 33);
        assert_eq!(setattr.mode, 0o644);
        assert_eq!(setattr.gid, 1001);

        let mut body = Vec::new();
        put_u32(&mut body, 0o100_0101);
        put_u32(&mut body, 0o100644);
        put_u32(&mut body, 0o022);
        put_u32(&mut body, 0);
        assert_eq!(body.len(), CreateIn::SIZE);
        let create = CreateIn::decode(&mut Cursor::new(&body)).unwrap();
        assert_eq!(create.mode, 0o100644);

        let mut body = Vec::new();
        put_u32(&mut body, 0o755);
        put_u32(&mut body, 0o022);
        assert_eq!(body.len(), MkdirIn::SIZE);
        assert_eq!(
            MkdirIn::decode(&mut Cursor::new(&body)).unwrap().mode,
            0o755
        );

        let mut body = Vec::new();
        put_u64(&mut body, 9);
        assert_eq!(body.len(), RenameIn::SIZE);
        assert_eq!(RenameIn::decode(&mut Cursor::new(&body)).unwrap().newdir, 9);

        let mut body = Vec::new();
        put_u64(&mut body, 9);
        put_u32(&mut body, rename_flags::NOREPLACE);
        put_u32(&mut body, 0);
        assert_eq!(body.len(), Rename2In::SIZE);
        let rename2 = Rename2In::decode(&mut Cursor::new(&body)).unwrap();
        assert_eq!(rename2.newdir, 9);
        assert_eq!(rename2.flags, rename_flags::NOREPLACE);

        let mut body = Vec::new();
        put_u64(&mut body, 5);
        put_u32(&mut body, 0);
        put_u32(&mut body, 0);
        put_u64(&mut body, 0);
        assert_eq!(FlushIn::decode(&mut Cursor::new(&body)).unwrap().fh, 5);

        let mut body = Vec::new();
        put_u64(&mut body, 6);
        put_u32(&mut body, 1);
        put_u32(&mut body, 0);
        let fsync = FsyncIn::decode(&mut Cursor::new(&body)).unwrap();
        assert_eq!(fsync.fh, 6);
        assert_eq!(fsync.flags & 1, 1);
    }

    #[test]
    fn write_reply_goldens() {
        assert_eq!(
            hex(&reply_write(3, 4096)),
            "18000000000000000300000000000000\
             0010000000000000",
        );
        let attr = Attr {
            ino: 5,
            mode: 0o100600,
            nlink: 1,
            blksize: 4096,
            ..Attr::default()
        };
        let entry = EntryOut {
            nodeid: 5,
            generation: 0,
            entry_valid: 1,
            attr_valid: 1,
            entry_valid_nsec: 0,
            attr_valid_nsec: 0,
            attr,
        };
        let open = OpenOut {
            fh: 88,
            open_flags: 0,
        };
        let create = reply_create(4, &entry, &open);
        assert_eq!(create.len(), 16 + 128 + 16);
        assert_eq!(hex(&create[16 + 128..16 + 136]), "5800000000000000");
    }

    #[test]
    fn names_parse_and_refuse() {
        assert_eq!(name_from(b"docs\0"), Some(b"docs".as_slice()));
        assert_eq!(name_from(b"\0"), None, "empty names do not exist");
        assert_eq!(name_from(b"unterminated"), None);
        let (old, new) = two_names_from(b"old.txt\0new.txt\0").unwrap();
        assert_eq!(old, b"old.txt");
        assert_eq!(new, b"new.txt");
        assert!(two_names_from(b"only\0").is_none());
        assert!(two_names_from(b"a\0\0").is_none(), "second name empty");
    }
}
