use scalefs_core::wire::{Cursor, put_u16, put_u32, put_u64};

use crate::mountcore::{MountAttr, MountError};

pub const INTERFACE_VERSION: u16 = 1;

pub const MAX_BODY: usize = 1 << 20;

pub const MAX_FRAME: usize = MAX_BODY + 72;

pub mod op {
    pub const HELLO: u16 = 1;
    pub const STATFS: u16 = 2;
    pub const LOOKUP: u16 = 3;
    pub const GETATTR: u16 = 4;
    pub const SETATTR: u16 = 5;
    pub const READDIR: u16 = 6;
    pub const READ: u16 = 7;
    pub const WRITE: u16 = 8;
    pub const CREATE: u16 = 9;
    pub const MKDIR: u16 = 10;
    pub const MKNOD: u16 = 11;
    pub const SYMLINK: u16 = 12;
    pub const READLINK: u16 = 13;
    pub const LINK: u16 = 14;
    pub const UNLINK: u16 = 15;
    pub const RMDIR: u16 = 16;
    pub const RENAME: u16 = 17;
    pub const UNLINK_HANDLE: u16 = 18;
    pub const OPEN: u16 = 19;
    pub const CLOSE: u16 = 20;
    pub const GETXATTR: u16 = 21;
    pub const SETXATTR: u16 = 22;
    pub const LISTXATTR: u16 = 23;
    pub const REMOVEXATTR: u16 = 24;
    pub const FSYNC: u16 = 25;
    pub const BYE: u16 = 26;
    pub const READDIR_PLUS: u16 = 27;

    pub const EJECT_PREPARE: u16 = 0x0100;
    pub const EJECT_ABORT: u16 = 0x0101;
    pub const EJECT_COMMIT: u16 = 0x0102;
}

pub mod request_flags {
    pub const FSYNC_ON_CLOSE: u16 = 1 << 0;
}

pub mod eject {
    pub const ACK: u8 = 0;
    pub const NAK_FENCE_HELD: u8 = 1;
    pub const NAK_BUSY_WITH_JOB: u8 = 2;
    pub const NAK_FSYNC_FAILED: u8 = 3;
    pub const UNSUPPORTED: u8 = 4;
    pub const NAK_STATE_WRITE_FAILED: u8 = 5;
    pub const REQUEST_BODY_LEN: usize = 20;
    pub const GENERATION_BODY_LEN: usize = 28;
    pub const BLIND_GENERATION: u64 = 0;
    pub const PREPARE_REPLY_LEN: usize = 9;
}

pub mod status {
    pub const OK: i16 = 0;
    pub const NOT_FOUND: i16 = 1;
    pub const NOT_DIRECTORY: i16 = 2;
    pub const IS_DIRECTORY: i16 = 3;
    pub const EXISTS: i16 = 4;
    pub const NOT_EMPTY: i16 = 5;
    pub const NO_SPACE: i16 = 6;
    pub const TOO_MANY_LINKS: i16 = 7;
    pub const NOT_SUPPORTED: i16 = 8;
    pub const NAME_TOO_LONG: i16 = 9;
    pub const INVALID_NAME: i16 = 10;
    pub const INVALID: i16 = 11;
    pub const READ_ONLY: i16 = 12;
    pub const DENIED: i16 = 13;
    pub const IO: i16 = 14;
    pub const PROTOCOL: i16 = 100;
    pub const BAD_VERSION: i16 = 101;
    pub const BAD_TOKEN: i16 = 102;
    pub const UNKNOWN_OP: i16 = 103;
}

pub mod setattr_mask {
    pub const SIZE: u32 = 1 << 0;
    pub const MODE: u32 = 1 << 1;
    pub const UID: u32 = 1 << 2;
    pub const GID: u32 = 1 << 3;
    pub const ATIME: u32 = 1 << 4;
    pub const MTIME: u32 = 1 << 5;
    pub const CTIME: u32 = 1 << 6;
    pub const CRTIME: u32 = 1 << 7;
    pub const ATIME_NOW: u32 = 1 << 8;
    pub const MTIME_NOW: u32 = 1 << 9;
    pub const ATTRS: u32 = 1 << 10;
    pub const BSD_FLAGS: u32 = 1 << 11;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub req_id: u32,
    pub op: u16,
    pub flags: u16,
    pub body: Vec<u8>,
}

pub fn status_of(error: MountError) -> i16 {
    match error {
        MountError::NotFound => status::NOT_FOUND,
        MountError::NotDirectory => status::NOT_DIRECTORY,
        MountError::IsDirectory => status::IS_DIRECTORY,
        MountError::Exists => status::EXISTS,
        MountError::NotEmpty => status::NOT_EMPTY,
        MountError::NoSpace => status::NO_SPACE,
        MountError::TooManyLinks => status::TOO_MANY_LINKS,
        MountError::NotSupported => status::NOT_SUPPORTED,
        MountError::NameTooLong => status::NAME_TOO_LONG,
        MountError::InvalidName => status::INVALID_NAME,
        MountError::Invalid => status::INVALID,
        MountError::ReadOnly => status::READ_ONLY,
        MountError::Denied => status::DENIED,
        MountError::Io => status::IO,
    }
}

pub fn read_request<R: std::io::Read>(reader: &mut R) -> std::io::Result<Option<Request>> {
    let mut len_bytes = [0u8; 4];
    if !read_exact_or_eof(reader, &mut len_bytes)? {
        return Ok(None);
    }
    let frame_len = u32::from_le_bytes(len_bytes) as usize;
    if !(8..=MAX_FRAME).contains(&frame_len) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "data-plane frame length out of range",
        ));
    }
    let mut frame = vec![0u8; frame_len];
    reader.read_exact(&mut frame)?;
    Ok(Some(Request {
        req_id: u32::from_le_bytes(frame[0..4].try_into().expect("4 bytes")),
        op: u16::from_le_bytes(frame[4..6].try_into().expect("2 bytes")),
        flags: u16::from_le_bytes(frame[6..8].try_into().expect("2 bytes")),
        body: frame[8..].to_vec(),
    }))
}

pub fn write_response<W: std::io::Write>(
    writer: &mut W,
    req_id: u32,
    status: i16,
    body: &[u8],
) -> std::io::Result<()> {
    debug_assert!(8 + body.len() <= MAX_FRAME);
    let mut frame = Vec::with_capacity(12 + body.len());
    put_u32(&mut frame, (8 + body.len()) as u32);
    put_u32(&mut frame, req_id);
    frame.extend_from_slice(&status.to_le_bytes());
    put_u16(&mut frame, 0);
    frame.extend_from_slice(body);
    writer.write_all(&frame)
}

fn read_exact_or_eof<R: std::io::Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) if filled == 0 => return Ok(false),
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "peer closed mid-frame",
                ));
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

pub fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

pub fn take_bytes<'a>(cursor: &mut Cursor<'a>) -> Result<&'a [u8], scalefs_core::ScaleFsError> {
    let len = cursor.take_u32()? as usize;
    cursor.take(len)
}

pub fn put_attr(out: &mut Vec<u8>, attr: &MountAttr) {
    put_u64(out, attr.inode);
    put_u32(out, attr.attrs.mode);
    put_u32(out, attr.attrs.nlink);
    put_u32(out, attr.attrs.uid);
    put_u32(out, attr.attrs.gid);
    put_u64(out, attr.attrs.size);
    put_u32(out, attr.blksize);
    put_u64(out, attr.rdev);
    out.extend_from_slice(&attr.attrs.atime_ns.to_le_bytes());
    out.extend_from_slice(&attr.attrs.mtime_ns.to_le_bytes());
    out.extend_from_slice(&attr.attrs.ctime_ns.to_le_bytes());
    out.extend_from_slice(&attr.attrs.crtime_ns.to_le_bytes());
    put_u32(out, u32::from(attr.deferred));
    put_u32(out, attr.attrs.bsd_flags);
}

pub const ATTR_LEN: usize = 84;

#[cfg(test)]
mod tests {
    use super::*;
    use scalefs_core::tree::InodeAttrs;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn fixture_attr() -> MountAttr {
        MountAttr {
            inode: 0x1122_3344_5566_7788,
            attrs: InodeAttrs {
                size: 4096,
                mode: 0o100644,
                uid: 1000,
                gid: 100,
                nlink: 2,
                attrs: 0x20,
                bsd_flags: 0x8000,
                crtime_ns: 1_700_000_000_000_000_001,
                mtime_ns: 1_700_000_000_000_000_002,
                ctime_ns: 1_700_000_000_000_000_003,
                atime_ns: 1_700_000_000_000_000_004,
            },
            blksize: 4096,
            deferred: true,
            rdev: 0,
        }
    }

    #[test]
    fn golden_attr_fixture_is_stable() {
        let mut out = Vec::new();
        put_attr(&mut out, &fixture_attr());
        assert_eq!(out.len(), ATTR_LEN);
        assert_eq!(
            hex(&out),
            "8877665544332211a481000002000000e8030000640000000010000000000000\
             00100000000000000000000004002a36fe9c971702002a36fe9c971703002a36\
             fe9c971701002a36fe9c97170100000000800000"
        );
    }

    #[test]
    fn frames_round_trip_and_reject_hostile_lengths() {
        let mut buf = Vec::new();
        put_u32(&mut buf, 8 + 3);
        put_u32(&mut buf, 42);
        put_u16(&mut buf, op::LOOKUP);
        put_u16(&mut buf, 0);
        buf.extend_from_slice(b"abc");
        let request = read_request(&mut buf.as_slice()).unwrap().unwrap();
        assert_eq!(request.req_id, 42);
        assert_eq!(request.op, op::LOOKUP);
        assert_eq!(request.body, b"abc");

        assert!(read_request(&mut [].as_slice()).unwrap().is_none());

        assert!(read_request(&mut buf[..7].to_vec().as_slice()).is_err());

        let mut hostile = Vec::new();
        put_u32(&mut hostile, u32::MAX);
        assert!(read_request(&mut hostile.as_slice()).is_err());
        let mut tiny = Vec::new();
        put_u32(&mut tiny, 4);
        assert!(read_request(&mut tiny.as_slice()).is_err());
    }

    #[test]
    fn responses_encode_status_and_body() {
        let mut out = Vec::new();
        write_response(&mut out, 7, status::NOT_FOUND, b"").unwrap();
        assert_eq!(hex(&out), "080000000700000001000000");
        let mut out = Vec::new();
        write_response(&mut out, 8, status::OK, b"xy").unwrap();
        assert_eq!(hex(&out), "0a0000000800000000000000".to_string() + "7879");
    }
}
