use scalefs_core::error::Result;
use scalefs_core::wire::{Cursor, put_u16, put_u32, put_u64};

pub type FileId = [u8; 16];

pub mod attr {
    pub const READONLY: u32 = 0x0000_0001;
    pub const DIRECTORY: u32 = 0x0000_0010;
    pub const ARCHIVE: u32 = 0x0000_0020;
    pub const NORMAL: u32 = 0x0000_0080;
}

pub mod disposition {
    pub const SUPERSEDE: u32 = 0;
    pub const OPEN: u32 = 1;
    pub const CREATE: u32 = 2;
    pub const OPEN_IF: u32 = 3;
    pub const OVERWRITE: u32 = 4;
    pub const OVERWRITE_IF: u32 = 5;
}

pub mod action {
    pub const SUPERSEDED: u32 = 0;
    pub const OPENED: u32 = 1;
    pub const CREATED: u32 = 2;
    pub const OVERWRITTEN: u32 = 3;
}

pub mod options {
    pub const DIRECTORY_FILE: u32 = 0x0000_0001;
    pub const NON_DIRECTORY_FILE: u32 = 0x0000_0040;
    pub const DELETE_ON_CLOSE: u32 = 0x0000_1000;
}

pub mod info_type {
    pub const FILE: u8 = 0x01;
    pub const FILESYSTEM: u8 = 0x02;
}

pub mod file_class {
    pub const DIRECTORY: u8 = 0x01;
    pub const FULL_DIRECTORY: u8 = 0x02;
    pub const BOTH_DIRECTORY: u8 = 0x03;
    pub const BASIC: u8 = 0x04;
    pub const STANDARD: u8 = 0x05;
    pub const INTERNAL: u8 = 0x06;
    pub const EA: u8 = 0x07;
    pub const NAME: u8 = 0x09;
    pub const NAMES: u8 = 0x0C;
    pub const STREAM: u8 = 0x16;
    pub const RENAME: u8 = 0x0A;
    pub const LINK: u8 = 0x0B;
    pub const DISPOSITION: u8 = 0x0D;
    pub const POSITION: u8 = 0x0E;
    pub const ALL: u8 = 0x12;
    pub const ALLOCATION: u8 = 0x13;
    pub const END_OF_FILE: u8 = 0x14;
    pub const NETWORK_OPEN: u8 = 0x22;
    pub const ID_BOTH_DIRECTORY: u8 = 0x25;
    pub const ID_FULL_DIRECTORY: u8 = 0x26;
    pub const NORMALIZED_NAME: u8 = 0x30;
}

pub mod fs_class {
    pub const VOLUME: u8 = 1;
    pub const SIZE: u8 = 3;
    pub const DEVICE: u8 = 4;
    pub const ATTRIBUTE: u8 = 5;
    pub const FULL_SIZE: u8 = 7;
}

const FILETIME_EPOCH_DIFF: i64 = 116_444_736_000_000_000;

pub fn to_filetime(ns: i64) -> u64 {
    (ns / 100 + FILETIME_EPOCH_DIFF).max(0) as u64
}

pub fn from_filetime(ft: u64) -> Option<i64> {
    if ft == 0 {
        return None;
    }
    Some((ft as i64 - FILETIME_EPOCH_DIFF).saturating_mul(100))
}

#[derive(Debug, Clone, Copy)]
pub struct FileMeta {
    pub inode: u64,
    pub creation: u64,
    pub access: u64,
    pub write: u64,
    pub change: u64,
    pub alloc_size: u64,
    pub eof: u64,
    pub attributes: u32,
    pub nlink: u32,
    pub is_dir: bool,
}

fn put_filetimes(out: &mut Vec<u8>, m: &FileMeta) {
    put_u64(out, m.creation);
    put_u64(out, m.access);
    put_u64(out, m.write);
    put_u64(out, m.change);
}

#[derive(Debug, Clone)]
pub struct CreateRequest {
    pub desired_access: u32,
    pub file_attributes: u32,
    pub create_disposition: u32,
    pub create_options: u32,
    pub name: Vec<u8>,
}

impl CreateRequest {
    pub fn decode(body: &[u8]) -> Result<CreateRequest> {
        let mut c = Cursor::new(body);
        let _structure_size = c.take_u16()?;
        c.take_u8()?;
        c.take_u8()?;
        c.take_u32()?;
        c.take_u64()?;
        c.take_u64()?;
        let desired_access = c.take_u32()?;
        let file_attributes = c.take_u32()?;
        c.take_u32()?;
        let create_disposition = c.take_u32()?;
        let create_options = c.take_u32()?;
        let name_offset = c.take_u16()? as usize;
        let name_length = c.take_u16()? as usize;
        c.take_u32()?;
        c.take_u32()?;
        let name = slice_from_header(body, name_offset, name_length)?.to_vec();
        Ok(CreateRequest {
            desired_access,
            file_attributes,
            create_disposition,
            create_options,
            name,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ReadRequest {
    pub length: u32,
    pub offset: u64,
    pub file_id: FileId,
}

impl ReadRequest {
    pub fn decode(body: &[u8]) -> Result<ReadRequest> {
        let mut c = Cursor::new(body);
        let _structure_size = c.take_u16()?;
        c.take_u8()?;
        c.take_u8()?;
        let length = c.take_u32()?;
        let offset = c.take_u64()?;
        let file_id = c.take_array::<16>()?;
        Ok(ReadRequest {
            length,
            offset,
            file_id,
        })
    }
}

#[derive(Debug, Clone)]
pub struct WriteRequest {
    pub offset: u64,
    pub file_id: FileId,
    pub data: Vec<u8>,
}

impl WriteRequest {
    pub fn decode(body: &[u8]) -> Result<WriteRequest> {
        let mut c = Cursor::new(body);
        let _structure_size = c.take_u16()?;
        let data_offset = c.take_u16()? as usize;
        let length = c.take_u32()? as usize;
        let offset = c.take_u64()?;
        let file_id = c.take_array::<16>()?;
        let data = slice_from_header(body, data_offset, length)?.to_vec();
        Ok(WriteRequest {
            offset,
            file_id,
            data,
        })
    }
}

pub fn file_id_at(body: &[u8], offset: usize) -> Result<FileId> {
    let mut c = Cursor::new(body.get(offset..).unwrap_or(&[]));
    c.take_array::<16>()
}

#[derive(Debug, Clone, Copy)]
pub struct CloseRequest {
    pub flags: u16,
    pub file_id: FileId,
}

impl CloseRequest {
    pub const POSTQUERY_ATTRIB: u16 = 0x0001;

    pub fn decode(body: &[u8]) -> Result<CloseRequest> {
        let mut c = Cursor::new(body);
        let _structure_size = c.take_u16()?;
        let flags = c.take_u16()?;
        c.take_u32()?;
        let file_id = c.take_array::<16>()?;
        Ok(CloseRequest { flags, file_id })
    }
}

#[derive(Debug, Clone)]
pub struct QueryDirectoryRequest {
    pub info_class: u8,
    pub flags: u8,
    pub file_id: FileId,
    pub output_len: u32,
    pub pattern: Vec<u8>,
}

impl QueryDirectoryRequest {
    pub const RESTART_SCANS: u8 = 0x01;
    pub const RETURN_SINGLE_ENTRY: u8 = 0x02;

    pub fn decode(body: &[u8]) -> Result<QueryDirectoryRequest> {
        let mut c = Cursor::new(body);
        let _structure_size = c.take_u16()?;
        let info_class = c.take_u8()?;
        let flags = c.take_u8()?;
        c.take_u32()?;
        let file_id = c.take_array::<16>()?;
        let name_offset = c.take_u16()? as usize;
        let name_length = c.take_u16()? as usize;
        let output_len = c.take_u32()?;
        let pattern = if name_length == 0 {
            Vec::new()
        } else {
            slice_from_header(body, name_offset, name_length)?.to_vec()
        };
        Ok(QueryDirectoryRequest {
            info_class,
            flags,
            file_id,
            output_len,
            pattern,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct QueryInfoRequest {
    pub info_type: u8,
    pub info_class: u8,
    pub output_len: u32,
    pub file_id: FileId,
}

impl QueryInfoRequest {
    pub fn decode(body: &[u8]) -> Result<QueryInfoRequest> {
        let mut c = Cursor::new(body);
        let _structure_size = c.take_u16()?;
        let info_type = c.take_u8()?;
        let info_class = c.take_u8()?;
        let output_len = c.take_u32()?;
        c.take_u16()?;
        c.take_u16()?;
        c.take_u32()?;
        c.take_u32()?;
        c.take_u32()?;
        let file_id = c.take_array::<16>()?;
        Ok(QueryInfoRequest {
            info_type,
            info_class,
            output_len,
            file_id,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SetInfoRequest {
    pub info_type: u8,
    pub info_class: u8,
    pub file_id: FileId,
    pub input: Vec<u8>,
}

impl SetInfoRequest {
    pub fn decode(body: &[u8]) -> Result<SetInfoRequest> {
        let mut c = Cursor::new(body);
        let _structure_size = c.take_u16()?;
        let info_type = c.take_u8()?;
        let info_class = c.take_u8()?;
        let buffer_length = c.take_u32()? as usize;
        let buffer_offset = c.take_u16()? as usize;
        c.take_u16()?;
        c.take_u32()?;
        let file_id = c.take_array::<16>()?;
        let input = slice_from_header(body, buffer_offset, buffer_length)?.to_vec();
        Ok(SetInfoRequest {
            info_type,
            info_class,
            file_id,
            input,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RenameInfo {
    pub replace: bool,
    pub name: Vec<u8>,
}

impl RenameInfo {
    pub fn decode(input: &[u8]) -> Result<RenameInfo> {
        let mut c = Cursor::new(input);
        let replace = c.take_u8()? != 0;
        c.take(7)?;
        c.take_u64()?;
        let name_length = c.take_u32()? as usize;
        let name = c.take(name_length)?.to_vec();
        Ok(RenameInfo { replace, name })
    }
}

fn slice_from_header(body: &[u8], header_offset: usize, len: usize) -> Result<&[u8]> {
    let start = header_offset.saturating_sub(super::wire::HEADER_LEN);
    body.get(start..start + len)
        .ok_or(scalefs_core::error::ScaleFsError::Corrupt(
            "smb buffer runs past the request",
        ))
}

pub fn create_response(file_id: FileId, create_action: u32, m: &FileMeta) -> Vec<u8> {
    let mut out = Vec::with_capacity(89);
    put_u16(&mut out, 89);
    out.push(0);
    out.push(0);
    put_u32(&mut out, create_action);
    put_filetimes(&mut out, m);
    put_u64(&mut out, m.alloc_size);
    put_u64(&mut out, m.eof);
    put_u32(&mut out, m.attributes);
    put_u32(&mut out, 0);
    out.extend_from_slice(&file_id);
    put_u32(&mut out, 0);
    put_u32(&mut out, 0);
    out
}

pub fn read_response(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + data.len());
    put_u16(&mut out, 17);
    out.push((super::wire::HEADER_LEN + 16) as u8);
    out.push(0);
    put_u32(&mut out, data.len() as u32);
    put_u32(&mut out, 0);
    put_u32(&mut out, 0);
    out.extend_from_slice(data);
    out
}

pub fn write_response(count: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(17);
    put_u16(&mut out, 17);
    put_u16(&mut out, 0);
    put_u32(&mut out, count);
    put_u32(&mut out, 0);
    put_u16(&mut out, 0);
    put_u16(&mut out, 0);
    out
}

pub fn close_response(meta: Option<&FileMeta>) -> Vec<u8> {
    let mut out = Vec::with_capacity(60);
    put_u16(&mut out, 60);
    let flags = if meta.is_some() {
        CloseRequest::POSTQUERY_ATTRIB
    } else {
        0
    };
    put_u16(&mut out, flags);
    put_u32(&mut out, 0);
    match meta {
        Some(m) => {
            put_filetimes(&mut out, m);
            put_u64(&mut out, m.alloc_size);
            put_u64(&mut out, m.eof);
            put_u32(&mut out, m.attributes);
        }
        None => out.extend_from_slice(&[0u8; 52]),
    }
    out
}

pub fn flush_response() -> Vec<u8> {
    let mut out = Vec::with_capacity(4);
    put_u16(&mut out, 4);
    put_u16(&mut out, 0);
    out
}

pub fn set_info_response() -> Vec<u8> {
    let mut out = Vec::with_capacity(2);
    put_u16(&mut out, 2);
    out
}

pub fn query_response(info: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + info.len());
    put_u16(&mut out, 9);
    put_u16(&mut out, (super::wire::HEADER_LEN + 8) as u16);
    put_u32(&mut out, info.len() as u32);
    out.extend_from_slice(info);
    out
}

pub fn basic_info(m: &FileMeta) -> Vec<u8> {
    let mut out = Vec::with_capacity(40);
    put_filetimes(&mut out, m);
    put_u32(&mut out, m.attributes);
    put_u32(&mut out, 0);
    out
}

pub fn standard_info(m: &FileMeta) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    put_u64(&mut out, m.alloc_size);
    put_u64(&mut out, m.eof);
    put_u32(&mut out, m.nlink);
    out.push(0);
    out.push(u8::from(m.is_dir));
    put_u16(&mut out, 0);
    out
}

pub fn network_open_info(m: &FileMeta) -> Vec<u8> {
    let mut out = Vec::with_capacity(56);
    put_filetimes(&mut out, m);
    put_u64(&mut out, m.alloc_size);
    put_u64(&mut out, m.eof);
    put_u32(&mut out, m.attributes);
    put_u32(&mut out, 0);
    out
}

pub fn internal_info(m: &FileMeta) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    put_u64(&mut out, m.inode);
    out
}

pub fn all_info(m: &FileMeta, name_utf16: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&basic_info(m));
    out.extend_from_slice(&standard_info(m));
    put_u64(&mut out, m.inode);
    put_u32(&mut out, 0);
    put_u32(&mut out, 0x001F_01FF);
    put_u64(&mut out, 0);
    put_u32(&mut out, 0);
    put_u32(&mut out, 0);
    put_u32(&mut out, name_utf16.len() as u32);
    out.extend_from_slice(name_utf16);
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirInfo {
    Directory,
    Full,
    Both,
    Names,
    IdBoth,
    IdFull,
}

impl DirInfo {
    pub fn from_class(class: u8) -> Option<DirInfo> {
        Some(match class {
            file_class::DIRECTORY => DirInfo::Directory,
            file_class::FULL_DIRECTORY => DirInfo::Full,
            file_class::BOTH_DIRECTORY => DirInfo::Both,
            file_class::NAMES => DirInfo::Names,
            file_class::ID_BOTH_DIRECTORY => DirInfo::IdBoth,
            file_class::ID_FULL_DIRECTORY => DirInfo::IdFull,
            _ => return None,
        })
    }
}

pub fn dir_entry(m: &FileMeta, name_utf16: &[u8], info: DirInfo) -> Vec<u8> {
    let mut out = Vec::new();
    put_u32(&mut out, 0);
    put_u32(&mut out, 0);

    if info == DirInfo::Names {
        put_u32(&mut out, name_utf16.len() as u32);
        out.extend_from_slice(name_utf16);
        return out;
    }

    put_filetimes(&mut out, m);
    put_u64(&mut out, m.eof);
    put_u64(&mut out, m.alloc_size);
    put_u32(&mut out, m.attributes);
    put_u32(&mut out, name_utf16.len() as u32);

    if info != DirInfo::Directory {
        put_u32(&mut out, 0);
    }
    match info {
        DirInfo::Directory | DirInfo::Full | DirInfo::Names => {}
        DirInfo::Both | DirInfo::IdBoth => {
            out.push(0);
            out.push(0);
            out.extend_from_slice(&[0u8; 24]);
            if info == DirInfo::IdBoth {
                put_u16(&mut out, 0);
                put_u64(&mut out, m.inode);
            }
        }
        DirInfo::IdFull => {
            put_u32(&mut out, 0);
            put_u64(&mut out, m.inode);
        }
    }
    out.extend_from_slice(name_utf16);
    out
}

pub fn name_info(name_utf16: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + name_utf16.len());
    put_u32(&mut out, name_utf16.len() as u32);
    out.extend_from_slice(name_utf16);
    out
}

pub fn ea_info() -> Vec<u8> {
    let mut out = Vec::with_capacity(4);
    put_u32(&mut out, 0);
    out
}

pub fn stream_info(m: &FileMeta) -> Vec<u8> {
    if m.is_dir {
        return Vec::new();
    }
    let name = super::wire::to_utf16le("::$DATA");
    let mut out = Vec::with_capacity(24 + name.len());
    put_u32(&mut out, 0);
    put_u32(&mut out, name.len() as u32);
    put_u64(&mut out, m.eof);
    put_u64(&mut out, m.alloc_size);
    out.extend_from_slice(&name);
    out
}

pub fn link_dir_entries(entries: Vec<Vec<u8>>) -> Vec<u8> {
    let count = entries.len();
    let mut out = Vec::new();
    for (index, mut entry) in entries.into_iter().enumerate() {
        let last = index + 1 == count;
        let padded = if last {
            entry.len()
        } else {
            entry.len().div_ceil(8) * 8
        };
        if !last {
            entry.resize(padded, 0);
            entry[0..4].copy_from_slice(&(padded as u32).to_le_bytes());
        }
        out.extend_from_slice(&entry);
    }
    out
}

pub fn fs_size_info(total_units: u64, free_units: u64, bytes_per_sector: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    put_u64(&mut out, total_units);
    put_u64(&mut out, free_units);
    put_u32(&mut out, 1);
    put_u32(&mut out, bytes_per_sector);
    out
}

pub fn fs_full_size_info(total_units: u64, free_units: u64, bytes_per_sector: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    put_u64(&mut out, total_units);
    put_u64(&mut out, free_units);
    put_u64(&mut out, free_units);
    put_u32(&mut out, 1);
    put_u32(&mut out, bytes_per_sector);
    out
}

pub fn fs_device_info() -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    put_u32(&mut out, 0x0000_0007);
    put_u32(&mut out, 0x0000_0020);
    out
}

pub fn fs_attribute_info() -> Vec<u8> {
    let name = super::wire::to_utf16le("ScaleFS");
    let mut out = Vec::new();
    put_u32(&mut out, 0x0000_0002 | 0x0000_0004);
    put_u32(&mut out, super::wire::HEADER_LEN as u32);
    put_u32(&mut out, name.len() as u32);
    out.extend_from_slice(&name);
    out
}

pub fn fs_volume_info(serial: u32, label: &str) -> Vec<u8> {
    let label16 = super::wire::to_utf16le(label);
    let mut out = Vec::new();
    put_u64(&mut out, 0);
    put_u32(&mut out, serial);
    put_u32(&mut out, label16.len() as u32);
    out.push(0);
    out.push(0);
    out.extend_from_slice(&label16);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_u8(out: &mut Vec<u8>, value: u8) {
        out.push(value);
    }

    fn meta() -> FileMeta {
        FileMeta {
            inode: 42,
            creation: 0x01D9_0000_0000_0000,
            access: 0x01D9_0000_0000_0001,
            write: 0x01D9_0000_0000_0002,
            change: 0x01D9_0000_0000_0003,
            alloc_size: 8192,
            eof: 5000,
            attributes: attr::ARCHIVE,
            nlink: 1,
            is_dir: false,
        }
    }

    #[test]
    fn filetime_round_trips() {
        let ns = 1_700_000_000_000_000_000i64;
        assert_eq!(from_filetime(to_filetime(ns)), Some(ns));
        assert_eq!(from_filetime(0), None);
        assert!(to_filetime(-1_000_000_000_000_000_000) > 0);
    }

    #[test]
    fn create_request_decodes() {
        let name = super::super::wire::to_utf16le("docs\\notes.txt");
        let mut body = Vec::new();
        put_u16(&mut body, 57);
        put_u8(&mut body, 0);
        put_u8(&mut body, 0);
        put_u32(&mut body, 2);
        put_u64(&mut body, 0);
        put_u64(&mut body, 0);
        put_u32(&mut body, 0x0012_0089);
        put_u32(&mut body, 0);
        put_u32(&mut body, 0x07);
        put_u32(&mut body, disposition::OPEN_IF);
        put_u32(&mut body, options::NON_DIRECTORY_FILE);
        let name_offset = super::super::wire::HEADER_LEN + 56;
        put_u16(&mut body, name_offset as u16);
        put_u16(&mut body, name.len() as u16);
        put_u32(&mut body, 0);
        put_u32(&mut body, 0);
        body.extend_from_slice(&name);

        let request = CreateRequest::decode(&body).unwrap();
        assert_eq!(request.create_disposition, disposition::OPEN_IF);
        assert_eq!(request.create_options, options::NON_DIRECTORY_FILE);
        assert_eq!(
            super::super::wire::from_utf16le(&request.name),
            "docs\\notes.txt"
        );
    }

    #[test]
    fn write_request_carries_its_data() {
        let payload = b"hello world";
        let mut body = Vec::new();
        put_u16(&mut body, 49);
        let data_offset = super::super::wire::HEADER_LEN + 48;
        put_u16(&mut body, data_offset as u16);
        put_u32(&mut body, payload.len() as u32);
        put_u64(&mut body, 4096);
        body.extend_from_slice(&[0x11; 16]);
        put_u32(&mut body, 0);
        put_u32(&mut body, 0);
        put_u16(&mut body, 0);
        put_u16(&mut body, 0);
        put_u32(&mut body, 0);
        body.extend_from_slice(payload);

        let request = WriteRequest::decode(&body).unwrap();
        assert_eq!(request.offset, 4096);
        assert_eq!(request.file_id, [0x11; 16]);
        assert_eq!(request.data, payload);
    }

    #[test]
    fn read_and_close_responses_pin_layout() {
        let read = read_response(b"abcd");
        assert_eq!(u16::from_le_bytes([read[0], read[1]]), 17);
        assert_eq!(read[2], (super::super::wire::HEADER_LEN + 16) as u8);
        assert_eq!(u32::from_le_bytes([read[4], read[5], read[6], read[7]]), 4);
        assert_eq!(&read[16..], b"abcd");

        let m = meta();
        let close = close_response(Some(&m));
        assert_eq!(u16::from_le_bytes([close[0], close[1]]), 60);
        assert_eq!(close.len(), 60);
        let eof = u64::from_le_bytes(close[48..56].try_into().unwrap());
        assert_eq!(eof, 5000);
        assert_eq!(close_response(None).len(), 60);
    }

    #[test]
    fn directory_entries_link_and_align() {
        let m = meta();
        let a = dir_entry(&m, &super::super::wire::to_utf16le("a"), DirInfo::IdBoth);
        let b = dir_entry(&m, &super::super::wire::to_utf16le("bb"), DirInfo::IdBoth);
        let linked = link_dir_entries(vec![a.clone(), b]);
        let first_next = u32::from_le_bytes(linked[0..4].try_into().unwrap()) as usize;
        assert_eq!(first_next % 8, 0);
        assert_eq!(first_next, a.len().div_ceil(8) * 8);
        let last_next = u32::from_le_bytes(linked[first_next..first_next + 4].try_into().unwrap());
        assert_eq!(last_next, 0);
    }

    #[test]
    fn rename_info_decodes() {
        let name = super::super::wire::to_utf16le("renamed.txt");
        let mut input = Vec::new();
        put_u8(&mut input, 1);
        input.extend_from_slice(&[0u8; 7]);
        put_u64(&mut input, 0);
        put_u32(&mut input, name.len() as u32);
        input.extend_from_slice(&name);
        let info = RenameInfo::decode(&input).unwrap();
        assert!(info.replace);
        assert_eq!(super::super::wire::from_utf16le(&info.name), "renamed.txt");
    }

    #[test]
    fn all_info_starts_with_basic_and_standard() {
        let m = meta();
        let name = super::super::wire::to_utf16le("f.txt");
        let all = all_info(&m, &name);
        assert_eq!(
            u64::from_le_bytes(all[0..8].try_into().unwrap()),
            m.creation
        );
        assert_eq!(
            u64::from_le_bytes(all[40..48].try_into().unwrap()),
            m.alloc_size
        );
    }
}
