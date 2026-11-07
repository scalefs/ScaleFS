use super::fileops::{
    self, CloseRequest, CreateRequest, FileId, FileMeta, QueryDirectoryRequest, QueryInfoRequest,
    ReadRequest, RenameInfo, SetInfoRequest, WriteRequest, action, attr, disposition, file_class,
    fs_class, info_type, options, to_filetime,
};
use super::ntlm::{self, Credential};
use super::session::{Handler, Response};
use super::spnego;
use super::wire::{self, Header, command, status};
use crate::mountcore::{MountCore, MountError, SetAttr, TimeChange};
use scalefs_core::wire::{Cursor, put_u16, put_u32};
use scalefs_core::{DirEntry, MAX_NAME_LEN, MODE_FILE, MODE_TYPE_MASK, ROOT_INODE, SharedDevice};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const STORED_ATTR_MASK: u32 = attr::READONLY | 0x0000_0002 | 0x0000_0004 | attr::ARCHIVE;

#[derive(Debug, Clone)]
pub struct ShareConfig {
    pub name: String,
    pub credential: Credential,
    pub server_guid: [u8; 16],
    pub target: String,
    pub read_only: bool,
    pub throttle: std::sync::Arc<ntlm::AuthThrottle>,
}

pub struct ConnectionNonces {
    pub salt: [u8; 32],
    pub challenge: [u8; 8],
    pub system_time: u64,
}

struct OpenFile {
    inode: u64,
    is_dir: bool,
    delete_on_close: AtomicBool,
    wrote: AtomicBool,
    naming: Mutex<Naming>,
    enumeration: Mutex<Option<(Vec<DirEntry>, usize)>>,
}

struct Naming {
    parent: u64,
    name: String,
    path: String,
}

pub struct SmbShare<D: SharedDevice> {
    config: ShareConfig,
    nonces: ConnectionNonces,
    core: Arc<MountCore<D>>,
    ntlm: Mutex<Option<ntlm::Server>>,
    session_id: u64,
    next_tree_id: AtomicU32,
    files: Mutex<BTreeMap<FileId, Arc<OpenFile>>>,
    next_file: AtomicU64,
    last_create: Mutex<Option<FileId>>,
    trees: Mutex<BTreeMap<u32, u8>>,
    setup_attempts: AtomicU32,
    connection_throttle: ntlm::AuthThrottle,
}

const SESSION_ID: u64 = 0x4653_0000_0000_0001;

const RELATED_FILE_ID: FileId = [0xFF; 16];

impl<D: SharedDevice> SmbShare<D> {
    fn read_only(&self) -> bool {
        self.config.read_only || self.core.is_read_only()
    }

    pub fn new(config: ShareConfig, nonces: ConnectionNonces, core: Arc<MountCore<D>>) -> Self {
        SmbShare {
            config,
            nonces,
            core,
            ntlm: Mutex::new(None),
            session_id: SESSION_ID,
            next_tree_id: AtomicU32::new(1),
            files: Mutex::new(BTreeMap::new()),
            next_file: AtomicU64::new(0),
            last_create: Mutex::new(None),
            trees: Mutex::new(BTreeMap::new()),
            setup_attempts: AtomicU32::new(0),
            connection_throttle: ntlm::AuthThrottle::default(),
        }
    }

    fn files(&self) -> std::sync::MutexGuard<'_, BTreeMap<FileId, Arc<OpenFile>>> {
        self.files.lock().expect("smb handle table")
    }

    fn file(&self, id: FileId) -> Option<Arc<OpenFile>> {
        self.files().get(&id).cloned()
    }

    fn negotiate(&self) -> Response {
        let security_buffer = spnego::negotiate_security_buffer();
        let mut body = Vec::new();
        wire::NegotiateResponse {
            server_guid: self.config.server_guid,
            server_salt: &self.nonces.salt,
            security_buffer: &security_buffer,
            system_time: self.nonces.system_time,
        }
        .encode(&mut body);
        Response::ok(body)
    }

    fn session_setup(&self, body: &[u8]) -> Response {
        if !self.connection_throttle.gate() || !self.config.throttle.gate() {
            return Response::error(status::LOGON_FAILURE);
        }
        let Some(token) = security_buffer_of(body) else {
            return Response::error(status::INVALID_PARAMETER);
        };
        let Some(ntlmssp) = spnego::extract_ntlmssp(token) else {
            return Response::error(status::INVALID_PARAMETER);
        };
        let exchange = self.ntlm.lock().expect("ntlm exchange").take();
        match exchange {
            None => {
                let challenge = if self.setup_attempts.fetch_add(1, Ordering::Relaxed) == 0 {
                    self.nonces.challenge
                } else {
                    let mut fresh = [0u8; 8];
                    if aws_lc_rs::rand::fill(&mut fresh).is_err() {
                        return Response::error(status::LOGON_FAILURE);
                    }
                    fresh
                };
                let server = ntlm::Server::new(challenge, &self.config.target);
                let challenge = server.challenge_message();
                let wrapped = spnego::challenge_security_buffer(&challenge);
                *self.ntlm.lock().expect("ntlm exchange") = Some(server);
                let mut response = session_setup_body(&wrapped);
                response.status = status::MORE_PROCESSING_REQUIRED;
                response.session_id = Some(self.session_id);
                response
            }
            Some(server) => match server.verify(&ntlmssp, &self.config.credential) {
                Ok(authenticated) => {
                    self.connection_throttle.record_success();
                    self.config.throttle.record_success();
                    let token = spnego::accept_complete_buffer();
                    let mut response = session_setup_body(&token);
                    response.session_id = Some(self.session_id);
                    response.session_key = Some(authenticated.session_key);
                    response
                }
                Err(_) => {
                    self.connection_throttle.record_failure();
                    self.config.throttle.record_failure();
                    Response::error(status::LOGON_FAILURE)
                }
            },
        }
    }

    fn tree_connect(&self, body: &[u8]) -> Response {
        let Some(path_bytes) = path_of(body) else {
            return Response::error(status::INVALID_PARAMETER);
        };
        let path = wire::from_utf16le(path_bytes);
        let requested = path.rsplit(['\\', '/']).next().unwrap_or("");
        let share_type = if requested.eq_ignore_ascii_case("IPC$") {
            SHARE_TYPE_PIPE
        } else if requested.eq_ignore_ascii_case(&self.config.name) {
            SHARE_TYPE_DISK
        } else {
            return Response::error(status::BAD_NETWORK_NAME);
        };
        let tree_id = self.next_tree_id.fetch_add(1, Ordering::Relaxed);
        self.trees
            .lock()
            .expect("tree table")
            .insert(tree_id, share_type);
        let mut response = Response::ok(tree_connect_body(share_type));
        response.tree_id = Some(tree_id);
        response
    }

    fn tree_disconnect(&self, tree_id: u32) -> Response {
        match self.trees.lock().expect("tree table").remove(&tree_id) {
            Some(_) => Response::ok(small_body(4)),
            None => Response::error(status::NETWORK_NAME_DELETED),
        }
    }

    fn logoff(&self) -> Response {
        self.release_all();
        self.trees.lock().expect("tree table").clear();
        Response::ok(small_body(4))
    }

    fn tree_connected(&self, tree_id: u32) -> bool {
        self.trees
            .lock()
            .expect("tree table")
            .contains_key(&tree_id)
    }

    fn release_all(&self) {
        let read_only = self.read_only();
        let files = std::mem::take(&mut *self.files());
        for file in files.values() {
            if !read_only
                && file.delete_on_close.load(Ordering::SeqCst)
                && let Ok(naming) = file.naming.lock()
                && !naming.name.is_empty()
            {
                let _ =
                    self.core
                        .unlink_handle(naming.parent, &naming.name, file.inode, file.is_dir);
            }
            self.core.release(file.inode);
        }
    }

    fn allocate_file_id(&self) -> FileId {
        let n = (self.next_file.fetch_add(1, Ordering::Relaxed) + 1).to_le_bytes();
        let mut id = [0u8; 16];
        id[0..8].copy_from_slice(&n);
        id[8..16].copy_from_slice(&n);
        id
    }

    fn resolve(&self, id: FileId) -> Option<FileId> {
        if id == RELATED_FILE_ID {
            *self.last_create.lock().expect("last create")
        } else {
            Some(id)
        }
    }

    fn meta_of(&self, inode: u64) -> Option<FileMeta> {
        let a = self.core.getattr(inode).ok()?;
        let is_dir = a.attrs.is_dir();
        let attributes = if is_dir {
            attr::DIRECTORY
        } else {
            let bits = a.attrs.attrs & STORED_ATTR_MASK;
            if bits == 0 { attr::NORMAL } else { bits }
        };
        Some(FileMeta {
            inode,
            creation: to_filetime(a.attrs.crtime_ns),
            access: to_filetime(a.attrs.atime_ns),
            write: to_filetime(a.attrs.mtime_ns),
            change: to_filetime(a.attrs.ctime_ns),
            alloc_size: a.attrs.size.div_ceil(4096).saturating_mul(4096),
            eof: a.attrs.size,
            attributes,
            nlink: a.attrs.nlink,
            is_dir,
        })
    }

    fn create(&self, body: &[u8]) -> Response {
        *self.last_create.lock().expect("last create") = None;
        let Ok(req) = CreateRequest::decode(body) else {
            return Response::error(status::INVALID_PARAMETER);
        };
        let path = wire::from_utf16le(&req.name);
        if path.contains(':') {
            return Response::error(status::OBJECT_NAME_INVALID);
        }
        let trimmed = path.trim_matches(['\\', '/']);
        let (dir, name) = match trimmed.rsplit_once(['\\', '/']) {
            Some((d, n)) => (d, n.to_string()),
            None => ("", trimmed.to_string()),
        };
        if name.len() > MAX_NAME_LEN {
            return Response::error(status::NAME_TOO_LONG);
        }
        let parent = match self.core.walk(dir) {
            Ok(inode) => inode,
            Err(e) => return Response::error(nt_status(e)),
        };

        let want_dir = req.create_options & options::DIRECTORY_FILE != 0;
        let want_file = req.create_options & options::NON_DIRECTORY_FILE != 0;
        let disp = req.create_disposition;

        if self.read_only() && req.create_options & options::DELETE_ON_CLOSE != 0 {
            return Response::error(status::ACCESS_DENIED);
        }

        let existing = if name.is_empty() {
            self.core.getattr(ROOT_INODE).ok()
        } else {
            self.core.lookup(parent, &name).ok()
        };

        let (inode, is_dir, create_action) = match existing {
            Some(attrs) => {
                let is_dir = attrs.attrs.is_dir();
                if !is_dir && attrs.attrs.mode & MODE_TYPE_MASK != MODE_FILE {
                    return Response::error(status::ACCESS_DENIED);
                }
                if disp == disposition::CREATE {
                    return Response::error(status::OBJECT_NAME_COLLISION);
                }
                if is_dir && want_file {
                    return Response::error(status::FILE_IS_A_DIRECTORY);
                }
                if !is_dir && want_dir {
                    return Response::error(status::NOT_A_DIRECTORY);
                }
                if !is_dir
                    && matches!(
                        disp,
                        disposition::OVERWRITE | disposition::OVERWRITE_IF | disposition::SUPERSEDE
                    )
                {
                    if self.read_only() {
                        return Response::error(status::ACCESS_DENIED);
                    }
                    if let Err(e) = self.core.setattr(
                        attrs.inode,
                        SetAttr {
                            size: Some(0),
                            ..Default::default()
                        },
                    ) {
                        return Response::error(nt_status(e));
                    }
                }
                let create_action = match disp {
                    disposition::OVERWRITE | disposition::OVERWRITE_IF => action::OVERWRITTEN,
                    disposition::SUPERSEDE => action::SUPERSEDED,
                    _ => action::OPENED,
                };
                (attrs.inode, is_dir, create_action)
            }
            None => {
                if matches!(disp, disposition::OPEN | disposition::OVERWRITE) || name.is_empty() {
                    return Response::error(status::OBJECT_NAME_NOT_FOUND);
                }
                if self.read_only() {
                    return Response::error(status::ACCESS_DENIED);
                }
                let created = if want_dir {
                    self.core.mkdir(parent, &name, 0o755, 0, 0)
                } else {
                    self.core.create(parent, &name, 0o644, 0, 0)
                };
                match created {
                    Ok(m) => (m.inode, want_dir, action::CREATED),
                    Err(e) => return Response::error(nt_status(e)),
                }
            }
        };

        let file_id = self.allocate_file_id();
        self.core.retain(inode);
        self.files().insert(
            file_id,
            Arc::new(OpenFile {
                inode,
                is_dir,
                delete_on_close: AtomicBool::new(
                    req.create_options & options::DELETE_ON_CLOSE != 0,
                ),
                wrote: AtomicBool::new(false),
                naming: Mutex::new(Naming {
                    parent,
                    name,
                    path: trimmed.to_string(),
                }),
                enumeration: Mutex::new(None),
            }),
        );
        *self.last_create.lock().expect("last create") = Some(file_id);

        let Some(meta) = self.meta_of(inode) else {
            return Response::error(status::INTERNAL_ERROR);
        };
        Response::ok(fileops::create_response(file_id, create_action, &meta))
    }

    fn close(&self, body: &[u8]) -> Response {
        let Ok(req) = CloseRequest::decode(body) else {
            return Response::error(status::INVALID_PARAMETER);
        };
        let Some(fid) = self.resolve(req.file_id) else {
            return Response::error(status::FILE_CLOSED);
        };
        let Some(file) = self.files().remove(&fid) else {
            return Response::error(status::FILE_CLOSED);
        };
        let meta = if req.flags & CloseRequest::POSTQUERY_ATTRIB != 0 {
            self.meta_of(file.inode)
        } else {
            None
        };
        let flush = if file.wrote.load(Ordering::SeqCst) {
            self.core.commit_if_dirty()
        } else {
            Ok(())
        };
        if !self.read_only() && file.delete_on_close.load(Ordering::SeqCst) {
            let naming = file.naming.lock().expect("handle naming");
            if !naming.name.is_empty() {
                let _ =
                    self.core
                        .unlink_handle(naming.parent, &naming.name, file.inode, file.is_dir);
            }
        }
        self.core.release(file.inode);
        match flush {
            Ok(()) => Response::ok(fileops::close_response(meta.as_ref())),
            Err(error) => Response::error(nt_status(error)),
        }
    }

    fn read(&self, body: &[u8]) -> Response {
        let Ok(req) = ReadRequest::decode(body) else {
            return Response::error(status::INVALID_PARAMETER);
        };
        if req.length > super::wire::MAX_READ_SIZE {
            return Response::error(status::INVALID_PARAMETER);
        }
        let Some(inode) = self
            .resolve(req.file_id)
            .and_then(|f| self.file(f))
            .map(|f| f.inode)
        else {
            return Response::error(status::FILE_CLOSED);
        };
        match self.core.read(inode, req.offset, req.length as usize) {
            Ok(data) => {
                if data.is_empty() && req.length > 0 {
                    Response::error(status::END_OF_FILE)
                } else {
                    Response::ok(fileops::read_response(&data))
                }
            }
            Err(e) => Response::error(nt_status(e)),
        }
    }

    fn write(&self, body: &[u8]) -> Response {
        if self.read_only() {
            return Response::error(status::ACCESS_DENIED);
        }
        let Ok(req) = WriteRequest::decode(body) else {
            return Response::error(status::INVALID_PARAMETER);
        };
        let Some(file) = self.resolve(req.file_id).and_then(|f| self.file(f)) else {
            return Response::error(status::FILE_CLOSED);
        };
        match self.core.write(file.inode, req.offset, &req.data) {
            Ok(count) => {
                file.wrote.store(true, Ordering::SeqCst);
                Response::ok(fileops::write_response(count))
            }
            Err(e) => Response::error(nt_status(e)),
        }
    }

    fn flush(&self) -> Response {
        match self.core.commit() {
            Ok(()) => Response::ok(fileops::flush_response()),
            Err(e) => Response::error(nt_status(e)),
        }
    }

    fn query_directory(&self, body: &[u8]) -> Response {
        let Ok(req) = QueryDirectoryRequest::decode(body) else {
            return Response::error(status::INVALID_PARAMETER);
        };
        let Some(dir_info) = fileops::DirInfo::from_class(req.info_class) else {
            return Response::error(status::INVALID_PARAMETER);
        };
        let Some(file) = self.resolve(req.file_id).and_then(|f| self.file(f)) else {
            return Response::error(status::FILE_CLOSED);
        };
        if !file.is_dir {
            return Response::error(status::INVALID_PARAMETER);
        }
        let (dir_inode, parent_inode) = {
            let naming = file.naming.lock().expect("handle naming");
            (file.inode, naming.parent)
        };

        let mut enumeration = file.enumeration.lock().expect("enumeration cursor");
        let restart = req.flags & QueryDirectoryRequest::RESTART_SCANS != 0;
        if restart || enumeration.is_none() {
            let entries = match self.core.readdir(dir_inode) {
                Ok(entries) => entries,
                Err(e) => return Response::error(nt_status(e)),
            };
            *enumeration = Some((entries, 0));
        }

        let (entries, pos) = {
            let (entries, pos) = enumeration.as_ref().unwrap();
            (entries.clone(), *pos)
        };
        let pattern = wire::from_utf16le(&req.pattern);
        let matches =
            |name: &str| pattern.is_empty() || pattern == "*" || glob_matches(&pattern, name);
        let mut all: Vec<(String, u64)> = vec![
            (".".to_string(), dir_inode),
            ("..".to_string(), parent_inode),
        ];
        all.extend(entries.iter().map(|e| (e.name.clone(), e.inode)));
        let filtered: Vec<(String, u64)> = all.into_iter().filter(|(n, _)| matches(n)).collect();

        let empty_scan_status = if pos == 0 {
            status::NO_SUCH_FILE
        } else {
            status::NO_MORE_FILES
        };
        if pos >= filtered.len() {
            return Response::error(empty_scan_status);
        }
        let single = req.flags & QueryDirectoryRequest::RETURN_SINGLE_ENTRY != 0;
        let budget = req.output_len as usize;
        let mut pieces = Vec::new();
        let mut used = 0usize;
        let mut index = pos;
        while index < filtered.len() {
            let (name, inode) = &filtered[index];
            let Some(meta) = self.meta_of(*inode) else {
                index += 1;
                continue;
            };
            let name16 = wire::to_utf16le(name);
            let entry = fileops::dir_entry(&meta, &name16, dir_info);
            let padded = entry.len().div_ceil(8) * 8;
            if used + padded > budget && !pieces.is_empty() {
                break;
            }
            used += padded;
            pieces.push(entry);
            index += 1;
            if single {
                break;
            }
        }
        if pieces.is_empty() {
            return Response::error(empty_scan_status);
        }
        enumeration.as_mut().unwrap().1 = index;
        Response::ok(fileops::query_response(&fileops::link_dir_entries(pieces)))
    }

    fn query_info(&self, body: &[u8]) -> Response {
        let Ok(req) = QueryInfoRequest::decode(body) else {
            return Response::error(status::INVALID_PARAMETER);
        };
        match req.info_type {
            info_type::FILE => {
                let Some(file) = self.resolve(req.file_id).and_then(|f| self.file(f)) else {
                    return Response::error(status::FILE_CLOSED);
                };
                let (inode, path) = {
                    let naming = file.naming.lock().expect("handle naming");
                    (file.inode, naming.path.clone())
                };
                let Some(meta) = self.meta_of(inode) else {
                    return Response::error(status::OBJECT_NAME_NOT_FOUND);
                };
                let info = match req.info_class {
                    file_class::BASIC => fileops::basic_info(&meta),
                    file_class::STANDARD => fileops::standard_info(&meta),
                    file_class::NETWORK_OPEN => fileops::network_open_info(&meta),
                    file_class::INTERNAL => fileops::internal_info(&meta),
                    file_class::ALL => {
                        let name16 = wire::to_utf16le(&format!("\\{path}"));
                        fileops::all_info(&meta, &name16)
                    }
                    file_class::NAME | file_class::NORMALIZED_NAME => {
                        let name16 = wire::to_utf16le(&format!("\\{path}"));
                        fileops::name_info(&name16)
                    }
                    file_class::EA => fileops::ea_info(),
                    file_class::STREAM => fileops::stream_info(&meta),
                    _ => return Response::error(status::INVALID_PARAMETER),
                };
                Response::ok(fileops::query_response(&info))
            }
            info_type::FILESYSTEM => {
                let stat = match self.core.statfs() {
                    Ok(s) => s,
                    Err(e) => return Response::error(nt_status(e)),
                };
                let info = match req.info_class {
                    fs_class::SIZE => fileops::fs_size_info(stat.blocks, stat.bfree, stat.bsize),
                    fs_class::FULL_SIZE => {
                        fileops::fs_full_size_info(stat.blocks, stat.bfree, stat.bsize)
                    }
                    fs_class::DEVICE => fileops::fs_device_info(),
                    fs_class::ATTRIBUTE => fileops::fs_attribute_info(),
                    fs_class::VOLUME => fileops::fs_volume_info(0x5CA1_E5F5, &self.config.name),
                    _ => return Response::error(status::INVALID_PARAMETER),
                };
                Response::ok(fileops::query_response(&info))
            }
            _ => Response::error(status::NOT_SUPPORTED),
        }
    }

    fn set_info(&self, body: &[u8]) -> Response {
        if self.read_only() {
            return Response::error(status::ACCESS_DENIED);
        }
        let Ok(req) = SetInfoRequest::decode(body) else {
            return Response::error(status::INVALID_PARAMETER);
        };
        if req.info_type != info_type::FILE {
            return Response::error(status::NOT_SUPPORTED);
        }
        let Some(file) = self.resolve(req.file_id).and_then(|f| self.file(f)) else {
            return Response::error(status::FILE_CLOSED);
        };
        let inode = file.inode;
        match req.info_class {
            file_class::BASIC => {
                let mut c = Cursor::new(&req.input);
                let (Ok(creation), Ok(access), Ok(write), Ok(change), Ok(attributes)) = (
                    c.take_u64(),
                    c.take_u64(),
                    c.take_u64(),
                    c.take_u64(),
                    c.take_u32(),
                ) else {
                    return Response::error(status::INVALID_PARAMETER);
                };
                let change_set = SetAttr {
                    crtime: fileops::from_filetime(creation),
                    atime: fileops::from_filetime(access).map(TimeChange::Set),
                    mtime: fileops::from_filetime(write).map(TimeChange::Set),
                    ctime: fileops::from_filetime(change),
                    attributes: (attributes != 0).then_some(attributes & STORED_ATTR_MASK),
                    ..Default::default()
                };
                match self.core.setattr(inode, change_set) {
                    Ok(_) => Response::ok(fileops::set_info_response()),
                    Err(e) => Response::error(nt_status(e)),
                }
            }
            file_class::END_OF_FILE => {
                let mut c = Cursor::new(&req.input);
                let Ok(eof) = c.take_u64() else {
                    return Response::error(status::INVALID_PARAMETER);
                };
                match self.core.setattr(
                    inode,
                    SetAttr {
                        size: Some(eof),
                        ..Default::default()
                    },
                ) {
                    Ok(_) => Response::ok(fileops::set_info_response()),
                    Err(e) => Response::error(nt_status(e)),
                }
            }
            file_class::ALLOCATION => Response::ok(fileops::set_info_response()),
            file_class::DISPOSITION => {
                let delete = req.input.first().copied().unwrap_or(0) != 0;
                file.delete_on_close.store(delete, Ordering::SeqCst);
                Response::ok(fileops::set_info_response())
            }
            file_class::RENAME => {
                let Ok(info) = RenameInfo::decode(&req.input) else {
                    return Response::error(status::INVALID_PARAMETER);
                };
                let new_path = wire::from_utf16le(&info.name);
                let trimmed = new_path.trim_matches(['\\', '/']);
                let (dir, new_name) = match trimmed.rsplit_once(['\\', '/']) {
                    Some((d, n)) => (d, n.to_string()),
                    None => ("", trimmed.to_string()),
                };
                let new_parent = match self.core.walk(dir) {
                    Ok(inode) => inode,
                    Err(e) => return Response::error(nt_status(e)),
                };
                let (old_parent, old_name) = {
                    let naming = file.naming.lock().expect("handle naming");
                    (naming.parent, naming.name.clone())
                };
                match self
                    .core
                    .rename(old_parent, &old_name, new_parent, &new_name, info.replace)
                {
                    Ok(()) => {
                        let mut naming = file.naming.lock().expect("handle naming");
                        naming.parent = new_parent;
                        naming.name = new_name;
                        naming.path = trimmed.to_string();
                        Response::ok(fileops::set_info_response())
                    }
                    Err(e) => Response::error(nt_status(e)),
                }
            }
            file_class::LINK => {
                let Ok(info) = RenameInfo::decode(&req.input) else {
                    return Response::error(status::INVALID_PARAMETER);
                };
                let new_path = wire::from_utf16le(&info.name);
                let trimmed = new_path.trim_matches(['\\', '/']);
                let (dir, new_name) = match trimmed.rsplit_once(['\\', '/']) {
                    Some((d, n)) => (d, n.to_string()),
                    None => ("", trimmed.to_string()),
                };
                let new_parent = match self.core.walk(dir) {
                    Ok(inode) => inode,
                    Err(e) => return Response::error(nt_status(e)),
                };
                if info.replace {
                    match self.core.unlink(new_parent, &new_name) {
                        Ok(()) | Err(MountError::NotFound) => {}
                        Err(e) => return Response::error(nt_status(e)),
                    }
                }
                match self.core.link(inode, new_parent, &new_name) {
                    Ok(_) => Response::ok(fileops::set_info_response()),
                    Err(e) => Response::error(nt_status(e)),
                }
            }
            _ => Response::error(status::NOT_SUPPORTED),
        }
    }
}

impl<D: SharedDevice> Handler for SmbShare<D> {
    fn negotiate_smb2_wildcard(&self) -> Response {
        let security_buffer = spnego::negotiate_security_buffer();
        let body = wire::wildcard_negotiate_body(
            self.config.server_guid,
            self.nonces.system_time,
            &security_buffer,
        );
        Response::ok(body)
    }

    fn dispatch(&self, header: &Header, body: &[u8]) -> Response {
        let _perf = scalefs_core::perftrace::op(
            scalefs_core::perftrace::Surface::Smb,
            u32::from(header.command),
        );
        match header.command {
            command::NEGOTIATE => self.negotiate(),
            command::SESSION_SETUP => self.session_setup(body),
            command::TREE_CONNECT => self.tree_connect(body),
            command::TREE_DISCONNECT => self.tree_disconnect(header.tree_id),
            command::LOGOFF => self.logoff(),
            command::ECHO => Response::ok(small_body(4)),
            command::CREATE
            | command::CLOSE
            | command::READ
            | command::WRITE
            | command::FLUSH
            | command::QUERY_DIRECTORY
            | command::QUERY_INFO
            | command::SET_INFO
                if !self.tree_connected(header.tree_id) =>
            {
                Response::error(status::NETWORK_NAME_DELETED)
            }
            command::CREATE => self.create(body),
            command::CLOSE => self.close(body),
            command::READ => self.read(body),
            command::WRITE => self.write(body),
            command::FLUSH => self.flush(),
            command::QUERY_DIRECTORY => self.query_directory(body),
            command::QUERY_INFO => self.query_info(body),
            command::SET_INFO => self.set_info(body),
            _ => Response::error(status::NOT_SUPPORTED),
        }
    }
}

impl<D: SharedDevice> Drop for SmbShare<D> {
    fn drop(&mut self) {
        self.release_all();
    }
}

fn nt_status(error: MountError) -> u32 {
    match error {
        MountError::NotFound => status::OBJECT_NAME_NOT_FOUND,
        MountError::NotDirectory => status::NOT_A_DIRECTORY,
        MountError::IsDirectory => status::FILE_IS_A_DIRECTORY,
        MountError::Exists => status::OBJECT_NAME_COLLISION,
        MountError::NotEmpty => status::DIRECTORY_NOT_EMPTY,
        MountError::NoSpace => status::DISK_FULL,
        MountError::TooManyLinks => status::TOO_MANY_LINKS,
        MountError::NotSupported => status::NOT_SUPPORTED,
        MountError::NameTooLong => status::NAME_TOO_LONG,
        MountError::InvalidName => status::OBJECT_NAME_INVALID,
        MountError::Invalid => status::INVALID_PARAMETER,
        MountError::ReadOnly | MountError::Denied => status::ACCESS_DENIED,
        MountError::Io => status::INTERNAL_ERROR,
    }
}

fn glob_matches(pattern: &str, name: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    let mut memo = vec![None; (pattern.len() + 1) * (name.len() + 1)];
    dos_match(&pattern, &name, 0, 0, &mut memo)
}

fn null_match(pattern: &[char]) -> bool {
    pattern.iter().all(|c| matches!(c, '*' | '<' | '"' | '>'))
}

fn dos_match(p: &[char], n: &[char], pi: usize, ni: usize, memo: &mut [Option<bool>]) -> bool {
    let key = pi * (n.len() + 1) + ni;
    if let Some(known) = memo[key] {
        return known;
    }
    let rest = pi + 1;
    let result = match p.get(pi) {
        None => ni == n.len(),
        Some('*') => (ni..=n.len()).any(|k| dos_match(p, n, rest, k, memo)),
        Some('?') => ni < n.len() && dos_match(p, n, rest, ni + 1, memo),
        Some('<') => {
            let mut k = ni;
            loop {
                if dos_match(p, n, rest, k, memo) {
                    break true;
                }
                match n.get(k) {
                    None => break false,
                    Some('.') if !n[k + 1..].contains(&'.') => {
                        break dos_match(p, n, rest, k + 1, memo);
                    }
                    Some(_) => k += 1,
                }
            }
        }
        Some('>') => match n.get(ni) {
            None => null_match(&p[rest..]),
            Some('.') => {
                (ni + 1 == n.len() && null_match(&p[rest..])) || dos_match(p, n, rest, ni, memo)
            }
            Some(_) => dos_match(p, n, rest, ni + 1, memo),
        },
        Some('"') => match n.get(ni) {
            None => null_match(&p[rest..]),
            Some('.') => dos_match(p, n, rest, ni + 1, memo),
            Some(_) => false,
        },
        Some(c) => {
            n.get(ni).is_some_and(|nc| nc.eq_ignore_ascii_case(c))
                && dos_match(p, n, rest, ni + 1, memo)
        }
    };
    memo[key] = Some(result);
    result
}

fn security_buffer_of(body: &[u8]) -> Option<&[u8]> {
    let offset = read_u16(body, 12)? as usize;
    let len = read_u16(body, 14)? as usize;
    buffer_at(body, offset, len)
}

fn path_of(body: &[u8]) -> Option<&[u8]> {
    let offset = read_u16(body, 4)? as usize;
    let len = read_u16(body, 6)? as usize;
    buffer_at(body, offset, len)
}

fn buffer_at(body: &[u8], header_offset: usize, len: usize) -> Option<&[u8]> {
    let start = header_offset.checked_sub(wire::HEADER_LEN)?;
    let end = start.checked_add(len)?;
    body.get(start..end)
}

fn read_u16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*bytes.get(at)?, *bytes.get(at + 1)?]))
}

fn session_setup_body(security_buffer: &[u8]) -> Response {
    let mut body = Vec::new();
    put_u16(&mut body, 9);
    put_u16(&mut body, 0);
    let offset = wire::HEADER_LEN as u16 + 8;
    put_u16(&mut body, offset);
    put_u16(&mut body, security_buffer.len() as u16);
    body.extend_from_slice(security_buffer);
    Response::ok(body)
}

const SHARE_TYPE_DISK: u8 = 0x01;
const SHARE_TYPE_PIPE: u8 = 0x02;

fn tree_connect_body(share_type: u8) -> Vec<u8> {
    let mut body = Vec::new();
    put_u16(&mut body, 16);
    body.push(share_type);
    body.push(0);
    put_u32(&mut body, 0);
    put_u32(&mut body, 0);
    put_u32(&mut body, 0x001F_01FF);
    body
}

fn small_body(structure_size: u16) -> Vec<u8> {
    let mut body = Vec::new();
    put_u16(&mut body, structure_size);
    put_u16(&mut body, 0);
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mountcore::MountCore;
    use scalefs_core::wire::put_u64;
    use scalefs_core::{
        AllocPurpose, CaseSensitivity, CreateParams, DeviceId, Geometry, MemoryBlockDevice, Pool,
        PoolId,
    };
    use std::sync::RwLock;

    fn put_u8(out: &mut Vec<u8>, value: u8) {
        out.push(value);
    }

    fn config() -> ShareConfig {
        ShareConfig {
            name: "vault".to_string(),
            credential: Credential::new("backup", "s3cret"),
            server_guid: [0xAB; 16],
            target: "SCALEFS".to_string(),
            read_only: false,
            throttle: std::sync::Arc::new(ntlm::AuthThrottle::default()),
        }
    }

    fn nonces() -> ConnectionNonces {
        ConnectionNonces {
            salt: [0x5A; 32],
            challenge: [0x11; 8],
            system_time: 0x01D9_0000_0000_0000,
        }
    }

    fn test_core() -> Arc<MountCore<Arc<MemoryBlockDevice>>> {
        let geometry = Geometry {
            logical_block_size: 4096,
            physical_block_size: 4096,
            zone_size: 64 * 1024,
            zone_count: 64,
            erase_granularity_zones: 1,
            sequential_write_required: false,
        };
        let mut pool = Pool::create(
            Arc::new(MemoryBlockDevice::new(scalefs_core::member_image_len(
                geometry.capacity_bytes(),
            ) as usize)),
            CreateParams {
                geometry,
                pool_id: PoolId([0x77; 16]),
                device_id: DeviceId([0x78; 16]),
                case_sensitivity: CaseSensitivity::InsensitivePreserving,
                dirent_hash_seed: 5,
                label: "vault".to_string(),
                created_at_ns: 1_700_000_000_000_000_000,
            },
        )
        .unwrap();
        pool.commit(AllocPurpose::Normal, 1_700_000_000_000_000_000)
            .unwrap();
        Arc::new(MountCore::read_write(Arc::new(RwLock::new(pool))))
    }

    fn share() -> SmbShare<Arc<MemoryBlockDevice>> {
        SmbShare::new(config(), nonces(), test_core())
    }

    #[test]
    fn glob_understands_the_dos_metacharacters() {
        assert!(glob_matches("<\"bin", "payload.bin"));
        assert!(glob_matches("<\"BIN", "payload.bin"));
        assert!(!glob_matches("<\"bin", "payload.binx"));
        assert!(!glob_matches("<\"bin", "bin"));
        assert!(glob_matches("<\"*", "payload.bin"));
        assert!(glob_matches("<\"*", "noext"));
        assert!(glob_matches("<\"*", "two.dots.here"));
        assert!(glob_matches("<\"", "noext"));
        assert!(!glob_matches("<\"", "payload.bin"));
        assert!(glob_matches("h<\"txt", "hello.txt"));
        assert!(!glob_matches("h<\"txt", "jello.txt"));
        assert!(glob_matches(">ello.txt", "hello.txt"));
        assert!(!glob_matches(">ello.txt", "ello.txt"));
        assert!(glob_matches("hello>.txt", "hello.txt"));
        assert!(glob_matches("hello.txt>", "hello.txt"));
        assert!(glob_matches("hello.txt>>", "hello.txt"));
        assert!(glob_matches("<", "noext"));
        assert!(!glob_matches("<", "a.b.c"));
        assert!(glob_matches("<\"c", "a.b.c"));
        assert!(!glob_matches("<\"b", "a.b.c"));
    }

    #[test]
    fn glob_is_correct_and_never_exponential() {
        fn oracle(pattern: &[char], name: &[char]) -> bool {
            match pattern.split_first() {
                None => name.is_empty(),
                Some(('*', rest)) => (0..=name.len()).any(|skip| oracle(rest, &name[skip..])),
                Some(('?', rest)) => !name.is_empty() && oracle(rest, &name[1..]),
                Some((c, rest)) => name
                    .split_first()
                    .is_some_and(|(n, tail)| n.eq_ignore_ascii_case(c) && oracle(rest, tail)),
            }
        }
        let patterns = [
            "*",
            "*.txt",
            "a*",
            "*a",
            "a?c",
            "??",
            "",
            "a*b*c",
            "*b",
            "A*.TXT",
            "**x",
            "x**",
            "*?*",
            "report (?).pdf",
        ];
        let names = [
            "",
            "a",
            "abc",
            "a.txt",
            "A.TXT",
            "ab",
            "aXbYc",
            "bbb",
            "x",
            "xx",
            "report (1).pdf",
            "report (12).pdf",
        ];
        for pattern in patterns {
            for name in names {
                let p: Vec<char> = pattern.chars().collect();
                let n: Vec<char> = name.chars().collect();
                assert_eq!(
                    glob_matches(pattern, name),
                    oracle(&p, &n),
                    "{pattern:?} vs {name:?}"
                );
            }
        }
        let started = std::time::Instant::now();
        assert!(!glob_matches(
            "*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b",
            &"a".repeat(255)
        ));
        assert!(glob_matches(
            "*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*",
            &"a".repeat(255)
        ));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    fn create_request(path: &str, disposition: u32, options: u32) -> Vec<u8> {
        let name = wire::to_utf16le(path);
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
        put_u32(&mut body, disposition);
        put_u32(&mut body, options);
        put_u16(&mut body, (wire::HEADER_LEN + 56) as u16);
        put_u16(&mut body, name.len() as u16);
        put_u32(&mut body, 0);
        put_u32(&mut body, 0);
        body.extend_from_slice(&name);
        body
    }

    fn write_request(file_id: FileId, offset: u64, data: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        put_u16(&mut body, 49);
        put_u16(&mut body, (wire::HEADER_LEN + 48) as u16);
        put_u32(&mut body, data.len() as u32);
        put_u64(&mut body, offset);
        body.extend_from_slice(&file_id);
        put_u32(&mut body, 0);
        put_u32(&mut body, 0);
        put_u16(&mut body, 0);
        put_u16(&mut body, 0);
        put_u32(&mut body, 0);
        body.extend_from_slice(data);
        body
    }

    fn read_request(file_id: FileId, offset: u64, length: u32) -> Vec<u8> {
        let mut body = Vec::new();
        put_u16(&mut body, 49);
        put_u8(&mut body, 0);
        put_u8(&mut body, 0);
        put_u32(&mut body, length);
        put_u64(&mut body, offset);
        body.extend_from_slice(&file_id);
        put_u32(&mut body, 0);
        put_u32(&mut body, 0);
        put_u32(&mut body, 0);
        put_u16(&mut body, 0);
        put_u16(&mut body, 0);
        body.push(0);
        body
    }

    fn close_request(file_id: FileId) -> Vec<u8> {
        let mut body = Vec::new();
        put_u16(&mut body, 24);
        put_u16(&mut body, CloseRequest::POSTQUERY_ATTRIB);
        put_u32(&mut body, 0);
        body.extend_from_slice(&file_id);
        body
    }

    fn query_directory_request(file_id: FileId, restart: bool) -> Vec<u8> {
        query_directory_pattern(file_id, "*", restart)
    }

    fn query_directory_pattern(file_id: FileId, pattern: &str, restart: bool) -> Vec<u8> {
        let pattern = wire::to_utf16le(pattern);
        let mut body = Vec::new();
        put_u16(&mut body, 33);
        put_u8(&mut body, file_class::ID_BOTH_DIRECTORY);
        put_u8(
            &mut body,
            if restart {
                QueryDirectoryRequest::RESTART_SCANS
            } else {
                0
            },
        );
        put_u32(&mut body, 0);
        body.extend_from_slice(&file_id);
        put_u16(&mut body, (wire::HEADER_LEN + 32) as u16);
        put_u16(&mut body, pattern.len() as u16);
        put_u32(&mut body, 65536);
        body.extend_from_slice(&pattern);
        body
    }

    fn set_info_request(file_id: FileId, class: u8, input: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        put_u16(&mut body, 33);
        put_u8(&mut body, info_type::FILE);
        put_u8(&mut body, class);
        put_u32(&mut body, input.len() as u32);
        put_u16(&mut body, (wire::HEADER_LEN + 32) as u16);
        put_u16(&mut body, 0);
        put_u32(&mut body, 0);
        body.extend_from_slice(&file_id);
        body.extend_from_slice(input);
        body
    }

    fn file_id_of_create(response: &[u8]) -> FileId {
        let mut id = [0u8; 16];
        id.copy_from_slice(&response[64..80]);
        id
    }

    fn status_of(response: &Response) -> u32 {
        response.status
    }

    #[test]
    fn create_write_read_close() {
        let share = share();
        let create = share.create(&create_request(
            "notes.txt",
            disposition::CREATE,
            options::NON_DIRECTORY_FILE,
        ));
        assert_eq!(status_of(&create), status::SUCCESS);
        let fid = file_id_of_create(&create.body);

        let payload = b"hello scalefs over smb";
        let write = share.write(&write_request(fid, 0, payload));
        assert_eq!(status_of(&write), status::SUCCESS);
        assert_eq!(
            u32::from_le_bytes(write.body[4..8].try_into().unwrap()),
            payload.len() as u32
        );

        let read = share.read(&read_request(fid, 0, 100));
        assert_eq!(status_of(&read), status::SUCCESS);
        assert_eq!(&read.body[16..], payload);

        let eof = share.read(&read_request(fid, payload.len() as u64, 100));
        assert_eq!(status_of(&eof), status::END_OF_FILE);

        let close = share.close(&close_request(fid));
        assert_eq!(status_of(&close), status::SUCCESS);
        assert_eq!(
            u64::from_le_bytes(close.body[48..56].try_into().unwrap()),
            payload.len() as u64
        );
    }

    #[test]
    fn create_dispositions() {
        let share = share();
        assert_eq!(
            status_of(&share.create(&create_request("ghost", disposition::OPEN, 0))),
            status::OBJECT_NAME_NOT_FOUND
        );
        assert_eq!(
            status_of(&share.create(&create_request("f", disposition::CREATE, 0))),
            status::SUCCESS
        );
        assert_eq!(
            status_of(&share.create(&create_request("f", disposition::CREATE, 0))),
            status::OBJECT_NAME_COLLISION
        );
        let open_if = share.create(&create_request("f", disposition::OPEN_IF, 0));
        assert_eq!(status_of(&open_if), status::SUCCESS);
        assert_eq!(
            u32::from_le_bytes(open_if.body[4..8].try_into().unwrap()),
            action::OPENED
        );
    }

    #[test]
    fn directory_create_and_enumerate() {
        let share = share();
        share.create(&create_request(
            "dir",
            disposition::CREATE,
            options::DIRECTORY_FILE,
        ));
        share.create(&create_request("dir\\a.txt", disposition::CREATE, 0));
        share.create(&create_request("dir\\b.txt", disposition::CREATE, 0));

        let open = share.create(&create_request(
            "dir",
            disposition::OPEN,
            options::DIRECTORY_FILE,
        ));
        assert_eq!(status_of(&open), status::SUCCESS);
        let fid = file_id_of_create(&open.body);

        let query = share.query_directory(&query_directory_request(fid, false));
        assert_eq!(status_of(&query), status::SUCCESS);
        let names = parse_dir_names(&query.body);
        assert!(names.contains(&".".to_string()));
        assert!(names.contains(&"..".to_string()));
        assert!(names.contains(&"a.txt".to_string()));
        assert!(names.contains(&"b.txt".to_string()));
        assert_eq!(
            status_of(&share.query_directory(&query_directory_request(fid, false))),
            status::NO_MORE_FILES
        );
    }

    #[test]
    fn set_info_rename() {
        let share = share();
        let create = share.create(&create_request(
            "before.txt",
            disposition::CREATE,
            options::NON_DIRECTORY_FILE,
        ));
        let fid = file_id_of_create(&create.body);

        let new_name = wire::to_utf16le("after.txt");
        let mut input = Vec::new();
        put_u8(&mut input, 0);
        input.extend_from_slice(&[0u8; 7]);
        put_u64(&mut input, 0);
        put_u32(&mut input, new_name.len() as u32);
        input.extend_from_slice(&new_name);
        let set = share.set_info(&set_info_request(fid, file_class::RENAME, &input));
        assert_eq!(status_of(&set), status::SUCCESS);
        share.close(&close_request(fid));

        assert_eq!(
            status_of(&share.create(&create_request("before.txt", disposition::OPEN, 0))),
            status::OBJECT_NAME_NOT_FOUND
        );
        assert_eq!(
            status_of(&share.create(&create_request("after.txt", disposition::OPEN, 0))),
            status::SUCCESS
        );
    }

    #[test]
    fn delete_on_close_removes_the_file() {
        let share = share();
        let create = share.create(&create_request(
            "temp.tmp",
            disposition::CREATE,
            options::NON_DIRECTORY_FILE | options::DELETE_ON_CLOSE,
        ));
        let fid = file_id_of_create(&create.body);
        share.close(&close_request(fid));
        assert_eq!(
            status_of(&share.create(&create_request("temp.tmp", disposition::OPEN, 0))),
            status::OBJECT_NAME_NOT_FOUND
        );
    }

    #[test]
    fn special_files_list_but_refuse_to_open() {
        let core = test_core();
        core.symlink(ROOT_INODE, "link", b"elsewhere", 1000, 100)
            .unwrap();
        let share = SmbShare::new(config(), nonces(), core);

        let open_root = share.create(&create_request(
            "",
            disposition::OPEN,
            options::DIRECTORY_FILE,
        ));
        let fid = file_id_of_create(&open_root.body);
        let query = share.query_directory(&query_directory_request(fid, true));
        assert_eq!(status_of(&query), status::SUCCESS);
        assert!(
            parse_dir_names(&query.body).contains(&"link".to_string()),
            "the symlink lists"
        );

        assert_eq!(
            status_of(&share.create(&create_request("link", disposition::OPEN, 0))),
            status::ACCESS_DENIED,
            "opening it is refused"
        );
    }

    #[test]
    fn fuse_and_smb_coordinate_through_one_core() {
        use crate::fuse::fs::Filesystem;

        let core = test_core();
        let smb = SmbShare::new(config(), nonces(), Arc::clone(&core));
        let fuse = crate::poolfs::PoolFilesystem::over(Arc::clone(&core));

        let (entry, open) = fuse.create(ROOT_INODE, b"both.txt", 0o644, 0, 0).unwrap();

        let create = smb.create(&create_request(
            "both.txt",
            disposition::OPEN,
            options::NON_DIRECTORY_FILE | options::DELETE_ON_CLOSE,
        ));
        assert_eq!(status_of(&create), status::SUCCESS);
        let fid = file_id_of_create(&create.body);
        assert_eq!(status_of(&smb.close(&close_request(fid))), status::SUCCESS);

        assert!(
            fuse.lookup(ROOT_INODE, b"both.txt").is_err(),
            "the name is gone"
        );
        let attr = fuse
            .getattr(entry.nodeid)
            .expect("the FUSE handle keeps the object alive across speakers");
        assert_eq!(attr.attr.nlink, 0, "reported as a deferred delete");

        fuse.release(entry.nodeid, open.fh);
        assert!(
            fuse.getattr(entry.nodeid).is_err(),
            "reaped at the last cross-speaker release"
        );
    }

    #[test]
    fn directory_search_statuses_and_globs() {
        let share = share();
        share.create(&create_request(
            "evidence.txt",
            disposition::CREATE,
            options::NON_DIRECTORY_FILE,
        ));
        let open_root = share.create(&create_request(
            "",
            disposition::OPEN,
            options::DIRECTORY_FILE,
        ));
        let fid = file_id_of_create(&open_root.body);

        assert_eq!(
            status_of(&share.query_directory(&query_directory_pattern(fid, "missing.txt", true))),
            status::NO_SUCH_FILE
        );
        let hit = share.query_directory(&query_directory_pattern(fid, "EVIDENCE.TXT", true));
        assert_eq!(status_of(&hit), status::SUCCESS);
        assert!(parse_dir_names(&hit.body).contains(&"evidence.txt".to_string()));
        assert_eq!(
            status_of(
                &share.query_directory(&query_directory_pattern(fid, "EVIDENCE.TXT", false,))
            ),
            status::NO_MORE_FILES
        );
        let glob = share.query_directory(&query_directory_pattern(fid, "evi*", true));
        assert_eq!(status_of(&glob), status::SUCCESS);
        assert!(parse_dir_names(&glob.body).contains(&"evidence.txt".to_string()));
        assert_eq!(
            status_of(&share.query_directory(&query_directory_pattern(fid, "evidence.tx?", true,))),
            status::SUCCESS
        );
        assert_eq!(
            status_of(
                &share.query_directory(&query_directory_pattern(fid, "evidence?txt?", true,))
            ),
            status::NO_SUCH_FILE
        );
    }

    #[test]
    fn read_only_share_over_a_shared_core() {
        let core = test_core();
        let writer = SmbShare::new(config(), nonces(), Arc::clone(&core));
        let ro_config = ShareConfig {
            read_only: true,
            ..config()
        };
        let ro = SmbShare::new(ro_config, nonces(), Arc::clone(&core));

        let create = writer.create(&create_request(
            "data.txt",
            disposition::CREATE,
            options::NON_DIRECTORY_FILE,
        ));
        assert_eq!(status_of(&create), status::SUCCESS);
        let wfid = file_id_of_create(&create.body);
        assert_eq!(
            status_of(&writer.write(&write_request(wfid, 0, b"payload"))),
            status::SUCCESS
        );
        assert_eq!(
            status_of(&writer.close(&close_request(wfid))),
            status::SUCCESS
        );
        let inode = core.lookup(ROOT_INODE, "data.txt").unwrap().inode;

        let open = ro.create(&create_request(
            "data.txt",
            disposition::OPEN,
            options::NON_DIRECTORY_FILE,
        ));
        assert_eq!(status_of(&open), status::SUCCESS);
        let rfid = file_id_of_create(&open.body);
        let read = ro.read(&read_request(rfid, 0, 100));
        assert_eq!(status_of(&read), status::SUCCESS);
        assert_eq!(&read.body[16..], b"payload");

        assert_eq!(
            status_of(&ro.create(&create_request(
                "new.txt",
                disposition::CREATE,
                options::NON_DIRECTORY_FILE,
            ))),
            status::ACCESS_DENIED
        );
        assert_eq!(
            status_of(&ro.create(&create_request(
                "data.txt",
                disposition::OVERWRITE_IF,
                options::NON_DIRECTORY_FILE,
            ))),
            status::ACCESS_DENIED
        );
        assert_eq!(
            status_of(&ro.create(&create_request(
                "data.txt",
                disposition::OPEN,
                options::NON_DIRECTORY_FILE | options::DELETE_ON_CLOSE,
            ))),
            status::ACCESS_DENIED
        );
        assert_eq!(
            status_of(&ro.write(&write_request(rfid, 0, b"x"))),
            status::ACCESS_DENIED
        );
        assert_eq!(
            status_of(&ro.set_info(&set_info_request(rfid, file_class::DISPOSITION, &[1]))),
            status::ACCESS_DENIED
        );
        assert_eq!(
            status_of(&ro.set_info(&set_info_request(
                rfid,
                file_class::END_OF_FILE,
                &0u64.to_le_bytes(),
            ))),
            status::ACCESS_DENIED
        );

        let del = writer.create(&create_request(
            "data.txt",
            disposition::OPEN,
            options::NON_DIRECTORY_FILE | options::DELETE_ON_CLOSE,
        ));
        assert_eq!(status_of(&del), status::SUCCESS);
        assert_eq!(
            status_of(&writer.close(&close_request(file_id_of_create(&del.body)))),
            status::SUCCESS
        );
        assert_eq!(
            status_of(&writer.create(&create_request("data.txt", disposition::OPEN, 0))),
            status::OBJECT_NAME_NOT_FOUND,
            "the name is gone"
        );
        let read = ro.read(&read_request(rfid, 0, 100));
        assert_eq!(status_of(&read), status::SUCCESS, "the holder still reads");
        assert_eq!(&read.body[16..], b"payload");
        assert_eq!(status_of(&ro.close(&close_request(rfid))), status::SUCCESS);
        assert!(
            core.getattr(inode).is_err(),
            "the read-only holder's close reaped the deferred object"
        );
    }

    #[test]
    fn concurrent_dispatch_is_coherent() {
        let geometry = Geometry {
            logical_block_size: 4096,
            physical_block_size: 4096,
            zone_size: 64 * 1024,
            zone_count: 256,
            erase_granularity_zones: 1,
            sequential_write_required: false,
        };
        let mut pool = Pool::create(
            Arc::new(MemoryBlockDevice::new(scalefs_core::member_image_len(
                geometry.capacity_bytes(),
            ) as usize)),
            CreateParams {
                geometry,
                pool_id: PoolId([0x79; 16]),
                device_id: DeviceId([0x7A; 16]),
                case_sensitivity: CaseSensitivity::InsensitivePreserving,
                dirent_hash_seed: 5,
                label: "vault".to_string(),
                created_at_ns: 1_700_000_000_000_000_000,
            },
        )
        .unwrap();
        pool.commit(AllocPurpose::Normal, 1_700_000_000_000_000_000)
            .unwrap();
        let core = Arc::new(MountCore::read_write(Arc::new(RwLock::new(pool))));
        let share = Arc::new(SmbShare::new(config(), nonces(), core));

        let create = share.create(&create_request(
            "shared.bin",
            disposition::CREATE,
            options::NON_DIRECTORY_FILE,
        ));
        assert_eq!(status_of(&create), status::SUCCESS);
        let shared_fid = file_id_of_create(&create.body);
        let payload: Vec<u8> = (0..16 * 1024).map(|i| (i % 251) as u8).collect();
        assert_eq!(
            status_of(&share.write(&write_request(shared_fid, 0, &payload))),
            status::SUCCESS
        );

        std::thread::scope(|scope| {
            for lane in 0..2 {
                let share = &share;
                scope.spawn(move || {
                    for i in 0..8 {
                        let name = format!("t{lane}-{i}.bin");
                        let create = share.create(&create_request(
                            &name,
                            disposition::CREATE,
                            options::NON_DIRECTORY_FILE,
                        ));
                        assert_eq!(status_of(&create), status::SUCCESS);
                        let fid = file_id_of_create(&create.body);
                        let body = format!("{lane}:{i}:payload").into_bytes();
                        assert_eq!(
                            status_of(&share.write(&write_request(fid, 0, &body))),
                            status::SUCCESS
                        );
                        let read = share.read(&read_request(fid, 0, 256));
                        assert_eq!(status_of(&read), status::SUCCESS);
                        assert_eq!(&read.body[16..], &body[..]);
                        assert_eq!(
                            status_of(&share.close(&close_request(fid))),
                            status::SUCCESS
                        );
                    }
                });
            }
            for _ in 0..2 {
                let share = &share;
                let payload = &payload;
                scope.spawn(move || {
                    for i in 0..64 {
                        let at = (i % 31) * 512;
                        let read = share.read(&read_request(shared_fid, at as u64, 512));
                        assert_eq!(status_of(&read), status::SUCCESS);
                        assert_eq!(&read.body[16..], &payload[at..at + 512]);
                    }
                });
            }
        });

        assert_eq!(
            status_of(&share.close(&close_request(shared_fid))),
            status::SUCCESS
        );
        assert!(share.files().is_empty());
    }

    fn parse_dir_names(query_body: &[u8]) -> Vec<String> {
        let info = &query_body[8..];
        let mut names = Vec::new();
        let mut at = 0usize;
        loop {
            if at + 4 > info.len() {
                break;
            }
            let next = u32::from_le_bytes(info[at..at + 4].try_into().unwrap()) as usize;
            let name_len = u32::from_le_bytes(info[at + 60..at + 64].try_into().unwrap()) as usize;
            let name_start = at + 104;
            let name_bytes = &info[name_start..name_start + name_len];
            names.push(wire::from_utf16le(name_bytes));
            if next == 0 {
                break;
            }
            at += next;
        }
        names
    }
}
