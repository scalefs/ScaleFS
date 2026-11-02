use super::crypto::md4::nt_hash;
use super::crypto::md5::hmac_md5;
use super::fileops::{
    CloseRequest, FileId, QueryDirectoryRequest, action, disposition, file_class, info_type,
    options,
};
use super::ntlm::{Credential, flags as ntlm};
use super::session::Connection;
use super::share::{ConnectionNonces, ShareConfig, SmbShare};
use super::wire::{self, Header, command, status};
use crate::mountcore::MountCore;
use scalefs_core::wire::{put_u16, put_u32, put_u64};
use scalefs_core::{
    AllocPurpose, CaseSensitivity, CreateParams, DeviceId, Geometry, MemoryBlockDevice, Pool,
    PoolId, SharedDevice,
};
use std::sync::{Arc, RwLock};

struct Reply {
    status: u32,
    body: Vec<u8>,
}

struct Client {
    connection: Connection,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
}

impl Client {
    fn new() -> Client {
        Client {
            connection: Connection::new(),
            message_id: 0,
            session_id: 0,
            tree_id: 0,
        }
    }

    fn send<D: SharedDevice>(
        &mut self,
        command: u16,
        body: &[u8],
        share: &mut SmbShare<D>,
    ) -> Reply {
        let header = Header {
            command,
            message_id: self.message_id,
            credits: 1,
            session_id: self.session_id,
            tree_id: self.tree_id,
            ..Header::default()
        };
        self.message_id += 1;

        let mut message = Vec::new();
        header.encode(&mut message);
        message.extend_from_slice(body);

        if let Some(key) = self.connection.signing_key() {
            let mut header_flags = u32::from_le_bytes(message[16..20].try_into().unwrap());
            header_flags |= wire::flags::SIGNED;
            message[16..20].copy_from_slice(&header_flags.to_le_bytes());
            super::sign::sign(&mut message, &key);
        }

        let framed = self
            .connection
            .handle(&message, share)
            .expect("server dropped the connection");
        let smb2 = &framed[4..];
        let reply_flags = u32::from_le_bytes(smb2[16..20].try_into().unwrap());
        if reply_flags & wire::flags::SIGNED != 0 {
            let key = self
                .connection
                .signing_key()
                .expect("a signed reply implies a session key");
            assert!(
                super::sign::verify(smb2, &key),
                "the server's reply to command 0x{command:04x} failed signature verification",
            );
        }
        let status = u32::from_le_bytes(smb2[8..12].try_into().unwrap());
        if command == command::SESSION_SETUP {
            self.session_id = u64::from_le_bytes(smb2[40..48].try_into().unwrap());
        }
        if command == command::TREE_CONNECT && status == status::SUCCESS {
            self.tree_id = u32::from_le_bytes(smb2[36..40].try_into().unwrap());
        }
        Reply {
            status,
            body: smb2[wire::HEADER_LEN..].to_vec(),
        }
    }

    fn log_in<D: SharedDevice>(&mut self, user: &str, password: &str, share: &mut SmbShare<D>) {
        let negotiate = self.send(command::NEGOTIATE, &negotiate_request(), share);
        assert_eq!(negotiate.status, status::SUCCESS, "NEGOTIATE");

        let step1 = self.send(
            command::SESSION_SETUP,
            &session_setup_request(&ntlmssp_negotiate()),
            share,
        );
        assert_eq!(
            step1.status,
            status::MORE_PROCESSING_REQUIRED,
            "SESSION_SETUP challenge",
        );
        let challenge = server_challenge_from(&step1.body);

        let auth = ntlmssp_authenticate(user, "", password, challenge);
        let step2 = self.send(command::SESSION_SETUP, &session_setup_request(&auth), share);
        assert_eq!(step2.status, status::SUCCESS, "SESSION_SETUP authenticate");
    }

    fn tree_connect<D: SharedDevice>(&mut self, path: &str, share: &mut SmbShare<D>) {
        let reply = self.send(command::TREE_CONNECT, &tree_connect_request(path), share);
        assert_eq!(reply.status, status::SUCCESS, "TREE_CONNECT");
    }
}

fn negotiate_request() -> Vec<u8> {
    let mut out = Vec::new();
    put_u16(&mut out, 36);
    put_u16(&mut out, 1);
    put_u16(&mut out, 1);
    put_u16(&mut out, 0);
    put_u32(&mut out, 0);
    out.extend_from_slice(&[0u8; 16]);
    put_u64(&mut out, 0);
    put_u16(&mut out, wire::DIALECT_311);
    put_u16(&mut out, 0);
    out
}

fn session_setup_request(token: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put_u16(&mut out, 25);
    out.push(0);
    out.push(0);
    put_u32(&mut out, 0);
    put_u32(&mut out, 0);
    put_u16(&mut out, (wire::HEADER_LEN + 24) as u16);
    put_u16(&mut out, token.len() as u16);
    put_u64(&mut out, 0);
    out.extend_from_slice(token);
    out
}

fn ntlmssp_negotiate() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"NTLMSSP\0");
    put_u32(&mut out, 1);
    put_u32(
        &mut out,
        ntlm::UNICODE | ntlm::NTLM | ntlm::EXTENDED_SESSIONSECURITY,
    );
    out.extend_from_slice(&[0u8; 16]);
    out
}

fn server_challenge_from(setup_body: &[u8]) -> [u8; 8] {
    let sec_len = u16::from_le_bytes([setup_body[6], setup_body[7]]) as usize;
    let security_buffer = &setup_body[8..8 + sec_len];
    let challenge = super::spnego::extract_ntlmssp(security_buffer).expect("NTLMSSP challenge");
    challenge[24..32].try_into().unwrap()
}

fn ntlmssp_authenticate(user: &str, domain: &str, password: &str, challenge: [u8; 8]) -> Vec<u8> {
    let nt_hash = nt_hash(password);
    let mut identity = utf16le(&user.to_uppercase());
    identity.extend_from_slice(&utf16le(domain));
    let ntowfv2 = hmac_md5(&nt_hash, &identity);

    let mut blob = Vec::new();
    blob.extend_from_slice(&[0x01, 0x01, 0, 0]);
    put_u32(&mut blob, 0);
    put_u64(&mut blob, 0x01D9_0000_0000_0000);
    blob.extend_from_slice(&[0xAA; 8]);
    put_u32(&mut blob, 0);
    put_u32(&mut blob, 0);

    let mut proof_input = Vec::new();
    proof_input.extend_from_slice(&challenge);
    proof_input.extend_from_slice(&blob);
    let proof = hmac_md5(&ntowfv2, &proof_input);
    let mut nt_response = proof.to_vec();
    nt_response.extend_from_slice(&blob);

    let mut fixed = vec![0u8; 64];
    fixed[0..8].copy_from_slice(b"NTLMSSP\0");
    fixed[8..12].copy_from_slice(&3u32.to_le_bytes());
    let mut payload = Vec::new();
    let place = |fixed: &mut [u8], pos: usize, data: &[u8], payload: &mut Vec<u8>| {
        let off = 64 + payload.len();
        fixed[pos..pos + 2].copy_from_slice(&(data.len() as u16).to_le_bytes());
        fixed[pos + 2..pos + 4].copy_from_slice(&(data.len() as u16).to_le_bytes());
        fixed[pos + 4..pos + 8].copy_from_slice(&(off as u32).to_le_bytes());
        payload.extend_from_slice(data);
    };
    place(&mut fixed, 12, &[], &mut payload);
    place(&mut fixed, 20, &nt_response, &mut payload);
    place(&mut fixed, 28, &utf16le(domain), &mut payload);
    place(&mut fixed, 36, &utf16le(user), &mut payload);
    place(&mut fixed, 44, &utf16le("client"), &mut payload);
    place(&mut fixed, 52, &[], &mut payload);
    fixed[60..64].copy_from_slice(
        &(ntlm::UNICODE | ntlm::NTLM | ntlm::EXTENDED_SESSIONSECURITY).to_le_bytes(),
    );

    let mut out = fixed;
    out.extend_from_slice(&payload);
    out
}

fn tree_connect_request(path: &str) -> Vec<u8> {
    let path16 = wire::to_utf16le(path);
    let mut out = Vec::new();
    put_u16(&mut out, 9);
    put_u16(&mut out, 0);
    put_u16(&mut out, (wire::HEADER_LEN + 8) as u16);
    put_u16(&mut out, path16.len() as u16);
    out.extend_from_slice(&path16);
    out
}

fn create_request(path: &str, disposition: u32, create_options: u32) -> Vec<u8> {
    let name = wire::to_utf16le(path);
    let mut out = Vec::new();
    put_u16(&mut out, 57);
    out.push(0);
    out.push(0);
    put_u32(&mut out, 2);
    put_u64(&mut out, 0);
    put_u64(&mut out, 0);
    put_u32(&mut out, 0x0012_0089);
    put_u32(&mut out, 0);
    put_u32(&mut out, 0x07);
    put_u32(&mut out, disposition);
    put_u32(&mut out, create_options);
    put_u16(&mut out, (wire::HEADER_LEN + 56) as u16);
    put_u16(&mut out, name.len() as u16);
    put_u32(&mut out, 0);
    put_u32(&mut out, 0);
    out.extend_from_slice(&name);
    out
}

fn write_request(file_id: FileId, offset: u64, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put_u16(&mut out, 49);
    put_u16(&mut out, (wire::HEADER_LEN + 48) as u16);
    put_u32(&mut out, data.len() as u32);
    put_u64(&mut out, offset);
    out.extend_from_slice(&file_id);
    put_u32(&mut out, 0);
    put_u32(&mut out, 0);
    put_u16(&mut out, 0);
    put_u16(&mut out, 0);
    put_u32(&mut out, 0);
    out.extend_from_slice(data);
    out
}

fn read_request(file_id: FileId, offset: u64, length: u32) -> Vec<u8> {
    let mut out = Vec::new();
    put_u16(&mut out, 49);
    out.push(0);
    out.push(0);
    put_u32(&mut out, length);
    put_u64(&mut out, offset);
    out.extend_from_slice(&file_id);
    put_u32(&mut out, 0);
    put_u32(&mut out, 0);
    put_u32(&mut out, 0);
    put_u16(&mut out, 0);
    put_u16(&mut out, 0);
    out.push(0);
    out
}

fn close_request(file_id: FileId) -> Vec<u8> {
    let mut out = Vec::new();
    put_u16(&mut out, 24);
    put_u16(&mut out, CloseRequest::POSTQUERY_ATTRIB);
    put_u32(&mut out, 0);
    out.extend_from_slice(&file_id);
    out
}

fn query_directory_request(file_id: FileId, info_class: u8) -> Vec<u8> {
    query_directory_request_flags(file_id, info_class, QueryDirectoryRequest::RESTART_SCANS)
}

fn query_directory_request_flags(file_id: FileId, info_class: u8, flags: u8) -> Vec<u8> {
    let pattern = wire::to_utf16le("*");
    let mut out = Vec::new();
    put_u16(&mut out, 33);
    out.push(info_class);
    out.push(flags);
    put_u32(&mut out, 0);
    out.extend_from_slice(&file_id);
    put_u16(&mut out, (wire::HEADER_LEN + 32) as u16);
    put_u16(&mut out, pattern.len() as u16);
    put_u32(&mut out, 65536);
    out.extend_from_slice(&pattern);
    out
}

fn query_info_request(file_id: FileId, info_type: u8, info_class: u8) -> Vec<u8> {
    let mut out = Vec::new();
    put_u16(&mut out, 41);
    out.push(info_type);
    out.push(info_class);
    put_u32(&mut out, 65536);
    put_u16(&mut out, 0);
    put_u16(&mut out, 0);
    put_u32(&mut out, 0);
    put_u32(&mut out, 0);
    put_u32(&mut out, 0);
    out.extend_from_slice(&file_id);
    out
}

fn created_file_id(body: &[u8]) -> FileId {
    body[64..80].try_into().unwrap()
}

fn created_action(body: &[u8]) -> u32 {
    u32::from_le_bytes(body[4..8].try_into().unwrap())
}

fn read_data(body: &[u8]) -> &[u8] {
    &body[16..]
}

fn closed_eof(body: &[u8]) -> u64 {
    u64::from_le_bytes(body[48..56].try_into().unwrap())
}

fn directory_names(query_body: &[u8], name_offset: usize) -> Vec<String> {
    let buffer = &query_body[8..];
    let mut names = Vec::new();
    let mut pos = 0;
    while pos + name_offset <= buffer.len() {
        let next = u32::from_le_bytes(buffer[pos..pos + 4].try_into().unwrap()) as usize;
        let name_len = u32::from_le_bytes(buffer[pos + 60..pos + 64].try_into().unwrap()) as usize;
        let name_start = pos + name_offset;
        if name_start + name_len <= buffer.len() {
            names.push(wire::from_utf16le(
                &buffer[name_start..name_start + name_len],
            ));
        }
        if next == 0 {
            break;
        }
        pos += next;
    }
    names
}

fn config() -> ShareConfig {
    ShareConfig {
        name: "vault".to_string(),
        credential: Credential::new("backup", "s3cret-pass"),
        server_guid: [0xAB; 16],
        target: "SCALEFS".to_string(),
        read_only: false,
        throttle: std::sync::Arc::new(super::ntlm::AuthThrottle::default()),
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
        Arc::new(MemoryBlockDevice::new(
            scalefs_core::member_image_len(geometry.capacity_bytes()) as usize,
        )),
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

#[test]
fn client_round_trips_a_file_over_the_protocol() {
    let mut share = SmbShare::new(config(), nonces(), test_core());
    let mut client = Client::new();

    client.log_in("backup", "s3cret-pass", &mut share);
    client.tree_connect("\\\\scalefs\\vault", &mut share);

    let create = client.send(
        command::CREATE,
        &create_request(
            "report.txt",
            disposition::CREATE,
            options::NON_DIRECTORY_FILE,
        ),
        &mut share,
    );
    assert_eq!(create.status, status::SUCCESS, "CREATE");
    assert_eq!(created_action(&create.body), action::CREATED);
    let fid = created_file_id(&create.body);

    let payload: Vec<u8> = (0..9000u32).map(|i| (i * 31) as u8).collect();
    let write = client.send(command::WRITE, &write_request(fid, 0, &payload), &mut share);
    assert_eq!(write.status, status::SUCCESS, "WRITE");
    assert_eq!(
        u32::from_le_bytes(write.body[4..8].try_into().unwrap()),
        payload.len() as u32,
        "the write count is the whole payload",
    );

    let close = client.send(command::CLOSE, &close_request(fid), &mut share);
    assert_eq!(close.status, status::SUCCESS, "CLOSE");
    assert_eq!(closed_eof(&close.body), payload.len() as u64);

    let reopen = client.send(
        command::CREATE,
        &create_request("report.txt", disposition::OPEN, options::NON_DIRECTORY_FILE),
        &mut share,
    );
    assert_eq!(reopen.status, status::SUCCESS, "re-OPEN");
    assert_eq!(created_action(&reopen.body), action::OPENED);
    let fid = created_file_id(&reopen.body);

    let read = client.send(
        command::READ,
        &read_request(fid, 0, payload.len() as u32),
        &mut share,
    );
    assert_eq!(read.status, status::SUCCESS, "READ");
    assert_eq!(read_data(&read.body), &payload[..], "the bytes round-trip");

    let _ = client.send(command::CLOSE, &close_request(fid), &mut share);

    let root = client.send(
        command::CREATE,
        &create_request("", disposition::OPEN, options::DIRECTORY_FILE),
        &mut share,
    );
    assert_eq!(root.status, status::SUCCESS, "open root");
    let root_fid = created_file_id(&root.body);
    let listing = client.send(
        command::QUERY_DIRECTORY,
        &query_directory_request(root_fid, file_class::ID_BOTH_DIRECTORY),
        &mut share,
    );
    assert_eq!(listing.status, status::SUCCESS, "QUERY_DIRECTORY");
    let names = directory_names(&listing.body, 104);
    assert!(names.contains(&".".to_string()), "names: {names:?}");
    assert!(names.contains(&"..".to_string()), "names: {names:?}");
    assert!(
        names.contains(&"report.txt".to_string()),
        "names: {names:?}"
    );
    let _ = client.send(command::CLOSE, &close_request(root_fid), &mut share);

    let doomed = client.send(
        command::CREATE,
        &create_request(
            "report.txt",
            disposition::OPEN,
            options::NON_DIRECTORY_FILE | options::DELETE_ON_CLOSE,
        ),
        &mut share,
    );
    assert_eq!(doomed.status, status::SUCCESS, "open for delete");
    let doomed_fid = created_file_id(&doomed.body);
    let close = client.send(command::CLOSE, &close_request(doomed_fid), &mut share);
    assert_eq!(close.status, status::SUCCESS, "delete-on-close");

    let reopen_deleted = client.send(
        command::CREATE,
        &create_request("report.txt", disposition::OPEN, options::NON_DIRECTORY_FILE),
        &mut share,
    );
    assert_eq!(
        reopen_deleted.status,
        status::OBJECT_NAME_NOT_FOUND,
        "the file is gone after delete-on-close",
    );
}

#[test]
fn full_directory_and_normalized_name_classes() {
    let mut share = SmbShare::new(config(), nonces(), test_core());
    let mut client = Client::new();
    client.log_in("backup", "s3cret-pass", &mut share);
    client.tree_connect("\\\\scalefs\\vault", &mut share);

    let create = client.send(
        command::CREATE,
        &create_request("data.bin", disposition::CREATE, options::NON_DIRECTORY_FILE),
        &mut share,
    );
    assert_eq!(create.status, status::SUCCESS);
    let fid = created_file_id(&create.body);
    let _ = client.send(
        command::WRITE,
        &write_request(fid, 0, b"payload"),
        &mut share,
    );
    let _ = client.send(command::CLOSE, &close_request(fid), &mut share);

    let root = client.send(
        command::CREATE,
        &create_request("", disposition::OPEN, options::DIRECTORY_FILE),
        &mut share,
    );
    let root_fid = created_file_id(&root.body);
    let listing = client.send(
        command::QUERY_DIRECTORY,
        &query_directory_request(root_fid, file_class::FULL_DIRECTORY),
        &mut share,
    );
    assert_eq!(listing.status, status::SUCCESS, "full-directory enumerate");
    let names = directory_names(&listing.body, 68);
    assert!(names.contains(&"data.bin".to_string()), "names: {names:?}");
    let _ = client.send(command::CLOSE, &close_request(root_fid), &mut share);

    let open = client.send(
        command::CREATE,
        &create_request("data.bin", disposition::OPEN, options::NON_DIRECTORY_FILE),
        &mut share,
    );
    let fid = created_file_id(&open.body);
    let name_info = client.send(
        command::QUERY_INFO,
        &query_info_request(fid, info_type::FILE, file_class::NORMALIZED_NAME),
        &mut share,
    );
    assert_eq!(name_info.status, status::SUCCESS, "normalized name");
    let name_len = u32::from_le_bytes(name_info.body[8..12].try_into().unwrap()) as usize;
    let name = wire::from_utf16le(&name_info.body[12..12 + name_len]);
    assert_eq!(name, "\\data.bin");
    let _ = client.send(command::CLOSE, &close_request(fid), &mut share);
}

#[test]
fn full_directory_buffer_walks_strictly() {
    let mut share = SmbShare::new(config(), nonces(), test_core());
    let mut client = Client::new();
    client.log_in("backup", "s3cret-pass", &mut share);
    client.tree_connect("\\\\scalefs\\vault", &mut share);

    for (name, opts) in [
        ("readme.txt", options::NON_DIRECTORY_FILE),
        ("docs", options::DIRECTORY_FILE),
    ] {
        let r = client.send(
            command::CREATE,
            &create_request(name, disposition::CREATE, opts),
            &mut share,
        );
        assert_eq!(r.status, status::SUCCESS, "create {name}");
        let _ = client.send(
            command::CLOSE,
            &close_request(created_file_id(&r.body)),
            &mut share,
        );
    }

    let root = client.send(
        command::CREATE,
        &create_request("", disposition::OPEN, options::DIRECTORY_FILE),
        &mut share,
    );
    let root_fid = created_file_id(&root.body);
    let reply = client.send(
        command::QUERY_DIRECTORY,
        &query_directory_request(root_fid, file_class::FULL_DIRECTORY),
        &mut share,
    );
    assert_eq!(reply.status, status::SUCCESS, "full enumerate");

    let out_len = u32::from_le_bytes(reply.body[4..8].try_into().unwrap()) as usize;
    let buffer = &reply.body[8..8 + out_len];

    let mut names = Vec::new();
    let mut pos = 0usize;
    loop {
        assert!(
            pos + 68 <= buffer.len(),
            "entry header past buffer at {pos}"
        );
        let next = u32::from_le_bytes(buffer[pos..pos + 4].try_into().unwrap()) as usize;
        let name_len = u32::from_le_bytes(buffer[pos + 60..pos + 64].try_into().unwrap()) as usize;
        assert!(
            pos + 68 + name_len <= buffer.len(),
            "name past buffer at {pos}"
        );
        names.push(wire::from_utf16le(&buffer[pos + 68..pos + 68 + name_len]));
        if next == 0 {
            break;
        }
        assert_eq!(next % 8, 0, "NextEntryOffset {next} is not 8-aligned");
        pos += next;
    }
    for expected in [".", "..", "docs", "readme.txt"] {
        assert!(
            names.contains(&expected.to_string()),
            "missing {expected} in {names:?}"
        );
    }
}

#[test]
fn single_entry_enumeration_returns_one_per_call() {
    let mut share = SmbShare::new(config(), nonces(), test_core());
    let mut client = Client::new();
    client.log_in("backup", "s3cret-pass", &mut share);
    client.tree_connect("\\\\scalefs\\vault", &mut share);
    for (name, opts) in [
        ("readme.txt", options::NON_DIRECTORY_FILE),
        ("docs", options::DIRECTORY_FILE),
    ] {
        let r = client.send(
            command::CREATE,
            &create_request(name, disposition::CREATE, opts),
            &mut share,
        );
        assert_eq!(r.status, status::SUCCESS);
        let _ = client.send(
            command::CLOSE,
            &close_request(created_file_id(&r.body)),
            &mut share,
        );
    }
    let root = client.send(
        command::CREATE,
        &create_request("", disposition::OPEN, options::DIRECTORY_FILE),
        &mut share,
    );
    let root_fid = created_file_id(&root.body);

    let single = QueryDirectoryRequest::RETURN_SINGLE_ENTRY;
    let restart = QueryDirectoryRequest::RESTART_SCANS;
    let mut names = Vec::new();
    let mut first = true;
    loop {
        let flags = if first { single | restart } else { single };
        first = false;
        let reply = client.send(
            command::QUERY_DIRECTORY,
            &query_directory_request_flags(root_fid, file_class::ID_BOTH_DIRECTORY, flags),
            &mut share,
        );
        if reply.status == status::NO_MORE_FILES {
            break;
        }
        assert_eq!(reply.status, status::SUCCESS, "single-entry query");
        let batch = directory_names(&reply.body, 104);
        assert_eq!(
            batch.len(),
            1,
            "must return exactly one entry, got {batch:?}"
        );
        names.push(batch.into_iter().next().unwrap());
        assert!(names.len() <= 8, "runaway enumeration: {names:?}");
    }
    assert_eq!(names.len(), 4, "one entry per call, four in all: {names:?}");
    for expected in [".", "..", "docs", "readme.txt"] {
        assert!(
            names.contains(&expected.to_string()),
            "missing {expected}: {names:?}"
        );
    }
}

#[test]
fn a_failed_create_does_not_orphan_a_related_close() {
    let mut share = SmbShare::new(config(), nonces(), test_core());
    let mut client = Client::new();
    client.log_in("backup", "s3cret-pass", &mut share);
    client.tree_connect("\\\\scalefs\\vault", &mut share);

    let keep = client.send(
        command::CREATE,
        &create_request("keep.txt", disposition::CREATE, options::NON_DIRECTORY_FILE),
        &mut share,
    );
    assert_eq!(keep.status, status::SUCCESS);
    let keep_fid = created_file_id(&keep.body);

    let ghost = client.send(
        command::CREATE,
        &create_request("ghost.txt", disposition::OPEN, options::NON_DIRECTORY_FILE),
        &mut share,
    );
    assert_eq!(ghost.status, status::OBJECT_NAME_NOT_FOUND);

    let related = [0xFFu8; 16];
    let close = client.send(command::CLOSE, &close_request(related), &mut share);
    assert_eq!(
        close.status,
        status::FILE_CLOSED,
        "0xFF after a failed create resolves to no handle",
    );

    let info = client.send(
        command::QUERY_INFO,
        &query_info_request(keep_fid, info_type::FILE, file_class::BASIC),
        &mut share,
    );
    assert_eq!(
        info.status,
        status::SUCCESS,
        "the kept handle survived the failed create's related close",
    );
}

#[test]
fn a_bad_password_is_refused() {
    let mut share = SmbShare::new(config(), nonces(), test_core());
    let mut client = Client::new();

    assert_eq!(
        client
            .send(command::NEGOTIATE, &negotiate_request(), &mut share)
            .status,
        status::SUCCESS,
    );
    let step1 = client.send(
        command::SESSION_SETUP,
        &session_setup_request(&ntlmssp_negotiate()),
        &mut share,
    );
    assert_eq!(step1.status, status::MORE_PROCESSING_REQUIRED);
    let challenge = server_challenge_from(&step1.body);
    let auth = ntlmssp_authenticate("backup", "", "the-wrong-password", challenge);
    let step2 = client.send(
        command::SESSION_SETUP,
        &session_setup_request(&auth),
        &mut share,
    );
    assert_eq!(step2.status, status::LOGON_FAILURE, "bad password");

    let tree = client.send(
        command::TREE_CONNECT,
        &tree_connect_request("\\\\s\\vault"),
        &mut share,
    );
    assert_eq!(tree.status, status::ACCESS_DENIED, "no session");
}

#[test]
fn a_guesser_on_one_connection_is_throttled_without_locking_the_share() {
    fn attempt(
        client: &mut Client,
        share: &mut SmbShare<Arc<MemoryBlockDevice>>,
        password: &str,
    ) -> (u32, Option<([u8; 8], u32)>) {
        let step1 = client.send(
            command::SESSION_SETUP,
            &session_setup_request(&ntlmssp_negotiate()),
            share,
        );
        if step1.status != status::MORE_PROCESSING_REQUIRED {
            return (step1.status, None);
        }
        let challenge = server_challenge_from(&step1.body);
        let auth = ntlmssp_authenticate("backup", "", password, challenge);
        let step2 = client.send(command::SESSION_SETUP, &session_setup_request(&auth), share);
        (step1.status, Some((challenge, step2.status)))
    }

    let core = test_core();
    let mut shared = config();
    shared.throttle = std::sync::Arc::new(super::ntlm::AuthThrottle::share_wide());

    let mut share = SmbShare::new(shared.clone(), nonces(), Arc::clone(&core));
    let mut guesser = Client::new();
    assert_eq!(
        guesser
            .send(command::NEGOTIATE, &negotiate_request(), &mut share)
            .status,
        status::SUCCESS,
    );
    let mut challenges = Vec::new();
    for _ in 0..4 {
        let (step1, step2) = attempt(&mut guesser, &mut share, "wrong");
        assert_eq!(step1, status::MORE_PROCESSING_REQUIRED);
        let (challenge, step2) = step2.expect("a challenge was offered");
        assert_eq!(step2, status::LOGON_FAILURE);
        challenges.push(challenge);
    }
    challenges.sort_unstable();
    challenges.dedup();
    assert_eq!(challenges.len(), 4, "every exchange gets its own challenge");
    assert_eq!(
        attempt(&mut guesser, &mut share, "s3cret-pass"),
        (status::LOGON_FAILURE, None)
    );

    let mut share_for_user = SmbShare::new(shared, nonces(), Arc::clone(&core));
    let mut user = Client::new();
    user.log_in("backup", "s3cret-pass", &mut share_for_user);
}

#[test]
fn failed_logons_back_off_share_wide() {
    let core = test_core();
    let mut throttled = config();
    throttled.throttle = std::sync::Arc::new(super::ntlm::AuthThrottle::with_tuning(
        1,
        std::time::Duration::from_millis(250),
        std::time::Duration::from_millis(250),
    ));

    let attempt = |password: &str| -> (u32, Option<u32>) {
        let mut share = SmbShare::new(throttled.clone(), nonces(), Arc::clone(&core));
        let mut client = Client::new();
        assert_eq!(
            client
                .send(command::NEGOTIATE, &negotiate_request(), &mut share)
                .status,
            status::SUCCESS,
        );
        let step1 = client.send(
            command::SESSION_SETUP,
            &session_setup_request(&ntlmssp_negotiate()),
            &mut share,
        );
        if step1.status != status::MORE_PROCESSING_REQUIRED {
            return (step1.status, None);
        }
        let challenge = server_challenge_from(&step1.body);
        let auth = ntlmssp_authenticate("backup", "", password, challenge);
        let step2 = client.send(
            command::SESSION_SETUP,
            &session_setup_request(&auth),
            &mut share,
        );
        (step1.status, Some(step2.status))
    };

    assert_eq!(
        attempt("wrong-1"),
        (
            status::MORE_PROCESSING_REQUIRED,
            Some(status::LOGON_FAILURE)
        ),
    );
    assert_eq!(
        attempt("wrong-2"),
        (
            status::MORE_PROCESSING_REQUIRED,
            Some(status::LOGON_FAILURE)
        ),
    );
    assert_eq!(attempt("s3cret-pass"), (status::LOGON_FAILURE, None));

    std::thread::sleep(std::time::Duration::from_millis(350));
    assert_eq!(
        attempt("s3cret-pass"),
        (status::MORE_PROCESSING_REQUIRED, Some(status::SUCCESS)),
    );
}

fn utf16le(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() * 2);
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}
