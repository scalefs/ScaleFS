
use super::crypto::kdf::smb3_signing_key;
use super::crypto::md4::nt_hash;
use super::crypto::md5::hmac_md5;
use super::fileops::{CloseRequest, FileId, QueryDirectoryRequest};
use super::ntlm::flags as ntlm;
use super::session::fold;
use super::{sign, spnego, wire};
use scalefs_core::wire::{put_u16, put_u32, put_u64};

pub fn utf16le(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() * 2);
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}


pub fn negotiate_request() -> Vec<u8> {
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

pub fn session_setup_request(token: &[u8]) -> Vec<u8> {
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

pub fn ntlmssp_negotiate() -> Vec<u8> {
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

pub fn server_challenge_from(setup_body: &[u8]) -> [u8; 8] {
    let sec_len = u16::from_le_bytes([setup_body[6], setup_body[7]]) as usize;
    let security_buffer = &setup_body[8..8 + sec_len];
    let challenge = spnego::extract_ntlmssp(security_buffer).expect("NTLMSSP challenge");
    challenge[24..32].try_into().unwrap()
}

fn ntowfv2(user: &str, domain: &str, password: &str) -> [u8; 16] {
    let nt = nt_hash(password);
    let mut identity = utf16le(&user.to_uppercase());
    identity.extend_from_slice(&utf16le(domain));
    hmac_md5(&nt, &identity)
}

fn ntlmv2_blob() -> Vec<u8> {
    let mut blob = Vec::new();
    blob.extend_from_slice(&[0x01, 0x01, 0, 0]);
    put_u32(&mut blob, 0);
    put_u64(&mut blob, 0x01D9_0000_0000_0000);
    blob.extend_from_slice(&[0xAA; 8]);
    put_u32(&mut blob, 0);
    put_u32(&mut blob, 0);
    blob
}

fn ntlmv2_proof(ntowfv2: &[u8; 16], challenge: [u8; 8], blob: &[u8]) -> [u8; 16] {
    let mut proof_input = Vec::with_capacity(8 + blob.len());
    proof_input.extend_from_slice(&challenge);
    proof_input.extend_from_slice(blob);
    hmac_md5(ntowfv2, &proof_input)
}

pub fn ntlmv2_session_key(
    user: &str,
    domain: &str,
    password: &str,
    challenge: [u8; 8],
) -> [u8; 16] {
    let ntowfv2 = ntowfv2(user, domain, password);
    let proof = ntlmv2_proof(&ntowfv2, challenge, &ntlmv2_blob());
    hmac_md5(&ntowfv2, &proof)
}

pub fn ntlmssp_authenticate(
    user: &str,
    domain: &str,
    password: &str,
    challenge: [u8; 8],
) -> Vec<u8> {
    let ntowfv2 = ntowfv2(user, domain, password);
    let blob = ntlmv2_blob();
    let proof = ntlmv2_proof(&ntowfv2, challenge, &blob);
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

pub fn tree_connect_request(path: &str) -> Vec<u8> {
    let path16 = wire::to_utf16le(path);
    let mut out = Vec::new();
    put_u16(&mut out, 9);
    put_u16(&mut out, 0);
    put_u16(&mut out, (wire::HEADER_LEN + 8) as u16);
    put_u16(&mut out, path16.len() as u16);
    out.extend_from_slice(&path16);
    out
}

pub fn create_request(path: &str, disposition: u32, create_options: u32) -> Vec<u8> {
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

pub fn write_request(file_id: FileId, offset: u64, data: &[u8]) -> Vec<u8> {
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

pub fn read_request(file_id: FileId, offset: u64, length: u32) -> Vec<u8> {
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

pub fn flush_request(file_id: FileId) -> Vec<u8> {
    let mut out = Vec::new();
    put_u16(&mut out, 24);
    put_u16(&mut out, 0);
    put_u32(&mut out, 0);
    out.extend_from_slice(&file_id);
    out
}

pub fn close_request(file_id: FileId) -> Vec<u8> {
    let mut out = Vec::new();
    put_u16(&mut out, 24);
    put_u16(&mut out, CloseRequest::POSTQUERY_ATTRIB);
    put_u32(&mut out, 0);
    out.extend_from_slice(&file_id);
    out
}

pub fn query_directory_request(file_id: FileId, info_class: u8) -> Vec<u8> {
    query_directory_request_flags(file_id, info_class, QueryDirectoryRequest::RESTART_SCANS)
}

pub fn query_directory_request_flags(file_id: FileId, info_class: u8, flags: u8) -> Vec<u8> {
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

pub fn query_info_request(file_id: FileId, info_type: u8, info_class: u8) -> Vec<u8> {
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


pub fn created_file_id(body: &[u8]) -> FileId {
    body[64..80].try_into().unwrap()
}

pub fn created_action(body: &[u8]) -> u32 {
    u32::from_le_bytes(body[4..8].try_into().unwrap())
}

pub fn read_data(body: &[u8]) -> &[u8] {
    &body[16..]
}

pub fn closed_eof(body: &[u8]) -> u64 {
    u64::from_le_bytes(body[48..56].try_into().unwrap())
}

pub fn directory_names(query_body: &[u8], name_offset: usize) -> Vec<String> {
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

pub struct Reply {
    pub status: u32,
    pub body: Vec<u8>,
}


#[derive(Debug)]
pub enum ClientError {
    Io(std::io::Error),
    BadSignature,
    Closed,
}

impl From<std::io::Error> for ClientError {
    fn from(error: std::io::Error) -> ClientError {
        ClientError::Io(error)
    }
}

pub struct TcpSmbClient {
    stream: std::net::TcpStream,
    preauth: [u8; 64],
    signing_key: Option<[u8; 16]>,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
}

impl TcpSmbClient {
    pub fn connect(
        addr: std::net::SocketAddr,
        user: &str,
        password: &str,
        share: &str,
        timeout: std::time::Duration,
    ) -> Result<TcpSmbClient, ClientError> {
        let stream = std::net::TcpStream::connect_timeout(&addr, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        stream.set_nodelay(true)?;
        let mut client = TcpSmbClient {
            stream,
            preauth: [0u8; 64],
            signing_key: None,
            message_id: 0,
            session_id: 0,
            tree_id: 0,
        };
        client.handshake(user, password)?;
        client.tree_connect(share)?;
        Ok(client)
    }

    fn handshake(&mut self, user: &str, password: &str) -> Result<(), ClientError> {
        let neg = self.exchange(wire::command::NEGOTIATE, &negotiate_request(), Fold::Yes)?;
        if neg.status != wire::status::SUCCESS {
            return Err(ClientError::Closed);
        }
        let step1 = self.exchange(
            wire::command::SESSION_SETUP,
            &session_setup_request(&ntlmssp_negotiate()),
            Fold::Yes,
        )?;
        if step1.status != wire::status::MORE_PROCESSING_REQUIRED {
            return Err(ClientError::Closed);
        }
        let challenge = server_challenge_from(&step1.body);
        let session_key = ntlmv2_session_key(user, "", password, challenge);
        let auth = session_setup_request(&ntlmssp_authenticate(user, "", password, challenge));
        self.send_message(wire::command::SESSION_SETUP, &auth, Fold::Yes)?;
        self.signing_key = Some(smb3_signing_key(&session_key, &self.preauth));
        let reply = self.read_reply(Fold::No)?;
        if reply.status != wire::status::SUCCESS {
            return Err(ClientError::Closed);
        }
        Ok(())
    }

    fn tree_connect(&mut self, share: &str) -> Result<(), ClientError> {
        let path = format!("\\\\scalefs\\{share}");
        let reply = self.exchange(
            wire::command::TREE_CONNECT,
            &tree_connect_request(&path),
            Fold::No,
        )?;
        if reply.status != wire::status::SUCCESS {
            return Err(ClientError::Closed);
        }
        Ok(())
    }

    fn exchange(&mut self, command: u16, body: &[u8], fold: Fold) -> Result<Reply, ClientError> {
        self.send_message(command, body, fold)?;
        self.read_reply(fold)
    }

    fn send_message(&mut self, command: u16, body: &[u8], fold: Fold) -> Result<(), ClientError> {
        let mut header = wire::Header {
            command,
            message_id: self.message_id,
            credits: 1,
            session_id: self.session_id,
            tree_id: self.tree_id,
            ..wire::Header::default()
        };
        if self.signing_key.is_some() {
            header.flags |= wire::flags::SIGNED;
        }
        self.message_id += 1;

        let mut message = Vec::new();
        header.encode(&mut message);
        message.extend_from_slice(body);
        if let Some(key) = self.signing_key {
            sign::sign(&mut message, &key);
        }
        if matches!(fold, Fold::Yes) {
            fold_preauth(&mut self.preauth, &message);
        }
        self.write_framed(&message)?;
        Ok(())
    }

    fn read_reply(&mut self, fold: Fold) -> Result<Reply, ClientError> {
        let message = self.read_framed()?;
        if message.len() < wire::HEADER_LEN {
            return Err(ClientError::Closed);
        }
        let reply_flags = u32::from_le_bytes(message[16..20].try_into().unwrap());
        if reply_flags & wire::flags::SIGNED != 0 {
            let key = self.signing_key.ok_or(ClientError::BadSignature)?;
            if !sign::verify(&message, &key) {
                return Err(ClientError::BadSignature);
            }
        }
        if matches!(fold, Fold::Yes) {
            fold_preauth(&mut self.preauth, &message);
        }
        Ok(Reply {
            status: u32::from_le_bytes(message[8..12].try_into().unwrap()),
            body: message[wire::HEADER_LEN..].to_vec(),
        })
    }

    fn write_framed(&mut self, message: &[u8]) -> Result<(), ClientError> {
        use std::io::Write;
        self.stream
            .write_all(&wire::transport_header(message.len()))?;
        self.stream.write_all(message)?;
        self.stream.flush()?;
        Ok(())
    }

    fn read_framed(&mut self) -> Result<Vec<u8>, ClientError> {
        use std::io::Read;
        let mut header = [0u8; 4];
        self.stream.read_exact(&mut header)?;
        let len = wire::parse_transport_header(&header).map_err(|_| ClientError::Closed)?;
        if len == 0 || len > (2 << 20) {
            return Err(ClientError::Closed);
        }
        let mut message = vec![0u8; len];
        self.stream.read_exact(&mut message)?;
        Ok(message)
    }


    pub fn create(&mut self, path: &str) -> Result<FileId, ClientError> {
        let body = create_request(
            path,
            super::fileops::disposition::OPEN_IF,
            super::fileops::options::NON_DIRECTORY_FILE,
        );
        let reply = self.exchange(wire::command::CREATE, &body, Fold::No)?;
        if reply.status != wire::status::SUCCESS {
            return Err(ClientError::Closed);
        }
        Ok(created_file_id(&reply.body))
    }

    pub fn write(&mut self, file: FileId, offset: u64, data: &[u8]) -> Result<u32, ClientError> {
        let reply = self.exchange(
            wire::command::WRITE,
            &write_request(file, offset, data),
            Fold::No,
        )?;
        if reply.status != wire::status::SUCCESS {
            return Err(ClientError::Closed);
        }
        Ok(u32::from_le_bytes(reply.body[4..8].try_into().unwrap()))
    }

    pub fn read(&mut self, file: FileId, offset: u64, length: u32) -> Result<Vec<u8>, ClientError> {
        let reply = self.exchange(
            wire::command::READ,
            &read_request(file, offset, length),
            Fold::No,
        )?;
        if reply.status != wire::status::SUCCESS {
            return Err(ClientError::Closed);
        }
        Ok(read_data(&reply.body).to_vec())
    }

    pub fn flush(&mut self, file: FileId) -> Result<(), ClientError> {
        let reply = self.exchange(wire::command::FLUSH, &flush_request(file), Fold::No)?;
        if reply.status != wire::status::SUCCESS {
            return Err(ClientError::Closed);
        }
        Ok(())
    }

    pub fn close(&mut self, file: FileId) -> Result<(), ClientError> {
        let reply = self.exchange(wire::command::CLOSE, &close_request(file), Fold::No)?;
        if reply.status != wire::status::SUCCESS {
            return Err(ClientError::Closed);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Fold {
    Yes,
    No,
}

fn fold_preauth(preauth: &mut [u8; 64], message: &[u8]) {
    fold(preauth, message);
}
