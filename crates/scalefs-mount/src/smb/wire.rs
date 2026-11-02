use scalefs_core::error::{Result, ScaleFsError};
use scalefs_core::wire::{Cursor, put_u16, put_u32, put_u64};

pub const SMB2_MAGIC: [u8; 4] = [0xFE, b'S', b'M', b'B'];
pub const DIALECT_311: u16 = 0x0311;
pub const HEADER_LEN: usize = 64;

pub mod command {
    pub const NEGOTIATE: u16 = 0x0000;
    pub const SESSION_SETUP: u16 = 0x0001;
    pub const LOGOFF: u16 = 0x0002;
    pub const TREE_CONNECT: u16 = 0x0003;
    pub const TREE_DISCONNECT: u16 = 0x0004;
    pub const CREATE: u16 = 0x0005;
    pub const CLOSE: u16 = 0x0006;
    pub const FLUSH: u16 = 0x0007;
    pub const READ: u16 = 0x0008;
    pub const WRITE: u16 = 0x0009;
    pub const QUERY_DIRECTORY: u16 = 0x000E;
    pub const QUERY_INFO: u16 = 0x0010;
    pub const SET_INFO: u16 = 0x0011;
    pub const ECHO: u16 = 0x000D;
}

pub mod status {
    pub const SUCCESS: u32 = 0x0000_0000;
    pub const PENDING: u32 = 0x0000_0103;
    pub const NOTIFY_ENUM_DIR: u32 = 0x0000_010C;
    pub const NO_MORE_FILES: u32 = 0x8000_0006;
    pub const NO_SUCH_FILE: u32 = 0xC000_000F;
    pub const END_OF_FILE: u32 = 0xC000_0011;
    pub const INVALID_PARAMETER: u32 = 0xC000_000D;
    pub const NOT_SUPPORTED: u32 = 0xC000_00BB;
    pub const ACCESS_DENIED: u32 = 0xC000_0022;
    pub const OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
    pub const OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
    pub const OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
    pub const OBJECT_NAME_INVALID: u32 = 0xC000_0033;
    pub const NAME_TOO_LONG: u32 = 0xC000_0106;
    pub const FILE_CLOSED: u32 = 0xC000_0128;
    pub const LOGON_FAILURE: u32 = 0xC000_006D;
    pub const MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
    pub const FILE_IS_A_DIRECTORY: u32 = 0xC000_00BA;
    pub const NOT_A_DIRECTORY: u32 = 0xC000_0103;
    pub const DIRECTORY_NOT_EMPTY: u32 = 0xC000_0101;
    pub const DISK_FULL: u32 = 0xC000_007F;
    pub const TOO_MANY_LINKS: u32 = 0xC000_0265;
    pub const DELETE_PENDING: u32 = 0xC000_0056;
    pub const USER_SESSION_DELETED: u32 = 0xC000_00DF;
    pub const NETWORK_NAME_DELETED: u32 = 0xC000_00C9;
    pub const BAD_NETWORK_NAME: u32 = 0xC000_00CC;
    pub const INTERNAL_ERROR: u32 = 0xC000_00E5;
}

pub mod flags {
    pub const SERVER_TO_REDIR: u32 = 0x0000_0001;
    pub const ASYNC_COMMAND: u32 = 0x0000_0002;
    pub const RELATED_OPERATIONS: u32 = 0x0000_0004;
    pub const SIGNED: u32 = 0x0000_0008;
}

pub const SIGNATURE_OFFSET: usize = 48;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Header {
    pub credit_charge: u16,
    pub status: u32,
    pub command: u16,
    pub credits: u16,
    pub flags: u32,
    pub next_command: u32,
    pub message_id: u64,
    pub tree_id: u32,
    pub session_id: u64,
    pub signature: [u8; 16],
}

impl Header {
    pub fn decode(cursor: &mut Cursor<'_>) -> Result<Header> {
        let magic = cursor.take_array::<4>()?;
        if magic != SMB2_MAGIC {
            return Err(ScaleFsError::Corrupt("not an SMB2 header"));
        }
        let structure_size = cursor.take_u16()?;
        if structure_size != 64 {
            return Err(ScaleFsError::Corrupt("SMB2 header size must be 64"));
        }
        let credit_charge = cursor.take_u16()?;
        let status = cursor.take_u32()?;
        let command = cursor.take_u16()?;
        let credits = cursor.take_u16()?;
        let flags = cursor.take_u32()?;
        let next_command = cursor.take_u32()?;
        let message_id = cursor.take_u64()?;
        cursor.take_u32()?;
        let tree_id = cursor.take_u32()?;
        let session_id = cursor.take_u64()?;
        let signature = cursor.take_array::<16>()?;
        Ok(Header {
            credit_charge,
            status,
            command,
            credits,
            flags,
            next_command,
            message_id,
            tree_id,
            session_id,
            signature,
        })
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&SMB2_MAGIC);
        put_u16(out, 64);
        put_u16(out, self.credit_charge);
        put_u32(out, self.status);
        put_u16(out, self.command);
        put_u16(out, self.credits);
        put_u32(out, self.flags);
        put_u32(out, self.next_command);
        put_u64(out, self.message_id);
        put_u32(out, 0);
        put_u32(out, self.tree_id);
        put_u64(out, self.session_id);
        out.extend_from_slice(&self.signature);
    }
}

pub fn transport_header(message_len: usize) -> [u8; 4] {
    let len = message_len as u32;
    [0, (len >> 16) as u8, (len >> 8) as u8, len as u8]
}

pub fn parse_transport_header(bytes: &[u8; 4]) -> Result<usize> {
    if bytes[0] != 0 {
        return Err(ScaleFsError::Corrupt("transport header must start with 0"));
    }
    Ok(((bytes[1] as usize) << 16) | ((bytes[2] as usize) << 8) | bytes[3] as usize)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiateRequest {
    pub dialects: Vec<u16>,
    pub client_guid: [u8; 16],
    pub preauth_offered: bool,
    pub client_salt: Vec<u8>,
}

impl NegotiateRequest {
    pub fn decode(body: &[u8]) -> Result<NegotiateRequest> {
        let mut cursor = Cursor::new(body);
        let structure_size = cursor.take_u16()?;
        if structure_size != 36 {
            return Err(ScaleFsError::Corrupt("negotiate structure size"));
        }
        let dialect_count = cursor.take_u16()? as usize;
        if dialect_count == 0 || dialect_count > 64 {
            return Err(ScaleFsError::Corrupt("implausible dialect count"));
        }
        cursor.take_u16()?;
        cursor.take_u16()?;
        cursor.take_u32()?;
        let client_guid = cursor.take_array::<16>()?;
        let context_offset = cursor.take_u32()? as usize;
        let context_count = cursor.take_u16()? as usize;
        cursor.take_u16()?;
        let mut dialects = Vec::with_capacity(dialect_count);
        for _ in 0..dialect_count {
            dialects.push(cursor.take_u16()?);
        }

        let mut preauth_offered = false;
        let mut client_salt = Vec::new();
        if dialects.contains(&DIALECT_311) && context_offset >= HEADER_LEN {
            let mut at = context_offset - HEADER_LEN;
            for _ in 0..context_count {
                if at + 8 > body.len() {
                    break;
                }
                let ctype = u16::from_le_bytes([body[at], body[at + 1]]);
                let dlen = u16::from_le_bytes([body[at + 2], body[at + 3]]) as usize;
                let data_start = at + 8;
                let data_end = data_start + dlen;
                if data_end > body.len() {
                    break;
                }
                let data = &body[data_start..data_end];
                if ctype == 0x0001 && data.len() >= 6 {
                    let hash_count = u16::from_le_bytes([data[0], data[1]]) as usize;
                    let salt_len = u16::from_le_bytes([data[2], data[3]]) as usize;
                    let mut offers_sha512 = false;
                    for h in 0..hash_count {
                        let o = 4 + h * 2;
                        if o + 2 <= data.len()
                            && u16::from_le_bytes([data[o], data[o + 1]]) == 0x0001
                        {
                            offers_sha512 = true;
                        }
                    }
                    let salt_start = 4 + hash_count * 2;
                    if offers_sha512 && salt_start + salt_len <= data.len() {
                        preauth_offered = true;
                        client_salt = data[salt_start..salt_start + salt_len].to_vec();
                    }
                }
                at = data_end.div_ceil(8) * 8;
            }
        }

        Ok(NegotiateRequest {
            dialects,
            client_guid,
            preauth_offered,
            client_salt,
        })
    }
}

pub struct NegotiateResponse<'a> {
    pub server_guid: [u8; 16],
    pub server_salt: &'a [u8],
    pub security_buffer: &'a [u8],
    pub system_time: u64,
}

impl NegotiateResponse<'_> {
    pub fn encode(&self, out: &mut Vec<u8>) {
        let sec_offset = HEADER_LEN as u16 + 64;
        put_u16(out, 65);
        put_u16(out, 0x0003);
        put_u16(out, DIALECT_311);
        put_u16(out, 1);
        out.extend_from_slice(&self.server_guid);
        put_u32(out, 0);
        put_u32(out, 1 << 20);
        put_u32(out, 1 << 20);
        put_u32(out, 1 << 20);
        put_u64(out, self.system_time);
        put_u64(out, 0);
        put_u16(out, sec_offset);
        put_u16(out, self.security_buffer.len() as u16);
        let after_sec = usize::from(sec_offset) + self.security_buffer.len();
        let ctx_offset = after_sec.div_ceil(8) * 8;
        put_u32(out, ctx_offset as u32);
        out.extend_from_slice(self.security_buffer);
        while (out.len() + HEADER_LEN) < ctx_offset {
            out.push(0);
        }
        encode_preauth_context(out, self.server_salt);
    }
}

fn encode_preauth_context(out: &mut Vec<u8>, salt: &[u8]) {
    let data_len = 4 + 2 + salt.len();
    put_u16(out, 0x0001);
    put_u16(out, data_len as u16);
    put_u32(out, 0);
    put_u16(out, 1);
    put_u16(out, salt.len() as u16);
    put_u16(out, 0x0001);
    out.extend_from_slice(salt);
}

pub fn wildcard_negotiate_body(
    server_guid: [u8; 16],
    system_time: u64,
    security_buffer: &[u8],
) -> Vec<u8> {
    let sec_offset = HEADER_LEN as u16 + 64;
    let mut out = Vec::new();
    put_u16(&mut out, 65);
    put_u16(&mut out, 0x0001);
    put_u16(&mut out, 0x02FF);
    put_u16(&mut out, 0);
    out.extend_from_slice(&server_guid);
    put_u32(&mut out, 0x0000_0004);
    put_u32(&mut out, 1 << 20);
    put_u32(&mut out, 1 << 20);
    put_u32(&mut out, 1 << 20);
    put_u64(&mut out, system_time);
    put_u64(&mut out, 0);
    put_u16(&mut out, sec_offset);
    put_u16(&mut out, security_buffer.len() as u16);
    put_u32(&mut out, 0);
    out.extend_from_slice(security_buffer);
    out
}

pub fn to_utf16le(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() * 2);
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

pub fn from_utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

pub fn frame_message(header: &Header, body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(HEADER_LEN + body.len());
    header.encode(&mut message);
    message.extend_from_slice(body);
    let mut framed = Vec::with_capacity(4 + message.len());
    framed.extend_from_slice(&transport_header(message.len()));
    framed.extend_from_slice(&message);
    framed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn header_round_trips() {
        let header = Header {
            credit_charge: 1,
            status: status::SUCCESS,
            command: command::NEGOTIATE,
            credits: 1,
            flags: flags::SERVER_TO_REDIR | flags::SIGNED,
            next_command: 0,
            message_id: 0x1122_3344,
            tree_id: 5,
            session_id: 0xAABB,
            signature: [0x11; 16],
        };
        let mut bytes = Vec::new();
        header.encode(&mut bytes);
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(&bytes[0..4], &SMB2_MAGIC);
        assert_eq!(hex(&bytes[4..6]), "4000");
        assert_eq!(hex(&bytes[12..14]), "0000");
        assert_eq!(&bytes[SIGNATURE_OFFSET..], &[0x11; 16]);
        let decoded = Header::decode(&mut Cursor::new(&bytes)).unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    fn header_rejects_garbage() {
        let mut bad = vec![0u8; HEADER_LEN];
        assert!(Header::decode(&mut Cursor::new(&bad)).is_err());
        bad[0..4].copy_from_slice(&SMB2_MAGIC);
        assert!(Header::decode(&mut Cursor::new(&bad)).is_err());
        assert!(Header::decode(&mut Cursor::new(&[0u8; 10])).is_err());
    }

    #[test]
    fn transport_header_is_big_endian_24_bit() {
        assert_eq!(transport_header(0x010203), [0x00, 0x01, 0x02, 0x03]);
        assert_eq!(
            parse_transport_header(&[0x00, 0x01, 0x02, 0x03]).unwrap(),
            0x010203
        );
        assert!(parse_transport_header(&[0x01, 0, 0, 0]).is_err());
    }

    #[test]
    fn negotiate_request_decodes_with_preauth() {
        let salt = [0x5Au8; 32];
        let mut body = Vec::new();
        put_u16(&mut body, 36);
        put_u16(&mut body, 2);
        put_u16(&mut body, 0x0001);
        put_u16(&mut body, 0);
        put_u32(&mut body, 0);
        body.extend_from_slice(&[0x77; 16]);
        let dialects_len = 4usize;
        let ctx_from_header = HEADER_LEN + 36 + dialects_len;
        let ctx_aligned = ctx_from_header.div_ceil(8) * 8;
        put_u32(&mut body, ctx_aligned as u32);
        put_u16(&mut body, 1);
        put_u16(&mut body, 0);
        put_u16(&mut body, DIALECT_311);
        put_u16(&mut body, 0x0302);
        while body.len() + HEADER_LEN < ctx_aligned {
            body.push(0);
        }
        put_u16(&mut body, 0x0001);
        put_u16(&mut body, (4 + 2 + salt.len()) as u16);
        put_u32(&mut body, 0);
        put_u16(&mut body, 1);
        put_u16(&mut body, salt.len() as u16);
        put_u16(&mut body, 0x0001);
        body.extend_from_slice(&salt);

        let request = NegotiateRequest::decode(&body).unwrap();
        assert_eq!(request.dialects, vec![DIALECT_311, 0x0302]);
        assert_eq!(request.client_guid, [0x77; 16]);
        assert!(request.preauth_offered);
        assert_eq!(request.client_salt, salt);
    }

    #[test]
    fn negotiate_response_is_well_formed() {
        let response = NegotiateResponse {
            server_guid: [0xAB; 16],
            server_salt: &[0x11; 32],
            security_buffer: &[0x60, 0x06, 0x06, 0x2b],
            system_time: 0x01D9_0000_0000_0000,
        };
        let mut body = Vec::new();
        response.encode(&mut body);
        assert_eq!(hex(&body[0..2]), "4100");
        assert_eq!(hex(&body[2..4]), "0300");
        assert_eq!(hex(&body[4..6]), "1103");
        let sec_offset = u16::from_le_bytes([body[56], body[57]]);
        assert!(usize::from(sec_offset) >= HEADER_LEN);

        let ctx_offset = u32::from_le_bytes([body[60], body[61], body[62], body[63]]) as usize;
        assert_eq!(ctx_offset % 8, 0);
        assert!(ctx_offset - HEADER_LEN <= body.len());
        let at = ctx_offset - HEADER_LEN;
        assert_eq!(u16::from_le_bytes([body[at], body[at + 1]]), 0x0001);
    }

    #[test]
    fn utf16_round_trips() {
        let name = "vault";
        let encoded = to_utf16le(name);
        assert_eq!(encoded, [0x76, 0, 0x61, 0, 0x75, 0, 0x6c, 0, 0x74, 0]);
        assert_eq!(from_utf16le(&encoded), name);
        assert_eq!(from_utf16le(&to_utf16le("dir\\file.txt")), "dir\\file.txt");
    }

    #[test]
    fn framing_prefixes_the_length() {
        let header = Header {
            command: command::ECHO,
            ..Header::default()
        };
        let framed = frame_message(&header, &[0xAA, 0xBB]);
        assert_eq!(&framed[0..4], &[0, 0, 0, (HEADER_LEN + 2) as u8]);
        assert_eq!(
            parse_transport_header(&[framed[0], framed[1], framed[2], framed[3]]).unwrap(),
            HEADER_LEN + 2
        );
        assert_eq!(framed.len(), 4 + HEADER_LEN + 2);
    }
}
