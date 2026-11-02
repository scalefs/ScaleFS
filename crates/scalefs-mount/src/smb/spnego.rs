const NTLMSSP_OID: [u8; 10] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];

const SPNEGO_OID: [u8; 6] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

fn der_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = (len as u64).to_be_bytes();
        let first = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let significant = &bytes[first..];
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
}

fn der_element(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    out.push(tag);
    der_len(out, value.len());
    out.extend_from_slice(value);
}

fn der_read(bytes: &[u8], pos: usize) -> Option<(u8, &[u8], usize)> {
    let tag = *bytes.get(pos)?;
    let len_byte = *bytes.get(pos + 1)?;
    let (len, header) = if len_byte < 0x80 {
        (len_byte as usize, 2)
    } else {
        let n = (len_byte & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *bytes.get(pos + 2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let start = pos + header;
    let end = start.checked_add(len)?;
    let value = bytes.get(start..end)?;
    Some((tag, value, end))
}

pub fn negotiate_security_buffer() -> Vec<u8> {
    let mut oid = Vec::new();
    der_element(&mut oid, 0x06, &NTLMSSP_OID);
    let mut mech_types = Vec::new();
    der_element(&mut mech_types, 0x30, &oid);
    let mut ctx0 = Vec::new();
    der_element(&mut ctx0, 0xA0, &mech_types);
    let mut neg_token_init = Vec::new();
    der_element(&mut neg_token_init, 0x30, &ctx0);
    let mut choice = Vec::new();
    der_element(&mut choice, 0xA0, &neg_token_init);
    let mut inner = Vec::new();
    der_element(&mut inner, 0x06, &SPNEGO_OID);
    inner.extend_from_slice(&choice);
    let mut out = Vec::new();
    der_element(&mut out, 0x60, &inner);
    out
}

pub fn challenge_security_buffer(ntlm_challenge: &[u8]) -> Vec<u8> {
    let mut neg_state = Vec::new();
    der_element(&mut neg_state, 0x0a, &[0x01]);
    let mut ctx0 = Vec::new();
    der_element(&mut ctx0, 0xA0, &neg_state);
    let mut oid = Vec::new();
    der_element(&mut oid, 0x06, &NTLMSSP_OID);
    let mut ctx1 = Vec::new();
    der_element(&mut ctx1, 0xA1, &oid);
    let mut token = Vec::new();
    der_element(&mut token, 0x04, ntlm_challenge);
    let mut ctx2 = Vec::new();
    der_element(&mut ctx2, 0xA2, &token);
    let mut seq = Vec::new();
    seq.extend_from_slice(&ctx0);
    seq.extend_from_slice(&ctx1);
    seq.extend_from_slice(&ctx2);
    let mut neg_token_resp = Vec::new();
    der_element(&mut neg_token_resp, 0x30, &seq);
    let mut out = Vec::new();
    der_element(&mut out, 0xA1, &neg_token_resp);
    out
}

pub fn accept_complete_buffer() -> Vec<u8> {
    let mut neg_state = Vec::new();
    der_element(&mut neg_state, 0x0a, &[0x00]);
    let mut ctx0 = Vec::new();
    der_element(&mut ctx0, 0xA0, &neg_state);
    let mut neg_token_resp = Vec::new();
    der_element(&mut neg_token_resp, 0x30, &ctx0);
    let mut out = Vec::new();
    der_element(&mut out, 0xA1, &neg_token_resp);
    out
}

pub fn extract_ntlmssp(security_buffer: &[u8]) -> Option<Vec<u8>> {
    if security_buffer.starts_with(b"NTLMSSP\0") {
        return Some(security_buffer.to_vec());
    }
    find_ntlmssp_octet(security_buffer, 0)
}

fn find_ntlmssp_octet(bytes: &[u8], depth: usize) -> Option<Vec<u8>> {
    if depth > 8 {
        return None;
    }
    let mut pos = 0;
    while pos < bytes.len() {
        let (tag, value, next) = der_read(bytes, pos)?;
        if value.starts_with(b"NTLMSSP\0") {
            return Some(value.to_vec());
        }
        if tag & 0x20 != 0
            && let Some(found) = find_ntlmssp_octet(value, depth + 1)
        {
            return Some(found);
        }
        if next <= pos {
            break;
        }
        pos = next;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_buffer_advertises_ntlm() {
        let buffer = negotiate_security_buffer();
        assert_eq!(buffer[0], 0x60);
        assert!(
            buffer.windows(NTLMSSP_OID.len()).any(|w| w == NTLMSSP_OID),
            "NTLM OID present"
        );
        let (_, value, end) = der_read(&buffer, 0).unwrap();
        assert_eq!(end, buffer.len());
        assert!(!value.is_empty());
    }

    #[test]
    fn challenge_buffer_round_trips_the_token() {
        let ntlm = b"NTLMSSP\0\x02\x00\x00\x00 the challenge bytes";
        let buffer = challenge_security_buffer(ntlm);
        assert_eq!(buffer[0], 0xA1, "negTokenResp");
        let recovered = extract_ntlmssp(&buffer).unwrap();
        assert_eq!(recovered, ntlm);
    }

    #[test]
    fn extract_from_neg_token_init() {
        let ntlm = b"NTLMSSP\0\x01\x00\x00\x00 negotiate";
        let mut mech_types_oid = Vec::new();
        der_element(&mut mech_types_oid, 0x06, &NTLMSSP_OID);
        let mut mech_types_seq = Vec::new();
        der_element(&mut mech_types_seq, 0x30, &mech_types_oid);
        let mut ctx0 = Vec::new();
        der_element(&mut ctx0, 0xA0, &mech_types_seq);
        let mut token = Vec::new();
        der_element(&mut token, 0x04, ntlm);
        let mut ctx2 = Vec::new();
        der_element(&mut ctx2, 0xA2, &token);
        let mut inner_seq = Vec::new();
        inner_seq.extend_from_slice(&ctx0);
        inner_seq.extend_from_slice(&ctx2);
        let mut seq = Vec::new();
        der_element(&mut seq, 0x30, &inner_seq);
        let mut choice = Vec::new();
        der_element(&mut choice, 0xA0, &seq);
        let mut app_inner = Vec::new();
        der_element(&mut app_inner, 0x06, &SPNEGO_OID);
        app_inner.extend_from_slice(&choice);
        let mut buffer = Vec::new();
        der_element(&mut buffer, 0x60, &app_inner);

        let recovered = extract_ntlmssp(&buffer).unwrap();
        assert_eq!(recovered, ntlm);
    }

    #[test]
    fn extract_tolerates_raw_ntlmssp() {
        let ntlm = b"NTLMSSP\0\x03\x00\x00\x00 authenticate".to_vec();
        assert_eq!(extract_ntlmssp(&ntlm).unwrap(), ntlm);
    }

    #[test]
    fn extract_refuses_junk() {
        assert!(extract_ntlmssp(&[]).is_none());
        assert!(extract_ntlmssp(&[0x30, 0x80]).is_none());
        assert!(extract_ntlmssp(b"no token here at all").is_none());
        assert!(extract_ntlmssp(&[0xA1, 0x03, 0x04, 0x01, 0x00]).is_none());
    }

    #[test]
    fn der_lengths_round_trip() {
        for len in [0usize, 1, 127, 128, 255, 256, 300, 65535, 70000] {
            let mut out = Vec::new();
            der_element(&mut out, 0x04, &vec![0xAB; len]);
            let (tag, value, end) = der_read(&out, 0).unwrap();
            assert_eq!(tag, 0x04);
            assert_eq!(value.len(), len);
            assert_eq!(end, out.len());
        }
    }
}
