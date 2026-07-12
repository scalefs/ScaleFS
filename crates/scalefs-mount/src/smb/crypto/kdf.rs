
use super::sha256::hmac_sha256;

pub fn sp800_108_counter(key: &[u8], label: &[u8], context: &[u8], out_bits: u32) -> Vec<u8> {
    let out_bytes = (out_bits as usize).div_ceil(8);
    let mut output = Vec::with_capacity(out_bytes);
    let mut counter: u32 = 1;
    while output.len() < out_bytes {
        let mut input = Vec::with_capacity(4 + label.len() + 1 + context.len() + 4);
        input.extend_from_slice(&counter.to_be_bytes());
        input.extend_from_slice(label);
        input.push(0x00);
        input.extend_from_slice(context);
        input.extend_from_slice(&out_bits.to_be_bytes());
        output.extend_from_slice(&hmac_sha256(key, &input));
        counter += 1;
    }
    output.truncate(out_bytes);
    output
}

pub fn smb3_signing_key(session_key: &[u8], preauth_hash: &[u8]) -> [u8; 16] {
    let derived = sp800_108_counter(session_key, b"SMBSigningKey\0", preauth_hash, 128);
    let mut key = [0u8; 16];
    key.copy_from_slice(&derived[..16]);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_kdf_matches_the_manual_block() {
        let key = b"0123456789abcdef";
        let label = b"SMBSigningKey\0";
        let context = &[0xAAu8; 64];
        let derived = sp800_108_counter(key, label, context, 128);
        assert_eq!(derived.len(), 16);

        let mut input = Vec::new();
        input.extend_from_slice(&1u32.to_be_bytes());
        input.extend_from_slice(label);
        input.push(0x00);
        input.extend_from_slice(context);
        input.extend_from_slice(&128u32.to_be_bytes());
        let expected = &super::super::sha256::hmac_sha256(key, &input)[..16];
        assert_eq!(derived, expected);
    }

    #[test]
    fn counter_kdf_spans_two_blocks() {
        let derived = sp800_108_counter(b"key", b"label\0", &[0u8; 8], 256);
        assert_eq!(derived.len(), 32);
        assert_ne!(derived[..16], derived[16..]);
        let smaller = sp800_108_counter(b"key", b"label\0", &[0u8; 8], 128);
        assert_ne!(derived[..16], smaller[..]);
    }

    #[test]
    fn signing_key_is_128_bits_and_deterministic() {
        let session = [0x11u8; 16];
        let preauth = [0x22u8; 64];
        let a = smb3_signing_key(&session, &preauth);
        let b = smb3_signing_key(&session, &preauth);
        assert_eq!(a, b);
        let c = smb3_signing_key(&session, &[0x23u8; 64]);
        assert_ne!(a, c, "the preauth hash is bound into the key");
    }
}
