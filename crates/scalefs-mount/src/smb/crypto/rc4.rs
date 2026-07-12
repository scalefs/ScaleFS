
pub fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: [u8; 256] = [0; 256];
    for (i, byte) in s.iter_mut().enumerate() {
        *byte = i as u8;
    }
    let mut j: usize = 0;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) & 0xff;
        s.swap(i, j);
    }
    let mut out = Vec::with_capacity(data.len());
    let (mut i, mut j) = (0usize, 0usize);
    for &byte in data {
        i = (i + 1) & 0xff;
        j = (j + s[i] as usize) & 0xff;
        s.swap(i, j);
        let k = s[(s[i] as usize + s[j] as usize) & 0xff];
        out.push(byte ^ k);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn rfc6229_keystream_vectors() {
        let key = [0x01, 0x02, 0x03, 0x04, 0x05];
        let stream = rc4(&key, &[0u8; 16]);
        assert_eq!(hex(&stream), "b2396305f03dc027ccc3524a0a1118a8");

        assert_eq!(hex(&rc4(b"Key", b"Plaintext")), "bbf316e8d940af0ad3");
        assert_eq!(hex(&rc4(b"Wiki", b"pedia")), "1021bf0420");
    }

    #[test]
    fn encrypt_then_decrypt_round_trips() {
        let key = b"session-base-key";
        let secret = b"the exported session key........";
        let cipher = rc4(key, secret);
        assert_ne!(cipher, secret);
        assert_eq!(rc4(key, &cipher), secret);
    }
}
