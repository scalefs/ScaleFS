
pub mod aes;
pub mod kdf;
pub mod md4;
pub mod md5;
pub mod rc4;
pub mod sha256;
pub mod sha512;

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::ct_eq;

    #[test]
    fn ct_eq_compares() {
        assert!(ct_eq(b"same bytes", b"same bytes"));
        assert!(!ct_eq(b"same bytes", b"same byteZ"));
        assert!(!ct_eq(b"short", b"longer than"));
        assert!(ct_eq(b"", b""));
    }
}
