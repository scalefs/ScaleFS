use super::crypto::aes::aes128_cmac;
use super::crypto::ct_eq;
use super::wire::{HEADER_LEN, SIGNATURE_OFFSET, flags};

const SIGNATURE_RANGE: std::ops::Range<usize> = SIGNATURE_OFFSET..SIGNATURE_OFFSET + 16;

pub fn sign(message: &mut [u8], signing_key: &[u8; 16]) {
    if message.len() < HEADER_LEN {
        return;
    }
    for byte in &mut message[SIGNATURE_RANGE] {
        *byte = 0;
    }
    let mac = aes128_cmac(signing_key, message);
    message[SIGNATURE_RANGE].copy_from_slice(&mac);
}

pub fn verify(message: &[u8], signing_key: &[u8; 16]) -> bool {
    if message.len() < HEADER_LEN {
        return false;
    }
    let header_flags = u32::from_le_bytes([message[16], message[17], message[18], message[19]]);
    if header_flags & flags::SIGNED == 0 {
        return false;
    }
    let mut claimed = [0u8; 16];
    claimed.copy_from_slice(&message[SIGNATURE_RANGE]);
    let mut scratch = message.to_vec();
    for byte in &mut scratch[SIGNATURE_RANGE] {
        *byte = 0;
    }
    let mac = aes128_cmac(signing_key, &scratch);
    ct_eq(&mac, &claimed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smb::wire::{Header, command, status};

    fn signed_message(key: &[u8; 16]) -> Vec<u8> {
        let header = Header {
            command: command::TREE_CONNECT,
            status: status::SUCCESS,
            flags: flags::SERVER_TO_REDIR | flags::SIGNED,
            message_id: 7,
            session_id: 0x99,
            ..Header::default()
        };
        let mut message = Vec::new();
        header.encode(&mut message);
        message.extend_from_slice(&[0xCD; 24]);
        sign(&mut message, key);
        message
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let key = [0x40u8; 16];
        let message = signed_message(&key);
        assert!(verify(&message, &key));
        assert_ne!(&message[SIGNATURE_RANGE], &[0u8; 16]);
    }

    #[test]
    fn a_tampered_body_fails_verification() {
        let key = [0x40u8; 16];
        let mut message = signed_message(&key);
        let last = message.len() - 1;
        message[last] ^= 0x01;
        assert!(!verify(&message, &key));
    }

    #[test]
    fn a_wrong_key_fails_verification() {
        let key = [0x40u8; 16];
        let message = signed_message(&key);
        assert!(!verify(&message, &[0x41u8; 16]));
    }

    #[test]
    fn an_unsigned_message_is_not_accepted() {
        let key = [0x40u8; 16];
        let header = Header {
            command: command::ECHO,
            flags: flags::SERVER_TO_REDIR,
            ..Header::default()
        };
        let mut message = Vec::new();
        header.encode(&mut message);
        message.extend_from_slice(&[0u8; 8]);
        assert!(!verify(&message, &key));
    }

    #[test]
    fn signing_covers_the_flags() {
        let key = [0x7Fu8; 16];
        let a = signed_message(&key);
        let mut b = a.clone();
        let f = u32::from_le_bytes([b[16], b[17], b[18], b[19]]) & !flags::SIGNED;
        b[16..20].copy_from_slice(&f.to_le_bytes());
        assert!(!verify(&b, &key));
    }
}
