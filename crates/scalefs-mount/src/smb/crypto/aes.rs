use aws_lc_rs::cmac;

pub fn aes128_cmac(key: &[u8; 16], message: &[u8]) -> [u8; 16] {
    let key = cmac::Key::new(cmac::AES_128, key).expect("AES-128 CMAC key");
    let tag = cmac::sign(&key, message).expect("AES-128 CMAC");
    let mut mac = [0u8; 16];
    mac.copy_from_slice(tag.as_ref());
    mac
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn nist_cmac_vectors() {
        let key: [u8; 16] = unhex("2b7e151628aed2a6abf7158809cf4f3c")
            .try_into()
            .unwrap();
        assert_eq!(
            hex(&aes128_cmac(&key, &[])),
            "bb1d6929e95937287fa37d129b756746"
        );
        assert_eq!(
            hex(&aes128_cmac(
                &key,
                &unhex("6bc1bee22e409f96e93d7e117393172a")
            )),
            "070a16b46b4d4144f79bdd9dd04a287c"
        );
        assert_eq!(
            hex(&aes128_cmac(
                &key,
                &unhex(
                    "6bc1bee22e409f96e93d7e117393172a\
                     ae2d8a571e03ac9c9eb76fac45af8e51\
                     30c81c46a35ce411"
                )
            )),
            "dfa66747de9ae63030ca32611497c827"
        );
        assert_eq!(
            hex(&aes128_cmac(
                &key,
                &unhex(
                    "6bc1bee22e409f96e93d7e117393172a\
                     ae2d8a571e03ac9c9eb76fac45af8e51\
                     30c81c46a35ce411e5fbc1191a0a52ef\
                     f69f2445df4f9b17ad2b417be66c3710"
                )
            )),
            "51f0bebf7e3b9d92fc49741779363cfe"
        );
    }
}
