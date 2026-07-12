
use aws_lc_rs::digest;

pub fn sha512(message: &[u8]) -> [u8; 64] {
    let digest = digest::digest(&digest::SHA512, message);
    let mut out = [0u8; 64];
    out.copy_from_slice(digest.as_ref());
    out
}

pub struct Sha512 {
    context: digest::Context,
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha512 {
    pub fn new() -> Sha512 {
        Sha512 {
            context: digest::Context::new(&digest::SHA512),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    pub fn finish(self) -> [u8; 64] {
        let digest = self.context.finish();
        let mut out = [0u8; 64];
        out.copy_from_slice(digest.as_ref());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn fips_180_4_vectors() {
        assert_eq!(
            hex(&sha512(b"")),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
        assert_eq!(
            hex(&sha512(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        assert_eq!(
            hex(&sha512(
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
                  hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
            )),
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
             501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
        );
    }

    #[test]
    fn streaming_matches_one_shot() {
        let data: Vec<u8> = (0..500u32).map(|i| (i % 256) as u8).collect();
        let mut streamed = Sha512::new();
        for chunk in data.chunks(13) {
            streamed.update(chunk);
        }
        assert_eq!(streamed.finish(), sha512(&data));
    }

    #[test]
    fn running_hash_folds() {
        let mut preauth = [0u8; 64];
        for message in [
            b"NEGOTIATE".as_slice(),
            b"SESSION_SETUP_1",
            b"SESSION_SETUP_2",
        ] {
            let mut concat = preauth.to_vec();
            concat.extend_from_slice(message);
            let expected = sha512(&concat);
            let mut h = Sha512::new();
            h.update(&preauth);
            h.update(message);
            preauth = h.finish();
            assert_eq!(preauth, expected);
        }
        assert_ne!(preauth, [0u8; 64], "the hash actually moved");
    }
}
