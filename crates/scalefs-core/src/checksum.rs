
pub fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = Crc32c::new();
    crc.update(bytes);
    crc.finalize()
}

#[derive(Debug, Clone)]
pub struct Crc32c {
    state: u32,
}

impl Crc32c {
    pub fn new() -> Self {
        Self { state: 0xFFFF_FFFF }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.state = update(self.state, bytes);
    }

    pub fn finalize(self) -> u32 {
        self.state ^ 0xFFFF_FFFF
    }
}

impl Default for Crc32c {
    fn default() -> Self {
        Self::new()
    }
}

fn update(state: u32, bytes: &[u8]) -> u32 {
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("sse4.2") {
        return hw::update_sse42(state, bytes);
    }
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("crc") {
        return hw::update_aarch64_crc(state, bytes);
    }
    update_sw(state, bytes)
}

const fn build_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

static TABLE: [u32; 256] = build_table();

pub(crate) fn update_sw(state: u32, bytes: &[u8]) -> u32 {
    let mut crc = state;
    for &byte in bytes {
        crc = (crc >> 8) ^ TABLE[((crc ^ u32::from(byte)) & 0xFF) as usize];
    }
    crc
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod hw {
    #![allow(unsafe_code)]

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse4.2")]
    fn update_sse42_impl(state: u32, bytes: &[u8]) -> u32 {
        use std::arch::x86_64::{_mm_crc32_u8, _mm_crc32_u64};
        let mut chunks = bytes.chunks_exact(8);
        let mut crc64 = u64::from(state);
        for chunk in &mut chunks {
            let word = u64::from_le_bytes(chunk.try_into().expect("chunk is 8 bytes"));
            crc64 = _mm_crc32_u64(crc64, word);
        }
        let mut crc = crc64 as u32;
        for &byte in chunks.remainder() {
            crc = _mm_crc32_u8(crc, byte);
        }
        crc
    }

    #[cfg(target_arch = "x86_64")]
    pub(super) fn update_sse42(state: u32, bytes: &[u8]) -> u32 {
        unsafe { update_sse42_impl(state, bytes) }
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "crc")]
    fn update_aarch64_impl(state: u32, bytes: &[u8]) -> u32 {
        use std::arch::aarch64::{__crc32cb, __crc32cd};
        let mut chunks = bytes.chunks_exact(8);
        let mut crc = state;
        for chunk in &mut chunks {
            let word = u64::from_le_bytes(chunk.try_into().expect("chunk is 8 bytes"));
            crc = __crc32cd(crc, word);
        }
        for &byte in chunks.remainder() {
            crc = __crc32cb(crc, byte);
        }
        crc
    }

    #[cfg(target_arch = "aarch64")]
    pub(super) fn update_aarch64_crc(state: u32, bytes: &[u8]) -> u32 {
        unsafe { update_aarch64_impl(state, bytes) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::XorShift64;

    fn crc32c_software_only(bytes: &[u8]) -> u32 {
        update_sw(0xFFFF_FFFF, bytes) ^ 0xFFFF_FFFF
    }

    #[test]
    fn rfc3720_reference_vectors() {
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
        assert_eq!(crc32c(&[0xFFu8; 32]), 0x62A8_AB43);
        let ascending: Vec<u8> = (0..32).collect();
        assert_eq!(crc32c(&ascending), 0x46DD_794E);
        let descending: Vec<u8> = (0..32).rev().collect();
        assert_eq!(crc32c(&descending), 0x113F_DB5C);
    }

    #[test]
    fn common_check_values() {
        assert_eq!(crc32c(b""), 0x0000_0000);
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn software_path_matches_reference_vectors() {
        assert_eq!(crc32c_software_only(&[0u8; 32]), 0x8A91_36AA);
        assert_eq!(crc32c_software_only(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn streaming_matches_one_shot_at_every_split_point() {
        let data: Vec<u8> = (0..=255).collect();
        let expected = crc32c(&data);
        for split in 0..=data.len() {
            let (a, b) = data.split_at(split);
            let mut crc = Crc32c::new();
            crc.update(a);
            crc.update(b);
            assert_eq!(crc.finalize(), expected, "split at {split}");
        }
    }

    #[test]
    fn hardware_and_software_paths_agree_on_random_buffers() {
        let mut rng = XorShift64::new(0x5CA1_EF5C_0DE0_0001);
        for len in [0usize, 1, 7, 8, 9, 63, 64, 65, 4096, 4097] {
            let buf: Vec<u8> = (0..len).map(|_| rng.next_u64() as u8).collect();
            assert_eq!(crc32c(&buf), crc32c_software_only(&buf), "len {len}");
        }
    }
}
