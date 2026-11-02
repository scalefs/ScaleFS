mod tables_17_0_0;

use std::fmt;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnicodeVersion(u32);

impl UnicodeVersion {
    pub const fn new(major: u8, minor: u8, update: u8) -> Self {
        Self((major as u32) << 16 | (minor as u32) << 8 | update as u32)
    }

    pub const fn to_u32(self) -> u32 {
        self.0
    }

    pub const fn from_u32(value: u32) -> Self {
        Self(value)
    }

    pub const fn major(self) -> u8 {
        (self.0 >> 16) as u8
    }

    pub const fn minor(self) -> u8 {
        (self.0 >> 8) as u8
    }

    pub const fn update(self) -> u8 {
        self.0 as u8
    }
}

impl fmt::Display for UnicodeVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major(), self.minor(), self.update())
    }
}

pub const V17_0_0: UnicodeVersion = UnicodeVersion::new(17, 0, 0);

pub const SUPPORTED_UNICODE_VERSIONS: &[UnicodeVersion] = &[V17_0_0];

pub const NEWEST_SUPPORTED_UNICODE_VERSION: UnicodeVersion = V17_0_0;

pub fn is_supported(version: UnicodeVersion) -> bool {
    SUPPORTED_UNICODE_VERSIONS.contains(&version)
}

struct Tables {
    decomp: &'static [(u32, &'static [u32])],
    ccc: &'static [(u32, u8)],
    fold: &'static [(u32, u32)],
}

const TABLES_17_0_0: Tables = Tables {
    decomp: tables_17_0_0::CANONICAL_DECOMP,
    ccc: tables_17_0_0::COMBINING_CLASS,
    fold: tables_17_0_0::SIMPLE_FOLD,
};

fn tables_for(version: UnicodeVersion) -> Option<&'static Tables> {
    if version == V17_0_0 {
        Some(&TABLES_17_0_0)
    } else {
        None
    }
}

fn tables(version: UnicodeVersion) -> &'static Tables {
    tables_for(version)
        .expect("a pool's Unicode version is validated at open before any name is folded")
}

const S_BASE: u32 = 0xAC00;
const L_BASE: u32 = 0x1100;
const V_BASE: u32 = 0x1161;
const T_BASE: u32 = 0x11A7;
const T_COUNT: u32 = 28;
const N_COUNT: u32 = 588;
const S_COUNT: u32 = 11172;

fn scalar(cp: u32) -> char {
    char::from_u32(cp).expect("Unicode table entries and jamo are scalar values")
}

fn decomp_of(t: &Tables, cp: u32) -> Option<&'static [u32]> {
    t.decomp
        .binary_search_by_key(&cp, |&(k, _)| k)
        .ok()
        .map(|i| t.decomp[i].1)
}

fn combining_class(t: &Tables, cp: u32) -> u8 {
    t.ccc
        .binary_search_by_key(&cp, |&(k, _)| k)
        .map(|i| t.ccc[i].1)
        .unwrap_or(0)
}

fn simple_fold_cp(t: &Tables, cp: u32) -> Option<u32> {
    t.fold
        .binary_search_by_key(&cp, |&(k, _)| k)
        .ok()
        .map(|i| t.fold[i].1)
}

fn decompose_char(t: &Tables, c: char, out: &mut Vec<char>) {
    let u = c as u32;
    if (S_BASE..S_BASE + S_COUNT).contains(&u) {
        let s = u - S_BASE;
        out.push(scalar(L_BASE + s / N_COUNT));
        out.push(scalar(V_BASE + (s % N_COUNT) / T_COUNT));
        let t_index = s % T_COUNT;
        if t_index != 0 {
            out.push(scalar(T_BASE + t_index));
        }
        return;
    }
    match decomp_of(t, u) {
        Some(seq) => out.extend(seq.iter().map(|&d| scalar(d))),
        None => out.push(c),
    }
}

fn canonical_order(t: &Tables, chars: &mut [char]) {
    let n = chars.len();
    if n < 2 {
        return;
    }
    let mut i = 1;
    while i < n {
        let ccc_i = combining_class(t, chars[i] as u32);
        if ccc_i != 0 {
            let ccc_prev = combining_class(t, chars[i - 1] as u32);
            if ccc_prev != 0 && ccc_prev > ccc_i {
                chars.swap(i - 1, i);
                if i > 1 {
                    i -= 1;
                    continue;
                }
            }
        }
        i += 1;
    }
}

pub fn nfd(version: UnicodeVersion, s: &str) -> String {
    let t = tables(version);
    let mut chars: Vec<char> = Vec::with_capacity(s.len());
    for c in s.chars() {
        decompose_char(t, c, &mut chars);
    }
    canonical_order(t, &mut chars);
    chars.into_iter().collect()
}

pub fn simple_casefold(version: UnicodeVersion, s: &str) -> String {
    let t = tables(version);
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match simple_fold_cp(t, c as u32) {
            Some(f) => out.push(scalar(f)),
            None => out.push(c),
        }
    }
    out
}

pub fn caseless_key(version: UnicodeVersion, s: &str) -> String {
    nfd(version, &simple_casefold(version, &nfd(version, s)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const V: UnicodeVersion = V17_0_0;

    #[test]
    fn version_packing_and_ordering() {
        assert_eq!(V17_0_0.major(), 17);
        assert_eq!(V17_0_0.minor(), 0);
        assert_eq!(V17_0_0.update(), 0);
        assert_eq!(V17_0_0.to_u32(), 0x0011_0000);
        assert_eq!(UnicodeVersion::from_u32(0x0011_0000), V17_0_0);
        assert_eq!(format!("{V17_0_0}"), "17.0.0");
        assert!(V17_0_0 < UnicodeVersion::new(18, 0, 0));
        assert!(UnicodeVersion::new(16, 0, 0) < UnicodeVersion::new(16, 1, 0));
        assert!(is_supported(V17_0_0));
        assert!(!is_supported(UnicodeVersion::new(18, 0, 0)));
        assert_eq!(NEWEST_SUPPORTED_UNICODE_VERSION, V17_0_0);
    }

    #[test]
    fn nfd_decomposes_precomposed_latin() {
        assert_eq!(nfd(V, "À"), "A\u{300}");
        assert_eq!(nfd(V, "Å"), "A\u{30A}");
        assert_eq!(nfd(V, "A\u{30A}"), "A\u{30A}");
    }

    #[test]
    fn nfd_decomposes_hangul_algorithmically() {
        assert_eq!(nfd(V, "\u{AC00}"), "\u{1100}\u{1161}");
        assert_eq!(nfd(V, "\u{AC01}"), "\u{1100}\u{1161}\u{11A8}");
    }

    #[test]
    fn nfd_canonically_orders_combining_marks() {
        let reordered = nfd(V, "e\u{301}\u{323}");
        assert_eq!(reordered, "e\u{323}\u{301}");
        assert_eq!(nfd(V, "e\u{323}\u{301}"), "e\u{323}\u{301}");
    }

    #[test]
    fn normalization_insensitivity_aliases_nfc_and_nfd() {
        let nfc = "caf\u{E9}";
        let nfd_spelling = "cafe\u{301}";
        assert_eq!(nfd(V, nfc), nfd(V, nfd_spelling));
        assert_ne!(nfd(V, "café"), nfd(V, "CAFÉ"));
    }

    #[test]
    fn vector_turkic_i_decompose_then_fold() {
        assert_eq!(caseless_key(V, "İ"), caseless_key(V, "i\u{307}"));
        assert_ne!(caseless_key(V, "İ"), caseless_key(V, "i"));
        assert_eq!(caseless_key(V, "I"), caseless_key(V, "i"));
    }

    #[test]
    fn vector_ypogegrammeni_folds_to_base_iota() {
        assert_eq!(caseless_key(V, "\u{345}"), "ι");
    }

    #[test]
    fn vector_sigma_forms_all_fold_together() {
        let sigma = caseless_key(V, "Σ");
        assert_eq!(sigma, caseless_key(V, "σ"));
        assert_eq!(sigma, caseless_key(V, "ς"));
    }

    #[test]
    fn vector_strasse_coexists_under_simple_fold() {
        assert_ne!(caseless_key(V, "straße"), caseless_key(V, "STRASSE"));
        assert_ne!(caseless_key(V, "straße"), caseless_key(V, "strasse"));
        assert_eq!(caseless_key(V, "STRASSE"), caseless_key(V, "strasse"));
    }

    #[test]
    fn vector_nfd_may_exceed_original_length() {
        let name = "Å".repeat(90);
        assert_eq!(name.len(), 180);
        assert!(name.len() <= 255);
        assert!(nfd(V, &name).len() > 255);
    }

    #[test]
    fn sensitive_key_keeps_case_but_still_normalizes() {
        assert_ne!(nfd(V, "File"), nfd(V, "file"));
        assert_eq!(nfd(V, "Café"), nfd(V, "Cafe\u{301}"));
    }
}
