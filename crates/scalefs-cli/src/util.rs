
use std::collections::{HashMap, HashSet};

pub struct Opts {
    flags: HashSet<String>,
    values: HashMap<String, String>,
    pub positional: Vec<String>,
}

impl Opts {
    pub fn parse(
        args: &[String],
        flag_names: &[&str],
        value_names: &[&str],
    ) -> Result<Self, String> {
        let mut opts = Self {
            flags: HashSet::new(),
            values: HashMap::new(),
            positional: Vec::new(),
        };
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            if let Some(name) = arg.strip_prefix("--") {
                if flag_names.contains(&name) {
                    opts.flags.insert(name.to_string());
                } else if value_names.contains(&name) {
                    let value = iter
                        .next()
                        .ok_or_else(|| format!("option --{name} needs a value"))?;
                    opts.values.insert(name.to_string(), value.clone());
                } else {
                    return Err(format!("unknown option --{name}"));
                }
            } else {
                opts.positional.push(arg.clone());
            }
        }
        Ok(opts)
    }

    pub fn flag(&self, name: &str) -> bool {
        self.flags.contains(name)
    }

    pub fn value(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }
}

pub fn parse_size(text: &str) -> Result<u64, String> {
    let cleaned = text.trim().to_ascii_uppercase();
    let cleaned = cleaned
        .strip_suffix("IB")
        .or_else(|| cleaned.strip_suffix('B'))
        .unwrap_or(&cleaned);
    let (digits, shift) = match cleaned.chars().last() {
        Some('K') => (&cleaned[..cleaned.len() - 1], 10),
        Some('M') => (&cleaned[..cleaned.len() - 1], 20),
        Some('G') => (&cleaned[..cleaned.len() - 1], 30),
        Some('T') => (&cleaned[..cleaned.len() - 1], 40),
        _ => (cleaned, 0),
    };
    let number: u64 = digits
        .parse()
        .map_err(|_| format!("invalid size '{text}'"))?;
    number
        .checked_shl(shift)
        .filter(|_| number.leading_zeros() >= shift)
        .ok_or_else(|| format!("size '{text}' is too large"))
}

pub fn format_size(bytes: u64) -> String {
    const UNITS: [(&str, u64); 4] = [("TiB", 40), ("GiB", 30), ("MiB", 20), ("KiB", 10)];
    for (unit, shift) in UNITS {
        let scale = 1u64 << shift;
        if bytes >= scale {
            let whole = bytes / scale;
            let tenths = (bytes % scale) * 10 / scale;
            return if tenths == 0 {
                format!("{whole} {unit}")
            } else {
                format!("{whole}.{tenths} {unit}")
            };
        }
    }
    format!("{bytes} B")
}

pub fn now_ns() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(elapsed) => i64::try_from(elapsed.as_nanos()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

pub fn format_time(ns: i64) -> String {
    let secs = ns.div_euclid(1_000_000_000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        tod / 3600,
        tod % 3600 / 60,
        tod % 60
    )
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

pub fn fill_random(buf: &mut [u8]) -> Result<(), String> {
    os_random(buf)
}

#[cfg(unix)]
fn os_random(buf: &mut [u8]) -> Result<(), String> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(buf))
        .map_err(|err| format!("cannot read /dev/urandom: {err}"))
}

#[cfg(windows)]
fn os_random(buf: &mut [u8]) -> Result<(), String> {
    #[allow(unsafe_code)]
    mod ffi {
        #[link(name = "bcryptprimitives", kind = "raw-dylib")]
        unsafe extern "system" {
            pub fn ProcessPrng(pb_data: *mut u8, cb_data: usize) -> i32;
        }
    }
    #[allow(unsafe_code)]
    let ok = unsafe { ffi::ProcessPrng(buf.as_mut_ptr(), buf.len()) };
    if ok == 1 {
        Ok(())
    } else {
        Err("ProcessPrng failed".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_parse_and_format() {
        assert_eq!(parse_size("4096").unwrap(), 4096);
        assert_eq!(parse_size("64K").unwrap(), 65536);
        assert_eq!(parse_size("64k").unwrap(), 65536);
        assert_eq!(parse_size("512MiB").unwrap(), 512 << 20);
        assert_eq!(parse_size("2G").unwrap(), 2 << 30);
        assert_eq!(parse_size("1T").unwrap(), 1 << 40);
        assert!(parse_size("").is_err());
        assert!(parse_size("12X").is_err());
        assert!(parse_size("999999999999T").is_err());

        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(65536), "64 KiB");
        assert_eq!(format_size(3 << 29), "1.5 GiB");
    }

    #[test]
    fn times_format_as_utc() {
        assert_eq!(format_time(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(
            format_time(1_700_000_000_000_000_000),
            "2023-11-14 22:13:20 UTC"
        );
    }

    #[test]
    fn entropy_fills_buffers() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        fill_random(&mut a).unwrap();
        fill_random(&mut b).unwrap();
        assert_ne!(a, b, "two 128-bit draws should differ");
    }

    #[test]
    fn opts_parse_flags_values_and_positionals() {
        let args: Vec<String> = ["--label", "tank", "img.bin", "--case-sensitive"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let opts = Opts::parse(&args, &["case-sensitive"], &["label"]).unwrap();
        assert!(opts.flag("case-sensitive"));
        assert_eq!(opts.value("label"), Some("tank"));
        assert_eq!(opts.positional, ["img.bin"]);
        assert!(Opts::parse(&args, &[], &[]).is_err());
    }
}
