use crate::error::{Result, ScaleFsError};
use crate::wire::{Cursor, put_u16, put_u32, put_u64};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PoolId(pub [u8; 16]);

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(pub [u8; 16]);

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CaseSensitivity {
    Sensitive,
    InsensitivePreserving,
}

impl CaseSensitivity {
    pub(crate) fn to_u8(self) -> u8 {
        match self {
            Self::Sensitive => 0,
            Self::InsensitivePreserving => 1,
        }
    }

    pub(crate) fn from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Sensitive),
            1 => Ok(Self::InsensitivePreserving),
            _ => Err(ScaleFsError::Corrupt("unknown case sensitivity value")),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Geometry {
    pub logical_block_size: u32,
    pub physical_block_size: u32,
    pub zone_size: u64,
    pub zone_count: u64,
    pub erase_granularity_zones: u32,
    pub sequential_write_required: bool,
}

impl Geometry {
    pub fn validate(self) -> Result<Self> {
        if !self.logical_block_size.is_power_of_two()
            || self.logical_block_size < 512
            || self.logical_block_size > 65536
        {
            return Err(ScaleFsError::Corrupt(
                "logical block size must be a power of two in 512..=65536",
            ));
        }
        if self.physical_block_size == 0 || !self.physical_block_size.is_power_of_two() {
            return Err(ScaleFsError::Corrupt(
                "physical block size must be a nonzero power of two",
            ));
        }
        if self.zone_size < 65536
            || !self
                .zone_size
                .is_multiple_of(u64::from(self.logical_block_size))
        {
            return Err(ScaleFsError::Corrupt(
                "zone size must be a multiple of the logical block size, at least 64 KiB",
            ));
        }
        if self.zone_count < 3 {
            return Err(ScaleFsError::Corrupt("a device needs at least three zones"));
        }
        if self.erase_granularity_zones == 0 {
            return Err(ScaleFsError::Corrupt(
                "erase granularity must be at least one zone",
            ));
        }
        if self.zone_size.checked_mul(self.zone_count).is_none() {
            return Err(ScaleFsError::Corrupt("device capacity overflows"));
        }
        if zone_summary_len(self.zone_count) > self.zone_size {
            return Err(ScaleFsError::Corrupt(
                "zone count too large for the zone size: the zone summary must fit in one zone",
            ));
        }
        Ok(self)
    }

    pub fn capacity_bytes(self) -> u64 {
        self.zone_size.saturating_mul(self.zone_count)
    }
}

pub fn superblock_slots(device_len: u64) -> [u64; 2] {
    [0, device_len.saturating_sub(4096) & !4095]
}

pub const ZONE_SUMMARY_ENTRY_LEN: u64 = 14;

pub fn zone_summary_len(zone_count: u64) -> u64 {
    (crate::format::RECORD_HEADER_LEN as u64 + 8)
        .saturating_add(ZONE_SUMMARY_ENTRY_LEN.saturating_mul(zone_count))
}

pub(crate) fn encode_geometry(out: &mut Vec<u8>, geometry: Geometry) {
    put_u32(out, geometry.logical_block_size);
    put_u32(out, geometry.physical_block_size);
    put_u64(out, geometry.zone_size);
    put_u64(out, geometry.zone_count);
    put_u32(out, geometry.erase_granularity_zones);
    out.push(u8::from(geometry.sequential_write_required));
}

pub(crate) fn decode_geometry(cursor: &mut Cursor<'_>) -> Result<Geometry> {
    let logical_block_size = cursor.take_u32()?;
    let physical_block_size = cursor.take_u32()?;
    let zone_size = cursor.take_u64()?;
    let zone_count = cursor.take_u64()?;
    let erase_granularity_zones = cursor.take_u32()?;
    let sequential_write_required = match cursor.take_u8()? {
        0 => false,
        1 => true,
        _ => return Err(ScaleFsError::Corrupt("invalid sequential-write flag")),
    };
    Geometry {
        logical_block_size,
        physical_block_size,
        zone_size,
        zone_count,
        erase_granularity_zones,
        sequential_write_required,
    }
    .validate()
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct Extent {
    pub device_index: u16,
    pub offset: u64,
    pub length: u64,
}

impl Extent {
    pub fn end_offset(self) -> Option<u64> {
        self.offset.checked_add(self.length)
    }
}

pub(crate) fn encode_extent(out: &mut Vec<u8>, extent: Extent) {
    put_u16(out, extent.device_index);
    put_u16(out, 0);
    put_u64(out, extent.offset);
    put_u64(out, extent.length);
}

pub(crate) fn decode_extent(cursor: &mut Cursor<'_>) -> Result<Extent> {
    let device_index = cursor.take_u16()?;
    let reserved = cursor.take_u16()?;
    if reserved != 0 {
        return Err(ScaleFsError::Corrupt("nonzero reserved field in extent"));
    }
    let extent = Extent {
        device_index,
        offset: cursor.take_u64()?,
        length: cursor.take_u64()?,
    };
    if extent.end_offset().is_none() {
        return Err(ScaleFsError::Corrupt("extent overflows the address space"));
    }
    Ok(extent)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_geometry() -> Geometry {
        Geometry {
            logical_block_size: 4096,
            physical_block_size: 4096,
            zone_size: 1 << 26,
            zone_count: 1024,
            erase_granularity_zones: 1,
            sequential_write_required: true,
        }
    }

    #[test]
    fn accepts_valid_geometry() {
        assert!(valid_geometry().validate().is_ok());
    }

    #[test]
    fn rejects_invalid_geometry() {
        let mut g = valid_geometry();
        g.logical_block_size = 4097;
        assert!(g.validate().is_err());

        let mut g = valid_geometry();
        g.logical_block_size = 256;
        assert!(g.validate().is_err());

        let mut g = valid_geometry();
        g.zone_size = 4096 * 3 + 1;
        assert!(g.validate().is_err());

        let mut g = valid_geometry();
        g.zone_size = 32768;
        assert!(g.validate().is_err());

        let mut g = valid_geometry();
        g.zone_count = 2;
        assert!(g.validate().is_err());

        let mut g = valid_geometry();
        g.erase_granularity_zones = 0;
        assert!(g.validate().is_err());

        let mut g = valid_geometry();
        g.zone_size = u64::MAX / 2;
        g.zone_count = 4;
        assert!(g.validate().is_err());

        let mut g = valid_geometry();
        g.zone_size = 65536;
        g.zone_count = 5000;
        assert!(g.validate().is_err());
        g.zone_count = 4000;
        assert!(g.validate().is_ok());
    }

    #[test]
    fn superblock_slots_depend_only_on_device_length() {
        let len = valid_geometry().capacity_bytes();
        assert_eq!(superblock_slots(len), [0, len - 4096]);
        assert_eq!(superblock_slots(len + 1000), [0, len - 4096]);
        assert_eq!(superblock_slots(len + 5000), [0, len]);
    }

    #[test]
    fn geometry_round_trips() {
        let mut out = Vec::new();
        encode_geometry(&mut out, valid_geometry());
        let mut cursor = Cursor::new(&out);
        assert_eq!(decode_geometry(&mut cursor).unwrap(), valid_geometry());
        cursor.expect_end("trailing").unwrap();
    }

    #[test]
    fn extent_round_trips_and_validates() {
        let extent = Extent {
            device_index: 3,
            offset: 1 << 30,
            length: 8192,
        };
        let mut out = Vec::new();
        encode_extent(&mut out, extent);
        let mut cursor = Cursor::new(&out);
        assert_eq!(decode_extent(&mut cursor).unwrap(), extent);

        out[2] = 0xFF;
        assert!(decode_extent(&mut Cursor::new(&out)).is_err());

        let mut out = Vec::new();
        encode_extent(
            &mut out,
            Extent {
                device_index: 0,
                offset: u64::MAX,
                length: 1,
            },
        );
        assert!(decode_extent(&mut Cursor::new(&out)).is_err());
    }

    #[test]
    fn case_sensitivity_round_trips() {
        for case in [
            CaseSensitivity::Sensitive,
            CaseSensitivity::InsensitivePreserving,
        ] {
            assert_eq!(CaseSensitivity::from_u8(case.to_u8()).unwrap(), case);
        }
        assert!(CaseSensitivity::from_u8(2).is_err());
    }
}
