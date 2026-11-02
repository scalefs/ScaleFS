use crate::error::{Result, ScaleFsError};
use crate::format::{RecordKind, decode_record, encode_record};
use crate::layout::Geometry;
use crate::wire::{Cursor, put_u32, put_u64};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ZoneClass {
    Metadata,
    Data,
    Parity,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AllocPurpose {
    Normal,
    Reclaim,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Allocation {
    pub zone_index: u64,
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct ZoneInfo {
    class: Option<ZoneClass>,
    open: bool,
    write_pointer: u64,
    erase_count: u32,
}

impl ZoneInfo {
    const FREE: Self = Self {
        class: None,
        open: false,
        write_pointer: 0,
        erase_count: 0,
    };
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ZoneView {
    pub zone_index: u64,
    pub class: Option<ZoneClass>,
    pub open: bool,
    pub write_pointer: u64,
    pub erase_count: u32,
}

#[derive(Debug, Clone)]
pub struct ZoneAllocator {
    geometry: Geometry,
    zones: Vec<ZoneInfo>,
    open_metadata: Option<u64>,
    open_data: Option<u64>,
    open_parity: Option<u64>,
    free_usable: u64,
    usable_total: u64,
    actuator_ranges: Vec<std::ops::Range<u64>>,
}

impl PartialEq for ZoneAllocator {
    fn eq(&self, other: &Self) -> bool {
        self.geometry == other.geometry
            && self.zones == other.zones
            && self.open_metadata == other.open_metadata
            && self.open_data == other.open_data
            && self.open_parity == other.open_parity
            && self.free_usable == other.free_usable
            && self.usable_total == other.usable_total
    }
}

impl Eq for ZoneAllocator {}

impl ZoneAllocator {
    pub fn new(geometry: Geometry) -> Result<Self> {
        let geometry = geometry.validate()?;
        let zone_count = usize::try_from(geometry.zone_count)
            .map_err(|_| ScaleFsError::InvalidArgument("zone count exceeds address space"))?;
        let mut allocator = Self {
            geometry,
            zones: vec![ZoneInfo::FREE; zone_count],
            open_metadata: None,
            open_data: None,
            open_parity: None,
            free_usable: 0,
            usable_total: 0,
            actuator_ranges: Vec::new(),
        };
        allocator.usable_total = (0..geometry.zone_count)
            .filter(|&z| allocator.is_usable_zone(z))
            .count() as u64;
        allocator.free_usable = allocator.usable_total;
        Ok(allocator)
    }

    pub fn geometry(&self) -> Geometry {
        self.geometry
    }

    pub fn set_actuator_byte_ranges(&mut self, ranges: &[std::ops::Range<u64>]) {
        let zone_size = self.geometry.zone_size;
        let half = zone_size / 2;
        let mut spans: Vec<std::ops::Range<u64>> = ranges
            .iter()
            .map(|range| {
                let first = (range.start + half) / zone_size;
                let end = (range.end + half) / zone_size;
                first..end.min(self.geometry.zone_count)
            })
            .filter(|span| span.start < span.end)
            .collect();
        spans.sort_by_key(|span| span.start);
        let sound = spans.len() >= 2 && spans.windows(2).all(|pair| pair[0].end <= pair[1].start);
        self.actuator_ranges = if sound { spans } else { Vec::new() };
    }

    pub fn actuator_range_count(&self) -> usize {
        self.actuator_ranges.len()
    }

    pub fn is_reserved_zone(&self, zone_index: u64) -> bool {
        zone_index == 0 || zone_index == self.geometry.zone_count - 1
    }

    pub fn is_usable_zone(&self, zone_index: u64) -> bool {
        let stripe = u64::from(self.geometry.erase_granularity_zones);
        let first = (zone_index / stripe) * stripe;
        let end = (first + stripe).min(self.geometry.zone_count);
        (first..end).all(|z| !self.is_reserved_zone(z))
    }

    pub fn free_usable_zone_count(&self) -> u64 {
        debug_assert_eq!(self.free_usable, self.scan_free_usable());
        self.free_usable
    }

    fn scan_free_usable(&self) -> u64 {
        self.zones
            .iter()
            .enumerate()
            .filter(|(i, zone)| zone.class.is_none() && self.is_usable_zone(*i as u64))
            .count() as u64
    }

    pub fn reserve_zone_count(&self) -> u64 {
        if self.usable_total > 4 { 2 } else { 1 }
    }

    pub fn can_allocate(&self, class: ZoneClass, length: u64, purpose: AllocPurpose) -> bool {
        if length == 0 {
            return false;
        }
        let block = u64::from(self.geometry.logical_block_size);
        let Some(rounded) = length
            .checked_add(block - 1)
            .map(|padded| padded / block * block)
        else {
            return false;
        };
        if rounded > self.geometry.zone_size {
            return false;
        }
        if let Some(zone_index) = self.open_slot(class) {
            let zone = &self.zones[zone_index as usize];
            if zone.write_pointer + rounded <= self.geometry.zone_size {
                return true;
            }
        }
        let held_back = match purpose {
            AllocPurpose::Normal => self.reserve_zone_count(),
            AllocPurpose::Reclaim => 0,
        };
        self.free_usable_zone_count() > held_back
    }

    pub fn zone(&self, zone_index: u64) -> Option<ZoneView> {
        let info = self.zones.get(usize::try_from(zone_index).ok()?)?;
        Some(ZoneView {
            zone_index,
            class: info.class,
            open: info.open,
            write_pointer: info.write_pointer,
            erase_count: info.erase_count,
        })
    }

    pub fn zones(&self) -> impl Iterator<Item = ZoneView> + '_ {
        (0..self.zones.len() as u64).map(|i| self.zone(i).expect("index in range"))
    }

    pub fn zone_start(&self, zone_index: u64) -> u64 {
        zone_index * self.geometry.zone_size
    }

    pub fn allocate(
        &mut self,
        class: ZoneClass,
        length: u64,
        purpose: AllocPurpose,
    ) -> Result<Allocation> {
        if length == 0 {
            return Err(ScaleFsError::InvalidArgument(
                "allocation length must be nonzero",
            ));
        }
        let block = u64::from(self.geometry.logical_block_size);
        let rounded = length
            .checked_add(block - 1)
            .ok_or(ScaleFsError::InvalidArgument("allocation length overflows"))?
            / block
            * block;
        if rounded > self.geometry.zone_size {
            return Err(ScaleFsError::InvalidArgument(
                "allocation exceeds zone capacity",
            ));
        }

        if let Some(zone_index) = self.open_slot(class) {
            let zone = &mut self.zones[zone_index as usize];
            if zone.write_pointer + rounded <= self.geometry.zone_size {
                let offset = zone_index * self.geometry.zone_size + zone.write_pointer;
                zone.write_pointer += rounded;
                return Ok(Allocation {
                    zone_index,
                    offset,
                    length: rounded,
                });
            }
        }

        if purpose == AllocPurpose::Normal
            && self.free_usable_zone_count() <= self.reserve_zone_count()
        {
            return Err(ScaleFsError::OutOfSpace);
        }
        let zone_index = self.pick_free_zone(class).ok_or(ScaleFsError::OutOfSpace)?;
        if let Some(previous) = self.open_slot(class) {
            self.zones[previous as usize].open = false;
        }
        let zone = &mut self.zones[zone_index as usize];
        zone.class = Some(class);
        zone.open = true;
        zone.write_pointer = rounded;
        *self.open_slot_mut(class) = Some(zone_index);
        self.free_usable -= 1;
        Ok(Allocation {
            zone_index,
            offset: zone_index * self.geometry.zone_size,
            length: rounded,
        })
    }

    pub fn reserve_ghost(&mut self, class: ZoneClass, offset: u64, length: u64) -> Result<()> {
        if length == 0 {
            return Err(ScaleFsError::InvalidArgument(
                "ghost reservation must be nonzero",
            ));
        }
        let block = u64::from(self.geometry.logical_block_size);
        let zone_index = offset / self.geometry.zone_size;
        let end = offset
            .checked_add(length)
            .ok_or(ScaleFsError::InvalidArgument("ghost reservation overflows"))?;
        if zone_index >= self.geometry.zone_count
            || end > (zone_index + 1) * self.geometry.zone_size
        {
            return Err(ScaleFsError::InvalidArgument(
                "ghost reservation crosses a zone boundary",
            ));
        }
        if !self.is_usable_zone(zone_index) {
            return Err(ScaleFsError::InvalidArgument(
                "ghost reservation names a reserved zone",
            ));
        }
        let within = end - zone_index * self.geometry.zone_size;
        let wanted = within.div_ceil(block) * block;
        let zone = &mut self.zones[zone_index as usize];
        match zone.class {
            None => {
                zone.class = Some(class);
                zone.write_pointer = wanted;
                self.free_usable -= 1;
            }
            Some(existing) if existing == class => {
                zone.write_pointer = zone.write_pointer.max(wanted);
            }
            Some(_) => {
                return Err(ScaleFsError::Corrupt(
                    "ghost reservation class conflicts with the zone",
                ));
            }
        }
        Ok(())
    }

    pub fn close_open_zone(&mut self, zone_index: u64) -> Result<()> {
        for class in [ZoneClass::Metadata, ZoneClass::Data, ZoneClass::Parity] {
            if self.open_slot(class) == Some(zone_index) {
                self.zones[zone_index as usize].open = false;
                *self.open_slot_mut(class) = None;
                return Ok(());
            }
        }
        Err(ScaleFsError::InvalidArgument("zone is not open"))
    }

    pub fn reset_stripe(&mut self, first_zone: u64) -> Result<()> {
        let stripe = u64::from(self.geometry.erase_granularity_zones);
        if !first_zone.is_multiple_of(stripe) {
            return Err(ScaleFsError::InvalidArgument(
                "stripe reset must start on an erase-stripe boundary",
            ));
        }
        if first_zone >= self.geometry.zone_count {
            return Err(ScaleFsError::InvalidArgument("stripe is out of range"));
        }
        let end = (first_zone + stripe).min(self.geometry.zone_count);
        if !self.is_usable_zone(first_zone) {
            return Err(ScaleFsError::InvalidArgument(
                "stripe contains a reserved zone",
            ));
        }
        if (first_zone..end).any(|z| self.zones[z as usize].open) {
            return Err(ScaleFsError::InvalidArgument(
                "stripe contains an open zone",
            ));
        }
        for z in first_zone..end {
            let zone = &mut self.zones[z as usize];
            self.free_usable += u64::from(zone.class.take().is_some());
            zone.write_pointer = 0;
            zone.erase_count = zone.erase_count.saturating_add(1);
        }
        Ok(())
    }

    pub fn encoded_len(&self) -> usize {
        crate::layout::zone_summary_len(self.zones.len() as u64) as usize
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(
            8 + self.zones.len() * crate::layout::ZONE_SUMMARY_ENTRY_LEN as usize,
        );
        put_u64(&mut payload, self.geometry.zone_count);
        for zone in &self.zones {
            let class_bits = match zone.class {
                None => 0u8,
                Some(ZoneClass::Metadata) => 1,
                Some(ZoneClass::Data) => 2,
                Some(ZoneClass::Parity) => 3,
            };
            payload.push(class_bits | if zone.open { 0b100 } else { 0 });
            payload.push(0);
            put_u32(&mut payload, zone.erase_count);
            put_u64(&mut payload, zone.write_pointer);
        }
        encode_record(RecordKind::ZoneSummary, &payload)
    }

    pub fn decode(geometry: Geometry, bytes: &[u8]) -> Result<Self> {
        let geometry = geometry.validate()?;
        let record = decode_record(bytes)?;
        if record.kind != RecordKind::ZoneSummary {
            return Err(ScaleFsError::Corrupt("expected a zone summary record"));
        }

        let mut cursor = Cursor::new(&record.payload);
        if cursor.take_u64()? != geometry.zone_count {
            return Err(ScaleFsError::Corrupt(
                "zone summary does not match device geometry",
            ));
        }

        let mut allocator = Self::new(geometry)?;
        let block = u64::from(geometry.logical_block_size);
        for index in 0..geometry.zone_count {
            let packed = cursor.take_u8()?;
            if packed & !0b111 != 0 {
                return Err(ScaleFsError::Corrupt("unknown zone flags"));
            }
            if cursor.take_u8()? != 0 {
                return Err(ScaleFsError::Corrupt("nonzero reserved byte in zone entry"));
            }
            let erase_count = cursor.take_u32()?;
            let write_pointer = cursor.take_u64()?;
            let class = match packed & 0b11 {
                0 => None,
                1 => Some(ZoneClass::Metadata),
                2 => Some(ZoneClass::Data),
                3 => Some(ZoneClass::Parity),
                _ => unreachable!("the class occupies two bits"),
            };
            let open = packed & 0b100 != 0;

            if write_pointer > geometry.zone_size || !write_pointer.is_multiple_of(block) {
                return Err(ScaleFsError::Corrupt("zone write pointer is invalid"));
            }
            if class.is_none() && (open || write_pointer != 0) {
                return Err(ScaleFsError::Corrupt("free zone has residual state"));
            }
            if class.is_some() && !allocator.is_usable_zone(index) {
                return Err(ScaleFsError::Corrupt("reserved zone is marked allocated"));
            }
            if open {
                let slot = match class {
                    Some(ZoneClass::Metadata) => &mut allocator.open_metadata,
                    Some(ZoneClass::Data) => &mut allocator.open_data,
                    Some(ZoneClass::Parity) => &mut allocator.open_parity,
                    None => unreachable!("free zones were rejected above"),
                };
                if slot.is_some() {
                    return Err(ScaleFsError::Corrupt("more than one open zone for a class"));
                }
                *slot = Some(index);
            }
            allocator.zones[index as usize] = ZoneInfo {
                class,
                open,
                write_pointer,
                erase_count,
            };
        }
        cursor.expect_end("zone summary has trailing bytes")?;
        allocator.free_usable = allocator.scan_free_usable();
        Ok(allocator)
    }

    fn open_slot(&self, class: ZoneClass) -> Option<u64> {
        match class {
            ZoneClass::Metadata => self.open_metadata,
            ZoneClass::Data => self.open_data,
            ZoneClass::Parity => self.open_parity,
        }
    }

    fn open_slot_mut(&mut self, class: ZoneClass) -> &mut Option<u64> {
        match class {
            ZoneClass::Metadata => &mut self.open_metadata,
            ZoneClass::Data => &mut self.open_data,
            ZoneClass::Parity => &mut self.open_parity,
        }
    }

    fn pick_free_zone(&self, class: ZoneClass) -> Option<u64> {
        let n = self.actuator_ranges.len();
        if n >= 2 {
            let anchor = match class {
                ZoneClass::Data => self.open_data,
                _ => self.open_slot(ZoneClass::Data).or(self.open_slot(class)),
            };
            let start = match anchor {
                Some(zone) => (self.range_of(zone) + 1) % n,
                None => 0,
            };
            for step in 0..n {
                let span = self.actuator_ranges[(start + step) % n].clone();
                if let Some(zone) = self.pick_free_in(span) {
                    return Some(zone);
                }
            }
        }
        self.pick_free_anywhere()
    }

    fn pick_free_anywhere(&self) -> Option<u64> {
        self.pick_free_in(0..self.geometry.zone_count)
    }

    fn pick_free_in(&self, span: std::ops::Range<u64>) -> Option<u64> {
        span.filter(|&z| self.is_usable_zone(z))
            .filter(|&z| self.zones[z as usize].class.is_none())
            .min_by_key(|&z| (self.zones[z as usize].erase_count, z))
    }

    fn range_of(&self, zone: u64) -> usize {
        self.actuator_ranges
            .iter()
            .position(|range| range.contains(&zone))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn geometry(zone_count: u64, erase_granularity_zones: u32) -> Geometry {
        Geometry {
            logical_block_size: 4096,
            physical_block_size: 4096,
            zone_size: 65536,
            zone_count,
            erase_granularity_zones,
            sequential_write_required: true,
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn fresh_allocator_reserves_superblock_zones() {
        let alloc = ZoneAllocator::new(geometry(8, 1)).unwrap();
        assert_eq!(alloc.free_usable_zone_count(), 6);
        assert!(alloc.is_reserved_zone(0));
        assert!(alloc.is_reserved_zone(7));
        assert!(!alloc.is_usable_zone(0));
        assert!(!alloc.is_usable_zone(7));
        assert!(alloc.is_usable_zone(1));
    }

    #[test]
    fn allocations_are_block_rounded_and_append_within_a_zone() {
        let mut alloc = ZoneAllocator::new(geometry(8, 1)).unwrap();
        let a = alloc
            .allocate(ZoneClass::Metadata, 100, AllocPurpose::Normal)
            .unwrap();
        assert_eq!(a.zone_index, 1);
        assert_eq!(a.offset, 65536);
        assert_eq!(a.length, 4096);

        let b = alloc
            .allocate(ZoneClass::Metadata, 4097, AllocPurpose::Normal)
            .unwrap();
        assert_eq!(b.zone_index, 1);
        assert_eq!(b.offset, 65536 + 4096);
        assert_eq!(b.length, 8192);
        assert_eq!(alloc.zone(1).unwrap().write_pointer, 12288);
    }

    #[test]
    fn each_class_uses_its_own_zone() {
        let mut alloc = ZoneAllocator::new(geometry(8, 1)).unwrap();
        let m = alloc
            .allocate(ZoneClass::Metadata, 1, AllocPurpose::Normal)
            .unwrap();
        let d = alloc
            .allocate(ZoneClass::Data, 1, AllocPurpose::Normal)
            .unwrap();
        let p = alloc
            .allocate(ZoneClass::Parity, 1, AllocPurpose::Normal)
            .unwrap();
        assert_ne!(m.zone_index, d.zone_index);
        assert_ne!(m.zone_index, p.zone_index);
        assert_ne!(d.zone_index, p.zone_index);
        assert_eq!(
            alloc.zone(m.zone_index).unwrap().class,
            Some(ZoneClass::Metadata)
        );
        assert_eq!(
            alloc.zone(d.zone_index).unwrap().class,
            Some(ZoneClass::Data)
        );
        assert_eq!(
            alloc.zone(p.zone_index).unwrap().class,
            Some(ZoneClass::Parity)
        );
        let p2 = alloc
            .allocate(ZoneClass::Parity, 1, AllocPurpose::Normal)
            .unwrap();
        assert_eq!(p2.zone_index, p.zone_index);
    }

    #[test]
    fn rolling_to_a_new_zone_closes_the_previous_one() {
        let mut alloc = ZoneAllocator::new(geometry(8, 1)).unwrap();
        alloc
            .allocate(ZoneClass::Data, 61440, AllocPurpose::Normal)
            .unwrap();
        let next = alloc
            .allocate(ZoneClass::Data, 8192, AllocPurpose::Normal)
            .unwrap();
        assert_ne!(next.zone_index, 1);
        assert!(!alloc.zone(1).unwrap().open);
        assert!(alloc.zone(next.zone_index).unwrap().open);
    }

    #[test]
    fn oversized_and_empty_allocations_are_invalid() {
        let mut alloc = ZoneAllocator::new(geometry(8, 1)).unwrap();
        assert!(matches!(
            alloc.allocate(ZoneClass::Data, 65537, AllocPurpose::Normal),
            Err(ScaleFsError::InvalidArgument(_))
        ));
        assert!(matches!(
            alloc.allocate(ZoneClass::Data, 0, AllocPurpose::Normal),
            Err(ScaleFsError::InvalidArgument(_))
        ));
    }

    #[test]
    fn reserve_zones_are_kept_for_reclamation() {
        let mut alloc = ZoneAllocator::new(geometry(8, 1)).unwrap();
        assert_eq!(alloc.reserve_zone_count(), 2);

        for _ in 0..4 {
            alloc
                .allocate(ZoneClass::Data, 65536, AllocPurpose::Normal)
                .unwrap();
        }
        assert_eq!(alloc.free_usable_zone_count(), 2);

        assert!(matches!(
            alloc.allocate(ZoneClass::Data, 65536, AllocPurpose::Normal),
            Err(ScaleFsError::OutOfSpace)
        ));
        alloc
            .allocate(ZoneClass::Metadata, 4096, AllocPurpose::Reclaim)
            .unwrap();
        alloc
            .allocate(ZoneClass::Data, 65536, AllocPurpose::Reclaim)
            .unwrap();
        assert!(matches!(
            alloc.allocate(ZoneClass::Data, 65536, AllocPurpose::Reclaim),
            Err(ScaleFsError::OutOfSpace)
        ));
    }

    #[test]
    fn appends_into_an_open_zone_ignore_the_reserve() {
        let mut alloc = ZoneAllocator::new(geometry(8, 1)).unwrap();
        alloc
            .allocate(ZoneClass::Data, 4096, AllocPurpose::Normal)
            .unwrap();
        for _ in 0..3 {
            alloc
                .allocate(ZoneClass::Metadata, 65536, AllocPurpose::Normal)
                .unwrap();
        }
        assert_eq!(alloc.free_usable_zone_count(), 2);
        let a = alloc
            .allocate(ZoneClass::Data, 4096, AllocPurpose::Normal)
            .unwrap();
        assert_eq!(a.zone_index, 1);
    }

    #[test]
    fn stripe_reset_frees_zones_and_counts_erases() {
        let mut alloc = ZoneAllocator::new(geometry(8, 1)).unwrap();
        alloc
            .allocate(ZoneClass::Data, 65536, AllocPurpose::Normal)
            .unwrap();
        alloc
            .allocate(ZoneClass::Data, 4096, AllocPurpose::Normal)
            .unwrap();
        assert!(!alloc.zone(1).unwrap().open);

        alloc.reset_stripe(1).unwrap();
        let zone = alloc.zone(1).unwrap();
        assert_eq!(zone.class, None);
        assert_eq!(zone.write_pointer, 0);
        assert_eq!(zone.erase_count, 1);

        assert!(alloc.reset_stripe(2).is_err());
        assert!(alloc.reset_stripe(0).is_err());
        let a = alloc
            .allocate(ZoneClass::Metadata, 4096, AllocPurpose::Normal)
            .unwrap();
        assert_eq!(a.zone_index, 3);
    }

    #[test]
    fn cached_free_counts_match_the_scan_oracle() {
        let assert_counts = |alloc: &ZoneAllocator| {
            let scanned = (0..alloc.geometry().zone_count)
                .filter(|&z| alloc.is_usable_zone(z) && alloc.zone(z).unwrap().class.is_none())
                .count() as u64;
            assert_eq!(alloc.free_usable_zone_count(), scanned);
            let usable = (0..alloc.geometry().zone_count)
                .filter(|&z| alloc.is_usable_zone(z))
                .count() as u64;
            let expected_reserve = if usable > 4 { 2 } else { 1 };
            assert_eq!(alloc.reserve_zone_count(), expected_reserve);
        };

        let mut alloc = ZoneAllocator::new(geometry(12, 2)).unwrap();
        assert_counts(&alloc);

        let first_data = alloc
            .allocate(ZoneClass::Data, 65536, AllocPurpose::Normal)
            .unwrap();
        assert_counts(&alloc);
        for class in [ZoneClass::Metadata, ZoneClass::Parity, ZoneClass::Data] {
            alloc.allocate(class, 65536, AllocPurpose::Normal).unwrap();
            assert_counts(&alloc);
        }
        let partial = alloc
            .allocate(ZoneClass::Data, 4096, AllocPurpose::Reclaim)
            .unwrap();
        assert_counts(&alloc);

        alloc.close_open_zone(partial.zone_index).unwrap();
        assert_counts(&alloc);
        let stripe = u64::from(alloc.geometry().erase_granularity_zones);
        let first = (first_data.zone_index / stripe) * stripe;
        let open_mate = (first..first + stripe)
            .find(|&z| alloc.zone(z).unwrap().open)
            .expect("the metadata zone shares the first stripe");
        alloc.close_open_zone(open_mate).unwrap();
        assert_counts(&alloc);
        alloc.reset_stripe(first).unwrap();
        assert_counts(&alloc);

        let free_zone = (0..alloc.geometry().zone_count)
            .find(|&z| alloc.is_usable_zone(z) && alloc.zone(z).unwrap().class.is_none())
            .expect("the reset freed zones");
        alloc
            .reserve_ghost(ZoneClass::Data, free_zone * 65536, 4096)
            .unwrap();
        assert_counts(&alloc);
        alloc
            .reserve_ghost(ZoneClass::Data, free_zone * 65536 + 8192, 4096)
            .unwrap();
        assert_counts(&alloc);
        let parity_zone = (0..alloc.geometry().zone_count)
            .find(|&z| alloc.is_usable_zone(z) && alloc.zone(z).unwrap().class.is_none())
            .expect("another free zone remains");
        alloc
            .reserve_ghost(ZoneClass::Parity, parity_zone * 65536, 4096)
            .unwrap();
        assert_counts(&alloc);

        let decoded = ZoneAllocator::decode(alloc.geometry(), &alloc.encode()).unwrap();
        assert_counts(&decoded);
        assert_eq!(decoded, alloc);
        assert_eq!(alloc.encoded_len(), alloc.encode().len());
    }

    #[test]
    fn multi_zone_stripes_exclude_neighbors_of_reserved_zones() {
        let mut alloc = ZoneAllocator::new(geometry(8, 2)).unwrap();
        assert!(!alloc.is_usable_zone(1));
        assert!(!alloc.is_usable_zone(6));
        assert_eq!(alloc.free_usable_zone_count(), 4);
        assert_eq!(alloc.reserve_zone_count(), 1);

        let a = alloc
            .allocate(ZoneClass::Data, 65536, AllocPurpose::Normal)
            .unwrap();
        assert_eq!(a.zone_index, 2);

        assert!(alloc.reset_stripe(3).is_err());
        assert!(alloc.reset_stripe(0).is_err());
        assert!(alloc.reset_stripe(6).is_err());
        alloc
            .allocate(ZoneClass::Data, 65536, AllocPurpose::Normal)
            .unwrap();
        assert!(alloc.reset_stripe(2).is_err());
        alloc
            .allocate(ZoneClass::Data, 4096, AllocPurpose::Normal)
            .unwrap();
        alloc.reset_stripe(2).unwrap();
        assert_eq!(alloc.zone(2).unwrap().erase_count, 1);
        assert_eq!(alloc.zone(3).unwrap().erase_count, 1);
    }

    #[test]
    fn summary_round_trips_exactly() {
        let mut alloc = ZoneAllocator::new(geometry(8, 1)).unwrap();
        alloc
            .allocate(ZoneClass::Metadata, 100, AllocPurpose::Normal)
            .unwrap();
        alloc
            .allocate(ZoneClass::Data, 5000, AllocPurpose::Normal)
            .unwrap();
        alloc
            .allocate(ZoneClass::Parity, 700, AllocPurpose::Normal)
            .unwrap();
        alloc
            .allocate(ZoneClass::Data, 65536, AllocPurpose::Normal)
            .unwrap();
        assert!(alloc.reset_stripe(3).is_err());

        let decoded = ZoneAllocator::decode(geometry(8, 1), &alloc.encode()).unwrap();
        assert_eq!(decoded, alloc);

        let mut resumed = decoded;
        let a = resumed
            .allocate(ZoneClass::Metadata, 1, AllocPurpose::Normal)
            .unwrap();
        assert_eq!(a.zone_index, 1);
        assert_eq!(a.offset, 65536 + 4096);
    }

    #[test]
    fn summary_decode_rejects_invalid_state() {
        let alloc = ZoneAllocator::new(geometry(8, 1)).unwrap();
        let encoded = alloc.encode();

        assert!(ZoneAllocator::decode(geometry(16, 1), &encoded).is_err());

        let corrupt = |mutate: &dyn Fn(&mut Vec<u8>)| {
            let record = decode_record(&encoded).unwrap();
            let mut payload = record.payload;
            mutate(&mut payload);
            let bytes = encode_record(RecordKind::ZoneSummary, &payload);
            ZoneAllocator::decode(geometry(8, 1), &bytes)
        };
        let entry = |zone: usize| 8 + zone * 14;

        assert!(corrupt(&|p| p[entry(1) + 7] = 0x10).is_err());
        assert!(corrupt(&|p| p[entry(1)] = 0b100).is_err());
        assert!(corrupt(&|p| p[entry(0)] = 1).is_err());
        assert!(
            corrupt(&|p| {
                p[entry(2)] = 3;
                p[entry(2) + 7] = 0x10;
            })
            .is_ok()
        );
        assert!(
            corrupt(&|p| {
                p[entry(2)] = 0b111;
                p[entry(2) + 7] = 0x10;
                p[entry(3)] = 0b111;
                p[entry(3) + 7] = 0x10;
            })
            .is_err()
        );
        assert!(corrupt(&|p| p[entry(1)] = 0b1000).is_err());
        assert!(corrupt(&|p| p[entry(1) + 1] = 1).is_err());
        assert!(
            corrupt(&|p| {
                p[entry(1)] = 1;
                p[entry(1) + 6] = 1;
            })
            .is_err()
        );
        assert!(
            corrupt(&|p| {
                p[entry(1)] = 0b101;
                p[entry(1) + 7] = 0x10;
                p[entry(2)] = 0b101;
                p[entry(2) + 7] = 0x10;
            })
            .is_err()
        );
        assert!(corrupt(&|p| p.push(0)).is_err());
    }

    #[test]
    fn golden_zone_summary_fixture_is_stable() {
        let mut alloc = ZoneAllocator::new(geometry(8, 1)).unwrap();
        alloc
            .allocate(ZoneClass::Metadata, 100, AllocPurpose::Normal)
            .unwrap();
        alloc
            .allocate(ZoneClass::Data, 5000, AllocPurpose::Normal)
            .unwrap();
        let encoded = alloc.encode();
        assert_eq!(
            hex(&encoded),
            "5363616c6546530001000000050000007800000000000000224a6fcd00000000080000000000000000000000000000000000000000000500000000000010000000000000060000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            ZoneAllocator::decode(geometry(8, 1), &encoded).unwrap(),
            alloc
        );
    }

    fn dual_actuator(zone_count: u64) -> ZoneAllocator {
        let mut alloc = ZoneAllocator::new(geometry(zone_count, 1)).unwrap();
        let half = zone_count / 2 * 65536;
        alloc.set_actuator_byte_ranges(&[0..half, half..zone_count * 65536]);
        assert_eq!(alloc.actuator_range_count(), 2);
        alloc
    }

    #[test]
    fn data_rolls_alternate_actuator_ranges() {
        let mut alloc = dual_actuator(12);
        let mut opened = Vec::new();
        for _ in 0..4 {
            let run = alloc
                .allocate(ZoneClass::Data, 65536, AllocPurpose::Normal)
                .unwrap();
            opened.push(run.zone_index);
        }
        assert_eq!(opened, vec![1, 6, 2, 7]);
    }

    #[test]
    fn metadata_and_parity_yield_the_data_head() {
        let mut alloc = dual_actuator(12);
        let data = alloc
            .allocate(ZoneClass::Data, 100, AllocPurpose::Normal)
            .unwrap();
        assert_eq!(data.zone_index, 1, "data anchors range 0");
        let metadata = alloc
            .allocate(ZoneClass::Metadata, 100, AllocPurpose::Normal)
            .unwrap();
        let parity = alloc
            .allocate(ZoneClass::Parity, 100, AllocPurpose::Normal)
            .unwrap();
        assert_eq!(metadata.zone_index, 6, "metadata yields to range 1");
        assert_eq!(parity.zone_index, 7, "parity yields beside it");
    }

    #[test]
    fn a_full_preferred_range_falls_back() {
        let mut alloc = dual_actuator(12);
        for zone in 6..=10u64 {
            alloc
                .reserve_ghost(ZoneClass::Data, zone * 65536, 65536)
                .unwrap();
        }
        let first = alloc
            .allocate(ZoneClass::Data, 65536, AllocPurpose::Normal)
            .unwrap();
        assert_eq!(first.zone_index, 1, "first roll starts in range 0");
        let second = alloc
            .allocate(ZoneClass::Data, 65536, AllocPurpose::Normal)
            .unwrap();
        assert_eq!(
            second.zone_index, 2,
            "range 1 is full; the alternation falls back to range 0",
        );
    }

    #[test]
    fn the_actuator_map_is_runtime_only() {
        let mut alloc = dual_actuator(12);
        alloc
            .allocate(ZoneClass::Data, 100, AllocPurpose::Normal)
            .unwrap();
        let decoded = ZoneAllocator::decode(geometry(12, 1), &alloc.encode()).unwrap();
        assert_eq!(decoded, alloc);
        assert_eq!(decoded.actuator_range_count(), 0);
    }

    #[test]
    fn byte_range_mapping_is_midpoint_tiled_and_fails_closed() {
        let mut alloc = ZoneAllocator::new(geometry(12, 1)).unwrap();
        let boundary = 3 * 65536 + 40_000;
        alloc.set_actuator_byte_ranges(&[0..boundary, boundary..12 * 65536]);
        assert_eq!(alloc.actuator_range_count(), 2);
        let first = alloc
            .allocate(ZoneClass::Data, 65536, AllocPurpose::Normal)
            .unwrap();
        let second = alloc
            .allocate(ZoneClass::Data, 65536, AllocPurpose::Normal)
            .unwrap();
        assert!(first.zone_index < 4, "first roll in the first span");
        assert!(second.zone_index >= 4, "second roll alternates spans");

        #[allow(clippy::single_range_in_vec_init)]
        alloc.set_actuator_byte_ranges(&[0..12 * 65536]);
        assert_eq!(alloc.actuator_range_count(), 0, "one range steers nothing");
        alloc.set_actuator_byte_ranges(&[0..8 * 65536, 4 * 65536..12 * 65536]);
        assert_eq!(alloc.actuator_range_count(), 0, "overlap fails closed");
    }
}
