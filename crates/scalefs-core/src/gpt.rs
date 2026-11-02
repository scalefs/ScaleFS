use crate::checksum::crc32_ieee;
use crate::device::{BlockDevice, PartitionView};
use crate::error::{Result, ScaleFsError};

pub const SCALEFS_PART_TYPE_GUID: [u8; 16] = [
    0xFD, 0x7E, 0x4E, 0x4C, 0xFB, 0x24, 0xD9, 0x4D, 0xA7, 0xF8, 0x33, 0xB0, 0x6F, 0xA6, 0xC8, 0x5C,
];

pub const SCALEFS_PART_TYPE_GUID_TEXT: &str = "4C4E7EFD-24FB-4DD9-A7F8-33B06FA6C85C";

pub const MEMBER_PARTITION_START: u64 = 1 << 20;

const PARTITION_NAME: &str = "ScaleFS pool member";

const ENTRY_COUNT: u32 = 128;

const ENTRY_SIZE: u32 = 128;

const ENTRY_ARRAY_BYTES: u64 = ENTRY_COUNT as u64 * ENTRY_SIZE as u64;

const MAX_FOREIGN_ARRAY_BYTES: u64 = 1 << 20;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct MemberPartition {
    pub start: u64,
    pub len: u64,
    pub disk_guid: [u8; 16],
    pub part_guid: [u8; 16],
}

struct Layout {
    sector: u64,
    total_lba: u64,
    entry_sectors: u64,
    part_first: u64,
    part_last: u64,
}

impl Layout {
    fn compute(device_len: u64, sector_size: u32) -> Option<Layout> {
        if !sector_size.is_power_of_two() || !(512..=65536).contains(&sector_size) {
            return None;
        }
        let sector = u64::from(sector_size);
        let total_lba = device_len / sector;
        let entry_sectors = ENTRY_ARRAY_BYTES.div_ceil(sector);
        let part_first = MEMBER_PARTITION_START / sector;
        let part_last = total_lba.checked_sub(2 + entry_sectors)?;
        if part_last < part_first {
            return None;
        }
        Some(Layout {
            sector,
            total_lba,
            entry_sectors,
            part_first,
            part_last,
        })
    }

    fn partition_bytes(&self) -> (u64, u64) {
        (
            self.part_first * self.sector,
            (self.part_last + 1 - self.part_first) * self.sector,
        )
    }
}

pub fn usable_len(device_len: u64, sector_size: u32) -> u64 {
    Layout::compute(device_len, sector_size).map_or(0, |layout| layout.partition_bytes().1)
}

pub fn member_image_len(capacity: u64) -> u64 {
    debug_assert!(capacity.is_multiple_of(512));
    capacity + MEMBER_PARTITION_START + (2 + ENTRY_ARRAY_BYTES.div_ceil(512)) * 512 - 512
}

pub fn write_member_gpt<D: BlockDevice>(
    device: &D,
    disk_guid: [u8; 16],
    part_guid: [u8; 16],
) -> Result<MemberPartition> {
    let sector_size = device.sector_size();
    let Some(layout) = Layout::compute(device.len(), sector_size) else {
        return Err(ScaleFsError::InvalidArgument(
            "device is too small for a pool member (the GPT wrapper needs 1 MiB plus tail sectors)",
        ));
    };
    let entries = encode_entry_array(&layout, part_guid);
    let entries_crc = crc32_ieee(&entries);

    let mut head = vec![0u8; ((2 + layout.entry_sectors) * layout.sector) as usize];
    encode_protective_mbr(&mut head[..512], layout.total_lba);
    let header_at = layout.sector as usize;
    encode_header(
        &mut head[header_at..header_at + 92],
        &layout,
        disk_guid,
        entries_crc,
        true,
    );
    let entries_at = 2 * layout.sector as usize;
    head[entries_at..entries_at + entries.len()].copy_from_slice(&entries);

    let mut tail = vec![0u8; ((layout.entry_sectors + 1) * layout.sector) as usize];
    tail[..entries.len()].copy_from_slice(&entries);
    let backup_header_at = (layout.entry_sectors * layout.sector) as usize;
    encode_header(
        &mut tail[backup_header_at..backup_header_at + 92],
        &layout,
        disk_guid,
        entries_crc,
        false,
    );

    device.write_at(0, &head)?;
    device.flush()?;
    device.write_at(
        (layout.total_lba - 1 - layout.entry_sectors) * layout.sector,
        &tail,
    )?;
    device.flush()?;

    let (start, len) = layout.partition_bytes();
    Ok(MemberPartition {
        start,
        len,
        disk_guid,
        part_guid,
    })
}

pub fn find_member_partition<D: BlockDevice>(device: &D) -> Result<Option<MemberPartition>> {
    let own = device.sector_size();
    let candidates = if own == 4096 {
        [4096u32, 512]
    } else {
        [own, 4096]
    };
    for sector_size in candidates {
        if sector_size < 512 || !sector_size.is_power_of_two() {
            continue;
        }
        match parse_gpt(device, sector_size)? {
            GptScan::NoGpt | GptScan::NoScaleFsPartition => continue,
            GptScan::Member(partition) => return Ok(Some(partition)),
        }
    }
    Ok(None)
}

enum GptScan {
    NoGpt,
    NoScaleFsPartition,
    Member(MemberPartition),
}

fn parse_gpt<D: BlockDevice>(device: &D, sector_size: u32) -> Result<GptScan> {
    let sector = u64::from(sector_size);
    let total_lba = device.len() / sector;
    if total_lba < 4 {
        return Ok(GptScan::NoGpt);
    }
    for header_lba in [1, total_lba - 1] {
        let Some(header) = read_valid_header(device, sector, total_lba, header_lba)? else {
            continue;
        };
        let array_bytes = header.num_entries as u64 * header.entry_size as u64;
        let mut entries = vec![0u8; array_bytes as usize];
        let array_end = header
            .entry_lba
            .checked_mul(sector)
            .and_then(|start| start.checked_add(array_bytes));
        match array_end {
            Some(end) if end <= device.len() => {
                device.read_at(header.entry_lba * sector, &mut entries)?;
            }
            _ => continue,
        }
        if crc32_ieee(&entries) != header.entries_crc {
            continue;
        }
        let mut member: Option<MemberPartition> = None;
        for index in 0..header.num_entries as usize {
            let entry = &entries[index * header.entry_size as usize..][..ENTRY_SIZE as usize];
            if entry[0..16] != SCALEFS_PART_TYPE_GUID {
                continue;
            }
            if member.is_some() {
                return Err(ScaleFsError::Corrupt(
                    "device carries more than one ScaleFS-typed partition",
                ));
            }
            let first = u64::from_le_bytes(entry[32..40].try_into().expect("8 bytes"));
            let last = u64::from_le_bytes(entry[40..48].try_into().expect("8 bytes"));
            let end = last
                .checked_add(1)
                .and_then(|lba| lba.checked_mul(sector))
                .ok_or(ScaleFsError::Corrupt("partition overflows the device"))?;
            if first < 1 || first > last || end > device.len() {
                return Err(ScaleFsError::Corrupt(
                    "ScaleFS partition bounds reach outside the device",
                ));
            }
            member = Some(MemberPartition {
                start: first * sector,
                len: end - first * sector,
                disk_guid: header.disk_guid,
                part_guid: entry[16..32].try_into().expect("16 bytes"),
            });
        }
        return Ok(match member {
            Some(partition) => GptScan::Member(partition),
            None => GptScan::NoScaleFsPartition,
        });
    }
    Ok(GptScan::NoGpt)
}

struct ParsedHeader {
    disk_guid: [u8; 16],
    entry_lba: u64,
    num_entries: u32,
    entry_size: u32,
    entries_crc: u32,
}

fn read_valid_header<D: BlockDevice>(
    device: &D,
    sector: u64,
    total_lba: u64,
    header_lba: u64,
) -> Result<Option<ParsedHeader>> {
    let mut block = vec![0u8; sector as usize];
    device.read_at(header_lba * sector, &mut block)?;
    if block[0..8] != *b"EFI PART" {
        return Ok(None);
    }
    let header_size = u32::from_le_bytes(block[12..16].try_into().expect("4 bytes"));
    if !(92..=sector.min(4096) as u32).contains(&header_size) {
        return Ok(None);
    }
    let stored_crc = u32::from_le_bytes(block[16..20].try_into().expect("4 bytes"));
    let mut zeroed = block[..header_size as usize].to_vec();
    zeroed[16..20].fill(0);
    if crc32_ieee(&zeroed) != stored_crc {
        return Ok(None);
    }
    let my_lba = u64::from_le_bytes(block[24..32].try_into().expect("8 bytes"));
    if my_lba != header_lba {
        return Ok(None);
    }
    let entry_lba = u64::from_le_bytes(block[72..80].try_into().expect("8 bytes"));
    let num_entries = u32::from_le_bytes(block[80..84].try_into().expect("4 bytes"));
    let entry_size = u32::from_le_bytes(block[84..88].try_into().expect("4 bytes"));
    if entry_size < ENTRY_SIZE
        || !entry_size.is_power_of_two()
        || num_entries == 0
        || u64::from(num_entries) * u64::from(entry_size) > MAX_FOREIGN_ARRAY_BYTES
        || entry_lba < 1
        || entry_lba >= total_lba
    {
        return Ok(None);
    }
    Ok(Some(ParsedHeader {
        disk_guid: block[56..72].try_into().expect("16 bytes"),
        entry_lba,
        num_entries,
        entry_size,
        entries_crc: u32::from_le_bytes(block[88..92].try_into().expect("4 bytes")),
    }))
}

pub fn member_view<D: BlockDevice>(device: D) -> Result<PartitionView<D>> {
    match find_member_partition(&device)? {
        Some(partition) => PartitionView::new(device, partition.start, partition.len),
        None => Err(ScaleFsError::Corrupt(
            "no ScaleFS partition: not a pool member device",
        )),
    }
}

pub fn member_view_forensic<D: BlockDevice>(device: D) -> PartitionView<D> {
    let (start, len) = forensic_bounds(&device);
    PartitionView::new(device, start, len).expect("bounds derived from the device length")
}

fn forensic_bounds<D: BlockDevice>(device: &D) -> (u64, u64) {
    if let Ok(Some(partition)) = find_member_partition(device) {
        return (partition.start, partition.len);
    }
    let mut fallback = None;
    for sector in [512u32, 4096] {
        let Some(layout) = Layout::compute(device.len(), sector) else {
            continue;
        };
        let (start, len) = layout.partition_bytes();
        if fallback.is_none() {
            fallback = Some((start, len));
        }
        for offset in crate::layout::superblock_slots(len) {
            let want = len.saturating_sub(offset).min(4096);
            if want == 0 {
                continue;
            }
            let mut block = vec![0u8; want as usize];
            if device.read_at(start + offset, &mut block).is_err() {
                continue;
            }
            if crate::records::decode_superblock(&block).is_ok() {
                return (start, len);
            }
        }
    }
    fallback.unwrap_or((0, device.len()))
}

fn encode_protective_mbr(sector: &mut [u8], total_lba: u64) {
    let entry = &mut sector[446..462];
    entry[1..4].copy_from_slice(&[0x00, 0x02, 0x00]);
    entry[4] = 0xEE;
    entry[5..8].copy_from_slice(&[0xFF, 0xFF, 0xFF]);
    entry[8..12].copy_from_slice(&1u32.to_le_bytes());
    let span = u32::try_from(total_lba - 1).unwrap_or(u32::MAX);
    entry[12..16].copy_from_slice(&span.to_le_bytes());
    sector[510] = 0x55;
    sector[511] = 0xAA;
}

fn encode_header(
    out: &mut [u8],
    layout: &Layout,
    disk_guid: [u8; 16],
    entries_crc: u32,
    primary: bool,
) {
    let (my_lba, alternate_lba, entry_lba) = if primary {
        (1, layout.total_lba - 1, 2)
    } else {
        (
            layout.total_lba - 1,
            1,
            layout.total_lba - 1 - layout.entry_sectors,
        )
    };
    out[0..8].copy_from_slice(b"EFI PART");
    out[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    out[12..16].copy_from_slice(&92u32.to_le_bytes());
    out[24..32].copy_from_slice(&my_lba.to_le_bytes());
    out[32..40].copy_from_slice(&alternate_lba.to_le_bytes());
    out[40..48].copy_from_slice(&layout.part_first.to_le_bytes());
    out[48..56].copy_from_slice(&layout.part_last.to_le_bytes());
    out[56..72].copy_from_slice(&disk_guid);
    out[72..80].copy_from_slice(&entry_lba.to_le_bytes());
    out[80..84].copy_from_slice(&ENTRY_COUNT.to_le_bytes());
    out[84..88].copy_from_slice(&ENTRY_SIZE.to_le_bytes());
    out[88..92].copy_from_slice(&entries_crc.to_le_bytes());
    let crc = crc32_ieee(&out[..92]);
    out[16..20].copy_from_slice(&crc.to_le_bytes());
}

fn encode_entry_array(layout: &Layout, part_guid: [u8; 16]) -> Vec<u8> {
    let mut entries = vec![0u8; ENTRY_ARRAY_BYTES as usize];
    let entry = &mut entries[..ENTRY_SIZE as usize];
    entry[0..16].copy_from_slice(&SCALEFS_PART_TYPE_GUID);
    entry[16..32].copy_from_slice(&part_guid);
    entry[32..40].copy_from_slice(&layout.part_first.to_le_bytes());
    entry[40..48].copy_from_slice(&layout.part_last.to_le_bytes());
    for (index, code) in PARTITION_NAME.encode_utf16().enumerate() {
        entry[56 + index * 2..58 + index * 2].copy_from_slice(&code.to_le_bytes());
    }
    entries
}

pub fn guid_text(bytes: &[u8; 16]) -> String {
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        bytes[3],
        bytes[2],
        bytes[1],
        bytes[0],
        bytes[5],
        bytes[4],
        bytes[7],
        bytes[6],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::MemoryBlockDevice;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    struct FourKn(MemoryBlockDevice);

    impl BlockDevice for FourKn {
        fn len(&self) -> u64 {
            self.0.len()
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.0.read_at(offset, buf)
        }
        fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
            self.0.write_at(offset, data)
        }
        fn flush(&self) -> Result<()> {
            self.0.flush()
        }
        fn sector_size(&self) -> u32 {
            4096
        }
    }

    #[test]
    fn type_guid_bytes_match_canonical_text() {
        assert_eq!(
            guid_text(&SCALEFS_PART_TYPE_GUID),
            SCALEFS_PART_TYPE_GUID_TEXT
        );
    }

    #[test]
    fn layout_math_is_exact() {
        let len = member_image_len(1 << 20);
        assert_eq!(len, (1 << 20) + (1 << 20) + 33 * 512);
        assert_eq!(usable_len(len, 512), 1 << 20);
        assert_eq!(usable_len(len + 511, 512), 1 << 20);
        assert_eq!(usable_len(len + 512, 512), (1 << 20) + 512);
        let len_4k = (1 << 20) + (1 << 20) + 5 * 4096;
        assert_eq!(usable_len(len_4k, 4096), 1 << 20);
        assert_eq!(usable_len(1 << 20, 512), 0);
        assert_eq!(usable_len(0, 512), 0);
        assert_eq!(usable_len(1 << 30, 300), 0);
        assert_eq!(usable_len(1 << 30, 1 << 20), 0);
    }

    #[test]
    fn write_then_find_round_trips_both_sector_sizes() {
        let disk_guid = [0xA1; 16];
        let part_guid = [0xB2; 16];

        let device = MemoryBlockDevice::new(member_image_len(1 << 20) as usize);
        let written = write_member_gpt(&device, disk_guid, part_guid).unwrap();
        assert_eq!(written.start, MEMBER_PARTITION_START);
        assert_eq!(written.len, 1 << 20);
        let found = find_member_partition(&device).unwrap().unwrap();
        assert_eq!(found, written);

        let device = FourKn(MemoryBlockDevice::new((3 << 20) as usize));
        let written = write_member_gpt(&device, disk_guid, part_guid).unwrap();
        assert_eq!(written.start, MEMBER_PARTITION_START);
        assert_eq!(written.len, (2 << 20) - 5 * 4096);
        let found = find_member_partition(&device).unwrap().unwrap();
        assert_eq!(found, written);

        let raw = device.0;
        let found = find_member_partition(&raw).unwrap().unwrap();
        assert_eq!(found, written);
    }

    #[test]
    fn backup_header_carries_a_destroyed_primary() {
        let device = MemoryBlockDevice::new(member_image_len(1 << 20) as usize);
        let written = write_member_gpt(&device, [1; 16], [2; 16]).unwrap();

        device.write_at(512, &[0u8; 512 * 33]).unwrap();
        let found = find_member_partition(&device).unwrap().unwrap();
        assert_eq!(found, written);

        let len = device.len();
        device
            .write_at(len - 33 * 512, &vec![0u8; 33 * 512])
            .unwrap();
        assert!(find_member_partition(&device).unwrap().is_none());
    }

    #[test]
    fn member_view_resolves_and_refuses() {
        let device = MemoryBlockDevice::new(member_image_len(1 << 20) as usize);
        write_member_gpt(&device, [1; 16], [2; 16]).unwrap();
        let view = member_view(device).unwrap();
        assert_eq!(view.len(), 1 << 20);
        assert_eq!(view.start(), MEMBER_PARTITION_START);

        view.write_at(0, b"slot0").unwrap();
        let device = view.into_inner();
        let mut probe = [0u8; 5];
        device.read_at(MEMBER_PARTITION_START, &mut probe).unwrap();
        assert_eq!(&probe, b"slot0");

        assert!(member_view(MemoryBlockDevice::new(1 << 21)).is_err());
    }

    #[test]
    fn foreign_and_hostile_tables_never_read_as_members() {
        let device = MemoryBlockDevice::new(member_image_len(1 << 20) as usize);
        write_member_gpt(&device, [1; 16], [2; 16]).unwrap();
        for (entry_at, header_at) in [
            (1024u64, 512u64),
            (device.len() - 33 * 512, device.len() - 512),
        ] {
            let mut entry = vec![0u8; 16384];
            device.read_at(entry_at, &mut entry).unwrap();
            entry[0] ^= 0xFF;
            device.write_at(entry_at, &entry).unwrap();
            let mut header = vec![0u8; 92];
            device.read_at(header_at, &mut header).unwrap();
            header[88..92].copy_from_slice(&crc32_ieee(&entry).to_le_bytes());
            header[16..20].fill(0);
            let crc = crc32_ieee(&header);
            header[16..20].copy_from_slice(&crc.to_le_bytes());
            device.write_at(header_at, &header).unwrap();
        }
        assert!(find_member_partition(&device).unwrap().is_none());

        let device = MemoryBlockDevice::new(member_image_len(1 << 20) as usize);
        write_member_gpt(&device, [1; 16], [2; 16]).unwrap();
        let mut entry = vec![0u8; 16384];
        device.read_at(1024, &mut entry).unwrap();
        entry.copy_within(0..128, 128);
        device.write_at(1024, &entry).unwrap();
        let mut header = vec![0u8; 92];
        device.read_at(512, &mut header).unwrap();
        header[88..92].copy_from_slice(&crc32_ieee(&entry).to_le_bytes());
        header[16..20].fill(0);
        let crc = crc32_ieee(&header);
        header[16..20].copy_from_slice(&crc.to_le_bytes());
        device.write_at(512, &header).unwrap();
        assert!(find_member_partition(&device).is_err());

        let device = MemoryBlockDevice::new(1 << 21);
        let mut header = vec![0u8; 92];
        header[0..8].copy_from_slice(b"EFI PART");
        header[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        header[12..16].copy_from_slice(&92u32.to_le_bytes());
        header[24..32].copy_from_slice(&1u64.to_le_bytes());
        header[72..80].copy_from_slice(&2u64.to_le_bytes());
        header[80..84].copy_from_slice(&u32::MAX.to_le_bytes());
        header[84..88].copy_from_slice(&128u32.to_le_bytes());
        let crc = crc32_ieee(&header);
        header[16..20].copy_from_slice(&crc.to_le_bytes());
        device.write_at(512, &header).unwrap();
        assert!(find_member_partition(&device).unwrap().is_none());

        for len in [0usize, 100, 511, 512, 600, 1024, 4096] {
            let device = MemoryBlockDevice::new(len);
            assert!(find_member_partition(&device).unwrap().is_none(), "{len}");
        }
    }

    #[test]
    fn golden_gpt_fixture_is_stable() {
        let device = MemoryBlockDevice::new(member_image_len(3 << 20) as usize);
        write_member_gpt(&device, [0x11; 16], [0x22; 16]).unwrap();
        let mut mbr = vec![0u8; 512];
        device.read_at(0, &mut mbr).unwrap();
        assert_eq!(hex(&mbr[446..462]), "00000200eeffffff0100000020200000");
        assert_eq!((mbr[510], mbr[511]), (0x55, 0xAA));
        assert!(mbr[..446].iter().all(|&b| b == 0));
        let mut header = vec![0u8; 92];
        device.read_at(512, &mut header).unwrap();
        assert_eq!(
            hex(&header),
            "4546492050415254000001005c000000d962e6df00000000010000000000000020200000\
             000000000008000000000000ff1f00000000000011111111111111111111111111111111\
             02000000000000008000000080000000705def0d"
        );
        let mut entry = vec![0u8; 128];
        device.read_at(1024, &mut entry).unwrap();
        assert_eq!(
            hex(&entry),
            "fd7e4e4cfb24d94da7f833b06fa6c85c22222222222222222222222222222222\
             0008000000000000ff1f00000000000000000000000000005300630061006c00\
             650046005300200070006f006f006c0020006d0065006d006200650072000000\
             0000000000000000000000000000000000000000000000000000000000000000"
        );
        let mut backup = vec![0u8; 92];
        device.read_at(device.len() - 512, &mut backup).unwrap();
        assert_eq!(
            hex(&backup),
            "4546492050415254000001005c00000060bf7056000000002020000000000000\
             01000000000000000008000000000000ff1f0000000000001111111111111111\
             111111111111111100200000000000008000000080000000705def0d"
        );

        let device = FourKn(MemoryBlockDevice::new(3 << 20));
        write_member_gpt(&device, [0x11; 16], [0x22; 16]).unwrap();
        let mut header = vec![0u8; 92];
        device.read_at(4096, &mut header).unwrap();
        assert_eq!(
            hex(&header),
            "4546492050415254000001005c0000002781479b000000000100000000000000\
             ff020000000000000001000000000000fa020000000000001111111111111111\
             111111111111111102000000000000008000000080000000cc1fdfe5"
        );
        let mut entry = vec![0u8; 128];
        device.read_at(8192, &mut entry).unwrap();
        assert_eq!(
            hex(&entry),
            "fd7e4e4cfb24d94da7f833b06fa6c85c22222222222222222222222222222222\
             0001000000000000fa0200000000000000000000000000005300630061006c00\
             650046005300200070006f006f006c0020006d0065006d006200650072000000\
             0000000000000000000000000000000000000000000000000000000000000000"
        );
    }
}
