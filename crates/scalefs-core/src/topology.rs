use crate::error::{Result, ScaleFsError};
use crate::format::{RecordKind, decode_record, encode_record};
use crate::layout::{
    DeviceId, Extent, Geometry, decode_extent, decode_geometry, encode_extent, encode_geometry,
};
use crate::wire::{Cursor, put_u16, put_u32, put_u64};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MemberState {
    Active,
    Removed,
}

impl MemberState {
    fn to_u8(self) -> u8 {
        match self {
            Self::Active => 0,
            Self::Removed => 1,
        }
    }

    fn from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Active),
            1 => Ok(Self::Removed),
            _ => Err(ScaleFsError::Unsupported(
                "pool member state unknown to this build",
            )),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TopologyMember {
    pub device_id: DeviceId,
    pub state: MemberState,
    pub newest_tx: u64,
    pub newest_commit: Extent,
    pub newest_summary: Extent,
    pub geometry: Geometry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Topology {
    pub tx_id: u64,
    pub topology_generation: u64,
    pub data_width: u16,
    pub parity_width: u16,
    pub mirror_width: u16,
    pub members: Vec<TopologyMember>,
    pub metadata_root_replicas: Vec<Extent>,
}

impl Topology {
    pub fn validate(&self) -> Result<()> {
        if self.tx_id == 0 {
            return Err(ScaleFsError::Corrupt("topology transaction id is zero"));
        }
        if self.topology_generation == 0 {
            return Err(ScaleFsError::Corrupt("topology generation is zero"));
        }
        if self.data_width == 0 || self.mirror_width == 0 {
            return Err(ScaleFsError::Corrupt("pool protection widths are invalid"));
        }
        let mirror_only = self.data_width == 1 && self.parity_width == 0;
        let parity = self.data_width >= 2
            && usize::from(self.data_width) <= crate::rs::MAX_DATA
            && self.parity_width >= 1
            && usize::from(self.parity_width) <= crate::rs::MAX_PARITY;
        if !mirror_only && !parity {
            return Err(ScaleFsError::Unsupported(
                "pool protection widths unknown to this build",
            ));
        }
        if parity && self.mirror_width <= self.parity_width {
            return Err(ScaleFsError::Corrupt(
                "mirror width must exceed the parity width",
            ));
        }
        if self.members.is_empty() {
            return Err(ScaleFsError::Corrupt("topology has no members"));
        }
        let active = self
            .members
            .iter()
            .filter(|member| member.state == MemberState::Active)
            .count();
        if usize::from(self.mirror_width) > active {
            return Err(ScaleFsError::Corrupt(
                "mirror width exceeds the active membership",
            ));
        }
        if self.mirror_width > 255 {
            return Err(ScaleFsError::Corrupt("mirror width exceeds 255"));
        }
        if self.metadata_root_replicas.is_empty() {
            return Err(ScaleFsError::Corrupt("topology has no root replica"));
        }
        if self.metadata_root_replicas.len() > usize::from(self.mirror_width) {
            return Err(ScaleFsError::Corrupt(
                "root replica count exceeds the mirror width",
            ));
        }
        for replica in &self.metadata_root_replicas {
            if replica.length == 0 {
                return Err(ScaleFsError::Corrupt("root replica extent is empty"));
            }
            let named = self.members.get(usize::from(replica.device_index));
            if !named.is_some_and(|member| member.state == MemberState::Active) {
                return Err(ScaleFsError::Corrupt("root replica names an absent member"));
            }
        }
        if self.members.len() > usize::from(u16::MAX) {
            return Err(ScaleFsError::InvalidArgument("too many pool members"));
        }
        let mut seen = std::collections::HashSet::new();
        for (index, member) in self.members.iter().enumerate() {
            if !seen.insert(member.device_id) {
                return Err(ScaleFsError::Corrupt("duplicate device id in topology"));
            }
            match member.state {
                MemberState::Removed => {
                    let zero = Extent {
                        device_index: 0,
                        offset: 0,
                        length: 0,
                    };
                    if member.newest_tx != 0
                        || member.newest_commit != zero
                        || member.newest_summary != zero
                    {
                        return Err(ScaleFsError::Corrupt(
                            "removed member still records a chain",
                        ));
                    }
                    continue;
                }
                MemberState::Active => {}
            }
            if member.newest_tx == 0 {
                return Err(ScaleFsError::Corrupt("member newest transaction is zero"));
            }
            if member.newest_tx > self.tx_id {
                return Err(ScaleFsError::Corrupt(
                    "member newest transaction is newer than the topology",
                ));
            }
            let index = index as u16;
            for extent in [member.newest_commit, member.newest_summary] {
                if extent.length == 0 {
                    return Err(ScaleFsError::Corrupt("member extent is empty"));
                }
                if extent.device_index != index {
                    return Err(ScaleFsError::Corrupt(
                        "member extent names the wrong device",
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn active_members(&self) -> impl Iterator<Item = u16> + '_ {
        self.members
            .iter()
            .enumerate()
            .filter(|(_, member)| member.state == MemberState::Active)
            .map(|(index, _)| index as u16)
    }

    pub fn member_index(&self, device_id: DeviceId) -> Option<u16> {
        self.members
            .iter()
            .position(|member| member.device_id == device_id)
            .map(|index| index as u16)
    }
}

const ZERO_EXTENT: Extent = Extent {
    device_index: 0,
    offset: 0,
    length: 0,
};

pub fn encode_topology(topology: &Topology) -> Result<Vec<u8>> {
    topology.validate()?;

    let mut payload = Vec::with_capacity(32 + topology.members.len() * 104);
    put_u64(&mut payload, topology.tx_id);
    put_u64(&mut payload, topology.topology_generation);
    put_u16(&mut payload, topology.data_width);
    put_u16(&mut payload, topology.parity_width);
    put_u16(&mut payload, topology.mirror_width);
    put_u16(&mut payload, 0);
    put_u16(&mut payload, topology.members.len() as u16);
    put_u16(&mut payload, 0);
    put_u32(&mut payload, 0);
    for member in &topology.members {
        payload.extend_from_slice(&member.device_id.0);
        payload.push(member.state.to_u8());
        payload.push(0);
        put_u16(&mut payload, 0);
        put_u64(&mut payload, member.newest_tx);
        encode_extent(&mut payload, member.newest_commit);
        encode_extent(&mut payload, member.newest_summary);
        encode_geometry(&mut payload, member.geometry);
        payload.extend_from_slice(&[0u8; 3]);
    }
    for replica in &topology.metadata_root_replicas {
        encode_extent(&mut payload, *replica);
    }
    for _ in topology.metadata_root_replicas.len()..usize::from(topology.mirror_width) {
        encode_extent(&mut payload, ZERO_EXTENT);
    }
    Ok(encode_record(RecordKind::Topology, &payload))
}

pub fn decode_topology(bytes: &[u8]) -> Result<Topology> {
    let record = decode_record(bytes)?;
    if record.kind != RecordKind::Topology {
        return Err(ScaleFsError::Corrupt("expected a topology record"));
    }

    let mut cursor = Cursor::new(&record.payload);
    let tx_id = cursor.take_u64()?;
    let topology_generation = cursor.take_u64()?;
    let data_width = cursor.take_u16()?;
    let parity_width = cursor.take_u16()?;
    let mirror_width = cursor.take_u16()?;
    let member_count = {
        let reserved = cursor.take_u16()?;
        let count = cursor.take_u16()?;
        if reserved != 0 || cursor.take_u16()? != 0 || cursor.take_u32()? != 0 {
            return Err(ScaleFsError::Corrupt("nonzero reserved field in topology"));
        }
        count
    };

    let mut members = Vec::with_capacity(usize::from(member_count));
    for _ in 0..member_count {
        let device_id = DeviceId(cursor.take_array::<16>()?);
        let state = MemberState::from_u8(cursor.take_u8()?)?;
        if cursor.take_u8()? != 0 || cursor.take_u16()? != 0 {
            return Err(ScaleFsError::Corrupt(
                "nonzero reserved field in topology member",
            ));
        }
        let newest_tx = cursor.take_u64()?;
        let newest_commit = decode_extent(&mut cursor)?;
        let newest_summary = decode_extent(&mut cursor)?;
        let geometry = decode_geometry(&mut cursor)?;
        if cursor.take(3)? != [0u8; 3] {
            return Err(ScaleFsError::Corrupt(
                "nonzero reserved field in topology member",
            ));
        }
        members.push(TopologyMember {
            device_id,
            state,
            newest_tx,
            newest_commit,
            newest_summary,
            geometry,
        });
    }
    let mut metadata_root_replicas = Vec::with_capacity(usize::from(mirror_width));
    let mut padding = false;
    for _ in 0..mirror_width {
        let replica = decode_extent(&mut cursor)?;
        if replica == ZERO_EXTENT {
            padding = true;
            continue;
        }
        if padding {
            return Err(ScaleFsError::Corrupt("root replica after padding"));
        }
        metadata_root_replicas.push(replica);
    }
    cursor.expect_end("topology payload has trailing bytes")?;

    let topology = Topology {
        tx_id,
        topology_generation,
        data_width,
        parity_width,
        mirror_width,
        members,
        metadata_root_replicas,
    };
    topology.validate()?;
    Ok(topology)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn member(index: u16, id_byte: u8, newest_tx: u64) -> TopologyMember {
        TopologyMember {
            device_id: DeviceId([id_byte; 16]),
            state: MemberState::Active,
            newest_tx,
            newest_commit: Extent {
                device_index: index,
                offset: 1 << 26,
                length: 117,
            },
            newest_summary: Extent {
                device_index: index,
                offset: (1 << 26) + 4096,
                length: 4096,
            },
            geometry: Geometry {
                logical_block_size: 4096,
                physical_block_size: 4096,
                zone_size: 1 << 26,
                zone_count: 1024,
                erase_granularity_zones: 1,
                sequential_write_required: true,
            },
        }
    }

    fn fixture_topology() -> Topology {
        Topology {
            tx_id: 5,
            topology_generation: 2,
            data_width: 1,
            parity_width: 0,
            mirror_width: 1,
            members: vec![member(0, 0x22, 5), member(1, 0x33, 4)],
            metadata_root_replicas: vec![Extent {
                device_index: 0,
                offset: (1 << 26) + 8192,
                length: 4096,
            }],
        }
    }

    #[test]
    fn round_trips() {
        let encoded = encode_topology(&fixture_topology()).unwrap();
        assert_eq!(decode_topology(&encoded).unwrap(), fixture_topology());
    }

    #[test]
    fn thin_root_replicas_round_trip() {
        let mut thin = fixture_topology();
        thin.mirror_width = 2;
        assert_eq!(thin.metadata_root_replicas.len(), 1);
        let encoded = encode_topology(&thin).unwrap();
        let mut full = thin.clone();
        full.metadata_root_replicas.push(Extent {
            device_index: 1,
            offset: (1 << 26) + 8192,
            length: 4096,
        });
        assert_eq!(
            encoded.len(),
            encode_topology(&full).unwrap().len(),
            "the replica list keeps its fixed size"
        );
        assert_eq!(decode_topology(&encoded).unwrap(), thin);
    }

    #[test]
    fn member_index_finds_members() {
        let topology = fixture_topology();
        assert_eq!(topology.member_index(DeviceId([0x22; 16])), Some(0));
        assert_eq!(topology.member_index(DeviceId([0x33; 16])), Some(1));
        assert_eq!(topology.member_index(DeviceId([0x44; 16])), None);
    }

    #[test]
    fn validation_rejects_bad_topologies() {
        let corrupt = |mutate: &dyn Fn(&mut Topology)| {
            let mut topology = fixture_topology();
            mutate(&mut topology);
            encode_topology(&topology)
        };

        for (name, mutation) in [
            (
                "zero tx",
                &(|t: &mut Topology| t.tx_id = 0) as &dyn Fn(&mut Topology),
            ),
            ("zero generation", &|t: &mut Topology| {
                t.topology_generation = 0
            }),
            ("zero data width", &|t: &mut Topology| t.data_width = 0),
            ("zero mirror width", &|t: &mut Topology| t.mirror_width = 0),
            ("no members", &|t: &mut Topology| t.members.clear()),
            ("duplicate ids", &|t: &mut Topology| {
                t.members[1].device_id = t.members[0].device_id
            }),
            ("zero member tx", &|t: &mut Topology| {
                t.members[0].newest_tx = 0
            }),
            ("member tx too new", &|t: &mut Topology| {
                t.members[1].newest_tx = t.tx_id + 1
            }),
            ("empty member extent", &|t: &mut Topology| {
                t.members[0].newest_commit.length = 0
            }),
            ("extent on wrong device", &|t: &mut Topology| {
                t.members[1].newest_summary.device_index = 0
            }),
            ("mirror width beyond membership", &|t: &mut Topology| {
                t.mirror_width = 3
            }),
            ("no root replicas", &|t: &mut Topology| {
                t.metadata_root_replicas.clear()
            }),
            (
                "root replicas beyond the mirror width",
                &|t: &mut Topology| {
                    let extra = t.metadata_root_replicas[0];
                    t.metadata_root_replicas.push(extra)
                },
            ),
            ("empty root replica", &|t: &mut Topology| {
                t.metadata_root_replicas[0].length = 0
            }),
            ("root replica on absent member", &|t: &mut Topology| {
                t.metadata_root_replicas[0].device_index = 9
            }),
        ] {
            assert!(
                matches!(corrupt(mutation), Err(ScaleFsError::Corrupt(_))),
                "{name}"
            );
        }

        assert!(matches!(
            corrupt(&|t| t.data_width = 2),
            Err(ScaleFsError::Unsupported(_))
        ));
        assert!(matches!(
            corrupt(&|t| t.parity_width = 1),
            Err(ScaleFsError::Unsupported(_))
        ));
    }

    fn parity_topology() -> Topology {
        Topology {
            tx_id: 7,
            topology_generation: 3,
            data_width: 3,
            parity_width: 1,
            mirror_width: 2,
            members: vec![member(0, 0x22, 7), member(1, 0x33, 7), member(2, 0x44, 6)],
            metadata_root_replicas: vec![
                Extent {
                    device_index: 0,
                    offset: (1 << 26) + 8192,
                    length: 4096,
                },
                Extent {
                    device_index: 1,
                    offset: (1 << 26) + 8192,
                    length: 4096,
                },
            ],
        }
    }

    #[test]
    fn parity_widths_round_trip_and_validate() {
        let encoded = encode_topology(&parity_topology()).unwrap();
        assert_eq!(decode_topology(&encoded).unwrap(), parity_topology());

        let corrupt = |mutate: &dyn Fn(&mut Topology)| {
            let mut topology = parity_topology();
            mutate(&mut topology);
            encode_topology(&topology)
        };
        assert!(matches!(
            corrupt(&|t| t.mirror_width = 1),
            Err(ScaleFsError::Corrupt(_))
        ));
        assert!(matches!(
            corrupt(&|t| t.data_width = 65),
            Err(ScaleFsError::Unsupported(_))
        ));
        assert!(matches!(
            corrupt(&|t| t.parity_width = 4),
            Err(ScaleFsError::Unsupported(_))
        ));
        assert!(matches!(
            corrupt(&|t| t.parity_width = 0),
            Err(ScaleFsError::Unsupported(_))
        ));
    }

    #[test]
    fn golden_parity_topology_fixture_is_stable() {
        let encoded = encode_topology(&parity_topology()).unwrap();
        assert_eq!(
            hex(&encoded),
            "5363616c654653000100000007000000740100000000000059a492d400000000070000000000000003000000000000000300010002000000030000000000000022222222222222222222222222222222000000000700000000000000000000000000000400000000750000000000000000000000001000040000000000100000000000000010000000100000000000040000000000040000000000000100000001000000333333333333333333333333333333330000000007000000000000000100000000000004000000007500000000000000010000000010000400000000001000000000000000100000001000000000000400000000000400000000000001000000010000004444444444444444444444444444444400000000060000000000000002000000000000040000000075000000000000000200000000100004000000000010000000000000001000000010000000000004000000000004000000000000010000000100000000000000002000040000000000100000000000000100000000200004000000000010000000000000"
        );
        assert_eq!(decode_topology(&encoded).unwrap(), parity_topology());
    }

    #[test]
    fn decode_rejects_reserved_state_and_kind_violations() {
        let encoded = encode_topology(&fixture_topology()).unwrap();

        let corrupt = |mutate: &dyn Fn(&mut Vec<u8>)| {
            let record = decode_record(&encoded).unwrap();
            let mut payload = record.payload;
            mutate(&mut payload);
            decode_topology(&encode_record(RecordKind::Topology, &payload))
        };
        let member_base = |index: usize| 32 + index * 100;

        assert!(matches!(
            corrupt(&|p| p[22] = 1),
            Err(ScaleFsError::Corrupt(_))
        ));
        assert!(matches!(
            corrupt(&|p| p[member_base(0) + 16] = 3),
            Err(ScaleFsError::Unsupported(_))
        ));
        assert!(matches!(
            corrupt(&|p| p[member_base(0) + 17] = 1),
            Err(ScaleFsError::Corrupt(_))
        ));
        assert!(matches!(
            corrupt(&|p| p[member_base(1) + 97] = 1),
            Err(ScaleFsError::Corrupt(_))
        ));
        assert!(matches!(
            corrupt(&|p| p[24] = 3),
            Err(ScaleFsError::Corrupt(_))
        ));
        assert!(matches!(
            corrupt(&|p| p[24] = 1),
            Err(ScaleFsError::Corrupt(_))
        ));

        let commit_shaped = encode_record(RecordKind::Commit, b"x");
        assert!(decode_topology(&commit_shaped).is_err());
    }

    #[test]
    fn golden_topology_fixture_is_stable() {
        let encoded = encode_topology(&fixture_topology()).unwrap();
        assert_eq!(
            hex(&encoded),
            "5363616c654653000100000007000000fc0000000000000077e571a400000000050000000000000002000000000000000100000001000000020000000000000022222222222222222222222222222222000000000500000000000000000000000000000400000000750000000000000000000000001000040000000000100000000000000010000000100000000000040000000000040000000000000100000001000000333333333333333333333333333333330000000004000000000000000100000000000004000000007500000000000000010000000010000400000000001000000000000000100000001000000000000400000000000400000000000001000000010000000000000000200004000000000010000000000000"
        );
        assert_eq!(decode_topology(&encoded).unwrap(), fixture_topology());
    }

    #[test]
    fn golden_tombstone_topology_fixture_is_stable() {
        let tombstone = TopologyMember {
            state: MemberState::Removed,
            newest_tx: 0,
            newest_commit: Extent {
                device_index: 0,
                offset: 0,
                length: 0,
            },
            newest_summary: Extent {
                device_index: 0,
                offset: 0,
                length: 0,
            },
            ..member(1, 0x33, 0)
        };
        let topology = Topology {
            tx_id: 9,
            topology_generation: 4,
            data_width: 1,
            parity_width: 0,
            mirror_width: 2,
            members: vec![member(0, 0x22, 9), tombstone, member(2, 0x44, 9)],
            metadata_root_replicas: vec![
                Extent {
                    device_index: 0,
                    offset: (1 << 26) + 8192,
                    length: 4096,
                },
                Extent {
                    device_index: 2,
                    offset: (1 << 26) + 8192,
                    length: 4096,
                },
            ],
        };
        let encoded = encode_topology(&topology).unwrap();
        assert_eq!(
            hex(&encoded),
            "5363616c6546530001000000070000007401000000000000c39373e600000000090000000000000004000000000000000100000002000000030000000000000022222222222222222222222222222222000000000900000000000000000000000000000400000000750000000000000000000000001000040000000000100000000000000010000000100000000000040000000000040000000000000100000001000000333333333333333333333333333333330100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000001000000000000400000000000400000000000001000000010000004444444444444444444444444444444400000000090000000000000002000000000000040000000075000000000000000200000000100004000000000010000000000000001000000010000000000004000000000004000000000000010000000100000000000000002000040000000000100000000000000200000000200004000000000010000000000000"
        );
        assert_eq!(decode_topology(&encoded).unwrap(), topology);
    }
}
