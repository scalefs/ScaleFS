
use crate::device::{BlockDevice, ReadOnly};
use crate::dirent::{dirent_hash, fold_name};
use crate::error::{Result, ScaleFsError};
use crate::format::{RecordKind, decode_record};
use crate::layout::{CaseSensitivity, DeviceId, Extent, Geometry, PoolId, superblock_slots};
use crate::records::{
    Commit, FEATURE_INCOMPAT_MULTI_DEVICE, Superblock, decode_commit, decode_superblock,
};
use crate::topology::{MemberState, Topology, decode_topology};
use crate::tree::{
    DirEntry, ITEM_DIRENT, ITEM_INODE, InodeAttrs, MetadataKey, MetadataValue, ROOT_INODE,
    decode_internal_record, decode_leaf_record,
};

#[derive(Debug, Default, Clone)]
pub struct SalvageOptions {
    pub view_tx: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rung {
    StrictEquivalent,
    PartialRoster,
    CommitRoot,
}

#[derive(Debug, Clone)]
pub enum SlotHealth {
    Valid,
    Corrupt(&'static str),
    Unreadable(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceRole {
    Member(u16),
    Orphan,
    Shadowed,
    Foreign,
    Unidentified,
}

#[derive(Debug, Clone)]
pub struct DeviceReport {
    pub pool_id: Option<PoolId>,
    pub device_id: Option<DeviceId>,
    pub slots: [SlotHealth; 2],
    pub newest_tx: Option<u64>,
    pub role: DeviceRole,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct MissingMember {
    pub member_index: u16,
    pub device_id: DeviceId,
    pub newest_tx: u64,
    pub geometry: Geometry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateKind {
    Roster,
    Commit,
}

#[derive(Debug, Clone)]
pub struct ViewCandidate {
    pub tx: u64,
    pub kind: CandidateKind,
    pub adopted: bool,
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AssemblyReport {
    pub pool_id: Option<PoolId>,
    pub label: Option<String>,
    pub feature_compat: u64,
    pub feature_ro_compat: u64,
    pub feature_incompat: u64,
    pub unknown_incompat: bool,
    pub unknown_ro_compat: bool,
    pub rung: Option<Rung>,
    pub view_tx: Option<u64>,
    pub devices: Vec<DeviceReport>,
    pub missing: Vec<MissingMember>,
    pub candidates: Vec<ViewCandidate>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadFailure {
    AbsentMember(u16),
    Io(u16, String),
    Corrupt(u16, &'static str),
}

impl std::fmt::Display for ReadFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadFailure::AbsentMember(index) => write!(f, "member {index} absent"),
            ReadFailure::Io(index, error) => write!(f, "member {index} I/O: {error}"),
            ReadFailure::Corrupt(index, reason) => write!(f, "member {index}: {reason}"),
        }
    }
}

const MAX_RECORD_READ: u64 = 128 << 20;

pub struct Salvage<D: BlockDevice> {
    devices: Vec<ReadOnly<D>>,
    member_map: Vec<Option<usize>>,
    root: Vec<Extent>,
    live_root: Vec<Extent>,
    dirent_seed: u64,
    case_sensitivity: CaseSensitivity,
    report: AssemblyReport,
}

struct ChainHead {
    device_slot: usize,
    tx: u64,
    commit: Commit,
    roster: Option<Topology>,
}

struct Probe {
    superblock: Option<Superblock>,
    heads: Vec<ChainHead>,
    newest_tx: Option<u64>,
}

impl<D: BlockDevice> Salvage<D> {
    pub fn assemble(devices: Vec<D>) -> Result<Salvage<D>> {
        Salvage::assemble_with(devices, &SalvageOptions::default())
    }

    pub fn assemble_at(devices: Vec<D>, view_tx: u64) -> Result<Salvage<D>> {
        Salvage::assemble_with(
            devices,
            &SalvageOptions {
                view_tx: Some(view_tx),
            },
        )
    }

    pub fn assemble_with(devices: Vec<D>, options: &SalvageOptions) -> Result<Salvage<D>> {
        let devices: Vec<ReadOnly<D>> = devices.into_iter().map(ReadOnly::new).collect();
        let mut report = AssemblyReport {
            pool_id: None,
            label: None,
            feature_compat: 0,
            feature_ro_compat: 0,
            feature_incompat: 0,
            unknown_incompat: false,
            unknown_ro_compat: false,
            rung: None,
            view_tx: None,
            devices: Vec::new(),
            missing: Vec::new(),
            candidates: Vec::new(),
            notes: Vec::new(),
        };

        let mut probes: Vec<Probe> = Vec::new();
        for device in &devices {
            let mut slots = [SlotHealth::Valid, SlotHealth::Valid];
            let mut decoded: Vec<(usize, Superblock)> = Vec::new();
            for (which, offset) in superblock_slots(device.len()).into_iter().enumerate() {
                let mut block = vec![0u8; 4096];
                match device.read_at(offset, &mut block) {
                    Err(error) => slots[which] = SlotHealth::Unreadable(error.to_string()),
                    Ok(()) => match decode_superblock(&block) {
                        Ok(superblock) => {
                            slots[which] = SlotHealth::Valid;
                            decoded.push((which, superblock));
                        }
                        Err(error) => slots[which] = SlotHealth::Corrupt(corrupt_reason(&error)),
                    },
                }
            }
            let mut notes = Vec::new();
            if let [(_, a), (_, b)] = &decoded[..]
                && (a.pool_id != b.pool_id || a.device_id != b.device_id)
            {
                notes.push(
                    "the two superblock slots disagree on identity; using the head slot"
                        .to_string(),
                );
            }
            let superblock = decoded.first().map(|(_, sb)| sb.clone());
            report.devices.push(DeviceReport {
                pool_id: superblock.as_ref().map(|sb| sb.pool_id),
                device_id: superblock.as_ref().map(|sb| sb.device_id),
                slots,
                newest_tx: None,
                role: if superblock.is_some() {
                    DeviceRole::Orphan
                } else {
                    DeviceRole::Unidentified
                },
                notes,
            });
            probes.push(Probe {
                superblock,
                heads: Vec::new(),
                newest_tx: None,
            });
        }

        let Some(target) = probes
            .iter()
            .find_map(|p| p.superblock.as_ref().map(|sb| sb.pool_id))
        else {
            return Err(ScaleFsError::Corrupt(
                "no supplied device carries a decodable ScaleFS superblock",
            ));
        };
        report.pool_id = Some(target);
        for (slot, probe) in probes.iter_mut().enumerate() {
            let Some(sb) = &probe.superblock else {
                continue;
            };
            if sb.pool_id != target {
                report.devices[slot].role = DeviceRole::Foreign;
                probe.superblock = None;
            }
        }

        let mut dirent_seed = 0;
        let mut case_sensitivity = CaseSensitivity::Sensitive;
        let mut saw_pool_facts = false;
        for probe in &probes {
            let Some(sb) = &probe.superblock else {
                continue;
            };
            report.feature_compat |= sb.feature_compat;
            report.feature_ro_compat |= sb.feature_ro_compat;
            report.feature_incompat |= sb.feature_incompat;
            if !saw_pool_facts {
                report.label = Some(sb.label.clone());
                dirent_seed = sb.dirent_hash_seed;
                case_sensitivity = sb.case_sensitivity;
                saw_pool_facts = true;
            } else if sb.dirent_hash_seed != dirent_seed {
                report
                    .notes
                    .push("members disagree on the directory hash seed".to_string());
            }
        }
        let unknown_incompat = report.feature_incompat & !crate::records::FEATURE_INCOMPAT_KNOWN;
        report.unknown_incompat = unknown_incompat != 0;
        report.unknown_ro_compat =
            report.feature_ro_compat & !crate::records::FEATURE_RO_COMPAT_KNOWN != 0;
        if report.unknown_incompat {
            report.notes.push(format!(
                "unknown incompatible feature bits {unknown_incompat:#x}: this build reports \
                 identity only and does not interpret the pool's contents",
            ));
            return Ok(Salvage {
                devices,
                member_map: Vec::new(),
                root: Vec::new(),
                live_root: Vec::new(),
                dirent_seed,
                case_sensitivity,
                report,
            });
        }

        for (slot, probe) in probes.iter_mut().enumerate() {
            if probe.superblock.is_none() {
                continue;
            }
            let device = &devices[slot];
            let mut heads: Vec<ChainHead> = Vec::new();
            for offset in superblock_slots(device.len()) {
                let mut block = vec![0u8; 4096];
                if device.read_at(offset, &mut block).is_err() {
                    continue;
                }
                let Ok(superblock) = decode_superblock(&block) else {
                    continue;
                };
                let Some(commit_extent) = superblock.newest_commit else {
                    continue;
                };
                let Ok(bytes) = read_local_record(device, commit_extent, &[RecordKind::Commit])
                else {
                    continue;
                };
                let Ok(commit) = decode_commit(&bytes) else {
                    continue;
                };
                let mut roster = None;
                if let Some(aux) = commit.aux_root {
                    match read_local_record(device, aux, &[RecordKind::Topology])
                        .and_then(|bytes| decode_topology(&bytes))
                    {
                        Ok(topology) => {
                            if topology.tx_id != commit.tx_id {
                                report.devices[slot].notes.push(format!(
                                    "the tx {} commit's roster carries tx {}",
                                    commit.tx_id, topology.tx_id,
                                ));
                            }
                            roster = Some(topology);
                        }
                        Err(_) => report.devices[slot].notes.push(format!(
                            "the tx {} commit's roster did not decode",
                            commit.tx_id,
                        )),
                    }
                }
                if heads.iter().any(|head| head.tx == commit.tx_id) {
                    continue;
                }
                heads.push(ChainHead {
                    device_slot: slot,
                    tx: commit.tx_id,
                    commit,
                    roster,
                });
            }
            probe.newest_tx = heads.iter().map(|head| head.tx).max();
            report.devices[slot].newest_tx = probe.newest_tx;
            probe.heads = heads;
        }
        let mut kept: std::collections::BTreeMap<DeviceId, usize> =
            std::collections::BTreeMap::new();
        for (slot, probe) in probes.iter().enumerate() {
            let Some(sb) = &probe.superblock else {
                continue;
            };
            match kept.get(&sb.device_id) {
                None => {
                    kept.insert(sb.device_id, slot);
                }
                Some(&other) => {
                    let freshness = |slot: usize| {
                        let probe = &probes[slot];
                        (
                            probe
                                .superblock
                                .as_ref()
                                .map_or(0, |sb| sb.topology_generation),
                            probe.newest_tx.unwrap_or(0),
                        )
                    };
                    let (winner, loser) = if freshness(slot) > freshness(other) {
                        (slot, other)
                    } else {
                        (other, slot)
                    };
                    kept.insert(sb.device_id, winner);
                    report.devices[loser].role = DeviceRole::Shadowed;
                    report.devices[loser]
                        .notes
                        .push("a fresher duplicate of this device was supplied".to_string());
                }
            }
        }
        let device_for = |id: DeviceId| kept.get(&id).copied();

        let mut heads: Vec<&ChainHead> = probes
            .iter()
            .enumerate()
            .filter(|(slot, _)| {
                !matches!(
                    report.devices[*slot].role,
                    DeviceRole::Shadowed | DeviceRole::Foreign
                )
            })
            .flat_map(|(_, probe)| probe.heads.iter())
            .collect();
        heads.sort_by_key(|head| std::cmp::Reverse(head.tx));

        let multi = report.feature_incompat & FEATURE_INCOMPAT_MULTI_DEVICE != 0;

        let mut roster_candidates: Vec<&ChainHead> = Vec::new();
        for head in &heads {
            if head.roster.is_some() && !roster_candidates.iter().any(|c| c.tx == head.tx) {
                roster_candidates.push(head);
            }
        }

        let wanted = |tx: u64| options.view_tx.is_none_or(|want| want == tx);

        type Adopted = (Rung, u64, Vec<Option<usize>>, Vec<Extent>);
        let mut adopted: Option<Adopted> = None;

        if multi {
            for head in &roster_candidates {
                let roster = head
                    .roster
                    .as_ref()
                    .expect("roster candidates have rosters");
                if !wanted(head.tx) {
                    report.candidates.push(ViewCandidate {
                        tx: head.tx,
                        kind: CandidateKind::Roster,
                        adopted: false,
                        note: Some("skipped: a different view was requested".to_string()),
                    });
                    continue;
                }
                if adopted.is_some() {
                    report.candidates.push(ViewCandidate {
                        tx: head.tx,
                        kind: CandidateKind::Roster,
                        adopted: false,
                        note: None,
                    });
                    continue;
                }
                let mut map: Vec<Option<usize>> = Vec::new();
                let mut absent = 0u32;
                let mut chain_failures = 0u32;
                for member in &roster.members {
                    if member.state == MemberState::Removed {
                        map.push(None);
                        continue;
                    }
                    match device_for(member.device_id) {
                        None => {
                            map.push(None);
                            absent += 1;
                        }
                        Some(slot) => {
                            map.push(Some(slot));
                            let commit_ok = read_local_record(
                                &devices[slot],
                                member.newest_commit,
                                &[RecordKind::Commit],
                            )
                            .and_then(|bytes| decode_commit(&bytes))
                            .map(|commit| commit.tx_id == member.newest_tx)
                            .unwrap_or(false);
                            let summary_ok = read_local_record(
                                &devices[slot],
                                member.newest_summary,
                                &[RecordKind::ZoneSummary],
                            )
                            .is_ok();
                            if !commit_ok || !summary_ok {
                                chain_failures += 1;
                            }
                        }
                    }
                }
                let root_ok = roster.metadata_root_replicas.iter().any(|extent| {
                    read_mapped_record(
                        &devices,
                        &map,
                        *extent,
                        &[
                            RecordKind::MetadataLeaf,
                            RecordKind::MetadataInternal,
                            RecordKind::MetadataInternalMirrored,
                        ],
                    )
                    .is_ok()
                });
                if !root_ok {
                    report.candidates.push(ViewCandidate {
                        tx: head.tx,
                        kind: CandidateKind::Roster,
                        adopted: false,
                        note: Some("no metadata root replica decodes".to_string()),
                    });
                    continue;
                }
                let rung = if absent == 0 && chain_failures == 0 {
                    Rung::StrictEquivalent
                } else {
                    Rung::PartialRoster
                };
                let note = match (absent, chain_failures) {
                    (0, 0) => None,
                    (a, 0) => Some(format!("{a} member(s) absent")),
                    (0, c) => Some(format!("{c} member chain(s) do not validate")),
                    (a, c) => Some(format!(
                        "{a} member(s) absent, {c} member chain(s) do not validate"
                    )),
                };
                report.candidates.push(ViewCandidate {
                    tx: head.tx,
                    kind: CandidateKind::Roster,
                    adopted: true,
                    note,
                });
                for (index, member) in roster.members.iter().enumerate() {
                    if member.state == MemberState::Active && map[index].is_none() {
                        report.missing.push(MissingMember {
                            member_index: index as u16,
                            device_id: member.device_id,
                            newest_tx: member.newest_tx,
                            geometry: member.geometry,
                        });
                    }
                }
                adopted = Some((rung, head.tx, map, roster.metadata_root_replicas.clone()));
            }

            if adopted.is_none()
                && let Some(map_source) = roster_candidates.first()
            {
                let roster = map_source.roster.as_ref().expect("roster candidate");
                let map: Vec<Option<usize>> = roster
                    .members
                    .iter()
                    .map(|member| {
                        (member.state == MemberState::Active)
                            .then(|| device_for(member.device_id))
                            .flatten()
                    })
                    .collect();
                for head in &heads {
                    if !wanted(head.tx) || adopted.is_some() {
                        continue;
                    }
                    let root_ok = read_mapped_record(
                        &devices,
                        &map,
                        head.commit.metadata_root,
                        &[
                            RecordKind::MetadataLeaf,
                            RecordKind::MetadataInternal,
                            RecordKind::MetadataInternalMirrored,
                        ],
                    )
                    .is_ok();
                    report.candidates.push(ViewCandidate {
                        tx: head.tx,
                        kind: CandidateKind::Commit,
                        adopted: root_ok,
                        note: root_ok
                            .then(|| {
                                format!(
                                    "root via a commit; index map borrowed from the tx {} roster",
                                    roster.tx_id
                                )
                            })
                            .or(Some("the commit's root does not decode".to_string())),
                    });
                    if root_ok {
                        adopted = Some((
                            Rung::CommitRoot,
                            head.tx,
                            map.clone(),
                            vec![head.commit.metadata_root],
                        ));
                    }
                }
            }
            if roster_candidates.is_empty() {
                report.notes.push(
                    "multi-device pool with no decodable roster on any member: the member \
                     index map cannot be recovered; reporting identity and chains only"
                        .to_string(),
                );
            }
        } else {
            for head in &heads {
                if !wanted(head.tx) {
                    report.candidates.push(ViewCandidate {
                        tx: head.tx,
                        kind: CandidateKind::Commit,
                        adopted: false,
                        note: Some("skipped: a different view was requested".to_string()),
                    });
                    continue;
                }
                if adopted.is_some() {
                    report.candidates.push(ViewCandidate {
                        tx: head.tx,
                        kind: CandidateKind::Commit,
                        adopted: false,
                        note: None,
                    });
                    continue;
                }
                let map = vec![Some(head.device_slot)];
                let root_ok = read_mapped_record(
                    &devices,
                    &map,
                    head.commit.metadata_root,
                    &[
                        RecordKind::MetadataLeaf,
                        RecordKind::MetadataInternal,
                        RecordKind::MetadataInternalMirrored,
                    ],
                )
                .is_ok();
                let summary_ok = read_local_record(
                    &devices[head.device_slot],
                    head.commit.allocator_summary,
                    &[RecordKind::ZoneSummary],
                )
                .is_ok();
                report.candidates.push(ViewCandidate {
                    tx: head.tx,
                    kind: CandidateKind::Commit,
                    adopted: root_ok,
                    note: (!root_ok).then(|| "the commit's root does not decode".to_string()),
                });
                if root_ok {
                    let newest = heads.first().map(|h| h.tx) == Some(head.tx);
                    let rung = if newest && summary_ok {
                        Rung::StrictEquivalent
                    } else {
                        Rung::PartialRoster
                    };
                    adopted = Some((rung, head.tx, map, vec![head.commit.metadata_root]));
                }
            }
        }

        let (member_map, root) = match adopted {
            Some((rung, tx, map, root)) => {
                report.rung = Some(rung);
                report.view_tx = Some(tx);
                for (index, slot) in map.iter().enumerate() {
                    if let Some(slot) = *slot {
                        report.devices[slot].role = DeviceRole::Member(index as u16);
                    }
                }
                (map, root)
            }
            None => {
                if !report.unknown_incompat && report.candidates.is_empty() && multi {
                } else if report.rung.is_none() && !report.candidates.is_empty() {
                    report
                        .notes
                        .push("no candidate view could be adopted".to_string());
                }
                (Vec::new(), Vec::new())
            }
        };

        Ok(Salvage {
            devices,
            member_map,
            live_root: root.clone(),
            root,
            dirent_seed,
            case_sensitivity,
            report,
        })
    }

    pub fn report(&self) -> &AssemblyReport {
        &self.report
    }

    pub fn has_view(&self) -> bool {
        !self.root.is_empty()
    }

    pub fn root_extents(&self) -> &[Extent] {
        &self.root
    }

    pub(crate) fn read_record_any(
        &self,
        extents: &[Extent],
        kinds: &[RecordKind],
    ) -> std::result::Result<(usize, Vec<u8>), Vec<ReadFailure>> {
        let mut failures = Vec::new();
        for (index, extent) in extents.iter().enumerate() {
            match read_one_mapped(&self.devices, &self.member_map, *extent, kinds) {
                Ok(bytes) => return Ok((index, bytes)),
                Err(failure) => failures.push(failure),
            }
        }
        Err(failures)
    }

    pub(crate) fn read_record_copy(
        &self,
        extent: Extent,
        kinds: &[RecordKind],
    ) -> std::result::Result<Vec<u8>, ReadFailure> {
        read_one_mapped(&self.devices, &self.member_map, extent, kinds)
    }


    fn load_node(
        &self,
        extents: &[Extent],
        first_key: MetadataKey,
        last_key: MetadataKey,
    ) -> std::result::Result<Node, Damage> {
        match self.read_record_any(
            extents,
            &[
                RecordKind::MetadataLeaf,
                RecordKind::MetadataInternal,
                RecordKind::MetadataInternalMirrored,
            ],
        ) {
            Err(reasons) => Err(Damage {
                extents: extents.to_vec(),
                reasons,
                first_key,
                last_key,
            }),
            Ok((_, bytes)) => {
                let decoded = if decode_record(&bytes)
                    .map(|record| record.kind == RecordKind::MetadataLeaf)
                    .unwrap_or(false)
                {
                    decode_leaf_record(&bytes).map(Node::Leaf)
                } else {
                    decode_internal_record(&bytes).map(Node::Internal)
                };
                decoded.map_err(|error| Damage {
                    extents: extents.to_vec(),
                    reasons: vec![ReadFailure::Corrupt(
                        extents.first().map_or(0, |e| e.device_index),
                        corrupt_reason(&error),
                    )],
                    first_key,
                    last_key,
                })
            }
        }
    }

    pub fn walk(&self, visit: &mut dyn FnMut(WalkEvent<'_>)) -> Result<()> {
        if !self.has_view() {
            return Err(ScaleFsError::Unsupported(
                "no view was adopted; nothing to walk",
            ));
        }
        self.walk_node(
            &self.root,
            MetadataKey::MIN,
            MetadataKey::MAX,
            None,
            visit,
            0,
        );
        Ok(())
    }

    pub(crate) fn walk_range(
        &self,
        start: MetadataKey,
        end: MetadataKey,
        visit: &mut dyn FnMut(WalkEvent<'_>),
    ) -> Result<()> {
        if !self.has_view() {
            return Err(ScaleFsError::Unsupported(
                "no view was adopted; nothing to walk",
            ));
        }
        self.walk_node(
            &self.root,
            MetadataKey::MIN,
            MetadataKey::MAX,
            Some((start, end)),
            visit,
            0,
        );
        Ok(())
    }

    fn walk_node(
        &self,
        extents: &[Extent],
        first_key: MetadataKey,
        last_key: MetadataKey,
        window: Option<(MetadataKey, MetadataKey)>,
        visit: &mut dyn FnMut(WalkEvent<'_>),
        depth: u32,
    ) {
        if let Some((start, end)) = window
            && (last_key < start || first_key > end)
        {
            return;
        }
        if depth > MAX_TREE_DEPTH {
            visit(WalkEvent::Lost(&Damage {
                extents: extents.to_vec(),
                reasons: vec![ReadFailure::Corrupt(
                    extents.first().map_or(0, |e| e.device_index),
                    "tree deeper than any writer produces",
                )],
                first_key,
                last_key,
            }));
            return;
        }
        match self.load_node(extents, first_key, last_key) {
            Err(damage) => visit(WalkEvent::Lost(&damage)),
            Ok(Node::Leaf(items)) => {
                for (key, value) in &items {
                    if let Some((start, end)) = window
                        && (*key < start || *key > end)
                    {
                        continue;
                    }
                    visit(WalkEvent::Item(key, value));
                }
            }
            Ok(Node::Internal(children)) => {
                for (index, (separator, child)) in children.iter().enumerate() {
                    let child_last = children
                        .get(index + 1)
                        .map(|(next, _)| previous_key(*next))
                        .unwrap_or(last_key);
                    self.walk_node(child, *separator, child_last, window, visit, depth + 1);
                }
            }
        }
    }

    pub fn read_dir(&self, dir: u64) -> Result<DirListing> {
        let mut listing = DirListing {
            entries: Vec::new(),
            damage: Vec::new(),
        };
        let start = MetadataKey {
            object_id: dir,
            item_type: ITEM_DIRENT,
            offset: 0,
        };
        let end = MetadataKey {
            object_id: dir,
            item_type: ITEM_DIRENT,
            offset: u64::MAX,
        };
        self.walk_range(start, end, &mut |event| match event {
            WalkEvent::Item(_, MetadataValue::DirEntries(entries)) => {
                listing.entries.extend(entries.iter().cloned());
            }
            WalkEvent::Item(..) => {}
            WalkEvent::Lost(damage) => listing.damage.push(damage.clone()),
        })?;
        listing.entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(listing)
    }

    pub fn stat(&self, object: u64) -> Result<StatOutcome> {
        let key = MetadataKey {
            object_id: object,
            item_type: ITEM_INODE,
            offset: 0,
        };
        let mut found = None;
        let mut damage = Vec::new();
        self.walk_range(key, key, &mut |event| match event {
            WalkEvent::Item(_, MetadataValue::Inode(attrs)) => found = Some(*attrs),
            WalkEvent::Item(..) => {}
            WalkEvent::Lost(lost) => damage.push(lost.clone()),
        })?;
        Ok(match (found, damage.is_empty()) {
            (Some(attrs), _) => StatOutcome::Found(attrs),
            (None, true) => StatOutcome::Missing,
            (None, false) => StatOutcome::Lost(damage),
        })
    }

    pub fn resolve_path(&self, path: &str) -> Result<PathOutcome> {
        let mut object = ROOT_INODE;
        for component in path.split(['/', '\\']).filter(|c| !c.is_empty()) {
            let hash = dirent_hash(
                self.dirent_seed,
                &fold_name(self.case_sensitivity, component),
            );
            let key = MetadataKey {
                object_id: object,
                item_type: ITEM_DIRENT,
                offset: hash,
            };
            let mut next = None;
            let mut damage = Vec::new();
            let folded = fold_name(self.case_sensitivity, component);
            self.walk_range(key, key, &mut |event| match event {
                WalkEvent::Item(_, MetadataValue::DirEntries(entries)) => {
                    for entry in entries {
                        if fold_name(self.case_sensitivity, &entry.name) == folded {
                            next = Some(entry.inode);
                        }
                    }
                }
                WalkEvent::Item(..) => {}
                WalkEvent::Lost(lost) => damage.push(lost.clone()),
            })?;
            match (next, damage.is_empty()) {
                (Some(inode), _) => object = inode,
                (None, true) => return Ok(PathOutcome::Missing),
                (None, false) => return Ok(PathOutcome::Lost(damage)),
            }
        }
        Ok(PathOutcome::Found(object))
    }

    pub fn survey(&self) -> Result<Survey> {
        let mut survey = Survey {
            items: 0,
            files: 0,
            directories: 0,
            damage: Vec::new(),
            disconnected: Vec::new(),
        };
        let mut inodes: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        let mut referenced: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        self.walk(&mut |event| match event {
            WalkEvent::Item(key, value) => {
                survey.items += 1;
                match value {
                    MetadataValue::Inode(attrs) => {
                        inodes.insert(key.object_id);
                        if attrs.is_dir() {
                            survey.directories += 1;
                        } else {
                            survey.files += 1;
                        }
                    }
                    MetadataValue::DirEntries(entries) => {
                        referenced.extend(entries.iter().map(|entry| entry.inode));
                    }
                    _ => {}
                }
            }
            WalkEvent::Lost(damage) => survey.damage.push(damage.clone()),
        })?;
        referenced.insert(ROOT_INODE);
        survey.disconnected = inodes.difference(&referenced).copied().collect();
        Ok(survey)
    }
}

impl<D: BlockDevice> Salvage<D> {

    pub fn salvage_file(&self, object: u64, sink: &mut dyn std::io::Write) -> Result<FileReport> {
        let attrs = match self.stat(object)? {
            StatOutcome::Found(attrs) => attrs,
            StatOutcome::Missing => {
                return Err(ScaleFsError::NotFound);
            }
            StatOutcome::Lost(_) => {
                return Err(ScaleFsError::Corrupt(
                    "the object's inode is in a lost tree range",
                ));
            }
        };
        if attrs.is_dir() {
            return Err(ScaleFsError::Unsupported("the object is a directory"));
        }
        let size = attrs.size;

        let start = MetadataKey {
            object_id: object,
            item_type: crate::tree::ITEM_FILE_EXTENT,
            offset: 0,
        };
        let end = MetadataKey {
            object_id: object,
            item_type: crate::tree::ITEM_FILE_EXTENT,
            offset: u64::MAX,
        };
        let mut runs: Vec<(u64, u64, RunSource)> = Vec::new();
        let mut map_damage: Vec<Damage> = Vec::new();
        self.walk_range(start, end, &mut |event| match event {
            WalkEvent::Item(
                key,
                MetadataValue::FileExtent {
                    extents,
                    data_offset,
                    logical_len,
                },
            ) => runs.push((
                key.offset,
                *logical_len,
                RunSource::Mirrored {
                    extents: extents.clone(),
                    data_offset: *data_offset,
                },
            )),
            WalkEvent::Item(
                key,
                MetadataValue::StripedExtent {
                    extent,
                    parity_extents,
                    data_offset,
                    logical_len,
                },
            ) => runs.push((
                key.offset,
                *logical_len,
                RunSource::Striped {
                    extent: *extent,
                    parity_extents: parity_extents.clone(),
                    data_offset: *data_offset,
                },
            )),
            WalkEvent::Item(..) => {}
            WalkEvent::Lost(damage) => {
                let lo = if damage.first_key < start {
                    0
                } else {
                    damage.first_key.offset
                };
                let hi = if damage.last_key > end {
                    size
                } else {
                    damage
                        .last_key
                        .offset
                        .saturating_add(crate::fs::FILE_DATA_CHUNK as u64)
                        .min(size)
                };
                if lo < hi {
                    runs.push((lo, hi - lo, RunSource::MapLost));
                }
                map_damage.push(damage.clone());
            }
        })?;
        runs.sort_by_key(|(offset, _, _)| *offset);
        let decoded: Vec<(u64, u64)> = runs
            .iter()
            .filter(|(_, _, source)| !matches!(source, RunSource::MapLost))
            .map(|(offset, len, _)| (*offset, offset.saturating_add(*len)))
            .collect();
        let mut clipped: Vec<(u64, u64, RunSource)> = Vec::with_capacity(runs.len());
        for (offset, len, source) in runs {
            if !matches!(source, RunSource::MapLost) {
                clipped.push((offset, len, source));
                continue;
            }
            let mut lo = offset;
            let end = offset.saturating_add(len);
            for &(decoded_lo, decoded_hi) in &decoded {
                if decoded_hi <= lo {
                    continue;
                }
                if decoded_lo >= end {
                    break;
                }
                if decoded_lo > lo {
                    clipped.push((lo, decoded_lo - lo, RunSource::MapLost));
                }
                lo = lo.max(decoded_hi);
                if lo >= end {
                    break;
                }
            }
            if lo < end {
                clipped.push((lo, end - lo, RunSource::MapLost));
            }
        }
        let mut runs = clipped;
        runs.sort_by_key(|(offset, _, _)| *offset);

        let mut report = FileReport {
            size,
            ranges: Vec::new(),
            map_damage,
            bytes_lost: 0,
        };
        let mut cursor = 0u64;
        for (logical, len, source) in runs {
            let len = len.min(size.saturating_sub(logical));
            if len == 0 || logical >= size {
                continue;
            }
            if logical > cursor {
                write_zeros(sink, logical - cursor)?;
            }
            if logical.saturating_add(len) <= cursor {
                continue;
            }
            let (skip, logical, len) = if logical < cursor {
                (cursor - logical, cursor, len - (cursor - logical))
            } else {
                (0, logical, len)
            };
            let verdict = match &source {
                RunSource::MapLost => {
                    write_zeros(sink, len)?;
                    report.bytes_lost += len;
                    ExtentVerdict::MapLost
                }
                RunSource::Mirrored {
                    extents,
                    data_offset,
                } => match self.read_record_any(extents, &[RecordKind::FileData]) {
                    Ok((copy, bytes)) => {
                        write_payload(sink, &bytes, data_offset + skip, len)?;
                        if copy == 0 {
                            ExtentVerdict::Intact
                        } else {
                            ExtentVerdict::HealedFromCopy { copy }
                        }
                    }
                    Err(reasons) => {
                        write_zeros(sink, len)?;
                        report.bytes_lost += len;
                        ExtentVerdict::Lost { reasons }
                    }
                },
                RunSource::Striped {
                    extent,
                    parity_extents,
                    data_offset,
                } => match self.read_record_copy(*extent, &[RecordKind::FileData]) {
                    Ok(bytes) => {
                        write_payload(sink, &bytes, data_offset + skip, len)?;
                        ExtentVerdict::Intact
                    }
                    Err(first) => match self.reconstruct_piece(*extent, parity_extents, first) {
                        Ok(bytes) => {
                            write_payload(sink, &bytes, data_offset + skip, len)?;
                            ExtentVerdict::ReconstructedFromParity
                        }
                        Err(reasons) => {
                            write_zeros(sink, len)?;
                            report.bytes_lost += len;
                            ExtentVerdict::Lost { reasons }
                        }
                    },
                },
            };
            report.push(logical, len, verdict);
            cursor = logical + len;
        }
        if cursor < size {
            write_zeros(sink, size - cursor)?;
        }
        Ok(report)
    }

    pub fn snapshots(&self) -> Result<(Vec<SnapshotCandidate>, Vec<Damage>)> {
        let start = MetadataKey {
            object_id: 0,
            item_type: crate::tree::ITEM_RETAINED_ROOT,
            offset: 0,
        };
        let end = MetadataKey {
            object_id: 0,
            item_type: crate::tree::ITEM_RETAINED_ROOT,
            offset: u64::MAX,
        };
        let mut snapshots = Vec::new();
        let mut damage = Vec::new();
        self.walk_range(start, end, &mut |event| match event {
            WalkEvent::Item(
                _,
                MetadataValue::RetainedRoot {
                    tx_id,
                    metadata_roots,
                    created_at_ns,
                    name,
                },
            ) => snapshots.push(SnapshotCandidate {
                tx_id: *tx_id,
                name: name.clone(),
                created_at_ns: *created_at_ns,
                roots: metadata_roots.clone(),
            }),
            WalkEvent::Item(..) => {}
            WalkEvent::Lost(lost) => damage.push(lost.clone()),
        })?;
        Ok((snapshots, damage))
    }

    pub fn enter_snapshot(&mut self, snapshot: &SnapshotCandidate) -> Result<()> {
        read_mapped_record(
            &self.devices,
            &self.member_map,
            *snapshot
                .roots
                .first()
                .ok_or(ScaleFsError::Corrupt("snapshot has no root replicas"))?,
            &[
                RecordKind::MetadataLeaf,
                RecordKind::MetadataInternal,
                RecordKind::MetadataInternalMirrored,
            ],
        )
        .or_else(|_| {
            snapshot
                .roots
                .iter()
                .skip(1)
                .find_map(|extent| {
                    read_mapped_record(
                        &self.devices,
                        &self.member_map,
                        *extent,
                        &[
                            RecordKind::MetadataLeaf,
                            RecordKind::MetadataInternal,
                            RecordKind::MetadataInternalMirrored,
                        ],
                    )
                    .ok()
                })
                .ok_or(ScaleFsError::Corrupt("no snapshot root replica decodes"))
        })?;
        self.root = snapshot.roots.clone();
        Ok(())
    }

    pub fn enter_live(&mut self) {
        self.root = self.live_root.clone();
    }

    pub fn read_special(&self, object: u64) -> Result<Option<Vec<u8>>> {
        let key = MetadataKey {
            object_id: object,
            item_type: crate::tree::ITEM_SPECIAL,
            offset: 0,
        };
        let mut data = None;
        self.walk_range(key, key, &mut |event| {
            if let WalkEvent::Item(_, MetadataValue::Special { data: bytes }) = event {
                data = Some(bytes.clone());
            }
        })?;
        Ok(data)
    }

    fn reconstruct_piece(
        &self,
        target: Extent,
        parity_extents: &[Extent],
        first_failure: ReadFailure,
    ) -> std::result::Result<Vec<u8>, Vec<ReadFailure>> {
        let mut reasons = vec![first_failure];
        for parity_extent in parity_extents {
            let descriptor = match self.read_record_copy(*parity_extent, &[RecordKind::Parity]) {
                Ok(bytes) => match crate::stripes::decode_parity_record(&bytes) {
                    Ok(descriptor) => descriptor,
                    Err(error) => {
                        reasons.push(ReadFailure::Corrupt(
                            parity_extent.device_index,
                            corrupt_reason(&error),
                        ));
                        continue;
                    }
                },
                Err(failure) => {
                    reasons.push(failure);
                    continue;
                }
            };
            let data_count = descriptor.data_pieces.len();
            let parity_count = descriptor.parity_pieces.len();
            let Ok(coverage) = usize::try_from(descriptor.coverage_len) else {
                reasons.push(ReadFailure::Corrupt(
                    parity_extent.device_index,
                    "stripe coverage exceeds the address space",
                ));
                continue;
            };
            let Some(column) = descriptor.data_pieces.iter().position(|piece| {
                piece.device_index == target.device_index
                    && piece.offset == target.offset
                    && piece.length == target.length
            }) else {
                reasons.push(ReadFailure::Corrupt(
                    parity_extent.device_index,
                    "stripe descriptor does not name the piece being read",
                ));
                continue;
            };
            let mut available: Vec<(usize, Vec<u8>)> = Vec::new();
            let mut erased = vec![column];
            for (index, piece) in descriptor.data_pieces.iter().enumerate() {
                if index == column {
                    continue;
                }
                match self.read_record_copy(*piece, &[RecordKind::FileData]) {
                    Ok(bytes) => available.push((index, bytes)),
                    Err(failure) => {
                        reasons.push(failure);
                        erased.push(index);
                    }
                }
            }
            for (row, piece) in descriptor.parity_pieces.iter().enumerate() {
                match self.read_record_copy(*piece, &[RecordKind::Parity]) {
                    Ok(bytes) => {
                        if let Ok(parity) = crate::stripes::decode_parity_record(&bytes)
                            && usize::from(parity.parity_index) == row
                        {
                            available.push((data_count + row, parity.parity));
                        }
                    }
                    Err(failure) => reasons.push(failure),
                }
            }
            let borrowed: Vec<(usize, &[u8])> = available
                .iter()
                .map(|(column, bytes)| (*column, bytes.as_slice()))
                .collect();
            let Ok(mut rebuilt) =
                crate::rs::reconstruct_data(data_count, parity_count, coverage, &borrowed, &erased)
            else {
                reasons.push(ReadFailure::Corrupt(
                    parity_extent.device_index,
                    "too many stripe pieces lost to solve",
                ));
                continue;
            };
            let mut bytes = rebuilt.swap_remove(0);
            bytes.truncate(target.length as usize);
            if decode_record(&bytes).is_err() {
                reasons.push(ReadFailure::Corrupt(
                    parity_extent.device_index,
                    "stripe reconstruction failed checksum verification",
                ));
                continue;
            }
            return Ok(bytes);
        }
        Err(reasons)
    }
}

enum RunSource {
    Mirrored {
        extents: Vec<Extent>,
        data_offset: u64,
    },
    Striped {
        extent: Extent,
        parity_extents: Vec<Extent>,
        data_offset: u64,
    },
    MapLost,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtentVerdict {
    Intact,
    HealedFromCopy { copy: usize },
    ReconstructedFromParity,
    Lost { reasons: Vec<ReadFailure> },
    MapLost,
}

impl ExtentVerdict {
    fn severity(&self) -> u8 {
        match self {
            ExtentVerdict::Intact => 0,
            ExtentVerdict::HealedFromCopy { .. } => 1,
            ExtentVerdict::ReconstructedFromParity => 2,
            ExtentVerdict::Lost { .. } => 3,
            ExtentVerdict::MapLost => 3,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RangeVerdict {
    pub offset: u64,
    pub len: u64,
    pub verdict: ExtentVerdict,
}

#[derive(Debug)]
pub struct FileReport {
    pub size: u64,
    pub ranges: Vec<RangeVerdict>,
    pub map_damage: Vec<Damage>,
    pub bytes_lost: u64,
}

impl FileReport {
    fn push(&mut self, offset: u64, len: u64, verdict: ExtentVerdict) {
        if let Some(last) = self.ranges.last_mut()
            && last.verdict == verdict
            && last.offset + last.len == offset
        {
            last.len += len;
            return;
        }
        self.ranges.push(RangeVerdict {
            offset,
            len,
            verdict,
        });
    }

    pub fn rollup(&self) -> ExtentVerdict {
        self.ranges
            .iter()
            .max_by_key(|range| range.verdict.severity())
            .map(|range| range.verdict.clone())
            .unwrap_or(ExtentVerdict::Intact)
    }
}

fn write_zeros(sink: &mut dyn std::io::Write, mut remaining: u64) -> Result<()> {
    let zeros = [0u8; 8192];
    while remaining > 0 {
        let step = remaining.min(zeros.len() as u64) as usize;
        sink.write_all(&zeros[..step])?;
        remaining -= step as u64;
    }
    Ok(())
}

fn write_payload(
    sink: &mut dyn std::io::Write,
    record_bytes: &[u8],
    data_offset: u64,
    len: u64,
) -> Result<()> {
    let record = decode_record(record_bytes)?;
    let start = usize::try_from(data_offset)
        .map_err(|_| ScaleFsError::Corrupt("data offset exceeds the address space"))?;
    let end = start
        .checked_add(len as usize)
        .filter(|end| *end <= record.payload.len())
        .ok_or(ScaleFsError::Corrupt(
            "file extent references bytes outside its record",
        ))?;
    sink.write_all(&record.payload[start..end])?;
    Ok(())
}

const MAX_TREE_DEPTH: u32 = 64;

enum Node {
    Leaf(Vec<(MetadataKey, MetadataValue)>),
    Internal(Vec<(MetadataKey, Vec<Extent>)>),
}

#[derive(Debug, Clone)]
pub struct Damage {
    pub extents: Vec<Extent>,
    pub reasons: Vec<ReadFailure>,
    pub first_key: MetadataKey,
    pub last_key: MetadataKey,
}

pub enum WalkEvent<'a> {
    Item(&'a MetadataKey, &'a MetadataValue),
    Lost(&'a Damage),
}

#[derive(Debug)]
pub struct DirListing {
    pub entries: Vec<DirEntry>,
    pub damage: Vec<Damage>,
}

#[derive(Debug)]
pub enum StatOutcome {
    Found(InodeAttrs),
    Missing,
    Lost(Vec<Damage>),
}

#[derive(Debug)]
pub enum PathOutcome {
    Found(u64),
    Missing,
    Lost(Vec<Damage>),
}

#[derive(Debug, Clone)]
pub struct SnapshotCandidate {
    pub tx_id: u64,
    pub name: String,
    pub created_at_ns: i64,
    pub roots: Vec<Extent>,
}

#[derive(Debug)]
pub struct Survey {
    pub items: u64,
    pub files: u64,
    pub directories: u64,
    pub damage: Vec<Damage>,
    pub disconnected: Vec<u64>,
}

fn previous_key(key: MetadataKey) -> MetadataKey {
    if key.offset > 0 {
        MetadataKey {
            offset: key.offset - 1,
            ..key
        }
    } else if key.item_type > 0 {
        MetadataKey {
            item_type: key.item_type - 1,
            offset: u64::MAX,
            ..key
        }
    } else {
        MetadataKey {
            object_id: key.object_id.saturating_sub(1),
            item_type: u8::MAX,
            offset: u64::MAX,
        }
    }
}

fn corrupt_reason(error: &ScaleFsError) -> &'static str {
    match error {
        ScaleFsError::Corrupt(reason) | ScaleFsError::Unsupported(reason) => reason,
        _ => "did not decode",
    }
}

fn read_local_record<D: BlockDevice>(
    device: &ReadOnly<D>,
    extent: Extent,
    kinds: &[RecordKind],
) -> Result<Vec<u8>> {
    if extent.length == 0 || extent.length > MAX_RECORD_READ {
        return Err(ScaleFsError::Corrupt("implausible record extent"));
    }
    let mut bytes = vec![0u8; extent.length as usize];
    device.read_at(extent.offset, &mut bytes)?;
    let record = decode_record(&bytes)?;
    if !kinds.contains(&record.kind) {
        return Err(ScaleFsError::Corrupt("unexpected record kind"));
    }
    Ok(bytes)
}

fn read_one_mapped<D: BlockDevice>(
    devices: &[ReadOnly<D>],
    member_map: &[Option<usize>],
    extent: Extent,
    kinds: &[RecordKind],
) -> std::result::Result<Vec<u8>, ReadFailure> {
    let index = extent.device_index;
    let Some(&Some(slot)) = member_map.get(index as usize) else {
        return Err(ReadFailure::AbsentMember(index));
    };
    if extent.length == 0 || extent.length > MAX_RECORD_READ {
        return Err(ReadFailure::Corrupt(index, "implausible record extent"));
    }
    let mut bytes = vec![0u8; extent.length as usize];
    if let Err(error) = devices[slot].read_at(extent.offset, &mut bytes) {
        return Err(ReadFailure::Io(index, error.to_string()));
    }
    let record = match decode_record(&bytes) {
        Ok(record) => record,
        Err(error) => return Err(ReadFailure::Corrupt(index, corrupt_reason(&error))),
    };
    if !kinds.contains(&record.kind) {
        return Err(ReadFailure::Corrupt(index, "unexpected record kind"));
    }
    Ok(bytes)
}

fn read_mapped_record<D: BlockDevice>(
    devices: &[ReadOnly<D>],
    member_map: &[Option<usize>],
    extent: Extent,
    kinds: &[RecordKind],
) -> Result<Vec<u8>> {
    read_one_mapped(devices, member_map, extent, kinds)
        .map_err(|_| ScaleFsError::Corrupt("no readable copy"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::MemoryBlockDevice;
    use crate::pool::{CreateParams, MemberSpec, Pool, PoolParams};
    use crate::records::encode_superblock;
    use crate::tree::ROOT_INODE;
    use crate::zones::AllocPurpose;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const NOW: i64 = 1_700_000_000_000_000_000;

    fn geometry() -> Geometry {
        Geometry {
            logical_block_size: 4096,
            physical_block_size: 4096,
            zone_size: 64 * 1024,
            zone_count: 64,
            erase_granularity_zones: 1,
            sequential_write_required: false,
        }
    }

    fn mirror_pool(members: usize, m: u16) -> (Vec<Arc<MemoryBlockDevice>>, u64) {
        let devices: Vec<Arc<MemoryBlockDevice>> = (0..members)
            .map(|_| Arc::new(MemoryBlockDevice::new(geometry().capacity_bytes() as usize)))
            .collect();
        let specs = devices
            .iter()
            .enumerate()
            .map(|(index, device)| MemberSpec {
                device: Arc::clone(device),
                device_id: DeviceId([index as u8 + 1; 16]),
                geometry: geometry(),
            })
            .collect();
        let mut pool = Pool::create_multi(
            specs,
            PoolParams {
                pool_id: PoolId([0xAA; 16]),
                case_sensitivity: CaseSensitivity::Sensitive,
                dirent_hash_seed: 7,
                label: "salv".to_string(),
                created_at_ns: NOW,
                mirror_width: m,
                data_width: 1,
                parity_width: 0,
            },
        )
        .unwrap();
        let file = pool
            .create_file(ROOT_INODE, "hello.txt", 0o644, NOW)
            .unwrap();
        pool.write(file, 0, b"salvage me", NOW).unwrap();
        let file = pool
            .create_file(ROOT_INODE, "world.txt", 0o644, NOW)
            .unwrap();
        pool.write(file, 0, &[0xC3u8; 40_000], NOW).unwrap();
        let tx = pool.commit(AllocPurpose::Normal, NOW).unwrap();
        (devices, tx)
    }

    fn salvage(devices: &[Arc<MemoryBlockDevice>]) -> Salvage<Arc<MemoryBlockDevice>> {
        Salvage::assemble(devices.to_vec()).expect("assemble")
    }

    fn corrupt_record(device: &MemoryBlockDevice, extent: Extent) {
        let at = extent.offset + 40;
        let mut byte = [0u8; 1];
        device.read_at(at, &mut byte).unwrap();
        byte[0] ^= 0xFF;
        device.write_at(at, &byte).unwrap();
    }

    fn zero_slot(device: &MemoryBlockDevice, which: usize) {
        let offset = superblock_slots(device.len())[which];
        device.write_at(offset, &[0u8; 4096]).unwrap();
    }

    fn chain_of(device: &MemoryBlockDevice) -> (Superblock, Commit, Option<Topology>) {
        let mut block = vec![0u8; 4096];
        device
            .read_at(superblock_slots(device.len())[0], &mut block)
            .unwrap();
        let superblock = decode_superblock(&block).unwrap();
        let commit_extent = superblock.newest_commit.unwrap();
        let mut bytes = vec![0u8; commit_extent.length as usize];
        device.read_at(commit_extent.offset, &mut bytes).unwrap();
        let commit = decode_commit(&bytes).unwrap();
        let roster = commit.aux_root.map(|aux| {
            let mut bytes = vec![0u8; aux.length as usize];
            device.read_at(aux.offset, &mut bytes).unwrap();
            decode_topology(&bytes).unwrap()
        });
        (superblock, commit, roster)
    }

    fn slot_bytes(device: &MemoryBlockDevice, which: usize) -> Vec<u8> {
        let mut block = vec![0u8; 4096];
        device
            .read_at(superblock_slots(device.len())[which], &mut block)
            .unwrap();
        block
    }

    fn restore_slots(device: &MemoryBlockDevice, bytes: &[Vec<u8>; 2]) {
        for (which, block) in bytes.iter().enumerate() {
            let offset = superblock_slots(device.len())[which];
            device.write_at(offset, block).unwrap();
        }
    }

    #[test]
    fn healthy_pool_assembles_strict_equivalent() {
        let (devices, tx) = mirror_pool(3, 2);
        let session = salvage(&devices);
        let report = session.report();
        assert_eq!(report.rung, Some(Rung::StrictEquivalent));
        assert_eq!(report.view_tx, Some(tx));
        assert!(session.has_view());
        assert!(report.missing.is_empty());
        assert_eq!(report.label.as_deref(), Some("salv"));
        for (index, device) in report.devices.iter().enumerate() {
            assert_eq!(device.role, DeviceRole::Member(index as u16));
            assert!(matches!(device.slots[0], SlotHealth::Valid));
            assert!(matches!(device.slots[1], SlotHealth::Valid));
        }
        assert!(report.candidates.iter().any(|c| c.adopted && c.tx == tx));
    }

    #[test]
    fn absent_member_degrades_to_partial_roster() {
        let (devices, tx) = mirror_pool(3, 2);
        let session = salvage(&devices[..2]);
        let report = session.report();
        assert_eq!(report.rung, Some(Rung::PartialRoster));
        assert_eq!(report.view_tx, Some(tx));
        assert!(session.has_view());
        assert_eq!(report.missing.len(), 1);
        let missing = &report.missing[0];
        assert_eq!(missing.device_id, DeviceId([3; 16]));
        assert_eq!(missing.member_index, 2);
        assert_eq!(missing.geometry.zone_count, geometry().zone_count);
    }

    #[test]
    fn a_dead_superblock_slot_does_not_cost_strictness() {
        let (devices, tx) = mirror_pool(3, 2);
        zero_slot(&devices[0], 0);
        let session = salvage(&devices);
        let report = session.report();
        assert_eq!(report.rung, Some(Rung::StrictEquivalent));
        assert_eq!(report.view_tx, Some(tx));
        assert!(matches!(report.devices[0].slots[0], SlotHealth::Corrupt(_)));
        assert!(matches!(report.devices[0].slots[1], SlotHealth::Valid));
    }

    #[test]
    fn an_unidentifiable_device_counts_as_missing() {
        let (devices, _) = mirror_pool(3, 2);
        zero_slot(&devices[2], 0);
        zero_slot(&devices[2], 1);
        let session = salvage(&devices);
        let report = session.report();
        assert_eq!(report.rung, Some(Rung::PartialRoster));
        assert_eq!(report.devices[2].role, DeviceRole::Unidentified);
        assert_eq!(report.missing.len(), 1);
        assert_eq!(report.missing[0].device_id, DeviceId([3; 16]));
    }

    #[test]
    fn dead_roots_roll_back_to_a_lagging_members_candidate() {
        let (devices, t1) = mirror_pool(3, 2);
        let lagged: [Vec<u8>; 2] = [slot_bytes(&devices[0], 0), slot_bytes(&devices[0], 1)];

        {
            let mut pool =
                Pool::open_multi(devices.iter().map(Arc::clone).collect()).expect("reopen");
            let file = pool
                .create_file(ROOT_INODE, "later.txt", 0o644, NOW)
                .unwrap();
            pool.write(file, 0, b"newer", NOW).unwrap();
            let t2 = pool.commit(AllocPurpose::Normal, NOW).unwrap();
            assert!(t2 > t1);
        }
        restore_slots(&devices[0], &lagged);

        let (_, _, roster) = chain_of(&devices[1]);
        let roster = roster.expect("multi pools carry rosters");
        for replica in &roster.metadata_root_replicas {
            corrupt_record(&devices[replica.device_index as usize], *replica);
        }

        let session = salvage(&devices);
        let report = session.report();
        assert_eq!(
            report.view_tx,
            Some(t1),
            "rolled back to the lagging candidate"
        );
        assert_eq!(report.rung, Some(Rung::StrictEquivalent));
        assert!(report.candidates.iter().any(|c| !c.adopted
            && c.kind == CandidateKind::Roster
            && c.note.as_deref() == Some("no metadata root replica decodes")));
    }

    #[test]
    fn commit_root_rung_pairs_a_roster_map_with_a_commit_root() {
        let (devices, t1) = mirror_pool(3, 2);
        let lagged: [Vec<u8>; 2] = [slot_bytes(&devices[0], 0), slot_bytes(&devices[0], 1)];
        let (_, t1_commit, _) = chain_of(&devices[0]);
        {
            let mut pool =
                Pool::open_multi(devices.iter().map(Arc::clone).collect()).expect("reopen");
            let file = pool
                .create_file(ROOT_INODE, "later.txt", 0o644, NOW)
                .unwrap();
            pool.write(file, 0, b"newer", NOW).unwrap();
            pool.commit(AllocPurpose::Normal, NOW).unwrap();
        }
        restore_slots(&devices[0], &lagged);

        let (_, _, newest_roster) = chain_of(&devices[1]);
        for replica in &newest_roster.expect("roster").metadata_root_replicas {
            corrupt_record(&devices[replica.device_index as usize], *replica);
        }
        let newest_tx = devices
            .iter()
            .map(|device| chain_of(device).1.tx_id)
            .max()
            .unwrap();
        let mut corrupted: Vec<(usize, u64)> = Vec::new();
        for (slot, device) in devices.iter().enumerate() {
            for which in 0..2 {
                let Ok(superblock) = decode_superblock(&slot_bytes(device, which)) else {
                    continue;
                };
                let Some(commit_extent) = superblock.newest_commit else {
                    continue;
                };
                let mut bytes = vec![0u8; commit_extent.length as usize];
                device.read_at(commit_extent.offset, &mut bytes).unwrap();
                let Ok(commit) = decode_commit(&bytes) else {
                    continue;
                };
                if commit.tx_id == newest_tx {
                    continue;
                }
                let Some(aux) = commit.aux_root else { continue };
                if corrupted.contains(&(slot, aux.offset)) {
                    continue;
                }
                corrupted.push((slot, aux.offset));
                corrupt_record(device, aux);
            }
        }
        assert_eq!(t1_commit.tx_id, t1);

        let session = salvage(&devices);
        let report = session.report();
        assert_eq!(report.rung, Some(Rung::CommitRoot));
        assert_eq!(report.view_tx, Some(t1));
        assert!(session.has_view());
        assert!(
            report
                .candidates
                .iter()
                .any(|c| c.adopted && c.kind == CandidateKind::Commit)
        );
    }

    #[test]
    fn a_pinned_view_is_honored() {
        let (devices, t1) = mirror_pool(3, 2);
        let lagged: [Vec<u8>; 2] = [slot_bytes(&devices[0], 0), slot_bytes(&devices[0], 1)];
        {
            let mut pool =
                Pool::open_multi(devices.iter().map(Arc::clone).collect()).expect("reopen");
            pool.create_file(ROOT_INODE, "later.txt", 0o644, NOW)
                .unwrap();
            pool.commit(AllocPurpose::Normal, NOW).unwrap();
        }
        restore_slots(&devices[0], &lagged);
        let session = Salvage::assemble_at(devices.to_vec(), t1).expect("assemble");
        assert_eq!(session.report().view_tx, Some(t1));
        assert_eq!(session.report().rung, Some(Rung::StrictEquivalent));
    }

    #[test]
    fn single_device_pools_assemble_without_a_roster() {
        let device = Arc::new(MemoryBlockDevice::new(geometry().capacity_bytes() as usize));
        let mut pool = Pool::create(
            Arc::clone(&device),
            CreateParams {
                geometry: geometry(),
                pool_id: PoolId([0xBB; 16]),
                device_id: DeviceId([0xBC; 16]),
                case_sensitivity: CaseSensitivity::InsensitivePreserving,
                dirent_hash_seed: 9,
                label: "solo".to_string(),
                created_at_ns: NOW,
            },
        )
        .unwrap();
        let file = pool.create_file(ROOT_INODE, "one.txt", 0o644, NOW).unwrap();
        pool.write(file, 0, b"single", NOW).unwrap();
        let tx = pool.commit(AllocPurpose::Normal, NOW).unwrap();
        drop(pool);
        let session = Salvage::assemble(vec![Arc::clone(&device)]).expect("assemble");
        let report = session.report();
        assert_eq!(report.rung, Some(Rung::StrictEquivalent));
        assert_eq!(report.view_tx, Some(tx));
        assert_eq!(report.devices[0].role, DeviceRole::Member(0));
    }

    #[test]
    fn unknown_incompatible_bits_stop_at_identity() {
        let (devices, _) = mirror_pool(3, 2);
        let (mut superblock, _, _) = chain_of(&devices[0]);
        superblock.feature_incompat |= 1 << 7;
        let encoded = encode_superblock(&superblock).unwrap();
        for which in 0..2 {
            let offset = superblock_slots(devices[0].len())[which];
            devices[0].write_at(offset, &encoded).unwrap();
        }
        let session = salvage(&devices);
        let report = session.report();
        assert!(report.unknown_incompat);
        assert_eq!(report.rung, None);
        assert!(!session.has_view());
        assert!(report.notes.iter().any(|n| n.contains("identity only")));
        assert!(report.devices.iter().all(|d| d.newest_tx.is_none()));
    }

    #[test]
    fn devices_that_decode_nothing_are_refused() {
        let blank = Arc::new(MemoryBlockDevice::new(1 << 20));
        assert!(Salvage::assemble(vec![blank]).is_err());
    }

    #[test]
    fn read_only_wrapper_refuses_the_write_side() {
        let device = MemoryBlockDevice::new(1 << 16);
        let read_only = ReadOnly::new(device);
        let mut buf = [0u8; 16];
        read_only.read_at(0, &mut buf).unwrap();
        assert!(matches!(
            read_only.write_at(0, &[1]),
            Err(ScaleFsError::Unsupported(_))
        ));
        assert!(matches!(
            read_only.flush(),
            Err(ScaleFsError::Unsupported(_))
        ));
    }

    #[derive(Clone)]
    pub(super) struct Counting {
        inner: Arc<MemoryBlockDevice>,
        writes: Arc<AtomicUsize>,
    }

    impl Counting {
        pub(super) fn wrap(
            devices: &[Arc<MemoryBlockDevice>],
        ) -> (Vec<Counting>, Arc<AtomicUsize>) {
            let writes = Arc::new(AtomicUsize::new(0));
            let wrapped = devices
                .iter()
                .map(|device| Counting {
                    inner: Arc::clone(device),
                    writes: Arc::clone(&writes),
                })
                .collect();
            (wrapped, writes)
        }
    }

    impl BlockDevice for Counting {
        fn len(&self) -> u64 {
            self.inner.len()
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.inner.read_at(offset, buf)
        }

        fn write_at(&self, _offset: u64, _data: &[u8]) -> Result<()> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Err(ScaleFsError::Unsupported("salvage must not write"))
        }

        fn flush(&self) -> Result<()> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Err(ScaleFsError::Unsupported("salvage must not flush"))
        }
    }

    #[test]
    fn assembly_never_touches_the_write_side() {
        let (devices, _) = mirror_pool(3, 2);
        let (wrapped, writes) = Counting::wrap(&devices);
        let _ = Salvage::assemble(wrapped).expect("healthy");
        assert_eq!(writes.load(Ordering::SeqCst), 0);

        let (wrapped, writes) = Counting::wrap(&devices[..2]);
        let _ = Salvage::assemble(wrapped).expect("degraded");
        assert_eq!(writes.load(Ordering::SeqCst), 0);

        zero_slot(&devices[0], 0);
        let (_, _, roster) = chain_of(&devices[1]);
        for replica in &roster.expect("roster").metadata_root_replicas {
            corrupt_record(&devices[replica.device_index as usize], *replica);
        }
        let (wrapped, writes) = Counting::wrap(&devices);
        let _ = Salvage::assemble(wrapped).expect("damaged");
        assert_eq!(writes.load(Ordering::SeqCst), 0);
    }


    fn many_file_pool(count: usize) -> (Vec<Arc<MemoryBlockDevice>>, u64) {
        let devices: Vec<Arc<MemoryBlockDevice>> = (0..3)
            .map(|_| Arc::new(MemoryBlockDevice::new(geometry().capacity_bytes() as usize)))
            .collect();
        let specs = devices
            .iter()
            .enumerate()
            .map(|(index, device)| MemberSpec {
                device: Arc::clone(device),
                device_id: DeviceId([index as u8 + 1; 16]),
                geometry: geometry(),
            })
            .collect();
        let mut pool = Pool::create_multi(
            specs,
            PoolParams {
                pool_id: PoolId([0xAA; 16]),
                case_sensitivity: CaseSensitivity::Sensitive,
                dirent_hash_seed: 7,
                label: "many".to_string(),
                created_at_ns: NOW,
                mirror_width: 2,
                data_width: 1,
                parity_width: 0,
            },
        )
        .unwrap();
        for index in 0..count {
            let name = format!("f-{index:03}");
            let file = pool.create_file(ROOT_INODE, &name, 0o644, NOW).unwrap();
            pool.write(file, 0, name.as_bytes(), NOW).unwrap();
        }
        let tx = pool.commit(AllocPurpose::Normal, NOW).unwrap();
        (devices, tx)
    }

    fn leaf_holding(session: &Salvage<Arc<MemoryBlockDevice>>, key: MetadataKey) -> Vec<Extent> {
        let mut extents = session.root_extents().to_vec();
        loop {
            match session
                .load_node(&extents, MetadataKey::MIN, MetadataKey::MAX)
                .expect("healthy fixture")
            {
                Node::Leaf(_) => return extents,
                Node::Internal(children) => {
                    let mut chosen = children[0].1.clone();
                    for (separator, child) in &children {
                        if *separator <= key {
                            chosen = child.clone();
                        }
                    }
                    extents = chosen;
                }
            }
        }
    }

    #[test]
    fn the_walk_serves_a_healthy_tree_in_full() {
        let (devices, _) = mirror_pool(3, 2);
        let session = salvage(&devices);

        let listing = session.read_dir(ROOT_INODE).unwrap();
        assert!(listing.damage.is_empty());
        let names: Vec<&str> = listing.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["hello.txt", "world.txt"]);

        let PathOutcome::Found(object) = session.resolve_path("/world.txt").unwrap() else {
            panic!("world.txt resolves");
        };
        let StatOutcome::Found(attrs) = session.stat(object).unwrap() else {
            panic!("world.txt stats");
        };
        assert_eq!(attrs.size, 40_000);
        assert!(matches!(
            session.resolve_path("/nope").unwrap(),
            PathOutcome::Missing
        ));

        let survey = session.survey().unwrap();
        assert_eq!(survey.files, 2);
        assert!(survey.directories >= 1);
        assert!(survey.damage.is_empty());
        assert!(survey.disconnected.is_empty());
    }

    #[test]
    fn a_lost_leaf_is_reported_and_the_walk_continues() {
        let (devices, _) = many_file_pool(300);
        let healthy = salvage(&devices);
        let healthy_survey = healthy.survey().unwrap();
        assert!(healthy_survey.damage.is_empty());
        assert_eq!(healthy_survey.files, 300);

        let target = leaf_holding(
            &healthy,
            MetadataKey {
                object_id: ROOT_INODE,
                item_type: ITEM_DIRENT,
                offset: 0,
            },
        );
        for extent in &target {
            corrupt_record(&devices[extent.device_index as usize], *extent);
        }

        let session = salvage(&devices);
        let survey = session.survey().unwrap();
        assert_eq!(survey.damage.len(), 1, "exactly the one lost subtree");
        assert!(survey.items < healthy_survey.items);
        let damage = &survey.damage[0];
        assert!(damage.first_key <= damage.last_key);
        assert!(!damage.reasons.is_empty());
        assert!(
            !survey.disconnected.is_empty(),
            "names died, inodes survived: disconnected objects appear"
        );

        let listing = session.read_dir(ROOT_INODE).unwrap();
        assert!(!listing.damage.is_empty());
        assert!(listing.entries.len() < 300);

        let (mut found, mut lost) = (0, 0);
        for index in 0..300 {
            match session.resolve_path(&format!("/f-{index:03}")).unwrap() {
                PathOutcome::Found(_) => found += 1,
                PathOutcome::Lost(_) => lost += 1,
                PathOutcome::Missing => {}
            }
        }
        assert!(found > 0, "entries outside the dead leaf still resolve");
        assert!(lost > 0, "entries inside it report lost, not missing");
    }

    #[test]
    fn the_walk_never_touches_the_write_side() {
        let (devices, _) = many_file_pool(50);
        let (wrapped, writes) = Counting::wrap(&devices);
        let session = Salvage::assemble(wrapped).expect("assemble");
        let _ = session.survey().unwrap();
        let _ = session.read_dir(ROOT_INODE).unwrap();
        let _ = session.resolve_path("/f-001").unwrap();
        let _ = session.stat(ROOT_INODE).unwrap();
        assert_eq!(writes.load(Ordering::SeqCst), 0);
    }


    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    fn runs_of(session: &Salvage<Arc<MemoryBlockDevice>>, object: u64) -> Vec<(u64, Vec<Extent>)> {
        let start = MetadataKey {
            object_id: object,
            item_type: crate::tree::ITEM_FILE_EXTENT,
            offset: 0,
        };
        let end = MetadataKey {
            object_id: object,
            item_type: crate::tree::ITEM_FILE_EXTENT,
            offset: u64::MAX,
        };
        let mut runs = Vec::new();
        session
            .walk_range(start, end, &mut |event| match event {
                WalkEvent::Item(key, MetadataValue::FileExtent { extents, .. }) => {
                    runs.push((key.offset, extents.clone()));
                }
                WalkEvent::Item(key, MetadataValue::StripedExtent { extent, .. }) => {
                    runs.push((key.offset, vec![*extent]));
                }
                _ => {}
            })
            .unwrap();
        runs
    }

    fn object_of(session: &Salvage<Arc<MemoryBlockDevice>>, path: &str) -> u64 {
        match session.resolve_path(path).unwrap() {
            PathOutcome::Found(object) => object,
            other => panic!("{path} did not resolve: {other:?}"),
        }
    }

    fn salvaged_bytes(
        session: &Salvage<Arc<MemoryBlockDevice>>,
        object: u64,
    ) -> (Vec<u8>, FileReport) {
        let mut sink = Vec::new();
        let report = session.salvage_file(object, &mut sink).unwrap();
        (sink, report)
    }

    #[test]
    fn a_healthy_file_salvages_byte_identically() {
        let (devices, _) = mirror_pool(3, 2);
        let session = salvage(&devices);
        let object = object_of(&session, "/world.txt");
        let (bytes, report) = salvaged_bytes(&session, object);
        assert_eq!(bytes, vec![0xC3u8; 40_000]);
        assert_eq!(report.rollup(), ExtentVerdict::Intact);
        assert_eq!(report.bytes_lost, 0);
        assert!(report.map_damage.is_empty());
    }

    #[test]
    fn a_dead_primary_copy_heals_from_its_sibling() {
        let (devices, _) = mirror_pool(3, 2);
        let healthy = salvage(&devices);
        let object = object_of(&healthy, "/world.txt");
        let runs = runs_of(&healthy, object);
        assert!(!runs.is_empty());
        let (_, extents) = &runs[runs.len() / 2];
        assert!(extents.len() >= 2, "mirror-2 runs carry two copies");
        corrupt_record(&devices[extents[0].device_index as usize], extents[0]);

        let session = salvage(&devices);
        let (bytes, report) = salvaged_bytes(&session, object);
        assert_eq!(bytes, vec![0xC3u8; 40_000], "healed bytes are exact");
        assert_eq!(report.bytes_lost, 0);
        assert_eq!(
            report.rollup(),
            ExtentVerdict::HealedFromCopy { copy: 1 },
            "the report says which sibling served"
        );
    }

    #[test]
    fn every_copy_dead_is_an_honest_loss() {
        let (devices, _) = mirror_pool(3, 2);
        let healthy = salvage(&devices);
        let object = object_of(&healthy, "/world.txt");
        let runs = runs_of(&healthy, object);
        let (logical, extents) = runs[runs.len() / 2].clone();
        for extent in &extents {
            corrupt_record(&devices[extent.device_index as usize], *extent);
        }

        let session = salvage(&devices);
        let (bytes, report) = salvaged_bytes(&session, object);
        assert_eq!(bytes.len(), 40_000, "losses zero-fill; the size holds");
        let expected = pattern(0);
        let _ = expected;
        let lost = report
            .ranges
            .iter()
            .find(|range| matches!(range.verdict, ExtentVerdict::Lost { .. }))
            .expect("a lost range is reported");
        assert_eq!(lost.offset, logical);
        assert!(report.bytes_lost > 0);
        assert!(
            bytes[lost.offset as usize..(lost.offset + lost.len) as usize]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert!(bytes[..lost.offset as usize].iter().all(|b| *b == 0xC3));
        assert!(
            bytes[(lost.offset + lost.len) as usize..]
                .iter()
                .all(|b| *b == 0xC3)
        );
        if let ExtentVerdict::Lost { reasons } = &lost.verdict {
            assert_eq!(reasons.len(), extents.len(), "one reason per copy");
        }
    }

    fn parity_pool() -> (Vec<Arc<MemoryBlockDevice>>, Vec<u8>) {
        let devices: Vec<Arc<MemoryBlockDevice>> = (0..4)
            .map(|_| Arc::new(MemoryBlockDevice::new(geometry().capacity_bytes() as usize)))
            .collect();
        let specs = devices
            .iter()
            .enumerate()
            .map(|(index, device)| MemberSpec {
                device: Arc::clone(device),
                device_id: DeviceId([index as u8 + 1; 16]),
                geometry: geometry(),
            })
            .collect();
        let mut pool = Pool::create_multi(
            specs,
            PoolParams {
                pool_id: PoolId([0xAB; 16]),
                case_sensitivity: CaseSensitivity::Sensitive,
                dirent_hash_seed: 7,
                label: "par".to_string(),
                created_at_ns: NOW,
                mirror_width: 2,
                data_width: 2,
                parity_width: 1,
            },
        )
        .unwrap();
        let content = pattern(100_000);
        let file = pool
            .create_file(ROOT_INODE, "striped.bin", 0o644, NOW)
            .unwrap();
        pool.write(file, 0, &content, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        (devices, content)
    }

    #[test]
    fn a_dead_stripe_piece_reconstructs_from_parity() {
        let (devices, content) = parity_pool();
        let healthy = salvage(&devices);
        let object = object_of(&healthy, "/striped.bin");
        let runs = runs_of(&healthy, object);
        assert!(!runs.is_empty());
        let (_, extents) = &runs[runs.len() / 2];
        corrupt_record(&devices[extents[0].device_index as usize], extents[0]);

        let session = salvage(&devices);
        let (bytes, report) = salvaged_bytes(&session, object);
        assert_eq!(bytes, content, "reconstruction is byte-exact");
        assert_eq!(report.bytes_lost, 0);
        assert_eq!(report.rollup(), ExtentVerdict::ReconstructedFromParity);
    }

    #[test]
    fn losses_beyond_parity_tolerance_are_honest() {
        let (devices, content) = parity_pool();
        let healthy = salvage(&devices);
        let object = object_of(&healthy, "/striped.bin");
        let runs = runs_of(&healthy, object);
        let (logical, extents) = runs[runs.len() / 2].clone();

        let start = MetadataKey {
            object_id: object,
            item_type: crate::tree::ITEM_FILE_EXTENT,
            offset: logical,
        };
        let mut stripe: Vec<Extent> = Vec::new();
        healthy
            .walk_range(start, start, &mut |event| {
                if let WalkEvent::Item(
                    _,
                    MetadataValue::StripedExtent {
                        extent,
                        parity_extents,
                        ..
                    },
                ) = event
                {
                    stripe.push(*extent);
                    stripe.extend_from_slice(parity_extents);
                }
            })
            .unwrap();
        assert!(!stripe.is_empty());
        for extent in &stripe {
            corrupt_record(&devices[extent.device_index as usize], *extent);
        }
        let _ = extents;

        let session = salvage(&devices);
        let (bytes, report) = salvaged_bytes(&session, object);
        assert_eq!(bytes.len(), content.len());
        assert!(report.bytes_lost > 0);
        assert!(matches!(report.rollup(), ExtentVerdict::Lost { .. }));
        let lost = report
            .ranges
            .iter()
            .find(|range| matches!(range.verdict, ExtentVerdict::Lost { .. }))
            .unwrap();
        assert!(bytes[..lost.offset as usize] == content[..lost.offset as usize]);
    }

    #[test]
    fn a_lost_extent_map_projects_map_lost_onto_the_file() {
        let big_geometry = Geometry {
            zone_count: 512,
            ..geometry()
        };
        let devices: Vec<Arc<MemoryBlockDevice>> = (0..3)
            .map(|_| {
                Arc::new(MemoryBlockDevice::new(
                    big_geometry.capacity_bytes() as usize
                ))
            })
            .collect();
        let specs = devices
            .iter()
            .enumerate()
            .map(|(index, device)| MemberSpec {
                device: Arc::clone(device),
                device_id: DeviceId([index as u8 + 1; 16]),
                geometry: big_geometry,
            })
            .collect();
        let mut pool = Pool::create_multi(
            specs,
            PoolParams {
                pool_id: PoolId([0xAC; 16]),
                case_sensitivity: CaseSensitivity::Sensitive,
                dirent_hash_seed: 7,
                label: "big".to_string(),
                created_at_ns: NOW,
                mirror_width: 2,
                data_width: 1,
                parity_width: 0,
            },
        )
        .unwrap();
        let content = pattern(9 << 20);
        let file = pool.create_file(ROOT_INODE, "big.bin", 0o644, NOW).unwrap();
        pool.write(file, 0, &content, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        drop(pool);

        let healthy = Salvage::assemble(devices.to_vec()).unwrap();
        let object = object_of(&healthy, "/big.bin");
        let inode_leaf = leaf_holding(
            &healthy,
            MetadataKey {
                object_id: object,
                item_type: ITEM_INODE,
                offset: 0,
            },
        );
        let tail_leaf = leaf_holding(
            &healthy,
            MetadataKey {
                object_id: object,
                item_type: crate::tree::ITEM_FILE_EXTENT,
                offset: (8 << 20) as u64,
            },
        );
        assert_ne!(
            inode_leaf, tail_leaf,
            "the fixture needs the map split off the inode"
        );
        for extent in &tail_leaf {
            corrupt_record(&devices[extent.device_index as usize], *extent);
        }

        let session = Salvage::assemble(devices.to_vec()).unwrap();
        let (bytes, report) = salvaged_bytes(&session, object);
        assert_eq!(bytes.len(), content.len(), "size holds through map loss");
        assert!(!report.map_damage.is_empty());
        assert!(report.bytes_lost > 0);
        assert!(
            report
                .ranges
                .iter()
                .any(|range| range.verdict == ExtentVerdict::MapLost)
        );
        let first_map_lost = report
            .ranges
            .iter()
            .find(|range| range.verdict == ExtentVerdict::MapLost)
            .unwrap()
            .offset as usize;
        assert!(first_map_lost > 0);
        assert_eq!(bytes[..first_map_lost], content[..first_map_lost]);
    }

    #[test]
    fn interior_map_damage_does_not_zero_the_decoded_neighbor() {
        let big_geometry = Geometry {
            zone_count: 512,
            ..geometry()
        };
        let devices: Vec<Arc<MemoryBlockDevice>> = (0..3)
            .map(|_| {
                Arc::new(MemoryBlockDevice::new(
                    big_geometry.capacity_bytes() as usize
                ))
            })
            .collect();
        let specs = devices
            .iter()
            .enumerate()
            .map(|(index, device)| MemberSpec {
                device: Arc::clone(device),
                device_id: DeviceId([index as u8 + 1; 16]),
                geometry: big_geometry,
            })
            .collect();
        let mut pool = Pool::create_multi(
            specs,
            PoolParams {
                pool_id: PoolId([0xAD; 16]),
                case_sensitivity: CaseSensitivity::Sensitive,
                dirent_hash_seed: 7,
                label: "interior".to_string(),
                created_at_ns: NOW,
                mirror_width: 2,
                data_width: 1,
                parity_width: 0,
            },
        )
        .unwrap();
        let len: usize = 16 << 20;
        let content = pattern(len);
        let file = pool.create_file(ROOT_INODE, "big.bin", 0o644, NOW).unwrap();
        pool.write(file, 0, &content, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        drop(pool);

        let healthy = Salvage::assemble(devices.to_vec()).unwrap();
        let object = object_of(&healthy, "/big.bin");
        let chunk_usize = crate::fs::FILE_DATA_CHUNK;
        let extent_leaf_at = |offset: u64| {
            leaf_holding(
                &healthy,
                MetadataKey {
                    object_id: object,
                    item_type: crate::tree::ITEM_FILE_EXTENT,
                    offset,
                },
            )
        };
        let first_leaf = extent_leaf_at(0);
        let tail_leaf = extent_leaf_at((len - chunk_usize) as u64);
        assert_ne!(first_leaf, tail_leaf, "fixture: the map spans leaves");
        let mid_leaf = (1..(len / chunk_usize))
            .map(|index| extent_leaf_at((index * chunk_usize) as u64))
            .find(|leaf| *leaf != first_leaf && *leaf != tail_leaf)
            .expect("fixture: an interior extent leaf exists");
        for extent in &mid_leaf {
            corrupt_record(&devices[extent.device_index as usize], *extent);
        }

        let session = Salvage::assemble(devices.to_vec()).unwrap();
        let (bytes, report) = salvaged_bytes(&session, object);
        assert_eq!(bytes.len(), content.len());
        assert!(report.bytes_lost > 0, "the interior damage is visible");

        let chunk = crate::fs::FILE_DATA_CHUNK as u64;
        assert_eq!(
            report.bytes_lost % chunk,
            0,
            "the projection clips at decoded coverage: whole chunks \
             only, never the separator-pad overshoot"
        );
        let mut lost = vec![false; bytes.len()];
        for range in &report.ranges {
            if matches!(
                range.verdict,
                ExtentVerdict::MapLost | ExtentVerdict::Lost { .. }
            ) {
                let from = range.offset as usize;
                let to = (range.offset + range.len).min(bytes.len() as u64) as usize;
                lost[from..to].fill(true);
            }
        }
        for (index, flagged) in lost.iter().enumerate() {
            if !flagged {
                assert_eq!(
                    bytes[index], content[index],
                    "non-lost byte {index} must be exact"
                );
            }
        }
    }

    #[test]
    fn the_verdict_reader_never_touches_the_write_side() {
        let (devices, _) = mirror_pool(3, 2);
        {
            let healthy = salvage(&devices);
            let object = object_of(&healthy, "/world.txt");
            let runs = runs_of(&healthy, object);
            let (_, extents) = &runs[0];
            corrupt_record(&devices[extents[0].device_index as usize], extents[0]);
        }
        let (wrapped, writes) = Counting::wrap(&devices);
        let session = Salvage::assemble(wrapped).unwrap();
        let PathOutcome::Found(object) = session.resolve_path("/world.txt").unwrap() else {
            panic!("resolves");
        };
        let mut sink = Vec::new();
        let report = session.salvage_file(object, &mut sink).unwrap();
        assert_eq!(report.bytes_lost, 0, "healed, not lost");
        assert_eq!(writes.load(Ordering::SeqCst), 0);

        let (devices, _) = parity_pool();
        {
            let healthy = salvage(&devices);
            let object = object_of(&healthy, "/striped.bin");
            let runs = runs_of(&healthy, object);
            let (_, extents) = &runs[0];
            corrupt_record(&devices[extents[0].device_index as usize], extents[0]);
        }
        let (wrapped, writes) = Counting::wrap(&devices);
        let session = Salvage::assemble(wrapped).unwrap();
        let PathOutcome::Found(object) = session.resolve_path("/striped.bin").unwrap() else {
            panic!("resolves");
        };
        let mut sink = Vec::new();
        let report = session.salvage_file(object, &mut sink).unwrap();
        assert_eq!(report.rollup(), ExtentVerdict::ReconstructedFromParity);
        assert_eq!(
            writes.load(Ordering::SeqCst),
            0,
            "even reconstruction never writes"
        );
    }


    #[test]
    fn snapshots_enter_and_serve_their_retained_bytes() {
        let (devices, _) = mirror_pool(3, 2);
        {
            let mut pool =
                Pool::open_multi(devices.iter().map(Arc::clone).collect()).expect("reopen");
            pool.snapshot_create("keep", NOW).unwrap();
            let file = match salvage(&devices).resolve_path("/world.txt").unwrap() {
                PathOutcome::Found(object) => object,
                other => panic!("{other:?}"),
            };
            pool.write(file, 0, &[0x11u8; 40_000], NOW).unwrap();
            pool.commit(AllocPurpose::Normal, NOW).unwrap();
        }

        let mut session = salvage(&devices);
        let (snapshots, damage) = session.snapshots().unwrap();
        assert!(damage.is_empty());
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].name, "keep");

        let object = object_of(&session, "/world.txt");
        let (live_bytes, _) = salvaged_bytes(&session, object);
        assert_eq!(live_bytes, vec![0x11u8; 40_000]);

        session.enter_snapshot(&snapshots[0].clone()).unwrap();
        let snap_object = object_of(&session, "/world.txt");
        let (snap_bytes, report) = salvaged_bytes(&session, snap_object);
        assert_eq!(snap_bytes, vec![0xC3u8; 40_000]);
        assert_eq!(report.rollup(), ExtentVerdict::Intact);

        session.enter_live();
        let (back, _) = salvaged_bytes(&session, object);
        assert_eq!(back, vec![0x11u8; 40_000]);
    }
}
