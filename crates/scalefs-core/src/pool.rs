use crate::device::{BlockDevice, PartitionView};
use crate::error::{Result, ScaleFsError};
use crate::format::{RecordKind, decode_record};
use crate::layout::{CaseSensitivity, DeviceId, Extent, Geometry, PoolId, superblock_slots};
use crate::records::{
    Commit, FEATURE_INCOMPAT_MULTI_DEVICE, FEATURE_INCOMPAT_PARITY, FEATURE_INCOMPAT_THIN_METADATA,
    Superblock, decode_commit, decode_superblock, encode_commit, encode_superblock,
};
use crate::stripes::{ParityRecord, decode_parity_record, parity_record_len};
use crate::topology::{MemberState, Topology, TopologyMember, decode_topology, encode_topology};
use crate::tree::{
    ITEM_FILE_EXTENT, ITEM_INODE, ITEM_POOL_STATE, ITEM_RETAINED_ROOT, InodeAttrs, MetadataKey,
    MetadataTree, MetadataValue, ROOT_INODE, decode_internal_record, decode_leaf_record,
    encode_internal_record, encode_leaf_record,
};
use crate::zones::{AllocPurpose, Allocation, ZoneAllocator, ZoneClass};
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct CreateParams {
    pub pool_id: PoolId,
    pub device_id: DeviceId,
    pub geometry: Geometry,
    pub case_sensitivity: CaseSensitivity,
    pub dirent_hash_seed: u64,
    pub label: String,
    pub created_at_ns: i64,
}

#[derive(Debug, Clone)]
pub struct PoolParams {
    pub pool_id: PoolId,
    pub case_sensitivity: CaseSensitivity,
    pub dirent_hash_seed: u64,
    pub label: String,
    pub created_at_ns: i64,
    pub mirror_width: u16,
    pub data_width: u16,
    pub parity_width: u16,
}

#[derive(Debug)]
pub struct MemberSpec<D> {
    pub device: D,
    pub device_id: DeviceId,
    pub geometry: Geometry,
}

#[derive(Debug, Clone)]
pub(crate) struct MultiState {
    pub(crate) generation: u64,
    pub(crate) data_width: u16,
    pub(crate) parity_width: u16,
    pub(crate) mirror_width: u16,
}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct RebuildReport {
    pub records_rebuilt: u64,
    pub copies_written: u64,
    pub snapshots_rewritten: u64,
    pub tx_id: u64,
}

#[derive(Debug, Clone)]
struct StripeHeal {
    moved: std::collections::HashMap<(u16, u64), Extent>,
    parity_extents: Vec<Extent>,
}

impl StripeHeal {
    fn new_data_extent(&self, old: Extent) -> Extent {
        self.moved
            .get(&(old.device_index, old.offset))
            .copied()
            .unwrap_or(old)
    }
}

type StripeMembers =
    std::collections::HashMap<(u16, u64), std::collections::BTreeSet<(u16, u64, u64)>>;

type PlacedStripe = (Vec<(u16, Allocation)>, Vec<(u16, Allocation)>);

type LiveStripe = (Vec<Extent>, HashSet<(u16, u64)>);

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct ScrubReport {
    pub records_checked: u64,
    pub copies_checked: u64,
    pub copies_bad: u64,
    pub copies_repaired: u64,
    pub copies_unrepairable: u64,
    pub copies_missing: u64,
}

impl ScrubReport {
    pub fn healthy(&self) -> bool {
        self.copies_bad == self.copies_repaired && self.copies_unrepairable == 0
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct CompactReport {
    pub stripes_compacted: u64,
    pub records_rewritten: u64,
    pub reclaim: ReclaimReport,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ReclaimReport {
    pub stripes_reset: u64,
    pub zones_reset: u64,
    pub bytes_reclaimed: u64,
    pub tx_id: u64,
}

type ImportCandidate<D> = (D, Superblock, Option<(Commit, Topology)>);

#[derive(Debug)]
pub struct Pool<D: BlockDevice> {
    pub(crate) devices: Vec<PartitionView<D>>,
    pub(crate) superblocks: Vec<Superblock>,
    pub(crate) allocators: Vec<ZoneAllocator>,
    pub(crate) member_slots: Vec<Option<usize>>,
    pub(crate) member_ids: Vec<DeviceId>,
    pub(crate) member_geometries: Vec<Geometry>,
    pub(crate) removed: Vec<bool>,
    pub(crate) absent_chains: Vec<Option<TopologyMember>>,
    pub(crate) evacuating: Option<u16>,
    pub(crate) wounded: bool,
    pub(crate) degrade_commit: bool,
    pub(crate) live_degrade: Option<LiveDegrade>,
    pub(crate) thin_metadata_published: bool,
    pub(crate) orphaned: Vec<DeviceId>,
    pub(crate) multi: Option<MultiState>,
    pub(crate) tree: MetadataTree,
    pub(crate) committed_tx: u64,
    pub(crate) read_only: bool,
    pub(crate) last_metadata_root: Vec<Extent>,
    pub(crate) dirty_members: HashSet<u16>,
    pub(crate) force_full_commit: bool,
    pub(crate) last_roster_members: Vec<TopologyMember>,
    pub(crate) last_participation: Vec<std::time::Instant>,
    pub(crate) probe_staleness: std::time::Duration,
    pub(crate) suspects: std::sync::Mutex<HashSet<u16>>,
    pub(crate) commit_in_flight: bool,
}

impl<D: BlockDevice> Pool<D> {
    pub fn create(device: D, params: CreateParams) -> Result<Self> {
        let CreateParams {
            pool_id,
            device_id,
            geometry,
            case_sensitivity,
            dirent_hash_seed,
            label,
            created_at_ns,
        } = params;
        Self::create_impl(
            vec![MemberSpec {
                device,
                device_id,
                geometry,
            }],
            PoolParams {
                pool_id,
                case_sensitivity,
                dirent_hash_seed,
                label,
                created_at_ns,
                mirror_width: 1,
                data_width: 1,
                parity_width: 0,
            },
            false,
        )
    }

    pub fn create_multi(members: Vec<MemberSpec<D>>, params: PoolParams) -> Result<Self> {
        if members.is_empty() {
            return Err(ScaleFsError::InvalidArgument("a pool needs a member"));
        }
        Self::create_impl(members, params, true)
    }

    fn create_impl(members: Vec<MemberSpec<D>>, params: PoolParams, multi: bool) -> Result<Self> {
        if members.len() > usize::from(u16::MAX) {
            return Err(ScaleFsError::InvalidArgument("too many pool members"));
        }
        let mut ids = HashSet::new();
        if !members.iter().all(|member| ids.insert(member.device_id)) {
            return Err(ScaleFsError::InvalidArgument(
                "pool members must have distinct device ids",
            ));
        }
        if params.mirror_width == 0 || usize::from(params.mirror_width) > members.len() {
            return Err(ScaleFsError::InvalidArgument(
                "mirror width must be between one and the member count",
            ));
        }
        if params.mirror_width > 1 && !multi {
            return Err(ScaleFsError::InvalidArgument(
                "mirrors need a multi-device pool",
            ));
        }
        match (params.data_width, params.parity_width) {
            (1, 0) => {}
            (data, parity @ 1..) => {
                if !multi {
                    return Err(ScaleFsError::InvalidArgument(
                        "parity needs a multi-device pool",
                    ));
                }
                if data < 2 || usize::from(data) > crate::rs::MAX_DATA {
                    return Err(ScaleFsError::InvalidArgument(
                        "data width must be between 2 and 64 on parity pools",
                    ));
                }
                if usize::from(parity) > crate::rs::MAX_PARITY {
                    return Err(ScaleFsError::InvalidArgument(
                        "parity width must be between 1 and 3",
                    ));
                }
                if params.mirror_width <= parity {
                    return Err(ScaleFsError::InvalidArgument(
                        "the metadata mirror must exceed the parity width",
                    ));
                }
            }
            _ => {
                return Err(ScaleFsError::InvalidArgument(
                    "data width above 1 needs a parity width",
                ));
            }
        }
        let mut devices = Vec::with_capacity(members.len());
        let mut superblocks = Vec::with_capacity(members.len());
        let mut allocators = Vec::with_capacity(members.len());
        for member in members {
            let geometry = member.geometry.validate()?;
            check_member_fits(&member.device, geometry)?;
            let superblock = Superblock {
                pool_id: params.pool_id,
                device_id: member.device_id,
                created_at_ns: params.created_at_ns,
                topology_generation: 1,
                feature_compat: 0,
                feature_ro_compat: 0,
                feature_incompat: match (multi, params.parity_width > 0) {
                    (true, true) => FEATURE_INCOMPAT_MULTI_DEVICE | FEATURE_INCOMPAT_PARITY,
                    (true, false) => FEATURE_INCOMPAT_MULTI_DEVICE,
                    (false, _) => 0,
                },
                geometry,
                case_sensitivity: params.case_sensitivity,
                unicode_version: crate::unicode::NEWEST_SUPPORTED_UNICODE_VERSION,
                dirent_hash_seed: params.dirent_hash_seed,
                newest_commit: None,
                aux_record: None,
                label: params.label.clone(),
            };
            encode_superblock(&superblock)?;
            allocators.push(ZoneAllocator::new(geometry)?);
            superblocks.push(superblock);
            devices.push(format_member_wrapper(
                member.device,
                params.pool_id,
                member.device_id,
            )?);
        }

        let mut tree = MetadataTree::new();
        tree.insert(
            MetadataKey {
                object_id: 0,
                item_type: ITEM_POOL_STATE,
                offset: 0,
            },
            MetadataValue::PoolState { next_object_id: 2 },
        )?;
        tree.insert(
            MetadataKey {
                object_id: ROOT_INODE,
                item_type: ITEM_INODE,
                offset: 0,
            },
            MetadataValue::Inode(InodeAttrs {
                size: 0,
                mode: 0o040755,
                uid: 0,
                gid: 0,
                nlink: 1,
                attrs: 0,
                bsd_flags: 0,
                crtime_ns: params.created_at_ns,
                mtime_ns: params.created_at_ns,
                ctime_ns: params.created_at_ns,
                atime_ns: params.created_at_ns,
            }),
        )?;

        let member_count = devices.len();
        let member_slots = (0..member_count).map(Some).collect();
        let member_ids = superblocks.iter().map(|sb| sb.device_id).collect();
        let member_geometries = superblocks.iter().map(|sb| sb.geometry).collect();
        let removed = vec![false; devices.len()];
        let absent_chains = vec![None; devices.len()];
        let orphaned = Vec::new();
        let mut pool = Self {
            devices,
            superblocks,
            allocators,
            member_slots,
            member_ids,
            member_geometries,
            removed,
            absent_chains,
            evacuating: None,
            wounded: false,
            degrade_commit: false,
            live_degrade: None,
            thin_metadata_published: false,
            orphaned,
            multi: multi.then_some(MultiState {
                generation: 1,
                data_width: params.data_width,
                parity_width: params.parity_width,
                mirror_width: params.mirror_width,
            }),
            tree,
            committed_tx: 0,
            read_only: false,
            last_metadata_root: Vec::new(),
            dirty_members: HashSet::new(),
            force_full_commit: true,
            last_roster_members: Vec::new(),
            last_participation: vec![std::time::Instant::now(); member_count],
            probe_staleness: PARTICIPATION_STALENESS,
            suspects: std::sync::Mutex::new(HashSet::new()),
            commit_in_flight: false,
        };
        pool.apply_actuator_ranges();
        pool.commit(AllocPurpose::Normal, params.created_at_ns)?;
        Ok(pool)
    }

    pub fn open(device: D) -> Result<Self> {
        Self::open_view(crate::gpt::member_view(device)?)
    }

    fn open_view(device: PartitionView<D>) -> Result<Self> {
        let mut candidates: Vec<(Superblock, Commit)> = Vec::new();
        let mut last_error = ScaleFsError::Corrupt("no valid superblock found");

        for offset in superblock_slots(device.len()) {
            let superblock =
                read_prefix(&device, offset).and_then(|bytes| decode_superblock(&bytes));
            match superblock {
                Ok(superblock) => {
                    if superblock.unknown_incompat() != 0 {
                        return Err(ScaleFsError::Unsupported(
                            "pool uses incompatible features unknown to this build",
                        ));
                    }
                    superblock.require_supported_unicode_version()?;
                    if superblock.feature_incompat & FEATURE_INCOMPAT_MULTI_DEVICE != 0 {
                        return Err(ScaleFsError::Unsupported(
                            "pool spans multiple devices: supply every member to import it",
                        ));
                    }
                    match load_candidate(&device, superblock) {
                        Ok(candidate) => candidates.push(candidate),
                        Err(err) => last_error = err,
                    }
                }
                Err(err) => last_error = err,
            }
        }

        if candidates.len() == 2 {
            let (a, b) = (&candidates[0].0, &candidates[1].0);
            if a.pool_id != b.pool_id || a.device_id != b.device_id {
                return Err(ScaleFsError::Corrupt(
                    "superblock slots disagree on device identity",
                ));
            }
        }
        candidates.sort_by_key(|(_, commit)| std::cmp::Reverse(commit.tx_id));

        for (superblock, commit) in candidates {
            match Self::load(&device, &superblock, &commit) {
                Ok((allocator, tree)) => {
                    let read_only = superblock.unknown_ro_compat() != 0;
                    let mut pool = Self {
                        devices: vec![device],
                        committed_tx: commit.tx_id,
                        last_metadata_root: vec![commit.metadata_root],
                        dirty_members: HashSet::new(),
                        force_full_commit: false,
                        last_roster_members: Vec::new(),
                        last_participation: vec![std::time::Instant::now(); 1],
                        probe_staleness: PARTICIPATION_STALENESS,
                        suspects: std::sync::Mutex::new(HashSet::new()),
                        commit_in_flight: false,
                        member_ids: vec![superblock.device_id],
                        member_geometries: vec![superblock.geometry],
                        superblocks: vec![superblock],
                        allocators: vec![allocator],
                        member_slots: vec![Some(0)],
                        removed: vec![false],
                        absent_chains: vec![None],
                        evacuating: None,
                        wounded: false,
                        degrade_commit: false,
                        live_degrade: None,
                        thin_metadata_published: false,
                        orphaned: Vec::new(),
                        multi: None,
                        tree,
                        read_only,
                    };
                    pool.apply_actuator_ranges();
                    return Ok(pool);
                }
                Err(err) => last_error = err,
            }
        }
        Err(last_error)
    }

    pub fn open_multi(devices: Vec<D>) -> Result<Self> {
        let mut pool = Self::open_multi_impl(Self::member_views(devices)?, false)?;
        pool.apply_actuator_ranges();
        Ok(pool)
    }

    pub fn open_multi_degraded(devices: Vec<D>) -> Result<Self> {
        let mut pool = Self::open_multi_impl(Self::member_views(devices)?, true)?;
        pool.apply_actuator_ranges();
        Ok(pool)
    }

    fn member_views(devices: Vec<D>) -> Result<Vec<PartitionView<D>>> {
        devices.into_iter().map(crate::gpt::member_view).collect()
    }

    fn open_multi_impl(mut devices: Vec<PartitionView<D>>, allow_degraded: bool) -> Result<Self> {
        match devices.len() {
            0 => return Err(ScaleFsError::InvalidArgument("no devices supplied")),
            1 => {
                let superblock = any_superblock(&devices[0])?;
                if superblock.feature_incompat & FEATURE_INCOMPAT_MULTI_DEVICE == 0 {
                    return Self::open_view(devices.pop().expect("length checked"));
                }
            }
            _ => {}
        }

        let mut candidates = Vec::with_capacity(devices.len());
        for device in devices {
            let superblock = any_superblock(&device)?;
            if superblock.unknown_incompat() != 0 {
                return Err(ScaleFsError::Unsupported(
                    "pool uses incompatible features unknown to this build",
                ));
            }
            superblock.require_supported_unicode_version()?;
            let chain = best_candidate(&device).ok().and_then(|(_, commit)| {
                let aux = commit.aux_root?;
                let bytes = read_extent_from_set(std::slice::from_ref(&device), aux).ok()?;
                let roster = decode_topology(&bytes).ok()?;
                (roster.tx_id == commit.tx_id).then_some((commit, roster))
            });
            candidates.push((device, superblock, chain));
        }
        let first = &candidates[0].1;
        let (pool_id, dirent_hash_seed, case_sensitivity) = (
            first.pool_id,
            first.dirent_hash_seed,
            first.case_sensitivity,
        );
        for (_, superblock, _) in &candidates {
            if superblock.pool_id != pool_id {
                return Err(ScaleFsError::InvalidArgument(
                    "the supplied devices belong to different pools",
                ));
            }
            if superblock.dirent_hash_seed != dirent_hash_seed
                || superblock.case_sensitivity != case_sensitivity
            {
                return Err(ScaleFsError::Corrupt(
                    "members disagree on pool-wide settings",
                ));
            }
        }
        let mut ids = HashSet::new();
        if !candidates
            .iter()
            .all(|(_, superblock, _)| ids.insert(superblock.device_id))
        {
            return Err(ScaleFsError::InvalidArgument(
                "the same member was supplied twice",
            ));
        }

        let mut views: Vec<Topology> = candidates
            .iter()
            .filter_map(|(_, _, chain)| chain.as_ref().map(|(_, roster)| roster.clone()))
            .collect();
        Self::order_candidate_views(&mut views);
        if views.is_empty() {
            return Err(ScaleFsError::Corrupt(
                "no device carries a valid commit chain",
            ));
        }

        let mut refusal: Option<ScaleFsError> = None;
        for roster in &views {
            match Self::assemble_view(&candidates, roster, allow_degraded) {
                Ok(plan) => return Self::adopt_view(candidates, roster, plan),
                Err(err) => {
                    if refusal.is_none() {
                        refusal = Some(err);
                    }
                }
            }
        }
        Err(refusal.expect("at least one view was tried"))
    }

    fn order_candidate_views(views: &mut Vec<Topology>) {
        views.sort_by_key(|roster| std::cmp::Reverse((roster.tx_id, roster.topology_generation)));
        views.dedup_by_key(|roster| roster.tx_id);
    }

    fn assemble_view(
        candidates: &[ImportCandidate<PartitionView<D>>],
        roster: &Topology,
        allow_degraded: bool,
    ) -> Result<Vec<Option<usize>>> {
        let mut plan: Vec<Option<usize>> = vec![None; roster.members.len()];
        for (index, (_, superblock, _)) in candidates.iter().enumerate() {
            if let Some(member) = roster.member_index(superblock.device_id)
                && roster.members[usize::from(member)].state == MemberState::Active
            {
                plan[usize::from(member)] = Some(index);
            }
        }
        let missing: Vec<DeviceId> = roster
            .members
            .iter()
            .zip(&plan)
            .filter(|(member, slot)| member.state == MemberState::Active && slot.is_none())
            .map(|(member, _)| member.device_id)
            .collect();
        let tolerated = if roster.parity_width > 0 {
            usize::from(
                roster
                    .parity_width
                    .min(roster.mirror_width.saturating_sub(1)),
            )
        } else {
            usize::from(roster.mirror_width.saturating_sub(1))
        };
        if !missing.is_empty() && (!allow_degraded || missing.len() > tolerated) {
            return Err(ScaleFsError::MissingMembers { missing });
        }
        for (member, slot) in roster.members.iter().zip(&plan) {
            let Some(index) = *slot else { continue };
            if candidates[index].0.len() < member.geometry.capacity_bytes() {
                return Err(ScaleFsError::Corrupt(
                    "device is smaller than its recorded geometry",
                ));
            }
            let device = std::slice::from_ref(&candidates[index].0);
            let commit_bytes = read_extent_from_set(
                device,
                Extent {
                    device_index: 0,
                    ..member.newest_commit
                },
            )?;
            let commit = decode_commit(&commit_bytes)?;
            if commit.tx_id != member.newest_tx {
                return Err(ScaleFsError::Corrupt(
                    "member state does not match the roster",
                ));
            }
            let summary_bytes = read_extent_from_set(
                device,
                Extent {
                    device_index: 0,
                    ..member.newest_summary
                },
            )?;
            decode_record(&summary_bytes)?;
        }
        Ok(plan)
    }

    fn adopt_view(
        candidates: Vec<ImportCandidate<PartitionView<D>>>,
        roster: &Topology,
        plan: Vec<Option<usize>>,
    ) -> Result<Self> {
        let mut taken: Vec<Option<(PartitionView<D>, Superblock)>> = candidates
            .into_iter()
            .map(|(device, superblock, _)| Some((device, superblock)))
            .collect();
        let mut orphaned: Vec<DeviceId> = Vec::new();

        let mut ordered_devices = Vec::new();
        let mut superblocks = Vec::new();
        let mut member_slots: Vec<Option<usize>> = Vec::with_capacity(plan.len());
        for slot in &plan {
            match slot {
                Some(index) => {
                    let (device, mut superblock) = taken[*index].take().expect("planned once");
                    superblock.topology_generation = roster.topology_generation;
                    member_slots.push(Some(ordered_devices.len()));
                    ordered_devices.push(device);
                    superblocks.push(superblock);
                }
                None => member_slots.push(None),
            }
        }
        for leftover in taken.into_iter().flatten() {
            orphaned.push(leftover.1.device_id);
        }

        let feature_compat = superblocks
            .iter()
            .fold(0, |acc, sb| acc | sb.feature_compat);
        let feature_ro_compat = superblocks
            .iter()
            .fold(0, |acc, sb| acc | sb.feature_ro_compat);
        let feature_incompat = superblocks
            .iter()
            .fold(0, |acc, sb| acc | sb.feature_incompat);
        for superblock in &mut superblocks {
            superblock.feature_compat = feature_compat;
            superblock.feature_ro_compat = feature_ro_compat;
            superblock.feature_incompat = feature_incompat;
        }

        let degraded = member_slots
            .iter()
            .zip(roster.members.iter())
            .any(|(slot, member)| slot.is_none() && member.state == MemberState::Active);
        let read_only = degraded
            || superblocks
                .iter()
                .any(|superblock| superblock.unknown_ro_compat() != 0);
        let mut allocators = Vec::with_capacity(superblocks.len());
        for (index, member) in roster.members.iter().enumerate() {
            let Some(slot) = member_slots[index] else {
                continue;
            };
            let summary = read_extent_from_set(
                std::slice::from_ref(&ordered_devices[slot]),
                Extent {
                    device_index: 0,
                    ..member.newest_summary
                },
            )?;
            allocators.push(ZoneAllocator::decode(superblocks[slot].geometry, &summary)?);
        }
        let root_replicas = roster.metadata_root_replicas.clone();
        let tree = MetadataTree::load(&root_replicas, &mut |copies| {
            read_any_copy_slotted(&ordered_devices, &member_slots, copies)
        })?;

        let absent_chains: Vec<Option<TopologyMember>> = roster
            .members
            .iter()
            .zip(&member_slots)
            .map(|(member, slot)| {
                (slot.is_none() && member.state == MemberState::Active).then_some(*member)
            })
            .collect();
        let thin_metadata_published = superblocks
            .iter()
            .any(|superblock| superblock.feature_incompat & FEATURE_INCOMPAT_THIN_METADATA != 0);
        let pool = Self {
            devices: ordered_devices,
            superblocks,
            allocators,
            member_slots,
            member_ids: roster
                .members
                .iter()
                .map(|member| member.device_id)
                .collect(),
            member_geometries: roster
                .members
                .iter()
                .map(|member| member.geometry)
                .collect(),
            removed: roster
                .members
                .iter()
                .map(|member| member.state == MemberState::Removed)
                .collect(),
            absent_chains,
            evacuating: None,
            wounded: false,
            degrade_commit: false,
            live_degrade: None,
            thin_metadata_published,
            orphaned,
            multi: Some(MultiState {
                generation: roster.topology_generation,
                data_width: roster.data_width,
                parity_width: roster.parity_width,
                mirror_width: roster.mirror_width,
            }),
            tree,
            committed_tx: roster.tx_id,
            read_only,
            last_metadata_root: root_replicas,
            dirty_members: HashSet::new(),
            force_full_commit: false,
            last_roster_members: roster.members.clone(),
            last_participation: vec![std::time::Instant::now(); roster.members.len()],
            probe_staleness: PARTICIPATION_STALENESS,
            suspects: std::sync::Mutex::new(HashSet::new()),
            commit_in_flight: false,
        };
        Ok(pool)
    }

    pub fn orphaned_members(&self) -> &[DeviceId] {
        &self.orphaned
    }

    pub fn missing_members(&self) -> Vec<u16> {
        self.member_slots
            .iter()
            .enumerate()
            .filter(|(member, slot)| slot.is_none() && !self.removed[*member])
            .map(|(member, _)| member as u16)
            .collect()
    }

    pub fn is_degraded(&self) -> bool {
        !self.missing_members().is_empty()
    }

    pub fn allocator_for_member(&self, member: u16) -> Option<&ZoneAllocator> {
        let slot = (*self.member_slots.get(usize::from(member))?)?;
        self.allocators.get(slot)
    }

    pub fn superblock_for_member(&self, member: u16) -> Option<&Superblock> {
        let slot = (*self.member_slots.get(usize::from(member))?)?;
        self.superblocks.get(slot)
    }

    pub fn mirror_width(&self) -> u16 {
        self.multi.as_ref().map_or(1, |state| state.mirror_width)
    }

    pub fn parity_width(&self) -> u16 {
        self.multi.as_ref().map_or(0, |state| state.parity_width)
    }

    pub fn data_width(&self) -> u16 {
        self.multi.as_ref().map_or(1, |state| state.data_width)
    }

    fn apply_actuator_ranges(&mut self) {
        for slot in 0..self.devices.len() {
            let ranges = self.devices[slot].actuator_ranges();
            self.allocators[slot].set_actuator_byte_ranges(&ranges);
        }
    }

    fn load(
        device: &PartitionView<D>,
        superblock: &Superblock,
        commit: &Commit,
    ) -> Result<(ZoneAllocator, MetadataTree)> {
        if device.len() < superblock.geometry.capacity_bytes() {
            return Err(ScaleFsError::Corrupt(
                "device is smaller than its formatted geometry",
            ));
        }
        let summary = read_extent_from_set(std::slice::from_ref(device), commit.allocator_summary)?;
        let allocator = ZoneAllocator::decode(superblock.geometry, &summary)?;
        let tree = MetadataTree::load(&[commit.metadata_root], &mut |copies| {
            read_any_copy(std::slice::from_ref(device), copies)
        })?;
        Ok((allocator, tree))
    }

    pub fn commit(&mut self, purpose: AllocPurpose, created_at_ns: i64) -> Result<u64> {
        self.commit_impl(purpose, created_at_ns)
            .map_err(|failure| failure.error)
    }

    fn commit_impl(
        &mut self,
        purpose: AllocPurpose,
        created_at_ns: i64,
    ) -> std::result::Result<u64, CommitFailure> {
        let plan = self
            .plan_commit_impl(purpose, created_at_ns)
            .map_err(|error| CommitFailure {
                error,
                suspect: None,
            })?;
        match execute_commit(&self.devices, &plan) {
            Ok(()) => Ok(self.publish_commit_impl(plan)),
            Err(failure) => {
                self.abandon_commit_impl(plan, failure.suspect);
                Err(failure)
            }
        }
    }

    pub fn commit_or_degrade(
        &mut self,
        purpose: AllocPurpose,
        created_at_ns: i64,
    ) -> Result<CommitOutcome> {
        match self.commit_impl(purpose, created_at_ns) {
            Ok(tx_id) => Ok(CommitOutcome::Committed { tx_id }),
            Err(failure) if self.wounded => self.recover_abandoned(failure, purpose, created_at_ns),
            Err(failure) => Err(failure.error),
        }
    }

    fn recover_abandoned(
        &mut self,
        failure: CommitFailure,
        purpose: AllocPurpose,
        created_at_ns: i64,
    ) -> Result<CommitOutcome> {
        debug_assert!(self.wounded, "recovery runs on a wounded pool");
        let Some(member) = failure.suspect else {
            return Err(failure.error);
        };
        if !self.live_degrade_possible(member) {
            return Err(failure.error);
        }
        self.wounded = false;
        let retry = match self.commit_impl(purpose, created_at_ns) {
            Ok(tx_id) => return Ok(CommitOutcome::Committed { tx_id }),
            Err(retry) => retry,
        };
        if retry.suspect != Some(member) {
            return Err(retry.error);
        }
        let device_id = self.member_ids[usize::from(member)];
        self.detach_member_in_place(member);
        self.degrade_commit = true;
        self.wounded = false;
        let outcome = self.commit_impl(purpose, created_at_ns);
        self.degrade_commit = false;
        match outcome {
            Ok(tx_id) => {
                self.read_only = true;
                let degrade = LiveDegrade {
                    member,
                    device_id,
                    tx_id,
                };
                self.live_degrade = Some(degrade.clone());
                Ok(CommitOutcome::Degraded(degrade))
            }
            Err(failure) => Err(failure.error),
        }
    }

    fn live_degrade_possible(&self, member: u16) -> bool {
        let Some(state) = &self.multi else {
            return false;
        };
        if self.read_only || self.member_slot(member).is_none() {
            return false;
        }
        let tolerated = if state.parity_width > 0 {
            usize::from(state.parity_width.min(state.mirror_width.saturating_sub(1)))
        } else {
            usize::from(state.mirror_width.saturating_sub(1))
        };
        self.missing_members().len() < tolerated
    }

    fn detach_member_in_place(&mut self, member: u16) {
        let index = usize::from(member);
        let position = self.member_slots[index]
            .take()
            .expect("only a present member can be detached in place");
        drop(self.devices.remove(position));
        self.superblocks.remove(position);
        self.allocators.remove(position);
        for slot in self.member_slots.iter_mut().flatten() {
            if *slot > position {
                *slot -= 1;
            }
        }
        self.apply_actuator_ranges();
        self.absent_chains[index] = Some(self.last_roster_members[index]);
        self.dirty_members.remove(&member);
        self.suspects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&member);
        if self.evacuating == Some(member) {
            self.evacuating = None;
        }
        self.force_full_commit = true;
    }

    pub fn live_degrade(&self) -> Option<&LiveDegrade> {
        self.live_degrade.as_ref()
    }

    fn plan_commit_impl(
        &mut self,
        purpose: AllocPurpose,
        created_at_ns: i64,
    ) -> Result<PlannedCommit> {
        if self.commit_in_flight {
            return Err(ScaleFsError::Unsupported(
                "a commit is already in flight: publish or abandon it first",
            ));
        }
        if self.wounded {
            return Err(ScaleFsError::Unsupported(
                "a commit failed while writing: reopen the pool before committing again",
            ));
        }
        if self.read_only {
            return Err(ScaleFsError::Unsupported(
                "pool is read-only: it uses read-only-compatible features unknown to this build",
            ));
        }
        let saved_allocators = self.allocators.clone();
        let taken_dirty = std::mem::take(&mut self.dirty_members);
        let taken_force_full = std::mem::take(&mut self.force_full_commit);
        let drained_suspects: Vec<u16> = self
            .suspects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain()
            .collect();
        match self.plan_commit_stages(
            purpose,
            created_at_ns,
            &taken_dirty,
            taken_force_full,
            &drained_suspects,
        ) {
            Ok(mut plan) => {
                plan.taken_dirty = taken_dirty;
                plan.taken_force_full = taken_force_full;
                plan.drained_suspects = drained_suspects;
                if !plan.dropped_probe_suspects.is_empty() {
                    self.suspects
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .extend(plan.dropped_probe_suspects.iter().copied());
                }
                self.commit_in_flight = true;
                Ok(plan)
            }
            Err(err) => {
                self.allocators = saved_allocators;
                self.tree.mark_all_dirty();
                self.dirty_members.extend(taken_dirty);
                self.force_full_commit |= taken_force_full;
                self.suspects
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .extend(drained_suspects);
                Err(err)
            }
        }
    }

    fn plan_chain_allocations(
        allocator: &mut ZoneAllocator,
        commit_len: u64,
        roster_len: u64,
        is_multi: bool,
        purpose: AllocPurpose,
    ) -> Result<ChainAllocations> {
        let commit_alloc = allocator.allocate(ZoneClass::Metadata, commit_len, purpose)?;
        let roster_alloc = if is_multi {
            Some(allocator.allocate(ZoneClass::Metadata, roster_len, purpose)?)
        } else {
            None
        };
        let summary_len = allocator.encoded_len();
        let summary_alloc = allocator.allocate(ZoneClass::Metadata, summary_len as u64, purpose)?;
        let summary_bytes = allocator.encode();
        debug_assert_eq!(summary_bytes.len(), summary_len);
        Ok((
            commit_alloc,
            roster_alloc,
            (summary_alloc, std::sync::Arc::new(summary_bytes)),
        ))
    }

    fn plan_commit_stages(
        &mut self,
        purpose: AllocPurpose,
        created_at_ns: i64,
        dirty_members: &HashSet<u16>,
        force_full: bool,
        drained_suspects: &[u16],
    ) -> Result<PlannedCommit> {
        let tx_id = self.committed_tx + 1;
        let slot_count = self.devices.len();
        let members_total = self.member_slots.len();
        let commit_len: u64 = if self.multi.is_some() { 117 } else { 97 };
        let mirror_width = self.multi.as_ref().map_or(1, |state| state.mirror_width);
        let roster_len =
            (RECORD_ENVELOPE_LEN + 32 + 100 * members_total + 20 * usize::from(mirror_width))
                as u64;

        let present = self.member_slots.iter().flatten().count() as u16;
        let page_copies = if self.degrade_commit {
            mirror_width.min(present).max(1)
        } else {
            mirror_width
        };
        let thin_metadata = page_copies < mirror_width;
        let force_full = if thin_metadata != self.thin_metadata_published {
            for superblock in &mut self.superblocks {
                if thin_metadata {
                    superblock.feature_incompat |= FEATURE_INCOMPAT_THIN_METADATA;
                } else {
                    superblock.feature_incompat &= !FEATURE_INCOMPAT_THIN_METADATA;
                }
            }
            true
        } else {
            force_full
        };
        let tree = &mut self.tree;
        let allocators = &mut self.allocators;
        let member_slots = &self.member_slots;
        let exclude: Vec<u16> = self.evacuating.into_iter().collect();
        let (root_replicas, pages) = tree.plan_commit(&mut |len| {
            Ok(place_distinct_excluding(
                allocators,
                member_slots,
                ZoneClass::Metadata,
                len,
                purpose,
                page_copies,
                &exclude,
            )?
            .into_iter()
            .map(|(member, allocation)| (member, allocation.offset))
            .collect())
        })?;
        let metadata_root = root_replicas[0];

        let full =
            self.multi.is_none() || force_full || self.last_roster_members.len() != members_total;
        let mut participating = vec![full; slot_count];
        let mut probe_only = vec![false; slot_count];
        if !full {
            for member in dirty_members {
                if let Some(slot) = self.member_slot(*member) {
                    participating[slot] = true;
                }
            }
            for member in drained_suspects {
                if let Some(slot) = self.member_slot(*member) {
                    probe_only[slot] = !participating[slot];
                    participating[slot] = true;
                }
            }
            for (member, last) in self.last_participation.iter().enumerate() {
                if last.elapsed() >= self.probe_staleness
                    && let Some(slot) = self.member_slot(member as u16)
                {
                    probe_only[slot] = !participating[slot] || probe_only[slot];
                    participating[slot] = true;
                }
            }
            for page in &pages {
                for extent in &page.extents {
                    let slot = self
                        .member_slot(extent.device_index)
                        .expect("pages are placed on present members");
                    participating[slot] = true;
                    probe_only[slot] = false;
                }
            }
        }

        let mut commit_allocs: Vec<Option<Allocation>> = vec![None; slot_count];
        let mut roster_allocs: Vec<Option<Allocation>> = vec![None; slot_count];
        let mut summaries: Vec<Option<(Allocation, std::sync::Arc<Vec<u8>>)>> =
            (0..slot_count).map(|_| None).collect();
        let is_multi = self.multi.is_some();
        let mut dropped_probe_suspects: Vec<u16> = Vec::new();
        for i in 0..slot_count {
            if !participating[i] {
                continue;
            }
            let saved = probe_only[i].then(|| self.allocators[i].clone());
            match Self::plan_chain_allocations(
                &mut self.allocators[i],
                commit_len,
                roster_len,
                is_multi,
                purpose,
            ) {
                Ok((commit_alloc, roster_alloc, summary)) => {
                    commit_allocs[i] = Some(commit_alloc);
                    roster_allocs[i] = roster_alloc;
                    summaries[i] = Some(summary);
                }
                Err(ScaleFsError::OutOfSpace) if probe_only[i] => {
                    self.allocators[i] = saved.expect("probe-only members keep a restore point");
                    participating[i] = false;
                    if let Some(member) = (0..members_total as u16)
                        .find(|member| self.member_slot(*member) == Some(i))
                        && drained_suspects.contains(&member)
                    {
                        dropped_probe_suspects.push(member);
                    }
                }
                Err(err) => return Err(err),
            }
        }
        if !participating.contains(&true) {
            for extent in &root_replicas {
                let slot = self
                    .member_slot(extent.device_index)
                    .expect("root replicas live on present members");
                participating[slot] = true;
            }
            for i in 0..slot_count {
                if !participating[i] || summaries[i].is_some() {
                    continue;
                }
                let (commit_alloc, roster_alloc, summary) = Self::plan_chain_allocations(
                    &mut self.allocators[i],
                    commit_len,
                    roster_len,
                    is_multi,
                    purpose,
                )?;
                commit_allocs[i] = Some(commit_alloc);
                roster_allocs[i] = roster_alloc;
                summaries[i] = Some(summary);
            }
        }

        let roster_members: Option<Vec<TopologyMember>> = self.multi.as_ref().map(|_| {
            (0..members_total)
                .map(|member| match self.member_slots[member] {
                    None if !self.removed[member] => {
                        self.absent_chains[member].expect("absent active members carry their chain")
                    }
                    None => TopologyMember {
                        device_id: self.member_ids[member],
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
                        geometry: self.member_geometries[member],
                    },
                    Some(slot) if !participating[slot] => {
                        let carried = self.last_roster_members[member];
                        debug_assert_eq!(carried.device_id, self.superblocks[slot].device_id);
                        debug_assert_eq!(carried.state, MemberState::Active);
                        carried
                    }
                    Some(slot) => {
                        let (summary_alloc, summary_bytes) =
                            summaries[slot].as_ref().expect("participants allocate");
                        TopologyMember {
                            device_id: self.superblocks[slot].device_id,
                            state: MemberState::Active,
                            newest_tx: tx_id,
                            newest_commit: Extent {
                                device_index: member as u16,
                                offset: commit_allocs[slot].expect("participants allocate").offset,
                                length: commit_len,
                            },
                            newest_summary: Extent {
                                device_index: member as u16,
                                offset: summary_alloc.offset,
                                length: summary_bytes.len() as u64,
                            },
                            geometry: self.superblocks[slot].geometry,
                        }
                    }
                })
                .collect()
        });
        let roster_arc = match (&self.multi, &roster_members) {
            (Some(state), Some(members)) => {
                let bytes = encode_topology(&Topology {
                    tx_id,
                    topology_generation: state.generation,
                    data_width: state.data_width,
                    parity_width: state.parity_width,
                    mirror_width: state.mirror_width,
                    members: members.clone(),
                    metadata_root_replicas: root_replicas.clone(),
                })?;
                debug_assert_eq!(bytes.len() as u64, roster_len);
                Some(std::sync::Arc::new(bytes))
            }
            _ => None,
        };

        let mut stage_pages_and_summaries = Vec::new();
        for page in pages {
            let bytes = std::sync::Arc::new(page.bytes);
            for extent in &page.extents {
                let slot = self
                    .member_slot(extent.device_index)
                    .expect("pages are placed on present members");
                stage_pages_and_summaries.push(PlannedWrite {
                    member: Some(extent.device_index),
                    slot,
                    offset: extent.offset,
                    bytes: std::sync::Arc::clone(&bytes),
                    pad: self.superblocks[slot].geometry.logical_block_size as usize,
                });
            }
        }
        for i in 0..slot_count {
            let Some((summary_alloc, summary_bytes)) = &summaries[i] else {
                continue;
            };
            if let (Some(alloc), Some(bytes)) = (&roster_allocs[i], &roster_arc) {
                stage_pages_and_summaries.push(PlannedWrite {
                    member: self.member_of_slot(i),
                    slot: i,
                    offset: alloc.offset,
                    bytes: std::sync::Arc::clone(bytes),
                    pad: self.superblocks[i].geometry.logical_block_size as usize,
                });
            }
            stage_pages_and_summaries.push(PlannedWrite {
                member: self.member_of_slot(i),
                slot: i,
                offset: summary_alloc.offset,
                bytes: std::sync::Arc::clone(summary_bytes),
                pad: self.superblocks[i].geometry.logical_block_size as usize,
            });
        }

        let mut stage_commit_records = Vec::new();
        let mut commit_extents: Vec<Option<Extent>> = vec![None; slot_count];
        for i in 0..slot_count {
            let Some((summary_alloc, summary_bytes)) = &summaries[i] else {
                continue;
            };
            let commit = Commit {
                tx_id,
                supersedes: self.committed_tx,
                created_at_ns,
                metadata_root,
                allocator_summary: Extent {
                    device_index: 0,
                    offset: summary_alloc.offset,
                    length: summary_bytes.len() as u64,
                },
                aux_root: roster_allocs[i].as_ref().map(|alloc| Extent {
                    device_index: 0,
                    offset: alloc.offset,
                    length: roster_len,
                }),
            };
            let commit_bytes = encode_commit(&commit)?;
            debug_assert_eq!(commit_bytes.len() as u64, commit_len);
            let commit_offset = commit_allocs[i].expect("participants allocate").offset;
            stage_commit_records.push(PlannedWrite {
                member: self.member_of_slot(i),
                slot: i,
                offset: commit_offset,
                bytes: std::sync::Arc::new(commit_bytes),
                pad: self.superblocks[i].geometry.logical_block_size as usize,
            });
            commit_extents[i] = Some(Extent {
                device_index: 0,
                offset: commit_offset,
                length: commit_len,
            });
        }

        let mut stage_superblocks = Vec::new();
        for (i, commit_extent) in commit_extents.iter().enumerate() {
            let Some(commit_extent) = commit_extent else {
                continue;
            };
            let mut superblock = self.superblocks[i].clone();
            superblock.newest_commit = Some(*commit_extent);
            let superblock_bytes = std::sync::Arc::new(encode_superblock(&superblock)?);
            for offset in superblock_slots(self.devices[i].len()) {
                stage_superblocks.push(PlannedWrite {
                    member: None,
                    slot: i,
                    offset,
                    bytes: std::sync::Arc::clone(&superblock_bytes),
                    pad: SUPERBLOCK_PAD,
                });
            }
        }

        Ok(PlannedCommit {
            tx_id,
            purpose,
            created_at_ns,
            thin_metadata,
            participating,
            stage_pages_and_summaries,
            stage_commit_records,
            stage_superblocks,
            root_replicas,
            roster_members,
            commit_extents,
            taken_dirty: HashSet::new(),
            taken_force_full: false,
            drained_suspects: Vec::new(),
            dropped_probe_suspects,
        })
    }

    fn publish_commit_impl(&mut self, plan: PlannedCommit) -> u64 {
        self.commit_in_flight = false;
        self.committed_tx = plan.tx_id;
        self.thin_metadata_published = plan.thin_metadata;
        self.last_metadata_root = plan.root_replicas;
        if let Some(members) = plan.roster_members {
            self.last_roster_members = members;
        }
        for (i, commit_extent) in plan.commit_extents.iter().enumerate() {
            if let Some(commit_extent) = commit_extent {
                self.superblocks[i].newest_commit = Some(*commit_extent);
            }
        }
        let now = std::time::Instant::now();
        for (member, slot) in self.member_slots.iter().enumerate() {
            if slot.is_some_and(|slot| plan.participating[slot])
                && let Some(last) = self.last_participation.get_mut(member)
            {
                *last = now;
            }
        }
        plan.tx_id
    }

    fn abandon_commit_impl(&mut self, plan: PlannedCommit, suspect: Option<u16>) {
        self.commit_in_flight = false;
        self.wounded = true;
        self.tree.mark_all_dirty();
        self.dirty_members.extend(plan.taken_dirty);
        self.force_full_commit |= plan.taken_force_full;
        {
            let mut suspects = self
                .suspects
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            suspects.extend(plan.drained_suspects);
            if let Some(member) = suspect {
                suspects.insert(member);
            }
        }
    }

    fn member_of_slot(&self, slot: usize) -> Option<u16> {
        self.member_slots
            .iter()
            .position(|entry| *entry == Some(slot))
            .map(|member| member as u16)
    }

    pub(crate) fn place_mirrored(
        &mut self,
        class: ZoneClass,
        length: u64,
        purpose: AllocPurpose,
    ) -> Result<Vec<(u16, Allocation)>> {
        let mirror_width = self.multi.as_ref().map_or(1, |state| state.mirror_width);
        let exclude: Vec<u16> = self.evacuating.into_iter().collect();
        let placements = place_distinct_excluding(
            &mut self.allocators,
            &self.member_slots,
            class,
            length,
            purpose,
            mirror_width,
            &exclude,
        )?;
        for (member, _) in &placements {
            self.dirty_members.insert(*member);
        }
        Ok(placements)
    }

    pub(crate) fn place_stripe(
        &mut self,
        piece_lens: &[u64],
        purpose: AllocPurpose,
    ) -> Result<PlacedStripe> {
        let state = self.multi.as_ref().expect("parity pools are multi-device");
        let parity_count = usize::from(state.parity_width);
        debug_assert!(parity_count >= 1, "place_stripe needs a parity policy");
        debug_assert!(!piece_lens.is_empty());
        let mut want = piece_lens.len();
        loop {
            let coverage = piece_lens[..want]
                .iter()
                .copied()
                .max()
                .expect("stripe has a piece");
            let parity_len = parity_record_len(want, parity_count, coverage);

            let mut order: Vec<(u16, usize)> = self
                .member_slots
                .iter()
                .enumerate()
                .filter_map(|(member, slot)| slot.map(|slot| (member as u16, slot)))
                .filter(|(member, _)| self.evacuating != Some(*member))
                .collect();
            order.sort_by_key(|&(member, slot)| {
                (
                    std::cmp::Reverse(self.allocators[slot].free_usable_zone_count()),
                    member,
                )
            });
            let mut data: Vec<(u16, usize)> = Vec::with_capacity(want);
            let mut parity: Vec<(u16, usize)> = Vec::with_capacity(parity_count);
            for (member, slot) in order {
                if data.len() < want {
                    if self.allocators[slot].can_allocate(
                        ZoneClass::Data,
                        piece_lens[data.len()],
                        purpose,
                    ) {
                        data.push((member, slot));
                    }
                } else if parity.len() < parity_count {
                    if self.allocators[slot].can_allocate(ZoneClass::Parity, parity_len, purpose) {
                        parity.push((member, slot));
                    }
                } else {
                    break;
                }
            }
            if data.len() < want || parity.len() < parity_count {
                if want > 1 {
                    want -= 1;
                    continue;
                }
                return Err(ScaleFsError::OutOfSpace);
            }

            let mut data_placements = Vec::with_capacity(want);
            for (index, (member, slot)) in data.iter().enumerate() {
                let allocation =
                    self.allocators[*slot].allocate(ZoneClass::Data, piece_lens[index], purpose)?;
                self.dirty_members.insert(*member);
                data_placements.push((*member, allocation));
            }
            let mut parity_placements = Vec::with_capacity(parity_count);
            for (member, slot) in &parity {
                let allocation =
                    self.allocators[*slot].allocate(ZoneClass::Parity, parity_len, purpose)?;
                self.dirty_members.insert(*member);
                parity_placements.push((*member, allocation));
            }
            return Ok((data_placements, parity_placements));
        }
    }

    pub(crate) fn note_superblock_change(&mut self) {
        self.force_full_commit = true;
    }

    pub(crate) fn write_record_padded(&self, slot: usize, offset: u64, bytes: &[u8]) -> Result<()> {
        let unit = self.superblocks[slot].geometry.logical_block_size as usize;
        let written = write_padded(&self.devices[slot], offset, bytes, unit);
        if let Err(ScaleFsError::Io(_)) = &written
            && let Some(member) = self.member_of_slot(slot)
        {
            self.note_suspect_member(member);
        }
        written
    }

    fn note_suspect_member(&self, member: u16) {
        self.suspects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(member);
    }

    pub fn read_record(&self, copies: &[Extent]) -> Result<Vec<u8>> {
        let mut last_error = ScaleFsError::Corrupt("record has no copies");
        for extent in copies {
            match self.read_extent(*extent) {
                Ok(bytes) => match decode_record(&bytes) {
                    Ok(_) => return Ok(bytes),
                    Err(err) => last_error = err,
                },
                Err(err) => {
                    if matches!(err, ScaleFsError::Io(_)) {
                        self.note_suspect_member(extent.device_index);
                    }
                    last_error = err;
                }
            }
        }
        Err(last_error)
    }

    pub fn read_extent(&self, extent: Extent) -> Result<Vec<u8>> {
        let slot = self
            .member_slots
            .get(usize::from(extent.device_index))
            .copied()
            .flatten()
            .ok_or(ScaleFsError::Corrupt(
                "extent references a device that is not present",
            ))?;
        read_extent_from_set(
            std::slice::from_ref(&self.devices[slot]),
            Extent {
                device_index: 0,
                ..extent
            },
        )
    }

    pub(crate) fn read_striped(&self, data: Extent, parity_extents: &[Extent]) -> Result<Vec<u8>> {
        match self.read_extent(data) {
            Ok(bytes) if decode_record(&bytes).is_ok() => return Ok(bytes),
            Ok(_) => {}
            Err(err) => {
                if matches!(err, ScaleFsError::Io(_)) {
                    self.note_suspect_member(data.device_index);
                }
            }
        }
        self.reconstruct_piece(data, parity_extents)
    }

    fn reconstruct_piece(&self, target: Extent, parity_extents: &[Extent]) -> Result<Vec<u8>> {
        let mut last_error = ScaleFsError::Corrupt("stripe has no readable parity record");
        for extent in parity_extents {
            let bytes = match self.read_extent(*extent) {
                Ok(bytes) => bytes,
                Err(err) => {
                    if matches!(err, ScaleFsError::Io(_)) {
                        self.note_suspect_member(extent.device_index);
                    }
                    last_error = err;
                    continue;
                }
            };
            match decode_parity_record(&bytes) {
                Ok(descriptor) => return self.reconstruct_from(&descriptor, target),
                Err(err) => last_error = err,
            }
        }
        Err(last_error)
    }

    fn reconstruct_from(&self, descriptor: &ParityRecord, target: Extent) -> Result<Vec<u8>> {
        let data_count = descriptor.data_pieces.len();
        let parity_count = descriptor.parity_pieces.len();
        let coverage = usize::try_from(descriptor.coverage_len)
            .map_err(|_| ScaleFsError::Corrupt("stripe coverage exceeds the address space"))?;
        let column = descriptor
            .data_pieces
            .iter()
            .position(|piece| {
                piece.device_index == target.device_index
                    && piece.offset == target.offset
                    && piece.length == target.length
            })
            .ok_or(ScaleFsError::Corrupt(
                "stripe descriptor does not name the piece being read",
            ))?;

        let mut available: Vec<(usize, Vec<u8>)> = Vec::new();
        let mut erased = vec![column];
        for (index, piece) in descriptor.data_pieces.iter().enumerate() {
            if index == column {
                continue;
            }
            match self.read_extent(*piece) {
                Ok(bytes) if decode_record(&bytes).is_ok() => available.push((index, bytes)),
                Ok(_) => erased.push(index),
                Err(err) => {
                    if matches!(err, ScaleFsError::Io(_)) {
                        self.note_suspect_member(piece.device_index);
                    }
                    erased.push(index);
                }
            }
        }
        for (row, piece) in descriptor.parity_pieces.iter().enumerate() {
            match self.read_extent(*piece) {
                Ok(bytes) => {
                    if let Ok(parity) = decode_parity_record(&bytes)
                        && usize::from(parity.parity_index) == row
                        && parity.data_pieces == descriptor.data_pieces
                        && parity.parity_pieces == descriptor.parity_pieces
                        && parity.coverage_len == descriptor.coverage_len
                    {
                        available.push((data_count + row, parity.parity));
                    }
                }
                Err(err) => {
                    if matches!(err, ScaleFsError::Io(_)) {
                        self.note_suspect_member(piece.device_index);
                    }
                }
            }
        }
        let borrowed: Vec<(usize, &[u8])> = available
            .iter()
            .map(|(column, bytes)| (*column, bytes.as_slice()))
            .collect();
        let mut rebuilt =
            crate::rs::reconstruct_data(data_count, parity_count, coverage, &borrowed, &erased)?;
        let mut bytes = rebuilt.swap_remove(0);
        bytes.truncate(target.length as usize);
        if decode_record(&bytes).is_err() {
            return Err(ScaleFsError::Corrupt(
                "stripe reconstruction failed checksum verification",
            ));
        }
        Ok(bytes)
    }

    pub fn superblock(&self) -> &Superblock {
        &self.superblocks[0]
    }

    pub fn superblocks(&self) -> &[Superblock] {
        &self.superblocks
    }

    pub fn member_count(&self) -> usize {
        self.member_slots.len()
    }

    pub fn committed_tx(&self) -> u64 {
        self.committed_tx
    }

    pub fn read_only(&self) -> bool {
        self.read_only
    }

    pub fn wounded(&self) -> bool {
        self.wounded
    }

    pub fn ensure_mutable(&self) -> Result<()> {
        if self.read_only {
            return Err(ScaleFsError::Unsupported(
                "pool is read-only: mutations are not permitted",
            ));
        }
        if self.wounded {
            return Err(ScaleFsError::Unsupported(
                "a commit failed while writing: reopen the pool before mutating again",
            ));
        }
        Ok(())
    }

    pub fn tree(&self) -> &MetadataTree {
        &self.tree
    }

    pub fn tree_mut(&mut self) -> &mut MetadataTree {
        &mut self.tree
    }

    pub fn allocator(&self) -> &ZoneAllocator {
        &self.allocators[0]
    }

    pub fn allocators(&self) -> &[ZoneAllocator] {
        &self.allocators
    }

    pub fn is_multi(&self) -> bool {
        self.multi.is_some()
    }

    pub fn member_rosters(&self) -> Result<Vec<Topology>> {
        if self.multi.is_none() {
            return Err(ScaleFsError::Unsupported(
                "single-device pools have no roster",
            ));
        }
        self.devices
            .iter()
            .map(|device| {
                let (_, commit) = best_candidate(device)?;
                let aux = commit
                    .aux_root
                    .ok_or(ScaleFsError::Corrupt("multi-device commit lacks a roster"))?;
                let bytes = read_extent_from_set(std::slice::from_ref(device), aux)?;
                let roster = decode_topology(&bytes)?;
                if roster.tx_id != commit.tx_id {
                    return Err(ScaleFsError::Corrupt("roster does not match its commit"));
                }
                Ok(roster)
            })
            .collect()
    }

    pub(crate) fn member_slot(&self, member: u16) -> Option<usize> {
        self.member_slots
            .get(usize::from(member))
            .copied()
            .flatten()
    }

    fn stripe_memberships(&self) -> Result<StripeMembers> {
        let mut memberships = std::collections::HashMap::new();
        let mut visited: HashSet<(u16, u64)> = HashSet::new();
        let mut roots = vec![self.last_metadata_root.clone()];
        while let Some(root) = roots.pop() {
            self.collect_memberships_in_tree(&root, &mut memberships, &mut visited, &mut roots)?;
        }
        Ok(memberships)
    }

    fn collect_memberships_in_tree(
        &self,
        root: &[Extent],
        memberships: &mut StripeMembers,
        visited: &mut HashSet<(u16, u64)>,
        pending_roots: &mut Vec<Vec<Extent>>,
    ) -> Result<()> {
        let first = root
            .first()
            .ok_or(ScaleFsError::Corrupt("tree root has no copies"))?;
        if !visited.insert((first.device_index, first.offset)) {
            return Ok(());
        }
        let bytes = self.read_record(root)?;
        match decode_record(&bytes)?.kind {
            RecordKind::MetadataInternal | RecordKind::MetadataInternalMirrored => {
                for (_, child) in decode_internal_record(&bytes)? {
                    self.collect_memberships_in_tree(&child, memberships, visited, pending_roots)?;
                }
            }
            RecordKind::MetadataLeaf => {
                for (_, value) in decode_leaf_record(&bytes)? {
                    match value {
                        MetadataValue::StripedExtent {
                            extent,
                            parity_extents,
                            ..
                        } => {
                            if let Some(stripe_first) = parity_extents.first() {
                                memberships
                                    .entry((stripe_first.device_index, stripe_first.offset))
                                    .or_default()
                                    .insert((extent.device_index, extent.offset, extent.length));
                            }
                        }
                        MetadataValue::RetainedRoot { metadata_roots, .. } => {
                            pending_roots.push(metadata_roots);
                        }
                        _ => {}
                    }
                }
            }
            _ => return Err(ScaleFsError::Corrupt("expected a metadata page record")),
        }
        Ok(())
    }

    fn references_onto_member(&self, member: u16) -> Result<Vec<(ZoneClass, Extent)>> {
        let mut out = Vec::new();
        let mut visited: HashSet<(u16, u64)> = HashSet::new();
        let mut stripes_seen: HashSet<(u16, u64)> = HashSet::new();
        let mut roots = vec![self.last_metadata_root.clone()];
        while let Some(root) = roots.pop() {
            self.collect_references_in_tree(
                &root,
                member,
                &mut out,
                &mut visited,
                &mut stripes_seen,
                &mut roots,
            )?;
        }
        Ok(out)
    }

    fn collect_references_in_tree(
        &self,
        root: &[Extent],
        member: u16,
        out: &mut Vec<(ZoneClass, Extent)>,
        visited: &mut HashSet<(u16, u64)>,
        stripes_seen: &mut HashSet<(u16, u64)>,
        pending_roots: &mut Vec<Vec<Extent>>,
    ) -> Result<()> {
        let first = root
            .first()
            .ok_or(ScaleFsError::Corrupt("tree root has no copies"))?;
        if !visited.insert((first.device_index, first.offset)) {
            return Ok(());
        }
        for copy in root {
            if copy.device_index == member {
                out.push((ZoneClass::Metadata, *copy));
            }
        }
        let bytes = self.read_record(root)?;
        match decode_record(&bytes)?.kind {
            RecordKind::MetadataInternal | RecordKind::MetadataInternalMirrored => {
                for (_, child) in decode_internal_record(&bytes)? {
                    self.collect_references_in_tree(
                        &child,
                        member,
                        out,
                        visited,
                        stripes_seen,
                        pending_roots,
                    )?;
                }
            }
            RecordKind::MetadataLeaf => {
                for (_, value) in decode_leaf_record(&bytes)? {
                    match value {
                        MetadataValue::FileExtent { extents, .. } => {
                            for extent in extents {
                                if extent.device_index == member {
                                    out.push((ZoneClass::Data, extent));
                                }
                            }
                        }
                        MetadataValue::StripedExtent {
                            extent,
                            parity_extents,
                            ..
                        } => {
                            if extent.device_index == member {
                                out.push((ZoneClass::Data, extent));
                            }
                            for parity in &parity_extents {
                                if parity.device_index == member {
                                    out.push((ZoneClass::Parity, *parity));
                                }
                            }
                            let Some(stripe_first) = parity_extents.first() else {
                                continue;
                            };
                            if !stripes_seen
                                .insert((stripe_first.device_index, stripe_first.offset))
                            {
                                continue;
                            }
                            let mut described = false;
                            let mut present_rows = false;
                            for parity in &parity_extents {
                                if parity.device_index == member
                                    || self.member_slot(parity.device_index).is_none()
                                {
                                    continue;
                                }
                                present_rows = true;
                                let Ok(bytes) = self.read_extent(*parity) else {
                                    continue;
                                };
                                let Ok(record) = decode_parity_record(&bytes) else {
                                    continue;
                                };
                                for piece in &record.data_pieces {
                                    if piece.device_index == member {
                                        out.push((ZoneClass::Data, *piece));
                                    }
                                }
                                for piece in &record.parity_pieces {
                                    if piece.device_index == member {
                                        out.push((ZoneClass::Parity, *piece));
                                    }
                                }
                                described = true;
                                break;
                            }
                            if !described && present_rows {
                                return Err(ScaleFsError::Corrupt(
                                    "a live stripe has no readable parity record; scrub before replacing",
                                ));
                            }
                        }
                        MetadataValue::RetainedRoot { metadata_roots, .. } => {
                            pending_roots.push(metadata_roots);
                        }
                        _ => {}
                    }
                }
            }
            _ => return Err(ScaleFsError::Corrupt("expected a metadata page record")),
        }
        Ok(())
    }

    fn copy_is_backed(&self, extent: Extent) -> bool {
        let Some(slot) = self.member_slot(extent.device_index) else {
            return false;
        };
        let allocator = &self.allocators[slot];
        let zone_size = allocator.geometry().zone_size;
        let zone_index = extent.offset / zone_size;
        allocator.zone(zone_index).is_some_and(|zone| {
            zone.class.is_some()
                && extent.offset + extent.length <= zone_index * zone_size + zone.write_pointer
        })
    }

    pub fn replace_member(&mut self, member: u16, spec: MemberSpec<D>, now_ns: i64) -> Result<()> {
        self.force_full_commit = true;
        if usize::from(member) >= self.member_slots.len() {
            return Err(ScaleFsError::InvalidArgument("no such member"));
        }
        if self.member_slot(member).is_some() {
            return Err(ScaleFsError::InvalidArgument(
                "only an absent member can be replaced",
            ));
        }
        if self.removed[usize::from(member)] {
            return Err(ScaleFsError::InvalidArgument(
                "a removed member's index is retired; grow the pool instead",
            ));
        }
        let geometry = spec.geometry.validate()?;
        check_member_fits(&spec.device, geometry)?;
        if self
            .superblocks
            .iter()
            .any(|superblock| superblock.device_id == spec.device_id)
        {
            return Err(ScaleFsError::InvalidArgument(
                "pool members must have distinct device ids",
            ));
        }
        if self
            .superblocks
            .iter()
            .any(|superblock| superblock.unknown_ro_compat() != 0)
        {
            return Err(ScaleFsError::Unsupported(
                "pool has unknown read-only-compatible features; \
                 a newer scalefs is required to change its membership",
            ));
        }

        let generation = self.multi.as_ref().map_or(1, |state| state.generation) + 1;
        let template = &self.superblocks[0];
        let superblock = Superblock {
            pool_id: template.pool_id,
            device_id: spec.device_id,
            created_at_ns: template.created_at_ns,
            topology_generation: generation,
            feature_compat: template.feature_compat,
            feature_ro_compat: template.feature_ro_compat,
            feature_incompat: template.feature_incompat | FEATURE_INCOMPAT_MULTI_DEVICE,
            geometry,
            case_sensitivity: template.case_sensitivity,
            unicode_version: template.unicode_version,
            dirent_hash_seed: template.dirent_hash_seed,
            newest_commit: None,
            aux_record: None,
            label: template.label.clone(),
        };
        let bytes = encode_superblock(&superblock)?;
        let device = format_member_wrapper(spec.device, template.pool_id, spec.device_id)?;
        for offset in superblock_slots(device.len()) {
            write_padded(&device, offset, &bytes, SUPERBLOCK_PAD)?;
        }
        device.flush()?;

        let position = self.member_slots[..usize::from(member)]
            .iter()
            .filter(|slot| slot.is_some())
            .count();
        let previous_id = self.member_ids[usize::from(member)];
        let previous_geometry = self.member_geometries[usize::from(member)];
        let previous_chain = self.absent_chains[usize::from(member)].take();
        let previous_read_only = self.read_only;
        self.devices.insert(position, device);
        self.superblocks.insert(position, superblock);
        self.allocators
            .insert(position, ZoneAllocator::new(geometry)?);
        self.apply_actuator_ranges();
        for slot in self.member_slots.iter_mut().flatten() {
            if *slot >= position {
                *slot += 1;
            }
        }
        self.member_slots[usize::from(member)] = Some(position);
        self.member_ids[usize::from(member)] = spec.device_id;
        self.member_geometries[usize::from(member)] = geometry;
        for existing in &mut self.superblocks {
            existing.topology_generation = generation;
        }
        if let Some(state) = &mut self.multi {
            state.generation = generation;
        }

        let ghosts = self.references_onto_member(member)?;
        for (class, extent) in ghosts {
            self.allocators[position].reserve_ghost(class, extent.offset, extent.length)?;
        }

        self.read_only = false;
        if let Err(err) = self.commit(AllocPurpose::Normal, now_ns) {
            let removed_device = self.devices.remove(position);
            drop(removed_device);
            self.superblocks.remove(position);
            self.allocators.remove(position);
            self.member_slots[usize::from(member)] = None;
            for slot in self.member_slots.iter_mut().flatten() {
                if *slot > position {
                    *slot -= 1;
                }
            }
            self.member_ids[usize::from(member)] = previous_id;
            self.member_geometries[usize::from(member)] = previous_geometry;
            self.absent_chains[usize::from(member)] = previous_chain;
            self.read_only = previous_read_only;
            let old_generation = generation - 1;
            for existing in &mut self.superblocks {
                existing.topology_generation = old_generation;
            }
            if let Some(state) = &mut self.multi {
                state.generation = old_generation;
            }
            return Err(err);
        }
        self.read_only = self.is_degraded()
            || self
                .superblocks
                .iter()
                .any(|superblock| superblock.unknown_ro_compat() != 0);
        Ok(())
    }

    pub fn rebuild(&mut self, now_ns: i64) -> Result<RebuildReport> {
        if self.read_only {
            return Err(ScaleFsError::Unsupported(
                "pool is read-only: replace missing members before rebuilding",
            ));
        }
        let mut report = RebuildReport::default();
        let mut memo: std::collections::HashMap<(u16, u64), Vec<Extent>> =
            std::collections::HashMap::new();
        let mut stripes: std::collections::HashMap<(u16, u64), Option<StripeHeal>> =
            std::collections::HashMap::new();
        let memberships = if self.parity_width() > 0 {
            self.stripe_memberships()?
        } else {
            StripeMembers::new()
        };

        let keys: Vec<MetadataKey> = self
            .tree
            .range(MetadataKey::MIN, MetadataKey::MAX)
            .iter()
            .filter(|(key, value)| {
                key.item_type == ITEM_FILE_EXTENT
                    && matches!(
                        value,
                        MetadataValue::FileExtent { .. } | MetadataValue::StripedExtent { .. }
                    )
            })
            .map(|(key, _)| *key)
            .collect();
        for key in keys {
            match self.tree.get(key).cloned() {
                Some(MetadataValue::FileExtent {
                    extents,
                    data_offset,
                    logical_len,
                }) => {
                    if let Some(healed) = self.rebuild_copy_set(&extents, &mut memo, &mut report)? {
                        self.tree.insert(
                            key,
                            MetadataValue::FileExtent {
                                extents: healed,
                                data_offset,
                                logical_len,
                            },
                        )?;
                    }
                }
                Some(MetadataValue::StripedExtent {
                    extent,
                    parity_extents,
                    data_offset,
                    logical_len,
                }) => {
                    if let Some(heal) = self.rebuild_stripe(
                        &parity_extents,
                        &memberships,
                        &mut stripes,
                        &mut report,
                    )? {
                        self.tree.insert(
                            key,
                            MetadataValue::StripedExtent {
                                extent: heal.new_data_extent(extent),
                                parity_extents: heal.parity_extents.clone(),
                                data_offset,
                                logical_len,
                            },
                        )?;
                    }
                }
                _ => continue,
            }
        }

        let retained: Vec<(MetadataKey, MetadataValue)> = self
            .tree
            .range(
                MetadataKey {
                    object_id: 0,
                    item_type: ITEM_RETAINED_ROOT,
                    offset: 0,
                },
                MetadataKey {
                    object_id: 0,
                    item_type: ITEM_RETAINED_ROOT,
                    offset: u64::MAX,
                },
            )
            .iter()
            .map(|(key, value)| (*key, (*value).clone()))
            .collect();
        for (key, value) in retained {
            let MetadataValue::RetainedRoot {
                tx_id,
                metadata_roots,
                created_at_ns,
                name,
            } = value
            else {
                continue;
            };
            let (new_roots, changed) = self.rebuild_tree(
                &metadata_roots,
                &mut memo,
                &memberships,
                &mut stripes,
                &mut report,
            )?;
            if changed {
                report.snapshots_rewritten += 1;
                self.tree.insert(
                    key,
                    MetadataValue::RetainedRoot {
                        tx_id,
                        metadata_roots: new_roots,
                        created_at_ns,
                        name,
                    },
                )?;
            }
        }

        self.tree.mark_all_dirty();
        report.tx_id = self.commit(AllocPurpose::Normal, now_ns)?;

        Ok(report)
    }

    fn rebuild_copy_set(
        &mut self,
        copies: &[Extent],
        memo: &mut std::collections::HashMap<(u16, u64), Vec<Extent>>,
        report: &mut RebuildReport,
    ) -> Result<Option<Vec<Extent>>> {
        let Some(first) = copies.first() else {
            return Ok(None);
        };
        if let Some(healed) = memo.get(&(first.device_index, first.offset)) {
            return Ok(Some(healed.clone()));
        }
        let mut live: Vec<Extent> = Vec::new();
        let mut bytes: Option<Vec<u8>> = None;
        for extent in copies {
            if self.evacuating == Some(extent.device_index) {
                continue;
            }
            let Some(slot) = self.member_slot(extent.device_index) else {
                continue;
            };
            let local = Extent {
                device_index: 0,
                ..*extent
            };
            if let Ok(data) = read_extent_from_set(std::slice::from_ref(&self.devices[slot]), local)
                && decode_record(&data).is_ok()
            {
                if bytes.is_none() {
                    bytes = Some(data);
                }
                live.push(*extent);
            }
        }
        if live.len() == copies.len() {
            return Ok(None);
        }
        let bytes = match bytes {
            Some(bytes) => bytes,
            None if self.evacuating.is_some() => match self.read_record(copies) {
                Ok(data) => data,
                Err(_) => return Ok(None),
            },
            None => return Ok(None),
        };
        let want = self.mirror_width().max(copies.len() as u16);
        let need = usize::from(want).saturating_sub(live.len());
        let mut exclude: Vec<u16> = live.iter().map(|extent| extent.device_index).collect();
        exclude.extend(self.evacuating);
        let placements = place_distinct_excluding(
            &mut self.allocators,
            &self.member_slots,
            ZoneClass::Data,
            bytes.len() as u64,
            AllocPurpose::Normal,
            need as u16,
            &exclude,
        )?;
        let mut healed = live;
        for (member, allocation) in placements {
            self.dirty_members.insert(member);
            let slot = self
                .member_slot(member)
                .expect("placed on a present member");
            self.write_record_padded(slot, allocation.offset, &bytes)?;
            healed.push(Extent {
                device_index: member,
                offset: allocation.offset,
                length: bytes.len() as u64,
            });
            report.copies_written += 1;
        }
        report.records_rebuilt += 1;
        memo.insert((first.device_index, first.offset), healed.clone());
        Ok(Some(healed))
    }

    fn rebuild_stripe(
        &mut self,
        parity_extents: &[Extent],
        memberships: &StripeMembers,
        stripes: &mut std::collections::HashMap<(u16, u64), Option<StripeHeal>>,
        report: &mut RebuildReport,
    ) -> Result<Option<StripeHeal>> {
        let first = parity_extents.first().ok_or(ScaleFsError::Corrupt(
            "striped extent has no parity records",
        ))?;
        if let Some(heal) = stripes.get(&(first.device_index, first.offset)) {
            return Ok(heal.clone());
        }
        let needs_move = |pool: &Self, extent: &Extent| {
            pool.evacuating == Some(extent.device_index)
                || pool.member_slot(extent.device_index).is_none()
        };

        let mut descriptor: Option<ParityRecord> = None;
        let mut parity_payloads: Vec<Option<Vec<u8>>> = Vec::with_capacity(parity_extents.len());
        for (row, extent) in parity_extents.iter().enumerate() {
            let record = self
                .read_extent(*extent)
                .ok()
                .and_then(|bytes| decode_parity_record(&bytes).ok())
                .filter(|record| usize::from(record.parity_index) == row);
            if let Some(record) = record {
                if descriptor.is_none() {
                    descriptor = Some(record.clone());
                }
                parity_payloads.push(Some(record.parity));
            } else {
                parity_payloads.push(None);
            }
        }
        let Some(descriptor) = descriptor else {
            return self.rebuild_stripe_from_members(parity_extents, memberships, stripes, report);
        };
        if descriptor.parity_pieces != *parity_extents {
            return Err(ScaleFsError::Corrupt(
                "stripe descriptor disagrees with the reference's parity list",
            ));
        }
        let data_count = descriptor.data_pieces.len();
        let parity_count = descriptor.parity_pieces.len();
        let coverage = usize::try_from(descriptor.coverage_len)
            .map_err(|_| ScaleFsError::Corrupt("stripe coverage exceeds the address space"))?;

        let mut data_bytes: Vec<Option<Vec<u8>>> = Vec::with_capacity(data_count);
        let mut moving_data: Vec<usize> = Vec::new();
        for (column, piece) in descriptor.data_pieces.iter().enumerate() {
            let bytes = self
                .read_extent(*piece)
                .ok()
                .filter(|bytes| decode_record(bytes).is_ok());
            if bytes.is_none() || needs_move(self, piece) {
                moving_data.push(column);
            }
            data_bytes.push(bytes);
        }
        let moving_parity: Vec<usize> = parity_extents
            .iter()
            .enumerate()
            .filter(|(row, extent)| parity_payloads[*row].is_none() || needs_move(self, extent))
            .map(|(row, _)| row)
            .collect();
        if moving_data.is_empty() && moving_parity.is_empty() {
            stripes.insert((first.device_index, first.offset), None);
            return Ok(None);
        }

        let erased: Vec<usize> = (0..data_count)
            .filter(|&column| data_bytes[column].is_none())
            .collect();
        if !erased.is_empty() {
            let available: Vec<(usize, &[u8])> = data_bytes
                .iter()
                .enumerate()
                .filter_map(|(column, bytes)| bytes.as_deref().map(|bytes| (column, bytes)))
                .chain(
                    parity_payloads
                        .iter()
                        .enumerate()
                        .filter_map(|(row, payload)| {
                            payload
                                .as_deref()
                                .map(|payload| (data_count + row, payload))
                        }),
                )
                .collect();
            let rebuilt = crate::rs::reconstruct_data(
                data_count,
                parity_count,
                coverage,
                &available,
                &erased,
            )?;
            for (piece, &column) in rebuilt.into_iter().zip(&erased) {
                let mut bytes = piece;
                bytes.truncate(descriptor.data_pieces[column].length as usize);
                if decode_record(&bytes).is_err() {
                    return Err(ScaleFsError::Corrupt(
                        "stripe reconstruction failed checksum verification",
                    ));
                }
                data_bytes[column] = Some(bytes);
            }
        }

        let mut used: Vec<u16> = descriptor
            .data_pieces
            .iter()
            .enumerate()
            .filter(|(column, _)| !moving_data.contains(column))
            .map(|(_, piece)| piece.device_index)
            .chain(
                parity_extents
                    .iter()
                    .enumerate()
                    .filter(|(row, _)| !moving_parity.contains(row))
                    .map(|(_, extent)| extent.device_index),
            )
            .collect();
        used.extend(self.evacuating);

        let mut new_data_pieces = descriptor.data_pieces.clone();
        let mut moved: std::collections::HashMap<(u16, u64), Extent> =
            std::collections::HashMap::new();
        for &column in &moving_data {
            let bytes = data_bytes[column].as_ref().expect("reconstructed above");
            let placements = place_distinct_excluding(
                &mut self.allocators,
                &self.member_slots,
                ZoneClass::Data,
                bytes.len() as u64,
                AllocPurpose::Normal,
                1,
                &used,
            )?;
            let (member, allocation) = placements[0];
            self.dirty_members.insert(member);
            let slot = self
                .member_slot(member)
                .expect("placed on a present member");
            self.write_record_padded(slot, allocation.offset, bytes)?;
            let new_extent = Extent {
                device_index: member,
                offset: allocation.offset,
                length: bytes.len() as u64,
            };
            let old = descriptor.data_pieces[column];
            moved.insert((old.device_index, old.offset), new_extent);
            new_data_pieces[column] = new_extent;
            used.push(member);
            report.copies_written += 1;
        }

        let parity_len = parity_record_len(data_count, parity_count, descriptor.coverage_len);
        let mut new_parity_pieces = Vec::with_capacity(parity_count);
        let mut parity_slots: Vec<(u16, Allocation)> = Vec::with_capacity(parity_count);
        for (row, extent) in parity_extents.iter().enumerate() {
            let stay = !moving_parity.contains(&row);
            let (member, allocation) = if stay {
                let slot = self
                    .member_slot(extent.device_index)
                    .expect("a staying row's member is present");
                (
                    extent.device_index,
                    self.allocators[slot].allocate(
                        ZoneClass::Parity,
                        parity_len,
                        AllocPurpose::Normal,
                    )?,
                )
            } else {
                let placements = place_distinct_excluding(
                    &mut self.allocators,
                    &self.member_slots,
                    ZoneClass::Parity,
                    parity_len,
                    AllocPurpose::Normal,
                    1,
                    &used,
                )?;
                used.push(placements[0].0);
                placements[0]
            };
            self.dirty_members.insert(member);
            new_parity_pieces.push(Extent {
                device_index: member,
                offset: allocation.offset,
                length: parity_len,
            });
            parity_slots.push((member, allocation));
        }
        let all_data: Vec<&[u8]> = data_bytes
            .iter()
            .map(|bytes| bytes.as_deref().expect("every column read or rebuilt"))
            .collect();
        let regenerated = crate::rs::generate_parity(&all_data, parity_count, coverage)?;
        for (row, (member, allocation)) in parity_slots.iter().enumerate() {
            let payload = match &parity_payloads[row] {
                Some(payload) => payload.clone(),
                None => regenerated[row].clone(),
            };
            let record = ParityRecord {
                parity_index: row as u8,
                coverage_len: descriptor.coverage_len,
                data_pieces: new_data_pieces.clone(),
                parity_pieces: new_parity_pieces.clone(),
                parity: payload,
            };
            let bytes = crate::stripes::encode_parity_record(&record)?;
            debug_assert_eq!(bytes.len() as u64, parity_len);
            let slot = self
                .member_slot(*member)
                .expect("placed on a present member");
            self.write_record_padded(slot, allocation.offset, &bytes)?;
            report.copies_written += 1;
        }
        report.records_rebuilt += 1;
        let heal = StripeHeal {
            moved,
            parity_extents: new_parity_pieces,
        };
        stripes.insert((first.device_index, first.offset), Some(heal.clone()));
        Ok(Some(heal))
    }

    fn rebuild_stripe_from_members(
        &mut self,
        parity_extents: &[Extent],
        memberships: &StripeMembers,
        stripes: &mut std::collections::HashMap<(u16, u64), Option<StripeHeal>>,
        report: &mut RebuildReport,
    ) -> Result<Option<StripeHeal>> {
        let first = parity_extents.first().expect("checked by the caller");
        let members = memberships
            .get(&(first.device_index, first.offset))
            .filter(|members| !members.is_empty() && members.len() <= crate::rs::MAX_DATA)
            .ok_or(ScaleFsError::Corrupt(
                "stripe has no readable parity record and no reassemblable membership",
            ))?;
        let needs_move = |pool: &Self, extent: &Extent| {
            pool.evacuating == Some(extent.device_index)
                || pool.member_slot(extent.device_index).is_none()
        };
        let old_pieces: Vec<Extent> = members
            .iter()
            .map(|&(device_index, offset, length)| Extent {
                device_index,
                offset,
                length,
            })
            .collect();
        let mut data_bytes: Vec<Vec<u8>> = Vec::with_capacity(old_pieces.len());
        let mut moving_data: Vec<usize> = Vec::new();
        for (column, piece) in old_pieces.iter().enumerate() {
            let bytes = self
                .read_extent(*piece)
                .ok()
                .filter(|bytes| decode_record(bytes).is_ok())
                .ok_or(ScaleFsError::Corrupt(
                    "stripe has too few surviving pieces to reconstruct",
                ))?;
            if needs_move(self, piece) {
                moving_data.push(column);
            }
            data_bytes.push(bytes);
        }
        let data_count = old_pieces.len();
        let parity_count = parity_extents.len();
        let coverage = data_bytes
            .iter()
            .map(Vec::len)
            .max()
            .expect("membership is nonempty");
        let coverage_len = coverage as u64;

        let mut used: Vec<u16> = old_pieces
            .iter()
            .enumerate()
            .filter(|(column, _)| !moving_data.contains(column))
            .map(|(_, piece)| piece.device_index)
            .collect();
        used.extend(self.evacuating);

        let mut new_data_pieces = old_pieces.clone();
        let mut moved: std::collections::HashMap<(u16, u64), Extent> =
            std::collections::HashMap::new();
        for &column in &moving_data {
            let bytes = &data_bytes[column];
            let placements = place_distinct_excluding(
                &mut self.allocators,
                &self.member_slots,
                ZoneClass::Data,
                bytes.len() as u64,
                AllocPurpose::Normal,
                1,
                &used,
            )?;
            let (member, allocation) = placements[0];
            self.dirty_members.insert(member);
            let slot = self
                .member_slot(member)
                .expect("placed on a present member");
            self.write_record_padded(slot, allocation.offset, bytes)?;
            let old = old_pieces[column];
            let new_extent = Extent {
                device_index: member,
                offset: allocation.offset,
                length: bytes.len() as u64,
            };
            moved.insert((old.device_index, old.offset), new_extent);
            new_data_pieces[column] = new_extent;
            used.push(member);
            report.copies_written += 1;
        }

        let parity_len = parity_record_len(data_count, parity_count, coverage_len);
        let mut new_parity_pieces: Vec<Extent> = Vec::with_capacity(parity_count);
        let mut parity_slots: Vec<(u16, Allocation)> = Vec::with_capacity(parity_count);
        for extent in parity_extents {
            let reusable = self.member_slot(extent.device_index).is_some()
                && self.evacuating != Some(extent.device_index)
                && !used.contains(&extent.device_index);
            let (member, allocation) = if reusable {
                let slot = self
                    .member_slot(extent.device_index)
                    .expect("presence just checked");
                used.push(extent.device_index);
                (
                    extent.device_index,
                    self.allocators[slot].allocate(
                        ZoneClass::Parity,
                        parity_len,
                        AllocPurpose::Normal,
                    )?,
                )
            } else {
                let placements = place_distinct_excluding(
                    &mut self.allocators,
                    &self.member_slots,
                    ZoneClass::Parity,
                    parity_len,
                    AllocPurpose::Normal,
                    1,
                    &used,
                )?;
                used.push(placements[0].0);
                placements[0]
            };
            self.dirty_members.insert(member);
            new_parity_pieces.push(Extent {
                device_index: member,
                offset: allocation.offset,
                length: parity_len,
            });
            parity_slots.push((member, allocation));
        }
        let refs: Vec<&[u8]> = data_bytes.iter().map(Vec::as_slice).collect();
        let rows = crate::rs::generate_parity(&refs, parity_count, coverage)?;
        for (row, ((member, allocation), payload)) in parity_slots.iter().zip(rows).enumerate() {
            let record = ParityRecord {
                parity_index: row as u8,
                coverage_len,
                data_pieces: new_data_pieces.clone(),
                parity_pieces: new_parity_pieces.clone(),
                parity: payload,
            };
            let bytes = crate::stripes::encode_parity_record(&record)?;
            debug_assert_eq!(bytes.len() as u64, parity_len);
            let slot = self
                .member_slot(*member)
                .expect("placed on a present member");
            self.write_record_padded(slot, allocation.offset, &bytes)?;
            report.copies_written += 1;
        }
        report.records_rebuilt += 1;
        let heal = StripeHeal {
            moved,
            parity_extents: new_parity_pieces,
        };
        stripes.insert((first.device_index, first.offset), Some(heal.clone()));
        Ok(Some(heal))
    }

    fn rebuild_tree(
        &mut self,
        root: &[Extent],
        memo: &mut std::collections::HashMap<(u16, u64), Vec<Extent>>,
        memberships: &StripeMembers,
        stripes: &mut std::collections::HashMap<(u16, u64), Option<StripeHeal>>,
        report: &mut RebuildReport,
    ) -> Result<(Vec<Extent>, bool)> {
        let bytes = self.read_record(root)?;
        let live_copies = root
            .iter()
            .filter(|extent| {
                self.evacuating != Some(extent.device_index)
                    && self.member_slot(extent.device_index).is_some_and(|slot| {
                        let local = Extent {
                            device_index: 0,
                            ..**extent
                        };
                        read_extent_from_set(std::slice::from_ref(&self.devices[slot]), local)
                            .is_ok_and(|data| decode_record(&data).is_ok())
                    })
            })
            .count();
        let mut changed = live_copies != root.len();

        let new_bytes = match decode_record(&bytes)?.kind {
            RecordKind::MetadataInternal | RecordKind::MetadataInternalMirrored => {
                let mut entries = decode_internal_record(&bytes)?;
                for (_, child) in &mut entries {
                    let (new_child, child_changed) =
                        self.rebuild_tree(child, memo, memberships, stripes, report)?;
                    if child_changed {
                        *child = new_child;
                        changed = true;
                    }
                }
                changed.then(|| encode_internal_record(&entries))
            }
            RecordKind::MetadataLeaf => {
                let mut items = decode_leaf_record(&bytes)?;
                for (_, value) in &mut items {
                    match value {
                        MetadataValue::FileExtent { extents, .. } => {
                            if let Some(healed) = self.rebuild_copy_set(extents, memo, report)? {
                                *extents = healed;
                                changed = true;
                            }
                        }
                        MetadataValue::StripedExtent {
                            extent,
                            parity_extents,
                            ..
                        } => {
                            if let Some(heal) =
                                self.rebuild_stripe(parity_extents, memberships, stripes, report)?
                            {
                                *extent = heal.new_data_extent(*extent);
                                *parity_extents = heal.parity_extents.clone();
                                changed = true;
                            }
                        }
                        MetadataValue::RetainedRoot { metadata_roots, .. } => {
                            let nested = metadata_roots.clone();
                            let (new_roots, nested_changed) =
                                self.rebuild_tree(&nested, memo, memberships, stripes, report)?;
                            if nested_changed {
                                *metadata_roots = new_roots;
                                changed = true;
                            }
                        }
                        _ => {}
                    }
                }
                changed.then(|| encode_leaf_record(&items))
            }
            _ => return Err(ScaleFsError::Corrupt("expected a metadata page record")),
        };

        match new_bytes {
            None => Ok((root.to_vec(), false)),
            Some(bytes) => {
                let mirror_width = self.mirror_width();
                let exclude: Vec<u16> = self.evacuating.into_iter().collect();
                let placements = place_distinct_excluding(
                    &mut self.allocators,
                    &self.member_slots,
                    ZoneClass::Metadata,
                    bytes.len() as u64,
                    AllocPurpose::Normal,
                    mirror_width,
                    &exclude,
                )?;
                let mut extents = Vec::with_capacity(placements.len());
                for (member, allocation) in placements {
                    self.dirty_members.insert(member);
                    let slot = self
                        .member_slot(member)
                        .expect("placed on a present member");
                    self.write_record_padded(slot, allocation.offset, &bytes)?;
                    extents.push(Extent {
                        device_index: member,
                        offset: allocation.offset,
                        length: bytes.len() as u64,
                    });
                }
                Ok((extents, true))
            }
        }
    }

    pub fn remove_member(&mut self, member: u16, now_ns: i64) -> Result<D> {
        self.force_full_commit = true;
        if self.read_only {
            return Err(ScaleFsError::Unsupported(
                "pool is read-only: replace missing members before shrinking",
            ));
        }
        let Some(slot) = self.member_slot(member) else {
            return Err(ScaleFsError::InvalidArgument(
                "only a present member can be removed; replace absent ones",
            ));
        };
        let remaining = self.member_slots.iter().flatten().count() - 1;
        if remaining < usize::from(self.mirror_width()) || remaining == 0 {
            return Err(ScaleFsError::InvalidArgument(
                "too few members would remain for the pool's mirror width",
            ));
        }
        let leaving_used: u64 = self.allocators[slot]
            .zones()
            .map(|zone| zone.write_pointer)
            .sum();
        let free_elsewhere: u64 = self
            .allocators
            .iter()
            .enumerate()
            .filter(|(other, _)| *other != slot)
            .map(|(_, allocator)| {
                allocator.free_usable_zone_count() * allocator.geometry().zone_size
            })
            .sum();
        if leaving_used > free_elsewhere {
            return Err(ScaleFsError::OutOfSpace);
        }

        self.evacuating = Some(member);
        let evacuated = self.rebuild(now_ns);
        self.evacuating = None;
        evacuated?;
        self.assert_member_clean(member)?;
        self.force_full_commit = true;

        let generation = self.multi.as_ref().map_or(1, |state| state.generation) + 1;
        let device = self.devices.remove(slot);
        let superblock = self.superblocks.remove(slot);
        let allocator = self.allocators.remove(slot);
        self.member_slots[usize::from(member)] = None;
        for other in self.member_slots.iter_mut().flatten() {
            if *other > slot {
                *other -= 1;
            }
        }
        self.removed[usize::from(member)] = true;
        for existing in &mut self.superblocks {
            existing.topology_generation = generation;
        }
        if let Some(state) = &mut self.multi {
            state.generation = generation;
        }
        if let Err(err) = self.commit(AllocPurpose::Normal, now_ns) {
            for other in self.member_slots.iter_mut().flatten() {
                if *other >= slot {
                    *other += 1;
                }
            }
            self.member_slots[usize::from(member)] = Some(slot);
            self.removed[usize::from(member)] = false;
            self.devices.insert(slot, device);
            self.superblocks.insert(slot, superblock);
            self.allocators.insert(slot, allocator);
            let old_generation = generation - 1;
            for existing in &mut self.superblocks {
                existing.topology_generation = old_generation;
            }
            if let Some(state) = &mut self.multi {
                state.generation = old_generation;
            }
            return Err(err);
        }

        let zeros = vec![0u8; 4096];
        for offset in superblock_slots(device.len()) {
            let len = ((device.len() - offset).min(4096)) as usize;
            device.write_at(offset, &zeros[..len])?;
        }
        let device = device.into_inner();
        for offset in (0..MEMBER_WRAPPER_BLANK.min(device.len())).step_by(4096) {
            let len = ((device.len() - offset).min(4096)) as usize;
            device.write_at(offset, &zeros[..len])?;
        }
        let tail = device.len().saturating_sub(MEMBER_WRAPPER_BLANK);
        for offset in (tail..device.len()).step_by(4096) {
            let len = ((device.len() - offset).min(4096)) as usize;
            device.write_at(offset, &zeros[..len])?;
        }
        device.flush()?;
        Ok(device)
    }

    pub fn retire_member(&mut self, member: u16, now_ns: i64) -> Result<RebuildReport> {
        self.force_full_commit = true;
        if usize::from(member) >= self.member_slots.len() {
            return Err(ScaleFsError::InvalidArgument("no such member"));
        }
        if self.member_slot(member).is_some() {
            return Err(ScaleFsError::InvalidArgument(
                "only an absent member can be retired; remove present ones",
            ));
        }
        if self.removed[usize::from(member)] {
            return Err(ScaleFsError::InvalidArgument("member is already retired"));
        }
        if self.parity_width() > 0 {
            return Err(ScaleFsError::Unsupported(
                "parity pools cannot retire members yet; replace the missing member instead",
            ));
        }
        let absent_active = self
            .member_slots
            .iter()
            .enumerate()
            .filter(|(index, slot)| slot.is_none() && !self.removed[*index])
            .count();
        if absent_active != 1 {
            return Err(ScaleFsError::Unsupported(
                "retire heals from surviving copies; every other member must be present",
            ));
        }
        let present = self.member_slots.iter().flatten().count();
        if present < usize::from(self.mirror_width()) || present == 0 {
            return Err(ScaleFsError::InvalidArgument(
                "too few members would remain for the pool's mirror width",
            ));
        }
        if self
            .superblocks
            .iter()
            .any(|superblock| superblock.unknown_ro_compat() != 0)
        {
            return Err(ScaleFsError::Unsupported(
                "pool has unknown read-only-compatible features; \
                 a newer scalefs is required to change its membership",
            ));
        }

        let needed: u64 = self
            .references_onto_member(member)?
            .iter()
            .map(|(_, extent)| extent.length)
            .sum();
        let free_elsewhere: u64 = self
            .allocators
            .iter()
            .map(|allocator| allocator.free_usable_zone_count() * allocator.geometry().zone_size)
            .sum();
        if needed > free_elsewhere {
            return Err(ScaleFsError::OutOfSpace);
        }

        let was_read_only = self.read_only;
        self.read_only = false;
        let mut report = match self.rebuild(now_ns) {
            Ok(report) => report,
            Err(err) => {
                self.read_only = was_read_only;
                return Err(err);
            }
        };

        match self.references_onto_member(member) {
            Ok(remaining) if remaining.is_empty() => {}
            Ok(_) => {
                self.read_only = was_read_only;
                return Err(ScaleFsError::Corrupt(
                    "records still reference the retiring member after the heal",
                ));
            }
            Err(err) => {
                self.read_only = was_read_only;
                return Err(err);
            }
        }

        self.force_full_commit = true;

        let generation = self.multi.as_ref().map_or(1, |state| state.generation) + 1;
        let previous_chain = self.absent_chains[usize::from(member)].take();
        self.removed[usize::from(member)] = true;
        for existing in &mut self.superblocks {
            existing.topology_generation = generation;
        }
        if let Some(state) = &mut self.multi {
            state.generation = generation;
        }
        if let Err(err) = self.commit(AllocPurpose::Normal, now_ns) {
            self.removed[usize::from(member)] = false;
            self.absent_chains[usize::from(member)] = previous_chain;
            let old_generation = generation - 1;
            for existing in &mut self.superblocks {
                existing.topology_generation = old_generation;
            }
            if let Some(state) = &mut self.multi {
                state.generation = old_generation;
            }
            self.read_only = was_read_only;
            return Err(err);
        }

        self.read_only = self.is_degraded()
            || self
                .superblocks
                .iter()
                .any(|superblock| superblock.unknown_ro_compat() != 0);
        report.tx_id = self.committed_tx;
        Ok(report)
    }

    fn assert_member_clean(&self, member: u16) -> Result<()> {
        let zone_sizes: Vec<u64> = self
            .allocators
            .iter()
            .map(|allocator| allocator.geometry().zone_size)
            .collect();
        let mut live: Vec<Vec<bool>> = self
            .allocators
            .iter()
            .map(|allocator| vec![false; allocator.geometry().zone_count as usize])
            .collect();
        let mut visited: HashSet<(u16, u64)> = HashSet::new();
        let mut roots = vec![self.last_metadata_root.clone()];
        while let Some(root) = roots.pop() {
            mark_tree_live(
                &self.devices,
                &zone_sizes,
                &self.member_slots,
                &root,
                &mut live,
                &mut visited,
                &mut roots,
            )?;
        }
        let slot = self.member_slot(member).expect("member is present");
        if live[slot].iter().any(|&marked| marked) {
            return Err(ScaleFsError::Corrupt(
                "evacuation left reachable data on the member",
            ));
        }
        Ok(())
    }

    pub fn add_member(&mut self, spec: MemberSpec<D>, now_ns: i64) -> Result<u16> {
        self.force_full_commit = true;
        if self.read_only {
            return Err(ScaleFsError::Unsupported(
                "pool is read-only: replace missing members before growing",
            ));
        }
        if self.member_slots.len() >= usize::from(u16::MAX) {
            return Err(ScaleFsError::InvalidArgument("too many pool members"));
        }
        let geometry = spec.geometry.validate()?;
        check_member_fits(&spec.device, geometry)?;
        if self
            .superblocks
            .iter()
            .any(|superblock| superblock.device_id == spec.device_id)
        {
            return Err(ScaleFsError::InvalidArgument(
                "pool members must have distinct device ids",
            ));
        }

        let generation = self.multi.as_ref().map_or(1, |state| state.generation) + 1;
        let template = &self.superblocks[0];
        let superblock = Superblock {
            pool_id: template.pool_id,
            device_id: spec.device_id,
            created_at_ns: template.created_at_ns,
            topology_generation: generation,
            feature_compat: template.feature_compat,
            feature_ro_compat: template.feature_ro_compat,
            feature_incompat: template.feature_incompat | FEATURE_INCOMPAT_MULTI_DEVICE,
            geometry,
            case_sensitivity: template.case_sensitivity,
            unicode_version: template.unicode_version,
            dirent_hash_seed: template.dirent_hash_seed,
            newest_commit: None,
            aux_record: None,
            label: template.label.clone(),
        };
        let bytes = encode_superblock(&superblock)?;
        let device = format_member_wrapper(spec.device, template.pool_id, spec.device_id)?;
        for offset in superblock_slots(device.len()) {
            write_padded(&device, offset, &bytes, SUPERBLOCK_PAD)?;
        }
        device.flush()?;

        let previous_multi = self.multi.clone();
        for existing in &mut self.superblocks {
            existing.topology_generation = generation;
            existing.feature_incompat |= FEATURE_INCOMPAT_MULTI_DEVICE;
        }
        self.devices.push(device);
        self.allocators.push(ZoneAllocator::new(geometry)?);
        self.apply_actuator_ranges();
        self.member_ids.push(spec.device_id);
        self.member_geometries.push(geometry);
        self.last_participation.push(std::time::Instant::now());
        self.removed.push(false);
        self.absent_chains.push(None);
        self.superblocks.push(superblock);
        let member = self.member_slots.len() as u16;
        self.member_slots.push(Some(self.devices.len() - 1));
        match &mut self.multi {
            Some(state) => state.generation = generation,
            None => {
                self.multi = Some(MultiState {
                    generation,
                    data_width: 1,
                    parity_width: 0,
                    mirror_width: 1,
                })
            }
        }
        if let Err(err) = self.commit(AllocPurpose::Normal, now_ns) {
            self.devices.pop();
            self.allocators.pop();
            self.superblocks.pop();
            self.member_slots.pop();
            self.member_ids.pop();
            self.member_geometries.pop();
            self.removed.pop();
            self.absent_chains.pop();
            self.last_participation.pop();
            self.multi = previous_multi;
            let old_generation = generation - 1;
            for existing in &mut self.superblocks {
                existing.topology_generation = old_generation;
                if self.multi.is_none() {
                    existing.feature_incompat &= !FEATURE_INCOMPAT_MULTI_DEVICE;
                }
            }
            return Err(err);
        }
        Ok(member)
    }

    pub fn scrub(&mut self, repair: bool) -> Result<ScrubReport> {
        let mut report = ScrubReport::default();
        let mut dirty: HashSet<usize> = HashSet::new();

        for slot in 0..self.devices.len() {
            report.records_checked += 1;
            let offsets = superblock_slots(self.devices[slot].len());
            for offset in offsets {
                report.copies_checked += 1;
                let healthy = read_prefix(&self.devices[slot], offset)
                    .and_then(|bytes| decode_superblock(&bytes))
                    .is_ok();
                if !healthy {
                    report.copies_bad += 1;
                    if repair {
                        let bytes = encode_superblock(&self.superblocks[slot])?;
                        write_padded(&self.devices[slot], offset, &bytes, SUPERBLOCK_PAD)?;
                        report.copies_repaired += 1;
                        dirty.insert(slot);
                    }
                }
            }

            let mut chain: Vec<Extent> = Vec::new();
            if let Some(commit_extent) = self.superblocks[slot].newest_commit {
                chain.push(commit_extent);
                if let Ok(bytes) =
                    read_extent_from_set(std::slice::from_ref(&self.devices[slot]), commit_extent)
                    && let Ok(commit) = decode_commit(&bytes)
                {
                    chain.push(commit.allocator_summary);
                    if let Some(aux) = commit.aux_root {
                        chain.push(aux);
                    }
                }
            }
            for extent in chain {
                report.records_checked += 1;
                report.copies_checked += 1;
                let healthy =
                    read_extent_from_set(std::slice::from_ref(&self.devices[slot]), extent)
                        .and_then(|bytes| decode_record(&bytes).map(|_| ()))
                        .is_ok();
                if !healthy {
                    report.copies_bad += 1;
                    report.copies_unrepairable += 1;
                }
            }
        }

        let mut visited: HashSet<(u16, u64)> = HashSet::new();
        let mut stack = vec![self.last_metadata_root.clone()];
        while let Some(copies) = stack.pop() {
            let Some(first) = copies.first() else {
                continue;
            };
            if !visited.insert((first.device_index, first.offset)) {
                continue;
            }
            let Some(bytes) = self.scrub_copy_set(&copies, repair, &mut report, &mut dirty)? else {
                continue;
            };
            match decode_record(&bytes)?.kind {
                RecordKind::MetadataInternal | RecordKind::MetadataInternalMirrored => {
                    for (_, child) in decode_internal_record(&bytes)? {
                        stack.push(child);
                    }
                }
                RecordKind::MetadataLeaf => {
                    for (_, value) in decode_leaf_record(&bytes)? {
                        match value {
                            MetadataValue::FileExtent { extents, .. } => {
                                let Some(first) = extents.first() else {
                                    continue;
                                };
                                if visited.insert((first.device_index, first.offset)) {
                                    self.scrub_copy_set(&extents, repair, &mut report, &mut dirty)?;
                                }
                            }
                            MetadataValue::StripedExtent {
                                extent,
                                parity_extents,
                                ..
                            } => {
                                let Some(first) = parity_extents.first() else {
                                    continue;
                                };
                                let fresh = visited.insert((first.device_index, first.offset));
                                if fresh
                                    && self.scrub_stripe(
                                        &parity_extents,
                                        repair,
                                        &mut report,
                                        &mut dirty,
                                        &mut visited,
                                    )?
                                {
                                    continue;
                                }
                                if fresh {
                                    visited.remove(&(first.device_index, first.offset));
                                    for parity in &parity_extents {
                                        if visited.insert((parity.device_index, parity.offset | 1))
                                        {
                                            report.records_checked += 1;
                                            report.copies_checked += 1;
                                            report.copies_bad += 1;
                                            report.copies_unrepairable += 1;
                                        }
                                    }
                                }
                                if visited.insert((extent.device_index, extent.offset)) {
                                    self.scrub_copy_set(
                                        &[extent],
                                        repair,
                                        &mut report,
                                        &mut dirty,
                                    )?;
                                }
                            }
                            MetadataValue::RetainedRoot { metadata_roots, .. } => {
                                stack.push(metadata_roots);
                            }
                            _ => {}
                        }
                    }
                }
                _ => return Err(ScaleFsError::Corrupt("expected a metadata page record")),
            }
        }

        for slot in dirty {
            self.devices[slot].flush()?;
        }
        Ok(report)
    }

    fn scrub_copy_set(
        &mut self,
        copies: &[Extent],
        repair: bool,
        report: &mut ScrubReport,
        dirty: &mut HashSet<usize>,
    ) -> Result<Option<Vec<u8>>> {
        report.records_checked += 1;
        let mut good: Option<Vec<u8>> = None;
        let mut bad: Vec<(usize, Extent)> = Vec::new();
        for extent in copies {
            let Some(slot) = self.member_slot(extent.device_index) else {
                report.copies_missing += 1;
                continue;
            };
            report.copies_checked += 1;
            let local = Extent {
                device_index: 0,
                ..*extent
            };
            match read_extent_from_set(std::slice::from_ref(&self.devices[slot]), local) {
                Ok(bytes) if decode_record(&bytes).is_ok() => {
                    if good.is_none() {
                        good = Some(bytes);
                    }
                }
                _ => {
                    report.copies_bad += 1;
                    bad.push((slot, *extent));
                }
            }
        }
        match (&good, bad.is_empty()) {
            (Some(bytes), false) => {
                if repair {
                    for (slot, extent) in bad {
                        if !self.copy_is_backed(extent) {
                            report.copies_unrepairable += 1;
                            continue;
                        }
                        self.write_record_padded(slot, extent.offset, bytes)?;
                        report.copies_repaired += 1;
                        dirty.insert(slot);
                    }
                }
            }
            (None, false) => report.copies_unrepairable += bad.len() as u64,
            _ => {}
        }
        Ok(good)
    }

    fn scrub_stripe(
        &mut self,
        parity_extents: &[Extent],
        repair: bool,
        report: &mut ScrubReport,
        dirty: &mut HashSet<usize>,
        visited: &mut HashSet<(u16, u64)>,
    ) -> Result<bool> {
        let mut parity_records: Vec<Option<ParityRecord>> = Vec::new();
        for (row, extent) in parity_extents.iter().enumerate() {
            let record = if self.member_slot(extent.device_index).is_none() {
                None
            } else {
                self.read_extent(*extent)
                    .ok()
                    .and_then(|bytes| decode_parity_record(&bytes).ok())
                    .filter(|record| usize::from(record.parity_index) == row)
            };
            parity_records.push(record);
        }
        let Some(descriptor) = parity_records.iter().flatten().next().cloned() else {
            return Ok(false);
        };
        if descriptor.parity_pieces != *parity_extents {
            return Ok(false);
        }
        let data_count = descriptor.data_pieces.len();
        let parity_count = descriptor.parity_pieces.len();
        let coverage = usize::try_from(descriptor.coverage_len)
            .map_err(|_| ScaleFsError::Corrupt("stripe coverage exceeds the address space"))?;

        let mut data_bytes: Vec<Option<Vec<u8>>> = Vec::with_capacity(data_count);
        let mut data_missing = vec![false; data_count];
        for (index, piece) in descriptor.data_pieces.iter().enumerate() {
            visited.insert((piece.device_index, piece.offset));
            if self.member_slot(piece.device_index).is_none() {
                report.copies_missing += 1;
                data_missing[index] = true;
                data_bytes.push(None);
                continue;
            }
            report.records_checked += 1;
            report.copies_checked += 1;
            match self.read_extent(*piece) {
                Ok(bytes) if decode_record(&bytes).is_ok() => data_bytes.push(Some(bytes)),
                _ => {
                    report.copies_bad += 1;
                    data_bytes.push(None);
                }
            }
        }
        let mut parity_missing = vec![false; parity_count];
        for (row, extent) in parity_extents.iter().enumerate() {
            visited.insert((extent.device_index, extent.offset));
            if self.member_slot(extent.device_index).is_none() {
                report.copies_missing += 1;
                parity_missing[row] = true;
                continue;
            }
            report.records_checked += 1;
            report.copies_checked += 1;
            if parity_records[row].is_none() {
                report.copies_bad += 1;
            }
        }

        let erased: Vec<usize> = (0..data_count)
            .filter(|&index| data_bytes[index].is_none())
            .collect();
        let repairable = erased.iter().filter(|&&index| !data_missing[index]).count();
        if !erased.is_empty() {
            let available: Vec<(usize, &[u8])> = data_bytes
                .iter()
                .enumerate()
                .filter_map(|(index, bytes)| bytes.as_deref().map(|bytes| (index, bytes)))
                .chain(
                    parity_records
                        .iter()
                        .enumerate()
                        .filter_map(|(row, record)| {
                            record
                                .as_ref()
                                .map(|record| (data_count + row, record.parity.as_slice()))
                        }),
                )
                .collect();
            match crate::rs::reconstruct_data(
                data_count,
                parity_count,
                coverage,
                &available,
                &erased,
            ) {
                Ok(rebuilt) => {
                    for (piece, &column) in rebuilt.into_iter().zip(&erased) {
                        let extent = descriptor.data_pieces[column];
                        let mut bytes = piece;
                        bytes.truncate(extent.length as usize);
                        if decode_record(&bytes).is_err() {
                            if !data_missing[column] {
                                report.copies_unrepairable += 1;
                            }
                            continue;
                        }
                        if data_missing[column] {
                            data_bytes[column] = Some(bytes);
                            continue;
                        }
                        if repair {
                            if !self.copy_is_backed(extent) {
                                report.copies_unrepairable += 1;
                                continue;
                            }
                            let slot = self
                                .member_slot(extent.device_index)
                                .expect("presence checked above");
                            self.write_record_padded(slot, extent.offset, &bytes)?;
                            report.copies_repaired += 1;
                            dirty.insert(slot);
                        }
                        data_bytes[column] = Some(bytes);
                    }
                }
                Err(_) => {
                    report.copies_unrepairable += repairable as u64;
                }
            }
        }

        let all_data: Option<Vec<&[u8]>> =
            data_bytes.iter().map(|bytes| bytes.as_deref()).collect();
        match all_data {
            Some(pieces) => {
                let rows = crate::rs::generate_parity(&pieces, parity_count, coverage)?;
                for (row, extent) in parity_extents.iter().enumerate() {
                    if parity_missing[row] {
                        continue;
                    }
                    let consistent = parity_records[row]
                        .as_ref()
                        .is_some_and(|record| record.parity == rows[row]);
                    if consistent {
                        continue;
                    }
                    if parity_records[row].is_some() {
                        report.copies_bad += 1;
                    }
                    if repair {
                        if !self.copy_is_backed(*extent) {
                            report.copies_unrepairable += 1;
                            continue;
                        }
                        let record = ParityRecord {
                            parity_index: row as u8,
                            coverage_len: descriptor.coverage_len,
                            data_pieces: descriptor.data_pieces.clone(),
                            parity_pieces: descriptor.parity_pieces.clone(),
                            parity: rows[row].clone(),
                        };
                        let bytes = crate::stripes::encode_parity_record(&record)?;
                        let slot = self
                            .member_slot(extent.device_index)
                            .expect("presence checked above");
                        self.write_record_padded(slot, extent.offset, &bytes)?;
                        report.copies_repaired += 1;
                        dirty.insert(slot);
                    }
                }
            }
            None => {
                for (row, _) in parity_extents.iter().enumerate() {
                    if !parity_missing[row] && parity_records[row].is_none() {
                        report.copies_unrepairable += 1;
                    }
                }
            }
        }
        Ok(true)
    }

    pub fn compact(&mut self, now_ns: i64) -> Result<CompactReport> {
        if self.read_only {
            return Err(ScaleFsError::Unsupported(
                "pool is read-only: writes are not permitted",
            ));
        }
        if self.parity_width() == 0 {
            return Err(ScaleFsError::Unsupported(
                "mirror pools have no stripes to compact",
            ));
        }
        self.commit(AllocPurpose::Normal, now_ns)?;

        let mut snapshot_stripes: HashSet<(u16, u64)> = HashSet::new();
        {
            let retained: Vec<Vec<Extent>> = self
                .tree
                .range(
                    MetadataKey {
                        object_id: 0,
                        item_type: ITEM_RETAINED_ROOT,
                        offset: 0,
                    },
                    MetadataKey {
                        object_id: 0,
                        item_type: ITEM_RETAINED_ROOT,
                        offset: u64::MAX,
                    },
                )
                .iter()
                .filter_map(|(_, value)| match value {
                    MetadataValue::RetainedRoot { metadata_roots, .. } => {
                        Some(metadata_roots.clone())
                    }
                    _ => None,
                })
                .collect();
            let mut visited: HashSet<(u16, u64)> = HashSet::new();
            let mut roots = retained;
            while let Some(root) = roots.pop() {
                self.collect_stripe_keys(&root, &mut snapshot_stripes, &mut visited, &mut roots)?;
            }
        }

        let mut live_refs: Vec<((u16, u64), LiveStripe)> = Vec::new();
        {
            let mut by_stripe: std::collections::BTreeMap<(u16, u64), LiveStripe> =
                std::collections::BTreeMap::new();
            for (_, value) in self.tree.range(MetadataKey::MIN, MetadataKey::MAX) {
                let MetadataValue::StripedExtent {
                    extent,
                    parity_extents,
                    ..
                } = value
                else {
                    continue;
                };
                let Some(first) = parity_extents.first() else {
                    continue;
                };
                by_stripe
                    .entry((first.device_index, first.offset))
                    .or_insert_with(|| (parity_extents.clone(), HashSet::new()))
                    .1
                    .insert((extent.device_index, extent.offset));
            }
            live_refs.extend(by_stripe);
        }

        let target = usize::from(self.data_width()).max(1);
        let mut pending: Vec<(Extent, Vec<u8>)> = Vec::new();
        let mut stripes_compacted = 0u64;
        for (key, (parity_list, live_pieces)) in live_refs {
            if snapshot_stripes.contains(&key) {
                continue;
            }
            let mut descriptor = None;
            for extent in &parity_list {
                if let Ok(bytes) = self.read_extent(*extent)
                    && let Ok(record) = decode_parity_record(&bytes)
                {
                    descriptor = Some(record);
                    break;
                }
            }
            let Some(descriptor) = descriptor else {
                continue;
            };
            let total = descriptor.data_pieces.len();
            let live_count = descriptor
                .data_pieces
                .iter()
                .filter(|piece| live_pieces.contains(&(piece.device_index, piece.offset)))
                .count();
            if live_count == 0 || (live_count == total && total >= target) {
                continue;
            }
            let mut stripe_records: Vec<(Extent, Vec<u8>)> = Vec::new();
            let mut readable = true;
            for piece in &descriptor.data_pieces {
                if !live_pieces.contains(&(piece.device_index, piece.offset)) {
                    continue;
                }
                match self.read_striped(*piece, &parity_list) {
                    Ok(bytes) => stripe_records.push((*piece, bytes)),
                    Err(_) => {
                        readable = false;
                        break;
                    }
                }
            }
            if !readable {
                continue;
            }
            stripes_compacted += 1;
            pending.extend(stripe_records);
        }

        let mut moved: std::collections::HashMap<(u16, u64), (Extent, Vec<Extent>)> =
            std::collections::HashMap::new();
        let mut index = 0usize;
        while index < pending.len() {
            let end = (index + target).min(pending.len());
            let group: Vec<Vec<u8>> = pending[index..end]
                .iter()
                .map(|(_, bytes)| bytes.clone())
                .collect();
            let (placed, data_extents, parity_extents) = self.emit_stripe(&group)?;
            for (position, (old, _)) in pending[index..index + placed].iter().enumerate() {
                moved.insert(
                    (old.device_index, old.offset),
                    (data_extents[position], parity_extents.clone()),
                );
            }
            index += placed;
        }
        let records_rewritten = moved.len() as u64;
        let repoint: Vec<(MetadataKey, MetadataValue)> = self
            .tree
            .range(MetadataKey::MIN, MetadataKey::MAX)
            .iter()
            .filter_map(|(key, value)| match value {
                MetadataValue::StripedExtent {
                    extent,
                    data_offset,
                    logical_len,
                    ..
                } => moved.get(&(extent.device_index, extent.offset)).map(
                    |(new_extent, new_parity)| {
                        (
                            *key,
                            MetadataValue::StripedExtent {
                                extent: *new_extent,
                                parity_extents: new_parity.clone(),
                                data_offset: *data_offset,
                                logical_len: *logical_len,
                            },
                        )
                    },
                ),
                _ => None,
            })
            .collect();
        for (key, value) in repoint {
            self.tree.insert(key, value)?;
        }

        let reclaim = self.reclaim(now_ns)?;
        Ok(CompactReport {
            stripes_compacted,
            records_rewritten,
            reclaim,
        })
    }

    fn collect_stripe_keys(
        &self,
        root: &[Extent],
        keys: &mut HashSet<(u16, u64)>,
        visited: &mut HashSet<(u16, u64)>,
        pending_roots: &mut Vec<Vec<Extent>>,
    ) -> Result<()> {
        let first = root
            .first()
            .ok_or(ScaleFsError::Corrupt("tree root has no copies"))?;
        if !visited.insert((first.device_index, first.offset)) {
            return Ok(());
        }
        let bytes = self.read_record(root)?;
        match decode_record(&bytes)?.kind {
            RecordKind::MetadataInternal | RecordKind::MetadataInternalMirrored => {
                for (_, child) in decode_internal_record(&bytes)? {
                    self.collect_stripe_keys(&child, keys, visited, pending_roots)?;
                }
            }
            RecordKind::MetadataLeaf => {
                for (_, value) in decode_leaf_record(&bytes)? {
                    match value {
                        MetadataValue::StripedExtent { parity_extents, .. } => {
                            if let Some(first) = parity_extents.first() {
                                keys.insert((first.device_index, first.offset));
                            }
                        }
                        MetadataValue::RetainedRoot { metadata_roots, .. } => {
                            pending_roots.push(metadata_roots);
                        }
                        _ => {}
                    }
                }
            }
            _ => return Err(ScaleFsError::Corrupt("expected a metadata page record")),
        }
        Ok(())
    }

    pub fn reclaim(&mut self, now_ns: i64) -> Result<ReclaimReport> {
        match self.commit(AllocPurpose::Reclaim, now_ns) {
            Ok(_) => {}
            Err(ScaleFsError::OutOfSpace) if self.dirty_members.is_empty() => {}
            Err(error) => return Err(error),
        }

        let zone_sizes: Vec<u64> = self
            .allocators
            .iter()
            .map(|allocator| allocator.geometry().zone_size)
            .collect();
        let mut live: Vec<Vec<bool>> = self
            .allocators
            .iter()
            .map(|allocator| vec![false; allocator.geometry().zone_count as usize])
            .collect();

        let mut visited: HashSet<(u16, u64)> = HashSet::new();
        let mut roots = vec![self.last_metadata_root.clone()];
        while let Some(root) = roots.pop() {
            mark_tree_live(
                &self.devices,
                &zone_sizes,
                &self.member_slots,
                &root,
                &mut live,
                &mut visited,
                &mut roots,
            )?;
        }

        for slot in 0..self.devices.len() {
            let commit_extent = self.superblocks[slot]
                .newest_commit
                .ok_or(ScaleFsError::Corrupt("superblock references no commit"))?;
            mark_local_extent(&mut live, &zone_sizes, slot, commit_extent)?;
            let device = std::slice::from_ref(&self.devices[slot]);
            let commit = decode_commit(&read_extent_from_set(device, commit_extent)?)?;
            mark_local_extent(&mut live, &zone_sizes, slot, commit.allocator_summary)?;
            if let Some(aux) = commit.aux_root {
                mark_local_extent(&mut live, &zone_sizes, slot, aux)?;
                let roster = decode_topology(&read_extent_from_set(device, aux)?)?;
                mark_roster_chain_heads(&mut live, &zone_sizes, &self.member_slots, &roster)?;
            }
        }

        let mut changed_slots: HashSet<usize> = HashSet::new();
        for (member, allocator) in self.allocators.iter_mut().enumerate() {
            let dead_open: Vec<u64> = allocator
                .zones()
                .filter(|zone| zone.open && !live[member][zone.zone_index as usize])
                .map(|zone| zone.zone_index)
                .collect();
            for zone in dead_open {
                allocator.close_open_zone(zone)?;
                changed_slots.insert(member);
            }
        }

        let mut report = ReclaimReport {
            stripes_reset: 0,
            zones_reset: 0,
            bytes_reclaimed: 0,
            tx_id: self.committed_tx,
        };
        for (member, allocator) in self.allocators.iter_mut().enumerate() {
            let geometry = allocator.geometry();
            let stripe = u64::from(geometry.erase_granularity_zones);
            let mut first = 0;
            while first < geometry.zone_count {
                let end = (first + stripe).min(geometry.zone_count);
                let zones = || (first..end).map(|z| allocator.zone(z).expect("zone in range"));
                if allocator.is_usable_zone(first)
                    && zones().any(|zone| zone.class.is_some())
                    && zones().all(|zone| !zone.open && !live[member][zone.zone_index as usize])
                {
                    report.bytes_reclaimed += zones().map(|zone| zone.write_pointer).sum::<u64>();
                    allocator.reset_stripe(first)?;
                    changed_slots.insert(member);
                    report.stripes_reset += 1;
                    report.zones_reset += end - first;
                }
                first = end;
            }
        }

        for (member, slot) in self.member_slots.iter().enumerate() {
            if slot.is_some_and(|slot| changed_slots.contains(&slot)) {
                self.dirty_members.insert(member as u16);
            }
        }

        if report.zones_reset > 0 {
            report.tx_id = self.commit(AllocPurpose::Reclaim, now_ns)?;
        }
        Ok(report)
    }
}

#[cfg(test)]
impl<D: BlockDevice> Pool<D> {
    pub(crate) fn into_device(self) -> D {
        assert_eq!(self.devices.len(), 1, "pool has one member");
        self.devices
            .into_iter()
            .next()
            .expect("length checked")
            .into_inner()
    }
}

#[derive(Debug)]
struct PlannedWrite {
    member: Option<u16>,
    slot: usize,
    offset: u64,
    bytes: std::sync::Arc<Vec<u8>>,
    pad: usize,
}

type ChainAllocations = (
    Allocation,
    Option<Allocation>,
    (Allocation, std::sync::Arc<Vec<u8>>),
);

#[derive(Debug)]
struct PlannedCommit {
    tx_id: u64,
    purpose: AllocPurpose,
    created_at_ns: i64,
    thin_metadata: bool,
    participating: Vec<bool>,
    stage_pages_and_summaries: Vec<PlannedWrite>,
    stage_commit_records: Vec<PlannedWrite>,
    stage_superblocks: Vec<PlannedWrite>,
    root_replicas: Vec<Extent>,
    roster_members: Option<Vec<TopologyMember>>,
    commit_extents: Vec<Option<Extent>>,
    taken_dirty: HashSet<u16>,
    taken_force_full: bool,
    drained_suspects: Vec<u16>,
    dropped_probe_suspects: Vec<u16>,
}

#[derive(Debug)]
struct CommitFailure {
    error: ScaleFsError,
    suspect: Option<u16>,
}

fn execute_commit<D: BlockDevice>(
    devices: &[D],
    plan: &PlannedCommit,
) -> std::result::Result<(), CommitFailure> {
    fn write_stage<D: BlockDevice>(
        devices: &[D],
        writes: &[PlannedWrite],
    ) -> std::result::Result<(), CommitFailure> {
        for write in writes {
            if let Err(error) =
                write_padded(&devices[write.slot], write.offset, &write.bytes, write.pad)
            {
                let suspect = match &error {
                    ScaleFsError::Io(_) => write.member,
                    _ => None,
                };
                return Err(CommitFailure { error, suspect });
            }
        }
        Ok(())
    }
    fn barrier<D: BlockDevice>(
        devices: &[D],
        participating: &[bool],
    ) -> std::result::Result<(), CommitFailure> {
        let participants: Vec<&D> = devices
            .iter()
            .zip(participating)
            .filter_map(|(device, yes)| yes.then_some(device))
            .collect();
        D::flush_group(&participants).map_err(|error| CommitFailure {
            error,
            suspect: None,
        })
    }
    write_stage(devices, &plan.stage_pages_and_summaries)?;
    barrier(devices, &plan.participating)?;
    write_stage(devices, &plan.stage_commit_records)?;
    barrier(devices, &plan.participating)?;
    write_stage(devices, &plan.stage_superblocks)?;
    barrier(devices, &plan.participating)?;
    Ok(())
}

pub struct CommitTicket<D> {
    plan: Box<PlannedCommit>,
    devices: Vec<PartitionView<D>>,
}

impl<D: BlockDevice> CommitTicket<D> {
    pub fn tx_id(&self) -> u64 {
        self.plan.tx_id
    }

    pub fn execute(self) -> std::result::Result<ExecutedCommit, AbortedCommit> {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            execute_commit(&self.devices, &self.plan)
        }));
        match outcome {
            Ok(Ok(())) => Ok(ExecutedCommit { plan: self.plan }),
            Ok(Err(failure)) => Err(AbortedCommit {
                plan: self.plan,
                suspect: failure.suspect,
                error: failure.error,
            }),
            Err(_panic) => Err(AbortedCommit {
                plan: self.plan,
                suspect: None,
                error: ScaleFsError::Io(std::io::Error::other(
                    "a device implementation panicked during commit I/O",
                )),
            }),
        }
    }
}

#[derive(Debug)]
pub struct ExecutedCommit {
    plan: Box<PlannedCommit>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitOutcome {
    Committed { tx_id: u64 },
    Degraded(LiveDegrade),
}

impl CommitOutcome {
    pub fn tx_id(&self) -> u64 {
        match self {
            CommitOutcome::Committed { tx_id } => *tx_id,
            CommitOutcome::Degraded(degrade) => degrade.tx_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveDegrade {
    pub member: u16,
    pub device_id: DeviceId,
    pub tx_id: u64,
}

#[derive(Debug)]
pub struct AbortedCommit {
    plan: Box<PlannedCommit>,
    suspect: Option<u16>,
    error: ScaleFsError,
}

impl AbortedCommit {
    pub fn error(&self) -> &ScaleFsError {
        &self.error
    }
}

impl<D: crate::device::SharedDevice> Pool<D> {
    pub fn commit_plan(
        &mut self,
        purpose: AllocPurpose,
        created_at_ns: i64,
    ) -> Result<CommitTicket<D>> {
        let plan = self.plan_commit_impl(purpose, created_at_ns)?;
        Ok(CommitTicket {
            devices: self.devices.clone(),
            plan: Box::new(plan),
        })
    }

    pub fn commit_publish(&mut self, executed: ExecutedCommit) -> u64 {
        debug_assert!(
            self.commit_in_flight,
            "publish without a commit in flight: ticket from another pool?"
        );
        self.publish_commit_impl(*executed.plan)
    }

    pub fn commit_abandon(&mut self, aborted: AbortedCommit) -> Result<CommitOutcome> {
        debug_assert!(
            self.commit_in_flight,
            "abandon without a commit in flight: ticket from another pool?"
        );
        let AbortedCommit {
            plan,
            suspect,
            error,
        } = aborted;
        let (purpose, created_at_ns) = (plan.purpose, plan.created_at_ns);
        self.abandon_commit_impl(*plan, suspect);
        self.recover_abandoned(CommitFailure { error, suspect }, purpose, created_at_ns)
    }
}

const RECORD_ENVELOPE_LEN: usize = crate::format::RECORD_HEADER_LEN;

const SUPERBLOCK_PAD: usize = 4096;

const MEMBER_WRAPPER_BLANK: u64 = crate::gpt::MEMBER_PARTITION_START;

const PARTICIPATION_STALENESS: std::time::Duration = std::time::Duration::from_secs(10);

fn write_padded<D: BlockDevice>(device: &D, offset: u64, bytes: &[u8], unit: usize) -> Result<()> {
    let padded = bytes.len().div_ceil(unit) * unit;
    if padded == bytes.len() {
        return device.write_at(offset, bytes);
    }
    let mut buf = Vec::with_capacity(padded);
    buf.extend_from_slice(bytes);
    buf.resize(padded, 0);
    device.write_at(offset, &buf)
}

fn read_any_copy<D: BlockDevice>(devices: &[D], copies: &[Extent]) -> Result<Vec<u8>> {
    let identity: Vec<Option<usize>> = (0..devices.len()).map(Some).collect();
    read_any_copy_slotted(devices, &identity, copies)
}

fn read_any_copy_slotted<D: BlockDevice>(
    devices: &[D],
    slots: &[Option<usize>],
    copies: &[Extent],
) -> Result<Vec<u8>> {
    let mut last_error = ScaleFsError::Corrupt("record has no copies");
    for extent in copies {
        let Some(slot) = slots
            .get(usize::from(extent.device_index))
            .copied()
            .flatten()
        else {
            last_error = ScaleFsError::Corrupt("extent references a device that is not present");
            continue;
        };
        let local = Extent {
            device_index: 0,
            ..*extent
        };
        match read_extent_from_set(std::slice::from_ref(&devices[slot]), local) {
            Ok(bytes) => match decode_record(&bytes) {
                Ok(_) => return Ok(bytes),
                Err(err) => last_error = err,
            },
            Err(err) => last_error = err,
        }
    }
    Err(last_error)
}

fn place_distinct_excluding(
    allocators: &mut [ZoneAllocator],
    member_slots: &[Option<usize>],
    class: ZoneClass,
    length: u64,
    purpose: AllocPurpose,
    copies: u16,
    exclude: &[u16],
) -> Result<Vec<(u16, Allocation)>> {
    let mut placements = Vec::with_capacity(usize::from(copies));
    let mut used: HashSet<u16> = exclude.iter().copied().collect();
    for _ in 0..copies {
        let mut order: Vec<(u16, usize)> = member_slots
            .iter()
            .enumerate()
            .filter_map(|(member, slot)| slot.map(|slot| (member as u16, slot)))
            .filter(|(member, _)| !used.contains(member))
            .collect();
        order.sort_by_key(|&(member, slot)| {
            (
                std::cmp::Reverse(allocators[slot].free_usable_zone_count()),
                member,
            )
        });
        let mut placed = false;
        for (member, slot) in order {
            match allocators[slot].allocate(class, length, purpose) {
                Ok(allocation) => {
                    used.insert(member);
                    placements.push((member, allocation));
                    placed = true;
                    break;
                }
                Err(ScaleFsError::OutOfSpace) => continue,
                Err(err) => return Err(err),
            }
        }
        if !placed {
            return Err(ScaleFsError::OutOfSpace);
        }
    }
    Ok(placements)
}

fn read_extent_from_set<D: BlockDevice>(devices: &[D], extent: Extent) -> Result<Vec<u8>> {
    let device = devices
        .get(usize::from(extent.device_index))
        .ok_or(ScaleFsError::Corrupt(
            "extent references a device that is not present",
        ))?;
    let end = extent
        .end_offset()
        .ok_or(ScaleFsError::Corrupt("extent overflows the address space"))?;
    if end > device.len() {
        return Err(ScaleFsError::Corrupt("extent reaches past the device end"));
    }
    let mut bytes = vec![
        0;
        usize::try_from(extent.length).map_err(|_| ScaleFsError::Corrupt(
            "extent length exceeds address space"
        ))?
    ];
    device.read_at(extent.offset, &mut bytes)?;
    Ok(bytes)
}

fn check_member_fits<D: BlockDevice>(device: &D, geometry: Geometry) -> Result<()> {
    if crate::gpt::usable_len(device.len(), device.sector_size()) < geometry.capacity_bytes() {
        return Err(ScaleFsError::InvalidArgument(
            "device is smaller than the requested geometry plus its GPT wrapper",
        ));
    }
    Ok(())
}

fn format_member_wrapper<D: BlockDevice>(
    device: D,
    pool_id: PoolId,
    device_id: DeviceId,
) -> Result<PartitionView<D>> {
    let partition = crate::gpt::write_member_gpt(&device, pool_id.0, device_id.0)?;
    let mut view = PartitionView::new(device, partition.start, partition.len)?;
    blank_member_headers(&mut view)?;
    view.flush()?;
    Ok(view)
}

fn blank_member_headers<D: BlockDevice>(device: &mut D) -> Result<()> {
    let len = device.len();
    let zeros = [0u8; 8192];
    let head = len.min(8192) as usize;
    device.write_at(0, &zeros[..head])?;
    let [_, tail] = superblock_slots(len);
    if tail > 0 {
        let span = (len - tail).min(4096) as usize;
        device.write_at(tail, &zeros[..span])?;
    }
    Ok(())
}

fn read_prefix<D: BlockDevice>(device: &D, offset: u64) -> Result<Vec<u8>> {
    let available = device.len().saturating_sub(offset).min(4096);
    if available == 0 {
        return Err(ScaleFsError::Corrupt("device has no superblock slot"));
    }
    let mut bytes = vec![0; available as usize];
    device.read_at(offset, &mut bytes)?;
    Ok(bytes)
}

fn load_candidate<D: BlockDevice>(
    device: &D,
    superblock: Superblock,
) -> Result<(Superblock, Commit)> {
    let extent = superblock
        .newest_commit
        .ok_or(ScaleFsError::Corrupt("superblock references no commit"))?;
    let commit = decode_commit(&read_extent_from_set(std::slice::from_ref(device), extent)?)?;
    Ok((superblock, commit))
}

fn mark_roster_chain_heads(
    live: &mut [Vec<bool>],
    zone_sizes: &[u64],
    slots: &[Option<usize>],
    roster: &Topology,
) -> Result<()> {
    for entry in &roster.members {
        if entry.state == MemberState::Removed {
            continue;
        }
        mark_extent(live, zone_sizes, slots, entry.newest_commit)?;
        mark_extent(live, zone_sizes, slots, entry.newest_summary)?;
    }
    Ok(())
}

fn mark_extent(
    live: &mut [Vec<bool>],
    zone_sizes: &[u64],
    slots: &[Option<usize>],
    extent: Extent,
) -> Result<()> {
    let slot = slots
        .get(usize::from(extent.device_index))
        .copied()
        .flatten()
        .ok_or(ScaleFsError::Corrupt(
            "extent references a device that is not present",
        ))?;
    let zones = &mut live[slot];
    let end = extent
        .end_offset()
        .ok_or(ScaleFsError::Corrupt("extent overflows the address space"))?;
    let zone_size = zone_sizes[slot];
    let first = extent.offset / zone_size;
    let last = end.saturating_sub(1) / zone_size;
    for zone in first..=last {
        *zones
            .get_mut(zone as usize)
            .ok_or(ScaleFsError::Corrupt("extent reaches past the device end"))? = true;
    }
    Ok(())
}

fn mark_local_extent(
    live: &mut [Vec<bool>],
    zone_sizes: &[u64],
    slot: usize,
    extent: Extent,
) -> Result<()> {
    if extent.device_index != 0 {
        return Err(ScaleFsError::Corrupt(
            "device-local extent names another device",
        ));
    }
    let identity: Vec<Option<usize>> = (0..live.len()).map(Some).collect();
    mark_extent(
        live,
        zone_sizes,
        &identity,
        Extent {
            device_index: slot as u16,
            ..extent
        },
    )
}

fn mark_tree_live<D: BlockDevice>(
    devices: &[D],
    zone_sizes: &[u64],
    slots: &[Option<usize>],
    root: &[Extent],
    live: &mut [Vec<bool>],
    visited: &mut HashSet<(u16, u64)>,
    pending_roots: &mut Vec<Vec<Extent>>,
) -> Result<()> {
    let first = root
        .first()
        .ok_or(ScaleFsError::Corrupt("tree root has no copies"))?;
    if !visited.insert((first.device_index, first.offset)) {
        return Ok(());
    }
    for copy in root {
        mark_extent(live, zone_sizes, slots, *copy)?;
    }
    let bytes = read_any_copy_slotted(devices, slots, root)?;
    match decode_record(&bytes)?.kind {
        RecordKind::MetadataInternal | RecordKind::MetadataInternalMirrored => {
            for (_, child) in decode_internal_record(&bytes)? {
                mark_tree_live(
                    devices,
                    zone_sizes,
                    slots,
                    &child,
                    live,
                    visited,
                    pending_roots,
                )?;
            }
        }
        RecordKind::MetadataLeaf => {
            for (_, value) in decode_leaf_record(&bytes)? {
                match value {
                    MetadataValue::FileExtent { extents, .. } => {
                        for extent in extents {
                            mark_extent(live, zone_sizes, slots, extent)?;
                        }
                    }
                    MetadataValue::StripedExtent {
                        extent,
                        parity_extents,
                        ..
                    } => {
                        mark_extent(live, zone_sizes, slots, extent)?;
                        for parity in &parity_extents {
                            mark_extent(live, zone_sizes, slots, *parity)?;
                        }
                        let first = parity_extents.first().ok_or(ScaleFsError::Corrupt(
                            "striped extent has no parity records",
                        ))?;
                        if !visited.insert((first.device_index, first.offset)) {
                            continue;
                        }
                        let mut descriptor = None;
                        for parity in &parity_extents {
                            if let Ok(bytes) =
                                read_any_copy_slotted(devices, slots, std::slice::from_ref(parity))
                                && let Ok(record) = decode_parity_record(&bytes)
                            {
                                descriptor = Some(record);
                                break;
                            }
                        }
                        let Some(descriptor) = descriptor else {
                            return Err(ScaleFsError::Corrupt(
                                "live stripe has no readable parity record; scrub before reclaiming",
                            ));
                        };
                        for piece in descriptor
                            .data_pieces
                            .iter()
                            .chain(&descriptor.parity_pieces)
                        {
                            mark_extent(live, zone_sizes, slots, *piece)?;
                        }
                    }
                    MetadataValue::RetainedRoot { metadata_roots, .. } => {
                        pending_roots.push(metadata_roots);
                    }
                    _ => {}
                }
            }
        }
        _ => return Err(ScaleFsError::Corrupt("expected a metadata page record")),
    }
    Ok(())
}

fn any_superblock<D: BlockDevice>(device: &D) -> Result<Superblock> {
    let mut last_error = ScaleFsError::Corrupt("no valid superblock found");
    for offset in superblock_slots(device.len()) {
        match read_prefix(device, offset).and_then(|bytes| decode_superblock(&bytes)) {
            Ok(superblock) => return Ok(superblock),
            Err(err) => last_error = err,
        }
    }
    Err(last_error)
}

fn best_candidate<D: BlockDevice>(device: &D) -> Result<(Superblock, Commit)> {
    let mut decoded: Vec<Superblock> = Vec::new();
    let mut best: Option<(Superblock, Commit)> = None;
    let mut last_error = ScaleFsError::Corrupt("no valid superblock found");
    for offset in superblock_slots(device.len()) {
        match read_prefix(device, offset).and_then(|bytes| decode_superblock(&bytes)) {
            Ok(superblock) => {
                if superblock.unknown_incompat() != 0 {
                    return Err(ScaleFsError::Unsupported(
                        "pool uses incompatible features unknown to this build",
                    ));
                }
                superblock.require_supported_unicode_version()?;
                if let Some(previous) = decoded.first()
                    && (previous.pool_id != superblock.pool_id
                        || previous.device_id != superblock.device_id)
                {
                    return Err(ScaleFsError::Corrupt(
                        "superblock slots disagree on device identity",
                    ));
                }
                decoded.push(superblock.clone());
                match load_candidate(device, superblock) {
                    Ok((superblock, commit)) => {
                        if best
                            .as_ref()
                            .is_none_or(|(_, existing)| commit.tx_id > existing.tx_id)
                        {
                            best = Some((superblock, commit));
                        }
                    }
                    Err(err) => last_error = err,
                }
            }
            Err(err) => last_error = err,
        }
    }
    best.ok_or(last_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::MemoryBlockDevice;
    use crate::dirent;
    use crate::records::FEATURE_RO_COMPAT_SPECIAL_FILES;
    use crate::torture::{Op, RecordingBlockDevice, TortureBlockDevice};
    use crate::tree::{DirEntry, EntryKind, ITEM_FILE_EXTENT};

    const SEED: u64 = 0x5EED_CAFE_F00D_0001;
    const NOW: i64 = 1_700_000_000_000_000_000;

    fn geometry() -> Geometry {
        Geometry {
            logical_block_size: 4096,
            physical_block_size: 4096,
            zone_size: 65536,
            zone_count: 8,
            erase_granularity_zones: 1,
            sequential_write_required: true,
        }
    }

    fn params() -> CreateParams {
        CreateParams {
            pool_id: PoolId([0x11; 16]),
            device_id: DeviceId([0x22; 16]),
            geometry: geometry(),
            case_sensitivity: CaseSensitivity::InsensitivePreserving,
            dirent_hash_seed: SEED,
            label: "tank".to_string(),
            created_at_ns: NOW,
        }
    }

    fn device_len() -> usize {
        crate::gpt::member_image_len(geometry().capacity_bytes()) as usize
    }

    fn inode_key(object_id: u64) -> MetadataKey {
        MetadataKey {
            object_id,
            item_type: ITEM_INODE,
            offset: 0,
        }
    }

    fn file_inode() -> MetadataValue {
        MetadataValue::Inode(InodeAttrs {
            size: 0,
            mode: 0o100644,
            uid: 0,
            gid: 0,
            nlink: 1,
            attrs: 0,
            bsd_flags: 0,
            crtime_ns: NOW,
            mtime_ns: NOW,
            ctime_ns: NOW,
            atime_ns: NOW,
        })
    }

    fn add_test_file(pool: &mut Pool<impl BlockDevice>) {
        let case = pool.superblock().case_sensitivity;
        let version = pool.superblock().unicode_version;
        let tree = pool.tree_mut();
        tree.insert(inode_key(2), file_inode()).unwrap();
        dirent::add_entry(
            tree,
            SEED,
            version,
            case,
            ROOT_INODE,
            "f.txt",
            2,
            EntryKind::File,
        )
        .unwrap();
    }

    fn lookup_test_file(pool: &Pool<impl BlockDevice>) -> Option<DirEntry> {
        dirent::lookup_entry(
            pool.tree(),
            SEED,
            pool.superblock().unicode_version,
            pool.superblock().case_sensitivity,
            ROOT_INODE,
            "f.txt",
        )
    }

    #[test]
    fn create_then_open_round_trips() {
        let pool = Pool::create(MemoryBlockDevice::new(device_len()), params()).unwrap();
        assert_eq!(pool.committed_tx(), 1);
        let device = pool.into_device();

        let pool = Pool::open(device).unwrap();
        assert_eq!(pool.committed_tx(), 1);
        assert_eq!(pool.superblock().label, "tank");
        assert_eq!(pool.superblock().pool_id, PoolId([0x11; 16]));
        assert_eq!(pool.superblock().dirent_hash_seed, SEED);
        assert!(!pool.read_only());
        assert!(matches!(
            pool.tree().get(inode_key(ROOT_INODE)),
            Some(MetadataValue::Inode(inode)) if inode.is_dir()
        ));
    }

    #[test]
    fn committed_changes_survive_reopen() {
        let mut pool = Pool::create(MemoryBlockDevice::new(device_len()), params()).unwrap();
        add_test_file(&mut pool);
        assert_eq!(pool.commit(AllocPurpose::Normal, NOW).unwrap(), 2);

        let pool = Pool::open(pool.into_device()).unwrap();
        assert_eq!(pool.committed_tx(), 2);
        assert_eq!(lookup_test_file(&pool).unwrap().inode, 2);
    }

    #[test]
    fn uncommitted_changes_do_not_survive_reopen() {
        let mut pool = Pool::create(MemoryBlockDevice::new(device_len()), params()).unwrap();
        add_test_file(&mut pool);
        let pool = Pool::open(pool.into_device()).unwrap();
        assert_eq!(pool.committed_tx(), 1);
        assert!(lookup_test_file(&pool).is_none());
    }

    #[test]
    fn repeated_commits_reopen_cleanly() {
        let mut device = MemoryBlockDevice::new(device_len());
        Pool::create(&mut device, params()).unwrap();
        for round in 0..5u64 {
            let mut pool = Pool::open(&mut device).unwrap();
            assert_eq!(pool.committed_tx(), round + 1);
            let key = MetadataKey {
                object_id: 100 + round,
                item_type: ITEM_INODE,
                offset: 0,
            };
            pool.tree_mut().insert(key, file_inode()).unwrap();
            pool.commit(AllocPurpose::Normal, NOW).unwrap();
        }
        let pool = Pool::open(&mut device).unwrap();
        assert_eq!(pool.committed_tx(), 6);
        for round in 0..5u64 {
            assert!(pool.tree().get(inode_key(100 + round)).is_some());
        }
    }

    #[test]
    fn either_superblock_slot_alone_recovers_the_pool() {
        let mut pool = Pool::create(MemoryBlockDevice::new(device_len()), params()).unwrap();
        add_test_file(&mut pool);
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let device = pool.into_device();
        let [slot_a, slot_b] = superblock_slots(device.len());

        let only_b = device.clone();
        only_b.write_at(slot_a, &[0xFF; 4096]).unwrap();
        let pool = Pool::open(only_b).unwrap();
        assert_eq!(pool.committed_tx(), 2);

        let only_a = device.clone();
        only_a.write_at(slot_b, &[0xFF; 4096]).unwrap();
        let pool = Pool::open(only_a).unwrap();
        assert_eq!(pool.committed_tx(), 2);

        let neither = device.clone();
        neither.write_at(slot_a, &[0xFF; 4096]).unwrap();
        neither.write_at(slot_b, &[0xFF; 4096]).unwrap();
        assert!(Pool::open(neither).is_err());
    }

    #[test]
    fn import_heals_a_feature_bit_a_crash_left_off_one_member() {
        let mut pool = Pool::create_multi(roomy_members(2), mirrored_params()).unwrap();
        pool.symlink(ROOT_INODE, "l", b"target", NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        assert_ne!(
            pool.superblocks[1].feature_ro_compat & FEATURE_RO_COMPAT_SPECIAL_FILES,
            0
        );

        let mut skewed = pool.superblocks[1].clone();
        skewed.feature_ro_compat &= !FEATURE_RO_COMPAT_SPECIAL_FILES;
        let bytes = encode_superblock(&skewed).unwrap();
        for offset in superblock_slots(pool.devices[1].len()) {
            pool.devices[1].write_at(offset, &bytes).unwrap();
        }

        let devices: Vec<MemoryBlockDevice> = pool
            .devices
            .drain(..)
            .map(PartitionView::into_inner)
            .collect();
        let reopened = Pool::open_multi(devices).unwrap();
        assert!(
            !reopened.read_only(),
            "the lagging member is healed, not read-only"
        );
        for superblock in reopened.superblocks() {
            assert_ne!(
                superblock.feature_ro_compat & FEATURE_RO_COMPAT_SPECIAL_FILES,
                0,
                "every member regained the bit"
            );
        }
    }

    #[test]
    fn unsupported_unicode_version_refuses_opening() {
        let pool = Pool::create(MemoryBlockDevice::new(device_len()), params()).unwrap();
        let device = pool.into_device();

        let modified = device.clone();
        let view = crate::gpt::member_view(&modified).unwrap();
        let bytes = read_prefix(&view, 0).unwrap();
        let mut superblock = decode_superblock(&bytes).unwrap();
        superblock.unicode_version = crate::unicode::UnicodeVersion::new(99, 0, 0);
        let encoded = encode_superblock(&superblock).unwrap();
        for offset in superblock_slots(view.len()) {
            view.write_at(offset, &encoded).unwrap();
        }

        assert!(matches!(
            Pool::open(modified),
            Err(ScaleFsError::UnsupportedUnicodeVersion { .. })
        ));
    }

    #[test]
    fn feature_masks_gate_opening() {
        let pool = Pool::create(MemoryBlockDevice::new(device_len()), params()).unwrap();
        let device = pool.into_device();

        let with_features = |device: &MemoryBlockDevice, ro: u64, incompat: u64| {
            let modified = device.clone();
            let view = crate::gpt::member_view(&modified).unwrap();
            let bytes = read_prefix(&view, 0).unwrap();
            let mut superblock = decode_superblock(&bytes).unwrap();
            superblock.feature_ro_compat = ro;
            superblock.feature_incompat = incompat;
            let encoded = encode_superblock(&superblock).unwrap();
            for offset in superblock_slots(view.len()) {
                view.write_at(offset, &encoded).unwrap();
            }
            modified
        };

        const UNKNOWN_INCOMPAT: u64 = 1 << 63;
        const UNKNOWN_RO_COMPAT: u64 = 1 << 62;

        let mut pool = Pool::open(with_features(&device, UNKNOWN_RO_COMPAT, 0)).unwrap();
        assert!(pool.read_only());
        assert!(matches!(
            pool.commit(AllocPurpose::Normal, NOW),
            Err(ScaleFsError::Unsupported(_))
        ));

        let pool = Pool::open(with_features(&device, FEATURE_RO_COMPAT_SPECIAL_FILES, 0)).unwrap();
        assert!(!pool.read_only());

        assert!(matches!(
            Pool::open(with_features(&device, 0, UNKNOWN_INCOMPAT)),
            Err(ScaleFsError::Unsupported(_))
        ));

        assert!(matches!(
            Pool::open(with_features(&device, 0, FEATURE_INCOMPAT_MULTI_DEVICE)),
            Err(ScaleFsError::Unsupported(_))
        ));

        let wreck = |device: &MemoryBlockDevice| {
            let wrecked = device.clone();
            let view = crate::gpt::member_view(&wrecked).unwrap();
            let [_, tail_slot] = superblock_slots(view.len());
            let body = vec![0xFFu8; (tail_slot - 4096) as usize];
            view.write_at(4096, &body).unwrap();
            wrecked
        };
        assert!(matches!(
            Pool::open(wreck(&with_features(&device, 0, UNKNOWN_INCOMPAT))),
            Err(ScaleFsError::Unsupported(_))
        ));
        assert!(matches!(
            Pool::open(wreck(&device)),
            Err(ScaleFsError::Corrupt(_))
        ));
    }

    #[test]
    fn truncated_devices_are_rejected() {
        let pool = Pool::create(MemoryBlockDevice::new(device_len()), params()).unwrap();
        let device = pool.into_device();
        let truncated = MemoryBlockDevice::from_bytes(device.bytes()[..device_len() / 2].to_vec());
        assert!(Pool::open(truncated).is_err());

        assert!(matches!(
            Pool::create(MemoryBlockDevice::new(1024), params()),
            Err(ScaleFsError::InvalidArgument(_))
        ));
    }

    fn crash_sweep(base: &[u8], ops: &[Op], mut check: impl FnMut(MemoryBlockDevice, usize)) {
        let mut states = 0usize;
        for prefix in 0..=ops.len() {
            let device = TortureBlockDevice::from_image(base.to_vec(), 4096);
            for op in &ops[..prefix] {
                match op {
                    Op::Write { offset, data } => device.write_at(*offset, data).unwrap(),
                    Op::Flush => device.flush().unwrap(),
                }
            }
            for image in device.all_crash_images() {
                check(image, prefix);
                states += 1;
            }
        }
        assert!(states > ops.len(), "sweep enumerated too few states");
    }

    #[test]
    fn formatting_is_crash_safe() {
        let recorder = RecordingBlockDevice::new(MemoryBlockDevice::new(device_len()));
        let pool = Pool::create(recorder, params()).unwrap();
        let ops = pool.devices[0].inner().ops().to_vec();
        let base = vec![0u8; device_len()];

        crash_sweep(&base, &ops, |image, _| {
            if let Ok(pool) = Pool::open(image) {
                assert_eq!(pool.committed_tx(), 1);
                assert!(pool.tree().get(inode_key(ROOT_INODE)).is_some());
            }
        });

        let complete = pool.into_device().into_inner();
        assert_eq!(Pool::open(complete).unwrap().committed_tx(), 1);
    }

    #[test]
    fn commits_are_atomic_across_every_crash_state() {
        let pool = Pool::create(MemoryBlockDevice::new(device_len()), params()).unwrap();
        let base = pool.devices[0].inner().bytes().to_vec();

        let mut pool = Pool::open(RecordingBlockDevice::new(pool.into_device())).unwrap();
        add_test_file(&mut pool);
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let ops = pool.devices[0].inner().ops().to_vec();
        assert!(
            ops.iter().filter(|op| matches!(op, Op::Flush)).count() >= 3,
            "commit must issue its three barriers"
        );

        crash_sweep(&base, &ops, |image, prefix| {
            let pool = Pool::open(image).unwrap_or_else(|err| {
                panic!("crash state at prefix {prefix} failed to open: {err}")
            });
            match pool.committed_tx() {
                1 => assert!(
                    lookup_test_file(&pool).is_none(),
                    "old transaction must not show the new file (prefix {prefix})"
                ),
                2 => assert_eq!(
                    lookup_test_file(&pool).map(|e| e.inode),
                    Some(2),
                    "new transaction must show the new file (prefix {prefix})"
                ),
                other => panic!("recovered impossible transaction {other} (prefix {prefix})"),
            }
        });
    }

    #[test]
    fn hardlink_commits_are_atomic_across_every_crash_state() {
        let mut pool = Pool::create(MemoryBlockDevice::new(device_len()), params()).unwrap();
        let file = pool.create_file(ROOT_INODE, "a", 0o644, NOW).unwrap();
        pool.write(file, 0, b"linked payload", NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let base = pool.devices[0].inner().bytes().to_vec();
        {
            let mut pool = Pool::open(RecordingBlockDevice::new(pool.into_device())).unwrap();
            pool.link(file, ROOT_INODE, "b", NOW).unwrap();
            pool.commit(AllocPurpose::Normal, NOW).unwrap();
            let ops = pool.devices[0].inner().ops().to_vec();
            let linked_tx = pool.committed_tx();

            crash_sweep(&base, &ops, |image, prefix| {
                let pool = Pool::open(image).unwrap_or_else(|err| {
                    panic!("crash state at prefix {prefix} failed to open: {err}")
                });
                let b = pool.lookup(ROOT_INODE, "b").ok();
                let nlink = pool.getattr(file).unwrap().nlink;
                if pool.committed_tx() == linked_tx {
                    assert_eq!(b.map(|e| e.inode), Some(file), "new state lacks the link");
                    assert_eq!(
                        nlink, 2,
                        "new state must count both names (prefix {prefix})"
                    );
                } else {
                    assert!(b.is_none(), "old state must not show the link");
                    assert_eq!(nlink, 1, "old state must count one name (prefix {prefix})");
                }
                assert_eq!(
                    pool.read(file, 0, 14).unwrap(),
                    b"linked payload",
                    "the bytes hold in every state (prefix {prefix})"
                );
            });
        }

        let linked = {
            let mut pool = Pool::open(MemoryBlockDevice::from_bytes(base)).unwrap();
            pool.link(file, ROOT_INODE, "b", NOW).unwrap();
            pool.commit(AllocPurpose::Normal, NOW).unwrap();
            pool.devices[0].inner().bytes().to_vec()
        };
        let mut pool = Pool::open(RecordingBlockDevice::new(MemoryBlockDevice::from_bytes(
            linked.clone(),
        )))
        .unwrap();
        pool.unlink(ROOT_INODE, "a", NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let ops = pool.devices[0].inner().ops().to_vec();
        let unlinked_tx = pool.committed_tx();

        crash_sweep(&linked, &ops, |image, prefix| {
            let pool = Pool::open(image).unwrap_or_else(|err| {
                panic!("crash state at prefix {prefix} failed to open: {err}")
            });
            let a = pool.lookup(ROOT_INODE, "a").ok();
            let nlink = pool.getattr(file).unwrap().nlink;
            if pool.committed_tx() == unlinked_tx {
                assert!(
                    a.is_none(),
                    "new state must have dropped 'a' (prefix {prefix})"
                );
                assert_eq!(nlink, 1, "new state counts the survivor (prefix {prefix})");
            } else {
                assert_eq!(a.map(|e| e.inode), Some(file), "old state keeps 'a'");
                assert_eq!(nlink, 2, "old state counts both (prefix {prefix})");
            }
            assert_eq!(
                pool.read(file, 0, 14).unwrap(),
                b"linked payload",
                "the bytes hold in every state (prefix {prefix})"
            );
        });
    }

    #[test]
    fn xattr_commits_are_atomic_across_every_crash_state() {
        let mut pool = Pool::create(MemoryBlockDevice::new(device_len()), params()).unwrap();
        let file = pool.create_file(ROOT_INODE, "f", 0o644, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let base = pool.devices[0].inner().bytes().to_vec();

        let mut pool = Pool::open(RecordingBlockDevice::new(pool.into_device())).unwrap();
        pool.set_xattr(
            file,
            "user.tag",
            b"attr bytes",
            crate::fs::XATTR_SET_EITHER,
            NOW,
        )
        .unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let ops = pool.devices[0].inner().ops().to_vec();
        let tagged_tx = pool.committed_tx();

        crash_sweep(&base, &ops, |image, prefix| {
            let pool = Pool::open(image).unwrap_or_else(|err| {
                panic!("crash state at prefix {prefix} failed to open: {err}")
            });
            let value = pool.get_xattr(file, "user.tag").ok();
            if pool.committed_tx() == tagged_tx {
                assert_eq!(
                    value.as_deref(),
                    Some(b"attr bytes".as_slice()),
                    "new state must serve the attribute (prefix {prefix})"
                );
            } else {
                assert!(value.is_none(), "old state must not (prefix {prefix})");
            }
        });
    }

    #[test]
    fn staging_between_plan_and_publish_is_crash_safe() {
        use std::sync::Arc;
        let pool = Pool::create(MemoryBlockDevice::new(device_len()), params()).unwrap();
        let base = pool.devices[0].inner().bytes().to_vec();

        let device = Arc::new(RecordingBlockDevice::new(MemoryBlockDevice::from_bytes(
            base.clone(),
        )));
        let mut pool = Pool::open(Arc::clone(&device)).unwrap();
        add_test_file(&mut pool);
        let ticket = pool.commit_plan(AllocPurpose::Normal, NOW).unwrap();

        let late = pool
            .create_file(ROOT_INODE, "late.bin", 0o644, NOW)
            .unwrap();
        let late_payload = [7u8; 5000];
        pool.write(late, 0, &late_payload, NOW).unwrap();
        pool.suspects.lock().unwrap().insert(0);

        assert!(pool.commit(AllocPurpose::Normal, NOW).is_err());
        assert!(pool.commit_plan(AllocPurpose::Normal, NOW).is_err());

        let done = ticket.execute().expect("healthy devices execute");
        assert_eq!(pool.commit_publish(done), 2);
        assert!(
            !pool.dirty_members.is_empty(),
            "interleaved staging must survive publish to drive the next commit"
        );
        assert!(
            pool.suspects.lock().unwrap().contains(&0),
            "a suspicion recorded during the window must survive publish"
        );

        assert_eq!(pool.commit(AllocPurpose::Normal, NOW).unwrap(), 3);

        let ops = device.ops();
        crash_sweep(&base, &ops, |image, prefix| {
            let pool = Pool::open(image).unwrap_or_else(|err| {
                panic!("crash state at prefix {prefix} failed to open: {err}")
            });
            let late_entry = pool.lookup(ROOT_INODE, "late.bin").ok();
            match pool.committed_tx() {
                1 => {
                    assert!(lookup_test_file(&pool).is_none(), "prefix {prefix}");
                    assert!(late_entry.is_none(), "prefix {prefix}");
                }
                2 => {
                    assert!(lookup_test_file(&pool).is_some(), "prefix {prefix}");
                    assert!(
                        late_entry.is_none(),
                        "the in-flight commit must not reference \
                         window-staged material (prefix {prefix})"
                    );
                }
                3 => {
                    assert!(lookup_test_file(&pool).is_some(), "prefix {prefix}");
                    let entry = late_entry.expect("covered by tx 3");
                    assert_eq!(
                        pool.read(entry.inode, 0, late_payload.len()).unwrap(),
                        late_payload,
                        "prefix {prefix}"
                    );
                }
                other => panic!("recovered impossible transaction {other} (prefix {prefix})"),
            }
        });
    }

    #[test]
    fn execute_failure_wounds_before_any_retry_window() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        struct ArmedFailure {
            inner: MemoryBlockDevice,
            fail_writes: AtomicBool,
        }
        impl BlockDevice for ArmedFailure {
            fn len(&self) -> u64 {
                self.inner.len()
            }
            fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
                self.inner.read_at(offset, buf)
            }
            fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
                if self.fail_writes.load(Ordering::Relaxed) {
                    return Err(ScaleFsError::Io(std::io::Error::other("armed failure")));
                }
                self.inner.write_at(offset, data)
            }
            fn flush(&self) -> Result<()> {
                self.inner.flush()
            }
        }

        let device = Arc::new(ArmedFailure {
            inner: MemoryBlockDevice::new(device_len()),
            fail_writes: AtomicBool::new(false),
        });
        let mut pool = Pool::create(Arc::clone(&device), params()).unwrap();
        add_test_file(&mut pool);

        let ticket = pool.commit_plan(AllocPurpose::Normal, NOW).unwrap();
        device.fail_writes.store(true, Ordering::Relaxed);
        let aborted = ticket.execute().expect_err("armed writes must fail");
        assert!(matches!(aborted.error(), ScaleFsError::Io(_)));
        let error = pool
            .commit_abandon(aborted)
            .expect_err("no redundancy: wounded");
        assert!(matches!(error, ScaleFsError::Io(_)));

        assert!(pool.wounded);
        assert!(pool.suspects.lock().unwrap().contains(&0));
        device.fail_writes.store(false, Ordering::Relaxed);
        let refused = pool.commit(AllocPurpose::Normal, NOW).unwrap_err();
        assert!(
            matches!(refused, ScaleFsError::Unsupported(msg) if msg.contains("reopen")),
            "a wounded pool refuses commits until reopened"
        );
        let refused = pool.write(2, 0, b"black hole", NOW).unwrap_err();
        assert!(
            matches!(refused, ScaleFsError::Unsupported(msg) if msg.contains("before writing")),
            "a wounded pool refuses new writes"
        );
        for refused in [
            pool.mkdir(ROOT_INODE, "late-dir", 0o755, NOW).map(|_| ()),
            pool.truncate(2, 0, NOW),
            pool.unlink(ROOT_INODE, "f.txt", NOW),
            pool.rename(ROOT_INODE, "f.txt", ROOT_INODE, "g.txt", NOW),
        ] {
            assert!(
                matches!(refused, Err(ScaleFsError::Unsupported(msg)) if msg.contains("reopen")),
                "a wounded pool refuses metadata mutations"
            );
        }

        assert!(lookup_test_file(&pool).is_some());
        drop(pool);
        let device = Arc::into_inner(device).expect("sole owner");
        let reopened = Pool::open(MemoryBlockDevice::from_bytes(device.inner.bytes())).unwrap();
        assert_eq!(reopened.committed_tx(), 1);
        assert!(lookup_test_file(&reopened).is_none());
    }

    #[test]
    fn back_to_back_commits_never_overwrite_published_records() {
        let mut pool = Pool::create(MemoryBlockDevice::new(device_len()), params()).unwrap();
        add_test_file(&mut pool);
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let base = pool.devices[0].inner().bytes().to_vec();

        let mut pool = Pool::open(RecordingBlockDevice::new(pool.into_device())).unwrap();
        pool.tree_mut().insert(inode_key(3), file_inode()).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let ops = pool.devices[0].inner().ops().to_vec();

        crash_sweep(&base, &ops, |image, prefix| {
            let pool = Pool::open(image).unwrap_or_else(|err| {
                panic!("crash state at prefix {prefix} failed to open: {err}")
            });
            match pool.committed_tx() {
                2 => assert!(pool.tree().get(inode_key(3)).is_none()),
                3 => assert!(pool.tree().get(inode_key(3)).is_some()),
                other => panic!("recovered impossible transaction {other} (prefix {prefix})"),
            }
        });
    }

    #[test]
    fn failed_commits_roll_back_cleanly() {
        let mut pool = Pool::create(MemoryBlockDevice::new(device_len()), params()).unwrap();
        let file = pool
            .create_file(ROOT_INODE, "fill.bin", 0o644, NOW)
            .unwrap();
        let filler: Vec<u8> = (0..100_000usize).map(|i| (i % 249) as u8).collect();
        pool.write(file, 0, &filler, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        for id in 100..3000 {
            pool.tree_mut().insert(inode_key(id), file_inode()).unwrap();
        }
        let before = pool.allocators.clone();
        let err = pool.commit(AllocPurpose::Normal, NOW).unwrap_err();
        assert!(matches!(err, ScaleFsError::OutOfSpace), "{err:?}");
        assert_eq!(pool.allocators, before, "allocators must roll back");
        assert!(pool.tree().get(inode_key(100)).is_some());

        for id in 100..3000 {
            pool.tree_mut().remove(inode_key(id));
        }
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let reopened = Pool::open(pool.into_device()).unwrap();
        let entry = reopened.lookup(ROOT_INODE, "fill.bin").unwrap();
        assert_eq!(reopened.read(entry.inode, 0, filler.len()).unwrap(), filler);
        assert!(reopened.tree().get(inode_key(100)).is_none());
    }

    fn pool_params() -> PoolParams {
        PoolParams {
            pool_id: PoolId([0x11; 16]),
            case_sensitivity: CaseSensitivity::InsensitivePreserving,
            dirent_hash_seed: SEED,
            label: "tank".to_string(),
            created_at_ns: NOW,
            mirror_width: 1,
            data_width: 1,
            parity_width: 0,
        }
    }

    fn multi_members(count: usize) -> Vec<MemberSpec<MemoryBlockDevice>> {
        (0..count)
            .map(|i| MemberSpec {
                device: MemoryBlockDevice::new(device_len()),
                device_id: DeviceId([0x30 + i as u8; 16]),
                geometry: geometry(),
            })
            .collect()
    }

    #[test]
    fn multi_device_pools_create_commit_and_spread_data() {
        let mut pool = Pool::create_multi(multi_members(3), pool_params()).unwrap();
        assert_eq!(pool.member_count(), 3);
        for (i, superblock) in pool.superblocks().iter().enumerate() {
            assert_eq!(superblock.feature_incompat, FEATURE_INCOMPAT_MULTI_DEVICE);
            assert_eq!(superblock.pool_id, PoolId([0x11; 16]));
            assert_eq!(superblock.device_id, DeviceId([0x30 + i as u8; 16]));
            assert_eq!(superblock.topology_generation, 1);
        }

        let data: Vec<u8> = (0..200_000usize).map(|i| (i * 31 % 251) as u8).collect();
        let file = pool.create_file(ROOT_INODE, "big.bin", 0o644, NOW).unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        let spread: std::collections::HashSet<u16> = pool
            .tree()
            .range(
                MetadataKey {
                    object_id: file,
                    item_type: ITEM_FILE_EXTENT,
                    offset: 0,
                },
                MetadataKey {
                    object_id: file,
                    item_type: ITEM_FILE_EXTENT,
                    offset: u64::MAX,
                },
            )
            .iter()
            .flat_map(|(_, value)| match value {
                MetadataValue::FileExtent { extents, .. } => {
                    extents.iter().map(|extent| extent.device_index).collect()
                }
                _ => Vec::new(),
            })
            .collect();
        assert!(
            spread.len() >= 2,
            "expected data on several members, got {spread:?}"
        );
        assert_eq!(pool.read(file, 0, data.len()).unwrap(), data);

        for i in 0..pool.member_count() {
            let device = std::slice::from_ref(&pool.devices[i]);
            let superblock = decode_superblock(&read_prefix(&pool.devices[i], 0).unwrap()).unwrap();
            let commit_extent = superblock.newest_commit.expect("committed member");
            let commit =
                decode_commit(&read_extent_from_set(device, commit_extent).unwrap()).unwrap();
            assert_eq!(commit.tx_id, pool.committed_tx());
            let aux = commit
                .aux_root
                .expect("multi-device commits carry a roster");
            let roster = decode_topology(&read_extent_from_set(device, aux).unwrap()).unwrap();
            assert_eq!(roster.tx_id, commit.tx_id);
            assert_eq!(roster.topology_generation, 1);
            assert_eq!(roster.members.len(), 3);
            assert_eq!(roster.member_index(superblock.device_id), Some(i as u16));
            let entry = &roster.members[i];
            assert_eq!(entry.newest_tx, commit.tx_id);
            assert_eq!(entry.newest_summary.offset, commit.allocator_summary.offset);
            assert_eq!(entry.newest_commit.offset, commit_extent.offset);
        }

        let stray = pool.devices.remove(0).into_inner();
        assert!(matches!(
            Pool::open(stray),
            Err(ScaleFsError::Unsupported(_))
        ));
    }

    #[test]
    fn multi_device_creation_validates_members() {
        assert!(matches!(
            Pool::create_multi(multi_members(0), pool_params()),
            Err(ScaleFsError::InvalidArgument(_))
        ));

        let mut duplicated = multi_members(2);
        duplicated[1].device_id = duplicated[0].device_id;
        assert!(matches!(
            Pool::create_multi(duplicated, pool_params()),
            Err(ScaleFsError::InvalidArgument(_))
        ));
    }

    #[test]
    fn multi_device_pools_import_from_any_order() {
        let mut pool = Pool::create_multi(multi_members(3), pool_params()).unwrap();
        let data: Vec<u8> = (0..150_000usize).map(|i| (i * 17 % 253) as u8).collect();
        let file = pool
            .create_file(ROOT_INODE, "spread.bin", 0o644, NOW)
            .unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let tx = pool.committed_tx();

        let mut devices: Vec<_> = pool
            .devices
            .into_iter()
            .map(PartitionView::into_inner)
            .collect();
        devices.rotate_left(2);
        let mut pool = Pool::open_multi(devices).unwrap();
        assert_eq!(pool.committed_tx(), tx);
        assert_eq!(pool.member_count(), 3);
        for (i, superblock) in pool.superblocks().iter().enumerate() {
            assert_eq!(superblock.device_id, DeviceId([0x30 + i as u8; 16]));
        }
        let entry = pool.lookup(ROOT_INODE, "spread.bin").unwrap();
        assert_eq!(pool.read(entry.inode, 0, data.len()).unwrap(), data);

        pool.tree_mut().insert(inode_key(20), file_inode()).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let mut devices: Vec<_> = pool
            .devices
            .into_iter()
            .map(PartitionView::into_inner)
            .collect();
        devices.rotate_left(1);
        let pool = Pool::open_multi(devices).unwrap();
        assert_eq!(pool.committed_tx(), tx + 1);
        assert!(pool.tree().get(inode_key(20)).is_some());
    }

    #[test]
    fn multi_device_import_validates_the_member_set() {
        let pool = Pool::create_multi(multi_members(3), pool_params()).unwrap();
        let devices: Vec<_> = pool
            .devices
            .into_iter()
            .map(PartitionView::into_inner)
            .collect();

        let partial = vec![devices[0].clone(), devices[2].clone()];
        match Pool::open_multi(partial) {
            Err(ScaleFsError::MissingMembers { missing }) => {
                assert_eq!(missing, vec![DeviceId([0x31; 16])]);
            }
            other => panic!("expected MissingMembers, got {other:?}"),
        }

        let doubled = vec![
            devices[0].clone(),
            devices[0].clone(),
            devices[1].clone(),
            devices[2].clone(),
        ];
        assert!(matches!(
            Pool::open_multi(doubled),
            Err(ScaleFsError::InvalidArgument(_))
        ));

        let mut foreign_params = pool_params();
        foreign_params.pool_id = PoolId([0x99; 16]);
        let foreign = Pool::create_multi(
            vec![MemberSpec {
                device: MemoryBlockDevice::new(device_len()),
                device_id: DeviceId([0x77; 16]),
                geometry: geometry(),
            }],
            foreign_params,
        )
        .unwrap();
        let mixed = vec![
            devices[0].clone(),
            devices[1].clone(),
            foreign.devices.into_iter().next().unwrap().into_inner(),
        ];
        assert!(matches!(
            Pool::open_multi(mixed),
            Err(ScaleFsError::InvalidArgument(_))
        ));

        let solo = Pool::create_multi(multi_members(1), pool_params()).unwrap();
        let solo = Pool::open_multi(
            solo.devices
                .into_iter()
                .map(PartitionView::into_inner)
                .collect(),
        )
        .unwrap();
        assert_eq!(solo.member_count(), 1);
        assert!(solo.multi.is_some());

        let plain = Pool::create(MemoryBlockDevice::new(device_len()), params()).unwrap();
        let plain = Pool::open_multi(vec![plain.into_device()]).unwrap();
        assert!(plain.multi.is_none());
        assert_eq!(plain.committed_tx(), 1);
    }

    #[test]
    fn multi_device_commits_are_transactional_across_crashes() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicU64;

        let pool = Pool::create_multi(multi_members(2), pool_params()).unwrap();
        let bases: Vec<Vec<u8>> = pool
            .devices
            .iter()
            .map(|device| device.inner().bytes().to_vec())
            .collect();

        let sequence: Arc<AtomicU64> = Arc::default();
        let recorders: Vec<RecordingBlockDevice<MemoryBlockDevice>> = pool
            .devices
            .into_iter()
            .map(|device| {
                RecordingBlockDevice::with_shared_sequence(
                    device.into_inner(),
                    Arc::clone(&sequence),
                )
            })
            .collect();
        let mut pool = Pool::open_multi(recorders).unwrap();
        let data: Vec<u8> = (0..5000usize).map(|i| (i % 240) as u8).collect();
        let file = pool.create_file(ROOT_INODE, "tx.bin", 0o644, NOW).unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        let mut schedule: Vec<(u64, usize, Op)> = Vec::new();
        for (member, device) in pool.devices.iter().enumerate() {
            for (seq, op) in device.inner().sequenced_ops() {
                schedule.push((seq, member, op.clone()));
            }
        }
        schedule.sort_by_key(|(seq, _, _)| *seq);

        let member_tx = |device: &MemoryBlockDevice| -> u64 {
            crate::gpt::member_view(device)
                .ok()
                .and_then(|view| best_candidate(&view).ok())
                .map(|(_, c)| c.tx_id)
                .unwrap_or(0)
        };

        let mut states = 0usize;
        let mut lagging_continued = false;
        for prefix in 0..=schedule.len() {
            let torture: Vec<TortureBlockDevice> = bases
                .iter()
                .map(|base| TortureBlockDevice::from_image(base.clone(), 4096))
                .collect();
            for (_, member, op) in &schedule[..prefix] {
                match op {
                    Op::Write { offset, data } => torture[*member].write_at(*offset, data).unwrap(),
                    Op::Flush => torture[*member].flush().unwrap(),
                }
            }
            let images: Vec<Vec<MemoryBlockDevice>> = torture
                .iter()
                .map(|device| device.all_crash_images())
                .collect();
            for a in &images[0] {
                for b in &images[1] {
                    states += 1;
                    let recovered =
                        Pool::open_multi(vec![a.clone(), b.clone()]).unwrap_or_else(|err| {
                            panic!("crash state at prefix {prefix} failed to import: {err}")
                        });
                    match recovered.committed_tx() {
                        1 => assert!(matches!(
                            recovered.lookup(ROOT_INODE, "tx.bin"),
                            Err(ScaleFsError::NotFound)
                        )),
                        2 => {
                            let entry = recovered.lookup(ROOT_INODE, "tx.bin").unwrap();
                            assert_eq!(recovered.read(entry.inode, 0, data.len()).unwrap(), data);
                            if !lagging_continued && (member_tx(a) == 1 || member_tx(b) == 1) {
                                let mut continued =
                                    Pool::open_multi(vec![a.clone(), b.clone()]).unwrap();
                                continued
                                    .tree_mut()
                                    .insert(inode_key(30), file_inode())
                                    .unwrap();
                                continued.commit(AllocPurpose::Normal, NOW).unwrap();
                                let reopened = Pool::open_multi(
                                    continued
                                        .devices
                                        .into_iter()
                                        .map(PartitionView::into_inner)
                                        .collect(),
                                )
                                .unwrap();
                                assert_eq!(reopened.committed_tx(), 3);
                                assert!(reopened.tree().get(inode_key(30)).is_some());
                                let entry = reopened.lookup(ROOT_INODE, "tx.bin").unwrap();
                                assert_eq!(
                                    reopened.read(entry.inode, 0, data.len()).unwrap(),
                                    data
                                );
                                lagging_continued = true;
                            }
                        }
                        other => {
                            panic!("recovered impossible transaction {other} (prefix {prefix})")
                        }
                    }
                }
            }
        }
        assert!(
            lagging_continued,
            "the sweep never reached a lagging-superblock recovery"
        );
        assert!(states > 200, "sweep unexpectedly small: {states} states");
    }

    #[test]
    fn reclaim_returns_dead_space() {
        let mut pool = Pool::create(MemoryBlockDevice::new(device_len()), params()).unwrap();
        let keep: Vec<u8> = (0..30_000usize).map(|i| (i % 199) as u8).collect();
        let keeper = pool
            .create_file(ROOT_INODE, "keep.bin", 0o644, NOW)
            .unwrap();
        pool.write(keeper, 0, &keep, NOW).unwrap();
        let bulk: Vec<u8> = (0..60_000usize).map(|i| (i % 197) as u8).collect();
        let goner = pool
            .create_file(ROOT_INODE, "gone.bin", 0o644, NOW)
            .unwrap();
        pool.write(goner, 0, &bulk, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        let free_before = pool.allocators()[0].free_usable_zone_count();
        pool.unlink(ROOT_INODE, "gone.bin", NOW).unwrap();
        let report = pool.reclaim(NOW).unwrap();
        assert!(report.zones_reset >= 1, "{report:?}");
        assert!(report.bytes_reclaimed > 0);
        assert!(pool.allocators()[0].free_usable_zone_count() > free_before);

        let again = pool.reclaim(NOW).unwrap();
        assert_eq!(again.zones_reset, 0, "{again:?}");

        let reopened = Pool::open(pool.into_device()).unwrap();
        let entry = reopened.lookup(ROOT_INODE, "keep.bin").unwrap();
        assert_eq!(reopened.read(entry.inode, 0, keep.len()).unwrap(), keep);
        assert!(matches!(
            reopened.lookup(ROOT_INODE, "gone.bin"),
            Err(ScaleFsError::NotFound)
        ));
    }

    #[test]
    fn snapshots_pin_space_until_released() {
        let mut pool = Pool::create(MemoryBlockDevice::new(device_len()), params()).unwrap();
        let bulk: Vec<u8> = (0..60_000usize).map(|i| (i % 193) as u8).collect();
        let file = pool
            .create_file(ROOT_INODE, "bulk.bin", 0o644, NOW)
            .unwrap();
        pool.write(file, 0, &bulk, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        pool.snapshot_create("pin", NOW).unwrap();

        pool.unlink(ROOT_INODE, "bulk.bin", NOW).unwrap();
        let report = pool.reclaim(NOW).unwrap();
        assert_eq!(
            report.zones_reset, 0,
            "snapshot must pin the data: {report:?}"
        );

        {
            let snapshot = pool.snapshot_open("pin").unwrap();
            let entry = snapshot.lookup(ROOT_INODE, "bulk.bin").unwrap();
            assert_eq!(snapshot.read(entry.inode, 0, bulk.len()).unwrap(), bulk);
        }

        pool.snapshot_release("pin").unwrap();
        let report = pool.reclaim(NOW).unwrap();
        assert!(report.zones_reset >= 1, "{report:?}");
        assert!(Pool::open(pool.into_device()).is_ok());
    }

    #[test]
    fn reclaim_rescues_a_pool_at_the_reserve_floor() {
        let mut pool = Pool::create(MemoryBlockDevice::new(device_len()), params()).unwrap();
        let chunk: Vec<u8> = (0..30_000usize).map(|i| (i % 251) as u8).collect();
        let mut names: Vec<String> = Vec::new();
        for i in 0..10_000 {
            let name = format!("f{i:04}");
            let file = match pool.create_file(ROOT_INODE, &name, 0o644, NOW) {
                Ok(entry) => entry,
                Err(ScaleFsError::OutOfSpace) => break,
                Err(error) => panic!("create refused oddly: {error:?}"),
            };
            match pool.write(file, 0, &chunk, NOW) {
                Ok(_) => {}
                Err(ScaleFsError::OutOfSpace) => break,
                Err(error) => panic!("write refused oddly: {error:?}"),
            }
            match pool.commit(AllocPurpose::Normal, NOW) {
                Ok(_) => names.push(name),
                Err(ScaleFsError::OutOfSpace) => break,
                Err(error) => panic!("fill commit refused oddly: {error:?}"),
            }
        }
        assert!(names.len() > 3, "the fill must land some files first");
        let mut floored = false;
        for i in 0..10_000 {
            match pool.create_file(ROOT_INODE, &format!("t{i:04}"), 0o644, NOW) {
                Ok(_) | Err(ScaleFsError::OutOfSpace) => {}
                Err(error) => panic!("create refused oddly: {error:?}"),
            }
            match pool.commit(AllocPurpose::Normal, NOW) {
                Ok(_) => {}
                Err(ScaleFsError::OutOfSpace) => {
                    floored = true;
                    break;
                }
                Err(error) => panic!("commit refused oddly: {error:?}"),
            }
        }
        assert!(floored, "the grind must reach commit-refusal");
        for name in &names {
            pool.unlink(ROOT_INODE, name, NOW).unwrap();
        }
        let report = pool.reclaim(NOW).unwrap();
        assert!(report.zones_reset >= 1, "{report:?}");
        let file = pool
            .create_file(ROOT_INODE, "after.bin", 0o644, NOW)
            .unwrap();
        pool.write(file, 0, &chunk, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let reopened = Pool::open(pool.into_device()).unwrap();
        let entry = reopened.lookup(ROOT_INODE, "after.bin").unwrap();
        assert_eq!(reopened.read(entry.inode, 0, chunk.len()).unwrap(), chunk);
    }

    fn roomy_members(count: usize) -> Vec<MemberSpec<MemoryBlockDevice>> {
        (0..count)
            .map(|i| {
                let mut geometry = geometry();
                geometry.zone_count = 16;
                MemberSpec {
                    device: MemoryBlockDevice::new(crate::gpt::member_image_len(
                        geometry.capacity_bytes(),
                    ) as usize),
                    device_id: DeviceId([0x30 + i as u8; 16]),
                    geometry,
                }
            })
            .collect()
    }

    #[test]
    fn reclaim_frees_space_across_members() {
        let mut pool = Pool::create_multi(roomy_members(2), pool_params()).unwrap();
        let bulk: Vec<u8> = (0..260_000usize).map(|i| (i % 189) as u8).collect();
        let goner = pool
            .create_file(ROOT_INODE, "gone.bin", 0o644, NOW)
            .unwrap();
        pool.write(goner, 0, &bulk, NOW).unwrap();
        let keep: Vec<u8> = (0..20_000usize).map(|i| (i % 191) as u8).collect();
        let keeper = pool
            .create_file(ROOT_INODE, "keep.bin", 0o644, NOW)
            .unwrap();
        pool.write(keeper, 0, &keep, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        let free_before: Vec<u64> = pool
            .allocators()
            .iter()
            .map(ZoneAllocator::free_usable_zone_count)
            .collect();
        pool.unlink(ROOT_INODE, "gone.bin", NOW).unwrap();
        let report = pool.reclaim(NOW).unwrap();
        assert!(report.zones_reset >= 2, "{report:?}");
        let freed_members = pool
            .allocators()
            .iter()
            .zip(&free_before)
            .filter(|(allocator, before)| allocator.free_usable_zone_count() > **before)
            .count();
        assert!(
            freed_members >= 2,
            "expected space back on several members: {report:?}"
        );

        let mut devices: Vec<_> = pool
            .devices
            .into_iter()
            .map(PartitionView::into_inner)
            .collect();
        devices.rotate_left(1);
        let reopened = Pool::open_multi(devices).unwrap();
        let entry = reopened.lookup(ROOT_INODE, "keep.bin").unwrap();
        assert_eq!(reopened.read(entry.inode, 0, keep.len()).unwrap(), keep);
    }

    #[test]
    fn multi_zone_stripes_reset_only_when_fully_dead() {
        let mut geometry = geometry();
        geometry.erase_granularity_zones = 2;
        geometry.zone_count = 12;
        let mut params = params();
        params.geometry = geometry;
        let device = MemoryBlockDevice::new(
            crate::gpt::member_image_len(geometry.capacity_bytes()) as usize,
        );
        let mut pool = Pool::create(device, params).unwrap();

        let a: Vec<u8> = (0..90_000usize).map(|i| (i % 187) as u8).collect();
        let file_a = pool.create_file(ROOT_INODE, "a.bin", 0o644, NOW).unwrap();
        pool.write(file_a, 0, &a, NOW).unwrap();
        let b: Vec<u8> = (0..30_000usize).map(|i| (i % 181) as u8).collect();
        let file_b = pool.create_file(ROOT_INODE, "b.bin", 0o644, NOW).unwrap();
        pool.write(file_b, 0, &b, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        pool.unlink(ROOT_INODE, "a.bin", NOW).unwrap();
        let report = pool.reclaim(NOW).unwrap();
        assert_eq!(report.zones_reset, 0, "{report:?}");

        pool.unlink(ROOT_INODE, "b.bin", NOW).unwrap();
        let report = pool.reclaim(NOW).unwrap();
        assert_eq!(report.stripes_reset, 1, "{report:?}");
        assert_eq!(report.zones_reset, 2);
    }

    #[test]
    fn reclamation_is_transactional_across_crashes() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicU64;

        let mut pool = Pool::create_multi(roomy_members(2), pool_params()).unwrap();
        let bulk: Vec<u8> = (0..260_000usize).map(|i| (i % 189) as u8).collect();
        let goner = pool
            .create_file(ROOT_INODE, "gone.bin", 0o644, NOW)
            .unwrap();
        pool.write(goner, 0, &bulk, NOW).unwrap();
        let keep: Vec<u8> = (0..20_000usize).map(|i| (i % 191) as u8).collect();
        let keeper = pool
            .create_file(ROOT_INODE, "keep.bin", 0o644, NOW)
            .unwrap();
        pool.write(keeper, 0, &keep, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        pool.unlink(ROOT_INODE, "gone.bin", NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let base_tx = pool.committed_tx();
        let bases: Vec<Vec<u8>> = pool
            .devices
            .iter()
            .map(|device| device.inner().bytes().to_vec())
            .collect();

        let sequence: Arc<AtomicU64> = Arc::default();
        let recorders: Vec<RecordingBlockDevice<MemoryBlockDevice>> = pool
            .devices
            .into_iter()
            .map(|device| {
                RecordingBlockDevice::with_shared_sequence(
                    device.into_inner(),
                    Arc::clone(&sequence),
                )
            })
            .collect();
        let mut pool = Pool::open_multi(recorders).unwrap();
        let report = pool.reclaim(NOW).unwrap();
        assert!(report.zones_reset >= 2, "{report:?}");
        assert_eq!(report.tx_id, base_tx + 2);
        let mut schedule: Vec<(u64, usize, Op)> = Vec::new();
        for (member, device) in pool.devices.iter().enumerate() {
            for (seq, op) in device.inner().sequenced_ops() {
                schedule.push((seq, member, op.clone()));
            }
        }
        schedule.sort_by_key(|(seq, _, _)| *seq);

        let member_tx = |device: &MemoryBlockDevice| -> u64 {
            crate::gpt::member_view(device)
                .ok()
                .and_then(|view| best_candidate(&view).ok())
                .map(|(_, c)| c.tx_id)
                .unwrap_or(0)
        };

        let mut states = 0usize;
        let mut continued_kinds: HashSet<u64> = HashSet::new();
        let mut lagging_continued = false;
        for prefix in 0..=schedule.len() {
            let torture: Vec<TortureBlockDevice> = bases
                .iter()
                .map(|base| TortureBlockDevice::from_image(base.clone(), 4096))
                .collect();
            for (_, member, op) in &schedule[..prefix] {
                match op {
                    Op::Write { offset, data } => torture[*member].write_at(*offset, data).unwrap(),
                    Op::Flush => torture[*member].flush().unwrap(),
                }
            }
            let images: Vec<Vec<MemoryBlockDevice>> = torture
                .iter()
                .map(|device| device.all_crash_images())
                .collect();
            for a in &images[0] {
                for b in &images[1] {
                    states += 1;
                    let recovered =
                        Pool::open_multi(vec![a.clone(), b.clone()]).unwrap_or_else(|err| {
                            panic!("crash state at prefix {prefix} failed to import: {err}")
                        });
                    let tx = recovered.committed_tx();
                    assert!(
                        (base_tx..=base_tx + 2).contains(&tx),
                        "recovered impossible transaction {tx} (prefix {prefix})"
                    );
                    let entry = recovered.lookup(ROOT_INODE, "keep.bin").unwrap();
                    assert_eq!(recovered.read(entry.inode, 0, keep.len()).unwrap(), keep);
                    assert!(matches!(
                        recovered.lookup(ROOT_INODE, "gone.bin"),
                        Err(ScaleFsError::NotFound)
                    ));

                    let lag = member_tx(a) != member_tx(b);
                    if continued_kinds.insert(tx) || (lag && !lagging_continued) {
                        if lag {
                            lagging_continued = true;
                        }
                        let mut continued = Pool::open_multi(vec![a.clone(), b.clone()]).unwrap();
                        continued.reclaim(NOW).unwrap();
                        let reopened = Pool::open_multi(
                            continued
                                .devices
                                .into_iter()
                                .map(PartitionView::into_inner)
                                .collect(),
                        )
                        .unwrap();
                        let entry = reopened.lookup(ROOT_INODE, "keep.bin").unwrap();
                        assert_eq!(reopened.read(entry.inode, 0, keep.len()).unwrap(), keep);
                    }
                }
            }
        }
        assert!(
            lagging_continued,
            "the sweep never reached a lagging-superblock recovery"
        );
        assert!(states > 80, "sweep unexpectedly small: {states} states");
    }

    #[test]
    fn small_commits_skip_untouched_members() {
        let mut pool = Pool::create_multi(roomy_members(5), mirrored_params()).unwrap();
        pool.probe_staleness = std::time::Duration::MAX;
        let data: Vec<u8> = (0..20_000usize).map(|i| (i * 7 % 251) as u8).collect();
        let file = pool.create_file(ROOT_INODE, "one.bin", 0o644, NOW).unwrap();
        pool.write(file, 0, &data, NOW).unwrap();

        let before: Vec<Vec<u8>> = pool
            .devices
            .iter()
            .map(|device| device.inner().bytes().to_vec())
            .collect();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let touched: Vec<usize> = (0..pool.devices.len())
            .filter(|&i| pool.devices[i].inner().bytes() != before[i].as_slice())
            .collect();
        assert!(
            touched.len() >= 2 && touched.len() <= 4,
            "expected 2..=4 participants, commit touched {touched:?}"
        );

        pool.write(file, 0, &data[..5_000], NOW).unwrap();
        let before: Vec<Vec<u8>> = pool
            .devices
            .iter()
            .map(|device| device.inner().bytes().to_vec())
            .collect();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let touched: Vec<usize> = (0..pool.devices.len())
            .filter(|&i| pool.devices[i].inner().bytes() != before[i].as_slice())
            .collect();
        assert!(
            touched.len() < pool.devices.len(),
            "a one-record tx must skip someone: {touched:?}"
        );

        let tx = pool.committed_tx();
        let reopened = Pool::open_multi(
            pool.devices
                .into_iter()
                .map(PartitionView::into_inner)
                .collect(),
        )
        .unwrap();
        assert_eq!(reopened.committed_tx(), tx);
        let entry = reopened.lookup(ROOT_INODE, "one.bin").unwrap();
        assert_eq!(reopened.read(entry.inode, 0, data.len()).unwrap(), data);
    }

    #[test]
    fn skip_committed_pools_import_with_any_single_member_absent() {
        let mut pool = Pool::create_multi(roomy_members(5), mirrored_params()).unwrap();
        pool.probe_staleness = std::time::Duration::MAX;
        let mut files = Vec::new();
        for i in 0..6u64 {
            let data: Vec<u8> = (0..8_000usize)
                .map(|j| ((j + i as usize) % 251) as u8)
                .collect();
            let name = format!("f-{i}");
            let file = pool.create_file(ROOT_INODE, &name, 0o644, NOW).unwrap();
            pool.write(file, 0, &data, NOW).unwrap();
            pool.commit(AllocPurpose::Normal, NOW).unwrap();
            files.push((name, data));
        }
        let tx = pool.committed_tx();

        let devices: Vec<_> = pool
            .devices
            .into_iter()
            .map(PartitionView::into_inner)
            .collect();
        for absent in 0..devices.len() {
            let survivors: Vec<MemoryBlockDevice> = devices
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != absent)
                .map(|(_, device)| device.clone())
                .collect();
            let mut degraded = Pool::open_multi_degraded(survivors)
                .unwrap_or_else(|err| panic!("import without member {absent} failed: {err}"));
            assert_eq!(
                degraded.committed_tx(),
                tx,
                "newest roster lost with member {absent} absent"
            );
            assert!(degraded.is_degraded() && degraded.read_only());
            assert!(matches!(
                degraded.create_file(ROOT_INODE, "nope", 0o644, NOW),
                Err(ScaleFsError::Unsupported(msg)) if msg.contains("read-only")
            ));
            for (name, data) in &files {
                let entry = degraded.lookup(ROOT_INODE, name).unwrap();
                assert_eq!(&degraded.read(entry.inode, 0, data.len()).unwrap(), data);
            }
        }
    }

    #[test]
    fn skip_commits_are_transactional_across_crashes() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicU64;

        let mut pool = Pool::create_multi(roomy_members(5), mirrored_params()).unwrap();
        let keep: Vec<u8> = (0..24_000usize).map(|i| (i % 197) as u8).collect();
        let keeper = pool
            .create_file(ROOT_INODE, "keep.bin", 0o644, NOW)
            .unwrap();
        pool.write(keeper, 0, &keep, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let base_tx = pool.committed_tx();
        let bases: Vec<Vec<u8>> = pool
            .devices
            .iter()
            .map(|device| device.inner().bytes().to_vec())
            .collect();

        let sequence: Arc<AtomicU64> = Arc::default();
        let recorders: Vec<RecordingBlockDevice<MemoryBlockDevice>> = pool
            .devices
            .into_iter()
            .map(|device| {
                RecordingBlockDevice::with_shared_sequence(
                    device.into_inner(),
                    Arc::clone(&sequence),
                )
            })
            .collect();
        let mut pool = Pool::open_multi(recorders).unwrap();
        pool.probe_staleness = std::time::Duration::MAX;
        let fresh: Vec<u8> = (0..9_000usize).map(|i| (i % 193) as u8).collect();
        let file = pool.create_file(ROOT_INODE, "new.bin", 0o644, NOW).unwrap();
        pool.write(file, 0, &fresh, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let mut schedule: Vec<(u64, usize, Op)> = Vec::new();
        let mut wrote: Vec<bool> = Vec::new();
        for (member, device) in pool.devices.iter().enumerate() {
            let ops: Vec<(u64, Op)> = device.inner().sequenced_ops();
            wrote.push(!ops.is_empty());
            for (seq, op) in ops {
                schedule.push((seq, member, op));
            }
        }
        schedule.sort_by_key(|(seq, _, _)| *seq);
        assert!(
            wrote.iter().any(|w| !w),
            "the small tx should have skipped a member entirely"
        );

        let mut new_seen = false;
        for prefix in 0..=schedule.len() {
            let torture: Vec<TortureBlockDevice> = bases
                .iter()
                .map(|base| TortureBlockDevice::from_image(base.clone(), 4096))
                .collect();
            for (_, member, op) in &schedule[..prefix] {
                match op {
                    Op::Write { offset, data } => torture[*member].write_at(*offset, data).unwrap(),
                    Op::Flush => torture[*member].flush().unwrap(),
                }
            }
            for seed in 0..6u64 {
                let members: Vec<MemoryBlockDevice> = torture
                    .iter()
                    .enumerate()
                    .map(|(m, device)| device.crash_image(seed * 31 + m as u64))
                    .collect();
                let recovered = Pool::open_multi(members).unwrap_or_else(|err| {
                    panic!("crash state (prefix {prefix}, seed {seed}) failed to import: {err}")
                });
                let tx = recovered.committed_tx();
                assert!(
                    tx == base_tx || tx == base_tx + 1,
                    "recovered impossible transaction {tx} (prefix {prefix}, seed {seed})"
                );
                let entry = recovered.lookup(ROOT_INODE, "keep.bin").unwrap();
                assert_eq!(recovered.read(entry.inode, 0, keep.len()).unwrap(), keep);
                match recovered.lookup(ROOT_INODE, "new.bin") {
                    Ok(entry) => {
                        assert_eq!(tx, base_tx + 1);
                        assert_eq!(recovered.read(entry.inode, 0, fresh.len()).unwrap(), fresh);
                        new_seen = true;
                    }
                    Err(ScaleFsError::NotFound) => assert_eq!(tx, base_tx),
                    Err(err) => panic!("lookup failed: {err}"),
                }
            }
        }
        assert!(new_seen, "the sweep never reached the committed state");
    }

    #[test]
    fn skip_commits_are_transactional_on_parity_pools() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicU64;

        let params = PoolParams {
            mirror_width: 2,
            data_width: 2,
            parity_width: 1,
            ..pool_params()
        };
        let mut pool = Pool::create_multi(roomy_members(5), params).unwrap();
        let keep: Vec<u8> = (0..80_000usize).map(|i| (i % 197) as u8).collect();
        let keeper = pool
            .create_file(ROOT_INODE, "keep.bin", 0o644, NOW)
            .unwrap();
        pool.write(keeper, 0, &keep, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let base_tx = pool.committed_tx();
        let bases: Vec<Vec<u8>> = pool
            .devices
            .iter()
            .map(|device| device.inner().bytes().to_vec())
            .collect();

        let sequence: Arc<AtomicU64> = Arc::default();
        let recorders: Vec<RecordingBlockDevice<MemoryBlockDevice>> = pool
            .devices
            .into_iter()
            .map(|device| {
                RecordingBlockDevice::with_shared_sequence(
                    device.into_inner(),
                    Arc::clone(&sequence),
                )
            })
            .collect();
        let mut pool = Pool::open_multi(recorders).unwrap();
        pool.probe_staleness = std::time::Duration::MAX;
        let fresh: Vec<u8> = (0..40_000usize).map(|i| (i % 193) as u8).collect();
        let file = pool.create_file(ROOT_INODE, "new.bin", 0o644, NOW).unwrap();
        pool.write(file, 0, &fresh, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let mut schedule: Vec<(u64, usize, Op)> = Vec::new();
        let mut wrote: Vec<bool> = Vec::new();
        for (member, device) in pool.devices.iter().enumerate() {
            let ops: Vec<(u64, Op)> = device.inner().sequenced_ops();
            wrote.push(!ops.is_empty());
            for (seq, op) in ops {
                schedule.push((seq, member, op));
            }
        }
        schedule.sort_by_key(|(seq, _, _)| *seq);
        assert!(
            wrote.iter().any(|w| !w),
            "the small striped tx should have skipped a member entirely"
        );

        let mut new_seen = false;
        for prefix in 0..=schedule.len() {
            let torture: Vec<TortureBlockDevice> = bases
                .iter()
                .map(|base| TortureBlockDevice::from_image(base.clone(), 4096))
                .collect();
            for (_, member, op) in &schedule[..prefix] {
                match op {
                    Op::Write { offset, data } => torture[*member].write_at(*offset, data).unwrap(),
                    Op::Flush => torture[*member].flush().unwrap(),
                }
            }
            for seed in 0..4u64 {
                let members: Vec<MemoryBlockDevice> = torture
                    .iter()
                    .enumerate()
                    .map(|(m, device)| device.crash_image(seed * 31 + m as u64))
                    .collect();
                let recovered = Pool::open_multi(members).unwrap_or_else(|err| {
                    panic!("crash state (prefix {prefix}, seed {seed}) failed to import: {err}")
                });
                let tx = recovered.committed_tx();
                assert!(
                    tx == base_tx || tx == base_tx + 1,
                    "recovered impossible transaction {tx} (prefix {prefix}, seed {seed})"
                );
                let entry = recovered.lookup(ROOT_INODE, "keep.bin").unwrap();
                assert_eq!(recovered.read(entry.inode, 0, keep.len()).unwrap(), keep);
                match recovered.lookup(ROOT_INODE, "new.bin") {
                    Ok(entry) => {
                        assert_eq!(tx, base_tx + 1);
                        assert_eq!(recovered.read(entry.inode, 0, fresh.len()).unwrap(), fresh);
                        new_seen = true;
                    }
                    Err(ScaleFsError::NotFound) => assert_eq!(tx, base_tx),
                    Err(err) => panic!("lookup failed: {err}"),
                }
            }
        }
        assert!(new_seen, "the sweep never reached the committed state");

        let devices: Vec<MemoryBlockDevice> = pool
            .devices
            .into_iter()
            .map(|view| view.into_inner().into_inner())
            .collect();
        for absent in 0..devices.len() {
            let survivors: Vec<MemoryBlockDevice> = devices
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != absent)
                .map(|(_, device)| device.clone())
                .collect();
            let degraded = Pool::open_multi_degraded(survivors)
                .unwrap_or_else(|err| panic!("import without member {absent} failed: {err}"));
            assert!(degraded.is_degraded() && degraded.read_only());
            for (name, data) in [("keep.bin", &keep), ("new.bin", &fresh)] {
                let entry = degraded.lookup(ROOT_INODE, name).unwrap();
                assert_eq!(&degraded.read(entry.inode, 0, data.len()).unwrap(), data);
            }
        }
    }

    #[test]
    fn feature_and_transition_commits_republish_every_member() {
        let mut pool = Pool::create_multi(roomy_members(4), mirrored_params()).unwrap();
        pool.probe_staleness = std::time::Duration::MAX;
        for i in 0..3u64 {
            let data: Vec<u8> = (0..6_000usize)
                .map(|j| ((j + i as usize) % 251) as u8)
                .collect();
            let file = pool
                .create_file(ROOT_INODE, &format!("s-{i}"), 0o644, NOW)
                .unwrap();
            pool.write(file, 0, &data, NOW).unwrap();
            pool.commit(AllocPurpose::Normal, NOW).unwrap();
        }

        pool.mknod(ROOT_INODE, "fifo", 0o010644, 0, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let feature_tx = pool.committed_tx();
        for i in 0..pool.devices.len() {
            let superblock = decode_superblock(&read_prefix(&pool.devices[i], 0).unwrap()).unwrap();
            assert_ne!(
                superblock.feature_ro_compat & FEATURE_RO_COMPAT_SPECIAL_FILES,
                0
            );
            let device = std::slice::from_ref(&pool.devices[i]);
            let commit_extent = superblock.newest_commit.expect("committed member");
            let commit =
                decode_commit(&read_extent_from_set(device, commit_extent).unwrap()).unwrap();
            assert_eq!(
                commit.tx_id, feature_tx,
                "member {i} lags the feature commit"
            );
        }

        let file = pool.create_file(ROOT_INODE, "skew", 0o644, NOW).unwrap();
        pool.write(file, 0, &[7u8; 4096], NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let spec = MemberSpec {
            device: MemoryBlockDevice::new({
                let mut geometry = geometry();
                geometry.zone_count = 16;
                crate::gpt::member_image_len(geometry.capacity_bytes()) as usize
            }),
            device_id: DeviceId([0x77; 16]),
            geometry: {
                let mut geometry = geometry();
                geometry.zone_count = 16;
                geometry
            },
        };
        pool.add_member(spec, NOW).unwrap();
        let grow_tx = pool.committed_tx();
        for i in 0..pool.devices.len() {
            let superblock = decode_superblock(&read_prefix(&pool.devices[i], 0).unwrap()).unwrap();
            let device = std::slice::from_ref(&pool.devices[i]);
            let commit_extent = superblock.newest_commit.expect("committed member");
            let commit =
                decode_commit(&read_extent_from_set(device, commit_extent).unwrap()).unwrap();
            assert_eq!(commit.tx_id, grow_tx, "member {i} lags the transition");
        }
    }

    #[test]
    fn empty_commits_advance_the_chain_on_root_members() {
        let mut pool = Pool::create_multi(roomy_members(4), mirrored_params()).unwrap();
        pool.probe_staleness = std::time::Duration::MAX;
        let file = pool.create_file(ROOT_INODE, "seed", 0o644, NOW).unwrap();
        pool.write(file, 0, &[3u8; 2048], NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        let before: Vec<Vec<u8>> = pool
            .devices
            .iter()
            .map(|device| device.inner().bytes().to_vec())
            .collect();
        let tx = pool.commit(AllocPurpose::Normal, NOW).unwrap();
        assert_eq!(tx, pool.committed_tx());
        let touched: Vec<usize> = (0..pool.devices.len())
            .filter(|&i| pool.devices[i].inner().bytes() != before[i].as_slice())
            .collect();
        assert!(
            !touched.is_empty() && touched.len() < pool.devices.len(),
            "an empty commit touches the root replicas only: {touched:?}"
        );
        let reopened = Pool::open_multi(
            pool.devices
                .into_iter()
                .map(PartitionView::into_inner)
                .collect(),
        )
        .unwrap();
        assert_eq!(reopened.committed_tx(), tx);
    }

    #[test]
    fn engine_writes_are_block_aligned_on_every_path() {
        struct AlignmentChecking {
            inner: MemoryBlockDevice,
            block: u64,
        }
        impl BlockDevice for AlignmentChecking {
            fn len(&self) -> u64 {
                self.inner.len()
            }
            fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
                self.inner.read_at(offset, buf)
            }
            fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
                let wrapper = offset < crate::gpt::MEMBER_PARTITION_START
                    || offset >= self.inner.len() - 33 * 512;
                let unit = if wrapper { 512 } else { self.block };
                assert_eq!(offset % unit, 0, "unaligned write offset {offset}");
                assert_eq!(
                    data.len() as u64 % unit,
                    0,
                    "unaligned write length {} at {offset}",
                    data.len()
                );
                self.inner.write_at(offset, data)
            }
            fn flush(&self) -> Result<()> {
                self.inner.flush()
            }
        }

        let members: Vec<MemberSpec<AlignmentChecking>> = (0..3)
            .map(|i| {
                let mut geometry = geometry();
                geometry.zone_count = 16;
                MemberSpec {
                    device: AlignmentChecking {
                        inner: MemoryBlockDevice::new(crate::gpt::member_image_len(
                            geometry.capacity_bytes(),
                        ) as usize),
                        block: u64::from(geometry.logical_block_size),
                    },
                    device_id: DeviceId([0x50 + i as u8; 16]),
                    geometry,
                }
            })
            .collect();
        let mut pool = Pool::create_multi(members, mirrored_params()).unwrap();
        let data: Vec<u8> = (0..150_000usize).map(|i| (i * 11 % 251) as u8).collect();
        let file = pool
            .create_file(ROOT_INODE, "data.bin", 0o644, NOW)
            .unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        pool.write(file, 3_000, &data[..10_000], NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        pool.unlink(ROOT_INODE, "data.bin", NOW).unwrap();
        pool.reclaim(NOW).unwrap();
        let survivor = pool
            .create_file(ROOT_INODE, "keep.bin", 0o644, NOW)
            .unwrap();
        pool.write(survivor, 0, &data[..40_000], NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        let copies: Vec<Extent> = pool
            .tree()
            .range(
                MetadataKey {
                    object_id: survivor,
                    item_type: ITEM_FILE_EXTENT,
                    offset: 0,
                },
                MetadataKey {
                    object_id: survivor,
                    item_type: ITEM_FILE_EXTENT,
                    offset: u64::MAX,
                },
            )
            .iter()
            .flat_map(|(_, value)| match value {
                MetadataValue::FileExtent { extents, .. } => extents.clone(),
                _ => Vec::new(),
            })
            .collect();
        let target = copies[0];
        let slot = pool.member_slot(target.device_index).unwrap();
        let zeros = vec![0u8; 4096];
        pool.devices[slot]
            .write_at(target.offset - target.offset % 4096, &zeros)
            .unwrap();
        let report = pool.scrub(true).unwrap();
        assert!(report.copies_repaired >= 1, "{report:?}");
    }

    #[test]
    fn parity_engine_writes_are_block_aligned_on_every_path() {
        struct AlignmentChecking {
            inner: MemoryBlockDevice,
            block: u64,
        }
        impl BlockDevice for AlignmentChecking {
            fn len(&self) -> u64 {
                self.inner.len()
            }
            fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
                self.inner.read_at(offset, buf)
            }
            fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
                let wrapper = offset < crate::gpt::MEMBER_PARTITION_START
                    || offset >= self.inner.len() - 33 * 512;
                let unit = if wrapper { 512 } else { self.block };
                assert_eq!(offset % unit, 0, "unaligned write offset {offset}");
                assert_eq!(
                    data.len() as u64 % unit,
                    0,
                    "unaligned write length {} at {offset}",
                    data.len()
                );
                self.inner.write_at(offset, data)
            }
            fn flush(&self) -> Result<()> {
                self.inner.flush()
            }
        }

        let members: Vec<MemberSpec<AlignmentChecking>> = (0..4)
            .map(|i| {
                let mut geometry = geometry();
                geometry.zone_count = 16;
                MemberSpec {
                    device: AlignmentChecking {
                        inner: MemoryBlockDevice::new(crate::gpt::member_image_len(
                            geometry.capacity_bytes(),
                        ) as usize),
                        block: u64::from(geometry.logical_block_size),
                    },
                    device_id: DeviceId([0x60 + i as u8; 16]),
                    geometry,
                }
            })
            .collect();
        let params = PoolParams {
            mirror_width: 2,
            data_width: 2,
            parity_width: 1,
            ..pool_params()
        };
        let mut pool = Pool::create_multi(members, params).unwrap();
        let data: Vec<u8> = (0..150_000usize).map(|i| (i * 13 % 251) as u8).collect();
        let file = pool
            .create_file(ROOT_INODE, "data.bin", 0o644, NOW)
            .unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        pool.write(file, 3_000, &data[..10_000], NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let survivor = pool
            .create_file(ROOT_INODE, "keep.bin", 0o644, NOW)
            .unwrap();
        pool.write(survivor, 0, &data[..70_000], NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        pool.unlink(ROOT_INODE, "data.bin", NOW).unwrap();
        pool.reclaim(NOW).unwrap();
        pool.compact(NOW).unwrap();

        let runs = striped_runs(&pool, survivor);
        let target = runs[0].0;
        let slot = pool.member_slot(target.device_index).unwrap();
        let zeros = vec![0u8; 4096];
        pool.devices[slot]
            .write_at(target.offset - target.offset % 4096, &zeros)
            .unwrap();
        let report = pool.scrub(true).unwrap();
        assert!(report.copies_repaired >= 1, "{report:?}");
        assert_eq!(pool.read(survivor, 0, 70_000).unwrap(), &data[..70_000]);
    }

    #[derive(Debug)]
    struct Yankable {
        inner: MemoryBlockDevice,
        dead: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl Yankable {
        fn io_dead() -> ScaleFsError {
            ScaleFsError::Io(std::io::Error::other("yanked"))
        }
    }

    impl BlockDevice for Yankable {
        fn len(&self) -> u64 {
            self.inner.len()
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            if self.dead.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(Self::io_dead());
            }
            self.inner.read_at(offset, buf)
        }
        fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
            if self.dead.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(Self::io_dead());
            }
            self.inner.write_at(offset, data)
        }
        fn flush(&self) -> Result<()> {
            if self.dead.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(Self::io_dead());
            }
            self.inner.flush()
        }
    }

    fn yankable_pool() -> (
        Pool<Yankable>,
        Vec<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    ) {
        let switches: Vec<std::sync::Arc<std::sync::atomic::AtomicBool>> = (0..5)
            .map(|_| std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)))
            .collect();
        let members: Vec<MemberSpec<Yankable>> = (0..5)
            .map(|i| {
                let mut geometry = geometry();
                geometry.zone_count = 16;
                MemberSpec {
                    device: Yankable {
                        inner: MemoryBlockDevice::new(crate::gpt::member_image_len(
                            geometry.capacity_bytes(),
                        ) as usize),
                        dead: std::sync::Arc::clone(&switches[i]),
                    },
                    device_id: DeviceId([0x60 + i as u8; 16]),
                    geometry,
                }
            })
            .collect();
        (
            Pool::create_multi(members, mirrored_params()).unwrap(),
            switches,
        )
    }

    fn first_copy_member(pool: &Pool<Yankable>, object: u64) -> u16 {
        pool.tree()
            .range(
                MetadataKey {
                    object_id: object,
                    item_type: ITEM_FILE_EXTENT,
                    offset: 0,
                },
                MetadataKey {
                    object_id: object,
                    item_type: ITEM_FILE_EXTENT,
                    offset: u64::MAX,
                },
            )
            .iter()
            .find_map(|(_, value)| match value {
                MetadataValue::FileExtent { extents, .. } => {
                    Some(extents.first().expect("copies").device_index)
                }
                _ => None,
            })
            .expect("file has extents")
    }

    #[test]
    fn stale_members_join_the_next_commit_as_a_probe() {
        let (mut pool, switches) = yankable_pool();
        let data: Vec<u8> = (0..8_000usize).map(|i| (i % 251) as u8).collect();
        let file = pool.create_file(ROOT_INODE, "f.bin", 0o644, NOW).unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        pool.probe_staleness = std::time::Duration::ZERO;
        let before: Vec<Vec<u8>> = pool
            .devices
            .iter()
            .map(|device| device.inner().inner.bytes().to_vec())
            .collect();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        for (i, before) in before.iter().enumerate() {
            assert_ne!(
                pool.devices[i].inner().inner.bytes(),
                before.as_slice(),
                "stale member {i} was not probed"
            );
        }

        pool.probe_staleness = std::time::Duration::MAX;
        pool.write(file, 0, &data[..2_000], NOW).unwrap();
        let before: Vec<Vec<u8>> = pool
            .devices
            .iter()
            .map(|device| device.inner().inner.bytes().to_vec())
            .collect();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let untouched: Vec<usize> = (0..pool.devices.len())
            .filter(|&i| pool.devices[i].inner().inner.bytes() == before[i].as_slice())
            .collect();
        assert!(!untouched.is_empty(), "a small tx should skip someone");

        let victim = untouched[0] as u16;
        switches[usize::from(victim)].store(true, std::sync::atomic::Ordering::Relaxed);
        pool.probe_staleness = std::time::Duration::ZERO;
        let err = pool.commit(AllocPurpose::Normal, NOW).unwrap_err();
        assert!(matches!(err, ScaleFsError::Io(_)), "{err}");
    }

    #[test]
    fn io_errors_force_the_next_commit_to_probe_the_member() {
        let (mut pool, switches) = yankable_pool();
        let data: Vec<u8> = (0..20_000usize).map(|i| (i * 3 % 251) as u8).collect();
        let file = pool.create_file(ROOT_INODE, "f.bin", 0o644, NOW).unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        let victim = first_copy_member(&pool, file);
        switches[usize::from(victim)].store(true, std::sync::atomic::Ordering::Relaxed);

        assert_eq!(pool.read(file, 0, data.len()).unwrap(), data);
        assert!(
            pool.suspects.lock().unwrap().contains(&victim),
            "the failed first copy should have implicated member {victim}"
        );

        let err = pool.commit(AllocPurpose::Normal, NOW).unwrap_err();
        assert!(matches!(err, ScaleFsError::Io(_)), "{err}");
        let refused = pool.commit(AllocPurpose::Normal, NOW).unwrap_err();
        assert!(matches!(refused, ScaleFsError::Unsupported(_)), "{refused}");
    }

    #[test]
    fn transient_io_errors_clear_with_the_probing_commit() {
        let (mut pool, switches) = yankable_pool();
        let data: Vec<u8> = (0..20_000usize).map(|i| (i * 5 % 251) as u8).collect();
        let file = pool.create_file(ROOT_INODE, "f.bin", 0o644, NOW).unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        let victim = first_copy_member(&pool, file);
        switches[usize::from(victim)].store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(pool.read(file, 0, data.len()).unwrap(), data);
        assert!(pool.suspects.lock().unwrap().contains(&victim));
        switches[usize::from(victim)].store(false, std::sync::atomic::Ordering::Relaxed);

        let tx = pool.commit(AllocPurpose::Normal, NOW).unwrap();
        assert!(pool.suspects.lock().unwrap().is_empty());
        let slot = pool.member_slot(victim).unwrap();
        let superblock = decode_superblock(&read_prefix(&pool.devices[slot], 0).unwrap()).unwrap();
        let commit_extent = superblock.newest_commit.expect("committed member");
        let commit = decode_commit(
            &read_extent_from_set(std::slice::from_ref(&pool.devices[slot]), commit_extent)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(commit.tx_id, tx, "the probing commit touched the suspect");
    }

    #[test]
    fn reclaim_commits_staged_state_and_collects_orphans() {
        let mut pool = Pool::create(MemoryBlockDevice::new(device_len()), params()).unwrap();

        let staged: Vec<u8> = (0..40_000usize).map(|i| (i % 179) as u8).collect();
        let file = pool
            .create_file(ROOT_INODE, "staged.bin", 0o644, NOW)
            .unwrap();
        pool.write(file, 0, &staged, NOW).unwrap();
        let report = pool.reclaim(NOW).unwrap();
        assert_eq!(report.zones_reset, 0, "{report:?}");
        assert_eq!(pool.read(file, 0, staged.len()).unwrap(), staged);

        let free_before = pool.allocators()[0].free_usable_zone_count();
        let orphan: Vec<u8> = (0..60_000usize).map(|i| (i % 173) as u8).collect();
        let doomed = pool
            .create_file(ROOT_INODE, "orphan.bin", 0o644, NOW)
            .unwrap();
        pool.write(doomed, 0, &orphan, NOW).unwrap();
        let mut abandoned = Pool::open(pool.devices[0].inner().clone()).unwrap();
        assert!(matches!(
            abandoned.lookup(ROOT_INODE, "orphan.bin"),
            Err(ScaleFsError::NotFound)
        ));
        assert_eq!(
            abandoned.allocators()[0].free_usable_zone_count(),
            free_before,
            "abandoned writes must not occupy space after reopen"
        );
        let report = abandoned.reclaim(NOW).unwrap();
        assert_eq!(report.zones_reset, 0, "{report:?}");
        let entry = abandoned.lookup(ROOT_INODE, "staged.bin").unwrap();
        assert_eq!(
            abandoned.read(entry.inode, 0, staged.len()).unwrap(),
            staged
        );
    }

    fn mirrored_params() -> PoolParams {
        PoolParams {
            mirror_width: 2,
            ..pool_params()
        }
    }

    #[test]
    fn mirrored_pools_survive_any_single_member_loss() {
        let mut pool = Pool::create_multi(roomy_members(3), mirrored_params()).unwrap();
        let data: Vec<u8> = (0..120_000usize).map(|i| (i * 13 % 251) as u8).collect();
        let dir = pool.mkdir(ROOT_INODE, "docs", 0o755, NOW).unwrap();
        let file = pool.create_file(dir, "data.bin", 0o644, NOW).unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.snapshot_create("pin", NOW).unwrap();
        let tx = pool.committed_tx();

        let roster = pool.member_rosters().unwrap().remove(0);
        assert_eq!(roster.mirror_width, 2);
        assert_eq!(roster.metadata_root_replicas.len(), 2);
        assert_ne!(
            roster.metadata_root_replicas[0].device_index,
            roster.metadata_root_replicas[1].device_index,
        );

        let devices: Vec<_> = pool
            .devices
            .into_iter()
            .map(PartitionView::into_inner)
            .collect();
        for dropped in 0..3usize {
            let survivors: Vec<MemoryBlockDevice> = devices
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != dropped)
                .map(|(_, device)| device.clone())
                .collect();

            assert!(matches!(
                Pool::open_multi(survivors.clone()),
                Err(ScaleFsError::MissingMembers { .. })
            ));

            let mut degraded = Pool::open_multi_degraded(survivors).unwrap();
            assert!(degraded.is_degraded());
            assert!(degraded.read_only());
            assert_eq!(degraded.missing_members(), vec![dropped as u16]);
            assert_eq!(degraded.committed_tx(), tx);

            let docs = degraded.lookup(ROOT_INODE, "docs").unwrap();
            let entry = degraded.lookup(docs.inode, "data.bin").unwrap();
            assert_eq!(degraded.read(entry.inode, 0, data.len()).unwrap(), data);
            {
                let snapshot = degraded.snapshot_open("pin").unwrap();
                let docs = snapshot.lookup(ROOT_INODE, "docs").unwrap();
                let entry = snapshot.lookup(docs.inode, "data.bin").unwrap();
                assert_eq!(snapshot.read(entry.inode, 0, data.len()).unwrap(), data);
            }
            assert!(matches!(
                degraded.commit(AllocPurpose::Normal, NOW),
                Err(ScaleFsError::Unsupported(_))
            ));
        }

        assert!(matches!(
            Pool::open_multi_degraded(vec![devices[0].clone()]),
            Err(ScaleFsError::MissingMembers { .. })
        ));

        let complete = Pool::open_multi(devices).unwrap();
        assert!(!complete.read_only());
        assert!(!complete.is_degraded());
    }

    #[test]
    fn reclaim_frees_all_copies_and_degraded_reads_survive_it() {
        let mut pool = Pool::create_multi(roomy_members(3), mirrored_params()).unwrap();
        let bulk: Vec<u8> = (0..200_000usize).map(|i| (i % 187) as u8).collect();
        let goner = pool
            .create_file(ROOT_INODE, "gone.bin", 0o644, NOW)
            .unwrap();
        pool.write(goner, 0, &bulk, NOW).unwrap();
        let keep: Vec<u8> = (0..30_000usize).map(|i| (i % 181) as u8).collect();
        let keeper = pool
            .create_file(ROOT_INODE, "keep.bin", 0o644, NOW)
            .unwrap();
        pool.write(keeper, 0, &keep, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        pool.unlink(ROOT_INODE, "gone.bin", NOW).unwrap();
        let report = pool.reclaim(NOW).unwrap();
        assert!(report.zones_reset >= 2, "{report:?}");

        for dropped in 0..3usize {
            let survivors: Vec<MemoryBlockDevice> = pool
                .devices
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != dropped)
                .map(|(_, device)| device.inner().clone())
                .collect();
            let degraded = Pool::open_multi_degraded(survivors).unwrap();
            let entry = degraded.lookup(ROOT_INODE, "keep.bin").unwrap();
            assert_eq!(degraded.read(entry.inode, 0, keep.len()).unwrap(), keep);
        }
    }

    #[test]
    fn mirrored_commits_survive_crashes_and_member_loss() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicU64;

        let pool = Pool::create_multi(roomy_members(2), mirrored_params()).unwrap();
        let bases: Vec<Vec<u8>> = pool
            .devices
            .iter()
            .map(|device| device.inner().bytes().to_vec())
            .collect();

        let sequence: Arc<AtomicU64> = Arc::default();
        let recorders: Vec<RecordingBlockDevice<MemoryBlockDevice>> = pool
            .devices
            .into_iter()
            .map(|device| {
                RecordingBlockDevice::with_shared_sequence(
                    device.into_inner(),
                    Arc::clone(&sequence),
                )
            })
            .collect();
        let mut pool = Pool::open_multi(recorders).unwrap();
        let data: Vec<u8> = (0..5000usize).map(|i| (i % 240) as u8).collect();
        let file = pool.create_file(ROOT_INODE, "tx.bin", 0o644, NOW).unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        let mut schedule: Vec<(u64, usize, Op)> = Vec::new();
        for (member, device) in pool.devices.iter().enumerate() {
            for (seq, op) in device.inner().sequenced_ops() {
                schedule.push((seq, member, op.clone()));
            }
        }
        schedule.sort_by_key(|(seq, _, _)| *seq);

        let check = |pool: &Pool<MemoryBlockDevice>, prefix: usize| match pool.committed_tx() {
            1 => assert!(matches!(
                pool.lookup(ROOT_INODE, "tx.bin"),
                Err(ScaleFsError::NotFound)
            )),
            2 => {
                let entry = pool.lookup(ROOT_INODE, "tx.bin").unwrap();
                assert_eq!(pool.read(entry.inode, 0, data.len()).unwrap(), data);
            }
            other => panic!("recovered impossible transaction {other} (prefix {prefix})"),
        };

        let mut states = 0usize;
        for prefix in 0..=schedule.len() {
            let torture: Vec<TortureBlockDevice> = bases
                .iter()
                .map(|base| TortureBlockDevice::from_image(base.clone(), 4096))
                .collect();
            for (_, member, op) in &schedule[..prefix] {
                match op {
                    Op::Write { offset, data } => torture[*member].write_at(*offset, data).unwrap(),
                    Op::Flush => torture[*member].flush().unwrap(),
                }
            }
            let images: Vec<Vec<MemoryBlockDevice>> = torture
                .iter()
                .map(|device| device.all_crash_images())
                .collect();
            for a in &images[0] {
                for b in &images[1] {
                    states += 1;
                    let complete =
                        Pool::open_multi(vec![a.clone(), b.clone()]).unwrap_or_else(|err| {
                            panic!("crash state at prefix {prefix} failed to import: {err}")
                        });
                    check(&complete, prefix);

                    for lone in [a, b] {
                        let degraded = Pool::open_multi_degraded(vec![lone.clone()])
                            .unwrap_or_else(|err| {
                                panic!("degraded import at prefix {prefix} failed: {err}")
                            });
                        assert!(degraded.read_only());
                        check(&degraded, prefix);
                    }
                }
            }
        }
        assert!(states > 200, "sweep unexpectedly small: {states} states");
    }

    fn parity_params() -> PoolParams {
        PoolParams {
            mirror_width: 2,
            data_width: 3,
            parity_width: 1,
            ..pool_params()
        }
    }

    fn arc_parity_members(
        count: usize,
    ) -> (
        Vec<MemberSpec<std::sync::Arc<MemoryBlockDevice>>>,
        Vec<std::sync::Arc<MemoryBlockDevice>>,
    ) {
        let members: Vec<MemberSpec<std::sync::Arc<MemoryBlockDevice>>> = (0..count)
            .map(|i| {
                let mut geometry = geometry();
                geometry.zone_count = 16;
                MemberSpec {
                    device: std::sync::Arc::new(MemoryBlockDevice::new(
                        crate::gpt::member_image_len(geometry.capacity_bytes()) as usize,
                    )),
                    device_id: DeviceId([0x30 + i as u8; 16]),
                    geometry,
                }
            })
            .collect();
        let handles = members
            .iter()
            .map(|member| std::sync::Arc::clone(&member.device))
            .collect();
        (members, handles)
    }

    #[test]
    fn scrub_heals_a_corrupt_piece_on_a_degraded_stripe() {
        let (members, handles) = arc_parity_members(4);
        let params = PoolParams {
            mirror_width: 3,
            data_width: 2,
            parity_width: 2,
            ..pool_params()
        };
        let mut pool = Pool::create_multi(members, params).unwrap();
        let file = pool
            .create_file(crate::tree::ROOT_INODE, "f", 0o644, NOW)
            .unwrap();
        let chunk = crate::fs::FILE_DATA_CHUNK;
        let data: Vec<u8> = (0..2 * chunk).map(|i| (i % 251) as u8).collect();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let runs = striped_runs(&pool, file);
        assert_eq!(runs.len(), 2, "one full K'=2 stripe");
        let corrupt_piece = runs[0].0;
        let absent_member = runs[1].0.device_index;
        drop(pool);

        let zeros = vec![0u8; corrupt_piece.length as usize];
        handles[corrupt_piece.device_index as usize]
            .write_at(
                crate::gpt::MEMBER_PARTITION_START + corrupt_piece.offset,
                &zeros,
            )
            .unwrap();
        let present: Vec<std::sync::Arc<MemoryBlockDevice>> = handles
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != absent_member as usize)
            .map(|(_, handle)| std::sync::Arc::clone(handle))
            .collect();
        let mut degraded = Pool::open_multi_degraded(present).unwrap();

        let report = degraded.scrub(true).unwrap();
        assert_eq!(
            report.copies_unrepairable, 0,
            "two losses within P=2 are repairable, not hopeless"
        );
        assert!(
            report.copies_repaired >= 1,
            "the corrupt present piece heals in place"
        );
        assert_eq!(
            degraded.read(file, 0, 2 * chunk).unwrap(),
            data,
            "healed stripe serves the original bytes"
        );
    }

    #[test]
    fn unreadable_descriptors_fail_replace_reference_collection() {
        let (members, handles) = arc_parity_members(4);
        let mut pool = Pool::create_multi(members, parity_params()).unwrap();
        let file = pool
            .create_file(crate::tree::ROOT_INODE, "f", 0o644, NOW)
            .unwrap();
        let chunk = crate::fs::FILE_DATA_CHUNK;
        let data: Vec<u8> = (0..3 * chunk).map(|i| (i % 249) as u8).collect();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let runs = striped_runs(&pool, file);
        let parity = runs[0].1[0];
        let data_member = runs[0].0.device_index;

        let zeros = vec![0u8; parity.length as usize];
        handles[parity.device_index as usize]
            .write_at(crate::gpt::MEMBER_PARTITION_START + parity.offset, &zeros)
            .unwrap();

        let refused = pool.references_onto_member(data_member).unwrap_err();
        assert!(
            matches!(refused, ScaleFsError::Corrupt(msg) if msg.contains("no readable parity")),
            "reference collection fails closed on an unreadable descriptor"
        );
    }

    #[test]
    fn same_tx_roster_ties_resolve_by_generation() {
        let roster = |generation: u64| Topology {
            tx_id: 9,
            topology_generation: generation,
            data_width: 1,
            parity_width: 0,
            mirror_width: 2,
            members: Vec::new(),
            metadata_root_replicas: Vec::new(),
        };
        for supply in [[1u64, 2], [2, 1]] {
            let mut views: Vec<Topology> = supply.iter().map(|g| roster(*g)).collect();
            Pool::<MemoryBlockDevice>::order_candidate_views(&mut views);
            assert_eq!(views.len(), 1, "one view per tx after dedup");
            assert_eq!(
                views[0].topology_generation, 2,
                "the higher generation wins the tie for supply order {supply:?}"
            );
        }
    }

    #[test]
    fn a_panicking_device_concludes_the_ticket() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        struct PanicOnWrite {
            inner: MemoryBlockDevice,
            armed: AtomicBool,
        }
        impl BlockDevice for PanicOnWrite {
            fn len(&self) -> u64 {
                self.inner.len()
            }
            fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
                self.inner.read_at(offset, buf)
            }
            fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
                if self.armed.load(Ordering::Relaxed) {
                    panic!("armed device panic");
                }
                self.inner.write_at(offset, data)
            }
            fn flush(&self) -> Result<()> {
                self.inner.flush()
            }
        }

        let device = Arc::new(PanicOnWrite {
            inner: MemoryBlockDevice::new(device_len()),
            armed: AtomicBool::new(false),
        });
        let mut pool = Pool::create(Arc::clone(&device), params()).unwrap();
        add_test_file(&mut pool);

        let ticket = pool.commit_plan(AllocPurpose::Normal, NOW).unwrap();
        device.armed.store(true, Ordering::Relaxed);
        let aborted = ticket
            .execute()
            .expect_err("an armed panic must conclude as an error");
        assert!(matches!(aborted.error(), ScaleFsError::Io(_)));
        let error = pool
            .commit_abandon(aborted)
            .expect_err("no redundancy: wounded");
        assert!(matches!(error, ScaleFsError::Io(_)));
        assert!(pool.wounded);

        device.armed.store(false, Ordering::Relaxed);
        let refused = pool.commit(AllocPurpose::Normal, NOW).unwrap_err();
        assert!(
            matches!(refused, ScaleFsError::Unsupported(msg) if msg.contains("reopen")),
            "the wounded refusal, never the in-flight strand"
        );
    }

    fn fault_members(
        count: usize,
    ) -> (
        Vec<MemberSpec<crate::torture::FaultDevice>>,
        Vec<crate::torture::FaultSwitch>,
    ) {
        let mut switches = Vec::new();
        let members = (0..count)
            .map(|i| {
                let mut geometry = geometry();
                geometry.zone_count = 16;
                let device = crate::torture::FaultDevice::new(crate::gpt::member_image_len(
                    geometry.capacity_bytes(),
                ) as usize);
                switches.push(device.switch());
                MemberSpec {
                    device,
                    device_id: DeviceId([0x50 + i as u8; 16]),
                    geometry,
                }
            })
            .collect();
        (members, switches)
    }

    #[test]
    fn a_member_dying_before_the_commit_degrades_the_pool_and_keeps_the_writes() {
        let (members, switches) = fault_members(2);
        let backings: Vec<_> = members.iter().map(|m| m.device.backing()).collect();
        let mut pool = Pool::create_multi(members, mirrored_params()).unwrap();
        let payload: Vec<u8> = (0..70_000usize).map(|i| (i % 251) as u8).collect();
        let file = pool.create_file(ROOT_INODE, "ack.bin", 0o644, NOW).unwrap();
        pool.write(file, 0, &payload, NOW).unwrap();
        let before = pool.committed_tx();

        switches[1].fail();
        let outcome = pool
            .commit_or_degrade(AllocPurpose::Normal, NOW)
            .expect("the commit lands on the survivor");
        let CommitOutcome::Degraded(degrade) = outcome else {
            panic!("expected a live degrade, got {outcome:?}");
        };
        assert_eq!(degrade.member, 1);
        assert_eq!(degrade.device_id, DeviceId([0x51; 16]));
        assert!(degrade.tx_id > before);
        assert_eq!(pool.committed_tx(), degrade.tx_id);
        assert!(!pool.wounded, "a recovered commit is not a wound");
        assert!(pool.is_degraded());
        assert_eq!(pool.missing_members(), vec![1]);
        assert!(pool.read_only());
        assert_eq!(pool.live_degrade(), Some(&degrade));
        assert_ne!(
            pool.superblock().feature_incompat & FEATURE_INCOMPAT_THIN_METADATA,
            0
        );
        assert_eq!(pool.read(file, 0, payload.len()).unwrap(), payload);
        let refused = pool.write(file, 0, b"more", NOW).unwrap_err();
        assert!(
            matches!(refused, ScaleFsError::Unsupported(msg) if msg.contains("read-only")),
            "{refused:?}"
        );

        drop(pool);
        let survivor = crate::torture::FaultDevice::over(std::sync::Arc::clone(&backings[0]));
        let reopened = Pool::open_multi_degraded(vec![survivor]).unwrap();
        assert_eq!(reopened.committed_tx(), degrade.tx_id);
        assert!(reopened.is_degraded());
        let entry = dirent::lookup_entry(
            reopened.tree(),
            SEED,
            reopened.superblock().unicode_version,
            reopened.superblock().case_sensitivity,
            ROOT_INODE,
            "ack.bin",
        )
        .expect("the write survived");
        assert_eq!(
            reopened.read(entry.inode, 0, payload.len()).unwrap(),
            payload
        );
        drop(reopened);

        let both: Vec<_> = backings
            .iter()
            .map(|b| crate::torture::FaultDevice::over(std::sync::Arc::clone(b)))
            .collect();
        let mut whole = Pool::open_multi(both).unwrap();
        assert_eq!(whole.committed_tx(), degrade.tx_id);
        assert!(!whole.is_degraded());
        assert!(!whole.read_only());
        assert_ne!(
            whole.superblock().feature_incompat & FEATURE_INCOMPAT_THIN_METADATA,
            0,
            "the thin roster is still the newest view"
        );
        let entry = dirent::lookup_entry(
            whole.tree(),
            SEED,
            whole.superblock().unicode_version,
            whole.superblock().case_sensitivity,
            ROOT_INODE,
            "ack.bin",
        )
        .expect("the write is in the newest view");
        assert_eq!(whole.read(entry.inode, 0, payload.len()).unwrap(), payload);
        add_test_file(&mut whole);
        whole.commit(AllocPurpose::Normal, NOW).unwrap();
        for superblock in whole.superblocks() {
            assert_eq!(
                superblock.feature_incompat & FEATURE_INCOMPAT_THIN_METADATA,
                0
            );
        }
    }

    #[test]
    fn a_transient_write_failure_is_retried_before_any_degrade() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Clone)]
        struct Flaky {
            inner: Arc<MemoryBlockDevice>,
            remaining: Arc<AtomicUsize>,
        }
        impl BlockDevice for Flaky {
            fn len(&self) -> u64 {
                self.inner.len()
            }
            fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
                self.inner.read_at(offset, buf)
            }
            fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
                let left = self.remaining.load(Ordering::SeqCst);
                if left > 0 {
                    self.remaining.store(left - 1, Ordering::SeqCst);
                    return Err(ScaleFsError::Io(std::io::Error::other("flaky write")));
                }
                self.inner.write_at(offset, data)
            }
            fn flush(&self) -> Result<()> {
                self.inner.flush()
            }
        }
        let mut geometry = geometry();
        geometry.zone_count = 16;
        let len = crate::gpt::member_image_len(geometry.capacity_bytes()) as usize;
        let flake = Arc::new(AtomicUsize::new(0));
        let members = vec![
            MemberSpec {
                device: Flaky {
                    inner: Arc::new(MemoryBlockDevice::new(len)),
                    remaining: Arc::new(AtomicUsize::new(0)),
                },
                device_id: DeviceId([0x60; 16]),
                geometry,
            },
            MemberSpec {
                device: Flaky {
                    inner: Arc::new(MemoryBlockDevice::new(len)),
                    remaining: Arc::clone(&flake),
                },
                device_id: DeviceId([0x61; 16]),
                geometry,
            },
        ];
        let mut pool = Pool::create_multi(members, mirrored_params()).unwrap();
        add_test_file(&mut pool);
        flake.store(1, Ordering::SeqCst);
        let outcome = pool.commit_or_degrade(AllocPurpose::Normal, NOW).unwrap();
        assert!(
            matches!(outcome, CommitOutcome::Committed { .. }),
            "a transient failure commits whole after one retry, got {outcome:?}"
        );
        assert!(!pool.is_degraded());
        assert!(!pool.read_only());
        assert!(!pool.wounded);
        assert!(pool.live_degrade().is_none());
        assert_eq!(
            flake.load(Ordering::SeqCst),
            0,
            "the one failure was consumed"
        );
        assert!(lookup_test_file(&pool).is_some());
    }

    #[test]
    fn a_live_degraded_pool_is_healed_by_replace_and_rebuild() {
        let (members, switches) = fault_members(3);
        let mut pool = Pool::create_multi(members, mirrored_params()).unwrap();
        let payload: Vec<u8> = (0..40_000usize).map(|i| (i % 199) as u8).collect();
        let file = pool
            .create_file(ROOT_INODE, "keep.bin", 0o644, NOW)
            .unwrap();
        pool.write(file, 0, &payload, NOW).unwrap();
        switches[2].fail();
        let outcome = pool.commit_or_degrade(AllocPurpose::Normal, NOW).unwrap();
        assert!(matches!(
            outcome,
            CommitOutcome::Degraded(LiveDegrade { member: 2, .. })
        ));
        assert!(pool.read_only());
        assert_eq!(pool.missing_members(), vec![2]);
        assert_eq!(
            pool.superblock().feature_incompat & FEATURE_INCOMPAT_THIN_METADATA,
            0
        );
        assert_eq!(pool.read(file, 0, payload.len()).unwrap(), payload);

        let again = pool.commit_or_degrade(AllocPurpose::Normal, NOW);
        assert!(
            matches!(again, Err(ScaleFsError::Unsupported(msg)) if msg.contains("read-only")),
            "{again:?}"
        );
        assert!(!pool.wounded);

        let mut geometry = geometry();
        geometry.zone_count = 16;
        let fresh = crate::torture::FaultDevice::new(crate::gpt::member_image_len(
            geometry.capacity_bytes(),
        ) as usize);
        pool.replace_member(
            2,
            MemberSpec {
                device: fresh,
                device_id: DeviceId([0x70; 16]),
                geometry,
            },
            NOW,
        )
        .unwrap();
        assert!(!pool.read_only());
        assert!(!pool.is_degraded());
        let report = pool.rebuild(NOW).unwrap();
        assert!(
            report.copies_written > 0,
            "the dead member's copies are re-mirrored"
        );
        assert_eq!(pool.read(file, 0, payload.len()).unwrap(), payload);
        pool.write(file, 0, b"after heal", NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
    }

    #[test]
    fn a_failure_beyond_the_protection_policy_still_wounds() {
        let (members, switches) = fault_members(3);
        let mut pool = Pool::create_multi(members, mirrored_params()).unwrap();
        add_test_file(&mut pool);
        switches[1].fail();
        switches[2].fail();
        let error = pool
            .commit_or_degrade(AllocPurpose::Normal, NOW)
            .expect_err("two of three mirror-2 members gone exceeds the policy");
        assert!(matches!(error, ScaleFsError::Io(_)), "{error:?}");
        assert!(pool.wounded);
        assert!(pool.live_degrade().is_none());
        let refused = pool.commit(AllocPurpose::Normal, NOW).unwrap_err();
        assert!(matches!(refused, ScaleFsError::Unsupported(msg) if msg.contains("reopen")));
    }

    #[test]
    fn a_full_member_cannot_wedge_commits_with_its_probe() {
        let mut pool = Pool::create_multi(roomy_members(2), pool_params()).unwrap();
        loop {
            match pool.allocators[0].allocate(ZoneClass::Metadata, 65536, AllocPurpose::Normal) {
                Ok(_) => {}
                Err(ScaleFsError::OutOfSpace) => break,
                Err(other) => panic!("unexpected allocator error: {other}"),
            }
        }
        pool.probe_staleness = std::time::Duration::ZERO;
        add_test_file(&mut pool);
        pool.commit(AllocPurpose::Normal, NOW)
            .expect("a full member's unanswerable probe must not wedge the commit");

        pool.suspects.lock().unwrap().insert(0);
        pool.commit(AllocPurpose::Normal, NOW)
            .expect("a full suspect drops out; the commit proceeds");
        assert!(
            pool.suspects.lock().unwrap().contains(&0),
            "the unanswerable suspect probe stays armed for retry"
        );

        let tx = pool.committed_tx();
        let devices: Vec<MemoryBlockDevice> = pool
            .devices
            .drain(..)
            .map(PartitionView::into_inner)
            .collect();
        let reopened = Pool::open_multi(devices).unwrap();
        assert_eq!(reopened.committed_tx(), tx);
        assert!(lookup_test_file(&reopened).is_some());
    }

    #[test]
    fn a_failed_striped_overwrite_leaves_the_old_bytes() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicI64, Ordering};

        struct FailAfter {
            inner: MemoryBlockDevice,
            allow: AtomicI64,
        }
        impl BlockDevice for FailAfter {
            fn len(&self) -> u64 {
                self.inner.len()
            }
            fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
                self.inner.read_at(offset, buf)
            }
            fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
                if self.allow.fetch_sub(1, Ordering::Relaxed) <= 0 {
                    return Err(ScaleFsError::Io(std::io::Error::other("armed failure")));
                }
                self.inner.write_at(offset, data)
            }
            fn flush(&self) -> Result<()> {
                self.inner.flush()
            }
        }

        let members: Vec<MemberSpec<Arc<FailAfter>>> = (0..4)
            .map(|i| {
                let mut geometry = geometry();
                geometry.zone_count = 16;
                MemberSpec {
                    device: Arc::new(FailAfter {
                        inner: MemoryBlockDevice::new(crate::gpt::member_image_len(
                            geometry.capacity_bytes(),
                        ) as usize),
                        allow: AtomicI64::new(i64::MAX),
                    }),
                    device_id: DeviceId([0x30 + i as u8; 16]),
                    geometry,
                }
            })
            .collect();
        let handles: Vec<Arc<FailAfter>> = members
            .iter()
            .map(|member| Arc::clone(&member.device))
            .collect();
        let mut pool = Pool::create_multi(members, parity_params()).unwrap();
        let file = pool
            .create_file(crate::tree::ROOT_INODE, "f", 0o644, NOW)
            .unwrap();
        let chunk = crate::fs::FILE_DATA_CHUNK;
        let old: Vec<u8> = (0..3 * chunk).map(|i| (i % 251) as u8).collect();
        pool.write(file, 0, &old, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        handles[2].allow.store(0, Ordering::Relaxed);
        let new: Vec<u8> = (0..3 * chunk).map(|i| (i % 249) as u8).collect();
        assert!(pool.write(file, 0, &new, NOW).is_err());
        handles[2].allow.store(i64::MAX, Ordering::Relaxed);

        assert_eq!(pool.read(file, 0, 3 * chunk).unwrap(), old);
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        assert_eq!(pool.read(file, 0, 3 * chunk).unwrap(), old);
    }

    fn striped_runs<D: BlockDevice>(pool: &Pool<D>, object: u64) -> Vec<(Extent, Vec<Extent>)> {
        pool.tree()
            .range(
                MetadataKey {
                    object_id: object,
                    item_type: ITEM_FILE_EXTENT,
                    offset: 0,
                },
                MetadataKey {
                    object_id: object,
                    item_type: ITEM_FILE_EXTENT,
                    offset: u64::MAX,
                },
            )
            .iter()
            .filter_map(|(_, value)| match value {
                MetadataValue::StripedExtent {
                    extent,
                    parity_extents,
                    ..
                } => Some((*extent, parity_extents.clone())),
                _ => None,
            })
            .collect()
    }

    fn zone_class_of(pool: &Pool<MemoryBlockDevice>, extent: &Extent) -> Option<ZoneClass> {
        let allocator = pool.allocator_for_member(extent.device_index).unwrap();
        allocator
            .zone(extent.offset / allocator.geometry().zone_size)
            .unwrap()
            .class
    }

    #[test]
    fn parity_pools_stripe_writes_and_read_back() {
        let chunk = crate::fs::FILE_DATA_CHUNK;
        let mut pool = Pool::create_multi(roomy_members(5), parity_params()).unwrap();
        for superblock in pool.superblocks() {
            assert_eq!(
                superblock.feature_incompat,
                FEATURE_INCOMPAT_MULTI_DEVICE | FEATURE_INCOMPAT_PARITY
            );
        }

        let data: Vec<u8> = (0..chunk * 3 + 5000).map(|i| (i * 7 % 251) as u8).collect();
        let file = pool.create_file(ROOT_INODE, "big.bin", 0o644, NOW).unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        let small = pool
            .create_file(ROOT_INODE, "small.bin", 0o644, NOW)
            .unwrap();
        pool.write(small, 0, b"tiny stripe", NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        let runs = striped_runs(&pool, file);
        assert_eq!(runs.len(), 4);
        assert_eq!(runs[0].1, runs[1].1, "one stripe shares parity");
        assert_eq!(runs[0].1, runs[2].1);
        assert_ne!(runs[0].1, runs[3].1, "the tail is its own stripe");
        assert_eq!(runs[0].1.len(), 1);
        for (extent, parity) in &runs {
            assert_eq!(zone_class_of(&pool, extent), Some(ZoneClass::Data));
            for piece in parity {
                assert_eq!(zone_class_of(&pool, piece), Some(ZoneClass::Parity));
            }
        }
        let mut members: Vec<u16> = runs[..3]
            .iter()
            .map(|(extent, _)| extent.device_index)
            .chain(runs[0].1.iter().map(|piece| piece.device_index))
            .collect();
        members.sort_unstable();
        members.dedup();
        assert_eq!(members.len(), 4, "3 data + 1 parity on distinct members");

        assert_eq!(pool.read(file, 0, data.len()).unwrap(), data);
        let mut reopened = Pool::open_multi(
            pool.devices
                .into_iter()
                .map(PartitionView::into_inner)
                .collect(),
        )
        .unwrap();
        assert_eq!(reopened.parity_width(), 1);
        assert_eq!(reopened.data_width(), 3);
        let entry = reopened.lookup(ROOT_INODE, "big.bin").unwrap();
        assert_eq!(reopened.read(entry.inode, 0, data.len()).unwrap(), data);
        let small_entry = reopened.lookup(ROOT_INODE, "small.bin").unwrap();
        assert_eq!(
            reopened.read(small_entry.inode, 0, 100).unwrap(),
            b"tiny stripe"
        );

        let fresh: Vec<u8> = (0..1000).map(|i| (i * 3 % 251) as u8).collect();
        reopened.write(entry.inode, 100, &fresh, NOW).unwrap();
        let mut expect = data.clone();
        expect[100..1100].copy_from_slice(&fresh);
        assert_eq!(reopened.read(entry.inode, 0, expect.len()).unwrap(), expect);
        reopened.commit(AllocPurpose::Normal, NOW).unwrap();
        let again = Pool::open_multi(
            reopened
                .devices
                .into_iter()
                .map(PartitionView::into_inner)
                .collect(),
        )
        .unwrap();
        let entry = again.lookup(ROOT_INODE, "big.bin").unwrap();
        assert_eq!(again.read(entry.inode, 0, expect.len()).unwrap(), expect);
    }

    #[test]
    fn parity_creation_validates_widths() {
        let bad = [
            PoolParams {
                mirror_width: 1,
                data_width: 2,
                parity_width: 1,
                ..pool_params()
            },
            PoolParams {
                mirror_width: 2,
                data_width: 1,
                parity_width: 1,
                ..pool_params()
            },
            PoolParams {
                mirror_width: 2,
                data_width: 2,
                parity_width: 0,
                ..pool_params()
            },
            PoolParams {
                mirror_width: 2,
                data_width: 65,
                parity_width: 1,
                ..pool_params()
            },
        ];
        for params in bad {
            assert!(
                matches!(
                    Pool::create_multi(roomy_members(3), params.clone()),
                    Err(ScaleFsError::InvalidArgument(_))
                ),
                "{params:?}"
            );
        }
    }

    #[test]
    fn parity_pools_survive_any_single_member_loss() {
        let mut pool = Pool::create_multi(roomy_members(5), parity_params()).unwrap();
        let data: Vec<u8> = (0..200_000usize).map(|i| (i * 13 % 251) as u8).collect();
        let file = pool
            .create_file(ROOT_INODE, "keep.bin", 0o644, NOW)
            .unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.snapshot_create("pin", NOW).unwrap();

        let devices: Vec<_> = pool
            .devices
            .into_iter()
            .map(PartitionView::into_inner)
            .collect();
        for absent in 0..devices.len() {
            let survivors: Vec<MemoryBlockDevice> = devices
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != absent)
                .map(|(_, device)| device.clone())
                .collect();
            let mut degraded = Pool::open_multi_degraded(survivors).unwrap();
            assert!(degraded.is_degraded());
            assert!(degraded.read_only());
            let entry = degraded.lookup(ROOT_INODE, "keep.bin").unwrap();
            assert_eq!(
                degraded.read(entry.inode, 0, data.len()).unwrap(),
                data,
                "absent member {absent}"
            );
            let snapshot = degraded.snapshot_open("pin").unwrap();
            assert_eq!(snapshot.read(entry.inode, 0, data.len()).unwrap(), data);
            assert!(matches!(
                degraded.write(entry.inode, 0, b"x", NOW),
                Err(ScaleFsError::Unsupported(_))
            ));
        }

        let two_gone: Vec<MemoryBlockDevice> = devices.iter().skip(2).cloned().collect();
        assert!(matches!(
            Pool::open_multi(two_gone.clone()),
            Err(ScaleFsError::MissingMembers { .. })
        ));
        assert!(matches!(
            Pool::open_multi_degraded(two_gone),
            Err(ScaleFsError::MissingMembers { .. })
        ));
    }

    #[test]
    fn double_parity_survives_any_pair_loss() {
        let params = PoolParams {
            mirror_width: 3,
            data_width: 2,
            parity_width: 2,
            ..pool_params()
        };
        let mut pool = Pool::create_multi(roomy_members(5), params).unwrap();
        let data: Vec<u8> = (0..150_000usize).map(|i| (i * 17 % 251) as u8).collect();
        let file = pool
            .create_file(ROOT_INODE, "dual.bin", 0o644, NOW)
            .unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        let devices: Vec<_> = pool
            .devices
            .into_iter()
            .map(PartitionView::into_inner)
            .collect();
        for a in 0..devices.len() {
            for b in a + 1..devices.len() {
                let survivors: Vec<MemoryBlockDevice> = devices
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| *index != a && *index != b)
                    .map(|(_, device)| device.clone())
                    .collect();
                let degraded = Pool::open_multi_degraded(survivors).unwrap();
                let entry = degraded.lookup(ROOT_INODE, "dual.bin").unwrap();
                assert_eq!(
                    degraded.read(entry.inode, 0, data.len()).unwrap(),
                    data,
                    "absent members {a} and {b}"
                );
            }
        }
    }

    #[test]
    fn corrupt_stripe_pieces_reconstruct_on_read() {
        let chunk = crate::fs::FILE_DATA_CHUNK;
        let mut pool = Pool::create_multi(roomy_members(5), parity_params()).unwrap();
        let data: Vec<u8> = (0..chunk * 3 + 5000)
            .map(|i| (i * 19 % 251) as u8)
            .collect();
        let file = pool
            .create_file(ROOT_INODE, "heal.bin", 0o644, NOW)
            .unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        let runs = striped_runs(&pool, file);
        corrupt_copy(&mut pool, runs[0].0);
        assert_eq!(pool.read(file, 0, data.len()).unwrap(), data);

        corrupt_copy(&mut pool, runs[3].0);
        corrupt_copy(&mut pool, runs[3].1[0]);
        assert!(pool.read(file, (3 * chunk) as u64, 100).is_err());
        assert_eq!(pool.read(file, 0, chunk).unwrap(), &data[..chunk]);
    }

    #[test]
    fn reclaim_keeps_stripe_siblings_for_reconstruction() {
        let chunk = crate::fs::FILE_DATA_CHUNK;
        let mut pool = Pool::create_multi(roomy_members(5), parity_params()).unwrap();
        let data: Vec<u8> = (0..2 * chunk).map(|i| (i * 23 % 251) as u8).collect();
        let file = pool.create_file(ROOT_INODE, "pin.bin", 0o644, NOW).unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let runs = striped_runs(&pool, file);
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].1, runs[1].1, "both chunks share one stripe");

        pool.truncate(file, chunk as u64, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        pool.reclaim(NOW).unwrap();
        assert_eq!(pool.read(file, 0, chunk).unwrap(), &data[..chunk]);

        let survivor_member = usize::from(runs[0].0.device_index);
        let devices: Vec<_> = pool
            .devices
            .into_iter()
            .map(PartitionView::into_inner)
            .collect();
        let survivors: Vec<MemoryBlockDevice> = devices
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != survivor_member)
            .map(|(_, device)| device.clone())
            .collect();
        let degraded = Pool::open_multi_degraded(survivors).unwrap();
        let entry = degraded.lookup(ROOT_INODE, "pin.bin").unwrap();
        assert_eq!(
            degraded.read(entry.inode, 0, chunk).unwrap(),
            &data[..chunk]
        );
    }

    #[test]
    fn mirror_pools_write_no_parity_material() {
        let mut pool = Pool::create_multi(roomy_members(3), mirrored_params()).unwrap();
        let data: Vec<u8> = (0..80_000usize).map(|i| (i * 29 % 251) as u8).collect();
        let file = pool
            .create_file(ROOT_INODE, "plain.bin", 0o644, NOW)
            .unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.snapshot_create("pin", NOW).unwrap();

        for superblock in pool.superblocks() {
            assert_eq!(superblock.feature_incompat, FEATURE_INCOMPAT_MULTI_DEVICE);
        }
        for allocator in pool.allocators() {
            assert!(
                allocator
                    .zones()
                    .all(|zone| zone.class != Some(ZoneClass::Parity))
            );
        }
        assert!(
            pool.tree()
                .range(MetadataKey::MIN, MetadataKey::MAX)
                .iter()
                .all(|(_, value)| !matches!(value, MetadataValue::StripedExtent { .. }))
        );
    }

    #[test]
    fn compact_merges_short_and_partial_stripes() {
        let chunk = crate::fs::FILE_DATA_CHUNK;
        let mut pool = Pool::create_multi(roomy_members(5), parity_params()).unwrap();
        let small_a: Vec<u8> = (0..700usize).map(|i| (i * 3 % 251) as u8).collect();
        let small_b: Vec<u8> = (0..900usize).map(|i| (i * 5 % 251) as u8).collect();
        let big: Vec<u8> = (0..2 * chunk).map(|i| (i * 7 % 251) as u8).collect();
        let a = pool.create_file(ROOT_INODE, "a", 0o644, NOW).unwrap();
        pool.write(a, 0, &small_a, NOW).unwrap();
        let b = pool.create_file(ROOT_INODE, "b", 0o644, NOW).unwrap();
        pool.write(b, 0, &small_b, NOW).unwrap();
        let c = pool.create_file(ROOT_INODE, "c", 0o644, NOW).unwrap();
        pool.write(c, 0, &big, NOW).unwrap();
        pool.truncate(c, chunk as u64, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let before = striped_runs(&pool, a)[0].1.clone();

        let report = pool.compact(NOW).unwrap();
        assert_eq!(report.stripes_compacted, 3, "{report:?}");
        assert_eq!(report.records_rewritten, 3);

        let runs_a = striped_runs(&pool, a);
        let runs_b = striped_runs(&pool, b);
        let runs_c = striped_runs(&pool, c);
        assert_eq!(runs_a[0].1, runs_b[0].1, "one merged stripe");
        assert_eq!(runs_a[0].1, runs_c[0].1);
        assert_ne!(runs_a[0].1, before);
        assert_eq!(pool.read(a, 0, small_a.len()).unwrap(), small_a);
        assert_eq!(pool.read(b, 0, small_b.len()).unwrap(), small_b);
        assert_eq!(pool.read(c, 0, chunk).unwrap(), &big[..chunk]);
        assert!(pool.scrub(false).unwrap().healthy());

        let devices: Vec<_> = pool
            .devices
            .into_iter()
            .map(PartitionView::into_inner)
            .collect();
        for absent in 0..devices.len() {
            let survivors: Vec<MemoryBlockDevice> = devices
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != absent)
                .map(|(_, device)| device.clone())
                .collect();
            let degraded = Pool::open_multi_degraded(survivors).unwrap();
            let entry = degraded.lookup(ROOT_INODE, "a").unwrap();
            assert_eq!(
                degraded.read(entry.inode, 0, small_a.len()).unwrap(),
                small_a,
                "absent device {absent}"
            );
        }
    }

    #[test]
    fn compact_leaves_snapshot_pinned_stripes() {
        let chunk = crate::fs::FILE_DATA_CHUNK;
        let mut pool = Pool::create_multi(roomy_members(5), parity_params()).unwrap();
        let data: Vec<u8> = (0..2 * chunk).map(|i| (i * 11 % 251) as u8).collect();
        let file = pool.create_file(ROOT_INODE, "pinned", 0o644, NOW).unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.snapshot_create("pin", NOW).unwrap();
        pool.truncate(file, chunk as u64, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let before = striped_runs(&pool, file)[0].1.clone();

        let report = pool.compact(NOW).unwrap();
        assert_eq!(report.stripes_compacted, 0, "{report:?}");
        assert_eq!(striped_runs(&pool, file)[0].1, before);
        assert_eq!(pool.read(file, 0, chunk).unwrap(), &data[..chunk]);
        let snapshot = pool.snapshot_open("pin").unwrap();
        assert_eq!(snapshot.read(file, 0, data.len()).unwrap(), data);

        let mut mirror = Pool::create_multi(roomy_members(3), mirrored_params()).unwrap();
        assert!(matches!(
            mirror.compact(NOW),
            Err(ScaleFsError::Unsupported(_))
        ));
    }

    #[test]
    fn replace_and_rebuild_heals_parity_pools() {
        let chunk = crate::fs::FILE_DATA_CHUNK;
        let mut pool = Pool::create_multi(roomy_members(5), parity_params()).unwrap();
        let data: Vec<u8> = (0..chunk * 3 + 5000).map(|i| (i * 7 % 251) as u8).collect();
        let file = pool
            .create_file(ROOT_INODE, "keep.bin", 0o644, NOW)
            .unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.snapshot_create("pin", NOW).unwrap();

        let victim = striped_runs(&pool, file)[0].0.device_index;
        let devices: Vec<_> = pool
            .devices
            .into_iter()
            .map(PartitionView::into_inner)
            .collect();
        let survivors: Vec<MemoryBlockDevice> = devices
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != usize::from(victim))
            .map(|(_, device)| device.clone())
            .collect();
        let mut degraded = Pool::open_multi_degraded(survivors).unwrap();
        assert!(degraded.is_degraded());

        let mut geometry = geometry();
        geometry.zone_count = 16;
        degraded
            .replace_member(
                victim,
                MemberSpec {
                    device: MemoryBlockDevice::new(crate::gpt::member_image_len(
                        geometry.capacity_bytes(),
                    ) as usize),
                    device_id: DeviceId([0x99; 16]),
                    geometry,
                },
                NOW,
            )
            .unwrap();
        assert!(!degraded.read_only());
        let report = degraded.rebuild(NOW).unwrap();
        assert!(report.records_rebuilt > 0, "{report:?}");
        assert!(report.copies_written > 0);

        let entry = degraded.lookup(ROOT_INODE, "keep.bin").unwrap();
        assert_eq!(degraded.read(entry.inode, 0, data.len()).unwrap(), data);
        let snapshot = degraded.snapshot_open("pin").unwrap();
        assert_eq!(snapshot.read(entry.inode, 0, data.len()).unwrap(), data);
        assert!(degraded.scrub(false).unwrap().healthy());

        let healed_devices = degraded.devices;
        for absent in 0..healed_devices.len() {
            let survivors: Vec<MemoryBlockDevice> = healed_devices
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != absent)
                .map(|(_, device)| device.inner().clone())
                .collect();
            let again = Pool::open_multi_degraded(survivors).unwrap();
            let entry = again.lookup(ROOT_INODE, "keep.bin").unwrap();
            assert_eq!(
                again.read(entry.inode, 0, data.len()).unwrap(),
                data,
                "absent device {absent}"
            );
        }
    }

    #[test]
    fn remove_member_evacuates_parity_stripes() {
        let chunk = crate::fs::FILE_DATA_CHUNK;
        let mut pool = Pool::create_multi(roomy_members(5), parity_params()).unwrap();
        let data: Vec<u8> = (0..chunk * 2 + 900).map(|i| (i * 19 % 251) as u8).collect();
        let file = pool
            .create_file(ROOT_INODE, "move.bin", 0o644, NOW)
            .unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        let victim = striped_runs(&pool, file)[0].0.device_index;
        let freed = pool.remove_member(victim, NOW).unwrap();
        drop(freed);
        assert!(pool.missing_members().is_empty());
        assert_eq!(pool.devices.len(), 4);
        assert_eq!(pool.read(file, 0, data.len()).unwrap(), data);
        assert!(pool.scrub(false).unwrap().healthy());

        let devices: Vec<_> = pool
            .devices
            .into_iter()
            .map(PartitionView::into_inner)
            .collect();
        let reopened = Pool::open_multi(devices.clone()).unwrap();
        let entry = reopened.lookup(ROOT_INODE, "move.bin").unwrap();
        assert_eq!(reopened.read(entry.inode, 0, data.len()).unwrap(), data);
        for absent in 0..devices.len() {
            let survivors: Vec<MemoryBlockDevice> = devices
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != absent)
                .map(|(_, device)| device.clone())
                .collect();
            let degraded = Pool::open_multi_degraded(survivors).unwrap();
            let entry = degraded.lookup(ROOT_INODE, "move.bin").unwrap();
            assert_eq!(
                degraded.read(entry.inode, 0, data.len()).unwrap(),
                data,
                "absent device {absent}"
            );
        }
    }

    #[test]
    fn parity_rebuild_is_crash_consistent() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicU64;

        let chunk = crate::fs::FILE_DATA_CHUNK;
        let mut pool = Pool::create_multi(multi_members(3), parity_params()).unwrap();
        let data: Vec<u8> = (0..chunk + 700).map(|i| (i * 23 % 251) as u8).collect();
        let file = pool.create_file(ROOT_INODE, "tx.bin", 0o644, NOW).unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        let victim = striped_runs(&pool, file)[0].0.device_index;
        let devices: Vec<_> = pool
            .devices
            .into_iter()
            .map(PartitionView::into_inner)
            .collect();
        let survivors: Vec<MemoryBlockDevice> = devices
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != usize::from(victim))
            .map(|(_, device)| device.clone())
            .collect();
        let mut degraded = Pool::open_multi_degraded(survivors).unwrap();
        degraded
            .replace_member(
                victim,
                MemberSpec {
                    device: MemoryBlockDevice::new(device_len()),
                    device_id: DeviceId([0x99; 16]),
                    geometry: geometry(),
                },
                NOW,
            )
            .unwrap();

        let bases: Vec<Vec<u8>> = degraded
            .devices
            .iter()
            .map(|device| device.inner().bytes().to_vec())
            .collect();
        let sequence: Arc<AtomicU64> = Arc::default();
        let recorders: Vec<RecordingBlockDevice<MemoryBlockDevice>> = degraded
            .devices
            .into_iter()
            .map(|device| {
                RecordingBlockDevice::with_shared_sequence(
                    device.into_inner(),
                    Arc::clone(&sequence),
                )
            })
            .collect();
        let mut pool = Pool::open_multi(recorders).unwrap();
        let pre_tx = pool.committed_tx();
        pool.rebuild(NOW).unwrap();

        let mut schedule: Vec<(u64, usize, Op)> = Vec::new();
        for (member, device) in pool.devices.iter().enumerate() {
            for (seq, op) in device.inner().sequenced_ops() {
                schedule.push((seq, member, op.clone()));
            }
        }
        schedule.sort_by_key(|(seq, _, _)| *seq);

        let mut states = 0usize;
        for prefix in 0..=schedule.len() {
            let torture: Vec<TortureBlockDevice> = bases
                .iter()
                .map(|base| TortureBlockDevice::from_image(base.clone(), 4096))
                .collect();
            for (_, member, op) in &schedule[..prefix] {
                match op {
                    Op::Write { offset, data } => torture[*member].write_at(*offset, data).unwrap(),
                    Op::Flush => torture[*member].flush().unwrap(),
                }
            }
            for sample in 0..4u64 {
                states += 1;
                let set: Vec<MemoryBlockDevice> = torture
                    .iter()
                    .enumerate()
                    .map(|(member, device)| {
                        device.crash_image(prefix as u64 * 909_091 + sample * 131 + member as u64)
                    })
                    .collect();
                let recovered = Pool::open_multi(set).unwrap_or_else(|err| {
                    panic!("crash state at prefix {prefix} sample {sample} failed: {err}")
                });
                let tx = recovered.committed_tx();
                assert!(
                    tx == pre_tx || tx == pre_tx + 1,
                    "impossible transaction {tx} (prefix {prefix})"
                );
                let entry = recovered.lookup(ROOT_INODE, "tx.bin").unwrap();
                assert_eq!(
                    recovered.read(entry.inode, 0, data.len()).unwrap(),
                    data,
                    "prefix {prefix} sample {sample} tx {tx}"
                );
            }
        }
        assert_eq!(states, (schedule.len() + 1) * 4);
        assert!(schedule.len() > 10, "schedule: {} ops", schedule.len());
    }

    #[test]
    fn scrub_heals_corrupt_stripe_pieces() {
        let chunk = crate::fs::FILE_DATA_CHUNK;
        let mut pool = Pool::create_multi(roomy_members(5), parity_params()).unwrap();
        let data: Vec<u8> = (0..chunk * 3 + 5000).map(|i| (i * 7 % 251) as u8).collect();
        let file = pool
            .create_file(ROOT_INODE, "heal.bin", 0o644, NOW)
            .unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        let runs = striped_runs(&pool, file);
        let piece = runs[1].0;
        let original = pool.read_extent(piece).unwrap();
        corrupt_copy(&mut pool, piece);

        let found = pool.scrub(false).unwrap();
        assert_eq!(found.copies_bad, 1, "{found:?}");
        assert_eq!(found.copies_repaired, 0);
        assert_eq!(found.copies_unrepairable, 0);
        assert!(!found.healthy());

        let healed = pool.scrub(true).unwrap();
        assert_eq!(healed.copies_bad, 1, "{healed:?}");
        assert_eq!(healed.copies_repaired, 1);
        assert!(healed.healthy());
        assert_eq!(pool.read_extent(piece).unwrap(), original);
        assert!(pool.scrub(false).unwrap().healthy());
        assert_eq!(pool.read(file, 0, data.len()).unwrap(), data);
    }

    #[test]
    fn scrub_regenerates_dead_parity_rows_from_a_surviving_descriptor() {
        let chunk = crate::fs::FILE_DATA_CHUNK;
        let params = PoolParams {
            mirror_width: 3,
            data_width: 2,
            parity_width: 2,
            ..pool_params()
        };
        let mut pool = Pool::create_multi(roomy_members(5), params).unwrap();
        let data: Vec<u8> = (0..chunk * 2).map(|i| (i * 11 % 251) as u8).collect();
        let file = pool
            .create_file(ROOT_INODE, "rows.bin", 0o644, NOW)
            .unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        let runs = striped_runs(&pool, file);
        let parity_extent = runs[0].1[0];
        let original = pool.read_extent(parity_extent).unwrap();

        corrupt_copy(&mut pool, parity_extent);
        let healed = pool.scrub(true).unwrap();
        assert_eq!(healed.copies_bad, 1, "{healed:?}");
        assert_eq!(healed.copies_repaired, 1);
        assert!(healed.healthy());
        assert_eq!(pool.read_extent(parity_extent).unwrap(), original);
        assert!(pool.scrub(false).unwrap().healthy());
    }

    #[test]
    fn scrub_heals_inconsistent_parity_the_checksum_cannot_see() {
        let chunk = crate::fs::FILE_DATA_CHUNK;
        let mut pool = Pool::create_multi(roomy_members(5), parity_params()).unwrap();
        let data: Vec<u8> = (0..chunk * 3).map(|i| (i * 11 % 251) as u8).collect();
        let file = pool
            .create_file(ROOT_INODE, "rows.bin", 0o644, NOW)
            .unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        let runs = striped_runs(&pool, file);
        let parity_extent = runs[0].1[0];
        let original = pool.read_extent(parity_extent).unwrap();

        let mut record = crate::stripes::decode_parity_record(&original).unwrap();
        record.parity[7] ^= 0xFF;
        let forged = crate::stripes::encode_parity_record(&record).unwrap();
        let slot = usize::from(parity_extent.device_index);
        pool.devices[slot]
            .write_at(parity_extent.offset, &forged)
            .unwrap();
        let found = pool.scrub(false).unwrap();
        assert_eq!(found.copies_bad, 1, "{found:?}");
        assert!(!found.healthy());
        let healed = pool.scrub(true).unwrap();
        assert_eq!(healed.copies_repaired, 1, "{healed:?}");
        assert!(healed.healthy());
        assert_eq!(pool.read_extent(parity_extent).unwrap(), original);
    }

    #[test]
    fn scrub_counts_unrepairable_stripe_damage() {
        let chunk = crate::fs::FILE_DATA_CHUNK;
        let mut pool = Pool::create_multi(roomy_members(5), parity_params()).unwrap();
        let data: Vec<u8> = (0..2 * chunk).map(|i| (i * 13 % 251) as u8).collect();
        let file = pool
            .create_file(ROOT_INODE, "gone.bin", 0o644, NOW)
            .unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        let runs = striped_runs(&pool, file);
        assert_eq!(runs[0].1, runs[1].1, "one stripe");
        corrupt_copy(&mut pool, runs[0].0);
        corrupt_copy(&mut pool, runs[0].1[0]);

        let report = pool.scrub(true).unwrap();
        assert_eq!(report.copies_bad, 2, "{report:?}");
        assert_eq!(report.copies_repaired, 0);
        assert_eq!(report.copies_unrepairable, 2);
        assert_eq!(
            pool.read(file, chunk as u64, chunk).unwrap(),
            &data[chunk..]
        );
        assert!(pool.read(file, 0, 100).is_err());
    }

    #[test]
    fn parity_commits_are_transactional_across_crashes() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicU64;

        let pool = Pool::create_multi(multi_members(2), parity_params()).unwrap();
        let bases: Vec<Vec<u8>> = pool
            .devices
            .iter()
            .map(|device| device.inner().bytes().to_vec())
            .collect();

        let sequence: Arc<AtomicU64> = Arc::default();
        let recorders: Vec<RecordingBlockDevice<MemoryBlockDevice>> = pool
            .devices
            .into_iter()
            .map(|device| {
                RecordingBlockDevice::with_shared_sequence(
                    device.into_inner(),
                    Arc::clone(&sequence),
                )
            })
            .collect();
        let mut pool = Pool::open_multi(recorders).unwrap();
        let data: Vec<u8> = (0..700usize).map(|i| (i * 31 % 251) as u8).collect();
        let file = pool.create_file(ROOT_INODE, "tx.bin", 0o644, NOW).unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        let mut schedule: Vec<(u64, usize, Op)> = Vec::new();
        for (member, device) in pool.devices.iter().enumerate() {
            for (seq, op) in device.inner().sequenced_ops() {
                schedule.push((seq, member, op.clone()));
            }
        }
        schedule.sort_by_key(|(seq, _, _)| *seq);

        let check = |pool: &Pool<MemoryBlockDevice>, prefix: usize| match pool.committed_tx() {
            1 => assert!(matches!(
                pool.lookup(ROOT_INODE, "tx.bin"),
                Err(ScaleFsError::NotFound)
            )),
            2 => {
                let entry = pool.lookup(ROOT_INODE, "tx.bin").unwrap();
                assert_eq!(pool.read(entry.inode, 0, data.len()).unwrap(), data);
            }
            other => panic!("recovered impossible transaction {other} (prefix {prefix})"),
        };

        let mut states = 0usize;
        for prefix in 0..=schedule.len() {
            let torture: Vec<TortureBlockDevice> = bases
                .iter()
                .map(|base| TortureBlockDevice::from_image(base.clone(), 4096))
                .collect();
            for (_, member, op) in &schedule[..prefix] {
                match op {
                    Op::Write { offset, data } => torture[*member].write_at(*offset, data).unwrap(),
                    Op::Flush => torture[*member].flush().unwrap(),
                }
            }
            let images: Vec<Vec<MemoryBlockDevice>> = torture
                .iter()
                .map(|device| device.all_crash_images())
                .collect();
            for a in &images[0] {
                for b in &images[1] {
                    states += 1;
                    let complete =
                        Pool::open_multi(vec![a.clone(), b.clone()]).unwrap_or_else(|err| {
                            panic!("crash state at prefix {prefix} failed to import: {err}")
                        });
                    check(&complete, prefix);

                    for lone in [a, b] {
                        let degraded = Pool::open_multi_degraded(vec![lone.clone()])
                            .unwrap_or_else(|err| {
                                panic!("degraded import at prefix {prefix} failed: {err}")
                            });
                        assert!(degraded.read_only());
                        check(&degraded, prefix);
                    }
                }
            }
        }
        assert!(states > 200, "sweep unexpectedly small: {states} states");
    }

    #[test]
    fn striped_multi_piece_commits_survive_sampled_crashes() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicU64;

        let chunk = crate::fs::FILE_DATA_CHUNK;
        let pool = Pool::create_multi(multi_members(3), parity_params()).unwrap();
        let bases: Vec<Vec<u8>> = pool
            .devices
            .iter()
            .map(|device| device.inner().bytes().to_vec())
            .collect();

        let sequence: Arc<AtomicU64> = Arc::default();
        let recorders: Vec<RecordingBlockDevice<MemoryBlockDevice>> = pool
            .devices
            .into_iter()
            .map(|device| {
                RecordingBlockDevice::with_shared_sequence(
                    device.into_inner(),
                    Arc::clone(&sequence),
                )
            })
            .collect();
        let mut pool = Pool::open_multi(recorders).unwrap();
        let data: Vec<u8> = (0..chunk + 700).map(|i| (i * 31 % 251) as u8).collect();
        let file = pool.create_file(ROOT_INODE, "tx.bin", 0o644, NOW).unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        let mut schedule: Vec<(u64, usize, Op)> = Vec::new();
        for (member, device) in pool.devices.iter().enumerate() {
            for (seq, op) in device.inner().sequenced_ops() {
                schedule.push((seq, member, op.clone()));
            }
        }
        schedule.sort_by_key(|(seq, _, _)| *seq);

        let check = |pool: &Pool<MemoryBlockDevice>, prefix: usize, sample: u64| match pool
            .committed_tx()
        {
            1 => assert!(matches!(
                pool.lookup(ROOT_INODE, "tx.bin"),
                Err(ScaleFsError::NotFound)
            )),
            2 => {
                let entry = pool.lookup(ROOT_INODE, "tx.bin").unwrap();
                assert_eq!(pool.read(entry.inode, 0, data.len()).unwrap(), data);
            }
            other => {
                panic!(
                    "recovered impossible transaction {other} (prefix {prefix}, sample {sample})"
                )
            }
        };

        let mut states = 0usize;
        for prefix in 0..=schedule.len() {
            let torture: Vec<TortureBlockDevice> = bases
                .iter()
                .map(|base| TortureBlockDevice::from_image(base.clone(), 4096))
                .collect();
            for (_, member, op) in &schedule[..prefix] {
                match op {
                    Op::Write { offset, data } => torture[*member].write_at(*offset, data).unwrap(),
                    Op::Flush => torture[*member].flush().unwrap(),
                }
            }
            for sample in 0..6u64 {
                states += 1;
                let set: Vec<MemoryBlockDevice> = torture
                    .iter()
                    .enumerate()
                    .map(|(member, device)| {
                        device.crash_image(prefix as u64 * 1_000_003 + sample * 97 + member as u64)
                    })
                    .collect();
                let complete = Pool::open_multi(set.clone()).unwrap_or_else(|err| {
                    panic!("crash state at prefix {prefix} sample {sample} failed: {err}")
                });
                check(&complete, prefix, sample);

                let absent = (prefix + sample as usize) % set.len();
                let survivors: Vec<MemoryBlockDevice> = set
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| *index != absent)
                    .map(|(_, device)| device.clone())
                    .collect();
                let degraded = Pool::open_multi_degraded(survivors).unwrap_or_else(|err| {
                    panic!("degraded import at prefix {prefix} sample {sample} failed: {err}")
                });
                assert!(degraded.read_only());
                check(&degraded, prefix, sample);
            }
        }
        assert_eq!(states, (schedule.len() + 1) * 6);
        assert!(
            schedule.len() > 25,
            "schedule unexpectedly small: {} ops",
            schedule.len()
        );
    }

    fn file_copies(pool: &Pool<MemoryBlockDevice>, object: u64) -> Vec<Extent> {
        pool.tree()
            .range(
                MetadataKey {
                    object_id: object,
                    item_type: ITEM_FILE_EXTENT,
                    offset: 0,
                },
                MetadataKey {
                    object_id: object,
                    item_type: ITEM_FILE_EXTENT,
                    offset: u64::MAX,
                },
            )
            .iter()
            .find_map(|(_, value)| match value {
                MetadataValue::FileExtent { extents, .. } => Some(extents.clone()),
                _ => None,
            })
            .expect("file has extents")
    }

    fn corrupt_copy(pool: &mut Pool<MemoryBlockDevice>, extent: Extent) {
        let slot = usize::from(extent.device_index);
        let mut byte = [0u8; 1];
        pool.devices[slot]
            .read_at(extent.offset + 50, &mut byte)
            .unwrap();
        pool.devices[slot]
            .write_at(extent.offset + 50, &[byte[0] ^ 0xFF])
            .unwrap();
    }

    #[test]
    fn scrub_heals_corrupted_copies_from_siblings() {
        let mut pool = Pool::create_multi(roomy_members(3), mirrored_params()).unwrap();
        let data: Vec<u8> = (0..60_000usize).map(|i| (i * 11 % 251) as u8).collect();
        let file = pool
            .create_file(ROOT_INODE, "data.bin", 0o644, NOW)
            .unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.snapshot_create("pin", NOW).unwrap();

        let copies = file_copies(&pool, file);
        assert_eq!(copies.len(), 2);
        corrupt_copy(&mut pool, copies[1]);
        let root = pool.last_metadata_root.clone();
        assert_eq!(root.len(), 2);
        corrupt_copy(&mut pool, root[1]);

        assert_eq!(pool.read(file, 0, data.len()).unwrap(), data);

        let found = pool.scrub(false).unwrap();
        assert_eq!(found.copies_bad, 2, "{found:?}");
        assert_eq!(found.copies_repaired, 0);
        assert_eq!(found.copies_unrepairable, 0);
        assert!(!found.healthy());

        let healed = pool.scrub(true).unwrap();
        assert_eq!(healed.copies_bad, 2, "{healed:?}");
        assert_eq!(healed.copies_repaired, 2);
        assert!(healed.healthy());

        let clean = pool.scrub(false).unwrap();
        assert_eq!(clean.copies_bad, 0, "{clean:?}");
        assert!(clean.healthy());

        assert_eq!(
            pool.read_extent(copies[0]).unwrap(),
            pool.read_extent(copies[1]).unwrap()
        );
        let reopened = Pool::open_multi(
            pool.devices
                .into_iter()
                .map(PartitionView::into_inner)
                .collect(),
        )
        .unwrap();
        let entry = reopened.lookup(ROOT_INODE, "data.bin").unwrap();
        assert_eq!(reopened.read(entry.inode, 0, data.len()).unwrap(), data);
        assert!(reopened.snapshot_open("pin").is_ok());
    }

    #[test]
    fn scrub_reports_unrepairable_and_missing_copies() {
        let mut pool = Pool::create_multi(roomy_members(2), mirrored_params()).unwrap();
        let data: Vec<u8> = (0..10_000usize).map(|i| (i % 251) as u8).collect();
        let file = pool
            .create_file(ROOT_INODE, "doomed.bin", 0o644, NOW)
            .unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let copies = file_copies(&pool, file);
        corrupt_copy(&mut pool, copies[0]);
        corrupt_copy(&mut pool, copies[1]);
        let report = pool.scrub(true).unwrap();
        assert_eq!(report.copies_unrepairable, 2, "{report:?}");
        assert_eq!(report.copies_repaired, 0);
        assert!(pool.read(file, 0, data.len()).is_err());

        let mut single = Pool::create(MemoryBlockDevice::new(device_len()), params()).unwrap();
        let file = single
            .create_file(ROOT_INODE, "solo.bin", 0o644, NOW)
            .unwrap();
        single.write(file, 0, &data, NOW).unwrap();
        single.commit(AllocPurpose::Normal, NOW).unwrap();
        let copies = file_copies(&single, file);
        corrupt_copy(&mut single, copies[0]);
        let report = single.scrub(true).unwrap();
        assert_eq!(report.copies_unrepairable, 1, "{report:?}");

        let mut pool = Pool::create_multi(roomy_members(3), mirrored_params()).unwrap();
        let file = pool.create_file(ROOT_INODE, "d.bin", 0o644, NOW).unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let survivors: Vec<MemoryBlockDevice> = pool
            .devices
            .drain(1..)
            .map(PartitionView::into_inner)
            .collect::<Vec<_>>();
        let mut degraded = Pool::open_multi_degraded(survivors).unwrap();
        let report = degraded.scrub(true).unwrap();
        assert!(report.copies_missing > 0, "{report:?}");
        assert!(report.healthy(), "{report:?}");
    }

    #[test]
    fn scrub_heals_a_damaged_superblock_slot() {
        let mut pool = Pool::create_multi(roomy_members(2), mirrored_params()).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        pool.devices[1].write_at(0, &[0xFF; 16]).unwrap();
        let found = pool.scrub(false).unwrap();
        assert_eq!(found.copies_bad, 1, "{found:?}");
        let healed = pool.scrub(true).unwrap();
        assert_eq!(healed.copies_repaired, 1, "{healed:?}");
        assert!(pool.scrub(false).unwrap().healthy());
        let bytes = read_prefix(&pool.devices[1], 0).unwrap();
        assert!(decode_superblock(&bytes).is_ok());
    }

    #[test]
    fn adding_a_member_grows_the_pool() {
        let mut pool = Pool::create(MemoryBlockDevice::new(device_len()), params()).unwrap();
        let data: Vec<u8> = (0..40_000usize).map(|i| (i * 3 % 251) as u8).collect();
        let file = pool.create_file(ROOT_INODE, "old.bin", 0o644, NOW).unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.snapshot_create("early", NOW).unwrap();
        let free_before: u64 = pool
            .allocators()
            .iter()
            .map(ZoneAllocator::free_usable_zone_count)
            .sum();

        let mut geometry = geometry();
        geometry.zone_count = 16;
        let member = pool
            .add_member(
                MemberSpec {
                    device: MemoryBlockDevice::new(crate::gpt::member_image_len(
                        geometry.capacity_bytes(),
                    ) as usize),
                    device_id: DeviceId([0x77; 16]),
                    geometry,
                },
                NOW,
            )
            .unwrap();
        assert_eq!(member, 1);
        assert_eq!(pool.member_count(), 2);
        assert!(pool.is_multi());
        for superblock in pool.superblocks() {
            assert_ne!(
                superblock.feature_incompat & FEATURE_INCOMPAT_MULTI_DEVICE,
                0
            );
            assert_eq!(superblock.topology_generation, 2);
        }
        let free_after: u64 = pool
            .allocators()
            .iter()
            .map(ZoneAllocator::free_usable_zone_count)
            .sum();
        assert!(free_after > free_before, "{free_before} -> {free_after}");

        let more: Vec<u8> = (0..200_000usize).map(|i| (i * 7 % 251) as u8).collect();
        let second = pool.create_file(ROOT_INODE, "new.bin", 0o644, NOW).unwrap();
        pool.write(second, 0, &more, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        let devices: Vec<_> = pool
            .devices
            .into_iter()
            .map(PartitionView::into_inner)
            .collect();
        assert!(matches!(
            Pool::open(devices[0].clone()),
            Err(ScaleFsError::Unsupported(_))
        ));
        let reopened = Pool::open_multi(devices).unwrap();
        assert_eq!(reopened.member_count(), 2);
        let entry = reopened.lookup(ROOT_INODE, "old.bin").unwrap();
        assert_eq!(reopened.read(entry.inode, 0, data.len()).unwrap(), data);
        let entry = reopened.lookup(ROOT_INODE, "new.bin").unwrap();
        assert_eq!(reopened.read(entry.inode, 0, more.len()).unwrap(), more);
        assert!(reopened.snapshot_open("early").is_ok());

        let mut pool = Pool::create_multi(roomy_members(2), mirrored_params()).unwrap();
        let file = pool.create_file(ROOT_INODE, "m.bin", 0o644, NOW).unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        pool.add_member(
            MemberSpec {
                device: MemoryBlockDevice::new(crate::gpt::member_image_len(
                    geometry.capacity_bytes(),
                ) as usize),
                device_id: DeviceId([0x78; 16]),
                geometry,
            },
            NOW,
        )
        .unwrap();
        assert_eq!(pool.member_count(), 3);
        assert_eq!(pool.mirror_width(), 2);
        let survivors: Vec<MemoryBlockDevice> = pool.devices[1..]
            .iter()
            .map(|view| view.inner().clone())
            .collect();
        let degraded = Pool::open_multi_degraded(survivors).unwrap();
        let entry = degraded.lookup(ROOT_INODE, "m.bin").unwrap();
        assert_eq!(degraded.read(entry.inode, 0, data.len()).unwrap(), data);
    }

    #[test]
    fn growing_a_pool_is_transactional_across_crashes() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicU64;

        let mut single = Pool::create(MemoryBlockDevice::new(device_len()), params()).unwrap();
        let data: Vec<u8> = (0..30_000usize).map(|i| (i % 240) as u8).collect();
        let file = single
            .create_file(ROOT_INODE, "keep.bin", 0o644, NOW)
            .unwrap();
        single.write(file, 0, &data, NOW).unwrap();
        single.commit(AllocPurpose::Normal, NOW).unwrap();
        let base_tx = single.committed_tx();
        let old_base = single.devices[0].inner().bytes().to_vec();
        let new_len = device_len();

        let sequence: Arc<AtomicU64> = Arc::default();
        let old_recorder =
            RecordingBlockDevice::with_shared_sequence(single.into_device(), Arc::clone(&sequence));
        let mut pool = Pool::open(old_recorder).unwrap();
        let newcomer = RecordingBlockDevice::with_shared_sequence(
            MemoryBlockDevice::new(new_len),
            Arc::clone(&sequence),
        );
        pool.add_member(
            MemberSpec {
                device: newcomer,
                device_id: DeviceId([0x77; 16]),
                geometry: geometry(),
            },
            NOW,
        )
        .unwrap();

        let mut schedule: Vec<(u64, usize, Op)> = Vec::new();
        for (member, device) in pool.devices.iter().enumerate() {
            for (seq, op) in device.inner().sequenced_ops() {
                schedule.push((seq, member, op.clone()));
            }
        }
        schedule.sort_by_key(|(seq, _, _)| *seq);

        let mut states = 0usize;
        let mut old_views = 0usize;
        let mut new_views = 0usize;
        for prefix in 0..=schedule.len() {
            let torture = [
                TortureBlockDevice::from_image(old_base.clone(), 4096),
                TortureBlockDevice::from_image(vec![0u8; new_len], 4096),
            ];
            for (_, member, op) in &schedule[..prefix] {
                match op {
                    Op::Write { offset, data } => torture[*member].write_at(*offset, data).unwrap(),
                    Op::Flush => torture[*member].flush().unwrap(),
                }
            }
            for a in &torture[0].all_crash_images() {
                for b in &torture[1].all_crash_images() {
                    states += 1;
                    let recovered = match Pool::open_multi(vec![a.clone(), b.clone()]) {
                        Ok(pool) => pool,
                        Err(_) => Pool::open_multi(vec![a.clone()]).unwrap_or_else(|err| {
                            panic!("old view lost at prefix {prefix}: {err}")
                        }),
                    };
                    match recovered.member_count() {
                        1 => {
                            old_views += 1;
                            assert_eq!(recovered.committed_tx(), base_tx);
                        }
                        2 => {
                            new_views += 1;
                            assert_eq!(recovered.committed_tx(), base_tx + 1);
                        }
                        other => panic!("impossible membership {other}"),
                    }
                    let entry = recovered.lookup(ROOT_INODE, "keep.bin").unwrap();
                    assert_eq!(recovered.read(entry.inode, 0, data.len()).unwrap(), data);
                }
            }
        }
        assert!(old_views > 0 && new_views > 0, "{old_views}/{new_views}");
        assert!(states > 50, "sweep unexpectedly small: {states} states");
    }

    #[test]
    fn replace_and_rebuild_makes_a_degraded_pool_whole() {
        let mut pool = Pool::create_multi(roomy_members(3), mirrored_params()).unwrap();
        let data: Vec<u8> = (0..150_000usize).map(|i| (i * 13 % 251) as u8).collect();
        let file = pool
            .create_file(ROOT_INODE, "data.bin", 0o644, NOW)
            .unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.snapshot_create("pin", NOW).unwrap();
        let old_member = pool.devices[1].inner().clone();

        let survivors: Vec<MemoryBlockDevice> = pool
            .devices
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != 1)
            .map(|(_, device)| device.inner().clone())
            .collect();
        let mut pool = Pool::open_multi_degraded(survivors).unwrap();
        assert!(pool.read_only());

        let mut geometry = geometry();
        geometry.zone_count = 16;
        pool.replace_member(
            1,
            MemberSpec {
                device: MemoryBlockDevice::new(crate::gpt::member_image_len(
                    geometry.capacity_bytes(),
                ) as usize),
                device_id: DeviceId([0x99; 16]),
                geometry,
            },
            NOW,
        )
        .unwrap();
        assert!(!pool.is_degraded());
        assert!(!pool.read_only());
        assert_eq!(pool.member_count(), 3);

        let before = pool.scrub(false).unwrap();
        assert!(before.copies_bad > 0, "{before:?}");
        assert_eq!(pool.read(file, 0, data.len()).unwrap(), data);

        let rebuilt = pool.rebuild(NOW).unwrap();
        assert!(rebuilt.records_rebuilt > 0, "{rebuilt:?}");
        assert!(rebuilt.copies_written > 0);
        assert_eq!(rebuilt.snapshots_rewritten, 1);
        let after = pool.scrub(false).unwrap();
        assert!(after.healthy(), "{after:?}");

        for dropped in 0..3usize {
            let survivors: Vec<MemoryBlockDevice> = pool
                .devices
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != dropped)
                .map(|(_, device)| device.inner().clone())
                .collect();
            let degraded = Pool::open_multi_degraded(survivors).unwrap();
            let entry = degraded.lookup(ROOT_INODE, "data.bin").unwrap();
            assert_eq!(degraded.read(entry.inode, 0, data.len()).unwrap(), data);
            let snapshot = degraded.snapshot_open("pin").unwrap();
            let entry = snapshot.lookup(ROOT_INODE, "data.bin").unwrap();
            assert_eq!(snapshot.read(entry.inode, 0, data.len()).unwrap(), data);
        }

        let mut with_ghost: Vec<MemoryBlockDevice> = pool
            .devices
            .iter()
            .map(|view| view.inner().clone())
            .collect();
        with_ghost.push(old_member);
        let haunted = Pool::open_multi(with_ghost).unwrap();
        assert_eq!(haunted.member_count(), 3);
        assert_eq!(haunted.orphaned_members().len(), 1);

        pool.reclaim(NOW).unwrap();
        assert!(pool.scrub(false).unwrap().healthy());
    }

    #[test]
    fn rebuild_heals_data_retained_only_through_a_nested_snapshot() {
        let mut pool = Pool::create_multi(roomy_members(3), mirrored_params()).unwrap();
        let old: Vec<u8> = (0..140_000usize).map(|i| (i * 7 % 251) as u8).collect();
        let gone = pool.create_file(ROOT_INODE, "old.bin", 0o644, NOW).unwrap();
        pool.write(gone, 0, &old, NOW).unwrap();
        pool.snapshot_create("inner", NOW).unwrap();
        pool.unlink(ROOT_INODE, "old.bin", NOW).unwrap();
        let live: Vec<u8> = (0..90_000usize).map(|i| (i * 11 % 251) as u8).collect();
        let keep = pool
            .create_file(ROOT_INODE, "live.bin", 0o644, NOW)
            .unwrap();
        pool.write(keep, 0, &live, NOW).unwrap();
        pool.snapshot_create("outer", NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        let survivors: Vec<MemoryBlockDevice> = pool
            .devices
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != 2)
            .map(|(_, device)| device.inner().clone())
            .collect();
        let mut pool = Pool::open_multi_degraded(survivors).unwrap();
        let mut geometry = geometry();
        geometry.zone_count = 16;
        pool.replace_member(
            2,
            MemberSpec {
                device: MemoryBlockDevice::new(crate::gpt::member_image_len(
                    geometry.capacity_bytes(),
                ) as usize),
                device_id: DeviceId([0xA7; 16]),
                geometry,
            },
            NOW,
        )
        .unwrap();
        pool.rebuild(NOW).unwrap();

        assert!(
            pool.scrub(false).unwrap().healthy(),
            "nested-snapshot data left under-mirrored after a heal",
        );
        for dropped in 0..3usize {
            let survivors: Vec<MemoryBlockDevice> = pool
                .devices
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != dropped)
                .map(|(_, device)| device.inner().clone())
                .collect();
            let degraded = Pool::open_multi_degraded(survivors).unwrap();
            let snapshot = degraded.snapshot_open("inner").unwrap();
            let entry = snapshot.lookup(ROOT_INODE, "old.bin").unwrap();
            assert_eq!(
                snapshot.read(entry.inode, 0, old.len()).unwrap(),
                old,
                "nested-snapshot file unreadable after losing member {dropped}",
            );
        }
    }

    #[test]
    fn rebuild_is_resumable_across_crashes() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicU64;

        let mut pool = Pool::create_multi(roomy_members(3), mirrored_params()).unwrap();
        let data: Vec<u8> = (0..60_000usize).map(|i| (i * 17 % 251) as u8).collect();
        let file = pool
            .create_file(ROOT_INODE, "keep.bin", 0o644, NOW)
            .unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        let survivors: Vec<MemoryBlockDevice> = pool
            .devices
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != 1)
            .map(|(_, device)| device.inner().clone())
            .collect();
        let mut degraded = Pool::open_multi_degraded(survivors).unwrap();
        let mut geometry = geometry();
        geometry.zone_count = 16;
        degraded
            .replace_member(
                1,
                MemberSpec {
                    device: MemoryBlockDevice::new(crate::gpt::member_image_len(
                        geometry.capacity_bytes(),
                    ) as usize),
                    device_id: DeviceId([0x99; 16]),
                    geometry,
                },
                NOW,
            )
            .unwrap();
        let bases: Vec<Vec<u8>> = degraded
            .devices
            .iter()
            .map(|device| device.inner().bytes().to_vec())
            .collect();

        let sequence: Arc<AtomicU64> = Arc::default();
        let recorders: Vec<RecordingBlockDevice<MemoryBlockDevice>> = degraded
            .devices
            .into_iter()
            .map(|device| {
                RecordingBlockDevice::with_shared_sequence(
                    device.into_inner(),
                    Arc::clone(&sequence),
                )
            })
            .collect();
        let mut pool = Pool::open_multi(recorders).unwrap();
        pool.rebuild(NOW).unwrap();
        let mut schedule: Vec<(u64, usize, Op)> = Vec::new();
        for (member, device) in pool.devices.iter().enumerate() {
            for (seq, op) in device.inner().sequenced_ops() {
                schedule.push((seq, member, op.clone()));
            }
        }
        schedule.sort_by_key(|(seq, _, _)| *seq);

        for prefix in 0..=schedule.len() {
            let torture: Vec<TortureBlockDevice> = bases
                .iter()
                .map(|base| TortureBlockDevice::from_image(base.clone(), 4096))
                .collect();
            for (_, member, op) in &schedule[..prefix] {
                match op {
                    Op::Write { offset, data } => torture[*member].write_at(*offset, data).unwrap(),
                    Op::Flush => torture[*member].flush().unwrap(),
                }
            }
            for seed in 0..4u64 {
                let images: Vec<MemoryBlockDevice> = torture
                    .iter()
                    .map(|device| {
                        device.crash_image(seed.wrapping_mul(31).wrapping_add(prefix as u64))
                    })
                    .collect();
                let mut recovered = Pool::open_multi(images).unwrap_or_else(|err| {
                    panic!("crash state at prefix {prefix} failed to import: {err}")
                });
                let entry = recovered.lookup(ROOT_INODE, "keep.bin").unwrap();
                assert_eq!(recovered.read(entry.inode, 0, data.len()).unwrap(), data);
                recovered.rebuild(NOW).unwrap();
                assert!(recovered.scrub(false).unwrap().healthy());
            }
        }
    }

    #[test]
    fn removing_a_member_shrinks_the_pool() {
        let mut pool = Pool::create_multi(roomy_members(3), mirrored_params()).unwrap();
        let data: Vec<u8> = (0..150_000usize).map(|i| (i * 19 % 251) as u8).collect();
        let file = pool
            .create_file(ROOT_INODE, "data.bin", 0o644, NOW)
            .unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.snapshot_create("pin", NOW).unwrap();

        let freed = pool.remove_member(1, NOW).unwrap();
        assert_eq!(pool.member_count(), 3, "index stays retired");
        assert_eq!(pool.devices.len(), 2);
        assert!(!pool.is_degraded());
        assert!(pool.missing_members().is_empty());
        assert_eq!(pool.read(file, 0, data.len()).unwrap(), data);
        {
            let snapshot = pool.snapshot_open("pin").unwrap();
            let entry = snapshot.lookup(ROOT_INODE, "data.bin").unwrap();
            assert_eq!(snapshot.read(entry.inode, 0, data.len()).unwrap(), data);
        }
        assert!(pool.scrub(false).unwrap().healthy());

        assert!(any_superblock(&freed).is_err());

        let reopened = Pool::open_multi(
            pool.devices
                .into_iter()
                .map(PartitionView::into_inner)
                .collect(),
        )
        .unwrap();
        assert_eq!(reopened.member_count(), 3);
        assert_eq!(reopened.devices.len(), 2);
        let entry = reopened.lookup(ROOT_INODE, "data.bin").unwrap();
        assert_eq!(reopened.read(entry.inode, 0, data.len()).unwrap(), data);

        for dropped in 0..2usize {
            let survivors: Vec<MemoryBlockDevice> = reopened
                .devices
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != dropped)
                .map(|(_, device)| device.inner().clone())
                .collect();
            let degraded = Pool::open_multi_degraded(survivors).unwrap();
            let entry = degraded.lookup(ROOT_INODE, "data.bin").unwrap();
            assert_eq!(degraded.read(entry.inode, 0, data.len()).unwrap(), data);
        }

        let mut pool = reopened;
        let mut geometry = geometry();
        geometry.zone_count = 16;
        let member = pool
            .add_member(
                MemberSpec {
                    device: MemoryBlockDevice::new(crate::gpt::member_image_len(
                        geometry.capacity_bytes(),
                    ) as usize),
                    device_id: DeviceId([0x55; 16]),
                    geometry,
                },
                NOW,
            )
            .unwrap();
        assert_eq!(member, 3, "retired indices are never reused");
        assert_eq!(pool.member_count(), 4);
        assert_eq!(pool.devices.len(), 3);
        pool.reclaim(NOW).unwrap();
        assert!(pool.scrub(false).unwrap().healthy());
    }

    #[test]
    fn reclaim_after_removal_without_reopen() {
        let mut pool = Pool::create_multi(roomy_members(4), mirrored_params()).unwrap();
        for i in 0..5 {
            let data: Vec<u8> = (0..24_000usize).map(|b| ((b + i) % 251) as u8).collect();
            let file = pool
                .create_file(ROOT_INODE, &format!("f{i}.bin"), 0o644, NOW)
                .unwrap();
            pool.write(file, 0, &data, NOW).unwrap();
            pool.commit(AllocPurpose::Normal, NOW).unwrap();
        }
        pool.snapshot_create("pin", NOW).unwrap();

        pool.remove_member(2, NOW).unwrap();
        pool.reclaim(NOW).unwrap();
        assert!(pool.scrub(false).unwrap().healthy());
        for i in 0..5 {
            let data: Vec<u8> = (0..24_000usize).map(|b| ((b + i) % 251) as u8).collect();
            let entry = pool.lookup(ROOT_INODE, &format!("f{i}.bin")).unwrap();
            assert_eq!(pool.read(entry.inode, 0, data.len()).unwrap(), data);
        }
    }

    #[test]
    fn removal_guards_hold() {
        let mut pool = Pool::create_multi(roomy_members(2), mirrored_params()).unwrap();
        assert!(matches!(
            pool.remove_member(0, NOW),
            Err(ScaleFsError::InvalidArgument(_))
        ));

        let mut pool = Pool::create_multi(roomy_members(3), mirrored_params()).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let survivors: Vec<MemoryBlockDevice> = pool
            .devices
            .drain(1..)
            .map(PartitionView::into_inner)
            .collect();
        let mut degraded = Pool::open_multi_degraded(survivors).unwrap();
        assert!(matches!(
            degraded.remove_member(1, NOW),
            Err(ScaleFsError::Unsupported(_))
        ));
    }

    #[test]
    fn retire_restores_write_availability() {
        let mut pool = Pool::create_multi(roomy_members(3), mirrored_params()).unwrap();
        let keep_data: Vec<u8> = (0..48_000usize).map(|i| (i % 251) as u8).collect();
        let gone_data: Vec<u8> = (0..24_000usize).map(|i| (i * 7 % 251) as u8).collect();
        let dir = pool.mkdir(ROOT_INODE, "docs", 0o755, NOW).unwrap();
        let keep = pool.create_file(dir, "keep.bin", 0o644, NOW).unwrap();
        pool.write(keep, 0, &keep_data, NOW).unwrap();
        pool.snapshot_create("older", NOW).unwrap();
        let gone = pool
            .create_file(ROOT_INODE, "gone.bin", 0o644, NOW)
            .unwrap();
        pool.write(gone, 0, &gone_data, NOW).unwrap();
        pool.snapshot_create("newer", NOW).unwrap();
        pool.unlink(ROOT_INODE, "gone.bin", NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        let devices: Vec<_> = pool
            .devices
            .into_iter()
            .map(PartitionView::into_inner)
            .collect();
        let survivors: Vec<MemoryBlockDevice> = vec![devices[1].clone(), devices[2].clone()];
        let mut pool = Pool::open_multi_degraded(survivors).unwrap();
        assert_eq!(pool.missing_members(), vec![0]);
        assert!(pool.read_only());
        assert!(matches!(
            pool.commit(AllocPurpose::Normal, NOW),
            Err(ScaleFsError::Unsupported(_))
        ));

        let report = pool.retire_member(0, NOW).unwrap();
        assert!(report.records_rebuilt > 0);
        assert_eq!(report.tx_id, pool.committed_tx());
        assert!(!pool.read_only());
        assert!(!pool.is_degraded());

        let docs = pool.lookup(ROOT_INODE, "docs").unwrap();
        let entry = pool.lookup(docs.inode, "keep.bin").unwrap();
        assert_eq!(
            pool.read(entry.inode, 0, keep_data.len()).unwrap(),
            keep_data
        );
        assert!(pool.lookup(ROOT_INODE, "gone.bin").is_err());
        {
            let snapshot = pool.snapshot_open("newer").unwrap();
            let entry = snapshot.lookup(ROOT_INODE, "gone.bin").unwrap();
            assert_eq!(
                snapshot.read(entry.inode, 0, gone_data.len()).unwrap(),
                gone_data
            );
        }
        {
            let snapshot = pool.snapshot_open("older").unwrap();
            let docs = snapshot.lookup(ROOT_INODE, "docs").unwrap();
            let entry = snapshot.lookup(docs.inode, "keep.bin").unwrap();
            assert_eq!(
                snapshot.read(entry.inode, 0, keep_data.len()).unwrap(),
                keep_data
            );
        }

        let fresh = pool
            .create_file(ROOT_INODE, "fresh.bin", 0o644, NOW)
            .unwrap();
        pool.write(fresh, 0, b"post-retire bytes", NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        assert!(pool.scrub(false).unwrap().healthy());

        let survivors: Vec<_> = pool
            .devices
            .into_iter()
            .map(PartitionView::into_inner)
            .collect();
        let mut reopened = Pool::open_multi(survivors).unwrap();
        assert!(!reopened.read_only());
        let entry = reopened.lookup(ROOT_INODE, "fresh.bin").unwrap();
        assert_eq!(
            reopened
                .read(entry.inode, 0, b"post-retire bytes".len())
                .unwrap(),
            b"post-retire bytes".to_vec()
        );
        let spec = roomy_members(4).pop().expect("four specs");
        let added = reopened.add_member(spec, NOW).unwrap();
        assert_eq!(added, 3, "retired indices are never reused");
    }

    #[test]
    fn retire_guards_hold() {
        let mut pool = Pool::create_multi(roomy_members(3), mirrored_params()).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        assert!(matches!(
            pool.retire_member(1, NOW),
            Err(ScaleFsError::InvalidArgument(_))
        ));
        assert!(matches!(
            pool.retire_member(9, NOW),
            Err(ScaleFsError::InvalidArgument(_))
        ));

        let mut pool = Pool::create_multi(roomy_members(2), mirrored_params()).unwrap();
        let file = pool.create_file(ROOT_INODE, "f.bin", 0o644, NOW).unwrap();
        pool.write(file, 0, b"bytes worth keeping", NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let devices: Vec<_> = pool
            .devices
            .into_iter()
            .map(PartitionView::into_inner)
            .collect();
        let mut degraded = Pool::open_multi_degraded(vec![devices[1].clone()]).unwrap();
        assert!(matches!(
            degraded.retire_member(0, NOW),
            Err(ScaleFsError::InvalidArgument(_))
        ));
        assert!(degraded.read_only());
        assert!(matches!(
            degraded.commit(AllocPurpose::Normal, NOW),
            Err(ScaleFsError::Unsupported(_))
        ));
        let entry = degraded.lookup(ROOT_INODE, "f.bin").unwrap();
        assert_eq!(
            degraded.read(entry.inode, 0, 19).unwrap(),
            b"bytes worth keeping".to_vec()
        );

        let mut pool = Pool::create_multi(
            roomy_members(5),
            PoolParams {
                mirror_width: 3,
                ..pool_params()
            },
        )
        .unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let devices: Vec<_> = pool
            .devices
            .into_iter()
            .map(PartitionView::into_inner)
            .collect();
        let survivors: Vec<MemoryBlockDevice> = devices[..3].to_vec();
        let mut degraded = Pool::open_multi_degraded(survivors).unwrap();
        assert_eq!(degraded.missing_members(), vec![3, 4]);
        assert!(matches!(
            degraded.retire_member(3, NOW),
            Err(ScaleFsError::Unsupported(_))
        ));

        let mut pool = Pool::create_multi(roomy_members(4), parity_params()).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let devices: Vec<_> = pool
            .devices
            .into_iter()
            .map(PartitionView::into_inner)
            .collect();
        let survivors: Vec<MemoryBlockDevice> = devices[..3].to_vec();
        let mut degraded = Pool::open_multi_degraded(survivors).unwrap();
        assert!(matches!(
            degraded.retire_member(3, NOW),
            Err(ScaleFsError::Unsupported(_))
        ));

        let mut pool = Pool::create_multi(roomy_members(3), mirrored_params()).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let devices: Vec<_> = pool
            .devices
            .into_iter()
            .map(PartitionView::into_inner)
            .collect();
        let mut pool =
            Pool::open_multi_degraded(vec![devices[1].clone(), devices[2].clone()]).unwrap();
        pool.retire_member(0, NOW).unwrap();
        assert!(matches!(
            pool.retire_member(0, NOW),
            Err(ScaleFsError::InvalidArgument(_))
        ));
    }

    #[test]
    fn reclaim_after_retire_without_reopen() {
        let mut pool = Pool::create_multi(roomy_members(4), mirrored_params()).unwrap();
        for i in 0..5 {
            let data: Vec<u8> = (0..24_000usize).map(|b| ((b + i) % 251) as u8).collect();
            let file = pool
                .create_file(ROOT_INODE, &format!("f{i}.bin"), 0o644, NOW)
                .unwrap();
            pool.write(file, 0, &data, NOW).unwrap();
            pool.commit(AllocPurpose::Normal, NOW).unwrap();
        }
        pool.snapshot_create("pin", NOW).unwrap();

        let devices: Vec<_> = pool
            .devices
            .into_iter()
            .map(PartitionView::into_inner)
            .collect();
        let survivors: Vec<MemoryBlockDevice> = devices
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != 2)
            .map(|(_, device)| device.clone())
            .collect();
        let mut pool = Pool::open_multi_degraded(survivors).unwrap();
        pool.retire_member(2, NOW).unwrap();
        pool.reclaim(NOW).unwrap();
        assert!(pool.scrub(false).unwrap().healthy());
        for i in 0..5 {
            let data: Vec<u8> = (0..24_000usize).map(|b| ((b + i) % 251) as u8).collect();
            let entry = pool.lookup(ROOT_INODE, &format!("f{i}.bin")).unwrap();
            assert_eq!(pool.read(entry.inode, 0, data.len()).unwrap(), data);
        }
    }

    #[test]
    fn retire_crash_states_recover_to_old_or_new() {
        let mut pool = Pool::create_multi(roomy_members(3), mirrored_params()).unwrap();
        let data: Vec<u8> = (0..48_000usize).map(|i| (i * 11 % 251) as u8).collect();
        let file = pool
            .create_file(ROOT_INODE, "keep.bin", 0o644, NOW)
            .unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.snapshot_create("pin", NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        let survivors: Vec<MemoryBlockDevice> = vec![
            pool.devices[1].inner().clone(),
            pool.devices[2].inner().clone(),
        ];
        let bases: Vec<Vec<u8>> = survivors
            .iter()
            .map(|device| device.bytes().to_vec())
            .collect();

        let sequence: std::sync::Arc<std::sync::atomic::AtomicU64> = std::sync::Arc::default();
        let recorders: Vec<RecordingBlockDevice<MemoryBlockDevice>> = survivors
            .into_iter()
            .map(|device| {
                RecordingBlockDevice::with_shared_sequence(device, std::sync::Arc::clone(&sequence))
            })
            .collect();
        let mut recorded = Pool::open_multi_degraded(recorders).unwrap();
        recorded.retire_member(0, NOW).unwrap();
        let mut schedule: Vec<(u64, usize, Op)> = Vec::new();
        for (member, device) in recorded.devices.iter().enumerate() {
            for (seq, op) in device.inner().sequenced_ops() {
                schedule.push((seq, member, op.clone()));
            }
        }
        schedule.sort_by_key(|(seq, _, _)| *seq);

        for prefix in 0..=schedule.len() {
            let torture: Vec<TortureBlockDevice> = bases
                .iter()
                .map(|base| TortureBlockDevice::from_image(base.clone(), 4096))
                .collect();
            for (_, member, op) in &schedule[..prefix] {
                match op {
                    Op::Write { offset, data } => torture[*member].write_at(*offset, data).unwrap(),
                    Op::Flush => torture[*member].flush().unwrap(),
                }
            }
            for seed in 0..3u64 {
                let images: Vec<MemoryBlockDevice> = torture
                    .iter()
                    .map(|device| {
                        device.crash_image(seed.wrapping_mul(37).wrapping_add(prefix as u64))
                    })
                    .collect();
                match Pool::open_multi(images.clone()) {
                    Ok(mut whole) => {
                        assert!(
                            !whole.read_only(),
                            "prefix {prefix} seed {seed}: new world must be writable"
                        );
                        let entry = whole.lookup(ROOT_INODE, "keep.bin").unwrap();
                        assert_eq!(whole.read(entry.inode, 0, data.len()).unwrap(), data);
                        {
                            let snapshot = whole.snapshot_open("pin").unwrap();
                            let entry = snapshot.lookup(ROOT_INODE, "keep.bin").unwrap();
                            assert_eq!(snapshot.read(entry.inode, 0, data.len()).unwrap(), data);
                        }
                        assert!(whole.scrub(false).unwrap().healthy());
                    }
                    Err(ScaleFsError::MissingMembers { .. }) => {
                        let mut degraded = Pool::open_multi_degraded(images).unwrap();
                        assert!(degraded.read_only());
                        let entry = degraded.lookup(ROOT_INODE, "keep.bin").unwrap();
                        assert_eq!(degraded.read(entry.inode, 0, data.len()).unwrap(), data);
                        degraded.retire_member(0, NOW).unwrap();
                        assert!(!degraded.read_only());
                        let entry = degraded.lookup(ROOT_INODE, "keep.bin").unwrap();
                        assert_eq!(degraded.read(entry.inode, 0, data.len()).unwrap(), data);
                        assert!(degraded.scrub(false).unwrap().healthy());
                    }
                    Err(err) => {
                        panic!("crash state at prefix {prefix} seed {seed} failed to import: {err}")
                    }
                }
            }
        }
    }

    #[test]
    fn retired_drive_returns_as_stale_extra() {
        let mut pool = Pool::create_multi(roomy_members(3), mirrored_params()).unwrap();
        let data: Vec<u8> = (0..36_000usize).map(|i| (i * 3 % 251) as u8).collect();
        let file = pool
            .create_file(ROOT_INODE, "keep.bin", 0o644, NOW)
            .unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();

        let stale = pool.devices[0].inner().clone();
        let survivors: Vec<MemoryBlockDevice> = vec![
            pool.devices[1].inner().clone(),
            pool.devices[2].inner().clone(),
        ];
        let mut pool = Pool::open_multi_degraded(survivors).unwrap();
        pool.retire_member(0, NOW).unwrap();
        let fresh = pool
            .create_file(ROOT_INODE, "fresh.bin", 0o644, NOW)
            .unwrap();
        pool.write(fresh, 0, b"after retirement", NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let survivors: Vec<_> = pool
            .devices
            .into_iter()
            .map(PartitionView::into_inner)
            .collect();

        let all = vec![survivors[0].clone(), survivors[1].clone(), stale];
        match Pool::open_multi(all) {
            Ok(reopened) => {
                assert!(!reopened.is_degraded());
                assert!(!reopened.read_only());
                assert_eq!(reopened.devices.len(), 2, "the stale drive is not adopted");
                let entry = reopened.lookup(ROOT_INODE, "fresh.bin").unwrap();
                assert_eq!(
                    reopened
                        .read(entry.inode, 0, b"after retirement".len())
                        .unwrap(),
                    b"after retirement".to_vec()
                );
            }
            Err(_) => {
                let reopened = Pool::open_multi(survivors).unwrap();
                let entry = reopened.lookup(ROOT_INODE, "fresh.bin").unwrap();
                assert_eq!(
                    reopened
                        .read(entry.inode, 0, b"after retirement".len())
                        .unwrap(),
                    b"after retirement".to_vec()
                );
            }
        }
    }

    #[test]
    fn retire_refuses_for_space() {
        let mut pool = Pool::create_multi(roomy_members(3), mirrored_params()).unwrap();
        let data: Vec<u8> = (0..24_000usize).map(|i| (i % 251) as u8).collect();
        let mut written = Vec::new();
        for i in 0..1000 {
            let name = format!("f{i}.bin");
            let Ok(file) = pool.create_file(ROOT_INODE, &name, 0o644, NOW) else {
                break;
            };
            if pool.write(file, 0, &data, NOW).is_err() {
                break;
            }
            if pool.commit(AllocPurpose::Normal, NOW).is_err() {
                break;
            }
            written.push(name);
        }
        assert!(written.len() >= 3, "fixture: the pool actually filled");

        let devices: Vec<_> = pool
            .devices
            .into_iter()
            .map(PartitionView::into_inner)
            .collect();
        let mut pool =
            Pool::open_multi_degraded(vec![devices[1].clone(), devices[2].clone()]).unwrap();
        assert!(matches!(
            pool.retire_member(0, NOW),
            Err(ScaleFsError::OutOfSpace)
        ));
        assert!(pool.read_only());
        let entry = pool.lookup(ROOT_INODE, &written[0]).unwrap();
        assert_eq!(pool.read(entry.inode, 0, data.len()).unwrap(), data);
    }

    #[test]
    fn divergent_views_cannot_be_created() {
        let mut pool = Pool::create_multi(roomy_members(3), mirrored_params()).unwrap();
        let file = pool.create_file(ROOT_INODE, "one.bin", 0o644, NOW).unwrap();
        pool.write(file, 0, b"consistent", NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let tx = pool.committed_tx();
        let devices: Vec<_> = pool
            .devices
            .into_iter()
            .map(PartitionView::into_inner)
            .collect();

        let mut left =
            Pool::open_multi_degraded(vec![devices[0].clone(), devices[1].clone()]).unwrap();
        let mut right =
            Pool::open_multi_degraded(vec![devices[1].clone(), devices[2].clone()]).unwrap();
        assert!(left.read_only() && right.read_only());
        assert!(matches!(
            left.commit(AllocPurpose::Normal, NOW),
            Err(ScaleFsError::Unsupported(_))
        ));
        assert!(matches!(
            right.commit(AllocPurpose::Normal, NOW),
            Err(ScaleFsError::Unsupported(_))
        ));
        assert!(matches!(
            Pool::open_multi(vec![devices[0].clone(), devices[1].clone()]),
            Err(ScaleFsError::MissingMembers { .. })
        ));

        let reopened = Pool::open_multi(devices).unwrap();
        assert_eq!(reopened.committed_tx(), tx);
        assert!(!reopened.read_only());
    }

    #[test]
    fn writes_route_correctly_after_membership_changes() {
        let mut pool = Pool::create_multi(roomy_members(3), mirrored_params()).unwrap();
        let data: Vec<u8> = (0..60_000usize).map(|i| (i * 23 % 251) as u8).collect();
        let first = pool
            .create_file(ROOT_INODE, "first.bin", 0o644, NOW)
            .unwrap();
        pool.write(first, 0, &data, NOW).unwrap();
        pool.remove_member(0, NOW).unwrap();

        let second = pool
            .create_file(ROOT_INODE, "second.bin", 0o644, NOW)
            .unwrap();
        pool.write(second, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        assert_eq!(pool.read(first, 0, data.len()).unwrap(), data);
        assert_eq!(pool.read(second, 0, data.len()).unwrap(), data);
        assert!(pool.scrub(false).unwrap().healthy());

        let reopened = Pool::open_multi(
            pool.devices
                .into_iter()
                .map(PartitionView::into_inner)
                .collect(),
        )
        .unwrap();
        let entry = reopened.lookup(ROOT_INODE, "second.bin").unwrap();
        assert_eq!(reopened.read(entry.inode, 0, data.len()).unwrap(), data);
    }

    #[test]
    fn degraded_pools_refuse_writes() {
        let mut pool = Pool::create_multi(roomy_members(3), mirrored_params()).unwrap();
        let file = pool.create_file(ROOT_INODE, "f.bin", 0o644, NOW).unwrap();
        pool.write(file, 0, b"data", NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let survivors: Vec<MemoryBlockDevice> = pool
            .devices
            .drain(1..)
            .map(PartitionView::into_inner)
            .collect();
        let mut degraded = Pool::open_multi_degraded(survivors).unwrap();
        assert!(matches!(
            degraded.write(file, 0, b"nope", NOW),
            Err(ScaleFsError::Unsupported(_))
        ));
    }

    #[test]
    fn replacing_one_of_two_absentees_keeps_the_other_alive() {
        let params = PoolParams {
            mirror_width: 3,
            ..pool_params()
        };
        let mut pool = Pool::create_multi(roomy_members(4), params).unwrap();
        let data: Vec<u8> = (0..60_000usize).map(|i| (i * 29 % 251) as u8).collect();
        let file = pool.create_file(ROOT_INODE, "f.bin", 0o644, NOW).unwrap();
        pool.write(file, 0, &data, NOW).unwrap();
        pool.commit(AllocPurpose::Normal, NOW).unwrap();
        let tx = pool.committed_tx();

        let survivors: Vec<MemoryBlockDevice> = pool
            .devices
            .drain(..2)
            .map(PartitionView::into_inner)
            .collect();
        let mut degraded = Pool::open_multi_degraded(survivors).unwrap();
        assert_eq!(degraded.missing_members(), vec![2, 3]);

        let mut geometry = geometry();
        geometry.zone_count = 16;
        degraded
            .replace_member(
                2,
                MemberSpec {
                    device: MemoryBlockDevice::new(crate::gpt::member_image_len(
                        geometry.capacity_bytes(),
                    ) as usize),
                    device_id: DeviceId([0x99; 16]),
                    geometry,
                },
                NOW,
            )
            .unwrap();

        assert!(degraded.read_only());
        assert_eq!(degraded.missing_members(), vec![3]);
        let roster = degraded.member_rosters().unwrap().remove(0);
        assert_eq!(roster.members[3].state, MemberState::Active);
        assert_eq!(roster.members[3].newest_tx, tx);

        degraded
            .replace_member(
                3,
                MemberSpec {
                    device: MemoryBlockDevice::new(crate::gpt::member_image_len(
                        geometry.capacity_bytes(),
                    ) as usize),
                    device_id: DeviceId([0x9A; 16]),
                    geometry,
                },
                NOW,
            )
            .unwrap();
        assert!(!degraded.read_only());
        assert!(!degraded.is_degraded());
        degraded.rebuild(NOW).unwrap();
        assert!(degraded.scrub(false).unwrap().healthy());
        assert_eq!(degraded.read(file, 0, data.len()).unwrap(), data);

        let mut pool = Pool::create_multi(roomy_members(3), mirrored_params()).unwrap();
        pool.remove_member(0, NOW).unwrap();
        assert!(matches!(
            pool.replace_member(
                0,
                MemberSpec {
                    device: MemoryBlockDevice::new(crate::gpt::member_image_len(
                        geometry.capacity_bytes()
                    ) as usize),
                    device_id: DeviceId([0x9B; 16]),
                    geometry,
                },
                NOW,
            ),
            Err(ScaleFsError::InvalidArgument(_))
        ));
    }

    #[test]
    fn single_device_pools_stay_featureless() {
        let pool = Pool::create(MemoryBlockDevice::new(device_len()), params()).unwrap();
        let superblock = pool.superblock();
        assert_eq!(superblock.feature_incompat, 0);
        let commit_extent = superblock.newest_commit.expect("created pools commit");
        assert_eq!(commit_extent.length, 97);
        let commit = decode_commit(&pool.read_extent(commit_extent).unwrap()).unwrap();
        assert_eq!(commit.aux_root, None);
    }

    fn partitioned_device(len: usize) -> MemoryBlockDevice {
        let device = MemoryBlockDevice::new(len);
        let mut sector0 = vec![0u8; 512];
        sector0[446] = 0x80;
        sector0[450] = 0x07;
        sector0[510] = 0x55;
        sector0[511] = 0xAA;
        device.write_at(0, &sector0).unwrap();
        device.write_at(512, b"EFI PART").unwrap();
        device.write_at(4096, b"EFI PART").unwrap();
        device.write_at(len as u64 - 512, b"EFI PART").unwrap();
        device
    }

    fn assert_member_wrapper(device: &MemoryBlockDevice, pool_id: [u8; 16], device_id: [u8; 16]) {
        let partition = crate::gpt::find_member_partition(device)
            .unwrap()
            .expect("provisioning writes the member GPT");
        assert_eq!(partition.start, crate::gpt::MEMBER_PARTITION_START);
        assert_eq!(
            partition.disk_guid, pool_id,
            "disk GUID carries the pool id"
        );
        assert_eq!(
            partition.part_guid, device_id,
            "partition GUID carries the device id"
        );
        let mut entries = vec![0u8; 64];
        device.read_at(446, &mut entries).unwrap();
        assert_eq!(entries[4], 0xEE, "protective MBR replaced the old table");
        assert!(
            entries[16..].iter().all(|&byte| byte == 0),
            "old MBR entries survived member provisioning"
        );
    }

    #[test]
    fn member_provisioning_replaces_old_partition_tables() {
        let len = device_len();
        let pool = Pool::create(partitioned_device(len), params()).unwrap();
        assert_member_wrapper(pool.devices[0].inner(), [0x11; 16], [0x22; 16]);
        assert_eq!(pool.superblock().label, "tank");

        let mut pool = Pool::create_multi(roomy_members(2), mirrored_params()).unwrap();
        let pool_id = pool.superblock().pool_id.0;
        let mut geometry = geometry();
        geometry.zone_count = 16;
        let dirty_len = crate::gpt::member_image_len(geometry.capacity_bytes()) as usize;
        pool.add_member(
            MemberSpec {
                device: partitioned_device(dirty_len),
                device_id: DeviceId([0x77; 16]),
                geometry,
            },
            NOW,
        )
        .unwrap();
        assert_member_wrapper(pool.devices.last().unwrap().inner(), pool_id, [0x77; 16]);

        let pool3 = Pool::create_multi(roomy_members(3), mirrored_params()).unwrap();
        let pool_id = pool3.superblock().pool_id.0;
        let survivors: Vec<MemoryBlockDevice> = pool3.devices[..2]
            .iter()
            .map(|view| view.inner().clone())
            .collect();
        let mut pool = Pool::open_multi_degraded(survivors).unwrap();
        pool.replace_member(
            2,
            MemberSpec {
                device: partitioned_device(dirty_len),
                device_id: DeviceId([0x78; 16]),
                geometry,
            },
            NOW,
        )
        .unwrap();
        assert_member_wrapper(pool.devices.last().unwrap().inner(), pool_id, [0x78; 16]);
    }
}
