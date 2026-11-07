use crate::device::MemoryBlockDevice;
use crate::error::ScaleFsError;
use crate::layout::{CaseSensitivity, DeviceId, Geometry, PoolId};
use crate::pool::{MemberSpec, Pool, PoolParams};
use crate::rng::XorShift64;
use crate::topology::MemberState;
use crate::torture::{FaultDevice, FaultSwitch};
use crate::tree::ROOT_INODE;
use crate::zones::AllocPurpose;
use std::collections::BTreeMap;
use std::sync::Arc;

type Dev = FaultDevice;

type Manifest = BTreeMap<String, Vec<u8>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    Mirror,
    Parity,
}

#[derive(Clone)]
struct Member {
    backing: Arc<MemoryBlockDevice>,
    device_id: DeviceId,
}

impl Member {
    fn spec(&self) -> MemberSpec<Dev> {
        MemberSpec {
            device: FaultDevice::over(Arc::clone(&self.backing)),
            device_id: self.device_id,
            geometry: GEOMETRY,
        }
    }
}

const GEOMETRY: Geometry = Geometry {
    logical_block_size: 4096,
    physical_block_size: 4096,
    zone_size: 64 * 1024,
    zone_count: 256,
    erase_granularity_zones: 1,
    sequential_write_required: false,
};

const MAX_FILE_BYTES: u64 = 48 * 1024;

const MIRROR_WIDTH: u16 = 2;
const INITIAL_MEMBERS: usize = 5;

pub struct Chaos {
    shape: Shape,
    members: Vec<Member>,
    down: Option<usize>,
    expected: (u64, Manifest),
    rng: XorShift64,
    next_device_id: u64,
    next_file: u64,
    next_snapshot: u64,
    seed: u64,
    cycle: u64,
    staged: bool,
    thinned: bool,
}

impl Chaos {
    pub fn new(seed: u64, shape: Shape) -> Chaos {
        let mut chaos = Chaos {
            shape,
            members: Vec::new(),
            down: None,
            expected: (0, Manifest::new()),
            rng: XorShift64::new(seed ^ 0x0be1_dead_c0de_1111),
            next_device_id: 0x40,
            next_file: 0,
            next_snapshot: 0,
            seed,
            cycle: 0,
            staged: false,
            thinned: false,
        };
        let members: Vec<Member> = (0..INITIAL_MEMBERS).map(|_| chaos.fresh_member()).collect();
        let specs = members.iter().map(Member::spec).collect();
        let (data_width, parity_width) = match shape {
            Shape::Mirror => (1, 0),
            Shape::Parity => (3, 1),
        };
        let mut pool = Pool::create_multi(
            specs,
            PoolParams {
                pool_id: PoolId([0x5c; 16]),
                case_sensitivity: CaseSensitivity::InsensitivePreserving,
                dirent_hash_seed: seed,
                label: "chaos".to_string(),
                created_at_ns: 1_700_000_000_000_000_000,
                mirror_width: MIRROR_WIDTH,
                data_width,
                parity_width,
            },
        )
        .expect("create the chaos pool");
        chaos.members = members;
        chaos.commit_and_settle(&mut pool);
        chaos
    }

    fn fresh_member(&mut self) -> Member {
        let serial = self.next_device_id;
        self.next_device_id += 1;
        let mut id = [0x40u8; 16];
        id[..8].copy_from_slice(&serial.to_le_bytes());
        Member {
            backing: Arc::new(MemoryBlockDevice::new(crate::gpt::member_image_len(
                GEOMETRY.capacity_bytes(),
            ) as usize)),
            device_id: DeviceId(id),
        }
    }

    fn now(&self) -> i64 {
        1_700_000_000_000_000_000 + (self.cycle as i64) * 1_000_000
    }

    fn present(&self) -> Vec<&Member> {
        self.members
            .iter()
            .enumerate()
            .filter(|(index, _)| Some(*index) != self.down)
            .map(|(_, member)| member)
            .collect()
    }

    fn open(&self) -> Result<(Pool<Dev>, Vec<FaultSwitch>), ScaleFsError> {
        let specs: Vec<MemberSpec<Dev>> = self.present().iter().map(|m| m.spec()).collect();
        let switches: Vec<FaultSwitch> = specs.iter().map(|spec| spec.device.switch()).collect();
        let devices: Vec<Dev> = specs.into_iter().map(|spec| spec.device).collect();
        let pool = if self.down.is_some() {
            Pool::open_multi_degraded(devices)?
        } else {
            Pool::open_multi(devices)?
        };
        Ok((pool, switches))
    }

    fn open_whole(&self, what: &str) -> (Pool<Dev>, Vec<FaultSwitch>) {
        self.open().unwrap_or_else(|error| {
            self.fail(&format!("could not open the pool to {what}: {error:?}"))
        })
    }

    pub fn run(&mut self, count: u64) {
        for _ in 0..count {
            self.cycle += 1;
            self.step();
            self.verify();
        }
    }

    fn step(&mut self) {
        self.staged = false;
        if self.down.is_none() && self.cycle.is_multiple_of(8) {
            let (mut pool, _switches) = self.open_whole("housekeeping reclaim");
            match pool.reclaim(self.now()) {
                Ok(_) => {}
                Err(ScaleFsError::Corrupt(advice))
                    if advice.contains("scrub before reclaiming") => {}
                Err(error) => self.fail(&format!("housekeeping reclaim failed: {error:?}")),
            }
            if self.cycle.is_multiple_of(64) {
                match pool.rebuild(self.now()) {
                    Ok(_) | Err(ScaleFsError::OutOfSpace) => {}
                    Err(error) => self.fail(&format!("housekeeping rebuild failed: {error:?}")),
                }
            }
            self.settle(&pool);
            drop(pool);
        }
        let roll = self.rng.next_u64() % 100;
        if self.down.is_some() {
            if roll < 55 {
                self.heal_via_replace();
            } else if roll < 70
                && matches!(self.shape, Shape::Mirror)
                && self.members.len() > usize::from(MIRROR_WIDTH)
            {
                self.retire_downed();
            } else {
                self.write_through_degraded();
            }
            return;
        }
        match roll {
            0..=29 => self.write_burst(),
            30..=49 if self.thinned => self.write_burst(),
            30..=49 => self.yank_during_writes(),
            50..=59 if self.thinned => self.write_burst(),
            50..=59 => self.double_fault_never_lies(),
            60..=69 => self.hardlink_churn(),
            70..=79 => self.maintain(),
            80..=89 if self.members.len() > usize::from(MIRROR_WIDTH) + 1 => self.remove_member(),
            _ => self.add_member(),
        }
    }

    fn hardlink_churn(&mut self) {
        let (mut pool, _switches) = self.open_whole("churn hard links");
        let _ = self.write_one(&mut pool, Strict::MustAccept);
        let entries = pool
            .readdir(ROOT_INODE)
            .unwrap_or_else(|error| self.fail(&format!("readdir for link churn: {error:?}")));
        let entry = entries[(self.rng.next_u64() as usize) % entries.len()].clone();
        let name = format!("l{:05}", self.next_file);
        self.next_file += 1;
        let linked = match pool.link(entry.inode, ROOT_INODE, &name, self.now()) {
            Ok(()) => {
                self.staged = true;
                true
            }
            Err(ScaleFsError::OutOfSpace) => false,
            Err(error) => self.fail(&format!("a link on a whole pool was refused: {error:?}")),
        };
        if self.rng.next_u64().is_multiple_of(2) {
            let victim = if linked && self.rng.next_u64().is_multiple_of(2) {
                name
            } else {
                entry.name.clone()
            };
            if let Err(error) = pool.unlink(ROOT_INODE, &victim, self.now()) {
                self.fail(&format!(
                    "unlink of '{victim}' on a whole pool was refused: {error:?}"
                ));
            }
            self.staged = true;
        }
        let _ = self.write_one(&mut pool, Strict::MustAccept);
        self.commit_and_settle(&mut pool);
    }

    fn write_burst(&mut self) {
        let (mut pool, _switches) = self.open_whole("run a write burst");
        let raw = (self.members.len() as u64) * GEOMETRY.zone_size * GEOMETRY.zone_count;
        let live: u64 = self.expected.1.values().map(|v| v.len() as u64).sum();
        if live * 4 > raw {
            let victims: Vec<String> = self.expected.1.keys().take(8).cloned().collect();
            for name in &victims {
                pool.unlink(ROOT_INODE, name, self.now())
                    .unwrap_or_else(|error| {
                        self.fail(&format!("pressure-valve unlink failed: {error:?}"))
                    });
            }
            self.staged = true;
            self.commit_and_settle(&mut pool);
            return;
        }
        let ops = 1 + self.rng.next_u64() % 6;
        for _ in 0..ops {
            self.write_one(&mut pool, Strict::MustAccept);
        }
        self.commit_and_settle(&mut pool);
    }

    fn yank_during_writes(&mut self) {
        let (mut pool, switches) = self.open_whole("yank a member");
        let _ = self.write_one(&mut pool, Strict::MustAccept);
        self.commit_and_settle(&mut pool);

        let victim = (self.rng.next_u64() as usize) % switches.len();
        switches[victim].fail();

        let ops = 1 + self.rng.next_u64() % 3;
        for _ in 0..ops {
            self.write_one(&mut pool, Strict::MayRefuse);
        }
        self.commit_and_settle(&mut pool);
        self.down = Some(victim);
    }

    fn double_fault_never_lies(&mut self) {
        let (mut pool, switches) = self.open_whole("double-fault");
        let _ = self.write_one(&mut pool, Strict::MustAccept);
        self.commit_and_settle(&mut pool);

        let first = (self.rng.next_u64() as usize) % switches.len();
        let second =
            (first + 1 + (self.rng.next_u64() as usize) % (switches.len() - 1)) % switches.len();
        switches[first].fail();
        switches[second].fail();

        let ops = 1 + self.rng.next_u64() % 3;
        for _ in 0..ops {
            self.write_one(&mut pool, Strict::MayRefuse);
        }
        let _ = pool.commit(AllocPurpose::Normal, self.now());
        self.staged = false;
        drop(pool);

        self.down = Some(first);
        let (reopened, _switches) = match self.open() {
            Ok(opened) => opened,
            Err(error) => self.fail(&format!("could not reopen after a double fault: {error:?}")),
        };
        self.settle(&reopened);
    }

    fn write_through_degraded(&mut self) {
        let Ok((mut pool, _switches)) = self.open() else {
            return;
        };
        let ops = 1 + self.rng.next_u64() % 3;
        for _ in 0..ops {
            self.write_one(&mut pool, Strict::MayRefuse);
        }
        self.commit_and_settle(&mut pool);
    }

    fn retire_downed(&mut self) {
        let (mut pool, _switches) = match self.open() {
            Ok(opened) => opened,
            Err(error) => self.fail(&format!("could not open degraded to retire: {error:?}")),
        };
        let missing = pool.missing_members();
        let Some(&member) = missing.first() else {
            self.down = None;
            return;
        };
        let retired_id = pool
            .member_rosters()
            .ok()
            .and_then(|rosters| {
                rosters
                    .first()
                    .map(|roster| roster.members[usize::from(member)].device_id)
            })
            .unwrap_or_else(|| self.fail("no roster naming the missing member"));
        match pool.retire_member(member, self.now()) {
            Ok(_) => {
                let downed = self
                    .down
                    .take()
                    .unwrap_or_else(|| self.fail("retire ran without a downed member"));
                let removed = self.members.remove(downed);
                if removed.device_id != retired_id {
                    self.fail("retire bookkeeping: the downed member is not the retired one");
                }
                self.thinned = false;
                if !pool
                    .scrub(false)
                    .unwrap_or_else(|error| self.fail(&format!("post-retire scrub: {error:?}")))
                    .healthy()
                {
                    self.fail("post-retire scrub found unhealthy copies");
                }
                self.settle(&pool);
            }
            Err(ScaleFsError::OutOfSpace) => {
                self.observe_heal_commits(&pool);
            }
            Err(error) => self.fail(&format!("retire refused unexpectedly: {error:?}")),
        }
    }

    fn heal_via_replace(&mut self) {
        let (mut pool, _switches) = match self.open() {
            Ok(opened) => opened,
            Err(error) => self.fail(&format!("could not open degraded to heal: {error:?}")),
        };
        let missing = pool.missing_members();
        let Some(&slot) = missing.first() else {
            self.down = None;
            return;
        };
        let replacement = self.fresh_member();
        match pool.replace_member(slot, replacement.spec(), self.now()) {
            Ok(_) => {}
            Err(ScaleFsError::OutOfSpace) => {
                self.settle(&pool);
                return;
            }
            Err(error) => self.fail(&format!("replace_member failed: {error:?}")),
        }
        let index = self.down.take().expect("a downed member to replace");
        self.members[index] = replacement;
        self.settle(&pool);
        let mut rebuilt = false;
        if !pool.is_degraded() {
            rebuilt = match pool.rebuild(self.now()) {
                Ok(_) => true,
                Err(ScaleFsError::OutOfSpace) => {
                    drop(pool);
                    self.staged = false;
                    let (reopened, _switches) = match self.open() {
                        Ok(opened) => opened,
                        Err(error) => self.fail(&format!(
                            "reopen for the full-pool remedy failed: {error:?}"
                        )),
                    };
                    pool = reopened;
                    let snapshots = pool.snapshot_list().unwrap_or_else(|error| {
                        self.fail(&format!("snapshot_list failed: {error:?}"))
                    });
                    for snapshot in snapshots {
                        pool.snapshot_release(&snapshot.name)
                            .unwrap_or_else(|error| {
                                self.fail(&format!(
                                    "snapshot_release during the full-pool remedy failed: {error:?}"
                                ))
                            });
                    }
                    for _ in 0..2 {
                        match pool.reclaim(self.now()) {
                            Ok(_) => {}
                            Err(ScaleFsError::Corrupt(advice))
                                if advice.contains("scrub before reclaiming") =>
                            {
                                pool.scrub(true).unwrap_or_else(|error| {
                                    self.fail(&format!(
                                        "repair scrub during the full-pool remedy \
                                         failed: {error:?}"
                                    ))
                                });
                                match pool.reclaim(self.now()) {
                                    Ok(_) => {}
                                    Err(ScaleFsError::Corrupt(again))
                                        if again.contains("scrub before reclaiming") => {}
                                    Err(error) => self.fail(&format!(
                                        "reclaim after the advised repair scrub \
                                         failed: {error:?}"
                                    )),
                                }
                                break;
                            }
                            Err(error) => self.fail(&format!(
                                "reclaim during the full-pool remedy failed: {error:?}"
                            )),
                        }
                    }
                    match pool.rebuild(self.now()) {
                        Ok(_) => true,
                        Err(ScaleFsError::OutOfSpace) => false,
                        Err(error) => self.fail(&format!(
                            "rebuild after the full-pool remedy failed: {error:?}"
                        )),
                    }
                }
                Err(error) => self.fail(&format!("rebuild failed: {error:?}")),
            };
            self.thinned = !rebuilt;
            self.settle(&pool);
        }
        self.commit_and_settle(&mut pool);
        if rebuilt && !pool.is_degraded() {
            let report = pool
                .scrub(false)
                .unwrap_or_else(|error| self.fail(&format!("scrub failed: {error:?}")));
            if !report.healthy() {
                self.fail(&format!(
                    "a healed pool scrubbed unhealthy: {} bad / {} unrepairable",
                    report.copies_bad, report.copies_unrepairable,
                ));
            }
        }
    }

    fn maintain(&mut self) {
        let (mut pool, _switches) = self.open_whole("run maintenance");
        match self.rng.next_u64() % 4 {
            0 => {
                let snapshots = pool
                    .snapshot_list()
                    .unwrap_or_else(|error| self.fail(&format!("snapshot_list failed: {error:?}")));
                if snapshots.len() >= 6 {
                    let victim = snapshots[0].name.clone();
                    pool.snapshot_release(&victim).unwrap_or_else(|error| {
                        self.fail(&format!("snapshot_release failed: {error:?}"))
                    });
                } else {
                    let name = format!("s{:03}", self.next_snapshot);
                    self.next_snapshot += 1;
                    match pool.snapshot_create(&name, self.now()) {
                        Ok(_) | Err(ScaleFsError::OutOfSpace) => {}
                        Err(error) => self.fail(&format!("snapshot_create failed: {error:?}")),
                    }
                }
            }
            1 => {
                let snapshots = pool
                    .snapshot_list()
                    .unwrap_or_else(|error| self.fail(&format!("snapshot_list failed: {error:?}")));
                if !snapshots.is_empty() {
                    let victim = snapshots[(self.rng.next_u64() as usize) % snapshots.len()]
                        .name
                        .clone();
                    pool.snapshot_release(&victim).unwrap_or_else(|error| {
                        self.fail(&format!("snapshot_release failed: {error:?}"))
                    });
                }
            }
            2 => match pool.reclaim(self.now()) {
                Ok(_) => {}
                Err(ScaleFsError::Corrupt(advice))
                    if advice.contains("scrub before reclaiming") => {}
                Err(error) => self.fail(&format!("reclaim failed: {error:?}")),
            },
            _ => {
                let report = pool
                    .scrub(false)
                    .unwrap_or_else(|error| self.fail(&format!("scrub failed: {error:?}")));
                if !self.thinned && !report.healthy() {
                    self.fail(&format!(
                        "an undamaged pool scrubbed unhealthy: {} bad / {} unrepairable",
                        report.copies_bad, report.copies_unrepairable,
                    ));
                }
            }
        }
        self.settle(&pool);
        let _ = self.write_one(&mut pool, Strict::MustAccept);
        self.commit_and_settle(&mut pool);
    }

    fn add_member(&mut self) {
        let (mut pool, _switches) = self.open_whole("add a member");
        let newcomer = self.fresh_member();
        match pool.add_member(newcomer.spec(), self.now()) {
            Ok(_) => {
                self.members.push(newcomer);
                self.settle(&pool);
                let _ = self.write_one(&mut pool, Strict::MustAccept);
                self.commit_and_settle(&mut pool);
            }
            Err(ScaleFsError::OutOfSpace) => self.finish_with_writes(pool),
            Err(error) => self.fail(&format!("add_member failed: {error:?}")),
        }
    }

    fn remove_member(&mut self) {
        let (mut pool, _switches) = self.open_whole("remove a member");
        let active = active_members(&pool);
        if active.len() <= usize::from(MIRROR_WIDTH) + 1 {
            return self.finish_with_writes(pool);
        }
        let (victim_index, victim_id) = active[(self.rng.next_u64() as usize) % active.len()];
        match pool.remove_member(victim_index, self.now()) {
            Ok(_evacuated) => {
                self.members.retain(|member| member.device_id != victim_id);
                self.settle(&pool);
                self.commit_and_settle(&mut pool);
            }
            Err(_) => {
                self.observe_heal_commits(&pool);
                self.finish_with_writes(pool)
            }
        }
    }

    fn finish_with_writes(&mut self, mut pool: Pool<Dev>) {
        let ops = 1 + self.rng.next_u64() % 4;
        for _ in 0..ops {
            self.write_one(&mut pool, Strict::MustAccept);
        }
        self.commit_and_settle(&mut pool);
    }

    fn write_one(&mut self, pool: &mut Pool<Dev>, strict: Strict) -> bool {
        let chunk = self.random_chunk();
        let result = self.try_write(pool, &chunk);
        match result {
            Ok(()) => {
                self.staged = true;
                true
            }
            Err(ScaleFsError::OutOfSpace) => false,
            Err(error) => {
                if strict == Strict::MustAccept {
                    self.fail(&format!("a write on a whole pool was refused: {error:?}"));
                }
                false
            }
        }
    }

    fn try_write(&mut self, pool: &mut Pool<Dev>, chunk: &[u8]) -> Result<(), ScaleFsError> {
        let existing: Vec<String> = pool
            .readdir(ROOT_INODE)?
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        let mut append = !existing.is_empty() && !self.rng.next_u64().is_multiple_of(3);
        let mut append_name = String::new();
        if append {
            append_name = existing[(self.rng.next_u64() as usize) % existing.len()].clone();
            let entry = pool.lookup(ROOT_INODE, &append_name)?;
            if pool.getattr(entry.inode)?.size >= MAX_FILE_BYTES {
                append = false;
            }
        }
        if append {
            let entry = pool.lookup(ROOT_INODE, &append_name)?;
            let at = pool.getattr(entry.inode)?.size;
            pool.write(entry.inode, at, chunk, self.now())
        } else {
            let raw = (self.members.len() as u64) * GEOMETRY.zone_size * GEOMETRY.zone_count;
            let live: u64 = self.expected.1.values().map(|v| v.len() as u64).sum();
            if live * 4 > raw {
                let mut victims: Vec<String> = existing
                    .iter()
                    .filter(|name| name.starts_with('f'))
                    .cloned()
                    .collect();
                victims.sort();
                for victim in victims.iter().take(2) {
                    pool.unlink(ROOT_INODE, victim, self.now())?;
                }
            }
            let name = format!("f{:05}", self.next_file);
            self.next_file += 1;
            let object = pool.create_file(ROOT_INODE, &name, 0o644, self.now())?;
            pool.write(object, 0, chunk, self.now())
        }
    }

    fn random_chunk(&mut self) -> Vec<u8> {
        let chunk = crate::fs::FILE_DATA_CHUNK;
        let len = if self.rng.next_u64().is_multiple_of(4) {
            chunk + 1 + (self.rng.next_u64() as usize % (2 * chunk))
        } else {
            1024 + (self.rng.next_u64() as usize % (11 * 1024))
        };
        let mut seed = self.rng.next_u64();
        (0..len)
            .map(|_| {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (seed >> 33) as u8
            })
            .collect()
    }

    fn commit_and_settle(&mut self, pool: &mut Pool<Dev>) {
        if pool.commit(AllocPurpose::Normal, self.now()).is_ok() {
            self.staged = false;
            self.settle(pool);
        }
    }

    fn pool_tx(&self, pool: &Pool<Dev>) -> u64 {
        pool.committed_tx()
    }

    fn observe_heal_commits(&mut self, pool: &Pool<Dev>) {
        let tx = self.pool_tx(pool);
        if tx < self.expected.0 {
            self.fail(&format!(
                "the live pool's committed transaction moved BACKWARDS \
                 ({} -> {tx}) without a reopen",
                self.expected.0,
            ));
        }
        self.expected.0 = tx;
    }

    fn settle(&mut self, pool: &Pool<Dev>) {
        assert!(
            !self.staged,
            "harness bug: settling while accepted writes are uncommitted \
             would record bytes ahead of the committed transaction",
        );
        let tx = self.pool_tx(pool);
        if tx < self.expected.0 {
            self.fail(&format!(
                "the live pool's committed transaction moved BACKWARDS \
                 ({} -> {tx}) without a reopen",
                self.expected.0,
            ));
        }
        let mut manifest = Manifest::new();
        let entries = pool
            .readdir(ROOT_INODE)
            .unwrap_or_else(|error| self.fail(&format!("readdir at settle failed: {error:?}")));
        for entry in entries {
            let attrs = pool
                .getattr(entry.inode)
                .unwrap_or_else(|error| self.fail(&format!("getattr at settle failed: {error:?}")));
            let bytes = pool
                .read(entry.inode, 0, attrs.size as usize)
                .unwrap_or_else(|error| {
                    self.fail(&format!(
                        "'{}' unreadable at settle (before any reopen): {error:?}",
                        entry.name,
                    ))
                });
            manifest.insert(entry.name, bytes);
        }
        self.expected = (tx, manifest);
    }

    fn verify(&mut self) {
        let (pool, _switches) = match self.open() {
            Ok(opened) => opened,
            Err(error) => self.fail(&format!("reopen failed: {error:?}")),
        };
        let (expected_tx, manifest) = &self.expected;
        let tx = pool.committed_tx();
        if tx != *expected_tx {
            self.fail(&format!(
                "reopened at tx {tx}, but the newest observed commit was tx {expected_tx} \
                 ({} — durability went {})",
                if tx < *expected_tx {
                    "an acknowledged commit was lost"
                } else {
                    "a transaction appeared that was never observed committed"
                },
                if tx < *expected_tx {
                    "backwards"
                } else {
                    "sideways"
                },
            ));
        }
        for (name, expected) in manifest {
            let entry = pool.lookup(ROOT_INODE, name).unwrap_or_else(|error| {
                self.fail(&format!(
                    "tx {tx}: committed file '{name}' is gone on reopen ({error:?})"
                ))
            });
            let size = pool
                .getattr(entry.inode)
                .unwrap_or_else(|error| {
                    self.fail(&format!(
                        "tx {tx}: committed file '{name}' has no attributes on reopen ({error:?})"
                    ))
                })
                .size;
            if size != expected.len() as u64 {
                self.fail(&format!(
                    "tx {tx}: committed file '{name}' changed size on reopen \
                     ({size} vs {})",
                    expected.len(),
                ));
            }
            let got = pool
                .read(entry.inode, 0, expected.len())
                .unwrap_or_else(|error| {
                    self.fail(&format!(
                        "tx {tx}: committed file '{name}' unreadable on reopen ({error:?})"
                    ))
                });
            if got != *expected {
                let differing = got.iter().zip(expected).filter(|(a, b)| a != b).count()
                    + expected.len().abs_diff(got.len());
                self.fail(&format!(
                    "tx {tx}: committed file '{name}' changed on reopen \
                     ({differing} of {} bytes differ)",
                    expected.len(),
                ));
            }
        }
        let listed = pool
            .readdir(ROOT_INODE)
            .unwrap_or_else(|error| self.fail(&format!("readdir on reopen failed: {error:?}")));
        for entry in &listed {
            if !manifest.contains_key(&entry.name) {
                self.fail(&format!(
                    "tx {tx}: reopen shows file '{}' the settled commit never held",
                    entry.name,
                ));
            }
        }
    }

    fn tag(&self) -> String {
        format!(
            "chaos[shape={:?} seed={} cycle={}]",
            self.shape, self.seed, self.cycle,
        )
    }

    fn fail(&self, why: &str) -> ! {
        panic!(
            "{}: DURABILITY VIOLATION — {why}\n  reproduce: \
             SCALEFS_CHAOS_SHAPE={} SCALEFS_CHAOS_SEED={} SCALEFS_CHAOS_EPISODES={} \
             cargo test -p scalefs-core chaos_campaign -- --ignored --nocapture",
            self.tag(),
            match self.shape {
                Shape::Mirror => "mirror",
                Shape::Parity => "parity",
            },
            self.seed,
            self.cycle,
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Strict {
    MustAccept,
    MayRefuse,
}

fn active_members(pool: &Pool<Dev>) -> Vec<(u16, DeviceId)> {
    pool.member_rosters()
        .ok()
        .and_then(|mut rosters| rosters.drain(..).next())
        .map(|roster| {
            roster
                .members
                .iter()
                .enumerate()
                .filter(|(_, member)| member.state == MemberState::Active)
                .map(|(index, member)| (index as u16, member.device_id))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::BlockDevice;

    #[test]
    fn chaos_smoke() {
        for seed in [1, 2, 3, 7, 42] {
            Chaos::new(seed, Shape::Mirror).run(8);
            Chaos::new(seed, Shape::Parity).run(8);
        }
    }

    #[test]
    #[ignore = "campaign; run explicitly with SCALEFS_CHAOS_* env"]
    fn chaos_campaign() {
        let shape = match std::env::var("SCALEFS_CHAOS_SHAPE").as_deref() {
            Ok("parity") => Shape::Parity,
            _ => Shape::Mirror,
        };
        let seed = std::env::var("SCALEFS_CHAOS_SEED")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0x_c0ffee);
        let episodes = std::env::var("SCALEFS_CHAOS_EPISODES")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(100);
        eprintln!("chaos campaign: shape={shape:?} seed={seed} episodes={episodes}");
        Chaos::new(seed, shape).run(episodes);
    }

    #[test]
    #[should_panic(expected = "DURABILITY VIOLATION")]
    fn the_oracle_detects_planted_corruption() {
        let mut chaos = Chaos::new(99, Shape::Mirror);
        for _ in 0..12 {
            let (mut pool, _switches) = chaos.open_whole("populate");
            chaos.write_one(&mut pool, Strict::MustAccept);
            chaos.commit_and_settle(&mut pool);
        }
        assert!(
            !chaos.expected.1.is_empty(),
            "the corruption test needs committed files",
        );
        for member in &chaos.members {
            let len = member.backing.len();
            let from = GEOMETRY.zone_size;
            let garbage = vec![0xA5u8; (len - from) as usize];
            member
                .backing
                .write_at(from, &garbage)
                .expect("scribble the member");
        }
        chaos.verify();
    }

    #[test]
    #[should_panic(expected = "DURABILITY VIOLATION")]
    fn the_oracle_detects_rollback() {
        let mut chaos = Chaos::new(101, Shape::Mirror);
        for _ in 0..4 {
            let (mut pool, _switches) = chaos.open_whole("populate");
            chaos.write_one(&mut pool, Strict::MustAccept);
            chaos.commit_and_settle(&mut pool);
        }
        let earlier: Vec<Vec<u8>> = chaos
            .members
            .iter()
            .map(|member| member.backing.bytes())
            .collect();
        for _ in 0..4 {
            let (mut pool, _switches) = chaos.open_whole("advance");
            chaos.write_one(&mut pool, Strict::MustAccept);
            chaos.commit_and_settle(&mut pool);
        }
        for (member, bytes) in chaos.members.iter().zip(earlier) {
            member
                .backing
                .write_at(0, &bytes)
                .expect("roll back the member");
        }
        chaos.verify();
    }
}
