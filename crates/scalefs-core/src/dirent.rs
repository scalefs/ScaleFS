use crate::error::{Result, ScaleFsError};
use crate::layout::CaseSensitivity;
use crate::tree::{
    DirEntry, EntryKind, ITEM_DIRENT, MAX_NAME_LEN, MetadataKey, MetadataValue, TreeMut, TreeRef,
};
use crate::unicode::UnicodeVersion;

pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(ScaleFsError::InvalidArgument(
            "name must be 1..=255 bytes of UTF-8",
        ));
    }
    if name == "." || name == ".." {
        return Err(ScaleFsError::InvalidArgument("name may not be . or .."));
    }
    if name.bytes().any(|b| b == 0 || b == b'/') {
        return Err(ScaleFsError::InvalidArgument(
            "name may not contain '/' or NUL",
        ));
    }
    Ok(())
}

pub fn fold_name(version: UnicodeVersion, case: CaseSensitivity, name: &str) -> String {
    match case {
        CaseSensitivity::Sensitive => crate::unicode::nfd(version, name),
        CaseSensitivity::InsensitivePreserving => crate::unicode::caseless_key(version, name),
    }
}

pub fn dirent_hash(seed: u64, folded_name: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64 ^ seed;
    for byte in folded_name.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn dirent_key(dir: u64, hash: u64) -> MetadataKey {
    MetadataKey {
        object_id: dir,
        item_type: ITEM_DIRENT,
        offset: hash,
    }
}

fn names_equal(version: UnicodeVersion, case: CaseSensitivity, a: &str, b: &str) -> bool {
    fold_name(version, case, a) == fold_name(version, case, b)
}

#[allow(clippy::too_many_arguments)]
pub fn add_entry(
    tree: TreeMut<'_>,
    seed: u64,
    version: UnicodeVersion,
    case: CaseSensitivity,
    dir: u64,
    name: &str,
    inode: u64,
    kind: EntryKind,
) -> Result<()> {
    if matches!(kind, EntryKind::Unknown(_)) {
        return Err(ScaleFsError::InvalidArgument(
            "entries of an unknown kind cannot be created",
        ));
    }
    validate_name(name)?;
    let hash = dirent_hash(seed, &fold_name(version, case, name));
    add_entry_at_hash(tree, version, case, dir, hash, name, inode, kind)
}

#[allow(clippy::too_many_arguments)]
fn add_entry_at_hash(
    tree: TreeMut<'_>,
    version: UnicodeVersion,
    case: CaseSensitivity,
    dir: u64,
    hash: u64,
    name: &str,
    inode: u64,
    kind: EntryKind,
) -> Result<()> {
    let key = dirent_key(dir, hash);
    let mut entries = match tree.get(key)? {
        Some(MetadataValue::DirEntries(entries)) => entries,
        Some(_) => return Err(ScaleFsError::Corrupt("non-bucket value at a dirent key")),
        None => Vec::new(),
    };
    if entries
        .iter()
        .any(|e| names_equal(version, case, &e.name, name))
    {
        return Err(ScaleFsError::AlreadyExists);
    }
    entries.push(DirEntry {
        inode,
        kind,
        name: name.to_string(),
    });
    tree.insert(key, MetadataValue::DirEntries(entries))
        .map_err(|err| match err {
            ScaleFsError::InvalidArgument(_) => {
                ScaleFsError::InvalidArgument("too many colliding names in one directory")
            }
            other => other,
        })
}

pub fn lookup_entry(
    tree: TreeRef<'_>,
    seed: u64,
    version: UnicodeVersion,
    case: CaseSensitivity,
    dir: u64,
    name: &str,
) -> Result<Option<DirEntry>> {
    let hash = dirent_hash(seed, &fold_name(version, case, name));
    lookup_entry_at_hash(tree, version, case, dir, hash, name)
}

fn lookup_entry_at_hash(
    tree: TreeRef<'_>,
    version: UnicodeVersion,
    case: CaseSensitivity,
    dir: u64,
    hash: u64,
    name: &str,
) -> Result<Option<DirEntry>> {
    tree.get_with(dirent_key(dir, hash), |value| match value {
        Some(MetadataValue::DirEntries(entries)) => entries
            .iter()
            .find(|e| names_equal(version, case, &e.name, name))
            .cloned(),
        _ => None,
    })
}

pub fn remove_entry(
    tree: TreeMut<'_>,
    seed: u64,
    version: UnicodeVersion,
    case: CaseSensitivity,
    dir: u64,
    name: &str,
) -> Result<DirEntry> {
    let hash = dirent_hash(seed, &fold_name(version, case, name));
    remove_entry_at_hash(tree, version, case, dir, hash, name)
}

fn remove_entry_at_hash(
    tree: TreeMut<'_>,
    version: UnicodeVersion,
    case: CaseSensitivity,
    dir: u64,
    hash: u64,
    name: &str,
) -> Result<DirEntry> {
    let key = dirent_key(dir, hash);
    let mut entries = match tree.get(key)? {
        Some(MetadataValue::DirEntries(entries)) => entries,
        Some(_) => return Err(ScaleFsError::Corrupt("non-bucket value at a dirent key")),
        None => return Err(ScaleFsError::NotFound),
    };
    let index = entries
        .iter()
        .position(|e| names_equal(version, case, &e.name, name))
        .ok_or(ScaleFsError::NotFound)?;
    let removed = entries.remove(index);
    if entries.is_empty() {
        tree.remove(key)?;
    } else {
        tree.insert(key, MetadataValue::DirEntries(entries))?;
    }
    Ok(removed)
}

pub fn list_entries(tree: TreeRef<'_>, dir: u64) -> Result<Vec<DirEntry>> {
    let start = dirent_key(dir, 0);
    let end = dirent_key(dir, u64::MAX);
    let mut out = Vec::new();
    for (_, value) in tree.range(start, end)? {
        if let MetadataValue::DirEntries(entries) = value {
            out.extend(entries);
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

#[derive(Debug, Clone)]
pub struct HashedEntry {
    pub hash: u64,
    pub entry: DirEntry,
}

pub fn list_entries_hashed(tree: TreeRef<'_>, dir: u64) -> Result<Vec<HashedEntry>> {
    let start = dirent_key(dir, 0);
    let end = dirent_key(dir, u64::MAX);
    let mut out = Vec::new();
    for (key, value) in tree.range(start, end)? {
        if let MetadataValue::DirEntries(entries) = value {
            let mut bucket = entries;
            bucket.sort_by(|a, b| a.name.cmp(&b.name));
            for entry in bucket {
                out.push(HashedEntry {
                    hash: key.offset,
                    entry,
                });
            }
        }
    }
    Ok(out)
}

pub fn entry_count(tree: TreeRef<'_>, dir: u64) -> Result<usize> {
    let start = dirent_key(dir, 0);
    let end = dirent_key(dir, u64::MAX);
    let mut count = 0;
    tree.scan(start, end, &mut |items| {
        count += items
            .iter()
            .map(|(_, value)| match value {
                MetadataValue::DirEntries(entries) => entries.len(),
                _ => 0,
            })
            .sum::<usize>();
    })?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::MetadataTree;

    const SEED: u64 = 0x5EED_CAFE_F00D_0001;
    const VER: UnicodeVersion = crate::unicode::V17_0_0;
    const DIR: u64 = 1;

    fn sensitive() -> (MetadataTree, CaseSensitivity) {
        (MetadataTree::new(), CaseSensitivity::Sensitive)
    }

    fn insensitive() -> (MetadataTree, CaseSensitivity) {
        (MetadataTree::new(), CaseSensitivity::InsensitivePreserving)
    }

    fn view(tree: &MetadataTree) -> crate::tree::TreeRef<'_> {
        tree.view(&crate::tree::NoPages)
    }

    fn lookup(
        tree: &MetadataTree,
        seed: u64,
        version: UnicodeVersion,
        case: CaseSensitivity,
        dir: u64,
        name: &str,
    ) -> Option<DirEntry> {
        lookup_entry(view(tree), seed, version, case, dir, name).unwrap()
    }

    fn lookup_at_hash(
        tree: &MetadataTree,
        version: UnicodeVersion,
        case: CaseSensitivity,
        dir: u64,
        hash: u64,
        name: &str,
    ) -> Option<DirEntry> {
        lookup_entry_at_hash(view(tree), version, case, dir, hash, name).unwrap()
    }

    #[test]
    fn add_lookup_remove_round_trip() {
        let (mut tree, case) = sensitive();
        add_entry(
            tree.in_memory(),
            SEED,
            VER,
            case,
            DIR,
            "hello.txt",
            2,
            EntryKind::File,
        )
        .unwrap();
        let entry = lookup(&tree, SEED, VER, case, DIR, "hello.txt").unwrap();
        assert_eq!(entry.inode, 2);
        assert_eq!(entry.kind, EntryKind::File);

        assert!(matches!(
            add_entry(
                tree.in_memory(),
                SEED,
                VER,
                case,
                DIR,
                "hello.txt",
                3,
                EntryKind::File
            ),
            Err(ScaleFsError::AlreadyExists)
        ));

        let removed = remove_entry(tree.in_memory(), SEED, VER, case, DIR, "hello.txt").unwrap();
        assert_eq!(removed.inode, 2);
        assert!(lookup(&tree, SEED, VER, case, DIR, "hello.txt").is_none());
        assert!(matches!(
            remove_entry(tree.in_memory(), SEED, VER, case, DIR, "hello.txt"),
            Err(ScaleFsError::NotFound)
        ));
    }

    #[test]
    fn insensitive_pools_fold_ascii_case() {
        let (mut tree, case) = insensitive();
        add_entry(
            tree.in_memory(),
            SEED,
            VER,
            case,
            DIR,
            "ReadMe.MD",
            2,
            EntryKind::File,
        )
        .unwrap();
        let entry = lookup(&tree, SEED, VER, case, DIR, "readme.md").unwrap();
        assert_eq!(entry.name, "ReadMe.MD");
        assert!(lookup(&tree, SEED, VER, case, DIR, "README.MD").is_some());
        assert!(matches!(
            add_entry(
                tree.in_memory(),
                SEED,
                VER,
                case,
                DIR,
                "readme.md",
                3,
                EntryKind::File
            ),
            Err(ScaleFsError::AlreadyExists)
        ));
        remove_entry(tree.in_memory(), SEED, VER, case, DIR, "rEaDmE.mD").unwrap();
        assert!(lookup(&tree, SEED, VER, case, DIR, "ReadMe.MD").is_none());
    }

    #[test]
    fn sensitive_pools_keep_casings_distinct() {
        let (mut tree, case) = sensitive();
        add_entry(
            tree.in_memory(),
            SEED,
            VER,
            case,
            DIR,
            "File",
            2,
            EntryKind::File,
        )
        .unwrap();
        add_entry(
            tree.in_memory(),
            SEED,
            VER,
            case,
            DIR,
            "file",
            3,
            EntryKind::File,
        )
        .unwrap();
        assert_eq!(
            lookup(&tree, SEED, VER, case, DIR, "File").unwrap().inode,
            2
        );
        assert_eq!(
            lookup(&tree, SEED, VER, case, DIR, "file").unwrap().inode,
            3
        );
    }

    #[test]
    fn insensitive_pools_fold_full_unicode_case() {
        let (mut tree, case) = insensitive();
        add_entry(
            tree.in_memory(),
            SEED,
            VER,
            case,
            DIR,
            "café",
            2,
            EntryKind::File,
        )
        .unwrap();
        assert!(matches!(
            add_entry(
                tree.in_memory(),
                SEED,
                VER,
                case,
                DIR,
                "CAFÉ",
                3,
                EntryKind::File
            ),
            Err(ScaleFsError::AlreadyExists)
        ));
        assert_eq!(
            lookup(&tree, SEED, VER, case, DIR, "CAFÉ").unwrap().name,
            "café"
        );
        add_entry(
            tree.in_memory(),
            SEED,
            VER,
            case,
            DIR,
            "Σ",
            4,
            EntryKind::File,
        )
        .unwrap();
        assert_eq!(lookup(&tree, SEED, VER, case, DIR, "σ").unwrap().inode, 4);
        assert_eq!(lookup(&tree, SEED, VER, case, DIR, "ς").unwrap().inode, 4);
    }

    #[test]
    fn normalization_aliases_on_both_pool_kinds() {
        for (mut tree, case) in [sensitive(), insensitive()] {
            add_entry(
                tree.in_memory(),
                SEED,
                VER,
                case,
                DIR,
                "caf\u{E9}",
                2,
                EntryKind::File,
            )
            .unwrap();
            assert!(matches!(
                add_entry(
                    tree.in_memory(),
                    SEED,
                    VER,
                    case,
                    DIR,
                    "cafe\u{301}",
                    3,
                    EntryKind::File
                ),
                Err(ScaleFsError::AlreadyExists)
            ));
            assert!(lookup(&tree, SEED, VER, case, DIR, "cafe\u{301}").is_some());
        }
    }

    #[test]
    fn straße_and_strasse_stay_distinct_on_insensitive_pools() {
        let (mut tree, case) = insensitive();
        add_entry(
            tree.in_memory(),
            SEED,
            VER,
            case,
            DIR,
            "straße",
            2,
            EntryKind::File,
        )
        .unwrap();
        add_entry(
            tree.in_memory(),
            SEED,
            VER,
            case,
            DIR,
            "STRASSE",
            3,
            EntryKind::File,
        )
        .unwrap();
        assert_eq!(
            lookup(&tree, SEED, VER, case, DIR, "straße").unwrap().inode,
            2
        );
        assert_eq!(
            lookup(&tree, SEED, VER, case, DIR, "strasse")
                .unwrap()
                .inode,
            3
        );
    }

    #[test]
    fn a_name_whose_nfd_exceeds_255_bytes_is_storable() {
        let (mut tree, case) = insensitive();
        let name = "Å".repeat(90);
        assert!(name.len() <= 255);
        add_entry(
            tree.in_memory(),
            SEED,
            VER,
            case,
            DIR,
            &name,
            2,
            EntryKind::File,
        )
        .unwrap();
        assert_eq!(lookup(&tree, SEED, VER, case, DIR, &name).unwrap().inode, 2);
        assert!(lookup(&tree, SEED, VER, case, DIR, &"a\u{30A}".repeat(90)).is_some());
    }

    #[test]
    fn colliding_hashes_share_a_bucket_correctly() {
        let (mut tree, case) = sensitive();
        let hash = 42;
        add_entry_at_hash(
            tree.in_memory(),
            VER,
            case,
            DIR,
            hash,
            "first",
            2,
            EntryKind::File,
        )
        .unwrap();
        add_entry_at_hash(
            tree.in_memory(),
            VER,
            case,
            DIR,
            hash,
            "second",
            3,
            EntryKind::Directory,
        )
        .unwrap();

        let first = lookup_at_hash(&tree, VER, case, DIR, hash, "first").unwrap();
        let second = lookup_at_hash(&tree, VER, case, DIR, hash, "second").unwrap();
        assert_eq!((first.inode, second.inode), (2, 3));

        remove_entry_at_hash(tree.in_memory(), VER, case, DIR, hash, "first").unwrap();
        assert!(lookup_at_hash(&tree, VER, case, DIR, hash, "first").is_none());
        assert_eq!(
            lookup_at_hash(&tree, VER, case, DIR, hash, "second")
                .unwrap()
                .inode,
            3
        );

        remove_entry_at_hash(tree.in_memory(), VER, case, DIR, hash, "second").unwrap();
        assert_eq!(view(&tree).item_count().unwrap(), 0);
    }

    #[test]
    fn listing_is_sorted_and_scoped_to_the_directory() {
        let (mut tree, case) = sensitive();
        for (name, inode) in [("zeta", 5), ("alpha", 2), ("midway", 3)] {
            add_entry(
                tree.in_memory(),
                SEED,
                VER,
                case,
                DIR,
                name,
                inode,
                EntryKind::File,
            )
            .unwrap();
        }
        add_entry(
            tree.in_memory(),
            SEED,
            VER,
            case,
            9,
            "elsewhere",
            7,
            EntryKind::File,
        )
        .unwrap();

        let names: Vec<String> = list_entries(view(&tree), DIR)
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, ["alpha", "midway", "zeta"]);
        assert_eq!(entry_count(view(&tree), DIR).unwrap(), 3);
        assert_eq!(entry_count(view(&tree), 9).unwrap(), 1);
        assert_eq!(entry_count(view(&tree), 8).unwrap(), 0);
    }

    #[test]
    fn seed_changes_hash_placement() {
        assert_ne!(dirent_hash(1, "name"), dirent_hash(2, "name"));
        assert_ne!(dirent_hash(SEED, "a"), dirent_hash(SEED, "b"));
    }

    #[test]
    fn name_validation_rejects_bad_names() {
        for bad in ["", ".", "..", "a/b", "nul\0byte"] {
            assert!(validate_name(bad).is_err(), "{bad:?}");
        }
        assert!(validate_name(&"x".repeat(256)).is_err());
        assert!(validate_name(&"x".repeat(255)).is_ok());
        assert!(validate_name("ordinary name.txt").is_ok());
    }
}
