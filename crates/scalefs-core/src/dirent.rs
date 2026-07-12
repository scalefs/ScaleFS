
use crate::error::{Result, ScaleFsError};
use crate::layout::CaseSensitivity;
use crate::tree::{
    DirEntry, EntryKind, ITEM_DIRENT, MAX_NAME_LEN, MetadataKey, MetadataTree, MetadataValue,
};

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

pub fn fold_name(case: CaseSensitivity, name: &str) -> String {
    match case {
        CaseSensitivity::Sensitive => name.to_string(),
        CaseSensitivity::InsensitivePreserving => name.to_ascii_lowercase(),
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

fn names_equal(case: CaseSensitivity, a: &str, b: &str) -> bool {
    match case {
        CaseSensitivity::Sensitive => a == b,
        CaseSensitivity::InsensitivePreserving => a.eq_ignore_ascii_case(b),
    }
}

pub fn add_entry(
    tree: &mut MetadataTree,
    seed: u64,
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
    let hash = dirent_hash(seed, &fold_name(case, name));
    add_entry_at_hash(tree, case, dir, hash, name, inode, kind)
}

fn add_entry_at_hash(
    tree: &mut MetadataTree,
    case: CaseSensitivity,
    dir: u64,
    hash: u64,
    name: &str,
    inode: u64,
    kind: EntryKind,
) -> Result<()> {
    let key = dirent_key(dir, hash);
    let mut entries = match tree.get(key) {
        Some(MetadataValue::DirEntries(entries)) => entries.clone(),
        Some(_) => return Err(ScaleFsError::Corrupt("non-bucket value at a dirent key")),
        None => Vec::new(),
    };
    if entries.iter().any(|e| names_equal(case, &e.name, name)) {
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
    tree: &MetadataTree,
    seed: u64,
    case: CaseSensitivity,
    dir: u64,
    name: &str,
) -> Option<DirEntry> {
    let hash = dirent_hash(seed, &fold_name(case, name));
    lookup_entry_at_hash(tree, case, dir, hash, name)
}

fn lookup_entry_at_hash(
    tree: &MetadataTree,
    case: CaseSensitivity,
    dir: u64,
    hash: u64,
    name: &str,
) -> Option<DirEntry> {
    match tree.get(dirent_key(dir, hash)) {
        Some(MetadataValue::DirEntries(entries)) => entries
            .iter()
            .find(|e| names_equal(case, &e.name, name))
            .cloned(),
        _ => None,
    }
}

pub fn remove_entry(
    tree: &mut MetadataTree,
    seed: u64,
    case: CaseSensitivity,
    dir: u64,
    name: &str,
) -> Result<DirEntry> {
    let hash = dirent_hash(seed, &fold_name(case, name));
    remove_entry_at_hash(tree, case, dir, hash, name)
}

fn remove_entry_at_hash(
    tree: &mut MetadataTree,
    case: CaseSensitivity,
    dir: u64,
    hash: u64,
    name: &str,
) -> Result<DirEntry> {
    let key = dirent_key(dir, hash);
    let mut entries = match tree.get(key) {
        Some(MetadataValue::DirEntries(entries)) => entries.clone(),
        Some(_) => return Err(ScaleFsError::Corrupt("non-bucket value at a dirent key")),
        None => return Err(ScaleFsError::NotFound),
    };
    let index = entries
        .iter()
        .position(|e| names_equal(case, &e.name, name))
        .ok_or(ScaleFsError::NotFound)?;
    let removed = entries.remove(index);
    if entries.is_empty() {
        tree.remove(key);
    } else {
        tree.insert(key, MetadataValue::DirEntries(entries))?;
    }
    Ok(removed)
}

pub fn list_entries(tree: &MetadataTree, dir: u64) -> Vec<DirEntry> {
    let start = dirent_key(dir, 0);
    let end = dirent_key(dir, u64::MAX);
    let mut out = Vec::new();
    for (_, value) in tree.range(start, end) {
        if let MetadataValue::DirEntries(entries) = value {
            out.extend(entries.iter().cloned());
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

pub fn entry_count(tree: &MetadataTree, dir: u64) -> usize {
    let start = dirent_key(dir, 0);
    let end = dirent_key(dir, u64::MAX);
    tree.range(start, end)
        .iter()
        .map(|(_, value)| match value {
            MetadataValue::DirEntries(entries) => entries.len(),
            _ => 0,
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: u64 = 0x5EED_CAFE_F00D_0001;
    const DIR: u64 = 1;

    fn sensitive() -> (MetadataTree, CaseSensitivity) {
        (MetadataTree::new(), CaseSensitivity::Sensitive)
    }

    fn insensitive() -> (MetadataTree, CaseSensitivity) {
        (MetadataTree::new(), CaseSensitivity::InsensitivePreserving)
    }

    #[test]
    fn add_lookup_remove_round_trip() {
        let (mut tree, case) = sensitive();
        add_entry(&mut tree, SEED, case, DIR, "hello.txt", 2, EntryKind::File).unwrap();
        let entry = lookup_entry(&tree, SEED, case, DIR, "hello.txt").unwrap();
        assert_eq!(entry.inode, 2);
        assert_eq!(entry.kind, EntryKind::File);

        assert!(matches!(
            add_entry(&mut tree, SEED, case, DIR, "hello.txt", 3, EntryKind::File),
            Err(ScaleFsError::AlreadyExists)
        ));

        let removed = remove_entry(&mut tree, SEED, case, DIR, "hello.txt").unwrap();
        assert_eq!(removed.inode, 2);
        assert!(lookup_entry(&tree, SEED, case, DIR, "hello.txt").is_none());
        assert!(matches!(
            remove_entry(&mut tree, SEED, case, DIR, "hello.txt"),
            Err(ScaleFsError::NotFound)
        ));
    }

    #[test]
    fn insensitive_pools_fold_ascii_case() {
        let (mut tree, case) = insensitive();
        add_entry(&mut tree, SEED, case, DIR, "ReadMe.MD", 2, EntryKind::File).unwrap();
        let entry = lookup_entry(&tree, SEED, case, DIR, "readme.md").unwrap();
        assert_eq!(entry.name, "ReadMe.MD");
        assert!(lookup_entry(&tree, SEED, case, DIR, "README.MD").is_some());
        assert!(matches!(
            add_entry(&mut tree, SEED, case, DIR, "readme.md", 3, EntryKind::File),
            Err(ScaleFsError::AlreadyExists)
        ));
        remove_entry(&mut tree, SEED, case, DIR, "rEaDmE.mD").unwrap();
        assert!(lookup_entry(&tree, SEED, case, DIR, "ReadMe.MD").is_none());
    }

    #[test]
    fn sensitive_pools_keep_casings_distinct() {
        let (mut tree, case) = sensitive();
        add_entry(&mut tree, SEED, case, DIR, "File", 2, EntryKind::File).unwrap();
        add_entry(&mut tree, SEED, case, DIR, "file", 3, EntryKind::File).unwrap();
        assert_eq!(
            lookup_entry(&tree, SEED, case, DIR, "File").unwrap().inode,
            2
        );
        assert_eq!(
            lookup_entry(&tree, SEED, case, DIR, "file").unwrap().inode,
            3
        );
    }

    #[test]
    fn folding_is_ascii_only_by_design() {
        let (mut tree, case) = insensitive();
        add_entry(&mut tree, SEED, case, DIR, "café", 2, EntryKind::File).unwrap();
        add_entry(&mut tree, SEED, case, DIR, "CAFÉ", 3, EntryKind::File).unwrap();
        assert_eq!(
            lookup_entry(&tree, SEED, case, DIR, "café").unwrap().inode,
            2
        );
        assert_eq!(
            lookup_entry(&tree, SEED, case, DIR, "cafÉ").unwrap().inode,
            3
        );
    }

    #[test]
    fn colliding_hashes_share_a_bucket_correctly() {
        let (mut tree, case) = sensitive();
        let hash = 42;
        add_entry_at_hash(&mut tree, case, DIR, hash, "first", 2, EntryKind::File).unwrap();
        add_entry_at_hash(
            &mut tree,
            case,
            DIR,
            hash,
            "second",
            3,
            EntryKind::Directory,
        )
        .unwrap();

        let first = lookup_entry_at_hash(&tree, case, DIR, hash, "first").unwrap();
        let second = lookup_entry_at_hash(&tree, case, DIR, hash, "second").unwrap();
        assert_eq!((first.inode, second.inode), (2, 3));

        remove_entry_at_hash(&mut tree, case, DIR, hash, "first").unwrap();
        assert!(lookup_entry_at_hash(&tree, case, DIR, hash, "first").is_none());
        assert_eq!(
            lookup_entry_at_hash(&tree, case, DIR, hash, "second")
                .unwrap()
                .inode,
            3
        );

        remove_entry_at_hash(&mut tree, case, DIR, hash, "second").unwrap();
        assert_eq!(tree.item_count(), 0);
    }

    #[test]
    fn listing_is_sorted_and_scoped_to_the_directory() {
        let (mut tree, case) = sensitive();
        for (name, inode) in [("zeta", 5), ("alpha", 2), ("midway", 3)] {
            add_entry(&mut tree, SEED, case, DIR, name, inode, EntryKind::File).unwrap();
        }
        add_entry(&mut tree, SEED, case, 9, "elsewhere", 7, EntryKind::File).unwrap();

        let names: Vec<String> = list_entries(&tree, DIR)
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, ["alpha", "midway", "zeta"]);
        assert_eq!(entry_count(&tree, DIR), 3);
        assert_eq!(entry_count(&tree, 9), 1);
        assert_eq!(entry_count(&tree, 8), 0);
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
