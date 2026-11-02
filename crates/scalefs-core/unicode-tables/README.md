# ScaleFS Unicode tables — provenance & regeneration

ScaleFS keys every directory entry on a canonical form of the name (NFD, plus
simple case folding on case-insensitive pools). That canonical form is part of
the **on-disk format**: it decides which hash bucket a name lands in. It must
therefore be pinned to one Unicode version for the life of a pool and must
never drift with the host's system libraries.

This directory holds the pinned source data and the generator that turns it
into the committed Rust tables. The build itself never runs the generator —
it is a plain `cargo build` over the generated file. (These extracts are dev
provenance, not needed to compile; the publish tarball can exclude this
directory.)

## Pinned version

**Unicode 17.0.0** (released 2025-09-09).

A pool records its Unicode version in the superblock (`unicode_version`) and is
tied to it forever. Newer ScaleFS releases carry additional versions' tables
*append-only* (an older pool always opens on an equal-or-newer build); a pool
whose version this build does not carry is refused with an upgrade message.
See `src/unicode/mod.rs`.

## Vendored inputs (unmodified upstream)

- `UnicodeData-17.0.0.txt` — <https://www.unicode.org/Public/17.0.0/ucd/UnicodeData.txt>
- `CaseFolding-17.0.0.txt` — <https://www.unicode.org/Public/17.0.0/ucd/CaseFolding.txt>
- `NormalizationTest-17.0.0.txt` — <https://www.unicode.org/Public/17.0.0/ucd/NormalizationTest.txt>
  (the official conformance suite; used only to validate the generated tables)

These are byte-for-byte the official Unicode Character Database files
(`.gitattributes` keeps them LF so they stay diffable against unicode.org).
They are distributed under the Unicode License
(<https://www.unicode.org/license.txt>), permissive and compatible with
ScaleFS's MIT/Apache-2.0 licensing; they are generator input only.

Fields used: `UnicodeData` field 3 (canonical combining class) and field 5
(canonical decomposition, i.e. mappings with no `<compatibility>` tag);
`CaseFolding` status `C` and `S` lines (simple 1:1 folding). Hangul syllables
are decomposed algorithmically at runtime, not from a table.

## Regeneration

```
python3 generate_unicode_tables.py
```

Before writing anything the generator re-implements the exact runtime NFD on
top of the tables it builds and validates it against, in order:

1. **`NormalizationTest-17.0.0.txt`** — Unicode's official conformance suite,
   the primary and *version-independent* oracle (every canonical NFD case);
2. **Python's bundled `unicodedata`** — a full all-code-point sweep, but only
   when Python's UCD version matches the pinned one (a second opinion; skipped
   with a note otherwise, e.g. CPython 3.14 ships Unicode 16.0.0);

plus the memo's §7 named vectors. Any mismatch aborts. Output is deterministic
(sorted, no timestamps): regenerating on the same inputs reproduces
`../src/unicode/tables_17_0_0.rs` byte-for-byte.

## Adding a future Unicode version (append-only)

1. Vendor `UnicodeData-<new>.txt`, `CaseFolding-<new>.txt`, and
   `NormalizationTest-<new>.txt` here.
2. Point the generator at `<new>` and emit `tables_<new>.rs` (keep 17.0.0
   forever).
3. Register the new `UnicodeVersion` in `src/unicode/mod.rs`
   (`SUPPORTED_UNICODE_VERSIONS`, table selection). Never remove an old one —
   that would break the forward-compatibility invariant.
