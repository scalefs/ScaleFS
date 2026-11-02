#!/usr/bin/env python3
"""Generate ScaleFS's in-tree Unicode tables from pinned UCD extracts.

Reproducibility / maintenance tool. This is NOT run at build time: the build
is pure `cargo build` over the committed `../src/unicode/tables_17_0_0.rs`.
Run this by hand only to (re)generate that file from the vendored
`UnicodeData-<ver>.txt` and `CaseFolding-<ver>.txt` alongside this script.

Emitted tables (sorted by code point, for binary search at runtime):
  * CANONICAL_DECOMP  — fully-expanded canonical decomposition mappings.
    Compatibility decompositions (tagged `<...>` in UnicodeData field 5) are
    excluded; Hangul syllables are decomposed algorithmically at runtime and
    are therefore absent here.
  * COMBINING_CLASS   — non-zero canonical combining classes.
  * SIMPLE_FOLD       — Unicode simple case folding, CaseFolding.txt status
    C and S (each a 1:1 mapping).

Determinism: the output carries no timestamps and is fully sorted, so
re-running on the same inputs reproduces the file byte-for-byte.

Validation (before writing anything): the script re-implements the exact
runtime NFD on top of the tables it just built and checks it against
  1. `NormalizationTest-<ver>.txt` — Unicode's official conformance suite,
     the PRIMARY, version-independent oracle (every canonical NFD case); and
  2. Python's bundled `unicodedata`, but only when its version matches the
     pinned one (a full all-code-point sweep — a belt-and-braces second
     opinion).
plus the memo's §7 named vectors. Any mismatch aborts — unvalidated tables
are never emitted.

Usage:  python3 generate_unicode_tables.py
"""

import os
import sys
import unicodedata

VERSION = "17.0.0"
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "src", "unicode", "tables_17_0_0.rs")

# Hangul algorithmic decomposition constants (Unicode 3.12, "Hangul
# Syllable Decomposition"). Kept identical in the Rust runtime.
S_BASE, L_BASE, V_BASE, T_BASE = 0xAC00, 0x1100, 0x1161, 0x11A7
L_COUNT, V_COUNT, T_COUNT = 19, 21, 28
N_COUNT = V_COUNT * T_COUNT          # 588
S_COUNT = L_COUNT * N_COUNT          # 11172


def parse_unicode_data(path):
    """Return (ccc: {cp: klass}, decomp1: {cp: [cp,...]} one-step canonical)."""
    ccc = {}
    decomp1 = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if not line:
                continue
            fields = line.split(";")
            cp = int(fields[0], 16)
            klass = int(fields[3])
            if klass != 0:
                ccc[cp] = klass
            mapping = fields[5].strip()
            # A canonical decomposition has no `<compatibility>` tag.
            if mapping and not mapping.startswith("<"):
                decomp1[cp] = [int(x, 16) for x in mapping.split()]
    return ccc, decomp1


def full_decompose(decomp1):
    """Recursively expand each canonical decomposition to terminal form."""
    cache = {}

    def expand(cp, seen):
        if cp in cache:
            return cache[cp]
        if cp not in decomp1:
            return [cp]
        if cp in seen:
            raise ValueError(f"canonical decomposition cycle at U+{cp:04X}")
        seen = seen | {cp}
        out = []
        for element in decomp1[cp]:
            out.extend(expand(element, seen))
        cache[cp] = out
        return out

    return {cp: expand(cp, set()) for cp in decomp1}


def parse_case_folding(path):
    """Return {cp: cp} for simple folding (CaseFolding status C and S)."""
    fold = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split(";")]
            code = int(parts[0], 16)
            status = parts[1]
            if status in ("C", "S"):
                target = parts[2].split()
                if len(target) != 1:
                    raise ValueError(f"simple fold not 1:1 at U+{code:04X}")
                fold[code] = int(target[0], 16)
    return fold


def parse_normalization_test(path):
    """Return [(source, nfc, nfd)] scalar-string triples for every test line.

    NormalizationTest.txt columns: source; NFC; NFD; NFKC; NFKD; # comment.
    Section headers (`@PartN`) and comments are skipped.
    """
    cases = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith("@"):
                continue
            cols = line.split(";")

            def s(field):
                return "".join(chr(int(x, 16)) for x in field.split())

            cases.append((s(cols[0]), s(cols[1]), s(cols[2])))
    return cases


# ---- runtime NFD, re-implemented here to validate the emitted tables ----

def rt_decompose_char(cp, decompf, out):
    if S_BASE <= cp < S_BASE + S_COUNT:
        s = cp - S_BASE
        out.append(L_BASE + s // N_COUNT)
        out.append(V_BASE + (s % N_COUNT) // T_COUNT)
        t = s % T_COUNT
        if t != 0:
            out.append(T_BASE + t)
        return
    seq = decompf.get(cp)
    if seq is None:
        out.append(cp)
    else:
        out.extend(seq)


def rt_canonical_order(chars, ccc):
    n = len(chars)
    i = 1
    while i < n:
        c = ccc.get(chars[i], 0)
        if c != 0:
            p = ccc.get(chars[i - 1], 0)
            if p != 0 and p > c:
                chars[i - 1], chars[i] = chars[i], chars[i - 1]
                if i > 1:
                    i -= 1
                    continue
        i += 1


def rt_nfd(s, decompf, ccc):
    chars = []
    for ch in s:
        rt_decompose_char(ord(ch), decompf, chars)
    rt_canonical_order(chars, ccc)
    return "".join(chr(c) for c in chars)


def rt_simple_fold(s, fold):
    return "".join(chr(fold.get(ord(ch), ord(ch))) for ch in s)


def rt_caseless_key(s, decompf, ccc, fold):
    return rt_nfd(rt_simple_fold(rt_nfd(s, decompf, ccc), fold), decompf, ccc)


def validate(decompf, ccc, fold, norm_cases):
    # PRIMARY, version-independent oracle: the official conformance suite.
    # For every test line, source/NFC/NFD all decompose to the NFD column.
    for source, nfc, nfd in norm_cases:
        for form in (source, nfc, nfd):
            if rt_nfd(form, decompf, ccc) != nfd:
                raise SystemExit(f"ABORT: NormalizationTest NFD mismatch on {form!r}")
    print(f"  NFD == NormalizationTest.txt on {len(norm_cases)} conformance cases OK")

    # SECONDARY oracle: an all-code-point sweep, only when Python's bundled
    # UCD matches the pinned version.
    if unicodedata.unidata_version == VERSION:
        mismatches = 0
        for cp in range(0x110000):
            if 0xD800 <= cp <= 0xDFFF:  # surrogates are not scalar values
                continue
            ch = chr(cp)
            if rt_nfd(ch, decompf, ccc) != unicodedata.normalize("NFD", ch):
                mismatches += 1
        if mismatches:
            raise SystemExit(f"ABORT: {mismatches} unicodedata NFD mismatches")
        print(f"  NFD == unicodedata NFD for all code points ({VERSION}) OK")
    else:
        print(
            f"  (Python unicodedata is {unicodedata.unidata_version}, not the pinned "
            f"{VERSION}; NormalizationTest.txt is the oracle)"
        )

    # Named caseless vectors (the memo's §7 must-haves), version-independent.
    def key(s):
        return rt_caseless_key(s, decompf, ccc, fold)

    assert key("İ") == key("i̇"), "İ must fold-equal i + U+0307"
    assert key("I") == key("i"), "ASCII I/i must fold-equal"
    assert key("İ") != key("i"), "İ must NOT fold-equal bare i"
    assert "ι" in key("ͅ"), "U+0345 must fold to base iota"
    assert key("straße") != key("STRASSE"), "straße/STRASSE must coexist"
    print("  named caseless vectors (U+0130, I/i, U+0345, strasse/ss) OK")


# ------------------------------ emit ------------------------------

def wrap_pairs(entries, fmt, per_line):
    lines = []
    for start in range(0, len(entries), per_line):
        chunk = entries[start:start + per_line]
        lines.append("    " + " ".join(fmt(e) for e in chunk))
    return "\n".join(lines)


def emit(decompf, ccc, fold):
    decomp_items = sorted(decompf.items())
    ccc_items = sorted(ccc.items())
    fold_items = sorted(fold.items())

    body = []
    body.append(
        "//! Unicode {v} tables: canonical decomposition, canonical combining\n"
        "//! class, and simple case folding.\n"
        "//!\n"
        "//! GENERATED from the vendored UCD extracts by\n"
        "//! `unicode-tables/generate_unicode_tables.py`. Do not edit by hand;\n"
        "//! see `unicode-tables/README.md` for provenance and regeneration.\n".format(v=VERSION)
    )
    body.append(
        "/// Fully-expanded canonical decomposition mappings. Compatibility\n"
        "/// decompositions are excluded; Hangul is decomposed algorithmically\n"
        "/// at runtime and is absent here. Sorted by code point.\n"
        "#[rustfmt::skip]\n"
        "pub(super) static CANONICAL_DECOMP: &[(u32, &[u32])] = &[\n"
        + "\n".join(
            "    (0x{:04X}, &[{}]),".format(cp, ", ".join("0x{:04X}".format(x) for x in seq))
            for cp, seq in decomp_items
        )
        + "\n];\n"
    )
    body.append(
        "/// Non-zero canonical combining classes, sorted by code point.\n"
        "#[rustfmt::skip]\n"
        "pub(super) static COMBINING_CLASS: &[(u32, u8)] = &[\n"
        + wrap_pairs(ccc_items, lambda e: "(0x{:04X}, {}),".format(e[0], e[1]), 6)
        + "\n];\n"
    )
    body.append(
        "/// Unicode simple case folding (CaseFolding.txt status C and S),\n"
        "/// sorted by code point.\n"
        "#[rustfmt::skip]\n"
        "pub(super) static SIMPLE_FOLD: &[(u32, u32)] = &[\n"
        + wrap_pairs(fold_items, lambda e: "(0x{:04X}, 0x{:04X}),".format(e[0], e[1]), 4)
        + "\n];\n"
    )

    text = "\n".join(body)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print(
        f"  wrote {os.path.relpath(OUT, HERE)}: "
        f"{len(decomp_items)} decomp, {len(ccc_items)} ccc, {len(fold_items)} fold"
    )


def main():
    # The console may be a legacy code page (Windows cp1252); make our
    # progress output encoding-independent.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass
    ccc, decomp1 = parse_unicode_data(os.path.join(HERE, f"UnicodeData-{VERSION}.txt"))
    decompf = full_decompose(decomp1)
    fold = parse_case_folding(os.path.join(HERE, f"CaseFolding-{VERSION}.txt"))
    norm_cases = parse_normalization_test(os.path.join(HERE, f"NormalizationTest-{VERSION}.txt"))
    print(f"parsed: {len(decomp1)} canonical decomps, {len(ccc)} ccc, {len(fold)} simple folds, "
          f"{len(norm_cases)} normalization tests")
    validate(decompf, ccc, fold, norm_cases)
    emit(decompf, ccc, fold)
    print("done.")


if __name__ == "__main__":
    main()
