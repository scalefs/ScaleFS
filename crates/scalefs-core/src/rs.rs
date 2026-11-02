use crate::error::{Result, ScaleFsError};

pub const MAX_PARITY: usize = 3;

pub const MAX_DATA: usize = 64;

const GF_POLY: u32 = 0x11D;

static GF_EXP: [u8; 510] = build_exp();

static GF_LOG: [u8; 256] = build_log();

const fn build_exp() -> [u8; 510] {
    let mut exp = [0u8; 510];
    let mut x: u32 = 1;
    let mut i = 0;
    while i < 255 {
        exp[i] = x as u8;
        exp[i + 255] = x as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= GF_POLY;
        }
        i += 1;
    }
    exp
}

const fn build_log() -> [u8; 256] {
    let mut log = [0u8; 256];
    let mut x: u32 = 1;
    let mut i = 0;
    while i < 255 {
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= GF_POLY;
        }
        i += 1;
    }
    log
}

#[inline]
fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    GF_EXP[GF_LOG[a as usize] as usize + GF_LOG[b as usize] as usize]
}

#[inline]
fn gf_inv(a: u8) -> u8 {
    debug_assert_ne!(a, 0, "zero has no inverse");
    GF_EXP[255 - GF_LOG[a as usize] as usize]
}

#[inline]
fn coefficient(row: usize, col: usize) -> u8 {
    GF_EXP[(row * col) % 255]
}

fn validate_widths(data_count: usize, parity_count: usize) -> Result<()> {
    if data_count == 0 || data_count > MAX_DATA {
        return Err(ScaleFsError::InvalidArgument(
            "stripe data width is out of range",
        ));
    }
    if parity_count == 0 || parity_count > MAX_PARITY {
        return Err(ScaleFsError::InvalidArgument(
            "stripe parity width is out of range",
        ));
    }
    Ok(())
}

pub struct ParityEncoder {
    rows: Vec<Vec<u8>>,
}

impl ParityEncoder {
    pub fn new(parity_count: usize, coverage_len: usize) -> Result<Self> {
        validate_widths(1, parity_count)?;
        Ok(Self {
            rows: vec![vec![0u8; coverage_len]; parity_count],
        })
    }

    pub fn add_piece(&mut self, column: usize, bytes: &[u8]) -> Result<()> {
        if column >= MAX_DATA {
            return Err(ScaleFsError::InvalidArgument(
                "stripe data column is out of range",
            ));
        }
        if bytes.len() > self.rows[0].len() {
            return Err(ScaleFsError::InvalidArgument(
                "piece is longer than the stripe coverage",
            ));
        }
        for (row_index, row) in self.rows.iter_mut().enumerate() {
            let c = coefficient(row_index, column);
            if c == 1 {
                for (acc, byte) in row.iter_mut().zip(bytes) {
                    *acc ^= *byte;
                }
            } else {
                for (acc, byte) in row.iter_mut().zip(bytes) {
                    *acc ^= gf_mul(c, *byte);
                }
            }
        }
        Ok(())
    }

    pub fn finish(self) -> Vec<Vec<u8>> {
        self.rows
    }
}

pub fn generate_parity(
    pieces: &[&[u8]],
    parity_count: usize,
    coverage_len: usize,
) -> Result<Vec<Vec<u8>>> {
    validate_widths(pieces.len(), parity_count)?;
    let mut encoder = ParityEncoder::new(parity_count, coverage_len)?;
    for (column, piece) in pieces.iter().enumerate() {
        encoder.add_piece(column, piece)?;
    }
    Ok(encoder.finish())
}

pub fn reconstruct_data(
    data_count: usize,
    parity_count: usize,
    coverage_len: usize,
    available: &[(usize, &[u8])],
    erased_data: &[usize],
) -> Result<Vec<Vec<u8>>> {
    validate_widths(data_count, parity_count)?;
    if erased_data.is_empty() {
        return Ok(Vec::new());
    }
    let total = data_count + parity_count;
    let mut seen = vec![false; total];
    for &(column, bytes) in available {
        if column >= total {
            return Err(ScaleFsError::InvalidArgument(
                "available piece names a column outside the stripe",
            ));
        }
        if bytes.len() > coverage_len {
            return Err(ScaleFsError::InvalidArgument(
                "piece is longer than the stripe coverage",
            ));
        }
        if seen[column] {
            return Err(ScaleFsError::InvalidArgument(
                "a stripe column was supplied twice",
            ));
        }
        seen[column] = true;
    }
    let mut erased = vec![false; data_count];
    for &column in erased_data {
        if column >= data_count {
            return Err(ScaleFsError::InvalidArgument(
                "erased column is not a data column",
            ));
        }
        if seen[column] {
            return Err(ScaleFsError::InvalidArgument(
                "an erased column was also supplied as available",
            ));
        }
        if erased[column] {
            return Err(ScaleFsError::InvalidArgument(
                "an erased column was named twice",
            ));
        }
        erased[column] = true;
    }
    if let Some(column) = (0..data_count).find(|&c| !seen[c] && !erased[c]) {
        let _ = column;
        return Err(ScaleFsError::InvalidArgument(
            "a data column is neither available nor erased",
        ));
    }

    let e = erased_data.len();
    let parity_rows: Vec<(usize, &[u8])> = available
        .iter()
        .filter(|(column, _)| *column >= data_count)
        .map(|&(column, bytes)| (column - data_count, bytes))
        .take(e)
        .collect();
    if parity_rows.len() < e {
        return Err(ScaleFsError::Corrupt(
            "stripe has too few surviving pieces to reconstruct",
        ));
    }
    let mut rhs: Vec<Vec<u8>> = parity_rows
        .iter()
        .map(|(_, bytes)| {
            let mut row = vec![0u8; coverage_len];
            row[..bytes.len()].copy_from_slice(bytes);
            row
        })
        .collect();
    for &(column, bytes) in available {
        if column >= data_count {
            continue;
        }
        for ((row_index, _), row) in parity_rows.iter().zip(rhs.iter_mut()) {
            let c = coefficient(*row_index, column);
            if c == 1 {
                for (acc, byte) in row.iter_mut().zip(bytes) {
                    *acc ^= *byte;
                }
            } else {
                for (acc, byte) in row.iter_mut().zip(bytes) {
                    *acc ^= gf_mul(c, *byte);
                }
            }
        }
    }

    let matrix: Vec<Vec<u8>> = parity_rows
        .iter()
        .map(|(row_index, _)| {
            erased_data
                .iter()
                .map(|&column| coefficient(*row_index, column))
                .collect()
        })
        .collect();
    let inverse =
        invert(matrix).ok_or(ScaleFsError::Corrupt("stripe parity matrix is singular"))?;
    let out = inverse
        .iter()
        .map(|row| {
            let mut piece = vec![0u8; coverage_len];
            for (&factor, rhs_row) in row.iter().zip(&rhs) {
                if factor == 0 {
                    continue;
                }
                if factor == 1 {
                    for (acc, byte) in piece.iter_mut().zip(rhs_row) {
                        *acc ^= *byte;
                    }
                } else {
                    for (acc, byte) in piece.iter_mut().zip(rhs_row) {
                        *acc ^= gf_mul(factor, *byte);
                    }
                }
            }
            piece
        })
        .collect();
    Ok(out)
}

fn invert(mut m: Vec<Vec<u8>>) -> Option<Vec<Vec<u8>>> {
    let n = m.len();
    let mut inv: Vec<Vec<u8>> = (0..n)
        .map(|r| (0..n).map(|c| u8::from(r == c)).collect())
        .collect();
    for col in 0..n {
        let pivot = (col..n).find(|&r| m[r][col] != 0)?;
        m.swap(col, pivot);
        inv.swap(col, pivot);
        let scale = gf_inv(m[col][col]);
        for x in 0..n {
            m[col][x] = gf_mul(m[col][x], scale);
            inv[col][x] = gf_mul(inv[col][x], scale);
        }
        for row in 0..n {
            if row == col || m[row][col] == 0 {
                continue;
            }
            let factor = m[row][col];
            for x in 0..n {
                let a = gf_mul(factor, m[col][x]);
                m[row][x] ^= a;
                let b = gf_mul(factor, inv[col][x]);
                inv[row][x] ^= b;
            }
        }
    }
    Some(inv)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slow_mul(mut a: u8, mut b: u8) -> u8 {
        let mut acc = 0u8;
        while b != 0 {
            if b & 1 != 0 {
                acc ^= a;
            }
            let carry = a & 0x80 != 0;
            a <<= 1;
            if carry {
                a ^= (GF_POLY & 0xFF) as u8;
            }
            b >>= 1;
        }
        acc
    }

    fn pattern(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn tables_match_the_reference_multiplier_exactly() {
        assert_eq!(GF_EXP[0], 1);
        assert_eq!(GF_EXP[1], 2);
        assert_eq!(GF_EXP[8], 0x1D, "x^8 reduces to the low polynomial bits");
        assert_eq!(GF_EXP[255], 1, "the multiplicative order is 255");
        for i in 0..255 {
            assert_eq!(GF_EXP[i], GF_EXP[i + 255]);
            assert_eq!(GF_LOG[GF_EXP[i] as usize] as usize, i % 255);
        }
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(gf_mul(a, b), slow_mul(a, b), "{a} * {b}");
            }
        }
        for a in 1..=255u8 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1, "inv({a})");
        }
    }

    #[test]
    fn single_parity_is_plain_xor() {
        let pieces: Vec<Vec<u8>> = (0..5).map(|c| pattern(97, 100 + c)).collect();
        let refs: Vec<&[u8]> = pieces.iter().map(Vec::as_slice).collect();
        let parity = generate_parity(&refs, 1, 97).unwrap();
        let mut expect = vec![0u8; 97];
        for piece in &pieces {
            for (acc, byte) in expect.iter_mut().zip(piece) {
                *acc ^= *byte;
            }
        }
        assert_eq!(parity, vec![expect]);
    }

    #[test]
    fn incremental_and_one_shot_agree_with_zero_extension() {
        let pieces: Vec<Vec<u8>> = (0..4)
            .map(|c| pattern(40 + 13 * c as usize, 7 + c))
            .collect();
        let coverage = pieces.iter().map(Vec::len).max().unwrap();
        let refs: Vec<&[u8]> = pieces.iter().map(Vec::as_slice).collect();
        let one_shot = generate_parity(&refs, 3, coverage).unwrap();

        let mut encoder = ParityEncoder::new(3, coverage).unwrap();
        for column in [2usize, 0, 3, 1] {
            encoder.add_piece(column, &pieces[column]).unwrap();
        }
        assert_eq!(encoder.finish(), one_shot);

        let mut padded = pieces[0].clone();
        padded.resize(coverage, 0);
        let mut refs2 = refs.clone();
        refs2[0] = &padded;
        assert_eq!(generate_parity(&refs2, 3, coverage).unwrap(), one_shot);
    }

    #[test]
    fn every_erasure_set_solves_at_the_full_width() {
        let data: Vec<Vec<u8>> = (0..MAX_DATA).map(|c| vec![(c as u8) ^ 0x5A]).collect();
        let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
        let parity = generate_parity(&refs, MAX_PARITY, 1).unwrap();

        let mut solves = 0usize;
        let mut erased_sets: Vec<Vec<usize>> = Vec::new();
        for a in 0..MAX_DATA {
            erased_sets.push(vec![a]);
            for b in (a + 1)..MAX_DATA {
                erased_sets.push(vec![a, b]);
                for c in (b + 1)..MAX_DATA {
                    erased_sets.push(vec![a, b, c]);
                }
            }
        }
        for erased in &erased_sets {
            let need = erased.len();
            for row_mask in 1u32..(1 << MAX_PARITY) {
                if row_mask.count_ones() as usize != need {
                    continue;
                }
                let available: Vec<(usize, &[u8])> = (0..MAX_DATA)
                    .filter(|column| !erased.contains(column))
                    .map(|column| (column, data[column].as_slice()))
                    .chain(
                        (0..MAX_PARITY)
                            .filter(|row| row_mask & (1 << row) != 0)
                            .map(|row| {
                                let bytes: &[u8] = &parity[row];
                                (MAX_DATA + row, bytes)
                            }),
                    )
                    .collect();
                let rebuilt =
                    reconstruct_data(MAX_DATA, MAX_PARITY, 1, &available, erased).unwrap();
                for (bytes, &column) in rebuilt.iter().zip(erased) {
                    assert_eq!(bytes, &data[column], "erased {erased:?} rows {row_mask:#b}");
                }
                solves += 1;
            }
        }
        assert_eq!(solves, 47_904, "the sweep really ran in full");
    }

    #[test]
    fn every_erasure_pattern_reconstructs() {
        for k in 1..=6usize {
            for p in 1..=MAX_PARITY {
                let pieces: Vec<Vec<u8>> = (0..k)
                    .map(|c| pattern(31 + 9 * c, (k * 100 + p * 10 + c) as u64))
                    .collect();
                let coverage = pieces.iter().map(Vec::len).max().unwrap();
                let refs: Vec<&[u8]> = pieces.iter().map(Vec::as_slice).collect();
                let parity = generate_parity(&refs, p, coverage).unwrap();
                let total = k + p;

                for mask in 1u32..(1 << total) {
                    if mask.count_ones() as usize > p {
                        continue;
                    }
                    let erased: Vec<usize> = (0..total).filter(|c| mask & (1 << c) != 0).collect();
                    let erased_data: Vec<usize> =
                        erased.iter().copied().filter(|&c| c < k).collect();
                    let available: Vec<(usize, &[u8])> = (0..total)
                        .filter(|c| mask & (1 << c) == 0)
                        .map(|c| {
                            let bytes: &[u8] = if c < k { &pieces[c] } else { &parity[c - k] };
                            (c, bytes)
                        })
                        .collect();

                    let rebuilt = reconstruct_data(k, p, coverage, &available, &erased_data)
                        .unwrap_or_else(|err| panic!("k={k} p={p} mask={mask:b}: {err:?}"));
                    for (piece, &column) in rebuilt.iter().zip(&erased_data) {
                        let mut want = pieces[column].clone();
                        want.resize(coverage, 0);
                        assert_eq!(piece, &want, "k={k} p={p} mask={mask:b} col={column}");
                    }

                    let mut full: Vec<Vec<u8>> = pieces
                        .iter()
                        .map(|piece| {
                            let mut padded = piece.clone();
                            padded.resize(coverage, 0);
                            padded
                        })
                        .collect();
                    for (piece, &column) in rebuilt.iter().zip(&erased_data) {
                        full[column] = piece.clone();
                    }
                    let full_refs: Vec<&[u8]> = full.iter().map(Vec::as_slice).collect();
                    let regenerated = generate_parity(&full_refs, p, coverage).unwrap();
                    for &column in erased.iter().filter(|&&c| c >= k) {
                        assert_eq!(
                            regenerated[column - k],
                            parity[column - k],
                            "k={k} p={p} mask={mask:b} parity row {}",
                            column - k
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn wide_stripes_reconstruct_at_the_cap() {
        let k = MAX_DATA;
        let p = MAX_PARITY;
        let pieces: Vec<Vec<u8>> = (0..k).map(|c| pattern(64, 5000 + c as u64)).collect();
        let coverage = 64;
        let refs: Vec<&[u8]> = pieces.iter().map(Vec::as_slice).collect();
        let parity = generate_parity(&refs, p, coverage).unwrap();
        for erased_data in [vec![0usize, 31, 63], vec![1, 2, 3], vec![62, 63, 0]] {
            let available: Vec<(usize, &[u8])> = (0..k)
                .filter(|c| !erased_data.contains(c))
                .map(|c| (c, pieces[c].as_slice()))
                .chain((0..p).map(|j| (k + j, parity[j].as_slice())))
                .collect();
            let rebuilt = reconstruct_data(k, p, coverage, &available, &erased_data).unwrap();
            for (piece, &column) in rebuilt.iter().zip(&erased_data) {
                assert_eq!(piece, &pieces[column]);
            }
        }
    }

    #[test]
    fn impossible_and_malformed_reconstructions_are_refused() {
        let pieces: Vec<Vec<u8>> = (0..3).map(|c| pattern(16, 40 + c)).collect();
        let refs: Vec<&[u8]> = pieces.iter().map(Vec::as_slice).collect();
        let parity = generate_parity(&refs, 1, 16).unwrap();

        let available = vec![(2usize, pieces[2].as_slice()), (3, parity[0].as_slice())];
        assert!(matches!(
            reconstruct_data(3, 1, 16, &available, &[0, 1]),
            Err(ScaleFsError::Corrupt(_))
        ));
        let available = vec![(3usize, parity[0].as_slice()), (0, pieces[0].as_slice())];
        assert!(matches!(
            reconstruct_data(3, 1, 16, &available, &[1]),
            Err(ScaleFsError::InvalidArgument(_))
        ));
        let available = vec![
            (0usize, pieces[0].as_slice()),
            (1, pieces[1].as_slice()),
            (2, pieces[2].as_slice()),
            (3, parity[0].as_slice()),
        ];
        assert!(matches!(
            reconstruct_data(3, 1, 16, &available, &[0]),
            Err(ScaleFsError::InvalidArgument(_))
        ));
        assert!(generate_parity(&refs, MAX_PARITY + 1, 16).is_err());
        assert!(ParityEncoder::new(0, 16).is_err());
    }

    #[test]
    fn golden_parity_fixture_is_stable() {
        let pieces = [
            b"scalefs parity golden 0".as_slice(),
            b"scalefs parity golden 11".as_slice(),
            b"scalefs golden 2".as_slice(),
        ];
        let parity = generate_parity(&pieces, 2, 24).unwrap();
        assert_eq!(
            hex(&parity[0]),
            "7363616c65667320676f6c64656e20320000000000000131"
        );
        assert_eq!(
            hex(&parity[1]),
            "44343a19262f44e011023b36152ee061b1b4acafb2605262"
        );
    }

    #[test]
    #[ignore = "manual throughput measurement"]
    fn parity_throughput() {
        let piece = pattern(1 << 20, 99);
        for p in 1..=MAX_PARITY {
            let start = std::time::Instant::now();
            let mut encoder = ParityEncoder::new(p, piece.len()).unwrap();
            let rounds = 64usize;
            for round in 0..rounds {
                encoder.add_piece(round % MAX_DATA, &piece).unwrap();
            }
            let elapsed = start.elapsed();
            let mib = (rounds * piece.len()) as f64 / (1 << 20) as f64;
            println!("p={p}: {:.0} MiB/s generate", mib / elapsed.as_secs_f64());
        }
    }
}
