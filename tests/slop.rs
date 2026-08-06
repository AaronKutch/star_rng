use star_rng::StarRng;

// slop statistical regression guards for the internal bit buffer

/// Every bit position of a `width`-bit draw must be set with probability 1/2.
/// Widths 1..=32 exercise a single `consume`; widths > 32 exercise the
/// multi-word path that mixes full `internal_next_u32` words with a trailing
/// partial consume.
#[test]
#[cfg(not(debug_assertions))]
fn bit_density() {
    const N: u64 = 1 << 17;
    let widths = (1..=32usize).chain([33, 40, 48, 56, 63, 64, 65, 96, 100, 127, 128]);
    for w in widths {
        let mut ones = [0u64; 128];
        for seed in 0..4u64 {
            let mut rng = StarRng::new(seed);
            for _ in 0..N {
                let v = rng.next_width_u128(w).unwrap();
                for b in 0..w {
                    ones[b] += ((v >> b) & 1) as u64;
                }
            }
        }
        let total = (N * 4) as f64;
        for b in 0..w {
            let p = ones[b] as f64 / total;
            assert!(
                (p - 0.5).abs() < 0.01,
                "next_width_u128({w}) bit {b} is biased: P(1) = {p}"
            );
        }
    }
}

/// Normalized chi-square statistic: `|z|` stays within a few sigma under
/// uniformity and explodes for biased output.
fn chi2_z(hist: &[u64]) -> f64 {
    let total: u64 = hist.iter().sum();
    let e = total as f64 / hist.len() as f64;
    let chi2: f64 = hist.iter().map(|&o| (o as f64 - e).powi(2) / e).sum();
    let df = (hist.len() - 1) as f64;
    (chi2 - df) / (2.0 * df).sqrt()
}

/// Chi-square uniformity check on ranges that require multiple 32-bit words,
/// which exercises the word/partial-consume boundary that bit-exact tests
/// cannot see.
#[test]
#[cfg(not(debug_assertions))]
fn chi_square_uniformity() {
    const BUCKETS: usize = 1000;
    const N: u64 = 1 << 22;

    // `uniform_u64` over 0..10^12 needs a 40-bit draw (one word + `consume(8)`).
    // `range` is divisible by `BUCKETS` so the buckets are exactly equal width.
    let range: u64 = 1_000_000_000_000;
    let mut hist = vec![0u64; BUCKETS];
    let mut rng = StarRng::new(0);
    for _ in 0..N {
        let v = rng.uniform_u64(range - 1);
        hist[(v / (range / BUCKETS as u64)) as usize] += 1;
    }
    let z = chi2_z(&hist);
    assert!(z.abs() < 8.0, "uniform_u64 is non-uniform: chi2_z = {z}");

    // `index` over 0..1_000_000
    let range = 1_000_000usize;
    let mut hist = vec![0u64; BUCKETS];
    let mut rng = StarRng::new(1);
    for _ in 0..N {
        let v = rng.index(range).unwrap();
        hist[v / (range / BUCKETS)] += 1;
    }
    let z = chi2_z(&hist);
    assert!(z.abs() < 8.0, "index is non-uniform: chi2_z = {z}");

    // `index_inclusive` over 0..1_000_000
    let range = 1_000_000usize;
    let mut hist = vec![0u64; BUCKETS];
    let mut rng = StarRng::new(2);
    for _ in 0..N {
        let v = rng.index_inclusive(range - 1);
        hist[v / (range / BUCKETS)] += 1;
    }
    let z = chi2_z(&hist);
    assert!(
        z.abs() < 8.0,
        "index_inclusive is non-uniform: chi2_z = {z}"
    );
}

/// Sample count for statistical tests: enough to be meaningful in release,
/// reduced in debug so a plain `cargo test` still exercises the code path.
fn stat_samples(release: u32, debug: u32) -> u64 {
    1 << if cfg!(debug_assertions) {
        debug
    } else {
        release
    }
}

/// Lehmer code -> index in `0..n!`, a bijection on permutations of `0..n`.
fn perm_index(p: &[usize]) -> usize {
    let n = p.len();
    let mut inx = 0;
    for i in 0..n {
        let mut smaller = 0;
        for j in (i + 1)..n {
            if p[j] < p[i] {
                smaller += 1;
            }
        }
        inx = inx * (n - i) + smaller;
    }
    inx
}

/// Structural invariants for every length and `num`: the slice stays a
/// permutation of itself, and the split lands where the docs say.
#[test]
fn shuffle_structure() {
    let mut rng = StarRng::new(0);
    for len in 0..24usize {
        for num in 0..=(len + 2) {
            let mut v: Vec<usize> = (0..len).collect();
            let (shuffled, rest) = rng.partial_shuffle(&mut v, num);
            let expected = num.min(len);
            assert_eq!(shuffled.len(), expected);
            assert_eq!(rest.len(), len - expected);
            v.sort_unstable();
            assert!(v.iter().copied().eq(0..len), "len {len} num {num}");

            let mut v: Vec<usize> = (0..len).collect();
            rng.shuffle(&mut v);
            v.sort_unstable();
            assert!(v.iter().copied().eq(0..len), "len {len}");
        }
    }
}

/// Degenerate cases must not panic and must not consume RNG state, so
/// shuffling an empty or single-element slice is unobservable.
#[test]
fn shuffle_degenerate() {
    for len in 0..2usize {
        let mut a = StarRng::new(7);
        let mut b = StarRng::new(7);
        let mut v: Vec<usize> = (0..len).collect();
        a.shuffle(&mut v);
        assert!(v.iter().copied().eq(0..len));
        assert_eq!(a.next_u64(), b.next_u64(), "len {len} consumed state");
    }

    // `num == 0` is a no-op on any length
    let mut a = StarRng::new(7);
    let mut b = StarRng::new(7);
    let mut v: Vec<usize> = (0..64).collect();
    let (shuffled, rest) = a.partial_shuffle(&mut v, 0);
    assert!(shuffled.is_empty());
    assert_eq!(rest.len(), 64);
    assert!(v.iter().copied().eq(0..64));
    assert_eq!(a.next_u64(), b.next_u64());
}

/// `shuffle` must agree with `partial_shuffle` at and above `len`, in both
/// output and resulting state, since it is defined in terms of it. Also
/// checks that `num` is clamped rather than wrapping.
#[test]
fn shuffle_agrees_with_partial() {
    for len in 0..32usize {
        let mut a = StarRng::new(len as u64);
        let mut b = StarRng::new(len as u64);
        let mut c = StarRng::new(len as u64);

        let mut va: Vec<usize> = (0..len).collect();
        let mut vb: Vec<usize> = (0..len).collect();
        let mut vc: Vec<usize> = (0..len).collect();

        a.shuffle(&mut va);
        let _ = b.partial_shuffle(&mut vb, len);
        let (_, rest) = c.partial_shuffle(&mut vc, usize::MAX);

        assert!(rest.is_empty());
        assert_eq!(va, vb, "len {len}");
        assert_eq!(va, vc, "len {len}");
        assert_eq!(a.next_u64(), b.next_u64(), "len {len} state differs");
        assert_eq!(a.next_u64(), c.next_u64(), "len {len} state differs");
    }
}

/// The last step of a full shuffle draws from a one-element range, so
/// `num == len` and `num == len - 1` must produce the same permutation.
#[test]
fn shuffle_final_step_is_a_noop() {
    for len in 1..32usize {
        let mut a = StarRng::new(len as u64);
        let mut b = StarRng::new(len as u64);
        let mut va: Vec<usize> = (0..len).collect();
        let mut vb: Vec<usize> = (0..len).collect();
        let _ = a.partial_shuffle(&mut va, len);
        let _ = b.partial_shuffle(&mut vb, len - 1);
        assert_eq!(va, vb, "len {len}");
        assert_eq!(a.next_u64(), b.next_u64(), "len {len} state differs");
    }
}

/// The point of `partial_shuffle`: exactly `num` index draws no matter how
/// long the slice is. Replaying those draws by hand must land the RNG in an
/// identical state.
#[test]
fn partial_shuffle_draw_count() {
    const LEN: usize = 1 << 16;
    for num in [1usize, 2, 4, 17] {
        let mut a = StarRng::new(0);
        let mut b = StarRng::new(0);
        let mut v: Vec<usize> = (0..LEN).collect();
        let _ = a.partial_shuffle(&mut v, num);
        for i in 0..num {
            let _ = b.index_inclusive(LEN - 1 - i);
        }
        assert_eq!(a.next_u64(), b.next_u64(), "num {num} draw count differs");
    }
}

/// All `4! == 24` permutations of a 4-element slice must be equally likely.
/// Catches an inclusive/exclusive slip in the `len - 1 - i` bound and any
/// modulo bias leaking in through `index_inclusive`.
#[test]
fn shuffle_uniformity() {
    let n = stat_samples(21, 14);
    let mut hist = [0u64; 24];
    let mut rng = StarRng::new(0);
    for _ in 0..n {
        let mut v = [0usize, 1, 2, 3];
        rng.shuffle(&mut v);
        hist[perm_index(&v)] += 1;
    }
    let z = chi2_z(&hist);
    assert!(z.abs() < 8.0, "shuffle is non-uniform: chi2_z = {z}");
}

/// The prefix must be uniform over *ordered* samples without replacement:
/// all `P(4, 2) == 12` ordered pairs equally likely, none repeating an
/// element. At `num == len` the loop bounds coincide at the ends, so a
/// full-shuffle test cannot see an off-by-one in `len - 1 - i`.
#[test]
fn partial_shuffle_uniformity() {
    let n = stat_samples(21, 14);
    let mut hist = [0u64; 16];
    let mut rng = StarRng::new(0);
    for _ in 0..n {
        let mut v = [0usize, 1, 2, 3];
        let (shuffled, _) = rng.partial_shuffle(&mut v, 2);
        hist[(shuffled[0] * 4) + shuffled[1]] += 1;
    }

    // diagonal entries would mean an element was drawn twice
    let mut pairs = Vec::with_capacity(12);
    for a in 0..4 {
        for b in 0..4 {
            let count = hist[(a * 4) + b];
            if a == b {
                assert_eq!(count, 0, "sampled {a} twice");
            } else {
                pairs.push(count);
            }
        }
    }
    let z = chi2_z(&pairs);
    assert!(
        z.abs() < 8.0,
        "partial_shuffle is non-uniform: chi2_z = {z}"
    );
}
