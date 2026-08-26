use std::cmp::max;

use rand_xoshiro::rand_core::Rng;
use star_rng::StarRng;

// NOTE: there are other tests upstream in `awint`

// downstream crates will rely on a deterministic behavior
#[test]
#[allow(clippy::bool_assert_comparison)]
fn test_vectors() {
    let mut rng = StarRng::new(0);
    let mut dst = [0; 65];
    rng.fill_bytes(&mut dst);
    assert_eq!(dst, [
        93, 4, 201, 222, 117, 157, 8, 154, 98, 211, 119, 171, 5, 100, 225, 195, 218, 168, 149, 92,
        86, 160, 222, 96, 64, 81, 90, 194, 20, 6, 41, 164, 175, 37, 5, 158, 185, 55, 61, 149, 119,
        59, 151, 202, 87, 132, 44, 54, 8, 210, 248, 126, 178, 2, 132, 201, 166, 209, 126, 231, 27,
        64, 168, 234, 98
    ]);

    assert_eq!(rng.index(1 << 15).unwrap(), 27303);
    assert_eq!(*rng.index_slice(&dst).unwrap(), 5);
    assert_eq!(*rng.index_slice_mut(&mut dst).unwrap(), 231);
    assert_eq!(rng.next_bool(), false);
    assert_eq!(rng.next_u8(), 60);
    assert_eq!(rng.next_u16(), 55860);
    assert_eq!(rng.next_u32(), 1142491458);
    assert_eq!(rng.next_u64(), 7750222263744231949);
    assert_eq!(rng.next_u128(), 107347936578185361932231794775361051828);
    assert_eq!(rng.out_of_4(1), false);
    assert_eq!(rng.out_of_8(3), true);
    assert_eq!(rng.out_of_16(7), true);
    assert_eq!(rng.out_of_32(20), false);
    assert_eq!(rng.out_of_64(31), true);
    assert_eq!(rng.out_of_128(50), false);
    assert_eq!(rng.out_of_256(100), false);
    assert_eq!(rng.uniform_u8(u8::MAX / 8), 31);
    assert_eq!(rng.uniform_u16(u16::MAX / 8), 2436);
    assert_eq!(rng.uniform_u32(u32::MAX / 8), 414907957);
    assert_eq!(rng.uniform_u64(u64::MAX / 8), 1339345442184903593);
    assert_eq!(
        rng.uniform_u128(u128::MAX / 8),
        13939501709697904127631821811304380035
    );

    assert_eq!(rng.bits_consumed(), 1094);
}

#[test]
fn test_vectors2() {
    let mut rng = StarRng::new(0);
    let mut dst = [0; 65];
    rng.fill_bytes(&mut dst);

    assert_eq!(rng.index_inclusive(0), 0);
    assert_eq!(rng.index_inclusive(1 << 15), 27303);
    assert_eq!(rng.index_inclusive(1), 1);
    assert_eq!(rng.index_inclusive(1), 0);
    assert_eq!(rng.index_inclusive(1), 0);
    assert_eq!(rng.index_inclusive(1), 0);
    assert_eq!(rng.index_inclusive(1), 1);

    assert_eq!(rng.index_inclusive(2), 2);
    assert_eq!(rng.index_inclusive(2), 0);
}

#[test]
fn star_rng() {
    let mut rng0 = StarRng::new(0);
    let n = 1_000_000;

    let mut yes = 0u64;
    for _ in 0..n {
        yes += rng0.out_of_128(42) as u64;
    }
    assert_eq!(yes, 327464);
    let mut yes = 0u64;
    for _ in 0..n {
        yes += rng0.out_of_256(84) as u64;
    }
    assert_eq!(yes, 328435);
    for _ in 0..n {
        assert!(!rng0.out_of_128(0))
    }
    let mut yes = 0u64;
    for _ in 0..n {
        yes += rng0.out_of_128(127) as u64;
    }
    assert_eq!(yes, 992168);
    for _ in 0..n {
        assert!(rng0.out_of_128(128))
    }
    for _ in 0..n {
        assert!(!rng0.out_of_256(0))
    }
    let mut yes = 0u64;
    for _ in 0..n {
        yes += rng0.out_of_256(255) as u64;
    }
    assert_eq!(yes, 996064);
    let mut yes = 0u64;
    for _ in 0..n {
        yes += rng0.out_of_4(3) as u64;
    }
    assert_eq!(yes, 749947);

    let mut rng0 = StarRng::new(0);
    assert!(rng0.index(0).is_none());
    assert!(rng0.index_slice(&[0u8; 0]).is_none());
    let mut slice = vec![0u64; 7];
    for _ in 0..n {
        *rng0.index_slice_mut(&mut slice).unwrap() += 1;
    }
    for e in slice {
        assert!((142409..=143532).contains(&e));
    }
}

#[test]
#[cfg(not(debug_assertions))]
fn uniform() {
    let mut rng0 = StarRng::new(0);
    for max in 0..=255 {
        let mut slice = [0u32; 256];
        let n = 1 << 18;
        for _ in 0..n {
            slice[usize::from(rng0.uniform_u8(max))] += 1;
        }
        for i in ((max as usize) + 1)..256 {
            assert_eq!(slice[i], 0);
        }
        let avg = n / ((max as u32) + 1);
        // approximate division by square root, with adjustments to reduce freak
        // outliers to 0
        let dev = avg.div_ceil(1 << (((avg.next_power_of_two().trailing_zeros() - 1) / 2) - 2));
        for i in 0..(max as usize) {
            // check for bias
            let v = slice[i];
            assert!((v > (avg - dev)) && (v < (avg + dev)));
        }
    }
}

#[test]
fn loops() {
    // copied from the `index` and `uniform` methods, check that the number of
    // expected retries is happening

    fn retries(rng: &mut StarRng, len: usize) -> usize {
        let w = if len >= (1 << (usize::BITS - 1)) {
            usize::BITS as usize
        } else {
            len.next_power_of_two().trailing_zeros() as usize
        };
        for retry in 0..64 {
            let test_val = rng.next_width_u128(w).unwrap() as usize;
            if test_val < len {
                return retry;
            }
        }
        panic!()
    }

    let mut rng = StarRng::new(0);
    let mut max_retries = 0;
    let mut total = 0;
    for _ in 0..(1 << 16) {
        let res = retries(&mut rng, 16);
        total += res;
        max_retries = max(max_retries, res);
    }
    assert_eq!(max_retries, 0);
    assert_eq!(total, 0);

    let mut rng = StarRng::new(0);
    let mut max_retries = 0;
    let mut total = 0;
    for _ in 0..(1 << 16) {
        let res = retries(&mut rng, 15);
        total += res;
        max_retries = max(max_retries, res);
    }
    assert_eq!(max_retries, 4);
    assert_eq!(total, 4487);

    let mut rng = StarRng::new(0);
    let mut max_retries = 0;
    let mut total = 0;
    for _ in 0..(1 << 16) {
        let res = retries(&mut rng, 17);
        total += res;
        max_retries = max(max_retries, res);
    }
    assert_eq!(max_retries, 17);
    assert_eq!(total, 58403);
}
