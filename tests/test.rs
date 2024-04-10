use std::{cmp::max, num::NonZeroUsize};

use awint::awi::*;
use rand_xoshiro::{
    rand_core::{RngCore, SeedableRng},
    Xoshiro128StarStar,
};
use star_rng::StarRng;

fn rand_choice(
    metarng: &mut Xoshiro128StarStar,
    rng: &mut StarRng,
    mut bits: &mut Bits,
    actions: &mut u64,
) {
    let mut used = 0;
    loop {
        let remaining = bits.bw() - used;
        if remaining == 0 {
            break
        }
        if remaining < 192 {
            // need to fill up without encountering a potential overflow case
            let mut tmp = Awi::zero(NonZeroUsize::new(remaining).unwrap());
            rng.next_bits(&mut tmp);
            cc!(tmp, ..; bits).unwrap();
            break
        }
        match metarng.next_u32() % 8 {
            0 => {
                cc!(InlAwi::from_bool(rng.next_bool()); bits[used]).unwrap();
                used += 1;
            }
            1 => {
                cc!(InlAwi::from_u8(rng.next_u8()); bits[used..(used+8)]).unwrap();
                used += 8;
            }
            2 => {
                cc!(InlAwi::from_u16(rng.next_u16()); bits[used..(used+16)]).unwrap();
                used += 16;
            }
            3 => {
                cc!(InlAwi::from_u32(rng.next_u32()); bits[used..(used+32)]).unwrap();
                used += 32;
            }
            4 => {
                cc!(InlAwi::from_u64(rng.next_u64()); bits[used..(used+64)]).unwrap();
                used += 64;
            }
            5 => {
                cc!(InlAwi::from_u128(rng.next_u128()); bits[used..(used+128)]).unwrap();
                used += 128;
            }
            6 => {
                let w = NonZeroUsize::new((metarng.next_u32() % 192) as usize + 1).unwrap();
                let mut tmp = Awi::zero(w);
                rng.next_bits(&mut tmp);
                cc!(tmp; bits[used..(used+w.get())]).unwrap();
                used += w.get();
            }
            7 => {
                let w = NonZeroUsize::new((metarng.next_u32() % 192) as usize + 1).unwrap();
                let mut tmp = Awi::zero(w);
                let width = (metarng.next_u32() as usize) % w.get();
                rng.next_bits_width(&mut tmp, width).unwrap();
                cc!(tmp[..width]; bits[used..(used+width)]).unwrap();
                used += width;
            }
            _ => unreachable!(),
        }
        *actions += 1;
    }
}

#[test]
fn star_rng() {
    const N: usize = 1 << 16;
    let mut metarng = Xoshiro128StarStar::seed_from_u64(1);
    let mut rng0 = StarRng::new(0);
    let mut rng1 = StarRng::new(0);
    let mut bits0 = Awi::zero(bw(N));
    let mut bits1 = Awi::zero(bw(N));
    let mut actions = 0;
    rand_choice(&mut metarng, &mut rng0, &mut bits0, &mut actions);
    assert_eq!(actions, 1273);
    actions = 0;
    // the `metarng` is different and will fill `bits1` in a different way, but the
    // overall result should be the same since the buffering is bitwise and `rng0`
    // and `rng1` started with the same bits
    rand_choice(&mut metarng, &mut rng1, &mut bits1, &mut actions);
    assert_eq!(actions, 1338);
    assert_eq!(bits0, bits1);

    let mut rng0 = StarRng::new(0);
    let mut yes = 0u64;
    for _ in 0..(1 << 16) {
        yes += rng0.out_of_128(42) as u64;
    }
    assert_eq!(yes, 21597);
    let mut yes = 0u64;
    for _ in 0..(1 << 16) {
        yes += rng0.out_of_256(84) as u64;
    }
    assert_eq!(yes, 21429);
    for _ in 0..(1 << 16) {
        assert!(!rng0.out_of_128(0))
    }
    let mut yes = 0u64;
    for _ in 0..(1 << 16) {
        yes += rng0.out_of_128(127) as u64;
    }
    assert_eq!(yes, 65053);
    for _ in 0..(1 << 16) {
        assert!(rng0.out_of_128(128))
    }
    for _ in 0..(1 << 16) {
        assert!(!rng0.out_of_256(0))
    }
    let mut yes = 0u64;
    for _ in 0..(1 << 16) {
        yes += rng0.out_of_256(255) as u64;
    }
    assert_eq!(yes, 65303);
    let mut yes = 0u64;
    for _ in 0..(1 << 16) {
        yes += rng0.out_of_4(3) as u64;
    }
    assert_eq!(yes, 49176);

    let mut rng0 = StarRng::new(0);
    assert!(rng0.index(0).is_none());
    assert!(rng0.index_slice(&[0u8; 0]).is_none());
    let mut slice = vec![0u64; 7];
    for _ in 0..(1 << 16) {
        *rng0.index_slice_mut(&mut slice).unwrap() += 1;
    }
    for e in slice {
        assert!((e > 9149) && (e < 9513));
    }

    // just to make sure there are not panics
    let mut x = awi!(0u7);
    for _ in 0..100 {
        rng0.linear_fuzz_step(&mut x);
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
        let mut tmp = InlAwi::from_usize(0);
        for retry in 0..64 {
            rng.next_bits_width(&mut tmp, w).unwrap();
            let test_val = tmp.to_usize();
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
