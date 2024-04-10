#![no_std]

use core::cmp::{max, min};

use awint::awi::*;
use rand_xoshiro::{
    rand_core::{RngCore, SeedableRng},
    Xoshiro128StarStar,
};

/// A PRNG (psuedorandom number generator).
///
/// This is an opinionated wrapper around [rand_xoshiro::Xoshiro128StarStar]
/// that buffers rng calls down to the bit level for even higher performance.
/// This is _not_ suitable for cryptographic purposes, but rather is meant for
/// deterministic fuzzing tests and more.
#[derive(Debug)]
pub struct StarRng {
    rng: Xoshiro128StarStar,
    buf: inlawi_ty!(64),
    // invariant: `used < buf.bw()` and indicates the number of bits used out of `buf`
    used: u8,
}

macro_rules! next {
    ($($name:ident $x:ident $from:ident $to:ident),*,) => {
        $(
            /// Returns an output with all bits being randomized
            pub fn $name(&mut self) -> $x {
                let mut res = InlAwi::$from(0);
                let mut processed = 0;
                loop {
                    let remaining_in_buf = usize::from(Self::BW_U8.wrapping_sub(self.used));
                    let remaining = res.bw().wrapping_sub(processed);
                    if remaining == 0 {
                        break
                    }
                    if remaining < remaining_in_buf {
                        res.field(
                            processed,
                            &self.buf,
                            usize::from(self.used),
                            remaining
                        ).unwrap();
                        self.used = self.used.wrapping_add(remaining as u8);
                        break
                    } else {
                        res.field(
                            processed,
                            &self.buf,
                            usize::from(self.used),
                            remaining_in_buf
                        ).unwrap();
                        processed = processed.wrapping_add(remaining_in_buf);
                        self.buf = InlAwi::from_u64(self.rng.next_u64());
                        self.used = 0;
                    }
                }
                res.$to()
            }
        )*
    };
}

macro_rules! out_of {
    ($($fn:ident, $max:expr, $bw:expr);*;) => {
        $(
            /// The `num` input determines the fractional chance of the output being
            /// true.
            ///
            /// If `num` is zero, it will always return `false`. If `num` is equal to or
            /// larger than the denominator specified by the function name,
            /// it will always return `true`.
            pub fn $fn(&mut self, num: u8) -> bool {
                if num == 0 {
                    false
                } else if num >= $max {
                    true
                } else {
                    let mut tmp: inlawi_ty!($bw) = InlAwi::zero();
                    tmp.u8_(num);
                    self.next_bits(&mut tmp);
                    num > tmp.to_u8()
                }
            }
        )*
    };
}

// almost the same thing as `index`, but I use a different name because `usize`
// should usually only be used in a fuzzing context when randomly indexing a
// memory limited set of things

macro_rules! uniform {
    ($($fn:ident, $x:ident, $to_x:ident, $bw:expr);*;) => {
        $(
            /// Returns an integer uniformly from 0..=max.
            #[must_use]
            pub fn $fn(&mut self, max: $x) -> $x {
                if max == 0 {
                    0
                } else {
                    let w = if max >= (1 << ($bw - 1)) {
                        $bw
                    } else {
                        max.wrapping_add(1).next_power_of_two().trailing_zeros() as usize
                    };
                    let mut tmp: inlawi_ty!($bw) = InlAwi::zero();
                    // TODO are there any ill states that `Xoshiro128StarStar` can get into?
                    // In case of such a state, we have a finite
                    // number of loops to guarantee termination
                    for _ in 0..64 {
                        self.next_bits_width(&mut tmp, w).unwrap();
                        let test_val = tmp.$to_x();
                        if test_val <= max {
                            return test_val;
                        }
                        // else retry and avoid bias, the simplest and cheapest method for
                        // small `max` values. Because of our choice of `w`, the chance of
                        // success is at least 50%, meaning that the worst case is that we
                        // have to sample twice on average.
                    }
                    return 0;
                }
            }
        )*
    }
}

impl StarRng {
    /// The bitwidth of the internal buffer as a `u8`
    const BW_U8: u8 = 64;

    next!(
        next_u8 u8 from_u8 to_u8,
        next_u16 u16 from_u16 to_u16,
        next_u32 u32 from_u32 to_u32,
        next_u64 u64 from_u64 to_u64,
        next_u128 u128 from_u128 to_u128,
    );

    // note: do not implement `next_usize`, if it exists then there will inevitably
    // be arch-dependent rng code in a lot of places

    out_of!(
        out_of_4, 4, 2;
        out_of_8, 8, 3;
        out_of_16, 16, 4;
        out_of_32, 32, 5;
        out_of_64, 64, 6;
        out_of_128, 128, 7;
    );

    uniform!(
        uniform_u8, u8, to_u8, 8;
        uniform_u16, u16, to_u16, 16;
        uniform_u32, u32, to_u32, 32;
        uniform_u64, u64, to_u64, 64;
        uniform_u128, u128, to_u128, 128;
    );

    /// Creates a new `StarRng` with the given seed
    pub fn new(seed: u64) -> Self {
        let mut rng = Xoshiro128StarStar::seed_from_u64(seed);
        let buf = InlAwi::from_u64(rng.next_u64());
        Self { rng, buf, used: 0 }
    }

    /// Returns a random boolean
    pub fn next_bool(&mut self) -> bool {
        let res = self.buf.get(usize::from(self.used)).unwrap();
        self.used += 1;
        if self.used >= Self::BW_U8 {
            self.buf = InlAwi::from_u64(self.rng.next_u64());
            self.used = 0;
        }
        res
    }

    /// The `num` input determines the fractional chance of the output being
    /// true.
    ///
    /// If `num` is zero, it will always return `false`. If `num` is equal to or
    /// larger than the denominator specified by the function name,
    /// it will always return `true`.
    pub fn out_of_256(&mut self, num: u8) -> bool {
        if num == 0 {
            false
        } else {
            let mut tmp = InlAwi::from_u8(num);
            tmp.u8_(num);
            self.next_bits(&mut tmp);
            num > tmp.to_u8()
        }
    }

    /// Assigns random value to `bits[..width]`, zeroing the rest of the bits.
    /// Returns `None` if `width > bits.bw()`.
    #[must_use]
    pub fn next_bits_width(&mut self, bits: &mut Bits, width: usize) -> Option<()> {
        if width > bits.bw() {
            return None
        }
        bits.zero_();
        if width == 0 {
            return Some(())
        }
        let mut processed = 0;
        loop {
            let remaining_in_buf = usize::from(Self::BW_U8.wrapping_sub(self.used));
            let remaining = width.wrapping_sub(processed);
            if remaining == 0 {
                break
            }
            // TODO use `digit_or_` for better perf, but then we need to handle differing
            // `Digit` sizes and test appropriately
            if remaining < remaining_in_buf {
                bits.field(processed, &self.buf, usize::from(self.used), remaining)
                    .unwrap();
                self.used = self.used.wrapping_add(remaining as u8);
                break
            } else {
                // in the middle iterations of the loop, `remaining_in_buf` will be `BW_U8` bits
                // which leads to a more optimized `field` path on most platforms
                bits.field(
                    processed,
                    &self.buf,
                    usize::from(self.used),
                    remaining_in_buf,
                )
                .unwrap();
                processed = processed.wrapping_add(remaining_in_buf);
                self.buf = InlAwi::from_u64(self.rng.next_u64());
                self.used = 0;
            }
        }
        Some(())
    }

    /// Assigns random value to `bits`
    pub fn next_bits(&mut self, bits: &mut Bits) {
        self.next_bits_width(bits, bits.bw()).unwrap();
    }

    /// Returns a random index, given an exclusive maximum of `len`. Returns
    /// `None` if `len == 0`.
    #[must_use]
    pub fn index(&mut self, len: usize) -> Option<usize> {
        if len == 0 {
            None
        } else {
            let w = if len >= (1 << (usize::BITS - 1)) {
                usize::BITS as usize
            } else {
                len.next_power_of_two().trailing_zeros() as usize
            };
            let mut tmp = InlAwi::from_usize(0);
            // TODO are there any ill states that `Xoshiro128StarStar` can get into?
            // In case of such a state, we have a finite
            // number of loops to guarantee termination
            for _ in 0..64 {
                self.next_bits_width(&mut tmp, w).unwrap();
                let test_val = tmp.to_usize();
                if test_val < len {
                    return Some(test_val);
                }
                // else retry and avoid bias, the simplest and cheapest method
                // for small `max` values. Because of our choice
                // of `w`, the chance of success is at least
                // 50%, meaning that the worst case is that we
                // have to sample twice on average.
            }
            Some(0)
        }
    }

    /// Takes a random index of a slice. Returns `None` if `slice.is_empty()`.
    #[must_use]
    pub fn index_slice<'a, T>(&mut self, slice: &'a [T]) -> Option<&'a T> {
        let inx = self.index(slice.len())?;
        slice.get(inx)
    }

    /// Takes a random index of a slice. Returns `None` if `slice.is_empty()`.
    #[must_use]
    pub fn index_slice_mut<'a, T>(&mut self, slice: &'a mut [T]) -> Option<&'a mut T> {
        let inx = self.index(slice.len())?;
        slice.get_mut(inx)
    }

    /// This performs one step of a fuzzer where a random field of ones is
    /// ORed, ANDed, or XORed to `x`.
    ///
    /// In many cases there are issues that involve long lines of all set or
    /// unset bits, and the `next_bits` function is unsuitable for this as
    /// `x.bw()` gets larger than a few bits. This function produces random
    /// length strings of ones and zeros concatenated together, which can
    /// rapidly probe a more structured space even for large `x`.
    ///
    /// ```
    /// use awint::awi::*;
    /// use star_rng::StarRng;
    ///
    /// let mut rng = StarRng::new(7);
    /// let mut x = awi!(0u128);
    /// // this should be done in a loop with thousands of iterations,
    /// // here I have unrolled a few for example
    /// rng.linear_fuzz_step(&mut x);
    /// assert_eq!(x, awi!(0x1_ffffffff_f0000000_u128));
    /// rng.linear_fuzz_step(&mut x);
    /// assert_eq!(x, awi!(0x3ffff01_ffffffff_f0000000_u128));
    /// rng.linear_fuzz_step(&mut x);
    /// assert_eq!(x, awi!(0x3fffcfe_00000001_f0000000_u128));
    /// rng.linear_fuzz_step(&mut x);
    /// assert_eq!(x, awi!(0xc000301_fffffffe_0fffff00_u128));
    /// rng.linear_fuzz_step(&mut x);
    /// assert_eq!(x, awi!(0xc_0c000301_fffffffe_0fffff00_u128));
    /// ```
    pub fn linear_fuzz_step(&mut self, x: &mut Bits) {
        let tmp0 = self.index(x.bw()).unwrap();
        let tmp1 = self.index(x.bw().wrapping_add(1)).unwrap();
        let r0 = min(tmp0, tmp1);
        let r1 = max(tmp0, tmp1);
        // note: it needs to be 2 parts XOR to 1 part OR and 1 part AND, the ordering
        // guarantees this
        if self.next_bool() {
            x.range_xor_(r0..r1).unwrap();
        } else if self.next_bool() {
            x.range_or_(r0..r1).unwrap();
        } else {
            x.range_and_(r0..r1).unwrap();
        }
    }
}

impl RngCore for StarRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // TODO make faster
        for byte in dest {
            *byte = self.next_u8();
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_xoshiro::rand_core::Error> {
        for byte in dest {
            *byte = self.next_u8();
        }
        Ok(())
    }
}

impl SeedableRng for StarRng {
    type Seed = [u8; 8];

    fn from_seed(seed: Self::Seed) -> Self {
        Self::new(u64::from_le_bytes(seed))
    }
}
