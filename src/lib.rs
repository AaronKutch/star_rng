#![no_std]

use core::{convert::Infallible, num::NonZeroU8};

use rand_core::{Rng, SeedableRng, TryRng};
use rand_xoshiro::Xoshiro128StarStar;

// the maximum number of retries for trying something that has as low as a 1/2 probability of happening
const MAX_RETRIES: usize = 64;

/// A PRNG (psuedorandom number generator).
///
/// This is an opinionated wrapper around [rand_xoshiro::Xoshiro128StarStar]
/// that buffers rng calls down to the bit level for even higher performance.
/// This is _not_ suitable for cryptographic purposes, but rather is meant for
/// deterministic fuzzing tests and more.
#[derive(Debug)]
pub struct StarRng {
    rng: Xoshiro128StarStar,
    // this is always filled with valid bits, shifting LSB-wards from `buf1` as they are consumed
    buf0: u32,
    // this is filled with `used` valid bits, the MSB-wards bits being zeroed. Must be filled with
    // new bits once `used` would reach zero
    buf1: u32,
    // Used bits in `buf1`, must be at most `BW`
    used: NonZeroU8,
}

/// The bitwidth of the internal buffer
const BW: usize = 32;
/// The bitwidth of the internal buffer as a `NonZeroU8`
const BW_U: NonZeroU8 = NonZeroU8::new(32).unwrap();

fn checked_sub(lhs: NonZeroU8, rhs: u8) -> Option<NonZeroU8> {
    NonZeroU8::new(lhs.get().checked_sub(rhs)?)
}

fn u(x: NonZeroU8) -> usize {
    usize::from(x.get())
}

impl TryRng for StarRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        // special casing, no updates to `used` since it is modulo 32
        let res = self.buf0;
        self.buf0 = self.buf1;
        let new = self.rng.next_u32();
        if self.used == BW_U {
            self.buf1 = new;
        } else {
            self.buf0 |= new << u(self.used);
            self.buf1 = new >> u(self.used);
        }
        Ok(res)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok((self.next_u32() as u64) | ((self.next_u32() as u64) << 32))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let mut i = 0;
        loop {
            let rem = dst.len().wrapping_sub(i);
            if rem < (BW / 8) {
                if rem == 0 {
                    break;
                }
                dst[i..].copy_from_slice(&self.consume((rem * 8) as u8).to_be_bytes());
                break;
            }
            // safe by isize::MAX limit
            let next = i.wrapping_add(4);
            dst[i..next].copy_from_slice(&self.next_u32().to_le_bytes());
            i = next;
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

macro_rules! next_width {
    ($($fn:ident $x:ident),*,) => {
        $(
            /// Returns an output with the first `width` bits being randomized. Returns `None` if `width` is greater than the bitwidth of the type.
            #[must_use]
            pub fn $fn(&mut self, mut width: usize) -> Option<$x> {
                if width > ($x::BITS as usize) {
                    return None
                }
                Some(if $x::BITS <= u32::BITS {
                    self.consume(width as u8) as $x
                } else {
                    let mut res: $x = 0;
                    let mut shl = 0;
                    loop {
                        if width < BW {
                            res |= (self.consume(width as u8) as $x) << shl;
                            break
                        }
                        res |= (self.next_u32() as $x) << shl;
                        width -= 32;
                        shl += 32;
                    }
                    res
                })
            }
        )*
    }
}

macro_rules! next {
    ($($name:ident $x:ident),*,) => {
        $(
            /// Returns an output with all bits being randomized
            pub fn $name(&mut self) -> $x {
                if $x::BITS <= u32::BITS {
                    self.consume($x::BITS as u8) as $x
                } else {
                    let mut res: $x = 0;
                    let mut shl = 0usize;
                    for _ in 0..($x::BITS / u32::BITS) {
                        res |= (self.next_u32() as $x) << shl;
                        shl += 32;
                    }
                    res
                }
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
                    num > (self.consume($bw) as u8)
                }
            }
        )*
    };
}

// almost the same thing as `index`, but I use a different name because `usize`
// should usually only be used in a fuzzing context when randomly indexing a
// memory limited set of things

macro_rules! uniform {
    ($($fn:ident $x:ident $next_width:ident),*,) => {
        $(
            /// Returns an integer uniformly from 0..=max.
            #[must_use]
            pub fn $fn(&mut self, max: $x) -> $x {
                if max == 0 {
                    0
                } else {
                    let bw = $x::BITS as usize;
                    let w = if max >= (1 << (bw - 1)) {
                        bw
                    } else {
                        max.wrapping_add(1).next_power_of_two().trailing_zeros() as usize
                    };
                    for _ in 0..MAX_RETRIES {
                        let test_val = self.$next_width(w).unwrap();
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

#[allow(clippy::reversed_empty_ranges)]
impl StarRng {
    // note: do not implement `next_usize`, if it exists then there will inevitably
    // be arch-dependent rng code in a lot of places
    next!(
        next_u8 u8,
        next_u16 u16,
        next_u32 u32,
        next_u64 u64,
        next_u128 u128,
    );

    next_width!(
        next_width_u8 u8,
        next_width_u16 u16,
        next_width_u32 u32,
        next_width_u64 u64,
        next_width_u128 u128,
    );

    out_of!(
        out_of_4, 4, 2;
        out_of_8, 8, 3;
        out_of_16, 16, 4;
        out_of_32, 32, 5;
        out_of_64, 64, 6;
        out_of_128, 128, 7;
    );

    uniform!(
        uniform_u8 u8 next_width_u8,
        uniform_u16 u16 next_width_u16,
        uniform_u32 u32 next_width_u32,
        uniform_u64 u64 next_width_u64,
        uniform_u128 u128 next_width_u128,
    );

    /// Creates a new `StarRng` with the given seed
    pub fn new(seed: u64) -> Self {
        let mut rng = Xoshiro128StarStar::seed_from_u64(seed);
        let buf0 = rng.next_u32();
        let buf1 = rng.next_u32();
        Self {
            rng,
            buf0,
            buf1,
            used: BW_U,
        }
    }

    /// Returns a random boolean
    pub fn next_bool(&mut self) -> bool {
        // special case everything
        let res = (self.buf0 & 1) != 0;
        self.buf0 >>= 1;
        self.buf0 |= self.buf1 << (BW - 1);
        self.buf1 >>= 1;
        if let Some(next) = checked_sub(self.used, 1) {
            self.used = next;
        } else {
            // must have been zeroed
            self.buf1 = self.rng.next_u32();
            self.used = BW_U;
        }
        res
    }

    /// Returns `bits` (must be less than or equal to `BW`) used bits in the
    /// `u32` and maintains invariants
    #[inline] // some preconditions are often unneccesary but they will get optimized away
    fn consume(&mut self, bits: u8) -> u32 {
        assert!(bits <= BW_U.get());
        if bits == 0 {
            return 0;
        }
        if bits == BW_U.get() {
            return self.next_u32();
        }
        let res = self.buf0 & (u32::MAX >> (BW_U.get() - bits));
        self.buf0 >>= bits;
        // there can be unused bits shifted in after used bits, we will OR in the rest
        self.buf0 |= self.buf1 << bits;
        self.buf1 >>= bits;
        if let Some(next) = checked_sub(self.used, bits) {
            // drawdown
            self.used = next;
        } else if bits == self.used.get() {
            // exact consumption
            self.buf1 = self.rng.next_u32();
            self.used = BW_U;
        } else {
            // the extended correction case
            let lo = bits.wrapping_sub(self.used.get());
            let hi = checked_sub(BW_U, lo).unwrap();
            let new = self.rng.next_u32();
            self.buf0 |= new << usize::from(hi.get());
            self.buf1 = new >> usize::from(lo);
            self.used = hi;
        }
        res
    }

    #[inline]
    fn consume_usize(&mut self, mut bits: usize) -> usize {
        assert!(bits <= (usize::BITS as usize));
        if usize::BITS <= u32::BITS {
            self.consume(bits as u8) as usize
        } else {
            let mut res = 0usize;
            let mut shl = 0;
            loop {
                if bits < BW {
                    res |= (self.consume(bits as u8) as usize) << shl;
                    break res;
                }
                res |= (self.next_u32() as usize) << shl;
                bits -= 32;
                shl += 32;
            }
        }
    }

    // special cased because 256 cannot be reached by `u8`

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
            num > self.next_u8()
        }
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
            for _ in 0..MAX_RETRIES {
                let test_val = self.consume_usize(w);
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

    /// Assigns random value to `bits[..width]`, zeroing the rest of the bits.
    /// Returns `None` if `width > bits.bw()`.
    #[must_use]
    #[cfg(feature = "awint_support")]
    pub fn next_bits_width(&mut self, bits: &mut awint::Bits, mut width: usize) -> Option<()> {
        if width > bits.bw() {
            return None;
        }
        bits.zero_();
        if width == 0 {
            return Some(());
        }
        let mut tmp = awint::InlAwi::from_u32(0);
        let mut shl = 0;
        loop {
            if width < BW {
                tmp.u32_(self.consume(width as u8));
                bits.field_to(shl, &tmp, width).unwrap();
                break;
            }
            tmp.u32_(self.next_u32());
            bits.field_to(shl, &tmp, 32).unwrap();
            width -= 32;
            shl += 32;
        }
        Some(())
    }

    /// Assigns random value to `bits`
    #[cfg(feature = "awint_support")]
    pub fn next_bits(&mut self, bits: &mut awint::Bits) {
        self.next_bits_width(bits, bits.bw()).unwrap();
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
    #[cfg(feature = "awint_support")]
    pub fn linear_fuzz_step(&mut self, x: &mut awint::Bits) {
        let tmp0 = self.index(x.bw()).unwrap();
        let tmp1 = self.index(x.bw().wrapping_add(1)).unwrap();
        let r0 = core::cmp::min(tmp0, tmp1);
        let r1 = core::cmp::max(tmp0, tmp1);
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
