# StarRNG - Xoshiro128StarStar-based opinionated psuedorandom number generator

This crate features an evolved version of a psuedorandom number generation strategy that I have been using for several years now. The internal rng is buffered at the bit level to dramatically improve efficiency when many single random booleans or small integers are being used.

`no-std` and `no-alloc` compatible.

#### License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>
