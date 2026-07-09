# Changelog

## [0.3.0] - TODO
### Crate
- Set the MSRV to 1.86
- removed mandatory dependency on `awint`, so that it can be used by more crates and is more
  optimized. The specially optimized `next_bits`, `next_bits_width`, and `linear_fuzz_step`
  functions can be accessed again with the "awint_support" feature FIXME

## [0.2.0] - 2025-02-11
### Crate
- `rand_core` 0.9
- `awint` 0.18
- `rand_xoshiro` 0.7

## [0.1.0] - 2024-04-08
### Crate
- `awint` 0.17
- `rand_xoshiro` 0.6

### Additions
- Initial release with `StarRng`
