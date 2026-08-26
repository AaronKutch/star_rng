# Changelog

## [0.3.0] - 2026-08-26
### Crate
- MSRV 1.88
- removed mandatory dependency on `awint`, so that it can be used by more crates and is more
  optimized. The specially optimized functions can be accessed again with the "star_rng_support"
  feature on `awint`.
- `rand_core` 0.10
- `rand_xoshiro` 0.8

The same deterministic behavior has remained through reviews of idealness,
the exact behavior of this version should remain stable for the forseeable future.

### Changes
- Added `index_inclusive`
- Added `shuffle` and `partial_shuffle`
- Added `seed` and `bits_consumed` to indicate the exact deterministic place in RNG, and added them to the debug impl

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
