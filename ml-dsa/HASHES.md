# Overview

Documenting running ML-DSA with different hash functions.

## Testig

```bash
cargo test --lib crypto
cargo test --lib crypto_blake3 --features blake3
```

## Round Trip Analysis

```bash
cargo test --test round_trip_analysis --features shake -- --nocapture
cargo test --test round_trip_analysis --features blake3 -- --nocapture
```

## Benchmarking

```bash
cargo bench --bench ml_dsa --no-default-features --features shake
cargo bench --bench ml_dsa --no-default-features --features blake3
```

```bash
cargo bench --bench ml_dsa_warm_v_cold --no-default-features --features shake
cargo bench --bench ml_dsa_warm_v_cold --no-default-features --features blake3
```
