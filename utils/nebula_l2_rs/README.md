# Nebula Testnet Runtime

This crate contains Nebula's local testnet readiness contract and command-line
runner. It is intentionally self-contained and does not depend on inherited
node, wallet, mining, reproducible-build, or daemon surfaces.

## Commands

```bash
cargo fmt --manifest-path utils/nebula_l2_rs/Cargo.toml -- --check
cargo build --manifest-path utils/nebula_l2_rs/Cargo.toml --bin nebula-testnet
cargo test --manifest-path utils/nebula_l2_rs/Cargo.toml public_launch -- --test-threads=1
cargo run --manifest-path utils/nebula_l2_rs/Cargo.toml --bin nebula-testnet -- --mainnet-readiness --json
```

The readiness report keeps local testnet acceptance separate from public launch
approval. The local testnet can be ready while public launch remains blocked by
the required deployment attestation.
