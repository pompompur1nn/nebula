# Nebula Testnet Runtime

This crate contains Nebula's local testnet readiness contract and command-line
runner. It is intentionally self-contained and does not depend on inherited
node, wallet, mining, reproducible-build, or daemon surfaces.

## Commands

```bash
cargo fmt --manifest-path crates/nebula-testnet/Cargo.toml -- --check
cargo build --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet
cargo test --manifest-path crates/nebula-testnet/Cargo.toml -- --test-threads=1
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --mainnet-readiness --json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --sample-deployment-attestation > /tmp/nebula-attestation.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-deployment-attestation /tmp/nebula-attestation.json --json
```

The readiness report keeps local testnet acceptance separate from public launch
approval. The local testnet can be ready while public launch remains blocked by
the required deployment attestation.

Gas can be paid in `NBLA` or `nXMR`. `NBLA` fees go directly to the validator
reward ledger. `nXMR` fees are converted into NBLA accounting value and split
with `90%` reserved for NBLA backing and `10%` credited to validator rewards.
Fees and validator points are denominated in `nebulai`, where
`1 NBLA = 1,000,000 nebulai` and the target reserve reference is
`1 NBLA = 0.001 nXMR`.
