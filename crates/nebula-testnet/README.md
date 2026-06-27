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
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --sample-public-status > /tmp/nebula-public-status.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-public-status /tmp/nebula-public-status.json --json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --sample-public-probe > /tmp/nebula-public-probe.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-public-probe /tmp/nebula-public-probe.json --json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --sample-preflight-receipt > /tmp/nebula-preflight.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-preflight-receipt /tmp/nebula-preflight.json --json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --sample-runbook-receipt > /tmp/nebula-runbook.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-runbook-receipt /tmp/nebula-runbook.json --json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --sample-deployment-attestation > /tmp/nebula-attestation.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-deployment-attestation /tmp/nebula-attestation.json --json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --sample-validator-set > /tmp/nebula-validator-set.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-validator-set /tmp/nebula-validator-set.json --json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --build-genesis-manifest --deployment-attestation /tmp/nebula-attestation.json --validator-set /tmp/nebula-validator-set.json > /tmp/nebula-genesis.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-genesis-manifest /tmp/nebula-genesis.json --json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-launch-package --deployment-attestation /tmp/nebula-attestation.json --public-status /tmp/nebula-public-status.json --public-probe /tmp/nebula-public-probe.json --validator-set /tmp/nebula-validator-set.json --genesis-manifest /tmp/nebula-genesis.json --json
```

The readiness report keeps local testnet acceptance separate from public launch
approval. The local testnet can be ready while public launch remains blocked by
the required deployment attestation.

Public status and probe verifiers let operators prove the exact public surface
before wrapping it in deployment evidence.

Preflight and runbook receipt verifiers let operators prove launch steps before
wrapping those receipts in deployment evidence.

Gas can be paid in `NBLA` or `nXMR`. `NBLA` fees go directly to the validator
reward ledger. `nXMR` fees are converted into NBLA accounting value and split
with `90%` reserved for NBLA backing and `10%` credited to validator rewards.
Fees and validator points are denominated in `nebulai`, where
`1 NBLA = 1,000,000 nebulai` and the target reserve reference is
`1 NBLA = 0.001 nXMR`.

The validator-set verifier requires at least two validators, two operators, and
two regions. Validator admission rewards are denominated in `nebulai`.

The genesis manifest builder binds verified deployment evidence and validator
admission into the root artifact used to start a public testnet.

The launch-package verifier checks that the deployment, public surface,
validator set, and genesis artifacts all agree before operators advance to a
live rollout. It also rejects admitted validators that do not map to attested
deployment operators and bootstrap nodes.
