# Nebula Layer 2

Nebula is a privacy-preserving Layer 2 testnet runtime focused on post-quantum
attestation, low-fee private execution, deterministic public launch gates, and
operator-owned deployment evidence.

This repository now carries the Nebula runtime and public testnet tooling only.
Inherited upstream node, wallet, mining, reproducible-build, and daemon CI
surfaces have been removed from the active tree.

## Public Testnet Status

The local Nebula testnet checks pass, but the public launch gate intentionally
stays closed until a filled deployment attestation is supplied and verified.

Expected readiness contract:

```json
{
  "local_testnet_ready": true,
  "public_launch_ready": false,
  "public_launch_level": "public-launch-blocked",
  "blocking_gaps": ["public-launch-deployment-attestation"]
}
```

That blocked state is correct for an operator workspace that has not yet
provided live public deployment evidence.

## Repository Layout

- `crates/nebula-testnet/` - Nebula Rust runtime and testnet tooling.
- `crates/nebula-testnet/src/bin/nebula-testnet.rs` - standalone public testnet,
  public launch, readiness, package, and deployment-attestation verifier.
- `docs/NEBULA_LAYER2.md` - mirrored operator guide. This file intentionally
  matches this README so CI can enforce one source of truth.
- `.github/workflows/nebula.yml` - Nebula-owned CI. It builds and tests the
  Rust public testnet path instead of inherited upstream daemon workflows.

## Local Checks

Run the public testnet checks from the repository root:

```bash
cargo fmt --manifest-path crates/nebula-testnet/Cargo.toml -- --check
cargo build --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet
cargo test --manifest-path crates/nebula-testnet/Cargo.toml -- --test-threads=1
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --mainnet-readiness --json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --sample-deployment-attestation > /tmp/nebula-attestation.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-deployment-attestation /tmp/nebula-attestation.json --json
cmp docs/NEBULA_LAYER2.md README.md
```

The public launch suite covers:

- launch bundle and package identity checks
- readiness report shape and remediation roots
- deployment evidence root binding
- public status manifest redaction
- public endpoint and TLS pin evidence
- policy claim and public probe body exact-shape validation
- preflight and runbook receipt exact-shape validation
- bootstrap node/operator and observer attestation exact-shape validation

## Hybrid Fees And Validator Rewards

Nebula testnet uses a hybrid fee policy:

- Gas can be paid in native `NBLA`.
- Gas can also be paid in bridged `nXMR`.
- `nebulai` is the base accounting unit for gas and validator rewards.
- `1 NBLA = 1,000,000 nebulai`.
- The target reserve reference is `1 NBLA = 0.001 nXMR`.
- At that target, one `nXMR` base unit maps to one `nebulai`.
- `NBLA` gas is credited directly to the validator reward ledger.
- `nXMR` gas is converted into NBLA accounting value before distribution.
- Converted `nXMR` value is split with `90%` reserved as NBLA backing and `10%`
  credited to the validator reward ledger.

Public testnet rewards are non-transferable validator points. Points mirror the
validator reward ledger in `nebulai` so validators can prove uptime, attestation
quality, and fee contribution before any live-value reward policy is enabled.

## CI

The active GitHub Actions workflow is Nebula-owned:

1. Install stable Rust.
2. Check Rust formatting.
3. Build `nebula-testnet`.
4. Run the Nebula test suite.
5. Assert the current readiness contract.
6. Generate and verify a deployment attestation sample.
7. Assert `README.md` and `docs/NEBULA_LAYER2.md` are identical.

Legacy upstream CI for daemon, wallet, Guix, depends, Docker daemon images, and
source archives has been removed.

## Deployment Attestation Gate

Public launch requires a filled deployment attestation. The verifier rejects:

- unexpected top-level evidence fields
- unexpected public probe body fields
- unexpected policy claim fields
- unexpected TLS endpoint pin fields
- unexpected preflight/runbook receipt and nested phase/step fields
- unexpected bootstrap node/operator fields
- unexpected observer and signature verification fields
- stale or mismatched roots, package identities, launch bundle identities, and
  public status manifest identities

Until an operator provides fresh deployment evidence that satisfies those rules,
`public_launch_ready` must remain `false`.

Operators can generate the required shape and verify a filled attestation with:

```bash
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --sample-deployment-attestation > /tmp/nebula-attestation.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-deployment-attestation /tmp/nebula-attestation.json --json
```

## License

Nebula-specific code and documentation in this repository are distributed under
the license terms in `LICENSE`.
