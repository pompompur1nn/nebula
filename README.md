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
cmp docs/NEBULA_LAYER2.md README.md
```

The public launch suite covers:

- launch bundle and package identity checks
- fixed public-testnet launch bundle ID validation
- package artifact and lockfile root domain separation
- readiness report shape and remediation roots
- deployment evidence root binding
- deployment component root domain separation
- public status manifest redaction
- public endpoint and TLS pin evidence
- HTTPS-only public status/probe endpoints with non-empty hosts, no userinfo,
  and no query or fragment
- public status endpoint binding to the expected public surface
- standalone public status/probe surface exact-shape validation
- final package binding for the public status/probe surface
- shared deployment witness root binding for bootstrap nodes, operators, and
  observers
- deterministic operator, observer, and validator admission signature-root
  validation
- unique bootstrap node, operator, observer, endpoint, witness-key,
  bootstrap-region, operator-region, and observer-region validation
- role-separated bootstrap node, operator, and observer identities
- whitespace-free bootstrap, operator, observer, and deployment-region labels
- 64-character hex and role-separated witness/validator public-key material
  validation
- unique and role-separated TLS certificate/public-key pin validation
- deployment freshness windows for generated attestations, preflight/runbook
  receipts, expiry, TLS pins, and rollback drills
- positive deployment attestation validity windows
- standalone preflight/runbook receipt exact-shape and unique evidence
  validation
- preflight/runbook receipt evidence separation
- preflight/runbook receipt completion before deployment generation
- rollback drill completion before deployment generation
- distinct rollback plan and recovery-point roots
- policy claim and public probe body exact-shape validation
- preflight and runbook receipt exact-shape validation
- bootstrap node/operator and observer attestation exact-shape validation
- validator-set admission, whitespace-free and role-separated identity,
  fixed genesis epoch, whitespace-free region, contact, reward-unit,
  uniqueness, operator power concentration, and region-spread validation
- genesis manifest root binding across deployment evidence, validator set, and
  fee policy
- genesis manifest artifact-root domain separation
- genesis manifest freshness validation
- genesis timestamp binding to the deployment attestation validity window
- launch package coherence across deployment attestation, public surface,
  validator set, and genesis manifest artifacts
- launch package binding between admitted validators, deployment operators, and
  bootstrap nodes
- launch package binding between validator P2P hosts and attested bootstrap
  endpoint hosts
- launch package key-domain separation between admitted validators and
  deployment witnesses
- launch package host separation between the public endpoint and bootstrap
  endpoints
- launch package rejection of deployment operators and bootstrap nodes that
  have no admitted validator
- bootstrap node/operator region binding inside deployment evidence

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
6. Generate and verify public status and probe samples.
7. Generate and verify preflight and runbook receipt samples.
8. Generate and verify a deployment attestation sample.
9. Generate and verify a validator-set manifest sample.
10. Build and verify a genesis manifest from the verified samples.
11. Verify the launch package is internally coherent.
12. Assert `README.md` and `docs/NEBULA_LAYER2.md` are identical.

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
- launch bundles that do not use `nebula-public-testnet-bundle-1`
- package artifact roots that reuse Cargo.lock roots
- deployment component roots that reuse another component root
- duplicated preflight/runbook receipt phase names, step names, and step
  evidence roots
- public status/probe endpoints that do not use `https://`
- public status/probe endpoints that do not include a host, include userinfo,
  include query/fragment components, or include a nonnumeric/zero port
- public status endpoint URLs that do not match the expected public surface
- bootstrap endpoints that include a path, omit a host, include userinfo, or
  include query/fragment components or a nonnumeric/zero port
- bootstrap endpoint hosts that reuse the public endpoint host
- operator and observer witness roots that do not match the deployment surface
- operator and observer public keys that are not 64-character hex values
- observer public keys that reuse an operator public key
- validator consensus/network keys that reuse deployment witness public keys
- bootstrap node attestation roots that do not bind the deployment witness root
- operator, observer, and validator admission signature roots that do not bind
  the signed payload
- duplicate bootstrap node IDs, bootstrap endpoints, bootstrap endpoint hosts,
  operator IDs, operator keys, observer IDs, and observer keys
- bootstrap node IDs that reuse operator IDs
- observer IDs that reuse bootstrap node IDs or operator IDs
- bootstrap, operator, observer, and region labels containing whitespace
- bootstrap node sets that do not cover at least two regions
- bootstrap nodes whose region does not match the attested operator region
- operator quorums that do not cover at least two regions
- observer quorums that do not cover at least two regions
- duplicate or cross-reused TLS certificate and public-key pins
- deployment attestations older than `24` hours, expiry windows that do not end
  after generation, expiry windows longer than `7` days from generation, preflight/runbook
  receipts older than `24` hours, TLS pins with less than `7` days remaining,
  and rollback drills older than `7` days
- runbook receipt evidence roots that reuse preflight receipt evidence
- preflight/runbook receipts completed after deployment attestation generation
- rollback drills completed after deployment attestation generation
- rollback recovery roots that reuse rollback plan roots

Until an operator provides fresh deployment evidence that satisfies those rules,
`public_launch_ready` must remain `false`.

Operators can generate and verify the public status/probe surface before filling
deployment evidence:

```bash
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --sample-public-status > /tmp/nebula-public-status.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-public-status /tmp/nebula-public-status.json --json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --sample-public-probe > /tmp/nebula-public-probe.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-public-probe /tmp/nebula-public-probe.json --json
```

Operators can also verify preflight and runbook receipts before wrapping them in
deployment evidence. Receipt phase names must be unique, step names must be
unique within each phase, and step evidence roots must be unique across the
receipt. Receipts older than `24` hours are rejected:

```bash
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --sample-preflight-receipt > /tmp/nebula-preflight.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-preflight-receipt /tmp/nebula-preflight.json --json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --sample-runbook-receipt > /tmp/nebula-runbook.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-runbook-receipt /tmp/nebula-runbook.json --json
```

Operators can generate the required shape and verify a filled attestation with:

```bash
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --sample-deployment-attestation > /tmp/nebula-attestation.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-deployment-attestation /tmp/nebula-attestation.json --json
```

## Validator Set Gate

Public testnet admission also requires a validator-set manifest. The verifier
requires genesis epoch `0`, at least two validators, two operators, and two
regions. Validator IDs, operator IDs, and node IDs must not contain whitespace
or reuse each other.
Operator IDs must be unique across admitted validators. Validator region labels
must not contain whitespace. Validator IDs, node IDs, consensus keys, network
keys, reward accounts, and P2P endpoints must be unique. Genesis power must be
positive, no single validator or operator may hold more than `5000` basis points
of total genesis power, commission must be at or below `10000` basis points,
operator contacts must use `mailto:` or `https://`, `mailto:`
contacts must include exactly one email address with no query/fragment
components, `https://` contacts must include a host and no
userinfo/query/fragment components, P2P endpoints must use `tcp://host:port`
with no path/userinfo/query/fragment components,
reward accounts must use the `nbla-reward-{operator_id}` form, and rewards must
be denominated in `nebulai`. Each validator admission signature root must bind
the validator identity, operator contact, keys, reward account, commission,
genesis power, reward unit, and fee-policy root. Consensus and network public
keys must be 64-character hex values, and consensus/network key domains must be
disjoint.

Operators can generate the required shape and verify a filled validator set
with:

```bash
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --sample-validator-set > /tmp/nebula-validator-set.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-validator-set /tmp/nebula-validator-set.json --json
```

## Genesis Manifest Gate

The final local launch artifact is a genesis manifest. It can only be built from
a deployment attestation and validator-set manifest that already pass their
verifiers. The manifest binds the deployment evidence root, validator-set root,
fee-policy root, validator-admission root, initial validator count, total genesis
power, fixed activation height `1`, and fee token identities. The verifier keeps
deployment, validator-set, fee-policy, and validator-admission roots in separate
domains. The final launch-package check requires the genesis timestamp to be
fresh and to fall inside the deployment attestation validity window.

Operators can build and verify the launch manifest with:

```bash
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --build-genesis-manifest --deployment-attestation /tmp/nebula-attestation.json --validator-set /tmp/nebula-validator-set.json > /tmp/nebula-genesis.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-genesis-manifest /tmp/nebula-genesis.json --json
```

## Launch Package Gate

The final package check verifies the deployment attestation, public status
manifest, public probe, validator-set manifest, and genesis manifest together.
It rejects a package when the public surface roots do not match the deployment
attestation, or when the genesis manifest does not bind the exact deployment
evidence root, validator-set root, validator count, total genesis power, and
deployment validity window produced by the other verified files. It also rejects
validator consensus/network keys that reuse deployment witness keys,
validator-set manifests whose admitted validators do not map to the attested
deployment operators and bootstrap nodes, validator P2P hosts that do not match
their attested bootstrap endpoint host, and deployment operators or bootstrap
nodes that are not represented by an admitted validator.

Operators can verify the full package with:

```bash
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-launch-package --deployment-attestation /tmp/nebula-attestation.json --public-status /tmp/nebula-public-status.json --public-probe /tmp/nebula-public-probe.json --validator-set /tmp/nebula-validator-set.json --genesis-manifest /tmp/nebula-genesis.json --json
```

## License

Nebula-specific code and documentation in this repository are distributed under
the license terms in `LICENSE`.
