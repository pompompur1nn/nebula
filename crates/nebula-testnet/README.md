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

Public status and probe verifiers let operators prove the exact public surface,
including the expected public status endpoint URL, before wrapping it in
deployment evidence.

Deployment evidence binds bootstrap nodes, operators, and observers to one
shared witness root for the launch bundle, public status, HTTPS endpoint/TLS
pins, policy claim, and public probe. Operator and observer signature roots must
bind their signer identity and that witness root. The launch bundle must use
`nebula-public-testnet-bundle-1`, and package artifact roots must not reuse
Cargo.lock roots. Launch bundle, public status, policy claim, and public probe
roots must be disjoint. Bootstrap node IDs,
endpoints, endpoint hosts, operator IDs/keys, observer IDs/keys, and TLS
certificate/public-key pins must be unique. Bootstrap node IDs must not reuse
operator IDs. TLS certificate pins and public-key pins must not reuse each
other. Observer IDs must not reuse bootstrap node IDs or operator IDs. Operator
and observer public keys must be 64-character hex values, and observer keys
must not reuse operator keys.
Public status and probe HTTPS endpoints must include a host and no
userinfo/query/fragment components; any explicit HTTPS port must be numeric and
nonzero. Bootstrap HTTPS endpoints must include a host and no
path/userinfo/query/fragment components; any explicit bootstrap port must be
numeric and nonzero. Bootstrap endpoint hosts must not reuse the public endpoint
host. Bootstrap nodes must match their attested operator region.
Bootstrap
nodes, operator quorums, and observer quorums must each cover at least two
regions. Bootstrap, operator, observer, and deployment-region labels must not
contain whitespace. Observer IDs must not reuse operator IDs. Deployment
evidence must be generated within `24` hours, expire after its generation time
and within `7` days, carry TLS pins with at least `7` days remaining, and
include a rollback drill from the last `7` days that completed before deployment
evidence was generated. Rollback recovery roots must differ from rollback plan
roots.

Preflight and runbook receipt verifiers let operators prove launch steps before
wrapping those receipts in deployment evidence. Receipt phase names must be
unique, step names must be unique within each phase, and step evidence roots
must be unique across the receipt. Runbook receipts must not reuse preflight
evidence roots. Receipts must complete before deployment evidence is generated,
and receipts older than `24` hours are rejected.

Gas can be paid in `NBLA` or `nXMR`. `NBLA` fees go directly to the validator
reward ledger. `nXMR` fees are converted into NBLA accounting value and split
with `90%` reserved for NBLA backing and `10%` credited to validator rewards.
Fees and validator points are denominated in `nebulai`, where
`1 NBLA = 1,000,000 nebulai` and the target reserve reference is
`1 NBLA = 0.001 nXMR`.

The validator-set verifier requires at least two validators, two operators, and
two regions. Validator IDs, operator IDs, and node IDs must not contain
whitespace or reuse each other. Operator IDs must be unique across admitted
validators. Validator region labels must not contain whitespace. Validator IDs,
node IDs, keys, reward accounts, and P2P endpoints must be unique. No single
validator or operator may hold more than `5000` basis points of total genesis
power. Operator contacts must use `mailto:` or `https://`.
`mailto:` contacts must include exactly one email address with no
query/fragment components, `https://` contacts must include a host and no
userinfo/query/fragment components, and P2P endpoints must use
`tcp://host:port` with no path/userinfo/query/fragment components.
Validator admission reward accounts must use
`nbla-reward-{operator_id}` and rewards are denominated in `nebulai`. Each
signed admission root must bind the validator identity, operator contact, keys,
reward account, commission, genesis power, reward unit, and fee-policy root.
Consensus and network public keys must be 64-character hex values, and
consensus/network key domains must be disjoint.

The genesis manifest builder binds verified deployment evidence and validator
admission into the root artifact used to start a public testnet at activation
height `1`. Genesis deployment, validator-set, fee-policy, and
validator-admission roots must be disjoint. Genesis manifests older than `24`
hours are rejected. The final launch-package check requires the genesis
timestamp to fall inside the deployment attestation validity window.

The launch-package verifier checks that the deployment, public surface,
validator set, and genesis artifacts all agree before operators advance to a
live rollout. It also rejects validator consensus/network keys that reuse
deployment witness keys, admitted validators that do not map to attested
deployment operators and bootstrap nodes, validator P2P hosts that do not match
their attested bootstrap endpoint host, plus deployment operators or bootstrap
nodes that are not represented by an admitted validator.
