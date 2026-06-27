# Nebula Testnet Runtime

This crate contains Nebula's local testnet readiness contract and command-line
runner. It is intentionally self-contained and does not depend on inherited
node, wallet, mining, reproducible-build, or daemon surfaces.

## Target Architecture And Launch Plan

The public testnet target is a Monero Layer 2 with deterministic sub-second
block slots, native `NBLA` gas, bridged Monero gas as `nXMR`, and public launch
artifacts that bind deployment evidence before the network is treated as
public. The runtime starts from validator-set epoch `0` and activation height
`1`, then admits only validators whose deployment, operator handoff, operator
acceptance, genesis, launch-package bundle, activation, join, observer, and
launch-certificate artifacts all verify against the same roots.

In the Base-style public testnet phase, a sequencer produces deterministic
sub-second blocks, while followers persist their own local state and
continuously sync Ed25519-signed, verified snapshots from the sequencer or
another upstream peer.

The economics trial keeps live value disabled while proving the accounting
model: `NBLA` gas credits validator rewards directly, and `nXMR` gas funds NBLA
buybacks, NBLA backing, and validator rewards at the target reference price of
`0.001 XMR` per `NBLA`.

Bridge custody is a public-testnet launch gate, not an honor-system credit
path. Policy discovery uses `nebula_bridgePolicy`; deposits use
`nebula_observeBridgeDeposit`; withdrawals use `nebula_requestWithdrawal`; and
withdrawal finalization uses `nebula_finalizeWithdrawal`. Public testnet policy
requires explicit Monero confirmation, custody proof, relayer/observer evidence,
replay protection, and withdrawal finalization evidence before `nXMR` can be
treated as public gas.

Public spend paths require Ed25519 account signatures. For
`nebula_sendTransaction`, `tx.from` is the 32-byte account public key hex and
`tx.signature` signs `RuntimeTransaction::signing_root()`. For
`nebula_requestWithdrawal`, the request includes `nonce` and `signature` over
`withdrawal_authorization_root(account, monero_address, amount_nxmr_units,
nonce)`, and accepted withdrawals consume the account nonce before burning
nXMR into `operator_pending`.

Operator ops, backup, and metrics evidence is also a launch gate. The runtime
surfaces `/ops`, `/backup`, `/metrics`, `nebula_opsStatus`, and
`nebula_backupManifest` are intended for public operators to verify block
freshness, latest height/hash, state/snapshot roots, persisted snapshot path and
presence, sync peer count, RPC limit policy, bridge policy root, backup manifest
root, and scrapeable public ops readiness gauges before opening an endpoint.

Sequencer key rotation and operator accountability are launch gates too. Public
operators must be able to discover the active sequencer key, key-rotation
history/root, accountability evidence root, equivocation evidence, and
mis-signing evidence through `/status` and `nebula_status`, rotate keys through
`nebula_rotateSequencerKey`, and report conflicting block/signature evidence
through `nebula_reportEquivocation`. Unresolved accountability evidence keeps
the public endpoint fail-closed.

The public launch sequence for this crate is:

1. Prove local readiness with formatting, build, tests, the readiness contract,
   and generated sample artifacts for public status, public probe, preflight,
   runbook, deployment, validator-set, operator handoff, operator acceptance,
   genesis, launch package, launch-package bundle, activation, join, observer,
   and launch-certificate gates.
2. Publish and verify the public status and public probe surfaces over HTTPS,
   including the exact endpoint URL, probe body, endpoint policy, TLS
   certificate pin, TLS public-key pin, and launch-bundle identity.
3. Complete preflight and runbook receipts before deployment evidence, keep
   their evidence roots separated, and record fresh rollback drill and
   recovery-point evidence.
4. Fill and verify deployment attestation evidence for bootstrap nodes,
   operators, observers, public endpoint policy, probe, TLS pins, rollback,
   preflight, and runbook material. The deployment root plus bootstrap-roster,
   public-surface, operator-approval, observer-confirmation,
   rollback-readiness, deployment-validity, deployment-quorum, and
   operational-evidence roots must all verify.
5. Admit the validator set at genesis epoch `0`, with unique validator,
   operator, node, reward-account, consensus-key, network-key, region, contact,
   and P2P endpoint material, then verify the operator-roster and reward-ledger
   roots.
6. Build and verify operator handoff, operator acceptance, and the genesis
   manifest for activation height `1`.
7. Verify the strict launch package, then build and verify the launch-package
   bundle that external validators compare before joining.
8. Rehearse the Base-style RPC devnet with one persistent sequencer and
   persisted followers. Followers must import a verified startup snapshot with
   `--bootstrap-rpc`, continuously sync newer verified snapshots from a
   repeatable `--sync-rpc` peer set, and expose matching `/health`, `/status`,
   `/snapshot`, and JSON-RPC `/rpc` views. Each snapshot block must commit to
   the expected sequencer public key and verify its Ed25519 signature before
   accepting the follower. `/health`, `/status`, and `nebula_status` must expose
   configured sync peers so operators can confirm replica failover coverage.
   Public RPC nodes enforce bounded mempool admission, request-size limits, and
   per-client rate limits; tune them with `--max-mempool-transactions`,
   `--max-request-bytes`, and `--max-requests-per-minute`. Admission rejects
   missing senders, duplicate pending account nonces, nonce mismatches, and
   insufficient `NBLA`/`nXMR` balances before consuming bounded capacity.
9. Exercise the bridge custody policy. `nebula_bridgePolicy` must expose the
   active bridge policy root and quorum constants. Deposits must prove the
   current `monero_tx_id`, `account`, `amount_nxmr_units`, `confirmations`,
   `observer_id`, `proof_root`, `custody_proof_root`, `relayer_set_root`,
   `observer_signature_roots`, and observed time fields plus a minimum `10`
   Monero confirmations and at least `2` observer signatures. Withdrawals must
   include account-owner `nonce` and `signature` evidence, then stay
   `operator_pending` until `nebula_finalizeWithdrawal` binds the `withdrawal_id`,
   `finalized_monero_tx_id`, `finalization_proof_root`, and at least `2`
   `operator_approval_roots`. `/health`, `/status`, and
   `nebula_status` must expose or agree with `bridge_policy_root`,
   `bridge_min_deposit_confirmations`, `bridge_deposit_observer_quorum`,
   `bridge_withdrawal_operator_quorum`, `bridge_live_value_enabled`,
   `bridge_deposit_count`, and `withdrawal_request_count`.
10. Exercise the operator ops, backup, and metrics evidence gate. `/ops`,
   `/backup`, `/metrics`, `nebula_opsStatus`, and `nebula_backupManifest` must
   agree with `/health`, `/status`, `/snapshot`, and `nebula_status` on block
   freshness, latest height/hash, state root, snapshot root, persisted snapshot
   path and presence, sync peer count, mempool cap/remaining capacity/full
   and admission rejection counts, RPC request-size and rate-limit policy,
   bridge policy root, backup manifest root, and public ops readiness gauges.
   Stale blocks, missing persisted snapshots, mismatched backup roots, missing
   bridge policy roots, full mempools, unexpected admission-rejection spikes, or
   unexpected sync/RPC limit values keep the public endpoint launch-blocked.
11. Exercise sequencer key rotation and operator accountability. `/health`,
   `/status`, and `nebula_status` must expose the current sequencer public key,
   key-rotation history/root, accountability evidence root, equivocation
   evidence, and mis-signing evidence. `nebula_rotateSequencerKey` must bind
   old/new sequencer keys, activation height, rotation proof root, and operator
   approval roots. `nebula_reportEquivocation` must bind conflicting
   block/signature evidence, and unresolved accountability evidence must keep
   the endpoint launch-blocked.
12. Build and verify validator activation receipts, validator join receipts,
   operator join confirmations, public observer confirmations, and the public
   testnet launch-candidate certificate against the same deployment,
   public-surface, validator, genesis, fee-policy, and bundle roots.
13. Open the public launch gate only after the signed launch package, verified
    bundle, sequencer/follower rehearsal evidence, verified snapshots, and
    launch certificate all agree. Run the `NBLA`/`nXMR` economics trial with
    live value disabled, and keep reporting any remaining blocking evidence
    until every deployment, operator, validator, observer, RPC, snapshot, bridge
    custody, ops/backup, key-rotation/accountability, certificate, and economics
    gap is closed.

## Local RPC Devnet

Run a local Base-style public-testnet rehearsal with one sequencer and
persisted followers:

```bash
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --run-rpc --sequencer --rpc-bind 127.0.0.1:9944 --block-ms 250 --validator-id validator-a --data-dir /tmp/nebula-validator-a --admin-token <operator-token> --max-mempool-transactions 10000 --max-request-bytes 1048576 --max-requests-per-minute 600
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --run-rpc --follower --rpc-bind 127.0.0.1:9945 --block-ms 250 --validator-id validator-b --data-dir /tmp/nebula-validator-b --sequencer-public-key <sequencer-public-key-hex> --bootstrap-rpc http://127.0.0.1:9944/snapshot --sync-rpc http://127.0.0.1:9944/snapshot --sync-rpc http://127.0.0.1:9946/snapshot --max-mempool-transactions 10000 --max-request-bytes 1048576 --max-requests-per-minute 600
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --run-rpc --follower --rpc-bind 127.0.0.1:9946 --block-ms 250 --validator-id validator-c --data-dir /tmp/nebula-validator-c --sequencer-public-key <sequencer-public-key-hex> --bootstrap-rpc http://127.0.0.1:9944/snapshot --sync-rpc http://127.0.0.1:9944/snapshot --sync-rpc http://127.0.0.1:9945/snapshot --max-mempool-transactions 10000 --max-request-bytes 1048576 --max-requests-per-minute 600
```

The sequencer produces sub-second blocks. Followers do not produce blocks; they
persist `nebula-runtime-snapshot.json` under `--data-dir`. `--bootstrap-rpc`
imports one verified snapshot at startup. Repeat
`--sync-rpc <http://peer/snapshot>` for the sequencer and replica peers; the
follower keeps fetching, verifying, importing, and persisting newer snapshots
from the highest ahead peer whose snapshot extends local state. `/health`,
`/status`, and `nebula_status` expose the configured `sync_peer_urls` list,
per-peer `sync_peer_telemetry`, successful peer count, attempt/success/failure/import
counts, stale snapshot count, and fork rejection count. Followers remain
launch-blocked with `follower-no-successful-sync-peer` until at least one
configured peer has returned a valid snapshot response.

Public RPC nodes enforce a bounded local mempool, maximum request body size, and
per-client request rate limit before dispatching JSON-RPC work. Use
`--max-mempool-transactions <count>`, `--max-request-bytes <bytes>`, and
`--max-requests-per-minute <count>` to tune rehearsals or public endpoint
hardening. `/health`, `/status`, `/ops`, `/backup`, and `nebula_status` expose
the mempool cap, remaining capacity, full/admission rejection counts, and admin
RPC state. Signed spend admission rejects missing senders, duplicate pending
account nonces, nonce mismatches, and insufficient `NBLA`/`nXMR` balances before
consuming local mempool capacity.

Operator-only JSON-RPC methods require a node started with
`--admin-token <operator-token>` and request params containing
`"admin_token": "<operator-token>"`. This protects `nebula_importSnapshot`,
`nebula_observeBridgeDeposit`, `nebula_finalizeWithdrawal`,
`nebula_rotateSequencerKey`, `nebula_reportEquivocation`, and
`nebula_produceBlock` from the public RPC surface. Public read/query and user
flow methods remain callable without that token.

Bridge custody policy is rehearsed over the existing RPC names.
`nebula_bridgePolicy` reports the active policy root and quorum constants.
The faucet credits only `NBLA`; `faucet_nxmr_units` must remain `0`, and nXMR
enters runtime state only through bridge deposit evidence.
`nebula_observeBridgeDeposit` accepts a deposit with `monero_tx_id`, `account`,
`amount_nxmr_units`, `confirmations`, `observer_id`, `proof_root`,
`custody_proof_root`, `relayer_set_root`, `observer_signature_roots`, and
`observed_at_unix_ms`. `nebula_requestWithdrawal` accepts `account`,
`monero_address`, `amount_nxmr_units`, `nonce`, and `signature`, then keeps the
withdrawal `operator_pending` until `nebula_finalizeWithdrawal` supplies
`withdrawal_id`,
`finalized_monero_tx_id`, `finalization_proof_root`, and
`operator_approval_roots`. Public testnet operators should require `/health`,
`/status`, and `nebula_status` to report or agree with the bridge policy root,
confirmation floor, observer quorum, withdrawal operator quorum, live-value
disabled state, deposit count, withdrawal count, finalized withdrawal count,
replay cache count, `bridge_only_nxmr`, `bridge_custody_reconciled`, and zero
`nxmr_custody_deficit_units` before advertising `nXMR` gas.

Operator ops, backup, and metrics evidence is exposed through `GET /ops`,
`GET /backup`, `GET /metrics`, JSON-RPC `nebula_opsStatus`, and JSON-RPC
`nebula_backupManifest`. Before advertising a public endpoint, operators should
compare those reports with `/health`, `/status`, `/snapshot`, and
`nebula_status` and verify block
freshness, latest height/hash, state root, snapshot root, persisted snapshot
path and presence, configured sync peer count, mempool cap/remaining capacity,
full/admission rejection counts, RPC max-request/rate-limit policy, admin RPC
state, bridge policy root, bridge custody reconciliation, and backup manifest
root. The metrics scrape must expose matching block freshness, mempool pressure,
RPC limit, peer count, bridge counter, storage snapshot, accountability, bridge
custody, and public ops readiness gauges.
Backup manifests must bind the node role, validator ID, latest chain head,
state/snapshot roots, persisted snapshot location, sync peer coverage, mempool
capacity policy, full/admission rejection counters, RPC limit policy, admin RPC
state, bridge policy root, and nXMR custody reconciliation without exporting
sequencer secret key material. Snapshots imported by followers must have a state
root that matches the latest signed block state root; wait for the next
sub-second block after direct bridge/faucet/withdrawal mutations before using a
snapshot as bootstrap evidence.

The default dev sequencer key is only for throwaway local rehearsals. Public
rehearsals should pass `--sequencer-public-key <hex>` to all nodes and pass the
matching `--sequencer-secret-key <hex>` only to the sequencer. Snapshots export
the public sequencer key and block signatures, never the secret key.

Sequencer key rotation and accountability are rehearsed over
`nebula_rotateSequencerKey` and `nebula_reportEquivocation`. Public operators
should require `/health`, `/status`, and `nebula_status` to expose the current
sequencer key, key-rotation history/root, latest rotation activation height,
accountability evidence root, equivocation evidence, and mis-signing evidence
before advertising an endpoint. Rotation RPC parameters are
`admin_token`, `new_sequencer_secret_key_hex`, `operator_id`, and
`approval_root`; the response binds the old key, new key, activation height,
approval root, and rotation root. Equivocation RPC parameters are `height`,
`first_block_hash`, `second_block_hash`, `reporter_id`, `evidence_root`, and
`admin_token`; unresolved evidence halts block production and state mutations
while status/ops evidence remains visible.

Each node exposes `/health`, `/status`, `/snapshot`, `/ops`, `/backup`,
`/metrics`, and JSON-RPC 2.0 on `/rpc` for
`nebula_status`, `nebula_chainHead`, `nebula_getBlockByHeight`,
`nebula_getAccount`, `nebula_getReceipt`, `nebula_exportSnapshot`,
`nebula_importSnapshot`, `nebula_feeQuote`, `nebula_faucet`,
`nebula_sendTransaction`, `nebula_observeBridgeDeposit`,
`nebula_requestWithdrawal`, `nebula_finalizeWithdrawal`, `nebula_bridgePolicy`,
`nebula_opsStatus`, `nebula_backupManifest`, `nebula_rotateSequencerKey`,
`nebula_reportEquivocation`, and `nebula_produceBlock`.

Real endpoint deployment evidence starts by building public status and probe
artifacts for the actual HTTPS URL, then building a deployment attestation from
those artifacts, preflight/runbook receipts, TLS pins, bootstrap nodes,
operators, observers, and rollback evidence:

```bash
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --build-public-status --endpoint-url https://testnet.nebula.example/status > /tmp/nebula-public-status.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --build-public-probe --endpoint-url https://testnet.nebula.example/status > /tmp/nebula-public-probe.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --build-deployment-attestation --public-status /tmp/nebula-public-status.json --public-probe /tmp/nebula-public-probe.json --preflight-receipt /tmp/nebula-preflight.json --runbook-receipt /tmp/nebula-runbook.json --tls-pin <cert_sha256,public_key_sha256,not_after_unix_ms> --tls-pin <cert_sha256,public_key_sha256,not_after_unix_ms> --bootstrap-node <node_id,operator_id,region,endpoint> --bootstrap-node <node_id,operator_id,region,endpoint> --operator <operator_id,region,public_key> --operator <operator_id,region,public_key> --observer <observer_id,region,public_key> --observer <observer_id,region,public_key> --rollback-plan-sha3-256 <hex> --rollback-recovery-root <hex> > /tmp/nebula-attestation.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-deployment-attestation /tmp/nebula-attestation.json --json
```

## Commands

```bash
cargo fmt --manifest-path crates/nebula-testnet/Cargo.toml -- --check
cargo build --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet
cargo test --manifest-path crates/nebula-testnet/Cargo.toml -- --test-threads=1
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --run-rpc --sequencer --rpc-bind 127.0.0.1:9944 --block-ms 250 --validator-id validator-a --data-dir /tmp/nebula-validator-a --admin-token <operator-token> --max-mempool-transactions 10000 --max-request-bytes 1048576 --max-requests-per-minute 600
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --run-rpc --follower --rpc-bind 127.0.0.1:9946 --block-ms 250 --validator-id validator-c --data-dir /tmp/nebula-validator-c --sequencer-public-key <sequencer-public-key-hex> --bootstrap-rpc http://127.0.0.1:9944/snapshot --sync-rpc http://127.0.0.1:9944/snapshot --sync-rpc http://127.0.0.1:9945/snapshot --max-mempool-transactions 10000 --max-request-bytes 1048576 --max-requests-per-minute 600
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
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --build-operator-handoff --deployment-attestation /tmp/nebula-attestation.json --validator-set /tmp/nebula-validator-set.json > /tmp/nebula-operator-handoff.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-operator-handoff /tmp/nebula-operator-handoff.json --deployment-attestation /tmp/nebula-attestation.json --validator-set /tmp/nebula-validator-set.json --json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --build-operator-acceptance --operator-handoff /tmp/nebula-operator-handoff.json --deployment-attestation /tmp/nebula-attestation.json --validator-set /tmp/nebula-validator-set.json > /tmp/nebula-operator-acceptance.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-operator-acceptance /tmp/nebula-operator-acceptance.json --operator-handoff /tmp/nebula-operator-handoff.json --deployment-attestation /tmp/nebula-attestation.json --validator-set /tmp/nebula-validator-set.json --json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --build-genesis-manifest --deployment-attestation /tmp/nebula-attestation.json --validator-set /tmp/nebula-validator-set.json > /tmp/nebula-genesis.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-genesis-manifest /tmp/nebula-genesis.json --json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-launch-package --deployment-attestation /tmp/nebula-attestation.json --public-status /tmp/nebula-public-status.json --public-probe /tmp/nebula-public-probe.json --validator-set /tmp/nebula-validator-set.json --operator-handoff /tmp/nebula-operator-handoff.json --operator-acceptance /tmp/nebula-operator-acceptance.json --genesis-manifest /tmp/nebula-genesis.json --json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --build-launch-package-bundle --deployment-attestation /tmp/nebula-attestation.json --public-status /tmp/nebula-public-status.json --public-probe /tmp/nebula-public-probe.json --validator-set /tmp/nebula-validator-set.json --operator-handoff /tmp/nebula-operator-handoff.json --operator-acceptance /tmp/nebula-operator-acceptance.json --genesis-manifest /tmp/nebula-genesis.json > /tmp/nebula-launch-package-bundle.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-launch-package-bundle /tmp/nebula-launch-package-bundle.json --deployment-attestation /tmp/nebula-attestation.json --public-status /tmp/nebula-public-status.json --public-probe /tmp/nebula-public-probe.json --validator-set /tmp/nebula-validator-set.json --operator-handoff /tmp/nebula-operator-handoff.json --operator-acceptance /tmp/nebula-operator-acceptance.json --genesis-manifest /tmp/nebula-genesis.json --json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --build-validator-activation --launch-package-bundle /tmp/nebula-launch-package-bundle.json --deployment-attestation /tmp/nebula-attestation.json --public-status /tmp/nebula-public-status.json --public-probe /tmp/nebula-public-probe.json --validator-set /tmp/nebula-validator-set.json --operator-handoff /tmp/nebula-operator-handoff.json --operator-acceptance /tmp/nebula-operator-acceptance.json --genesis-manifest /tmp/nebula-genesis.json > /tmp/nebula-validator-activation.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-validator-activation /tmp/nebula-validator-activation.json --launch-package-bundle /tmp/nebula-launch-package-bundle.json --deployment-attestation /tmp/nebula-attestation.json --public-status /tmp/nebula-public-status.json --public-probe /tmp/nebula-public-probe.json --validator-set /tmp/nebula-validator-set.json --operator-handoff /tmp/nebula-operator-handoff.json --operator-acceptance /tmp/nebula-operator-acceptance.json --genesis-manifest /tmp/nebula-genesis.json --json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --build-validator-join --validator-activation /tmp/nebula-validator-activation.json --launch-package-bundle /tmp/nebula-launch-package-bundle.json --deployment-attestation /tmp/nebula-attestation.json --public-status /tmp/nebula-public-status.json --public-probe /tmp/nebula-public-probe.json --validator-set /tmp/nebula-validator-set.json --operator-handoff /tmp/nebula-operator-handoff.json --operator-acceptance /tmp/nebula-operator-acceptance.json --genesis-manifest /tmp/nebula-genesis.json > /tmp/nebula-validator-join.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-validator-join /tmp/nebula-validator-join.json --validator-activation /tmp/nebula-validator-activation.json --launch-package-bundle /tmp/nebula-launch-package-bundle.json --deployment-attestation /tmp/nebula-attestation.json --public-status /tmp/nebula-public-status.json --public-probe /tmp/nebula-public-probe.json --validator-set /tmp/nebula-validator-set.json --operator-handoff /tmp/nebula-operator-handoff.json --operator-acceptance /tmp/nebula-operator-acceptance.json --genesis-manifest /tmp/nebula-genesis.json --json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --build-operator-join-confirmation --validator-join /tmp/nebula-validator-join.json --validator-activation /tmp/nebula-validator-activation.json --launch-package-bundle /tmp/nebula-launch-package-bundle.json --deployment-attestation /tmp/nebula-attestation.json --public-status /tmp/nebula-public-status.json --public-probe /tmp/nebula-public-probe.json --validator-set /tmp/nebula-validator-set.json --operator-handoff /tmp/nebula-operator-handoff.json --operator-acceptance /tmp/nebula-operator-acceptance.json --genesis-manifest /tmp/nebula-genesis.json > /tmp/nebula-operator-join-confirmation.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-operator-join-confirmation /tmp/nebula-operator-join-confirmation.json --validator-join /tmp/nebula-validator-join.json --validator-activation /tmp/nebula-validator-activation.json --launch-package-bundle /tmp/nebula-launch-package-bundle.json --deployment-attestation /tmp/nebula-attestation.json --public-status /tmp/nebula-public-status.json --public-probe /tmp/nebula-public-probe.json --validator-set /tmp/nebula-validator-set.json --operator-handoff /tmp/nebula-operator-handoff.json --operator-acceptance /tmp/nebula-operator-acceptance.json --genesis-manifest /tmp/nebula-genesis.json --json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --build-public-observer-confirmation --operator-join-confirmation /tmp/nebula-operator-join-confirmation.json --validator-join /tmp/nebula-validator-join.json --validator-activation /tmp/nebula-validator-activation.json --launch-package-bundle /tmp/nebula-launch-package-bundle.json --deployment-attestation /tmp/nebula-attestation.json --public-status /tmp/nebula-public-status.json --public-probe /tmp/nebula-public-probe.json --validator-set /tmp/nebula-validator-set.json --operator-handoff /tmp/nebula-operator-handoff.json --operator-acceptance /tmp/nebula-operator-acceptance.json --genesis-manifest /tmp/nebula-genesis.json > /tmp/nebula-public-observer-confirmation.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-public-observer-confirmation /tmp/nebula-public-observer-confirmation.json --operator-join-confirmation /tmp/nebula-operator-join-confirmation.json --validator-join /tmp/nebula-validator-join.json --validator-activation /tmp/nebula-validator-activation.json --launch-package-bundle /tmp/nebula-launch-package-bundle.json --deployment-attestation /tmp/nebula-attestation.json --public-status /tmp/nebula-public-status.json --public-probe /tmp/nebula-public-probe.json --validator-set /tmp/nebula-validator-set.json --operator-handoff /tmp/nebula-operator-handoff.json --operator-acceptance /tmp/nebula-operator-acceptance.json --genesis-manifest /tmp/nebula-genesis.json --json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --build-public-testnet-launch-certificate --public-observer-confirmation /tmp/nebula-public-observer-confirmation.json --operator-join-confirmation /tmp/nebula-operator-join-confirmation.json --validator-join /tmp/nebula-validator-join.json --validator-activation /tmp/nebula-validator-activation.json --launch-package-bundle /tmp/nebula-launch-package-bundle.json --deployment-attestation /tmp/nebula-attestation.json --public-status /tmp/nebula-public-status.json --public-probe /tmp/nebula-public-probe.json --validator-set /tmp/nebula-validator-set.json --operator-handoff /tmp/nebula-operator-handoff.json --operator-acceptance /tmp/nebula-operator-acceptance.json --genesis-manifest /tmp/nebula-genesis.json > /tmp/nebula-public-testnet-launch-certificate.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-public-testnet-launch-certificate /tmp/nebula-public-testnet-launch-certificate.json --public-observer-confirmation /tmp/nebula-public-observer-confirmation.json --operator-join-confirmation /tmp/nebula-operator-join-confirmation.json --validator-join /tmp/nebula-validator-join.json --validator-activation /tmp/nebula-validator-activation.json --launch-package-bundle /tmp/nebula-launch-package-bundle.json --deployment-attestation /tmp/nebula-attestation.json --public-status /tmp/nebula-public-status.json --public-probe /tmp/nebula-public-probe.json --validator-set /tmp/nebula-validator-set.json --operator-handoff /tmp/nebula-operator-handoff.json --operator-acceptance /tmp/nebula-operator-acceptance.json --genesis-manifest /tmp/nebula-genesis.json --json
```

The readiness report keeps local testnet acceptance separate from public launch
approval. The local testnet can be ready while public launch remains blocked by
the required deployment attestation.

Public status and probe builders let operators produce the exact public
surface, including the expected public status endpoint URL, before wrapping it
in deployment evidence. Custom endpoint surfaces are checked against the
deployment attestation and public observer confirmation instead of the
sample-only standalone verifiers.

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
roots. The deployment verifier reports a deterministic bootstrap-roster root
over the attested bootstrap node IDs, operator IDs, regions, and HTTPS
endpoints. It also reports a deterministic operational-evidence root over the
preflight receipt, runbook receipt, rollback plan, rollback drill time, and
recovery-point root.
The deployment verifier also reports a deterministic public-surface root over
the launch bundle, public status root, public endpoint URL, TLS pins, policy
claim root, and public probe root.
It also reports a deterministic operator-approval root over the attested
operator IDs, regions, public keys, signed witness root, and signature roots.
It also reports a deterministic observer-confirmation root over observer IDs,
regions, observed endpoint URL, observed witness root, signature material, and
verification status.
It also reports a deterministic rollback-readiness root over deployment
generation time, preflight and runbook roots, rollback plan, rollback drill
time, and recovery-point root.
It also reports a deterministic deployment-validity root over attestation
generation and expiry times, public endpoint URL, launch bundle root, validity
policy constants, and TLS pin expiry evidence.
It also reports a deterministic deployment-quorum root over the required and
actual bootstrap, operator, observer, and deployment-region coverage.

Preflight and runbook receipt verifiers let operators prove launch steps before
wrapping those receipts in deployment evidence. Receipt phase names must be
unique, step names must be unique within each phase, and step evidence roots
must be unique across the receipt. Runbook receipts must not reuse preflight
evidence roots. Receipts must complete before deployment evidence is generated,
and receipts older than `24` hours are rejected.

Gas can be paid in native `NBLA` or bridged Monero as `nXMR`. `NBLA` fees go
directly to the validator reward ledger. The faucet credits only `NBLA`; `nXMR`
must be credited by bridge deposits. `nXMR` fees are converted into NBLA
accounting value and are the funding source for NBLA buybacks, NBLA backing, and
validator rewards. Converted `nXMR` value is split with `90%` reserved for NBLA
buybacks and backing and `10%` credited to validator rewards. Fees and
validator points are denominated in `nebulai`, where
`1 NBLA = 1,000,000 nebulai` and the target buyback and reserve reference is
`1 NBLA = 0.001 XMR`, represented on Nebula as `1 NBLA = 0.001 nXMR`.

The validator-set verifier requires genesis epoch `0`, at least two validators,
two operators, and two regions. Validator IDs, operator IDs, and node IDs must
not contain whitespace or reuse each other. Operator IDs must be unique across
admitted validators. Validator region labels must not contain whitespace.
Validator IDs, node IDs, keys, reward accounts, and P2P endpoints must be
unique. No single validator or operator may hold more than `5000` basis points
of total genesis power. Operator contacts must use `mailto:` or `https://`.
`mailto:` contacts must include exactly one email address with no
query/fragment components, `https://` contacts must include a host and no
userinfo/query/fragment components, and P2P endpoints must use
`tcp://host:port` with no path/userinfo/query/fragment components.
Validator admission reward accounts must use
`nbla-reward-{operator_id}` and rewards are denominated in `nebulai`. Each
signed admission root must bind the validator identity, operator contact, keys,
reward account, commission, genesis power, reward unit, and fee-policy root.
Consensus and network public keys must be 64-character hex values, and
consensus/network key domains must be disjoint. The verifier reports a
deterministic operator-roster root derived from the admitted operator IDs,
validator IDs, node IDs, regions, contact endpoints, P2P endpoints, and
commission settings. It also reports a deterministic reward-ledger root and
reward-account count derived from the admitted validator reward accounts.

The operator handoff manifest is generated from a verified deployment
attestation and validator-set manifest. It gives each admitted operator a
deterministic entry covering operator ID, validator ID, node ID, region,
operator contact, bootstrap endpoint, P2P endpoint, reward account, consensus
and network keys, genesis power, signed admission root, and bootstrap
attestation root. Each entry has its own handoff root, and the manifest root
binds the launch-bundle root, validator-set root, validator-deployment-binding
root, and all entries.

The operator acceptance manifest is generated from a verified handoff manifest,
deployment attestation, and validator-set manifest. It records one fresh
acceptance entry per handoff entry, binds the accepted handoff root, operator
public key, validator ID, node ID, and launch-bundle root, and verifies the
operator acceptance signature root.

The genesis manifest builder binds verified deployment evidence and validator
admission into the root artifact used to start a public testnet at activation
height `1` with validator-set epoch `0`. Genesis deployment, validator-set,
public-surface, operator-approval, observer-confirmation, bootstrap-roster,
rollback-readiness, deployment-validity, operator-roster, reward-ledger,
deployment-quorum, validator-deployment-binding, fee-policy, and
operational-evidence roots must be disjoint from validator-admission roots, and
initial validator, operator, and region counts must match the verified
validator set.
Genesis manifests older than `24` hours are rejected. The final launch-package
check requires the genesis timestamp to fall inside the deployment attestation
validity window.

The launch-package verifier checks that the deployment, public surface,
validator set, operator handoff, operator acceptance, and genesis artifacts all
agree before operators advance to a live rollout, with deployment attestations
expiring within `7` days of generation. It reports the verified deployment
observer quorum count and
deployment region count, public-surface root, operator-approval root,
observer-confirmation root, bootstrap-roster root, operator-roster root,
matched reward-account count, reward-ledger root, rollback-readiness root,
deployment-validity root, operational-evidence root, and the genesis fee token
identities. It also reports the deployment-quorum root and
validator-deployment-binding root and operator-handoff root and rejects
validator consensus/network keys that reuse deployment witness keys, admitted
validators that do not map to
attested deployment operators and bootstrap nodes, validator P2P hosts that do
not match their attested bootstrap endpoint host, plus deployment operators or
bootstrap nodes that are not represented by an admitted validator. The strict
package gate also verifies that operator acceptance entries bind the same
handoff root and accepted operator/validator counts.

The launch-package bundle builder emits the compact manifest external
validators should compare before joining. It binds the seven launch artifact
SHA3-256 digests, the verified artifact roots, the operator acceptance root,
the deterministic launch-package root, and the bundle root.

The validator activation builder records one activated entry per admitted
validator after bundle verification. Each entry binds the validator identity,
P2P endpoint, validator keys, reward account, launch-package bundle root, and
operator acceptance root before the set is treated as ready to join.

The validator join builder records one join entry per activated validator. Each
entry proves the validator observed the chain at or after activation height and
with the required peer count before the set is treated as joined.

The operator join confirmation builder records one confirmation entry per joined
validator. Each entry binds the validator join root, validator activation root,
launch-package bundle root, operator acceptance root, and operator confirmation
signature root before the joined set is treated as operator-confirmed.

The public observer confirmation builder records one confirmation entry per
deployment observer after operator-confirmed validator join. Each entry binds the
public endpoint, public status root, public probe root, operator join
confirmation root, observer region, and observer signature root.

The public testnet launch certificate builder binds every verified launch
artifact root and the validator, operator, observer, and region counts into one
candidate certificate root for final operator comparison.
