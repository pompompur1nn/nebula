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

## Target Public Testnet Architecture

Nebula's public testnet target is a Monero Layer 2 that keeps Monero as the
external settlement and privacy asset while Nebula provides a fast
validator-operated execution layer. The testnet is planned around deterministic
sub-second block slots, private low-fee execution, public launch evidence, and a
hybrid gas model that accepts both native `NBLA` and bridged Monero as `nXMR`.

The target architecture is:

- a standalone Nebula Rust runtime with genesis validator-set epoch `0` and
  activation height `1`
- a Base-style public testnet phase where a sequencer produces deterministic
  sub-second blocks after launch package verification, while followers persist
  local state and continuously sync Ed25519-signed, verified snapshots from a
  sequencer/replica peer set with failover, with public RPC nodes enforcing
  bounded mempool admission, request-size limits, and per-client rate limits
- public status and public probe surfaces that are bound into deployment
  evidence before operators can label the testnet public
- bootstrap nodes, operators, and observers tied to one deployment witness root
  for endpoint, TLS pin, policy, probe, and launch-bundle evidence
- `NBLA` as the native gas and validator-accounting token
- `nXMR` as the bridged Monero gas token used for users who want to pay gas from
  bridged XMR liquidity
- nXMR-funded NBLA buybacks, NBLA backing, and validator rewards at the target
  reference price of `0.001 XMR` per `NBLA`
- explicit Monero bridge custody policy for `nebula_bridgePolicy`,
  `nebula_observeBridgeDeposit`, `nebula_requestWithdrawal`, and
  `nebula_finalizeWithdrawal`: minimum confirmations, operator custody quorum,
  relayer/observer quorum, replay protection, withdrawal finalization evidence,
  bridge-only nXMR crediting, custody reconciliation, and `/health`/`/status`
  visibility
- Ed25519 account signatures for public spend paths: `nebula_sendTransaction`
  transactions must be signed by `tx.from`, and `nebula_requestWithdrawal`
  must bind account, destination, amount, nonce, and signature before nXMR burns
- operator ops, backup, and scrapeable metrics evidence through `/ops`, `/backup`,
  `/metrics`,
  `nebula_opsStatus`, and `nebula_backupManifest` so public operators can
  verify block freshness, chain head, state/snapshot roots, persisted snapshot
  state, sync peers, RPC limits, admin RPC state, bridge policy root, and
  backup manifest root before opening endpoints
- post-quantum attestation roots and role-separated validator, operator,
  observer, witness, TLS, consensus, and network keys

Public testnet accounting is intentionally separated from live-value policy.
Validator rewards are testnet points in `nebulai`, and nXMR-funded NBLA
buyback and backing entries are launch-policy accounting until a later live-value
policy is explicitly enabled.

## Public Testnet Launch Plan

The complete public-testnet rollout is evidence-first and staged in this order.
Each stage carries the roots, receipts, and operator-visible reports needed by
the next stage, and `public_launch_ready` must remain `false` while any required
evidence is absent or stale.

1. Prove local readiness from a clean checkout with formatting, build, tests,
   and the readiness contract. Generate and verify sample public status, public
   probe, preflight receipt, runbook receipt, deployment attestation,
   validator-set, operator-handoff, operator-acceptance, genesis,
   launch-package, launch-package bundle, validator activation, validator join,
   operator join confirmation, public observer confirmation, and launch
   certificate artifacts.
2. Publish the public status endpoint and public probe endpoint over HTTPS. Bind
   the exact public status URL, probe body, endpoint policy, TLS certificate pin,
   TLS public-key pin, and launch-bundle identity into the public-surface root.
3. Complete the preflight and runbook receipts before deployment evidence is
   generated. Keep phase names, step names, and step evidence roots unique, keep
   preflight and runbook evidence separated, and record fresh rollback drill and
   recovery-point evidence.
4. Fill deployment attestation evidence for bootstrap nodes, operators,
   observers, endpoint policy, public probe, TLS pins, rollback drill, preflight
   receipt, and runbook receipt. Verify the deployment evidence root plus the
   bootstrap-roster, public-surface, operator-approval,
   observer-confirmation, rollback-readiness, deployment-validity,
   deployment-quorum, and operational-evidence roots.
5. Admit the validator set at genesis epoch `0` with unique validator,
   operator, node, reward-account, consensus-key, network-key, region, contact,
   and P2P endpoint material. Verify operator power limits, region spread,
   reward-ledger root, operator-roster root, and role separation from deployment
   witness keys.
6. Build and verify the operator handoff manifest from the verified deployment
   attestation and validator set so each operator can compare its assigned
   bootstrap endpoint, P2P endpoint, reward account, keys, genesis power, signed
   admission root, and bootstrap attestation root.
7. Build and verify the operator acceptance manifest so every admitted operator
   signs acceptance of the handoff root, launch-bundle root, operator identity,
   validator identity, and node identity before genesis artifacts are accepted.
8. Build and verify the genesis manifest for activation height `1`. Bind the
   deployment, public-surface, validator-set, validator-admission,
   operator-roster, reward-ledger, fee-policy, bootstrap-roster,
   rollback-readiness, deployment-validity, deployment-quorum,
   operational-evidence, operator-approval, observer-confirmation, and
   validator-deployment-binding roots.
9. Verify the strict launch package across deployment attestation, public
   status, public probe, validator set, operator handoff, operator acceptance,
   and genesis. Reject mismatched roots, expired deployment evidence, validator
   keys that reuse deployment witness keys, missing operator/bootstrap coverage,
   or validator P2P hosts that do not match attested bootstrap hosts.
10. Build and verify the launch-package bundle for external validators. Bundle
    the seven launch artifact SHA3-256 digests, verified artifact roots,
    operator acceptance root, launch-package root, and bundle root so validators
    can compare local files before joining.
11. Rehearse the Base-style RPC devnet using the launch package expectations:
    run one persistent sequencer that produces deterministic sub-second blocks,
    pin its Ed25519 sequencer identity with `--sequencer-public-key`, keep the
    matching `--sequencer-secret-key` only on the sequencer, run followers that
    persist `nebula-runtime-snapshot.json`, import a verified startup snapshot
    with `--bootstrap-rpc`, and continuously sync newer verified snapshots from
    a repeatable `--sync-rpc` peer set. Configure public RPC abuse-resistance with
    `--max-mempool-transactions`, `--max-request-bytes`, and
    `--max-requests-per-minute`. Mempool admission is stateful: public nodes
    reject missing senders, duplicate pending account nonces, nonce mismatches,
    and insufficient `NBLA`/`nXMR` balances before consuming bounded capacity.
    Follower ops readiness must include at least one configured sync peer with a
    successful valid snapshot response; attempts, successes, failures, stale
    snapshots, fork rejections, and imports must be visible as telemetry.
12. Confirm the sequencer/follower public-testnet RPC surfaces before launch.
    `/health`, `/status`, `/snapshot`, and JSON-RPC `/rpc` must agree on chain
    head, genesis identity, activation height, fee policy, validator identity,
    state root, snapshot root, sequencer public key, and configured follower sync
    peers plus per-peer sync telemetry. Every snapshot block must commit to the producer public key and verify
    its Ed25519 signature before a follower treats the peer as ready; exported
    snapshots must never include the sequencer secret key. Imported snapshots
    must bind the current state root to the latest signed block and reconcile
    bridge-deposited nXMR against account balances, withdrawal burns, and nXMR
    fees. Public RPC nodes must reject invalid signed spend attempts before mempool admission, reject
    transactions beyond the configured mempool cap, reject oversized requests,
    and throttle per-client request bursts before launch observers treat the
    endpoint as ready.
13. Gate bridge custody before treating `nXMR` as public-testnet gas. The
    `nebula_bridgePolicy` method must expose the policy root and testnet
    custody constants. Deposits submitted through `nebula_observeBridgeDeposit`
    must carry `monero_tx_id`, `account`, `amount_nxmr_units`, `confirmations`,
    `observer_id`, `proof_root`, `custody_proof_root`, `relayer_set_root`,
    `observer_signature_roots`, and observed time, with at least `10` Monero
    confirmations and at least `2` observer signatures. Withdrawals submitted
    through `nebula_requestWithdrawal` must include account-owner `nonce` and
    `signature` evidence, then remain `operator_pending` until
    `nebula_finalizeWithdrawal` binds the `withdrawal_id`,
    `finalized_monero_tx_id`, `finalization_proof_root`, and at least `2`
    `operator_approval_roots`. `/health`, `/status`, and `nebula_status` must
    expose or agree with `bridge_policy_root`,
    `bridge_min_deposit_confirmations`, `bridge_deposit_observer_quorum`,
    `bridge_withdrawal_operator_quorum`, `bridge_live_value_enabled`,
    `faucet_nxmr_units`, `bridge_only_nxmr`, `bridge_custody_reconciled`,
    `nxmr_custody_deficit_units`, `bridge_deposit_count`, and
    `withdrawal_request_count`.
14. Gate operator ops, backup, and metrics evidence before public endpoint
    exposure. `/ops`, `/backup`, `/metrics`, `nebula_opsStatus`, and
    `nebula_backupManifest` must agree with `/health`, `/status`, and
    `nebula_status` on block freshness,
    latest height/hash, state root, snapshot root, persisted snapshot path and
    presence, sync peer count, successful peer count, sync attempt/success/failure/import
    counts, mempool cap/remaining capacity/full and admission rejection counts,
    RPC request-size and rate-limit policy, admin RPC state, bridge policy root,
    bridge custody reconciliation, backup
    manifest root, and public ops readiness gauges. Operators must treat
    stale blocks, missing
    persisted snapshots, mismatched backup roots, missing bridge policy roots,
    nXMR custody deficits, full mempools, followers with no successful sync peer
    evidence, unexpected admission-rejection spikes, disabled or unexpected
    admin RPC state, or unexpected sync/RPC-limit values as public-launch blockers.
15. Gate sequencer key rotation and operator accountability before public
    endpoint exposure. `/health`, `/status`, and `nebula_status` must expose
    the current sequencer public key, sequencer key-rotation history/root,
    accountability evidence root, equivocation evidence, and mis-signing
    evidence. Operators must rehearse `nebula_rotateSequencerKey` with the old
    key, new key, activation height, rotation proof root, and operator approval
    roots, then prove followers fail closed on stale-key blocks. Operator-only
    methods must require `params.admin_token` from a node started with
    `--admin-token`.
    `nebula_reportEquivocation` must bind conflicting block/signature evidence
    to the accountability root, and unresolved equivocation or mis-signing
    evidence must halt block production and state mutations while status/ops
    evidence stays visible.
16. Build and verify validator activation receipts that bind every admitted
    validator to the verified launch-package bundle, activation root, reward
    account, P2P endpoint, consensus key, network key, and operator acceptance
    root.
17. Build and verify validator join receipts after activation. Each activated
    validator must observe the chain at or after activation height `1`, prove the
    required peer count, and sign the observed validator join root.
18. Build and verify operator join confirmations after validator join. Every
    operator must confirm the validator join root, activation root,
    launch-package bundle root, operator acceptance root, and operator
    confirmation signature root.
19. Build and verify public observer confirmations after operator-confirmed
    validator join. Deployment observers must re-check the live public endpoint,
    public status root, public probe root, observer region, and observer
    signature root with the required observer and region coverage.
20. Build and verify the public testnet launch-candidate certificate. The
    certificate binds the launch-package bundle, validator activation, validator
    join, operator join confirmation, public observer confirmation, public
    status, public probe, validator set, genesis, endpoint URL, and validator,
    operator, observer, and region counts into one candidate root.
21. Open the public launch gate only after the signed launch package, verified
    launch-package bundle, Base-style sequencer/follower rehearsal evidence,
    verified snapshots, and launch-candidate certificate all bind to the same
    deployment, public-surface, validator, genesis, and fee-policy roots.
22. Run the economics trial with `NBLA` gas, `nXMR` gas, nXMR-funded NBLA
    buybacks, NBLA backing, and validator-reward accounting at `0.001 XMR` per
    `NBLA`, while live-value policy stays disabled.
23. Publish the remaining blocking evidence list. If any deployment, operator,
    validator, observer, sequencer/follower, snapshot, ops/backup, bridge
    custody, key-rotation/accountability, certificate, or economics evidence is
    missing, mismatched, unsigned, signed by an unexpected sequencer key, or
    stale, keep the public launch gate closed and report the exact blocking gap.

## Local RPC Devnet

The runtime now includes a local in-memory RPC node for public-testnet rehearsal.
It supports the Base-style public testnet phase: a sequencer produces
deterministic sub-second blocks, while follower nodes persist local state and
continuously sync signed, verified snapshots from a configured peer set. It
targets `250 ms` blocks by default, enforces a public-testnet block target below
one second, exposes health/status JSON and scrapeable metrics, accepts transfer transactions, and
accounts for `NBLA` gas, `nXMR` gas, nXMR-funded NBLA buybacks/backing, and
validator rewards. Public RPC nodes enforce stateful signed-spend admission, a
bounded mempool, maximum request body size, and per-client request rate limit;
tune rehearsal limits with
`--max-mempool-transactions`, `--max-request-bytes`, and
`--max-requests-per-minute`. Admission rejects missing senders, duplicate
pending account nonces, nonce mismatches, and insufficient `NBLA`/`nXMR`
balances before consuming local mempool capacity.

Operator-only JSON-RPC methods require a node started with
`--admin-token <operator-token>` and request params containing
`"admin_token": "<operator-token>"`. This protects `nebula_importSnapshot`,
`nebula_observeBridgeDeposit`, `nebula_finalizeWithdrawal`,
`nebula_rotateSequencerKey`, `nebula_reportEquivocation`, and
`nebula_produceBlock` from the public RPC surface. Public read/query and user
flow methods remain callable without that token.

Run a local persistent sequencer:

```bash
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --run-rpc --sequencer --rpc-bind 127.0.0.1:9944 --block-ms 250 --validator-id validator-a --data-dir /tmp/nebula-validator-a --admin-token <operator-token> --max-mempool-transactions 10000 --max-request-bytes 1048576 --max-requests-per-minute 600
```

The default dev sequencer key is only for throwaway local rehearsals. Public
rehearsals should pass `--sequencer-public-key <hex>` to all nodes and pass the
matching `--sequencer-secret-key <hex>` only to the sequencer. The secret key is
kept in process memory and is never exported in `/snapshot`.

Sequencer key rotation and accountability are public-testnet launch gates.
`/health`, `/status`, and `nebula_status` must expose the current sequencer
public key, key-rotation history/root, accountability evidence root,
equivocation evidence root, and mis-signing evidence root. Runtime rotation
uses `nebula_rotateSequencerKey`; public rehearsals should prove the old key,
new key, activation height, rotation proof root, and operator approval roots
agree before followers accept post-rotation blocks. Accountability reports use
`nebula_reportEquivocation` to bind conflicting height/hash/signature evidence
or other sequencer mis-signing evidence. Public endpoints fail closed when
unresolved accountability evidence is present.

The node writes a versioned, self-verifying, Ed25519-signed JSON snapshot to
`nebula-runtime-snapshot.json` under `--data-dir`. Snapshots preserve genesis,
blocks, block signatures, mempool, receipts, bridge deposits, withdrawals,
balances, fee accounting, and current state root across restarts. Followers use
the same snapshot format for persisted local state and reject blocks whose
signature does not verify against the expected sequencer public key.

Public spend flows require Ed25519 account signatures. For
`nebula_sendTransaction`, `tx.from` is the 32-byte account public key hex and
`tx.signature` signs `RuntimeTransaction::signing_root()`. For
`nebula_requestWithdrawal`, the request includes `nonce` and `signature` over
`withdrawal_authorization_root(account, monero_address, amount_nxmr_units,
nonce)`, and accepted withdrawals consume the account nonce before burning
nXMR into `operator_pending`.

Bridge custody rehearsal uses the runtime RPC names that public operators will
see. `nebula_bridgePolicy` reports the active policy root and quorum constants.
The faucet credits only `NBLA`; `faucet_nxmr_units` must remain `0`, and nXMR
enters runtime state only through bridge deposit evidence. Deposits enter through
`nebula_observeBridgeDeposit` with `monero_tx_id`,
`account`, `amount_nxmr_units`, `confirmations`, `observer_id`, `proof_root`,
`custody_proof_root`, `relayer_set_root`, `observer_signature_roots`, and
`observed_at_unix_ms`. Withdrawals enter through `nebula_requestWithdrawal`
with `account`, `monero_address`, `amount_nxmr_units`, `nonce`, and
`signature`, then remain `operator_pending` until `nebula_finalizeWithdrawal`
supplies `withdrawal_id`,
`finalized_monero_tx_id`, `finalization_proof_root`, and
`operator_approval_roots`. `/health`, `/status`, and `nebula_status` are the
operator-facing surfaces for bridge policy visibility and must show
`bridge_only_nxmr`, `bridge_custody_reconciled`, and zero
`nxmr_custody_deficit_units` before `nXMR` gas is advertised.

Operator ops, backup, and metrics evidence uses the runtime surfaces public
operators need during launch rehearsals: `GET /ops`, `GET /backup`,
`GET /metrics`, JSON-RPC
`nebula_opsStatus`, and JSON-RPC `nebula_backupManifest`. Before opening a
public testnet endpoint, operators must compare those reports with `/health`,
`/status`, `/snapshot`, and `nebula_status` and verify block freshness, latest
height/hash, state root, snapshot root, persisted snapshot path and presence,
configured sync peer count, mempool cap/remaining capacity/full and admission
rejection counts, RPC max-request/rate-limit policy, admin RPC state, bridge
policy root, bridge custody reconciliation, and backup manifest root. The
`/metrics` scrape must expose the same block freshness, mempool pressure, RPC
limit, peer count, bridge counter, storage snapshot, accountability, bridge
custody, and public ops readiness gauges. A valid backup manifest must
bind the node role, validator ID, latest chain head, state/snapshot roots,
persisted snapshot location, sync peer coverage, mempool capacity policy,
full/admission rejection counters, RPC limit policy, admin RPC state, bridge
policy root, and nXMR custody reconciliation without exporting any sequencer
secret key material. Snapshots imported by followers must have a state root that
matches the latest signed block state root; operators should wait for the next
sub-second block after direct bridge/faucet/withdrawal mutations before using a
snapshot as bootstrap evidence.

A follower can import once from an ahead peer before it starts serving RPC:

```bash
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --run-rpc --follower --rpc-bind 127.0.0.1:9945 --block-ms 250 --validator-id validator-b --data-dir /tmp/nebula-validator-b --sequencer-public-key <sequencer-public-key-hex> --bootstrap-rpc http://127.0.0.1:9944/snapshot --sync-rpc http://127.0.0.1:9944/snapshot --sync-rpc http://127.0.0.1:9946/snapshot --max-mempool-transactions 10000 --max-request-bytes 1048576 --max-requests-per-minute 600
```

`--bootstrap-rpc` performs that one-time startup import. To keep following a
sequencer plus replica set, repeat `--sync-rpc <http://peer/snapshot>` for each
upstream snapshot peer; the follower continuously fetches, verifies, imports,
and persists newer snapshots from the highest ahead peer whose snapshot extends
local state:

```bash
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --run-rpc --follower --rpc-bind 127.0.0.1:9946 --block-ms 250 --validator-id validator-c --data-dir /tmp/nebula-validator-c --sequencer-public-key <sequencer-public-key-hex> --bootstrap-rpc http://127.0.0.1:9944/snapshot --sync-rpc http://127.0.0.1:9944/snapshot --sync-rpc http://127.0.0.1:9945/snapshot --max-mempool-transactions 10000 --max-request-bytes 1048576 --max-requests-per-minute 600
```

This gives public replicas a Base-style failover shape: each follower can sync
from the sequencer or another verified replica, skip stale or unreachable peers,
and keep serving from its persisted local snapshot. `/health`, `/status`, and
`nebula_status` expose the configured `sync_peer_urls` list, per-peer
`sync_peer_telemetry`, successful peer count, attempt/success/failure/import
counts, stale snapshot count, and fork rejection count. Followers remain
launch-blocked with `follower-no-successful-sync-peer` until at least one
configured peer has returned a valid snapshot response.

HTTP surfaces:

- `GET /health`
- `GET /status`
- `GET /snapshot`
- `GET /ops`
- `GET /backup`
- `GET /metrics`

RPC methods are JSON-RPC 2.0 over `POST /rpc`:

- `nebula_status`
- `nebula_chainHead`
- `nebula_getBlockByHeight`
- `nebula_getAccount`
- `nebula_getReceipt`
- `nebula_exportSnapshot`
- `nebula_importSnapshot`
- `nebula_feeQuote`
- `nebula_faucet`
- `nebula_sendTransaction`
- `nebula_observeBridgeDeposit`
- `nebula_requestWithdrawal`
- `nebula_finalizeWithdrawal`
- `nebula_bridgePolicy`
- `nebula_opsStatus`
- `nebula_backupManifest`
- `nebula_rotateSequencerKey`
- `nebula_reportEquivocation`
- `nebula_produceBlock`

Example trial:

```bash
curl -s http://127.0.0.1:9944/status
curl -s http://127.0.0.1:9944/metrics
curl -s -X POST http://127.0.0.1:9944/rpc -d '{"jsonrpc":"2.0","id":1,"method":"nebula_faucet","params":{"account":"alice"}}'
curl -s -X POST http://127.0.0.1:9944/rpc -d '{"jsonrpc":"2.0","id":2,"method":"nebula_sendTransaction","params":{"tx":{"from":"alice","to":"bob","amount_nebulai":100,"gas_units":100,"gas_price_nebulai":10,"fee_asset":"NBLA","nonce":0,"memo":"first NBLA gas transfer"}}}'
curl -s -X POST http://127.0.0.1:9944/rpc -d '{"jsonrpc":"2.0","id":3,"method":"nebula_getAccount","params":{"account":"bob"}}'
```

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
- deployment-scoped public status/probe validation for custom endpoints
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
- deterministic operational-evidence root for preflight, runbook, and rollback
  evidence
- deterministic public-surface root for endpoint, TLS pins, policy claim, and
  public probe evidence
- deterministic operator-approval root for signed deployment witness approvals
- deterministic observer-confirmation root for independently observed public
  endpoint evidence
- deterministic rollback-readiness root for preflight, runbook, rollback drill,
  and recovery-point evidence
- deterministic deployment-validity root for attestation lifetime and TLS pin
  expiry evidence
- deterministic deployment-quorum root for bootstrap, operator, observer, and
  region coverage
- policy claim and public probe body exact-shape validation
- preflight and runbook receipt exact-shape validation
- bootstrap node/operator and observer attestation exact-shape validation
- validator-set admission, whitespace-free and role-separated identity,
  fixed genesis epoch, deterministic operator-roster root, deterministic
  reward-ledger root, whitespace-free region, contact, reward-unit, uniqueness,
  operator power concentration, and region-spread validation
- genesis manifest root and epoch binding across deployment evidence,
  validator set, operator roster, reward ledger, and fee policy
- genesis manifest operator-count and region-count binding
- launch package reporting for genesis fee token identities
- genesis manifest artifact-root domain separation
- genesis manifest freshness validation
- genesis timestamp binding to the deployment attestation validity window
- launch package coherence across deployment attestation, public surface,
  validator set, and genesis manifest artifacts
- launch package reporting for deployment observer quorum and deployment regions
- launch package binding between admitted validators, deployment operators, and
  bootstrap nodes
- launch package binding for the deterministic deployment bootstrap roster
- launch package binding between validator P2P hosts and attested bootstrap
  endpoint hosts
- launch package key-domain separation between admitted validators and
  deployment witnesses
- launch package host separation between the public endpoint and bootstrap
  endpoints
- launch package rejection of deployment operators and bootstrap nodes that
  have no admitted validator
- launch package bundle artifact hashes, operator acceptance root, and bundle
  root for external validator comparison
- validator activation receipts that bind every admitted validator to the
  verified launch-package bundle
- validator join receipts that prove activated validators observed the chain
  at or after activation height with the required peer count
- operator join confirmations that prove operators acknowledged the final
  validator join receipt
- public observer confirmations that prove deployment observers re-confirmed
  the public endpoint after operator-confirmed validator join
- a public testnet launch-candidate certificate that binds the full artifact
  chain into one root for operator handoff
- bootstrap node/operator region binding inside deployment evidence

## Hybrid Fees And Validator Rewards

Nebula testnet uses a hybrid fee policy:

- Gas can be paid in native `NBLA`.
- Gas can also be paid in bridged Monero as `nXMR`.
- The faucet credits only `NBLA`; `nXMR` must be credited by bridge deposits.
- `nebulai` is the base accounting unit for gas and validator rewards.
- `1 NBLA = 1,000,000 nebulai`.
- The target buyback and reserve reference is `1 NBLA = 0.001 XMR`; on Nebula
  this is represented as `1 NBLA = 0.001 nXMR`.
- At that target, one `nXMR` base unit maps to one `nebulai`.
- `NBLA` gas is credited directly to the validator reward ledger.
- `nXMR` gas is converted into NBLA accounting value before distribution and is
  the funding source for NBLA buybacks, NBLA backing, and validator rewards.
- Converted `nXMR` value is split with `90%` reserved for NBLA buybacks and
  backing and `10%` credited to the validator reward ledger.

Public testnet rewards are non-transferable validator points. Points mirror the
validator reward ledger in `nebulai` so validators can prove uptime, attestation
quality, and fee contribution before any live-value reward policy is enabled.
The validator-set verifier reports a deterministic reward-ledger root over the
admitted reward accounts, and the genesis and launch-package gates bind that
root before public testnet rollout.

## Monero Bridge Custody Policy

The public-testnet bridge policy is evidence-first and fail-closed. The runtime
API names are `nebula_bridgePolicy` for policy discovery,
`nebula_observeBridgeDeposit` for deposits, `nebula_requestWithdrawal` for
withdrawal requests, and `nebula_finalizeWithdrawal` for withdrawal
finalization. The status surfaces are `GET /health`, `GET /status`, and
JSON-RPC `nebula_status`.

Deposits must prove:

- at least `10` Monero confirmations before crediting `nXMR`
- a unique `monero_tx_id` replay key and a deterministic replay-protection root
- the destination Nebula `account`, `amount_nxmr_units`, `observer_id`,
  `proof_root`, and `observed_at_unix_ms`
- `custody_proof_root` evidence for the bridge wallet or custody set
- `relayer_set_root` evidence for the relayer set that observed the Monero
  deposit
- at least `2` distinct `observer_signature_roots` agreeing on the credited
  `nXMR` amount

Withdrawals must prove:

- the request burned or locked the caller's `nXMR` and produced a deterministic
  `withdrawal_id`, `bridge_policy_root`, and withdrawal root
- the withdrawal stayed `operator_pending` until at least `2`
  `operator_approval_roots` were present
- `nebula_finalizeWithdrawal` bound the destination Monero address, amount,
  withdrawal root, `finalized_monero_tx_id`, `finalization_proof_root`, and
  finalization timestamp
- withdrawal replay protection prevented the same `withdrawal_id`,
  `finalization_proof_root`, or Monero payout transaction from finalizing twice

Public launch observers should treat the bridge as launch-blocked unless
`/health`, `/status`, and `nebula_status` expose or agree with
`bridge_policy_root`, `bridge_min_deposit_confirmations`,
`bridge_deposit_observer_quorum`, `bridge_withdrawal_operator_quorum`,
`bridge_live_value_enabled`, `faucet_nxmr_units`, `bridge_only_nxmr`,
`bridge_custody_reconciled`, `nxmr_custody_deficit_units`,
`bridge_deposit_count`, and `withdrawal_request_count`, and
`nebula_bridgePolicy` returns the same policy root. `bridge_live_value_enabled`
must remain `false`, `faucet_nxmr_units` must remain `0`, and
`nxmr_custody_deficit_units` must remain `0` for public testnet.

## Sequencer Key Rotation And Accountability

Public testnet operators must be able to discover the current sequencer key and
prove rotation readiness before an endpoint is advertised. `GET /health`,
`GET /status`, and JSON-RPC `nebula_status` should agree on the active
sequencer public key, the sequencer key-rotation history/root, the latest
rotation activation height, the accountability evidence root, and unresolved
equivocation or mis-signing evidence counts.

Key rotation uses `nebula_rotateSequencerKey` with
`new_sequencer_secret_key_hex`, `operator_id`, and `approval_root`. A public
rehearsal must prove the response binds the old sequencer public key, new
sequencer public key, activation height, approval root, and rotation root, then
prove followers reject stale-key blocks and accept only blocks signed by the
active key after the activation height. Rotation history must be rooted so
launch observers can compare it across `/status`, `nebula_status`, and
snapshots.

Accountability evidence uses `nebula_reportEquivocation` with `height`,
`first_block_hash`, `second_block_hash`, `reporter_id`, and `evidence_root`.
The evidence root must bind the conflicting signatures or mis-signing proof
outside the canonical block hash pair. Public testnet launch stays fail-closed
when unresolved equivocation, stale-key signing, or other sequencer mis-signing
evidence is present, and the runtime halts block production and state mutations
while status/ops evidence remains visible.

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

The deployment attestation verifier reports a deterministic bootstrap-roster
root over the attested bootstrap node IDs, operator IDs, regions, and HTTPS
endpoints. The genesis and launch-package gates bind that root so operators can
compare the exact public bootstrap set before rollout.
It also reports a deterministic operational-evidence root over the preflight
receipt, runbook receipt, rollback plan, rollback drill time, and recovery-point
root.
The verifier also reports a deterministic public-surface root over the launch
bundle, public status root, public endpoint URL, TLS pins, policy claim root,
and public probe root.
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

Operators should build the public status/probe surface for the actual HTTPS
endpoint before filling deployment evidence. Custom endpoint surfaces are bound
to deployment attestations and later observer confirmations; the standalone
sample verifiers remain intentionally sample-shaped:

```bash
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --build-public-status --endpoint-url https://testnet.nebula.example/status > /tmp/nebula-public-status.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --build-public-probe --endpoint-url https://testnet.nebula.example/status > /tmp/nebula-public-probe.json
```

Sample-only fixtures remain available for local rehearsal:

```bash
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --sample-public-status > /tmp/nebula-sample-public-status.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-public-status /tmp/nebula-sample-public-status.json --json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --sample-public-probe > /tmp/nebula-sample-public-probe.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-public-probe /tmp/nebula-sample-public-probe.json --json
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

Operators can build the deployment attestation from real public-surface,
preflight, runbook, TLS, operator, observer, bootstrap, and rollback evidence,
then verify the filled attestation with:

```bash
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --build-deployment-attestation --public-status /tmp/nebula-public-status.json --public-probe /tmp/nebula-public-probe.json --preflight-receipt /tmp/nebula-preflight.json --runbook-receipt /tmp/nebula-runbook.json --tls-pin <cert_sha256,public_key_sha256,not_after_unix_ms> --tls-pin <cert_sha256,public_key_sha256,not_after_unix_ms> --bootstrap-node <node_id,operator_id,region,endpoint> --bootstrap-node <node_id,operator_id,region,endpoint> --operator <operator_id,region,public_key> --operator <operator_id,region,public_key> --observer <observer_id,region,public_key> --observer <observer_id,region,public_key> --rollback-plan-sha3-256 <hex> --rollback-recovery-root <hex> > /tmp/nebula-attestation.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-deployment-attestation /tmp/nebula-attestation.json --json
```

Sample-only deployment fixtures remain available for local rehearsal:

```bash
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --sample-deployment-attestation > /tmp/nebula-sample-attestation.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-deployment-attestation /tmp/nebula-sample-attestation.json --json
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
disjoint. The verifier reports a deterministic operator-roster root over the
admitted operator IDs, validator IDs, node IDs, regions, contact endpoints, P2P
endpoints, and commission settings. It also reports a deterministic
reward-ledger root and reward-account count derived from the admitted validator
reward accounts.

Operators can generate the required shape and verify a filled validator set
with:

```bash
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --sample-validator-set > /tmp/nebula-validator-set.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-validator-set /tmp/nebula-validator-set.json --json
```

## Operator Handoff Gate

The operator handoff manifest is generated from a verified deployment
attestation and validator-set manifest. It gives each admitted operator a
deterministic entry covering operator ID, validator ID, node ID, region,
operator contact, bootstrap endpoint, P2P endpoint, reward account, consensus
and network keys, genesis power, signed admission root, and bootstrap
attestation root. Each entry has its own handoff root, and the manifest root
binds the launch-bundle root, validator-set root, validator-deployment-binding
root, and all entries. This gives external validators a compact file to compare
against their node configuration before the genesis package is accepted.

Operators can build and verify the handoff manifest with:

```bash
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --build-operator-handoff --deployment-attestation /tmp/nebula-attestation.json --validator-set /tmp/nebula-validator-set.json > /tmp/nebula-operator-handoff.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-operator-handoff /tmp/nebula-operator-handoff.json --deployment-attestation /tmp/nebula-attestation.json --validator-set /tmp/nebula-validator-set.json --json
```

## Operator Acceptance Gate

The operator acceptance manifest is generated from a verified handoff manifest,
deployment attestation, and validator-set manifest. It records one fresh
acceptance entry per handoff entry, binds the accepted handoff root, operator
public key, validator ID, node ID, and launch-bundle root, and verifies the
operator acceptance signature root. This lets external validators explicitly
acknowledge their assigned node and reward identity before launch materials are
treated as accepted.

Operators can build and verify acceptance with:

```bash
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --build-operator-acceptance --operator-handoff /tmp/nebula-operator-handoff.json --deployment-attestation /tmp/nebula-attestation.json --validator-set /tmp/nebula-validator-set.json > /tmp/nebula-operator-acceptance.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-operator-acceptance /tmp/nebula-operator-acceptance.json --operator-handoff /tmp/nebula-operator-handoff.json --deployment-attestation /tmp/nebula-attestation.json --validator-set /tmp/nebula-validator-set.json --json
```

## Genesis Manifest Gate

The final local launch artifact is a genesis manifest. It can only be built from
a deployment attestation and validator-set manifest that already pass their
verifiers. The manifest binds the deployment evidence root, validator-set root,
validator-set epoch `0`, fee-policy root, validator-admission root, initial
bootstrap-roster root, operator-roster root, reward-ledger root, validator,
operator, and region counts, total genesis power, fixed activation height `1`,
public-surface root, operator-approval root, observer-confirmation root,
rollback-readiness root, deployment-validity root, operational-evidence root,
deployment-quorum root, validator-deployment-binding root, and fee token
identities. The verifier keeps
deployment, public-surface, operator-approval, observer-confirmation,
rollback-readiness, deployment-validity, deployment-quorum,
bootstrap-roster,
operational-evidence, validator-set, operator-roster, reward-ledger,
validator-deployment-binding, fee-policy, and validator-admission roots in
separate domains. The final launch-package check requires the genesis timestamp
to be fresh and to fall inside the deployment attestation validity window.

Operators can build and verify the launch manifest with:

```bash
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --build-genesis-manifest --deployment-attestation /tmp/nebula-attestation.json --validator-set /tmp/nebula-validator-set.json > /tmp/nebula-genesis.json
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --verify-genesis-manifest /tmp/nebula-genesis.json --json
```

## Launch Package Gate

The final package check verifies the deployment attestation, public status
manifest, public probe, validator-set manifest, operator handoff, operator
acceptance, and genesis manifest together.
It rejects a package when the public surface roots do not match the deployment
attestation, or when the genesis manifest does not bind the exact deployment
evidence root, validator-set root, validator-set epoch, validator count, total
operator count, region count, public-surface root, bootstrap-roster root,
operator-approval root, observer-confirmation root, rollback-readiness root,
deployment-validity root, operator-roster root, reward-ledger root,
deployment-quorum root, validator-deployment-binding root,
operational-evidence root, genesis power, and deployment validity window
produced by the other verified files. It also rejects validator
consensus/network keys that reuse deployment witness keys, validator-set
manifests whose admitted validators do not map to the attested deployment
operators and bootstrap nodes, validator P2P hosts that do not match their
attested bootstrap endpoint host, and deployment operators or bootstrap nodes
that are not represented by an admitted validator. The launch-package report
also exposes the deployment observer quorum count and deployment region count
verified from the attestation, the public-surface root, the operator-approval
root, the observer-confirmation root, the bootstrap-roster root, the
rollback-readiness root, the operational-evidence root, the deployment-validity
root, the deployment-quorum root, the validator-deployment-binding root, the
operator-handoff root, the operator-roster root, the matched reward-account
count, the reward-ledger root, and the genesis fee token identities. The strict
package gate also verifies that operator acceptance entries bind the same
handoff root and accepted operator/validator counts.

After the strict package check passes, operators can build a launch-package
bundle manifest for external validators. The bundle records the exact
SHA3-256 digest for each of the seven launch artifacts, the verified deployment,
public status, public probe, validator-set, operator handoff, operator
acceptance, and genesis roots, plus a deterministic launch-package root and
bundle root. Validators verify the bundle against the artifact files before
joining the public testnet.

Validator activation manifests are built after bundle verification. Each
activation entry binds the admitted validator identity, P2P endpoint,
consensus/network keys, reward account, launch-package bundle root, and
operator acceptance root. The verifier requires one activated entry per
admitted validator and checks validator activation signature roots before
operators treat the set as ready to join.

Validator join receipts are built after activation. Each join entry binds the
activated validator identity, activation root, launch-package bundle root,
observed block height, peer count, and validator join signature root. The
verifier requires one join entry per activated validator, observed block height
at or after the genesis activation height, and enough peers for the activated
validator set.

Operator join confirmations are built after validator join receipts. Each
confirmation entry binds the operator identity, validator identity, validator
join root, validator activation root, launch-package bundle root, operator
acceptance root, and operator confirmation signature root. The verifier requires
one operator confirmation per joined validator before the joined validator set
is treated as operator-confirmed.

Public observer confirmations are built after operator join confirmations. Each
observer entry binds the public endpoint URL, public status root, public probe
root, operator join confirmation root, observer region, and observer signature
root. The verifier requires one confirmation per deployment observer and the
same minimum observer and region coverage as the deployment attestation.

The public testnet launch-candidate certificate is built after public observer
confirmation. It binds the launch-package bundle, validator activation,
validator join, operator join confirmation, public observer confirmation,
public status, public probe, validator set, genesis, endpoint URL, and validator,
operator, observer, and region counts into one final candidate root.

Operators can verify the full package with:

```bash
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

## License

Nebula-specific code and documentation in this repository are distributed under
the license terms in `LICENSE`.
