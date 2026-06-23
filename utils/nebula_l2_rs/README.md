# Nebula L2 Rust Core

This crate is the Rust migration target for the Nebula L2 prototype. The
Python devnet in `../nebula_l2` remains the executable reference model; this
crate starts by matching the reference transcript hashing, post-quantum policy
metadata, signed performance benchmark/calibration artifacts, and the
resource-level fee/execution profile model. It now also carries the first
private DeFi ledger slice: native asset records, shielded notes, issuer-signed
minting, private burns, AMM pool transitions, LP minting, constant-product
swaps, same-signer batch swaps, multi-hop route swaps, dark-pool atomic swaps,
stable swaps, explicit pool roots, oracle price roots, private collateralized
lending markets, position commitments, borrow/repay/liquidation records,
lending roots, sealed-swap order commitments, solver bids, sealed AMM batch
swaps, solver-signed settlement receipts, and the first deterministic
smart-contract execution slice. It also includes native-asset contract escrow
deposits and withdrawals with private note transitions, plus owner-signed,
timelocked contract upgrade proposals with upgrade event commitments. It also
includes the first Rust block commitment layer: L2 headers, deterministic DA
shards, PQ validator votes, privacy-proof aggregates, block-committed sealed
swap settlement receipt roots, and signed validity certificates. The settlement
slice now models Monero anchor commitments, epoch checkpoints, bridge signer
sets, hashed deposit observations, withdrawal queues, release delays, signed
reserve reports, withdrawal challenge evidence, and bridge roots. A dedicated
Monero monitor state records privacy-preserving RPC, ZMQ, block, transaction,
anchor, withdrawal, reserve, and reorg observations behind deterministic roots.
The mempool slice now models encrypted admission receipts,
sequencer preconfirmations, omission evidence, forced inclusion receipts, and
relay-path commitments without publishing raw relay paths. The status slice
composes mempool, DA, validity, privacy aggregate, and anchor records into
wallet-facing pending, omitted, included, soft-final, anchored, and Monero-final
responses. The paymaster slice now adds policy-limited sponsored contract
calls, private sponsor deposits, signed pause/resume/policy governance,
fee-market resources, relayer reward receipts, bonded relayer slashing hooks,
and paymaster state roots. The runtime slice adds a deterministic
Wasm-shaped boundary with module manifests, host-permission roots, contract
instances, private-argument execution receipts, host-call/storage-delta roots,
fee-market resources, module bytecode validation roots, and a block-committed
`wasm_runtime_root`. The wallet slice adds read-only wallet sync views that
compose owned notes, watched mempool receipts, contract/runtime receipts,
bridge deposit and withdrawal records, Monero anchor/withdrawal/reorg evidence,
and paymaster sponsorships into wallet-local history roots without publishing
raw view keys, relay paths, caller labels, Monero addresses, or private
payloads.
The account slice now adds an `AccountRegistry` with public account roots,
SLH-DSA-shaped recovery-signed key rotation, retired signer labels, active
wallet-session revocation on rotation, ML-KEM-shaped wallet-to-node session
transcripts, relay-path commitments, liveness/stale-network status, and
wallet-session roots without exposing raw session routes or account labels.
The sequencer slice now adds a local rollup loop that composes DeFi,
contracts, Wasm runtime, bridge, account, mempool, consensus, status, and wallet state:
it admits transaction records into encrypted mempool receipts, emits signed
preconfirmations, builds DA-backed L2 blocks from pending transactions,
stores validity and privacy aggregate evidence, exposes transaction/admission
status, and submits Monero-style epoch anchors. Typed DeFi submissions now
stage against an admission mirror so wallets can reserve pending notes and
nullifiers without mutating canonical DeFi state until block production. The
prover/watchtower slice now models staked prover nodes, proof jobs, signed
prover receipts, receipt aggregation, proof-market fee resources, DA sampling
receipts, and signed watchtower block audit/challenge reports. The network
slice adds signed node advertisements, root inventory gossip, admission
inventory gossip, encrypted gossip envelopes, peer scoring, and root-conflict
evidence without publishing raw transport routes.
The consensus slice adds stake-weighted proposer slots, validator stake
records, fast-finality votes, quorum certificates, downtime evidence, and
equivocation slashing evidence. The mempool now also emits encrypted batch
receipts, relay fairness tickets, and anti-censorship lane commitments, while
fee smoothing adds low-fee lane budgets for privacy transfers, Monero bridge
operations, and small DeFi calls.

The current crypto is still devnet-shaped. It models ML-DSA/SLH-DSA/ML-KEM
transcripts and roots so the protocol surface can be tested before audited
post-quantum libraries are wired in.

Current Rust scope:

- Domain-separated SHAKE256 transcript hashing and Merkle roots.
- Post-quantum crypto-policy roots and ML-DSA-shaped authorization records.
- Performance benchmark and calibration artifacts with Python golden vectors.
- Resource-level local fee lanes, block execution profiles, DA batching, and
  wallet-facing fee quote projections.
- Native asset, AMM, dark-pool, and private lending state transitions with
  private public records, note commitments, nullifiers, supply roots, pool
  roots, same-signer batch swaps, multi-hop route swaps, direct atomic swaps,
  sealed-swap order commitments, solver bids, sealed AMM batch swaps,
  solver-signed settlement receipts, auction/receipt roots, oracle roots,
  lending market/position roots, Python-compatible swap math, and
  oracle-backed liquidation checks.
- Counter-contract deployment and execution with PQ-signed calls, private
  argument commitments, fuel metering, same-signer batched execution, event
  roots, execution receipt roots, and fee-market resources.
- Native-asset contract escrow deposits and withdrawals with private note
  nullifiers, change notes, recipient commitments, vault allowance commitments,
  beneficiary withdrawals, balance-root events, collected network fees, and
  fee-market resources.
- DAO governor contract execution with hash-addressed proposals, committed
  proposers/voters, yes/no weight accounting, quorum checks, voting windows,
  execution outcomes, and event roots without raw voter labels.
- Owner-signed contract upgrade proposals with deterministic proposal IDs,
  timelocks, version/code-hash/fuel-limit commitments, executor commitments,
  upgrade events, and a `contract_upgrade_root` folded into the contract state
  root.
- Block production commitments for transaction roots, state roots, DA shard and
  attestation roots, sealed-swap settlement receipt roots, PQ validator vote
  roots, privacy-proof aggregates, and post-quantum-signed validity
  certificates.
- Monero settlement commitments for epoch checkpoints, fixed-format anchor
  submissions, PQ bridge signer-set rotation, deposit attestations, withdrawal
  queue/release signatures, amount buckets, reserve snapshots, signed reserve
  reports, withdrawal challenge evidence, and public bridge roots.
- Monero monitor commitments for endpoint registrations, RPC/ZMQ observations,
  block-tip observations, hashed transaction observations, anchor
  confirmations, withdrawal confirmations, reserve reports, reorg evidence,
  and a `monero_monitor_root` advertised through network inventory.
- Encrypted mempool commitments for ML-KEM-shaped committee keys and
  ciphertexts, relay-path policy metadata, sequencer preconfirmation receipts,
  omission/preconfirmation-miss evidence, forced inclusion receipts, encrypted
  batch receipts, relay fairness tickets, anti-censorship lane commitments,
  and block admission roots.
- Low-fee smoothing records with per-lane budgets, rebates, credits,
  settlement roots, and resource tags for privacy-transfer, Monero-bridge, and
  small-DeFi lanes.
- Wallet-facing status queries for mempool admissions, transaction inclusion,
  local quorum-certificate latency, anchor coverage, and Monero-final settlement without
  exposing raw relay paths or private payloads.
- Paymaster fee sponsorship with caller commitments, per-call/per-caller caps,
  private deposit proofs, signed governance actions, relayer reward accounting,
  bonded relayer slashing, and fee-market lanes for low-fee contract UX.
- Wasm runtime boundary records for deterministic module manifests, storage
  instances, metered calls, private argument commitments, host-call roots,
  storage-delta roots, execution receipt roots, and block `wasm_runtime_root`
  commitments.
- Wasm module validation for binary magic/version, canonical section order,
  supported Nebula host imports, requested-permission matching, memory limits,
  function/code body count matching, required `execute` export, and validation
  hashes committed into module manifests.
- Wallet sync records with owner commitments, domain-specific caller
  commitments, wallet scan tags, watched transaction hashes, watched
  nullifiers, amount buckets, and history roots for notes, mempool,
  contract/runtime, bridge, Monero observation evidence, and paymaster
  activity.
- Account registry records with ML-DSA-shaped spend keys, SLH-DSA-shaped
  recovery keys, ML-KEM-shaped network keys, recovery-signed rotations, retired
  signer labels, wallet-session revocation, node-network staleness checks, and
  `account_root`/`wallet_session_root` commitments.
- Role-bound crypto policy helpers for account, validator, recovery, and
  key-establishment surfaces, plus validator/prover/watchtower role block
  vote, proof receipt, DA attestation, and audit signing, with duplicate-signer
  rejection for bridge quorums.
- Policy-bound ML-KEM-shaped envelope records for encrypted mempool admissions
  and wallet sessions, preserving legacy ciphertext hashes while committing
  scheme, recipient key id/root, transcript hash, and crypto-policy root.
- Local sequencer orchestration with `LocalSequencer`, encrypted mempool
  admissions, sequencer preconfirmations, integrated state roots, DA-backed
  block production, validity/privacy evidence storage, epoch anchor
  submissions, stake-weighted proposer selection, fast-finality certificates,
  wallet scans, and status queries.
- Typed `LocalSequencer` DeFi submission wrappers for asset mint/burn, AMM
  liquidity, direct/batch/route/dark/sealed swaps, and lending
  borrow/repay/liquidation, each admitted through encrypted mempool receipts
  with fee resources, private state records, and staged canonical execution.
- Deterministic block packing policy and selection receipts for fee-density,
  lane-fair, resource-capped block proposals, with state-safe staged DeFi
  inclusion from an admission mirror into canonical block state.
- Capacity-aware preconfirmation target heights through
  `MempoolPreconfirmation::build_with_target_height`, so packed mempools can
  honestly promise later inclusion instead of every tx claiming the next block.
- Prover-network state with staked prover registration, block proof jobs,
  capacity-aware assignment receipts, signed completion receipts, recursive
  receipt aggregation roots, proof-market fee resources, and slashing-oriented
  prover disputes.
- Watchtower audit surfaces for sampled DA shards, proof-status roots,
  validity/privacy aggregate roots, bridge roots, and signed block challenge
  reports.
- Privacy-preserving network inventory with committed node routes, signed root
  announcements, mempool admission inventory, ML-KEM-shaped gossip envelopes,
  peer scoring, Monero monitor roots, consensus roots, mempool fairness roots,
  and root-conflict evidence for fast wallet/watchtower routing.

Run from this directory:

```powershell
cargo test
```

Functional bridge testnet runner:

```powershell
cargo run --manifest-path testnet_runner\Cargo.toml -- --blocks 4 --self-test --listen-ms 150 --json
```

Hardened mainnet-readiness dry run with the single-process local
quorum-certificate latency target set to under 200ms:

```powershell
cargo run --manifest-path testnet_runner\Cargo.toml -- --blocks 8 --target-finality-ms 200 --mainnet-readiness --adversarial-self-test --self-test --listen-ms 150 --json
```

The same dry run can write an operator checklist and redacted evidence template:

```powershell
cargo run --manifest-path testnet_runner\Cargo.toml -- --blocks 8 --target-finality-ms 200 --mainnet-readiness --adversarial-self-test --self-test --listen-ms 150 --write-readiness-template .\nebula-readiness-template.json --json
```

For a controlled public-alpha bootstrap, write the redacted deployment profile,
public status manifest, typed deployment runbook, combined launch handoff bundle,
schema v5 deployment evidence worksheet, and standalone capture todo:

```powershell
cargo run --manifest-path testnet_runner\Cargo.toml -- --blocks 8 --target-finality-ms 200 --mainnet-readiness --adversarial-self-test --write-public-bootstrap-profile .\nebula-public-bootstrap.json --write-public-status-manifest .\nebula-public-status.json --write-public-deployment-runbook .\nebula-public-deployment-runbook.json --write-public-launch-artifact-manifest .\nebula-public-launch-artifacts.json --write-public-launch-bundle .\nebula-public-launch-bundle.json --write-public-capture-todo .\nebula-public-capture-todo.json --verify-public-capture-todo .\nebula-public-capture-todo.json --write-public-deployment-evidence-template .\nebula-public-deployment-template.json --json
```

The same public-alpha handoff can be exported as one rooted package directory:

```powershell
cargo run --manifest-path testnet_runner\Cargo.toml -- --blocks 8 --target-finality-ms 200 --mainnet-readiness --adversarial-self-test --write-public-launch-package .\nebula-public-launch-package --json
```

Deployment CI can verify that package in the same release-candidate invocation
before any public endpoint evidence is filled:

```powershell
cargo run --manifest-path testnet_runner\Cargo.toml -- --blocks 8 --target-finality-ms 200 --mainnet-readiness --adversarial-self-test --write-public-launch-package .\nebula-public-launch-package --verify-public-launch-package .\nebula-public-launch-package --json
```

To produce a one-command local certification directory with the verified
package, operator launch report, and exact remaining blocker/remediation state:

```powershell
cargo run --manifest-path testnet_runner\Cargo.toml -- --blocks 8 --target-finality-ms 200 --mainnet-readiness --adversarial-self-test --write-public-testnet-certification .\nebula-public-testnet-certification --verify-public-testnet-certification .\nebula-public-testnet-certification --json
```

The runner uses the Monero `stagenet` bridge profile by default, produces local
L2 blocks, exercises deposit observation and withdrawal release accounting,
publishes reserve coverage roots, prepares epoch checkpoint/anchor, DA,
validity, privacy aggregate, bridge, validator, and finality-certificate roots,
and briefly binds loopback-only RPC/P2P status surfaces for self-test probes.
Those probe surfaces serve a redacted `nebula-public-status-manifest` rather
than the full operator summary. The RPC self-test parses the public status JSON
and checks the expected chain and no-mainnet-custody fields; the P2P self-test
checks the deterministic handshake root for the same status payload. `--json`
still prints the complete local operator summary and should be treated as
private release-candidate output.
`run_profile` records the local configuration provenance for the release
candidate: runner version, block count, network profile, loopback endpoint
checks, finality target, signer/validator/watchtower quorums, deposit and
withdrawal sizes, release delay/rate cap, anchor capacity, and operations drill
limits. Its report root is bound into the run checkpoint as local provenance,
not as live Monero, audit, or release-authority evidence.
`wasm_runtime_local` records the deterministic runtime coverage required by the
roadmap while the production Wasm engine remains external to this runner:
produced blocks commit `wasm_runtime_root`, and the report binds module
validation, fuel and memory bounds, host-permission matching, private-argument
commitments, append-only event roots, timelocked-upgrade rejection, and negative
validation roots for malformed Wasm and unsupported host imports.
`finality_latency_profile` records the local quorum-certificate latency shape
for the run: p50/p95/p99/max samples, block-construction latency, slow-sample
count, target margin, and deterministic sample roots. The
`finality-latency-profile-local` check must pass before the dry run is healthy,
but distributed validator latency evidence remains a separate mainnet
readiness artifact.
`distributed_finality_local` adds a threaded loopback quorum harness for every
produced block. It records per-validator vote roots, threshold-arrival latency,
logical region count, quorum-certificate roots, p50/p95/p99/max latency, and
slow-sample counts under the 200ms target. This proves the release candidate's
local distributed-finality shape is checkpoint-bound, but it still does not
replace external multi-region validator benchmark evidence.
`public_bootstrap_profile` binds the public-alpha deployment envelope without
opening the runner itself to the network. It commits public RPC/P2P endpoint
roots, typed bootstrap node commitment records, bootstrap node/operator/region
set roots, minimum bootstrap node/operator/region coverage, RPC rate-limit
policy, P2P peer cap, faucet daily and per-account caps, reset-window policy,
monitoring roots, health-check root, status-page
commitment, incident contact commitment, and deployment runbook root. A separate
typed public deployment runbook export turns that committed root into an ordered
public-alpha operations handoff and publishes its own step-set root. The
profile passes only while the runner binds remain loopback-only, Monero mainnet
stays rejected, ops/reserve/privacy/DA/wallet reports pass, the bootstrap
topology has minimum node, operator, and region coverage, and the public
policies remain within bounded launch limits. Public endpoint URLs belong in deployment
tooling, not in this local runner output.
Each admitted bootstrap transaction now receives a public
`MempoolAdmissionReceipt` and `MempoolPreconfirmationReceipt`; produced blocks
commit a `mempool_admission_root`, and the summary exposes a
`mempool_accountability` report proving all admitted encrypted transactions were
included before expiry with no missed preconfirmations. The summary also exposes
`bridge_release_safety`, which gates reserve coverage, bridge signer quorum,
withdrawal release delay, per-height release cap, emergency-pause state, and
challenge-hold state before the dry run can be treated as a healthy testnet.
`reserve_monitoring` adds the local proof-of-reserve monitoring surface: reserve
address hashes, attestation roots, liability snapshots, independent reporter
commitments, bounded monitoring cadence, coverage ratio,
completed-withdrawal exclusion, and an underreserve alert drill without
publishing raw reserve addresses.
For every produced block, `da_proof_watchtower_coverage` records deterministic
DA shard roots, validator availability attestation roots, validity certificate
roots, privacy aggregate roots, watchtower audit roots, and no-conflict
challenge roots. This is still a local deterministic coverage surface, not
production erasure coding, but readiness now fails if any produced block is
missing those DA/proof/watchtower commitments.
`wallet_recovery_audit` binds the local wallet-facing recovery path: admission
and preconfirmation commitments, included block status roots, DA/proof roots,
anchor roots, and bridge history counters. It proves the testnet status surface
can recover and audit the local wallet history from public commitments without
including raw view keys, relay paths, Monero addresses, or secret material.
`privacy_surface` audits the runner's own public surfaces for raw identifier
leaks: admissions, preconfirmations, stable block roots, bridge public roots,
and local report roots must expose root-shaped identifiers, amount buckets,
delayed withdrawal metadata, and no raw Monero addresses, raw txids, wallet
keys, seeds, or exact relay paths.
`operations_readiness_local` binds deterministic local operations drill receipts
for incident handoff, rollback replay/restore, withdrawal queue drain,
pause/resume quorum behavior, and reserve reconciliation. The report is bound
into the run checkpoint, but it remains local drill evidence rather than a
replacement for signed operator transcripts.
`--mainnet-readiness` is an evidence report, not a custody mode: the runner
rejects `mainnet` network selection and keeps `mainnet_value_ready=false`
permanently. Complete live Monero RPC/wallet evidence, adversarial
fault-injection evidence, audited proof-system evidence, external review roots,
and signed release approval can make the dry-run evidence shape complete, but
custody authorization remains outside this runner.

`--adversarial-self-test` runs deterministic local negative scenarios for weak
validator quorum, bridge guard failures, DA root tamper detection, and solver
settlement conflicts. It is useful testnet evidence, but it is not a substitute
for external adversarial testing or audit evidence.

`--write-readiness-template path\to\template.json` requires
`--mainnet-readiness` and writes a `kind:
nebula-mainnet-readiness-template` wrapper with `template_only: true`,
`usable_as_readiness_evidence: false`, the current manifest id, run checkpoint
root, mainnet-readiness check root, missing blocker ids, required artifact
families, the local run-profile, Wasm-runtime, finality-latency, and loopback
distributed-finality roots, deterministic local binding roots such as the
operations run-binding root, a public-bootstrap profile template, a redacted
readiness-evidence skeleton, and a redacted release approval skeleton. The
generated file is a collection worksheet; it is intentionally not accepted by
`--readiness-evidence`.

`--write-public-bootstrap-profile path\to\bootstrap.json` also requires
`--mainnet-readiness` and writes a `kind:
nebula-public-testnet-bootstrap-profile` wrapper with `template_only: true`.
It is the handoff artifact for public-alpha deployment automation: fill public
RPC/P2P URLs and per-node status-page endpoints outside the runner while
preserving typed bootnode commitments, node/operator/region roots, the
operator-registry template, and derivation rules. The registry template makes
operator independence, exact committed-operator coverage, and ML-DSA-65
signature-verification transcripts explicit before public deployment capture.
It is not a mainnet custody approval and does not make the runner accept
non-loopback binds.

`--write-public-status-manifest path\to\status.json` also requires
`--mainnet-readiness` and writes the same redacted
`nebula-public-status-manifest` served by the loopback RPC/P2P probe surfaces.
The manifest includes chain/version, latest block, no-mainnet-custody
acceptance, finality metrics, public-bootstrap policy roots, and root-only
commitments. It omits the full bridge ledger, run profile, block roots, probe
bind addresses, release approval, release authority registry, and internal
mainnet-readiness object. It also contains no generic `readiness` or
`public_launch_readiness` object; that operator-only launch report appears only
in the full local `--json` summary.

`--write-public-deployment-runbook path\to\runbook.json` also requires
`--mainnet-readiness` and writes a `kind:
nebula-public-deployment-runbook` handoff for public-alpha launch operators. It
is `template_only`, root-only, redacted, and not usable as public deployment
evidence or mainnet custody approval. The artifact binds the public status
manifest root, bootstrap profile roots, the committed deployment runbook root,
incident/status/monitoring/health/faucet/reset/rate-limit/bootstrap roots,
local operations runbook and incident-handoff roots, reserve/privacy report
roots, a no-mainnet-custody boundary root, and an ordered twelve-step runbook
for publishing the redacted status, keeping the full operator summary private,
provisioning public RPC/P2P, publishing status/health/metrics, deploying faucet
caps and reset communications, handing off incidents, rolling out bootstrap
nodes, verifying operator registry records, capturing deployment evidence,
binding rollback/reset communications, and confirming no mainnet custody.

`--write-public-launch-artifact-manifest path\to\artifacts.json` also requires
`--mainnet-readiness` and writes a rooted
`nebula-public-launch-artifact-manifest` over the pre-capture handoff set:
public status manifest, public bootstrap profile template, typed deployment
runbook, and public launch bundle. It records each artifact's export flag,
root field, root, order, required-before-capture flag, publishability flag,
non-evidence/non-custody flags, record root, and a collection `artifact_set_root`
without embedding operator-private evidence. The manifest guard recomputes the
artifact record, set, and manifest roots before export/package verification. The
capture plan and deployment evidence worksheet bind `public_launch_artifact_manifest_root` and
`public_launch_artifact_set_root`, so deployment CI can freeze the exact files
used before public probes, TLS pin capture, and observer attestations begin.

`--write-public-launch-bundle path\to\bundle.json` also requires
`--mainnet-readiness` and writes a `kind:
nebula-public-testnet-launch-bundle` handoff for deployment automation. It
combines the public status manifest, bootstrap profile template, proxy policy,
typed bootstrap-node commitment manifest, bootstrap operator registry manifest,
faucet policy, reset policy, monitoring policy, the typed public deployment
runbook root and step-set root, preflight gates, and operator action list. The
registry manifest requires exactly one independently verified
ML-DSA-65-signed registry record per committed operator before deployment
evidence can pass. The bundle is
`template_only`, keeps public runner listeners disabled, requires deployment
proxies to publish only the public status manifest, is not public deployment
evidence, is not a mainnet custody approval, and is root-recomputed by the
bundle guard before export/package verification.

`--write-public-launch-readiness-report path\to\launch-report.json` also
requires `--mainnet-readiness` and writes a local operator-only
`nebula-public-launch-readiness-report`. It archives the public launch gate
level, blocker ids, remediation commands, public status/bundle/capture-plan
roots, package file-set root, deployment evidence root if present, and its own
artifact root. The report is not a public deployment attestation and has both
`usable_as_public_deployment_evidence` and
`usable_as_mainnet_custody_approval` set to false.

`--write-public-launch-package path\to\package-dir` also requires
`--mainnet-readiness` and writes the full redacted public-alpha handoff set into
one directory: public status manifest, bootstrap profile template, typed
deployment runbook, launch artifact manifest, launch bundle, schema v5
local launch-readiness report, deployment evidence template, deployment capture
plan, and a `nebula-public-launch-package` manifest. The package manifest
records each filename, root field, artifact root, record root,
required-before-capture flag, operator-fill flag, and
non-evidence/non-custody flags under an `artifact_set_root`, plus a
`package_file_set_root` over the exact ordered top-level file list. It also
binds the package-level launch status, blocker/remediation counts, and
readiness report/artifact roots so deployment automation can detect stale,
swapped, cross-run, extra, or metadata-tampered files before filling public
probe evidence.
`--verify-public-launch-package path\to\package-dir` reruns those checks against
the current release-candidate summary, so CI should combine it with the export
step for the same runner invocation. It recomputes every artifact and package
root, verifies package-only/public-alpha boundaries and per-artifact
capture/operator-fill flags, enforces the exact top-level package file set and
package-level readiness summary, and fails if the directory contains stale,
tampered, swapped, cross-run, or extra handoff files.
The package also includes `nebula-public-capture-todo.json`, a rooted
machine-readable work order for the exact endpoint, TLS, probe, observer,
operator-registry, runbook, preflight, freshness, package, and
no-mainnet-custody fields deployment CI must capture. The todo artifact is
operator-fill-required, not public deployment evidence, and not custody
approval.

`--write-public-capture-todo path\to\todo.json` also requires
`--mainnet-readiness` and writes that same rooted work order as a standalone
JSON artifact for deployment CI that wants the remaining external-capture
contract without unpacking the full launch package. Its root guard recomputes
`public_capture_todo_root` before writing.
`--verify-public-capture-todo path\to\todo.json` also requires
`--mainnet-readiness`, recomputes the expected todo for the current
release-candidate summary, and fails on stale, tampered, or cross-run work
orders before public evidence capture starts.

`--write-public-testnet-certification path\to\cert-dir` also requires
`--mainnet-readiness` and writes a one-command public-testnet certification
directory. It exports and verifies `nebula-public-launch-package`, writes the
operator-only launch readiness report, and writes
`nebula-public-testnet-certification.json` with `local_testnet_ready`,
`public_launch_ready`, package roots, launch report roots, blocking gaps,
remediations, whether external capture is still required, and the exact capture,
verify, assemble, and launch-gate commands. The certification artifact is
operator-local, not public deployment evidence and not mainnet custody approval;
it truthfully remains `public-launch-blocked` until a filled schema v5
deployment attestation passes the gate.
`--verify-public-testnet-certification path\to\cert-dir` also requires
`--mainnet-readiness`, verifies the nested launch package, recomputes the
launch readiness report and certification root against the current
release-candidate summary, enforces the exact top-level directory shape, and
fails on stale, tampered, cross-run, extra-file, or swapped package/report/cert
roots before public evidence capture starts.

`--write-public-deployment-evidence-template path\to\deployment-template.json`
also requires `--mainnet-readiness` and writes the schema v5 worksheet that a
deployment system fills before using `--public-deployment-evidence`. The
template embeds the canonical redacted public status manifest, launch bundle
root, launch artifact manifest roots, the package file-set root, typed public
deployment runbook roots, the public deployment runbook receipt template, typed bootstrap node commitments, expected health/status-page/metrics/deployed-finality/
incident-contact/faucet/reset body shapes, typed proxy/firewall/rate-limit policy claims,
private-summary denial probe shape, typed `bootstrap_node_probes` reachability
records, typed `public_surface_probes` records for the status manifest, aggregate
P2P handshake, health, status-page, metrics, deployed-finality,
incident-contact, faucet, reset-runbook, and private-summary denial surfaces, typed
`bootstrap_operator_registry` records, typed `probe_observers`,
freshness window, and root derivation rules for policy claims, status, P2P, health, ops-surface,
deployed finality, private-summary denial, the typed public surface probe-set
root, the aggregate public probe-set root, bootstrap node probe-set root,
bootstrap operator registry/signature roots,
observer registry/signature roots, provenance, and final attestation roots. It
is intentionally `template_only: true`, contains placeholders, and is rejected
by the verifier until deployment tooling replaces every placeholder and
recomputes roots.

`--write-public-deployment-capture-plan path\to\capture-plan.json` also
requires `--mainnet-readiness` and writes a
`kind: nebula-public-deployment-capture-plan` work order for deployment CI. It
does not contain captured evidence and is not loadable as deployment evidence;
instead it binds the launch bundle, public status manifest, bootstrap profile,
typed public deployment runbook, launch artifact manifest, artifact-set, and
package file-set roots plus the evidence-template root while listing the exact
required capture fields, public endpoint fields, public surfaces, probe-root
fields, freshness window, bootstrap node slots, operator commitments, TLS pin
roles, the required typed public surface probe roles, observer quorum, a rooted
ordered deployment
preflight checklist, and `deployment_run_id` propagation rule that the assembler
will enforce. The plan publishes both `capture_contract_root` and
`capture_plan_root`; a later filled
deployment attestation must carry those roots, proving it followed the exact
rooted work order for this run. The capture-plan guard recomputes the preflight
checklist, capture contract, and plan roots before export/package verification.
It also includes a `package_handoff_capture` section that names
`nebula-public-launch-package.json` as the source of
`public_launch_package_manifest_root` and
`nebula-public-launch-readiness-report.json` as the source of
`public_launch_readiness_artifact_root`; those values must be copied into the
deployment capture from the pre-capture package, but the plan does not embed
the actual roots so the package manifest root stays non-circular.
This turns the remaining public-launch blocker into a deterministic capture
checklist without letting the local runner invent external reachability, TLS,
or observer-signature evidence.

The capture plan also includes `deployment_preflight`, a rooted ordered
checklist with twelve required phases: freeze launch roots, publish the redacted
status manifest, provision public endpoints, capture TLS pins, deploy bootstrap
nodes, verify bootstrap operators, capture typed public-surface probes, capture
bootstrap-node probes, capture observer attestations, verify private-summary
denial, assemble the public deployment attestation, and confirm no mainnet
custody. Its `checklist_root` is copied into the capture contract so deployment
CI can fail fast when a capture skipped a phase or was assembled against the
wrong launch/package/status/template roots. The capture contract also requires a
completed `deployment_preflight_receipt` covering the same twelve phases in
order. The assembler derives `deployment_preflight_phase_set_root`,
`deployment_preflight_receipt_root`, and `deployment_preflight_phase_count`
from that receipt and rejects missing, incomplete, out-of-order, stale, or
root-mismatched phase receipts.

`--audit-public-deployment-capture path\to\capture.json
--write-public-deployment-capture-audit path\to\capture-audit.json` also
requires `--mainnet-readiness` and writes a non-passing
`nebula-public-deployment-capture-audit` report. The audit lists missing
required capture fields, missing and invalid public endpoint fields, invalid
timestamp types, freshness-window bounds, current capture-time validity,
deployment-run-id validity, malformed preflight receipt fields/phases,
malformed runbook receipt fields/steps, expected capture-plan, capture-contract,
and preflight roots, mismatched frozen launch/status roots, TLS endpoint pin
counts and missing/extra/duplicate TLS endpoint pin roles,
indexed malformed TLS endpoint pin records,
public-surface probe counts and missing/extra/duplicate probe roles,
indexed malformed public-surface probe records, bootstrap
node/probe counts, missing/extra/duplicate bootstrap-node probe slots,
indexed malformed bootstrap-node probe records, bootstrap operator/registry counts,
missing/extra/duplicate operator-registry commitments, indexed malformed
bootstrap-operator registry records, observer count and
quorum reachability, placeholder presence, observer region coverage, malformed
observer region indexes, duplicate observer ids or keys, unsigned/unverified
observer signature indexes, invalid observer signature-verification transcript
indexes, sensitive key markers, public-forbidden key names, size/parseability
checks, current capture-plan/contract/preflight root matches, expected
capture-plan, capture-contract, and preflight roots, the expected package
file-set root, package file-set root matches, and
`structural_failed_checks`/`failed_checks` arrays with counts for CI routing,
plus an `assembler_ready` boolean. It is diagnostic only:
`usable_as_public_deployment_evidence` is false, so it helps deployment CI
repair incomplete captures without clearing the public launch gate. The audit
separates cheap `structural_ready` checks from `strict_verifier_passed`; when a
top-level-complete capture still fails nested policy/probe/receipt validation,
`failed_checks` contains `strict_public_deployment_verifier_passed` and
`strict_verifier_error` records the first assembler/verifier failure.

`--verify-public-deployment-capture path\to\capture.json` also requires
`--mainnet-readiness` and dry-runs the same assembler/verifier path without
leaving a final `nebula-public-deployment` artifact on disk. It derives the
schema v5 attestation into a temporary file, loads it through the normal public
deployment verifier, and feeds it into the in-memory public-launch report, so
deployment CI can combine it with `--fail-on-public-launch-gaps` before
publishing or archiving the final attestation.

`--assemble-public-deployment-evidence path\to\capture.json
--write-public-deployment-evidence path\to\deployment.json` also requires
`--mainnet-readiness` and turns captured deployment transcripts into a
loadable schema v5 attestation. The capture JSON supplies the public endpoints,
the `capture_plan_root`, `capture_contract_root`, and
`deployment_preflight_checklist_root` exported by
`--write-public-deployment-capture-plan`, a completed
`deployment_preflight_receipt` with one rooted completion record per required
preflight phase, a completed `public_deployment_runbook_receipt` with one
rooted completion record per ordered public deployment runbook step,
typed `tls_endpoint_pins` records for every HTTPS public surface, typed
`bootstrap_nodes` records with unique public P2P/status endpoints for every
committed node slot, typed `bootstrap_operator_registry` records with unique
entity, control-plane, infrastructure-account, and contact commitments for every
committed operator, typed `bootstrap_node_probes` records proving every
advertised bootstrap node's P2P handshake and status-page reachability, typed
proxy/firewall/rate-limit claims, captured
status/P2P/health/status-page/metrics/deployed-finality/
incident-contact/faucet/reset/private-summary probe bodies, typed `public_surface_probes`
records binding each required public surface to its endpoint, transcript root,
probe root, `deployment_run_id`, and observation time, a `probe_observers` array with
unique observer ids, observer key roots, regions, observation times, ML-DSA-65
signature roots, typed `signature_verification` transcripts with verifier/tool
roots and verification times, and a freshness window. TLS pin records,
bootstrap operator registry records, observer records, and observer/operator
signature verification transcripts must all bind the same `deployment_run_id`
so deployment CI cannot stitch together independently valid fragments from
different captures. The runner binds the current run's public status manifest,
launch bundle, package file-set root, bootstrap profile, node set, and policy
roots, derives TLS endpoint-pin set roots and the aggregate SPKI root from
`tls_endpoint_pins`, derives bootstrap node/operator/region roots plus public
endpoint-set roots and the bootstrap operator count from `bootstrap_nodes`,
derives `bootstrap_node_probe_set_root` from one reachability record per
committed bootstrap node,
derives `public_surface_probe_set_root` from the typed status, aggregate P2P,
health, status-page, metrics, deployed-finality, incident-contact, faucet, reset-runbook, and
private-summary-denial probe records,
derives bootstrap operator registry, independence, and signature roots from
`bootstrap_operator_registry`, derives the canonical observer attestation,
signature-payload, and signature-verification roots, then rejects observers
that do not carry externally verified signatures over those payloads.
It also derives the observer set root, attestor registry root, region count,
observer count, PQ signature collection root, and canonical `public_probe_set_root`
from the required public probe transcript roots, including
`public_surface_probe_set_root` and `bootstrap_node_probe_set_root`, then computes every policy/probe/provenance/
evidence root and immediately validates the assembled output with the same
`--public-deployment-evidence` verifier.
The verifier and public deployment report also compare the embedded
`capture_plan_root`, `capture_contract_root`, and
`deployment_preflight_checklist_root` against the current generated capture plan,
require the embedded `public_launch_package_file_set_root` to match the current
rooted package file set, require the embedded
`public_launch_package_manifest_root` and
`public_launch_readiness_artifact_root` to match the pre-capture launch package
handoff, and require the embedded preflight receipt root,
phase-set root, and phase count to match the completed receipt body. Schema v5 also requires the embedded
public deployment runbook root, step-set root, runbook receipt root,
step-receipt-set root, and step receipt count to match the completed runbook
receipt body and the current generated runbook. A self-consistent attestation
assembled from the wrong work order, from stale launch artifacts, or from a
capture that skipped a preflight phase or runbook step cannot clear
`--fail-on-public-launch-gaps`.
This gives deployment CI a deterministic offline path from observer captures to
a gate-checkable public launch artifact without allowing the runner to invent
observer signatures.

`--public-deployment-evidence path\to\deployment.json` also requires
`--mainnet-readiness` and verifies a filled `kind:
nebula-public-deployment-attestation` artifact for a specific launch bundle. It
requires `schema_version: 5` and `template_only: false`, rejects placeholders
and sensitive field names, requires HTTPS publicly routable
RPC/status/health/metrics/incident-contact/faucet/reset endpoints, and requires a publicly
routable P2P endpoint. It must bind the capture plan root, capture contract
root, and deployment preflight checklist root generated for the same run.
It also must bind the current `public_launch_package_file_set_root`,
the pre-capture `public_launch_package_manifest_root`, the pre-capture
`public_launch_readiness_artifact_root`,
`deployment_preflight_receipt`,
`deployment_preflight_receipt_root`, `deployment_preflight_phase_set_root`, and
`deployment_preflight_phase_count`, proving every required preflight phase was
completed in order before the public deployment evidence was assembled.
When either package handoff root is stale, the deployment report exposes the
expected package file-set, package manifest, and readiness artifact roots
alongside the failed subchecks so the capture can be repaired from the
pre-capture package files.
It must also bind `public_deployment_runbook_receipt`,
`public_deployment_runbook_receipt_root`,
`public_deployment_runbook_step_receipt_set_root`, and
`public_deployment_runbook_step_receipt_count`, proving every ordered public
deployment runbook step was completed against the frozen runbook step roots.
Literal private, loopback, link-local, documentation,
multicast, CGNAT, and local-only addresses are rejected; deployment DNS names
and public IP or multiaddr endpoints remain valid. The artifact must include the actual captured
`public_status_manifest`, the HTTPS status probe code/root, the observed P2P
handshake derived from the canonical status JSON, and a minimal health JSON
that binds the status-manifest and bootstrap-profile roots while asserting
no-mainnet-custody and no public runner listener. It must also include captured
status-page, metrics, incident-contact, faucet, and reset-runbook JSON bodies whose roots bind
the public bootstrap policy commitments, faucet caps, reset window, and
deployment runbook root. A separate deployed-finality probe, rooted from the
metrics endpoint, must cover the same manifest, latest height, validator count,
threshold, region count, sample count, and <=200ms p95/max finality target as
the public manifest. Its body includes `testnet_manifest_id`,
`latest_block_height`, `sample_count`, `validator_count`,
`validator_threshold`, `region_count`, `target_finality_micros`,
`p95_quorum_certificate_micros`, `max_quorum_certificate_micros`,
`all_samples_under_target`, `network_profile_root`, `clock_sync_root`, and
`sample_set_root`; the verifier requires a real quorum, `p95 <= max <= target`,
and target <=200ms. Finally, the artifact binds typed TLS endpoint-pin records
for public RPC, status-page, health, metrics, incident-contact, faucet, and reset-runbook HTTPS
surfaces; each record must assert TLS1.3, hostname verification, SPKI pin match,
non-expired certificate, certificate-chain/issuer roots, and observation inside
the freshness window. It also binds typed bootstrap node records whose derived node/operator/region and public
endpoint-set roots and operator count must match the public bootstrap profile
with no duplicate public P2P or status-page endpoints and at least the minimum
committed operator coverage, plus typed `bootstrap_node_probes` covering every
committed node slot. Each bootstrap node probe must bind the deployment run id,
launch bundle root, status-manifest root, node slot, public P2P endpoint,
canonical P2P handshake, verified handshake flag, HTTPS status-page endpoint,
200 status-page response root, and observation time; its aggregate
`bootstrap_node_probe_set_root` is included in observer attestations and the
canonical `public_probe_set_root`. Typed `public_surface_probes` must also cover
the status manifest, aggregate P2P handshake, health, status-page, metrics,
deployed-finality, incident-contact, faucet, reset-runbook, and private-summary denial surfaces
exactly once. Each record must bind the public endpoint, transport, transcript
kind/status, transcript root, probe root, launch bundle root, status-manifest
root, `deployment_run_id`, `observed_at_unix_ms`, and public-routability claim;
the derived `public_surface_probe_set_root` is included in observer attestations,
provenance, the final attestation, and the canonical `public_probe_set_root`.
The operator registry must cover every committed
operator exactly once, require unique entity/control-plane/infrastructure/contact
commitments, bind an independence proof root, assert verified independence, and
bind ML-DSA-65 signature verification transcripts. The artifact also binds
proxy/firewall/rate-limit roots plus their
typed claim bodies, typed multi-observer probe provenance, derived attestor
registry and PQ signature roots, `public_probe_set_root` plus `public_probe_count`,
`observed_at_unix_ms`, `expires_at_unix_ms`, and a bounded freshness window.
The proxy claims must keep public runner listeners disabled, publish only the
approved public surfaces, require TLS/redaction, and require a private-summary
probe. The firewall claims must keep loopback runner ports private and block
private-summary, admin, debug, and non-public routes. The rate-limit claims
must bind the public bootstrap RPC/P2P/faucet caps and include observed 429
rejections, retry-after data, route coverage, peer-limit observation, and
faucet-cap enforcement. A rooted `private_summary_probe` must target
`/operator-summary`, prove 403/404 denial, bind a response-body root and small
content-length cap, and assert no redirect or private-summary content. The
verifier requires unique observer ids and keys, multiple regions, observer
observation times inside the freshness window, observer attestations bound to
every captured probe root, `signature_scheme: ML-DSA-65`, canonical
`signature_payload_root` values, `signature_verified: true`, typed
`signature_verification` transcripts, and matching
`signature_verification_root` values. The verifier recomputes the policy,
probe, observer, provenance, and attestation roots, then
requires the embedded status manifest and launch bundle roots to match the
current run's generated public artifacts. Live Internet reachability and raw PQ
signature verification remain deployment-system probes outside this local
runner, but duplicate, unsigned, or unverified observer captures are no longer
assembled.

`--fail-on-public-launch-gaps` also requires `--mainnet-readiness` and turns the
public-alpha package into a CI gate. It exits nonzero until the local public
bootstrap profile, redacted status manifest, launch bundle, bounded public
policies, reserve/ops/privacy/DA/wallet/mempool/bridge-safety surfaces, and a
filled schema v5 public deployment attestation all pass. This is a public
testnet launch gate, not a mainnet value gate. The full local `--json` summary
includes `public_launch_readiness` with check roots, blocker ids, machine-actionable
`remediations`, a `remediation_root`, and a `public-launch-ready` or
`public-launch-blocked` level. Each remediation names the stable expected
artifact id/path, expected artifact, remediation kind, relevant command,
expected evidence root, granular failed subchecks, root-specific `repair_roots`
for failed capture/preflight/package/runbook receipt/status/bootstrap topology and policy bindings, privacy
classification, and whether external deployment capture is required.
Deployment-attestation remediations
also list failed subchecks, including capture-plan, launch-bundle, package
file-set, bootstrap profile/report/rate-limit policy roots, status-manifest
root/payload, preflight, runbook, bootstrap topology/count/registry/probe
bindings, aggregate probe repair roots/counts, per-endpoint publicness, TLS pin repair roots/counts,
proxy/firewall/rate-limit policy repair roots, per-surface probe roots/counts,
placeholder hygiene, local bootstrap/finality dependencies, wallet recovery,
mempool accountability, bridge release safety, privacy-denial, and custody
bindings; the redacted public status manifest does not include that local
operator report.

`--fail-on-readiness-gaps` also requires `--mainnet-readiness` and turns the
dry-run report into a CI/release gate: the command exits nonzero until every
non-custody artifact gate passes. The permanent `mainnet-release-approval`
sentinel remains out-of-band and still does not make this runner a mainnet
custody authority.

Structured readiness evidence can be supplied with `--readiness-evidence
path\to\evidence.json`. The bundle is local-only JSON, must not contain raw
Monero addresses, txids, view keys, seeds, private keys, or other secrets, and
must complete every section emitted by `--write-readiness-template`. The
abbreviated excerpt below shows representative fields and array entries only;
it is not loadable as written until all required arrays, run-binding fields,
computed roots, and provenance attestations are filled.

```json
{
  "schema_version": 1,
  "chain_id": "nebula-monero-l2-testnet",
  "custody_mode": "no-mainnet-custody",
  "live_monero_rpc": {
    "passed": true,
    "network": "stagenet",
    "monero_tip_height": 2100000,
    "monero_finality_depth": 20,
    "rpc_endpoint_commitment": "<64-hex-root>",
    "wallet_rpc_endpoint_commitment": "<64-hex-root>",
    "signer_set_root": "<64-hex-root>",
    "reorg_observation_root": "<64-hex-root>",
    "testnet_manifest_id": "<runner-manifest-id>",
    "run_profile_report_root": "<runner-run-profile-report-root>",
    "local_bridge_signer_set_root": "<runner-bridge-signer-set-root>",
    "local_reserve_report_root": "<runner-reserve-report-root>",
    "latest_block_height": 4,
    "synthetic_observed_height": 1920004,
    "run_binding_root": "<64-hex-root>",
    "observations": [
      {
        "kind": "deposit_observation",
        "observed_height": 2099981,
        "confirmations": 20,
        "signer_threshold": 2,
        "signer_count": 3,
        "command_root": "<64-hex-root>",
        "result_root": "<64-hex-root>",
        "artifact_root": "<64-hex-root>",
        "privacy_root": "<64-hex-root>",
        "signer_quorum_root": "<64-hex-root>",
        "evidence_root": "<64-hex-root>"
      }
    ],
    "evidence_root": "<64-hex-root>"
  },
  "distributed_finality": {
    "passed": true,
    "validator_count": 32,
    "validator_threshold": 22,
    "region_count": 4,
    "sample_count": 256,
    "target_finality_micros": 200000,
    "max_quorum_certificate_micros": 180000,
    "p95_quorum_certificate_micros": 150000,
    "benchmark_root": "<64-hex-root>",
    "network_profile_root": "<64-hex-root>",
    "clock_sync_root": "<64-hex-root>",
    "sample_set_root": "<64-hex-root>",
    "testnet_manifest_id": "<runner-manifest-id>",
    "run_profile_report_root": "<runner-run-profile-report-root>",
    "local_validator_count": 4,
    "local_validator_threshold": 3,
    "local_region_count": 4,
    "local_target_finality_micros": 200000,
    "latest_block_height": 4,
    "run_binding_root": "<64-hex-root>",
    "evidence_root": "<64-hex-root>"
  },
  "anchor_capacity": {
    "passed": true,
    "max_transactions_per_anchor": 10000,
    "observed_epoch_count": 16,
    "fixed_format_payload": true,
    "anchor_payload_bytes": 128,
    "capacity_policy_root": "<64-hex-root>",
    "fixed_format_payload_root": "<64-hex-root>",
    "capacity_root": "<64-hex-root>",
    "benchmark_root": "<64-hex-root>",
    "evidence_root": "<64-hex-root>"
  },
  "adversarial_tests": {
    "passed": true,
    "adversarial_performance_root": "<64-hex-root>",
    "adversarial_calibration_root": "<64-hex-root>",
    "max_block_count": 128,
    "max_validator_count": 32,
    "covered_finality_target_micros": 200000,
    "coverage_root": "<64-hex-root>",
    "scenarios": [
      {
        "kind": "validator_fault_injection",
        "passed": true,
        "injected_at_height": 1,
        "detected_at_height": 1,
        "fault_root": "<64-hex-root>",
        "command_root": "<64-hex-root>",
        "expected_rejection_root": "<64-hex-root>",
        "observed_rejection_root": "<64-hex-root>",
        "invariant_root": "<64-hex-root>",
        "performance_sample_root": "<64-hex-root>",
        "evidence_root": "<64-hex-root>"
      }
    ],
    "evidence_root": "<64-hex-root>"
  },
  "privacy_policy": {
    "passed": true,
    "policy_root": "<64-hex-root>",
    "threat_model_root": "<64-hex-root>",
    "testnet_manifest_id": "<runner-manifest-id>",
    "local_privacy_surface_report_root": "<runner-privacy-surface-report-root>",
    "wallet_recovery_audit_report_root": "<runner-wallet-recovery-audit-report-root>",
    "latest_block_height": 4,
    "run_binding_root": "<64-hex-root>",
    "components": [
      {
        "kind": "anchor_privacy_profile",
        "passed": true,
        "reviewed_at_height": 1,
        "reviewer_commitment": "<64-hex-root>",
        "scope_root": "<64-hex-root>",
        "implementation_evidence_root": "<64-hex-root>",
        "negative_test_root": "<64-hex-root>",
        "mitigation_root": "<64-hex-root>",
        "constant_size_payload": true,
        "bounded_cadence_jitter": true,
        "unique_amounts_avoided": true,
        "raw_identifiers_excluded": true,
        "independent_submitter_count": 3,
        "evidence_root": "<64-hex-root>"
      }
    ],
    "evidence_root": "<64-hex-root>"
  },
  "operations_readiness": {
    "passed": true,
    "operations_policy_root": "<64-hex-root>",
    "runbook_set_root": "<64-hex-root>",
    "testnet_manifest_id": "<runner-manifest-id>",
    "local_operations_readiness_report_root": "<runner-operations-readiness-local-report-root>",
    "reserve_monitoring_report_root": "<runner-reserve-monitoring-report-root>",
    "latest_block_height": 4,
    "run_binding_root": "<64-hex-root>",
    "components": [
      {
        "kind": "incident_response_runbook",
        "passed": true,
        "executed_at_height": 1,
        "operator_commitment": "<64-hex-root>",
        "runbook_root": "<64-hex-root>",
        "transcript_root": "<64-hex-root>",
        "artifact_root": "<64-hex-root>",
        "signoff_root": "<64-hex-root>",
        "incident_handoff_tested": true,
        "escalation_quorum_verified": true,
        "public_status_template_ready": true,
        "postmortem_owner_assigned": true,
        "evidence_root": "<64-hex-root>"
      }
    ],
    "evidence_root": "<64-hex-root>"
  },
  "fee_efficiency": {
    "passed": true,
    "sample_count": 256,
    "normal_load_tps": 32,
    "l2_p95_fee_piconero": 1000000,
    "monero_l1_reference_fee_piconero": 20000000,
    "fee_ratio_bps": 500,
    "fee_policy_root": "<64-hex-root>",
    "normal_load_profile_root": "<64-hex-root>",
    "monero_l1_fee_reference_root": "<64-hex-root>",
    "fee_curve_root": "<64-hex-root>",
    "evidence_root": "<64-hex-root>"
  },
  "crypto_policy": {
    "passed": true,
    "crypto_policy_root": "<runner-pq-crypto-policy-root>",
    "dependency_tree_root": "<64-hex-root>",
    "production_feature_set_root": "<64-hex-root>",
    "denylist_scan_root": "<runner-crypto-dependency-inventory-root>",
    "allowed_exception_root": "<64-hex-root>",
    "testnet_manifest_id": "<runner-manifest-id>",
    "local_crypto_inventory_report_root": "<runner-crypto-inventory-report-root>",
    "local_dependency_inventory_root": "<runner-crypto-dependency-inventory-root>",
    "latest_block_height": 4,
    "run_binding_root": "<64-hex-root>",
    "components": [
      {
        "kind": "no_pairing_kzg_bls_profile",
        "passed": true,
        "reviewed_at_height": 1,
        "reviewer_commitment": "<64-hex-root>",
        "scope_root": "<64-hex-root>",
        "implementation_evidence_root": "<64-hex-root>",
        "test_vector_root": "<64-hex-root>",
        "signoff_root": "<64-hex-root>",
        "no_bls_signatures": true,
        "no_kzg_commitments": true,
        "no_pairing_snarks": true,
        "no_pairing_dependencies": true,
        "hash_based_da_commitments": true,
        "non_hybrid_ec_only_auth_rejected": true,
        "allowed_exception_count": 0,
        "evidence_root": "<64-hex-root>"
      }
    ],
    "evidence_root": "<64-hex-root>"
  },
  "external_review": {
    "passed": true,
    "review_policy_root": "<64-hex-root>",
    "production_readiness_state_root": "<64-hex-root>",
    "testnet_manifest_id": "<runner-manifest-id>",
    "run_profile_report_root": "<runner-run-profile-report-root>",
    "wasm_runtime_report_root": "<runner-wasm-runtime-report-root>",
    "crypto_inventory_report_root": "<runner-crypto-inventory-report-root>",
    "privacy_surface_report_root": "<runner-privacy-surface-report-root>",
    "operations_readiness_local_report_root": "<runner-operations-readiness-local-report-root>",
    "latest_block_height": 4,
    "run_binding_root": "<64-hex-root>",
    "reviews": [
      {
        "kind": "monero_bridge_security_audit",
        "passed": true,
        "opened_at_height": 1,
        "accepted_at_height": 11,
        "reviewer_commitment": "<64-hex-root>",
        "scope_root": "<64-hex-root>",
        "report_root": "<64-hex-root>",
        "finding_root": "<64-hex-root>",
        "remediation_root": "<64-hex-root>",
        "signoff_root": "<64-hex-root>",
        "evidence_root": "<64-hex-root>"
      }
    ],
    "evidence_root": "<64-hex-root>"
  },
  "proof_system_audit": {
    "passed": true,
    "audit_policy_root": "<64-hex-root>",
    "proof_system_root": "<64-hex-root>",
    "max_block_count": 128,
    "max_transaction_count": 1024,
    "capacity_root": "<64-hex-root>",
    "proof_family": "transparent-pq-recursive",
    "commitment_scheme": "hash-based-merkle",
    "setup_trust_model": "transparent-no-trusted-setup",
    "transparent_or_pq_proof_system": true,
    "pairing_assumption_used": false,
    "assumption_root": "<64-hex-root>",
    "components": [
      {
        "kind": "transfer_privacy_proof",
        "passed": true,
        "audit_height": 1,
        "auditor_commitment": "<64-hex-root>",
        "circuit_manifest_root": "<64-hex-root>",
        "public_input_schema_root": "<64-hex-root>",
        "test_vector_root": "<64-hex-root>",
        "negative_test_root": "<64-hex-root>",
        "parameter_root": "<64-hex-root>",
        "report_root": "<64-hex-root>",
        "evidence_root": "<64-hex-root>"
      }
    ],
    "evidence_root": "<64-hex-root>"
  },
  "evidence_provenance": {
    "passed": true,
    "threshold": 10,
    "producer_registry_root": "<64-hex-root>",
    "attestations": [
      {
        "family": "live_monero_rpc",
        "accepted": true,
        "section_root": "<live-monero-rpc-evidence-root>",
        "signer_commitment": "<64-hex-root>",
        "pq_public_key_root": "<64-hex-root>",
        "producer_id": "<64-hex-root>",
        "attestation_id": "<64-hex-root>",
        "pq_signature_root": "<64-hex-root>",
        "attestation_root": "<64-hex-root>"
      },
      {
        "family": "<one-attestation-for-each-remaining-required-family>",
        "accepted": true,
        "section_root": "<matching-section-evidence-root>",
        "signer_commitment": "<64-hex-root>",
        "pq_public_key_root": "<64-hex-root>",
        "producer_id": "<64-hex-root>",
        "attestation_id": "<64-hex-root>",
        "pq_signature_root": "<64-hex-root>",
        "attestation_root": "<64-hex-root>"
      }
    ],
    "evidence_root": "<64-hex-root>"
  }
}
```

The runner recomputes the live Monero transcript roots for
`deposit_address_derivation`, `deposit_observation`,
`withdrawal_construction`, `withdrawal_signing`, `reserve_report`,
`confirmation_finality_reorg`, and `privacy_constraints`, then computes a
bundle root for the readiness report. It also recomputes adversarial transcript
roots for `validator_fault_injection`, `bridge_fault_injection`,
`da_fault_injection`, and `solver_fault_injection`, binding those scenarios to
adversarial performance, calibration, and campaign coverage roots. Placeholder
roots are useful for testing the verifier only; they are not evidence that
mainnet value is safe.
The emitted `*_transcript_shape_verified` fields mean the local JSON structure
and commitment roots are internally consistent; they do not authenticate RPC
operators, external auditors, or release authorities.
The `evidence-provenance-authentication` check requires the readiness bundle to
include registry-bound producer attestations for each external evidence family,
binding the family id, section `evidence_root`, signer commitment, PQ public-key
root, producer id, attestation id, and registry root. This is still a
deterministic commitment verifier; live PQ signature verification and custody
authority remain outside the runner.
The `readiness-evidence-freshness` check also requires the live Monero evidence
tip to cover the current testnet run's synthetic observed Monero height and the
evidence finality depth to be at least the runner's configured finality depth.
The evidence network must also match the runner's non-mainnet Monero profile
(`stagenet` or `regtest`), and the live transcript must bind the generated
manifest id, run-profile root, local bridge signer-set root, local reserve
report root, latest block height, and synthetic observed height.
`release_approval.target_network = "mainnet"` remains the separate out-of-band
deployment decision. That prevents a stale or cross-network but internally
consistent evidence bundle from clearing the dry-run gates.
The `distributed-finality-evidence` and `distributed-finality-for-run` checks
require an external distributed validator benchmark to cover the current run's
block count, validator count, threshold, region count, and local
quorum-certificate target. The benchmark's max quorum-certificate latency must
be at or below its target, and the target must be no more than 200,000
microseconds. Its run binding must also match the release-candidate manifest
id, local run-profile report root, local validator quorum, local loopback region
count, local target finality, and latest block height.
The external benchmark's region count must also cover the local loopback
distributed-finality shape exposed in the readiness template. The
`distributed-finality-local-loopback` check binds that local shape into the run
checkpoint, but it is not accepted as WAN or multi-operator evidence.
The `finality-latency-profile-local` check is the complementary local latency
profile: it binds every local quorum-certificate sample, p50/p95/p99/max
latency, block-construction latency, slow-sample count, and target margin into
the run checkpoint. It does not replace the distributed benchmark.
The `anchor-capacity-local`, `anchor-capacity-evidence`, and
`anchor-capacity-for-run` checks require fixed-format epoch anchors that can
commit at least 10,000 L2 transactions. The local report binds the produced
anchor and epoch checkpoint roots, while the external benchmark must bind a
capacity policy root, fixed-format payload root, capacity root, benchmark root,
observed epoch count, and payload byte count. A shaped but undersized benchmark
cannot clear the current run's configured anchor capacity.
The `adversarial-coverage-for-run` check requires adversarial campaign evidence
to declare tested block capacity, validator capacity, and a covered local
quorum-certificate target at least as strict as the current run. Its coverage
root binds those limits to the adversarial performance and calibration roots, so
a component-complete but undersized adversarial campaign cannot clear the run.
The `privacy-policy-evidence` check requires shape-checked profiles for
`anchor_privacy_profile`, `deposit_privacy_profile`,
`withdrawal_privacy_profile`, and `wallet_recovery_privacy_profile`. The runner
verifies concrete claims such as constant-size anchors, bounded anchor jitter,
one-time deposit addresses, batched deposit attestations, delayed/bucketed
withdrawals, recipient redaction, no transparent wallet balance mode, and wallet
history recovery from view keys plus DA payloads. Those profile roots are
commitments to external operator/auditor evidence, not local proof that the
policies are deployed. The `privacy-policy-for-run` check additionally requires
that evidence to bind this run's manifest id, latest block height, local
`privacy_surface.report_root`, `wallet_recovery_audit.report_root`, and the
template's `privacy_policy.run_binding_root`, so stale privacy-policy evidence
cannot clear a different release candidate.
The `privacy-surface-local` check is the complementary local surface audit: it
requires root-shaped public identifiers, amount buckets, delayed withdrawal
metadata, redacted relay paths, and no raw Monero or wallet-secret fields in the
runner's own public outputs.
The `wallet-recovery-audit-local` check is the complementary local proof: it
requires every admitted wallet-visible transaction to be included, every block
to expose status and DA/proof audit roots, every block to have an anchor audit
root, and bridge deposit/withdrawal history to be committed without raw wallet
or Monero identifiers.
The `operations-readiness-evidence` check requires shape-checked operations
transcripts for `incident_response_runbook`, `rollback_drill`,
`withdrawal_queue_drain_drill`, `bridge_pause_resume_drill`, and
`reserve_reconciliation_monitoring`. The runner verifies concrete claims such
as incident handoff, escalation quorum, rollback replay and state restore,
withdrawal rate-limit and queue-drain drills, pause/resume quorum behavior,
preserved challenge holds, independent reserve reporters, completed-withdrawal
exclusion, and underreserve alert testing. The separate
`operations-readiness-for-run` check requires that evidence to bind the current
manifest id, latest height, local operations drill report root, and local
reserve-monitoring report root.
The `reserve-monitoring-local` check is the complementary local reserve proof:
it requires reserve coverage above liabilities plus pending releases, at least
two independent reporter commitments, a hash-bound reserve address, a bounded
monitoring cadence, completed withdrawals excluded from live liabilities, and
an underreserve alert drill root.
The `operations-readiness-local-drills` check is the complementary local drill
coverage surface: it requires incident handoff, escalation quorum, at least two
rollback checkpoints with replay/restore roots inside the configured recovery
window, a simulated withdrawal queue drain to zero under the release cap,
paused mint/release rejection roots with quorum resume, preserved challenge
holds, and a reserve reconciliation receipt that references the local reserve
monitoring report root.
The `fee-efficiency-local-estimate`, `fee-efficiency-evidence`, and
`fee-efficiency-for-run` checks require normal-load fee evidence showing the L2
p95 fee below one-tenth of the Monero L1 reference fee. The external benchmark
must cover the current run's public transaction count and normal-load TPS, bind
the fee policy, L1 reference, normal-load profile, and fee curve roots, and
report a matching fee ratio in basis points.
The `pq-no-pairing-local-inventory` check scans the Rust manifests and
lockfiles for BLS, KZG, pairing, and pairing-SNARK dependency markers. The
`pq-crypto-policy-evidence` check separately requires shape-checked external
claims for `ml_dsa_65_authorization_profile`, `slh_dsa_recovery_profile`,
`ml_kem_768_session_profile`, `sha3_transcript_domain_profile`, and
`no_pairing_kzg_bls_profile`, binding the runner's PQ policy root, production
feature-set root, dependency tree root, denylist scan root, and exception root.
The `crypto-policy-for-run` check requires that evidence to bind the current
manifest id, latest height, local crypto-inventory report root, local dependency
inventory root, and PQ policy root, so a stale crypto review cannot clear a
changed dependency tree.
The `proof-audit-capacity-for-run` check requires proof-system audit evidence
to declare an audited block and public transaction capacity that covers the
current run. Its capacity root binds those limits to the audit policy and proof
system roots, so a component-complete but undersized proof audit cannot clear
the run. The proof-system audit also binds a proof assumption root requiring a
transparent/PQ recursive proof family, hash-based commitment scheme,
transparent no-trusted-setup model, and `pairing_assumption_used=false`.
The `external-review-for-run` check requires independent review evidence to
bind the current manifest id, latest height, and local run-profile, Wasm
runtime, crypto-inventory, privacy-surface, and operations-readiness report
roots. Timing-sample coverage remains enforced by the dedicated finality
benchmark gates, while this check prevents a component-complete external review
packet from clearing a different release candidate.

Privacy policy evidence must include transcript roots for
`anchor_privacy_profile`, `deposit_privacy_profile`,
`withdrawal_privacy_profile`, and `wallet_recovery_privacy_profile`.
The run-specific privacy binding must also match the generated template's
manifest id, latest block height, local `privacy_surface.report_root`,
`wallet_recovery_audit.report_root`, and `privacy_policy.run_binding_root`.
The `privacy-surface-local` check is the complementary local privacy surface
audit: it scans the runner's public admissions, preconfirmations, stable block
roots, bridge public roots, and local report roots for forbidden raw identifier
fields, verifies root-shaped public identifiers, requires amount buckets and
delayed withdrawal release metadata, and rejects transparent-balance or raw
relay-path surfaces. It does not replace signed privacy-policy review.
Operations readiness evidence must include transcript roots for
`incident_response_runbook`, `rollback_drill`,
`withdrawal_queue_drain_drill`, `bridge_pause_resume_drill`, and
`reserve_reconciliation_monitoring`.
Fee efficiency evidence must include normal-load profile, fee policy, Monero L1
reference fee, and fee-curve roots proving p95 L2 fees are below one-tenth of
the equivalent Monero L1 payment fee.
Anchor capacity evidence must include capacity policy, fixed-format payload,
capacity, and benchmark roots proving one fixed-format Monero anchor can commit
at least 10,000 L2 transactions.
Crypto policy evidence must include transcript roots for
`ml_dsa_65_authorization_profile`, `slh_dsa_recovery_profile`,
`ml_kem_768_session_profile`, `sha3_transcript_domain_profile`, and
`no_pairing_kzg_bls_profile`, plus the generated
`crypto_policy.run_binding_root` for this release-candidate run.
External review evidence must include transcript roots for
`post_quantum_crypto_review`, `monero_bridge_security_audit`,
`privacy_leakage_review`, `fast_finality_and_ordering_stress`, and
`recursive_proof_capacity_stress`, plus the generated
`external_review.run_binding_root` for this release-candidate run.
Proof-system audit evidence must include
`transfer_privacy_proof`, `private_fee_note_proof`, `batch_transfer_proof`,
`block_privacy_aggregate`, `validity_certificate_proof`, and
`proof_parameter_ceremony`.

A release go/no-go artifact can also be supplied with `--release-approval
path\to\approval.json`. The file is local-only JSON, must not contain secrets,
and must bind the exact testnet manifest id, readiness evidence bundle root,
local adversarial self-test root, run checkpoint root, and, when authority
verification is required, the release authority registry root:

```json
{
  "schema_version": 1,
  "chain_id": "nebula-monero-l2-testnet",
  "approval_kind": "nebula-mainnet-release-approval",
  "target_network": "mainnet",
  "custody_mode": "external-mainnet-process-required",
  "approved": true,
  "testnet_manifest_id": "<64-hex-root>",
  "testnet_run_checkpoint_root": "<64-hex-root>",
  "readiness_evidence_bundle_root": "<64-hex-root>",
  "local_adversarial_self_test_root": "<64-hex-root>",
  "release_authority_registry_root": "<64-hex-root>",
  "production_readiness_report": {
    "release_candidate": true,
    "open_blockers": 0,
    "release_score_bps": 9500,
    "critical_score_bps": 10000,
    "report_root": "<64-hex-root>",
    "signoff_root": "<64-hex-root>"
  },
  "signoff_quorum": {
    "threshold": 7,
    "signoffs": [
      {
        "role": "core_protocol",
        "accepted": true,
        "signer_commitment": "<64-hex-root>",
        "pq_signature_root": "<64-hex-root>",
        "signoff_id": "<64-hex-root>"
      }
    ]
  },
  "signed_at_height": 1,
  "expires_at_height": 10080,
  "approval_root": "<64-hex-root>"
}
```

`--release-authority-registry path\to\registry.json` supplies the local
authority set used by the `release-authority-registry` readiness check. The
registry must bind every required role to an active signer commitment and PQ
public-key root:

```json
{
  "schema_version": 1,
  "chain_id": "nebula-monero-l2-testnet",
  "registry_kind": "nebula-release-authority-registry",
  "custody_mode": "external-mainnet-process-required",
  "threshold": 7,
  "authorities": [
    {
      "role": "core_protocol",
      "active": true,
      "signer_commitment": "<64-hex-root>",
      "pq_public_key_root": "<64-hex-root>",
      "authority_id": "<64-hex-root>"
    }
  ],
  "registry_root": "<64-hex-root>"
}
```

With a registry supplied, approval signoffs must use signer commitments from
the active registry and PQ signature roots bound to the role, signer commitment,
PQ public-key root, authority id, signoff id, run checkpoint root, readiness
evidence bundle root, and local adversarial self-test root. A shape-valid
approval without a matching registry can pass `release-approval-artifact`, but
it will not pass `release-authority-registry`.

The approval verifier requires accepted signoffs for `core_protocol`,
`cryptography`, `bridge_security`, `privacy`, `defi_risk`, `operations`, and
`governance`, and it recomputes the approval root. The run checkpoint binds the
manifest id, testnet id, local run profile root, local Wasm-runtime report root,
local finality-latency profile root, local loopback distributed-finality report
root, latest block root, consensus certificate root, reserve report root,
watchtower hold root, release-rate-limit root, mempool accountability report
root, bridge release safety report root, reserve monitoring report root,
DA/proof watchtower coverage report root, crypto inventory root, fee-efficiency
report root, anchor-capacity report root, wallet recovery audit report root,
local operations readiness report root, privacy surface report root, readiness
evidence bundle root, and local adversarial self-test root. A valid
registry-backed approval can pass the
non-custody artifact checks, but this runner still keeps
`mainnet-release-approval` and `mainnet_value_ready=false` blocked; any custody
enablement must happen through an out-of-band mainnet deployment authority
outside this testnet runner.
