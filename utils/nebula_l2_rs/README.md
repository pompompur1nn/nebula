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
  local soft finality, anchor coverage, and Monero-final settlement without
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
