# Nebula Layer 2 Protocol Plan

This document defines a first architecture for a Monero-settled Nebula layer 2
focused on five priorities:

1. Quantum resistance.
2. Speed.
3. DeFi support, including tokens and smart contracts.
4. Low fees.
5. Privacy by default.

The design target is a private rollup-style execution layer that uses Monero for
economic settlement and timestamped checkpoints, while keeping high-throughput
execution, DeFi state, post-quantum authentication, and privacy-specific
protocol logic off the base chain.

## Design Constraints

Monero is excellent as private base money, but it is not a general-purpose smart
contract chain. A Nebula L2 therefore cannot start as a fully trustless rollup
bridge in the same sense as an Ethereum rollup that has L1 contracts verifying
deposits, exits, fraud proofs, or validity proofs.

The first practical version must separate these layers:

- L2 consensus and execution: fast, programmable, post-quantum aware.
- Monero anchoring: ordered commitments that timestamp L2 epochs.
- XMR bridge custody: threshold/federated at first, then progressively more
  trust-minimized as Monero protocol support and research allow.

This is not a weakness to hide. It is the central engineering constraint.

## External Standards And Assumptions

- Monero hides sender, receiver, and amount using stealth addresses, ring
  signatures, and RingCT. The L2 must not degrade that base-layer privacy by
  emitting uniquely identifiable anchor or bridge transactions.
- Monero blocks arrive roughly every two minutes and use dynamic block sizing.
  L2 speed therefore comes from L2 consensus, with Monero providing slower hard
  settlement.
- NIST has standardized ML-KEM, ML-DSA, and SLH-DSA for post-quantum
  cryptography. Nebula should use these names and parameter sets rather than
  pre-standard Kyber, Dilithium, or SPHINCS+ labels.
- For hashing and domain-separated transcripts, use SHA-3 derived functions
  such as cSHAKE, KMAC, TupleHash, and ParallelHash.
- For smart contracts, WebAssembly is a good execution substrate because it is
  safe, portable, compact, and designed for efficient execution. Nebula must
  still define a deterministic profile rather than expose raw Wasm behavior.

References:

- Monero privacy overview: https://www.getmonero.org/get-started/what-is-monero/
- Monero project overview: https://www.getmonero.org/resources/about/
- NIST FIPS 203 ML-KEM: https://csrc.nist.gov/pubs/fips/203/final
- NIST FIPS 204 ML-DSA: https://csrc.nist.gov/pubs/fips/204/final
- NIST FIPS 205 SLH-DSA: https://csrc.nist.gov/pubs/fips/205/final
- NIST SP 800-185 SHA-3 derived functions: https://csrc.nist.gov/pubs/sp/800/185/final
- W3C WebAssembly Core: https://www.w3.org/TR/wasm-core-2/

## System Overview

Nebula L2 has five major services:

- Sequencer network: accepts encrypted transactions, orders them, and produces
  fast L2 blocks.
- Executor network: deterministically executes blocks, updates private state,
  and verifies contract metering.
- Prover network: produces validity artifacts for state transitions and privacy
  rules.
- Data availability network: stores erasure-coded block data and serves it to
  validators, wallets, auditors, and challengers.
- Monero bridge/watchtower network: watches Monero deposits, submits anchor
  transactions, and processes withdrawals from threshold-controlled vaults.

The network can start with the same machines running multiple roles on devnet,
but the protocol treats them as separable from day one.

```text
User wallet
  -> encrypted L2 transaction
  -> sequencer committee
  -> deterministic execution and privacy proof verification
  -> L2 block and DA commitment
  -> Monero checkpoint anchor
```

## Devnet Scaffold

A small stdlib-only prototype lives at `utils/nebula_l2/devnet.py`. It is not
production cryptography, but it exercises the first protocol objects. The
`ML-DSA-65` signatures are mock signatures over typed transcripts; they are
strictly there to keep the devnet wire/state shape ready for a real audited
post-quantum implementation.

The production implementation track is Rust. The Python devnet remains the
executable specification for protocol behavior, while `utils/nebula_l2_rs`
ports consensus-critical primitives into a memory-safe, faster core. The Rust
core now covers the Python-compatible SHAKE256 transcript hashing, Merkle
encoding, post-quantum crypto-policy root, ML-DSA-shaped authorization records,
performance benchmark/calibration artifacts, resource-level fee markets, block
execution profiles, native asset records, shielded note commitments,
issuer-authorized minting, private burns, AMM pool transitions, deterministic
counter-contract execution, same-signer batch swaps, multi-hop route swaps,
dark-pool atomic swaps, oracle price roots, private collateralized lending
markets, private position commitments, borrow/repay/liquidation records,
native-asset contract escrow deposits/withdrawals, owner-signed timelocked
contract upgrade proposals, and the first L2 block commitment layer. That block
layer binds transaction roots, state roots, DA shard and attestation roots, PQ
validator vote roots, privacy-proof aggregates, and post-quantum-signed
validity certificates. Rust also now carries the first Monero settlement
commitment layer: epoch checkpoints, fixed-format anchor submissions, PQ bridge
signer sets, hashed deposit observations, withdrawal queues, release delays,
amount buckets, and bridge roots. The Rust mempool layer now covers
ML-KEM-shaped committee keys and ciphertext commitments, relay-path policy
metadata, sequencer preconfirmations, omission and preconfirmation-miss
evidence, forced inclusion receipts, and block admission roots. Rust status
queries now compose mempool, DA, validity, privacy aggregate, and anchor records
into wallet-facing pending, omitted, included, soft-final, anchored, and
Monero-final responses without exposing raw relay paths or private payloads.
Rust paymasters now cover policy-limited sponsored contract calls, private
sponsor deposits, signed governance actions, relayer reward receipts, bonded
relayer slashing hooks, and paymaster roots for low-fee private contract UX.
Rust also now exposes a deterministic Wasm-shaped runtime boundary: signed
module manifests, host-permission roots, storage instances, metered execution
receipts, private-argument proof roots, host-call/storage-delta roots,
fee-market resources, module validation roots, and block `wasm_runtime_root`
commitments. The Rust validator checks Wasm binary magic/version, canonical
section order, supported `nebula` host imports, requested-permission matching,
memory limits, function/code body count matching, and the required `execute`
export before a module can be signed into state. Rust wallet sync now composes
owned notes, watched mempool admissions/preconfirmations, contract and Wasm
execution receipts, bridge deposits/mints/withdrawals, and paymaster
sponsorships into wallet-local history roots using owner commitments, scan
tags, caller commitments, watched transaction hashes, and watched nullifiers
without publishing raw view keys, relay paths, caller labels, Monero addresses,
or private payloads. Rust account state now mirrors the devnet registry:
`AccountRegistry` commits public account records, SLH-DSA-shaped recovery
rotations, retired signer labels, ML-KEM-shaped wallet-session transcripts,
relay-path commitments, session revocation on rotation, stale node-network
status, `account_root`, and `wallet_session_root`. Future Rust slices should
absorb vault/governor templates, live bridge verification, and a production
Wasm engine adapter before the Python harness is retired.

- Shielded-style note commitments.
- Nullifier based double-spend prevention.
- Versioned post-quantum crypto policy roots with CLI test vectors for
  account signatures, recovery signatures, ML-KEM-shaped mempool encryption,
  transcript hashing, and proof placeholders.
- ML-DSA-65-shaped devnet account authorization transcripts.
- Registered PQ account state with SLH-DSA-shaped recovery key rotation.
- ML-KEM-shaped wallet-to-node session receipts with account-root commitments
  and rotation-based revocation.
- Deterministic mock privacy proof bundles for note-spend transactions.
- Validator registration with ML-DSA-65-shaped consensus vote transcripts.
- Soft-finality metadata on produced L2 blocks.
- Block execution profiles for target latency, DA byte estimates, proof byte
  estimates, fuel, observed fee units, local fee-market roots, and batch
  discounts.
- Read-only devnet performance profiles for target throughput, projected
  latency, DA/proof/auth bandwidth, local fee pressure, and wallet fee curves.
- Persisted performance benchmark runs that sign measured public execution
  summaries, fee-curve roots, and local fee-pressure roots.
- Signed performance calibration records that compare benchmark estimates with
  measured prover, signer, DA, and contract-runtime costs.
- Wallet-facing fee quotes that project marginal DA cost, batch savings,
  fee pressure, local fee lanes, and fast-inclusion fees without mutating the
  mempool.
- Rust native asset, AMM, and private lending state transitions with issuer
  authorization, private burn records, note/nullifier commitments, asset roots,
  AMM pool roots, LP minting, constant-product swaps, stable-asset swap math,
  same-signer batch swaps, multi-hop route swaps, dark-pool atomic swaps, fee
  lanes for richer swap classes, sealed-swap order commitments, solver bids,
  sealed AMM batch swaps, solver-signed settlement receipts, auction/receipt
  roots, oracle price roots, private position commitments,
  borrow/repay/liquidation records, lending roots, and oracle-backed
  liquidation checks.
- Rust deterministic counter-contract execution with PQ-signed calls,
  private-argument commitments, same-signer batched execution, storage roots,
  contract events, execution receipt roots, fuel metering, and fee-market
  resources.
- Rust native-asset contract escrow deposits and withdrawals with private note
  nullifiers, change/output notes, recipient commitments, vault allowance
  commitments, beneficiary withdrawals, contract balance-root events, collected
  network fees, and fee-market lanes.
- Rust DAO governor contract execution with hash-addressed proposals, committed
  proposers/voters, quorum and voting-window checks, execution outcomes, and
  event roots without raw voter labels.
- Rust owner-signed contract upgrade governance with deterministic proposal ids,
  timelocks, code-hash/version/fuel commitments, executor commitments, upgrade
  events, and a committed `contract_upgrade_root`.
- Rust L2 block commitments with transaction roots, state roots, deterministic
  DA shard records, sealed-swap settlement receipt roots, PQ validator vote
  roots, block privacy-proof aggregates, and post-quantum-signed validity
  certificates.
- Rust Monero settlement commitments with epoch checkpoints, anchor submission
  transcripts, PQ bridge signer-set rotation, deposit attestation roots,
  withdrawal queue/release signature roots, amount buckets, privacy release
  delays, and combined bridge roots.
- Rust encrypted mempool commitments with ML-KEM-shaped committee ids,
  ciphertext hashes, public relay-path metadata, sequencer preconfirmation
  receipts, omission/preconfirmation-miss evidence, forced inclusion receipts,
  and block admission roots.
- Rust wallet-facing status queries for admission state, transaction inclusion,
  DA-backed block membership, validity/proof roots, anchor coverage, and
  Monero-final settlement.
- Rust paymaster state for sponsored contract fees, caller-commitment policy
  caps, private sponsor deposits, governance actions, relayer rewards, bonded
  slashing hooks, and fee-market lanes.
- Rust Wasm runtime boundary records for signed module manifests, committed
  host permissions, storage instances, metered private calls, host-call roots,
  storage-delta roots, execution receipts, fee lanes, and block
  `wasm_runtime_root` commitments.
- Rust Wasm module validation for binary versioning, supported host imports,
  memory caps, required exports, function/code section consistency, and
  validation hashes committed into module ids.
- Rust wallet sync views for private-note discovery, watched mempool receipts,
  contract/runtime execution history, bridge deposit and withdrawal progress,
  paymaster sponsorships, scan tags, nullifier tracking, and wallet-local
  history roots.
- Rust account registry state for PQ spend/recovery/network keys,
  recovery-signed rotations, retired signer labels, wallet-session revocation,
  stale node-network checks, and `account_root`/`wallet_session_root`
  commitments.
- Rust role-bound crypto policy helpers for account, validator, recovery, and
  key-establishment roles, validator/prover/watchtower-role block vote, proof
  receipt, DA attestation, and audit signing, and duplicate-signer rejection for
  bridge signer quorums.
- Rust policy-bound ML-KEM-shaped envelope records for encrypted mempool
  admissions and wallet sessions, preserving legacy ciphertext hashes while
  committing scheme, recipient key id/root, transcript hash, and crypto-policy
  root.
- Rust local sequencer orchestration with encrypted mempool admission,
  signed preconfirmation, integrated DeFi/contract/Wasm/bridge/account state
  roots, DA-backed block production, validity certificate and privacy aggregate
  storage, transaction/admission status, wallet scans, and Monero-style epoch
  anchor submission.
- Rust fee-density and lane-fair block packing policy for resource-capped local
  proposals, including selection receipts and state-safe inclusion of staged
  DeFi transitions from an admission mirror into canonical block state.
- Rust capacity-aware mempool preconfirmation target heights, allowing local
  sequencers to promise inclusion based on fee/resource packing rather than
  claiming every admission targets the next block.
- Rust prover-network state for staked prover registration, block proof jobs,
  assignment receipts, signed prover completion receipts, receipt aggregation,
  proof-market fee resources, and prover dispute/slashing evidence.
- Rust watchtower audit and challenge reports over sampled DA shards, proof
  status roots, validity certificates, privacy aggregates, bridge roots, and
  mempool admission roots.
- Rust network inventory state for signed node advertisements, committed relay
  routes, root inventory announcements, admission inventory announcements,
  encrypted gossip envelopes, peer scores, and root-conflict evidence.
- Deterministic data-availability shard records with validator attestations and
  CLI sampling.
- Post-quantum-signed devnet validity certificates for block state transitions.
- Block privacy-proof aggregates that commit every public proof bundle in a
  block into the validity certificate and epoch checkpoint.
- Encrypted mempool admission receipts with ML-KEM-shaped committee key ids,
  relay-path policy/hop metadata, route commitments, and sequencer
  authorization.
- Post-quantum oracle price feeds with multiple publisher attestations.
- Deterministic devnet contract deployment.
- Signed contract calls with fuel limits, private fee-note spends, and
  persistent storage roots.
- Public contract execution receipts that bind template/code hash, entrypoint,
  args commitment, block transaction index, fuel limit/used, storage roots
  before/after, event id, and event-chain root for validator and indexer replay.
- Native asset escrow balances for contracts with private-note deposits and
  owner-authorized private-note withdrawals.
- Vault contract allowances for committed beneficiaries.
- Contract event logs with caller commitments for DeFi indexing without raw
  wallet-label disclosure.
- Scoped signed private contract-event disclosures so a caller can open hidden
  event arguments to an auditor or indexer without changing the public event
  stream.
- Owner-signed, timelocked contract upgrade proposals that commit current and
  proposed code hashes, versions, fuel limits, and upgrade events.
- Governor contract template with hash-addressed proposals, committed voters,
  quorum checks, and PQ-signed vote transactions.
- Policy-limited contract paymasters with private sponsor deposits, caller
  commitment allow lists, per-call/per-caller caps, sponsor-signed
  pause/resume/close actions, replenishment targets, refill plans, refund note
  commitments, relayer-bound refill authorization receipts, refill failure
  receipts, relayer challenge windows, slashing hooks, bonded relayer stake
  settlement, relayer reputation counters, and explicit sponsored contract-call
  fees.
- Native asset creation.
- Asset supply roots for minted, burned, and circulating amounts.
- PQ issuer-signed native token mints with hidden recipient labels.
- Private native token burns with note-spend proofs and public supply accounting.
- Private transfer public records.
- Same-owner private batch transfers with one proof, one authorization, and one
  fee across multiple note inputs and recipient outputs.
- Constant-product AMM pool contracts.
- Stable-asset AMM pool curve for near-parity assets.
- Shielded LP-token minting.
- Private-note swap inputs and outputs.
- Same-signer private batch swaps with one AMM update and one network fee.
- Private multi-hop AMM route swaps that cross several pools with one note
  spend, one privacy proof, one authorization, and one network fee.
- Private dark-pool atomic swaps that match two shielded notes with two
  post-quantum authorizations, one proof, hidden raw trade amounts, and no AMM
  reserve update.
- Multi-user sealed AMM batch swaps with per-intent authorization, aggregate
  settlement, and hidden recipient labels.
- Solver-signed sealed-swap settlement receipts with route, clearing-price,
  aggregate surplus, and fill-commitment roots for private DeFi accountability.
- PQ-signed sealed-swap order commitments for large-order commit/reveal without
  publishing raw note ids, recipient labels, amounts, or opening secrets.
- PQ-signed solver bids for private sealed-swap batch auctions, binding an
  ordered commitment-root batch to a public quote and settlement outcome.
- Deterministic sealed-auction expiry so unrevealed commitments and stale
  solver bids stop locking private order flow or bloating the active auction
  book.
- Scoped signed view-key disclosure bundles for audits, merchants, and tax
  reporting without making wallet scans public by default.
- View-key wallet history scanning across confirmed blocks, pending
  transactions, current notes, spent events, fee totals, and unindexed devnet
  state notes.
- Private collateralized lending markets with public risk parameters,
  oracle-backed valuation, and shielded borrow/repay/liquidation note flows.
- Fee accounting.
- L2 block roots.
- Monero epoch anchor commitments.
- Explicit epoch checkpoints with block-hash roots, DA roots, bridge roots,
  mempool-admission roots, and soft-finality counts for anchor amortization.
- Signed Monero anchor submissions with confirmation/finality tracking.
- Watchtower-reported omission evidence for expired encrypted mempool
  admissions, with sequencer stake slashing and no decrypted payload or wallet
  labels exposed.
- Sequencer-signed forced-inclusion receipts that requeue omitted encrypted
  admissions from private recovery state after slashing evidence.
- Sequencer-signed encrypted mempool preconfirmations that promise a target
  L2 block height and can be missed/slashed without revealing payloads.
- Wallet-facing `mempool-status` lookup that classifies an admission as pending,
  included with its committed block/DA/settlement record, or omitted with
  slashing evidence.
- Wallet-facing `tx-status` receipts that classify a public transaction hash as
  pending or included and attach block, proof, DA, and settlement roots.
- Signed watchtower block audit receipts that bind DA samples, validity
  certificates, privacy-proof aggregates, bridge roots, and mempool roots.
- Signed watchtower block challenge reports for missing local proof artifacts
  or conflicting external roots, with proposer slashing for slashable local
  faults.
- Devnet one-time Monero deposit addresses.
- Threshold bridge-signer-attested wrapped-XMR minting with signer-set ids,
  quorum counts, and replay-verified attestation roots.
- Wrapped-XMR withdrawal burns with queued bridge records, hashed release txids,
  threshold signer roots, and Monero confirmation/finality tracking.
- Explicit post-quantum bridge signer sets with public-key roots, quorum
  thresholds, signed rotations, and active-set enforcement for releases.
- Watchtower bridge withdrawal challenge holds that extend the release window
  without exposing raw evidence or recipient addresses.
- Per-height bridge withdrawal release rate-limit accounting to slow large exit
  bursts.
- Public bridge reserve reports that compare hashed Monero reserve attestations
  against circulating wrapped XMR plus incomplete withdrawal liabilities.
- Threshold-signed bridge emergency pause/resume actions that bind the active
  PQ bridge signer set, block new bridge mints, withdrawals, and releases, and
  preserve observation, confirmation, and reserve reporting.

The devnet `proof_bundle` is a transcript-shaped placeholder, not a real
zero-knowledge proof. Public transaction records expose `proof_system`,
`public_input_hash`, and `proof_root`; persistent devnet state also keeps a
`private_witness_hash` so tests can reload pending blocks and recompute the
same proof roots. Block production rejects missing or tampered proof bundles for
private transfers, native token burns, AMM liquidity adds, AMM swaps, private
lending flows, and wrapped-XMR withdrawals.

Run:

```text
py -3.13 utils/nebula_l2/devnet.py --self-test
cd utils/nebula_l2_rs && cargo test
```

or use any Python 3.10+ interpreter for the executable spec.

Persistent devnet example:

```text
py -3.13 utils/nebula_l2/devnet.py account --label alice-view-key
py -3.13 utils/nebula_l2/devnet.py crypto-policy
py -3.13 utils/nebula_l2/devnet.py init --state l2_state.json
py -3.13 utils/nebula_l2/devnet.py account-register --state l2_state.json --label alice-view-key
py -3.13 utils/nebula_l2/devnet.py account-rotate --state l2_state.json --account-id <account_id> --new-label alice-v2 --recovery-label alice-view-key
py -3.13 utils/nebula_l2/devnet.py accounts --state l2_state.json
py -3.13 utils/nebula_l2/devnet.py session-open --state l2_state.json --account-id <account_id> --signer alice-view-key --relay-path dandelion-stem-fluff
py -3.13 utils/nebula_l2/devnet.py session-status --state l2_state.json --session-id <session_id>
py -3.13 utils/nebula_l2/devnet.py sessions --state l2_state.json
py -3.13 utils/nebula_l2/devnet.py validator-add --state l2_state.json --label validator-two --stake 2500
py -3.13 utils/nebula_l2/devnet.py validators --state l2_state.json
py -3.13 utils/nebula_l2/devnet.py asset --state l2_state.json --symbol DFEE --issuer-policy devnet-fee-issuer
py -3.13 utils/nebula_l2/devnet.py mint --state l2_state.json --asset-id <fee_asset_id> --owner alice-view-key --amount 10
py -3.13 utils/nebula_l2/devnet.py asset --state l2_state.json --symbol DGR --issuer-policy issuer:treasury-key --supply-policy fixed --max-supply 1000000
py -3.13 utils/nebula_l2/devnet.py token-mint --state l2_state.json --asset-id <dgr_asset_id> --to alice-view-key --amount 100000 --signer treasury-key
py -3.13 utils/nebula_l2/devnet.py token-burn --state l2_state.json --spent-note-id <dgr_note_id> --amount 1000
py -3.13 utils/nebula_l2/devnet.py contract-deploy --state l2_state.json --template counter --owner alice-view-key --fuel-limit 100000
py -3.13 utils/nebula_l2/devnet.py contract-deploy --state l2_state.json --template counter --owner alice-view-key --fuel-limit 100000 --private-storage
py -3.13 utils/nebula_l2/devnet.py contract-deploy --state l2_state.json --template vault --owner alice-view-key --fuel-limit 300
py -3.13 utils/nebula_l2/devnet.py contract-deploy --state l2_state.json --template governor --owner dao-owner-key --fuel-limit 300
py -3.13 utils/nebula_l2/devnet.py contract-call --state l2_state.json --contract-id <contract_id> --entrypoint increment --args-json "{\"amount\": 5}" --signer alice-view-key --fuel-limit 20 --fee-asset-id <fee_asset_id> --fee-note-id <fee_note_id> --max-fee 1
py -3.13 utils/nebula_l2/devnet.py contract-call --state l2_state.json --contract-id <contract_id> --entrypoint increment --args-json "{\"amount\": 5}" --private-args --signer alice-view-key --fuel-limit 20
py -3.13 utils/nebula_l2/devnet.py contract-call-batch --state l2_state.json --calls-json "[{\"contract_id\":\"<contract_id>\",\"entrypoint\":\"increment\",\"args\":{\"amount\":3},\"fuel_limit\":20,\"private_args\":true},{\"contract_id\":\"<contract_id>\",\"entrypoint\":\"increment\",\"args\":{\"amount\":4},\"fuel_limit\":20,\"private_args\":true}]" --signer bob-view-key --fee-asset-id <fee_asset_id> --fee-note-id <fee_note_id> --max-fee 1
py -3.13 utils/nebula_l2/devnet.py contract-disclose --state l2_state.json --contract-id <contract_id> --owner alice-view-key --audience defi-indexer --path count
py -3.13 utils/nebula_l2/devnet.py contract-event-disclose --state l2_state.json --event-id <event_id> --signer bob-view-key --audience defi-indexer
py -3.13 utils/nebula_l2/devnet.py contract-upgrade-propose --state l2_state.json --contract-id <contract_id> --version 2 --fuel-limit 150000 --proposer alice-view-key --timelock-blocks 2
py -3.13 utils/nebula_l2/devnet.py contract-upgrade-execute --state l2_state.json --proposal-id <proposal_id> --executor upgrade-keeper
py -3.13 utils/nebula_l2/devnet.py contract-upgrades --state l2_state.json --contract-id <contract_id>
py -3.13 utils/nebula_l2/devnet.py contract-call --state l2_state.json --contract-id <governor_contract_id> --entrypoint propose --args-json "{\"description_hash\":\"<description_hash>\",\"action_hash\":\"<action_hash>\",\"voting_period_blocks\":2,\"quorum\":2}" --signer alice-view-key --fuel-limit 100
py -3.13 utils/nebula_l2/devnet.py contract-call --state l2_state.json --contract-id <governor_contract_id> --entrypoint vote --args-json "{\"proposal_id\":\"<proposal_id>\",\"support\":true,\"weight\":1}" --signer bob-view-key --fuel-limit 80
py -3.13 utils/nebula_l2/devnet.py contract-call --state l2_state.json --contract-id <governor_contract_id> --entrypoint execute --args-json "{\"proposal_id\":\"<proposal_id>\"}" --signer keeper-key --fuel-limit 80
py -3.13 utils/nebula_l2/devnet.py contract-call --state l2_state.json --contract-id <vault_contract_id> --entrypoint grant --args-json "{\"asset_id\":\"<asset_id>\",\"beneficiary_commitment\":\"<beneficiary_commitment>\",\"amount\":100}" --signer alice-view-key --fuel-limit 200
py -3.13 utils/nebula_l2/devnet.py paymaster-create --state l2_state.json --contract-id <contract_id> --fee-asset-id <fee_asset_id> --sponsor sponsor-view-key --per-call-cap 1 --per-caller-cap 5 --replenish-threshold 10 --replenish-target 100 --relayer-reward-units 1 --relayer-reward-budget 25 --allowed-caller bob-view-key
py -3.13 utils/nebula_l2/devnet.py paymaster-deposit --state l2_state.json --paymaster-id <paymaster_id> --spent-note-id <sponsor_fee_note_id> --amount 100
py -3.13 utils/nebula_l2/devnet.py contract-call --state l2_state.json --contract-id <contract_id> --entrypoint increment --args-json "{\"amount\": 1}" --signer bob-view-key --fuel-limit 20 --paymaster-id <paymaster_id> --max-fee 1
py -3.13 utils/nebula_l2/devnet.py paymaster-pause --state l2_state.json --paymaster-id <paymaster_id> --sponsor sponsor-view-key --reason <incident_summary>
py -3.13 utils/nebula_l2/devnet.py paymaster-resume --state l2_state.json --paymaster-id <paymaster_id> --sponsor sponsor-view-key --reason <review_summary>
py -3.13 utils/nebula_l2/devnet.py paymaster-policy --state l2_state.json --paymaster-id <paymaster_id> --sponsor sponsor-view-key --per-caller-cap 3 --allowed-caller carol-view-key --replenish-threshold 20 --replenish-target 200 --relayer-reward-units 1 --relayer-reward-budget 50
py -3.13 utils/nebula_l2/devnet.py paymaster-relayer-bond --state l2_state.json --spent-note-id <relayer_bond_note_id> --relayer fee-relayer-a --amount 25
py -3.13 utils/nebula_l2/devnet.py paymaster-relayer-bonds --state l2_state.json --relayer-commitment <relayer_commitment>
py -3.13 utils/nebula_l2/devnet.py paymaster-relayer-select --state l2_state.json --paymaster-id <paymaster_id> --limit 3
py -3.13 utils/nebula_l2/devnet.py paymaster-relayer-unbond --state l2_state.json --bond-id <bond_id> --relayer fee-relayer-a --amount 5
py -3.13 utils/nebula_l2/devnet.py paymaster-relayer-unbond-claim --state l2_state.json --request-id <unbond_request_id> --relayer fee-relayer-a
py -3.13 utils/nebula_l2/devnet.py paymaster-refill-plan --state l2_state.json --paymaster-id <paymaster_id>
py -3.13 utils/nebula_l2/devnet.py paymaster-refill-route-authorize --state l2_state.json --paymaster-id <paymaster_id> --spent-note-id <sponsor_refill_note_id> --sponsor sponsor-view-key --max-amount 100 --expires-in-blocks 10
py -3.13 utils/nebula_l2/devnet.py paymaster-refill-authorize --state l2_state.json --paymaster-id <paymaster_id> --spent-note-id <sponsor_refill_note_id> --sponsor sponsor-view-key --relayer fee-relayer-a --max-amount 100 --expires-in-blocks 10
py -3.13 utils/nebula_l2/devnet.py paymaster-refill --state l2_state.json --paymaster-id <paymaster_id> --spent-note-id <sponsor_refill_note_id> --authorization-id <authorization_id> --relayer fee-relayer-a
py -3.13 utils/nebula_l2/devnet.py paymaster-relayer-reward-claim --state l2_state.json --reward-id <reward_id> --relayer fee-relayer-a
py -3.13 utils/nebula_l2/devnet.py paymaster-relayer-reward-claim-quote --state l2_state.json --reward-id <reward_id_1> --reward-id <reward_id_2> --relayer fee-relayer-a --expires-in-blocks 3 --inclusion-deadline-blocks 1
py -3.13 utils/nebula_l2/devnet.py paymaster-relayer-reward-claim-batch --state l2_state.json --reward-id <reward_id_1> --reward-id <reward_id_2> --relayer fee-relayer-a --expires-in-blocks 3 --inclusion-deadline-blocks 1
py -3.13 utils/nebula_l2/devnet.py paymaster-relayer-reward-settlement-monitor --state l2_state.json --relayer-commitment <relayer_commitment> --quote-json '<claim_quote_json>'
py -3.13 utils/nebula_l2/devnet.py paymaster-relayer-reward-quote-invalidate --state l2_state.json --quote-json '<claim_quote_json>' --reporter reward-watchtower-a
py -3.13 utils/nebula_l2/devnet.py paymaster-refill-authorizations --state l2_state.json --paymaster-id <paymaster_id>
py -3.13 utils/nebula_l2/devnet.py paymaster-refill-failure --state l2_state.json --authorization-id <authorization_id> --reporter sponsor-view-key --evidence <missed_refill_summary>
py -3.13 utils/nebula_l2/devnet.py paymaster-refill-challenge --state l2_state.json --receipt-id <failure_receipt_id> --relayer fee-relayer-a --evidence <private_delivery_summary>
py -3.13 utils/nebula_l2/devnet.py paymaster-refill-slash --state l2_state.json --receipt-id <failure_receipt_id> --reporter sponsor-view-key --penalty-units 1
py -3.13 utils/nebula_l2/devnet.py paymaster-refill-slash-settle --state l2_state.json --hook-id <slashing_hook_id> --reporter sponsor-view-key
py -3.13 utils/nebula_l2/devnet.py paymaster-refill-reputation --state l2_state.json
py -3.13 utils/nebula_l2/devnet.py paymaster-close --state l2_state.json --paymaster-id <paymaster_id> --sponsor sponsor-view-key --reason <shutdown_summary>
py -3.13 utils/nebula_l2/devnet.py contract-deposit --state l2_state.json --contract-id <contract_id> --spent-note-id <asset_note_id> --amount 500 --network-fee 1
py -3.13 utils/nebula_l2/devnet.py contract-withdraw --state l2_state.json --contract-id <contract_id> --asset-id <asset_id> --amount 250 --to bob-view-key --network-fee 1 --signer alice-view-key
py -3.13 utils/nebula_l2/devnet.py paymasters --state l2_state.json
py -3.13 utils/nebula_l2/devnet.py contracts --state l2_state.json
py -3.13 utils/nebula_l2/devnet.py contract-events --state l2_state.json --contract-id <contract_id>
py -3.13 utils/nebula_l2/devnet.py contract-execution-receipts --state l2_state.json --contract-id <contract_id>
py -3.13 utils/nebula_l2/devnet.py bridge-deposit --state l2_state.json --owner alice-view-key
py -3.13 utils/nebula_l2/devnet.py bridge-observe --state l2_state.json --deposit-id <deposit_id> --monero-txid <monero_txid> --amount 1000000 --confirmations 10 --watcher bridge-signer-1 --watcher bridge-signer-2
py -3.13 utils/nebula_l2/devnet.py bridge-mint --state l2_state.json --deposit-id <deposit_id>
py -3.13 utils/nebula_l2/devnet.py block --state l2_state.json
py -3.13 utils/nebula_l2/devnet.py asset --state l2_state.json --symbol DUSD --issuer-policy devnet-stable-issuer
py -3.13 utils/nebula_l2/devnet.py pool --state l2_state.json --asset-a-id <wrapped_xmr_asset_id> --asset-b-id <dusd_asset_id>
py -3.13 utils/nebula_l2/devnet.py pool --state l2_state.json --asset-a-id <dusd_asset_id> --asset-b-id <dusc_asset_id> --fee-bps 5 --curve stable
py -3.13 utils/nebula_l2/devnet.py oracle-publish --state l2_state.json --base-asset-id <wrapped_xmr_asset_id> --quote-asset-id <dusd_asset_id> --price-numerator 2 --price-denominator 1 --publisher oracle-a --publisher oracle-b
py -3.13 utils/nebula_l2/devnet.py oracles --state l2_state.json
py -3.13 utils/nebula_l2/devnet.py lending-market --state l2_state.json --collateral-asset-id <wrapped_xmr_asset_id> --debt-asset-id <dusd_asset_id> --collateral-factor-bps 5000 --oracle-feed-id <oracle_feed_id>
py -3.13 utils/nebula_l2/devnet.py mint --state l2_state.json --asset-id <dusd_asset_id> --owner alice-view-key --amount 2000000
py -3.13 utils/nebula_l2/devnet.py transfer --state l2_state.json --spent-note-id <transfer_wxmr_note_id> --to bob-view-key --amount 25000 --fee 20
py -3.13 utils/nebula_l2/devnet.py batch-transfer --state l2_state.json --spent-note-id <note_1> --spent-note-id <note_2> --to bob-view-key --amount 25000 --to carol-view-key --amount 10000 --fee 20
py -3.13 utils/nebula_l2/devnet.py mempool --state l2_state.json
py -3.13 utils/nebula_l2/devnet.py mempool-status --state l2_state.json --admission-id <admission_id>
py -3.13 utils/nebula_l2/devnet.py tx-status --state l2_state.json --tx-hash <tx_public_hash>
py -3.13 utils/nebula_l2/devnet.py preconfirmations --state l2_state.json
py -3.13 utils/nebula_l2/devnet.py block --state l2_state.json --defer-mempool
py -3.13 utils/nebula_l2/devnet.py preconfirm-miss --state l2_state.json --preconfirmation-id <preconfirmation_id> --reporter watchtower-a
py -3.13 utils/nebula_l2/devnet.py mempool-expire --state l2_state.json --admission-id <admission_id> --reporter watchtower-a
py -3.13 utils/nebula_l2/devnet.py mempool-force-include --state l2_state.json --evidence-id <evidence_id> --sequencer devnet-proposer
py -3.13 utils/nebula_l2/devnet.py mempool-evidence --state l2_state.json
py -3.13 utils/nebula_l2/devnet.py fee-quote --state l2_state.json --operation batch-transfer --input-count 2 --output-count 3
py -3.13 utils/nebula_l2/devnet.py fee-quote --state l2_state.json --operation contract-call --contract-id <contract_id> --paymaster-id <paymaster_id> --fee-mode paymaster --contract-fuel 40
py -3.13 utils/nebula_l2/devnet.py fee-quote --state l2_state.json --operation contract-call-batch --input-count 2 --contract-id <contract_id> --contract-fuel 40 --private-args
py -3.13 utils/nebula_l2/devnet.py fee-quote --state l2_state.json --operation contract-call --contract-id <contract_id> --fee-mode paymaster --contract-fuel 40 --private-args
py -3.13 utils/nebula_l2/devnet.py fee-markets --state l2_state.json --pending
py -3.13 utils/nebula_l2/devnet.py profile --state l2_state.json
py -3.13 utils/nebula_l2/devnet.py fee-quote --state l2_state.json --operation contract-deposit --output-count 1 --fee-asset-id <asset_id>
py -3.13 utils/nebula_l2/devnet.py fee-quote --state l2_state.json --operation contract-withdraw --fee-mode contract-balance --fee-asset-id <asset_id>
py -3.13 utils/nebula_l2/devnet.py fee-quote --state l2_state.json --operation paymaster-reward-claim-batch --input-count 3 --fee-asset-id <fee_asset_id>
py -3.13 utils/nebula_l2/devnet.py benchmark --state l2_state.json --scenario local-throughput-smoke --benchmarker performance-watchtower-a
py -3.13 utils/nebula_l2/devnet.py benchmarks --state l2_state.json
py -3.13 utils/nebula_l2/devnet.py calibrate --state l2_state.json --benchmark-id <benchmark_id> --calibrator performance-lab-a --measured-proof-bytes 4096 --measured-auth-bytes 7168 --measured-da-bytes 8192 --measured-prover-ms 12 --measured-signer-ms 4 --measured-total-latency-ms 525
py -3.13 utils/nebula_l2/devnet.py calibrations --state l2_state.json
py -3.13 utils/nebula_l2/devnet.py borrow --state l2_state.json --market-id <market_id> --collateral-note-id <wxmr_note_id> --collateral-amount 100000 --borrow-amount 50000 --owner alice-view-key --borrow-fee 10
py -3.13 utils/nebula_l2/devnet.py repay --state l2_state.json --position-id <position_id> --debt-note-id <dusd_note_id>
py -3.13 utils/nebula_l2/devnet.py lending --state l2_state.json
py -3.13 utils/nebula_l2/devnet.py liquidity --state l2_state.json --pool-id <pool_id> --note-a-id <lp_wxmr_note_id> --note-b-id <lp_dusd_note_id> --amount-a 500000 --amount-b 1000000 --owner alice-view-key
py -3.13 utils/nebula_l2/devnet.py swap --state l2_state.json --pool-id <pool_id> --note-in-id <swap_wxmr_note_id> --amount-in 10000 --min-amount-out 1 --to bob-view-key
py -3.13 utils/nebula_l2/devnet.py batch-swap --state l2_state.json --pool-id <pool_id> --note-in-id <note_1> --amount-in 600 --note-in-id <note_2> --amount-in 400 --min-total-amount-out 1 --to bob-view-key
py -3.13 utils/nebula_l2/devnet.py fee-quote --state l2_state.json --operation route-swap --input-count 2 --output-count 2 --pool-id <first_pool_id>
py -3.13 utils/nebula_l2/devnet.py route-swap --state l2_state.json --pool-id <pool_1> --pool-id <pool_2> --note-in-id <route_note> --amount-in 10000 --min-amount-out 1 --to bob-view-key
py -3.13 utils/nebula_l2/devnet.py fee-quote --state l2_state.json --operation dark-swap --input-count 2 --output-count 4
py -3.13 utils/nebula_l2/devnet.py dark-swap --state l2_state.json --note-a-id <alice_note> --note-b-id <bob_note> --amount-a 400 --amount-b 800 --to-a alice-view-key --to-b bob-view-key --network-fee-a 2 --network-fee-b 3
py -3.13 utils/nebula_l2/devnet.py sealed-swap-commit --state l2_state.json --pool-id <pool_id> --note-in-id <alice_note> --amount-in 600 --min-amount-out 1 --to alice-view-key --network-fee 2 --reveal-secret <alice_secret>
py -3.13 utils/nebula_l2/devnet.py sealed-bid --state l2_state.json --pool-id <pool_id> --commitment-id <alice_commitment_id> --commitment-id <bob_commitment_id> --asset-in-id <wrapped_xmr_asset_id> --asset-out-id <dusd_asset_id> --total-amount-in 1000 --quoted-amount-out 891 --network-fee-total 3 --solver solver-a
py -3.13 utils/nebula_l2/devnet.py sealed-bids --state l2_state.json --pool-id <pool_id>
py -3.13 utils/nebula_l2/devnet.py sealed-swap --state l2_state.json --pool-id <pool_id> --note-in-id <alice_note> --amount-in 600 --min-amount-out 1 --to alice-view-key --network-fee 2 --note-in-id <bob_note> --amount-in 400 --min-amount-out 1 --to bob-view-key --network-fee 1 --solver solver-a --solver-bid-id <bid_id>
py -3.13 utils/nebula_l2/devnet.py sealed-expire --state l2_state.json
py -3.13 utils/nebula_l2/devnet.py sealed-settlements --state l2_state.json --pool-id <pool_id>
py -3.13 utils/nebula_l2/devnet.py sealed-commitments --state l2_state.json --pool-id <pool_id>
py -3.13 utils/nebula_l2/devnet.py block --state l2_state.json --proposer validator-two
py -3.13 utils/nebula_l2/devnet.py da --state l2_state.json --block-height <block_height>
py -3.13 utils/nebula_l2/devnet.py da-sample --state l2_state.json --block-height <block_height> --shard-index 0
py -3.13 utils/nebula_l2/devnet.py validity --state l2_state.json --block-height <block_height>
py -3.13 utils/nebula_l2/devnet.py proofs --state l2_state.json --block-height <block_height>
py -3.13 utils/nebula_l2/devnet.py audit-block --state l2_state.json --block-height <block_height> --watchtower watchtower-a --sample-shard 0 --sample-shard 1
py -3.13 utils/nebula_l2/devnet.py block-audits --state l2_state.json --block-height <block_height>
py -3.13 utils/nebula_l2/devnet.py challenge-block --state l2_state.json --block-height <block_height> --type bridge-root-mismatch --observed-root <conflicting_root> --reporter watchtower-a
py -3.13 utils/nebula_l2/devnet.py block-challenges --state l2_state.json --block-height <block_height>
py -3.13 utils/nebula_l2/devnet.py fee-markets --state l2_state.json --block-height <block_height>
py -3.13 utils/nebula_l2/devnet.py wallet --state l2_state.json --owner bob-view-key
py -3.13 utils/nebula_l2/devnet.py wallet-history --state l2_state.json --owner bob-view-key
py -3.13 utils/nebula_l2/devnet.py disclose --state l2_state.json --owner bob-view-key --audience merchant-auditor --asset-id <wrapped_xmr_asset_id>
py -3.13 utils/nebula_l2/devnet.py pools --state l2_state.json
py -3.13 utils/nebula_l2/devnet.py bridge-withdraw --state l2_state.json --spent-note-id <wxmr_note_id> --monero-address <monero_address> --amount 25000 --bridge-fee 10
py -3.13 utils/nebula_l2/devnet.py bridge-withdraw-challenge --state l2_state.json --withdrawal-id <withdrawal_id> --type watchtower-hold --evidence <private_evidence_summary> --reporter bridge-watchtower-a --hold-blocks 3
py -3.13 utils/nebula_l2/devnet.py bridge-withdraw-challenges --state l2_state.json --withdrawal-id <withdrawal_id>
py -3.13 utils/nebula_l2/devnet.py bridge-rate-limit --state l2_state.json
py -3.13 utils/nebula_l2/devnet.py bridge-signers --state l2_state.json
py -3.13 utils/nebula_l2/devnet.py bridge-signer-rotate --state l2_state.json --signer bridge-signer-a --signer bridge-signer-b --signer bridge-signer-c --threshold 2 --operator bridge-guardian
py -3.13 utils/nebula_l2/devnet.py bridge-withdraw-release --state l2_state.json --withdrawal-id <withdrawal_id> --monero-txid <withdrawal_txid> --signer bridge-signer-1 --signer bridge-signer-2
py -3.13 utils/nebula_l2/devnet.py bridge-withdraw-confirm --state l2_state.json --withdrawal-id <withdrawal_id> --confirmations 10
py -3.13 utils/nebula_l2/devnet.py bridge-reserve-report --state l2_state.json --reserve-address <reserve_address> --reserve-amount <atomic_xmr_reserve> --reporter reserve-auditor-1 --reporter reserve-auditor-2
py -3.13 utils/nebula_l2/devnet.py bridge-pause --state l2_state.json --reason <incident_summary> --operator bridge-guardian
py -3.13 utils/nebula_l2/devnet.py bridge-resume --state l2_state.json --reason <resolution_summary> --operator bridge-guardian
py -3.13 utils/nebula_l2/devnet.py bridge --state l2_state.json
py -3.13 utils/nebula_l2/devnet.py anchor --state l2_state.json
py -3.13 utils/nebula_l2/devnet.py epoch-checkpoint --state l2_state.json --block-height <block_height>
py -3.13 utils/nebula_l2/devnet.py anchor-submit --state l2_state.json --block-height <block_height> --submitter anchor-operator-1 --monero-txid <anchor_txid>
py -3.13 utils/nebula_l2/devnet.py anchor-confirm --state l2_state.json --anchor-id <anchor_id> --confirmations 10
py -3.13 utils/nebula_l2/devnet.py settlement --state l2_state.json --block-height <block_height>
py -3.13 utils/nebula_l2/devnet.py anchors --state l2_state.json
```

For an unsafe oracle-backed lending position, publish the new collateral price,
then spend a liquidator-controlled debt note to close the position:

```text
py -3.13 utils/nebula_l2/devnet.py oracle-publish --state l2_state.json --base-asset-id <wrapped_xmr_asset_id> --quote-asset-id <dusd_asset_id> --price-numerator 1 --price-denominator 1 --publisher oracle-a --publisher oracle-b
py -3.13 utils/nebula_l2/devnet.py liquidate --state l2_state.json --position-id <position_id> --debt-note-id <liquidator_dusd_note_id> --liquidator liquidator-view-key
```

Tests:

```text
py -3.13 utils/nebula_l2/test_devnet.py
py -3.13 -m unittest utils.nebula_l2.test_devnet
```

## Consensus And Finality

Use a small-to-medium rotating BFT committee for soft finality. A practical
target for the first implementation:

- 250 ms to 1 s local mempool admission.
- 1 s block time.
- 2 to 5 s L2 soft finality under normal network conditions.
- Monero hard settlement after an anchor transaction receives the configured
  base-chain confirmation depth.

Each L2 epoch contains many L2 blocks. At the end of an epoch, the committee
commits the epoch root to Monero in a standardized anchor transaction.

### Committee Rotation

Validators are selected from staked L2 operators. Rotation is epoch based.
Validator identity keys are post-quantum signature keys. Consensus may use
efficient classical aggregation during an early hybrid phase, but every
consensus vote must also be bound to a post-quantum signature transcript so a
future migration can reject classical-only authority.

Required validator key material:

- `consensus_pq_key`: ML-DSA key for validator votes.
- `bridge_pq_key`: ML-DSA or SLH-DSA key for bridge actions.
- `network_kem_key`: ML-KEM key for encrypted peer channels.
- `classical_compat_key`: optional legacy key used only during hybrid migration.

## Post-Quantum Cryptography Profile

Nebula should use a crypto-agile suite registry. Version 1 should define:

- Signatures: ML-DSA-65 for normal account and validator signatures.
- Long-lived recovery signatures: SLH-DSA-SHAKE-128s or a stronger SLH-DSA
  parameter set when signature size is acceptable.
- Key establishment: ML-KEM-768 for wallet-to-node and node-to-node encrypted
  sessions, with a hybrid X25519 plus ML-KEM mode during migration.
- Hashing and domain separation: cSHAKE256, KMAC256, TupleHash256, and
  ParallelHash256.
- Merkle trees: hash-based sparse Merkle or Verkle-like structures only if the
  chosen commitment is not quantum-vulnerable.
- Avoid as security-critical dependencies: BLS signatures, KZG commitments,
  pairing-based SNARKs, and non-hybrid elliptic-curve-only authentication.

Every signature signs a typed transcript:

```text
TupleHash256(
  "NEBULA-L2",
  chain_id,
  domain,
  protocol_version,
  account_or_validator_id,
  monotonic_nonce_or_nullifier,
  payload_hash
)
```

The devnet now includes an account registry committed by `account_root`.
Registration stores the active ML-DSA-shaped spend key, SLH-DSA-shaped recovery
key, ML-KEM-shaped network key, and a rotation nonce. A recovery-signed
`account_rotation` transaction replaces the spend, recovery, and network keys,
increments the nonce, and retires the old signer label so stale credentials are
rejected in later blocks. This is still deterministic mock cryptography, but it
models the recovery path a quantum-resistant wallet needs before real keys are
plugged in.
Wallets can open an ML-KEM-shaped wallet-to-node session with `session-open`.
The receipt binds the account id, wallet network public key, active node
committee key id, node network root, relay-path policy/hop metadata, route
commitment, expiry height, KEM ciphertext hash, and session transcript hash
under an ML-DSA-shaped account signature. Public session records omit the exact
relay path and wallet label; persisted devnet state keeps them only to verify
the mock signature and KEM transcript. Account key rotation revokes active
sessions for that account so stale network keys stop being accepted.
The Rust core mirrors this model with `AccountRegistry`, `AccountRotation`, and
`WalletSession` records. The Rust `account_root` commits public account records
plus the current `wallet_session_root`; session public records expose only
relay-path policy, hop count, and route commitment while the raw route remains
state-local for transcript verification.

The devnet also exposes a `crypto-policy` command. It returns the policy id,
policy version, suite registry, `crypto_policy_root`, and deterministic test
vectors for account authorization, recovery authorization, and an
ML-KEM-shaped mempool ciphertext commitment. Snapshots, persisted state, and
block headers carry the same root, and state loading rejects mismatched policy
roots or unsupported suite names.

## Privacy Model

Privacy is mandatory for user balances. The base L2 ledger is note based:

- A note commits to owner, asset id, amount, spending conditions, and blinding.
- A nullifier prevents double spends without revealing the spent note.
- Recipients scan encrypted output payloads using view keys.
- Amounts are confidential by default.
- Asset ids are hidden when possible, or grouped into anonymity classes when
  fully hidden asset ids are too expensive.
- Transaction fees are paid through a fee note or relayer mechanism that avoids
  linking payer identity to transaction contents.

The privacy model has three execution tiers:

- Private transfer tier: shielded XMR-equivalent and shielded token transfers.
- Private DeFi tier: batched AMMs, sealed-bid intents, dark pool matching, and
  auctions where users reveal only the minimum data needed for settlement.
- Public contract tier: deterministic public state for applications that do not
  require full privacy, still using private account authentication and encrypted
  mempool submission.

No protocol path should require a transparent account balance. Wallets may offer
view-key based disclosure for audits, taxes, disputes, and merchants.

The devnet models this with a signed `ViewKeyDisclosure` export. A wallet chooses
an audience label, optional asset scope, and expiry window, then signs a bundle
containing the disclosed view-key label, matching current wallet notes, asset
totals, note commitment root, and owner commitment. The public disclosure record
omits raw notes and the view-key label; the audit record intentionally includes
them for the selected recipient. Verification rejects expired, tampered, or
non-current note bundles.

The `wallet-history` command scans confirmed block payloads and pending
transactions with a view-key label, then returns commitment-only received
events, spend events, current totals, received totals, spent totals, fee totals,
and a `history_root`. Notes created by devnet-only immediate state mints are
reported as `current_unindexed` if they are current but not recoverable from a
block payload; production mint and bridge paths should be block transactions so
wallet history can come from DA plus view keys.

### Mempool Privacy

Transactions are encrypted to the current sequencer committee and relayed
through a Dandelion-style stem/fluff path or Tor/I2P. Sequencers commit to a
batch before decrypting the full orderable payload. This reduces basic mempool
surveillance and simple front-running.

The devnet models this with `MempoolAdmission` receipts. Each queued
transaction gets a public admission id, public transaction hash, encrypted
payload hash, ML-KEM-shaped committee key id, ML-KEM-shaped ciphertext hash,
policy-bound KEM envelope, relay-path policy, hop count, route commitment,
expiry height, and sequencer authorization. Public receipts do not publish the
exact relay path; persisted devnet state keeps the route only so deterministic
mock signatures and KEM transcripts can be replayed. The legacy
`kem_ciphertext_hash` stays stable while the envelope commits the
key-establishment scheme, recipient committee key id, recipient key root,
transcript hash, and active crypto-policy root. It is not real payload
encryption yet, but it makes pending-state persistence, CLI inspection, and
block production enforce the same receipt shape a privacy-preserving sequencer
path will need.

Each admission also receives a `MempoolPreconfirmation` receipt. This is a
sequencer-signed promise to include the encrypted admission by a target L2
height. The Rust sequencer can now use fee/resource packing to target a later
height when a transaction will not fit the next local block. The receipt binds the
admission id, public transaction hash, encrypted payload hash, promised mempool
root, pending transaction count, and local fee-market root. If the target passes
without inclusion, a watchtower can submit `preconfirm-miss`; this creates
`MempoolPreconfirmationMissEvidence`, slashes the sequencer, and leaves the
admission pending so it can still be included later. That gives wallets a fast
accountability surface without decrypting or revealing the payload.

Produced devnet blocks now commit `mempool_admission_root` and
`mempool_admission_count` into the signed header and DA payload. That preserves
the encrypted batch the sequencer accepted before execution, giving wallets and
watchtowers a concrete commitment to compare against mempool receipts when
checking for censorship, omission, or ordering games.

The `mempool-expire` command lets a watchtower turn an expired admission receipt
into `MempoolOmissionEvidence`. The evidence preserves the sequencer-signed
receipt hashes, reporter authorization, missed block count, penalty units, and
the validator stake slash applied to the registered sequencer that signed the
receipt. It then evicts the stale pending transaction without revealing the
encrypted payload contents or wallet labels. `block --defer-mempool` exists for
adversarial devnet scenarios where a sequencer produces blocks while omitting
already admitted encrypted transactions.

After omission evidence exists, `mempool-force-include` can requeue the omitted
transaction from private recovery state. The resulting `MempoolForcedInclusion`
receipt is signed by an active sequencer and binds the omission evidence id, old
admission id, old encrypted payload hash, new admission id, new encrypted
payload hash, new committee key id, forced-inclusion relay policy, hop count,
and route commitment. The public receipt proves the transaction was reaccepted
without publishing the transaction body, exact relay path, or wallet labels; the
private recovery payload is removed once the fresh admission is created.

Wallets and watchtowers can call `mempool-status` with an admission id. The
lookup first checks live pending receipts, then omission evidence, then
historical DA payloads committed by produced blocks. Status responses also
include the matching preconfirmation receipts, whether they are still
preconfirmed, fulfilled, target-missed, miss-reported, or included late. Included
results return the block height, block hash, DA root, admission root, and
current settlement status for the block, so users can distinguish fast local
inclusion from Monero-final settlement without revealing the encrypted payload.
Wallets can also call `tx-status` with either the general `TX-PUBLIC`
transaction hash or the mempool receipt hash. Pending responses include the
encrypted admission and preconfirmation receipts; included responses attach the
transaction index, block hash, DA root, validity-certificate root,
privacy-proof aggregate root, optional per-transaction proof item, and the same
settlement ladder used by `settlement`.

The Rust `LocalSequencer` is the first single API that ties these surfaces
together. It owns `DefiState`, `ContractState`, `WasmRuntimeState`,
`BridgeState`, `AccountRegistry`, `MempoolState`, `ConsensusState`, validators,
and `StatusIndex`.
`admit_transaction` accepts a public transaction record, state/private record,
fee resource, and relay path, then creates a signed encrypted mempool admission
and preconfirmation. It also exposes typed DeFi submission wrappers for asset
mint/burn, AMM liquidity, direct/batch/route/dark/sealed swaps, and lending
borrow/repay/liquidation. Those wrappers stage against an `admission_defi`
mirror, reserving pending notes and nullifiers for wallet UX while leaving
canonical `DefiState` unchanged until selected block execution.
`next_block_packing` and
`next_state_safe_block_packing` expose deterministic fee-density, lane-fair,
resource-capped proposal receipts; staged DeFi transitions are replayed from
canonical state during `produce_block`, and non-executable staged transactions
remain pending instead of corrupting block roots. `produce_block` drains pending admissions into
`build_l2_block`, committing integrated state roots for notes, nullifiers,
contracts, Wasm, accounts, assets, sealed-swap settlement receipts, bridge,
fees, and crypto policy. It stores the DA record, privacy aggregate, validity
certificate, block, and pending-cleared status view. `submit_epoch_anchor`
turns stored headers into an `EpochCheckpoint` and `AnchorSubmission`, giving
the Rust prototype a local path from private transaction admission to
Monero-style anchor evidence.

The Rust prover surface now wraps produced blocks in explicit `ProofJob`
records, assigns them to staked `ProverNode` records, and records signed
`ProverReceipt` completions under a prover-specific ML-DSA transcript domain.
Sequencer snapshots expose a proof-market view so proof cost and capacity can
be priced alongside DA, execution, and privacy-proof resources. The
watchtower surface can sample committed DA shards, sign block audit reports,
and publish challenge reports for missing or conflicting proof, DA, bridge, or
mempool roots without revealing private payloads.

The Rust network inventory layer keeps transport details state-local while
publishing route commitments, relay policy metadata, and signed root vectors.
Sequencers can announce current state, DA, mempool, prover, watchtower, bridge,
Monero-monitor, consensus, mempool-fairness, and fee-market roots; they can
separately announce encrypted admission inventory with target-height
commitments. Watchtowers can compare
inventory announcements, score peers, and publish root-conflict evidence before
forcing wallets or relays into expensive replay.

The Rust consensus state adds devnet fast-finality machinery around the block
builder. Validators are imported as stake records with consensus public keys;
the sequencer records stake-weighted proposer slots, signs fast-finality votes,
builds quorum certificates, and commits downtime/equivocation evidence into
consensus roots. This is not production consensus yet, but it gives blocks a
deterministic finality certificate and gives watchtowers slashable evidence
formats to build on.

The Rust mempool now creates privacy-preserving fairness artifacts for private
admission flow. Each admission can be accompanied by an encrypted batch receipt,
a relay fairness ticket with only relay-policy metadata, and an anti-censorship
lane commitment that reserves private slots without exposing relay paths or
payloads. Fee smoothing adds low-fee lane budgets for privacy transfers, Monero
bridge operations, and small DeFi calls so congestion can be absorbed with
explicit rebates rather than forcing every private action into the same fee
auction.

The Rust Monero monitor is now a deterministic evidence layer rather than a
live daemon client. It records endpoint registrations, RPC response roots, ZMQ
payload roots, block-tip observations, hashed transaction observations, anchor
confirmations, withdrawal confirmations, reserve reports, and reorg evidence.
Those records expose txid hashes, address hashes, amount buckets, endpoint
commitments, observer signature roots, and status strings while keeping raw
routes, addresses, and daemon payloads out of public records. `StatusIndex`
folds the monitor into settlement status, excludes anchors with active reorg
evidence from covering-anchor status, and exposes a `monero_status` surface for
wallets and watchtowers.

The Rust wallet sync index builds a local history view across those status
surfaces. A wallet supplies its view key plus watched transaction hashes and
nullifiers; the index derives owner, contract-caller, Wasm-caller, and
paymaster-caller commitments, then scans notes, mempool receipts, contract
receipts, Wasm receipts, bridge deposit/mint/withdrawal records, Monero
anchor/withdrawal/reorg evidence, and paymaster sponsorships. The resulting
wallet view exposes scan tags, amount buckets, record hashes, and a
`history_root`, but omits raw view keys, exact relay paths, caller labels,
Monero addresses, and private payloads.

For DeFi, wallets should prefer intent submission:

- User signs an encrypted intent.
- Solvers compete to satisfy it.
- The settlement contract verifies price bounds and privacy proofs.
- Failed intents expire without leaking more than their encrypted envelope.

## Smart Contracts

The contract runtime is deterministic Wasm with a narrow host interface.
The current devnet scaffold does not embed a Wasm engine yet; it uses a
deterministic template executor with code hashes, storage roots, signed calls,
fuel limits, and append-only event logs to keep the transaction and state model
aligned with the future Wasm runtime. The Rust core now adds the runtime
boundary object model around that target: `WasmModuleManifest` commits the code
hash, ABI hash, runtime version, host-permission root, max fuel, memory limit,
imported host-function root, exported function root, validation hash,
deterministic profile, upgrade policy, and owner authorization. Module
deployment rejects malformed Wasm bytes, unsupported host modules, unsupported
host permissions, imported permissions that do not match the manifest request,
memory declarations above policy, function/code count mismatches, and modules
without the required `execute` export. 
`WasmContractInstance` commits storage state; and
`WasmRuntimeExecutionReceipt` binds the call transaction hash, entrypoint,
args commitment, caller commitment, fuel, memory pages, host-call root,
storage-delta root, event root, paymaster id, and fee asset. L2 block headers
now include `wasm_runtime_root`, allowing validators to sign the runtime state
root alongside note, contract, bridge, fee, and crypto-policy roots while a
production Wasm engine is still being wired in. Contracts also carry native
`asset_balances` so deposits can spend private notes into public escrow and
withdrawals can release escrow into fresh private notes without relying on
token-contract accounting. Every committed contract call emits a public
`ContractExecutionReceipt` that binds the template/code hash, entrypoint,
args commitment, caller commitment, block transaction index, fuel limit/used,
storage roots before and after execution, event id, and event-chain root. This
gives validators and DeFi indexers a cheap replay target for metered execution
without publishing hidden arguments. Event payloads commit to callers with
`caller_commitment` values instead of raw wallet labels, giving DeFi indexers a
stable public stream without turning contract calls into account doxxing.
Each `ContractEvent` also carries the prior public event Merkle root and its
own event-chain root, so indexers can verify that the event log advanced by
append only and was not reordered, deleted, or rewritten between snapshots.
Contract calls can also set `--private-args`: the signed state witness keeps the
raw JSON arguments for deterministic execution, while public transaction,
block, DA, and event records expose only `args_commitment` plus a deterministic
privacy proof. This hides calldata-style intent from observers, but public
contract storage and intentionally public events can still reveal state effects.
Callers can selectively open private contract-event arguments with
`contract-event-disclose`. The disclosure signs the event id, event data hash,
caller commitment, args commitment, audience, expiry, and opening root; the
auditor record includes the signer label and raw argument opening.
Contracts can opt into `--private-storage` at deployment. In that mode, public
contract, snapshot, and contract-root inputs publish only `storage_root` /
`storage_commitment`; the persisted state witness retains the raw storage so
devnet execution and replay stay deterministic.
Private storage can be selectively opened with `contract-disclose`. A disclosure
signs the contract id, storage root, audience, expiry, and opening root. Public
disclosure records expose only hashes; auditor records add the disclosed owner
label and the requested path/value openings.
The `contract-call-batch` transaction executes several calls sequentially under
one post-quantum authorization, one optional privacy proof, and one fee note or
paymaster debit. This is the contract-side analogue of private transfer
batching: DeFi workflows can update multiple contract states while amortizing
authorization, DA, and fee overhead.

The `vault` template is the first escrow-aware contract example. The owner can
call `grant` or `revoke` against an `asset_id` and beneficiary commitment. A
committed beneficiary can then use `contract-withdraw` to release the allowed
amount to their own private note; the devnet deducts both the contract balance
and the allowance, and rejects queued withdrawals that would overspend either.
Each allowance stores an `allowance_commitment`, and vault storage carries an
`allowance_root` so wallets and DeFi indexers can track committed allowance
changes without raw beneficiary labels.

The `governor` template is the first DAO-style governance example. Proposals
store only a `description_hash`, optional `action_hash`, quorum, voting window,
and proposer commitment. Votes are PQ-signed contract calls and are indexed by
`voter_commitment`, preventing duplicate votes without publishing raw voter
labels. Execution after the voting window records whether quorum and majority
passed, then emits a `governor.executed` event with an executor commitment.

Rules:

- No floating point.
- No nondeterministic syscalls.
- No wall-clock access except protocol-provided block and epoch values.
- Explicit fuel metering.
- Actual `fuel_used` is committed into the signed contract-call transcript.
- Private argument calls publish an `args_commitment` and require a privacy
  proof even when fuel is sponsored by a paymaster.
- Private contract-event disclosures are scoped by event id, caller, audience,
  expiry, data hash, and args commitment.
- Private-storage contracts publish only storage commitments in public contract
  views.
- Private storage disclosures are scoped by path, audience, expiry, and storage
  root.
- Contract-call batches count each internal call for fuel and event indexing,
  but use one outer authorization and one fee settlement.
- Bounded memory.
- Bounded storage reads and writes.
- Contract calls are typed and versioned.
- Contract upgrades require an owner-signed, timelocked policy object.

The devnet models that policy as `ContractUpgradeProposal`. A proposal binds the
contract id, template, current and proposed versions, current and proposed code
hashes, current and proposed fuel limits, proposal height, execution height, and
an ML-DSA-shaped owner authorization. Execution is rejected until the timelock
height is reached and emits a `contract.upgraded` event with only an executor
commitment, not the raw executor label.

First-class objects:

- Account keys and recovery policies.
- Shielded notes.
- Mempool admissions.
- Assets.
- Contracts.
- Liquidity pools.
- Oracles.
- Bridge claims.

### Tokens

Assets are native ledger objects, not ad hoc contract storage entries.

Each asset has:

- `asset_id`
- `issuer_policy`
- `supply_policy`
- `privacy_class`
- `metadata_hash`
- `freeze_or_pause_policy`, optional and visible to users

Supported initial token types:

- Fixed supply fungible tokens.
- Mint/burn fungible tokens.
- NFT-like unique notes.
- LP shares.
- Wrapped XMR.

## DeFi Applications

Priority DeFi applications:

- Private transfers for wrapped XMR and native L2 tokens.
- Constant-product AMMs with batched clearing.
- Stable-asset pools for near-parity assets with deterministic 1:1 minus fee
  settlement and the same private-note liquidity/swap flow.
- Same-signer private batch swaps that aggregate several notes into one AMM
  update while paying one network fee.
- Private multi-hop route swaps for best-path execution across AMM pools while
  paying one proof, one authorization, and one network fee.
- Dark-pool atomic swaps for direct two-party token matches that avoid AMM
  slippage and publish only nullifiers, output commitments, a trade commitment,
  proof root, and post-quantum authorization material.
- Multi-user sealed-bid swaps where each wallet signs a private intent and a
  solver clears the batch with one aggregate AMM update.
- Collateralized lending with private positions, public risk parameters, and
  oracle-triggered liquidations.
- DAO/governance contracts using post-quantum voting keys.
- Oracle feeds with threshold post-quantum attestations.

The Rust core now includes richer private swap and lending state models:
same-signer batch swaps, multi-hop route swaps, and dark-pool atomic swaps
share one privacy proof/authorization surface per transaction class and expose
only nullifiers, commitments, route roots, proof roots, and fee-lane resources.
Lending adds oracle price feeds with signed attestations, lending market roots,
position commitments that hide owner labels and raw amounts from public
records, private borrow/repay records, and oracle-backed liquidation records.

MEV controls:

- Encrypted mempool.
- Batch auctions for swaps.
- Commit-reveal for large orders.
- Solver competition with user-signed price limits.
- Slashing for sequencers that reveal, reorder, or censor encrypted batches
  outside protocol rules.

The devnet records `SealedSwapSettlementReceipt` entries when a sealed AMM
batch is executed. The transaction still hides per-user fills from the public
transaction body, but the solver signs a receipt over the block height, public
transaction hash, pool route, intent root, total input/output, aggregate
network fee, pool curve, clearing price, before/after pool-view roots, fill
commitment root, minimum-output commitment root, surplus commitment root, and
aggregate surplus. The public receipt also carries a clearing-price commitment
root and aggregate-surplus commitment root so wallets and indexers can verify
solver behavior and price-improvement claims from `sealed-settlements` without
seeing recipient view keys or raw per-intent minimums.

The Rust core now mirrors this path with `SealedSwapIntentReveal`,
`AmmSealedBatchSwap`, `SealedSwapFill`, and
`SealedSwapSettlementReceipt`. `submit_amm_sealed_batch_swap` opens active
commitments, enforces reveal windows, verifies per-intent PQ-shaped
authorizations, rejects non-winning solver bids when a better active bid
exists, updates the AMM pool once for the aggregate batch, marks matching
solver bids won/lost, and stores a solver-signed settlement receipt. The
receipt root is folded into the Rust sealed-auction root and into
`BlockStateRoots.sealed_swap_settlement_receipt_root`, so block headers,
validator vote payloads, validity public inputs, and transaction-status
responses can commit to sealed-settlement accountability.

Large orders can publish `sealed-swap-commit` records before revealing into a
sealed batch. Each commitment is signed by the user's post-quantum account key
and commits the pool, hidden note id, nullifier, input/output assets, amount,
minimum output, recipient commitment, network fee, reveal secret, reveal window,
and expiry. A later `sealed-swap` reveal must supply matching commitment ids and
opening secrets in intent order; the public transaction carries only a
commitment-count and commitment-root, while `sealed-commitments` shows active or
revealed commitment status without raw wallet labels.

Solver competition is represented by `sealed-bid` records. A bid signs an
ordered commitment-root batch, aggregate input, quoted output, fee total,
expiry, and solver commitment. A `sealed-swap` can name a `solver_bid_id`;
validation rejects it if a better active matching bid exists. Settlement marks
the selected bid `won` and competing active matching bids `lost`, giving public
auction accountability without recipient labels, note ids, or reveal secrets.

The `sealed-expire` command and block-production path deterministically mark
overdue active commitments and solver bids as `expired` once the current L2
height passes their expiry height. Inclusion-time proof verification also
rebuilds the sealed-swap context at the settlement height, so a reveal queued
before expiry cannot settle after its private auction window has closed.

The `route-swap` command models private multi-hop AMM execution. A wallet spends
one private input note through an ordered pool route, receives only the final
output asset plus optional input-asset change, and pays one network fee. The
public record commits the route pool ids, asset path, per-hop output amounts,
and route root, while hiding the spent note id, recipient label, and change
note. This gives aggregators better DeFi pricing without forcing users to
publish separate intermediate swaps or pay multiple proofs.

The `dark-swap` command models a two-party dark-pool match. Each side signs a
private leg transcript with its post-quantum account key; the transaction spends
both notes atomically, creates the two exchanged output notes plus optional
change notes, and pays side-specific fees. The public record does not include
spent note ids, recipient labels, raw asset ids, or raw trade amounts; it
publishes nullifiers, output commitments, a trade commitment, proof root, and
the two authorization transcripts so validators can enforce settlement without
turning the match into a public order book.

## Fee Model

Fees are priced by resource:

- Execution fuel.
- State reads.
- State writes.
- Proof verification.
- Data availability bytes.
- Monero anchor amortization.

The base L2 fee should be paid in wrapped XMR. Contracts may sponsor fees or
accept approved tokens through a paymaster interface. The devnet contract-call
path already computes a charged fee from actual deterministic fuel used, spends a
private fee note or deducts a contract paymaster balance, publishes only a fee
nullifier/change commitment for user-paid calls, commits `fuel_used`,
`fee_asset_id`, `fee`, optional `paymaster_id`, and the fee proof bundle into
the signed transcript, enforces a caller-provided `max_fee`, and credits the
selected fee asset into the block fee root. Paymasters can now publish a policy
hash with optional caller commitment allow lists, per-call caps, per-caller
lifetime caps, replenishment thresholds and targets, sponsor-configurable
relayer reward units, optional total relayer reward budget caps, and public
per-caller commitment spend totals, giving dapps a low-friction sponsorship path
without opening an unlimited fee or automation reward drain. Sponsors can also
publish signed pause, resume, policy-update, and close governance actions; the
public record commits the sponsor, reason text hash, previous policy hash, new
policy hash, action root, and any refund note commitment without leaking raw
sponsor or caller labels.
Relayers can query the refill plan to learn when the balance is at or below the
threshold. A sponsor can then publish a refill authorization receipt that binds
the sponsor note commitment, maximum top-up amount, relayer commitment, policy
hash, and expiry height; the relayer consumes that receipt to submit exactly the
target top-up amount without exposing raw sponsor or relayer labels. Expired
open authorizations can be reported as refill failure receipts; reputation rows
aggregate used, failed, open, expired-open, challenged, slashable, and penalty
counts by relayer commitment so wallets can avoid unreliable automation paths.
Each failure receipt commits a challenge deadline. A relayer can answer within
that window using `paymaster-refill-challenge`, which signs a private evidence
hash without exposing the raw relayer label. If the window closes unchallenged,
`paymaster-refill-slash` publishes a sponsor-signed slashing hook with penalty
units and the same relayer commitment, giving low-fee automation an
accountability path without making refill evidence public by default. Relayers
can bond private notes with `paymaster-relayer-bond`; public bond records expose
only the note commitment, nullifier, asset, relayer commitment, active amount,
slashed amount, and withdrawn amount. `paymaster-refill-slash-settle` consumes
a slashing hook once, deducts available bonded stake in the paymaster fee asset,
records any remaining unbonded penalty, and updates reputation with bonded,
active, settled-slashed, withdrawn, selectable, pending-unbond, and
unsettled-penalty totals. Relayers exit with `paymaster-relayer-unbond`, which
locks a delayed request before `paymaster-relayer-unbond-claim` creates a fresh
private note. Wallets can call `paymaster-relayer-select` to rank refill
relayers by fee-asset stake that is still selectable, excluding pending unbonds
and applying historical success once a relayer has authorization history.
Sponsors can use `paymaster-refill-route-authorize` to bind their refill note
to the top ranked relayer without naming a raw label in the public record.
Successful relayer-bound refills emit signed reward receipts. Relayers claim
those sponsor-funded rewards with `paymaster-relayer-reward-claim`, which
debits the paymaster balance and mints a fresh private note while publishing
only the claim note commitment, claimed amount, claimed height, and claim proof
root. For low-fee automation, `paymaster-relayer-reward-claim-batch` claims
many earned rewards for one relayer and fee asset with one signed bundle proof
root over all claim note commitments. Relayers can first call the read-only
`paymaster-relayer-reward-claim-quote` endpoint to get the max bundle size,
expiry height, inclusion deadline, deterministic re-quote backoff score,
estimated fee units, estimated proof bytes, estimated DA bytes, and quote root;
the batch claim binds those values into the signed public bundle so validators
can reject oversized or stale automation plans. Each claimed receipt links back
through `claim_bundle_id` and uses the bundle proof root as its claim proof.
Automation can call
`paymaster-relayer-reward-settlement-monitor` to observe claimable rewards,
settled bundles, persisted quote invalidation reports, and the status of
specific quote JSON records. Watchtowers can publish
`paymaster-relayer-reward-quote-invalidate` reports for expired,
inclusion-deadline-missed, settled, or otherwise non-claimable quotes; the
public report stores quote fields, observed reward statuses, a status root, a
reason code, re-quote pacing metadata, and a reporter commitment rather than
raw operator labels. Earned
reward units count against the paymaster reward budget cap before the private
refill deposit is queued, and every reward receipt carries a public budget
range plus budget proof root. Validators replay the ranges as a contiguous
cumulative sequence per paymaster, so a capped-out reward policy cannot leave a
partial pending refill behind or double-count budget units. Earned and claimed
reward units feed back into reputation and routing weights alongside success
and unsettled penalty exposure.

Low fees come from:

- One Monero anchor per epoch, not one Monero transaction per L2 transaction.
- Batching and compression.
- Native assets instead of expensive token contract boilerplate.
- Deterministic metering.
- Optional off-peak DA pricing.
- Local fee markets per congested contract or asset class.

The devnet now commits a block execution profile into every block header. The
profile records the target block interval, transaction count, privacy proof
count, contract fuel, uncompressed DA bytes, batched DA bytes, amortized DA bytes
per transaction, estimated proof/authentication bytes, observed fee units, local
fee-market root, local lane count, max local fee density, and batch discount
basis points. This is still an estimator, but it gives wallets and relayers an
objective place to compare latency and fee pressure before the full
prover-backed fee-note and paymaster design exists.

The `fee-quote` command adds a read-only wallet estimate before submission. It
projects a candidate operation into the pending block, returns the pending and
projected execution profiles, reports marginal DA bytes after batching, batch
savings, target inclusion time, minimum fee units, recommended fee units, a
fast-inclusion fee, and candidate/pending/projected local fee lanes. Lanes group
public resource pressure by operation, asset, contract, AMM pool, paymaster,
bridge, lending market, or account without exposing wallet labels. The
`fee-markets` command returns the recomputed lane report for pending
transactions or a produced block. This helps wallets choose between waiting for
cheap batch space, paying a small speed premium, using a paymaster, or
consolidating several notes into one private batch. Contract deposit quotes
account for one private note proof and change output; contract withdrawal quotes
use `contract-balance` fee mode because the fee comes from escrow rather than a
separate private fee note.

The `profile` command rolls those same public execution profiles into a
hash-addressed devnet performance report. It returns confirmed and pending
target TPS, target block and epoch-anchor latency, batched DA bytes, encoded DA
bytes, projected proof/auth bandwidth, average fee units per transaction,
batch-discount basis points, local fee pressure, and a small fee curve for
common wallet and DeFi operations. The report uses public transaction records,
block headers, DA records, and read-only `fee-quote` projections, so it does
not mutate the mempool and does not reveal private note owners, hidden contract
arguments, or raw Monero bridge addresses.

The `benchmark` command persists that public profile as a signed
`PerformanceBenchmarkRun`. Each run records the measured height, scenario,
confirmed and pending summaries, fee-curve root, local fee-pressure root, and a
ML-DSA-shaped benchmarker authorization. The `benchmarks` command lists the
history and aggregate root, giving operators an auditable trail for calibrating
latency, throughput, proof-size, bandwidth, and fee curves as real prover,
signer, DA, and contract-runtime measurements replace devnet estimates.

The `calibrate` command binds external measurements to a signed benchmark. A
`PerformanceCalibrationRecord` recomputes the benchmark's estimated proof bytes,
authorization bytes, DA bytes, execution fuel, proof count, authorization count,
and target latency, then records measured prover, signer, DA, contract-runtime,
and total-latency values. Public multipliers and per-unit timings let wallets
and relayers adjust fee and speed assumptions without exposing private notes or
contract arguments. The `calibrations` command lists the signed history and
aggregate calibration root.

## Monero Settlement And Anchoring

An anchor is a fixed-format Monero transaction that commits to an L2 epoch
without exposing user-level data.

Anchor commitment:

```text
epoch_checkpoint_root = TupleHash256(
  "EPOCH-CHECKPOINT",
  chain_id,
  epoch_number,
  start_height,
  end_height,
  block_hash_root,
  tx_root,
  state_root,
  da_root,
  validity_root,
  privacy_proof_aggregate_root,
  bridge_root,
  mempool_admission_root,
  validator_set_root,
  soft_finality_count
)

anchor_root = TupleHash256(
  "NEBULA-L2-EPOCH-ANCHOR",
  chain_id,
  epoch_number,
  previous_epoch_checkpoint_root,
  epoch_checkpoint_root
)
```

Anchor privacy requirements:

- Use a constant-size anchor payload.
- Submit anchors on a predictable cadence with jitter bounded by protocol rules.
- Avoid unique amounts.
- Avoid embedding user txids, user addresses, or bridge account ids.
- Allow multiple independent anchor submitters so one operator does not become
  a network-wide metadata beacon.

Anchor lifecycle:

1. An L2 node computes the epoch checkpoint for a historical block height.
2. An anchor submitter creates a fixed-format Monero transaction carrying that
   commitment.
3. The submitter signs a public transcript containing the block height, epoch,
   anchor commitment, checkpoint root, epoch range, block hash, state root,
   bridge root, submitter label, and a hash of the Monero transaction id.
4. Watchers update confirmation depth until the submission reaches the protocol
   finality depth.

The devnet exposes `epoch-checkpoint` so wallets and watchtowers can inspect the
checkpoint root before an anchor is submitted. `anchor-submit` remains compatible
with a historical `--block-height`, but the submission now commits to the epoch
checkpoint root and range that height finalizes up to. This is the mechanism
that lets one Monero transaction amortize many L2 blocks while still giving
watchtowers a small root to verify against DA and block headers.
Mainnet readiness must also include anchor-capacity evidence: a signed benchmark
root proving the fixed-format payload can commit at least 10,000 L2 transactions
per anchor, with the capacity policy, payload-shape root, observed epoch count,
and benchmark root bound into the release-candidate run.

The `settlement` command gives wallets a single finality surface for a block. It
reports whether the block has L2 soft finality, which local epoch checkpoint root
contains it, whether any submitted Monero anchor covers that checkpoint range,
and whether a covering anchor has reached the configured Monero finality depth.
The status ladder is `produced`, `soft_final`, `anchored`, and `monero_final`.

Public L2 state should expose only `monero_txid_hash`, not the raw Monero txid.
The raw txid can remain in operator-local or devnet state for auditing and
tests. Confirmation updates are committed through an `anchor_submission_root`
separate from historical block headers, so Monero settlement metadata can evolve
without mutating past L2 state roots.

The Monero base chain cannot validate this root by itself. Watchtowers, wallets,
and L2 nodes validate roots by downloading DA data and replaying or verifying
the L2 state transition.

## Bridge Design

### Deposits

1. Wallet asks bridge coordinators for a one-time Monero deposit address.
2. User sends XMR on Monero.
3. Bridge signers scan with view keys and wait for confirmation depth.
4. A threshold of the active bridge signer set signs a deposit attestation.
5. L2 mints wrapped XMR to a shielded note after threshold attestation.

Deposit privacy requirements:

- Use one-time deposit addresses.
- Batch attestations.
- Avoid publishing deposit amount/address mappings on L2.
- Let users delay minting to avoid tight timing links.

### Withdrawals

1. User burns wrapped XMR on L2 to a withdrawal note.
2. The bridge creates a Monero transaction to the requested address.
3. Threshold bridge signers authorize the spend after the challenge window.
4. Watchtowers confirm inclusion and close the L2 withdrawal record.

The devnet models that lifecycle with `bridge-withdraw-release`,
`bridge-withdraw-confirm`, `bridge-signers`, and `bridge-signer-rotate`. A
queued withdrawal records the note nullifier, amount, recipient address hash,
fee, request height, queue signer-set id, queue threshold, queue signer count,
and queue signature root. A release records only the hash of the Monero
withdrawal txid, the active release signer-set id, a threshold signer count,
and a signature root. Confirmation updates move the public status from `queued`
to `submitted` to `completed` once the configured Monero finality depth is
reached.

Bridge deposits and releases are authorized by an explicit `BridgeSignerSet`.
The devnet starts with a signed 2-of-3 post-quantum signer set, commits every
signer set to `bridge_root`, and rejects deposit observations or release
attempts from labels outside the active set or below threshold. Deposit
observations publish the signer-set id, signer threshold, signer count, and
attestation root; wrapped-XMR mint transactions bind the same signer-set
metadata into their bridge signature root. Rotations retire the prior set, sign
the new set with a guardian transcript, publish a public key root over the
signer labels, and update the active signer-set id. This is still a devnet
threshold model, but it keeps bridge authorization tied to a committed,
rotatable PQ signer policy instead of ad hoc signer labels.

Queued withdrawals also carry an amount bucket and a `release_not_before_height`.
The devnet enforces a short deterministic privacy delay before release signing,
so operators cannot immediately mirror an L2 burn with a Monero spend. This is a
small stand-in for production batching, randomized delay windows, and amount
bucket policies.

Watchtowers can publish `BridgeWithdrawalChallenge` holds with
`bridge-withdraw-challenge`. The challenge record commits to the withdrawal id,
nullifier, amount bucket, challenge type, hashed evidence root, reporter label,
report height, and hold height. Raw evidence text is not stored in the public
record. While the hold is active, release signing is blocked; after the hold
height, signers can release or continue emergency procedures based on their
policy. This gives bridge operators a privacy-preserving intervention path for
reserve concerns, address-risk screening, amount-linkability review, or signer
policy review.

The devnet also tracks a simple per-height withdrawal release cap. `bridge`
and `bridge-rate-limit` report the release amount limit, amount already released
at the current L2 height, remaining capacity, and released withdrawal ids. This
is not a production liquidity controller yet, but it models the public queue
accounting needed to slow exit bursts and give watchtowers time to react before
large amounts leave bridge custody.

The `bridge-reserve-report` command publishes a public proof-of-reserve style
attestation without exposing raw reserve addresses. The devnet computes
liabilities from state as circulating wrapped XMR plus queued and submitted
withdrawals that have burned on L2 but have not completed on Monero. Reporters
sign the reserve amount, reserve-address hash, liability totals, coverage basis
points, and healthy or underreserved status. Completed withdrawals are tracked
separately so auditors can reconcile historical outflows without counting them
as current liabilities.

The Rust bridge state now owns signed reserve reports and withdrawal challenge
evidence directly. `BridgeState::reserve_snapshot` derives deposited,
released, completed, queued, submitted, and liability totals from local bridge
records; `publish_reserve_report` signs a bucketed reserve amount against the
active bridge signer set and commits it into `bridge_reserve_report_root`.
Withdrawal release reorg evidence is signed by bridge/watchtower reporters and
committed into `bridge_withdrawal_challenge_root`, so the bridge root can change
when a Monero-side release becomes disputed.

The `bridge-pause` and `bridge-resume` commands publish operator-signed
emergency actions with hashed reason text and a threshold PQ bridge signer
quorum root. Each action commits to the active signer set id, threshold, signer
count, effective height, and pause or resume intent. While paused, the devnet
rejects new deposit addresses, bridge mint submissions, wrapped-XMR
withdrawals, withdrawal release signing, and execution of already pending bridge
mint or withdrawal transactions. Deposit observation, Monero confirmation
updates, and reserve reports remain available so operators can keep publishing
facts during an incident.

### Bridge Trust Levels

Phase 0 is federated and threshold-custodial. It can be useful, but it is not
fully trustless.

Phase 1 adds staked bridge signers, slashing, independent watchtowers, public
proof-of-reserve reports, and withdrawal rate limits.

Phase 2 requires deeper Monero-side support or new cryptographic construction
to make bridge exits trust-minimized without sacrificing Monero privacy.

## Data Availability

Every L2 block body is erasure coded and distributed across the DA network.
Validators sign availability attestations before finalizing an epoch.

The devnet models this with deterministic DA records for every produced block.
Each record stores data shards, parity shards, a shard root, and ML-DSA-shaped
validator attestations over the DA payload hash. The block header commits to the
record through `da_root`, and the CLI can sample individual shards. This is not
production erasure coding, but it makes the settlement invariant explicit:
watchers should refuse an anchor if the corresponding L2 block payload is not
available.

Every produced devnet block also receives a `BlockValidityCertificate`. This is
not a production proof, but it is shaped like the future prover artifact: it
hashes the public state-transition inputs, binds the previous and new state
roots, `tx_root`, `da_root`, execution profile, validator set, and PQ vote root,
then signs the certificate with an ML-DSA-shaped prover transcript. Watchtowers
can inspect these records through `validity`; epoch checkpoints include a
`validity_root` so Monero anchors commit to the execution proof surface as well
as the data-availability and state roots.

Blocks also receive a `BlockPrivacyProofAggregate`. The aggregate lists only
public proof metadata for each proved transaction: transaction index, transaction
kind, public transaction hash, proof system, public-input hash, and proof root.
It deliberately omits private witness hashes and wallet labels. The validity
certificate commits to the aggregate root and aggregate proof root, and
watchtowers can inspect the surface through `proofs` without replaying private
witnesses.

Watchtowers can publish `BlockWatchtowerAuditReport` receipts with
`audit-block`. A receipt signs the block hash, state root, DA root, bridge root,
mempool admission root, validity certificate root, privacy-proof aggregate root,
and a Merkle root over sampled DA shard metadata. It is a positive availability
and proof-coverage receipt, not a private payload dump: sampled shards are
committed by hash and byte size in the report.

If a proof artifact is missing from local state, or an outside peer serves a
root that conflicts with the canonical block header, a watchtower can publish
`BlockChallengeReport` evidence with `challenge-block`. Missing local DA,
validity-certificate, or privacy-aggregate artifacts are slashable proposer
faults in the devnet. External conflicts such as a bridge-root mismatch are
recorded as disputes without slashing the local proposer, which lets bridge
operators and light clients quarantine inconsistent data without pretending the
canonical chain proved local misconduct.

Wallets and light clients need:

- L2 headers.
- Validator signatures.
- DA sampling responses.
- Relevant encrypted note payloads.
- Merkle paths for their notes and nullifiers.

DA commitments must avoid pairing-based KZG if quantum resistance is a hard
requirement. Prefer hash-based Merkle commitments first. Research transparent
post-quantum polynomial commitment options only after the basic network works.

## Core Data Structures

```text
L2BlockHeader {
  version
  chain_id
  height
  epoch
  prev_block_hash
  tx_root
  mempool_admission_root
  mempool_admission_count
  state_root
  note_root
  nullifier_root
  contract_root
  wasm_runtime_root
  account_root
  asset_root
  bridge_root
  da_root
  fee_root
  crypto_policy_root
  execution_profile {
    target_block_ms
    tx_count
    privacy_proof_count
    contract_call_count
    execution_fuel
    uncompressed_da_bytes
    batched_da_bytes
    amortized_da_bytes_per_tx
    estimated_proof_bytes
    authorization_count
    estimated_authorization_bytes
    observed_fee_units
    fee_asset_count
    fee_density_microunits
    batch_discount_bps
    local_fee_market_root
    local_fee_lane_count
    max_local_fee_density_microunits
  }
  proposer_id
  validator_set_root
  pq_vote_root
  validator_vote_count
  validator_stake_weight
  soft_finality
}

AccountRegistry {
  account_root
  account_rotation_root
  wallet_session_root
  retired_signer_labels_state
}

LocalFeeMarketLane {
  lane_id
  lane_type
  lane_key
  tx_count
  execution_fuel
  uncompressed_da_bytes
  batched_da_bytes
  observed_fee_units
  privacy_proof_count
  contract_call_count
  fee_density_microunits
}

PerformanceBenchmarkRun {
  benchmark_id
  scenario
  measured_at_height
  measured_at_ms
  include_pending
  benchmarker_label
  profile_root
  fee_curve_root
  local_fee_market_root
  confirmed_summary
  pending_summary
  latency_targets
  fee_curve
  benchmark_root
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

PerformanceCalibrationRecord {
  calibration_id
  source_benchmark_id
  calibrated_at_height
  calibrated_at_ms
  calibrator_label
  measured_proof_bytes
  measured_authorization_bytes
  measured_da_encoded_bytes
  measured_contract_runtime_ms
  measured_prover_ms
  measured_signer_ms
  measured_total_latency_ms
  estimated_proof_bytes
  estimated_authorization_bytes
  estimated_da_encoded_bytes
  estimated_execution_fuel
  estimated_privacy_proof_count
  estimated_authorization_count
  estimated_contract_call_count
  target_latency_ms
  proof_size_multiplier_bps
  authorization_size_multiplier_bps
  da_bandwidth_multiplier_bps
  contract_runtime_micros_per_fuel
  prover_micros_per_proof
  signer_micros_per_authorization
  target_latency_delta_ms
  calibrated_summary_root
  calibration_root
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

CryptoPolicy {
  policy_id
  policy_version
  crypto_policy_root
  suites {
    role
    scheme
    standard
    devnet_domain
    status
  }
}

L2Transaction {
  version
  chain_id
  domain
  fee_policy
  encrypted_payload
  public_inputs
  proof_bundle {
    proof_system
    public_input_hash
    proof_root
  }
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

FeeQuote {
  operation
  input_count
  output_count
  fee_mode
  fee_asset_id
  target_block_ms
  target_inclusion_blocks
  estimated_inclusion_ms
  candidate_profile
  pending_profile
  projected_profile
  marginal_uncompressed_da_bytes
  marginal_batched_da_bytes
  marginal_batch_savings_bps
  minimum_fee_units
  recommended_fee_units
  fast_fee_units
  congestion_multiplier_bps
  quote_hash
}

ViewKeyDisclosure {
  disclosure_id
  audience_label
  owner_commitment
  asset_id
  disclosed_at_height
  expires_at_height
  note_count
  note_commitment_root
  asset_totals
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

ContractStorageDisclosure {
  disclosure_id
  audience_label
  contract_id
  owner_commitment
  storage_root
  disclosed_at_height
  expires_at_height
  path_count
  opening_root
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

WalletHistory {
  owner_commitment
  height
  event_count
  current_notes
  current_totals
  received_totals
  spent_totals
  fee_totals
  unindexed_current_note_count
  events
  history_root
}

MempoolAdmission {
  admission_id
  mempool_sequence
  tx_public_hash
  encrypted_payload_hash
  committee_key_id
  kem_ciphertext_hash
  relay_path_policy
  relay_path_hop_count
  relay_path_commitment
  admitted_at_height
  expires_at_height
  sequencer_label
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

MempoolPreconfirmation {
  preconfirmation_id
  admission_id
  tx_public_hash
  encrypted_payload_hash
  target_height
  expires_at_height
  preconfirmed_at_height
  sequencer_label
  promised_mempool_root
  promised_pending_tx_count
  local_fee_market_root
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

MempoolPreconfirmationMissEvidence {
  evidence_id
  preconfirmation_id
  admission_id
  tx_public_hash
  encrypted_payload_hash
  target_height
  reported_at_height
  sequencer_label
  reporter_label
  missed_block_count
  penalty_units
  preconfirmation_auth_transcript_hash
  preconfirmation_auth_signature
  slashed_validator_id
  slashed_amount
  validator_stake_after
  status
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

MempoolOmissionEvidence {
  evidence_id
  admission_id
  tx_public_hash
  encrypted_payload_hash
  committee_key_id
  kem_ciphertext_hash
  relay_path_policy
  relay_path_hop_count
  relay_path_commitment
  admitted_at_height
  expires_at_height
  reported_at_height
  sequencer_label
  reporter_label
  missed_block_count
  penalty_units
  admission_auth_transcript_hash
  admission_auth_signature
  slashed_validator_id
  slashed_amount
  validator_stake_after
  status
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

MempoolForcedInclusion {
  forced_inclusion_id
  evidence_id
  admission_id
  tx_public_hash
  old_encrypted_payload_hash
  new_admission_id
  new_encrypted_payload_hash
  new_committee_key_id
  new_kem_ciphertext_hash
  new_relay_path_policy
  new_relay_path_hop_count
  new_relay_path_commitment
  forced_at_height
  sequencer_label
  reporter_label
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

MempoolAdmissionStatus {
  status
  admission_id
  current_height
  admission
  block_height
  block_hash
  da_root
  settlement
  evidence
  forced_inclusion_count
  forced_inclusions
  preconfirmations
  preconfirmation_miss_evidence
  mempool_preconfirmation_root
  mempool_preconfirmation_miss_root
  mempool_admission_root
  mempool_omission_evidence_root
  mempool_forced_inclusion_root
}

Validator {
  validator_id
  label
  stake
  consensus_public_key
  network_public_key
  status
  slashed_stake
  omission_count
  preconfirmation_miss_count
  block_challenge_count
}

WalletSession {
  session_id
  account_id
  wallet_network_public_key
  node_committee_key_id
  node_network_root
  relay_path_policy
  relay_path_hop_count
  relay_path_commitment
  opened_at_height
  expires_at_height
  account_rotation_nonce
  kem_ciphertext_hash
  session_transcript_hash
  status
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

PrivateTransferBatch {
  input_count
  nullifiers
  output_commitments
  fee
  encrypted_payload_hash
  proof_bundle
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

AnchorSubmission {
  anchor_id
  block_height
  epoch
  anchor_commitment
  checkpoint_root
  epoch_start_height
  epoch_end_height
  epoch_block_count
  block_hash
  state_root
  bridge_root
  submitter_label
  monero_txid_hash
  confirmations
  status
  submitted_at_ms
  finalized_at_ms
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

EpochCheckpoint {
  epoch
  start_height
  end_height
  block_count
  complete
  block_hash_root
  tx_root
  state_root
  da_root
  validity_root
  privacy_proof_aggregate_root
  bridge_root
  mempool_admission_root
  validator_set_root
  soft_finality_count
  checkpoint_root
}

BlockValidityCertificate {
  block_height
  block_hash
  prev_block_hash
  previous_state_root
  state_root
  tx_root
  da_root
  execution_profile_hash
  privacy_proof_aggregate_root
  privacy_proof_aggregate_proof_root
  public_input_hash
  proof_system
  proof_root
  prover_label
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

BlockPrivacyProofAggregate {
  block_height
  block_hash
  tx_root
  privacy_proof_count
  proof_item_root
  proof_system_root
  aggregate_public_input_hash
  aggregate_proof_system
  aggregate_proof_root
  proof_items [
    tx_index
    tx_kind
    tx_public_hash
    proof_system
    public_input_hash
    proof_root
  ]
  aggregate_root
}

BlockWatchtowerAuditReport {
  audit_id
  block_height
  block_hash
  tx_root
  state_root
  da_root
  bridge_root
  mempool_admission_root
  validity_certificate_root
  privacy_proof_aggregate_root
  sampled_shard_indices
  sampled_shard_root
  sampled_shard_count
  sampled_encoded_bytes
  audit_status
  watchtower_label
  created_at_ms
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

BlockChallengeReport {
  challenge_id
  block_height
  block_hash
  challenge_type
  expected_root
  observed_root
  evidence_root
  reporter_label
  reported_at_height
  challenged_validator_id
  penalty_units
  slashed_amount
  validator_stake_after
  status
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

SettlementStatus {
  status
  block_height
  epoch
  block_hash
  soft_finality
  validator_vote_count
  validator_stake_weight
  checkpointed
  local_checkpoint_root
  local_checkpoint
  anchored
  monero_final
  best_anchor
  covering_anchor_count
  covering_anchors
  anchor_submission_root
}

TransactionStatus {
  status
  inclusion_status
  current_height
  tx_public_hash
  mempool_tx_public_hash
  tx_kind
  transaction
  pending_index
  mempool_admission
  preconfirmations
  block_height
  tx_index
  block_hash
  tx_root
  state_root
  da_root
  validity_certificate_root
  privacy_proof_aggregate_root
  privacy_proof_item
  settlement
}

NoteCommitment {
  asset_commitment
  amount_commitment
  owner_commitment
  spend_policy_hash
  blinding
}

Asset {
  asset_id
  symbol
  issuer_policy
  supply_policy
  privacy_class
  metadata_hash
  max_supply
}

AssetSupply {
  asset_id
  minted_amount
  burned_amount
  circulating_amount
}

AssetMint {
  asset_id
  amount
  mint_id
  output_commitment
  proof_system
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

AssetBurn {
  asset_id
  amount
  nullifier
  terms_hash
  output_commitments
  proof_bundle
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

BridgeDepositObservation {
  deposit_id
  monero_txid_hash
  amount
  confirmations
  signer_set_id
  signer_threshold
  signer_count
  attestation_root
  status
}

BridgeMint {
  deposit_id
  monero_txid_hash
  amount
  output_commitment
  attestation_root
  bridge_signature_root
  signer_set_id
  signer_threshold
  signer_count
  proof_system
}

BridgeWithdrawalRecord {
  withdrawal_id
  nullifier
  amount
  monero_address_hash
  bridge_fee
  status
  bridge_signature_root
  queue_signer_set_id
  queue_signer_threshold
  queue_signer_count
  requested_at_height
  amount_bucket
  privacy_delay_blocks
  release_not_before_height
  release_monero_txid_hash
  release_signer_count
  release_signer_set_id
  release_signature_root
  release_confirmations
  released_at_height
  released_at_ms
  completed_at_ms
}

BridgeSignerSet {
  signer_set_id
  epoch
  threshold
  signer_labels
  signer_public_key_root
  active_from_height
  retired_at_height
  status
  rotation_id
  operator_label
  signer_count
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

BridgeWithdrawalChallenge {
  challenge_id
  withdrawal_id
  nullifier
  amount_bucket
  challenge_type
  evidence_root
  reporter_label
  reported_at_height
  hold_until_height
  status
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

BridgeReserveReport {
  report_id
  reserve_asset_id
  reserve_address_hash
  reported_reserve_amount
  circulating_amount
  queued_withdrawal_amount
  submitted_withdrawal_amount
  completed_withdrawal_amount
  outstanding_liability
  surplus_amount
  coverage_bps
  status
  reporter_count
  attestation_root
  reported_at_height
  reported_at_ms
}

BridgeEmergencyAction {
  action_id
  action
  paused
  reason_hash
  operator_label
  effective_height
  created_at_ms
  emergency_signer_set_id
  emergency_signer_threshold
  emergency_signer_count
  emergency_signature_root
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

AmmPool {
  pool_id
  asset_a_id
  asset_b_id
  lp_asset_id
  reserve_a
  reserve_b
  total_lp
  fee_bps
  curve
}

AmmBatchSwap {
  pool_id
  input_count
  nullifiers
  asset_in_id
  asset_out_id
  amount_ins
  total_amount_in
  total_amount_out
  output_commitments
  network_fee
  proof_bundle
}

AmmRouteSwap {
  pool_ids
  route_hop_count
  route_root
  nullifier
  asset_path
  hop_amounts
  asset_in_id
  asset_out_id
  amount_in
  amount_out
  output_commitments
  network_fee
  proof_bundle
}

DarkPoolSwap {
  trade_commitment
  nullifier_a
  nullifier_b
  output_commitments
  encrypted_payload_hash
  proof_bundle
  auth_a_scheme
  auth_a_public_key
  auth_a_transcript_hash
  auth_a_signature
  auth_b_scheme
  auth_b_public_key
  auth_b_transcript_hash
  auth_b_signature
}

SealedAmmBatchSwap {
  pool_id
  intent_count
  intent_root
  nullifiers
  asset_in_id
  asset_out_id
  total_amount_in
  total_amount_out
  network_fee_total
  commitment_count
  commitment_root
  output_commitments
  solver_bid_id
  solver_commitment
  proof_bundle
}

SealedSwapOrderCommitment {
  commitment_id
  pool_id
  asset_in_id
  asset_out_id
  order_commitment
  owner_commitment
  min_reveal_height
  expires_height
  status
  revealed_intent_hash
  revealed_at_height
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

SealedSwapSolverBid {
  bid_id
  pool_id
  solver_label
  batch_commitment_root
  asset_in_id
  asset_out_id
  total_amount_in
  quoted_amount_out
  network_fee_total
  expires_height
  status
  settled_tx_public_hash
  settled_at_height
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

SealedSwapSettlementReceipt {
  receipt_id
  block_height
  tx_public_hash
  pool_id
  solver_label
  solver_bid_id
  intent_count
  intent_root
  route_commitment
  asset_in_id
  asset_out_id
  total_amount_in
  total_amount_out
  network_fee_total
  pool_fee_bps
  pool_curve
  pool_before_root
  pool_after_root
  pool_before_reserve_in
  pool_before_reserve_out
  pool_after_reserve_in
  pool_after_reserve_out
  fill_commitment_root
  minimum_output_root
  surplus_commitment_root
  total_surplus_amount
  clearing_price_numerator
  clearing_price_denominator
  clearing_price_commitment_root
  aggregate_surplus_commitment_root
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

DataAvailabilityRecord {
  block_height
  tx_root
  payload_hash
  da_root
  shard_root
  attestation_root
  original_shard_count
  parity_shard_count
  original_bytes
  encoded_bytes
  attestations
}

LendingMarket {
  market_id
  collateral_asset_id
  debt_asset_id
  collateral_factor_bps
  liquidation_threshold_bps
  oracle_feed_id
  total_collateral
  total_debt
  status
}

OraclePriceFeed {
  feed_id
  base_asset_id
  quote_asset_id
  price_numerator
  price_denominator
  confidence_bps
  round_id
  published_at_height
  attestation_root
  attestation_count
}

LendingPosition {
  position_id
  market_id
  owner_commitment
  collateral_asset_id
  debt_asset_id
  collateral_commitment
  debt_commitment
  status
}

LendingBorrow {
  market_id
  nullifier
  position_id
  terms_hash
  output_commitments
  proof_bundle
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

LendingRepay {
  position_id
  nullifier
  terms_hash
  output_commitments
  proof_bundle
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

LendingLiquidation {
  position_id
  nullifier
  liquidator_commitment
  terms_hash
  output_commitments
  proof_bundle
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

Contract {
  contract_id
  template
  code_hash
  owner_label
  private_storage
  storage                  // omitted from public records when private_storage=true
  storage_root
  storage_commitment
  asset_balances
  asset_balance_root
  fuel_limit
  version
}

VaultAllowance {
  allowance_key
  asset_id
  beneficiary_commitment
  amount
  allowance_commitment
}

ContractEvent {
  event_id
  contract_id
  event_name
  event_index
  tx_hash
  emitted_at_height
  contract_storage_root
  data_hash
  previous_event_root
  event_chain_root
  public_data {
    caller_commitment
  }
}

ContractExecutionReceipt {
  receipt_id
  runtime
  tx_hash
  contract_id
  template
  code_hash
  contract_version
  entrypoint
  call_index
  block_height
  tx_index
  args_commitment
  private_args
  caller_commitment
  fuel_limit
  fuel_used
  storage_root_before
  storage_root_after
  event_id
  event_chain_root
}

ContractEventDisclosure {
  disclosure_id
  audience_label
  event_id
  contract_id
  event_name
  tx_hash
  data_hash
  emitted_at_height
  expires_at_height
  caller_commitment
  args_commitment
  opening_root
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

GovernorProposal {
  proposal_id
  proposal_index
  description_hash
  action_hash
  proposer_commitment
  start_height
  end_height
  yes_weight
  no_weight
  quorum
  status
  outcome
  executed_at_height
  voter_commitments
}

ContractUpgradeProposal {
  proposal_id
  contract_id
  template
  current_version
  proposed_version
  current_code_hash
  proposed_code_hash
  current_fuel_limit
  proposed_fuel_limit
  proposer_label
  proposed_at_height
  executable_at_height
  status
  executed_at_height
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

Paymaster {
  paymaster_id
  contract_id
  fee_asset_id
  sponsor_commitment
  policy_hash
  per_call_cap
  per_caller_cap
  allowed_caller_commitments
  replenish_threshold
  replenish_target
  relayer_reward_units
  relayer_reward_budget
  balance
  spent_amount
  spent_by_caller
  deposit_count
  status
  paused_reason_hash
  last_governance_action_id
}

PaymasterGovernanceAction {
  action_id
  action_nonce
  paymaster_id
  action
  sponsor_commitment
  previous_status
  new_status
  previous_policy_hash
  new_policy_hash
  reason_hash
  per_call_cap
  per_caller_cap
  allowed_caller_commitments
  replenish_threshold
  replenish_target
  relayer_reward_units
  relayer_reward_budget
  refund_amount
  refund_note_commitment
  effective_height
  created_at_ms
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

PaymasterRefillAuthorization {
  authorization_id
  authorization_nonce
  paymaster_id
  fee_asset_id
  note_commitment
  max_refill_amount
  sponsor_commitment
  relayer_commitment
  policy_hash
  expires_at_height
  created_at_height
  status
  used_at_height
  deposit_tx_hash
  failure_receipt_id
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

PaymasterRefillFailureReceipt {
  receipt_id
  authorization_id
  paymaster_id
  relayer_commitment
  reporter_commitment
  reason_code
  evidence_hash
  authorization_expires_at_height
  reported_at_height
  challenge_deadline_height
  reported_at_ms
  status
  challenge_id
  slashing_hook_id
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

PaymasterRefillFailureChallenge {
  challenge_id
  receipt_id
  authorization_id
  paymaster_id
  relayer_commitment
  evidence_hash
  challenged_at_height
  challenged_at_ms
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

PaymasterRelayerSlashingHook {
  hook_id
  receipt_id
  authorization_id
  paymaster_id
  relayer_commitment
  reporter_commitment
  penalty_units
  challenge_deadline_height
  slashed_at_height
  slashed_at_ms
  status
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

PaymasterRelayerBond {
  bond_id
  bond_nonce
  relayer_commitment
  asset_id
  note_commitment
  nullifier
  amount
  active_amount
  slashed_amount
  withdrawn_amount
  slash_count
  bonded_at_height
  bonded_at_ms
  change_note_commitment
  status
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

PaymasterRelayerUnbondRequest {
  request_id
  bond_id
  relayer_commitment
  asset_id
  requested_amount
  available_at_height
  requested_at_height
  requested_at_ms
  claimed_amount
  claim_note_commitment
  claimed_at_height
  status
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

PaymasterRelayerSlashSettlement {
  settlement_id
  hook_id
  receipt_id
  authorization_id
  paymaster_id
  relayer_commitment
  reporter_commitment
  asset_id
  penalty_units
  slashed_amount
  remaining_penalty_units
  bond_deltas[]
  settled_at_height
  settled_at_ms
  status
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

PaymasterRelayerRewardReceipt {
  reward_id
  authorization_id
  paymaster_id
  relayer_commitment
  fee_asset_id
  refill_amount
  reward_units
  budget_units_before
  budget_units_after
  reward_budget
  budget_proof_root
  claimed_amount
  claim_note_commitment
  claimed_at_height
  claim_bundle_id
  claim_proof_root
  status
  deposit_tx_hash
  rewarded_at_height
  rewarded_at_ms
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

PaymasterRelayerRewardClaimBundle {
  bundle_id
  bundle_nonce
  relayer_commitment
  fee_asset_id
  reward_ids
  claim_note_commitments
  total_claimed_amount
  claimed_at_height
  expires_at_height
  inclusion_deadline_height
  requote_after_height
  requote_backoff_blocks
  requote_backoff_score
  claimed_at_ms
  claim_count
  max_bundle_size
  estimated_fee_units
  estimated_proof_bytes
  estimated_da_bytes
  quote_root
  bundle_proof_root
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

PaymasterRelayerRewardQuoteInvalidationReport {
  report_id
  report_nonce
  quote_root
  relayer_commitment
  fee_asset_id
  reward_ids
  total_claimed_amount
  claim_count
  claimed_at_height
  expires_at_height
  inclusion_deadline_height
  requote_after_height
  requote_backoff_blocks
  requote_backoff_score
  max_bundle_size
  estimated_fee_units
  estimated_proof_bytes
  estimated_da_bytes
  invalidated_at_height
  reason_code
  observed_reward_statuses
  observed_reward_status_root
  settled_bundle_id
  reporter_commitment
  reported_at_ms
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

PaymasterDeposit {
  paymaster_id
  nullifier
  amount
  terms_hash
  refill_authorization_id
  refill_relayer_commitment
  output_commitments
  proof_bundle
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

ContractCall {
  contract_id
  entrypoint
  args                   // omitted from public records when private_args=true
  private_args
  args_commitment
  fuel_limit
  fuel_used
  fee_asset_id
  fee
  fee_nullifier
  fee_change_commitment
  paymaster_id
  proof_bundle
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

ContractCallBatch {
  call_count
  call_root
  calls[]                // each call follows ContractCall args privacy rules
  total_fuel_used
  fee_asset_id
  fee
  fee_nullifier
  fee_change_commitment
  paymaster_id
  proof_bundle
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

ContractDeposit {
  contract_id
  nullifier
  asset_id
  amount
  network_fee
  terms_hash
  output_commitments
  proof_bundle
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}

ContractWithdraw {
  contract_id
  asset_id
  amount
  network_fee
  output_commitment
  recipient_commitment
  auth_scheme
  auth_public_key
  auth_transcript_hash
  auth_signature
}
```

## Wallet Requirements

The wallet is part of the privacy protocol, not just a signing client.

It must:

- Generate post-quantum account keys.
- Keep separate spend, view, recovery, and network keys.
- Scan encrypted note payloads.
- Recover confirmed and pending wallet history from view keys and DA payloads.
- Build shielded spends.
- Estimate fee and privacy costs.
- Route through privacy-preserving relays by default.
- Verify relay-path commitments without exposing exact route strings in public
  receipts.
- Support scoped signed view-key disclosure.
- Warn when bridge timing or amount patterns are linkable.

## Implementation Roadmap

### Milestone 0: Specification And Threat Model

- Keep this document updated.
- Write a formal threat model for users, validators, bridge signers, solvers,
  DA nodes, and passive network observers.
- Choose exact PQ parameter sets and transcript domains.

### Milestone 1: Local Devnet

- Build a standalone `nebulad-l2` devnet service.
- Connect to `monerod` through existing RPC/ZMQ interfaces.
- Produce local L2 blocks.
- Add Rust local sequencer orchestration for encrypted admission,
  preconfirmation, integrated state-root block production, status, wallet
  scans, and Monero-style epoch anchors.
- Persist and verify encrypted mempool admission receipts with public relay-path
  commitments and state-only exact route replay.
- Issue encrypted mempool preconfirmation receipts for fast inclusion promises.
- Report missed preconfirmation targets as public evidence and slash the
  sequencer without evicting the still-pending encrypted transaction.
- Report expired encrypted mempool admissions as public omission evidence and
  slash the registered sequencer stake.
- Requeue omitted encrypted admissions with active-sequencer forced-inclusion
  receipts while keeping private payloads out of public evidence.
- Expose wallet-facing admission status for pending, included, and omitted
  encrypted transactions.
- Commit DA records and validator availability attestations for each block.
- Commit block validity certificates for state-transition verification.
- Commit block privacy-proof aggregates into validity certificates and epoch
  checkpoints.
- Publish watchtower block audit receipts over DA samples, validity
  certificates, privacy-proof aggregates, bridge roots, and mempool roots.
- Report missing block proof artifacts or conflicting external roots as signed
  watchtower challenge evidence.
- Submit and confirm dummy epoch anchors on stagenet or regtest.
- Add explicit epoch checkpoint roots for one-anchor-per-epoch settlement.
- Expose wallet-facing settlement status for soft-final, anchored, and
  Monero-final blocks.
- Track bridge withdrawal release and confirmation lifecycle without exposing
  raw Monero recipient addresses or release txids.
- Enforce committed post-quantum bridge signer sets, quorum checks, and signed
  signer rotation for withdrawal releases.
- Enforce a bridge withdrawal release delay with public amount-bucket metadata
  for exit privacy.
- Add signed bridge withdrawal challenge holds for watchtower intervention
  before release signing.
- Expose per-height bridge withdrawal release rate-limit accounting.
- Publish public bridge reserve reports against wrapped-XMR and incomplete
  withdrawal liabilities.
- Add threshold-signed bridge emergency pause/resume controls for incident
  response.
- Add a CLI wallet that can create accounts and submit test transfers.
- Add read-only fee quotes for wallet cost estimation and fast inclusion.
- Expose local fee-market lanes for pending blocks and finalized DeFi resources.

### Milestone 2: Post-Quantum Accounts

- Add ML-DSA account signatures.
- Add SLH-DSA recovery keys.
- Scaffold account registry roots and recovery-signed key rotation in Python
  and Rust.
- Scaffold ML-KEM-shaped wallet-to-node sessions in Python and Rust.
- Implement typed transcript hashing.
- Add crypto-agility tests and test vectors.
- Expose a committed `crypto_policy_root` and deterministic devnet crypto
  policy vectors through CLI, snapshots, persisted state, and block headers.

### Milestone 3: Native Assets

- Implement mint/burn and fixed-supply assets with issuer authorization.
- Add asset supply roots and supply accounting.
- Add fixed-supply cap enforcement for current and pending mints.
- Implement shielded note commitments.
- Implement nullifier checks.
- Add wrapped-XMR accounting without live bridge custody.

### Milestone 4: Deterministic Wasm Contracts

- Replace deterministic template execution receipts with metered Wasm execution.
- Add native asset host functions.
- Add contract storage.
- Add native asset escrow deposits and withdrawals for contracts.
- Add AMM and sealed-bid swap examples.
- Add multi-user intent settlement tests for private DeFi batching.
- Add private multi-hop AMM route swaps with one proof and one fee across
  multiple pools.
- Add private dark-pool atomic swaps with two PQ authorizations and hidden raw
  trade terms.
- Add private collateralized lending examples with public risk parameters.
- Add PQ-attested oracle feeds for lending collateral valuation.
- Add oracle-backed private lending liquidation tests.
- Add signed sealed-swap order commitments with reveal windows and public
  commitment roots for large-order MEV control.
- Add PQ-signed sealed-swap solver bids with best-bid enforcement and public
  won/lost settlement state.
- Add Rust sealed AMM batch execution with solver-signed settlement receipts,
  surplus/clearing-price commitments, and block-committed receipt roots.
- Add sealed-auction expiry sweeps for unrevealed commitments and stale solver
  bids, including inclusion-time expiry checks for pending reveals.
- Add stable-asset AMM pools with curve-bound receipts and private-note swaps.
- Add owner-signed timelocked contract upgrade proposals for version, code hash,
  and fuel-limit governance.
- Add a governor template with committed DAO proposals, PQ-signed votes, quorum
  checks, duplicate-vote prevention, and execution events.

### Milestone 5: Privacy Proofs

- Replace deterministic devnet proof bundles with audited ZK proof systems.
- Implement transfer privacy proofs.
- Implement private fee notes.
- Implement private batch transfer proofs for wallet consolidation and
  low-fee payouts.
- Add wallet scanning and view-key disclosure.
- Add wallet history recovery from confirmed blocks, pending transactions, and
  current state notes.
- Add signed scoped disclosure exports with expiry and note-root verification.
- Add block-level privacy-proof aggregates so validators and watchtowers can
  audit proof coverage from public roots.
- Add batch auction privacy for swaps.

### Milestone 6: Bridge Testnet

- Replace the devnet one-time deposit address service with wallet/RPC-backed
  Monero address derivation.
- Replace devnet threshold bridge signer attestations with live Monero
  wallet/RPC-backed observation infrastructure.
- Replace devnet threshold withdrawal queue signatures with live threshold
  withdrawal construction and signing.
- Replace devnet reserve reports with live wallet/RPC-backed proof-of-reserve
  attestations.
- Replace devnet threshold-signed incident governance with live operational
  runbooks and withdrawal queue rate limits.

### Milestone 7: Adversarial Testnet

- Run validator, bridge, DA, and solver fault-injection tests.
- Extend signed devnet performance benchmark runs with adversarial latency,
  throughput, proof-size, bandwidth, and fee-curve workloads.
- Extend signed calibration records against live prover, signer, DA, and
  contract-runtime benchmark harnesses.
- Bind adversarial campaign evidence to the release-candidate run by declaring
  covered block count, validator count, and local quorum-certificate finality
  target, with a coverage root committed into the adversarial transcript.
- Commission external review before mainnet value is accepted.

## Minimum Viable Product

The smallest useful MVP is:

- Standalone L2 devnet.
- ML-DSA signed accounts.
- Shielded native notes for a test asset.
- 1 second L2 blocks.
- Fixed-format Monero stagenet anchor commitments with confirmation tracking.
- Native token mint/burn.
- One AMM contract.
- CLI wallet with view-key scanning.
- No mainnet bridge custody.

This MVP proves the execution, privacy, fee, and anchoring design before risking
real XMR.

## Non-Goals For Version 1

- Replacing Monero consensus.
- Adding arbitrary smart contracts to Monero L1.
- Mainnet bridge custody before adversarial testing.
- Pairing-based proof systems as core security assumptions.
- Transparent-by-default accounts.
- Perfect MEV elimination.

## Open Research Questions

- Which transparent post-quantum proof system has acceptable proof size and
  prover cost for private transfers and private DeFi?
- Can bridge exits become meaningfully trust-minimized without Monero L1 script
  support?
- What is the best privacy-preserving DA sampling design for light wallets?
- How should slashing work when validator identities are privacy-sensitive?
- Can AMMs keep reserves private while still giving users trustworthy quotes?
- What wallet UX best prevents timing links between Monero deposits and L2
  mints?

## Success Metrics

- L2 soft finality under 5 seconds.
- Mainnet readiness evidence includes a distributed validator benchmark whose
  quorum-certificate max latency is at or below 200ms for the release-candidate
  validator count and threshold. The benchmark must bind the
  release-candidate manifest id, local run-profile report root, local validator
  quorum, local loopback region count, target finality, and latest block height.
- Fees below one-tenth of an equivalent Monero L1 payment during normal load,
  backed by a signed fee policy, normal-load profile, L1 reference-fee, and fee
  curve evidence root.
- No user-visible transparent balance mode.
- Post-quantum signatures on every account authorization.
- No KZG, BLS, or pairing dependency in the core trust model.
- Mainnet readiness evidence binds a `crypto_policy_root` for ML-DSA-65
  authorization, SLH-DSA recovery, ML-KEM-768 sessions, SHA-3 transcript
  domains, hash-based DA commitments, and no BLS/KZG/pairing exceptions.
  That evidence must also bind the release-candidate manifest id, latest
  height, local crypto-inventory report root, dependency inventory root, and
  PQ policy root.
- Proof-system audit evidence binds transparent/PQ proof assumptions,
  hash-based commitments, no trusted setup, and no pairing assumptions.
- Mainnet readiness evidence includes registry-bound provenance attestations
  for every external evidence family, binding each section root to a producer
  identity, signer commitment, PQ public-key root, attestation id, and registry
  root before the release authority can consider custody.
- A redacted readiness-template worksheet binds the current run checkpoint,
  mainnet-readiness check root, public-bootstrap template, local binding roots,
  release-approval skeleton, and release-authority registry skeleton. The
  paired `--verify-readiness-template` command recomputes the worksheet root
  and rejects stale or cross-run evidence collection templates before external
  producers and release authorities fill them.
- Standalone `--write-release-approval-template` and
  `--write-release-authority-registry-template` exports split those release
  authority handoff skeletons into exact-verifiable JSON files. Their paired
  verifiers reject stale, filled, or incomplete signoff packets before external
  authorities turn them into real approval and registry artifacts.
- One Monero anchor can commit at least 10,000 L2 transactions, backed by signed
  capacity policy, fixed-format payload, capacity, and benchmark roots.
- Mainnet readiness evidence includes signed privacy profiles for anchor
  payload/cadence/submitter diversity, one-time and batched deposits,
  delayed/bucketed withdrawals, and wallet recovery from view keys plus DA.
  Those profiles must bind the release-candidate manifest id, latest block
  height, local privacy-surface report root, wallet-recovery audit report root,
  and `privacy_policy.run_binding_root`.
- The release-candidate testnet locally audits public privacy surfaces for
  root-shaped identifiers, bucketed amounts, delayed withdrawals, and absence of
  raw Monero addresses, txids, wallet secrets, transparent balances, or exact
  relay paths.
- The release-candidate testnet binds local run-profile provenance into the
  run checkpoint: runner version, block count, non-mainnet network profile,
  loopback-only endpoints, finality target, quorums, bridge amounts, release
  delay/rate limit, anchor capacity, and operations drill limits.
- Live Monero readiness evidence must bind the same non-mainnet runner network
  profile (`stagenet` or `regtest`) as the release-candidate testnet; mainnet
  remains a separate release-approval target outside the runner. It must also
  bind the release-candidate manifest id, run-profile report root, local bridge
  signer-set root, reserve-report root, latest block height, and synthetic
  observed Monero height.
- The release-candidate testnet binds local deterministic Wasm runtime coverage
  into blocks and the run checkpoint via `wasm_runtime_root` values, module
  validation roots, fuel/memory bounds, private-argument commitments,
  append-only event roots, and timelocked-upgrade rejection roots.
- The release-candidate testnet binds a local finality latency profile into the
  run checkpoint, including quorum-certificate sample roots, p50/p95/p99/max
  latency under the 200ms target, block-construction latency, slow-sample
  count, and target margin. Distributed validator finality evidence is still
  required before mainnet value.
- The release-candidate testnet binds a threaded loopback distributed-finality
  profile into the run checkpoint, including per-block validator vote roots,
  threshold-arrival latency, logical region count, quorum-certificate roots,
  and p50/p95/p99/max latency under the 200ms target. External distributed
  validator evidence must cover that region count and still remains required
  before mainnet value.
- A controlled public-alpha bootstrap profile binds endpoint commitments, typed
  bootstrap node commitment records, node/operator/region set roots, RPC rate
  limits, P2P peer caps, faucet caps, reset policy, monitoring roots,
  health-check roots, status-page commitments, incident contact commitments,
  and deployment runbooks while the local runner remains loopback-only. Public
  bootstrap topology must meet minimum node, committed-operator, and region
  coverage before the profile passes, and the filled deployment evidence must
  derive the same operator count from `bootstrap_nodes`. Public
  endpoint deployment happens outside the runner and must not weaken the
  no-mainnet-custody boundary.
- Public testnet status surfaces expose a redacted
  `nebula-public-status-manifest` with chain, latest-block, finality,
  no-mainnet-custody, and public-bootstrap root commitments only. Full bridge
  ledgers, run profiles, block roots, probe binds, release approvals, and
  authority registries remain local operator output.
- A typed public deployment runbook export gives launch operators a rooted
  `nebula-public-deployment-runbook` handoff before external capture. It is
  not evidence and not custody approval; it binds the public status manifest
  root, bootstrap profile roots, committed deployment runbook root, incident,
  status, monitoring, health, faucet, reset, rate-limit, bootstrap, local
  operations, reserve, privacy, run-checkpoint, and no-mainnet-custody boundary
  roots. Its ordered twelve-step set covers redacted status publication,
  private-summary denial, public RPC/P2P provisioning, status/health/metrics,
  faucet caps, reset communications, incident handoff, bootstrap node rollout,
  operator-registry verification, public deployment evidence capture,
  rollback/reset communications, and no-mainnet-custody confirmation. The
  launch bundle and capture plan both freeze the runbook root and step-set
  root, while standalone bootstrap, status, runbook, and launch-bundle
  verification recompute the public payloads, so deployment CI can detect stale
  or mismatched operator handoffs.
- A public launch artifact manifest export gives operators a rooted
  `nebula-public-launch-artifact-manifest` before public probe capture starts.
  It freezes the pre-capture handoff set: redacted public status manifest,
  public bootstrap profile template, typed deployment runbook, public launch
  bundle, release approval template, and release-authority registry template.
  Each record carries its export flag, root field, artifact
  root, order, required-before-capture flag, publishability flag,
  non-evidence/non-custody flags, and record root, plus a collection
  `artifact_set_root`, without embedding operator-private evidence. The
  manifest guard recomputes those record, set, and manifest roots before export,
  standalone manifest verification, or package verification. The evidence
  worksheet and capture plan bind
  `public_launch_artifact_manifest_root` and
  `public_launch_artifact_set_root` so CI can detect swapped or stale launch
  artifacts before TLS, public probes, or observer attestations are captured.
- A public launch package export gives operators one rooted directory handoff
  before capture starts. It contains the public status manifest, bootstrap
  profile template, typed deployment runbook, launch artifact manifest, launch
  bundle, local launch-readiness report, release approval template,
  release-authority registry template, schema v5 deployment evidence template,
  deployment capture plan, a rooted machine-readable
  `nebula-public-capture-todo` work order, and a
  `nebula-public-launch-package` manifest. The package manifest binds each
  filename, root field, artifact
  root, record root, required-before-capture flag, operator-fill flag,
  non-evidence/non-custody flags, package `artifact_set_root`, package
  `package_file_set_root`, release-candidate manifest id, launch level,
  ready/blocker counts, readiness report/artifact roots, no-mainnet-custody
  boundary, rooted `next_steps`, and rooted capture command sequence so
  deployment automation can reject stale, swapped, cross-run, extra, or
  metadata-tampered handoff files before public endpoint evidence is assembled.
  When combined with the export step in the same runner invocation,
  `--verify-public-launch-package` recomputes each package artifact and the
  package manifest root against the current release-candidate summary, enforces
  the exact top-level package file set and package-level readiness summary, and
  fails on stale, tampered, swapped, cross-run, shape-tampered, or extra-file
  package directories before public evidence capture begins.
- A public testnet certification export writes and verifies the rooted launch
  package, emits the operator-only launch readiness report, writes exact release
  approval and release-authority registry handoff templates, and records
  `local_testnet_ready`, `public_launch_ready`, the
  `certification_file_set_root`, package/report/template roots, the aggregate
  `public_launch_package_handoff_root`, the public deployment evidence root,
  its readiness-report binding boolean, package-bound
  release-template roots, package-binding booleans for both release handoff
  templates, package-bound public deployment evidence-template, capture-plan,
  and capture-todo roots, the capture-contract root, binding booleans for those
  capture handoff artifacts, blocking gaps, rooted remediation commands for capture audit, audit
  verification, strict capture verification, assembly, and launch verification,
  a rooted command sequence for that order, and whether external capture is still
  required in
  `nebula-public-testnet-certification.json`. It is deliberately
  operator-local and remains blocked until the filled schema v5 deployment
  attestation passes.
  The paired `--verify-public-testnet-certification` command verifies the nested
  package, recomputes the launch report, certification file-set root, and
  certification root, verifies both release handoff templates, enforces the
  exact top-level directory shape, and rejects stale, tampered, cross-run,
  extra-file, or swapped package/report/template/cert roots.
- The package-level public capture todo export gives CI a rooted
  `nebula-public-capture-todo` artifact that repeats the exact remaining
  external-capture work without scraping prose: capture-plan, capture-contract,
  preflight, readiness, status, launch-bundle, package file-set, required
  endpoint, TLS, probe, observer, operator-registry, runbook-step, freshness,
  and no-mainnet-custody inputs. It is required before public capture,
  operator-fill-required, and explicitly not deployment evidence or custody
  approval; it avoids embedding the package manifest root to keep package roots
  acyclic. The same rooted todo can be written standalone with
  `--write-public-capture-todo` and verified with
  `--verify-public-capture-todo` for deployment CI that does not need the full
  package directory. The verifier recomputes the current run's todo and rejects
  stale, tampered, or cross-run work orders.
- A local operator-only public launch readiness report export gives CI a
  standalone `nebula-public-launch-readiness-report` with the launch level,
  blocker ids, remediation commands, public status/bundle/capture-plan roots,
  capture-contract root, evidence-template root, preflight-checklist root,
  package file-set root, deployment evidence root if present,
  deployment-attestation failed subchecks such as package file-set, package
  manifest, and readiness artifact binding mismatches, expected package file-set,
  package manifest, and readiness artifact repair roots, and a report artifact
  root. It is marked unusable as public deployment evidence or mainnet custody
  approval. The paired `--verify-public-launch-readiness-report` command
  recomputes the report and artifact root against the current run, rejecting
  stale package-root, status, bundle, capture-plan, capture-contract,
  evidence-template, preflight, or deployment-evidence bindings before
  deployment CI consumes the report root.
- Public launch automation consumes a redacted
  `nebula-public-testnet-launch-bundle` that binds the status manifest,
  bootstrap profile, proxy policy, typed bootstrap-node commitment manifest,
  bootstrap operator registry manifest, faucet/reset policies, monitoring
  commitments, the typed public deployment runbook root and step-set root,
  preflight gates, and operator action list without enabling public runner
  listeners or authorizing mainnet custody. The registry manifest
  requires exactly one independently verified ML-DSA-65-signed registry record
  per committed operator before deployment evidence can clear the public launch
  gate. The bundle is explicitly unusable as public deployment evidence or
  mainnet custody approval, and its guard recomputes the bundle root before
  export or package verification.
- Public deployment evidence templates give deployment automation a schema v5
  worksheet with the canonical public status manifest, launch bundle root,
  launch artifact manifest roots, package file-set root, placeholder package
  handoff root, release approval template root, release-authority registry
  template root, typed public deployment runbook roots, a public deployment
  runbook receipt template,
  typed bootstrap node commitments, typed proxy/firewall/rate-limit policy claims,
  health/status-page/metrics/deployed-finality/incident-contact/faucet/reset body shapes,
  private-summary denial probe shape, typed bootstrap-node reachability probes,
  typed public surface probe records, typed bootstrap-operator registry records,
  typed probe-observer records, freshness fields, and policy/status/P2P/ops/
  finality/private-summary/public-surface-probe-set/bootstrap-node-probe-set/
  public-probe-set/operator-registry/observer/provenance/attestation root
  derivation rules. Templates remain rejected until every placeholder is
  replaced by captured deployment evidence. The paired
  `--verify-public-deployment-evidence-template` command recomputes the
  template root and rejects stale status, launch-bundle, launch-artifact,
  package-file-set, package-handoff, release-template, runbook, bootstrap, or
  local probe roots before operators fill public endpoint evidence.
- A public deployment capture-plan export gives deployment CI a rooted
  `nebula-public-deployment-capture-plan` work order before capture starts. It
  is not evidence; it lists the exact required capture fields, public endpoint
  fields, public surfaces, probe-root fields, freshness window, bootstrap node
  slots, operator commitments, TLS pin roles, required typed public surface probe roles,
  observer quorum, a rooted ordered deployment preflight checklist, and
  `deployment_run_id` propagation rule that the assembler will enforce. The
  plan publishes `capture_contract_root` and `capture_plan_root`; filled public
  deployment attestations must carry those roots so they prove they followed the
  exact rooted capture work order for the current run. The capture-plan guard
  recomputes the preflight checklist, capture contract, and plan roots before
  export or package verification. The capture contract also freezes the public
  launch artifact manifest root, artifact-set root, package file-set root,
  release approval template root, release-authority registry template root,
  typed public deployment runbook root, and step-set root, and includes a
  `package_handoff_capture` section that tells operators to copy
  `public_launch_package_manifest_root` from `nebula-public-launch-package.json`
  and `public_launch_readiness_artifact_root` from
  `nebula-public-launch-readiness-report.json`, plus the release-template roots
  from `nebula-release-approval-template.json` and
  `nebula-release-authority-registry-template.json`, into the deployment capture.
  The plan requires, but does not embed, `public_launch_package_handoff_root` so
  the filled capture can later bind the package file-set, manifest, readiness,
  and release-template roots with one aggregate checksum without creating a
  circular package manifest root. The plan names those required source files and
  capture fields while keeping the operator handoff aligned with the same status,
  bootstrap, launch, package, and evidence-template roots, with the
  evidence-template root frozen in both the preflight source roots and capture
  contract. It also requires a completed
  `deployment_preflight_receipt` covering every required preflight phase in
  order plus a completed `public_deployment_runbook_receipt` covering every
  ordered public deployment runbook step. This keeps the remaining
  public-launch blocker operationally precise without letting the local runner
  invent external reachability, TLS, or observer-signature evidence. The paired
  capture-plan verifier recomputes the current work order and rejects stale,
  tampered, or cross-run plans before public endpoint evidence is filled.
- A package-bound capture scaffold export lets deployment CI start from a
  verified `nebula-public-launch-package` directory and write a schema v5
  capture worksheet with the current capture-plan root, capture-contract root,
  public deployment evidence-template root, deployment preflight checklist
  root, package file-set root, package handoff root, package manifest root,
  readiness artifact root, release-template roots, and matching
  preflight/runbook receipt bindings already filled. The release-template roots
  are copied from the verified package's release approval and release-authority
  registry template files. The scaffold is still marked operator-fill-required
  and unusable as public deployment evidence; live endpoints, TLS pins, public
  probes, bootstrap/operator records, observer signatures, freshness, and the
  final evidence root must still be captured before the public launch gate can
  pass. The paired scaffold verifier recomputes the worksheet against the
  verified package and current release-candidate summary, rejecting stale,
  tampered, cross-run, or package-mismatched scaffolds before capture starts.
- A public deployment evidence assembler lets deployment automation feed
  captured endpoint, TLS, typed policy, probe, observer, runbook receipt,
  capture-plan, and freshness transcripts into the runner and receive a rooted schema v5
  attestation. The
  assembler binds the current run's public status manifest, launch bundle,
  package file-set root, package handoff root, bootstrap profile,
  launch artifact manifest roots, release approval template root,
  release-authority registry template root,
  capture plan, preflight checklist, completed preflight
  receipt, completed runbook receipt, node set, and policy roots, derives
  preflight phase-set and receipt roots, derives runbook step-receipt-set and
  receipt roots, derives TLS endpoint-pin set
  roots and the aggregate SPKI root from captured `tls_endpoint_pins`, derives
  bootstrap node/operator/region roots, public endpoint-set roots, and the
  bootstrap operator count from captured
  `bootstrap_nodes`, derives `bootstrap_node_probe_set_root` from one
  reachability record per committed bootstrap node, derives
  `public_surface_probe_set_root` from typed status, aggregate P2P, health,
  status-page, metrics, deployed-finality, incident-contact, faucet, reset-runbook, and
  private-summary-denial records, derives bootstrap operator
  registry, independence, and signature roots from captured
  `bootstrap_operator_registry`, derives canonical observer attestation, signature-payload,
  and signature-verification roots, and rejects observer records that do not
  carry externally verified ML-DSA-65 signature roots plus typed verification
  transcripts over those payloads. TLS pin records, bootstrap operator registry
  records, observer records, and observer/operator signature verification
  transcripts must all bind the same `deployment_run_id`, preventing a public
  launch attestation from being assembled out of valid fragments from different
  deployment captures. It then derives observer set, attestor
  registry, region-count, observer-count, and PQ-signature collection roots
  from unique probe-observer records, derives the canonical public probe-set
  root from the required probe transcript roots, including the typed public
  surface probe-set root and bootstrap-node probe-set root, computes every
  policy/probe/provenance/evidence root, writes
  the assembled artifact, and validates it through the same verifier used by
  the public launch gate. The public deployment report compares the embedded
  `capture_plan_root`, `capture_contract_root`,
  `public_deployment_evidence_template_root`, and
  `deployment_preflight_checklist_root` against the current generated capture
  plan, binds those actual/expected capture roots into the report root, exposes
  individual root-binding booleans plus expected repair roots,
  seals the public RPC, P2P, status, health, metrics, incident, faucet, and
  reset-runbook endpoint strings into the report root,
  requires the embedded `public_launch_package_file_set_root` to match
  the current rooted package file set, requires the embedded
  `public_launch_package_handoff_root` to match both the expected package
  handoff and the roots carried in the capture, requires the embedded
  `public_launch_package_manifest_root` and
  `public_launch_readiness_artifact_root` to match the pre-capture launch
  package handoff, requires the embedded `release_approval_template_root`
  and `release_authority_registry_template_root` to match the release
  handoff templates in the verified package, seals the embedded public
  bootstrap profile root, profile report root, and rate-limit policy root
  against the current bootstrap profile in the report root, seals the local
  finality latency profile report root, and requires the embedded
  `deployment_preflight_receipt_root`, `deployment_preflight_phase_set_root`,
  and phase count to match the completed receipt body. It also requires the
  embedded public deployment runbook root, step-set root, `public_deployment_runbook_receipt_root`,
  `public_deployment_runbook_step_receipt_set_root`, and step receipt count to
  match the completed receipt body and the current generated runbook. Missing,
  incomplete, out-of-order, stale, source-mismatched, or root-mismatched
  preflight or runbook receipts cannot clear the public launch gate. Deployment
  CI can run `--audit-public-deployment-capture` first to write a non-passing
  capture audit that lists missing required fields, missing or invalid public
  endpoint fields, invalid freshness windows, stale capture times,
  invalid deployment run ids, malformed preflight receipt fields or phases,
  malformed runbook receipt fields or steps, expected capture-plan,
  capture-contract, evidence-template, preflight, package-manifest,
  readiness-artifact, release-approval-template, and
  release-authority-registry-template roots, mismatched frozen launch/status
  roots,
  missing or extra TLS endpoint pin roles,
  malformed TLS endpoint pin records, missing or extra public-surface probe
  roles, malformed public-surface probe records, insufficient bootstrap node
  counts, missing or extra bootstrap-node
  probe slots, malformed bootstrap-node probe records, missing or extra
  bootstrap-operator registry commitments, malformed bootstrap-operator
  registry records, unreachable
  observer quorums, insufficient observer region coverage, malformed observer
  regions, duplicate observer ids or keys, unsigned or unverified observer
  signatures/transcripts, placeholders, sensitive markers, public-forbidden
  keys, current capture-plan and package file-set root mismatches, structural
  readiness, machine-readable
  structural and full failed-check lists, strict verifier status, and the first
  nested verifier error. CI can verify the audit report itself against the
  capture and current release-candidate summary to reject stale, tampered,
  cross-run, or capture-mismatched diagnostics, then run
  `--verify-public-deployment-capture` to dry-run the same assembler/verifier
  path and feed the resulting temporary attestation into
  `--fail-on-public-launch-gaps` before writing the final public deployment
  artifact.
- Filled public deployment attestations bind the launch bundle to publicly
  routable HTTPS endpoints, the exact capture plan root, capture contract root,
  public deployment evidence-template root, deployment preflight checklist
  root, package file-set root, release approval template root,
  release-authority registry template root, completed
  preflight receipt root and phase-set root, completed runbook receipt root and
  step-receipt-set root, typed TLS endpoint-pin records for public RPC,
  status-page, health, metrics, incident-contact, faucet, and reset-runbook surfaces, typed bootstrap node
  records whose derived node/operator/region roots must match the public bootstrap profile,
  proxy/firewall/rate-limit roots and their typed claim bodies, the captured
  public status manifest, the P2P handshake derived from that canonical status
  JSON, health/status-page/metrics/incident-contact/faucet/reset probe bodies, a
  deployed-finality probe, a private-summary denial probe, and observer
  provenance. Bootstrap node records must cover every committed node slot with
  unique public P2P and HTTPS status-page endpoints whose set roots are bound
  into the deployment attestation, and they must cover at least the minimum
  committed operator count. Literal private, loopback, link-local,
  documentation, multicast, CGNAT, and local-only endpoint addresses are
  rejected; deployment DNS names and public IP or multiaddr endpoints remain
  valid. Typed `bootstrap_node_probes` must also cover every
  committed node slot, bind the deployment run id, launch bundle root,
  status-manifest root, node slot, public P2P endpoint, canonical P2P
  handshake, verified handshake flag, HTTPS status-page endpoint, 200
  status-page response root, and observation time. Their aggregate
  `bootstrap_node_probe_set_root` is included in observer attestations and the
  canonical `public_probe_set_root`. Typed `public_surface_probes` must also
  cover the status manifest, aggregate P2P handshake, health, status-page,
  metrics, deployed-finality, incident-contact, faucet, reset-runbook, and private-summary denial
  surfaces exactly once. Each record must bind the public endpoint, transport,
  transcript kind/status, transcript root, probe root, launch bundle root,
  status-manifest root, `deployment_run_id`, `observed_at_unix_ms`, and
  public-routability claim; the derived `public_surface_probe_set_root` is
  included in observer attestations, provenance, the final attestation, and the
  canonical `public_probe_set_root`. A typed bootstrap operator registry must cover every
  committed operator exactly once, require unique entity/control-plane/
  infrastructure/contact commitments, bind an independence proof root, assert
  verified independence, and bind ML-DSA-65 signature verification transcripts.
  Probe-observer records must have
  unique observer ids and keys,
  multiple regions, observation times inside the freshness window, attestations
  bound to every captured probe root, `signature_scheme: ML-DSA-65`, canonical
  `signature_payload_root` values, `signature_verified: true`, typed
  `signature_verification` transcripts, and matching
  `signature_verification_root` values; the verifier derives and checks
  observer set, registry, and PQ-signature roots from those records. The
  artifact also binds `public_probe_set_root` and `public_probe_count`, derived
  from the status, P2P, health, status-page, metrics, deployed-finality, incident-contact,
  faucet, reset-runbook, bootstrap-node reachability, and private-summary-denial probe roots. The
  proxy claims must disable public runner listeners, restrict output to
  approved public surfaces, require TLS/redaction, and require the
  private-summary probe. Firewall claims must keep loopback runner ports
  private and block private-summary, admin, debug, and non-public routes.
  Rate-limit claims must bind the public bootstrap RPC/P2P/faucet caps and
  include observed 429 rejections, retry-after data, route coverage,
  peer-limit observation, and faucet-cap enforcement. Probe bodies bind
  status/bootstrap roots, public ops commitments, faucet caps, reset window,
  and deployment runbook roots while asserting no-mainnet-custody. The
  deployed-finality probe must cover the same manifest, latest height,
  validator count, threshold, region count, sample count, and <=200ms p95/max
  finality target as the public manifest. Its body binds network-profile,
  clock-sync, and sample-set roots, and the verifier requires a real quorum
  plus `p95 <= max <= target`. The private-summary probe must target
  `/operator-summary`, prove 403/404 denial, bind a response-body root and
  small content-length cap, and assert no redirect or private-summary content.
  The local verifier rejects stale self-consistent captures by requiring the
  status manifest root, embedded status payload, and launch bundle root to match
  the current run's generated public artifacts and by enforcing an observed/expires freshness window,
  multi-observer/multi-region probe roots, unique observer ids/keys, unique
  bootstrap endpoint roots, an attestor registry root, and a PQ signature root.
  The explicit `--verify-public-deployment-evidence` command loads the filled
  attestation, recomputes the public deployment report for the current run, and
  exits nonzero unless every public launch gate passes.
  Live reachability checks and raw PQ signature verification remain
  deployment-system evidence outside the local runner, but duplicate bootstrap
  endpoints and duplicate, unsigned, or unverified observer captures are
  rejected by the audit, assembler, and verifier.
- A dedicated public launch gate fails until local public-alpha surfaces,
  bounded bootstrap policies, redacted launch artifacts, and schema v5
  deployment evidence all pass. This gate is separate from the mainnet evidence
  and custody-approval gate, and the full local operator summary exposes a
  `public_launch_readiness` report with blocker ids, check roots,
  machine-actionable remediation entries, and a remediation root. Each
  remediation names the stable expected artifact id/path, expected artifact,
  remediation kind, relevant command, expected evidence root, granular failed
  subchecks, root-specific `repair_roots` for failed capture/preflight/package/
  runbook receipt/status/bootstrap topology and policy bindings, and capture roots, bootstrap profile/report/rate-limit roots,
  bootstrap topology/count/registry/probe bindings, aggregate probe repair roots/counts,
  endpoint publicness, TLS pin repair roots/counts,
  proxy/firewall/rate-limit policy repair roots, status-manifest root/payload, and
  per-surface probe roots/counts, placeholder hygiene, and local bootstrap/
  finality dependencies, wallet recovery, mempool accountability, bridge release
  safety, privacy classification, and whether external deployment capture is
  required. When the deployment attestation is still absent, the remediation
  still seeds the current capture-plan, package file-set, status, runbook, and
  bootstrap topology roots so deployment CI can start capture from deterministic
  expected bindings. That private operator report is intentionally absent from the public status
  manifest and launch bundle.
- External review evidence must bind the release-candidate manifest id, latest
  height, and local run-profile, Wasm runtime, crypto-inventory,
  privacy-surface, and operations-readiness report roots. Timing-sample
  coverage remains enforced by the dedicated local and distributed finality
  gates.
- A wallet can recover and audit its own history from view keys and DA data,
  with the release-candidate testnet binding local admission, block-status,
  DA/proof, anchor, and bridge-history roots into a wallet recovery audit report.
- Mainnet readiness evidence includes signed incident handoff, rollback,
  withdrawal queue-drain, pause/resume, and reserve reconciliation drills.
- The release-candidate testnet binds local operations drill coverage receipts
  for incident handoff, rollback replay/restore, withdrawal queue drain,
  pause/reject/resume behavior, and reserve reconciliation into the run
  checkpoint, while still requiring signed operations evidence for mainnet.
- Bridge reserves can be independently monitored, with the release-candidate
  testnet binding reserve address hashes, reserve attestations, liability
  snapshots, independent reporter commitments, monitoring cadence,
  completed-withdrawal exclusion, and underreserve alert drills into a reserve
  monitoring report.
