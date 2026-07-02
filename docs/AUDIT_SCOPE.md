# Nebula External Audit Scope

**Status: experimental testnet, unaudited, no mainnet, `live_value_enabled = false`.** This
document is the code-derived map an external auditor should start from. It states, per subsystem,
the invariants the code establishes (with `file:line`), what is cryptographically **verified**
versus merely **trusted**, the residual gaps, and the third-party dependencies whose correctness
Nebula inherits. Read alongside [SECURITY.md](../SECURITY.md) and
[THREAT_MODEL.md](../THREAT_MODEL.md); this document does not restate the asset/adversary model,
it enumerates the review surface.

Line references are anchors, not guarantees — verify against the current tree
(`git rev-parse HEAD`). Where a range is given the enforcement spans those lines.

## 1. System model in one paragraph

Nebula is a single-sequencer Monero L2. The sequencer signs each block and the resulting state
root; followers **verify the signature and re-derive a subset of the state**, they do not
re-execute the whole chain. Concretely, followers independently re-execute **per-account nXMR
balances and validator points** and check **aggregate nXMR custody conservation**; they accept
**NBLA balances, account nonces, the shielded-note set, and EVM state** on the strength of the
sequencer signature over the state root alone. A partially-trusted M-of-N Monero bridge mints and
redeems nXMR; with a live verifier configured each deposit is checked against a Monero node, and
operator/observer keys are launch-attested and bondable. Quantum resistance is opt-in hybrid
Ed25519+ML-DSA-65 signatures; confidential amounts (Pedersen + Bulletproofs) are **not**
post-quantum and the transaction graph is public.

## 2. The central trust boundary

The single most important thing to audit is the line between verified and trusted state, because
the whole security argument rests on it:

| State | Verified by followers? | Mechanism |
|---|---|---|
| nXMR balances (per account) | **Yes** | `reexecute_replayable_state` re-derives from deposits − non-reverted withdrawals − nXMR fees + in-kind rewards; rejects on mismatch (`runtime.rs:8058-8074`) |
| Validator points (per account + total) | **Yes** | same re-execution, keyed to `reward_account_for_validator(binding, block.producer)` (`runtime.rs:8076-8100`) |
| nXMR custody (aggregate) | **Yes** | `deposits == accounts + non-reverted reserved + fees`, surplus==deficit==0 (`runtime.rs:8317`) |
| Block/state roots + signatures | **Yes** | re-hash + verify under key-active-at-height + cosigner quorum (`runtime.rs:7803-7818`) |
| NBLA balances, nonces | **No — trusted** | only bound via the signed state root; never re-derived from transactions |
| Shielded-note set, range proofs, balance | **No — trusted** | followers do not re-run Bulletproofs/balance checks; only the set is folded into the signed root |
| EVM state (accounts/code/storage) | **No — trusted** | structurally re-validated on import (`nebula-evm/src/lib.rs:371-404`) but never re-executed |
| Bridge Monero facts | **Trusted quorum** | M-of-N attestation; with a live verifier, view-key/confirmation/`tx_extra` proofs against a Monero node |

An auditor's highest-value question: **can a compromised sequencer produce a signed snapshot whose
trusted columns are internally inconsistent yet passes `validate_snapshot`?** The re-execution and
custody checks are the only defense on the nXMR/points columns; everything else is sequencer-
attested by design.

## 3. Per-subsystem review guide

### 3.1 Cryptography (`nebula-crypto`)
Stateless signing/verification used by both signer and verifiers.
- **Verified:** possession of the secret matching a public key over a specific 64-hex root; for
  hybrid, possession of **both** halves (`scheme.rs:248-259`); Ed25519 canonicality + weak-key
  rejection via `verify_strict` / `is_weak` (`lib.rs:29,78`).
- **Key invariants:** hybrid accepts only if both halves verify (`scheme.rs:251`); no scheme
  confusion — signature tag must equal key tag (`scheme.rs:218`); exact length checks before any
  curve/lattice op (`scheme.rs:225,232`); deterministic signing (`lib.rs:63`).
- **Trusted / residual:** domain separation lives entirely in callers (the library signs any
  64-hex string verbatim); no key→scheme binding forcing PQ; `parse_tagged` has no length cap
  before `hex::decode` (`scheme.rs:85`); `SchemeId::from_tag` is case-sensitive.
- **Focus:** the ML-DSA path and hybrid split/verify math; confirm no acceptance-of-forgery in the
  `mldsa65`-only path (there is no Ed25519 fallback for those keys).

### 3.2 Roots & determinism (`runtime.rs` `runtime_state_root`/`snapshot_root`/`block_root`)
- **Invariants:** every root = `SHA3-256(serde_json::to_vec(Value))`; `serde_json` built **without**
  `preserve_order` so `Map` is a `BTreeMap` → canonical key order; domain-tag per root prevents
  cross-structure collisions; every consensus-state field folded into `runtime_state_root`
  (`runtime.rs:10426`); `validate_snapshot` recomputes and rejects on mismatch, and binds
  `snapshot.state_root` to the latest signed block's state_root (`runtime.rs:7962-7972`).
- **Fixed during audit-prep (see §5):** an out-of-`u64`-range `u128` panicked the `json!` builders
  (remote DoS); `note_owners` was folded into `runtime_state_root` but omitted from `snapshot_root`.
- **Residual:** byte-compat silently depends on `serde_json`'s `preserve_order` staying off (feature
  unification risk); `exported_at_unix_ms` is folded into no root (unauthenticated metadata).
- **Focus:** confirm the manual fold lists stay in lockstep with the struct fields on every future
  change; this class of drift is exactly what the two fixed bugs were.

### 3.3 Follower re-execution & economics (`reexecute_replayable_state`, `nxmr_custody_reconciliation`, `derive_runtime_snapshot_economics`)
- **Invariants:** per-account nXMR + points equality vs an independently rebuilt ledger
  (`runtime.rs:8058-8100`); in-kind nXMR split mirrors `apply_transaction` exactly
  (`runtime.rs:8044-8054` vs `5141-5168`); aggregate custody conservation (`runtime.rs:7980-7988`);
  receipt-level economics re-derivation (`runtime.rs:8179-8228`).
- **Residual:** the reward account is keyed off `block.producer`, which is pinned by the producer-
  uniformity + launch-attested-validator check (`runtime.rs:7710-7737`) — on a **non-launch-bound**
  dev chain the launch-attested branch is skipped, so producer identity is only pinned to genesis-
  uniform (documented; no value at stake there). Custody is nominal-unit conservation only (no
  reserve check vs real Monero, consistent with live-value disabled).
- **Focus:** the differential correctness of `apply == reexec == economics` across every fee/reward
  path; a divergence that keeps totals constant but relocates value/points is the crown-jewel bug
  class (two such were found and fixed this cycle — producer binding and equivocation replay).

### 3.4 Monero bridge (`runtime.rs` deposit/withdrawal/bond, `nebula-monero`)
- **Invariants (24 mapped):** no deposit double-mint incl. hex-case variants (`runtime.rs:4427`);
  withdrawal finalize replay guards on tx-id/proof-root reuse (`runtime.rs:4613`); reverted
  withdrawals excluded from custody (`runtime.rs:8289`); slashing burns the bond, never credits
  (`runtime.rs:4386`); M-of-N observer/operator quorums with id/root dedup via
  `validate_identity_root_quorum`/`validate_quorum_roots` (`runtime.rs:9337-9386`), invoked for
  deposit observers (`runtime.rs:8560`) and withdrawal operators (`runtime.rs:4606`); live-mode
  deposit verified against a Monero node — exact amount, ≥10 confirmations, not-in-pool, custody
  address, `tx_extra` account binding (`runtime.rs:4443`, `nebula-monero/src/verify.rs:69`).
- **Residual:** on the shipped default (no launch binding, no live verifier) observer/operator
  signatures are **not** verified and no Monero proof is required — deposits/withdrawals ride on
  unsigned quorum strings authored by the sole sequencer; `verify_on_chain_custody` is a live-mode
  liveness check, not part of consensus validation; TLS pinning is optional.
- **Focus:** the launch-bound + live-verifier path (that is what a real deployment uses), and the
  custody conservation identity under adversarial deposit/withdraw/challenge interleavings.

### 3.5 Privacy (`nebula-privacy`, shield/transfer/unshield)
- **Invariants:** every output carries a Bulletproofs range proof that must verify
  (`runtime.rs:5425/5531`); homomorphic balance `Σinputs = Σoutputs + fee` enforced
  (`runtime.rs:5435/5541`); shield/unshield conserve value across the transparent boundary via
  Pedersen binding; authenticated shield (sig + nonce) and owner-authenticated spend/unshield.
- **Residual (by design, already in THREAT_MODEL):** transaction graph is public; notes are bearer
  instruments; **not post-quantum**; the v2 nullifier is not bound to the note opening (commitment
  removal is the authoritative double-spend guard); `note_commitments` is a plain set, not a
  Merkle/zk accumulator. Followers do **not** re-verify range proofs or balance.
- **Focus:** that range-proof + balance verification cannot be bypassed at execution time, and that
  the honest residual (no follower re-verification) is exactly as documented — a differential test
  in `runtime.rs` pins that a follower accepts an internally-inflated shielded pool.

### 3.6 EVM (`nebula-evm`, `runtime.rs` `evm_*`)
- **Invariants:** NBLA conserved across the transparent↔EVM boundary (`runtime.rs:3983-4010`);
  replay-safe via `evm_authorization_root` binding `chain_id`/account/action/target/payload/value/
  gas/nonce (`runtime.rs:3352-3376`); atomic charge only on `Ok` with value-refund on error;
  gas bounded (30M mutate / 10M view); views read-only via `DatabaseRef` (no clone);
  deterministic canonical export/import.
- **Residual:** fee is on `gas_limit` not `gas_used` (reverts pay full fee, keep the nonce); revm's
  `cfg.chain_id` is hardcoded (`6_874_269`) independent of `config.chain_id`; EVM state is
  sequencer-attested (never re-executed by followers).
- **Focus:** revm determinism (it feeds the signed state root), `import_state` robustness on
  adversarial snapshots, and the atomicity of `evm_execute_atomic` under executor errors.

### 3.7 Fee model (`quote_hybrid_fee`, validator fee-preference)
- **Invariants:** nXMR fee conservation `pooled + reward == paid` (`runtime.rs:5157`);
  apply==reexec==economics agreement; per-height activation binding defeats authorization replay
  (`runtime.rs:7785`); log monotonicity + registry==latest-log; monotonic issuance
  (`sequence == current+1`).
- **Residual:** `NXMR_VALIDATOR_REWARD_BPS == NXMR_BUYBACK_BPS == 10000`, `RESERVE_BACKING_BPS == 0`
  — validator-reward and buyback are parallel 100%-of-converted accountings, not a partition, and
  `pooled` is always 0 in the in-kind path; `ceil_div` rounding lets `converted` exceed `required`
  by up to `rate-1` (exact only because `rate == 1` today); a block may omit the `nxmr` stamp even
  when the producer's active preference is `nxmr`.
- **Focus:** the three-way agreement across production and follower verification, and the rounding
  direction (auditor should confirm the payer-overpays direction is intended).

### 3.8 RPC / HTTP / parsers (`runtime.rs` HTTP layer, `nebula-monero` client)
- **Invariants (25 mapped):** request/header/body size caps (`runtime.rs:6492,6506,6585`); overflow-
  safe Content-Length via `saturating_add` (`runtime.rs:7380`); fail-closed rate limiting with
  bounded client table (`runtime.rs:1640-1670`); connection caps; admin methods gated by access
  class **and** constant-time SHA3 token compare (`runtime.rs:6701,7293`); admin listener must bind
  loopback/private (`runtime.rs:5838`); account-id and fixed-hex bounds; Monero RPC response size
  cap (8 MiB).
- **Residual:** `content_length_from_headers` matches only two capitalizations and no
  `Transfer-Encoding: chunked`; thread-per-connection model relies on caps + a 750ms per-read
  timeout for slowloris resistance (no total-request deadline); several `.expect()` on
  by-construction-infallible paths.
- **Focus:** panic-freedom of the unauthenticated framing/param/dispatch paths (now fuzzed — see
  §6) and the trusted-proxy header parsing.

### 3.9 Sync & accountability (snapshot import, key rotation, equivocation)
- **Invariants:** malicious peer cannot inject an invalid chain (every block re-hashed + signature
  verified under key-active-at-height); accountability reports must be genuine height-bound
  equivocation proofs (two different same-height blocks, both re-hashed + signature-verified) so a
  peer cannot weaponize `ensure_accountability_clean` to halt a follower (`runtime.rs:8471-8511`);
  rotation chain continuity + no-downgrade + no-lockout + M-of-N operator quorum; key-at-height is
  monotone by activation height and feeds both block and report verification.
- **Residual:** sync quorum counts distinct peers by **self-reported** `config.validator_id`
  (Sybil-able by one fork under many ids); `DEFAULT_SYNC_PEER_QUORUM = 1` unless a manifest raises
  it; the initial-bootstrap path does not enforce quorum; without a launch binding, rotations
  require zero **signed** operator approvals — the signed `operator_approvals` vector may be empty
  (`runtime.rs:9084-9092`); ≥2 unsigned, sequencer-authored approval id/root strings are still
  structurally required (`rotation_quorum(None) = 2`) but carry no cryptographic authority, so the
  effective authorization barrier is nil.
- **Focus:** the key-rotation approval chain and `resolve_sequencer_public_key_for_height`
  boundary behavior across activation heights (an off-by-one checks a block against the wrong key).

## 4. Dependency-risk register

The correctness of these third-party crates is inherited and **must be in audit scope**:

| Dependency | Where | Risk |
|---|---|---|
| `ml-dsa` 0.1.1 | all PQ signatures | pre-1.0, **unaudited** ML-DSA/FIPS-204; a soundness bug voids PQ protection (hybrid stays Ed25519-safe; `mldsa65`-only keys fully broken) |
| `bulletproofs` + `merlin` | confidential amounts | the entire no-inflation guarantee reduces to range-proof soundness + the Fiat-Shamir transcript |
| `revm` 14 | EVM execution | all EVM semantics/gas/**determinism** feed the signed state root; any nondeterminism forks the root |
| `curve25519-dalek` 4.1.3 | Pedersen/Ristretto | commitment binding/hiding; 4.1.3 includes the RUSTSEC-2024-0344 timing fix |
| `ed25519-dalek` 2.2.0 | classical signatures | mature; code uses `verify_strict` + `is_weak` |
| `serde_json` 1 | all roots + RPC | built **without** `arbitrary_precision` (the u128 footgun, now guarded) and **without** `preserve_order` (the determinism dependency) |
| `rustls`/`webpki-roots`/`ring` | Monero TLS + snapshot fetch | custom `PinnedServerCertVerifier`; pinning optional |
| `sha3` | every root + address checksum + token compare | SHA3-256 collision/preimage resistance underpins all domain separation |

There is no `cargo-audit`/`cargo-deny` gate and no upstream audit of the PQ dependency — supply-
chain review is entirely on the integrator. **Recommend adding a `cargo-deny` CI gate.**

## 5. Prior adversarial-audit history (what has already been checked)

Nebula has been through multiple in-house adversarial audit rounds (find → adversarially verify →
fix → re-verify to convergence). Confirmed-and-fixed defects to date include: a double-mint via
case-variant `monero_tx_id`; a hybrid-rotation lockout / PQC downgrade; a forgeable equivocation
report (unbound to height) that could permanently halt a follower via peer snapshot import; an
unvalidated `block.producer` that let a compromised sequencer redirect nXMR/points attribution;
a fee-preference authorization replay after revocation; several DoS/overflow paths. Two more were
found during this audit-prep pass and fixed: **(1)** an out-of-`u64`-range `u128` in a folded field
panicked the `json!` root builders (remote DoS on importing followers) — now rejected up front in
`validate_snapshot`; **(2)** `note_owners` was missing from `snapshot_root`'s fold — now included.
These are documented so an external auditor knows the surface has been probed but should **not**
assume it is exhausted (each round found real HIGHs).

## 6. Test & fuzz coverage handed to the auditor

Arbitrary-input never-panic and property harnesses (deterministic LCG-seeded, no `proptest` dep):

- `nebula-crypto`: scheme parsers, tagged-length boundaries, random-seed sign/verify + cross-key
  rejection.
- `nebula-monero`: base58 decode, `tx_extra` parse, and the Monero address parser — all never-panic
  on arbitrary input.
- `nebula-privacy`: `amounts_balance` split/inflation property; `verify_amount`/`Commitment::from_hex`/
  `nullifier_hex` never-panic on arbitrary proof/hex bytes.
- `nebula-evm`: `parse_address`/`parse_bytes`/`parse_u256`, every executor entry point, and
  `import_state` never-panic on arbitrary input; export/import round-trip.
- `nebula-testnet`: HTTP framing + param helpers never-panic; `quote_hybrid_fee` + in-kind split
  property; custody + re-execution hold across random fee-asset / fee-preference mixes (single
  fixed deposit, transfers only — see recommended additions for withdrawal/revert coverage);
  out-of-range-`u128` rejection; `note_owners` fold.

**Recommended additions before/for the audit:** coverage-guided fuzzing (`cargo-fuzz`) on
`validate_snapshot` and the crypto verify paths; ML-DSA known-answer differential vectors; a
`cargo-deny` supply-chain gate; a custody property test that exercises bridge withdrawals
including the reverted-withdrawal path (needs a launch-bound runtime with a non-zero challenge
window, so it is not covered by the transfers-only custody harness above).

## 7. Out of scope for this testnet (documented design limits, not defects)

Fully trustless (SPV/covenant) Monero bridging, BFT/decentralized consensus, zk graph privacy,
post-quantum confidential amounts, follower re-execution of NBLA/EVM state, real-value custody, and
the external audit itself. These are the honest limits of the current design and are tracked in
[SECURITY.md](../SECURITY.md) / [THREAT_MODEL.md](../THREAT_MODEL.md).
