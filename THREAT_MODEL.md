# Nebula Threat Model

**Status: experimental testnet, unaudited, no mainnet, no real value.** This document
enumerates assets, adversaries, trust boundaries, and the outcomes an attacker can achieve,
with the mitigations Nebula implements and the residual gaps. Read alongside
[SECURITY.md](SECURITY.md).

## Assets

| Asset | Where it lives | Protected by |
|---|---|---|
| **NBLA balances** | `RuntimeAccount.nbla_nebulai` in the signed state | Sequencer state signature; per-account Ed25519/hybrid tx signatures + nonces |
| **nXMR balances** | `RuntimeAccount.nxmr_units` | Bridge quorum + (opt-in) node view-key proofs; **follower re-execution** of per-account nXMR (including the in-kind validator fee share routed by each block's signed `fee_preference` stamp) |
| **Custody XMR** | Off-chain Monero multisig wallet | M-of-N operators; optional on-chain balance check (`verify_on_chain_custody`); operator bonds |
| **Shielded amounts** | Pedersen commitments in `shielded_notes` | Bulletproofs range proofs + homomorphic balance; amounts hidden, **graph public** |
| **EVM contract state** | `RuntimeSnapshot.evm_state` (accounts/code/storage) | Signed state root; per-account signatures + nonces on deploy/call/withdraw; NBLA-only prepaid fees; sequencer-attested (no follower contract re-execution) |
| **Sequencer signing key** | Operator infrastructure | Out-of-band key management (HSM = ops); equivocation accountability fail-closed |
| **Bridge quorum keys** | Operator/observer infrastructure | Identity-attested launch roster; **slashable bonds**; signer diversity = ops |
| **Validator co-signer keys** | Validator infrastructure | Launch-attested roster; N-of-M block co-signatures |
| **Witness keys** | Witness infrastructure | Launch-attested `witness_keys` roster; role-separated (validated distinct from validator co-signer, bridge operator, and bridge observer keys) |

## Adversaries and outcomes

### Colluding bridge quorum (≥ M observers or operators)
- **Deposit side:** M observers can attest a deposit that did not happen and mint unbacked
  nXMR. **Mitigations:** identity-attested M-of-N quorum, replay/uniqueness guards, custody
  reconciliation gate, per-account nXMR re-execution, and — when a live verifier is configured
  (`with_monero_bridge`) — mandatory view-key `check_tx_key` amount + confirmation + `tx_extra`
  binding proofs against a Monero node. **Residual:** the trust assumption itself (M honest
  signers) is by design; slashable operator bonds (`post_bridge_bond`/`slash_bridge_participant`)
  raise the economic cost of misbehavior.
- **Withdrawal side:** M operators can approve a fraudulent payout. **Mitigations:** account
  nonce+signature binding before nXMR burn, launch-attested operator quorum, replay guards,
  optional on-chain payout proof (`check_tx_key` against the withdrawal address), and a
  configurable **withdrawal challenge window** (`finalizing` → `settled` on settle, or `reverted` on
  challenge) that lets a fraudulent finalization be reverted before it settles, restoring the user's own
  burned nXMR escrow (`challenge_withdrawal`). Operator bond slashing
  (`slash_bridge_participant`) is a *separate*, unlinked economic penalty — the burned bond is not
  paid out to the user. The challenge window is an *optimistic* mechanism and is mutually exclusive
  with live node verification: when a Monero verifier is configured (`with_monero_bridge`),
  `finalize_withdrawal` requires the payout tx to be on-chain-confirmed (`check_tx_key`, ≥
  `MIN_BRIDGE_CONFIRMATIONS`) and settles immediately, so a proven payout cannot be
  challenge-reverted (which would double-credit the user). **Residual:** in optimistic mode the
  window only helps while the payout has not yet settled; it cannot claw back XMR already sent
  on-chain, and it does not compensate a user for a payout that both settled and was fraudulent.

### Compromised sequencer key
- Can forge state, censor, or halt the chain. **Mitigations:** followers verify the per-height
  sequencer signature *and* re-execute the replayable columns (per-account nXMR + validator
  points) so silent nXMR/point forgery is caught (`reexecute_replayable_state`); equivocation and
  mis-sign evidence halt all mutations fail-closed (`ensure_accountability_clean`). An equivocation
  report only wedges the chain if it carries **cryptographic proof** — the two conflicting block
  headers, each re-hashed with `block_root` (which commits to height), whose recomputed hashes
  match the signed hashes, whose heights both equal the reported height, and whose signatures
  verify against the key active at that height (`validate_accountability_report`). Binding both
  headers to a single height means two unrelated real block signatures (from different heights)
  can no longer be replayed as a fabricated equivocation to grief a follower via snapshot import.
  Key
  rotation is scheme-aware and quorum-gated; N-of-M block co-signing (when configured) requires
  validator attestations. **Residual:** NBLA balances, nonces, and the shielded-note set remain
  sequencer-attested (no in-block journal); chain-governed policy (fee floor, faucet rate, block/
  mempool limits) travels in the sequencer-attested config, guarded by the distinct-peer sync
  quorum rather than a separately-signed governance root; and censorship/liveness depend on the
  single sequencer — decentralized BFT is future work. Each block that stamps `nxmr` fee routing
  must carry the producing validator's own signed, sequence-numbered fee-preference authorization
  (verified under the launch-attested cosigner key, a key distinct from the sequencer block key),
  and it must be the authorization *active at that block's height* per the per-validator
  activation log — so the raw sequencer key can neither forge nor replay a superseded (revoked)
  authorization to redirect the in-kind nXMR reward. The sequencer can still *delay* processing a
  preference change (choosing its activation height), but that reduces to the same censorship
  power the single sequencer already holds and cannot fabricate an unsigned routing choice.

### Network attacker (MITM on Monero or peer RPC)
- **Monero RPC:** mitigated by TLS with optional SHA-256 leaf-certificate pinning
  (`HttpMoneroRpc` / `PinnedServerCertVerifier`); plaintext `http://` should only be a trusted
  loopback link. **Peer snapshots:** authenticated by the sequencer signature and a distinct-peer
  sync quorum; followers reject snapshots that do not chain or match their launch binding.

### Quantum ("Q-day") adversary
- Breaks the default Ed25519 signatures and the Pedersen/Bulletproofs commitments. **Mitigations:**
  opt-in hybrid Ed25519+ML-DSA-65 signing for blocks, transactions, accounts, attestation roots,
  and bridge/rotation evidence (both halves must verify). **Residual:** hybrid is opt-in (default
  is classical Ed25519), `ml-dsa` 0.1.1 is unaudited, and confidential amounts are not
  post-quantum.

### Note-opening thief (privacy)
- Shielded notes are **bearer** instruments: knowledge of a note's opening (value + blinding)
  authorizes spend/unshield; there is no per-note spend key. A thief who learns an opening can
  spend it. The transaction graph (which note funds which) is public. **Mitigation:** none today
  beyond keeping openings secret. **Residual:** true graph privacy + per-note ownership needs a zk
  nullifier scheme (the `nullifier` + accumulator here is a foundation, not unlinkability).

## Trust boundaries

```
   user ──(public RPC, TLS-terminating proxy)──► sequencer node ──► signed state / blocks
                                                     │
   followers ◄──(sequencer-signed snapshots; verify sig + hash-chain + re-execute nXMR/points)
                                                     │
   runtime ──(bridge quorum evidence; optional MoneroRpc)──► Monero node / custody wallet
```

- **User ↔ sequencer:** users trust the sequencer for ordering, inclusion, and honest state.
- **Sequencer ↔ followers:** followers trust the sequencer key for NBLA/nonce/shielded state;
  they independently re-execute nXMR + points and can co-sign blocks. Snapshot validation binds
  each block's `producer` to the configured sequencer validator id, so the per-account
  nXMR/points re-execution cannot be redirected to an attacker-chosen validator id.
- **Runtime ↔ bridge quorum:** the chain trusts the M-of-N quorum to report Monero facts
  honestly (reduced, not removed, by live node proofs + bonds).
- **Bridge ↔ Monero node:** the observer trusts one operator-chosen node/wallet (pinned TLS).

## Out of scope for this testnet

Fully trustless (SPV/light-client or covenant-based) Monero bridging, BFT/decentralized
consensus, zk graph privacy, post-quantum confidential amounts, real-value custody, and an
external security audit. These are documented as future work in [SECURITY.md](SECURITY.md).
