# Nebula Threat Model

**Status: experimental testnet, unaudited, no mainnet, no real value.** This document
enumerates assets, adversaries, trust boundaries, and the outcomes an attacker can achieve,
with the mitigations Nebula implements and the residual gaps. Read alongside
[SECURITY.md](SECURITY.md).

## Assets

| Asset | Where it lives | Protected by |
|---|---|---|
| **NBLA balances** | `RuntimeAccount.nbla_nebulai` in the signed state | Sequencer state signature; per-account Ed25519/hybrid tx signatures + nonces |
| **nXMR balances** | `RuntimeAccount.nxmr_units` | Bridge quorum + (opt-in) node view-key proofs; **follower re-execution** of per-account nXMR |
| **Custody XMR** | Off-chain Monero multisig wallet | M-of-N operators; optional on-chain balance check (`verify_on_chain_custody`); operator bonds |
| **Shielded amounts** | Pedersen commitments in `shielded_notes` | Bulletproofs range proofs + homomorphic balance; amounts hidden, **graph public** |
| **Sequencer signing key** | Operator infrastructure | Out-of-band key management (HSM = ops); equivocation accountability fail-closed |
| **Bridge quorum keys** | Operator/observer infrastructure | Identity-attested launch roster; **slashable bonds**; signer diversity = ops |
| **Validator co-signer keys** | Validator infrastructure | Launch-attested roster; N-of-M block co-signatures |

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
  configurable **withdrawal challenge window** (`finalizing` → `settle`/`challenge` → `reverted`)
  that lets a fraudulent finalization be reverted (refunding the user from the slashed operator
  bond). **Residual:** the window makes the user whole from the bond; it cannot claw back XMR
  already sent on-chain.

### Compromised sequencer key
- Can forge state, censor, or halt the chain. **Mitigations:** followers verify the per-height
  sequencer signature *and* re-execute the replayable columns (per-account nXMR + validator
  points) so silent nXMR/point forgery is caught (`reexecute_replayable_state`); equivocation and
  mis-sign evidence halt all mutations fail-closed (`ensure_accountability_clean`); key rotation
  is scheme-aware and quorum-gated; N-of-M block co-signing (when configured) requires validator
  attestations. **Residual:** NBLA balances, nonces, and the shielded-note set remain
  sequencer-attested (no in-block journal), and censorship/liveness depend on the single
  sequencer — decentralized BFT is future work.

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
  they independently re-execute nXMR + points and can co-sign blocks.
- **Runtime ↔ bridge quorum:** the chain trusts the M-of-N quorum to report Monero facts
  honestly (reduced, not removed, by live node proofs + bonds).
- **Bridge ↔ Monero node:** the observer trusts one operator-chosen node/wallet (pinned TLS).

## Out of scope for this testnet

Fully trustless (SPV/light-client or covenant-based) Monero bridging, BFT/decentralized
consensus, zk graph privacy, post-quantum confidential amounts, real-value custody, and an
external security audit. These are documented as future work in [SECURITY.md](SECURITY.md).
