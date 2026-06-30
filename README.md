# <img src="https://raw.githubusercontent.com/pompompur1nn/nebula/master/docs/assets/nebula-logo.svg" alt="" align="left" width="40" height="40"> Nebula

Nebula is a privacy-preserving, quantum-resistant Monero Layer 2.


## Documentation

Soon to be added to https://nebulacha.in.

## What is Nebula?

Nebula is a Monero layer 2 (L2) chain that adds accounting features, and other features that do not exist on the Monero chain whilst maintaining privacy. Everything below is wired into the testnet runtime today — experimental, but real and tested, not a roadmap.

## Why Nebula?

- **Hybrid gas trial:** `NBLA` is the native gas and validator-accounting token, while bridged Monero appears as `nXMR` for gas paths that exercise buyback and reward accounting.

- **Speed:** Unlike other chains, NBLA is built to be fast.

- **Quantum-resistant design:** On the testnet, blocks and transactions can be signed with hybrid Ed25519 + ML-DSA-65 (FIPS 204) signatures — valid only if *both* halves verify — and accounts can hold hybrid keys, so security survives a "Q-day" where one primitive falls. It is opt-in: plain Ed25519 stays the default and remains backward compatible. Unlike chains such as Ethereum, Bitcoin, and Solana, Nebula is built to be futureproof against such attacks.

- **Privacy:** By inheriting Monero's privacy infrastructure, Nebula is built to be private by default. On the testnet, balances can be shielded into Pedersen commitments and moved between shielded notes with Bulletproofs range proofs and a homomorphic balance check, so transfer amounts stay hidden in the state root and value can't be inflated. Privacy onchain shouldn't be opt-in.

- **Monero-native bridge:** Bridge observers can verify each deposit against a real Monero node — address validity, a view-key amount proof, confirmations, and an experimental `tx_extra` binding that names the destination Nebula account — before a configurable M-of-N quorum signs. It is a partially-trusted multisig bridge: the chain trusts the quorum, honestly and by design.

## Quick Start

Generate a quantum-resistant (hybrid) testnet account:

```bash
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --generate-account --scheme hybrid --json
```

Run the local readiness contract:

```bash
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --mainnet-readiness --json
```

Prove the local launch artifact chain:

```bash
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --prove-local-public-testnet --json
```

Prove the stronger loopback RPC devnet:

```bash
cargo run --manifest-path crates/nebula-testnet/Cargo.toml --bin nebula-testnet -- --prove-live-rpc-devnet --json
```

Run the test suite:

```bash
cargo test --workspace -- --test-threads=1
```

## License

This project is licensed under the Nebula Source License. See [LICENSE](https://github.com/pompompur1nn/nebula/blob/master/LICENSE) for details.

Copyright (c) 2026 Nebula contributors.

---

[![Nebula CI](https://github.com/pompompur1nn/nebula/actions/workflows/nebula.yml/badge.svg)](https://github.com/pompompur1nn/nebula/actions/workflows/nebula.yml)
