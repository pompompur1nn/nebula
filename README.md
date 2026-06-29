# <img src="https://raw.githubusercontent.com/pompompur1nn/nebula/master/docs/assets/nebula-logo.svg" alt="" align="left" width="40" height="40"> Nebula

Nebula is a privacy-preserving Monero Layer 2 testnet runtime for fast private execution, deterministic public launch gates, and operator-owned deployment evidence.


## Documentation

**[Read the testnet runtime guide](https://github.com/pompompur1nn/nebula/blob/master/crates/nebula-testnet/README.md)**, review the [public testnet readiness runbook](https://github.com/pompompur1nn/nebula/blob/master/docs/PUBLIC_TESTNET_READINESS_RUNBOOK.md), or inspect the [Nebula CI checks](https://github.com/pompompur1nn/nebula/actions/workflows/nebula.yml).

## What is Nebula?

Nebula keeps Monero as the external settlement and privacy asset while adding a validator-operated execution layer with sub-second local block production. The runtime is written in Rust and focuses on a public-testnet path where every launch claim is backed by reproducible artifacts: public status, public probes, deployment attestations, validator manifests, launch packages, observer confirmations, runtime-surface evidence, and launch certificates.

The local tooling can prove the full launch mechanics without pretending that a public network is already live. A clean local rehearsal reports `local_testnet_ready: true` while keeping `public_launch_ready: false` until real public deployment evidence is supplied.

## Why Nebula?

- **Private Monero-native settlement:** Bridge policy centers on Monero custody evidence, `nXMR` accounting, replay protection, observer quorum, and withdrawal finalization.

- **Fast local execution:** The Base-style devnet path runs a sequencer with deterministic sub-second blocks while followers import verified Ed25519-signed snapshots.

- **Evidence-first public launch:** Public status, probe, deployment, validator, handoff, acceptance, genesis, launch-package, observer, runtime-surface, and certificate roots must agree before a launch can be called ready.

- **Operator-safe RPC surfaces:** Public RPC, private admin RPC, rate limits, request-size limits, bounded mempool admission, backup status, metrics, and runtime health are separated and verified.

- **Hybrid gas trial:** `NBLA` is the native gas and validator-accounting token, while bridged Monero appears as `nXMR` for gas paths that exercise buyback and reward accounting.

- **Launch-blocked by default:** Missing live deployment attestation is treated as a correct blocker, not a warning to wave away.

## Quick Start

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
cargo test --manifest-path crates/nebula-testnet/Cargo.toml -- --test-threads=1
```

## Public Testnet Status

The expected local readiness shape is:

```json
{
  "local_testnet_ready": true,
  "public_launch_ready": false,
  "public_launch_level": "public-launch-blocked",
  "blocking_gaps": ["public-launch-deployment-attestation"]
}
```

That state is intentional for an operator workspace that has not supplied live public deployment evidence. See the [runtime guide](https://github.com/pompompur1nn/nebula/blob/master/crates/nebula-testnet/README.md) for the full public-testnet architecture and launch sequence.

## License

This project is licensed under the Nebula Source License. See [LICENSE](https://github.com/pompompur1nn/nebula/blob/master/LICENSE) for details.

Copyright (c) 2026 Nebula contributors.

---

[![Nebula CI](https://github.com/pompompur1nn/nebula/actions/workflows/nebula.yml/badge.svg)](https://github.com/pompompur1nn/nebula/actions/workflows/nebula.yml)
