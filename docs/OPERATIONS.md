# Nebula Node Operations Runbook

This runbook covers running, monitoring, backing up, and upgrading a Nebula node using the
artifacts in this repository (`Dockerfile`, `docker-compose.yml`). Read
[SECURITY.md](../SECURITY.md) and [THREAT_MODEL.md](../THREAT_MODEL.md) first — the chain is an
experimental testnet and `live_value_enabled` must remain `false` until every gate there passes.

## Roles

| Role | Flag | What it does |
|---|---|---|
| Sequencer | `--sequencer` | Produces and signs blocks; needs the sequencer secret key |
| Follower | `--follower` | Syncs sequencer-signed snapshots, verifies the signature + hash chain, and re-executes per-account nXMR + validator points |

`--sequencer` and `--follower` are mutually exclusive. Exactly one sequencer may exist per chain.

## Secrets

Never pass secrets as CLI arguments on shared hosts — use the `-file` variants, which the compose
file mounts as Docker secrets:

- `--sequencer-secret-key-file` — the sequencer signing seed. Bare 64-hex is classical Ed25519;
  scheme-tagged seeds (`hybrid-ed25519-mldsa65:<128 hex>`) enable hybrid post-quantum signing.
- `--admin-token-file` — bearer token required by every admin RPC method.

Before `docker compose up`, create the secret files (never commit them):

```
mkdir -p secrets
head -c 32 /dev/urandom | xxd -p -c 64 > secrets/sequencer_key
head -c 32 /dev/urandom | xxd -p -c 64 > secrets/admin_token
```

The `/health` endpoint reports `default_dev_sequencer_key` — it must be `false` on any
non-development deployment.

## Listeners

- **Public RPC** (`--rpc-bind`, default `127.0.0.1:9944`; the container binds `0.0.0.0:9944`):
  public JSON-RPC methods plus `GET /health` and `GET /metrics`. Terminate TLS in front of it and
  pass client identity with `--trusted-proxy-ip <ip>` so per-client rate limiting keys on the real
  client, not the proxy.
- **Admin RPC** (`--admin-rpc-bind`): privileged methods (`nebula_produceBlock`,
  `nebula_importSnapshot`, bridge/withdrawal/rotation/accountability mutations). Keep it on
  loopback or a private network and never publish the port; the compose file binds it to
  `127.0.0.1:9945` inside the sequencer container only.

## Monitoring

- `GET /health` — JSON gate summary: chain head, roots, launch-binding presence,
  `public_ops_ready`, listener/limit configuration, and key-hygiene flags. Non-`ok` means stop and
  investigate before producing further blocks.
- `GET /metrics` — Prometheus text format for scraping.
- Docker's `HEALTHCHECK` polls `/health` every 15s; `docker compose ps` shows the rollup.
- `nebula_mainnetReadiness` (public RPC) — machine-readable mainnet gate assessment: the
  code-checkable `blocking_gaps` (post-quantum sequencer key, live Monero verifier, quorum policy,
  challenge window, operator/observer bonds, plus every public-ops gate) and the `external_gates`
  that cannot be satisfied by code (external cryptographic audit, HSM/multisig custody ceremony,
  deployment soak, live-value flip authorization). `code_gates_ready` must be `true` and every
  external gate signed off before flipping `live_value_enabled`.

## Backup and restore

State lives under `--data-dir` (the `sequencer-data` / `follower-data` volumes).

1. `nebula_backupManifest` (public RPC) returns the manifest describing what a complete backup
   must contain, bound to the current snapshot root.
2. `nebula_exportSnapshot` returns the full signed snapshot; store it with the manifest.
3. Restore = start a node with an empty data dir and import via `nebula_importSnapshot`
   (admin RPC) or let a follower re-sync from peers; either path re-verifies the sequencer
   signature, hash chain, and re-executed nXMR/points before accepting.

Back up the sequencer secret separately and offline; the chain cannot produce blocks without it,
and rotation (`nebula_rotateSequencerKey`) requires an operator quorum.

## Upgrades

1. Snapshot + manifest backup (above).
2. Stop the node, deploy the new binary/image, restart with the same `--data-dir`.
3. Verify `/health` reports `ok: true`, the expected `runtime_version`, and the pre-upgrade chain
   head, then confirm a follower still accepts newly produced blocks.

A node restart intentionally adopts chain governance from its own verified snapshot; cross-check
governance parameters against peers via the sync quorum after any upgrade.

## Bridge (optional, sequencer only)

Enable live Monero verification with `--monero-wallet-rpc-url`, `--monero-daemon-rpc-url`,
`--monero-custody-address`, and pin the node's TLS leaf with `--monero-cert-pin <sha256>`.
With a live verifier configured, deposits require `check_tx_key` amount + confirmation +
`tx_extra` binding proofs, and withdrawal finalization requires an on-chain-confirmed payout
(settling immediately, no challenge window). Without it, the optimistic
`withdrawal_challenge_window_ms` policy applies. Observers should verify before signing:
`nebula-testnet --verify-monero-deposit ...` or `--sign-bridge-observer-evidence` with
`--wallet-rpc-url`/`--tx-key`/`--bridge-address`.

## Incident response

- **Equivocation observed** (two signed blocks at one height): submit both signed hashes and the
  sequencer's signatures via `nebula_reportEquivocation` (admin). A proven report halts all
  mutations fail-closed until operators intervene.
- **Custody drift**: `nebula_verifyCustody` (admin) reconciles on-chain nXMR against the custody
  wallet when a live verifier is configured.
- **Suspected fraudulent withdrawal** (optimistic mode): `nebula_challengeWithdrawal` (admin)
  before the challenge deadline reverts it and restores the user's burned nXMR escrow.
