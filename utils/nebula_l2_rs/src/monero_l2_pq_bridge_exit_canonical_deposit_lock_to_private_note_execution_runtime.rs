use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalDepositLockToPrivateNoteExecutionRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_DEPOSIT_LOCK_TO_PRIVATE_NOTE_EXECUTION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-deposit-lock-to-private-note-execution-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_DEPOSIT_LOCK_TO_PRIVATE_NOTE_EXECUTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";

pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEFAULT_MONERO_LOCK_HEIGHT: u64 = 3_518_240;
pub const DEFAULT_MONERO_OBSERVED_HEIGHT: u64 = 3_518_266;
pub const DEFAULT_L2_EXECUTION_HEIGHT: u64 = 4_233_920;
pub const DEFAULT_MIN_CONFIRMATIONS: u64 = 18;
pub const DEFAULT_REORG_SAFETY_MARGIN: u64 = 6;
pub const DEFAULT_MIN_WATCHER_WEIGHT: u64 = 5;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub monero_network: String,
    pub l2_network: String,
    pub monero_lock_height: u64,
    pub monero_observed_height: u64,
    pub l2_execution_height: u64,
    pub min_confirmations: u64,
    pub reorg_safety_margin: u64,
    pub min_watcher_weight: u64,
    pub min_privacy_set_size: u64,
    pub fail_closed_on_reorg_risk: bool,
    pub fail_closed_on_attestation_gap: bool,
    pub fail_closed_on_privacy_leak: bool,
    pub fail_closed_on_note_mismatch: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_lock_height: DEFAULT_MONERO_LOCK_HEIGHT,
            monero_observed_height: DEFAULT_MONERO_OBSERVED_HEIGHT,
            l2_execution_height: DEFAULT_L2_EXECUTION_HEIGHT,
            min_confirmations: DEFAULT_MIN_CONFIRMATIONS,
            reorg_safety_margin: DEFAULT_REORG_SAFETY_MARGIN,
            min_watcher_weight: DEFAULT_MIN_WATCHER_WEIGHT,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            fail_closed_on_reorg_risk: true,
            fail_closed_on_attestation_gap: true,
            fail_closed_on_privacy_leak: true,
            fail_closed_on_note_mismatch: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "monero_lock_height": self.monero_lock_height,
            "monero_observed_height": self.monero_observed_height,
            "l2_execution_height": self.l2_execution_height,
            "min_confirmations": self.min_confirmations,
            "reorg_safety_margin": self.reorg_safety_margin,
            "min_watcher_weight": self.min_watcher_weight,
            "min_privacy_set_size": self.min_privacy_set_size,
            "fail_closed": {
                "reorg_risk": self.fail_closed_on_reorg_risk,
                "attestation_gap": self.fail_closed_on_attestation_gap,
                "privacy_leak": self.fail_closed_on_privacy_leak,
                "note_mismatch": self.fail_closed_on_note_mismatch
            }
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MoneroLockEvidence {
    pub lock_id: String,
    pub txid: String,
    pub output_index: u64,
    pub amount_piconero_commitment: String,
    pub custody_address_commitment: String,
    pub key_image_absence_root: String,
    pub lock_height: u64,
    pub observed_height: u64,
    pub header_hash: String,
    pub tx_merkle_proof_root: String,
}

impl MoneroLockEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "lock_id": self.lock_id,
            "txid": self.txid,
            "output_index": self.output_index,
            "amount_piconero_commitment": self.amount_piconero_commitment,
            "custody_address_commitment": self.custody_address_commitment,
            "key_image_absence_root": self.key_image_absence_root,
            "lock_height": self.lock_height,
            "observed_height": self.observed_height,
            "header_hash": self.header_hash,
            "tx_merkle_proof_root": self.tx_merkle_proof_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherPqAttestation {
    pub watcher_id: String,
    pub pq_scheme: String,
    pub public_key_commitment: String,
    pub lock_id: String,
    pub observed_header_hash: String,
    pub attestation_root: String,
    pub signature_commitment: String,
    pub weight: u64,
}

impl WatcherPqAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "watcher_id": self.watcher_id,
            "pq_scheme": self.pq_scheme,
            "public_key_commitment": self.public_key_commitment,
            "lock_id": self.lock_id,
            "observed_header_hash": self.observed_header_hash,
            "attestation_root": self.attestation_root,
            "signature_commitment": self.signature_commitment,
            "weight": self.weight
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DepositFinality {
    pub lock_id: String,
    pub confirmations: u64,
    pub reorg_margin: u64,
    pub canonical_header_root: String,
    pub competing_header_root: String,
    pub status: String,
}

impl DepositFinality {
    pub fn public_record(&self) -> Value {
        json!({
            "lock_id": self.lock_id,
            "confirmations": self.confirmations,
            "reorg_margin": self.reorg_margin,
            "canonical_header_root": self.canonical_header_root,
            "competing_header_root": self.competing_header_root,
            "status": self.status
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyRedaction {
    pub lock_id: String,
    pub redaction_policy: String,
    pub disclosed_fields: Vec<String>,
    pub redacted_fields: Vec<String>,
    pub privacy_set_size: u64,
    pub redacted_deposit_root: String,
    pub audit_hint_root: String,
}

impl PrivacyRedaction {
    pub fn public_record(&self) -> Value {
        json!({
            "lock_id": self.lock_id,
            "redaction_policy": self.redaction_policy,
            "disclosed_fields": self.disclosed_fields,
            "redacted_fields": self.redacted_fields,
            "privacy_set_size": self.privacy_set_size,
            "redacted_deposit_root": self.redacted_deposit_root,
            "audit_hint_root": self.audit_hint_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateNoteCommitment {
    pub note_id: String,
    pub lock_id: String,
    pub recipient_view_tag: String,
    pub asset_commitment: String,
    pub amount_commitment: String,
    pub nullifier_commitment: String,
    pub note_commitment: String,
    pub note_merkle_leaf: String,
}

impl PrivateNoteCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "lock_id": self.lock_id,
            "recipient_view_tag": self.recipient_view_tag,
            "asset_commitment": self.asset_commitment,
            "amount_commitment": self.amount_commitment,
            "nullifier_commitment": self.nullifier_commitment,
            "note_commitment": self.note_commitment,
            "note_merkle_leaf": self.note_merkle_leaf
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletScanHint {
    pub hint_id: String,
    pub note_id: String,
    pub scan_epoch: u64,
    pub view_tag: String,
    pub encrypted_hint_commitment: String,
    pub recovery_hint_root: String,
}

impl WalletScanHint {
    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "note_id": self.note_id,
            "scan_epoch": self.scan_epoch,
            "view_tag": self.view_tag,
            "encrypted_hint_commitment": self.encrypted_hint_commitment,
            "recovery_hint_root": self.recovery_hint_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FailClosedBlocker {
    pub blocker_id: String,
    pub scope: String,
    pub active: bool,
    pub severity: String,
    pub evidence_root: String,
    pub resolution_gate: String,
}

impl FailClosedBlocker {
    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "scope": self.scope,
            "active": self.active,
            "severity": self.severity,
            "evidence_root": self.evidence_root,
            "resolution_gate": self.resolution_gate
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub lock_evidence: MoneroLockEvidence,
    pub watcher_attestations: Vec<WatcherPqAttestation>,
    pub finality: DepositFinality,
    pub privacy_redaction: PrivacyRedaction,
    pub note_commitment: PrivateNoteCommitment,
    pub wallet_scan_hints: Vec<WalletScanHint>,
    pub fail_closed_blockers: Vec<FailClosedBlocker>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let lock_id = scoped_hash("lock-id", "monero-devnet-lock-0007");
        let txid = scoped_hash("monero-txid", "deposit-lock-tx-0007");
        let header_hash = scoped_hash("monero-header", "height-3518240-main");
        let lock_evidence = MoneroLockEvidence {
            lock_id: lock_id.clone(),
            txid: txid.clone(),
            output_index: 2,
            amount_piconero_commitment: scoped_hash("amount-commitment", "xmr-12-500000000000"),
            custody_address_commitment: scoped_hash(
                "custody-address-commitment",
                "bridge-custody-subaddress-17",
            ),
            key_image_absence_root: scoped_hash("key-image-absence", "no-spend-at-observation"),
            lock_height: config.monero_lock_height,
            observed_height: config.monero_observed_height,
            header_hash: header_hash.clone(),
            tx_merkle_proof_root: scoped_hash("tx-merkle-proof", "deposit-lock-tx-0007-proof"),
        };

        let watcher_attestations = vec![
            watcher_attestation("watcher-alpha", "ML-DSA-65", &lock_id, &header_hash, 3),
            watcher_attestation(
                "watcher-bravo",
                "SLH-DSA-SHAKE-128s",
                &lock_id,
                &header_hash,
                2,
            ),
            watcher_attestation("watcher-charlie", "Falcon-512", &lock_id, &header_hash, 1),
        ];

        let confirmations = config.monero_observed_height - config.monero_lock_height;
        let finality = DepositFinality {
            lock_id: lock_id.clone(),
            confirmations,
            reorg_margin: confirmations.saturating_sub(config.min_confirmations),
            canonical_header_root: merkle_root(
                "monero-l2-deposit-lock-to-note:canonical-headers",
                &[
                    json!({"height": config.monero_lock_height, "hash": header_hash}),
                    json!({"height": config.monero_observed_height, "hash": scoped_hash("monero-header", "height-3518266-main")}),
                ],
            ),
            competing_header_root: merkle_root(
                "monero-l2-deposit-lock-to-note:competing-headers",
                &[],
            ),
            status: "mature".to_string(),
        };

        let redacted_deposit_root = hash_json(
            "redacted-deposit",
            &json!({
                "lock_id": lock_id,
                "txid": txid,
                "output_index": lock_evidence.output_index,
                "amount": "commitment_only",
                "recipient": "commitment_only",
                "monero_origin": "redacted"
            }),
        );
        let privacy_redaction = PrivacyRedaction {
            lock_id: lock_id.clone(),
            redaction_policy: "commitments-only-public-spine-v1".to_string(),
            disclosed_fields: vec![
                "lock_id".to_string(),
                "txid".to_string(),
                "output_index".to_string(),
                "confirmation_depth".to_string(),
            ],
            redacted_fields: vec![
                "amount_piconero".to_string(),
                "sender_view_key".to_string(),
                "recipient_private_address".to_string(),
                "monero_decoy_set".to_string(),
            ],
            privacy_set_size: 65_536,
            redacted_deposit_root,
            audit_hint_root: scoped_hash("audit-hint-root", "deposit-lock-0007-redacted-audit"),
        };

        let note_commitment = private_note_commitment(&lock_id, &lock_evidence, &privacy_redaction);
        let wallet_scan_hints = vec![
            wallet_scan_hint("hint-primary", &note_commitment, 42),
            wallet_scan_hint("hint-recovery", &note_commitment, 43),
        ];
        let fail_closed_blockers = vec![
            FailClosedBlocker {
                blocker_id: "blocker-reorg-competing-header".to_string(),
                scope: "deposit_finality".to_string(),
                active: false,
                severity: "critical".to_string(),
                evidence_root: finality.competing_header_root.clone(),
                resolution_gate: "no competing header root observed inside safety margin"
                    .to_string(),
            },
            FailClosedBlocker {
                blocker_id: "blocker-watcher-quorum-gap".to_string(),
                scope: "pq_attestation".to_string(),
                active: false,
                severity: "critical".to_string(),
                evidence_root: merkle_root(
                    "monero-l2-deposit-lock-to-note:watcher-attestations",
                    &watcher_attestations
                        .iter()
                        .map(WatcherPqAttestation::public_record)
                        .collect::<Vec<_>>(),
                ),
                resolution_gate: "watcher weight meets or exceeds configured minimum".to_string(),
            },
            FailClosedBlocker {
                blocker_id: "blocker-private-note-mismatch".to_string(),
                scope: "private_note_commitment".to_string(),
                active: false,
                severity: "critical".to_string(),
                evidence_root: note_commitment.note_commitment.clone(),
                resolution_gate: "note leaf binds lock evidence and redacted deposit root"
                    .to_string(),
            },
        ];

        Self {
            config,
            lock_evidence,
            watcher_attestations,
            finality,
            privacy_redaction,
            note_commitment,
            wallet_scan_hints,
            fail_closed_blockers,
        }
    }

    pub fn watcher_weight(&self) -> u64 {
        self.watcher_attestations
            .iter()
            .map(|attestation| attestation.weight)
            .sum()
    }

    pub fn ready_to_mint_private_note(&self) -> bool {
        self.finality.status == "mature"
            && self.watcher_weight() >= self.config.min_watcher_weight
            && self.privacy_redaction.privacy_set_size >= self.config.min_privacy_set_size
            && !self
                .fail_closed_blockers
                .iter()
                .any(|blocker| blocker.active)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_deposit_lock_to_private_note_execution_runtime_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "config": self.config.public_record(),
            "lock_evidence": self.lock_evidence.public_record(),
            "watcher_attestations": self.watcher_attestations.iter().map(WatcherPqAttestation::public_record).collect::<Vec<_>>(),
            "deposit_finality": self.finality.public_record(),
            "privacy_redaction": self.privacy_redaction.public_record(),
            "note_commitment": self.note_commitment.public_record(),
            "wallet_scan_hints": self.wallet_scan_hints.iter().map(WalletScanHint::public_record).collect::<Vec<_>>(),
            "fail_closed_blockers": self.fail_closed_blockers.iter().map(FailClosedBlocker::public_record).collect::<Vec<_>>(),
            "watcher_weight": self.watcher_weight(),
            "ready_to_mint_private_note": self.ready_to_mint_private_note(),
            "state_root": self.state_root()
        })
    }

    pub fn state_root(&self) -> String {
        let leaves = vec![
            self.config.public_record(),
            self.lock_evidence.public_record(),
            json!(self
                .watcher_attestations
                .iter()
                .map(WatcherPqAttestation::public_record)
                .collect::<Vec<_>>()),
            self.finality.public_record(),
            self.privacy_redaction.public_record(),
            self.note_commitment.public_record(),
            json!(self
                .wallet_scan_hints
                .iter()
                .map(WalletScanHint::public_record)
                .collect::<Vec<_>>()),
            json!(self
                .fail_closed_blockers
                .iter()
                .map(FailClosedBlocker::public_record)
                .collect::<Vec<_>>()),
        ];
        merkle_root(
            "monero-l2-pq-bridge-exit-canonical-deposit-lock-to-private-note:state",
            &leaves,
        )
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn watcher_attestation(
    watcher_id: &str,
    pq_scheme: &str,
    lock_id: &str,
    observed_header_hash: &str,
    weight: u64,
) -> WatcherPqAttestation {
    let payload = json!({
        "watcher_id": watcher_id,
        "pq_scheme": pq_scheme,
        "lock_id": lock_id,
        "observed_header_hash": observed_header_hash,
        "weight": weight
    });
    WatcherPqAttestation {
        watcher_id: watcher_id.to_string(),
        pq_scheme: pq_scheme.to_string(),
        public_key_commitment: hash_json("watcher-public-key", &payload),
        lock_id: lock_id.to_string(),
        observed_header_hash: observed_header_hash.to_string(),
        attestation_root: hash_json("watcher-attestation", &payload),
        signature_commitment: scoped_hash("watcher-signature", watcher_id),
        weight,
    }
}

fn private_note_commitment(
    lock_id: &str,
    lock_evidence: &MoneroLockEvidence,
    privacy_redaction: &PrivacyRedaction,
) -> PrivateNoteCommitment {
    let note_id = scoped_hash("private-note-id", lock_id);
    let asset_commitment = scoped_hash("asset-commitment", "xmr-native-private-l2");
    let amount_commitment = lock_evidence.amount_piconero_commitment.clone();
    let nullifier_commitment = scoped_hash("nullifier-commitment", lock_id);
    let note_payload = json!({
        "note_id": note_id,
        "lock_id": lock_id,
        "asset_commitment": asset_commitment,
        "amount_commitment": amount_commitment,
        "nullifier_commitment": nullifier_commitment,
        "redacted_deposit_root": privacy_redaction.redacted_deposit_root
    });
    let note_commitment = hash_json("private-note-commitment", &note_payload);
    PrivateNoteCommitment {
        note_id,
        lock_id: lock_id.to_string(),
        recipient_view_tag: "7f".to_string(),
        asset_commitment,
        amount_commitment,
        nullifier_commitment,
        note_merkle_leaf: scoped_hash("private-note-leaf", &note_commitment),
        note_commitment,
    }
}

fn wallet_scan_hint(
    hint_id: &str,
    note: &PrivateNoteCommitment,
    scan_epoch: u64,
) -> WalletScanHint {
    let payload = json!({
        "hint_id": hint_id,
        "note_id": note.note_id,
        "scan_epoch": scan_epoch,
        "view_tag": note.recipient_view_tag
    });
    WalletScanHint {
        hint_id: hint_id.to_string(),
        note_id: note.note_id.clone(),
        scan_epoch,
        view_tag: note.recipient_view_tag.clone(),
        encrypted_hint_commitment: hash_json("wallet-scan-encrypted-hint", &payload),
        recovery_hint_root: hash_json("wallet-scan-recovery-root", &payload),
    }
}

fn scoped_hash(domain: &str, value: &str) -> String {
    domain_hash(
        &format!("monero-l2-deposit-lock-to-private-note:{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Str(value)],
        32,
    )
}

fn hash_json(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("monero-l2-deposit-lock-to-private-note:{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(value)],
        32,
    )
}
