use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceWithdrawalClaimGateExecutionReceiptRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WITHDRAWAL_CLAIM_GATE_EXECUTION_RECEIPT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-withdrawal-claim-gate-execution-receipt-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WITHDRAWAL_CLAIM_GATE_EXECUTION_RECEIPT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RECEIPT_ENVELOPE_SUITE: &str =
    "monero-l2-pq-bridge-exit-withdrawal-claim-gate-execution-receipt-envelope-v1";
pub const DEFAULT_REFERENCE_HEIGHT: u64 = 4_260_768;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_RELEASE_HOLD_BLOCKS: u64 = 36;
pub const DEFAULT_MIN_RESERVE_CONFIRMATIONS: u64 = 18;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_500;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub receipt_envelope_suite: String,
    pub reference_height: u64,
    pub challenge_window_blocks: u64,
    pub release_hold_blocks: u64,
    pub min_reserve_confirmations: u64,
    pub min_reserve_coverage_bps: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub cargo_runtime_execution_allowed: bool,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            receipt_envelope_suite: RECEIPT_ENVELOPE_SUITE.to_string(),
            reference_height: DEFAULT_REFERENCE_HEIGHT,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            release_hold_blocks: DEFAULT_RELEASE_HOLD_BLOCKS,
            min_reserve_confirmations: DEFAULT_MIN_RESERVE_CONFIRMATIONS,
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            cargo_runtime_execution_allowed: true,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "receipt_envelope_suite": self.receipt_envelope_suite,
            "reference_height": self.reference_height,
            "challenge_window_blocks": self.challenge_window_blocks,
            "release_hold_blocks": self.release_hold_blocks,
            "min_reserve_confirmations": self.min_reserve_confirmations,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "cargo_runtime_execution_allowed": self.cargo_runtime_execution_allowed,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptEnvelope {
    pub envelope_id: String,
    pub lane: String,
    pub status: String,
    pub subject_root: String,
    pub evidence_root: String,
    pub redaction_root: String,
    pub wallet_visible: bool,
    pub operator_visible: bool,
    pub fail_closed: bool,
}

impl ReceiptEnvelope {
    pub fn new(
        lane: impl Into<String>,
        status: impl Into<String>,
        subject_root: impl Into<String>,
        evidence_root: impl Into<String>,
        redaction_root: impl Into<String>,
        wallet_visible: bool,
        operator_visible: bool,
        fail_closed: bool,
    ) -> Self {
        let lane = lane.into();
        let status = status.into();
        let subject_root = subject_root.into();
        let evidence_root = evidence_root.into();
        let redaction_root = redaction_root.into();
        let envelope_id = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-GATE-EXECUTION-RECEIPT-ENVELOPE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&lane),
                HashPart::Str(&status),
                HashPart::Str(&subject_root),
                HashPart::Str(&evidence_root),
                HashPart::Str(bool_str(fail_closed)),
            ],
            32,
        );

        Self {
            envelope_id,
            lane,
            status,
            subject_root,
            evidence_root,
            redaction_root,
            wallet_visible,
            operator_visible,
            fail_closed,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "envelope_id": self.envelope_id,
            "lane": self.lane,
            "status": self.status,
            "subject_root": self.subject_root,
            "evidence_root": self.evidence_root,
            "redaction_root": self.redaction_root,
            "wallet_visible": self.wallet_visible,
            "operator_visible": self.operator_visible,
            "fail_closed": self.fail_closed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("receipt_envelope", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptEnvelopeEvidence {
    pub claim_authorization_accepted: ReceiptEnvelope,
    pub settlement_receipt_checked: ReceiptEnvelope,
    pub challenge_window_checked: ReceiptEnvelope,
    pub reserve_proof_checked: ReceiptEnvelope,
    pub pq_withdrawal_authorization: ReceiptEnvelope,
    pub wallet_recovery_payload_root: ReceiptEnvelope,
    pub privacy_preserving_proof_export: ReceiptEnvelope,
    pub expected_invocation_root: ReceiptEnvelope,
    pub expected_preflight_root: ReceiptEnvelope,
    pub operator_evidence_root: ReceiptEnvelope,
    pub wallet_visible_receipt_root: ReceiptEnvelope,
    pub fail_closed_receipt_root: ReceiptEnvelope,
    pub production_release_hold: ReceiptEnvelope,
}

impl ReceiptEnvelopeEvidence {
    pub fn devnet(config: &Config) -> Self {
        let claim_id = label_root("claim", "devnet-withdrawal-claim-0001");
        let claim_authorization_root = evidence_root(
            "claim_authorization_accepted",
            &json!({
                "claim_id": claim_id,
                "claim_commitment_root": label_root("claim-commitment", "claim-commitment"),
                "authorization_policy_root": label_root("policy", "withdrawal-claim-authorization"),
                "quorum_root": label_root("quorum", "pq-claim-signers"),
                "accepted": true,
            }),
        );
        let settlement_root = evidence_root(
            "settlement_receipt_checked",
            &json!({
                "settlement_id": label_root("settlement", "devnet-settlement-0001"),
                "canonical_exit_root": label_root("canonical-exit", "forced-exit-spine"),
                "settlement_receipt_root": label_root("receipt", "settlement-receipt"),
                "checked_at_height": config.reference_height,
                "checked": true,
            }),
        );
        let challenge_root = evidence_root(
            "challenge_window_checked",
            &json!({
                "opened_at_height": config.reference_height - config.challenge_window_blocks - config.release_hold_blocks,
                "closed_at_height": config.reference_height - config.release_hold_blocks,
                "observed_height": config.reference_height,
                "unresolved_challenges": 0_u64,
                "elapsed": true,
            }),
        );
        let reserve_root = evidence_root(
            "reserve_proof_checked",
            &json!({
                "reserve_commitment_root": label_root("reserve", "xmr-reserve"),
                "liability_commitment_root": label_root("liability", "withdrawal-liability"),
                "confirmations": config.min_reserve_confirmations,
                "coverage_bps": config.min_reserve_coverage_bps,
                "sufficient": true,
            }),
        );
        let pq_root = evidence_root(
            "pq_withdrawal_authorization",
            &json!({
                "scheme": "ml-dsa-87+kyber768-transcript-v1",
                "security_bits": config.min_pq_security_bits,
                "signature_bundle_root": label_root("signature", "pq-signature-bundle"),
                "authorization_transcript_root": label_root("withdrawal-transcript", "withdrawal-call"),
                "verified": true,
            }),
        );
        let wallet_recovery_root = evidence_root(
            "wallet_recovery_payload_root",
            &json!({
                "encrypted_payload_root": label_root("encrypted-payload", "wallet-recovery-ciphertext"),
                "recipient_commitment_root": label_root("recipient", "claimant-recovery-recipient"),
                "scan_hint_root": label_root("scan-hint", "redacted-wallet-scan-hint"),
                "available": true,
            }),
        );
        let privacy_export_root = evidence_root(
            "privacy_preserving_proof_export",
            &json!({
                "proof_system": "plonkish-redacted-withdrawal-export-v1",
                "public_inputs_root": label_root("public-inputs", "withdrawal-public-inputs"),
                "redacted_witness_root": label_root("redacted-witness", "claim-witness"),
                "privacy_set_size": config.min_privacy_set_size,
                "verified": true,
            }),
        );
        let expected_invocation_root = invocation_root(
            "withdrawal_claim_gate_execution_receipt_runtime",
            "execution_receipt",
            &claim_id,
            &settlement_root,
        );
        let expected_preflight_root = invocation_root(
            "withdrawal_claim_gate_preflight_runtime",
            "preflight",
            &claim_id,
            &claim_authorization_root,
        );
        let operator_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-GATE-EXECUTION-OPERATOR-EVIDENCE",
            &[
                claim_authorization_root.clone(),
                settlement_root.clone(),
                challenge_root.clone(),
                reserve_root.clone(),
                pq_root.clone(),
            ],
        );
        let wallet_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-GATE-EXECUTION-WALLET-VISIBLE",
            &[
                claim_authorization_root.clone(),
                settlement_root.clone(),
                wallet_recovery_root.clone(),
                privacy_export_root.clone(),
                expected_invocation_root.clone(),
            ],
        );
        let fail_closed_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-GATE-EXECUTION-FAIL-CLOSED",
            &[
                fail_closed_reason_root("missing_claim_authorization", &claim_id),
                fail_closed_reason_root("settlement_receipt_unchecked", &claim_id),
                fail_closed_reason_root("challenge_window_not_elapsed", &claim_id),
                fail_closed_reason_root("reserve_proof_insufficient", &claim_id),
                fail_closed_reason_root("pq_authorization_invalid", &claim_id),
                fail_closed_reason_root("privacy_export_unavailable", &claim_id),
                fail_closed_reason_root("unexpected_invocation_root", &claim_id),
                fail_closed_reason_root("production_release_hold_active", &claim_id),
            ],
        );
        let release_hold_root = evidence_root(
            "production_release_hold",
            &json!({
                "cargo_runtime_execution_allowed": config.cargo_runtime_execution_allowed,
                "production_release_allowed": config.production_release_allowed,
                "release_hold_blocks": config.release_hold_blocks,
                "hold_reason": "execution receipt evidence is deterministic while production release remains gated",
                "deferred": !config.production_release_allowed,
            }),
        );

        Self {
            claim_authorization_accepted: ReceiptEnvelope::new(
                "claim_authorization_accepted",
                "accepted",
                &claim_id,
                claim_authorization_root,
                label_root("redaction", "claim-authorization-wallet-safe"),
                true,
                true,
                true,
            ),
            settlement_receipt_checked: ReceiptEnvelope::new(
                "settlement_receipt_checked",
                "checked",
                &claim_id,
                settlement_root,
                label_root("redaction", "settlement-receipt-wallet-safe"),
                true,
                true,
                true,
            ),
            challenge_window_checked: ReceiptEnvelope::new(
                "challenge_window_checked",
                "checked",
                &claim_id,
                challenge_root,
                label_root("redaction", "challenge-window-public-safe"),
                true,
                true,
                true,
            ),
            reserve_proof_checked: ReceiptEnvelope::new(
                "reserve_proof_checked",
                "checked",
                &claim_id,
                reserve_root,
                label_root("redaction", "reserve-proof-committed-only"),
                false,
                true,
                true,
            ),
            pq_withdrawal_authorization: ReceiptEnvelope::new(
                "pq_withdrawal_authorization",
                "authorized",
                &claim_id,
                pq_root,
                label_root("redaction", "pq-auth-signature-hidden"),
                true,
                true,
                true,
            ),
            wallet_recovery_payload_root: ReceiptEnvelope::new(
                "wallet_recovery_payload_root",
                "available",
                &claim_id,
                wallet_recovery_root,
                label_root("redaction", "wallet-recovery-ciphertext-only"),
                true,
                false,
                true,
            ),
            privacy_preserving_proof_export: ReceiptEnvelope::new(
                "privacy_preserving_proof_export",
                "exported",
                &claim_id,
                privacy_export_root,
                label_root("redaction", "privacy-proof-no-witness"),
                true,
                true,
                true,
            ),
            expected_invocation_root: ReceiptEnvelope::new(
                "expected_invocation_root",
                "matched",
                &claim_id,
                expected_invocation_root,
                label_root("redaction", "expected-invocation-public"),
                true,
                true,
                true,
            ),
            expected_preflight_root: ReceiptEnvelope::new(
                "expected_preflight_root",
                "matched",
                &claim_id,
                expected_preflight_root,
                label_root("redaction", "expected-preflight-public"),
                true,
                true,
                true,
            ),
            operator_evidence_root: ReceiptEnvelope::new(
                "operator_evidence_root",
                "committed",
                &claim_id,
                operator_root,
                label_root("redaction", "operator-evidence-aggregate"),
                false,
                true,
                true,
            ),
            wallet_visible_receipt_root: ReceiptEnvelope::new(
                "wallet_visible_receipt_root",
                "committed",
                &claim_id,
                wallet_root,
                label_root("redaction", "wallet-visible-aggregate"),
                true,
                false,
                true,
            ),
            fail_closed_receipt_root: ReceiptEnvelope::new(
                "fail_closed_receipt_root",
                "armed",
                &claim_id,
                fail_closed_root,
                label_root("redaction", "negative-path-aggregate"),
                true,
                true,
                true,
            ),
            production_release_hold: ReceiptEnvelope::new(
                "production_release_hold",
                "deferred",
                &claim_id,
                release_hold_root,
                label_root("redaction", "release-hold-public"),
                true,
                true,
                true,
            ),
        }
    }

    pub fn envelopes(&self) -> Vec<ReceiptEnvelope> {
        vec![
            self.claim_authorization_accepted.clone(),
            self.settlement_receipt_checked.clone(),
            self.challenge_window_checked.clone(),
            self.reserve_proof_checked.clone(),
            self.pq_withdrawal_authorization.clone(),
            self.wallet_recovery_payload_root.clone(),
            self.privacy_preserving_proof_export.clone(),
            self.expected_invocation_root.clone(),
            self.expected_preflight_root.clone(),
            self.operator_evidence_root.clone(),
            self.wallet_visible_receipt_root.clone(),
            self.fail_closed_receipt_root.clone(),
            self.production_release_hold.clone(),
        ]
    }

    pub fn public_record(&self) -> Value {
        json!({
            "claim_authorization_accepted": self.claim_authorization_accepted.public_record(),
            "settlement_receipt_checked": self.settlement_receipt_checked.public_record(),
            "challenge_window_checked": self.challenge_window_checked.public_record(),
            "reserve_proof_checked": self.reserve_proof_checked.public_record(),
            "pq_withdrawal_authorization": self.pq_withdrawal_authorization.public_record(),
            "wallet_recovery_payload_root": self.wallet_recovery_payload_root.public_record(),
            "privacy_preserving_proof_export": self.privacy_preserving_proof_export.public_record(),
            "expected_invocation_root": self.expected_invocation_root.public_record(),
            "expected_preflight_root": self.expected_preflight_root.public_record(),
            "operator_evidence_root": self.operator_evidence_root.public_record(),
            "wallet_visible_receipt_root": self.wallet_visible_receipt_root.public_record(),
            "fail_closed_receipt_root": self.fail_closed_receipt_root.public_record(),
            "production_release_hold": self.production_release_hold.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-GATE-EXECUTION-RECEIPT-EVIDENCE",
            &self
                .envelopes()
                .iter()
                .map(ReceiptEnvelope::state_root)
                .collect::<Vec<_>>(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub receipt_evidence: ReceiptEnvelopeEvidence,
    pub envelope_root: String,
    pub operator_evidence_root: String,
    pub wallet_visible_receipt_root: String,
    pub fail_closed_receipt_root: String,
    pub release_hold_root: String,
    pub evidence_roots: BTreeMap<String, String>,
    pub execution_receipt_accepted: bool,
    pub production_release_held: bool,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let receipt_evidence = ReceiptEnvelopeEvidence::devnet(&config);
        let envelope_root = receipt_evidence.state_root();
        let operator_evidence_root = receipt_evidence
            .operator_evidence_root
            .evidence_root
            .clone();
        let wallet_visible_receipt_root = receipt_evidence
            .wallet_visible_receipt_root
            .evidence_root
            .clone();
        let fail_closed_receipt_root = receipt_evidence
            .fail_closed_receipt_root
            .evidence_root
            .clone();
        let release_hold_root = receipt_evidence
            .production_release_hold
            .evidence_root
            .clone();
        let evidence_roots = evidence_map(&receipt_evidence);
        let execution_receipt_accepted = config.cargo_runtime_execution_allowed
            && receipt_evidence
                .envelopes()
                .iter()
                .all(|envelope| envelope.fail_closed)
            && receipt_evidence.claim_authorization_accepted.status == "accepted"
            && receipt_evidence.settlement_receipt_checked.status == "checked"
            && receipt_evidence.challenge_window_checked.status == "checked"
            && receipt_evidence.reserve_proof_checked.status == "checked"
            && receipt_evidence.pq_withdrawal_authorization.status == "authorized";
        let production_release_held = !config.production_release_allowed
            && receipt_evidence.production_release_hold.status == "deferred";

        Self {
            config,
            receipt_evidence,
            envelope_root,
            operator_evidence_root,
            wallet_visible_receipt_root,
            fail_closed_receipt_root,
            release_hold_root,
            evidence_roots,
            execution_receipt_accepted,
            production_release_held,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "receipt_evidence": self.receipt_evidence.public_record(),
            "envelope_root": self.envelope_root,
            "operator_evidence_root": self.operator_evidence_root,
            "wallet_visible_receipt_root": self.wallet_visible_receipt_root,
            "fail_closed_receipt_root": self.fail_closed_receipt_root,
            "release_hold_root": self.release_hold_root,
            "evidence_roots": self.evidence_roots,
            "execution_receipt_accepted": self.execution_receipt_accepted,
            "production_release_held": self.production_release_held,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-GATE-EXECUTION-RECEIPT-STATE",
            &[
                HashPart::Str(&self.config.chain_id),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(SCHEMA_VERSION),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.receipt_evidence.state_root()),
                HashPart::Str(&self.envelope_root),
                HashPart::Str(&self.operator_evidence_root),
                HashPart::Str(&self.wallet_visible_receipt_root),
                HashPart::Str(&self.fail_closed_receipt_root),
                HashPart::Str(&self.release_hold_root),
                HashPart::Str(&evidence_map_root(&self.evidence_roots)),
                HashPart::Str(bool_str(self.execution_receipt_accepted)),
                HashPart::Str(bool_str(self.production_release_held)),
            ],
            32,
        )
    }
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
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

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-GATE-EXECUTION-RECEIPT-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::U64(SCHEMA_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn evidence_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-GATE-EXECUTION-RECEIPT-EVIDENCE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn label_root(kind: &str, label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-GATE-EXECUTION-RECEIPT-LABEL",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn invocation_root(
    expected_runtime: &str,
    expected_function: &str,
    claim_id: &str,
    anchor_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-GATE-EXECUTION-RECEIPT-INVOCATION",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(expected_runtime),
            HashPart::Str(expected_function),
            HashPart::Str(claim_id),
            HashPart::Str(anchor_root),
        ],
        32,
    )
}

pub fn fail_closed_reason_root(reason: &str, claim_id: &str) -> String {
    record_root(
        "fail_closed_reason",
        &json!({
            "reason": reason,
            "claim_id": claim_id,
            "action": "reject_withdrawal_claim_execution_receipt",
            "release_allowed": false,
        }),
    )
}

pub fn evidence_map(evidence: &ReceiptEnvelopeEvidence) -> BTreeMap<String, String> {
    let mut roots = BTreeMap::new();
    for envelope in evidence.envelopes() {
        roots.insert(envelope.lane, envelope.evidence_root);
    }
    roots
}

pub fn evidence_map_root(records: &BTreeMap<String, String>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-GATE-EXECUTION-RECEIPT-EVIDENCE-MAP",
        &leaves,
    )
}

pub fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
