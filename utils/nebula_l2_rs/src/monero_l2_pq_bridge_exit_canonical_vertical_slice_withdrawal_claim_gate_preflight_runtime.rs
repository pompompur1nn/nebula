use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceWithdrawalClaimGatePreflightRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WITHDRAWAL_CLAIM_GATE_PREFLIGHT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-withdrawal-claim-gate-preflight-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WITHDRAWAL_CLAIM_GATE_PREFLIGHT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PREFLIGHT_SUITE: &str = "monero-l2-pq-bridge-exit-withdrawal-claim-gate-preflight-v1";
pub const DEFAULT_DEVNET_HEIGHT: u64 = 4_260_512;
pub const DEFAULT_MIN_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_RELEASE_HOLD_BLOCKS: u64 = 36;
pub const DEFAULT_MIN_RESERVE_CONFIRMATIONS: u64 = 18;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_REQUIRED_QUORUM_WEIGHT: u64 = 5;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub preflight_suite: String,
    pub reference_height: u64,
    pub min_challenge_window_blocks: u64,
    pub release_hold_blocks: u64,
    pub min_reserve_confirmations: u64,
    pub min_privacy_set_size: u64,
    pub required_quorum_weight: u64,
    pub cargo_runtime_execution_allowed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ClaimAuthorization {
    pub claim_id: String,
    pub claimant_commitment: String,
    pub exit_nullifier_root: String,
    pub claim_commitment_root: String,
    pub authorization_policy_root: String,
    pub signer_quorum_root: String,
    pub observed_quorum_weight: u64,
    pub authorization_digest: String,
    pub authorized: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SettlementReceipt {
    pub settlement_id: String,
    pub settlement_receipt_root: String,
    pub canonical_exit_root: String,
    pub settlement_amount_commitment: String,
    pub fee_receipt_root: String,
    pub paid_to_withdrawal_address_root: String,
    pub settled_at_height: u64,
    pub receipt_verified: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ChallengeWindow {
    pub challenge_id: String,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
    pub observed_height: u64,
    pub required_window_blocks: u64,
    pub dispute_registry_root: String,
    pub unresolved_disputes: u64,
    pub elapsed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReserveProof {
    pub reserve_proof_id: String,
    pub reserve_commitment_root: String,
    pub monero_header_root: String,
    pub output_set_root: String,
    pub liability_commitment_root: String,
    pub confirmations: u64,
    pub surplus_commitment_root: String,
    pub reserve_sufficient: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PqWithdrawalAuthorization {
    pub authorization_id: String,
    pub pq_scheme: String,
    pub account_key_commitment: String,
    pub withdrawal_transcript_root: String,
    pub signature_bundle_root: String,
    pub recovery_delegate_root: String,
    pub expiry_height: u64,
    pub signature_verified: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct WalletRecoveryPayload {
    pub recovery_id: String,
    pub encrypted_payload_root: String,
    pub recipient_commitment_root: String,
    pub wallet_scan_hint_root: String,
    pub recovery_policy_root: String,
    pub disclosure_cap_root: String,
    pub payload_available: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PrivacyProofExport {
    pub export_id: String,
    pub proof_system: String,
    pub public_inputs_root: String,
    pub redacted_witness_root: String,
    pub nullifier_set_root: String,
    pub privacy_set_size: u64,
    pub selective_disclosure_root: String,
    pub export_verified: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct InvocationExpectation {
    pub invocation_id: String,
    pub expected_runtime: String,
    pub expected_function: String,
    pub expected_args_root: String,
    pub expected_call_root: String,
    pub expected_invocation_root: String,
    pub observed_invocation_root: String,
    pub matches_expected: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct FailClosedReason {
    pub reason_code: String,
    pub reason_root: String,
    pub blocking: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReleaseHold {
    pub hold_id: String,
    pub hold_reason_root: String,
    pub held_until_height: u64,
    pub release_authority_root: String,
    pub release_receipt_root: String,
    pub release_allowed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub claim_authorization: ClaimAuthorization,
    pub settlement_receipt: SettlementReceipt,
    pub challenge_window: ChallengeWindow,
    pub reserve_proof: ReserveProof,
    pub pq_withdrawal_authorization: PqWithdrawalAuthorization,
    pub wallet_recovery_payload: WalletRecoveryPayload,
    pub privacy_proof_export: PrivacyProofExport,
    pub invocation_expectation: InvocationExpectation,
    pub fail_closed_reasons: Vec<FailClosedReason>,
    pub release_hold: ReleaseHold,
    pub evidence_roots: BTreeMap<String, String>,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            preflight_suite: PREFLIGHT_SUITE.to_string(),
            reference_height: DEFAULT_DEVNET_HEIGHT,
            min_challenge_window_blocks: DEFAULT_MIN_CHALLENGE_WINDOW_BLOCKS,
            release_hold_blocks: DEFAULT_RELEASE_HOLD_BLOCKS,
            min_reserve_confirmations: DEFAULT_MIN_RESERVE_CONFIRMATIONS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            required_quorum_weight: DEFAULT_REQUIRED_QUORUM_WEIGHT,
            cargo_runtime_execution_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "preflight_suite": self.preflight_suite,
            "reference_height": self.reference_height,
            "min_challenge_window_blocks": self.min_challenge_window_blocks,
            "release_hold_blocks": self.release_hold_blocks,
            "min_reserve_confirmations": self.min_reserve_confirmations,
            "min_privacy_set_size": self.min_privacy_set_size,
            "required_quorum_weight": self.required_quorum_weight,
            "cargo_runtime_execution_allowed": self.cargo_runtime_execution_allowed,
        })
    }

    pub fn root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let claim_authorization = ClaimAuthorization {
            claim_id: label_root("claim", "devnet-withdrawal-claim-0001"),
            claimant_commitment: label_root("claimant", "wallet-owner-commitment"),
            exit_nullifier_root: label_root("nullifier", "forced-exit-nullifier-set"),
            claim_commitment_root: label_root("claim-commitment", "claim-commitment"),
            authorization_policy_root: label_root("policy", "withdrawal-claim-authorization"),
            signer_quorum_root: label_root("quorum", "pq-claim-signers"),
            observed_quorum_weight: DEFAULT_REQUIRED_QUORUM_WEIGHT,
            authorization_digest: label_root("digest", "authorization-transcript"),
            authorized: true,
        };
        let settlement_receipt = SettlementReceipt {
            settlement_id: label_root("settlement", "devnet-settlement-0001"),
            settlement_receipt_root: label_root("receipt", "settlement-receipt"),
            canonical_exit_root: label_root("canonical-exit", "forced-exit-spine"),
            settlement_amount_commitment: label_root("amount", "withdrawal-amount-commitment"),
            fee_receipt_root: label_root("fee", "settlement-fee-receipt"),
            paid_to_withdrawal_address_root: label_root("address", "withdrawal-address"),
            settled_at_height: DEFAULT_DEVNET_HEIGHT - 24,
            receipt_verified: true,
        };
        let challenge_window = ChallengeWindow {
            challenge_id: label_root("challenge", "withdrawal-claim-challenge-window"),
            opened_at_height: DEFAULT_DEVNET_HEIGHT - DEFAULT_MIN_CHALLENGE_WINDOW_BLOCKS - 1,
            closes_at_height: DEFAULT_DEVNET_HEIGHT - 1,
            observed_height: DEFAULT_DEVNET_HEIGHT,
            required_window_blocks: DEFAULT_MIN_CHALLENGE_WINDOW_BLOCKS,
            dispute_registry_root: label_root("dispute", "empty-dispute-registry"),
            unresolved_disputes: 0,
            elapsed: true,
        };
        let reserve_proof = ReserveProof {
            reserve_proof_id: label_root("reserve", "withdrawal-reserve-proof"),
            reserve_commitment_root: label_root("reserve-commitment", "xmr-reserve"),
            monero_header_root: label_root("monero-header", "canonical-reserve-header"),
            output_set_root: label_root("output-set", "reserve-output-set"),
            liability_commitment_root: label_root("liability", "withdrawal-liability"),
            confirmations: DEFAULT_MIN_RESERVE_CONFIRMATIONS,
            surplus_commitment_root: label_root("surplus", "positive-reserve-surplus"),
            reserve_sufficient: true,
        };
        let pq_withdrawal_authorization = PqWithdrawalAuthorization {
            authorization_id: label_root("pq-withdrawal", "withdrawal-authorization"),
            pq_scheme: "ml-dsa-87+kyber768-transcript-v1".to_string(),
            account_key_commitment: label_root("account-key", "pq-account-key"),
            withdrawal_transcript_root: label_root("withdrawal-transcript", "withdrawal-call"),
            signature_bundle_root: label_root("signature", "pq-signature-bundle"),
            recovery_delegate_root: label_root("delegate", "wallet-recovery-delegate"),
            expiry_height: DEFAULT_DEVNET_HEIGHT + 288,
            signature_verified: true,
        };
        let wallet_recovery_payload = WalletRecoveryPayload {
            recovery_id: label_root("wallet-recovery", "claim-wallet-recovery"),
            encrypted_payload_root: label_root("encrypted-payload", "wallet-recovery-ciphertext"),
            recipient_commitment_root: label_root("recipient", "claimant-recovery-recipient"),
            wallet_scan_hint_root: label_root("scan-hint", "redacted-wallet-scan-hint"),
            recovery_policy_root: label_root("recovery-policy", "wallet-recovery-policy"),
            disclosure_cap_root: label_root("disclosure-cap", "minimum-disclosure"),
            payload_available: true,
        };
        let privacy_proof_export = PrivacyProofExport {
            export_id: label_root("privacy-export", "claim-proof-export"),
            proof_system: "plonkish-redacted-withdrawal-export-v1".to_string(),
            public_inputs_root: label_root("public-inputs", "withdrawal-public-inputs"),
            redacted_witness_root: label_root("redacted-witness", "claim-witness"),
            nullifier_set_root: label_root("nullifier-set", "withdrawal-nullifier-set"),
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            selective_disclosure_root: label_root("selective-disclosure", "export-disclosure"),
            export_verified: true,
        };
        let expected_args_root = label_root("args", "withdrawal-claim-runtime-args");
        let expected_call_root = invocation_call_root(
            "withdrawal_claim_gate",
            "preflight",
            &expected_args_root,
            &claim_authorization.claim_commitment_root,
        );
        let expected_invocation_root = invocation_root(
            &claim_authorization.claim_id,
            &settlement_receipt.settlement_id,
            &expected_call_root,
        );
        let invocation_expectation = InvocationExpectation {
            invocation_id: label_root("invocation", "withdrawal-claim-gate-preflight"),
            expected_runtime: "withdrawal_claim_gate_preflight_runtime".to_string(),
            expected_function: "preflight".to_string(),
            expected_args_root,
            expected_call_root,
            expected_invocation_root: expected_invocation_root.clone(),
            observed_invocation_root: expected_invocation_root,
            matches_expected: true,
        };
        let release_hold = ReleaseHold {
            hold_id: label_root("hold", "runtime-execution-release-hold"),
            hold_reason_root: label_root("hold-reason", "manual-runtime-gate-required"),
            held_until_height: DEFAULT_DEVNET_HEIGHT + DEFAULT_RELEASE_HOLD_BLOCKS,
            release_authority_root: label_root("release-authority", "bridge-operator-quorum"),
            release_receipt_root: label_root("release-receipt", "not-released"),
            release_allowed: false,
        };
        let fail_closed_reasons = vec![FailClosedReason {
            reason_code: "runtime_execution_release_hold_active".to_string(),
            reason_root: release_hold.hold_reason_root.clone(),
            blocking: true,
        }];
        let mut state = Self {
            config,
            claim_authorization,
            settlement_receipt,
            challenge_window,
            reserve_proof,
            pq_withdrawal_authorization,
            wallet_recovery_payload,
            privacy_proof_export,
            invocation_expectation,
            fail_closed_reasons,
            release_hold,
            evidence_roots: BTreeMap::new(),
        };
        state.evidence_roots = state.derive_evidence_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "claim_authorization": claim_authorization_record(&self.claim_authorization),
            "settlement_receipt": settlement_receipt_record(&self.settlement_receipt),
            "challenge_window": challenge_window_record(&self.challenge_window),
            "reserve_proof": reserve_proof_record(&self.reserve_proof),
            "pq_withdrawal_authorization": pq_withdrawal_authorization_record(&self.pq_withdrawal_authorization),
            "wallet_recovery_payload": wallet_recovery_payload_record(&self.wallet_recovery_payload),
            "privacy_proof_export": privacy_proof_export_record(&self.privacy_proof_export),
            "invocation_expectation": invocation_expectation_record(&self.invocation_expectation),
            "fail_closed_reasons": self.fail_closed_reasons.iter().map(fail_closed_reason_record).collect::<Vec<_>>(),
            "release_hold": release_hold_record(&self.release_hold),
            "evidence_roots": self.derive_evidence_roots(),
            "runtime_execution_allowed": self.runtime_execution_allowed(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-GATE-PREFLIGHT-STATE",
            &[
                HashPart::Str(&self.config.chain_id),
                HashPart::Str(&self.config.protocol_version),
                HashPart::Str(&self.config.root()),
                HashPart::Str(&claim_authorization_root(&self.claim_authorization)),
                HashPart::Str(&settlement_receipt_root(&self.settlement_receipt)),
                HashPart::Str(&challenge_window_root(&self.challenge_window)),
                HashPart::Str(&reserve_proof_root(&self.reserve_proof)),
                HashPart::Str(&pq_withdrawal_authorization_root(
                    &self.pq_withdrawal_authorization,
                )),
                HashPart::Str(&wallet_recovery_payload_root(&self.wallet_recovery_payload)),
                HashPart::Str(&privacy_proof_export_root(&self.privacy_proof_export)),
                HashPart::Str(&invocation_expectation_root(&self.invocation_expectation)),
                HashPart::Str(&fail_closed_root(&self.fail_closed_reasons)),
                HashPart::Str(&release_hold_root(&self.release_hold)),
                HashPart::Str(&evidence_map_root(&self.derive_evidence_roots())),
                HashPart::Str(bool_str(self.runtime_execution_allowed())),
            ],
            32,
        )
    }

    pub fn runtime_execution_allowed(&self) -> bool {
        self.config.cargo_runtime_execution_allowed
            && self.claim_authorization.authorized
            && self.claim_authorization.observed_quorum_weight >= self.config.required_quorum_weight
            && self.settlement_receipt.receipt_verified
            && self.challenge_window.elapsed
            && self.challenge_window.unresolved_disputes == 0
            && self.challenge_window.closes_at_height >= self.challenge_window.opened_at_height
            && self.challenge_window.closes_at_height - self.challenge_window.opened_at_height
                >= self.config.min_challenge_window_blocks
            && self.reserve_proof.reserve_sufficient
            && self.reserve_proof.confirmations >= self.config.min_reserve_confirmations
            && self.pq_withdrawal_authorization.signature_verified
            && self.pq_withdrawal_authorization.expiry_height > self.config.reference_height
            && self.wallet_recovery_payload.payload_available
            && self.privacy_proof_export.export_verified
            && self.privacy_proof_export.privacy_set_size >= self.config.min_privacy_set_size
            && self.invocation_expectation.matches_expected
            && self.invocation_expectation.expected_invocation_root
                == self.invocation_expectation.observed_invocation_root
            && self.release_hold.release_allowed
            && self.release_hold.held_until_height <= self.config.reference_height
            && !self
                .fail_closed_reasons
                .iter()
                .any(|reason| reason.blocking)
    }

    pub fn derive_evidence_roots(&self) -> BTreeMap<String, String> {
        let mut roots = BTreeMap::new();
        roots.insert(
            "claim_authorization".to_string(),
            claim_authorization_root(&self.claim_authorization),
        );
        roots.insert(
            "settlement_receipt".to_string(),
            settlement_receipt_root(&self.settlement_receipt),
        );
        roots.insert(
            "challenge_window".to_string(),
            challenge_window_root(&self.challenge_window),
        );
        roots.insert(
            "reserve_proof".to_string(),
            reserve_proof_root(&self.reserve_proof),
        );
        roots.insert(
            "pq_withdrawal_authorization".to_string(),
            pq_withdrawal_authorization_root(&self.pq_withdrawal_authorization),
        );
        roots.insert(
            "wallet_recovery_payload".to_string(),
            wallet_recovery_payload_root(&self.wallet_recovery_payload),
        );
        roots.insert(
            "privacy_proof_export".to_string(),
            privacy_proof_export_root(&self.privacy_proof_export),
        );
        roots.insert(
            "expected_invocation".to_string(),
            invocation_expectation_root(&self.invocation_expectation),
        );
        roots.insert(
            "fail_closed".to_string(),
            fail_closed_root(&self.fail_closed_reasons),
        );
        roots.insert(
            "release_hold".to_string(),
            release_hold_root(&self.release_hold),
        );
        roots
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

pub fn claim_authorization_record(record: &ClaimAuthorization) -> Value {
    json!({
        "claim_id": record.claim_id,
        "claimant_commitment": record.claimant_commitment,
        "exit_nullifier_root": record.exit_nullifier_root,
        "claim_commitment_root": record.claim_commitment_root,
        "authorization_policy_root": record.authorization_policy_root,
        "signer_quorum_root": record.signer_quorum_root,
        "observed_quorum_weight": record.observed_quorum_weight,
        "authorization_digest": record.authorization_digest,
        "authorized": record.authorized,
    })
}

pub fn settlement_receipt_record(record: &SettlementReceipt) -> Value {
    json!({
        "settlement_id": record.settlement_id,
        "settlement_receipt_root": record.settlement_receipt_root,
        "canonical_exit_root": record.canonical_exit_root,
        "settlement_amount_commitment": record.settlement_amount_commitment,
        "fee_receipt_root": record.fee_receipt_root,
        "paid_to_withdrawal_address_root": record.paid_to_withdrawal_address_root,
        "settled_at_height": record.settled_at_height,
        "receipt_verified": record.receipt_verified,
    })
}

pub fn challenge_window_record(record: &ChallengeWindow) -> Value {
    json!({
        "challenge_id": record.challenge_id,
        "opened_at_height": record.opened_at_height,
        "closes_at_height": record.closes_at_height,
        "observed_height": record.observed_height,
        "required_window_blocks": record.required_window_blocks,
        "dispute_registry_root": record.dispute_registry_root,
        "unresolved_disputes": record.unresolved_disputes,
        "elapsed": record.elapsed,
    })
}

pub fn reserve_proof_record(record: &ReserveProof) -> Value {
    json!({
        "reserve_proof_id": record.reserve_proof_id,
        "reserve_commitment_root": record.reserve_commitment_root,
        "monero_header_root": record.monero_header_root,
        "output_set_root": record.output_set_root,
        "liability_commitment_root": record.liability_commitment_root,
        "confirmations": record.confirmations,
        "surplus_commitment_root": record.surplus_commitment_root,
        "reserve_sufficient": record.reserve_sufficient,
    })
}

pub fn pq_withdrawal_authorization_record(record: &PqWithdrawalAuthorization) -> Value {
    json!({
        "authorization_id": record.authorization_id,
        "pq_scheme": record.pq_scheme,
        "account_key_commitment": record.account_key_commitment,
        "withdrawal_transcript_root": record.withdrawal_transcript_root,
        "signature_bundle_root": record.signature_bundle_root,
        "recovery_delegate_root": record.recovery_delegate_root,
        "expiry_height": record.expiry_height,
        "signature_verified": record.signature_verified,
    })
}

pub fn wallet_recovery_payload_record(record: &WalletRecoveryPayload) -> Value {
    json!({
        "recovery_id": record.recovery_id,
        "encrypted_payload_root": record.encrypted_payload_root,
        "recipient_commitment_root": record.recipient_commitment_root,
        "wallet_scan_hint_root": record.wallet_scan_hint_root,
        "recovery_policy_root": record.recovery_policy_root,
        "disclosure_cap_root": record.disclosure_cap_root,
        "payload_available": record.payload_available,
    })
}

pub fn privacy_proof_export_record(record: &PrivacyProofExport) -> Value {
    json!({
        "export_id": record.export_id,
        "proof_system": record.proof_system,
        "public_inputs_root": record.public_inputs_root,
        "redacted_witness_root": record.redacted_witness_root,
        "nullifier_set_root": record.nullifier_set_root,
        "privacy_set_size": record.privacy_set_size,
        "selective_disclosure_root": record.selective_disclosure_root,
        "export_verified": record.export_verified,
    })
}

pub fn invocation_expectation_record(record: &InvocationExpectation) -> Value {
    json!({
        "invocation_id": record.invocation_id,
        "expected_runtime": record.expected_runtime,
        "expected_function": record.expected_function,
        "expected_args_root": record.expected_args_root,
        "expected_call_root": record.expected_call_root,
        "expected_invocation_root": record.expected_invocation_root,
        "observed_invocation_root": record.observed_invocation_root,
        "matches_expected": record.matches_expected,
    })
}

pub fn fail_closed_reason_record(record: &FailClosedReason) -> Value {
    json!({
        "reason_code": record.reason_code,
        "reason_root": record.reason_root,
        "blocking": record.blocking,
    })
}

pub fn release_hold_record(record: &ReleaseHold) -> Value {
    json!({
        "hold_id": record.hold_id,
        "hold_reason_root": record.hold_reason_root,
        "held_until_height": record.held_until_height,
        "release_authority_root": record.release_authority_root,
        "release_receipt_root": record.release_receipt_root,
        "release_allowed": record.release_allowed,
    })
}

pub fn claim_authorization_root(record: &ClaimAuthorization) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-GATE-PREFLIGHT-CLAIM-AUTHORIZATION",
        &[
            HashPart::Str(&record.claim_id),
            HashPart::Str(&record.claimant_commitment),
            HashPart::Str(&record.exit_nullifier_root),
            HashPart::Str(&record.claim_commitment_root),
            HashPart::Str(&record.authorization_policy_root),
            HashPart::Str(&record.signer_quorum_root),
            HashPart::U64(record.observed_quorum_weight),
            HashPart::Str(&record.authorization_digest),
            HashPart::Str(bool_str(record.authorized)),
        ],
        32,
    )
}

pub fn settlement_receipt_root(record: &SettlementReceipt) -> String {
    record_root("settlement_receipt", &settlement_receipt_record(record))
}

pub fn challenge_window_root(record: &ChallengeWindow) -> String {
    record_root("challenge_window", &challenge_window_record(record))
}

pub fn reserve_proof_root(record: &ReserveProof) -> String {
    record_root("reserve_proof", &reserve_proof_record(record))
}

pub fn pq_withdrawal_authorization_root(record: &PqWithdrawalAuthorization) -> String {
    record_root(
        "pq_withdrawal_authorization",
        &pq_withdrawal_authorization_record(record),
    )
}

pub fn wallet_recovery_payload_root(record: &WalletRecoveryPayload) -> String {
    record_root(
        "wallet_recovery_payload",
        &wallet_recovery_payload_record(record),
    )
}

pub fn privacy_proof_export_root(record: &PrivacyProofExport) -> String {
    record_root("privacy_proof_export", &privacy_proof_export_record(record))
}

pub fn invocation_expectation_root(record: &InvocationExpectation) -> String {
    record_root(
        "invocation_expectation",
        &invocation_expectation_record(record),
    )
}

pub fn fail_closed_root(records: &[FailClosedReason]) -> String {
    let leaves = records
        .iter()
        .map(fail_closed_reason_record)
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-GATE-PREFLIGHT-FAIL-CLOSED",
        &leaves,
    )
}

pub fn release_hold_root(record: &ReleaseHold) -> String {
    record_root("release_hold", &release_hold_record(record))
}

pub fn evidence_map_root(records: &BTreeMap<String, String>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-GATE-PREFLIGHT-EVIDENCE-MAP",
        &leaves,
    )
}

pub fn invocation_call_root(
    expected_runtime: &str,
    expected_function: &str,
    expected_args_root: &str,
    claim_commitment_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-GATE-PREFLIGHT-INVOCATION-CALL",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(expected_runtime),
            HashPart::Str(expected_function),
            HashPart::Str(expected_args_root),
            HashPart::Str(claim_commitment_root),
        ],
        32,
    )
}

pub fn invocation_root(claim_id: &str, settlement_id: &str, expected_call_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-GATE-PREFLIGHT-INVOCATION",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(claim_id),
            HashPart::Str(settlement_id),
            HashPart::Str(expected_call_root),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-GATE-PREFLIGHT-RECORD",
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
        "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-GATE-PREFLIGHT-LABEL",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
        32,
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
