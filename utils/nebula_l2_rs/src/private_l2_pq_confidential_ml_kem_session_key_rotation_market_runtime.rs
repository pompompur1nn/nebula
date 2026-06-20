use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialMlKemSessionKeyRotationMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_ML_KEM_SESSION_KEY_ROTATION_MARKET_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-ml-kem-session-key-rotation-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_ML_KEM_SESSION_KEY_ROTATION_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PRIMARY_KEM_SUITE: &str = "ML-KEM-1024-confidential-session-rotation-v1";
pub const SECONDARY_KEM_SUITE: &str = "ML-KEM-768-mobile-session-rotation-v1";
pub const BID_ENCRYPTION_SUITE: &str = "sealed-ml-kem-bid-envelope+viewtag-redaction-v1";
pub const ATTESTATION_SUITE: &str = "pq-session-key-rotation-watchtower-attestation-v1";
pub const SETTLEMENT_SUITE: &str = "confidential-low-fee-session-rotation-settlement-v1";
pub const OPERATOR_SUMMARY_SUITE: &str = "operator-safe-key-rotation-summary-v1";
pub const DEVNET_HEIGHT: u64 = 812_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_COHORT_SIZE: u32 = 64;
pub const DEFAULT_TARGET_COHORT_SIZE: u32 = 512;
pub const DEFAULT_MAX_COHORT_SIZE: u32 = 4096;
pub const DEFAULT_BID_WINDOW_BLOCKS: u64 = 72;
pub const DEFAULT_CEREMONY_WINDOW_BLOCKS: u64 = 48;
pub const DEFAULT_ACTIVATION_DELAY_BLOCKS: u64 = 16;
pub const DEFAULT_GRACE_BLOCKS: u64 = 96;
pub const DEFAULT_MAX_ROTATION_AGE_BLOCKS: u64 = 21_600;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 4_096;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 8_750;
pub const DEFAULT_OPERATOR_FEE_CAP_MICRONERO: u64 = 75_000;
pub const DEFAULT_MARKET_CLEARING_FEE_MICRONERO: u64 = 18_000;
pub const DEFAULT_MIN_WATCHER_QUORUM_BPS: u64 = 6_700;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationUrgency {
    Routine,
    FeeOptimized,
    CongestionRelief,
    EntropyRefresh,
    IncidentRecovery,
    EmergencyRevocation,
}

impl RotationUrgency {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Routine => "routine",
            Self::FeeOptimized => "fee_optimized",
            Self::CongestionRelief => "congestion_relief",
            Self::EntropyRefresh => "entropy_refresh",
            Self::IncidentRecovery => "incident_recovery",
            Self::EmergencyRevocation => "emergency_revocation",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Routine => 10,
            Self::FeeOptimized => 14,
            Self::CongestionRelief => 18,
            Self::EntropyRefresh => 24,
            Self::IncidentRecovery => 42,
            Self::EmergencyRevocation => 64,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationPolicyKind {
    AgeBound,
    VolumeBound,
    FeeMarketAdaptive,
    CohortPrivacyFloor,
    WatchtowerRequired,
    HybridGrace,
    EmergencyOnly,
}

impl RotationPolicyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AgeBound => "age_bound",
            Self::VolumeBound => "volume_bound",
            Self::FeeMarketAdaptive => "fee_market_adaptive",
            Self::CohortPrivacyFloor => "cohort_privacy_floor",
            Self::WatchtowerRequired => "watchtower_required",
            Self::HybridGrace => "hybrid_grace",
            Self::EmergencyOnly => "emergency_only",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionClass {
    WalletInteractive,
    WalletBackgroundSync,
    ContractCall,
    SequencerAdmission,
    BridgeExit,
    WatchtowerEvidence,
    OperatorMaintenance,
}

impl SessionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletInteractive => "wallet_interactive",
            Self::WalletBackgroundSync => "wallet_background_sync",
            Self::ContractCall => "contract_call",
            Self::SequencerAdmission => "sequencer_admission",
            Self::BridgeExit => "bridge_exit",
            Self::WatchtowerEvidence => "watchtower_evidence",
            Self::OperatorMaintenance => "operator_maintenance",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MlKemParameterSet {
    MlKem512,
    MlKem768,
    MlKem1024,
    HybridX25519MlKem768,
    HybridX25519MlKem1024,
}

impl MlKemParameterSet {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlKem512 => "ml_kem_512",
            Self::MlKem768 => "ml_kem_768",
            Self::MlKem1024 => "ml_kem_1024",
            Self::HybridX25519MlKem768 => "hybrid_x25519_ml_kem_768",
            Self::HybridX25519MlKem1024 => "hybrid_x25519_ml_kem_1024",
        }
    }

    pub fn pq_security_bits(self) -> u16 {
        match self {
            Self::MlKem512 => 128,
            Self::MlKem768 | Self::HybridX25519MlKem768 => 192,
            Self::MlKem1024 | Self::HybridX25519MlKem1024 => 256,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortStatus {
    Drafted,
    Bidding,
    Sealed,
    CeremonyOpen,
    Attesting,
    Settling,
    Activated,
    GracePeriod,
    Retired,
    Paused,
}

impl CohortStatus {
    pub fn is_open(self) -> bool {
        matches!(self, Self::Bidding | Self::CeremonyOpen | Self::Attesting)
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Activated | Self::Retired | Self::Paused)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drafted => "drafted",
            Self::Bidding => "bidding",
            Self::Sealed => "sealed",
            Self::CeremonyOpen => "ceremony_open",
            Self::Attesting => "attesting",
            Self::Settling => "settling",
            Self::Activated => "activated",
            Self::GracePeriod => "grace_period",
            Self::Retired => "retired",
            Self::Paused => "paused",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Submitted,
    Eligible,
    Cleared,
    RebateReserved,
    Settled,
    Rejected,
    Expired,
}

impl BidStatus {
    pub fn accepted(self) -> bool {
        matches!(
            self,
            Self::Eligible | Self::Cleared | Self::RebateReserved | Self::Settled
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Observed,
    WeakCiphertext,
    EntropyBelowFloor,
    TranscriptMismatch,
    MissingOpening,
    ReplayFenceCollision,
    OperatorVeto,
}

impl AttestationVerdict {
    pub fn positive(self) -> bool {
        matches!(self, Self::Observed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Pending,
    Receipted,
    Rebated,
    Challenged,
    Finalized,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub network: String,
    pub chain_id: u64,
    pub l2_chain_id: u64,
    pub activation_height: u64,
    pub min_pq_security_bits: u16,
    pub min_cohort_size: u32,
    pub target_cohort_size: u32,
    pub max_cohort_size: u32,
    pub bid_window_blocks: u64,
    pub ceremony_window_blocks: u64,
    pub activation_delay_blocks: u64,
    pub grace_blocks: u64,
    pub max_rotation_age_blocks: u64,
    pub redaction_budget_units: u64,
    pub low_fee_rebate_bps: u64,
    pub operator_fee_cap_micronero: u64,
    pub market_clearing_fee_micronero: u64,
    pub min_watcher_quorum_bps: u64,
    pub require_dual_kem_transcript: bool,
    pub require_monero_anchor_receipt: bool,
    pub allow_emergency_operator_pause: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            network: "devnet".to_string(),
            chain_id: 31_337,
            l2_chain_id: 731_337,
            activation_height: DEVNET_HEIGHT,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_cohort_size: DEFAULT_MIN_COHORT_SIZE,
            target_cohort_size: DEFAULT_TARGET_COHORT_SIZE,
            max_cohort_size: DEFAULT_MAX_COHORT_SIZE,
            bid_window_blocks: DEFAULT_BID_WINDOW_BLOCKS,
            ceremony_window_blocks: DEFAULT_CEREMONY_WINDOW_BLOCKS,
            activation_delay_blocks: DEFAULT_ACTIVATION_DELAY_BLOCKS,
            grace_blocks: DEFAULT_GRACE_BLOCKS,
            max_rotation_age_blocks: DEFAULT_MAX_ROTATION_AGE_BLOCKS,
            redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            operator_fee_cap_micronero: DEFAULT_OPERATOR_FEE_CAP_MICRONERO,
            market_clearing_fee_micronero: DEFAULT_MARKET_CLEARING_FEE_MICRONERO,
            min_watcher_quorum_bps: DEFAULT_MIN_WATCHER_QUORUM_BPS,
            require_dual_kem_transcript: true,
            require_monero_anchor_receipt: true,
            allow_emergency_operator_pause: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "network": self.network,
            "chain_id": self.chain_id,
            "l2_chain_id": self.l2_chain_id,
            "activation_height": self.activation_height,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_cohort_size": self.min_cohort_size,
            "target_cohort_size": self.target_cohort_size,
            "max_cohort_size": self.max_cohort_size,
            "bid_window_blocks": self.bid_window_blocks,
            "ceremony_window_blocks": self.ceremony_window_blocks,
            "activation_delay_blocks": self.activation_delay_blocks,
            "grace_blocks": self.grace_blocks,
            "max_rotation_age_blocks": self.max_rotation_age_blocks,
            "redaction_budget_units": self.redaction_budget_units,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "operator_fee_cap_micronero": self.operator_fee_cap_micronero,
            "market_clearing_fee_micronero": self.market_clearing_fee_micronero,
            "min_watcher_quorum_bps": self.min_watcher_quorum_bps,
            "require_dual_kem_transcript": self.require_dual_kem_transcript,
            "require_monero_anchor_receipt": self.require_monero_anchor_receipt,
            "allow_emergency_operator_pause": self.allow_emergency_operator_pause,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.min_pq_security_bits < 192 {
            return Err("min_pq_security_bits below ML-KEM production floor".to_string());
        }
        if self.min_cohort_size == 0 || self.min_cohort_size > self.target_cohort_size {
            return Err("cohort size bounds are inconsistent".to_string());
        }
        if self.target_cohort_size > self.max_cohort_size {
            return Err("target cohort exceeds max cohort".to_string());
        }
        if self.low_fee_rebate_bps > MAX_BPS || self.min_watcher_quorum_bps > MAX_BPS {
            return Err("basis points value exceeds MAX_BPS".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub rotation_policy_count: u64,
    pub session_cohort_count: u64,
    pub encrypted_bid_count: u64,
    pub attestation_count: u64,
    pub ceremony_window_count: u64,
    pub settlement_receipt_count: u64,
    pub rebate_count: u64,
    pub redaction_budget_count: u64,
    pub operator_summary_count: u64,
    pub accepted_bid_count: u64,
    pub rejected_bid_count: u64,
    pub activated_cohort_count: u64,
    pub paused_cohort_count: u64,
    pub challenged_receipt_count: u64,
    pub total_rebate_micronero: u64,
    pub total_clearing_fee_micronero: u64,
    pub total_redaction_units_spent: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "rotation_policy_count": self.rotation_policy_count,
            "session_cohort_count": self.session_cohort_count,
            "encrypted_bid_count": self.encrypted_bid_count,
            "attestation_count": self.attestation_count,
            "ceremony_window_count": self.ceremony_window_count,
            "settlement_receipt_count": self.settlement_receipt_count,
            "rebate_count": self.rebate_count,
            "redaction_budget_count": self.redaction_budget_count,
            "operator_summary_count": self.operator_summary_count,
            "accepted_bid_count": self.accepted_bid_count,
            "rejected_bid_count": self.rejected_bid_count,
            "activated_cohort_count": self.activated_cohort_count,
            "paused_cohort_count": self.paused_cohort_count,
            "challenged_receipt_count": self.challenged_receipt_count,
            "total_rebate_micronero": self.total_rebate_micronero,
            "total_clearing_fee_micronero": self.total_clearing_fee_micronero,
            "total_redaction_units_spent": self.total_redaction_units_spent,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub rotation_policy_root: String,
    pub session_cohort_root: String,
    pub encrypted_bid_root: String,
    pub attestation_root: String,
    pub ceremony_window_root: String,
    pub settlement_receipt_root: String,
    pub low_fee_rebate_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "rotation_policy_root": self.rotation_policy_root,
            "session_cohort_root": self.session_cohort_root,
            "encrypted_bid_root": self.encrypted_bid_root,
            "attestation_root": self.attestation_root,
            "ceremony_window_root": self.ceremony_window_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "redaction_budget_root": self.redaction_budget_root,
            "operator_summary_root": self.operator_summary_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RotationPolicy {
    pub policy_id: String,
    pub kind: RotationPolicyKind,
    pub session_class: SessionClass,
    pub urgency: RotationUrgency,
    pub min_pq_security_bits: u16,
    pub max_session_age_blocks: u64,
    pub max_messages_per_session: u64,
    pub min_anonymity_set: u64,
    pub require_watchtower_attestation: bool,
    pub allow_low_fee_rebate: bool,
    pub created_at_height: u64,
}

impl RotationPolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "kind": self.kind,
            "kind_label": self.kind.as_str(),
            "session_class": self.session_class,
            "session_class_label": self.session_class.as_str(),
            "urgency": self.urgency,
            "urgency_label": self.urgency.as_str(),
            "priority_weight": self.urgency.priority_weight(),
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_session_age_blocks": self.max_session_age_blocks,
            "max_messages_per_session": self.max_messages_per_session,
            "min_anonymity_set": self.min_anonymity_set,
            "require_watchtower_attestation": self.require_watchtower_attestation,
            "allow_low_fee_rebate": self.allow_low_fee_rebate,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn policy_root(&self) -> String {
        runtime_hash("ROTATION-POLICY", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SessionCohort {
    pub cohort_id: String,
    pub policy_id: String,
    pub class: SessionClass,
    pub status: CohortStatus,
    pub parameter_set: MlKemParameterSet,
    pub session_commitment_root: String,
    pub entry_nullifier_root: String,
    pub view_tag_root: String,
    pub expected_sessions: u32,
    pub sealed_sessions: u32,
    pub active_sessions: u32,
    pub opened_at_height: u64,
    pub bid_close_height: u64,
    pub ceremony_open_height: u64,
    pub activation_height: u64,
    pub retirement_height: Option<u64>,
}

impl SessionCohort {
    pub fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "policy_id": self.policy_id,
            "class": self.class,
            "class_label": self.class.as_str(),
            "status": self.status,
            "status_label": self.status.as_str(),
            "is_open": self.status.is_open(),
            "terminal": self.status.terminal(),
            "parameter_set": self.parameter_set,
            "parameter_set_label": self.parameter_set.as_str(),
            "pq_security_bits": self.parameter_set.pq_security_bits(),
            "session_commitment_root": self.session_commitment_root,
            "entry_nullifier_root": self.entry_nullifier_root,
            "view_tag_root": self.view_tag_root,
            "expected_sessions": self.expected_sessions,
            "sealed_sessions": self.sealed_sessions,
            "active_sessions": self.active_sessions,
            "opened_at_height": self.opened_at_height,
            "bid_close_height": self.bid_close_height,
            "ceremony_open_height": self.ceremony_open_height,
            "activation_height": self.activation_height,
            "retirement_height": self.retirement_height,
        })
    }

    pub fn cohort_root(&self) -> String {
        runtime_hash("SESSION-COHORT", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedRotationBid {
    pub bid_id: String,
    pub cohort_id: String,
    pub bidder_commitment: String,
    pub sealed_bid_ciphertext_root: String,
    pub ml_kem_ciphertext_hash: String,
    pub fee_commitment: String,
    pub max_fee_micronero_commitment: String,
    pub rebate_claim_commitment: String,
    pub privacy_nullifier: String,
    pub status: BidStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub redaction_units_reserved: u64,
}

impl EncryptedRotationBid {
    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "cohort_id": self.cohort_id,
            "bidder_commitment": self.bidder_commitment,
            "sealed_bid_ciphertext_root": self.sealed_bid_ciphertext_root,
            "ml_kem_ciphertext_hash": self.ml_kem_ciphertext_hash,
            "fee_commitment": self.fee_commitment,
            "max_fee_micronero_commitment": self.max_fee_micronero_commitment,
            "rebate_claim_commitment": self.rebate_claim_commitment,
            "privacy_nullifier": self.privacy_nullifier,
            "status": self.status,
            "accepted": self.status.accepted(),
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "redaction_units_reserved": self.redaction_units_reserved,
        })
    }

    pub fn bid_root(&self) -> String {
        runtime_hash(
            "ENCRYPTED-ROTATION-BID",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub cohort_id: String,
    pub bid_id: Option<String>,
    pub watcher_committee_id: String,
    pub transcript_root: String,
    pub kem_parameter_set: MlKemParameterSet,
    pub verdict: AttestationVerdict,
    pub observed_ciphertext_count: u32,
    pub watcher_weight_bps: u64,
    pub evidence_root: String,
    pub attested_at_height: u64,
}

impl PqAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "cohort_id": self.cohort_id,
            "bid_id": self.bid_id,
            "watcher_committee_id": self.watcher_committee_id,
            "transcript_root": self.transcript_root,
            "kem_parameter_set": self.kem_parameter_set,
            "kem_parameter_set_label": self.kem_parameter_set.as_str(),
            "pq_security_bits": self.kem_parameter_set.pq_security_bits(),
            "verdict": self.verdict,
            "positive": self.verdict.positive(),
            "observed_ciphertext_count": self.observed_ciphertext_count,
            "watcher_weight_bps": self.watcher_weight_bps,
            "evidence_root": self.evidence_root,
            "attested_at_height": self.attested_at_height,
        })
    }

    pub fn attestation_root(&self) -> String {
        runtime_hash("PQ-ATTESTATION", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KeyCeremonyWindow {
    pub window_id: String,
    pub cohort_id: String,
    pub status: CohortStatus,
    pub opens_at_height: u64,
    pub closes_at_height: u64,
    pub activation_height: u64,
    pub participant_commitment_root: String,
    pub transcript_root: String,
    pub opening_share_root: String,
    pub operator_guardrail_root: String,
    pub min_successful_openings: u32,
    pub successful_openings: u32,
}

impl KeyCeremonyWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "cohort_id": self.cohort_id,
            "status": self.status,
            "status_label": self.status.as_str(),
            "opens_at_height": self.opens_at_height,
            "closes_at_height": self.closes_at_height,
            "activation_height": self.activation_height,
            "participant_commitment_root": self.participant_commitment_root,
            "transcript_root": self.transcript_root,
            "opening_share_root": self.opening_share_root,
            "operator_guardrail_root": self.operator_guardrail_root,
            "min_successful_openings": self.min_successful_openings,
            "successful_openings": self.successful_openings,
            "success_bps": bps(self.successful_openings as u64, self.min_successful_openings as u64),
        })
    }

    pub fn window_root(&self) -> String {
        runtime_hash(
            "KEY-CEREMONY-WINDOW",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub cohort_id: String,
    pub bid_id: String,
    pub status: SettlementStatus,
    pub clearing_fee_micronero: u64,
    pub operator_fee_micronero: u64,
    pub rebate_micronero: u64,
    pub settlement_note_commitment: String,
    pub monero_anchor_txid_hash: String,
    pub l2_receipt_root: String,
    pub settled_at_height: u64,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "cohort_id": self.cohort_id,
            "bid_id": self.bid_id,
            "status": self.status,
            "clearing_fee_micronero": self.clearing_fee_micronero,
            "operator_fee_micronero": self.operator_fee_micronero,
            "rebate_micronero": self.rebate_micronero,
            "effective_fee_micronero": self.clearing_fee_micronero.saturating_sub(self.rebate_micronero),
            "settlement_note_commitment": self.settlement_note_commitment,
            "monero_anchor_txid_hash": self.monero_anchor_txid_hash,
            "l2_receipt_root": self.l2_receipt_root,
            "settled_at_height": self.settled_at_height,
        })
    }

    pub fn receipt_root(&self) -> String {
        runtime_hash(
            "SETTLEMENT-RECEIPT",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub cohort_id: String,
    pub beneficiary_commitment: String,
    pub rebate_micronero: u64,
    pub rebate_bps: u64,
    pub sponsor_pool_id: String,
    pub claim_nullifier: String,
    pub reserved_at_height: u64,
    pub claimable_at_height: u64,
}

impl LowFeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "cohort_id": self.cohort_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "rebate_micronero": self.rebate_micronero,
            "rebate_bps": self.rebate_bps,
            "sponsor_pool_id": self.sponsor_pool_id,
            "claim_nullifier": self.claim_nullifier,
            "reserved_at_height": self.reserved_at_height,
            "claimable_at_height": self.claimable_at_height,
        })
    }

    pub fn rebate_root(&self) -> String {
        runtime_hash("LOW-FEE-REBATE", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub cohort_id: String,
    pub owner_commitment: String,
    pub initial_units: u64,
    pub spent_units: u64,
    pub reserved_units: u64,
    pub transcript_redaction_root: String,
    pub operator_visible_digest: String,
    pub expires_at_height: u64,
}

impl RedactionBudget {
    pub fn remaining_units(&self) -> u64 {
        self.initial_units
            .saturating_sub(self.spent_units)
            .saturating_sub(self.reserved_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "cohort_id": self.cohort_id,
            "owner_commitment": self.owner_commitment,
            "initial_units": self.initial_units,
            "spent_units": self.spent_units,
            "reserved_units": self.reserved_units,
            "remaining_units": self.remaining_units(),
            "transcript_redaction_root": self.transcript_redaction_root,
            "operator_visible_digest": self.operator_visible_digest,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn budget_root(&self) -> String {
        runtime_hash("REDACTION-BUDGET", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSafeSummary {
    pub summary_id: String,
    pub cohort_id: String,
    pub period_start_height: u64,
    pub period_end_height: u64,
    pub active_cohort_count: u64,
    pub open_bid_count: u64,
    pub accepted_bid_count: u64,
    pub rejected_bid_count: u64,
    pub positive_attestation_count: u64,
    pub challenged_receipt_count: u64,
    pub median_clearing_fee_micronero: u64,
    pub max_operator_fee_micronero: u64,
    pub redaction_units_remaining: u64,
    pub disclosure_floor: String,
    pub operator_notes_commitment: String,
}

impl OperatorSafeSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "cohort_id": self.cohort_id,
            "period_start_height": self.period_start_height,
            "period_end_height": self.period_end_height,
            "active_cohort_count": self.active_cohort_count,
            "open_bid_count": self.open_bid_count,
            "accepted_bid_count": self.accepted_bid_count,
            "rejected_bid_count": self.rejected_bid_count,
            "positive_attestation_count": self.positive_attestation_count,
            "challenged_receipt_count": self.challenged_receipt_count,
            "median_clearing_fee_micronero": self.median_clearing_fee_micronero,
            "max_operator_fee_micronero": self.max_operator_fee_micronero,
            "redaction_units_remaining": self.redaction_units_remaining,
            "disclosure_floor": self.disclosure_floor,
            "operator_notes_commitment": self.operator_notes_commitment,
        })
    }

    pub fn summary_root(&self) -> String {
        runtime_hash(
            "OPERATOR-SAFE-SUMMARY",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub rotation_policies: BTreeMap<String, RotationPolicy>,
    pub session_cohorts: BTreeMap<String, SessionCohort>,
    pub encrypted_bids: BTreeMap<String, EncryptedRotationBid>,
    pub pq_attestations: BTreeMap<String, PqAttestation>,
    pub ceremony_windows: BTreeMap<String, KeyCeremonyWindow>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSafeSummary>,
    pub used_privacy_nullifiers: BTreeSet<String>,
    pub active_cohort_ids: BTreeSet<String>,
    pub paused_cohort_ids: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            rotation_policies: BTreeMap::new(),
            session_cohorts: BTreeMap::new(),
            encrypted_bids: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            ceremony_windows: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            used_privacy_nullifiers: BTreeSet::new(),
            active_cohort_ids: BTreeSet::new(),
            paused_cohort_ids: BTreeSet::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        state.seed_devnet();
        state.recompute();
        state
    }

    pub fn add_rotation_policy(&mut self, policy: RotationPolicy) -> Result<String> {
        self.config.validate()?;
        if policy.min_pq_security_bits < self.config.min_pq_security_bits {
            return Err(format!(
                "policy {} below configured pq security floor",
                policy.policy_id
            ));
        }
        let id = policy.policy_id.clone();
        self.rotation_policies.insert(id.clone(), policy);
        self.recompute();
        Ok(id)
    }

    pub fn open_cohort(&mut self, cohort: SessionCohort) -> Result<String> {
        if !self.rotation_policies.contains_key(&cohort.policy_id) {
            return Err(format!("unknown policy {}", cohort.policy_id));
        }
        if cohort.expected_sessions < self.config.min_cohort_size {
            return Err(format!("cohort {} below privacy floor", cohort.cohort_id));
        }
        if cohort.expected_sessions > self.config.max_cohort_size {
            return Err(format!(
                "cohort {} exceeds max cohort size",
                cohort.cohort_id
            ));
        }
        if cohort.parameter_set.pq_security_bits() < self.config.min_pq_security_bits {
            return Err(format!(
                "cohort {} uses weak ML-KEM parameter set",
                cohort.cohort_id
            ));
        }
        let id = cohort.cohort_id.clone();
        if matches!(
            cohort.status,
            CohortStatus::Activated | CohortStatus::GracePeriod
        ) {
            self.active_cohort_ids.insert(id.clone());
        }
        if matches!(cohort.status, CohortStatus::Paused) {
            self.paused_cohort_ids.insert(id.clone());
        }
        self.session_cohorts.insert(id.clone(), cohort);
        self.recompute();
        Ok(id)
    }

    pub fn submit_encrypted_bid(&mut self, bid: EncryptedRotationBid) -> Result<String> {
        let cohort = self
            .session_cohorts
            .get(&bid.cohort_id)
            .ok_or_else(|| format!("unknown cohort {}", bid.cohort_id))?;
        if !cohort.status.is_open() && cohort.status != CohortStatus::Bidding {
            return Err(format!("cohort {} is not accepting bids", bid.cohort_id));
        }
        if self
            .used_privacy_nullifiers
            .contains(&bid.privacy_nullifier)
        {
            return Err(format!(
                "duplicate privacy nullifier for bid {}",
                bid.bid_id
            ));
        }
        if bid.expires_at_height <= bid.submitted_at_height {
            return Err(format!("bid {} has invalid expiry", bid.bid_id));
        }
        let id = bid.bid_id.clone();
        self.used_privacy_nullifiers
            .insert(bid.privacy_nullifier.clone());
        self.encrypted_bids.insert(id.clone(), bid);
        self.recompute();
        Ok(id)
    }

    pub fn record_attestation(&mut self, attestation: PqAttestation) -> Result<String> {
        if !self.session_cohorts.contains_key(&attestation.cohort_id) {
            return Err(format!("unknown cohort {}", attestation.cohort_id));
        }
        if attestation.watcher_weight_bps > MAX_BPS {
            return Err("watcher weight exceeds MAX_BPS".to_string());
        }
        if attestation.kem_parameter_set.pq_security_bits() < self.config.min_pq_security_bits {
            return Err(format!(
                "attestation {} below pq security floor",
                attestation.attestation_id
            ));
        }
        let id = attestation.attestation_id.clone();
        self.pq_attestations.insert(id.clone(), attestation);
        self.recompute();
        Ok(id)
    }

    pub fn open_ceremony_window(&mut self, window: KeyCeremonyWindow) -> Result<String> {
        if !self.session_cohorts.contains_key(&window.cohort_id) {
            return Err(format!("unknown cohort {}", window.cohort_id));
        }
        if window.closes_at_height <= window.opens_at_height {
            return Err(format!(
                "window {} closes before it opens",
                window.window_id
            ));
        }
        if window.activation_height < window.closes_at_height {
            return Err(format!(
                "window {} activates before close",
                window.window_id
            ));
        }
        let id = window.window_id.clone();
        self.ceremony_windows.insert(id.clone(), window);
        self.recompute();
        Ok(id)
    }

    pub fn settle_receipt(&mut self, receipt: SettlementReceipt) -> Result<String> {
        if !self.session_cohorts.contains_key(&receipt.cohort_id) {
            return Err(format!("unknown cohort {}", receipt.cohort_id));
        }
        if !self.encrypted_bids.contains_key(&receipt.bid_id) {
            return Err(format!("unknown bid {}", receipt.bid_id));
        }
        if receipt.operator_fee_micronero > self.config.operator_fee_cap_micronero {
            return Err(format!(
                "receipt {} exceeds operator fee cap",
                receipt.receipt_id
            ));
        }
        let id = receipt.receipt_id.clone();
        self.settlement_receipts.insert(id.clone(), receipt);
        self.recompute();
        Ok(id)
    }

    pub fn reserve_low_fee_rebate(&mut self, rebate: LowFeeRebate) -> Result<String> {
        if rebate.rebate_bps > self.config.low_fee_rebate_bps {
            return Err(format!(
                "rebate {} exceeds configured bps",
                rebate.rebate_id
            ));
        }
        if !self.settlement_receipts.contains_key(&rebate.receipt_id) {
            return Err(format!("unknown receipt {}", rebate.receipt_id));
        }
        let id = rebate.rebate_id.clone();
        self.low_fee_rebates.insert(id.clone(), rebate);
        self.recompute();
        Ok(id)
    }

    pub fn allocate_redaction_budget(&mut self, budget: RedactionBudget) -> Result<String> {
        if !self.session_cohorts.contains_key(&budget.cohort_id) {
            return Err(format!("unknown cohort {}", budget.cohort_id));
        }
        if budget.spent_units + budget.reserved_units > budget.initial_units {
            return Err(format!("redaction budget {} overdrawn", budget.budget_id));
        }
        let id = budget.budget_id.clone();
        self.redaction_budgets.insert(id.clone(), budget);
        self.recompute();
        Ok(id)
    }

    pub fn record_operator_summary(&mut self, summary: OperatorSafeSummary) -> Result<String> {
        if summary.period_end_height < summary.period_start_height {
            return Err(format!("summary {} has invalid period", summary.summary_id));
        }
        let id = summary.summary_id.clone();
        self.operator_summaries.insert(id.clone(), summary);
        self.recompute();
        Ok(id)
    }

    pub fn recompute(&mut self) {
        self.counters = self.compute_counters();
        self.roots = self.compute_roots();
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "primary_kem_suite": PRIMARY_KEM_SUITE,
            "secondary_kem_suite": SECONDARY_KEM_SUITE,
            "bid_encryption_suite": BID_ENCRYPTION_SUITE,
            "attestation_suite": ATTESTATION_SUITE,
            "settlement_suite": SETTLEMENT_SUITE,
            "operator_summary_suite": OPERATOR_SUMMARY_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "rotation_policies": map_records(&self.rotation_policies, RotationPolicy::public_record),
            "session_cohorts": map_records(&self.session_cohorts, SessionCohort::public_record),
            "encrypted_bids": map_records(&self.encrypted_bids, EncryptedRotationBid::public_record),
            "pq_attestations": map_records(&self.pq_attestations, PqAttestation::public_record),
            "ceremony_windows": map_records(&self.ceremony_windows, KeyCeremonyWindow::public_record),
            "settlement_receipts": map_records(&self.settlement_receipts, SettlementReceipt::public_record),
            "low_fee_rebates": map_records(&self.low_fee_rebates, LowFeeRebate::public_record),
            "redaction_budgets": map_records(&self.redaction_budgets, RedactionBudget::public_record),
            "operator_summaries": map_records(&self.operator_summaries, OperatorSafeSummary::public_record),
            "used_privacy_nullifier_root": string_set_root("USED-PRIVACY-NULLIFIERS", &self.used_privacy_nullifiers),
            "active_cohort_ids": self.active_cohort_ids.iter().cloned().collect::<Vec<_>>(),
            "paused_cohort_ids": self.paused_cohort_ids.iter().cloned().collect::<Vec<_>>(),
            "state_root": self.state_root_without_self_reference(),
        })
    }

    pub fn state_root(&self) -> String {
        self.state_root_without_self_reference()
    }

    fn state_root_without_self_reference(&self) -> String {
        let record = json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "active_cohort_ids": self.active_cohort_ids.iter().cloned().collect::<Vec<_>>(),
            "paused_cohort_ids": self.paused_cohort_ids.iter().cloned().collect::<Vec<_>>(),
        });
        runtime_hash("STATE", &[HashPart::Json(&record)])
    }

    fn compute_counters(&self) -> Counters {
        let settlement_totals =
            self.settlement_receipts
                .values()
                .fold((0_u64, 0_u64, 0_u64), |acc, receipt| {
                    (
                        acc.0 + receipt.rebate_micronero,
                        acc.1 + receipt.clearing_fee_micronero,
                        acc.2 + u64::from(matches!(receipt.status, SettlementStatus::Challenged)),
                    )
                });
        Counters {
            rotation_policy_count: self.rotation_policies.len() as u64,
            session_cohort_count: self.session_cohorts.len() as u64,
            encrypted_bid_count: self.encrypted_bids.len() as u64,
            attestation_count: self.pq_attestations.len() as u64,
            ceremony_window_count: self.ceremony_windows.len() as u64,
            settlement_receipt_count: self.settlement_receipts.len() as u64,
            rebate_count: self.low_fee_rebates.len() as u64,
            redaction_budget_count: self.redaction_budgets.len() as u64,
            operator_summary_count: self.operator_summaries.len() as u64,
            accepted_bid_count: self
                .encrypted_bids
                .values()
                .filter(|bid| bid.status.accepted())
                .count() as u64,
            rejected_bid_count: self
                .encrypted_bids
                .values()
                .filter(|bid| matches!(bid.status, BidStatus::Rejected | BidStatus::Expired))
                .count() as u64,
            activated_cohort_count: self
                .session_cohorts
                .values()
                .filter(|cohort| matches!(cohort.status, CohortStatus::Activated))
                .count() as u64,
            paused_cohort_count: self.paused_cohort_ids.len() as u64,
            challenged_receipt_count: settlement_totals.2,
            total_rebate_micronero: settlement_totals.0,
            total_clearing_fee_micronero: settlement_totals.1,
            total_redaction_units_spent: self
                .redaction_budgets
                .values()
                .map(|budget| budget.spent_units)
                .sum(),
        }
    }

    fn compute_roots(&self) -> Roots {
        Roots {
            rotation_policy_root: merkle_values(
                "ROTATION-POLICY-ROOT",
                self.rotation_policies
                    .values()
                    .map(RotationPolicy::public_record)
                    .collect(),
            ),
            session_cohort_root: merkle_values(
                "SESSION-COHORT-ROOT",
                self.session_cohorts
                    .values()
                    .map(SessionCohort::public_record)
                    .collect(),
            ),
            encrypted_bid_root: merkle_values(
                "ENCRYPTED-BID-ROOT",
                self.encrypted_bids
                    .values()
                    .map(EncryptedRotationBid::public_record)
                    .collect(),
            ),
            attestation_root: merkle_values(
                "PQ-ATTESTATION-ROOT",
                self.pq_attestations
                    .values()
                    .map(PqAttestation::public_record)
                    .collect(),
            ),
            ceremony_window_root: merkle_values(
                "CEREMONY-WINDOW-ROOT",
                self.ceremony_windows
                    .values()
                    .map(KeyCeremonyWindow::public_record)
                    .collect(),
            ),
            settlement_receipt_root: merkle_values(
                "SETTLEMENT-RECEIPT-ROOT",
                self.settlement_receipts
                    .values()
                    .map(SettlementReceipt::public_record)
                    .collect(),
            ),
            low_fee_rebate_root: merkle_values(
                "LOW-FEE-REBATE-ROOT",
                self.low_fee_rebates
                    .values()
                    .map(LowFeeRebate::public_record)
                    .collect(),
            ),
            redaction_budget_root: merkle_values(
                "REDACTION-BUDGET-ROOT",
                self.redaction_budgets
                    .values()
                    .map(RedactionBudget::public_record)
                    .collect(),
            ),
            operator_summary_root: merkle_values(
                "OPERATOR-SUMMARY-ROOT",
                self.operator_summaries
                    .values()
                    .map(OperatorSafeSummary::public_record)
                    .collect(),
            ),
        }
    }

    fn seed_devnet(&mut self) {
        let policy_wallet = RotationPolicy {
            policy_id: sample_id("policy", "wallet-routine", 0),
            kind: RotationPolicyKind::FeeMarketAdaptive,
            session_class: SessionClass::WalletInteractive,
            urgency: RotationUrgency::FeeOptimized,
            min_pq_security_bits: 256,
            max_session_age_blocks: DEFAULT_MAX_ROTATION_AGE_BLOCKS,
            max_messages_per_session: 10_000,
            min_anonymity_set: 65_536,
            require_watchtower_attestation: true,
            allow_low_fee_rebate: true,
            created_at_height: DEVNET_HEIGHT,
        };
        let policy_bridge = RotationPolicy {
            policy_id: sample_id("policy", "bridge-exit", 1),
            kind: RotationPolicyKind::WatchtowerRequired,
            session_class: SessionClass::BridgeExit,
            urgency: RotationUrgency::EntropyRefresh,
            min_pq_security_bits: 256,
            max_session_age_blocks: 7_200,
            max_messages_per_session: 2_048,
            min_anonymity_set: 131_072,
            require_watchtower_attestation: true,
            allow_low_fee_rebate: true,
            created_at_height: DEVNET_HEIGHT + 1,
        };
        self.rotation_policies
            .insert(policy_wallet.policy_id.clone(), policy_wallet.clone());
        self.rotation_policies
            .insert(policy_bridge.policy_id.clone(), policy_bridge.clone());

        let cohort_a = SessionCohort {
            cohort_id: sample_id("cohort", "wallet-sync", 0),
            policy_id: policy_wallet.policy_id.clone(),
            class: SessionClass::WalletInteractive,
            status: CohortStatus::Activated,
            parameter_set: MlKemParameterSet::HybridX25519MlKem1024,
            session_commitment_root: sample_hash("session-commitments", 0),
            entry_nullifier_root: sample_hash("entry-nullifiers", 0),
            view_tag_root: sample_hash("view-tags", 0),
            expected_sessions: 512,
            sealed_sessions: 509,
            active_sessions: 506,
            opened_at_height: DEVNET_HEIGHT + 8,
            bid_close_height: DEVNET_HEIGHT + 80,
            ceremony_open_height: DEVNET_HEIGHT + 88,
            activation_height: DEVNET_HEIGHT + 144,
            retirement_height: None,
        };
        let cohort_b = SessionCohort {
            cohort_id: sample_id("cohort", "bridge-exit", 1),
            policy_id: policy_bridge.policy_id.clone(),
            class: SessionClass::BridgeExit,
            status: CohortStatus::Attesting,
            parameter_set: MlKemParameterSet::MlKem1024,
            session_commitment_root: sample_hash("session-commitments", 1),
            entry_nullifier_root: sample_hash("entry-nullifiers", 1),
            view_tag_root: sample_hash("view-tags", 1),
            expected_sessions: 128,
            sealed_sessions: 122,
            active_sessions: 0,
            opened_at_height: DEVNET_HEIGHT + 32,
            bid_close_height: DEVNET_HEIGHT + 104,
            ceremony_open_height: DEVNET_HEIGHT + 112,
            activation_height: DEVNET_HEIGHT + 176,
            retirement_height: None,
        };
        self.active_cohort_ids.insert(cohort_a.cohort_id.clone());
        self.session_cohorts
            .insert(cohort_a.cohort_id.clone(), cohort_a.clone());
        self.session_cohorts
            .insert(cohort_b.cohort_id.clone(), cohort_b.clone());

        for index in 0..6 {
            let cohort_id = if index < 4 {
                cohort_a.cohort_id.clone()
            } else {
                cohort_b.cohort_id.clone()
            };
            let status = match index {
                0 | 1 => BidStatus::Settled,
                2 | 4 => BidStatus::Cleared,
                3 => BidStatus::RebateReserved,
                _ => BidStatus::Eligible,
            };
            let bid = EncryptedRotationBid {
                bid_id: sample_id("bid", "sealed-rotation", index),
                cohort_id,
                bidder_commitment: sample_hash("bidder-commitment", index),
                sealed_bid_ciphertext_root: sample_hash("sealed-bid-ciphertext", index),
                ml_kem_ciphertext_hash: sample_hash("ml-kem-ciphertext", index),
                fee_commitment: sample_hash("fee-commitment", index),
                max_fee_micronero_commitment: sample_hash("max-fee-commitment", index),
                rebate_claim_commitment: sample_hash("rebate-claim", index),
                privacy_nullifier: sample_hash("privacy-nullifier", index),
                status,
                submitted_at_height: DEVNET_HEIGHT + 40 + index,
                expires_at_height: DEVNET_HEIGHT + 180 + index,
                redaction_units_reserved: 64 + index * 8,
            };
            self.used_privacy_nullifiers
                .insert(bid.privacy_nullifier.clone());
            self.encrypted_bids.insert(bid.bid_id.clone(), bid);
        }

        for index in 0..4 {
            let cohort_id = if index < 2 {
                cohort_a.cohort_id.clone()
            } else {
                cohort_b.cohort_id.clone()
            };
            let attestation = PqAttestation {
                attestation_id: sample_id("attestation", "watcher", index),
                cohort_id,
                bid_id: Some(sample_id("bid", "sealed-rotation", index)),
                watcher_committee_id: format!("pq-watchers-devnet-{}", index % 2),
                transcript_root: sample_hash("attestation-transcript", index),
                kem_parameter_set: MlKemParameterSet::HybridX25519MlKem1024,
                verdict: AttestationVerdict::Observed,
                observed_ciphertext_count: 128 + index as u32 * 32,
                watcher_weight_bps: 7_200 + index * 100,
                evidence_root: sample_hash("attestation-evidence", index),
                attested_at_height: DEVNET_HEIGHT + 120 + index,
            };
            self.pq_attestations
                .insert(attestation.attestation_id.clone(), attestation);
        }

        for index in 0..2 {
            let cohort = if index == 0 { &cohort_a } else { &cohort_b };
            let window = KeyCeremonyWindow {
                window_id: sample_id("window", "ceremony", index),
                cohort_id: cohort.cohort_id.clone(),
                status: if index == 0 {
                    CohortStatus::Activated
                } else {
                    CohortStatus::Attesting
                },
                opens_at_height: cohort.ceremony_open_height,
                closes_at_height: cohort.ceremony_open_height + DEFAULT_CEREMONY_WINDOW_BLOCKS,
                activation_height: cohort.activation_height,
                participant_commitment_root: sample_hash("participants", index),
                transcript_root: sample_hash("ceremony-transcript", index),
                opening_share_root: sample_hash("opening-shares", index),
                operator_guardrail_root: sample_hash("operator-guardrails", index),
                min_successful_openings: if index == 0 { 384 } else { 96 },
                successful_openings: if index == 0 { 506 } else { 119 },
            };
            self.ceremony_windows
                .insert(window.window_id.clone(), window);
        }

        for index in 0..2 {
            let receipt = SettlementReceipt {
                receipt_id: sample_id("receipt", "settlement", index),
                cohort_id: cohort_a.cohort_id.clone(),
                bid_id: sample_id("bid", "sealed-rotation", index),
                status: if index == 0 {
                    SettlementStatus::Finalized
                } else {
                    SettlementStatus::Rebated
                },
                clearing_fee_micronero: DEFAULT_MARKET_CLEARING_FEE_MICRONERO + index * 1_000,
                operator_fee_micronero: 8_000 + index * 500,
                rebate_micronero: 12_000 + index * 700,
                settlement_note_commitment: sample_hash("settlement-note", index),
                monero_anchor_txid_hash: sample_hash("monero-anchor-txid", index),
                l2_receipt_root: sample_hash("l2-receipt", index),
                settled_at_height: DEVNET_HEIGHT + 190 + index,
            };
            self.settlement_receipts
                .insert(receipt.receipt_id.clone(), receipt);
        }

        for index in 0..2 {
            let rebate = LowFeeRebate {
                rebate_id: sample_id("rebate", "low-fee", index),
                receipt_id: sample_id("receipt", "settlement", index),
                cohort_id: cohort_a.cohort_id.clone(),
                beneficiary_commitment: sample_hash("rebate-beneficiary", index),
                rebate_micronero: 12_000 + index * 700,
                rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
                sponsor_pool_id: format!("devnet-session-rotation-sponsor-{}", index),
                claim_nullifier: sample_hash("rebate-claim-nullifier", index),
                reserved_at_height: DEVNET_HEIGHT + 188 + index,
                claimable_at_height: DEVNET_HEIGHT + 208 + index,
            };
            self.low_fee_rebates
                .insert(rebate.rebate_id.clone(), rebate);
        }

        for index in 0..3 {
            let cohort_id = if index < 2 {
                cohort_a.cohort_id.clone()
            } else {
                cohort_b.cohort_id.clone()
            };
            let budget = RedactionBudget {
                budget_id: sample_id("redaction-budget", "cohort", index),
                cohort_id,
                owner_commitment: sample_hash("redaction-owner", index),
                initial_units: DEFAULT_REDACTION_BUDGET_UNITS,
                spent_units: 512 + index * 128,
                reserved_units: 128 + index * 32,
                transcript_redaction_root: sample_hash("transcript-redaction", index),
                operator_visible_digest: sample_hash("operator-visible-digest", index),
                expires_at_height: DEVNET_HEIGHT + 10_000 + index,
            };
            self.redaction_budgets
                .insert(budget.budget_id.clone(), budget);
        }

        let summary = OperatorSafeSummary {
            summary_id: sample_id("summary", "operator-safe", 0),
            cohort_id: cohort_a.cohort_id.clone(),
            period_start_height: DEVNET_HEIGHT,
            period_end_height: DEVNET_HEIGHT + 256,
            active_cohort_count: 1,
            open_bid_count: 4,
            accepted_bid_count: 6,
            rejected_bid_count: 0,
            positive_attestation_count: 4,
            challenged_receipt_count: 0,
            median_clearing_fee_micronero: DEFAULT_MARKET_CLEARING_FEE_MICRONERO,
            max_operator_fee_micronero: 8_500,
            redaction_units_remaining: DEFAULT_REDACTION_BUDGET_UNITS * 3 - 2_304,
            disclosure_floor: "k-anonymous-cohort-only-no-bidder-identifiers".to_string(),
            operator_notes_commitment: sample_hash("operator-notes", 0),
        };
        self.operator_summaries
            .insert(summary.summary_id.clone(), summary);
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn rotation_policy_id(kind: RotationPolicyKind, class: SessionClass, nonce: u64) -> String {
    runtime_hash(
        "ROTATION-POLICY-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(class.as_str()),
            HashPart::U64(nonce),
        ],
    )
}

pub fn cohort_id(policy_id: &str, class: SessionClass, opened_at_height: u64) -> String {
    runtime_hash(
        "SESSION-COHORT-ID",
        &[
            HashPart::Str(policy_id),
            HashPart::Str(class.as_str()),
            HashPart::U64(opened_at_height),
        ],
    )
}

pub fn encrypted_bid_id(
    cohort_id: &str,
    bidder_commitment: &str,
    privacy_nullifier: &str,
) -> String {
    runtime_hash(
        "ENCRYPTED-BID-ID",
        &[
            HashPart::Str(cohort_id),
            HashPart::Str(bidder_commitment),
            HashPart::Str(privacy_nullifier),
        ],
    )
}

pub fn settlement_receipt_id(cohort_id: &str, bid_id: &str, settled_at_height: u64) -> String {
    runtime_hash(
        "SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(cohort_id),
            HashPart::Str(bid_id),
            HashPart::U64(settled_at_height),
        ],
    )
}

fn runtime_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-ML-KEM-SESSION-KEY-ROTATION-MARKET:{domain}"),
        parts,
        32,
    )
}

fn sample_id(kind: &str, label: &str, index: u64) -> String {
    runtime_hash(
        "DEVNET-ID",
        &[
            HashPart::Str(kind),
            HashPart::Str(label),
            HashPart::U64(index),
        ],
    )
}

fn sample_hash(label: &str, index: u64) -> String {
    runtime_hash("DEVNET-HASH", &[HashPart::Str(label), HashPart::U64(index)])
}

fn merkle_values(domain: &str, mut values: Vec<Value>) -> String {
    values.sort_by_key(crate::hash::canonical_json_string);
    merkle_root(domain, &values)
}

fn string_set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn map_records<T>(map: &BTreeMap<String, T>, f: fn(&T) -> Value) -> Value {
    Value::Array(map.values().map(f).collect())
}

fn bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        0
    } else {
        numerator.saturating_mul(MAX_BPS) / denominator
    }
}
