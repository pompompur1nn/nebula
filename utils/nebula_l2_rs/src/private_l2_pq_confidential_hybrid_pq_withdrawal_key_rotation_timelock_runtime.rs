use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = PrivateL2PqConfidentialHybridPqWithdrawalKeyRotationTimelockRuntimeResult<T>;
pub type PrivateL2PqConfidentialHybridPqWithdrawalKeyRotationTimelockRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_HYBRID_PQ_WITHDRAWAL_KEY_ROTATION_TIMELOCK_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-hybrid-pq-withdrawal-key-rotation-timelock-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_HYBRID_PQ_WITHDRAWAL_KEY_ROTATION_TIMELOCK_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_SLOT: u64 = 918_400;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-stagenet-private-exit-devnet";
pub const DEFAULT_WITHDRAWAL_ASSET_ID: &str = "xmr-private-withdrawal-note";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SIGNATURE_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-withdrawal-key-rotation-timelock-v1";
pub const PQ_HYBRID_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-key-rotation-rollover-attestation-v1";
pub const ESCROW_COMMITMENT_SCHEME: &str = "confidential-hybrid-pq-key-escrow-commitment-v1";
pub const QUARANTINE_SCHEME: &str = "legacy-withdrawal-key-quarantine-root-v1";
pub const CHALLENGE_SCHEME: &str = "hybrid-pq-key-rotation-timelock-challenge-window-root-v1";
pub const REBATE_SCHEME: &str = "low-fee-key-rotation-withdrawal-fee-credit-rebate-root-v1";
pub const REDACTION_SCHEME: &str = "operator-safe-key-rotation-redaction-budget-root-v1";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_WITHDRAWAL_QUORUM_BPS: u64 = 7_500;
pub const DEFAULT_ROLLOVER_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_EMERGENCY_QUORUM_BPS: u64 = 9_000;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 14;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 6;
pub const DEFAULT_KEY_ESCROW_FLOOR_PICONERO: u64 = 25_000_000_000;
pub const DEFAULT_EPOCH_LENGTH_SLOTS: u64 = 7_200;
pub const DEFAULT_ROLLOVER_GRACE_SLOTS: u64 = 360;
pub const DEFAULT_CHALLENGE_WINDOW_SLOTS: u64 = 180;
pub const DEFAULT_QUARANTINE_SLOTS: u64 = 14_400;
pub const DEFAULT_REDACTION_PUBLIC_BYTE_LIMIT: u64 = 1_280;
pub const DEFAULT_MAX_SIGNER_SETS: usize = 262_144;
pub const DEFAULT_MAX_SIGNERS: usize = 4_194_304;
pub const DEFAULT_MAX_EPOCHS: usize = 524_288;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 8_388_608;
pub const DEFAULT_MAX_ESCROWS: usize = 4_194_304;
pub const DEFAULT_MAX_QUARANTINES: usize = 1_048_576;
pub const DEFAULT_MAX_CHALLENGES: usize = 2_097_152;
pub const DEFAULT_MAX_REBATES: usize = 2_097_152;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 2_097_152;
pub const DEFAULT_MAX_OPERATOR_SUMMARIES: usize = 262_144;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerSetStatus {
    Candidate,
    Warming,
    Active,
    RolloverPending,
    Grace,
    Retired,
    Quarantined,
    Slashed,
}

impl SignerSetStatus {
    pub fn can_authorize_withdrawals(self) -> bool {
        matches!(self, Self::Active | Self::Grace)
    }

    pub fn can_receive_rollover(self) -> bool {
        matches!(
            self,
            Self::Candidate | Self::Warming | Self::RolloverPending
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Warming => "warming",
            Self::Active => "active",
            Self::RolloverPending => "rollover_pending",
            Self::Grace => "grace",
            Self::Retired => "retired",
            Self::Quarantined => "quarantined",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerStatus {
    Candidate,
    Bonded,
    Active,
    RotatingOut,
    LegacyQuarantined,
    Retired,
    Slashed,
}

impl SignerStatus {
    pub fn contributes_weight(self) -> bool {
        matches!(self, Self::Bonded | Self::Active | Self::RotatingOut)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalEpochStatus {
    Scheduled,
    Open,
    RolloverCollecting,
    ChallengeOpen,
    RolloverFinalized,
    Grace,
    Closed,
    EmergencyPaused,
}

impl WithdrawalEpochStatus {
    pub fn accepts_attestations(self) -> bool {
        matches!(
            self,
            Self::Open | Self::RolloverCollecting | Self::ChallengeOpen | Self::Grace
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloverAttestationKind {
    WithdrawalQuorumObserved,
    NewSignerSetCommitted,
    LegacySignerRetired,
    EscrowCoverageObserved,
    PrivacySetObserved,
    FeeBoundObserved,
    EmergencyStopObserved,
    FraudWarning,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloverAttestationStatus {
    Submitted,
    Counted,
    Superseded,
    Challenged,
    Rejected,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscrowStatus {
    Pending,
    Locked,
    Active,
    Unbonding,
    Released,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    LegacyScheme,
    MissedRollover,
    DuplicateKeyMaterial,
    LowPqSecurity,
    ChallengePending,
    FraudEvidence,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    EvidenceQueued,
    Upheld,
    Rejected,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeCreditStatus {
    Reserved,
    Earned,
    Paid,
    Expired,
    ClawedBack,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub withdrawal_asset_id: String,
    pub fee_asset_id: String,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub withdrawal_quorum_bps: u64,
    pub rollover_quorum_bps: u64,
    pub emergency_quorum_bps: u64,
    pub max_user_fee_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub key_escrow_commitment_floor_piconero: u64,
    pub epoch_length_slots: u64,
    pub rollover_grace_slots: u64,
    pub challenge_window_slots: u64,
    pub quarantine_slots: u64,
    pub redaction_public_byte_limit: u64,
    pub max_signer_sets: usize,
    pub max_signers: usize,
    pub max_epochs: usize,
    pub max_attestations: usize,
    pub max_key_escrows: usize,
    pub max_quarantines: usize,
    pub max_challenges: usize,
    pub max_rebates: usize,
    pub max_redaction_budgets: usize,
    pub max_operator_summaries: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            withdrawal_asset_id: DEFAULT_WITHDRAWAL_ASSET_ID.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            withdrawal_quorum_bps: DEFAULT_WITHDRAWAL_QUORUM_BPS,
            rollover_quorum_bps: DEFAULT_ROLLOVER_QUORUM_BPS,
            emergency_quorum_bps: DEFAULT_EMERGENCY_QUORUM_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            key_escrow_commitment_floor_piconero: DEFAULT_KEY_ESCROW_FLOOR_PICONERO,
            epoch_length_slots: DEFAULT_EPOCH_LENGTH_SLOTS,
            rollover_grace_slots: DEFAULT_ROLLOVER_GRACE_SLOTS,
            challenge_window_slots: DEFAULT_CHALLENGE_WINDOW_SLOTS,
            quarantine_slots: DEFAULT_QUARANTINE_SLOTS,
            redaction_public_byte_limit: DEFAULT_REDACTION_PUBLIC_BYTE_LIMIT,
            max_signer_sets: DEFAULT_MAX_SIGNER_SETS,
            max_signers: DEFAULT_MAX_SIGNERS,
            max_epochs: DEFAULT_MAX_EPOCHS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_key_escrows: DEFAULT_MAX_ESCROWS,
            max_quarantines: DEFAULT_MAX_QUARANTINES,
            max_challenges: DEFAULT_MAX_CHALLENGES,
            max_rebates: DEFAULT_MAX_REBATES,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            max_operator_summaries: DEFAULT_MAX_OPERATOR_SUMMARIES,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_bps("withdrawal_quorum_bps", self.withdrawal_quorum_bps)?;
        ensure_bps("rollover_quorum_bps", self.rollover_quorum_bps)?;
        ensure_bps("emergency_quorum_bps", self.emergency_quorum_bps)?;
        ensure_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        ensure_bps("low_fee_rebate_bps", self.low_fee_rebate_bps)?;
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("config min_pq_security_bits below 256-bit target".to_string());
        }
        if self.min_privacy_set_size < DEFAULT_MIN_PRIVACY_SET_SIZE {
            return Err("config min_privacy_set_size below private L2 floor".to_string());
        }
        if self.epoch_length_slots == 0
            || self.rollover_grace_slots == 0
            || self.challenge_window_slots == 0
        {
            return Err("epoch, grace, and challenge windows must be non-zero".to_string());
        }
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub next_sequence: u64,
    pub signer_sets: u64,
    pub signers: u64,
    pub withdrawal_epochs: u64,
    pub rollover_attestations: u64,
    pub key_escrow_commitments: u64,
    pub legacy_quarantines: u64,
    pub challenge_windows: u64,
    pub fee_credit_rebates: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub rejected_records: u64,
}

impl Counters {
    fn allocate(&mut self, prefix: &str) -> String {
        self.next_sequence = self.next_sequence.saturating_add(1);
        format!("{prefix}-{:012}", self.next_sequence)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub signer_set_root: String,
    pub signer_root: String,
    pub withdrawal_epoch_root: String,
    pub rollover_attestation_root: String,
    pub key_escrow_commitment_root: String,
    pub legacy_quarantine_root: String,
    pub challenge_window_root: String,
    pub fee_credit_rebate_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub nullifier_root: String,
    pub safety_root: String,
    pub privacy_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HybridPqWithdrawalKeySet {
    pub signer_set_id: String,
    pub status: SignerSetStatus,
    pub activation_slot: u64,
    pub retirement_slot: u64,
    pub signer_count: u64,
    pub active_weight_bps: u64,
    pub slh_dsa_public_key_root: String,
    pub ml_dsa_public_key_root: String,
    pub membership_nullifier_root: String,
    pub withdrawal_policy_root: String,
    pub operator_hint_root: String,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
}

impl HybridPqWithdrawalKeySet {
    pub fn root(&self) -> String {
        object_root("hybrid-pq-withdrawal-key-set", self)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "signer_set_id": self.signer_set_id,
            "status": self.status,
            "activation_slot": self.activation_slot,
            "retirement_slot": self.retirement_slot,
            "signer_count": self.signer_count,
            "active_weight_bps": self.active_weight_bps,
            "slh_dsa_public_key_root": self.slh_dsa_public_key_root,
            "ml_dsa_public_key_root": self.ml_dsa_public_key_root,
            "membership_nullifier_root": self.membership_nullifier_root,
            "withdrawal_policy_root": self.withdrawal_policy_root,
            "operator_hint_root": self.operator_hint_root,
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HybridPqWithdrawalKey {
    pub signer_id: String,
    pub signer_set_id: String,
    pub status: SignerStatus,
    pub weight_bps: u64,
    pub slh_dsa_public_key_commitment: String,
    pub proof_of_possession_root: String,
    pub escrow_id: String,
    pub legacy_key_nullifier: String,
    pub joined_slot: u64,
    pub exit_slot: u64,
    pub pq_security_bits: u16,
}

impl HybridPqWithdrawalKey {
    pub fn root(&self) -> String {
        object_root("hybrid-pq-withdrawal-key", self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WithdrawalQuorumEpoch {
    pub epoch_id: String,
    pub status: WithdrawalEpochStatus,
    pub active_signer_set_id: String,
    pub next_signer_set_id: String,
    pub epoch_index: u64,
    pub start_slot: u64,
    pub rollover_slot: u64,
    pub challenge_deadline_slot: u64,
    pub close_slot: u64,
    pub withdrawal_quorum_bps: u64,
    pub rollover_quorum_bps: u64,
    pub emergency_quorum_bps: u64,
    pub withdrawal_batch_root: String,
    pub nullifier_set_root: String,
    pub redaction_policy_root: String,
    pub max_user_fee_bps: u64,
    pub min_privacy_set_size: u64,
}

impl WithdrawalQuorumEpoch {
    pub fn root(&self) -> String {
        object_root("withdrawal-quorum-epoch", self)
    }

    pub fn challenge_is_open_at(&self, slot: u64) -> bool {
        self.rollover_slot <= slot && slot <= self.challenge_deadline_slot
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RolloverAttestation {
    pub attestation_id: String,
    pub epoch_id: String,
    pub signer_set_id: String,
    pub kind: RolloverAttestationKind,
    pub status: RolloverAttestationStatus,
    pub statement_root: String,
    pub slh_dsa_signature_root: String,
    pub hybrid_ml_dsa_signature_root: String,
    pub transcript_root: String,
    pub signer_bitmap_root: String,
    pub signer_weight_bps: u64,
    pub observed_slot: u64,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
}

impl RolloverAttestation {
    pub fn root(&self) -> String {
        object_root("rollover-attestation", self)
    }

    pub fn is_safety_positive(&self) -> bool {
        !matches!(
            self.kind,
            RolloverAttestationKind::EmergencyStopObserved | RolloverAttestationKind::FraudWarning
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KeyEscrowCommitment {
    pub escrow_id: String,
    pub signer_id: String,
    pub signer_set_id: String,
    pub status: EscrowStatus,
    pub escrow_commitment_root: String,
    pub reserve_proof_root: String,
    pub amount_piconero: u64,
    pub locked_slot: u64,
    pub unlock_slot: u64,
    pub slash_claim_root: String,
}

impl KeyEscrowCommitment {
    pub fn root(&self) -> String {
        object_root("key-escrow-commitment", self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LegacySignerQuarantine {
    pub quarantine_id: String,
    pub signer_id: String,
    pub signer_set_id: String,
    pub reason: QuarantineReason,
    pub legacy_key_nullifier: String,
    pub quarantine_root: String,
    pub evidence_root: String,
    pub start_slot: u64,
    pub release_slot: u64,
    pub slashed: bool,
}

impl LegacySignerQuarantine {
    pub fn root(&self) -> String {
        object_root("legacy-withdrawal-key-quarantine", self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChallengeWindow {
    pub challenge_id: String,
    pub epoch_id: String,
    pub attestation_id: String,
    pub challenger_commitment: String,
    pub status: ChallengeStatus,
    pub evidence_root: String,
    pub response_root: String,
    pub opened_slot: u64,
    pub deadline_slot: u64,
    pub slash_amount_piconero: u64,
}

impl ChallengeWindow {
    pub fn root(&self) -> String {
        object_root("challenge-window", self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeCreditRebate {
    pub rebate_id: String,
    pub epoch_id: String,
    pub signer_set_id: String,
    pub status: FeeCreditStatus,
    pub beneficiary_commitment_root: String,
    pub fee_credit_pool_root: String,
    pub rebate_bps: u64,
    pub rebate_amount_piconero: u64,
    pub earned_slot: u64,
    pub expires_slot: u64,
}

impl FeeCreditRebate {
    pub fn root(&self) -> String {
        object_root("fee-credit-rebate", self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub target_id: String,
    pub budget_root: String,
    pub public_fields: BTreeSet<String>,
    pub redacted_fields: BTreeSet<String>,
    pub max_public_bytes: u64,
    pub actual_public_bytes: u64,
    pub privacy_set_size: u64,
    pub published_slot: u64,
    pub operator_safe: bool,
}

impl RedactionBudget {
    pub fn root(&self) -> String {
        object_root("redaction-budget", self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSafeSummary {
    pub summary_id: String,
    pub slot: u64,
    pub active_signer_set_count: u64,
    pub active_signer_count: u64,
    pub open_epoch_count: u64,
    pub counted_attestation_count: u64,
    pub quarantined_signer_count: u64,
    pub open_challenge_count: u64,
    pub median_fee_bps: u64,
    pub rebate_bps: u64,
    pub aggregate_rollover_weight_bps: u64,
    pub redaction_budget_root: String,
    pub safety_summary_root: String,
}

impl OperatorSafeSummary {
    pub fn root(&self) -> String {
        object_root("operator-safe-summary", self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RolloverReadiness {
    pub epoch_id: String,
    pub active_signer_set_id: String,
    pub next_signer_set_id: String,
    pub counted_rollover_weight_bps: u64,
    pub required_rollover_weight_bps: u64,
    pub open_challenge_count: u64,
    pub quarantined_legacy_signer_count: u64,
    pub escrow_coverage_piconero: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub ready: bool,
}

impl RolloverReadiness {
    pub fn root(&self) -> String {
        object_root("rollover-readiness", self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BridgeSafetyPosture {
    pub active_bond_piconero: u64,
    pub locked_bond_piconero: u64,
    pub slashed_bond_piconero: u64,
    pub open_challenge_count: u64,
    pub fraud_warning_count: u64,
    pub emergency_stop_count: u64,
    pub emergency_quorum_bps: u64,
    pub safety_root: String,
}

impl BridgeSafetyPosture {
    pub fn root(&self) -> String {
        object_root("bridge-safety-posture", self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyPosture {
    pub min_privacy_set_size: u64,
    pub lowest_observed_privacy_set_size: u64,
    pub redaction_budget_count: u64,
    pub operator_safe_budget_count: u64,
    pub total_public_bytes: u64,
    pub redacted_field_count: u64,
    pub privacy_root: String,
}

impl PrivacyPosture {
    pub fn root(&self) -> String {
        object_root("privacy-posture", self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeePosture {
    pub max_user_fee_bps: u64,
    pub lowest_epoch_fee_bps: u64,
    pub earned_rebate_count: u64,
    pub paid_rebate_count: u64,
    pub total_rebate_piconero: u64,
    pub rebate_root: String,
}

impl LowFeePosture {
    pub fn root(&self) -> String {
        object_root("low-fee-posture", self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegisterSignerSetRequest {
    pub activation_slot: u64,
    pub retirement_slot: u64,
    pub signer_count: u64,
    pub active_weight_bps: u64,
    pub slh_dsa_public_key_root: String,
    pub ml_dsa_public_key_root: String,
    pub membership_nullifier_root: String,
    pub withdrawal_policy_root: String,
    pub operator_hint_root: String,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegisterSignerRequest {
    pub signer_set_id: String,
    pub weight_bps: u64,
    pub slh_dsa_public_key_commitment: String,
    pub proof_of_possession_root: String,
    pub escrow_commitment_root: String,
    pub reserve_proof_root: String,
    pub bond_amount_piconero: u64,
    pub legacy_key_nullifier: String,
    pub joined_slot: u64,
    pub exit_slot: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScheduleEpochRequest {
    pub active_signer_set_id: String,
    pub next_signer_set_id: String,
    pub epoch_index: u64,
    pub start_slot: u64,
    pub withdrawal_batch_root: String,
    pub nullifier_set_root: String,
    pub redaction_policy_root: String,
    pub max_user_fee_bps: u64,
    pub min_privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubmitRolloverAttestationRequest {
    pub epoch_id: String,
    pub signer_set_id: String,
    pub kind: RolloverAttestationKind,
    pub statement_root: String,
    pub slh_dsa_signature_root: String,
    pub hybrid_ml_dsa_signature_root: String,
    pub transcript_root: String,
    pub signer_bitmap_root: String,
    pub signer_weight_bps: u64,
    pub observed_slot: u64,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QuarantineSignerRequest {
    pub signer_id: String,
    pub reason: QuarantineReason,
    pub evidence_root: String,
    pub start_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpenChallengeRequest {
    pub epoch_id: String,
    pub attestation_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub opened_slot: u64,
    pub slash_amount_piconero: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssueFeeCreditRebateRequest {
    pub epoch_id: String,
    pub signer_set_id: String,
    pub beneficiary_commitment_root: String,
    pub fee_credit_pool_root: String,
    pub rebate_bps: u64,
    pub rebate_amount_piconero: u64,
    pub earned_slot: u64,
    pub expires_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublishRedactionBudgetRequest {
    pub target_id: String,
    pub public_fields: BTreeSet<String>,
    pub redacted_fields: BTreeSet<String>,
    pub max_public_bytes: u64,
    pub actual_public_bytes: u64,
    pub privacy_set_size: u64,
    pub published_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublishOperatorSummaryRequest {
    pub slot: u64,
    pub median_fee_bps: u64,
    pub rebate_bps: u64,
    pub aggregate_rollover_weight_bps: u64,
    pub safety_summary_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub protocol_version: String,
    pub schema_version: u64,
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub signer_sets: BTreeMap<String, HybridPqWithdrawalKeySet>,
    pub signers: BTreeMap<String, HybridPqWithdrawalKey>,
    pub withdrawal_epochs: BTreeMap<String, WithdrawalQuorumEpoch>,
    pub rollover_attestations: BTreeMap<String, RolloverAttestation>,
    pub key_escrow_commitments: BTreeMap<String, KeyEscrowCommitment>,
    pub legacy_quarantines: BTreeMap<String, LegacySignerQuarantine>,
    pub challenge_windows: BTreeMap<String, ChallengeWindow>,
    pub fee_credit_rebates: BTreeMap<String, FeeCreditRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSafeSummary>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            signer_sets: BTreeMap::new(),
            signers: BTreeMap::new(),
            withdrawal_epochs: BTreeMap::new(),
            rollover_attestations: BTreeMap::new(),
            key_escrow_commitments: BTreeMap::new(),
            legacy_quarantines: BTreeMap::new(),
            challenge_windows: BTreeMap::new(),
            fee_credit_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }
}

impl State {
    pub fn devnet() -> Self {
        devnet()
    }

    pub fn register_signer_set(&mut self, request: RegisterSignerSetRequest) -> Result<String> {
        self.config.validate()?;
        self.ensure_capacity(
            "signer_sets",
            self.signer_sets.len(),
            self.config.max_signer_sets,
        )?;
        ensure_bps("active_weight_bps", request.active_weight_bps)?;
        self.ensure_pq_and_privacy(request.pq_security_bits, request.privacy_set_size)?;
        if request.retirement_slot <= request.activation_slot {
            return Err("signer set retirement_slot must exceed activation_slot".to_string());
        }

        let signer_set_id = self.counters.allocate("hybrid-pq-withdrawal-key-set");
        let signer_set = HybridPqWithdrawalKeySet {
            signer_set_id: signer_set_id.clone(),
            status: SignerSetStatus::Candidate,
            activation_slot: request.activation_slot,
            retirement_slot: request.retirement_slot,
            signer_count: request.signer_count,
            active_weight_bps: request.active_weight_bps,
            slh_dsa_public_key_root: request.slh_dsa_public_key_root,
            ml_dsa_public_key_root: request.ml_dsa_public_key_root,
            membership_nullifier_root: request.membership_nullifier_root,
            withdrawal_policy_root: request.withdrawal_policy_root,
            operator_hint_root: request.operator_hint_root,
            pq_security_bits: request.pq_security_bits,
            privacy_set_size: request.privacy_set_size,
        };
        self.signer_sets.insert(signer_set_id.clone(), signer_set);
        self.counters.signer_sets = self.counters.signer_sets.saturating_add(1);
        self.refresh_roots();
        Ok(signer_set_id)
    }

    pub fn register_signer(&mut self, request: RegisterSignerRequest) -> Result<String> {
        self.ensure_capacity("signers", self.signers.len(), self.config.max_signers)?;
        ensure_bps("weight_bps", request.weight_bps)?;
        self.ensure_pq_and_privacy(request.pq_security_bits, self.config.min_privacy_set_size)?;
        if request.bond_amount_piconero < self.config.key_escrow_commitment_floor_piconero {
            return Err("key escrow commitment amount below configured floor".to_string());
        }
        if !self.signer_sets.contains_key(&request.signer_set_id) {
            return Err(format!("unknown signer set {}", request.signer_set_id));
        }

        let signer_id = self.counters.allocate("hybrid-pq-withdrawal-key");
        let escrow_id = self.counters.allocate("signer-bond");
        let signer = HybridPqWithdrawalKey {
            signer_id: signer_id.clone(),
            signer_set_id: request.signer_set_id.clone(),
            status: SignerStatus::Bonded,
            weight_bps: request.weight_bps,
            slh_dsa_public_key_commitment: request.slh_dsa_public_key_commitment,
            proof_of_possession_root: request.proof_of_possession_root,
            escrow_id: escrow_id.clone(),
            legacy_key_nullifier: request.legacy_key_nullifier,
            joined_slot: request.joined_slot,
            exit_slot: request.exit_slot,
            pq_security_bits: request.pq_security_bits,
        };
        let bond = KeyEscrowCommitment {
            escrow_id: escrow_id.clone(),
            signer_id: signer_id.clone(),
            signer_set_id: request.signer_set_id,
            status: EscrowStatus::Locked,
            escrow_commitment_root: request.escrow_commitment_root,
            reserve_proof_root: request.reserve_proof_root,
            amount_piconero: request.bond_amount_piconero,
            locked_slot: request.joined_slot,
            unlock_slot: request.exit_slot,
            slash_claim_root: stable_root("empty-slash-claim", &json!({})),
        };
        self.signers.insert(signer_id.clone(), signer);
        self.key_escrow_commitments.insert(escrow_id, bond);
        self.counters.signers = self.counters.signers.saturating_add(1);
        self.counters.key_escrow_commitments =
            self.counters.key_escrow_commitments.saturating_add(1);
        self.refresh_roots();
        Ok(signer_id)
    }

    pub fn schedule_epoch(&mut self, request: ScheduleEpochRequest) -> Result<String> {
        self.ensure_capacity(
            "withdrawal_epochs",
            self.withdrawal_epochs.len(),
            self.config.max_epochs,
        )?;
        ensure_bps("max_user_fee_bps", request.max_user_fee_bps)?;
        if request.max_user_fee_bps > self.config.max_user_fee_bps {
            return Err("epoch max_user_fee_bps exceeds low-fee policy".to_string());
        }
        if request.min_privacy_set_size < self.config.min_privacy_set_size {
            return Err("epoch privacy set below configured minimum".to_string());
        }
        self.require_signer_set(&request.active_signer_set_id)?;
        self.require_signer_set(&request.next_signer_set_id)?;

        let epoch_id = self.counters.allocate("withdrawal-quorum-epoch");
        let rollover_slot = request
            .start_slot
            .saturating_add(self.config.epoch_length_slots);
        let challenge_deadline_slot =
            rollover_slot.saturating_add(self.config.challenge_window_slots);
        let close_slot = challenge_deadline_slot.saturating_add(self.config.rollover_grace_slots);
        let epoch = WithdrawalQuorumEpoch {
            epoch_id: epoch_id.clone(),
            status: WithdrawalEpochStatus::Scheduled,
            active_signer_set_id: request.active_signer_set_id,
            next_signer_set_id: request.next_signer_set_id,
            epoch_index: request.epoch_index,
            start_slot: request.start_slot,
            rollover_slot,
            challenge_deadline_slot,
            close_slot,
            withdrawal_quorum_bps: self.config.withdrawal_quorum_bps,
            rollover_quorum_bps: self.config.rollover_quorum_bps,
            emergency_quorum_bps: self.config.emergency_quorum_bps,
            withdrawal_batch_root: request.withdrawal_batch_root,
            nullifier_set_root: request.nullifier_set_root,
            redaction_policy_root: request.redaction_policy_root,
            max_user_fee_bps: request.max_user_fee_bps,
            min_privacy_set_size: request.min_privacy_set_size,
        };
        self.withdrawal_epochs.insert(epoch_id.clone(), epoch);
        self.counters.withdrawal_epochs = self.counters.withdrawal_epochs.saturating_add(1);
        self.refresh_roots();
        Ok(epoch_id)
    }

    pub fn submit_rollover_attestation(
        &mut self,
        request: SubmitRolloverAttestationRequest,
    ) -> Result<String> {
        self.ensure_capacity(
            "rollover_attestations",
            self.rollover_attestations.len(),
            self.config.max_attestations,
        )?;
        self.ensure_pq_and_privacy(request.pq_security_bits, request.privacy_set_size)?;
        ensure_bps("signer_weight_bps", request.signer_weight_bps)?;

        let epoch = self
            .withdrawal_epochs
            .get(&request.epoch_id)
            .ok_or_else(|| format!("unknown epoch {}", request.epoch_id))?;
        if !epoch.status.accepts_attestations() && epoch.status != WithdrawalEpochStatus::Scheduled
        {
            return Err("epoch does not accept rollover attestations".to_string());
        }
        self.require_signer_set(&request.signer_set_id)?;

        let attestation_id = self.counters.allocate("rollover-attestation");
        let status = if request.signer_weight_bps >= epoch.rollover_quorum_bps
            && request.kind != RolloverAttestationKind::FraudWarning
        {
            RolloverAttestationStatus::Counted
        } else {
            RolloverAttestationStatus::Submitted
        };
        let attestation = RolloverAttestation {
            attestation_id: attestation_id.clone(),
            epoch_id: request.epoch_id,
            signer_set_id: request.signer_set_id,
            kind: request.kind,
            status,
            statement_root: request.statement_root,
            slh_dsa_signature_root: request.slh_dsa_signature_root,
            hybrid_ml_dsa_signature_root: request.hybrid_ml_dsa_signature_root,
            transcript_root: request.transcript_root,
            signer_bitmap_root: request.signer_bitmap_root,
            signer_weight_bps: request.signer_weight_bps,
            observed_slot: request.observed_slot,
            pq_security_bits: request.pq_security_bits,
            privacy_set_size: request.privacy_set_size,
        };
        self.rollover_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.rollover_attestations = self.counters.rollover_attestations.saturating_add(1);
        self.recompute_epoch_statuses();
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn quarantine_legacy_signer(&mut self, request: QuarantineSignerRequest) -> Result<String> {
        self.ensure_capacity(
            "legacy_quarantines",
            self.legacy_quarantines.len(),
            self.config.max_quarantines,
        )?;
        let signer = self
            .signers
            .get_mut(&request.signer_id)
            .ok_or_else(|| format!("unknown signer {}", request.signer_id))?;
        signer.status = SignerStatus::LegacyQuarantined;
        let quarantine_id = self.counters.allocate("legacy-signer-quarantine");
        let quarantine = LegacySignerQuarantine {
            quarantine_id: quarantine_id.clone(),
            signer_id: request.signer_id,
            signer_set_id: signer.signer_set_id.clone(),
            reason: request.reason,
            legacy_key_nullifier: signer.legacy_key_nullifier.clone(),
            quarantine_root: stable_root(
                QUARANTINE_SCHEME,
                &json!({
                    "signer_set_id": signer.signer_set_id,
                    "legacy_key_nullifier": signer.legacy_key_nullifier,
                    "reason": request.reason,
                }),
            ),
            evidence_root: request.evidence_root,
            start_slot: request.start_slot,
            release_slot: request
                .start_slot
                .saturating_add(self.config.quarantine_slots),
            slashed: matches!(request.reason, QuarantineReason::FraudEvidence),
        };
        self.legacy_quarantines
            .insert(quarantine_id.clone(), quarantine);
        self.counters.legacy_quarantines = self.counters.legacy_quarantines.saturating_add(1);
        self.refresh_roots();
        Ok(quarantine_id)
    }

    pub fn open_challenge(&mut self, request: OpenChallengeRequest) -> Result<String> {
        self.ensure_capacity(
            "challenge_windows",
            self.challenge_windows.len(),
            self.config.max_challenges,
        )?;
        let epoch = self
            .withdrawal_epochs
            .get(&request.epoch_id)
            .ok_or_else(|| format!("unknown epoch {}", request.epoch_id))?;
        if !epoch.challenge_is_open_at(request.opened_slot) {
            return Err("challenge opened outside epoch challenge window".to_string());
        }
        if !self
            .rollover_attestations
            .contains_key(&request.attestation_id)
        {
            return Err(format!("unknown attestation {}", request.attestation_id));
        }

        let challenge_id = self.counters.allocate("challenge-window");
        let challenge = ChallengeWindow {
            challenge_id: challenge_id.clone(),
            epoch_id: request.epoch_id,
            attestation_id: request.attestation_id,
            challenger_commitment: request.challenger_commitment,
            status: ChallengeStatus::Open,
            evidence_root: request.evidence_root,
            response_root: stable_root("empty-challenge-response", &json!({})),
            opened_slot: request.opened_slot,
            deadline_slot: request
                .opened_slot
                .saturating_add(self.config.challenge_window_slots),
            slash_amount_piconero: request.slash_amount_piconero,
        };
        self.challenge_windows
            .insert(challenge_id.clone(), challenge);
        self.counters.challenge_windows = self.counters.challenge_windows.saturating_add(1);
        if let Some(attestation) = self.rollover_attestations.get_mut(&request.attestation_id) {
            attestation.status = RolloverAttestationStatus::Challenged;
        }
        self.recompute_epoch_statuses();
        self.refresh_roots();
        Ok(challenge_id)
    }

    pub fn issue_fee_credit_rebate(
        &mut self,
        request: IssueFeeCreditRebateRequest,
    ) -> Result<String> {
        self.ensure_capacity(
            "fee_credit_rebates",
            self.fee_credit_rebates.len(),
            self.config.max_rebates,
        )?;
        ensure_bps("rebate_bps", request.rebate_bps)?;
        if request.rebate_bps > self.config.low_fee_rebate_bps {
            return Err("rebate_bps exceeds configured low-fee rebate".to_string());
        }
        if request.expires_slot <= request.earned_slot {
            return Err("rebate expires_slot must exceed earned_slot".to_string());
        }
        if !self.withdrawal_epochs.contains_key(&request.epoch_id) {
            return Err(format!("unknown epoch {}", request.epoch_id));
        }
        self.require_signer_set(&request.signer_set_id)?;

        let rebate_id = self.counters.allocate("fee-credit-rebate");
        let rebate = FeeCreditRebate {
            rebate_id: rebate_id.clone(),
            epoch_id: request.epoch_id,
            signer_set_id: request.signer_set_id,
            status: FeeCreditStatus::Earned,
            beneficiary_commitment_root: request.beneficiary_commitment_root,
            fee_credit_pool_root: request.fee_credit_pool_root,
            rebate_bps: request.rebate_bps,
            rebate_amount_piconero: request.rebate_amount_piconero,
            earned_slot: request.earned_slot,
            expires_slot: request.expires_slot,
        };
        self.fee_credit_rebates.insert(rebate_id.clone(), rebate);
        self.counters.fee_credit_rebates = self.counters.fee_credit_rebates.saturating_add(1);
        self.refresh_roots();
        Ok(rebate_id)
    }

    pub fn publish_redaction_budget(
        &mut self,
        request: PublishRedactionBudgetRequest,
    ) -> Result<String> {
        self.ensure_capacity(
            "redaction_budgets",
            self.redaction_budgets.len(),
            self.config.max_redaction_budgets,
        )?;
        if request.actual_public_bytes > request.max_public_bytes {
            return Err("redaction actual_public_bytes exceeds max_public_bytes".to_string());
        }
        if request.max_public_bytes > self.config.redaction_public_byte_limit {
            return Err("redaction budget exceeds operator-safe public byte limit".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("redaction budget privacy set below configured minimum".to_string());
        }

        let budget_id = self.counters.allocate("redaction-budget");
        let budget = RedactionBudget {
            budget_id: budget_id.clone(),
            target_id: request.target_id,
            budget_root: stable_root(
                REDACTION_SCHEME,
                &json!({
                    "public_fields": request.public_fields,
                    "redacted_fields": request.redacted_fields,
                    "max_public_bytes": request.max_public_bytes,
                    "privacy_set_size": request.privacy_set_size,
                }),
            ),
            public_fields: request.public_fields,
            redacted_fields: request.redacted_fields,
            max_public_bytes: request.max_public_bytes,
            actual_public_bytes: request.actual_public_bytes,
            privacy_set_size: request.privacy_set_size,
            published_slot: request.published_slot,
            operator_safe: true,
        };
        self.redaction_budgets.insert(budget_id.clone(), budget);
        self.counters.redaction_budgets = self.counters.redaction_budgets.saturating_add(1);
        self.refresh_roots();
        Ok(budget_id)
    }

    pub fn publish_operator_summary(
        &mut self,
        request: PublishOperatorSummaryRequest,
    ) -> Result<String> {
        self.ensure_capacity(
            "operator_summaries",
            self.operator_summaries.len(),
            self.config.max_operator_summaries,
        )?;
        ensure_bps("median_fee_bps", request.median_fee_bps)?;
        ensure_bps("rebate_bps", request.rebate_bps)?;
        ensure_bps(
            "aggregate_rollover_weight_bps",
            request.aggregate_rollover_weight_bps,
        )?;

        let summary_id = self.counters.allocate("operator-safe-summary");
        let summary = OperatorSafeSummary {
            summary_id: summary_id.clone(),
            slot: request.slot,
            active_signer_set_count: self
                .signer_sets
                .values()
                .filter(|set| set.status.can_authorize_withdrawals())
                .count() as u64,
            active_signer_count: self
                .signers
                .values()
                .filter(|signer| signer.status == SignerStatus::Active)
                .count() as u64,
            open_epoch_count: self
                .withdrawal_epochs
                .values()
                .filter(|epoch| epoch.status.accepts_attestations())
                .count() as u64,
            counted_attestation_count: self
                .rollover_attestations
                .values()
                .filter(|attestation| attestation.status == RolloverAttestationStatus::Counted)
                .count() as u64,
            quarantined_signer_count: self
                .legacy_quarantines
                .values()
                .filter(|quarantine| !quarantine.slashed)
                .count() as u64,
            open_challenge_count: self
                .challenge_windows
                .values()
                .filter(|challenge| challenge.status == ChallengeStatus::Open)
                .count() as u64,
            median_fee_bps: request.median_fee_bps,
            rebate_bps: request.rebate_bps,
            aggregate_rollover_weight_bps: request.aggregate_rollover_weight_bps,
            redaction_budget_root: self.roots.redaction_budget_root.clone(),
            safety_summary_root: request.safety_summary_root,
        };
        self.operator_summaries.insert(summary_id.clone(), summary);
        self.counters.operator_summaries = self.counters.operator_summaries.saturating_add(1);
        self.refresh_roots();
        Ok(summary_id)
    }

    pub fn finalize_rollover(&mut self, epoch_id: &str, slot: u64) -> Result<()> {
        let epoch = self
            .withdrawal_epochs
            .get_mut(epoch_id)
            .ok_or_else(|| format!("unknown epoch {epoch_id}"))?;
        if slot < epoch.challenge_deadline_slot {
            return Err("cannot finalize rollover before challenge deadline".to_string());
        }
        let counted_weight = counted_rollover_weight(&self.rollover_attestations, epoch_id);
        if counted_weight < epoch.rollover_quorum_bps {
            return Err("cannot finalize rollover without rollover quorum".to_string());
        }
        if has_open_challenge(&self.challenge_windows, epoch_id) {
            return Err("cannot finalize rollover while challenges remain open".to_string());
        }
        epoch.status = WithdrawalEpochStatus::RolloverFinalized;
        if let Some(active) = self.signer_sets.get_mut(&epoch.active_signer_set_id) {
            active.status = SignerSetStatus::Grace;
        }
        if let Some(next) = self.signer_sets.get_mut(&epoch.next_signer_set_id) {
            next.status = SignerSetStatus::Active;
        }
        self.refresh_roots();
        Ok(())
    }

    pub fn rollover_readiness(&self, epoch_id: &str) -> Result<RolloverReadiness> {
        let epoch = self
            .withdrawal_epochs
            .get(epoch_id)
            .ok_or_else(|| format!("unknown epoch {epoch_id}"))?;
        let next_set = self
            .signer_sets
            .get(&epoch.next_signer_set_id)
            .ok_or_else(|| format!("unknown next signer set {}", epoch.next_signer_set_id))?;
        let counted_rollover_weight_bps =
            counted_rollover_weight(&self.rollover_attestations, epoch_id);
        let open_challenge_count = self
            .challenge_windows
            .values()
            .filter(|challenge| {
                challenge.epoch_id == epoch_id && challenge.status == ChallengeStatus::Open
            })
            .count() as u64;
        let quarantined_legacy_signer_count = self
            .legacy_quarantines
            .values()
            .filter(|quarantine| quarantine.signer_set_id == epoch.active_signer_set_id)
            .count() as u64;
        let escrow_coverage_piconero = self
            .key_escrow_commitments
            .values()
            .filter(|bond| {
                bond.signer_set_id == epoch.next_signer_set_id
                    && matches!(bond.status, EscrowStatus::Locked | EscrowStatus::Active)
            })
            .map(|bond| bond.amount_piconero)
            .fold(0u64, u64::saturating_add);
        let ready = counted_rollover_weight_bps >= epoch.rollover_quorum_bps
            && open_challenge_count == 0
            && next_set.pq_security_bits >= self.config.min_pq_security_bits
            && next_set.privacy_set_size >= epoch.min_privacy_set_size
            && escrow_coverage_piconero
                >= self
                    .config
                    .key_escrow_commitment_floor_piconero
                    .saturating_mul(next_set.signer_count);
        Ok(RolloverReadiness {
            epoch_id: epoch.epoch_id.clone(),
            active_signer_set_id: epoch.active_signer_set_id.clone(),
            next_signer_set_id: epoch.next_signer_set_id.clone(),
            counted_rollover_weight_bps,
            required_rollover_weight_bps: epoch.rollover_quorum_bps,
            open_challenge_count,
            quarantined_legacy_signer_count,
            escrow_coverage_piconero,
            privacy_set_size: next_set.privacy_set_size,
            pq_security_bits: next_set.pq_security_bits,
            ready,
        })
    }

    pub fn bridge_safety_posture(&self) -> BridgeSafetyPosture {
        let active_bond_piconero = self
            .key_escrow_commitments
            .values()
            .filter(|bond| bond.status == EscrowStatus::Active)
            .map(|bond| bond.amount_piconero)
            .fold(0u64, u64::saturating_add);
        let locked_bond_piconero = self
            .key_escrow_commitments
            .values()
            .filter(|bond| bond.status == EscrowStatus::Locked)
            .map(|bond| bond.amount_piconero)
            .fold(0u64, u64::saturating_add);
        let slashed_bond_piconero = self
            .key_escrow_commitments
            .values()
            .filter(|bond| bond.status == EscrowStatus::Slashed)
            .map(|bond| bond.amount_piconero)
            .fold(0u64, u64::saturating_add);
        BridgeSafetyPosture {
            active_bond_piconero,
            locked_bond_piconero,
            slashed_bond_piconero,
            open_challenge_count: self
                .challenge_windows
                .values()
                .filter(|challenge| challenge.status == ChallengeStatus::Open)
                .count() as u64,
            fraud_warning_count: self
                .rollover_attestations
                .values()
                .filter(|attestation| attestation.kind == RolloverAttestationKind::FraudWarning)
                .count() as u64,
            emergency_stop_count: self
                .rollover_attestations
                .values()
                .filter(|attestation| {
                    attestation.kind == RolloverAttestationKind::EmergencyStopObserved
                })
                .count() as u64,
            emergency_quorum_bps: self.config.emergency_quorum_bps,
            safety_root: self.roots.safety_root.clone(),
        }
    }

    pub fn privacy_posture(&self) -> PrivacyPosture {
        let lowest_set = self
            .signer_sets
            .values()
            .map(|set| set.privacy_set_size)
            .chain(
                self.rollover_attestations
                    .values()
                    .map(|attestation| attestation.privacy_set_size),
            )
            .min()
            .unwrap_or(self.config.min_privacy_set_size);
        PrivacyPosture {
            min_privacy_set_size: self.config.min_privacy_set_size,
            lowest_observed_privacy_set_size: lowest_set,
            redaction_budget_count: self.redaction_budgets.len() as u64,
            operator_safe_budget_count: self
                .redaction_budgets
                .values()
                .filter(|budget| budget.operator_safe)
                .count() as u64,
            total_public_bytes: self
                .redaction_budgets
                .values()
                .map(|budget| budget.actual_public_bytes)
                .fold(0u64, u64::saturating_add),
            redacted_field_count: self
                .redaction_budgets
                .values()
                .map(|budget| budget.redacted_fields.len() as u64)
                .fold(0u64, u64::saturating_add),
            privacy_root: self.roots.privacy_root.clone(),
        }
    }

    pub fn low_fee_posture(&self) -> LowFeePosture {
        LowFeePosture {
            max_user_fee_bps: self.config.max_user_fee_bps,
            lowest_epoch_fee_bps: self
                .withdrawal_epochs
                .values()
                .map(|epoch| epoch.max_user_fee_bps)
                .min()
                .unwrap_or(self.config.max_user_fee_bps),
            earned_rebate_count: self
                .fee_credit_rebates
                .values()
                .filter(|rebate| rebate.status == FeeCreditStatus::Earned)
                .count() as u64,
            paid_rebate_count: self
                .fee_credit_rebates
                .values()
                .filter(|rebate| rebate.status == FeeCreditStatus::Paid)
                .count() as u64,
            total_rebate_piconero: self
                .fee_credit_rebates
                .values()
                .map(|rebate| rebate.rebate_amount_piconero)
                .fold(0u64, u64::saturating_add),
            rebate_root: self.roots.fee_credit_rebate_root.clone(),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        self.public_record_without_state_root_with_roots(&self.roots)
    }

    pub fn public_record_without_state_root_with_roots(&self, roots: &Roots) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "config": self.config,
            "counters": self.counters,
            "roots": {
                "signer_set_root": roots.signer_set_root,
                "signer_root": roots.signer_root,
                "withdrawal_epoch_root": roots.withdrawal_epoch_root,
                "rollover_attestation_root": roots.rollover_attestation_root,
                "key_escrow_commitment_root": roots.key_escrow_commitment_root,
                "legacy_quarantine_root": roots.legacy_quarantine_root,
                "challenge_window_root": roots.challenge_window_root,
                "fee_credit_rebate_root": roots.fee_credit_rebate_root,
                "redaction_budget_root": roots.redaction_budget_root,
                "operator_summary_root": roots.operator_summary_root,
                "nullifier_root": roots.nullifier_root,
                "safety_root": roots.safety_root,
                "privacy_root": roots.privacy_root,
            },
            "signer_sets": public_values(&self.signer_sets),
            "signers": public_values(&self.signers),
            "withdrawal_epochs": public_values(&self.withdrawal_epochs),
            "rollover_attestations": public_values(&self.rollover_attestations),
            "key_escrow_commitments": public_values(&self.key_escrow_commitments),
            "legacy_quarantines": public_values(&self.legacy_quarantines),
            "challenge_windows": public_values(&self.challenge_windows),
            "fee_credit_rebates": public_values(&self.fee_credit_rebates),
            "redaction_budgets": public_values(&self.redaction_budgets),
            "operator_summaries": public_values(&self.operator_summaries),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root_with_roots(&self.roots);
        record["roots"]["state_root"] = json!(self.state_root());
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn refresh_roots(&mut self) {
        self.roots.signer_set_root = map_root("signer-sets", &self.signer_sets);
        self.roots.signer_root = map_root("signers", &self.signers);
        self.roots.withdrawal_epoch_root = map_root("withdrawal-epochs", &self.withdrawal_epochs);
        self.roots.rollover_attestation_root =
            map_root("rollover-attestations", &self.rollover_attestations);
        self.roots.key_escrow_commitment_root =
            map_root("key-escrow-commitments", &self.key_escrow_commitments);
        self.roots.legacy_quarantine_root =
            map_root("legacy-quarantines", &self.legacy_quarantines);
        self.roots.challenge_window_root = map_root("challenge-windows", &self.challenge_windows);
        self.roots.fee_credit_rebate_root =
            map_root("fee-credit-rebates", &self.fee_credit_rebates);
        self.roots.redaction_budget_root = map_root("redaction-budgets", &self.redaction_budgets);
        self.roots.operator_summary_root = map_root("operator-summaries", &self.operator_summaries);
        self.roots.nullifier_root = stable_root(
            "withdrawal-rollover-nullifiers",
            &json!({
                "signer_sets": self.signer_sets.values().map(|set| set.membership_nullifier_root.clone()).collect::<Vec<_>>(),
                "epochs": self.withdrawal_epochs.values().map(|epoch| epoch.nullifier_set_root.clone()).collect::<Vec<_>>(),
                "legacy": self.signers.values().map(|signer| signer.legacy_key_nullifier.clone()).collect::<Vec<_>>(),
            }),
        );
        self.roots.safety_root = stable_root(
            "withdrawal-rollover-safety",
            &json!({
                "key_escrows": self.roots.key_escrow_commitment_root,
                "quarantines": self.roots.legacy_quarantine_root,
                "challenges": self.roots.challenge_window_root,
                "emergency_quorum_bps": self.config.emergency_quorum_bps,
            }),
        );
        self.roots.privacy_root = stable_root(
            "withdrawal-rollover-privacy",
            &json!({
                "redaction": self.roots.redaction_budget_root,
                "privacy_floor": self.config.min_privacy_set_size,
                "fee_rebates": self.roots.fee_credit_rebate_root,
            }),
        );
        self.roots.state_root = state_root_from_record(&self.public_record_without_state_root());
    }

    fn recompute_epoch_statuses(&mut self) {
        for epoch in self.withdrawal_epochs.values_mut() {
            let counted = counted_rollover_weight(&self.rollover_attestations, &epoch.epoch_id);
            let challenged = has_open_challenge(&self.challenge_windows, &epoch.epoch_id);
            epoch.status = if challenged {
                WithdrawalEpochStatus::ChallengeOpen
            } else if counted >= epoch.rollover_quorum_bps {
                WithdrawalEpochStatus::RolloverCollecting
            } else if epoch.status == WithdrawalEpochStatus::Scheduled {
                WithdrawalEpochStatus::Open
            } else {
                epoch.status
            };
        }
    }

    fn require_signer_set(&self, signer_set_id: &str) -> Result<()> {
        self.signer_sets
            .get(signer_set_id)
            .map(|_| ())
            .ok_or_else(|| format!("unknown signer set {signer_set_id}"))
    }

    fn ensure_pq_and_privacy(&self, pq_security_bits: u16, privacy_set_size: u64) -> Result<()> {
        if pq_security_bits < self.config.min_pq_security_bits {
            return Err("record below configured post-quantum security floor".to_string());
        }
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("record below configured privacy set floor".to_string());
        }
        Ok(())
    }

    fn ensure_capacity(&mut self, label: &str, current: usize, max: usize) -> Result<()> {
        if current >= max {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
            Err(format!("{label} capacity exceeded"))
        } else {
            Ok(())
        }
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    state.config = Config::devnet();

    let active_set = state
        .register_signer_set(RegisterSignerSetRequest {
            activation_slot: DEVNET_SLOT,
            retirement_slot: DEVNET_SLOT
                + DEFAULT_EPOCH_LENGTH_SLOTS
                + DEFAULT_ROLLOVER_GRACE_SLOTS,
            signer_count: 16,
            active_weight_bps: MAX_BPS,
            slh_dsa_public_key_root: sample_root("active-slh-dsa-key-set"),
            ml_dsa_public_key_root: sample_root("active-ml-dsa-key-set"),
            membership_nullifier_root: sample_root("active-membership-nullifiers"),
            withdrawal_policy_root: sample_root("active-withdrawal-policy"),
            operator_hint_root: sample_root("active-operator-hints"),
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE * 2,
        })
        .expect("devnet signer set should be valid");
    let next_set = state
        .register_signer_set(RegisterSignerSetRequest {
            activation_slot: DEVNET_SLOT + DEFAULT_EPOCH_LENGTH_SLOTS,
            retirement_slot: DEVNET_SLOT + (DEFAULT_EPOCH_LENGTH_SLOTS * 2),
            signer_count: 19,
            active_weight_bps: MAX_BPS,
            slh_dsa_public_key_root: sample_root("next-slh-dsa-key-set"),
            ml_dsa_public_key_root: sample_root("next-ml-dsa-key-set"),
            membership_nullifier_root: sample_root("next-membership-nullifiers"),
            withdrawal_policy_root: sample_root("next-withdrawal-policy"),
            operator_hint_root: sample_root("next-operator-hints"),
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE * 2,
        })
        .expect("devnet next signer set should be valid");

    for index in 0..6 {
        let signer_id = state
            .register_signer(RegisterSignerRequest {
                signer_set_id: active_set.clone(),
                weight_bps: 1_250,
                slh_dsa_public_key_commitment: sample_root(&format!("active-signer-key-{index}")),
                proof_of_possession_root: sample_root(&format!("active-pop-{index}")),
                escrow_commitment_root: sample_root(&format!("active-bond-{index}")),
                reserve_proof_root: sample_root(&format!("active-reserve-{index}")),
                bond_amount_piconero: DEFAULT_KEY_ESCROW_FLOOR_PICONERO + (index * 1_000_000),
                legacy_key_nullifier: sample_root(&format!("active-legacy-nullifier-{index}")),
                joined_slot: DEVNET_SLOT,
                exit_slot: DEVNET_SLOT + DEFAULT_EPOCH_LENGTH_SLOTS + DEFAULT_QUARANTINE_SLOTS,
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            })
            .expect("devnet signer should be valid");
        if let Some(signer) = state.signers.get_mut(&signer_id) {
            signer.status = SignerStatus::Active;
        }
        if index == 0 {
            let _ = state.quarantine_legacy_signer(QuarantineSignerRequest {
                signer_id,
                reason: QuarantineReason::LegacyScheme,
                evidence_root: sample_root("legacy-scheme-evidence"),
                start_slot: DEVNET_SLOT + 12,
            });
        }
    }

    for index in 0..6 {
        let signer_id = state
            .register_signer(RegisterSignerRequest {
                signer_set_id: next_set.clone(),
                weight_bps: 1_200,
                slh_dsa_public_key_commitment: sample_root(&format!("next-signer-key-{index}")),
                proof_of_possession_root: sample_root(&format!("next-pop-{index}")),
                escrow_commitment_root: sample_root(&format!("next-bond-{index}")),
                reserve_proof_root: sample_root(&format!("next-reserve-{index}")),
                bond_amount_piconero: DEFAULT_KEY_ESCROW_FLOOR_PICONERO + (index * 1_000_000),
                legacy_key_nullifier: sample_root(&format!("next-legacy-nullifier-{index}")),
                joined_slot: DEVNET_SLOT + 6,
                exit_slot: DEVNET_SLOT + (DEFAULT_EPOCH_LENGTH_SLOTS * 2),
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            })
            .expect("devnet next signer should be valid");
        if let Some(signer) = state.signers.get_mut(&signer_id) {
            signer.status = SignerStatus::Bonded;
        }
    }

    if let Some(set) = state.signer_sets.get_mut(&active_set) {
        set.status = SignerSetStatus::Active;
    }
    if let Some(set) = state.signer_sets.get_mut(&next_set) {
        set.status = SignerSetStatus::Warming;
    }

    let epoch_id = state
        .schedule_epoch(ScheduleEpochRequest {
            active_signer_set_id: active_set.clone(),
            next_signer_set_id: next_set.clone(),
            epoch_index: 1,
            start_slot: DEVNET_SLOT,
            withdrawal_batch_root: sample_root("devnet-withdrawal-batch"),
            nullifier_set_root: sample_root("devnet-withdrawal-nullifiers"),
            redaction_policy_root: sample_root("devnet-redaction-policy"),
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
        })
        .expect("devnet epoch should be valid");

    let _attestation_id = state
        .submit_rollover_attestation(SubmitRolloverAttestationRequest {
            epoch_id: epoch_id.clone(),
            signer_set_id: active_set.clone(),
            kind: RolloverAttestationKind::WithdrawalQuorumObserved,
            statement_root: sample_root("devnet-withdrawal-quorum-statement"),
            slh_dsa_signature_root: sample_root("devnet-slh-dsa-rollover-sig"),
            hybrid_ml_dsa_signature_root: sample_root("devnet-ml-dsa-rollover-sig"),
            transcript_root: sample_root("devnet-rollover-transcript"),
            signer_bitmap_root: sample_root("devnet-rollover-bitmap"),
            signer_weight_bps: DEFAULT_ROLLOVER_QUORUM_BPS,
            observed_slot: DEVNET_SLOT + DEFAULT_EPOCH_LENGTH_SLOTS,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE * 2,
        })
        .expect("devnet attestation should be valid");

    let _ = state.issue_fee_credit_rebate(IssueFeeCreditRebateRequest {
        epoch_id: epoch_id.clone(),
        signer_set_id: active_set,
        beneficiary_commitment_root: sample_root("devnet-rebate-beneficiary"),
        fee_credit_pool_root: sample_root("devnet-fee-credit-pool"),
        rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
        rebate_amount_piconero: 42_000_000,
        earned_slot: DEVNET_SLOT + DEFAULT_EPOCH_LENGTH_SLOTS,
        expires_slot: DEVNET_SLOT + DEFAULT_EPOCH_LENGTH_SLOTS + DEFAULT_ROLLOVER_GRACE_SLOTS,
    });

    let mut public_fields = BTreeSet::new();
    public_fields.insert("epoch_id".to_string());
    public_fields.insert("rollover_quorum_bps".to_string());
    public_fields.insert("challenge_deadline_slot".to_string());
    let mut redacted_fields = BTreeSet::new();
    redacted_fields.insert("signer_bitmap_root".to_string());
    redacted_fields.insert("beneficiary_commitment_root".to_string());
    let _ = state.publish_redaction_budget(PublishRedactionBudgetRequest {
        target_id: epoch_id,
        public_fields,
        redacted_fields,
        max_public_bytes: DEFAULT_REDACTION_PUBLIC_BYTE_LIMIT,
        actual_public_bytes: 812,
        privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
        published_slot: DEVNET_SLOT + 24,
    });

    let _ = state.publish_operator_summary(PublishOperatorSummaryRequest {
        slot: DEVNET_SLOT + 48,
        median_fee_bps: DEFAULT_MAX_USER_FEE_BPS / 2,
        rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
        aggregate_rollover_weight_bps: DEFAULT_ROLLOVER_QUORUM_BPS,
        safety_summary_root: sample_root("devnet-safety-summary"),
    });

    state.refresh_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let epoch_id = state
        .withdrawal_epochs
        .keys()
        .next()
        .cloned()
        .unwrap_or_else(|| "withdrawal-quorum-epoch-demo".to_string());
    let attestation_id = state
        .rollover_attestations
        .keys()
        .next()
        .cloned()
        .unwrap_or_else(|| "rollover-attestation-demo".to_string());
    let _ = state.open_challenge(OpenChallengeRequest {
        epoch_id,
        attestation_id,
        challenger_commitment: sample_root("demo-challenger"),
        evidence_root: sample_root("demo-benign-challenge-evidence"),
        opened_slot: DEVNET_SLOT + DEFAULT_EPOCH_LENGTH_SLOTS + 4,
        slash_amount_piconero: DEFAULT_KEY_ESCROW_FLOOR_PICONERO / 10,
    });
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn public_record_root(record: &Value) -> String {
    stable_root("public-record", record)
}

pub fn state_root_from_record(record: &Value) -> String {
    stable_root(PROTOCOL_VERSION, record)
}

fn ensure_bps(label: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{label} exceeds {MAX_BPS} basis points"))
    } else {
        Ok(())
    }
}

fn counted_rollover_weight(
    attestations: &BTreeMap<String, RolloverAttestation>,
    epoch_id: &str,
) -> u64 {
    attestations
        .values()
        .filter(|attestation| {
            attestation.epoch_id == epoch_id
                && attestation.status == RolloverAttestationStatus::Counted
                && attestation.is_safety_positive()
        })
        .map(|attestation| attestation.signer_weight_bps)
        .fold(0u64, u64::saturating_add)
        .min(MAX_BPS)
}

fn has_open_challenge(challenges: &BTreeMap<String, ChallengeWindow>, epoch_id: &str) -> bool {
    challenges.values().any(|challenge| {
        challenge.epoch_id == epoch_id && challenge.status == ChallengeStatus::Open
    })
}

fn map_root<T: Serialize>(label: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| stable_root(label, &json!({ "key": key, "value": value })))
        .collect::<Vec<_>>();
    merkle_or_empty(label, leaves)
}

fn public_values<T: Serialize>(map: &BTreeMap<String, T>) -> Vec<Value> {
    map.values()
        .map(|value| serde_json::to_value(value).expect("runtime public value serialization"))
        .collect()
}

fn object_root<T: Serialize>(label: &str, value: &T) -> String {
    stable_root(
        label,
        &serde_json::to_value(value).expect("runtime object serialization"),
    )
}

fn sample_root(label: &str) -> String {
    stable_root("sample", &json!({ "label": label }))
}

fn stable_root(label: &str, value: &Value) -> String {
    domain_hash(
        label,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(value)],
        32,
    )
}

fn merkle_or_empty(label: &str, leaves: Vec<String>) -> String {
    if leaves.is_empty() {
        stable_root(label, &json!([]))
    } else {
        let values = leaves.into_iter().map(Value::String).collect::<Vec<_>>();
        merkle_root(label, &values)
    }
}
