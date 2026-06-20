use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialMlDsaSponsorSlashingArbitrationRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_ML_DSA_SPONSOR_SLASHING_ARBITRATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-ml-dsa-sponsor-slashing-arbitration-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_ML_DSA_SPONSOR_SLASHING_ARBITRATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ML_DSA_SUITE: &str = "ML-DSA-87-sponsor-accountability-v1";
pub const PQ_EVIDENCE_SUITE: &str = "ML-DSA-87+ML-KEM-1024+SLH-DSA-SHAKE-256f-private-evidence-v1";
pub const SPONSOR_BOND_SUITE: &str = "confidential-ml-dsa-sponsor-bond-escrow-root-v1";
pub const ARBITRATION_SUITE: &str = "private-low-fee-sponsor-slashing-arbitration-root-v1";
pub const POLICY_BREACH_SUITE: &str = "privacy-preserving-sponsor-policy-breach-attestation-v1";
pub const FEE_REFUND_SUITE: &str = "confidential-fee-credit-refund-root-v1";
pub const NULLIFIER_SUITE: &str = "sponsor-slashing-dispute-nullifier-replay-guard-v1";
pub const OPERATOR_SUMMARY_SUITE: &str = "operator-safe-sponsor-slashing-summary-root-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_users_amounts_view_keys_session_keys_signatures_or_call_data";
pub const DEFAULT_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_BOND_ASSET_ID: &str = "ml-dsa-sponsor-bond-note-devnet";
pub const DEVNET_HEIGHT: u64 = 4_880_000;
pub const DEVNET_EPOCH: u64 = 19_264;
pub const DEVNET_SLOT: u64 = 88;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_SPONSOR_BOND_MICRO_UNITS: u64 = 25_000_000;
pub const DEFAULT_MIN_ARBITER_BOND_MICRO_UNITS: u64 = 5_000_000;
pub const DEFAULT_DISPUTE_WINDOW_SLOTS: u64 = 1_024;
pub const DEFAULT_EVIDENCE_REVEAL_WINDOW_SLOTS: u64 = 256;
pub const DEFAULT_APPEAL_WINDOW_SLOTS: u64 = 512;
pub const DEFAULT_REFUND_WINDOW_SLOTS: u64 = 2_048;
pub const DEFAULT_MAX_CASE_FEE_BPS: u64 = 10;
pub const DEFAULT_TARGET_CASE_FEE_BPS: u64 = 3;
pub const DEFAULT_MIN_COMMITTEE_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_COMMITTEE_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_MINOR_SLASH_BPS: u64 = 500;
pub const DEFAULT_MAJOR_SLASH_BPS: u64 = 2_500;
pub const DEFAULT_PRIVACY_LEAK_SLASH_BPS: u64 = 5_000;
pub const DEFAULT_REFUND_BPS: u64 = 9_800;
pub const DEFAULT_ARBITER_REWARD_BPS: u64 = 120;
pub const DEFAULT_PROTOCOL_RESERVE_BPS: u64 = 80;
pub const DEFAULT_MAX_SPONSOR_RISK_BPS: u64 = 7_500;
pub const DEFAULT_MAX_EVIDENCE_ITEMS_PER_CASE: usize = 128;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_SPONSOR_BONDS: usize = 1_048_576;
pub const MAX_POLICY_BREACH_ATTESTATIONS: usize = 4_194_304;
pub const MAX_PRIVATE_EVIDENCE_ENVELOPES: usize = 4_194_304;
pub const MAX_SLASHING_DISPUTES: usize = 1_048_576;
pub const MAX_ARBITRATION_COMMITTEES: usize = 524_288;
pub const MAX_ARBITER_MEMBERS: usize = 262_144;
pub const MAX_COMMITTEE_VOTES: usize = 8_388_608;
pub const MAX_SLASHING_VERDICTS: usize = 1_048_576;
pub const MAX_FEE_CREDIT_REFUNDS: usize = 2_097_152;
pub const MAX_NULLIFIER_GUARDS: usize = 4_194_304;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const MAX_EVENTS: usize = 8_388_608;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorRole {
    WalletPaymaster,
    MerchantPaymaster,
    BatchSponsor,
    BridgeExitSponsor,
    RecoverySponsor,
    LiquiditySponsor,
    DataAvailabilitySponsor,
    EmergencySponsor,
}

impl SponsorRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletPaymaster => "wallet_paymaster",
            Self::MerchantPaymaster => "merchant_paymaster",
            Self::BatchSponsor => "batch_sponsor",
            Self::BridgeExitSponsor => "bridge_exit_sponsor",
            Self::RecoverySponsor => "recovery_sponsor",
            Self::LiquiditySponsor => "liquidity_sponsor",
            Self::DataAvailabilitySponsor => "data_availability_sponsor",
            Self::EmergencySponsor => "emergency_sponsor",
        }
    }

    pub fn risk_weight_bps(self) -> u64 {
        match self {
            Self::WalletPaymaster => 4_000,
            Self::MerchantPaymaster => 4_600,
            Self::BatchSponsor => 5_200,
            Self::BridgeExitSponsor => 7_500,
            Self::RecoverySponsor => 6_800,
            Self::LiquiditySponsor => 6_000,
            Self::DataAvailabilitySponsor => 5_500,
            Self::EmergencySponsor => 8_500,
        }
    }

    pub fn public_record(self) -> Value {
        json!(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Candidate,
    Active,
    CapacityLimited,
    UnderReview,
    Quarantined,
    Slashed,
    Draining,
    Retired,
}
impl SponsorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::CapacityLimited => "capacity_limited",
            Self::UnderReview => "under_review",
            Self::Quarantined => "quarantined",
            Self::Slashed => "slashed",
            Self::Draining => "draining",
            Self::Retired => "retired",
        }
    }
    pub fn can_sponsor(self) -> bool {
        matches!(self, Self::Active | Self::CapacityLimited)
    }
    pub fn public_record(self) -> Value {
        json!(self.as_str())
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BondStatus {
    Pending,
    Escrowed,
    Active,
    LockedByDispute,
    PartiallySlashed,
    Slashed,
    Releasing,
    Released,
}
impl BondStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Escrowed => "escrowed",
            Self::Active => "active",
            Self::LockedByDispute => "locked_by_dispute",
            Self::PartiallySlashed => "partially_slashed",
            Self::Slashed => "slashed",
            Self::Releasing => "releasing",
            Self::Released => "released",
        }
    }
    pub fn liquid(self) -> bool {
        matches!(self, Self::Escrowed | Self::Active | Self::PartiallySlashed)
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyBreachKind {
    FeeOvercharge,
    SponsorshipDenial,
    InvalidMlDsaAuthorization,
    ExpiredPolicyUse,
    ReplayAccepted,
    RefundWithheld,
    PrivacyLeak,
    BondUnderfunded,
    RouteMisrepresentation,
    SelectiveCensorship,
}
impl PolicyBreachKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FeeOvercharge => "fee_overcharge",
            Self::SponsorshipDenial => "sponsorship_denial",
            Self::InvalidMlDsaAuthorization => "invalid_ml_dsa_authorization",
            Self::ExpiredPolicyUse => "expired_policy_use",
            Self::ReplayAccepted => "replay_accepted",
            Self::RefundWithheld => "refund_withheld",
            Self::PrivacyLeak => "privacy_leak",
            Self::BondUnderfunded => "bond_underfunded",
            Self::RouteMisrepresentation => "route_misrepresentation",
            Self::SelectiveCensorship => "selective_censorship",
        }
    }
    pub fn severity_bps(self) -> u64 {
        match self {
            Self::PrivacyLeak => 9_500,
            Self::InvalidMlDsaAuthorization => 8_800,
            Self::ReplayAccepted => 8_200,
            Self::BondUnderfunded => 7_800,
            Self::RefundWithheld => 7_000,
            Self::FeeOvercharge => 6_400,
            Self::ExpiredPolicyUse => 6_000,
            Self::SelectiveCensorship => 5_800,
            Self::SponsorshipDenial => 5_200,
            Self::RouteMisrepresentation => 4_600,
        }
    }
    pub fn default_slash_bps(self, config: &Config) -> u64 {
        match self {
            Self::PrivacyLeak => config.privacy_leak_slash_bps,
            Self::InvalidMlDsaAuthorization | Self::ReplayAccepted | Self::BondUnderfunded => {
                config.major_slash_bps
            }
            _ => config.minor_slash_bps,
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceEnvelopeStatus {
    Sealed,
    Redacted,
    RevealQueued,
    DecryptSharesCollected,
    CommitteeVisible,
    Accepted,
    Rejected,
    Quarantined,
}
impl EvidenceEnvelopeStatus {
    pub fn committee_readable(self) -> bool {
        matches!(
            self,
            Self::CommitteeVisible | Self::Accepted | Self::Rejected | Self::Quarantined
        )
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeStatus {
    Submitted,
    EvidencePending,
    EvidenceSealed,
    CommitteeAssigned,
    Attesting,
    Deliberating,
    VerdictPublished,
    Appealed,
    Settled,
    Rejected,
    Expired,
}
impl DisputeStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::EvidencePending
                | Self::EvidenceSealed
                | Self::CommitteeAssigned
                | Self::Attesting
                | Self::Deliberating
                | Self::Appealed
        )
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeStatus {
    Forming,
    Active,
    QuorumReached,
    StrongQuorumReached,
    VerdictReady,
    Expired,
    Dissolved,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArbiterRole {
    EvidenceDecryptor,
    PolicyAuditor,
    FeeAccountant,
    PrivacyReviewer,
    BondExecutor,
    AppealsReviewer,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoteKind {
    PqSignatureValid,
    PolicyBreachProven,
    EvidenceBoundarySafe,
    FeeRefundOwed,
    SlashMinor,
    SlashMajor,
    RejectDispute,
    EscalateAppeal,
}
impl VoteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqSignatureValid => "pq_signature_valid",
            Self::PolicyBreachProven => "policy_breach_proven",
            Self::EvidenceBoundarySafe => "evidence_boundary_safe",
            Self::FeeRefundOwed => "fee_refund_owed",
            Self::SlashMinor => "slash_minor",
            Self::SlashMajor => "slash_major",
            Self::RejectDispute => "reject_dispute",
            Self::EscalateAppeal => "escalate_appeal",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictDecision {
    Dismiss,
    RefundOnly,
    Warning,
    MinorSlash,
    MajorSlash,
    PrivacySlash,
    QuarantineSponsor,
    RetireSponsor,
}
impl VerdictDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dismiss => "dismiss",
            Self::RefundOnly => "refund_only",
            Self::Warning => "warning",
            Self::MinorSlash => "minor_slash",
            Self::MajorSlash => "major_slash",
            Self::PrivacySlash => "privacy_slash",
            Self::QuarantineSponsor => "quarantine_sponsor",
            Self::RetireSponsor => "retire_sponsor",
        }
    }
    pub fn slashing(self) -> bool {
        matches!(
            self,
            Self::MinorSlash
                | Self::MajorSlash
                | Self::PrivacySlash
                | Self::QuarantineSponsor
                | Self::RetireSponsor
        )
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefundStatus {
    Pending,
    Proved,
    Queued,
    Paid,
    Rejected,
    Expired,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NullifierStatus {
    Reserved,
    Consumed,
    ReplayBlocked,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub protocol_version: String,
    pub hash_suite: String,
    pub ml_dsa_suite: String,
    pub pq_evidence_suite: String,
    pub sponsor_bond_suite: String,
    pub arbitration_suite: String,
    pub policy_breach_suite: String,
    pub fee_refund_suite: String,
    pub nullifier_suite: String,
    pub operator_summary_suite: String,
    pub privacy_boundary: String,
    pub fee_asset_id: String,
    pub bond_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_sponsor_bond_micro_units: u64,
    pub min_arbiter_bond_micro_units: u64,
    pub dispute_window_slots: u64,
    pub evidence_reveal_window_slots: u64,
    pub appeal_window_slots: u64,
    pub refund_window_slots: u64,
    pub max_case_fee_bps: u64,
    pub target_case_fee_bps: u64,
    pub min_committee_quorum_bps: u64,
    pub strong_committee_quorum_bps: u64,
    pub minor_slash_bps: u64,
    pub major_slash_bps: u64,
    pub privacy_leak_slash_bps: u64,
    pub refund_bps: u64,
    pub arbiter_reward_bps: u64,
    pub protocol_reserve_bps: u64,
    pub max_sponsor_risk_bps: u64,
    pub max_evidence_items_per_case: usize,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEFAULT_L2_NETWORK.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            ml_dsa_suite: ML_DSA_SUITE.to_string(),
            pq_evidence_suite: PQ_EVIDENCE_SUITE.to_string(),
            sponsor_bond_suite: SPONSOR_BOND_SUITE.to_string(),
            arbitration_suite: ARBITRATION_SUITE.to_string(),
            policy_breach_suite: POLICY_BREACH_SUITE.to_string(),
            fee_refund_suite: FEE_REFUND_SUITE.to_string(),
            nullifier_suite: NULLIFIER_SUITE.to_string(),
            operator_summary_suite: OPERATOR_SUMMARY_SUITE.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            bond_asset_id: DEFAULT_BOND_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_sponsor_bond_micro_units: DEFAULT_MIN_SPONSOR_BOND_MICRO_UNITS,
            min_arbiter_bond_micro_units: DEFAULT_MIN_ARBITER_BOND_MICRO_UNITS,
            dispute_window_slots: DEFAULT_DISPUTE_WINDOW_SLOTS,
            evidence_reveal_window_slots: DEFAULT_EVIDENCE_REVEAL_WINDOW_SLOTS,
            appeal_window_slots: DEFAULT_APPEAL_WINDOW_SLOTS,
            refund_window_slots: DEFAULT_REFUND_WINDOW_SLOTS,
            max_case_fee_bps: DEFAULT_MAX_CASE_FEE_BPS,
            target_case_fee_bps: DEFAULT_TARGET_CASE_FEE_BPS,
            min_committee_quorum_bps: DEFAULT_MIN_COMMITTEE_QUORUM_BPS,
            strong_committee_quorum_bps: DEFAULT_STRONG_COMMITTEE_QUORUM_BPS,
            minor_slash_bps: DEFAULT_MINOR_SLASH_BPS,
            major_slash_bps: DEFAULT_MAJOR_SLASH_BPS,
            privacy_leak_slash_bps: DEFAULT_PRIVACY_LEAK_SLASH_BPS,
            refund_bps: DEFAULT_REFUND_BPS,
            arbiter_reward_bps: DEFAULT_ARBITER_REWARD_BPS,
            protocol_reserve_bps: DEFAULT_PROTOCOL_RESERVE_BPS,
            max_sponsor_risk_bps: DEFAULT_MAX_SPONSOR_RISK_BPS,
            max_evidence_items_per_case: DEFAULT_MAX_EVIDENCE_ITEMS_PER_CASE,
        }
    }
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure_non_empty(&self.chain_id, "chain_id")?;
        ensure_non_empty(&self.protocol_version, "protocol_version")?;
        ensure!(
            self.min_pq_security_bits >= 192,
            "min pq security must be at least 192 bits"
        );
        ensure!(self.min_privacy_set_size >= 8_192, "privacy set too small");
        ensure!(
            self.target_privacy_set_size >= self.min_privacy_set_size,
            "target privacy set below minimum"
        );
        ensure!(
            self.min_sponsor_bond_micro_units > 0,
            "sponsor bond must be non-zero"
        );
        validate_bps(self.max_case_fee_bps, "max_case_fee_bps")?;
        validate_bps(self.target_case_fee_bps, "target_case_fee_bps")?;
        validate_bps(self.min_committee_quorum_bps, "min_committee_quorum_bps")?;
        validate_bps(
            self.strong_committee_quorum_bps,
            "strong_committee_quorum_bps",
        )?;
        validate_bps(self.minor_slash_bps, "minor_slash_bps")?;
        validate_bps(self.major_slash_bps, "major_slash_bps")?;
        validate_bps(self.privacy_leak_slash_bps, "privacy_leak_slash_bps")?;
        ensure!(
            self.target_case_fee_bps <= self.max_case_fee_bps,
            "target fee exceeds max case fee"
        );
        ensure!(
            self.min_committee_quorum_bps <= self.strong_committee_quorum_bps,
            "strong quorum below minimum quorum"
        );
        ensure!(
            self.minor_slash_bps <= self.major_slash_bps,
            "minor slash exceeds major slash"
        );
        ensure!(
            self.major_slash_bps <= self.privacy_leak_slash_bps,
            "major slash exceeds privacy slash"
        );
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub sponsor_bonds: u64,
    pub active_sponsors: u64,
    pub policy_breach_attestations: u64,
    pub private_evidence_envelopes: u64,
    pub slashing_disputes: u64,
    pub live_disputes: u64,
    pub arbitration_committees: u64,
    pub arbiter_members: u64,
    pub committee_votes: u64,
    pub slashing_verdicts: u64,
    pub fee_credit_refunds: u64,
    pub paid_refunds: u64,
    pub nullifier_guards: u64,
    pub replay_blocks: u64,
    pub operator_summaries: u64,
    pub events: u64,
    pub total_bonded_micro_units: u64,
    pub total_locked_micro_units: u64,
    pub total_slashed_micro_units: u64,
    pub total_refund_micro_units: u64,
    pub total_case_fee_micro_units: u64,
    pub total_arbiter_reward_micro_units: u64,
}
impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub sponsor_bond_root: String,
    pub policy_breach_attestation_root: String,
    pub private_evidence_envelope_root: String,
    pub slashing_dispute_root: String,
    pub arbitration_committee_root: String,
    pub arbiter_member_root: String,
    pub committee_vote_root: String,
    pub slashing_verdict_root: String,
    pub fee_credit_refund_root: String,
    pub nullifier_guard_root: String,
    pub nullifier_set_root: String,
    pub operator_summary_root: String,
    pub event_root: String,
    pub public_record_root: String,
    pub state_root: String,
}
impl Default for Roots {
    fn default() -> Self {
        Self {
            config_root: empty_root("config"),
            sponsor_bond_root: empty_root("sponsor-bonds"),
            policy_breach_attestation_root: empty_root("policy-breach-attestations"),
            private_evidence_envelope_root: empty_root("private-evidence-envelopes"),
            slashing_dispute_root: empty_root("slashing-disputes"),
            arbitration_committee_root: empty_root("arbitration-committees"),
            arbiter_member_root: empty_root("arbiter-members"),
            committee_vote_root: empty_root("committee-votes"),
            slashing_verdict_root: empty_root("slashing-verdicts"),
            fee_credit_refund_root: empty_root("fee-credit-refunds"),
            nullifier_guard_root: empty_root("nullifier-guards"),
            nullifier_set_root: empty_root("nullifier-set"),
            operator_summary_root: empty_root("operator-summaries"),
            event_root: empty_root("events"),
            public_record_root: empty_root("public-record"),
            state_root: empty_root("state"),
        }
    }
}
impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorBond {
    pub sponsor_id: String,
    pub role: SponsorRole,
    pub status: SponsorStatus,
    pub bond_status: BondStatus,
    pub ml_dsa_key_root: String,
    pub sponsor_commitment_root: String,
    pub policy_root: String,
    pub bond_note_commitment: String,
    pub bond_asset_id: String,
    pub bonded_micro_units: u64,
    pub locked_micro_units: u64,
    pub slashed_micro_units: u64,
    pub refunded_micro_units: u64,
    pub active_dispute_count: u64,
    pub resolved_dispute_count: u64,
    pub accepted_breach_count: u64,
    pub rejected_breach_count: u64,
    pub first_active_slot: u64,
    pub last_activity_slot: u64,
    pub expiry_slot: u64,
    pub min_privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub risk_score_bps: u64,
    pub notes: Vec<String>,
}
impl SponsorBond {
    pub fn available_bond(&self) -> u64 {
        self.bonded_micro_units
            .saturating_sub(self.locked_micro_units)
            .saturating_sub(self.slashed_micro_units)
    }
    pub fn accountability_score_bps(&self) -> u64 {
        MAX_BPS.saturating_sub(
            (self.accepted_breach_count * 850
                + self.active_dispute_count * 200
                + self.risk_score_bps / 8)
                .min(MAX_BPS),
        )
    }
    pub fn can_back_dispute(&self, min_bond: u64) -> bool {
        self.status.can_sponsor() && self.bond_status.liquid() && self.available_bond() >= min_bond
    }
    pub fn public_record(&self) -> Value {
        let mut v = json!(self);
        v["available_bond"] = json!(self.available_bond());
        v["accountability_score_bps"] = json!(self.accountability_score_bps());
        v
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyBreachAttestation {
    pub attestation_id: String,
    pub dispute_id: String,
    pub sponsor_id: String,
    pub breach_kind: PolicyBreachKind,
    pub policy_epoch: u64,
    pub observed_slot: u64,
    pub submitted_slot: u64,
    pub expires_slot: u64,
    pub ml_dsa_attestor_key_root: String,
    pub policy_commitment_root: String,
    pub breach_commitment_root: String,
    pub redacted_context_root: String,
    pub signature_root: String,
    pub privacy_set_size: u64,
    pub decoy_set_root: String,
    pub severity_bps: u64,
    pub requested_slash_bps: u64,
    pub fee_delta_commitment: String,
    pub refund_commitment: String,
    pub accepted: bool,
}
impl PolicyBreachAttestation {
    pub fn expired(&self, slot: u64) -> bool {
        slot > self.expires_slot
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateEvidenceEnvelope {
    pub evidence_id: String,
    pub dispute_id: String,
    pub sponsor_id: String,
    pub status: EvidenceEnvelopeStatus,
    pub envelope_commitment_root: String,
    pub ciphertext_root: String,
    pub redaction_root: String,
    pub decrypt_share_root: String,
    pub access_policy_root: String,
    pub opening_nullifier: String,
    pub submitter_commitment: String,
    pub created_slot: u64,
    pub reveal_after_slot: u64,
    pub expires_slot: u64,
    pub byte_size: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub fee_micro_units: u64,
    pub risk_bps: u64,
}
impl PrivateEvidenceEnvelope {
    pub fn public_record(&self) -> Value {
        let mut v = json!(self);
        v["committee_readable"] = json!(self.status.committee_readable());
        v
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingDispute {
    pub dispute_id: String,
    pub sponsor_id: String,
    pub complainant_commitment: String,
    pub status: DisputeStatus,
    pub breach_kind: PolicyBreachKind,
    pub created_slot: u64,
    pub evidence_deadline_slot: u64,
    pub appeal_deadline_slot: u64,
    pub settlement_deadline_slot: u64,
    pub policy_epoch: u64,
    pub disputed_fee_commitment: String,
    pub requested_refund_commitment: String,
    pub requested_slash_bps: u64,
    pub bond_lock_micro_units: u64,
    pub case_fee_micro_units: u64,
    pub evidence_ids: BTreeSet<String>,
    pub attestation_ids: BTreeSet<String>,
    pub committee_id: Option<String>,
    pub verdict_id: Option<String>,
    pub nullifier: String,
    pub risk_bps: u64,
    pub low_fee_score_bps: u64,
}
impl SlashingDispute {
    pub fn expired(&self, slot: u64) -> bool {
        self.status.live() && slot > self.settlement_deadline_slot
    }
    pub fn public_record(&self) -> Value {
        let mut v = json!(self);
        v["evidence_count"] = json!(self.evidence_ids.len());
        v
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArbiterMember {
    pub arbiter_id: String,
    pub role: ArbiterRole,
    pub stake_commitment_root: String,
    pub ml_dsa_key_root: String,
    pub bond_micro_units: u64,
    pub reliability_bps: u64,
    pub privacy_training_epoch: u64,
    pub active: bool,
}
impl ArbiterMember {
    pub fn voting_weight(&self) -> u64 {
        if self.active {
            self.reliability_bps
                .saturating_mul(self.bond_micro_units.max(1))
                / 10_000
        } else {
            0
        }
    }
    pub fn public_record(&self) -> Value {
        let mut v = json!(self);
        v["voting_weight"] = json!(self.voting_weight());
        v
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArbitrationCommittee {
    pub committee_id: String,
    pub dispute_id: String,
    pub status: CommitteeStatus,
    pub member_ids: BTreeSet<String>,
    pub required_quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub formed_slot: u64,
    pub vote_deadline_slot: u64,
    pub evidence_access_root: String,
    pub committee_transcript_root: String,
    pub quorum_weight: u64,
    pub yes_weight: u64,
    pub no_weight: u64,
    pub abstain_weight: u64,
    pub privacy_objection_count: u64,
}
impl ArbitrationCommittee {
    pub fn total_vote_weight(&self) -> u64 {
        self.yes_weight + self.no_weight + self.abstain_weight
    }
    pub fn yes_bps(&self) -> u64 {
        let t = self.total_vote_weight();
        if t == 0 {
            0
        } else {
            self.yes_weight * MAX_BPS / t
        }
    }
    pub fn has_quorum(&self) -> bool {
        self.yes_bps() >= self.required_quorum_bps
    }
    pub fn has_strong_quorum(&self) -> bool {
        self.yes_bps() >= self.strong_quorum_bps
    }
    pub fn public_record(&self) -> Value {
        let mut v = json!(self);
        v["yes_bps"] = json!(self.yes_bps());
        v["has_quorum"] = json!(self.has_quorum());
        v["has_strong_quorum"] = json!(self.has_strong_quorum());
        v
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitteeVote {
    pub vote_id: String,
    pub committee_id: String,
    pub dispute_id: String,
    pub arbiter_id: String,
    pub vote_kind: VoteKind,
    pub support: bool,
    pub weight: u64,
    pub cast_slot: u64,
    pub reasoning_commitment_root: String,
    pub privacy_objection_root: String,
    pub ml_dsa_signature_root: String,
}
impl CommitteeVote {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingVerdict {
    pub verdict_id: String,
    pub dispute_id: String,
    pub sponsor_id: String,
    pub committee_id: String,
    pub decision: VerdictDecision,
    pub published_slot: u64,
    pub slash_bps: u64,
    pub slash_micro_units: u64,
    pub refund_micro_units: u64,
    pub arbiter_reward_micro_units: u64,
    pub protocol_reserve_micro_units: u64,
    pub verdict_commitment_root: String,
    pub public_reason_root: String,
    pub settlement_root: String,
    pub appeal_nullifier: String,
    pub final_after_slot: u64,
}
impl SlashingVerdict {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCreditRefund {
    pub refund_id: String,
    pub dispute_id: String,
    pub sponsor_id: String,
    pub status: RefundStatus,
    pub recipient_commitment: String,
    pub fee_credit_asset_id: String,
    pub refund_commitment_root: String,
    pub refund_micro_units: u64,
    pub case_fee_rebate_micro_units: u64,
    pub created_slot: u64,
    pub payable_after_slot: u64,
    pub expires_slot: u64,
    pub nullifier: String,
    pub payment_proof_root: String,
}
impl FeeCreditRefund {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierGuard {
    pub nullifier: String,
    pub subject_id: String,
    pub sponsor_id: String,
    pub status: NullifierStatus,
    pub domain: String,
    pub first_seen_slot: u64,
    pub expires_slot: u64,
    pub replay_count: u64,
    pub commitment_root: String,
}
impl NullifierGuard {
    pub fn expired(&self, slot: u64) -> bool {
        slot > self.expires_slot
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub operator_id: String,
    pub epoch: u64,
    pub sponsor_count: u64,
    pub active_dispute_count: u64,
    pub settled_dispute_count: u64,
    pub accepted_breach_count: u64,
    pub rejected_breach_count: u64,
    pub total_bonded_micro_units: u64,
    pub total_slashed_micro_units: u64,
    pub total_refund_micro_units: u64,
    pub average_case_fee_bps: u64,
    pub replay_blocks: u64,
    pub sponsor_bond_root: String,
    pub dispute_root: String,
    pub refund_root: String,
    pub risk_root: String,
    pub notes: Vec<String>,
}
impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub kind: String,
    pub slot: u64,
    pub subject_id: String,
    pub commitment_root: String,
    pub operator_visible: bool,
}
impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterSponsorBondRequest {
    pub sponsor_commitment_root: String,
    pub role: SponsorRole,
    pub ml_dsa_key_root: String,
    pub policy_root: String,
    pub bond_note_commitment: String,
    pub bonded_micro_units: u64,
    pub expiry_slot: u64,
    pub max_fee_bps: u64,
    pub notes: Vec<String>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitDisputeRequest {
    pub sponsor_id: String,
    pub complainant_commitment: String,
    pub breach_kind: PolicyBreachKind,
    pub policy_epoch: u64,
    pub disputed_fee_commitment: String,
    pub requested_refund_commitment: String,
    pub requested_slash_bps: u64,
    pub case_fee_micro_units: u64,
    pub nullifier: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttachEvidenceRequest {
    pub dispute_id: String,
    pub envelope_commitment_root: String,
    pub ciphertext_root: String,
    pub redaction_root: String,
    pub access_policy_root: String,
    pub opening_nullifier: String,
    pub submitter_commitment: String,
    pub byte_size: u64,
    pub fee_micro_units: u64,
    pub risk_bps: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttestPolicyBreachRequest {
    pub dispute_id: String,
    pub sponsor_id: String,
    pub breach_kind: PolicyBreachKind,
    pub policy_epoch: u64,
    pub ml_dsa_attestor_key_root: String,
    pub policy_commitment_root: String,
    pub breach_commitment_root: String,
    pub redacted_context_root: String,
    pub signature_root: String,
    pub decoy_set_root: String,
    pub fee_delta_commitment: String,
    pub refund_commitment: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AssignCommitteeRequest {
    pub dispute_id: String,
    pub member_ids: BTreeSet<String>,
    pub evidence_access_root: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CastVoteRequest {
    pub committee_id: String,
    pub arbiter_id: String,
    pub vote_kind: VoteKind,
    pub support: bool,
    pub reasoning_commitment_root: String,
    pub privacy_objection_root: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishVerdictRequest {
    pub dispute_id: String,
    pub committee_id: String,
    pub decision: VerdictDecision,
    pub slash_bps: u64,
    pub refund_micro_units: u64,
    pub public_reason_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_height: u64,
    pub current_epoch: u64,
    pub current_slot: u64,
    pub sponsor_bonds: BTreeMap<String, SponsorBond>,
    pub policy_breach_attestations: BTreeMap<String, PolicyBreachAttestation>,
    pub private_evidence_envelopes: BTreeMap<String, PrivateEvidenceEnvelope>,
    pub slashing_disputes: BTreeMap<String, SlashingDispute>,
    pub arbitration_committees: BTreeMap<String, ArbitrationCommittee>,
    pub arbiter_members: BTreeMap<String, ArbiterMember>,
    pub committee_votes: BTreeMap<String, CommitteeVote>,
    pub slashing_verdicts: BTreeMap<String, SlashingVerdict>,
    pub fee_credit_refunds: BTreeMap<String, FeeCreditRefund>,
    pub nullifier_guards: BTreeMap<String, NullifierGuard>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub events: BTreeMap<String, RuntimeEvent>,
    pub nullifiers: BTreeSet<String>,
}
impl Default for State {
    fn default() -> Self {
        Self::new(Config::default()).expect("default sponsor slashing arbitration config")
    }
}
impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            current_height: DEVNET_HEIGHT,
            current_epoch: DEVNET_EPOCH,
            current_slot: DEVNET_SLOT,
            sponsor_bonds: BTreeMap::new(),
            policy_breach_attestations: BTreeMap::new(),
            private_evidence_envelopes: BTreeMap::new(),
            slashing_disputes: BTreeMap::new(),
            arbitration_committees: BTreeMap::new(),
            arbiter_members: BTreeMap::new(),
            committee_votes: BTreeMap::new(),
            slashing_verdicts: BTreeMap::new(),
            fee_credit_refunds: BTreeMap::new(),
            nullifier_guards: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            events: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
        };
        state.recompute();
        Ok(state)
    }
    pub fn devnet() -> Self {
        let mut state = Self::new(Config::default()).expect("default config is valid");
        state.seed_devnet();
        state
    }
    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root());
        record
    }
    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }
    pub fn register_sponsor_bond(&mut self, request: RegisterSponsorBondRequest) -> Result<String> {
        ensure_capacity(self.sponsor_bonds.len(), MAX_SPONSOR_BONDS, "sponsor_bonds")?;
        ensure_non_empty(&request.sponsor_commitment_root, "sponsor_commitment_root")?;
        ensure_non_empty(&request.ml_dsa_key_root, "ml_dsa_key_root")?;
        ensure_non_empty(&request.policy_root, "policy_root")?;
        ensure!(
            request.bonded_micro_units >= self.config.min_sponsor_bond_micro_units,
            "sponsor bond below minimum"
        );
        validate_bps(request.max_fee_bps, "max_fee_bps")?;
        let sponsor_id = deterministic_id(
            "sponsor-bond",
            &[
                HashPart::Str(&request.sponsor_commitment_root),
                HashPart::Str(&request.ml_dsa_key_root),
                HashPart::U64(request.bonded_micro_units),
            ],
        );
        let risk_score_bps = request
            .role
            .risk_weight_bps()
            .min(self.config.max_sponsor_risk_bps);
        let bond = SponsorBond {
            sponsor_id: sponsor_id.clone(),
            role: request.role,
            status: SponsorStatus::Active,
            bond_status: BondStatus::Active,
            ml_dsa_key_root: request.ml_dsa_key_root,
            sponsor_commitment_root: request.sponsor_commitment_root,
            policy_root: request.policy_root,
            bond_note_commitment: request.bond_note_commitment,
            bond_asset_id: self.config.bond_asset_id.clone(),
            bonded_micro_units: request.bonded_micro_units,
            locked_micro_units: 0,
            slashed_micro_units: 0,
            refunded_micro_units: 0,
            active_dispute_count: 0,
            resolved_dispute_count: 0,
            accepted_breach_count: 0,
            rejected_breach_count: 0,
            first_active_slot: self.current_slot,
            last_activity_slot: self.current_slot,
            expiry_slot: request.expiry_slot,
            min_privacy_set_size: self.config.min_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            max_fee_bps: request.max_fee_bps,
            risk_score_bps,
            notes: request.notes,
        };
        self.sponsor_bonds.insert(sponsor_id.clone(), bond);
        self.push_event("sponsor_bond_registered", &sponsor_id, true);
        self.recompute();
        Ok(sponsor_id)
    }
    pub fn add_arbiter_member(&mut self, mut member: ArbiterMember) -> Result<String> {
        ensure_capacity(
            self.arbiter_members.len(),
            MAX_ARBITER_MEMBERS,
            "arbiter_members",
        )?;
        ensure!(
            member.bond_micro_units >= self.config.min_arbiter_bond_micro_units,
            "arbiter bond below minimum"
        );
        if member.arbiter_id.is_empty() {
            member.arbiter_id = deterministic_id(
                "arbiter-member",
                &[
                    HashPart::Str(&member.stake_commitment_root),
                    HashPart::Str(&member.ml_dsa_key_root),
                    HashPart::U64(member.bond_micro_units),
                ],
            );
        }
        let id = member.arbiter_id.clone();
        self.arbiter_members.insert(id.clone(), member);
        self.push_event("arbiter_member_registered", &id, true);
        self.recompute();
        Ok(id)
    }
    pub fn submit_dispute(&mut self, request: SubmitDisputeRequest) -> Result<String> {
        ensure_capacity(
            self.slashing_disputes.len(),
            MAX_SLASHING_DISPUTES,
            "slashing_disputes",
        )?;
        ensure!(
            !self.nullifiers.contains(&request.nullifier),
            "dispute replay nullifier already used"
        );
        let sponsor = self
            .sponsor_bonds
            .get_mut(&request.sponsor_id)
            .ok_or_else(|| "unknown sponsor".to_string())?;
        let bond_lock_micro_units = prorata(
            sponsor.bonded_micro_units,
            request.requested_slash_bps.max(self.config.minor_slash_bps),
        );
        ensure!(
            sponsor.available_bond() >= bond_lock_micro_units,
            "insufficient available sponsor bond"
        );
        sponsor.locked_micro_units = sponsor
            .locked_micro_units
            .saturating_add(bond_lock_micro_units);
        sponsor.active_dispute_count = sponsor.active_dispute_count.saturating_add(1);
        sponsor.status = SponsorStatus::UnderReview;
        sponsor.bond_status = BondStatus::LockedByDispute;
        let dispute_id = deterministic_id(
            "slashing-dispute",
            &[
                HashPart::Str(&request.sponsor_id),
                HashPart::Str(&request.complainant_commitment),
                HashPart::Str(request.breach_kind.as_str()),
                HashPart::Str(&request.nullifier),
            ],
        );
        let dispute = SlashingDispute {
            dispute_id: dispute_id.clone(),
            sponsor_id: request.sponsor_id.clone(),
            complainant_commitment: request.complainant_commitment,
            status: DisputeStatus::EvidencePending,
            breach_kind: request.breach_kind,
            created_slot: self.current_slot,
            evidence_deadline_slot: self.current_slot + self.config.evidence_reveal_window_slots,
            appeal_deadline_slot: self.current_slot + self.config.appeal_window_slots,
            settlement_deadline_slot: self.current_slot + self.config.dispute_window_slots,
            policy_epoch: request.policy_epoch,
            disputed_fee_commitment: request.disputed_fee_commitment,
            requested_refund_commitment: request.requested_refund_commitment,
            requested_slash_bps: request.requested_slash_bps,
            bond_lock_micro_units,
            case_fee_micro_units: request.case_fee_micro_units,
            evidence_ids: BTreeSet::new(),
            attestation_ids: BTreeSet::new(),
            committee_id: None,
            verdict_id: None,
            nullifier: request.nullifier.clone(),
            risk_bps: request.breach_kind.severity_bps(),
            low_fee_score_bps: MAX_BPS - self.config.target_case_fee_bps * 100,
        };
        self.insert_nullifier_guard(
            request.nullifier,
            dispute_id.clone(),
            request.sponsor_id,
            "dispute".to_string(),
            self.current_slot + self.config.dispute_window_slots,
        )?;
        self.slashing_disputes.insert(dispute_id.clone(), dispute);
        self.push_event("slashing_dispute_submitted", &dispute_id, true);
        self.recompute();
        Ok(dispute_id)
    }
    pub fn attach_private_evidence(&mut self, request: AttachEvidenceRequest) -> Result<String> {
        ensure_capacity(
            self.private_evidence_envelopes.len(),
            MAX_PRIVATE_EVIDENCE_ENVELOPES,
            "private_evidence_envelopes",
        )?;
        let dispute = self
            .slashing_disputes
            .get_mut(&request.dispute_id)
            .ok_or_else(|| "unknown dispute".to_string())?;
        ensure!(
            dispute.evidence_ids.len() < self.config.max_evidence_items_per_case,
            "too many evidence envelopes for dispute"
        );
        let evidence_id = deterministic_id(
            "private-evidence",
            &[
                HashPart::Str(&request.dispute_id),
                HashPart::Str(&request.envelope_commitment_root),
                HashPart::Str(&request.opening_nullifier),
            ],
        );
        let envelope = PrivateEvidenceEnvelope {
            evidence_id: evidence_id.clone(),
            dispute_id: request.dispute_id.clone(),
            sponsor_id: dispute.sponsor_id.clone(),
            status: EvidenceEnvelopeStatus::Sealed,
            envelope_commitment_root: request.envelope_commitment_root,
            ciphertext_root: request.ciphertext_root,
            redaction_root: request.redaction_root,
            decrypt_share_root: sample_hash(
                "decrypt-share-root",
                self.private_evidence_envelopes.len() as u64,
            ),
            access_policy_root: request.access_policy_root,
            opening_nullifier: request.opening_nullifier.clone(),
            submitter_commitment: request.submitter_commitment,
            created_slot: self.current_slot,
            reveal_after_slot: self.current_slot + self.config.evidence_reveal_window_slots / 4,
            expires_slot: dispute.settlement_deadline_slot,
            byte_size: request.byte_size,
            privacy_set_size: self.config.min_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            fee_micro_units: request.fee_micro_units,
            risk_bps: request.risk_bps,
        };
        dispute.evidence_ids.insert(evidence_id.clone());
        dispute.status = DisputeStatus::EvidenceSealed;
        self.private_evidence_envelopes
            .insert(evidence_id.clone(), envelope);
        self.nullifiers.insert(request.opening_nullifier);
        self.push_event("private_evidence_attached", &evidence_id, false);
        self.recompute();
        Ok(evidence_id)
    }
    pub fn attest_policy_breach(&mut self, request: AttestPolicyBreachRequest) -> Result<String> {
        ensure_capacity(
            self.policy_breach_attestations.len(),
            MAX_POLICY_BREACH_ATTESTATIONS,
            "policy_breach_attestations",
        )?;
        let dispute = self
            .slashing_disputes
            .get_mut(&request.dispute_id)
            .ok_or_else(|| "unknown dispute".to_string())?;
        let attestation_id = deterministic_id(
            "policy-breach-attestation",
            &[
                HashPart::Str(&request.dispute_id),
                HashPart::Str(&request.sponsor_id),
                HashPart::Str(request.breach_kind.as_str()),
                HashPart::Str(&request.signature_root),
            ],
        );
        let attestation = PolicyBreachAttestation {
            attestation_id: attestation_id.clone(),
            dispute_id: request.dispute_id.clone(),
            sponsor_id: request.sponsor_id,
            breach_kind: request.breach_kind,
            policy_epoch: request.policy_epoch,
            observed_slot: self.current_slot.saturating_sub(1),
            submitted_slot: self.current_slot,
            expires_slot: self.current_slot + self.config.dispute_window_slots,
            ml_dsa_attestor_key_root: request.ml_dsa_attestor_key_root,
            policy_commitment_root: request.policy_commitment_root,
            breach_commitment_root: request.breach_commitment_root,
            redacted_context_root: request.redacted_context_root,
            signature_root: request.signature_root,
            privacy_set_size: self.config.min_privacy_set_size,
            decoy_set_root: request.decoy_set_root,
            severity_bps: request.breach_kind.severity_bps(),
            requested_slash_bps: request
                .breach_kind
                .default_slash_bps(&self.config)
                .max(dispute.requested_slash_bps),
            fee_delta_commitment: request.fee_delta_commitment,
            refund_commitment: request.refund_commitment,
            accepted: false,
        };
        dispute.attestation_ids.insert(attestation_id.clone());
        dispute.status = DisputeStatus::Attesting;
        self.policy_breach_attestations
            .insert(attestation_id.clone(), attestation);
        self.push_event("policy_breach_attested", &attestation_id, true);
        self.recompute();
        Ok(attestation_id)
    }
    pub fn assign_committee(&mut self, request: AssignCommitteeRequest) -> Result<String> {
        ensure_capacity(
            self.arbitration_committees.len(),
            MAX_ARBITRATION_COMMITTEES,
            "arbitration_committees",
        )?;
        ensure!(
            !request.member_ids.is_empty(),
            "committee must have members"
        );
        let dispute = self
            .slashing_disputes
            .get_mut(&request.dispute_id)
            .ok_or_else(|| "unknown dispute".to_string())?;
        let committee_id = deterministic_id(
            "arbitration-committee",
            &[
                HashPart::Str(&request.dispute_id),
                HashPart::Json(&json!(request.member_ids)),
                HashPart::Str(&request.evidence_access_root),
            ],
        );
        let quorum_weight = request
            .member_ids
            .iter()
            .filter_map(|id| self.arbiter_members.get(id))
            .map(ArbiterMember::voting_weight)
            .sum();
        let committee = ArbitrationCommittee {
            committee_id: committee_id.clone(),
            dispute_id: request.dispute_id.clone(),
            status: CommitteeStatus::Active,
            member_ids: request.member_ids,
            required_quorum_bps: self.config.min_committee_quorum_bps,
            strong_quorum_bps: self.config.strong_committee_quorum_bps,
            formed_slot: self.current_slot,
            vote_deadline_slot: self.current_slot + self.config.dispute_window_slots / 2,
            evidence_access_root: request.evidence_access_root,
            committee_transcript_root: sample_hash(
                "committee-transcript",
                self.arbitration_committees.len() as u64,
            ),
            quorum_weight,
            yes_weight: 0,
            no_weight: 0,
            abstain_weight: 0,
            privacy_objection_count: 0,
        };
        dispute.committee_id = Some(committee_id.clone());
        dispute.status = DisputeStatus::CommitteeAssigned;
        self.arbitration_committees
            .insert(committee_id.clone(), committee);
        self.push_event("arbitration_committee_assigned", &committee_id, true);
        self.recompute();
        Ok(committee_id)
    }
    pub fn cast_vote(&mut self, request: CastVoteRequest) -> Result<String> {
        ensure_capacity(
            self.committee_votes.len(),
            MAX_COMMITTEE_VOTES,
            "committee_votes",
        )?;
        let committee = self
            .arbitration_committees
            .get_mut(&request.committee_id)
            .ok_or_else(|| "unknown committee".to_string())?;
        ensure!(
            committee.member_ids.contains(&request.arbiter_id),
            "arbiter not in committee"
        );
        let member = self
            .arbiter_members
            .get(&request.arbiter_id)
            .ok_or_else(|| "unknown arbiter".to_string())?;
        let weight = member.voting_weight();
        let vote_id = deterministic_id(
            "committee-vote",
            &[
                HashPart::Str(&request.committee_id),
                HashPart::Str(&request.arbiter_id),
                HashPart::Str(request.vote_kind.as_str()),
                HashPart::U64(self.current_slot),
            ],
        );
        if request.support {
            committee.yes_weight += weight
        } else if request.vote_kind == VoteKind::RejectDispute {
            committee.no_weight += weight
        } else {
            committee.abstain_weight += weight
        };
        committee.status = if committee.has_strong_quorum() {
            CommitteeStatus::StrongQuorumReached
        } else if committee.has_quorum() {
            CommitteeStatus::QuorumReached
        } else {
            CommitteeStatus::Active
        };
        let vote = CommitteeVote {
            vote_id: vote_id.clone(),
            committee_id: request.committee_id.clone(),
            dispute_id: committee.dispute_id.clone(),
            arbiter_id: request.arbiter_id,
            vote_kind: request.vote_kind,
            support: request.support,
            weight,
            cast_slot: self.current_slot,
            reasoning_commitment_root: request.reasoning_commitment_root,
            privacy_objection_root: request.privacy_objection_root,
            ml_dsa_signature_root: sample_hash("vote-signature", self.committee_votes.len() as u64),
        };
        self.committee_votes.insert(vote_id.clone(), vote);
        self.push_event("committee_vote_cast", &vote_id, true);
        self.recompute();
        Ok(vote_id)
    }
    pub fn publish_verdict(&mut self, request: PublishVerdictRequest) -> Result<String> {
        ensure_capacity(
            self.slashing_verdicts.len(),
            MAX_SLASHING_VERDICTS,
            "slashing_verdicts",
        )?;
        let committee = self
            .arbitration_committees
            .get_mut(&request.committee_id)
            .ok_or_else(|| "unknown committee".to_string())?;
        let dispute = self
            .slashing_disputes
            .get_mut(&request.dispute_id)
            .ok_or_else(|| "unknown dispute".to_string())?;
        let sponsor = self
            .sponsor_bonds
            .get_mut(&dispute.sponsor_id)
            .ok_or_else(|| "unknown sponsor".to_string())?;
        let effective_slash_bps = if request.decision.slashing() {
            request
                .slash_bps
                .max(dispute.requested_slash_bps)
                .min(self.config.privacy_leak_slash_bps)
        } else {
            0
        };
        let slash_micro_units = prorata(sponsor.bonded_micro_units, effective_slash_bps)
            .min(sponsor.locked_micro_units.max(sponsor.available_bond()));
        let arbiter_reward_micro_units = prorata(slash_micro_units, self.config.arbiter_reward_bps);
        let protocol_reserve_micro_units =
            prorata(slash_micro_units, self.config.protocol_reserve_bps);
        sponsor.slashed_micro_units += slash_micro_units;
        sponsor.locked_micro_units = sponsor
            .locked_micro_units
            .saturating_sub(dispute.bond_lock_micro_units);
        sponsor.active_dispute_count = sponsor.active_dispute_count.saturating_sub(1);
        sponsor.resolved_dispute_count += 1;
        if request.decision.slashing() {
            sponsor.accepted_breach_count += 1;
            sponsor.bond_status = BondStatus::PartiallySlashed;
            sponsor.status = SponsorStatus::CapacityLimited
        } else {
            sponsor.rejected_breach_count += 1;
            sponsor.bond_status = BondStatus::Active;
            sponsor.status = SponsorStatus::Active
        };
        let verdict_id = deterministic_id(
            "slashing-verdict",
            &[
                HashPart::Str(&request.dispute_id),
                HashPart::Str(&request.committee_id),
                HashPart::Str(request.decision.as_str()),
                HashPart::U64(self.current_slot),
            ],
        );
        let verdict = SlashingVerdict {
            verdict_id: verdict_id.clone(),
            dispute_id: request.dispute_id.clone(),
            sponsor_id: dispute.sponsor_id.clone(),
            committee_id: request.committee_id.clone(),
            decision: request.decision,
            published_slot: self.current_slot,
            slash_bps: effective_slash_bps,
            slash_micro_units,
            refund_micro_units: request.refund_micro_units,
            arbiter_reward_micro_units,
            protocol_reserve_micro_units,
            verdict_commitment_root: sample_hash(
                "verdict-commitment",
                self.slashing_verdicts.len() as u64,
            ),
            public_reason_root: request.public_reason_root,
            settlement_root: sample_hash("settlement-root", self.slashing_verdicts.len() as u64),
            appeal_nullifier: sample_hash("appeal-nullifier", self.slashing_verdicts.len() as u64),
            final_after_slot: self.current_slot + self.config.appeal_window_slots,
        };
        dispute.verdict_id = Some(verdict_id.clone());
        dispute.status = DisputeStatus::VerdictPublished;
        committee.status = CommitteeStatus::VerdictReady;
        self.slashing_verdicts
            .insert(verdict_id.clone(), verdict.clone());
        if verdict.refund_micro_units > 0 {
            self.queue_refund(&verdict)?;
        }
        self.push_event("slashing_verdict_published", &verdict_id, true);
        self.recompute();
        Ok(verdict_id)
    }
    pub fn settle_refund(
        &mut self,
        refund_id: &str,
        payment_proof_root: impl Into<String>,
    ) -> Result<()> {
        let refund = self
            .fee_credit_refunds
            .get_mut(refund_id)
            .ok_or_else(|| "unknown refund".to_string())?;
        refund.status = RefundStatus::Paid;
        refund.payment_proof_root = payment_proof_root.into();
        self.push_event("fee_credit_refund_paid", refund_id, false);
        self.recompute();
        Ok(())
    }
    pub fn advance_slot(&mut self, slots: u64) {
        self.current_slot += slots;
        self.current_height += slots / 2;
        self.current_epoch = DEVNET_EPOCH + self.current_slot / 512;
        self.recompute()
    }
    pub fn recompute(&mut self) {
        self.counters = self.compute_counters();
        self.roots = self.compute_roots();
    }
    fn compute_counters(&self) -> Counters {
        Counters {
            sponsor_bonds: self.sponsor_bonds.len() as u64,
            active_sponsors: self
                .sponsor_bonds
                .values()
                .filter(|b| b.status.can_sponsor())
                .count() as u64,
            policy_breach_attestations: self.policy_breach_attestations.len() as u64,
            private_evidence_envelopes: self.private_evidence_envelopes.len() as u64,
            slashing_disputes: self.slashing_disputes.len() as u64,
            live_disputes: self
                .slashing_disputes
                .values()
                .filter(|d| d.status.live())
                .count() as u64,
            arbitration_committees: self.arbitration_committees.len() as u64,
            arbiter_members: self.arbiter_members.len() as u64,
            committee_votes: self.committee_votes.len() as u64,
            slashing_verdicts: self.slashing_verdicts.len() as u64,
            fee_credit_refunds: self.fee_credit_refunds.len() as u64,
            paid_refunds: self
                .fee_credit_refunds
                .values()
                .filter(|r| r.status == RefundStatus::Paid)
                .count() as u64,
            nullifier_guards: self.nullifier_guards.len() as u64,
            replay_blocks: self.nullifier_guards.values().map(|g| g.replay_count).sum(),
            operator_summaries: self.operator_summaries.len() as u64,
            events: self.events.len() as u64,
            total_bonded_micro_units: self
                .sponsor_bonds
                .values()
                .map(|b| b.bonded_micro_units)
                .sum(),
            total_locked_micro_units: self
                .sponsor_bonds
                .values()
                .map(|b| b.locked_micro_units)
                .sum(),
            total_slashed_micro_units: self
                .sponsor_bonds
                .values()
                .map(|b| b.slashed_micro_units)
                .sum(),
            total_refund_micro_units: self
                .fee_credit_refunds
                .values()
                .map(|r| r.refund_micro_units)
                .sum(),
            total_case_fee_micro_units: self
                .slashing_disputes
                .values()
                .map(|d| d.case_fee_micro_units)
                .sum(),
            total_arbiter_reward_micro_units: self
                .slashing_verdicts
                .values()
                .map(|v| v.arbiter_reward_micro_units)
                .sum(),
        }
    }
    fn compute_roots(&self) -> Roots {
        let mut roots = Roots {
            config_root: value_root("config", &self.config.public_record()),
            sponsor_bond_root: record_map_root(
                "sponsor-bonds",
                &public_map(&self.sponsor_bonds, SponsorBond::public_record),
            ),
            policy_breach_attestation_root: record_map_root(
                "policy-breach-attestations",
                &public_map(
                    &self.policy_breach_attestations,
                    PolicyBreachAttestation::public_record,
                ),
            ),
            private_evidence_envelope_root: record_map_root(
                "private-evidence-envelopes",
                &public_map(
                    &self.private_evidence_envelopes,
                    PrivateEvidenceEnvelope::public_record,
                ),
            ),
            slashing_dispute_root: record_map_root(
                "slashing-disputes",
                &public_map(&self.slashing_disputes, SlashingDispute::public_record),
            ),
            arbitration_committee_root: record_map_root(
                "arbitration-committees",
                &public_map(
                    &self.arbitration_committees,
                    ArbitrationCommittee::public_record,
                ),
            ),
            arbiter_member_root: record_map_root(
                "arbiter-members",
                &public_map(&self.arbiter_members, ArbiterMember::public_record),
            ),
            committee_vote_root: record_map_root(
                "committee-votes",
                &public_map(&self.committee_votes, CommitteeVote::public_record),
            ),
            slashing_verdict_root: record_map_root(
                "slashing-verdicts",
                &public_map(&self.slashing_verdicts, SlashingVerdict::public_record),
            ),
            fee_credit_refund_root: record_map_root(
                "fee-credit-refunds",
                &public_map(&self.fee_credit_refunds, FeeCreditRefund::public_record),
            ),
            nullifier_guard_root: record_map_root(
                "nullifier-guards",
                &public_map(&self.nullifier_guards, NullifierGuard::public_record),
            ),
            nullifier_set_root: set_root("nullifiers", &self.nullifiers),
            operator_summary_root: record_map_root(
                "operator-summaries",
                &public_map(&self.operator_summaries, OperatorSummary::public_record),
            ),
            event_root: record_map_root(
                "events",
                &public_map(&self.events, RuntimeEvent::public_record),
            ),
            public_record_root: empty_root("public-record"),
            state_root: empty_root("state"),
        };
        let record = self.public_record_without_roots(&roots);
        roots.public_record_root = value_root("public-record", &record);
        roots.state_root = state_root_from_record(&record);
        roots
    }
    fn public_record_without_state_root(&self) -> Value {
        self.public_record_without_roots(&self.roots)
    }
    fn public_record_without_roots(&self, roots: &Roots) -> Value {
        json!({"schema_version":SCHEMA_VERSION,"protocol_version":self.config.protocol_version,"chain_id":self.config.chain_id,"l2_network":self.config.l2_network,"height":self.current_height,"epoch":self.current_epoch,"slot":self.current_slot,"hash_suite":self.config.hash_suite,"ml_dsa_suite":self.config.ml_dsa_suite,"pq_evidence_suite":self.config.pq_evidence_suite,"privacy_boundary":self.config.privacy_boundary,"config":self.config.public_record(),"counters":self.counters.public_record(),"roots":roots.public_record(),"sponsor_bonds":public_map(&self.sponsor_bonds,SponsorBond::public_record),"policy_breach_attestations":public_map(&self.policy_breach_attestations,PolicyBreachAttestation::public_record),"private_evidence_envelopes":public_map(&self.private_evidence_envelopes,PrivateEvidenceEnvelope::public_record),"slashing_disputes":public_map(&self.slashing_disputes,SlashingDispute::public_record),"arbitration_committees":public_map(&self.arbitration_committees,ArbitrationCommittee::public_record),"arbiter_members":public_map(&self.arbiter_members,ArbiterMember::public_record),"committee_votes":public_map(&self.committee_votes,CommitteeVote::public_record),"slashing_verdicts":public_map(&self.slashing_verdicts,SlashingVerdict::public_record),"fee_credit_refunds":public_map(&self.fee_credit_refunds,FeeCreditRefund::public_record),"nullifier_guards":public_map(&self.nullifier_guards,NullifierGuard::public_record),"operator_summaries":public_map(&self.operator_summaries,OperatorSummary::public_record),"events":public_map(&self.events,RuntimeEvent::public_record)})
    }
    fn insert_nullifier_guard(
        &mut self,
        nullifier: String,
        subject_id: String,
        sponsor_id: String,
        domain: String,
        expires_slot: u64,
    ) -> Result<()> {
        if self.nullifiers.contains(&nullifier) {
            if let Some(g) = self.nullifier_guards.get_mut(&nullifier) {
                g.status = NullifierStatus::ReplayBlocked;
                g.replay_count += 1;
            }
            return Err("nullifier replay blocked".to_string());
        }
        let guard = NullifierGuard {
            nullifier: nullifier.clone(),
            subject_id,
            sponsor_id,
            status: NullifierStatus::Consumed,
            domain,
            first_seen_slot: self.current_slot,
            expires_slot,
            replay_count: 0,
            commitment_root: sample_hash(
                "nullifier-commitment",
                self.nullifier_guards.len() as u64,
            ),
        };
        self.nullifiers.insert(nullifier.clone());
        self.nullifier_guards.insert(nullifier, guard);
        Ok(())
    }
    fn queue_refund(&mut self, verdict: &SlashingVerdict) -> Result<()> {
        let refund_id = deterministic_id(
            "fee-credit-refund",
            &[
                HashPart::Str(&verdict.dispute_id),
                HashPart::Str(&verdict.sponsor_id),
                HashPart::U64(verdict.refund_micro_units),
            ],
        );
        let nullifier = deterministic_id("refund-nullifier", &[HashPart::Str(&refund_id)]);
        let refund = FeeCreditRefund {
            refund_id: refund_id.clone(),
            dispute_id: verdict.dispute_id.clone(),
            sponsor_id: verdict.sponsor_id.clone(),
            status: RefundStatus::Queued,
            recipient_commitment: sample_hash(
                "refund-recipient",
                self.fee_credit_refunds.len() as u64,
            ),
            fee_credit_asset_id: self.config.fee_asset_id.clone(),
            refund_commitment_root: sample_hash(
                "refund-commitment",
                self.fee_credit_refunds.len() as u64,
            ),
            refund_micro_units: verdict.refund_micro_units,
            case_fee_rebate_micro_units: prorata(
                verdict.refund_micro_units,
                self.config.refund_bps,
            ),
            created_slot: self.current_slot,
            payable_after_slot: self.current_slot,
            expires_slot: self.current_slot + self.config.refund_window_slots,
            nullifier: nullifier.clone(),
            payment_proof_root: empty_root("refund-payment-proof"),
        };
        self.insert_nullifier_guard(
            nullifier,
            refund_id.clone(),
            verdict.sponsor_id.clone(),
            "refund".to_string(),
            refund.expires_slot,
        )?;
        self.fee_credit_refunds.insert(refund_id, refund);
        Ok(())
    }
    fn push_event(&mut self, kind: &str, subject_id: &str, operator_visible: bool) {
        if self.events.len() >= MAX_EVENTS {
            return;
        }
        let event_id = deterministic_id(
            "event",
            &[
                HashPart::Str(kind),
                HashPart::Str(subject_id),
                HashPart::U64(self.current_slot),
                HashPart::U64(self.events.len() as u64),
            ],
        );
        let event = RuntimeEvent {
            event_id: event_id.clone(),
            kind: kind.to_string(),
            slot: self.current_slot,
            subject_id: subject_id.to_string(),
            commitment_root: sample_hash("event-commitment", self.events.len() as u64),
            operator_visible,
        };
        self.events.insert(event_id, event);
    }
    fn seed_devnet(&mut self) {
        for index in 0..6 {
            let role = match index {
                0 => SponsorRole::WalletPaymaster,
                1 => SponsorRole::MerchantPaymaster,
                2 => SponsorRole::BatchSponsor,
                3 => SponsorRole::BridgeExitSponsor,
                4 => SponsorRole::RecoverySponsor,
                _ => SponsorRole::LiquiditySponsor,
            };
            let _ = self.register_sponsor_bond(RegisterSponsorBondRequest {
                sponsor_commitment_root: sample_hash("sponsor-commitment", index),
                role,
                ml_dsa_key_root: sample_hash("sponsor-ml-dsa-key", index),
                policy_root: sample_hash("sponsor-policy", index),
                bond_note_commitment: sample_hash("sponsor-bond-note", index),
                bonded_micro_units: self.config.min_sponsor_bond_micro_units
                    + (index + 1) * 5_000_000,
                expiry_slot: self.current_slot + 20_000 + index,
                max_fee_bps: self.config.target_case_fee_bps + index,
                notes: vec![
                    "devnet sponsor fixture".to_string(),
                    format!("lane-{index}"),
                ],
            });
        }
        for index in 0..9 {
            let role = match index % 6 {
                0 => ArbiterRole::EvidenceDecryptor,
                1 => ArbiterRole::PolicyAuditor,
                2 => ArbiterRole::FeeAccountant,
                3 => ArbiterRole::PrivacyReviewer,
                4 => ArbiterRole::BondExecutor,
                _ => ArbiterRole::AppealsReviewer,
            };
            let _ = self.add_arbiter_member(ArbiterMember {
                arbiter_id: String::new(),
                role,
                stake_commitment_root: sample_hash("arbiter-stake", index),
                ml_dsa_key_root: sample_hash("arbiter-key", index),
                bond_micro_units: self.config.min_arbiter_bond_micro_units
                    + (index + 1) * 1_000_000,
                reliability_bps: 8_500 + index * 100,
                privacy_training_epoch: self.current_epoch - index,
                active: true,
            });
        }
        let sponsor_ids = self.sponsor_bonds.keys().cloned().collect::<Vec<_>>();
        if let Some(sponsor_id) = sponsor_ids.get(3) {
            let dispute_id = self
                .submit_dispute(SubmitDisputeRequest {
                    sponsor_id: sponsor_id.clone(),
                    complainant_commitment: sample_hash("complainant", 0),
                    breach_kind: PolicyBreachKind::FeeOvercharge,
                    policy_epoch: self.current_epoch,
                    disputed_fee_commitment: sample_hash("disputed-fee", 0),
                    requested_refund_commitment: sample_hash("requested-refund", 0),
                    requested_slash_bps: self.config.minor_slash_bps,
                    case_fee_micro_units: 3_000,
                    nullifier: sample_hash("dispute-nullifier", 0),
                })
                .expect("devnet dispute");
            let _ = self.attach_private_evidence(AttachEvidenceRequest {
                dispute_id: dispute_id.clone(),
                envelope_commitment_root: sample_hash("evidence-envelope", 0),
                ciphertext_root: sample_hash("evidence-ciphertext", 0),
                redaction_root: sample_hash("evidence-redaction", 0),
                access_policy_root: sample_hash("evidence-access", 0),
                opening_nullifier: sample_hash("evidence-nullifier", 0),
                submitter_commitment: sample_hash("evidence-submitter", 0),
                byte_size: 32_768,
                fee_micro_units: 500,
                risk_bps: 2_000,
            });
            let _ = self.attest_policy_breach(AttestPolicyBreachRequest {
                dispute_id: dispute_id.clone(),
                sponsor_id: sponsor_id.clone(),
                breach_kind: PolicyBreachKind::FeeOvercharge,
                policy_epoch: self.current_epoch,
                ml_dsa_attestor_key_root: sample_hash("attestor-key", 0),
                policy_commitment_root: sample_hash("attested-policy", 0),
                breach_commitment_root: sample_hash("breach-commitment", 0),
                redacted_context_root: sample_hash("redacted-context", 0),
                signature_root: sample_hash("attestation-signature", 0),
                decoy_set_root: sample_hash("decoy-set", 0),
                fee_delta_commitment: sample_hash("fee-delta", 0),
                refund_commitment: sample_hash("refund-claim", 0),
            });
            let member_ids = self
                .arbiter_members
                .keys()
                .take(5)
                .cloned()
                .collect::<BTreeSet<_>>();
            let committee_id = self
                .assign_committee(AssignCommitteeRequest {
                    dispute_id: dispute_id.clone(),
                    member_ids: member_ids.clone(),
                    evidence_access_root: sample_hash("committee-access", 0),
                })
                .expect("devnet committee");
            for (index, arbiter_id) in member_ids.iter().enumerate() {
                let _ = self.cast_vote(CastVoteRequest {
                    committee_id: committee_id.clone(),
                    arbiter_id: arbiter_id.clone(),
                    vote_kind: if index % 2 == 0 {
                        VoteKind::PolicyBreachProven
                    } else {
                        VoteKind::FeeRefundOwed
                    },
                    support: true,
                    reasoning_commitment_root: sample_hash("vote-reason", index as u64),
                    privacy_objection_root: empty_root("privacy-objection"),
                });
            }
            let _ = self.publish_verdict(PublishVerdictRequest {
                dispute_id,
                committee_id,
                decision: VerdictDecision::MinorSlash,
                slash_bps: self.config.minor_slash_bps,
                refund_micro_units: 25_000,
                public_reason_root: sample_hash("public-reason", 0),
            });
        }
        self.refresh_operator_summary("devnet-operator-0");
        self.recompute();
    }
    fn refresh_operator_summary(&mut self, operator_id: &str) {
        let summary = OperatorSummary {
            operator_id: operator_id.to_string(),
            epoch: self.current_epoch,
            sponsor_count: self.sponsor_bonds.len() as u64,
            active_dispute_count: self
                .slashing_disputes
                .values()
                .filter(|d| d.status.live())
                .count() as u64,
            settled_dispute_count: self
                .slashing_disputes
                .values()
                .filter(|d| {
                    matches!(
                        d.status,
                        DisputeStatus::Settled | DisputeStatus::VerdictPublished
                    )
                })
                .count() as u64,
            accepted_breach_count: self
                .sponsor_bonds
                .values()
                .map(|b| b.accepted_breach_count)
                .sum(),
            rejected_breach_count: self
                .sponsor_bonds
                .values()
                .map(|b| b.rejected_breach_count)
                .sum(),
            total_bonded_micro_units: self
                .sponsor_bonds
                .values()
                .map(|b| b.bonded_micro_units)
                .sum(),
            total_slashed_micro_units: self
                .sponsor_bonds
                .values()
                .map(|b| b.slashed_micro_units)
                .sum(),
            total_refund_micro_units: self
                .fee_credit_refunds
                .values()
                .map(|r| r.refund_micro_units)
                .sum(),
            average_case_fee_bps: self.config.target_case_fee_bps,
            replay_blocks: self.nullifier_guards.values().map(|g| g.replay_count).sum(),
            sponsor_bond_root: record_map_root(
                "summary-sponsor-bonds",
                &public_map(&self.sponsor_bonds, SponsorBond::public_record),
            ),
            dispute_root: record_map_root(
                "summary-disputes",
                &public_map(&self.slashing_disputes, SlashingDispute::public_record),
            ),
            refund_root: record_map_root(
                "summary-refunds",
                &public_map(&self.fee_credit_refunds, FeeCreditRefund::public_record),
            ),
            risk_root: sample_hash("summary-risk", self.current_epoch),
            notes: vec![
                "operator-safe roots only".to_string(),
                "no private evidence plaintext exported".to_string(),
            ],
        };
        self.operator_summaries
            .insert(operator_id.to_string(), summary);
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
pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-ML-DSA-SPONSOR-SLASHING-ARBITRATION-STATE",
        &[HashPart::Json(record)],
        32,
    )
}
pub fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-ML-DSA-SPONSOR-SLASHING-ARBITRATION-{domain}"),
        parts,
        32,
    )
}
pub fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-ML-DSA-SPONSOR-SLASHING-ARBITRATION-{domain}"),
        &[HashPart::Json(value)],
        32,
    )
}
pub fn empty_root(domain: &str) -> String {
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-ML-DSA-SPONSOR-SLASHING-ARBITRATION-{domain}"),
        &[],
    )
}
pub fn record_map_root(domain: &str, records: &BTreeMap<String, Value>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| json!({"key":key,"value":value}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-ML-DSA-SPONSOR-SLASHING-ARBITRATION-{domain}"),
        &leaves,
    )
}
pub fn set_root(domain: &str, records: &BTreeSet<String>) -> String {
    let leaves = records.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-ML-DSA-SPONSOR-SLASHING-ARBITRATION-{domain}"),
        &leaves,
    )
}
pub fn public_map<T>(
    records: &BTreeMap<String, T>,
    render: fn(&T) -> Value,
) -> BTreeMap<String, Value> {
    records
        .iter()
        .map(|(key, value)| (key.clone(), render(value)))
        .collect()
}
pub fn validate_bps(value: u64, label: &str) -> Result<()> {
    ensure!(value <= MAX_BPS, "{label} exceeds 100% bps");
    Ok(())
}
pub fn ensure_capacity(current: usize, max: usize, label: &str) -> Result<()> {
    ensure!(current < max, "{label} capacity exhausted");
    Ok(())
}
pub fn ensure_non_empty(value: &str, label: &str) -> Result<()> {
    ensure!(!value.trim().is_empty(), "{label} must be non-empty");
    Ok(())
}
pub fn prorata(amount: u64, bps: u64) -> u64 {
    amount.saturating_mul(bps) / MAX_BPS
}
pub fn sample_hash(label: &str, index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-ML-DSA-SPONSOR-SLASHING-ARBITRATION-DEVNET-SAMPLE",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}
