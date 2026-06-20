use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateBridgeLiquiditySafetyCouncilResult<T> = Result<T, String>;

pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_PROTOCOL_ID: &str =
    "nebula-private-bridge-liquidity-safety-council-v1";
pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_PUBLIC_RECORD_SCHEMA: &str =
    "private-bridge-liquidity-safety-council-public-record-v1";
pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEVNET_NETWORK: &str = "monero-devnet";
pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_PQ_SIGNATURE_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_PQ_KEM_SCHEME: &str = "ML-KEM-1024";
pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_PRIVATE_ENVELOPE_SCHEME: &str =
    "ml-kem-1024+xchacha20poly1305-private-bridge-risk-envelope-v1";
pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_RESERVE_COMMITMENT_SCHEME: &str =
    "monero-view-key-reserve-commitment-v1";
pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_CHALLENGE_PROOF_SYSTEM: &str =
    "pq-bridge-liquidity-challenge-proof-v1";
pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_SETTLEMENT_REPORT_SCHEMA: &str =
    "private-bridge-liquidity-settlement-report-v1";
pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_MAX_BPS: u64 = 10_000;
pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEVNET_HEIGHT: u64 = 1_536;
pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_QUORUM_WEIGHT: u64 = 7;
pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_SUPERMAJORITY_WEIGHT: u64 = 9;
pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_EMERGENCY_WEIGHT: u64 = 5;
pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 1_024;
pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_SNAPSHOT_TTL_BLOCKS: u64 = 36;
pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_APPROVAL_TTL_BLOCKS: u64 = 24;
pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_THROTTLE_TTL_BLOCKS: u64 = 72;
pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 144;
pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_REORG_FINALITY_DELAY_BLOCKS: u64 = 18;
pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_FAST_EXIT_CAP_BPS: u64 = 2_500;
pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_LOW_FEE_SUBSIDY_BPS: u64 = 8_500;
pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_TARGET_COVERAGE_BPS: u64 = 11_000;
pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_WARNING_COVERAGE_BPS: u64 = 10_250;
pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_HALT_COVERAGE_BPS: u64 = 9_500;
pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_MAX_MAKER_RISK_BPS: u64 = 6_500;
pub const PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_MAX_SPONSOR_FEE_UNITS: u64 = 12_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CouncilMemberRole {
    ReserveGuardian,
    LiquidityRiskSigner,
    ReorgResponder,
    FeeSponsorAuditor,
    SettlementReporter,
    EmergencyCoordinator,
}

impl CouncilMemberRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReserveGuardian => "reserve_guardian",
            Self::LiquidityRiskSigner => "liquidity_risk_signer",
            Self::ReorgResponder => "reorg_responder",
            Self::FeeSponsorAuditor => "fee_sponsor_auditor",
            Self::SettlementReporter => "settlement_reporter",
            Self::EmergencyCoordinator => "emergency_coordinator",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CouncilMemberStatus {
    Candidate,
    Active,
    Rotating,
    Suspended,
    Slashed,
    Retired,
}

impl CouncilMemberStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Suspended => "suspended",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn voting(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardianDuty {
    ReserveProof,
    WithdrawalRelease,
    MakerRisk,
    ReorgContainment,
    EmergencyThrottle,
    SubsidyApproval,
}

impl GuardianDuty {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReserveProof => "reserve_proof",
            Self::WithdrawalRelease => "withdrawal_release",
            Self::MakerRisk => "maker_risk",
            Self::ReorgContainment => "reorg_containment",
            Self::EmergencyThrottle => "emergency_throttle",
            Self::SubsidyApproval => "subsidy_approval",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveGuardianStatus {
    Standby,
    Monitoring,
    Signing,
    Challenged,
    Jailed,
    Retired,
}

impl ReserveGuardianStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standby => "standby",
            Self::Monitoring => "monitoring",
            Self::Signing => "signing",
            Self::Challenged => "challenged",
            Self::Jailed => "jailed",
            Self::Retired => "retired",
        }
    }

    pub fn can_guard(self) -> bool {
        matches!(self, Self::Monitoring | Self::Signing)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqApprovalKind {
    ReserveSnapshot,
    FastExitCap,
    MakerRiskBand,
    EmergencyThrottle,
    ReorgIncident,
    SubsidizedSafetyAction,
    SettlementReport,
    ChallengeResolution,
}

impl PqApprovalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReserveSnapshot => "reserve_snapshot",
            Self::FastExitCap => "fast_exit_cap",
            Self::MakerRiskBand => "maker_risk_band",
            Self::EmergencyThrottle => "emergency_throttle",
            Self::ReorgIncident => "reorg_incident",
            Self::SubsidizedSafetyAction => "subsidized_safety_action",
            Self::SettlementReport => "settlement_report",
            Self::ChallengeResolution => "challenge_resolution",
        }
    }

    pub fn requires_supermajority(self) -> bool {
        matches!(
            self,
            Self::EmergencyThrottle | Self::ReorgIncident | Self::ChallengeResolution
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqApprovalStatus {
    Draft,
    Collecting,
    QuorumMet,
    SupermajorityMet,
    Executed,
    Rejected,
    Expired,
}

impl PqApprovalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Collecting => "collecting",
            Self::QuorumMet => "quorum_met",
            Self::SupermajorityMet => "supermajority_met",
            Self::Executed => "executed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn accepted(self) -> bool {
        matches!(
            self,
            Self::QuorumMet | Self::SupermajorityMet | Self::Executed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MakerRiskBand {
    Prime,
    Standard,
    Caution,
    Constrained,
    Quarantined,
    Retired,
}

impl MakerRiskBand {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prime => "prime",
            Self::Standard => "standard",
            Self::Caution => "caution",
            Self::Constrained => "constrained",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
        }
    }

    pub fn risk_bps(self) -> u64 {
        match self {
            Self::Prime => 800,
            Self::Standard => 2_000,
            Self::Caution => 4_000,
            Self::Constrained => 6_500,
            Self::Quarantined => 9_000,
            Self::Retired => 10_000,
        }
    }

    pub fn allows_fast_exit(self) -> bool {
        matches!(self, Self::Prime | Self::Standard | Self::Caution)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MakerStatus {
    Onboarding,
    Active,
    Throttled,
    Paused,
    Quarantined,
    Retired,
}

impl MakerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Onboarding => "onboarding",
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Paused => "paused",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyThrottleKind {
    ReserveCoverage,
    MakerConcentration,
    ReorgContainment,
    FeeSpike,
    PrivacySetWeakness,
    PqSignerDrift,
    ManualCouncilBrake,
}

impl EmergencyThrottleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReserveCoverage => "reserve_coverage",
            Self::MakerConcentration => "maker_concentration",
            Self::ReorgContainment => "reorg_containment",
            Self::FeeSpike => "fee_spike",
            Self::PrivacySetWeakness => "privacy_set_weakness",
            Self::PqSignerDrift => "pq_signer_drift",
            Self::ManualCouncilBrake => "manual_council_brake",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThrottleStatus {
    Proposed,
    Active,
    CoolingDown,
    Lifted,
    Superseded,
    Expired,
}

impl ThrottleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::CoolingDown => "cooling_down",
            Self::Lifted => "lifted",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
        }
    }

    pub fn limits_flow(self) -> bool {
        matches!(self, Self::Active | Self::CoolingDown)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FastExitCapStatus {
    Draft,
    Active,
    Saturated,
    Reduced,
    Paused,
    Retired,
}

impl FastExitCapStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Saturated => "saturated",
            Self::Reduced => "reduced",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn available(self) -> bool {
        matches!(self, Self::Active | Self::Reduced)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReorgIncidentStatus {
    Observed,
    Containing,
    Challenged,
    Resolved,
    Compensated,
    FalseAlarm,
}

impl ReorgIncidentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Containing => "containing",
            Self::Challenged => "challenged",
            Self::Resolved => "resolved",
            Self::Compensated => "compensated",
            Self::FalseAlarm => "false_alarm",
        }
    }

    pub fn open(self) -> bool {
        matches!(
            self,
            Self::Observed | Self::Containing | Self::Challenged | Self::Resolved
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyActionKind {
    ReserveProofRefresh,
    MakerCapReduction,
    FastExitPause,
    ReorgCompensation,
    ChallengeReward,
    PrivacySetTopUp,
    PqKeyRotation,
}

impl SafetyActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReserveProofRefresh => "reserve_proof_refresh",
            Self::MakerCapReduction => "maker_cap_reduction",
            Self::FastExitPause => "fast_exit_pause",
            Self::ReorgCompensation => "reorg_compensation",
            Self::ChallengeReward => "challenge_reward",
            Self::PrivacySetTopUp => "privacy_set_top_up",
            Self::PqKeyRotation => "pq_key_rotation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyActionStatus {
    Proposed,
    Approved,
    Subsidized,
    Executed,
    Reimbursed,
    Denied,
    Expired,
}

impl SafetyActionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Approved => "approved",
            Self::Subsidized => "subsidized",
            Self::Executed => "executed",
            Self::Reimbursed => "reimbursed",
            Self::Denied => "denied",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    ReserveMismatch,
    MakerOverCap,
    StalePqApproval,
    ReorgMisclassification,
    SubsidyAbuse,
    SettlementDelay,
    PrivacyLeakage,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReserveMismatch => "reserve_mismatch",
            Self::MakerOverCap => "maker_over_cap",
            Self::StalePqApproval => "stale_pq_approval",
            Self::ReorgMisclassification => "reorg_misclassification",
            Self::SubsidyAbuse => "subsidy_abuse",
            Self::SettlementDelay => "settlement_delay",
            Self::PrivacyLeakage => "privacy_leakage",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Committed,
    EvidenceOpen,
    CouncilAccepted,
    CouncilRejected,
    Escalated,
    Rewarded,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::EvidenceOpen => "evidence_open",
            Self::CouncilAccepted => "council_accepted",
            Self::CouncilRejected => "council_rejected",
            Self::Escalated => "escalated",
            Self::Rewarded => "rewarded",
            Self::Expired => "expired",
        }
    }

    pub fn open(self) -> bool {
        matches!(
            self,
            Self::Committed | Self::EvidenceOpen | Self::CouncilAccepted | Self::Escalated
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementReportStatus {
    Draft,
    Published,
    PqApproved,
    Challenged,
    Final,
    Corrected,
}

impl SettlementReportStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Published => "published",
            Self::PqApproved => "pq_approved",
            Self::Challenged => "challenged",
            Self::Final => "final",
            Self::Corrected => "corrected",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateBridgeLiquiditySafetyCouncilConfig {
    pub protocol_id: String,
    pub public_record_schema: String,
    pub chain_id: String,
    pub monero_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub pq_signature_scheme: String,
    pub pq_kem_scheme: String,
    pub private_envelope_scheme: String,
    pub reserve_commitment_scheme: String,
    pub challenge_proof_system: String,
    pub settlement_report_schema: String,
    pub min_pq_security_bits: u16,
    pub quorum_weight: u64,
    pub supermajority_weight: u64,
    pub emergency_weight: u64,
    pub min_privacy_set_size: u64,
    pub snapshot_ttl_blocks: u64,
    pub approval_ttl_blocks: u64,
    pub throttle_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub reorg_finality_delay_blocks: u64,
    pub default_fast_exit_cap_bps: u64,
    pub low_fee_subsidy_bps: u64,
    pub target_coverage_bps: u64,
    pub warning_coverage_bps: u64,
    pub halt_coverage_bps: u64,
    pub max_maker_risk_bps: u64,
    pub max_sponsor_fee_units: u64,
}

impl PrivateBridgeLiquiditySafetyCouncilConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_id: PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_PROTOCOL_ID.to_string(),
            public_record_schema: PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_PUBLIC_RECORD_SCHEMA
                .to_string(),
            chain_id: CHAIN_ID.to_string(),
            monero_network: PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEVNET_NETWORK.to_string(),
            asset_id: PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEVNET_FEE_ASSET_ID.to_string(),
            pq_signature_scheme: PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_PQ_SIGNATURE_SCHEME
                .to_string(),
            pq_kem_scheme: PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_PQ_KEM_SCHEME.to_string(),
            private_envelope_scheme:
                PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_PRIVATE_ENVELOPE_SCHEME.to_string(),
            reserve_commitment_scheme:
                PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_RESERVE_COMMITMENT_SCHEME.to_string(),
            challenge_proof_system: PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_CHALLENGE_PROOF_SYSTEM
                .to_string(),
            settlement_report_schema:
                PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_SETTLEMENT_REPORT_SCHEMA.to_string(),
            min_pq_security_bits:
                PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_MIN_PQ_SECURITY_BITS,
            quorum_weight: PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_QUORUM_WEIGHT,
            supermajority_weight:
                PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_SUPERMAJORITY_WEIGHT,
            emergency_weight: PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_EMERGENCY_WEIGHT,
            min_privacy_set_size:
                PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_MIN_PRIVACY_SET_SIZE,
            snapshot_ttl_blocks:
                PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_SNAPSHOT_TTL_BLOCKS,
            approval_ttl_blocks:
                PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_APPROVAL_TTL_BLOCKS,
            throttle_ttl_blocks:
                PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_THROTTLE_TTL_BLOCKS,
            challenge_window_blocks:
                PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            reorg_finality_delay_blocks:
                PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_REORG_FINALITY_DELAY_BLOCKS,
            default_fast_exit_cap_bps:
                PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_FAST_EXIT_CAP_BPS,
            low_fee_subsidy_bps:
                PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_LOW_FEE_SUBSIDY_BPS,
            target_coverage_bps:
                PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_TARGET_COVERAGE_BPS,
            warning_coverage_bps:
                PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_WARNING_COVERAGE_BPS,
            halt_coverage_bps: PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_HALT_COVERAGE_BPS,
            max_maker_risk_bps: PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_MAX_MAKER_RISK_BPS,
            max_sponsor_fee_units:
                PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEFAULT_MAX_SPONSOR_FEE_UNITS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_id": self.protocol_id,
            "public_record_schema": self.public_record_schema,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_kem_scheme": self.pq_kem_scheme,
            "private_envelope_scheme": self.private_envelope_scheme,
            "reserve_commitment_scheme": self.reserve_commitment_scheme,
            "challenge_proof_system": self.challenge_proof_system,
            "settlement_report_schema": self.settlement_report_schema,
            "min_pq_security_bits": self.min_pq_security_bits,
            "quorum_weight": self.quorum_weight,
            "supermajority_weight": self.supermajority_weight,
            "emergency_weight": self.emergency_weight,
            "min_privacy_set_size": self.min_privacy_set_size,
            "snapshot_ttl_blocks": self.snapshot_ttl_blocks,
            "approval_ttl_blocks": self.approval_ttl_blocks,
            "throttle_ttl_blocks": self.throttle_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "reorg_finality_delay_blocks": self.reorg_finality_delay_blocks,
            "default_fast_exit_cap_bps": self.default_fast_exit_cap_bps,
            "low_fee_subsidy_bps": self.low_fee_subsidy_bps,
            "target_coverage_bps": self.target_coverage_bps,
            "warning_coverage_bps": self.warning_coverage_bps,
            "halt_coverage_bps": self.halt_coverage_bps,
            "max_maker_risk_bps": self.max_maker_risk_bps,
            "max_sponsor_fee_units": self.max_sponsor_fee_units,
        })
    }

    pub fn validate(&self) -> PrivateBridgeLiquiditySafetyCouncilResult<()> {
        require_non_empty("protocol_id", &self.protocol_id)?;
        require_non_empty("monero_network", &self.monero_network)?;
        require_non_empty("asset_id", &self.asset_id)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_non_empty("pq_signature_scheme", &self.pq_signature_scheme)?;
        require_non_empty("pq_kem_scheme", &self.pq_kem_scheme)?;
        if self.quorum_weight == 0 {
            return Err("quorum_weight must be non-zero".to_string());
        }
        if self.supermajority_weight < self.quorum_weight {
            return Err("supermajority_weight must be >= quorum_weight".to_string());
        }
        if self.emergency_weight == 0 || self.emergency_weight > self.quorum_weight {
            return Err("emergency_weight must be in 1..=quorum_weight".to_string());
        }
        if self.halt_coverage_bps > self.warning_coverage_bps
            || self.warning_coverage_bps > self.target_coverage_bps
        {
            return Err("coverage thresholds must be halt <= warning <= target".to_string());
        }
        if self.default_fast_exit_cap_bps > PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_MAX_BPS {
            return Err("default_fast_exit_cap_bps exceeds max bps".to_string());
        }
        if self.low_fee_subsidy_bps > PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_MAX_BPS {
            return Err("low_fee_subsidy_bps exceeds max bps".to_string());
        }
        if self.max_maker_risk_bps > PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_MAX_BPS {
            return Err("max_maker_risk_bps exceeds max bps".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CouncilMember {
    pub member_id: String,
    pub label: String,
    pub role: CouncilMemberRole,
    pub status: CouncilMemberStatus,
    pub pq_public_key_root: String,
    pub pq_backup_key_root: String,
    pub sealed_contact_root: String,
    pub weight: u64,
    pub joined_height: u64,
    pub last_seen_height: u64,
    pub slash_count: u64,
}

impl CouncilMember {
    pub fn new(
        label: &str,
        role: CouncilMemberRole,
        weight: u64,
        joined_height: u64,
    ) -> PrivateBridgeLiquiditySafetyCouncilResult<Self> {
        require_non_empty("label", label)?;
        let member_id = private_bridge_liquidity_safety_council_id(
            "COUNCIL-MEMBER",
            &[label, role.as_str(), &joined_height.to_string()],
        );
        Ok(Self {
            member_id,
            label: label.to_string(),
            role,
            status: CouncilMemberStatus::Active,
            pq_public_key_root: private_bridge_liquidity_safety_council_id(
                "COUNCIL-MEMBER-PQ-PUBKEY",
                &[label],
            ),
            pq_backup_key_root: private_bridge_liquidity_safety_council_id(
                "COUNCIL-MEMBER-PQ-BACKUP",
                &[label],
            ),
            sealed_contact_root: private_bridge_liquidity_safety_council_id(
                "COUNCIL-MEMBER-CONTACT",
                &[label],
            ),
            weight,
            joined_height,
            last_seen_height: joined_height,
            slash_count: 0,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "member_id": self.member_id,
            "label": self.label,
            "role": self.role.as_str(),
            "status": self.status.as_str(),
            "pq_public_key_root": self.pq_public_key_root,
            "pq_backup_key_root": self.pq_backup_key_root,
            "sealed_contact_root": self.sealed_contact_root,
            "weight": self.weight,
            "joined_height": self.joined_height,
            "last_seen_height": self.last_seen_height,
            "slash_count": self.slash_count,
        })
    }

    pub fn validate(&self) -> PrivateBridgeLiquiditySafetyCouncilResult<()> {
        require_non_empty("member_id", &self.member_id)?;
        require_non_empty("label", &self.label)?;
        require_non_empty("pq_public_key_root", &self.pq_public_key_root)?;
        require_non_empty("pq_backup_key_root", &self.pq_backup_key_root)?;
        require_non_empty("sealed_contact_root", &self.sealed_contact_root)?;
        if self.weight == 0 {
            return Err(format!("member {} has zero weight", self.member_id));
        }
        if self.last_seen_height < self.joined_height {
            return Err(format!(
                "member {} last seen before join height",
                self.member_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveGuardian {
    pub guardian_id: String,
    pub member_id: String,
    pub duty: GuardianDuty,
    pub status: ReserveGuardianStatus,
    pub reserve_address_commitment: String,
    pub view_key_commitment: String,
    pub spend_key_nullifier_root: String,
    pub watchtower_set_root: String,
    pub coverage_limit_units: u64,
    pub used_coverage_units: u64,
    pub last_snapshot_id: Option<String>,
    pub active_throttle_ids: BTreeSet<String>,
}

impl ReserveGuardian {
    pub fn public_record(&self) -> Value {
        json!({
            "guardian_id": self.guardian_id,
            "member_id": self.member_id,
            "duty": self.duty.as_str(),
            "status": self.status.as_str(),
            "reserve_address_commitment": self.reserve_address_commitment,
            "view_key_commitment": self.view_key_commitment,
            "spend_key_nullifier_root": self.spend_key_nullifier_root,
            "watchtower_set_root": self.watchtower_set_root,
            "coverage_limit_units": self.coverage_limit_units,
            "used_coverage_units": self.used_coverage_units,
            "last_snapshot_id": self.last_snapshot_id,
            "active_throttle_ids": self.active_throttle_ids,
        })
    }

    pub fn validate(&self) -> PrivateBridgeLiquiditySafetyCouncilResult<()> {
        require_non_empty("guardian_id", &self.guardian_id)?;
        require_non_empty("member_id", &self.member_id)?;
        require_non_empty(
            "reserve_address_commitment",
            &self.reserve_address_commitment,
        )?;
        require_non_empty("view_key_commitment", &self.view_key_commitment)?;
        if self.used_coverage_units > self.coverage_limit_units {
            return Err(format!(
                "guardian {} used coverage exceeds limit",
                self.guardian_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveSnapshot {
    pub snapshot_id: String,
    pub guardian_id: String,
    pub monero_height: u64,
    pub l2_height: u64,
    pub reserve_commitment_root: String,
    pub unlocked_reserve_units: u64,
    pub locked_exit_units: u64,
    pub pending_exit_units: u64,
    pub maker_credit_units: u64,
    pub target_liability_units: u64,
    pub coverage_bps: u64,
    pub privacy_set_size: u64,
    pub approval_id: Option<String>,
    pub expires_at_height: u64,
}

impl ReserveSnapshot {
    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "guardian_id": self.guardian_id,
            "monero_height": self.monero_height,
            "l2_height": self.l2_height,
            "reserve_commitment_root": self.reserve_commitment_root,
            "unlocked_reserve_units": self.unlocked_reserve_units,
            "locked_exit_units": self.locked_exit_units,
            "pending_exit_units": self.pending_exit_units,
            "maker_credit_units": self.maker_credit_units,
            "target_liability_units": self.target_liability_units,
            "coverage_bps": self.coverage_bps,
            "privacy_set_size": self.privacy_set_size,
            "approval_id": self.approval_id,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(
        &self,
        config: &PrivateBridgeLiquiditySafetyCouncilConfig,
    ) -> PrivateBridgeLiquiditySafetyCouncilResult<()> {
        require_non_empty("snapshot_id", &self.snapshot_id)?;
        require_non_empty("guardian_id", &self.guardian_id)?;
        require_non_empty("reserve_commitment_root", &self.reserve_commitment_root)?;
        if self.expires_at_height <= self.l2_height {
            return Err(format!("snapshot {} already expired", self.snapshot_id));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!(
                "snapshot {} privacy set too small",
                self.snapshot_id
            ));
        }
        if self.target_liability_units == 0 {
            return Err(format!("snapshot {} has zero liability", self.snapshot_id));
        }
        let expected = ratio_bps(
            self.unlocked_reserve_units
                .saturating_add(self.maker_credit_units),
            self.target_liability_units,
        );
        if self.coverage_bps != expected {
            return Err(format!("snapshot {} coverage mismatch", self.snapshot_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqQuorumApproval {
    pub approval_id: String,
    pub kind: PqApprovalKind,
    pub status: PqApprovalStatus,
    pub subject_id: String,
    pub payload_root: String,
    pub message_root: String,
    pub signer_ids: BTreeSet<String>,
    pub signer_weight: u64,
    pub rejected_signer_ids: BTreeSet<String>,
    pub rejected_weight: u64,
    pub threshold_weight: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub execution_root: Option<String>,
}

impl PqQuorumApproval {
    pub fn public_record(&self) -> Value {
        json!({
            "approval_id": self.approval_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "message_root": self.message_root,
            "signer_ids": self.signer_ids,
            "signer_weight": self.signer_weight,
            "rejected_signer_ids": self.rejected_signer_ids,
            "rejected_weight": self.rejected_weight,
            "threshold_weight": self.threshold_weight,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "execution_root": self.execution_root,
        })
    }

    pub fn validate(&self) -> PrivateBridgeLiquiditySafetyCouncilResult<()> {
        require_non_empty("approval_id", &self.approval_id)?;
        require_non_empty("subject_id", &self.subject_id)?;
        require_non_empty("payload_root", &self.payload_root)?;
        require_non_empty("message_root", &self.message_root)?;
        if self.threshold_weight == 0 {
            return Err(format!("approval {} has zero threshold", self.approval_id));
        }
        if self.expires_at_height <= self.created_at_height {
            return Err(format!("approval {} expires too early", self.approval_id));
        }
        if self.status.accepted() && self.signer_weight < self.threshold_weight {
            return Err(format!(
                "approval {} accepted below threshold",
                self.approval_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateMakerRiskProfile {
    pub maker_id: String,
    pub label_commitment: String,
    pub status: MakerStatus,
    pub risk_band: MakerRiskBand,
    pub sealed_inventory_root: String,
    pub quote_commitment_root: String,
    pub privacy_pool_root: String,
    pub available_fast_exit_units: u64,
    pub daily_cap_units: u64,
    pub used_daily_cap_units: u64,
    pub max_slippage_bps: u64,
    pub failure_rate_bps: u64,
    pub pq_key_age_blocks: u64,
    pub approval_id: Option<String>,
}

impl PrivateMakerRiskProfile {
    pub fn public_record(&self) -> Value {
        json!({
            "maker_id": self.maker_id,
            "label_commitment": self.label_commitment,
            "status": self.status.as_str(),
            "risk_band": self.risk_band.as_str(),
            "sealed_inventory_root": self.sealed_inventory_root,
            "quote_commitment_root": self.quote_commitment_root,
            "privacy_pool_root": self.privacy_pool_root,
            "available_fast_exit_units": self.available_fast_exit_units,
            "daily_cap_units": self.daily_cap_units,
            "used_daily_cap_units": self.used_daily_cap_units,
            "max_slippage_bps": self.max_slippage_bps,
            "failure_rate_bps": self.failure_rate_bps,
            "pq_key_age_blocks": self.pq_key_age_blocks,
            "approval_id": self.approval_id,
        })
    }

    pub fn validate(
        &self,
        config: &PrivateBridgeLiquiditySafetyCouncilConfig,
    ) -> PrivateBridgeLiquiditySafetyCouncilResult<()> {
        require_non_empty("maker_id", &self.maker_id)?;
        require_non_empty("label_commitment", &self.label_commitment)?;
        require_non_empty("sealed_inventory_root", &self.sealed_inventory_root)?;
        require_non_empty("quote_commitment_root", &self.quote_commitment_root)?;
        if self.used_daily_cap_units > self.daily_cap_units {
            return Err(format!(
                "maker {} used cap exceeds daily cap",
                self.maker_id
            ));
        }
        if self.max_slippage_bps > PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_MAX_BPS {
            return Err(format!("maker {} slippage exceeds max bps", self.maker_id));
        }
        if self.failure_rate_bps > PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_MAX_BPS {
            return Err(format!(
                "maker {} failure rate exceeds max bps",
                self.maker_id
            ));
        }
        if self.status.usable() && self.risk_band.risk_bps() > config.max_maker_risk_bps {
            return Err(format!(
                "maker {} is usable above risk limit",
                self.maker_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyThrottle {
    pub throttle_id: String,
    pub kind: EmergencyThrottleKind,
    pub status: ThrottleStatus,
    pub scope_root: String,
    pub reason_root: String,
    pub flow_reduction_bps: u64,
    pub maker_cap_reduction_bps: u64,
    pub fast_exit_cap_reduction_bps: u64,
    pub reserve_release_delay_blocks: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub approval_id: Option<String>,
}

impl EmergencyThrottle {
    pub fn public_record(&self) -> Value {
        json!({
            "throttle_id": self.throttle_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "scope_root": self.scope_root,
            "reason_root": self.reason_root,
            "flow_reduction_bps": self.flow_reduction_bps,
            "maker_cap_reduction_bps": self.maker_cap_reduction_bps,
            "fast_exit_cap_reduction_bps": self.fast_exit_cap_reduction_bps,
            "reserve_release_delay_blocks": self.reserve_release_delay_blocks,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "approval_id": self.approval_id,
        })
    }

    pub fn validate(&self) -> PrivateBridgeLiquiditySafetyCouncilResult<()> {
        require_non_empty("throttle_id", &self.throttle_id)?;
        require_non_empty("scope_root", &self.scope_root)?;
        require_non_empty("reason_root", &self.reason_root)?;
        validate_bps("flow_reduction_bps", self.flow_reduction_bps)?;
        validate_bps("maker_cap_reduction_bps", self.maker_cap_reduction_bps)?;
        validate_bps(
            "fast_exit_cap_reduction_bps",
            self.fast_exit_cap_reduction_bps,
        )?;
        if self.expires_at_height <= self.created_at_height {
            return Err(format!("throttle {} expires too early", self.throttle_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastExitLiquidityCap {
    pub cap_id: String,
    pub maker_id: String,
    pub status: FastExitCapStatus,
    pub cap_units: u64,
    pub used_units: u64,
    pub per_exit_max_units: u64,
    pub privacy_delay_blocks: u64,
    pub low_fee_lane_bps: u64,
    pub approval_id: Option<String>,
    pub expires_at_height: u64,
}

impl FastExitLiquidityCap {
    pub fn public_record(&self) -> Value {
        json!({
            "cap_id": self.cap_id,
            "maker_id": self.maker_id,
            "status": self.status.as_str(),
            "cap_units": self.cap_units,
            "used_units": self.used_units,
            "per_exit_max_units": self.per_exit_max_units,
            "privacy_delay_blocks": self.privacy_delay_blocks,
            "low_fee_lane_bps": self.low_fee_lane_bps,
            "approval_id": self.approval_id,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(&self) -> PrivateBridgeLiquiditySafetyCouncilResult<()> {
        require_non_empty("cap_id", &self.cap_id)?;
        require_non_empty("maker_id", &self.maker_id)?;
        if self.used_units > self.cap_units {
            return Err(format!("fast exit cap {} overused", self.cap_id));
        }
        if self.per_exit_max_units > self.cap_units {
            return Err(format!(
                "fast exit cap {} per-exit limit exceeds cap",
                self.cap_id
            ));
        }
        validate_bps("low_fee_lane_bps", self.low_fee_lane_bps)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReorgIncident {
    pub incident_id: String,
    pub status: ReorgIncidentStatus,
    pub observed_monero_height: u64,
    pub depth_blocks: u64,
    pub orphaned_tx_root: String,
    pub affected_exit_root: String,
    pub affected_maker_root: String,
    pub estimated_liability_units: u64,
    pub containment_throttle_id: Option<String>,
    pub compensation_action_id: Option<String>,
    pub approval_id: Option<String>,
    pub opened_at_height: u64,
    pub finality_delay_until_height: u64,
}

impl ReorgIncident {
    pub fn public_record(&self) -> Value {
        json!({
            "incident_id": self.incident_id,
            "status": self.status.as_str(),
            "observed_monero_height": self.observed_monero_height,
            "depth_blocks": self.depth_blocks,
            "orphaned_tx_root": self.orphaned_tx_root,
            "affected_exit_root": self.affected_exit_root,
            "affected_maker_root": self.affected_maker_root,
            "estimated_liability_units": self.estimated_liability_units,
            "containment_throttle_id": self.containment_throttle_id,
            "compensation_action_id": self.compensation_action_id,
            "approval_id": self.approval_id,
            "opened_at_height": self.opened_at_height,
            "finality_delay_until_height": self.finality_delay_until_height,
        })
    }

    pub fn validate(&self) -> PrivateBridgeLiquiditySafetyCouncilResult<()> {
        require_non_empty("incident_id", &self.incident_id)?;
        require_non_empty("orphaned_tx_root", &self.orphaned_tx_root)?;
        require_non_empty("affected_exit_root", &self.affected_exit_root)?;
        require_non_empty("affected_maker_root", &self.affected_maker_root)?;
        if self.depth_blocks == 0 {
            return Err(format!(
                "incident {} has zero reorg depth",
                self.incident_id
            ));
        }
        if self.finality_delay_until_height < self.opened_at_height {
            return Err(format!(
                "incident {} finality delay before open height",
                self.incident_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubsidizedSafetyAction {
    pub action_id: String,
    pub kind: SafetyActionKind,
    pub status: SafetyActionStatus,
    pub actor_commitment: String,
    pub subject_id: String,
    pub evidence_root: String,
    pub max_fee_units: u64,
    pub reimbursed_fee_units: u64,
    pub subsidy_bps: u64,
    pub privacy_credit_units: u64,
    pub approval_id: Option<String>,
    pub executed_at_height: Option<u64>,
}

impl SubsidizedSafetyAction {
    pub fn public_record(&self) -> Value {
        json!({
            "action_id": self.action_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "actor_commitment": self.actor_commitment,
            "subject_id": self.subject_id,
            "evidence_root": self.evidence_root,
            "max_fee_units": self.max_fee_units,
            "reimbursed_fee_units": self.reimbursed_fee_units,
            "subsidy_bps": self.subsidy_bps,
            "privacy_credit_units": self.privacy_credit_units,
            "approval_id": self.approval_id,
            "executed_at_height": self.executed_at_height,
        })
    }

    pub fn validate(
        &self,
        config: &PrivateBridgeLiquiditySafetyCouncilConfig,
    ) -> PrivateBridgeLiquiditySafetyCouncilResult<()> {
        require_non_empty("action_id", &self.action_id)?;
        require_non_empty("actor_commitment", &self.actor_commitment)?;
        require_non_empty("subject_id", &self.subject_id)?;
        require_non_empty("evidence_root", &self.evidence_root)?;
        if self.max_fee_units > config.max_sponsor_fee_units {
            return Err(format!("action {} fee cap too high", self.action_id));
        }
        if self.reimbursed_fee_units > self.max_fee_units {
            return Err(format!("action {} over-reimbursed", self.action_id));
        }
        validate_bps("subsidy_bps", self.subsidy_bps)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeRecord {
    pub challenge_id: String,
    pub kind: ChallengeKind,
    pub status: ChallengeStatus,
    pub challenger_commitment: String,
    pub subject_id: String,
    pub evidence_root: String,
    pub private_witness_envelope_root: String,
    pub bond_units: u64,
    pub reward_units: u64,
    pub approval_id: Option<String>,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl ChallengeRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "challenger_commitment": self.challenger_commitment,
            "subject_id": self.subject_id,
            "evidence_root": self.evidence_root,
            "private_witness_envelope_root": self.private_witness_envelope_root,
            "bond_units": self.bond_units,
            "reward_units": self.reward_units,
            "approval_id": self.approval_id,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(&self) -> PrivateBridgeLiquiditySafetyCouncilResult<()> {
        require_non_empty("challenge_id", &self.challenge_id)?;
        require_non_empty("challenger_commitment", &self.challenger_commitment)?;
        require_non_empty("subject_id", &self.subject_id)?;
        require_non_empty("evidence_root", &self.evidence_root)?;
        require_non_empty(
            "private_witness_envelope_root",
            &self.private_witness_envelope_root,
        )?;
        if self.bond_units == 0 {
            return Err(format!("challenge {} has zero bond", self.challenge_id));
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err(format!("challenge {} expires too early", self.challenge_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReport {
    pub report_id: String,
    pub status: SettlementReportStatus,
    pub epoch: u64,
    pub reserve_snapshot_id: String,
    pub settled_exit_root: String,
    pub maker_fill_root: String,
    pub fee_subsidy_root: String,
    pub challenge_root: String,
    pub total_exits_units: u64,
    pub total_fast_exit_units: u64,
    pub total_reimbursed_fee_units: u64,
    pub unresolved_liability_units: u64,
    pub privacy_set_size: u64,
    pub approval_id: Option<String>,
    pub published_at_height: u64,
}

impl SettlementReport {
    pub fn public_record(&self) -> Value {
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "epoch": self.epoch,
            "reserve_snapshot_id": self.reserve_snapshot_id,
            "settled_exit_root": self.settled_exit_root,
            "maker_fill_root": self.maker_fill_root,
            "fee_subsidy_root": self.fee_subsidy_root,
            "challenge_root": self.challenge_root,
            "total_exits_units": self.total_exits_units,
            "total_fast_exit_units": self.total_fast_exit_units,
            "total_reimbursed_fee_units": self.total_reimbursed_fee_units,
            "unresolved_liability_units": self.unresolved_liability_units,
            "privacy_set_size": self.privacy_set_size,
            "approval_id": self.approval_id,
            "published_at_height": self.published_at_height,
        })
    }

    pub fn validate(
        &self,
        config: &PrivateBridgeLiquiditySafetyCouncilConfig,
    ) -> PrivateBridgeLiquiditySafetyCouncilResult<()> {
        require_non_empty("report_id", &self.report_id)?;
        require_non_empty("reserve_snapshot_id", &self.reserve_snapshot_id)?;
        require_non_empty("settled_exit_root", &self.settled_exit_root)?;
        require_non_empty("maker_fill_root", &self.maker_fill_root)?;
        require_non_empty("fee_subsidy_root", &self.fee_subsidy_root)?;
        require_non_empty("challenge_root", &self.challenge_root)?;
        if self.total_fast_exit_units > self.total_exits_units {
            return Err(format!("report {} fast exits exceed exits", self.report_id));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!("report {} privacy set too small", self.report_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyCouncilRoots {
    pub config_root: String,
    pub member_root: String,
    pub guardian_root: String,
    pub reserve_snapshot_root: String,
    pub pq_approval_root: String,
    pub maker_risk_root: String,
    pub emergency_throttle_root: String,
    pub fast_exit_cap_root: String,
    pub reorg_incident_root: String,
    pub safety_action_root: String,
    pub challenge_root: String,
    pub settlement_report_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl SafetyCouncilRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "member_root": self.member_root,
            "guardian_root": self.guardian_root,
            "reserve_snapshot_root": self.reserve_snapshot_root,
            "pq_approval_root": self.pq_approval_root,
            "maker_risk_root": self.maker_risk_root,
            "emergency_throttle_root": self.emergency_throttle_root,
            "fast_exit_cap_root": self.fast_exit_cap_root,
            "reorg_incident_root": self.reorg_incident_root,
            "safety_action_root": self.safety_action_root,
            "challenge_root": self.challenge_root,
            "settlement_report_root": self.settlement_report_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyCouncilCounters {
    pub members: usize,
    pub active_members: usize,
    pub guardians: usize,
    pub active_guardians: usize,
    pub reserve_snapshots: usize,
    pub pq_approvals: usize,
    pub accepted_pq_approvals: usize,
    pub makers: usize,
    pub usable_makers: usize,
    pub active_throttles: usize,
    pub fast_exit_caps: usize,
    pub open_reorg_incidents: usize,
    pub subsidized_actions: usize,
    pub open_challenges: usize,
    pub settlement_reports: usize,
    pub total_quorum_weight: u64,
    pub total_fast_exit_cap_units: u64,
    pub total_available_fast_exit_units: u64,
    pub total_unresolved_liability_units: u64,
}

impl SafetyCouncilCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "members": self.members,
            "active_members": self.active_members,
            "guardians": self.guardians,
            "active_guardians": self.active_guardians,
            "reserve_snapshots": self.reserve_snapshots,
            "pq_approvals": self.pq_approvals,
            "accepted_pq_approvals": self.accepted_pq_approvals,
            "makers": self.makers,
            "usable_makers": self.usable_makers,
            "active_throttles": self.active_throttles,
            "fast_exit_caps": self.fast_exit_caps,
            "open_reorg_incidents": self.open_reorg_incidents,
            "subsidized_actions": self.subsidized_actions,
            "open_challenges": self.open_challenges,
            "settlement_reports": self.settlement_reports,
            "total_quorum_weight": self.total_quorum_weight,
            "total_fast_exit_cap_units": self.total_fast_exit_cap_units,
            "total_available_fast_exit_units": self.total_available_fast_exit_units,
            "total_unresolved_liability_units": self.total_unresolved_liability_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateBridgeLiquiditySafetyCouncilState {
    pub config: PrivateBridgeLiquiditySafetyCouncilConfig,
    pub current_height: u64,
    pub members: BTreeMap<String, CouncilMember>,
    pub guardians: BTreeMap<String, ReserveGuardian>,
    pub reserve_snapshots: BTreeMap<String, ReserveSnapshot>,
    pub pq_approvals: BTreeMap<String, PqQuorumApproval>,
    pub maker_risk_profiles: BTreeMap<String, PrivateMakerRiskProfile>,
    pub emergency_throttles: BTreeMap<String, EmergencyThrottle>,
    pub fast_exit_caps: BTreeMap<String, FastExitLiquidityCap>,
    pub reorg_incidents: BTreeMap<String, ReorgIncident>,
    pub subsidized_actions: BTreeMap<String, SubsidizedSafetyAction>,
    pub challenge_records: BTreeMap<String, ChallengeRecord>,
    pub settlement_reports: BTreeMap<String, SettlementReport>,
    pub public_records: BTreeMap<String, Value>,
}

impl PrivateBridgeLiquiditySafetyCouncilState {
    pub fn new(config: PrivateBridgeLiquiditySafetyCouncilConfig, current_height: u64) -> Self {
        Self {
            config,
            current_height,
            members: BTreeMap::new(),
            guardians: BTreeMap::new(),
            reserve_snapshots: BTreeMap::new(),
            pq_approvals: BTreeMap::new(),
            maker_risk_profiles: BTreeMap::new(),
            emergency_throttles: BTreeMap::new(),
            fast_exit_caps: BTreeMap::new(),
            reorg_incidents: BTreeMap::new(),
            subsidized_actions: BTreeMap::new(),
            challenge_records: BTreeMap::new(),
            settlement_reports: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn set_height(&mut self, height: u64) -> PrivateBridgeLiquiditySafetyCouncilResult<()> {
        if height < self.current_height {
            return Err(format!(
                "private bridge liquidity safety council height cannot move backward from {} to {}",
                self.current_height, height
            ));
        }
        self.current_height = height;
        Ok(())
    }

    pub fn devnet() -> PrivateBridgeLiquiditySafetyCouncilResult<Self> {
        let config = PrivateBridgeLiquiditySafetyCouncilConfig::devnet();
        let mut state = Self::new(
            config.clone(),
            PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_DEVNET_HEIGHT,
        );

        for (index, (label, role, weight)) in [
            (
                "devnet-reserve-guardian-a",
                CouncilMemberRole::ReserveGuardian,
                3,
            ),
            (
                "devnet-reserve-guardian-b",
                CouncilMemberRole::ReserveGuardian,
                3,
            ),
            (
                "devnet-liquidity-risk-signer",
                CouncilMemberRole::LiquidityRiskSigner,
                2,
            ),
            (
                "devnet-reorg-responder",
                CouncilMemberRole::ReorgResponder,
                2,
            ),
            (
                "devnet-fee-sponsor-auditor",
                CouncilMemberRole::FeeSponsorAuditor,
                1,
            ),
            (
                "devnet-emergency-coordinator",
                CouncilMemberRole::EmergencyCoordinator,
                2,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let mut member = CouncilMember::new(label, role, weight, state.current_height - 200)?;
            member.last_seen_height = state.current_height - index as u64;
            state.insert_member(member)?;
        }

        let member_ids = state.members.keys().cloned().collect::<Vec<_>>();
        for (index, member_id) in member_ids.iter().take(4).enumerate() {
            let guardian_id = format!("reserve-guardian-devnet-{index:03}");
            state.insert_guardian(ReserveGuardian {
                guardian_id: guardian_id.clone(),
                member_id: member_id.clone(),
                duty: match index {
                    0 => GuardianDuty::ReserveProof,
                    1 => GuardianDuty::WithdrawalRelease,
                    2 => GuardianDuty::MakerRisk,
                    _ => GuardianDuty::ReorgContainment,
                },
                status: ReserveGuardianStatus::Monitoring,
                reserve_address_commitment: private_bridge_liquidity_safety_council_id(
                    "DEVNET-RESERVE-ADDRESS",
                    &[&guardian_id],
                ),
                view_key_commitment: private_bridge_liquidity_safety_council_id(
                    "DEVNET-VIEW-KEY",
                    &[&guardian_id],
                ),
                spend_key_nullifier_root: private_bridge_liquidity_safety_council_string_root(
                    "DEVNET-SPEND-NULLIFIERS",
                    &guardian_id,
                ),
                watchtower_set_root: private_bridge_liquidity_safety_council_string_root(
                    "DEVNET-WATCHTOWER-SET",
                    &guardian_id,
                ),
                coverage_limit_units: 450_000_000_000 + index as u64 * 50_000_000_000,
                used_coverage_units: 80_000_000_000 + index as u64 * 10_000_000_000,
                last_snapshot_id: None,
                active_throttle_ids: BTreeSet::new(),
            })?;
        }

        let signer_ids = state
            .members
            .values()
            .filter(|member| member.status.voting())
            .take(4)
            .map(|member| member.member_id.clone())
            .collect::<BTreeSet<_>>();
        let signer_weight = state.signer_weight(&signer_ids);

        let snapshot_id = "reserve-snapshot-devnet-000".to_string();
        let snapshot_payload = json!({
            "snapshot_id": snapshot_id,
            "network": config.monero_network,
            "height": state.current_height,
        });
        let snapshot_approval_id = state.create_quorum_approval(
            PqApprovalKind::ReserveSnapshot,
            &snapshot_id,
            &snapshot_payload,
            signer_ids.clone(),
            signer_weight,
        )?;
        state.insert_reserve_snapshot(ReserveSnapshot {
            snapshot_id: snapshot_id.clone(),
            guardian_id: "reserve-guardian-devnet-000".to_string(),
            monero_height: 744,
            l2_height: state.current_height,
            reserve_commitment_root: private_bridge_liquidity_safety_council_value_root(
                "DEVNET-RESERVE-COMMITMENT",
                &snapshot_payload,
            ),
            unlocked_reserve_units: 1_250_000_000_000,
            locked_exit_units: 120_000_000_000,
            pending_exit_units: 50_000_000_000,
            maker_credit_units: 90_000_000_000,
            target_liability_units: 1_200_000_000_000,
            coverage_bps: ratio_bps(1_340_000_000_000, 1_200_000_000_000),
            privacy_set_size: 2_048,
            approval_id: Some(snapshot_approval_id),
            expires_at_height: state.current_height + config.snapshot_ttl_blocks,
        })?;

        for (index, (label, band, status, cap)) in [
            (
                "devnet-maker-prime",
                MakerRiskBand::Prime,
                MakerStatus::Active,
                160_000_000_000,
            ),
            (
                "devnet-maker-standard",
                MakerRiskBand::Standard,
                MakerStatus::Active,
                120_000_000_000,
            ),
            (
                "devnet-maker-caution",
                MakerRiskBand::Caution,
                MakerStatus::Throttled,
                70_000_000_000,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let maker_id = private_bridge_liquidity_safety_council_id("DEVNET-MAKER", &[label]);
            let approval_id = state.create_quorum_approval(
                PqApprovalKind::MakerRiskBand,
                &maker_id,
                &json!({"maker": label, "band": band.as_str()}),
                signer_ids.clone(),
                signer_weight,
            )?;
            state.insert_maker_risk_profile(PrivateMakerRiskProfile {
                maker_id: maker_id.clone(),
                label_commitment: private_bridge_liquidity_safety_council_id(
                    "DEVNET-MAKER-LABEL",
                    &[label],
                ),
                status,
                risk_band: band,
                sealed_inventory_root: private_bridge_liquidity_safety_council_string_root(
                    "DEVNET-MAKER-INVENTORY",
                    label,
                ),
                quote_commitment_root: private_bridge_liquidity_safety_council_string_root(
                    "DEVNET-MAKER-QUOTES",
                    label,
                ),
                privacy_pool_root: private_bridge_liquidity_safety_council_string_root(
                    "DEVNET-MAKER-PRIVACY",
                    label,
                ),
                available_fast_exit_units: cap,
                daily_cap_units: cap + 40_000_000_000,
                used_daily_cap_units: index as u64 * 8_000_000_000,
                max_slippage_bps: 20 + index as u64 * 12,
                failure_rate_bps: 10 + index as u64 * 40,
                pq_key_age_blocks: 300 + index as u64 * 32,
                approval_id: Some(approval_id),
            })?;
            let cap_id = format!("fast-exit-cap-devnet-{index:03}");
            let cap_approval_id = state.create_quorum_approval(
                PqApprovalKind::FastExitCap,
                &cap_id,
                &json!({"maker_id": maker_id, "cap_units": cap}),
                signer_ids.clone(),
                signer_weight,
            )?;
            state.insert_fast_exit_cap(FastExitLiquidityCap {
                cap_id,
                maker_id,
                status: FastExitCapStatus::Active,
                cap_units: cap,
                used_units: index as u64 * 9_000_000_000,
                per_exit_max_units: cap / 8,
                privacy_delay_blocks: 2 + index as u64,
                low_fee_lane_bps: config.default_fast_exit_cap_bps,
                approval_id: Some(cap_approval_id),
                expires_at_height: state.current_height + 240,
            })?;
        }

        let throttle_id = "emergency-throttle-devnet-000".to_string();
        let throttle_approval_id = state.create_quorum_approval(
            PqApprovalKind::EmergencyThrottle,
            &throttle_id,
            &json!({"kind": "reorg_containment", "flow_reduction_bps": 3500}),
            signer_ids.clone(),
            signer_weight,
        )?;
        state.insert_emergency_throttle(EmergencyThrottle {
            throttle_id: throttle_id.clone(),
            kind: EmergencyThrottleKind::ReorgContainment,
            status: ThrottleStatus::Active,
            scope_root: private_bridge_liquidity_safety_council_string_root(
                "DEVNET-THROTTLE-SCOPE",
                "fast-exit-and-maker-release",
            ),
            reason_root: private_bridge_liquidity_safety_council_string_root(
                "DEVNET-THROTTLE-REASON",
                "devnet-reorg-drill",
            ),
            flow_reduction_bps: 3_500,
            maker_cap_reduction_bps: 2_000,
            fast_exit_cap_reduction_bps: 4_000,
            reserve_release_delay_blocks: 6,
            created_at_height: state.current_height,
            expires_at_height: state.current_height + config.throttle_ttl_blocks,
            approval_id: Some(throttle_approval_id),
        })?;

        let incident_id = "reorg-incident-devnet-000".to_string();
        let incident_approval_id = state.create_quorum_approval(
            PqApprovalKind::ReorgIncident,
            &incident_id,
            &json!({"depth": 4, "estimated_liability_units": 35_000_000_000_u64}),
            signer_ids.clone(),
            signer_weight,
        )?;
        state.insert_reorg_incident(ReorgIncident {
            incident_id: incident_id.clone(),
            status: ReorgIncidentStatus::Containing,
            observed_monero_height: 742,
            depth_blocks: 4,
            orphaned_tx_root: private_bridge_liquidity_safety_council_string_root(
                "DEVNET-ORPHANED-TXS",
                &incident_id,
            ),
            affected_exit_root: private_bridge_liquidity_safety_council_string_root(
                "DEVNET-AFFECTED-EXITS",
                &incident_id,
            ),
            affected_maker_root: private_bridge_liquidity_safety_council_string_root(
                "DEVNET-AFFECTED-MAKERS",
                &incident_id,
            ),
            estimated_liability_units: 35_000_000_000,
            containment_throttle_id: Some(throttle_id.clone()),
            compensation_action_id: Some("safety-action-devnet-000".to_string()),
            approval_id: Some(incident_approval_id),
            opened_at_height: state.current_height,
            finality_delay_until_height: state.current_height + config.reorg_finality_delay_blocks,
        })?;

        let action_id = "safety-action-devnet-000".to_string();
        let action_approval_id = state.create_quorum_approval(
            PqApprovalKind::SubsidizedSafetyAction,
            &action_id,
            &json!({"kind": "reorg_compensation", "incident_id": incident_id}),
            signer_ids.clone(),
            signer_weight,
        )?;
        state.insert_subsidized_action(SubsidizedSafetyAction {
            action_id: action_id.clone(),
            kind: SafetyActionKind::ReorgCompensation,
            status: SafetyActionStatus::Subsidized,
            actor_commitment: private_bridge_liquidity_safety_council_id(
                "DEVNET-ACTION-ACTOR",
                &["devnet-reorg-responder"],
            ),
            subject_id: incident_id.clone(),
            evidence_root: private_bridge_liquidity_safety_council_string_root(
                "DEVNET-ACTION-EVIDENCE",
                &action_id,
            ),
            max_fee_units: 8_500,
            reimbursed_fee_units: 6_400,
            subsidy_bps: config.low_fee_subsidy_bps,
            privacy_credit_units: 128,
            approval_id: Some(action_approval_id),
            executed_at_height: Some(state.current_height + 1),
        })?;

        let challenge_id = "challenge-devnet-000".to_string();
        let challenge_approval_id = state.create_quorum_approval(
            PqApprovalKind::ChallengeResolution,
            &challenge_id,
            &json!({"kind": "settlement_delay", "accepted": true}),
            signer_ids.clone(),
            signer_weight,
        )?;
        state.insert_challenge_record(ChallengeRecord {
            challenge_id: challenge_id.clone(),
            kind: ChallengeKind::SettlementDelay,
            status: ChallengeStatus::CouncilAccepted,
            challenger_commitment: private_bridge_liquidity_safety_council_id(
                "DEVNET-CHALLENGER",
                &["privacy-preserving-watchtower"],
            ),
            subject_id: action_id.clone(),
            evidence_root: private_bridge_liquidity_safety_council_string_root(
                "DEVNET-CHALLENGE-EVIDENCE",
                &challenge_id,
            ),
            private_witness_envelope_root: private_bridge_liquidity_safety_council_string_root(
                "DEVNET-CHALLENGE-WITNESS",
                &challenge_id,
            ),
            bond_units: 20_000,
            reward_units: 7_500,
            approval_id: Some(challenge_approval_id),
            opened_at_height: state.current_height - 2,
            expires_at_height: state.current_height + config.challenge_window_blocks,
        })?;

        let report_id = "settlement-report-devnet-000".to_string();
        let report_approval_id = state.create_quorum_approval(
            PqApprovalKind::SettlementReport,
            &report_id,
            &json!({"epoch": 7, "snapshot_id": snapshot_id}),
            signer_ids,
            signer_weight,
        )?;
        state.insert_settlement_report(SettlementReport {
            report_id,
            status: SettlementReportStatus::PqApproved,
            epoch: 7,
            reserve_snapshot_id: snapshot_id,
            settled_exit_root: private_bridge_liquidity_safety_council_string_root(
                "DEVNET-SETTLED-EXITS",
                "epoch-7",
            ),
            maker_fill_root: private_bridge_liquidity_safety_council_string_root(
                "DEVNET-MAKER-FILLS",
                "epoch-7",
            ),
            fee_subsidy_root: private_bridge_liquidity_safety_council_string_root(
                "DEVNET-FEE-SUBSIDIES",
                "epoch-7",
            ),
            challenge_root: private_bridge_liquidity_safety_council_string_root(
                "DEVNET-REPORT-CHALLENGES",
                "epoch-7",
            ),
            total_exits_units: 210_000_000_000,
            total_fast_exit_units: 96_000_000_000,
            total_reimbursed_fee_units: 6_400,
            unresolved_liability_units: 15_000_000_000,
            privacy_set_size: 2_048,
            approval_id: Some(report_approval_id),
            published_at_height: state.current_height + 3,
        })?;

        state.refresh_public_records();
        state.validate()?;
        Ok(state)
    }

    pub fn insert_member(
        &mut self,
        member: CouncilMember,
    ) -> PrivateBridgeLiquiditySafetyCouncilResult<String> {
        member.validate()?;
        let member_id = member.member_id.clone();
        self.members.insert(member_id.clone(), member);
        self.refresh_public_records();
        Ok(member_id)
    }

    pub fn insert_guardian(
        &mut self,
        guardian: ReserveGuardian,
    ) -> PrivateBridgeLiquiditySafetyCouncilResult<String> {
        guardian.validate()?;
        if !self.members.contains_key(&guardian.member_id) {
            return Err(format!(
                "guardian {} has unknown member",
                guardian.guardian_id
            ));
        }
        let guardian_id = guardian.guardian_id.clone();
        self.guardians.insert(guardian_id.clone(), guardian);
        self.refresh_public_records();
        Ok(guardian_id)
    }

    pub fn insert_reserve_snapshot(
        &mut self,
        snapshot: ReserveSnapshot,
    ) -> PrivateBridgeLiquiditySafetyCouncilResult<String> {
        snapshot.validate(&self.config)?;
        if !self.guardians.contains_key(&snapshot.guardian_id) {
            return Err(format!(
                "snapshot {} has unknown guardian",
                snapshot.snapshot_id
            ));
        }
        if let Some(approval_id) = &snapshot.approval_id {
            self.require_accepted_approval(approval_id, PqApprovalKind::ReserveSnapshot)?;
        }
        let snapshot_id = snapshot.snapshot_id.clone();
        if let Some(guardian) = self.guardians.get_mut(&snapshot.guardian_id) {
            guardian.last_snapshot_id = Some(snapshot_id.clone());
        }
        self.reserve_snapshots.insert(snapshot_id.clone(), snapshot);
        self.refresh_public_records();
        Ok(snapshot_id)
    }

    pub fn insert_maker_risk_profile(
        &mut self,
        profile: PrivateMakerRiskProfile,
    ) -> PrivateBridgeLiquiditySafetyCouncilResult<String> {
        profile.validate(&self.config)?;
        if let Some(approval_id) = &profile.approval_id {
            self.require_accepted_approval(approval_id, PqApprovalKind::MakerRiskBand)?;
        }
        let maker_id = profile.maker_id.clone();
        self.maker_risk_profiles.insert(maker_id.clone(), profile);
        self.refresh_public_records();
        Ok(maker_id)
    }

    pub fn insert_emergency_throttle(
        &mut self,
        throttle: EmergencyThrottle,
    ) -> PrivateBridgeLiquiditySafetyCouncilResult<String> {
        throttle.validate()?;
        if let Some(approval_id) = &throttle.approval_id {
            self.require_accepted_approval(approval_id, PqApprovalKind::EmergencyThrottle)?;
        }
        let throttle_id = throttle.throttle_id.clone();
        if throttle.status.limits_flow() {
            for guardian in self.guardians.values_mut() {
                guardian.active_throttle_ids.insert(throttle_id.clone());
            }
        }
        self.emergency_throttles
            .insert(throttle_id.clone(), throttle);
        self.refresh_public_records();
        Ok(throttle_id)
    }

    pub fn insert_fast_exit_cap(
        &mut self,
        cap: FastExitLiquidityCap,
    ) -> PrivateBridgeLiquiditySafetyCouncilResult<String> {
        cap.validate()?;
        if !self.maker_risk_profiles.contains_key(&cap.maker_id) {
            return Err(format!("fast exit cap {} unknown maker", cap.cap_id));
        }
        if let Some(profile) = self.maker_risk_profiles.get(&cap.maker_id) {
            if cap.status.available() && !profile.risk_band.allows_fast_exit() {
                return Err(format!(
                    "fast exit cap {} assigned to ineligible risk band",
                    cap.cap_id
                ));
            }
        }
        if let Some(approval_id) = &cap.approval_id {
            self.require_accepted_approval(approval_id, PqApprovalKind::FastExitCap)?;
        }
        let cap_id = cap.cap_id.clone();
        self.fast_exit_caps.insert(cap_id.clone(), cap);
        self.refresh_public_records();
        Ok(cap_id)
    }

    pub fn insert_reorg_incident(
        &mut self,
        incident: ReorgIncident,
    ) -> PrivateBridgeLiquiditySafetyCouncilResult<String> {
        incident.validate()?;
        if let Some(approval_id) = &incident.approval_id {
            self.require_accepted_approval(approval_id, PqApprovalKind::ReorgIncident)?;
        }
        if let Some(throttle_id) = &incident.containment_throttle_id {
            if !self.emergency_throttles.contains_key(throttle_id) {
                return Err(format!(
                    "incident {} unknown containment throttle",
                    incident.incident_id
                ));
            }
        }
        let incident_id = incident.incident_id.clone();
        self.reorg_incidents.insert(incident_id.clone(), incident);
        self.refresh_public_records();
        Ok(incident_id)
    }

    pub fn insert_subsidized_action(
        &mut self,
        action: SubsidizedSafetyAction,
    ) -> PrivateBridgeLiquiditySafetyCouncilResult<String> {
        action.validate(&self.config)?;
        if let Some(approval_id) = &action.approval_id {
            self.require_accepted_approval(approval_id, PqApprovalKind::SubsidizedSafetyAction)?;
        }
        let action_id = action.action_id.clone();
        self.subsidized_actions.insert(action_id.clone(), action);
        self.refresh_public_records();
        Ok(action_id)
    }

    pub fn insert_challenge_record(
        &mut self,
        challenge: ChallengeRecord,
    ) -> PrivateBridgeLiquiditySafetyCouncilResult<String> {
        challenge.validate()?;
        if let Some(approval_id) = &challenge.approval_id {
            self.require_accepted_approval(approval_id, PqApprovalKind::ChallengeResolution)?;
        }
        let challenge_id = challenge.challenge_id.clone();
        self.challenge_records
            .insert(challenge_id.clone(), challenge);
        self.refresh_public_records();
        Ok(challenge_id)
    }

    pub fn insert_settlement_report(
        &mut self,
        report: SettlementReport,
    ) -> PrivateBridgeLiquiditySafetyCouncilResult<String> {
        report.validate(&self.config)?;
        if !self
            .reserve_snapshots
            .contains_key(&report.reserve_snapshot_id)
        {
            return Err(format!(
                "report {} unknown reserve snapshot",
                report.report_id
            ));
        }
        if let Some(approval_id) = &report.approval_id {
            self.require_accepted_approval(approval_id, PqApprovalKind::SettlementReport)?;
        }
        let report_id = report.report_id.clone();
        self.settlement_reports.insert(report_id.clone(), report);
        self.refresh_public_records();
        Ok(report_id)
    }

    pub fn create_quorum_approval(
        &mut self,
        kind: PqApprovalKind,
        subject_id: &str,
        payload: &Value,
        signer_ids: BTreeSet<String>,
        signer_weight: u64,
    ) -> PrivateBridgeLiquiditySafetyCouncilResult<String> {
        require_non_empty("subject_id", subject_id)?;
        let threshold_weight = if kind.requires_supermajority() {
            self.config.supermajority_weight
        } else {
            self.config.quorum_weight
        };
        let status = if signer_weight >= self.config.supermajority_weight {
            PqApprovalStatus::SupermajorityMet
        } else if signer_weight >= threshold_weight {
            PqApprovalStatus::QuorumMet
        } else {
            PqApprovalStatus::Collecting
        };
        let payload_root = private_bridge_liquidity_safety_council_value_root(
            "SAFETY-COUNCIL-APPROVAL-PAYLOAD",
            payload,
        );
        let approval_id = private_bridge_liquidity_safety_council_id(
            "PQ-APPROVAL",
            &[
                kind.as_str(),
                subject_id,
                &payload_root,
                &self.current_height.to_string(),
            ],
        );
        let message_root = private_bridge_liquidity_safety_council_value_root(
            "SAFETY-COUNCIL-APPROVAL-MESSAGE",
            &json!({
                "kind": kind.as_str(),
                "subject_id": subject_id,
                "payload_root": payload_root,
                "threshold_weight": threshold_weight,
            }),
        );
        let approval = PqQuorumApproval {
            approval_id: approval_id.clone(),
            kind,
            status,
            subject_id: subject_id.to_string(),
            payload_root,
            message_root,
            signer_ids,
            signer_weight,
            rejected_signer_ids: BTreeSet::new(),
            rejected_weight: 0,
            threshold_weight,
            created_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.approval_ttl_blocks,
            execution_root: None,
        };
        approval.validate()?;
        self.pq_approvals.insert(approval_id.clone(), approval);
        self.refresh_public_records();
        Ok(approval_id)
    }

    pub fn signer_weight(&self, signer_ids: &BTreeSet<String>) -> u64 {
        signer_ids
            .iter()
            .filter_map(|id| self.members.get(id))
            .filter(|member| member.status.voting())
            .map(|member| member.weight)
            .sum()
    }

    pub fn require_accepted_approval(
        &self,
        approval_id: &str,
        expected_kind: PqApprovalKind,
    ) -> PrivateBridgeLiquiditySafetyCouncilResult<()> {
        let approval = self
            .pq_approvals
            .get(approval_id)
            .ok_or_else(|| format!("unknown approval {approval_id}"))?;
        if approval.kind != expected_kind {
            return Err(format!("approval {approval_id} has unexpected kind"));
        }
        if !approval.status.accepted() {
            return Err(format!("approval {approval_id} is not accepted"));
        }
        Ok(())
    }

    pub fn active_throttle_bps(&self) -> u64 {
        match self
            .emergency_throttles
            .values()
            .filter(|throttle| throttle.status.limits_flow())
            .map(|throttle| throttle.flow_reduction_bps)
            .max()
        {
            Some(value) => value,
            None => 0,
        }
    }

    pub fn effective_fast_exit_capacity_units(&self) -> u64 {
        let throttle_bps = self.active_throttle_bps();
        self.fast_exit_caps
            .values()
            .filter(|cap| cap.status.available())
            .map(|cap| {
                cap.cap_units.saturating_sub(cap.used_units).saturating_mul(
                    PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_MAX_BPS.saturating_sub(throttle_bps),
                ) / PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_MAX_BPS
            })
            .sum()
    }

    pub fn counters(&self) -> SafetyCouncilCounters {
        SafetyCouncilCounters {
            members: self.members.len(),
            active_members: self
                .members
                .values()
                .filter(|member| member.status.voting())
                .count(),
            guardians: self.guardians.len(),
            active_guardians: self
                .guardians
                .values()
                .filter(|guardian| guardian.status.can_guard())
                .count(),
            reserve_snapshots: self.reserve_snapshots.len(),
            pq_approvals: self.pq_approvals.len(),
            accepted_pq_approvals: self
                .pq_approvals
                .values()
                .filter(|approval| approval.status.accepted())
                .count(),
            makers: self.maker_risk_profiles.len(),
            usable_makers: self
                .maker_risk_profiles
                .values()
                .filter(|profile| profile.status.usable())
                .count(),
            active_throttles: self
                .emergency_throttles
                .values()
                .filter(|throttle| throttle.status.limits_flow())
                .count(),
            fast_exit_caps: self.fast_exit_caps.len(),
            open_reorg_incidents: self
                .reorg_incidents
                .values()
                .filter(|incident| incident.status.open())
                .count(),
            subsidized_actions: self
                .subsidized_actions
                .values()
                .filter(|action| {
                    matches!(
                        action.status,
                        SafetyActionStatus::Subsidized | SafetyActionStatus::Executed
                    )
                })
                .count(),
            open_challenges: self
                .challenge_records
                .values()
                .filter(|challenge| challenge.status.open())
                .count(),
            settlement_reports: self.settlement_reports.len(),
            total_quorum_weight: self
                .members
                .values()
                .filter(|member| member.status.voting())
                .map(|member| member.weight)
                .sum(),
            total_fast_exit_cap_units: self.fast_exit_caps.values().map(|cap| cap.cap_units).sum(),
            total_available_fast_exit_units: self.effective_fast_exit_capacity_units(),
            total_unresolved_liability_units: self
                .settlement_reports
                .values()
                .map(|report| report.unresolved_liability_units)
                .sum(),
        }
    }

    pub fn public_record_root(&self) -> String {
        private_bridge_liquidity_safety_council_root_from_map(
            "SAFETY-COUNCIL-PUBLIC-RECORD",
            &self.public_records,
        )
    }

    pub fn roots(&self) -> SafetyCouncilRoots {
        let config_root = private_bridge_liquidity_safety_council_value_root(
            "SAFETY-COUNCIL-CONFIG",
            &self.config.public_record(),
        );
        let member_root = private_bridge_liquidity_safety_council_root_from_map_records(
            "SAFETY-COUNCIL-MEMBERS",
            self.members.values().map(CouncilMember::public_record),
        );
        let guardian_root = private_bridge_liquidity_safety_council_root_from_map_records(
            "SAFETY-COUNCIL-GUARDIANS",
            self.guardians.values().map(ReserveGuardian::public_record),
        );
        let reserve_snapshot_root = private_bridge_liquidity_safety_council_root_from_map_records(
            "SAFETY-COUNCIL-RESERVE-SNAPSHOTS",
            self.reserve_snapshots
                .values()
                .map(ReserveSnapshot::public_record),
        );
        let pq_approval_root = private_bridge_liquidity_safety_council_root_from_map_records(
            "SAFETY-COUNCIL-PQ-APPROVALS",
            self.pq_approvals
                .values()
                .map(PqQuorumApproval::public_record),
        );
        let maker_risk_root = private_bridge_liquidity_safety_council_root_from_map_records(
            "SAFETY-COUNCIL-MAKER-RISK",
            self.maker_risk_profiles
                .values()
                .map(PrivateMakerRiskProfile::public_record),
        );
        let emergency_throttle_root = private_bridge_liquidity_safety_council_root_from_map_records(
            "SAFETY-COUNCIL-EMERGENCY-THROTTLES",
            self.emergency_throttles
                .values()
                .map(EmergencyThrottle::public_record),
        );
        let fast_exit_cap_root = private_bridge_liquidity_safety_council_root_from_map_records(
            "SAFETY-COUNCIL-FAST-EXIT-CAPS",
            self.fast_exit_caps
                .values()
                .map(FastExitLiquidityCap::public_record),
        );
        let reorg_incident_root = private_bridge_liquidity_safety_council_root_from_map_records(
            "SAFETY-COUNCIL-REORG-INCIDENTS",
            self.reorg_incidents
                .values()
                .map(ReorgIncident::public_record),
        );
        let safety_action_root = private_bridge_liquidity_safety_council_root_from_map_records(
            "SAFETY-COUNCIL-SAFETY-ACTIONS",
            self.subsidized_actions
                .values()
                .map(SubsidizedSafetyAction::public_record),
        );
        let challenge_root = private_bridge_liquidity_safety_council_root_from_map_records(
            "SAFETY-COUNCIL-CHALLENGES",
            self.challenge_records
                .values()
                .map(ChallengeRecord::public_record),
        );
        let settlement_report_root = private_bridge_liquidity_safety_council_root_from_map_records(
            "SAFETY-COUNCIL-SETTLEMENT-REPORTS",
            self.settlement_reports
                .values()
                .map(SettlementReport::public_record),
        );
        let public_record_root = self.public_record_root();
        let state_root = private_bridge_liquidity_safety_council_state_root_from_parts(&[
            &config_root,
            &member_root,
            &guardian_root,
            &reserve_snapshot_root,
            &pq_approval_root,
            &maker_risk_root,
            &emergency_throttle_root,
            &fast_exit_cap_root,
            &reorg_incident_root,
            &safety_action_root,
            &challenge_root,
            &settlement_report_root,
            &public_record_root,
        ]);
        SafetyCouncilRoots {
            config_root,
            member_root,
            guardian_root,
            reserve_snapshot_root,
            pq_approval_root,
            maker_risk_root,
            emergency_throttle_root,
            fast_exit_cap_root,
            reorg_incident_root,
            safety_action_root,
            challenge_root,
            settlement_report_root,
            public_record_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "schema": PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_PUBLIC_RECORD_SCHEMA,
            "config": self.config.public_record(),
            "current_height": self.current_height,
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn refresh_public_records(&mut self) {
        let mut records = BTreeMap::new();
        for (id, record) in &self.members {
            records.insert(format!("member:{id}"), record.public_record());
        }
        for (id, record) in &self.guardians {
            records.insert(format!("guardian:{id}"), record.public_record());
        }
        for (id, record) in &self.reserve_snapshots {
            records.insert(format!("reserve_snapshot:{id}"), record.public_record());
        }
        for (id, record) in &self.pq_approvals {
            records.insert(format!("pq_approval:{id}"), record.public_record());
        }
        for (id, record) in &self.maker_risk_profiles {
            records.insert(format!("maker_risk:{id}"), record.public_record());
        }
        for (id, record) in &self.emergency_throttles {
            records.insert(format!("emergency_throttle:{id}"), record.public_record());
        }
        for (id, record) in &self.fast_exit_caps {
            records.insert(format!("fast_exit_cap:{id}"), record.public_record());
        }
        for (id, record) in &self.reorg_incidents {
            records.insert(format!("reorg_incident:{id}"), record.public_record());
        }
        for (id, record) in &self.subsidized_actions {
            records.insert(format!("safety_action:{id}"), record.public_record());
        }
        for (id, record) in &self.challenge_records {
            records.insert(format!("challenge:{id}"), record.public_record());
        }
        for (id, record) in &self.settlement_reports {
            records.insert(format!("settlement_report:{id}"), record.public_record());
        }
        self.public_records = records;
    }

    pub fn validate(&self) -> PrivateBridgeLiquiditySafetyCouncilResult<String> {
        self.config.validate()?;
        for member in self.members.values() {
            member.validate()?;
        }
        for guardian in self.guardians.values() {
            guardian.validate()?;
            if !self.members.contains_key(&guardian.member_id) {
                return Err(format!("guardian {} unknown member", guardian.guardian_id));
            }
        }
        for approval in self.pq_approvals.values() {
            approval.validate()?;
            let computed_weight = self.signer_weight(&approval.signer_ids);
            if computed_weight != approval.signer_weight {
                return Err(format!(
                    "approval {} signer weight mismatch",
                    approval.approval_id
                ));
            }
        }
        for snapshot in self.reserve_snapshots.values() {
            snapshot.validate(&self.config)?;
            if !self.guardians.contains_key(&snapshot.guardian_id) {
                return Err(format!(
                    "snapshot {} unknown guardian",
                    snapshot.snapshot_id
                ));
            }
        }
        for profile in self.maker_risk_profiles.values() {
            profile.validate(&self.config)?;
        }
        for throttle in self.emergency_throttles.values() {
            throttle.validate()?;
        }
        for cap in self.fast_exit_caps.values() {
            cap.validate()?;
            if !self.maker_risk_profiles.contains_key(&cap.maker_id) {
                return Err(format!("cap {} unknown maker", cap.cap_id));
            }
        }
        for incident in self.reorg_incidents.values() {
            incident.validate()?;
        }
        for action in self.subsidized_actions.values() {
            action.validate(&self.config)?;
        }
        for challenge in self.challenge_records.values() {
            challenge.validate()?;
        }
        for report in self.settlement_reports.values() {
            report.validate(&self.config)?;
            if !self
                .reserve_snapshots
                .contains_key(&report.reserve_snapshot_id)
            {
                return Err(format!("report {} unknown snapshot", report.report_id));
            }
        }
        let counters = self.counters();
        if counters.total_quorum_weight < self.config.quorum_weight {
            return Err("active quorum weight below config threshold".to_string());
        }
        Ok(self.state_root())
    }
}

pub fn private_bridge_liquidity_safety_council_id(domain: &str, parts: &[&str]) -> String {
    let hash_parts = parts
        .iter()
        .map(|part| HashPart::Str(part))
        .collect::<Vec<_>>();
    domain_hash(
        &format!("PRIVATE-BRIDGE-LIQUIDITY-SAFETY-COUNCIL-{domain}"),
        &hash_parts,
        32,
    )
}

pub fn private_bridge_liquidity_safety_council_value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-BRIDGE-LIQUIDITY-SAFETY-COUNCIL-{domain}"),
        &[HashPart::Json(value)],
        32,
    )
}

pub fn private_bridge_liquidity_safety_council_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        &format!("PRIVATE-BRIDGE-LIQUIDITY-SAFETY-COUNCIL-{domain}"),
        &[HashPart::Str(value)],
        32,
    )
}

pub fn private_bridge_liquidity_safety_council_state_root_from_record(record: &Value) -> String {
    private_bridge_liquidity_safety_council_value_root("STATE-ROOT-FROM-RECORD", record)
}

pub fn private_bridge_liquidity_safety_council_state_root_from_parts(parts: &[&str]) -> String {
    let hash_parts = parts
        .iter()
        .map(|part| HashPart::Str(part))
        .collect::<Vec<_>>();
    domain_hash(
        "PRIVATE-BRIDGE-LIQUIDITY-SAFETY-COUNCIL-STATE-ROOT",
        &hash_parts,
        32,
    )
}

pub fn private_bridge_liquidity_safety_council_root_from_map(
    domain: &str,
    records: &BTreeMap<String, Value>,
) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| json!({"key": key, "value": value}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-BRIDGE-LIQUIDITY-SAFETY-COUNCIL-{domain}"),
        &leaves,
    )
}

pub fn private_bridge_liquidity_safety_council_root_from_map_records<I>(
    domain: &str,
    records: I,
) -> String
where
    I: IntoIterator<Item = Value>,
{
    let leaves = records.into_iter().collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-BRIDGE-LIQUIDITY-SAFETY-COUNCIL-{domain}"),
        &leaves,
    )
}

fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator.saturating_mul(PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_MAX_BPS) / denominator
}

fn validate_bps(name: &str, value: u64) -> PrivateBridgeLiquiditySafetyCouncilResult<()> {
    if value > PRIVATE_BRIDGE_LIQUIDITY_SAFETY_COUNCIL_MAX_BPS {
        return Err(format!("{name} exceeds max bps"));
    }
    Ok(())
}

fn require_non_empty(name: &str, value: &str) -> PrivateBridgeLiquiditySafetyCouncilResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{name} must be non-empty"));
    }
    Ok(())
}
