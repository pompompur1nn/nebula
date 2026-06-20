use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateLiquidityInsuranceUnderwriterResult<T> = Result<T, String>;

pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_PROTOCOL_VERSION: u32 = 1;
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_PROTOCOL_ID: &str =
    "nebula-private-liquidity-insurance-underwriter-v1";
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEVNET_HEIGHT: u64 = 1_344;
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_PQ_BACKUP_SCHEME: &str = "SLH-DSA-SHAKE-256f";
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_PQ_KEM_SCHEME: &str = "ML-KEM-1024";
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_VAULT_SEALING_SCHEME: &str =
    "ml-kem-1024+xchacha20poly1305-confidential-underwriter-vault-v1";
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_POLICY_ENVELOPE_SCHEME: &str =
    "private-bridge-defi-policy-envelope-v1";
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_RISK_ATTESTATION_SCHEME: &str =
    "pq-sealed-liquidity-risk-attestation-v1";
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_CLAIM_PROOF_SCHEME: &str =
    "private-claim-loss-proof-envelope-v1";
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_PAYOUT_THROTTLE_SCHEME: &str =
    "deterministic-confidential-payout-throttle-v1";
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_REBATE_SCHEME: &str =
    "low-fee-premium-rebate-credit-v1";
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_CHALLENGE_SCHEME: &str =
    "pq-claims-committee-challenge-slashing-evidence-v1";
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_FEE_ASSET_ID: &str = "asset:dxmr";
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MONERO_NETWORK: &str = "monero-devnet";
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS: u64 = 10_000;
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_PRICE_SCALE: u64 = 1_000_000_000_000;
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_POLICY_TTL_BLOCKS: u64 = 21_600;
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 72;
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_CLAIM_CHALLENGE_BLOCKS: u64 = 96;
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_PAYOUT_WINDOW_BLOCKS: u64 = 144;
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_REBATE_WINDOW_BLOCKS: u64 = 720;
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 1_024;
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_COMMITTEE_QUORUM_BPS: u64 = 6_700;
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_SUPERMAJORITY_BPS: u64 = 7_500;
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_MAX_POLICY_EXPOSURE_BPS: u64 = 1_500;
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_MAX_VAULT_UTILIZATION_BPS: u64 = 6_500;
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_MIN_SOLVENCY_BPS: u64 = 11_500;
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_MAX_DAILY_PAYOUT_BPS: u64 = 750;
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 450;
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_CLAIM_SLASH_BPS: u64 = 2_000;
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_REPORTER_REWARD_BPS: u64 = 1_000;
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_VAULTS: usize = 16_384;
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_POLICIES: usize = 262_144;
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_ATTESTATIONS: usize = 524_288;
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_CLAIMS: usize = 262_144;
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_PAYOUTS: usize = 262_144;
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_REBATES: usize = 262_144;
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_COMMITTEE_MEMBERS: usize = 16_384;
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_CHALLENGES: usize = 131_072;
pub const PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_EVENTS: usize = 524_288;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoveredDomain {
    MoneroBridge,
    PrivateDex,
    LendingMarket,
    StablecoinPeg,
    PerpClearing,
    TokenizedVault,
    CrossRollupBridge,
    ProofFeeMarket,
    SequencerFastLane,
    DataAvailability,
}

impl CoveredDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroBridge => "monero_bridge",
            Self::PrivateDex => "private_dex",
            Self::LendingMarket => "lending_market",
            Self::StablecoinPeg => "stablecoin_peg",
            Self::PerpClearing => "perp_clearing",
            Self::TokenizedVault => "tokenized_vault",
            Self::CrossRollupBridge => "cross_rollup_bridge",
            Self::ProofFeeMarket => "proof_fee_market",
            Self::SequencerFastLane => "sequencer_fast_lane",
            Self::DataAvailability => "data_availability",
        }
    }

    pub fn base_risk_bps(self) -> u64 {
        match self {
            Self::MoneroBridge => 3_200,
            Self::PrivateDex => 4_100,
            Self::LendingMarket => 3_700,
            Self::StablecoinPeg => 2_900,
            Self::PerpClearing => 5_400,
            Self::TokenizedVault => 3_400,
            Self::CrossRollupBridge => 4_800,
            Self::ProofFeeMarket => 2_500,
            Self::SequencerFastLane => 2_800,
            Self::DataAvailability => 3_100,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnderwriterVaultStatus {
    Bootstrapping,
    Active,
    ExposureCapped,
    PayoutOnly,
    Frozen,
    Slashed,
    Retired,
}

impl UnderwriterVaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrapping => "bootstrapping",
            Self::Active => "active",
            Self::ExposureCapped => "exposure_capped",
            Self::PayoutOnly => "payout_only",
            Self::Frozen => "frozen",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn can_underwrite(self) -> bool {
        matches!(
            self,
            Self::Bootstrapping | Self::Active | Self::ExposureCapped
        )
    }

    pub fn can_pay_claims(self) -> bool {
        matches!(self, Self::Active | Self::ExposureCapped | Self::PayoutOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEnvelopeStatus {
    Quoted,
    Active,
    GracePeriod,
    ClaimPending,
    Settled,
    Expired,
    Cancelled,
    Challenged,
}

impl PolicyEnvelopeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quoted => "quoted",
            Self::Active => "active",
            Self::GracePeriod => "grace_period",
            Self::ClaimPending => "claim_pending",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Challenged => "challenged",
        }
    }

    pub fn accepts_claims(self) -> bool {
        matches!(self, Self::Active | Self::GracePeriod | Self::ClaimPending)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskAttestationStatus {
    Submitted,
    RangeChecked,
    Counted,
    Superseded,
    Rejected,
    Expired,
    Challenged,
}

impl RiskAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::RangeChecked => "range_checked",
            Self::Counted => "counted",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Queued,
    CommitteeReview,
    Challenged,
    Approved,
    PayoutScheduled,
    Paid,
    Rejected,
    Expired,
}

impl ClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::CommitteeReview => "committee_review",
            Self::Challenged => "challenged",
            Self::Approved => "approved",
            Self::PayoutScheduled => "payout_scheduled",
            Self::Paid => "paid",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn open(self) -> bool {
        matches!(
            self,
            Self::Queued
                | Self::CommitteeReview
                | Self::Challenged
                | Self::Approved
                | Self::PayoutScheduled
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayoutStatus {
    Scheduled,
    Throttled,
    Released,
    Deferred,
    Cancelled,
}

impl PayoutStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Throttled => "throttled",
            Self::Released => "released",
            Self::Deferred => "deferred",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accrued,
    Claimable,
    Credited,
    Expired,
    Revoked,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accrued => "accrued",
            Self::Claimable => "claimable",
            Self::Credited => "credited",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimsCommitteeRole {
    ClaimReviewer,
    RiskAttester,
    PayoutSigner,
    ChallengeJudge,
    SlashingWatcher,
    RebateAuditor,
}

impl ClaimsCommitteeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClaimReviewer => "claim_reviewer",
            Self::RiskAttester => "risk_attester",
            Self::PayoutSigner => "payout_signer",
            Self::ChallengeJudge => "challenge_judge",
            Self::SlashingWatcher => "slashing_watcher",
            Self::RebateAuditor => "rebate_auditor",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeMemberStatus {
    Active,
    Suspended,
    RotatingOut,
    Slashed,
    Retired,
}

impl CommitteeMemberStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::RotatingOut => "rotating_out",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn voting(self) -> bool {
        matches!(self, Self::Active | Self::RotatingOut)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Filed,
    EvidenceAccepted,
    CommitteeReview,
    Sustained,
    Dismissed,
    Slashed,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Filed => "filed",
            Self::EvidenceAccepted => "evidence_accepted",
            Self::CommitteeReview => "committee_review",
            Self::Sustained => "sustained",
            Self::Dismissed => "dismissed",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultSolvencyDimension {
    CommittedCapital,
    EncryptedBalance,
    ClaimReserve,
    PremiumFloat,
    RebateLiability,
    BridgeExposure,
    DefiExposure,
    ColdReserve,
    HotReserve,
    EmergencyBuffer,
}

impl VaultSolvencyDimension {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CommittedCapital => "committed_capital",
            Self::EncryptedBalance => "encrypted_balance",
            Self::ClaimReserve => "claim_reserve",
            Self::PremiumFloat => "premium_float",
            Self::RebateLiability => "rebate_liability",
            Self::BridgeExposure => "bridge_exposure",
            Self::DefiExposure => "defi_exposure",
            Self::ColdReserve => "cold_reserve",
            Self::HotReserve => "hot_reserve",
            Self::EmergencyBuffer => "emergency_buffer",
        }
    }

    pub fn weight_bps(self) -> u64 {
        match self {
            Self::CommittedCapital => 500,
            Self::EncryptedBalance => 625,
            Self::ClaimReserve => 750,
            Self::PremiumFloat => 875,
            Self::RebateLiability => 1000,
            Self::BridgeExposure => 1125,
            Self::DefiExposure => 1250,
            Self::ColdReserve => 1375,
            Self::HotReserve => 1500,
            Self::EmergencyBuffer => 1625,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRiskDimension {
    BridgeFinality,
    OracleIntegrity,
    LiquidityDepth,
    SmartContract,
    Governance,
    SequencerLatency,
    DataAvailability,
    ReserveProof,
    Slippage,
    WithdrawalCongestion,
}

impl PolicyRiskDimension {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeFinality => "bridge_finality",
            Self::OracleIntegrity => "oracle_integrity",
            Self::LiquidityDepth => "liquidity_depth",
            Self::SmartContract => "smart_contract",
            Self::Governance => "governance",
            Self::SequencerLatency => "sequencer_latency",
            Self::DataAvailability => "data_availability",
            Self::ReserveProof => "reserve_proof",
            Self::Slippage => "slippage",
            Self::WithdrawalCongestion => "withdrawal_congestion",
        }
    }

    pub fn weight_bps(self) -> u64 {
        match self {
            Self::BridgeFinality => 500,
            Self::OracleIntegrity => 625,
            Self::LiquidityDepth => 750,
            Self::SmartContract => 875,
            Self::Governance => 1000,
            Self::SequencerLatency => 1125,
            Self::DataAvailability => 1250,
            Self::ReserveProof => 1375,
            Self::Slippage => 1500,
            Self::WithdrawalCongestion => 1625,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimEvidenceDimension {
    LossProof,
    IncidentRoot,
    NullifierTrail,
    BridgeReceipt,
    OracleSnapshot,
    CommitteeTranscript,
    PayoutAddress,
    DeductibleProof,
    PrivacySet,
    ChallengeWindow,
}

impl ClaimEvidenceDimension {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LossProof => "loss_proof",
            Self::IncidentRoot => "incident_root",
            Self::NullifierTrail => "nullifier_trail",
            Self::BridgeReceipt => "bridge_receipt",
            Self::OracleSnapshot => "oracle_snapshot",
            Self::CommitteeTranscript => "committee_transcript",
            Self::PayoutAddress => "payout_address",
            Self::DeductibleProof => "deductible_proof",
            Self::PrivacySet => "privacy_set",
            Self::ChallengeWindow => "challenge_window",
        }
    }

    pub fn weight_bps(self) -> u64 {
        match self {
            Self::LossProof => 500,
            Self::IncidentRoot => 625,
            Self::NullifierTrail => 750,
            Self::BridgeReceipt => 875,
            Self::OracleSnapshot => 1000,
            Self::CommitteeTranscript => 1125,
            Self::PayoutAddress => 1250,
            Self::DeductibleProof => 1375,
            Self::PrivacySet => 1500,
            Self::ChallengeWindow => 1625,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThrottleDimension {
    DailyCap,
    VaultUtilization,
    QueuePriority,
    CommitteeQuorum,
    EmergencyDelay,
    LowFeeLane,
    ReserveDrain,
    BatchPayout,
    DeferredRemainder,
    FinalRelease,
}

impl ThrottleDimension {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DailyCap => "daily_cap",
            Self::VaultUtilization => "vault_utilization",
            Self::QueuePriority => "queue_priority",
            Self::CommitteeQuorum => "committee_quorum",
            Self::EmergencyDelay => "emergency_delay",
            Self::LowFeeLane => "low_fee_lane",
            Self::ReserveDrain => "reserve_drain",
            Self::BatchPayout => "batch_payout",
            Self::DeferredRemainder => "deferred_remainder",
            Self::FinalRelease => "final_release",
        }
    }

    pub fn weight_bps(self) -> u64 {
        match self {
            Self::DailyCap => 500,
            Self::VaultUtilization => 625,
            Self::QueuePriority => 750,
            Self::CommitteeQuorum => 875,
            Self::EmergencyDelay => 1000,
            Self::LowFeeLane => 1125,
            Self::ReserveDrain => 1250,
            Self::BatchPayout => 1375,
            Self::DeferredRemainder => 1500,
            Self::FinalRelease => 1625,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateDimension {
    SmallPremium,
    BatchDiscount,
    PrivateLane,
    BridgeHealth,
    NoClaimBonus,
    PaymasterSponsor,
    ProofCompression,
    EarlyRenewal,
    LiquidityDepth,
    ProtocolSafety,
}

impl RebateDimension {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SmallPremium => "small_premium",
            Self::BatchDiscount => "batch_discount",
            Self::PrivateLane => "private_lane",
            Self::BridgeHealth => "bridge_health",
            Self::NoClaimBonus => "no_claim_bonus",
            Self::PaymasterSponsor => "paymaster_sponsor",
            Self::ProofCompression => "proof_compression",
            Self::EarlyRenewal => "early_renewal",
            Self::LiquidityDepth => "liquidity_depth",
            Self::ProtocolSafety => "protocol_safety",
        }
    }

    pub fn weight_bps(self) -> u64 {
        match self {
            Self::SmallPremium => 500,
            Self::BatchDiscount => 625,
            Self::PrivateLane => 750,
            Self::BridgeHealth => 875,
            Self::NoClaimBonus => 1000,
            Self::PaymasterSponsor => 1125,
            Self::ProofCompression => 1250,
            Self::EarlyRenewal => 1375,
            Self::LiquidityDepth => 1500,
            Self::ProtocolSafety => 1625,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingDimension {
    Equivocation,
    BadRangeProof,
    LateVote,
    Censorship,
    InvalidPayout,
    FalseChallenge,
    KeyCompromise,
    ReserveMisreport,
    RebateFraud,
    QuorumForgery,
}

impl SlashingDimension {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Equivocation => "equivocation",
            Self::BadRangeProof => "bad_range_proof",
            Self::LateVote => "late_vote",
            Self::Censorship => "censorship",
            Self::InvalidPayout => "invalid_payout",
            Self::FalseChallenge => "false_challenge",
            Self::KeyCompromise => "key_compromise",
            Self::ReserveMisreport => "reserve_misreport",
            Self::RebateFraud => "rebate_fraud",
            Self::QuorumForgery => "quorum_forgery",
        }
    }

    pub fn weight_bps(self) -> u64 {
        match self {
            Self::Equivocation => 500,
            Self::BadRangeProof => 625,
            Self::LateVote => 750,
            Self::Censorship => 875,
            Self::InvalidPayout => 1000,
            Self::FalseChallenge => 1125,
            Self::KeyCompromise => 1250,
            Self::ReserveMisreport => 1375,
            Self::RebateFraud => 1500,
            Self::QuorumForgery => 1625,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnderwriterConfig {
    pub protocol_id: String,
    pub protocol_version: u32,
    pub hash_suite: String,
    pub pq_signature_scheme: String,
    pub pq_backup_scheme: String,
    pub pq_kem_scheme: String,
    pub vault_sealing_scheme: String,
    pub policy_envelope_scheme: String,
    pub risk_attestation_scheme: String,
    pub claim_proof_scheme: String,
    pub payout_throttle_scheme: String,
    pub rebate_scheme: String,
    pub challenge_scheme: String,
    pub fee_asset_id: String,
    pub monero_network: String,
    pub epoch_blocks: u64,
    pub policy_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub claim_challenge_blocks: u64,
    pub payout_window_blocks: u64,
    pub rebate_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub committee_quorum_bps: u64,
    pub supermajority_bps: u64,
    pub max_policy_exposure_bps: u64,
    pub max_vault_utilization_bps: u64,
    pub min_solvency_bps: u64,
    pub max_daily_payout_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub claim_slash_bps: u64,
    pub reporter_reward_bps: u64,
}

impl UnderwriterConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_id: PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_PROTOCOL_ID.to_string(),
            protocol_version: PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_PROTOCOL_VERSION,
            hash_suite: PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_HASH_SUITE.to_string(),
            pq_signature_scheme: PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_PQ_SIGNATURE_SCHEME
                .to_string(),
            pq_backup_scheme: PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_PQ_BACKUP_SCHEME.to_string(),
            pq_kem_scheme: PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_PQ_KEM_SCHEME.to_string(),
            vault_sealing_scheme: PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_VAULT_SEALING_SCHEME
                .to_string(),
            policy_envelope_scheme: PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_POLICY_ENVELOPE_SCHEME
                .to_string(),
            risk_attestation_scheme:
                PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_RISK_ATTESTATION_SCHEME.to_string(),
            claim_proof_scheme: PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_CLAIM_PROOF_SCHEME
                .to_string(),
            payout_throttle_scheme: PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_PAYOUT_THROTTLE_SCHEME
                .to_string(),
            rebate_scheme: PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_REBATE_SCHEME.to_string(),
            challenge_scheme: PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_CHALLENGE_SCHEME.to_string(),
            fee_asset_id: PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_FEE_ASSET_ID.to_string(),
            monero_network: PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MONERO_NETWORK.to_string(),
            epoch_blocks: PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_EPOCH_BLOCKS,
            policy_ttl_blocks: PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_POLICY_TTL_BLOCKS,
            attestation_ttl_blocks:
                PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_ATTESTATION_TTL_BLOCKS,
            claim_challenge_blocks:
                PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_CLAIM_CHALLENGE_BLOCKS,
            payout_window_blocks:
                PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_PAYOUT_WINDOW_BLOCKS,
            rebate_window_blocks:
                PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_REBATE_WINDOW_BLOCKS,
            min_privacy_set_size:
                PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_MIN_PQ_SECURITY_BITS,
            committee_quorum_bps:
                PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_COMMITTEE_QUORUM_BPS,
            supermajority_bps: PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_SUPERMAJORITY_BPS,
            max_policy_exposure_bps:
                PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_MAX_POLICY_EXPOSURE_BPS,
            max_vault_utilization_bps:
                PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_MAX_VAULT_UTILIZATION_BPS,
            min_solvency_bps: PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_MIN_SOLVENCY_BPS,
            max_daily_payout_bps:
                PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_MAX_DAILY_PAYOUT_BPS,
            low_fee_rebate_bps: PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_LOW_FEE_REBATE_BPS,
            claim_slash_bps: PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_CLAIM_SLASH_BPS,
            reporter_reward_bps:
                PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_REPORTER_REWARD_BPS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID, "protocol_id": self.protocol_id, "protocol_version": self.protocol_version,
            "hash_suite": self.hash_suite, "pq_signature_scheme": self.pq_signature_scheme,
            "pq_backup_scheme": self.pq_backup_scheme, "pq_kem_scheme": self.pq_kem_scheme,
            "vault_sealing_scheme": self.vault_sealing_scheme, "policy_envelope_scheme": self.policy_envelope_scheme,
            "risk_attestation_scheme": self.risk_attestation_scheme, "claim_proof_scheme": self.claim_proof_scheme,
            "payout_throttle_scheme": self.payout_throttle_scheme, "rebate_scheme": self.rebate_scheme,
            "challenge_scheme": self.challenge_scheme, "fee_asset_id": self.fee_asset_id, "monero_network": self.monero_network,
            "epoch_blocks": self.epoch_blocks, "policy_ttl_blocks": self.policy_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks, "claim_challenge_blocks": self.claim_challenge_blocks,
            "payout_window_blocks": self.payout_window_blocks, "rebate_window_blocks": self.rebate_window_blocks,
            "min_privacy_set_size": self.min_privacy_set_size, "min_pq_security_bits": self.min_pq_security_bits,
            "committee_quorum_bps": self.committee_quorum_bps, "supermajority_bps": self.supermajority_bps,
            "max_policy_exposure_bps": self.max_policy_exposure_bps, "max_vault_utilization_bps": self.max_vault_utilization_bps,
            "min_solvency_bps": self.min_solvency_bps, "max_daily_payout_bps": self.max_daily_payout_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps, "claim_slash_bps": self.claim_slash_bps,
            "reporter_reward_bps": self.reporter_reward_bps,
        })
    }

    pub fn state_root(&self) -> String {
        underwriter_hash("CONFIG", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateLiquidityInsuranceUnderwriterResult<()> {
        ensure_non_empty("protocol_id", &self.protocol_id)?;
        ensure_non_empty("hash_suite", &self.hash_suite)?;
        ensure_non_empty("pq_signature_scheme", &self.pq_signature_scheme)?;
        ensure_non_empty("pq_kem_scheme", &self.pq_kem_scheme)?;
        ensure_bps("committee_quorum_bps", self.committee_quorum_bps)?;
        ensure_bps("supermajority_bps", self.supermajority_bps)?;
        ensure_bps("max_policy_exposure_bps", self.max_policy_exposure_bps)?;
        ensure_bps("max_vault_utilization_bps", self.max_vault_utilization_bps)?;
        ensure_bps("max_daily_payout_bps", self.max_daily_payout_bps)?;
        ensure_bps("low_fee_rebate_bps", self.low_fee_rebate_bps)?;
        ensure_bps("claim_slash_bps", self.claim_slash_bps)?;
        ensure_bps("reporter_reward_bps", self.reporter_reward_bps)?;
        if self.supermajority_bps < self.committee_quorum_bps {
            return Err("supermajority_bps must be at least committee_quorum_bps".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("min_pq_security_bits below devnet floor".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfidentialUnderwriterVault {
    pub vault_id: String,
    pub operator_commitment: String,
    pub capital_commitment_root: String,
    pub encrypted_balance_root: String,
    pub reserve_bucket_root: String,
    pub nullifier_root: String,
    pub exposure_root: String,
    pub solvency_proof_root: String,
    pub committee_guardian_root: String,
    pub status: UnderwriterVaultStatus,
    pub total_capacity_units: u64,
    pub active_exposure_units: u64,
    pub reserved_claim_units: u64,
    pub paid_claim_units: u64,
    pub premium_collected_units: u64,
    pub rebate_liability_units: u64,
    pub utilization_bps: u64,
    pub solvency_bps: u64,
    pub privacy_set_size: u64,
    pub created_at_height: u64,
    pub updated_at_height: u64,
}

impl ConfidentialUnderwriterVault {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "vault_id": self.vault_id,
            "operator_commitment": self.operator_commitment,
            "capital_commitment_root": self.capital_commitment_root,
            "encrypted_balance_root": self.encrypted_balance_root,
            "reserve_bucket_root": self.reserve_bucket_root,
            "nullifier_root": self.nullifier_root,
            "exposure_root": self.exposure_root,
            "solvency_proof_root": self.solvency_proof_root,
            "committee_guardian_root": self.committee_guardian_root,
            "status": self.status.as_str(),
            "total_capacity_units": self.total_capacity_units,
            "active_exposure_units": self.active_exposure_units,
            "reserved_claim_units": self.reserved_claim_units,
            "paid_claim_units": self.paid_claim_units,
            "premium_collected_units": self.premium_collected_units,
            "rebate_liability_units": self.rebate_liability_units,
            "utilization_bps": self.utilization_bps,
            "solvency_bps": self.solvency_bps,
            "privacy_set_size": self.privacy_set_size,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        underwriter_hash(
            "CONFIDENTIALUNDERWRITERVAULT",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn available_capacity_units(&self) -> u64 {
        self.total_capacity_units
            .saturating_sub(self.active_exposure_units)
            .saturating_sub(self.reserved_claim_units)
            .saturating_sub(self.rebate_liability_units)
    }

    pub fn validate(&self) -> PrivateLiquidityInsuranceUnderwriterResult<()> {
        ensure_non_empty("vault_id", &self.vault_id)?;
        ensure_non_empty("operator_commitment", &self.operator_commitment)?;
        ensure_bps("utilization_bps", self.utilization_bps)?;
        if self
            .active_exposure_units
            .saturating_add(self.reserved_claim_units)
            > self.total_capacity_units
        {
            return Err(format!("vault {} over-reserved", self.vault_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeDefiPolicyEnvelope {
    pub policy_id: String,
    pub vault_id: String,
    pub covered_domain: CoveredDomain,
    pub insured_account_commitment: String,
    pub protocol_commitment: String,
    pub bridge_or_pool_id: String,
    pub encrypted_terms_root: String,
    pub covered_asset_root: String,
    pub premium_note_commitment: String,
    pub premium_nullifier: String,
    pub risk_attestation_root: String,
    pub payout_address_commitment: String,
    pub status: PolicyEnvelopeStatus,
    pub coverage_units: u64,
    pub deductible_units: u64,
    pub premium_units: u64,
    pub max_payout_units: u64,
    pub risk_score_bps: u64,
    pub rebate_bps: u64,
    pub issued_at_height: u64,
    pub active_from_height: u64,
    pub expires_at_height: u64,
    pub updated_at_height: u64,
}

impl BridgeDefiPolicyEnvelope {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "policy_id": self.policy_id,
            "vault_id": self.vault_id,
            "covered_domain": self.covered_domain.as_str(),
            "insured_account_commitment": self.insured_account_commitment,
            "protocol_commitment": self.protocol_commitment,
            "bridge_or_pool_id": self.bridge_or_pool_id,
            "encrypted_terms_root": self.encrypted_terms_root,
            "covered_asset_root": self.covered_asset_root,
            "premium_note_commitment": self.premium_note_commitment,
            "premium_nullifier": self.premium_nullifier,
            "risk_attestation_root": self.risk_attestation_root,
            "payout_address_commitment": self.payout_address_commitment,
            "status": self.status.as_str(),
            "coverage_units": self.coverage_units,
            "deductible_units": self.deductible_units,
            "premium_units": self.premium_units,
            "max_payout_units": self.max_payout_units,
            "risk_score_bps": self.risk_score_bps,
            "rebate_bps": self.rebate_bps,
            "issued_at_height": self.issued_at_height,
            "active_from_height": self.active_from_height,
            "expires_at_height": self.expires_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        underwriter_hash(
            "BRIDGEDEFIPOLICYENVELOPE",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self) -> PrivateLiquidityInsuranceUnderwriterResult<()> {
        ensure_non_empty("policy_id", &self.policy_id)?;
        ensure_non_empty("vault_id", &self.vault_id)?;
        ensure_non_empty("premium_nullifier", &self.premium_nullifier)?;
        ensure_bps("risk_score_bps", self.risk_score_bps)?;
        ensure_bps("rebate_bps", self.rebate_bps)?;
        if self.coverage_units == 0 {
            return Err(format!("policy {} has zero coverage", self.policy_id));
        }
        if self.max_payout_units > self.coverage_units {
            return Err(format!(
                "policy {} max payout exceeds coverage",
                self.policy_id
            ));
        }
        if self.expires_at_height <= self.active_from_height {
            return Err(format!("policy {} expiry invalid", self.policy_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RiskAttestation {
    pub attestation_id: String,
    pub policy_id: String,
    pub vault_id: String,
    pub attester_id: String,
    pub covered_domain: CoveredDomain,
    pub sealed_risk_vector_root: String,
    pub range_proof_root: String,
    pub oracle_context_root: String,
    pub liquidity_depth_root: String,
    pub reserve_health_root: String,
    pub transcript_root: String,
    pub status: RiskAttestationStatus,
    pub risk_score_bps: u64,
    pub confidence_bps: u64,
    pub privacy_set_size: u64,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub submitted_at_height: u64,
}

impl RiskAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "attestation_id": self.attestation_id,
            "policy_id": self.policy_id,
            "vault_id": self.vault_id,
            "attester_id": self.attester_id,
            "covered_domain": self.covered_domain.as_str(),
            "sealed_risk_vector_root": self.sealed_risk_vector_root,
            "range_proof_root": self.range_proof_root,
            "oracle_context_root": self.oracle_context_root,
            "liquidity_depth_root": self.liquidity_depth_root,
            "reserve_health_root": self.reserve_health_root,
            "transcript_root": self.transcript_root,
            "status": self.status.as_str(),
            "risk_score_bps": self.risk_score_bps,
            "confidence_bps": self.confidence_bps,
            "privacy_set_size": self.privacy_set_size,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
            "submitted_at_height": self.submitted_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        underwriter_hash("RISKATTESTATION", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateLiquidityInsuranceUnderwriterResult<()> {
        ensure_non_empty("attestation_id", &self.attestation_id)?;
        ensure_non_empty("policy_id", &self.policy_id)?;
        ensure_non_empty("attester_id", &self.attester_id)?;
        ensure_bps("risk_score_bps", self.risk_score_bps)?;
        ensure_bps("confidence_bps", self.confidence_bps)?;
        if self.expires_at_height <= self.valid_from_height {
            return Err(format!(
                "attestation {} expiry invalid",
                self.attestation_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimQueueEntry {
    pub claim_id: String,
    pub policy_id: String,
    pub vault_id: String,
    pub claimant_commitment: String,
    pub incident_commitment: String,
    pub loss_proof_root: String,
    pub private_loss_bucket_root: String,
    pub committee_vote_root: String,
    pub payout_address_commitment: String,
    pub challenge_window_end_height: u64,
    pub priority_score: u64,
    pub status: ClaimStatus,
    pub claimed_units: u64,
    pub approved_units: u64,
    pub deductible_applied_units: u64,
    pub queued_at_height: u64,
    pub updated_at_height: u64,
}

impl ClaimQueueEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "claim_id": self.claim_id,
            "policy_id": self.policy_id,
            "vault_id": self.vault_id,
            "claimant_commitment": self.claimant_commitment,
            "incident_commitment": self.incident_commitment,
            "loss_proof_root": self.loss_proof_root,
            "private_loss_bucket_root": self.private_loss_bucket_root,
            "committee_vote_root": self.committee_vote_root,
            "payout_address_commitment": self.payout_address_commitment,
            "challenge_window_end_height": self.challenge_window_end_height,
            "priority_score": self.priority_score,
            "status": self.status.as_str(),
            "claimed_units": self.claimed_units,
            "approved_units": self.approved_units,
            "deductible_applied_units": self.deductible_applied_units,
            "queued_at_height": self.queued_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        underwriter_hash("CLAIMQUEUEENTRY", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateLiquidityInsuranceUnderwriterResult<()> {
        ensure_non_empty("claim_id", &self.claim_id)?;
        if self.claimed_units == 0 {
            return Err(format!("claim {} has zero claimed units", self.claim_id));
        }
        if self.approved_units > self.claimed_units {
            return Err(format!(
                "claim {} approves more than claimed",
                self.claim_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PayoutThrottle {
    pub payout_id: String,
    pub claim_id: String,
    pub policy_id: String,
    pub vault_id: String,
    pub throttle_window_id: String,
    pub payout_note_commitment: String,
    pub payout_nullifier: String,
    pub committee_signature_root: String,
    pub status: PayoutStatus,
    pub requested_units: u64,
    pub released_units: u64,
    pub deferred_units: u64,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub scheduled_at_height: u64,
    pub released_at_height: u64,
}

impl PayoutThrottle {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "payout_id": self.payout_id,
            "claim_id": self.claim_id,
            "policy_id": self.policy_id,
            "vault_id": self.vault_id,
            "throttle_window_id": self.throttle_window_id,
            "payout_note_commitment": self.payout_note_commitment,
            "payout_nullifier": self.payout_nullifier,
            "committee_signature_root": self.committee_signature_root,
            "status": self.status.as_str(),
            "requested_units": self.requested_units,
            "released_units": self.released_units,
            "deferred_units": self.deferred_units,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "scheduled_at_height": self.scheduled_at_height,
            "released_at_height": self.released_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        underwriter_hash("PAYOUTTHROTTLE", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateLiquidityInsuranceUnderwriterResult<()> {
        ensure_non_empty("payout_id", &self.payout_id)?;
        ensure_non_empty("claim_id", &self.claim_id)?;
        if self.requested_units == 0 {
            return Err(format!(
                "payout {} has zero requested units",
                self.payout_id
            ));
        }
        if self.released_units.saturating_add(self.deferred_units) > self.requested_units {
            return Err(format!("payout {} exceeds request", self.payout_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PremiumRebateCredit {
    pub rebate_id: String,
    pub policy_id: String,
    pub vault_id: String,
    pub beneficiary_commitment: String,
    pub premium_note_commitment: String,
    pub rebate_note_commitment: String,
    pub rebate_nullifier: String,
    pub low_fee_lane_id: String,
    pub status: RebateStatus,
    pub premium_units: u64,
    pub rebate_units: u64,
    pub rebate_bps: u64,
    pub accrued_at_height: u64,
    pub claimable_at_height: u64,
    pub expires_at_height: u64,
}

impl PremiumRebateCredit {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "rebate_id": self.rebate_id,
            "policy_id": self.policy_id,
            "vault_id": self.vault_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "premium_note_commitment": self.premium_note_commitment,
            "rebate_note_commitment": self.rebate_note_commitment,
            "rebate_nullifier": self.rebate_nullifier,
            "low_fee_lane_id": self.low_fee_lane_id,
            "status": self.status.as_str(),
            "premium_units": self.premium_units,
            "rebate_units": self.rebate_units,
            "rebate_bps": self.rebate_bps,
            "accrued_at_height": self.accrued_at_height,
            "claimable_at_height": self.claimable_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        underwriter_hash(
            "PREMIUMREBATECREDIT",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self) -> PrivateLiquidityInsuranceUnderwriterResult<()> {
        ensure_non_empty("rebate_id", &self.rebate_id)?;
        ensure_bps("rebate_bps", self.rebate_bps)?;
        if self.rebate_units > self.premium_units {
            return Err(format!("rebate {} exceeds premium", self.rebate_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqClaimsCommitteeMember {
    pub member_id: String,
    pub operator_commitment: String,
    pub pq_public_key_root: String,
    pub backup_public_key_root: String,
    pub role: ClaimsCommitteeRole,
    pub status: CommitteeMemberStatus,
    pub stake_units: u64,
    pub voting_weight_bps: u64,
    pub joined_at_height: u64,
    pub updated_at_height: u64,
}

impl PqClaimsCommitteeMember {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "member_id": self.member_id,
            "operator_commitment": self.operator_commitment,
            "pq_public_key_root": self.pq_public_key_root,
            "backup_public_key_root": self.backup_public_key_root,
            "role": self.role.as_str(),
            "status": self.status.as_str(),
            "stake_units": self.stake_units,
            "voting_weight_bps": self.voting_weight_bps,
            "joined_at_height": self.joined_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        underwriter_hash(
            "PQCLAIMSCOMMITTEEMEMBER",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self) -> PrivateLiquidityInsuranceUnderwriterResult<()> {
        ensure_non_empty("member_id", &self.member_id)?;
        ensure_non_empty("pq_public_key_root", &self.pq_public_key_root)?;
        ensure_bps("voting_weight_bps", self.voting_weight_bps)?;
        if self.stake_units == 0 && self.status.voting() {
            return Err(format!("committee member {} has no stake", self.member_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeSlashingEvidence {
    pub challenge_id: String,
    pub target_kind: String,
    pub target_id: String,
    pub reporter_commitment: String,
    pub accused_member_id: String,
    pub evidence_root: String,
    pub transcript_root: String,
    pub conflicting_commitment_root: String,
    pub status: ChallengeStatus,
    pub slash_units: u64,
    pub reporter_reward_units: u64,
    pub filed_at_height: u64,
    pub resolved_at_height: u64,
}

impl ChallengeSlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "challenge_id": self.challenge_id,
            "target_kind": self.target_kind,
            "target_id": self.target_id,
            "reporter_commitment": self.reporter_commitment,
            "accused_member_id": self.accused_member_id,
            "evidence_root": self.evidence_root,
            "transcript_root": self.transcript_root,
            "conflicting_commitment_root": self.conflicting_commitment_root,
            "status": self.status.as_str(),
            "slash_units": self.slash_units,
            "reporter_reward_units": self.reporter_reward_units,
            "filed_at_height": self.filed_at_height,
            "resolved_at_height": self.resolved_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        underwriter_hash(
            "CHALLENGESLASHINGEVIDENCE",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self) -> PrivateLiquidityInsuranceUnderwriterResult<()> {
        ensure_non_empty("challenge_id", &self.challenge_id)?;
        ensure_non_empty("target_id", &self.target_id)?;
        if self.reporter_reward_units > self.slash_units {
            return Err(format!(
                "challenge {} reward exceeds slash",
                self.challenge_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnderwriterEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub state_root_after: String,
    pub metadata_root: String,
    pub height: u64,
}

impl UnderwriterEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "state_root_after": self.state_root_after,
            "metadata_root": self.metadata_root,
            "height": self.height,
        })
    }

    pub fn state_root(&self) -> String {
        underwriter_hash("UNDERWRITEREVENT", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateLiquidityInsuranceUnderwriterResult<()> {
        ensure_non_empty("event_id", &self.event_id)?;
        ensure_non_empty("event_kind", &self.event_kind)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateLiquidityInsuranceUnderwriterRoots {
    pub config_root: String,
    pub vault_root: String,
    pub policy_root: String,
    pub risk_attestation_root: String,
    pub claim_queue_root: String,
    pub payout_throttle_root: String,
    pub premium_rebate_root: String,
    pub committee_root: String,
    pub challenge_root: String,
    pub nullifier_root: String,
    pub event_root: String,
}

impl PrivateLiquidityInsuranceUnderwriterRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID, "config_root": self.config_root, "vault_root": self.vault_root,
            "policy_root": self.policy_root, "risk_attestation_root": self.risk_attestation_root,
            "claim_queue_root": self.claim_queue_root, "payout_throttle_root": self.payout_throttle_root,
            "premium_rebate_root": self.premium_rebate_root, "committee_root": self.committee_root,
            "challenge_root": self.challenge_root, "nullifier_root": self.nullifier_root, "event_root": self.event_root,
        })
    }
    pub fn state_root(&self) -> String {
        underwriter_hash("ROOTS", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateLiquidityInsuranceUnderwriterCounters {
    pub vaults: usize,
    pub policies: usize,
    pub risk_attestations: usize,
    pub queued_claims: usize,
    pub open_claims: usize,
    pub payouts: usize,
    pub rebates: usize,
    pub committee_members: usize,
    pub active_committee_members: usize,
    pub challenges: usize,
    pub events: usize,
    pub total_capacity_units: u64,
    pub active_exposure_units: u64,
    pub reserved_claim_units: u64,
    pub total_premium_units: u64,
    pub total_rebate_units: u64,
    pub released_payout_units: u64,
}

impl PrivateLiquidityInsuranceUnderwriterCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID, "vaults": self.vaults, "policies": self.policies,
            "risk_attestations": self.risk_attestations, "queued_claims": self.queued_claims,
            "open_claims": self.open_claims, "payouts": self.payouts, "rebates": self.rebates,
            "committee_members": self.committee_members, "active_committee_members": self.active_committee_members,
            "challenges": self.challenges, "events": self.events, "total_capacity_units": self.total_capacity_units,
            "active_exposure_units": self.active_exposure_units, "reserved_claim_units": self.reserved_claim_units,
            "total_premium_units": self.total_premium_units, "total_rebate_units": self.total_rebate_units,
            "released_payout_units": self.released_payout_units,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateLiquidityInsuranceUnderwriterState {
    pub height: u64,
    pub config: UnderwriterConfig,
    pub vaults: BTreeMap<String, ConfidentialUnderwriterVault>,
    pub policies: BTreeMap<String, BridgeDefiPolicyEnvelope>,
    pub risk_attestations: BTreeMap<String, RiskAttestation>,
    pub claims: BTreeMap<String, ClaimQueueEntry>,
    pub payouts: BTreeMap<String, PayoutThrottle>,
    pub rebates: BTreeMap<String, PremiumRebateCredit>,
    pub committee_members: BTreeMap<String, PqClaimsCommitteeMember>,
    pub challenges: BTreeMap<String, ChallengeSlashingEvidence>,
    pub spent_nullifiers: BTreeSet<String>,
    pub events: BTreeMap<String, UnderwriterEvent>,
}

impl PrivateLiquidityInsuranceUnderwriterState {
    pub fn new(config: UnderwriterConfig, height: u64) -> Self {
        Self {
            height,
            config,
            vaults: BTreeMap::new(),
            policies: BTreeMap::new(),
            risk_attestations: BTreeMap::new(),
            claims: BTreeMap::new(),
            payouts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            committee_members: BTreeMap::new(),
            challenges: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            events: BTreeMap::new(),
        }
    }

    pub fn devnet() -> PrivateLiquidityInsuranceUnderwriterResult<Self> {
        let mut state = Self::new(
            UnderwriterConfig::devnet(),
            PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEVNET_HEIGHT,
        );
        for index in 0..4_u64 {
            state.register_vault(make_devnet_vault(index, state.height))?;
        }
        for index in 0..8_u64 {
            state.register_committee_member(make_devnet_member(index, state.height))?;
        }
        for index in 0..12_u64 {
            state.issue_policy(make_devnet_policy(
                index,
                state.height,
                state.config.policy_ttl_blocks,
            ))?;
        }
        for index in 0..12_u64 {
            state.record_risk_attestation(make_devnet_attestation(
                index,
                state.height,
                state.config.attestation_ttl_blocks,
            ))?;
        }
        for index in 0..5_u64 {
            state.queue_claim(make_devnet_claim(
                index,
                state.height,
                state.config.claim_challenge_blocks,
            ))?;
        }
        for index in 0..3_u64 {
            state.schedule_payout(make_devnet_payout(
                index,
                state.height,
                state.config.payout_window_blocks,
            ))?;
        }
        for index in 0..8_u64 {
            state.accrue_rebate(make_devnet_rebate(
                index,
                state.height,
                state.config.rebate_window_blocks,
            ))?;
        }
        state.file_challenge(make_devnet_challenge(0, state.height))?;
        state.validate()?;
        Ok(state)
    }

    pub fn update_height(
        &mut self,
        next_height: u64,
    ) -> PrivateLiquidityInsuranceUnderwriterResult<()> {
        if next_height < self.height {
            return Err(format!(
                "height regression from {} to {}",
                self.height, next_height
            ));
        }
        self.height = next_height;
        self.expire_stale_records();
        Ok(())
    }

    pub fn register_vault(
        &mut self,
        mut vault: ConfidentialUnderwriterVault,
    ) -> PrivateLiquidityInsuranceUnderwriterResult<String> {
        self.ensure_capacity(
            "vault",
            self.vaults.len(),
            PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_VAULTS,
        )?;
        vault.updated_at_height = self.height.max(vault.updated_at_height);
        vault.validate()?;
        if vault.privacy_set_size < self.config.min_privacy_set_size {
            return Err(format!("vault {} privacy set below floor", vault.vault_id));
        }
        if vault.solvency_bps < self.config.min_solvency_bps && vault.status.can_underwrite() {
            return Err(format!("vault {} is below solvency floor", vault.vault_id));
        }
        if self.vaults.contains_key(&vault.vault_id) {
            return Err(format!("vault {} already exists", vault.vault_id));
        }
        let id = vault.vault_id.clone();
        self.vaults.insert(id.clone(), vault);
        self.record_event("vault_registered", &id)?;
        Ok(id)
    }

    pub fn issue_policy(
        &mut self,
        mut policy: BridgeDefiPolicyEnvelope,
    ) -> PrivateLiquidityInsuranceUnderwriterResult<String> {
        self.ensure_capacity(
            "policy",
            self.policies.len(),
            PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_POLICIES,
        )?;
        policy.updated_at_height = self.height.max(policy.updated_at_height);
        policy.validate()?;
        if policy
            .expires_at_height
            .saturating_sub(policy.issued_at_height)
            > self.config.policy_ttl_blocks
        {
            return Err(format!("policy {} exceeds ttl", policy.policy_id));
        }
        if self.spent_nullifiers.contains(&policy.premium_nullifier) {
            return Err(format!(
                "premium nullifier {} already spent",
                policy.premium_nullifier
            ));
        }
        let vault = self
            .vaults
            .get(&policy.vault_id)
            .ok_or_else(|| format!("missing vault {}", policy.vault_id))?;
        if !vault.status.can_underwrite() {
            return Err(format!("vault {} cannot underwrite", policy.vault_id));
        }
        let max_policy_units = bps_mul(
            vault.total_capacity_units,
            self.config.max_policy_exposure_bps,
        );
        if policy.coverage_units > max_policy_units {
            return Err(format!(
                "policy {} exceeds single policy exposure",
                policy.policy_id
            ));
        }
        if policy.coverage_units > vault.available_capacity_units() {
            return Err(format!(
                "policy {} exceeds available vault capacity",
                policy.policy_id
            ));
        }
        let id = policy.policy_id.clone();
        self.spent_nullifiers
            .insert(policy.premium_nullifier.clone());
        self.policies.insert(id.clone(), policy);
        self.recompute_vault_exposure(&id)?;
        self.record_event("policy_issued", &id)?;
        Ok(id)
    }

    pub fn record_risk_attestation(
        &mut self,
        attestation: RiskAttestation,
    ) -> PrivateLiquidityInsuranceUnderwriterResult<String> {
        self.ensure_capacity(
            "risk_attestation",
            self.risk_attestations.len(),
            PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_ATTESTATIONS,
        )?;
        attestation.validate()?;
        if attestation
            .expires_at_height
            .saturating_sub(attestation.submitted_at_height)
            > self.config.attestation_ttl_blocks
        {
            return Err(format!(
                "attestation {} exceeds ttl",
                attestation.attestation_id
            ));
        }
        if attestation.privacy_set_size < self.config.min_privacy_set_size {
            return Err(format!(
                "attestation {} privacy set below floor",
                attestation.attestation_id
            ));
        }
        if !self.policies.contains_key(&attestation.policy_id) {
            return Err(format!("missing policy {}", attestation.policy_id));
        }
        if !self
            .committee_members
            .contains_key(&attestation.attester_id)
        {
            return Err(format!("missing attester {}", attestation.attester_id));
        }
        let id = attestation.attestation_id.clone();
        self.risk_attestations.insert(id.clone(), attestation);
        self.record_event("risk_attestation_recorded", &id)?;
        Ok(id)
    }

    pub fn queue_claim(
        &mut self,
        claim: ClaimQueueEntry,
    ) -> PrivateLiquidityInsuranceUnderwriterResult<String> {
        self.ensure_capacity(
            "claim",
            self.claims.len(),
            PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_CLAIMS,
        )?;
        claim.validate()?;
        let policy = self
            .policies
            .get(&claim.policy_id)
            .ok_or_else(|| format!("missing policy {}", claim.policy_id))?;
        if !policy.status.accepts_claims() {
            return Err(format!("policy {} does not accept claims", claim.policy_id));
        }
        if claim.claimed_units > policy.max_payout_units {
            return Err(format!(
                "claim {} exceeds policy max payout",
                claim.claim_id
            ));
        }
        let id = claim.claim_id.clone();
        self.claims.insert(id.clone(), claim);
        self.record_event("claim_queued", &id)?;
        Ok(id)
    }

    pub fn approve_claim(
        &mut self,
        claim_id: &str,
        approved_units: u64,
        vote_root: &str,
    ) -> PrivateLiquidityInsuranceUnderwriterResult<()> {
        ensure_non_empty("claim_id", claim_id)?;
        ensure_non_empty("vote_root", vote_root)?;
        let claim = self
            .claims
            .get_mut(claim_id)
            .ok_or_else(|| format!("missing claim {claim_id}"))?;
        if !claim.status.open() {
            return Err(format!("claim {claim_id} is closed"));
        }
        if approved_units > claim.claimed_units {
            return Err(format!("claim {claim_id} approval exceeds claimed units"));
        }
        claim.approved_units = approved_units;
        claim.committee_vote_root = vote_root.to_string();
        claim.status = ClaimStatus::Approved;
        claim.updated_at_height = self.height;
        self.record_event("claim_approved", claim_id)?;
        Ok(())
    }

    pub fn schedule_payout(
        &mut self,
        payout: PayoutThrottle,
    ) -> PrivateLiquidityInsuranceUnderwriterResult<String> {
        self.ensure_capacity(
            "payout",
            self.payouts.len(),
            PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_PAYOUTS,
        )?;
        payout.validate()?;
        if self.spent_nullifiers.contains(&payout.payout_nullifier) {
            return Err(format!(
                "payout nullifier {} already spent",
                payout.payout_nullifier
            ));
        }
        let vault = self
            .vaults
            .get(&payout.vault_id)
            .ok_or_else(|| format!("missing vault {}", payout.vault_id))?;
        if !vault.status.can_pay_claims() {
            return Err(format!("vault {} cannot pay claims", payout.vault_id));
        }
        let claim = self
            .claims
            .get(&payout.claim_id)
            .ok_or_else(|| format!("missing claim {}", payout.claim_id))?;
        if payout.requested_units > claim.approved_units.max(claim.claimed_units) {
            return Err(format!(
                "payout {} exceeds claim allowance",
                payout.payout_id
            ));
        }
        let window_cap = bps_mul(vault.total_capacity_units, self.config.max_daily_payout_bps);
        if payout.released_units > window_cap {
            return Err(format!("payout {} exceeds throttle cap", payout.payout_id));
        }
        let id = payout.payout_id.clone();
        self.spent_nullifiers
            .insert(payout.payout_nullifier.clone());
        self.payouts.insert(id.clone(), payout);
        self.record_event("payout_scheduled", &id)?;
        Ok(id)
    }

    pub fn release_payout(
        &mut self,
        payout_id: &str,
        release_units: u64,
    ) -> PrivateLiquidityInsuranceUnderwriterResult<()> {
        ensure_non_empty("payout_id", payout_id)?;
        let payout = self
            .payouts
            .get_mut(payout_id)
            .ok_or_else(|| format!("missing payout {payout_id}"))?;
        let next_released = payout.released_units.saturating_add(release_units);
        if next_released > payout.requested_units {
            return Err(format!("payout {payout_id} release exceeds request"));
        }
        payout.released_units = next_released;
        payout.deferred_units = payout.requested_units.saturating_sub(next_released);
        payout.status = if payout.deferred_units == 0 {
            PayoutStatus::Released
        } else {
            PayoutStatus::Throttled
        };
        payout.released_at_height = self.height;
        if let Some(claim) = self.claims.get_mut(&payout.claim_id) {
            claim.status = if payout.deferred_units == 0 {
                ClaimStatus::Paid
            } else {
                ClaimStatus::PayoutScheduled
            };
            claim.updated_at_height = self.height;
        }
        self.record_event("payout_released", payout_id)?;
        Ok(())
    }

    pub fn accrue_rebate(
        &mut self,
        rebate: PremiumRebateCredit,
    ) -> PrivateLiquidityInsuranceUnderwriterResult<String> {
        self.ensure_capacity(
            "rebate",
            self.rebates.len(),
            PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_REBATES,
        )?;
        rebate.validate()?;
        if self.spent_nullifiers.contains(&rebate.rebate_nullifier) {
            return Err(format!(
                "rebate nullifier {} already spent",
                rebate.rebate_nullifier
            ));
        }
        if !self.policies.contains_key(&rebate.policy_id) {
            return Err(format!("missing policy {}", rebate.policy_id));
        }
        let id = rebate.rebate_id.clone();
        self.spent_nullifiers
            .insert(rebate.rebate_nullifier.clone());
        self.rebates.insert(id.clone(), rebate);
        self.record_event("rebate_accrued", &id)?;
        Ok(id)
    }

    pub fn register_committee_member(
        &mut self,
        member: PqClaimsCommitteeMember,
    ) -> PrivateLiquidityInsuranceUnderwriterResult<String> {
        self.ensure_capacity(
            "committee_member",
            self.committee_members.len(),
            PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_COMMITTEE_MEMBERS,
        )?;
        member.validate()?;
        if self.committee_members.contains_key(&member.member_id) {
            return Err(format!(
                "committee member {} already exists",
                member.member_id
            ));
        }
        let id = member.member_id.clone();
        self.committee_members.insert(id.clone(), member);
        self.record_event("committee_member_registered", &id)?;
        Ok(id)
    }

    pub fn file_challenge(
        &mut self,
        challenge: ChallengeSlashingEvidence,
    ) -> PrivateLiquidityInsuranceUnderwriterResult<String> {
        self.ensure_capacity(
            "challenge",
            self.challenges.len(),
            PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_CHALLENGES,
        )?;
        challenge.validate()?;
        let id = challenge.challenge_id.clone();
        self.challenges.insert(id.clone(), challenge);
        self.record_event("challenge_filed", &id)?;
        Ok(id)
    }

    pub fn sustain_challenge(
        &mut self,
        challenge_id: &str,
    ) -> PrivateLiquidityInsuranceUnderwriterResult<()> {
        ensure_non_empty("challenge_id", challenge_id)?;
        let accused_member_id = {
            let challenge = self
                .challenges
                .get_mut(challenge_id)
                .ok_or_else(|| format!("missing challenge {challenge_id}"))?;
            challenge.status = ChallengeStatus::Sustained;
            challenge.resolved_at_height = self.height;
            challenge.accused_member_id.clone()
        };
        if let Some(member) = self.committee_members.get_mut(&accused_member_id) {
            member.status = CommitteeMemberStatus::Slashed;
            member.updated_at_height = self.height;
        }
        self.record_event("challenge_sustained", challenge_id)?;
        Ok(())
    }

    pub fn roots(&self) -> PrivateLiquidityInsuranceUnderwriterRoots {
        PrivateLiquidityInsuranceUnderwriterRoots {
            config_root: self.config.state_root(),
            vault_root: merkle_public_records(
                "PRIVATE-LIQUIDITY-INSURANCE-VAULTS",
                self.vaults
                    .values()
                    .map(ConfidentialUnderwriterVault::public_record)
                    .collect(),
            ),
            policy_root: merkle_public_records(
                "PRIVATE-LIQUIDITY-INSURANCE-POLICIES",
                self.policies
                    .values()
                    .map(BridgeDefiPolicyEnvelope::public_record)
                    .collect(),
            ),
            risk_attestation_root: merkle_public_records(
                "PRIVATE-LIQUIDITY-INSURANCE-RISK-ATTESTATIONS",
                self.risk_attestations
                    .values()
                    .map(RiskAttestation::public_record)
                    .collect(),
            ),
            claim_queue_root: merkle_public_records(
                "PRIVATE-LIQUIDITY-INSURANCE-CLAIMS",
                self.claims
                    .values()
                    .map(ClaimQueueEntry::public_record)
                    .collect(),
            ),
            payout_throttle_root: merkle_public_records(
                "PRIVATE-LIQUIDITY-INSURANCE-PAYOUTS",
                self.payouts
                    .values()
                    .map(PayoutThrottle::public_record)
                    .collect(),
            ),
            premium_rebate_root: merkle_public_records(
                "PRIVATE-LIQUIDITY-INSURANCE-REBATES",
                self.rebates
                    .values()
                    .map(PremiumRebateCredit::public_record)
                    .collect(),
            ),
            committee_root: merkle_public_records(
                "PRIVATE-LIQUIDITY-INSURANCE-COMMITTEE",
                self.committee_members
                    .values()
                    .map(PqClaimsCommitteeMember::public_record)
                    .collect(),
            ),
            challenge_root: merkle_public_records(
                "PRIVATE-LIQUIDITY-INSURANCE-CHALLENGES",
                self.challenges
                    .values()
                    .map(ChallengeSlashingEvidence::public_record)
                    .collect(),
            ),
            nullifier_root: merkle_public_records(
                "PRIVATE-LIQUIDITY-INSURANCE-NULLIFIERS",
                self.spent_nullifiers
                    .iter()
                    .map(|value| json!(value))
                    .collect(),
            ),
            event_root: merkle_public_records(
                "PRIVATE-LIQUIDITY-INSURANCE-EVENTS",
                self.events
                    .values()
                    .map(UnderwriterEvent::public_record)
                    .collect(),
            ),
        }
    }

    pub fn counters(&self) -> PrivateLiquidityInsuranceUnderwriterCounters {
        PrivateLiquidityInsuranceUnderwriterCounters {
            vaults: self.vaults.len(),
            policies: self.policies.len(),
            risk_attestations: self.risk_attestations.len(),
            queued_claims: self.claims.len(),
            open_claims: self
                .claims
                .values()
                .filter(|claim| claim.status.open())
                .count(),
            payouts: self.payouts.len(),
            rebates: self.rebates.len(),
            committee_members: self.committee_members.len(),
            active_committee_members: self
                .committee_members
                .values()
                .filter(|member| member.status.voting())
                .count(),
            challenges: self.challenges.len(),
            events: self.events.len(),
            total_capacity_units: self
                .vaults
                .values()
                .map(|vault| vault.total_capacity_units)
                .sum(),
            active_exposure_units: self
                .vaults
                .values()
                .map(|vault| vault.active_exposure_units)
                .sum(),
            reserved_claim_units: self
                .vaults
                .values()
                .map(|vault| vault.reserved_claim_units)
                .sum(),
            total_premium_units: self
                .policies
                .values()
                .map(|policy| policy.premium_units)
                .sum(),
            total_rebate_units: self
                .rebates
                .values()
                .map(|rebate| rebate.rebate_units)
                .sum(),
            released_payout_units: self
                .payouts
                .values()
                .map(|payout| payout.released_units)
                .sum(),
        }
    }

    pub fn state_root(&self) -> String {
        let roots = self.roots();
        let counters = self.counters();
        underwriter_hash(
            "STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Int(self.height as i128),
                HashPart::Json(&roots.public_record()),
                HashPart::Json(&counters.public_record()),
            ],
        )
    }

    pub fn public_record(&self) -> Value {
        json!({ "chain_id": CHAIN_ID, "height": self.height, "protocol_id": self.config.protocol_id, "state_root": self.state_root(), "roots": self.roots().public_record(), "counters": self.counters().public_record() })
    }

    pub fn validate(&self) -> PrivateLiquidityInsuranceUnderwriterResult<()> {
        self.config.validate()?;
        for vault in self.vaults.values() {
            vault.validate()?;
            if vault.privacy_set_size < self.config.min_privacy_set_size {
                return Err(format!("vault {} privacy set below floor", vault.vault_id));
            }
        }
        for policy in self.policies.values() {
            policy.validate()?;
            if !self.vaults.contains_key(&policy.vault_id) {
                return Err(format!(
                    "policy {} references missing vault",
                    policy.policy_id
                ));
            }
        }
        for attestation in self.risk_attestations.values() {
            attestation.validate()?;
            if !self.policies.contains_key(&attestation.policy_id) {
                return Err(format!(
                    "attestation {} references missing policy",
                    attestation.attestation_id
                ));
            }
        }
        for claim in self.claims.values() {
            claim.validate()?;
            if !self.policies.contains_key(&claim.policy_id) {
                return Err(format!(
                    "claim {} references missing policy",
                    claim.claim_id
                ));
            }
        }
        for payout in self.payouts.values() {
            payout.validate()?;
            if !self.claims.contains_key(&payout.claim_id) {
                return Err(format!(
                    "payout {} references missing claim",
                    payout.payout_id
                ));
            }
        }
        for rebate in self.rebates.values() {
            rebate.validate()?;
            if !self.policies.contains_key(&rebate.policy_id) {
                return Err(format!(
                    "rebate {} references missing policy",
                    rebate.rebate_id
                ));
            }
        }
        for member in self.committee_members.values() {
            member.validate()?;
        }
        for challenge in self.challenges.values() {
            challenge.validate()?;
        }
        Ok(())
    }

    fn ensure_capacity(
        &self,
        label: &str,
        len: usize,
        max: usize,
    ) -> PrivateLiquidityInsuranceUnderwriterResult<()> {
        if len >= max {
            return Err(format!("{label} capacity reached"));
        }
        Ok(())
    }

    fn recompute_vault_exposure(
        &mut self,
        policy_id: &str,
    ) -> PrivateLiquidityInsuranceUnderwriterResult<()> {
        let policy = self
            .policies
            .get(policy_id)
            .ok_or_else(|| format!("missing policy {policy_id}"))?;
        let vault = self
            .vaults
            .get_mut(&policy.vault_id)
            .ok_or_else(|| format!("missing vault {}", policy.vault_id))?;
        vault.active_exposure_units = self
            .policies
            .values()
            .filter(|candidate| {
                candidate.vault_id == policy.vault_id
                    && matches!(
                        candidate.status,
                        PolicyEnvelopeStatus::Quoted
                            | PolicyEnvelopeStatus::Active
                            | PolicyEnvelopeStatus::GracePeriod
                            | PolicyEnvelopeStatus::ClaimPending
                    )
            })
            .map(|candidate| candidate.coverage_units)
            .sum();
        vault.premium_collected_units = self
            .policies
            .values()
            .filter(|candidate| candidate.vault_id == policy.vault_id)
            .map(|candidate| candidate.premium_units)
            .sum();
        vault.rebate_liability_units = self
            .rebates
            .values()
            .filter(|candidate| {
                candidate.vault_id == policy.vault_id
                    && matches!(
                        candidate.status,
                        RebateStatus::Accrued | RebateStatus::Claimable
                    )
            })
            .map(|candidate| candidate.rebate_units)
            .sum();
        vault.reserved_claim_units = self
            .claims
            .values()
            .filter(|candidate| candidate.vault_id == policy.vault_id && candidate.status.open())
            .map(|candidate| candidate.approved_units.max(candidate.claimed_units))
            .sum();
        vault.utilization_bps = ratio_bps(
            vault
                .active_exposure_units
                .saturating_add(vault.reserved_claim_units),
            vault.total_capacity_units,
        );
        vault.updated_at_height = self.height;
        Ok(())
    }

    fn expire_stale_records(&mut self) {
        for policy in self.policies.values_mut() {
            if self.height > policy.expires_at_height
                && matches!(
                    policy.status,
                    PolicyEnvelopeStatus::Quoted
                        | PolicyEnvelopeStatus::Active
                        | PolicyEnvelopeStatus::GracePeriod
                )
            {
                policy.status = PolicyEnvelopeStatus::Expired;
                policy.updated_at_height = self.height;
            }
        }
        for attestation in self.risk_attestations.values_mut() {
            if self.height > attestation.expires_at_height
                && !matches!(
                    attestation.status,
                    RiskAttestationStatus::Rejected | RiskAttestationStatus::Challenged
                )
            {
                attestation.status = RiskAttestationStatus::Expired;
            }
        }
        for claim in self.claims.values_mut() {
            if self.height > claim.challenge_window_end_height
                && matches!(claim.status, ClaimStatus::Queued)
            {
                claim.status = ClaimStatus::CommitteeReview;
                claim.updated_at_height = self.height;
            }
        }
        for rebate in self.rebates.values_mut() {
            if self.height > rebate.expires_at_height
                && matches!(
                    rebate.status,
                    RebateStatus::Accrued | RebateStatus::Claimable
                )
            {
                rebate.status = RebateStatus::Expired;
            } else if self.height >= rebate.claimable_at_height
                && matches!(rebate.status, RebateStatus::Accrued)
            {
                rebate.status = RebateStatus::Claimable;
            }
        }
    }

    fn record_event(
        &mut self,
        event_kind: &str,
        subject_id: &str,
    ) -> PrivateLiquidityInsuranceUnderwriterResult<()> {
        self.ensure_capacity(
            "event",
            self.events.len(),
            PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_EVENTS,
        )?;
        let metadata_root = underwriter_hash(
            "EVENT-METADATA",
            &[
                HashPart::Str(event_kind),
                HashPart::Str(subject_id),
                HashPart::Int(self.height as i128),
            ],
        );
        let event_id = underwriter_hash(
            "EVENT-ID",
            &[
                HashPart::Str(event_kind),
                HashPart::Str(subject_id),
                HashPart::Int(self.height as i128),
                HashPart::Int(self.events.len() as i128),
            ],
        );
        let event = UnderwriterEvent {
            event_id: event_id.clone(),
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            state_root_after: self.roots().state_root(),
            metadata_root,
            height: self.height,
        };
        self.events.insert(event_id, event);
        Ok(())
    }
}

pub fn devnet(
) -> PrivateLiquidityInsuranceUnderwriterResult<PrivateLiquidityInsuranceUnderwriterState> {
    PrivateLiquidityInsuranceUnderwriterState::devnet()
}

pub fn deterministic_underwriter_metric_000(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(0u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(0u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

pub fn deterministic_underwriter_metric_001(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(1u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(1u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

pub fn deterministic_underwriter_metric_002(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(2u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(2u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

pub fn deterministic_underwriter_metric_003(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(3u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(3u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

pub fn deterministic_underwriter_metric_004(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(4u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(4u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

pub fn deterministic_underwriter_metric_005(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(5u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(5u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

pub fn deterministic_underwriter_metric_006(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(6u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(6u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

pub fn deterministic_underwriter_metric_007(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(7u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(7u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

pub fn deterministic_underwriter_metric_008(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(8u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(8u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

pub fn deterministic_underwriter_metric_009(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(9u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(9u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

pub fn deterministic_underwriter_metric_010(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(10u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(10u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

pub fn deterministic_underwriter_metric_011(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(11u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(11u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

pub fn deterministic_underwriter_metric_012(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(12u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(12u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

pub fn deterministic_underwriter_metric_013(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(13u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(13u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

pub fn deterministic_underwriter_metric_014(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(14u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(14u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

pub fn deterministic_underwriter_metric_015(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(15u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(15u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

pub fn deterministic_underwriter_metric_016(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(16u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(16u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

pub fn deterministic_underwriter_metric_017(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(17u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(17u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

pub fn deterministic_underwriter_metric_018(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(18u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(18u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

pub fn deterministic_underwriter_metric_019(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(19u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(19u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

pub fn deterministic_underwriter_metric_020(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(20u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(20u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

pub fn deterministic_underwriter_metric_021(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(21u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(21u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

pub fn deterministic_underwriter_metric_022(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(22u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(22u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

pub fn deterministic_underwriter_metric_023(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(23u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(23u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

pub fn deterministic_underwriter_metric_024(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(24u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(24u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

pub fn deterministic_underwriter_metric_025(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(25u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(25u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

pub fn deterministic_underwriter_metric_026(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(26u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(26u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

pub fn deterministic_underwriter_metric_027(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(27u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(27u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

pub fn deterministic_underwriter_metric_028(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(28u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(28u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

pub fn deterministic_underwriter_metric_029(base_units: u64, risk_bps: u64) -> u64 {
    let adjusted = base_units.saturating_add(29u64);
    bps_mul(
        adjusted,
        risk_bps
            .saturating_add(29u64)
            .min(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS),
    )
}

fn underwriter_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-LIQUIDITY-INSURANCE-UNDERWRITER-{domain}"),
        parts,
        32,
    )
}
fn merkle_public_records(domain: &str, leaves: Vec<Value>) -> String {
    merkle_root(domain, &leaves)
}
fn ensure_non_empty(label: &str, value: &str) -> PrivateLiquidityInsuranceUnderwriterResult<()> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}
fn ensure_bps(label: &str, value: u64) -> PrivateLiquidityInsuranceUnderwriterResult<()> {
    if value > PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS {
        return Err(format!("{label} exceeds bps max"));
    }
    Ok(())
}
fn bps_mul(value: u64, bps: u64) -> u64 {
    value.saturating_mul(bps) / PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS
}
fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator.saturating_mul(PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_MAX_BPS) / denominator
}
fn devnet_hash(label: &str, index: u64) -> String {
    underwriter_hash(
        "DEVNET-SEED",
        &[HashPart::Str(label), HashPart::Int(index as i128)],
    )
}

fn make_devnet_vault(index: u64, height: u64) -> ConfidentialUnderwriterVault {
    let capacity = 12_000_000_u64.saturating_add(index.saturating_mul(3_000_000));
    ConfidentialUnderwriterVault {
        vault_id: format!("underwriter-vault-{index:02}"),
        operator_commitment: devnet_hash("vault-operator", index),
        capital_commitment_root: devnet_hash("vault-capital", index),
        encrypted_balance_root: devnet_hash("vault-balance", index),
        reserve_bucket_root: devnet_hash("vault-reserve-bucket", index),
        nullifier_root: devnet_hash("vault-nullifier", index),
        exposure_root: devnet_hash("vault-exposure", index),
        solvency_proof_root: devnet_hash("vault-solvency", index),
        committee_guardian_root: devnet_hash("vault-guardian", index),
        status: if index == 0 {
            UnderwriterVaultStatus::ExposureCapped
        } else {
            UnderwriterVaultStatus::Active
        },
        total_capacity_units: capacity,
        active_exposure_units: 0,
        reserved_claim_units: 0,
        paid_claim_units: index.saturating_mul(35_000),
        premium_collected_units: 0,
        rebate_liability_units: 0,
        utilization_bps: 0,
        solvency_bps: 12_500_u64.saturating_add(index.saturating_mul(250)),
        privacy_set_size: 1_280_u64.saturating_add(index.saturating_mul(128)),
        created_at_height: height.saturating_sub(96).saturating_add(index),
        updated_at_height: height,
    }
}
fn domain_for(index: u64) -> CoveredDomain {
    match index % 6 {
        0 => CoveredDomain::MoneroBridge,
        1 => CoveredDomain::PrivateDex,
        2 => CoveredDomain::LendingMarket,
        3 => CoveredDomain::StablecoinPeg,
        4 => CoveredDomain::PerpClearing,
        _ => CoveredDomain::CrossRollupBridge,
    }
}
fn make_devnet_policy(index: u64, height: u64, ttl: u64) -> BridgeDefiPolicyEnvelope {
    let domain = domain_for(index);
    let coverage = 480_000_u64.saturating_add(index.saturating_mul(75_000));
    BridgeDefiPolicyEnvelope {
        policy_id: format!("policy-{index:03}"),
        vault_id: format!("underwriter-vault-{:02}", index % 4),
        covered_domain: domain,
        insured_account_commitment: devnet_hash("insured-account", index),
        protocol_commitment: devnet_hash("insured-protocol", index),
        bridge_or_pool_id: format!("pool-or-bridge-{index:03}"),
        encrypted_terms_root: devnet_hash("policy-terms", index),
        covered_asset_root: devnet_hash("policy-asset", index),
        premium_note_commitment: devnet_hash("premium-note", index),
        premium_nullifier: devnet_hash("premium-nullifier", index),
        risk_attestation_root: devnet_hash("policy-risk", index),
        payout_address_commitment: devnet_hash("payout-address", index),
        status: if index % 5 == 0 {
            PolicyEnvelopeStatus::GracePeriod
        } else {
            PolicyEnvelopeStatus::Active
        },
        coverage_units: coverage,
        deductible_units: coverage / 20,
        premium_units: 1_200_u64.saturating_add(index.saturating_mul(110)),
        max_payout_units: coverage.saturating_sub(coverage / 20),
        risk_score_bps: domain
            .base_risk_bps()
            .saturating_add(index.saturating_mul(35)),
        rebate_bps: PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_LOW_FEE_REBATE_BPS,
        issued_at_height: height.saturating_sub(20).saturating_add(index),
        active_from_height: height.saturating_sub(16).saturating_add(index),
        expires_at_height: height.saturating_add(ttl / 2).saturating_add(index),
        updated_at_height: height,
    }
}
fn make_devnet_attestation(index: u64, height: u64, ttl: u64) -> RiskAttestation {
    let domain = domain_for(index);
    RiskAttestation {
        attestation_id: format!("risk-attestation-{index:03}"),
        policy_id: format!("policy-{index:03}"),
        vault_id: format!("underwriter-vault-{:02}", index % 4),
        attester_id: format!("claims-committee-member-{:02}", index % 8),
        covered_domain: domain,
        sealed_risk_vector_root: devnet_hash("attestation-risk-vector", index),
        range_proof_root: devnet_hash("attestation-range-proof", index),
        oracle_context_root: devnet_hash("attestation-oracle", index),
        liquidity_depth_root: devnet_hash("attestation-depth", index),
        reserve_health_root: devnet_hash("attestation-reserve", index),
        transcript_root: devnet_hash("attestation-transcript", index),
        status: RiskAttestationStatus::Counted,
        risk_score_bps: domain
            .base_risk_bps()
            .saturating_add(index.saturating_mul(25)),
        confidence_bps: 8_200_u64.saturating_sub(index.saturating_mul(20)),
        privacy_set_size: 1_536_u64.saturating_add(index.saturating_mul(16)),
        valid_from_height: height.saturating_sub(4),
        expires_at_height: height.saturating_add(ttl / 2),
        submitted_at_height: height.saturating_sub(6),
    }
}
fn make_devnet_claim(index: u64, height: u64, challenge_blocks: u64) -> ClaimQueueEntry {
    let claimed = 80_000_u64.saturating_add(index.saturating_mul(15_000));
    ClaimQueueEntry {
        claim_id: format!("claim-{index:03}"),
        policy_id: format!("policy-{index:03}"),
        vault_id: format!("underwriter-vault-{:02}", index % 4),
        claimant_commitment: devnet_hash("claimant", index),
        incident_commitment: devnet_hash("incident", index),
        loss_proof_root: devnet_hash("loss-proof", index),
        private_loss_bucket_root: devnet_hash("loss-bucket", index),
        committee_vote_root: devnet_hash("claim-vote", index),
        payout_address_commitment: devnet_hash("claim-payout-address", index),
        challenge_window_end_height: height
            .saturating_add(challenge_blocks / 2)
            .saturating_add(index),
        priority_score: 1_000_u64.saturating_sub(index.saturating_mul(20)),
        status: if index % 2 == 0 {
            ClaimStatus::CommitteeReview
        } else {
            ClaimStatus::Queued
        },
        claimed_units: claimed,
        approved_units: if index % 2 == 0 {
            claimed.saturating_sub(10_000)
        } else {
            0
        },
        deductible_applied_units: 10_000,
        queued_at_height: height.saturating_sub(12).saturating_add(index),
        updated_at_height: height,
    }
}
fn make_devnet_payout(index: u64, height: u64, window_blocks: u64) -> PayoutThrottle {
    let requested = 70_000_u64.saturating_add(index.saturating_mul(12_000));
    PayoutThrottle {
        payout_id: format!("payout-{index:03}"),
        claim_id: format!("claim-{index:03}"),
        policy_id: format!("policy-{index:03}"),
        vault_id: format!("underwriter-vault-{:02}", index % 4),
        throttle_window_id: format!("payout-window-{:03}", height / window_blocks.max(1)),
        payout_note_commitment: devnet_hash("payout-note", index),
        payout_nullifier: devnet_hash("payout-nullifier", index),
        committee_signature_root: devnet_hash("payout-signature", index),
        status: if index == 0 {
            PayoutStatus::Released
        } else {
            PayoutStatus::Throttled
        },
        requested_units: requested,
        released_units: requested / 2,
        deferred_units: requested.saturating_sub(requested / 2),
        window_start_height: height,
        window_end_height: height.saturating_add(window_blocks),
        scheduled_at_height: height,
        released_at_height: if index == 0 { height } else { 0 },
    }
}
fn make_devnet_rebate(index: u64, height: u64, window_blocks: u64) -> PremiumRebateCredit {
    let premium = 1_200_u64.saturating_add(index.saturating_mul(110));
    let rebate_bps = PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_LOW_FEE_REBATE_BPS;
    PremiumRebateCredit {
        rebate_id: format!("rebate-{index:03}"),
        policy_id: format!("policy-{index:03}"),
        vault_id: format!("underwriter-vault-{:02}", index % 4),
        beneficiary_commitment: devnet_hash("rebate-beneficiary", index),
        premium_note_commitment: devnet_hash("premium-note", index),
        rebate_note_commitment: devnet_hash("rebate-note", index),
        rebate_nullifier: devnet_hash("rebate-nullifier", index),
        low_fee_lane_id: "low-fee-private-insurance-premium".to_string(),
        status: if index % 3 == 0 {
            RebateStatus::Claimable
        } else {
            RebateStatus::Accrued
        },
        premium_units: premium,
        rebate_units: bps_mul(premium, rebate_bps),
        rebate_bps,
        accrued_at_height: height.saturating_sub(8),
        claimable_at_height: height.saturating_add(4),
        expires_at_height: height.saturating_add(window_blocks),
    }
}
fn make_devnet_member(index: u64, height: u64) -> PqClaimsCommitteeMember {
    let role = match index % 6 {
        0 => ClaimsCommitteeRole::ClaimReviewer,
        1 => ClaimsCommitteeRole::RiskAttester,
        2 => ClaimsCommitteeRole::PayoutSigner,
        3 => ClaimsCommitteeRole::ChallengeJudge,
        4 => ClaimsCommitteeRole::SlashingWatcher,
        _ => ClaimsCommitteeRole::RebateAuditor,
    };
    PqClaimsCommitteeMember {
        member_id: format!("claims-committee-member-{index:02}"),
        operator_commitment: devnet_hash("committee-operator", index),
        pq_public_key_root: devnet_hash("committee-pq-key", index),
        backup_public_key_root: devnet_hash("committee-backup-key", index),
        role,
        status: CommitteeMemberStatus::Active,
        stake_units: 250_000_u64.saturating_add(index.saturating_mul(10_000)),
        voting_weight_bps: 1_250,
        joined_at_height: height.saturating_sub(200).saturating_add(index),
        updated_at_height: height,
    }
}
fn make_devnet_challenge(index: u64, height: u64) -> ChallengeSlashingEvidence {
    let slash_units = 25_000_u64.saturating_add(index.saturating_mul(5_000));
    ChallengeSlashingEvidence {
        challenge_id: format!("challenge-{index:03}"),
        target_kind: "risk_attestation".to_string(),
        target_id: format!("risk-attestation-{index:03}"),
        reporter_commitment: devnet_hash("challenge-reporter", index),
        accused_member_id: format!("claims-committee-member-{index:02}"),
        evidence_root: devnet_hash("challenge-evidence", index),
        transcript_root: devnet_hash("challenge-transcript", index),
        conflicting_commitment_root: devnet_hash("challenge-conflict", index),
        status: ChallengeStatus::EvidenceAccepted,
        slash_units,
        reporter_reward_units: bps_mul(
            slash_units,
            PRIVATE_LIQUIDITY_INSURANCE_UNDERWRITER_DEFAULT_REPORTER_REWARD_BPS,
        ),
        filed_at_height: height.saturating_sub(2),
        resolved_at_height: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_state_validates_and_is_deterministic() {
        let left = PrivateLiquidityInsuranceUnderwriterState::devnet();
        let right = PrivateLiquidityInsuranceUnderwriterState::devnet();
        assert!(left.is_ok());
        assert!(right.is_ok());
        if let (Ok(left_state), Ok(right_state)) = (left, right) {
            assert_eq!(left_state.state_root(), right_state.state_root());
            assert!(left_state.validate().is_ok());
        }
    }

    #[test]
    fn height_update_is_monotonic() {
        let state = PrivateLiquidityInsuranceUnderwriterState::devnet();
        assert!(state.is_ok());
        if let Ok(mut state) = state {
            let current = state.height;
            assert!(state.update_height(current + 1).is_ok());
            assert!(state.update_height(current.saturating_sub(1)).is_err());
        }
    }
}
