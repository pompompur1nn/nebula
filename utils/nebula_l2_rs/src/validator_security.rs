use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ValidatorSecurityResult<T> = Result<T, String>;

pub const VALIDATOR_SECURITY_PROTOCOL_VERSION: &str = "nebula-l2-validator-security-v1";
pub const VALIDATOR_SECURITY_DEVNET_HEIGHT: u64 = 64;
pub const VALIDATOR_SECURITY_DEVNET_ASSET_ID: &str = "dnr-devnet";
pub const VALIDATOR_SECURITY_DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const VALIDATOR_SECURITY_DEVNET_BRIDGE_ASSET_ID: &str = "wxmr-devnet";
pub const VALIDATOR_SECURITY_DEFAULT_EPOCH_LENGTH_BLOCKS: u64 = 720;
pub const VALIDATOR_SECURITY_DEFAULT_COMMITTEE_SIZE_TARGET: usize = 8;
pub const VALIDATOR_SECURITY_DEFAULT_MIN_VALIDATOR_STAKE_UNITS: u64 = 1_000_000;
pub const VALIDATOR_SECURITY_DEFAULT_MIN_BRIDGE_BOND_UNITS: u64 = 250_000;
pub const VALIDATOR_SECURITY_DEFAULT_MIN_PROVER_BOND_UNITS: u64 = 150_000;
pub const VALIDATOR_SECURITY_DEFAULT_UNBONDING_DELAY_BLOCKS: u64 = 2_880;
pub const VALIDATOR_SECURITY_DEFAULT_WITHDRAWAL_CHALLENGE_BLOCKS: u64 = 144;
pub const VALIDATOR_SECURITY_DEFAULT_KEY_ROTATION_GRACE_BLOCKS: u64 = 96;
pub const VALIDATOR_SECURITY_DEFAULT_LIVENESS_WINDOW_BLOCKS: u64 = 72;
pub const VALIDATOR_SECURITY_DEFAULT_DOWNTIME_JAIL_THRESHOLD_BPS: u64 = 2_000;
pub const VALIDATOR_SECURITY_DEFAULT_DOWNTIME_SLASH_THRESHOLD_BPS: u64 = 5_000;
pub const VALIDATOR_SECURITY_DEFAULT_MISSED_SLOT_SLASH_BPS: u64 = 100;
pub const VALIDATOR_SECURITY_DEFAULT_EQUIVOCATION_SLASH_BPS: u64 = 4_000;
pub const VALIDATOR_SECURITY_DEFAULT_INVALID_PROOF_SLASH_BPS: u64 = 2_500;
pub const VALIDATOR_SECURITY_DEFAULT_BRIDGE_FAULT_SLASH_BPS: u64 = 5_000;
pub const VALIDATOR_SECURITY_DEFAULT_CHALLENGE_PERIOD_BLOCKS: u64 = 144;
pub const VALIDATOR_SECURITY_DEFAULT_CHALLENGE_RESPONSE_BLOCKS: u64 = 48;
pub const VALIDATOR_SECURITY_DEFAULT_MAX_ACTIVE_CHALLENGES: usize = 256;
pub const VALIDATOR_SECURITY_DEFAULT_COVERAGE_TARGET_BPS: u64 = 12_000;
pub const VALIDATOR_SECURITY_DEFAULT_RESERVE_MIN_COVERAGE_BPS: u64 = 10_000;
pub const VALIDATOR_SECURITY_DEFAULT_LOW_FEE_EPOCH_BUDGET_UNITS: u64 = 500_000;
pub const VALIDATOR_SECURITY_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 8_500;
pub const VALIDATOR_SECURITY_DEFAULT_MIN_SUBSIDY_BALANCE_UNITS: u64 = 25_000;
pub const VALIDATOR_SECURITY_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorPqAlgorithm {
    MlDsa65,
    SlhDsaShake128s,
    Falcon1024,
    Dilithium5,
    Kyber1024Kem,
    HybridThreshold,
}

impl ValidatorPqAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa65 => "ml-dsa-65",
            Self::SlhDsaShake128s => "slh-dsa-shake-128s",
            Self::Falcon1024 => "falcon-1024",
            Self::Dilithium5 => "dilithium5",
            Self::Kyber1024Kem => "kyber-1024-kem",
            Self::HybridThreshold => "hybrid-threshold-pq",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorRole {
    BlockProducer,
    Prover,
    BridgeObserver,
    BridgeSigner,
    ReserveAuditor,
    FeeSponsor,
    ChallengeJudge,
}

impl ValidatorRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BlockProducer => "block_producer",
            Self::Prover => "prover",
            Self::BridgeObserver => "bridge_observer",
            Self::BridgeSigner => "bridge_signer",
            Self::ReserveAuditor => "reserve_auditor",
            Self::FeeSponsor => "fee_sponsor",
            Self::ChallengeJudge => "challenge_judge",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorStatus {
    Candidate,
    Active,
    Jailed,
    Exiting,
    Retired,
    Slashed,
}

impl ValidatorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::Jailed => "jailed",
            Self::Exiting => "exiting",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn can_join_committee(self) -> bool {
        matches!(self, Self::Candidate | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StakePositionStatus {
    Bonded,
    Unbonding,
    Withdrawable,
    Withdrawn,
    Slashed,
    Frozen,
}

impl StakePositionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bonded => "bonded",
            Self::Unbonding => "unbonding",
            Self::Withdrawable => "withdrawable",
            Self::Withdrawn => "withdrawn",
            Self::Slashed => "slashed",
            Self::Frozen => "frozen",
        }
    }

    pub fn is_locked(self) -> bool {
        matches!(self, Self::Bonded | Self::Unbonding | Self::Frozen)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeEpochStatus {
    Scheduled,
    Active,
    Grace,
    Retired,
    Slashed,
}

impl CommitteeEpochStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Active => "active",
            Self::Grace => "grace",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn accepts_work(self) -> bool {
        matches!(self, Self::Scheduled | Self::Active | Self::Grace)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingEvidenceKind {
    Equivocation,
    InvalidProof,
    BridgeCustodyFault,
    ReserveMisreport,
    Downtime,
    KeyCompromise,
    ChallengeFraud,
}

impl SlashingEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Equivocation => "equivocation",
            Self::InvalidProof => "invalid_proof",
            Self::BridgeCustodyFault => "bridge_custody_fault",
            Self::ReserveMisreport => "reserve_misreport",
            Self::Downtime => "downtime",
            Self::KeyCompromise => "key_compromise",
            Self::ChallengeFraud => "challenge_fraud",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Submitted,
    Accepted,
    Rejected,
    Expired,
    Superseded,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Superseded => "superseded",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(self, Self::Submitted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LivenessWindowStatus {
    Healthy,
    Warning,
    Jailable,
    Slashable,
}

impl LivenessWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Warning => "warning",
            Self::Jailable => "jailable",
            Self::Slashable => "slashable",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRotationStatus {
    Announced,
    Attesting,
    Effective,
    Expired,
    Cancelled,
}

impl KeyRotationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Announced => "announced",
            Self::Attesting => "attesting",
            Self::Effective => "effective",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalStatus {
    Requested,
    ChallengeOpen,
    Delayed,
    Withdrawable,
    Completed,
    Cancelled,
    Slashed,
}

impl WithdrawalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::ChallengeOpen => "challenge_open",
            Self::Delayed => "delayed",
            Self::Withdrawable => "withdrawable",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::Slashed => "slashed",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Requested | Self::ChallengeOpen | Self::Delayed | Self::Withdrawable
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    Withdrawal,
    SlashingEvidence,
    CommitteeSelection,
    LivenessScore,
    CoverageClaim,
    SubsidyReward,
    KeyRotation,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Withdrawal => "withdrawal",
            Self::SlashingEvidence => "slashing_evidence",
            Self::CommitteeSelection => "committee_selection",
            Self::LivenessScore => "liveness_score",
            Self::CoverageClaim => "coverage_claim",
            Self::SubsidyReward => "subsidy_reward",
            Self::KeyRotation => "key_rotation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    Responded,
    Sustained,
    Dismissed,
    Expired,
    Cancelled,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Responded => "responded",
            Self::Sustained => "sustained",
            Self::Dismissed => "dismissed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(self, Self::Open | Self::Responded)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeDecision {
    Pending,
    ChallengerWins,
    RespondentWins,
    Split,
    Expired,
}

impl ChallengeDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::ChallengerWins => "challenger_wins",
            Self::RespondentWins => "respondent_wins",
            Self::Split => "split",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoveragePoolKind {
    BridgeCustody,
    InvalidProof,
    Reorg,
    ReserveShortfall,
    LowFeeBackstop,
}

impl CoveragePoolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeCustody => "bridge_custody",
            Self::InvalidProof => "invalid_proof",
            Self::Reorg => "reorg",
            Self::ReserveShortfall => "reserve_shortfall",
            Self::LowFeeBackstop => "low_fee_backstop",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoveragePoolStatus {
    Active,
    Depleted,
    Expired,
    Paused,
}

impl CoveragePoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Depleted => "depleted",
            Self::Expired => "expired",
            Self::Paused => "paused",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageClaimStatus {
    Open,
    Reserved,
    Approved,
    Rejected,
    Paid,
    Expired,
}

impl CoverageClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Paid => "paid",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubsidyStatus {
    Active,
    Exhausted,
    Settled,
    Expired,
}

impl SubsidyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Exhausted => "exhausted",
            Self::Settled => "settled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorSecurityEventKind {
    ValidatorRegistered,
    StakeBonded,
    BondLocked,
    CommitteeOpened,
    LivenessReported,
    EvidenceSubmitted,
    SlashApplied,
    KeyRotationStarted,
    WithdrawalRequested,
    WithdrawalCompleted,
    ChallengeOpened,
    ChallengeAdjudicated,
    CoveragePoolFunded,
    CoverageClaimAdjudicated,
    SubsidyRewarded,
    HeightAdvanced,
    DevnetGenesis,
}

impl ValidatorSecurityEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ValidatorRegistered => "validator_registered",
            Self::StakeBonded => "stake_bonded",
            Self::BondLocked => "bond_locked",
            Self::CommitteeOpened => "committee_opened",
            Self::LivenessReported => "liveness_reported",
            Self::EvidenceSubmitted => "evidence_submitted",
            Self::SlashApplied => "slash_applied",
            Self::KeyRotationStarted => "key_rotation_started",
            Self::WithdrawalRequested => "withdrawal_requested",
            Self::WithdrawalCompleted => "withdrawal_completed",
            Self::ChallengeOpened => "challenge_opened",
            Self::ChallengeAdjudicated => "challenge_adjudicated",
            Self::CoveragePoolFunded => "coverage_pool_funded",
            Self::CoverageClaimAdjudicated => "coverage_claim_adjudicated",
            Self::SubsidyRewarded => "subsidy_rewarded",
            Self::HeightAdvanced => "height_advanced",
            Self::DevnetGenesis => "devnet_genesis",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSecurityConfig {
    pub protocol_version: String,
    pub epoch_length_blocks: u64,
    pub committee_size_target: usize,
    pub min_validator_stake_units: u64,
    pub min_bridge_bond_units: u64,
    pub min_prover_bond_units: u64,
    pub unbonding_delay_blocks: u64,
    pub withdrawal_challenge_blocks: u64,
    pub key_rotation_grace_blocks: u64,
    pub liveness_window_blocks: u64,
    pub downtime_jail_threshold_bps: u64,
    pub downtime_slash_threshold_bps: u64,
    pub missed_slot_slash_bps: u64,
    pub equivocation_slash_bps: u64,
    pub invalid_proof_slash_bps: u64,
    pub bridge_fault_slash_bps: u64,
    pub challenge_period_blocks: u64,
    pub challenge_response_blocks: u64,
    pub max_active_challenges: usize,
    pub coverage_target_bps: u64,
    pub reserve_min_coverage_bps: u64,
    pub low_fee_epoch_budget_units: u64,
    pub low_fee_rebate_bps: u64,
    pub min_subsidy_balance_units: u64,
}

impl Default for ValidatorSecurityConfig {
    fn default() -> Self {
        Self {
            protocol_version: VALIDATOR_SECURITY_PROTOCOL_VERSION.to_string(),
            epoch_length_blocks: VALIDATOR_SECURITY_DEFAULT_EPOCH_LENGTH_BLOCKS,
            committee_size_target: VALIDATOR_SECURITY_DEFAULT_COMMITTEE_SIZE_TARGET,
            min_validator_stake_units: VALIDATOR_SECURITY_DEFAULT_MIN_VALIDATOR_STAKE_UNITS,
            min_bridge_bond_units: VALIDATOR_SECURITY_DEFAULT_MIN_BRIDGE_BOND_UNITS,
            min_prover_bond_units: VALIDATOR_SECURITY_DEFAULT_MIN_PROVER_BOND_UNITS,
            unbonding_delay_blocks: VALIDATOR_SECURITY_DEFAULT_UNBONDING_DELAY_BLOCKS,
            withdrawal_challenge_blocks: VALIDATOR_SECURITY_DEFAULT_WITHDRAWAL_CHALLENGE_BLOCKS,
            key_rotation_grace_blocks: VALIDATOR_SECURITY_DEFAULT_KEY_ROTATION_GRACE_BLOCKS,
            liveness_window_blocks: VALIDATOR_SECURITY_DEFAULT_LIVENESS_WINDOW_BLOCKS,
            downtime_jail_threshold_bps: VALIDATOR_SECURITY_DEFAULT_DOWNTIME_JAIL_THRESHOLD_BPS,
            downtime_slash_threshold_bps: VALIDATOR_SECURITY_DEFAULT_DOWNTIME_SLASH_THRESHOLD_BPS,
            missed_slot_slash_bps: VALIDATOR_SECURITY_DEFAULT_MISSED_SLOT_SLASH_BPS,
            equivocation_slash_bps: VALIDATOR_SECURITY_DEFAULT_EQUIVOCATION_SLASH_BPS,
            invalid_proof_slash_bps: VALIDATOR_SECURITY_DEFAULT_INVALID_PROOF_SLASH_BPS,
            bridge_fault_slash_bps: VALIDATOR_SECURITY_DEFAULT_BRIDGE_FAULT_SLASH_BPS,
            challenge_period_blocks: VALIDATOR_SECURITY_DEFAULT_CHALLENGE_PERIOD_BLOCKS,
            challenge_response_blocks: VALIDATOR_SECURITY_DEFAULT_CHALLENGE_RESPONSE_BLOCKS,
            max_active_challenges: VALIDATOR_SECURITY_DEFAULT_MAX_ACTIVE_CHALLENGES,
            coverage_target_bps: VALIDATOR_SECURITY_DEFAULT_COVERAGE_TARGET_BPS,
            reserve_min_coverage_bps: VALIDATOR_SECURITY_DEFAULT_RESERVE_MIN_COVERAGE_BPS,
            low_fee_epoch_budget_units: VALIDATOR_SECURITY_DEFAULT_LOW_FEE_EPOCH_BUDGET_UNITS,
            low_fee_rebate_bps: VALIDATOR_SECURITY_DEFAULT_LOW_FEE_REBATE_BPS,
            min_subsidy_balance_units: VALIDATOR_SECURITY_DEFAULT_MIN_SUBSIDY_BALANCE_UNITS,
        }
    }
}

impl ValidatorSecurityConfig {
    pub fn validate(&self) -> ValidatorSecurityResult<String> {
        ensure_non_empty(
            &self.protocol_version,
            "validator security protocol version",
        )?;
        if self.protocol_version != VALIDATOR_SECURITY_PROTOCOL_VERSION {
            return Err("validator security protocol version mismatch".to_string());
        }
        ensure_positive(self.epoch_length_blocks, "epoch length blocks")?;
        if self.committee_size_target == 0 {
            return Err("committee size target must be non-zero".to_string());
        }
        ensure_positive(
            self.min_validator_stake_units,
            "minimum validator stake units",
        )?;
        ensure_positive(self.unbonding_delay_blocks, "unbonding delay blocks")?;
        ensure_positive(
            self.withdrawal_challenge_blocks,
            "withdrawal challenge blocks",
        )?;
        ensure_positive(self.key_rotation_grace_blocks, "key rotation grace blocks")?;
        ensure_positive(self.liveness_window_blocks, "liveness window blocks")?;
        ensure_bps(
            self.downtime_jail_threshold_bps,
            "downtime jail threshold bps",
        )?;
        ensure_bps(
            self.downtime_slash_threshold_bps,
            "downtime slash threshold bps",
        )?;
        ensure_bps(self.missed_slot_slash_bps, "missed slot slash bps")?;
        ensure_bps(self.equivocation_slash_bps, "equivocation slash bps")?;
        ensure_bps(self.invalid_proof_slash_bps, "invalid proof slash bps")?;
        ensure_bps(self.bridge_fault_slash_bps, "bridge fault slash bps")?;
        ensure_positive(self.challenge_period_blocks, "challenge period blocks")?;
        ensure_positive(self.challenge_response_blocks, "challenge response blocks")?;
        if self.challenge_response_blocks > self.challenge_period_blocks {
            return Err("challenge response blocks exceed challenge period".to_string());
        }
        if self.max_active_challenges == 0 {
            return Err("max active challenges must be non-zero".to_string());
        }
        if self.coverage_target_bps < VALIDATOR_SECURITY_MAX_BPS {
            return Err("coverage target bps must cover at least 100%".to_string());
        }
        if self.reserve_min_coverage_bps < VALIDATOR_SECURITY_MAX_BPS {
            return Err("reserve minimum coverage bps must cover at least 100%".to_string());
        }
        ensure_bps(self.low_fee_rebate_bps, "low fee rebate bps")?;
        ensure_positive(
            self.min_subsidy_balance_units,
            "minimum subsidy balance units",
        )?;
        Ok(self.config_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "validator_security_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "epoch_length_blocks": self.epoch_length_blocks,
            "committee_size_target": self.committee_size_target as u64,
            "min_validator_stake_units": self.min_validator_stake_units,
            "min_bridge_bond_units": self.min_bridge_bond_units,
            "min_prover_bond_units": self.min_prover_bond_units,
            "unbonding_delay_blocks": self.unbonding_delay_blocks,
            "withdrawal_challenge_blocks": self.withdrawal_challenge_blocks,
            "key_rotation_grace_blocks": self.key_rotation_grace_blocks,
            "liveness_window_blocks": self.liveness_window_blocks,
            "downtime_jail_threshold_bps": self.downtime_jail_threshold_bps,
            "downtime_slash_threshold_bps": self.downtime_slash_threshold_bps,
            "missed_slot_slash_bps": self.missed_slot_slash_bps,
            "equivocation_slash_bps": self.equivocation_slash_bps,
            "invalid_proof_slash_bps": self.invalid_proof_slash_bps,
            "bridge_fault_slash_bps": self.bridge_fault_slash_bps,
            "challenge_period_blocks": self.challenge_period_blocks,
            "challenge_response_blocks": self.challenge_response_blocks,
            "max_active_challenges": self.max_active_challenges as u64,
            "coverage_target_bps": self.coverage_target_bps,
            "reserve_min_coverage_bps": self.reserve_min_coverage_bps,
            "low_fee_epoch_budget_units": self.low_fee_epoch_budget_units,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "min_subsidy_balance_units": self.min_subsidy_balance_units,
        })
    }

    pub fn config_root(&self) -> String {
        validator_security_payload_root("VALIDATOR-SECURITY-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqPublicKeySet {
    pub key_set_id: String,
    pub owner_label: String,
    pub consensus_sig_algorithm: ValidatorPqAlgorithm,
    pub consensus_public_key_hash: String,
    pub session_kem_algorithm: ValidatorPqAlgorithm,
    pub session_public_key_hash: String,
    pub bridge_sig_algorithm: ValidatorPqAlgorithm,
    pub bridge_public_key_hash: String,
    pub proof_of_possession_root: String,
    pub attestation_root: String,
    pub added_height: u64,
    pub expires_height: u64,
    pub revoked_height: Option<u64>,
}

impl PqPublicKeySet {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_label: impl Into<String>,
        consensus_sig_algorithm: ValidatorPqAlgorithm,
        consensus_public_key_hash: impl Into<String>,
        session_kem_algorithm: ValidatorPqAlgorithm,
        session_public_key_hash: impl Into<String>,
        bridge_sig_algorithm: ValidatorPqAlgorithm,
        bridge_public_key_hash: impl Into<String>,
        proof_of_possession_root: impl Into<String>,
        attestation_root: impl Into<String>,
        added_height: u64,
        expires_height: u64,
    ) -> ValidatorSecurityResult<Self> {
        let owner_label = owner_label.into();
        let consensus_public_key_hash = consensus_public_key_hash.into();
        let session_public_key_hash = session_public_key_hash.into();
        let bridge_public_key_hash = bridge_public_key_hash.into();
        let proof_of_possession_root = proof_of_possession_root.into();
        let attestation_root = attestation_root.into();
        ensure_non_empty(&owner_label, "validator key owner label")?;
        ensure_non_empty(
            &consensus_public_key_hash,
            "validator consensus public key hash",
        )?;
        ensure_non_empty(
            &session_public_key_hash,
            "validator session public key hash",
        )?;
        ensure_non_empty(&bridge_public_key_hash, "validator bridge public key hash")?;
        ensure_non_empty(
            &proof_of_possession_root,
            "validator proof-of-possession root",
        )?;
        ensure_height_window(added_height, expires_height, "validator key set validity")?;
        let identity_record = json!({
            "chain_id": CHAIN_ID,
            "owner_label": owner_label,
            "consensus_sig_algorithm": consensus_sig_algorithm.as_str(),
            "consensus_public_key_hash": consensus_public_key_hash,
            "session_kem_algorithm": session_kem_algorithm.as_str(),
            "session_public_key_hash": session_public_key_hash,
            "bridge_sig_algorithm": bridge_sig_algorithm.as_str(),
            "bridge_public_key_hash": bridge_public_key_hash,
            "proof_of_possession_root": proof_of_possession_root,
            "attestation_root": attestation_root,
            "added_height": added_height,
            "expires_height": expires_height,
        });
        let key_set_id =
            validator_security_payload_root("VALIDATOR-PQ-KEY-SET-ID", &identity_record);
        Ok(Self {
            key_set_id,
            owner_label,
            consensus_sig_algorithm,
            consensus_public_key_hash,
            session_kem_algorithm,
            session_public_key_hash,
            bridge_sig_algorithm,
            bridge_public_key_hash,
            proof_of_possession_root,
            attestation_root,
            added_height,
            expires_height,
            revoked_height: None,
        })
    }

    pub fn devnet(owner_label: &str, key_index: u64, height: u64) -> ValidatorSecurityResult<Self> {
        Self::new(
            owner_label,
            ValidatorPqAlgorithm::MlDsa65,
            validator_security_string_root(
                "VALIDATOR-SECURITY-DEVNET-CONSENSUS-KEY",
                &format!("{owner_label}:{key_index}"),
            ),
            ValidatorPqAlgorithm::Kyber1024Kem,
            validator_security_string_root(
                "VALIDATOR-SECURITY-DEVNET-SESSION-KEY",
                &format!("{owner_label}:{key_index}"),
            ),
            ValidatorPqAlgorithm::Dilithium5,
            validator_security_string_root(
                "VALIDATOR-SECURITY-DEVNET-BRIDGE-KEY",
                &format!("{owner_label}:{key_index}"),
            ),
            validator_security_string_root(
                "VALIDATOR-SECURITY-DEVNET-POP",
                &format!("{owner_label}:{key_index}"),
            ),
            validator_security_string_root(
                "VALIDATOR-SECURITY-DEVNET-KEY-ATTESTATION",
                &format!("{owner_label}:{key_index}"),
            ),
            height,
            height.saturating_add(20_000),
        )
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.added_height <= height
            && height <= self.expires_height
            && self.revoked_height.map_or(true, |revoked| height < revoked)
    }

    pub fn revoke(&mut self, height: u64) -> ValidatorSecurityResult<String> {
        if height < self.added_height {
            return Err("validator key revocation precedes key activation".to_string());
        }
        self.revoked_height = Some(height);
        Ok(self.key_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "validator_pq_public_key_set",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "key_set_id": self.key_set_id,
            "owner_label": self.owner_label,
            "consensus_sig_algorithm": self.consensus_sig_algorithm.as_str(),
            "consensus_public_key_hash": self.consensus_public_key_hash,
            "session_kem_algorithm": self.session_kem_algorithm.as_str(),
            "session_public_key_hash": self.session_public_key_hash,
            "bridge_sig_algorithm": self.bridge_sig_algorithm.as_str(),
            "bridge_public_key_hash": self.bridge_public_key_hash,
            "proof_of_possession_root": self.proof_of_possession_root,
            "attestation_root": self.attestation_root,
            "added_height": self.added_height,
            "expires_height": self.expires_height,
            "revoked_height": self.revoked_height,
            "key_root": self.key_root(),
        })
    }

    pub fn key_root(&self) -> String {
        validator_security_payload_root("VALIDATOR-PQ-KEY-SET", &self.public_record_without_root())
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "validator_pq_public_key_set",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "key_set_id": self.key_set_id,
            "owner_label": self.owner_label,
            "consensus_sig_algorithm": self.consensus_sig_algorithm.as_str(),
            "consensus_public_key_hash": self.consensus_public_key_hash,
            "session_kem_algorithm": self.session_kem_algorithm.as_str(),
            "session_public_key_hash": self.session_public_key_hash,
            "bridge_sig_algorithm": self.bridge_sig_algorithm.as_str(),
            "bridge_public_key_hash": self.bridge_public_key_hash,
            "proof_of_possession_root": self.proof_of_possession_root,
            "attestation_root": self.attestation_root,
            "added_height": self.added_height,
            "expires_height": self.expires_height,
            "revoked_height": self.revoked_height,
        })
    }

    pub fn validate(&self) -> ValidatorSecurityResult<String> {
        ensure_non_empty(&self.key_set_id, "validator key set id")?;
        ensure_non_empty(&self.owner_label, "validator key owner label")?;
        ensure_non_empty(
            &self.consensus_public_key_hash,
            "validator consensus public key hash",
        )?;
        ensure_non_empty(
            &self.session_public_key_hash,
            "validator session public key hash",
        )?;
        ensure_non_empty(
            &self.bridge_public_key_hash,
            "validator bridge public key hash",
        )?;
        ensure_non_empty(
            &self.proof_of_possession_root,
            "validator proof-of-possession root",
        )?;
        ensure_height_window(self.added_height, self.expires_height, "validator key set")?;
        if let Some(revoked_height) = self.revoked_height {
            if revoked_height < self.added_height {
                return Err("validator key set revoked before it was added".to_string());
            }
        }
        let expected_id = validator_security_payload_root(
            "VALIDATOR-PQ-KEY-SET-ID",
            &json!({
                "chain_id": CHAIN_ID,
                "owner_label": self.owner_label,
                "consensus_sig_algorithm": self.consensus_sig_algorithm.as_str(),
                "consensus_public_key_hash": self.consensus_public_key_hash,
                "session_kem_algorithm": self.session_kem_algorithm.as_str(),
                "session_public_key_hash": self.session_public_key_hash,
                "bridge_sig_algorithm": self.bridge_sig_algorithm.as_str(),
                "bridge_public_key_hash": self.bridge_public_key_hash,
                "proof_of_possession_root": self.proof_of_possession_root,
                "attestation_root": self.attestation_root,
                "added_height": self.added_height,
                "expires_height": self.expires_height,
            }),
        );
        if expected_id != self.key_set_id {
            return Err("validator key set id does not match deterministic record".to_string());
        }
        Ok(self.key_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorIdentity {
    pub validator_id: String,
    pub operator_label: String,
    pub account_commitment: String,
    pub payout_commitment: String,
    pub network_address_hash: String,
    pub metadata_root: String,
    pub current_key_set_id: String,
    pub key_set_root: String,
    pub roles: BTreeSet<ValidatorRole>,
    pub status: ValidatorStatus,
    pub activation_height: u64,
    pub jailed_until_height: u64,
    pub total_stake_units: u64,
    pub total_bond_units: u64,
    pub slash_reserved_units: u64,
    pub reputation_score_bps: u64,
    pub consecutive_missed_windows: u64,
}

impl ValidatorIdentity {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operator_label: impl Into<String>,
        account_commitment: impl Into<String>,
        payout_commitment: impl Into<String>,
        network_address_hash: impl Into<String>,
        metadata_root: impl Into<String>,
        roles: BTreeSet<ValidatorRole>,
        key_set: &PqPublicKeySet,
        activation_height: u64,
    ) -> ValidatorSecurityResult<Self> {
        let operator_label = operator_label.into();
        let account_commitment = account_commitment.into();
        let payout_commitment = payout_commitment.into();
        let network_address_hash = network_address_hash.into();
        let metadata_root = metadata_root.into();
        ensure_non_empty(&operator_label, "validator operator label")?;
        ensure_non_empty(&account_commitment, "validator account commitment")?;
        ensure_non_empty(&payout_commitment, "validator payout commitment")?;
        ensure_non_empty(&network_address_hash, "validator network address hash")?;
        ensure_non_empty(&metadata_root, "validator metadata root")?;
        if roles.is_empty() {
            return Err("validator must have at least one role".to_string());
        }
        key_set.validate()?;
        let role_strings = validator_role_strings(&roles);
        let key_set_root = key_set.key_root();
        let identity_record = json!({
            "chain_id": CHAIN_ID,
            "operator_label": operator_label,
            "account_commitment": account_commitment,
            "payout_commitment": payout_commitment,
            "network_address_hash": network_address_hash,
            "metadata_root": metadata_root,
            "current_key_set_id": key_set.key_set_id,
            "key_set_root": key_set_root,
            "roles": role_strings,
            "activation_height": activation_height,
        });
        let validator_id =
            validator_security_payload_root("VALIDATOR-IDENTITY-ID", &identity_record);
        Ok(Self {
            validator_id,
            operator_label,
            account_commitment,
            payout_commitment,
            network_address_hash,
            metadata_root,
            current_key_set_id: key_set.key_set_id.clone(),
            key_set_root,
            roles,
            status: ValidatorStatus::Candidate,
            activation_height,
            jailed_until_height: 0,
            total_stake_units: 0,
            total_bond_units: 0,
            slash_reserved_units: 0,
            reputation_score_bps: VALIDATOR_SECURITY_MAX_BPS,
            consecutive_missed_windows: 0,
        })
    }

    pub fn has_role(&self, role: ValidatorRole) -> bool {
        self.roles.contains(&role)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.can_join_committee()
            && height >= self.activation_height
            && height >= self.jailed_until_height
    }

    pub fn jail_until(&mut self, height: u64) {
        self.status = ValidatorStatus::Jailed;
        self.jailed_until_height = self.jailed_until_height.max(height);
    }

    pub fn refresh(&mut self, height: u64, min_stake_units: u64) {
        if self.status == ValidatorStatus::Jailed && height >= self.jailed_until_height {
            self.status = if self.total_stake_units >= min_stake_units {
                ValidatorStatus::Active
            } else {
                ValidatorStatus::Candidate
            };
        }
        if self.status == ValidatorStatus::Candidate && self.total_stake_units >= min_stake_units {
            self.status = ValidatorStatus::Active;
        }
    }

    pub fn apply_key_set(&mut self, key_set: &PqPublicKeySet) -> ValidatorSecurityResult<String> {
        key_set.validate()?;
        self.current_key_set_id = key_set.key_set_id.clone();
        self.key_set_root = key_set.key_root();
        Ok(self.identity_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "validator_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "validator_id": self.validator_id,
            "operator_label": self.operator_label,
            "account_commitment": self.account_commitment,
            "payout_commitment": self.payout_commitment,
            "network_address_hash": self.network_address_hash,
            "metadata_root": self.metadata_root,
            "current_key_set_id": self.current_key_set_id,
            "key_set_root": self.key_set_root,
            "roles": validator_role_strings(&self.roles),
            "status": self.status.as_str(),
            "activation_height": self.activation_height,
            "jailed_until_height": self.jailed_until_height,
            "total_stake_units": self.total_stake_units,
            "total_bond_units": self.total_bond_units,
            "slash_reserved_units": self.slash_reserved_units,
            "reputation_score_bps": self.reputation_score_bps,
            "consecutive_missed_windows": self.consecutive_missed_windows,
            "identity_root": self.identity_root(),
        })
    }

    pub fn identity_root(&self) -> String {
        validator_security_payload_root("VALIDATOR-IDENTITY", &self.public_record_without_root())
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "validator_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "validator_id": self.validator_id,
            "operator_label": self.operator_label,
            "account_commitment": self.account_commitment,
            "payout_commitment": self.payout_commitment,
            "network_address_hash": self.network_address_hash,
            "metadata_root": self.metadata_root,
            "current_key_set_id": self.current_key_set_id,
            "key_set_root": self.key_set_root,
            "roles": validator_role_strings(&self.roles),
            "status": self.status.as_str(),
            "activation_height": self.activation_height,
            "jailed_until_height": self.jailed_until_height,
            "total_stake_units": self.total_stake_units,
            "total_bond_units": self.total_bond_units,
            "slash_reserved_units": self.slash_reserved_units,
            "reputation_score_bps": self.reputation_score_bps,
            "consecutive_missed_windows": self.consecutive_missed_windows,
        })
    }

    pub fn validate(&self) -> ValidatorSecurityResult<String> {
        ensure_non_empty(&self.validator_id, "validator id")?;
        ensure_non_empty(&self.operator_label, "validator operator label")?;
        ensure_non_empty(&self.account_commitment, "validator account commitment")?;
        ensure_non_empty(&self.payout_commitment, "validator payout commitment")?;
        ensure_non_empty(&self.network_address_hash, "validator network address hash")?;
        ensure_non_empty(&self.metadata_root, "validator metadata root")?;
        ensure_non_empty(&self.current_key_set_id, "validator key set id")?;
        ensure_non_empty(&self.key_set_root, "validator key set root")?;
        if self.roles.is_empty() {
            return Err("validator roles cannot be empty".to_string());
        }
        ensure_bps(self.reputation_score_bps, "validator reputation score bps")?;
        if self.slash_reserved_units > self.total_stake_units.saturating_add(self.total_bond_units)
        {
            return Err("validator slash reservation exceeds stake plus bonds".to_string());
        }
        Ok(self.identity_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakePosition {
    pub position_id: String,
    pub validator_id: String,
    pub asset_id: String,
    pub owner_commitment: String,
    pub amount_units: u64,
    pub bonded_units: u64,
    pub slashed_units: u64,
    pub slash_reserved_units: u64,
    pub activation_height: u64,
    pub locked_until_height: u64,
    pub unbonding_start_height: Option<u64>,
    pub withdrawal_available_height: Option<u64>,
    pub status: StakePositionStatus,
}

impl StakePosition {
    pub fn new(
        validator_id: impl Into<String>,
        asset_id: impl Into<String>,
        owner_commitment: impl Into<String>,
        amount_units: u64,
        activation_height: u64,
        locked_until_height: u64,
    ) -> ValidatorSecurityResult<Self> {
        let validator_id = validator_id.into();
        let asset_id = asset_id.into();
        let owner_commitment = owner_commitment.into();
        ensure_non_empty(&validator_id, "stake position validator id")?;
        ensure_non_empty(&asset_id, "stake position asset id")?;
        ensure_non_empty(&owner_commitment, "stake position owner commitment")?;
        ensure_positive(amount_units, "stake position amount units")?;
        ensure_height_window(
            activation_height,
            locked_until_height,
            "stake position lock window",
        )?;
        let position_id = validator_security_stake_position_id(
            &validator_id,
            &asset_id,
            &owner_commitment,
            amount_units,
            activation_height,
        );
        Ok(Self {
            position_id,
            validator_id,
            asset_id,
            owner_commitment,
            amount_units,
            bonded_units: amount_units,
            slashed_units: 0,
            slash_reserved_units: 0,
            activation_height,
            locked_until_height,
            unbonding_start_height: None,
            withdrawal_available_height: None,
            status: StakePositionStatus::Bonded,
        })
    }

    pub fn available_units(&self) -> u64 {
        self.bonded_units
            .saturating_sub(self.slashed_units)
            .saturating_sub(self.slash_reserved_units)
    }

    pub fn begin_unbonding(
        &mut self,
        height: u64,
        delay_blocks: u64,
    ) -> ValidatorSecurityResult<String> {
        if self.status != StakePositionStatus::Bonded {
            return Err("only bonded stake can begin unbonding".to_string());
        }
        if height < self.locked_until_height {
            return Err("stake position is still lock-bound".to_string());
        }
        self.unbonding_start_height = Some(height);
        self.withdrawal_available_height = Some(height.saturating_add(delay_blocks));
        self.status = StakePositionStatus::Unbonding;
        Ok(self.position_root())
    }

    pub fn reserve_for_slash(&mut self, units: u64) -> ValidatorSecurityResult<String> {
        if units > self.available_units() {
            return Err("stake slash reservation exceeds available units".to_string());
        }
        self.slash_reserved_units = self.slash_reserved_units.saturating_add(units);
        if self.status == StakePositionStatus::Unbonding {
            self.status = StakePositionStatus::Frozen;
        }
        Ok(self.position_root())
    }

    pub fn apply_slash(&mut self, units: u64) -> ValidatorSecurityResult<String> {
        let slash_units = units.min(self.bonded_units.saturating_sub(self.slashed_units));
        self.slashed_units = self.slashed_units.saturating_add(slash_units);
        self.slash_reserved_units = self.slash_reserved_units.saturating_sub(slash_units);
        if self.available_units() == 0 {
            self.status = StakePositionStatus::Slashed;
        }
        Ok(self.position_root())
    }

    pub fn refresh(&mut self, height: u64) {
        if self.status == StakePositionStatus::Unbonding
            && self
                .withdrawal_available_height
                .map_or(false, |available| height >= available)
        {
            self.status = StakePositionStatus::Withdrawable;
        }
    }

    pub fn mark_withdrawn(&mut self) -> ValidatorSecurityResult<String> {
        if self.status != StakePositionStatus::Withdrawable {
            return Err("stake position is not withdrawable".to_string());
        }
        self.status = StakePositionStatus::Withdrawn;
        self.bonded_units = 0;
        Ok(self.position_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "validator_stake_position",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "position_id": self.position_id,
            "validator_id": self.validator_id,
            "asset_id": self.asset_id,
            "owner_commitment": self.owner_commitment,
            "amount_units": self.amount_units,
            "bonded_units": self.bonded_units,
            "slashed_units": self.slashed_units,
            "slash_reserved_units": self.slash_reserved_units,
            "available_units": self.available_units(),
            "activation_height": self.activation_height,
            "locked_until_height": self.locked_until_height,
            "unbonding_start_height": self.unbonding_start_height,
            "withdrawal_available_height": self.withdrawal_available_height,
            "status": self.status.as_str(),
            "position_root": self.position_root(),
        })
    }

    pub fn position_root(&self) -> String {
        validator_security_payload_root(
            "VALIDATOR-STAKE-POSITION",
            &self.public_record_without_root(),
        )
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "validator_stake_position",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "position_id": self.position_id,
            "validator_id": self.validator_id,
            "asset_id": self.asset_id,
            "owner_commitment": self.owner_commitment,
            "amount_units": self.amount_units,
            "bonded_units": self.bonded_units,
            "slashed_units": self.slashed_units,
            "slash_reserved_units": self.slash_reserved_units,
            "available_units": self.available_units(),
            "activation_height": self.activation_height,
            "locked_until_height": self.locked_until_height,
            "unbonding_start_height": self.unbonding_start_height,
            "withdrawal_available_height": self.withdrawal_available_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ValidatorSecurityResult<String> {
        ensure_non_empty(&self.position_id, "stake position id")?;
        ensure_non_empty(&self.validator_id, "stake position validator id")?;
        ensure_non_empty(&self.asset_id, "stake position asset id")?;
        ensure_non_empty(&self.owner_commitment, "stake position owner commitment")?;
        ensure_positive(self.amount_units, "stake position amount units")?;
        if self.bonded_units > self.amount_units {
            return Err("stake position bonded units exceed amount units".to_string());
        }
        if self.slashed_units > self.bonded_units {
            return Err("stake position slashed units exceed bonded units".to_string());
        }
        if self.slash_reserved_units > self.bonded_units.saturating_sub(self.slashed_units) {
            return Err("stake position slash reservation exceeds available stake".to_string());
        }
        if let Some(start) = self.unbonding_start_height {
            if start < self.activation_height {
                return Err("stake position unbonding predates activation".to_string());
            }
        }
        if let (Some(start), Some(available)) = (
            self.unbonding_start_height,
            self.withdrawal_available_height,
        ) {
            if available < start {
                return Err("stake position withdrawal availability predates unbonding".to_string());
            }
        }
        Ok(self.position_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondPosition {
    pub bond_id: String,
    pub validator_id: String,
    pub bond_role: ValidatorRole,
    pub asset_id: String,
    pub amount_units: u64,
    pub locked_until_height: u64,
    pub slashed_units: u64,
    pub status: StakePositionStatus,
}

impl BondPosition {
    pub fn new(
        validator_id: impl Into<String>,
        bond_role: ValidatorRole,
        asset_id: impl Into<String>,
        amount_units: u64,
        locked_until_height: u64,
    ) -> ValidatorSecurityResult<Self> {
        let validator_id = validator_id.into();
        let asset_id = asset_id.into();
        ensure_non_empty(&validator_id, "bond position validator id")?;
        ensure_non_empty(&asset_id, "bond position asset id")?;
        ensure_positive(amount_units, "bond position amount units")?;
        let bond_id = validator_security_bond_position_id(
            &validator_id,
            bond_role,
            &asset_id,
            amount_units,
            locked_until_height,
        );
        Ok(Self {
            bond_id,
            validator_id,
            bond_role,
            asset_id,
            amount_units,
            locked_until_height,
            slashed_units: 0,
            status: StakePositionStatus::Bonded,
        })
    }

    pub fn available_units(&self) -> u64 {
        self.amount_units.saturating_sub(self.slashed_units)
    }

    pub fn apply_slash(&mut self, units: u64) -> ValidatorSecurityResult<String> {
        let slash_units = units.min(self.available_units());
        self.slashed_units = self.slashed_units.saturating_add(slash_units);
        if self.available_units() == 0 {
            self.status = StakePositionStatus::Slashed;
        }
        Ok(self.bond_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "validator_bond_position",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "bond_id": self.bond_id,
            "validator_id": self.validator_id,
            "bond_role": self.bond_role.as_str(),
            "asset_id": self.asset_id,
            "amount_units": self.amount_units,
            "available_units": self.available_units(),
            "locked_until_height": self.locked_until_height,
            "slashed_units": self.slashed_units,
            "status": self.status.as_str(),
            "bond_root": self.bond_root(),
        })
    }

    pub fn bond_root(&self) -> String {
        validator_security_payload_root(
            "VALIDATOR-BOND-POSITION",
            &self.public_record_without_root(),
        )
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "validator_bond_position",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "bond_id": self.bond_id,
            "validator_id": self.validator_id,
            "bond_role": self.bond_role.as_str(),
            "asset_id": self.asset_id,
            "amount_units": self.amount_units,
            "available_units": self.available_units(),
            "locked_until_height": self.locked_until_height,
            "slashed_units": self.slashed_units,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ValidatorSecurityResult<String> {
        ensure_non_empty(&self.bond_id, "bond position id")?;
        ensure_non_empty(&self.validator_id, "bond position validator id")?;
        ensure_non_empty(&self.asset_id, "bond position asset id")?;
        ensure_positive(self.amount_units, "bond position amount units")?;
        if self.slashed_units > self.amount_units {
            return Err("bond position slashed units exceed amount units".to_string());
        }
        Ok(self.bond_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeMember {
    pub validator_id: String,
    pub role: ValidatorRole,
    pub weight_units: u64,
    pub stake_position_ids: Vec<String>,
    pub bond_position_ids: Vec<String>,
    pub key_set_id: String,
    pub selection_score: u64,
    pub joined_height: u64,
}

impl CommitteeMember {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "validator_committee_member",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "validator_id": self.validator_id,
            "role": self.role.as_str(),
            "weight_units": self.weight_units,
            "stake_position_ids": self.stake_position_ids,
            "bond_position_ids": self.bond_position_ids,
            "key_set_id": self.key_set_id,
            "selection_score": self.selection_score,
            "joined_height": self.joined_height,
        })
    }

    pub fn validate(&self) -> ValidatorSecurityResult<String> {
        ensure_non_empty(&self.validator_id, "committee member validator id")?;
        ensure_positive(self.weight_units, "committee member weight units")?;
        ensure_non_empty(&self.key_set_id, "committee member key set id")?;
        Ok(validator_security_payload_root(
            "VALIDATOR-COMMITTEE-MEMBER",
            &self.public_record(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeEpoch {
    pub epoch_id: String,
    pub epoch_index: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub seed_root: String,
    pub member_root: String,
    pub role_root: String,
    pub total_weight_units: u64,
    pub quorum_weight_units: u64,
    pub status: CommitteeEpochStatus,
    pub members: Vec<CommitteeMember>,
}

impl CommitteeEpoch {
    pub fn new(
        epoch_index: u64,
        start_height: u64,
        end_height: u64,
        seed_root: impl Into<String>,
        members: Vec<CommitteeMember>,
    ) -> ValidatorSecurityResult<Self> {
        let seed_root = seed_root.into();
        ensure_height_window(start_height, end_height, "committee epoch")?;
        ensure_non_empty(&seed_root, "committee epoch seed root")?;
        if members.is_empty() {
            return Err("committee epoch requires at least one member".to_string());
        }
        for member in &members {
            member.validate()?;
        }
        let member_root = validator_security_committee_member_root(&members);
        let roles = members
            .iter()
            .map(|member| {
                json!({
                    "validator_id": member.validator_id,
                    "role": member.role.as_str(),
                    "weight_units": member.weight_units,
                })
            })
            .collect::<Vec<_>>();
        let role_root = merkle_root("VALIDATOR-COMMITTEE-ROLE", &roles);
        let total_weight_units = members
            .iter()
            .map(|member| member.weight_units)
            .fold(0_u64, u64::saturating_add);
        let quorum_weight_units = threshold_units(total_weight_units, 6_700);
        let epoch_id = validator_security_committee_epoch_id(
            epoch_index,
            start_height,
            end_height,
            &seed_root,
            &member_root,
        );
        Ok(Self {
            epoch_id,
            epoch_index,
            start_height,
            end_height,
            seed_root,
            member_root,
            role_root,
            total_weight_units,
            quorum_weight_units,
            status: CommitteeEpochStatus::Scheduled,
            members,
        })
    }

    pub fn contains_height(&self, height: u64) -> bool {
        self.start_height <= height && height <= self.end_height
    }

    pub fn refresh(&mut self, height: u64, grace_blocks: u64) {
        self.status = if height < self.start_height {
            CommitteeEpochStatus::Scheduled
        } else if height <= self.end_height {
            CommitteeEpochStatus::Active
        } else if height <= self.end_height.saturating_add(grace_blocks) {
            CommitteeEpochStatus::Grace
        } else {
            CommitteeEpochStatus::Retired
        };
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "validator_committee_epoch",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "epoch_id": self.epoch_id,
            "epoch_index": self.epoch_index,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "seed_root": self.seed_root,
            "member_root": self.member_root,
            "role_root": self.role_root,
            "total_weight_units": self.total_weight_units,
            "quorum_weight_units": self.quorum_weight_units,
            "status": self.status.as_str(),
            "member_count": self.members.len() as u64,
            "epoch_root": self.epoch_root(),
        })
    }

    pub fn epoch_root(&self) -> String {
        validator_security_payload_root(
            "VALIDATOR-COMMITTEE-EPOCH",
            &self.public_record_without_root(),
        )
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "validator_committee_epoch",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "epoch_id": self.epoch_id,
            "epoch_index": self.epoch_index,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "seed_root": self.seed_root,
            "member_root": self.member_root,
            "role_root": self.role_root,
            "total_weight_units": self.total_weight_units,
            "quorum_weight_units": self.quorum_weight_units,
            "status": self.status.as_str(),
            "member_count": self.members.len() as u64,
        })
    }

    pub fn validate(&self) -> ValidatorSecurityResult<String> {
        ensure_non_empty(&self.epoch_id, "committee epoch id")?;
        ensure_height_window(self.start_height, self.end_height, "committee epoch")?;
        ensure_non_empty(&self.seed_root, "committee epoch seed root")?;
        if self.members.is_empty() {
            return Err("committee epoch members cannot be empty".to_string());
        }
        for member in &self.members {
            member.validate()?;
        }
        if validator_security_committee_member_root(&self.members) != self.member_root {
            return Err("committee epoch member root is stale".to_string());
        }
        let expected_weight = self
            .members
            .iter()
            .map(|member| member.weight_units)
            .fold(0_u64, u64::saturating_add);
        if expected_weight != self.total_weight_units {
            return Err("committee epoch total weight is stale".to_string());
        }
        if self.quorum_weight_units == 0 || self.quorum_weight_units > self.total_weight_units {
            return Err("committee epoch quorum weight is invalid".to_string());
        }
        Ok(self.epoch_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub evidence_kind: SlashingEvidenceKind,
    pub reporter_id: String,
    pub accused_validator_id: String,
    pub subject_id: String,
    pub subject_root: String,
    pub conflicting_root: Option<String>,
    pub observed_height: u64,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub slash_bps: u64,
    pub evidence_payload_root: String,
    pub status: EvidenceStatus,
    pub adjudication_id: Option<String>,
}

impl SlashingEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        evidence_kind: SlashingEvidenceKind,
        reporter_id: impl Into<String>,
        accused_validator_id: impl Into<String>,
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        conflicting_root: Option<String>,
        observed_height: u64,
        submitted_height: u64,
        expires_height: u64,
        slash_bps: u64,
        payload: &Value,
    ) -> ValidatorSecurityResult<Self> {
        let reporter_id = reporter_id.into();
        let accused_validator_id = accused_validator_id.into();
        let subject_id = subject_id.into();
        let subject_root = subject_root.into();
        ensure_non_empty(&reporter_id, "slashing evidence reporter id")?;
        ensure_non_empty(
            &accused_validator_id,
            "slashing evidence accused validator id",
        )?;
        ensure_non_empty(&subject_id, "slashing evidence subject id")?;
        ensure_non_empty(&subject_root, "slashing evidence subject root")?;
        ensure_height_window(
            observed_height,
            submitted_height,
            "slashing evidence observation submission",
        )?;
        ensure_height_window(
            submitted_height,
            expires_height,
            "slashing evidence submission expiry",
        )?;
        ensure_bps(slash_bps, "slashing evidence slash bps")?;
        let evidence_payload_root =
            validator_security_payload_root("VALIDATOR-SLASHING-EVIDENCE-PAYLOAD", payload);
        let evidence_id = validator_security_slashing_evidence_id(
            evidence_kind,
            &reporter_id,
            &accused_validator_id,
            &subject_id,
            &subject_root,
            &evidence_payload_root,
            submitted_height,
        );
        Ok(Self {
            evidence_id,
            evidence_kind,
            reporter_id,
            accused_validator_id,
            subject_id,
            subject_root,
            conflicting_root,
            observed_height,
            submitted_height,
            expires_height,
            slash_bps,
            evidence_payload_root,
            status: EvidenceStatus::Submitted,
            adjudication_id: None,
        })
    }

    pub fn refresh(&mut self, height: u64) {
        if self.status == EvidenceStatus::Submitted && height > self.expires_height {
            self.status = EvidenceStatus::Expired;
        }
    }

    pub fn accept(
        &mut self,
        adjudication_id: impl Into<String>,
    ) -> ValidatorSecurityResult<String> {
        let adjudication_id = adjudication_id.into();
        ensure_non_empty(&adjudication_id, "slashing adjudication id")?;
        self.status = EvidenceStatus::Accepted;
        self.adjudication_id = Some(adjudication_id);
        Ok(self.evidence_root())
    }

    pub fn reject(
        &mut self,
        adjudication_id: impl Into<String>,
    ) -> ValidatorSecurityResult<String> {
        let adjudication_id = adjudication_id.into();
        ensure_non_empty(&adjudication_id, "slashing adjudication id")?;
        self.status = EvidenceStatus::Rejected;
        self.adjudication_id = Some(adjudication_id);
        Ok(self.evidence_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "validator_slashing_evidence",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "evidence_id": self.evidence_id,
            "evidence_kind": self.evidence_kind.as_str(),
            "reporter_id": self.reporter_id,
            "accused_validator_id": self.accused_validator_id,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "conflicting_root": self.conflicting_root,
            "observed_height": self.observed_height,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "slash_bps": self.slash_bps,
            "evidence_payload_root": self.evidence_payload_root,
            "status": self.status.as_str(),
            "adjudication_id": self.adjudication_id,
            "evidence_root": self.evidence_root(),
        })
    }

    pub fn evidence_root(&self) -> String {
        validator_security_payload_root(
            "VALIDATOR-SLASHING-EVIDENCE",
            &self.public_record_without_root(),
        )
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "validator_slashing_evidence",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "evidence_id": self.evidence_id,
            "evidence_kind": self.evidence_kind.as_str(),
            "reporter_id": self.reporter_id,
            "accused_validator_id": self.accused_validator_id,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "conflicting_root": self.conflicting_root,
            "observed_height": self.observed_height,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "slash_bps": self.slash_bps,
            "evidence_payload_root": self.evidence_payload_root,
            "status": self.status.as_str(),
            "adjudication_id": self.adjudication_id,
        })
    }

    pub fn validate(&self) -> ValidatorSecurityResult<String> {
        ensure_non_empty(&self.evidence_id, "slashing evidence id")?;
        ensure_non_empty(&self.reporter_id, "slashing evidence reporter id")?;
        ensure_non_empty(
            &self.accused_validator_id,
            "slashing evidence accused validator id",
        )?;
        ensure_non_empty(&self.subject_id, "slashing evidence subject id")?;
        ensure_non_empty(&self.subject_root, "slashing evidence subject root")?;
        ensure_non_empty(
            &self.evidence_payload_root,
            "slashing evidence payload root",
        )?;
        ensure_height_window(
            self.observed_height,
            self.submitted_height,
            "slashing evidence observation submission",
        )?;
        ensure_height_window(
            self.submitted_height,
            self.expires_height,
            "slashing evidence submission expiry",
        )?;
        ensure_bps(self.slash_bps, "slashing evidence slash bps")?;
        Ok(self.evidence_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LivenessReport {
    pub report_id: String,
    pub validator_id: String,
    pub epoch_id: String,
    pub window_index: u64,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub assigned_slots: u64,
    pub signed_slots: u64,
    pub missed_slots: u64,
    pub late_slots: u64,
    pub downtime_bps: u64,
    pub availability_bps: u64,
    pub liveness_score_bps: u64,
    pub status: LivenessWindowStatus,
    pub evidence_root: String,
}

impl LivenessReport {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        validator_id: impl Into<String>,
        epoch_id: impl Into<String>,
        window_index: u64,
        window_start_height: u64,
        window_end_height: u64,
        assigned_slots: u64,
        signed_slots: u64,
        late_slots: u64,
        jail_threshold_bps: u64,
        slash_threshold_bps: u64,
        evidence: &Value,
    ) -> ValidatorSecurityResult<Self> {
        let validator_id = validator_id.into();
        let epoch_id = epoch_id.into();
        ensure_non_empty(&validator_id, "liveness validator id")?;
        ensure_non_empty(&epoch_id, "liveness epoch id")?;
        ensure_height_window(
            window_start_height,
            window_end_height,
            "liveness report window",
        )?;
        ensure_positive(assigned_slots, "liveness assigned slots")?;
        if signed_slots > assigned_slots {
            return Err("liveness signed slots exceed assigned slots".to_string());
        }
        if late_slots > signed_slots {
            return Err("liveness late slots exceed signed slots".to_string());
        }
        ensure_bps(jail_threshold_bps, "liveness jail threshold bps")?;
        ensure_bps(slash_threshold_bps, "liveness slash threshold bps")?;
        let missed_slots = assigned_slots.saturating_sub(signed_slots);
        let downtime_bps = ratio_bps(missed_slots.saturating_add(late_slots / 2), assigned_slots);
        let availability_bps = VALIDATOR_SECURITY_MAX_BPS.saturating_sub(downtime_bps);
        let liveness_score_bps =
            availability_bps.saturating_sub(ratio_bps(late_slots, assigned_slots) / 2);
        let status = if downtime_bps >= slash_threshold_bps {
            LivenessWindowStatus::Slashable
        } else if downtime_bps >= jail_threshold_bps {
            LivenessWindowStatus::Jailable
        } else if downtime_bps >= jail_threshold_bps / 2 {
            LivenessWindowStatus::Warning
        } else {
            LivenessWindowStatus::Healthy
        };
        let evidence_root =
            validator_security_payload_root("VALIDATOR-LIVENESS-EVIDENCE", evidence);
        let report_id = validator_security_liveness_report_id(
            &validator_id,
            &epoch_id,
            window_index,
            window_start_height,
            window_end_height,
            &evidence_root,
        );
        Ok(Self {
            report_id,
            validator_id,
            epoch_id,
            window_index,
            window_start_height,
            window_end_height,
            assigned_slots,
            signed_slots,
            missed_slots,
            late_slots,
            downtime_bps,
            availability_bps,
            liveness_score_bps,
            status,
            evidence_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "validator_liveness_report",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "report_id": self.report_id,
            "validator_id": self.validator_id,
            "epoch_id": self.epoch_id,
            "window_index": self.window_index,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "assigned_slots": self.assigned_slots,
            "signed_slots": self.signed_slots,
            "missed_slots": self.missed_slots,
            "late_slots": self.late_slots,
            "downtime_bps": self.downtime_bps,
            "availability_bps": self.availability_bps,
            "liveness_score_bps": self.liveness_score_bps,
            "status": self.status.as_str(),
            "evidence_root": self.evidence_root,
            "report_root": self.report_root(),
        })
    }

    pub fn report_root(&self) -> String {
        validator_security_payload_root(
            "VALIDATOR-LIVENESS-REPORT",
            &self.public_record_without_root(),
        )
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "validator_liveness_report",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "report_id": self.report_id,
            "validator_id": self.validator_id,
            "epoch_id": self.epoch_id,
            "window_index": self.window_index,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "assigned_slots": self.assigned_slots,
            "signed_slots": self.signed_slots,
            "missed_slots": self.missed_slots,
            "late_slots": self.late_slots,
            "downtime_bps": self.downtime_bps,
            "availability_bps": self.availability_bps,
            "liveness_score_bps": self.liveness_score_bps,
            "status": self.status.as_str(),
            "evidence_root": self.evidence_root,
        })
    }

    pub fn validate(&self) -> ValidatorSecurityResult<String> {
        ensure_non_empty(&self.report_id, "liveness report id")?;
        ensure_non_empty(&self.validator_id, "liveness validator id")?;
        ensure_non_empty(&self.epoch_id, "liveness epoch id")?;
        ensure_height_window(
            self.window_start_height,
            self.window_end_height,
            "liveness report window",
        )?;
        ensure_positive(self.assigned_slots, "liveness assigned slots")?;
        if self.signed_slots > self.assigned_slots {
            return Err("liveness signed slots exceed assigned slots".to_string());
        }
        if self.missed_slots != self.assigned_slots.saturating_sub(self.signed_slots) {
            return Err("liveness missed slot count is stale".to_string());
        }
        if self.late_slots > self.signed_slots {
            return Err("liveness late slots exceed signed slots".to_string());
        }
        ensure_bps(self.downtime_bps, "liveness downtime bps")?;
        ensure_bps(self.availability_bps, "liveness availability bps")?;
        ensure_bps(self.liveness_score_bps, "liveness score bps")?;
        ensure_non_empty(&self.evidence_root, "liveness evidence root")?;
        Ok(self.report_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DowntimeScore {
    pub validator_id: String,
    pub window_count: u64,
    pub total_assigned_slots: u64,
    pub total_missed_slots: u64,
    pub total_late_slots: u64,
    pub rolling_downtime_bps: u64,
    pub rolling_availability_bps: u64,
    pub consecutive_failed_windows: u64,
    pub last_report_height: u64,
    pub jailed_until_height: u64,
}

impl DowntimeScore {
    pub fn new(validator_id: impl Into<String>) -> ValidatorSecurityResult<Self> {
        let validator_id = validator_id.into();
        ensure_non_empty(&validator_id, "downtime score validator id")?;
        Ok(Self {
            validator_id,
            window_count: 0,
            total_assigned_slots: 0,
            total_missed_slots: 0,
            total_late_slots: 0,
            rolling_downtime_bps: 0,
            rolling_availability_bps: VALIDATOR_SECURITY_MAX_BPS,
            consecutive_failed_windows: 0,
            last_report_height: 0,
            jailed_until_height: 0,
        })
    }

    pub fn apply_report(
        &mut self,
        report: &LivenessReport,
        jail_threshold_bps: u64,
        jail_until_height: u64,
    ) -> ValidatorSecurityResult<String> {
        if self.validator_id != report.validator_id {
            return Err("downtime score report validator mismatch".to_string());
        }
        self.window_count = self.window_count.saturating_add(1);
        self.total_assigned_slots = self
            .total_assigned_slots
            .saturating_add(report.assigned_slots);
        self.total_missed_slots = self.total_missed_slots.saturating_add(report.missed_slots);
        self.total_late_slots = self.total_late_slots.saturating_add(report.late_slots);
        self.rolling_downtime_bps = ratio_bps(
            self.total_missed_slots
                .saturating_add(self.total_late_slots / 2),
            self.total_assigned_slots,
        );
        self.rolling_availability_bps =
            VALIDATOR_SECURITY_MAX_BPS.saturating_sub(self.rolling_downtime_bps);
        self.last_report_height = report.window_end_height;
        if report.downtime_bps >= jail_threshold_bps {
            self.consecutive_failed_windows = self.consecutive_failed_windows.saturating_add(1);
            self.jailed_until_height = self.jailed_until_height.max(jail_until_height);
        } else {
            self.consecutive_failed_windows = 0;
        }
        Ok(self.score_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "validator_downtime_score",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "validator_id": self.validator_id,
            "window_count": self.window_count,
            "total_assigned_slots": self.total_assigned_slots,
            "total_missed_slots": self.total_missed_slots,
            "total_late_slots": self.total_late_slots,
            "rolling_downtime_bps": self.rolling_downtime_bps,
            "rolling_availability_bps": self.rolling_availability_bps,
            "consecutive_failed_windows": self.consecutive_failed_windows,
            "last_report_height": self.last_report_height,
            "jailed_until_height": self.jailed_until_height,
            "score_root": self.score_root(),
        })
    }

    pub fn score_root(&self) -> String {
        validator_security_payload_root(
            "VALIDATOR-DOWNTIME-SCORE",
            &self.public_record_without_root(),
        )
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "validator_downtime_score",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "validator_id": self.validator_id,
            "window_count": self.window_count,
            "total_assigned_slots": self.total_assigned_slots,
            "total_missed_slots": self.total_missed_slots,
            "total_late_slots": self.total_late_slots,
            "rolling_downtime_bps": self.rolling_downtime_bps,
            "rolling_availability_bps": self.rolling_availability_bps,
            "consecutive_failed_windows": self.consecutive_failed_windows,
            "last_report_height": self.last_report_height,
            "jailed_until_height": self.jailed_until_height,
        })
    }

    pub fn validate(&self) -> ValidatorSecurityResult<String> {
        ensure_non_empty(&self.validator_id, "downtime score validator id")?;
        if self.total_missed_slots > self.total_assigned_slots {
            return Err("downtime total missed slots exceed assigned slots".to_string());
        }
        if self.total_late_slots > self.total_assigned_slots {
            return Err("downtime total late slots exceed assigned slots".to_string());
        }
        ensure_bps(self.rolling_downtime_bps, "downtime rolling downtime bps")?;
        ensure_bps(
            self.rolling_availability_bps,
            "downtime rolling availability bps",
        )?;
        Ok(self.score_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotationCeremony {
    pub rotation_id: String,
    pub validator_id: String,
    pub previous_key_set_id: String,
    pub previous_key_set_root: String,
    pub next_key_set_id: String,
    pub next_key_set_root: String,
    pub announcement_height: u64,
    pub effective_height: u64,
    pub grace_until_height: u64,
    pub attester_root: String,
    pub attestation_count: u64,
    pub quorum_weight_units: u64,
    pub status: KeyRotationStatus,
}

impl KeyRotationCeremony {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        validator_id: impl Into<String>,
        previous_key_set: &PqPublicKeySet,
        next_key_set: &PqPublicKeySet,
        announcement_height: u64,
        effective_height: u64,
        grace_blocks: u64,
        attesters: &[String],
        quorum_weight_units: u64,
    ) -> ValidatorSecurityResult<Self> {
        let validator_id = validator_id.into();
        ensure_non_empty(&validator_id, "key rotation validator id")?;
        previous_key_set.validate()?;
        next_key_set.validate()?;
        ensure_height_window(
            announcement_height,
            effective_height,
            "key rotation activation window",
        )?;
        let attester_root =
            validator_security_string_set_root("VALIDATOR-KEY-ROTATION-ATTESTER", attesters);
        let previous_key_set_root = previous_key_set.key_root();
        let next_key_set_root = next_key_set.key_root();
        let grace_until_height = effective_height.saturating_add(grace_blocks);
        let rotation_id = validator_security_key_rotation_id(
            &validator_id,
            &previous_key_set.key_set_id,
            &next_key_set.key_set_id,
            announcement_height,
            effective_height,
            &attester_root,
        );
        Ok(Self {
            rotation_id,
            validator_id,
            previous_key_set_id: previous_key_set.key_set_id.clone(),
            previous_key_set_root,
            next_key_set_id: next_key_set.key_set_id.clone(),
            next_key_set_root,
            announcement_height,
            effective_height,
            grace_until_height,
            attester_root,
            attestation_count: attesters.len() as u64,
            quorum_weight_units,
            status: KeyRotationStatus::Announced,
        })
    }

    pub fn refresh(&mut self, height: u64) {
        self.status = if height < self.effective_height {
            if self.attestation_count > 0 {
                KeyRotationStatus::Attesting
            } else {
                KeyRotationStatus::Announced
            }
        } else if height <= self.grace_until_height {
            KeyRotationStatus::Effective
        } else {
            KeyRotationStatus::Expired
        };
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "validator_key_rotation_ceremony",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "rotation_id": self.rotation_id,
            "validator_id": self.validator_id,
            "previous_key_set_id": self.previous_key_set_id,
            "previous_key_set_root": self.previous_key_set_root,
            "next_key_set_id": self.next_key_set_id,
            "next_key_set_root": self.next_key_set_root,
            "announcement_height": self.announcement_height,
            "effective_height": self.effective_height,
            "grace_until_height": self.grace_until_height,
            "attester_root": self.attester_root,
            "attestation_count": self.attestation_count,
            "quorum_weight_units": self.quorum_weight_units,
            "status": self.status.as_str(),
            "rotation_root": self.rotation_root(),
        })
    }

    pub fn rotation_root(&self) -> String {
        validator_security_payload_root(
            "VALIDATOR-KEY-ROTATION",
            &self.public_record_without_root(),
        )
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "validator_key_rotation_ceremony",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "rotation_id": self.rotation_id,
            "validator_id": self.validator_id,
            "previous_key_set_id": self.previous_key_set_id,
            "previous_key_set_root": self.previous_key_set_root,
            "next_key_set_id": self.next_key_set_id,
            "next_key_set_root": self.next_key_set_root,
            "announcement_height": self.announcement_height,
            "effective_height": self.effective_height,
            "grace_until_height": self.grace_until_height,
            "attester_root": self.attester_root,
            "attestation_count": self.attestation_count,
            "quorum_weight_units": self.quorum_weight_units,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ValidatorSecurityResult<String> {
        ensure_non_empty(&self.rotation_id, "key rotation id")?;
        ensure_non_empty(&self.validator_id, "key rotation validator id")?;
        ensure_non_empty(&self.previous_key_set_id, "key rotation previous key id")?;
        ensure_non_empty(
            &self.previous_key_set_root,
            "key rotation previous key root",
        )?;
        ensure_non_empty(&self.next_key_set_id, "key rotation next key id")?;
        ensure_non_empty(&self.next_key_set_root, "key rotation next key root")?;
        ensure_height_window(
            self.announcement_height,
            self.effective_height,
            "key rotation activation window",
        )?;
        ensure_height_window(
            self.effective_height,
            self.grace_until_height,
            "key rotation grace window",
        )?;
        ensure_non_empty(&self.attester_root, "key rotation attester root")?;
        Ok(self.rotation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakeWithdrawalRequest {
    pub withdrawal_id: String,
    pub validator_id: String,
    pub position_id: String,
    pub requested_units: u64,
    pub request_height: u64,
    pub challenge_until_height: u64,
    pub available_height: u64,
    pub completed_height: Option<u64>,
    pub recipient_commitment: String,
    pub challenge_root: String,
    pub status: WithdrawalStatus,
}

impl StakeWithdrawalRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        validator_id: impl Into<String>,
        position_id: impl Into<String>,
        requested_units: u64,
        request_height: u64,
        challenge_blocks: u64,
        unbonding_delay_blocks: u64,
        recipient_commitment: impl Into<String>,
    ) -> ValidatorSecurityResult<Self> {
        let validator_id = validator_id.into();
        let position_id = position_id.into();
        let recipient_commitment = recipient_commitment.into();
        ensure_non_empty(&validator_id, "stake withdrawal validator id")?;
        ensure_non_empty(&position_id, "stake withdrawal position id")?;
        ensure_non_empty(
            &recipient_commitment,
            "stake withdrawal recipient commitment",
        )?;
        ensure_positive(requested_units, "stake withdrawal requested units")?;
        let challenge_until_height = request_height.saturating_add(challenge_blocks);
        let available_height = request_height
            .saturating_add(challenge_blocks)
            .saturating_add(unbonding_delay_blocks);
        let challenge_root = validator_security_empty_root("VALIDATOR-WITHDRAWAL-CHALLENGE");
        let withdrawal_id = validator_security_withdrawal_id(
            &validator_id,
            &position_id,
            requested_units,
            request_height,
            &recipient_commitment,
        );
        Ok(Self {
            withdrawal_id,
            validator_id,
            position_id,
            requested_units,
            request_height,
            challenge_until_height,
            available_height,
            completed_height: None,
            recipient_commitment,
            challenge_root,
            status: WithdrawalStatus::Requested,
        })
    }

    pub fn refresh(&mut self, height: u64) {
        if self.status == WithdrawalStatus::Requested && height <= self.challenge_until_height {
            self.status = WithdrawalStatus::ChallengeOpen;
        } else if matches!(
            self.status,
            WithdrawalStatus::Requested
                | WithdrawalStatus::ChallengeOpen
                | WithdrawalStatus::Delayed
        ) && height < self.available_height
        {
            self.status = WithdrawalStatus::Delayed;
        } else if matches!(
            self.status,
            WithdrawalStatus::Requested
                | WithdrawalStatus::ChallengeOpen
                | WithdrawalStatus::Delayed
        ) && height >= self.available_height
        {
            self.status = WithdrawalStatus::Withdrawable;
        }
    }

    pub fn complete(&mut self, height: u64) -> ValidatorSecurityResult<String> {
        self.refresh(height);
        if self.status != WithdrawalStatus::Withdrawable {
            return Err("stake withdrawal is not withdrawable".to_string());
        }
        self.status = WithdrawalStatus::Completed;
        self.completed_height = Some(height);
        Ok(self.withdrawal_root())
    }

    pub fn attach_challenge_root(
        &mut self,
        challenge_root: impl Into<String>,
    ) -> ValidatorSecurityResult<String> {
        let challenge_root = challenge_root.into();
        ensure_non_empty(&challenge_root, "stake withdrawal challenge root")?;
        self.challenge_root = challenge_root;
        self.status = WithdrawalStatus::ChallengeOpen;
        Ok(self.withdrawal_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "validator_stake_withdrawal_request",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "withdrawal_id": self.withdrawal_id,
            "validator_id": self.validator_id,
            "position_id": self.position_id,
            "requested_units": self.requested_units,
            "request_height": self.request_height,
            "challenge_until_height": self.challenge_until_height,
            "available_height": self.available_height,
            "completed_height": self.completed_height,
            "recipient_commitment": self.recipient_commitment,
            "challenge_root": self.challenge_root,
            "status": self.status.as_str(),
            "withdrawal_root": self.withdrawal_root(),
        })
    }

    pub fn withdrawal_root(&self) -> String {
        validator_security_payload_root(
            "VALIDATOR-STAKE-WITHDRAWAL",
            &self.public_record_without_root(),
        )
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "validator_stake_withdrawal_request",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "withdrawal_id": self.withdrawal_id,
            "validator_id": self.validator_id,
            "position_id": self.position_id,
            "requested_units": self.requested_units,
            "request_height": self.request_height,
            "challenge_until_height": self.challenge_until_height,
            "available_height": self.available_height,
            "completed_height": self.completed_height,
            "recipient_commitment": self.recipient_commitment,
            "challenge_root": self.challenge_root,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ValidatorSecurityResult<String> {
        ensure_non_empty(&self.withdrawal_id, "stake withdrawal id")?;
        ensure_non_empty(&self.validator_id, "stake withdrawal validator id")?;
        ensure_non_empty(&self.position_id, "stake withdrawal position id")?;
        ensure_positive(self.requested_units, "stake withdrawal requested units")?;
        ensure_height_window(
            self.request_height,
            self.challenge_until_height,
            "stake withdrawal challenge window",
        )?;
        ensure_height_window(
            self.challenge_until_height,
            self.available_height,
            "stake withdrawal delay window",
        )?;
        ensure_non_empty(
            &self.recipient_commitment,
            "stake withdrawal recipient commitment",
        )?;
        ensure_non_empty(&self.challenge_root, "stake withdrawal challenge root")?;
        if let Some(completed_height) = self.completed_height {
            if completed_height < self.available_height {
                return Err("stake withdrawal completed before availability".to_string());
            }
        }
        Ok(self.withdrawal_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeCase {
    pub challenge_id: String,
    pub challenge_kind: ChallengeKind,
    pub challenger_id: String,
    pub respondent_validator_id: String,
    pub subject_id: String,
    pub subject_root: String,
    pub opened_height: u64,
    pub response_due_height: u64,
    pub adjudication_due_height: u64,
    pub stake_at_risk_units: u64,
    pub challenge_bond_units: u64,
    pub response_root: Option<String>,
    pub adjudicator_root: String,
    pub decision: ChallengeDecision,
    pub status: ChallengeStatus,
    pub award_units: u64,
    pub penalty_units: u64,
}

impl ChallengeCase {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        challenge_kind: ChallengeKind,
        challenger_id: impl Into<String>,
        respondent_validator_id: impl Into<String>,
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        opened_height: u64,
        response_blocks: u64,
        adjudication_blocks: u64,
        stake_at_risk_units: u64,
        challenge_bond_units: u64,
    ) -> ValidatorSecurityResult<Self> {
        let challenger_id = challenger_id.into();
        let respondent_validator_id = respondent_validator_id.into();
        let subject_id = subject_id.into();
        let subject_root = subject_root.into();
        ensure_non_empty(&challenger_id, "challenge challenger id")?;
        ensure_non_empty(
            &respondent_validator_id,
            "challenge respondent validator id",
        )?;
        ensure_non_empty(&subject_id, "challenge subject id")?;
        ensure_non_empty(&subject_root, "challenge subject root")?;
        ensure_positive(challenge_bond_units, "challenge bond units")?;
        let response_due_height = opened_height.saturating_add(response_blocks);
        let adjudication_due_height = opened_height.saturating_add(adjudication_blocks);
        if response_due_height > adjudication_due_height {
            return Err(
                "challenge response due height exceeds adjudication due height".to_string(),
            );
        }
        let adjudicator_root = validator_security_empty_root("VALIDATOR-CHALLENGE-ADJUDICATOR");
        let challenge_id = validator_security_challenge_id(
            challenge_kind,
            &challenger_id,
            &respondent_validator_id,
            &subject_id,
            &subject_root,
            opened_height,
        );
        Ok(Self {
            challenge_id,
            challenge_kind,
            challenger_id,
            respondent_validator_id,
            subject_id,
            subject_root,
            opened_height,
            response_due_height,
            adjudication_due_height,
            stake_at_risk_units,
            challenge_bond_units,
            response_root: None,
            adjudicator_root,
            decision: ChallengeDecision::Pending,
            status: ChallengeStatus::Open,
            award_units: 0,
            penalty_units: 0,
        })
    }

    pub fn refresh(&mut self, height: u64) {
        if self.status.is_open() && height > self.adjudication_due_height {
            self.status = ChallengeStatus::Expired;
            self.decision = ChallengeDecision::Expired;
        }
    }

    pub fn respond(&mut self, height: u64, response: &Value) -> ValidatorSecurityResult<String> {
        if height > self.response_due_height {
            return Err("challenge response missed due height".to_string());
        }
        if !self.status.is_open() {
            return Err("challenge is not open".to_string());
        }
        self.response_root = Some(validator_security_payload_root(
            "VALIDATOR-CHALLENGE-RESPONSE",
            response,
        ));
        self.status = ChallengeStatus::Responded;
        Ok(self.challenge_root())
    }

    pub fn adjudicate(
        &mut self,
        height: u64,
        decision: ChallengeDecision,
        adjudicator_root: impl Into<String>,
        award_units: u64,
        penalty_units: u64,
    ) -> ValidatorSecurityResult<String> {
        let adjudicator_root = adjudicator_root.into();
        ensure_non_empty(&adjudicator_root, "challenge adjudicator root")?;
        if height > self.adjudication_due_height {
            return Err("challenge adjudication missed due height".to_string());
        }
        if !self.status.is_open() {
            return Err("challenge is not open for adjudication".to_string());
        }
        self.adjudicator_root = adjudicator_root;
        self.decision = decision;
        self.award_units = award_units;
        self.penalty_units = penalty_units;
        self.status = match decision {
            ChallengeDecision::ChallengerWins | ChallengeDecision::Split => {
                ChallengeStatus::Sustained
            }
            ChallengeDecision::RespondentWins => ChallengeStatus::Dismissed,
            ChallengeDecision::Expired => ChallengeStatus::Expired,
            ChallengeDecision::Pending => ChallengeStatus::Open,
        };
        Ok(self.challenge_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "validator_challenge_case",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "challenge_id": self.challenge_id,
            "challenge_kind": self.challenge_kind.as_str(),
            "challenger_id": self.challenger_id,
            "respondent_validator_id": self.respondent_validator_id,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "opened_height": self.opened_height,
            "response_due_height": self.response_due_height,
            "adjudication_due_height": self.adjudication_due_height,
            "stake_at_risk_units": self.stake_at_risk_units,
            "challenge_bond_units": self.challenge_bond_units,
            "response_root": self.response_root,
            "adjudicator_root": self.adjudicator_root,
            "decision": self.decision.as_str(),
            "status": self.status.as_str(),
            "award_units": self.award_units,
            "penalty_units": self.penalty_units,
            "challenge_root": self.challenge_root(),
        })
    }

    pub fn challenge_root(&self) -> String {
        validator_security_payload_root(
            "VALIDATOR-CHALLENGE-CASE",
            &self.public_record_without_root(),
        )
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "validator_challenge_case",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "challenge_id": self.challenge_id,
            "challenge_kind": self.challenge_kind.as_str(),
            "challenger_id": self.challenger_id,
            "respondent_validator_id": self.respondent_validator_id,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "opened_height": self.opened_height,
            "response_due_height": self.response_due_height,
            "adjudication_due_height": self.adjudication_due_height,
            "stake_at_risk_units": self.stake_at_risk_units,
            "challenge_bond_units": self.challenge_bond_units,
            "response_root": self.response_root,
            "adjudicator_root": self.adjudicator_root,
            "decision": self.decision.as_str(),
            "status": self.status.as_str(),
            "award_units": self.award_units,
            "penalty_units": self.penalty_units,
        })
    }

    pub fn validate(&self) -> ValidatorSecurityResult<String> {
        ensure_non_empty(&self.challenge_id, "challenge id")?;
        ensure_non_empty(&self.challenger_id, "challenge challenger id")?;
        ensure_non_empty(
            &self.respondent_validator_id,
            "challenge respondent validator id",
        )?;
        ensure_non_empty(&self.subject_id, "challenge subject id")?;
        ensure_non_empty(&self.subject_root, "challenge subject root")?;
        ensure_height_window(
            self.opened_height,
            self.response_due_height,
            "challenge response window",
        )?;
        ensure_height_window(
            self.response_due_height,
            self.adjudication_due_height,
            "challenge adjudication window",
        )?;
        ensure_positive(self.challenge_bond_units, "challenge bond units")?;
        ensure_non_empty(&self.adjudicator_root, "challenge adjudicator root")?;
        Ok(self.challenge_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoveragePool {
    pub pool_id: String,
    pub pool_kind: CoveragePoolKind,
    pub asset_id: String,
    pub sponsor_id: String,
    pub total_deposited_units: u64,
    pub reserved_units: u64,
    pub paid_units: u64,
    pub target_coverage_units: u64,
    pub coverage_bps: u64,
    pub reserve_root: String,
    pub active_from_height: u64,
    pub expires_height: u64,
    pub status: CoveragePoolStatus,
}

impl CoveragePool {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool_kind: CoveragePoolKind,
        asset_id: impl Into<String>,
        sponsor_id: impl Into<String>,
        total_deposited_units: u64,
        target_coverage_units: u64,
        reserve_root: impl Into<String>,
        active_from_height: u64,
        expires_height: u64,
    ) -> ValidatorSecurityResult<Self> {
        let asset_id = asset_id.into();
        let sponsor_id = sponsor_id.into();
        let reserve_root = reserve_root.into();
        ensure_non_empty(&asset_id, "coverage pool asset id")?;
        ensure_non_empty(&sponsor_id, "coverage pool sponsor id")?;
        ensure_positive(total_deposited_units, "coverage pool deposited units")?;
        ensure_positive(target_coverage_units, "coverage pool target coverage units")?;
        ensure_non_empty(&reserve_root, "coverage pool reserve root")?;
        ensure_height_window(
            active_from_height,
            expires_height,
            "coverage pool active window",
        )?;
        let coverage_bps = ratio_bps(total_deposited_units, target_coverage_units);
        let pool_id = validator_security_coverage_pool_id(
            pool_kind,
            &asset_id,
            &sponsor_id,
            total_deposited_units,
            target_coverage_units,
            &reserve_root,
            active_from_height,
        );
        Ok(Self {
            pool_id,
            pool_kind,
            asset_id,
            sponsor_id,
            total_deposited_units,
            reserved_units: 0,
            paid_units: 0,
            target_coverage_units,
            coverage_bps,
            reserve_root,
            active_from_height,
            expires_height,
            status: CoveragePoolStatus::Active,
        })
    }

    pub fn available_units(&self) -> u64 {
        self.total_deposited_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.paid_units)
    }

    pub fn refresh(&mut self, height: u64) {
        if height > self.expires_height {
            self.status = CoveragePoolStatus::Expired;
        } else if self.available_units() == 0 {
            self.status = CoveragePoolStatus::Depleted;
        } else if self.status != CoveragePoolStatus::Paused {
            self.status = CoveragePoolStatus::Active;
        }
        self.coverage_bps = ratio_bps(
            self.total_deposited_units.saturating_sub(self.paid_units),
            self.target_coverage_units,
        );
    }

    pub fn reserve_claim(&mut self, units: u64) -> ValidatorSecurityResult<String> {
        if units > self.available_units() {
            return Err("coverage pool claim reservation exceeds available units".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(units);
        Ok(self.pool_root())
    }

    pub fn settle_claim(
        &mut self,
        reserved_units: u64,
        paid_units: u64,
    ) -> ValidatorSecurityResult<String> {
        if reserved_units > self.reserved_units {
            return Err("coverage pool settlement releases more than reserved".to_string());
        }
        if paid_units > reserved_units {
            return Err("coverage pool paid units exceed reserved claim units".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_sub(reserved_units);
        self.paid_units = self.paid_units.saturating_add(paid_units);
        self.coverage_bps = ratio_bps(
            self.total_deposited_units.saturating_sub(self.paid_units),
            self.target_coverage_units,
        );
        if self.available_units() == 0 {
            self.status = CoveragePoolStatus::Depleted;
        }
        Ok(self.pool_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "validator_coverage_pool",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "pool_id": self.pool_id,
            "pool_kind": self.pool_kind.as_str(),
            "asset_id": self.asset_id,
            "sponsor_id": self.sponsor_id,
            "total_deposited_units": self.total_deposited_units,
            "reserved_units": self.reserved_units,
            "paid_units": self.paid_units,
            "available_units": self.available_units(),
            "target_coverage_units": self.target_coverage_units,
            "coverage_bps": self.coverage_bps,
            "reserve_root": self.reserve_root,
            "active_from_height": self.active_from_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "pool_root": self.pool_root(),
        })
    }

    pub fn pool_root(&self) -> String {
        validator_security_payload_root(
            "VALIDATOR-COVERAGE-POOL",
            &self.public_record_without_root(),
        )
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "validator_coverage_pool",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "pool_id": self.pool_id,
            "pool_kind": self.pool_kind.as_str(),
            "asset_id": self.asset_id,
            "sponsor_id": self.sponsor_id,
            "total_deposited_units": self.total_deposited_units,
            "reserved_units": self.reserved_units,
            "paid_units": self.paid_units,
            "available_units": self.available_units(),
            "target_coverage_units": self.target_coverage_units,
            "coverage_bps": self.coverage_bps,
            "reserve_root": self.reserve_root,
            "active_from_height": self.active_from_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ValidatorSecurityResult<String> {
        ensure_non_empty(&self.pool_id, "coverage pool id")?;
        ensure_non_empty(&self.asset_id, "coverage pool asset id")?;
        ensure_non_empty(&self.sponsor_id, "coverage pool sponsor id")?;
        ensure_positive(self.total_deposited_units, "coverage pool deposited units")?;
        ensure_positive(
            self.target_coverage_units,
            "coverage pool target coverage units",
        )?;
        if self.reserved_units.saturating_add(self.paid_units) > self.total_deposited_units {
            return Err("coverage pool reserved plus paid units exceed deposits".to_string());
        }
        ensure_non_empty(&self.reserve_root, "coverage pool reserve root")?;
        ensure_height_window(
            self.active_from_height,
            self.expires_height,
            "coverage pool active window",
        )?;
        Ok(self.pool_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageClaim {
    pub claim_id: String,
    pub pool_id: String,
    pub claimant_id: String,
    pub incident_id: String,
    pub subject_root: String,
    pub requested_units: u64,
    pub reserved_units: u64,
    pub approved_units: u64,
    pub payout_units: u64,
    pub opened_height: u64,
    pub decision_height: Option<u64>,
    pub expires_height: u64,
    pub status: CoverageClaimStatus,
    pub adjudication_id: Option<String>,
}

impl CoverageClaim {
    pub fn new(
        pool_id: impl Into<String>,
        claimant_id: impl Into<String>,
        incident_id: impl Into<String>,
        subject_root: impl Into<String>,
        requested_units: u64,
        opened_height: u64,
        expires_height: u64,
    ) -> ValidatorSecurityResult<Self> {
        let pool_id = pool_id.into();
        let claimant_id = claimant_id.into();
        let incident_id = incident_id.into();
        let subject_root = subject_root.into();
        ensure_non_empty(&pool_id, "coverage claim pool id")?;
        ensure_non_empty(&claimant_id, "coverage claim claimant id")?;
        ensure_non_empty(&incident_id, "coverage claim incident id")?;
        ensure_non_empty(&subject_root, "coverage claim subject root")?;
        ensure_positive(requested_units, "coverage claim requested units")?;
        ensure_height_window(opened_height, expires_height, "coverage claim window")?;
        let claim_id = validator_security_coverage_claim_id(
            &pool_id,
            &claimant_id,
            &incident_id,
            &subject_root,
            requested_units,
            opened_height,
        );
        Ok(Self {
            claim_id,
            pool_id,
            claimant_id,
            incident_id,
            subject_root,
            requested_units,
            reserved_units: 0,
            approved_units: 0,
            payout_units: 0,
            opened_height,
            decision_height: None,
            expires_height,
            status: CoverageClaimStatus::Open,
            adjudication_id: None,
        })
    }

    pub fn reserve(&mut self, units: u64) -> ValidatorSecurityResult<String> {
        if units > self.requested_units {
            return Err("coverage claim reserved units exceed requested units".to_string());
        }
        self.reserved_units = units;
        self.status = CoverageClaimStatus::Reserved;
        Ok(self.claim_root())
    }

    pub fn approve(
        &mut self,
        height: u64,
        approved_units: u64,
        adjudication_id: impl Into<String>,
    ) -> ValidatorSecurityResult<String> {
        let adjudication_id = adjudication_id.into();
        ensure_non_empty(&adjudication_id, "coverage claim adjudication id")?;
        if height > self.expires_height {
            return Err("coverage claim approval after expiry".to_string());
        }
        if approved_units > self.requested_units {
            return Err("coverage claim approved units exceed requested units".to_string());
        }
        self.approved_units = approved_units;
        self.payout_units = approved_units.min(self.reserved_units);
        self.decision_height = Some(height);
        self.status = CoverageClaimStatus::Approved;
        self.adjudication_id = Some(adjudication_id);
        Ok(self.claim_root())
    }

    pub fn reject(
        &mut self,
        height: u64,
        adjudication_id: impl Into<String>,
    ) -> ValidatorSecurityResult<String> {
        let adjudication_id = adjudication_id.into();
        ensure_non_empty(&adjudication_id, "coverage claim adjudication id")?;
        self.approved_units = 0;
        self.payout_units = 0;
        self.decision_height = Some(height);
        self.status = CoverageClaimStatus::Rejected;
        self.adjudication_id = Some(adjudication_id);
        Ok(self.claim_root())
    }

    pub fn mark_paid(&mut self) -> ValidatorSecurityResult<String> {
        if self.status != CoverageClaimStatus::Approved {
            return Err("coverage claim must be approved before payment".to_string());
        }
        self.status = CoverageClaimStatus::Paid;
        Ok(self.claim_root())
    }

    pub fn refresh(&mut self, height: u64) {
        if matches!(
            self.status,
            CoverageClaimStatus::Open | CoverageClaimStatus::Reserved
        ) && height > self.expires_height
        {
            self.status = CoverageClaimStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "validator_coverage_claim",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "claim_id": self.claim_id,
            "pool_id": self.pool_id,
            "claimant_id": self.claimant_id,
            "incident_id": self.incident_id,
            "subject_root": self.subject_root,
            "requested_units": self.requested_units,
            "reserved_units": self.reserved_units,
            "approved_units": self.approved_units,
            "payout_units": self.payout_units,
            "opened_height": self.opened_height,
            "decision_height": self.decision_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "adjudication_id": self.adjudication_id,
            "claim_root": self.claim_root(),
        })
    }

    pub fn claim_root(&self) -> String {
        validator_security_payload_root(
            "VALIDATOR-COVERAGE-CLAIM",
            &self.public_record_without_root(),
        )
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "validator_coverage_claim",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "claim_id": self.claim_id,
            "pool_id": self.pool_id,
            "claimant_id": self.claimant_id,
            "incident_id": self.incident_id,
            "subject_root": self.subject_root,
            "requested_units": self.requested_units,
            "reserved_units": self.reserved_units,
            "approved_units": self.approved_units,
            "payout_units": self.payout_units,
            "opened_height": self.opened_height,
            "decision_height": self.decision_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "adjudication_id": self.adjudication_id,
        })
    }

    pub fn validate(&self) -> ValidatorSecurityResult<String> {
        ensure_non_empty(&self.claim_id, "coverage claim id")?;
        ensure_non_empty(&self.pool_id, "coverage claim pool id")?;
        ensure_non_empty(&self.claimant_id, "coverage claim claimant id")?;
        ensure_non_empty(&self.incident_id, "coverage claim incident id")?;
        ensure_non_empty(&self.subject_root, "coverage claim subject root")?;
        ensure_positive(self.requested_units, "coverage claim requested units")?;
        if self.reserved_units > self.requested_units {
            return Err("coverage claim reserved units exceed requested units".to_string());
        }
        if self.approved_units > self.requested_units {
            return Err("coverage claim approved units exceed requested units".to_string());
        }
        if self.payout_units > self.approved_units {
            return Err("coverage claim payout units exceed approved units".to_string());
        }
        ensure_height_window(
            self.opened_height,
            self.expires_height,
            "coverage claim window",
        )?;
        Ok(self.claim_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeValidatorSubsidyEpoch {
    pub subsidy_id: String,
    pub epoch_index: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub fee_asset_id: String,
    pub sponsor_id: String,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub earned_units: u64,
    pub paid_units: u64,
    pub validator_reward_root: String,
    pub status: SubsidyStatus,
}

impl LowFeeValidatorSubsidyEpoch {
    pub fn new(
        epoch_index: u64,
        start_height: u64,
        end_height: u64,
        fee_asset_id: impl Into<String>,
        sponsor_id: impl Into<String>,
        budget_units: u64,
    ) -> ValidatorSecurityResult<Self> {
        let fee_asset_id = fee_asset_id.into();
        let sponsor_id = sponsor_id.into();
        ensure_height_window(start_height, end_height, "low fee subsidy epoch")?;
        ensure_non_empty(&fee_asset_id, "low fee subsidy fee asset id")?;
        ensure_non_empty(&sponsor_id, "low fee subsidy sponsor id")?;
        ensure_positive(budget_units, "low fee subsidy budget units")?;
        let validator_reward_root = validator_security_empty_root("VALIDATOR-LOW-FEE-REWARD");
        let subsidy_id = validator_security_subsidy_epoch_id(
            epoch_index,
            start_height,
            end_height,
            &fee_asset_id,
            &sponsor_id,
            budget_units,
        );
        Ok(Self {
            subsidy_id,
            epoch_index,
            start_height,
            end_height,
            fee_asset_id,
            sponsor_id,
            budget_units,
            reserved_units: 0,
            earned_units: 0,
            paid_units: 0,
            validator_reward_root,
            status: SubsidyStatus::Active,
        })
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.earned_units)
            .saturating_sub(self.paid_units)
    }

    pub fn contains_height(&self, height: u64) -> bool {
        self.start_height <= height && height <= self.end_height
    }

    pub fn refresh(&mut self, height: u64) {
        if self.paid_units >= self.budget_units {
            self.status = SubsidyStatus::Exhausted;
        } else if height > self.end_height && self.earned_units == self.paid_units {
            self.status = SubsidyStatus::Settled;
        } else if height > self.end_height {
            self.status = SubsidyStatus::Expired;
        }
    }

    pub fn apply_reward(
        &mut self,
        reward: &LowFeeValidatorReward,
    ) -> ValidatorSecurityResult<String> {
        if reward.subsidy_id != self.subsidy_id {
            return Err("low fee reward subsidy mismatch".to_string());
        }
        if reward.earned_units > self.available_units() {
            return Err("low fee reward exceeds available subsidy budget".to_string());
        }
        self.earned_units = self.earned_units.saturating_add(reward.earned_units);
        Ok(self.subsidy_root())
    }

    pub fn settle_reward(&mut self, claimed_units: u64) -> ValidatorSecurityResult<String> {
        if self.paid_units.saturating_add(claimed_units) > self.earned_units {
            return Err("low fee subsidy paid units exceed earned units".to_string());
        }
        self.paid_units = self.paid_units.saturating_add(claimed_units);
        Ok(self.subsidy_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_validator_subsidy_epoch",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "subsidy_id": self.subsidy_id,
            "epoch_index": self.epoch_index,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "fee_asset_id": self.fee_asset_id,
            "sponsor_id": self.sponsor_id,
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "earned_units": self.earned_units,
            "paid_units": self.paid_units,
            "available_units": self.available_units(),
            "validator_reward_root": self.validator_reward_root,
            "status": self.status.as_str(),
            "subsidy_root": self.subsidy_root(),
        })
    }

    pub fn subsidy_root(&self) -> String {
        validator_security_payload_root(
            "VALIDATOR-LOW-FEE-SUBSIDY-EPOCH",
            &self.public_record_without_root(),
        )
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "low_fee_validator_subsidy_epoch",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "subsidy_id": self.subsidy_id,
            "epoch_index": self.epoch_index,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "fee_asset_id": self.fee_asset_id,
            "sponsor_id": self.sponsor_id,
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "earned_units": self.earned_units,
            "paid_units": self.paid_units,
            "available_units": self.available_units(),
            "validator_reward_root": self.validator_reward_root,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ValidatorSecurityResult<String> {
        ensure_non_empty(&self.subsidy_id, "low fee subsidy id")?;
        ensure_height_window(self.start_height, self.end_height, "low fee subsidy epoch")?;
        ensure_non_empty(&self.fee_asset_id, "low fee subsidy fee asset id")?;
        ensure_non_empty(&self.sponsor_id, "low fee subsidy sponsor id")?;
        ensure_positive(self.budget_units, "low fee subsidy budget units")?;
        if self
            .reserved_units
            .saturating_add(self.earned_units)
            .saturating_add(self.paid_units)
            > self.budget_units
        {
            return Err("low fee subsidy accounting exceeds budget".to_string());
        }
        ensure_non_empty(
            &self.validator_reward_root,
            "low fee subsidy validator reward root",
        )?;
        Ok(self.subsidy_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeValidatorReward {
    pub reward_id: String,
    pub subsidy_id: String,
    pub validator_id: String,
    pub role: ValidatorRole,
    pub earned_units: u64,
    pub claimed_units: u64,
    pub liveness_score_bps: u64,
    pub fee_rebate_bps: u64,
    pub subject_root: String,
    pub status: SubsidyStatus,
}

impl LowFeeValidatorReward {
    pub fn new(
        subsidy_id: impl Into<String>,
        validator_id: impl Into<String>,
        role: ValidatorRole,
        earned_units: u64,
        liveness_score_bps: u64,
        fee_rebate_bps: u64,
        subject_root: impl Into<String>,
    ) -> ValidatorSecurityResult<Self> {
        let subsidy_id = subsidy_id.into();
        let validator_id = validator_id.into();
        let subject_root = subject_root.into();
        ensure_non_empty(&subsidy_id, "low fee reward subsidy id")?;
        ensure_non_empty(&validator_id, "low fee reward validator id")?;
        ensure_positive(earned_units, "low fee reward earned units")?;
        ensure_bps(liveness_score_bps, "low fee reward liveness score bps")?;
        ensure_bps(fee_rebate_bps, "low fee reward fee rebate bps")?;
        ensure_non_empty(&subject_root, "low fee reward subject root")?;
        let reward_id = validator_security_subsidy_reward_id(
            &subsidy_id,
            &validator_id,
            role,
            earned_units,
            liveness_score_bps,
            fee_rebate_bps,
            &subject_root,
        );
        Ok(Self {
            reward_id,
            subsidy_id,
            validator_id,
            role,
            earned_units,
            claimed_units: 0,
            liveness_score_bps,
            fee_rebate_bps,
            subject_root,
            status: SubsidyStatus::Active,
        })
    }

    pub fn claim(&mut self, units: u64) -> ValidatorSecurityResult<String> {
        if self.claimed_units.saturating_add(units) > self.earned_units {
            return Err("low fee reward claim exceeds earned units".to_string());
        }
        self.claimed_units = self.claimed_units.saturating_add(units);
        if self.claimed_units >= self.earned_units {
            self.status = SubsidyStatus::Settled;
        }
        Ok(self.reward_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_validator_reward",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "reward_id": self.reward_id,
            "subsidy_id": self.subsidy_id,
            "validator_id": self.validator_id,
            "role": self.role.as_str(),
            "earned_units": self.earned_units,
            "claimed_units": self.claimed_units,
            "liveness_score_bps": self.liveness_score_bps,
            "fee_rebate_bps": self.fee_rebate_bps,
            "subject_root": self.subject_root,
            "status": self.status.as_str(),
            "reward_root": self.reward_root(),
        })
    }

    pub fn reward_root(&self) -> String {
        validator_security_payload_root(
            "VALIDATOR-LOW-FEE-REWARD",
            &self.public_record_without_root(),
        )
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "low_fee_validator_reward",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "reward_id": self.reward_id,
            "subsidy_id": self.subsidy_id,
            "validator_id": self.validator_id,
            "role": self.role.as_str(),
            "earned_units": self.earned_units,
            "claimed_units": self.claimed_units,
            "liveness_score_bps": self.liveness_score_bps,
            "fee_rebate_bps": self.fee_rebate_bps,
            "subject_root": self.subject_root,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ValidatorSecurityResult<String> {
        ensure_non_empty(&self.reward_id, "low fee reward id")?;
        ensure_non_empty(&self.subsidy_id, "low fee reward subsidy id")?;
        ensure_non_empty(&self.validator_id, "low fee reward validator id")?;
        ensure_positive(self.earned_units, "low fee reward earned units")?;
        if self.claimed_units > self.earned_units {
            return Err("low fee reward claimed units exceed earned units".to_string());
        }
        ensure_bps(self.liveness_score_bps, "low fee reward liveness score bps")?;
        ensure_bps(self.fee_rebate_bps, "low fee reward fee rebate bps")?;
        ensure_non_empty(&self.subject_root, "low fee reward subject root")?;
        Ok(self.reward_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSecurityEvent {
    pub event_id: String,
    pub sequence: u64,
    pub height: u64,
    pub event_kind: ValidatorSecurityEventKind,
    pub actor: String,
    pub subject_id: String,
    pub subject_root: String,
    pub amount_units: u64,
    pub details_root: String,
}

impl ValidatorSecurityEvent {
    pub fn new(
        sequence: u64,
        height: u64,
        event_kind: ValidatorSecurityEventKind,
        actor: impl Into<String>,
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        amount_units: u64,
        details: &Value,
    ) -> ValidatorSecurityResult<Self> {
        let actor = actor.into();
        let subject_id = subject_id.into();
        let subject_root = subject_root.into();
        ensure_non_empty(&actor, "validator security event actor")?;
        ensure_non_empty(&subject_id, "validator security event subject id")?;
        ensure_non_empty(&subject_root, "validator security event subject root")?;
        let details_root =
            validator_security_payload_root("VALIDATOR-SECURITY-EVENT-DETAILS", details);
        let event_id = validator_security_event_id(
            sequence,
            height,
            event_kind,
            &actor,
            &subject_id,
            &subject_root,
            amount_units,
            &details_root,
        );
        Ok(Self {
            event_id,
            sequence,
            height,
            event_kind,
            actor,
            subject_id,
            subject_root,
            amount_units,
            details_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "validator_security_event",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "event_id": self.event_id,
            "sequence": self.sequence,
            "height": self.height,
            "event_kind": self.event_kind.as_str(),
            "actor": self.actor,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "amount_units": self.amount_units,
            "details_root": self.details_root,
            "event_root": self.event_root(),
        })
    }

    pub fn event_root(&self) -> String {
        validator_security_payload_root(
            "VALIDATOR-SECURITY-EVENT",
            &self.public_record_without_root(),
        )
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "validator_security_event",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "event_id": self.event_id,
            "sequence": self.sequence,
            "height": self.height,
            "event_kind": self.event_kind.as_str(),
            "actor": self.actor,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "amount_units": self.amount_units,
            "details_root": self.details_root,
        })
    }

    pub fn validate(&self) -> ValidatorSecurityResult<String> {
        ensure_non_empty(&self.event_id, "validator security event id")?;
        ensure_non_empty(&self.actor, "validator security event actor")?;
        ensure_non_empty(&self.subject_id, "validator security event subject id")?;
        ensure_non_empty(&self.subject_root, "validator security event subject root")?;
        ensure_non_empty(&self.details_root, "validator security event details root")?;
        Ok(self.event_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSecurityCounters {
    pub validator_count: u64,
    pub active_validator_count: u64,
    pub jailed_validator_count: u64,
    pub key_set_count: u64,
    pub stake_position_count: u64,
    pub bond_position_count: u64,
    pub committee_epoch_count: u64,
    pub slashing_evidence_count: u64,
    pub accepted_slashing_evidence_count: u64,
    pub liveness_report_count: u64,
    pub downtime_score_count: u64,
    pub key_rotation_count: u64,
    pub withdrawal_count: u64,
    pub open_challenge_count: u64,
    pub coverage_pool_count: u64,
    pub coverage_claim_count: u64,
    pub subsidy_epoch_count: u64,
    pub subsidy_reward_count: u64,
    pub event_count: u64,
    pub total_stake_units: u64,
    pub total_bond_units: u64,
    pub total_slashed_units: u64,
    pub total_coverage_units: u64,
    pub total_subsidy_budget_units: u64,
}

impl ValidatorSecurityCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "validator_security_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "validator_count": self.validator_count,
            "active_validator_count": self.active_validator_count,
            "jailed_validator_count": self.jailed_validator_count,
            "key_set_count": self.key_set_count,
            "stake_position_count": self.stake_position_count,
            "bond_position_count": self.bond_position_count,
            "committee_epoch_count": self.committee_epoch_count,
            "slashing_evidence_count": self.slashing_evidence_count,
            "accepted_slashing_evidence_count": self.accepted_slashing_evidence_count,
            "liveness_report_count": self.liveness_report_count,
            "downtime_score_count": self.downtime_score_count,
            "key_rotation_count": self.key_rotation_count,
            "withdrawal_count": self.withdrawal_count,
            "open_challenge_count": self.open_challenge_count,
            "coverage_pool_count": self.coverage_pool_count,
            "coverage_claim_count": self.coverage_claim_count,
            "subsidy_epoch_count": self.subsidy_epoch_count,
            "subsidy_reward_count": self.subsidy_reward_count,
            "event_count": self.event_count,
            "total_stake_units": self.total_stake_units,
            "total_bond_units": self.total_bond_units,
            "total_slashed_units": self.total_slashed_units,
            "total_coverage_units": self.total_coverage_units,
            "total_subsidy_budget_units": self.total_subsidy_budget_units,
        })
    }

    pub fn counters_root(&self) -> String {
        validator_security_payload_root("VALIDATOR-SECURITY-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSecurityRoots {
    pub config_root: String,
    pub validator_root: String,
    pub key_set_root: String,
    pub stake_position_root: String,
    pub bond_position_root: String,
    pub committee_epoch_root: String,
    pub slashing_evidence_root: String,
    pub liveness_report_root: String,
    pub downtime_score_root: String,
    pub key_rotation_root: String,
    pub withdrawal_root: String,
    pub challenge_root: String,
    pub coverage_pool_root: String,
    pub coverage_claim_root: String,
    pub subsidy_epoch_root: String,
    pub subsidy_reward_root: String,
    pub event_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl ValidatorSecurityRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "validator_security_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "validator_root": self.validator_root,
            "key_set_root": self.key_set_root,
            "stake_position_root": self.stake_position_root,
            "bond_position_root": self.bond_position_root,
            "committee_epoch_root": self.committee_epoch_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "liveness_report_root": self.liveness_report_root,
            "downtime_score_root": self.downtime_score_root,
            "key_rotation_root": self.key_rotation_root,
            "withdrawal_root": self.withdrawal_root,
            "challenge_root": self.challenge_root,
            "coverage_pool_root": self.coverage_pool_root,
            "coverage_claim_root": self.coverage_claim_root,
            "subsidy_epoch_root": self.subsidy_epoch_root,
            "subsidy_reward_root": self.subsidy_reward_root,
            "event_root": self.event_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }

    pub fn roots_root(&self) -> String {
        validator_security_payload_root(
            "VALIDATOR-SECURITY-ROOTS",
            &self.public_record_without_root(),
        )
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "validator_security_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "validator_root": self.validator_root,
            "key_set_root": self.key_set_root,
            "stake_position_root": self.stake_position_root,
            "bond_position_root": self.bond_position_root,
            "committee_epoch_root": self.committee_epoch_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "liveness_report_root": self.liveness_report_root,
            "downtime_score_root": self.downtime_score_root,
            "key_rotation_root": self.key_rotation_root,
            "withdrawal_root": self.withdrawal_root,
            "challenge_root": self.challenge_root,
            "coverage_pool_root": self.coverage_pool_root,
            "coverage_claim_root": self.coverage_claim_root,
            "subsidy_epoch_root": self.subsidy_epoch_root,
            "subsidy_reward_root": self.subsidy_reward_root,
            "event_root": self.event_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSecurityState {
    pub config: ValidatorSecurityConfig,
    pub height: u64,
    pub next_event_sequence: u64,
    pub validators: BTreeMap<String, ValidatorIdentity>,
    pub key_sets: BTreeMap<String, PqPublicKeySet>,
    pub stake_positions: BTreeMap<String, StakePosition>,
    pub bond_positions: BTreeMap<String, BondPosition>,
    pub committee_epochs: BTreeMap<String, CommitteeEpoch>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub liveness_reports: BTreeMap<String, LivenessReport>,
    pub downtime_scores: BTreeMap<String, DowntimeScore>,
    pub key_rotations: BTreeMap<String, KeyRotationCeremony>,
    pub withdrawals: BTreeMap<String, StakeWithdrawalRequest>,
    pub challenges: BTreeMap<String, ChallengeCase>,
    pub coverage_pools: BTreeMap<String, CoveragePool>,
    pub coverage_claims: BTreeMap<String, CoverageClaim>,
    pub subsidy_epochs: BTreeMap<String, LowFeeValidatorSubsidyEpoch>,
    pub subsidy_rewards: BTreeMap<String, LowFeeValidatorReward>,
    pub events: BTreeMap<String, ValidatorSecurityEvent>,
}

impl Default for ValidatorSecurityState {
    fn default() -> Self {
        Self {
            config: ValidatorSecurityConfig::default(),
            height: 0,
            next_event_sequence: 0,
            validators: BTreeMap::new(),
            key_sets: BTreeMap::new(),
            stake_positions: BTreeMap::new(),
            bond_positions: BTreeMap::new(),
            committee_epochs: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            liveness_reports: BTreeMap::new(),
            downtime_scores: BTreeMap::new(),
            key_rotations: BTreeMap::new(),
            withdrawals: BTreeMap::new(),
            challenges: BTreeMap::new(),
            coverage_pools: BTreeMap::new(),
            coverage_claims: BTreeMap::new(),
            subsidy_epochs: BTreeMap::new(),
            subsidy_rewards: BTreeMap::new(),
            events: BTreeMap::new(),
        }
    }
}

impl ValidatorSecurityState {
    pub fn new(config: ValidatorSecurityConfig) -> ValidatorSecurityResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::default()
        })
    }

    pub fn devnet() -> ValidatorSecurityResult<Self> {
        let mut state = Self {
            height: VALIDATOR_SECURITY_DEVNET_HEIGHT,
            ..Self::default()
        };
        state.config.validate()?;

        let alice_roles = role_set(&[
            ValidatorRole::BlockProducer,
            ValidatorRole::BridgeSigner,
            ValidatorRole::ReserveAuditor,
            ValidatorRole::ChallengeJudge,
        ]);
        let bob_roles = role_set(&[
            ValidatorRole::BlockProducer,
            ValidatorRole::Prover,
            ValidatorRole::FeeSponsor,
        ]);
        let carla_roles = role_set(&[
            ValidatorRole::Prover,
            ValidatorRole::BridgeObserver,
            ValidatorRole::ReserveAuditor,
        ]);
        let diego_roles = role_set(&[
            ValidatorRole::BlockProducer,
            ValidatorRole::BridgeObserver,
            ValidatorRole::ChallengeJudge,
        ]);

        let alice_id = state.register_devnet_validator(
            "devnet-validator-alice",
            0,
            alice_roles,
            2_500_000,
            450_000,
            1,
        )?;
        let bob_id = state.register_devnet_validator(
            "devnet-validator-bob",
            1,
            bob_roles,
            1_800_000,
            300_000,
            2,
        )?;
        let carla_id = state.register_devnet_validator(
            "devnet-validator-carla",
            2,
            carla_roles,
            1_450_000,
            275_000,
            3,
        )?;
        let diego_id = state.register_devnet_validator(
            "devnet-validator-diego",
            3,
            diego_roles,
            1_200_000,
            225_000,
            4,
        )?;

        let epoch_id = state.form_committee_epoch(
            0,
            48,
            48 + state.config.epoch_length_blocks - 1,
            validator_security_string_root("VALIDATOR-DEVNET-COMMITTEE-SEED", "epoch-0"),
            &[
                ValidatorRole::BlockProducer,
                ValidatorRole::Prover,
                ValidatorRole::BridgeObserver,
                ValidatorRole::BridgeSigner,
                ValidatorRole::ReserveAuditor,
                ValidatorRole::FeeSponsor,
                ValidatorRole::ChallengeJudge,
            ],
        )?;

        state.apply_liveness_report(LivenessReport::new(
            &alice_id,
            &epoch_id,
            0,
            48,
            119,
            32,
            32,
            1,
            state.config.downtime_jail_threshold_bps,
            state.config.downtime_slash_threshold_bps,
            &json!({"fixture": "alice_signed_all_slots"}),
        )?)?;
        state.apply_liveness_report(LivenessReport::new(
            &bob_id,
            &epoch_id,
            0,
            48,
            119,
            32,
            30,
            2,
            state.config.downtime_jail_threshold_bps,
            state.config.downtime_slash_threshold_bps,
            &json!({"fixture": "bob_minor_lateness"}),
        )?)?;
        state.apply_liveness_report(LivenessReport::new(
            &carla_id,
            &epoch_id,
            0,
            48,
            119,
            32,
            27,
            4,
            state.config.downtime_jail_threshold_bps,
            state.config.downtime_slash_threshold_bps,
            &json!({"fixture": "carla_warning_window"}),
        )?)?;
        state.apply_liveness_report(LivenessReport::new(
            &diego_id,
            &epoch_id,
            0,
            48,
            119,
            32,
            24,
            3,
            state.config.downtime_jail_threshold_bps,
            state.config.downtime_slash_threshold_bps,
            &json!({"fixture": "diego_jailable_window"}),
        )?)?;

        let bob_previous_key = state
            .validators
            .get(&bob_id)
            .ok_or_else(|| "missing bob validator".to_string())?
            .current_key_set_id
            .clone();
        let bob_previous_key_set = state
            .key_sets
            .get(&bob_previous_key)
            .cloned()
            .ok_or_else(|| "missing bob previous key set".to_string())?;
        let bob_next_key_set = PqPublicKeySet::devnet("devnet-validator-bob", 11, state.height)?;
        let rotation = KeyRotationCeremony::new(
            &bob_id,
            &bob_previous_key_set,
            &bob_next_key_set,
            60,
            72,
            state.config.key_rotation_grace_blocks,
            &[alice_id.clone(), carla_id.clone(), diego_id.clone()],
            3_000_000,
        )?;
        state.start_key_rotation(rotation, bob_next_key_set)?;

        let bridge_pool = CoveragePool::new(
            CoveragePoolKind::BridgeCustody,
            VALIDATOR_SECURITY_DEVNET_BRIDGE_ASSET_ID,
            &alice_id,
            1_250_000,
            1_000_000,
            validator_security_string_root("VALIDATOR-DEVNET-RESERVE", "bridge-custody"),
            48,
            48 + 4_320,
        )?;
        let bridge_pool_id = state.create_coverage_pool(bridge_pool)?;
        let proof_pool = CoveragePool::new(
            CoveragePoolKind::InvalidProof,
            VALIDATOR_SECURITY_DEVNET_ASSET_ID,
            &bob_id,
            750_000,
            600_000,
            validator_security_string_root("VALIDATOR-DEVNET-RESERVE", "invalid-proof"),
            48,
            48 + 4_320,
        )?;
        state.create_coverage_pool(proof_pool)?;

        let mut claim = CoverageClaim::new(
            &bridge_pool_id,
            "devnet-bridge-user-cohort",
            "devnet-bridge-delay-incident",
            validator_security_string_root("VALIDATOR-DEVNET-COVERAGE-SUBJECT", "bridge-delay"),
            25_000,
            63,
            63 + state.config.challenge_period_blocks,
        )?;
        claim.reserve(25_000)?;
        let claim_id = state.open_coverage_claim(claim)?;
        state.adjudicate_coverage_claim(
            &claim_id,
            true,
            20_000,
            "devnet-coverage-adjudicators",
            64,
        )?;

        let subsidy = LowFeeValidatorSubsidyEpoch::new(
            0,
            48,
            48 + state.config.epoch_length_blocks - 1,
            VALIDATOR_SECURITY_DEVNET_FEE_ASSET_ID,
            "devnet-low-fee-foundation",
            state.config.low_fee_epoch_budget_units,
        )?;
        let subsidy_id = state.create_subsidy_epoch(subsidy)?;
        state.record_subsidy_reward(LowFeeValidatorReward::new(
            &subsidy_id,
            &alice_id,
            ValidatorRole::BlockProducer,
            30_000,
            9_950,
            state.config.low_fee_rebate_bps,
            validator_security_string_root("VALIDATOR-DEVNET-LOW-FEE-SUBJECT", "alice"),
        )?)?;
        state.record_subsidy_reward(LowFeeValidatorReward::new(
            &subsidy_id,
            &bob_id,
            ValidatorRole::FeeSponsor,
            24_000,
            9_300,
            state.config.low_fee_rebate_bps,
            validator_security_string_root("VALIDATOR-DEVNET-LOW-FEE-SUBJECT", "bob"),
        )?)?;

        let evidence = SlashingEvidence::new(
            SlashingEvidenceKind::Downtime,
            &alice_id,
            &diego_id,
            "devnet-liveness-window-0",
            validator_security_string_root("VALIDATOR-DEVNET-SLASH-SUBJECT", "diego-downtime"),
            None,
            119,
            120,
            120 + state.config.challenge_period_blocks,
            state.config.missed_slot_slash_bps,
            &json!({"fixture": "diego missed a jailable window"}),
        )?;
        let evidence_id = state.submit_slashing_evidence(evidence)?;
        state.finalize_slashing_evidence(
            &evidence_id,
            false,
            validator_security_string_root("VALIDATOR-DEVNET-ADJUDICATION", "downtime-dismissed"),
        )?;

        let diego_position = state
            .stake_positions
            .values()
            .find(|position| position.validator_id == diego_id)
            .map(|position| position.position_id.clone())
            .ok_or_else(|| "missing diego stake position".to_string())?;
        let withdrawal_id = state.request_stake_withdrawal(
            &diego_id,
            &diego_position,
            100_000,
            validator_security_string_root("VALIDATOR-DEVNET-WITHDRAWAL-RECIPIENT", "diego"),
        )?;
        let challenge = ChallengeCase::new(
            ChallengeKind::Withdrawal,
            &alice_id,
            &diego_id,
            &withdrawal_id,
            state
                .withdrawals
                .get(&withdrawal_id)
                .map(StakeWithdrawalRequest::withdrawal_root)
                .ok_or_else(|| "missing devnet withdrawal".to_string())?,
            state.height,
            state.config.challenge_response_blocks,
            state.config.challenge_period_blocks,
            100_000,
            5_000,
        )?;
        let challenge_id = state.open_challenge(challenge)?;
        state.respond_challenge(
            &challenge_id,
            state.height + 1,
            &json!({"fixture": "withdrawal still above minimum stake"}),
        )?;
        state.adjudicate_challenge(
            &challenge_id,
            state.height + 2,
            ChallengeDecision::RespondentWins,
            validator_security_string_root("VALIDATOR-DEVNET-ADJUDICATOR", "withdrawal-panel"),
            0,
            0,
        )?;

        state.append_event(
            ValidatorSecurityEventKind::DevnetGenesis,
            "devnet-fixture",
            "validator-security-devnet",
            state.roots().roots_root(),
            0,
            &json!({
                "validators": [&alice_id, &bob_id, &carla_id, &diego_id],
                "committee_epoch_id": epoch_id,
                "subsidy_id": subsidy_id,
            }),
        )?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> ValidatorSecurityResult<String> {
        if height < self.height {
            return Err("validator security height cannot move backward".to_string());
        }
        self.height = height;
        for validator in self.validators.values_mut() {
            validator.refresh(height, self.config.min_validator_stake_units);
        }
        for position in self.stake_positions.values_mut() {
            position.refresh(height);
        }
        for epoch in self.committee_epochs.values_mut() {
            epoch.refresh(height, self.config.key_rotation_grace_blocks);
        }
        for evidence in self.slashing_evidence.values_mut() {
            evidence.refresh(height);
        }
        for rotation in self.key_rotations.values_mut() {
            rotation.refresh(height);
        }
        for withdrawal in self.withdrawals.values_mut() {
            withdrawal.refresh(height);
        }
        for challenge in self.challenges.values_mut() {
            challenge.refresh(height);
        }
        for pool in self.coverage_pools.values_mut() {
            pool.refresh(height);
        }
        for claim in self.coverage_claims.values_mut() {
            claim.refresh(height);
        }
        for subsidy in self.subsidy_epochs.values_mut() {
            subsidy.refresh(height);
        }
        self.recompute_validator_totals()?;
        self.append_event(
            ValidatorSecurityEventKind::HeightAdvanced,
            "validator-security-clock",
            "height",
            validator_security_string_root("VALIDATOR-SECURITY-HEIGHT", &height.to_string()),
            0,
            &json!({"height": height}),
        )?;
        Ok(self.state_root())
    }

    pub fn register_validator(
        &mut self,
        identity: ValidatorIdentity,
        key_set: PqPublicKeySet,
    ) -> ValidatorSecurityResult<String> {
        key_set.validate()?;
        identity.validate()?;
        if identity.current_key_set_id != key_set.key_set_id {
            return Err("validator identity references a different key set".to_string());
        }
        if identity.key_set_root != key_set.key_root() {
            return Err("validator identity key root is stale".to_string());
        }
        insert_unique_record(
            &mut self.key_sets,
            key_set.key_set_id.clone(),
            key_set,
            "validator key set",
        )?;
        let validator_id = identity.validator_id.clone();
        insert_unique_record(
            &mut self.validators,
            validator_id.clone(),
            identity.clone(),
            "validator identity",
        )?;
        self.downtime_scores
            .insert(validator_id.clone(), DowntimeScore::new(&validator_id)?);
        self.append_event(
            ValidatorSecurityEventKind::ValidatorRegistered,
            &identity.operator_label,
            &validator_id,
            identity.identity_root(),
            0,
            &identity.public_record(),
        )?;
        Ok(validator_id)
    }

    pub fn add_stake_position(
        &mut self,
        position: StakePosition,
    ) -> ValidatorSecurityResult<String> {
        position.validate()?;
        if !self.validators.contains_key(&position.validator_id) {
            return Err("stake position references unknown validator".to_string());
        }
        let position_id = position.position_id.clone();
        insert_unique_record(
            &mut self.stake_positions,
            position_id.clone(),
            position.clone(),
            "stake position",
        )?;
        self.recompute_validator_totals()?;
        self.append_event(
            ValidatorSecurityEventKind::StakeBonded,
            &position.validator_id,
            &position_id,
            position.position_root(),
            position.amount_units,
            &position.public_record(),
        )?;
        Ok(position_id)
    }

    pub fn add_bond_position(&mut self, bond: BondPosition) -> ValidatorSecurityResult<String> {
        bond.validate()?;
        if !self.validators.contains_key(&bond.validator_id) {
            return Err("bond position references unknown validator".to_string());
        }
        let bond_id = bond.bond_id.clone();
        insert_unique_record(
            &mut self.bond_positions,
            bond_id.clone(),
            bond.clone(),
            "bond position",
        )?;
        self.recompute_validator_totals()?;
        self.append_event(
            ValidatorSecurityEventKind::BondLocked,
            &bond.validator_id,
            &bond_id,
            bond.bond_root(),
            bond.amount_units,
            &bond.public_record(),
        )?;
        Ok(bond_id)
    }

    pub fn form_committee_epoch(
        &mut self,
        epoch_index: u64,
        start_height: u64,
        end_height: u64,
        seed_root: String,
        roles: &[ValidatorRole],
    ) -> ValidatorSecurityResult<String> {
        let mut candidates = Vec::new();
        for validator in self.validators.values() {
            if !validator.is_active_at(start_height) {
                continue;
            }
            let role = roles
                .iter()
                .copied()
                .find(|role| validator.has_role(*role))
                .unwrap_or(ValidatorRole::BlockProducer);
            if !validator.has_role(role) {
                continue;
            }
            let stake_ids = self
                .stake_positions
                .values()
                .filter(|position| {
                    position.validator_id == validator.validator_id
                        && position.status == StakePositionStatus::Bonded
                })
                .map(|position| position.position_id.clone())
                .collect::<Vec<_>>();
            let bond_ids = self
                .bond_positions
                .values()
                .filter(|bond| {
                    bond.validator_id == validator.validator_id
                        && bond.status == StakePositionStatus::Bonded
                })
                .map(|bond| bond.bond_id.clone())
                .collect::<Vec<_>>();
            let weight_units = validator
                .total_stake_units
                .saturating_add(validator.total_bond_units);
            if weight_units < self.config.min_validator_stake_units {
                continue;
            }
            let selection_score = deterministic_u64(
                "VALIDATOR-COMMITTEE-SELECTION",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(&seed_root),
                    HashPart::Str(&validator.validator_id),
                    HashPart::Int(epoch_index as i128),
                ],
            );
            candidates.push(CommitteeMember {
                validator_id: validator.validator_id.clone(),
                role,
                weight_units,
                stake_position_ids: stake_ids,
                bond_position_ids: bond_ids,
                key_set_id: validator.current_key_set_id.clone(),
                selection_score,
                joined_height: start_height,
            });
        }
        candidates.sort_by_key(|member| (member.selection_score, member.validator_id.clone()));
        candidates.truncate(self.config.committee_size_target);
        let mut epoch =
            CommitteeEpoch::new(epoch_index, start_height, end_height, seed_root, candidates)?;
        epoch.refresh(self.height, self.config.key_rotation_grace_blocks);
        let epoch_id = epoch.epoch_id.clone();
        insert_unique_record(
            &mut self.committee_epochs,
            epoch_id.clone(),
            epoch.clone(),
            "committee epoch",
        )?;
        self.append_event(
            ValidatorSecurityEventKind::CommitteeOpened,
            "committee-selection",
            &epoch_id,
            epoch.epoch_root(),
            epoch.total_weight_units,
            &epoch.public_record(),
        )?;
        Ok(epoch_id)
    }

    pub fn submit_slashing_evidence(
        &mut self,
        evidence: SlashingEvidence,
    ) -> ValidatorSecurityResult<String> {
        evidence.validate()?;
        if !self.validators.contains_key(&evidence.accused_validator_id) {
            return Err("slashing evidence references unknown accused validator".to_string());
        }
        if !self.validators.contains_key(&evidence.reporter_id) {
            return Err("slashing evidence references unknown reporter".to_string());
        }
        let evidence_id = evidence.evidence_id.clone();
        insert_unique_record(
            &mut self.slashing_evidence,
            evidence_id.clone(),
            evidence.clone(),
            "slashing evidence",
        )?;
        self.append_event(
            ValidatorSecurityEventKind::EvidenceSubmitted,
            &evidence.reporter_id,
            &evidence_id,
            evidence.evidence_root(),
            0,
            &evidence.public_record(),
        )?;
        Ok(evidence_id)
    }

    pub fn finalize_slashing_evidence(
        &mut self,
        evidence_id: &str,
        accepted: bool,
        adjudication_id: String,
    ) -> ValidatorSecurityResult<String> {
        let (accused_validator_id, slash_bps, evidence_root, evidence_record) = {
            let evidence = self
                .slashing_evidence
                .get_mut(evidence_id)
                .ok_or_else(|| "unknown slashing evidence".to_string())?;
            if accepted {
                evidence.accept(adjudication_id)?;
            } else {
                evidence.reject(adjudication_id)?;
            }
            (
                evidence.accused_validator_id.clone(),
                evidence.slash_bps,
                evidence.evidence_root(),
                evidence.public_record(),
            )
        };
        if accepted {
            let slashed_units = self.apply_validator_slash(&accused_validator_id, slash_bps)?;
            self.append_event(
                ValidatorSecurityEventKind::SlashApplied,
                "slashing-adjudicator",
                evidence_id,
                evidence_root,
                slashed_units,
                &evidence_record,
            )?;
        }
        Ok(self.state_root())
    }

    pub fn apply_liveness_report(
        &mut self,
        report: LivenessReport,
    ) -> ValidatorSecurityResult<String> {
        report.validate()?;
        if !self.validators.contains_key(&report.validator_id) {
            return Err("liveness report references unknown validator".to_string());
        }
        if !self.committee_epochs.contains_key(&report.epoch_id) {
            return Err("liveness report references unknown committee epoch".to_string());
        }
        let score = self
            .downtime_scores
            .entry(report.validator_id.clone())
            .or_insert(DowntimeScore::new(&report.validator_id)?);
        let jail_until = report
            .window_end_height
            .saturating_add(self.config.liveness_window_blocks);
        score.apply_report(&report, self.config.downtime_jail_threshold_bps, jail_until)?;
        if report.status == LivenessWindowStatus::Jailable
            || report.status == LivenessWindowStatus::Slashable
        {
            if let Some(validator) = self.validators.get_mut(&report.validator_id) {
                validator.consecutive_missed_windows =
                    validator.consecutive_missed_windows.saturating_add(1);
                validator.reputation_score_bps = validator
                    .reputation_score_bps
                    .saturating_sub(report.downtime_bps / 4);
                validator.jail_until(jail_until);
            }
        } else if let Some(validator) = self.validators.get_mut(&report.validator_id) {
            validator.consecutive_missed_windows = 0;
            validator.reputation_score_bps = validator
                .reputation_score_bps
                .saturating_add(25)
                .min(VALIDATOR_SECURITY_MAX_BPS);
        }
        let report_id = report.report_id.clone();
        insert_unique_record(
            &mut self.liveness_reports,
            report_id.clone(),
            report.clone(),
            "liveness report",
        )?;
        self.append_event(
            ValidatorSecurityEventKind::LivenessReported,
            &report.validator_id,
            &report_id,
            report.report_root(),
            report.missed_slots,
            &report.public_record(),
        )?;
        Ok(report_id)
    }

    pub fn start_key_rotation(
        &mut self,
        mut rotation: KeyRotationCeremony,
        next_key_set: PqPublicKeySet,
    ) -> ValidatorSecurityResult<String> {
        rotation.validate()?;
        next_key_set.validate()?;
        if rotation.next_key_set_id != next_key_set.key_set_id {
            return Err("key rotation next key set mismatch".to_string());
        }
        let validator = self
            .validators
            .get_mut(&rotation.validator_id)
            .ok_or_else(|| "key rotation references unknown validator".to_string())?;
        if validator.current_key_set_id != rotation.previous_key_set_id {
            return Err(
                "key rotation previous key does not match validator current key".to_string(),
            );
        }
        if !self.key_sets.contains_key(&rotation.previous_key_set_id) {
            return Err("key rotation previous key set is unknown".to_string());
        }
        rotation.refresh(self.height);
        self.key_sets
            .insert(next_key_set.key_set_id.clone(), next_key_set.clone());
        if self.height >= rotation.effective_height {
            validator.apply_key_set(&next_key_set)?;
        }
        let rotation_id = rotation.rotation_id.clone();
        insert_unique_record(
            &mut self.key_rotations,
            rotation_id.clone(),
            rotation.clone(),
            "key rotation",
        )?;
        self.append_event(
            ValidatorSecurityEventKind::KeyRotationStarted,
            &rotation.validator_id,
            &rotation_id,
            rotation.rotation_root(),
            0,
            &rotation.public_record(),
        )?;
        Ok(rotation_id)
    }

    pub fn request_stake_withdrawal(
        &mut self,
        validator_id: &str,
        position_id: &str,
        requested_units: u64,
        recipient_commitment: String,
    ) -> ValidatorSecurityResult<String> {
        if !self.validators.contains_key(validator_id) {
            return Err("stake withdrawal references unknown validator".to_string());
        }
        let position = self
            .stake_positions
            .get_mut(position_id)
            .ok_or_else(|| "stake withdrawal references unknown stake position".to_string())?;
        if position.validator_id != validator_id {
            return Err("stake withdrawal validator mismatch".to_string());
        }
        if requested_units > position.available_units() {
            return Err("stake withdrawal exceeds available stake".to_string());
        }
        position.begin_unbonding(self.height, self.config.unbonding_delay_blocks)?;
        let mut withdrawal = StakeWithdrawalRequest::new(
            validator_id,
            position_id,
            requested_units,
            self.height,
            self.config.withdrawal_challenge_blocks,
            self.config.unbonding_delay_blocks,
            recipient_commitment,
        )?;
        withdrawal.refresh(self.height);
        let withdrawal_id = withdrawal.withdrawal_id.clone();
        insert_unique_record(
            &mut self.withdrawals,
            withdrawal_id.clone(),
            withdrawal.clone(),
            "stake withdrawal",
        )?;
        self.recompute_validator_totals()?;
        self.append_event(
            ValidatorSecurityEventKind::WithdrawalRequested,
            validator_id,
            &withdrawal_id,
            withdrawal.withdrawal_root(),
            requested_units,
            &withdrawal.public_record(),
        )?;
        Ok(withdrawal_id)
    }

    pub fn complete_stake_withdrawal(
        &mut self,
        withdrawal_id: &str,
        height: u64,
    ) -> ValidatorSecurityResult<String> {
        if height < self.height {
            return Err("stake withdrawal completion height is stale".to_string());
        }
        let (position_id, validator_id, requested_units, withdrawal_root, withdrawal_record) = {
            let withdrawal = self
                .withdrawals
                .get_mut(withdrawal_id)
                .ok_or_else(|| "unknown stake withdrawal".to_string())?;
            withdrawal.complete(height)?;
            (
                withdrawal.position_id.clone(),
                withdrawal.validator_id.clone(),
                withdrawal.requested_units,
                withdrawal.withdrawal_root(),
                withdrawal.public_record(),
            )
        };
        let position = self
            .stake_positions
            .get_mut(&position_id)
            .ok_or_else(|| "stake withdrawal position missing".to_string())?;
        position.mark_withdrawn()?;
        self.recompute_validator_totals()?;
        self.append_event(
            ValidatorSecurityEventKind::WithdrawalCompleted,
            &validator_id,
            withdrawal_id,
            withdrawal_root,
            requested_units,
            &withdrawal_record,
        )?;
        Ok(self.state_root())
    }

    pub fn open_challenge(&mut self, challenge: ChallengeCase) -> ValidatorSecurityResult<String> {
        challenge.validate()?;
        if self.open_challenge_count() >= self.config.max_active_challenges {
            return Err("validator security active challenge limit reached".to_string());
        }
        if !self
            .validators
            .contains_key(&challenge.respondent_validator_id)
        {
            return Err("challenge references unknown respondent validator".to_string());
        }
        let challenge_id = challenge.challenge_id.clone();
        insert_unique_record(
            &mut self.challenges,
            challenge_id.clone(),
            challenge.clone(),
            "challenge case",
        )?;
        if challenge.challenge_kind == ChallengeKind::Withdrawal {
            if let Some(withdrawal) = self.withdrawals.get_mut(&challenge.subject_id) {
                withdrawal.attach_challenge_root(challenge.challenge_root())?;
            }
        }
        self.append_event(
            ValidatorSecurityEventKind::ChallengeOpened,
            &challenge.challenger_id,
            &challenge_id,
            challenge.challenge_root(),
            challenge.challenge_bond_units,
            &challenge.public_record(),
        )?;
        Ok(challenge_id)
    }

    pub fn respond_challenge(
        &mut self,
        challenge_id: &str,
        height: u64,
        response: &Value,
    ) -> ValidatorSecurityResult<String> {
        let challenge = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| "unknown challenge".to_string())?;
        challenge.respond(height, response)?;
        Ok(challenge.challenge_root())
    }

    pub fn adjudicate_challenge(
        &mut self,
        challenge_id: &str,
        height: u64,
        decision: ChallengeDecision,
        adjudicator_root: String,
        award_units: u64,
        penalty_units: u64,
    ) -> ValidatorSecurityResult<String> {
        let (respondent_validator_id, challenge_root, challenge_record) = {
            let challenge = self
                .challenges
                .get_mut(challenge_id)
                .ok_or_else(|| "unknown challenge".to_string())?;
            challenge.adjudicate(
                height,
                decision,
                adjudicator_root,
                award_units,
                penalty_units,
            )?;
            (
                challenge.respondent_validator_id.clone(),
                challenge.challenge_root(),
                challenge.public_record(),
            )
        };
        if matches!(
            decision,
            ChallengeDecision::ChallengerWins | ChallengeDecision::Split
        ) && penalty_units > 0
        {
            self.apply_validator_slash_by_units(&respondent_validator_id, penalty_units)?;
        }
        self.append_event(
            ValidatorSecurityEventKind::ChallengeAdjudicated,
            "challenge-adjudicator",
            challenge_id,
            challenge_root,
            penalty_units,
            &challenge_record,
        )?;
        Ok(self.state_root())
    }

    pub fn create_coverage_pool(&mut self, pool: CoveragePool) -> ValidatorSecurityResult<String> {
        pool.validate()?;
        let pool_id = pool.pool_id.clone();
        insert_unique_record(
            &mut self.coverage_pools,
            pool_id.clone(),
            pool.clone(),
            "coverage pool",
        )?;
        self.append_event(
            ValidatorSecurityEventKind::CoveragePoolFunded,
            &pool.sponsor_id,
            &pool_id,
            pool.pool_root(),
            pool.total_deposited_units,
            &pool.public_record(),
        )?;
        Ok(pool_id)
    }

    pub fn open_coverage_claim(
        &mut self,
        mut claim: CoverageClaim,
    ) -> ValidatorSecurityResult<String> {
        claim.validate()?;
        let pool = self
            .coverage_pools
            .get_mut(&claim.pool_id)
            .ok_or_else(|| "coverage claim references unknown pool".to_string())?;
        let reserve_units = if claim.reserved_units == 0 {
            claim.requested_units.min(pool.available_units())
        } else {
            claim.reserved_units
        };
        pool.reserve_claim(reserve_units)?;
        claim.reserve(reserve_units)?;
        let claim_id = claim.claim_id.clone();
        insert_unique_record(
            &mut self.coverage_claims,
            claim_id.clone(),
            claim,
            "coverage claim",
        )?;
        Ok(claim_id)
    }

    pub fn adjudicate_coverage_claim(
        &mut self,
        claim_id: &str,
        approved: bool,
        approved_units: u64,
        adjudication_id: impl Into<String>,
        height: u64,
    ) -> ValidatorSecurityResult<String> {
        let adjudication_id = adjudication_id.into();
        let (pool_id, reserved_units, payout_units, claim_root, claim_record) = {
            let claim = self
                .coverage_claims
                .get_mut(claim_id)
                .ok_or_else(|| "unknown coverage claim".to_string())?;
            if approved {
                claim.approve(height, approved_units, adjudication_id)?;
                claim.mark_paid()?;
            } else {
                claim.reject(height, adjudication_id)?;
            }
            (
                claim.pool_id.clone(),
                claim.reserved_units,
                claim.payout_units,
                claim.claim_root(),
                claim.public_record(),
            )
        };
        let pool = self
            .coverage_pools
            .get_mut(&pool_id)
            .ok_or_else(|| "coverage claim pool missing".to_string())?;
        pool.settle_claim(reserved_units, payout_units)?;
        self.append_event(
            ValidatorSecurityEventKind::CoverageClaimAdjudicated,
            "coverage-adjudicator",
            claim_id,
            claim_root,
            payout_units,
            &claim_record,
        )?;
        Ok(self.state_root())
    }

    pub fn create_subsidy_epoch(
        &mut self,
        subsidy: LowFeeValidatorSubsidyEpoch,
    ) -> ValidatorSecurityResult<String> {
        subsidy.validate()?;
        let subsidy_id = subsidy.subsidy_id.clone();
        insert_unique_record(
            &mut self.subsidy_epochs,
            subsidy_id.clone(),
            subsidy,
            "low fee validator subsidy epoch",
        )?;
        Ok(subsidy_id)
    }

    pub fn record_subsidy_reward(
        &mut self,
        reward: LowFeeValidatorReward,
    ) -> ValidatorSecurityResult<String> {
        reward.validate()?;
        if !self.validators.contains_key(&reward.validator_id) {
            return Err("low fee reward references unknown validator".to_string());
        }
        let subsidy = self
            .subsidy_epochs
            .get_mut(&reward.subsidy_id)
            .ok_or_else(|| "low fee reward references unknown subsidy epoch".to_string())?;
        subsidy.apply_reward(&reward)?;
        let reward_id = reward.reward_id.clone();
        insert_unique_record(
            &mut self.subsidy_rewards,
            reward_id.clone(),
            reward.clone(),
            "low fee validator reward",
        )?;
        self.refresh_subsidy_reward_roots();
        self.append_event(
            ValidatorSecurityEventKind::SubsidyRewarded,
            &reward.validator_id,
            &reward_id,
            reward.reward_root(),
            reward.earned_units,
            &reward.public_record(),
        )?;
        Ok(reward_id)
    }

    pub fn roots(&self) -> ValidatorSecurityRoots {
        let public_record_root = merkle_root(
            "VALIDATOR-SECURITY-PUBLIC-RECORD",
            &self.all_public_records().into_values().collect::<Vec<_>>(),
        );
        let mut roots = ValidatorSecurityRoots {
            config_root: self.config.config_root(),
            validator_root: validator_security_validator_root(
                &self.validators.values().cloned().collect::<Vec<_>>(),
            ),
            key_set_root: validator_security_key_set_root(
                &self.key_sets.values().cloned().collect::<Vec<_>>(),
            ),
            stake_position_root: validator_security_stake_position_root(
                &self.stake_positions.values().cloned().collect::<Vec<_>>(),
            ),
            bond_position_root: validator_security_bond_position_root(
                &self.bond_positions.values().cloned().collect::<Vec<_>>(),
            ),
            committee_epoch_root: validator_security_committee_epoch_root(
                &self.committee_epochs.values().cloned().collect::<Vec<_>>(),
            ),
            slashing_evidence_root: validator_security_slashing_evidence_root(
                &self.slashing_evidence.values().cloned().collect::<Vec<_>>(),
            ),
            liveness_report_root: validator_security_liveness_report_root(
                &self.liveness_reports.values().cloned().collect::<Vec<_>>(),
            ),
            downtime_score_root: validator_security_downtime_score_root(
                &self.downtime_scores.values().cloned().collect::<Vec<_>>(),
            ),
            key_rotation_root: validator_security_key_rotation_root(
                &self.key_rotations.values().cloned().collect::<Vec<_>>(),
            ),
            withdrawal_root: validator_security_withdrawal_root(
                &self.withdrawals.values().cloned().collect::<Vec<_>>(),
            ),
            challenge_root: validator_security_challenge_root(
                &self.challenges.values().cloned().collect::<Vec<_>>(),
            ),
            coverage_pool_root: validator_security_coverage_pool_root(
                &self.coverage_pools.values().cloned().collect::<Vec<_>>(),
            ),
            coverage_claim_root: validator_security_coverage_claim_root(
                &self.coverage_claims.values().cloned().collect::<Vec<_>>(),
            ),
            subsidy_epoch_root: validator_security_subsidy_epoch_root(
                &self.subsidy_epochs.values().cloned().collect::<Vec<_>>(),
            ),
            subsidy_reward_root: validator_security_subsidy_reward_root(
                &self.subsidy_rewards.values().cloned().collect::<Vec<_>>(),
            ),
            event_root: validator_security_event_root(
                &self.events.values().cloned().collect::<Vec<_>>(),
            ),
            public_record_root,
            state_root: String::new(),
        };
        roots.state_root = roots.roots_root();
        roots
    }

    pub fn state_root(&self) -> String {
        validator_security_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("validator security state record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn counters(&self) -> ValidatorSecurityCounters {
        let total_stake_units = self
            .stake_positions
            .values()
            .map(StakePosition::available_units)
            .fold(0_u64, u64::saturating_add);
        let total_bond_units = self
            .bond_positions
            .values()
            .map(BondPosition::available_units)
            .fold(0_u64, u64::saturating_add);
        let total_slashed_stake = self
            .stake_positions
            .values()
            .map(|position| position.slashed_units)
            .fold(0_u64, u64::saturating_add);
        let total_slashed_bonds = self
            .bond_positions
            .values()
            .map(|bond| bond.slashed_units)
            .fold(0_u64, u64::saturating_add);
        ValidatorSecurityCounters {
            validator_count: self.validators.len() as u64,
            active_validator_count: self
                .validators
                .values()
                .filter(|validator| validator.status == ValidatorStatus::Active)
                .count() as u64,
            jailed_validator_count: self
                .validators
                .values()
                .filter(|validator| validator.status == ValidatorStatus::Jailed)
                .count() as u64,
            key_set_count: self.key_sets.len() as u64,
            stake_position_count: self.stake_positions.len() as u64,
            bond_position_count: self.bond_positions.len() as u64,
            committee_epoch_count: self.committee_epochs.len() as u64,
            slashing_evidence_count: self.slashing_evidence.len() as u64,
            accepted_slashing_evidence_count: self
                .slashing_evidence
                .values()
                .filter(|evidence| evidence.status == EvidenceStatus::Accepted)
                .count() as u64,
            liveness_report_count: self.liveness_reports.len() as u64,
            downtime_score_count: self.downtime_scores.len() as u64,
            key_rotation_count: self.key_rotations.len() as u64,
            withdrawal_count: self.withdrawals.len() as u64,
            open_challenge_count: self.open_challenge_count() as u64,
            coverage_pool_count: self.coverage_pools.len() as u64,
            coverage_claim_count: self.coverage_claims.len() as u64,
            subsidy_epoch_count: self.subsidy_epochs.len() as u64,
            subsidy_reward_count: self.subsidy_rewards.len() as u64,
            event_count: self.events.len() as u64,
            total_stake_units,
            total_bond_units,
            total_slashed_units: total_slashed_stake.saturating_add(total_slashed_bonds),
            total_coverage_units: self
                .coverage_pools
                .values()
                .map(|pool| pool.total_deposited_units.saturating_sub(pool.paid_units))
                .fold(0_u64, u64::saturating_add),
            total_subsidy_budget_units: self
                .subsidy_epochs
                .values()
                .map(|subsidy| subsidy.budget_units)
                .fold(0_u64, u64::saturating_add),
        }
    }

    pub fn validate(&self) -> ValidatorSecurityResult<String> {
        self.config.validate()?;
        for (id, key_set) in &self.key_sets {
            if id != &key_set.key_set_id {
                return Err("validator key set map key mismatch".to_string());
            }
            key_set.validate()?;
        }
        for (id, validator) in &self.validators {
            if id != &validator.validator_id {
                return Err("validator identity map key mismatch".to_string());
            }
            validator.validate()?;
            let key_set = self
                .key_sets
                .get(&validator.current_key_set_id)
                .ok_or_else(|| "validator references unknown current key set".to_string())?;
            if key_set.key_root() != validator.key_set_root {
                return Err("validator current key set root is stale".to_string());
            }
        }
        for (id, position) in &self.stake_positions {
            if id != &position.position_id {
                return Err("stake position map key mismatch".to_string());
            }
            position.validate()?;
            if !self.validators.contains_key(&position.validator_id) {
                return Err("stake position references unknown validator".to_string());
            }
        }
        for (id, bond) in &self.bond_positions {
            if id != &bond.bond_id {
                return Err("bond position map key mismatch".to_string());
            }
            bond.validate()?;
            if !self.validators.contains_key(&bond.validator_id) {
                return Err("bond position references unknown validator".to_string());
            }
        }
        for validator in self.validators.values() {
            let expected_stake = self.validator_available_stake_units(&validator.validator_id);
            let expected_bond = self.validator_available_bond_units(&validator.validator_id);
            if validator.total_stake_units != expected_stake {
                return Err("validator total stake units are stale".to_string());
            }
            if validator.total_bond_units != expected_bond {
                return Err("validator total bond units are stale".to_string());
            }
        }
        for (id, epoch) in &self.committee_epochs {
            if id != &epoch.epoch_id {
                return Err("committee epoch map key mismatch".to_string());
            }
            epoch.validate()?;
            for member in &epoch.members {
                let validator = self
                    .validators
                    .get(&member.validator_id)
                    .ok_or_else(|| "committee member references unknown validator".to_string())?;
                if validator.current_key_set_id != member.key_set_id {
                    return Err("committee member key set is stale".to_string());
                }
            }
        }
        for evidence in self.slashing_evidence.values() {
            evidence.validate()?;
            if !self.validators.contains_key(&evidence.reporter_id) {
                return Err("slashing evidence references unknown reporter".to_string());
            }
            if !self.validators.contains_key(&evidence.accused_validator_id) {
                return Err("slashing evidence references unknown accused validator".to_string());
            }
        }
        for report in self.liveness_reports.values() {
            report.validate()?;
            if !self.validators.contains_key(&report.validator_id) {
                return Err("liveness report references unknown validator".to_string());
            }
            if !self.committee_epochs.contains_key(&report.epoch_id) {
                return Err("liveness report references unknown committee epoch".to_string());
            }
        }
        for score in self.downtime_scores.values() {
            score.validate()?;
            if !self.validators.contains_key(&score.validator_id) {
                return Err("downtime score references unknown validator".to_string());
            }
        }
        for rotation in self.key_rotations.values() {
            rotation.validate()?;
            if !self.validators.contains_key(&rotation.validator_id) {
                return Err("key rotation references unknown validator".to_string());
            }
            if !self.key_sets.contains_key(&rotation.previous_key_set_id) {
                return Err("key rotation references unknown previous key set".to_string());
            }
            if !self.key_sets.contains_key(&rotation.next_key_set_id) {
                return Err("key rotation references unknown next key set".to_string());
            }
        }
        for withdrawal in self.withdrawals.values() {
            withdrawal.validate()?;
            if !self.validators.contains_key(&withdrawal.validator_id) {
                return Err("withdrawal references unknown validator".to_string());
            }
            if !self.stake_positions.contains_key(&withdrawal.position_id) {
                return Err("withdrawal references unknown stake position".to_string());
            }
        }
        for challenge in self.challenges.values() {
            challenge.validate()?;
            if !self
                .validators
                .contains_key(&challenge.respondent_validator_id)
            {
                return Err("challenge references unknown respondent validator".to_string());
            }
        }
        for pool in self.coverage_pools.values() {
            pool.validate()?;
        }
        for claim in self.coverage_claims.values() {
            claim.validate()?;
            if !self.coverage_pools.contains_key(&claim.pool_id) {
                return Err("coverage claim references unknown pool".to_string());
            }
        }
        for subsidy in self.subsidy_epochs.values() {
            subsidy.validate()?;
            let rewards = self
                .subsidy_rewards
                .values()
                .filter(|reward| reward.subsidy_id == subsidy.subsidy_id)
                .cloned()
                .collect::<Vec<_>>();
            let reward_root = validator_security_subsidy_reward_root(&rewards);
            if subsidy.validator_reward_root != reward_root
                && !(rewards.is_empty()
                    && subsidy.validator_reward_root
                        == validator_security_empty_root("VALIDATOR-LOW-FEE-REWARD"))
            {
                return Err("low fee subsidy reward root is stale".to_string());
            }
        }
        for reward in self.subsidy_rewards.values() {
            reward.validate()?;
            if !self.validators.contains_key(&reward.validator_id) {
                return Err("low fee reward references unknown validator".to_string());
            }
            if !self.subsidy_epochs.contains_key(&reward.subsidy_id) {
                return Err("low fee reward references unknown subsidy epoch".to_string());
            }
        }
        for event in self.events.values() {
            event.validate()?;
        }
        Ok(self.state_root())
    }

    fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "validator_security_state",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDATOR_SECURITY_PROTOCOL_VERSION,
            "height": self.height,
            "next_event_sequence": self.next_event_sequence,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "root_commitment": roots.roots_root(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
            "active_committee_epoch_ids": self.active_committee_epoch_ids(),
            "jailed_validator_ids": self.jailed_validator_ids(),
            "withdrawable_position_ids": self.withdrawable_position_ids(),
            "open_challenge_ids": self.open_challenge_ids(),
            "undercovered_pool_ids": self.undercovered_pool_ids(),
        })
    }

    fn register_devnet_validator(
        &mut self,
        label: &str,
        key_index: u64,
        roles: BTreeSet<ValidatorRole>,
        stake_units: u64,
        bond_units: u64,
        activation_height: u64,
    ) -> ValidatorSecurityResult<String> {
        let key_set = PqPublicKeySet::devnet(label, key_index, activation_height)?;
        let identity = ValidatorIdentity::new(
            label,
            validator_security_string_root("VALIDATOR-DEVNET-ACCOUNT", label),
            validator_security_string_root("VALIDATOR-DEVNET-PAYOUT", label),
            validator_security_string_root("VALIDATOR-DEVNET-NETWORK", label),
            validator_security_string_root("VALIDATOR-DEVNET-METADATA", label),
            roles.clone(),
            &key_set,
            activation_height,
        )?;
        let validator_id = self.register_validator(identity, key_set)?;
        self.add_stake_position(StakePosition::new(
            &validator_id,
            VALIDATOR_SECURITY_DEVNET_ASSET_ID,
            validator_security_string_root("VALIDATOR-DEVNET-STAKE-OWNER", label),
            stake_units,
            activation_height,
            activation_height.saturating_add(48),
        )?)?;
        let bond_role = roles
            .iter()
            .copied()
            .find(|role| matches!(role, ValidatorRole::BridgeSigner | ValidatorRole::Prover))
            .unwrap_or(ValidatorRole::BlockProducer);
        self.add_bond_position(BondPosition::new(
            &validator_id,
            bond_role,
            VALIDATOR_SECURITY_DEVNET_ASSET_ID,
            bond_units,
            activation_height.saturating_add(1_440),
        )?)?;
        Ok(validator_id)
    }

    fn append_event(
        &mut self,
        event_kind: ValidatorSecurityEventKind,
        actor: impl Into<String>,
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        amount_units: u64,
        details: &Value,
    ) -> ValidatorSecurityResult<String> {
        let event = ValidatorSecurityEvent::new(
            self.next_event_sequence,
            self.height,
            event_kind,
            actor,
            subject_id,
            subject_root,
            amount_units,
            details,
        )?;
        self.next_event_sequence = self.next_event_sequence.saturating_add(1);
        let event_id = event.event_id.clone();
        self.events.insert(event_id.clone(), event);
        Ok(event_id)
    }

    fn apply_validator_slash(
        &mut self,
        validator_id: &str,
        slash_bps: u64,
    ) -> ValidatorSecurityResult<u64> {
        ensure_bps(slash_bps, "validator slash bps")?;
        let stake = self.validator_available_stake_units(validator_id);
        let bond = self.validator_available_bond_units(validator_id);
        let total = stake.saturating_add(bond);
        let slash_units = threshold_units(total, slash_bps);
        self.apply_validator_slash_by_units(validator_id, slash_units)
    }

    fn apply_validator_slash_by_units(
        &mut self,
        validator_id: &str,
        slash_units: u64,
    ) -> ValidatorSecurityResult<u64> {
        if !self.validators.contains_key(validator_id) {
            return Err("cannot slash unknown validator".to_string());
        }
        let mut remaining = slash_units;
        for bond in self
            .bond_positions
            .values_mut()
            .filter(|bond| bond.validator_id == validator_id)
        {
            if remaining == 0 {
                break;
            }
            let apply = remaining.min(bond.available_units());
            bond.apply_slash(apply)?;
            remaining = remaining.saturating_sub(apply);
        }
        for position in self
            .stake_positions
            .values_mut()
            .filter(|position| position.validator_id == validator_id)
        {
            if remaining == 0 {
                break;
            }
            let apply = remaining.min(position.available_units());
            position.apply_slash(apply)?;
            remaining = remaining.saturating_sub(apply);
        }
        let applied = slash_units.saturating_sub(remaining);
        if let Some(validator) = self.validators.get_mut(validator_id) {
            validator.status = ValidatorStatus::Slashed;
            validator.reputation_score_bps = validator.reputation_score_bps.saturating_sub(1_000);
        }
        self.recompute_validator_totals()?;
        Ok(applied)
    }

    fn recompute_validator_totals(&mut self) -> ValidatorSecurityResult<()> {
        let validator_ids = self.validators.keys().cloned().collect::<Vec<_>>();
        for validator_id in validator_ids {
            let total_stake_units = self.validator_available_stake_units(&validator_id);
            let total_bond_units = self.validator_available_bond_units(&validator_id);
            let slash_reserved_units = self
                .stake_positions
                .values()
                .filter(|position| position.validator_id == validator_id)
                .map(|position| position.slash_reserved_units)
                .fold(0_u64, u64::saturating_add);
            if let Some(validator) = self.validators.get_mut(&validator_id) {
                validator.total_stake_units = total_stake_units;
                validator.total_bond_units = total_bond_units;
                validator.slash_reserved_units = slash_reserved_units;
                validator.refresh(self.height, self.config.min_validator_stake_units);
            }
        }
        Ok(())
    }

    fn refresh_subsidy_reward_roots(&mut self) {
        let subsidy_ids = self.subsidy_epochs.keys().cloned().collect::<Vec<_>>();
        for subsidy_id in subsidy_ids {
            let reward_root = validator_security_subsidy_reward_root(
                &self
                    .subsidy_rewards
                    .values()
                    .filter(|reward| reward.subsidy_id == subsidy_id)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            if let Some(subsidy) = self.subsidy_epochs.get_mut(&subsidy_id) {
                subsidy.validator_reward_root = reward_root;
            }
        }
    }

    fn validator_available_stake_units(&self, validator_id: &str) -> u64 {
        self.stake_positions
            .values()
            .filter(|position| {
                position.validator_id == validator_id
                    && matches!(
                        position.status,
                        StakePositionStatus::Bonded
                            | StakePositionStatus::Unbonding
                            | StakePositionStatus::Withdrawable
                            | StakePositionStatus::Frozen
                    )
            })
            .map(StakePosition::available_units)
            .fold(0_u64, u64::saturating_add)
    }

    fn validator_available_bond_units(&self, validator_id: &str) -> u64 {
        self.bond_positions
            .values()
            .filter(|bond| {
                bond.validator_id == validator_id
                    && matches!(
                        bond.status,
                        StakePositionStatus::Bonded
                            | StakePositionStatus::Unbonding
                            | StakePositionStatus::Withdrawable
                            | StakePositionStatus::Frozen
                    )
            })
            .map(BondPosition::available_units)
            .fold(0_u64, u64::saturating_add)
    }

    fn active_committee_epoch_ids(&self) -> Vec<String> {
        self.committee_epochs
            .values()
            .filter(|epoch| epoch.status.accepts_work())
            .map(|epoch| epoch.epoch_id.clone())
            .collect()
    }

    fn jailed_validator_ids(&self) -> Vec<String> {
        self.validators
            .values()
            .filter(|validator| validator.status == ValidatorStatus::Jailed)
            .map(|validator| validator.validator_id.clone())
            .collect()
    }

    fn withdrawable_position_ids(&self) -> Vec<String> {
        self.stake_positions
            .values()
            .filter(|position| position.status == StakePositionStatus::Withdrawable)
            .map(|position| position.position_id.clone())
            .collect()
    }

    fn open_challenge_ids(&self) -> Vec<String> {
        self.challenges
            .values()
            .filter(|challenge| challenge.status.is_open())
            .map(|challenge| challenge.challenge_id.clone())
            .collect()
    }

    fn open_challenge_count(&self) -> usize {
        self.challenges
            .values()
            .filter(|challenge| challenge.status.is_open())
            .count()
    }

    fn undercovered_pool_ids(&self) -> Vec<String> {
        self.coverage_pools
            .values()
            .filter(|pool| pool.coverage_bps < self.config.reserve_min_coverage_bps)
            .map(|pool| pool.pool_id.clone())
            .collect()
    }

    fn all_public_records(&self) -> BTreeMap<String, Value> {
        let mut records = BTreeMap::new();
        records.insert("config".to_string(), self.config.public_record());
        for key_set in self.key_sets.values() {
            records.insert(
                format!("key_set:{}", key_set.key_set_id),
                key_set.public_record(),
            );
        }
        for validator in self.validators.values() {
            records.insert(
                format!("validator:{}", validator.validator_id),
                validator.public_record(),
            );
        }
        for position in self.stake_positions.values() {
            records.insert(
                format!("stake:{}", position.position_id),
                position.public_record(),
            );
        }
        for bond in self.bond_positions.values() {
            records.insert(format!("bond:{}", bond.bond_id), bond.public_record());
        }
        for epoch in self.committee_epochs.values() {
            records.insert(
                format!("committee:{}", epoch.epoch_id),
                epoch.public_record(),
            );
        }
        for evidence in self.slashing_evidence.values() {
            records.insert(
                format!("evidence:{}", evidence.evidence_id),
                evidence.public_record(),
            );
        }
        for report in self.liveness_reports.values() {
            records.insert(
                format!("liveness:{}", report.report_id),
                report.public_record(),
            );
        }
        for score in self.downtime_scores.values() {
            records.insert(
                format!("downtime:{}", score.validator_id),
                score.public_record(),
            );
        }
        for rotation in self.key_rotations.values() {
            records.insert(
                format!("rotation:{}", rotation.rotation_id),
                rotation.public_record(),
            );
        }
        for withdrawal in self.withdrawals.values() {
            records.insert(
                format!("withdrawal:{}", withdrawal.withdrawal_id),
                withdrawal.public_record(),
            );
        }
        for challenge in self.challenges.values() {
            records.insert(
                format!("challenge:{}", challenge.challenge_id),
                challenge.public_record(),
            );
        }
        for pool in self.coverage_pools.values() {
            records.insert(
                format!("coverage_pool:{}", pool.pool_id),
                pool.public_record(),
            );
        }
        for claim in self.coverage_claims.values() {
            records.insert(
                format!("coverage_claim:{}", claim.claim_id),
                claim.public_record(),
            );
        }
        for subsidy in self.subsidy_epochs.values() {
            records.insert(
                format!("subsidy_epoch:{}", subsidy.subsidy_id),
                subsidy.public_record(),
            );
        }
        for reward in self.subsidy_rewards.values() {
            records.insert(
                format!("subsidy_reward:{}", reward.reward_id),
                reward.public_record(),
            );
        }
        for event in self.events.values() {
            records.insert(format!("event:{}", event.event_id), event.public_record());
        }
        records
    }
}

pub fn validator_security_state_root_from_record(record: &Value) -> String {
    validator_security_payload_root("VALIDATOR-SECURITY-STATE", record)
}

pub fn validator_security_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn validator_security_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn validator_security_empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

pub fn validator_security_string_set_root(domain: &str, values: &[String]) -> String {
    let mut records = values
        .iter()
        .map(|value| json!({"chain_id": CHAIN_ID, "value": value}))
        .collect::<Vec<_>>();
    records.sort_by_key(|record| record.to_string());
    merkle_root(domain, &records)
}

pub fn validator_security_stake_position_id(
    validator_id: &str,
    asset_id: &str,
    owner_commitment: &str,
    amount_units: u64,
    activation_height: u64,
) -> String {
    domain_hash(
        "VALIDATOR-STAKE-POSITION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(validator_id),
            HashPart::Str(asset_id),
            HashPart::Str(owner_commitment),
            HashPart::Int(amount_units as i128),
            HashPart::Int(activation_height as i128),
        ],
        32,
    )
}

pub fn validator_security_bond_position_id(
    validator_id: &str,
    bond_role: ValidatorRole,
    asset_id: &str,
    amount_units: u64,
    locked_until_height: u64,
) -> String {
    domain_hash(
        "VALIDATOR-BOND-POSITION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(validator_id),
            HashPart::Str(bond_role.as_str()),
            HashPart::Str(asset_id),
            HashPart::Int(amount_units as i128),
            HashPart::Int(locked_until_height as i128),
        ],
        32,
    )
}

pub fn validator_security_committee_epoch_id(
    epoch_index: u64,
    start_height: u64,
    end_height: u64,
    seed_root: &str,
    member_root: &str,
) -> String {
    domain_hash(
        "VALIDATOR-COMMITTEE-EPOCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch_index as i128),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
            HashPart::Str(seed_root),
            HashPart::Str(member_root),
        ],
        32,
    )
}

pub fn validator_security_slashing_evidence_id(
    evidence_kind: SlashingEvidenceKind,
    reporter_id: &str,
    accused_validator_id: &str,
    subject_id: &str,
    subject_root: &str,
    payload_root: &str,
    submitted_height: u64,
) -> String {
    domain_hash(
        "VALIDATOR-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(evidence_kind.as_str()),
            HashPart::Str(reporter_id),
            HashPart::Str(accused_validator_id),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(payload_root),
            HashPart::Int(submitted_height as i128),
        ],
        32,
    )
}

pub fn validator_security_liveness_report_id(
    validator_id: &str,
    epoch_id: &str,
    window_index: u64,
    window_start_height: u64,
    window_end_height: u64,
    evidence_root: &str,
) -> String {
    domain_hash(
        "VALIDATOR-LIVENESS-REPORT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(validator_id),
            HashPart::Str(epoch_id),
            HashPart::Int(window_index as i128),
            HashPart::Int(window_start_height as i128),
            HashPart::Int(window_end_height as i128),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn validator_security_key_rotation_id(
    validator_id: &str,
    previous_key_set_id: &str,
    next_key_set_id: &str,
    announcement_height: u64,
    effective_height: u64,
    attester_root: &str,
) -> String {
    domain_hash(
        "VALIDATOR-KEY-ROTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(validator_id),
            HashPart::Str(previous_key_set_id),
            HashPart::Str(next_key_set_id),
            HashPart::Int(announcement_height as i128),
            HashPart::Int(effective_height as i128),
            HashPart::Str(attester_root),
        ],
        32,
    )
}

pub fn validator_security_withdrawal_id(
    validator_id: &str,
    position_id: &str,
    requested_units: u64,
    request_height: u64,
    recipient_commitment: &str,
) -> String {
    domain_hash(
        "VALIDATOR-STAKE-WITHDRAWAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(validator_id),
            HashPart::Str(position_id),
            HashPart::Int(requested_units as i128),
            HashPart::Int(request_height as i128),
            HashPart::Str(recipient_commitment),
        ],
        32,
    )
}

pub fn validator_security_challenge_id(
    challenge_kind: ChallengeKind,
    challenger_id: &str,
    respondent_validator_id: &str,
    subject_id: &str,
    subject_root: &str,
    opened_height: u64,
) -> String {
    domain_hash(
        "VALIDATOR-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(challenge_kind.as_str()),
            HashPart::Str(challenger_id),
            HashPart::Str(respondent_validator_id),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Int(opened_height as i128),
        ],
        32,
    )
}

pub fn validator_security_coverage_pool_id(
    pool_kind: CoveragePoolKind,
    asset_id: &str,
    sponsor_id: &str,
    total_deposited_units: u64,
    target_coverage_units: u64,
    reserve_root: &str,
    active_from_height: u64,
) -> String {
    domain_hash(
        "VALIDATOR-COVERAGE-POOL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_kind.as_str()),
            HashPart::Str(asset_id),
            HashPart::Str(sponsor_id),
            HashPart::Int(total_deposited_units as i128),
            HashPart::Int(target_coverage_units as i128),
            HashPart::Str(reserve_root),
            HashPart::Int(active_from_height as i128),
        ],
        32,
    )
}

pub fn validator_security_coverage_claim_id(
    pool_id: &str,
    claimant_id: &str,
    incident_id: &str,
    subject_root: &str,
    requested_units: u64,
    opened_height: u64,
) -> String {
    domain_hash(
        "VALIDATOR-COVERAGE-CLAIM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(claimant_id),
            HashPart::Str(incident_id),
            HashPart::Str(subject_root),
            HashPart::Int(requested_units as i128),
            HashPart::Int(opened_height as i128),
        ],
        32,
    )
}

pub fn validator_security_subsidy_epoch_id(
    epoch_index: u64,
    start_height: u64,
    end_height: u64,
    fee_asset_id: &str,
    sponsor_id: &str,
    budget_units: u64,
) -> String {
    domain_hash(
        "VALIDATOR-LOW-FEE-SUBSIDY-EPOCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch_index as i128),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
            HashPart::Str(fee_asset_id),
            HashPart::Str(sponsor_id),
            HashPart::Int(budget_units as i128),
        ],
        32,
    )
}

pub fn validator_security_subsidy_reward_id(
    subsidy_id: &str,
    validator_id: &str,
    role: ValidatorRole,
    earned_units: u64,
    liveness_score_bps: u64,
    fee_rebate_bps: u64,
    subject_root: &str,
) -> String {
    domain_hash(
        "VALIDATOR-LOW-FEE-REWARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subsidy_id),
            HashPart::Str(validator_id),
            HashPart::Str(role.as_str()),
            HashPart::Int(earned_units as i128),
            HashPart::Int(liveness_score_bps as i128),
            HashPart::Int(fee_rebate_bps as i128),
            HashPart::Str(subject_root),
        ],
        32,
    )
}

pub fn validator_security_event_id(
    sequence: u64,
    height: u64,
    event_kind: ValidatorSecurityEventKind,
    actor: &str,
    subject_id: &str,
    subject_root: &str,
    amount_units: u64,
    details_root: &str,
) -> String {
    domain_hash(
        "VALIDATOR-SECURITY-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(sequence as i128),
            HashPart::Int(height as i128),
            HashPart::Str(event_kind.as_str()),
            HashPart::Str(actor),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Int(amount_units as i128),
            HashPart::Str(details_root),
        ],
        32,
    )
}

pub fn validator_security_validator_root(validators: &[ValidatorIdentity]) -> String {
    merkle_root(
        "VALIDATOR-IDENTITY",
        &validators
            .iter()
            .map(ValidatorIdentity::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn validator_security_key_set_root(key_sets: &[PqPublicKeySet]) -> String {
    merkle_root(
        "VALIDATOR-PQ-KEY-SET",
        &key_sets
            .iter()
            .map(PqPublicKeySet::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn validator_security_stake_position_root(positions: &[StakePosition]) -> String {
    merkle_root(
        "VALIDATOR-STAKE-POSITION",
        &positions
            .iter()
            .map(StakePosition::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn validator_security_bond_position_root(bonds: &[BondPosition]) -> String {
    merkle_root(
        "VALIDATOR-BOND-POSITION",
        &bonds
            .iter()
            .map(BondPosition::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn validator_security_committee_member_root(members: &[CommitteeMember]) -> String {
    merkle_root(
        "VALIDATOR-COMMITTEE-MEMBER",
        &members
            .iter()
            .map(CommitteeMember::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn validator_security_committee_epoch_root(epochs: &[CommitteeEpoch]) -> String {
    merkle_root(
        "VALIDATOR-COMMITTEE-EPOCH",
        &epochs
            .iter()
            .map(CommitteeEpoch::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn validator_security_slashing_evidence_root(evidence: &[SlashingEvidence]) -> String {
    merkle_root(
        "VALIDATOR-SLASHING-EVIDENCE",
        &evidence
            .iter()
            .map(SlashingEvidence::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn validator_security_liveness_report_root(reports: &[LivenessReport]) -> String {
    merkle_root(
        "VALIDATOR-LIVENESS-REPORT",
        &reports
            .iter()
            .map(LivenessReport::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn validator_security_downtime_score_root(scores: &[DowntimeScore]) -> String {
    merkle_root(
        "VALIDATOR-DOWNTIME-SCORE",
        &scores
            .iter()
            .map(DowntimeScore::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn validator_security_key_rotation_root(rotations: &[KeyRotationCeremony]) -> String {
    merkle_root(
        "VALIDATOR-KEY-ROTATION",
        &rotations
            .iter()
            .map(KeyRotationCeremony::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn validator_security_withdrawal_root(withdrawals: &[StakeWithdrawalRequest]) -> String {
    merkle_root(
        "VALIDATOR-STAKE-WITHDRAWAL",
        &withdrawals
            .iter()
            .map(StakeWithdrawalRequest::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn validator_security_challenge_root(challenges: &[ChallengeCase]) -> String {
    merkle_root(
        "VALIDATOR-CHALLENGE-CASE",
        &challenges
            .iter()
            .map(ChallengeCase::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn validator_security_coverage_pool_root(pools: &[CoveragePool]) -> String {
    merkle_root(
        "VALIDATOR-COVERAGE-POOL",
        &pools
            .iter()
            .map(CoveragePool::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn validator_security_coverage_claim_root(claims: &[CoverageClaim]) -> String {
    merkle_root(
        "VALIDATOR-COVERAGE-CLAIM",
        &claims
            .iter()
            .map(CoverageClaim::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn validator_security_subsidy_epoch_root(epochs: &[LowFeeValidatorSubsidyEpoch]) -> String {
    merkle_root(
        "VALIDATOR-LOW-FEE-SUBSIDY-EPOCH",
        &epochs
            .iter()
            .map(LowFeeValidatorSubsidyEpoch::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn validator_security_subsidy_reward_root(rewards: &[LowFeeValidatorReward]) -> String {
    merkle_root(
        "VALIDATOR-LOW-FEE-REWARD",
        &rewards
            .iter()
            .map(LowFeeValidatorReward::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn validator_security_event_root(events: &[ValidatorSecurityEvent]) -> String {
    merkle_root(
        "VALIDATOR-SECURITY-EVENT",
        &events
            .iter()
            .map(ValidatorSecurityEvent::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn threshold_units(total_units: u64, bps: u64) -> u64 {
    total_units
        .saturating_mul(bps)
        .saturating_add(VALIDATOR_SECURITY_MAX_BPS - 1)
        / VALIDATOR_SECURITY_MAX_BPS
}

pub fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator
        .saturating_mul(VALIDATOR_SECURITY_MAX_BPS)
        .checked_div(denominator)
        .unwrap_or(0)
        .min(VALIDATOR_SECURITY_MAX_BPS)
}

pub fn deterministic_u64(domain: &str, parts: &[HashPart<'_>]) -> u64 {
    let hash = domain_hash(domain, parts, 8);
    u64::from_str_radix(&hash, 16).unwrap_or_default()
}

fn validator_role_strings(roles: &BTreeSet<ValidatorRole>) -> Vec<String> {
    roles.iter().map(|role| role.as_str().to_string()).collect()
}

fn role_set(roles: &[ValidatorRole]) -> BTreeSet<ValidatorRole> {
    roles.iter().copied().collect()
}

fn ensure_non_empty(value: &str, label: &str) -> ValidatorSecurityResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> ValidatorSecurityResult<()> {
    if value == 0 {
        Err(format!("{label} must be non-zero"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> ValidatorSecurityResult<()> {
    if value > VALIDATOR_SECURITY_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

fn ensure_height_window(start: u64, end: u64, label: &str) -> ValidatorSecurityResult<()> {
    if end < start {
        Err(format!("{label} end height precedes start height"))
    } else {
        Ok(())
    }
}

fn insert_unique_record<T>(
    map: &mut BTreeMap<String, T>,
    key: String,
    value: T,
    label: &str,
) -> ValidatorSecurityResult<()> {
    if map.contains_key(&key) {
        return Err(format!("{label} already exists"));
    }
    map.insert(key, value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_fixture_validates_and_has_stable_root() {
        let state = ValidatorSecurityState::devnet().expect("devnet validator security state");
        assert_eq!(
            state.config.protocol_version,
            VALIDATOR_SECURITY_PROTOCOL_VERSION
        );
        assert!(state.counters().validator_count >= 4);
        assert_eq!(
            state.validate().expect("state validates"),
            state.state_root()
        );
        assert_eq!(
            validator_security_state_root_from_record(&state.public_record_without_root()),
            state.state_root()
        );
    }

    #[test]
    fn liveness_report_scores_downtime_deterministically() {
        let report = LivenessReport::new(
            "validator-a",
            "epoch-a",
            0,
            10,
            20,
            10,
            8,
            2,
            2_000,
            5_000,
            &json!({"sample": true}),
        )
        .expect("liveness report");
        assert_eq!(report.missed_slots, 2);
        assert_eq!(report.downtime_bps, 3_000);
        assert_eq!(report.status, LivenessWindowStatus::Jailable);
    }
}
