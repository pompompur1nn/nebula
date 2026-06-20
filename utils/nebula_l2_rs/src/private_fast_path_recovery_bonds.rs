use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateFastPathRecoveryBondsResult<T> = Result<T, String>;

pub const PRIVATE_FAST_PATH_RECOVERY_BONDS_PROTOCOL_VERSION: &str =
    "nebula-private-fast-path-recovery-bonds-v1";
pub const PROTOCOL_VERSION: &str = PRIVATE_FAST_PATH_RECOVERY_BONDS_PROTOCOL_VERSION;
pub const PRIVATE_FAST_PATH_RECOVERY_BONDS_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_FAST_PATH_RECOVERY_BONDS_DEVNET_HEIGHT: u64 = 2_304;
pub const PRIVATE_FAST_PATH_RECOVERY_BONDS_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_FAST_PATH_RECOVERY_BONDS_PQ_SIGNER_SUITE: &str =
    "ML-DSA-65+SLH-DSA-SHAKE-128s-recovery-bond";
pub const PRIVATE_FAST_PATH_RECOVERY_BONDS_NOTICE_ENCRYPTION_SUITE: &str =
    "ML-KEM-768+view-tag-sealed-failure-notice-v1";
pub const PRIVATE_FAST_PATH_RECOVERY_BONDS_RECEIPT_SUITE: &str =
    "private-recovery-receipt-nullifier-commitment-v1";
pub const PRIVATE_FAST_PATH_RECOVERY_BONDS_LOW_LATENCY_COMMITMENT_SUITE: &str =
    "low-latency-lane-commitment-v1";
pub const PRIVATE_FAST_PATH_RECOVERY_BONDS_REBATE_ASSET_ID: &str = "wxmr-devnet";
pub const PRIVATE_FAST_PATH_RECOVERY_BONDS_BOND_ASSET_ID: &str = "dusd-devnet";
pub const PRIVATE_FAST_PATH_RECOVERY_BONDS_DEFAULT_EPOCH_BLOCKS: u64 = 360;
pub const PRIVATE_FAST_PATH_RECOVERY_BONDS_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 36;
pub const PRIVATE_FAST_PATH_RECOVERY_BONDS_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 720;
pub const PRIVATE_FAST_PATH_RECOVERY_BONDS_DEFAULT_NOTICE_TTL_BLOCKS: u64 = 144;
pub const PRIVATE_FAST_PATH_RECOVERY_BONDS_DEFAULT_REBATE_CLAIM_TTL_BLOCKS: u64 = 1_440;
pub const PRIVATE_FAST_PATH_RECOVERY_BONDS_DEFAULT_SLA_LATENCY_MS: u64 = 650;
pub const PRIVATE_FAST_PATH_RECOVERY_BONDS_DEFAULT_MIN_BOND_UNITS: u64 = 50_000;
pub const PRIVATE_FAST_PATH_RECOVERY_BONDS_DEFAULT_MIN_SIGNER_STAKE_UNITS: u64 = 250_000;
pub const PRIVATE_FAST_PATH_RECOVERY_BONDS_DEFAULT_BASE_REBATE_BPS: u64 = 8_000;
pub const PRIVATE_FAST_PATH_RECOVERY_BONDS_DEFAULT_MAX_REBATE_BPS: u64 = 9_750;
pub const PRIVATE_FAST_PATH_RECOVERY_BONDS_DEFAULT_SLASH_BPS: u64 = 1_500;
pub const PRIVATE_FAST_PATH_RECOVERY_BONDS_DEFAULT_NOTICE_PRIVACY_SET: u64 = 512;
pub const PRIVATE_FAST_PATH_RECOVERY_BONDS_DEFAULT_MAX_ACTIVE_LANES_PER_SIGNER: usize = 32;
pub const PRIVATE_FAST_PATH_RECOVERY_BONDS_DEFAULT_MAX_PENDING_COMMITMENTS_PER_LANE: usize = 512;
pub const PRIVATE_FAST_PATH_RECOVERY_BONDS_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FastPathLaneKind {
    WalletRecovery,
    ContractRecovery,
    TokenVaultRecovery,
    MoneroExitRecovery,
    DeFiPositionRecovery,
    SmartAccountRecovery,
    EmergencyLowFee,
}

impl FastPathLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletRecovery => "wallet_recovery",
            Self::ContractRecovery => "contract_recovery",
            Self::TokenVaultRecovery => "token_vault_recovery",
            Self::MoneroExitRecovery => "monero_exit_recovery",
            Self::DeFiPositionRecovery => "defi_position_recovery",
            Self::SmartAccountRecovery => "smart_account_recovery",
            Self::EmergencyLowFee => "emergency_low_fee",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyLowFee => 100,
            Self::MoneroExitRecovery => 94,
            Self::TokenVaultRecovery => 88,
            Self::DeFiPositionRecovery => 84,
            Self::SmartAccountRecovery => 80,
            Self::ContractRecovery => 76,
            Self::WalletRecovery => 72,
        }
    }

    pub fn requires_contract_context(self) -> bool {
        matches!(
            self,
            Self::ContractRecovery
                | Self::TokenVaultRecovery
                | Self::DeFiPositionRecovery
                | Self::SmartAccountRecovery
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Draft,
    Active,
    Congested,
    Challenged,
    Paused,
    Draining,
    Retired,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Congested => "congested",
            Self::Challenged => "challenged",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_commitments(self) -> bool {
        matches!(self, Self::Active | Self::Congested | Self::Challenged)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoverySignerStatus {
    Bonding,
    Active,
    Warning,
    Challenged,
    Slashed,
    Suspended,
    Exiting,
    Retired,
}

impl RecoverySignerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bonding => "bonding",
            Self::Active => "active",
            Self::Warning => "warning",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Suspended => "suspended",
            Self::Exiting => "exiting",
            Self::Retired => "retired",
        }
    }

    pub fn may_serve(self) -> bool {
        matches!(self, Self::Active | Self::Warning | Self::Challenged)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Queued,
    Accepted,
    Preconfirmed,
    Executing,
    Recovered,
    Failed,
    Challenged,
    Expired,
    Cancelled,
}

impl CommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Accepted => "accepted",
            Self::Preconfirmed => "preconfirmed",
            Self::Executing => "executing",
            Self::Recovered => "recovered",
            Self::Failed => "failed",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Accepted | Self::Preconfirmed | Self::Executing | Self::Challenged
        )
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Recovered | Self::Failed | Self::Expired | Self::Cancelled
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureNoticeStatus {
    Sealed,
    Delivered,
    Acknowledged,
    Disputed,
    Expired,
}

impl FailureNoticeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Delivered => "delivered",
            Self::Acknowledged => "acknowledged",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateClaimStatus {
    Open,
    Verified,
    Paid,
    Rejected,
    Expired,
}

impl RebateClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Verified => "verified",
            Self::Paid => "paid",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    EvidenceSubmitted,
    Upheld,
    Rejected,
    TimedOut,
    Withdrawn,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceSubmitted => "evidence_submitted",
            Self::Upheld => "upheld",
            Self::Rejected => "rejected",
            Self::TimedOut => "timed_out",
            Self::Withdrawn => "withdrawn",
        }
    }

    pub fn unresolved(self) -> bool {
        matches!(self, Self::Open | Self::EvidenceSubmitted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Finalized,
    Replayed,
    Revoked,
    Expired,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Finalized => "finalized",
            Self::Replayed => "replayed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashReason {
    MissedSla,
    InvalidRecoveryReceipt,
    WithheldFailureNotice,
    DuplicateCommitment,
    InsufficientBond,
    FraudulentRebate,
}

impl SlashReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissedSla => "missed_sla",
            Self::InvalidRecoveryReceipt => "invalid_recovery_receipt",
            Self::WithheldFailureNotice => "withheld_failure_notice",
            Self::DuplicateCommitment => "duplicate_commitment",
            Self::InsufficientBond => "insufficient_bond",
            Self::FraudulentRebate => "fraudulent_rebate",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateFastPathRecoveryBondsConfig {
    pub epoch_blocks: u64,
    pub challenge_window_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub notice_ttl_blocks: u64,
    pub rebate_claim_ttl_blocks: u64,
    pub sla_latency_ms: u64,
    pub min_bond_units: u64,
    pub min_signer_stake_units: u64,
    pub base_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub default_slash_bps: u64,
    pub notice_privacy_set: u64,
    pub max_active_lanes_per_signer: usize,
    pub max_pending_commitments_per_lane: usize,
    pub bond_asset_id: String,
    pub rebate_asset_id: String,
    pub hash_suite: String,
    pub pq_signer_suite: String,
    pub notice_encryption_suite: String,
    pub receipt_suite: String,
    pub low_latency_commitment_suite: String,
}

impl PrivateFastPathRecoveryBondsConfig {
    pub fn devnet() -> Self {
        Self {
            epoch_blocks: PRIVATE_FAST_PATH_RECOVERY_BONDS_DEFAULT_EPOCH_BLOCKS,
            challenge_window_blocks:
                PRIVATE_FAST_PATH_RECOVERY_BONDS_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            receipt_ttl_blocks: PRIVATE_FAST_PATH_RECOVERY_BONDS_DEFAULT_RECEIPT_TTL_BLOCKS,
            notice_ttl_blocks: PRIVATE_FAST_PATH_RECOVERY_BONDS_DEFAULT_NOTICE_TTL_BLOCKS,
            rebate_claim_ttl_blocks:
                PRIVATE_FAST_PATH_RECOVERY_BONDS_DEFAULT_REBATE_CLAIM_TTL_BLOCKS,
            sla_latency_ms: PRIVATE_FAST_PATH_RECOVERY_BONDS_DEFAULT_SLA_LATENCY_MS,
            min_bond_units: PRIVATE_FAST_PATH_RECOVERY_BONDS_DEFAULT_MIN_BOND_UNITS,
            min_signer_stake_units: PRIVATE_FAST_PATH_RECOVERY_BONDS_DEFAULT_MIN_SIGNER_STAKE_UNITS,
            base_rebate_bps: PRIVATE_FAST_PATH_RECOVERY_BONDS_DEFAULT_BASE_REBATE_BPS,
            max_rebate_bps: PRIVATE_FAST_PATH_RECOVERY_BONDS_DEFAULT_MAX_REBATE_BPS,
            default_slash_bps: PRIVATE_FAST_PATH_RECOVERY_BONDS_DEFAULT_SLASH_BPS,
            notice_privacy_set: PRIVATE_FAST_PATH_RECOVERY_BONDS_DEFAULT_NOTICE_PRIVACY_SET,
            max_active_lanes_per_signer:
                PRIVATE_FAST_PATH_RECOVERY_BONDS_DEFAULT_MAX_ACTIVE_LANES_PER_SIGNER,
            max_pending_commitments_per_lane:
                PRIVATE_FAST_PATH_RECOVERY_BONDS_DEFAULT_MAX_PENDING_COMMITMENTS_PER_LANE,
            bond_asset_id: PRIVATE_FAST_PATH_RECOVERY_BONDS_BOND_ASSET_ID.to_string(),
            rebate_asset_id: PRIVATE_FAST_PATH_RECOVERY_BONDS_REBATE_ASSET_ID.to_string(),
            hash_suite: PRIVATE_FAST_PATH_RECOVERY_BONDS_HASH_SUITE.to_string(),
            pq_signer_suite: PRIVATE_FAST_PATH_RECOVERY_BONDS_PQ_SIGNER_SUITE.to_string(),
            notice_encryption_suite: PRIVATE_FAST_PATH_RECOVERY_BONDS_NOTICE_ENCRYPTION_SUITE
                .to_string(),
            receipt_suite: PRIVATE_FAST_PATH_RECOVERY_BONDS_RECEIPT_SUITE.to_string(),
            low_latency_commitment_suite:
                PRIVATE_FAST_PATH_RECOVERY_BONDS_LOW_LATENCY_COMMITMENT_SUITE.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch_blocks": self.epoch_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "notice_ttl_blocks": self.notice_ttl_blocks,
            "rebate_claim_ttl_blocks": self.rebate_claim_ttl_blocks,
            "sla_latency_ms": self.sla_latency_ms,
            "min_bond_units": self.min_bond_units,
            "min_signer_stake_units": self.min_signer_stake_units,
            "base_rebate_bps": self.base_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "default_slash_bps": self.default_slash_bps,
            "notice_privacy_set": self.notice_privacy_set,
            "max_active_lanes_per_signer": self.max_active_lanes_per_signer,
            "max_pending_commitments_per_lane": self.max_pending_commitments_per_lane,
            "bond_asset_id": self.bond_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "hash_suite": self.hash_suite,
            "pq_signer_suite": self.pq_signer_suite,
            "notice_encryption_suite": self.notice_encryption_suite,
            "receipt_suite": self.receipt_suite,
            "low_latency_commitment_suite": self.low_latency_commitment_suite,
        })
    }

    pub fn config_root(&self) -> String {
        recovery_bonds_hash("CONFIG", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateFastPathRecoveryBondsResult<()> {
        if self.epoch_blocks == 0
            || self.challenge_window_blocks == 0
            || self.receipt_ttl_blocks == 0
            || self.notice_ttl_blocks == 0
            || self.rebate_claim_ttl_blocks == 0
            || self.sla_latency_ms == 0
            || self.min_bond_units == 0
            || self.min_signer_stake_units == 0
            || self.notice_privacy_set == 0
            || self.max_active_lanes_per_signer == 0
            || self.max_pending_commitments_per_lane == 0
        {
            return Err(
                "private fast path recovery bond config values must be positive".to_string(),
            );
        }
        if self.base_rebate_bps > self.max_rebate_bps
            || self.max_rebate_bps > PRIVATE_FAST_PATH_RECOVERY_BONDS_MAX_BPS
            || self.default_slash_bps > PRIVATE_FAST_PATH_RECOVERY_BONDS_MAX_BPS
        {
            return Err("private fast path recovery bond bps values are invalid".to_string());
        }
        if self.bond_asset_id.is_empty()
            || self.rebate_asset_id.is_empty()
            || self.hash_suite.is_empty()
            || self.pq_signer_suite.is_empty()
            || self.notice_encryption_suite.is_empty()
            || self.receipt_suite.is_empty()
            || self.low_latency_commitment_suite.is_empty()
        {
            return Err(
                "private fast path recovery bond suite labels must be populated".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowLatencyLane {
    pub lane_id: String,
    pub lane_kind: FastPathLaneKind,
    pub operator_commitment: String,
    pub contract_context_root: String,
    pub admission_policy_root: String,
    pub min_bond_units: u64,
    pub max_latency_ms: u64,
    pub max_pending_commitments: usize,
    pub opened_height: u64,
    pub updated_height: u64,
    pub status: LaneStatus,
}

impl LowLatencyLane {
    pub fn new(
        lane_label: &str,
        lane_kind: FastPathLaneKind,
        operator_commitment: &str,
        contract_context_root: &str,
        admission_policy_root: &str,
        opened_height: u64,
        config: &PrivateFastPathRecoveryBondsConfig,
    ) -> PrivateFastPathRecoveryBondsResult<Self> {
        if lane_label.is_empty()
            || operator_commitment.is_empty()
            || admission_policy_root.is_empty()
        {
            return Err("low latency lane identifiers must be populated".to_string());
        }
        if lane_kind.requires_contract_context() && contract_context_root.is_empty() {
            return Err("contract recovery lanes require contract context root".to_string());
        }
        let lane_id = recovery_bonds_hash(
            "LANE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(lane_label),
                HashPart::Str(lane_kind.as_str()),
                HashPart::Str(operator_commitment),
                HashPart::Int(opened_height as i128),
            ],
        );
        Ok(Self {
            lane_id,
            lane_kind,
            operator_commitment: operator_commitment.to_string(),
            contract_context_root: contract_context_root.to_string(),
            admission_policy_root: admission_policy_root.to_string(),
            min_bond_units: config.min_bond_units,
            max_latency_ms: config.sla_latency_ms,
            max_pending_commitments: config.max_pending_commitments_per_lane,
            opened_height,
            updated_height: opened_height,
            status: LaneStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "operator_commitment": self.operator_commitment,
            "contract_context_root": self.contract_context_root,
            "admission_policy_root": self.admission_policy_root,
            "min_bond_units": self.min_bond_units,
            "max_latency_ms": self.max_latency_ms,
            "max_pending_commitments": self.max_pending_commitments,
            "opened_height": self.opened_height,
            "updated_height": self.updated_height,
            "status": self.status.as_str(),
        })
    }

    pub fn lane_root(&self) -> String {
        recovery_bonds_hash("LANE", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateFastPathRecoveryBondsResult<()> {
        if self.lane_id.is_empty()
            || self.operator_commitment.is_empty()
            || self.admission_policy_root.is_empty()
        {
            return Err("low latency lane identifiers must be populated".to_string());
        }
        if self.lane_kind.requires_contract_context() && self.contract_context_root.is_empty() {
            return Err("contract recovery lane has empty contract context root".to_string());
        }
        if self.min_bond_units == 0 || self.max_latency_ms == 0 || self.max_pending_commitments == 0
        {
            return Err("low latency lane limits must be positive".to_string());
        }
        if self.updated_height < self.opened_height {
            return Err("low latency lane update height regressed".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoverySignerBond {
    pub signer_id: String,
    pub signer_commitment: String,
    pub pq_public_key_root: String,
    pub notice_encryption_key_root: String,
    pub stake_units: u64,
    pub bonded_units: u64,
    pub slashed_units: u64,
    pub active_lane_ids: BTreeSet<String>,
    pub service_policy_root: String,
    pub joined_height: u64,
    pub updated_height: u64,
    pub status: RecoverySignerStatus,
}

impl RecoverySignerBond {
    pub fn new(
        signer_label: &str,
        signer_commitment: &str,
        pq_public_key_root: &str,
        notice_encryption_key_root: &str,
        stake_units: u64,
        joined_height: u64,
        config: &PrivateFastPathRecoveryBondsConfig,
    ) -> PrivateFastPathRecoveryBondsResult<Self> {
        if signer_label.is_empty()
            || signer_commitment.is_empty()
            || pq_public_key_root.is_empty()
            || notice_encryption_key_root.is_empty()
        {
            return Err("recovery signer bond identifiers must be populated".to_string());
        }
        if stake_units < config.min_signer_stake_units {
            return Err("recovery signer stake is below minimum".to_string());
        }
        let signer_id = recovery_bonds_hash(
            "SIGNER-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(signer_label),
                HashPart::Str(signer_commitment),
                HashPart::Str(pq_public_key_root),
                HashPart::Int(joined_height as i128),
            ],
        );
        let service_policy_root = recovery_bonds_hash(
            "SIGNER-SERVICE-POLICY",
            &[
                HashPart::Str(&signer_id),
                HashPart::Str(pq_public_key_root),
                HashPart::Int(config.sla_latency_ms as i128),
                HashPart::Int(config.max_active_lanes_per_signer as i128),
            ],
        );
        Ok(Self {
            signer_id,
            signer_commitment: signer_commitment.to_string(),
            pq_public_key_root: pq_public_key_root.to_string(),
            notice_encryption_key_root: notice_encryption_key_root.to_string(),
            stake_units,
            bonded_units: stake_units,
            slashed_units: 0,
            active_lane_ids: BTreeSet::new(),
            service_policy_root,
            joined_height,
            updated_height: joined_height,
            status: RecoverySignerStatus::Active,
        })
    }

    pub fn available_bond_units(&self) -> u64 {
        self.bonded_units.saturating_sub(self.slashed_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "signer_id": self.signer_id,
            "signer_commitment": self.signer_commitment,
            "pq_public_key_root": self.pq_public_key_root,
            "notice_encryption_key_root": self.notice_encryption_key_root,
            "stake_units": self.stake_units,
            "bonded_units": self.bonded_units,
            "slashed_units": self.slashed_units,
            "active_lane_ids": self.active_lane_ids,
            "service_policy_root": self.service_policy_root,
            "joined_height": self.joined_height,
            "updated_height": self.updated_height,
            "status": self.status.as_str(),
        })
    }

    pub fn signer_root(&self) -> String {
        recovery_bonds_hash("SIGNER-BOND", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(
        &self,
        config: &PrivateFastPathRecoveryBondsConfig,
    ) -> PrivateFastPathRecoveryBondsResult<()> {
        if self.signer_id.is_empty()
            || self.signer_commitment.is_empty()
            || self.pq_public_key_root.is_empty()
            || self.notice_encryption_key_root.is_empty()
            || self.service_policy_root.is_empty()
        {
            return Err("recovery signer bond identifiers must be populated".to_string());
        }
        if self.stake_units < config.min_signer_stake_units || self.bonded_units == 0 {
            return Err("recovery signer bond is undercollateralized".to_string());
        }
        if self.slashed_units > self.bonded_units {
            return Err("recovery signer slashed units exceed bond".to_string());
        }
        if self.active_lane_ids.len() > config.max_active_lanes_per_signer {
            return Err("recovery signer has too many active lanes".to_string());
        }
        if self.updated_height < self.joined_height {
            return Err("recovery signer update height regressed".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneCommitment {
    pub commitment_id: String,
    pub lane_id: String,
    pub signer_id: String,
    pub account_commitment: String,
    pub recovery_payload_root: String,
    pub private_input_root: String,
    pub nullifier_root: String,
    pub fee_note_root: String,
    pub expected_fee_units: u64,
    pub rebate_bps: u64,
    pub submitted_height: u64,
    pub accepted_height: u64,
    pub deadline_height: u64,
    pub observed_latency_ms: u64,
    pub status: CommitmentStatus,
}

impl LaneCommitment {
    pub fn new(
        lane_id: &str,
        signer_id: &str,
        account_commitment: &str,
        recovery_payload_root: &str,
        private_input_root: &str,
        fee_note_root: &str,
        expected_fee_units: u64,
        submitted_height: u64,
        config: &PrivateFastPathRecoveryBondsConfig,
    ) -> PrivateFastPathRecoveryBondsResult<Self> {
        if lane_id.is_empty()
            || signer_id.is_empty()
            || account_commitment.is_empty()
            || recovery_payload_root.is_empty()
            || private_input_root.is_empty()
            || fee_note_root.is_empty()
        {
            return Err("lane commitment identifiers must be populated".to_string());
        }
        if expected_fee_units == 0 {
            return Err("lane commitment expected fee must be positive".to_string());
        }
        let nullifier_root = recovery_bonds_hash(
            "COMMITMENT-NULLIFIER",
            &[
                HashPart::Str(lane_id),
                HashPart::Str(account_commitment),
                HashPart::Str(recovery_payload_root),
                HashPart::Int(submitted_height as i128),
            ],
        );
        let commitment_id = recovery_bonds_hash(
            "COMMITMENT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(lane_id),
                HashPart::Str(signer_id),
                HashPart::Str(&nullifier_root),
            ],
        );
        Ok(Self {
            commitment_id,
            lane_id: lane_id.to_string(),
            signer_id: signer_id.to_string(),
            account_commitment: account_commitment.to_string(),
            recovery_payload_root: recovery_payload_root.to_string(),
            private_input_root: private_input_root.to_string(),
            nullifier_root,
            fee_note_root: fee_note_root.to_string(),
            expected_fee_units,
            rebate_bps: config.base_rebate_bps,
            submitted_height,
            accepted_height: submitted_height,
            deadline_height: submitted_height.saturating_add(config.challenge_window_blocks),
            observed_latency_ms: 0,
            status: CommitmentStatus::Accepted,
        })
    }

    pub fn rebate_units(&self) -> u64 {
        self.expected_fee_units
            .saturating_mul(self.rebate_bps)
            .saturating_div(PRIVATE_FAST_PATH_RECOVERY_BONDS_MAX_BPS)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "commitment_id": self.commitment_id,
            "lane_id": self.lane_id,
            "signer_id": self.signer_id,
            "account_commitment": self.account_commitment,
            "recovery_payload_root": self.recovery_payload_root,
            "private_input_root": self.private_input_root,
            "nullifier_root": self.nullifier_root,
            "fee_note_root": self.fee_note_root,
            "expected_fee_units": self.expected_fee_units,
            "rebate_bps": self.rebate_bps,
            "submitted_height": self.submitted_height,
            "accepted_height": self.accepted_height,
            "deadline_height": self.deadline_height,
            "observed_latency_ms": self.observed_latency_ms,
            "status": self.status.as_str(),
        })
    }

    pub fn commitment_root(&self) -> String {
        recovery_bonds_hash("LANE-COMMITMENT", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(
        &self,
        config: &PrivateFastPathRecoveryBondsConfig,
    ) -> PrivateFastPathRecoveryBondsResult<()> {
        if self.commitment_id.is_empty()
            || self.lane_id.is_empty()
            || self.signer_id.is_empty()
            || self.account_commitment.is_empty()
            || self.recovery_payload_root.is_empty()
            || self.private_input_root.is_empty()
            || self.nullifier_root.is_empty()
            || self.fee_note_root.is_empty()
        {
            return Err("lane commitment identifiers must be populated".to_string());
        }
        if self.expected_fee_units == 0 {
            return Err("lane commitment expected fee must be positive".to_string());
        }
        if self.rebate_bps > config.max_rebate_bps {
            return Err("lane commitment rebate exceeds configured max".to_string());
        }
        if self.accepted_height < self.submitted_height
            || self.deadline_height < self.accepted_height
        {
            return Err("lane commitment heights are inconsistent".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedFailureNotice {
    pub notice_id: String,
    pub commitment_id: String,
    pub lane_id: String,
    pub signer_id: String,
    pub recipient_commitment: String,
    pub ciphertext_root: String,
    pub ephemeral_key_root: String,
    pub failure_code_root: String,
    pub sealed_height: u64,
    pub expiry_height: u64,
    pub status: FailureNoticeStatus,
}

impl EncryptedFailureNotice {
    pub fn new(
        commitment_id: &str,
        lane_id: &str,
        signer_id: &str,
        recipient_commitment: &str,
        ciphertext_root: &str,
        ephemeral_key_root: &str,
        failure_code: &str,
        sealed_height: u64,
        config: &PrivateFastPathRecoveryBondsConfig,
    ) -> PrivateFastPathRecoveryBondsResult<Self> {
        if commitment_id.is_empty()
            || lane_id.is_empty()
            || signer_id.is_empty()
            || recipient_commitment.is_empty()
            || ciphertext_root.is_empty()
            || ephemeral_key_root.is_empty()
            || failure_code.is_empty()
        {
            return Err("encrypted failure notice identifiers must be populated".to_string());
        }
        let failure_code_root = recovery_bonds_hash("FAILURE-CODE", &[HashPart::Str(failure_code)]);
        let notice_id = recovery_bonds_hash(
            "FAILURE-NOTICE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(commitment_id),
                HashPart::Str(recipient_commitment),
                HashPart::Str(&failure_code_root),
            ],
        );
        Ok(Self {
            notice_id,
            commitment_id: commitment_id.to_string(),
            lane_id: lane_id.to_string(),
            signer_id: signer_id.to_string(),
            recipient_commitment: recipient_commitment.to_string(),
            ciphertext_root: ciphertext_root.to_string(),
            ephemeral_key_root: ephemeral_key_root.to_string(),
            failure_code_root,
            sealed_height,
            expiry_height: sealed_height.saturating_add(config.notice_ttl_blocks),
            status: FailureNoticeStatus::Sealed,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "notice_id": self.notice_id,
            "commitment_id": self.commitment_id,
            "lane_id": self.lane_id,
            "signer_id": self.signer_id,
            "recipient_commitment": self.recipient_commitment,
            "ciphertext_root": self.ciphertext_root,
            "ephemeral_key_root": self.ephemeral_key_root,
            "failure_code_root": self.failure_code_root,
            "sealed_height": self.sealed_height,
            "expiry_height": self.expiry_height,
            "status": self.status.as_str(),
        })
    }

    pub fn notice_root(&self) -> String {
        recovery_bonds_hash("FAILURE-NOTICE", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateFastPathRecoveryBondsResult<()> {
        if self.notice_id.is_empty()
            || self.commitment_id.is_empty()
            || self.lane_id.is_empty()
            || self.signer_id.is_empty()
            || self.recipient_commitment.is_empty()
            || self.ciphertext_root.is_empty()
            || self.ephemeral_key_root.is_empty()
            || self.failure_code_root.is_empty()
        {
            return Err("encrypted failure notice identifiers must be populated".to_string());
        }
        if self.expiry_height <= self.sealed_height {
            return Err("encrypted failure notice expiry must follow sealed height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeRebateClaim {
    pub claim_id: String,
    pub commitment_id: String,
    pub lane_id: String,
    pub claimant_commitment: String,
    pub fee_note_root: String,
    pub rebate_units: u64,
    pub proof_root: String,
    pub claimed_height: u64,
    pub expiry_height: u64,
    pub paid_height: u64,
    pub status: RebateClaimStatus,
}

impl FeeRebateClaim {
    pub fn new(
        commitment: &LaneCommitment,
        claimant_commitment: &str,
        proof_root: &str,
        claimed_height: u64,
        config: &PrivateFastPathRecoveryBondsConfig,
    ) -> PrivateFastPathRecoveryBondsResult<Self> {
        if claimant_commitment.is_empty() || proof_root.is_empty() {
            return Err("fee rebate claim identifiers must be populated".to_string());
        }
        let rebate_units = commitment.rebate_units();
        if rebate_units == 0 {
            return Err("fee rebate claim amount must be positive".to_string());
        }
        let claim_id = recovery_bonds_hash(
            "REBATE-CLAIM-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&commitment.commitment_id),
                HashPart::Str(claimant_commitment),
                HashPart::Str(proof_root),
            ],
        );
        Ok(Self {
            claim_id,
            commitment_id: commitment.commitment_id.clone(),
            lane_id: commitment.lane_id.clone(),
            claimant_commitment: claimant_commitment.to_string(),
            fee_note_root: commitment.fee_note_root.clone(),
            rebate_units,
            proof_root: proof_root.to_string(),
            claimed_height,
            expiry_height: claimed_height.saturating_add(config.rebate_claim_ttl_blocks),
            paid_height: 0,
            status: RebateClaimStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "claim_id": self.claim_id,
            "commitment_id": self.commitment_id,
            "lane_id": self.lane_id,
            "claimant_commitment": self.claimant_commitment,
            "fee_note_root": self.fee_note_root,
            "rebate_units": self.rebate_units,
            "proof_root": self.proof_root,
            "claimed_height": self.claimed_height,
            "expiry_height": self.expiry_height,
            "paid_height": self.paid_height,
            "status": self.status.as_str(),
        })
    }

    pub fn claim_root(&self) -> String {
        recovery_bonds_hash("REBATE-CLAIM", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateFastPathRecoveryBondsResult<()> {
        if self.claim_id.is_empty()
            || self.commitment_id.is_empty()
            || self.lane_id.is_empty()
            || self.claimant_commitment.is_empty()
            || self.fee_note_root.is_empty()
            || self.proof_root.is_empty()
        {
            return Err("fee rebate claim identifiers must be populated".to_string());
        }
        if self.rebate_units == 0 || self.expiry_height <= self.claimed_height {
            return Err("fee rebate claim amount or expiry is invalid".to_string());
        }
        if matches!(self.status, RebateClaimStatus::Paid) && self.paid_height < self.claimed_height
        {
            return Err("fee rebate claim paid height regressed".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissedSlaChallenge {
    pub challenge_id: String,
    pub commitment_id: String,
    pub lane_id: String,
    pub signer_id: String,
    pub challenger_commitment: String,
    pub expected_latency_ms: u64,
    pub observed_latency_ms: u64,
    pub evidence_root: String,
    pub bond_at_risk_units: u64,
    pub opened_height: u64,
    pub deadline_height: u64,
    pub resolved_height: u64,
    pub status: ChallengeStatus,
}

impl MissedSlaChallenge {
    pub fn new(
        commitment: &LaneCommitment,
        challenger_commitment: &str,
        observed_latency_ms: u64,
        evidence_root: &str,
        opened_height: u64,
        config: &PrivateFastPathRecoveryBondsConfig,
    ) -> PrivateFastPathRecoveryBondsResult<Self> {
        if challenger_commitment.is_empty() || evidence_root.is_empty() {
            return Err("missed SLA challenge identifiers must be populated".to_string());
        }
        if observed_latency_ms <= config.sla_latency_ms {
            return Err("missed SLA challenge requires latency above SLA".to_string());
        }
        let bond_at_risk_units = config
            .min_bond_units
            .saturating_mul(config.default_slash_bps)
            .saturating_div(PRIVATE_FAST_PATH_RECOVERY_BONDS_MAX_BPS);
        let challenge_id = recovery_bonds_hash(
            "MISSED-SLA-CHALLENGE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&commitment.commitment_id),
                HashPart::Str(challenger_commitment),
                HashPart::Int(observed_latency_ms as i128),
                HashPart::Str(evidence_root),
            ],
        );
        Ok(Self {
            challenge_id,
            commitment_id: commitment.commitment_id.clone(),
            lane_id: commitment.lane_id.clone(),
            signer_id: commitment.signer_id.clone(),
            challenger_commitment: challenger_commitment.to_string(),
            expected_latency_ms: config.sla_latency_ms,
            observed_latency_ms,
            evidence_root: evidence_root.to_string(),
            bond_at_risk_units,
            opened_height,
            deadline_height: opened_height.saturating_add(config.challenge_window_blocks),
            resolved_height: 0,
            status: ChallengeStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "challenge_id": self.challenge_id,
            "commitment_id": self.commitment_id,
            "lane_id": self.lane_id,
            "signer_id": self.signer_id,
            "challenger_commitment": self.challenger_commitment,
            "expected_latency_ms": self.expected_latency_ms,
            "observed_latency_ms": self.observed_latency_ms,
            "evidence_root": self.evidence_root,
            "bond_at_risk_units": self.bond_at_risk_units,
            "opened_height": self.opened_height,
            "deadline_height": self.deadline_height,
            "resolved_height": self.resolved_height,
            "status": self.status.as_str(),
        })
    }

    pub fn challenge_root(&self) -> String {
        recovery_bonds_hash(
            "MISSED-SLA-CHALLENGE",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self) -> PrivateFastPathRecoveryBondsResult<()> {
        if self.challenge_id.is_empty()
            || self.commitment_id.is_empty()
            || self.lane_id.is_empty()
            || self.signer_id.is_empty()
            || self.challenger_commitment.is_empty()
            || self.evidence_root.is_empty()
        {
            return Err("missed SLA challenge identifiers must be populated".to_string());
        }
        if self.expected_latency_ms == 0
            || self.observed_latency_ms <= self.expected_latency_ms
            || self.bond_at_risk_units == 0
            || self.deadline_height <= self.opened_height
        {
            return Err("missed SLA challenge values are invalid".to_string());
        }
        if !self.status.unresolved() && self.resolved_height < self.opened_height {
            return Err("missed SLA challenge resolved height regressed".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryReceipt {
    pub receipt_id: String,
    pub commitment_id: String,
    pub lane_id: String,
    pub signer_id: String,
    pub account_commitment: String,
    pub recovery_result_root: String,
    pub receipt_nullifier_root: String,
    pub pq_signature_root: String,
    pub fee_rebate_claim_id: String,
    pub issued_height: u64,
    pub expiry_height: u64,
    pub status: ReceiptStatus,
}

impl RecoveryReceipt {
    pub fn new(
        commitment: &LaneCommitment,
        recovery_result_root: &str,
        pq_signature_root: &str,
        fee_rebate_claim_id: &str,
        issued_height: u64,
        config: &PrivateFastPathRecoveryBondsConfig,
    ) -> PrivateFastPathRecoveryBondsResult<Self> {
        if recovery_result_root.is_empty() || pq_signature_root.is_empty() {
            return Err("recovery receipt identifiers must be populated".to_string());
        }
        let receipt_nullifier_root = recovery_bonds_hash(
            "RECEIPT-NULLIFIER",
            &[
                HashPart::Str(&commitment.commitment_id),
                HashPart::Str(&commitment.account_commitment),
                HashPart::Str(recovery_result_root),
            ],
        );
        let receipt_id = recovery_bonds_hash(
            "RECOVERY-RECEIPT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&commitment.commitment_id),
                HashPart::Str(&receipt_nullifier_root),
                HashPart::Str(pq_signature_root),
            ],
        );
        Ok(Self {
            receipt_id,
            commitment_id: commitment.commitment_id.clone(),
            lane_id: commitment.lane_id.clone(),
            signer_id: commitment.signer_id.clone(),
            account_commitment: commitment.account_commitment.clone(),
            recovery_result_root: recovery_result_root.to_string(),
            receipt_nullifier_root,
            pq_signature_root: pq_signature_root.to_string(),
            fee_rebate_claim_id: fee_rebate_claim_id.to_string(),
            issued_height,
            expiry_height: issued_height.saturating_add(config.receipt_ttl_blocks),
            status: ReceiptStatus::Finalized,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "commitment_id": self.commitment_id,
            "lane_id": self.lane_id,
            "signer_id": self.signer_id,
            "account_commitment": self.account_commitment,
            "recovery_result_root": self.recovery_result_root,
            "receipt_nullifier_root": self.receipt_nullifier_root,
            "pq_signature_root": self.pq_signature_root,
            "fee_rebate_claim_id": self.fee_rebate_claim_id,
            "issued_height": self.issued_height,
            "expiry_height": self.expiry_height,
            "status": self.status.as_str(),
        })
    }

    pub fn receipt_root(&self) -> String {
        recovery_bonds_hash("RECOVERY-RECEIPT", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateFastPathRecoveryBondsResult<()> {
        if self.receipt_id.is_empty()
            || self.commitment_id.is_empty()
            || self.lane_id.is_empty()
            || self.signer_id.is_empty()
            || self.account_commitment.is_empty()
            || self.recovery_result_root.is_empty()
            || self.receipt_nullifier_root.is_empty()
            || self.pq_signature_root.is_empty()
        {
            return Err("recovery receipt identifiers must be populated".to_string());
        }
        if self.expiry_height <= self.issued_height {
            return Err("recovery receipt expiry must follow issued height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingRecord {
    pub slash_id: String,
    pub signer_id: String,
    pub lane_id: String,
    pub challenge_id: String,
    pub commitment_id: String,
    pub reason: SlashReason,
    pub slash_units: u64,
    pub remaining_bond_units: u64,
    pub evidence_root: String,
    pub executed_height: u64,
}

impl SlashingRecord {
    pub fn new(
        signer: &RecoverySignerBond,
        challenge: &MissedSlaChallenge,
        reason: SlashReason,
        slash_units: u64,
        evidence_root: &str,
        executed_height: u64,
    ) -> PrivateFastPathRecoveryBondsResult<Self> {
        if evidence_root.is_empty() {
            return Err("slashing evidence root must be populated".to_string());
        }
        if slash_units == 0 || slash_units > signer.available_bond_units() {
            return Err("slashing units must be positive and covered by signer bond".to_string());
        }
        let remaining_bond_units = signer.available_bond_units().saturating_sub(slash_units);
        let slash_id = recovery_bonds_hash(
            "SLASH-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&signer.signer_id),
                HashPart::Str(&challenge.challenge_id),
                HashPart::Str(reason.as_str()),
                HashPart::Int(slash_units as i128),
            ],
        );
        Ok(Self {
            slash_id,
            signer_id: signer.signer_id.clone(),
            lane_id: challenge.lane_id.clone(),
            challenge_id: challenge.challenge_id.clone(),
            commitment_id: challenge.commitment_id.clone(),
            reason,
            slash_units,
            remaining_bond_units,
            evidence_root: evidence_root.to_string(),
            executed_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "slash_id": self.slash_id,
            "signer_id": self.signer_id,
            "lane_id": self.lane_id,
            "challenge_id": self.challenge_id,
            "commitment_id": self.commitment_id,
            "reason": self.reason.as_str(),
            "slash_units": self.slash_units,
            "remaining_bond_units": self.remaining_bond_units,
            "evidence_root": self.evidence_root,
            "executed_height": self.executed_height,
        })
    }

    pub fn slash_root(&self) -> String {
        recovery_bonds_hash("SLASHING-RECORD", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateFastPathRecoveryBondsResult<()> {
        if self.slash_id.is_empty()
            || self.signer_id.is_empty()
            || self.lane_id.is_empty()
            || self.challenge_id.is_empty()
            || self.commitment_id.is_empty()
            || self.evidence_root.is_empty()
        {
            return Err("slashing record identifiers must be populated".to_string());
        }
        if self.slash_units == 0 {
            return Err("slashing record amount must be positive".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateFastPathRecoveryBondsCounters {
    pub lanes: usize,
    pub signers: usize,
    pub commitments: usize,
    pub failure_notices: usize,
    pub rebate_claims: usize,
    pub challenges: usize,
    pub receipts: usize,
    pub slashing_records: usize,
    pub active_commitments: usize,
    pub unresolved_challenges: usize,
    pub total_bonded_units: u64,
    pub total_slashed_units: u64,
    pub total_rebate_units: u64,
}

impl PrivateFastPathRecoveryBondsCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "lanes": self.lanes,
            "signers": self.signers,
            "commitments": self.commitments,
            "failure_notices": self.failure_notices,
            "rebate_claims": self.rebate_claims,
            "challenges": self.challenges,
            "receipts": self.receipts,
            "slashing_records": self.slashing_records,
            "active_commitments": self.active_commitments,
            "unresolved_challenges": self.unresolved_challenges,
            "total_bonded_units": self.total_bonded_units,
            "total_slashed_units": self.total_slashed_units,
            "total_rebate_units": self.total_rebate_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateFastPathRecoveryBondsRoots {
    pub config_root: String,
    pub lane_root: String,
    pub signer_root: String,
    pub commitment_root: String,
    pub failure_notice_root: String,
    pub rebate_claim_root: String,
    pub challenge_root: String,
    pub receipt_root: String,
    pub slashing_root: String,
    pub nullifier_root: String,
    pub counter_root: String,
}

impl PrivateFastPathRecoveryBondsRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "signer_root": self.signer_root,
            "commitment_root": self.commitment_root,
            "failure_notice_root": self.failure_notice_root,
            "rebate_claim_root": self.rebate_claim_root,
            "challenge_root": self.challenge_root,
            "receipt_root": self.receipt_root,
            "slashing_root": self.slashing_root,
            "nullifier_root": self.nullifier_root,
            "counter_root": self.counter_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateFastPathRecoveryBondsState {
    pub height: u64,
    pub config: PrivateFastPathRecoveryBondsConfig,
    pub lanes: BTreeMap<String, LowLatencyLane>,
    pub signers: BTreeMap<String, RecoverySignerBond>,
    pub commitments: BTreeMap<String, LaneCommitment>,
    pub failure_notices: BTreeMap<String, EncryptedFailureNotice>,
    pub rebate_claims: BTreeMap<String, FeeRebateClaim>,
    pub challenges: BTreeMap<String, MissedSlaChallenge>,
    pub receipts: BTreeMap<String, RecoveryReceipt>,
    pub slashing_records: BTreeMap<String, SlashingRecord>,
    pub commitment_nullifiers: BTreeSet<String>,
    pub receipt_nullifiers: BTreeSet<String>,
}

impl PrivateFastPathRecoveryBondsState {
    pub fn new(height: u64, config: PrivateFastPathRecoveryBondsConfig) -> Self {
        Self {
            height,
            config,
            lanes: BTreeMap::new(),
            signers: BTreeMap::new(),
            commitments: BTreeMap::new(),
            failure_notices: BTreeMap::new(),
            rebate_claims: BTreeMap::new(),
            challenges: BTreeMap::new(),
            receipts: BTreeMap::new(),
            slashing_records: BTreeMap::new(),
            commitment_nullifiers: BTreeSet::new(),
            receipt_nullifiers: BTreeSet::new(),
        }
    }

    pub fn devnet() -> PrivateFastPathRecoveryBondsResult<Self> {
        let config = PrivateFastPathRecoveryBondsConfig::devnet();
        let mut state = Self::new(PRIVATE_FAST_PATH_RECOVERY_BONDS_DEVNET_HEIGHT, config);
        let wallet_lane = LowLatencyLane::new(
            "devnet-wallet-recovery",
            FastPathLaneKind::WalletRecovery,
            "operator:fast-path:wallet:commitment",
            "",
            "admission:wallet-recovery:policy-root",
            state.height,
            &state.config,
        )?;
        let monero_lane = LowLatencyLane::new(
            "devnet-monero-exit-recovery",
            FastPathLaneKind::MoneroExitRecovery,
            "operator:fast-path:monero:commitment",
            "",
            "admission:monero-exit-recovery:policy-root",
            state.height,
            &state.config,
        )?;
        state.insert_lane(wallet_lane)?;
        state.insert_lane(monero_lane)?;

        let signer = RecoverySignerBond::new(
            "devnet-recovery-signer-a",
            "signer:a:private-commitment",
            "pq:ml-dsa-65:signer-a:public-key-root",
            "kem:ml-kem-768:signer-a:notice-key-root",
            400_000,
            state.height,
            &state.config,
        )?;
        state.insert_signer(signer)?;

        let lane_id = state
            .lanes
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| "devnet recovery bonds missing lane".to_string())?;
        let signer_id = state
            .signers
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| "devnet recovery bonds missing signer".to_string())?;
        state.bind_signer_to_lane(&signer_id, &lane_id)?;

        let commitment = LaneCommitment::new(
            &lane_id,
            &signer_id,
            "acct:shielded:alice:commitment",
            "recovery:payload:alice:root",
            "private-input:alice:root",
            "fee-note:alice:root",
            120,
            state.height.saturating_add(1),
            &state.config,
        )?;
        let commitment_id = commitment.commitment_id.clone();
        state.insert_commitment(commitment)?;

        let notice = EncryptedFailureNotice::new(
            &commitment_id,
            &lane_id,
            &signer_id,
            "acct:shielded:alice:notice-recipient",
            "ciphertext:alice:failure:root",
            "kem:alice:ephemeral:root",
            "recoverable-timeout",
            state.height.saturating_add(2),
            &state.config,
        )?;
        state.insert_failure_notice(notice)?;

        let commitment = state
            .commitments
            .get(&commitment_id)
            .cloned()
            .ok_or_else(|| "devnet recovery bonds missing commitment".to_string())?;
        let claim = FeeRebateClaim::new(
            &commitment,
            "acct:shielded:alice:rebate-claimant",
            "rebate-proof:alice:root",
            state.height.saturating_add(3),
            &state.config,
        )?;
        let claim_id = claim.claim_id.clone();
        state.insert_rebate_claim(claim)?;

        let receipt = RecoveryReceipt::new(
            &commitment,
            "recovery:result:alice:root",
            "pq-signature:alice:receipt:root",
            &claim_id,
            state.height.saturating_add(4),
            &state.config,
        )?;
        state.insert_receipt(receipt)?;

        let challenge = MissedSlaChallenge::new(
            &commitment,
            "watchtower:devnet:challenger",
            state.config.sla_latency_ms.saturating_add(275),
            "sla:evidence:alice:root",
            state.height.saturating_add(5),
            &state.config,
        )?;
        let challenge_id = challenge.challenge_id.clone();
        state.insert_challenge(challenge)?;

        let signer = state
            .signers
            .get(&signer_id)
            .cloned()
            .ok_or_else(|| "devnet recovery bonds missing signer for slash".to_string())?;
        let challenge = state
            .challenges
            .get(&challenge_id)
            .cloned()
            .ok_or_else(|| "devnet recovery bonds missing challenge for slash".to_string())?;
        let slash = SlashingRecord::new(
            &signer,
            &challenge,
            SlashReason::MissedSla,
            challenge.bond_at_risk_units,
            "sla:evidence:alice:root",
            state.height.saturating_add(6),
        )?;
        state.insert_slashing_record(slash)?;
        state.validate()?;
        Ok(state)
    }

    pub fn advance_height(&mut self, new_height: u64) -> PrivateFastPathRecoveryBondsResult<u64> {
        if new_height < self.height {
            return Err("private fast path recovery bonds height cannot decrease".to_string());
        }
        self.height = new_height;
        Ok(self.height)
    }

    pub fn insert_lane(&mut self, lane: LowLatencyLane) -> PrivateFastPathRecoveryBondsResult<()> {
        lane.validate()?;
        if self.lanes.contains_key(&lane.lane_id) {
            return Err("duplicate low latency lane".to_string());
        }
        self.lanes.insert(lane.lane_id.clone(), lane);
        Ok(())
    }

    pub fn insert_signer(
        &mut self,
        signer: RecoverySignerBond,
    ) -> PrivateFastPathRecoveryBondsResult<()> {
        signer.validate(&self.config)?;
        if self.signers.contains_key(&signer.signer_id) {
            return Err("duplicate recovery signer bond".to_string());
        }
        self.signers.insert(signer.signer_id.clone(), signer);
        Ok(())
    }

    pub fn bind_signer_to_lane(
        &mut self,
        signer_id: &str,
        lane_id: &str,
    ) -> PrivateFastPathRecoveryBondsResult<()> {
        if !self.lanes.contains_key(lane_id) {
            return Err("cannot bind signer to unknown lane".to_string());
        }
        let signer = self
            .signers
            .get_mut(signer_id)
            .ok_or_else(|| "cannot bind unknown signer to lane".to_string())?;
        if signer.active_lane_ids.len() >= self.config.max_active_lanes_per_signer
            && !signer.active_lane_ids.contains(lane_id)
        {
            return Err("recovery signer lane capacity exceeded".to_string());
        }
        signer.active_lane_ids.insert(lane_id.to_string());
        signer.updated_height = self.height;
        Ok(())
    }

    pub fn insert_commitment(
        &mut self,
        commitment: LaneCommitment,
    ) -> PrivateFastPathRecoveryBondsResult<()> {
        commitment.validate(&self.config)?;
        if self.commitments.contains_key(&commitment.commitment_id) {
            return Err("duplicate lane commitment".to_string());
        }
        let lane = self
            .lanes
            .get(&commitment.lane_id)
            .ok_or_else(|| "lane commitment references unknown lane".to_string())?;
        if !lane.status.accepts_commitments() {
            return Err(
                "lane commitment references lane that does not accept commitments".to_string(),
            );
        }
        let signer = self
            .signers
            .get(&commitment.signer_id)
            .ok_or_else(|| "lane commitment references unknown signer".to_string())?;
        if !signer.status.may_serve() || !signer.active_lane_ids.contains(&commitment.lane_id) {
            return Err("lane commitment references signer not active on lane".to_string());
        }
        if self
            .commitment_nullifiers
            .contains(&commitment.nullifier_root)
        {
            return Err("duplicate lane commitment nullifier".to_string());
        }
        let live_count = self
            .commitments
            .values()
            .filter(|candidate| candidate.lane_id == commitment.lane_id && candidate.status.live())
            .count();
        if live_count >= lane.max_pending_commitments {
            return Err("lane pending commitment capacity exceeded".to_string());
        }
        self.commitment_nullifiers
            .insert(commitment.nullifier_root.clone());
        self.commitments
            .insert(commitment.commitment_id.clone(), commitment);
        Ok(())
    }

    pub fn insert_failure_notice(
        &mut self,
        notice: EncryptedFailureNotice,
    ) -> PrivateFastPathRecoveryBondsResult<()> {
        notice.validate()?;
        if self.failure_notices.contains_key(&notice.notice_id) {
            return Err("duplicate encrypted failure notice".to_string());
        }
        self.ensure_commitment_lane_signer(
            &notice.commitment_id,
            &notice.lane_id,
            &notice.signer_id,
        )?;
        self.failure_notices
            .insert(notice.notice_id.clone(), notice);
        Ok(())
    }

    pub fn insert_rebate_claim(
        &mut self,
        claim: FeeRebateClaim,
    ) -> PrivateFastPathRecoveryBondsResult<()> {
        claim.validate()?;
        if self.rebate_claims.contains_key(&claim.claim_id) {
            return Err("duplicate fee rebate claim".to_string());
        }
        if !self.commitments.contains_key(&claim.commitment_id) {
            return Err("fee rebate claim references unknown commitment".to_string());
        }
        self.rebate_claims.insert(claim.claim_id.clone(), claim);
        Ok(())
    }

    pub fn insert_challenge(
        &mut self,
        challenge: MissedSlaChallenge,
    ) -> PrivateFastPathRecoveryBondsResult<()> {
        challenge.validate()?;
        if self.challenges.contains_key(&challenge.challenge_id) {
            return Err("duplicate missed SLA challenge".to_string());
        }
        self.ensure_commitment_lane_signer(
            &challenge.commitment_id,
            &challenge.lane_id,
            &challenge.signer_id,
        )?;
        self.challenges
            .insert(challenge.challenge_id.clone(), challenge);
        Ok(())
    }

    pub fn insert_receipt(
        &mut self,
        receipt: RecoveryReceipt,
    ) -> PrivateFastPathRecoveryBondsResult<()> {
        receipt.validate()?;
        if self.receipts.contains_key(&receipt.receipt_id) {
            return Err("duplicate recovery receipt".to_string());
        }
        self.ensure_commitment_lane_signer(
            &receipt.commitment_id,
            &receipt.lane_id,
            &receipt.signer_id,
        )?;
        if self
            .receipt_nullifiers
            .contains(&receipt.receipt_nullifier_root)
        {
            return Err("duplicate recovery receipt nullifier".to_string());
        }
        if !receipt.fee_rebate_claim_id.is_empty()
            && !self
                .rebate_claims
                .contains_key(&receipt.fee_rebate_claim_id)
        {
            return Err("recovery receipt references unknown fee rebate claim".to_string());
        }
        self.receipt_nullifiers
            .insert(receipt.receipt_nullifier_root.clone());
        self.receipts.insert(receipt.receipt_id.clone(), receipt);
        Ok(())
    }

    pub fn insert_slashing_record(
        &mut self,
        slash: SlashingRecord,
    ) -> PrivateFastPathRecoveryBondsResult<()> {
        slash.validate()?;
        if self.slashing_records.contains_key(&slash.slash_id) {
            return Err("duplicate slashing record".to_string());
        }
        if !self.challenges.contains_key(&slash.challenge_id) {
            return Err("slashing record references unknown challenge".to_string());
        }
        let signer = self
            .signers
            .get_mut(&slash.signer_id)
            .ok_or_else(|| "slashing record references unknown signer".to_string())?;
        if slash.slash_units > signer.available_bond_units() {
            return Err("slashing record exceeds signer available bond".to_string());
        }
        signer.slashed_units = signer.slashed_units.saturating_add(slash.slash_units);
        signer.status = RecoverySignerStatus::Slashed;
        signer.updated_height = slash.executed_height;
        self.slashing_records.insert(slash.slash_id.clone(), slash);
        Ok(())
    }

    pub fn mark_commitment_recovered(
        &mut self,
        commitment_id: &str,
        observed_latency_ms: u64,
        height: u64,
    ) -> PrivateFastPathRecoveryBondsResult<()> {
        self.advance_height(height)?;
        let commitment = self
            .commitments
            .get_mut(commitment_id)
            .ok_or_else(|| "cannot recover unknown lane commitment".to_string())?;
        if commitment.status.terminal() {
            return Err("cannot recover terminal lane commitment".to_string());
        }
        commitment.observed_latency_ms = observed_latency_ms;
        commitment.status = CommitmentStatus::Recovered;
        Ok(())
    }

    pub fn mark_rebate_paid(
        &mut self,
        claim_id: &str,
        paid_height: u64,
    ) -> PrivateFastPathRecoveryBondsResult<()> {
        self.advance_height(paid_height)?;
        let claim = self
            .rebate_claims
            .get_mut(claim_id)
            .ok_or_else(|| "cannot pay unknown fee rebate claim".to_string())?;
        if matches!(
            claim.status,
            RebateClaimStatus::Rejected | RebateClaimStatus::Expired
        ) {
            return Err("cannot pay rejected or expired fee rebate claim".to_string());
        }
        claim.status = RebateClaimStatus::Paid;
        claim.paid_height = paid_height;
        Ok(())
    }

    pub fn resolve_challenge(
        &mut self,
        challenge_id: &str,
        status: ChallengeStatus,
        resolved_height: u64,
    ) -> PrivateFastPathRecoveryBondsResult<()> {
        if status.unresolved() {
            return Err("resolve challenge requires terminal status".to_string());
        }
        self.advance_height(resolved_height)?;
        let challenge = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| "cannot resolve unknown missed SLA challenge".to_string())?;
        challenge.status = status;
        challenge.resolved_height = resolved_height;
        Ok(())
    }

    pub fn roots(&self) -> PrivateFastPathRecoveryBondsRoots {
        let config_root = self.config.config_root();
        let lane_root = map_merkle_root(
            "PRIVATE-FAST-PATH-RECOVERY-BONDS-LANES",
            self.lanes
                .iter()
                .map(|(id, lane)| json!({"id": id, "record": lane.public_record()})),
        );
        let signer_root = map_merkle_root(
            "PRIVATE-FAST-PATH-RECOVERY-BONDS-SIGNERS",
            self.signers
                .iter()
                .map(|(id, signer)| json!({"id": id, "record": signer.public_record()})),
        );
        let commitment_root = map_merkle_root(
            "PRIVATE-FAST-PATH-RECOVERY-BONDS-COMMITMENTS",
            self.commitments
                .iter()
                .map(|(id, commitment)| json!({"id": id, "record": commitment.public_record()})),
        );
        let failure_notice_root = map_merkle_root(
            "PRIVATE-FAST-PATH-RECOVERY-BONDS-FAILURE-NOTICES",
            self.failure_notices
                .iter()
                .map(|(id, notice)| json!({"id": id, "record": notice.public_record()})),
        );
        let rebate_claim_root = map_merkle_root(
            "PRIVATE-FAST-PATH-RECOVERY-BONDS-REBATE-CLAIMS",
            self.rebate_claims
                .iter()
                .map(|(id, claim)| json!({"id": id, "record": claim.public_record()})),
        );
        let challenge_root = map_merkle_root(
            "PRIVATE-FAST-PATH-RECOVERY-BONDS-CHALLENGES",
            self.challenges
                .iter()
                .map(|(id, challenge)| json!({"id": id, "record": challenge.public_record()})),
        );
        let receipt_root = map_merkle_root(
            "PRIVATE-FAST-PATH-RECOVERY-BONDS-RECEIPTS",
            self.receipts
                .iter()
                .map(|(id, receipt)| json!({"id": id, "record": receipt.public_record()})),
        );
        let slashing_root = map_merkle_root(
            "PRIVATE-FAST-PATH-RECOVERY-BONDS-SLASHING",
            self.slashing_records
                .iter()
                .map(|(id, slash)| json!({"id": id, "record": slash.public_record()})),
        );
        let nullifier_root = map_merkle_root(
            "PRIVATE-FAST-PATH-RECOVERY-BONDS-NULLIFIERS",
            self.commitment_nullifiers
                .iter()
                .chain(self.receipt_nullifiers.iter())
                .map(|nullifier| json!({"nullifier": nullifier})),
        );
        let counters = self.counters();
        let counter_root =
            recovery_bonds_hash("COUNTERS", &[HashPart::Json(&counters.public_record())]);
        PrivateFastPathRecoveryBondsRoots {
            config_root,
            lane_root,
            signer_root,
            commitment_root,
            failure_notice_root,
            rebate_claim_root,
            challenge_root,
            receipt_root,
            slashing_root,
            nullifier_root,
            counter_root,
        }
    }

    pub fn counters(&self) -> PrivateFastPathRecoveryBondsCounters {
        PrivateFastPathRecoveryBondsCounters {
            lanes: self.lanes.len(),
            signers: self.signers.len(),
            commitments: self.commitments.len(),
            failure_notices: self.failure_notices.len(),
            rebate_claims: self.rebate_claims.len(),
            challenges: self.challenges.len(),
            receipts: self.receipts.len(),
            slashing_records: self.slashing_records.len(),
            active_commitments: self
                .commitments
                .values()
                .filter(|commitment| commitment.status.live())
                .count(),
            unresolved_challenges: self
                .challenges
                .values()
                .filter(|challenge| challenge.status.unresolved())
                .count(),
            total_bonded_units: self
                .signers
                .values()
                .map(|signer| signer.bonded_units)
                .sum(),
            total_slashed_units: self
                .signers
                .values()
                .map(|signer| signer.slashed_units)
                .sum(),
            total_rebate_units: self
                .rebate_claims
                .values()
                .map(|claim| claim.rebate_units)
                .sum(),
        }
    }

    pub fn state_root(&self) -> String {
        let roots = self.roots();
        recovery_bonds_hash(
            "STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Int(PRIVATE_FAST_PATH_RECOVERY_BONDS_SCHEMA_VERSION as i128),
                HashPart::Int(self.height as i128),
                HashPart::Json(&roots.public_record()),
            ],
        )
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_FAST_PATH_RECOVERY_BONDS_PROTOCOL_VERSION,
            "schema_version": PRIVATE_FAST_PATH_RECOVERY_BONDS_SCHEMA_VERSION,
            "height": self.height,
            "state_root": self.state_root(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "config": self.config.public_record(),
        })
    }

    pub fn validate(&self) -> PrivateFastPathRecoveryBondsResult<()> {
        self.config.validate()?;
        let mut commitment_nullifiers = BTreeSet::new();
        let mut receipt_nullifiers = BTreeSet::new();
        for (lane_id, lane) in &self.lanes {
            if lane_id != &lane.lane_id {
                return Err("low latency lane map key mismatch".to_string());
            }
            lane.validate()?;
        }
        for (signer_id, signer) in &self.signers {
            if signer_id != &signer.signer_id {
                return Err("recovery signer map key mismatch".to_string());
            }
            signer.validate(&self.config)?;
            for lane_id in &signer.active_lane_ids {
                if !self.lanes.contains_key(lane_id) {
                    return Err("recovery signer references unknown lane".to_string());
                }
            }
        }
        for (commitment_id, commitment) in &self.commitments {
            if commitment_id != &commitment.commitment_id {
                return Err("lane commitment map key mismatch".to_string());
            }
            commitment.validate(&self.config)?;
            self.ensure_commitment_lane_signer(
                &commitment.commitment_id,
                &commitment.lane_id,
                &commitment.signer_id,
            )?;
            if !commitment_nullifiers.insert(commitment.nullifier_root.clone()) {
                return Err("duplicate lane commitment nullifier in state".to_string());
            }
        }
        for (notice_id, notice) in &self.failure_notices {
            if notice_id != &notice.notice_id {
                return Err("encrypted failure notice map key mismatch".to_string());
            }
            notice.validate()?;
            self.ensure_commitment_lane_signer(
                &notice.commitment_id,
                &notice.lane_id,
                &notice.signer_id,
            )?;
        }
        for (claim_id, claim) in &self.rebate_claims {
            if claim_id != &claim.claim_id {
                return Err("fee rebate claim map key mismatch".to_string());
            }
            claim.validate()?;
            if !self.commitments.contains_key(&claim.commitment_id) {
                return Err("fee rebate claim references unknown commitment".to_string());
            }
        }
        for (challenge_id, challenge) in &self.challenges {
            if challenge_id != &challenge.challenge_id {
                return Err("missed SLA challenge map key mismatch".to_string());
            }
            challenge.validate()?;
            self.ensure_commitment_lane_signer(
                &challenge.commitment_id,
                &challenge.lane_id,
                &challenge.signer_id,
            )?;
        }
        for (receipt_id, receipt) in &self.receipts {
            if receipt_id != &receipt.receipt_id {
                return Err("recovery receipt map key mismatch".to_string());
            }
            receipt.validate()?;
            self.ensure_commitment_lane_signer(
                &receipt.commitment_id,
                &receipt.lane_id,
                &receipt.signer_id,
            )?;
            if !receipt_nullifiers.insert(receipt.receipt_nullifier_root.clone()) {
                return Err("duplicate recovery receipt nullifier in state".to_string());
            }
            if !receipt.fee_rebate_claim_id.is_empty()
                && !self
                    .rebate_claims
                    .contains_key(&receipt.fee_rebate_claim_id)
            {
                return Err("recovery receipt references unknown fee rebate claim".to_string());
            }
        }
        for (slash_id, slash) in &self.slashing_records {
            if slash_id != &slash.slash_id {
                return Err("slashing record map key mismatch".to_string());
            }
            slash.validate()?;
            if !self.signers.contains_key(&slash.signer_id)
                || !self.challenges.contains_key(&slash.challenge_id)
            {
                return Err("slashing record references unknown signer or challenge".to_string());
            }
        }
        if commitment_nullifiers != self.commitment_nullifiers {
            return Err("commitment nullifier index is out of sync".to_string());
        }
        if receipt_nullifiers != self.receipt_nullifiers {
            return Err("receipt nullifier index is out of sync".to_string());
        }
        Ok(())
    }

    fn ensure_commitment_lane_signer(
        &self,
        commitment_id: &str,
        lane_id: &str,
        signer_id: &str,
    ) -> PrivateFastPathRecoveryBondsResult<()> {
        let commitment = self
            .commitments
            .get(commitment_id)
            .ok_or_else(|| "record references unknown lane commitment".to_string())?;
        if commitment.lane_id != lane_id || commitment.signer_id != signer_id {
            return Err("record lane or signer does not match commitment".to_string());
        }
        if !self.lanes.contains_key(lane_id) || !self.signers.contains_key(signer_id) {
            return Err("record references unknown lane or signer".to_string());
        }
        Ok(())
    }
}

pub fn private_fast_path_recovery_bonds_devnet(
) -> PrivateFastPathRecoveryBondsResult<PrivateFastPathRecoveryBondsState> {
    PrivateFastPathRecoveryBondsState::devnet()
}

pub fn private_fast_path_recovery_bonds_payload_root(label: &str, payload: &Value) -> String {
    recovery_bonds_hash(label, &[HashPart::Json(payload)])
}

pub fn private_fast_path_recovery_bonds_metadata_root(
    label: &str,
    metadata: &BTreeMap<String, String>,
) -> String {
    recovery_bonds_hash(
        "METADATA",
        &[HashPart::Str(label), HashPart::Json(&json!(metadata))],
    )
}

fn map_merkle_root<I>(domain: &str, values: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let leaves = values.into_iter().collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn recovery_bonds_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    let namespaced_domain = format!("PRIVATE-FAST-PATH-RECOVERY-BONDS-{domain}");
    domain_hash(&namespaced_domain, parts, 32)
}
