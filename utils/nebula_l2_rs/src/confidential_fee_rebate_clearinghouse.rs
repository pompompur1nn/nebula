use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, HashPart},
    CHAIN_ID,
};

pub type ConfidentialFeeRebateClearinghouseResult<T> = Result<T, String>;

pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_PROTOCOL_VERSION: &str =
    "nebula-confidential-fee-rebate-clearinghouse-v1";
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEVNET_HEIGHT: u64 = 192;
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEVNET_REBATE_ASSET_ID: &str = "wxmr-devnet";
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_PQ_AUTH_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-sponsor-auth-v1";
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_USAGE_COMMITMENT_SCHEME: &str =
    "zk-fee-usage-nullifier-commitment-v1";
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_REBATE_NOTE_SCHEME: &str =
    "shielded-rebate-note-commitment-v1";
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_SPONSOR_POOL_SCHEME: &str =
    "private-sponsor-pool-accounting-v1";
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_CLEARING_BATCH_SCHEME: &str =
    "deterministic-confidential-fee-clearing-batch-v1";
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEFAULT_CLAIM_TTL_BLOCKS: u64 = 2_160;
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEFAULT_SETTLEMENT_DELAY_BLOCKS: u64 = 8;
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 256;
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEFAULT_MAX_REBATE_BPS: u64 = 9_500;
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEFAULT_STANDARD_REBATE_BPS: u64 = 5_000;
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEFAULT_PRIORITY_REBATE_BPS: u64 = 7_500;
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEFAULT_EMERGENCY_REBATE_BPS: u64 = 9_000;
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEFAULT_BASE_POOL_UNITS: u64 = 500_000;
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEFAULT_MAX_CLAIMS_PER_EPOCH: usize = 131_072;
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEFAULT_MAX_BATCH_CLAIMS: usize = 8_192;
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_MAX_BPS: u64 = 10_000;
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_MAX_LANES: usize = 256;
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_MAX_POOLS: usize = 65_536;
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_MAX_EPOCHS: usize = 65_536;
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_MAX_USAGE_COMMITMENTS: usize = 524_288;
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_MAX_REBATE_CLAIMS: usize = 524_288;
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_MAX_BATCHES: usize = 262_144;
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_MAX_ATTESTATIONS: usize = 262_144;
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_MAX_ABUSE_SIGNALS: usize = 131_072;
pub const CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_MAX_EVENTS: usize = 524_288;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateLaneKind {
    PrivateTransfer,
    MoneroBridgeExit,
    MoneroBridgeEntry,
    PrivateContractCall,
    TokenMint,
    TokenSwap,
    LendingAction,
    DerivativesAction,
    ProofJob,
    WalletRecovery,
    EmergencyExit,
}

impl RebateLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::MoneroBridgeEntry => "monero_bridge_entry",
            Self::PrivateContractCall => "private_contract_call",
            Self::TokenMint => "token_mint",
            Self::TokenSwap => "token_swap",
            Self::LendingAction => "lending_action",
            Self::DerivativesAction => "derivatives_action",
            Self::ProofJob => "proof_job",
            Self::WalletRecovery => "wallet_recovery",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn default_priority_weight(self) -> u64 {
        match self {
            Self::EmergencyExit => 100,
            Self::WalletRecovery => 95,
            Self::MoneroBridgeExit | Self::MoneroBridgeEntry => 88,
            Self::PrivateTransfer => 80,
            Self::ProofJob => 74,
            Self::PrivateContractCall => 68,
            Self::TokenSwap => 62,
            Self::LendingAction | Self::DerivativesAction => 58,
            Self::TokenMint => 52,
        }
    }

    pub fn default_rebate_bps(self, config: &ConfidentialFeeRebateClearinghouseConfig) -> u64 {
        match self {
            Self::EmergencyExit | Self::WalletRecovery => config.emergency_rebate_bps,
            Self::MoneroBridgeExit | Self::MoneroBridgeEntry | Self::ProofJob => {
                config.priority_rebate_bps
            }
            _ => config.standard_rebate_bps,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorPoolStatus {
    Active,
    Replenishing,
    Exhausted,
    Paused,
    Slashed,
    Retired,
}

impl SponsorPoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Replenishing => "replenishing",
            Self::Exhausted => "exhausted",
            Self::Paused => "paused",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn can_sponsor(self) -> bool {
        matches!(self, Self::Active | Self::Replenishing)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateEpochStatus {
    Scheduled,
    Open,
    Sealing,
    Settling,
    Settled,
    Disputed,
    Expired,
}

impl RebateEpochStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Open => "open",
            Self::Sealing => "sealing",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_claims(self) -> bool {
        matches!(self, Self::Open)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageCommitmentStatus {
    Observed,
    Eligible,
    Claimed,
    Settled,
    Rejected,
    Expired,
}

impl UsageCommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Eligible => "eligible",
            Self::Claimed => "claimed",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn claimable(self) -> bool {
        matches!(self, Self::Observed | Self::Eligible)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateClaimStatus {
    Submitted,
    PrivacyChecked,
    Sponsored,
    Batched,
    Settling,
    Settled,
    Challenged,
    Rejected,
    Expired,
}

impl RebateClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::PrivacyChecked => "privacy_checked",
            Self::Sponsored => "sponsored",
            Self::Batched => "batched",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn open(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::PrivacyChecked | Self::Sponsored | Self::Batched
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyBucketKind {
    Tiny,
    Small,
    Medium,
    Large,
    Whale,
    Emergency,
}

impl PrivacyBucketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tiny => "tiny",
            Self::Small => "small",
            Self::Medium => "medium",
            Self::Large => "large",
            Self::Whale => "whale",
            Self::Emergency => "emergency",
        }
    }

    pub fn minimum_set_size(self, config: &ConfidentialFeeRebateClearinghouseConfig) -> u64 {
        match self {
            Self::Tiny | Self::Small => config.min_privacy_set_size,
            Self::Medium => config.min_privacy_set_size.saturating_mul(2),
            Self::Large => config.min_privacy_set_size.saturating_mul(4),
            Self::Whale => config.min_privacy_set_size.saturating_mul(8),
            Self::Emergency => config.min_privacy_set_size / 2,
        }
        .max(32)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingBatchStatus {
    Draft,
    Committed,
    Revealing,
    Settling,
    Settled,
    Disputed,
    RolledBack,
}

impl ClearingBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Committed => "committed",
            Self::Revealing => "revealing",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::RolledBack => "rolled_back",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialFeeRebateClearinghouseConfig {
    pub chain_id: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub protocol_version: String,
    pub hash_suite: String,
    pub pq_authorization_suite: String,
    pub usage_commitment_scheme: String,
    pub rebate_note_scheme: String,
    pub sponsor_pool_scheme: String,
    pub clearing_batch_scheme: String,
    pub epoch_blocks: u64,
    pub claim_ttl_blocks: u64,
    pub settlement_delay_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_rebate_bps: u64,
    pub standard_rebate_bps: u64,
    pub priority_rebate_bps: u64,
    pub emergency_rebate_bps: u64,
    pub base_pool_units: u64,
    pub max_claims_per_epoch: usize,
    pub max_batch_claims: usize,
}

impl ConfidentialFeeRebateClearinghouseConfig {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            fee_asset_id: CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEVNET_FEE_ASSET_ID.to_string(),
            rebate_asset_id: CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEVNET_REBATE_ASSET_ID
                .to_string(),
            protocol_version: CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_PROTOCOL_VERSION.to_string(),
            hash_suite: CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_HASH_SUITE.to_string(),
            pq_authorization_suite: CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_PQ_AUTH_SUITE.to_string(),
            usage_commitment_scheme: CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_USAGE_COMMITMENT_SCHEME
                .to_string(),
            rebate_note_scheme: CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_REBATE_NOTE_SCHEME
                .to_string(),
            sponsor_pool_scheme: CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_SPONSOR_POOL_SCHEME
                .to_string(),
            clearing_batch_scheme: CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_CLEARING_BATCH_SCHEME
                .to_string(),
            epoch_blocks: CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEFAULT_EPOCH_BLOCKS,
            claim_ttl_blocks: CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEFAULT_CLAIM_TTL_BLOCKS,
            settlement_delay_blocks:
                CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEFAULT_SETTLEMENT_DELAY_BLOCKS,
            min_privacy_set_size:
                CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_rebate_bps: CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEFAULT_MAX_REBATE_BPS,
            standard_rebate_bps: CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEFAULT_STANDARD_REBATE_BPS,
            priority_rebate_bps: CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEFAULT_PRIORITY_REBATE_BPS,
            emergency_rebate_bps:
                CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEFAULT_EMERGENCY_REBATE_BPS,
            base_pool_units: CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEFAULT_BASE_POOL_UNITS,
            max_claims_per_epoch:
                CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEFAULT_MAX_CLAIMS_PER_EPOCH,
            max_batch_claims: CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEFAULT_MAX_BATCH_CLAIMS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "protocol_version": self.protocol_version,
            "hash_suite": self.hash_suite,
            "pq_authorization_suite": self.pq_authorization_suite,
            "usage_commitment_scheme": self.usage_commitment_scheme,
            "rebate_note_scheme": self.rebate_note_scheme,
            "sponsor_pool_scheme": self.sponsor_pool_scheme,
            "clearing_batch_scheme": self.clearing_batch_scheme,
            "epoch_blocks": self.epoch_blocks,
            "claim_ttl_blocks": self.claim_ttl_blocks,
            "settlement_delay_blocks": self.settlement_delay_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_rebate_bps": self.max_rebate_bps,
            "standard_rebate_bps": self.standard_rebate_bps,
            "priority_rebate_bps": self.priority_rebate_bps,
            "emergency_rebate_bps": self.emergency_rebate_bps,
            "base_pool_units": self.base_pool_units,
            "max_claims_per_epoch": self.max_claims_per_epoch,
            "max_batch_claims": self.max_batch_claims,
        })
    }

    pub fn validate(&self) -> ConfidentialFeeRebateClearinghouseResult<()> {
        if self.chain_id != CHAIN_ID {
            return Err("confidential fee rebate clearinghouse chain id mismatch".to_string());
        }
        if self.epoch_blocks == 0 {
            return Err(
                "confidential fee rebate clearinghouse epoch blocks must be non-zero".to_string(),
            );
        }
        if self.claim_ttl_blocks < self.settlement_delay_blocks {
            return Err(
                "confidential fee rebate claim ttl must cover settlement delay".to_string(),
            );
        }
        if self.max_rebate_bps > CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_MAX_BPS {
            return Err("confidential fee rebate max rebate bps exceeds denominator".to_string());
        }
        if self.standard_rebate_bps > self.max_rebate_bps
            || self.priority_rebate_bps > self.max_rebate_bps
            || self.emergency_rebate_bps > self.max_rebate_bps
        {
            return Err(
                "confidential fee rebate lane rebate bps exceeds configured max".to_string(),
            );
        }
        if self.min_pq_security_bits < 128 {
            return Err("confidential fee rebate pq security bits too low".to_string());
        }
        if self.max_batch_claims == 0 || self.max_claims_per_epoch == 0 {
            return Err("confidential fee rebate claim limits must be non-zero".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebateLane {
    pub lane_id: String,
    pub kind: RebateLaneKind,
    pub display_name: String,
    pub sponsor_pool_ids: BTreeSet<String>,
    pub base_rebate_bps: u64,
    pub max_fee_units: u64,
    pub priority_weight: u64,
    pub min_privacy_set_size: u64,
    pub active: bool,
}

impl RebateLane {
    pub fn new(
        lane_id: impl Into<String>,
        kind: RebateLaneKind,
        config: &ConfidentialFeeRebateClearinghouseConfig,
    ) -> Self {
        let lane_id = lane_id.into();
        let display_name = kind.as_str().replace('_', " ");
        Self {
            lane_id,
            kind,
            display_name,
            sponsor_pool_ids: BTreeSet::new(),
            base_rebate_bps: kind.default_rebate_bps(config),
            max_fee_units: match kind {
                RebateLaneKind::EmergencyExit => 20_000,
                RebateLaneKind::WalletRecovery => 12_000,
                RebateLaneKind::MoneroBridgeExit | RebateLaneKind::MoneroBridgeEntry => 9_500,
                RebateLaneKind::ProofJob => 8_000,
                RebateLaneKind::PrivateContractCall => 6_500,
                _ => 4_500,
            },
            priority_weight: kind.default_priority_weight(),
            min_privacy_set_size: config.min_privacy_set_size,
            active: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "display_name": self.display_name,
            "sponsor_pool_ids": self.sponsor_pool_ids.iter().cloned().collect::<Vec<_>>(),
            "base_rebate_bps": self.base_rebate_bps,
            "max_fee_units": self.max_fee_units,
            "priority_weight": self.priority_weight,
            "min_privacy_set_size": self.min_privacy_set_size,
            "active": self.active,
        })
    }

    pub fn validate(
        &self,
        config: &ConfidentialFeeRebateClearinghouseConfig,
    ) -> ConfidentialFeeRebateClearinghouseResult<()> {
        if self.lane_id.is_empty() {
            return Err("confidential fee rebate lane id must not be empty".to_string());
        }
        if self.base_rebate_bps > config.max_rebate_bps {
            return Err(format!(
                "confidential fee rebate lane {} exceeds max rebate",
                self.lane_id
            ));
        }
        if self.min_privacy_set_size < 32 {
            return Err(format!(
                "confidential fee rebate lane {} privacy set is too small",
                self.lane_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorPool {
    pub pool_id: String,
    pub sponsor_commitment: String,
    pub lane_ids: BTreeSet<String>,
    pub status: SponsorPoolStatus,
    pub available_units: u64,
    pub reserved_units: u64,
    pub settled_units: u64,
    pub slashed_units: u64,
    pub replenishment_root: String,
    pub pq_authorization_root: String,
    pub min_pq_security_bits: u16,
    pub created_height: u64,
    pub updated_height: u64,
}

impl SponsorPool {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "sponsor_commitment": self.sponsor_commitment,
            "lane_ids": self.lane_ids.iter().cloned().collect::<Vec<_>>(),
            "status": self.status.as_str(),
            "available_units": self.available_units,
            "reserved_units": self.reserved_units,
            "settled_units": self.settled_units,
            "slashed_units": self.slashed_units,
            "replenishment_root": self.replenishment_root,
            "pq_authorization_root": self.pq_authorization_root,
            "min_pq_security_bits": self.min_pq_security_bits,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }

    pub fn total_accounted_units(&self) -> u64 {
        self.available_units
            .saturating_add(self.reserved_units)
            .saturating_add(self.settled_units)
            .saturating_add(self.slashed_units)
    }

    pub fn validate(
        &self,
        config: &ConfidentialFeeRebateClearinghouseConfig,
    ) -> ConfidentialFeeRebateClearinghouseResult<()> {
        if self.pool_id.is_empty() {
            return Err("confidential fee rebate sponsor pool id must not be empty".to_string());
        }
        if self.sponsor_commitment.is_empty() {
            return Err(format!(
                "confidential fee rebate pool {} sponsor commitment missing",
                self.pool_id
            ));
        }
        if self.min_pq_security_bits < config.min_pq_security_bits {
            return Err(format!(
                "confidential fee rebate pool {} pq security too low",
                self.pool_id
            ));
        }
        if !self.status.can_sponsor() && self.reserved_units > 0 {
            return Err(format!(
                "confidential fee rebate pool {} has inactive reserved units",
                self.pool_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebateEpoch {
    pub epoch_id: String,
    pub status: RebateEpochStatus,
    pub start_height: u64,
    pub end_height: u64,
    pub claim_deadline_height: u64,
    pub lane_ids: BTreeSet<String>,
    pub usage_commitment_root: String,
    pub claim_root: String,
    pub settled_batch_root: String,
    pub target_privacy_set_size: u64,
    pub max_claim_count: usize,
}

impl RebateEpoch {
    pub fn public_record(&self) -> Value {
        json!({
            "epoch_id": self.epoch_id,
            "status": self.status.as_str(),
            "start_height": self.start_height,
            "end_height": self.end_height,
            "claim_deadline_height": self.claim_deadline_height,
            "lane_ids": self.lane_ids.iter().cloned().collect::<Vec<_>>(),
            "usage_commitment_root": self.usage_commitment_root,
            "claim_root": self.claim_root,
            "settled_batch_root": self.settled_batch_root,
            "target_privacy_set_size": self.target_privacy_set_size,
            "max_claim_count": self.max_claim_count,
        })
    }

    pub fn contains_height(&self, height: u64) -> bool {
        self.start_height <= height && height <= self.end_height
    }

    pub fn validate(
        &self,
        config: &ConfidentialFeeRebateClearinghouseConfig,
    ) -> ConfidentialFeeRebateClearinghouseResult<()> {
        if self.epoch_id.is_empty() {
            return Err("confidential fee rebate epoch id must not be empty".to_string());
        }
        if self.start_height >= self.end_height {
            return Err(format!(
                "confidential fee rebate epoch {} invalid height range",
                self.epoch_id
            ));
        }
        if self.claim_deadline_height < self.end_height {
            return Err(format!(
                "confidential fee rebate epoch {} claim deadline before end",
                self.epoch_id
            ));
        }
        if self.target_privacy_set_size < config.min_privacy_set_size {
            return Err(format!(
                "confidential fee rebate epoch {} target privacy set too small",
                self.epoch_id
            ));
        }
        if self.max_claim_count == 0 || self.max_claim_count > config.max_claims_per_epoch {
            return Err(format!(
                "confidential fee rebate epoch {} claim count limit invalid",
                self.epoch_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeUsageCommitment {
    pub usage_id: String,
    pub epoch_id: String,
    pub lane_id: String,
    pub fee_nullifier: String,
    pub user_commitment: String,
    pub fee_amount_bucket: PrivacyBucketKind,
    pub observed_fee_units: u64,
    pub eligible_rebate_units: u64,
    pub privacy_set_size: u64,
    pub status: UsageCommitmentStatus,
    pub observed_height: u64,
    pub expires_height: u64,
}

impl FeeUsageCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "usage_id": self.usage_id,
            "epoch_id": self.epoch_id,
            "lane_id": self.lane_id,
            "fee_nullifier": self.fee_nullifier,
            "user_commitment": self.user_commitment,
            "fee_amount_bucket": self.fee_amount_bucket.as_str(),
            "observed_fee_units": self.observed_fee_units,
            "eligible_rebate_units": self.eligible_rebate_units,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status.as_str(),
            "observed_height": self.observed_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn validate(
        &self,
        config: &ConfidentialFeeRebateClearinghouseConfig,
    ) -> ConfidentialFeeRebateClearinghouseResult<()> {
        if self.usage_id.is_empty() || self.fee_nullifier.is_empty() {
            return Err(
                "confidential fee rebate usage commitment ids must not be empty".to_string(),
            );
        }
        if self.eligible_rebate_units > self.observed_fee_units {
            return Err(format!(
                "confidential fee rebate usage {} rebate exceeds fee",
                self.usage_id
            ));
        }
        if self.privacy_set_size < self.fee_amount_bucket.minimum_set_size(config) {
            return Err(format!(
                "confidential fee rebate usage {} privacy set too small",
                self.usage_id
            ));
        }
        if self.observed_height >= self.expires_height {
            return Err(format!(
                "confidential fee rebate usage {} expires before observation",
                self.usage_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebateClaim {
    pub claim_id: String,
    pub usage_id: String,
    pub epoch_id: String,
    pub lane_id: String,
    pub pool_id: String,
    pub rebate_note_commitment: String,
    pub claim_nullifier: String,
    pub encrypted_recipient: String,
    pub requested_rebate_units: u64,
    pub approved_rebate_units: u64,
    pub status: RebateClaimStatus,
    pub submitted_height: u64,
    pub expires_height: u64,
}

impl RebateClaim {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "usage_id": self.usage_id,
            "epoch_id": self.epoch_id,
            "lane_id": self.lane_id,
            "pool_id": self.pool_id,
            "rebate_note_commitment": self.rebate_note_commitment,
            "claim_nullifier": self.claim_nullifier,
            "encrypted_recipient": self.encrypted_recipient,
            "requested_rebate_units": self.requested_rebate_units,
            "approved_rebate_units": self.approved_rebate_units,
            "status": self.status.as_str(),
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn validate(&self) -> ConfidentialFeeRebateClearinghouseResult<()> {
        if self.claim_id.is_empty()
            || self.usage_id.is_empty()
            || self.pool_id.is_empty()
            || self.claim_nullifier.is_empty()
        {
            return Err("confidential fee rebate claim ids must not be empty".to_string());
        }
        if self.approved_rebate_units > self.requested_rebate_units {
            return Err(format!(
                "confidential fee rebate claim {} approves too much",
                self.claim_id
            ));
        }
        if self.submitted_height >= self.expires_height {
            return Err(format!(
                "confidential fee rebate claim {} expires before submission",
                self.claim_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClearingBatch {
    pub batch_id: String,
    pub epoch_id: String,
    pub status: ClearingBatchStatus,
    pub claim_ids: BTreeSet<String>,
    pub pool_ids: BTreeSet<String>,
    pub claim_root: String,
    pub rebate_note_root: String,
    pub pool_debit_root: String,
    pub total_rebate_units: u64,
    pub fee_saved_units: u64,
    pub committed_height: u64,
    pub settle_after_height: u64,
}

impl ClearingBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "epoch_id": self.epoch_id,
            "status": self.status.as_str(),
            "claim_ids": self.claim_ids.iter().cloned().collect::<Vec<_>>(),
            "pool_ids": self.pool_ids.iter().cloned().collect::<Vec<_>>(),
            "claim_root": self.claim_root,
            "rebate_note_root": self.rebate_note_root,
            "pool_debit_root": self.pool_debit_root,
            "total_rebate_units": self.total_rebate_units,
            "fee_saved_units": self.fee_saved_units,
            "committed_height": self.committed_height,
            "settle_after_height": self.settle_after_height,
        })
    }

    pub fn validate(
        &self,
        config: &ConfidentialFeeRebateClearinghouseConfig,
    ) -> ConfidentialFeeRebateClearinghouseResult<()> {
        if self.batch_id.is_empty() {
            return Err("confidential fee rebate batch id must not be empty".to_string());
        }
        if self.claim_ids.is_empty() {
            return Err(format!(
                "confidential fee rebate batch {} has no claims",
                self.batch_id
            ));
        }
        if self.claim_ids.len() > config.max_batch_claims {
            return Err(format!(
                "confidential fee rebate batch {} exceeds max claims",
                self.batch_id
            ));
        }
        if self.settle_after_height < self.committed_height {
            return Err(format!(
                "confidential fee rebate batch {} settles before commit",
                self.batch_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSponsorAttestation {
    pub attestation_id: String,
    pub pool_id: String,
    pub sponsor_commitment: String,
    pub pq_key_commitment: String,
    pub signature_commitment: String,
    pub security_bits: u16,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub revoked: bool,
}

impl PqSponsorAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "pool_id": self.pool_id,
            "sponsor_commitment": self.sponsor_commitment,
            "pq_key_commitment": self.pq_key_commitment,
            "signature_commitment": self.signature_commitment,
            "security_bits": self.security_bits,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "revoked": self.revoked,
        })
    }

    pub fn validate(
        &self,
        config: &ConfidentialFeeRebateClearinghouseConfig,
    ) -> ConfidentialFeeRebateClearinghouseResult<()> {
        if self.attestation_id.is_empty() || self.pool_id.is_empty() {
            return Err(
                "confidential fee rebate sponsor attestation ids must not be empty".to_string(),
            );
        }
        if self.security_bits < config.min_pq_security_bits {
            return Err(format!(
                "confidential fee rebate attestation {} pq security too low",
                self.attestation_id
            ));
        }
        if self.valid_from_height >= self.valid_until_height {
            return Err(format!(
                "confidential fee rebate attestation {} invalid validity range",
                self.attestation_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbuseSignal {
    pub signal_id: String,
    pub lane_id: String,
    pub epoch_id: String,
    pub nullifier_root: String,
    pub reason_code: String,
    pub severity_score: u64,
    pub opened_height: u64,
    pub resolved_height: Option<u64>,
}

impl AbuseSignal {
    pub fn public_record(&self) -> Value {
        json!({
            "signal_id": self.signal_id,
            "lane_id": self.lane_id,
            "epoch_id": self.epoch_id,
            "nullifier_root": self.nullifier_root,
            "reason_code": self.reason_code,
            "severity_score": self.severity_score,
            "opened_height": self.opened_height,
            "resolved_height": self.resolved_height,
        })
    }

    pub fn validate(&self) -> ConfidentialFeeRebateClearinghouseResult<()> {
        if self.signal_id.is_empty() || self.nullifier_root.is_empty() {
            return Err("confidential fee rebate abuse signal ids must not be empty".to_string());
        }
        if self.severity_score > 100 {
            return Err(format!(
                "confidential fee rebate abuse signal {} severity too high",
                self.signal_id
            ));
        }
        if let Some(resolved_height) = self.resolved_height {
            if resolved_height < self.opened_height {
                return Err(format!(
                    "confidential fee rebate abuse signal {} resolves before open",
                    self.signal_id
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClearingEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub event_height: u64,
    pub event_root: String,
}

impl ClearingEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "event_height": self.event_height,
            "event_root": self.event_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialFeeRebateClearinghouseRoots {
    pub config_root: String,
    pub lane_root: String,
    pub sponsor_pool_root: String,
    pub epoch_root: String,
    pub usage_commitment_root: String,
    pub rebate_claim_root: String,
    pub clearing_batch_root: String,
    pub pq_attestation_root: String,
    pub abuse_signal_root: String,
    pub event_root: String,
}

impl ConfidentialFeeRebateClearinghouseRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "sponsor_pool_root": self.sponsor_pool_root,
            "epoch_root": self.epoch_root,
            "usage_commitment_root": self.usage_commitment_root,
            "rebate_claim_root": self.rebate_claim_root,
            "clearing_batch_root": self.clearing_batch_root,
            "pq_attestation_root": self.pq_attestation_root,
            "abuse_signal_root": self.abuse_signal_root,
            "event_root": self.event_root,
        })
    }

    pub fn state_root(&self) -> String {
        hash32(
            "confidential_fee_rebate_clearinghouse_roots",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialFeeRebateClearinghouseCounters {
    pub lane_count: u64,
    pub active_lane_count: u64,
    pub sponsor_pool_count: u64,
    pub active_sponsor_pool_count: u64,
    pub epoch_count: u64,
    pub open_epoch_count: u64,
    pub usage_commitment_count: u64,
    pub claimable_usage_count: u64,
    pub rebate_claim_count: u64,
    pub open_claim_count: u64,
    pub clearing_batch_count: u64,
    pub unsettled_batch_count: u64,
    pub pq_attestation_count: u64,
    pub active_pq_attestation_count: u64,
    pub abuse_signal_count: u64,
    pub unresolved_abuse_signal_count: u64,
    pub event_count: u64,
    pub total_available_sponsor_units: u64,
    pub total_reserved_sponsor_units: u64,
    pub total_settled_rebate_units: u64,
    pub total_fee_saved_units: u64,
}

impl ConfidentialFeeRebateClearinghouseCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_count": self.lane_count,
            "active_lane_count": self.active_lane_count,
            "sponsor_pool_count": self.sponsor_pool_count,
            "active_sponsor_pool_count": self.active_sponsor_pool_count,
            "epoch_count": self.epoch_count,
            "open_epoch_count": self.open_epoch_count,
            "usage_commitment_count": self.usage_commitment_count,
            "claimable_usage_count": self.claimable_usage_count,
            "rebate_claim_count": self.rebate_claim_count,
            "open_claim_count": self.open_claim_count,
            "clearing_batch_count": self.clearing_batch_count,
            "unsettled_batch_count": self.unsettled_batch_count,
            "pq_attestation_count": self.pq_attestation_count,
            "active_pq_attestation_count": self.active_pq_attestation_count,
            "abuse_signal_count": self.abuse_signal_count,
            "unresolved_abuse_signal_count": self.unresolved_abuse_signal_count,
            "event_count": self.event_count,
            "total_available_sponsor_units": self.total_available_sponsor_units,
            "total_reserved_sponsor_units": self.total_reserved_sponsor_units,
            "total_settled_rebate_units": self.total_settled_rebate_units,
            "total_fee_saved_units": self.total_fee_saved_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialFeeRebateClearinghouseState {
    pub config: ConfidentialFeeRebateClearinghouseConfig,
    pub height: u64,
    pub lanes: BTreeMap<String, RebateLane>,
    pub sponsor_pools: BTreeMap<String, SponsorPool>,
    pub epochs: BTreeMap<String, RebateEpoch>,
    pub usage_commitments: BTreeMap<String, FeeUsageCommitment>,
    pub rebate_claims: BTreeMap<String, RebateClaim>,
    pub clearing_batches: BTreeMap<String, ClearingBatch>,
    pub pq_attestations: BTreeMap<String, PqSponsorAttestation>,
    pub abuse_signals: BTreeMap<String, AbuseSignal>,
    pub events: BTreeMap<String, ClearingEvent>,
}

impl ConfidentialFeeRebateClearinghouseState {
    pub fn devnet() -> ConfidentialFeeRebateClearinghouseResult<Self> {
        let config = ConfidentialFeeRebateClearinghouseConfig::devnet();
        let height = CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_DEVNET_HEIGHT;
        let mut lanes = BTreeMap::new();
        for (lane_id, kind) in [
            ("lane-private-transfer", RebateLaneKind::PrivateTransfer),
            ("lane-monero-exit", RebateLaneKind::MoneroBridgeExit),
            ("lane-monero-entry", RebateLaneKind::MoneroBridgeEntry),
            ("lane-contract-call", RebateLaneKind::PrivateContractCall),
            ("lane-token-swap", RebateLaneKind::TokenSwap),
            ("lane-proof-job", RebateLaneKind::ProofJob),
            ("lane-wallet-recovery", RebateLaneKind::WalletRecovery),
            ("lane-emergency-exit", RebateLaneKind::EmergencyExit),
        ] {
            lanes.insert(lane_id.to_string(), RebateLane::new(lane_id, kind, &config));
        }

        let mut sponsor_pools = BTreeMap::new();
        for index in 0..4 {
            let pool_id = format!("sponsor-pool-devnet-{index}");
            let mut lane_ids = BTreeSet::new();
            for lane_id in lanes.keys().skip(index).step_by(2) {
                lane_ids.insert(lane_id.clone());
            }
            if lane_ids.is_empty() {
                lane_ids.insert("lane-private-transfer".to_string());
            }
            for lane_id in &lane_ids {
                if let Some(lane) = lanes.get_mut(lane_id) {
                    lane.sponsor_pool_ids.insert(pool_id.clone());
                }
            }
            sponsor_pools.insert(
                pool_id.clone(),
                SponsorPool {
                    sponsor_commitment: hash32(
                        "confidential_fee_rebate_sponsor_commitment",
                        &[HashPart::Str(&pool_id)],
                    ),
                    lane_ids,
                    status: if index == 3 {
                        SponsorPoolStatus::Replenishing
                    } else {
                        SponsorPoolStatus::Active
                    },
                    available_units: config.base_pool_units.saturating_mul((index + 1) as u64),
                    reserved_units: 12_500_u64.saturating_mul(index as u64),
                    settled_units: 42_000_u64.saturating_mul(index as u64),
                    slashed_units: 0,
                    replenishment_root: hash32(
                        "confidential_fee_rebate_replenishment_root",
                        &[HashPart::Str(&pool_id), HashPart::Int((height) as i128)],
                    ),
                    pq_authorization_root: hash32(
                        "confidential_fee_rebate_pq_authorization_root",
                        &[HashPart::Str(&pool_id)],
                    ),
                    min_pq_security_bits: config.min_pq_security_bits,
                    created_height: height.saturating_sub(96),
                    updated_height: height,
                    pool_id,
                },
            );
        }

        let mut epochs = BTreeMap::new();
        for epoch_index in 0..3 {
            let epoch_id = format!("rebate-epoch-devnet-{epoch_index}");
            let start_height = height.saturating_sub(config.epoch_blocks * (2 - epoch_index));
            let end_height = start_height.saturating_add(config.epoch_blocks - 1);
            epochs.insert(
                epoch_id.clone(),
                RebateEpoch {
                    status: if epoch_index == 2 {
                        RebateEpochStatus::Open
                    } else {
                        RebateEpochStatus::Settled
                    },
                    start_height,
                    end_height,
                    claim_deadline_height: end_height.saturating_add(config.claim_ttl_blocks),
                    lane_ids: lanes.keys().cloned().collect(),
                    usage_commitment_root: hash32(
                        "confidential_fee_rebate_epoch_usage_root",
                        &[HashPart::Str(&epoch_id)],
                    ),
                    claim_root: hash32(
                        "confidential_fee_rebate_epoch_claim_root",
                        &[HashPart::Str(&epoch_id)],
                    ),
                    settled_batch_root: hash32(
                        "confidential_fee_rebate_epoch_settled_batch_root",
                        &[HashPart::Str(&epoch_id)],
                    ),
                    target_privacy_set_size: config.min_privacy_set_size * 4,
                    max_claim_count: config.max_claims_per_epoch,
                    epoch_id,
                },
            );
        }

        let active_epoch_id = "rebate-epoch-devnet-2".to_string();
        let mut usage_commitments = BTreeMap::new();
        let lane_keys = lanes.keys().cloned().collect::<Vec<_>>();
        for index in 0..24 {
            let lane_id = lane_keys[index % lane_keys.len()].clone();
            let usage_id = format!("fee-usage-devnet-{index:03}");
            let observed_fee_units = 500 + (index as u64 * 37);
            let eligible_rebate_units = observed_fee_units / 2;
            usage_commitments.insert(
                usage_id.clone(),
                FeeUsageCommitment {
                    epoch_id: active_epoch_id.clone(),
                    lane_id,
                    fee_nullifier: hash32(
                        "confidential_fee_rebate_fee_nullifier",
                        &[HashPart::Str(&usage_id)],
                    ),
                    user_commitment: hash32(
                        "confidential_fee_rebate_user_commitment",
                        &[HashPart::Str(&usage_id)],
                    ),
                    fee_amount_bucket: match index % 5 {
                        0 => PrivacyBucketKind::Tiny,
                        1 => PrivacyBucketKind::Small,
                        2 => PrivacyBucketKind::Medium,
                        3 => PrivacyBucketKind::Large,
                        _ => PrivacyBucketKind::Emergency,
                    },
                    observed_fee_units,
                    eligible_rebate_units,
                    privacy_set_size: config.min_privacy_set_size * (2 + (index % 4) as u64),
                    status: if index < 16 {
                        UsageCommitmentStatus::Eligible
                    } else {
                        UsageCommitmentStatus::Observed
                    },
                    observed_height: height.saturating_sub(24 - index as u64),
                    expires_height: height.saturating_add(config.claim_ttl_blocks),
                    usage_id,
                },
            );
        }

        let pool_keys = sponsor_pools.keys().cloned().collect::<Vec<_>>();
        let mut rebate_claims = BTreeMap::new();
        for (index, usage) in usage_commitments.values().take(14).enumerate() {
            let claim_id = format!("rebate-claim-devnet-{index:03}");
            rebate_claims.insert(
                claim_id.clone(),
                RebateClaim {
                    usage_id: usage.usage_id.clone(),
                    epoch_id: usage.epoch_id.clone(),
                    lane_id: usage.lane_id.clone(),
                    pool_id: pool_keys[index % pool_keys.len()].clone(),
                    rebate_note_commitment: hash32(
                        "confidential_fee_rebate_note_commitment",
                        &[HashPart::Str(&claim_id)],
                    ),
                    claim_nullifier: hash32(
                        "confidential_fee_rebate_claim_nullifier",
                        &[HashPart::Str(&claim_id)],
                    ),
                    encrypted_recipient: hash32(
                        "confidential_fee_rebate_encrypted_recipient",
                        &[HashPart::Str(&claim_id)],
                    ),
                    requested_rebate_units: usage.eligible_rebate_units,
                    approved_rebate_units: usage.eligible_rebate_units.saturating_sub(index as u64),
                    status: if index < 6 {
                        RebateClaimStatus::Batched
                    } else {
                        RebateClaimStatus::PrivacyChecked
                    },
                    submitted_height: height.saturating_sub(12 - index as u64),
                    expires_height: height.saturating_add(config.claim_ttl_blocks),
                    claim_id,
                },
            );
        }

        let batched_claim_ids = rebate_claims
            .iter()
            .filter_map(|(claim_id, claim)| {
                if claim.status == RebateClaimStatus::Batched {
                    Some(claim_id.clone())
                } else {
                    None
                }
            })
            .collect::<BTreeSet<_>>();
        let batch_rebate_units = batched_claim_ids
            .iter()
            .filter_map(|claim_id| rebate_claims.get(claim_id))
            .map(|claim| claim.approved_rebate_units)
            .sum::<u64>();
        let mut clearing_batches = BTreeMap::new();
        clearing_batches.insert(
            "fee-rebate-batch-devnet-000".to_string(),
            ClearingBatch {
                batch_id: "fee-rebate-batch-devnet-000".to_string(),
                epoch_id: active_epoch_id.clone(),
                status: ClearingBatchStatus::Committed,
                claim_root: collection_root(
                    "confidential_fee_rebate_devnet_batch_claims",
                    &batched_claim_ids,
                ),
                rebate_note_root: hash32(
                    "confidential_fee_rebate_devnet_batch_notes",
                    &[HashPart::Int((batch_rebate_units) as i128)],
                ),
                pool_debit_root: collection_root(
                    "confidential_fee_rebate_devnet_batch_pools",
                    &pool_keys.iter().cloned().collect::<BTreeSet<_>>(),
                ),
                total_rebate_units: batch_rebate_units,
                fee_saved_units: batch_rebate_units,
                committed_height: height,
                settle_after_height: height.saturating_add(config.settlement_delay_blocks),
                claim_ids: batched_claim_ids,
                pool_ids: pool_keys.iter().cloned().collect(),
            },
        );

        let mut pq_attestations = BTreeMap::new();
        for pool_id in sponsor_pools.keys() {
            let attestation_id = format!("pq-sponsor-attestation-{pool_id}");
            pq_attestations.insert(
                attestation_id.clone(),
                PqSponsorAttestation {
                    pool_id: pool_id.clone(),
                    sponsor_commitment: hash32(
                        "confidential_fee_rebate_attested_sponsor",
                        &[HashPart::Str(pool_id)],
                    ),
                    pq_key_commitment: hash32(
                        "confidential_fee_rebate_pq_key_commitment",
                        &[HashPart::Str(pool_id)],
                    ),
                    signature_commitment: hash32(
                        "confidential_fee_rebate_signature_commitment",
                        &[HashPart::Str(&attestation_id)],
                    ),
                    security_bits: config.min_pq_security_bits,
                    valid_from_height: height.saturating_sub(config.epoch_blocks),
                    valid_until_height: height.saturating_add(config.epoch_blocks * 4),
                    revoked: false,
                    attestation_id,
                },
            );
        }

        let mut abuse_signals = BTreeMap::new();
        abuse_signals.insert(
            "fee-rebate-abuse-signal-devnet-000".to_string(),
            AbuseSignal {
                signal_id: "fee-rebate-abuse-signal-devnet-000".to_string(),
                lane_id: "lane-token-swap".to_string(),
                epoch_id: active_epoch_id.clone(),
                nullifier_root: hash32(
                    "confidential_fee_rebate_devnet_abuse_nullifiers",
                    &[HashPart::Str("token-swap-burst")],
                ),
                reason_code: "burst_same_bucket_nullifier_pressure".to_string(),
                severity_score: 27,
                opened_height: height.saturating_sub(3),
                resolved_height: None,
            },
        );

        let mut events = BTreeMap::new();
        for (index, subject_id) in [
            "lane-private-transfer",
            "sponsor-pool-devnet-0",
            "rebate-epoch-devnet-2",
            "fee-rebate-batch-devnet-000",
        ]
        .iter()
        .enumerate()
        {
            let event_id = format!("fee-rebate-event-devnet-{index:03}");
            events.insert(
                event_id.clone(),
                ClearingEvent {
                    event_kind: match index {
                        0 => "lane_opened",
                        1 => "pool_funded",
                        2 => "epoch_opened",
                        _ => "batch_committed",
                    }
                    .to_string(),
                    subject_id: (*subject_id).to_string(),
                    event_height: height.saturating_sub((4 - index) as u64),
                    event_root: hash32(
                        "confidential_fee_rebate_event",
                        &[HashPart::Str(&event_id), HashPart::Str(subject_id)],
                    ),
                    event_id,
                },
            );
        }

        let state = Self {
            config,
            height,
            lanes,
            sponsor_pools,
            epochs,
            usage_commitments,
            rebate_claims,
            clearing_batches,
            pq_attestations,
            abuse_signals,
            events,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> ConfidentialFeeRebateClearinghouseResult<()> {
        if height < self.height {
            return Err("confidential fee rebate clearinghouse cannot rewind height".to_string());
        }
        self.height = height;
        for epoch in self.epochs.values_mut() {
            if epoch.status == RebateEpochStatus::Open && height > epoch.end_height {
                epoch.status = RebateEpochStatus::Sealing;
            }
            if epoch.status == RebateEpochStatus::Sealing
                && height
                    >= epoch
                        .end_height
                        .saturating_add(self.config.settlement_delay_blocks)
            {
                epoch.status = RebateEpochStatus::Settling;
            }
        }
        for usage in self.usage_commitments.values_mut() {
            if usage.status.claimable() && height > usage.expires_height {
                usage.status = UsageCommitmentStatus::Expired;
            }
        }
        for claim in self.rebate_claims.values_mut() {
            if claim.status.open() && height > claim.expires_height {
                claim.status = RebateClaimStatus::Expired;
            }
        }
        for batch in self.clearing_batches.values_mut() {
            if batch.status == ClearingBatchStatus::Committed && height >= batch.settle_after_height
            {
                batch.status = ClearingBatchStatus::Settling;
            }
        }
        self.validate()
    }

    pub fn roots(&self) -> ConfidentialFeeRebateClearinghouseRoots {
        ConfidentialFeeRebateClearinghouseRoots {
            config_root: value_root(
                "confidential_fee_rebate_config",
                &self.config.public_record(),
            ),
            lane_root: map_root("confidential_fee_rebate_lanes", &self.lanes),
            sponsor_pool_root: map_root(
                "confidential_fee_rebate_sponsor_pools",
                &self.sponsor_pools,
            ),
            epoch_root: map_root("confidential_fee_rebate_epochs", &self.epochs),
            usage_commitment_root: map_root(
                "confidential_fee_rebate_usage_commitments",
                &self.usage_commitments,
            ),
            rebate_claim_root: map_root("confidential_fee_rebate_claims", &self.rebate_claims),
            clearing_batch_root: map_root(
                "confidential_fee_rebate_clearing_batches",
                &self.clearing_batches,
            ),
            pq_attestation_root: map_root(
                "confidential_fee_rebate_pq_attestations",
                &self.pq_attestations,
            ),
            abuse_signal_root: map_root(
                "confidential_fee_rebate_abuse_signals",
                &self.abuse_signals,
            ),
            event_root: map_root("confidential_fee_rebate_events", &self.events),
        }
    }

    pub fn counters(&self) -> ConfidentialFeeRebateClearinghouseCounters {
        ConfidentialFeeRebateClearinghouseCounters {
            lane_count: self.lanes.len() as u64,
            active_lane_count: self.lanes.values().filter(|lane| lane.active).count() as u64,
            sponsor_pool_count: self.sponsor_pools.len() as u64,
            active_sponsor_pool_count: self
                .sponsor_pools
                .values()
                .filter(|pool| pool.status.can_sponsor())
                .count() as u64,
            epoch_count: self.epochs.len() as u64,
            open_epoch_count: self
                .epochs
                .values()
                .filter(|epoch| epoch.status.accepts_claims())
                .count() as u64,
            usage_commitment_count: self.usage_commitments.len() as u64,
            claimable_usage_count: self
                .usage_commitments
                .values()
                .filter(|usage| usage.status.claimable())
                .count() as u64,
            rebate_claim_count: self.rebate_claims.len() as u64,
            open_claim_count: self
                .rebate_claims
                .values()
                .filter(|claim| claim.status.open())
                .count() as u64,
            clearing_batch_count: self.clearing_batches.len() as u64,
            unsettled_batch_count: self
                .clearing_batches
                .values()
                .filter(|batch| batch.status != ClearingBatchStatus::Settled)
                .count() as u64,
            pq_attestation_count: self.pq_attestations.len() as u64,
            active_pq_attestation_count: self
                .pq_attestations
                .values()
                .filter(|attestation| {
                    !attestation.revoked && self.height <= attestation.valid_until_height
                })
                .count() as u64,
            abuse_signal_count: self.abuse_signals.len() as u64,
            unresolved_abuse_signal_count: self
                .abuse_signals
                .values()
                .filter(|signal| signal.resolved_height.is_none())
                .count() as u64,
            event_count: self.events.len() as u64,
            total_available_sponsor_units: self.total_available_sponsor_units(),
            total_reserved_sponsor_units: self
                .sponsor_pools
                .values()
                .map(|pool| pool.reserved_units)
                .sum(),
            total_settled_rebate_units: self
                .clearing_batches
                .values()
                .filter(|batch| batch.status == ClearingBatchStatus::Settled)
                .map(|batch| batch.total_rebate_units)
                .sum(),
            total_fee_saved_units: self
                .clearing_batches
                .values()
                .map(|batch| batch.fee_saved_units)
                .sum(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_fee_rebate_clearinghouse",
            "protocol_version": CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "active_lane_ids": self.active_lane_ids(),
            "open_epoch_ids": self.open_epoch_ids(),
            "open_claim_ids": self.open_claim_ids(),
            "sponsor_pool_ids": self.sponsor_pools.keys().cloned().collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        confidential_fee_rebate_clearinghouse_state_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> ConfidentialFeeRebateClearinghouseResult<()> {
        self.config.validate()?;
        if self.lanes.len() > CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_MAX_LANES {
            return Err("confidential fee rebate lane limit exceeded".to_string());
        }
        if self.sponsor_pools.len() > CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_MAX_POOLS {
            return Err("confidential fee rebate sponsor pool limit exceeded".to_string());
        }
        if self.epochs.len() > CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_MAX_EPOCHS {
            return Err("confidential fee rebate epoch limit exceeded".to_string());
        }
        if self.usage_commitments.len()
            > CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_MAX_USAGE_COMMITMENTS
        {
            return Err("confidential fee rebate usage commitment limit exceeded".to_string());
        }
        if self.rebate_claims.len() > CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_MAX_REBATE_CLAIMS {
            return Err("confidential fee rebate claim limit exceeded".to_string());
        }
        if self.clearing_batches.len() > CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_MAX_BATCHES {
            return Err("confidential fee rebate batch limit exceeded".to_string());
        }
        if self.pq_attestations.len() > CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_MAX_ATTESTATIONS {
            return Err("confidential fee rebate attestation limit exceeded".to_string());
        }
        if self.abuse_signals.len() > CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_MAX_ABUSE_SIGNALS {
            return Err("confidential fee rebate abuse signal limit exceeded".to_string());
        }
        if self.events.len() > CONFIDENTIAL_FEE_REBATE_CLEARINGHOUSE_MAX_EVENTS {
            return Err("confidential fee rebate event limit exceeded".to_string());
        }
        for lane in self.lanes.values() {
            lane.validate(&self.config)?;
            for pool_id in &lane.sponsor_pool_ids {
                if !self.sponsor_pools.contains_key(pool_id) {
                    return Err(format!(
                        "confidential fee rebate lane {} references missing pool {}",
                        lane.lane_id, pool_id
                    ));
                }
            }
        }
        for pool in self.sponsor_pools.values() {
            pool.validate(&self.config)?;
            for lane_id in &pool.lane_ids {
                if !self.lanes.contains_key(lane_id) {
                    return Err(format!(
                        "confidential fee rebate pool {} references missing lane {}",
                        pool.pool_id, lane_id
                    ));
                }
            }
        }
        for epoch in self.epochs.values() {
            epoch.validate(&self.config)?;
            for lane_id in &epoch.lane_ids {
                if !self.lanes.contains_key(lane_id) {
                    return Err(format!(
                        "confidential fee rebate epoch {} references missing lane {}",
                        epoch.epoch_id, lane_id
                    ));
                }
            }
        }
        let mut fee_nullifiers = BTreeSet::new();
        for usage in self.usage_commitments.values() {
            usage.validate(&self.config)?;
            if !self.epochs.contains_key(&usage.epoch_id) {
                return Err(format!(
                    "confidential fee rebate usage {} references missing epoch",
                    usage.usage_id
                ));
            }
            if !self.lanes.contains_key(&usage.lane_id) {
                return Err(format!(
                    "confidential fee rebate usage {} references missing lane",
                    usage.usage_id
                ));
            }
            if !fee_nullifiers.insert(usage.fee_nullifier.clone()) {
                return Err(format!(
                    "confidential fee rebate duplicate fee nullifier {}",
                    usage.fee_nullifier
                ));
            }
        }
        let mut claim_nullifiers = BTreeSet::new();
        for claim in self.rebate_claims.values() {
            claim.validate()?;
            if !self.usage_commitments.contains_key(&claim.usage_id) {
                return Err(format!(
                    "confidential fee rebate claim {} references missing usage",
                    claim.claim_id
                ));
            }
            if !self.sponsor_pools.contains_key(&claim.pool_id) {
                return Err(format!(
                    "confidential fee rebate claim {} references missing pool",
                    claim.claim_id
                ));
            }
            if !claim_nullifiers.insert(claim.claim_nullifier.clone()) {
                return Err(format!(
                    "confidential fee rebate duplicate claim nullifier {}",
                    claim.claim_nullifier
                ));
            }
        }
        for batch in self.clearing_batches.values() {
            batch.validate(&self.config)?;
            for claim_id in &batch.claim_ids {
                if !self.rebate_claims.contains_key(claim_id) {
                    return Err(format!(
                        "confidential fee rebate batch {} references missing claim {}",
                        batch.batch_id, claim_id
                    ));
                }
            }
        }
        for attestation in self.pq_attestations.values() {
            attestation.validate(&self.config)?;
            if !self.sponsor_pools.contains_key(&attestation.pool_id) {
                return Err(format!(
                    "confidential fee rebate attestation {} references missing pool",
                    attestation.attestation_id
                ));
            }
        }
        for signal in self.abuse_signals.values() {
            signal.validate()?;
        }
        Ok(())
    }

    pub fn active_lane_ids(&self) -> Vec<String> {
        self.lanes
            .values()
            .filter(|lane| lane.active)
            .map(|lane| lane.lane_id.clone())
            .collect()
    }

    pub fn open_epoch_ids(&self) -> Vec<String> {
        self.epochs
            .values()
            .filter(|epoch| epoch.status.accepts_claims())
            .map(|epoch| epoch.epoch_id.clone())
            .collect()
    }

    pub fn open_claim_ids(&self) -> Vec<String> {
        self.rebate_claims
            .values()
            .filter(|claim| claim.status.open())
            .map(|claim| claim.claim_id.clone())
            .collect()
    }

    pub fn total_available_sponsor_units(&self) -> u64 {
        self.sponsor_pools
            .values()
            .map(|pool| pool.available_units)
            .sum()
    }
}

pub fn confidential_fee_rebate_clearinghouse_state_root_from_record(record: &Value) -> String {
    hash32(
        "confidential_fee_rebate_clearinghouse_state",
        &[HashPart::Json(record)],
    )
}

fn value_root(label: &str, value: &Value) -> String {
    hash32(label, &[HashPart::Json(value)])
}

fn map_root<T: Serialize>(label: &str, map: &BTreeMap<String, T>) -> String {
    let value = json!(map);
    hash32(label, &[HashPart::Json(&value)])
}

fn collection_root(label: &str, set: &BTreeSet<String>) -> String {
    let value = json!(set.iter().cloned().collect::<Vec<_>>());
    hash32(label, &[HashPart::Json(&value)])
}

fn hash32(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}
