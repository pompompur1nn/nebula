use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, HashPart};

pub type PrivateLiquidityRewardsResult<T> = Result<T, String>;

pub const PRIVATE_LIQUIDITY_REWARDS_PROTOCOL_VERSION: &str = "nebula-private-liquidity-rewards-v1";
pub const PRIVATE_LIQUIDITY_REWARDS_COMMITMENT_SCHEME: &str = "poseidon-blake3-hybrid";
pub const PRIVATE_LIQUIDITY_REWARDS_PQ_AUTH_SCHEME: &str = "ML-DSA-65+SLH-DSA-SHAKE-128s";
pub const PRIVATE_LIQUIDITY_REWARDS_PROOF_SYSTEM: &str = "zk-reward-eligibility-v1";
pub const PRIVATE_LIQUIDITY_REWARDS_DEFAULT_EPOCH_LENGTH: u64 = 720;
pub const PRIVATE_LIQUIDITY_REWARDS_DEFAULT_CLAIM_TTL: u64 = 2_880;
pub const PRIVATE_LIQUIDITY_REWARDS_DEFAULT_REBATE_TTL: u64 = 1_440;
pub const PRIVATE_LIQUIDITY_REWARDS_MAX_POOLS: usize = 128;
pub const PRIVATE_LIQUIDITY_REWARDS_MAX_EPOCHS: usize = 256;
pub const PRIVATE_LIQUIDITY_REWARDS_MAX_POSITIONS: usize = 4_096;
pub const PRIVATE_LIQUIDITY_REWARDS_MAX_COMMITMENTS: usize = 8_192;
pub const PRIVATE_LIQUIDITY_REWARDS_MAX_CLAIMS: usize = 8_192;
pub const PRIVATE_LIQUIDITY_REWARDS_MAX_REBATE_VAULTS: usize = 512;
pub const PRIVATE_LIQUIDITY_REWARDS_MAX_SPONSORS: usize = 512;
pub const PRIVATE_LIQUIDITY_REWARDS_MAX_RECEIPTS: usize = 8_192;
pub const PRIVATE_LIQUIDITY_REWARDS_MAX_EVENTS: usize = 16_384;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PrivateLiquidityRewardDomain {
    Amm,
    Lending,
    Perps,
    Stablecoin,
    BridgeInventory,
    ContractVault,
    PrivateOrderflow,
}

impl PrivateLiquidityRewardDomain {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Amm => "amm",
            Self::Lending => "lending",
            Self::Perps => "perps",
            Self::Stablecoin => "stablecoin",
            Self::BridgeInventory => "bridge_inventory",
            Self::ContractVault => "contract_vault",
            Self::PrivateOrderflow => "private_orderflow",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RewardPoolStatus {
    Active,
    Paused,
    Draining,
    Retired,
}

impl RewardPoolStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Retired => "retired",
        }
    }

    pub fn admits_new_positions(&self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RewardEpochStatus {
    Scheduled,
    Open,
    Sealed,
    Settled,
    Cancelled,
}

impl RewardEpochStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_live(&self) -> bool {
        matches!(self, Self::Scheduled | Self::Open | Self::Sealed)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LiquidityPositionStatus {
    Pending,
    Active,
    CoolingDown,
    Withdrawn,
    Slashed,
}

impl LiquidityPositionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::CoolingDown => "cooling_down",
            Self::Withdrawn => "withdrawn",
            Self::Slashed => "slashed",
        }
    }

    pub fn is_rewardable(&self) -> bool {
        matches!(self, Self::Active | Self::CoolingDown)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RewardCommitmentStatus {
    PendingProof,
    Eligible,
    Ineligible,
    Claimed,
    Expired,
}

impl RewardCommitmentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PendingProof => "pending_proof",
            Self::Eligible => "eligible",
            Self::Ineligible => "ineligible",
            Self::Claimed => "claimed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RewardClaimStatus {
    Submitted,
    Verified,
    Settled,
    Rejected,
    Expired,
}

impl RewardClaimStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Verified => "verified",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RewardSponsorStatus {
    Active,
    Throttled,
    Exhausted,
    Revoked,
}

impl RewardSponsorStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Exhausted => "exhausted",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FeeRebateVaultStatus {
    Active,
    Frozen,
    Draining,
    Empty,
}

impl FeeRebateVaultStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Frozen => "frozen",
            Self::Draining => "draining",
            Self::Empty => "empty",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RewardReceiptStatus {
    Pending,
    Posted,
    Audited,
    Disputed,
}

impl RewardReceiptStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Posted => "posted",
            Self::Audited => "audited",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RewardEventKind {
    PoolOpened,
    EpochOpened,
    PositionCommitted,
    RewardAccrued,
    ClaimVerified,
    ClaimSettled,
    RebatePosted,
    SponsorDebited,
    RiskThrottle,
}

impl RewardEventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PoolOpened => "pool_opened",
            Self::EpochOpened => "epoch_opened",
            Self::PositionCommitted => "position_committed",
            Self::RewardAccrued => "reward_accrued",
            Self::ClaimVerified => "claim_verified",
            Self::ClaimSettled => "claim_settled",
            Self::RebatePosted => "rebate_posted",
            Self::SponsorDebited => "sponsor_debited",
            Self::RiskThrottle => "risk_throttle",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateLiquidityRewardsConfig {
    pub protocol_version: String,
    pub reward_asset_id: String,
    pub fee_asset_id: String,
    pub epoch_length_blocks: u64,
    pub claim_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub min_reward_commitment_units: u64,
    pub max_reward_multiplier_bps: u64,
    pub low_fee_boost_bps: u64,
    pub privacy_preserving_audit_bps: u64,
    pub pq_auth_scheme: String,
    pub proof_system: String,
    pub commitment_scheme: String,
}

impl Default for PrivateLiquidityRewardsConfig {
    fn default() -> Self {
        Self {
            protocol_version: PRIVATE_LIQUIDITY_REWARDS_PROTOCOL_VERSION.to_string(),
            reward_asset_id: "pvt-reward-xmr-liquidity".to_string(),
            fee_asset_id: "xmr-piconero".to_string(),
            epoch_length_blocks: PRIVATE_LIQUIDITY_REWARDS_DEFAULT_EPOCH_LENGTH,
            claim_ttl_blocks: PRIVATE_LIQUIDITY_REWARDS_DEFAULT_CLAIM_TTL,
            rebate_ttl_blocks: PRIVATE_LIQUIDITY_REWARDS_DEFAULT_REBATE_TTL,
            min_reward_commitment_units: 1_000,
            max_reward_multiplier_bps: 25_000,
            low_fee_boost_bps: 1_250,
            privacy_preserving_audit_bps: 500,
            pq_auth_scheme: PRIVATE_LIQUIDITY_REWARDS_PQ_AUTH_SCHEME.to_string(),
            proof_system: PRIVATE_LIQUIDITY_REWARDS_PROOF_SYSTEM.to_string(),
            commitment_scheme: PRIVATE_LIQUIDITY_REWARDS_COMMITMENT_SCHEME.to_string(),
        }
    }
}

impl PrivateLiquidityRewardsConfig {
    pub fn validate(&self) -> PrivateLiquidityRewardsResult<()> {
        if self.protocol_version.trim().is_empty() {
            return Err("private liquidity rewards protocol version cannot be empty".to_string());
        }
        if self.reward_asset_id.trim().is_empty() {
            return Err("private liquidity rewards reward asset cannot be empty".to_string());
        }
        if self.fee_asset_id.trim().is_empty() {
            return Err("private liquidity rewards fee asset cannot be empty".to_string());
        }
        if self.epoch_length_blocks == 0 {
            return Err("private liquidity rewards epoch length must be positive".to_string());
        }
        if self.claim_ttl_blocks == 0 {
            return Err("private liquidity rewards claim ttl must be positive".to_string());
        }
        if self.rebate_ttl_blocks == 0 {
            return Err("private liquidity rewards rebate ttl must be positive".to_string());
        }
        if self.min_reward_commitment_units == 0 {
            return Err(
                "private liquidity rewards minimum commitment units must be positive".to_string(),
            );
        }
        if self.max_reward_multiplier_bps < 10_000 {
            return Err(
                "private liquidity rewards max multiplier must be at least par".to_string(),
            );
        }
        if self.privacy_preserving_audit_bps > 10_000 {
            return Err("private liquidity rewards audit bps cannot exceed 10000".to_string());
        }
        if self.pq_auth_scheme.trim().is_empty()
            || self.proof_system.trim().is_empty()
            || self.commitment_scheme.trim().is_empty()
        {
            return Err(
                "private liquidity rewards cryptographic labels cannot be empty".to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_liquidity_rewards_config",
            "protocol_version": self.protocol_version,
            "reward_asset_id": self.reward_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "epoch_length_blocks": self.epoch_length_blocks,
            "claim_ttl_blocks": self.claim_ttl_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "min_reward_commitment_units": self.min_reward_commitment_units,
            "max_reward_multiplier_bps": self.max_reward_multiplier_bps,
            "low_fee_boost_bps": self.low_fee_boost_bps,
            "privacy_preserving_audit_bps": self.privacy_preserving_audit_bps,
            "pq_auth_scheme": self.pq_auth_scheme,
            "proof_system": self.proof_system,
            "commitment_scheme": self.commitment_scheme,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateRewardPool {
    pub pool_id: String,
    pub label: String,
    pub domain: PrivateLiquidityRewardDomain,
    pub asset_pair_root: String,
    pub venue_root: String,
    pub status: RewardPoolStatus,
    pub min_liquidity_units: u64,
    pub reward_rate_bps: u64,
    pub low_fee_boost_bps: u64,
    pub risk_weight_bps: u64,
    pub privacy_budget_units: u64,
    pub opened_at_height: u64,
    pub metadata_root: String,
}

impl PrivateRewardPool {
    pub fn new(
        label: &str,
        domain: PrivateLiquidityRewardDomain,
        asset_pair_root: &str,
        venue_root: &str,
        min_liquidity_units: u64,
        reward_rate_bps: u64,
        opened_at_height: u64,
        metadata: &Value,
    ) -> PrivateLiquidityRewardsResult<Self> {
        if label.trim().is_empty() {
            return Err("private reward pool label cannot be empty".to_string());
        }
        if asset_pair_root.trim().is_empty() || venue_root.trim().is_empty() {
            return Err("private reward pool roots cannot be empty".to_string());
        }
        if min_liquidity_units == 0 {
            return Err("private reward pool min liquidity must be positive".to_string());
        }
        let metadata_root = private_liquidity_rewards_payload_root("POOL-METADATA", metadata);
        let pool_id = private_reward_pool_id(
            label,
            &domain,
            asset_pair_root,
            venue_root,
            opened_at_height,
        );
        let pool = Self {
            pool_id,
            label: label.to_string(),
            domain,
            asset_pair_root: asset_pair_root.to_string(),
            venue_root: venue_root.to_string(),
            status: RewardPoolStatus::Active,
            min_liquidity_units,
            reward_rate_bps,
            low_fee_boost_bps: 0,
            risk_weight_bps: 10_000,
            privacy_budget_units: 0,
            opened_at_height,
            metadata_root,
        };
        pool.validate()?;
        Ok(pool)
    }

    pub fn with_low_fee_boost(mut self, low_fee_boost_bps: u64) -> Self {
        self.low_fee_boost_bps = low_fee_boost_bps;
        self
    }

    pub fn with_privacy_budget(mut self, privacy_budget_units: u64) -> Self {
        self.privacy_budget_units = privacy_budget_units;
        self
    }

    pub fn with_risk_weight(mut self, risk_weight_bps: u64) -> Self {
        self.risk_weight_bps = risk_weight_bps;
        self
    }

    pub fn validate(&self) -> PrivateLiquidityRewardsResult<()> {
        if self.pool_id.trim().is_empty() || self.label.trim().is_empty() {
            return Err("private reward pool identifiers cannot be empty".to_string());
        }
        if self.asset_pair_root.trim().is_empty()
            || self.venue_root.trim().is_empty()
            || self.metadata_root.trim().is_empty()
        {
            return Err("private reward pool roots cannot be empty".to_string());
        }
        if self.min_liquidity_units == 0 {
            return Err("private reward pool minimum liquidity must be positive".to_string());
        }
        if self.risk_weight_bps == 0 || self.risk_weight_bps > 100_000 {
            return Err("private reward pool risk weight out of range".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_reward_pool",
            "pool_id": self.pool_id,
            "label": self.label,
            "domain": self.domain.as_str(),
            "asset_pair_root": self.asset_pair_root,
            "venue_root": self.venue_root,
            "status": self.status.as_str(),
            "min_liquidity_units": self.min_liquidity_units,
            "reward_rate_bps": self.reward_rate_bps,
            "low_fee_boost_bps": self.low_fee_boost_bps,
            "risk_weight_bps": self.risk_weight_bps,
            "privacy_budget_units": self.privacy_budget_units,
            "opened_at_height": self.opened_at_height,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateRewardEpoch {
    pub epoch_id: String,
    pub pool_id: String,
    pub status: RewardEpochStatus,
    pub start_height: u64,
    pub end_height: u64,
    pub reward_budget_units: u64,
    pub fee_rebate_budget_units: u64,
    pub eligibility_root: String,
    pub distribution_root: String,
    pub sponsor_root: String,
    pub sealed_at_height: Option<u64>,
}

impl PrivateRewardEpoch {
    pub fn new(
        pool_id: &str,
        start_height: u64,
        end_height: u64,
        reward_budget_units: u64,
        fee_rebate_budget_units: u64,
        sponsor_ids: &[String],
    ) -> PrivateLiquidityRewardsResult<Self> {
        if pool_id.trim().is_empty() {
            return Err("private reward epoch pool id cannot be empty".to_string());
        }
        if start_height >= end_height {
            return Err("private reward epoch end must be after start".to_string());
        }
        if reward_budget_units == 0 && fee_rebate_budget_units == 0 {
            return Err("private reward epoch must fund rewards or rebates".to_string());
        }
        let sponsor_root = private_liquidity_rewards_string_set_root("EPOCH-SPONSOR", sponsor_ids);
        let epoch_id = private_reward_epoch_id(pool_id, start_height, end_height, &sponsor_root);
        let epoch = Self {
            epoch_id,
            pool_id: pool_id.to_string(),
            status: RewardEpochStatus::Scheduled,
            start_height,
            end_height,
            reward_budget_units,
            fee_rebate_budget_units,
            eligibility_root: private_liquidity_rewards_string_root("EPOCH-ELIGIBILITY", "pending"),
            distribution_root: private_liquidity_rewards_string_root(
                "EPOCH-DISTRIBUTION",
                "pending",
            ),
            sponsor_root,
            sealed_at_height: None,
        };
        epoch.validate()?;
        Ok(epoch)
    }

    pub fn open(mut self) -> Self {
        self.status = RewardEpochStatus::Open;
        self
    }

    pub fn with_roots(mut self, eligibility_root: &str, distribution_root: &str) -> Self {
        self.eligibility_root = eligibility_root.to_string();
        self.distribution_root = distribution_root.to_string();
        self
    }

    pub fn seal(
        &mut self,
        height: u64,
        distribution_root: &str,
    ) -> PrivateLiquidityRewardsResult<()> {
        if height < self.start_height {
            return Err("private reward epoch cannot seal before start".to_string());
        }
        if distribution_root.trim().is_empty() {
            return Err("private reward epoch distribution root cannot be empty".to_string());
        }
        self.status = RewardEpochStatus::Sealed;
        self.sealed_at_height = Some(height);
        self.distribution_root = distribution_root.to_string();
        Ok(())
    }

    pub fn validate(&self) -> PrivateLiquidityRewardsResult<()> {
        if self.epoch_id.trim().is_empty() || self.pool_id.trim().is_empty() {
            return Err("private reward epoch identifiers cannot be empty".to_string());
        }
        if self.start_height >= self.end_height {
            return Err("private reward epoch end must be after start".to_string());
        }
        if self.reward_budget_units == 0 && self.fee_rebate_budget_units == 0 {
            return Err("private reward epoch must fund rewards or rebates".to_string());
        }
        if self.eligibility_root.trim().is_empty()
            || self.distribution_root.trim().is_empty()
            || self.sponsor_root.trim().is_empty()
        {
            return Err("private reward epoch roots cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_reward_epoch",
            "epoch_id": self.epoch_id,
            "pool_id": self.pool_id,
            "status": self.status.as_str(),
            "start_height": self.start_height,
            "end_height": self.end_height,
            "reward_budget_units": self.reward_budget_units,
            "fee_rebate_budget_units": self.fee_rebate_budget_units,
            "eligibility_root": self.eligibility_root,
            "distribution_root": self.distribution_root,
            "sponsor_root": self.sponsor_root,
            "sealed_at_height": self.sealed_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateLiquidityPosition {
    pub position_id: String,
    pub pool_id: String,
    pub owner_commitment: String,
    pub liquidity_commitment: String,
    pub range_commitment: String,
    pub strategy_root: String,
    pub status: LiquidityPositionStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub low_fee_lane: bool,
    pub pq_authorization_root: String,
    pub nullifier_root: String,
}

impl PrivateLiquidityPosition {
    pub fn new(
        pool_id: &str,
        owner_label: &str,
        liquidity_units: u64,
        range_label: &str,
        strategy: &Value,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateLiquidityRewardsResult<Self> {
        if pool_id.trim().is_empty() || owner_label.trim().is_empty() {
            return Err("private liquidity position identifiers cannot be empty".to_string());
        }
        if liquidity_units == 0 {
            return Err("private liquidity position units must be positive".to_string());
        }
        if opened_at_height >= expires_at_height {
            return Err("private liquidity position expiry must be after open".to_string());
        }
        let owner_commitment = private_liquidity_rewards_string_root("POSITION-OWNER", owner_label);
        let liquidity_commitment =
            private_liquidity_amount_commitment("POSITION-LIQUIDITY", liquidity_units);
        let range_commitment = private_liquidity_rewards_string_root("POSITION-RANGE", range_label);
        let strategy_root = private_liquidity_rewards_payload_root("POSITION-STRATEGY", strategy);
        let nullifier_root = private_liquidity_rewards_string_root(
            "POSITION-NULLIFIER",
            &format!("{pool_id}:{owner_label}:{opened_at_height}"),
        );
        let pq_authorization_root = private_liquidity_rewards_payload_root(
            "POSITION-PQ-AUTH",
            &json!({
                "scheme": PRIVATE_LIQUIDITY_REWARDS_PQ_AUTH_SCHEME,
                "owner_commitment": owner_commitment,
                "height": opened_at_height,
            }),
        );
        let position_id = private_liquidity_position_id(
            pool_id,
            &owner_commitment,
            &liquidity_commitment,
            opened_at_height,
        );
        let position = Self {
            position_id,
            pool_id: pool_id.to_string(),
            owner_commitment,
            liquidity_commitment,
            range_commitment,
            strategy_root,
            status: LiquidityPositionStatus::Pending,
            opened_at_height,
            expires_at_height,
            low_fee_lane: false,
            pq_authorization_root,
            nullifier_root,
        };
        position.validate()?;
        Ok(position)
    }

    pub fn activate(mut self) -> Self {
        self.status = LiquidityPositionStatus::Active;
        self
    }

    pub fn with_low_fee_lane(mut self) -> Self {
        self.low_fee_lane = true;
        self
    }

    pub fn validate(&self) -> PrivateLiquidityRewardsResult<()> {
        if self.position_id.trim().is_empty() || self.pool_id.trim().is_empty() {
            return Err("private liquidity position identifiers cannot be empty".to_string());
        }
        if self.owner_commitment.trim().is_empty()
            || self.liquidity_commitment.trim().is_empty()
            || self.range_commitment.trim().is_empty()
            || self.strategy_root.trim().is_empty()
            || self.pq_authorization_root.trim().is_empty()
            || self.nullifier_root.trim().is_empty()
        {
            return Err("private liquidity position commitments cannot be empty".to_string());
        }
        if self.opened_at_height >= self.expires_at_height {
            return Err("private liquidity position expiry must be after open".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_liquidity_position",
            "position_id": self.position_id,
            "pool_id": self.pool_id,
            "owner_commitment": self.owner_commitment,
            "liquidity_commitment": self.liquidity_commitment,
            "range_commitment": self.range_commitment,
            "strategy_root": self.strategy_root,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "low_fee_lane": self.low_fee_lane,
            "pq_authorization_root": self.pq_authorization_root,
            "nullifier_root": self.nullifier_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateRewardCommitment {
    pub commitment_id: String,
    pub epoch_id: String,
    pub position_id: String,
    pub reward_commitment: String,
    pub fee_rebate_commitment: String,
    pub eligibility_proof_root: String,
    pub status: RewardCommitmentStatus,
    pub score_bps: u64,
    pub low_fee_weight_bps: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivateRewardCommitment {
    pub fn new(
        epoch_id: &str,
        position_id: &str,
        reward_units: u64,
        fee_rebate_units: u64,
        score_bps: u64,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateLiquidityRewardsResult<Self> {
        if epoch_id.trim().is_empty() || position_id.trim().is_empty() {
            return Err("private reward commitment identifiers cannot be empty".to_string());
        }
        if reward_units == 0 && fee_rebate_units == 0 {
            return Err("private reward commitment must include reward or rebate".to_string());
        }
        if created_at_height >= expires_at_height {
            return Err("private reward commitment expiry must be after creation".to_string());
        }
        let reward_commitment = private_liquidity_amount_commitment("REWARD-AMOUNT", reward_units);
        let fee_rebate_commitment =
            private_liquidity_amount_commitment("REWARD-FEE-REBATE", fee_rebate_units);
        let eligibility_proof_root = private_liquidity_rewards_payload_root(
            "REWARD-ELIGIBILITY-PROOF",
            &json!({
                "epoch_id": epoch_id,
                "position_id": position_id,
                "proof_system": PRIVATE_LIQUIDITY_REWARDS_PROOF_SYSTEM,
                "score_bps": score_bps,
            }),
        );
        let commitment_id = private_reward_commitment_id(
            epoch_id,
            position_id,
            &reward_commitment,
            &fee_rebate_commitment,
        );
        let commitment = Self {
            commitment_id,
            epoch_id: epoch_id.to_string(),
            position_id: position_id.to_string(),
            reward_commitment,
            fee_rebate_commitment,
            eligibility_proof_root,
            status: RewardCommitmentStatus::PendingProof,
            score_bps,
            low_fee_weight_bps: 0,
            created_at_height,
            expires_at_height,
        };
        commitment.validate()?;
        Ok(commitment)
    }

    pub fn eligible(mut self) -> Self {
        self.status = RewardCommitmentStatus::Eligible;
        self
    }

    pub fn with_low_fee_weight(mut self, low_fee_weight_bps: u64) -> Self {
        self.low_fee_weight_bps = low_fee_weight_bps;
        self
    }

    pub fn validate(&self) -> PrivateLiquidityRewardsResult<()> {
        if self.commitment_id.trim().is_empty()
            || self.epoch_id.trim().is_empty()
            || self.position_id.trim().is_empty()
        {
            return Err("private reward commitment identifiers cannot be empty".to_string());
        }
        if self.reward_commitment.trim().is_empty()
            || self.fee_rebate_commitment.trim().is_empty()
            || self.eligibility_proof_root.trim().is_empty()
        {
            return Err("private reward commitment roots cannot be empty".to_string());
        }
        if self.created_at_height >= self.expires_at_height {
            return Err("private reward commitment expiry must be after creation".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_reward_commitment",
            "commitment_id": self.commitment_id,
            "epoch_id": self.epoch_id,
            "position_id": self.position_id,
            "reward_commitment": self.reward_commitment,
            "fee_rebate_commitment": self.fee_rebate_commitment,
            "eligibility_proof_root": self.eligibility_proof_root,
            "status": self.status.as_str(),
            "score_bps": self.score_bps,
            "low_fee_weight_bps": self.low_fee_weight_bps,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateRewardClaim {
    pub claim_id: String,
    pub commitment_id: String,
    pub claimant_commitment: String,
    pub nullifier: String,
    pub payout_note_commitment: String,
    pub fee_rebate_note_commitment: String,
    pub disclosure_ticket_root: String,
    pub status: RewardClaimStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivateRewardClaim {
    pub fn new(
        commitment_id: &str,
        claimant_label: &str,
        payout_units: u64,
        fee_rebate_units: u64,
        submitted_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateLiquidityRewardsResult<Self> {
        if commitment_id.trim().is_empty() || claimant_label.trim().is_empty() {
            return Err("private reward claim identifiers cannot be empty".to_string());
        }
        if submitted_at_height >= expires_at_height {
            return Err("private reward claim expiry must be after submission".to_string());
        }
        let claimant_commitment = private_liquidity_rewards_string_root("CLAIMANT", claimant_label);
        let nullifier = private_reward_claim_nullifier(
            commitment_id,
            &claimant_commitment,
            submitted_at_height,
        );
        let payout_note_commitment =
            private_liquidity_amount_commitment("CLAIM-PAYOUT", payout_units);
        let fee_rebate_note_commitment =
            private_liquidity_amount_commitment("CLAIM-FEE-REBATE", fee_rebate_units);
        let disclosure_ticket_root = private_liquidity_rewards_payload_root(
            "CLAIM-DISCLOSURE",
            &json!({
                "claimant_commitment": claimant_commitment,
                "mode": "auditor-threshold-only",
                "submitted_at_height": submitted_at_height,
            }),
        );
        let claim_id = private_reward_claim_id(
            commitment_id,
            &nullifier,
            &payout_note_commitment,
            &fee_rebate_note_commitment,
        );
        let claim = Self {
            claim_id,
            commitment_id: commitment_id.to_string(),
            claimant_commitment,
            nullifier,
            payout_note_commitment,
            fee_rebate_note_commitment,
            disclosure_ticket_root,
            status: RewardClaimStatus::Submitted,
            submitted_at_height,
            expires_at_height,
        };
        claim.validate()?;
        Ok(claim)
    }

    pub fn verified(mut self) -> Self {
        self.status = RewardClaimStatus::Verified;
        self
    }

    pub fn settle(&mut self) {
        self.status = RewardClaimStatus::Settled;
    }

    pub fn validate(&self) -> PrivateLiquidityRewardsResult<()> {
        if self.claim_id.trim().is_empty()
            || self.commitment_id.trim().is_empty()
            || self.claimant_commitment.trim().is_empty()
        {
            return Err("private reward claim identifiers cannot be empty".to_string());
        }
        if self.nullifier.trim().is_empty()
            || self.payout_note_commitment.trim().is_empty()
            || self.fee_rebate_note_commitment.trim().is_empty()
            || self.disclosure_ticket_root.trim().is_empty()
        {
            return Err("private reward claim commitments cannot be empty".to_string());
        }
        if self.submitted_at_height >= self.expires_at_height {
            return Err("private reward claim expiry must be after submission".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_reward_claim",
            "claim_id": self.claim_id,
            "commitment_id": self.commitment_id,
            "claimant_commitment": self.claimant_commitment,
            "nullifier": self.nullifier,
            "payout_note_commitment": self.payout_note_commitment,
            "fee_rebate_note_commitment": self.fee_rebate_note_commitment,
            "disclosure_ticket_root": self.disclosure_ticket_root,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateFeeRebateVault {
    pub vault_id: String,
    pub sponsor_id: String,
    pub pool_id: String,
    pub status: FeeRebateVaultStatus,
    pub available_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub per_claim_cap_units: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub policy_root: String,
}

impl PrivateFeeRebateVault {
    pub fn new(
        sponsor_id: &str,
        pool_id: &str,
        available_units: u64,
        per_claim_cap_units: u64,
        opened_at_height: u64,
        expires_at_height: u64,
        policy: &Value,
    ) -> PrivateLiquidityRewardsResult<Self> {
        if sponsor_id.trim().is_empty() || pool_id.trim().is_empty() {
            return Err("private fee rebate vault identifiers cannot be empty".to_string());
        }
        if available_units == 0 || per_claim_cap_units == 0 {
            return Err("private fee rebate vault budgets must be positive".to_string());
        }
        if opened_at_height >= expires_at_height {
            return Err("private fee rebate vault expiry must be after open".to_string());
        }
        let policy_root = private_liquidity_rewards_payload_root("REBATE-VAULT-POLICY", policy);
        let vault_id =
            private_fee_rebate_vault_id(sponsor_id, pool_id, &policy_root, opened_at_height);
        let vault = Self {
            vault_id,
            sponsor_id: sponsor_id.to_string(),
            pool_id: pool_id.to_string(),
            status: FeeRebateVaultStatus::Active,
            available_units,
            reserved_units: 0,
            spent_units: 0,
            per_claim_cap_units,
            opened_at_height,
            expires_at_height,
            policy_root,
        };
        vault.validate()?;
        Ok(vault)
    }

    pub fn reserve(&mut self, units: u64) -> PrivateLiquidityRewardsResult<()> {
        if units == 0 {
            return Err("private fee rebate reserve units must be positive".to_string());
        }
        if units > self.per_claim_cap_units {
            return Err("private fee rebate reserve exceeds per-claim cap".to_string());
        }
        if self.available_units < units {
            return Err("private fee rebate vault has insufficient available units".to_string());
        }
        self.available_units = self.available_units.saturating_sub(units);
        self.reserved_units = self.reserved_units.saturating_add(units);
        if self.available_units == 0 {
            self.status = FeeRebateVaultStatus::Empty;
        }
        Ok(())
    }

    pub fn settle(&mut self, units: u64) -> PrivateLiquidityRewardsResult<()> {
        if units == 0 {
            return Err("private fee rebate settlement units must be positive".to_string());
        }
        if self.reserved_units < units {
            return Err("private fee rebate settlement exceeds reserved units".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_sub(units);
        self.spent_units = self.spent_units.saturating_add(units);
        Ok(())
    }

    pub fn validate(&self) -> PrivateLiquidityRewardsResult<()> {
        if self.vault_id.trim().is_empty()
            || self.sponsor_id.trim().is_empty()
            || self.pool_id.trim().is_empty()
            || self.policy_root.trim().is_empty()
        {
            return Err("private fee rebate vault identifiers cannot be empty".to_string());
        }
        if self.per_claim_cap_units == 0 {
            return Err("private fee rebate vault cap must be positive".to_string());
        }
        if self.opened_at_height >= self.expires_at_height {
            return Err("private fee rebate vault expiry must be after open".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_fee_rebate_vault",
            "vault_id": self.vault_id,
            "sponsor_id": self.sponsor_id,
            "pool_id": self.pool_id,
            "status": self.status.as_str(),
            "available_units": self.available_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "per_claim_cap_units": self.per_claim_cap_units,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "policy_root": self.policy_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateRewardSponsor {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub status: RewardSponsorStatus,
    pub reward_budget_units: u64,
    pub rebate_budget_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub domain_allowlist_root: String,
    pub pq_authorization_root: String,
    pub metadata_root: String,
}

impl PrivateRewardSponsor {
    pub fn new(
        sponsor_label: &str,
        reward_budget_units: u64,
        rebate_budget_units: u64,
        allowed_domains: &[PrivateLiquidityRewardDomain],
        metadata: &Value,
    ) -> PrivateLiquidityRewardsResult<Self> {
        if sponsor_label.trim().is_empty() {
            return Err("private reward sponsor label cannot be empty".to_string());
        }
        if reward_budget_units == 0 && rebate_budget_units == 0 {
            return Err("private reward sponsor must fund rewards or rebates".to_string());
        }
        let sponsor_commitment = private_liquidity_rewards_string_root("SPONSOR", sponsor_label);
        let domain_labels = allowed_domains
            .iter()
            .map(|domain| domain.as_str().to_string())
            .collect::<Vec<_>>();
        let domain_allowlist_root =
            private_liquidity_rewards_string_set_root("SPONSOR-DOMAIN", &domain_labels);
        let pq_authorization_root = private_liquidity_rewards_payload_root(
            "SPONSOR-PQ-AUTH",
            &json!({
                "scheme": PRIVATE_LIQUIDITY_REWARDS_PQ_AUTH_SCHEME,
                "sponsor_commitment": sponsor_commitment,
                "domain_allowlist_root": domain_allowlist_root,
            }),
        );
        let metadata_root = private_liquidity_rewards_payload_root("SPONSOR-METADATA", metadata);
        let sponsor_id = private_reward_sponsor_id(
            &sponsor_commitment,
            &domain_allowlist_root,
            reward_budget_units,
            rebate_budget_units,
        );
        let sponsor = Self {
            sponsor_id,
            sponsor_commitment,
            status: RewardSponsorStatus::Active,
            reward_budget_units,
            rebate_budget_units,
            reserved_units: 0,
            spent_units: 0,
            domain_allowlist_root,
            pq_authorization_root,
            metadata_root,
        };
        sponsor.validate()?;
        Ok(sponsor)
    }

    pub fn reserve(&mut self, units: u64) -> PrivateLiquidityRewardsResult<()> {
        if units == 0 {
            return Err("private reward sponsor reserve units must be positive".to_string());
        }
        let available = self.available_units();
        if available < units {
            return Err("private reward sponsor has insufficient available units".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(units);
        Ok(())
    }

    pub fn debit(&mut self, units: u64) -> PrivateLiquidityRewardsResult<()> {
        if units == 0 {
            return Err("private reward sponsor debit units must be positive".to_string());
        }
        if self.reserved_units < units {
            return Err("private reward sponsor debit exceeds reserved units".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_sub(units);
        self.spent_units = self.spent_units.saturating_add(units);
        if self.available_units() == 0 {
            self.status = RewardSponsorStatus::Exhausted;
        }
        Ok(())
    }

    pub fn total_budget_units(&self) -> u64 {
        self.reward_budget_units
            .saturating_add(self.rebate_budget_units)
    }

    pub fn available_units(&self) -> u64 {
        self.total_budget_units()
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn validate(&self) -> PrivateLiquidityRewardsResult<()> {
        if self.sponsor_id.trim().is_empty() || self.sponsor_commitment.trim().is_empty() {
            return Err("private reward sponsor identifiers cannot be empty".to_string());
        }
        if self.reward_budget_units == 0 && self.rebate_budget_units == 0 {
            return Err("private reward sponsor must fund rewards or rebates".to_string());
        }
        if self.domain_allowlist_root.trim().is_empty()
            || self.pq_authorization_root.trim().is_empty()
            || self.metadata_root.trim().is_empty()
        {
            return Err("private reward sponsor roots cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_reward_sponsor",
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment": self.sponsor_commitment,
            "status": self.status.as_str(),
            "reward_budget_units": self.reward_budget_units,
            "rebate_budget_units": self.rebate_budget_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "domain_allowlist_root": self.domain_allowlist_root,
            "pq_authorization_root": self.pq_authorization_root,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateRewardReceipt {
    pub receipt_id: String,
    pub claim_id: String,
    pub epoch_id: String,
    pub payout_root: String,
    pub fee_rebate_root: String,
    pub sponsor_debit_root: String,
    pub status: RewardReceiptStatus,
    pub posted_at_height: u64,
    pub audit_root: String,
}

impl PrivateRewardReceipt {
    pub fn new(
        claim_id: &str,
        epoch_id: &str,
        payout_units: u64,
        fee_rebate_units: u64,
        sponsor_ids: &[String],
        posted_at_height: u64,
    ) -> PrivateLiquidityRewardsResult<Self> {
        if claim_id.trim().is_empty() || epoch_id.trim().is_empty() {
            return Err("private reward receipt identifiers cannot be empty".to_string());
        }
        let payout_root = private_liquidity_amount_commitment("RECEIPT-PAYOUT", payout_units);
        let fee_rebate_root =
            private_liquidity_amount_commitment("RECEIPT-FEE-REBATE", fee_rebate_units);
        let sponsor_debit_root =
            private_liquidity_rewards_string_set_root("RECEIPT-SPONSOR-DEBIT", sponsor_ids);
        let audit_root = private_liquidity_rewards_payload_root(
            "RECEIPT-AUDIT",
            &json!({
                "proof_system": PRIVATE_LIQUIDITY_REWARDS_PROOF_SYSTEM,
                "claim_id": claim_id,
                "epoch_id": epoch_id,
                "posted_at_height": posted_at_height,
            }),
        );
        let receipt_id = private_reward_receipt_id(
            claim_id,
            epoch_id,
            &payout_root,
            &fee_rebate_root,
            posted_at_height,
        );
        let receipt = Self {
            receipt_id,
            claim_id: claim_id.to_string(),
            epoch_id: epoch_id.to_string(),
            payout_root,
            fee_rebate_root,
            sponsor_debit_root,
            status: RewardReceiptStatus::Posted,
            posted_at_height,
            audit_root,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> PrivateLiquidityRewardsResult<()> {
        if self.receipt_id.trim().is_empty()
            || self.claim_id.trim().is_empty()
            || self.epoch_id.trim().is_empty()
        {
            return Err("private reward receipt identifiers cannot be empty".to_string());
        }
        if self.payout_root.trim().is_empty()
            || self.fee_rebate_root.trim().is_empty()
            || self.sponsor_debit_root.trim().is_empty()
            || self.audit_root.trim().is_empty()
        {
            return Err("private reward receipt roots cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_reward_receipt",
            "receipt_id": self.receipt_id,
            "claim_id": self.claim_id,
            "epoch_id": self.epoch_id,
            "payout_root": self.payout_root,
            "fee_rebate_root": self.fee_rebate_root,
            "sponsor_debit_root": self.sponsor_debit_root,
            "status": self.status.as_str(),
            "posted_at_height": self.posted_at_height,
            "audit_root": self.audit_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateRewardEvent {
    pub event_id: String,
    pub event_kind: RewardEventKind,
    pub subject_id: String,
    pub height: u64,
    pub payload_root: String,
}

impl PrivateRewardEvent {
    pub fn new(
        event_kind: RewardEventKind,
        subject_id: &str,
        height: u64,
        payload: &Value,
    ) -> PrivateLiquidityRewardsResult<Self> {
        if subject_id.trim().is_empty() {
            return Err("private reward event subject cannot be empty".to_string());
        }
        let payload_root = private_liquidity_rewards_payload_root("EVENT-PAYLOAD", payload);
        let event_id = private_reward_event_id(&event_kind, subject_id, height, &payload_root);
        let event = Self {
            event_id,
            event_kind,
            subject_id: subject_id.to_string(),
            height,
            payload_root,
        };
        event.validate()?;
        Ok(event)
    }

    pub fn validate(&self) -> PrivateLiquidityRewardsResult<()> {
        if self.event_id.trim().is_empty()
            || self.subject_id.trim().is_empty()
            || self.payload_root.trim().is_empty()
        {
            return Err("private reward event identifiers cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_reward_event",
            "event_id": self.event_id,
            "event_kind": self.event_kind.as_str(),
            "subject_id": self.subject_id,
            "height": self.height,
            "payload_root": self.payload_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateLiquidityRewardsRoots {
    pub pool_root: String,
    pub epoch_root: String,
    pub position_root: String,
    pub commitment_root: String,
    pub claim_root: String,
    pub rebate_vault_root: String,
    pub sponsor_root: String,
    pub receipt_root: String,
    pub event_root: String,
}

impl PrivateLiquidityRewardsRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_liquidity_rewards_roots",
            "pool_root": self.pool_root,
            "epoch_root": self.epoch_root,
            "position_root": self.position_root,
            "commitment_root": self.commitment_root,
            "claim_root": self.claim_root,
            "rebate_vault_root": self.rebate_vault_root,
            "sponsor_root": self.sponsor_root,
            "receipt_root": self.receipt_root,
            "event_root": self.event_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateLiquidityRewardsCounters {
    pub pool_count: u64,
    pub live_epoch_count: u64,
    pub active_position_count: u64,
    pub eligible_commitment_count: u64,
    pub open_claim_count: u64,
    pub active_rebate_vault_count: u64,
    pub active_sponsor_count: u64,
    pub receipt_count: u64,
    pub event_count: u64,
    pub total_available_sponsor_units: u64,
    pub total_available_rebate_units: u64,
}

impl PrivateLiquidityRewardsCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_liquidity_rewards_counters",
            "pool_count": self.pool_count,
            "live_epoch_count": self.live_epoch_count,
            "active_position_count": self.active_position_count,
            "eligible_commitment_count": self.eligible_commitment_count,
            "open_claim_count": self.open_claim_count,
            "active_rebate_vault_count": self.active_rebate_vault_count,
            "active_sponsor_count": self.active_sponsor_count,
            "receipt_count": self.receipt_count,
            "event_count": self.event_count,
            "total_available_sponsor_units": self.total_available_sponsor_units,
            "total_available_rebate_units": self.total_available_rebate_units,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateLiquidityRewardsState {
    pub config: PrivateLiquidityRewardsConfig,
    pub height: u64,
    pub active_epoch_id: Option<String>,
    pub pools: BTreeMap<String, PrivateRewardPool>,
    pub epochs: BTreeMap<String, PrivateRewardEpoch>,
    pub positions: BTreeMap<String, PrivateLiquidityPosition>,
    pub commitments: BTreeMap<String, PrivateRewardCommitment>,
    pub claims: BTreeMap<String, PrivateRewardClaim>,
    pub rebate_vaults: BTreeMap<String, PrivateFeeRebateVault>,
    pub sponsors: BTreeMap<String, PrivateRewardSponsor>,
    pub receipts: BTreeMap<String, PrivateRewardReceipt>,
    pub events: BTreeMap<String, PrivateRewardEvent>,
}

impl Default for PrivateLiquidityRewardsState {
    fn default() -> Self {
        Self {
            config: PrivateLiquidityRewardsConfig::default(),
            height: 0,
            active_epoch_id: None,
            pools: BTreeMap::new(),
            epochs: BTreeMap::new(),
            positions: BTreeMap::new(),
            commitments: BTreeMap::new(),
            claims: BTreeMap::new(),
            rebate_vaults: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            receipts: BTreeMap::new(),
            events: BTreeMap::new(),
        }
    }
}

impl PrivateLiquidityRewardsState {
    pub fn new(config: PrivateLiquidityRewardsConfig) -> PrivateLiquidityRewardsResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::default()
        })
    }

    pub fn devnet() -> PrivateLiquidityRewardsResult<Self> {
        let mut state = Self::new(PrivateLiquidityRewardsConfig::default())?;
        state.height = 1;

        let sponsor = PrivateRewardSponsor::new(
            "devnet-liquidity-reward-sponsor",
            2_500_000,
            750_000,
            &[
                PrivateLiquidityRewardDomain::Amm,
                PrivateLiquidityRewardDomain::Lending,
                PrivateLiquidityRewardDomain::BridgeInventory,
                PrivateLiquidityRewardDomain::PrivateOrderflow,
            ],
            &json!({"profile": "devnet", "privacy": "commitment-only"}),
        )?;
        let sponsor_id = sponsor.sponsor_id.clone();
        state.insert_sponsor(sponsor)?;

        let amm_pool = PrivateRewardPool::new(
            "devnet-private-amm-rewards",
            PrivateLiquidityRewardDomain::Amm,
            &private_liquidity_rewards_string_root("ASSET-PAIR", "pXMR/pUSD"),
            &private_liquidity_rewards_string_root("VENUE", "private-dex"),
            25_000,
            175,
            state.height,
            &json!({"route": "private-dex", "goal": "low-fee-liquidity"}),
        )?
        .with_low_fee_boost(state.config.low_fee_boost_bps)
        .with_privacy_budget(25_000)
        .with_risk_weight(9_500);
        let amm_pool_id = amm_pool.pool_id.clone();
        state.insert_pool(amm_pool)?;

        let bridge_pool = PrivateRewardPool::new(
            "devnet-bridge-inventory-rewards",
            PrivateLiquidityRewardDomain::BridgeInventory,
            &private_liquidity_rewards_string_root("ASSET-PAIR", "XMR/wXMR"),
            &private_liquidity_rewards_string_root("VENUE", "monero-bridge"),
            100_000,
            90,
            state.height,
            &json!({"route": "monero-exit", "goal": "fast-private-withdrawals"}),
        )?
        .with_low_fee_boost(900)
        .with_privacy_budget(15_000)
        .with_risk_weight(8_500);
        state.insert_pool(bridge_pool)?;

        let epoch = PrivateRewardEpoch::new(
            &amm_pool_id,
            state.height,
            state
                .height
                .saturating_add(state.config.epoch_length_blocks),
            1_000_000,
            250_000,
            &[sponsor_id.clone()],
        )?
        .open()
        .with_roots(
            &private_liquidity_rewards_string_root("DEVNET-ELIGIBILITY", "amm-lp-v1"),
            &private_liquidity_rewards_string_root("DEVNET-DISTRIBUTION", "pro-rata-private"),
        );
        let epoch_id = epoch.epoch_id.clone();
        state.active_epoch_id = Some(epoch_id.clone());
        state.insert_epoch(epoch)?;

        let position = PrivateLiquidityPosition::new(
            &amm_pool_id,
            "devnet-private-lp-1",
            150_000,
            "wide-xmr-usd",
            &json!({"kind": "concentrated-liquidity", "privacy": "range-commitment"}),
            state.height,
            state.height.saturating_add(3_600),
        )?
        .activate()
        .with_low_fee_lane();
        let position_id = position.position_id.clone();
        state.insert_position(position)?;

        let commitment = PrivateRewardCommitment::new(
            &epoch_id,
            &position_id,
            12_500,
            3_000,
            9_700,
            state.height,
            state.height.saturating_add(state.config.claim_ttl_blocks),
        )?
        .eligible()
        .with_low_fee_weight(1_100);
        let commitment_id = commitment.commitment_id.clone();
        state.insert_commitment(commitment)?;

        let claim = PrivateRewardClaim::new(
            &commitment_id,
            "devnet-private-lp-1",
            12_500,
            3_000,
            state.height.saturating_add(1),
            state.height.saturating_add(state.config.claim_ttl_blocks),
        )?
        .verified();
        let claim_id = claim.claim_id.clone();
        state.insert_claim(claim)?;

        let rebate_vault = PrivateFeeRebateVault::new(
            &sponsor_id,
            &amm_pool_id,
            250_000,
            5_000,
            state.height,
            state.height.saturating_add(state.config.rebate_ttl_blocks),
            &json!({"rebate": "private-amm-low-fee", "cap": "per-claim"}),
        )?;
        state.insert_rebate_vault(rebate_vault)?;

        let receipt = PrivateRewardReceipt::new(
            &claim_id,
            &epoch_id,
            12_500,
            3_000,
            &[sponsor_id.clone()],
            state.height.saturating_add(2),
        )?;
        state.insert_receipt(receipt)?;

        state.insert_event(PrivateRewardEvent::new(
            RewardEventKind::PoolOpened,
            &amm_pool_id,
            state.height,
            &json!({"source": "devnet"}),
        )?)?;
        state.insert_event(PrivateRewardEvent::new(
            RewardEventKind::ClaimVerified,
            &claim_id,
            state.height.saturating_add(1),
            &json!({"proof_system": PRIVATE_LIQUIDITY_REWARDS_PROOF_SYSTEM}),
        )?)?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateLiquidityRewardsResult<()> {
        self.height = height;
        self.expire_records();
        Ok(())
    }

    pub fn insert_pool(&mut self, pool: PrivateRewardPool) -> PrivateLiquidityRewardsResult<()> {
        if self.pools.len() >= PRIVATE_LIQUIDITY_REWARDS_MAX_POOLS
            && !self.pools.contains_key(&pool.pool_id)
        {
            return Err("private liquidity rewards pool limit exceeded".to_string());
        }
        pool.validate()?;
        self.pools.insert(pool.pool_id.clone(), pool);
        Ok(())
    }

    pub fn insert_epoch(&mut self, epoch: PrivateRewardEpoch) -> PrivateLiquidityRewardsResult<()> {
        if self.epochs.len() >= PRIVATE_LIQUIDITY_REWARDS_MAX_EPOCHS
            && !self.epochs.contains_key(&epoch.epoch_id)
        {
            return Err("private liquidity rewards epoch limit exceeded".to_string());
        }
        if !self.pools.contains_key(&epoch.pool_id) {
            return Err("private liquidity rewards epoch references unknown pool".to_string());
        }
        epoch.validate()?;
        self.epochs.insert(epoch.epoch_id.clone(), epoch);
        Ok(())
    }

    pub fn insert_position(
        &mut self,
        position: PrivateLiquidityPosition,
    ) -> PrivateLiquidityRewardsResult<()> {
        if self.positions.len() >= PRIVATE_LIQUIDITY_REWARDS_MAX_POSITIONS
            && !self.positions.contains_key(&position.position_id)
        {
            return Err("private liquidity rewards position limit exceeded".to_string());
        }
        let pool = self
            .pools
            .get(&position.pool_id)
            .ok_or_else(|| "private liquidity position references unknown pool".to_string())?;
        if !pool.status.admits_new_positions() {
            return Err("private liquidity position pool is not admitting positions".to_string());
        }
        position.validate()?;
        self.positions
            .insert(position.position_id.clone(), position);
        Ok(())
    }

    pub fn insert_commitment(
        &mut self,
        commitment: PrivateRewardCommitment,
    ) -> PrivateLiquidityRewardsResult<()> {
        if self.commitments.len() >= PRIVATE_LIQUIDITY_REWARDS_MAX_COMMITMENTS
            && !self.commitments.contains_key(&commitment.commitment_id)
        {
            return Err("private liquidity rewards commitment limit exceeded".to_string());
        }
        if !self.epochs.contains_key(&commitment.epoch_id) {
            return Err("private reward commitment references unknown epoch".to_string());
        }
        if !self.positions.contains_key(&commitment.position_id) {
            return Err("private reward commitment references unknown position".to_string());
        }
        commitment.validate()?;
        self.commitments
            .insert(commitment.commitment_id.clone(), commitment);
        Ok(())
    }

    pub fn insert_claim(&mut self, claim: PrivateRewardClaim) -> PrivateLiquidityRewardsResult<()> {
        if self.claims.len() >= PRIVATE_LIQUIDITY_REWARDS_MAX_CLAIMS
            && !self.claims.contains_key(&claim.claim_id)
        {
            return Err("private liquidity rewards claim limit exceeded".to_string());
        }
        if !self.commitments.contains_key(&claim.commitment_id) {
            return Err("private reward claim references unknown commitment".to_string());
        }
        let duplicate_nullifier = self.claims.values().any(|existing| {
            existing.nullifier == claim.nullifier && existing.claim_id != claim.claim_id
        });
        if duplicate_nullifier {
            return Err("private reward claim nullifier already used".to_string());
        }
        claim.validate()?;
        self.claims.insert(claim.claim_id.clone(), claim);
        Ok(())
    }

    pub fn insert_rebate_vault(
        &mut self,
        vault: PrivateFeeRebateVault,
    ) -> PrivateLiquidityRewardsResult<()> {
        if self.rebate_vaults.len() >= PRIVATE_LIQUIDITY_REWARDS_MAX_REBATE_VAULTS
            && !self.rebate_vaults.contains_key(&vault.vault_id)
        {
            return Err("private liquidity rewards rebate vault limit exceeded".to_string());
        }
        if !self.sponsors.contains_key(&vault.sponsor_id) {
            return Err("private rebate vault references unknown sponsor".to_string());
        }
        if !self.pools.contains_key(&vault.pool_id) {
            return Err("private rebate vault references unknown pool".to_string());
        }
        vault.validate()?;
        self.rebate_vaults.insert(vault.vault_id.clone(), vault);
        Ok(())
    }

    pub fn insert_sponsor(
        &mut self,
        sponsor: PrivateRewardSponsor,
    ) -> PrivateLiquidityRewardsResult<()> {
        if self.sponsors.len() >= PRIVATE_LIQUIDITY_REWARDS_MAX_SPONSORS
            && !self.sponsors.contains_key(&sponsor.sponsor_id)
        {
            return Err("private liquidity rewards sponsor limit exceeded".to_string());
        }
        sponsor.validate()?;
        self.sponsors.insert(sponsor.sponsor_id.clone(), sponsor);
        Ok(())
    }

    pub fn insert_receipt(
        &mut self,
        receipt: PrivateRewardReceipt,
    ) -> PrivateLiquidityRewardsResult<()> {
        if self.receipts.len() >= PRIVATE_LIQUIDITY_REWARDS_MAX_RECEIPTS
            && !self.receipts.contains_key(&receipt.receipt_id)
        {
            return Err("private liquidity rewards receipt limit exceeded".to_string());
        }
        if !self.claims.contains_key(&receipt.claim_id) {
            return Err("private reward receipt references unknown claim".to_string());
        }
        if !self.epochs.contains_key(&receipt.epoch_id) {
            return Err("private reward receipt references unknown epoch".to_string());
        }
        receipt.validate()?;
        self.receipts.insert(receipt.receipt_id.clone(), receipt);
        Ok(())
    }

    pub fn insert_event(&mut self, event: PrivateRewardEvent) -> PrivateLiquidityRewardsResult<()> {
        if self.events.len() >= PRIVATE_LIQUIDITY_REWARDS_MAX_EVENTS
            && !self.events.contains_key(&event.event_id)
        {
            return Err("private liquidity rewards event limit exceeded".to_string());
        }
        event.validate()?;
        self.events.insert(event.event_id.clone(), event);
        Ok(())
    }

    pub fn live_epoch_ids(&self) -> Vec<String> {
        self.epochs
            .values()
            .filter(|epoch| epoch.status.is_live())
            .map(|epoch| epoch.epoch_id.clone())
            .collect()
    }

    pub fn active_pool_ids(&self) -> Vec<String> {
        self.pools
            .values()
            .filter(|pool| pool.status == RewardPoolStatus::Active)
            .map(|pool| pool.pool_id.clone())
            .collect()
    }

    pub fn rewardable_position_ids(&self) -> Vec<String> {
        self.positions
            .values()
            .filter(|position| position.status.is_rewardable())
            .map(|position| position.position_id.clone())
            .collect()
    }

    pub fn eligible_commitment_ids(&self) -> Vec<String> {
        self.commitments
            .values()
            .filter(|commitment| commitment.status == RewardCommitmentStatus::Eligible)
            .map(|commitment| commitment.commitment_id.clone())
            .collect()
    }

    pub fn open_claim_ids(&self) -> Vec<String> {
        self.claims
            .values()
            .filter(|claim| {
                matches!(
                    claim.status,
                    RewardClaimStatus::Submitted | RewardClaimStatus::Verified
                )
            })
            .map(|claim| claim.claim_id.clone())
            .collect()
    }

    pub fn total_available_sponsor_units(&self) -> u64 {
        self.sponsors
            .values()
            .filter(|sponsor| sponsor.status == RewardSponsorStatus::Active)
            .map(PrivateRewardSponsor::available_units)
            .fold(0u64, u64::saturating_add)
    }

    pub fn total_available_rebate_units(&self) -> u64 {
        self.rebate_vaults
            .values()
            .filter(|vault| vault.status == FeeRebateVaultStatus::Active)
            .map(|vault| vault.available_units)
            .fold(0u64, u64::saturating_add)
    }

    pub fn roots(&self) -> PrivateLiquidityRewardsRoots {
        PrivateLiquidityRewardsRoots {
            pool_root: private_reward_pool_root(&self.pools.values().cloned().collect::<Vec<_>>()),
            epoch_root: private_reward_epoch_root(
                &self.epochs.values().cloned().collect::<Vec<_>>(),
            ),
            position_root: private_liquidity_position_root(
                &self.positions.values().cloned().collect::<Vec<_>>(),
            ),
            commitment_root: private_reward_commitment_root(
                &self.commitments.values().cloned().collect::<Vec<_>>(),
            ),
            claim_root: private_reward_claim_root(
                &self.claims.values().cloned().collect::<Vec<_>>(),
            ),
            rebate_vault_root: private_fee_rebate_vault_root(
                &self.rebate_vaults.values().cloned().collect::<Vec<_>>(),
            ),
            sponsor_root: private_reward_sponsor_root(
                &self.sponsors.values().cloned().collect::<Vec<_>>(),
            ),
            receipt_root: private_reward_receipt_root(
                &self.receipts.values().cloned().collect::<Vec<_>>(),
            ),
            event_root: private_reward_event_root(
                &self.events.values().cloned().collect::<Vec<_>>(),
            ),
        }
    }

    pub fn counters(&self) -> PrivateLiquidityRewardsCounters {
        PrivateLiquidityRewardsCounters {
            pool_count: self.pools.len() as u64,
            live_epoch_count: self.live_epoch_ids().len() as u64,
            active_position_count: self.rewardable_position_ids().len() as u64,
            eligible_commitment_count: self.eligible_commitment_ids().len() as u64,
            open_claim_count: self.open_claim_ids().len() as u64,
            active_rebate_vault_count: self
                .rebate_vaults
                .values()
                .filter(|vault| vault.status == FeeRebateVaultStatus::Active)
                .count() as u64,
            active_sponsor_count: self
                .sponsors
                .values()
                .filter(|sponsor| sponsor.status == RewardSponsorStatus::Active)
                .count() as u64,
            receipt_count: self.receipts.len() as u64,
            event_count: self.events.len() as u64,
            total_available_sponsor_units: self.total_available_sponsor_units(),
            total_available_rebate_units: self.total_available_rebate_units(),
        }
    }

    pub fn validate(&self) -> PrivateLiquidityRewardsResult<()> {
        self.config.validate()?;
        for pool in self.pools.values() {
            pool.validate()?;
        }
        for epoch in self.epochs.values() {
            epoch.validate()?;
            if !self.pools.contains_key(&epoch.pool_id) {
                return Err("private liquidity rewards epoch references unknown pool".to_string());
            }
        }
        for position in self.positions.values() {
            position.validate()?;
            if !self.pools.contains_key(&position.pool_id) {
                return Err(
                    "private liquidity rewards position references unknown pool".to_string()
                );
            }
        }
        for commitment in self.commitments.values() {
            commitment.validate()?;
            if !self.epochs.contains_key(&commitment.epoch_id)
                || !self.positions.contains_key(&commitment.position_id)
            {
                return Err(
                    "private liquidity rewards commitment references missing state".to_string(),
                );
            }
        }
        let mut nullifiers = BTreeSet::new();
        for claim in self.claims.values() {
            claim.validate()?;
            if !self.commitments.contains_key(&claim.commitment_id) {
                return Err(
                    "private liquidity rewards claim references unknown commitment".to_string(),
                );
            }
            if !nullifiers.insert(claim.nullifier.clone()) {
                return Err("private liquidity rewards duplicate claim nullifier".to_string());
            }
        }
        for vault in self.rebate_vaults.values() {
            vault.validate()?;
            if !self.sponsors.contains_key(&vault.sponsor_id)
                || !self.pools.contains_key(&vault.pool_id)
            {
                return Err(
                    "private liquidity rewards rebate vault references missing state".to_string(),
                );
            }
        }
        for sponsor in self.sponsors.values() {
            sponsor.validate()?;
        }
        for receipt in self.receipts.values() {
            receipt.validate()?;
            if !self.claims.contains_key(&receipt.claim_id)
                || !self.epochs.contains_key(&receipt.epoch_id)
            {
                return Err(
                    "private liquidity rewards receipt references missing state".to_string()
                );
            }
        }
        for event in self.events.values() {
            event.validate()?;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "private_liquidity_rewards_state",
            "config": self.config.public_record(),
            "height": self.height,
            "active_epoch_id": self.active_epoch_id,
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "active_pool_ids": self.active_pool_ids(),
            "live_epoch_ids": self.live_epoch_ids(),
            "rewardable_position_ids": self.rewardable_position_ids(),
            "eligible_commitment_ids": self.eligible_commitment_ids(),
            "open_claim_ids": self.open_claim_ids(),
        })
    }

    pub fn state_root(&self) -> String {
        private_liquidity_rewards_state_root_from_record(&self.public_record())
    }

    fn expire_records(&mut self) {
        for position in self.positions.values_mut() {
            if self.height >= position.expires_at_height
                && matches!(
                    position.status,
                    LiquidityPositionStatus::Pending | LiquidityPositionStatus::Active
                )
            {
                position.status = LiquidityPositionStatus::Withdrawn;
            }
        }
        for commitment in self.commitments.values_mut() {
            if self.height >= commitment.expires_at_height
                && matches!(
                    commitment.status,
                    RewardCommitmentStatus::PendingProof | RewardCommitmentStatus::Eligible
                )
            {
                commitment.status = RewardCommitmentStatus::Expired;
            }
        }
        for claim in self.claims.values_mut() {
            if self.height >= claim.expires_at_height
                && matches!(
                    claim.status,
                    RewardClaimStatus::Submitted | RewardClaimStatus::Verified
                )
            {
                claim.status = RewardClaimStatus::Expired;
            }
        }
        for vault in self.rebate_vaults.values_mut() {
            if self.height >= vault.expires_at_height
                && vault.status == FeeRebateVaultStatus::Active
            {
                vault.status = FeeRebateVaultStatus::Draining;
            }
        }
        for epoch in self.epochs.values_mut() {
            if self.height >= epoch.end_height && epoch.status == RewardEpochStatus::Open {
                epoch.status = RewardEpochStatus::Sealed;
                epoch.sealed_at_height = Some(self.height);
            }
        }
    }
}

pub fn private_liquidity_rewards_state_root_from_record(record: &Value) -> String {
    private_liquidity_rewards_payload_root("STATE", record)
}

pub fn private_liquidity_rewards_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-LIQUIDITY-REWARDS-{domain}"),
        &[HashPart::Json(payload)],
        32,
    )
}

pub fn private_liquidity_rewards_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        &format!("PRIVATE-LIQUIDITY-REWARDS-{domain}"),
        &[HashPart::Str(value)],
        32,
    )
}

pub fn private_liquidity_rewards_string_set_root(domain: &str, values: &[String]) -> String {
    let mut sorted = values.to_vec();
    sorted.sort();
    domain_hash(
        &format!("PRIVATE-LIQUIDITY-REWARDS-{domain}"),
        &sorted
            .iter()
            .map(|value| HashPart::Str(value))
            .collect::<Vec<_>>(),
        32,
    )
}

pub fn private_liquidity_amount_commitment(domain: &str, units: u64) -> String {
    domain_hash(
        &format!("PRIVATE-LIQUIDITY-REWARDS-{domain}"),
        &[HashPart::Int(units as i128)],
        32,
    )
}

pub fn private_reward_pool_id(
    label: &str,
    domain: &PrivateLiquidityRewardDomain,
    asset_pair_root: &str,
    venue_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-LIQUIDITY-REWARDS-POOL-ID",
        &[
            HashPart::Str(label),
            HashPart::Str(domain.as_str()),
            HashPart::Str(asset_pair_root),
            HashPart::Str(venue_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn private_reward_epoch_id(
    pool_id: &str,
    start_height: u64,
    end_height: u64,
    sponsor_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-LIQUIDITY-REWARDS-EPOCH-ID",
        &[
            HashPart::Str(pool_id),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
            HashPart::Str(sponsor_root),
        ],
        32,
    )
}

pub fn private_liquidity_position_id(
    pool_id: &str,
    owner_commitment: &str,
    liquidity_commitment: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-LIQUIDITY-REWARDS-POSITION-ID",
        &[
            HashPart::Str(pool_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(liquidity_commitment),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn private_reward_commitment_id(
    epoch_id: &str,
    position_id: &str,
    reward_commitment: &str,
    fee_rebate_commitment: &str,
) -> String {
    domain_hash(
        "PRIVATE-LIQUIDITY-REWARDS-COMMITMENT-ID",
        &[
            HashPart::Str(epoch_id),
            HashPart::Str(position_id),
            HashPart::Str(reward_commitment),
            HashPart::Str(fee_rebate_commitment),
        ],
        32,
    )
}

pub fn private_reward_claim_nullifier(
    commitment_id: &str,
    claimant_commitment: &str,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-LIQUIDITY-REWARDS-CLAIM-NULLIFIER",
        &[
            HashPart::Str(commitment_id),
            HashPart::Str(claimant_commitment),
            HashPart::Int(submitted_at_height as i128),
        ],
        32,
    )
}

pub fn private_reward_claim_id(
    commitment_id: &str,
    nullifier: &str,
    payout_note_commitment: &str,
    fee_rebate_note_commitment: &str,
) -> String {
    domain_hash(
        "PRIVATE-LIQUIDITY-REWARDS-CLAIM-ID",
        &[
            HashPart::Str(commitment_id),
            HashPart::Str(nullifier),
            HashPart::Str(payout_note_commitment),
            HashPart::Str(fee_rebate_note_commitment),
        ],
        32,
    )
}

pub fn private_fee_rebate_vault_id(
    sponsor_id: &str,
    pool_id: &str,
    policy_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-LIQUIDITY-REWARDS-REBATE-VAULT-ID",
        &[
            HashPart::Str(sponsor_id),
            HashPart::Str(pool_id),
            HashPart::Str(policy_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn private_reward_sponsor_id(
    sponsor_commitment: &str,
    domain_allowlist_root: &str,
    reward_budget_units: u64,
    rebate_budget_units: u64,
) -> String {
    domain_hash(
        "PRIVATE-LIQUIDITY-REWARDS-SPONSOR-ID",
        &[
            HashPart::Str(sponsor_commitment),
            HashPart::Str(domain_allowlist_root),
            HashPart::Int(reward_budget_units as i128),
            HashPart::Int(rebate_budget_units as i128),
        ],
        32,
    )
}

pub fn private_reward_receipt_id(
    claim_id: &str,
    epoch_id: &str,
    payout_root: &str,
    fee_rebate_root: &str,
    posted_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-LIQUIDITY-REWARDS-RECEIPT-ID",
        &[
            HashPart::Str(claim_id),
            HashPart::Str(epoch_id),
            HashPart::Str(payout_root),
            HashPart::Str(fee_rebate_root),
            HashPart::Int(posted_at_height as i128),
        ],
        32,
    )
}

pub fn private_reward_event_id(
    event_kind: &RewardEventKind,
    subject_id: &str,
    height: u64,
    payload_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-LIQUIDITY-REWARDS-EVENT-ID",
        &[
            HashPart::Str(event_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Int(height as i128),
            HashPart::Str(payload_root),
        ],
        32,
    )
}

pub fn private_reward_pool_root(pools: &[PrivateRewardPool]) -> String {
    private_liquidity_rewards_record_root(
        "POOL-ROOT",
        &pools
            .iter()
            .map(PrivateRewardPool::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_reward_epoch_root(epochs: &[PrivateRewardEpoch]) -> String {
    private_liquidity_rewards_record_root(
        "EPOCH-ROOT",
        &epochs
            .iter()
            .map(PrivateRewardEpoch::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_liquidity_position_root(positions: &[PrivateLiquidityPosition]) -> String {
    private_liquidity_rewards_record_root(
        "POSITION-ROOT",
        &positions
            .iter()
            .map(PrivateLiquidityPosition::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_reward_commitment_root(commitments: &[PrivateRewardCommitment]) -> String {
    private_liquidity_rewards_record_root(
        "COMMITMENT-ROOT",
        &commitments
            .iter()
            .map(PrivateRewardCommitment::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_reward_claim_root(claims: &[PrivateRewardClaim]) -> String {
    private_liquidity_rewards_record_root(
        "CLAIM-ROOT",
        &claims
            .iter()
            .map(PrivateRewardClaim::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_fee_rebate_vault_root(vaults: &[PrivateFeeRebateVault]) -> String {
    private_liquidity_rewards_record_root(
        "REBATE-VAULT-ROOT",
        &vaults
            .iter()
            .map(PrivateFeeRebateVault::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_reward_sponsor_root(sponsors: &[PrivateRewardSponsor]) -> String {
    private_liquidity_rewards_record_root(
        "SPONSOR-ROOT",
        &sponsors
            .iter()
            .map(PrivateRewardSponsor::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_reward_receipt_root(receipts: &[PrivateRewardReceipt]) -> String {
    private_liquidity_rewards_record_root(
        "RECEIPT-ROOT",
        &receipts
            .iter()
            .map(PrivateRewardReceipt::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_reward_event_root(events: &[PrivateRewardEvent]) -> String {
    private_liquidity_rewards_record_root(
        "EVENT-ROOT",
        &events
            .iter()
            .map(PrivateRewardEvent::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_liquidity_rewards_record_root(domain: &str, records: &[Value]) -> String {
    let mut roots = records
        .iter()
        .map(|record| private_liquidity_rewards_payload_root("RECORD", record))
        .collect::<Vec<_>>();
    roots.sort();
    private_liquidity_rewards_string_set_root(domain, &roots)
}
