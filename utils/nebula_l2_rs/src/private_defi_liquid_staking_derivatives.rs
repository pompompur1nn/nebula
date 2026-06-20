use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateDefiLiquidStakingDerivativesResult<T> = Result<T, String>;

pub const PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_PROTOCOL_VERSION: &str =
    "nebula-private-defi-liquid-staking-derivatives-v1";
pub const PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_PUBLIC_RECORD_SCHEME: &str =
    "deterministic-private-defi-liquid-staking-derivatives-public-record-v1";
pub const PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_STAKE_NOTE_SCHEME: &str =
    "shake256-shielded-stake-position-note-v1";
pub const PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_BASKET_SCHEME: &str =
    "weighted-validator-basket-commitment-v1";
pub const PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_TOKEN_SCHEME: &str =
    "private-liquid-staking-derivative-token-v1";
pub const PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_REWARD_SCHEME: &str =
    "zk-staking-reward-commitment-v1";
pub const PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_INSURANCE_SCHEME: &str =
    "confidential-slashing-insurance-pool-v1";
pub const PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_UNSTAKE_EXIT_SCHEME: &str =
    "low-fee-private-unstake-exit-v1";
pub const PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_NAV_ORACLE_SCHEME: &str =
    "threshold-zk-nav-oracle-snapshot-v1";
pub const PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_SETTLEMENT_RECEIPT_SCHEME: &str =
    "private-liquid-staking-settlement-receipt-v1";
pub const PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_DEVNET_HEIGHT: u64 = 768;
pub const PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_DEFAULT_EPOCH_BLOCKS: u64 = 120;
pub const PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_DEFAULT_NAV_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_DEFAULT_EXIT_TTL_BLOCKS: u64 = 240;
pub const PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 192;
pub const PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_MAX_BPS: u64 = 10_000;
pub const PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_NAV_SCALE: u64 = 1_000_000_000_000;
pub const PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_SHARE_SCALE: u64 = 1_000_000_000_000;
pub const PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_DEVNET_STAKE_ASSET_ID: &str = "wxmr-devnet";
pub const PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_DEVNET_DERIVATIVE_ASSET_ID: &str =
    "p-lsd-wxmr-devnet";
pub const PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_DEVNET_REWARD_ASSET_ID: &str =
    "wxmr-staking-reward-devnet";
pub const PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_DEFAULT_LOW_FEE_LANE: &str =
    "small-private-lsd-exit";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorStatus {
    Candidate,
    Active,
    Degraded,
    Jailed,
    Exiting,
    Retired,
}

impl ValidatorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::Degraded => "degraded",
            Self::Jailed => "jailed",
            Self::Exiting => "exiting",
            Self::Retired => "retired",
        }
    }

    pub fn allocatable(self) -> bool {
        matches!(self, Self::Candidate | Self::Active | Self::Degraded)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BasketStatus {
    Draft,
    Active,
    Rebalancing,
    ExitOnly,
    Frozen,
    Retired,
}

impl BasketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Rebalancing => "rebalancing",
            Self::ExitOnly => "exit_only",
            Self::Frozen => "frozen",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_stake(self) -> bool {
        matches!(self, Self::Active | Self::Rebalancing)
    }

    pub fn accepts_exit(self) -> bool {
        matches!(self, Self::Active | Self::Rebalancing | Self::ExitOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StakePositionStatus {
    Pending,
    Active,
    Compounding,
    ExitQueued,
    Exited,
    Slashed,
    Frozen,
}

impl StakePositionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Compounding => "compounding",
            Self::ExitQueued => "exit_queued",
            Self::Exited => "exited",
            Self::Slashed => "slashed",
            Self::Frozen => "frozen",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Pending | Self::Active | Self::Compounding | Self::ExitQueued
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivativeTokenStatus {
    Draft,
    Mintable,
    Transferable,
    RedeemOnly,
    Frozen,
    Retired,
}

impl DerivativeTokenStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Mintable => "mintable",
            Self::Transferable => "transferable",
            Self::RedeemOnly => "redeem_only",
            Self::Frozen => "frozen",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewardStatus {
    Accruing,
    Committed,
    Claimed,
    Compounded,
    Disputed,
    Expired,
}

impl RewardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accruing => "accruing",
            Self::Committed => "committed",
            Self::Claimed => "claimed",
            Self::Compounded => "compounded",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InsuranceStatus {
    Funding,
    Active,
    ClaimWindow,
    Settling,
    Exhausted,
    Retired,
}

impl InsuranceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Funding => "funding",
            Self::Active => "active",
            Self::ClaimWindow => "claim_window",
            Self::Settling => "settling",
            Self::Exhausted => "exhausted",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitStatus {
    Requested,
    Sponsored,
    Batched,
    Proving,
    Ready,
    Settled,
    Cancelled,
    Expired,
}

impl ExitStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Sponsored => "sponsored",
            Self::Batched => "batched",
            Self::Proving => "proving",
            Self::Ready => "ready",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Pending,
    Applied,
    Challenged,
    Reversed,
    Finalized,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Applied => "applied",
            Self::Challenged => "challenged",
            Self::Reversed => "reversed",
            Self::Finalized => "finalized",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub stake_asset_id: String,
    pub derivative_asset_id: String,
    pub reward_asset_id: String,
    pub epoch_blocks: u64,
    pub nav_ttl_blocks: u64,
    pub exit_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_validator_weight_bps: u64,
    pub insurance_reserve_bps: u64,
    pub low_fee_exit_lane: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            stake_asset_id: PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_DEVNET_STAKE_ASSET_ID
                .to_string(),
            derivative_asset_id: PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_DEVNET_DERIVATIVE_ASSET_ID
                .to_string(),
            reward_asset_id: PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_DEVNET_REWARD_ASSET_ID
                .to_string(),
            epoch_blocks: PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_DEFAULT_EPOCH_BLOCKS,
            nav_ttl_blocks: PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_DEFAULT_NAV_TTL_BLOCKS,
            exit_ttl_blocks: PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_DEFAULT_EXIT_TTL_BLOCKS,
            min_privacy_set_size:
                PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_validator_weight_bps: 4_000,
            insurance_reserve_bps: 1_250,
            low_fee_exit_lane: PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_DEFAULT_LOW_FEE_LANE
                .to_string(),
        }
    }
}

impl Config {
    pub fn validate(&self) -> PrivateDefiLiquidStakingDerivativesResult<()> {
        ensure_non_empty("protocol_version", &self.protocol_version)?;
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_non_empty("stake_asset_id", &self.stake_asset_id)?;
        ensure_non_empty("derivative_asset_id", &self.derivative_asset_id)?;
        ensure_non_empty("reward_asset_id", &self.reward_asset_id)?;
        ensure_non_empty("low_fee_exit_lane", &self.low_fee_exit_lane)?;
        ensure_positive("epoch_blocks", self.epoch_blocks)?;
        ensure_positive("nav_ttl_blocks", self.nav_ttl_blocks)?;
        ensure_positive("exit_ttl_blocks", self.exit_ttl_blocks)?;
        ensure_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        ensure_bps("max_validator_weight_bps", self.max_validator_weight_bps)?;
        ensure_bps("insurance_reserve_bps", self.insurance_reserve_bps)?;
        if self.min_pq_security_bits < 128 {
            return Err("min_pq_security_bits must be at least 128".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "stake_asset_id": self.stake_asset_id,
            "derivative_asset_id": self.derivative_asset_id,
            "reward_asset_id": self.reward_asset_id,
            "epoch_blocks": self.epoch_blocks,
            "nav_ttl_blocks": self.nav_ttl_blocks,
            "exit_ttl_blocks": self.exit_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_validator_weight_bps": self.max_validator_weight_bps,
            "insurance_reserve_bps": self.insurance_reserve_bps,
            "low_fee_exit_lane": self.low_fee_exit_lane,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorDescriptor {
    pub validator_id: String,
    pub operator_commitment: String,
    pub consensus_key_commitment: String,
    pub status: ValidatorStatus,
    pub commission_bps: u64,
    pub uptime_score_bps: u64,
    pub slash_risk_bps: u64,
    pub max_stake_units: u64,
    pub metadata_root: String,
}

impl ValidatorDescriptor {
    pub fn new(
        operator_commitment: impl Into<String>,
        consensus_key_commitment: impl Into<String>,
        status: ValidatorStatus,
        commission_bps: u64,
        uptime_score_bps: u64,
        slash_risk_bps: u64,
        max_stake_units: u64,
        metadata_root: impl Into<String>,
    ) -> Self {
        let operator_commitment = operator_commitment.into();
        let consensus_key_commitment = consensus_key_commitment.into();
        let metadata_root = metadata_root.into();
        let validator_id = validator_id(
            &operator_commitment,
            &consensus_key_commitment,
            commission_bps,
            max_stake_units,
            &metadata_root,
        );
        Self {
            validator_id,
            operator_commitment,
            consensus_key_commitment,
            status,
            commission_bps,
            uptime_score_bps,
            slash_risk_bps,
            max_stake_units,
            metadata_root,
        }
    }

    pub fn validate(&self) -> PrivateDefiLiquidStakingDerivativesResult<()> {
        ensure_non_empty("validator_id", &self.validator_id)?;
        ensure_non_empty("operator_commitment", &self.operator_commitment)?;
        ensure_non_empty("consensus_key_commitment", &self.consensus_key_commitment)?;
        ensure_non_empty("metadata_root", &self.metadata_root)?;
        ensure_bps("commission_bps", self.commission_bps)?;
        ensure_bps("uptime_score_bps", self.uptime_score_bps)?;
        ensure_bps("slash_risk_bps", self.slash_risk_bps)?;
        ensure_positive("max_stake_units", self.max_stake_units)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "validator_id": self.validator_id,
            "operator_commitment": self.operator_commitment,
            "consensus_key_commitment": self.consensus_key_commitment,
            "status": self.status.as_str(),
            "commission_bps": self.commission_bps,
            "uptime_score_bps": self.uptime_score_bps,
            "slash_risk_bps": self.slash_risk_bps,
            "max_stake_units": self.max_stake_units,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        payload_root("VALIDATOR-DESCRIPTOR", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorBasket {
    pub basket_id: String,
    pub manager_commitment: String,
    pub status: BasketStatus,
    pub validator_weights_bps: BTreeMap<String, u64>,
    pub target_stake_units: u64,
    pub rebalance_nonce: u64,
    pub risk_band: String,
    pub created_at_height: u64,
    pub updated_at_height: u64,
}

impl ValidatorBasket {
    pub fn new(
        manager_commitment: impl Into<String>,
        validator_weights_bps: BTreeMap<String, u64>,
        target_stake_units: u64,
        risk_band: impl Into<String>,
        created_at_height: u64,
    ) -> Self {
        let manager_commitment = manager_commitment.into();
        let risk_band = risk_band.into();
        let weights_root = map_u64_root("LSD-BASKET-WEIGHTS", &validator_weights_bps);
        let basket_id = domain_hash(
            "PRIVATE-DEFI-LSD-BASKET-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&manager_commitment),
                HashPart::Str(&weights_root),
                HashPart::Int(target_stake_units as i128),
                HashPart::Str(&risk_band),
                HashPart::Int(created_at_height as i128),
            ],
            32,
        );
        Self {
            basket_id,
            manager_commitment,
            status: BasketStatus::Active,
            validator_weights_bps,
            target_stake_units,
            rebalance_nonce: 0,
            risk_band,
            created_at_height,
            updated_at_height: created_at_height,
        }
    }

    pub fn validate(
        &self,
        validators: &BTreeMap<String, ValidatorDescriptor>,
        max_validator_weight_bps: u64,
    ) -> PrivateDefiLiquidStakingDerivativesResult<()> {
        ensure_non_empty("basket_id", &self.basket_id)?;
        ensure_non_empty("manager_commitment", &self.manager_commitment)?;
        ensure_non_empty("risk_band", &self.risk_band)?;
        ensure_positive("target_stake_units", self.target_stake_units)?;
        if self.updated_at_height < self.created_at_height {
            return Err(format!("basket {} updated before creation", self.basket_id));
        }
        let mut total_weight = 0_u64;
        for (validator_id, weight) in &self.validator_weights_bps {
            ensure_positive("validator_weight_bps", *weight)?;
            ensure_bps("validator_weight_bps", *weight)?;
            if *weight > max_validator_weight_bps {
                return Err(format!(
                    "basket {} validator {} exceeds max weight",
                    self.basket_id, validator_id
                ));
            }
            let validator = validators.get(validator_id).ok_or_else(|| {
                format!(
                    "basket {} references unknown validator {}",
                    self.basket_id, validator_id
                )
            })?;
            if !validator.status.allocatable() {
                return Err(format!(
                    "basket {} references non-allocatable validator {}",
                    self.basket_id, validator_id
                ));
            }
            total_weight = total_weight.saturating_add(*weight);
        }
        if total_weight != PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_MAX_BPS {
            return Err(format!(
                "basket {} weights must sum to 10000 bps",
                self.basket_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "basket_id": self.basket_id,
            "manager_commitment": self.manager_commitment,
            "status": self.status.as_str(),
            "validator_weights_bps": self.validator_weights_bps,
            "target_stake_units": self.target_stake_units,
            "rebalance_nonce": self.rebalance_nonce,
            "risk_band": self.risk_band,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
            "weights_root": map_u64_root("LSD-BASKET-WEIGHTS", &self.validator_weights_bps),
        })
    }

    pub fn root(&self) -> String {
        payload_root("VALIDATOR-BASKET", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedStakePosition {
    pub position_id: String,
    pub owner_commitment: String,
    pub stake_note_commitment: String,
    pub basket_id: String,
    pub derivative_token_id: String,
    pub stake_amount_commitment: String,
    pub stake_amount_bucket: u64,
    pub shares_minted_commitment: String,
    pub entry_nav_snapshot_id: String,
    pub nullifier_root: String,
    pub status: StakePositionStatus,
    pub opened_at_height: u64,
    pub unlock_after_height: u64,
}

impl ShieldedStakePosition {
    pub fn new(
        owner_commitment: impl Into<String>,
        basket_id: impl Into<String>,
        derivative_token_id: impl Into<String>,
        stake_amount_bucket: u64,
        entry_nav_snapshot_id: impl Into<String>,
        opened_at_height: u64,
        unlock_after_height: u64,
    ) -> Self {
        let owner_commitment = owner_commitment.into();
        let basket_id = basket_id.into();
        let derivative_token_id = derivative_token_id.into();
        let entry_nav_snapshot_id = entry_nav_snapshot_id.into();
        let stake_note_commitment = note_commitment(
            "STAKE-NOTE",
            &owner_commitment,
            &basket_id,
            stake_amount_bucket,
            opened_at_height,
        );
        let stake_amount_commitment = note_commitment(
            "STAKE-AMOUNT",
            &owner_commitment,
            &basket_id,
            stake_amount_bucket,
            unlock_after_height,
        );
        let shares_minted_commitment = note_commitment(
            "SHARES-MINTED",
            &owner_commitment,
            &derivative_token_id,
            stake_amount_bucket,
            opened_at_height,
        );
        let nullifier_root = payload_root(
            "STAKE-NULLIFIER-ROOT",
            &json!({
                "owner_commitment": owner_commitment,
                "stake_note_commitment": stake_note_commitment,
                "opened_at_height": opened_at_height,
            }),
        );
        let position_id = position_id(
            &owner_commitment,
            &basket_id,
            &derivative_token_id,
            &stake_note_commitment,
            opened_at_height,
        );
        Self {
            position_id,
            owner_commitment,
            stake_note_commitment,
            basket_id,
            derivative_token_id,
            stake_amount_commitment,
            stake_amount_bucket,
            shares_minted_commitment,
            entry_nav_snapshot_id,
            nullifier_root,
            status: StakePositionStatus::Active,
            opened_at_height,
            unlock_after_height,
        }
    }

    pub fn validate(&self) -> PrivateDefiLiquidStakingDerivativesResult<()> {
        ensure_non_empty("position_id", &self.position_id)?;
        ensure_non_empty("owner_commitment", &self.owner_commitment)?;
        ensure_non_empty("stake_note_commitment", &self.stake_note_commitment)?;
        ensure_non_empty("basket_id", &self.basket_id)?;
        ensure_non_empty("derivative_token_id", &self.derivative_token_id)?;
        ensure_non_empty("stake_amount_commitment", &self.stake_amount_commitment)?;
        ensure_non_empty("shares_minted_commitment", &self.shares_minted_commitment)?;
        ensure_non_empty("entry_nav_snapshot_id", &self.entry_nav_snapshot_id)?;
        ensure_non_empty("nullifier_root", &self.nullifier_root)?;
        ensure_positive("stake_amount_bucket", self.stake_amount_bucket)?;
        if self.unlock_after_height < self.opened_at_height {
            return Err(format!("position {} unlocks before open", self.position_id));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "position_id": self.position_id,
            "owner_commitment": self.owner_commitment,
            "stake_note_commitment": self.stake_note_commitment,
            "basket_id": self.basket_id,
            "derivative_token_id": self.derivative_token_id,
            "stake_amount_commitment": self.stake_amount_commitment,
            "stake_amount_bucket": self.stake_amount_bucket,
            "shares_minted_commitment": self.shares_minted_commitment,
            "entry_nav_snapshot_id": self.entry_nav_snapshot_id,
            "nullifier_root": self.nullifier_root,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "unlock_after_height": self.unlock_after_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("SHIELDED-STAKE-POSITION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDerivativeToken {
    pub token_id: String,
    pub basket_id: String,
    pub asset_id: String,
    pub supply_commitment: String,
    pub nav_snapshot_id: String,
    pub redemption_queue_root: String,
    pub transfer_policy_root: String,
    pub status: DerivativeTokenStatus,
    pub total_supply_bucket: u64,
    pub issued_at_height: u64,
}

impl PrivateDerivativeToken {
    pub fn new(
        basket_id: impl Into<String>,
        asset_id: impl Into<String>,
        nav_snapshot_id: impl Into<String>,
        total_supply_bucket: u64,
        issued_at_height: u64,
    ) -> Self {
        let basket_id = basket_id.into();
        let asset_id = asset_id.into();
        let nav_snapshot_id = nav_snapshot_id.into();
        let token_id =
            derivative_token_id(&basket_id, &asset_id, &nav_snapshot_id, issued_at_height);
        let supply_commitment = note_commitment(
            "DERIVATIVE-SUPPLY",
            &token_id,
            &asset_id,
            total_supply_bucket,
            issued_at_height,
        );
        let redemption_queue_root = merkle_root("LSD-EMPTY-REDEMPTION-QUEUE", &[]);
        let transfer_policy_root = payload_root(
            "LSD-TRANSFER-POLICY",
            &json!({
                "token_id": token_id,
                "private_transfers": true,
                "view_key_disclosure": "selective",
            }),
        );
        Self {
            token_id,
            basket_id,
            asset_id,
            supply_commitment,
            nav_snapshot_id,
            redemption_queue_root,
            transfer_policy_root,
            status: DerivativeTokenStatus::Transferable,
            total_supply_bucket,
            issued_at_height,
        }
    }

    pub fn validate(&self) -> PrivateDefiLiquidStakingDerivativesResult<()> {
        ensure_non_empty("token_id", &self.token_id)?;
        ensure_non_empty("basket_id", &self.basket_id)?;
        ensure_non_empty("asset_id", &self.asset_id)?;
        ensure_non_empty("supply_commitment", &self.supply_commitment)?;
        ensure_non_empty("nav_snapshot_id", &self.nav_snapshot_id)?;
        ensure_non_empty("redemption_queue_root", &self.redemption_queue_root)?;
        ensure_non_empty("transfer_policy_root", &self.transfer_policy_root)?;
        ensure_positive("total_supply_bucket", self.total_supply_bucket)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "token_id": self.token_id,
            "basket_id": self.basket_id,
            "asset_id": self.asset_id,
            "supply_commitment": self.supply_commitment,
            "nav_snapshot_id": self.nav_snapshot_id,
            "redemption_queue_root": self.redemption_queue_root,
            "transfer_policy_root": self.transfer_policy_root,
            "status": self.status.as_str(),
            "total_supply_bucket": self.total_supply_bucket,
            "issued_at_height": self.issued_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("PRIVATE-DERIVATIVE-TOKEN", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardCommitment {
    pub reward_id: String,
    pub position_id: String,
    pub reward_asset_id: String,
    pub reward_commitment: String,
    pub reward_amount_bucket: u64,
    pub epoch_start_height: u64,
    pub epoch_end_height: u64,
    pub validator_reward_root: String,
    pub status: RewardStatus,
}

impl RewardCommitment {
    pub fn new(
        position_id: impl Into<String>,
        reward_asset_id: impl Into<String>,
        reward_amount_bucket: u64,
        epoch_start_height: u64,
        epoch_end_height: u64,
        validator_reward_root: impl Into<String>,
    ) -> Self {
        let position_id = position_id.into();
        let reward_asset_id = reward_asset_id.into();
        let validator_reward_root = validator_reward_root.into();
        let reward_commitment = note_commitment(
            "REWARD-COMMITMENT",
            &position_id,
            &reward_asset_id,
            reward_amount_bucket,
            epoch_end_height,
        );
        let reward_id = reward_id(
            &position_id,
            &reward_asset_id,
            &reward_commitment,
            epoch_start_height,
            epoch_end_height,
        );
        Self {
            reward_id,
            position_id,
            reward_asset_id,
            reward_commitment,
            reward_amount_bucket,
            epoch_start_height,
            epoch_end_height,
            validator_reward_root,
            status: RewardStatus::Committed,
        }
    }

    pub fn validate(&self) -> PrivateDefiLiquidStakingDerivativesResult<()> {
        ensure_non_empty("reward_id", &self.reward_id)?;
        ensure_non_empty("position_id", &self.position_id)?;
        ensure_non_empty("reward_asset_id", &self.reward_asset_id)?;
        ensure_non_empty("reward_commitment", &self.reward_commitment)?;
        ensure_non_empty("validator_reward_root", &self.validator_reward_root)?;
        ensure_positive("reward_amount_bucket", self.reward_amount_bucket)?;
        if self.epoch_end_height <= self.epoch_start_height {
            return Err(format!("reward {} has invalid epoch range", self.reward_id));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reward_id": self.reward_id,
            "position_id": self.position_id,
            "reward_asset_id": self.reward_asset_id,
            "reward_commitment": self.reward_commitment,
            "reward_amount_bucket": self.reward_amount_bucket,
            "epoch_start_height": self.epoch_start_height,
            "epoch_end_height": self.epoch_end_height,
            "validator_reward_root": self.validator_reward_root,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        payload_root("REWARD-COMMITMENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingInsurancePool {
    pub pool_id: String,
    pub basket_id: String,
    pub underwriter_commitment: String,
    pub insured_validator_ids: BTreeSet<String>,
    pub reserve_commitment: String,
    pub reserve_bucket: u64,
    pub coverage_bps: u64,
    pub deductible_bps: u64,
    pub claim_window_blocks: u64,
    pub status: InsuranceStatus,
    pub opened_at_height: u64,
}

impl SlashingInsurancePool {
    pub fn new(
        basket_id: impl Into<String>,
        underwriter_commitment: impl Into<String>,
        insured_validator_ids: BTreeSet<String>,
        reserve_bucket: u64,
        coverage_bps: u64,
        deductible_bps: u64,
        claim_window_blocks: u64,
        opened_at_height: u64,
    ) -> Self {
        let basket_id = basket_id.into();
        let underwriter_commitment = underwriter_commitment.into();
        let insured_root = set_root("LSD-INSURED-VALIDATORS", &insured_validator_ids);
        let reserve_commitment = note_commitment(
            "INSURANCE-RESERVE",
            &basket_id,
            &underwriter_commitment,
            reserve_bucket,
            opened_at_height,
        );
        let pool_id = domain_hash(
            "PRIVATE-DEFI-LSD-INSURANCE-POOL-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&basket_id),
                HashPart::Str(&underwriter_commitment),
                HashPart::Str(&insured_root),
                HashPart::Int(reserve_bucket as i128),
                HashPart::Int(opened_at_height as i128),
            ],
            32,
        );
        Self {
            pool_id,
            basket_id,
            underwriter_commitment,
            insured_validator_ids,
            reserve_commitment,
            reserve_bucket,
            coverage_bps,
            deductible_bps,
            claim_window_blocks,
            status: InsuranceStatus::Active,
            opened_at_height,
        }
    }

    pub fn validate(&self) -> PrivateDefiLiquidStakingDerivativesResult<()> {
        ensure_non_empty("pool_id", &self.pool_id)?;
        ensure_non_empty("basket_id", &self.basket_id)?;
        ensure_non_empty("underwriter_commitment", &self.underwriter_commitment)?;
        ensure_non_empty("reserve_commitment", &self.reserve_commitment)?;
        ensure_positive("reserve_bucket", self.reserve_bucket)?;
        ensure_positive("claim_window_blocks", self.claim_window_blocks)?;
        ensure_bps("coverage_bps", self.coverage_bps)?;
        ensure_bps("deductible_bps", self.deductible_bps)?;
        if self.coverage_bps <= self.deductible_bps {
            return Err(format!(
                "insurance pool {} coverage must exceed deductible",
                self.pool_id
            ));
        }
        if self.insured_validator_ids.is_empty() {
            return Err(format!("insurance pool {} has no validators", self.pool_id));
        }
        for validator_id in &self.insured_validator_ids {
            ensure_non_empty("insured_validator_id", validator_id)?;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "basket_id": self.basket_id,
            "underwriter_commitment": self.underwriter_commitment,
            "insured_validator_ids": self.insured_validator_ids,
            "insured_validator_root": set_root("LSD-INSURED-VALIDATORS", &self.insured_validator_ids),
            "reserve_commitment": self.reserve_commitment,
            "reserve_bucket": self.reserve_bucket,
            "coverage_bps": self.coverage_bps,
            "deductible_bps": self.deductible_bps,
            "claim_window_blocks": self.claim_window_blocks,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("SLASHING-INSURANCE-POOL", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeUnstakeExit {
    pub exit_id: String,
    pub position_id: String,
    pub owner_nullifier: String,
    pub derivative_token_id: String,
    pub exit_amount_commitment: String,
    pub exit_amount_bucket: u64,
    pub fee_sponsor_commitment: String,
    pub max_fee_units: u64,
    pub low_fee_lane: String,
    pub requested_at_height: u64,
    pub executable_at_height: u64,
    pub expires_at_height: u64,
    pub status: ExitStatus,
}

impl LowFeeUnstakeExit {
    pub fn new(
        position_id: impl Into<String>,
        owner_nullifier: impl Into<String>,
        derivative_token_id: impl Into<String>,
        exit_amount_bucket: u64,
        fee_sponsor_commitment: impl Into<String>,
        max_fee_units: u64,
        low_fee_lane: impl Into<String>,
        requested_at_height: u64,
        exit_ttl_blocks: u64,
    ) -> Self {
        let position_id = position_id.into();
        let owner_nullifier = owner_nullifier.into();
        let derivative_token_id = derivative_token_id.into();
        let fee_sponsor_commitment = fee_sponsor_commitment.into();
        let low_fee_lane = low_fee_lane.into();
        let executable_at_height = requested_at_height.saturating_add(6);
        let expires_at_height = requested_at_height.saturating_add(exit_ttl_blocks);
        let exit_amount_commitment = note_commitment(
            "UNSTAKE-EXIT-AMOUNT",
            &position_id,
            &derivative_token_id,
            exit_amount_bucket,
            requested_at_height,
        );
        let exit_id = exit_id(
            &position_id,
            &owner_nullifier,
            &exit_amount_commitment,
            requested_at_height,
        );
        Self {
            exit_id,
            position_id,
            owner_nullifier,
            derivative_token_id,
            exit_amount_commitment,
            exit_amount_bucket,
            fee_sponsor_commitment,
            max_fee_units,
            low_fee_lane,
            requested_at_height,
            executable_at_height,
            expires_at_height,
            status: ExitStatus::Sponsored,
        }
    }

    pub fn validate(&self) -> PrivateDefiLiquidStakingDerivativesResult<()> {
        ensure_non_empty("exit_id", &self.exit_id)?;
        ensure_non_empty("position_id", &self.position_id)?;
        ensure_non_empty("owner_nullifier", &self.owner_nullifier)?;
        ensure_non_empty("derivative_token_id", &self.derivative_token_id)?;
        ensure_non_empty("exit_amount_commitment", &self.exit_amount_commitment)?;
        ensure_non_empty("fee_sponsor_commitment", &self.fee_sponsor_commitment)?;
        ensure_non_empty("low_fee_lane", &self.low_fee_lane)?;
        ensure_positive("exit_amount_bucket", self.exit_amount_bucket)?;
        if self.executable_at_height < self.requested_at_height {
            return Err(format!("exit {} executable before request", self.exit_id));
        }
        if self.expires_at_height <= self.executable_at_height {
            return Err(format!(
                "exit {} expires before executable window",
                self.exit_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "exit_id": self.exit_id,
            "position_id": self.position_id,
            "owner_nullifier": self.owner_nullifier,
            "derivative_token_id": self.derivative_token_id,
            "exit_amount_commitment": self.exit_amount_commitment,
            "exit_amount_bucket": self.exit_amount_bucket,
            "fee_sponsor_commitment": self.fee_sponsor_commitment,
            "max_fee_units": self.max_fee_units,
            "low_fee_lane": self.low_fee_lane,
            "requested_at_height": self.requested_at_height,
            "executable_at_height": self.executable_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        payload_root("LOW-FEE-UNSTAKE-EXIT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkNavOracleSnapshot {
    pub snapshot_id: String,
    pub basket_id: String,
    pub oracle_committee_root: String,
    pub nav_per_share_scaled: u64,
    pub total_stake_bucket: u64,
    pub total_derivative_supply_bucket: u64,
    pub reward_index_scaled: u64,
    pub slash_index_scaled: u64,
    pub confidence_bps: u64,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
    pub proof_root: String,
}

impl ZkNavOracleSnapshot {
    pub fn new(
        basket_id: impl Into<String>,
        oracle_committee_root: impl Into<String>,
        nav_per_share_scaled: u64,
        total_stake_bucket: u64,
        total_derivative_supply_bucket: u64,
        reward_index_scaled: u64,
        slash_index_scaled: u64,
        confidence_bps: u64,
        observed_at_height: u64,
        nav_ttl_blocks: u64,
    ) -> Self {
        let basket_id = basket_id.into();
        let oracle_committee_root = oracle_committee_root.into();
        let expires_at_height = observed_at_height.saturating_add(nav_ttl_blocks);
        let proof_root = payload_root(
            "ZK-NAV-PROOF",
            &json!({
                "basket_id": basket_id,
                "nav_per_share_scaled": nav_per_share_scaled,
                "total_stake_bucket": total_stake_bucket,
                "total_derivative_supply_bucket": total_derivative_supply_bucket,
                "reward_index_scaled": reward_index_scaled,
                "slash_index_scaled": slash_index_scaled,
                "observed_at_height": observed_at_height,
            }),
        );
        let snapshot_id = nav_snapshot_id(
            &basket_id,
            &oracle_committee_root,
            nav_per_share_scaled,
            observed_at_height,
        );
        Self {
            snapshot_id,
            basket_id,
            oracle_committee_root,
            nav_per_share_scaled,
            total_stake_bucket,
            total_derivative_supply_bucket,
            reward_index_scaled,
            slash_index_scaled,
            confidence_bps,
            observed_at_height,
            expires_at_height,
            proof_root,
        }
    }

    pub fn validate(&self) -> PrivateDefiLiquidStakingDerivativesResult<()> {
        ensure_non_empty("snapshot_id", &self.snapshot_id)?;
        ensure_non_empty("basket_id", &self.basket_id)?;
        ensure_non_empty("oracle_committee_root", &self.oracle_committee_root)?;
        ensure_non_empty("proof_root", &self.proof_root)?;
        ensure_positive("nav_per_share_scaled", self.nav_per_share_scaled)?;
        ensure_positive("total_stake_bucket", self.total_stake_bucket)?;
        ensure_positive(
            "total_derivative_supply_bucket",
            self.total_derivative_supply_bucket,
        )?;
        ensure_bps("confidence_bps", self.confidence_bps)?;
        if self.expires_at_height <= self.observed_at_height {
            return Err(format!("nav snapshot {} has invalid ttl", self.snapshot_id));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "basket_id": self.basket_id,
            "oracle_committee_root": self.oracle_committee_root,
            "nav_per_share_scaled": self.nav_per_share_scaled,
            "total_stake_bucket": self.total_stake_bucket,
            "total_derivative_supply_bucket": self.total_derivative_supply_bucket,
            "reward_index_scaled": self.reward_index_scaled,
            "slash_index_scaled": self.slash_index_scaled,
            "confidence_bps": self.confidence_bps,
            "observed_at_height": self.observed_at_height,
            "expires_at_height": self.expires_at_height,
            "proof_root": self.proof_root,
        })
    }

    pub fn root(&self) -> String {
        payload_root("ZK-NAV-ORACLE-SNAPSHOT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub exit_id: String,
    pub position_id: String,
    pub basket_id: String,
    pub derivative_token_id: String,
    pub nav_snapshot_id: String,
    pub burned_share_commitment: String,
    pub released_stake_commitment: String,
    pub reward_release_commitment: String,
    pub insurance_claim_commitment: String,
    pub fee_receipt_root: String,
    pub settled_at_height: u64,
    pub status: SettlementStatus,
}

impl SettlementReceipt {
    pub fn new(
        exit_id: impl Into<String>,
        position_id: impl Into<String>,
        basket_id: impl Into<String>,
        derivative_token_id: impl Into<String>,
        nav_snapshot_id: impl Into<String>,
        settlement_bucket: u64,
        fee_receipt_root: impl Into<String>,
        settled_at_height: u64,
    ) -> Self {
        let exit_id = exit_id.into();
        let position_id = position_id.into();
        let basket_id = basket_id.into();
        let derivative_token_id = derivative_token_id.into();
        let nav_snapshot_id = nav_snapshot_id.into();
        let fee_receipt_root = fee_receipt_root.into();
        let burned_share_commitment = note_commitment(
            "BURNED-LSD-SHARE",
            &exit_id,
            &derivative_token_id,
            settlement_bucket,
            settled_at_height,
        );
        let released_stake_commitment = note_commitment(
            "RELEASED-STAKE",
            &exit_id,
            &basket_id,
            settlement_bucket,
            settled_at_height,
        );
        let reward_release_commitment = note_commitment(
            "REWARD-RELEASE",
            &position_id,
            &nav_snapshot_id,
            settlement_bucket / 20,
            settled_at_height,
        );
        let insurance_claim_commitment = note_commitment(
            "INSURANCE-CLAIM",
            &position_id,
            &basket_id,
            settlement_bucket / 100,
            settled_at_height,
        );
        let receipt_id = receipt_id(
            &exit_id,
            &position_id,
            &burned_share_commitment,
            &released_stake_commitment,
            settled_at_height,
        );
        Self {
            receipt_id,
            exit_id,
            position_id,
            basket_id,
            derivative_token_id,
            nav_snapshot_id,
            burned_share_commitment,
            released_stake_commitment,
            reward_release_commitment,
            insurance_claim_commitment,
            fee_receipt_root,
            settled_at_height,
            status: SettlementStatus::Finalized,
        }
    }

    pub fn validate(&self) -> PrivateDefiLiquidStakingDerivativesResult<()> {
        ensure_non_empty("receipt_id", &self.receipt_id)?;
        ensure_non_empty("exit_id", &self.exit_id)?;
        ensure_non_empty("position_id", &self.position_id)?;
        ensure_non_empty("basket_id", &self.basket_id)?;
        ensure_non_empty("derivative_token_id", &self.derivative_token_id)?;
        ensure_non_empty("nav_snapshot_id", &self.nav_snapshot_id)?;
        ensure_non_empty("burned_share_commitment", &self.burned_share_commitment)?;
        ensure_non_empty("released_stake_commitment", &self.released_stake_commitment)?;
        ensure_non_empty("reward_release_commitment", &self.reward_release_commitment)?;
        ensure_non_empty(
            "insurance_claim_commitment",
            &self.insurance_claim_commitment,
        )?;
        ensure_non_empty("fee_receipt_root", &self.fee_receipt_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "exit_id": self.exit_id,
            "position_id": self.position_id,
            "basket_id": self.basket_id,
            "derivative_token_id": self.derivative_token_id,
            "nav_snapshot_id": self.nav_snapshot_id,
            "burned_share_commitment": self.burned_share_commitment,
            "released_stake_commitment": self.released_stake_commitment,
            "reward_release_commitment": self.reward_release_commitment,
            "insurance_claim_commitment": self.insurance_claim_commitment,
            "fee_receipt_root": self.fee_receipt_root,
            "settled_at_height": self.settled_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        payload_root("SETTLEMENT-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub validator_root: String,
    pub basket_root: String,
    pub stake_position_root: String,
    pub derivative_token_root: String,
    pub reward_commitment_root: String,
    pub insurance_pool_root: String,
    pub unstake_exit_root: String,
    pub nav_oracle_snapshot_root: String,
    pub settlement_receipt_root: String,
    pub nullifier_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "validator_root": self.validator_root,
            "basket_root": self.basket_root,
            "stake_position_root": self.stake_position_root,
            "derivative_token_root": self.derivative_token_root,
            "reward_commitment_root": self.reward_commitment_root,
            "insurance_pool_root": self.insurance_pool_root,
            "unstake_exit_root": self.unstake_exit_root,
            "nav_oracle_snapshot_root": self.nav_oracle_snapshot_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "nullifier_root": self.nullifier_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub validators: u64,
    pub validator_baskets: u64,
    pub shielded_stake_positions: u64,
    pub private_derivative_tokens: u64,
    pub reward_commitments: u64,
    pub slashing_insurance_pools: u64,
    pub low_fee_unstake_exits: u64,
    pub zk_nav_oracle_snapshots: u64,
    pub settlement_receipts: u64,
    pub live_positions: u64,
    pub queued_exits: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "validators": self.validators,
            "validator_baskets": self.validator_baskets,
            "shielded_stake_positions": self.shielded_stake_positions,
            "private_derivative_tokens": self.private_derivative_tokens,
            "reward_commitments": self.reward_commitments,
            "slashing_insurance_pools": self.slashing_insurance_pools,
            "low_fee_unstake_exits": self.low_fee_unstake_exits,
            "zk_nav_oracle_snapshots": self.zk_nav_oracle_snapshots,
            "settlement_receipts": self.settlement_receipts,
            "live_positions": self.live_positions,
            "queued_exits": self.queued_exits,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub validators: BTreeMap<String, ValidatorDescriptor>,
    pub validator_baskets: BTreeMap<String, ValidatorBasket>,
    pub shielded_stake_positions: BTreeMap<String, ShieldedStakePosition>,
    pub private_derivative_tokens: BTreeMap<String, PrivateDerivativeToken>,
    pub reward_commitments: BTreeMap<String, RewardCommitment>,
    pub slashing_insurance_pools: BTreeMap<String, SlashingInsurancePool>,
    pub low_fee_unstake_exits: BTreeMap<String, LowFeeUnstakeExit>,
    pub zk_nav_oracle_snapshots: BTreeMap<String, ZkNavOracleSnapshot>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> PrivateDefiLiquidStakingDerivativesResult<State> {
        let config = Config::default();
        config.validate()?;
        let height = PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_DEVNET_HEIGHT;

        let validator_a = ValidatorDescriptor::new(
            "operator-commitment-alpha",
            "consensus-key-commitment-alpha",
            ValidatorStatus::Active,
            350,
            9_920,
            45,
            75_000_000_000,
            payload_root(
                "VALIDATOR-METADATA",
                &json!({"region": "devnet-a", "tier": "blue"}),
            ),
        );
        let validator_b = ValidatorDescriptor::new(
            "operator-commitment-beta",
            "consensus-key-commitment-beta",
            ValidatorStatus::Active,
            420,
            9_880,
            60,
            60_000_000_000,
            payload_root(
                "VALIDATOR-METADATA",
                &json!({"region": "devnet-b", "tier": "green"}),
            ),
        );
        let validator_c = ValidatorDescriptor::new(
            "operator-commitment-gamma",
            "consensus-key-commitment-gamma",
            ValidatorStatus::Degraded,
            250,
            9_640,
            95,
            50_000_000_000,
            payload_root(
                "VALIDATOR-METADATA",
                &json!({"region": "devnet-c", "tier": "amber"}),
            ),
        );

        let mut validators = BTreeMap::new();
        validators.insert(validator_a.validator_id.clone(), validator_a.clone());
        validators.insert(validator_b.validator_id.clone(), validator_b.clone());
        validators.insert(validator_c.validator_id.clone(), validator_c.clone());

        let mut weights = BTreeMap::new();
        weights.insert(validator_a.validator_id.clone(), 3_800);
        weights.insert(validator_b.validator_id.clone(), 3_500);
        weights.insert(validator_c.validator_id.clone(), 2_700);
        let basket = ValidatorBasket::new(
            "basket-manager-commitment-devnet",
            weights,
            100_000_000_000,
            "balanced-private-yield",
            height.saturating_sub(72),
        );

        let oracle_committee_root = merkle_root(
            "LSD-ORACLE-COMMITTEE",
            &[
                Value::String("oracle-commitment-alpha".to_string()),
                Value::String("oracle-commitment-beta".to_string()),
                Value::String("oracle-commitment-gamma".to_string()),
            ],
        );
        let nav = ZkNavOracleSnapshot::new(
            basket.basket_id.clone(),
            oracle_committee_root,
            PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_NAV_SCALE + 18_500_000_000,
            100_000_000_000,
            98_183_000_000,
            PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_SHARE_SCALE + 12_000_000_000,
            PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_SHARE_SCALE - 2_500_000_000,
            9_850,
            height.saturating_sub(2),
            config.nav_ttl_blocks,
        );
        let token = PrivateDerivativeToken::new(
            basket.basket_id.clone(),
            config.derivative_asset_id.clone(),
            nav.snapshot_id.clone(),
            98_183_000_000,
            height.saturating_sub(70),
        );
        let position = ShieldedStakePosition::new(
            "owner-commitment-devnet-alice",
            basket.basket_id.clone(),
            token.token_id.clone(),
            12_500_000_000,
            nav.snapshot_id.clone(),
            height.saturating_sub(64),
            height.saturating_add(24),
        );
        let reward = RewardCommitment::new(
            position.position_id.clone(),
            config.reward_asset_id.clone(),
            82_000_000,
            height.saturating_sub(config.epoch_blocks),
            height,
            map_u64_root(
                "LSD-VALIDATOR-REWARD-BUCKETS",
                &BTreeMap::from([
                    (validator_a.validator_id.clone(), 31_000_000),
                    (validator_b.validator_id.clone(), 29_000_000),
                    (validator_c.validator_id.clone(), 22_000_000),
                ]),
            ),
        );
        let insured = BTreeSet::from([
            validator_a.validator_id.clone(),
            validator_b.validator_id.clone(),
            validator_c.validator_id.clone(),
        ]);
        let insurance = SlashingInsurancePool::new(
            basket.basket_id.clone(),
            "underwriter-commitment-devnet",
            insured,
            2_000_000_000,
            8_000,
            500,
            360,
            height.saturating_sub(60),
        );
        let unstake_exit = LowFeeUnstakeExit::new(
            position.position_id.clone(),
            "owner-nullifier-devnet-alice-0",
            token.token_id.clone(),
            1_250_000_000,
            "fee-sponsor-commitment-devnet",
            12_000,
            config.low_fee_exit_lane.clone(),
            height.saturating_sub(3),
            config.exit_ttl_blocks,
        );
        let receipt = SettlementReceipt::new(
            unstake_exit.exit_id.clone(),
            position.position_id.clone(),
            basket.basket_id.clone(),
            token.token_id.clone(),
            nav.snapshot_id.clone(),
            1_250_000_000,
            payload_root(
                "LOW-FEE-EXIT-FEE-RECEIPT",
                &json!({
                    "exit_id": unstake_exit.exit_id,
                    "sponsor": "fee-sponsor-commitment-devnet",
                    "charged_fee_units": 8_400_u64,
                }),
            ),
            height,
        );

        let mut validator_baskets = BTreeMap::new();
        validator_baskets.insert(basket.basket_id.clone(), basket);
        let mut zk_nav_oracle_snapshots = BTreeMap::new();
        zk_nav_oracle_snapshots.insert(nav.snapshot_id.clone(), nav);
        let mut private_derivative_tokens = BTreeMap::new();
        private_derivative_tokens.insert(token.token_id.clone(), token);
        let mut shielded_stake_positions = BTreeMap::new();
        shielded_stake_positions.insert(position.position_id.clone(), position);
        let mut reward_commitments = BTreeMap::new();
        reward_commitments.insert(reward.reward_id.clone(), reward);
        let mut slashing_insurance_pools = BTreeMap::new();
        slashing_insurance_pools.insert(insurance.pool_id.clone(), insurance);
        let mut low_fee_unstake_exits = BTreeMap::new();
        low_fee_unstake_exits.insert(unstake_exit.exit_id.clone(), unstake_exit);
        let mut settlement_receipts = BTreeMap::new();
        settlement_receipts.insert(receipt.receipt_id.clone(), receipt);

        let state = Self {
            config,
            height,
            validators,
            validator_baskets,
            shielded_stake_positions,
            private_derivative_tokens,
            reward_commitments,
            slashing_insurance_pools,
            low_fee_unstake_exits,
            zk_nav_oracle_snapshots,
            settlement_receipts,
            spent_nullifiers: BTreeSet::from(["owner-nullifier-devnet-alice-0".to_string()]),
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> PrivateDefiLiquidStakingDerivativesResult<()> {
        self.config.validate()?;
        for (id, validator) in &self.validators {
            if id != &validator.validator_id {
                return Err(format!("validator key mismatch for {}", id));
            }
            validator.validate()?;
        }
        for (id, basket) in &self.validator_baskets {
            if id != &basket.basket_id {
                return Err(format!("basket key mismatch for {}", id));
            }
            basket.validate(&self.validators, self.config.max_validator_weight_bps)?;
        }
        for (id, snapshot) in &self.zk_nav_oracle_snapshots {
            if id != &snapshot.snapshot_id {
                return Err(format!("nav snapshot key mismatch for {}", id));
            }
            snapshot.validate()?;
            ensure_known(
                &self.validator_baskets,
                &snapshot.basket_id,
                "nav snapshot basket",
            )?;
        }
        for (id, token) in &self.private_derivative_tokens {
            if id != &token.token_id {
                return Err(format!("token key mismatch for {}", id));
            }
            token.validate()?;
            ensure_known(&self.validator_baskets, &token.basket_id, "token basket")?;
            ensure_known(
                &self.zk_nav_oracle_snapshots,
                &token.nav_snapshot_id,
                "token nav snapshot",
            )?;
        }
        for (id, position) in &self.shielded_stake_positions {
            if id != &position.position_id {
                return Err(format!("position key mismatch for {}", id));
            }
            position.validate()?;
            ensure_known(
                &self.validator_baskets,
                &position.basket_id,
                "position basket",
            )?;
            ensure_known(
                &self.private_derivative_tokens,
                &position.derivative_token_id,
                "position token",
            )?;
            ensure_known(
                &self.zk_nav_oracle_snapshots,
                &position.entry_nav_snapshot_id,
                "position nav snapshot",
            )?;
        }
        for (id, reward) in &self.reward_commitments {
            if id != &reward.reward_id {
                return Err(format!("reward key mismatch for {}", id));
            }
            reward.validate()?;
            ensure_known(
                &self.shielded_stake_positions,
                &reward.position_id,
                "reward position",
            )?;
        }
        for (id, pool) in &self.slashing_insurance_pools {
            if id != &pool.pool_id {
                return Err(format!("insurance key mismatch for {}", id));
            }
            pool.validate()?;
            ensure_known(&self.validator_baskets, &pool.basket_id, "insurance basket")?;
            for validator_id in &pool.insured_validator_ids {
                ensure_known(&self.validators, validator_id, "insurance validator")?;
            }
        }
        for (id, exit) in &self.low_fee_unstake_exits {
            if id != &exit.exit_id {
                return Err(format!("exit key mismatch for {}", id));
            }
            exit.validate()?;
            ensure_known(
                &self.shielded_stake_positions,
                &exit.position_id,
                "exit position",
            )?;
            ensure_known(
                &self.private_derivative_tokens,
                &exit.derivative_token_id,
                "exit token",
            )?;
        }
        for (id, receipt) in &self.settlement_receipts {
            if id != &receipt.receipt_id {
                return Err(format!("receipt key mismatch for {}", id));
            }
            receipt.validate()?;
            ensure_known(
                &self.low_fee_unstake_exits,
                &receipt.exit_id,
                "receipt exit",
            )?;
            ensure_known(
                &self.shielded_stake_positions,
                &receipt.position_id,
                "receipt position",
            )?;
            ensure_known(
                &self.private_derivative_tokens,
                &receipt.derivative_token_id,
                "receipt token",
            )?;
            ensure_known(
                &self.zk_nav_oracle_snapshots,
                &receipt.nav_snapshot_id,
                "receipt nav snapshot",
            )?;
            ensure_known(
                &self.validator_baskets,
                &receipt.basket_id,
                "receipt basket",
            )?;
        }
        for nullifier in &self.spent_nullifiers {
            ensure_non_empty("spent_nullifier", nullifier)?;
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> PrivateDefiLiquidStakingDerivativesResult<()> {
        self.height = height;
        self.validate()
    }

    pub fn update_height(&mut self, height: u64) -> PrivateDefiLiquidStakingDerivativesResult<()> {
        if height < self.height {
            return Err(format!(
                "height cannot move backwards from {} to {}",
                self.height, height
            ));
        }
        self.set_height(height)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            validator_root: map_root(
                "LSD-VALIDATORS",
                self.validators
                    .values()
                    .map(ValidatorDescriptor::public_record)
                    .collect(),
            ),
            basket_root: map_root(
                "LSD-VALIDATOR-BASKETS",
                self.validator_baskets
                    .values()
                    .map(ValidatorBasket::public_record)
                    .collect(),
            ),
            stake_position_root: map_root(
                "LSD-SHIELDED-STAKE-POSITIONS",
                self.shielded_stake_positions
                    .values()
                    .map(ShieldedStakePosition::public_record)
                    .collect(),
            ),
            derivative_token_root: map_root(
                "LSD-PRIVATE-DERIVATIVE-TOKENS",
                self.private_derivative_tokens
                    .values()
                    .map(PrivateDerivativeToken::public_record)
                    .collect(),
            ),
            reward_commitment_root: map_root(
                "LSD-REWARD-COMMITMENTS",
                self.reward_commitments
                    .values()
                    .map(RewardCommitment::public_record)
                    .collect(),
            ),
            insurance_pool_root: map_root(
                "LSD-SLASHING-INSURANCE-POOLS",
                self.slashing_insurance_pools
                    .values()
                    .map(SlashingInsurancePool::public_record)
                    .collect(),
            ),
            unstake_exit_root: map_root(
                "LSD-LOW-FEE-UNSTAKE-EXITS",
                self.low_fee_unstake_exits
                    .values()
                    .map(LowFeeUnstakeExit::public_record)
                    .collect(),
            ),
            nav_oracle_snapshot_root: map_root(
                "LSD-ZK-NAV-ORACLE-SNAPSHOTS",
                self.zk_nav_oracle_snapshots
                    .values()
                    .map(ZkNavOracleSnapshot::public_record)
                    .collect(),
            ),
            settlement_receipt_root: map_root(
                "LSD-SETTLEMENT-RECEIPTS",
                self.settlement_receipts
                    .values()
                    .map(SettlementReceipt::public_record)
                    .collect(),
            ),
            nullifier_root: set_root("LSD-SPENT-NULLIFIERS", &self.spent_nullifiers),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            validators: self.validators.len() as u64,
            validator_baskets: self.validator_baskets.len() as u64,
            shielded_stake_positions: self.shielded_stake_positions.len() as u64,
            private_derivative_tokens: self.private_derivative_tokens.len() as u64,
            reward_commitments: self.reward_commitments.len() as u64,
            slashing_insurance_pools: self.slashing_insurance_pools.len() as u64,
            low_fee_unstake_exits: self.low_fee_unstake_exits.len() as u64,
            zk_nav_oracle_snapshots: self.zk_nav_oracle_snapshots.len() as u64,
            settlement_receipts: self.settlement_receipts.len() as u64,
            live_positions: self
                .shielded_stake_positions
                .values()
                .filter(|position| position.status.live())
                .count() as u64,
            queued_exits: self
                .low_fee_unstake_exits
                .values()
                .filter(|exit| {
                    matches!(
                        exit.status,
                        ExitStatus::Requested
                            | ExitStatus::Sponsored
                            | ExitStatus::Batched
                            | ExitStatus::Proving
                            | ExitStatus::Ready
                    )
                })
                .count() as u64,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        let mut record = self.public_record_without_root(roots, counters);
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        root_from_record(&self.public_record_without_root(self.roots(), self.counters()))
    }

    fn public_record_without_root(&self, roots: Roots, counters: Counters) -> Value {
        json!({
            "scheme": PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_PUBLIC_RECORD_SCHEME,
            "config": self.config.public_record(),
            "height": self.height,
            "roots": roots.public_record(),
            "counters": counters.public_record(),
        })
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-DEFI-LIQUID-STAKING-DERIVATIVES-STATE-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn devnet() -> PrivateDefiLiquidStakingDerivativesResult<State> {
    State::devnet()
}

fn ensure_non_empty(field: &str, value: &str) -> PrivateDefiLiquidStakingDerivativesResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    Ok(())
}

fn ensure_positive(field: &str, value: u64) -> PrivateDefiLiquidStakingDerivativesResult<()> {
    if value == 0 {
        return Err(format!("{field} must be positive"));
    }
    Ok(())
}

fn ensure_bps(field: &str, value: u64) -> PrivateDefiLiquidStakingDerivativesResult<()> {
    if value > PRIVATE_DEFI_LIQUID_STAKING_DERIVATIVES_MAX_BPS {
        return Err(format!("{field} exceeds 10000 bps"));
    }
    Ok(())
}

fn ensure_known<T>(
    map: &BTreeMap<String, T>,
    key: &str,
    label: &str,
) -> PrivateDefiLiquidStakingDerivativesResult<()> {
    if !map.contains_key(key) {
        return Err(format!("{label} references unknown id {key}"));
    }
    Ok(())
}

fn payload_root(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(value)],
        32,
    )
}

fn map_root(domain: &str, values: Vec<Value>) -> String {
    merkle_root(domain, &values)
}

fn set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values
        .iter()
        .map(|value| Value::String(value.clone()))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn map_u64_root(domain: &str, values: &BTreeMap<String, u64>) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| json!({"key": key, "value": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn validator_id(
    operator_commitment: &str,
    consensus_key_commitment: &str,
    commission_bps: u64,
    max_stake_units: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-DEFI-LSD-VALIDATOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_commitment),
            HashPart::Str(consensus_key_commitment),
            HashPart::Int(commission_bps as i128),
            HashPart::Int(max_stake_units as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

fn derivative_token_id(
    basket_id: &str,
    asset_id: &str,
    nav_snapshot_id: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEFI-LSD-DERIVATIVE-TOKEN-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(basket_id),
            HashPart::Str(asset_id),
            HashPart::Str(nav_snapshot_id),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

fn position_id(
    owner_commitment: &str,
    basket_id: &str,
    derivative_token_id: &str,
    stake_note_commitment: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEFI-LSD-POSITION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Str(basket_id),
            HashPart::Str(derivative_token_id),
            HashPart::Str(stake_note_commitment),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

fn reward_id(
    position_id: &str,
    reward_asset_id: &str,
    reward_commitment: &str,
    epoch_start_height: u64,
    epoch_end_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEFI-LSD-REWARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(position_id),
            HashPart::Str(reward_asset_id),
            HashPart::Str(reward_commitment),
            HashPart::Int(epoch_start_height as i128),
            HashPart::Int(epoch_end_height as i128),
        ],
        32,
    )
}

fn exit_id(
    position_id: &str,
    owner_nullifier: &str,
    exit_amount_commitment: &str,
    requested_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEFI-LSD-EXIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(position_id),
            HashPart::Str(owner_nullifier),
            HashPart::Str(exit_amount_commitment),
            HashPart::Int(requested_at_height as i128),
        ],
        32,
    )
}

fn nav_snapshot_id(
    basket_id: &str,
    oracle_committee_root: &str,
    nav_per_share_scaled: u64,
    observed_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEFI-LSD-NAV-SNAPSHOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(basket_id),
            HashPart::Str(oracle_committee_root),
            HashPart::Int(nav_per_share_scaled as i128),
            HashPart::Int(observed_at_height as i128),
        ],
        32,
    )
}

fn receipt_id(
    exit_id: &str,
    position_id: &str,
    burned_share_commitment: &str,
    released_stake_commitment: &str,
    settled_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEFI-LSD-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(exit_id),
            HashPart::Str(position_id),
            HashPart::Str(burned_share_commitment),
            HashPart::Str(released_stake_commitment),
            HashPart::Int(settled_at_height as i128),
        ],
        32,
    )
}

fn note_commitment(
    domain: &str,
    owner_or_subject: &str,
    asset_or_scope: &str,
    amount_bucket: u64,
    nonce_height: u64,
) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_or_subject),
            HashPart::Str(asset_or_scope),
            HashPart::Int(amount_bucket as i128),
            HashPart::Int(nonce_height as i128),
        ],
        32,
    )
}
