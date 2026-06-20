use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialAmmPoolRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-amm-pool-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_POOL_SCHEME: &str =
    "private-confidential-amm-pool-note-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_SWAP_SCHEME: &str =
    "private-confidential-amm-swap-intent-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_LIQUIDITY_SCHEME: &str =
    "private-confidential-amm-liquidity-note-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_BATCH_SCHEME: &str =
    "private-confidential-amm-recursive-batch-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_DEVNET_HEIGHT: u64 = 176_000;
pub const PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_DEFAULT_MAX_POOLS: usize = 65_536;
pub const PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_DEFAULT_MAX_PENDING_SWAPS: usize = 1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_DEFAULT_MAX_BATCH_SWAPS: usize = 4_096;
pub const PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 2_048;
pub const PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 16_384;
pub const PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_DEFAULT_MAX_SWAP_FEE_BPS: u64 = 22;
pub const PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_DEFAULT_PROTOCOL_FEE_BPS: u64 = 4;
pub const PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AmmPoolKind {
    ConstantProduct,
    StableSwap,
    ConcentratedRange,
    OracleWeighted,
}

impl AmmPoolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConstantProduct => "constant_product",
            Self::StableSwap => "stable_swap",
            Self::ConcentratedRange => "concentrated_range",
            Self::OracleWeighted => "oracle_weighted",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Open,
    Paused,
    Draining,
    Closed,
}

impl PoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Closed => "closed",
        }
    }

    pub fn accepts_flow(self) -> bool {
        matches!(self, Self::Open)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityAction {
    Add,
    Remove,
    Rebalance,
    FeeSkim,
}

impl LiquidityAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Remove => "remove",
            Self::Rebalance => "rebalance",
            Self::FeeSkim => "fee_skim",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapDirection {
    BaseToQuote,
    QuoteToBase,
}

impl SwapDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BaseToQuote => "base_to_quote",
            Self::QuoteToBase => "quote_to_base",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteStatus {
    Pending,
    Batched,
    Settled,
    Expired,
    Rejected,
}

impl NoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn pending(self) -> bool {
        matches!(self, Self::Pending)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    SettlementReady,
    Settled,
    Rejected,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
        }
    }

    pub fn can_settle(self) -> bool {
        matches!(self, Self::SettlementReady)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub max_pools: usize,
    pub max_pending_swaps: usize,
    pub max_batch_swaps: usize,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_swap_fee_bps: u64,
    pub protocol_fee_bps: u64,
    pub require_fee_sponsor: bool,
    pub require_oracle_bound: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            max_pools: PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_DEFAULT_MAX_POOLS,
            max_pending_swaps: PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_DEFAULT_MAX_PENDING_SWAPS,
            max_batch_swaps: PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_DEFAULT_MAX_BATCH_SWAPS,
            min_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_swap_fee_bps: PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_DEFAULT_MAX_SWAP_FEE_BPS,
            protocol_fee_bps: PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_DEFAULT_PROTOCOL_FEE_BPS,
            require_fee_sponsor: true,
            require_oracle_bound: true,
        }
    }

    pub fn validate(&self) -> PrivateL2ConfidentialAmmPoolRuntimeResult<()> {
        if self.max_pools == 0 {
            return Err("confidential AMM max_pools must be positive".to_string());
        }
        if self.max_pending_swaps == 0 {
            return Err("confidential AMM max_pending_swaps must be positive".to_string());
        }
        if self.max_batch_swaps == 0 {
            return Err("confidential AMM max_batch_swaps must be positive".to_string());
        }
        if self.max_batch_swaps > self.max_pending_swaps {
            return Err("confidential AMM batch size cannot exceed pending capacity".to_string());
        }
        if self.min_privacy_set_size == 0 {
            return Err("confidential AMM min_privacy_set_size must be positive".to_string());
        }
        if self.target_privacy_set_size < self.min_privacy_set_size {
            return Err("confidential AMM target privacy set is below minimum".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("confidential AMM PQ security floor is too low".to_string());
        }
        if self.max_swap_fee_bps > PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_MAX_BPS {
            return Err("confidential AMM max fee exceeds BPS range".to_string());
        }
        if self.protocol_fee_bps > self.max_swap_fee_bps {
            return Err("confidential AMM protocol fee exceeds user max fee".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "max_pools": self.max_pools,
            "max_pending_swaps": self.max_pending_swaps,
            "max_batch_swaps": self.max_batch_swaps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_swap_fee_bps": self.max_swap_fee_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "require_fee_sponsor": self.require_fee_sponsor,
            "require_oracle_bound": self.require_oracle_bound,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub pool_counter: u64,
    pub liquidity_note_counter: u64,
    pub swap_intent_counter: u64,
    pub batch_counter: u64,
    pub settlement_counter: u64,
    pub rejected_counter: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_counter": self.pool_counter,
            "liquidity_note_counter": self.liquidity_note_counter,
            "swap_intent_counter": self.swap_intent_counter,
            "batch_counter": self.batch_counter,
            "settlement_counter": self.settlement_counter,
            "rejected_counter": self.rejected_counter,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenPoolRequest {
    pub pool_kind: AmmPoolKind,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub pool_owner_commitment: String,
    pub asset_pair_root: String,
    pub invariant_commitment_root: String,
    pub initial_liquidity_root: String,
    pub fee_policy_root: String,
    pub oracle_root: String,
    pub pq_authority_root: String,
    pub privacy_policy_root: String,
    pub low_fee_sponsor_root: String,
    pub pool_note_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_swap_fee_bps: u64,
    pub opened_at_height: u64,
}

impl OpenPoolRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialAmmPoolRuntimeResult<()> {
        required("base_asset_id", &self.base_asset_id)?;
        required("quote_asset_id", &self.quote_asset_id)?;
        if self.base_asset_id == self.quote_asset_id {
            return Err("confidential AMM pool assets must differ".to_string());
        }
        required("pool_owner_commitment", &self.pool_owner_commitment)?;
        required("asset_pair_root", &self.asset_pair_root)?;
        required("invariant_commitment_root", &self.invariant_commitment_root)?;
        required("initial_liquidity_root", &self.initial_liquidity_root)?;
        required("fee_policy_root", &self.fee_policy_root)?;
        required("pq_authority_root", &self.pq_authority_root)?;
        required("privacy_policy_root", &self.privacy_policy_root)?;
        required("pool_note_nullifier", &self.pool_note_nullifier)?;
        if config.require_oracle_bound {
            required("oracle_root", &self.oracle_root)?;
        }
        if config.require_fee_sponsor {
            required("low_fee_sponsor_root", &self.low_fee_sponsor_root)?;
        }
        validate_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.max_swap_fee_bps > config.max_swap_fee_bps {
            return Err("confidential AMM pool fee exceeds configured max".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pool_kind": self.pool_kind.as_str(),
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "pool_owner_commitment": self.pool_owner_commitment,
            "asset_pair_root": self.asset_pair_root,
            "invariant_commitment_root": self.invariant_commitment_root,
            "initial_liquidity_root": self.initial_liquidity_root,
            "fee_policy_root": self.fee_policy_root,
            "oracle_root": self.oracle_root,
            "pq_authority_root": self.pq_authority_root,
            "privacy_policy_root": self.privacy_policy_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "pool_note_nullifier": self.pool_note_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_swap_fee_bps": self.max_swap_fee_bps,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitLiquidityNoteRequest {
    pub pool_id: String,
    pub action: LiquidityAction,
    pub provider_commitment: String,
    pub liquidity_note_root: String,
    pub amount_commitment_root: String,
    pub range_commitment_root: String,
    pub fee_claim_root: String,
    pub reserve_delta_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub sponsor_receipt_root: String,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl SubmitLiquidityNoteRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialAmmPoolRuntimeResult<()> {
        required("pool_id", &self.pool_id)?;
        required("provider_commitment", &self.provider_commitment)?;
        required("liquidity_note_root", &self.liquidity_note_root)?;
        required("amount_commitment_root", &self.amount_commitment_root)?;
        required("range_commitment_root", &self.range_commitment_root)?;
        required("fee_claim_root", &self.fee_claim_root)?;
        required("reserve_delta_root", &self.reserve_delta_root)?;
        required("pq_authorization_root", &self.pq_authorization_root)?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        required("nullifier", &self.nullifier)?;
        if config.require_fee_sponsor {
            required("sponsor_receipt_root", &self.sponsor_receipt_root)?;
        }
        validate_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.max_fee_bps > config.max_swap_fee_bps {
            return Err("confidential AMM liquidity fee exceeds configured max".to_string());
        }
        if self.expires_at_height <= self.submitted_at_height {
            return Err(
                "confidential AMM liquidity note expiry must be after submission".to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "action": self.action.as_str(),
            "provider_commitment": self.provider_commitment,
            "liquidity_note_root": self.liquidity_note_root,
            "amount_commitment_root": self.amount_commitment_root,
            "range_commitment_root": self.range_commitment_root,
            "fee_claim_root": self.fee_claim_root,
            "reserve_delta_root": self.reserve_delta_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "sponsor_receipt_root": self.sponsor_receipt_root,
            "nullifier": self.nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitSwapIntentRequest {
    pub pool_id: String,
    pub direction: SwapDirection,
    pub trader_commitment: String,
    pub input_note_root: String,
    pub output_note_root: String,
    pub amount_in_commitment_root: String,
    pub min_amount_out_commitment_root: String,
    pub price_limit_root: String,
    pub route_hint_root: String,
    pub mev_commitment_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub sponsor_receipt_root: String,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl SubmitSwapIntentRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialAmmPoolRuntimeResult<()> {
        required("pool_id", &self.pool_id)?;
        required("trader_commitment", &self.trader_commitment)?;
        required("input_note_root", &self.input_note_root)?;
        required("output_note_root", &self.output_note_root)?;
        required("amount_in_commitment_root", &self.amount_in_commitment_root)?;
        required(
            "min_amount_out_commitment_root",
            &self.min_amount_out_commitment_root,
        )?;
        required("price_limit_root", &self.price_limit_root)?;
        required("route_hint_root", &self.route_hint_root)?;
        required("mev_commitment_root", &self.mev_commitment_root)?;
        required("pq_authorization_root", &self.pq_authorization_root)?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        required("nullifier", &self.nullifier)?;
        if config.require_fee_sponsor {
            required("sponsor_receipt_root", &self.sponsor_receipt_root)?;
        }
        validate_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.max_fee_bps > config.max_swap_fee_bps {
            return Err("confidential AMM swap fee exceeds configured max".to_string());
        }
        if self.expires_at_height <= self.submitted_at_height {
            return Err("confidential AMM swap expiry must be after submission".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "direction": self.direction.as_str(),
            "trader_commitment": self.trader_commitment,
            "input_note_root": self.input_note_root,
            "output_note_root": self.output_note_root,
            "amount_in_commitment_root": self.amount_in_commitment_root,
            "min_amount_out_commitment_root": self.min_amount_out_commitment_root,
            "price_limit_root": self.price_limit_root,
            "route_hint_root": self.route_hint_root,
            "mev_commitment_root": self.mev_commitment_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "sponsor_receipt_root": self.sponsor_receipt_root,
            "nullifier": self.nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildSwapBatchRequest {
    pub pool_id: String,
    pub swap_intent_ids: Vec<String>,
    pub liquidity_note_ids: Vec<String>,
    pub builder_commitment: String,
    pub clearing_price_root: String,
    pub invariant_delta_root: String,
    pub fee_delta_root: String,
    pub reserve_delta_root: String,
    pub low_fee_rebate_root: String,
    pub recursive_proof_request_root: String,
    pub pq_batch_authorization_root: String,
    pub privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub built_at_height: u64,
}

impl BuildSwapBatchRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialAmmPoolRuntimeResult<()> {
        required("pool_id", &self.pool_id)?;
        if self.swap_intent_ids.is_empty() {
            return Err("confidential AMM batch requires at least one swap".to_string());
        }
        if self.swap_intent_ids.len() > config.max_batch_swaps {
            return Err("confidential AMM batch exceeds configured max swaps".to_string());
        }
        required("builder_commitment", &self.builder_commitment)?;
        required("clearing_price_root", &self.clearing_price_root)?;
        required("invariant_delta_root", &self.invariant_delta_root)?;
        required("fee_delta_root", &self.fee_delta_root)?;
        required("reserve_delta_root", &self.reserve_delta_root)?;
        required("low_fee_rebate_root", &self.low_fee_rebate_root)?;
        required(
            "recursive_proof_request_root",
            &self.recursive_proof_request_root,
        )?;
        required(
            "pq_batch_authorization_root",
            &self.pq_batch_authorization_root,
        )?;
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("confidential AMM batch privacy set is below minimum".to_string());
        }
        if self.max_fee_bps > config.max_swap_fee_bps {
            return Err("confidential AMM batch fee exceeds configured max".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "swap_intent_ids": self.swap_intent_ids,
            "liquidity_note_ids": self.liquidity_note_ids,
            "builder_commitment": self.builder_commitment,
            "clearing_price_root": self.clearing_price_root,
            "invariant_delta_root": self.invariant_delta_root,
            "fee_delta_root": self.fee_delta_root,
            "reserve_delta_root": self.reserve_delta_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "recursive_proof_request_root": self.recursive_proof_request_root,
            "pq_batch_authorization_root": self.pq_batch_authorization_root,
            "privacy_set_size": self.privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "built_at_height": self.built_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleSwapBatchRequest {
    pub batch_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub pool_state_root_after: String,
    pub account_delta_root: String,
    pub nullifier_root: String,
    pub output_note_root: String,
    pub fee_receipt_root: String,
    pub pq_settlement_root: String,
    pub settled_fee_bps: u64,
    pub settled_at_height: u64,
}

impl SettleSwapBatchRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialAmmPoolRuntimeResult<()> {
        required("batch_id", &self.batch_id)?;
        required("settlement_tx_root", &self.settlement_tx_root)?;
        required("settlement_proof_root", &self.settlement_proof_root)?;
        required("pool_state_root_after", &self.pool_state_root_after)?;
        required("account_delta_root", &self.account_delta_root)?;
        required("nullifier_root", &self.nullifier_root)?;
        required("output_note_root", &self.output_note_root)?;
        required("fee_receipt_root", &self.fee_receipt_root)?;
        required("pq_settlement_root", &self.pq_settlement_root)?;
        if self.settled_fee_bps > config.max_swap_fee_bps {
            return Err("confidential AMM settled fee exceeds configured max".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_proof_root": self.settlement_proof_root,
            "pool_state_root_after": self.pool_state_root_after,
            "account_delta_root": self.account_delta_root,
            "nullifier_root": self.nullifier_root,
            "output_note_root": self.output_note_root,
            "fee_receipt_root": self.fee_receipt_root,
            "pq_settlement_root": self.pq_settlement_root,
            "settled_fee_bps": self.settled_fee_bps,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialAmmPool {
    pub pool_id: String,
    pub pool_kind: AmmPoolKind,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub asset_pair_root: String,
    pub invariant_commitment_root: String,
    pub pool_owner_commitment: String,
    pub fee_policy_root: String,
    pub oracle_root: String,
    pub pq_authority_root: String,
    pub privacy_policy_root: String,
    pub low_fee_sponsor_root: String,
    pub status: PoolStatus,
    pub max_swap_fee_bps: u64,
    pub opened_at_height: u64,
    pub latest_pool_state_root: String,
    pub pending_liquidity_note_ids: Vec<String>,
    pub pending_swap_intent_ids: Vec<String>,
    pub settled_batch_ids: Vec<String>,
}

impl ConfidentialAmmPool {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "pool_kind": self.pool_kind.as_str(),
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "asset_pair_root": self.asset_pair_root,
            "invariant_commitment_root": self.invariant_commitment_root,
            "pool_owner_commitment": self.pool_owner_commitment,
            "fee_policy_root": self.fee_policy_root,
            "oracle_root": self.oracle_root,
            "pq_authority_root": self.pq_authority_root,
            "privacy_policy_root": self.privacy_policy_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "status": self.status.as_str(),
            "max_swap_fee_bps": self.max_swap_fee_bps,
            "opened_at_height": self.opened_at_height,
            "latest_pool_state_root": self.latest_pool_state_root,
            "pending_liquidity_note_ids": self.pending_liquidity_note_ids,
            "pending_swap_intent_ids": self.pending_swap_intent_ids,
            "settled_batch_ids": self.settled_batch_ids,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityNote {
    pub note_id: String,
    pub pool_id: String,
    pub action: LiquidityAction,
    pub provider_commitment: String,
    pub liquidity_note_root: String,
    pub amount_commitment_root: String,
    pub range_commitment_root: String,
    pub fee_claim_root: String,
    pub reserve_delta_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub sponsor_receipt_root: String,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub status: NoteStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl LiquidityNote {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "pool_id": self.pool_id,
            "action": self.action.as_str(),
            "provider_commitment": self.provider_commitment,
            "liquidity_note_root": self.liquidity_note_root,
            "amount_commitment_root": self.amount_commitment_root,
            "range_commitment_root": self.range_commitment_root,
            "fee_claim_root": self.fee_claim_root,
            "reserve_delta_root": self.reserve_delta_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "sponsor_receipt_root": self.sponsor_receipt_root,
            "nullifier": self.nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapIntent {
    pub intent_id: String,
    pub pool_id: String,
    pub direction: SwapDirection,
    pub trader_commitment: String,
    pub input_note_root: String,
    pub output_note_root: String,
    pub amount_in_commitment_root: String,
    pub min_amount_out_commitment_root: String,
    pub price_limit_root: String,
    pub route_hint_root: String,
    pub mev_commitment_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub sponsor_receipt_root: String,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub status: NoteStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl SwapIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "pool_id": self.pool_id,
            "direction": self.direction.as_str(),
            "trader_commitment": self.trader_commitment,
            "input_note_root": self.input_note_root,
            "output_note_root": self.output_note_root,
            "amount_in_commitment_root": self.amount_in_commitment_root,
            "min_amount_out_commitment_root": self.min_amount_out_commitment_root,
            "price_limit_root": self.price_limit_root,
            "route_hint_root": self.route_hint_root,
            "mev_commitment_root": self.mev_commitment_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "sponsor_receipt_root": self.sponsor_receipt_root,
            "nullifier": self.nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapBatch {
    pub batch_id: String,
    pub pool_id: String,
    pub swap_intent_ids: Vec<String>,
    pub liquidity_note_ids: Vec<String>,
    pub builder_commitment: String,
    pub clearing_price_root: String,
    pub invariant_delta_root: String,
    pub fee_delta_root: String,
    pub reserve_delta_root: String,
    pub low_fee_rebate_root: String,
    pub recursive_proof_request_root: String,
    pub pq_batch_authorization_root: String,
    pub privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub status: BatchStatus,
    pub built_at_height: u64,
}

impl SwapBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "pool_id": self.pool_id,
            "swap_intent_ids": self.swap_intent_ids,
            "liquidity_note_ids": self.liquidity_note_ids,
            "builder_commitment": self.builder_commitment,
            "clearing_price_root": self.clearing_price_root,
            "invariant_delta_root": self.invariant_delta_root,
            "fee_delta_root": self.fee_delta_root,
            "reserve_delta_root": self.reserve_delta_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "recursive_proof_request_root": self.recursive_proof_request_root,
            "pq_batch_authorization_root": self.pq_batch_authorization_root,
            "privacy_set_size": self.privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "status": self.status.as_str(),
            "built_at_height": self.built_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapSettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub pool_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub pool_state_root_after: String,
    pub account_delta_root: String,
    pub nullifier_root: String,
    pub output_note_root: String,
    pub fee_receipt_root: String,
    pub pq_settlement_root: String,
    pub settled_fee_bps: u64,
    pub settled_at_height: u64,
}

impl SwapSettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "pool_id": self.pool_id,
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_proof_root": self.settlement_proof_root,
            "pool_state_root_after": self.pool_state_root_after,
            "account_delta_root": self.account_delta_root,
            "nullifier_root": self.nullifier_root,
            "output_note_root": self.output_note_root,
            "fee_receipt_root": self.fee_receipt_root,
            "pq_settlement_root": self.pq_settlement_root,
            "settled_fee_bps": self.settled_fee_bps,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub pool_root: String,
    pub liquidity_note_root: String,
    pub swap_intent_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_root": self.pool_root,
            "liquidity_note_root": self.liquidity_note_root,
            "swap_intent_root": self.swap_intent_root,
            "batch_root": self.batch_root,
            "receipt_root": self.receipt_root,
            "nullifier_root": self.nullifier_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub chain_id: String,
    pub protocol_version: String,
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub pools: BTreeMap<String, ConfidentialAmmPool>,
    pub liquidity_notes: BTreeMap<String, LiquidityNote>,
    pub swap_intents: BTreeMap<String, SwapIntent>,
    pub batches: BTreeMap<String, SwapBatch>,
    pub receipts: BTreeMap<String, SwapSettlementReceipt>,
    pub nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> PrivateL2ConfidentialAmmPoolRuntimeResult<Self> {
        let config = Config::devnet();
        config.validate()?;
        Ok(Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_PROTOCOL_VERSION.to_string(),
            config,
            counters: Counters::default(),
            current_height: PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_DEVNET_HEIGHT,
            pools: BTreeMap::new(),
            liquidity_notes: BTreeMap::new(),
            swap_intents: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
        })
    }

    pub fn open_pool(
        &mut self,
        request: OpenPoolRequest,
    ) -> PrivateL2ConfidentialAmmPoolRuntimeResult<ConfidentialAmmPool> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.pools.len() >= self.config.max_pools {
            return Err("confidential AMM pool capacity exhausted".to_string());
        }
        self.insert_nullifier(&request.pool_note_nullifier)?;
        self.counters.pool_counter = self.counters.pool_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.opened_at_height);
        let pool_id = pool_id(&request, self.counters.pool_counter);
        let latest_pool_state_root = root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-AMM-POOL-INITIAL-STATE",
            &json!({
                "pool_id": pool_id.clone(),
                "initial_liquidity_root": request.initial_liquidity_root.clone(),
                "invariant_commitment_root": request.invariant_commitment_root.clone(),
                "opened_at_height": request.opened_at_height,
            }),
        );
        let pool = ConfidentialAmmPool {
            pool_id: pool_id.clone(),
            pool_kind: request.pool_kind,
            base_asset_id: request.base_asset_id,
            quote_asset_id: request.quote_asset_id,
            asset_pair_root: request.asset_pair_root,
            invariant_commitment_root: request.invariant_commitment_root,
            pool_owner_commitment: request.pool_owner_commitment,
            fee_policy_root: request.fee_policy_root,
            oracle_root: request.oracle_root,
            pq_authority_root: request.pq_authority_root,
            privacy_policy_root: request.privacy_policy_root,
            low_fee_sponsor_root: request.low_fee_sponsor_root,
            status: PoolStatus::Open,
            max_swap_fee_bps: request.max_swap_fee_bps,
            opened_at_height: request.opened_at_height,
            latest_pool_state_root,
            pending_liquidity_note_ids: Vec::new(),
            pending_swap_intent_ids: Vec::new(),
            settled_batch_ids: Vec::new(),
        };
        self.pools.insert(pool_id, pool.clone());
        Ok(pool)
    }

    pub fn submit_liquidity_note(
        &mut self,
        request: SubmitLiquidityNoteRequest,
    ) -> PrivateL2ConfidentialAmmPoolRuntimeResult<LiquidityNote> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.liquidity_notes.len() >= self.config.max_pending_swaps {
            return Err("confidential AMM pending liquidity capacity exhausted".to_string());
        }
        {
            let pool = self
                .pools
                .get(&request.pool_id)
                .ok_or_else(|| "confidential AMM pool not found for liquidity note".to_string())?;
            if !pool.status.accepts_flow() {
                return Err("confidential AMM pool is not accepting liquidity".to_string());
            }
        }
        self.insert_nullifier(&request.nullifier)?;
        self.counters.liquidity_note_counter =
            self.counters.liquidity_note_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.submitted_at_height);
        let note_id = liquidity_note_id(&request, self.counters.liquidity_note_counter);
        let note = LiquidityNote {
            note_id: note_id.clone(),
            pool_id: request.pool_id.clone(),
            action: request.action,
            provider_commitment: request.provider_commitment,
            liquidity_note_root: request.liquidity_note_root,
            amount_commitment_root: request.amount_commitment_root,
            range_commitment_root: request.range_commitment_root,
            fee_claim_root: request.fee_claim_root,
            reserve_delta_root: request.reserve_delta_root,
            pq_authorization_root: request.pq_authorization_root,
            privacy_proof_root: request.privacy_proof_root,
            sponsor_receipt_root: request.sponsor_receipt_root,
            nullifier: request.nullifier,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            max_fee_bps: request.max_fee_bps,
            status: NoteStatus::Pending,
            submitted_at_height: request.submitted_at_height,
            expires_at_height: request.expires_at_height,
        };
        if let Some(pool) = self.pools.get_mut(&request.pool_id) {
            pool.pending_liquidity_note_ids.push(note_id.clone());
        }
        self.liquidity_notes.insert(note_id, note.clone());
        Ok(note)
    }

    pub fn submit_swap_intent(
        &mut self,
        request: SubmitSwapIntentRequest,
    ) -> PrivateL2ConfidentialAmmPoolRuntimeResult<SwapIntent> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.swap_intents.len() >= self.config.max_pending_swaps {
            return Err("confidential AMM pending swap capacity exhausted".to_string());
        }
        {
            let pool = self
                .pools
                .get(&request.pool_id)
                .ok_or_else(|| "confidential AMM pool not found for swap intent".to_string())?;
            if !pool.status.accepts_flow() {
                return Err("confidential AMM pool is not accepting swaps".to_string());
            }
            if request.max_fee_bps > pool.max_swap_fee_bps {
                return Err("confidential AMM swap fee exceeds pool max".to_string());
            }
        }
        self.insert_nullifier(&request.nullifier)?;
        self.counters.swap_intent_counter = self.counters.swap_intent_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.submitted_at_height);
        let intent_id = swap_intent_id(&request, self.counters.swap_intent_counter);
        let intent = SwapIntent {
            intent_id: intent_id.clone(),
            pool_id: request.pool_id.clone(),
            direction: request.direction,
            trader_commitment: request.trader_commitment,
            input_note_root: request.input_note_root,
            output_note_root: request.output_note_root,
            amount_in_commitment_root: request.amount_in_commitment_root,
            min_amount_out_commitment_root: request.min_amount_out_commitment_root,
            price_limit_root: request.price_limit_root,
            route_hint_root: request.route_hint_root,
            mev_commitment_root: request.mev_commitment_root,
            pq_authorization_root: request.pq_authorization_root,
            privacy_proof_root: request.privacy_proof_root,
            sponsor_receipt_root: request.sponsor_receipt_root,
            nullifier: request.nullifier,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            max_fee_bps: request.max_fee_bps,
            status: NoteStatus::Pending,
            submitted_at_height: request.submitted_at_height,
            expires_at_height: request.expires_at_height,
        };
        if let Some(pool) = self.pools.get_mut(&request.pool_id) {
            pool.pending_swap_intent_ids.push(intent_id.clone());
        }
        self.swap_intents.insert(intent_id, intent.clone());
        Ok(intent)
    }

    pub fn build_swap_batch(
        &mut self,
        request: BuildSwapBatchRequest,
    ) -> PrivateL2ConfidentialAmmPoolRuntimeResult<SwapBatch> {
        self.config.validate()?;
        request.validate(&self.config)?;
        let pool = self
            .pools
            .get(&request.pool_id)
            .ok_or_else(|| "confidential AMM pool not found for batch".to_string())?;
        if !pool.status.accepts_flow() {
            return Err("confidential AMM pool is not accepting batches".to_string());
        }

        let mut seen = BTreeSet::new();
        for intent_id in &request.swap_intent_ids {
            if !seen.insert(intent_id.clone()) {
                return Err("confidential AMM duplicate swap intent in batch".to_string());
            }
            let intent = self
                .swap_intents
                .get(intent_id)
                .ok_or_else(|| format!("confidential AMM swap intent {intent_id} missing"))?;
            if intent.pool_id != request.pool_id {
                return Err("confidential AMM swap intent belongs to a different pool".to_string());
            }
            if !intent.status.pending() {
                return Err("confidential AMM swap intent is not pending".to_string());
            }
            if intent.expires_at_height <= request.built_at_height {
                return Err("confidential AMM swap intent expired before batch".to_string());
            }
        }

        let mut liquidity_seen = BTreeSet::new();
        for note_id in &request.liquidity_note_ids {
            if !liquidity_seen.insert(note_id.clone()) {
                return Err("confidential AMM duplicate liquidity note in batch".to_string());
            }
            let note = self
                .liquidity_notes
                .get(note_id)
                .ok_or_else(|| format!("confidential AMM liquidity note {note_id} missing"))?;
            if note.pool_id != request.pool_id {
                return Err(
                    "confidential AMM liquidity note belongs to a different pool".to_string(),
                );
            }
            if !note.status.pending() {
                return Err("confidential AMM liquidity note is not pending".to_string());
            }
            if note.expires_at_height <= request.built_at_height {
                return Err("confidential AMM liquidity note expired before batch".to_string());
            }
        }

        self.counters.batch_counter = self.counters.batch_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.built_at_height);
        let batch_id = swap_batch_id(&request, self.counters.batch_counter);
        for intent_id in &request.swap_intent_ids {
            if let Some(intent) = self.swap_intents.get_mut(intent_id) {
                intent.status = NoteStatus::Batched;
            }
        }
        for note_id in &request.liquidity_note_ids {
            if let Some(note) = self.liquidity_notes.get_mut(note_id) {
                note.status = NoteStatus::Batched;
            }
        }
        if let Some(pool) = self.pools.get_mut(&request.pool_id) {
            pool.pending_swap_intent_ids
                .retain(|id| !request.swap_intent_ids.contains(id));
            pool.pending_liquidity_note_ids
                .retain(|id| !request.liquidity_note_ids.contains(id));
        }
        let batch = SwapBatch {
            batch_id: batch_id.clone(),
            pool_id: request.pool_id,
            swap_intent_ids: request.swap_intent_ids,
            liquidity_note_ids: request.liquidity_note_ids,
            builder_commitment: request.builder_commitment,
            clearing_price_root: request.clearing_price_root,
            invariant_delta_root: request.invariant_delta_root,
            fee_delta_root: request.fee_delta_root,
            reserve_delta_root: request.reserve_delta_root,
            low_fee_rebate_root: request.low_fee_rebate_root,
            recursive_proof_request_root: request.recursive_proof_request_root,
            pq_batch_authorization_root: request.pq_batch_authorization_root,
            privacy_set_size: request.privacy_set_size,
            max_fee_bps: request.max_fee_bps,
            status: BatchStatus::SettlementReady,
            built_at_height: request.built_at_height,
        };
        self.batches.insert(batch_id, batch.clone());
        Ok(batch)
    }

    pub fn settle_swap_batch(
        &mut self,
        request: SettleSwapBatchRequest,
    ) -> PrivateL2ConfidentialAmmPoolRuntimeResult<SwapSettlementReceipt> {
        self.config.validate()?;
        request.validate(&self.config)?;
        let batch = self
            .batches
            .get(&request.batch_id)
            .ok_or_else(|| "confidential AMM batch not found for settlement".to_string())?
            .clone();
        if !batch.status.can_settle() {
            return Err("confidential AMM batch cannot settle from current status".to_string());
        }
        if request.settled_fee_bps > batch.max_fee_bps {
            return Err("confidential AMM settled fee exceeds batch max".to_string());
        }

        self.counters.settlement_counter = self.counters.settlement_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.settled_at_height);
        let receipt_id = settlement_receipt_id(&request, self.counters.settlement_counter);
        for intent_id in &batch.swap_intent_ids {
            if let Some(intent) = self.swap_intents.get_mut(intent_id) {
                intent.status = NoteStatus::Settled;
            }
        }
        for note_id in &batch.liquidity_note_ids {
            if let Some(note) = self.liquidity_notes.get_mut(note_id) {
                note.status = NoteStatus::Settled;
            }
        }
        if let Some(stored_batch) = self.batches.get_mut(&request.batch_id) {
            stored_batch.status = BatchStatus::Settled;
        }
        if let Some(pool) = self.pools.get_mut(&batch.pool_id) {
            pool.latest_pool_state_root = request.pool_state_root_after.clone();
            pool.settled_batch_ids.push(request.batch_id.clone());
        }
        let receipt = SwapSettlementReceipt {
            receipt_id: receipt_id.clone(),
            batch_id: request.batch_id,
            pool_id: batch.pool_id,
            settlement_tx_root: request.settlement_tx_root,
            settlement_proof_root: request.settlement_proof_root,
            pool_state_root_after: request.pool_state_root_after,
            account_delta_root: request.account_delta_root,
            nullifier_root: request.nullifier_root,
            output_note_root: request.output_note_root,
            fee_receipt_root: request.fee_receipt_root,
            pq_settlement_root: request.pq_settlement_root,
            settled_fee_bps: request.settled_fee_bps,
            settled_at_height: request.settled_at_height,
        };
        self.receipts.insert(receipt_id, receipt.clone());
        Ok(receipt)
    }

    pub fn roots(&self) -> Roots {
        let pool_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-AMM-POOLS",
            &self
                .pools
                .values()
                .map(ConfidentialAmmPool::public_record)
                .collect::<Vec<_>>(),
        );
        let liquidity_note_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-AMM-LIQUIDITY-NOTES",
            &self
                .liquidity_notes
                .values()
                .map(LiquidityNote::public_record)
                .collect::<Vec<_>>(),
        );
        let swap_intent_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-AMM-SWAP-INTENTS",
            &self
                .swap_intents
                .values()
                .map(SwapIntent::public_record)
                .collect::<Vec<_>>(),
        );
        let batch_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-AMM-BATCHES",
            &self
                .batches
                .values()
                .map(SwapBatch::public_record)
                .collect::<Vec<_>>(),
        );
        let receipt_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-AMM-RECEIPTS",
            &self
                .receipts
                .values()
                .map(SwapSettlementReceipt::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-AMM-NULLIFIERS",
            &self
                .nullifiers
                .iter()
                .map(|nullifier| json!(nullifier))
                .collect::<Vec<_>>(),
        );
        let state_root = root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-AMM-STATE",
            &json!({
                "chain_id": self.chain_id,
                "protocol_version": self.protocol_version,
                "current_height": self.current_height,
                "pool_root": pool_root,
                "liquidity_note_root": liquidity_note_root,
                "swap_intent_root": swap_intent_root,
                "batch_root": batch_root,
                "receipt_root": receipt_root,
                "nullifier_root": nullifier_root,
                "counters": self.counters.public_record(),
            }),
        );
        Roots {
            pool_root,
            liquidity_note_root,
            swap_intent_root,
            batch_root,
            receipt_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_SCHEMA_VERSION,
            "hash_suite": PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_HASH_SUITE,
            "pool_scheme": PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_POOL_SCHEME,
            "swap_scheme": PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_SWAP_SCHEME,
            "liquidity_scheme": PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_LIQUIDITY_SCHEME,
            "batch_scheme": PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_BATCH_SCHEME,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "pool_ids": self.pools.keys().cloned().collect::<Vec<_>>(),
            "liquidity_note_ids": self.liquidity_notes.keys().cloned().collect::<Vec<_>>(),
            "swap_intent_ids": self.swap_intents.keys().cloned().collect::<Vec<_>>(),
            "batch_ids": self.batches.keys().cloned().collect::<Vec<_>>(),
            "receipt_ids": self.receipts.keys().cloned().collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn insert_nullifier(
        &mut self,
        nullifier: &str,
    ) -> PrivateL2ConfidentialAmmPoolRuntimeResult<()> {
        if !self.nullifiers.insert(nullifier.to_string()) {
            return Err("confidential AMM nullifier already consumed".to_string());
        }
        Ok(())
    }
}

pub fn pool_id(request: &OpenPoolRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-AMM-POOL-ID",
        &json!({
            "counter": counter,
            "pool_kind": request.pool_kind.as_str(),
            "base_asset_id": request.base_asset_id,
            "quote_asset_id": request.quote_asset_id,
            "asset_pair_root": request.asset_pair_root,
            "pool_owner_commitment": request.pool_owner_commitment,
            "opened_at_height": request.opened_at_height,
        }),
    )
}

pub fn liquidity_note_id(request: &SubmitLiquidityNoteRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-AMM-LIQUIDITY-NOTE-ID",
        &json!({
            "counter": counter,
            "pool_id": request.pool_id,
            "action": request.action.as_str(),
            "liquidity_note_root": request.liquidity_note_root,
            "provider_commitment": request.provider_commitment,
            "nullifier": request.nullifier,
            "submitted_at_height": request.submitted_at_height,
        }),
    )
}

pub fn swap_intent_id(request: &SubmitSwapIntentRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-AMM-SWAP-INTENT-ID",
        &json!({
            "counter": counter,
            "pool_id": request.pool_id,
            "direction": request.direction.as_str(),
            "input_note_root": request.input_note_root,
            "output_note_root": request.output_note_root,
            "trader_commitment": request.trader_commitment,
            "nullifier": request.nullifier,
            "submitted_at_height": request.submitted_at_height,
        }),
    )
}

pub fn swap_batch_id(request: &BuildSwapBatchRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-AMM-BATCH-ID",
        &json!({
            "counter": counter,
            "pool_id": request.pool_id,
            "swap_intent_ids": request.swap_intent_ids,
            "liquidity_note_ids": request.liquidity_note_ids,
            "clearing_price_root": request.clearing_price_root,
            "recursive_proof_request_root": request.recursive_proof_request_root,
            "built_at_height": request.built_at_height,
        }),
    )
}

pub fn settlement_receipt_id(request: &SettleSwapBatchRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-AMM-SETTLEMENT-RECEIPT-ID",
        &json!({
            "counter": counter,
            "batch_id": request.batch_id,
            "settlement_tx_root": request.settlement_tx_root,
            "pool_state_root_after": request.pool_state_root_after,
            "settled_at_height": request.settled_at_height,
        }),
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_AMM_POOL_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

fn required(field: &str, value: &str) -> PrivateL2ConfidentialAmmPoolRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("confidential AMM field {field} is required"));
    }
    Ok(())
}

fn validate_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    min_privacy_set_size: u64,
    min_pq_security_bits: u16,
) -> PrivateL2ConfidentialAmmPoolRuntimeResult<()> {
    if privacy_set_size < min_privacy_set_size {
        return Err("confidential AMM privacy set is below minimum".to_string());
    }
    if pq_security_bits < min_pq_security_bits {
        return Err("confidential AMM PQ security bits below minimum".to_string());
    }
    Ok(())
}
