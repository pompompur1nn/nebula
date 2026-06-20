use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type LowFeeConfidentialTokenSwapNettingEngineResult<T> = Result<T, String>;

pub const LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_PROTOCOL_VERSION: &str =
    "nebula-low-fee-confidential-token-swap-netting-engine-v1";
pub const LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_SCHEMA_VERSION: u64 = 1;
pub const LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_HASH_SUITE: &str =
    "SHAKE256-domain-separated";
pub const LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_ROUTE_INTENT_SCHEME: &str =
    "zk-confidential-token-swap-route-intent-v1";
pub const LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_BATCH_SETTLEMENT_SCHEME: &str =
    "private-amm-netted-batch-settlement-v1";
pub const LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_RECEIPT_SCHEME: &str =
    "zk-confidential-swap-settlement-receipt-v1";
pub const LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_PQ_AUTH_SCHEME: &str =
    "ml-dsa-87-confidential-swap-netting-v1";
pub const LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_DEVNET_HEIGHT: u64 = 768;
pub const LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_MAX_BPS: u64 = 10_000;
pub const LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_DEFAULT_EPOCH_BLOCKS: u64 = 240;
pub const LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 8;
pub const LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_DEFAULT_INTENT_TTL_BLOCKS: u64 = 32;
pub const LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_DEFAULT_SOLVER_CREDIT_TTL_BLOCKS: u64 =
    720;
pub const LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_DEFAULT_SPONSOR_REBATE_TTL_BLOCKS: u64 =
    720;
pub const LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_DEFAULT_MAX_INTENTS_PER_BATCH: u64 = 384;
pub const LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_DEFAULT_MAX_ROUTE_HOPS: u64 = 6;
pub const LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_DEFAULT_MIN_BUCKET_SIZE: u64 = 64;
pub const LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_DEFAULT_MAX_FEE_CEILING_BPS: u64 = 35;
pub const LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_DEFAULT_MAX_SOLVER_SHARE_BPS: u64 = 7_000;
pub const LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_DEFAULT_MIN_REBATE_COVERAGE_BPS: u64 =
    1_200;
pub const LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapSide {
    ExactInput,
    ExactOutput,
    TwoSidedBand,
}
impl SwapSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExactInput => "exact_input",
            Self::ExactOutput => "exact_output",
            Self::TwoSidedBand => "two_sided_band",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteIntentStatus {
    Queued,
    Bucketed,
    Matched,
    Netted,
    Settled,
    Expired,
    Cancelled,
    Rejected,
}
impl RouteIntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Bucketed => "bucketed",
            Self::Matched => "matched",
            Self::Netted => "netted",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Rejected => "rejected",
        }
    }
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Bucketed | Self::Matched | Self::Netted
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetBucketStatus {
    Open,
    Sealed,
    Netted,
    Settling,
    Settled,
    Disputed,
    Expired,
}
impl AssetBucketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Netted => "netted",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
    pub fn accepts_intents(self) -> bool {
        matches!(self, Self::Open)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementBatchStatus {
    Open,
    Sealed,
    Solved,
    Proving,
    Posted,
    Finalized,
    Challenged,
    Abandoned,
}
impl SettlementBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Solved => "solved",
            Self::Proving => "proving",
            Self::Posted => "posted",
            Self::Finalized => "finalized",
            Self::Challenged => "challenged",
            Self::Abandoned => "abandoned",
        }
    }
    pub fn receipt_ready(self) -> bool {
        matches!(self, Self::Posted | Self::Finalized)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverCreditStatus {
    Active,
    Reserved,
    Earned,
    Spent,
    Slashed,
    Expired,
}
impl SolverCreditStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Reserved => "reserved",
            Self::Earned => "earned",
            Self::Spent => "spent",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Earned)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorRebateStatus {
    Available,
    Reserved,
    Applied,
    Refunded,
    Expired,
    Revoked,
}
impl SponsorRebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
    pub fn reservable(self) -> bool {
        matches!(self, Self::Available | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Published,
    Finalized,
    Disputed,
}
impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub route_intent_scheme: String,
    pub batch_settlement_scheme: String,
    pub receipt_scheme: String,
    pub pq_authorization_scheme: String,
    pub epoch_blocks: u64,
    pub batch_window_blocks: u64,
    pub intent_ttl_blocks: u64,
    pub solver_credit_ttl_blocks: u64,
    pub sponsor_rebate_ttl_blocks: u64,
    pub max_intents_per_batch: u64,
    pub max_route_hops: u64,
    pub min_bucket_size: u64,
    pub max_fee_ceiling_bps: u64,
    pub max_solver_share_bps: u64,
    pub min_rebate_coverage_bps: u64,
    pub min_pq_security_bits: u16,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_PROTOCOL_VERSION
                .to_string(),
            schema_version: LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_HASH_SUITE.to_string(),
            route_intent_scheme: LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_ROUTE_INTENT_SCHEME
                .to_string(),
            batch_settlement_scheme:
                LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_BATCH_SETTLEMENT_SCHEME.to_string(),
            receipt_scheme: LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_RECEIPT_SCHEME
                .to_string(),
            pq_authorization_scheme: LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_PQ_AUTH_SCHEME
                .to_string(),
            epoch_blocks: LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_DEFAULT_EPOCH_BLOCKS,
            batch_window_blocks:
                LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_DEFAULT_BATCH_WINDOW_BLOCKS,
            intent_ttl_blocks:
                LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_DEFAULT_INTENT_TTL_BLOCKS,
            solver_credit_ttl_blocks:
                LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_DEFAULT_SOLVER_CREDIT_TTL_BLOCKS,
            sponsor_rebate_ttl_blocks:
                LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_DEFAULT_SPONSOR_REBATE_TTL_BLOCKS,
            max_intents_per_batch:
                LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_DEFAULT_MAX_INTENTS_PER_BATCH,
            max_route_hops: LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_DEFAULT_MAX_ROUTE_HOPS,
            min_bucket_size: LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_DEFAULT_MIN_BUCKET_SIZE,
            max_fee_ceiling_bps:
                LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_DEFAULT_MAX_FEE_CEILING_BPS,
            max_solver_share_bps:
                LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_DEFAULT_MAX_SOLVER_SHARE_BPS,
            min_rebate_coverage_bps:
                LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_DEFAULT_MIN_REBATE_COVERAGE_BPS,
            min_pq_security_bits:
                LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }
}
impl Config {
    pub fn devnet() -> Self {
        Self {
            batch_window_blocks: 4,
            intent_ttl_blocks: 18,
            max_intents_per_batch: 96,
            min_bucket_size: 16,
            ..Self::default()
        }
    }
    pub fn public_record(&self) -> Value {
        json!({ "kind": "low_fee_confidential_token_swap_netting_engine_config", "protocol_version": self.protocol_version, "schema_version": self.schema_version, "chain_id": self.chain_id, "hash_suite": self.hash_suite, "route_intent_scheme": self.route_intent_scheme, "batch_settlement_scheme": self.batch_settlement_scheme, "receipt_scheme": self.receipt_scheme, "pq_authorization_scheme": self.pq_authorization_scheme, "epoch_blocks": self.epoch_blocks, "batch_window_blocks": self.batch_window_blocks, "intent_ttl_blocks": self.intent_ttl_blocks, "solver_credit_ttl_blocks": self.solver_credit_ttl_blocks, "sponsor_rebate_ttl_blocks": self.sponsor_rebate_ttl_blocks, "max_intents_per_batch": self.max_intents_per_batch, "max_route_hops": self.max_route_hops, "min_bucket_size": self.min_bucket_size, "max_fee_ceiling_bps": self.max_fee_ceiling_bps, "max_solver_share_bps": self.max_solver_share_bps, "min_rebate_coverage_bps": self.min_rebate_coverage_bps, "min_pq_security_bits": self.min_pq_security_bits })
    }
    pub fn root(&self) -> String {
        payload_root("LOW-FEE-CONFIDENTIAL-SWAP-CONFIG", &self.public_record())
    }
    pub fn validate(&self) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
        ensure_non_empty("config.protocol_version", &self.protocol_version)?;
        ensure_non_empty("config.chain_id", &self.chain_id)?;
        ensure_non_zero("config.epoch_blocks", self.epoch_blocks)?;
        ensure_non_zero("config.batch_window_blocks", self.batch_window_blocks)?;
        ensure_non_zero("config.intent_ttl_blocks", self.intent_ttl_blocks)?;
        ensure_bps("config.max_fee_ceiling_bps", self.max_fee_ceiling_bps)?;
        ensure_bps("config.max_solver_share_bps", self.max_solver_share_bps)?;
        ensure_bps(
            "config.min_rebate_coverage_bps",
            self.min_rebate_coverage_bps,
        )?;
        if self.min_pq_security_bits < 128 {
            return Err("config.min_pq_security_bits must be at least 128".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialToken {
    pub token_id: String,
    pub symbol_commitment: String,
    pub decimals: String,
    pub asset_registry_root: String,
    pub compliance_policy_root: String,
    pub transfer_hook_root: String,
    pub active: bool,
}

impl ConfidentialToken {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_token",
            "protocol_version": LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_PROTOCOL_VERSION,
            "token_id": self.token_id,
            "symbol_commitment": self.symbol_commitment,
            "decimals": self.decimals,
            "asset_registry_root": self.asset_registry_root,
            "compliance_policy_root": self.compliance_policy_root,
            "transfer_hook_root": self.transfer_hook_root,
            "active": self.active,
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "LOW-FEE-CONFIDENTIAL-SWAP-CONFIDENTIAL-TOKEN",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
        ensure_non_empty("ConfidentialToken.token_id", &self.token_id)?;
        ensure_non_empty(
            "ConfidentialToken.symbol_commitment",
            &self.symbol_commitment,
        )?;
        ensure_non_empty("ConfidentialToken.decimals", &self.decimals)?;
        ensure_non_empty(
            "ConfidentialToken.asset_registry_root",
            &self.asset_registry_root,
        )?;
        ensure_non_empty(
            "ConfidentialToken.compliance_policy_root",
            &self.compliance_policy_root,
        )?;
        ensure_non_empty(
            "ConfidentialToken.transfer_hook_root",
            &self.transfer_hook_root,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateAmmPool {
    pub pool_id: String,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub fee_bps: u64,
    pub liquidity_commitment: String,
    pub invariant_commitment: String,
    pub oracle_root: String,
    pub active: bool,
}

impl PrivateAmmPool {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_amm_pool",
            "protocol_version": LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_PROTOCOL_VERSION,
            "pool_id": self.pool_id,
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "fee_bps": self.fee_bps,
            "liquidity_commitment": self.liquidity_commitment,
            "invariant_commitment": self.invariant_commitment,
            "oracle_root": self.oracle_root,
            "active": self.active,
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "LOW-FEE-CONFIDENTIAL-SWAP-PRIVATE-AMM-POOL",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
        ensure_non_empty("PrivateAmmPool.pool_id", &self.pool_id)?;
        ensure_non_empty("PrivateAmmPool.base_asset_id", &self.base_asset_id)?;
        ensure_non_empty("PrivateAmmPool.quote_asset_id", &self.quote_asset_id)?;
        ensure_non_empty(
            "PrivateAmmPool.liquidity_commitment",
            &self.liquidity_commitment,
        )?;
        ensure_non_empty(
            "PrivateAmmPool.invariant_commitment",
            &self.invariant_commitment,
        )?;
        ensure_non_empty("PrivateAmmPool.oracle_root", &self.oracle_root)?;
        ensure_named_number("PrivateAmmPool.fee_bps", self.fee_bps)?;
        ensure_bps("PrivateAmmPool.fee_bps", self.fee_bps)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteIntent {
    pub intent_id: String,
    pub owner_commitment: String,
    pub side: SwapSide,
    pub input_asset_id: String,
    pub output_asset_id: String,
    pub amount_commitment: String,
    pub limit_price_commitment: String,
    pub slippage_bucket_id: String,
    pub route_hint_root: String,
    pub fee_ceiling_bps: u64,
    pub max_hops: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: RouteIntentStatus,
}

impl RouteIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "route_intent",
            "protocol_version": LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_PROTOCOL_VERSION,
            "intent_id": self.intent_id,
            "owner_commitment": self.owner_commitment,
            "side": self.side.as_str(),
            "input_asset_id": self.input_asset_id,
            "output_asset_id": self.output_asset_id,
            "amount_commitment": self.amount_commitment,
            "limit_price_commitment": self.limit_price_commitment,
            "slippage_bucket_id": self.slippage_bucket_id,
            "route_hint_root": self.route_hint_root,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "max_hops": self.max_hops,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "LOW-FEE-CONFIDENTIAL-SWAP-ROUTE-INTENT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
        ensure_non_empty("RouteIntent.intent_id", &self.intent_id)?;
        ensure_non_empty("RouteIntent.owner_commitment", &self.owner_commitment)?;
        ensure_non_empty("RouteIntent.input_asset_id", &self.input_asset_id)?;
        ensure_non_empty("RouteIntent.output_asset_id", &self.output_asset_id)?;
        ensure_non_empty("RouteIntent.amount_commitment", &self.amount_commitment)?;
        ensure_non_empty(
            "RouteIntent.limit_price_commitment",
            &self.limit_price_commitment,
        )?;
        ensure_non_empty("RouteIntent.slippage_bucket_id", &self.slippage_bucket_id)?;
        ensure_non_empty("RouteIntent.route_hint_root", &self.route_hint_root)?;
        ensure_named_number("RouteIntent.fee_ceiling_bps", self.fee_ceiling_bps)?;
        ensure_named_number("RouteIntent.max_hops", self.max_hops)?;
        ensure_named_number("RouteIntent.created_at_height", self.created_at_height)?;
        ensure_named_number("RouteIntent.expires_at_height", self.expires_at_height)?;
        ensure_bps("RouteIntent.fee_ceiling_bps", self.fee_ceiling_bps)?;
        if self.expires_at_height <= self.created_at_height {
            return Err(
                "RouteIntent.expires_at_height must be after created_at_height".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteHopCommitment {
    pub hop_id: String,
    pub intent_id: String,
    pub pool_id: String,
    pub input_asset_id: String,
    pub output_asset_id: String,
    pub encrypted_path_commitment: String,
    pub expected_fill_commitment: String,
    pub hop_index: u64,
    pub fee_bps: u64,
}

impl RouteHopCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "route_hop_commitment",
            "protocol_version": LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_PROTOCOL_VERSION,
            "hop_id": self.hop_id,
            "intent_id": self.intent_id,
            "pool_id": self.pool_id,
            "input_asset_id": self.input_asset_id,
            "output_asset_id": self.output_asset_id,
            "encrypted_path_commitment": self.encrypted_path_commitment,
            "expected_fill_commitment": self.expected_fill_commitment,
            "hop_index": self.hop_index,
            "fee_bps": self.fee_bps,
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "LOW-FEE-CONFIDENTIAL-SWAP-ROUTE-HOP-COMMITMENT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
        ensure_non_empty("RouteHopCommitment.hop_id", &self.hop_id)?;
        ensure_non_empty("RouteHopCommitment.intent_id", &self.intent_id)?;
        ensure_non_empty("RouteHopCommitment.pool_id", &self.pool_id)?;
        ensure_non_empty("RouteHopCommitment.input_asset_id", &self.input_asset_id)?;
        ensure_non_empty("RouteHopCommitment.output_asset_id", &self.output_asset_id)?;
        ensure_non_empty(
            "RouteHopCommitment.encrypted_path_commitment",
            &self.encrypted_path_commitment,
        )?;
        ensure_non_empty(
            "RouteHopCommitment.expected_fill_commitment",
            &self.expected_fill_commitment,
        )?;
        ensure_named_number("RouteHopCommitment.hop_index", self.hop_index)?;
        ensure_named_number("RouteHopCommitment.fee_bps", self.fee_bps)?;
        ensure_bps("RouteHopCommitment.fee_bps", self.fee_bps)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NettedAssetBucket {
    pub bucket_id: String,
    pub batch_id: String,
    pub input_asset_id: String,
    pub output_asset_id: String,
    pub privacy_bucket_id: String,
    pub gross_input_commitment: String,
    pub gross_output_commitment: String,
    pub net_input_commitment: String,
    pub net_output_commitment: String,
    pub participant_root: String,
    pub status: AssetBucketStatus,
}

impl NettedAssetBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "netted_asset_bucket",
            "protocol_version": LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_PROTOCOL_VERSION,
            "bucket_id": self.bucket_id,
            "batch_id": self.batch_id,
            "input_asset_id": self.input_asset_id,
            "output_asset_id": self.output_asset_id,
            "privacy_bucket_id": self.privacy_bucket_id,
            "gross_input_commitment": self.gross_input_commitment,
            "gross_output_commitment": self.gross_output_commitment,
            "net_input_commitment": self.net_input_commitment,
            "net_output_commitment": self.net_output_commitment,
            "participant_root": self.participant_root,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "LOW-FEE-CONFIDENTIAL-SWAP-NETTED-ASSET-BUCKET",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
        ensure_non_empty("NettedAssetBucket.bucket_id", &self.bucket_id)?;
        ensure_non_empty("NettedAssetBucket.batch_id", &self.batch_id)?;
        ensure_non_empty("NettedAssetBucket.input_asset_id", &self.input_asset_id)?;
        ensure_non_empty("NettedAssetBucket.output_asset_id", &self.output_asset_id)?;
        ensure_non_empty(
            "NettedAssetBucket.privacy_bucket_id",
            &self.privacy_bucket_id,
        )?;
        ensure_non_empty(
            "NettedAssetBucket.gross_input_commitment",
            &self.gross_input_commitment,
        )?;
        ensure_non_empty(
            "NettedAssetBucket.gross_output_commitment",
            &self.gross_output_commitment,
        )?;
        ensure_non_empty(
            "NettedAssetBucket.net_input_commitment",
            &self.net_input_commitment,
        )?;
        ensure_non_empty(
            "NettedAssetBucket.net_output_commitment",
            &self.net_output_commitment,
        )?;
        ensure_non_empty("NettedAssetBucket.participant_root", &self.participant_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlippagePrivacyBand {
    pub band_id: String,
    pub input_asset_id: String,
    pub output_asset_id: String,
    pub min_price_commitment: String,
    pub max_price_commitment: String,
    pub noise_commitment: String,
    pub min_participants: u64,
    pub current_participants: u64,
    pub max_slippage_bps: u64,
}

impl SlippagePrivacyBand {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "slippage_privacy_band",
            "protocol_version": LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_PROTOCOL_VERSION,
            "band_id": self.band_id,
            "input_asset_id": self.input_asset_id,
            "output_asset_id": self.output_asset_id,
            "min_price_commitment": self.min_price_commitment,
            "max_price_commitment": self.max_price_commitment,
            "noise_commitment": self.noise_commitment,
            "min_participants": self.min_participants,
            "current_participants": self.current_participants,
            "max_slippage_bps": self.max_slippage_bps,
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "LOW-FEE-CONFIDENTIAL-SWAP-SLIPPAGE-PRIVACY-BAND",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
        ensure_non_empty("SlippagePrivacyBand.band_id", &self.band_id)?;
        ensure_non_empty("SlippagePrivacyBand.input_asset_id", &self.input_asset_id)?;
        ensure_non_empty("SlippagePrivacyBand.output_asset_id", &self.output_asset_id)?;
        ensure_non_empty(
            "SlippagePrivacyBand.min_price_commitment",
            &self.min_price_commitment,
        )?;
        ensure_non_empty(
            "SlippagePrivacyBand.max_price_commitment",
            &self.max_price_commitment,
        )?;
        ensure_non_empty(
            "SlippagePrivacyBand.noise_commitment",
            &self.noise_commitment,
        )?;
        ensure_named_number(
            "SlippagePrivacyBand.min_participants",
            self.min_participants,
        )?;
        ensure_named_number(
            "SlippagePrivacyBand.current_participants",
            self.current_participants,
        )?;
        ensure_named_number(
            "SlippagePrivacyBand.max_slippage_bps",
            self.max_slippage_bps,
        )?;
        ensure_bps(
            "SlippagePrivacyBand.max_slippage_bps",
            self.max_slippage_bps,
        )?;
        if self.current_participants < self.min_participants {
            return Err(
                "SlippagePrivacyBand.current_participants below min_participants".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverCredit {
    pub credit_id: String,
    pub solver_commitment: String,
    pub asset_id: String,
    pub amount_commitment: String,
    pub earned_from_batch_id: String,
    pub expires_at_height: u64,
    pub status: SolverCreditStatus,
}

impl SolverCredit {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "solver_credit",
            "protocol_version": LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_PROTOCOL_VERSION,
            "credit_id": self.credit_id,
            "solver_commitment": self.solver_commitment,
            "asset_id": self.asset_id,
            "amount_commitment": self.amount_commitment,
            "earned_from_batch_id": self.earned_from_batch_id,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "LOW-FEE-CONFIDENTIAL-SWAP-SOLVER-CREDIT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
        ensure_non_empty("SolverCredit.credit_id", &self.credit_id)?;
        ensure_non_empty("SolverCredit.solver_commitment", &self.solver_commitment)?;
        ensure_non_empty("SolverCredit.asset_id", &self.asset_id)?;
        ensure_non_empty("SolverCredit.amount_commitment", &self.amount_commitment)?;
        ensure_non_empty(
            "SolverCredit.earned_from_batch_id",
            &self.earned_from_batch_id,
        )?;
        ensure_named_number("SolverCredit.expires_at_height", self.expires_at_height)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeCeiling {
    pub ceiling_id: String,
    pub asset_pair_key: String,
    pub sponsor_id: String,
    pub max_fee_bps: u64,
    pub max_total_fee_commitment: String,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub policy_root: String,
}

impl LowFeeCeiling {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_ceiling",
            "protocol_version": LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_PROTOCOL_VERSION,
            "ceiling_id": self.ceiling_id,
            "asset_pair_key": self.asset_pair_key,
            "sponsor_id": self.sponsor_id,
            "max_fee_bps": self.max_fee_bps,
            "max_total_fee_commitment": self.max_total_fee_commitment,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "policy_root": self.policy_root,
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "LOW-FEE-CONFIDENTIAL-SWAP-LOW-FEE-CEILING",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
        ensure_non_empty("LowFeeCeiling.ceiling_id", &self.ceiling_id)?;
        ensure_non_empty("LowFeeCeiling.asset_pair_key", &self.asset_pair_key)?;
        ensure_non_empty("LowFeeCeiling.sponsor_id", &self.sponsor_id)?;
        ensure_non_empty(
            "LowFeeCeiling.max_total_fee_commitment",
            &self.max_total_fee_commitment,
        )?;
        ensure_non_empty("LowFeeCeiling.policy_root", &self.policy_root)?;
        ensure_named_number("LowFeeCeiling.max_fee_bps", self.max_fee_bps)?;
        ensure_named_number("LowFeeCeiling.valid_from_height", self.valid_from_height)?;
        ensure_named_number("LowFeeCeiling.valid_until_height", self.valid_until_height)?;
        ensure_bps("LowFeeCeiling.max_fee_bps", self.max_fee_bps)?;
        if self.valid_until_height <= self.valid_from_height {
            return Err(
                "LowFeeCeiling.valid_until_height must be after valid_from_height".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorRebate {
    pub rebate_id: String,
    pub sponsor_commitment: String,
    pub asset_id: String,
    pub amount_commitment: String,
    pub reserved_for_batch_id: String,
    pub coverage_bps: u64,
    pub expires_at_height: u64,
    pub status: SponsorRebateStatus,
}

impl SponsorRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sponsor_rebate",
            "protocol_version": LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_PROTOCOL_VERSION,
            "rebate_id": self.rebate_id,
            "sponsor_commitment": self.sponsor_commitment,
            "asset_id": self.asset_id,
            "amount_commitment": self.amount_commitment,
            "reserved_for_batch_id": self.reserved_for_batch_id,
            "coverage_bps": self.coverage_bps,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "LOW-FEE-CONFIDENTIAL-SWAP-SPONSOR-REBATE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
        ensure_non_empty("SponsorRebate.rebate_id", &self.rebate_id)?;
        ensure_non_empty("SponsorRebate.sponsor_commitment", &self.sponsor_commitment)?;
        ensure_non_empty("SponsorRebate.asset_id", &self.asset_id)?;
        ensure_non_empty("SponsorRebate.amount_commitment", &self.amount_commitment)?;
        ensure_non_empty(
            "SponsorRebate.reserved_for_batch_id",
            &self.reserved_for_batch_id,
        )?;
        ensure_named_number("SponsorRebate.coverage_bps", self.coverage_bps)?;
        ensure_named_number("SponsorRebate.expires_at_height", self.expires_at_height)?;
        ensure_bps("SponsorRebate.coverage_bps", self.coverage_bps)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSettlementBatch {
    pub batch_id: String,
    pub epoch: String,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub solver_commitment: String,
    pub intent_root: String,
    pub bucket_root: String,
    pub rebate_root: String,
    pub credit_root: String,
    pub settlement_price_root: String,
    pub fee_root: String,
    pub status: SettlementBatchStatus,
}

impl PrivateSettlementBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_settlement_batch",
            "protocol_version": LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "epoch": self.epoch,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "solver_commitment": self.solver_commitment,
            "intent_root": self.intent_root,
            "bucket_root": self.bucket_root,
            "rebate_root": self.rebate_root,
            "credit_root": self.credit_root,
            "settlement_price_root": self.settlement_price_root,
            "fee_root": self.fee_root,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "LOW-FEE-CONFIDENTIAL-SWAP-PRIVATE-SETTLEMENT-BATCH",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
        ensure_non_empty("PrivateSettlementBatch.batch_id", &self.batch_id)?;
        ensure_non_empty("PrivateSettlementBatch.epoch", &self.epoch)?;
        ensure_non_empty(
            "PrivateSettlementBatch.solver_commitment",
            &self.solver_commitment,
        )?;
        ensure_non_empty("PrivateSettlementBatch.intent_root", &self.intent_root)?;
        ensure_non_empty("PrivateSettlementBatch.bucket_root", &self.bucket_root)?;
        ensure_non_empty("PrivateSettlementBatch.rebate_root", &self.rebate_root)?;
        ensure_non_empty("PrivateSettlementBatch.credit_root", &self.credit_root)?;
        ensure_non_empty(
            "PrivateSettlementBatch.settlement_price_root",
            &self.settlement_price_root,
        )?;
        ensure_non_empty("PrivateSettlementBatch.fee_root", &self.fee_root)?;
        ensure_named_number(
            "PrivateSettlementBatch.opened_at_height",
            self.opened_at_height,
        )?;
        ensure_named_number(
            "PrivateSettlementBatch.sealed_at_height",
            self.sealed_at_height,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub intent_id: String,
    pub owner_commitment: String,
    pub input_nullifier_root: String,
    pub output_note_root: String,
    pub fee_note_root: String,
    pub rebate_note_root: String,
    pub solver_credit_root: String,
    pub settlement_proof_root: String,
    pub status: ReceiptStatus,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "settlement_receipt",
            "protocol_version": LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "intent_id": self.intent_id,
            "owner_commitment": self.owner_commitment,
            "input_nullifier_root": self.input_nullifier_root,
            "output_note_root": self.output_note_root,
            "fee_note_root": self.fee_note_root,
            "rebate_note_root": self.rebate_note_root,
            "solver_credit_root": self.solver_credit_root,
            "settlement_proof_root": self.settlement_proof_root,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "LOW-FEE-CONFIDENTIAL-SWAP-SETTLEMENT-RECEIPT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
        ensure_non_empty("SettlementReceipt.receipt_id", &self.receipt_id)?;
        ensure_non_empty("SettlementReceipt.batch_id", &self.batch_id)?;
        ensure_non_empty("SettlementReceipt.intent_id", &self.intent_id)?;
        ensure_non_empty("SettlementReceipt.owner_commitment", &self.owner_commitment)?;
        ensure_non_empty(
            "SettlementReceipt.input_nullifier_root",
            &self.input_nullifier_root,
        )?;
        ensure_non_empty("SettlementReceipt.output_note_root", &self.output_note_root)?;
        ensure_non_empty("SettlementReceipt.fee_note_root", &self.fee_note_root)?;
        ensure_non_empty("SettlementReceipt.rebate_note_root", &self.rebate_note_root)?;
        ensure_non_empty(
            "SettlementReceipt.solver_credit_root",
            &self.solver_credit_root,
        )?;
        ensure_non_empty(
            "SettlementReceipt.settlement_proof_root",
            &self.settlement_proof_root,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverAttestation {
    pub attestation_id: String,
    pub solver_commitment: String,
    pub batch_id: String,
    pub pq_public_key_commitment: String,
    pub signature_root: String,
    pub security_bits: u16,
    pub valid_until_height: u64,
}

impl SolverAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "solver_attestation",
            "protocol_version": LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "solver_commitment": self.solver_commitment,
            "batch_id": self.batch_id,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "signature_root": self.signature_root,
            "security_bits": self.security_bits,
            "valid_until_height": self.valid_until_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "LOW-FEE-CONFIDENTIAL-SWAP-SOLVER-ATTESTATION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
        ensure_non_empty("SolverAttestation.attestation_id", &self.attestation_id)?;
        ensure_non_empty(
            "SolverAttestation.solver_commitment",
            &self.solver_commitment,
        )?;
        ensure_non_empty("SolverAttestation.batch_id", &self.batch_id)?;
        ensure_non_empty(
            "SolverAttestation.pq_public_key_commitment",
            &self.pq_public_key_commitment,
        )?;
        ensure_non_empty("SolverAttestation.signature_root", &self.signature_root)?;
        ensure_named_number(
            "SolverAttestation.valid_until_height",
            self.valid_until_height,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NettingProofEnvelope {
    pub proof_id: String,
    pub batch_id: String,
    pub circuit_id: String,
    pub public_input_root: String,
    pub private_witness_commitment: String,
    pub aggregate_receipt_root: String,
    pub recursive_proof_root: String,
    pub verifier_key_root: String,
}

impl NettingProofEnvelope {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "netting_proof_envelope",
            "protocol_version": LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_PROTOCOL_VERSION,
            "proof_id": self.proof_id,
            "batch_id": self.batch_id,
            "circuit_id": self.circuit_id,
            "public_input_root": self.public_input_root,
            "private_witness_commitment": self.private_witness_commitment,
            "aggregate_receipt_root": self.aggregate_receipt_root,
            "recursive_proof_root": self.recursive_proof_root,
            "verifier_key_root": self.verifier_key_root,
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "LOW-FEE-CONFIDENTIAL-SWAP-NETTING-PROOF-ENVELOPE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
        ensure_non_empty("NettingProofEnvelope.proof_id", &self.proof_id)?;
        ensure_non_empty("NettingProofEnvelope.batch_id", &self.batch_id)?;
        ensure_non_empty("NettingProofEnvelope.circuit_id", &self.circuit_id)?;
        ensure_non_empty(
            "NettingProofEnvelope.public_input_root",
            &self.public_input_root,
        )?;
        ensure_non_empty(
            "NettingProofEnvelope.private_witness_commitment",
            &self.private_witness_commitment,
        )?;
        ensure_non_empty(
            "NettingProofEnvelope.aggregate_receipt_root",
            &self.aggregate_receipt_root,
        )?;
        ensure_non_empty(
            "NettingProofEnvelope.recursive_proof_root",
            &self.recursive_proof_root,
        )?;
        ensure_non_empty(
            "NettingProofEnvelope.verifier_key_root",
            &self.verifier_key_root,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityReservation {
    pub reservation_id: String,
    pub pool_id: String,
    pub batch_id: String,
    pub solver_commitment: String,
    pub input_asset_id: String,
    pub output_asset_id: String,
    pub liquidity_commitment: String,
    pub expires_at_height: u64,
}

impl LiquidityReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "liquidity_reservation",
            "protocol_version": LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_PROTOCOL_VERSION,
            "reservation_id": self.reservation_id,
            "pool_id": self.pool_id,
            "batch_id": self.batch_id,
            "solver_commitment": self.solver_commitment,
            "input_asset_id": self.input_asset_id,
            "output_asset_id": self.output_asset_id,
            "liquidity_commitment": self.liquidity_commitment,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "LOW-FEE-CONFIDENTIAL-SWAP-LIQUIDITY-RESERVATION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
        ensure_non_empty("LiquidityReservation.reservation_id", &self.reservation_id)?;
        ensure_non_empty("LiquidityReservation.pool_id", &self.pool_id)?;
        ensure_non_empty("LiquidityReservation.batch_id", &self.batch_id)?;
        ensure_non_empty(
            "LiquidityReservation.solver_commitment",
            &self.solver_commitment,
        )?;
        ensure_non_empty("LiquidityReservation.input_asset_id", &self.input_asset_id)?;
        ensure_non_empty(
            "LiquidityReservation.output_asset_id",
            &self.output_asset_id,
        )?;
        ensure_non_empty(
            "LiquidityReservation.liquidity_commitment",
            &self.liquidity_commitment,
        )?;
        ensure_named_number(
            "LiquidityReservation.expires_at_height",
            self.expires_at_height,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceGuardRail {
    pub guard_id: String,
    pub asset_pair_key: String,
    pub oracle_root: String,
    pub min_price_commitment: String,
    pub max_price_commitment: String,
    pub twap_window: String,
    pub max_deviation_bps: u64,
}

impl PriceGuardRail {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "price_guard_rail",
            "protocol_version": LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_PROTOCOL_VERSION,
            "guard_id": self.guard_id,
            "asset_pair_key": self.asset_pair_key,
            "oracle_root": self.oracle_root,
            "min_price_commitment": self.min_price_commitment,
            "max_price_commitment": self.max_price_commitment,
            "twap_window": self.twap_window,
            "max_deviation_bps": self.max_deviation_bps,
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "LOW-FEE-CONFIDENTIAL-SWAP-PRICE-GUARD-RAIL",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
        ensure_non_empty("PriceGuardRail.guard_id", &self.guard_id)?;
        ensure_non_empty("PriceGuardRail.asset_pair_key", &self.asset_pair_key)?;
        ensure_non_empty("PriceGuardRail.oracle_root", &self.oracle_root)?;
        ensure_non_empty(
            "PriceGuardRail.min_price_commitment",
            &self.min_price_commitment,
        )?;
        ensure_non_empty(
            "PriceGuardRail.max_price_commitment",
            &self.max_price_commitment,
        )?;
        ensure_non_empty("PriceGuardRail.twap_window", &self.twap_window)?;
        ensure_named_number("PriceGuardRail.max_deviation_bps", self.max_deviation_bps)?;
        ensure_bps("PriceGuardRail.max_deviation_bps", self.max_deviation_bps)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentCancellation {
    pub cancellation_id: String,
    pub intent_id: String,
    pub owner_commitment: String,
    pub authorization_root: String,
    pub cancelled_at_height: u64,
    pub reason_code: String,
}

impl IntentCancellation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "intent_cancellation",
            "protocol_version": LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_PROTOCOL_VERSION,
            "cancellation_id": self.cancellation_id,
            "intent_id": self.intent_id,
            "owner_commitment": self.owner_commitment,
            "authorization_root": self.authorization_root,
            "cancelled_at_height": self.cancelled_at_height,
            "reason_code": self.reason_code,
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "LOW-FEE-CONFIDENTIAL-SWAP-INTENT-CANCELLATION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
        ensure_non_empty("IntentCancellation.cancellation_id", &self.cancellation_id)?;
        ensure_non_empty("IntentCancellation.intent_id", &self.intent_id)?;
        ensure_non_empty(
            "IntentCancellation.owner_commitment",
            &self.owner_commitment,
        )?;
        ensure_non_empty(
            "IntentCancellation.authorization_root",
            &self.authorization_root,
        )?;
        ensure_non_empty("IntentCancellation.reason_code", &self.reason_code)?;
        ensure_named_number(
            "IntentCancellation.cancelled_at_height",
            self.cancelled_at_height,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchDispute {
    pub dispute_id: String,
    pub batch_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub bond_commitment: String,
    pub opened_at_height: u64,
    pub resolved_at_height: u64,
    pub status: String,
}

impl BatchDispute {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "batch_dispute",
            "protocol_version": LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_PROTOCOL_VERSION,
            "dispute_id": self.dispute_id,
            "batch_id": self.batch_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "bond_commitment": self.bond_commitment,
            "opened_at_height": self.opened_at_height,
            "resolved_at_height": self.resolved_at_height,
            "status": self.status,
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "LOW-FEE-CONFIDENTIAL-SWAP-BATCH-DISPUTE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
        ensure_non_empty("BatchDispute.dispute_id", &self.dispute_id)?;
        ensure_non_empty("BatchDispute.batch_id", &self.batch_id)?;
        ensure_non_empty(
            "BatchDispute.challenger_commitment",
            &self.challenger_commitment,
        )?;
        ensure_non_empty("BatchDispute.evidence_root", &self.evidence_root)?;
        ensure_non_empty("BatchDispute.bond_commitment", &self.bond_commitment)?;
        ensure_non_empty("BatchDispute.status", &self.status)?;
        ensure_named_number("BatchDispute.opened_at_height", self.opened_at_height)?;
        ensure_named_number("BatchDispute.resolved_at_height", self.resolved_at_height)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditTrailEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub emitted_at_height: u64,
    pub operator_commitment: String,
}

impl AuditTrailEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "audit_trail_event",
            "protocol_version": LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_PROTOCOL_VERSION,
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "emitted_at_height": self.emitted_at_height,
            "operator_commitment": self.operator_commitment,
        })
    }

    pub fn root(&self) -> String {
        payload_root(
            "LOW-FEE-CONFIDENTIAL-SWAP-AUDIT-TRAIL-EVENT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
        ensure_non_empty("AuditTrailEvent.event_id", &self.event_id)?;
        ensure_non_empty("AuditTrailEvent.event_kind", &self.event_kind)?;
        ensure_non_empty("AuditTrailEvent.subject_id", &self.subject_id)?;
        ensure_non_empty("AuditTrailEvent.subject_root", &self.subject_root)?;
        ensure_non_empty(
            "AuditTrailEvent.operator_commitment",
            &self.operator_commitment,
        )?;
        ensure_named_number("AuditTrailEvent.emitted_at_height", self.emitted_at_height)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub token_root: String,
    pub amm_pool_root: String,
    pub route_intent_root: String,
    pub route_hop_root: String,
    pub netted_asset_bucket_root: String,
    pub slippage_privacy_band_root: String,
    pub solver_credit_root: String,
    pub low_fee_ceiling_root: String,
    pub sponsor_rebate_root: String,
    pub settlement_batch_root: String,
    pub settlement_receipt_root: String,
    pub solver_attestation_root: String,
    pub netting_proof_root: String,
    pub liquidity_reservation_root: String,
    pub price_guard_rail_root: String,
    pub cancellation_root: String,
    pub dispute_root: String,
    pub audit_event_root: String,
}
impl Roots {
    pub fn public_record(&self) -> Value {
        json!({ "kind": "low_fee_confidential_token_swap_netting_engine_roots", "protocol_version": LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_PROTOCOL_VERSION, "config_root": self.config_root, "token_root": self.token_root, "amm_pool_root": self.amm_pool_root, "route_intent_root": self.route_intent_root, "route_hop_root": self.route_hop_root, "netted_asset_bucket_root": self.netted_asset_bucket_root, "slippage_privacy_band_root": self.slippage_privacy_band_root, "solver_credit_root": self.solver_credit_root, "low_fee_ceiling_root": self.low_fee_ceiling_root, "sponsor_rebate_root": self.sponsor_rebate_root, "settlement_batch_root": self.settlement_batch_root, "settlement_receipt_root": self.settlement_receipt_root, "solver_attestation_root": self.solver_attestation_root, "netting_proof_root": self.netting_proof_root, "liquidity_reservation_root": self.liquidity_reservation_root, "price_guard_rail_root": self.price_guard_rail_root, "cancellation_root": self.cancellation_root, "dispute_root": self.dispute_root, "audit_event_root": self.audit_event_root })
    }
    pub fn root(&self) -> String {
        payload_root("LOW-FEE-CONFIDENTIAL-SWAP-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub token_count: u64,
    pub amm_pool_count: u64,
    pub route_intent_count: u64,
    pub live_route_intent_count: u64,
    pub route_hop_count: u64,
    pub netted_asset_bucket_count: u64,
    pub open_bucket_count: u64,
    pub slippage_privacy_band_count: u64,
    pub solver_credit_count: u64,
    pub usable_solver_credit_count: u64,
    pub low_fee_ceiling_count: u64,
    pub sponsor_rebate_count: u64,
    pub reservable_sponsor_rebate_count: u64,
    pub settlement_batch_count: u64,
    pub receipt_ready_batch_count: u64,
    pub settlement_receipt_count: u64,
    pub solver_attestation_count: u64,
    pub netting_proof_count: u64,
    pub liquidity_reservation_count: u64,
    pub price_guard_rail_count: u64,
    pub cancellation_count: u64,
    pub dispute_count: u64,
    pub audit_event_count: u64,
}
impl Counters {
    pub fn public_record(&self) -> Value {
        json!({ "kind": "low_fee_confidential_token_swap_netting_engine_counters", "protocol_version": LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_PROTOCOL_VERSION, "token_count": self.token_count, "amm_pool_count": self.amm_pool_count, "route_intent_count": self.route_intent_count, "live_route_intent_count": self.live_route_intent_count, "route_hop_count": self.route_hop_count, "netted_asset_bucket_count": self.netted_asset_bucket_count, "open_bucket_count": self.open_bucket_count, "slippage_privacy_band_count": self.slippage_privacy_band_count, "solver_credit_count": self.solver_credit_count, "usable_solver_credit_count": self.usable_solver_credit_count, "low_fee_ceiling_count": self.low_fee_ceiling_count, "sponsor_rebate_count": self.sponsor_rebate_count, "reservable_sponsor_rebate_count": self.reservable_sponsor_rebate_count, "settlement_batch_count": self.settlement_batch_count, "receipt_ready_batch_count": self.receipt_ready_batch_count, "settlement_receipt_count": self.settlement_receipt_count, "solver_attestation_count": self.solver_attestation_count, "netting_proof_count": self.netting_proof_count, "liquidity_reservation_count": self.liquidity_reservation_count, "price_guard_rail_count": self.price_guard_rail_count, "cancellation_count": self.cancellation_count, "dispute_count": self.dispute_count, "audit_event_count": self.audit_event_count })
    }
    pub fn root(&self) -> String {
        payload_root("LOW-FEE-CONFIDENTIAL-SWAP-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub tokens: BTreeMap<String, ConfidentialToken>,
    pub amm_pools: BTreeMap<String, PrivateAmmPool>,
    pub route_intents: BTreeMap<String, RouteIntent>,
    pub route_hops: BTreeMap<String, RouteHopCommitment>,
    pub netted_asset_buckets: BTreeMap<String, NettedAssetBucket>,
    pub slippage_privacy_bands: BTreeMap<String, SlippagePrivacyBand>,
    pub solver_credits: BTreeMap<String, SolverCredit>,
    pub low_fee_ceilings: BTreeMap<String, LowFeeCeiling>,
    pub sponsor_rebates: BTreeMap<String, SponsorRebate>,
    pub settlement_batches: BTreeMap<String, PrivateSettlementBatch>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub solver_attestations: BTreeMap<String, SolverAttestation>,
    pub netting_proofs: BTreeMap<String, NettingProofEnvelope>,
    pub liquidity_reservations: BTreeMap<String, LiquidityReservation>,
    pub price_guard_rails: BTreeMap<String, PriceGuardRail>,
    pub cancellations: BTreeMap<String, IntentCancellation>,
    pub disputes: BTreeMap<String, BatchDispute>,
    pub audit_events: BTreeMap<String, AuditTrailEvent>,
}
impl State {
    pub fn new(height: u64, config: Config) -> Self {
        Self {
            height,
            config,
            tokens: BTreeMap::new(),
            amm_pools: BTreeMap::new(),
            route_intents: BTreeMap::new(),
            route_hops: BTreeMap::new(),
            netted_asset_buckets: BTreeMap::new(),
            slippage_privacy_bands: BTreeMap::new(),
            solver_credits: BTreeMap::new(),
            low_fee_ceilings: BTreeMap::new(),
            sponsor_rebates: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            solver_attestations: BTreeMap::new(),
            netting_proofs: BTreeMap::new(),
            liquidity_reservations: BTreeMap::new(),
            price_guard_rails: BTreeMap::new(),
            cancellations: BTreeMap::new(),
            disputes: BTreeMap::new(),
            audit_events: BTreeMap::new(),
        }
    }
    pub fn devnet() -> LowFeeConfidentialTokenSwapNettingEngineResult<Self> {
        let mut state = Self::new(
            LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_DEVNET_HEIGHT,
            Config::devnet(),
        );
        state.seed_devnet_records()?;
        state.validate()?;
        Ok(state)
    }
    pub fn set_height(
        &mut self,
        height: u64,
    ) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
        self.height = height;
        self.validate_height_windows()
    }
    pub fn update_height(
        &mut self,
        height: u64,
    ) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
        self.set_height(height)
    }
    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.root(),
            token_root: map_root(
                "LOW-FEE-CONFIDENTIAL-SWAP-TOKEN",
                &self.tokens,
                ConfidentialToken::public_record,
            ),
            amm_pool_root: map_root(
                "LOW-FEE-CONFIDENTIAL-SWAP-AMM-POOL",
                &self.amm_pools,
                PrivateAmmPool::public_record,
            ),
            route_intent_root: map_root(
                "LOW-FEE-CONFIDENTIAL-SWAP-ROUTE-INTENT",
                &self.route_intents,
                RouteIntent::public_record,
            ),
            route_hop_root: map_root(
                "LOW-FEE-CONFIDENTIAL-SWAP-ROUTE-HOP",
                &self.route_hops,
                RouteHopCommitment::public_record,
            ),
            netted_asset_bucket_root: map_root(
                "LOW-FEE-CONFIDENTIAL-SWAP-NETTED-ASSET-BUCKET",
                &self.netted_asset_buckets,
                NettedAssetBucket::public_record,
            ),
            slippage_privacy_band_root: map_root(
                "LOW-FEE-CONFIDENTIAL-SWAP-SLIPPAGE-PRIVACY-BAND",
                &self.slippage_privacy_bands,
                SlippagePrivacyBand::public_record,
            ),
            solver_credit_root: map_root(
                "LOW-FEE-CONFIDENTIAL-SWAP-SOLVER-CREDIT",
                &self.solver_credits,
                SolverCredit::public_record,
            ),
            low_fee_ceiling_root: map_root(
                "LOW-FEE-CONFIDENTIAL-SWAP-LOW-FEE-CEILING",
                &self.low_fee_ceilings,
                LowFeeCeiling::public_record,
            ),
            sponsor_rebate_root: map_root(
                "LOW-FEE-CONFIDENTIAL-SWAP-SPONSOR-REBATE",
                &self.sponsor_rebates,
                SponsorRebate::public_record,
            ),
            settlement_batch_root: map_root(
                "LOW-FEE-CONFIDENTIAL-SWAP-SETTLEMENT-BATCH",
                &self.settlement_batches,
                PrivateSettlementBatch::public_record,
            ),
            settlement_receipt_root: map_root(
                "LOW-FEE-CONFIDENTIAL-SWAP-SETTLEMENT-RECEIPT",
                &self.settlement_receipts,
                SettlementReceipt::public_record,
            ),
            solver_attestation_root: map_root(
                "LOW-FEE-CONFIDENTIAL-SWAP-SOLVER-ATTESTATION",
                &self.solver_attestations,
                SolverAttestation::public_record,
            ),
            netting_proof_root: map_root(
                "LOW-FEE-CONFIDENTIAL-SWAP-NETTING-PROOF",
                &self.netting_proofs,
                NettingProofEnvelope::public_record,
            ),
            liquidity_reservation_root: map_root(
                "LOW-FEE-CONFIDENTIAL-SWAP-LIQUIDITY-RESERVATION",
                &self.liquidity_reservations,
                LiquidityReservation::public_record,
            ),
            price_guard_rail_root: map_root(
                "LOW-FEE-CONFIDENTIAL-SWAP-PRICE-GUARD-RAIL",
                &self.price_guard_rails,
                PriceGuardRail::public_record,
            ),
            cancellation_root: map_root(
                "LOW-FEE-CONFIDENTIAL-SWAP-CANCELLATION",
                &self.cancellations,
                IntentCancellation::public_record,
            ),
            dispute_root: map_root(
                "LOW-FEE-CONFIDENTIAL-SWAP-DISPUTE",
                &self.disputes,
                BatchDispute::public_record,
            ),
            audit_event_root: map_root(
                "LOW-FEE-CONFIDENTIAL-SWAP-AUDIT-EVENT",
                &self.audit_events,
                AuditTrailEvent::public_record,
            ),
        }
    }
    pub fn counters(&self) -> Counters {
        Counters {
            token_count: self.tokens.len() as u64,
            amm_pool_count: self.amm_pools.len() as u64,
            route_intent_count: self.route_intents.len() as u64,
            live_route_intent_count: self
                .route_intents
                .values()
                .filter(|intent| intent.status.live())
                .count() as u64,
            route_hop_count: self.route_hops.len() as u64,
            netted_asset_bucket_count: self.netted_asset_buckets.len() as u64,
            open_bucket_count: self
                .netted_asset_buckets
                .values()
                .filter(|bucket| bucket.status.accepts_intents())
                .count() as u64,
            slippage_privacy_band_count: self.slippage_privacy_bands.len() as u64,
            solver_credit_count: self.solver_credits.len() as u64,
            usable_solver_credit_count: self
                .solver_credits
                .values()
                .filter(|credit| credit.status.usable())
                .count() as u64,
            low_fee_ceiling_count: self.low_fee_ceilings.len() as u64,
            sponsor_rebate_count: self.sponsor_rebates.len() as u64,
            reservable_sponsor_rebate_count: self
                .sponsor_rebates
                .values()
                .filter(|rebate| rebate.status.reservable())
                .count() as u64,
            settlement_batch_count: self.settlement_batches.len() as u64,
            receipt_ready_batch_count: self
                .settlement_batches
                .values()
                .filter(|batch| batch.status.receipt_ready())
                .count() as u64,
            settlement_receipt_count: self.settlement_receipts.len() as u64,
            solver_attestation_count: self.solver_attestations.len() as u64,
            netting_proof_count: self.netting_proofs.len() as u64,
            liquidity_reservation_count: self.liquidity_reservations.len() as u64,
            price_guard_rail_count: self.price_guard_rails.len() as u64,
            cancellation_count: self.cancellations.len() as u64,
            dispute_count: self.disputes.len() as u64,
            audit_event_count: self.audit_events.len() as u64,
        }
    }
    pub fn state_root(&self) -> String {
        root_from_record(&self.public_record_without_state_root())
    }
    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        let root = root_from_record(&record);
        if let Value::Object(values) = &mut record {
            values.insert("state_root".to_string(), Value::String(root));
        }
        record
    }
    pub fn validate(&self) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
        self.config.validate()?;
        self.validate_height_windows()?;
        validate_map("tokens", &self.tokens, ConfidentialToken::validate)?;
        validate_map("amm_pools", &self.amm_pools, PrivateAmmPool::validate)?;
        validate_map("route_intents", &self.route_intents, RouteIntent::validate)?;
        validate_map("route_hops", &self.route_hops, RouteHopCommitment::validate)?;
        validate_map(
            "netted_asset_buckets",
            &self.netted_asset_buckets,
            NettedAssetBucket::validate,
        )?;
        validate_map(
            "slippage_privacy_bands",
            &self.slippage_privacy_bands,
            SlippagePrivacyBand::validate,
        )?;
        validate_map(
            "solver_credits",
            &self.solver_credits,
            SolverCredit::validate,
        )?;
        validate_map(
            "low_fee_ceilings",
            &self.low_fee_ceilings,
            LowFeeCeiling::validate,
        )?;
        validate_map(
            "sponsor_rebates",
            &self.sponsor_rebates,
            SponsorRebate::validate,
        )?;
        validate_map(
            "settlement_batches",
            &self.settlement_batches,
            PrivateSettlementBatch::validate,
        )?;
        validate_map(
            "settlement_receipts",
            &self.settlement_receipts,
            SettlementReceipt::validate,
        )?;
        validate_map(
            "solver_attestations",
            &self.solver_attestations,
            SolverAttestation::validate,
        )?;
        validate_map(
            "netting_proofs",
            &self.netting_proofs,
            NettingProofEnvelope::validate,
        )?;
        validate_map(
            "liquidity_reservations",
            &self.liquidity_reservations,
            LiquidityReservation::validate,
        )?;
        validate_map(
            "price_guard_rails",
            &self.price_guard_rails,
            PriceGuardRail::validate,
        )?;
        validate_map(
            "cancellations",
            &self.cancellations,
            IntentCancellation::validate,
        )?;
        validate_map("disputes", &self.disputes, BatchDispute::validate)?;
        validate_map(
            "audit_events",
            &self.audit_events,
            AuditTrailEvent::validate,
        )?;
        self.validate_references()?;
        self.validate_limits()?;
        Ok(())
    }
    fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({ "kind": "low_fee_confidential_token_swap_netting_engine_state", "protocol_version": LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_PROTOCOL_VERSION, "height": self.height, "config": self.config.public_record(), "roots": roots.public_record(), "counters": counters.public_record(), "tokens": values_record(&self.tokens, ConfidentialToken::public_record), "amm_pools": values_record(&self.amm_pools, PrivateAmmPool::public_record), "route_intents": values_record(&self.route_intents, RouteIntent::public_record), "route_hops": values_record(&self.route_hops, RouteHopCommitment::public_record), "netted_asset_buckets": values_record(&self.netted_asset_buckets, NettedAssetBucket::public_record), "slippage_privacy_bands": values_record(&self.slippage_privacy_bands, SlippagePrivacyBand::public_record), "solver_credits": values_record(&self.solver_credits, SolverCredit::public_record), "low_fee_ceilings": values_record(&self.low_fee_ceilings, LowFeeCeiling::public_record), "sponsor_rebates": values_record(&self.sponsor_rebates, SponsorRebate::public_record), "settlement_batches": values_record(&self.settlement_batches, PrivateSettlementBatch::public_record), "settlement_receipts": values_record(&self.settlement_receipts, SettlementReceipt::public_record), "solver_attestations": values_record(&self.solver_attestations, SolverAttestation::public_record), "netting_proofs": values_record(&self.netting_proofs, NettingProofEnvelope::public_record), "liquidity_reservations": values_record(&self.liquidity_reservations, LiquidityReservation::public_record), "price_guard_rails": values_record(&self.price_guard_rails, PriceGuardRail::public_record), "cancellations": values_record(&self.cancellations, IntentCancellation::public_record), "disputes": values_record(&self.disputes, BatchDispute::public_record), "audit_events": values_record(&self.audit_events, AuditTrailEvent::public_record) })
    }
    fn validate_height_windows(&self) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
        for (intent_id, intent) in &self.route_intents {
            if intent.status.live() && intent.expires_at_height < self.height {
                return Err(format!(
                    "route intent {intent_id} expired before current height"
                ));
            }
        }
        for (rebate_id, rebate) in &self.sponsor_rebates {
            if rebate.status.reservable() && rebate.expires_at_height < self.height {
                return Err(format!(
                    "sponsor rebate {rebate_id} expired before current height"
                ));
            }
        }
        for (credit_id, credit) in &self.solver_credits {
            if credit.status.usable() && credit.expires_at_height < self.height {
                return Err(format!(
                    "solver credit {credit_id} expired before current height"
                ));
            }
        }
        Ok(())
    }
    fn validate_references(&self) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
        let token_ids = self.tokens.keys().cloned().collect::<BTreeSet<_>>();
        for (pool_id, pool) in &self.amm_pools {
            ensure_contains(
                &token_ids,
                &pool.base_asset_id,
                "amm_pool.base_asset_id",
                pool_id,
            )?;
            ensure_contains(
                &token_ids,
                &pool.quote_asset_id,
                "amm_pool.quote_asset_id",
                pool_id,
            )?;
        }
        for (intent_id, intent) in &self.route_intents {
            ensure_contains(
                &token_ids,
                &intent.input_asset_id,
                "route_intent.input_asset_id",
                intent_id,
            )?;
            ensure_contains(
                &token_ids,
                &intent.output_asset_id,
                "route_intent.output_asset_id",
                intent_id,
            )?;
        }
        for (hop_id, hop) in &self.route_hops {
            if !self.route_intents.contains_key(&hop.intent_id) {
                return Err(format!("route hop {hop_id} references missing intent"));
            }
            if !self.amm_pools.contains_key(&hop.pool_id) {
                return Err(format!("route hop {hop_id} references missing pool"));
            }
        }
        for (bucket_id, bucket) in &self.netted_asset_buckets {
            if !self.settlement_batches.contains_key(&bucket.batch_id) {
                return Err(format!(
                    "netted asset bucket {bucket_id} references missing batch"
                ));
            }
            ensure_contains(
                &token_ids,
                &bucket.input_asset_id,
                "bucket.input_asset_id",
                bucket_id,
            )?;
            ensure_contains(
                &token_ids,
                &bucket.output_asset_id,
                "bucket.output_asset_id",
                bucket_id,
            )?;
        }
        for (receipt_id, receipt) in &self.settlement_receipts {
            if !self.settlement_batches.contains_key(&receipt.batch_id) {
                return Err(format!(
                    "settlement receipt {receipt_id} references missing batch"
                ));
            }
            if !self.route_intents.contains_key(&receipt.intent_id) {
                return Err(format!(
                    "settlement receipt {receipt_id} references missing intent"
                ));
            }
        }
        Ok(())
    }
    fn validate_limits(&self) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
        if self.route_intents.len() as u64 > self.config.max_intents_per_batch.saturating_mul(8) {
            return Err("route intent backlog exceeds configured devnet envelope".to_string());
        }
        for (intent_id, intent) in &self.route_intents {
            if intent.max_hops > self.config.max_route_hops {
                return Err(format!("route intent {intent_id} exceeds max route hops"));
            }
            if intent.fee_ceiling_bps > self.config.max_fee_ceiling_bps {
                return Err(format!("route intent {intent_id} exceeds fee ceiling"));
            }
        }
        for (rebate_id, rebate) in &self.sponsor_rebates {
            if rebate.coverage_bps < self.config.min_rebate_coverage_bps {
                return Err(format!("sponsor rebate {rebate_id} below minimum coverage"));
            }
        }
        for (attestation_id, attestation) in &self.solver_attestations {
            if attestation.security_bits < self.config.min_pq_security_bits {
                return Err(format!(
                    "solver attestation {attestation_id} below pq security floor"
                ));
            }
        }
        Ok(())
    }
    fn seed_devnet_records(&mut self) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
        let wxmr = ConfidentialToken {
            token_id: "asset:wxmr".to_string(),
            symbol_commitment: commitment("TOKEN", "WXMR"),
            decimals: "12".to_string(),
            asset_registry_root: commitment("REGISTRY", "wxmr"),
            compliance_policy_root: commitment("POLICY", "private-transfer"),
            transfer_hook_root: commitment("HOOK", "confidential-transfer"),
            active: true,
        };
        self.tokens.insert(wxmr.token_id.clone(), wxmr);
        let dusd = ConfidentialToken {
            token_id: "asset:dusd".to_string(),
            symbol_commitment: commitment("TOKEN", "DUSD"),
            decimals: "6".to_string(),
            asset_registry_root: commitment("REGISTRY", "dusd"),
            compliance_policy_root: commitment("POLICY", "stable-private-transfer"),
            transfer_hook_root: commitment("HOOK", "confidential-transfer"),
            active: true,
        };
        self.tokens.insert(dusd.token_id.clone(), dusd);
        let pool = PrivateAmmPool {
            pool_id: "pool:wxmr-dusd:stable".to_string(),
            base_asset_id: "asset:wxmr".to_string(),
            quote_asset_id: "asset:dusd".to_string(),
            fee_bps: 18,
            liquidity_commitment: commitment("LIQUIDITY", "wxmr-dusd"),
            invariant_commitment: commitment("INVARIANT", "constant-product-private"),
            oracle_root: commitment("ORACLE", "wxmr-dusd-twap"),
            active: true,
        };
        self.amm_pools.insert(pool.pool_id.clone(), pool);
        let batch = PrivateSettlementBatch {
            batch_id: "batch:devnet:0001".to_string(),
            epoch: "epoch:3".to_string(),
            opened_at_height: self.height,
            sealed_at_height: self.height + self.config.batch_window_blocks,
            solver_commitment: commitment("SOLVER", "devnet-solver"),
            intent_root: commitment("INTENT-ROOT", "devnet"),
            bucket_root: commitment("BUCKET-ROOT", "devnet"),
            rebate_root: commitment("REBATE-ROOT", "devnet"),
            credit_root: commitment("CREDIT-ROOT", "devnet"),
            settlement_price_root: commitment("PRICE-ROOT", "devnet"),
            fee_root: commitment("FEE-ROOT", "devnet"),
            status: SettlementBatchStatus::Posted,
        };
        self.settlement_batches
            .insert(batch.batch_id.clone(), batch);
        let band = SlippagePrivacyBand {
            band_id: "band:wxmr-dusd:low-slip".to_string(),
            input_asset_id: "asset:wxmr".to_string(),
            output_asset_id: "asset:dusd".to_string(),
            min_price_commitment: commitment("PRICE-MIN", "wxmr-dusd"),
            max_price_commitment: commitment("PRICE-MAX", "wxmr-dusd"),
            noise_commitment: commitment("NOISE", "band-1"),
            min_participants: 16,
            current_participants: 24,
            max_slippage_bps: 45,
        };
        self.slippage_privacy_bands
            .insert(band.band_id.clone(), band);
        let intent = RouteIntent {
            intent_id: "intent:devnet:swap:0001".to_string(),
            owner_commitment: commitment("OWNER", "alice"),
            side: SwapSide::ExactInput,
            input_asset_id: "asset:wxmr".to_string(),
            output_asset_id: "asset:dusd".to_string(),
            amount_commitment: commitment("AMOUNT", "wxmr-in"),
            limit_price_commitment: commitment("LIMIT", "dusd-out"),
            slippage_bucket_id: "band:wxmr-dusd:low-slip".to_string(),
            route_hint_root: commitment("ROUTE-HINT", "direct"),
            fee_ceiling_bps: 24,
            max_hops: 2,
            created_at_height: self.height,
            expires_at_height: self.height + self.config.intent_ttl_blocks,
            status: RouteIntentStatus::Settled,
        };
        self.route_intents.insert(intent.intent_id.clone(), intent);
        let hop = RouteHopCommitment {
            hop_id: "hop:devnet:0001:0".to_string(),
            intent_id: "intent:devnet:swap:0001".to_string(),
            pool_id: "pool:wxmr-dusd:stable".to_string(),
            input_asset_id: "asset:wxmr".to_string(),
            output_asset_id: "asset:dusd".to_string(),
            encrypted_path_commitment: commitment("PATH", "direct-hop"),
            expected_fill_commitment: commitment("FILL", "direct-hop"),
            hop_index: 0,
            fee_bps: 18,
        };
        self.route_hops.insert(hop.hop_id.clone(), hop);
        let bucket = NettedAssetBucket {
            bucket_id: "bucket:devnet:wxmr-dusd".to_string(),
            batch_id: "batch:devnet:0001".to_string(),
            input_asset_id: "asset:wxmr".to_string(),
            output_asset_id: "asset:dusd".to_string(),
            privacy_bucket_id: "band:wxmr-dusd:low-slip".to_string(),
            gross_input_commitment: commitment("GROSS-IN", "wxmr"),
            gross_output_commitment: commitment("GROSS-OUT", "dusd"),
            net_input_commitment: commitment("NET-IN", "wxmr"),
            net_output_commitment: commitment("NET-OUT", "dusd"),
            participant_root: commitment("PARTICIPANTS", "bucket-1"),
            status: AssetBucketStatus::Settled,
        };
        self.netted_asset_buckets
            .insert(bucket.bucket_id.clone(), bucket);
        let rebate = SponsorRebate {
            rebate_id: "rebate:devnet:sponsor:0001".to_string(),
            sponsor_commitment: commitment("SPONSOR", "fee-sponsor"),
            asset_id: "asset:dusd".to_string(),
            amount_commitment: commitment("REBATE-AMOUNT", "dusd"),
            reserved_for_batch_id: "batch:devnet:0001".to_string(),
            coverage_bps: 1_800,
            expires_at_height: self.height + self.config.sponsor_rebate_ttl_blocks,
            status: SponsorRebateStatus::Applied,
        };
        self.sponsor_rebates
            .insert(rebate.rebate_id.clone(), rebate);
        let credit = SolverCredit {
            credit_id: "credit:devnet:solver:0001".to_string(),
            solver_commitment: commitment("SOLVER", "devnet-solver"),
            asset_id: "asset:dusd".to_string(),
            amount_commitment: commitment("SOLVER-CREDIT", "dusd"),
            earned_from_batch_id: "batch:devnet:0001".to_string(),
            expires_at_height: self.height + self.config.solver_credit_ttl_blocks,
            status: SolverCreditStatus::Earned,
        };
        self.solver_credits.insert(credit.credit_id.clone(), credit);
        let ceiling = LowFeeCeiling {
            ceiling_id: "ceiling:wxmr-dusd:devnet".to_string(),
            asset_pair_key: "asset:wxmr/asset:dusd".to_string(),
            sponsor_id: "sponsor:devnet".to_string(),
            max_fee_bps: 30,
            max_total_fee_commitment: commitment("MAX-FEE", "wxmr-dusd"),
            valid_from_height: self.height,
            valid_until_height: self.height + self.config.sponsor_rebate_ttl_blocks,
            policy_root: commitment("FEE-POLICY", "low-fee"),
        };
        self.low_fee_ceilings
            .insert(ceiling.ceiling_id.clone(), ceiling);
        let receipt = SettlementReceipt {
            receipt_id: "receipt:devnet:0001".to_string(),
            batch_id: "batch:devnet:0001".to_string(),
            intent_id: "intent:devnet:swap:0001".to_string(),
            owner_commitment: commitment("OWNER", "alice"),
            input_nullifier_root: commitment("NULLIFIER", "input"),
            output_note_root: commitment("NOTE", "output"),
            fee_note_root: commitment("NOTE", "fee"),
            rebate_note_root: commitment("NOTE", "rebate"),
            solver_credit_root: commitment("NOTE", "credit"),
            settlement_proof_root: commitment("PROOF", "settled"),
            status: ReceiptStatus::Finalized,
        };
        self.settlement_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        let attestation = SolverAttestation {
            attestation_id: "attestation:devnet:solver:0001".to_string(),
            solver_commitment: commitment("SOLVER", "devnet-solver"),
            batch_id: "batch:devnet:0001".to_string(),
            pq_public_key_commitment: commitment("PQ-PK", "devnet-solver"),
            signature_root: commitment("PQ-SIG", "batch-1"),
            security_bits: self.config.min_pq_security_bits,
            valid_until_height: self.height + self.config.solver_credit_ttl_blocks,
        };
        self.solver_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        let proof = NettingProofEnvelope {
            proof_id: "proof:devnet:batch:0001".to_string(),
            batch_id: "batch:devnet:0001".to_string(),
            circuit_id: "circuit:confidential-swap-netting:v1".to_string(),
            public_input_root: commitment("PUBLIC-INPUT", "batch-1"),
            private_witness_commitment: commitment("PRIVATE-WITNESS", "batch-1"),
            aggregate_receipt_root: commitment("RECEIPTS", "batch-1"),
            recursive_proof_root: commitment("RECURSIVE-PROOF", "batch-1"),
            verifier_key_root: commitment("VK", "swap-netting"),
        };
        self.netting_proofs.insert(proof.proof_id.clone(), proof);
        let reservation = LiquidityReservation {
            reservation_id: "reservation:devnet:0001".to_string(),
            pool_id: "pool:wxmr-dusd:stable".to_string(),
            batch_id: "batch:devnet:0001".to_string(),
            solver_commitment: commitment("SOLVER", "devnet-solver"),
            input_asset_id: "asset:wxmr".to_string(),
            output_asset_id: "asset:dusd".to_string(),
            liquidity_commitment: commitment("RESERVED-LIQUIDITY", "batch-1"),
            expires_at_height: self.height + self.config.batch_window_blocks,
        };
        self.liquidity_reservations
            .insert(reservation.reservation_id.clone(), reservation);
        let guard = PriceGuardRail {
            guard_id: "guard:wxmr-dusd:devnet".to_string(),
            asset_pair_key: "asset:wxmr/asset:dusd".to_string(),
            oracle_root: commitment("ORACLE", "wxmr-dusd-twap"),
            min_price_commitment: commitment("GUARD-MIN", "wxmr-dusd"),
            max_price_commitment: commitment("GUARD-MAX", "wxmr-dusd"),
            twap_window: "64-blocks".to_string(),
            max_deviation_bps: 120,
        };
        self.price_guard_rails.insert(guard.guard_id.clone(), guard);
        let audit = AuditTrailEvent {
            event_id: "event:devnet:batch-posted:0001".to_string(),
            event_kind: "batch_posted".to_string(),
            subject_id: "batch:devnet:0001".to_string(),
            subject_root: commitment("SUBJECT", "batch-1"),
            emitted_at_height: self.height + self.config.batch_window_blocks,
            operator_commitment: commitment("OPERATOR", "devnet"),
        };
        self.audit_events.insert(audit.event_id.clone(), audit);
        Ok(())
    }
}

pub fn root_from_record(record: &Value) -> String {
    payload_root("LOW-FEE-CONFIDENTIAL-SWAP-STATE", record)
}
pub fn devnet() -> LowFeeConfidentialTokenSwapNettingEngineResult<State> {
    State::devnet()
}
fn payload_root(domain: &str, value: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(value)], 32)
}
fn commitment(domain: &str, label: &str) -> String {
    domain_hash(
        "LOW-FEE-CONFIDENTIAL-SWAP-COMMITMENT",
        &[HashPart::Str(domain), HashPart::Str(label)],
        32,
    )
}
fn values_record<T, F>(map: &BTreeMap<String, T>, record: F) -> Vec<Value>
where
    F: Fn(&T) -> Value,
{
    map.values().map(record).collect::<Vec<_>>()
}
fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = values_record(map, record);
    merkle_root(domain, &leaves)
}
fn validate_map<T, F>(
    label: &str,
    map: &BTreeMap<String, T>,
    validate: F,
) -> LowFeeConfidentialTokenSwapNettingEngineResult<()>
where
    F: Fn(&T) -> LowFeeConfidentialTokenSwapNettingEngineResult<()>,
{
    for (key, value) in map {
        ensure_non_empty(label, key)?;
        validate(value)?;
    }
    Ok(())
}
fn ensure_non_empty(
    label: &str,
    value: &str,
) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}
fn ensure_non_zero(label: &str, value: u64) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
    if value == 0 {
        return Err(format!("{label} must be non-zero"));
    }
    Ok(())
}
fn ensure_named_number(
    label: &str,
    value: u64,
) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
    let encoded = value.to_string();
    ensure_non_empty(label, &encoded)
}
fn ensure_bps(label: &str, value: u64) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
    if value > LOW_FEE_CONFIDENTIAL_TOKEN_SWAP_NETTING_ENGINE_MAX_BPS {
        return Err(format!("{label} exceeds basis point maximum"));
    }
    Ok(())
}
fn ensure_contains(
    values: &BTreeSet<String>,
    needle: &str,
    field: &str,
    owner: &str,
) -> LowFeeConfidentialTokenSwapNettingEngineResult<()> {
    if !values.contains(needle) {
        return Err(format!("{field} on {owner} references unknown token"));
    }
    Ok(())
}
