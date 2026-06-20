use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LiquidityBatcherResult<T> = Result<T, String>;

pub const PRIVATE_L2_LIQUIDITY_BATCHER_PROTOCOL_VERSION: &str =
    "nebula-private-l2-liquidity-batcher-v1";
pub const PRIVATE_L2_LIQUIDITY_BATCHER_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_LIQUIDITY_BATCHER_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_L2_LIQUIDITY_BATCHER_SEALED_INTENT_SCHEME: &str =
    "zk-sealed-private-l2-liquidity-intent-v1";
pub const PRIVATE_L2_LIQUIDITY_BATCHER_PRIVATE_ROUTE_SCHEME: &str =
    "zk-private-amm-darkpool-route-v1";
pub const PRIVATE_L2_LIQUIDITY_BATCHER_LOW_FEE_NETTING_SCHEME: &str =
    "low-fee-liquidity-delta-netting-v1";
pub const PRIVATE_L2_LIQUIDITY_BATCHER_SPONSOR_SCHEME: &str =
    "zk-liquidity-fee-sponsor-commitment-v1";
pub const PRIVATE_L2_LIQUIDITY_BATCHER_PQ_AUTH_SCHEME: &str =
    "ml-dsa-87-liquidity-batch-authorization-v1";
pub const PRIVATE_L2_LIQUIDITY_BATCHER_PRIVACY_PROOF_SCHEME: &str =
    "zk-private-liquidity-batch-proof-v1";
pub const PRIVATE_L2_LIQUIDITY_BATCHER_RECEIPT_SCHEME: &str =
    "settlement-ready-private-liquidity-receipt-v1";
pub const PRIVATE_L2_LIQUIDITY_BATCHER_DEVNET_HEIGHT: u64 = 110_000;
pub const PRIVATE_L2_LIQUIDITY_BATCHER_DEVNET_LOW_FEE_LANE: &str =
    "devnet-private-l2-liquidity-low-fee";
pub const PRIVATE_L2_LIQUIDITY_BATCHER_DEVNET_AMM_BOOK: &str = "devnet-private-amm-book";
pub const PRIVATE_L2_LIQUIDITY_BATCHER_DEVNET_DARKPOOL_BOOK: &str = "devnet-private-darkpool-book";
pub const PRIVATE_L2_LIQUIDITY_BATCHER_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_LIQUIDITY_BATCHER_DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 6;
pub const PRIVATE_L2_LIQUIDITY_BATCHER_DEFAULT_INTENT_TTL_BLOCKS: u64 = 24;
pub const PRIVATE_L2_LIQUIDITY_BATCHER_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 12;
pub const PRIVATE_L2_LIQUIDITY_BATCHER_DEFAULT_MAX_INTENTS_PER_BATCH: usize = 512;
pub const PRIVATE_L2_LIQUIDITY_BATCHER_DEFAULT_MAX_ROUTE_HOPS: usize = 8;
pub const PRIVATE_L2_LIQUIDITY_BATCHER_DEFAULT_MIN_PRIVACY_SET: u64 = 48;
pub const PRIVATE_L2_LIQUIDITY_BATCHER_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_LIQUIDITY_BATCHER_DEFAULT_MAX_USER_FEE_BPS: u64 = 30;
pub const PRIVATE_L2_LIQUIDITY_BATCHER_DEFAULT_MAX_NETTING_IMBALANCE_BPS: u64 = 225;
pub const PRIVATE_L2_LIQUIDITY_BATCHER_DEFAULT_MIN_SPONSOR_COVERAGE_BPS: u64 = 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityIntentKind {
    SwapExactIn,
    SwapExactOut,
    AddLiquidity,
    RemoveLiquidity,
    Rebalance,
    CrossPoolArbitrage,
}

impl LiquidityIntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SwapExactIn => "swap_exact_in",
            Self::SwapExactOut => "swap_exact_out",
            Self::AddLiquidity => "add_liquidity",
            Self::RemoveLiquidity => "remove_liquidity",
            Self::Rebalance => "rebalance",
            Self::CrossPoolArbitrage => "cross_pool_arbitrage",
        }
    }

    pub fn default_weight(self) -> u64 {
        match self {
            Self::SwapExactIn | Self::SwapExactOut => 18,
            Self::AddLiquidity | Self::RemoveLiquidity => 24,
            Self::Rebalance => 32,
            Self::CrossPoolArbitrage => 40,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Submitted,
    Accepted,
    Routed,
    Netted,
    Settled,
    Expired,
    Cancelled,
    Rejected,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Routed => "routed",
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
            Self::Submitted | Self::Accepted | Self::Routed | Self::Netted
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteVenueKind {
    AmmPool,
    Darkpool,
    InternalNetting,
    SponsorRebate,
    SettlementVault,
}

impl RouteVenueKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AmmPool => "amm_pool",
            Self::Darkpool => "darkpool",
            Self::InternalNetting => "internal_netting",
            Self::SponsorRebate => "sponsor_rebate",
            Self::SettlementVault => "settlement_vault",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    Proving,
    SettlementReady,
    Settled,
    Disputed,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Proving => "proving",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn can_settle(self) -> bool {
        matches!(self, Self::SettlementReady)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaDirection {
    Credit,
    Debit,
    NetZero,
}

impl DeltaDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Credit => "credit",
            Self::Debit => "debit",
            Self::NetZero => "net_zero",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Draft,
    Published,
    Finalized,
    Disputed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub hash_suite: String,
    pub sealed_intent_scheme: String,
    pub private_route_scheme: String,
    pub low_fee_netting_scheme: String,
    pub sponsor_scheme: String,
    pub pq_auth_scheme: String,
    pub privacy_proof_scheme: String,
    pub receipt_scheme: String,
    pub low_fee_lane: String,
    pub batch_window_blocks: u64,
    pub intent_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub max_intents_per_batch: usize,
    pub max_route_hops: usize,
    pub min_privacy_set: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_netting_imbalance_bps: u64,
    pub min_sponsor_coverage_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_LIQUIDITY_BATCHER_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_LIQUIDITY_BATCHER_HASH_SUITE.to_string(),
            sealed_intent_scheme: PRIVATE_L2_LIQUIDITY_BATCHER_SEALED_INTENT_SCHEME.to_string(),
            private_route_scheme: PRIVATE_L2_LIQUIDITY_BATCHER_PRIVATE_ROUTE_SCHEME.to_string(),
            low_fee_netting_scheme: PRIVATE_L2_LIQUIDITY_BATCHER_LOW_FEE_NETTING_SCHEME.to_string(),
            sponsor_scheme: PRIVATE_L2_LIQUIDITY_BATCHER_SPONSOR_SCHEME.to_string(),
            pq_auth_scheme: PRIVATE_L2_LIQUIDITY_BATCHER_PQ_AUTH_SCHEME.to_string(),
            privacy_proof_scheme: PRIVATE_L2_LIQUIDITY_BATCHER_PRIVACY_PROOF_SCHEME.to_string(),
            receipt_scheme: PRIVATE_L2_LIQUIDITY_BATCHER_RECEIPT_SCHEME.to_string(),
            low_fee_lane: PRIVATE_L2_LIQUIDITY_BATCHER_DEVNET_LOW_FEE_LANE.to_string(),
            batch_window_blocks: PRIVATE_L2_LIQUIDITY_BATCHER_DEFAULT_BATCH_WINDOW_BLOCKS,
            intent_ttl_blocks: PRIVATE_L2_LIQUIDITY_BATCHER_DEFAULT_INTENT_TTL_BLOCKS,
            settlement_ttl_blocks: PRIVATE_L2_LIQUIDITY_BATCHER_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            max_intents_per_batch: PRIVATE_L2_LIQUIDITY_BATCHER_DEFAULT_MAX_INTENTS_PER_BATCH,
            max_route_hops: PRIVATE_L2_LIQUIDITY_BATCHER_DEFAULT_MAX_ROUTE_HOPS,
            min_privacy_set: PRIVATE_L2_LIQUIDITY_BATCHER_DEFAULT_MIN_PRIVACY_SET,
            min_pq_security_bits: PRIVATE_L2_LIQUIDITY_BATCHER_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: PRIVATE_L2_LIQUIDITY_BATCHER_DEFAULT_MAX_USER_FEE_BPS,
            max_netting_imbalance_bps:
                PRIVATE_L2_LIQUIDITY_BATCHER_DEFAULT_MAX_NETTING_IMBALANCE_BPS,
            min_sponsor_coverage_bps: PRIVATE_L2_LIQUIDITY_BATCHER_DEFAULT_MIN_SPONSOR_COVERAGE_BPS,
        }
    }

    pub fn validate(&self) -> PrivateL2LiquidityBatcherResult<()> {
        if self.protocol_version.is_empty()
            || self.chain_id.is_empty()
            || self.hash_suite.is_empty()
            || self.sealed_intent_scheme.is_empty()
            || self.private_route_scheme.is_empty()
            || self.low_fee_netting_scheme.is_empty()
            || self.sponsor_scheme.is_empty()
            || self.pq_auth_scheme.is_empty()
            || self.privacy_proof_scheme.is_empty()
            || self.receipt_scheme.is_empty()
            || self.low_fee_lane.is_empty()
        {
            return Err("private l2 liquidity batcher labels cannot be empty".to_string());
        }
        if self.batch_window_blocks == 0
            || self.intent_ttl_blocks == 0
            || self.settlement_ttl_blocks == 0
            || self.max_intents_per_batch == 0
            || self.max_route_hops == 0
            || self.min_privacy_set == 0
            || self.min_pq_security_bits == 0
        {
            return Err("private l2 liquidity batcher limits must be non-zero".to_string());
        }
        if self.max_user_fee_bps > PRIVATE_L2_LIQUIDITY_BATCHER_MAX_BPS
            || self.max_netting_imbalance_bps > PRIVATE_L2_LIQUIDITY_BATCHER_MAX_BPS
            || self.min_sponsor_coverage_bps > PRIVATE_L2_LIQUIDITY_BATCHER_MAX_BPS
        {
            return Err("private l2 liquidity batcher bps values cannot exceed 100%".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": PRIVATE_L2_LIQUIDITY_BATCHER_SCHEMA_VERSION,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "sealed_intent_scheme": self.sealed_intent_scheme,
            "private_route_scheme": self.private_route_scheme,
            "low_fee_netting_scheme": self.low_fee_netting_scheme,
            "sponsor_scheme": self.sponsor_scheme,
            "pq_auth_scheme": self.pq_auth_scheme,
            "privacy_proof_scheme": self.privacy_proof_scheme,
            "receipt_scheme": self.receipt_scheme,
            "low_fee_lane": self.low_fee_lane,
            "batch_window_blocks": self.batch_window_blocks,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "max_intents_per_batch": self.max_intents_per_batch,
            "max_route_hops": self.max_route_hops,
            "min_privacy_set": self.min_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_netting_imbalance_bps": self.max_netting_imbalance_bps,
            "min_sponsor_coverage_bps": self.min_sponsor_coverage_bps,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub next_intent_nonce: u64,
    pub next_route_nonce: u64,
    pub next_batch_nonce: u64,
    pub intents_submitted: u64,
    pub intents_accepted: u64,
    pub intents_rejected: u64,
    pub batches_built: u64,
    pub batches_settled: u64,
    pub settlement_deltas_ready: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "next_intent_nonce": self.next_intent_nonce,
            "next_route_nonce": self.next_route_nonce,
            "next_batch_nonce": self.next_batch_nonce,
            "intents_submitted": self.intents_submitted,
            "intents_accepted": self.intents_accepted,
            "intents_rejected": self.intents_rejected,
            "batches_built": self.batches_built,
            "batches_settled": self.batches_settled,
            "settlement_deltas_ready": self.settlement_deltas_ready,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityIntentRequest {
    pub owner_commitment: String,
    pub intent_kind: LiquidityIntentKind,
    pub asset_in_commitment: String,
    pub asset_out_commitment: String,
    pub amount_band_root: String,
    pub limit_price_root: String,
    pub slippage_bps: u64,
    pub fee_cap_bps: u64,
    pub amm_pool_root: String,
    pub darkpool_root: String,
    pub route_hint_root: String,
    pub sponsor_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub nullifier_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl LiquidityIntentRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LiquidityBatcherResult<()> {
        validate_commitment(&self.owner_commitment, "owner commitment")?;
        validate_root(&self.asset_in_commitment, "asset in commitment")?;
        validate_root(&self.asset_out_commitment, "asset out commitment")?;
        validate_root(&self.amount_band_root, "amount band root")?;
        validate_root(&self.limit_price_root, "limit price root")?;
        validate_root(&self.amm_pool_root, "amm pool root")?;
        validate_root(&self.darkpool_root, "darkpool root")?;
        validate_root(&self.route_hint_root, "route hint root")?;
        validate_root(&self.sponsor_root, "sponsor root")?;
        validate_root(&self.pq_authorization_root, "pq authorization root")?;
        validate_root(&self.privacy_proof_root, "privacy proof root")?;
        validate_root(&self.nullifier_root, "nullifier root")?;
        if self.opened_at_height >= self.expires_at_height {
            return Err("liquidity intent expiry must be after open height".to_string());
        }
        if self.expires_at_height - self.opened_at_height > config.intent_ttl_blocks {
            return Err("liquidity intent ttl exceeds config".to_string());
        }
        if self.slippage_bps > PRIVATE_L2_LIQUIDITY_BATCHER_MAX_BPS
            || self.fee_cap_bps > config.max_user_fee_bps
        {
            return Err("liquidity intent fee or slippage bps exceeds policy".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedLiquidityIntent {
    pub intent_id: String,
    pub status: IntentStatus,
    pub owner_commitment: String,
    pub intent_kind: LiquidityIntentKind,
    pub asset_pair_root: String,
    pub amount_band_root: String,
    pub limit_price_root: String,
    pub slippage_bps: u64,
    pub fee_cap_bps: u64,
    pub amm_pool_root: String,
    pub darkpool_root: String,
    pub route_hint_root: String,
    pub sponsor_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub nullifier_root: String,
    pub sealed_payload_root: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub privacy_weight: u64,
}

impl SealedLiquidityIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "status": self.status.as_str(),
            "owner_commitment": self.owner_commitment,
            "intent_kind": self.intent_kind.as_str(),
            "asset_pair_root": self.asset_pair_root,
            "amount_band_root": self.amount_band_root,
            "limit_price_root": self.limit_price_root,
            "slippage_bps": self.slippage_bps,
            "fee_cap_bps": self.fee_cap_bps,
            "amm_pool_root": self.amm_pool_root,
            "darkpool_root": self.darkpool_root,
            "route_hint_root": self.route_hint_root,
            "sponsor_root": self.sponsor_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "nullifier_root": self.nullifier_root,
            "sealed_payload_root": self.sealed_payload_root,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "privacy_weight": self.privacy_weight,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-LIQUIDITY-BATCHER-INTENT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteHop {
    pub hop_index: u64,
    pub venue_kind: RouteVenueKind,
    pub venue_commitment: String,
    pub pool_root_before: String,
    pub pool_root_after: String,
    pub darkpool_root_before: String,
    pub darkpool_root_after: String,
    pub fee_bps: u64,
    pub witness_root: String,
}

impl RouteHop {
    pub fn public_record(&self) -> Value {
        json!({
            "hop_index": self.hop_index,
            "venue_kind": self.venue_kind.as_str(),
            "venue_commitment": self.venue_commitment,
            "pool_root_before": self.pool_root_before,
            "pool_root_after": self.pool_root_after,
            "darkpool_root_before": self.darkpool_root_before,
            "darkpool_root_after": self.darkpool_root_after,
            "fee_bps": self.fee_bps,
            "witness_root": self.witness_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSwapRoute {
    pub route_id: String,
    pub intent_id: String,
    pub route_commitment: String,
    pub route_root: String,
    pub hop_root: String,
    pub amm_pool_root_before: String,
    pub amm_pool_root_after: String,
    pub darkpool_root_before: String,
    pub darkpool_root_after: String,
    pub sponsor_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub max_fee_bps: u64,
    pub hops: Vec<RouteHop>,
}

impl PrivateSwapRoute {
    pub fn public_record(&self) -> Value {
        json!({
            "route_id": self.route_id,
            "intent_id": self.intent_id,
            "route_commitment": self.route_commitment,
            "route_root": self.route_root,
            "hop_root": self.hop_root,
            "amm_pool_root_before": self.amm_pool_root_before,
            "amm_pool_root_after": self.amm_pool_root_after,
            "darkpool_root_before": self.darkpool_root_before,
            "darkpool_root_after": self.darkpool_root_after,
            "sponsor_root": self.sponsor_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "max_fee_bps": self.max_fee_bps,
            "hop_count": self.hops.len(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-LIQUIDITY-BATCHER-ROUTE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityDelta {
    pub delta_id: String,
    pub batch_id: String,
    pub asset_commitment: String,
    pub venue_commitment: String,
    pub direction: DeltaDirection,
    pub amount_root: String,
    pub fee_root: String,
    pub sponsor_credit_root: String,
    pub settlement_account_root: String,
    pub proof_root: String,
}

impl LiquidityDelta {
    pub fn public_record(&self) -> Value {
        json!({
            "delta_id": self.delta_id,
            "batch_id": self.batch_id,
            "asset_commitment": self.asset_commitment,
            "venue_commitment": self.venue_commitment,
            "direction": self.direction.as_str(),
            "amount_root": self.amount_root,
            "fee_root": self.fee_root,
            "sponsor_credit_root": self.sponsor_credit_root,
            "settlement_account_root": self.settlement_account_root,
            "proof_root": self.proof_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityBatch {
    pub batch_id: String,
    pub status: BatchStatus,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub settlement_deadline_height: u64,
    pub intent_root: String,
    pub route_root: String,
    pub amm_pool_root_before: String,
    pub amm_pool_root_after: String,
    pub darkpool_root_before: String,
    pub darkpool_root_after: String,
    pub netting_root: String,
    pub sponsor_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub settlement_delta_root: String,
    pub low_fee_lane: String,
    pub total_fee_bps: u64,
    pub netting_imbalance_bps: u64,
    pub privacy_set_size: u64,
    pub intent_ids: Vec<String>,
    pub route_ids: Vec<String>,
    pub settlement_delta_ids: Vec<String>,
}

impl LiquidityBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "settlement_deadline_height": self.settlement_deadline_height,
            "intent_root": self.intent_root,
            "route_root": self.route_root,
            "amm_pool_root_before": self.amm_pool_root_before,
            "amm_pool_root_after": self.amm_pool_root_after,
            "darkpool_root_before": self.darkpool_root_before,
            "darkpool_root_after": self.darkpool_root_after,
            "netting_root": self.netting_root,
            "sponsor_root": self.sponsor_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "settlement_delta_root": self.settlement_delta_root,
            "low_fee_lane": self.low_fee_lane,
            "total_fee_bps": self.total_fee_bps,
            "netting_imbalance_bps": self.netting_imbalance_bps,
            "privacy_set_size": self.privacy_set_size,
            "intent_count": self.intent_ids.len(),
            "route_count": self.route_ids.len(),
            "settlement_delta_count": self.settlement_delta_ids.len(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-LIQUIDITY-BATCHER-BATCH",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub status: ReceiptStatus,
    pub batch_root: String,
    pub settlement_delta_root: String,
    pub settlement_tx_root: String,
    pub sponsor_settlement_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub published_at_height: u64,
    pub finalized_at_height: Option<u64>,
}

impl BatchReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "batch_root": self.batch_root,
            "settlement_delta_root": self.settlement_delta_root,
            "settlement_tx_root": self.settlement_tx_root,
            "sponsor_settlement_root": self.sponsor_settlement_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "published_at_height": self.published_at_height,
            "finalized_at_height": self.finalized_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-LIQUIDITY-BATCHER-RECEIPT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildBatchRequest {
    pub intent_ids: Vec<String>,
    pub route_proof_root: String,
    pub amm_pool_root_after: String,
    pub darkpool_root_after: String,
    pub netting_root: String,
    pub sponsor_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub total_fee_bps: u64,
    pub netting_imbalance_bps: u64,
    pub privacy_set_size: u64,
    pub sealed_at_height: u64,
}

impl BuildBatchRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LiquidityBatcherResult<()> {
        if self.intent_ids.is_empty() {
            return Err("liquidity batch requires at least one intent".to_string());
        }
        if self.intent_ids.len() > config.max_intents_per_batch {
            return Err("liquidity batch exceeds max intents".to_string());
        }
        validate_root(&self.route_proof_root, "route proof root")?;
        validate_root(&self.amm_pool_root_after, "amm pool root after")?;
        validate_root(&self.darkpool_root_after, "darkpool root after")?;
        validate_root(&self.netting_root, "netting root")?;
        validate_root(&self.sponsor_root, "sponsor root")?;
        validate_root(&self.pq_authorization_root, "pq authorization root")?;
        validate_root(&self.privacy_proof_root, "privacy proof root")?;
        if self.total_fee_bps > config.max_user_fee_bps {
            return Err("liquidity batch fee exceeds low-fee cap".to_string());
        }
        if self.netting_imbalance_bps > config.max_netting_imbalance_bps {
            return Err("liquidity batch netting imbalance exceeds policy".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set {
            return Err("liquidity batch privacy set is below policy".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementRequest {
    pub batch_id: String,
    pub settlement_tx_root: String,
    pub sponsor_settlement_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub finalized_at_height: Option<u64>,
    pub settled_at_height: u64,
}

impl SettlementRequest {
    pub fn validate(&self) -> PrivateL2LiquidityBatcherResult<()> {
        validate_identifier(&self.batch_id, "batch id")?;
        validate_root(&self.settlement_tx_root, "settlement tx root")?;
        validate_root(&self.sponsor_settlement_root, "sponsor settlement root")?;
        validate_root(&self.pq_authorization_root, "pq authorization root")?;
        validate_root(&self.privacy_proof_root, "privacy proof root")?;
        if let Some(finalized_at_height) = self.finalized_at_height {
            if finalized_at_height < self.settled_at_height {
                return Err("receipt finalization height cannot precede settlement".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub amm_pool_book_root: String,
    pub darkpool_book_root: String,
    pub active_intents: BTreeMap<String, SealedLiquidityIntent>,
    pub private_routes: BTreeMap<String, PrivateSwapRoute>,
    pub batches: BTreeMap<String, LiquidityBatch>,
    pub settlement_deltas: BTreeMap<String, LiquidityDelta>,
    pub receipts: BTreeMap<String, BatchReceipt>,
    pub consumed_nullifier_roots: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let amm_pool_book_root = domain_hash(
            "PRIVATE-L2-LIQUIDITY-BATCHER-DEVNET-AMM-BOOK",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PRIVATE_L2_LIQUIDITY_BATCHER_DEVNET_AMM_BOOK),
            ],
            32,
        );
        let darkpool_book_root = domain_hash(
            "PRIVATE-L2-LIQUIDITY-BATCHER-DEVNET-DARKPOOL-BOOK",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PRIVATE_L2_LIQUIDITY_BATCHER_DEVNET_DARKPOOL_BOOK),
            ],
            32,
        );
        Self {
            config,
            counters: Counters::default(),
            current_height: PRIVATE_L2_LIQUIDITY_BATCHER_DEVNET_HEIGHT,
            amm_pool_book_root,
            darkpool_book_root,
            active_intents: BTreeMap::new(),
            private_routes: BTreeMap::new(),
            batches: BTreeMap::new(),
            settlement_deltas: BTreeMap::new(),
            receipts: BTreeMap::new(),
            consumed_nullifier_roots: BTreeSet::new(),
        }
    }

    pub fn submit_liquidity_intent(
        &mut self,
        request: LiquidityIntentRequest,
    ) -> PrivateL2LiquidityBatcherResult<SealedLiquidityIntent> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if request.opened_at_height
            < self
                .current_height
                .saturating_sub(self.config.intent_ttl_blocks)
        {
            return Err("liquidity intent open height is outside accepted window".to_string());
        }
        if self
            .consumed_nullifier_roots
            .contains(&request.nullifier_root)
            || self
                .active_intents
                .values()
                .any(|intent| intent.nullifier_root == request.nullifier_root)
        {
            self.counters.intents_rejected += 1;
            return Err(
                "liquidity intent nullifier root is already pending or consumed".to_string(),
            );
        }

        let nonce = self.counters.next_intent_nonce;
        let asset_pair_root = asset_pair_root(
            &request.asset_in_commitment,
            &request.asset_out_commitment,
            request.intent_kind,
        );
        let sealed_payload_root = sealed_payload_root(&request, &asset_pair_root, nonce);
        let intent_id = liquidity_intent_id(
            nonce,
            &request.owner_commitment,
            request.intent_kind,
            &asset_pair_root,
            &sealed_payload_root,
        );
        let intent = SealedLiquidityIntent {
            intent_id: intent_id.clone(),
            status: IntentStatus::Accepted,
            owner_commitment: request.owner_commitment,
            intent_kind: request.intent_kind,
            asset_pair_root,
            amount_band_root: request.amount_band_root,
            limit_price_root: request.limit_price_root,
            slippage_bps: request.slippage_bps,
            fee_cap_bps: request.fee_cap_bps,
            amm_pool_root: request.amm_pool_root,
            darkpool_root: request.darkpool_root,
            route_hint_root: request.route_hint_root,
            sponsor_root: request.sponsor_root,
            pq_authorization_root: request.pq_authorization_root,
            privacy_proof_root: request.privacy_proof_root,
            nullifier_root: request.nullifier_root,
            sealed_payload_root,
            submitted_at_height: request.opened_at_height,
            expires_at_height: request.expires_at_height,
            privacy_weight: request.intent_kind.default_weight(),
        };

        self.counters.next_intent_nonce += 1;
        self.counters.intents_submitted += 1;
        self.counters.intents_accepted += 1;
        self.current_height = self.current_height.max(intent.submitted_at_height);
        self.active_intents.insert(intent_id, intent.clone());
        Ok(intent)
    }

    pub fn build_batch(
        &mut self,
        request: BuildBatchRequest,
    ) -> PrivateL2LiquidityBatcherResult<LiquidityBatch> {
        self.config.validate()?;
        request.validate(&self.config)?;
        let unique_intents = request.intent_ids.iter().collect::<BTreeSet<_>>();
        if unique_intents.len() != request.intent_ids.len() {
            return Err("liquidity batch cannot include duplicate intent ids".to_string());
        }

        let mut selected = Vec::with_capacity(request.intent_ids.len());
        for intent_id in &request.intent_ids {
            let intent = self
                .active_intents
                .get(intent_id)
                .ok_or_else(|| format!("unknown liquidity intent id {intent_id}"))?;
            if !intent.status.live() {
                return Err(format!("liquidity intent {intent_id} is not live"));
            }
            if intent.expires_at_height < request.sealed_at_height {
                return Err(format!(
                    "liquidity intent {intent_id} expired before batch sealing"
                ));
            }
            selected.push(intent.clone());
        }

        let batch_nonce = self.counters.next_batch_nonce;
        let batch_id =
            liquidity_batch_id(batch_nonce, &request.intent_ids, request.sealed_at_height);
        let mut routes = Vec::with_capacity(selected.len());
        let mut route_ids = Vec::with_capacity(selected.len());
        let mut deltas = Vec::with_capacity(selected.len() * 2);
        let mut delta_ids = Vec::with_capacity(selected.len() * 2);
        let amm_before = merkle_root(
            "PRIVATE-L2-LIQUIDITY-BATCHER-BATCH-AMM-BEFORE",
            &selected
                .iter()
                .map(|intent| json!(intent.amm_pool_root))
                .collect::<Vec<_>>(),
        );
        let darkpool_before = merkle_root(
            "PRIVATE-L2-LIQUIDITY-BATCHER-BATCH-DARKPOOL-BEFORE",
            &selected
                .iter()
                .map(|intent| json!(intent.darkpool_root))
                .collect::<Vec<_>>(),
        );

        for (index, intent) in selected.iter().enumerate() {
            let route_nonce = self.counters.next_route_nonce + index as u64;
            let route = self.derive_route(route_nonce, intent, &request)?;
            route_ids.push(route.route_id.clone());
            routes.push(route);

            for direction in [DeltaDirection::Debit, DeltaDirection::Credit] {
                let delta = self.derive_delta(
                    &batch_id,
                    intent,
                    index as u64,
                    direction,
                    &request.netting_root,
                );
                delta_ids.push(delta.delta_id.clone());
                deltas.push(delta);
            }
        }

        let intent_root = merkle_root(
            "PRIVATE-L2-LIQUIDITY-BATCHER-BATCH-INTENT",
            &selected
                .iter()
                .map(SealedLiquidityIntent::public_record)
                .collect::<Vec<_>>(),
        );
        let route_root = merkle_root(
            "PRIVATE-L2-LIQUIDITY-BATCHER-BATCH-ROUTE",
            &routes
                .iter()
                .map(PrivateSwapRoute::public_record)
                .collect::<Vec<_>>(),
        );
        let delta_root = merkle_root(
            "PRIVATE-L2-LIQUIDITY-BATCHER-BATCH-DELTA",
            &deltas
                .iter()
                .map(LiquidityDelta::public_record)
                .collect::<Vec<_>>(),
        );

        let batch = LiquidityBatch {
            batch_id: batch_id.clone(),
            status: BatchStatus::SettlementReady,
            opened_at_height: request
                .sealed_at_height
                .saturating_sub(self.config.batch_window_blocks),
            sealed_at_height: request.sealed_at_height,
            settlement_deadline_height: request.sealed_at_height
                + self.config.settlement_ttl_blocks,
            intent_root,
            route_root,
            amm_pool_root_before: amm_before,
            amm_pool_root_after: request.amm_pool_root_after,
            darkpool_root_before: darkpool_before,
            darkpool_root_after: request.darkpool_root_after,
            netting_root: request.netting_root,
            sponsor_root: request.sponsor_root,
            pq_authorization_root: request.pq_authorization_root,
            privacy_proof_root: request.privacy_proof_root,
            settlement_delta_root: delta_root,
            low_fee_lane: self.config.low_fee_lane.clone(),
            total_fee_bps: request.total_fee_bps,
            netting_imbalance_bps: request.netting_imbalance_bps,
            privacy_set_size: request.privacy_set_size,
            intent_ids: request.intent_ids.clone(),
            route_ids: route_ids.clone(),
            settlement_delta_ids: delta_ids.clone(),
        };

        for intent_id in &request.intent_ids {
            if let Some(intent) = self.active_intents.get_mut(intent_id) {
                intent.status = IntentStatus::Netted;
            }
        }
        for route in routes {
            self.private_routes.insert(route.route_id.clone(), route);
        }
        for delta in deltas {
            self.settlement_deltas.insert(delta.delta_id.clone(), delta);
        }
        self.amm_pool_book_root = batch.amm_pool_root_after.clone();
        self.darkpool_book_root = batch.darkpool_root_after.clone();
        self.counters.next_route_nonce += selected.len() as u64;
        self.counters.next_batch_nonce += 1;
        self.counters.batches_built += 1;
        self.counters.settlement_deltas_ready += delta_ids.len() as u64;
        self.current_height = self.current_height.max(batch.sealed_at_height);
        self.batches.insert(batch_id, batch.clone());
        Ok(batch)
    }

    pub fn settle_batch(
        &mut self,
        request: SettlementRequest,
    ) -> PrivateL2LiquidityBatcherResult<BatchReceipt> {
        self.config.validate()?;
        request.validate()?;
        let state_root_before = self.state_root();
        let batch = self
            .batches
            .get(&request.batch_id)
            .cloned()
            .ok_or_else(|| format!("unknown liquidity batch id {}", request.batch_id))?;
        if !batch.status.can_settle() {
            return Err("liquidity batch is not settlement ready".to_string());
        }
        if request.settled_at_height > batch.settlement_deadline_height {
            return Err("liquidity batch settlement deadline elapsed".to_string());
        }
        if request.pq_authorization_root != batch.pq_authorization_root {
            return Err("liquidity batch pq authorization root mismatch".to_string());
        }
        if request.privacy_proof_root != batch.privacy_proof_root {
            return Err("liquidity batch privacy proof root mismatch".to_string());
        }

        for intent_id in &batch.intent_ids {
            if let Some(intent) = self.active_intents.get_mut(intent_id) {
                intent.status = IntentStatus::Settled;
                self.consumed_nullifier_roots
                    .insert(intent.nullifier_root.clone());
            }
        }
        if let Some(stored_batch) = self.batches.get_mut(&request.batch_id) {
            stored_batch.status = BatchStatus::Settled;
        }

        self.current_height = self.current_height.max(request.settled_at_height);
        self.counters.batches_settled += 1;
        let state_root_after = self.state_root();
        let receipt_id = batch_receipt_id(
            &request.batch_id,
            &batch.settlement_delta_root,
            &request.settlement_tx_root,
            request.settled_at_height,
        );
        let receipt = BatchReceipt {
            receipt_id: receipt_id.clone(),
            batch_id: request.batch_id,
            status: if request.finalized_at_height.is_some() {
                ReceiptStatus::Finalized
            } else {
                ReceiptStatus::Published
            },
            batch_root: batch.state_root(),
            settlement_delta_root: batch.settlement_delta_root,
            settlement_tx_root: request.settlement_tx_root,
            sponsor_settlement_root: request.sponsor_settlement_root,
            pq_authorization_root: request.pq_authorization_root,
            privacy_proof_root: request.privacy_proof_root,
            state_root_before,
            state_root_after,
            published_at_height: request.settled_at_height,
            finalized_at_height: request.finalized_at_height,
        };
        self.receipts.insert(receipt_id, receipt.clone());
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "current_height": self.current_height,
            "amm_pool_book_root": self.amm_pool_book_root,
            "darkpool_book_root": self.darkpool_book_root,
            "active_intent_root": self.active_intent_root(),
            "private_route_root": self.private_route_root(),
            "batch_root": self.batch_root(),
            "settlement_delta_root": self.settlement_delta_root(),
            "receipt_root": self.receipt_root(),
            "consumed_nullifier_root": self.consumed_nullifier_root(),
            "state_root": self.state_root_without_self_reference(),
        })
    }

    pub fn state_root(&self) -> String {
        self.state_root_without_self_reference()
    }

    pub fn active_intent_root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-LIQUIDITY-BATCHER-STATE-INTENT",
            &self
                .active_intents
                .values()
                .map(SealedLiquidityIntent::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn private_route_root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-LIQUIDITY-BATCHER-STATE-ROUTE",
            &self
                .private_routes
                .values()
                .map(PrivateSwapRoute::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn batch_root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-LIQUIDITY-BATCHER-STATE-BATCH",
            &self
                .batches
                .values()
                .map(LiquidityBatch::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn settlement_delta_root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-LIQUIDITY-BATCHER-STATE-DELTA",
            &self
                .settlement_deltas
                .values()
                .map(LiquidityDelta::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn receipt_root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-LIQUIDITY-BATCHER-STATE-RECEIPT",
            &self
                .receipts
                .values()
                .map(BatchReceipt::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn consumed_nullifier_root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-LIQUIDITY-BATCHER-STATE-CONSUMED-NULLIFIER",
            &self
                .consumed_nullifier_roots
                .iter()
                .map(|root| json!(root))
                .collect::<Vec<_>>(),
        )
    }

    fn state_root_without_self_reference(&self) -> String {
        domain_hash(
            "PRIVATE-L2-LIQUIDITY-BATCHER-STATE",
            &[
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Int(self.current_height as i128),
                HashPart::Str(&self.amm_pool_book_root),
                HashPart::Str(&self.darkpool_book_root),
                HashPart::Str(&self.active_intent_root()),
                HashPart::Str(&self.private_route_root()),
                HashPart::Str(&self.batch_root()),
                HashPart::Str(&self.settlement_delta_root()),
                HashPart::Str(&self.receipt_root()),
                HashPart::Str(&self.consumed_nullifier_root()),
            ],
            32,
        )
    }

    fn derive_route(
        &self,
        route_nonce: u64,
        intent: &SealedLiquidityIntent,
        request: &BuildBatchRequest,
    ) -> PrivateL2LiquidityBatcherResult<PrivateSwapRoute> {
        let hop = RouteHop {
            hop_index: 0,
            venue_kind: RouteVenueKind::InternalNetting,
            venue_commitment: domain_hash(
                "PRIVATE-L2-LIQUIDITY-BATCHER-NETTING-VENUE",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(&intent.intent_id),
                    HashPart::Str(&request.netting_root),
                ],
                32,
            ),
            pool_root_before: intent.amm_pool_root.clone(),
            pool_root_after: request.amm_pool_root_after.clone(),
            darkpool_root_before: intent.darkpool_root.clone(),
            darkpool_root_after: request.darkpool_root_after.clone(),
            fee_bps: request.total_fee_bps,
            witness_root: request.route_proof_root.clone(),
        };
        let hops = vec![hop];
        if hops.len() > self.config.max_route_hops {
            return Err("private liquidity route exceeds max hops".to_string());
        }
        let hop_records = hops.iter().map(RouteHop::public_record).collect::<Vec<_>>();
        let hop_root = merkle_root("PRIVATE-L2-LIQUIDITY-BATCHER-ROUTE-HOP", &hop_records);
        let route_commitment = private_route_commitment(route_nonce, intent, &hop_root, request);
        let route_root = domain_hash(
            "PRIVATE-L2-LIQUIDITY-BATCHER-ROUTE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&intent.intent_id),
                HashPart::Str(&route_commitment),
                HashPart::Str(&hop_root),
                HashPart::Str(&request.route_proof_root),
            ],
            32,
        );
        let route_id = private_route_id(route_nonce, &intent.intent_id, &route_root);
        Ok(PrivateSwapRoute {
            route_id,
            intent_id: intent.intent_id.clone(),
            route_commitment,
            route_root,
            hop_root,
            amm_pool_root_before: intent.amm_pool_root.clone(),
            amm_pool_root_after: request.amm_pool_root_after.clone(),
            darkpool_root_before: intent.darkpool_root.clone(),
            darkpool_root_after: request.darkpool_root_after.clone(),
            sponsor_root: request.sponsor_root.clone(),
            pq_authorization_root: request.pq_authorization_root.clone(),
            privacy_proof_root: request.privacy_proof_root.clone(),
            max_fee_bps: request.total_fee_bps,
            hops,
        })
    }

    fn derive_delta(
        &self,
        batch_id: &str,
        intent: &SealedLiquidityIntent,
        index: u64,
        direction: DeltaDirection,
        netting_root: &str,
    ) -> LiquidityDelta {
        let delta_id = liquidity_delta_id(batch_id, &intent.intent_id, index, direction);
        LiquidityDelta {
            delta_id,
            batch_id: batch_id.to_string(),
            asset_commitment: intent.asset_pair_root.clone(),
            venue_commitment: domain_hash(
                "PRIVATE-L2-LIQUIDITY-BATCHER-DELTA-VENUE",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(batch_id),
                    HashPart::Str(&intent.intent_id),
                    HashPart::Str(direction.as_str()),
                ],
                32,
            ),
            direction,
            amount_root: domain_hash(
                "PRIVATE-L2-LIQUIDITY-BATCHER-DELTA-AMOUNT",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(&intent.amount_band_root),
                    HashPart::Str(direction.as_str()),
                    HashPart::Str(netting_root),
                ],
                32,
            ),
            fee_root: domain_hash(
                "PRIVATE-L2-LIQUIDITY-BATCHER-DELTA-FEE",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(&intent.intent_id),
                    HashPart::Int(intent.fee_cap_bps as i128),
                    HashPart::Str(netting_root),
                ],
                32,
            ),
            sponsor_credit_root: intent.sponsor_root.clone(),
            settlement_account_root: intent.owner_commitment.clone(),
            proof_root: intent.privacy_proof_root.clone(),
        }
    }
}

fn asset_pair_root(
    asset_in_commitment: &str,
    asset_out_commitment: &str,
    kind: LiquidityIntentKind,
) -> String {
    domain_hash(
        "PRIVATE-L2-LIQUIDITY-BATCHER-ASSET-PAIR",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(asset_in_commitment),
            HashPart::Str(asset_out_commitment),
        ],
        32,
    )
}

fn sealed_payload_root(
    request: &LiquidityIntentRequest,
    asset_pair_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LIQUIDITY-BATCHER-SEALED-PAYLOAD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LIQUIDITY_BATCHER_SEALED_INTENT_SCHEME),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(request.intent_kind.as_str()),
            HashPart::Str(asset_pair_root),
            HashPart::Str(&request.amount_band_root),
            HashPart::Str(&request.limit_price_root),
            HashPart::Str(&request.amm_pool_root),
            HashPart::Str(&request.darkpool_root),
            HashPart::Str(&request.route_hint_root),
            HashPart::Str(&request.sponsor_root),
            HashPart::Str(&request.pq_authorization_root),
            HashPart::Str(&request.privacy_proof_root),
            HashPart::Str(&request.nullifier_root),
            HashPart::Int(request.opened_at_height as i128),
            HashPart::Int(request.expires_at_height as i128),
        ],
        32,
    )
}

fn liquidity_intent_id(
    nonce: u64,
    owner_commitment: &str,
    kind: LiquidityIntentKind,
    asset_pair_root: &str,
    sealed_payload_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-LIQUIDITY-BATCHER-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(owner_commitment),
            HashPart::Str(kind.as_str()),
            HashPart::Str(asset_pair_root),
            HashPart::Str(sealed_payload_root),
        ],
        32,
    )
}

fn private_route_commitment(
    route_nonce: u64,
    intent: &SealedLiquidityIntent,
    hop_root: &str,
    request: &BuildBatchRequest,
) -> String {
    domain_hash(
        "PRIVATE-L2-LIQUIDITY-BATCHER-PRIVATE-ROUTE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(route_nonce as i128),
            HashPart::Str(&intent.intent_id),
            HashPart::Str(&intent.route_hint_root),
            HashPart::Str(hop_root),
            HashPart::Str(&request.amm_pool_root_after),
            HashPart::Str(&request.darkpool_root_after),
            HashPart::Str(&request.privacy_proof_root),
        ],
        32,
    )
}

fn private_route_id(route_nonce: u64, intent_id: &str, route_root: &str) -> String {
    domain_hash(
        "PRIVATE-L2-LIQUIDITY-BATCHER-PRIVATE-ROUTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(route_nonce as i128),
            HashPart::Str(intent_id),
            HashPart::Str(route_root),
        ],
        32,
    )
}

fn liquidity_batch_id(batch_nonce: u64, intent_ids: &[String], sealed_at_height: u64) -> String {
    let intent_root = merkle_root(
        "PRIVATE-L2-LIQUIDITY-BATCHER-BATCH-ID-INTENT",
        &intent_ids.iter().map(|id| json!(id)).collect::<Vec<_>>(),
    );
    domain_hash(
        "PRIVATE-L2-LIQUIDITY-BATCHER-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(batch_nonce as i128),
            HashPart::Str(&intent_root),
            HashPart::Int(sealed_at_height as i128),
        ],
        32,
    )
}

fn liquidity_delta_id(
    batch_id: &str,
    intent_id: &str,
    index: u64,
    direction: DeltaDirection,
) -> String {
    domain_hash(
        "PRIVATE-L2-LIQUIDITY-BATCHER-DELTA-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(intent_id),
            HashPart::Int(index as i128),
            HashPart::Str(direction.as_str()),
        ],
        32,
    )
}

fn batch_receipt_id(
    batch_id: &str,
    settlement_delta_root: &str,
    settlement_tx_root: &str,
    settled_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LIQUIDITY-BATCHER-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(settlement_delta_root),
            HashPart::Str(settlement_tx_root),
            HashPart::Int(settled_at_height as i128),
        ],
        32,
    )
}

fn validate_identifier(value: &str, label: &str) -> PrivateL2LiquidityBatcherResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    if value.len() > 256 {
        return Err(format!("{label} is too long"));
    }
    Ok(())
}

fn validate_commitment(value: &str, label: &str) -> PrivateL2LiquidityBatcherResult<()> {
    validate_identifier(value, label)?;
    if value.len() < 16 {
        return Err(format!("{label} must be commitment-like"));
    }
    Ok(())
}

fn validate_root(value: &str, label: &str) -> PrivateL2LiquidityBatcherResult<()> {
    validate_identifier(value, label)?;
    if value.len() < 16 {
        return Err(format!("{label} must be root-like"));
    }
    Ok(())
}
