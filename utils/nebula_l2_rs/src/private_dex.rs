use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateDexResult<T> = Result<T, String>;

pub const PROTOCOL_VERSION: &str = PRIVATE_DEX_PROTOCOL_VERSION;
pub const PRIVATE_DEX_PROTOCOL_VERSION: &str = "nebula-private-dex-v1";
pub const PRIVATE_DEX_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_DEX_MAX_BPS: u64 = 10_000;
pub const PRIVATE_DEX_PRICE_SCALE: u64 = 1_000_000_000_000;
pub const PRIVATE_DEX_DEFAULT_AUCTION_WINDOW_BLOCKS: u64 = 4;
pub const PRIVATE_DEX_DEFAULT_REVEAL_DELAY_BLOCKS: u64 = 1;
pub const PRIVATE_DEX_DEFAULT_REVEAL_WINDOW_BLOCKS: u64 = 4;
pub const PRIVATE_DEX_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 8;
pub const PRIVATE_DEX_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 16;
pub const PRIVATE_DEX_DEFAULT_ROUTE_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_DEX_DEFAULT_INTENT_TTL_BLOCKS: u64 = 32;
pub const PRIVATE_DEX_DEFAULT_PRIVACY_EPOCH_BLOCKS: u64 = 720;
pub const PRIVATE_DEX_DEFAULT_PRIVACY_BUDGET_UNITS: u64 = 300_000;
pub const PRIVATE_DEX_DEFAULT_POOL_FEE_BPS: u64 = 18;
pub const PRIVATE_DEX_DEFAULT_PROTOCOL_FEE_SHARE_BPS: u64 = 1_250;
pub const PRIVATE_DEX_DEFAULT_MAX_PRICE_IMPACT_BPS: u64 = 900;
pub const PRIVATE_DEX_DEFAULT_MAX_ROUTE_HOPS: u64 = 4;
pub const PRIVATE_DEX_DEFAULT_MAX_BATCH_INTENTS: u64 = 512;
pub const PRIVATE_DEX_DEFAULT_MIN_SOLVER_BOND_UNITS: u64 = 25_000;
pub const PRIVATE_DEX_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 7_000;
pub const PRIVATE_DEX_DEFAULT_MAX_LOW_FEE_REBATE_UNITS: u64 = 250;
pub const PRIVATE_DEX_DEFAULT_MAX_ORACLE_STALENESS_BLOCKS: u64 = 12;
pub const PRIVATE_DEX_DEFAULT_MAX_ORACLE_DEVIATION_BPS: u64 = 650;
pub const PRIVATE_DEX_DEFAULT_TWAP_WINDOW_BLOCKS: u64 = 120;
pub const PRIVATE_DEX_DEFAULT_MIN_LIQUIDITY_UNITS: u64 = 1;
pub const PRIVATE_DEX_DEVNET_HEIGHT: u64 = 64;
pub const PRIVATE_DEX_DEVNET_WXMR_ASSET_ID: &str = "wxmr-devnet";
pub const PRIVATE_DEX_DEVNET_USDD_ASSET_ID: &str = "usdd-devnet";
pub const PRIVATE_DEX_DEVNET_DNR_ASSET_ID: &str = "dnr-devnet";
pub const PRIVATE_DEX_DEVNET_LP_WXMR_USDD: &str = "lp-wxmr-usdd-private-dex";
pub const PRIVATE_DEX_DEVNET_LP_WXMR_DNR: &str = "lp-wxmr-dnr-private-dex";
pub const PRIVATE_DEX_DEVNET_LP_DNR_USDD: &str = "lp-dnr-usdd-private-dex";
pub const PRIVATE_DEX_DEFAULT_FEE_ASSET_ID: &str = PRIVATE_DEX_DEVNET_WXMR_ASSET_ID;
pub const PRIVATE_DEX_DEFAULT_LOW_FEE_LANE: &str = "private_dex_low_fee";
pub const PRIVATE_DEX_DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const PRIVATE_DEX_COMMITMENT_SCHEME: &str = "shake256-domain-separated-commitments-v1";
pub const PRIVATE_DEX_ENCRYPTION_SCHEME: &str = "ml-kem-768+view-key-sealed-route-v1";
pub const PRIVATE_DEX_TRANSCRIPT_SCHEME: &str = "ml-dsa-65+slh-dsa-shake-128s+ml-kem-768+shake256";
pub const PRIVATE_DEX_INTENT_PROOF_SYSTEM: &str = "pq-private-dex-intent-membership-devnet";
pub const PRIVATE_DEX_BATCH_PROOF_SYSTEM: &str = "pq-private-dex-batch-clearing-devnet";
pub const PRIVATE_DEX_ROUTE_PROOF_SYSTEM: &str = "pq-private-dex-cfmm-route-devnet";
pub const PRIVATE_DEX_SETTLEMENT_PROOF_SYSTEM: &str = "pq-private-dex-settlement-devnet";
pub const PRIVATE_DEX_RESERVE_LINK_PROOF_SYSTEM: &str = "pq-monero-reserve-link-devnet";
pub const PRIVATE_DEX_STATUS_ACTIVE: &str = "active";
pub const PRIVATE_DEX_STATUS_PENDING: &str = "pending";
pub const PRIVATE_DEX_STATUS_COLLECTING: &str = "collecting";
pub const PRIVATE_DEX_STATUS_REVEALING: &str = "revealing";
pub const PRIVATE_DEX_STATUS_MATCHING: &str = "matching";
pub const PRIVATE_DEX_STATUS_SETTLED: &str = "settled";
pub const PRIVATE_DEX_STATUS_EXPIRED: &str = "expired";
pub const PRIVATE_DEX_STATUS_CANCELLED: &str = "cancelled";
pub const PRIVATE_DEX_STATUS_CONSUMED: &str = "consumed";
pub const PRIVATE_DEX_STATUS_RELEASED: &str = "released";
pub const PRIVATE_DEX_STATUS_VERIFIED: &str = "verified";
pub const PRIVATE_DEX_STATUS_REJECTED: &str = "rejected";
pub const PRIVATE_DEX_STATUS_PAUSED: &str = "paused";
pub const PRIVATE_DEX_STATUS_KILLED: &str = "killed";
pub const PRIVATE_DEX_STATUS_LOCKED: &str = "locked";
pub const PRIVATE_DEX_STATUS_OPEN: &str = "open";
pub const PRIVATE_DEX_STATUS_FILLED: &str = "filled";
pub const PRIVATE_DEX_STATUS_PARTIAL: &str = "partial";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateDexPoolKind {
    ConstantProduct,
    Stable,
    Hybrid,
}

impl PrivateDexPoolKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ConstantProduct => "constant_product",
            Self::Stable => "stable",
            Self::Hybrid => "hybrid",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateDexOrderSide {
    Buy,
    Sell,
}

impl PrivateDexOrderSide {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Buy => "buy",
            Self::Sell => "sell",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateDexOrderKind {
    ExactInput,
    ExactOutput,
    Limit,
    Market,
    Range,
}

impl PrivateDexOrderKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ExactInput => "exact_input",
            Self::ExactOutput => "exact_output",
            Self::Limit => "limit",
            Self::Market => "market",
            Self::Range => "range",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateDexVisibility {
    Public,
    Sealed,
    Private,
    AggregateOnly,
}

impl PrivateDexVisibility {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Sealed => "sealed",
            Self::Private => "private",
            Self::AggregateOnly => "aggregate_only",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateDexAuctionPhase {
    Collecting,
    Revealing,
    Matching,
    Challenge,
    Settled,
    Expired,
}

impl PrivateDexAuctionPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Revealing => "revealing",
            Self::Matching => "matching",
            Self::Challenge => "challenge",
            Self::Settled => "settled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateDexSolverKind {
    InternalCfmm,
    ExternalSolver,
    BatchAuction,
    HybridRouter,
}

impl PrivateDexSolverKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InternalCfmm => "internal_cfmm",
            Self::ExternalSolver => "external_solver",
            Self::BatchAuction => "batch_auction",
            Self::HybridRouter => "hybrid_router",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateDexCircuitFamily {
    IntentMembership,
    BatchClearing,
    CfmmRoute,
    Settlement,
    MoneroReserveLink,
    RiskGuard,
    LowFeeEligibility,
}

impl PrivateDexCircuitFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::IntentMembership => "intent_membership",
            Self::BatchClearing => "batch_clearing",
            Self::CfmmRoute => "cfmm_route",
            Self::Settlement => "settlement",
            Self::MoneroReserveLink => "monero_reserve_link",
            Self::RiskGuard => "risk_guard",
            Self::LowFeeEligibility => "low_fee_eligibility",
        }
    }

    pub fn default_proof_system(&self) -> &'static str {
        match self {
            Self::IntentMembership => PRIVATE_DEX_INTENT_PROOF_SYSTEM,
            Self::BatchClearing => PRIVATE_DEX_BATCH_PROOF_SYSTEM,
            Self::CfmmRoute => PRIVATE_DEX_ROUTE_PROOF_SYSTEM,
            Self::Settlement => PRIVATE_DEX_SETTLEMENT_PROOF_SYSTEM,
            Self::MoneroReserveLink => PRIVATE_DEX_RESERVE_LINK_PROOF_SYSTEM,
            Self::RiskGuard => "pq-private-dex-risk-guard-devnet",
            Self::LowFeeEligibility => "pq-private-dex-low-fee-eligibility-devnet",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateDexTranscriptPurpose {
    IntentAuthorization,
    SolverQuote,
    BatchClearing,
    RouteExecution,
    SettlementFinality,
    MoneroAnchor,
}

impl PrivateDexTranscriptPurpose {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::IntentAuthorization => "intent_authorization",
            Self::SolverQuote => "solver_quote",
            Self::BatchClearing => "batch_clearing",
            Self::RouteExecution => "route_execution",
            Self::SettlementFinality => "settlement_finality",
            Self::MoneroAnchor => "monero_anchor",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateDexRiskMode {
    Normal,
    Watch,
    ReduceOnly,
    Paused,
    Killed,
}

impl PrivateDexRiskMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Watch => "watch",
            Self::ReduceOnly => "reduce_only",
            Self::Paused => "paused",
            Self::Killed => "killed",
        }
    }

    pub fn blocks_new_orders(&self) -> bool {
        matches!(self, Self::Paused | Self::Killed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateDexSwitchScope {
    Global,
    Pair,
    Pool,
    Auction,
    Router,
    Circuit,
    LowFeeLane,
}

impl PrivateDexSwitchScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Pair => "pair",
            Self::Pool => "pool",
            Self::Auction => "auction",
            Self::Router => "router",
            Self::Circuit => "circuit",
            Self::LowFeeLane => "low_fee_lane",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexConfig {
    pub protocol_version: String,
    pub schema_version: u64,
    pub default_monero_network: String,
    pub fee_asset_id: String,
    pub default_low_fee_lane: String,
    pub default_auction_window_blocks: u64,
    pub default_reveal_delay_blocks: u64,
    pub default_reveal_window_blocks: u64,
    pub default_challenge_window_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub route_ttl_blocks: u64,
    pub intent_ttl_blocks: u64,
    pub privacy_epoch_blocks: u64,
    pub privacy_budget_units: u64,
    pub max_batch_intents: u64,
    pub max_route_hops: u64,
    pub default_pool_fee_bps: u64,
    pub protocol_fee_share_bps: u64,
    pub max_price_impact_bps: u64,
    pub max_oracle_staleness_blocks: u64,
    pub max_oracle_deviation_bps: u64,
    pub default_twap_window_blocks: u64,
    pub min_liquidity_units: u64,
    pub min_solver_bond_units: u64,
    pub low_fee_rebate_bps: u64,
    pub max_low_fee_rebate_units: u64,
    pub commitment_scheme: String,
    pub encryption_scheme: String,
    pub transcript_scheme: String,
    pub intent_proof_system: String,
    pub batch_proof_system: String,
    pub route_proof_system: String,
    pub settlement_proof_system: String,
    pub reserve_link_proof_system: String,
    pub metadata_root: String,
}

impl Default for PrivateDexConfig {
    fn default() -> Self {
        Self {
            protocol_version: PRIVATE_DEX_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_DEX_SCHEMA_VERSION,
            default_monero_network: PRIVATE_DEX_DEFAULT_MONERO_NETWORK.to_string(),
            fee_asset_id: PRIVATE_DEX_DEFAULT_FEE_ASSET_ID.to_string(),
            default_low_fee_lane: PRIVATE_DEX_DEFAULT_LOW_FEE_LANE.to_string(),
            default_auction_window_blocks: PRIVATE_DEX_DEFAULT_AUCTION_WINDOW_BLOCKS,
            default_reveal_delay_blocks: PRIVATE_DEX_DEFAULT_REVEAL_DELAY_BLOCKS,
            default_reveal_window_blocks: PRIVATE_DEX_DEFAULT_REVEAL_WINDOW_BLOCKS,
            default_challenge_window_blocks: PRIVATE_DEX_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            settlement_ttl_blocks: PRIVATE_DEX_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            route_ttl_blocks: PRIVATE_DEX_DEFAULT_ROUTE_TTL_BLOCKS,
            intent_ttl_blocks: PRIVATE_DEX_DEFAULT_INTENT_TTL_BLOCKS,
            privacy_epoch_blocks: PRIVATE_DEX_DEFAULT_PRIVACY_EPOCH_BLOCKS,
            privacy_budget_units: PRIVATE_DEX_DEFAULT_PRIVACY_BUDGET_UNITS,
            max_batch_intents: PRIVATE_DEX_DEFAULT_MAX_BATCH_INTENTS,
            max_route_hops: PRIVATE_DEX_DEFAULT_MAX_ROUTE_HOPS,
            default_pool_fee_bps: PRIVATE_DEX_DEFAULT_POOL_FEE_BPS,
            protocol_fee_share_bps: PRIVATE_DEX_DEFAULT_PROTOCOL_FEE_SHARE_BPS,
            max_price_impact_bps: PRIVATE_DEX_DEFAULT_MAX_PRICE_IMPACT_BPS,
            max_oracle_staleness_blocks: PRIVATE_DEX_DEFAULT_MAX_ORACLE_STALENESS_BLOCKS,
            max_oracle_deviation_bps: PRIVATE_DEX_DEFAULT_MAX_ORACLE_DEVIATION_BPS,
            default_twap_window_blocks: PRIVATE_DEX_DEFAULT_TWAP_WINDOW_BLOCKS,
            min_liquidity_units: PRIVATE_DEX_DEFAULT_MIN_LIQUIDITY_UNITS,
            min_solver_bond_units: PRIVATE_DEX_DEFAULT_MIN_SOLVER_BOND_UNITS,
            low_fee_rebate_bps: PRIVATE_DEX_DEFAULT_LOW_FEE_REBATE_BPS,
            max_low_fee_rebate_units: PRIVATE_DEX_DEFAULT_MAX_LOW_FEE_REBATE_UNITS,
            commitment_scheme: PRIVATE_DEX_COMMITMENT_SCHEME.to_string(),
            encryption_scheme: PRIVATE_DEX_ENCRYPTION_SCHEME.to_string(),
            transcript_scheme: PRIVATE_DEX_TRANSCRIPT_SCHEME.to_string(),
            intent_proof_system: PRIVATE_DEX_INTENT_PROOF_SYSTEM.to_string(),
            batch_proof_system: PRIVATE_DEX_BATCH_PROOF_SYSTEM.to_string(),
            route_proof_system: PRIVATE_DEX_ROUTE_PROOF_SYSTEM.to_string(),
            settlement_proof_system: PRIVATE_DEX_SETTLEMENT_PROOF_SYSTEM.to_string(),
            reserve_link_proof_system: PRIVATE_DEX_RESERVE_LINK_PROOF_SYSTEM.to_string(),
            metadata_root: private_dex_payload_root(
                "PRIVATE-DEX-CONFIG-METADATA",
                &json!({
                    "mode": "default",
                    "privacy": "commitments-only public surface",
                    "quantum_resistance": PRIVATE_DEX_TRANSCRIPT_SCHEME,
                }),
            ),
        }
    }
}

impl PrivateDexConfig {
    pub fn validate(&self) -> PrivateDexResult<()> {
        ensure_non_empty(&self.protocol_version, "private DEX protocol version")?;
        ensure_non_empty(&self.default_monero_network, "private DEX monero network")?;
        ensure_non_empty(&self.fee_asset_id, "private DEX fee asset id")?;
        ensure_non_empty(&self.default_low_fee_lane, "private DEX low fee lane")?;
        ensure_non_empty(&self.commitment_scheme, "private DEX commitment scheme")?;
        ensure_non_empty(&self.encryption_scheme, "private DEX encryption scheme")?;
        ensure_non_empty(&self.transcript_scheme, "private DEX transcript scheme")?;
        ensure_non_empty(&self.metadata_root, "private DEX metadata root")?;
        validate_bps("default_pool_fee_bps", self.default_pool_fee_bps)?;
        validate_bps("protocol_fee_share_bps", self.protocol_fee_share_bps)?;
        validate_bps("max_price_impact_bps", self.max_price_impact_bps)?;
        validate_bps("max_oracle_deviation_bps", self.max_oracle_deviation_bps)?;
        validate_bps("low_fee_rebate_bps", self.low_fee_rebate_bps)?;
        if self.schema_version != PRIVATE_DEX_SCHEMA_VERSION {
            return Err("private DEX config schema version mismatch".to_string());
        }
        if self.default_auction_window_blocks == 0
            || self.default_reveal_window_blocks == 0
            || self.default_challenge_window_blocks == 0
        {
            return Err("private DEX auction windows must be positive".to_string());
        }
        if self.settlement_ttl_blocks == 0
            || self.route_ttl_blocks == 0
            || self.intent_ttl_blocks == 0
        {
            return Err("private DEX TTL values must be positive".to_string());
        }
        if self.max_batch_intents == 0 || self.max_route_hops == 0 {
            return Err("private DEX batch and route limits must be positive".to_string());
        }
        if self.min_liquidity_units == 0 {
            return Err("private DEX minimum liquidity must be positive".to_string());
        }
        if !self.transcript_scheme.contains("ml-dsa")
            || !self.transcript_scheme.contains("slh-dsa")
            || !self.transcript_scheme.contains("shake256")
        {
            return Err(
                "private DEX transcript scheme must commit to ML-DSA, SLH-DSA, and SHAKE"
                    .to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "default_monero_network": self.default_monero_network,
            "fee_asset_id": self.fee_asset_id,
            "default_low_fee_lane": self.default_low_fee_lane,
            "default_auction_window_blocks": self.default_auction_window_blocks,
            "default_reveal_delay_blocks": self.default_reveal_delay_blocks,
            "default_reveal_window_blocks": self.default_reveal_window_blocks,
            "default_challenge_window_blocks": self.default_challenge_window_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "route_ttl_blocks": self.route_ttl_blocks,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "privacy_epoch_blocks": self.privacy_epoch_blocks,
            "privacy_budget_units": self.privacy_budget_units,
            "max_batch_intents": self.max_batch_intents,
            "max_route_hops": self.max_route_hops,
            "default_pool_fee_bps": self.default_pool_fee_bps,
            "protocol_fee_share_bps": self.protocol_fee_share_bps,
            "max_price_impact_bps": self.max_price_impact_bps,
            "max_oracle_staleness_blocks": self.max_oracle_staleness_blocks,
            "max_oracle_deviation_bps": self.max_oracle_deviation_bps,
            "default_twap_window_blocks": self.default_twap_window_blocks,
            "min_liquidity_units": self.min_liquidity_units,
            "min_solver_bond_units": self.min_solver_bond_units,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "max_low_fee_rebate_units": self.max_low_fee_rebate_units,
            "commitment_scheme": self.commitment_scheme,
            "encryption_scheme": self.encryption_scheme,
            "transcript_scheme": self.transcript_scheme,
            "intent_proof_system": self.intent_proof_system,
            "batch_proof_system": self.batch_proof_system,
            "route_proof_system": self.route_proof_system,
            "settlement_proof_system": self.settlement_proof_system,
            "reserve_link_proof_system": self.reserve_link_proof_system,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn config_root(&self) -> String {
        private_dex_payload_root("PRIVATE-DEX-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexAssetPair {
    pub pair_id: String,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub base_asset_commitment: String,
    pub quote_asset_commitment: String,
    pub tick_size_units: u64,
    pub lot_size_units: u64,
    pub min_order_units: u64,
    pub max_order_units: u64,
    pub price_scale: u64,
    pub monero_anchor_asset: bool,
    pub metadata_root: String,
    pub status: String,
}

impl PrivateDexAssetPair {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        base_asset_id: impl Into<String>,
        quote_asset_id: impl Into<String>,
        tick_size_units: u64,
        lot_size_units: u64,
        min_order_units: u64,
        max_order_units: u64,
        monero_anchor_asset: bool,
        metadata: &Value,
    ) -> PrivateDexResult<Self> {
        let base_asset_id = base_asset_id.into();
        let quote_asset_id = quote_asset_id.into();
        ensure_non_empty(&base_asset_id, "private DEX pair base asset")?;
        ensure_non_empty(&quote_asset_id, "private DEX pair quote asset")?;
        if base_asset_id == quote_asset_id {
            return Err("private DEX pair assets must differ".to_string());
        }
        if tick_size_units == 0 || lot_size_units == 0 || min_order_units == 0 {
            return Err(
                "private DEX pair tick, lot, and minimum order sizes must be positive".to_string(),
            );
        }
        if max_order_units < min_order_units {
            return Err("private DEX pair max order must be at least min order".to_string());
        }
        let base_asset_commitment = private_dex_asset_commitment(&base_asset_id);
        let quote_asset_commitment = private_dex_asset_commitment(&quote_asset_id);
        let metadata_root = private_dex_payload_root("PRIVATE-DEX-PAIR-METADATA", metadata);
        let pair_id = private_dex_pair_id(
            &base_asset_id,
            &quote_asset_id,
            tick_size_units,
            lot_size_units,
            &metadata_root,
        );
        let pair = Self {
            pair_id,
            base_asset_id,
            quote_asset_id,
            base_asset_commitment,
            quote_asset_commitment,
            tick_size_units,
            lot_size_units,
            min_order_units,
            max_order_units,
            price_scale: PRIVATE_DEX_PRICE_SCALE,
            monero_anchor_asset,
            metadata_root,
            status: PRIVATE_DEX_STATUS_ACTIVE.to_string(),
        };
        pair.validate()?;
        Ok(pair)
    }

    pub fn validate(&self) -> PrivateDexResult<String> {
        ensure_non_empty(&self.pair_id, "private DEX pair id")?;
        ensure_non_empty(&self.base_asset_id, "private DEX pair base asset")?;
        ensure_non_empty(&self.quote_asset_id, "private DEX pair quote asset")?;
        ensure_non_empty(
            &self.base_asset_commitment,
            "private DEX pair base commitment",
        )?;
        ensure_non_empty(
            &self.quote_asset_commitment,
            "private DEX pair quote commitment",
        )?;
        ensure_non_empty(&self.metadata_root, "private DEX pair metadata root")?;
        ensure_status(
            &self.status,
            &[
                PRIVATE_DEX_STATUS_ACTIVE,
                PRIVATE_DEX_STATUS_PAUSED,
                PRIVATE_DEX_STATUS_KILLED,
            ],
        )?;
        if self.base_asset_id == self.quote_asset_id {
            return Err("private DEX pair assets must differ".to_string());
        }
        if self.tick_size_units == 0 || self.lot_size_units == 0 || self.min_order_units == 0 {
            return Err("private DEX pair sizing must be positive".to_string());
        }
        if self.max_order_units < self.min_order_units {
            return Err("private DEX pair max order must be at least min order".to_string());
        }
        let expected_id = private_dex_pair_id(
            &self.base_asset_id,
            &self.quote_asset_id,
            self.tick_size_units,
            self.lot_size_units,
            &self.metadata_root,
        );
        if self.pair_id != expected_id {
            return Err("private DEX pair id mismatch".to_string());
        }
        Ok(self.pair_id.clone())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_asset_pair",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "pair_id": self.pair_id,
            "base_asset_commitment": self.base_asset_commitment,
            "quote_asset_commitment": self.quote_asset_commitment,
            "tick_size_units": self.tick_size_units,
            "lot_size_units": self.lot_size_units,
            "min_order_units": self.min_order_units,
            "max_order_units": self.max_order_units,
            "price_scale": self.price_scale,
            "monero_anchor_asset": self.monero_anchor_asset,
            "metadata_root": self.metadata_root,
            "status": self.status,
        })
    }

    pub fn pair_root(&self) -> String {
        private_dex_payload_root("PRIVATE-DEX-ASSET-PAIR-ROOT", &self.public_record())
    }

    pub fn contains_asset(&self, asset_id: &str) -> bool {
        self.base_asset_id == asset_id || self.quote_asset_id == asset_id
    }

    pub fn other_asset(&self, asset_id: &str) -> PrivateDexResult<String> {
        if self.base_asset_id == asset_id {
            Ok(self.quote_asset_id.clone())
        } else if self.quote_asset_id == asset_id {
            Ok(self.base_asset_id.clone())
        } else {
            Err("asset is not part of private DEX pair".to_string())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexCfmmPoolConfig {
    pub pool_id: String,
    pub pair_id: String,
    pub pool_kind: PrivateDexPoolKind,
    pub asset_x_id: String,
    pub asset_y_id: String,
    pub asset_x_commitment: String,
    pub asset_y_commitment: String,
    pub lp_asset_id: String,
    pub fee_bps: u64,
    pub protocol_fee_share_bps: u64,
    pub amplification_bps: u64,
    pub max_price_impact_bps: u64,
    pub low_fee_lane_id: String,
    pub risk_profile_id: String,
    pub circuit_profile_id: String,
    pub metadata_root: String,
    pub status: String,
}

impl PrivateDexCfmmPoolConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pair_id: impl Into<String>,
        pool_kind: PrivateDexPoolKind,
        asset_x_id: impl Into<String>,
        asset_y_id: impl Into<String>,
        lp_asset_id: impl Into<String>,
        fee_bps: u64,
        protocol_fee_share_bps: u64,
        amplification_bps: u64,
        max_price_impact_bps: u64,
        low_fee_lane_id: impl Into<String>,
        risk_profile_id: impl Into<String>,
        circuit_profile_id: impl Into<String>,
        metadata: &Value,
    ) -> PrivateDexResult<Self> {
        let pair_id = pair_id.into();
        let asset_x_id = asset_x_id.into();
        let asset_y_id = asset_y_id.into();
        let lp_asset_id = lp_asset_id.into();
        let low_fee_lane_id = low_fee_lane_id.into();
        let risk_profile_id = risk_profile_id.into();
        let circuit_profile_id = circuit_profile_id.into();
        ensure_non_empty(&pair_id, "private DEX pool pair id")?;
        ensure_non_empty(&asset_x_id, "private DEX pool asset x")?;
        ensure_non_empty(&asset_y_id, "private DEX pool asset y")?;
        ensure_non_empty(&lp_asset_id, "private DEX pool LP asset")?;
        ensure_non_empty(&low_fee_lane_id, "private DEX pool low fee lane")?;
        ensure_non_empty(&risk_profile_id, "private DEX pool risk profile")?;
        ensure_non_empty(&circuit_profile_id, "private DEX pool circuit profile")?;
        if asset_x_id == asset_y_id {
            return Err("private DEX pool assets must differ".to_string());
        }
        validate_bps("pool fee_bps", fee_bps)?;
        validate_bps("pool protocol_fee_share_bps", protocol_fee_share_bps)?;
        validate_bps("pool amplification_bps", amplification_bps)?;
        validate_bps("pool max_price_impact_bps", max_price_impact_bps)?;
        let metadata_root = private_dex_payload_root("PRIVATE-DEX-CFMM-POOL-METADATA", metadata);
        let pool_id = private_dex_pool_id(
            &pair_id,
            pool_kind,
            &asset_x_id,
            &asset_y_id,
            &lp_asset_id,
            fee_bps,
            amplification_bps,
            &metadata_root,
        );
        let pool = Self {
            pool_id,
            pair_id,
            pool_kind,
            asset_x_id: asset_x_id.clone(),
            asset_y_id: asset_y_id.clone(),
            asset_x_commitment: private_dex_asset_commitment(&asset_x_id),
            asset_y_commitment: private_dex_asset_commitment(&asset_y_id),
            lp_asset_id,
            fee_bps,
            protocol_fee_share_bps,
            amplification_bps,
            max_price_impact_bps,
            low_fee_lane_id,
            risk_profile_id,
            circuit_profile_id,
            metadata_root,
            status: PRIVATE_DEX_STATUS_ACTIVE.to_string(),
        };
        pool.validate()?;
        Ok(pool)
    }

    pub fn validate(&self) -> PrivateDexResult<String> {
        ensure_non_empty(&self.pool_id, "private DEX pool id")?;
        ensure_non_empty(&self.pair_id, "private DEX pool pair id")?;
        ensure_non_empty(&self.asset_x_id, "private DEX pool asset x")?;
        ensure_non_empty(&self.asset_y_id, "private DEX pool asset y")?;
        ensure_non_empty(&self.lp_asset_id, "private DEX pool LP asset")?;
        ensure_non_empty(&self.low_fee_lane_id, "private DEX pool low fee lane")?;
        ensure_non_empty(&self.risk_profile_id, "private DEX pool risk profile")?;
        ensure_non_empty(&self.circuit_profile_id, "private DEX pool circuit profile")?;
        ensure_non_empty(&self.metadata_root, "private DEX pool metadata root")?;
        validate_bps("pool fee_bps", self.fee_bps)?;
        validate_bps("pool protocol_fee_share_bps", self.protocol_fee_share_bps)?;
        validate_bps("pool amplification_bps", self.amplification_bps)?;
        validate_bps("pool max_price_impact_bps", self.max_price_impact_bps)?;
        ensure_status(
            &self.status,
            &[
                PRIVATE_DEX_STATUS_ACTIVE,
                PRIVATE_DEX_STATUS_PAUSED,
                PRIVATE_DEX_STATUS_KILLED,
            ],
        )?;
        if self.asset_x_id == self.asset_y_id {
            return Err("private DEX pool assets must differ".to_string());
        }
        let expected_id = private_dex_pool_id(
            &self.pair_id,
            self.pool_kind,
            &self.asset_x_id,
            &self.asset_y_id,
            &self.lp_asset_id,
            self.fee_bps,
            self.amplification_bps,
            &self.metadata_root,
        );
        if self.pool_id != expected_id {
            return Err("private DEX pool id mismatch".to_string());
        }
        Ok(self.pool_id.clone())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_cfmm_pool_config",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "pool_id": self.pool_id,
            "pair_id": self.pair_id,
            "pool_kind": self.pool_kind.as_str(),
            "asset_x_commitment": self.asset_x_commitment,
            "asset_y_commitment": self.asset_y_commitment,
            "lp_asset_id": self.lp_asset_id,
            "fee_bps": self.fee_bps,
            "protocol_fee_share_bps": self.protocol_fee_share_bps,
            "amplification_bps": self.amplification_bps,
            "max_price_impact_bps": self.max_price_impact_bps,
            "low_fee_lane_id": self.low_fee_lane_id,
            "risk_profile_id": self.risk_profile_id,
            "circuit_profile_id": self.circuit_profile_id,
            "metadata_root": self.metadata_root,
            "status": self.status,
        })
    }

    pub fn config_root(&self) -> String {
        private_dex_payload_root("PRIVATE-DEX-CFMM-POOL-CONFIG-ROOT", &self.public_record())
    }

    pub fn contains_asset(&self, asset_id: &str) -> bool {
        self.asset_x_id == asset_id || self.asset_y_id == asset_id
    }

    pub fn other_asset(&self, asset_id: &str) -> PrivateDexResult<String> {
        if self.asset_x_id == asset_id {
            Ok(self.asset_y_id.clone())
        } else if self.asset_y_id == asset_id {
            Ok(self.asset_x_id.clone())
        } else {
            Err("asset is not in private DEX pool".to_string())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexCfmmPoolState {
    pub pool_id: String,
    pub reserve_x: u64,
    pub reserve_y: u64,
    pub virtual_reserve_x: u64,
    pub virtual_reserve_y: u64,
    pub total_liquidity: u64,
    pub fee_growth_x: u64,
    pub fee_growth_y: u64,
    pub protocol_fee_x: u64,
    pub protocol_fee_y: u64,
    pub cumulative_volume_x: u64,
    pub cumulative_volume_y: u64,
    pub oracle_price_x_to_y_scaled: u64,
    pub twap_price_x_to_y_scaled: u64,
    pub invariant_root: String,
    pub last_update_height: u64,
    pub status: String,
}

impl PrivateDexCfmmPoolState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: &PrivateDexCfmmPoolConfig,
        reserve_x: u64,
        reserve_y: u64,
        virtual_reserve_x: u64,
        virtual_reserve_y: u64,
        total_liquidity: u64,
        oracle_price_x_to_y_scaled: u64,
        twap_price_x_to_y_scaled: u64,
        last_update_height: u64,
    ) -> PrivateDexResult<Self> {
        if reserve_x == 0 || reserve_y == 0 {
            return Err("private DEX pool reserves must be positive".to_string());
        }
        if total_liquidity == 0 {
            return Err("private DEX pool liquidity must be positive".to_string());
        }
        let invariant_root = private_dex_pool_invariant_root(
            &config.pool_id,
            reserve_x,
            reserve_y,
            virtual_reserve_x,
            virtual_reserve_y,
            total_liquidity,
        );
        let pool = Self {
            pool_id: config.pool_id.clone(),
            reserve_x,
            reserve_y,
            virtual_reserve_x,
            virtual_reserve_y,
            total_liquidity,
            fee_growth_x: 0,
            fee_growth_y: 0,
            protocol_fee_x: 0,
            protocol_fee_y: 0,
            cumulative_volume_x: 0,
            cumulative_volume_y: 0,
            oracle_price_x_to_y_scaled,
            twap_price_x_to_y_scaled,
            invariant_root,
            last_update_height,
            status: PRIVATE_DEX_STATUS_ACTIVE.to_string(),
        };
        pool.validate()?;
        Ok(pool)
    }

    pub fn validate(&self) -> PrivateDexResult<String> {
        ensure_non_empty(&self.pool_id, "private DEX pool state id")?;
        ensure_non_empty(&self.invariant_root, "private DEX pool invariant root")?;
        ensure_status(
            &self.status,
            &[
                PRIVATE_DEX_STATUS_ACTIVE,
                PRIVATE_DEX_STATUS_PAUSED,
                PRIVATE_DEX_STATUS_KILLED,
            ],
        )?;
        if self.reserve_x == 0 || self.reserve_y == 0 {
            return Err("private DEX pool reserves must be positive".to_string());
        }
        if self.total_liquidity == 0 {
            return Err("private DEX pool liquidity must be positive".to_string());
        }
        Ok(self.pool_id.clone())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_cfmm_pool_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "pool_id": self.pool_id,
            "reserve_x": self.reserve_x,
            "reserve_y": self.reserve_y,
            "virtual_reserve_x": self.virtual_reserve_x,
            "virtual_reserve_y": self.virtual_reserve_y,
            "total_liquidity": self.total_liquidity,
            "fee_growth_x": self.fee_growth_x,
            "fee_growth_y": self.fee_growth_y,
            "protocol_fee_x": self.protocol_fee_x,
            "protocol_fee_y": self.protocol_fee_y,
            "cumulative_volume_x": self.cumulative_volume_x,
            "cumulative_volume_y": self.cumulative_volume_y,
            "oracle_price_x_to_y_scaled": self.oracle_price_x_to_y_scaled,
            "twap_price_x_to_y_scaled": self.twap_price_x_to_y_scaled,
            "invariant_root": self.invariant_root,
            "last_update_height": self.last_update_height,
            "status": self.status,
        })
    }

    pub fn pool_root(&self) -> String {
        private_dex_pool_state_root(self)
    }

    pub fn refresh_invariant(&mut self) {
        self.invariant_root = private_dex_pool_invariant_root(
            &self.pool_id,
            self.reserve_x,
            self.reserve_y,
            self.virtual_reserve_x,
            self.virtual_reserve_y,
            self.total_liquidity,
        );
    }

    pub fn reserves_for_asset(
        &self,
        config: &PrivateDexCfmmPoolConfig,
        asset_in_id: &str,
    ) -> PrivateDexResult<(u64, u64, String)> {
        if config.asset_x_id == asset_in_id {
            Ok((self.reserve_x, self.reserve_y, config.asset_y_id.clone()))
        } else if config.asset_y_id == asset_in_id {
            Ok((self.reserve_y, self.reserve_x, config.asset_x_id.clone()))
        } else {
            Err("private DEX pool quote asset mismatch".to_string())
        }
    }

    pub fn virtual_reserves_for_asset(
        &self,
        config: &PrivateDexCfmmPoolConfig,
        asset_in_id: &str,
    ) -> PrivateDexResult<(u64, u64)> {
        if config.asset_x_id == asset_in_id {
            Ok((
                self.reserve_x.saturating_add(self.virtual_reserve_x),
                self.reserve_y.saturating_add(self.virtual_reserve_y),
            ))
        } else if config.asset_y_id == asset_in_id {
            Ok((
                self.reserve_y.saturating_add(self.virtual_reserve_y),
                self.reserve_x.saturating_add(self.virtual_reserve_x),
            ))
        } else {
            Err("private DEX virtual reserve asset mismatch".to_string())
        }
    }

    pub fn mark_updated(&mut self, height: u64) {
        self.last_update_height = height;
        self.refresh_invariant();
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexLiquidityPosition {
    pub position_id: String,
    pub owner_commitment: String,
    pub pool_id: String,
    pub liquidity_units: u64,
    pub asset_x_commitment: String,
    pub asset_y_commitment: String,
    pub amount_x_bucket: u64,
    pub amount_y_bucket: u64,
    pub lower_price_bucket: u64,
    pub upper_price_bucket: u64,
    pub unlock_height: u64,
    pub nonce: u64,
    pub metadata_root: String,
    pub status: String,
}

impl PrivateDexLiquidityPosition {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_label: &str,
        pool_id: &str,
        asset_x_id: &str,
        asset_y_id: &str,
        liquidity_units: u64,
        amount_x_units: u64,
        amount_y_units: u64,
        lower_price_bucket: u64,
        upper_price_bucket: u64,
        unlock_height: u64,
        nonce: u64,
        metadata: &Value,
    ) -> PrivateDexResult<Self> {
        ensure_non_empty(owner_label, "private DEX LP owner")?;
        ensure_non_empty(pool_id, "private DEX LP pool")?;
        ensure_non_empty(asset_x_id, "private DEX LP asset x")?;
        ensure_non_empty(asset_y_id, "private DEX LP asset y")?;
        if liquidity_units == 0 {
            return Err("private DEX LP liquidity must be positive".to_string());
        }
        if lower_price_bucket > upper_price_bucket {
            return Err("private DEX LP price bucket range is invalid".to_string());
        }
        let owner_commitment = private_dex_account_commitment(owner_label);
        let asset_x_commitment = private_dex_asset_commitment(asset_x_id);
        let asset_y_commitment = private_dex_asset_commitment(asset_y_id);
        let amount_x_bucket = private_dex_amount_bucket(amount_x_units);
        let amount_y_bucket = private_dex_amount_bucket(amount_y_units);
        let metadata_root = private_dex_payload_root("PRIVATE-DEX-LP-METADATA", metadata);
        let position_id = private_dex_liquidity_position_id(
            &owner_commitment,
            pool_id,
            liquidity_units,
            lower_price_bucket,
            upper_price_bucket,
            nonce,
        );
        let position = Self {
            position_id,
            owner_commitment,
            pool_id: pool_id.to_string(),
            liquidity_units,
            asset_x_commitment,
            asset_y_commitment,
            amount_x_bucket,
            amount_y_bucket,
            lower_price_bucket,
            upper_price_bucket,
            unlock_height,
            nonce,
            metadata_root,
            status: PRIVATE_DEX_STATUS_ACTIVE.to_string(),
        };
        position.validate()?;
        Ok(position)
    }

    pub fn validate(&self) -> PrivateDexResult<String> {
        ensure_non_empty(&self.position_id, "private DEX LP position id")?;
        ensure_non_empty(&self.owner_commitment, "private DEX LP owner commitment")?;
        ensure_non_empty(&self.pool_id, "private DEX LP pool id")?;
        ensure_non_empty(
            &self.asset_x_commitment,
            "private DEX LP asset x commitment",
        )?;
        ensure_non_empty(
            &self.asset_y_commitment,
            "private DEX LP asset y commitment",
        )?;
        ensure_non_empty(&self.metadata_root, "private DEX LP metadata root")?;
        ensure_status(
            &self.status,
            &[
                PRIVATE_DEX_STATUS_ACTIVE,
                PRIVATE_DEX_STATUS_LOCKED,
                PRIVATE_DEX_STATUS_RELEASED,
                PRIVATE_DEX_STATUS_CANCELLED,
            ],
        )?;
        if self.liquidity_units == 0 {
            return Err("private DEX LP liquidity must be positive".to_string());
        }
        if self.lower_price_bucket > self.upper_price_bucket {
            return Err("private DEX LP price bucket range is invalid".to_string());
        }
        let expected_id = private_dex_liquidity_position_id(
            &self.owner_commitment,
            &self.pool_id,
            self.liquidity_units,
            self.lower_price_bucket,
            self.upper_price_bucket,
            self.nonce,
        );
        if self.position_id != expected_id {
            return Err("private DEX LP position id mismatch".to_string());
        }
        Ok(self.position_id.clone())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_liquidity_position",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "position_id": self.position_id,
            "owner_commitment": self.owner_commitment,
            "pool_id": self.pool_id,
            "liquidity_units": self.liquidity_units,
            "asset_x_commitment": self.asset_x_commitment,
            "asset_y_commitment": self.asset_y_commitment,
            "amount_x_bucket": self.amount_x_bucket,
            "amount_y_bucket": self.amount_y_bucket,
            "lower_price_bucket": self.lower_price_bucket,
            "upper_price_bucket": self.upper_price_bucket,
            "unlock_height": self.unlock_height,
            "nonce": self.nonce,
            "metadata_root": self.metadata_root,
            "status": self.status,
        })
    }

    pub fn position_root(&self) -> String {
        private_dex_payload_root("PRIVATE-DEX-LIQUIDITY-POSITION-ROOT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexPqTranscript {
    pub transcript_id: String,
    pub purpose: PrivateDexTranscriptPurpose,
    pub circuit_family: PrivateDexCircuitFamily,
    pub session_label_commitment: String,
    pub domain_separator: String,
    pub input_root: String,
    pub challenge_root: String,
    pub response_root: String,
    pub ml_dsa_signature_root: String,
    pub slh_dsa_signature_root: String,
    pub kem_ciphertext_root: String,
    pub aggregate_signature_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl PrivateDexPqTranscript {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        purpose: PrivateDexTranscriptPurpose,
        circuit_family: PrivateDexCircuitFamily,
        session_label: &str,
        input_root: &str,
        challenge_payload: &Value,
        response_payload: &Value,
        signer_labels: &[String],
        kem_ciphertexts: &[Value],
        created_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateDexResult<Self> {
        ensure_non_empty(session_label, "private DEX transcript session label")?;
        ensure_non_empty(input_root, "private DEX transcript input root")?;
        if expires_at_height <= created_at_height {
            return Err("private DEX transcript expiry must be after creation".to_string());
        }
        let session_label_commitment =
            private_dex_string_root("PRIVATE-DEX-PQ-TRANSCRIPT-SESSION", session_label);
        let domain_separator = private_dex_transcript_domain_separator(purpose, circuit_family);
        let challenge_root =
            private_dex_payload_root("PRIVATE-DEX-PQ-TRANSCRIPT-CHALLENGE", challenge_payload);
        let response_root =
            private_dex_payload_root("PRIVATE-DEX-PQ-TRANSCRIPT-RESPONSE", response_payload);
        let ml_dsa_signature_root = private_dex_signature_set_root(
            "PRIVATE-DEX-PQ-ML-DSA-SIGNATURES",
            signer_labels,
            &domain_separator,
        );
        let slh_dsa_signature_root = private_dex_signature_set_root(
            "PRIVATE-DEX-PQ-SLH-DSA-SIGNATURES",
            signer_labels,
            &domain_separator,
        );
        let kem_ciphertext_root = merkle_root("PRIVATE-DEX-PQ-KEM-CIPHERTEXTS", kem_ciphertexts);
        let aggregate_signature_root = private_dex_aggregate_signature_root(
            &ml_dsa_signature_root,
            &slh_dsa_signature_root,
            &kem_ciphertext_root,
            input_root,
            &challenge_root,
        );
        let transcript_id = private_dex_pq_transcript_id(
            purpose,
            circuit_family,
            &session_label_commitment,
            input_root,
            &challenge_root,
            &aggregate_signature_root,
            created_at_height,
        );
        let transcript = Self {
            transcript_id,
            purpose,
            circuit_family,
            session_label_commitment,
            domain_separator,
            input_root: input_root.to_string(),
            challenge_root,
            response_root,
            ml_dsa_signature_root,
            slh_dsa_signature_root,
            kem_ciphertext_root,
            aggregate_signature_root,
            created_at_height,
            expires_at_height,
            status: PRIVATE_DEX_STATUS_ACTIVE.to_string(),
        };
        transcript.validate()?;
        Ok(transcript)
    }

    pub fn validate(&self) -> PrivateDexResult<String> {
        ensure_non_empty(&self.transcript_id, "private DEX transcript id")?;
        ensure_non_empty(
            &self.session_label_commitment,
            "private DEX transcript session commitment",
        )?;
        ensure_non_empty(
            &self.domain_separator,
            "private DEX transcript domain separator",
        )?;
        ensure_non_empty(&self.input_root, "private DEX transcript input root")?;
        ensure_non_empty(
            &self.challenge_root,
            "private DEX transcript challenge root",
        )?;
        ensure_non_empty(&self.response_root, "private DEX transcript response root")?;
        ensure_non_empty(
            &self.ml_dsa_signature_root,
            "private DEX transcript ML-DSA root",
        )?;
        ensure_non_empty(
            &self.slh_dsa_signature_root,
            "private DEX transcript SLH-DSA root",
        )?;
        ensure_non_empty(&self.kem_ciphertext_root, "private DEX transcript KEM root")?;
        ensure_non_empty(
            &self.aggregate_signature_root,
            "private DEX transcript aggregate root",
        )?;
        ensure_status(
            &self.status,
            &[
                PRIVATE_DEX_STATUS_ACTIVE,
                PRIVATE_DEX_STATUS_EXPIRED,
                PRIVATE_DEX_STATUS_REJECTED,
            ],
        )?;
        if self.expires_at_height <= self.created_at_height {
            return Err("private DEX transcript expiry must be after creation".to_string());
        }
        let expected_id = private_dex_pq_transcript_id(
            self.purpose,
            self.circuit_family,
            &self.session_label_commitment,
            &self.input_root,
            &self.challenge_root,
            &self.aggregate_signature_root,
            self.created_at_height,
        );
        if self.transcript_id != expected_id {
            return Err("private DEX transcript id mismatch".to_string());
        }
        Ok(self.transcript_id.clone())
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status == PRIVATE_DEX_STATUS_ACTIVE
            && self.created_at_height <= height
            && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_pq_transcript",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "transcript_id": self.transcript_id,
            "purpose": self.purpose.as_str(),
            "circuit_family": self.circuit_family.as_str(),
            "scheme": PRIVATE_DEX_TRANSCRIPT_SCHEME,
            "session_label_commitment": self.session_label_commitment,
            "domain_separator": self.domain_separator,
            "input_root": self.input_root,
            "challenge_root": self.challenge_root,
            "response_root": self.response_root,
            "ml_dsa_signature_root": self.ml_dsa_signature_root,
            "slh_dsa_signature_root": self.slh_dsa_signature_root,
            "kem_ciphertext_root": self.kem_ciphertext_root,
            "aggregate_signature_root": self.aggregate_signature_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn transcript_root(&self) -> String {
        private_dex_payload_root("PRIVATE-DEX-PQ-TRANSCRIPT-ROOT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexCircuitProfile {
    pub profile_id: String,
    pub circuit_family: PrivateDexCircuitFamily,
    pub proof_system: String,
    pub version: u64,
    pub verifying_key_root: String,
    pub parameter_root: String,
    pub public_input_schema_root: String,
    pub private_witness_schema_root: String,
    pub max_proof_bytes: u64,
    pub estimated_verify_micros: u64,
    pub recursion_depth: u64,
    pub pq_transcript_policy_root: String,
    pub status: String,
}

impl PrivateDexCircuitProfile {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        circuit_family: PrivateDexCircuitFamily,
        version: u64,
        verifying_key_root: &str,
        parameter_root: &str,
        public_input_schema: &Value,
        private_witness_schema: &Value,
        max_proof_bytes: u64,
        estimated_verify_micros: u64,
        recursion_depth: u64,
        pq_transcript_policy: &Value,
    ) -> PrivateDexResult<Self> {
        ensure_non_empty(verifying_key_root, "private DEX circuit verifying key root")?;
        ensure_non_empty(parameter_root, "private DEX circuit parameter root")?;
        if version == 0 {
            return Err("private DEX circuit version must be positive".to_string());
        }
        if max_proof_bytes == 0 || estimated_verify_micros == 0 {
            return Err(
                "private DEX circuit proof and verification bounds must be positive".to_string(),
            );
        }
        let proof_system = circuit_family.default_proof_system().to_string();
        let public_input_schema_root = private_dex_payload_root(
            "PRIVATE-DEX-CIRCUIT-PUBLIC-INPUT-SCHEMA",
            public_input_schema,
        );
        let private_witness_schema_root = private_dex_payload_root(
            "PRIVATE-DEX-CIRCUIT-PRIVATE-WITNESS-SCHEMA",
            private_witness_schema,
        );
        let pq_transcript_policy_root =
            private_dex_payload_root("PRIVATE-DEX-CIRCUIT-PQ-POLICY", pq_transcript_policy);
        let profile_id = private_dex_circuit_profile_id(
            circuit_family,
            &proof_system,
            version,
            verifying_key_root,
            parameter_root,
            &public_input_schema_root,
            &private_witness_schema_root,
            recursion_depth,
        );
        let profile = Self {
            profile_id,
            circuit_family,
            proof_system,
            version,
            verifying_key_root: verifying_key_root.to_string(),
            parameter_root: parameter_root.to_string(),
            public_input_schema_root,
            private_witness_schema_root,
            max_proof_bytes,
            estimated_verify_micros,
            recursion_depth,
            pq_transcript_policy_root,
            status: PRIVATE_DEX_STATUS_ACTIVE.to_string(),
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn validate(&self) -> PrivateDexResult<String> {
        ensure_non_empty(&self.profile_id, "private DEX circuit profile id")?;
        ensure_non_empty(&self.proof_system, "private DEX circuit proof system")?;
        ensure_non_empty(
            &self.verifying_key_root,
            "private DEX circuit verifying key root",
        )?;
        ensure_non_empty(&self.parameter_root, "private DEX circuit parameter root")?;
        ensure_non_empty(
            &self.public_input_schema_root,
            "private DEX circuit public input schema root",
        )?;
        ensure_non_empty(
            &self.private_witness_schema_root,
            "private DEX circuit private witness schema root",
        )?;
        ensure_non_empty(
            &self.pq_transcript_policy_root,
            "private DEX circuit PQ policy root",
        )?;
        ensure_status(
            &self.status,
            &[
                PRIVATE_DEX_STATUS_ACTIVE,
                PRIVATE_DEX_STATUS_PAUSED,
                PRIVATE_DEX_STATUS_REJECTED,
            ],
        )?;
        if self.version == 0 || self.max_proof_bytes == 0 || self.estimated_verify_micros == 0 {
            return Err("private DEX circuit numeric bounds must be positive".to_string());
        }
        let expected_id = private_dex_circuit_profile_id(
            self.circuit_family,
            &self.proof_system,
            self.version,
            &self.verifying_key_root,
            &self.parameter_root,
            &self.public_input_schema_root,
            &self.private_witness_schema_root,
            self.recursion_depth,
        );
        if self.profile_id != expected_id {
            return Err("private DEX circuit profile id mismatch".to_string());
        }
        Ok(self.profile_id.clone())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_circuit_profile",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "profile_id": self.profile_id,
            "circuit_family": self.circuit_family.as_str(),
            "proof_system": self.proof_system,
            "version": self.version,
            "verifying_key_root": self.verifying_key_root,
            "parameter_root": self.parameter_root,
            "public_input_schema_root": self.public_input_schema_root,
            "private_witness_schema_root": self.private_witness_schema_root,
            "max_proof_bytes": self.max_proof_bytes,
            "estimated_verify_micros": self.estimated_verify_micros,
            "recursion_depth": self.recursion_depth,
            "pq_transcript_policy_root": self.pq_transcript_policy_root,
            "status": self.status,
        })
    }

    pub fn profile_root(&self) -> String {
        private_dex_payload_root("PRIVATE-DEX-CIRCUIT-PROFILE-ROOT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexValidityProof {
    pub proof_id: String,
    pub transcript_id: String,
    pub circuit_profile_id: String,
    pub object_id: String,
    pub public_input_root: String,
    pub proof_root: String,
    pub recursive_accumulator_root: String,
    pub verifier_manifest_root: String,
    pub proof_bytes: u64,
    pub verified_at_height: u64,
    pub status: String,
}

impl PrivateDexValidityProof {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transcript_id: &str,
        circuit_profile_id: &str,
        object_id: &str,
        public_input_root: &str,
        private_witness_commitment: &str,
        recursive_accumulator_root: &str,
        verifier_manifest_root: &str,
        proof_bytes: u64,
        verified_at_height: u64,
    ) -> PrivateDexResult<Self> {
        ensure_non_empty(transcript_id, "private DEX proof transcript id")?;
        ensure_non_empty(circuit_profile_id, "private DEX proof circuit profile id")?;
        ensure_non_empty(object_id, "private DEX proof object id")?;
        ensure_non_empty(public_input_root, "private DEX proof public input root")?;
        ensure_non_empty(
            private_witness_commitment,
            "private DEX proof witness commitment",
        )?;
        ensure_non_empty(
            recursive_accumulator_root,
            "private DEX proof recursive accumulator",
        )?;
        ensure_non_empty(
            verifier_manifest_root,
            "private DEX proof verifier manifest",
        )?;
        if proof_bytes == 0 {
            return Err("private DEX proof bytes must be positive".to_string());
        }
        let proof_root = private_dex_validity_proof_root(
            transcript_id,
            circuit_profile_id,
            object_id,
            public_input_root,
            private_witness_commitment,
            recursive_accumulator_root,
            verifier_manifest_root,
        );
        let proof_id = private_dex_validity_proof_id(
            transcript_id,
            circuit_profile_id,
            object_id,
            &proof_root,
            verified_at_height,
        );
        let proof = Self {
            proof_id,
            transcript_id: transcript_id.to_string(),
            circuit_profile_id: circuit_profile_id.to_string(),
            object_id: object_id.to_string(),
            public_input_root: public_input_root.to_string(),
            proof_root,
            recursive_accumulator_root: recursive_accumulator_root.to_string(),
            verifier_manifest_root: verifier_manifest_root.to_string(),
            proof_bytes,
            verified_at_height,
            status: PRIVATE_DEX_STATUS_VERIFIED.to_string(),
        };
        proof.validate()?;
        Ok(proof)
    }

    pub fn validate(&self) -> PrivateDexResult<String> {
        ensure_non_empty(&self.proof_id, "private DEX proof id")?;
        ensure_non_empty(&self.transcript_id, "private DEX proof transcript id")?;
        ensure_non_empty(
            &self.circuit_profile_id,
            "private DEX proof circuit profile id",
        )?;
        ensure_non_empty(&self.object_id, "private DEX proof object id")?;
        ensure_non_empty(
            &self.public_input_root,
            "private DEX proof public input root",
        )?;
        ensure_non_empty(&self.proof_root, "private DEX proof root")?;
        ensure_non_empty(
            &self.recursive_accumulator_root,
            "private DEX proof accumulator",
        )?;
        ensure_non_empty(
            &self.verifier_manifest_root,
            "private DEX proof verifier manifest",
        )?;
        ensure_status(
            &self.status,
            &[PRIVATE_DEX_STATUS_VERIFIED, PRIVATE_DEX_STATUS_REJECTED],
        )?;
        if self.proof_bytes == 0 {
            return Err("private DEX proof bytes must be positive".to_string());
        }
        let expected_id = private_dex_validity_proof_id(
            &self.transcript_id,
            &self.circuit_profile_id,
            &self.object_id,
            &self.proof_root,
            self.verified_at_height,
        );
        if self.proof_id != expected_id {
            return Err("private DEX proof id mismatch".to_string());
        }
        Ok(self.proof_id.clone())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_validity_proof",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "proof_id": self.proof_id,
            "transcript_id": self.transcript_id,
            "circuit_profile_id": self.circuit_profile_id,
            "object_id": self.object_id,
            "public_input_root": self.public_input_root,
            "proof_root": self.proof_root,
            "recursive_accumulator_root": self.recursive_accumulator_root,
            "verifier_manifest_root": self.verifier_manifest_root,
            "proof_bytes": self.proof_bytes,
            "verified_at_height": self.verified_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexIntent {
    pub intent_id: String,
    pub owner_commitment: String,
    pub pair_id: String,
    pub side: PrivateDexOrderSide,
    pub order_kind: PrivateDexOrderKind,
    pub visibility: PrivateDexVisibility,
    pub asset_in_commitment: String,
    pub asset_out_commitment: String,
    pub amount_in_commitment: String,
    pub amount_out_min_commitment: String,
    pub limit_price_commitment: String,
    pub max_slippage_bps: u64,
    pub deadline_height: u64,
    pub submitted_at_height: u64,
    pub nonce: u64,
    pub encrypted_payload_root: String,
    pub route_hint_root: String,
    pub privacy_budget_id: String,
    pub nullifier_hash: String,
    pub recipient_commitment: String,
    pub pq_transcript_id: String,
    pub proof_public_input_root: String,
    pub public_metadata_root: String,
    pub status: String,
}

impl PrivateDexIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_label: &str,
        pair_id: &str,
        side: PrivateDexOrderSide,
        order_kind: PrivateDexOrderKind,
        asset_in_id: &str,
        asset_out_id: &str,
        amount_in_units: u64,
        min_amount_out_units: u64,
        limit_price_numerator: u64,
        limit_price_denominator: u64,
        max_slippage_bps: u64,
        deadline_height: u64,
        submitted_at_height: u64,
        nonce: u64,
        encrypted_payload: &Value,
        route_hint_root: impl Into<String>,
        privacy_budget_id: impl Into<String>,
        recipient_label: &str,
        pq_transcript_id: impl Into<String>,
        public_metadata: &Value,
    ) -> PrivateDexResult<Self> {
        ensure_non_empty(owner_label, "private DEX intent owner")?;
        ensure_non_empty(pair_id, "private DEX intent pair")?;
        ensure_non_empty(asset_in_id, "private DEX intent input asset")?;
        ensure_non_empty(asset_out_id, "private DEX intent output asset")?;
        ensure_non_empty(recipient_label, "private DEX intent recipient")?;
        if asset_in_id == asset_out_id {
            return Err("private DEX intent assets must differ".to_string());
        }
        if amount_in_units == 0 {
            return Err("private DEX intent amount must be positive".to_string());
        }
        if limit_price_denominator == 0 {
            return Err("private DEX intent limit price denominator cannot be zero".to_string());
        }
        if max_slippage_bps > PRIVATE_DEX_MAX_BPS {
            return Err("private DEX intent max slippage exceeds 10000 bps".to_string());
        }
        if deadline_height <= submitted_at_height {
            return Err("private DEX intent deadline must be after submission".to_string());
        }
        let route_hint_root = route_hint_root.into();
        let privacy_budget_id = privacy_budget_id.into();
        let pq_transcript_id = pq_transcript_id.into();
        ensure_non_empty(&route_hint_root, "private DEX intent route hint root")?;
        ensure_non_empty(&privacy_budget_id, "private DEX intent privacy budget id")?;
        ensure_non_empty(&pq_transcript_id, "private DEX intent PQ transcript id")?;
        let owner_commitment = private_dex_account_commitment(owner_label);
        let asset_in_commitment = private_dex_asset_commitment(asset_in_id);
        let asset_out_commitment = private_dex_asset_commitment(asset_out_id);
        let amount_in_commitment = private_dex_amount_commitment(
            amount_in_units,
            &private_dex_blinding(owner_label, nonce, "amount_in"),
        );
        let amount_out_min_commitment = private_dex_amount_commitment(
            min_amount_out_units,
            &private_dex_blinding(owner_label, nonce, "amount_out_min"),
        );
        let limit_price_commitment = private_dex_price_commitment(
            limit_price_numerator,
            limit_price_denominator,
            &private_dex_blinding(owner_label, nonce, "limit_price"),
        );
        let encrypted_payload_root =
            private_dex_payload_root("PRIVATE-DEX-INTENT-ENCRYPTED-PAYLOAD", encrypted_payload);
        let public_metadata_root =
            private_dex_payload_root("PRIVATE-DEX-INTENT-PUBLIC-METADATA", public_metadata);
        let nullifier_hash = private_dex_nullifier_hash(owner_label, nonce, "intent");
        let recipient_commitment = private_dex_account_commitment(recipient_label);
        let proof_public_input_root = private_dex_intent_public_input_root(
            pair_id,
            side,
            order_kind,
            &asset_in_commitment,
            &asset_out_commitment,
            private_dex_amount_bucket(amount_in_units),
            private_dex_amount_bucket(min_amount_out_units),
            max_slippage_bps,
            &route_hint_root,
        );
        let intent_id = private_dex_intent_id(
            &owner_commitment,
            pair_id,
            side,
            order_kind,
            &asset_in_commitment,
            &asset_out_commitment,
            &amount_in_commitment,
            &amount_out_min_commitment,
            &limit_price_commitment,
            &route_hint_root,
            deadline_height,
            nonce,
        );
        let intent = Self {
            intent_id,
            owner_commitment,
            pair_id: pair_id.to_string(),
            side,
            order_kind,
            visibility: PrivateDexVisibility::Private,
            asset_in_commitment,
            asset_out_commitment,
            amount_in_commitment,
            amount_out_min_commitment,
            limit_price_commitment,
            max_slippage_bps,
            deadline_height,
            submitted_at_height,
            nonce,
            encrypted_payload_root,
            route_hint_root,
            privacy_budget_id,
            nullifier_hash,
            recipient_commitment,
            pq_transcript_id,
            proof_public_input_root,
            public_metadata_root,
            status: PRIVATE_DEX_STATUS_ACTIVE.to_string(),
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "private_dex_intent_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "intent_id": self.intent_id,
            "owner_commitment": self.owner_commitment,
            "pair_id": self.pair_id,
            "side": self.side.as_str(),
            "order_kind": self.order_kind.as_str(),
            "visibility": self.visibility.as_str(),
            "asset_in_commitment": self.asset_in_commitment,
            "asset_out_commitment": self.asset_out_commitment,
            "amount_in_commitment": self.amount_in_commitment,
            "amount_out_min_commitment": self.amount_out_min_commitment,
            "limit_price_commitment": self.limit_price_commitment,
            "max_slippage_bps": self.max_slippage_bps,
            "deadline_height": self.deadline_height,
            "submitted_at_height": self.submitted_at_height,
            "nonce": self.nonce,
            "encrypted_payload_root": self.encrypted_payload_root,
            "route_hint_root": self.route_hint_root,
            "privacy_budget_id": self.privacy_budget_id,
            "nullifier_hash": self.nullifier_hash,
            "recipient_commitment": self.recipient_commitment,
            "pq_transcript_id": self.pq_transcript_id,
            "proof_public_input_root": self.proof_public_input_root,
            "public_metadata_root": self.public_metadata_root,
            "commitment_scheme": PRIVATE_DEX_COMMITMENT_SCHEME,
            "encryption_scheme": PRIVATE_DEX_ENCRYPTION_SCHEME,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        record
            .as_object_mut()
            .expect("private DEX intent public record object")
            .insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn validate(&self) -> PrivateDexResult<String> {
        ensure_non_empty(&self.intent_id, "private DEX intent id")?;
        ensure_non_empty(
            &self.owner_commitment,
            "private DEX intent owner commitment",
        )?;
        ensure_non_empty(&self.pair_id, "private DEX intent pair id")?;
        ensure_non_empty(
            &self.asset_in_commitment,
            "private DEX intent input asset commitment",
        )?;
        ensure_non_empty(
            &self.asset_out_commitment,
            "private DEX intent output asset commitment",
        )?;
        ensure_non_empty(
            &self.amount_in_commitment,
            "private DEX intent input amount commitment",
        )?;
        ensure_non_empty(
            &self.amount_out_min_commitment,
            "private DEX intent minimum output commitment",
        )?;
        ensure_non_empty(
            &self.limit_price_commitment,
            "private DEX intent limit price commitment",
        )?;
        ensure_non_empty(
            &self.encrypted_payload_root,
            "private DEX intent encrypted payload root",
        )?;
        ensure_non_empty(&self.route_hint_root, "private DEX intent route hint root")?;
        ensure_non_empty(
            &self.privacy_budget_id,
            "private DEX intent privacy budget id",
        )?;
        ensure_non_empty(&self.nullifier_hash, "private DEX intent nullifier")?;
        ensure_non_empty(
            &self.recipient_commitment,
            "private DEX intent recipient commitment",
        )?;
        ensure_non_empty(
            &self.pq_transcript_id,
            "private DEX intent PQ transcript id",
        )?;
        ensure_non_empty(
            &self.proof_public_input_root,
            "private DEX intent public input root",
        )?;
        ensure_non_empty(
            &self.public_metadata_root,
            "private DEX intent metadata root",
        )?;
        validate_bps("intent max_slippage_bps", self.max_slippage_bps)?;
        ensure_status(
            &self.status,
            &[
                PRIVATE_DEX_STATUS_ACTIVE,
                PRIVATE_DEX_STATUS_PENDING,
                PRIVATE_DEX_STATUS_FILLED,
                PRIVATE_DEX_STATUS_PARTIAL,
                PRIVATE_DEX_STATUS_EXPIRED,
                PRIVATE_DEX_STATUS_CANCELLED,
            ],
        )?;
        if self.deadline_height <= self.submitted_at_height {
            return Err("private DEX intent deadline must be after submission".to_string());
        }
        let expected_id = private_dex_intent_id(
            &self.owner_commitment,
            &self.pair_id,
            self.side,
            self.order_kind,
            &self.asset_in_commitment,
            &self.asset_out_commitment,
            &self.amount_in_commitment,
            &self.amount_out_min_commitment,
            &self.limit_price_commitment,
            &self.route_hint_root,
            self.deadline_height,
            self.nonce,
        );
        if self.intent_id != expected_id {
            return Err("private DEX intent id mismatch".to_string());
        }
        Ok(self.intent_id.clone())
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status == PRIVATE_DEX_STATUS_ACTIVE
            && self.submitted_at_height <= height
            && height <= self.deadline_height
    }

    pub fn mark_pending(&mut self) {
        self.status = PRIVATE_DEX_STATUS_PENDING.to_string();
    }

    pub fn mark_filled(&mut self) {
        self.status = PRIVATE_DEX_STATUS_FILLED.to_string();
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexRouteHint {
    pub hint_id: String,
    pub intent_id: String,
    pub venue_commitment: String,
    pub hop_commitment_root: String,
    pub route_ciphertext_root: String,
    pub disclosure_policy_root: String,
    pub max_hops: u16,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl PrivateDexRouteHint {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_id: &str,
        venue_label: &str,
        route_hops: &[Value],
        encrypted_route_payload: &Value,
        disclosure_policy: &Value,
        max_hops: u16,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateDexResult<Self> {
        ensure_non_empty(intent_id, "private DEX route hint intent")?;
        ensure_non_empty(venue_label, "private DEX route hint venue")?;
        if max_hops == 0 {
            return Err("private DEX route hint max hops must be positive".to_string());
        }
        if expires_at_height <= created_at_height {
            return Err("private DEX route hint expiry must be after creation".to_string());
        }
        let venue_commitment = private_dex_account_commitment(venue_label);
        let hop_commitment_root = private_dex_route_hop_root(route_hops);
        let route_ciphertext_root =
            private_dex_payload_root("PRIVATE-DEX-ROUTE-CIPHERTEXT", encrypted_route_payload);
        let disclosure_policy_root =
            private_dex_payload_root("PRIVATE-DEX-ROUTE-DISCLOSURE-POLICY", disclosure_policy);
        let hint_id = private_dex_route_hint_id(
            intent_id,
            &venue_commitment,
            &hop_commitment_root,
            &route_ciphertext_root,
            expires_at_height,
        );
        let hint = Self {
            hint_id,
            intent_id: intent_id.to_string(),
            venue_commitment,
            hop_commitment_root,
            route_ciphertext_root,
            disclosure_policy_root,
            max_hops,
            created_at_height,
            expires_at_height,
            status: PRIVATE_DEX_STATUS_ACTIVE.to_string(),
        };
        hint.validate()?;
        Ok(hint)
    }

    pub fn validate(&self) -> PrivateDexResult<String> {
        ensure_non_empty(&self.hint_id, "private DEX route hint id")?;
        ensure_non_empty(&self.intent_id, "private DEX route hint intent")?;
        ensure_non_empty(
            &self.venue_commitment,
            "private DEX route hint venue commitment",
        )?;
        ensure_non_empty(&self.hop_commitment_root, "private DEX route hint hop root")?;
        ensure_non_empty(
            &self.route_ciphertext_root,
            "private DEX route hint ciphertext root",
        )?;
        ensure_non_empty(
            &self.disclosure_policy_root,
            "private DEX route hint disclosure policy root",
        )?;
        ensure_status(
            &self.status,
            &[
                PRIVATE_DEX_STATUS_ACTIVE,
                PRIVATE_DEX_STATUS_EXPIRED,
                PRIVATE_DEX_STATUS_CANCELLED,
            ],
        )?;
        if self.max_hops == 0 {
            return Err("private DEX route hint max hops must be positive".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("private DEX route hint expiry must be after creation".to_string());
        }
        let expected_id = private_dex_route_hint_id(
            &self.intent_id,
            &self.venue_commitment,
            &self.hop_commitment_root,
            &self.route_ciphertext_root,
            self.expires_at_height,
        );
        if self.hint_id != expected_id {
            return Err("private DEX route hint id mismatch".to_string());
        }
        Ok(self.hint_id.clone())
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status == PRIVATE_DEX_STATUS_ACTIVE
            && self.created_at_height <= height
            && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_route_hint",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "hint_id": self.hint_id,
            "intent_id": self.intent_id,
            "venue_commitment": self.venue_commitment,
            "hop_commitment_root": self.hop_commitment_root,
            "route_ciphertext_root": self.route_ciphertext_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "max_hops": self.max_hops,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexPrivacyBudget {
    pub budget_id: String,
    pub owner_commitment: String,
    pub epoch: u64,
    pub epoch_start_height: u64,
    pub epoch_end_height: u64,
    pub total_units: u64,
    pub reserved_units: u64,
    pub consumed_units: u64,
    pub released_units: u64,
    pub status: String,
}

impl PrivateDexPrivacyBudget {
    pub fn new(
        owner_label: &str,
        epoch: u64,
        epoch_start_height: u64,
        epoch_blocks: u64,
        total_units: u64,
    ) -> PrivateDexResult<Self> {
        ensure_non_empty(owner_label, "private DEX privacy budget owner")?;
        if epoch_blocks == 0 || total_units == 0 {
            return Err("private DEX privacy budget epoch and units must be positive".to_string());
        }
        let owner_commitment = private_dex_account_commitment(owner_label);
        let epoch_end_height = epoch_start_height.saturating_add(epoch_blocks);
        let budget_id = private_dex_privacy_budget_id(
            &owner_commitment,
            epoch,
            epoch_start_height,
            epoch_end_height,
            total_units,
        );
        let budget = Self {
            budget_id,
            owner_commitment,
            epoch,
            epoch_start_height,
            epoch_end_height,
            total_units,
            reserved_units: 0,
            consumed_units: 0,
            released_units: 0,
            status: PRIVATE_DEX_STATUS_ACTIVE.to_string(),
        };
        budget.validate()?;
        Ok(budget)
    }

    pub fn validate(&self) -> PrivateDexResult<String> {
        ensure_non_empty(&self.budget_id, "private DEX privacy budget id")?;
        ensure_non_empty(
            &self.owner_commitment,
            "private DEX privacy budget owner commitment",
        )?;
        ensure_status(
            &self.status,
            &[PRIVATE_DEX_STATUS_ACTIVE, PRIVATE_DEX_STATUS_EXPIRED],
        )?;
        if self.epoch_end_height <= self.epoch_start_height {
            return Err("private DEX privacy budget epoch is invalid".to_string());
        }
        if self.total_units == 0 {
            return Err("private DEX privacy budget units must be positive".to_string());
        }
        if self
            .reserved_units
            .saturating_add(self.consumed_units)
            .saturating_add(self.released_units)
            > self.total_units.saturating_mul(2)
        {
            return Err("private DEX privacy budget accounting is inconsistent".to_string());
        }
        let expected_id = private_dex_privacy_budget_id(
            &self.owner_commitment,
            self.epoch,
            self.epoch_start_height,
            self.epoch_end_height,
            self.total_units,
        );
        if self.budget_id != expected_id {
            return Err("private DEX privacy budget id mismatch".to_string());
        }
        Ok(self.budget_id.clone())
    }

    pub fn available_units(&self) -> u64 {
        self.total_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.consumed_units)
    }

    pub fn reserve(&mut self, units: u64) -> PrivateDexResult<()> {
        if units == 0 {
            return Err(
                "private DEX privacy budget reservation units must be positive".to_string(),
            );
        }
        if self.available_units() < units {
            return Err("private DEX privacy budget exhausted".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(units);
        Ok(())
    }

    pub fn consume_reserved(&mut self, units: u64) -> PrivateDexResult<()> {
        if units == 0 || self.reserved_units < units {
            return Err("private DEX privacy budget reserved units are insufficient".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_sub(units);
        self.consumed_units = self.consumed_units.saturating_add(units);
        Ok(())
    }

    pub fn release_reserved(&mut self, units: u64) -> PrivateDexResult<()> {
        if units == 0 || self.reserved_units < units {
            return Err("private DEX privacy budget reserved units are insufficient".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_sub(units);
        self.released_units = self.released_units.saturating_add(units);
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_privacy_budget",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "budget_id": self.budget_id,
            "owner_commitment": self.owner_commitment,
            "epoch": self.epoch,
            "epoch_start_height": self.epoch_start_height,
            "epoch_end_height": self.epoch_end_height,
            "total_units": self.total_units,
            "reserved_units": self.reserved_units,
            "consumed_units": self.consumed_units,
            "released_units": self.released_units,
            "available_units": self.available_units(),
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexPrivacyReservation {
    pub reservation_id: String,
    pub budget_id: String,
    pub object_kind: String,
    pub object_id: String,
    pub units: u64,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub consumed_at_height: Option<u64>,
    pub released_at_height: Option<u64>,
    pub status: String,
}

impl PrivateDexPrivacyReservation {
    pub fn new(
        budget_id: &str,
        object_kind: &str,
        object_id: &str,
        units: u64,
        reserved_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateDexResult<Self> {
        ensure_non_empty(budget_id, "private DEX privacy reservation budget")?;
        ensure_non_empty(object_kind, "private DEX privacy reservation object kind")?;
        ensure_non_empty(object_id, "private DEX privacy reservation object id")?;
        if units == 0 {
            return Err("private DEX privacy reservation units must be positive".to_string());
        }
        if expires_at_height <= reserved_at_height {
            return Err(
                "private DEX privacy reservation expiry must be after reservation".to_string(),
            );
        }
        let reservation_id = private_dex_privacy_reservation_id(
            budget_id,
            object_kind,
            object_id,
            units,
            reserved_at_height,
            expires_at_height,
        );
        let reservation = Self {
            reservation_id,
            budget_id: budget_id.to_string(),
            object_kind: object_kind.to_string(),
            object_id: object_id.to_string(),
            units,
            reserved_at_height,
            expires_at_height,
            consumed_at_height: None,
            released_at_height: None,
            status: PRIVATE_DEX_STATUS_ACTIVE.to_string(),
        };
        reservation.validate()?;
        Ok(reservation)
    }

    pub fn validate(&self) -> PrivateDexResult<String> {
        ensure_non_empty(&self.reservation_id, "private DEX privacy reservation id")?;
        ensure_non_empty(&self.budget_id, "private DEX privacy reservation budget id")?;
        ensure_non_empty(
            &self.object_kind,
            "private DEX privacy reservation object kind",
        )?;
        ensure_non_empty(&self.object_id, "private DEX privacy reservation object id")?;
        ensure_status(
            &self.status,
            &[
                PRIVATE_DEX_STATUS_ACTIVE,
                PRIVATE_DEX_STATUS_CONSUMED,
                PRIVATE_DEX_STATUS_RELEASED,
                PRIVATE_DEX_STATUS_EXPIRED,
            ],
        )?;
        if self.units == 0 {
            return Err("private DEX privacy reservation units must be positive".to_string());
        }
        if self.expires_at_height <= self.reserved_at_height {
            return Err(
                "private DEX privacy reservation expiry must be after reservation".to_string(),
            );
        }
        let expected_id = private_dex_privacy_reservation_id(
            &self.budget_id,
            &self.object_kind,
            &self.object_id,
            self.units,
            self.reserved_at_height,
            self.expires_at_height,
        );
        if self.reservation_id != expected_id {
            return Err("private DEX privacy reservation id mismatch".to_string());
        }
        Ok(self.reservation_id.clone())
    }

    pub fn mark_consumed(&mut self, height: u64) -> PrivateDexResult<()> {
        if self.status != PRIVATE_DEX_STATUS_ACTIVE {
            return Err("private DEX privacy reservation is not active".to_string());
        }
        self.consumed_at_height = Some(height);
        self.status = PRIVATE_DEX_STATUS_CONSUMED.to_string();
        Ok(())
    }

    pub fn mark_released(&mut self, height: u64) -> PrivateDexResult<()> {
        if self.status != PRIVATE_DEX_STATUS_ACTIVE {
            return Err("private DEX privacy reservation is not active".to_string());
        }
        self.released_at_height = Some(height);
        self.status = PRIVATE_DEX_STATUS_RELEASED.to_string();
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_privacy_reservation",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "reservation_id": self.reservation_id,
            "budget_id": self.budget_id,
            "object_kind": self.object_kind,
            "object_id": self.object_id,
            "units": self.units,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
            "consumed_at_height": self.consumed_at_height,
            "released_at_height": self.released_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexAuction {
    pub auction_id: String,
    pub market_id: String,
    pub pair_id: String,
    pub pair_commitment: String,
    pub intent_root: String,
    pub route_hint_root: String,
    pub privacy_budget_root: String,
    pub pool_snapshot_root: String,
    pub oracle_guard_root: String,
    pub commit_start_height: u64,
    pub commit_end_height: u64,
    pub reveal_start_height: u64,
    pub reveal_end_height: u64,
    pub challenge_end_height: u64,
    pub settlement_deadline_height: u64,
    pub ordering_seed: String,
    pub pq_transcript_id: String,
    pub solver_commitment_root: String,
    pub clearing_result_root: String,
    pub status: String,
}

impl PrivateDexAuction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        pair_id: &str,
        pair_commitment: &str,
        intent_root: &str,
        route_hint_root: &str,
        privacy_budget_root: &str,
        pool_snapshot_root: &str,
        oracle_guard_root: &str,
        commit_start_height: u64,
        auction_window_blocks: u64,
        reveal_delay_blocks: u64,
        reveal_window_blocks: u64,
        challenge_window_blocks: u64,
        settlement_ttl_blocks: u64,
        ordering_seed: &str,
        pq_transcript_id: &str,
    ) -> PrivateDexResult<Self> {
        ensure_non_empty(market_id, "private DEX auction market")?;
        ensure_non_empty(pair_id, "private DEX auction pair")?;
        ensure_non_empty(pair_commitment, "private DEX auction pair commitment")?;
        ensure_non_empty(intent_root, "private DEX auction intent root")?;
        ensure_non_empty(route_hint_root, "private DEX auction route hint root")?;
        ensure_non_empty(
            privacy_budget_root,
            "private DEX auction privacy budget root",
        )?;
        ensure_non_empty(pool_snapshot_root, "private DEX auction pool snapshot root")?;
        ensure_non_empty(oracle_guard_root, "private DEX auction oracle guard root")?;
        ensure_non_empty(ordering_seed, "private DEX auction ordering seed")?;
        ensure_non_empty(pq_transcript_id, "private DEX auction PQ transcript")?;
        if auction_window_blocks == 0 || reveal_window_blocks == 0 || challenge_window_blocks == 0 {
            return Err("private DEX auction windows must be positive".to_string());
        }
        let commit_end_height = commit_start_height.saturating_add(auction_window_blocks);
        let reveal_start_height = commit_end_height.saturating_add(reveal_delay_blocks);
        let reveal_end_height = reveal_start_height.saturating_add(reveal_window_blocks);
        let challenge_end_height = reveal_end_height.saturating_add(challenge_window_blocks);
        let settlement_deadline_height = challenge_end_height.saturating_add(settlement_ttl_blocks);
        let auction_id = private_dex_auction_id(
            market_id,
            pair_id,
            pair_commitment,
            intent_root,
            commit_start_height,
            commit_end_height,
            ordering_seed,
        );
        let auction = Self {
            auction_id,
            market_id: market_id.to_string(),
            pair_id: pair_id.to_string(),
            pair_commitment: pair_commitment.to_string(),
            intent_root: intent_root.to_string(),
            route_hint_root: route_hint_root.to_string(),
            privacy_budget_root: privacy_budget_root.to_string(),
            pool_snapshot_root: pool_snapshot_root.to_string(),
            oracle_guard_root: oracle_guard_root.to_string(),
            commit_start_height,
            commit_end_height,
            reveal_start_height,
            reveal_end_height,
            challenge_end_height,
            settlement_deadline_height,
            ordering_seed: ordering_seed.to_string(),
            pq_transcript_id: pq_transcript_id.to_string(),
            solver_commitment_root: private_dex_solver_quote_commitment_root(&[]),
            clearing_result_root: merkle_root("PRIVATE-DEX-AUCTION-CLEARING-EMPTY", &[]),
            status: PRIVATE_DEX_STATUS_COLLECTING.to_string(),
        };
        auction.validate()?;
        Ok(auction)
    }

    pub fn validate(&self) -> PrivateDexResult<String> {
        ensure_non_empty(&self.auction_id, "private DEX auction id")?;
        ensure_non_empty(&self.market_id, "private DEX auction market")?;
        ensure_non_empty(&self.pair_id, "private DEX auction pair")?;
        ensure_non_empty(&self.pair_commitment, "private DEX auction pair commitment")?;
        ensure_non_empty(&self.intent_root, "private DEX auction intent root")?;
        ensure_non_empty(&self.route_hint_root, "private DEX auction route hint root")?;
        ensure_non_empty(
            &self.privacy_budget_root,
            "private DEX auction privacy budget root",
        )?;
        ensure_non_empty(
            &self.pool_snapshot_root,
            "private DEX auction pool snapshot root",
        )?;
        ensure_non_empty(
            &self.oracle_guard_root,
            "private DEX auction oracle guard root",
        )?;
        ensure_non_empty(&self.ordering_seed, "private DEX auction ordering seed")?;
        ensure_non_empty(&self.pq_transcript_id, "private DEX auction PQ transcript")?;
        ensure_non_empty(
            &self.solver_commitment_root,
            "private DEX auction solver root",
        )?;
        ensure_non_empty(
            &self.clearing_result_root,
            "private DEX auction clearing root",
        )?;
        ensure_status(
            &self.status,
            &[
                PRIVATE_DEX_STATUS_COLLECTING,
                PRIVATE_DEX_STATUS_REVEALING,
                PRIVATE_DEX_STATUS_MATCHING,
                PRIVATE_DEX_STATUS_SETTLED,
                PRIVATE_DEX_STATUS_EXPIRED,
                PRIVATE_DEX_STATUS_CANCELLED,
            ],
        )?;
        if self.commit_end_height <= self.commit_start_height
            || self.reveal_start_height < self.commit_end_height
            || self.reveal_end_height <= self.reveal_start_height
            || self.challenge_end_height <= self.reveal_end_height
            || self.settlement_deadline_height <= self.challenge_end_height
        {
            return Err("private DEX auction height windows are invalid".to_string());
        }
        let expected_id = private_dex_auction_id(
            &self.market_id,
            &self.pair_id,
            &self.pair_commitment,
            &self.intent_root,
            self.commit_start_height,
            self.commit_end_height,
            &self.ordering_seed,
        );
        if self.auction_id != expected_id {
            return Err("private DEX auction id mismatch".to_string());
        }
        Ok(self.auction_id.clone())
    }

    pub fn phase_at(&self, height: u64) -> PrivateDexAuctionPhase {
        if self.status == PRIVATE_DEX_STATUS_SETTLED {
            return PrivateDexAuctionPhase::Settled;
        }
        if height <= self.commit_end_height {
            PrivateDexAuctionPhase::Collecting
        } else if height < self.reveal_start_height {
            PrivateDexAuctionPhase::Matching
        } else if height <= self.reveal_end_height {
            PrivateDexAuctionPhase::Revealing
        } else if height <= self.challenge_end_height {
            PrivateDexAuctionPhase::Challenge
        } else if height <= self.settlement_deadline_height {
            PrivateDexAuctionPhase::Matching
        } else {
            PrivateDexAuctionPhase::Expired
        }
    }

    pub fn accepts_intents_at(&self, height: u64) -> bool {
        self.status == PRIVATE_DEX_STATUS_COLLECTING
            && self.commit_start_height <= height
            && height <= self.commit_end_height
    }

    pub fn accepts_reveals_at(&self, height: u64) -> bool {
        matches!(
            self.status.as_str(),
            PRIVATE_DEX_STATUS_REVEALING
                | PRIVATE_DEX_STATUS_MATCHING
                | PRIVATE_DEX_STATUS_COLLECTING
        ) && self.reveal_start_height <= height
            && height <= self.reveal_end_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_auction",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "auction_id": self.auction_id,
            "market_id": self.market_id,
            "pair_id": self.pair_id,
            "pair_commitment": self.pair_commitment,
            "intent_root": self.intent_root,
            "route_hint_root": self.route_hint_root,
            "privacy_budget_root": self.privacy_budget_root,
            "pool_snapshot_root": self.pool_snapshot_root,
            "oracle_guard_root": self.oracle_guard_root,
            "commit_start_height": self.commit_start_height,
            "commit_end_height": self.commit_end_height,
            "reveal_start_height": self.reveal_start_height,
            "reveal_end_height": self.reveal_end_height,
            "challenge_end_height": self.challenge_end_height,
            "settlement_deadline_height": self.settlement_deadline_height,
            "ordering_seed": self.ordering_seed,
            "pq_transcript_id": self.pq_transcript_id,
            "solver_commitment_root": self.solver_commitment_root,
            "clearing_result_root": self.clearing_result_root,
            "status": self.status,
            "phase_hint_at_commit_end": self.phase_at(self.commit_end_height).as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexSolverQuoteCommitment {
    pub quote_id: String,
    pub auction_id: String,
    pub solver_commitment: String,
    pub solver_kind: PrivateDexSolverKind,
    pub route_commitment: String,
    pub asset_pair_commitment: String,
    pub amount_in_commitment: String,
    pub amount_out_commitment: String,
    pub clearing_price_commitment: String,
    pub solver_fee_commitment: String,
    pub surplus_commitment: String,
    pub quote_commitment: String,
    pub pq_transcript_id: String,
    pub bond_units: u64,
    pub committed_at_height: u64,
    pub reveal_deadline_height: u64,
    pub status: String,
}

impl PrivateDexSolverQuoteCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: &str,
        solver_label: &str,
        solver_kind: PrivateDexSolverKind,
        route_commitment: &str,
        asset_pair_commitment: &str,
        amount_in_units: u64,
        amount_out_units: u64,
        clearing_price_numerator: u64,
        clearing_price_denominator: u64,
        solver_fee_units: u64,
        surplus_units: u64,
        quote_secret: &str,
        pq_transcript_id: &str,
        bond_units: u64,
        committed_at_height: u64,
        reveal_deadline_height: u64,
    ) -> PrivateDexResult<Self> {
        ensure_non_empty(auction_id, "private DEX quote auction")?;
        ensure_non_empty(solver_label, "private DEX quote solver")?;
        ensure_non_empty(route_commitment, "private DEX quote route commitment")?;
        ensure_non_empty(asset_pair_commitment, "private DEX quote pair commitment")?;
        ensure_non_empty(quote_secret, "private DEX quote secret")?;
        ensure_non_empty(pq_transcript_id, "private DEX quote PQ transcript")?;
        if amount_in_units == 0 || amount_out_units == 0 {
            return Err("private DEX quote amounts must be positive".to_string());
        }
        if clearing_price_denominator == 0 {
            return Err("private DEX quote clearing price denominator cannot be zero".to_string());
        }
        if reveal_deadline_height <= committed_at_height {
            return Err("private DEX quote reveal deadline must be after commitment".to_string());
        }
        let solver_commitment = private_dex_solver_commitment(solver_label);
        let amount_in_commitment = private_dex_amount_commitment(amount_in_units, quote_secret);
        let amount_out_commitment = private_dex_amount_commitment(amount_out_units, quote_secret);
        let clearing_price_commitment = private_dex_price_commitment(
            clearing_price_numerator,
            clearing_price_denominator,
            quote_secret,
        );
        let solver_fee_commitment = private_dex_amount_commitment(solver_fee_units, quote_secret);
        let surplus_commitment = private_dex_amount_commitment(surplus_units, quote_secret);
        let quote_commitment = private_dex_quote_commitment_hash(
            auction_id,
            &solver_commitment,
            route_commitment,
            asset_pair_commitment,
            &amount_in_commitment,
            &amount_out_commitment,
            &clearing_price_commitment,
            &solver_fee_commitment,
            &surplus_commitment,
            pq_transcript_id,
            quote_secret,
        );
        let quote_id = private_dex_solver_quote_id(
            auction_id,
            &solver_commitment,
            &quote_commitment,
            committed_at_height,
            reveal_deadline_height,
        );
        let quote = Self {
            quote_id,
            auction_id: auction_id.to_string(),
            solver_commitment,
            solver_kind,
            route_commitment: route_commitment.to_string(),
            asset_pair_commitment: asset_pair_commitment.to_string(),
            amount_in_commitment,
            amount_out_commitment,
            clearing_price_commitment,
            solver_fee_commitment,
            surplus_commitment,
            quote_commitment,
            pq_transcript_id: pq_transcript_id.to_string(),
            bond_units,
            committed_at_height,
            reveal_deadline_height,
            status: PRIVATE_DEX_STATUS_PENDING.to_string(),
        };
        quote.validate()?;
        Ok(quote)
    }

    pub fn validate(&self) -> PrivateDexResult<String> {
        ensure_non_empty(&self.quote_id, "private DEX quote id")?;
        ensure_non_empty(&self.auction_id, "private DEX quote auction")?;
        ensure_non_empty(
            &self.solver_commitment,
            "private DEX quote solver commitment",
        )?;
        ensure_non_empty(&self.route_commitment, "private DEX quote route commitment")?;
        ensure_non_empty(
            &self.asset_pair_commitment,
            "private DEX quote pair commitment",
        )?;
        ensure_non_empty(
            &self.amount_in_commitment,
            "private DEX quote input amount commitment",
        )?;
        ensure_non_empty(
            &self.amount_out_commitment,
            "private DEX quote output amount commitment",
        )?;
        ensure_non_empty(
            &self.clearing_price_commitment,
            "private DEX quote price commitment",
        )?;
        ensure_non_empty(
            &self.solver_fee_commitment,
            "private DEX quote fee commitment",
        )?;
        ensure_non_empty(
            &self.surplus_commitment,
            "private DEX quote surplus commitment",
        )?;
        ensure_non_empty(&self.quote_commitment, "private DEX quote commitment")?;
        ensure_non_empty(&self.pq_transcript_id, "private DEX quote PQ transcript")?;
        ensure_status(
            &self.status,
            &[
                PRIVATE_DEX_STATUS_PENDING,
                PRIVATE_DEX_STATUS_REVEALING,
                PRIVATE_DEX_STATUS_REJECTED,
                PRIVATE_DEX_STATUS_SETTLED,
            ],
        )?;
        if self.reveal_deadline_height <= self.committed_at_height {
            return Err("private DEX quote reveal deadline must be after commitment".to_string());
        }
        let expected_id = private_dex_solver_quote_id(
            &self.auction_id,
            &self.solver_commitment,
            &self.quote_commitment,
            self.committed_at_height,
            self.reveal_deadline_height,
        );
        if self.quote_id != expected_id {
            return Err("private DEX quote id mismatch".to_string());
        }
        Ok(self.quote_id.clone())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_solver_quote_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "quote_id": self.quote_id,
            "auction_id": self.auction_id,
            "solver_commitment": self.solver_commitment,
            "solver_kind": self.solver_kind.as_str(),
            "route_commitment": self.route_commitment,
            "asset_pair_commitment": self.asset_pair_commitment,
            "amount_in_commitment": self.amount_in_commitment,
            "amount_out_commitment": self.amount_out_commitment,
            "clearing_price_commitment": self.clearing_price_commitment,
            "solver_fee_commitment": self.solver_fee_commitment,
            "surplus_commitment": self.surplus_commitment,
            "quote_commitment": self.quote_commitment,
            "pq_transcript_id": self.pq_transcript_id,
            "bond_units": self.bond_units,
            "committed_at_height": self.committed_at_height,
            "reveal_deadline_height": self.reveal_deadline_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexRouteLeg {
    pub leg_id: String,
    pub index: u64,
    pub pool_id: String,
    pub asset_in_id: String,
    pub asset_out_id: String,
    pub amount_in: u64,
    pub amount_in_after_fee: u64,
    pub amount_out: u64,
    pub pool_fee_units: u64,
    pub protocol_fee_units: u64,
    pub price_impact_bps: u64,
    pub pool_before_root: String,
    pub pool_after_root: String,
    pub proof_root: String,
}

impl PrivateDexRouteLeg {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        index: u64,
        pool_id: &str,
        asset_in_id: &str,
        asset_out_id: &str,
        amount_in: u64,
        amount_in_after_fee: u64,
        amount_out: u64,
        pool_fee_units: u64,
        protocol_fee_units: u64,
        price_impact_bps: u64,
        pool_before_root: &str,
        pool_after_root: &str,
        proof_root: &str,
    ) -> PrivateDexResult<Self> {
        ensure_non_empty(pool_id, "private DEX route leg pool")?;
        ensure_non_empty(asset_in_id, "private DEX route leg input asset")?;
        ensure_non_empty(asset_out_id, "private DEX route leg output asset")?;
        ensure_non_empty(pool_before_root, "private DEX route leg pool before root")?;
        ensure_non_empty(pool_after_root, "private DEX route leg pool after root")?;
        ensure_non_empty(proof_root, "private DEX route leg proof root")?;
        if asset_in_id == asset_out_id {
            return Err("private DEX route leg assets must differ".to_string());
        }
        if amount_in == 0 || amount_out == 0 {
            return Err("private DEX route leg amounts must be positive".to_string());
        }
        let leg_id = private_dex_route_leg_id(
            index,
            pool_id,
            asset_in_id,
            asset_out_id,
            amount_in,
            amount_out,
            pool_before_root,
            pool_after_root,
        );
        let leg = Self {
            leg_id,
            index,
            pool_id: pool_id.to_string(),
            asset_in_id: asset_in_id.to_string(),
            asset_out_id: asset_out_id.to_string(),
            amount_in,
            amount_in_after_fee,
            amount_out,
            pool_fee_units,
            protocol_fee_units,
            price_impact_bps,
            pool_before_root: pool_before_root.to_string(),
            pool_after_root: pool_after_root.to_string(),
            proof_root: proof_root.to_string(),
        };
        leg.validate()?;
        Ok(leg)
    }

    pub fn validate(&self) -> PrivateDexResult<String> {
        ensure_non_empty(&self.leg_id, "private DEX route leg id")?;
        ensure_non_empty(&self.pool_id, "private DEX route leg pool")?;
        ensure_non_empty(&self.asset_in_id, "private DEX route leg input asset")?;
        ensure_non_empty(&self.asset_out_id, "private DEX route leg output asset")?;
        ensure_non_empty(
            &self.pool_before_root,
            "private DEX route leg pool before root",
        )?;
        ensure_non_empty(
            &self.pool_after_root,
            "private DEX route leg pool after root",
        )?;
        ensure_non_empty(&self.proof_root, "private DEX route leg proof root")?;
        if self.asset_in_id == self.asset_out_id || self.amount_in == 0 || self.amount_out == 0 {
            return Err("private DEX route leg is invalid".to_string());
        }
        let expected_id = private_dex_route_leg_id(
            self.index,
            &self.pool_id,
            &self.asset_in_id,
            &self.asset_out_id,
            self.amount_in,
            self.amount_out,
            &self.pool_before_root,
            &self.pool_after_root,
        );
        if self.leg_id != expected_id {
            return Err("private DEX route leg id mismatch".to_string());
        }
        Ok(self.leg_id.clone())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_route_leg",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "leg_id": self.leg_id,
            "index": self.index,
            "pool_id": self.pool_id,
            "asset_in_id": self.asset_in_id,
            "asset_out_id": self.asset_out_id,
            "amount_in": self.amount_in,
            "amount_in_after_fee": self.amount_in_after_fee,
            "amount_out": self.amount_out,
            "pool_fee_units": self.pool_fee_units,
            "protocol_fee_units": self.protocol_fee_units,
            "price_impact_bps": self.price_impact_bps,
            "pool_before_root": self.pool_before_root,
            "pool_after_root": self.pool_after_root,
            "proof_root": self.proof_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexCfmmQuote {
    pub quote_id: String,
    pub pool_id: String,
    pub asset_in_id: String,
    pub asset_out_id: String,
    pub amount_in: u64,
    pub amount_in_after_fee: u64,
    pub amount_out: u64,
    pub pool_fee_units: u64,
    pub protocol_fee_units: u64,
    pub fee_bps: u64,
    pub price_impact_bps: u64,
    pub reserve_in_before: u64,
    pub reserve_out_before: u64,
}

impl PrivateDexCfmmQuote {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool_id: &str,
        asset_in_id: &str,
        asset_out_id: &str,
        amount_in: u64,
        amount_in_after_fee: u64,
        amount_out: u64,
        pool_fee_units: u64,
        protocol_fee_units: u64,
        fee_bps: u64,
        price_impact_bps: u64,
        reserve_in_before: u64,
        reserve_out_before: u64,
    ) -> Self {
        let quote_id = private_dex_cfmm_quote_id(
            pool_id,
            asset_in_id,
            asset_out_id,
            amount_in,
            amount_out,
            fee_bps,
            reserve_in_before,
            reserve_out_before,
        );
        Self {
            quote_id,
            pool_id: pool_id.to_string(),
            asset_in_id: asset_in_id.to_string(),
            asset_out_id: asset_out_id.to_string(),
            amount_in,
            amount_in_after_fee,
            amount_out,
            pool_fee_units,
            protocol_fee_units,
            fee_bps,
            price_impact_bps,
            reserve_in_before,
            reserve_out_before,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_cfmm_quote",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "quote_id": self.quote_id,
            "pool_id": self.pool_id,
            "asset_in_id": self.asset_in_id,
            "asset_out_id": self.asset_out_id,
            "amount_in": self.amount_in,
            "amount_in_after_fee": self.amount_in_after_fee,
            "amount_out": self.amount_out,
            "pool_fee_units": self.pool_fee_units,
            "protocol_fee_units": self.protocol_fee_units,
            "fee_bps": self.fee_bps,
            "price_impact_bps": self.price_impact_bps,
            "reserve_in_before": self.reserve_in_before,
            "reserve_out_before": self.reserve_out_before,
        })
    }

    pub fn quote_root(&self) -> String {
        private_dex_payload_root("PRIVATE-DEX-CFMM-QUOTE-ROOT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexRoutePlan {
    pub route_id: String,
    pub intent_id: String,
    pub solver_commitment: String,
    pub pool_ids: Vec<String>,
    pub asset_path: Vec<String>,
    pub leg_root: String,
    pub quote_root: String,
    pub route_commitment: String,
    pub amount_in: u64,
    pub expected_amount_out: u64,
    pub worst_case_amount_out: u64,
    pub total_pool_fee_units: u64,
    pub total_protocol_fee_units: u64,
    pub aggregate_price_impact_bps: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub pq_transcript_id: String,
    pub low_fee_rebate_id: Option<String>,
    pub status: String,
    pub legs: Vec<PrivateDexRouteLeg>,
}

impl PrivateDexRoutePlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_id: &str,
        solver_label: &str,
        pool_ids: Vec<String>,
        asset_path: Vec<String>,
        amount_in: u64,
        expected_amount_out: u64,
        worst_case_amount_out: u64,
        total_pool_fee_units: u64,
        total_protocol_fee_units: u64,
        aggregate_price_impact_bps: u64,
        created_at_height: u64,
        ttl_blocks: u64,
        pq_transcript_id: &str,
        legs: Vec<PrivateDexRouteLeg>,
    ) -> PrivateDexResult<Self> {
        ensure_non_empty(intent_id, "private DEX route plan intent")?;
        ensure_non_empty(solver_label, "private DEX route plan solver")?;
        ensure_non_empty(pq_transcript_id, "private DEX route plan PQ transcript")?;
        if pool_ids.is_empty() || asset_path.len() != pool_ids.len().saturating_add(1) {
            return Err("private DEX route path is invalid".to_string());
        }
        if amount_in == 0 || expected_amount_out == 0 {
            return Err("private DEX route amounts must be positive".to_string());
        }
        if worst_case_amount_out > expected_amount_out {
            return Err("private DEX route worst case exceeds expected output".to_string());
        }
        if ttl_blocks == 0 {
            return Err("private DEX route TTL must be positive".to_string());
        }
        let solver_commitment = private_dex_solver_commitment(solver_label);
        let route_commitment = private_dex_route_commitment(&pool_ids, &asset_path);
        let leg_root = private_dex_route_leg_root(&legs);
        let quote_root = private_dex_payload_root(
            "PRIVATE-DEX-ROUTE-QUOTE-ROOT",
            &json!({
                "amount_in": amount_in,
                "expected_amount_out": expected_amount_out,
                "worst_case_amount_out": worst_case_amount_out,
                "total_pool_fee_units": total_pool_fee_units,
                "total_protocol_fee_units": total_protocol_fee_units,
                "aggregate_price_impact_bps": aggregate_price_impact_bps,
                "leg_root": leg_root,
            }),
        );
        let route_id = private_dex_route_plan_id(
            intent_id,
            &solver_commitment,
            &route_commitment,
            amount_in,
            expected_amount_out,
            worst_case_amount_out,
            created_at_height,
        );
        let route = Self {
            route_id,
            intent_id: intent_id.to_string(),
            solver_commitment,
            pool_ids,
            asset_path,
            leg_root,
            quote_root,
            route_commitment,
            amount_in,
            expected_amount_out,
            worst_case_amount_out,
            total_pool_fee_units,
            total_protocol_fee_units,
            aggregate_price_impact_bps,
            created_at_height,
            expires_at_height: created_at_height.saturating_add(ttl_blocks),
            pq_transcript_id: pq_transcript_id.to_string(),
            low_fee_rebate_id: None,
            status: PRIVATE_DEX_STATUS_ACTIVE.to_string(),
            legs,
        };
        route.validate()?;
        Ok(route)
    }

    pub fn validate(&self) -> PrivateDexResult<String> {
        ensure_non_empty(&self.route_id, "private DEX route id")?;
        ensure_non_empty(&self.intent_id, "private DEX route intent")?;
        ensure_non_empty(&self.solver_commitment, "private DEX route solver")?;
        ensure_non_empty(&self.leg_root, "private DEX route leg root")?;
        ensure_non_empty(&self.quote_root, "private DEX route quote root")?;
        ensure_non_empty(&self.route_commitment, "private DEX route commitment")?;
        ensure_non_empty(&self.pq_transcript_id, "private DEX route PQ transcript")?;
        ensure_status(
            &self.status,
            &[
                PRIVATE_DEX_STATUS_ACTIVE,
                PRIVATE_DEX_STATUS_SETTLED,
                PRIVATE_DEX_STATUS_EXPIRED,
                PRIVATE_DEX_STATUS_CANCELLED,
            ],
        )?;
        if self.pool_ids.is_empty()
            || self.asset_path.len() != self.pool_ids.len().saturating_add(1)
        {
            return Err("private DEX route path is invalid".to_string());
        }
        if self.amount_in == 0 || self.expected_amount_out == 0 {
            return Err("private DEX route amounts must be positive".to_string());
        }
        if self.worst_case_amount_out > self.expected_amount_out {
            return Err("private DEX route worst case exceeds expected output".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("private DEX route expiry must be after creation".to_string());
        }
        for leg in &self.legs {
            leg.validate()?;
        }
        let expected_id = private_dex_route_plan_id(
            &self.intent_id,
            &self.solver_commitment,
            &self.route_commitment,
            self.amount_in,
            self.expected_amount_out,
            self.worst_case_amount_out,
            self.created_at_height,
        );
        if self.route_id != expected_id {
            return Err("private DEX route id mismatch".to_string());
        }
        Ok(self.route_id.clone())
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status == PRIVATE_DEX_STATUS_ACTIVE
            && self.created_at_height <= height
            && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_route_plan",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "route_id": self.route_id,
            "intent_id": self.intent_id,
            "solver_commitment": self.solver_commitment,
            "pool_ids": self.pool_ids,
            "asset_path": self.asset_path,
            "leg_root": self.leg_root,
            "quote_root": self.quote_root,
            "route_commitment": self.route_commitment,
            "amount_in": self.amount_in,
            "expected_amount_out": self.expected_amount_out,
            "worst_case_amount_out": self.worst_case_amount_out,
            "total_pool_fee_units": self.total_pool_fee_units,
            "total_protocol_fee_units": self.total_protocol_fee_units,
            "aggregate_price_impact_bps": self.aggregate_price_impact_bps,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "pq_transcript_id": self.pq_transcript_id,
            "low_fee_rebate_id": self.low_fee_rebate_id,
            "status": self.status,
            "legs": self.legs.iter().map(PrivateDexRouteLeg::public_record).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexQuoteReveal {
    pub reveal_id: String,
    pub quote_id: String,
    pub auction_id: String,
    pub solver_commitment: String,
    pub route_id: String,
    pub route_commitment: String,
    pub amount_in: u64,
    pub amount_out: u64,
    pub clearing_price_numerator: u64,
    pub clearing_price_denominator: u64,
    pub solver_fee_units: u64,
    pub surplus_units: u64,
    pub route_plan_root: String,
    pub quote_secret_root: String,
    pub pq_transcript_id: String,
    pub revealed_at_height: u64,
    pub status: String,
}

impl PrivateDexQuoteReveal {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        quote: &PrivateDexSolverQuoteCommitment,
        route: &PrivateDexRoutePlan,
        amount_in: u64,
        amount_out: u64,
        clearing_price_numerator: u64,
        clearing_price_denominator: u64,
        solver_fee_units: u64,
        surplus_units: u64,
        quote_secret: &str,
        revealed_at_height: u64,
    ) -> PrivateDexResult<Self> {
        quote.validate()?;
        route.validate()?;
        ensure_non_empty(quote_secret, "private DEX quote reveal secret")?;
        if amount_in == 0 || amount_out == 0 {
            return Err("private DEX quote reveal amounts must be positive".to_string());
        }
        if clearing_price_denominator == 0 {
            return Err("private DEX quote reveal denominator cannot be zero".to_string());
        }
        if revealed_at_height > quote.reveal_deadline_height {
            return Err("private DEX quote reveal is past deadline".to_string());
        }
        let route_plan_root =
            private_dex_payload_root("PRIVATE-DEX-QUOTE-REVEAL-ROUTE", &route.public_record());
        let quote_secret_root =
            private_dex_string_root("PRIVATE-DEX-QUOTE-REVEAL-SECRET", quote_secret);
        let reveal_id = private_dex_quote_reveal_id(
            &quote.quote_id,
            &quote.solver_commitment,
            &route.route_id,
            &route_plan_root,
            &quote_secret_root,
            revealed_at_height,
        );
        let reveal = Self {
            reveal_id,
            quote_id: quote.quote_id.clone(),
            auction_id: quote.auction_id.clone(),
            solver_commitment: quote.solver_commitment.clone(),
            route_id: route.route_id.clone(),
            route_commitment: route.route_commitment.clone(),
            amount_in,
            amount_out,
            clearing_price_numerator,
            clearing_price_denominator,
            solver_fee_units,
            surplus_units,
            route_plan_root,
            quote_secret_root,
            pq_transcript_id: quote.pq_transcript_id.clone(),
            revealed_at_height,
            status: PRIVATE_DEX_STATUS_REVEALING.to_string(),
        };
        reveal.validate()?;
        Ok(reveal)
    }

    pub fn validate(&self) -> PrivateDexResult<String> {
        ensure_non_empty(&self.reveal_id, "private DEX quote reveal id")?;
        ensure_non_empty(&self.quote_id, "private DEX quote reveal quote")?;
        ensure_non_empty(&self.auction_id, "private DEX quote reveal auction")?;
        ensure_non_empty(&self.solver_commitment, "private DEX quote reveal solver")?;
        ensure_non_empty(&self.route_id, "private DEX quote reveal route")?;
        ensure_non_empty(
            &self.route_commitment,
            "private DEX quote reveal route commitment",
        )?;
        ensure_non_empty(&self.route_plan_root, "private DEX quote reveal route root")?;
        ensure_non_empty(
            &self.quote_secret_root,
            "private DEX quote reveal secret root",
        )?;
        ensure_non_empty(
            &self.pq_transcript_id,
            "private DEX quote reveal transcript",
        )?;
        ensure_status(
            &self.status,
            &[
                PRIVATE_DEX_STATUS_REVEALING,
                PRIVATE_DEX_STATUS_SETTLED,
                PRIVATE_DEX_STATUS_REJECTED,
            ],
        )?;
        if self.amount_in == 0 || self.amount_out == 0 || self.clearing_price_denominator == 0 {
            return Err("private DEX quote reveal numeric fields are invalid".to_string());
        }
        let expected_id = private_dex_quote_reveal_id(
            &self.quote_id,
            &self.solver_commitment,
            &self.route_id,
            &self.route_plan_root,
            &self.quote_secret_root,
            self.revealed_at_height,
        );
        if self.reveal_id != expected_id {
            return Err("private DEX quote reveal id mismatch".to_string());
        }
        Ok(self.reveal_id.clone())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_quote_reveal",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "reveal_id": self.reveal_id,
            "quote_id": self.quote_id,
            "auction_id": self.auction_id,
            "solver_commitment": self.solver_commitment,
            "route_id": self.route_id,
            "route_commitment": self.route_commitment,
            "amount_in": self.amount_in,
            "amount_out": self.amount_out,
            "clearing_price_numerator": self.clearing_price_numerator,
            "clearing_price_denominator": self.clearing_price_denominator,
            "solver_fee_units": self.solver_fee_units,
            "surplus_units": self.surplus_units,
            "route_plan_root": self.route_plan_root,
            "quote_secret_root": self.quote_secret_root,
            "pq_transcript_id": self.pq_transcript_id,
            "revealed_at_height": self.revealed_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexBatchOrder {
    pub batch_order_id: String,
    pub auction_id: String,
    pub batch_height: u64,
    pub ordering_seed: String,
    pub intent_order_root: String,
    pub quote_order_root: String,
    pub route_order_root: String,
    pub selected_intent_ids: Vec<String>,
    pub selected_quote_ids: Vec<String>,
    pub selected_route_ids: Vec<String>,
    pub tie_breaker_root: String,
    pub fairness_proof_root: String,
    pub status: String,
}

impl PrivateDexBatchOrder {
    pub fn new(
        auction_id: &str,
        batch_height: u64,
        ordering_seed: &str,
        selected_intent_ids: &[String],
        selected_quote_ids: &[String],
        selected_route_ids: &[String],
    ) -> PrivateDexResult<Self> {
        ensure_non_empty(auction_id, "private DEX batch auction")?;
        ensure_non_empty(ordering_seed, "private DEX batch ordering seed")?;
        if selected_intent_ids.is_empty()
            || selected_quote_ids.is_empty()
            || selected_route_ids.is_empty()
        {
            return Err(
                "private DEX batch requires selected intents, quotes, and routes".to_string(),
            );
        }
        let intent_order =
            private_dex_mev_resistant_order(auction_id, ordering_seed, selected_intent_ids);
        let quote_order =
            private_dex_mev_resistant_order(auction_id, ordering_seed, selected_quote_ids);
        let route_order =
            private_dex_mev_resistant_order(auction_id, ordering_seed, selected_route_ids);
        let intent_order_root =
            private_dex_string_set_root("PRIVATE-DEX-BATCH-INTENT-ORDER", &intent_order);
        let quote_order_root =
            private_dex_string_set_root("PRIVATE-DEX-BATCH-QUOTE-ORDER", &quote_order);
        let route_order_root =
            private_dex_string_set_root("PRIVATE-DEX-BATCH-ROUTE-ORDER", &route_order);
        let tie_breaker_root = private_dex_batch_tie_breaker_root(
            auction_id,
            ordering_seed,
            &intent_order,
            &quote_order,
            &route_order,
        );
        let fairness_proof_root = private_dex_payload_root(
            "PRIVATE-DEX-BATCH-FAIRNESS-PROOF",
            &json!({
                "auction_id": auction_id,
                "ordering_seed": ordering_seed,
                "intent_order_root": intent_order_root,
                "quote_order_root": quote_order_root,
                "route_order_root": route_order_root,
                "tie_breaker_root": tie_breaker_root,
                "policy": "commit-reveal deterministic order, no mempool arrival leakage"
            }),
        );
        let batch_order_id = private_dex_batch_order_id(
            auction_id,
            batch_height,
            ordering_seed,
            &intent_order_root,
            &quote_order_root,
            &route_order_root,
        );
        let batch = Self {
            batch_order_id,
            auction_id: auction_id.to_string(),
            batch_height,
            ordering_seed: ordering_seed.to_string(),
            intent_order_root,
            quote_order_root,
            route_order_root,
            selected_intent_ids: intent_order,
            selected_quote_ids: quote_order,
            selected_route_ids: route_order,
            tie_breaker_root,
            fairness_proof_root,
            status: PRIVATE_DEX_STATUS_MATCHING.to_string(),
        };
        batch.validate()?;
        Ok(batch)
    }

    pub fn validate(&self) -> PrivateDexResult<String> {
        ensure_non_empty(&self.batch_order_id, "private DEX batch order id")?;
        ensure_non_empty(&self.auction_id, "private DEX batch auction")?;
        ensure_non_empty(&self.ordering_seed, "private DEX batch ordering seed")?;
        ensure_non_empty(
            &self.intent_order_root,
            "private DEX batch intent order root",
        )?;
        ensure_non_empty(&self.quote_order_root, "private DEX batch quote order root")?;
        ensure_non_empty(&self.route_order_root, "private DEX batch route order root")?;
        ensure_non_empty(&self.tie_breaker_root, "private DEX batch tie breaker root")?;
        ensure_non_empty(
            &self.fairness_proof_root,
            "private DEX batch fairness proof root",
        )?;
        ensure_status(
            &self.status,
            &[PRIVATE_DEX_STATUS_MATCHING, PRIVATE_DEX_STATUS_SETTLED],
        )?;
        if self.selected_intent_ids.is_empty()
            || self.selected_quote_ids.is_empty()
            || self.selected_route_ids.is_empty()
        {
            return Err("private DEX batch selections cannot be empty".to_string());
        }
        let expected_id = private_dex_batch_order_id(
            &self.auction_id,
            self.batch_height,
            &self.ordering_seed,
            &self.intent_order_root,
            &self.quote_order_root,
            &self.route_order_root,
        );
        if self.batch_order_id != expected_id {
            return Err("private DEX batch order id mismatch".to_string());
        }
        Ok(self.batch_order_id.clone())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_batch_order",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "batch_order_id": self.batch_order_id,
            "auction_id": self.auction_id,
            "batch_height": self.batch_height,
            "ordering_seed": self.ordering_seed,
            "intent_order_root": self.intent_order_root,
            "quote_order_root": self.quote_order_root,
            "route_order_root": self.route_order_root,
            "selected_intent_ids": self.selected_intent_ids,
            "selected_quote_ids": self.selected_quote_ids,
            "selected_route_ids": self.selected_route_ids,
            "tie_breaker_root": self.tie_breaker_root,
            "fairness_proof_root": self.fairness_proof_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexClearingPrice {
    pub clearing_price_id: String,
    pub auction_id: String,
    pub pair_id: String,
    pub price_numerator: u64,
    pub price_denominator: u64,
    pub total_input_units: u64,
    pub total_output_units: u64,
    pub filled_intent_count: u64,
    pub rejected_intent_count: u64,
    pub solver_commitment: String,
    pub route_root: String,
    pub surplus_commitment_root: String,
}

impl PrivateDexClearingPrice {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: &str,
        pair_id: &str,
        price_numerator: u64,
        price_denominator: u64,
        total_input_units: u64,
        total_output_units: u64,
        filled_intent_count: u64,
        rejected_intent_count: u64,
        solver_commitment: &str,
        route_ids: &[String],
        surplus_commitments: &[String],
    ) -> PrivateDexResult<Self> {
        ensure_non_empty(auction_id, "private DEX clearing auction")?;
        ensure_non_empty(pair_id, "private DEX clearing pair")?;
        ensure_non_empty(solver_commitment, "private DEX clearing solver")?;
        if price_denominator == 0 || price_numerator == 0 {
            return Err("private DEX clearing price must be positive".to_string());
        }
        if total_input_units == 0 || total_output_units == 0 || filled_intent_count == 0 {
            return Err("private DEX clearing totals must be positive".to_string());
        }
        let route_root = private_dex_string_set_root("PRIVATE-DEX-CLEARING-ROUTES", route_ids);
        let surplus_commitment_root =
            private_dex_string_set_root("PRIVATE-DEX-CLEARING-SURPLUS", surplus_commitments);
        let clearing_price_id = private_dex_clearing_price_id(
            auction_id,
            pair_id,
            price_numerator,
            price_denominator,
            total_input_units,
            total_output_units,
            solver_commitment,
            &route_root,
        );
        let clearing = Self {
            clearing_price_id,
            auction_id: auction_id.to_string(),
            pair_id: pair_id.to_string(),
            price_numerator,
            price_denominator,
            total_input_units,
            total_output_units,
            filled_intent_count,
            rejected_intent_count,
            solver_commitment: solver_commitment.to_string(),
            route_root,
            surplus_commitment_root,
        };
        clearing.validate()?;
        Ok(clearing)
    }

    pub fn validate(&self) -> PrivateDexResult<String> {
        ensure_non_empty(&self.clearing_price_id, "private DEX clearing price id")?;
        ensure_non_empty(&self.auction_id, "private DEX clearing auction")?;
        ensure_non_empty(&self.pair_id, "private DEX clearing pair")?;
        ensure_non_empty(&self.solver_commitment, "private DEX clearing solver")?;
        ensure_non_empty(&self.route_root, "private DEX clearing route root")?;
        ensure_non_empty(
            &self.surplus_commitment_root,
            "private DEX clearing surplus root",
        )?;
        if self.price_denominator == 0 || self.price_numerator == 0 {
            return Err("private DEX clearing price must be positive".to_string());
        }
        if self.total_input_units == 0
            || self.total_output_units == 0
            || self.filled_intent_count == 0
        {
            return Err("private DEX clearing totals must be positive".to_string());
        }
        let expected_id = private_dex_clearing_price_id(
            &self.auction_id,
            &self.pair_id,
            self.price_numerator,
            self.price_denominator,
            self.total_input_units,
            self.total_output_units,
            &self.solver_commitment,
            &self.route_root,
        );
        if self.clearing_price_id != expected_id {
            return Err("private DEX clearing price id mismatch".to_string());
        }
        Ok(self.clearing_price_id.clone())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_clearing_price",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "clearing_price_id": self.clearing_price_id,
            "auction_id": self.auction_id,
            "pair_id": self.pair_id,
            "price_numerator": self.price_numerator,
            "price_denominator": self.price_denominator,
            "total_input_units": self.total_input_units,
            "total_output_units": self.total_output_units,
            "filled_intent_count": self.filled_intent_count,
            "rejected_intent_count": self.rejected_intent_count,
            "solver_commitment": self.solver_commitment,
            "route_root": self.route_root,
            "surplus_commitment_root": self.surplus_commitment_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexSettlementFill {
    pub fill_id: String,
    pub intent_id: String,
    pub quote_id: String,
    pub route_id: String,
    pub solver_commitment: String,
    pub input_nullifier_commitment: String,
    pub output_note_commitment: String,
    pub refund_note_commitment: String,
    pub fee_commitment: String,
    pub surplus_commitment: String,
    pub amount_in_bucket: u64,
    pub amount_out_bucket: u64,
    pub route_hint_id: String,
    pub monero_view_tag_root: String,
}

impl PrivateDexSettlementFill {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_id: &str,
        quote_id: &str,
        route_id: &str,
        solver_commitment: &str,
        input_nullifier_label: &str,
        output_note_label: &str,
        refund_note_label: &str,
        fee_units: u64,
        surplus_units: u64,
        amount_in_units: u64,
        amount_out_units: u64,
        route_hint_id: &str,
        monero_view_tag_label: &str,
    ) -> PrivateDexResult<Self> {
        ensure_non_empty(intent_id, "private DEX settlement fill intent")?;
        ensure_non_empty(quote_id, "private DEX settlement fill quote")?;
        ensure_non_empty(route_id, "private DEX settlement fill route")?;
        ensure_non_empty(solver_commitment, "private DEX settlement fill solver")?;
        ensure_non_empty(
            input_nullifier_label,
            "private DEX settlement fill input nullifier",
        )?;
        ensure_non_empty(output_note_label, "private DEX settlement fill output note")?;
        ensure_non_empty(route_hint_id, "private DEX settlement fill route hint")?;
        ensure_non_empty(
            monero_view_tag_label,
            "private DEX settlement fill Monero view tag",
        )?;
        if amount_in_units == 0 || amount_out_units == 0 {
            return Err("private DEX settlement fill amounts must be positive".to_string());
        }
        let input_nullifier_commitment =
            private_dex_nullifier_hash(input_nullifier_label, amount_in_units, "settlement");
        let output_note_commitment = private_dex_note_commitment(output_note_label);
        let refund_note_commitment = if refund_note_label.is_empty() {
            private_dex_string_root("PRIVATE-DEX-EMPTY-REFUND", intent_id)
        } else {
            private_dex_note_commitment(refund_note_label)
        };
        let fee_commitment = private_dex_amount_commitment(
            fee_units,
            &private_dex_blinding(intent_id, fee_units, "fee"),
        );
        let surplus_commitment = private_dex_amount_commitment(
            surplus_units,
            &private_dex_blinding(intent_id, surplus_units, "surplus"),
        );
        let amount_in_bucket = private_dex_amount_bucket(amount_in_units);
        let amount_out_bucket = private_dex_amount_bucket(amount_out_units);
        let monero_view_tag_root =
            private_dex_string_root("PRIVATE-DEX-MONERO-VIEW-TAG", monero_view_tag_label);
        let fill_id = private_dex_settlement_fill_id(
            intent_id,
            quote_id,
            route_id,
            solver_commitment,
            &input_nullifier_commitment,
            &output_note_commitment,
            &fee_commitment,
        );
        let fill = Self {
            fill_id,
            intent_id: intent_id.to_string(),
            quote_id: quote_id.to_string(),
            route_id: route_id.to_string(),
            solver_commitment: solver_commitment.to_string(),
            input_nullifier_commitment,
            output_note_commitment,
            refund_note_commitment,
            fee_commitment,
            surplus_commitment,
            amount_in_bucket,
            amount_out_bucket,
            route_hint_id: route_hint_id.to_string(),
            monero_view_tag_root,
        };
        fill.validate()?;
        Ok(fill)
    }

    pub fn validate(&self) -> PrivateDexResult<String> {
        ensure_non_empty(&self.fill_id, "private DEX settlement fill id")?;
        ensure_non_empty(&self.intent_id, "private DEX settlement fill intent")?;
        ensure_non_empty(&self.quote_id, "private DEX settlement fill quote")?;
        ensure_non_empty(&self.route_id, "private DEX settlement fill route")?;
        ensure_non_empty(
            &self.solver_commitment,
            "private DEX settlement fill solver",
        )?;
        ensure_non_empty(
            &self.input_nullifier_commitment,
            "private DEX settlement fill input nullifier",
        )?;
        ensure_non_empty(
            &self.output_note_commitment,
            "private DEX settlement fill output note",
        )?;
        ensure_non_empty(
            &self.refund_note_commitment,
            "private DEX settlement fill refund note",
        )?;
        ensure_non_empty(&self.fee_commitment, "private DEX settlement fill fee")?;
        ensure_non_empty(
            &self.surplus_commitment,
            "private DEX settlement fill surplus",
        )?;
        ensure_non_empty(
            &self.route_hint_id,
            "private DEX settlement fill route hint",
        )?;
        ensure_non_empty(
            &self.monero_view_tag_root,
            "private DEX settlement fill Monero view tag",
        )?;
        if self.amount_in_bucket == 0 || self.amount_out_bucket == 0 {
            return Err("private DEX settlement fill amount buckets must be positive".to_string());
        }
        let expected_id = private_dex_settlement_fill_id(
            &self.intent_id,
            &self.quote_id,
            &self.route_id,
            &self.solver_commitment,
            &self.input_nullifier_commitment,
            &self.output_note_commitment,
            &self.fee_commitment,
        );
        if self.fill_id != expected_id {
            return Err("private DEX settlement fill id mismatch".to_string());
        }
        Ok(self.fill_id.clone())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_settlement_fill",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "fill_id": self.fill_id,
            "intent_id": self.intent_id,
            "quote_id": self.quote_id,
            "route_id": self.route_id,
            "solver_commitment": self.solver_commitment,
            "input_nullifier_commitment": self.input_nullifier_commitment,
            "output_note_commitment": self.output_note_commitment,
            "refund_note_commitment": self.refund_note_commitment,
            "fee_commitment": self.fee_commitment,
            "surplus_commitment": self.surplus_commitment,
            "amount_in_bucket": self.amount_in_bucket,
            "amount_out_bucket": self.amount_out_bucket,
            "route_hint_id": self.route_hint_id,
            "monero_view_tag_root": self.monero_view_tag_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexSettlementManifest {
    pub manifest_id: String,
    pub auction_id: String,
    pub batch_order_id: String,
    pub clearing_price_id: String,
    pub winning_solver_commitment: String,
    pub fill_root: String,
    pub route_root: String,
    pub pool_delta_root: String,
    pub note_output_root: String,
    pub surplus_root: String,
    pub low_fee_rebate_root: String,
    pub monero_anchor_root: String,
    pub validity_proof_root: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub settlement_height: u64,
    pub finality_height: u64,
    pub status: String,
    pub fills: Vec<PrivateDexSettlementFill>,
}

impl PrivateDexSettlementManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: &str,
        batch_order_id: &str,
        clearing_price_id: &str,
        winning_solver_commitment: &str,
        fills: Vec<PrivateDexSettlementFill>,
        route_ids: &[String],
        pool_delta_records: &[Value],
        note_outputs: &[Value],
        surplus_commitments: &[String],
        low_fee_rebate_records: &[Value],
        monero_anchor: &PrivateDexMoneroAnchor,
        validity_proof_ids: &[String],
        pre_state_root: &str,
        post_state_root: &str,
        settlement_height: u64,
        finality_height: u64,
    ) -> PrivateDexResult<Self> {
        ensure_non_empty(auction_id, "private DEX settlement auction")?;
        ensure_non_empty(batch_order_id, "private DEX settlement batch")?;
        ensure_non_empty(clearing_price_id, "private DEX settlement clearing price")?;
        ensure_non_empty(winning_solver_commitment, "private DEX settlement solver")?;
        ensure_non_empty(pre_state_root, "private DEX settlement pre state root")?;
        ensure_non_empty(post_state_root, "private DEX settlement post state root")?;
        if fills.is_empty() {
            return Err("private DEX settlement requires at least one fill".to_string());
        }
        if finality_height < settlement_height {
            return Err("private DEX settlement finality height is invalid".to_string());
        }
        for fill in &fills {
            fill.validate()?;
        }
        let fill_root = private_dex_settlement_fill_root(&fills);
        let route_root = private_dex_string_set_root("PRIVATE-DEX-SETTLEMENT-ROUTES", route_ids);
        let pool_delta_root = merkle_root("PRIVATE-DEX-SETTLEMENT-POOL-DELTAS", pool_delta_records);
        let note_output_root = merkle_root("PRIVATE-DEX-SETTLEMENT-NOTE-OUTPUTS", note_outputs);
        let surplus_root =
            private_dex_string_set_root("PRIVATE-DEX-SETTLEMENT-SURPLUS", surplus_commitments);
        let low_fee_rebate_root = merkle_root(
            "PRIVATE-DEX-SETTLEMENT-LOW-FEE-REBATES",
            low_fee_rebate_records,
        );
        let monero_anchor_root = monero_anchor.anchor_root();
        let validity_proof_root = private_dex_string_set_root(
            "PRIVATE-DEX-SETTLEMENT-VALIDITY-PROOFS",
            validity_proof_ids,
        );
        let manifest_id = private_dex_settlement_manifest_id(
            auction_id,
            batch_order_id,
            clearing_price_id,
            winning_solver_commitment,
            &fill_root,
            settlement_height,
        );
        let manifest = Self {
            manifest_id,
            auction_id: auction_id.to_string(),
            batch_order_id: batch_order_id.to_string(),
            clearing_price_id: clearing_price_id.to_string(),
            winning_solver_commitment: winning_solver_commitment.to_string(),
            fill_root,
            route_root,
            pool_delta_root,
            note_output_root,
            surplus_root,
            low_fee_rebate_root,
            monero_anchor_root,
            validity_proof_root,
            pre_state_root: pre_state_root.to_string(),
            post_state_root: post_state_root.to_string(),
            settlement_height,
            finality_height,
            status: PRIVATE_DEX_STATUS_SETTLED.to_string(),
            fills,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> PrivateDexResult<String> {
        ensure_non_empty(&self.manifest_id, "private DEX settlement manifest id")?;
        ensure_non_empty(&self.auction_id, "private DEX settlement auction")?;
        ensure_non_empty(&self.batch_order_id, "private DEX settlement batch")?;
        ensure_non_empty(
            &self.clearing_price_id,
            "private DEX settlement clearing price",
        )?;
        ensure_non_empty(
            &self.winning_solver_commitment,
            "private DEX settlement solver",
        )?;
        ensure_non_empty(&self.fill_root, "private DEX settlement fill root")?;
        ensure_non_empty(&self.route_root, "private DEX settlement route root")?;
        ensure_non_empty(
            &self.pool_delta_root,
            "private DEX settlement pool delta root",
        )?;
        ensure_non_empty(
            &self.note_output_root,
            "private DEX settlement note output root",
        )?;
        ensure_non_empty(&self.surplus_root, "private DEX settlement surplus root")?;
        ensure_non_empty(
            &self.low_fee_rebate_root,
            "private DEX settlement rebate root",
        )?;
        ensure_non_empty(
            &self.monero_anchor_root,
            "private DEX settlement Monero anchor root",
        )?;
        ensure_non_empty(
            &self.validity_proof_root,
            "private DEX settlement validity proof root",
        )?;
        ensure_non_empty(
            &self.pre_state_root,
            "private DEX settlement pre state root",
        )?;
        ensure_non_empty(
            &self.post_state_root,
            "private DEX settlement post state root",
        )?;
        ensure_status(
            &self.status,
            &[PRIVATE_DEX_STATUS_SETTLED, PRIVATE_DEX_STATUS_REJECTED],
        )?;
        if self.fills.is_empty() {
            return Err("private DEX settlement fills cannot be empty".to_string());
        }
        for fill in &self.fills {
            fill.validate()?;
        }
        if self.finality_height < self.settlement_height {
            return Err("private DEX settlement finality height is invalid".to_string());
        }
        let expected_id = private_dex_settlement_manifest_id(
            &self.auction_id,
            &self.batch_order_id,
            &self.clearing_price_id,
            &self.winning_solver_commitment,
            &self.fill_root,
            self.settlement_height,
        );
        if self.manifest_id != expected_id {
            return Err("private DEX settlement manifest id mismatch".to_string());
        }
        Ok(self.manifest_id.clone())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_settlement_manifest",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "manifest_id": self.manifest_id,
            "auction_id": self.auction_id,
            "batch_order_id": self.batch_order_id,
            "clearing_price_id": self.clearing_price_id,
            "winning_solver_commitment": self.winning_solver_commitment,
            "fill_root": self.fill_root,
            "route_root": self.route_root,
            "pool_delta_root": self.pool_delta_root,
            "note_output_root": self.note_output_root,
            "surplus_root": self.surplus_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "monero_anchor_root": self.monero_anchor_root,
            "validity_proof_root": self.validity_proof_root,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "settlement_height": self.settlement_height,
            "finality_height": self.finality_height,
            "status": self.status,
            "fills": self.fills.iter().map(PrivateDexSettlementFill::public_record).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexTwapObservation {
    pub observation_id: String,
    pub pool_id: String,
    pub block_height: u64,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub price_x_to_y_scaled: u64,
    pub price_y_to_x_scaled: u64,
    pub liquidity_units: u64,
    pub sample_root: String,
}

impl PrivateDexTwapObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool_id: &str,
        block_height: u64,
        window_start_height: u64,
        window_end_height: u64,
        price_x_to_y_scaled: u64,
        price_y_to_x_scaled: u64,
        liquidity_units: u64,
        samples: &[Value],
    ) -> PrivateDexResult<Self> {
        ensure_non_empty(pool_id, "private DEX TWAP pool")?;
        if window_end_height <= window_start_height || block_height < window_end_height {
            return Err("private DEX TWAP height window is invalid".to_string());
        }
        if price_x_to_y_scaled == 0 || price_y_to_x_scaled == 0 || liquidity_units == 0 {
            return Err("private DEX TWAP numeric values must be positive".to_string());
        }
        let sample_root = merkle_root("PRIVATE-DEX-TWAP-SAMPLES", samples);
        let observation_id = private_dex_twap_observation_id(
            pool_id,
            block_height,
            window_start_height,
            window_end_height,
            price_x_to_y_scaled,
            price_y_to_x_scaled,
        );
        let observation = Self {
            observation_id,
            pool_id: pool_id.to_string(),
            block_height,
            window_start_height,
            window_end_height,
            price_x_to_y_scaled,
            price_y_to_x_scaled,
            liquidity_units,
            sample_root,
        };
        observation.validate()?;
        Ok(observation)
    }

    pub fn validate(&self) -> PrivateDexResult<String> {
        ensure_non_empty(&self.observation_id, "private DEX TWAP observation id")?;
        ensure_non_empty(&self.pool_id, "private DEX TWAP pool")?;
        ensure_non_empty(&self.sample_root, "private DEX TWAP sample root")?;
        if self.window_end_height <= self.window_start_height
            || self.block_height < self.window_end_height
        {
            return Err("private DEX TWAP height window is invalid".to_string());
        }
        if self.price_x_to_y_scaled == 0
            || self.price_y_to_x_scaled == 0
            || self.liquidity_units == 0
        {
            return Err("private DEX TWAP numeric values must be positive".to_string());
        }
        let expected_id = private_dex_twap_observation_id(
            &self.pool_id,
            self.block_height,
            self.window_start_height,
            self.window_end_height,
            self.price_x_to_y_scaled,
            self.price_y_to_x_scaled,
        );
        if self.observation_id != expected_id {
            return Err("private DEX TWAP observation id mismatch".to_string());
        }
        Ok(self.observation_id.clone())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_twap_observation",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "observation_id": self.observation_id,
            "pool_id": self.pool_id,
            "block_height": self.block_height,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "price_x_to_y_scaled": self.price_x_to_y_scaled,
            "price_y_to_x_scaled": self.price_y_to_x_scaled,
            "liquidity_units": self.liquidity_units,
            "sample_root": self.sample_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexOracleGuard {
    pub guard_id: String,
    pub pool_id: String,
    pub oracle_feed_id: String,
    pub reference_price_scaled: u64,
    pub twap_price_scaled: u64,
    pub deviation_bps: u64,
    pub max_deviation_bps: u64,
    pub last_oracle_height: u64,
    pub last_twap_height: u64,
    pub max_staleness_blocks: u64,
    pub evidence_root: String,
    pub status: String,
}

impl PrivateDexOracleGuard {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool_id: &str,
        oracle_feed_id: &str,
        reference_price_scaled: u64,
        twap_price_scaled: u64,
        max_deviation_bps: u64,
        last_oracle_height: u64,
        last_twap_height: u64,
        max_staleness_blocks: u64,
        evidence: &[Value],
    ) -> PrivateDexResult<Self> {
        ensure_non_empty(pool_id, "private DEX oracle guard pool")?;
        ensure_non_empty(oracle_feed_id, "private DEX oracle feed")?;
        if reference_price_scaled == 0 || twap_price_scaled == 0 {
            return Err("private DEX oracle prices must be positive".to_string());
        }
        validate_bps("oracle guard max_deviation_bps", max_deviation_bps)?;
        if max_staleness_blocks == 0 {
            return Err("private DEX oracle max staleness must be positive".to_string());
        }
        let deviation_bps = ratio_delta_bps(reference_price_scaled, twap_price_scaled);
        let evidence_root = merkle_root("PRIVATE-DEX-ORACLE-GUARD-EVIDENCE", evidence);
        let guard_id = private_dex_oracle_guard_id(
            pool_id,
            oracle_feed_id,
            reference_price_scaled,
            twap_price_scaled,
            max_deviation_bps,
            last_oracle_height,
            last_twap_height,
            &evidence_root,
        );
        let guard = Self {
            guard_id,
            pool_id: pool_id.to_string(),
            oracle_feed_id: oracle_feed_id.to_string(),
            reference_price_scaled,
            twap_price_scaled,
            deviation_bps,
            max_deviation_bps,
            last_oracle_height,
            last_twap_height,
            max_staleness_blocks,
            evidence_root,
            status: if deviation_bps <= max_deviation_bps {
                PRIVATE_DEX_STATUS_ACTIVE.to_string()
            } else {
                PRIVATE_DEX_STATUS_PAUSED.to_string()
            },
        };
        guard.validate()?;
        Ok(guard)
    }

    pub fn validate(&self) -> PrivateDexResult<String> {
        ensure_non_empty(&self.guard_id, "private DEX oracle guard id")?;
        ensure_non_empty(&self.pool_id, "private DEX oracle guard pool")?;
        ensure_non_empty(&self.oracle_feed_id, "private DEX oracle feed")?;
        ensure_non_empty(&self.evidence_root, "private DEX oracle evidence root")?;
        validate_bps("oracle guard deviation_bps", self.deviation_bps)?;
        validate_bps("oracle guard max_deviation_bps", self.max_deviation_bps)?;
        ensure_status(
            &self.status,
            &[PRIVATE_DEX_STATUS_ACTIVE, PRIVATE_DEX_STATUS_PAUSED],
        )?;
        if self.reference_price_scaled == 0 || self.twap_price_scaled == 0 {
            return Err("private DEX oracle prices must be positive".to_string());
        }
        if self.max_staleness_blocks == 0 {
            return Err("private DEX oracle staleness bound must be positive".to_string());
        }
        let expected_id = private_dex_oracle_guard_id(
            &self.pool_id,
            &self.oracle_feed_id,
            self.reference_price_scaled,
            self.twap_price_scaled,
            self.max_deviation_bps,
            self.last_oracle_height,
            self.last_twap_height,
            &self.evidence_root,
        );
        if self.guard_id != expected_id {
            return Err("private DEX oracle guard id mismatch".to_string());
        }
        Ok(self.guard_id.clone())
    }

    pub fn stale_at(&self, height: u64) -> bool {
        height.saturating_sub(self.last_oracle_height) > self.max_staleness_blocks
            || height.saturating_sub(self.last_twap_height) > self.max_staleness_blocks
    }

    pub fn allows_trading_at(&self, height: u64) -> bool {
        self.status == PRIVATE_DEX_STATUS_ACTIVE
            && self.deviation_bps <= self.max_deviation_bps
            && !self.stale_at(height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_oracle_guard",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "guard_id": self.guard_id,
            "pool_id": self.pool_id,
            "oracle_feed_id": self.oracle_feed_id,
            "reference_price_scaled": self.reference_price_scaled,
            "twap_price_scaled": self.twap_price_scaled,
            "deviation_bps": self.deviation_bps,
            "max_deviation_bps": self.max_deviation_bps,
            "last_oracle_height": self.last_oracle_height,
            "last_twap_height": self.last_twap_height,
            "max_staleness_blocks": self.max_staleness_blocks,
            "evidence_root": self.evidence_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexRiskControl {
    pub control_id: String,
    pub scope: PrivateDexSwitchScope,
    pub target_id: String,
    pub mode: PrivateDexRiskMode,
    pub max_trade_units: u64,
    pub max_trade_bps_of_pool: u64,
    pub max_price_impact_bps: u64,
    pub min_liquidity_units: u64,
    pub volume_window_blocks: u64,
    pub volume_cap_units: u64,
    pub triggered_volume_units: u64,
    pub active_from_height: Option<u64>,
    pub active_until_height: Option<u64>,
    pub reason_root: String,
}

impl PrivateDexRiskControl {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: PrivateDexSwitchScope,
        target_id: impl Into<String>,
        mode: PrivateDexRiskMode,
        max_trade_units: u64,
        max_trade_bps_of_pool: u64,
        max_price_impact_bps: u64,
        min_liquidity_units: u64,
        volume_window_blocks: u64,
        volume_cap_units: u64,
        triggered_volume_units: u64,
        active_from_height: Option<u64>,
        active_until_height: Option<u64>,
        reason: &Value,
    ) -> PrivateDexResult<Self> {
        let target_id = target_id.into();
        ensure_non_empty(&target_id, "private DEX risk control target")?;
        validate_bps("risk max_trade_bps_of_pool", max_trade_bps_of_pool)?;
        validate_bps("risk max_price_impact_bps", max_price_impact_bps)?;
        if let (Some(start), Some(end)) = (active_from_height, active_until_height) {
            if end <= start {
                return Err("private DEX risk active window is invalid".to_string());
            }
        }
        let reason_root = private_dex_payload_root("PRIVATE-DEX-RISK-REASON", reason);
        let control_id = private_dex_risk_control_id(
            scope,
            &target_id,
            mode,
            max_trade_units,
            max_trade_bps_of_pool,
            max_price_impact_bps,
            min_liquidity_units,
            volume_window_blocks,
            volume_cap_units,
            &reason_root,
        );
        let control = Self {
            control_id,
            scope,
            target_id,
            mode,
            max_trade_units,
            max_trade_bps_of_pool,
            max_price_impact_bps,
            min_liquidity_units,
            volume_window_blocks,
            volume_cap_units,
            triggered_volume_units,
            active_from_height,
            active_until_height,
            reason_root,
        };
        control.validate()?;
        Ok(control)
    }

    pub fn validate(&self) -> PrivateDexResult<String> {
        ensure_non_empty(&self.control_id, "private DEX risk control id")?;
        ensure_non_empty(&self.target_id, "private DEX risk control target")?;
        ensure_non_empty(&self.reason_root, "private DEX risk reason root")?;
        validate_bps("risk max_trade_bps_of_pool", self.max_trade_bps_of_pool)?;
        validate_bps("risk max_price_impact_bps", self.max_price_impact_bps)?;
        if let (Some(start), Some(end)) = (self.active_from_height, self.active_until_height) {
            if end <= start {
                return Err("private DEX risk active window is invalid".to_string());
            }
        }
        let expected_id = private_dex_risk_control_id(
            self.scope,
            &self.target_id,
            self.mode,
            self.max_trade_units,
            self.max_trade_bps_of_pool,
            self.max_price_impact_bps,
            self.min_liquidity_units,
            self.volume_window_blocks,
            self.volume_cap_units,
            &self.reason_root,
        );
        if self.control_id != expected_id {
            return Err("private DEX risk control id mismatch".to_string());
        }
        Ok(self.control_id.clone())
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.active_from_height
            .map_or(true, |start| height >= start)
            && self.active_until_height.map_or(true, |end| height <= end)
    }

    pub fn applies_to_pool(&self, pool_id: &str) -> bool {
        self.scope == PrivateDexSwitchScope::Global
            || (self.scope == PrivateDexSwitchScope::Pool && self.target_id == pool_id)
    }

    pub fn applies_to_pair(&self, pair_id: &str) -> bool {
        self.scope == PrivateDexSwitchScope::Global
            || (self.scope == PrivateDexSwitchScope::Pair && self.target_id == pair_id)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_risk_control",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "control_id": self.control_id,
            "scope": self.scope.as_str(),
            "target_id": self.target_id,
            "mode": self.mode.as_str(),
            "max_trade_units": self.max_trade_units,
            "max_trade_bps_of_pool": self.max_trade_bps_of_pool,
            "max_price_impact_bps": self.max_price_impact_bps,
            "min_liquidity_units": self.min_liquidity_units,
            "volume_window_blocks": self.volume_window_blocks,
            "volume_cap_units": self.volume_cap_units,
            "triggered_volume_units": self.triggered_volume_units,
            "active_from_height": self.active_from_height,
            "active_until_height": self.active_until_height,
            "reason_root": self.reason_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexLowFeeRebate {
    pub rebate_id: String,
    pub route_id: String,
    pub auction_id: String,
    pub lane_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub gross_fee_units: u64,
    pub eligible_fee_units: u64,
    pub rebate_bps: u64,
    pub rebate_units: u64,
    pub bond_id: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl PrivateDexLowFeeRebate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        route_id: &str,
        auction_id: &str,
        lane_id: &str,
        sponsor_label: &str,
        fee_asset_id: &str,
        gross_fee_units: u64,
        eligible_fee_units: u64,
        rebate_bps: u64,
        max_rebate_units: u64,
        bond_id: &str,
        created_at_height: u64,
        ttl_blocks: u64,
    ) -> PrivateDexResult<Self> {
        ensure_non_empty(route_id, "private DEX low fee rebate route")?;
        ensure_non_empty(auction_id, "private DEX low fee rebate auction")?;
        ensure_non_empty(lane_id, "private DEX low fee rebate lane")?;
        ensure_non_empty(sponsor_label, "private DEX low fee rebate sponsor")?;
        ensure_non_empty(fee_asset_id, "private DEX low fee rebate fee asset")?;
        ensure_non_empty(bond_id, "private DEX low fee rebate bond")?;
        validate_bps("low fee rebate_bps", rebate_bps)?;
        if ttl_blocks == 0 {
            return Err("private DEX low fee rebate TTL must be positive".to_string());
        }
        let sponsor_commitment = private_dex_account_commitment(sponsor_label);
        let rebate_units = bps_mul_floor(eligible_fee_units, rebate_bps).min(max_rebate_units);
        let rebate_id = private_dex_low_fee_rebate_id(
            route_id,
            auction_id,
            lane_id,
            &sponsor_commitment,
            fee_asset_id,
            gross_fee_units,
            eligible_fee_units,
            rebate_bps,
            created_at_height,
        );
        let rebate = Self {
            rebate_id,
            route_id: route_id.to_string(),
            auction_id: auction_id.to_string(),
            lane_id: lane_id.to_string(),
            sponsor_commitment,
            fee_asset_id: fee_asset_id.to_string(),
            gross_fee_units,
            eligible_fee_units,
            rebate_bps,
            rebate_units,
            bond_id: bond_id.to_string(),
            created_at_height,
            expires_at_height: created_at_height.saturating_add(ttl_blocks),
            status: PRIVATE_DEX_STATUS_ACTIVE.to_string(),
        };
        rebate.validate()?;
        Ok(rebate)
    }

    pub fn validate(&self) -> PrivateDexResult<String> {
        ensure_non_empty(&self.rebate_id, "private DEX low fee rebate id")?;
        ensure_non_empty(&self.route_id, "private DEX low fee rebate route")?;
        ensure_non_empty(&self.auction_id, "private DEX low fee rebate auction")?;
        ensure_non_empty(&self.lane_id, "private DEX low fee rebate lane")?;
        ensure_non_empty(
            &self.sponsor_commitment,
            "private DEX low fee rebate sponsor",
        )?;
        ensure_non_empty(&self.fee_asset_id, "private DEX low fee rebate fee asset")?;
        ensure_non_empty(&self.bond_id, "private DEX low fee rebate bond")?;
        validate_bps("low fee rebate_bps", self.rebate_bps)?;
        ensure_status(
            &self.status,
            &[
                PRIVATE_DEX_STATUS_ACTIVE,
                PRIVATE_DEX_STATUS_SETTLED,
                PRIVATE_DEX_STATUS_EXPIRED,
                PRIVATE_DEX_STATUS_CANCELLED,
            ],
        )?;
        if self.expires_at_height <= self.created_at_height {
            return Err("private DEX low fee rebate expiry must be after creation".to_string());
        }
        if self.eligible_fee_units > self.gross_fee_units {
            return Err("private DEX low fee eligible fee exceeds gross fee".to_string());
        }
        let expected_id = private_dex_low_fee_rebate_id(
            &self.route_id,
            &self.auction_id,
            &self.lane_id,
            &self.sponsor_commitment,
            &self.fee_asset_id,
            self.gross_fee_units,
            self.eligible_fee_units,
            self.rebate_bps,
            self.created_at_height,
        );
        if self.rebate_id != expected_id {
            return Err("private DEX low fee rebate id mismatch".to_string());
        }
        Ok(self.rebate_id.clone())
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status == PRIVATE_DEX_STATUS_ACTIVE
            && self.created_at_height <= height
            && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_low_fee_rebate",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "rebate_id": self.rebate_id,
            "route_id": self.route_id,
            "auction_id": self.auction_id,
            "lane_id": self.lane_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "gross_fee_units": self.gross_fee_units,
            "eligible_fee_units": self.eligible_fee_units,
            "rebate_bps": self.rebate_bps,
            "rebate_units": self.rebate_units,
            "bond_id": self.bond_id,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexMoneroAnchor {
    pub anchor_id: String,
    pub monero_network: String,
    pub reserve_asset_id: String,
    pub view_key_commitment: String,
    pub txid_root: String,
    pub output_commitment_root: String,
    pub key_image_root: String,
    pub ring_member_root: String,
    pub reserve_proof_root: String,
    pub pq_transcript_id: String,
    pub observed_height: u64,
    pub finality_depth: u64,
    pub status: String,
}

impl PrivateDexMoneroAnchor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        monero_network: &str,
        reserve_asset_id: &str,
        view_key_label: &str,
        txids: &[String],
        output_commitments: &[String],
        key_images: &[String],
        ring_members: &[Value],
        reserve_proof: &Value,
        pq_transcript_id: &str,
        observed_height: u64,
        finality_depth: u64,
    ) -> PrivateDexResult<Self> {
        ensure_non_empty(monero_network, "private DEX Monero network")?;
        ensure_non_empty(reserve_asset_id, "private DEX Monero reserve asset")?;
        ensure_non_empty(view_key_label, "private DEX Monero view key")?;
        ensure_non_empty(pq_transcript_id, "private DEX Monero anchor PQ transcript")?;
        if finality_depth == 0 {
            return Err("private DEX Monero anchor finality depth must be positive".to_string());
        }
        let view_key_commitment =
            private_dex_string_root("PRIVATE-DEX-MONERO-VIEW-KEY", view_key_label);
        let txid_root = private_dex_string_set_root("PRIVATE-DEX-MONERO-TXIDS", txids);
        let output_commitment_root = private_dex_string_set_root(
            "PRIVATE-DEX-MONERO-OUTPUT-COMMITMENTS",
            output_commitments,
        );
        let key_image_root =
            private_dex_string_set_root("PRIVATE-DEX-MONERO-KEY-IMAGES", key_images);
        let ring_member_root = merkle_root("PRIVATE-DEX-MONERO-RING-MEMBERS", ring_members);
        let reserve_proof_root =
            private_dex_payload_root("PRIVATE-DEX-MONERO-RESERVE-PROOF", reserve_proof);
        let anchor_id = private_dex_monero_anchor_id(
            monero_network,
            reserve_asset_id,
            &view_key_commitment,
            &txid_root,
            &output_commitment_root,
            &key_image_root,
            &reserve_proof_root,
            observed_height,
        );
        let anchor = Self {
            anchor_id,
            monero_network: monero_network.to_string(),
            reserve_asset_id: reserve_asset_id.to_string(),
            view_key_commitment,
            txid_root,
            output_commitment_root,
            key_image_root,
            ring_member_root,
            reserve_proof_root,
            pq_transcript_id: pq_transcript_id.to_string(),
            observed_height,
            finality_depth,
            status: PRIVATE_DEX_STATUS_ACTIVE.to_string(),
        };
        anchor.validate()?;
        Ok(anchor)
    }

    pub fn validate(&self) -> PrivateDexResult<String> {
        ensure_non_empty(&self.anchor_id, "private DEX Monero anchor id")?;
        ensure_non_empty(&self.monero_network, "private DEX Monero network")?;
        ensure_non_empty(&self.reserve_asset_id, "private DEX Monero reserve asset")?;
        ensure_non_empty(&self.view_key_commitment, "private DEX Monero view key")?;
        ensure_non_empty(&self.txid_root, "private DEX Monero txid root")?;
        ensure_non_empty(
            &self.output_commitment_root,
            "private DEX Monero output root",
        )?;
        ensure_non_empty(&self.key_image_root, "private DEX Monero key image root")?;
        ensure_non_empty(
            &self.ring_member_root,
            "private DEX Monero ring member root",
        )?;
        ensure_non_empty(&self.reserve_proof_root, "private DEX Monero reserve proof")?;
        ensure_non_empty(&self.pq_transcript_id, "private DEX Monero PQ transcript")?;
        ensure_status(
            &self.status,
            &[
                PRIVATE_DEX_STATUS_ACTIVE,
                PRIVATE_DEX_STATUS_VERIFIED,
                PRIVATE_DEX_STATUS_REJECTED,
            ],
        )?;
        if self.finality_depth == 0 {
            return Err("private DEX Monero anchor finality depth must be positive".to_string());
        }
        let expected_id = private_dex_monero_anchor_id(
            &self.monero_network,
            &self.reserve_asset_id,
            &self.view_key_commitment,
            &self.txid_root,
            &self.output_commitment_root,
            &self.key_image_root,
            &self.reserve_proof_root,
            self.observed_height,
        );
        if self.anchor_id != expected_id {
            return Err("private DEX Monero anchor id mismatch".to_string());
        }
        Ok(self.anchor_id.clone())
    }

    pub fn final_at_height(&self) -> u64 {
        self.observed_height.saturating_add(self.finality_depth)
    }

    pub fn anchor_root(&self) -> String {
        private_dex_payload_root("PRIVATE-DEX-MONERO-ANCHOR-ROOT", &self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_monero_anchor",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "anchor_id": self.anchor_id,
            "monero_network": self.monero_network,
            "reserve_asset_id": self.reserve_asset_id,
            "view_key_commitment": self.view_key_commitment,
            "txid_root": self.txid_root,
            "output_commitment_root": self.output_commitment_root,
            "key_image_root": self.key_image_root,
            "ring_member_root": self.ring_member_root,
            "reserve_proof_root": self.reserve_proof_root,
            "pq_transcript_id": self.pq_transcript_id,
            "observed_height": self.observed_height,
            "finality_depth": self.finality_depth,
            "final_at_height": self.final_at_height(),
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexPauseSwitch {
    pub switch_id: String,
    pub scope: PrivateDexSwitchScope,
    pub target_id: String,
    pub paused: bool,
    pub reason_root: String,
    pub set_by_commitment: String,
    pub set_at_height: u64,
    pub expires_at_height: Option<u64>,
    pub nonce: u64,
}

impl PrivateDexPauseSwitch {
    pub fn new(
        scope: PrivateDexSwitchScope,
        target_id: &str,
        paused: bool,
        reason: &Value,
        set_by_label: &str,
        set_at_height: u64,
        expires_at_height: Option<u64>,
        nonce: u64,
    ) -> PrivateDexResult<Self> {
        ensure_non_empty(target_id, "private DEX pause target")?;
        ensure_non_empty(set_by_label, "private DEX pause setter")?;
        if let Some(expires_at_height) = expires_at_height {
            if expires_at_height <= set_at_height {
                return Err("private DEX pause expiry must be after set height".to_string());
            }
        }
        let reason_root = private_dex_payload_root("PRIVATE-DEX-PAUSE-REASON", reason);
        let set_by_commitment = private_dex_account_commitment(set_by_label);
        let switch_id = private_dex_pause_switch_id(
            scope,
            target_id,
            paused,
            &reason_root,
            &set_by_commitment,
            set_at_height,
            nonce,
        );
        let switch = Self {
            switch_id,
            scope,
            target_id: target_id.to_string(),
            paused,
            reason_root,
            set_by_commitment,
            set_at_height,
            expires_at_height,
            nonce,
        };
        switch.validate()?;
        Ok(switch)
    }

    pub fn validate(&self) -> PrivateDexResult<String> {
        ensure_non_empty(&self.switch_id, "private DEX pause switch id")?;
        ensure_non_empty(&self.target_id, "private DEX pause target")?;
        ensure_non_empty(&self.reason_root, "private DEX pause reason")?;
        ensure_non_empty(&self.set_by_commitment, "private DEX pause setter")?;
        if let Some(expires_at_height) = self.expires_at_height {
            if expires_at_height <= self.set_at_height {
                return Err("private DEX pause expiry must be after set height".to_string());
            }
        }
        let expected_id = private_dex_pause_switch_id(
            self.scope,
            &self.target_id,
            self.paused,
            &self.reason_root,
            &self.set_by_commitment,
            self.set_at_height,
            self.nonce,
        );
        if self.switch_id != expected_id {
            return Err("private DEX pause switch id mismatch".to_string());
        }
        Ok(self.switch_id.clone())
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.paused
            && self.set_at_height <= height
            && self
                .expires_at_height
                .map_or(true, |expires| height <= expires)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_pause_switch",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "switch_id": self.switch_id,
            "scope": self.scope.as_str(),
            "target_id": self.target_id,
            "paused": self.paused,
            "reason_root": self.reason_root,
            "set_by_commitment": self.set_by_commitment,
            "set_at_height": self.set_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexKillSwitch {
    pub kill_id: String,
    pub scope: PrivateDexSwitchScope,
    pub target_id: String,
    pub killed: bool,
    pub requires_governance_unwind: bool,
    pub reason_root: String,
    pub set_by_commitment: String,
    pub set_at_height: u64,
    pub final_state_root: String,
}

impl PrivateDexKillSwitch {
    pub fn new(
        scope: PrivateDexSwitchScope,
        target_id: &str,
        killed: bool,
        requires_governance_unwind: bool,
        reason: &Value,
        set_by_label: &str,
        set_at_height: u64,
        final_state_root: &str,
    ) -> PrivateDexResult<Self> {
        ensure_non_empty(target_id, "private DEX kill target")?;
        ensure_non_empty(set_by_label, "private DEX kill setter")?;
        ensure_non_empty(final_state_root, "private DEX kill final state root")?;
        let reason_root = private_dex_payload_root("PRIVATE-DEX-KILL-REASON", reason);
        let set_by_commitment = private_dex_account_commitment(set_by_label);
        let kill_id = private_dex_kill_switch_id(
            scope,
            target_id,
            killed,
            requires_governance_unwind,
            &reason_root,
            &set_by_commitment,
            set_at_height,
            final_state_root,
        );
        let switch = Self {
            kill_id,
            scope,
            target_id: target_id.to_string(),
            killed,
            requires_governance_unwind,
            reason_root,
            set_by_commitment,
            set_at_height,
            final_state_root: final_state_root.to_string(),
        };
        switch.validate()?;
        Ok(switch)
    }

    pub fn validate(&self) -> PrivateDexResult<String> {
        ensure_non_empty(&self.kill_id, "private DEX kill switch id")?;
        ensure_non_empty(&self.target_id, "private DEX kill target")?;
        ensure_non_empty(&self.reason_root, "private DEX kill reason")?;
        ensure_non_empty(&self.set_by_commitment, "private DEX kill setter")?;
        ensure_non_empty(&self.final_state_root, "private DEX kill final state root")?;
        let expected_id = private_dex_kill_switch_id(
            self.scope,
            &self.target_id,
            self.killed,
            self.requires_governance_unwind,
            &self.reason_root,
            &self.set_by_commitment,
            self.set_at_height,
            &self.final_state_root,
        );
        if self.kill_id != expected_id {
            return Err("private DEX kill switch id mismatch".to_string());
        }
        Ok(self.kill_id.clone())
    }

    pub fn active(&self) -> bool {
        self.killed
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_kill_switch",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "kill_id": self.kill_id,
            "scope": self.scope.as_str(),
            "target_id": self.target_id,
            "killed": self.killed,
            "requires_governance_unwind": self.requires_governance_unwind,
            "reason_root": self.reason_root,
            "set_by_commitment": self.set_by_commitment,
            "set_at_height": self.set_at_height,
            "final_state_root": self.final_state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexPublicRecord {
    pub record_id: String,
    pub object_kind: String,
    pub object_id: String,
    pub record_root: String,
    pub payload: Value,
    pub recorded_at_height: u64,
}

impl PrivateDexPublicRecord {
    pub fn new(
        object_kind: &str,
        object_id: &str,
        payload: &Value,
        recorded_at_height: u64,
    ) -> PrivateDexResult<Self> {
        ensure_non_empty(object_kind, "private DEX public record object kind")?;
        ensure_non_empty(object_id, "private DEX public record object id")?;
        let record_root = private_dex_public_record_payload_root(payload);
        let record_id =
            private_dex_public_record_id(object_kind, object_id, &record_root, recorded_at_height);
        let record = Self {
            record_id,
            object_kind: object_kind.to_string(),
            object_id: object_id.to_string(),
            record_root,
            payload: payload.clone(),
            recorded_at_height,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> PrivateDexResult<String> {
        ensure_non_empty(&self.record_id, "private DEX public record id")?;
        ensure_non_empty(&self.object_kind, "private DEX public record object kind")?;
        ensure_non_empty(&self.object_id, "private DEX public record object id")?;
        ensure_non_empty(&self.record_root, "private DEX public record root")?;
        let expected_root = private_dex_public_record_payload_root(&self.payload);
        if self.record_root != expected_root {
            return Err("private DEX public record root mismatch".to_string());
        }
        let expected_id = private_dex_public_record_id(
            &self.object_kind,
            &self.object_id,
            &self.record_root,
            self.recorded_at_height,
        );
        if self.record_id != expected_id {
            return Err("private DEX public record id mismatch".to_string());
        }
        Ok(self.record_id.clone())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "object_kind": self.object_kind,
            "object_id": self.object_id,
            "record_root": self.record_root,
            "payload": self.payload,
            "recorded_at_height": self.recorded_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexStateRoots {
    pub config_root: String,
    pub pair_root: String,
    pub pool_config_root: String,
    pub pool_state_root: String,
    pub liquidity_position_root: String,
    pub intent_root: String,
    pub route_hint_root: String,
    pub privacy_budget_root: String,
    pub privacy_reservation_root: String,
    pub auction_root: String,
    pub solver_quote_commitment_root: String,
    pub route_plan_root: String,
    pub quote_reveal_root: String,
    pub batch_order_root: String,
    pub clearing_price_root: String,
    pub settlement_manifest_root: String,
    pub twap_observation_root: String,
    pub oracle_guard_root: String,
    pub pq_transcript_root: String,
    pub circuit_profile_root: String,
    pub validity_proof_root: String,
    pub low_fee_rebate_root: String,
    pub monero_anchor_root: String,
    pub risk_control_root: String,
    pub pause_switch_root: String,
    pub kill_switch_root: String,
    pub public_record_root: String,
}

impl PrivateDexStateRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_dex_state_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "pair_root": self.pair_root,
            "pool_config_root": self.pool_config_root,
            "pool_state_root": self.pool_state_root,
            "liquidity_position_root": self.liquidity_position_root,
            "intent_root": self.intent_root,
            "route_hint_root": self.route_hint_root,
            "privacy_budget_root": self.privacy_budget_root,
            "privacy_reservation_root": self.privacy_reservation_root,
            "auction_root": self.auction_root,
            "solver_quote_commitment_root": self.solver_quote_commitment_root,
            "route_plan_root": self.route_plan_root,
            "quote_reveal_root": self.quote_reveal_root,
            "batch_order_root": self.batch_order_root,
            "clearing_price_root": self.clearing_price_root,
            "settlement_manifest_root": self.settlement_manifest_root,
            "twap_observation_root": self.twap_observation_root,
            "oracle_guard_root": self.oracle_guard_root,
            "pq_transcript_root": self.pq_transcript_root,
            "circuit_profile_root": self.circuit_profile_root,
            "validity_proof_root": self.validity_proof_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "monero_anchor_root": self.monero_anchor_root,
            "risk_control_root": self.risk_control_root,
            "pause_switch_root": self.pause_switch_root,
            "kill_switch_root": self.kill_switch_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        private_dex_state_root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDexState {
    pub height: u64,
    pub nonce: u64,
    pub config: PrivateDexConfig,
    pub pairs: BTreeMap<String, PrivateDexAssetPair>,
    pub pool_configs: BTreeMap<String, PrivateDexCfmmPoolConfig>,
    pub pools: BTreeMap<String, PrivateDexCfmmPoolState>,
    pub liquidity_positions: BTreeMap<String, PrivateDexLiquidityPosition>,
    pub intents: BTreeMap<String, PrivateDexIntent>,
    pub route_hints: BTreeMap<String, PrivateDexRouteHint>,
    pub privacy_budgets: BTreeMap<String, PrivateDexPrivacyBudget>,
    pub privacy_reservations: BTreeMap<String, PrivateDexPrivacyReservation>,
    pub auctions: BTreeMap<String, PrivateDexAuction>,
    pub solver_quote_commitments: BTreeMap<String, PrivateDexSolverQuoteCommitment>,
    pub route_plans: BTreeMap<String, PrivateDexRoutePlan>,
    pub quote_reveals: BTreeMap<String, PrivateDexQuoteReveal>,
    pub batch_orders: BTreeMap<String, PrivateDexBatchOrder>,
    pub clearing_prices: BTreeMap<String, PrivateDexClearingPrice>,
    pub settlement_manifests: BTreeMap<String, PrivateDexSettlementManifest>,
    pub twap_observations: BTreeMap<String, PrivateDexTwapObservation>,
    pub oracle_guards: BTreeMap<String, PrivateDexOracleGuard>,
    pub pq_transcripts: BTreeMap<String, PrivateDexPqTranscript>,
    pub circuit_profiles: BTreeMap<String, PrivateDexCircuitProfile>,
    pub validity_proofs: BTreeMap<String, PrivateDexValidityProof>,
    pub low_fee_rebates: BTreeMap<String, PrivateDexLowFeeRebate>,
    pub monero_anchors: BTreeMap<String, PrivateDexMoneroAnchor>,
    pub risk_controls: BTreeMap<String, PrivateDexRiskControl>,
    pub pause_switches: BTreeMap<String, PrivateDexPauseSwitch>,
    pub kill_switches: BTreeMap<String, PrivateDexKillSwitch>,
    pub public_records: BTreeMap<String, PrivateDexPublicRecord>,
}

impl Default for PrivateDexState {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivateDexState {
    pub fn new() -> Self {
        Self {
            height: 0,
            nonce: 0,
            config: PrivateDexConfig::default(),
            pairs: BTreeMap::new(),
            pool_configs: BTreeMap::new(),
            pools: BTreeMap::new(),
            liquidity_positions: BTreeMap::new(),
            intents: BTreeMap::new(),
            route_hints: BTreeMap::new(),
            privacy_budgets: BTreeMap::new(),
            privacy_reservations: BTreeMap::new(),
            auctions: BTreeMap::new(),
            solver_quote_commitments: BTreeMap::new(),
            route_plans: BTreeMap::new(),
            quote_reveals: BTreeMap::new(),
            batch_orders: BTreeMap::new(),
            clearing_prices: BTreeMap::new(),
            settlement_manifests: BTreeMap::new(),
            twap_observations: BTreeMap::new(),
            oracle_guards: BTreeMap::new(),
            pq_transcripts: BTreeMap::new(),
            circuit_profiles: BTreeMap::new(),
            validity_proofs: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            monero_anchors: BTreeMap::new(),
            risk_controls: BTreeMap::new(),
            pause_switches: BTreeMap::new(),
            kill_switches: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn with_config(config: PrivateDexConfig) -> PrivateDexResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::new()
        })
    }

    pub fn devnet() -> PrivateDexResult<Self> {
        let mut state = Self::with_config(PrivateDexConfig::default())?;
        state.set_height(PRIVATE_DEX_DEVNET_HEIGHT);

        let intent_profile = PrivateDexCircuitProfile::new(
            PrivateDexCircuitFamily::IntentMembership,
            1,
            &private_dex_string_root("PRIVATE-DEX-DEVNET-VK", "intent-membership"),
            &private_dex_string_root("PRIVATE-DEX-DEVNET-PARAMS", "intent-membership"),
            &json!({
                "public_inputs": [
                    "intent_root",
                    "nullifier_hash",
                    "owner_commitment",
                    "pair_id",
                    "amount_buckets",
                    "route_hint_root"
                ]
            }),
            &json!({
                "private_witnesses": [
                    "note_opening",
                    "view_key",
                    "amount",
                    "limit_price",
                    "blinding"
                ]
            }),
            98_304,
            1_800,
            1,
            &json!({"required": PRIVATE_DEX_TRANSCRIPT_SCHEME, "domain": "intent"}),
        )?;
        let batch_profile = PrivateDexCircuitProfile::new(
            PrivateDexCircuitFamily::BatchClearing,
            1,
            &private_dex_string_root("PRIVATE-DEX-DEVNET-VK", "batch-clearing"),
            &private_dex_string_root("PRIVATE-DEX-DEVNET-PARAMS", "batch-clearing"),
            &json!({
                "public_inputs": [
                    "auction_id",
                    "intent_order_root",
                    "quote_order_root",
                    "clearing_price_root",
                    "fairness_proof_root"
                ]
            }),
            &json!({
                "private_witnesses": [
                    "sealed_intent_openings",
                    "solver_quote_openings",
                    "surplus_distribution"
                ]
            }),
            196_608,
            2_900,
            2,
            &json!({"required": PRIVATE_DEX_TRANSCRIPT_SCHEME, "domain": "batch"}),
        )?;
        let route_profile = PrivateDexCircuitProfile::new(
            PrivateDexCircuitFamily::CfmmRoute,
            1,
            &private_dex_string_root("PRIVATE-DEX-DEVNET-VK", "cfmm-route"),
            &private_dex_string_root("PRIVATE-DEX-DEVNET-PARAMS", "cfmm-route"),
            &json!({
                "public_inputs": [
                    "pool_path_root",
                    "asset_path_root",
                    "twap_guard_root",
                    "oracle_guard_root",
                    "pool_delta_root"
                ]
            }),
            &json!({
                "private_witnesses": [
                    "route_split",
                    "sealed_amounts",
                    "fee_rebate_opening"
                ]
            }),
            131_072,
            2_100,
            1,
            &json!({"required": PRIVATE_DEX_TRANSCRIPT_SCHEME, "domain": "route"}),
        )?;
        let settlement_profile = PrivateDexCircuitProfile::new(
            PrivateDexCircuitFamily::Settlement,
            1,
            &private_dex_string_root("PRIVATE-DEX-DEVNET-VK", "settlement"),
            &private_dex_string_root("PRIVATE-DEX-DEVNET-PARAMS", "settlement"),
            &json!({
                "public_inputs": [
                    "fill_root",
                    "note_output_root",
                    "monero_anchor_root",
                    "pre_state_root",
                    "post_state_root"
                ]
            }),
            &json!({
                "private_witnesses": [
                    "ownership_openings",
                    "refund_openings",
                    "view_tags"
                ]
            }),
            155_648,
            2_400,
            2,
            &json!({"required": PRIVATE_DEX_TRANSCRIPT_SCHEME, "domain": "settlement"}),
        )?;
        let reserve_profile = PrivateDexCircuitProfile::new(
            PrivateDexCircuitFamily::MoneroReserveLink,
            1,
            &private_dex_string_root("PRIVATE-DEX-DEVNET-VK", "monero-reserve-link"),
            &private_dex_string_root("PRIVATE-DEX-DEVNET-PARAMS", "monero-reserve-link"),
            &json!({
                "public_inputs": [
                    "monero_network",
                    "txid_root",
                    "output_commitment_root",
                    "reserve_proof_root"
                ]
            }),
            &json!({
                "private_witnesses": [
                    "view_key_opening",
                    "output_secret_key",
                    "ring_decoy_policy"
                ]
            }),
            88_064,
            1_500,
            1,
            &json!({"required": PRIVATE_DEX_TRANSCRIPT_SCHEME, "domain": "monero_anchor"}),
        )?;
        let intent_profile_id = intent_profile.profile_id.clone();
        let batch_profile_id = batch_profile.profile_id.clone();
        let route_profile_id = route_profile.profile_id.clone();
        let settlement_profile_id = settlement_profile.profile_id.clone();
        let reserve_profile_id = reserve_profile.profile_id.clone();
        state.insert_circuit_profile(intent_profile)?;
        state.insert_circuit_profile(batch_profile)?;
        state.insert_circuit_profile(route_profile)?;
        state.insert_circuit_profile(settlement_profile)?;
        state.insert_circuit_profile(reserve_profile)?;

        let wxmr_usdd = PrivateDexAssetPair::new(
            PRIVATE_DEX_DEVNET_WXMR_ASSET_ID,
            PRIVATE_DEX_DEVNET_USDD_ASSET_ID,
            1_000,
            10_000,
            100_000,
            250_000_000_000,
            true,
            &json!({"name": "wXMR/USDD private batch market", "display": "XMR privacy rail"}),
        )?;
        let wxmr_dnr = PrivateDexAssetPair::new(
            PRIVATE_DEX_DEVNET_WXMR_ASSET_ID,
            PRIVATE_DEX_DEVNET_DNR_ASSET_ID,
            1_000,
            10_000,
            100_000,
            180_000_000_000,
            true,
            &json!({"name": "wXMR/DNR private routing market", "display": "governance path"}),
        )?;
        let dnr_usdd = PrivateDexAssetPair::new(
            PRIVATE_DEX_DEVNET_DNR_ASSET_ID,
            PRIVATE_DEX_DEVNET_USDD_ASSET_ID,
            1_000,
            10_000,
            100_000,
            400_000_000_000,
            false,
            &json!({"name": "DNR/USDD stable private market", "display": "stable leg"}),
        )?;
        let wxmr_usdd_pair_id = wxmr_usdd.pair_id.clone();
        let wxmr_dnr_pair_id = wxmr_dnr.pair_id.clone();
        let dnr_usdd_pair_id = dnr_usdd.pair_id.clone();
        state.insert_pair(wxmr_usdd)?;
        state.insert_pair(wxmr_dnr)?;
        state.insert_pair(dnr_usdd)?;

        let wxmr_usdd_pool_config = PrivateDexCfmmPoolConfig::new(
            &wxmr_usdd_pair_id,
            PrivateDexPoolKind::Hybrid,
            PRIVATE_DEX_DEVNET_WXMR_ASSET_ID,
            PRIVATE_DEX_DEVNET_USDD_ASSET_ID,
            PRIVATE_DEX_DEVNET_LP_WXMR_USDD,
            16,
            state.config.protocol_fee_share_bps,
            2_500,
            750,
            &state.config.default_low_fee_lane,
            "risk-wxmr-usdd-devnet",
            &route_profile_id,
            &json!({"name": "hybrid wXMR/USDD pool", "privacy": "sealed-input-router"}),
        )?;
        let wxmr_dnr_pool_config = PrivateDexCfmmPoolConfig::new(
            &wxmr_dnr_pair_id,
            PrivateDexPoolKind::ConstantProduct,
            PRIVATE_DEX_DEVNET_WXMR_ASSET_ID,
            PRIVATE_DEX_DEVNET_DNR_ASSET_ID,
            PRIVATE_DEX_DEVNET_LP_WXMR_DNR,
            22,
            state.config.protocol_fee_share_bps,
            0,
            900,
            &state.config.default_low_fee_lane,
            "risk-wxmr-dnr-devnet",
            &route_profile_id,
            &json!({"name": "constant product wXMR/DNR pool", "privacy": "route-leg only"}),
        )?;
        let dnr_usdd_pool_config = PrivateDexCfmmPoolConfig::new(
            &dnr_usdd_pair_id,
            PrivateDexPoolKind::Stable,
            PRIVATE_DEX_DEVNET_DNR_ASSET_ID,
            PRIVATE_DEX_DEVNET_USDD_ASSET_ID,
            PRIVATE_DEX_DEVNET_LP_DNR_USDD,
            8,
            state.config.protocol_fee_share_bps,
            8_500,
            450,
            &state.config.default_low_fee_lane,
            "risk-dnr-usdd-devnet",
            &route_profile_id,
            &json!({"name": "stable DNR/USDD pool", "privacy": "batch settlement leg"}),
        )?;
        let wxmr_usdd_pool_id = wxmr_usdd_pool_config.pool_id.clone();
        let wxmr_dnr_pool_id = wxmr_dnr_pool_config.pool_id.clone();
        let dnr_usdd_pool_id = dnr_usdd_pool_config.pool_id.clone();
        state.insert_pool_config(wxmr_usdd_pool_config.clone())?;
        state.insert_pool_config(wxmr_dnr_pool_config.clone())?;
        state.insert_pool_config(dnr_usdd_pool_config.clone())?;

        state.insert_pool(PrivateDexCfmmPoolState::new(
            &wxmr_usdd_pool_config,
            16_000_000_000,
            2_560_000_000_000,
            4_000_000_000,
            400_000_000_000,
            190_000_000_000,
            160_000_000_000,
            159_500_000_000,
            state.height,
        )?)?;
        state.insert_pool(PrivateDexCfmmPoolState::new(
            &wxmr_dnr_pool_config,
            8_500_000_000,
            680_000_000_000,
            0,
            0,
            71_000_000_000,
            80_000_000_000,
            79_750_000_000,
            state.height,
        )?)?;
        state.insert_pool(PrivateDexCfmmPoolState::new(
            &dnr_usdd_pool_config,
            540_000_000_000,
            830_000_000_000,
            90_000_000_000,
            125_000_000_000,
            650_000_000_000,
            1_535_000_000_000,
            1_532_000_000_000,
            state.height,
        )?)?;

        let lp1 = PrivateDexLiquidityPosition::new(
            "devnet-alice-lp",
            &wxmr_usdd_pool_id,
            PRIVATE_DEX_DEVNET_WXMR_ASSET_ID,
            PRIVATE_DEX_DEVNET_USDD_ASSET_ID,
            95_000_000_000,
            9_500_000_000,
            1_520_000_000_000,
            150_000_000_000,
            172_000_000_000,
            state.height.saturating_add(720),
            state.next_nonce(),
            &json!({"strategy": "private-xmr-stable-core", "range": "wide"}),
        )?;
        let lp2 = PrivateDexLiquidityPosition::new(
            "devnet-bob-lp",
            &wxmr_dnr_pool_id,
            PRIVATE_DEX_DEVNET_WXMR_ASSET_ID,
            PRIVATE_DEX_DEVNET_DNR_ASSET_ID,
            44_000_000_000,
            4_100_000_000,
            328_000_000_000,
            68_000_000_000,
            92_000_000_000,
            state.height.saturating_add(720),
            state.next_nonce(),
            &json!({"strategy": "governance-route", "range": "volatile"}),
        )?;
        let lp3 = PrivateDexLiquidityPosition::new(
            "devnet-carol-lp",
            &dnr_usdd_pool_id,
            PRIVATE_DEX_DEVNET_DNR_ASSET_ID,
            PRIVATE_DEX_DEVNET_USDD_ASSET_ID,
            260_000_000_000,
            210_000_000_000,
            323_000_000_000,
            1_480_000_000_000,
            1_590_000_000_000,
            state.height.saturating_add(720),
            state.next_nonce(),
            &json!({"strategy": "stable-leg", "range": "tight"}),
        )?;
        state.insert_liquidity_position(lp1)?;
        state.insert_liquidity_position(lp2)?;
        state.insert_liquidity_position(lp3)?;

        state.install_devnet_oracle_and_twap(
            &wxmr_usdd_pool_id,
            "wxmr-usdd-private-feed",
            160_000_000_000,
        )?;
        state.install_devnet_oracle_and_twap(
            &wxmr_dnr_pool_id,
            "wxmr-dnr-private-feed",
            80_000_000_000,
        )?;
        state.install_devnet_oracle_and_twap(
            &dnr_usdd_pool_id,
            "dnr-usdd-private-feed",
            1_535_000_000_000,
        )?;

        state.insert_risk_control(PrivateDexRiskControl::new(
            PrivateDexSwitchScope::Global,
            "private-dex",
            PrivateDexRiskMode::Normal,
            5_000_000_000,
            400,
            state.config.max_price_impact_bps,
            1_000_000,
            120,
            2_500_000_000,
            0,
            Some(state.height.saturating_sub(10)),
            None,
            &json!({"mode": "devnet global guard", "priority": "low-fee fast settlement"}),
        )?)?;
        state.insert_risk_control(PrivateDexRiskControl::new(
            PrivateDexSwitchScope::Pool,
            &wxmr_usdd_pool_id,
            PrivateDexRiskMode::Watch,
            120_000_000,
            250,
            700,
            10_000_000,
            48,
            900_000_000,
            0,
            Some(state.height.saturating_sub(4)),
            Some(state.height.saturating_add(240)),
            &json!({"pool": "wxmr-usdd", "reason": "devnet launch watch band"}),
        )?)?;
        let pause_nonce = state.next_nonce();
        state.insert_pause_switch(PrivateDexPauseSwitch::new(
            PrivateDexSwitchScope::Global,
            "private-dex",
            false,
            &json!({"mode": "devnet active"}),
            "devnet-governance",
            state.height,
            None,
            pause_nonce,
        )?)?;
        state.insert_kill_switch(PrivateDexKillSwitch::new(
            PrivateDexSwitchScope::Global,
            "private-dex",
            false,
            true,
            &json!({"mode": "armed but inactive"}),
            "devnet-governance",
            state.height,
            &merkle_root("PRIVATE-DEX-DEVNET-FINAL-STATE", &[]),
        )?)?;

        let budget_alice = PrivateDexPrivacyBudget::new(
            "devnet-alice",
            0,
            0,
            state.config.privacy_epoch_blocks,
            state.config.privacy_budget_units,
        )?;
        let budget_bob = PrivateDexPrivacyBudget::new(
            "devnet-bob",
            0,
            0,
            state.config.privacy_epoch_blocks,
            state.config.privacy_budget_units / 2,
        )?;
        let alice_budget_id = budget_alice.budget_id.clone();
        let bob_budget_id = budget_bob.budget_id.clone();
        state.insert_privacy_budget(budget_alice)?;
        state.insert_privacy_budget(budget_bob)?;

        let intent_transcript = PrivateDexPqTranscript::new(
            PrivateDexTranscriptPurpose::IntentAuthorization,
            PrivateDexCircuitFamily::IntentMembership,
            "devnet-alice-intent-session",
            &state.pair_root(),
            &json!({"challenge": "intent-membership", "height": state.height}),
            &json!({"response": "dual-signature-root", "owner": "devnet-alice"}),
            &[
                "devnet-alice-ml-dsa".to_string(),
                "devnet-alice-recovery-slh-dsa".to_string(),
            ],
            &[json!({"kem": "ml-kem-768", "recipient": "devnet-router"})],
            state.height,
            state.height.saturating_add(64),
        )?;
        let intent_transcript_id = intent_transcript.transcript_id.clone();
        state.insert_pq_transcript(intent_transcript)?;

        let bob_intent_transcript = PrivateDexPqTranscript::new(
            PrivateDexTranscriptPurpose::IntentAuthorization,
            PrivateDexCircuitFamily::IntentMembership,
            "devnet-bob-intent-session",
            &state.pair_root(),
            &json!({"challenge": "intent-membership", "height": state.height, "owner": "bob"}),
            &json!({"response": "dual-signature-root", "owner": "devnet-bob"}),
            &[
                "devnet-bob-ml-dsa".to_string(),
                "devnet-bob-recovery-slh-dsa".to_string(),
            ],
            &[json!({"kem": "ml-kem-768", "recipient": "devnet-router"})],
            state.height,
            state.height.saturating_add(64),
        )?;
        let bob_intent_transcript_id = bob_intent_transcript.transcript_id.clone();
        state.insert_pq_transcript(bob_intent_transcript)?;

        let route_steps_alice = vec![
            json!({"pool_id": wxmr_usdd_pool_id, "asset_in": PRIVATE_DEX_DEVNET_WXMR_ASSET_ID, "asset_out": PRIVATE_DEX_DEVNET_USDD_ASSET_ID}),
            json!({"settlement": "shielded-output", "view_tag_policy": "recipient-only"}),
        ];
        let route_hint_root_alice = private_dex_route_hop_root(&route_steps_alice);
        let alice_intent = PrivateDexIntent::new(
            "devnet-alice",
            &wxmr_usdd_pair_id,
            PrivateDexOrderSide::Sell,
            PrivateDexOrderKind::ExactInput,
            PRIVATE_DEX_DEVNET_WXMR_ASSET_ID,
            PRIVATE_DEX_DEVNET_USDD_ASSET_ID,
            42_000_000,
            6_575_000_000,
            156_000_000_000,
            1,
            40,
            state.height.saturating_add(state.config.intent_ttl_blocks),
            state.height,
            state.next_nonce(),
            &json!({"kind": "swap", "amount": "sealed", "recipient": "alice-private-output"}),
            route_hint_root_alice.clone(),
            alice_budget_id.clone(),
            "devnet-alice-recipient",
            intent_transcript_id.clone(),
            &json!({"low_fee": true, "wallet_policy": "private_defi_intent_approval"}),
        )?;
        let alice_intent_id = alice_intent.intent_id.clone();
        state.insert_intent(alice_intent)?;
        let alice_hint = PrivateDexRouteHint::new(
            &alice_intent_id,
            "devnet-private-router",
            &route_steps_alice,
            &json!({"encrypted": "alice-route-ciphertext-root"}),
            &json!({"release": "settlement-only", "auditor": "watchtower-view-root"}),
            2,
            state.height,
            state.height.saturating_add(state.config.intent_ttl_blocks),
        )?;
        let alice_hint_id = alice_hint.hint_id.clone();
        state.insert_route_hint(alice_hint)?;

        let route_steps_bob = vec![
            json!({"pool_id": wxmr_dnr_pool_id, "asset_in": PRIVATE_DEX_DEVNET_WXMR_ASSET_ID, "asset_out": PRIVATE_DEX_DEVNET_DNR_ASSET_ID}),
            json!({"pool_id": dnr_usdd_pool_id, "asset_in": PRIVATE_DEX_DEVNET_DNR_ASSET_ID, "asset_out": PRIVATE_DEX_DEVNET_USDD_ASSET_ID}),
        ];
        let route_hint_root_bob = private_dex_route_hop_root(&route_steps_bob);
        let bob_intent = PrivateDexIntent::new(
            "devnet-bob",
            &wxmr_usdd_pair_id,
            PrivateDexOrderSide::Sell,
            PrivateDexOrderKind::ExactInput,
            PRIVATE_DEX_DEVNET_WXMR_ASSET_ID,
            PRIVATE_DEX_DEVNET_USDD_ASSET_ID,
            18_000_000,
            2_700_000_000,
            151_000_000_000,
            1,
            65,
            state.height.saturating_add(state.config.intent_ttl_blocks),
            state.height,
            state.next_nonce(),
            &json!({"kind": "swap", "amount": "sealed", "recipient": "bob-private-output"}),
            route_hint_root_bob.clone(),
            bob_budget_id.clone(),
            "devnet-bob-recipient",
            bob_intent_transcript_id.clone(),
            &json!({"low_fee": true, "route": "multi-hop"}),
        )?;
        let bob_intent_id = bob_intent.intent_id.clone();
        state.insert_intent(bob_intent)?;
        let bob_hint = PrivateDexRouteHint::new(
            &bob_intent_id,
            "devnet-private-router",
            &route_steps_bob,
            &json!({"encrypted": "bob-route-ciphertext-root"}),
            &json!({"release": "settlement-only", "auditor": "watchtower-view-root"}),
            3,
            state.height,
            state.height.saturating_add(state.config.intent_ttl_blocks),
        )?;
        state.insert_route_hint(bob_hint)?;

        let alice_reservation = state.reserve_privacy_budget(
            &alice_budget_id,
            "private_dex_intent",
            &alice_intent_id,
            35_000,
            state.height.saturating_add(state.config.intent_ttl_blocks),
        )?;
        let bob_reservation = state.reserve_privacy_budget(
            &bob_budget_id,
            "private_dex_intent",
            &bob_intent_id,
            22_500,
            state.height.saturating_add(state.config.intent_ttl_blocks),
        )?;

        let auction_transcript = PrivateDexPqTranscript::new(
            PrivateDexTranscriptPurpose::BatchClearing,
            PrivateDexCircuitFamily::BatchClearing,
            "devnet-wxmr-usdd-auction-64",
            &state.intent_root(),
            &json!({"challenge": "batch-clearing", "intent_root": state.intent_root()}),
            &json!({"response": "solver-set-root", "policy": "commit-reveal"}),
            &[
                "devnet-sequencer-ml-dsa".to_string(),
                "devnet-watchtower-slh-dsa".to_string(),
            ],
            &[json!({"kem": "ml-kem-768", "recipient": "solver-set"})],
            state.height,
            state.height.saturating_add(96),
        )?;
        let auction_transcript_id = auction_transcript.transcript_id.clone();
        state.insert_pq_transcript(auction_transcript)?;

        let pair_commitment = private_dex_pair_commitment(
            PRIVATE_DEX_DEVNET_WXMR_ASSET_ID,
            PRIVATE_DEX_DEVNET_USDD_ASSET_ID,
        );
        let ordering_seed =
            private_dex_ordering_seed("devnet-wxmr-usdd-batch", state.height, &state.intent_root());
        let mut auction = PrivateDexAuction::new(
            "devnet-private-dex-market",
            &wxmr_usdd_pair_id,
            &pair_commitment,
            &state.intent_root(),
            &state.route_hint_root(),
            &state.privacy_budget_root(),
            &state.pool_state_root(),
            &state.oracle_guard_root(),
            state.height,
            state.config.default_auction_window_blocks,
            state.config.default_reveal_delay_blocks,
            state.config.default_reveal_window_blocks,
            state.config.default_challenge_window_blocks,
            state.config.settlement_ttl_blocks,
            &ordering_seed,
            &auction_transcript_id,
        )?;
        let auction_id = auction.auction_id.clone();

        let route_transcript = PrivateDexPqTranscript::new(
            PrivateDexTranscriptPurpose::RouteExecution,
            PrivateDexCircuitFamily::CfmmRoute,
            "devnet-direct-route",
            &state.pool_state_root(),
            &json!({"challenge": "route-direct", "pool": wxmr_usdd_pool_id}),
            &json!({"response": "route-proof-direct"}),
            &["devnet-solver-1-ml-dsa".to_string()],
            &[json!({"kem": "ml-kem-768", "recipient": "devnet-sequencer"})],
            state.height,
            state.height.saturating_add(96),
        )?;
        let route_transcript_id = route_transcript.transcript_id.clone();
        state.insert_pq_transcript(route_transcript)?;

        let direct_route = state.build_route_plan(
            &alice_intent_id,
            "devnet-solver-1",
            vec![wxmr_usdd_pool_id.clone()],
            vec![
                PRIVATE_DEX_DEVNET_WXMR_ASSET_ID.to_string(),
                PRIVATE_DEX_DEVNET_USDD_ASSET_ID.to_string(),
            ],
            42_000_000,
            9_860,
            &route_transcript_id,
        )?;
        let direct_route_id = direct_route.route_id.clone();
        let direct_expected = direct_route.expected_amount_out;
        let direct_total_fees = direct_route
            .total_pool_fee_units
            .saturating_add(direct_route.total_protocol_fee_units);
        state.insert_route_plan(direct_route)?;

        let multi_route_transcript = PrivateDexPqTranscript::new(
            PrivateDexTranscriptPurpose::RouteExecution,
            PrivateDexCircuitFamily::CfmmRoute,
            "devnet-multi-hop-route",
            &state.pool_state_root(),
            &json!({"challenge": "route-multi", "pools": [wxmr_dnr_pool_id, dnr_usdd_pool_id]}),
            &json!({"response": "route-proof-multi"}),
            &["devnet-solver-2-ml-dsa".to_string()],
            &[json!({"kem": "ml-kem-768", "recipient": "devnet-sequencer"})],
            state.height,
            state.height.saturating_add(96),
        )?;
        let multi_route_transcript_id = multi_route_transcript.transcript_id.clone();
        state.insert_pq_transcript(multi_route_transcript)?;
        let multi_route = state.build_route_plan(
            &bob_intent_id,
            "devnet-solver-2",
            vec![wxmr_dnr_pool_id.clone(), dnr_usdd_pool_id.clone()],
            vec![
                PRIVATE_DEX_DEVNET_WXMR_ASSET_ID.to_string(),
                PRIVATE_DEX_DEVNET_DNR_ASSET_ID.to_string(),
                PRIVATE_DEX_DEVNET_USDD_ASSET_ID.to_string(),
            ],
            18_000_000,
            9_720,
            &multi_route_transcript_id,
        )?;
        let multi_route_id = multi_route.route_id.clone();
        let multi_expected = multi_route.expected_amount_out;
        let multi_total_fees = multi_route
            .total_pool_fee_units
            .saturating_add(multi_route.total_protocol_fee_units);
        state.insert_route_plan(multi_route)?;

        let solver_quote_transcript = PrivateDexPqTranscript::new(
            PrivateDexTranscriptPurpose::SolverQuote,
            PrivateDexCircuitFamily::BatchClearing,
            "devnet-solver-1-quote",
            &state.route_plan_root(),
            &json!({"challenge": "solver-quote", "route": direct_route_id}),
            &json!({"response": "quote-commitment", "solver": "devnet-solver-1"}),
            &["devnet-solver-1-ml-dsa".to_string()],
            &[json!({"kem": "ml-kem-768", "recipient": "auction"})],
            state.height,
            state.height.saturating_add(96),
        )?;
        let solver_quote_transcript_id = solver_quote_transcript.transcript_id.clone();
        state.insert_pq_transcript(solver_quote_transcript)?;
        let quote1 = PrivateDexSolverQuoteCommitment::new(
            &auction_id,
            "devnet-solver-1",
            PrivateDexSolverKind::HybridRouter,
            &state.route_plans[&direct_route_id].route_commitment,
            &pair_commitment,
            42_000_000,
            direct_expected,
            160_000_000_000,
            1,
            direct_total_fees,
            direct_expected.saturating_sub(6_575_000_000),
            "devnet-solver-1-secret",
            &solver_quote_transcript_id,
            state.config.min_solver_bond_units,
            state.height.saturating_add(1),
            state
                .height
                .saturating_add(state.config.default_auction_window_blocks)
                .saturating_add(state.config.default_reveal_delay_blocks)
                .saturating_add(state.config.default_reveal_window_blocks),
        )?;
        let quote1_id = quote1.quote_id.clone();
        state.insert_solver_quote_commitment(quote1)?;

        let solver2_quote_transcript = PrivateDexPqTranscript::new(
            PrivateDexTranscriptPurpose::SolverQuote,
            PrivateDexCircuitFamily::BatchClearing,
            "devnet-solver-2-quote",
            &state.route_plan_root(),
            &json!({"challenge": "solver-quote", "route": multi_route_id}),
            &json!({"response": "quote-commitment", "solver": "devnet-solver-2"}),
            &["devnet-solver-2-ml-dsa".to_string()],
            &[json!({"kem": "ml-kem-768", "recipient": "auction"})],
            state.height,
            state.height.saturating_add(96),
        )?;
        let solver2_quote_transcript_id = solver2_quote_transcript.transcript_id.clone();
        state.insert_pq_transcript(solver2_quote_transcript)?;
        let quote2 = PrivateDexSolverQuoteCommitment::new(
            &auction_id,
            "devnet-solver-2",
            PrivateDexSolverKind::BatchAuction,
            &state.route_plans[&multi_route_id].route_commitment,
            &pair_commitment,
            18_000_000,
            multi_expected,
            153_000_000_000,
            1,
            multi_total_fees,
            multi_expected.saturating_sub(2_700_000_000),
            "devnet-solver-2-secret",
            &solver2_quote_transcript_id,
            state.config.min_solver_bond_units.saturating_mul(2),
            state.height.saturating_add(1),
            state
                .height
                .saturating_add(state.config.default_auction_window_blocks)
                .saturating_add(state.config.default_reveal_delay_blocks)
                .saturating_add(state.config.default_reveal_window_blocks),
        )?;
        let quote2_id = quote2.quote_id.clone();
        state.insert_solver_quote_commitment(quote2)?;
        auction.solver_commitment_root = state.solver_quote_commitment_root();
        state.insert_auction(auction)?;

        let reveal_height = state
            .height
            .saturating_add(state.config.default_auction_window_blocks)
            .saturating_add(state.config.default_reveal_delay_blocks);
        let reveal1 = PrivateDexQuoteReveal::new(
            &state.solver_quote_commitments[&quote1_id],
            &state.route_plans[&direct_route_id],
            42_000_000,
            direct_expected,
            160_000_000_000,
            1,
            direct_total_fees,
            direct_expected.saturating_sub(6_575_000_000),
            "devnet-solver-1-secret",
            reveal_height,
        )?;
        let reveal1_id = reveal1.reveal_id.clone();
        state.insert_quote_reveal(reveal1)?;
        let reveal2 = PrivateDexQuoteReveal::new(
            &state.solver_quote_commitments[&quote2_id],
            &state.route_plans[&multi_route_id],
            18_000_000,
            multi_expected,
            153_000_000_000,
            1,
            multi_total_fees,
            multi_expected.saturating_sub(2_700_000_000),
            "devnet-solver-2-secret",
            reveal_height,
        )?;
        let reveal2_id = reveal2.reveal_id.clone();
        state.insert_quote_reveal(reveal2)?;

        let selected_intents = vec![alice_intent_id.clone(), bob_intent_id.clone()];
        let selected_quotes = vec![quote1_id.clone(), quote2_id.clone()];
        let selected_routes = vec![direct_route_id.clone(), multi_route_id.clone()];
        let batch_order = PrivateDexBatchOrder::new(
            &auction_id,
            reveal_height.saturating_add(1),
            &ordering_seed,
            &selected_intents,
            &selected_quotes,
            &selected_routes,
        )?;
        let batch_order_id = batch_order.batch_order_id.clone();
        state.insert_batch_order(batch_order)?;

        let clearing = PrivateDexClearingPrice::new(
            &auction_id,
            &wxmr_usdd_pair_id,
            158_400_000_000,
            1,
            60_000_000,
            direct_expected.saturating_add(multi_expected),
            2,
            0,
            &private_dex_solver_commitment("devnet-solver-set"),
            &selected_routes,
            &[
                state.quote_reveals[&reveal1_id].surplus_units.to_string(),
                state.quote_reveals[&reveal2_id].surplus_units.to_string(),
            ],
        )?;
        let clearing_price_id = clearing.clearing_price_id.clone();
        state.insert_clearing_price(clearing)?;

        let rebate1 = PrivateDexLowFeeRebate::new(
            &direct_route_id,
            &auction_id,
            &state.config.default_low_fee_lane,
            "devnet-foundation-paymaster",
            &state.config.fee_asset_id,
            direct_total_fees,
            direct_total_fees,
            state.config.low_fee_rebate_bps,
            state.config.max_low_fee_rebate_units,
            "devnet-rebate-bond-1",
            state.height,
            96,
        )?;
        let rebate1_id = rebate1.rebate_id.clone();
        state.insert_low_fee_rebate(rebate1)?;
        let rebate2 = PrivateDexLowFeeRebate::new(
            &multi_route_id,
            &auction_id,
            &state.config.default_low_fee_lane,
            "devnet-foundation-paymaster",
            &state.config.fee_asset_id,
            multi_total_fees,
            multi_total_fees,
            state.config.low_fee_rebate_bps,
            state.config.max_low_fee_rebate_units,
            "devnet-rebate-bond-2",
            state.height,
            96,
        )?;
        let rebate2_id = rebate2.rebate_id.clone();
        state.insert_low_fee_rebate(rebate2)?;
        if let Some(route) = state.route_plans.get_mut(&direct_route_id) {
            route.low_fee_rebate_id = Some(rebate1_id);
        }
        if let Some(route) = state.route_plans.get_mut(&multi_route_id) {
            route.low_fee_rebate_id = Some(rebate2_id);
        }

        let monero_transcript = PrivateDexPqTranscript::new(
            PrivateDexTranscriptPurpose::MoneroAnchor,
            PrivateDexCircuitFamily::MoneroReserveLink,
            "devnet-monero-anchor",
            &state.pool_state_root(),
            &json!({"challenge": "monero-anchor", "network": state.config.default_monero_network}),
            &json!({"response": "reserve-link-proof", "view_key": "committed"}),
            &[
                "devnet-bridge-signer-ml-dsa".to_string(),
                "devnet-watchtower-slh-dsa".to_string(),
            ],
            &[json!({"kem": "ml-kem-768", "recipient": "reserve-auditor"})],
            state.height,
            state.height.saturating_add(240),
        )?;
        let monero_transcript_id = monero_transcript.transcript_id.clone();
        state.insert_pq_transcript(monero_transcript)?;
        let monero_anchor = PrivateDexMoneroAnchor::new(
            &state.config.default_monero_network,
            PRIVATE_DEX_DEVNET_WXMR_ASSET_ID,
            "devnet-private-dex-view-key",
            &[
                "devnet-monero-txid-1".to_string(),
                "devnet-monero-txid-2".to_string(),
            ],
            &[
                "devnet-output-commitment-1".to_string(),
                "devnet-output-commitment-2".to_string(),
            ],
            &[
                "devnet-key-image-1".to_string(),
                "devnet-key-image-2".to_string(),
            ],
            &[
                json!({"ring": "ring-1", "size": 16}),
                json!({"ring": "ring-2", "size": 16}),
            ],
            &json!({"reserve": "wxmr", "coverage_bps": 10_250, "policy": "view-key-root-only"}),
            &monero_transcript_id,
            state.height.saturating_sub(2),
            10,
        )?;
        let monero_anchor_id = monero_anchor.anchor_id.clone();
        state.insert_monero_anchor(monero_anchor)?;

        let intent_proof = PrivateDexValidityProof::new(
            &intent_transcript_id,
            &intent_profile_id,
            &alice_intent_id,
            &state.intents[&alice_intent_id].proof_public_input_root,
            "alice-intent-witness",
            &private_dex_string_root("PRIVATE-DEX-DEVNET-ACCUMULATOR", "alice-intent"),
            &private_dex_string_root("PRIVATE-DEX-DEVNET-VERIFIER", "intent"),
            84_992,
            state.height,
        )?;
        let batch_proof = PrivateDexValidityProof::new(
            &auction_transcript_id,
            &batch_profile_id,
            &batch_order_id,
            &state.batch_orders[&batch_order_id].fairness_proof_root,
            "batch-clearing-witness",
            &private_dex_string_root("PRIVATE-DEX-DEVNET-ACCUMULATOR", "batch"),
            &private_dex_string_root("PRIVATE-DEX-DEVNET-VERIFIER", "batch"),
            150_144,
            reveal_height.saturating_add(1),
        )?;
        let route_proof = PrivateDexValidityProof::new(
            &route_transcript_id,
            &route_profile_id,
            &direct_route_id,
            &state.route_plans[&direct_route_id].quote_root,
            "direct-route-witness",
            &private_dex_string_root("PRIVATE-DEX-DEVNET-ACCUMULATOR", "route-direct"),
            &private_dex_string_root("PRIVATE-DEX-DEVNET-VERIFIER", "route"),
            112_640,
            state.height,
        )?;
        let reserve_proof = PrivateDexValidityProof::new(
            &monero_transcript_id,
            &reserve_profile_id,
            &monero_anchor_id,
            &state.monero_anchors[&monero_anchor_id].reserve_proof_root,
            "monero-reserve-witness",
            &private_dex_string_root("PRIVATE-DEX-DEVNET-ACCUMULATOR", "reserve"),
            &private_dex_string_root("PRIVATE-DEX-DEVNET-VERIFIER", "reserve"),
            76_288,
            state.height,
        )?;
        let settlement_transcript = PrivateDexPqTranscript::new(
            PrivateDexTranscriptPurpose::SettlementFinality,
            PrivateDexCircuitFamily::Settlement,
            "devnet-settlement-finality",
            &state.state_root(),
            &json!({"challenge": "settlement", "auction": auction_id}),
            &json!({"response": "settlement-manifest-ready"}),
            &[
                "devnet-sequencer-ml-dsa".to_string(),
                "devnet-watchtower-slh-dsa".to_string(),
            ],
            &[json!({"kem": "ml-kem-768", "recipient": "settlement-auditor"})],
            state.height,
            state.height.saturating_add(240),
        )?;
        let settlement_transcript_id = settlement_transcript.transcript_id.clone();
        state.insert_pq_transcript(settlement_transcript)?;
        let settlement_proof = PrivateDexValidityProof::new(
            &settlement_transcript_id,
            &settlement_profile_id,
            &batch_order_id,
            &state.batch_orders[&batch_order_id].fairness_proof_root,
            "settlement-witness",
            &private_dex_string_root("PRIVATE-DEX-DEVNET-ACCUMULATOR", "settlement"),
            &private_dex_string_root("PRIVATE-DEX-DEVNET-VERIFIER", "settlement"),
            128_320,
            reveal_height.saturating_add(2),
        )?;
        let proof_ids = vec![
            intent_proof.proof_id.clone(),
            batch_proof.proof_id.clone(),
            route_proof.proof_id.clone(),
            reserve_proof.proof_id.clone(),
            settlement_proof.proof_id.clone(),
        ];
        state.insert_validity_proof(intent_proof)?;
        state.insert_validity_proof(batch_proof)?;
        state.insert_validity_proof(route_proof)?;
        state.insert_validity_proof(reserve_proof)?;
        state.insert_validity_proof(settlement_proof)?;

        state.consume_privacy_budget(
            &alice_reservation.reservation_id,
            reveal_height.saturating_add(2),
        )?;
        state.consume_privacy_budget(
            &bob_reservation.reservation_id,
            reveal_height.saturating_add(2),
        )?;
        if let Some(intent) = state.intents.get_mut(&alice_intent_id) {
            intent.mark_filled();
        }
        if let Some(intent) = state.intents.get_mut(&bob_intent_id) {
            intent.mark_filled();
        }

        let fill1 = PrivateDexSettlementFill::new(
            &alice_intent_id,
            &quote1_id,
            &direct_route_id,
            &state.route_plans[&direct_route_id].solver_commitment,
            "alice-input-nullifier",
            "alice-output-note",
            "",
            direct_total_fees,
            direct_expected.saturating_sub(6_575_000_000),
            42_000_000,
            direct_expected,
            &alice_hint_id,
            "alice-monero-view-tag",
        )?;
        let fill2 = PrivateDexSettlementFill::new(
            &bob_intent_id,
            &quote2_id,
            &multi_route_id,
            &state.route_plans[&multi_route_id].solver_commitment,
            "bob-input-nullifier",
            "bob-output-note",
            "",
            multi_total_fees,
            multi_expected.saturating_sub(2_700_000_000),
            18_000_000,
            multi_expected,
            &state
                .route_hints
                .values()
                .find(|hint| hint.intent_id == bob_intent_id)
                .map(|hint| hint.hint_id.clone())
                .unwrap_or_else(|| {
                    private_dex_string_root("PRIVATE-DEX-DEVNET-HINT-FALLBACK", "bob")
                }),
            "bob-monero-view-tag",
        )?;
        let pre_state_root = state.state_root();
        let simulated_post_root = private_dex_payload_root(
            "PRIVATE-DEX-DEVNET-POST-SETTLEMENT",
            &json!({
                "pre_state_root": pre_state_root,
                "auction_id": auction_id,
                "batch_order_id": batch_order_id,
                "fills": [fill1.fill_id.clone(), fill2.fill_id.clone()],
            }),
        );
        let manifest = PrivateDexSettlementManifest::new(
            &auction_id,
            &batch_order_id,
            &clearing_price_id,
            &private_dex_solver_commitment("devnet-solver-set"),
            vec![fill1, fill2],
            &selected_routes,
            &[
                json!({"pool_id": wxmr_usdd_pool_id, "delta": "sealed"}),
                json!({"pool_id": wxmr_dnr_pool_id, "delta": "sealed"}),
                json!({"pool_id": dnr_usdd_pool_id, "delta": "sealed"}),
            ],
            &[
                json!({"output": "alice-output-note", "visibility": "view-key-only"}),
                json!({"output": "bob-output-note", "visibility": "view-key-only"}),
            ],
            &[
                state.quote_reveals[&reveal1_id].surplus_units.to_string(),
                state.quote_reveals[&reveal2_id].surplus_units.to_string(),
            ],
            &[state
                .low_fee_rebates
                .values()
                .next()
                .map(PrivateDexLowFeeRebate::public_record)
                .unwrap_or_else(|| json!({}))],
            &state.monero_anchors[&monero_anchor_id],
            &proof_ids,
            &pre_state_root,
            &simulated_post_root,
            reveal_height.saturating_add(2),
            reveal_height.saturating_add(12),
        )?;
        let manifest_id = manifest.manifest_id.clone();
        state.insert_settlement_manifest(manifest)?;
        let clearing_result_root = state.clearing_price_root();
        if let Some(auction) = state.auctions.get_mut(&auction_id) {
            auction.status = PRIVATE_DEX_STATUS_SETTLED.to_string();
            auction.clearing_result_root = clearing_result_root;
        }
        if let Some(batch) = state.batch_orders.get_mut(&batch_order_id) {
            batch.status = PRIVATE_DEX_STATUS_SETTLED.to_string();
        }
        for quote_id in [&quote1_id, &quote2_id] {
            if let Some(quote) = state.solver_quote_commitments.get_mut(quote_id) {
                quote.status = PRIVATE_DEX_STATUS_SETTLED.to_string();
            }
        }
        for reveal_id in [&reveal1_id, &reveal2_id] {
            if let Some(reveal) = state.quote_reveals.get_mut(reveal_id) {
                reveal.status = PRIVATE_DEX_STATUS_SETTLED.to_string();
            }
        }

        for (object_kind, object_id, payload) in [
            (
                "private_dex_intent",
                alice_intent_id.as_str(),
                state.intents[&alice_intent_id].public_record(),
            ),
            (
                "private_dex_intent",
                bob_intent_id.as_str(),
                state.intents[&bob_intent_id].public_record(),
            ),
            (
                "private_dex_auction",
                auction_id.as_str(),
                state.auctions[&auction_id].public_record(),
            ),
            (
                "private_dex_batch_order",
                batch_order_id.as_str(),
                state.batch_orders[&batch_order_id].public_record(),
            ),
            (
                "private_dex_settlement_manifest",
                manifest_id.as_str(),
                state.settlement_manifests[&manifest_id].public_record(),
            ),
        ] {
            state.publish_public_record(object_kind, object_id, &payload)?;
        }

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn advance_height(&mut self, blocks: u64) -> u64 {
        self.height = self.height.saturating_add(blocks);
        self.height
    }

    pub fn next_nonce(&mut self) -> u64 {
        self.nonce = self.nonce.saturating_add(1);
        self.nonce
    }

    pub fn insert_pair(&mut self, pair: PrivateDexAssetPair) -> PrivateDexResult<()> {
        pair.validate()?;
        self.pairs.insert(pair.pair_id.clone(), pair);
        Ok(())
    }

    pub fn insert_pool_config(&mut self, config: PrivateDexCfmmPoolConfig) -> PrivateDexResult<()> {
        config.validate()?;
        if !self.pairs.contains_key(&config.pair_id) {
            return Err("private DEX pool config references unknown pair".to_string());
        }
        self.pool_configs.insert(config.pool_id.clone(), config);
        Ok(())
    }

    pub fn insert_pool(&mut self, pool: PrivateDexCfmmPoolState) -> PrivateDexResult<()> {
        pool.validate()?;
        if !self.pool_configs.contains_key(&pool.pool_id) {
            return Err("private DEX pool state references unknown pool config".to_string());
        }
        self.pools.insert(pool.pool_id.clone(), pool);
        Ok(())
    }

    pub fn insert_liquidity_position(
        &mut self,
        position: PrivateDexLiquidityPosition,
    ) -> PrivateDexResult<()> {
        position.validate()?;
        if !self.pools.contains_key(&position.pool_id) {
            return Err("private DEX LP position references unknown pool".to_string());
        }
        self.liquidity_positions
            .insert(position.position_id.clone(), position);
        Ok(())
    }

    pub fn insert_intent(&mut self, intent: PrivateDexIntent) -> PrivateDexResult<()> {
        intent.validate()?;
        if !self.pairs.contains_key(&intent.pair_id) {
            return Err("private DEX intent references unknown pair".to_string());
        }
        if !self.privacy_budgets.contains_key(&intent.privacy_budget_id) {
            return Err("private DEX intent references unknown privacy budget".to_string());
        }
        if !self.pq_transcripts.contains_key(&intent.pq_transcript_id) {
            return Err("private DEX intent references unknown PQ transcript".to_string());
        }
        self.intents.insert(intent.intent_id.clone(), intent);
        Ok(())
    }

    pub fn insert_route_hint(&mut self, hint: PrivateDexRouteHint) -> PrivateDexResult<()> {
        hint.validate()?;
        if !self.intents.contains_key(&hint.intent_id) {
            return Err("private DEX route hint references unknown intent".to_string());
        }
        self.route_hints.insert(hint.hint_id.clone(), hint);
        Ok(())
    }

    pub fn insert_privacy_budget(
        &mut self,
        budget: PrivateDexPrivacyBudget,
    ) -> PrivateDexResult<()> {
        budget.validate()?;
        self.privacy_budgets
            .insert(budget.budget_id.clone(), budget);
        Ok(())
    }

    pub fn insert_privacy_reservation(
        &mut self,
        reservation: PrivateDexPrivacyReservation,
    ) -> PrivateDexResult<()> {
        reservation.validate()?;
        if !self.privacy_budgets.contains_key(&reservation.budget_id) {
            return Err("private DEX reservation references unknown budget".to_string());
        }
        self.privacy_reservations
            .insert(reservation.reservation_id.clone(), reservation);
        Ok(())
    }

    pub fn reserve_privacy_budget(
        &mut self,
        budget_id: &str,
        object_kind: &str,
        object_id: &str,
        units: u64,
        expires_at_height: u64,
    ) -> PrivateDexResult<PrivateDexPrivacyReservation> {
        let budget = self
            .privacy_budgets
            .get_mut(budget_id)
            .ok_or_else(|| "private DEX unknown privacy budget".to_string())?;
        budget.reserve(units)?;
        let reservation = PrivateDexPrivacyReservation::new(
            budget_id,
            object_kind,
            object_id,
            units,
            self.height,
            expires_at_height,
        )?;
        self.insert_privacy_reservation(reservation.clone())?;
        Ok(reservation)
    }

    pub fn consume_privacy_budget(
        &mut self,
        reservation_id: &str,
        height: u64,
    ) -> PrivateDexResult<()> {
        let reservation = self
            .privacy_reservations
            .get_mut(reservation_id)
            .ok_or_else(|| "private DEX unknown privacy reservation".to_string())?;
        let budget = self
            .privacy_budgets
            .get_mut(&reservation.budget_id)
            .ok_or_else(|| "private DEX unknown privacy budget".to_string())?;
        budget.consume_reserved(reservation.units)?;
        reservation.mark_consumed(height)
    }

    pub fn release_privacy_budget(
        &mut self,
        reservation_id: &str,
        height: u64,
    ) -> PrivateDexResult<()> {
        let reservation = self
            .privacy_reservations
            .get_mut(reservation_id)
            .ok_or_else(|| "private DEX unknown privacy reservation".to_string())?;
        let budget = self
            .privacy_budgets
            .get_mut(&reservation.budget_id)
            .ok_or_else(|| "private DEX unknown privacy budget".to_string())?;
        budget.release_reserved(reservation.units)?;
        reservation.mark_released(height)
    }

    pub fn insert_auction(&mut self, auction: PrivateDexAuction) -> PrivateDexResult<()> {
        auction.validate()?;
        if !self.pairs.contains_key(&auction.pair_id) {
            return Err("private DEX auction references unknown pair".to_string());
        }
        if !self.pq_transcripts.contains_key(&auction.pq_transcript_id) {
            return Err("private DEX auction references unknown PQ transcript".to_string());
        }
        self.auctions.insert(auction.auction_id.clone(), auction);
        Ok(())
    }

    pub fn insert_solver_quote_commitment(
        &mut self,
        quote: PrivateDexSolverQuoteCommitment,
    ) -> PrivateDexResult<()> {
        quote.validate()?;
        if !self.auctions.is_empty() && !self.auctions.contains_key(&quote.auction_id) {
            return Err("private DEX solver quote references unknown auction".to_string());
        }
        if !self.pq_transcripts.contains_key(&quote.pq_transcript_id) {
            return Err("private DEX solver quote references unknown PQ transcript".to_string());
        }
        self.solver_quote_commitments
            .insert(quote.quote_id.clone(), quote);
        Ok(())
    }

    pub fn insert_route_plan(&mut self, route: PrivateDexRoutePlan) -> PrivateDexResult<()> {
        route.validate()?;
        if !self.intents.contains_key(&route.intent_id) {
            return Err("private DEX route references unknown intent".to_string());
        }
        if !self.pq_transcripts.contains_key(&route.pq_transcript_id) {
            return Err("private DEX route references unknown PQ transcript".to_string());
        }
        for pool_id in &route.pool_ids {
            if !self.pools.contains_key(pool_id) {
                return Err("private DEX route references unknown pool".to_string());
            }
        }
        self.route_plans.insert(route.route_id.clone(), route);
        Ok(())
    }

    pub fn insert_quote_reveal(&mut self, reveal: PrivateDexQuoteReveal) -> PrivateDexResult<()> {
        reveal.validate()?;
        if !self.solver_quote_commitments.contains_key(&reveal.quote_id) {
            return Err("private DEX quote reveal references unknown quote".to_string());
        }
        if !self.route_plans.contains_key(&reveal.route_id) {
            return Err("private DEX quote reveal references unknown route".to_string());
        }
        self.quote_reveals.insert(reveal.reveal_id.clone(), reveal);
        Ok(())
    }

    pub fn insert_batch_order(&mut self, batch: PrivateDexBatchOrder) -> PrivateDexResult<()> {
        batch.validate()?;
        if !self.auctions.contains_key(&batch.auction_id) {
            return Err("private DEX batch references unknown auction".to_string());
        }
        for intent_id in &batch.selected_intent_ids {
            if !self.intents.contains_key(intent_id) {
                return Err("private DEX batch references unknown intent".to_string());
            }
        }
        for quote_id in &batch.selected_quote_ids {
            if !self.solver_quote_commitments.contains_key(quote_id) {
                return Err("private DEX batch references unknown quote".to_string());
            }
        }
        for route_id in &batch.selected_route_ids {
            if !self.route_plans.contains_key(route_id) {
                return Err("private DEX batch references unknown route".to_string());
            }
        }
        self.batch_orders
            .insert(batch.batch_order_id.clone(), batch);
        Ok(())
    }

    pub fn insert_clearing_price(
        &mut self,
        clearing: PrivateDexClearingPrice,
    ) -> PrivateDexResult<()> {
        clearing.validate()?;
        if !self.auctions.contains_key(&clearing.auction_id) {
            return Err("private DEX clearing price references unknown auction".to_string());
        }
        if !self.pairs.contains_key(&clearing.pair_id) {
            return Err("private DEX clearing price references unknown pair".to_string());
        }
        self.clearing_prices
            .insert(clearing.clearing_price_id.clone(), clearing);
        Ok(())
    }

    pub fn insert_settlement_manifest(
        &mut self,
        manifest: PrivateDexSettlementManifest,
    ) -> PrivateDexResult<()> {
        manifest.validate()?;
        if !self.auctions.contains_key(&manifest.auction_id) {
            return Err("private DEX settlement references unknown auction".to_string());
        }
        if !self.batch_orders.contains_key(&manifest.batch_order_id) {
            return Err("private DEX settlement references unknown batch".to_string());
        }
        if !self
            .clearing_prices
            .contains_key(&manifest.clearing_price_id)
        {
            return Err("private DEX settlement references unknown clearing price".to_string());
        }
        self.settlement_manifests
            .insert(manifest.manifest_id.clone(), manifest);
        Ok(())
    }

    pub fn insert_twap_observation(
        &mut self,
        observation: PrivateDexTwapObservation,
    ) -> PrivateDexResult<()> {
        observation.validate()?;
        if !self.pools.contains_key(&observation.pool_id) {
            return Err("private DEX TWAP references unknown pool".to_string());
        }
        self.twap_observations
            .insert(observation.observation_id.clone(), observation);
        Ok(())
    }

    pub fn insert_oracle_guard(&mut self, guard: PrivateDexOracleGuard) -> PrivateDexResult<()> {
        guard.validate()?;
        if !self.pools.contains_key(&guard.pool_id) {
            return Err("private DEX oracle guard references unknown pool".to_string());
        }
        self.oracle_guards.insert(guard.guard_id.clone(), guard);
        Ok(())
    }

    pub fn insert_pq_transcript(
        &mut self,
        transcript: PrivateDexPqTranscript,
    ) -> PrivateDexResult<()> {
        transcript.validate()?;
        self.pq_transcripts
            .insert(transcript.transcript_id.clone(), transcript);
        Ok(())
    }

    pub fn insert_circuit_profile(
        &mut self,
        profile: PrivateDexCircuitProfile,
    ) -> PrivateDexResult<()> {
        profile.validate()?;
        self.circuit_profiles
            .insert(profile.profile_id.clone(), profile);
        Ok(())
    }

    pub fn insert_validity_proof(
        &mut self,
        proof: PrivateDexValidityProof,
    ) -> PrivateDexResult<()> {
        proof.validate()?;
        if !self.pq_transcripts.contains_key(&proof.transcript_id) {
            return Err("private DEX validity proof references unknown transcript".to_string());
        }
        if !self
            .circuit_profiles
            .contains_key(&proof.circuit_profile_id)
        {
            return Err(
                "private DEX validity proof references unknown circuit profile".to_string(),
            );
        }
        self.validity_proofs.insert(proof.proof_id.clone(), proof);
        Ok(())
    }

    pub fn insert_low_fee_rebate(
        &mut self,
        rebate: PrivateDexLowFeeRebate,
    ) -> PrivateDexResult<()> {
        rebate.validate()?;
        if !self.route_plans.contains_key(&rebate.route_id) {
            return Err("private DEX low fee rebate references unknown route".to_string());
        }
        if !self.auctions.contains_key(&rebate.auction_id) {
            return Err("private DEX low fee rebate references unknown auction".to_string());
        }
        self.low_fee_rebates
            .insert(rebate.rebate_id.clone(), rebate);
        Ok(())
    }

    pub fn insert_monero_anchor(&mut self, anchor: PrivateDexMoneroAnchor) -> PrivateDexResult<()> {
        anchor.validate()?;
        if !self.pq_transcripts.contains_key(&anchor.pq_transcript_id) {
            return Err("private DEX Monero anchor references unknown PQ transcript".to_string());
        }
        self.monero_anchors.insert(anchor.anchor_id.clone(), anchor);
        Ok(())
    }

    pub fn insert_risk_control(&mut self, control: PrivateDexRiskControl) -> PrivateDexResult<()> {
        control.validate()?;
        self.risk_controls
            .insert(control.control_id.clone(), control);
        Ok(())
    }

    pub fn insert_pause_switch(&mut self, switch: PrivateDexPauseSwitch) -> PrivateDexResult<()> {
        switch.validate()?;
        self.pause_switches.insert(switch.switch_id.clone(), switch);
        Ok(())
    }

    pub fn insert_kill_switch(&mut self, switch: PrivateDexKillSwitch) -> PrivateDexResult<()> {
        switch.validate()?;
        self.kill_switches.insert(switch.kill_id.clone(), switch);
        Ok(())
    }

    pub fn publish_public_record(
        &mut self,
        object_kind: &str,
        object_id: &str,
        payload: &Value,
    ) -> PrivateDexResult<PrivateDexPublicRecord> {
        let record = PrivateDexPublicRecord::new(object_kind, object_id, payload, self.height)?;
        self.public_records
            .insert(record.record_id.clone(), record.clone());
        Ok(record)
    }

    pub fn quote_pool_exact_input(
        &self,
        pool_id: &str,
        asset_in_id: &str,
        amount_in: u64,
    ) -> PrivateDexResult<PrivateDexCfmmQuote> {
        if amount_in == 0 {
            return Err("private DEX quote amount must be positive".to_string());
        }
        self.ensure_pool_trade_enabled(pool_id)?;
        let config = self
            .pool_configs
            .get(pool_id)
            .ok_or_else(|| "private DEX pool config not found".to_string())?;
        let pool = self
            .pools
            .get(pool_id)
            .ok_or_else(|| "private DEX pool state not found".to_string())?;
        let (_, _, asset_out_id) = pool.reserves_for_asset(config, asset_in_id)?;
        let (reserve_in, reserve_out) = pool.virtual_reserves_for_asset(config, asset_in_id)?;
        if reserve_in == 0 || reserve_out == 0 {
            return Err("private DEX pool has no liquidity".to_string());
        }
        let pool_fee_units = bps_mul_floor(amount_in, config.fee_bps);
        let protocol_fee_units = bps_mul_floor(pool_fee_units, config.protocol_fee_share_bps);
        let amount_in_after_fee = amount_in.saturating_sub(pool_fee_units);
        let amount_out = match config.pool_kind {
            PrivateDexPoolKind::ConstantProduct => {
                constant_product_output(amount_in_after_fee, reserve_in, reserve_out)
            }
            PrivateDexPoolKind::Stable => stable_pool_output(
                amount_in_after_fee,
                reserve_in,
                reserve_out,
                config.amplification_bps,
            ),
            PrivateDexPoolKind::Hybrid => hybrid_pool_output(
                amount_in_after_fee,
                reserve_in,
                reserve_out,
                config.amplification_bps,
            ),
        };
        if amount_out == 0 || amount_out >= reserve_out {
            return Err("private DEX quote output is outside pool liquidity".to_string());
        }
        let price_impact_bps =
            price_impact_bps(amount_in_after_fee, amount_out, reserve_in, reserve_out);
        if price_impact_bps > config.max_price_impact_bps {
            return Err("private DEX quote exceeds pool price impact limit".to_string());
        }
        self.enforce_risk_controls(pool_id, amount_in, reserve_in, price_impact_bps)?;
        Ok(PrivateDexCfmmQuote::new(
            pool_id,
            asset_in_id,
            &asset_out_id,
            amount_in,
            amount_in_after_fee,
            amount_out,
            pool_fee_units,
            protocol_fee_units,
            config.fee_bps,
            price_impact_bps,
            reserve_in,
            reserve_out,
        ))
    }

    pub fn quote_route_exact_input(
        &self,
        pool_ids: &[String],
        asset_path: &[String],
        amount_in: u64,
    ) -> PrivateDexResult<Vec<PrivateDexCfmmQuote>> {
        if pool_ids.is_empty() || asset_path.len() != pool_ids.len().saturating_add(1) {
            return Err("private DEX route path is invalid".to_string());
        }
        if pool_ids.len() as u64 > self.config.max_route_hops {
            return Err("private DEX route exceeds hop limit".to_string());
        }
        let mut amount = amount_in;
        let mut quotes = Vec::with_capacity(pool_ids.len());
        for (pool_id, pair) in pool_ids.iter().zip(asset_path.windows(2)) {
            let quote = self.quote_pool_exact_input(pool_id, &pair[0], amount)?;
            if quote.asset_out_id != pair[1] {
                return Err("private DEX route asset path mismatch".to_string());
            }
            amount = quote.amount_out;
            quotes.push(quote);
        }
        Ok(quotes)
    }

    pub fn build_route_plan(
        &self,
        intent_id: &str,
        solver_label: &str,
        pool_ids: Vec<String>,
        asset_path: Vec<String>,
        amount_in: u64,
        worst_case_bps: u64,
        pq_transcript_id: &str,
    ) -> PrivateDexResult<PrivateDexRoutePlan> {
        validate_bps("private DEX route worst case bps", worst_case_bps)?;
        let quotes = self.quote_route_exact_input(&pool_ids, &asset_path, amount_in)?;
        let mut amount = amount_in;
        let mut total_pool_fee_units = 0_u64;
        let mut total_protocol_fee_units = 0_u64;
        let mut aggregate_price_impact_bps = 0_u64;
        let mut legs = Vec::with_capacity(quotes.len());
        for (index, quote) in quotes.iter().enumerate() {
            let pool_before_root = self
                .pools
                .get(&quote.pool_id)
                .ok_or_else(|| "private DEX route quote references unknown pool".to_string())?
                .pool_root();
            let mut simulated_pool = self
                .pools
                .get(&quote.pool_id)
                .ok_or_else(|| "private DEX route quote references unknown pool".to_string())?
                .clone();
            let config = self.pool_configs.get(&quote.pool_id).ok_or_else(|| {
                "private DEX route quote references unknown pool config".to_string()
            })?;
            apply_quote_to_pool(&mut simulated_pool, config, quote, self.height)?;
            let pool_after_root = simulated_pool.pool_root();
            let proof_root = private_dex_payload_root(
                "PRIVATE-DEX-ROUTE-LEG-PROOF",
                &json!({
                    "quote_id": quote.quote_id,
                    "pool_before_root": pool_before_root,
                    "pool_after_root": pool_after_root,
                    "pq_transcript_id": pq_transcript_id,
                }),
            );
            let leg = PrivateDexRouteLeg::new(
                index as u64,
                &quote.pool_id,
                &quote.asset_in_id,
                &quote.asset_out_id,
                quote.amount_in,
                quote.amount_in_after_fee,
                quote.amount_out,
                quote.pool_fee_units,
                quote.protocol_fee_units,
                quote.price_impact_bps,
                &pool_before_root,
                &pool_after_root,
                &proof_root,
            )?;
            total_pool_fee_units = total_pool_fee_units.saturating_add(quote.pool_fee_units);
            total_protocol_fee_units =
                total_protocol_fee_units.saturating_add(quote.protocol_fee_units);
            aggregate_price_impact_bps =
                aggregate_price_impact_bps.saturating_add(quote.price_impact_bps);
            amount = quote.amount_out;
            legs.push(leg);
        }
        PrivateDexRoutePlan::new(
            intent_id,
            solver_label,
            pool_ids,
            asset_path,
            amount_in,
            amount,
            bps_mul_floor(amount, worst_case_bps),
            total_pool_fee_units,
            total_protocol_fee_units,
            aggregate_price_impact_bps.min(PRIVATE_DEX_MAX_BPS),
            self.height,
            self.config.route_ttl_blocks,
            pq_transcript_id,
            legs,
        )
    }

    pub fn ensure_pool_trade_enabled(&self, pool_id: &str) -> PrivateDexResult<()> {
        if self.is_scope_killed(PrivateDexSwitchScope::Global, "private-dex") {
            return Err("private DEX global kill switch is active".to_string());
        }
        if self.is_scope_killed(PrivateDexSwitchScope::Pool, pool_id) {
            return Err("private DEX pool kill switch is active".to_string());
        }
        if self.is_scope_paused(PrivateDexSwitchScope::Global, "private-dex") {
            return Err("private DEX global pause switch is active".to_string());
        }
        if self.is_scope_paused(PrivateDexSwitchScope::Pool, pool_id) {
            return Err("private DEX pool pause switch is active".to_string());
        }
        let pool = self
            .pools
            .get(pool_id)
            .ok_or_else(|| "private DEX pool not found".to_string())?;
        if pool.status != PRIVATE_DEX_STATUS_ACTIVE {
            return Err("private DEX pool is not active".to_string());
        }
        if !self.oracle_allows_pool(pool_id) {
            return Err("private DEX pool oracle guard blocks trading".to_string());
        }
        Ok(())
    }

    pub fn oracle_allows_pool(&self, pool_id: &str) -> bool {
        let guards = self
            .oracle_guards
            .values()
            .filter(|guard| guard.pool_id == pool_id)
            .collect::<Vec<_>>();
        guards.is_empty()
            || guards
                .iter()
                .any(|guard| guard.allows_trading_at(self.height))
    }

    pub fn is_scope_paused(&self, scope: PrivateDexSwitchScope, target_id: &str) -> bool {
        self.pause_switches.values().any(|switch| {
            switch.scope == scope && switch.target_id == target_id && switch.active_at(self.height)
        })
    }

    pub fn is_scope_killed(&self, scope: PrivateDexSwitchScope, target_id: &str) -> bool {
        self.kill_switches
            .values()
            .any(|switch| switch.scope == scope && switch.target_id == target_id && switch.active())
    }

    pub fn enforce_risk_controls(
        &self,
        pool_id: &str,
        amount_in: u64,
        reserve_in: u64,
        price_impact_bps: u64,
    ) -> PrivateDexResult<()> {
        let pair_id = self
            .pool_configs
            .get(pool_id)
            .map(|config| config.pair_id.clone())
            .unwrap_or_default();
        for control in self.risk_controls.values() {
            if !control.active_at(self.height)
                || !(control.applies_to_pool(pool_id) || control.applies_to_pair(&pair_id))
            {
                continue;
            }
            if control.mode.blocks_new_orders() {
                return Err("private DEX risk control blocks trading".to_string());
            }
            if control.max_trade_units > 0 && amount_in > control.max_trade_units {
                return Err("private DEX trade exceeds max trade units".to_string());
            }
            let pool_limit = bps_mul_floor(reserve_in, control.max_trade_bps_of_pool);
            if pool_limit > 0 && amount_in > pool_limit {
                return Err("private DEX trade exceeds pool percentage risk limit".to_string());
            }
            if control.max_price_impact_bps > 0 && price_impact_bps > control.max_price_impact_bps {
                return Err("private DEX trade exceeds price impact risk limit".to_string());
            }
            if control.min_liquidity_units > 0 && reserve_in < control.min_liquidity_units {
                return Err("private DEX pool liquidity is below risk minimum".to_string());
            }
            if control.volume_cap_units > 0
                && control.triggered_volume_units.saturating_add(amount_in)
                    > control.volume_cap_units
            {
                return Err("private DEX trade exceeds risk volume cap".to_string());
            }
        }
        Ok(())
    }

    pub fn best_reveal_for_intent(
        &self,
        intent_id: &str,
    ) -> PrivateDexResult<Option<PrivateDexQuoteReveal>> {
        if !self.intents.contains_key(intent_id) {
            return Err("private DEX best reveal references unknown intent".to_string());
        }
        let best = self
            .quote_reveals
            .values()
            .filter(|reveal| {
                self.route_plans
                    .get(&reveal.route_id)
                    .map(|route| route.intent_id == intent_id)
                    .unwrap_or(false)
            })
            .max_by(|left, right| {
                left.amount_out
                    .cmp(&right.amount_out)
                    .then_with(|| right.solver_fee_units.cmp(&left.solver_fee_units))
                    .then_with(|| left.reveal_id.cmp(&right.reveal_id))
            })
            .cloned();
        Ok(best)
    }

    pub fn active_auction_ids(&self) -> Vec<String> {
        self.auctions
            .values()
            .filter(|auction| {
                matches!(
                    auction.status.as_str(),
                    PRIVATE_DEX_STATUS_COLLECTING
                        | PRIVATE_DEX_STATUS_REVEALING
                        | PRIVATE_DEX_STATUS_MATCHING
                )
            })
            .map(|auction| auction.auction_id.clone())
            .collect()
    }

    pub fn active_private_intent_count(&self) -> u64 {
        self.intents
            .values()
            .filter(|intent| intent.active_at(self.height))
            .count() as u64
    }

    pub fn total_pool_liquidity_units(&self) -> u64 {
        self.pools
            .values()
            .map(|pool| pool.total_liquidity)
            .fold(0_u64, u64::saturating_add)
    }

    pub fn total_locked_privacy_budget_units(&self) -> u64 {
        self.privacy_budgets
            .values()
            .map(|budget| budget.reserved_units)
            .fold(0_u64, u64::saturating_add)
    }

    pub fn active_low_fee_rebate_units(&self) -> u64 {
        self.low_fee_rebates
            .values()
            .filter(|rebate| rebate.active_at(self.height))
            .map(|rebate| rebate.rebate_units)
            .fold(0_u64, u64::saturating_add)
    }

    pub fn install_devnet_oracle_and_twap(
        &mut self,
        pool_id: &str,
        oracle_feed_id: &str,
        reference_price_scaled: u64,
    ) -> PrivateDexResult<()> {
        let pool = self
            .pools
            .get(pool_id)
            .ok_or_else(|| "private DEX devnet oracle references unknown pool".to_string())?;
        let twap_price_x_to_y_scaled = pool.twap_price_x_to_y_scaled.max(1);
        let oracle_price_x_to_y_scaled = pool.oracle_price_x_to_y_scaled;
        let total_liquidity = pool.total_liquidity;
        let twap = PrivateDexTwapObservation::new(
            pool_id,
            self.height,
            self.height
                .saturating_sub(self.config.default_twap_window_blocks),
            self.height.saturating_sub(1),
            twap_price_x_to_y_scaled,
            reciprocal_price_scaled(twap_price_x_to_y_scaled),
            total_liquidity,
            &[
                json!({"height": self.height.saturating_sub(3), "price": twap_price_x_to_y_scaled}),
                json!({"height": self.height.saturating_sub(2), "price": reference_price_scaled}),
                json!({"height": self.height.saturating_sub(1), "price": oracle_price_x_to_y_scaled}),
            ],
        )?;
        self.insert_twap_observation(twap)?;
        let guard = PrivateDexOracleGuard::new(
            pool_id,
            oracle_feed_id,
            reference_price_scaled,
            twap_price_x_to_y_scaled,
            self.config.max_oracle_deviation_bps,
            self.height.saturating_sub(1),
            self.height.saturating_sub(1),
            self.config.max_oracle_staleness_blocks,
            &[
                json!({"source": "devnet-median-1", "height": self.height.saturating_sub(1)}),
                json!({"source": "devnet-median-2", "height": self.height.saturating_sub(2)}),
            ],
        )?;
        self.insert_oracle_guard(guard)?;
        Ok(())
    }

    pub fn config_root(&self) -> String {
        self.config.config_root()
    }

    pub fn pair_root(&self) -> String {
        private_dex_asset_pair_root(&self.pairs.values().cloned().collect::<Vec<_>>())
    }

    pub fn pool_config_root(&self) -> String {
        private_dex_pool_config_root(&self.pool_configs.values().cloned().collect::<Vec<_>>())
    }

    pub fn pool_state_root(&self) -> String {
        private_dex_pool_state_set_root(&self.pools.values().cloned().collect::<Vec<_>>())
    }

    pub fn liquidity_position_root(&self) -> String {
        private_dex_liquidity_position_root(
            &self
                .liquidity_positions
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn intent_root(&self) -> String {
        private_dex_intent_root(&self.intents.values().cloned().collect::<Vec<_>>())
    }

    pub fn route_hint_root(&self) -> String {
        private_dex_route_hint_root(&self.route_hints.values().cloned().collect::<Vec<_>>())
    }

    pub fn privacy_budget_root(&self) -> String {
        private_dex_privacy_budget_root(&self.privacy_budgets.values().cloned().collect::<Vec<_>>())
    }

    pub fn privacy_reservation_root(&self) -> String {
        private_dex_privacy_reservation_root(
            &self
                .privacy_reservations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn auction_root(&self) -> String {
        private_dex_auction_root(&self.auctions.values().cloned().collect::<Vec<_>>())
    }

    pub fn solver_quote_commitment_root(&self) -> String {
        private_dex_solver_quote_commitment_root(
            &self
                .solver_quote_commitments
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn route_plan_root(&self) -> String {
        private_dex_route_plan_root(&self.route_plans.values().cloned().collect::<Vec<_>>())
    }

    pub fn quote_reveal_root(&self) -> String {
        private_dex_quote_reveal_root(&self.quote_reveals.values().cloned().collect::<Vec<_>>())
    }

    pub fn batch_order_root(&self) -> String {
        private_dex_batch_order_root(&self.batch_orders.values().cloned().collect::<Vec<_>>())
    }

    pub fn clearing_price_root(&self) -> String {
        private_dex_clearing_price_root(&self.clearing_prices.values().cloned().collect::<Vec<_>>())
    }

    pub fn settlement_manifest_root(&self) -> String {
        private_dex_settlement_manifest_root(
            &self
                .settlement_manifests
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn twap_observation_root(&self) -> String {
        private_dex_twap_observation_root(
            &self.twap_observations.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn oracle_guard_root(&self) -> String {
        private_dex_oracle_guard_root(&self.oracle_guards.values().cloned().collect::<Vec<_>>())
    }

    pub fn pq_transcript_root(&self) -> String {
        private_dex_pq_transcript_root(&self.pq_transcripts.values().cloned().collect::<Vec<_>>())
    }

    pub fn circuit_profile_root(&self) -> String {
        private_dex_circuit_profile_root(
            &self.circuit_profiles.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn validity_proof_root(&self) -> String {
        private_dex_validity_proof_set_root(
            &self.validity_proofs.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn low_fee_rebate_root(&self) -> String {
        private_dex_low_fee_rebate_root(&self.low_fee_rebates.values().cloned().collect::<Vec<_>>())
    }

    pub fn monero_anchor_root(&self) -> String {
        private_dex_monero_anchor_root(&self.monero_anchors.values().cloned().collect::<Vec<_>>())
    }

    pub fn risk_control_root(&self) -> String {
        private_dex_risk_control_root(&self.risk_controls.values().cloned().collect::<Vec<_>>())
    }

    pub fn pause_switch_root(&self) -> String {
        private_dex_pause_switch_root(&self.pause_switches.values().cloned().collect::<Vec<_>>())
    }

    pub fn kill_switch_root(&self) -> String {
        private_dex_kill_switch_root(&self.kill_switches.values().cloned().collect::<Vec<_>>())
    }

    pub fn public_record_root(&self) -> String {
        private_dex_public_record_root(&self.public_records.values().cloned().collect::<Vec<_>>())
    }

    pub fn liquidity_surface_root(&self) -> String {
        merkle_root(
            "PRIVATE-DEX-LIQUIDITY-SURFACE",
            &[json!({
                "pool_config_root": self.pool_config_root(),
                "pool_state_root": self.pool_state_root(),
                "liquidity_position_root": self.liquidity_position_root(),
                "total_pool_liquidity_units": self.total_pool_liquidity_units(),
            })],
        )
    }

    pub fn private_order_surface_root(&self) -> String {
        merkle_root(
            "PRIVATE-DEX-ORDER-SURFACE",
            &[json!({
                "intent_root": self.intent_root(),
                "route_hint_root": self.route_hint_root(),
                "privacy_budget_root": self.privacy_budget_root(),
                "privacy_reservation_root": self.privacy_reservation_root(),
                "active_private_intent_count": self.active_private_intent_count(),
                "locked_privacy_budget_units": self.total_locked_privacy_budget_units(),
            })],
        )
    }

    pub fn auction_surface_root(&self) -> String {
        merkle_root(
            "PRIVATE-DEX-AUCTION-SURFACE",
            &[json!({
                "auction_root": self.auction_root(),
                "solver_quote_commitment_root": self.solver_quote_commitment_root(),
                "quote_reveal_root": self.quote_reveal_root(),
                "batch_order_root": self.batch_order_root(),
                "clearing_price_root": self.clearing_price_root(),
                "active_auction_ids": self.active_auction_ids(),
            })],
        )
    }

    pub fn proof_surface_root(&self) -> String {
        merkle_root(
            "PRIVATE-DEX-PROOF-SURFACE",
            &[json!({
                "pq_transcript_root": self.pq_transcript_root(),
                "circuit_profile_root": self.circuit_profile_root(),
                "validity_proof_root": self.validity_proof_root(),
                "monero_anchor_root": self.monero_anchor_root(),
            })],
        )
    }

    pub fn guard_surface_root(&self) -> String {
        merkle_root(
            "PRIVATE-DEX-GUARD-SURFACE",
            &[json!({
                "twap_observation_root": self.twap_observation_root(),
                "oracle_guard_root": self.oracle_guard_root(),
                "risk_control_root": self.risk_control_root(),
                "pause_switch_root": self.pause_switch_root(),
                "kill_switch_root": self.kill_switch_root(),
            })],
        )
    }

    pub fn state_roots(&self) -> PrivateDexStateRoots {
        PrivateDexStateRoots {
            config_root: self.config_root(),
            pair_root: self.pair_root(),
            pool_config_root: self.pool_config_root(),
            pool_state_root: self.pool_state_root(),
            liquidity_position_root: self.liquidity_position_root(),
            intent_root: self.intent_root(),
            route_hint_root: self.route_hint_root(),
            privacy_budget_root: self.privacy_budget_root(),
            privacy_reservation_root: self.privacy_reservation_root(),
            auction_root: self.auction_root(),
            solver_quote_commitment_root: self.solver_quote_commitment_root(),
            route_plan_root: self.route_plan_root(),
            quote_reveal_root: self.quote_reveal_root(),
            batch_order_root: self.batch_order_root(),
            clearing_price_root: self.clearing_price_root(),
            settlement_manifest_root: self.settlement_manifest_root(),
            twap_observation_root: self.twap_observation_root(),
            oracle_guard_root: self.oracle_guard_root(),
            pq_transcript_root: self.pq_transcript_root(),
            circuit_profile_root: self.circuit_profile_root(),
            validity_proof_root: self.validity_proof_root(),
            low_fee_rebate_root: self.low_fee_rebate_root(),
            monero_anchor_root: self.monero_anchor_root(),
            risk_control_root: self.risk_control_root(),
            pause_switch_root: self.pause_switch_root(),
            kill_switch_root: self.kill_switch_root(),
            public_record_root: self.public_record_root(),
        }
    }

    pub fn state_root(&self) -> String {
        private_dex_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("private DEX state record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.state_roots();
        json!({
            "kind": "private_dex_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DEX_PROTOCOL_VERSION,
            "height": self.height,
            "nonce": self.nonce,
            "config": self.config.public_record(),
            "pair_count": self.pairs.len() as u64,
            "pool_config_count": self.pool_configs.len() as u64,
            "pool_count": self.pools.len() as u64,
            "liquidity_position_count": self.liquidity_positions.len() as u64,
            "intent_count": self.intents.len() as u64,
            "route_hint_count": self.route_hints.len() as u64,
            "privacy_budget_count": self.privacy_budgets.len() as u64,
            "privacy_reservation_count": self.privacy_reservations.len() as u64,
            "auction_count": self.auctions.len() as u64,
            "solver_quote_commitment_count": self.solver_quote_commitments.len() as u64,
            "route_plan_count": self.route_plans.len() as u64,
            "quote_reveal_count": self.quote_reveals.len() as u64,
            "batch_order_count": self.batch_orders.len() as u64,
            "clearing_price_count": self.clearing_prices.len() as u64,
            "settlement_manifest_count": self.settlement_manifests.len() as u64,
            "twap_observation_count": self.twap_observations.len() as u64,
            "oracle_guard_count": self.oracle_guards.len() as u64,
            "pq_transcript_count": self.pq_transcripts.len() as u64,
            "circuit_profile_count": self.circuit_profiles.len() as u64,
            "validity_proof_count": self.validity_proofs.len() as u64,
            "low_fee_rebate_count": self.low_fee_rebates.len() as u64,
            "monero_anchor_count": self.monero_anchors.len() as u64,
            "risk_control_count": self.risk_controls.len() as u64,
            "pause_switch_count": self.pause_switches.len() as u64,
            "kill_switch_count": self.kill_switches.len() as u64,
            "public_record_count": self.public_records.len() as u64,
            "active_auction_ids": self.active_auction_ids(),
            "active_private_intent_count": self.active_private_intent_count(),
            "total_pool_liquidity_units": self.total_pool_liquidity_units(),
            "locked_privacy_budget_units": self.total_locked_privacy_budget_units(),
            "active_low_fee_rebate_units": self.active_low_fee_rebate_units(),
            "liquidity_surface_root": self.liquidity_surface_root(),
            "private_order_surface_root": self.private_order_surface_root(),
            "auction_surface_root": self.auction_surface_root(),
            "proof_surface_root": self.proof_surface_root(),
            "guard_surface_root": self.guard_surface_root(),
            "roots": roots.public_record(),
        })
    }

    pub fn validate(&self) -> PrivateDexResult<String> {
        self.config.validate()?;
        for (id, pair) in &self.pairs {
            if id != &pair.pair_id {
                return Err("private DEX pair map key mismatch".to_string());
            }
            pair.validate()?;
        }
        for (id, config) in &self.pool_configs {
            if id != &config.pool_id {
                return Err("private DEX pool config map key mismatch".to_string());
            }
            config.validate()?;
            if !self.pairs.contains_key(&config.pair_id) {
                return Err("private DEX pool config references unknown pair".to_string());
            }
        }
        for (id, pool) in &self.pools {
            if id != &pool.pool_id {
                return Err("private DEX pool map key mismatch".to_string());
            }
            pool.validate()?;
            if !self.pool_configs.contains_key(&pool.pool_id) {
                return Err("private DEX pool references unknown config".to_string());
            }
        }
        for (id, position) in &self.liquidity_positions {
            if id != &position.position_id {
                return Err("private DEX LP map key mismatch".to_string());
            }
            position.validate()?;
        }
        for (id, budget) in &self.privacy_budgets {
            if id != &budget.budget_id {
                return Err("private DEX privacy budget map key mismatch".to_string());
            }
            budget.validate()?;
        }
        for (id, transcript) in &self.pq_transcripts {
            if id != &transcript.transcript_id {
                return Err("private DEX transcript map key mismatch".to_string());
            }
            transcript.validate()?;
        }
        for (id, intent) in &self.intents {
            if id != &intent.intent_id {
                return Err("private DEX intent map key mismatch".to_string());
            }
            intent.validate()?;
            if !self.pairs.contains_key(&intent.pair_id) {
                return Err("private DEX intent references unknown pair".to_string());
            }
        }
        for (id, hint) in &self.route_hints {
            if id != &hint.hint_id {
                return Err("private DEX route hint map key mismatch".to_string());
            }
            hint.validate()?;
            if !self.intents.contains_key(&hint.intent_id) {
                return Err("private DEX route hint references unknown intent".to_string());
            }
        }
        for (id, reservation) in &self.privacy_reservations {
            if id != &reservation.reservation_id {
                return Err("private DEX privacy reservation map key mismatch".to_string());
            }
            reservation.validate()?;
            if !self.privacy_budgets.contains_key(&reservation.budget_id) {
                return Err("private DEX privacy reservation references unknown budget".to_string());
            }
        }
        for (id, auction) in &self.auctions {
            if id != &auction.auction_id {
                return Err("private DEX auction map key mismatch".to_string());
            }
            auction.validate()?;
        }
        for (id, quote) in &self.solver_quote_commitments {
            if id != &quote.quote_id {
                return Err("private DEX quote map key mismatch".to_string());
            }
            quote.validate()?;
        }
        for (id, route) in &self.route_plans {
            if id != &route.route_id {
                return Err("private DEX route map key mismatch".to_string());
            }
            route.validate()?;
        }
        for (id, reveal) in &self.quote_reveals {
            if id != &reveal.reveal_id {
                return Err("private DEX reveal map key mismatch".to_string());
            }
            reveal.validate()?;
        }
        for (id, batch) in &self.batch_orders {
            if id != &batch.batch_order_id {
                return Err("private DEX batch map key mismatch".to_string());
            }
            batch.validate()?;
        }
        for (id, clearing) in &self.clearing_prices {
            if id != &clearing.clearing_price_id {
                return Err("private DEX clearing map key mismatch".to_string());
            }
            clearing.validate()?;
        }
        for (id, manifest) in &self.settlement_manifests {
            if id != &manifest.manifest_id {
                return Err("private DEX settlement map key mismatch".to_string());
            }
            manifest.validate()?;
        }
        for record in self.public_records.values() {
            record.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn private_dex_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn private_dex_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-DEX-STATE-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn private_dex_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn private_dex_string_set_root(domain: &str, values: &[String]) -> String {
    let mut leaves = values.to_vec();
    leaves.sort();
    merkle_root(
        domain,
        &leaves.into_iter().map(Value::String).collect::<Vec<_>>(),
    )
}

pub fn private_dex_account_commitment(label: &str) -> String {
    domain_hash(
        "PRIVATE-DEX-ACCOUNT-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn private_dex_solver_commitment(label: &str) -> String {
    domain_hash(
        "PRIVATE-DEX-SOLVER-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn private_dex_asset_commitment(asset_id: &str) -> String {
    domain_hash(
        "PRIVATE-DEX-ASSET-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(asset_id)],
        32,
    )
}

pub fn private_dex_pair_commitment(base_asset_id: &str, quote_asset_id: &str) -> String {
    domain_hash(
        "PRIVATE-DEX-PAIR-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(base_asset_id),
            HashPart::Str(quote_asset_id),
        ],
        32,
    )
}

pub fn private_dex_amount_commitment(amount_units: u64, blinding: &str) -> String {
    domain_hash(
        "PRIVATE-DEX-AMOUNT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(amount_units as i128),
            HashPart::Str(blinding),
        ],
        32,
    )
}

pub fn private_dex_price_commitment(numerator: u64, denominator: u64, blinding: &str) -> String {
    domain_hash(
        "PRIVATE-DEX-PRICE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(numerator as i128),
            HashPart::Int(denominator as i128),
            HashPart::Str(blinding),
        ],
        32,
    )
}

pub fn private_dex_blinding(label: &str, nonce: u64, field: &str) -> String {
    domain_hash(
        "PRIVATE-DEX-BLINDING",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(nonce as i128),
            HashPart::Str(field),
        ],
        32,
    )
}

pub fn private_dex_nullifier_hash(label: &str, nonce: u64, context: &str) -> String {
    domain_hash(
        "PRIVATE-DEX-NULLIFIER-HASH",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(nonce as i128),
            HashPart::Str(context),
        ],
        32,
    )
}

pub fn private_dex_note_commitment(label: &str) -> String {
    domain_hash(
        "PRIVATE-DEX-NOTE-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn private_dex_amount_bucket(amount_units: u64) -> u64 {
    if amount_units == 0 {
        0
    } else if amount_units <= 1_000 {
        1_000
    } else {
        amount_units.next_power_of_two()
    }
}

pub fn private_dex_pair_id(
    base_asset_id: &str,
    quote_asset_id: &str,
    tick_size_units: u64,
    lot_size_units: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-DEX-PAIR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(base_asset_id),
            HashPart::Str(quote_asset_id),
            HashPart::Int(tick_size_units as i128),
            HashPart::Int(lot_size_units as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_dex_pool_id(
    pair_id: &str,
    pool_kind: PrivateDexPoolKind,
    asset_x_id: &str,
    asset_y_id: &str,
    lp_asset_id: &str,
    fee_bps: u64,
    amplification_bps: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-DEX-CFMM-POOL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pair_id),
            HashPart::Str(pool_kind.as_str()),
            HashPart::Str(asset_x_id),
            HashPart::Str(asset_y_id),
            HashPart::Str(lp_asset_id),
            HashPart::Int(fee_bps as i128),
            HashPart::Int(amplification_bps as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn private_dex_pool_invariant_root(
    pool_id: &str,
    reserve_x: u64,
    reserve_y: u64,
    virtual_reserve_x: u64,
    virtual_reserve_y: u64,
    total_liquidity: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEX-CFMM-INVARIANT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Int(reserve_x as i128),
            HashPart::Int(reserve_y as i128),
            HashPart::Int(virtual_reserve_x as i128),
            HashPart::Int(virtual_reserve_y as i128),
            HashPart::Int(total_liquidity as i128),
        ],
        32,
    )
}

pub fn private_dex_pool_state_root(pool: &PrivateDexCfmmPoolState) -> String {
    private_dex_payload_root("PRIVATE-DEX-CFMM-POOL-STATE-ROOT", &pool.public_record())
}

pub fn private_dex_liquidity_position_id(
    owner_commitment: &str,
    pool_id: &str,
    liquidity_units: u64,
    lower_price_bucket: u64,
    upper_price_bucket: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEX-LIQUIDITY-POSITION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Str(pool_id),
            HashPart::Int(liquidity_units as i128),
            HashPart::Int(lower_price_bucket as i128),
            HashPart::Int(upper_price_bucket as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_dex_transcript_domain_separator(
    purpose: PrivateDexTranscriptPurpose,
    circuit_family: PrivateDexCircuitFamily,
) -> String {
    domain_hash(
        "PRIVATE-DEX-PQ-TRANSCRIPT-DOMAIN",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(purpose.as_str()),
            HashPart::Str(circuit_family.as_str()),
            HashPart::Str(PRIVATE_DEX_TRANSCRIPT_SCHEME),
        ],
        32,
    )
}

pub fn private_dex_signature_set_root(
    domain: &str,
    signer_labels: &[String],
    domain_separator: &str,
) -> String {
    let leaves = signer_labels
        .iter()
        .map(|label| {
            Value::String(domain_hash(
                domain,
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(label),
                    HashPart::Str(domain_separator),
                ],
                32,
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn private_dex_aggregate_signature_root(
    ml_dsa_signature_root: &str,
    slh_dsa_signature_root: &str,
    kem_ciphertext_root: &str,
    input_root: &str,
    challenge_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-DEX-PQ-AGGREGATE-SIGNATURE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(ml_dsa_signature_root),
            HashPart::Str(slh_dsa_signature_root),
            HashPart::Str(kem_ciphertext_root),
            HashPart::Str(input_root),
            HashPart::Str(challenge_root),
        ],
        32,
    )
}

pub fn private_dex_pq_transcript_id(
    purpose: PrivateDexTranscriptPurpose,
    circuit_family: PrivateDexCircuitFamily,
    session_label_commitment: &str,
    input_root: &str,
    challenge_root: &str,
    aggregate_signature_root: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEX-PQ-TRANSCRIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(purpose.as_str()),
            HashPart::Str(circuit_family.as_str()),
            HashPart::Str(session_label_commitment),
            HashPart::Str(input_root),
            HashPart::Str(challenge_root),
            HashPart::Str(aggregate_signature_root),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_dex_circuit_profile_id(
    circuit_family: PrivateDexCircuitFamily,
    proof_system: &str,
    version: u64,
    verifying_key_root: &str,
    parameter_root: &str,
    public_input_schema_root: &str,
    private_witness_schema_root: &str,
    recursion_depth: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEX-CIRCUIT-PROFILE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(circuit_family.as_str()),
            HashPart::Str(proof_system),
            HashPart::Int(version as i128),
            HashPart::Str(verifying_key_root),
            HashPart::Str(parameter_root),
            HashPart::Str(public_input_schema_root),
            HashPart::Str(private_witness_schema_root),
            HashPart::Int(recursion_depth as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_dex_validity_proof_root(
    transcript_id: &str,
    circuit_profile_id: &str,
    object_id: &str,
    public_input_root: &str,
    private_witness_commitment: &str,
    recursive_accumulator_root: &str,
    verifier_manifest_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-DEX-VALIDITY-PROOF-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(transcript_id),
            HashPart::Str(circuit_profile_id),
            HashPart::Str(object_id),
            HashPart::Str(public_input_root),
            HashPart::Str(private_witness_commitment),
            HashPart::Str(recursive_accumulator_root),
            HashPart::Str(verifier_manifest_root),
        ],
        32,
    )
}

pub fn private_dex_validity_proof_id(
    transcript_id: &str,
    circuit_profile_id: &str,
    object_id: &str,
    proof_root: &str,
    verified_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEX-VALIDITY-PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(transcript_id),
            HashPart::Str(circuit_profile_id),
            HashPart::Str(object_id),
            HashPart::Str(proof_root),
            HashPart::Int(verified_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_dex_intent_public_input_root(
    pair_id: &str,
    side: PrivateDexOrderSide,
    order_kind: PrivateDexOrderKind,
    asset_in_commitment: &str,
    asset_out_commitment: &str,
    amount_in_bucket: u64,
    amount_out_min_bucket: u64,
    max_slippage_bps: u64,
    route_hint_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-DEX-INTENT-PUBLIC-INPUT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pair_id),
            HashPart::Str(side.as_str()),
            HashPart::Str(order_kind.as_str()),
            HashPart::Str(asset_in_commitment),
            HashPart::Str(asset_out_commitment),
            HashPart::Int(amount_in_bucket as i128),
            HashPart::Int(amount_out_min_bucket as i128),
            HashPart::Int(max_slippage_bps as i128),
            HashPart::Str(route_hint_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_dex_intent_id(
    owner_commitment: &str,
    pair_id: &str,
    side: PrivateDexOrderSide,
    order_kind: PrivateDexOrderKind,
    asset_in_commitment: &str,
    asset_out_commitment: &str,
    amount_in_commitment: &str,
    amount_out_min_commitment: &str,
    limit_price_commitment: &str,
    route_hint_root: &str,
    deadline_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEX-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Str(pair_id),
            HashPart::Str(side.as_str()),
            HashPart::Str(order_kind.as_str()),
            HashPart::Str(asset_in_commitment),
            HashPart::Str(asset_out_commitment),
            HashPart::Str(amount_in_commitment),
            HashPart::Str(amount_out_min_commitment),
            HashPart::Str(limit_price_commitment),
            HashPart::Str(route_hint_root),
            HashPart::Int(deadline_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_dex_route_hint_id(
    intent_id: &str,
    venue_commitment: &str,
    hop_commitment_root: &str,
    route_ciphertext_root: &str,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEX-ROUTE-HINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(venue_commitment),
            HashPart::Str(hop_commitment_root),
            HashPart::Str(route_ciphertext_root),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

pub fn private_dex_route_hop_root(route_hops: &[Value]) -> String {
    let leaves = route_hops
        .iter()
        .enumerate()
        .map(|(index, hop)| {
            json!({
                "index": index as u64,
                "hop_root": private_dex_payload_root("PRIVATE-DEX-ROUTE-HOP", hop),
            })
        })
        .collect::<Vec<_>>();
    merkle_root("PRIVATE-DEX-ROUTE-HOP-ROOT", &leaves)
}

pub fn private_dex_privacy_budget_id(
    owner_commitment: &str,
    epoch: u64,
    epoch_start_height: u64,
    epoch_end_height: u64,
    total_units: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEX-PRIVACY-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Int(epoch as i128),
            HashPart::Int(epoch_start_height as i128),
            HashPart::Int(epoch_end_height as i128),
            HashPart::Int(total_units as i128),
        ],
        32,
    )
}

pub fn private_dex_privacy_reservation_id(
    budget_id: &str,
    object_kind: &str,
    object_id: &str,
    units: u64,
    reserved_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEX-PRIVACY-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(budget_id),
            HashPart::Str(object_kind),
            HashPart::Str(object_id),
            HashPart::Int(units as i128),
            HashPart::Int(reserved_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

pub fn private_dex_ordering_seed(context: &str, height: u64, root: &str) -> String {
    domain_hash(
        "PRIVATE-DEX-ORDERING-SEED",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(context),
            HashPart::Int(height as i128),
            HashPart::Str(root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_dex_auction_id(
    market_id: &str,
    pair_id: &str,
    pair_commitment: &str,
    intent_root: &str,
    commit_start_height: u64,
    commit_end_height: u64,
    ordering_seed: &str,
) -> String {
    domain_hash(
        "PRIVATE-DEX-AUCTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(pair_id),
            HashPart::Str(pair_commitment),
            HashPart::Str(intent_root),
            HashPart::Int(commit_start_height as i128),
            HashPart::Int(commit_end_height as i128),
            HashPart::Str(ordering_seed),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_dex_quote_commitment_hash(
    auction_id: &str,
    solver_commitment: &str,
    route_commitment: &str,
    asset_pair_commitment: &str,
    amount_in_commitment: &str,
    amount_out_commitment: &str,
    clearing_price_commitment: &str,
    solver_fee_commitment: &str,
    surplus_commitment: &str,
    pq_transcript_id: &str,
    quote_secret: &str,
) -> String {
    domain_hash(
        "PRIVATE-DEX-SOLVER-QUOTE-COMMITMENT-HASH",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(solver_commitment),
            HashPart::Str(route_commitment),
            HashPart::Str(asset_pair_commitment),
            HashPart::Str(amount_in_commitment),
            HashPart::Str(amount_out_commitment),
            HashPart::Str(clearing_price_commitment),
            HashPart::Str(solver_fee_commitment),
            HashPart::Str(surplus_commitment),
            HashPart::Str(pq_transcript_id),
            HashPart::Str(quote_secret),
        ],
        32,
    )
}

pub fn private_dex_solver_quote_id(
    auction_id: &str,
    solver_commitment: &str,
    quote_commitment: &str,
    committed_at_height: u64,
    reveal_deadline_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEX-SOLVER-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(solver_commitment),
            HashPart::Str(quote_commitment),
            HashPart::Int(committed_at_height as i128),
            HashPart::Int(reveal_deadline_height as i128),
        ],
        32,
    )
}

pub fn private_dex_cfmm_quote_id(
    pool_id: &str,
    asset_in_id: &str,
    asset_out_id: &str,
    amount_in: u64,
    amount_out: u64,
    fee_bps: u64,
    reserve_in_before: u64,
    reserve_out_before: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEX-CFMM-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(asset_in_id),
            HashPart::Str(asset_out_id),
            HashPart::Int(amount_in as i128),
            HashPart::Int(amount_out as i128),
            HashPart::Int(fee_bps as i128),
            HashPart::Int(reserve_in_before as i128),
            HashPart::Int(reserve_out_before as i128),
        ],
        32,
    )
}

pub fn private_dex_route_commitment(pool_ids: &[String], asset_path: &[String]) -> String {
    let pool_leaves = pool_ids
        .iter()
        .enumerate()
        .map(|(index, pool_id)| json!({"index": index as u64, "pool_id": pool_id}))
        .collect::<Vec<_>>();
    let asset_leaves = asset_path
        .iter()
        .enumerate()
        .map(|(index, asset_id)| json!({"index": index as u64, "asset_id": asset_id}))
        .collect::<Vec<_>>();
    let pool_root = merkle_root("PRIVATE-DEX-ROUTE-POOL-PATH", &pool_leaves);
    let asset_root = merkle_root("PRIVATE-DEX-ROUTE-ASSET-PATH", &asset_leaves);
    domain_hash(
        "PRIVATE-DEX-ROUTE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&pool_root),
            HashPart::Str(&asset_root),
            HashPart::Int(pool_ids.len() as i128),
            HashPart::Int(asset_path.len() as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_dex_route_leg_id(
    index: u64,
    pool_id: &str,
    asset_in_id: &str,
    asset_out_id: &str,
    amount_in: u64,
    amount_out: u64,
    pool_before_root: &str,
    pool_after_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-DEX-ROUTE-LEG-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(index as i128),
            HashPart::Str(pool_id),
            HashPart::Str(asset_in_id),
            HashPart::Str(asset_out_id),
            HashPart::Int(amount_in as i128),
            HashPart::Int(amount_out as i128),
            HashPart::Str(pool_before_root),
            HashPart::Str(pool_after_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_dex_route_plan_id(
    intent_id: &str,
    solver_commitment: &str,
    route_commitment: &str,
    amount_in: u64,
    expected_amount_out: u64,
    worst_case_amount_out: u64,
    created_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEX-ROUTE-PLAN-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(solver_commitment),
            HashPart::Str(route_commitment),
            HashPart::Int(amount_in as i128),
            HashPart::Int(expected_amount_out as i128),
            HashPart::Int(worst_case_amount_out as i128),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn private_dex_quote_reveal_id(
    quote_id: &str,
    solver_commitment: &str,
    route_id: &str,
    route_plan_root: &str,
    quote_secret_root: &str,
    revealed_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEX-QUOTE-REVEAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(quote_id),
            HashPart::Str(solver_commitment),
            HashPart::Str(route_id),
            HashPart::Str(route_plan_root),
            HashPart::Str(quote_secret_root),
            HashPart::Int(revealed_at_height as i128),
        ],
        32,
    )
}

pub fn private_dex_mev_order_key(auction_id: &str, ordering_seed: &str, object_id: &str) -> String {
    domain_hash(
        "PRIVATE-DEX-MEV-ORDER-KEY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(ordering_seed),
            HashPart::Str(object_id),
        ],
        32,
    )
}

pub fn private_dex_mev_resistant_order(
    auction_id: &str,
    ordering_seed: &str,
    object_ids: &[String],
) -> Vec<String> {
    let mut keyed = object_ids
        .iter()
        .map(|object_id| {
            (
                private_dex_mev_order_key(auction_id, ordering_seed, object_id),
                object_id.clone(),
            )
        })
        .collect::<Vec<_>>();
    keyed.sort();
    keyed.into_iter().map(|(_, object_id)| object_id).collect()
}

pub fn private_dex_batch_tie_breaker_root(
    auction_id: &str,
    ordering_seed: &str,
    intent_ids: &[String],
    quote_ids: &[String],
    route_ids: &[String],
) -> String {
    let mut leaves = Vec::new();
    for object_id in intent_ids {
        leaves.push(json!({
            "object_kind": "intent",
            "object_id": object_id,
            "order_key": private_dex_mev_order_key(auction_id, ordering_seed, object_id),
        }));
    }
    for object_id in quote_ids {
        leaves.push(json!({
            "object_kind": "quote",
            "object_id": object_id,
            "order_key": private_dex_mev_order_key(auction_id, ordering_seed, object_id),
        }));
    }
    for object_id in route_ids {
        leaves.push(json!({
            "object_kind": "route",
            "object_id": object_id,
            "order_key": private_dex_mev_order_key(auction_id, ordering_seed, object_id),
        }));
    }
    merkle_root("PRIVATE-DEX-BATCH-TIE-BREAKER", &leaves)
}

pub fn private_dex_batch_order_id(
    auction_id: &str,
    batch_height: u64,
    ordering_seed: &str,
    intent_order_root: &str,
    quote_order_root: &str,
    route_order_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-DEX-BATCH-ORDER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Int(batch_height as i128),
            HashPart::Str(ordering_seed),
            HashPart::Str(intent_order_root),
            HashPart::Str(quote_order_root),
            HashPart::Str(route_order_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_dex_clearing_price_id(
    auction_id: &str,
    pair_id: &str,
    price_numerator: u64,
    price_denominator: u64,
    total_input_units: u64,
    total_output_units: u64,
    solver_commitment: &str,
    route_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-DEX-CLEARING-PRICE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(pair_id),
            HashPart::Int(price_numerator as i128),
            HashPart::Int(price_denominator as i128),
            HashPart::Int(total_input_units as i128),
            HashPart::Int(total_output_units as i128),
            HashPart::Str(solver_commitment),
            HashPart::Str(route_root),
        ],
        32,
    )
}

pub fn private_dex_settlement_fill_id(
    intent_id: &str,
    quote_id: &str,
    route_id: &str,
    solver_commitment: &str,
    input_nullifier_commitment: &str,
    output_note_commitment: &str,
    fee_commitment: &str,
) -> String {
    domain_hash(
        "PRIVATE-DEX-SETTLEMENT-FILL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(quote_id),
            HashPart::Str(route_id),
            HashPart::Str(solver_commitment),
            HashPart::Str(input_nullifier_commitment),
            HashPart::Str(output_note_commitment),
            HashPart::Str(fee_commitment),
        ],
        32,
    )
}

pub fn private_dex_settlement_manifest_id(
    auction_id: &str,
    batch_order_id: &str,
    clearing_price_id: &str,
    winning_solver_commitment: &str,
    fill_root: &str,
    settlement_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEX-SETTLEMENT-MANIFEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(batch_order_id),
            HashPart::Str(clearing_price_id),
            HashPart::Str(winning_solver_commitment),
            HashPart::Str(fill_root),
            HashPart::Int(settlement_height as i128),
        ],
        32,
    )
}

pub fn private_dex_twap_observation_id(
    pool_id: &str,
    block_height: u64,
    window_start_height: u64,
    window_end_height: u64,
    price_x_to_y_scaled: u64,
    price_y_to_x_scaled: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEX-TWAP-OBSERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Int(block_height as i128),
            HashPart::Int(window_start_height as i128),
            HashPart::Int(window_end_height as i128),
            HashPart::Int(price_x_to_y_scaled as i128),
            HashPart::Int(price_y_to_x_scaled as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_dex_oracle_guard_id(
    pool_id: &str,
    oracle_feed_id: &str,
    reference_price_scaled: u64,
    twap_price_scaled: u64,
    max_deviation_bps: u64,
    last_oracle_height: u64,
    last_twap_height: u64,
    evidence_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-DEX-ORACLE-GUARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(oracle_feed_id),
            HashPart::Int(reference_price_scaled as i128),
            HashPart::Int(twap_price_scaled as i128),
            HashPart::Int(max_deviation_bps as i128),
            HashPart::Int(last_oracle_height as i128),
            HashPart::Int(last_twap_height as i128),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_dex_risk_control_id(
    scope: PrivateDexSwitchScope,
    target_id: &str,
    mode: PrivateDexRiskMode,
    max_trade_units: u64,
    max_trade_bps_of_pool: u64,
    max_price_impact_bps: u64,
    min_liquidity_units: u64,
    volume_window_blocks: u64,
    volume_cap_units: u64,
    reason_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-DEX-RISK-CONTROL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope.as_str()),
            HashPart::Str(target_id),
            HashPart::Str(mode.as_str()),
            HashPart::Int(max_trade_units as i128),
            HashPart::Int(max_trade_bps_of_pool as i128),
            HashPart::Int(max_price_impact_bps as i128),
            HashPart::Int(min_liquidity_units as i128),
            HashPart::Int(volume_window_blocks as i128),
            HashPart::Int(volume_cap_units as i128),
            HashPart::Str(reason_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_dex_low_fee_rebate_id(
    route_id: &str,
    auction_id: &str,
    lane_id: &str,
    sponsor_commitment: &str,
    fee_asset_id: &str,
    gross_fee_units: u64,
    eligible_fee_units: u64,
    rebate_bps: u64,
    created_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEX-LOW-FEE-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(route_id),
            HashPart::Str(auction_id),
            HashPart::Str(lane_id),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(fee_asset_id),
            HashPart::Int(gross_fee_units as i128),
            HashPart::Int(eligible_fee_units as i128),
            HashPart::Int(rebate_bps as i128),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_dex_monero_anchor_id(
    monero_network: &str,
    reserve_asset_id: &str,
    view_key_commitment: &str,
    txid_root: &str,
    output_commitment_root: &str,
    key_image_root: &str,
    reserve_proof_root: &str,
    observed_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEX-MONERO-ANCHOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(monero_network),
            HashPart::Str(reserve_asset_id),
            HashPart::Str(view_key_commitment),
            HashPart::Str(txid_root),
            HashPart::Str(output_commitment_root),
            HashPart::Str(key_image_root),
            HashPart::Str(reserve_proof_root),
            HashPart::Int(observed_height as i128),
        ],
        32,
    )
}

pub fn private_dex_pause_switch_id(
    scope: PrivateDexSwitchScope,
    target_id: &str,
    paused: bool,
    reason_root: &str,
    set_by_commitment: &str,
    set_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEX-PAUSE-SWITCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope.as_str()),
            HashPart::Str(target_id),
            HashPart::Str(if paused { "paused" } else { "unpaused" }),
            HashPart::Str(reason_root),
            HashPart::Str(set_by_commitment),
            HashPart::Int(set_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_dex_kill_switch_id(
    scope: PrivateDexSwitchScope,
    target_id: &str,
    killed: bool,
    requires_governance_unwind: bool,
    reason_root: &str,
    set_by_commitment: &str,
    set_at_height: u64,
    final_state_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-DEX-KILL-SWITCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope.as_str()),
            HashPart::Str(target_id),
            HashPart::Str(if killed { "killed" } else { "armed" }),
            HashPart::Str(if requires_governance_unwind {
                "governance_unwind"
            } else {
                "instant"
            }),
            HashPart::Str(reason_root),
            HashPart::Str(set_by_commitment),
            HashPart::Int(set_at_height as i128),
            HashPart::Str(final_state_root),
        ],
        32,
    )
}

pub fn private_dex_public_record_payload_root(payload: &Value) -> String {
    private_dex_payload_root("PRIVATE-DEX-PUBLIC-RECORD-PAYLOAD", payload)
}

pub fn private_dex_public_record_id(
    object_kind: &str,
    object_id: &str,
    record_root: &str,
    recorded_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEX-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(object_kind),
            HashPart::Str(object_id),
            HashPart::Str(record_root),
            HashPart::Int(recorded_at_height as i128),
        ],
        32,
    )
}

pub fn private_dex_asset_pair_root(pairs: &[PrivateDexAssetPair]) -> String {
    merkle_root(
        "PRIVATE-DEX-ASSET-PAIR",
        &pairs
            .iter()
            .map(PrivateDexAssetPair::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_dex_pool_config_root(configs: &[PrivateDexCfmmPoolConfig]) -> String {
    merkle_root(
        "PRIVATE-DEX-CFMM-POOL-CONFIG",
        &configs
            .iter()
            .map(PrivateDexCfmmPoolConfig::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_dex_pool_state_set_root(pools: &[PrivateDexCfmmPoolState]) -> String {
    merkle_root(
        "PRIVATE-DEX-CFMM-POOL-STATE",
        &pools
            .iter()
            .map(PrivateDexCfmmPoolState::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_dex_liquidity_position_root(positions: &[PrivateDexLiquidityPosition]) -> String {
    merkle_root(
        "PRIVATE-DEX-LIQUIDITY-POSITION",
        &positions
            .iter()
            .map(PrivateDexLiquidityPosition::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_dex_intent_root(intents: &[PrivateDexIntent]) -> String {
    merkle_root(
        "PRIVATE-DEX-INTENT",
        &intents
            .iter()
            .map(PrivateDexIntent::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_dex_route_hint_root(hints: &[PrivateDexRouteHint]) -> String {
    merkle_root(
        "PRIVATE-DEX-ROUTE-HINT",
        &hints
            .iter()
            .map(PrivateDexRouteHint::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_dex_privacy_budget_root(budgets: &[PrivateDexPrivacyBudget]) -> String {
    merkle_root(
        "PRIVATE-DEX-PRIVACY-BUDGET",
        &budgets
            .iter()
            .map(PrivateDexPrivacyBudget::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_dex_privacy_reservation_root(
    reservations: &[PrivateDexPrivacyReservation],
) -> String {
    merkle_root(
        "PRIVATE-DEX-PRIVACY-RESERVATION",
        &reservations
            .iter()
            .map(PrivateDexPrivacyReservation::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_dex_auction_root(auctions: &[PrivateDexAuction]) -> String {
    merkle_root(
        "PRIVATE-DEX-AUCTION",
        &auctions
            .iter()
            .map(PrivateDexAuction::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_dex_solver_quote_commitment_root(
    quotes: &[PrivateDexSolverQuoteCommitment],
) -> String {
    merkle_root(
        "PRIVATE-DEX-SOLVER-QUOTE-COMMITMENT",
        &quotes
            .iter()
            .map(PrivateDexSolverQuoteCommitment::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_dex_route_leg_root(legs: &[PrivateDexRouteLeg]) -> String {
    merkle_root(
        "PRIVATE-DEX-ROUTE-LEG",
        &legs
            .iter()
            .map(PrivateDexRouteLeg::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_dex_route_plan_root(routes: &[PrivateDexRoutePlan]) -> String {
    merkle_root(
        "PRIVATE-DEX-ROUTE-PLAN",
        &routes
            .iter()
            .map(PrivateDexRoutePlan::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_dex_quote_reveal_root(reveals: &[PrivateDexQuoteReveal]) -> String {
    merkle_root(
        "PRIVATE-DEX-QUOTE-REVEAL",
        &reveals
            .iter()
            .map(PrivateDexQuoteReveal::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_dex_batch_order_root(orders: &[PrivateDexBatchOrder]) -> String {
    merkle_root(
        "PRIVATE-DEX-BATCH-ORDER",
        &orders
            .iter()
            .map(PrivateDexBatchOrder::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_dex_clearing_price_root(prices: &[PrivateDexClearingPrice]) -> String {
    merkle_root(
        "PRIVATE-DEX-CLEARING-PRICE",
        &prices
            .iter()
            .map(PrivateDexClearingPrice::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_dex_settlement_fill_root(fills: &[PrivateDexSettlementFill]) -> String {
    merkle_root(
        "PRIVATE-DEX-SETTLEMENT-FILL",
        &fills
            .iter()
            .map(PrivateDexSettlementFill::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_dex_settlement_manifest_root(manifests: &[PrivateDexSettlementManifest]) -> String {
    merkle_root(
        "PRIVATE-DEX-SETTLEMENT-MANIFEST",
        &manifests
            .iter()
            .map(PrivateDexSettlementManifest::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_dex_twap_observation_root(observations: &[PrivateDexTwapObservation]) -> String {
    merkle_root(
        "PRIVATE-DEX-TWAP-OBSERVATION",
        &observations
            .iter()
            .map(PrivateDexTwapObservation::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_dex_oracle_guard_root(guards: &[PrivateDexOracleGuard]) -> String {
    merkle_root(
        "PRIVATE-DEX-ORACLE-GUARD",
        &guards
            .iter()
            .map(PrivateDexOracleGuard::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_dex_pq_transcript_root(transcripts: &[PrivateDexPqTranscript]) -> String {
    merkle_root(
        "PRIVATE-DEX-PQ-TRANSCRIPT",
        &transcripts
            .iter()
            .map(PrivateDexPqTranscript::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_dex_circuit_profile_root(profiles: &[PrivateDexCircuitProfile]) -> String {
    merkle_root(
        "PRIVATE-DEX-CIRCUIT-PROFILE",
        &profiles
            .iter()
            .map(PrivateDexCircuitProfile::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_dex_validity_proof_set_root(proofs: &[PrivateDexValidityProof]) -> String {
    merkle_root(
        "PRIVATE-DEX-VALIDITY-PROOF",
        &proofs
            .iter()
            .map(PrivateDexValidityProof::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_dex_low_fee_rebate_root(rebates: &[PrivateDexLowFeeRebate]) -> String {
    merkle_root(
        "PRIVATE-DEX-LOW-FEE-REBATE",
        &rebates
            .iter()
            .map(PrivateDexLowFeeRebate::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_dex_monero_anchor_root(anchors: &[PrivateDexMoneroAnchor]) -> String {
    merkle_root(
        "PRIVATE-DEX-MONERO-ANCHOR",
        &anchors
            .iter()
            .map(PrivateDexMoneroAnchor::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_dex_risk_control_root(controls: &[PrivateDexRiskControl]) -> String {
    merkle_root(
        "PRIVATE-DEX-RISK-CONTROL",
        &controls
            .iter()
            .map(PrivateDexRiskControl::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_dex_pause_switch_root(switches: &[PrivateDexPauseSwitch]) -> String {
    merkle_root(
        "PRIVATE-DEX-PAUSE-SWITCH",
        &switches
            .iter()
            .map(PrivateDexPauseSwitch::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_dex_kill_switch_root(switches: &[PrivateDexKillSwitch]) -> String {
    merkle_root(
        "PRIVATE-DEX-KILL-SWITCH",
        &switches
            .iter()
            .map(PrivateDexKillSwitch::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_dex_public_record_root(records: &[PrivateDexPublicRecord]) -> String {
    merkle_root(
        "PRIVATE-DEX-PUBLIC-RECORD",
        &records
            .iter()
            .map(PrivateDexPublicRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn bps_mul_floor(amount: u64, bps: u64) -> u64 {
    (((amount as u128).saturating_mul(bps as u128)) / PRIVATE_DEX_MAX_BPS as u128) as u64
}

pub fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    (((numerator as u128).saturating_mul(PRIVATE_DEX_MAX_BPS as u128)) / denominator as u128)
        .min(PRIVATE_DEX_MAX_BPS as u128) as u64
}

pub fn ratio_delta_bps(left: u64, right: u64) -> u64 {
    if left == 0 || right == 0 {
        return PRIVATE_DEX_MAX_BPS;
    }
    let delta = left.max(right).saturating_sub(left.min(right));
    ratio_bps(delta, left.max(right))
}

pub fn reciprocal_price_scaled(price_scaled: u64) -> u64 {
    if price_scaled == 0 {
        return 0;
    }
    ((PRIVATE_DEX_PRICE_SCALE as u128).saturating_mul(PRIVATE_DEX_PRICE_SCALE as u128)
        / price_scaled as u128)
        .min(u64::MAX as u128) as u64
}

pub fn constant_product_output(amount_in_after_fee: u64, reserve_in: u64, reserve_out: u64) -> u64 {
    if amount_in_after_fee == 0 || reserve_in == 0 || reserve_out == 0 {
        return 0;
    }
    let numerator = (amount_in_after_fee as u128).saturating_mul(reserve_out as u128);
    let denominator = (reserve_in as u128).saturating_add(amount_in_after_fee as u128);
    if denominator == 0 {
        0
    } else {
        (numerator / denominator).min(u64::MAX as u128) as u64
    }
}

pub fn stable_pool_output(
    amount_in_after_fee: u64,
    reserve_in: u64,
    reserve_out: u64,
    amplification_bps: u64,
) -> u64 {
    if amount_in_after_fee == 0 || reserve_in == 0 || reserve_out == 0 {
        return 0;
    }
    let cp_output = constant_product_output(amount_in_after_fee, reserve_in, reserve_out) as u128;
    let spot_output =
        (amount_in_after_fee as u128).saturating_mul(reserve_out as u128) / reserve_in as u128;
    let reserve_cap = (reserve_out as u128).saturating_mul(9_995) / PRIVATE_DEX_MAX_BPS as u128;
    let linear_cap = spot_output
        .saturating_mul(9_995)
        .saturating_div(PRIVATE_DEX_MAX_BPS as u128)
        .min(reserve_cap);
    let amp = amplification_bps.min(PRIVATE_DEX_MAX_BPS) as u128;
    let weighted = cp_output
        .saturating_mul(PRIVATE_DEX_MAX_BPS as u128 - amp)
        .saturating_add(linear_cap.saturating_mul(amp))
        / PRIVATE_DEX_MAX_BPS as u128;
    weighted.min(u64::MAX as u128) as u64
}

pub fn hybrid_pool_output(
    amount_in_after_fee: u64,
    reserve_in: u64,
    reserve_out: u64,
    amplification_bps: u64,
) -> u64 {
    let cp_output = constant_product_output(amount_in_after_fee, reserve_in, reserve_out);
    let stable_output = stable_pool_output(
        amount_in_after_fee,
        reserve_in,
        reserve_out,
        amplification_bps,
    );
    let weight = amplification_bps.min(PRIVATE_DEX_MAX_BPS) as u128;
    let output = (cp_output as u128)
        .saturating_mul(PRIVATE_DEX_MAX_BPS as u128 - weight / 2)
        .saturating_add((stable_output as u128).saturating_mul(weight / 2))
        / PRIVATE_DEX_MAX_BPS as u128;
    output.min(u64::MAX as u128) as u64
}

pub fn price_impact_bps(
    amount_in_after_fee: u64,
    amount_out: u64,
    reserve_in: u64,
    reserve_out: u64,
) -> u64 {
    if amount_in_after_fee == 0 || amount_out == 0 || reserve_in == 0 || reserve_out == 0 {
        return PRIVATE_DEX_MAX_BPS;
    }
    let spot_out =
        (amount_in_after_fee as u128).saturating_mul(reserve_out as u128) / reserve_in as u128;
    if spot_out == 0 {
        return PRIVATE_DEX_MAX_BPS;
    }
    let actual = amount_out as u128;
    if actual >= spot_out {
        0
    } else {
        (((spot_out - actual).saturating_mul(PRIVATE_DEX_MAX_BPS as u128)) / spot_out)
            .min(PRIVATE_DEX_MAX_BPS as u128) as u64
    }
}

pub fn apply_quote_to_pool(
    pool: &mut PrivateDexCfmmPoolState,
    config: &PrivateDexCfmmPoolConfig,
    quote: &PrivateDexCfmmQuote,
    height: u64,
) -> PrivateDexResult<()> {
    if quote.pool_id != pool.pool_id || quote.pool_id != config.pool_id {
        return Err("private DEX quote pool mismatch".to_string());
    }
    if config.asset_x_id == quote.asset_in_id {
        pool.reserve_x = pool.reserve_x.saturating_add(quote.amount_in_after_fee);
        pool.reserve_y = pool.reserve_y.saturating_sub(quote.amount_out);
        pool.fee_growth_x = pool.fee_growth_x.saturating_add(quote.pool_fee_units);
        pool.protocol_fee_x = pool.protocol_fee_x.saturating_add(quote.protocol_fee_units);
        pool.cumulative_volume_x = pool.cumulative_volume_x.saturating_add(quote.amount_in);
        pool.cumulative_volume_y = pool.cumulative_volume_y.saturating_add(quote.amount_out);
    } else if config.asset_y_id == quote.asset_in_id {
        pool.reserve_y = pool.reserve_y.saturating_add(quote.amount_in_after_fee);
        pool.reserve_x = pool.reserve_x.saturating_sub(quote.amount_out);
        pool.fee_growth_y = pool.fee_growth_y.saturating_add(quote.pool_fee_units);
        pool.protocol_fee_y = pool.protocol_fee_y.saturating_add(quote.protocol_fee_units);
        pool.cumulative_volume_y = pool.cumulative_volume_y.saturating_add(quote.amount_in);
        pool.cumulative_volume_x = pool.cumulative_volume_x.saturating_add(quote.amount_out);
    } else {
        return Err("private DEX quote input asset is not in pool".to_string());
    }
    pool.mark_updated(height);
    Ok(())
}

fn validate_bps(field: &str, bps: u64) -> PrivateDexResult<()> {
    if bps > PRIVATE_DEX_MAX_BPS {
        Err(format!("{field} cannot exceed {PRIVATE_DEX_MAX_BPS}"))
    } else {
        Ok(())
    }
}

fn ensure_non_empty(value: &str, field: &str) -> PrivateDexResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} is required"))
    } else {
        Ok(())
    }
}

fn ensure_status(status: &str, allowed: &[&str]) -> PrivateDexResult<()> {
    if allowed.iter().any(|allowed| allowed == &status) {
        Ok(())
    } else {
        Err(format!("private DEX status {status} is invalid"))
    }
}
