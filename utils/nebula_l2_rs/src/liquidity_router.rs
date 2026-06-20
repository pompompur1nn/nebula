#![allow(clippy::too_many_arguments)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID, TARGET_BLOCK_MS,
};

pub type LiquidityRouterResult<T> = Result<T, String>;

pub const LIQUIDITY_ROUTER_PROTOCOL_VERSION: &str = "nebula-liquidity-router-v1";
pub const LIQUIDITY_ROUTER_SCHEMA_VERSION: u64 = 1;
pub const LIQUIDITY_ROUTER_COMMITMENT_SCHEME: &str = "shake256-domain-separated-commitments-v1";
pub const LIQUIDITY_ROUTER_ENCRYPTION_SCHEME: &str = "ml-kem-768+view-key-sealed-route-v1";
pub const LIQUIDITY_ROUTER_SOLVER_AUTH_SCHEME: &str = "ml-dsa-65+slh-dsa-shake-128s";
pub const LIQUIDITY_ROUTER_PQ_TRANSCRIPT_SCHEME: &str =
    "ml-kem-768+ml-dsa-65+slh-dsa-shake-128s+shake256";
pub const LIQUIDITY_ROUTER_INTENT_PROOF_SYSTEM: &str =
    "pq-private-liquidity-intent-membership-devnet";
pub const LIQUIDITY_ROUTER_ROUTE_PROOF_SYSTEM: &str = "pq-private-liquidity-route-validity-devnet";
pub const LIQUIDITY_ROUTER_SETTLEMENT_PROOF_SYSTEM: &str = "pq-private-liquidity-settlement-devnet";
pub const LIQUIDITY_ROUTER_EQUIVOCATION_PROOF_SYSTEM: &str =
    "pq-solver-equivocation-evidence-devnet";
pub const LIQUIDITY_ROUTER_DEFAULT_AUCTION_WINDOW_BLOCKS: u64 = 4;
pub const LIQUIDITY_ROUTER_DEFAULT_REVEAL_WINDOW_BLOCKS: u64 = 3;
pub const LIQUIDITY_ROUTER_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 8;
pub const LIQUIDITY_ROUTER_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 16;
pub const LIQUIDITY_ROUTER_DEFAULT_INTENT_TTL_BLOCKS: u64 = 32;
pub const LIQUIDITY_ROUTER_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 8;
pub const LIQUIDITY_ROUTER_DEFAULT_MAX_ROUTE_LEGS: usize = 6;
pub const LIQUIDITY_ROUTER_DEFAULT_MAX_BATCH_INTENTS: usize = 512;
pub const LIQUIDITY_ROUTER_DEFAULT_MIN_SOLVER_BOND_UNITS: u64 = 25_000;
pub const LIQUIDITY_ROUTER_DEFAULT_BASE_FEE_UNITS: u64 = 8;
pub const LIQUIDITY_ROUTER_DEFAULT_MAX_REBATE_BPS: u64 = 8_000;
pub const LIQUIDITY_ROUTER_DEFAULT_CONGESTION_TARGET_BPS: u64 = 6_500;
pub const LIQUIDITY_ROUTER_DEFAULT_PRIVATE_LANE_SHARE_BPS: u64 = 2_500;
pub const LIQUIDITY_ROUTER_DEFAULT_BRIDGE_LANE_SHARE_BPS: u64 = 1_250;
pub const LIQUIDITY_ROUTER_DEFAULT_DEFI_LANE_SHARE_BPS: u64 = 2_000;
pub const LIQUIDITY_ROUTER_DEFAULT_LENDING_LANE_SHARE_BPS: u64 = 1_000;
pub const LIQUIDITY_ROUTER_DEFAULT_SPEED_WEIGHT_BPS: u64 = 2_000;
pub const LIQUIDITY_ROUTER_DEFAULT_PRIVACY_WEIGHT_BPS: u64 = 2_500;
pub const LIQUIDITY_ROUTER_DEFAULT_FEE_WEIGHT_BPS: u64 = 3_000;
pub const LIQUIDITY_ROUTER_DEFAULT_OUTPUT_WEIGHT_BPS: u64 = 2_500;
pub const LIQUIDITY_ROUTER_MAX_BPS: u64 = 10_000;
pub const LIQUIDITY_ROUTER_DEVNET_HEIGHT: u64 = 96;
pub const LIQUIDITY_ROUTER_DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const LIQUIDITY_ROUTER_DEVNET_WXMR_ASSET_ID: &str = "wxmr-devnet";
pub const LIQUIDITY_ROUTER_DEVNET_USDD_ASSET_ID: &str = "usdd-devnet";
pub const LIQUIDITY_ROUTER_DEVNET_DNR_ASSET_ID: &str = "dnr-devnet";
pub const LIQUIDITY_ROUTER_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const LIQUIDITY_ROUTER_DEFAULT_PRIVATE_LANE_ID: &str = "private_liquidity_router";
pub const LIQUIDITY_ROUTER_DEFAULT_BRIDGE_LANE_ID: &str = "monero_bridge_router";
pub const LIQUIDITY_ROUTER_DEFAULT_DEFI_LANE_ID: &str = "private_defi_router";
pub const LIQUIDITY_ROUTER_DEFAULT_LENDING_LANE_ID: &str = "private_lending_router";
pub const LIQUIDITY_ROUTER_STATUS_ACTIVE: &str = "active";
pub const LIQUIDITY_ROUTER_STATUS_PENDING: &str = "pending";
pub const LIQUIDITY_ROUTER_STATUS_COLLECTING: &str = "collecting";
pub const LIQUIDITY_ROUTER_STATUS_REVEALING: &str = "revealing";
pub const LIQUIDITY_ROUTER_STATUS_MATCHING: &str = "matching";
pub const LIQUIDITY_ROUTER_STATUS_SETTLED: &str = "settled";
pub const LIQUIDITY_ROUTER_STATUS_EXPIRED: &str = "expired";
pub const LIQUIDITY_ROUTER_STATUS_CANCELLED: &str = "cancelled";
pub const LIQUIDITY_ROUTER_STATUS_FILLED: &str = "filled";
pub const LIQUIDITY_ROUTER_STATUS_PARTIAL: &str = "partial";
pub const LIQUIDITY_ROUTER_STATUS_REJECTED: &str = "rejected";
pub const LIQUIDITY_ROUTER_STATUS_VERIFIED: &str = "verified";
pub const LIQUIDITY_ROUTER_STATUS_OPEN: &str = "open";
pub const LIQUIDITY_ROUTER_STATUS_WON: &str = "won";
pub const LIQUIDITY_ROUTER_STATUS_LOST: &str = "lost";
pub const LIQUIDITY_ROUTER_STATUS_RESERVED: &str = "reserved";
pub const LIQUIDITY_ROUTER_STATUS_APPLIED: &str = "applied";
pub const LIQUIDITY_ROUTER_STATUS_SLASHED: &str = "slashed";
pub const LIQUIDITY_ROUTER_STATUS_DISPUTED: &str = "disputed";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityRouteIntentKind {
    ExactInput,
    ExactOutput,
    BridgeDeposit,
    BridgeWithdrawal,
    CrossVenueSwap,
    Rebalance,
    LendingSupply,
    LendingBorrow,
    LendingRepay,
    CollateralSwap,
}

impl LiquidityRouteIntentKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ExactInput => "exact_input",
            Self::ExactOutput => "exact_output",
            Self::BridgeDeposit => "bridge_deposit",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::CrossVenueSwap => "cross_venue_swap",
            Self::Rebalance => "rebalance",
            Self::LendingSupply => "lending_supply",
            Self::LendingBorrow => "lending_borrow",
            Self::LendingRepay => "lending_repay",
            Self::CollateralSwap => "collateral_swap",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityPrivacyMode {
    Shielded,
    AggregateOnly,
    SolverViewKey,
    AuditEscrow,
    PublicSimulation,
}

impl LiquidityPrivacyMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Shielded => "shielded",
            Self::AggregateOnly => "aggregate_only",
            Self::SolverViewKey => "solver_view_key",
            Self::AuditEscrow => "audit_escrow",
            Self::PublicSimulation => "public_simulation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityRouteLegKind {
    MoneroBridge,
    PrivateDex,
    PublicDex,
    LendingMarket,
    StablecoinMint,
    Paymaster,
    Settlement,
    Rebate,
}

impl LiquidityRouteLegKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MoneroBridge => "monero_bridge",
            Self::PrivateDex => "private_dex",
            Self::PublicDex => "public_dex",
            Self::LendingMarket => "lending_market",
            Self::StablecoinMint => "stablecoin_mint",
            Self::Paymaster => "paymaster",
            Self::Settlement => "settlement",
            Self::Rebate => "rebate",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeLegDirection {
    Deposit,
    Withdrawal,
    RebalanceIn,
    RebalanceOut,
}

impl BridgeLegDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Deposit => "deposit",
            Self::Withdrawal => "withdrawal",
            Self::RebalanceIn => "rebalance_in",
            Self::RebalanceOut => "rebalance_out",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DexLegKind {
    ConstantProduct,
    Stable,
    Hybrid,
    BatchAuction,
    IntentMatch,
}

impl DexLegKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ConstantProduct => "constant_product",
            Self::Stable => "stable",
            Self::Hybrid => "hybrid",
            Self::BatchAuction => "batch_auction",
            Self::IntentMatch => "intent_match",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LendingLegAction {
    Supply,
    Withdraw,
    Borrow,
    Repay,
    FlashBorrow,
    Collateralize,
}

impl LendingLegAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Supply => "supply",
            Self::Withdraw => "withdraw",
            Self::Borrow => "borrow",
            Self::Repay => "repay",
            Self::FlashBorrow => "flash_borrow",
            Self::Collateralize => "collateralize",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquiditySolverKind {
    InternalRouter,
    MarketMaker,
    AuctionSolver,
    BridgeSpecialist,
    LendingSpecialist,
    HybridSolver,
}

impl LiquiditySolverKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InternalRouter => "internal_router",
            Self::MarketMaker => "market_maker",
            Self::AuctionSolver => "auction_solver",
            Self::BridgeSpecialist => "bridge_specialist",
            Self::LendingSpecialist => "lending_specialist",
            Self::HybridSolver => "hybrid_solver",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityAuctionPhase {
    Collecting,
    Revealing,
    Matching,
    Challenge,
    Settled,
    Expired,
}

impl LiquidityAuctionPhase {
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
pub enum SlashingReason {
    Equivocation,
    InvalidRoute,
    LateSettlement,
    BadPqAttestation,
    PrivacyLeak,
    FeeOvercharge,
}

impl SlashingReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Equivocation => "equivocation",
            Self::InvalidRoute => "invalid_route",
            Self::LateSettlement => "late_settlement",
            Self::BadPqAttestation => "bad_pq_attestation",
            Self::PrivacyLeak => "privacy_leak",
            Self::FeeOvercharge => "fee_overcharge",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityRouterConfig {
    pub protocol_version: String,
    pub schema_version: u64,
    pub intent_ttl_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub auction_window_blocks: u64,
    pub reveal_window_blocks: u64,
    pub challenge_window_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub max_route_legs: usize,
    pub max_batch_intents: usize,
    pub min_solver_bond_units: u64,
    pub base_fee_units: u64,
    pub max_rebate_bps: u64,
    pub congestion_target_bps: u64,
    pub private_lane_share_bps: u64,
    pub bridge_lane_share_bps: u64,
    pub defi_lane_share_bps: u64,
    pub lending_lane_share_bps: u64,
    pub speed_weight_bps: u64,
    pub privacy_weight_bps: u64,
    pub fee_weight_bps: u64,
    pub output_weight_bps: u64,
    pub fee_asset_id: String,
    pub monero_network: String,
    pub encryption_scheme: String,
    pub pq_transcript_scheme: String,
    pub solver_auth_scheme: String,
}

impl Default for LiquidityRouterConfig {
    fn default() -> Self {
        Self {
            protocol_version: LIQUIDITY_ROUTER_PROTOCOL_VERSION.to_string(),
            schema_version: LIQUIDITY_ROUTER_SCHEMA_VERSION,
            intent_ttl_blocks: LIQUIDITY_ROUTER_DEFAULT_INTENT_TTL_BLOCKS,
            quote_ttl_blocks: LIQUIDITY_ROUTER_DEFAULT_QUOTE_TTL_BLOCKS,
            auction_window_blocks: LIQUIDITY_ROUTER_DEFAULT_AUCTION_WINDOW_BLOCKS,
            reveal_window_blocks: LIQUIDITY_ROUTER_DEFAULT_REVEAL_WINDOW_BLOCKS,
            challenge_window_blocks: LIQUIDITY_ROUTER_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            settlement_ttl_blocks: LIQUIDITY_ROUTER_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            max_route_legs: LIQUIDITY_ROUTER_DEFAULT_MAX_ROUTE_LEGS,
            max_batch_intents: LIQUIDITY_ROUTER_DEFAULT_MAX_BATCH_INTENTS,
            min_solver_bond_units: LIQUIDITY_ROUTER_DEFAULT_MIN_SOLVER_BOND_UNITS,
            base_fee_units: LIQUIDITY_ROUTER_DEFAULT_BASE_FEE_UNITS,
            max_rebate_bps: LIQUIDITY_ROUTER_DEFAULT_MAX_REBATE_BPS,
            congestion_target_bps: LIQUIDITY_ROUTER_DEFAULT_CONGESTION_TARGET_BPS,
            private_lane_share_bps: LIQUIDITY_ROUTER_DEFAULT_PRIVATE_LANE_SHARE_BPS,
            bridge_lane_share_bps: LIQUIDITY_ROUTER_DEFAULT_BRIDGE_LANE_SHARE_BPS,
            defi_lane_share_bps: LIQUIDITY_ROUTER_DEFAULT_DEFI_LANE_SHARE_BPS,
            lending_lane_share_bps: LIQUIDITY_ROUTER_DEFAULT_LENDING_LANE_SHARE_BPS,
            speed_weight_bps: LIQUIDITY_ROUTER_DEFAULT_SPEED_WEIGHT_BPS,
            privacy_weight_bps: LIQUIDITY_ROUTER_DEFAULT_PRIVACY_WEIGHT_BPS,
            fee_weight_bps: LIQUIDITY_ROUTER_DEFAULT_FEE_WEIGHT_BPS,
            output_weight_bps: LIQUIDITY_ROUTER_DEFAULT_OUTPUT_WEIGHT_BPS,
            fee_asset_id: LIQUIDITY_ROUTER_DEVNET_FEE_ASSET_ID.to_string(),
            monero_network: LIQUIDITY_ROUTER_DEVNET_MONERO_NETWORK.to_string(),
            encryption_scheme: LIQUIDITY_ROUTER_ENCRYPTION_SCHEME.to_string(),
            pq_transcript_scheme: LIQUIDITY_ROUTER_PQ_TRANSCRIPT_SCHEME.to_string(),
            solver_auth_scheme: LIQUIDITY_ROUTER_SOLVER_AUTH_SCHEME.to_string(),
        }
    }
}

impl LiquidityRouterConfig {
    pub fn validate(&self) -> LiquidityRouterResult<()> {
        ensure_non_empty(&self.protocol_version, "liquidity router protocol version")?;
        ensure_non_empty(&self.fee_asset_id, "liquidity router fee asset")?;
        ensure_non_empty(&self.monero_network, "liquidity router monero network")?;
        ensure_non_empty(
            &self.encryption_scheme,
            "liquidity router encryption scheme",
        )?;
        ensure_non_empty(
            &self.pq_transcript_scheme,
            "liquidity router pq transcript scheme",
        )?;
        ensure_non_empty(
            &self.solver_auth_scheme,
            "liquidity router solver auth scheme",
        )?;
        ensure_positive(self.intent_ttl_blocks, "liquidity router intent ttl")?;
        ensure_positive(self.quote_ttl_blocks, "liquidity router quote ttl")?;
        ensure_positive(
            self.auction_window_blocks,
            "liquidity router auction window",
        )?;
        ensure_positive(self.reveal_window_blocks, "liquidity router reveal window")?;
        ensure_positive(
            self.challenge_window_blocks,
            "liquidity router challenge window",
        )?;
        ensure_positive(
            self.settlement_ttl_blocks,
            "liquidity router settlement ttl",
        )?;
        ensure_positive(
            self.max_route_legs as u64,
            "liquidity router max route legs",
        )?;
        ensure_positive(
            self.max_batch_intents as u64,
            "liquidity router max batch intents",
        )?;
        validate_bps(self.max_rebate_bps, "liquidity router max rebate")?;
        validate_bps(
            self.congestion_target_bps,
            "liquidity router congestion target",
        )?;
        validate_bps(
            self.private_lane_share_bps,
            "liquidity router private lane share",
        )?;
        validate_bps(
            self.bridge_lane_share_bps,
            "liquidity router bridge lane share",
        )?;
        validate_bps(self.defi_lane_share_bps, "liquidity router defi lane share")?;
        validate_bps(
            self.lending_lane_share_bps,
            "liquidity router lending lane share",
        )?;
        validate_bps(self.speed_weight_bps, "liquidity router speed weight")?;
        validate_bps(self.privacy_weight_bps, "liquidity router privacy weight")?;
        validate_bps(self.fee_weight_bps, "liquidity router fee weight")?;
        validate_bps(self.output_weight_bps, "liquidity router output weight")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "liquidity_router_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "auction_window_blocks": self.auction_window_blocks,
            "reveal_window_blocks": self.reveal_window_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "max_route_legs": self.max_route_legs,
            "max_batch_intents": self.max_batch_intents,
            "min_solver_bond_units": self.min_solver_bond_units,
            "base_fee_units": self.base_fee_units,
            "max_rebate_bps": self.max_rebate_bps,
            "congestion_target_bps": self.congestion_target_bps,
            "private_lane_share_bps": self.private_lane_share_bps,
            "bridge_lane_share_bps": self.bridge_lane_share_bps,
            "defi_lane_share_bps": self.defi_lane_share_bps,
            "lending_lane_share_bps": self.lending_lane_share_bps,
            "speed_weight_bps": self.speed_weight_bps,
            "privacy_weight_bps": self.privacy_weight_bps,
            "fee_weight_bps": self.fee_weight_bps,
            "output_weight_bps": self.output_weight_bps,
            "fee_asset_id": self.fee_asset_id,
            "monero_network": self.monero_network,
            "encryption_scheme": self.encryption_scheme,
            "pq_transcript_scheme": self.pq_transcript_scheme,
            "solver_auth_scheme": self.solver_auth_scheme,
        })
    }

    pub fn config_root(&self) -> String {
        liquidity_router_payload_root("LIQUIDITY-ROUTER-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityRouterCounters {
    pub submitted_intents: u64,
    pub active_intents: u64,
    pub expired_intents: u64,
    pub registered_solvers: u64,
    pub verified_attestations: u64,
    pub submitted_quotes: u64,
    pub accepted_quotes: u64,
    pub settled_routes: u64,
    pub auctions_opened: u64,
    pub auctions_settled: u64,
    pub total_route_legs: u64,
    pub bridge_legs: u64,
    pub dex_legs: u64,
    pub lending_legs: u64,
    pub fee_rebates_reserved: u64,
    pub fee_rebates_applied: u64,
    pub rebate_units_reserved: u64,
    pub rebate_units_applied: u64,
    pub solver_slashes: u64,
    pub slash_units: u64,
    pub equivocation_evidence: u64,
    pub cumulative_fee_units: u64,
    pub cumulative_solver_fee_units: u64,
    pub cumulative_output_units: u64,
}

impl LiquidityRouterCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "liquidity_router_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": LIQUIDITY_ROUTER_PROTOCOL_VERSION,
            "submitted_intents": self.submitted_intents,
            "active_intents": self.active_intents,
            "expired_intents": self.expired_intents,
            "registered_solvers": self.registered_solvers,
            "verified_attestations": self.verified_attestations,
            "submitted_quotes": self.submitted_quotes,
            "accepted_quotes": self.accepted_quotes,
            "settled_routes": self.settled_routes,
            "auctions_opened": self.auctions_opened,
            "auctions_settled": self.auctions_settled,
            "total_route_legs": self.total_route_legs,
            "bridge_legs": self.bridge_legs,
            "dex_legs": self.dex_legs,
            "lending_legs": self.lending_legs,
            "fee_rebates_reserved": self.fee_rebates_reserved,
            "fee_rebates_applied": self.fee_rebates_applied,
            "rebate_units_reserved": self.rebate_units_reserved,
            "rebate_units_applied": self.rebate_units_applied,
            "solver_slashes": self.solver_slashes,
            "slash_units": self.slash_units,
            "equivocation_evidence": self.equivocation_evidence,
            "cumulative_fee_units": self.cumulative_fee_units,
            "cumulative_solver_fee_units": self.cumulative_solver_fee_units,
            "cumulative_output_units": self.cumulative_output_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedRouteIntent {
    pub intent_id: String,
    pub owner_commitment: String,
    pub intent_kind: LiquidityRouteIntentKind,
    pub privacy_mode: LiquidityPrivacyMode,
    pub asset_in_commitment: String,
    pub asset_out_commitment: String,
    pub amount_in_commitment: String,
    pub min_output_commitment: String,
    pub max_fee_units: u64,
    pub max_slippage_bps: u64,
    pub deadline_height: u64,
    pub submitted_at_height: u64,
    pub nonce: u64,
    pub encryption_scheme: String,
    pub encrypted_payload_root: String,
    pub ciphertext_bytes: u64,
    pub route_hint_root: String,
    pub recipient_view_key_root: String,
    pub refund_commitment: String,
    pub privacy_budget_id: String,
    pub low_fee_lane_id: String,
    pub public_metadata_root: String,
    pub status: String,
}

impl EncryptedRouteIntent {
    pub fn new(
        owner_label: &str,
        intent_kind: LiquidityRouteIntentKind,
        privacy_mode: LiquidityPrivacyMode,
        asset_in_id: &str,
        asset_out_id: &str,
        amount_in_units: u64,
        min_output_units: u64,
        max_fee_units: u64,
        max_slippage_bps: u64,
        deadline_height: u64,
        submitted_at_height: u64,
        nonce: u64,
        encrypted_payload: &Value,
        route_hint: &Value,
        recipient_view_key: &str,
        refund_label: &str,
        privacy_budget_id: impl Into<String>,
        low_fee_lane_id: impl Into<String>,
        public_metadata: &Value,
    ) -> LiquidityRouterResult<Self> {
        ensure_non_empty(owner_label, "route intent owner")?;
        ensure_non_empty(asset_in_id, "route intent asset in")?;
        ensure_non_empty(asset_out_id, "route intent asset out")?;
        ensure_non_empty(recipient_view_key, "route intent recipient view key")?;
        ensure_non_empty(refund_label, "route intent refund label")?;
        ensure_positive(amount_in_units, "route intent amount in")?;
        validate_bps(max_slippage_bps, "route intent max slippage")?;
        if deadline_height <= submitted_at_height {
            return Err("route intent deadline must be after submission".to_string());
        }
        let privacy_budget_id = privacy_budget_id.into();
        let low_fee_lane_id = low_fee_lane_id.into();
        ensure_non_empty(&privacy_budget_id, "route intent privacy budget")?;
        ensure_non_empty(&low_fee_lane_id, "route intent low fee lane")?;

        let owner_commitment = liquidity_router_account_commitment(owner_label);
        let asset_in_commitment = liquidity_router_asset_commitment(asset_in_id);
        let asset_out_commitment = liquidity_router_asset_commitment(asset_out_id);
        let amount_in_commitment = liquidity_router_amount_commitment(
            amount_in_units,
            &liquidity_router_blinding(owner_label, nonce, "amount_in"),
        );
        let min_output_commitment = liquidity_router_amount_commitment(
            min_output_units,
            &liquidity_router_blinding(owner_label, nonce, "min_output"),
        );
        let encrypted_payload_root =
            liquidity_router_payload_root("LIQUIDITY-ROUTER-ENCRYPTED-PAYLOAD", encrypted_payload);
        let route_hint_root =
            liquidity_router_payload_root("LIQUIDITY-ROUTER-ROUTE-HINT", route_hint);
        let recipient_view_key_root =
            liquidity_router_string_root("LIQUIDITY-ROUTER-RECIPIENT-VIEW-KEY", recipient_view_key);
        let refund_commitment = liquidity_router_account_commitment(refund_label);
        let public_metadata_root =
            liquidity_router_payload_root("LIQUIDITY-ROUTER-INTENT-METADATA", public_metadata);
        let intent_id = encrypted_route_intent_id(
            &owner_commitment,
            intent_kind,
            privacy_mode,
            &asset_in_commitment,
            &asset_out_commitment,
            &amount_in_commitment,
            &min_output_commitment,
            &route_hint_root,
            deadline_height,
            nonce,
        );
        let intent = Self {
            intent_id,
            owner_commitment,
            intent_kind,
            privacy_mode,
            asset_in_commitment,
            asset_out_commitment,
            amount_in_commitment,
            min_output_commitment,
            max_fee_units,
            max_slippage_bps,
            deadline_height,
            submitted_at_height,
            nonce,
            encryption_scheme: LIQUIDITY_ROUTER_ENCRYPTION_SCHEME.to_string(),
            encrypted_payload_root,
            ciphertext_bytes: liquidity_router_json_size(encrypted_payload),
            route_hint_root,
            recipient_view_key_root,
            refund_commitment,
            privacy_budget_id,
            low_fee_lane_id,
            public_metadata_root,
            status: LIQUIDITY_ROUTER_STATUS_ACTIVE.to_string(),
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_route_intent",
            "chain_id": CHAIN_ID,
            "protocol_version": LIQUIDITY_ROUTER_PROTOCOL_VERSION,
            "intent_id": self.intent_id,
            "owner_commitment": self.owner_commitment,
            "intent_kind": self.intent_kind.as_str(),
            "privacy_mode": self.privacy_mode.as_str(),
            "asset_in_commitment": self.asset_in_commitment,
            "asset_out_commitment": self.asset_out_commitment,
            "amount_in_commitment": self.amount_in_commitment,
            "min_output_commitment": self.min_output_commitment,
            "max_fee_units": self.max_fee_units,
            "max_slippage_bps": self.max_slippage_bps,
            "deadline_height": self.deadline_height,
            "submitted_at_height": self.submitted_at_height,
            "nonce": self.nonce,
            "encryption_scheme": self.encryption_scheme,
            "commitment_scheme": LIQUIDITY_ROUTER_COMMITMENT_SCHEME,
            "encrypted_payload_root": self.encrypted_payload_root,
            "ciphertext_bytes": self.ciphertext_bytes,
            "route_hint_root": self.route_hint_root,
            "recipient_view_key_root": self.recipient_view_key_root,
            "refund_commitment": self.refund_commitment,
            "privacy_budget_id": self.privacy_budget_id,
            "low_fee_lane_id": self.low_fee_lane_id,
            "public_metadata_root": self.public_metadata_root,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> LiquidityRouterResult<()> {
        ensure_non_empty(&self.intent_id, "route intent id")?;
        ensure_non_empty(&self.owner_commitment, "route intent owner commitment")?;
        ensure_non_empty(
            &self.asset_in_commitment,
            "route intent asset in commitment",
        )?;
        ensure_non_empty(
            &self.asset_out_commitment,
            "route intent asset out commitment",
        )?;
        ensure_non_empty(&self.amount_in_commitment, "route intent amount commitment")?;
        ensure_non_empty(
            &self.min_output_commitment,
            "route intent min output commitment",
        )?;
        ensure_non_empty(
            &self.encrypted_payload_root,
            "route intent encrypted payload",
        )?;
        ensure_non_empty(&self.route_hint_root, "route intent route hint")?;
        ensure_non_empty(
            &self.recipient_view_key_root,
            "route intent recipient view key",
        )?;
        ensure_non_empty(&self.refund_commitment, "route intent refund commitment")?;
        ensure_non_empty(&self.privacy_budget_id, "route intent privacy budget")?;
        ensure_non_empty(&self.low_fee_lane_id, "route intent low fee lane")?;
        validate_bps(self.max_slippage_bps, "route intent max slippage")?;
        if self.deadline_height <= self.submitted_at_height {
            return Err("route intent deadline must be after submission".to_string());
        }
        ensure_status(
            &self.status,
            &[
                LIQUIDITY_ROUTER_STATUS_ACTIVE,
                LIQUIDITY_ROUTER_STATUS_PENDING,
                LIQUIDITY_ROUTER_STATUS_SETTLED,
                LIQUIDITY_ROUTER_STATUS_EXPIRED,
                LIQUIDITY_ROUTER_STATUS_CANCELLED,
                LIQUIDITY_ROUTER_STATUS_REJECTED,
            ],
        )?;
        Ok(())
    }

    pub fn root(&self) -> String {
        encrypted_route_intent_root(std::slice::from_ref(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquiditySolverProfile {
    pub solver_id: String,
    pub label: String,
    pub solver_kind: LiquiditySolverKind,
    pub operator_commitment: String,
    pub bond_asset_id: String,
    pub bond_units: u64,
    pub max_route_legs: usize,
    pub max_batch_intents: usize,
    pub fee_bps: u64,
    pub latency_target_ms: u64,
    pub pq_identity_root: String,
    pub endpoint_commitment: String,
    pub supported_leg_root: String,
    pub supported_asset_root: String,
    pub status: String,
}

impl LiquiditySolverProfile {
    pub fn new(
        label: &str,
        solver_kind: LiquiditySolverKind,
        operator_label: &str,
        bond_asset_id: &str,
        bond_units: u64,
        max_route_legs: usize,
        max_batch_intents: usize,
        fee_bps: u64,
        latency_target_ms: u64,
        pq_identity_payload: &Value,
        endpoint_label: &str,
        supported_legs: &[LiquidityRouteLegKind],
        supported_assets: &[String],
    ) -> LiquidityRouterResult<Self> {
        ensure_non_empty(label, "solver label")?;
        ensure_non_empty(operator_label, "solver operator")?;
        ensure_non_empty(bond_asset_id, "solver bond asset")?;
        ensure_non_empty(endpoint_label, "solver endpoint")?;
        ensure_positive(bond_units, "solver bond")?;
        ensure_positive(max_route_legs as u64, "solver max route legs")?;
        ensure_positive(max_batch_intents as u64, "solver max batch intents")?;
        validate_bps(fee_bps, "solver fee")?;
        ensure_positive(latency_target_ms, "solver latency target")?;
        let operator_commitment = liquidity_router_account_commitment(operator_label);
        let pq_identity_root = liquidity_router_payload_root(
            "LIQUIDITY-ROUTER-SOLVER-PQ-IDENTITY",
            pq_identity_payload,
        );
        let endpoint_commitment =
            liquidity_router_string_root("LIQUIDITY-ROUTER-SOLVER-ENDPOINT", endpoint_label);
        let supported_leg_root = liquidity_router_route_leg_kind_set_root(supported_legs);
        let supported_asset_root =
            liquidity_router_string_set_root("LIQUIDITY-ROUTER-SOLVER-ASSET", supported_assets);
        let solver_id = liquidity_solver_id(
            label,
            solver_kind,
            &operator_commitment,
            bond_asset_id,
            bond_units,
            &pq_identity_root,
        );
        Ok(Self {
            solver_id,
            label: label.to_string(),
            solver_kind,
            operator_commitment,
            bond_asset_id: bond_asset_id.to_string(),
            bond_units,
            max_route_legs,
            max_batch_intents,
            fee_bps,
            latency_target_ms,
            pq_identity_root,
            endpoint_commitment,
            supported_leg_root,
            supported_asset_root,
            status: LIQUIDITY_ROUTER_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "liquidity_solver_profile",
            "chain_id": CHAIN_ID,
            "protocol_version": LIQUIDITY_ROUTER_PROTOCOL_VERSION,
            "solver_id": self.solver_id,
            "label": self.label,
            "solver_kind": self.solver_kind.as_str(),
            "operator_commitment": self.operator_commitment,
            "bond_asset_id": self.bond_asset_id,
            "bond_units": self.bond_units,
            "max_route_legs": self.max_route_legs,
            "max_batch_intents": self.max_batch_intents,
            "fee_bps": self.fee_bps,
            "latency_target_ms": self.latency_target_ms,
            "pq_identity_root": self.pq_identity_root,
            "endpoint_commitment": self.endpoint_commitment,
            "supported_leg_root": self.supported_leg_root,
            "supported_asset_root": self.supported_asset_root,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> LiquidityRouterResult<()> {
        ensure_non_empty(&self.solver_id, "solver id")?;
        ensure_non_empty(&self.label, "solver label")?;
        ensure_non_empty(&self.operator_commitment, "solver operator commitment")?;
        ensure_non_empty(&self.bond_asset_id, "solver bond asset")?;
        ensure_non_empty(&self.pq_identity_root, "solver pq identity root")?;
        ensure_non_empty(&self.endpoint_commitment, "solver endpoint commitment")?;
        ensure_positive(self.bond_units, "solver bond")?;
        ensure_positive(self.max_route_legs as u64, "solver max route legs")?;
        ensure_positive(self.max_batch_intents as u64, "solver max batch intents")?;
        validate_bps(self.fee_bps, "solver fee")?;
        ensure_status(
            &self.status,
            &[
                LIQUIDITY_ROUTER_STATUS_ACTIVE,
                LIQUIDITY_ROUTER_STATUS_SLASHED,
                LIQUIDITY_ROUTER_STATUS_REJECTED,
            ],
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSolverAttestation {
    pub attestation_id: String,
    pub solver_id: String,
    pub transcript_scheme: String,
    pub auth_scheme: String,
    pub kem_public_key_root: String,
    pub signature_root: String,
    pub quote_capability_root: String,
    pub circuit_capability_root: String,
    pub hardware_attestation_root: String,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl PqSolverAttestation {
    pub fn new(
        solver_id: &str,
        kem_public_key: &str,
        signature_payload: &Value,
        quote_capabilities: &[String],
        circuit_capabilities: &[String],
        hardware_attestation_payload: &Value,
        attested_at_height: u64,
        expires_at_height: u64,
    ) -> LiquidityRouterResult<Self> {
        ensure_non_empty(solver_id, "pq attestation solver id")?;
        ensure_non_empty(kem_public_key, "pq attestation kem public key")?;
        if expires_at_height <= attested_at_height {
            return Err("pq attestation expiry must be after attestation".to_string());
        }
        let kem_public_key_root =
            liquidity_router_string_root("LIQUIDITY-ROUTER-KEM-PUBLIC-KEY", kem_public_key);
        let signature_root =
            liquidity_router_payload_root("LIQUIDITY-ROUTER-PQ-SIGNATURE", signature_payload);
        let quote_capability_root = liquidity_router_string_set_root(
            "LIQUIDITY-ROUTER-QUOTE-CAPABILITY",
            quote_capabilities,
        );
        let circuit_capability_root = liquidity_router_string_set_root(
            "LIQUIDITY-ROUTER-CIRCUIT-CAPABILITY",
            circuit_capabilities,
        );
        let hardware_attestation_root = liquidity_router_payload_root(
            "LIQUIDITY-ROUTER-HARDWARE-ATTESTATION",
            hardware_attestation_payload,
        );
        let attestation_id = pq_solver_attestation_id(
            solver_id,
            &kem_public_key_root,
            &signature_root,
            &quote_capability_root,
            attested_at_height,
            expires_at_height,
        );
        Ok(Self {
            attestation_id,
            solver_id: solver_id.to_string(),
            transcript_scheme: LIQUIDITY_ROUTER_PQ_TRANSCRIPT_SCHEME.to_string(),
            auth_scheme: LIQUIDITY_ROUTER_SOLVER_AUTH_SCHEME.to_string(),
            kem_public_key_root,
            signature_root,
            quote_capability_root,
            circuit_capability_root,
            hardware_attestation_root,
            attested_at_height,
            expires_at_height,
            status: LIQUIDITY_ROUTER_STATUS_VERIFIED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_solver_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": LIQUIDITY_ROUTER_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "solver_id": self.solver_id,
            "transcript_scheme": self.transcript_scheme,
            "auth_scheme": self.auth_scheme,
            "kem_public_key_root": self.kem_public_key_root,
            "signature_root": self.signature_root,
            "quote_capability_root": self.quote_capability_root,
            "circuit_capability_root": self.circuit_capability_root,
            "hardware_attestation_root": self.hardware_attestation_root,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> LiquidityRouterResult<()> {
        ensure_non_empty(&self.attestation_id, "pq attestation id")?;
        ensure_non_empty(&self.solver_id, "pq attestation solver id")?;
        ensure_non_empty(&self.kem_public_key_root, "pq attestation kem root")?;
        ensure_non_empty(&self.signature_root, "pq attestation signature root")?;
        ensure_non_empty(
            &self.quote_capability_root,
            "pq attestation quote capability root",
        )?;
        ensure_non_empty(
            &self.circuit_capability_root,
            "pq attestation circuit capability root",
        )?;
        if self.expires_at_height <= self.attested_at_height {
            return Err("pq attestation expiry must be after attestation".to_string());
        }
        ensure_status(
            &self.status,
            &[
                LIQUIDITY_ROUTER_STATUS_VERIFIED,
                LIQUIDITY_ROUTER_STATUS_EXPIRED,
                LIQUIDITY_ROUTER_STATUS_REJECTED,
            ],
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeRouteLeg {
    pub bridge_network: String,
    pub direction: BridgeLegDirection,
    pub reserve_lane_id: String,
    pub withdrawal_bucket_id: String,
    pub bridge_fee_units: u64,
    pub release_not_before_height: u64,
    pub reserve_proof_root: String,
}

impl BridgeRouteLeg {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bridge_route_leg",
            "chain_id": CHAIN_ID,
            "bridge_network": self.bridge_network,
            "direction": self.direction.as_str(),
            "reserve_lane_id": self.reserve_lane_id,
            "withdrawal_bucket_id": self.withdrawal_bucket_id,
            "bridge_fee_units": self.bridge_fee_units,
            "release_not_before_height": self.release_not_before_height,
            "reserve_proof_root": self.reserve_proof_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexRouteLeg {
    pub dex_kind: DexLegKind,
    pub venue_id: String,
    pub pool_id: String,
    pub price_limit_commitment: String,
    pub pool_fee_bps: u64,
    pub price_impact_bps: u64,
    pub oracle_guard_root: String,
}

impl DexRouteLeg {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "dex_route_leg",
            "chain_id": CHAIN_ID,
            "dex_kind": self.dex_kind.as_str(),
            "venue_id": self.venue_id,
            "pool_id": self.pool_id,
            "price_limit_commitment": self.price_limit_commitment,
            "pool_fee_bps": self.pool_fee_bps,
            "price_impact_bps": self.price_impact_bps,
            "oracle_guard_root": self.oracle_guard_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingRouteLeg {
    pub market_id: String,
    pub action: LendingLegAction,
    pub collateral_asset_commitment: String,
    pub debt_asset_commitment: String,
    pub health_factor_bps_after: u64,
    pub interest_rate_bps: u64,
    pub risk_guard_root: String,
}

impl LendingRouteLeg {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "lending_route_leg",
            "chain_id": CHAIN_ID,
            "market_id": self.market_id,
            "action": self.action.as_str(),
            "collateral_asset_commitment": self.collateral_asset_commitment,
            "debt_asset_commitment": self.debt_asset_commitment,
            "health_factor_bps_after": self.health_factor_bps_after,
            "interest_rate_bps": self.interest_rate_bps,
            "risk_guard_root": self.risk_guard_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityRouteLeg {
    pub leg_id: String,
    pub quote_id_hint: String,
    pub leg_index: u64,
    pub leg_kind: LiquidityRouteLegKind,
    pub asset_in_commitment: String,
    pub asset_out_commitment: String,
    pub amount_in_commitment: String,
    pub amount_out_commitment: String,
    pub expected_input_units: u64,
    pub expected_output_units: u64,
    pub fee_units: u64,
    pub fee_asset_id: String,
    pub adapter_id: String,
    pub bridge: Option<BridgeRouteLeg>,
    pub dex: Option<DexRouteLeg>,
    pub lending: Option<LendingRouteLeg>,
    pub leg_proof_root: String,
    pub status: String,
}

impl LiquidityRouteLeg {
    pub fn bridge(
        quote_id_hint: &str,
        leg_index: u64,
        asset_in_id: &str,
        asset_out_id: &str,
        input_units: u64,
        output_units: u64,
        fee_units: u64,
        fee_asset_id: &str,
        adapter_id: &str,
        bridge: BridgeRouteLeg,
    ) -> LiquidityRouterResult<Self> {
        Self::new(
            quote_id_hint,
            leg_index,
            LiquidityRouteLegKind::MoneroBridge,
            asset_in_id,
            asset_out_id,
            input_units,
            output_units,
            fee_units,
            fee_asset_id,
            adapter_id,
            Some(bridge),
            None,
            None,
            json!({"proof": "bridge-leg-devnet"}),
        )
    }

    pub fn dex(
        quote_id_hint: &str,
        leg_index: u64,
        asset_in_id: &str,
        asset_out_id: &str,
        input_units: u64,
        output_units: u64,
        fee_units: u64,
        fee_asset_id: &str,
        adapter_id: &str,
        dex: DexRouteLeg,
    ) -> LiquidityRouterResult<Self> {
        Self::new(
            quote_id_hint,
            leg_index,
            LiquidityRouteLegKind::PrivateDex,
            asset_in_id,
            asset_out_id,
            input_units,
            output_units,
            fee_units,
            fee_asset_id,
            adapter_id,
            None,
            Some(dex),
            None,
            json!({"proof": "dex-leg-devnet"}),
        )
    }

    pub fn lending(
        quote_id_hint: &str,
        leg_index: u64,
        asset_in_id: &str,
        asset_out_id: &str,
        input_units: u64,
        output_units: u64,
        fee_units: u64,
        fee_asset_id: &str,
        adapter_id: &str,
        lending: LendingRouteLeg,
    ) -> LiquidityRouterResult<Self> {
        Self::new(
            quote_id_hint,
            leg_index,
            LiquidityRouteLegKind::LendingMarket,
            asset_in_id,
            asset_out_id,
            input_units,
            output_units,
            fee_units,
            fee_asset_id,
            adapter_id,
            None,
            None,
            Some(lending),
            json!({"proof": "lending-leg-devnet"}),
        )
    }

    pub fn settlement(
        quote_id_hint: &str,
        leg_index: u64,
        asset_id: &str,
        output_units: u64,
        fee_asset_id: &str,
        adapter_id: &str,
    ) -> LiquidityRouterResult<Self> {
        Self::new(
            quote_id_hint,
            leg_index,
            LiquidityRouteLegKind::Settlement,
            asset_id,
            asset_id,
            output_units,
            output_units,
            0,
            fee_asset_id,
            adapter_id,
            None,
            None,
            None,
            json!({"proof": "settlement-leg-devnet"}),
        )
    }

    fn new(
        quote_id_hint: &str,
        leg_index: u64,
        leg_kind: LiquidityRouteLegKind,
        asset_in_id: &str,
        asset_out_id: &str,
        input_units: u64,
        output_units: u64,
        fee_units: u64,
        fee_asset_id: &str,
        adapter_id: &str,
        bridge: Option<BridgeRouteLeg>,
        dex: Option<DexRouteLeg>,
        lending: Option<LendingRouteLeg>,
        proof_payload: Value,
    ) -> LiquidityRouterResult<Self> {
        ensure_non_empty(quote_id_hint, "route leg quote hint")?;
        ensure_non_empty(asset_in_id, "route leg asset in")?;
        ensure_non_empty(asset_out_id, "route leg asset out")?;
        ensure_non_empty(fee_asset_id, "route leg fee asset")?;
        ensure_non_empty(adapter_id, "route leg adapter")?;
        ensure_positive(input_units, "route leg input units")?;
        let asset_in_commitment = liquidity_router_asset_commitment(asset_in_id);
        let asset_out_commitment = liquidity_router_asset_commitment(asset_out_id);
        let amount_in_commitment = liquidity_router_amount_commitment(
            input_units,
            &liquidity_router_string_root("LIQUIDITY-ROUTER-LEG-BLINDING", quote_id_hint),
        );
        let amount_out_commitment = liquidity_router_amount_commitment(
            output_units,
            &liquidity_router_string_root("LIQUIDITY-ROUTER-LEG-OUT-BLINDING", quote_id_hint),
        );
        let leg_proof_root =
            liquidity_router_payload_root("LIQUIDITY-ROUTER-LEG-PROOF", &proof_payload);
        let leg_id = liquidity_route_leg_id(
            quote_id_hint,
            leg_index,
            leg_kind,
            &asset_in_commitment,
            &asset_out_commitment,
            &amount_in_commitment,
            &amount_out_commitment,
            &leg_proof_root,
        );
        let leg = Self {
            leg_id,
            quote_id_hint: quote_id_hint.to_string(),
            leg_index,
            leg_kind,
            asset_in_commitment,
            asset_out_commitment,
            amount_in_commitment,
            amount_out_commitment,
            expected_input_units: input_units,
            expected_output_units: output_units,
            fee_units,
            fee_asset_id: fee_asset_id.to_string(),
            adapter_id: adapter_id.to_string(),
            bridge,
            dex,
            lending,
            leg_proof_root,
            status: LIQUIDITY_ROUTER_STATUS_PENDING.to_string(),
        };
        leg.validate()?;
        Ok(leg)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "liquidity_route_leg",
            "chain_id": CHAIN_ID,
            "protocol_version": LIQUIDITY_ROUTER_PROTOCOL_VERSION,
            "leg_id": self.leg_id,
            "quote_id_hint": self.quote_id_hint,
            "leg_index": self.leg_index,
            "leg_kind": self.leg_kind.as_str(),
            "asset_in_commitment": self.asset_in_commitment,
            "asset_out_commitment": self.asset_out_commitment,
            "amount_in_commitment": self.amount_in_commitment,
            "amount_out_commitment": self.amount_out_commitment,
            "expected_input_units": self.expected_input_units,
            "expected_output_units": self.expected_output_units,
            "fee_units": self.fee_units,
            "fee_asset_id": self.fee_asset_id,
            "adapter_id": self.adapter_id,
            "bridge": self.bridge.as_ref().map(BridgeRouteLeg::public_record),
            "dex": self.dex.as_ref().map(DexRouteLeg::public_record),
            "lending": self.lending.as_ref().map(LendingRouteLeg::public_record),
            "leg_proof_root": self.leg_proof_root,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> LiquidityRouterResult<()> {
        ensure_non_empty(&self.leg_id, "route leg id")?;
        ensure_non_empty(&self.quote_id_hint, "route leg quote hint")?;
        ensure_non_empty(&self.asset_in_commitment, "route leg asset in commitment")?;
        ensure_non_empty(&self.asset_out_commitment, "route leg asset out commitment")?;
        ensure_non_empty(&self.amount_in_commitment, "route leg amount in commitment")?;
        ensure_non_empty(
            &self.amount_out_commitment,
            "route leg amount out commitment",
        )?;
        ensure_non_empty(&self.fee_asset_id, "route leg fee asset")?;
        ensure_non_empty(&self.adapter_id, "route leg adapter")?;
        ensure_non_empty(&self.leg_proof_root, "route leg proof root")?;
        ensure_positive(self.expected_input_units, "route leg expected input")?;
        validate_bps(
            self.dex
                .as_ref()
                .map(|dex| dex.pool_fee_bps)
                .unwrap_or_default(),
            "route leg dex pool fee",
        )?;
        validate_bps(
            self.dex
                .as_ref()
                .map(|dex| dex.price_impact_bps)
                .unwrap_or_default(),
            "route leg price impact",
        )?;
        ensure_status(
            &self.status,
            &[
                LIQUIDITY_ROUTER_STATUS_PENDING,
                LIQUIDITY_ROUTER_STATUS_ACTIVE,
                LIQUIDITY_ROUTER_STATUS_FILLED,
                LIQUIDITY_ROUTER_STATUS_PARTIAL,
                LIQUIDITY_ROUTER_STATUS_REJECTED,
            ],
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverQuote {
    pub quote_id: String,
    pub solver_id: String,
    pub intent_id: String,
    pub auction_id: String,
    pub attestation_id: String,
    pub input_units: u64,
    pub expected_output_units: u64,
    pub guaranteed_output_units: u64,
    pub solver_fee_units: u64,
    pub protocol_fee_units: u64,
    pub estimated_l2_fee_units: u64,
    pub rebate_hint_units: u64,
    pub price_improvement_bps: u64,
    pub latency_estimate_ms: u64,
    pub privacy_score_bps: u64,
    pub route_legs: Vec<LiquidityRouteLeg>,
    pub route_root: String,
    pub quote_commitment: String,
    pub quote_signature_root: String,
    pub submitted_at_height: u64,
    pub valid_until_height: u64,
    pub status: String,
}

impl SolverQuote {
    pub fn new(
        solver_id: &str,
        intent_id: &str,
        auction_id: &str,
        attestation_id: &str,
        input_units: u64,
        expected_output_units: u64,
        guaranteed_output_units: u64,
        solver_fee_units: u64,
        protocol_fee_units: u64,
        estimated_l2_fee_units: u64,
        rebate_hint_units: u64,
        price_improvement_bps: u64,
        latency_estimate_ms: u64,
        privacy_score_bps: u64,
        route_legs: Vec<LiquidityRouteLeg>,
        quote_secret: &str,
        quote_signature: &Value,
        submitted_at_height: u64,
        valid_until_height: u64,
    ) -> LiquidityRouterResult<Self> {
        ensure_non_empty(solver_id, "solver quote solver id")?;
        ensure_non_empty(intent_id, "solver quote intent id")?;
        ensure_non_empty(auction_id, "solver quote auction id")?;
        ensure_non_empty(attestation_id, "solver quote attestation id")?;
        ensure_non_empty(quote_secret, "solver quote secret")?;
        ensure_positive(input_units, "solver quote input units")?;
        ensure_positive(expected_output_units, "solver quote expected output")?;
        ensure_positive(guaranteed_output_units, "solver quote guaranteed output")?;
        if guaranteed_output_units > expected_output_units {
            return Err("solver quote guarantee exceeds expected output".to_string());
        }
        validate_bps(price_improvement_bps, "solver quote price improvement")?;
        validate_bps(privacy_score_bps, "solver quote privacy score")?;
        if route_legs.is_empty() {
            return Err("solver quote route must include at least one leg".to_string());
        }
        if valid_until_height <= submitted_at_height {
            return Err("solver quote expiry must be after submission".to_string());
        }
        let route_root = liquidity_route_leg_root(&route_legs);
        let quote_signature_root =
            liquidity_router_payload_root("LIQUIDITY-ROUTER-QUOTE-SIGNATURE", quote_signature);
        let quote_commitment = liquidity_router_quote_commitment(
            solver_id,
            intent_id,
            auction_id,
            &route_root,
            expected_output_units,
            guaranteed_output_units,
            solver_fee_units.saturating_add(protocol_fee_units),
            quote_secret,
        );
        let quote_id = solver_quote_id(
            solver_id,
            intent_id,
            auction_id,
            &route_root,
            guaranteed_output_units,
            solver_fee_units,
            submitted_at_height,
        );
        let quote = Self {
            quote_id,
            solver_id: solver_id.to_string(),
            intent_id: intent_id.to_string(),
            auction_id: auction_id.to_string(),
            attestation_id: attestation_id.to_string(),
            input_units,
            expected_output_units,
            guaranteed_output_units,
            solver_fee_units,
            protocol_fee_units,
            estimated_l2_fee_units,
            rebate_hint_units,
            price_improvement_bps,
            latency_estimate_ms,
            privacy_score_bps,
            route_legs,
            route_root,
            quote_commitment,
            quote_signature_root,
            submitted_at_height,
            valid_until_height,
            status: LIQUIDITY_ROUTER_STATUS_OPEN.to_string(),
        };
        quote.validate()?;
        Ok(quote)
    }

    pub fn total_fee_units(&self) -> u64 {
        self.solver_fee_units
            .saturating_add(self.protocol_fee_units)
            .saturating_add(self.estimated_l2_fee_units)
            .saturating_sub(self.rebate_hint_units)
    }

    pub fn score(&self, config: &LiquidityRouterConfig) -> u128 {
        let output_score =
            (self.guaranteed_output_units as u128).saturating_mul(config.output_weight_bps as u128);
        let fee_penalty =
            (self.total_fee_units() as u128).saturating_mul(config.fee_weight_bps as u128);
        let speed_score = (TARGET_BLOCK_MS.saturating_mul(4) as u128)
            .saturating_sub(self.latency_estimate_ms.min(TARGET_BLOCK_MS * 4) as u128)
            .saturating_mul(config.speed_weight_bps as u128);
        let privacy_score =
            (self.privacy_score_bps as u128).saturating_mul(config.privacy_weight_bps as u128);
        output_score
            .saturating_add(speed_score)
            .saturating_add(privacy_score)
            .saturating_sub(fee_penalty)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "solver_quote",
            "chain_id": CHAIN_ID,
            "protocol_version": LIQUIDITY_ROUTER_PROTOCOL_VERSION,
            "quote_id": self.quote_id,
            "solver_id": self.solver_id,
            "intent_id": self.intent_id,
            "auction_id": self.auction_id,
            "attestation_id": self.attestation_id,
            "input_units": self.input_units,
            "expected_output_units": self.expected_output_units,
            "guaranteed_output_units": self.guaranteed_output_units,
            "solver_fee_units": self.solver_fee_units,
            "protocol_fee_units": self.protocol_fee_units,
            "estimated_l2_fee_units": self.estimated_l2_fee_units,
            "rebate_hint_units": self.rebate_hint_units,
            "net_fee_units": self.total_fee_units(),
            "price_improvement_bps": self.price_improvement_bps,
            "latency_estimate_ms": self.latency_estimate_ms,
            "privacy_score_bps": self.privacy_score_bps,
            "route_root": self.route_root,
            "quote_commitment": self.quote_commitment,
            "quote_signature_root": self.quote_signature_root,
            "route_legs": self.route_legs.iter().map(LiquidityRouteLeg::public_record).collect::<Vec<_>>(),
            "submitted_at_height": self.submitted_at_height,
            "valid_until_height": self.valid_until_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> LiquidityRouterResult<()> {
        ensure_non_empty(&self.quote_id, "solver quote id")?;
        ensure_non_empty(&self.solver_id, "solver quote solver id")?;
        ensure_non_empty(&self.intent_id, "solver quote intent id")?;
        ensure_non_empty(&self.auction_id, "solver quote auction id")?;
        ensure_non_empty(&self.attestation_id, "solver quote attestation id")?;
        ensure_non_empty(&self.route_root, "solver quote route root")?;
        ensure_non_empty(&self.quote_commitment, "solver quote commitment")?;
        ensure_non_empty(&self.quote_signature_root, "solver quote signature root")?;
        ensure_positive(self.input_units, "solver quote input")?;
        ensure_positive(self.expected_output_units, "solver quote expected output")?;
        ensure_positive(
            self.guaranteed_output_units,
            "solver quote guaranteed output",
        )?;
        if self.route_legs.is_empty() {
            return Err("solver quote route must include at least one leg".to_string());
        }
        if self.valid_until_height <= self.submitted_at_height {
            return Err("solver quote expiry must be after submission".to_string());
        }
        validate_bps(self.price_improvement_bps, "solver quote price improvement")?;
        validate_bps(self.privacy_score_bps, "solver quote privacy score")?;
        ensure_status(
            &self.status,
            &[
                LIQUIDITY_ROUTER_STATUS_OPEN,
                LIQUIDITY_ROUTER_STATUS_WON,
                LIQUIDITY_ROUTER_STATUS_LOST,
                LIQUIDITY_ROUTER_STATUS_FILLED,
                LIQUIDITY_ROUTER_STATUS_EXPIRED,
                LIQUIDITY_ROUTER_STATUS_REJECTED,
            ],
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityBatchAuction {
    pub auction_id: String,
    pub pair_commitment: String,
    pub batch_index: u64,
    pub start_height: u64,
    pub collect_end_height: u64,
    pub reveal_end_height: u64,
    pub challenge_end_height: u64,
    pub settlement_deadline_height: u64,
    pub intent_ids: Vec<String>,
    pub quote_ids: Vec<String>,
    pub winning_quote_ids: Vec<String>,
    pub intent_root: String,
    pub quote_root: String,
    pub winning_quote_root: String,
    pub clearing_price_root: String,
    pub surplus_root: String,
    pub solver_bond_root: String,
    pub pq_transcript_root: String,
    pub low_fee_rebate_pool_units: u64,
    pub phase: LiquidityAuctionPhase,
    pub status: String,
}

impl LiquidityBatchAuction {
    pub fn new(
        pair_label: &str,
        batch_index: u64,
        start_height: u64,
        config: &LiquidityRouterConfig,
        solver_bond_root: impl Into<String>,
        pq_transcript_root: impl Into<String>,
        low_fee_rebate_pool_units: u64,
    ) -> LiquidityRouterResult<Self> {
        ensure_non_empty(pair_label, "liquidity auction pair")?;
        let pair_commitment =
            liquidity_router_string_root("LIQUIDITY-ROUTER-AUCTION-PAIR", pair_label);
        let collect_end_height = start_height.saturating_add(config.auction_window_blocks);
        let reveal_end_height = collect_end_height.saturating_add(config.reveal_window_blocks);
        let challenge_end_height = reveal_end_height.saturating_add(config.challenge_window_blocks);
        let settlement_deadline_height =
            challenge_end_height.saturating_add(config.settlement_ttl_blocks);
        let intent_root = liquidity_router_string_set_root("LIQUIDITY-ROUTER-AUCTION-INTENT", &[]);
        let quote_root = liquidity_router_string_set_root("LIQUIDITY-ROUTER-AUCTION-QUOTE", &[]);
        let winning_quote_root =
            liquidity_router_string_set_root("LIQUIDITY-ROUTER-AUCTION-WINNING-QUOTE", &[]);
        let clearing_price_root =
            liquidity_router_payload_root("LIQUIDITY-ROUTER-CLEARING-PRICE", &json!({}));
        let surplus_root = liquidity_router_payload_root("LIQUIDITY-ROUTER-SURPLUS", &json!({}));
        let solver_bond_root = solver_bond_root.into();
        let pq_transcript_root = pq_transcript_root.into();
        ensure_non_empty(&solver_bond_root, "liquidity auction solver bond root")?;
        ensure_non_empty(&pq_transcript_root, "liquidity auction pq transcript root")?;
        let auction_id = liquidity_batch_auction_id(
            &pair_commitment,
            batch_index,
            start_height,
            collect_end_height,
            &solver_bond_root,
            &pq_transcript_root,
        );
        Ok(Self {
            auction_id,
            pair_commitment,
            batch_index,
            start_height,
            collect_end_height,
            reveal_end_height,
            challenge_end_height,
            settlement_deadline_height,
            intent_ids: Vec::new(),
            quote_ids: Vec::new(),
            winning_quote_ids: Vec::new(),
            intent_root,
            quote_root,
            winning_quote_root,
            clearing_price_root,
            surplus_root,
            solver_bond_root,
            pq_transcript_root,
            low_fee_rebate_pool_units,
            phase: LiquidityAuctionPhase::Collecting,
            status: LIQUIDITY_ROUTER_STATUS_COLLECTING.to_string(),
        })
    }

    pub fn refresh_phase(&mut self, height: u64) {
        if height > self.settlement_deadline_height
            && self.status != LIQUIDITY_ROUTER_STATUS_SETTLED
        {
            self.phase = LiquidityAuctionPhase::Expired;
            self.status = LIQUIDITY_ROUTER_STATUS_EXPIRED.to_string();
        } else if height > self.challenge_end_height {
            self.phase = LiquidityAuctionPhase::Challenge;
            self.status = LIQUIDITY_ROUTER_STATUS_MATCHING.to_string();
        } else if height > self.reveal_end_height {
            self.phase = LiquidityAuctionPhase::Matching;
            self.status = LIQUIDITY_ROUTER_STATUS_MATCHING.to_string();
        } else if height > self.collect_end_height {
            self.phase = LiquidityAuctionPhase::Revealing;
            self.status = LIQUIDITY_ROUTER_STATUS_REVEALING.to_string();
        } else {
            self.phase = LiquidityAuctionPhase::Collecting;
            self.status = LIQUIDITY_ROUTER_STATUS_COLLECTING.to_string();
        }
    }

    pub fn add_intent(&mut self, intent_id: String) {
        if !self.intent_ids.iter().any(|id| id == &intent_id) {
            self.intent_ids.push(intent_id);
            self.intent_ids.sort();
            self.intent_root = liquidity_router_string_set_root(
                "LIQUIDITY-ROUTER-AUCTION-INTENT",
                &self.intent_ids,
            );
        }
    }

    pub fn add_quote(&mut self, quote_id: String) {
        if !self.quote_ids.iter().any(|id| id == &quote_id) {
            self.quote_ids.push(quote_id);
            self.quote_ids.sort();
            self.quote_root =
                liquidity_router_string_set_root("LIQUIDITY-ROUTER-AUCTION-QUOTE", &self.quote_ids);
        }
    }

    pub fn set_winners(
        &mut self,
        winning_quote_ids: Vec<String>,
        clearing: &Value,
        surplus: &Value,
    ) {
        let mut winning_quote_ids = winning_quote_ids;
        winning_quote_ids.sort();
        winning_quote_ids.dedup();
        self.winning_quote_root = liquidity_router_string_set_root(
            "LIQUIDITY-ROUTER-AUCTION-WINNING-QUOTE",
            &winning_quote_ids,
        );
        self.clearing_price_root =
            liquidity_router_payload_root("LIQUIDITY-ROUTER-CLEARING-PRICE", clearing);
        self.surplus_root = liquidity_router_payload_root("LIQUIDITY-ROUTER-SURPLUS", surplus);
        self.winning_quote_ids = winning_quote_ids;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "liquidity_batch_auction",
            "chain_id": CHAIN_ID,
            "protocol_version": LIQUIDITY_ROUTER_PROTOCOL_VERSION,
            "auction_id": self.auction_id,
            "pair_commitment": self.pair_commitment,
            "batch_index": self.batch_index,
            "start_height": self.start_height,
            "collect_end_height": self.collect_end_height,
            "reveal_end_height": self.reveal_end_height,
            "challenge_end_height": self.challenge_end_height,
            "settlement_deadline_height": self.settlement_deadline_height,
            "intent_ids": self.intent_ids,
            "quote_ids": self.quote_ids,
            "winning_quote_ids": self.winning_quote_ids,
            "intent_root": self.intent_root,
            "quote_root": self.quote_root,
            "winning_quote_root": self.winning_quote_root,
            "clearing_price_root": self.clearing_price_root,
            "surplus_root": self.surplus_root,
            "solver_bond_root": self.solver_bond_root,
            "pq_transcript_root": self.pq_transcript_root,
            "low_fee_rebate_pool_units": self.low_fee_rebate_pool_units,
            "phase": self.phase.as_str(),
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CongestionAwareFeeRebate {
    pub rebate_id: String,
    pub intent_id: String,
    pub quote_id: String,
    pub auction_id: String,
    pub owner_commitment: String,
    pub lane_id: String,
    pub fee_asset_id: String,
    pub congestion_bps: u64,
    pub target_congestion_bps: u64,
    pub eligible_fee_units: u64,
    pub rebate_bps: u64,
    pub rebate_units: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl CongestionAwareFeeRebate {
    pub fn new(
        intent: &EncryptedRouteIntent,
        quote: &SolverQuote,
        config: &LiquidityRouterConfig,
        congestion_bps: u64,
        created_at_height: u64,
    ) -> LiquidityRouterResult<Self> {
        validate_bps(congestion_bps, "fee rebate congestion")?;
        let eligible_fee_units = quote
            .solver_fee_units
            .saturating_add(quote.protocol_fee_units)
            .saturating_add(quote.estimated_l2_fee_units);
        let pressure_bps = congestion_bps.saturating_sub(config.congestion_target_bps);
        let rebate_bps = if pressure_bps == 0 {
            config.max_rebate_bps / 2
        } else {
            config
                .max_rebate_bps
                .saturating_sub(pressure_bps.min(config.max_rebate_bps / 2))
        };
        let rebate_units =
            bps_mul_floor(eligible_fee_units, rebate_bps).min(quote.rebate_hint_units);
        let expires_at_height = created_at_height.saturating_add(config.settlement_ttl_blocks);
        let rebate_id = congestion_fee_rebate_id(
            &intent.intent_id,
            &quote.quote_id,
            &quote.auction_id,
            &intent.owner_commitment,
            &intent.low_fee_lane_id,
            eligible_fee_units,
            rebate_units,
            created_at_height,
        );
        Ok(Self {
            rebate_id,
            intent_id: intent.intent_id.clone(),
            quote_id: quote.quote_id.clone(),
            auction_id: quote.auction_id.clone(),
            owner_commitment: intent.owner_commitment.clone(),
            lane_id: intent.low_fee_lane_id.clone(),
            fee_asset_id: config.fee_asset_id.clone(),
            congestion_bps,
            target_congestion_bps: config.congestion_target_bps,
            eligible_fee_units,
            rebate_bps,
            rebate_units,
            created_at_height,
            expires_at_height,
            status: LIQUIDITY_ROUTER_STATUS_RESERVED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "congestion_aware_fee_rebate",
            "chain_id": CHAIN_ID,
            "protocol_version": LIQUIDITY_ROUTER_PROTOCOL_VERSION,
            "rebate_id": self.rebate_id,
            "intent_id": self.intent_id,
            "quote_id": self.quote_id,
            "auction_id": self.auction_id,
            "owner_commitment": self.owner_commitment,
            "lane_id": self.lane_id,
            "fee_asset_id": self.fee_asset_id,
            "congestion_bps": self.congestion_bps,
            "target_congestion_bps": self.target_congestion_bps,
            "eligible_fee_units": self.eligible_fee_units,
            "rebate_bps": self.rebate_bps,
            "rebate_units": self.rebate_units,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteLegReceipt {
    pub leg_receipt_id: String,
    pub leg_id: String,
    pub leg_index: u64,
    pub input_units: u64,
    pub output_units: u64,
    pub fee_units: u64,
    pub proof_root: String,
    pub status: String,
}

impl RouteLegReceipt {
    pub fn from_leg(leg: &LiquidityRouteLeg, quote_id: &str, settled_at_height: u64) -> Self {
        let proof_root = liquidity_router_payload_root(
            "LIQUIDITY-ROUTER-LEG-RECEIPT-PROOF",
            &json!({
                "leg_id": leg.leg_id,
                "quote_id": quote_id,
                "settled_at_height": settled_at_height,
            }),
        );
        let leg_receipt_id = route_leg_receipt_id(
            quote_id,
            &leg.leg_id,
            leg.leg_index,
            leg.expected_input_units,
            leg.expected_output_units,
            settled_at_height,
        );
        Self {
            leg_receipt_id,
            leg_id: leg.leg_id.clone(),
            leg_index: leg.leg_index,
            input_units: leg.expected_input_units,
            output_units: leg.expected_output_units,
            fee_units: leg.fee_units,
            proof_root,
            status: LIQUIDITY_ROUTER_STATUS_FILLED.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "route_leg_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": LIQUIDITY_ROUTER_PROTOCOL_VERSION,
            "leg_receipt_id": self.leg_receipt_id,
            "leg_id": self.leg_id,
            "leg_index": self.leg_index,
            "input_units": self.input_units,
            "output_units": self.output_units,
            "fee_units": self.fee_units,
            "proof_root": self.proof_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub intent_id: String,
    pub quote_id: String,
    pub auction_id: String,
    pub solver_id: String,
    pub route_root: String,
    pub leg_receipts: Vec<RouteLegReceipt>,
    pub leg_receipt_root: String,
    pub input_units: u64,
    pub output_units: u64,
    pub fee_units_paid: u64,
    pub rebate_units_applied: u64,
    pub settlement_height: u64,
    pub settlement_proof_root: String,
    pub nullifier_root: String,
    pub output_note_root: String,
    pub status: String,
}

impl SettlementReceipt {
    pub fn new(
        quote: &SolverQuote,
        rebate_units_applied: u64,
        settlement_height: u64,
        nullifier_payload: &Value,
        output_note_payload: &Value,
    ) -> LiquidityRouterResult<Self> {
        let leg_receipts = quote
            .route_legs
            .iter()
            .map(|leg| RouteLegReceipt::from_leg(leg, &quote.quote_id, settlement_height))
            .collect::<Vec<_>>();
        let leg_receipt_root = route_leg_receipt_root(&leg_receipts);
        let fee_units_paid = quote.total_fee_units().saturating_sub(rebate_units_applied);
        let settlement_proof_root = liquidity_router_payload_root(
            "LIQUIDITY-ROUTER-SETTLEMENT-PROOF",
            &json!({
                "proof_system": LIQUIDITY_ROUTER_SETTLEMENT_PROOF_SYSTEM,
                "quote_id": quote.quote_id,
                "route_root": quote.route_root,
                "leg_receipt_root": leg_receipt_root,
            }),
        );
        let nullifier_root = liquidity_router_payload_root(
            "LIQUIDITY-ROUTER-SETTLEMENT-NULLIFIER",
            nullifier_payload,
        );
        let output_note_root = liquidity_router_payload_root(
            "LIQUIDITY-ROUTER-SETTLEMENT-OUTPUT",
            output_note_payload,
        );
        let receipt_id = settlement_receipt_id(
            &quote.intent_id,
            &quote.quote_id,
            &quote.auction_id,
            &quote.solver_id,
            &quote.route_root,
            settlement_height,
        );
        Ok(Self {
            receipt_id,
            intent_id: quote.intent_id.clone(),
            quote_id: quote.quote_id.clone(),
            auction_id: quote.auction_id.clone(),
            solver_id: quote.solver_id.clone(),
            route_root: quote.route_root.clone(),
            leg_receipts,
            leg_receipt_root,
            input_units: quote.input_units,
            output_units: quote.guaranteed_output_units,
            fee_units_paid,
            rebate_units_applied,
            settlement_height,
            settlement_proof_root,
            nullifier_root,
            output_note_root,
            status: LIQUIDITY_ROUTER_STATUS_SETTLED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "settlement_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": LIQUIDITY_ROUTER_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "intent_id": self.intent_id,
            "quote_id": self.quote_id,
            "auction_id": self.auction_id,
            "solver_id": self.solver_id,
            "route_root": self.route_root,
            "leg_receipt_root": self.leg_receipt_root,
            "leg_receipts": self.leg_receipts.iter().map(RouteLegReceipt::public_record).collect::<Vec<_>>(),
            "input_units": self.input_units,
            "output_units": self.output_units,
            "fee_units_paid": self.fee_units_paid,
            "rebate_units_applied": self.rebate_units_applied,
            "settlement_height": self.settlement_height,
            "settlement_proof_root": self.settlement_proof_root,
            "nullifier_root": self.nullifier_root,
            "output_note_root": self.output_note_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivocationEvidence {
    pub evidence_id: String,
    pub solver_id: String,
    pub auction_id: String,
    pub first_quote_id: String,
    pub second_quote_id: String,
    pub first_quote_root: String,
    pub second_quote_root: String,
    pub conflicting_field: String,
    pub reporter_commitment: String,
    pub evidence_root: String,
    pub observed_at_height: u64,
    pub recommended_slash_units: u64,
    pub status: String,
}

impl EquivocationEvidence {
    pub fn new(
        first: &SolverQuote,
        second: &SolverQuote,
        conflicting_field: &str,
        reporter_label: &str,
        observed_at_height: u64,
        recommended_slash_units: u64,
    ) -> LiquidityRouterResult<Self> {
        if first.solver_id != second.solver_id {
            return Err("equivocation evidence requires one solver".to_string());
        }
        if first.auction_id != second.auction_id {
            return Err("equivocation evidence requires one auction".to_string());
        }
        if first.quote_id == second.quote_id {
            return Err("equivocation evidence requires two quotes".to_string());
        }
        ensure_non_empty(conflicting_field, "equivocation conflicting field")?;
        ensure_non_empty(reporter_label, "equivocation reporter")?;
        ensure_positive(recommended_slash_units, "equivocation slash units")?;
        let first_quote_root = liquidity_router_payload_root(
            "LIQUIDITY-ROUTER-EQUIVOCATION-FIRST",
            &first.public_record(),
        );
        let second_quote_root = liquidity_router_payload_root(
            "LIQUIDITY-ROUTER-EQUIVOCATION-SECOND",
            &second.public_record(),
        );
        let reporter_commitment = liquidity_router_account_commitment(reporter_label);
        let evidence_root = liquidity_router_payload_root(
            "LIQUIDITY-ROUTER-EQUIVOCATION-PROOF",
            &json!({
                "proof_system": LIQUIDITY_ROUTER_EQUIVOCATION_PROOF_SYSTEM,
                "first_quote_root": first_quote_root,
                "second_quote_root": second_quote_root,
                "conflicting_field": conflicting_field,
            }),
        );
        let evidence_id = equivocation_evidence_id(
            &first.solver_id,
            &first.auction_id,
            &first.quote_id,
            &second.quote_id,
            &evidence_root,
            observed_at_height,
        );
        Ok(Self {
            evidence_id,
            solver_id: first.solver_id.clone(),
            auction_id: first.auction_id.clone(),
            first_quote_id: first.quote_id.clone(),
            second_quote_id: second.quote_id.clone(),
            first_quote_root,
            second_quote_root,
            conflicting_field: conflicting_field.to_string(),
            reporter_commitment,
            evidence_root,
            observed_at_height,
            recommended_slash_units,
            status: LIQUIDITY_ROUTER_STATUS_OPEN.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "equivocation_evidence",
            "chain_id": CHAIN_ID,
            "protocol_version": LIQUIDITY_ROUTER_PROTOCOL_VERSION,
            "evidence_id": self.evidence_id,
            "solver_id": self.solver_id,
            "auction_id": self.auction_id,
            "first_quote_id": self.first_quote_id,
            "second_quote_id": self.second_quote_id,
            "first_quote_root": self.first_quote_root,
            "second_quote_root": self.second_quote_root,
            "conflicting_field": self.conflicting_field,
            "reporter_commitment": self.reporter_commitment,
            "evidence_root": self.evidence_root,
            "observed_at_height": self.observed_at_height,
            "recommended_slash_units": self.recommended_slash_units,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingRecord {
    pub slash_id: String,
    pub evidence_id: String,
    pub solver_id: String,
    pub reason: SlashingReason,
    pub bond_asset_id: String,
    pub bond_units_before: u64,
    pub slash_units: u64,
    pub bond_units_after: u64,
    pub beneficiary_commitment: String,
    pub executed_at_height: u64,
    pub status: String,
}

impl SlashingRecord {
    pub fn new(
        evidence: &EquivocationEvidence,
        solver: &LiquiditySolverProfile,
        reason: SlashingReason,
        beneficiary_label: &str,
        executed_at_height: u64,
    ) -> LiquidityRouterResult<Self> {
        ensure_non_empty(beneficiary_label, "slashing beneficiary")?;
        let slash_units = evidence.recommended_slash_units.min(solver.bond_units);
        ensure_positive(slash_units, "slashing units")?;
        let bond_units_after = solver.bond_units.saturating_sub(slash_units);
        let beneficiary_commitment = liquidity_router_account_commitment(beneficiary_label);
        let slash_id = slashing_record_id(
            &evidence.evidence_id,
            &solver.solver_id,
            reason,
            slash_units,
            executed_at_height,
        );
        Ok(Self {
            slash_id,
            evidence_id: evidence.evidence_id.clone(),
            solver_id: solver.solver_id.clone(),
            reason,
            bond_asset_id: solver.bond_asset_id.clone(),
            bond_units_before: solver.bond_units,
            slash_units,
            bond_units_after,
            beneficiary_commitment,
            executed_at_height,
            status: LIQUIDITY_ROUTER_STATUS_SLASHED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "slashing_record",
            "chain_id": CHAIN_ID,
            "protocol_version": LIQUIDITY_ROUTER_PROTOCOL_VERSION,
            "slash_id": self.slash_id,
            "evidence_id": self.evidence_id,
            "solver_id": self.solver_id,
            "reason": self.reason.as_str(),
            "bond_asset_id": self.bond_asset_id,
            "bond_units_before": self.bond_units_before,
            "slash_units": self.slash_units,
            "bond_units_after": self.bond_units_after,
            "beneficiary_commitment": self.beneficiary_commitment,
            "executed_at_height": self.executed_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityRouterRoots {
    pub config_root: String,
    pub intent_root: String,
    pub solver_root: String,
    pub attestation_root: String,
    pub quote_root: String,
    pub auction_root: String,
    pub route_leg_root: String,
    pub rebate_root: String,
    pub receipt_root: String,
    pub leg_receipt_root: String,
    pub equivocation_evidence_root: String,
    pub slashing_root: String,
    pub congestion_oracle_root: String,
    pub counters_root: String,
}

impl LiquidityRouterRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "liquidity_router_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": LIQUIDITY_ROUTER_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "intent_root": self.intent_root,
            "solver_root": self.solver_root,
            "attestation_root": self.attestation_root,
            "quote_root": self.quote_root,
            "auction_root": self.auction_root,
            "route_leg_root": self.route_leg_root,
            "rebate_root": self.rebate_root,
            "receipt_root": self.receipt_root,
            "leg_receipt_root": self.leg_receipt_root,
            "equivocation_evidence_root": self.equivocation_evidence_root,
            "slashing_root": self.slashing_root,
            "congestion_oracle_root": self.congestion_oracle_root,
            "counters_root": self.counters_root,
        })
    }

    pub fn state_root(&self) -> String {
        liquidity_router_state_root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityRouterState {
    pub config: LiquidityRouterConfig,
    pub height: u64,
    pub intents: BTreeMap<String, EncryptedRouteIntent>,
    pub solvers: BTreeMap<String, LiquiditySolverProfile>,
    pub attestations: BTreeMap<String, PqSolverAttestation>,
    pub quotes: BTreeMap<String, SolverQuote>,
    pub auctions: BTreeMap<String, LiquidityBatchAuction>,
    pub rebates: BTreeMap<String, CongestionAwareFeeRebate>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub equivocation_evidence: BTreeMap<String, EquivocationEvidence>,
    pub slashing_records: BTreeMap<String, SlashingRecord>,
    pub congestion_oracles: BTreeMap<String, u64>,
    pub counters: LiquidityRouterCounters,
}

impl Default for LiquidityRouterState {
    fn default() -> Self {
        Self {
            config: LiquidityRouterConfig::default(),
            height: 0,
            intents: BTreeMap::new(),
            solvers: BTreeMap::new(),
            attestations: BTreeMap::new(),
            quotes: BTreeMap::new(),
            auctions: BTreeMap::new(),
            rebates: BTreeMap::new(),
            receipts: BTreeMap::new(),
            equivocation_evidence: BTreeMap::new(),
            slashing_records: BTreeMap::new(),
            congestion_oracles: BTreeMap::new(),
            counters: LiquidityRouterCounters::default(),
        }
    }
}

impl LiquidityRouterState {
    pub fn new(config: LiquidityRouterConfig) -> LiquidityRouterResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::default()
        })
    }

    pub fn devnet() -> LiquidityRouterResult<Self> {
        let mut state = Self::new(LiquidityRouterConfig::default())?;
        state.height = LIQUIDITY_ROUTER_DEVNET_HEIGHT;
        state.set_congestion(LIQUIDITY_ROUTER_DEFAULT_PRIVATE_LANE_ID, 4_200)?;
        state.set_congestion(LIQUIDITY_ROUTER_DEFAULT_BRIDGE_LANE_ID, 5_800)?;
        state.set_congestion(LIQUIDITY_ROUTER_DEFAULT_DEFI_LANE_ID, 3_500)?;
        state.set_congestion(LIQUIDITY_ROUTER_DEFAULT_LENDING_LANE_ID, 2_700)?;

        let solver_legs = vec![
            LiquidityRouteLegKind::MoneroBridge,
            LiquidityRouteLegKind::PrivateDex,
            LiquidityRouteLegKind::LendingMarket,
            LiquidityRouteLegKind::Settlement,
            LiquidityRouteLegKind::Rebate,
        ];
        let supported_assets = vec![
            LIQUIDITY_ROUTER_DEVNET_WXMR_ASSET_ID.to_string(),
            LIQUIDITY_ROUTER_DEVNET_USDD_ASSET_ID.to_string(),
            LIQUIDITY_ROUTER_DEVNET_DNR_ASSET_ID.to_string(),
        ];
        let fast_solver = LiquiditySolverProfile::new(
            "devnet-fast-solver",
            LiquiditySolverKind::HybridSolver,
            "devnet-operator-fast",
            LIQUIDITY_ROUTER_DEVNET_FEE_ASSET_ID,
            125_000,
            5,
            256,
            12,
            TARGET_BLOCK_MS / 2,
            &json!({"ml_kem": "devnet-fast-kem", "ml_dsa": "devnet-fast-dsa"}),
            "devnet-fast-solver-private-endpoint",
            &solver_legs,
            &supported_assets,
        )?;
        let fast_solver_id = state.register_solver(fast_solver)?;
        let bridge_solver = LiquiditySolverProfile::new(
            "devnet-bridge-maker",
            LiquiditySolverKind::BridgeSpecialist,
            "devnet-operator-bridge",
            LIQUIDITY_ROUTER_DEVNET_FEE_ASSET_ID,
            95_000,
            4,
            128,
            10,
            TARGET_BLOCK_MS,
            &json!({"ml_kem": "devnet-bridge-kem", "reserve": "monero-hot-warm"}),
            "devnet-bridge-maker-private-endpoint",
            &solver_legs,
            &supported_assets,
        )?;
        let bridge_solver_id = state.register_solver(bridge_solver)?;

        let fast_attestation = PqSolverAttestation::new(
            &fast_solver_id,
            "devnet-fast-solver-ml-kem-768-pubkey",
            &json!({"signature": "devnet-fast-ml-dsa+slh-dsa", "height": state.height}),
            &[
                "private-dex-route".to_string(),
                "monero-bridge-route".to_string(),
                "lending-route".to_string(),
            ],
            &[
                LIQUIDITY_ROUTER_INTENT_PROOF_SYSTEM.to_string(),
                LIQUIDITY_ROUTER_ROUTE_PROOF_SYSTEM.to_string(),
                LIQUIDITY_ROUTER_SETTLEMENT_PROOF_SYSTEM.to_string(),
            ],
            &json!({"tee": "devnet-none", "deterministic": true}),
            state.height,
            state.height + 720,
        )?;
        let fast_attestation_id = state.record_attestation(fast_attestation)?;
        let bridge_attestation = PqSolverAttestation::new(
            &bridge_solver_id,
            "devnet-bridge-maker-ml-kem-768-pubkey",
            &json!({"signature": "devnet-bridge-ml-dsa+slh-dsa", "height": state.height}),
            &[
                "monero-bridge-route".to_string(),
                "rebate-route".to_string(),
            ],
            &[LIQUIDITY_ROUTER_ROUTE_PROOF_SYSTEM.to_string()],
            &json!({"reserve_attestation": "devnet-monero-reserve-root"}),
            state.height,
            state.height + 720,
        )?;
        let bridge_attestation_id = state.record_attestation(bridge_attestation)?;

        let encrypted_payload = json!({
            "intent": "withdraw-wxmr-swap-and-supply",
            "asset_in": LIQUIDITY_ROUTER_DEVNET_WXMR_ASSET_ID,
            "asset_out": LIQUIDITY_ROUTER_DEVNET_USDD_ASSET_ID,
            "amount_in": 42_000_000_u64,
            "min_output": 7_500_000_000_u64,
            "private_recipient": "devnet-alice-output-note",
            "lending_market": "devnet-usdd-supply-vault",
        });
        let route_hint = json!({
            "families": ["monero_bridge", "private_dex", "lending_market"],
            "max_hops": 4,
            "avoid": ["public_mempool", "toxic_orderflow"],
        });
        let intent = EncryptedRouteIntent::new(
            "devnet-alice",
            LiquidityRouteIntentKind::CrossVenueSwap,
            LiquidityPrivacyMode::SolverViewKey,
            LIQUIDITY_ROUTER_DEVNET_WXMR_ASSET_ID,
            LIQUIDITY_ROUTER_DEVNET_USDD_ASSET_ID,
            42_000_000,
            7_500_000_000,
            18_000,
            45,
            state.height + state.config.intent_ttl_blocks,
            state.height,
            1,
            &encrypted_payload,
            &route_hint,
            "devnet-alice-router-view-key",
            "devnet-alice-refund",
            "devnet-alice-privacy-budget",
            LIQUIDITY_ROUTER_DEFAULT_PRIVATE_LANE_ID,
            &json!({"wallet": "devnet-alice", "urgency": "fast-low-fee"}),
        )?;
        let intent_id = state.submit_intent(intent)?;

        let mut auction = LiquidityBatchAuction::new(
            "wxmr/usdd/private",
            1,
            state.height,
            &state.config,
            state.solver_root(),
            state.attestation_root(),
            40_000,
        )?;
        auction.add_intent(intent_id.clone());
        let auction_id = state.open_auction(auction)?;

        let quote_hint_fast = liquidity_router_string_root("LIQUIDITY-ROUTER-DEVNET-QUOTE", "fast");
        let bridge_leg = LiquidityRouteLeg::bridge(
            &quote_hint_fast,
            0,
            LIQUIDITY_ROUTER_DEVNET_WXMR_ASSET_ID,
            LIQUIDITY_ROUTER_DEVNET_WXMR_ASSET_ID,
            42_000_000,
            41_980_000,
            4_500,
            LIQUIDITY_ROUTER_DEVNET_FEE_ASSET_ID,
            "devnet-monero-bridge-adapter",
            BridgeRouteLeg {
                bridge_network: LIQUIDITY_ROUTER_DEVNET_MONERO_NETWORK.to_string(),
                direction: BridgeLegDirection::Withdrawal,
                reserve_lane_id: "devnet-hot-reserve".to_string(),
                withdrawal_bucket_id: "devnet-bucket-40m-50m".to_string(),
                bridge_fee_units: 4_500,
                release_not_before_height: state.height + 2,
                reserve_proof_root: liquidity_router_string_root(
                    "LIQUIDITY-ROUTER-DEVNET-RESERVE-PROOF",
                    "fast-reserve",
                ),
            },
        )?;
        let dex_leg = LiquidityRouteLeg::dex(
            &quote_hint_fast,
            1,
            LIQUIDITY_ROUTER_DEVNET_WXMR_ASSET_ID,
            LIQUIDITY_ROUTER_DEVNET_USDD_ASSET_ID,
            41_980_000,
            7_568_000_000,
            6_000,
            LIQUIDITY_ROUTER_DEVNET_FEE_ASSET_ID,
            "devnet-private-dex-adapter",
            DexRouteLeg {
                dex_kind: DexLegKind::Hybrid,
                venue_id: "devnet-private-dex".to_string(),
                pool_id: "devnet-wxmr-usdd-hybrid".to_string(),
                price_limit_commitment: liquidity_router_amount_commitment(
                    180_000_000,
                    "devnet-fast-price-limit",
                ),
                pool_fee_bps: 12,
                price_impact_bps: 35,
                oracle_guard_root: liquidity_router_string_root(
                    "LIQUIDITY-ROUTER-DEVNET-ORACLE-GUARD",
                    "wxmr-usdd-fast",
                ),
            },
        )?;
        let lending_leg = LiquidityRouteLeg::lending(
            &quote_hint_fast,
            2,
            LIQUIDITY_ROUTER_DEVNET_USDD_ASSET_ID,
            LIQUIDITY_ROUTER_DEVNET_USDD_ASSET_ID,
            7_568_000_000,
            7_566_500_000,
            2_000,
            LIQUIDITY_ROUTER_DEVNET_FEE_ASSET_ID,
            "devnet-private-lending-adapter",
            LendingRouteLeg {
                market_id: "devnet-usdd-supply-vault".to_string(),
                action: LendingLegAction::Supply,
                collateral_asset_commitment: liquidity_router_asset_commitment(
                    LIQUIDITY_ROUTER_DEVNET_USDD_ASSET_ID,
                ),
                debt_asset_commitment: liquidity_router_asset_commitment(
                    LIQUIDITY_ROUTER_DEVNET_WXMR_ASSET_ID,
                ),
                health_factor_bps_after: 18_500,
                interest_rate_bps: 312,
                risk_guard_root: liquidity_router_string_root(
                    "LIQUIDITY-ROUTER-DEVNET-RISK-GUARD",
                    "usdd-supply-fast",
                ),
            },
        )?;
        let settlement_leg = LiquidityRouteLeg::settlement(
            &quote_hint_fast,
            3,
            LIQUIDITY_ROUTER_DEVNET_USDD_ASSET_ID,
            7_566_500_000,
            LIQUIDITY_ROUTER_DEVNET_FEE_ASSET_ID,
            "devnet-private-settlement-adapter",
        )?;
        let fast_quote = SolverQuote::new(
            &fast_solver_id,
            &intent_id,
            &auction_id,
            &fast_attestation_id,
            42_000_000,
            7_568_000_000,
            7_550_000_000,
            3_200,
            1_400,
            9_500,
            10_000,
            55,
            TARGET_BLOCK_MS / 2,
            9_200,
            vec![bridge_leg, dex_leg, lending_leg, settlement_leg],
            "devnet-fast-quote-secret",
            &json!({"quote_sig": "devnet-fast-sig"}),
            state.height + 1,
            state.height + state.config.quote_ttl_blocks,
        )?;
        let fast_quote_id = state.submit_quote(fast_quote)?;

        let quote_hint_bridge =
            liquidity_router_string_root("LIQUIDITY-ROUTER-DEVNET-QUOTE", "bridge");
        let bridge_only_leg = LiquidityRouteLeg::bridge(
            &quote_hint_bridge,
            0,
            LIQUIDITY_ROUTER_DEVNET_WXMR_ASSET_ID,
            LIQUIDITY_ROUTER_DEVNET_WXMR_ASSET_ID,
            42_000_000,
            41_960_000,
            3_000,
            LIQUIDITY_ROUTER_DEVNET_FEE_ASSET_ID,
            "devnet-monero-bridge-adapter",
            BridgeRouteLeg {
                bridge_network: LIQUIDITY_ROUTER_DEVNET_MONERO_NETWORK.to_string(),
                direction: BridgeLegDirection::Withdrawal,
                reserve_lane_id: "devnet-warm-reserve".to_string(),
                withdrawal_bucket_id: "devnet-bucket-40m-50m".to_string(),
                bridge_fee_units: 3_000,
                release_not_before_height: state.height + 3,
                reserve_proof_root: liquidity_router_string_root(
                    "LIQUIDITY-ROUTER-DEVNET-RESERVE-PROOF",
                    "bridge-maker-reserve",
                ),
            },
        )?;
        let bridge_dex_leg = LiquidityRouteLeg::dex(
            &quote_hint_bridge,
            1,
            LIQUIDITY_ROUTER_DEVNET_WXMR_ASSET_ID,
            LIQUIDITY_ROUTER_DEVNET_USDD_ASSET_ID,
            41_960_000,
            7_538_000_000,
            5_000,
            LIQUIDITY_ROUTER_DEVNET_FEE_ASSET_ID,
            "devnet-private-dex-adapter",
            DexRouteLeg {
                dex_kind: DexLegKind::BatchAuction,
                venue_id: "devnet-private-dex".to_string(),
                pool_id: "devnet-wxmr-usdd-batch".to_string(),
                price_limit_commitment: liquidity_router_amount_commitment(
                    179_000_000,
                    "devnet-bridge-price-limit",
                ),
                pool_fee_bps: 10,
                price_impact_bps: 42,
                oracle_guard_root: liquidity_router_string_root(
                    "LIQUIDITY-ROUTER-DEVNET-ORACLE-GUARD",
                    "wxmr-usdd-bridge",
                ),
            },
        )?;
        let bridge_quote = SolverQuote::new(
            &bridge_solver_id,
            &intent_id,
            &auction_id,
            &bridge_attestation_id,
            42_000_000,
            7_538_000_000,
            7_522_000_000,
            2_200,
            1_200,
            8_000,
            8_500,
            35,
            TARGET_BLOCK_MS,
            8_500,
            vec![bridge_only_leg, bridge_dex_leg],
            "devnet-bridge-quote-secret",
            &json!({"quote_sig": "devnet-bridge-sig"}),
            state.height + 1,
            state.height + state.config.quote_ttl_blocks,
        )?;
        let bridge_quote_id = state.submit_quote(bridge_quote)?;

        state.attach_quote_to_auction(&auction_id, &fast_quote_id)?;
        state.attach_quote_to_auction(&auction_id, &bridge_quote_id)?;
        state.run_solver_competition(&auction_id)?;
        let receipt_id = state.settle_quote(
            &fast_quote_id,
            4_200,
            &json!({"nullifier": "devnet-alice-route-nullifier"}),
            &json!({"note": "devnet-alice-usdd-supply-note"}),
        )?;

        let mut conflicting_quote = state
            .quotes
            .get(&fast_quote_id)
            .cloned()
            .ok_or_else(|| "devnet fast quote missing".to_string())?;
        conflicting_quote.quote_id = solver_quote_id(
            &fast_solver_id,
            &intent_id,
            &auction_id,
            "devnet-conflicting-route-root",
            7_520_000_000,
            9_900,
            state.height + 2,
        );
        conflicting_quote.route_root = "devnet-conflicting-route-root".to_string();
        conflicting_quote.guaranteed_output_units = 7_520_000_000;
        conflicting_quote.solver_fee_units = 9_900;
        conflicting_quote.status = LIQUIDITY_ROUTER_STATUS_REJECTED.to_string();
        let conflicting_quote_id = state.submit_quote(conflicting_quote)?;
        let first = state
            .quotes
            .get(&fast_quote_id)
            .cloned()
            .ok_or_else(|| "devnet first quote missing".to_string())?;
        let second = state
            .quotes
            .get(&conflicting_quote_id)
            .cloned()
            .ok_or_else(|| "devnet second quote missing".to_string())?;
        let evidence = EquivocationEvidence::new(
            &first,
            &second,
            "route_root",
            "devnet-watchtower",
            state.height + 3,
            12_500,
        )?;
        let evidence_id = state.record_equivocation(evidence)?;
        state.slash_solver(
            &evidence_id,
            SlashingReason::Equivocation,
            "devnet-insurance-fund",
        )?;

        if !state.receipts.contains_key(&receipt_id) {
            return Err("devnet settlement receipt was not recorded".to_string());
        }
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> LiquidityRouterResult<String> {
        self.height = height;
        for auction in self.auctions.values_mut() {
            auction.refresh_phase(height);
        }
        for intent in self.intents.values_mut() {
            if intent.status == LIQUIDITY_ROUTER_STATUS_ACTIVE && intent.deadline_height < height {
                intent.status = LIQUIDITY_ROUTER_STATUS_EXPIRED.to_string();
                self.counters.expired_intents = self.counters.expired_intents.saturating_add(1);
            }
        }
        for attestation in self.attestations.values_mut() {
            if attestation.status == LIQUIDITY_ROUTER_STATUS_VERIFIED
                && attestation.expires_at_height < height
            {
                attestation.status = LIQUIDITY_ROUTER_STATUS_EXPIRED.to_string();
            }
        }
        Ok(self.state_root())
    }

    pub fn set_congestion(
        &mut self,
        lane_id: &str,
        congestion_bps: u64,
    ) -> LiquidityRouterResult<()> {
        ensure_non_empty(lane_id, "liquidity router congestion lane")?;
        validate_bps(congestion_bps, "liquidity router congestion")?;
        self.congestion_oracles
            .insert(lane_id.to_string(), congestion_bps);
        Ok(())
    }

    pub fn submit_intent(&mut self, intent: EncryptedRouteIntent) -> LiquidityRouterResult<String> {
        intent.validate()?;
        if self.intents.contains_key(&intent.intent_id) {
            return Err("route intent already exists".to_string());
        }
        let intent_id = intent.intent_id.clone();
        self.intents.insert(intent_id.clone(), intent);
        self.counters.submitted_intents = self.counters.submitted_intents.saturating_add(1);
        self.counters.active_intents = self.active_intent_count() as u64;
        Ok(intent_id)
    }

    pub fn register_solver(
        &mut self,
        solver: LiquiditySolverProfile,
    ) -> LiquidityRouterResult<String> {
        solver.validate()?;
        if solver.bond_units < self.config.min_solver_bond_units {
            return Err("solver bond is below router minimum".to_string());
        }
        if self.solvers.contains_key(&solver.solver_id) {
            return Err("solver already registered".to_string());
        }
        let solver_id = solver.solver_id.clone();
        self.solvers.insert(solver_id.clone(), solver);
        self.counters.registered_solvers = self.solvers.len() as u64;
        Ok(solver_id)
    }

    pub fn record_attestation(
        &mut self,
        attestation: PqSolverAttestation,
    ) -> LiquidityRouterResult<String> {
        attestation.validate()?;
        if !self.solvers.contains_key(&attestation.solver_id) {
            return Err("attestation references unknown solver".to_string());
        }
        if self.attestations.contains_key(&attestation.attestation_id) {
            return Err("pq attestation already exists".to_string());
        }
        let attestation_id = attestation.attestation_id.clone();
        self.attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.verified_attestations = self
            .attestations
            .values()
            .filter(|attestation| attestation.status == LIQUIDITY_ROUTER_STATUS_VERIFIED)
            .count() as u64;
        Ok(attestation_id)
    }

    pub fn open_auction(
        &mut self,
        mut auction: LiquidityBatchAuction,
    ) -> LiquidityRouterResult<String> {
        if self.auctions.contains_key(&auction.auction_id) {
            return Err("liquidity auction already exists".to_string());
        }
        if auction.intent_ids.len() > self.config.max_batch_intents {
            return Err("liquidity auction exceeds max batch intents".to_string());
        }
        auction.refresh_phase(self.height);
        let auction_id = auction.auction_id.clone();
        self.auctions.insert(auction_id.clone(), auction);
        self.counters.auctions_opened = self.counters.auctions_opened.saturating_add(1);
        Ok(auction_id)
    }

    pub fn attach_intent_to_auction(
        &mut self,
        auction_id: &str,
        intent_id: &str,
    ) -> LiquidityRouterResult<String> {
        let auction = self
            .auctions
            .get_mut(auction_id)
            .ok_or_else(|| "liquidity auction not found".to_string())?;
        if !self.intents.contains_key(intent_id) {
            return Err("route intent not found".to_string());
        }
        if auction.intent_ids.len() >= self.config.max_batch_intents
            && !auction.intent_ids.iter().any(|id| id == intent_id)
        {
            return Err("liquidity auction is full".to_string());
        }
        auction.add_intent(intent_id.to_string());
        Ok(auction.intent_root.clone())
    }

    pub fn submit_quote(&mut self, quote: SolverQuote) -> LiquidityRouterResult<String> {
        quote.validate()?;
        if !self.solvers.contains_key(&quote.solver_id) {
            return Err("solver quote references unknown solver".to_string());
        }
        if !self.intents.contains_key(&quote.intent_id) {
            return Err("solver quote references unknown intent".to_string());
        }
        if !self.auctions.contains_key(&quote.auction_id) {
            return Err("solver quote references unknown auction".to_string());
        }
        if !self.attestations.contains_key(&quote.attestation_id) {
            return Err("solver quote references unknown pq attestation".to_string());
        }
        if quote.route_legs.len() > self.config.max_route_legs {
            return Err("solver quote exceeds max route legs".to_string());
        }
        if self.quotes.contains_key(&quote.quote_id) {
            return Err("solver quote already exists".to_string());
        }
        let quote_id = quote.quote_id.clone();
        self.counters.submitted_quotes = self.counters.submitted_quotes.saturating_add(1);
        self.counters.total_route_legs = self
            .counters
            .total_route_legs
            .saturating_add(quote.route_legs.len() as u64);
        for leg in &quote.route_legs {
            match leg.leg_kind {
                LiquidityRouteLegKind::MoneroBridge => {
                    self.counters.bridge_legs = self.counters.bridge_legs.saturating_add(1);
                }
                LiquidityRouteLegKind::PrivateDex | LiquidityRouteLegKind::PublicDex => {
                    self.counters.dex_legs = self.counters.dex_legs.saturating_add(1);
                }
                LiquidityRouteLegKind::LendingMarket => {
                    self.counters.lending_legs = self.counters.lending_legs.saturating_add(1);
                }
                _ => {}
            }
        }
        self.quotes.insert(quote_id.clone(), quote);
        Ok(quote_id)
    }

    pub fn attach_quote_to_auction(
        &mut self,
        auction_id: &str,
        quote_id: &str,
    ) -> LiquidityRouterResult<String> {
        let quote = self
            .quotes
            .get(quote_id)
            .ok_or_else(|| "solver quote not found".to_string())?;
        if quote.auction_id != auction_id {
            return Err("solver quote auction mismatch".to_string());
        }
        let auction = self
            .auctions
            .get_mut(auction_id)
            .ok_or_else(|| "liquidity auction not found".to_string())?;
        auction.add_quote(quote_id.to_string());
        Ok(auction.quote_root.clone())
    }

    pub fn run_solver_competition(
        &mut self,
        auction_id: &str,
    ) -> LiquidityRouterResult<Vec<String>> {
        let auction = self
            .auctions
            .get(auction_id)
            .cloned()
            .ok_or_else(|| "liquidity auction not found".to_string())?;
        if auction.quote_ids.is_empty() {
            return Err("liquidity auction has no quotes".to_string());
        }
        let mut best_by_intent = BTreeMap::<String, SolverQuote>::new();
        for quote_id in &auction.quote_ids {
            let quote = self
                .quotes
                .get(quote_id)
                .cloned()
                .ok_or_else(|| "auction quote missing".to_string())?;
            if quote.valid_until_height < self.height {
                continue;
            }
            best_by_intent
                .entry(quote.intent_id.clone())
                .and_modify(|best| {
                    if quote.score(&self.config) > best.score(&self.config)
                        || (quote.score(&self.config) == best.score(&self.config)
                            && quote.quote_id < best.quote_id)
                    {
                        *best = quote.clone();
                    }
                })
                .or_insert(quote);
        }
        let winning_quote_ids = best_by_intent
            .values()
            .map(|quote| quote.quote_id.clone())
            .collect::<Vec<_>>();
        if winning_quote_ids.is_empty() {
            return Err("liquidity auction has no live quotes".to_string());
        }
        for quote in self.quotes.values_mut() {
            if quote.auction_id == auction_id {
                if winning_quote_ids.iter().any(|id| id == &quote.quote_id) {
                    quote.status = LIQUIDITY_ROUTER_STATUS_WON.to_string();
                    self.counters.accepted_quotes = self.counters.accepted_quotes.saturating_add(1);
                } else {
                    quote.status = LIQUIDITY_ROUTER_STATUS_LOST.to_string();
                }
            }
        }
        let clearing = json!({
            "auction_id": auction_id,
            "winner_count": winning_quote_ids.len(),
            "height": self.height,
        });
        let surplus = json!({
            "auction_id": auction_id,
            "policy": "best-guaranteed-output-net-fee",
            "height": self.height,
        });
        let auction = self
            .auctions
            .get_mut(auction_id)
            .ok_or_else(|| "liquidity auction not found".to_string())?;
        auction.set_winners(winning_quote_ids.clone(), &clearing, &surplus);
        auction.phase = LiquidityAuctionPhase::Challenge;
        auction.status = LIQUIDITY_ROUTER_STATUS_MATCHING.to_string();
        Ok(winning_quote_ids)
    }

    pub fn settle_quote(
        &mut self,
        quote_id: &str,
        congestion_bps: u64,
        nullifier_payload: &Value,
        output_note_payload: &Value,
    ) -> LiquidityRouterResult<String> {
        validate_bps(congestion_bps, "settlement congestion")?;
        let quote = self
            .quotes
            .get(quote_id)
            .cloned()
            .ok_or_else(|| "solver quote not found".to_string())?;
        if quote.status != LIQUIDITY_ROUTER_STATUS_WON
            && quote.status != LIQUIDITY_ROUTER_STATUS_OPEN
        {
            return Err("solver quote is not settleable".to_string());
        }
        let intent = self
            .intents
            .get(&quote.intent_id)
            .cloned()
            .ok_or_else(|| "settlement intent not found".to_string())?;
        let rebate = CongestionAwareFeeRebate::new(
            &intent,
            &quote,
            &self.config,
            congestion_bps,
            self.height,
        )?;
        let rebate_units = rebate.rebate_units;
        let rebate_id = rebate.rebate_id.clone();
        self.rebates.insert(rebate_id, rebate);
        self.counters.fee_rebates_reserved = self.counters.fee_rebates_reserved.saturating_add(1);
        self.counters.rebate_units_reserved = self
            .counters
            .rebate_units_reserved
            .saturating_add(rebate_units);

        let receipt = SettlementReceipt::new(
            &quote,
            rebate_units,
            self.height,
            nullifier_payload,
            output_note_payload,
        )?;
        let receipt_id = receipt.receipt_id.clone();
        self.receipts.insert(receipt_id.clone(), receipt);
        if let Some(intent) = self.intents.get_mut(&quote.intent_id) {
            intent.status = LIQUIDITY_ROUTER_STATUS_SETTLED.to_string();
        }
        if let Some(quote) = self.quotes.get_mut(quote_id) {
            quote.status = LIQUIDITY_ROUTER_STATUS_FILLED.to_string();
        }
        if let Some(auction) = self.auctions.get_mut(&quote.auction_id) {
            auction.phase = LiquidityAuctionPhase::Settled;
            auction.status = LIQUIDITY_ROUTER_STATUS_SETTLED.to_string();
        }
        for rebate in self.rebates.values_mut() {
            if rebate.quote_id == quote_id && rebate.status == LIQUIDITY_ROUTER_STATUS_RESERVED {
                rebate.status = LIQUIDITY_ROUTER_STATUS_APPLIED.to_string();
                self.counters.fee_rebates_applied =
                    self.counters.fee_rebates_applied.saturating_add(1);
                self.counters.rebate_units_applied = self
                    .counters
                    .rebate_units_applied
                    .saturating_add(rebate.rebate_units);
            }
        }
        self.counters.settled_routes = self.counters.settled_routes.saturating_add(1);
        self.counters.auctions_settled = self
            .auctions
            .values()
            .filter(|auction| auction.status == LIQUIDITY_ROUTER_STATUS_SETTLED)
            .count() as u64;
        self.counters.active_intents = self.active_intent_count() as u64;
        self.counters.cumulative_fee_units = self
            .counters
            .cumulative_fee_units
            .saturating_add(quote.total_fee_units().saturating_sub(rebate_units));
        self.counters.cumulative_solver_fee_units = self
            .counters
            .cumulative_solver_fee_units
            .saturating_add(quote.solver_fee_units);
        self.counters.cumulative_output_units = self
            .counters
            .cumulative_output_units
            .saturating_add(quote.guaranteed_output_units);
        Ok(receipt_id)
    }

    pub fn record_equivocation(
        &mut self,
        evidence: EquivocationEvidence,
    ) -> LiquidityRouterResult<String> {
        if !self.solvers.contains_key(&evidence.solver_id) {
            return Err("equivocation evidence references unknown solver".to_string());
        }
        if self
            .equivocation_evidence
            .contains_key(&evidence.evidence_id)
        {
            return Err("equivocation evidence already exists".to_string());
        }
        let evidence_id = evidence.evidence_id.clone();
        self.equivocation_evidence
            .insert(evidence_id.clone(), evidence);
        self.counters.equivocation_evidence = self.equivocation_evidence.len() as u64;
        Ok(evidence_id)
    }

    pub fn slash_solver(
        &mut self,
        evidence_id: &str,
        reason: SlashingReason,
        beneficiary_label: &str,
    ) -> LiquidityRouterResult<String> {
        let evidence = self
            .equivocation_evidence
            .get(evidence_id)
            .cloned()
            .ok_or_else(|| "slashing evidence not found".to_string())?;
        let solver = self
            .solvers
            .get(&evidence.solver_id)
            .cloned()
            .ok_or_else(|| "slashing solver not found".to_string())?;
        let slash =
            SlashingRecord::new(&evidence, &solver, reason, beneficiary_label, self.height)?;
        let slash_id = slash.slash_id.clone();
        if let Some(solver) = self.solvers.get_mut(&evidence.solver_id) {
            solver.bond_units = slash.bond_units_after;
            solver.status = LIQUIDITY_ROUTER_STATUS_SLASHED.to_string();
        }
        if let Some(evidence) = self.equivocation_evidence.get_mut(evidence_id) {
            evidence.status = LIQUIDITY_ROUTER_STATUS_SLASHED.to_string();
        }
        self.counters.solver_slashes = self.counters.solver_slashes.saturating_add(1);
        self.counters.slash_units = self.counters.slash_units.saturating_add(slash.slash_units);
        self.slashing_records.insert(slash_id.clone(), slash);
        Ok(slash_id)
    }

    pub fn roots(&self) -> LiquidityRouterRoots {
        LiquidityRouterRoots {
            config_root: self.config.config_root(),
            intent_root: self.intent_root(),
            solver_root: self.solver_root(),
            attestation_root: self.attestation_root(),
            quote_root: self.quote_root(),
            auction_root: self.auction_root(),
            route_leg_root: self.route_leg_root(),
            rebate_root: self.rebate_root(),
            receipt_root: self.receipt_root(),
            leg_receipt_root: self.leg_receipt_root(),
            equivocation_evidence_root: self.equivocation_evidence_root(),
            slashing_root: self.slashing_root(),
            congestion_oracle_root: self.congestion_oracle_root(),
            counters_root: liquidity_router_payload_root(
                "LIQUIDITY-ROUTER-COUNTERS",
                &self.counters.public_record(),
            ),
        }
    }

    pub fn state_root(&self) -> String {
        liquidity_router_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("liquidity router public record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "liquidity_router_state",
            "chain_id": CHAIN_ID,
            "protocol_version": LIQUIDITY_ROUTER_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters.public_record(),
        })
    }

    pub fn intent_count(&self) -> usize {
        self.intents.len()
    }

    pub fn active_intent_count(&self) -> usize {
        self.intents
            .values()
            .filter(|intent| intent.status == LIQUIDITY_ROUTER_STATUS_ACTIVE)
            .count()
    }

    pub fn solver_count(&self) -> usize {
        self.solvers.len()
    }

    pub fn verified_attestation_count(&self) -> usize {
        self.attestations
            .values()
            .filter(|attestation| attestation.status == LIQUIDITY_ROUTER_STATUS_VERIFIED)
            .count()
    }

    pub fn quote_count(&self) -> usize {
        self.quotes.len()
    }

    pub fn open_quote_count(&self) -> usize {
        self.quotes
            .values()
            .filter(|quote| quote.status == LIQUIDITY_ROUTER_STATUS_OPEN)
            .count()
    }

    pub fn auction_count(&self) -> usize {
        self.auctions.len()
    }

    pub fn open_auction_count(&self) -> usize {
        self.auctions
            .values()
            .filter(|auction| auction.status != LIQUIDITY_ROUTER_STATUS_SETTLED)
            .count()
    }

    pub fn receipt_count(&self) -> usize {
        self.receipts.len()
    }

    pub fn pending_rebate_units(&self) -> u64 {
        self.rebates
            .values()
            .filter(|rebate| rebate.status == LIQUIDITY_ROUTER_STATUS_RESERVED)
            .map(|rebate| rebate.rebate_units)
            .sum()
    }

    pub fn applied_rebate_units(&self) -> u64 {
        self.rebates
            .values()
            .filter(|rebate| rebate.status == LIQUIDITY_ROUTER_STATUS_APPLIED)
            .map(|rebate| rebate.rebate_units)
            .sum()
    }

    pub fn slashed_solver_count(&self) -> usize {
        self.solvers
            .values()
            .filter(|solver| solver.status == LIQUIDITY_ROUTER_STATUS_SLASHED)
            .count()
    }

    pub fn intent_root(&self) -> String {
        encrypted_route_intent_root(&self.intents.values().cloned().collect::<Vec<_>>())
    }

    pub fn solver_root(&self) -> String {
        liquidity_solver_root(&self.solvers.values().cloned().collect::<Vec<_>>())
    }

    pub fn attestation_root(&self) -> String {
        pq_solver_attestation_root(&self.attestations.values().cloned().collect::<Vec<_>>())
    }

    pub fn quote_root(&self) -> String {
        solver_quote_root(&self.quotes.values().cloned().collect::<Vec<_>>())
    }

    pub fn auction_root(&self) -> String {
        liquidity_batch_auction_root(&self.auctions.values().cloned().collect::<Vec<_>>())
    }

    pub fn route_leg_root(&self) -> String {
        let legs = self
            .quotes
            .values()
            .flat_map(|quote| quote.route_legs.iter().cloned())
            .collect::<Vec<_>>();
        liquidity_route_leg_root(&legs)
    }

    pub fn rebate_root(&self) -> String {
        congestion_fee_rebate_root(&self.rebates.values().cloned().collect::<Vec<_>>())
    }

    pub fn receipt_root(&self) -> String {
        settlement_receipt_root(&self.receipts.values().cloned().collect::<Vec<_>>())
    }

    pub fn leg_receipt_root(&self) -> String {
        let receipts = self
            .receipts
            .values()
            .flat_map(|receipt| receipt.leg_receipts.iter().cloned())
            .collect::<Vec<_>>();
        route_leg_receipt_root(&receipts)
    }

    pub fn equivocation_evidence_root(&self) -> String {
        equivocation_evidence_root(
            &self
                .equivocation_evidence
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn slashing_root(&self) -> String {
        slashing_record_root(&self.slashing_records.values().cloned().collect::<Vec<_>>())
    }

    pub fn congestion_oracle_root(&self) -> String {
        let records = self
            .congestion_oracles
            .iter()
            .map(|(lane_id, congestion_bps)| {
                (
                    lane_id.clone(),
                    json!({
                        "kind": "liquidity_router_congestion_oracle",
                        "chain_id": CHAIN_ID,
                        "lane_id": lane_id,
                        "congestion_bps": congestion_bps,
                    }),
                )
            })
            .collect::<Vec<_>>();
        keyed_record_root("LIQUIDITY-ROUTER-CONGESTION-ORACLE", records)
    }
}

pub fn liquidity_router_state_root_from_record(record: &Value) -> String {
    liquidity_router_payload_root("LIQUIDITY-ROUTER-STATE", record)
}

pub fn encrypted_route_intent_root(intents: &[EncryptedRouteIntent]) -> String {
    keyed_record_root(
        "LIQUIDITY-ROUTER-ENCRYPTED-INTENT",
        intents
            .iter()
            .map(|intent| (intent.intent_id.clone(), intent.public_record()))
            .collect(),
    )
}

pub fn liquidity_solver_root(solvers: &[LiquiditySolverProfile]) -> String {
    keyed_record_root(
        "LIQUIDITY-ROUTER-SOLVER",
        solvers
            .iter()
            .map(|solver| (solver.solver_id.clone(), solver.public_record()))
            .collect(),
    )
}

pub fn pq_solver_attestation_root(attestations: &[PqSolverAttestation]) -> String {
    keyed_record_root(
        "LIQUIDITY-ROUTER-PQ-SOLVER-ATTESTATION",
        attestations
            .iter()
            .map(|attestation| {
                (
                    attestation.attestation_id.clone(),
                    attestation.public_record(),
                )
            })
            .collect(),
    )
}

pub fn liquidity_route_leg_root(legs: &[LiquidityRouteLeg]) -> String {
    keyed_record_root(
        "LIQUIDITY-ROUTER-ROUTE-LEG",
        legs.iter()
            .map(|leg| (leg.leg_id.clone(), leg.public_record()))
            .collect(),
    )
}

pub fn solver_quote_root(quotes: &[SolverQuote]) -> String {
    keyed_record_root(
        "LIQUIDITY-ROUTER-SOLVER-QUOTE",
        quotes
            .iter()
            .map(|quote| (quote.quote_id.clone(), quote.public_record()))
            .collect(),
    )
}

pub fn liquidity_batch_auction_root(auctions: &[LiquidityBatchAuction]) -> String {
    keyed_record_root(
        "LIQUIDITY-ROUTER-BATCH-AUCTION",
        auctions
            .iter()
            .map(|auction| (auction.auction_id.clone(), auction.public_record()))
            .collect(),
    )
}

pub fn congestion_fee_rebate_root(rebates: &[CongestionAwareFeeRebate]) -> String {
    keyed_record_root(
        "LIQUIDITY-ROUTER-CONGESTION-FEE-REBATE",
        rebates
            .iter()
            .map(|rebate| (rebate.rebate_id.clone(), rebate.public_record()))
            .collect(),
    )
}

pub fn route_leg_receipt_root(receipts: &[RouteLegReceipt]) -> String {
    keyed_record_root(
        "LIQUIDITY-ROUTER-ROUTE-LEG-RECEIPT",
        receipts
            .iter()
            .map(|receipt| (receipt.leg_receipt_id.clone(), receipt.public_record()))
            .collect(),
    )
}

pub fn settlement_receipt_root(receipts: &[SettlementReceipt]) -> String {
    keyed_record_root(
        "LIQUIDITY-ROUTER-SETTLEMENT-RECEIPT",
        receipts
            .iter()
            .map(|receipt| (receipt.receipt_id.clone(), receipt.public_record()))
            .collect(),
    )
}

pub fn equivocation_evidence_root(evidence: &[EquivocationEvidence]) -> String {
    keyed_record_root(
        "LIQUIDITY-ROUTER-EQUIVOCATION-EVIDENCE",
        evidence
            .iter()
            .map(|evidence| (evidence.evidence_id.clone(), evidence.public_record()))
            .collect(),
    )
}

pub fn slashing_record_root(records: &[SlashingRecord]) -> String {
    keyed_record_root(
        "LIQUIDITY-ROUTER-SLASHING-RECORD",
        records
            .iter()
            .map(|record| (record.slash_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn liquidity_router_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn liquidity_router_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn liquidity_router_string_set_root(domain: &str, values: &[String]) -> String {
    let ordered = values.iter().cloned().collect::<BTreeSet<_>>();
    merkle_root(
        domain,
        &ordered
            .into_iter()
            .map(|value| json!(liquidity_router_string_root(domain, &value)))
            .collect::<Vec<_>>(),
    )
}

pub fn liquidity_router_route_leg_kind_set_root(kinds: &[LiquidityRouteLegKind]) -> String {
    let values = kinds
        .iter()
        .map(|kind| kind.as_str().to_string())
        .collect::<Vec<_>>();
    liquidity_router_string_set_root("LIQUIDITY-ROUTER-LEG-KIND", &values)
}

pub fn liquidity_router_account_commitment(label: &str) -> String {
    liquidity_router_string_root("LIQUIDITY-ROUTER-ACCOUNT-COMMITMENT", label)
}

pub fn liquidity_router_asset_commitment(asset_id: &str) -> String {
    liquidity_router_string_root("LIQUIDITY-ROUTER-ASSET-COMMITMENT", asset_id)
}

pub fn liquidity_router_amount_commitment(amount_units: u64, blinding_root: &str) -> String {
    domain_hash(
        "LIQUIDITY-ROUTER-AMOUNT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(amount_units as i128),
            HashPart::Str(blinding_root),
        ],
        32,
    )
}

pub fn liquidity_router_blinding(owner_label: &str, nonce: u64, purpose: &str) -> String {
    domain_hash(
        "LIQUIDITY-ROUTER-BLINDING",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_label),
            HashPart::Int(nonce as i128),
            HashPart::Str(purpose),
        ],
        32,
    )
}

pub fn liquidity_router_quote_commitment(
    solver_id: &str,
    intent_id: &str,
    auction_id: &str,
    route_root: &str,
    expected_output_units: u64,
    guaranteed_output_units: u64,
    total_fee_units: u64,
    quote_secret: &str,
) -> String {
    domain_hash(
        "LIQUIDITY-ROUTER-QUOTE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(solver_id),
            HashPart::Str(intent_id),
            HashPart::Str(auction_id),
            HashPart::Str(route_root),
            HashPart::Int(expected_output_units as i128),
            HashPart::Int(guaranteed_output_units as i128),
            HashPart::Int(total_fee_units as i128),
            HashPart::Str(quote_secret),
        ],
        32,
    )
}

pub fn encrypted_route_intent_id(
    owner_commitment: &str,
    intent_kind: LiquidityRouteIntentKind,
    privacy_mode: LiquidityPrivacyMode,
    asset_in_commitment: &str,
    asset_out_commitment: &str,
    amount_in_commitment: &str,
    min_output_commitment: &str,
    route_hint_root: &str,
    deadline_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "LIQUIDITY-ROUTER-ENCRYPTED-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Str(intent_kind.as_str()),
            HashPart::Str(privacy_mode.as_str()),
            HashPart::Str(asset_in_commitment),
            HashPart::Str(asset_out_commitment),
            HashPart::Str(amount_in_commitment),
            HashPart::Str(min_output_commitment),
            HashPart::Str(route_hint_root),
            HashPart::Int(deadline_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn liquidity_solver_id(
    label: &str,
    solver_kind: LiquiditySolverKind,
    operator_commitment: &str,
    bond_asset_id: &str,
    bond_units: u64,
    pq_identity_root: &str,
) -> String {
    domain_hash(
        "LIQUIDITY-ROUTER-SOLVER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(solver_kind.as_str()),
            HashPart::Str(operator_commitment),
            HashPart::Str(bond_asset_id),
            HashPart::Int(bond_units as i128),
            HashPart::Str(pq_identity_root),
        ],
        32,
    )
}

pub fn pq_solver_attestation_id(
    solver_id: &str,
    kem_public_key_root: &str,
    signature_root: &str,
    quote_capability_root: &str,
    attested_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "LIQUIDITY-ROUTER-PQ-SOLVER-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(solver_id),
            HashPart::Str(kem_public_key_root),
            HashPart::Str(signature_root),
            HashPart::Str(quote_capability_root),
            HashPart::Int(attested_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

pub fn liquidity_route_leg_id(
    quote_id_hint: &str,
    leg_index: u64,
    leg_kind: LiquidityRouteLegKind,
    asset_in_commitment: &str,
    asset_out_commitment: &str,
    amount_in_commitment: &str,
    amount_out_commitment: &str,
    leg_proof_root: &str,
) -> String {
    domain_hash(
        "LIQUIDITY-ROUTER-ROUTE-LEG-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(quote_id_hint),
            HashPart::Int(leg_index as i128),
            HashPart::Str(leg_kind.as_str()),
            HashPart::Str(asset_in_commitment),
            HashPart::Str(asset_out_commitment),
            HashPart::Str(amount_in_commitment),
            HashPart::Str(amount_out_commitment),
            HashPart::Str(leg_proof_root),
        ],
        32,
    )
}

pub fn solver_quote_id(
    solver_id: &str,
    intent_id: &str,
    auction_id: &str,
    route_root: &str,
    guaranteed_output_units: u64,
    solver_fee_units: u64,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "LIQUIDITY-ROUTER-SOLVER-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(solver_id),
            HashPart::Str(intent_id),
            HashPart::Str(auction_id),
            HashPart::Str(route_root),
            HashPart::Int(guaranteed_output_units as i128),
            HashPart::Int(solver_fee_units as i128),
            HashPart::Int(submitted_at_height as i128),
        ],
        32,
    )
}

pub fn liquidity_batch_auction_id(
    pair_commitment: &str,
    batch_index: u64,
    start_height: u64,
    collect_end_height: u64,
    solver_bond_root: &str,
    pq_transcript_root: &str,
) -> String {
    domain_hash(
        "LIQUIDITY-ROUTER-BATCH-AUCTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pair_commitment),
            HashPart::Int(batch_index as i128),
            HashPart::Int(start_height as i128),
            HashPart::Int(collect_end_height as i128),
            HashPart::Str(solver_bond_root),
            HashPart::Str(pq_transcript_root),
        ],
        32,
    )
}

pub fn congestion_fee_rebate_id(
    intent_id: &str,
    quote_id: &str,
    auction_id: &str,
    owner_commitment: &str,
    lane_id: &str,
    eligible_fee_units: u64,
    rebate_units: u64,
    created_at_height: u64,
) -> String {
    domain_hash(
        "LIQUIDITY-ROUTER-CONGESTION-FEE-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(quote_id),
            HashPart::Str(auction_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(lane_id),
            HashPart::Int(eligible_fee_units as i128),
            HashPart::Int(rebate_units as i128),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn route_leg_receipt_id(
    quote_id: &str,
    leg_id: &str,
    leg_index: u64,
    input_units: u64,
    output_units: u64,
    settled_at_height: u64,
) -> String {
    domain_hash(
        "LIQUIDITY-ROUTER-ROUTE-LEG-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(quote_id),
            HashPart::Str(leg_id),
            HashPart::Int(leg_index as i128),
            HashPart::Int(input_units as i128),
            HashPart::Int(output_units as i128),
            HashPart::Int(settled_at_height as i128),
        ],
        32,
    )
}

pub fn settlement_receipt_id(
    intent_id: &str,
    quote_id: &str,
    auction_id: &str,
    solver_id: &str,
    route_root: &str,
    settlement_height: u64,
) -> String {
    domain_hash(
        "LIQUIDITY-ROUTER-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(quote_id),
            HashPart::Str(auction_id),
            HashPart::Str(solver_id),
            HashPart::Str(route_root),
            HashPart::Int(settlement_height as i128),
        ],
        32,
    )
}

pub fn equivocation_evidence_id(
    solver_id: &str,
    auction_id: &str,
    first_quote_id: &str,
    second_quote_id: &str,
    evidence_root: &str,
    observed_at_height: u64,
) -> String {
    domain_hash(
        "LIQUIDITY-ROUTER-EQUIVOCATION-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(solver_id),
            HashPart::Str(auction_id),
            HashPart::Str(first_quote_id),
            HashPart::Str(second_quote_id),
            HashPart::Str(evidence_root),
            HashPart::Int(observed_at_height as i128),
        ],
        32,
    )
}

pub fn slashing_record_id(
    evidence_id: &str,
    solver_id: &str,
    reason: SlashingReason,
    slash_units: u64,
    executed_at_height: u64,
) -> String {
    domain_hash(
        "LIQUIDITY-ROUTER-SLASHING-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(evidence_id),
            HashPart::Str(solver_id),
            HashPart::Str(reason.as_str()),
            HashPart::Int(slash_units as i128),
            HashPart::Int(executed_at_height as i128),
        ],
        32,
    )
}

pub fn bps_mul_floor(amount: u64, bps: u64) -> u64 {
    (((amount as u128).saturating_mul(bps as u128)) / LIQUIDITY_ROUTER_MAX_BPS as u128) as u64
}

pub fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    (((numerator as u128).saturating_mul(LIQUIDITY_ROUTER_MAX_BPS as u128)) / denominator as u128)
        .min(LIQUIDITY_ROUTER_MAX_BPS as u128) as u64
}

fn keyed_record_root(domain: &str, mut records: Vec<(String, Value)>) -> String {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        domain,
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

fn liquidity_router_json_size(value: &Value) -> u64 {
    match value {
        Value::Null => 4,
        Value::Bool(value) => value.to_string().len() as u64,
        Value::Number(value) => value.to_string().len() as u64,
        Value::String(value) => value.len() as u64,
        Value::Array(values) => values.iter().map(liquidity_router_json_size).sum(),
        Value::Object(values) => values
            .iter()
            .map(|(key, value)| key.len() as u64 + liquidity_router_json_size(value))
            .sum(),
    }
}

fn ensure_non_empty(value: &str, field: &str) -> LiquidityRouterResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} is required"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, field: &str) -> LiquidityRouterResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn validate_bps(value: u64, field: &str) -> LiquidityRouterResult<()> {
    if value > LIQUIDITY_ROUTER_MAX_BPS {
        Err(format!(
            "{field} cannot exceed {LIQUIDITY_ROUTER_MAX_BPS} bps"
        ))
    } else {
        Ok(())
    }
}

fn ensure_status(status: &str, allowed: &[&str]) -> LiquidityRouterResult<()> {
    if allowed.iter().any(|allowed| allowed == &status) {
        Ok(())
    } else {
        Err(format!("liquidity router status {status} is invalid"))
    }
}
