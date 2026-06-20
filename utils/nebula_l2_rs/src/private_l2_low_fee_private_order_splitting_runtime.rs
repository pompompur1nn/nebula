use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePrivateOrderSplittingRuntimeResult<T> = Result<T>;

pub const PRIVATE_L2_LOW_FEE_PRIVATE_ORDER_SPLITTING_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-private-order-splitting-runtime-v1";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_ORDER_SPLITTING_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_LOW_FEE_PRIVATE_ORDER_SPLITTING_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_ORDER_SPLITTING_PARENT_ORDER_SCHEME: &str =
    "ml-kem-1024+zk-encrypted-parent-order-v1";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_ORDER_SPLITTING_CHILD_ROUTE_SCHEME: &str =
    "roots-only-private-child-route-split-v1";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_ORDER_SPLITTING_AUCTION_SCHEME: &str =
    "commit-reveal-low-fee-private-route-auction-v1";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_ORDER_SPLITTING_SOLVER_COMMITMENT_SCHEME: &str =
    "pq-solver-commitment-private-split-route-v1";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_ORDER_SPLITTING_BATCH_SCHEME: &str =
    "coalesced-private-settlement-batch-v1";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_ORDER_SPLITTING_SPONSOR_SCHEME: &str =
    "roots-only-low-fee-sponsor-reservation-v1";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_ORDER_SPLITTING_RECEIPT_SCHEME: &str =
    "zk-pq-private-order-splitting-settlement-receipt-v1";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_ORDER_SPLITTING_REBATE_SCHEME: &str =
    "private-fee-rebate-claim-root-v1";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_ORDER_SPLITTING_PRIVACY_FENCE_SCHEME: &str =
    "nullifier-fenced-private-split-order-v1";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_ORDER_SPLITTING_DEVNET_HEIGHT: u64 = 472_000;
pub const DEFAULT_AUCTION_WINDOW_BLOCKS: u64 = 6;
pub const DEFAULT_PARENT_ORDER_TTL_BLOCKS: u64 = 36;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 18;
pub const DEFAULT_MAX_PARENT_ORDERS: usize = 1_048_576;
pub const DEFAULT_MAX_CHILD_ROUTES_PER_PARENT: usize = 16;
pub const DEFAULT_MAX_SOLVER_COMMITMENTS: usize = 2_048;
pub const DEFAULT_MAX_BATCH_CHILD_ROUTES: usize = 2_048;
pub const DEFAULT_MAX_RESERVATIONS: usize = 2_048;
pub const DEFAULT_MIN_PARENT_PRIVACY_SET_SIZE: u64 = 256;
pub const DEFAULT_MIN_BATCH_PRIVACY_SET_SIZE: u64 = 768;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const DEFAULT_MAX_SOLVER_FEE_BPS: u64 = 24;
pub const DEFAULT_MIN_REBATE_BPS: u64 = 3;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 16;
pub const DEFAULT_ROUTE_HEALTH_FLOOR_BPS: u64 = 7_000;
pub const DEFAULT_SPONSOR_BUDGET_MICRO_UNITS: u64 = 180_000_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParentOrderKind {
    SwapExactIn,
    SwapExactOut,
    LimitSwap,
    DarkpoolCross,
    VaultRebalance,
    LendingRoll,
    PerpHedge,
    CrossVenueArb,
}

impl ParentOrderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SwapExactIn => "swap_exact_in",
            Self::SwapExactOut => "swap_exact_out",
            Self::LimitSwap => "limit_swap",
            Self::DarkpoolCross => "darkpool_cross",
            Self::VaultRebalance => "vault_rebalance",
            Self::LendingRoll => "lending_roll",
            Self::PerpHedge => "perp_hedge",
            Self::CrossVenueArb => "cross_venue_arb",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityVenueKind {
    PrivateAmm,
    Darkpool,
    Rfq,
    LendingPool,
    PerpBook,
    InternalNetting,
    BridgeVault,
    SolverInventory,
}

impl LiquidityVenueKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateAmm => "private_amm",
            Self::Darkpool => "darkpool",
            Self::Rfq => "rfq",
            Self::LendingPool => "lending_pool",
            Self::PerpBook => "perp_book",
            Self::InternalNetting => "internal_netting",
            Self::BridgeVault => "bridge_vault",
            Self::SolverInventory => "solver_inventory",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParentOrderStatus {
    Submitted,
    Split,
    Auctioned,
    Sponsored,
    Batched,
    Settled,
    Rejected,
    Expired,
}

impl ParentOrderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Split => "split",
            Self::Auctioned => "auctioned",
            Self::Sponsored => "sponsored",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn can_split(self) -> bool {
        matches!(self, Self::Submitted | Self::Split | Self::Auctioned)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChildRouteStatus {
    Proposed,
    AuctionOpen,
    SolverCommitted,
    Selected,
    Batched,
    Settled,
    Rejected,
    Expired,
}

impl ChildRouteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::AuctionOpen => "auction_open",
            Self::SolverCommitted => "solver_committed",
            Self::Selected => "selected",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn batchable(self) -> bool {
        matches!(self, Self::Selected | Self::SolverCommitted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Open,
    Sealed,
    Selected,
    Expired,
    Cancelled,
}

impl AuctionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Selected => "selected",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Committed,
    Selected,
    Settled,
    Slashed,
    Rejected,
    Expired,
}

impl CommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Selected => "selected",
            Self::Settled => "settled",
            Self::Slashed => "slashed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Consumed,
    Released,
    Expired,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Built,
    SettlementReady,
    Settled,
    Disputed,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Finalized,
    Disputed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
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
    pub encrypted_parent_order_scheme: String,
    pub child_route_scheme: String,
    pub route_auction_scheme: String,
    pub solver_commitment_scheme: String,
    pub settlement_batch_scheme: String,
    pub sponsor_reservation_scheme: String,
    pub receipt_scheme: String,
    pub rebate_scheme: String,
    pub privacy_fence_scheme: String,
    pub auction_window_blocks: u64,
    pub parent_order_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub max_parent_orders: usize,
    pub max_child_routes_per_parent: usize,
    pub max_solver_commitments: usize,
    pub max_batch_child_routes: usize,
    pub max_reservations: usize,
    pub min_parent_privacy_set_size: u64,
    pub min_batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_solver_fee_bps: u64,
    pub min_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub route_health_floor_bps: u64,
    pub sponsor_budget_micro_units: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PRIVATE_L2_LOW_FEE_PRIVATE_ORDER_SPLITTING_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_LOW_FEE_PRIVATE_ORDER_SPLITTING_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_LOW_FEE_PRIVATE_ORDER_SPLITTING_HASH_SUITE.to_string(),
            encrypted_parent_order_scheme:
                PRIVATE_L2_LOW_FEE_PRIVATE_ORDER_SPLITTING_PARENT_ORDER_SCHEME.to_string(),
            child_route_scheme: PRIVATE_L2_LOW_FEE_PRIVATE_ORDER_SPLITTING_CHILD_ROUTE_SCHEME
                .to_string(),
            route_auction_scheme: PRIVATE_L2_LOW_FEE_PRIVATE_ORDER_SPLITTING_AUCTION_SCHEME
                .to_string(),
            solver_commitment_scheme:
                PRIVATE_L2_LOW_FEE_PRIVATE_ORDER_SPLITTING_SOLVER_COMMITMENT_SCHEME.to_string(),
            settlement_batch_scheme: PRIVATE_L2_LOW_FEE_PRIVATE_ORDER_SPLITTING_BATCH_SCHEME
                .to_string(),
            sponsor_reservation_scheme: PRIVATE_L2_LOW_FEE_PRIVATE_ORDER_SPLITTING_SPONSOR_SCHEME
                .to_string(),
            receipt_scheme: PRIVATE_L2_LOW_FEE_PRIVATE_ORDER_SPLITTING_RECEIPT_SCHEME.to_string(),
            rebate_scheme: PRIVATE_L2_LOW_FEE_PRIVATE_ORDER_SPLITTING_REBATE_SCHEME.to_string(),
            privacy_fence_scheme: PRIVATE_L2_LOW_FEE_PRIVATE_ORDER_SPLITTING_PRIVACY_FENCE_SCHEME
                .to_string(),
            auction_window_blocks: DEFAULT_AUCTION_WINDOW_BLOCKS,
            parent_order_ttl_blocks: DEFAULT_PARENT_ORDER_TTL_BLOCKS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
            max_parent_orders: DEFAULT_MAX_PARENT_ORDERS,
            max_child_routes_per_parent: DEFAULT_MAX_CHILD_ROUTES_PER_PARENT,
            max_solver_commitments: DEFAULT_MAX_SOLVER_COMMITMENTS,
            max_batch_child_routes: DEFAULT_MAX_BATCH_CHILD_ROUTES,
            max_reservations: DEFAULT_MAX_RESERVATIONS,
            min_parent_privacy_set_size: DEFAULT_MIN_PARENT_PRIVACY_SET_SIZE,
            min_batch_privacy_set_size: DEFAULT_MIN_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_solver_fee_bps: DEFAULT_MAX_SOLVER_FEE_BPS,
            min_rebate_bps: DEFAULT_MIN_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            route_health_floor_bps: DEFAULT_ROUTE_HEALTH_FLOOR_BPS,
            sponsor_budget_micro_units: DEFAULT_SPONSOR_BUDGET_MICRO_UNITS,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "encrypted_parent_order_scheme": self.encrypted_parent_order_scheme,
            "child_route_scheme": self.child_route_scheme,
            "route_auction_scheme": self.route_auction_scheme,
            "solver_commitment_scheme": self.solver_commitment_scheme,
            "settlement_batch_scheme": self.settlement_batch_scheme,
            "sponsor_reservation_scheme": self.sponsor_reservation_scheme,
            "receipt_scheme": self.receipt_scheme,
            "rebate_scheme": self.rebate_scheme,
            "privacy_fence_scheme": self.privacy_fence_scheme,
            "auction_window_blocks": self.auction_window_blocks,
            "parent_order_ttl_blocks": self.parent_order_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "max_parent_orders": self.max_parent_orders,
            "max_child_routes_per_parent": self.max_child_routes_per_parent,
            "max_solver_commitments": self.max_solver_commitments,
            "max_batch_child_routes": self.max_batch_child_routes,
            "max_reservations": self.max_reservations,
            "min_parent_privacy_set_size": self.min_parent_privacy_set_size,
            "min_batch_privacy_set_size": self.min_batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_solver_fee_bps": self.max_solver_fee_bps,
            "min_rebate_bps": self.min_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "route_health_floor_bps": self.route_health_floor_bps,
            "sponsor_budget_micro_units": self.sponsor_budget_micro_units
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedParentOrder {
    pub parent_order_id: String,
    pub order_kind: ParentOrderKind,
    pub account_commitment: String,
    pub encrypted_order_root: String,
    pub encrypted_policy_root: String,
    pub source_asset_commitment: String,
    pub target_asset_commitment: String,
    pub notional_commitment_root: String,
    pub min_fill_commitment_root: String,
    pub user_fee_limit_bps: u64,
    pub split_count_hint: u16,
    pub nullifier_root: String,
    pub privacy_set_size: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub status: ParentOrderStatus,
    pub child_route_ids: BTreeSet<String>,
    pub reservation_ids: BTreeSet<String>,
    pub metadata_root: String,
}

impl EncryptedParentOrder {
    pub fn public_record(&self) -> Value {
        json!({
            "parent_order_id": self.parent_order_id,
            "order_kind": self.order_kind.as_str(),
            "account_commitment": self.account_commitment,
            "encrypted_order_root": self.encrypted_order_root,
            "encrypted_policy_root": self.encrypted_policy_root,
            "source_asset_commitment": self.source_asset_commitment,
            "target_asset_commitment": self.target_asset_commitment,
            "notional_commitment_root": self.notional_commitment_root,
            "min_fill_commitment_root": self.min_fill_commitment_root,
            "user_fee_limit_bps": self.user_fee_limit_bps,
            "split_count_hint": self.split_count_hint,
            "nullifier_root": self.nullifier_root,
            "privacy_set_size": self.privacy_set_size,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "child_route_ids": self.child_route_ids.iter().cloned().collect::<Vec<_>>(),
            "reservation_ids": self.reservation_ids.iter().cloned().collect::<Vec<_>>(),
            "metadata_root": self.metadata_root
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildRoute {
    pub child_route_id: String,
    pub parent_order_id: String,
    pub route_index: u16,
    pub venue_kind: LiquidityVenueKind,
    pub venue_hint_id: String,
    pub route_commitment_root: String,
    pub amount_share_bps: u64,
    pub price_limit_commitment_root: String,
    pub max_solver_fee_bps: u64,
    pub min_rebate_bps: u64,
    pub auction_id: Option<String>,
    pub selected_commitment_id: Option<String>,
    pub route_health_id: Option<String>,
    pub status: ChildRouteStatus,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl ChildRoute {
    pub fn public_record(&self) -> Value {
        json!({
            "child_route_id": self.child_route_id,
            "parent_order_id": self.parent_order_id,
            "route_index": self.route_index,
            "venue_kind": self.venue_kind.as_str(),
            "venue_hint_id": self.venue_hint_id,
            "route_commitment_root": self.route_commitment_root,
            "amount_share_bps": self.amount_share_bps,
            "price_limit_commitment_root": self.price_limit_commitment_root,
            "max_solver_fee_bps": self.max_solver_fee_bps,
            "min_rebate_bps": self.min_rebate_bps,
            "auction_id": self.auction_id,
            "selected_commitment_id": self.selected_commitment_id,
            "route_health_id": self.route_health_id,
            "status": self.status.as_str(),
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityVenueHint {
    pub venue_hint_id: String,
    pub venue_kind: LiquidityVenueKind,
    pub operator_commitment: String,
    pub pair_commitment_root: String,
    pub inventory_commitment_root: String,
    pub fee_hint_bps: u64,
    pub latency_hint_ms: u64,
    pub max_child_routes: u16,
    pub accepts_sponsored_fees: bool,
    pub health_id: String,
    pub metadata_root: String,
}

impl LiquidityVenueHint {
    pub fn public_record(&self) -> Value {
        json!({
            "venue_hint_id": self.venue_hint_id,
            "venue_kind": self.venue_kind.as_str(),
            "operator_commitment": self.operator_commitment,
            "pair_commitment_root": self.pair_commitment_root,
            "inventory_commitment_root": self.inventory_commitment_root,
            "fee_hint_bps": self.fee_hint_bps,
            "latency_hint_ms": self.latency_hint_ms,
            "max_child_routes": self.max_child_routes,
            "accepts_sponsored_fees": self.accepts_sponsored_fees,
            "health_id": self.health_id,
            "metadata_root": self.metadata_root
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteAuction {
    pub auction_id: String,
    pub child_route_id: String,
    pub auctioneer_commitment: String,
    pub sealed_bid_root: String,
    pub reserve_price_root: String,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
    pub status: AuctionStatus,
    pub solver_commitment_ids: BTreeSet<String>,
}

impl RouteAuction {
    pub fn public_record(&self) -> Value {
        json!({
            "auction_id": self.auction_id,
            "child_route_id": self.child_route_id,
            "auctioneer_commitment": self.auctioneer_commitment,
            "sealed_bid_root": self.sealed_bid_root,
            "reserve_price_root": self.reserve_price_root,
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
            "status": self.status.as_str(),
            "solver_commitment_ids": self.solver_commitment_ids.iter().cloned().collect::<Vec<_>>()
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverCommitment {
    pub commitment_id: String,
    pub auction_id: String,
    pub child_route_id: String,
    pub solver_id: String,
    pub route_solution_root: String,
    pub fill_quality_root: String,
    pub expected_surplus_micro_units: u64,
    pub solver_fee_bps: u64,
    pub rebate_bps: u64,
    pub stake_commitment_root: String,
    pub pq_attestation_root: String,
    pub committed_at_height: u64,
    pub reveal_deadline_height: u64,
    pub score: u128,
    pub status: CommitmentStatus,
}

impl SolverCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "auction_id": self.auction_id,
            "child_route_id": self.child_route_id,
            "solver_id": self.solver_id,
            "route_solution_root": self.route_solution_root,
            "fill_quality_root": self.fill_quality_root,
            "expected_surplus_micro_units": self.expected_surplus_micro_units,
            "solver_fee_bps": self.solver_fee_bps,
            "rebate_bps": self.rebate_bps,
            "stake_commitment_root": self.stake_commitment_root,
            "pq_attestation_root": self.pq_attestation_root,
            "committed_at_height": self.committed_at_height,
            "reveal_deadline_height": self.reveal_deadline_height,
            "score": self.score.to_string(),
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoalescedSettlementBatch {
    pub batch_id: String,
    pub batch_label: String,
    pub child_route_ids: BTreeSet<String>,
    pub selected_commitment_ids: BTreeSet<String>,
    pub reservation_ids: BTreeSet<String>,
    pub aggregate_parent_root: String,
    pub aggregate_child_route_root: String,
    pub aggregate_solver_root: String,
    pub aggregate_nullifier_root: String,
    pub settlement_calldata_root: String,
    pub privacy_set_size: u64,
    pub estimated_fee_micro_units: u64,
    pub built_at_height: u64,
    pub expires_at_height: u64,
    pub status: BatchStatus,
}

impl CoalescedSettlementBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "batch_label": self.batch_label,
            "child_route_ids": self.child_route_ids.iter().cloned().collect::<Vec<_>>(),
            "selected_commitment_ids": self.selected_commitment_ids.iter().cloned().collect::<Vec<_>>(),
            "reservation_ids": self.reservation_ids.iter().cloned().collect::<Vec<_>>(),
            "aggregate_parent_root": self.aggregate_parent_root,
            "aggregate_child_route_root": self.aggregate_child_route_root,
            "aggregate_solver_root": self.aggregate_solver_root,
            "aggregate_nullifier_root": self.aggregate_nullifier_root,
            "settlement_calldata_root": self.settlement_calldata_root,
            "privacy_set_size": self.privacy_set_size,
            "estimated_fee_micro_units": self.estimated_fee_micro_units,
            "built_at_height": self.built_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSponsorReservation {
    pub reservation_id: String,
    pub sponsor_commitment: String,
    pub parent_order_ids: BTreeSet<String>,
    pub child_route_ids: BTreeSet<String>,
    pub reserved_micro_units: u64,
    pub max_user_fee_bps: u64,
    pub rebate_commitment_root: String,
    pub remaining_sponsor_budget_micro_units: u64,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub status: ReservationStatus,
}

impl FeeSponsorReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "sponsor_commitment": self.sponsor_commitment,
            "parent_order_ids": self.parent_order_ids.iter().cloned().collect::<Vec<_>>(),
            "child_route_ids": self.child_route_ids.iter().cloned().collect::<Vec<_>>(),
            "reserved_micro_units": self.reserved_micro_units,
            "max_user_fee_bps": self.max_user_fee_bps,
            "rebate_commitment_root": self.rebate_commitment_root,
            "remaining_sponsor_budget_micro_units": self.remaining_sponsor_budget_micro_units,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub receipt_note_root: String,
    pub paid_fee_micro_units: u64,
    pub user_fee_bps: u64,
    pub finalized_nullifier_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub settled_at_height: u64,
    pub status: ReceiptStatus,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_proof_root": self.settlement_proof_root,
            "receipt_note_root": self.receipt_note_root,
            "paid_fee_micro_units": self.paid_fee_micro_units,
            "user_fee_bps": self.user_fee_bps,
            "finalized_nullifier_root": self.finalized_nullifier_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "settled_at_height": self.settled_at_height,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub reservation_id: Option<String>,
    pub sponsor_commitment: String,
    pub recipient_commitment: String,
    pub rebate_micro_units: u64,
    pub rebate_bps: u64,
    pub claim_root: String,
    pub claimed_nullifier_root: String,
    pub created_at_height: u64,
}

impl FeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "reservation_id": self.reservation_id,
            "sponsor_commitment": self.sponsor_commitment,
            "recipient_commitment": self.recipient_commitment,
            "rebate_micro_units": self.rebate_micro_units,
            "rebate_bps": self.rebate_bps,
            "claim_root": self.claim_root,
            "claimed_nullifier_root": self.claimed_nullifier_root,
            "created_at_height": self.created_at_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyNullifierFence {
    pub fence_id: String,
    pub parent_order_id: String,
    pub nullifier_root: String,
    pub spent_nullifier_root: String,
    pub replay_domain_root: String,
    pub privacy_set_size: u64,
    pub min_delay_blocks: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivacyNullifierFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "parent_order_id": self.parent_order_id,
            "nullifier_root": self.nullifier_root,
            "spent_nullifier_root": self.spent_nullifier_root,
            "replay_domain_root": self.replay_domain_root,
            "privacy_set_size": self.privacy_set_size,
            "min_delay_blocks": self.min_delay_blocks,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteHealthMetric {
    pub health_id: String,
    pub venue_hint_id: String,
    pub observed_window_blocks: u64,
    pub fill_rate_bps: u64,
    pub price_improvement_bps: i64,
    pub failure_rate_bps: u64,
    pub median_latency_ms: u64,
    pub inventory_depth_score_bps: u64,
    pub route_health_score_bps: u64,
    pub sample_root: String,
    pub measured_at_height: u64,
}

impl RouteHealthMetric {
    pub fn public_record(&self) -> Value {
        json!({
            "health_id": self.health_id,
            "venue_hint_id": self.venue_hint_id,
            "observed_window_blocks": self.observed_window_blocks,
            "fill_rate_bps": self.fill_rate_bps,
            "price_improvement_bps": self.price_improvement_bps,
            "failure_rate_bps": self.failure_rate_bps,
            "median_latency_ms": self.median_latency_ms,
            "inventory_depth_score_bps": self.inventory_depth_score_bps,
            "route_health_score_bps": self.route_health_score_bps,
            "sample_root": self.sample_root,
            "measured_at_height": self.measured_at_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub height: u64,
    pub payload_root: String,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "height": self.height,
            "payload_root": self.payload_root
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub parent_orders: u64,
    pub child_routes: u64,
    pub venue_hints: u64,
    pub route_auctions: u64,
    pub solver_commitments: u64,
    pub settlement_batches: u64,
    pub fee_reservations: u64,
    pub receipts: u64,
    pub rebates: u64,
    pub privacy_fences: u64,
    pub route_health_metrics: u64,
    pub public_events: u64,
    pub rejected_orders: u64,
    pub expired_routes: u64,
    pub total_reserved_micro_units: u64,
    pub total_paid_fee_micro_units: u64,
    pub total_rebate_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "parent_orders": self.parent_orders,
            "child_routes": self.child_routes,
            "venue_hints": self.venue_hints,
            "route_auctions": self.route_auctions,
            "solver_commitments": self.solver_commitments,
            "settlement_batches": self.settlement_batches,
            "fee_reservations": self.fee_reservations,
            "receipts": self.receipts,
            "rebates": self.rebates,
            "privacy_fences": self.privacy_fences,
            "route_health_metrics": self.route_health_metrics,
            "public_events": self.public_events,
            "rejected_orders": self.rejected_orders,
            "expired_routes": self.expired_routes,
            "total_reserved_micro_units": self.total_reserved_micro_units,
            "total_paid_fee_micro_units": self.total_paid_fee_micro_units,
            "total_rebate_micro_units": self.total_rebate_micro_units
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub parent_order_root: String,
    pub child_route_root: String,
    pub liquidity_venue_hint_root: String,
    pub route_auction_root: String,
    pub solver_commitment_root: String,
    pub settlement_batch_root: String,
    pub fee_sponsor_reservation_root: String,
    pub settlement_receipt_root: String,
    pub rebate_root: String,
    pub privacy_nullifier_fence_root: String,
    pub route_health_metric_root: String,
    pub public_event_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "parent_order_root": self.parent_order_root,
            "child_route_root": self.child_route_root,
            "liquidity_venue_hint_root": self.liquidity_venue_hint_root,
            "route_auction_root": self.route_auction_root,
            "solver_commitment_root": self.solver_commitment_root,
            "settlement_batch_root": self.settlement_batch_root,
            "fee_sponsor_reservation_root": self.fee_sponsor_reservation_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "rebate_root": self.rebate_root,
            "privacy_nullifier_fence_root": self.privacy_nullifier_fence_root,
            "route_health_metric_root": self.route_health_metric_root,
            "public_event_root": self.public_event_root
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitParentOrderRequest {
    pub order_kind: ParentOrderKind,
    pub account_commitment: String,
    pub encrypted_order_root: String,
    pub encrypted_policy_root: String,
    pub source_asset_commitment: String,
    pub target_asset_commitment: String,
    pub notional_commitment_root: String,
    pub min_fill_commitment_root: String,
    pub user_fee_limit_bps: u64,
    pub split_count_hint: u16,
    pub nullifier_root: String,
    pub privacy_set_size: u64,
    pub metadata_root: String,
    pub submitted_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterVenueHintRequest {
    pub venue_kind: LiquidityVenueKind,
    pub operator_commitment: String,
    pub pair_commitment_root: String,
    pub inventory_commitment_root: String,
    pub fee_hint_bps: u64,
    pub latency_hint_ms: u64,
    pub max_child_routes: u16,
    pub accepts_sponsored_fees: bool,
    pub health_id: String,
    pub metadata_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitChildRouteRequest {
    pub parent_order_id: String,
    pub route_index: u16,
    pub venue_hint_id: String,
    pub route_commitment_root: String,
    pub amount_share_bps: u64,
    pub price_limit_commitment_root: String,
    pub max_solver_fee_bps: u64,
    pub min_rebate_bps: u64,
    pub created_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenRouteAuctionRequest {
    pub child_route_id: String,
    pub auctioneer_commitment: String,
    pub sealed_bid_root: String,
    pub reserve_price_root: String,
    pub opened_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitSolverRouteRequest {
    pub auction_id: String,
    pub child_route_id: String,
    pub solver_id: String,
    pub route_solution_root: String,
    pub fill_quality_root: String,
    pub expected_surplus_micro_units: u64,
    pub solver_fee_bps: u64,
    pub rebate_bps: u64,
    pub stake_commitment_root: String,
    pub pq_attestation_root: String,
    pub committed_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveFeeSponsorRequest {
    pub sponsor_commitment: String,
    pub parent_order_ids: Vec<String>,
    pub child_route_ids: Vec<String>,
    pub reserved_micro_units: u64,
    pub max_user_fee_bps: u64,
    pub rebate_commitment_root: String,
    pub reserved_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildSettlementBatchRequest {
    pub batch_label: String,
    pub child_route_ids: Vec<String>,
    pub selected_commitment_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub aggregate_parent_root: String,
    pub aggregate_child_route_root: String,
    pub aggregate_solver_root: String,
    pub aggregate_nullifier_root: String,
    pub settlement_calldata_root: String,
    pub privacy_set_size: u64,
    pub estimated_fee_micro_units: u64,
    pub built_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleBatchRequest {
    pub batch_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub receipt_note_root: String,
    pub paid_fee_micro_units: u64,
    pub user_fee_bps: u64,
    pub finalized_nullifier_root: String,
    pub settled_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordRebateRequest {
    pub receipt_id: String,
    pub reservation_id: Option<String>,
    pub sponsor_commitment: String,
    pub recipient_commitment: String,
    pub rebate_micro_units: u64,
    pub rebate_bps: u64,
    pub claim_root: String,
    pub claimed_nullifier_root: String,
    pub created_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordRouteHealthRequest {
    pub venue_hint_id: String,
    pub observed_window_blocks: u64,
    pub fill_rate_bps: u64,
    pub price_improvement_bps: i64,
    pub failure_rate_bps: u64,
    pub median_latency_ms: u64,
    pub inventory_depth_score_bps: u64,
    pub sample_root: String,
    pub measured_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub sponsor_budget_remaining_micro_units: u64,
    pub parent_orders: BTreeMap<String, EncryptedParentOrder>,
    pub child_routes: BTreeMap<String, ChildRoute>,
    pub liquidity_venue_hints: BTreeMap<String, LiquidityVenueHint>,
    pub route_auctions: BTreeMap<String, RouteAuction>,
    pub solver_commitments: BTreeMap<String, SolverCommitment>,
    pub settlement_batches: BTreeMap<String, CoalescedSettlementBatch>,
    pub fee_sponsor_reservations: BTreeMap<String, FeeSponsorReservation>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub privacy_nullifier_fences: BTreeMap<String, PrivacyNullifierFence>,
    pub route_health_metrics: BTreeMap<String, RouteHealthMetric>,
    pub public_events: BTreeMap<String, RuntimeEvent>,
}

pub type Runtime = State;

impl Default for State {
    fn default() -> Self {
        let config = Config::default();
        Self {
            height: PRIVATE_L2_LOW_FEE_PRIVATE_ORDER_SPLITTING_DEVNET_HEIGHT,
            sponsor_budget_remaining_micro_units: config.sponsor_budget_micro_units,
            config,
            parent_orders: BTreeMap::new(),
            child_routes: BTreeMap::new(),
            liquidity_venue_hints: BTreeMap::new(),
            route_auctions: BTreeMap::new(),
            solver_commitments: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            fee_sponsor_reservations: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_nullifier_fences: BTreeMap::new(),
            route_health_metrics: BTreeMap::new(),
            public_events: BTreeMap::new(),
        }
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::default();

        let health_a = state
            .record_route_health(RecordRouteHealthRequest {
                venue_hint_id: "devnet-private-amm".to_string(),
                observed_window_blocks: 240,
                fill_rate_bps: 9_850,
                price_improvement_bps: 11,
                failure_rate_bps: 45,
                median_latency_ms: 410,
                inventory_depth_score_bps: 9_100,
                sample_root: sample_root("health-private-amm"),
                measured_at_height: state.height,
            })
            .expect("devnet health metric");

        let venue_a = state
            .register_venue_hint(RegisterVenueHintRequest {
                venue_kind: LiquidityVenueKind::PrivateAmm,
                operator_commitment: commitment("operator-private-amm"),
                pair_commitment_root: sample_root("xmr-usdc-pair"),
                inventory_commitment_root: sample_root("amm-inventory"),
                fee_hint_bps: 9,
                latency_hint_ms: 430,
                max_child_routes: 8,
                accepts_sponsored_fees: true,
                health_id: health_a,
                metadata_root: sample_root("amm-metadata"),
            })
            .expect("devnet venue");

        let parent = state
            .submit_parent_order(SubmitParentOrderRequest {
                order_kind: ParentOrderKind::SwapExactIn,
                account_commitment: commitment("alice-account"),
                encrypted_order_root: sample_root("alice-encrypted-parent-order"),
                encrypted_policy_root: sample_root("alice-policy"),
                source_asset_commitment: commitment("xmr"),
                target_asset_commitment: commitment("usdc"),
                notional_commitment_root: sample_root("notional-250-xmr"),
                min_fill_commitment_root: sample_root("min-fill-usdc"),
                user_fee_limit_bps: 14,
                split_count_hint: 3,
                nullifier_root: sample_root("alice-nullifier"),
                privacy_set_size: 512,
                metadata_root: sample_root("parent-metadata"),
                submitted_at_height: state.height,
            })
            .expect("devnet parent order");

        let route_a = state
            .split_child_route(SplitChildRouteRequest {
                parent_order_id: parent.clone(),
                route_index: 0,
                venue_hint_id: venue_a,
                route_commitment_root: sample_root("route-a"),
                amount_share_bps: 4_000,
                price_limit_commitment_root: sample_root("route-a-price-limit"),
                max_solver_fee_bps: 18,
                min_rebate_bps: 5,
                created_at_height: state.height + 1,
            })
            .expect("devnet route a");

        let auction_a = state
            .open_route_auction(OpenRouteAuctionRequest {
                child_route_id: route_a.clone(),
                auctioneer_commitment: commitment("auctioneer-a"),
                sealed_bid_root: sample_root("sealed-bids-a"),
                reserve_price_root: sample_root("reserve-a"),
                opened_at_height: state.height + 1,
            })
            .expect("devnet auction");

        let commitment_a = state
            .commit_solver_route(CommitSolverRouteRequest {
                auction_id: auction_a,
                child_route_id: route_a.clone(),
                solver_id: "solver-cobalt".to_string(),
                route_solution_root: sample_root("solver-cobalt-route"),
                fill_quality_root: sample_root("solver-cobalt-quality"),
                expected_surplus_micro_units: 42_000,
                solver_fee_bps: 12,
                rebate_bps: 6,
                stake_commitment_root: sample_root("solver-cobalt-stake"),
                pq_attestation_root: sample_root("solver-cobalt-pq-attestation"),
                committed_at_height: state.height + 2,
            })
            .expect("devnet solver commitment");

        let reservation = state
            .reserve_fee_sponsor(ReserveFeeSponsorRequest {
                sponsor_commitment: commitment("nebula-devnet-sponsor"),
                parent_order_ids: vec![parent],
                child_route_ids: vec![route_a.clone()],
                reserved_micro_units: 7_500,
                max_user_fee_bps: 12,
                rebate_commitment_root: sample_root("sponsor-rebate"),
                reserved_at_height: state.height + 2,
            })
            .expect("devnet reservation");

        let batch = state
            .build_settlement_batch(BuildSettlementBatchRequest {
                batch_label: "devnet-xmr-usdc-private-split-0".to_string(),
                child_route_ids: vec![route_a],
                selected_commitment_ids: vec![commitment_a],
                reservation_ids: vec![reservation.clone()],
                aggregate_parent_root: sample_root("batch-parent-root"),
                aggregate_child_route_root: sample_root("batch-child-root"),
                aggregate_solver_root: sample_root("batch-solver-root"),
                aggregate_nullifier_root: sample_root("batch-nullifier-root"),
                settlement_calldata_root: sample_root("batch-calldata"),
                privacy_set_size: 1_024,
                estimated_fee_micro_units: 6_900,
                built_at_height: state.height + 3,
            })
            .expect("devnet batch");

        let receipt = state
            .settle_batch(SettleBatchRequest {
                batch_id: batch,
                settlement_tx_root: sample_root("settlement-tx"),
                settlement_proof_root: sample_root("settlement-proof"),
                receipt_note_root: sample_root("receipt-note"),
                paid_fee_micro_units: 6_650,
                user_fee_bps: 10,
                finalized_nullifier_root: sample_root("final-nullifier"),
                settled_at_height: state.height + 5,
            })
            .expect("devnet receipt");

        let _ = state.record_rebate(RecordRebateRequest {
            receipt_id: receipt,
            reservation_id: Some(reservation),
            sponsor_commitment: commitment("nebula-devnet-sponsor"),
            recipient_commitment: commitment("alice-account"),
            rebate_micro_units: 600,
            rebate_bps: 6,
            claim_root: sample_root("rebate-claim"),
            claimed_nullifier_root: sample_root("rebate-nullifier"),
            created_at_height: state.height + 6,
        });

        state
    }

    pub fn counters(&self) -> Counters {
        Counters {
            parent_orders: self.parent_orders.len() as u64,
            child_routes: self.child_routes.len() as u64,
            venue_hints: self.liquidity_venue_hints.len() as u64,
            route_auctions: self.route_auctions.len() as u64,
            solver_commitments: self.solver_commitments.len() as u64,
            settlement_batches: self.settlement_batches.len() as u64,
            fee_reservations: self.fee_sponsor_reservations.len() as u64,
            receipts: self.settlement_receipts.len() as u64,
            rebates: self.rebates.len() as u64,
            privacy_fences: self.privacy_nullifier_fences.len() as u64,
            route_health_metrics: self.route_health_metrics.len() as u64,
            public_events: self.public_events.len() as u64,
            rejected_orders: self
                .parent_orders
                .values()
                .filter(|order| order.status == ParentOrderStatus::Rejected)
                .count() as u64,
            expired_routes: self
                .child_routes
                .values()
                .filter(|route| route.status == ChildRouteStatus::Expired)
                .count() as u64,
            total_reserved_micro_units: self
                .fee_sponsor_reservations
                .values()
                .map(|reservation| reservation.reserved_micro_units)
                .sum(),
            total_paid_fee_micro_units: self
                .settlement_receipts
                .values()
                .map(|receipt| receipt.paid_fee_micro_units)
                .sum(),
            total_rebate_micro_units: self
                .rebates
                .values()
                .map(|rebate| rebate.rebate_micro_units)
                .sum(),
        }
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: payload_root(
                "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-CONFIG",
                &self.config.public_record(),
            ),
            counters_root: payload_root(
                "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-COUNTERS",
                &self.counters().public_record(),
            ),
            parent_order_root: root_from_record(
                "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-PARENT-ORDER",
                self.parent_orders
                    .values()
                    .map(EncryptedParentOrder::public_record)
                    .collect(),
            ),
            child_route_root: root_from_record(
                "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-CHILD-ROUTE",
                self.child_routes
                    .values()
                    .map(ChildRoute::public_record)
                    .collect(),
            ),
            liquidity_venue_hint_root: root_from_record(
                "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-VENUE-HINT",
                self.liquidity_venue_hints
                    .values()
                    .map(LiquidityVenueHint::public_record)
                    .collect(),
            ),
            route_auction_root: root_from_record(
                "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-ROUTE-AUCTION",
                self.route_auctions
                    .values()
                    .map(RouteAuction::public_record)
                    .collect(),
            ),
            solver_commitment_root: root_from_record(
                "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-SOLVER-COMMITMENT",
                self.solver_commitments
                    .values()
                    .map(SolverCommitment::public_record)
                    .collect(),
            ),
            settlement_batch_root: root_from_record(
                "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-SETTLEMENT-BATCH",
                self.settlement_batches
                    .values()
                    .map(CoalescedSettlementBatch::public_record)
                    .collect(),
            ),
            fee_sponsor_reservation_root: root_from_record(
                "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-FEE-RESERVATION",
                self.fee_sponsor_reservations
                    .values()
                    .map(FeeSponsorReservation::public_record)
                    .collect(),
            ),
            settlement_receipt_root: root_from_record(
                "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-SETTLEMENT-RECEIPT",
                self.settlement_receipts
                    .values()
                    .map(SettlementReceipt::public_record)
                    .collect(),
            ),
            rebate_root: root_from_record(
                "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-REBATE",
                self.rebates
                    .values()
                    .map(FeeRebate::public_record)
                    .collect(),
            ),
            privacy_nullifier_fence_root: root_from_record(
                "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-PRIVACY-FENCE",
                self.privacy_nullifier_fences
                    .values()
                    .map(PrivacyNullifierFence::public_record)
                    .collect(),
            ),
            route_health_metric_root: root_from_record(
                "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-ROUTE-HEALTH",
                self.route_health_metrics
                    .values()
                    .map(RouteHealthMetric::public_record)
                    .collect(),
            ),
            public_event_root: root_from_record(
                "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-EVENT",
                self.public_events
                    .values()
                    .map(RuntimeEvent::public_record)
                    .collect(),
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_l2_low_fee_private_order_splitting_runtime_state",
            "chain_id": CHAIN_ID,
            "height": self.height,
            "protocol_version": PRIVATE_L2_LOW_FEE_PRIVATE_ORDER_SPLITTING_PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": self.counters().public_record(),
            "sponsor_budget_remaining_micro_units": self.sponsor_budget_remaining_micro_units,
            "parent_orders": self.parent_orders.values().map(EncryptedParentOrder::public_record).collect::<Vec<_>>(),
            "child_routes": self.child_routes.values().map(ChildRoute::public_record).collect::<Vec<_>>(),
            "liquidity_venue_hints": self.liquidity_venue_hints.values().map(LiquidityVenueHint::public_record).collect::<Vec<_>>(),
            "route_auctions": self.route_auctions.values().map(RouteAuction::public_record).collect::<Vec<_>>(),
            "solver_commitments": self.solver_commitments.values().map(SolverCommitment::public_record).collect::<Vec<_>>(),
            "settlement_batches": self.settlement_batches.values().map(CoalescedSettlementBatch::public_record).collect::<Vec<_>>(),
            "fee_sponsor_reservations": self.fee_sponsor_reservations.values().map(FeeSponsorReservation::public_record).collect::<Vec<_>>(),
            "settlement_receipts": self.settlement_receipts.values().map(SettlementReceipt::public_record).collect::<Vec<_>>(),
            "rebates": self.rebates.values().map(FeeRebate::public_record).collect::<Vec<_>>(),
            "privacy_nullifier_fences": self.privacy_nullifier_fences.values().map(PrivacyNullifierFence::public_record).collect::<Vec<_>>(),
            "route_health_metrics": self.route_health_metrics.values().map(RouteHealthMetric::public_record).collect::<Vec<_>>(),
            "public_events": self.public_events.values().map(RuntimeEvent::public_record).collect::<Vec<_>>()
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }

    pub fn submit_parent_order(&mut self, request: SubmitParentOrderRequest) -> Result<String> {
        require_root("encrypted_order_root", &request.encrypted_order_root)?;
        require_root("encrypted_policy_root", &request.encrypted_policy_root)?;
        require_root("nullifier_root", &request.nullifier_root)?;
        require_bps(
            "user_fee_limit_bps",
            request.user_fee_limit_bps,
            self.config.max_user_fee_bps,
        )?;
        if request.privacy_set_size < self.config.min_parent_privacy_set_size {
            return Err("parent order privacy set is below configured floor".to_string());
        }
        if self.parent_orders.len() >= self.config.max_parent_orders {
            return Err("parent order capacity exhausted".to_string());
        }
        let nonce = self.parent_orders.len() as u64 + 1;
        let parent_order_id = parent_order_id(&request, nonce);
        let expires_at_height = request
            .submitted_at_height
            .saturating_add(self.config.parent_order_ttl_blocks);
        let order = EncryptedParentOrder {
            parent_order_id: parent_order_id.clone(),
            order_kind: request.order_kind,
            account_commitment: request.account_commitment,
            encrypted_order_root: request.encrypted_order_root,
            encrypted_policy_root: request.encrypted_policy_root,
            source_asset_commitment: request.source_asset_commitment,
            target_asset_commitment: request.target_asset_commitment,
            notional_commitment_root: request.notional_commitment_root,
            min_fill_commitment_root: request.min_fill_commitment_root,
            user_fee_limit_bps: request.user_fee_limit_bps,
            split_count_hint: request.split_count_hint,
            nullifier_root: request.nullifier_root,
            privacy_set_size: request.privacy_set_size,
            submitted_at_height: request.submitted_at_height,
            expires_at_height,
            status: ParentOrderStatus::Submitted,
            child_route_ids: BTreeSet::new(),
            reservation_ids: BTreeSet::new(),
            metadata_root: request.metadata_root,
        };
        let fence_id = privacy_fence_id(&parent_order_id, &order.nullifier_root, nonce);
        let fence = PrivacyNullifierFence {
            fence_id: fence_id.clone(),
            parent_order_id: parent_order_id.clone(),
            nullifier_root: order.nullifier_root.clone(),
            spent_nullifier_root: sample_root(&format!("{parent_order_id}-unspent")),
            replay_domain_root: sample_root(&format!("{parent_order_id}-replay-domain")),
            privacy_set_size: order.privacy_set_size,
            min_delay_blocks: self.config.auction_window_blocks,
            opened_at_height: order.submitted_at_height,
            expires_at_height,
        };
        self.parent_orders.insert(parent_order_id.clone(), order);
        self.privacy_nullifier_fences.insert(fence_id, fence);
        self.emit_event("parent_order_submitted", &parent_order_id);
        Ok(parent_order_id)
    }

    pub fn register_venue_hint(&mut self, request: RegisterVenueHintRequest) -> Result<String> {
        require_root("pair_commitment_root", &request.pair_commitment_root)?;
        require_root(
            "inventory_commitment_root",
            &request.inventory_commitment_root,
        )?;
        require_bps(
            "fee_hint_bps",
            request.fee_hint_bps,
            self.config.max_solver_fee_bps,
        )?;
        let nonce = self.liquidity_venue_hints.len() as u64 + 1;
        let venue_hint_id = venue_hint_id(&request, nonce);
        let hint = LiquidityVenueHint {
            venue_hint_id: venue_hint_id.clone(),
            venue_kind: request.venue_kind,
            operator_commitment: request.operator_commitment,
            pair_commitment_root: request.pair_commitment_root,
            inventory_commitment_root: request.inventory_commitment_root,
            fee_hint_bps: request.fee_hint_bps,
            latency_hint_ms: request.latency_hint_ms,
            max_child_routes: request.max_child_routes,
            accepts_sponsored_fees: request.accepts_sponsored_fees,
            health_id: request.health_id,
            metadata_root: request.metadata_root,
        };
        self.liquidity_venue_hints
            .insert(venue_hint_id.clone(), hint);
        self.emit_event("venue_hint_registered", &venue_hint_id);
        Ok(venue_hint_id)
    }

    pub fn split_child_route(&mut self, request: SplitChildRouteRequest) -> Result<String> {
        require_root("route_commitment_root", &request.route_commitment_root)?;
        require_root(
            "price_limit_commitment_root",
            &request.price_limit_commitment_root,
        )?;
        require_bps("amount_share_bps", request.amount_share_bps, MAX_BPS)?;
        require_bps(
            "max_solver_fee_bps",
            request.max_solver_fee_bps,
            self.config.max_solver_fee_bps,
        )?;
        require_rebate_bps(request.min_rebate_bps, &self.config)?;
        let venue = self
            .liquidity_venue_hints
            .get(&request.venue_hint_id)
            .ok_or_else(|| "venue hint not found".to_string())?;
        if let Some(health) = self.route_health_metrics.get(&venue.health_id) {
            if health.route_health_score_bps < self.config.route_health_floor_bps {
                return Err("venue route health is below configured floor".to_string());
            }
        }
        let parent = self
            .parent_orders
            .get_mut(&request.parent_order_id)
            .ok_or_else(|| "parent order not found".to_string())?;
        if !parent.status.can_split() {
            return Err("parent order is not splittable".to_string());
        }
        if parent.child_route_ids.len() >= self.config.max_child_routes_per_parent {
            return Err("parent child route capacity exhausted".to_string());
        }
        let nonce = self.child_routes.len() as u64 + 1;
        let child_route_id = child_route_id(&request, nonce);
        let route = ChildRoute {
            child_route_id: child_route_id.clone(),
            parent_order_id: request.parent_order_id.clone(),
            route_index: request.route_index,
            venue_kind: venue.venue_kind,
            venue_hint_id: request.venue_hint_id,
            route_commitment_root: request.route_commitment_root,
            amount_share_bps: request.amount_share_bps,
            price_limit_commitment_root: request.price_limit_commitment_root,
            max_solver_fee_bps: request.max_solver_fee_bps,
            min_rebate_bps: request.min_rebate_bps,
            auction_id: None,
            selected_commitment_id: None,
            route_health_id: Some(venue.health_id.clone()),
            status: ChildRouteStatus::Proposed,
            created_at_height: request.created_at_height,
            expires_at_height: request
                .created_at_height
                .saturating_add(self.config.parent_order_ttl_blocks),
        };
        parent.status = ParentOrderStatus::Split;
        parent.child_route_ids.insert(child_route_id.clone());
        self.child_routes.insert(child_route_id.clone(), route);
        self.emit_event("child_route_split", &child_route_id);
        Ok(child_route_id)
    }

    pub fn open_route_auction(&mut self, request: OpenRouteAuctionRequest) -> Result<String> {
        require_root("sealed_bid_root", &request.sealed_bid_root)?;
        require_root("reserve_price_root", &request.reserve_price_root)?;
        let route = self
            .child_routes
            .get_mut(&request.child_route_id)
            .ok_or_else(|| "child route not found".to_string())?;
        let nonce = self.route_auctions.len() as u64 + 1;
        let auction_id = route_auction_id(&request, nonce);
        let auction = RouteAuction {
            auction_id: auction_id.clone(),
            child_route_id: request.child_route_id.clone(),
            auctioneer_commitment: request.auctioneer_commitment,
            sealed_bid_root: request.sealed_bid_root,
            reserve_price_root: request.reserve_price_root,
            opened_at_height: request.opened_at_height,
            closes_at_height: request
                .opened_at_height
                .saturating_add(self.config.auction_window_blocks),
            status: AuctionStatus::Open,
            solver_commitment_ids: BTreeSet::new(),
        };
        route.auction_id = Some(auction_id.clone());
        route.status = ChildRouteStatus::AuctionOpen;
        self.route_auctions.insert(auction_id.clone(), auction);
        self.emit_event("route_auction_opened", &auction_id);
        Ok(auction_id)
    }

    pub fn commit_solver_route(&mut self, request: CommitSolverRouteRequest) -> Result<String> {
        require_root("route_solution_root", &request.route_solution_root)?;
        require_root("fill_quality_root", &request.fill_quality_root)?;
        require_root("pq_attestation_root", &request.pq_attestation_root)?;
        require_bps(
            "solver_fee_bps",
            request.solver_fee_bps,
            self.config.max_solver_fee_bps,
        )?;
        require_rebate_bps(request.rebate_bps, &self.config)?;
        if self.solver_commitments.len() >= self.config.max_solver_commitments {
            return Err("solver commitment capacity exhausted".to_string());
        }
        let auction = self
            .route_auctions
            .get_mut(&request.auction_id)
            .ok_or_else(|| "route auction not found".to_string())?;
        if auction.status != AuctionStatus::Open {
            return Err("route auction is not open".to_string());
        }
        ensure_eq(
            &auction.child_route_id,
            &request.child_route_id,
            "auction child route",
        )?;
        let route = self
            .child_routes
            .get_mut(&request.child_route_id)
            .ok_or_else(|| "child route not found".to_string())?;
        let score = solver_score(&request);
        let nonce = self.solver_commitments.len() as u64 + 1;
        let commitment_id = solver_commitment_id(&request, score, nonce);
        let commitment = SolverCommitment {
            commitment_id: commitment_id.clone(),
            auction_id: request.auction_id,
            child_route_id: request.child_route_id,
            solver_id: request.solver_id,
            route_solution_root: request.route_solution_root,
            fill_quality_root: request.fill_quality_root,
            expected_surplus_micro_units: request.expected_surplus_micro_units,
            solver_fee_bps: request.solver_fee_bps,
            rebate_bps: request.rebate_bps,
            stake_commitment_root: request.stake_commitment_root,
            pq_attestation_root: request.pq_attestation_root,
            committed_at_height: request.committed_at_height,
            reveal_deadline_height: request
                .committed_at_height
                .saturating_add(self.config.auction_window_blocks),
            score,
            status: CommitmentStatus::Committed,
        };
        auction.solver_commitment_ids.insert(commitment_id.clone());
        route.status = ChildRouteStatus::SolverCommitted;
        self.solver_commitments
            .insert(commitment_id.clone(), commitment);
        self.emit_event("solver_route_committed", &commitment_id);
        Ok(commitment_id)
    }

    pub fn reserve_fee_sponsor(&mut self, request: ReserveFeeSponsorRequest) -> Result<String> {
        require_non_empty("sponsor_commitment", &request.sponsor_commitment)?;
        require_root("rebate_commitment_root", &request.rebate_commitment_root)?;
        require_bps(
            "max_user_fee_bps",
            request.max_user_fee_bps,
            self.config.max_user_fee_bps,
        )?;
        if self.fee_sponsor_reservations.len() >= self.config.max_reservations {
            return Err("fee sponsor reservation capacity exhausted".to_string());
        }
        if request.reserved_micro_units > self.sponsor_budget_remaining_micro_units {
            return Err("insufficient sponsor budget".to_string());
        }
        for parent_id in &request.parent_order_ids {
            if !self.parent_orders.contains_key(parent_id) {
                return Err(format!("parent order {parent_id} not found"));
            }
        }
        for route_id in &request.child_route_ids {
            if !self.child_routes.contains_key(route_id) {
                return Err(format!("child route {route_id} not found"));
            }
        }
        self.sponsor_budget_remaining_micro_units = self
            .sponsor_budget_remaining_micro_units
            .saturating_sub(request.reserved_micro_units);
        let nonce = self.fee_sponsor_reservations.len() as u64 + 1;
        let reservation_id =
            fee_sponsor_reservation_id(&request, nonce, self.sponsor_budget_remaining_micro_units);
        let reservation = FeeSponsorReservation {
            reservation_id: reservation_id.clone(),
            sponsor_commitment: request.sponsor_commitment,
            parent_order_ids: request.parent_order_ids.iter().cloned().collect(),
            child_route_ids: request.child_route_ids.iter().cloned().collect(),
            reserved_micro_units: request.reserved_micro_units,
            max_user_fee_bps: request.max_user_fee_bps,
            rebate_commitment_root: request.rebate_commitment_root,
            remaining_sponsor_budget_micro_units: self.sponsor_budget_remaining_micro_units,
            reserved_at_height: request.reserved_at_height,
            expires_at_height: request
                .reserved_at_height
                .saturating_add(self.config.settlement_ttl_blocks),
            status: ReservationStatus::Reserved,
        };
        for parent_id in &request.parent_order_ids {
            if let Some(parent) = self.parent_orders.get_mut(parent_id) {
                parent.status = ParentOrderStatus::Sponsored;
                parent.reservation_ids.insert(reservation_id.clone());
            }
        }
        self.fee_sponsor_reservations
            .insert(reservation_id.clone(), reservation);
        self.emit_event("fee_sponsor_reserved", &reservation_id);
        Ok(reservation_id)
    }

    pub fn build_settlement_batch(
        &mut self,
        request: BuildSettlementBatchRequest,
    ) -> Result<String> {
        require_root("aggregate_parent_root", &request.aggregate_parent_root)?;
        require_root(
            "aggregate_child_route_root",
            &request.aggregate_child_route_root,
        )?;
        require_root("aggregate_solver_root", &request.aggregate_solver_root)?;
        require_root(
            "aggregate_nullifier_root",
            &request.aggregate_nullifier_root,
        )?;
        require_root(
            "settlement_calldata_root",
            &request.settlement_calldata_root,
        )?;
        if request.child_route_ids.len() > self.config.max_batch_child_routes {
            return Err("batch child route capacity exceeded".to_string());
        }
        if request.privacy_set_size < self.config.min_batch_privacy_set_size {
            return Err("settlement batch privacy set is below configured floor".to_string());
        }
        for route_id in &request.child_route_ids {
            let route = self
                .child_routes
                .get(route_id)
                .ok_or_else(|| format!("child route {route_id} not found"))?;
            if !route.status.batchable() {
                return Err(format!("child route {route_id} is not batchable"));
            }
        }
        for commitment_id in &request.selected_commitment_ids {
            if !self.solver_commitments.contains_key(commitment_id) {
                return Err(format!("solver commitment {commitment_id} not found"));
            }
        }
        for reservation_id in &request.reservation_ids {
            if !self.fee_sponsor_reservations.contains_key(reservation_id) {
                return Err(format!("reservation {reservation_id} not found"));
            }
        }
        let nonce = self.settlement_batches.len() as u64 + 1;
        let batch_id = settlement_batch_id(&request, nonce);
        let batch = CoalescedSettlementBatch {
            batch_id: batch_id.clone(),
            batch_label: request.batch_label,
            child_route_ids: request.child_route_ids.iter().cloned().collect(),
            selected_commitment_ids: request.selected_commitment_ids.iter().cloned().collect(),
            reservation_ids: request.reservation_ids.iter().cloned().collect(),
            aggregate_parent_root: request.aggregate_parent_root,
            aggregate_child_route_root: request.aggregate_child_route_root,
            aggregate_solver_root: request.aggregate_solver_root,
            aggregate_nullifier_root: request.aggregate_nullifier_root,
            settlement_calldata_root: request.settlement_calldata_root,
            privacy_set_size: request.privacy_set_size,
            estimated_fee_micro_units: request.estimated_fee_micro_units,
            built_at_height: request.built_at_height,
            expires_at_height: request
                .built_at_height
                .saturating_add(self.config.settlement_ttl_blocks),
            status: BatchStatus::SettlementReady,
        };
        for route_id in &request.child_route_ids {
            if let Some(route) = self.child_routes.get_mut(route_id) {
                route.status = ChildRouteStatus::Batched;
            }
        }
        for commitment_id in &request.selected_commitment_ids {
            if let Some(commitment) = self.solver_commitments.get_mut(commitment_id) {
                commitment.status = CommitmentStatus::Selected;
            }
        }
        for reservation_id in &request.reservation_ids {
            if let Some(reservation) = self.fee_sponsor_reservations.get_mut(reservation_id) {
                reservation.status = ReservationStatus::Reserved;
            }
        }
        self.settlement_batches.insert(batch_id.clone(), batch);
        self.emit_event("settlement_batch_built", &batch_id);
        Ok(batch_id)
    }

    pub fn settle_batch(&mut self, request: SettleBatchRequest) -> Result<String> {
        require_root("settlement_tx_root", &request.settlement_tx_root)?;
        require_root("settlement_proof_root", &request.settlement_proof_root)?;
        require_root("receipt_note_root", &request.receipt_note_root)?;
        require_root(
            "finalized_nullifier_root",
            &request.finalized_nullifier_root,
        )?;
        require_bps(
            "user_fee_bps",
            request.user_fee_bps,
            self.config.max_user_fee_bps,
        )?;
        let state_root_before = self.state_root();
        let batch = self
            .settlement_batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| "settlement batch not found".to_string())?;
        if batch.status != BatchStatus::SettlementReady {
            return Err("settlement batch is not settlement ready".to_string());
        }
        batch.status = BatchStatus::Settled;
        for route_id in batch.child_route_ids.clone() {
            if let Some(route) = self.child_routes.get_mut(&route_id) {
                route.status = ChildRouteStatus::Settled;
                if let Some(parent) = self.parent_orders.get_mut(&route.parent_order_id) {
                    parent.status = ParentOrderStatus::Settled;
                }
            }
        }
        for commitment_id in batch.selected_commitment_ids.clone() {
            if let Some(commitment) = self.solver_commitments.get_mut(&commitment_id) {
                commitment.status = CommitmentStatus::Settled;
            }
        }
        for reservation_id in batch.reservation_ids.clone() {
            if let Some(reservation) = self.fee_sponsor_reservations.get_mut(&reservation_id) {
                reservation.status = ReservationStatus::Consumed;
            }
        }
        let nonce = self.settlement_receipts.len() as u64 + 1;
        let receipt_id = settlement_receipt_id(&request, nonce, &state_root_before);
        let mut receipt = SettlementReceipt {
            receipt_id: receipt_id.clone(),
            batch_id: request.batch_id,
            settlement_tx_root: request.settlement_tx_root,
            settlement_proof_root: request.settlement_proof_root,
            receipt_note_root: request.receipt_note_root,
            paid_fee_micro_units: request.paid_fee_micro_units,
            user_fee_bps: request.user_fee_bps,
            finalized_nullifier_root: request.finalized_nullifier_root,
            state_root_before,
            state_root_after: String::new(),
            settled_at_height: request.settled_at_height,
            status: ReceiptStatus::Published,
        };
        let provisional = receipt.public_record();
        receipt.state_root_after = payload_root(
            "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-RECEIPT-STATE-AFTER",
            &provisional,
        );
        self.settlement_receipts.insert(receipt_id.clone(), receipt);
        self.emit_event("settlement_receipt_published", &receipt_id);
        Ok(receipt_id)
    }

    pub fn record_rebate(&mut self, request: RecordRebateRequest) -> Result<String> {
        require_root("claim_root", &request.claim_root)?;
        require_root("claimed_nullifier_root", &request.claimed_nullifier_root)?;
        require_rebate_bps(request.rebate_bps, &self.config)?;
        if !self.settlement_receipts.contains_key(&request.receipt_id) {
            return Err("receipt not found".to_string());
        }
        if let Some(reservation_id) = &request.reservation_id {
            if !self.fee_sponsor_reservations.contains_key(reservation_id) {
                return Err("reservation not found".to_string());
            }
        }
        let nonce = self.rebates.len() as u64 + 1;
        let rebate_id = fee_rebate_id(&request, nonce);
        let rebate = FeeRebate {
            rebate_id: rebate_id.clone(),
            receipt_id: request.receipt_id,
            reservation_id: request.reservation_id,
            sponsor_commitment: request.sponsor_commitment,
            recipient_commitment: request.recipient_commitment,
            rebate_micro_units: request.rebate_micro_units,
            rebate_bps: request.rebate_bps,
            claim_root: request.claim_root,
            claimed_nullifier_root: request.claimed_nullifier_root,
            created_at_height: request.created_at_height,
        };
        self.rebates.insert(rebate_id.clone(), rebate);
        self.emit_event("fee_rebate_recorded", &rebate_id);
        Ok(rebate_id)
    }

    pub fn record_route_health(&mut self, request: RecordRouteHealthRequest) -> Result<String> {
        require_root("sample_root", &request.sample_root)?;
        require_bps("fill_rate_bps", request.fill_rate_bps, MAX_BPS)?;
        require_bps("failure_rate_bps", request.failure_rate_bps, MAX_BPS)?;
        require_bps(
            "inventory_depth_score_bps",
            request.inventory_depth_score_bps,
            MAX_BPS,
        )?;
        let route_health_score_bps = route_health_score_bps(&request);
        let nonce = self.route_health_metrics.len() as u64 + 1;
        let health_id = route_health_metric_id(&request, route_health_score_bps, nonce);
        let metric = RouteHealthMetric {
            health_id: health_id.clone(),
            venue_hint_id: request.venue_hint_id,
            observed_window_blocks: request.observed_window_blocks,
            fill_rate_bps: request.fill_rate_bps,
            price_improvement_bps: request.price_improvement_bps,
            failure_rate_bps: request.failure_rate_bps,
            median_latency_ms: request.median_latency_ms,
            inventory_depth_score_bps: request.inventory_depth_score_bps,
            route_health_score_bps,
            sample_root: request.sample_root,
            measured_at_height: request.measured_at_height,
        };
        self.route_health_metrics.insert(health_id.clone(), metric);
        self.emit_event("route_health_recorded", &health_id);
        Ok(health_id)
    }

    fn emit_event(&mut self, event_kind: &str, subject_id: &str) {
        let payload = json!({
            "event_kind": event_kind,
            "subject_id": subject_id,
            "height": self.height,
            "ordinal": self.public_events.len() + 1
        });
        let event_id = public_event_id(event_kind, subject_id, self.public_events.len() as u64 + 1);
        let event = RuntimeEvent {
            event_id: event_id.clone(),
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            height: self.height,
            payload_root: payload_root("PRIVATE-L2-LOW-FEE-ORDER-SPLIT-EVENT-PAYLOAD", &payload),
        };
        self.public_events.insert(event_id, event);
    }
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_LOW_FEE_PRIVATE_ORDER_SPLITTING_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

pub fn public_record_root(record: &Value) -> String {
    payload_root("PRIVATE-L2-LOW-FEE-ORDER-SPLIT-PUBLIC-RECORD", record)
}

pub fn state_root_from_record(record: &Value) -> String {
    payload_root("PRIVATE-L2-LOW-FEE-ORDER-SPLIT-STATE", record)
}

pub fn parent_order_id(request: &SubmitParentOrderRequest, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-PARENT-ORDER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(request.order_kind.as_str()),
            HashPart::Str(&request.account_commitment),
            HashPart::Str(&request.encrypted_order_root),
            HashPart::Str(&request.nullifier_root),
        ],
        32,
    )
}

pub fn venue_hint_id(request: &RegisterVenueHintRequest, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-VENUE-HINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(request.venue_kind.as_str()),
            HashPart::Str(&request.operator_commitment),
            HashPart::Str(&request.pair_commitment_root),
            HashPart::Str(&request.inventory_commitment_root),
        ],
        32,
    )
}

pub fn child_route_id(request: &SplitChildRouteRequest, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-CHILD-ROUTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.parent_order_id),
            HashPart::Int(request.route_index as i128),
            HashPart::Str(&request.venue_hint_id),
            HashPart::Str(&request.route_commitment_root),
        ],
        32,
    )
}

pub fn route_auction_id(request: &OpenRouteAuctionRequest, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-ROUTE-AUCTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.child_route_id),
            HashPart::Str(&request.auctioneer_commitment),
            HashPart::Str(&request.sealed_bid_root),
            HashPart::Int(request.opened_at_height as i128),
        ],
        32,
    )
}

pub fn solver_commitment_id(request: &CommitSolverRouteRequest, score: u128, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-SOLVER-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.auction_id),
            HashPart::Str(&request.child_route_id),
            HashPart::Str(&request.solver_id),
            HashPart::Str(&request.route_solution_root),
            HashPart::Int(score.min(i128::MAX as u128) as i128),
        ],
        32,
    )
}

pub fn fee_sponsor_reservation_id(
    request: &ReserveFeeSponsorRequest,
    nonce: u64,
    remaining_budget_micro_units: u64,
) -> String {
    let parent_root = root_from_record(
        "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-RESERVATION-PARENTS",
        request
            .parent_order_ids
            .iter()
            .map(|id| json!(id))
            .collect(),
    );
    let route_root = root_from_record(
        "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-RESERVATION-ROUTES",
        request.child_route_ids.iter().map(|id| json!(id)).collect(),
    );
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-FEE-SPONSOR-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&parent_root),
            HashPart::Str(&route_root),
            HashPart::Str(&request.rebate_commitment_root),
            HashPart::Int(request.reserved_micro_units as i128),
            HashPart::Int(remaining_budget_micro_units as i128),
        ],
        32,
    )
}

pub fn settlement_batch_id(request: &BuildSettlementBatchRequest, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-SETTLEMENT-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.batch_label),
            HashPart::Str(&request.aggregate_parent_root),
            HashPart::Str(&request.aggregate_child_route_root),
            HashPart::Str(&request.aggregate_solver_root),
            HashPart::Str(&request.aggregate_nullifier_root),
            HashPart::Int(request.built_at_height as i128),
        ],
        32,
    )
}

pub fn settlement_receipt_id(
    request: &SettleBatchRequest,
    nonce: u64,
    state_root_before: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.batch_id),
            HashPart::Str(&request.settlement_tx_root),
            HashPart::Str(&request.settlement_proof_root),
            HashPart::Str(state_root_before),
            HashPart::Int(request.settled_at_height as i128),
        ],
        32,
    )
}

pub fn fee_rebate_id(request: &RecordRebateRequest, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-FEE-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.receipt_id),
            HashPart::Str(request.reservation_id.as_deref().unwrap_or("none")),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.recipient_commitment),
            HashPart::Str(&request.claim_root),
            HashPart::Str(&request.claimed_nullifier_root),
        ],
        32,
    )
}

pub fn privacy_fence_id(parent_order_id: &str, nullifier_root: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-PRIVACY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(parent_order_id),
            HashPart::Str(nullifier_root),
        ],
        32,
    )
}

pub fn route_health_metric_id(
    request: &RecordRouteHealthRequest,
    route_health_score_bps: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-ROUTE-HEALTH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.venue_hint_id),
            HashPart::Int(route_health_score_bps as i128),
            HashPart::Str(&request.sample_root),
            HashPart::Int(request.measured_at_height as i128),
        ],
        32,
    )
}

pub fn public_event_id(event_kind: &str, subject_id: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(event_kind),
            HashPart::Str(subject_id),
        ],
        32,
    )
}

fn solver_score(request: &CommitSolverRouteRequest) -> u128 {
    let surplus = request.expected_surplus_micro_units as u128;
    let rebate_bonus = request.rebate_bps as u128 * 1_000_000;
    let fee_penalty = request.solver_fee_bps as u128 * 1_250_000;
    surplus
        .saturating_mul(1_000_000)
        .saturating_add(rebate_bonus)
        .saturating_sub(fee_penalty)
}

fn route_health_score_bps(request: &RecordRouteHealthRequest) -> u64 {
    let positive = request
        .fill_rate_bps
        .saturating_mul(45)
        .saturating_add(request.inventory_depth_score_bps.saturating_mul(30))
        .saturating_add(latency_score_bps(request.median_latency_ms).saturating_mul(20));
    let price_component = if request.price_improvement_bps >= 0 {
        (request.price_improvement_bps as u64)
            .min(500)
            .saturating_mul(10)
    } else {
        0
    };
    let penalty = request.failure_rate_bps.saturating_mul(25);
    positive
        .saturating_add(price_component)
        .saturating_sub(penalty)
        .saturating_div(95)
        .min(MAX_BPS)
}

fn latency_score_bps(latency_ms: u64) -> u64 {
    if latency_ms <= 250 {
        10_000
    } else if latency_ms >= 2_500 {
        1_000
    } else {
        10_000u64.saturating_sub((latency_ms - 250).saturating_mul(4))
    }
}

fn commitment(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-DEVNET-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

fn sample_root(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ORDER-SPLIT-DEVNET-SAMPLE-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

fn require_non_empty(label: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn require_root(label: &str, value: &str) -> Result<()> {
    if value.len() < 32 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!(
            "{label} must be a hex commitment/root of at least 32 chars"
        ));
    }
    Ok(())
}

fn require_bps(label: &str, value: u64, limit: u64) -> Result<()> {
    if value > limit || value > MAX_BPS {
        return Err(format!("{label} exceeds allowed bps limit"));
    }
    Ok(())
}

fn require_rebate_bps(value: u64, config: &Config) -> Result<()> {
    if value < config.min_rebate_bps || value > config.max_rebate_bps || value > MAX_BPS {
        return Err("rebate bps is outside configured bounds".to_string());
    }
    Ok(())
}

fn ensure_eq(actual: &str, expected: &str, label: &str) -> Result<()> {
    if actual != expected {
        return Err(format!(
            "{label} mismatch: expected {expected}, got {actual}"
        ));
    }
    Ok(())
}
