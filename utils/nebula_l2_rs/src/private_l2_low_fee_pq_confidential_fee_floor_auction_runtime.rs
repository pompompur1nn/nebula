use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_FEE_FLOOR_AUCTION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-fee-floor-auction-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_FEE_FLOOR_AUCTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-fee-floor-clearing-v1";
pub const PQ_SEALED_BID_SUITE: &str = "ML-KEM-1024+XWing-confidential-fee-floor-bid-v1";
pub const BID_COMMITMENT_SCHEME: &str = "ringct-style-private-fee-floor-bid-commitment-v1";
pub const CLEARING_PROOF_SCHEME: &str = "zk-pq-fee-floor-auction-clearing-proof-v1";
pub const SPONSOR_LIQUIDITY_SCHEME: &str = "roots-only-private-sponsor-liquidity-v1";
pub const REBATE_ROUTING_SCHEME: &str = "calldata-proof-da-rebate-routing-v1";
pub const CONGESTION_REBATE_SCHEME: &str = "private-l2-congestion-rebate-curve-v1";
pub const BRIDGE_EXIT_SMOOTHING_SCHEME: &str = "private-l2-bridge-exit-fee-smoothing-v1";
pub const MICRO_BATCH_DISCOUNT_SCHEME: &str = "private-l2-microbatch-discount-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str = "public-low-fee-operator-summary-v1";
pub const DEVNET_HEIGHT: u64 = 2_572_000;
pub const DEVNET_EPOCH: u64 = 3_891;
pub const DEVNET_CHAIN_ID: u64 = 731_337;
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET: &str = "fee-credit-devnet";
pub const DEVNET_BRIDGE_ASSET: &str = "wxmr-devnet";
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_AUCTION_TTL_BLOCKS: u64 = 18;
pub const DEFAULT_BID_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_CLEARING_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 4_320;
pub const DEFAULT_BRIDGE_SMOOTHING_WINDOW_BLOCKS: u64 = 360;
pub const DEFAULT_MICROBATCH_WINDOW_BLOCKS: u64 = 8;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_DECOY_SET_SIZE: u64 = 2_048;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 14;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 5;
pub const DEFAULT_FEE_CAP_HEADROOM_BPS: u64 = 2;
pub const DEFAULT_MIN_FLOOR_BPS: u64 = 1;
pub const DEFAULT_TARGET_FLOOR_BPS: u64 = 4;
pub const DEFAULT_MAX_FLOOR_BPS: u64 = 12;
pub const DEFAULT_MIN_REBATE_BPS: u64 = 2;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 9;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 28;
pub const DEFAULT_CONGESTION_REBATE_BPS: u64 = 10;
pub const DEFAULT_CALLDATA_REBATE_WEIGHT_BPS: u64 = 2_500;
pub const DEFAULT_PROOF_REBATE_WEIGHT_BPS: u64 = 3_000;
pub const DEFAULT_DA_REBATE_WEIGHT_BPS: u64 = 4_500;
pub const DEFAULT_SPONSOR_RESERVE_BPS: u64 = 1_500;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 8_500;
pub const DEFAULT_BRIDGE_EXIT_SMOOTHING_BPS: u64 = 1_200;
pub const DEFAULT_MICROBATCH_DISCOUNT_BPS: u64 = 1_800;
pub const DEFAULT_OPERATOR_SUMMARY_TTL_BLOCKS: u64 = 72;
pub const DEFAULT_MAX_AUCTIONS: usize = 2_097_152;
pub const DEFAULT_MAX_BIDS: usize = 16_777_216;
pub const DEFAULT_MAX_CLEARINGS: usize = 2_097_152;
pub const DEFAULT_MAX_SPONSOR_POOLS: usize = 1_048_576;
pub const DEFAULT_MAX_REBATE_ROUTES: usize = 8_388_608;
pub const DEFAULT_MAX_FEE_CAPS: usize = 8_388_608;
pub const DEFAULT_MAX_BRIDGE_WINDOWS: usize = 1_048_576;
pub const DEFAULT_MAX_MICROBATCHES: usize = 4_194_304;
pub const DEFAULT_MAX_OPERATOR_SUMMARIES: usize = 1_048_576;
pub const DEFAULT_MAX_PRIVACY_FENCES: usize = 8_388_608;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeLane {
    PrivateTransfer,
    ConfidentialSwap,
    StableSwap,
    LendingPool,
    Perpetuals,
    Options,
    ContractCall,
    AccountAbstraction,
    BridgeExit,
    FastBridgeExit,
    OracleUpdate,
    LiquidationBackstop,
    ProofAggregation,
    StateDiff,
    RecursiveBatch,
    CrossRollup,
}

impl FeeLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::ConfidentialSwap => "confidential_swap",
            Self::StableSwap => "stable_swap",
            Self::LendingPool => "lending_pool",
            Self::Perpetuals => "perpetuals",
            Self::Options => "options",
            Self::ContractCall => "contract_call",
            Self::AccountAbstraction => "account_abstraction",
            Self::BridgeExit => "bridge_exit",
            Self::FastBridgeExit => "fast_bridge_exit",
            Self::OracleUpdate => "oracle_update",
            Self::LiquidationBackstop => "liquidation_backstop",
            Self::ProofAggregation => "proof_aggregation",
            Self::StateDiff => "state_diff",
            Self::RecursiveBatch => "recursive_batch",
            Self::CrossRollup => "cross_rollup",
        }
    }

    pub fn urgency_weight(self) -> u64 {
        match self {
            Self::FastBridgeExit => 10_000,
            Self::LiquidationBackstop => 9_600,
            Self::BridgeExit => 8_900,
            Self::Perpetuals => 8_100,
            Self::Options => 7_800,
            Self::ConfidentialSwap => 7_200,
            Self::StableSwap => 6_900,
            Self::ContractCall => 6_300,
            Self::AccountAbstraction => 6_000,
            Self::PrivateTransfer => 5_600,
            Self::CrossRollup => 5_200,
            Self::RecursiveBatch => 4_900,
            Self::ProofAggregation => 4_700,
            Self::OracleUpdate => 4_300,
            Self::LendingPool => 3_900,
            Self::StateDiff => 3_400,
        }
    }

    pub fn default_floor_bps(self, config: &Config) -> u64 {
        let weight = self.urgency_weight();
        let span = config.max_floor_bps.saturating_sub(config.min_floor_bps);
        config
            .min_floor_bps
            .saturating_add(span.saturating_mul(weight).saturating_div(MAX_BPS))
            .min(config.max_floor_bps)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Draft,
    Open,
    Sealed,
    Clearing,
    Cleared,
    Settled,
    Rebated,
    Cancelled,
    Expired,
}

impl AuctionStatus {
    pub fn accepts_bids(self) -> bool {
        matches!(self, Self::Draft | Self::Open)
    }

    pub fn public_status(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Clearing => "clearing",
            Self::Cleared => "cleared",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Posted,
    Admitted,
    Selected,
    Cleared,
    Settled,
    Rebated,
    Rejected,
    Expired,
}

impl BidStatus {
    pub fn active(self) -> bool {
        matches!(self, Self::Posted | Self::Admitted | Self::Selected)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Registered,
    Active,
    Paused,
    Draining,
    Exhausted,
    Frozen,
    Retired,
}

impl SponsorStatus {
    pub fn can_cover(self) -> bool {
        matches!(self, Self::Registered | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateKind {
    Calldata,
    Proof,
    DataAvailability,
    Congestion,
    Sponsor,
    BridgeExitSmoothing,
    Microbatch,
}

impl RebateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Calldata => "calldata",
            Self::Proof => "proof",
            Self::DataAvailability => "data_availability",
            Self::Congestion => "congestion",
            Self::Sponsor => "sponsor",
            Self::BridgeExitSmoothing => "bridge_exit_smoothing",
            Self::Microbatch => "microbatch",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteStatus {
    Reserved,
    Routed,
    Claimed,
    Expired,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeCapStatus {
    Recorded,
    Enforced,
    Breached,
    Refunded,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SummaryStatus {
    Published,
    Superseded,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: u64,
    pub monero_network: String,
    pub l2_network: String,
    pub fee_asset: String,
    pub bridge_asset: String,
    pub epoch_blocks: u64,
    pub auction_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub clearing_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub bridge_smoothing_window_blocks: u64,
    pub microbatch_window_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_decoy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub target_user_fee_bps: u64,
    pub fee_cap_headroom_bps: u64,
    pub min_floor_bps: u64,
    pub target_floor_bps: u64,
    pub max_floor_bps: u64,
    pub min_rebate_bps: u64,
    pub target_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub congestion_rebate_bps: u64,
    pub calldata_rebate_weight_bps: u64,
    pub proof_rebate_weight_bps: u64,
    pub da_rebate_weight_bps: u64,
    pub sponsor_reserve_bps: u64,
    pub sponsor_cover_bps: u64,
    pub bridge_exit_smoothing_bps: u64,
    pub microbatch_discount_bps: u64,
    pub operator_summary_ttl_blocks: u64,
    pub max_auctions: usize,
    pub max_bids: usize,
    pub max_clearings: usize,
    pub max_sponsor_pools: usize,
    pub max_rebate_routes: usize,
    pub max_fee_caps: usize,
    pub max_bridge_windows: usize,
    pub max_microbatches: usize,
    pub max_operator_summaries: usize,
    pub max_privacy_fences: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: DEVNET_CHAIN_ID,
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset: DEVNET_FEE_ASSET.to_string(),
            bridge_asset: DEVNET_BRIDGE_ASSET.to_string(),
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            auction_ttl_blocks: DEFAULT_AUCTION_TTL_BLOCKS,
            bid_ttl_blocks: DEFAULT_BID_TTL_BLOCKS,
            clearing_ttl_blocks: DEFAULT_CLEARING_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            sponsor_ttl_blocks: DEFAULT_SPONSOR_TTL_BLOCKS,
            bridge_smoothing_window_blocks: DEFAULT_BRIDGE_SMOOTHING_WINDOW_BLOCKS,
            microbatch_window_blocks: DEFAULT_MICROBATCH_WINDOW_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_decoy_set_size: DEFAULT_MIN_DECOY_SET_SIZE,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            fee_cap_headroom_bps: DEFAULT_FEE_CAP_HEADROOM_BPS,
            min_floor_bps: DEFAULT_MIN_FLOOR_BPS,
            target_floor_bps: DEFAULT_TARGET_FLOOR_BPS,
            max_floor_bps: DEFAULT_MAX_FLOOR_BPS,
            min_rebate_bps: DEFAULT_MIN_REBATE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            congestion_rebate_bps: DEFAULT_CONGESTION_REBATE_BPS,
            calldata_rebate_weight_bps: DEFAULT_CALLDATA_REBATE_WEIGHT_BPS,
            proof_rebate_weight_bps: DEFAULT_PROOF_REBATE_WEIGHT_BPS,
            da_rebate_weight_bps: DEFAULT_DA_REBATE_WEIGHT_BPS,
            sponsor_reserve_bps: DEFAULT_SPONSOR_RESERVE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            bridge_exit_smoothing_bps: DEFAULT_BRIDGE_EXIT_SMOOTHING_BPS,
            microbatch_discount_bps: DEFAULT_MICROBATCH_DISCOUNT_BPS,
            operator_summary_ttl_blocks: DEFAULT_OPERATOR_SUMMARY_TTL_BLOCKS,
            max_auctions: DEFAULT_MAX_AUCTIONS,
            max_bids: DEFAULT_MAX_BIDS,
            max_clearings: DEFAULT_MAX_CLEARINGS,
            max_sponsor_pools: DEFAULT_MAX_SPONSOR_POOLS,
            max_rebate_routes: DEFAULT_MAX_REBATE_ROUTES,
            max_fee_caps: DEFAULT_MAX_FEE_CAPS,
            max_bridge_windows: DEFAULT_MAX_BRIDGE_WINDOWS,
            max_microbatches: DEFAULT_MAX_MICROBATCHES,
            max_operator_summaries: DEFAULT_MAX_OPERATOR_SUMMARIES,
            max_privacy_fences: DEFAULT_MAX_PRIVACY_FENCES,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "fee_asset": self.fee_asset,
            "bridge_asset": self.bridge_asset,
            "epoch_blocks": self.epoch_blocks,
            "auction_ttl_blocks": self.auction_ttl_blocks,
            "bid_ttl_blocks": self.bid_ttl_blocks,
            "clearing_ttl_blocks": self.clearing_ttl_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "sponsor_ttl_blocks": self.sponsor_ttl_blocks,
            "bridge_smoothing_window_blocks": self.bridge_smoothing_window_blocks,
            "microbatch_window_blocks": self.microbatch_window_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_decoy_set_size": self.min_decoy_set_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_user_fee_bps": self.target_user_fee_bps,
            "fee_cap_headroom_bps": self.fee_cap_headroom_bps,
            "min_floor_bps": self.min_floor_bps,
            "target_floor_bps": self.target_floor_bps,
            "max_floor_bps": self.max_floor_bps,
            "min_rebate_bps": self.min_rebate_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "congestion_rebate_bps": self.congestion_rebate_bps,
            "calldata_rebate_weight_bps": self.calldata_rebate_weight_bps,
            "proof_rebate_weight_bps": self.proof_rebate_weight_bps,
            "da_rebate_weight_bps": self.da_rebate_weight_bps,
            "sponsor_reserve_bps": self.sponsor_reserve_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "bridge_exit_smoothing_bps": self.bridge_exit_smoothing_bps,
            "microbatch_discount_bps": self.microbatch_discount_bps,
            "operator_summary_ttl_blocks": self.operator_summary_ttl_blocks,
            "limits": {
                "max_auctions": self.max_auctions,
                "max_bids": self.max_bids,
                "max_clearings": self.max_clearings,
                "max_sponsor_pools": self.max_sponsor_pools,
                "max_rebate_routes": self.max_rebate_routes,
                "max_fee_caps": self.max_fee_caps,
                "max_bridge_windows": self.max_bridge_windows,
                "max_microbatches": self.max_microbatches,
                "max_operator_summaries": self.max_operator_summaries,
                "max_privacy_fences": self.max_privacy_fences
            }
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub auctions_opened: u64,
    pub bids_posted: u64,
    pub bids_admitted: u64,
    pub bids_selected: u64,
    pub clearings_recorded: u64,
    pub settlements_recorded: u64,
    pub sponsor_pools_registered: u64,
    pub sponsor_credits_reserved: u64,
    pub sponsor_credits_spent: u64,
    pub rebate_routes_recorded: u64,
    pub rebates_routed: u64,
    pub congestion_rebates_routed: u64,
    pub fee_caps_recorded: u64,
    pub fee_cap_breaches: u64,
    pub bridge_windows_recorded: u64,
    pub microbatches_recorded: u64,
    pub operator_summaries_published: u64,
    pub privacy_fences_registered: u64,
    pub events_emitted: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "auctions_opened": self.auctions_opened,
            "bids_posted": self.bids_posted,
            "bids_admitted": self.bids_admitted,
            "bids_selected": self.bids_selected,
            "clearings_recorded": self.clearings_recorded,
            "settlements_recorded": self.settlements_recorded,
            "sponsor_pools_registered": self.sponsor_pools_registered,
            "sponsor_credits_reserved": self.sponsor_credits_reserved,
            "sponsor_credits_spent": self.sponsor_credits_spent,
            "rebate_routes_recorded": self.rebate_routes_recorded,
            "rebates_routed": self.rebates_routed,
            "congestion_rebates_routed": self.congestion_rebates_routed,
            "fee_caps_recorded": self.fee_caps_recorded,
            "fee_cap_breaches": self.fee_cap_breaches,
            "bridge_windows_recorded": self.bridge_windows_recorded,
            "microbatches_recorded": self.microbatches_recorded,
            "operator_summaries_published": self.operator_summaries_published,
            "privacy_fences_registered": self.privacy_fences_registered,
            "events_emitted": self.events_emitted
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub auctions_root: String,
    pub bids_root: String,
    pub clearings_root: String,
    pub sponsor_pools_root: String,
    pub rebate_routes_root: String,
    pub fee_caps_root: String,
    pub bridge_windows_root: String,
    pub microbatches_root: String,
    pub operator_summaries_root: String,
    pub privacy_fences_root: String,
    pub lane_index_root: String,
    pub event_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "auctions_root": self.auctions_root,
            "bids_root": self.bids_root,
            "clearings_root": self.clearings_root,
            "sponsor_pools_root": self.sponsor_pools_root,
            "rebate_routes_root": self.rebate_routes_root,
            "fee_caps_root": self.fee_caps_root,
            "bridge_windows_root": self.bridge_windows_root,
            "microbatches_root": self.microbatches_root,
            "operator_summaries_root": self.operator_summaries_root,
            "privacy_fences_root": self.privacy_fences_root,
            "lane_index_root": self.lane_index_root,
            "event_root": self.event_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpenAuctionRequest {
    pub auction_commitment: String,
    pub lane: FeeLane,
    pub epoch: u64,
    pub target_slots: u64,
    pub floor_bps: u64,
    pub fee_cap_bps: u64,
    pub calldata_bytes: u64,
    pub proof_bytes: u64,
    pub da_bytes: u64,
    pub sponsor_pool_id: String,
    pub encrypted_policy_root: String,
    pub pq_auth_key_commitment: String,
    pub privacy_set_size: u64,
    pub decoy_set_size: u64,
    pub valid_from_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateBidRequest {
    pub auction_id: String,
    pub bidder_commitment: String,
    pub sealed_bid_root: String,
    pub max_fee_bps_commitment: String,
    pub rebate_address_commitment: String,
    pub bid_weight: u64,
    pub requested_slots: u64,
    pub sponsor_hint: String,
    pub pq_auth_proof_root: String,
    pub privacy_set_size: u64,
    pub decoy_set_size: u64,
    pub valid_from_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorPoolRequest {
    pub sponsor_commitment: String,
    pub lane: FeeLane,
    pub available_fee_credits: u64,
    pub max_cover_bps: u64,
    pub min_rebate_bps: u64,
    pub policy_root: String,
    pub pq_auth_key_commitment: String,
    pub privacy_set_size: u64,
    pub valid_from_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClearingRequest {
    pub auction_id: String,
    pub clearing_root: String,
    pub selected_bids_root: String,
    pub rejected_bids_root: String,
    pub clearing_price_bps: u64,
    pub sponsor_paid: u64,
    pub user_paid: u64,
    pub pq_clearing_signature_root: String,
    pub validity_proof_root: String,
    pub operator_commitment: String,
    pub cleared_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RebateRouteRequest {
    pub auction_id: String,
    pub bid_id: String,
    pub kind: RebateKind,
    pub amount: u64,
    pub route_commitment: String,
    pub source_root: String,
    pub claim_nullifier: String,
    pub valid_from_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeCapRequest {
    pub auction_id: String,
    pub bid_id: String,
    pub cap_bps: u64,
    pub charged_bps: u64,
    pub refund_commitment: String,
    pub proof_root: String,
    pub valid_from_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BridgeExitWindowRequest {
    pub lane: FeeLane,
    pub window_label: String,
    pub exit_count: u64,
    pub raw_fee_bps: u64,
    pub smoothed_fee_bps: u64,
    pub smoothing_credit: u64,
    pub liquidity_root: String,
    pub valid_from_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MicrobatchRequest {
    pub auction_id: String,
    pub lane: FeeLane,
    pub microbatch_root: String,
    pub transaction_count: u64,
    pub aggregate_weight: u64,
    pub discount_bps: u64,
    pub operator_commitment: String,
    pub valid_from_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSummaryRequest {
    pub operator_commitment: String,
    pub epoch: u64,
    pub auctions_root: String,
    pub clearing_root: String,
    pub rebates_root: String,
    pub fee_cap_root: String,
    pub bridge_smoothing_root: String,
    pub microbatch_root: String,
    pub median_fee_bps: u64,
    pub p95_fee_bps: u64,
    pub rebate_total: u64,
    pub sponsor_total: u64,
    pub valid_from_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyFenceRequest {
    pub nullifier: String,
    pub scope: String,
    pub commitment_root: String,
    pub valid_from_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuctionRecord {
    pub auction_id: String,
    pub auction_commitment: String,
    pub lane: FeeLane,
    pub epoch: u64,
    pub target_slots: u64,
    pub filled_slots: u64,
    pub floor_bps: u64,
    pub fee_cap_bps: u64,
    pub calldata_bytes: u64,
    pub proof_bytes: u64,
    pub da_bytes: u64,
    pub sponsor_pool_id: String,
    pub encrypted_policy_root: String,
    pub pq_auth_key_commitment: String,
    pub privacy_set_size: u64,
    pub decoy_set_size: u64,
    pub status: AuctionStatus,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
}

impl AuctionRecord {
    pub fn from_request(config: &Config, request: OpenAuctionRequest) -> Self {
        let auction_id = auction_id(
            &request.auction_commitment,
            request.lane,
            request.epoch,
            request.nonce,
        );
        Self {
            auction_id,
            auction_commitment: request.auction_commitment,
            lane: request.lane,
            epoch: request.epoch,
            target_slots: request.target_slots,
            filled_slots: 0,
            floor_bps: request.floor_bps,
            fee_cap_bps: request.fee_cap_bps,
            calldata_bytes: request.calldata_bytes,
            proof_bytes: request.proof_bytes,
            da_bytes: request.da_bytes,
            sponsor_pool_id: request.sponsor_pool_id,
            encrypted_policy_root: request.encrypted_policy_root,
            pq_auth_key_commitment: request.pq_auth_key_commitment,
            privacy_set_size: request.privacy_set_size,
            decoy_set_size: request.decoy_set_size,
            status: AuctionStatus::Open,
            valid_from_height: request.valid_from_height,
            expires_at_height: request
                .valid_from_height
                .saturating_add(config.auction_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "auction_id": self.auction_id,
            "auction_commitment": self.auction_commitment,
            "lane": self.lane.as_str(),
            "epoch": self.epoch,
            "target_slots": self.target_slots,
            "filled_slots": self.filled_slots,
            "floor_bps": self.floor_bps,
            "fee_cap_bps": self.fee_cap_bps,
            "calldata_bytes": self.calldata_bytes,
            "proof_bytes": self.proof_bytes,
            "da_bytes": self.da_bytes,
            "sponsor_pool_id": self.sponsor_pool_id,
            "encrypted_policy_root": self.encrypted_policy_root,
            "pq_auth_key_commitment": self.pq_auth_key_commitment,
            "privacy_set_size": self.privacy_set_size,
            "decoy_set_size": self.decoy_set_size,
            "status": self.status.public_status(),
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BidRecord {
    pub bid_id: String,
    pub auction_id: String,
    pub bidder_commitment: String,
    pub sealed_bid_root: String,
    pub max_fee_bps_commitment: String,
    pub rebate_address_commitment: String,
    pub bid_weight: u64,
    pub requested_slots: u64,
    pub sponsor_hint: String,
    pub pq_auth_proof_root: String,
    pub privacy_set_size: u64,
    pub decoy_set_size: u64,
    pub status: BidStatus,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
}

impl BidRecord {
    pub fn from_request(config: &Config, request: PrivateBidRequest) -> Self {
        let bid_id = bid_id(
            &request.auction_id,
            &request.bidder_commitment,
            &request.sealed_bid_root,
            request.nonce,
        );
        Self {
            bid_id,
            auction_id: request.auction_id,
            bidder_commitment: request.bidder_commitment,
            sealed_bid_root: request.sealed_bid_root,
            max_fee_bps_commitment: request.max_fee_bps_commitment,
            rebate_address_commitment: request.rebate_address_commitment,
            bid_weight: request.bid_weight,
            requested_slots: request.requested_slots,
            sponsor_hint: request.sponsor_hint,
            pq_auth_proof_root: request.pq_auth_proof_root,
            privacy_set_size: request.privacy_set_size,
            decoy_set_size: request.decoy_set_size,
            status: BidStatus::Posted,
            valid_from_height: request.valid_from_height,
            expires_at_height: request
                .valid_from_height
                .saturating_add(config.bid_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "auction_id": self.auction_id,
            "bidder_commitment": self.bidder_commitment,
            "sealed_bid_root": self.sealed_bid_root,
            "max_fee_bps_commitment": self.max_fee_bps_commitment,
            "rebate_address_commitment": self.rebate_address_commitment,
            "bid_weight": self.bid_weight,
            "requested_slots": self.requested_slots,
            "sponsor_hint": self.sponsor_hint,
            "pq_auth_proof_root": self.pq_auth_proof_root,
            "privacy_set_size": self.privacy_set_size,
            "decoy_set_size": self.decoy_set_size,
            "status": format!("{:?}", self.status).to_lowercase(),
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorPoolRecord {
    pub sponsor_pool_id: String,
    pub sponsor_commitment: String,
    pub lane: FeeLane,
    pub available_fee_credits: u64,
    pub reserved_fee_credits: u64,
    pub spent_fee_credits: u64,
    pub max_cover_bps: u64,
    pub min_rebate_bps: u64,
    pub policy_root: String,
    pub pq_auth_key_commitment: String,
    pub privacy_set_size: u64,
    pub status: SponsorStatus,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
}

impl SponsorPoolRecord {
    pub fn from_request(config: &Config, request: SponsorPoolRequest) -> Self {
        let sponsor_pool_id = sponsor_pool_id(
            &request.sponsor_commitment,
            request.lane,
            &request.policy_root,
            request.nonce,
        );
        Self {
            sponsor_pool_id,
            sponsor_commitment: request.sponsor_commitment,
            lane: request.lane,
            available_fee_credits: request.available_fee_credits,
            reserved_fee_credits: 0,
            spent_fee_credits: 0,
            max_cover_bps: request.max_cover_bps,
            min_rebate_bps: request.min_rebate_bps,
            policy_root: request.policy_root,
            pq_auth_key_commitment: request.pq_auth_key_commitment,
            privacy_set_size: request.privacy_set_size,
            status: SponsorStatus::Registered,
            valid_from_height: request.valid_from_height,
            expires_at_height: request
                .valid_from_height
                .saturating_add(config.sponsor_ttl_blocks),
        }
    }

    pub fn free_credits(&self) -> u64 {
        self.available_fee_credits
            .saturating_sub(self.reserved_fee_credits)
            .saturating_sub(self.spent_fee_credits)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_pool_id": self.sponsor_pool_id,
            "sponsor_commitment": self.sponsor_commitment,
            "lane": self.lane.as_str(),
            "available_fee_credits": self.available_fee_credits,
            "reserved_fee_credits": self.reserved_fee_credits,
            "spent_fee_credits": self.spent_fee_credits,
            "max_cover_bps": self.max_cover_bps,
            "min_rebate_bps": self.min_rebate_bps,
            "policy_root": self.policy_root,
            "pq_auth_key_commitment": self.pq_auth_key_commitment,
            "privacy_set_size": self.privacy_set_size,
            "status": format!("{:?}", self.status).to_lowercase(),
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClearingRecord {
    pub clearing_id: String,
    pub auction_id: String,
    pub clearing_root: String,
    pub selected_bids_root: String,
    pub rejected_bids_root: String,
    pub clearing_price_bps: u64,
    pub sponsor_paid: u64,
    pub user_paid: u64,
    pub pq_clearing_signature_root: String,
    pub validity_proof_root: String,
    pub operator_commitment: String,
    pub cleared_at_height: u64,
    pub expires_at_height: u64,
}

impl ClearingRecord {
    pub fn from_request(config: &Config, request: ClearingRequest) -> Self {
        let clearing_id = clearing_id(
            &request.auction_id,
            &request.clearing_root,
            &request.pq_clearing_signature_root,
            request.cleared_at_height,
        );
        Self {
            clearing_id,
            auction_id: request.auction_id,
            clearing_root: request.clearing_root,
            selected_bids_root: request.selected_bids_root,
            rejected_bids_root: request.rejected_bids_root,
            clearing_price_bps: request.clearing_price_bps,
            sponsor_paid: request.sponsor_paid,
            user_paid: request.user_paid,
            pq_clearing_signature_root: request.pq_clearing_signature_root,
            validity_proof_root: request.validity_proof_root,
            operator_commitment: request.operator_commitment,
            cleared_at_height: request.cleared_at_height,
            expires_at_height: request
                .cleared_at_height
                .saturating_add(config.clearing_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "clearing_id": self.clearing_id,
            "auction_id": self.auction_id,
            "clearing_root": self.clearing_root,
            "selected_bids_root": self.selected_bids_root,
            "rejected_bids_root": self.rejected_bids_root,
            "clearing_price_bps": self.clearing_price_bps,
            "sponsor_paid": self.sponsor_paid,
            "user_paid": self.user_paid,
            "pq_clearing_signature_root": self.pq_clearing_signature_root,
            "validity_proof_root": self.validity_proof_root,
            "operator_commitment": self.operator_commitment,
            "cleared_at_height": self.cleared_at_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RebateRouteRecord {
    pub route_id: String,
    pub auction_id: String,
    pub bid_id: String,
    pub kind: RebateKind,
    pub amount: u64,
    pub route_commitment: String,
    pub source_root: String,
    pub claim_nullifier: String,
    pub status: RouteStatus,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
}

impl RebateRouteRecord {
    pub fn from_request(config: &Config, request: RebateRouteRequest) -> Self {
        let route_id = rebate_route_id(
            &request.auction_id,
            &request.bid_id,
            request.kind,
            &request.claim_nullifier,
            request.nonce,
        );
        Self {
            route_id,
            auction_id: request.auction_id,
            bid_id: request.bid_id,
            kind: request.kind,
            amount: request.amount,
            route_commitment: request.route_commitment,
            source_root: request.source_root,
            claim_nullifier: request.claim_nullifier,
            status: RouteStatus::Reserved,
            valid_from_height: request.valid_from_height,
            expires_at_height: request
                .valid_from_height
                .saturating_add(config.rebate_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "route_id": self.route_id,
            "auction_id": self.auction_id,
            "bid_id": self.bid_id,
            "kind": self.kind.as_str(),
            "amount": self.amount,
            "route_commitment": self.route_commitment,
            "source_root": self.source_root,
            "claim_nullifier": self.claim_nullifier,
            "status": format!("{:?}", self.status).to_lowercase(),
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeCapRecord {
    pub fee_cap_id: String,
    pub auction_id: String,
    pub bid_id: String,
    pub cap_bps: u64,
    pub charged_bps: u64,
    pub refund_amount: u64,
    pub refund_commitment: String,
    pub proof_root: String,
    pub status: FeeCapStatus,
    pub valid_from_height: u64,
}

impl FeeCapRecord {
    pub fn from_request(request: FeeCapRequest) -> Self {
        let refund_amount = request.charged_bps.saturating_sub(request.cap_bps);
        let fee_cap_id = fee_cap_id(
            &request.auction_id,
            &request.bid_id,
            request.cap_bps,
            request.nonce,
        );
        Self {
            fee_cap_id,
            auction_id: request.auction_id,
            bid_id: request.bid_id,
            cap_bps: request.cap_bps,
            charged_bps: request.charged_bps,
            refund_amount,
            refund_commitment: request.refund_commitment,
            proof_root: request.proof_root,
            status: if refund_amount == 0 {
                FeeCapStatus::Enforced
            } else {
                FeeCapStatus::Breached
            },
            valid_from_height: request.valid_from_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fee_cap_id": self.fee_cap_id,
            "auction_id": self.auction_id,
            "bid_id": self.bid_id,
            "cap_bps": self.cap_bps,
            "charged_bps": self.charged_bps,
            "refund_amount": self.refund_amount,
            "refund_commitment": self.refund_commitment,
            "proof_root": self.proof_root,
            "status": format!("{:?}", self.status).to_lowercase(),
            "valid_from_height": self.valid_from_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BridgeExitWindowRecord {
    pub window_id: String,
    pub lane: FeeLane,
    pub window_label: String,
    pub exit_count: u64,
    pub raw_fee_bps: u64,
    pub smoothed_fee_bps: u64,
    pub smoothing_credit: u64,
    pub liquidity_root: String,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
}

impl BridgeExitWindowRecord {
    pub fn from_request(config: &Config, request: BridgeExitWindowRequest) -> Self {
        let window_id = bridge_window_id(
            request.lane,
            &request.window_label,
            &request.liquidity_root,
            request.nonce,
        );
        Self {
            window_id,
            lane: request.lane,
            window_label: request.window_label,
            exit_count: request.exit_count,
            raw_fee_bps: request.raw_fee_bps,
            smoothed_fee_bps: request.smoothed_fee_bps,
            smoothing_credit: request.smoothing_credit,
            liquidity_root: request.liquidity_root,
            valid_from_height: request.valid_from_height,
            expires_at_height: request
                .valid_from_height
                .saturating_add(config.bridge_smoothing_window_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "lane": self.lane.as_str(),
            "window_label": self.window_label,
            "exit_count": self.exit_count,
            "raw_fee_bps": self.raw_fee_bps,
            "smoothed_fee_bps": self.smoothed_fee_bps,
            "smoothing_credit": self.smoothing_credit,
            "liquidity_root": self.liquidity_root,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MicrobatchRecord {
    pub microbatch_id: String,
    pub auction_id: String,
    pub lane: FeeLane,
    pub microbatch_root: String,
    pub transaction_count: u64,
    pub aggregate_weight: u64,
    pub discount_bps: u64,
    pub discount_amount: u64,
    pub operator_commitment: String,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
}

impl MicrobatchRecord {
    pub fn from_request(config: &Config, request: MicrobatchRequest) -> Self {
        let microbatch_id = microbatch_id(
            &request.auction_id,
            request.lane,
            &request.microbatch_root,
            request.nonce,
        );
        let discount_amount = request
            .aggregate_weight
            .saturating_mul(request.discount_bps)
            .saturating_div(MAX_BPS);
        Self {
            microbatch_id,
            auction_id: request.auction_id,
            lane: request.lane,
            microbatch_root: request.microbatch_root,
            transaction_count: request.transaction_count,
            aggregate_weight: request.aggregate_weight,
            discount_bps: request.discount_bps,
            discount_amount,
            operator_commitment: request.operator_commitment,
            valid_from_height: request.valid_from_height,
            expires_at_height: request
                .valid_from_height
                .saturating_add(config.microbatch_window_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "microbatch_id": self.microbatch_id,
            "auction_id": self.auction_id,
            "lane": self.lane.as_str(),
            "microbatch_root": self.microbatch_root,
            "transaction_count": self.transaction_count,
            "aggregate_weight": self.aggregate_weight,
            "discount_bps": self.discount_bps,
            "discount_amount": self.discount_amount,
            "operator_commitment": self.operator_commitment,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSummaryRecord {
    pub summary_id: String,
    pub operator_commitment: String,
    pub epoch: u64,
    pub auctions_root: String,
    pub clearing_root: String,
    pub rebates_root: String,
    pub fee_cap_root: String,
    pub bridge_smoothing_root: String,
    pub microbatch_root: String,
    pub median_fee_bps: u64,
    pub p95_fee_bps: u64,
    pub rebate_total: u64,
    pub sponsor_total: u64,
    pub status: SummaryStatus,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
}

impl OperatorSummaryRecord {
    pub fn from_request(config: &Config, request: OperatorSummaryRequest) -> Self {
        let summary_id = operator_summary_id(
            &request.operator_commitment,
            request.epoch,
            &request.clearing_root,
            request.nonce,
        );
        Self {
            summary_id,
            operator_commitment: request.operator_commitment,
            epoch: request.epoch,
            auctions_root: request.auctions_root,
            clearing_root: request.clearing_root,
            rebates_root: request.rebates_root,
            fee_cap_root: request.fee_cap_root,
            bridge_smoothing_root: request.bridge_smoothing_root,
            microbatch_root: request.microbatch_root,
            median_fee_bps: request.median_fee_bps,
            p95_fee_bps: request.p95_fee_bps,
            rebate_total: request.rebate_total,
            sponsor_total: request.sponsor_total,
            status: SummaryStatus::Published,
            valid_from_height: request.valid_from_height,
            expires_at_height: request
                .valid_from_height
                .saturating_add(config.operator_summary_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "operator_commitment": self.operator_commitment,
            "epoch": self.epoch,
            "auctions_root": self.auctions_root,
            "clearing_root": self.clearing_root,
            "rebates_root": self.rebates_root,
            "fee_cap_root": self.fee_cap_root,
            "bridge_smoothing_root": self.bridge_smoothing_root,
            "microbatch_root": self.microbatch_root,
            "median_fee_bps": self.median_fee_bps,
            "p95_fee_bps": self.p95_fee_bps,
            "rebate_total": self.rebate_total,
            "sponsor_total": self.sponsor_total,
            "status": format!("{:?}", self.status).to_lowercase(),
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyFenceRecord {
    pub fence_id: String,
    pub nullifier: String,
    pub scope: String,
    pub commitment_root: String,
    pub view_tag: String,
    pub valid_from_height: u64,
}

impl PrivacyFenceRecord {
    pub fn from_request(request: PrivacyFenceRequest) -> Self {
        let fence_id = privacy_fence_id(
            &request.nullifier,
            &request.scope,
            &request.commitment_root,
            request.nonce,
        );
        let view_tag = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-FLOOR-AUCTION:PRIVACY-FENCE-VIEW-TAG",
            &[HashPart::Str(&fence_id), HashPart::Str(&request.scope)],
            16,
        );
        Self {
            fence_id,
            nullifier: request.nullifier,
            scope: request.scope,
            commitment_root: request.commitment_root,
            view_tag,
            valid_from_height: request.valid_from_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "nullifier": self.nullifier,
            "scope": self.scope,
            "commitment_root": self.commitment_root,
            "view_tag": self.view_tag,
            "valid_from_height": self.valid_from_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EventRecord {
    pub event_id: String,
    pub kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub sequence: u64,
}

impl EventRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "sequence": self.sequence
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub auctions: BTreeMap<String, AuctionRecord>,
    pub bids: BTreeMap<String, BidRecord>,
    pub clearings: BTreeMap<String, ClearingRecord>,
    pub sponsor_pools: BTreeMap<String, SponsorPoolRecord>,
    pub rebate_routes: BTreeMap<String, RebateRouteRecord>,
    pub fee_caps: BTreeMap<String, FeeCapRecord>,
    pub bridge_windows: BTreeMap<String, BridgeExitWindowRecord>,
    pub microbatches: BTreeMap<String, MicrobatchRecord>,
    pub operator_summaries: BTreeMap<String, OperatorSummaryRecord>,
    pub privacy_fences: BTreeMap<String, PrivacyFenceRecord>,
    pub lane_index: BTreeMap<FeeLane, BTreeSet<String>>,
    pub bid_index: BTreeMap<String, BTreeSet<String>>,
    pub events: Vec<EventRecord>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            auctions: BTreeMap::new(),
            bids: BTreeMap::new(),
            clearings: BTreeMap::new(),
            sponsor_pools: BTreeMap::new(),
            rebate_routes: BTreeMap::new(),
            fee_caps: BTreeMap::new(),
            bridge_windows: BTreeMap::new(),
            microbatches: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            lane_index: BTreeMap::new(),
            bid_index: BTreeMap::new(),
            events: Vec::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet())
    }

    pub fn open_auction(&mut self, request: OpenAuctionRequest) -> Result<String> {
        ensure!(
            self.auctions.len() < self.config.max_auctions,
            "auction limit reached"
        );
        ensure!(request.target_slots > 0, "target slots must be positive");
        ensure!(
            request.floor_bps >= self.config.min_floor_bps,
            "floor below minimum"
        );
        ensure!(
            request.floor_bps <= self.config.max_floor_bps,
            "floor above maximum"
        );
        ensure!(
            request.fee_cap_bps <= self.config.max_user_fee_bps,
            "fee cap above maximum"
        );
        ensure!(
            request.fee_cap_bps >= request.floor_bps,
            "fee cap below floor"
        );
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set below minimum"
        );
        ensure!(
            request.decoy_set_size >= self.config.min_decoy_set_size,
            "decoy set below minimum"
        );
        let record = AuctionRecord::from_request(&self.config, request);
        let auction_id = record.auction_id.clone();
        ensure!(
            !self.auctions.contains_key(&auction_id),
            "auction already exists"
        );
        self.lane_index
            .entry(record.lane)
            .or_default()
            .insert(auction_id.clone());
        self.auctions.insert(auction_id.clone(), record);
        self.counters.auctions_opened = self.counters.auctions_opened.saturating_add(1);
        self.emit_event("auction_opened", &auction_id);
        self.refresh_roots();
        Ok(auction_id)
    }

    pub fn post_private_bid(&mut self, request: PrivateBidRequest) -> Result<String> {
        ensure!(self.bids.len() < self.config.max_bids, "bid limit reached");
        ensure!(request.bid_weight > 0, "bid weight must be positive");
        ensure!(
            request.requested_slots > 0,
            "requested slots must be positive"
        );
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set below minimum"
        );
        ensure!(
            request.decoy_set_size >= self.config.min_decoy_set_size,
            "decoy set below minimum"
        );
        let auction = self
            .auctions
            .get(&request.auction_id)
            .ok_or_else(|| format!("missing auction {}", request.auction_id))?;
        ensure!(
            auction.status.accepts_bids(),
            "auction does not accept bids"
        );
        ensure!(
            request.requested_slots <= auction.target_slots.saturating_sub(auction.filled_slots),
            "requested slots exceed remaining auction capacity"
        );
        let record = BidRecord::from_request(&self.config, request);
        let bid_id = record.bid_id.clone();
        ensure!(!self.bids.contains_key(&bid_id), "bid already exists");
        self.bid_index
            .entry(record.auction_id.clone())
            .or_default()
            .insert(bid_id.clone());
        self.bids.insert(bid_id.clone(), record);
        self.counters.bids_posted = self.counters.bids_posted.saturating_add(1);
        self.emit_event("private_bid_posted", &bid_id);
        self.refresh_roots();
        Ok(bid_id)
    }

    pub fn admit_bid(&mut self, bid_id: &str) -> Result<()> {
        let bid = self
            .bids
            .get_mut(bid_id)
            .ok_or_else(|| format!("missing bid {bid_id}"))?;
        ensure!(bid.status == BidStatus::Posted, "bid is not posted");
        bid.status = BidStatus::Admitted;
        self.counters.bids_admitted = self.counters.bids_admitted.saturating_add(1);
        self.emit_event("bid_admitted", bid_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn register_sponsor_pool(&mut self, request: SponsorPoolRequest) -> Result<String> {
        ensure!(
            self.sponsor_pools.len() < self.config.max_sponsor_pools,
            "sponsor pool limit reached"
        );
        ensure!(
            request.available_fee_credits > 0,
            "sponsor credits must be positive"
        );
        ensure!(
            request.max_cover_bps <= self.config.sponsor_cover_bps,
            "sponsor cover too high"
        );
        ensure!(
            request.min_rebate_bps >= self.config.min_rebate_bps,
            "rebate below minimum"
        );
        ensure!(
            request.min_rebate_bps <= self.config.max_rebate_bps,
            "rebate above maximum"
        );
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set below minimum"
        );
        let record = SponsorPoolRecord::from_request(&self.config, request);
        let sponsor_pool_id = record.sponsor_pool_id.clone();
        ensure!(
            !self.sponsor_pools.contains_key(&sponsor_pool_id),
            "sponsor pool already exists"
        );
        self.sponsor_pools.insert(sponsor_pool_id.clone(), record);
        self.counters.sponsor_pools_registered =
            self.counters.sponsor_pools_registered.saturating_add(1);
        self.emit_event("sponsor_pool_registered", &sponsor_pool_id);
        self.refresh_roots();
        Ok(sponsor_pool_id)
    }

    pub fn record_clearing(&mut self, request: ClearingRequest) -> Result<String> {
        ensure!(
            self.clearings.len() < self.config.max_clearings,
            "clearing limit reached"
        );
        let auction = self
            .auctions
            .get_mut(&request.auction_id)
            .ok_or_else(|| format!("missing auction {}", request.auction_id))?;
        ensure!(
            request.clearing_price_bps >= auction.floor_bps,
            "clearing below floor"
        );
        ensure!(
            request.clearing_price_bps <= auction.fee_cap_bps,
            "clearing above cap"
        );
        ensure!(
            request.clearing_price_bps <= self.config.max_user_fee_bps,
            "clearing above global user fee cap"
        );
        let record = ClearingRecord::from_request(&self.config, request);
        let clearing_id = record.clearing_id.clone();
        ensure!(
            !self.clearings.contains_key(&clearing_id),
            "clearing already exists"
        );
        auction.status = AuctionStatus::Cleared;
        self.clearings.insert(clearing_id.clone(), record);
        self.counters.clearings_recorded = self.counters.clearings_recorded.saturating_add(1);
        self.emit_event("auction_cleared", &clearing_id);
        self.refresh_roots();
        Ok(clearing_id)
    }

    pub fn select_bid(&mut self, bid_id: &str) -> Result<()> {
        let bid = self
            .bids
            .get_mut(bid_id)
            .ok_or_else(|| format!("missing bid {bid_id}"))?;
        ensure!(bid.status.active(), "bid is not active");
        let auction = self
            .auctions
            .get_mut(&bid.auction_id)
            .ok_or_else(|| format!("missing auction {}", bid.auction_id))?;
        ensure!(
            bid.requested_slots <= auction.target_slots.saturating_sub(auction.filled_slots),
            "bid exceeds remaining slots"
        );
        auction.filled_slots = auction.filled_slots.saturating_add(bid.requested_slots);
        bid.status = BidStatus::Selected;
        self.counters.bids_selected = self.counters.bids_selected.saturating_add(1);
        self.emit_event("bid_selected", bid_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn reserve_sponsor_liquidity(&mut self, sponsor_pool_id: &str, amount: u64) -> Result<()> {
        ensure!(amount > 0, "reserve amount must be positive");
        let pool = self
            .sponsor_pools
            .get_mut(sponsor_pool_id)
            .ok_or_else(|| format!("missing sponsor pool {sponsor_pool_id}"))?;
        ensure!(pool.status.can_cover(), "sponsor pool cannot cover");
        ensure!(
            pool.free_credits() >= amount,
            "insufficient free sponsor credits"
        );
        pool.reserved_fee_credits = pool.reserved_fee_credits.saturating_add(amount);
        pool.status = SponsorStatus::Active;
        self.counters.sponsor_credits_reserved = self
            .counters
            .sponsor_credits_reserved
            .saturating_add(amount);
        self.emit_event("sponsor_liquidity_reserved", sponsor_pool_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn spend_sponsor_liquidity(&mut self, sponsor_pool_id: &str, amount: u64) -> Result<()> {
        ensure!(amount > 0, "spend amount must be positive");
        let pool = self
            .sponsor_pools
            .get_mut(sponsor_pool_id)
            .ok_or_else(|| format!("missing sponsor pool {sponsor_pool_id}"))?;
        ensure!(
            pool.reserved_fee_credits >= amount,
            "insufficient reserved sponsor credits"
        );
        pool.reserved_fee_credits = pool.reserved_fee_credits.saturating_sub(amount);
        pool.spent_fee_credits = pool.spent_fee_credits.saturating_add(amount);
        if pool.free_credits() == 0 {
            pool.status = SponsorStatus::Exhausted;
        }
        self.counters.sponsor_credits_spent =
            self.counters.sponsor_credits_spent.saturating_add(amount);
        self.emit_event("sponsor_liquidity_spent", sponsor_pool_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn record_rebate_route(&mut self, request: RebateRouteRequest) -> Result<String> {
        ensure!(
            self.rebate_routes.len() < self.config.max_rebate_routes,
            "rebate route limit reached"
        );
        ensure!(request.amount > 0, "rebate amount must be positive");
        ensure!(
            self.auctions.contains_key(&request.auction_id),
            "missing auction"
        );
        ensure!(self.bids.contains_key(&request.bid_id), "missing bid");
        let record = RebateRouteRecord::from_request(&self.config, request);
        let route_id = record.route_id.clone();
        ensure!(
            !self.rebate_routes.contains_key(&route_id),
            "rebate route already exists"
        );
        let is_congestion = record.kind == RebateKind::Congestion;
        self.rebate_routes.insert(route_id.clone(), record);
        self.counters.rebate_routes_recorded =
            self.counters.rebate_routes_recorded.saturating_add(1);
        if is_congestion {
            self.counters.congestion_rebates_routed =
                self.counters.congestion_rebates_routed.saturating_add(1);
        }
        self.emit_event("rebate_route_recorded", &route_id);
        self.refresh_roots();
        Ok(route_id)
    }

    pub fn claim_rebate_route(&mut self, route_id: &str) -> Result<()> {
        let route = self
            .rebate_routes
            .get_mut(route_id)
            .ok_or_else(|| format!("missing rebate route {route_id}"))?;
        ensure!(
            route.status == RouteStatus::Reserved,
            "rebate route is not reserved"
        );
        route.status = RouteStatus::Claimed;
        self.counters.rebates_routed = self.counters.rebates_routed.saturating_add(route.amount);
        self.emit_event("rebate_route_claimed", route_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn record_fee_cap(&mut self, request: FeeCapRequest) -> Result<String> {
        ensure!(
            self.fee_caps.len() < self.config.max_fee_caps,
            "fee cap limit reached"
        );
        ensure!(
            request.cap_bps <= self.config.max_user_fee_bps,
            "cap above maximum"
        );
        ensure!(
            request.charged_bps
                <= request
                    .cap_bps
                    .saturating_add(self.config.fee_cap_headroom_bps),
            "charged fee exceeds cap headroom"
        );
        let record = FeeCapRecord::from_request(request);
        let fee_cap_id = record.fee_cap_id.clone();
        ensure!(
            !self.fee_caps.contains_key(&fee_cap_id),
            "fee cap already exists"
        );
        if record.status == FeeCapStatus::Breached {
            self.counters.fee_cap_breaches = self.counters.fee_cap_breaches.saturating_add(1);
        }
        self.fee_caps.insert(fee_cap_id.clone(), record);
        self.counters.fee_caps_recorded = self.counters.fee_caps_recorded.saturating_add(1);
        self.emit_event("fee_cap_recorded", &fee_cap_id);
        self.refresh_roots();
        Ok(fee_cap_id)
    }

    pub fn record_bridge_exit_window(
        &mut self,
        request: BridgeExitWindowRequest,
    ) -> Result<String> {
        ensure!(
            self.bridge_windows.len() < self.config.max_bridge_windows,
            "bridge window limit reached"
        );
        ensure!(
            matches!(request.lane, FeeLane::BridgeExit | FeeLane::FastBridgeExit),
            "bridge smoothing only applies to bridge exit lanes"
        );
        ensure!(
            request.smoothed_fee_bps <= request.raw_fee_bps,
            "smoothing increased fee"
        );
        ensure!(
            request.raw_fee_bps.saturating_sub(request.smoothed_fee_bps)
                <= self.config.bridge_exit_smoothing_bps,
            "smoothing exceeds configured bound"
        );
        let record = BridgeExitWindowRecord::from_request(&self.config, request);
        let window_id = record.window_id.clone();
        ensure!(
            !self.bridge_windows.contains_key(&window_id),
            "bridge window already exists"
        );
        self.bridge_windows.insert(window_id.clone(), record);
        self.counters.bridge_windows_recorded =
            self.counters.bridge_windows_recorded.saturating_add(1);
        self.emit_event("bridge_exit_window_recorded", &window_id);
        self.refresh_roots();
        Ok(window_id)
    }

    pub fn record_microbatch(&mut self, request: MicrobatchRequest) -> Result<String> {
        ensure!(
            self.microbatches.len() < self.config.max_microbatches,
            "microbatch limit reached"
        );
        ensure!(
            request.transaction_count > 1,
            "microbatch needs at least two transactions"
        );
        ensure!(
            request.discount_bps <= self.config.microbatch_discount_bps,
            "microbatch discount too high"
        );
        ensure!(
            self.auctions.contains_key(&request.auction_id),
            "missing auction"
        );
        let record = MicrobatchRecord::from_request(&self.config, request);
        let microbatch_id = record.microbatch_id.clone();
        ensure!(
            !self.microbatches.contains_key(&microbatch_id),
            "microbatch already exists"
        );
        self.microbatches.insert(microbatch_id.clone(), record);
        self.counters.microbatches_recorded = self.counters.microbatches_recorded.saturating_add(1);
        self.emit_event("microbatch_recorded", &microbatch_id);
        self.refresh_roots();
        Ok(microbatch_id)
    }

    pub fn publish_operator_summary(&mut self, request: OperatorSummaryRequest) -> Result<String> {
        ensure!(
            self.operator_summaries.len() < self.config.max_operator_summaries,
            "operator summary limit reached"
        );
        ensure!(
            request.median_fee_bps <= self.config.max_user_fee_bps,
            "median fee too high"
        );
        ensure!(
            request.p95_fee_bps <= self.config.max_user_fee_bps,
            "p95 fee too high"
        );
        let record = OperatorSummaryRecord::from_request(&self.config, request);
        let summary_id = record.summary_id.clone();
        ensure!(
            !self.operator_summaries.contains_key(&summary_id),
            "operator summary already exists"
        );
        self.operator_summaries.insert(summary_id.clone(), record);
        self.counters.operator_summaries_published =
            self.counters.operator_summaries_published.saturating_add(1);
        self.emit_event("operator_summary_published", &summary_id);
        self.refresh_roots();
        Ok(summary_id)
    }

    pub fn register_privacy_fence(&mut self, request: PrivacyFenceRequest) -> Result<String> {
        ensure!(
            self.privacy_fences.len() < self.config.max_privacy_fences,
            "privacy fence limit reached"
        );
        let record = PrivacyFenceRecord::from_request(request);
        let fence_id = record.fence_id.clone();
        ensure!(
            !self.privacy_fences.contains_key(&fence_id),
            "privacy fence already exists"
        );
        self.privacy_fences.insert(fence_id.clone(), record);
        self.counters.privacy_fences_registered =
            self.counters.privacy_fences_registered.saturating_add(1);
        self.emit_event("privacy_fence_registered", &fence_id);
        self.refresh_roots();
        Ok(fence_id)
    }

    pub fn settle_auction(&mut self, auction_id: &str) -> Result<()> {
        let auction = self
            .auctions
            .get_mut(auction_id)
            .ok_or_else(|| format!("missing auction {auction_id}"))?;
        ensure!(
            matches!(
                auction.status,
                AuctionStatus::Cleared | AuctionStatus::Rebated
            ),
            "auction is not clearable for settlement"
        );
        auction.status = AuctionStatus::Settled;
        self.counters.settlements_recorded = self.counters.settlements_recorded.saturating_add(1);
        self.emit_event("auction_settled", auction_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn route_standard_rebates(
        &mut self,
        auction_id: &str,
        bid_id: &str,
        base_amount: u64,
    ) -> Result<Vec<String>> {
        ensure!(base_amount > 0, "base rebate amount must be positive");
        let auction = self
            .auctions
            .get(auction_id)
            .ok_or_else(|| format!("missing auction {auction_id}"))?;
        ensure!(self.bids.contains_key(bid_id), "missing bid");
        let total_weight = self
            .config
            .calldata_rebate_weight_bps
            .saturating_add(self.config.proof_rebate_weight_bps)
            .saturating_add(self.config.da_rebate_weight_bps);
        ensure!(total_weight > 0, "rebate weights must be positive");
        let calldata_amount = base_amount
            .saturating_mul(self.config.calldata_rebate_weight_bps)
            .saturating_div(total_weight);
        let proof_amount = base_amount
            .saturating_mul(self.config.proof_rebate_weight_bps)
            .saturating_div(total_weight);
        let da_amount = base_amount
            .saturating_sub(calldata_amount)
            .saturating_sub(proof_amount);
        let source_root = record_root(
            "REBATE-STANDARD-SOURCE",
            &json!({
                "auction_id": auction_id,
                "bid_id": bid_id,
                "calldata_bytes": auction.calldata_bytes,
                "proof_bytes": auction.proof_bytes,
                "da_bytes": auction.da_bytes,
                "scheme": REBATE_ROUTING_SCHEME
            }),
        );
        let specs = [
            (RebateKind::Calldata, calldata_amount),
            (RebateKind::Proof, proof_amount),
            (RebateKind::DataAvailability, da_amount),
        ];
        let mut route_ids = Vec::new();
        for (index, (kind, amount)) in specs.iter().enumerate() {
            if *amount > 0 {
                let request = RebateRouteRequest {
                    auction_id: auction_id.to_string(),
                    bid_id: bid_id.to_string(),
                    kind: *kind,
                    amount: *amount,
                    route_commitment: domain_hash(
                        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-FLOOR-AUCTION:REBATE-ROUTE-COMMITMENT",
                        &[HashPart::Str(auction_id), HashPart::Str(bid_id), HashPart::U64(index as u64)],
                        32,
                    ),
                    source_root: source_root.clone(),
                    claim_nullifier: domain_hash(
                        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-FLOOR-AUCTION:REBATE-NULLIFIER",
                        &[HashPart::Str(auction_id), HashPart::Str(bid_id), HashPart::Str(kind.as_str())],
                        32,
                    ),
                    valid_from_height: DEVNET_HEIGHT,
                    nonce: self.counters.rebate_routes_recorded.saturating_add(index as u64),
                };
                route_ids.push(self.record_rebate_route(request)?);
            }
        }
        Ok(route_ids)
    }

    pub fn congestion_rebate_amount(
        &self,
        observed_fee_bps: u64,
        floor_bps: u64,
        weight: u64,
    ) -> u64 {
        if observed_fee_bps <= floor_bps || weight == 0 {
            return 0;
        }
        observed_fee_bps
            .saturating_sub(floor_bps)
            .saturating_mul(weight)
            .saturating_mul(self.config.congestion_rebate_bps)
            .saturating_div(MAX_BPS)
    }

    pub fn recommended_floor_bps(&self, lane: FeeLane, utilization_bps: u64) -> u64 {
        let utilization_bps = utilization_bps.min(MAX_BPS);
        let target = lane.default_floor_bps(&self.config);
        let congestion_lift = self
            .config
            .max_floor_bps
            .saturating_sub(target)
            .saturating_mul(utilization_bps)
            .saturating_div(MAX_BPS);
        target
            .saturating_add(congestion_lift)
            .max(self.config.min_floor_bps)
            .min(self.config.max_floor_bps)
    }

    pub fn capped_user_fee_bps(&self, requested_bps: u64, lane: FeeLane) -> u64 {
        requested_bps.min(self.config.max_user_fee_bps).max(
            lane.default_floor_bps(&self.config)
                .min(self.config.max_user_fee_bps),
        )
    }

    pub fn bridge_smoothed_fee_bps(&self, raw_fee_bps: u64, recent_average_bps: u64) -> u64 {
        let allowed_drop = self.config.bridge_exit_smoothing_bps.min(raw_fee_bps);
        let floor = raw_fee_bps.saturating_sub(allowed_drop);
        recent_average_bps.min(raw_fee_bps).max(floor)
    }

    pub fn microbatch_discount_amount(&self, aggregate_weight: u64, transaction_count: u64) -> u64 {
        if transaction_count <= 1 || aggregate_weight == 0 {
            return 0;
        }
        let density_bps = transaction_count
            .min(64)
            .saturating_mul(MAX_BPS)
            .saturating_div(64);
        aggregate_weight
            .saturating_mul(self.config.microbatch_discount_bps)
            .saturating_mul(density_bps)
            .saturating_div(MAX_BPS)
            .saturating_div(MAX_BPS)
    }

    pub fn refresh_roots(&mut self) {
        self.roots.auctions_root = map_root("AUCTIONS", &self.auctions);
        self.roots.bids_root = map_root("BIDS", &self.bids);
        self.roots.clearings_root = map_root("CLEARINGS", &self.clearings);
        self.roots.sponsor_pools_root = map_root("SPONSOR-POOLS", &self.sponsor_pools);
        self.roots.rebate_routes_root = map_root("REBATE-ROUTES", &self.rebate_routes);
        self.roots.fee_caps_root = map_root("FEE-CAPS", &self.fee_caps);
        self.roots.bridge_windows_root = map_root("BRIDGE-WINDOWS", &self.bridge_windows);
        self.roots.microbatches_root = map_root("MICROBATCHES", &self.microbatches);
        self.roots.operator_summaries_root =
            map_root("OPERATOR-SUMMARIES", &self.operator_summaries);
        self.roots.privacy_fences_root = map_root("PRIVACY-FENCES", &self.privacy_fences);
        self.roots.lane_index_root = lane_index_root(&self.lane_index);
        self.roots.event_root = list_root(
            "EVENTS",
            &self
                .events
                .iter()
                .map(EventRecord::public_record)
                .collect::<Vec<_>>(),
        );
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "auction_count": self.auctions.len(),
            "bid_count": self.bids.len(),
            "clearing_count": self.clearings.len(),
            "sponsor_pool_count": self.sponsor_pools.len(),
            "rebate_route_count": self.rebate_routes.len(),
            "fee_cap_count": self.fee_caps.len(),
            "bridge_window_count": self.bridge_windows.len(),
            "microbatch_count": self.microbatches.len(),
            "operator_summary_count": self.operator_summaries.len(),
            "privacy_fence_count": self.privacy_fences.len(),
            "operator_public_summaries": self.operator_summaries
                .values()
                .map(OperatorSummaryRecord::public_record)
                .collect::<Vec<_>>()
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        record_root("STATE", &self.public_record_without_state_root())
    }

    fn emit_event(&mut self, kind: &str, subject_id: &str) {
        let sequence = self.counters.events_emitted;
        let payload_root = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-FLOOR-AUCTION:EVENT-PAYLOAD",
            &[
                HashPart::Str(kind),
                HashPart::Str(subject_id),
                HashPart::U64(sequence),
            ],
            32,
        );
        let event_id = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-FLOOR-AUCTION:EVENT-ID",
            &[
                HashPart::Str(kind),
                HashPart::Str(subject_id),
                HashPart::U64(sequence),
            ],
            32,
        );
        self.events.push(EventRecord {
            event_id,
            kind: kind.to_string(),
            subject_id: subject_id.to_string(),
            payload_root,
            sequence,
        });
        self.counters.events_emitted = self.counters.events_emitted.saturating_add(1);
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let mut state = State::devnet();
    let sponsor_id = state
        .register_sponsor_pool(SponsorPoolRequest {
            sponsor_commitment: "demo-sponsor-commitment".to_string(),
            lane: FeeLane::PrivateTransfer,
            available_fee_credits: 5_000_000,
            max_cover_bps: 2_000,
            min_rebate_bps: DEFAULT_MIN_REBATE_BPS,
            policy_root: "demo-sponsor-policy-root".to_string(),
            pq_auth_key_commitment: "demo-sponsor-pq-auth-key".to_string(),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            valid_from_height: DEVNET_HEIGHT,
            nonce: 1,
        })
        .ok_or_error_string();
    let auction_id = state
        .open_auction(OpenAuctionRequest {
            auction_commitment: "demo-auction-commitment".to_string(),
            lane: FeeLane::PrivateTransfer,
            epoch: DEVNET_EPOCH,
            target_slots: 64,
            floor_bps: DEFAULT_TARGET_FLOOR_BPS,
            fee_cap_bps: DEFAULT_MAX_USER_FEE_BPS,
            calldata_bytes: 48_000,
            proof_bytes: 96_000,
            da_bytes: 128_000,
            sponsor_pool_id: sponsor_id.clone(),
            encrypted_policy_root: "demo-encrypted-policy-root".to_string(),
            pq_auth_key_commitment: "demo-auction-pq-auth-key".to_string(),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            decoy_set_size: DEFAULT_MIN_DECOY_SET_SIZE,
            valid_from_height: DEVNET_HEIGHT,
            nonce: 2,
        })
        .ok_or_error_string();
    let bid_id = state
        .post_private_bid(PrivateBidRequest {
            auction_id: auction_id.clone(),
            bidder_commitment: "demo-bidder-commitment".to_string(),
            sealed_bid_root: "demo-sealed-bid-root".to_string(),
            max_fee_bps_commitment: "demo-max-fee-commitment".to_string(),
            rebate_address_commitment: "demo-rebate-address-commitment".to_string(),
            bid_weight: 250_000,
            requested_slots: 8,
            sponsor_hint: sponsor_id.clone(),
            pq_auth_proof_root: "demo-pq-auth-proof-root".to_string(),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            decoy_set_size: DEFAULT_MIN_DECOY_SET_SIZE,
            valid_from_height: DEVNET_HEIGHT,
            nonce: 3,
        })
        .ok_or_error_string();
    let _ = state.admit_bid(&bid_id);
    let _ = state.select_bid(&bid_id);
    let _ = state.reserve_sponsor_liquidity(&sponsor_id, 25_000);
    let _ = state.record_clearing(ClearingRequest {
        auction_id: auction_id.clone(),
        clearing_root: "demo-clearing-root".to_string(),
        selected_bids_root: "demo-selected-bids-root".to_string(),
        rejected_bids_root: "demo-rejected-bids-root".to_string(),
        clearing_price_bps: DEFAULT_TARGET_FLOOR_BPS,
        sponsor_paid: 12_000,
        user_paid: 6_000,
        pq_clearing_signature_root: "demo-pq-clearing-signature-root".to_string(),
        validity_proof_root: "demo-validity-proof-root".to_string(),
        operator_commitment: "demo-operator-commitment".to_string(),
        cleared_at_height: DEVNET_HEIGHT.saturating_add(1),
    });
    let _ = state.spend_sponsor_liquidity(&sponsor_id, 12_000);
    let _ = state.route_standard_rebates(&auction_id, &bid_id, 4_500);
    let _ = state.record_fee_cap(FeeCapRequest {
        auction_id: auction_id.clone(),
        bid_id: bid_id.clone(),
        cap_bps: DEFAULT_MAX_USER_FEE_BPS,
        charged_bps: DEFAULT_TARGET_FLOOR_BPS,
        refund_commitment: "demo-refund-commitment".to_string(),
        proof_root: "demo-fee-cap-proof-root".to_string(),
        valid_from_height: DEVNET_HEIGHT.saturating_add(2),
        nonce: 4,
    });
    let _ = state.record_microbatch(MicrobatchRequest {
        auction_id: auction_id.clone(),
        lane: FeeLane::PrivateTransfer,
        microbatch_root: "demo-microbatch-root".to_string(),
        transaction_count: 16,
        aggregate_weight: 250_000,
        discount_bps: DEFAULT_MICROBATCH_DISCOUNT_BPS / 2,
        operator_commitment: "demo-operator-commitment".to_string(),
        valid_from_height: DEVNET_HEIGHT.saturating_add(2),
        nonce: 5,
    });
    let _ = state.publish_operator_summary(OperatorSummaryRequest {
        operator_commitment: "demo-operator-commitment".to_string(),
        epoch: DEVNET_EPOCH,
        auctions_root: state.roots.auctions_root.clone(),
        clearing_root: state.roots.clearings_root.clone(),
        rebates_root: state.roots.rebate_routes_root.clone(),
        fee_cap_root: state.roots.fee_caps_root.clone(),
        bridge_smoothing_root: state.roots.bridge_windows_root.clone(),
        microbatch_root: state.roots.microbatches_root.clone(),
        median_fee_bps: DEFAULT_TARGET_FLOOR_BPS,
        p95_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
        rebate_total: 4_500,
        sponsor_total: 12_000,
        valid_from_height: DEVNET_HEIGHT.saturating_add(3),
        nonce: 6,
    });
    state.refresh_roots();
    state
}

pub fn public_record() -> Value {
    demo().public_record()
}

pub fn state_root() -> String {
    demo().state_root()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    match record.get("state_root").and_then(Value::as_str) {
        Some(value) => value.to_string(),
        None => record_root("STATE", record),
    }
}

pub fn auction_id(commitment: &str, lane: FeeLane, epoch: u64, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-FLOOR-AUCTION:AUCTION-ID",
        &[
            HashPart::Str(commitment),
            HashPart::Str(lane.as_str()),
            HashPart::U64(epoch),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn bid_id(
    auction_id: &str,
    bidder_commitment: &str,
    sealed_bid_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-FLOOR-AUCTION:BID-ID",
        &[
            HashPart::Str(auction_id),
            HashPart::Str(bidder_commitment),
            HashPart::Str(sealed_bid_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn sponsor_pool_id(commitment: &str, lane: FeeLane, policy_root: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-FLOOR-AUCTION:SPONSOR-POOL-ID",
        &[
            HashPart::Str(commitment),
            HashPart::Str(lane.as_str()),
            HashPart::Str(policy_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn clearing_id(
    auction_id: &str,
    clearing_root: &str,
    signature_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-FLOOR-AUCTION:CLEARING-ID",
        &[
            HashPart::Str(auction_id),
            HashPart::Str(clearing_root),
            HashPart::Str(signature_root),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn rebate_route_id(
    auction_id: &str,
    bid_id: &str,
    kind: RebateKind,
    claim_nullifier: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-FLOOR-AUCTION:REBATE-ROUTE-ID",
        &[
            HashPart::Str(auction_id),
            HashPart::Str(bid_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(claim_nullifier),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn fee_cap_id(auction_id: &str, bid_id: &str, cap_bps: u64, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-FLOOR-AUCTION:FEE-CAP-ID",
        &[
            HashPart::Str(auction_id),
            HashPart::Str(bid_id),
            HashPart::U64(cap_bps),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn bridge_window_id(lane: FeeLane, label: &str, liquidity_root: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-FLOOR-AUCTION:BRIDGE-WINDOW-ID",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(label),
            HashPart::Str(liquidity_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn microbatch_id(auction_id: &str, lane: FeeLane, root: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-FLOOR-AUCTION:MICROBATCH-ID",
        &[
            HashPart::Str(auction_id),
            HashPart::Str(lane.as_str()),
            HashPart::Str(root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn operator_summary_id(operator: &str, epoch: u64, clearing_root: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-FLOOR-AUCTION:OPERATOR-SUMMARY-ID",
        &[
            HashPart::Str(operator),
            HashPart::U64(epoch),
            HashPart::Str(clearing_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn privacy_fence_id(nullifier: &str, scope: &str, commitment_root: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-FLOOR-AUCTION:PRIVACY-FENCE-ID",
        &[
            HashPart::Str(nullifier),
            HashPart::Str(scope),
            HashPart::Str(commitment_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn record_root(label: &str, value: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-FLOOR-AUCTION:RECORD-ROOT",
        &[HashPart::Str(label), HashPart::Json(value)],
        32,
    )
}

fn list_root(label: &str, leaves: &[Value]) -> String {
    merkle_root(
        &format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-FLOOR-AUCTION:{label}"),
        leaves,
    )
}

fn map_root<T>(label: &str, values: &BTreeMap<String, T>) -> String
where
    T: Serialize,
{
    let leaves = values
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    list_root(label, &leaves)
}

fn lane_index_root(index: &BTreeMap<FeeLane, BTreeSet<String>>) -> String {
    let leaves = index
        .iter()
        .map(|(lane, ids)| {
            json!({
                "lane": lane.as_str(),
                "auction_ids": ids.iter().cloned().collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>();
    list_root("LANE-INDEX", &leaves)
}

trait ResultStringIdentity {
    fn ok_or_error_string(self) -> String;
}

impl ResultStringIdentity for Result<String> {
    fn ok_or_error_string(self) -> String {
        match self {
            Ok(value) => value,
            Err(value) => value,
        }
    }
}
