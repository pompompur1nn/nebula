use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PqPrivateBridgeBatchAuctionRuntimeResult<T> = Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-bridge-batch-auction-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_PROTOCOL_VERSION;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEVNET_HEIGHT: u64 = 612_000;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEVNET_MONERO_NETWORK: &str =
    "monero-devnet";
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEVNET_L2_NETWORK: &str =
    "nebula-devnet";
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEVNET_FEE_ASSET_ID: &str =
    "piconero-devnet";
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEVNET_STABLE_ASSET_ID: &str =
    "dusd-devnet";
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_BATCH_SCHEME: &str =
    "ml-kem-1024+zk-monero-private-bridge-batch-root-v1";
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_PRIVATE_BID_SCHEME: &str =
    "ml-kem-1024-sealed-private-bridge-solver-bid-v1";
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_RESERVE_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-192f-pq-reserve-attestation-root-v1";
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_SPONSOR_SCHEME: &str =
    "roots-only-liquidity-sponsor-reservation-v1";
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_SETTLEMENT_SCHEME: &str =
    "zk-pq-monero-private-bridge-batch-settlement-v1";
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_RECEIPT_SCHEME: &str =
    "private-bridge-receipt-rebate-root-v1";
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_NULLIFIER_SCHEME: &str =
    "monero-l2-pq-private-bridge-batch-auction-nullifier-root-v1";
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_REPLAY_DOMAIN: &str =
    "monero-l2-pq-private-bridge-batch-auction-devnet";
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_MAX_BPS: u64 = 10_000;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS: u64 = 24;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_BID_TTL_BLOCKS: u64 = 8;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS: u64 =
    18;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 32;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 =
    6;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 =
    16_384;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 =
    65_536;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS: u16 =
    256;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 =
    10_500;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_TARGET_RESERVE_COVERAGE_BPS:
    u64 = 12_500;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_LOW_FEE_BPS: u64 = 5;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_MAX_SOLVER_FEE_BPS: u64 = 24;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_REBATE_BPS: u64 = 9;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_SPONSOR_COVER_BPS: u64 = 8_500;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_MAX_BATCH_ITEMS: usize = 768;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_MAX_BATCHES: usize = 262_144;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_MAX_BIDS: usize = 1_048_576;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_MAX_ATTESTATIONS: usize = 1_048_576;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_MAX_SPONSOR_RESERVATIONS: usize =
    524_288;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_MAX_SETTLEMENTS: usize = 262_144;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_MAX_RECEIPTS: usize = 524_288;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_MAX_REBATES: usize = 524_288;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_MAX_FENCES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeDirection {
    MoneroToL2,
    L2ToMonero,
    RebalanceIn,
    RebalanceOut,
    DefiMint,
    DefiRedeem,
}

impl BridgeDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroToL2 => "monero_to_l2",
            Self::L2ToMonero => "l2_to_monero",
            Self::RebalanceIn => "rebalance_in",
            Self::RebalanceOut => "rebalance_out",
            Self::DefiMint => "defi_mint",
            Self::DefiRedeem => "defi_redeem",
        }
    }

    pub fn exits_monero(self) -> bool {
        matches!(
            self,
            Self::L2ToMonero | Self::RebalanceOut | Self::DefiRedeem
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionLane {
    SponsoredLowFee,
    FastBridge,
    DefiRoute,
    ReserveRebalance,
    EmergencyExit,
    MakerBackstop,
}

impl AuctionLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SponsoredLowFee => "sponsored_low_fee",
            Self::FastBridge => "fast_bridge",
            Self::DefiRoute => "defi_route",
            Self::ReserveRebalance => "reserve_rebalance",
            Self::EmergencyExit => "emergency_exit",
            Self::MakerBackstop => "maker_backstop",
        }
    }

    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::SponsoredLowFee => config.low_fee_bps,
            Self::ReserveRebalance | Self::MakerBackstop => config.max_user_fee_bps / 2,
            Self::DefiRoute => config.max_user_fee_bps.saturating_mul(3) / 4,
            Self::FastBridge | Self::EmergencyExit => config.max_user_fee_bps,
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyExit => 1_000,
            Self::FastBridge => 930,
            Self::SponsoredLowFee => 880,
            Self::DefiRoute => 780,
            Self::ReserveRebalance => 720,
            Self::MakerBackstop => 660,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    Sponsored,
    ReserveAttested,
    Auctioned,
    Settling,
    Settled,
    Rejected,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Sponsored => "sponsored",
            Self::ReserveAttested => "reserve_attested",
            Self::Auctioned => "auctioned",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn auctionable(self) -> bool {
        matches!(self, Self::Sealed | Self::Sponsored | Self::ReserveAttested)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Committed,
    Revealed,
    Eligible,
    Selected,
    Settled,
    Rejected,
    Expired,
}

impl BidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Revealed => "revealed",
            Self::Eligible => "eligible",
            Self::Selected => "selected",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Posted,
    Accepted,
    QuorumAccepted,
    Superseded,
    Rejected,
    Expired,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Accepted => "accepted",
            Self::QuorumAccepted => "quorum_accepted",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Applied,
    Consumed,
    Released,
    Slashed,
    Expired,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Proposed,
    Executing,
    ReceiptPublished,
    Finalized,
    Disputed,
    Reverted,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Executing => "executing",
            Self::ReceiptPublished => "receipt_published",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Reverted => "reverted",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceKind {
    Nullifier,
    KeyImage,
    SpendTag,
    BidCommitment,
    Receipt,
    Rebate,
    SponsorReservation,
    ReplayDomain,
}

impl FenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nullifier => "nullifier",
            Self::KeyImage => "key_image",
            Self::SpendTag => "spend_tag",
            Self::BidCommitment => "bid_commitment",
            Self::Receipt => "receipt",
            Self::Rebate => "rebate",
            Self::SponsorReservation => "sponsor_reservation",
            Self::ReplayDomain => "replay_domain",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub bridge_asset_id: String,
    pub fee_asset_id: String,
    pub stable_asset_id: String,
    pub hash_suite: String,
    pub batch_scheme: String,
    pub private_bid_scheme: String,
    pub reserve_attestation_scheme: String,
    pub sponsor_scheme: String,
    pub settlement_scheme: String,
    pub receipt_scheme: String,
    pub nullifier_scheme: String,
    pub replay_domain: String,
    pub batch_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub min_reserve_coverage_bps: u64,
    pub target_reserve_coverage_bps: u64,
    pub max_user_fee_bps: u64,
    pub low_fee_bps: u64,
    pub max_solver_fee_bps: u64,
    pub rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub max_batch_items: usize,
    pub max_batches: usize,
    pub max_bids: usize,
    pub max_attestations: usize,
    pub max_sponsor_reservations: usize,
    pub max_settlements: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_fences: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network:
                MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEVNET_MONERO_NETWORK.to_string(),
            l2_network: MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEVNET_L2_NETWORK
                .to_string(),
            bridge_asset_id: MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEVNET_ASSET_ID
                .to_string(),
            fee_asset_id: MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEVNET_FEE_ASSET_ID
                .to_string(),
            stable_asset_id:
                MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEVNET_STABLE_ASSET_ID
                    .to_string(),
            hash_suite: MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_HASH_SUITE.to_string(),
            batch_scheme: MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_BATCH_SCHEME
                .to_string(),
            private_bid_scheme:
                MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_PRIVATE_BID_SCHEME.to_string(),
            reserve_attestation_scheme:
                MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_RESERVE_ATTESTATION_SCHEME
                    .to_string(),
            sponsor_scheme: MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_SPONSOR_SCHEME
                .to_string(),
            settlement_scheme: MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_SETTLEMENT_SCHEME
                .to_string(),
            receipt_scheme: MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_RECEIPT_SCHEME
                .to_string(),
            nullifier_scheme: MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_NULLIFIER_SCHEME
                .to_string(),
            replay_domain: MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_REPLAY_DOMAIN
                .to_string(),
            batch_ttl_blocks:
                MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
            bid_ttl_blocks: MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_BID_TTL_BLOCKS,
            reservation_ttl_blocks:
                MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            settlement_ttl_blocks:
                MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            receipt_finality_blocks:
                MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_RECEIPT_FINALITY_BLOCKS,
            min_privacy_set_size:
                MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits:
                MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS,
            min_reserve_coverage_bps:
                MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            target_reserve_coverage_bps:
                MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_TARGET_RESERVE_COVERAGE_BPS,
            max_user_fee_bps:
                MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            low_fee_bps: MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_LOW_FEE_BPS,
            max_solver_fee_bps:
                MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_MAX_SOLVER_FEE_BPS,
            rebate_bps: MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_REBATE_BPS,
            sponsor_cover_bps:
                MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_SPONSOR_COVER_BPS,
            max_batch_items: MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEFAULT_MAX_BATCH_ITEMS,
            max_batches: MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_MAX_BATCHES,
            max_bids: MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_MAX_BIDS,
            max_attestations: MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_MAX_ATTESTATIONS,
            max_sponsor_reservations:
                MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_MAX_SPONSOR_RESERVATIONS,
            max_settlements: MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_MAX_SETTLEMENTS,
            max_receipts: MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_MAX_RECEIPTS,
            max_rebates: MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_MAX_REBATES,
            max_fences: MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_MAX_FENCES,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "bridge_asset_id": self.bridge_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "stable_asset_id": self.stable_asset_id,
            "hash_suite": self.hash_suite,
            "batch_scheme": self.batch_scheme,
            "private_bid_scheme": self.private_bid_scheme,
            "reserve_attestation_scheme": self.reserve_attestation_scheme,
            "sponsor_scheme": self.sponsor_scheme,
            "settlement_scheme": self.settlement_scheme,
            "receipt_scheme": self.receipt_scheme,
            "nullifier_scheme": self.nullifier_scheme,
            "replay_domain": self.replay_domain,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "bid_ttl_blocks": self.bid_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "receipt_finality_blocks": self.receipt_finality_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "target_reserve_coverage_bps": self.target_reserve_coverage_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "low_fee_bps": self.low_fee_bps,
            "max_solver_fee_bps": self.max_solver_fee_bps,
            "rebate_bps": self.rebate_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "max_batch_items": self.max_batch_items,
            "max_batches": self.max_batches,
            "max_bids": self.max_bids,
            "max_attestations": self.max_attestations,
            "max_sponsor_reservations": self.max_sponsor_reservations,
            "max_settlements": self.max_settlements,
            "max_receipts": self.max_receipts,
            "max_rebates": self.max_rebates,
            "max_fences": self.max_fences,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub batches: u64,
    pub bids: u64,
    pub reserve_attestations: u64,
    pub sponsor_reservations: u64,
    pub settlements: u64,
    pub receipts: u64,
    pub rebates: u64,
    pub fences: u64,
    pub events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "batches": self.batches,
            "bids": self.bids,
            "reserve_attestations": self.reserve_attestations,
            "sponsor_reservations": self.sponsor_reservations,
            "settlements": self.settlements,
            "receipts": self.receipts,
            "rebates": self.rebates,
            "fences": self.fences,
            "events": self.events,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counter_root: String,
    pub batch_root: String,
    pub private_bid_root: String,
    pub reserve_attestation_root: String,
    pub sponsor_reservation_root: String,
    pub settlement_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub nullifier_fence_root: String,
    pub key_image_fence_root: String,
    pub replay_fence_root: String,
    pub route_root: String,
    pub event_root: String,
    pub public_record_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            config_root: empty_root("MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-CONFIG-EMPTY"),
            counter_root: empty_root("MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-COUNTERS-EMPTY"),
            batch_root: empty_root("MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-BATCH-EMPTY"),
            private_bid_root: empty_root("MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-BID-EMPTY"),
            reserve_attestation_root: empty_root(
                "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-ATTESTATION-EMPTY",
            ),
            sponsor_reservation_root: empty_root(
                "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-SPONSOR-EMPTY",
            ),
            settlement_root: empty_root(
                "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-SETTLEMENT-EMPTY",
            ),
            receipt_root: empty_root("MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-RECEIPT-EMPTY"),
            rebate_root: empty_root("MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-REBATE-EMPTY"),
            nullifier_fence_root: empty_root(
                "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-NULLIFIER-FENCE-EMPTY",
            ),
            key_image_fence_root: empty_root(
                "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-KEY-IMAGE-FENCE-EMPTY",
            ),
            replay_fence_root: empty_root(
                "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-REPLAY-FENCE-EMPTY",
            ),
            route_root: empty_root("MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-ROUTE-EMPTY"),
            event_root: empty_root("MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-EVENT-EMPTY"),
            public_record_root: empty_root(
                "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-PUBLIC-RECORD-EMPTY",
            ),
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counter_root": self.counter_root,
            "batch_root": self.batch_root,
            "private_bid_root": self.private_bid_root,
            "reserve_attestation_root": self.reserve_attestation_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "settlement_root": self.settlement_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "key_image_fence_root": self.key_image_fence_root,
            "replay_fence_root": self.replay_fence_root,
            "route_root": self.route_root,
            "event_root": self.event_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeBatch {
    pub batch_id: String,
    pub sequence: u64,
    pub direction: BridgeDirection,
    pub lane: AuctionLane,
    pub status: BatchStatus,
    pub asset_id: String,
    pub amount_bucket_units: u64,
    pub min_output_units: u64,
    pub max_user_fee_bps: u64,
    pub privacy_set_size: u64,
    pub order_commitment_root: String,
    pub encrypted_order_root: String,
    pub monero_output_root: String,
    pub l2_note_root: String,
    pub nullifier_root: String,
    pub key_image_root: String,
    pub route_hint_root: String,
    pub sponsor_reservation_root: String,
    pub reserve_attestation_root: String,
    pub selected_bid_root: String,
    pub settlement_root: String,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: String,
}

impl BridgeBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "sequence": self.sequence,
            "direction": self.direction.as_str(),
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "asset_id": self.asset_id,
            "amount_bucket_units": self.amount_bucket_units,
            "min_output_units": self.min_output_units,
            "max_user_fee_bps": self.max_user_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "order_commitment_root": self.order_commitment_root,
            "encrypted_order_root": self.encrypted_order_root,
            "monero_output_root": self.monero_output_root,
            "l2_note_root": self.l2_note_root,
            "nullifier_root": self.nullifier_root,
            "key_image_root": self.key_image_root,
            "route_hint_root": self.route_hint_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "reserve_attestation_root": self.reserve_attestation_root,
            "selected_bid_root": self.selected_bid_root,
            "settlement_root": self.settlement_root,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateBid {
    pub bid_id: String,
    pub batch_id: String,
    pub solver_commitment: String,
    pub status: BidStatus,
    pub lane: AuctionLane,
    pub encrypted_bid_root: String,
    pub bid_commitment_root: String,
    pub route_commitment_root: String,
    pub liquidity_source_root: String,
    pub expected_output_units: u64,
    pub solver_fee_bps: u64,
    pub rebate_bps: u64,
    pub fill_capacity_units: u64,
    pub reserve_attestation_root: String,
    pub sponsor_reservation_root: String,
    pub pq_signature_root: String,
    pub submitted_at_height: u64,
    pub reveal_deadline_height: u64,
    pub expires_at_height: u64,
    pub nonce: String,
}

impl PrivateBid {
    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "batch_id": self.batch_id,
            "solver_commitment": self.solver_commitment,
            "status": self.status.as_str(),
            "lane": self.lane.as_str(),
            "encrypted_bid_root": self.encrypted_bid_root,
            "bid_commitment_root": self.bid_commitment_root,
            "route_commitment_root": self.route_commitment_root,
            "liquidity_source_root": self.liquidity_source_root,
            "expected_output_units": self.expected_output_units,
            "solver_fee_bps": self.solver_fee_bps,
            "rebate_bps": self.rebate_bps,
            "fill_capacity_units": self.fill_capacity_units,
            "reserve_attestation_root": self.reserve_attestation_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "pq_signature_root": self.pq_signature_root,
            "submitted_at_height": self.submitted_at_height,
            "reveal_deadline_height": self.reveal_deadline_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveAttestation {
    pub attestation_id: String,
    pub batch_id: String,
    pub signer_commitment: String,
    pub status: AttestationStatus,
    pub monero_reserve_root: String,
    pub l2_reserve_root: String,
    pub route_liquidity_root: String,
    pub liability_root: String,
    pub witness_set_root: String,
    pub pq_signature_root: String,
    pub reserve_capacity_units: u64,
    pub pending_liability_units: u64,
    pub coverage_bps: u64,
    pub pq_security_bits: u16,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
}

impl ReserveAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "batch_id": self.batch_id,
            "signer_commitment": self.signer_commitment,
            "status": self.status.as_str(),
            "monero_reserve_root": self.monero_reserve_root,
            "l2_reserve_root": self.l2_reserve_root,
            "route_liquidity_root": self.route_liquidity_root,
            "liability_root": self.liability_root,
            "witness_set_root": self.witness_set_root,
            "pq_signature_root": self.pq_signature_root,
            "reserve_capacity_units": self.reserve_capacity_units,
            "pending_liability_units": self.pending_liability_units,
            "coverage_bps": self.coverage_bps,
            "pq_security_bits": self.pq_security_bits,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquiditySponsorReservation {
    pub reservation_id: String,
    pub sponsor_commitment: String,
    pub batch_id: String,
    pub bid_id: String,
    pub status: ReservationStatus,
    pub asset_id: String,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub applied_fee_bps: u64,
    pub max_rebate_bps: u64,
    pub route_policy_root: String,
    pub privacy_policy_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl LiquiditySponsorReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "sponsor_commitment": self.sponsor_commitment,
            "batch_id": self.batch_id,
            "bid_id": self.bid_id,
            "status": self.status.as_str(),
            "asset_id": self.asset_id,
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "applied_fee_bps": self.applied_fee_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "route_policy_root": self.route_policy_root,
            "privacy_policy_root": self.privacy_policy_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchSettlement {
    pub settlement_id: String,
    pub batch_id: String,
    pub selected_bid_id: String,
    pub status: SettlementStatus,
    pub direction: BridgeDirection,
    pub gross_input_units: u64,
    pub net_output_units: u64,
    pub solver_fee_units: u64,
    pub sponsor_rebate_units: u64,
    pub monero_release_root: String,
    pub l2_release_root: String,
    pub defi_route_root: String,
    pub reserve_delta_root: String,
    pub nullifier_fence_root: String,
    pub receipt_root: String,
    pub pq_attestation_root: String,
    pub proposed_at_height: u64,
    pub executable_at_height: u64,
    pub finalized_at_height: u64,
}

impl BatchSettlement {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "batch_id": self.batch_id,
            "selected_bid_id": self.selected_bid_id,
            "status": self.status.as_str(),
            "direction": self.direction.as_str(),
            "gross_input_units": self.gross_input_units,
            "net_output_units": self.net_output_units,
            "solver_fee_units": self.solver_fee_units,
            "sponsor_rebate_units": self.sponsor_rebate_units,
            "monero_release_root": self.monero_release_root,
            "l2_release_root": self.l2_release_root,
            "defi_route_root": self.defi_route_root,
            "reserve_delta_root": self.reserve_delta_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "receipt_root": self.receipt_root,
            "pq_attestation_root": self.pq_attestation_root,
            "proposed_at_height": self.proposed_at_height,
            "executable_at_height": self.executable_at_height,
            "finalized_at_height": self.finalized_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeReceipt {
    pub receipt_id: String,
    pub settlement_id: String,
    pub batch_id: String,
    pub owner_commitment: String,
    pub output_commitment_root: String,
    pub fee_receipt_root: String,
    pub rebate_root: String,
    pub privacy_receipt_root: String,
    pub delivered_units: u64,
    pub paid_fee_units: u64,
    pub rebate_units: u64,
    pub issued_at_height: u64,
    pub final_at_height: u64,
}

impl BridgeReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "settlement_id": self.settlement_id,
            "batch_id": self.batch_id,
            "owner_commitment": self.owner_commitment,
            "output_commitment_root": self.output_commitment_root,
            "fee_receipt_root": self.fee_receipt_root,
            "rebate_root": self.rebate_root,
            "privacy_receipt_root": self.privacy_receipt_root,
            "delivered_units": self.delivered_units,
            "paid_fee_units": self.paid_fee_units,
            "rebate_units": self.rebate_units,
            "issued_at_height": self.issued_at_height,
            "final_at_height": self.final_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub sponsor_reservation_id: String,
    pub owner_commitment: String,
    pub asset_id: String,
    pub amount_units: u64,
    pub rebate_bps: u64,
    pub claim_nullifier_root: String,
    pub claim_note_root: String,
    pub expires_at_height: u64,
}

impl Rebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "owner_commitment": self.owner_commitment,
            "asset_id": self.asset_id,
            "amount_units": self.amount_units,
            "rebate_bps": self.rebate_bps,
            "claim_nullifier_root": self.claim_nullifier_root,
            "claim_note_root": self.claim_note_root,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub kind: FenceKind,
    pub subject_id: String,
    pub commitment_root: String,
    pub domain: String,
    pub opened_at_height: u64,
}

impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "commitment_root": self.commitment_root,
            "domain": self.domain,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteSnapshot {
    pub route_id: String,
    pub batch_id: String,
    pub lane: AuctionLane,
    pub input_asset_id: String,
    pub output_asset_id: String,
    pub pool_commitment_root: String,
    pub solver_set_root: String,
    pub sponsor_set_root: String,
    pub expected_price_root: String,
    pub max_slippage_bps: u64,
    pub fee_bps: u64,
    pub recorded_at_height: u64,
}

impl RouteSnapshot {
    pub fn public_record(&self) -> Value {
        json!({
            "route_id": self.route_id,
            "batch_id": self.batch_id,
            "lane": self.lane.as_str(),
            "input_asset_id": self.input_asset_id,
            "output_asset_id": self.output_asset_id,
            "pool_commitment_root": self.pool_commitment_root,
            "solver_set_root": self.solver_set_root,
            "sponsor_set_root": self.sponsor_set_root,
            "expected_price_root": self.expected_price_root,
            "max_slippage_bps": self.max_slippage_bps,
            "fee_bps": self.fee_bps,
            "recorded_at_height": self.recorded_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRecord {
    pub event_id: String,
    pub event_type: String,
    pub subject_id: String,
    pub payload_root: String,
    pub height: u64,
}

impl EventRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_type": self.event_type,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub batches: BTreeMap<String, BridgeBatch>,
    pub bids: BTreeMap<String, PrivateBid>,
    pub reserve_attestations: BTreeMap<String, ReserveAttestation>,
    pub sponsor_reservations: BTreeMap<String, LiquiditySponsorReservation>,
    pub settlements: BTreeMap<String, BatchSettlement>,
    pub receipts: BTreeMap<String, BridgeReceipt>,
    pub rebates: BTreeMap<String, Rebate>,
    pub fences: BTreeMap<String, PrivacyFence>,
    pub routes: BTreeMap<String, RouteSnapshot>,
    pub events: Vec<Value>,
    pub used_nullifier_roots: BTreeSet<String>,
    pub used_key_image_roots: BTreeSet<String>,
    pub used_replay_fences: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            batches: BTreeMap::new(),
            bids: BTreeMap::new(),
            reserve_attestations: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            settlements: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            fences: BTreeMap::new(),
            routes: BTreeMap::new(),
            events: Vec::new(),
            used_nullifier_roots: BTreeSet::new(),
            used_key_image_roots: BTreeSet::new(),
            used_replay_fences: BTreeSet::new(),
        };
        state.refresh_roots();
        state
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::default();
        let height = MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_DEVNET_HEIGHT;
        let order_root = value_root(
            "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-DEVNET-ORDERS",
            vec![
                json!({"order": "entry", "amount_bucket_units": 2_500_000_000u64}),
                json!({"order": "exit", "amount_bucket_units": 1_750_000_000u64}),
                json!({"order": "defi_mint", "amount_bucket_units": 750_000_000u64}),
            ],
        );
        let encrypted_order_root = tagged_root("devnet-encrypted-order-root");
        let monero_output_root = tagged_root("devnet-monero-output-root");
        let l2_note_root = tagged_root("devnet-l2-note-root");
        let nullifier_root = tagged_root("devnet-nullifier-root");
        let key_image_root = tagged_root("devnet-key-image-root");
        let route_hint_root = tagged_root("devnet-route-hint-root");
        let batch_id = bridge_batch_id(
            1,
            BridgeDirection::MoneroToL2,
            AuctionLane::SponsoredLowFee,
            &order_root,
            height,
            "devnet-batch",
        );
        let route_id = route_snapshot_id(&batch_id, AuctionLane::SponsoredLowFee, height);
        let route = RouteSnapshot {
            route_id: route_id.clone(),
            batch_id: batch_id.clone(),
            lane: AuctionLane::SponsoredLowFee,
            input_asset_id: state.config.bridge_asset_id.clone(),
            output_asset_id: state.config.stable_asset_id.clone(),
            pool_commitment_root: tagged_root("devnet-pool-commitments"),
            solver_set_root: tagged_root("devnet-solvers"),
            sponsor_set_root: tagged_root("devnet-sponsors"),
            expected_price_root: tagged_root("devnet-private-price"),
            max_slippage_bps: 25,
            fee_bps: AuctionLane::SponsoredLowFee.fee_bps(&state.config),
            recorded_at_height: height,
        };
        state.routes.insert(route_id.clone(), route);
        let attestation_id = reserve_attestation_id(
            &batch_id,
            "devnet-reserve-committee",
            &tagged_root("devnet-monero-reserves"),
            &tagged_root("devnet-l2-reserves"),
            height,
        );
        let attestation = ReserveAttestation {
            attestation_id: attestation_id.clone(),
            batch_id: batch_id.clone(),
            signer_commitment: "devnet-reserve-committee".to_string(),
            status: AttestationStatus::QuorumAccepted,
            monero_reserve_root: tagged_root("devnet-monero-reserves"),
            l2_reserve_root: tagged_root("devnet-l2-reserves"),
            route_liquidity_root: route_id.clone(),
            liability_root: tagged_root("devnet-liabilities"),
            witness_set_root: tagged_root("devnet-watchers"),
            pq_signature_root: tagged_root("devnet-reserve-pq-signature"),
            reserve_capacity_units: 8_000_000_000,
            pending_liability_units: 5_000_000_000,
            coverage_bps: 16_000,
            pq_security_bits: state.config.target_pq_security_bits,
            signed_at_height: height,
            expires_at_height: height + state.config.settlement_ttl_blocks,
        };
        let bid_id = private_bid_id(
            &batch_id,
            "devnet-solver-a",
            &tagged_root("devnet-bid-commitment"),
            height,
            "bid-a",
        );
        let reservation_id = sponsor_reservation_id(
            "devnet-sponsor-a",
            &batch_id,
            &bid_id,
            state.config.low_fee_bps,
            height,
        );
        let reservation = LiquiditySponsorReservation {
            reservation_id: reservation_id.clone(),
            sponsor_commitment: "devnet-sponsor-a".to_string(),
            batch_id: batch_id.clone(),
            bid_id: bid_id.clone(),
            status: ReservationStatus::Applied,
            asset_id: state.config.fee_asset_id.clone(),
            budget_units: 40_000_000,
            reserved_units: 11_250_000,
            applied_fee_bps: state.config.low_fee_bps,
            max_rebate_bps: state.config.rebate_bps,
            route_policy_root: route_id,
            privacy_policy_root: tagged_root("devnet-sponsor-privacy-policy"),
            opened_at_height: height,
            expires_at_height: height + state.config.reservation_ttl_blocks,
        };
        let bid = PrivateBid {
            bid_id: bid_id.clone(),
            batch_id: batch_id.clone(),
            solver_commitment: "devnet-solver-a".to_string(),
            status: BidStatus::Selected,
            lane: AuctionLane::SponsoredLowFee,
            encrypted_bid_root: tagged_root("devnet-encrypted-bid"),
            bid_commitment_root: tagged_root("devnet-bid-commitment"),
            route_commitment_root: route_hint_root.clone(),
            liquidity_source_root: tagged_root("devnet-liquidity-source"),
            expected_output_units: 2_486_000_000,
            solver_fee_bps: state.config.low_fee_bps,
            rebate_bps: state.config.rebate_bps,
            fill_capacity_units: 3_000_000_000,
            reserve_attestation_root: attestation_id.clone(),
            sponsor_reservation_root: reservation_id.clone(),
            pq_signature_root: tagged_root("devnet-bid-pq-signature"),
            submitted_at_height: height,
            reveal_deadline_height: height + state.config.bid_ttl_blocks,
            expires_at_height: height + state.config.batch_ttl_blocks,
            nonce: "bid-a".to_string(),
        };
        let batch = BridgeBatch {
            batch_id: batch_id.clone(),
            sequence: 1,
            direction: BridgeDirection::MoneroToL2,
            lane: AuctionLane::SponsoredLowFee,
            status: BatchStatus::Auctioned,
            asset_id: state.config.bridge_asset_id.clone(),
            amount_bucket_units: 2_500_000_000,
            min_output_units: 2_480_000_000,
            max_user_fee_bps: state.config.max_user_fee_bps,
            privacy_set_size: state.config.batch_privacy_set_size,
            order_commitment_root: order_root,
            encrypted_order_root,
            monero_output_root,
            l2_note_root,
            nullifier_root: nullifier_root.clone(),
            key_image_root: key_image_root.clone(),
            route_hint_root,
            sponsor_reservation_root: reservation_id.clone(),
            reserve_attestation_root: attestation_id.clone(),
            selected_bid_root: bid_id.clone(),
            settlement_root: empty_root(
                "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-DEVNET-SETTLEMENT-PENDING",
            ),
            opened_at_height: height,
            sealed_at_height: height + 1,
            expires_at_height: height + state.config.batch_ttl_blocks,
            nonce: "devnet-batch".to_string(),
        };
        state.batches.insert(batch_id.clone(), batch);
        state.bids.insert(bid_id.clone(), bid);
        state
            .reserve_attestations
            .insert(attestation_id.clone(), attestation);
        state
            .sponsor_reservations
            .insert(reservation_id.clone(), reservation);
        state.insert_fence(
            FenceKind::Nullifier,
            &batch_id,
            &nullifier_root,
            MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_REPLAY_DOMAIN,
            height,
        );
        state.insert_fence(
            FenceKind::KeyImage,
            &batch_id,
            &key_image_root,
            MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_REPLAY_DOMAIN,
            height,
        );
        let settlement_id = settlement_id(
            &batch_id,
            &bid_id,
            &attestation_id,
            height + 2,
            "devnet-settlement",
        );
        let receipt_root = tagged_root("devnet-receipt-root");
        let settlement = BatchSettlement {
            settlement_id: settlement_id.clone(),
            batch_id: batch_id.clone(),
            selected_bid_id: bid_id.clone(),
            status: SettlementStatus::ReceiptPublished,
            direction: BridgeDirection::MoneroToL2,
            gross_input_units: 2_500_000_000,
            net_output_units: 2_486_000_000,
            solver_fee_units: 1_250_000,
            sponsor_rebate_units: 2_250_000,
            monero_release_root: tagged_root("devnet-monero-release"),
            l2_release_root: tagged_root("devnet-l2-release"),
            defi_route_root: tagged_root("devnet-defi-route"),
            reserve_delta_root: tagged_root("devnet-reserve-delta"),
            nullifier_fence_root: nullifier_root,
            receipt_root: receipt_root.clone(),
            pq_attestation_root: attestation_id,
            proposed_at_height: height + 2,
            executable_at_height: height + 3,
            finalized_at_height: height + 6,
        };
        let receipt_id = receipt_id(&settlement_id, &batch_id, "devnet-owner", height + 3);
        let rebate_id = rebate_id(&receipt_id, &reservation_id, "devnet-owner", height + 3);
        let receipt = BridgeReceipt {
            receipt_id: receipt_id.clone(),
            settlement_id: settlement_id.clone(),
            batch_id: batch_id.clone(),
            owner_commitment: "devnet-owner".to_string(),
            output_commitment_root: tagged_root("devnet-owner-output"),
            fee_receipt_root: tagged_root("devnet-fee-receipt"),
            rebate_root: rebate_id.clone(),
            privacy_receipt_root: receipt_root,
            delivered_units: 2_486_000_000,
            paid_fee_units: 1_250_000,
            rebate_units: 2_250_000,
            issued_at_height: height + 3,
            final_at_height: height + state.config.receipt_finality_blocks,
        };
        let rebate = Rebate {
            rebate_id: rebate_id.clone(),
            receipt_id: receipt_id.clone(),
            sponsor_reservation_id: reservation_id,
            owner_commitment: "devnet-owner".to_string(),
            asset_id: state.config.fee_asset_id.clone(),
            amount_units: 2_250_000,
            rebate_bps: state.config.rebate_bps,
            claim_nullifier_root: tagged_root("devnet-rebate-nullifier"),
            claim_note_root: tagged_root("devnet-rebate-note"),
            expires_at_height: height + 144,
        };
        state.settlements.insert(settlement_id.clone(), settlement);
        state.receipts.insert(receipt_id, receipt);
        state.rebates.insert(rebate_id, rebate);
        state.push_event("devnet_batch_auction_ready", &batch_id, height + 3);
        state.refresh_counters();
        state.refresh_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(ref mut map) = record {
            map.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_root())
    }

    pub fn refresh_counters(&mut self) {
        self.counters = Counters {
            batches: self.batches.len() as u64,
            bids: self.bids.len() as u64,
            reserve_attestations: self.reserve_attestations.len() as u64,
            sponsor_reservations: self.sponsor_reservations.len() as u64,
            settlements: self.settlements.len() as u64,
            receipts: self.receipts.len() as u64,
            rebates: self.rebates.len() as u64,
            fences: self.fences.len() as u64,
            events: self.events.len() as u64,
        };
    }

    pub fn refresh_roots(&mut self) {
        self.refresh_counters();
        let config_record = self.config.public_record();
        let counter_record = self.counters.public_record();
        self.roots.config_root = payload_root(&config_record);
        self.roots.counter_root = payload_root(&counter_record);
        self.roots.batch_root = map_root(
            "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-BATCH",
            &self.batches,
            BridgeBatch::public_record,
        );
        self.roots.private_bid_root = map_root(
            "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-BID",
            &self.bids,
            PrivateBid::public_record,
        );
        self.roots.reserve_attestation_root = map_root(
            "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-ATTESTATION",
            &self.reserve_attestations,
            ReserveAttestation::public_record,
        );
        self.roots.sponsor_reservation_root = map_root(
            "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-SPONSOR",
            &self.sponsor_reservations,
            LiquiditySponsorReservation::public_record,
        );
        self.roots.settlement_root = map_root(
            "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-SETTLEMENT",
            &self.settlements,
            BatchSettlement::public_record,
        );
        self.roots.receipt_root = map_root(
            "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-RECEIPT",
            &self.receipts,
            BridgeReceipt::public_record,
        );
        self.roots.rebate_root = map_root(
            "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-REBATE",
            &self.rebates,
            Rebate::public_record,
        );
        self.roots.nullifier_fence_root = set_root(
            "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-NULLIFIER-FENCE",
            &self.used_nullifier_roots,
        );
        self.roots.key_image_fence_root = set_root(
            "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-KEY-IMAGE-FENCE",
            &self.used_key_image_roots,
        );
        self.roots.replay_fence_root = set_root(
            "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-REPLAY-FENCE",
            &self.used_replay_fences,
        );
        self.roots.route_root = map_root(
            "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-ROUTE",
            &self.routes,
            RouteSnapshot::public_record,
        );
        self.roots.event_root = merkle_root(
            "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-EVENT",
            &self.events,
        );
        let root_record = self.public_record_without_root();
        self.roots.public_record_root = public_record_root(&root_record);
    }

    pub fn submit_batch(
        &mut self,
        direction: BridgeDirection,
        lane: AuctionLane,
        amount_bucket_units: u64,
        min_output_units: u64,
        order_commitment_root: String,
        encrypted_order_root: String,
        nullifier_root: String,
        key_image_root: String,
        route_hint_root: String,
        height: u64,
        nonce: &str,
    ) -> MoneroL2PqPrivateBridgeBatchAuctionRuntimeResult<String> {
        ensure_capacity(self.batches.len(), self.config.max_batches, "batches")?;
        ensure_fee(lane.fee_bps(&self.config), self.config.max_user_fee_bps)?;
        ensure_privacy_set(self.config.batch_privacy_set_size, &self.config)?;
        self.ensure_fence_unused(&nullifier_root, &key_image_root)?;
        let sequence = self.counters.batches.saturating_add(1);
        let batch_id = bridge_batch_id(
            sequence,
            direction,
            lane,
            &order_commitment_root,
            height,
            nonce,
        );
        let batch = BridgeBatch {
            batch_id: batch_id.clone(),
            sequence,
            direction,
            lane,
            status: BatchStatus::Sealed,
            asset_id: self.config.bridge_asset_id.clone(),
            amount_bucket_units,
            min_output_units,
            max_user_fee_bps: self.config.max_user_fee_bps,
            privacy_set_size: self.config.batch_privacy_set_size,
            order_commitment_root,
            encrypted_order_root,
            monero_output_root: empty_root(
                "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-MONERO-OUTPUT-PENDING",
            ),
            l2_note_root: empty_root("MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-L2-NOTE-PENDING"),
            nullifier_root: nullifier_root.clone(),
            key_image_root: key_image_root.clone(),
            route_hint_root,
            sponsor_reservation_root: empty_root(
                "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-SPONSOR-PENDING",
            ),
            reserve_attestation_root: empty_root(
                "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-ATTESTATION-PENDING",
            ),
            selected_bid_root: empty_root("MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-BID-PENDING"),
            settlement_root: empty_root(
                "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-SETTLEMENT-PENDING",
            ),
            opened_at_height: height,
            sealed_at_height: height,
            expires_at_height: height + self.config.batch_ttl_blocks,
            nonce: nonce.to_string(),
        };
        self.insert_fence(
            FenceKind::Nullifier,
            &batch_id,
            &nullifier_root,
            &self.config.replay_domain.clone(),
            height,
        );
        self.insert_fence(
            FenceKind::KeyImage,
            &batch_id,
            &key_image_root,
            &self.config.replay_domain.clone(),
            height,
        );
        self.batches.insert(batch_id.clone(), batch);
        self.push_event("batch_submitted", &batch_id, height);
        self.refresh_roots();
        Ok(batch_id)
    }

    pub fn post_private_bid(
        &mut self,
        batch_id: &str,
        solver_commitment: &str,
        encrypted_bid_root: String,
        bid_commitment_root: String,
        route_commitment_root: String,
        liquidity_source_root: String,
        expected_output_units: u64,
        solver_fee_bps: u64,
        fill_capacity_units: u64,
        height: u64,
        nonce: &str,
    ) -> MoneroL2PqPrivateBridgeBatchAuctionRuntimeResult<String> {
        ensure_capacity(self.bids.len(), self.config.max_bids, "bids")?;
        ensure_fee(solver_fee_bps, self.config.max_solver_fee_bps)?;
        let batch = self
            .batches
            .get(batch_id)
            .ok_or_else(|| format!("unknown batch: {batch_id}"))?;
        if !batch.status.auctionable() {
            return Err(format!(
                "batch is not auctionable: {}",
                batch.status.as_str()
            ));
        }
        if height > batch.expires_at_height {
            return Err("batch expired".to_string());
        }
        let bid_id = private_bid_id(
            batch_id,
            solver_commitment,
            &bid_commitment_root,
            height,
            nonce,
        );
        let bid = PrivateBid {
            bid_id: bid_id.clone(),
            batch_id: batch_id.to_string(),
            solver_commitment: solver_commitment.to_string(),
            status: BidStatus::Eligible,
            lane: batch.lane,
            encrypted_bid_root,
            bid_commitment_root,
            route_commitment_root,
            liquidity_source_root,
            expected_output_units,
            solver_fee_bps,
            rebate_bps: self.config.rebate_bps,
            fill_capacity_units,
            reserve_attestation_root: empty_root(
                "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-BID-ATTESTATION-PENDING",
            ),
            sponsor_reservation_root: empty_root(
                "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-BID-SPONSOR-PENDING",
            ),
            pq_signature_root: tagged_root(&format!("bid-pq-signature-{bid_id}")),
            submitted_at_height: height,
            reveal_deadline_height: height + self.config.bid_ttl_blocks,
            expires_at_height: height + self.config.bid_ttl_blocks,
            nonce: nonce.to_string(),
        };
        self.bids.insert(bid_id.clone(), bid);
        self.insert_fence(
            FenceKind::BidCommitment,
            &bid_id,
            &tagged_root(&bid_id),
            &self.config.replay_domain.clone(),
            height,
        );
        self.push_event("private_bid_posted", &bid_id, height);
        self.refresh_roots();
        Ok(bid_id)
    }

    pub fn record_reserve_attestation(
        &mut self,
        batch_id: &str,
        signer_commitment: &str,
        monero_reserve_root: String,
        l2_reserve_root: String,
        route_liquidity_root: String,
        liability_root: String,
        reserve_capacity_units: u64,
        pending_liability_units: u64,
        pq_security_bits: u16,
        height: u64,
    ) -> MoneroL2PqPrivateBridgeBatchAuctionRuntimeResult<String> {
        ensure_capacity(
            self.reserve_attestations.len(),
            self.config.max_attestations,
            "reserve_attestations",
        )?;
        let coverage_bps = reserve_coverage_bps(reserve_capacity_units, pending_liability_units);
        if coverage_bps < self.config.min_reserve_coverage_bps {
            return Err("reserve coverage below minimum".to_string());
        }
        if pq_security_bits < self.config.min_pq_security_bits {
            return Err("pq security bits below minimum".to_string());
        }
        let attestation_id = reserve_attestation_id(
            batch_id,
            signer_commitment,
            &monero_reserve_root,
            &l2_reserve_root,
            height,
        );
        let status = if coverage_bps >= self.config.target_reserve_coverage_bps
            && pq_security_bits >= self.config.target_pq_security_bits
        {
            AttestationStatus::QuorumAccepted
        } else {
            AttestationStatus::Accepted
        };
        let attestation = ReserveAttestation {
            attestation_id: attestation_id.clone(),
            batch_id: batch_id.to_string(),
            signer_commitment: signer_commitment.to_string(),
            status,
            monero_reserve_root,
            l2_reserve_root,
            route_liquidity_root,
            liability_root,
            witness_set_root: tagged_root(&format!("reserve-witness-{attestation_id}")),
            pq_signature_root: tagged_root(&format!("reserve-pq-signature-{attestation_id}")),
            reserve_capacity_units,
            pending_liability_units,
            coverage_bps,
            pq_security_bits,
            signed_at_height: height,
            expires_at_height: height + self.config.settlement_ttl_blocks,
        };
        if let Some(batch) = self.batches.get_mut(batch_id) {
            batch.reserve_attestation_root = attestation_id.clone();
            if matches!(batch.status, BatchStatus::Sealed | BatchStatus::Sponsored) {
                batch.status = BatchStatus::ReserveAttested;
            }
        }
        self.reserve_attestations
            .insert(attestation_id.clone(), attestation);
        self.push_event("reserve_attestation_recorded", &attestation_id, height);
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn reserve_sponsor_liquidity(
        &mut self,
        sponsor_commitment: &str,
        batch_id: &str,
        bid_id: &str,
        budget_units: u64,
        reserved_units: u64,
        applied_fee_bps: u64,
        max_rebate_bps: u64,
        height: u64,
    ) -> MoneroL2PqPrivateBridgeBatchAuctionRuntimeResult<String> {
        ensure_capacity(
            self.sponsor_reservations.len(),
            self.config.max_sponsor_reservations,
            "sponsor_reservations",
        )?;
        ensure_fee(applied_fee_bps, self.config.max_user_fee_bps)?;
        ensure_fee(max_rebate_bps, self.config.rebate_bps.max(max_rebate_bps))?;
        if !self.batches.contains_key(batch_id) {
            return Err(format!("unknown batch: {batch_id}"));
        }
        if !self.bids.contains_key(bid_id) {
            return Err(format!("unknown bid: {bid_id}"));
        }
        let reservation_id = sponsor_reservation_id(
            sponsor_commitment,
            batch_id,
            bid_id,
            applied_fee_bps,
            height,
        );
        let reservation = LiquiditySponsorReservation {
            reservation_id: reservation_id.clone(),
            sponsor_commitment: sponsor_commitment.to_string(),
            batch_id: batch_id.to_string(),
            bid_id: bid_id.to_string(),
            status: ReservationStatus::Reserved,
            asset_id: self.config.fee_asset_id.clone(),
            budget_units,
            reserved_units,
            applied_fee_bps,
            max_rebate_bps,
            route_policy_root: tagged_root(&format!("sponsor-route-policy-{reservation_id}")),
            privacy_policy_root: tagged_root(&format!("sponsor-privacy-policy-{reservation_id}")),
            opened_at_height: height,
            expires_at_height: height + self.config.reservation_ttl_blocks,
        };
        if let Some(batch) = self.batches.get_mut(batch_id) {
            batch.sponsor_reservation_root = reservation_id.clone();
            if matches!(batch.status, BatchStatus::Sealed) {
                batch.status = BatchStatus::Sponsored;
            }
        }
        if let Some(bid) = self.bids.get_mut(bid_id) {
            bid.sponsor_reservation_root = reservation_id.clone();
        }
        self.sponsor_reservations
            .insert(reservation_id.clone(), reservation);
        self.insert_fence(
            FenceKind::SponsorReservation,
            &reservation_id,
            &tagged_root(&reservation_id),
            &self.config.replay_domain.clone(),
            height,
        );
        self.push_event("sponsor_liquidity_reserved", &reservation_id, height);
        self.refresh_roots();
        Ok(reservation_id)
    }

    pub fn select_bid(
        &mut self,
        batch_id: &str,
        bid_id: &str,
        height: u64,
    ) -> MoneroL2PqPrivateBridgeBatchAuctionRuntimeResult<()> {
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| format!("unknown batch: {batch_id}"))?;
        if !batch.status.auctionable() {
            return Err(format!(
                "batch is not auctionable: {}",
                batch.status.as_str()
            ));
        }
        let bid = self
            .bids
            .get_mut(bid_id)
            .ok_or_else(|| format!("unknown bid: {bid_id}"))?;
        if bid.batch_id != batch_id {
            return Err("bid belongs to a different batch".to_string());
        }
        if bid.expected_output_units < batch.min_output_units {
            return Err("bid output below batch minimum".to_string());
        }
        bid.status = BidStatus::Selected;
        batch.status = BatchStatus::Auctioned;
        batch.selected_bid_root = bid_id.to_string();
        self.push_event("bid_selected", bid_id, height);
        self.refresh_roots();
        Ok(())
    }

    pub fn settle_batch(
        &mut self,
        batch_id: &str,
        selected_bid_id: &str,
        gross_input_units: u64,
        net_output_units: u64,
        monero_release_root: String,
        l2_release_root: String,
        defi_route_root: String,
        height: u64,
        nonce: &str,
    ) -> MoneroL2PqPrivateBridgeBatchAuctionRuntimeResult<String> {
        ensure_capacity(
            self.settlements.len(),
            self.config.max_settlements,
            "settlements",
        )?;
        let batch = self
            .batches
            .get(batch_id)
            .ok_or_else(|| format!("unknown batch: {batch_id}"))?
            .clone();
        let bid = self
            .bids
            .get(selected_bid_id)
            .ok_or_else(|| format!("unknown bid: {selected_bid_id}"))?
            .clone();
        if bid.batch_id != batch_id {
            return Err("selected bid belongs to a different batch".to_string());
        }
        if !matches!(
            batch.status,
            BatchStatus::Auctioned | BatchStatus::ReserveAttested
        ) {
            return Err("batch is not ready for settlement".to_string());
        }
        if net_output_units < batch.min_output_units {
            return Err("net output below batch minimum".to_string());
        }
        let settlement_id = settlement_id(
            batch_id,
            selected_bid_id,
            &batch.reserve_attestation_root,
            height,
            nonce,
        );
        let solver_fee_units = fee_units(gross_input_units, bid.solver_fee_bps);
        let sponsor_rebate_units = fee_units(gross_input_units, bid.rebate_bps);
        let settlement = BatchSettlement {
            settlement_id: settlement_id.clone(),
            batch_id: batch_id.to_string(),
            selected_bid_id: selected_bid_id.to_string(),
            status: SettlementStatus::Proposed,
            direction: batch.direction,
            gross_input_units,
            net_output_units,
            solver_fee_units,
            sponsor_rebate_units,
            monero_release_root,
            l2_release_root,
            defi_route_root,
            reserve_delta_root: tagged_root(&format!("reserve-delta-{settlement_id}")),
            nullifier_fence_root: batch.nullifier_root.clone(),
            receipt_root: empty_root(
                "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-SETTLEMENT-RECEIPT-PENDING",
            ),
            pq_attestation_root: batch.reserve_attestation_root.clone(),
            proposed_at_height: height,
            executable_at_height: height + 1,
            finalized_at_height: height + self.config.settlement_ttl_blocks,
        };
        if let Some(batch) = self.batches.get_mut(batch_id) {
            batch.status = BatchStatus::Settling;
            batch.settlement_root = settlement_id.clone();
        }
        if let Some(bid) = self.bids.get_mut(selected_bid_id) {
            bid.status = BidStatus::Settled;
        }
        self.settlements.insert(settlement_id.clone(), settlement);
        self.push_event("batch_settlement_proposed", &settlement_id, height);
        self.refresh_roots();
        Ok(settlement_id)
    }

    pub fn publish_receipt(
        &mut self,
        settlement_id: &str,
        owner_commitment: &str,
        output_commitment_root: String,
        fee_receipt_root: String,
        privacy_receipt_root: String,
        delivered_units: u64,
        paid_fee_units: u64,
        height: u64,
    ) -> MoneroL2PqPrivateBridgeBatchAuctionRuntimeResult<String> {
        ensure_capacity(self.receipts.len(), self.config.max_receipts, "receipts")?;
        let settlement = self
            .settlements
            .get(settlement_id)
            .ok_or_else(|| format!("unknown settlement: {settlement_id}"))?
            .clone();
        let receipt_id = receipt_id(
            settlement_id,
            &settlement.batch_id,
            owner_commitment,
            height,
        );
        let rebate_units = fee_units(delivered_units, self.config.rebate_bps);
        let rebate_root = rebate_id(
            &receipt_id,
            &settlement.selected_bid_id,
            owner_commitment,
            height,
        );
        let receipt = BridgeReceipt {
            receipt_id: receipt_id.clone(),
            settlement_id: settlement_id.to_string(),
            batch_id: settlement.batch_id.clone(),
            owner_commitment: owner_commitment.to_string(),
            output_commitment_root,
            fee_receipt_root,
            rebate_root,
            privacy_receipt_root,
            delivered_units,
            paid_fee_units,
            rebate_units,
            issued_at_height: height,
            final_at_height: height + self.config.receipt_finality_blocks,
        };
        if let Some(settlement) = self.settlements.get_mut(settlement_id) {
            settlement.status = SettlementStatus::ReceiptPublished;
            settlement.receipt_root = receipt_id.clone();
        }
        self.receipts.insert(receipt_id.clone(), receipt);
        self.insert_fence(
            FenceKind::Receipt,
            &receipt_id,
            &tagged_root(&receipt_id),
            &self.config.replay_domain.clone(),
            height,
        );
        self.push_event("receipt_published", &receipt_id, height);
        self.refresh_roots();
        Ok(receipt_id)
    }

    pub fn issue_rebate(
        &mut self,
        receipt_id: &str,
        sponsor_reservation_id: &str,
        owner_commitment: &str,
        amount_units: u64,
        height: u64,
    ) -> MoneroL2PqPrivateBridgeBatchAuctionRuntimeResult<String> {
        ensure_capacity(self.rebates.len(), self.config.max_rebates, "rebates")?;
        if !self.receipts.contains_key(receipt_id) {
            return Err(format!("unknown receipt: {receipt_id}"));
        }
        if !self
            .sponsor_reservations
            .contains_key(sponsor_reservation_id)
        {
            return Err(format!(
                "unknown sponsor reservation: {sponsor_reservation_id}"
            ));
        }
        let rebate_id = rebate_id(receipt_id, sponsor_reservation_id, owner_commitment, height);
        let rebate = Rebate {
            rebate_id: rebate_id.clone(),
            receipt_id: receipt_id.to_string(),
            sponsor_reservation_id: sponsor_reservation_id.to_string(),
            owner_commitment: owner_commitment.to_string(),
            asset_id: self.config.fee_asset_id.clone(),
            amount_units,
            rebate_bps: self.config.rebate_bps,
            claim_nullifier_root: tagged_root(&format!("rebate-nullifier-{rebate_id}")),
            claim_note_root: tagged_root(&format!("rebate-note-{rebate_id}")),
            expires_at_height: height + self.config.settlement_ttl_blocks,
        };
        if let Some(reservation) = self.sponsor_reservations.get_mut(sponsor_reservation_id) {
            reservation.status = ReservationStatus::Consumed;
        }
        self.rebates.insert(rebate_id.clone(), rebate);
        self.insert_fence(
            FenceKind::Rebate,
            &rebate_id,
            &tagged_root(&rebate_id),
            &self.config.replay_domain.clone(),
            height,
        );
        self.push_event("rebate_issued", &rebate_id, height);
        self.refresh_roots();
        Ok(rebate_id)
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "batch_root": self.roots.batch_root,
            "private_bid_root": self.roots.private_bid_root,
            "reserve_attestation_root": self.roots.reserve_attestation_root,
            "sponsor_reservation_root": self.roots.sponsor_reservation_root,
            "settlement_root": self.roots.settlement_root,
            "receipt_root": self.roots.receipt_root,
            "rebate_root": self.roots.rebate_root,
            "nullifier_fence_root": self.roots.nullifier_fence_root,
            "key_image_fence_root": self.roots.key_image_fence_root,
            "replay_fence_root": self.roots.replay_fence_root,
            "route_root": self.roots.route_root,
            "event_root": self.roots.event_root,
        })
    }

    fn ensure_fence_unused(
        &self,
        nullifier_root: &str,
        key_image_root: &str,
    ) -> MoneroL2PqPrivateBridgeBatchAuctionRuntimeResult<()> {
        if self.used_nullifier_roots.contains(nullifier_root) {
            return Err("nullifier fence already used".to_string());
        }
        if self.used_key_image_roots.contains(key_image_root) {
            return Err("key image fence already used".to_string());
        }
        Ok(())
    }

    fn insert_fence(
        &mut self,
        kind: FenceKind,
        subject_id: &str,
        commitment_root: &str,
        domain: &str,
        height: u64,
    ) -> String {
        let fence_id = privacy_fence_id(kind, subject_id, commitment_root, domain, height);
        let fence = PrivacyFence {
            fence_id: fence_id.clone(),
            kind,
            subject_id: subject_id.to_string(),
            commitment_root: commitment_root.to_string(),
            domain: domain.to_string(),
            opened_at_height: height,
        };
        match kind {
            FenceKind::Nullifier => {
                self.used_nullifier_roots
                    .insert(commitment_root.to_string());
            }
            FenceKind::KeyImage => {
                self.used_key_image_roots
                    .insert(commitment_root.to_string());
            }
            _ => {
                self.used_replay_fences.insert(fence_id.clone());
            }
        }
        self.fences.insert(fence_id.clone(), fence);
        fence_id
    }

    fn push_event(&mut self, event_type: &str, subject_id: &str, height: u64) {
        let payload = json!({
            "event_type": event_type,
            "subject_id": subject_id,
            "height": height,
            "sequence": self.events.len() + 1,
        });
        let event_id = event_id(event_type, subject_id, &payload, height);
        self.events.push(
            EventRecord {
                event_id,
                event_type: event_type.to_string(),
                subject_id: subject_id.to_string(),
                payload_root: payload_root(&payload),
                height,
            }
            .public_record(),
        );
    }
}

pub fn payload_root(payload: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-PAYLOAD",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-RECORD",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn public_record_root(record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-PUBLIC-RECORD",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-STATE",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn bridge_batch_id(
    sequence: u64,
    direction: BridgeDirection,
    lane: AuctionLane,
    order_commitment_root: &str,
    opened_at_height: u64,
    nonce: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(direction.as_str()),
            HashPart::Str(lane.as_str()),
            HashPart::Str(order_commitment_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn private_bid_id(
    batch_id: &str,
    solver_commitment: &str,
    bid_commitment_root: &str,
    submitted_at_height: u64,
    nonce: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Str(solver_commitment),
            HashPart::Str(bid_commitment_root),
            HashPart::Int(submitted_at_height as i128),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn reserve_attestation_id(
    batch_id: &str,
    signer_commitment: &str,
    monero_reserve_root: &str,
    l2_reserve_root: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-RESERVE-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Str(signer_commitment),
            HashPart::Str(monero_reserve_root),
            HashPart::Str(l2_reserve_root),
            HashPart::Int(signed_at_height as i128),
        ],
        32,
    )
}

pub fn sponsor_reservation_id(
    sponsor_commitment: &str,
    batch_id: &str,
    bid_id: &str,
    applied_fee_bps: u64,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-SPONSOR-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(batch_id),
            HashPart::Str(bid_id),
            HashPart::Int(applied_fee_bps as i128),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn settlement_id(
    batch_id: &str,
    selected_bid_id: &str,
    reserve_attestation_root: &str,
    proposed_at_height: u64,
    nonce: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-SETTLEMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Str(selected_bid_id),
            HashPart::Str(reserve_attestation_root),
            HashPart::Int(proposed_at_height as i128),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn receipt_id(
    settlement_id: &str,
    batch_id: &str,
    owner_commitment: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(settlement_id),
            HashPart::Str(batch_id),
            HashPart::Str(owner_commitment),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

pub fn rebate_id(
    receipt_id: &str,
    sponsor_reservation_id: &str,
    owner_commitment: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(receipt_id),
            HashPart::Str(sponsor_reservation_id),
            HashPart::Str(owner_commitment),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

pub fn privacy_fence_id(
    kind: FenceKind,
    subject_id: &str,
    commitment_root: &str,
    domain: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-PRIVACY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(commitment_root),
            HashPart::Str(domain),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn route_snapshot_id(batch_id: &str, lane: AuctionLane, recorded_at_height: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-ROUTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Str(lane.as_str()),
            HashPart::Int(recorded_at_height as i128),
        ],
        32,
    )
}

pub fn event_id(event_type: &str, subject_id: &str, payload: &Value, height: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(event_type),
            HashPart::Str(subject_id),
            HashPart::Json(payload),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn reserve_coverage_bps(reserve_capacity_units: u64, pending_liability_units: u64) -> u64 {
    if pending_liability_units == 0 {
        return MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_MAX_BPS * 10;
    }
    reserve_capacity_units.saturating_mul(MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_MAX_BPS)
        / pending_liability_units
}

pub fn fee_units(amount_units: u64, fee_bps: u64) -> u64 {
    amount_units.saturating_mul(fee_bps) / MONERO_L2_PQ_PRIVATE_BRIDGE_BATCH_AUCTION_RUNTIME_MAX_BPS
}

fn ensure_capacity(
    current: usize,
    max: usize,
    label: &str,
) -> MoneroL2PqPrivateBridgeBatchAuctionRuntimeResult<()> {
    if current >= max {
        return Err(format!("{label} capacity exceeded"));
    }
    Ok(())
}

fn ensure_fee(
    fee_bps: u64,
    max_fee_bps: u64,
) -> MoneroL2PqPrivateBridgeBatchAuctionRuntimeResult<()> {
    if fee_bps > max_fee_bps {
        return Err(format!("fee {fee_bps} bps exceeds max {max_fee_bps} bps"));
    }
    Ok(())
}

fn ensure_privacy_set(
    size: u64,
    config: &Config,
) -> MoneroL2PqPrivateBridgeBatchAuctionRuntimeResult<()> {
    if size < config.min_privacy_set_size {
        return Err("privacy set below minimum".to_string());
    }
    Ok(())
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &Vec::<Value>::new())
}

fn tagged_root(tag: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-BRIDGE-BATCH-AUCTION-TAGGED-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(tag)],
        32,
    )
}

fn value_root(domain: &str, leaves: Vec<Value>) -> String {
    merkle_root(domain, &leaves)
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves: Vec<Value> = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "record": public_record(value),
            })
        })
        .collect();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves: Vec<Value> = set.iter().map(|value| json!({ "value": value })).collect();
    merkle_root(domain, &leaves)
}
