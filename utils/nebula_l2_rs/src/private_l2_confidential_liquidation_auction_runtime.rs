use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialLiquidationAuctionRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-liquidation-auction-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_MARKET_SCHEME: &str =
    "ml-kem-1024+zk-shielded-liquidation-market-v1";
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_PRIVATE_BID_SCHEME: &str =
    "commit-reveal-private-liquidation-bid-v1";
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_RISK_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256s-risk-attestation-v1";
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_KEEPER_RESERVATION_SCHEME: &str =
    "roots-only-low-fee-keeper-reservation-v1";
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_SEALED_BATCH_SCHEME: &str =
    "zk-pq-sealed-liquidation-auction-batch-v1";
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_SETTLEMENT_RECEIPT_SCHEME: &str =
    "zk-pq-private-liquidation-settlement-receipt-v1";
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_REBATE_SCHEME: &str =
    "roots-only-private-liquidation-keeper-rebate-v1";
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MONERO_NETWORK: &str =
    "monero-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_LOW_FEE_LANE: &str =
    "devnet-private-l2-liquidation-low-fee";
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEVNET_HEIGHT: u64 = 493_000;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_AUCTION_WINDOW_BLOCKS: u64 =
    6;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MARKET_TTL_BLOCKS: u64 = 72;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_BID_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS: u64 =
    12;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS: u64 = 24;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 =
    18;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_REBATE_EPOCH_BLOCKS: u64 =
    1_440;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MAX_MARKETS: usize = 262_144;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MAX_PRIVATE_BIDS: usize =
    1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MAX_RISK_ATTESTATIONS: usize =
    1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MAX_KEEPER_RESERVATIONS:
    usize = 524_288;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MAX_BATCHES: usize = 131_072;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MAX_MARKETS_PER_BATCH: usize =
    512;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MAX_BIDS_PER_MARKET: usize =
    256;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 =
    512;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 =
    4_096;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 =
    256;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MAX_KEEPER_FEE_BPS: u64 = 22;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MIN_LIQUIDATION_BONUS_BPS:
    u64 = 150;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MAX_LIQUIDATION_BONUS_BPS:
    u64 = 1_200;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MIN_REBATE_BPS: u64 = 3;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MAX_REBATE_BPS: u64 = 20;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_KEEPER_BUDGET_MICRO_UNITS:
    u64 = 500_000_000;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidationMarketKind {
    LendingCollateral,
    PerpMargin,
    OptionsMargin,
    CreditVault,
    StablecoinPeg,
    CrossMarginNetting,
    InsuranceBackstop,
    BridgeReserve,
}

impl LiquidationMarketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LendingCollateral => "lending_collateral",
            Self::PerpMargin => "perp_margin",
            Self::OptionsMargin => "options_margin",
            Self::CreditVault => "credit_vault",
            Self::StablecoinPeg => "stablecoin_peg",
            Self::CrossMarginNetting => "cross_margin_netting",
            Self::InsuranceBackstop => "insurance_backstop",
            Self::BridgeReserve => "bridge_reserve",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollateralVenue {
    PrivateAmm,
    Darkpool,
    LendingPool,
    PerpEngine,
    VaultRouter,
    StableSwap,
    BridgeReserve,
    InternalNetting,
}

impl CollateralVenue {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateAmm => "private_amm",
            Self::Darkpool => "darkpool",
            Self::LendingPool => "lending_pool",
            Self::PerpEngine => "perp_engine",
            Self::VaultRouter => "vault_router",
            Self::StableSwap => "stable_swap",
            Self::BridgeReserve => "bridge_reserve",
            Self::InternalNetting => "internal_netting",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketStatus {
    Submitted,
    RiskAttested,
    Reservable,
    Bidding,
    Batched,
    Settled,
    Paused,
    Rejected,
    Expired,
}

impl MarketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::RiskAttested => "risk_attested",
            Self::Reservable => "reservable",
            Self::Bidding => "bidding",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Paused => "paused",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_attestation(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::RiskAttested | Self::Reservable
        )
    }

    pub fn accepts_reservation(self) -> bool {
        matches!(self, Self::RiskAttested | Self::Reservable | Self::Bidding)
    }

    pub fn accepts_bid(self) -> bool {
        matches!(self, Self::RiskAttested | Self::Reservable | Self::Bidding)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BidKind {
    FullRepay,
    PartialRepay,
    DutchDiscount,
    BackstopTakeover,
    NettingFill,
    FlashClose,
    InsuranceAbsorb,
}

impl BidKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FullRepay => "full_repay",
            Self::PartialRepay => "partial_repay",
            Self::DutchDiscount => "dutch_discount",
            Self::BackstopTakeover => "backstop_takeover",
            Self::NettingFill => "netting_fill",
            Self::FlashClose => "flash_close",
            Self::InsuranceAbsorb => "insurance_absorb",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateBidStatus {
    Committed,
    FeeProved,
    Reserved,
    Selected,
    Settled,
    Rejected,
    Expired,
}

impl PrivateBidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::FeeProved => "fee_proved",
            Self::Reserved => "reserved",
            Self::Selected => "selected",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn selectable(self) -> bool {
        matches!(self, Self::Committed | Self::FeeProved | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskVerdict {
    Healthy,
    Watch,
    ReduceOnly,
    Liquidatable,
    ProtocolBackstop,
    HaltLiquidation,
    Quarantine,
}

impl RiskVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Watch => "watch",
            Self::ReduceOnly => "reduce_only",
            Self::Liquidatable => "liquidatable",
            Self::ProtocolBackstop => "protocol_backstop",
            Self::HaltLiquidation => "halt_liquidation",
            Self::Quarantine => "quarantine",
        }
    }

    pub fn allows_liquidation(self) -> bool {
        matches!(
            self,
            Self::ReduceOnly | Self::Liquidatable | Self::ProtocolBackstop
        )
    }

    pub fn severity(self) -> u64 {
        match self {
            Self::Healthy => 0,
            Self::Watch => 1,
            Self::ReduceOnly => 2,
            Self::Liquidatable => 3,
            Self::ProtocolBackstop => 4,
            Self::HaltLiquidation => 5,
            Self::Quarantine => 6,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Recorded,
    Accepted,
    Superseded,
    Rejected,
    Expired,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Accepted => "accepted",
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
    Sealed,
    SettlementReady,
    Settled,
    Disputed,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::Sealed => "sealed",
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accrued,
    Reserved,
    Paid,
    ClawedBack,
    Expired,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accrued => "accrued",
            Self::Reserved => "reserved",
            Self::Paid => "paid",
            Self::ClawedBack => "clawed_back",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    MarketOpened,
    RiskAccepted,
    KeeperReserved,
    BidSelected,
    BatchSettled,
    RebatePaid,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MarketOpened => "market_opened",
            Self::RiskAccepted => "risk_accepted",
            Self::KeeperReserved => "keeper_reserved",
            Self::BidSelected => "bid_selected",
            Self::BatchSettled => "batch_settled",
            Self::RebatePaid => "rebate_paid",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub low_fee_lane: String,
    pub hash_suite: String,
    pub shielded_market_scheme: String,
    pub private_bid_scheme: String,
    pub pq_risk_attestation_scheme: String,
    pub keeper_reservation_scheme: String,
    pub sealed_batch_scheme: String,
    pub settlement_receipt_scheme: String,
    pub rebate_scheme: String,
    pub auction_window_blocks: u64,
    pub market_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub rebate_epoch_blocks: u64,
    pub max_markets: usize,
    pub max_private_bids: usize,
    pub max_risk_attestations: usize,
    pub max_keeper_reservations: usize,
    pub max_batches: usize,
    pub max_markets_per_batch: usize,
    pub max_bids_per_market: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_keeper_fee_bps: u64,
    pub min_liquidation_bonus_bps: u64,
    pub max_liquidation_bonus_bps: u64,
    pub min_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub keeper_budget_micro_units: u64,
    pub require_private_bids: bool,
    pub require_pq_risk_attestations: bool,
    pub require_low_fee_reservations: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MONERO_NETWORK
                    .to_string(),
            low_fee_lane:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_LOW_FEE_LANE
                    .to_string(),
            hash_suite: PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_HASH_SUITE.to_string(),
            shielded_market_scheme:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_MARKET_SCHEME.to_string(),
            private_bid_scheme:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_PRIVATE_BID_SCHEME.to_string(),
            pq_risk_attestation_scheme:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_RISK_ATTESTATION_SCHEME
                    .to_string(),
            keeper_reservation_scheme:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_KEEPER_RESERVATION_SCHEME
                    .to_string(),
            sealed_batch_scheme:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_SEALED_BATCH_SCHEME.to_string(),
            settlement_receipt_scheme:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_SETTLEMENT_RECEIPT_SCHEME
                    .to_string(),
            rebate_scheme: PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_REBATE_SCHEME
                .to_string(),
            auction_window_blocks:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_AUCTION_WINDOW_BLOCKS,
            market_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MARKET_TTL_BLOCKS,
            bid_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_BID_TTL_BLOCKS,
            reservation_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            batch_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
            settlement_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            rebate_epoch_blocks:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_REBATE_EPOCH_BLOCKS,
            max_markets: PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MAX_MARKETS,
            max_private_bids:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MAX_PRIVATE_BIDS,
            max_risk_attestations:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MAX_RISK_ATTESTATIONS,
            max_keeper_reservations:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MAX_KEEPER_RESERVATIONS,
            max_batches: PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MAX_BATCHES,
            max_markets_per_batch:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MAX_MARKETS_PER_BATCH,
            max_bids_per_market:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MAX_BIDS_PER_MARKET,
            min_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            max_keeper_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MAX_KEEPER_FEE_BPS,
            min_liquidation_bonus_bps:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MIN_LIQUIDATION_BONUS_BPS,
            max_liquidation_bonus_bps:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MAX_LIQUIDATION_BONUS_BPS,
            min_rebate_bps:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MIN_REBATE_BPS,
            max_rebate_bps:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_MAX_REBATE_BPS,
            keeper_budget_micro_units:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEFAULT_KEEPER_BUDGET_MICRO_UNITS,
            require_private_bids: true,
            require_pq_risk_attestations: true,
            require_low_fee_reservations: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_liquidation_auction_config",
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "low_fee_lane": self.low_fee_lane,
            "hash_suite": self.hash_suite,
            "shielded_market_scheme": self.shielded_market_scheme,
            "private_bid_scheme": self.private_bid_scheme,
            "pq_risk_attestation_scheme": self.pq_risk_attestation_scheme,
            "keeper_reservation_scheme": self.keeper_reservation_scheme,
            "sealed_batch_scheme": self.sealed_batch_scheme,
            "settlement_receipt_scheme": self.settlement_receipt_scheme,
            "rebate_scheme": self.rebate_scheme,
            "auction_window_blocks": self.auction_window_blocks,
            "market_ttl_blocks": self.market_ttl_blocks,
            "bid_ttl_blocks": self.bid_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "rebate_epoch_blocks": self.rebate_epoch_blocks,
            "max_markets": self.max_markets,
            "max_private_bids": self.max_private_bids,
            "max_risk_attestations": self.max_risk_attestations,
            "max_keeper_reservations": self.max_keeper_reservations,
            "max_batches": self.max_batches,
            "max_markets_per_batch": self.max_markets_per_batch,
            "max_bids_per_market": self.max_bids_per_market,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_keeper_fee_bps": self.max_keeper_fee_bps,
            "min_liquidation_bonus_bps": self.min_liquidation_bonus_bps,
            "max_liquidation_bonus_bps": self.max_liquidation_bonus_bps,
            "min_rebate_bps": self.min_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "keeper_budget_micro_units": self.keeper_budget_micro_units,
            "require_private_bids": self.require_private_bids,
            "require_pq_risk_attestations": self.require_pq_risk_attestations,
            "require_low_fee_reservations": self.require_low_fee_reservations,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub next_market_nonce: u64,
    pub next_bid_nonce: u64,
    pub next_risk_attestation_nonce: u64,
    pub next_keeper_reservation_nonce: u64,
    pub next_batch_nonce: u64,
    pub next_receipt_nonce: u64,
    pub next_rebate_nonce: u64,
    pub shielded_markets_opened: u64,
    pub private_bids_committed: u64,
    pub pq_attestations_accepted: u64,
    pub keeper_reservations_opened: u64,
    pub sealed_batches_built: u64,
    pub settlements_published: u64,
    pub rebates_paid: u64,
    pub consumed_nullifiers: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_liquidation_auction_counters",
            "next_market_nonce": self.next_market_nonce,
            "next_bid_nonce": self.next_bid_nonce,
            "next_risk_attestation_nonce": self.next_risk_attestation_nonce,
            "next_keeper_reservation_nonce": self.next_keeper_reservation_nonce,
            "next_batch_nonce": self.next_batch_nonce,
            "next_receipt_nonce": self.next_receipt_nonce,
            "next_rebate_nonce": self.next_rebate_nonce,
            "shielded_markets_opened": self.shielded_markets_opened,
            "private_bids_committed": self.private_bids_committed,
            "pq_attestations_accepted": self.pq_attestations_accepted,
            "keeper_reservations_opened": self.keeper_reservations_opened,
            "sealed_batches_built": self.sealed_batches_built,
            "settlements_published": self.settlements_published,
            "rebates_paid": self.rebates_paid,
            "consumed_nullifiers": self.consumed_nullifiers,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedMarketRequest {
    pub market_kind: LiquidationMarketKind,
    pub collateral_venue: CollateralVenue,
    pub sponsor_commitment: String,
    pub borrower_commitment: String,
    pub position_commitment_root: String,
    pub collateral_asset_root: String,
    pub debt_asset_root: String,
    pub seized_collateral_commitment_root: String,
    pub repay_amount_commitment_root: String,
    pub health_factor_commitment_root: String,
    pub oracle_price_root: String,
    pub sealed_terms_root: String,
    pub encrypted_payload_root: String,
    pub nullifier_root: String,
    pub max_user_fee_bps: u64,
    pub liquidation_bonus_bps: u64,
    pub min_privacy_set_size: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl ShieldedMarketRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialLiquidationAuctionRuntimeResult<()> {
        require_non_empty("sponsor commitment", &self.sponsor_commitment)?;
        require_non_empty("borrower commitment", &self.borrower_commitment)?;
        require_root("position commitment root", &self.position_commitment_root)?;
        require_root("collateral asset root", &self.collateral_asset_root)?;
        require_root("debt asset root", &self.debt_asset_root)?;
        require_root(
            "seized collateral commitment root",
            &self.seized_collateral_commitment_root,
        )?;
        require_root(
            "repay amount commitment root",
            &self.repay_amount_commitment_root,
        )?;
        require_root(
            "health factor commitment root",
            &self.health_factor_commitment_root,
        )?;
        require_root("oracle price root", &self.oracle_price_root)?;
        require_root("sealed terms root", &self.sealed_terms_root)?;
        require_root("encrypted payload root", &self.encrypted_payload_root)?;
        require_root("nullifier root", &self.nullifier_root)?;
        require_bps("max user fee bps", self.max_user_fee_bps)?;
        require_bps("liquidation bonus bps", self.liquidation_bonus_bps)?;
        if self.max_user_fee_bps > config.max_user_fee_bps {
            return Err("user fee exceeds configured cap".to_string());
        }
        if self.liquidation_bonus_bps < config.min_liquidation_bonus_bps
            || self.liquidation_bonus_bps > config.max_liquidation_bonus_bps
        {
            return Err("liquidation bonus outside configured bounds".to_string());
        }
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("market privacy set below configured minimum".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("market expiration must be after open height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "market_kind": self.market_kind.as_str(),
            "collateral_venue": self.collateral_venue.as_str(),
            "sponsor_commitment": self.sponsor_commitment,
            "borrower_commitment": self.borrower_commitment,
            "position_commitment_root": self.position_commitment_root,
            "collateral_asset_root": self.collateral_asset_root,
            "debt_asset_root": self.debt_asset_root,
            "seized_collateral_commitment_root": self.seized_collateral_commitment_root,
            "repay_amount_commitment_root": self.repay_amount_commitment_root,
            "health_factor_commitment_root": self.health_factor_commitment_root,
            "oracle_price_root": self.oracle_price_root,
            "sealed_terms_root": self.sealed_terms_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "nullifier_root": self.nullifier_root,
            "max_user_fee_bps": self.max_user_fee_bps,
            "liquidation_bonus_bps": self.liquidation_bonus_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateBidRequest {
    pub market_id: String,
    pub bid_kind: BidKind,
    pub keeper_commitment: String,
    pub bid_commitment_root: String,
    pub repay_commitment_root: String,
    pub receive_note_root: String,
    pub route_commitment_root: String,
    pub sealed_bid_root: String,
    pub encrypted_payload_root: String,
    pub pq_authorization_root: String,
    pub fee_ceiling_proof_root: String,
    pub max_keeper_fee_bps: u64,
    pub requested_rebate_bps: u64,
    pub priority_micro_units: u64,
    pub min_privacy_set_size: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivateBidRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialLiquidationAuctionRuntimeResult<()> {
        require_non_empty("market id", &self.market_id)?;
        require_non_empty("keeper commitment", &self.keeper_commitment)?;
        require_root("bid commitment root", &self.bid_commitment_root)?;
        require_root("repay commitment root", &self.repay_commitment_root)?;
        require_root("receive note root", &self.receive_note_root)?;
        require_root("route commitment root", &self.route_commitment_root)?;
        require_root("sealed bid root", &self.sealed_bid_root)?;
        require_root("encrypted payload root", &self.encrypted_payload_root)?;
        require_root("pq authorization root", &self.pq_authorization_root)?;
        require_root("fee ceiling proof root", &self.fee_ceiling_proof_root)?;
        require_bps("max keeper fee bps", self.max_keeper_fee_bps)?;
        require_bps("requested rebate bps", self.requested_rebate_bps)?;
        if self.max_keeper_fee_bps > config.max_keeper_fee_bps {
            return Err("keeper fee exceeds configured cap".to_string());
        }
        if self.requested_rebate_bps > config.max_rebate_bps {
            return Err("requested rebate exceeds configured cap".to_string());
        }
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("bid privacy set below configured minimum".to_string());
        }
        if self.expires_at_height <= self.submitted_at_height {
            return Err("bid expiration must be after submit height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "bid_kind": self.bid_kind.as_str(),
            "keeper_commitment": self.keeper_commitment,
            "bid_commitment_root": self.bid_commitment_root,
            "repay_commitment_root": self.repay_commitment_root,
            "receive_note_root": self.receive_note_root,
            "route_commitment_root": self.route_commitment_root,
            "sealed_bid_root": self.sealed_bid_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "pq_authorization_root": self.pq_authorization_root,
            "fee_ceiling_proof_root": self.fee_ceiling_proof_root,
            "max_keeper_fee_bps": self.max_keeper_fee_bps,
            "requested_rebate_bps": self.requested_rebate_bps,
            "priority_micro_units": self.priority_micro_units,
            "min_privacy_set_size": self.min_privacy_set_size,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRiskAttestationRequest {
    pub market_id: String,
    pub attestor_commitment: String,
    pub verdict: RiskVerdict,
    pub health_factor_bps: u64,
    pub risk_score_bps: u64,
    pub liquidation_threshold_bps: u64,
    pub exposure_commitment_root: String,
    pub oracle_bundle_root: String,
    pub circuit_public_input_root: String,
    pub pq_signature_root: String,
    pub pq_backup_signature_root: String,
    pub min_pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub attested_at_height: u64,
}

impl PqRiskAttestationRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialLiquidationAuctionRuntimeResult<()> {
        require_non_empty("market id", &self.market_id)?;
        require_non_empty("attestor commitment", &self.attestor_commitment)?;
        require_bps("health factor bps", self.health_factor_bps)?;
        require_bps("risk score bps", self.risk_score_bps)?;
        require_bps("liquidation threshold bps", self.liquidation_threshold_bps)?;
        require_root("exposure commitment root", &self.exposure_commitment_root)?;
        require_root("oracle bundle root", &self.oracle_bundle_root)?;
        require_root("circuit public input root", &self.circuit_public_input_root)?;
        require_root("pq signature root", &self.pq_signature_root)?;
        require_root("pq backup signature root", &self.pq_backup_signature_root)?;
        if self.min_pq_security_bits < config.min_pq_security_bits {
            return Err("risk attestation below configured PQ security bits".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("risk attestation privacy set below configured minimum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "attestor_commitment": self.attestor_commitment,
            "verdict": self.verdict.as_str(),
            "health_factor_bps": self.health_factor_bps,
            "risk_score_bps": self.risk_score_bps,
            "liquidation_threshold_bps": self.liquidation_threshold_bps,
            "exposure_commitment_root": self.exposure_commitment_root,
            "oracle_bundle_root": self.oracle_bundle_root,
            "circuit_public_input_root": self.circuit_public_input_root,
            "pq_signature_root": self.pq_signature_root,
            "pq_backup_signature_root": self.pq_backup_signature_root,
            "min_pq_security_bits": self.min_pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeeperReservationRequest {
    pub market_id: String,
    pub bid_id: Option<String>,
    pub keeper_commitment: String,
    pub sponsor_commitment: String,
    pub fee_note_root: String,
    pub rebate_commitment_root: String,
    pub reservation_proof_root: String,
    pub max_fee_bps: u64,
    pub requested_rebate_bps: u64,
    pub reserved_micro_units: u64,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl KeeperReservationRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialLiquidationAuctionRuntimeResult<()> {
        require_non_empty("market id", &self.market_id)?;
        require_non_empty("keeper commitment", &self.keeper_commitment)?;
        require_non_empty("sponsor commitment", &self.sponsor_commitment)?;
        require_root("fee note root", &self.fee_note_root)?;
        require_root("rebate commitment root", &self.rebate_commitment_root)?;
        require_root("reservation proof root", &self.reservation_proof_root)?;
        require_bps("max fee bps", self.max_fee_bps)?;
        require_bps("requested rebate bps", self.requested_rebate_bps)?;
        if self.max_fee_bps > config.max_keeper_fee_bps {
            return Err("reservation fee exceeds configured keeper cap".to_string());
        }
        if self.requested_rebate_bps > config.max_rebate_bps {
            return Err("reservation rebate exceeds configured cap".to_string());
        }
        if self.reserved_micro_units == 0 {
            return Err("reservation amount must be positive".to_string());
        }
        if self.expires_at_height <= self.reserved_at_height {
            return Err("reservation expiration must be after reserve height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "bid_id": self.bid_id,
            "keeper_commitment": self.keeper_commitment,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_note_root": self.fee_note_root,
            "rebate_commitment_root": self.rebate_commitment_root,
            "reservation_proof_root": self.reservation_proof_root,
            "max_fee_bps": self.max_fee_bps,
            "requested_rebate_bps": self.requested_rebate_bps,
            "reserved_micro_units": self.reserved_micro_units,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedBatchRequest {
    pub market_ids: Vec<String>,
    pub selected_bid_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub batch_builder_commitment: String,
    pub sealed_batch_root: String,
    pub encrypted_solver_payload_root: String,
    pub clearing_price_root: String,
    pub collateral_delta_root: String,
    pub debt_delta_root: String,
    pub keeper_payout_root: String,
    pub batch_proof_root: String,
    pub da_commitment_root: String,
    pub min_privacy_set_size: u64,
    pub built_at_height: u64,
}

impl SealedBatchRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialLiquidationAuctionRuntimeResult<()> {
        require_non_empty("batch builder commitment", &self.batch_builder_commitment)?;
        require_root("sealed batch root", &self.sealed_batch_root)?;
        require_root(
            "encrypted solver payload root",
            &self.encrypted_solver_payload_root,
        )?;
        require_root("clearing price root", &self.clearing_price_root)?;
        require_root("collateral delta root", &self.collateral_delta_root)?;
        require_root("debt delta root", &self.debt_delta_root)?;
        require_root("keeper payout root", &self.keeper_payout_root)?;
        require_root("batch proof root", &self.batch_proof_root)?;
        require_root("da commitment root", &self.da_commitment_root)?;
        require_non_empty_list("market ids", &self.market_ids)?;
        require_non_empty_list("selected bid ids", &self.selected_bid_ids)?;
        if self.market_ids.len() > config.max_markets_per_batch {
            return Err("too many markets in sealed batch".to_string());
        }
        if self.selected_bid_ids.len() > self.market_ids.len() * config.max_bids_per_market {
            return Err("too many selected bids in sealed batch".to_string());
        }
        if self.min_privacy_set_size < config.batch_privacy_set_size {
            return Err("batch privacy set below configured minimum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "market_ids": self.market_ids,
            "selected_bid_ids": self.selected_bid_ids,
            "reservation_ids": self.reservation_ids,
            "batch_builder_commitment": self.batch_builder_commitment,
            "sealed_batch_root": self.sealed_batch_root,
            "encrypted_solver_payload_root": self.encrypted_solver_payload_root,
            "clearing_price_root": self.clearing_price_root,
            "collateral_delta_root": self.collateral_delta_root,
            "debt_delta_root": self.debt_delta_root,
            "keeper_payout_root": self.keeper_payout_root,
            "batch_proof_root": self.batch_proof_root,
            "da_commitment_root": self.da_commitment_root,
            "min_privacy_set_size": self.min_privacy_set_size,
            "built_at_height": self.built_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceiptRequest {
    pub batch_id: String,
    pub market_ids: Vec<String>,
    pub selected_bid_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub rebate_ids: Vec<String>,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub spent_nullifier_root: String,
    pub output_note_root: String,
    pub collateral_release_root: String,
    pub debt_repayment_root: String,
    pub keeper_fee_root: String,
    pub receipt_payload_root: String,
    pub published_at_height: u64,
}

impl SettlementReceiptRequest {
    pub fn validate(&self) -> PrivateL2ConfidentialLiquidationAuctionRuntimeResult<()> {
        require_non_empty("batch id", &self.batch_id)?;
        require_non_empty_list("market ids", &self.market_ids)?;
        require_non_empty_list("selected bid ids", &self.selected_bid_ids)?;
        require_root("settlement tx root", &self.settlement_tx_root)?;
        require_root("settlement proof root", &self.settlement_proof_root)?;
        require_root("spent nullifier root", &self.spent_nullifier_root)?;
        require_root("output note root", &self.output_note_root)?;
        require_root("collateral release root", &self.collateral_release_root)?;
        require_root("debt repayment root", &self.debt_repayment_root)?;
        require_root("keeper fee root", &self.keeper_fee_root)?;
        require_root("receipt payload root", &self.receipt_payload_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "market_ids": self.market_ids,
            "selected_bid_ids": self.selected_bid_ids,
            "reservation_ids": self.reservation_ids,
            "rebate_ids": self.rebate_ids,
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_proof_root": self.settlement_proof_root,
            "spent_nullifier_root": self.spent_nullifier_root,
            "output_note_root": self.output_note_root,
            "collateral_release_root": self.collateral_release_root,
            "debt_repayment_root": self.debt_repayment_root,
            "keeper_fee_root": self.keeper_fee_root,
            "receipt_payload_root": self.receipt_payload_root,
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebateRequest {
    pub market_id: String,
    pub bid_id: String,
    pub reservation_id: Option<String>,
    pub keeper_commitment: String,
    pub rebate_note_root: String,
    pub eligibility_proof_root: String,
    pub fee_paid_root: String,
    pub rebate_bps: u64,
    pub rebate_micro_units: u64,
    pub epoch: u64,
    pub accrued_at_height: u64,
}

impl RebateRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialLiquidationAuctionRuntimeResult<()> {
        require_non_empty("market id", &self.market_id)?;
        require_non_empty("bid id", &self.bid_id)?;
        require_non_empty("keeper commitment", &self.keeper_commitment)?;
        require_root("rebate note root", &self.rebate_note_root)?;
        require_root("eligibility proof root", &self.eligibility_proof_root)?;
        require_root("fee paid root", &self.fee_paid_root)?;
        require_bps("rebate bps", self.rebate_bps)?;
        if self.rebate_bps < config.min_rebate_bps || self.rebate_bps > config.max_rebate_bps {
            return Err("rebate bps outside configured bounds".to_string());
        }
        if self.rebate_micro_units == 0 {
            return Err("rebate amount must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "bid_id": self.bid_id,
            "reservation_id": self.reservation_id,
            "keeper_commitment": self.keeper_commitment,
            "rebate_note_root": self.rebate_note_root,
            "eligibility_proof_root": self.eligibility_proof_root,
            "fee_paid_root": self.fee_paid_root,
            "rebate_bps": self.rebate_bps,
            "rebate_micro_units": self.rebate_micro_units,
            "epoch": self.epoch,
            "accrued_at_height": self.accrued_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedLiquidationMarketRecord {
    pub market_id: String,
    pub request: ShieldedMarketRequest,
    pub status: MarketStatus,
    pub risk_attestation_ids: BTreeSet<String>,
    pub private_bid_ids: BTreeSet<String>,
    pub keeper_reservation_ids: BTreeSet<String>,
    pub batch_id: Option<String>,
    pub settlement_receipt_id: Option<String>,
    pub latest_risk_root: String,
    pub latest_market_state_root: String,
}

impl ShieldedLiquidationMarketRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_liquidation_auction_market",
            "market_id": self.market_id,
            "status": self.status.as_str(),
            "request": self.request.public_record(),
            "risk_attestation_ids": self.risk_attestation_ids,
            "private_bid_ids": self.private_bid_ids,
            "keeper_reservation_ids": self.keeper_reservation_ids,
            "batch_id": self.batch_id,
            "settlement_receipt_id": self.settlement_receipt_id,
            "latest_risk_root": self.latest_risk_root,
            "latest_market_state_root": self.latest_market_state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateLiquidationBidRecord {
    pub bid_id: String,
    pub request: PrivateBidRequest,
    pub status: PrivateBidStatus,
    pub reservation_id: Option<String>,
    pub batch_id: Option<String>,
    pub settlement_receipt_id: Option<String>,
    pub score: u128,
}

impl PrivateLiquidationBidRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_liquidation_auction_bid",
            "bid_id": self.bid_id,
            "status": self.status.as_str(),
            "request": self.request.public_record(),
            "reservation_id": self.reservation_id,
            "batch_id": self.batch_id,
            "settlement_receipt_id": self.settlement_receipt_id,
            "score": self.score.to_string(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRiskAttestationRecord {
    pub attestation_id: String,
    pub request: PqRiskAttestationRequest,
    pub status: AttestationStatus,
    pub accepted_at_height: Option<u64>,
}

impl PqRiskAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_liquidation_auction_pq_risk_attestation",
            "attestation_id": self.attestation_id,
            "status": self.status.as_str(),
            "request": self.request.public_record(),
            "accepted_at_height": self.accepted_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeeperReservationRecord {
    pub reservation_id: String,
    pub request: KeeperReservationRequest,
    pub status: ReservationStatus,
}

impl KeeperReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_liquidation_auction_keeper_reservation",
            "reservation_id": self.reservation_id,
            "status": self.status.as_str(),
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedLiquidationBatchRecord {
    pub batch_id: String,
    pub request: SealedBatchRequest,
    pub status: BatchStatus,
    pub settlement_deadline_height: u64,
    pub settlement_receipt_id: Option<String>,
}

impl SealedLiquidationBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_liquidation_auction_sealed_batch",
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "request": self.request.public_record(),
            "settlement_deadline_height": self.settlement_deadline_height,
            "settlement_receipt_id": self.settlement_receipt_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceiptRecord {
    pub receipt_id: String,
    pub receipt_kind: ReceiptKind,
    pub status: ReceiptStatus,
    pub request: SettlementReceiptRequest,
}

impl SettlementReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_liquidation_auction_settlement_receipt",
            "receipt_id": self.receipt_id,
            "receipt_kind": self.receipt_kind.as_str(),
            "status": self.status.as_str(),
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeeperRebateRecord {
    pub rebate_id: String,
    pub request: RebateRequest,
    pub status: RebateStatus,
    pub receipt_id: Option<String>,
}

impl KeeperRebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_liquidation_auction_rebate",
            "rebate_id": self.rebate_id,
            "status": self.status.as_str(),
            "request": self.request.public_record(),
            "receipt_id": self.receipt_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counter_root: String,
    pub market_root: String,
    pub private_bid_root: String,
    pub risk_attestation_root: String,
    pub keeper_reservation_root: String,
    pub sealed_batch_root: String,
    pub settlement_receipt_root: String,
    pub rebate_root: String,
    pub consumed_nullifier_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_liquidation_auction_roots",
            "config_root": self.config_root,
            "counter_root": self.counter_root,
            "market_root": self.market_root,
            "private_bid_root": self.private_bid_root,
            "risk_attestation_root": self.risk_attestation_root,
            "keeper_reservation_root": self.keeper_reservation_root,
            "sealed_batch_root": self.sealed_batch_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "rebate_root": self.rebate_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub runtime_root: String,
    pub keeper_budget_remaining_micro_units: u64,
    pub shielded_markets: BTreeMap<String, ShieldedLiquidationMarketRecord>,
    pub private_bids: BTreeMap<String, PrivateLiquidationBidRecord>,
    pub risk_attestations: BTreeMap<String, PqRiskAttestationRecord>,
    pub keeper_reservations: BTreeMap<String, KeeperReservationRecord>,
    pub sealed_batches: BTreeMap<String, SealedLiquidationBatchRecord>,
    pub settlement_receipts: BTreeMap<String, SettlementReceiptRecord>,
    pub keeper_rebates: BTreeMap<String, KeeperRebateRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
}

impl State {
    pub fn devnet() -> Self {
        Self::new(
            Config::devnet(),
            PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_DEVNET_HEIGHT,
        )
    }

    pub fn new(config: Config, current_height: u64) -> Self {
        let keeper_budget_remaining_micro_units = config.keeper_budget_micro_units;
        Self {
            config,
            counters: Counters::default(),
            current_height,
            runtime_root: payload_root(
                "PRIVATE-L2-CONFIDENTIAL-LIQUIDATION-AUCTION-GENESIS",
                &json!({
                    "chain_id": CHAIN_ID,
                    "current_height": current_height,
                }),
            ),
            keeper_budget_remaining_micro_units,
            shielded_markets: BTreeMap::new(),
            private_bids: BTreeMap::new(),
            risk_attestations: BTreeMap::new(),
            keeper_reservations: BTreeMap::new(),
            sealed_batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            keeper_rebates: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn open_shielded_market(
        &mut self,
        mut request: ShieldedMarketRequest,
    ) -> PrivateL2ConfidentialLiquidationAuctionRuntimeResult<String> {
        if self.shielded_markets.len() >= self.config.max_markets {
            return Err("market capacity reached".to_string());
        }
        if request.expires_at_height == 0 {
            request.expires_at_height = request
                .opened_at_height
                .saturating_add(self.config.market_ttl_blocks);
        }
        request.validate(&self.config)?;
        self.current_height = self.current_height.max(request.opened_at_height);
        self.consume_nullifier(&request.nullifier_root)?;
        let market_id = liquidation_market_id(&request, self.counters.next_market_nonce);
        let latest_market_state_root = payload_root(
            "PRIVATE-L2-CONFIDENTIAL-LIQUIDATION-AUCTION-MARKET-INITIAL",
            &request.public_record(),
        );
        let market = ShieldedLiquidationMarketRecord {
            market_id: market_id.clone(),
            request,
            status: MarketStatus::Submitted,
            risk_attestation_ids: BTreeSet::new(),
            private_bid_ids: BTreeSet::new(),
            keeper_reservation_ids: BTreeSet::new(),
            batch_id: None,
            settlement_receipt_id: None,
            latest_risk_root: payload_root(
                "PRIVATE-L2-CONFIDENTIAL-LIQUIDATION-AUCTION-EMPTY-RISK",
                &json!({ "market_id": market_id }),
            ),
            latest_market_state_root,
        };
        self.counters.next_market_nonce = self.counters.next_market_nonce.saturating_add(1);
        self.counters.shielded_markets_opened =
            self.counters.shielded_markets_opened.saturating_add(1);
        self.publish_public_record("market_opened", &market_id, market.public_record());
        self.shielded_markets.insert(market_id.clone(), market);
        Ok(market_id)
    }

    pub fn record_pq_risk_attestation(
        &mut self,
        request: PqRiskAttestationRequest,
    ) -> PrivateL2ConfidentialLiquidationAuctionRuntimeResult<String> {
        if self.risk_attestations.len() >= self.config.max_risk_attestations {
            return Err("risk attestation capacity reached".to_string());
        }
        request.validate(&self.config)?;
        let market = self
            .shielded_markets
            .get_mut(&request.market_id)
            .ok_or_else(|| "market not found for risk attestation".to_string())?;
        if !market.status.accepts_attestation() {
            return Err("market no longer accepts risk attestations".to_string());
        }
        let attestation_id =
            risk_attestation_id(&request, self.counters.next_risk_attestation_nonce);
        let status = if request.verdict.allows_liquidation() {
            AttestationStatus::Accepted
        } else {
            AttestationStatus::Recorded
        };
        let accepted_at_height = if status == AttestationStatus::Accepted {
            Some(request.attested_at_height)
        } else {
            None
        };
        market.risk_attestation_ids.insert(attestation_id.clone());
        market.latest_risk_root = payload_root(
            "PRIVATE-L2-CONFIDENTIAL-LIQUIDATION-AUCTION-LATEST-RISK",
            &json!({
                "market_id": request.market_id,
                "attestation_id": attestation_id,
                "verdict": request.verdict.as_str(),
                "severity": request.verdict.severity(),
            }),
        );
        if request.verdict.allows_liquidation() {
            market.status = MarketStatus::RiskAttested;
        }
        let record = PqRiskAttestationRecord {
            attestation_id: attestation_id.clone(),
            request,
            status,
            accepted_at_height,
        };
        self.counters.next_risk_attestation_nonce =
            self.counters.next_risk_attestation_nonce.saturating_add(1);
        if status == AttestationStatus::Accepted {
            self.counters.pq_attestations_accepted =
                self.counters.pq_attestations_accepted.saturating_add(1);
        }
        self.publish_public_record("risk_attested", &attestation_id, record.public_record());
        self.risk_attestations
            .insert(attestation_id.clone(), record);
        Ok(attestation_id)
    }

    pub fn commit_private_bid(
        &mut self,
        request: PrivateBidRequest,
    ) -> PrivateL2ConfidentialLiquidationAuctionRuntimeResult<String> {
        if self.private_bids.len() >= self.config.max_private_bids {
            return Err("private bid capacity reached".to_string());
        }
        request.validate(&self.config)?;
        let market = self
            .shielded_markets
            .get_mut(&request.market_id)
            .ok_or_else(|| "market not found for private bid".to_string())?;
        if !market.status.accepts_bid() {
            return Err("market no longer accepts private bids".to_string());
        }
        let bid_id = private_bid_id(&request, self.counters.next_bid_nonce);
        let score = bid_score(&request);
        let record = PrivateLiquidationBidRecord {
            bid_id: bid_id.clone(),
            request,
            status: PrivateBidStatus::Committed,
            reservation_id: None,
            batch_id: None,
            settlement_receipt_id: None,
            score,
        };
        market.private_bid_ids.insert(bid_id.clone());
        market.status = MarketStatus::Bidding;
        self.counters.next_bid_nonce = self.counters.next_bid_nonce.saturating_add(1);
        self.counters.private_bids_committed =
            self.counters.private_bids_committed.saturating_add(1);
        self.publish_public_record("private_bid_committed", &bid_id, record.public_record());
        self.private_bids.insert(bid_id.clone(), record);
        Ok(bid_id)
    }

    pub fn reserve_keeper_fee(
        &mut self,
        request: KeeperReservationRequest,
    ) -> PrivateL2ConfidentialLiquidationAuctionRuntimeResult<String> {
        if self.keeper_reservations.len() >= self.config.max_keeper_reservations {
            return Err("keeper reservation capacity reached".to_string());
        }
        request.validate(&self.config)?;
        if request.reserved_micro_units > self.keeper_budget_remaining_micro_units {
            return Err("insufficient keeper reservation budget".to_string());
        }
        let market = self
            .shielded_markets
            .get_mut(&request.market_id)
            .ok_or_else(|| "market not found for keeper reservation".to_string())?;
        if !market.status.accepts_reservation() {
            return Err("market no longer accepts keeper reservations".to_string());
        }
        if let Some(bid_id) = &request.bid_id {
            let bid = self
                .private_bids
                .get_mut(bid_id)
                .ok_or_else(|| "bid not found for keeper reservation".to_string())?;
            if bid.request.market_id != request.market_id {
                return Err("reservation bid does not belong to market".to_string());
            }
            bid.status = PrivateBidStatus::Reserved;
        }
        let reservation_id =
            keeper_reservation_id(&request, self.counters.next_keeper_reservation_nonce);
        let record = KeeperReservationRecord {
            reservation_id: reservation_id.clone(),
            request,
            status: ReservationStatus::Reserved,
        };
        market.keeper_reservation_ids.insert(reservation_id.clone());
        market.status = MarketStatus::Reservable;
        self.keeper_budget_remaining_micro_units = self
            .keeper_budget_remaining_micro_units
            .saturating_sub(record.request.reserved_micro_units);
        self.counters.next_keeper_reservation_nonce = self
            .counters
            .next_keeper_reservation_nonce
            .saturating_add(1);
        self.counters.keeper_reservations_opened =
            self.counters.keeper_reservations_opened.saturating_add(1);
        self.publish_public_record("keeper_reserved", &reservation_id, record.public_record());
        self.keeper_reservations
            .insert(reservation_id.clone(), record);
        Ok(reservation_id)
    }

    pub fn build_sealed_batch(
        &mut self,
        request: SealedBatchRequest,
    ) -> PrivateL2ConfidentialLiquidationAuctionRuntimeResult<String> {
        if self.sealed_batches.len() >= self.config.max_batches {
            return Err("sealed batch capacity reached".to_string());
        }
        request.validate(&self.config)?;
        let batch_id = sealed_batch_id(&request, self.counters.next_batch_nonce);
        for market_id in &request.market_ids {
            let market = self
                .shielded_markets
                .get_mut(market_id)
                .ok_or_else(|| format!("market {market_id} not found for sealed batch"))?;
            if !matches!(
                market.status,
                MarketStatus::RiskAttested | MarketStatus::Reservable | MarketStatus::Bidding
            ) {
                return Err(format!("market {market_id} is not batchable"));
            }
            market.status = MarketStatus::Batched;
            market.batch_id = Some(batch_id.clone());
        }
        for bid_id in &request.selected_bid_ids {
            let bid = self
                .private_bids
                .get_mut(bid_id)
                .ok_or_else(|| format!("bid {bid_id} not found for sealed batch"))?;
            if !bid.status.selectable() {
                return Err(format!("bid {bid_id} is not selectable"));
            }
            bid.status = PrivateBidStatus::Selected;
            bid.batch_id = Some(batch_id.clone());
        }
        for reservation_id in &request.reservation_ids {
            let reservation = self
                .keeper_reservations
                .get_mut(reservation_id)
                .ok_or_else(|| {
                    format!("reservation {reservation_id} not found for sealed batch")
                })?;
            reservation.status = ReservationStatus::Consumed;
        }
        let record = SealedLiquidationBatchRecord {
            batch_id: batch_id.clone(),
            settlement_deadline_height: request
                .built_at_height
                .saturating_add(self.config.settlement_ttl_blocks),
            request,
            status: BatchStatus::SettlementReady,
            settlement_receipt_id: None,
        };
        self.counters.next_batch_nonce = self.counters.next_batch_nonce.saturating_add(1);
        self.counters.sealed_batches_built = self.counters.sealed_batches_built.saturating_add(1);
        self.publish_public_record("sealed_batch_built", &batch_id, record.public_record());
        self.sealed_batches.insert(batch_id.clone(), record);
        Ok(batch_id)
    }

    pub fn publish_settlement_receipt(
        &mut self,
        request: SettlementReceiptRequest,
    ) -> PrivateL2ConfidentialLiquidationAuctionRuntimeResult<String> {
        request.validate()?;
        let batch = self
            .sealed_batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| "batch not found for settlement receipt".to_string())?;
        if !batch.status.can_settle() {
            return Err("batch is not settlement ready".to_string());
        }
        let receipt_id = settlement_receipt_id(&request, self.counters.next_receipt_nonce);
        for market_id in &request.market_ids {
            let market = self
                .shielded_markets
                .get_mut(market_id)
                .ok_or_else(|| format!("market {market_id} not found for settlement"))?;
            market.status = MarketStatus::Settled;
            market.settlement_receipt_id = Some(receipt_id.clone());
        }
        for bid_id in &request.selected_bid_ids {
            let bid = self
                .private_bids
                .get_mut(bid_id)
                .ok_or_else(|| format!("bid {bid_id} not found for settlement"))?;
            bid.status = PrivateBidStatus::Settled;
            bid.settlement_receipt_id = Some(receipt_id.clone());
        }
        for rebate_id in &request.rebate_ids {
            if let Some(rebate) = self.keeper_rebates.get_mut(rebate_id) {
                rebate.status = RebateStatus::Paid;
                rebate.receipt_id = Some(receipt_id.clone());
            }
        }
        batch.status = BatchStatus::Settled;
        batch.settlement_receipt_id = Some(receipt_id.clone());
        let record = SettlementReceiptRecord {
            receipt_id: receipt_id.clone(),
            receipt_kind: ReceiptKind::BatchSettled,
            status: ReceiptStatus::Published,
            request,
        };
        self.counters.next_receipt_nonce = self.counters.next_receipt_nonce.saturating_add(1);
        self.counters.settlements_published = self.counters.settlements_published.saturating_add(1);
        self.publish_public_record("settlement_receipt", &receipt_id, record.public_record());
        self.settlement_receipts.insert(receipt_id.clone(), record);
        Ok(receipt_id)
    }

    pub fn accrue_keeper_rebate(
        &mut self,
        request: RebateRequest,
    ) -> PrivateL2ConfidentialLiquidationAuctionRuntimeResult<String> {
        request.validate(&self.config)?;
        if !self.shielded_markets.contains_key(&request.market_id) {
            return Err("market not found for rebate".to_string());
        }
        if !self.private_bids.contains_key(&request.bid_id) {
            return Err("bid not found for rebate".to_string());
        }
        let rebate_id = keeper_rebate_id(&request, self.counters.next_rebate_nonce);
        let record = KeeperRebateRecord {
            rebate_id: rebate_id.clone(),
            request,
            status: RebateStatus::Accrued,
            receipt_id: None,
        };
        self.counters.next_rebate_nonce = self.counters.next_rebate_nonce.saturating_add(1);
        self.publish_public_record("rebate_accrued", &rebate_id, record.public_record());
        self.keeper_rebates.insert(rebate_id.clone(), record);
        Ok(rebate_id)
    }

    pub fn finalize_receipt(
        &mut self,
        receipt_id: &str,
    ) -> PrivateL2ConfidentialLiquidationAuctionRuntimeResult<()> {
        let payload = {
            let receipt = self
                .settlement_receipts
                .get_mut(receipt_id)
                .ok_or_else(|| "settlement receipt not found".to_string())?;
            receipt.status = ReceiptStatus::Finalized;
            receipt.public_record()
        };
        self.publish_public_record("receipt_finalized", receipt_id, payload);
        Ok(())
    }

    pub fn expire_height(&mut self, height: u64) {
        self.current_height = self.current_height.max(height);
        for market in self.shielded_markets.values_mut() {
            if market.request.expires_at_height <= self.current_height
                && !matches!(
                    market.status,
                    MarketStatus::Settled | MarketStatus::Rejected
                )
            {
                market.status = MarketStatus::Expired;
            }
        }
        for bid in self.private_bids.values_mut() {
            if bid.request.expires_at_height <= self.current_height
                && !matches!(
                    bid.status,
                    PrivateBidStatus::Settled | PrivateBidStatus::Rejected
                )
            {
                bid.status = PrivateBidStatus::Expired;
            }
        }
        for reservation in self.keeper_reservations.values_mut() {
            if reservation.request.expires_at_height <= self.current_height
                && reservation.status == ReservationStatus::Reserved
            {
                reservation.status = ReservationStatus::Expired;
                self.keeper_budget_remaining_micro_units = self
                    .keeper_budget_remaining_micro_units
                    .saturating_add(reservation.request.reserved_micro_units);
            }
        }
        for batch in self.sealed_batches.values_mut() {
            if batch.settlement_deadline_height <= self.current_height
                && !matches!(batch.status, BatchStatus::Settled | BatchStatus::Disputed)
            {
                batch.status = BatchStatus::Expired;
            }
        }
    }

    pub fn roots(&self) -> Roots {
        let config_root = payload_root(
            "PRIVATE-L2-CONFIDENTIAL-LIQUIDATION-AUCTION-CONFIG",
            &self.config.public_record(),
        );
        let counter_root = payload_root(
            "PRIVATE-L2-CONFIDENTIAL-LIQUIDATION-AUCTION-COUNTERS",
            &self.counters.public_record(),
        );
        let market_root = public_record_root(
            "PRIVATE-L2-CONFIDENTIAL-LIQUIDATION-AUCTION-MARKETS",
            self.shielded_markets
                .values()
                .map(ShieldedLiquidationMarketRecord::public_record)
                .collect(),
        );
        let private_bid_root = public_record_root(
            "PRIVATE-L2-CONFIDENTIAL-LIQUIDATION-AUCTION-BIDS",
            self.private_bids
                .values()
                .map(PrivateLiquidationBidRecord::public_record)
                .collect(),
        );
        let risk_attestation_root = public_record_root(
            "PRIVATE-L2-CONFIDENTIAL-LIQUIDATION-AUCTION-RISK-ATTESTATIONS",
            self.risk_attestations
                .values()
                .map(PqRiskAttestationRecord::public_record)
                .collect(),
        );
        let keeper_reservation_root = public_record_root(
            "PRIVATE-L2-CONFIDENTIAL-LIQUIDATION-AUCTION-KEEPER-RESERVATIONS",
            self.keeper_reservations
                .values()
                .map(KeeperReservationRecord::public_record)
                .collect(),
        );
        let sealed_batch_root = public_record_root(
            "PRIVATE-L2-CONFIDENTIAL-LIQUIDATION-AUCTION-SEALED-BATCHES",
            self.sealed_batches
                .values()
                .map(SealedLiquidationBatchRecord::public_record)
                .collect(),
        );
        let settlement_receipt_root = public_record_root(
            "PRIVATE-L2-CONFIDENTIAL-LIQUIDATION-AUCTION-SETTLEMENT-RECEIPTS",
            self.settlement_receipts
                .values()
                .map(SettlementReceiptRecord::public_record)
                .collect(),
        );
        let rebate_root = public_record_root(
            "PRIVATE-L2-CONFIDENTIAL-LIQUIDATION-AUCTION-REBATES",
            self.keeper_rebates
                .values()
                .map(KeeperRebateRecord::public_record)
                .collect(),
        );
        let consumed_nullifier_root = public_record_root(
            "PRIVATE-L2-CONFIDENTIAL-LIQUIDATION-AUCTION-CONSUMED-NULLIFIERS",
            self.consumed_nullifiers
                .iter()
                .map(|nullifier| json!({ "nullifier": nullifier }))
                .collect(),
        );
        let runtime_public_record_root = public_record_root(
            "PRIVATE-L2-CONFIDENTIAL-LIQUIDATION-AUCTION-PUBLIC-RECORDS",
            self.public_records.values().cloned().collect(),
        );
        let record = json!({
            "config_root": config_root.clone(),
            "counter_root": counter_root.clone(),
            "market_root": market_root.clone(),
            "private_bid_root": private_bid_root.clone(),
            "risk_attestation_root": risk_attestation_root.clone(),
            "keeper_reservation_root": keeper_reservation_root.clone(),
            "sealed_batch_root": sealed_batch_root.clone(),
            "settlement_receipt_root": settlement_receipt_root.clone(),
            "rebate_root": rebate_root.clone(),
            "consumed_nullifier_root": consumed_nullifier_root.clone(),
            "public_record_root": runtime_public_record_root.clone(),
            "runtime_root": self.runtime_root.clone(),
            "keeper_budget_remaining_micro_units": self.keeper_budget_remaining_micro_units,
            "current_height": self.current_height,
        });
        let state_root = state_root_from_record(&record);
        Roots {
            config_root,
            counter_root,
            market_root,
            private_bid_root,
            risk_attestation_root,
            keeper_reservation_root,
            sealed_batch_root,
            settlement_receipt_root,
            rebate_root,
            consumed_nullifier_root,
            public_record_root: runtime_public_record_root,
            state_root,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_l2_confidential_liquidation_auction_runtime",
            "protocol_version": PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "hash_suite": PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_HASH_SUITE,
            "current_height": self.current_height,
            "runtime_root": self.runtime_root,
            "keeper_budget_remaining_micro_units": self.keeper_budget_remaining_micro_units,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let record = self.public_record_without_state_root();
        json!({
            "state_root": state_root_from_record(&record),
            "record": record,
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn consume_nullifier(
        &mut self,
        nullifier: &str,
    ) -> PrivateL2ConfidentialLiquidationAuctionRuntimeResult<()> {
        require_root("nullifier", nullifier)?;
        let nullifier_hash = payload_root(
            "PRIVATE-L2-CONFIDENTIAL-LIQUIDATION-AUCTION-NULLIFIER",
            &json!({ "nullifier": nullifier }),
        );
        if !self.consumed_nullifiers.insert(nullifier_hash) {
            return Err("nullifier already consumed".to_string());
        }
        self.counters.consumed_nullifiers = self.counters.consumed_nullifiers.saturating_add(1);
        Ok(())
    }

    fn publish_public_record(&mut self, record_kind: &str, subject_id: &str, payload: Value) {
        let record_id = public_record_id(record_kind, subject_id, &payload);
        self.public_records.insert(
            record_id,
            roots_only_public_record(record_kind, subject_id, &payload),
        );
    }
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn public_record_root(domain: &str, leaves: Vec<Value>) -> String {
    merkle_root(domain, &leaves)
}

pub fn state_root_from_record(record: &Value) -> String {
    payload_root("PRIVATE-L2-CONFIDENTIAL-LIQUIDATION-AUCTION-STATE", record)
}

pub fn liquidation_market_id(request: &ShieldedMarketRequest, nonce: u64) -> String {
    payload_root(
        "PRIVATE-L2-CONFIDENTIAL-LIQUIDATION-AUCTION-MARKET-ID",
        &json!({
            "nonce": nonce,
            "request": request.public_record(),
        }),
    )
}

pub fn private_bid_id(request: &PrivateBidRequest, nonce: u64) -> String {
    payload_root(
        "PRIVATE-L2-CONFIDENTIAL-LIQUIDATION-AUCTION-BID-ID",
        &json!({
            "nonce": nonce,
            "request": request.public_record(),
        }),
    )
}

pub fn risk_attestation_id(request: &PqRiskAttestationRequest, nonce: u64) -> String {
    payload_root(
        "PRIVATE-L2-CONFIDENTIAL-LIQUIDATION-AUCTION-RISK-ATTESTATION-ID",
        &json!({
            "nonce": nonce,
            "request": request.public_record(),
        }),
    )
}

pub fn keeper_reservation_id(request: &KeeperReservationRequest, nonce: u64) -> String {
    payload_root(
        "PRIVATE-L2-CONFIDENTIAL-LIQUIDATION-AUCTION-KEEPER-RESERVATION-ID",
        &json!({
            "nonce": nonce,
            "request": request.public_record(),
        }),
    )
}

pub fn sealed_batch_id(request: &SealedBatchRequest, nonce: u64) -> String {
    payload_root(
        "PRIVATE-L2-CONFIDENTIAL-LIQUIDATION-AUCTION-SEALED-BATCH-ID",
        &json!({
            "nonce": nonce,
            "request": request.public_record(),
        }),
    )
}

pub fn settlement_receipt_id(request: &SettlementReceiptRequest, nonce: u64) -> String {
    payload_root(
        "PRIVATE-L2-CONFIDENTIAL-LIQUIDATION-AUCTION-SETTLEMENT-RECEIPT-ID",
        &json!({
            "nonce": nonce,
            "request": request.public_record(),
        }),
    )
}

pub fn keeper_rebate_id(request: &RebateRequest, nonce: u64) -> String {
    payload_root(
        "PRIVATE-L2-CONFIDENTIAL-LIQUIDATION-AUCTION-KEEPER-REBATE-ID",
        &json!({
            "nonce": nonce,
            "request": request.public_record(),
        }),
    )
}

pub fn public_record_id(record_kind: &str, subject_id: &str, payload: &Value) -> String {
    payload_root(
        "PRIVATE-L2-CONFIDENTIAL-LIQUIDATION-AUCTION-PUBLIC-RECORD-ID",
        &json!({
            "record_kind": record_kind,
            "subject_id": subject_id,
            "payload_root": payload_root(
                "PRIVATE-L2-CONFIDENTIAL-LIQUIDATION-AUCTION-PUBLIC-RECORD-PAYLOAD",
                payload,
            ),
        }),
    )
}

pub fn roots_only_public_record(record_kind: &str, subject_id: &str, payload: &Value) -> Value {
    json!({
        "record_kind": record_kind,
        "subject_id": subject_id,
        "payload_root": payload_root(
            "PRIVATE-L2-CONFIDENTIAL-LIQUIDATION-AUCTION-ROOTS-ONLY-PAYLOAD",
            payload,
        ),
    })
}

pub fn bid_score(request: &PrivateBidRequest) -> u128 {
    let fee_score = PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_MAX_BPS
        .saturating_sub(request.max_keeper_fee_bps) as u128;
    let rebate_score = request.requested_rebate_bps as u128;
    let priority_score = request.priority_micro_units as u128;
    fee_score
        .saturating_mul(1_000_000)
        .saturating_add(rebate_score.saturating_mul(10_000))
        .saturating_add(priority_score)
}

fn require_non_empty(
    label: &str,
    value: &str,
) -> PrivateL2ConfidentialLiquidationAuctionRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}

fn require_root(
    label: &str,
    value: &str,
) -> PrivateL2ConfidentialLiquidationAuctionRuntimeResult<()> {
    require_non_empty(label, value)?;
    if value.len() < 16 {
        return Err(format!("{label} must look like a commitment root"));
    }
    Ok(())
}

fn require_bps(
    label: &str,
    value: u64,
) -> PrivateL2ConfidentialLiquidationAuctionRuntimeResult<()> {
    if value > PRIVATE_L2_CONFIDENTIAL_LIQUIDATION_AUCTION_RUNTIME_MAX_BPS {
        return Err(format!("{label} exceeds max bps"));
    }
    Ok(())
}

fn require_non_empty_list(
    label: &str,
    values: &[String],
) -> PrivateL2ConfidentialLiquidationAuctionRuntimeResult<()> {
    if values.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    for value in values {
        require_non_empty(label, value)?;
    }
    Ok(())
}
