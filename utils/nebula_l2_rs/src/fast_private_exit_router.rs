use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, HashPart},
    CHAIN_ID,
};

pub type FastPrivateExitRouterResult<T> = Result<T, String>;

pub const FAST_PRIVATE_EXIT_ROUTER_PROTOCOL_VERSION: &str = "nebula-fast-private-exit-router-v1";
pub const PROTOCOL_VERSION: &str = FAST_PRIVATE_EXIT_ROUTER_PROTOCOL_VERSION;
pub const FAST_PRIVATE_EXIT_ROUTER_SCHEMA_VERSION: u64 = 1;
pub const FAST_PRIVATE_EXIT_ROUTER_DEVNET_HEIGHT: u64 = 192;
pub const FAST_PRIVATE_EXIT_ROUTER_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const FAST_PRIVATE_EXIT_ROUTER_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const FAST_PRIVATE_EXIT_ROUTER_DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const FAST_PRIVATE_EXIT_ROUTER_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const FAST_PRIVATE_EXIT_ROUTER_PQ_SUITE: &str =
    "ML-KEM-768+ML-DSA-65+SLH-DSA-SHAKE-128s-router-devnet";
pub const FAST_PRIVATE_EXIT_ROUTER_SHIELDED_EXIT_SCHEME: &str =
    "shielded-exit-nullifier-commitment-v1";
pub const FAST_PRIVATE_EXIT_ROUTER_STEALTH_PAYOUT_SCHEME: &str =
    "monero-payout-stealth-commitment-v1";
pub const FAST_PRIVATE_EXIT_ROUTER_MAKER_ATTESTATION_SCHEME: &str =
    "ml-dsa-65-maker-liquidity-attestation-v1";
pub const FAST_PRIVATE_EXIT_ROUTER_DELAYED_REVEAL_SCHEME: &str =
    "delayed-reveal-private-receipt-v1";
pub const FAST_PRIVATE_EXIT_ROUTER_DISPUTE_SCHEME: &str =
    "private-exit-dispute-challenge-window-v1";
pub const FAST_PRIVATE_EXIT_ROUTER_LOW_FEE_SPONSOR_SCHEME: &str =
    "low-fee-private-exit-sponsorship-v1";
pub const FAST_PRIVATE_EXIT_ROUTER_DEFAULT_EXIT_TTL_BLOCKS: u64 = 24;
pub const FAST_PRIVATE_EXIT_ROUTER_DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 10;
pub const FAST_PRIVATE_EXIT_ROUTER_DEFAULT_REVEAL_DELAY_BLOCKS: u64 = 6;
pub const FAST_PRIVATE_EXIT_ROUTER_DEFAULT_REVEAL_TTL_BLOCKS: u64 = 24;
pub const FAST_PRIVATE_EXIT_ROUTER_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 18;
pub const FAST_PRIVATE_EXIT_ROUTER_DEFAULT_FINALITY_BLOCKS: u64 = 10;
pub const FAST_PRIVATE_EXIT_ROUTER_DEFAULT_REORG_GRACE_BLOCKS: u64 = 4;
pub const FAST_PRIVATE_EXIT_ROUTER_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 256;
pub const FAST_PRIVATE_EXIT_ROUTER_DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1024;
pub const FAST_PRIVATE_EXIT_ROUTER_DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 11_000;
pub const FAST_PRIVATE_EXIT_ROUTER_DEFAULT_WARN_RESERVE_COVERAGE_BPS: u64 = 12_000;
pub const FAST_PRIVATE_EXIT_ROUTER_DEFAULT_MAX_ROUTER_EXPOSURE_UNITS: u64 = 3_000_000;
pub const FAST_PRIVATE_EXIT_ROUTER_DEFAULT_MAX_MAKER_EXPOSURE_UNITS: u64 = 900_000;
pub const FAST_PRIVATE_EXIT_ROUTER_DEFAULT_MAX_PENDING_EXITS: usize = 2_048;
pub const FAST_PRIVATE_EXIT_ROUTER_DEFAULT_MAX_OPEN_RESERVATIONS_PER_MAKER: usize = 96;
pub const FAST_PRIVATE_EXIT_ROUTER_DEFAULT_BASE_FEE_BPS: u64 = 18;
pub const FAST_PRIVATE_EXIT_ROUTER_DEFAULT_FAST_FEE_BPS: u64 = 45;
pub const FAST_PRIVATE_EXIT_ROUTER_DEFAULT_URGENT_FEE_BPS: u64 = 90;
pub const FAST_PRIVATE_EXIT_ROUTER_DEFAULT_REORG_SURCHARGE_BPS: u64 = 35;
pub const FAST_PRIVATE_EXIT_ROUTER_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 7_500;
pub const FAST_PRIVATE_EXIT_ROUTER_DEFAULT_MAX_SPONSOR_REBATE_BPS: u64 = 9_500;
pub const FAST_PRIVATE_EXIT_ROUTER_DEFAULT_FEE_FLOOR_UNITS: u64 = 2;
pub const FAST_PRIVATE_EXIT_ROUTER_DEFAULT_SPONSOR_POOL_UNITS: u64 = 80_000;
pub const FAST_PRIVATE_EXIT_ROUTER_DEFAULT_DAILY_ROUTER_LIMIT_UNITS: u64 = 6_000_000;
pub const FAST_PRIVATE_EXIT_ROUTER_DEFAULT_DAILY_MAKER_LIMIT_UNITS: u64 = 1_800_000;
pub const FAST_PRIVATE_EXIT_ROUTER_DEFAULT_THROTTLE_WINDOW_BLOCKS: u64 = 64;
pub const FAST_PRIVATE_EXIT_ROUTER_DEFAULT_THROTTLE_MAX_EXITS: u64 = 384;
pub const FAST_PRIVATE_EXIT_ROUTER_DEFAULT_THROTTLE_MAX_UNITS: u64 = 1_200_000;
pub const FAST_PRIVATE_EXIT_ROUTER_MAX_BPS: u64 = 10_000;
pub const FAST_PRIVATE_EXIT_ROUTER_MAX_EXITS: usize = 262_144;
pub const FAST_PRIVATE_EXIT_ROUTER_MAX_RESERVATIONS: usize = 262_144;
pub const FAST_PRIVATE_EXIT_ROUTER_MAX_PAYOUTS: usize = 262_144;
pub const FAST_PRIVATE_EXIT_ROUTER_MAX_ATTESTATIONS: usize = 524_288;
pub const FAST_PRIVATE_EXIT_ROUTER_MAX_REORG_BANDS: usize = 64;
pub const FAST_PRIVATE_EXIT_ROUTER_MAX_SPONSORSHIPS: usize = 131_072;
pub const FAST_PRIVATE_EXIT_ROUTER_MAX_RECEIPTS: usize = 262_144;
pub const FAST_PRIVATE_EXIT_ROUTER_MAX_DISPUTES: usize = 131_072;
pub const FAST_PRIVATE_EXIT_ROUTER_MAX_THROTTLES: usize = 512;
pub const FAST_PRIVATE_EXIT_ROUTER_MAX_PUBLIC_RECORDS: usize = 524_288;
pub const FAST_PRIVATE_EXIT_ROUTER_MAX_EVENTS: usize = 524_288;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitSpeed {
    LowFee,
    Normal,
    Fast,
    Urgent,
    Emergency,
}

impl ExitSpeed {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::Normal => "normal",
            Self::Fast => "fast",
            Self::Urgent => "urgent",
            Self::Emergency => "emergency",
        }
    }

    pub fn fee_bps(self, config: &FastPrivateExitRouterConfig) -> u64 {
        match self {
            Self::LowFee => config.base_fee_bps / 2,
            Self::Normal => config.base_fee_bps,
            Self::Fast => config.fast_fee_bps,
            Self::Urgent | Self::Emergency => config.urgent_fee_bps,
        }
    }

    pub fn risk_weight_bps(self) -> u64 {
        match self {
            Self::LowFee => 9_500,
            Self::Normal => 10_000,
            Self::Fast => 11_250,
            Self::Urgent => 13_000,
            Self::Emergency => 16_000,
        }
    }

    pub fn ttl_blocks(self, config: &FastPrivateExitRouterConfig) -> u64 {
        match self {
            Self::Emergency => config.reservation_ttl_blocks.max(1),
            Self::Urgent => config.exit_ttl_blocks.min(12).max(1),
            Self::Fast => config.exit_ttl_blocks.min(18).max(1),
            Self::LowFee => config.exit_ttl_blocks.saturating_mul(2).max(1),
            Self::Normal => config.exit_ttl_blocks.max(1),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitPrivacyMode {
    FullyShielded,
    AmountBucketed,
    MakerScoped,
    Sponsored,
    EmergencyScoped,
}

impl ExitPrivacyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FullyShielded => "fully_shielded",
            Self::AmountBucketed => "amount_bucketed",
            Self::MakerScoped => "maker_scoped",
            Self::Sponsored => "sponsored",
            Self::EmergencyScoped => "emergency_scoped",
        }
    }

    pub fn requires_delayed_reveal(self) -> bool {
        matches!(
            self,
            Self::FullyShielded | Self::AmountBucketed | Self::Sponsored
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitCommitmentStatus {
    Submitted,
    Reserved,
    PayoutCommitted,
    Attested,
    Revealing,
    Settling,
    Settled,
    Challenged,
    Cancelled,
    Expired,
    Rejected,
}

impl ExitCommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Reserved => "reserved",
            Self::PayoutCommitted => "payout_committed",
            Self::Attested => "attested",
            Self::Revealing => "revealing",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::Reserved
                | Self::PayoutCommitted
                | Self::Attested
                | Self::Revealing
                | Self::Settling
                | Self::Challenged
        )
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Cancelled | Self::Expired | Self::Rejected
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Open,
    Bound,
    PartiallyFilled,
    Filled,
    Released,
    Challenged,
    Expired,
    Cancelled,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Bound => "bound",
            Self::PartiallyFilled => "partially_filled",
            Self::Filled => "filled",
            Self::Released => "released",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn open(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Bound | Self::PartiallyFilled | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayoutStatus {
    Planned,
    BroadcastCommitted,
    Confirmed,
    Final,
    Reorged,
    Cancelled,
}

impl PayoutStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::BroadcastCommitted => "broadcast_committed",
            Self::Confirmed => "confirmed",
            Self::Final => "final",
            Self::Reorged => "reorged",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Planned | Self::BroadcastCommitted | Self::Confirmed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MakerAttestationRole {
    Maker,
    Router,
    ReserveCommittee,
    Watchtower,
    Sponsor,
}

impl MakerAttestationRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Maker => "maker",
            Self::Router => "router",
            Self::ReserveCommittee => "reserve_committee",
            Self::Watchtower => "watchtower",
            Self::Sponsor => "sponsor",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReorgRiskLevel {
    Green,
    Yellow,
    Orange,
    Red,
    Halted,
}

impl ReorgRiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Green => "green",
            Self::Yellow => "yellow",
            Self::Orange => "orange",
            Self::Red => "red",
            Self::Halted => "halted",
        }
    }

    pub fn permits_fast_exit(self) -> bool {
        matches!(self, Self::Green | Self::Yellow | Self::Orange)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Offered,
    Reserved,
    Applied,
    Reclaimed,
    Expired,
    Cancelled,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Reclaimed => "reclaimed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Offered | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevealReceiptStatus {
    Hidden,
    RevealPending,
    RevealOpen,
    Revealed,
    Expired,
    Disputed,
}

impl RevealReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hidden => "hidden",
            Self::RevealPending => "reveal_pending",
            Self::RevealOpen => "reveal_open",
            Self::Revealed => "revealed",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Hidden | Self::RevealPending | Self::RevealOpen)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeStatus {
    Open,
    EvidenceCommitted,
    MakerResponded,
    RouterResponded,
    Resolved,
    Slashed,
    Expired,
}

impl DisputeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceCommitted => "evidence_committed",
            Self::MakerResponded => "maker_responded",
            Self::RouterResponded => "router_responded",
            Self::Resolved => "resolved",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::EvidenceCommitted | Self::MakerResponded | Self::RouterResponded
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyThrottleStatus {
    Armed,
    Active,
    Draining,
    Released,
    Expired,
}

impl EmergencyThrottleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }

    pub fn blocks_new_exits(self) -> bool {
        matches!(self, Self::Active | Self::Draining)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastPrivateExitRouterConfig {
    pub chain_id: String,
    pub schema_version: u64,
    pub monero_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_suite: String,
    pub shielded_exit_scheme: String,
    pub stealth_payout_scheme: String,
    pub maker_attestation_scheme: String,
    pub delayed_reveal_scheme: String,
    pub dispute_scheme: String,
    pub low_fee_sponsor_scheme: String,
    pub exit_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub reveal_delay_blocks: u64,
    pub reveal_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub finality_blocks: u64,
    pub reorg_grace_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_reserve_coverage_bps: u64,
    pub warn_reserve_coverage_bps: u64,
    pub max_router_exposure_units: u64,
    pub max_maker_exposure_units: u64,
    pub max_pending_exits: usize,
    pub max_open_reservations_per_maker: usize,
    pub base_fee_bps: u64,
    pub fast_fee_bps: u64,
    pub urgent_fee_bps: u64,
    pub reorg_surcharge_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub max_sponsor_rebate_bps: u64,
    pub fee_floor_units: u64,
    pub sponsor_pool_units: u64,
    pub daily_router_limit_units: u64,
    pub daily_maker_limit_units: u64,
    pub throttle_window_blocks: u64,
    pub throttle_max_exits: u64,
    pub throttle_max_units: u64,
    pub max_exits: usize,
    pub max_reservations: usize,
    pub max_payouts: usize,
    pub max_attestations: usize,
    pub max_reorg_bands: usize,
    pub max_sponsorships: usize,
    pub max_receipts: usize,
    pub max_disputes: usize,
    pub max_throttles: usize,
    pub max_public_records: usize,
    pub max_events: usize,
}

impl Default for FastPrivateExitRouterConfig {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            schema_version: FAST_PRIVATE_EXIT_ROUTER_SCHEMA_VERSION,
            monero_network: FAST_PRIVATE_EXIT_ROUTER_DEVNET_MONERO_NETWORK.to_string(),
            asset_id: FAST_PRIVATE_EXIT_ROUTER_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: FAST_PRIVATE_EXIT_ROUTER_DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: FAST_PRIVATE_EXIT_ROUTER_HASH_SUITE.to_string(),
            pq_suite: FAST_PRIVATE_EXIT_ROUTER_PQ_SUITE.to_string(),
            shielded_exit_scheme: FAST_PRIVATE_EXIT_ROUTER_SHIELDED_EXIT_SCHEME.to_string(),
            stealth_payout_scheme: FAST_PRIVATE_EXIT_ROUTER_STEALTH_PAYOUT_SCHEME.to_string(),
            maker_attestation_scheme: FAST_PRIVATE_EXIT_ROUTER_MAKER_ATTESTATION_SCHEME.to_string(),
            delayed_reveal_scheme: FAST_PRIVATE_EXIT_ROUTER_DELAYED_REVEAL_SCHEME.to_string(),
            dispute_scheme: FAST_PRIVATE_EXIT_ROUTER_DISPUTE_SCHEME.to_string(),
            low_fee_sponsor_scheme: FAST_PRIVATE_EXIT_ROUTER_LOW_FEE_SPONSOR_SCHEME.to_string(),
            exit_ttl_blocks: FAST_PRIVATE_EXIT_ROUTER_DEFAULT_EXIT_TTL_BLOCKS,
            reservation_ttl_blocks: FAST_PRIVATE_EXIT_ROUTER_DEFAULT_RESERVATION_TTL_BLOCKS,
            reveal_delay_blocks: FAST_PRIVATE_EXIT_ROUTER_DEFAULT_REVEAL_DELAY_BLOCKS,
            reveal_ttl_blocks: FAST_PRIVATE_EXIT_ROUTER_DEFAULT_REVEAL_TTL_BLOCKS,
            challenge_window_blocks: FAST_PRIVATE_EXIT_ROUTER_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            finality_blocks: FAST_PRIVATE_EXIT_ROUTER_DEFAULT_FINALITY_BLOCKS,
            reorg_grace_blocks: FAST_PRIVATE_EXIT_ROUTER_DEFAULT_REORG_GRACE_BLOCKS,
            min_privacy_set_size: FAST_PRIVATE_EXIT_ROUTER_DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: FAST_PRIVATE_EXIT_ROUTER_DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_reserve_coverage_bps: FAST_PRIVATE_EXIT_ROUTER_DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            warn_reserve_coverage_bps: FAST_PRIVATE_EXIT_ROUTER_DEFAULT_WARN_RESERVE_COVERAGE_BPS,
            max_router_exposure_units: FAST_PRIVATE_EXIT_ROUTER_DEFAULT_MAX_ROUTER_EXPOSURE_UNITS,
            max_maker_exposure_units: FAST_PRIVATE_EXIT_ROUTER_DEFAULT_MAX_MAKER_EXPOSURE_UNITS,
            max_pending_exits: FAST_PRIVATE_EXIT_ROUTER_DEFAULT_MAX_PENDING_EXITS,
            max_open_reservations_per_maker:
                FAST_PRIVATE_EXIT_ROUTER_DEFAULT_MAX_OPEN_RESERVATIONS_PER_MAKER,
            base_fee_bps: FAST_PRIVATE_EXIT_ROUTER_DEFAULT_BASE_FEE_BPS,
            fast_fee_bps: FAST_PRIVATE_EXIT_ROUTER_DEFAULT_FAST_FEE_BPS,
            urgent_fee_bps: FAST_PRIVATE_EXIT_ROUTER_DEFAULT_URGENT_FEE_BPS,
            reorg_surcharge_bps: FAST_PRIVATE_EXIT_ROUTER_DEFAULT_REORG_SURCHARGE_BPS,
            low_fee_rebate_bps: FAST_PRIVATE_EXIT_ROUTER_DEFAULT_LOW_FEE_REBATE_BPS,
            max_sponsor_rebate_bps: FAST_PRIVATE_EXIT_ROUTER_DEFAULT_MAX_SPONSOR_REBATE_BPS,
            fee_floor_units: FAST_PRIVATE_EXIT_ROUTER_DEFAULT_FEE_FLOOR_UNITS,
            sponsor_pool_units: FAST_PRIVATE_EXIT_ROUTER_DEFAULT_SPONSOR_POOL_UNITS,
            daily_router_limit_units: FAST_PRIVATE_EXIT_ROUTER_DEFAULT_DAILY_ROUTER_LIMIT_UNITS,
            daily_maker_limit_units: FAST_PRIVATE_EXIT_ROUTER_DEFAULT_DAILY_MAKER_LIMIT_UNITS,
            throttle_window_blocks: FAST_PRIVATE_EXIT_ROUTER_DEFAULT_THROTTLE_WINDOW_BLOCKS,
            throttle_max_exits: FAST_PRIVATE_EXIT_ROUTER_DEFAULT_THROTTLE_MAX_EXITS,
            throttle_max_units: FAST_PRIVATE_EXIT_ROUTER_DEFAULT_THROTTLE_MAX_UNITS,
            max_exits: FAST_PRIVATE_EXIT_ROUTER_MAX_EXITS,
            max_reservations: FAST_PRIVATE_EXIT_ROUTER_MAX_RESERVATIONS,
            max_payouts: FAST_PRIVATE_EXIT_ROUTER_MAX_PAYOUTS,
            max_attestations: FAST_PRIVATE_EXIT_ROUTER_MAX_ATTESTATIONS,
            max_reorg_bands: FAST_PRIVATE_EXIT_ROUTER_MAX_REORG_BANDS,
            max_sponsorships: FAST_PRIVATE_EXIT_ROUTER_MAX_SPONSORSHIPS,
            max_receipts: FAST_PRIVATE_EXIT_ROUTER_MAX_RECEIPTS,
            max_disputes: FAST_PRIVATE_EXIT_ROUTER_MAX_DISPUTES,
            max_throttles: FAST_PRIVATE_EXIT_ROUTER_MAX_THROTTLES,
            max_public_records: FAST_PRIVATE_EXIT_ROUTER_MAX_PUBLIC_RECORDS,
            max_events: FAST_PRIVATE_EXIT_ROUTER_MAX_EVENTS,
        }
    }
}

impl FastPrivateExitRouterConfig {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> FastPrivateExitRouterResult<()> {
        ensure_non_empty("config.chain_id", &self.chain_id)?;
        ensure_non_empty("config.monero_network", &self.monero_network)?;
        ensure_non_empty("config.asset_id", &self.asset_id)?;
        ensure_non_empty("config.fee_asset_id", &self.fee_asset_id)?;
        ensure_non_empty("config.hash_suite", &self.hash_suite)?;
        ensure_non_empty("config.pq_suite", &self.pq_suite)?;
        ensure_non_empty("config.shielded_exit_scheme", &self.shielded_exit_scheme)?;
        ensure_non_empty("config.stealth_payout_scheme", &self.stealth_payout_scheme)?;
        ensure_non_empty(
            "config.maker_attestation_scheme",
            &self.maker_attestation_scheme,
        )?;
        ensure_non_empty("config.delayed_reveal_scheme", &self.delayed_reveal_scheme)?;
        ensure_non_empty("config.dispute_scheme", &self.dispute_scheme)?;
        ensure_non_empty(
            "config.low_fee_sponsor_scheme",
            &self.low_fee_sponsor_scheme,
        )?;
        ensure_positive("config.exit_ttl_blocks", self.exit_ttl_blocks)?;
        ensure_positive("config.reservation_ttl_blocks", self.reservation_ttl_blocks)?;
        ensure_positive("config.reveal_delay_blocks", self.reveal_delay_blocks)?;
        ensure_positive("config.reveal_ttl_blocks", self.reveal_ttl_blocks)?;
        ensure_positive(
            "config.challenge_window_blocks",
            self.challenge_window_blocks,
        )?;
        ensure_positive("config.finality_blocks", self.finality_blocks)?;
        ensure_positive("config.reorg_grace_blocks", self.reorg_grace_blocks)?;
        ensure_positive("config.min_privacy_set_size", self.min_privacy_set_size)?;
        ensure_positive(
            "config.target_privacy_set_size",
            self.target_privacy_set_size,
        )?;
        if self.min_privacy_set_size > self.target_privacy_set_size {
            return Err("config privacy set bounds are inconsistent".to_string());
        }
        ensure_positive(
            "config.min_reserve_coverage_bps",
            self.min_reserve_coverage_bps,
        )?;
        ensure_positive(
            "config.warn_reserve_coverage_bps",
            self.warn_reserve_coverage_bps,
        )?;
        if self.warn_reserve_coverage_bps < self.min_reserve_coverage_bps {
            return Err("config reserve coverage warning below minimum".to_string());
        }
        ensure_positive(
            "config.max_router_exposure_units",
            self.max_router_exposure_units,
        )?;
        ensure_positive(
            "config.max_maker_exposure_units",
            self.max_maker_exposure_units,
        )?;
        ensure_capacity("config.max_pending_exits", self.max_pending_exits)?;
        ensure_capacity(
            "config.max_open_reservations_per_maker",
            self.max_open_reservations_per_maker,
        )?;
        ensure_bps("config.base_fee_bps", self.base_fee_bps)?;
        ensure_bps("config.fast_fee_bps", self.fast_fee_bps)?;
        ensure_bps("config.urgent_fee_bps", self.urgent_fee_bps)?;
        ensure_bps("config.reorg_surcharge_bps", self.reorg_surcharge_bps)?;
        ensure_bps("config.low_fee_rebate_bps", self.low_fee_rebate_bps)?;
        ensure_bps("config.max_sponsor_rebate_bps", self.max_sponsor_rebate_bps)?;
        if self.low_fee_rebate_bps > self.max_sponsor_rebate_bps {
            return Err("config low fee rebate exceeds sponsor rebate cap".to_string());
        }
        ensure_positive(
            "config.daily_router_limit_units",
            self.daily_router_limit_units,
        )?;
        ensure_positive(
            "config.daily_maker_limit_units",
            self.daily_maker_limit_units,
        )?;
        ensure_positive("config.throttle_window_blocks", self.throttle_window_blocks)?;
        ensure_positive("config.throttle_max_exits", self.throttle_max_exits)?;
        ensure_positive("config.throttle_max_units", self.throttle_max_units)?;
        ensure_capacity("config.max_exits", self.max_exits)?;
        ensure_capacity("config.max_reservations", self.max_reservations)?;
        ensure_capacity("config.max_payouts", self.max_payouts)?;
        ensure_capacity("config.max_attestations", self.max_attestations)?;
        ensure_capacity("config.max_reorg_bands", self.max_reorg_bands)?;
        ensure_capacity("config.max_sponsorships", self.max_sponsorships)?;
        ensure_capacity("config.max_receipts", self.max_receipts)?;
        ensure_capacity("config.max_disputes", self.max_disputes)?;
        ensure_capacity("config.max_throttles", self.max_throttles)?;
        ensure_capacity("config.max_public_records", self.max_public_records)?;
        ensure_capacity("config.max_events", self.max_events)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_private_exit_router_config",
            "chain_id": self.chain_id,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": self.schema_version,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "pq_suite": self.pq_suite,
            "shielded_exit_scheme": self.shielded_exit_scheme,
            "stealth_payout_scheme": self.stealth_payout_scheme,
            "maker_attestation_scheme": self.maker_attestation_scheme,
            "delayed_reveal_scheme": self.delayed_reveal_scheme,
            "dispute_scheme": self.dispute_scheme,
            "low_fee_sponsor_scheme": self.low_fee_sponsor_scheme,
            "exit_ttl_blocks": self.exit_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "reveal_delay_blocks": self.reveal_delay_blocks,
            "reveal_ttl_blocks": self.reveal_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "finality_blocks": self.finality_blocks,
            "reorg_grace_blocks": self.reorg_grace_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "warn_reserve_coverage_bps": self.warn_reserve_coverage_bps,
            "max_router_exposure_units": self.max_router_exposure_units,
            "max_maker_exposure_units": self.max_maker_exposure_units,
            "max_pending_exits": self.max_pending_exits as u64,
            "max_open_reservations_per_maker": self.max_open_reservations_per_maker as u64,
            "base_fee_bps": self.base_fee_bps,
            "fast_fee_bps": self.fast_fee_bps,
            "urgent_fee_bps": self.urgent_fee_bps,
            "reorg_surcharge_bps": self.reorg_surcharge_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "max_sponsor_rebate_bps": self.max_sponsor_rebate_bps,
            "fee_floor_units": self.fee_floor_units,
            "sponsor_pool_units": self.sponsor_pool_units,
            "daily_router_limit_units": self.daily_router_limit_units,
            "daily_maker_limit_units": self.daily_maker_limit_units,
            "throttle_window_blocks": self.throttle_window_blocks,
            "throttle_max_exits": self.throttle_max_exits,
            "throttle_max_units": self.throttle_max_units,
            "max_exits": self.max_exits as u64,
            "max_reservations": self.max_reservations as u64,
            "max_payouts": self.max_payouts as u64,
            "max_attestations": self.max_attestations as u64,
            "max_reorg_bands": self.max_reorg_bands as u64,
            "max_sponsorships": self.max_sponsorships as u64,
            "max_receipts": self.max_receipts as u64,
            "max_disputes": self.max_disputes as u64,
            "max_throttles": self.max_throttles as u64,
            "max_public_records": self.max_public_records as u64,
            "max_events": self.max_events as u64,
        })
    }

    pub fn config_root(&self) -> String {
        router_payload_root("FAST-PRIVATE-EXIT-ROUTER-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedExitCommitment {
    pub exit_id: String,
    pub owner_commitment: String,
    pub account_commitment: String,
    pub source_note_root: String,
    pub nullifier_root: String,
    pub amount_commitment: String,
    pub amount_bucket: u64,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub min_payout_units: u64,
    pub speed: ExitSpeed,
    pub privacy_mode: ExitPrivacyMode,
    pub pq_session_id: String,
    pub wallet_attestation_root: String,
    pub route_hint_root: String,
    pub sponsor_id: Option<String>,
    pub reservation_id: Option<String>,
    pub payout_id: Option<String>,
    pub receipt_id: Option<String>,
    pub dispute_id: Option<String>,
    pub requested_at_height: u64,
    pub expires_at_height: u64,
    pub challenge_window_end_height: u64,
    pub privacy_set_size: u64,
    pub reorg_band_id: String,
    pub risk_score_bps: u64,
    pub metadata_root: String,
    pub status: ExitCommitmentStatus,
}

impl ShieldedExitCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_commitment: &str,
        account_commitment: &str,
        source_note_root: &str,
        nullifier_root: &str,
        amount_commitment: &str,
        amount_bucket: u64,
        asset_id: &str,
        fee_asset_id: &str,
        max_fee_units: u64,
        min_payout_units: u64,
        speed: ExitSpeed,
        privacy_mode: ExitPrivacyMode,
        pq_session_id: &str,
        requested_at_height: u64,
        config: &FastPrivateExitRouterConfig,
    ) -> FastPrivateExitRouterResult<Self> {
        ensure_non_empty("exit.owner_commitment", owner_commitment)?;
        ensure_non_empty("exit.account_commitment", account_commitment)?;
        ensure_non_empty("exit.source_note_root", source_note_root)?;
        ensure_non_empty("exit.nullifier_root", nullifier_root)?;
        ensure_non_empty("exit.amount_commitment", amount_commitment)?;
        ensure_positive("exit.amount_bucket", amount_bucket)?;
        ensure_non_empty("exit.asset_id", asset_id)?;
        ensure_non_empty("exit.fee_asset_id", fee_asset_id)?;
        ensure_non_empty("exit.pq_session_id", pq_session_id)?;
        let expires_at_height = requested_at_height.saturating_add(speed.ttl_blocks(config));
        let challenge_window_end_height =
            requested_at_height.saturating_add(config.challenge_window_blocks);
        let identity = json!({
            "owner_commitment": owner_commitment,
            "account_commitment": account_commitment,
            "source_note_root": source_note_root,
            "nullifier_root": nullifier_root,
            "amount_commitment": amount_commitment,
            "amount_bucket": amount_bucket,
            "asset_id": asset_id,
            "pq_session_id": pq_session_id,
            "requested_at_height": requested_at_height,
        });
        let exit_id = router_payload_root("FAST-PRIVATE-EXIT-ROUTER-EXIT-ID", &identity);
        Ok(Self {
            exit_id,
            owner_commitment: owner_commitment.to_string(),
            account_commitment: account_commitment.to_string(),
            source_note_root: source_note_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            amount_commitment: amount_commitment.to_string(),
            amount_bucket,
            asset_id: asset_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            max_fee_units,
            min_payout_units,
            speed,
            privacy_mode,
            pq_session_id: pq_session_id.to_string(),
            wallet_attestation_root: String::new(),
            route_hint_root: empty_root("exit-route-hints"),
            sponsor_id: None,
            reservation_id: None,
            payout_id: None,
            receipt_id: None,
            dispute_id: None,
            requested_at_height,
            expires_at_height,
            challenge_window_end_height,
            privacy_set_size: config.target_privacy_set_size,
            reorg_band_id: "devnet-green".to_string(),
            risk_score_bps: speed.risk_weight_bps(),
            metadata_root: empty_root("exit-metadata"),
            status: ExitCommitmentStatus::Submitted,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_private_exit_router_shielded_exit",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "exit_id": self.exit_id,
            "owner_commitment": self.owner_commitment,
            "account_commitment": self.account_commitment,
            "source_note_root": self.source_note_root,
            "nullifier_root": self.nullifier_root,
            "amount_commitment": self.amount_commitment,
            "amount_bucket": self.amount_bucket,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "min_payout_units": self.min_payout_units,
            "speed": self.speed.as_str(),
            "privacy_mode": self.privacy_mode.as_str(),
            "pq_session_id": self.pq_session_id,
            "wallet_attestation_root": self.wallet_attestation_root,
            "route_hint_root": self.route_hint_root,
            "sponsor_id": self.sponsor_id,
            "reservation_id": self.reservation_id,
            "payout_id": self.payout_id,
            "receipt_id": self.receipt_id,
            "dispute_id": self.dispute_id,
            "requested_at_height": self.requested_at_height,
            "expires_at_height": self.expires_at_height,
            "challenge_window_end_height": self.challenge_window_end_height,
            "privacy_set_size": self.privacy_set_size,
            "reorg_band_id": self.reorg_band_id,
            "risk_score_bps": self.risk_score_bps,
            "metadata_root": self.metadata_root,
            "status": self.status.as_str(),
        })
    }

    pub fn exit_root(&self) -> String {
        router_payload_root(
            "FAST-PRIVATE-EXIT-ROUTER-SHIELDED-EXIT",
            &self.public_record(),
        )
    }

    pub fn validate(
        &self,
        config: &FastPrivateExitRouterConfig,
    ) -> FastPrivateExitRouterResult<String> {
        ensure_non_empty("exit.exit_id", &self.exit_id)?;
        ensure_non_empty("exit.owner_commitment", &self.owner_commitment)?;
        ensure_non_empty("exit.account_commitment", &self.account_commitment)?;
        ensure_non_empty("exit.source_note_root", &self.source_note_root)?;
        ensure_non_empty("exit.nullifier_root", &self.nullifier_root)?;
        ensure_non_empty("exit.amount_commitment", &self.amount_commitment)?;
        ensure_positive("exit.amount_bucket", self.amount_bucket)?;
        ensure_non_empty("exit.asset_id", &self.asset_id)?;
        ensure_non_empty("exit.fee_asset_id", &self.fee_asset_id)?;
        ensure_non_empty("exit.pq_session_id", &self.pq_session_id)?;
        ensure_height_order(
            "exit.requested_to_expires",
            self.requested_at_height,
            self.expires_at_height,
        )?;
        ensure_height_order(
            "exit.requested_to_challenge",
            self.requested_at_height,
            self.challenge_window_end_height,
        )?;
        ensure_positive("exit.privacy_set_size", self.privacy_set_size)?;
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("exit privacy set below configured minimum".to_string());
        }
        ensure_positive("exit.risk_score_bps", self.risk_score_bps)?;
        if self.asset_id != config.asset_id {
            return Err("exit asset mismatch".to_string());
        }
        if self.fee_asset_id != config.fee_asset_id {
            return Err("exit fee asset mismatch".to_string());
        }
        Ok(self.exit_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MakerLiquidityReservation {
    pub reservation_id: String,
    pub maker_id: String,
    pub maker_label: String,
    pub exit_ids: BTreeSet<String>,
    pub asset_id: String,
    pub reserved_units: u64,
    pub filled_units: u64,
    pub fee_units: u64,
    pub premium_bps: u64,
    pub reserve_coverage_bps: u64,
    pub available_inventory_root: String,
    pub maker_pq_key_commitment: String,
    pub attestation_id: Option<String>,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: ReservationStatus,
}

impl MakerLiquidityReservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        maker_id: &str,
        maker_label: &str,
        exit_id: &str,
        asset_id: &str,
        reserved_units: u64,
        fee_units: u64,
        premium_bps: u64,
        reserve_coverage_bps: u64,
        maker_pq_key_commitment: &str,
        created_at_height: u64,
        config: &FastPrivateExitRouterConfig,
    ) -> FastPrivateExitRouterResult<Self> {
        ensure_non_empty("reservation.maker_id", maker_id)?;
        ensure_non_empty("reservation.maker_label", maker_label)?;
        ensure_non_empty("reservation.exit_id", exit_id)?;
        ensure_non_empty("reservation.asset_id", asset_id)?;
        ensure_positive("reservation.reserved_units", reserved_units)?;
        ensure_bps("reservation.premium_bps", premium_bps)?;
        ensure_positive("reservation.reserve_coverage_bps", reserve_coverage_bps)?;
        ensure_non_empty(
            "reservation.maker_pq_key_commitment",
            maker_pq_key_commitment,
        )?;
        let mut exit_ids = BTreeSet::new();
        exit_ids.insert(exit_id.to_string());
        let identity = json!({
            "maker_id": maker_id,
            "exit_id": exit_id,
            "reserved_units": reserved_units,
            "created_at_height": created_at_height,
        });
        Ok(Self {
            reservation_id: router_payload_root(
                "FAST-PRIVATE-EXIT-ROUTER-RESERVATION-ID",
                &identity,
            ),
            maker_id: maker_id.to_string(),
            maker_label: maker_label.to_string(),
            exit_ids,
            asset_id: asset_id.to_string(),
            reserved_units,
            filled_units: 0,
            fee_units,
            premium_bps,
            reserve_coverage_bps,
            available_inventory_root: empty_root("maker-inventory"),
            maker_pq_key_commitment: maker_pq_key_commitment.to_string(),
            attestation_id: None,
            created_at_height,
            expires_at_height: created_at_height.saturating_add(config.reservation_ttl_blocks),
            status: ReservationStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_private_exit_router_maker_reservation",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "reservation_id": self.reservation_id,
            "maker_id": self.maker_id,
            "maker_label": self.maker_label,
            "exit_ids": set_strings(&self.exit_ids),
            "asset_id": self.asset_id,
            "reserved_units": self.reserved_units,
            "filled_units": self.filled_units,
            "available_units": self.available_units(),
            "fee_units": self.fee_units,
            "premium_bps": self.premium_bps,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "available_inventory_root": self.available_inventory_root,
            "maker_pq_key_commitment": self.maker_pq_key_commitment,
            "attestation_id": self.attestation_id,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn available_units(&self) -> u64 {
        self.reserved_units.saturating_sub(self.filled_units)
    }

    pub fn reservation_root(&self) -> String {
        router_payload_root(
            "FAST-PRIVATE-EXIT-ROUTER-MAKER-RESERVATION",
            &self.public_record(),
        )
    }

    pub fn validate(
        &self,
        config: &FastPrivateExitRouterConfig,
    ) -> FastPrivateExitRouterResult<String> {
        ensure_non_empty("reservation.reservation_id", &self.reservation_id)?;
        ensure_non_empty("reservation.maker_id", &self.maker_id)?;
        ensure_non_empty("reservation.maker_label", &self.maker_label)?;
        ensure_non_empty("reservation.asset_id", &self.asset_id)?;
        ensure_positive("reservation.reserved_units", self.reserved_units)?;
        if self.filled_units > self.reserved_units {
            return Err("reservation filled units exceed reserved units".to_string());
        }
        ensure_bps("reservation.premium_bps", self.premium_bps)?;
        ensure_positive(
            "reservation.reserve_coverage_bps",
            self.reserve_coverage_bps,
        )?;
        if self.reserve_coverage_bps < config.min_reserve_coverage_bps {
            return Err("reservation reserve coverage below minimum".to_string());
        }
        ensure_non_empty(
            "reservation.maker_pq_key_commitment",
            &self.maker_pq_key_commitment,
        )?;
        ensure_height_order(
            "reservation.created_to_expires",
            self.created_at_height,
            self.expires_at_height,
        )?;
        if self.exit_ids.is_empty() {
            return Err("reservation must bind at least one exit".to_string());
        }
        Ok(self.reservation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroPayoutStealthCommitment {
    pub payout_id: String,
    pub exit_id: String,
    pub reservation_id: String,
    pub maker_id: String,
    pub monero_network: String,
    pub stealth_address_commitment: String,
    pub view_tag_root: String,
    pub amount_commitment: String,
    pub amount_bucket: u64,
    pub tx_public_key_commitment: String,
    pub tx_key_image_root: String,
    pub decoy_set_root: String,
    pub ring_size: u64,
    pub payout_tx_commitment: String,
    pub broadcast_at_height: u64,
    pub confirmed_at_height: Option<u64>,
    pub final_at_height: u64,
    pub reorg_band_id: String,
    pub status: PayoutStatus,
}

impl MoneroPayoutStealthCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        exit_id: &str,
        reservation_id: &str,
        maker_id: &str,
        monero_network: &str,
        stealth_address_commitment: &str,
        view_tag_root: &str,
        amount_commitment: &str,
        amount_bucket: u64,
        broadcast_at_height: u64,
        config: &FastPrivateExitRouterConfig,
    ) -> FastPrivateExitRouterResult<Self> {
        ensure_non_empty("payout.exit_id", exit_id)?;
        ensure_non_empty("payout.reservation_id", reservation_id)?;
        ensure_non_empty("payout.maker_id", maker_id)?;
        ensure_non_empty("payout.monero_network", monero_network)?;
        ensure_non_empty(
            "payout.stealth_address_commitment",
            stealth_address_commitment,
        )?;
        ensure_non_empty("payout.view_tag_root", view_tag_root)?;
        ensure_non_empty("payout.amount_commitment", amount_commitment)?;
        ensure_positive("payout.amount_bucket", amount_bucket)?;
        let identity = json!({
            "exit_id": exit_id,
            "reservation_id": reservation_id,
            "maker_id": maker_id,
            "stealth_address_commitment": stealth_address_commitment,
            "broadcast_at_height": broadcast_at_height,
        });
        Ok(Self {
            payout_id: router_payload_root("FAST-PRIVATE-EXIT-ROUTER-PAYOUT-ID", &identity),
            exit_id: exit_id.to_string(),
            reservation_id: reservation_id.to_string(),
            maker_id: maker_id.to_string(),
            monero_network: monero_network.to_string(),
            stealth_address_commitment: stealth_address_commitment.to_string(),
            view_tag_root: view_tag_root.to_string(),
            amount_commitment: amount_commitment.to_string(),
            amount_bucket,
            tx_public_key_commitment: empty_root("payout-tx-public-key"),
            tx_key_image_root: empty_root("payout-key-images"),
            decoy_set_root: empty_root("payout-decoys"),
            ring_size: 32,
            payout_tx_commitment: empty_root("payout-tx"),
            broadcast_at_height,
            confirmed_at_height: None,
            final_at_height: broadcast_at_height.saturating_add(config.finality_blocks),
            reorg_band_id: "devnet-green".to_string(),
            status: PayoutStatus::Planned,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_private_exit_router_monero_payout",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "payout_id": self.payout_id,
            "exit_id": self.exit_id,
            "reservation_id": self.reservation_id,
            "maker_id": self.maker_id,
            "monero_network": self.monero_network,
            "stealth_address_commitment": self.stealth_address_commitment,
            "view_tag_root": self.view_tag_root,
            "amount_commitment": self.amount_commitment,
            "amount_bucket": self.amount_bucket,
            "tx_public_key_commitment": self.tx_public_key_commitment,
            "tx_key_image_root": self.tx_key_image_root,
            "decoy_set_root": self.decoy_set_root,
            "ring_size": self.ring_size,
            "payout_tx_commitment": self.payout_tx_commitment,
            "broadcast_at_height": self.broadcast_at_height,
            "confirmed_at_height": self.confirmed_at_height,
            "final_at_height": self.final_at_height,
            "reorg_band_id": self.reorg_band_id,
            "status": self.status.as_str(),
        })
    }

    pub fn payout_root(&self) -> String {
        router_payload_root(
            "FAST-PRIVATE-EXIT-ROUTER-MONERO-PAYOUT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> FastPrivateExitRouterResult<String> {
        ensure_non_empty("payout.payout_id", &self.payout_id)?;
        ensure_non_empty("payout.exit_id", &self.exit_id)?;
        ensure_non_empty("payout.reservation_id", &self.reservation_id)?;
        ensure_non_empty("payout.maker_id", &self.maker_id)?;
        ensure_non_empty("payout.monero_network", &self.monero_network)?;
        ensure_non_empty(
            "payout.stealth_address_commitment",
            &self.stealth_address_commitment,
        )?;
        ensure_positive("payout.amount_bucket", self.amount_bucket)?;
        ensure_positive("payout.ring_size", self.ring_size)?;
        ensure_height_order(
            "payout.broadcast_to_final",
            self.broadcast_at_height,
            self.final_at_height,
        )?;
        if let Some(confirmed_at_height) = self.confirmed_at_height {
            if confirmed_at_height < self.broadcast_at_height {
                return Err("payout confirmation precedes broadcast".to_string());
            }
        }
        Ok(self.payout_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqMakerAttestation {
    pub attestation_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub maker_id: String,
    pub role: MakerAttestationRole,
    pub pq_key_commitment: String,
    pub signature_scheme: String,
    pub signature_root: String,
    pub transcript_root: String,
    pub reserve_coverage_bps: u64,
    pub weight: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl PqMakerAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_kind: &str,
        subject_id: &str,
        subject_root: &str,
        maker_id: &str,
        role: MakerAttestationRole,
        pq_key_commitment: &str,
        signature_root: &str,
        transcript_root: &str,
        reserve_coverage_bps: u64,
        weight: u64,
        issued_at_height: u64,
        ttl_blocks: u64,
    ) -> FastPrivateExitRouterResult<Self> {
        ensure_non_empty("attestation.subject_kind", subject_kind)?;
        ensure_non_empty("attestation.subject_id", subject_id)?;
        ensure_non_empty("attestation.subject_root", subject_root)?;
        ensure_non_empty("attestation.maker_id", maker_id)?;
        ensure_non_empty("attestation.pq_key_commitment", pq_key_commitment)?;
        ensure_non_empty("attestation.signature_root", signature_root)?;
        ensure_non_empty("attestation.transcript_root", transcript_root)?;
        ensure_positive("attestation.reserve_coverage_bps", reserve_coverage_bps)?;
        ensure_positive("attestation.weight", weight)?;
        ensure_positive("attestation.ttl_blocks", ttl_blocks)?;
        let identity = json!({
            "subject_kind": subject_kind,
            "subject_id": subject_id,
            "maker_id": maker_id,
            "role": role.as_str(),
            "issued_at_height": issued_at_height,
        });
        Ok(Self {
            attestation_id: router_payload_root(
                "FAST-PRIVATE-EXIT-ROUTER-ATTESTATION-ID",
                &identity,
            ),
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            maker_id: maker_id.to_string(),
            role,
            pq_key_commitment: pq_key_commitment.to_string(),
            signature_scheme: FAST_PRIVATE_EXIT_ROUTER_MAKER_ATTESTATION_SCHEME.to_string(),
            signature_root: signature_root.to_string(),
            transcript_root: transcript_root.to_string(),
            reserve_coverage_bps,
            weight,
            issued_at_height,
            expires_at_height: issued_at_height.saturating_add(ttl_blocks),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_private_exit_router_pq_maker_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "maker_id": self.maker_id,
            "role": self.role.as_str(),
            "pq_key_commitment": self.pq_key_commitment,
            "signature_scheme": self.signature_scheme,
            "signature_root": self.signature_root,
            "transcript_root": self.transcript_root,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "weight": self.weight,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn attestation_root(&self) -> String {
        router_payload_root(
            "FAST-PRIVATE-EXIT-ROUTER-PQ-MAKER-ATTESTATION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> FastPrivateExitRouterResult<String> {
        ensure_non_empty("attestation.attestation_id", &self.attestation_id)?;
        ensure_non_empty("attestation.subject_kind", &self.subject_kind)?;
        ensure_non_empty("attestation.subject_id", &self.subject_id)?;
        ensure_non_empty("attestation.subject_root", &self.subject_root)?;
        ensure_non_empty("attestation.maker_id", &self.maker_id)?;
        ensure_non_empty("attestation.pq_key_commitment", &self.pq_key_commitment)?;
        ensure_non_empty("attestation.signature_scheme", &self.signature_scheme)?;
        ensure_non_empty("attestation.signature_root", &self.signature_root)?;
        ensure_non_empty("attestation.transcript_root", &self.transcript_root)?;
        ensure_positive(
            "attestation.reserve_coverage_bps",
            self.reserve_coverage_bps,
        )?;
        ensure_positive("attestation.weight", self.weight)?;
        ensure_height_order(
            "attestation.issued_to_expires",
            self.issued_at_height,
            self.expires_at_height,
        )?;
        Ok(self.attestation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReorgRiskBand {
    pub band_id: String,
    pub label: String,
    pub min_confirmations: u64,
    pub max_depth: u64,
    pub surcharge_bps: u64,
    pub required_reveal_delay_blocks: u64,
    pub maker_haircut_bps: u64,
    pub level: ReorgRiskLevel,
    pub active_from_height: u64,
    pub active_until_height: Option<u64>,
}

impl ReorgRiskBand {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: &str,
        min_confirmations: u64,
        max_depth: u64,
        surcharge_bps: u64,
        required_reveal_delay_blocks: u64,
        maker_haircut_bps: u64,
        level: ReorgRiskLevel,
        active_from_height: u64,
    ) -> FastPrivateExitRouterResult<Self> {
        ensure_non_empty("reorg_band.label", label)?;
        ensure_bps("reorg_band.surcharge_bps", surcharge_bps)?;
        ensure_bps("reorg_band.maker_haircut_bps", maker_haircut_bps)?;
        let identity = json!({
            "label": label,
            "min_confirmations": min_confirmations,
            "max_depth": max_depth,
            "level": level.as_str(),
            "active_from_height": active_from_height,
        });
        Ok(Self {
            band_id: router_payload_root("FAST-PRIVATE-EXIT-ROUTER-REORG-BAND-ID", &identity),
            label: label.to_string(),
            min_confirmations,
            max_depth,
            surcharge_bps,
            required_reveal_delay_blocks,
            maker_haircut_bps,
            level,
            active_from_height,
            active_until_height: None,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_private_exit_router_reorg_risk_band",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "band_id": self.band_id,
            "label": self.label,
            "min_confirmations": self.min_confirmations,
            "max_depth": self.max_depth,
            "surcharge_bps": self.surcharge_bps,
            "required_reveal_delay_blocks": self.required_reveal_delay_blocks,
            "maker_haircut_bps": self.maker_haircut_bps,
            "level": self.level.as_str(),
            "active_from_height": self.active_from_height,
            "active_until_height": self.active_until_height,
        })
    }

    pub fn band_root(&self) -> String {
        router_payload_root(
            "FAST-PRIVATE-EXIT-ROUTER-REORG-RISK-BAND",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> FastPrivateExitRouterResult<String> {
        ensure_non_empty("reorg_band.band_id", &self.band_id)?;
        ensure_non_empty("reorg_band.label", &self.label)?;
        ensure_bps("reorg_band.surcharge_bps", self.surcharge_bps)?;
        ensure_bps("reorg_band.maker_haircut_bps", self.maker_haircut_bps)?;
        if let Some(active_until_height) = self.active_until_height {
            if active_until_height < self.active_from_height {
                return Err("reorg band active-until precedes active-from".to_string());
            }
        }
        Ok(self.band_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub exit_id: Option<String>,
    pub fee_asset_id: String,
    pub reserved_rebate_units: u64,
    pub applied_rebate_units: u64,
    pub max_rebate_bps: u64,
    pub eligibility_root: String,
    pub privacy_budget_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: SponsorshipStatus,
}

impl LowFeeSponsorship {
    pub fn new(
        sponsor_commitment: &str,
        fee_asset_id: &str,
        reserved_rebate_units: u64,
        max_rebate_bps: u64,
        created_at_height: u64,
        config: &FastPrivateExitRouterConfig,
    ) -> FastPrivateExitRouterResult<Self> {
        ensure_non_empty("sponsorship.sponsor_commitment", sponsor_commitment)?;
        ensure_non_empty("sponsorship.fee_asset_id", fee_asset_id)?;
        ensure_bps("sponsorship.max_rebate_bps", max_rebate_bps)?;
        let identity = json!({
            "sponsor_commitment": sponsor_commitment,
            "fee_asset_id": fee_asset_id,
            "created_at_height": created_at_height,
        });
        Ok(Self {
            sponsorship_id: router_payload_root(
                "FAST-PRIVATE-EXIT-ROUTER-SPONSORSHIP-ID",
                &identity,
            ),
            sponsor_commitment: sponsor_commitment.to_string(),
            exit_id: None,
            fee_asset_id: fee_asset_id.to_string(),
            reserved_rebate_units,
            applied_rebate_units: 0,
            max_rebate_bps,
            eligibility_root: empty_root("sponsorship-eligibility"),
            privacy_budget_root: empty_root("sponsorship-privacy-budget"),
            created_at_height,
            expires_at_height: created_at_height.saturating_add(config.exit_ttl_blocks),
            status: SponsorshipStatus::Offered,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_private_exit_router_low_fee_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "exit_id": self.exit_id,
            "fee_asset_id": self.fee_asset_id,
            "reserved_rebate_units": self.reserved_rebate_units,
            "applied_rebate_units": self.applied_rebate_units,
            "available_rebate_units": self.available_rebate_units(),
            "max_rebate_bps": self.max_rebate_bps,
            "eligibility_root": self.eligibility_root,
            "privacy_budget_root": self.privacy_budget_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn available_rebate_units(&self) -> u64 {
        self.reserved_rebate_units
            .saturating_sub(self.applied_rebate_units)
    }

    pub fn sponsorship_root(&self) -> String {
        router_payload_root(
            "FAST-PRIVATE-EXIT-ROUTER-LOW-FEE-SPONSORSHIP",
            &self.public_record(),
        )
    }

    pub fn validate(
        &self,
        config: &FastPrivateExitRouterConfig,
    ) -> FastPrivateExitRouterResult<String> {
        ensure_non_empty("sponsorship.sponsorship_id", &self.sponsorship_id)?;
        ensure_non_empty("sponsorship.sponsor_commitment", &self.sponsor_commitment)?;
        ensure_non_empty("sponsorship.fee_asset_id", &self.fee_asset_id)?;
        if self.applied_rebate_units > self.reserved_rebate_units {
            return Err("sponsorship applied rebate exceeds reserved rebate".to_string());
        }
        ensure_bps("sponsorship.max_rebate_bps", self.max_rebate_bps)?;
        if self.max_rebate_bps > config.max_sponsor_rebate_bps {
            return Err("sponsorship rebate exceeds configured cap".to_string());
        }
        ensure_height_order(
            "sponsorship.created_to_expires",
            self.created_at_height,
            self.expires_at_height,
        )?;
        Ok(self.sponsorship_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelayedRevealReceipt {
    pub receipt_id: String,
    pub exit_id: String,
    pub payout_id: String,
    pub reservation_id: String,
    pub receipt_commitment: String,
    pub encrypted_payload_root: String,
    pub reveal_nullifier_root: String,
    pub reveal_transcript_root: String,
    pub maker_signature_root: String,
    pub router_signature_root: String,
    pub created_at_height: u64,
    pub reveal_at_height: u64,
    pub expires_at_height: u64,
    pub revealed_at_height: Option<u64>,
    pub status: RevealReceiptStatus,
}

impl DelayedRevealReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        exit_id: &str,
        payout_id: &str,
        reservation_id: &str,
        receipt_commitment: &str,
        encrypted_payload_root: &str,
        reveal_nullifier_root: &str,
        created_at_height: u64,
        config: &FastPrivateExitRouterConfig,
    ) -> FastPrivateExitRouterResult<Self> {
        ensure_non_empty("receipt.exit_id", exit_id)?;
        ensure_non_empty("receipt.payout_id", payout_id)?;
        ensure_non_empty("receipt.reservation_id", reservation_id)?;
        ensure_non_empty("receipt.receipt_commitment", receipt_commitment)?;
        ensure_non_empty("receipt.encrypted_payload_root", encrypted_payload_root)?;
        ensure_non_empty("receipt.reveal_nullifier_root", reveal_nullifier_root)?;
        let identity = json!({
            "exit_id": exit_id,
            "payout_id": payout_id,
            "reservation_id": reservation_id,
            "receipt_commitment": receipt_commitment,
            "created_at_height": created_at_height,
        });
        let reveal_at_height = created_at_height.saturating_add(config.reveal_delay_blocks);
        Ok(Self {
            receipt_id: router_payload_root("FAST-PRIVATE-EXIT-ROUTER-RECEIPT-ID", &identity),
            exit_id: exit_id.to_string(),
            payout_id: payout_id.to_string(),
            reservation_id: reservation_id.to_string(),
            receipt_commitment: receipt_commitment.to_string(),
            encrypted_payload_root: encrypted_payload_root.to_string(),
            reveal_nullifier_root: reveal_nullifier_root.to_string(),
            reveal_transcript_root: empty_root("receipt-reveal-transcript"),
            maker_signature_root: empty_root("receipt-maker-signature"),
            router_signature_root: empty_root("receipt-router-signature"),
            created_at_height,
            reveal_at_height,
            expires_at_height: reveal_at_height.saturating_add(config.reveal_ttl_blocks),
            revealed_at_height: None,
            status: RevealReceiptStatus::Hidden,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_private_exit_router_delayed_reveal_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "exit_id": self.exit_id,
            "payout_id": self.payout_id,
            "reservation_id": self.reservation_id,
            "receipt_commitment": self.receipt_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "reveal_nullifier_root": self.reveal_nullifier_root,
            "reveal_transcript_root": self.reveal_transcript_root,
            "maker_signature_root": self.maker_signature_root,
            "router_signature_root": self.router_signature_root,
            "created_at_height": self.created_at_height,
            "reveal_at_height": self.reveal_at_height,
            "expires_at_height": self.expires_at_height,
            "revealed_at_height": self.revealed_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn receipt_root(&self) -> String {
        router_payload_root(
            "FAST-PRIVATE-EXIT-ROUTER-DELAYED-REVEAL-RECEIPT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> FastPrivateExitRouterResult<String> {
        ensure_non_empty("receipt.receipt_id", &self.receipt_id)?;
        ensure_non_empty("receipt.exit_id", &self.exit_id)?;
        ensure_non_empty("receipt.payout_id", &self.payout_id)?;
        ensure_non_empty("receipt.reservation_id", &self.reservation_id)?;
        ensure_non_empty("receipt.receipt_commitment", &self.receipt_commitment)?;
        ensure_height_order(
            "receipt.created_to_reveal",
            self.created_at_height,
            self.reveal_at_height,
        )?;
        ensure_height_order(
            "receipt.reveal_to_expires",
            self.reveal_at_height,
            self.expires_at_height,
        )?;
        if let Some(revealed_at_height) = self.revealed_at_height {
            if revealed_at_height < self.reveal_at_height {
                return Err("receipt reveal height precedes reveal opening".to_string());
            }
        }
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeChallengeWindow {
    pub dispute_id: String,
    pub exit_id: String,
    pub reservation_id: Option<String>,
    pub payout_id: Option<String>,
    pub challenger_commitment: String,
    pub claim_root: String,
    pub evidence_root: String,
    pub response_root: String,
    pub bond_units: u64,
    pub opened_at_height: u64,
    pub respond_by_height: u64,
    pub resolve_by_height: u64,
    pub status: DisputeStatus,
}

impl DisputeChallengeWindow {
    pub fn new(
        exit_id: &str,
        challenger_commitment: &str,
        claim_root: &str,
        bond_units: u64,
        opened_at_height: u64,
        config: &FastPrivateExitRouterConfig,
    ) -> FastPrivateExitRouterResult<Self> {
        ensure_non_empty("dispute.exit_id", exit_id)?;
        ensure_non_empty("dispute.challenger_commitment", challenger_commitment)?;
        ensure_non_empty("dispute.claim_root", claim_root)?;
        let identity = json!({
            "exit_id": exit_id,
            "challenger_commitment": challenger_commitment,
            "claim_root": claim_root,
            "opened_at_height": opened_at_height,
        });
        let respond_by_height = opened_at_height.saturating_add(config.challenge_window_blocks / 2);
        Ok(Self {
            dispute_id: router_payload_root("FAST-PRIVATE-EXIT-ROUTER-DISPUTE-ID", &identity),
            exit_id: exit_id.to_string(),
            reservation_id: None,
            payout_id: None,
            challenger_commitment: challenger_commitment.to_string(),
            claim_root: claim_root.to_string(),
            evidence_root: empty_root("dispute-evidence"),
            response_root: empty_root("dispute-response"),
            bond_units,
            opened_at_height,
            respond_by_height,
            resolve_by_height: opened_at_height.saturating_add(config.challenge_window_blocks),
            status: DisputeStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_private_exit_router_dispute_challenge",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "dispute_id": self.dispute_id,
            "exit_id": self.exit_id,
            "reservation_id": self.reservation_id,
            "payout_id": self.payout_id,
            "challenger_commitment": self.challenger_commitment,
            "claim_root": self.claim_root,
            "evidence_root": self.evidence_root,
            "response_root": self.response_root,
            "bond_units": self.bond_units,
            "opened_at_height": self.opened_at_height,
            "respond_by_height": self.respond_by_height,
            "resolve_by_height": self.resolve_by_height,
            "status": self.status.as_str(),
        })
    }

    pub fn dispute_root(&self) -> String {
        router_payload_root(
            "FAST-PRIVATE-EXIT-ROUTER-DISPUTE-CHALLENGE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> FastPrivateExitRouterResult<String> {
        ensure_non_empty("dispute.dispute_id", &self.dispute_id)?;
        ensure_non_empty("dispute.exit_id", &self.exit_id)?;
        ensure_non_empty("dispute.challenger_commitment", &self.challenger_commitment)?;
        ensure_non_empty("dispute.claim_root", &self.claim_root)?;
        ensure_height_order(
            "dispute.opened_to_respond",
            self.opened_at_height,
            self.respond_by_height,
        )?;
        ensure_height_order(
            "dispute.respond_to_resolve",
            self.respond_by_height,
            self.resolve_by_height,
        )?;
        Ok(self.dispute_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyThrottle {
    pub throttle_id: String,
    pub scope: String,
    pub reason_root: String,
    pub activated_by_commitment: String,
    pub affected_makers: BTreeSet<String>,
    pub max_exit_count: u64,
    pub max_exit_units: u64,
    pub consumed_exit_count: u64,
    pub consumed_exit_units: u64,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
    pub status: EmergencyThrottleStatus,
}

impl EmergencyThrottle {
    pub fn new(
        scope: &str,
        reason_root: &str,
        activated_by_commitment: &str,
        activated_at_height: u64,
        config: &FastPrivateExitRouterConfig,
    ) -> FastPrivateExitRouterResult<Self> {
        ensure_non_empty("throttle.scope", scope)?;
        ensure_non_empty("throttle.reason_root", reason_root)?;
        ensure_non_empty("throttle.activated_by_commitment", activated_by_commitment)?;
        let identity = json!({
            "scope": scope,
            "reason_root": reason_root,
            "activated_by_commitment": activated_by_commitment,
            "activated_at_height": activated_at_height,
        });
        Ok(Self {
            throttle_id: router_payload_root("FAST-PRIVATE-EXIT-ROUTER-THROTTLE-ID", &identity),
            scope: scope.to_string(),
            reason_root: reason_root.to_string(),
            activated_by_commitment: activated_by_commitment.to_string(),
            affected_makers: BTreeSet::new(),
            max_exit_count: config.throttle_max_exits,
            max_exit_units: config.throttle_max_units,
            consumed_exit_count: 0,
            consumed_exit_units: 0,
            activated_at_height,
            expires_at_height: activated_at_height.saturating_add(config.throttle_window_blocks),
            status: EmergencyThrottleStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_private_exit_router_emergency_throttle",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "throttle_id": self.throttle_id,
            "scope": self.scope,
            "reason_root": self.reason_root,
            "activated_by_commitment": self.activated_by_commitment,
            "affected_makers": set_strings(&self.affected_makers),
            "max_exit_count": self.max_exit_count,
            "max_exit_units": self.max_exit_units,
            "consumed_exit_count": self.consumed_exit_count,
            "consumed_exit_units": self.consumed_exit_units,
            "remaining_exit_count": self.remaining_exit_count(),
            "remaining_exit_units": self.remaining_exit_units(),
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn remaining_exit_count(&self) -> u64 {
        self.max_exit_count.saturating_sub(self.consumed_exit_count)
    }

    pub fn remaining_exit_units(&self) -> u64 {
        self.max_exit_units.saturating_sub(self.consumed_exit_units)
    }

    pub fn throttle_root(&self) -> String {
        router_payload_root(
            "FAST-PRIVATE-EXIT-ROUTER-EMERGENCY-THROTTLE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> FastPrivateExitRouterResult<String> {
        ensure_non_empty("throttle.throttle_id", &self.throttle_id)?;
        ensure_non_empty("throttle.scope", &self.scope)?;
        ensure_non_empty("throttle.reason_root", &self.reason_root)?;
        ensure_non_empty(
            "throttle.activated_by_commitment",
            &self.activated_by_commitment,
        )?;
        if self.consumed_exit_count > self.max_exit_count {
            return Err("throttle consumed exits exceed cap".to_string());
        }
        if self.consumed_exit_units > self.max_exit_units {
            return Err("throttle consumed units exceed cap".to_string());
        }
        ensure_height_order(
            "throttle.activated_to_expires",
            self.activated_at_height,
            self.expires_at_height,
        )?;
        Ok(self.throttle_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicPublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
    pub publisher_commitment: String,
    pub sequence: u64,
}

impl DeterministicPublicRecord {
    pub fn new(
        record_kind: &str,
        subject_id: &str,
        subject_root: &str,
        payload: &Value,
        emitted_at_height: u64,
        publisher_commitment: &str,
        sequence: u64,
    ) -> FastPrivateExitRouterResult<Self> {
        ensure_non_empty("public_record.record_kind", record_kind)?;
        ensure_non_empty("public_record.subject_id", subject_id)?;
        ensure_non_empty("public_record.subject_root", subject_root)?;
        ensure_non_empty("public_record.publisher_commitment", publisher_commitment)?;
        let payload_root = router_payload_root("FAST-PRIVATE-EXIT-ROUTER-PUBLIC-PAYLOAD", payload);
        let identity = json!({
            "record_kind": record_kind,
            "subject_id": subject_id,
            "subject_root": subject_root,
            "payload_root": payload_root,
            "emitted_at_height": emitted_at_height,
            "publisher_commitment": publisher_commitment,
            "sequence": sequence,
        });
        Ok(Self {
            record_id: router_payload_root("FAST-PRIVATE-EXIT-ROUTER-PUBLIC-RECORD-ID", &identity),
            record_kind: record_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            payload_root,
            emitted_at_height,
            publisher_commitment: publisher_commitment.to_string(),
            sequence,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_private_exit_router_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
            "publisher_commitment": self.publisher_commitment,
            "sequence": self.sequence,
        })
    }

    pub fn record_root(&self) -> String {
        router_payload_root(
            "FAST-PRIVATE-EXIT-ROUTER-PUBLIC-RECORD",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> FastPrivateExitRouterResult<String> {
        ensure_non_empty("public_record.record_id", &self.record_id)?;
        ensure_non_empty("public_record.record_kind", &self.record_kind)?;
        ensure_non_empty("public_record.subject_id", &self.subject_id)?;
        ensure_non_empty("public_record.subject_root", &self.subject_root)?;
        ensure_non_empty("public_record.payload_root", &self.payload_root)?;
        ensure_non_empty(
            "public_record.publisher_commitment",
            &self.publisher_commitment,
        )?;
        Ok(self.record_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub height: u64,
    pub sequence: u64,
    pub details_root: String,
}

impl RouterEvent {
    pub fn new(
        event_kind: &str,
        subject_id: &str,
        subject_root: &str,
        height: u64,
        sequence: u64,
        details: &Value,
    ) -> FastPrivateExitRouterResult<Self> {
        ensure_non_empty("event.event_kind", event_kind)?;
        ensure_non_empty("event.subject_id", subject_id)?;
        ensure_non_empty("event.subject_root", subject_root)?;
        let details_root = router_payload_root("FAST-PRIVATE-EXIT-ROUTER-EVENT-DETAILS", details);
        let identity = json!({
            "event_kind": event_kind,
            "subject_id": subject_id,
            "subject_root": subject_root,
            "height": height,
            "sequence": sequence,
            "details_root": details_root,
        });
        Ok(Self {
            event_id: router_payload_root("FAST-PRIVATE-EXIT-ROUTER-EVENT-ID", &identity),
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            height,
            sequence,
            details_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_private_exit_router_event",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "height": self.height,
            "sequence": self.sequence,
            "details_root": self.details_root,
        })
    }

    pub fn event_root(&self) -> String {
        router_payload_root("FAST-PRIVATE-EXIT-ROUTER-EVENT", &self.public_record())
    }

    pub fn validate(&self) -> FastPrivateExitRouterResult<String> {
        ensure_non_empty("event.event_id", &self.event_id)?;
        ensure_non_empty("event.event_kind", &self.event_kind)?;
        ensure_non_empty("event.subject_id", &self.subject_id)?;
        ensure_non_empty("event.subject_root", &self.subject_root)?;
        ensure_non_empty("event.details_root", &self.details_root)?;
        Ok(self.event_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastPrivateExitRouterRoots {
    pub config_root: String,
    pub exit_commitment_root: String,
    pub maker_reservation_root: String,
    pub monero_payout_root: String,
    pub pq_maker_attestation_root: String,
    pub reorg_risk_band_root: String,
    pub low_fee_sponsorship_root: String,
    pub delayed_reveal_receipt_root: String,
    pub dispute_challenge_root: String,
    pub emergency_throttle_root: String,
    pub nullifier_index_root: String,
    pub maker_index_root: String,
    pub public_record_root: String,
    pub event_root: String,
}

impl FastPrivateExitRouterRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_private_exit_router_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "config_root": self.config_root,
            "exit_commitment_root": self.exit_commitment_root,
            "maker_reservation_root": self.maker_reservation_root,
            "monero_payout_root": self.monero_payout_root,
            "pq_maker_attestation_root": self.pq_maker_attestation_root,
            "reorg_risk_band_root": self.reorg_risk_band_root,
            "low_fee_sponsorship_root": self.low_fee_sponsorship_root,
            "delayed_reveal_receipt_root": self.delayed_reveal_receipt_root,
            "dispute_challenge_root": self.dispute_challenge_root,
            "emergency_throttle_root": self.emergency_throttle_root,
            "nullifier_index_root": self.nullifier_index_root,
            "maker_index_root": self.maker_index_root,
            "public_record_root": self.public_record_root,
            "event_root": self.event_root,
        })
    }

    pub fn roots_root(&self) -> String {
        router_payload_root("FAST-PRIVATE-EXIT-ROUTER-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastPrivateExitRouterCounters {
    pub exit_count: u64,
    pub live_exit_count: u64,
    pub settled_exit_count: u64,
    pub challenged_exit_count: u64,
    pub low_fee_exit_count: u64,
    pub reservation_count: u64,
    pub open_reservation_count: u64,
    pub payout_count: u64,
    pub live_payout_count: u64,
    pub pq_maker_attestation_count: u64,
    pub reorg_risk_band_count: u64,
    pub active_reorg_risk_band_count: u64,
    pub sponsorship_count: u64,
    pub active_sponsorship_count: u64,
    pub receipt_count: u64,
    pub live_receipt_count: u64,
    pub dispute_count: u64,
    pub live_dispute_count: u64,
    pub throttle_count: u64,
    pub active_throttle_count: u64,
    pub public_record_count: u64,
    pub event_count: u64,
    pub pending_exit_units: u64,
    pub reserved_maker_units: u64,
    pub filled_maker_units: u64,
    pub sponsor_reserved_units: u64,
    pub sponsor_applied_units: u64,
}

impl FastPrivateExitRouterCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_private_exit_router_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "exit_count": self.exit_count,
            "live_exit_count": self.live_exit_count,
            "settled_exit_count": self.settled_exit_count,
            "challenged_exit_count": self.challenged_exit_count,
            "low_fee_exit_count": self.low_fee_exit_count,
            "reservation_count": self.reservation_count,
            "open_reservation_count": self.open_reservation_count,
            "payout_count": self.payout_count,
            "live_payout_count": self.live_payout_count,
            "pq_maker_attestation_count": self.pq_maker_attestation_count,
            "reorg_risk_band_count": self.reorg_risk_band_count,
            "active_reorg_risk_band_count": self.active_reorg_risk_band_count,
            "sponsorship_count": self.sponsorship_count,
            "active_sponsorship_count": self.active_sponsorship_count,
            "receipt_count": self.receipt_count,
            "live_receipt_count": self.live_receipt_count,
            "dispute_count": self.dispute_count,
            "live_dispute_count": self.live_dispute_count,
            "throttle_count": self.throttle_count,
            "active_throttle_count": self.active_throttle_count,
            "public_record_count": self.public_record_count,
            "event_count": self.event_count,
            "pending_exit_units": self.pending_exit_units,
            "reserved_maker_units": self.reserved_maker_units,
            "filled_maker_units": self.filled_maker_units,
            "sponsor_reserved_units": self.sponsor_reserved_units,
            "sponsor_applied_units": self.sponsor_applied_units,
        })
    }

    pub fn counters_root(&self) -> String {
        router_payload_root("FAST-PRIVATE-EXIT-ROUTER-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastPrivateExitRouterState {
    pub height: u64,
    pub monero_network: String,
    pub asset_id: String,
    pub router_operator_commitment: String,
    pub active_reorg_band_id: String,
    pub config: FastPrivateExitRouterConfig,
    pub exit_commitments: BTreeMap<String, ShieldedExitCommitment>,
    pub maker_reservations: BTreeMap<String, MakerLiquidityReservation>,
    pub monero_payouts: BTreeMap<String, MoneroPayoutStealthCommitment>,
    pub pq_maker_attestations: BTreeMap<String, PqMakerAttestation>,
    pub reorg_risk_bands: BTreeMap<String, ReorgRiskBand>,
    pub low_fee_sponsorships: BTreeMap<String, LowFeeSponsorship>,
    pub delayed_reveal_receipts: BTreeMap<String, DelayedRevealReceipt>,
    pub dispute_challenges: BTreeMap<String, DisputeChallengeWindow>,
    pub emergency_throttles: BTreeMap<String, EmergencyThrottle>,
    pub nullifier_index: BTreeMap<String, String>,
    pub maker_exit_index: BTreeMap<String, BTreeSet<String>>,
    pub public_records: BTreeMap<String, DeterministicPublicRecord>,
    pub events: BTreeMap<String, RouterEvent>,
}

impl FastPrivateExitRouterState {
    pub fn new(
        config: FastPrivateExitRouterConfig,
        router_operator_commitment: &str,
        height: u64,
    ) -> FastPrivateExitRouterResult<Self> {
        config.validate()?;
        ensure_non_empty(
            "state.router_operator_commitment",
            router_operator_commitment,
        )?;
        Ok(Self {
            height,
            monero_network: config.monero_network.clone(),
            asset_id: config.asset_id.clone(),
            router_operator_commitment: router_operator_commitment.to_string(),
            active_reorg_band_id: String::new(),
            config,
            exit_commitments: BTreeMap::new(),
            maker_reservations: BTreeMap::new(),
            monero_payouts: BTreeMap::new(),
            pq_maker_attestations: BTreeMap::new(),
            reorg_risk_bands: BTreeMap::new(),
            low_fee_sponsorships: BTreeMap::new(),
            delayed_reveal_receipts: BTreeMap::new(),
            dispute_challenges: BTreeMap::new(),
            emergency_throttles: BTreeMap::new(),
            nullifier_index: BTreeMap::new(),
            maker_exit_index: BTreeMap::new(),
            public_records: BTreeMap::new(),
            events: BTreeMap::new(),
        })
    }

    pub fn devnet() -> FastPrivateExitRouterResult<Self> {
        let config = FastPrivateExitRouterConfig::devnet();
        let mut state = Self::new(
            config.clone(),
            "devnet-fast-private-exit-router-operator",
            FAST_PRIVATE_EXIT_ROUTER_DEVNET_HEIGHT,
        )?;

        let green = ReorgRiskBand {
            band_id: "devnet-green".to_string(),
            label: "devnet-green".to_string(),
            min_confirmations: 2,
            max_depth: 1,
            surcharge_bps: 0,
            required_reveal_delay_blocks: config.reveal_delay_blocks,
            maker_haircut_bps: 0,
            level: ReorgRiskLevel::Green,
            active_from_height: state.height,
            active_until_height: None,
        };
        state.active_reorg_band_id = green.band_id.clone();
        state
            .reorg_risk_bands
            .insert(green.band_id.clone(), green.clone());

        let yellow = ReorgRiskBand {
            band_id: "devnet-yellow".to_string(),
            label: "devnet-yellow".to_string(),
            min_confirmations: 5,
            max_depth: 3,
            surcharge_bps: config.reorg_surcharge_bps,
            required_reveal_delay_blocks: config
                .reveal_delay_blocks
                .saturating_add(config.reorg_grace_blocks),
            maker_haircut_bps: 250,
            level: ReorgRiskLevel::Yellow,
            active_from_height: state.height,
            active_until_height: None,
        };
        state
            .reorg_risk_bands
            .insert(yellow.band_id.clone(), yellow.clone());

        let exit = ShieldedExitCommitment::new(
            "devnet-owner-commitment-0",
            "devnet-account-commitment-0",
            &empty_root("devnet-source-note"),
            &empty_root("devnet-nullifier"),
            &empty_root("devnet-amount"),
            25_000,
            &config.asset_id,
            &config.fee_asset_id,
            20,
            24_950,
            ExitSpeed::Fast,
            ExitPrivacyMode::FullyShielded,
            "devnet-pq-session-0",
            state.height,
            &config,
        )?;
        let exit_id = exit.exit_id.clone();
        state
            .nullifier_index
            .insert(exit.nullifier_root.clone(), exit_id.clone());
        state.exit_commitments.insert(exit_id.clone(), exit);

        let mut reservation = MakerLiquidityReservation::new(
            "devnet-maker-0",
            "Devnet Maker Zero",
            &exit_id,
            &config.asset_id,
            25_000,
            12,
            config.fast_fee_bps,
            config.warn_reserve_coverage_bps,
            "devnet-maker-0-pq-key-commitment",
            state.height,
            &config,
        )?;
        reservation.status = ReservationStatus::Bound;
        let reservation_id = reservation.reservation_id.clone();
        state
            .maker_exit_index
            .entry(reservation.maker_id.clone())
            .or_default()
            .insert(exit_id.clone());
        state
            .maker_reservations
            .insert(reservation_id.clone(), reservation.clone());

        let payout = MoneroPayoutStealthCommitment::new(
            &exit_id,
            &reservation_id,
            "devnet-maker-0",
            &config.monero_network,
            &empty_root("devnet-stealth-address"),
            &empty_root("devnet-view-tags"),
            &empty_root("devnet-payout-amount"),
            25_000,
            state.height.saturating_add(1),
            &config,
        )?;
        let payout_id = payout.payout_id.clone();
        state.monero_payouts.insert(payout_id.clone(), payout);

        let receipt = DelayedRevealReceipt::new(
            &exit_id,
            &payout_id,
            &reservation_id,
            &empty_root("devnet-receipt"),
            &empty_root("devnet-receipt-payload"),
            &empty_root("devnet-reveal-nullifier"),
            state.height,
            &config,
        )?;
        let receipt_id = receipt.receipt_id.clone();
        state
            .delayed_reveal_receipts
            .insert(receipt_id.clone(), receipt);

        if let Some(exit) = state.exit_commitments.get_mut(&exit_id) {
            exit.reservation_id = Some(reservation_id.clone());
            exit.payout_id = Some(payout_id.clone());
            exit.receipt_id = Some(receipt_id.clone());
            exit.status = ExitCommitmentStatus::PayoutCommitted;
        }

        let attestation = PqMakerAttestation::new(
            "reservation",
            &reservation_id,
            &reservation.reservation_root(),
            "devnet-maker-0",
            MakerAttestationRole::Maker,
            "devnet-maker-0-pq-key-commitment",
            &empty_root("devnet-maker-signature"),
            &empty_root("devnet-maker-transcript"),
            config.warn_reserve_coverage_bps,
            1,
            state.height,
            config.exit_ttl_blocks,
        )?;
        state
            .pq_maker_attestations
            .insert(attestation.attestation_id.clone(), attestation);

        let sponsorship = LowFeeSponsorship::new(
            "devnet-low-fee-sponsor",
            &config.fee_asset_id,
            250,
            config.low_fee_rebate_bps,
            state.height,
            &config,
        )?;
        state
            .low_fee_sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship);

        state.record_event(
            "devnet_initialized",
            "fast_private_exit_router",
            &state.roots().roots_root(),
            json!({
                "height": state.height,
                "active_reorg_band_id": state.active_reorg_band_id,
            }),
        )?;
        state.publish_record(
            "state_bootstrap",
            "fast_private_exit_router",
            &state.roots().roots_root(),
        )?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> FastPrivateExitRouterResult<()> {
        if height < self.height {
            return Err("state height cannot move backwards".to_string());
        }
        self.height = height;

        for exit in self.exit_commitments.values_mut() {
            if height > exit.expires_at_height && exit.status.live() {
                exit.status = ExitCommitmentStatus::Expired;
            }
        }
        for reservation in self.maker_reservations.values_mut() {
            if height > reservation.expires_at_height && reservation.status.open() {
                reservation.status = ReservationStatus::Expired;
            }
        }
        for payout in self.monero_payouts.values_mut() {
            if payout.status == PayoutStatus::Confirmed && height >= payout.final_at_height {
                payout.status = PayoutStatus::Final;
            }
        }
        for receipt in self.delayed_reveal_receipts.values_mut() {
            if receipt.status == RevealReceiptStatus::Hidden && height >= receipt.reveal_at_height {
                receipt.status = RevealReceiptStatus::RevealOpen;
            }
            if height > receipt.expires_at_height && receipt.status.live() {
                receipt.status = RevealReceiptStatus::Expired;
            }
        }
        for dispute in self.dispute_challenges.values_mut() {
            if height > dispute.resolve_by_height && dispute.status.live() {
                dispute.status = DisputeStatus::Expired;
            }
        }
        for sponsorship in self.low_fee_sponsorships.values_mut() {
            if height > sponsorship.expires_at_height && sponsorship.status.active() {
                sponsorship.status = SponsorshipStatus::Expired;
            }
        }
        for throttle in self.emergency_throttles.values_mut() {
            if height > throttle.expires_at_height
                && throttle.status != EmergencyThrottleStatus::Released
            {
                throttle.status = EmergencyThrottleStatus::Expired;
            }
        }
        self.validate().map(|_| ())
    }

    pub fn roots(&self) -> FastPrivateExitRouterRoots {
        FastPrivateExitRouterRoots {
            config_root: self.config.config_root(),
            exit_commitment_root: collection_root(
                "FAST-PRIVATE-EXIT-ROUTER-EXIT-COLLECTION",
                self.exit_commitments
                    .values()
                    .map(ShieldedExitCommitment::public_record)
                    .collect(),
            ),
            maker_reservation_root: collection_root(
                "FAST-PRIVATE-EXIT-ROUTER-RESERVATION-COLLECTION",
                self.maker_reservations
                    .values()
                    .map(MakerLiquidityReservation::public_record)
                    .collect(),
            ),
            monero_payout_root: collection_root(
                "FAST-PRIVATE-EXIT-ROUTER-PAYOUT-COLLECTION",
                self.monero_payouts
                    .values()
                    .map(MoneroPayoutStealthCommitment::public_record)
                    .collect(),
            ),
            pq_maker_attestation_root: collection_root(
                "FAST-PRIVATE-EXIT-ROUTER-ATTESTATION-COLLECTION",
                self.pq_maker_attestations
                    .values()
                    .map(PqMakerAttestation::public_record)
                    .collect(),
            ),
            reorg_risk_band_root: collection_root(
                "FAST-PRIVATE-EXIT-ROUTER-REORG-BAND-COLLECTION",
                self.reorg_risk_bands
                    .values()
                    .map(ReorgRiskBand::public_record)
                    .collect(),
            ),
            low_fee_sponsorship_root: collection_root(
                "FAST-PRIVATE-EXIT-ROUTER-SPONSORSHIP-COLLECTION",
                self.low_fee_sponsorships
                    .values()
                    .map(LowFeeSponsorship::public_record)
                    .collect(),
            ),
            delayed_reveal_receipt_root: collection_root(
                "FAST-PRIVATE-EXIT-ROUTER-RECEIPT-COLLECTION",
                self.delayed_reveal_receipts
                    .values()
                    .map(DelayedRevealReceipt::public_record)
                    .collect(),
            ),
            dispute_challenge_root: collection_root(
                "FAST-PRIVATE-EXIT-ROUTER-DISPUTE-COLLECTION",
                self.dispute_challenges
                    .values()
                    .map(DisputeChallengeWindow::public_record)
                    .collect(),
            ),
            emergency_throttle_root: collection_root(
                "FAST-PRIVATE-EXIT-ROUTER-THROTTLE-COLLECTION",
                self.emergency_throttles
                    .values()
                    .map(EmergencyThrottle::public_record)
                    .collect(),
            ),
            nullifier_index_root: map_root(
                "FAST-PRIVATE-EXIT-ROUTER-NULLIFIER-INDEX",
                &self.nullifier_index,
            ),
            maker_index_root: set_map_root(
                "FAST-PRIVATE-EXIT-ROUTER-MAKER-INDEX",
                &self.maker_exit_index,
            ),
            public_record_root: collection_root(
                "FAST-PRIVATE-EXIT-ROUTER-PUBLIC-RECORD-COLLECTION",
                self.public_records
                    .values()
                    .map(DeterministicPublicRecord::public_record)
                    .collect(),
            ),
            event_root: collection_root(
                "FAST-PRIVATE-EXIT-ROUTER-EVENT-COLLECTION",
                self.events
                    .values()
                    .map(RouterEvent::public_record)
                    .collect(),
            ),
        }
    }

    pub fn counters(&self) -> FastPrivateExitRouterCounters {
        FastPrivateExitRouterCounters {
            exit_count: self.exit_commitments.len() as u64,
            live_exit_count: self
                .exit_commitments
                .values()
                .filter(|exit| exit.status.live())
                .count() as u64,
            settled_exit_count: self
                .exit_commitments
                .values()
                .filter(|exit| exit.status == ExitCommitmentStatus::Settled)
                .count() as u64,
            challenged_exit_count: self
                .exit_commitments
                .values()
                .filter(|exit| exit.status == ExitCommitmentStatus::Challenged)
                .count() as u64,
            low_fee_exit_count: self
                .exit_commitments
                .values()
                .filter(|exit| exit.speed == ExitSpeed::LowFee)
                .count() as u64,
            reservation_count: self.maker_reservations.len() as u64,
            open_reservation_count: self
                .maker_reservations
                .values()
                .filter(|reservation| reservation.status.open())
                .count() as u64,
            payout_count: self.monero_payouts.len() as u64,
            live_payout_count: self
                .monero_payouts
                .values()
                .filter(|payout| payout.status.live())
                .count() as u64,
            pq_maker_attestation_count: self.pq_maker_attestations.len() as u64,
            reorg_risk_band_count: self.reorg_risk_bands.len() as u64,
            active_reorg_risk_band_count: self
                .reorg_risk_bands
                .values()
                .filter(|band| band.active_until_height.is_none())
                .count() as u64,
            sponsorship_count: self.low_fee_sponsorships.len() as u64,
            active_sponsorship_count: self
                .low_fee_sponsorships
                .values()
                .filter(|sponsorship| sponsorship.status.active())
                .count() as u64,
            receipt_count: self.delayed_reveal_receipts.len() as u64,
            live_receipt_count: self
                .delayed_reveal_receipts
                .values()
                .filter(|receipt| receipt.status.live())
                .count() as u64,
            dispute_count: self.dispute_challenges.len() as u64,
            live_dispute_count: self
                .dispute_challenges
                .values()
                .filter(|dispute| dispute.status.live())
                .count() as u64,
            throttle_count: self.emergency_throttles.len() as u64,
            active_throttle_count: self
                .emergency_throttles
                .values()
                .filter(|throttle| throttle.status.blocks_new_exits())
                .count() as u64,
            public_record_count: self.public_records.len() as u64,
            event_count: self.events.len() as u64,
            pending_exit_units: self
                .exit_commitments
                .values()
                .filter(|exit| exit.status.live())
                .map(|exit| exit.amount_bucket)
                .sum(),
            reserved_maker_units: self
                .maker_reservations
                .values()
                .filter(|reservation| reservation.status.open())
                .map(|reservation| reservation.reserved_units)
                .sum(),
            filled_maker_units: self
                .maker_reservations
                .values()
                .map(|reservation| reservation.filled_units)
                .sum(),
            sponsor_reserved_units: self
                .low_fee_sponsorships
                .values()
                .map(|sponsorship| sponsorship.reserved_rebate_units)
                .sum(),
            sponsor_applied_units: self
                .low_fee_sponsorships
                .values()
                .map(|sponsorship| sponsorship.applied_rebate_units)
                .sum(),
        }
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        fast_private_exit_router_state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn validate(&self) -> FastPrivateExitRouterResult<String> {
        self.config.validate()?;
        if self.monero_network != self.config.monero_network {
            return Err("state monero network mismatch".to_string());
        }
        if self.asset_id != self.config.asset_id {
            return Err("state asset mismatch".to_string());
        }
        ensure_non_empty(
            "state.router_operator_commitment",
            &self.router_operator_commitment,
        )?;
        ensure_count_at_most(
            "exit_commitments",
            self.exit_commitments.len(),
            self.config.max_exits,
        )?;
        ensure_count_at_most(
            "maker_reservations",
            self.maker_reservations.len(),
            self.config.max_reservations,
        )?;
        ensure_count_at_most(
            "monero_payouts",
            self.monero_payouts.len(),
            self.config.max_payouts,
        )?;
        ensure_count_at_most(
            "pq_maker_attestations",
            self.pq_maker_attestations.len(),
            self.config.max_attestations,
        )?;
        ensure_count_at_most(
            "reorg_risk_bands",
            self.reorg_risk_bands.len(),
            self.config.max_reorg_bands,
        )?;
        ensure_count_at_most(
            "low_fee_sponsorships",
            self.low_fee_sponsorships.len(),
            self.config.max_sponsorships,
        )?;
        ensure_count_at_most(
            "delayed_reveal_receipts",
            self.delayed_reveal_receipts.len(),
            self.config.max_receipts,
        )?;
        ensure_count_at_most(
            "dispute_challenges",
            self.dispute_challenges.len(),
            self.config.max_disputes,
        )?;
        ensure_count_at_most(
            "emergency_throttles",
            self.emergency_throttles.len(),
            self.config.max_throttles,
        )?;
        ensure_count_at_most(
            "public_records",
            self.public_records.len(),
            self.config.max_public_records,
        )?;
        ensure_count_at_most("events", self.events.len(), self.config.max_events)?;

        if !self.active_reorg_band_id.is_empty()
            && !self
                .reorg_risk_bands
                .contains_key(&self.active_reorg_band_id)
        {
            return Err("active reorg band missing".to_string());
        }

        let pending_exit_count = self
            .exit_commitments
            .values()
            .filter(|exit| exit.status.live())
            .count();
        if pending_exit_count > self.config.max_pending_exits {
            return Err("pending exit count exceeds configured limit".to_string());
        }
        if self.counters().pending_exit_units > self.config.max_router_exposure_units {
            return Err("pending exit units exceed router exposure cap".to_string());
        }

        for (exit_id, exit) in &self.exit_commitments {
            if exit_id != &exit.exit_id {
                return Err("exit map key mismatch".to_string());
            }
            exit.validate(&self.config)?;
            if let Some(reservation_id) = &exit.reservation_id {
                let reservation = self
                    .maker_reservations
                    .get(reservation_id)
                    .ok_or_else(|| "exit references missing reservation".to_string())?;
                if !reservation.exit_ids.contains(exit_id) {
                    return Err("exit reservation reverse link mismatch".to_string());
                }
            }
            if let Some(payout_id) = &exit.payout_id {
                let payout = self
                    .monero_payouts
                    .get(payout_id)
                    .ok_or_else(|| "exit references missing payout".to_string())?;
                if payout.exit_id != *exit_id {
                    return Err("exit payout reverse link mismatch".to_string());
                }
            }
            if let Some(receipt_id) = &exit.receipt_id {
                let receipt = self
                    .delayed_reveal_receipts
                    .get(receipt_id)
                    .ok_or_else(|| "exit references missing receipt".to_string())?;
                if receipt.exit_id != *exit_id {
                    return Err("exit receipt reverse link mismatch".to_string());
                }
            }
            if let Some(dispute_id) = &exit.dispute_id {
                let dispute = self
                    .dispute_challenges
                    .get(dispute_id)
                    .ok_or_else(|| "exit references missing dispute".to_string())?;
                if dispute.exit_id != *exit_id {
                    return Err("exit dispute reverse link mismatch".to_string());
                }
            }
            if !self.reorg_risk_bands.contains_key(&exit.reorg_band_id) {
                return Err("exit references missing reorg band".to_string());
            }
        }

        for (nullifier_root, exit_id) in &self.nullifier_index {
            let exit = self
                .exit_commitments
                .get(exit_id)
                .ok_or_else(|| "nullifier index references missing exit".to_string())?;
            if &exit.nullifier_root != nullifier_root {
                return Err("nullifier index reverse link mismatch".to_string());
            }
        }

        for (reservation_id, reservation) in &self.maker_reservations {
            if reservation_id != &reservation.reservation_id {
                return Err("reservation map key mismatch".to_string());
            }
            reservation.validate(&self.config)?;
            for exit_id in &reservation.exit_ids {
                if !self.exit_commitments.contains_key(exit_id) {
                    return Err("reservation references missing exit".to_string());
                }
            }
        }

        for (maker_id, exit_ids) in &self.maker_exit_index {
            let open_count = self
                .maker_reservations
                .values()
                .filter(|reservation| {
                    reservation.maker_id == *maker_id && reservation.status.open()
                })
                .count();
            if open_count > self.config.max_open_reservations_per_maker {
                return Err("maker open reservation count exceeds configured limit".to_string());
            }
            let maker_reserved_units: u64 = self
                .maker_reservations
                .values()
                .filter(|reservation| {
                    reservation.maker_id == *maker_id && reservation.status.open()
                })
                .map(|reservation| reservation.reserved_units)
                .sum();
            if maker_reserved_units > self.config.max_maker_exposure_units {
                return Err("maker reserved units exceed exposure cap".to_string());
            }
            for exit_id in exit_ids {
                if !self.exit_commitments.contains_key(exit_id) {
                    return Err("maker index references missing exit".to_string());
                }
            }
        }

        for (payout_id, payout) in &self.monero_payouts {
            if payout_id != &payout.payout_id {
                return Err("payout map key mismatch".to_string());
            }
            payout.validate()?;
            if !self.exit_commitments.contains_key(&payout.exit_id) {
                return Err("payout references missing exit".to_string());
            }
            if !self.maker_reservations.contains_key(&payout.reservation_id) {
                return Err("payout references missing reservation".to_string());
            }
            if !self.reorg_risk_bands.contains_key(&payout.reorg_band_id) {
                return Err("payout references missing reorg band".to_string());
            }
        }

        for (attestation_id, attestation) in &self.pq_maker_attestations {
            if attestation_id != &attestation.attestation_id {
                return Err("attestation map key mismatch".to_string());
            }
            attestation.validate()?;
        }
        for (band_id, band) in &self.reorg_risk_bands {
            if band_id != &band.band_id {
                return Err("reorg band map key mismatch".to_string());
            }
            band.validate()?;
        }
        for (sponsorship_id, sponsorship) in &self.low_fee_sponsorships {
            if sponsorship_id != &sponsorship.sponsorship_id {
                return Err("sponsorship map key mismatch".to_string());
            }
            sponsorship.validate(&self.config)?;
            if let Some(exit_id) = &sponsorship.exit_id {
                if !self.exit_commitments.contains_key(exit_id) {
                    return Err("sponsorship references missing exit".to_string());
                }
            }
        }
        for (receipt_id, receipt) in &self.delayed_reveal_receipts {
            if receipt_id != &receipt.receipt_id {
                return Err("receipt map key mismatch".to_string());
            }
            receipt.validate()?;
            if !self.exit_commitments.contains_key(&receipt.exit_id) {
                return Err("receipt references missing exit".to_string());
            }
            if !self.monero_payouts.contains_key(&receipt.payout_id) {
                return Err("receipt references missing payout".to_string());
            }
            if !self
                .maker_reservations
                .contains_key(&receipt.reservation_id)
            {
                return Err("receipt references missing reservation".to_string());
            }
        }
        for (dispute_id, dispute) in &self.dispute_challenges {
            if dispute_id != &dispute.dispute_id {
                return Err("dispute map key mismatch".to_string());
            }
            dispute.validate()?;
            if !self.exit_commitments.contains_key(&dispute.exit_id) {
                return Err("dispute references missing exit".to_string());
            }
        }
        for (throttle_id, throttle) in &self.emergency_throttles {
            if throttle_id != &throttle.throttle_id {
                return Err("throttle map key mismatch".to_string());
            }
            throttle.validate()?;
        }
        for (record_id, record) in &self.public_records {
            if record_id != &record.record_id {
                return Err("public record map key mismatch".to_string());
            }
            record.validate()?;
        }
        for (event_id, event) in &self.events {
            if event_id != &event.event_id {
                return Err("event map key mismatch".to_string());
            }
            event.validate()?;
        }
        Ok(self.state_root())
    }

    fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "fast_private_exit_router_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": FAST_PRIVATE_EXIT_ROUTER_SCHEMA_VERSION,
            "height": self.height,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "router_operator_commitment": self.router_operator_commitment,
            "active_reorg_band_id": self.active_reorg_band_id,
            "config": self.config.public_record(),
            "config_root": self.config.config_root(),
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
        })
    }

    fn record_event(
        &mut self,
        event_kind: &str,
        subject_id: &str,
        subject_root: &str,
        details: Value,
    ) -> FastPrivateExitRouterResult<String> {
        let sequence = self.events.len() as u64;
        let event = RouterEvent::new(
            event_kind,
            subject_id,
            subject_root,
            self.height,
            sequence,
            &details,
        )?;
        let event_id = event.event_id.clone();
        self.events.insert(event_id.clone(), event);
        Ok(event_id)
    }

    fn publish_record(
        &mut self,
        record_kind: &str,
        subject_id: &str,
        subject_root: &str,
    ) -> FastPrivateExitRouterResult<String> {
        let payload = json!({
            "subject_id": subject_id,
            "subject_root": subject_root,
            "height": self.height,
            "roots": self.roots().public_record(),
        });
        let sequence = self.public_records.len() as u64;
        let record = DeterministicPublicRecord::new(
            record_kind,
            subject_id,
            subject_root,
            &payload,
            self.height,
            &self.router_operator_commitment,
            sequence,
        )?;
        let record_id = record.record_id.clone();
        self.public_records.insert(record_id.clone(), record);
        Ok(record_id)
    }
}

pub fn fast_private_exit_router_state_root_from_record(record: &Value) -> String {
    router_payload_root("FAST-PRIVATE-EXIT-ROUTER-STATE", record)
}

fn router_payload_root(domain: &str, value: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(value)], 32)
}

fn empty_root(label: &str) -> String {
    domain_hash(
        "FAST-PRIVATE-EXIT-ROUTER-EMPTY",
        &[HashPart::Str(label)],
        32,
    )
}

fn collection_root(domain: &str, values: Vec<Value>) -> String {
    if values.is_empty() {
        return domain_hash(&format!("{domain}:empty"), &[], 32);
    }
    let leaf_roots = values
        .iter()
        .map(|value| router_payload_root(&format!("{domain}:leaf"), value))
        .collect::<Vec<_>>();
    domain_hash(
        domain,
        &[HashPart::Json(&json!({
            "leaf_roots": leaf_roots,
            "leaf_count": values.len() as u64,
        }))],
        32,
    )
}

fn map_root(domain: &str, values: &BTreeMap<String, String>) -> String {
    let records = values
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    collection_root(domain, records)
}

fn set_map_root(domain: &str, values: &BTreeMap<String, BTreeSet<String>>) -> String {
    let records = values
        .iter()
        .map(|(key, set)| json!({ "key": key, "values": set_strings(set) }))
        .collect::<Vec<_>>();
    collection_root(domain, records)
}

fn set_strings(values: &BTreeSet<String>) -> Vec<String> {
    values.iter().cloned().collect()
}

fn ensure_non_empty(label: &str, value: &str) -> FastPrivateExitRouterResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}

fn ensure_positive(label: &str, value: u64) -> FastPrivateExitRouterResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_capacity(label: &str, value: usize) -> FastPrivateExitRouterResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_count_at_most(
    label: &str,
    count: usize,
    limit: usize,
) -> FastPrivateExitRouterResult<()> {
    if count > limit {
        return Err(format!("{label} count exceeds configured limit"));
    }
    Ok(())
}

fn ensure_bps(label: &str, value: u64) -> FastPrivateExitRouterResult<()> {
    if value > FAST_PRIVATE_EXIT_ROUTER_MAX_BPS {
        return Err(format!("{label} exceeds basis point maximum"));
    }
    Ok(())
}

fn ensure_height_order(label: &str, start: u64, end: u64) -> FastPrivateExitRouterResult<()> {
    if end < start {
        return Err(format!("{label} end height precedes start height"));
    }
    Ok(())
}
