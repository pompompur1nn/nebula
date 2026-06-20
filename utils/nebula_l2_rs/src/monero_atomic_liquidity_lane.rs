use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, HashPart},
    CHAIN_ID,
};

pub type MoneroAtomicLiquidityLaneResult<T> = Result<T, String>;

pub const MONERO_ATOMIC_LIQUIDITY_LANE_PROTOCOL_VERSION: u32 = 1;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_PROTOCOL_LABEL: &str =
    "nebula-monero-atomic-liquidity-lane-v1";
pub const MONERO_ATOMIC_LIQUIDITY_LANE_SCHEMA_VERSION: u64 = 1;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_DEVNET_HEIGHT: u64 = 224;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const MONERO_ATOMIC_LIQUIDITY_LANE_DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const MONERO_ATOMIC_LIQUIDITY_LANE_DEVNET_XMR_ASSET_ID: &str = "xmr-devnet";
pub const MONERO_ATOMIC_LIQUIDITY_LANE_DEVNET_WRAPPED_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_ATOMIC_LIQUIDITY_LANE_DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_ATOMIC_LIQUIDITY_LANE_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const MONERO_ATOMIC_LIQUIDITY_LANE_PQ_SUITE: &str =
    "ML-KEM-768+ML-DSA-65+SLH-DSA-SHAKE-128s-atomic-lane-devnet";
pub const MONERO_ATOMIC_LIQUIDITY_LANE_STEALTH_SCHEME: &str = "monero-stealth-payout-envelope-v1";
pub const MONERO_ATOMIC_LIQUIDITY_LANE_QUOTE_SCHEME: &str =
    "private-atomic-lane-quote-commitment-v1";
pub const MONERO_ATOMIC_LIQUIDITY_LANE_BOND_SCHEME: &str = "pq-maker-bond-slashable-liquidity-v1";
pub const MONERO_ATOMIC_LIQUIDITY_LANE_RECLAIM_SCHEME: &str = "atomic-lane-timeout-reclaim-v1";
pub const MONERO_ATOMIC_LIQUIDITY_LANE_SLASHING_SCHEME: &str =
    "atomic-lane-private-slashing-receipt-v1";
pub const MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 16;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 12;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 48;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_RECLAIM_DELAY_BLOCKS: u64 = 18;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_FINALITY_BLOCKS: u64 = 10;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_REORG_GRACE_BLOCKS: u64 = 6;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 6;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_MAX_BATCH_ITEMS: usize = 64;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 256;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1024;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_MIN_MAKER_BOND_BPS: u64 = 15_000;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_WARN_MAKER_BOND_BPS: u64 = 20_000;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_BASE_FEE_BPS: u64 = 16;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_FAST_FEE_BPS: u64 = 40;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_URGENT_FEE_BPS: u64 = 85;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 8_250;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_FEE_FLOOR_UNITS: u64 = 1;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_LANE_LIMIT_UNITS: u64 = 5_000_000;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_MAKER_LIMIT_UNITS: u64 = 1_250_000;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_THROTTLE_WINDOW_BLOCKS: u64 = 48;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_THROTTLE_MAX_OFFERS: u64 = 512;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_THROTTLE_MAX_UNITS: u64 = 1_500_000;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_MAX_BPS: u64 = 10_000;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_MAX_OFFERS: usize = 262_144;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_MAX_RESERVATIONS: usize = 262_144;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_MAX_PAYOUTS: usize = 262_144;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_MAX_QUOTES: usize = 262_144;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_MAX_BONDS: usize = 131_072;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_MAX_BATCHES: usize = 131_072;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_MAX_RECLAIMS: usize = 131_072;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_MAX_SLASHING_RECEIPTS: usize = 131_072;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_MAX_THROTTLES: usize = 512;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_MAX_PUBLIC_RECORDS: usize = 524_288;
pub const MONERO_ATOMIC_LIQUIDITY_LANE_MAX_EVENTS: usize = 524_288;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtomicLaneDirection {
    MoneroToL2,
    L2ToMonero,
}

impl AtomicLaneDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroToL2 => "monero_to_l2",
            Self::L2ToMonero => "l2_to_monero",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtomicLaneSpeed {
    LowFee,
    Normal,
    Fast,
    Urgent,
    ReorgSafe,
}

impl AtomicLaneSpeed {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::Normal => "normal",
            Self::Fast => "fast",
            Self::Urgent => "urgent",
            Self::ReorgSafe => "reorg_safe",
        }
    }

    pub fn fee_bps(self, config: &MoneroAtomicLiquidityLaneConfig) -> u64 {
        match self {
            Self::LowFee => config.base_fee_bps / 2,
            Self::Normal | Self::ReorgSafe => config.base_fee_bps,
            Self::Fast => config.fast_fee_bps,
            Self::Urgent => config.urgent_fee_bps,
        }
    }

    pub fn ttl_blocks(self, config: &MoneroAtomicLiquidityLaneConfig) -> u64 {
        match self {
            Self::LowFee => config.settlement_ttl_blocks.saturating_mul(2).max(1),
            Self::Normal => config.settlement_ttl_blocks.max(1),
            Self::Fast => config.settlement_ttl_blocks.min(24).max(1),
            Self::Urgent => config.reservation_ttl_blocks.max(1),
            Self::ReorgSafe => config
                .settlement_ttl_blocks
                .saturating_add(config.finality_blocks)
                .saturating_add(config.reorg_grace_blocks)
                .max(1),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtomicLaneOfferStatus {
    Draft,
    Open,
    PartiallyReserved,
    Reserved,
    Batched,
    Settling,
    Settled,
    Reclaimable,
    Slashed,
    Paused,
    Expired,
    Cancelled,
}

impl AtomicLaneOfferStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::PartiallyReserved => "partially_reserved",
            Self::Reserved => "reserved",
            Self::Batched => "batched",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Reclaimable => "reclaimable",
            Self::Slashed => "slashed",
            Self::Paused => "paused",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Open
                | Self::PartiallyReserved
                | Self::Reserved
                | Self::Batched
                | Self::Settling
                | Self::Reclaimable
        )
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Slashed | Self::Expired | Self::Cancelled
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityReservationKind {
    InboundMonero,
    OutboundMonero,
    NettingPair,
    BatchBackstop,
    EmergencyExit,
}

impl LiquidityReservationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InboundMonero => "inbound_monero",
            Self::OutboundMonero => "outbound_monero",
            Self::NettingPair => "netting_pair",
            Self::BatchBackstop => "batch_backstop",
            Self::EmergencyExit => "emergency_exit",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityReservationStatus {
    Open,
    Bound,
    PartiallyFilled,
    Filled,
    Released,
    ReorgHeld,
    Reclaimable,
    Slashed,
    Expired,
    Cancelled,
}

impl LiquidityReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Bound => "bound",
            Self::PartiallyFilled => "partially_filled",
            Self::Filled => "filled",
            Self::Released => "released",
            Self::ReorgHeld => "reorg_held",
            Self::Reclaimable => "reclaimable",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Open
                | Self::Bound
                | Self::PartiallyFilled
                | Self::Filled
                | Self::ReorgHeld
                | Self::Reclaimable
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StealthPayoutStatus {
    Committed,
    Batched,
    Broadcast,
    Confirming,
    Finalized,
    ReorgHeld,
    Reclaimed,
    Slashed,
    Expired,
}

impl StealthPayoutStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Batched => "batched",
            Self::Broadcast => "broadcast",
            Self::Confirming => "confirming",
            Self::Finalized => "finalized",
            Self::ReorgHeld => "reorg_held",
            Self::Reclaimed => "reclaimed",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Committed | Self::Batched | Self::Broadcast | Self::Confirming | Self::ReorgHeld
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MakerBondStatus {
    Posted,
    Active,
    Locked,
    Releasing,
    Released,
    Slashed,
    Expired,
    Suspended,
}

impl MakerBondStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Active => "active",
            Self::Locked => "locked",
            Self::Releasing => "releasing",
            Self::Released => "released",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
            Self::Suspended => "suspended",
        }
    }

    pub fn backs_liquidity(self) -> bool {
        matches!(self, Self::Posted | Self::Active | Self::Locked)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LowFeeBatchStatus {
    Collecting,
    Sealed,
    MakerAttested,
    Broadcast,
    Confirming,
    Finalized,
    ReorgHeld,
    Failed,
    Expired,
    Cancelled,
}

impl LowFeeBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Sealed => "sealed",
            Self::MakerAttested => "maker_attested",
            Self::Broadcast => "broadcast",
            Self::Confirming => "confirming",
            Self::Finalized => "finalized",
            Self::ReorgHeld => "reorg_held",
            Self::Failed => "failed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Collecting
                | Self::Sealed
                | Self::MakerAttested
                | Self::Broadcast
                | Self::Confirming
                | Self::ReorgHeld
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReclaimPathStatus {
    Armed,
    WaitingFinality,
    Executable,
    Executed,
    Cancelled,
    Expired,
    SlashedInstead,
}

impl ReclaimPathStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::WaitingFinality => "waiting_finality",
            Self::Executable => "executable",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::SlashedInstead => "slashed_instead",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Armed | Self::WaitingFinality | Self::Executable)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    MissingPayout,
    InvalidQuote,
    DoubleReservation,
    ReorgMisreport,
    TimeoutViolation,
    EquivocatedAttestation,
    FeeOvercharge,
}

impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingPayout => "missing_payout",
            Self::InvalidQuote => "invalid_quote",
            Self::DoubleReservation => "double_reservation",
            Self::ReorgMisreport => "reorg_misreport",
            Self::TimeoutViolation => "timeout_violation",
            Self::EquivocatedAttestation => "equivocated_attestation",
            Self::FeeOvercharge => "fee_overcharge",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneThrottleStatus {
    Monitoring,
    Constrained,
    Halted,
    CoolingDown,
    Retired,
}

impl LaneThrottleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Monitoring => "monitoring",
            Self::Constrained => "constrained",
            Self::Halted => "halted",
            Self::CoolingDown => "cooling_down",
            Self::Retired => "retired",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Monitoring | Self::Constrained | Self::Halted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroAtomicLiquidityLaneConfig {
    pub config_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub xmr_asset_id: String,
    pub wrapped_asset_id: String,
    pub fee_asset_id: String,
    pub quote_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub reclaim_delay_blocks: u64,
    pub finality_blocks: u64,
    pub reorg_grace_blocks: u64,
    pub batch_window_blocks: u64,
    pub max_batch_items: usize,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_maker_bond_bps: u64,
    pub warn_maker_bond_bps: u64,
    pub base_fee_bps: u64,
    pub fast_fee_bps: u64,
    pub urgent_fee_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub fee_floor_units: u64,
    pub lane_limit_units: u64,
    pub maker_limit_units: u64,
    pub throttle_window_blocks: u64,
    pub throttle_max_offers: u64,
    pub throttle_max_units: u64,
    pub require_pq_attestations: bool,
    pub require_private_quote_commitments: bool,
    pub require_stealth_payout_roots_only: bool,
    pub hash_suite: String,
    pub pq_suite: String,
    pub stealth_scheme: String,
    pub quote_scheme: String,
    pub bond_scheme: String,
    pub reclaim_scheme: String,
    pub slashing_scheme: String,
}

impl Default for MoneroAtomicLiquidityLaneConfig {
    fn default() -> Self {
        let mut config = Self {
            config_id: String::new(),
            monero_network: MONERO_ATOMIC_LIQUIDITY_LANE_DEVNET_MONERO_NETWORK.to_string(),
            l2_network: MONERO_ATOMIC_LIQUIDITY_LANE_DEVNET_L2_NETWORK.to_string(),
            xmr_asset_id: MONERO_ATOMIC_LIQUIDITY_LANE_DEVNET_XMR_ASSET_ID.to_string(),
            wrapped_asset_id: MONERO_ATOMIC_LIQUIDITY_LANE_DEVNET_WRAPPED_ASSET_ID.to_string(),
            fee_asset_id: MONERO_ATOMIC_LIQUIDITY_LANE_DEVNET_FEE_ASSET_ID.to_string(),
            quote_ttl_blocks: MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_QUOTE_TTL_BLOCKS,
            reservation_ttl_blocks: MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_RESERVATION_TTL_BLOCKS,
            settlement_ttl_blocks: MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            reclaim_delay_blocks: MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_RECLAIM_DELAY_BLOCKS,
            finality_blocks: MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_FINALITY_BLOCKS,
            reorg_grace_blocks: MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_REORG_GRACE_BLOCKS,
            batch_window_blocks: MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_BATCH_WINDOW_BLOCKS,
            max_batch_items: MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_MAX_BATCH_ITEMS,
            min_privacy_set_size: MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_maker_bond_bps: MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_MIN_MAKER_BOND_BPS,
            warn_maker_bond_bps: MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_WARN_MAKER_BOND_BPS,
            base_fee_bps: MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_BASE_FEE_BPS,
            fast_fee_bps: MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_FAST_FEE_BPS,
            urgent_fee_bps: MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_URGENT_FEE_BPS,
            low_fee_rebate_bps: MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_LOW_FEE_REBATE_BPS,
            fee_floor_units: MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_FEE_FLOOR_UNITS,
            lane_limit_units: MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_LANE_LIMIT_UNITS,
            maker_limit_units: MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_MAKER_LIMIT_UNITS,
            throttle_window_blocks: MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_THROTTLE_WINDOW_BLOCKS,
            throttle_max_offers: MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_THROTTLE_MAX_OFFERS,
            throttle_max_units: MONERO_ATOMIC_LIQUIDITY_LANE_DEFAULT_THROTTLE_MAX_UNITS,
            require_pq_attestations: true,
            require_private_quote_commitments: true,
            require_stealth_payout_roots_only: true,
            hash_suite: MONERO_ATOMIC_LIQUIDITY_LANE_HASH_SUITE.to_string(),
            pq_suite: MONERO_ATOMIC_LIQUIDITY_LANE_PQ_SUITE.to_string(),
            stealth_scheme: MONERO_ATOMIC_LIQUIDITY_LANE_STEALTH_SCHEME.to_string(),
            quote_scheme: MONERO_ATOMIC_LIQUIDITY_LANE_QUOTE_SCHEME.to_string(),
            bond_scheme: MONERO_ATOMIC_LIQUIDITY_LANE_BOND_SCHEME.to_string(),
            reclaim_scheme: MONERO_ATOMIC_LIQUIDITY_LANE_RECLAIM_SCHEME.to_string(),
            slashing_scheme: MONERO_ATOMIC_LIQUIDITY_LANE_SLASHING_SCHEME.to_string(),
        };
        config.config_id = lane_payload_root(
            "MONERO-ATOMIC-LIQUIDITY-LANE-CONFIG",
            &config.identity_record(),
        );
        config
    }
}

impl MoneroAtomicLiquidityLaneConfig {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_atomic_liquidity_lane_config",
            "chain_id": CHAIN_ID,
            "protocol_label": MONERO_ATOMIC_LIQUIDITY_LANE_PROTOCOL_LABEL,
            "protocol_version": MONERO_ATOMIC_LIQUIDITY_LANE_PROTOCOL_VERSION,
            "schema_version": MONERO_ATOMIC_LIQUIDITY_LANE_SCHEMA_VERSION,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "xmr_asset_id": self.xmr_asset_id,
            "wrapped_asset_id": self.wrapped_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "reclaim_delay_blocks": self.reclaim_delay_blocks,
            "finality_blocks": self.finality_blocks,
            "reorg_grace_blocks": self.reorg_grace_blocks,
            "batch_window_blocks": self.batch_window_blocks,
            "max_batch_items": self.max_batch_items,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_maker_bond_bps": self.min_maker_bond_bps,
            "warn_maker_bond_bps": self.warn_maker_bond_bps,
            "base_fee_bps": self.base_fee_bps,
            "fast_fee_bps": self.fast_fee_bps,
            "urgent_fee_bps": self.urgent_fee_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "fee_floor_units": self.fee_floor_units,
            "lane_limit_units": self.lane_limit_units,
            "maker_limit_units": self.maker_limit_units,
            "throttle_window_blocks": self.throttle_window_blocks,
            "throttle_max_offers": self.throttle_max_offers,
            "throttle_max_units": self.throttle_max_units,
            "require_pq_attestations": self.require_pq_attestations,
            "require_private_quote_commitments": self.require_private_quote_commitments,
            "require_stealth_payout_roots_only": self.require_stealth_payout_roots_only,
            "hash_suite": self.hash_suite,
            "pq_suite": self.pq_suite,
            "stealth_scheme": self.stealth_scheme,
            "quote_scheme": self.quote_scheme,
            "bond_scheme": self.bond_scheme,
            "reclaim_scheme": self.reclaim_scheme,
            "slashing_scheme": self.slashing_scheme,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        if let Some(object) = record.as_object_mut() {
            object.insert("config_id".to_string(), json!(self.config_id));
        }
        record
    }

    pub fn validate(&self) -> MoneroAtomicLiquidityLaneResult<()> {
        ensure_non_empty("config.config_id", &self.config_id)?;
        ensure_non_empty("config.monero_network", &self.monero_network)?;
        ensure_non_empty("config.l2_network", &self.l2_network)?;
        ensure_non_empty("config.xmr_asset_id", &self.xmr_asset_id)?;
        ensure_non_empty("config.wrapped_asset_id", &self.wrapped_asset_id)?;
        ensure_non_empty("config.fee_asset_id", &self.fee_asset_id)?;
        ensure_positive("config.quote_ttl_blocks", self.quote_ttl_blocks)?;
        ensure_positive("config.reservation_ttl_blocks", self.reservation_ttl_blocks)?;
        ensure_positive("config.settlement_ttl_blocks", self.settlement_ttl_blocks)?;
        ensure_positive("config.reclaim_delay_blocks", self.reclaim_delay_blocks)?;
        ensure_positive("config.finality_blocks", self.finality_blocks)?;
        ensure_positive("config.batch_window_blocks", self.batch_window_blocks)?;
        ensure_usize_positive("config.max_batch_items", self.max_batch_items)?;
        ensure_positive("config.min_privacy_set_size", self.min_privacy_set_size)?;
        ensure_positive(
            "config.target_privacy_set_size",
            self.target_privacy_set_size,
        )?;
        if self.target_privacy_set_size < self.min_privacy_set_size {
            return Err("config.target_privacy_set_size below minimum".to_string());
        }
        ensure_bps("config.base_fee_bps", self.base_fee_bps)?;
        ensure_bps("config.fast_fee_bps", self.fast_fee_bps)?;
        ensure_bps("config.urgent_fee_bps", self.urgent_fee_bps)?;
        ensure_bps("config.low_fee_rebate_bps", self.low_fee_rebate_bps)?;
        if self.fast_fee_bps < self.base_fee_bps {
            return Err("config.fast_fee_bps below base fee".to_string());
        }
        if self.urgent_fee_bps < self.fast_fee_bps {
            return Err("config.urgent_fee_bps below fast fee".to_string());
        }
        if self.warn_maker_bond_bps < self.min_maker_bond_bps {
            return Err("config.warn_maker_bond_bps below minimum maker bond".to_string());
        }
        ensure_positive("config.lane_limit_units", self.lane_limit_units)?;
        ensure_positive("config.maker_limit_units", self.maker_limit_units)?;
        ensure_positive("config.throttle_window_blocks", self.throttle_window_blocks)?;
        ensure_positive("config.throttle_max_offers", self.throttle_max_offers)?;
        ensure_positive("config.throttle_max_units", self.throttle_max_units)?;
        ensure_non_empty("config.hash_suite", &self.hash_suite)?;
        ensure_non_empty("config.pq_suite", &self.pq_suite)?;
        ensure_non_empty("config.stealth_scheme", &self.stealth_scheme)?;
        ensure_non_empty("config.quote_scheme", &self.quote_scheme)?;
        ensure_non_empty("config.bond_scheme", &self.bond_scheme)?;
        ensure_non_empty("config.reclaim_scheme", &self.reclaim_scheme)?;
        ensure_non_empty("config.slashing_scheme", &self.slashing_scheme)?;

        let derived_config_id = lane_payload_root(
            "MONERO-ATOMIC-LIQUIDITY-LANE-CONFIG",
            &self.identity_record(),
        );
        if derived_config_id != self.config_id {
            return Err("config.config_id does not match identity record".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicLaneOffer {
    pub offer_id: String,
    pub maker_id: String,
    pub maker_commitment: String,
    pub direction: AtomicLaneDirection,
    pub speed: AtomicLaneSpeed,
    pub source_asset_id: String,
    pub target_asset_id: String,
    pub available_units: u64,
    pub reserved_units: u64,
    pub min_fill_units: u64,
    pub max_fill_units: u64,
    pub fee_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub quote_root: String,
    pub inventory_root: String,
    pub monero_view_policy_root: String,
    pub l2_escrow_policy_root: String,
    pub pq_key_commitment: String,
    pub bond_id: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: AtomicLaneOfferStatus,
}

impl AtomicLaneOffer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        maker_id: &str,
        maker_commitment: &str,
        direction: AtomicLaneDirection,
        speed: AtomicLaneSpeed,
        source_asset_id: &str,
        target_asset_id: &str,
        available_units: u64,
        min_fill_units: u64,
        max_fill_units: u64,
        quote_root: &str,
        inventory_root: &str,
        monero_view_policy_root: &str,
        l2_escrow_policy_root: &str,
        pq_key_commitment: &str,
        bond_id: &str,
        opened_at_height: u64,
        config: &MoneroAtomicLiquidityLaneConfig,
    ) -> MoneroAtomicLiquidityLaneResult<Self> {
        ensure_non_empty("offer.maker_id", maker_id)?;
        ensure_non_empty("offer.maker_commitment", maker_commitment)?;
        ensure_non_empty("offer.source_asset_id", source_asset_id)?;
        ensure_non_empty("offer.target_asset_id", target_asset_id)?;
        ensure_positive("offer.available_units", available_units)?;
        ensure_positive("offer.min_fill_units", min_fill_units)?;
        ensure_positive("offer.max_fill_units", max_fill_units)?;
        if min_fill_units > max_fill_units || max_fill_units > available_units {
            return Err("offer fill bounds invalid".to_string());
        }
        ensure_non_empty("offer.quote_root", quote_root)?;
        ensure_non_empty("offer.inventory_root", inventory_root)?;
        ensure_non_empty("offer.monero_view_policy_root", monero_view_policy_root)?;
        ensure_non_empty("offer.l2_escrow_policy_root", l2_escrow_policy_root)?;
        ensure_non_empty("offer.pq_key_commitment", pq_key_commitment)?;
        ensure_non_empty("offer.bond_id", bond_id)?;

        let fee_bps = speed.fee_bps(config);
        let expires_at_height = opened_at_height.saturating_add(speed.ttl_blocks(config));
        let offer_id = atomic_lane_offer_id(
            maker_id,
            maker_commitment,
            direction,
            speed,
            source_asset_id,
            target_asset_id,
            available_units,
            min_fill_units,
            max_fill_units,
            fee_bps,
            quote_root,
            inventory_root,
            pq_key_commitment,
            opened_at_height,
            expires_at_height,
        );

        Ok(Self {
            offer_id,
            maker_id: maker_id.to_string(),
            maker_commitment: maker_commitment.to_string(),
            direction,
            speed,
            source_asset_id: source_asset_id.to_string(),
            target_asset_id: target_asset_id.to_string(),
            available_units,
            reserved_units: 0,
            min_fill_units,
            max_fill_units,
            fee_bps,
            low_fee_rebate_bps: config.low_fee_rebate_bps,
            quote_root: quote_root.to_string(),
            inventory_root: inventory_root.to_string(),
            monero_view_policy_root: monero_view_policy_root.to_string(),
            l2_escrow_policy_root: l2_escrow_policy_root.to_string(),
            pq_key_commitment: pq_key_commitment.to_string(),
            bond_id: bond_id.to_string(),
            opened_at_height,
            expires_at_height,
            status: AtomicLaneOfferStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "atomic_lane_offer",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_ATOMIC_LIQUIDITY_LANE_PROTOCOL_VERSION,
            "offer_id": self.offer_id,
            "maker_id": self.maker_id,
            "maker_commitment": self.maker_commitment,
            "direction": self.direction.as_str(),
            "speed": self.speed.as_str(),
            "source_asset_id": self.source_asset_id,
            "target_asset_id": self.target_asset_id,
            "available_units": self.available_units,
            "reserved_units": self.reserved_units,
            "min_fill_units": self.min_fill_units,
            "max_fill_units": self.max_fill_units,
            "fee_bps": self.fee_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "quote_root": self.quote_root,
            "inventory_root": self.inventory_root,
            "monero_view_policy_root": self.monero_view_policy_root,
            "l2_escrow_policy_root": self.l2_escrow_policy_root,
            "pq_key_commitment": self.pq_key_commitment,
            "bond_id": self.bond_id,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> MoneroAtomicLiquidityLaneResult<String> {
        ensure_non_empty("offer.offer_id", &self.offer_id)?;
        ensure_non_empty("offer.maker_id", &self.maker_id)?;
        ensure_non_empty("offer.maker_commitment", &self.maker_commitment)?;
        ensure_non_empty("offer.source_asset_id", &self.source_asset_id)?;
        ensure_non_empty("offer.target_asset_id", &self.target_asset_id)?;
        ensure_positive("offer.available_units", self.available_units)?;
        if self.reserved_units > self.available_units {
            return Err(format!("offer {} over-reserved", self.offer_id));
        }
        ensure_positive("offer.min_fill_units", self.min_fill_units)?;
        ensure_positive("offer.max_fill_units", self.max_fill_units)?;
        if self.min_fill_units > self.max_fill_units || self.max_fill_units > self.available_units {
            return Err(format!("offer {} fill bounds invalid", self.offer_id));
        }
        ensure_bps("offer.fee_bps", self.fee_bps)?;
        ensure_bps("offer.low_fee_rebate_bps", self.low_fee_rebate_bps)?;
        ensure_non_empty("offer.quote_root", &self.quote_root)?;
        ensure_non_empty("offer.inventory_root", &self.inventory_root)?;
        ensure_non_empty(
            "offer.monero_view_policy_root",
            &self.monero_view_policy_root,
        )?;
        ensure_non_empty("offer.l2_escrow_policy_root", &self.l2_escrow_policy_root)?;
        ensure_non_empty("offer.pq_key_commitment", &self.pq_key_commitment)?;
        ensure_non_empty("offer.bond_id", &self.bond_id)?;
        if self.expires_at_height <= self.opened_at_height {
            return Err(format!(
                "offer {} expiry not after open height",
                self.offer_id
            ));
        }
        Ok(lane_payload_root(
            "MONERO-ATOMIC-LANE-OFFER",
            &self.public_record(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StealthPayoutEnvelope {
    pub payout_id: String,
    pub offer_id: String,
    pub reservation_id: String,
    pub recipient_commitment: String,
    pub stealth_address_root: String,
    pub one_time_key_root: String,
    pub view_tag_root: String,
    pub amount_bucket_root: String,
    pub encrypted_payload_root: String,
    pub monero_tx_commitment_root: String,
    pub amount_units: u64,
    pub fee_units: u64,
    pub batch_id: String,
    pub created_at_height: u64,
    pub finality_height: u64,
    pub status: StealthPayoutStatus,
}

impl StealthPayoutEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        offer_id: &str,
        reservation_id: &str,
        recipient_commitment: &str,
        stealth_address_root: &str,
        one_time_key_root: &str,
        view_tag_root: &str,
        amount_bucket_root: &str,
        encrypted_payload_root: &str,
        amount_units: u64,
        fee_units: u64,
        created_at_height: u64,
        config: &MoneroAtomicLiquidityLaneConfig,
    ) -> MoneroAtomicLiquidityLaneResult<Self> {
        ensure_non_empty("payout.offer_id", offer_id)?;
        ensure_non_empty("payout.reservation_id", reservation_id)?;
        ensure_non_empty("payout.recipient_commitment", recipient_commitment)?;
        ensure_non_empty("payout.stealth_address_root", stealth_address_root)?;
        ensure_non_empty("payout.one_time_key_root", one_time_key_root)?;
        ensure_non_empty("payout.view_tag_root", view_tag_root)?;
        ensure_non_empty("payout.amount_bucket_root", amount_bucket_root)?;
        ensure_non_empty("payout.encrypted_payload_root", encrypted_payload_root)?;
        ensure_positive("payout.amount_units", amount_units)?;
        let finality_height = created_at_height
            .saturating_add(config.finality_blocks)
            .saturating_add(config.reorg_grace_blocks);
        let monero_tx_commitment_root = empty_root("pending-monero-tx");
        let payout_id = stealth_payout_envelope_id(
            offer_id,
            reservation_id,
            recipient_commitment,
            stealth_address_root,
            one_time_key_root,
            view_tag_root,
            amount_bucket_root,
            encrypted_payload_root,
            amount_units,
            fee_units,
            created_at_height,
            finality_height,
        );
        Ok(Self {
            payout_id,
            offer_id: offer_id.to_string(),
            reservation_id: reservation_id.to_string(),
            recipient_commitment: recipient_commitment.to_string(),
            stealth_address_root: stealth_address_root.to_string(),
            one_time_key_root: one_time_key_root.to_string(),
            view_tag_root: view_tag_root.to_string(),
            amount_bucket_root: amount_bucket_root.to_string(),
            encrypted_payload_root: encrypted_payload_root.to_string(),
            monero_tx_commitment_root,
            amount_units,
            fee_units,
            batch_id: String::new(),
            created_at_height,
            finality_height,
            status: StealthPayoutStatus::Committed,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "stealth_payout_envelope",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_ATOMIC_LIQUIDITY_LANE_PROTOCOL_VERSION,
            "payout_id": self.payout_id,
            "offer_id": self.offer_id,
            "reservation_id": self.reservation_id,
            "recipient_commitment": self.recipient_commitment,
            "stealth_address_root": self.stealth_address_root,
            "one_time_key_root": self.one_time_key_root,
            "view_tag_root": self.view_tag_root,
            "amount_bucket_root": self.amount_bucket_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "monero_tx_commitment_root": self.monero_tx_commitment_root,
            "amount_units": self.amount_units,
            "fee_units": self.fee_units,
            "batch_id": self.batch_id,
            "created_at_height": self.created_at_height,
            "finality_height": self.finality_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> MoneroAtomicLiquidityLaneResult<String> {
        ensure_non_empty("payout.payout_id", &self.payout_id)?;
        ensure_non_empty("payout.offer_id", &self.offer_id)?;
        ensure_non_empty("payout.reservation_id", &self.reservation_id)?;
        ensure_non_empty("payout.recipient_commitment", &self.recipient_commitment)?;
        ensure_non_empty("payout.stealth_address_root", &self.stealth_address_root)?;
        ensure_non_empty("payout.one_time_key_root", &self.one_time_key_root)?;
        ensure_non_empty("payout.view_tag_root", &self.view_tag_root)?;
        ensure_non_empty("payout.amount_bucket_root", &self.amount_bucket_root)?;
        ensure_non_empty(
            "payout.encrypted_payload_root",
            &self.encrypted_payload_root,
        )?;
        ensure_non_empty(
            "payout.monero_tx_commitment_root",
            &self.monero_tx_commitment_root,
        )?;
        ensure_positive("payout.amount_units", self.amount_units)?;
        if self.finality_height <= self.created_at_height {
            return Err(format!(
                "payout {} finality not after creation",
                self.payout_id
            ));
        }
        Ok(lane_payload_root(
            "MONERO-ATOMIC-LANE-PAYOUT",
            &self.public_record(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityReservation {
    pub reservation_id: String,
    pub offer_id: String,
    pub maker_id: String,
    pub taker_commitment: String,
    pub kind: LiquidityReservationKind,
    pub direction: AtomicLaneDirection,
    pub asset_id: String,
    pub amount_units: u64,
    pub fee_units: u64,
    pub bond_id: String,
    pub quote_commitment_id: String,
    pub payout_id: String,
    pub nullifier_root: String,
    pub reclaim_path_id: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: LiquidityReservationStatus,
}

impl LiquidityReservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        offer_id: &str,
        maker_id: &str,
        taker_commitment: &str,
        kind: LiquidityReservationKind,
        direction: AtomicLaneDirection,
        asset_id: &str,
        amount_units: u64,
        fee_units: u64,
        bond_id: &str,
        quote_commitment_id: &str,
        nullifier_root: &str,
        opened_at_height: u64,
        config: &MoneroAtomicLiquidityLaneConfig,
    ) -> MoneroAtomicLiquidityLaneResult<Self> {
        ensure_non_empty("reservation.offer_id", offer_id)?;
        ensure_non_empty("reservation.maker_id", maker_id)?;
        ensure_non_empty("reservation.taker_commitment", taker_commitment)?;
        ensure_non_empty("reservation.asset_id", asset_id)?;
        ensure_positive("reservation.amount_units", amount_units)?;
        ensure_non_empty("reservation.bond_id", bond_id)?;
        ensure_non_empty("reservation.quote_commitment_id", quote_commitment_id)?;
        ensure_non_empty("reservation.nullifier_root", nullifier_root)?;
        let expires_at_height = opened_at_height.saturating_add(config.reservation_ttl_blocks);
        let reservation_id = liquidity_reservation_id(
            offer_id,
            maker_id,
            taker_commitment,
            kind,
            direction,
            asset_id,
            amount_units,
            fee_units,
            bond_id,
            quote_commitment_id,
            nullifier_root,
            opened_at_height,
            expires_at_height,
        );
        Ok(Self {
            reservation_id,
            offer_id: offer_id.to_string(),
            maker_id: maker_id.to_string(),
            taker_commitment: taker_commitment.to_string(),
            kind,
            direction,
            asset_id: asset_id.to_string(),
            amount_units,
            fee_units,
            bond_id: bond_id.to_string(),
            quote_commitment_id: quote_commitment_id.to_string(),
            payout_id: String::new(),
            nullifier_root: nullifier_root.to_string(),
            reclaim_path_id: String::new(),
            opened_at_height,
            expires_at_height,
            status: LiquidityReservationStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "liquidity_reservation",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_ATOMIC_LIQUIDITY_LANE_PROTOCOL_VERSION,
            "reservation_id": self.reservation_id,
            "offer_id": self.offer_id,
            "maker_id": self.maker_id,
            "taker_commitment": self.taker_commitment,
            "reservation_kind": self.kind.as_str(),
            "direction": self.direction.as_str(),
            "asset_id": self.asset_id,
            "amount_units": self.amount_units,
            "fee_units": self.fee_units,
            "bond_id": self.bond_id,
            "quote_commitment_id": self.quote_commitment_id,
            "payout_id": self.payout_id,
            "nullifier_root": self.nullifier_root,
            "reclaim_path_id": self.reclaim_path_id,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> MoneroAtomicLiquidityLaneResult<String> {
        ensure_non_empty("reservation.reservation_id", &self.reservation_id)?;
        ensure_non_empty("reservation.offer_id", &self.offer_id)?;
        ensure_non_empty("reservation.maker_id", &self.maker_id)?;
        ensure_non_empty("reservation.taker_commitment", &self.taker_commitment)?;
        ensure_non_empty("reservation.asset_id", &self.asset_id)?;
        ensure_positive("reservation.amount_units", self.amount_units)?;
        ensure_non_empty("reservation.bond_id", &self.bond_id)?;
        ensure_non_empty("reservation.quote_commitment_id", &self.quote_commitment_id)?;
        ensure_non_empty("reservation.nullifier_root", &self.nullifier_root)?;
        if self.expires_at_height <= self.opened_at_height {
            return Err(format!(
                "reservation {} expiry not after open height",
                self.reservation_id
            ));
        }
        Ok(lane_payload_root(
            "MONERO-ATOMIC-LANE-RESERVATION",
            &self.public_record(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateQuoteCommitment {
    pub quote_commitment_id: String,
    pub maker_id: String,
    pub quote_root: String,
    pub price_bucket_root: String,
    pub spread_commitment_root: String,
    pub route_commitment_root: String,
    pub encrypted_terms_root: String,
    pub amount_floor_units: u64,
    pub amount_ceiling_units: u64,
    pub fee_bps: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivateQuoteCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        maker_id: &str,
        quote_root: &str,
        price_bucket_root: &str,
        spread_commitment_root: &str,
        route_commitment_root: &str,
        encrypted_terms_root: &str,
        amount_floor_units: u64,
        amount_ceiling_units: u64,
        fee_bps: u64,
        created_at_height: u64,
        config: &MoneroAtomicLiquidityLaneConfig,
    ) -> MoneroAtomicLiquidityLaneResult<Self> {
        ensure_non_empty("quote.maker_id", maker_id)?;
        ensure_non_empty("quote.quote_root", quote_root)?;
        ensure_non_empty("quote.price_bucket_root", price_bucket_root)?;
        ensure_non_empty("quote.spread_commitment_root", spread_commitment_root)?;
        ensure_non_empty("quote.route_commitment_root", route_commitment_root)?;
        ensure_non_empty("quote.encrypted_terms_root", encrypted_terms_root)?;
        ensure_positive("quote.amount_floor_units", amount_floor_units)?;
        ensure_positive("quote.amount_ceiling_units", amount_ceiling_units)?;
        if amount_floor_units > amount_ceiling_units {
            return Err("quote floor above ceiling".to_string());
        }
        ensure_bps("quote.fee_bps", fee_bps)?;
        let expires_at_height = created_at_height.saturating_add(config.quote_ttl_blocks);
        let quote_commitment_id = private_quote_commitment_id(
            maker_id,
            quote_root,
            price_bucket_root,
            spread_commitment_root,
            route_commitment_root,
            encrypted_terms_root,
            amount_floor_units,
            amount_ceiling_units,
            fee_bps,
            created_at_height,
            expires_at_height,
        );
        Ok(Self {
            quote_commitment_id,
            maker_id: maker_id.to_string(),
            quote_root: quote_root.to_string(),
            price_bucket_root: price_bucket_root.to_string(),
            spread_commitment_root: spread_commitment_root.to_string(),
            route_commitment_root: route_commitment_root.to_string(),
            encrypted_terms_root: encrypted_terms_root.to_string(),
            amount_floor_units,
            amount_ceiling_units,
            fee_bps,
            created_at_height,
            expires_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_quote_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_ATOMIC_LIQUIDITY_LANE_PROTOCOL_VERSION,
            "quote_commitment_id": self.quote_commitment_id,
            "maker_id": self.maker_id,
            "quote_root": self.quote_root,
            "price_bucket_root": self.price_bucket_root,
            "spread_commitment_root": self.spread_commitment_root,
            "route_commitment_root": self.route_commitment_root,
            "encrypted_terms_root": self.encrypted_terms_root,
            "amount_floor_units": self.amount_floor_units,
            "amount_ceiling_units": self.amount_ceiling_units,
            "fee_bps": self.fee_bps,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(&self) -> MoneroAtomicLiquidityLaneResult<String> {
        ensure_non_empty("quote.quote_commitment_id", &self.quote_commitment_id)?;
        ensure_non_empty("quote.maker_id", &self.maker_id)?;
        ensure_non_empty("quote.quote_root", &self.quote_root)?;
        ensure_non_empty("quote.price_bucket_root", &self.price_bucket_root)?;
        ensure_non_empty("quote.spread_commitment_root", &self.spread_commitment_root)?;
        ensure_non_empty("quote.route_commitment_root", &self.route_commitment_root)?;
        ensure_non_empty("quote.encrypted_terms_root", &self.encrypted_terms_root)?;
        ensure_positive("quote.amount_floor_units", self.amount_floor_units)?;
        ensure_positive("quote.amount_ceiling_units", self.amount_ceiling_units)?;
        if self.amount_floor_units > self.amount_ceiling_units {
            return Err(format!(
                "quote {} floor above ceiling",
                self.quote_commitment_id
            ));
        }
        ensure_bps("quote.fee_bps", self.fee_bps)?;
        if self.expires_at_height <= self.created_at_height {
            return Err(format!("quote {} expiry invalid", self.quote_commitment_id));
        }
        Ok(lane_payload_root(
            "MONERO-ATOMIC-LANE-QUOTE",
            &self.public_record(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqMakerBond {
    pub bond_id: String,
    pub maker_id: String,
    pub maker_commitment: String,
    pub asset_id: String,
    pub bonded_units: u64,
    pub covered_liquidity_units: u64,
    pub bond_bps: u64,
    pub pq_public_key_commitment: String,
    pub recovery_key_commitment: String,
    pub slashing_policy_root: String,
    pub posted_at_height: u64,
    pub unlocks_at_height: u64,
    pub status: MakerBondStatus,
}

impl PqMakerBond {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        maker_id: &str,
        maker_commitment: &str,
        asset_id: &str,
        bonded_units: u64,
        covered_liquidity_units: u64,
        pq_public_key_commitment: &str,
        recovery_key_commitment: &str,
        slashing_policy_root: &str,
        posted_at_height: u64,
        config: &MoneroAtomicLiquidityLaneConfig,
    ) -> MoneroAtomicLiquidityLaneResult<Self> {
        ensure_non_empty("bond.maker_id", maker_id)?;
        ensure_non_empty("bond.maker_commitment", maker_commitment)?;
        ensure_non_empty("bond.asset_id", asset_id)?;
        ensure_positive("bond.bonded_units", bonded_units)?;
        ensure_positive("bond.covered_liquidity_units", covered_liquidity_units)?;
        ensure_non_empty("bond.pq_public_key_commitment", pq_public_key_commitment)?;
        ensure_non_empty("bond.recovery_key_commitment", recovery_key_commitment)?;
        ensure_non_empty("bond.slashing_policy_root", slashing_policy_root)?;
        let bond_bps = ratio_bps(bonded_units, covered_liquidity_units)?;
        if bond_bps < config.min_maker_bond_bps {
            return Err("bond below minimum maker bond coverage".to_string());
        }
        let unlocks_at_height = posted_at_height
            .saturating_add(config.settlement_ttl_blocks)
            .saturating_add(config.reclaim_delay_blocks);
        let bond_id = pq_maker_bond_id(
            maker_id,
            maker_commitment,
            asset_id,
            bonded_units,
            covered_liquidity_units,
            bond_bps,
            pq_public_key_commitment,
            recovery_key_commitment,
            slashing_policy_root,
            posted_at_height,
            unlocks_at_height,
        );
        Ok(Self {
            bond_id,
            maker_id: maker_id.to_string(),
            maker_commitment: maker_commitment.to_string(),
            asset_id: asset_id.to_string(),
            bonded_units,
            covered_liquidity_units,
            bond_bps,
            pq_public_key_commitment: pq_public_key_commitment.to_string(),
            recovery_key_commitment: recovery_key_commitment.to_string(),
            slashing_policy_root: slashing_policy_root.to_string(),
            posted_at_height,
            unlocks_at_height,
            status: MakerBondStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_maker_bond",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_ATOMIC_LIQUIDITY_LANE_PROTOCOL_VERSION,
            "bond_id": self.bond_id,
            "maker_id": self.maker_id,
            "maker_commitment": self.maker_commitment,
            "asset_id": self.asset_id,
            "bonded_units": self.bonded_units,
            "covered_liquidity_units": self.covered_liquidity_units,
            "bond_bps": self.bond_bps,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "recovery_key_commitment": self.recovery_key_commitment,
            "slashing_policy_root": self.slashing_policy_root,
            "posted_at_height": self.posted_at_height,
            "unlocks_at_height": self.unlocks_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> MoneroAtomicLiquidityLaneResult<String> {
        ensure_non_empty("bond.bond_id", &self.bond_id)?;
        ensure_non_empty("bond.maker_id", &self.maker_id)?;
        ensure_non_empty("bond.maker_commitment", &self.maker_commitment)?;
        ensure_non_empty("bond.asset_id", &self.asset_id)?;
        ensure_positive("bond.bonded_units", self.bonded_units)?;
        ensure_positive("bond.covered_liquidity_units", self.covered_liquidity_units)?;
        ensure_non_empty(
            "bond.pq_public_key_commitment",
            &self.pq_public_key_commitment,
        )?;
        ensure_non_empty(
            "bond.recovery_key_commitment",
            &self.recovery_key_commitment,
        )?;
        ensure_non_empty("bond.slashing_policy_root", &self.slashing_policy_root)?;
        if self.unlocks_at_height <= self.posted_at_height {
            return Err(format!("bond {} unlock height invalid", self.bond_id));
        }
        let derived_bps = ratio_bps(self.bonded_units, self.covered_liquidity_units)?;
        if derived_bps != self.bond_bps {
            return Err(format!("bond {} coverage bps mismatch", self.bond_id));
        }
        Ok(lane_payload_root(
            "MONERO-ATOMIC-LANE-BOND",
            &self.public_record(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroFinalityWindow {
    pub window_id: String,
    pub network: String,
    pub anchor_height: u64,
    pub observed_tip_height: u64,
    pub finality_depth: u64,
    pub reorg_grace_blocks: u64,
    pub safe_release_height: u64,
    pub watcher_quorum_root: String,
    pub risk_label: String,
}

impl MoneroFinalityWindow {
    pub fn new(
        network: &str,
        anchor_height: u64,
        observed_tip_height: u64,
        watcher_quorum_root: &str,
        risk_label: &str,
        config: &MoneroAtomicLiquidityLaneConfig,
    ) -> MoneroAtomicLiquidityLaneResult<Self> {
        ensure_non_empty("finality.network", network)?;
        ensure_non_empty("finality.watcher_quorum_root", watcher_quorum_root)?;
        ensure_non_empty("finality.risk_label", risk_label)?;
        if observed_tip_height < anchor_height {
            return Err("finality observed tip below anchor".to_string());
        }
        let safe_release_height = anchor_height
            .saturating_add(config.finality_blocks)
            .saturating_add(config.reorg_grace_blocks);
        let window_id = finality_window_id(
            network,
            anchor_height,
            observed_tip_height,
            config.finality_blocks,
            config.reorg_grace_blocks,
            safe_release_height,
            watcher_quorum_root,
            risk_label,
        );
        Ok(Self {
            window_id,
            network: network.to_string(),
            anchor_height,
            observed_tip_height,
            finality_depth: config.finality_blocks,
            reorg_grace_blocks: config.reorg_grace_blocks,
            safe_release_height,
            watcher_quorum_root: watcher_quorum_root.to_string(),
            risk_label: risk_label.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_finality_window",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_ATOMIC_LIQUIDITY_LANE_PROTOCOL_VERSION,
            "window_id": self.window_id,
            "network": self.network,
            "anchor_height": self.anchor_height,
            "observed_tip_height": self.observed_tip_height,
            "finality_depth": self.finality_depth,
            "reorg_grace_blocks": self.reorg_grace_blocks,
            "safe_release_height": self.safe_release_height,
            "watcher_quorum_root": self.watcher_quorum_root,
            "risk_label": self.risk_label,
        })
    }

    pub fn validate(&self) -> MoneroAtomicLiquidityLaneResult<String> {
        ensure_non_empty("finality.window_id", &self.window_id)?;
        ensure_non_empty("finality.network", &self.network)?;
        ensure_positive("finality.finality_depth", self.finality_depth)?;
        ensure_non_empty("finality.watcher_quorum_root", &self.watcher_quorum_root)?;
        ensure_non_empty("finality.risk_label", &self.risk_label)?;
        if self.observed_tip_height < self.anchor_height {
            return Err(format!(
                "finality window {} tip below anchor",
                self.window_id
            ));
        }
        if self.safe_release_height <= self.anchor_height {
            return Err(format!(
                "finality window {} safe release height invalid",
                self.window_id
            ));
        }
        Ok(lane_payload_root(
            "MONERO-ATOMIC-LANE-FINALITY",
            &self.public_record(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeBatch {
    pub batch_id: String,
    pub direction: AtomicLaneDirection,
    pub maker_id: String,
    pub payout_ids: BTreeSet<String>,
    pub reservation_ids: BTreeSet<String>,
    pub total_units: u64,
    pub fee_units: u64,
    pub privacy_set_size: u64,
    pub batch_root: String,
    pub maker_attestation_root: String,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub expires_at_height: u64,
    pub status: LowFeeBatchStatus,
}

impl LowFeeBatch {
    pub fn new(
        direction: AtomicLaneDirection,
        maker_id: &str,
        opened_at_height: u64,
        config: &MoneroAtomicLiquidityLaneConfig,
    ) -> MoneroAtomicLiquidityLaneResult<Self> {
        ensure_non_empty("batch.maker_id", maker_id)?;
        let sealed_at_height = opened_at_height.saturating_add(config.batch_window_blocks);
        let expires_at_height = sealed_at_height.saturating_add(config.settlement_ttl_blocks);
        let batch_root = empty_root("collecting-low-fee-batch");
        let maker_attestation_root = empty_root("pending-maker-attestation");
        let batch_id = low_fee_batch_id(
            direction,
            maker_id,
            &batch_root,
            &maker_attestation_root,
            opened_at_height,
            sealed_at_height,
            expires_at_height,
        );
        Ok(Self {
            batch_id,
            direction,
            maker_id: maker_id.to_string(),
            payout_ids: BTreeSet::new(),
            reservation_ids: BTreeSet::new(),
            total_units: 0,
            fee_units: 0,
            privacy_set_size: config.target_privacy_set_size,
            batch_root,
            maker_attestation_root,
            opened_at_height,
            sealed_at_height,
            expires_at_height,
            status: LowFeeBatchStatus::Collecting,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_batch",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_ATOMIC_LIQUIDITY_LANE_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "direction": self.direction.as_str(),
            "maker_id": self.maker_id,
            "payout_ids": self.payout_ids,
            "reservation_ids": self.reservation_ids,
            "total_units": self.total_units,
            "fee_units": self.fee_units,
            "privacy_set_size": self.privacy_set_size,
            "batch_root": self.batch_root,
            "maker_attestation_root": self.maker_attestation_root,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> MoneroAtomicLiquidityLaneResult<String> {
        ensure_non_empty("batch.batch_id", &self.batch_id)?;
        ensure_non_empty("batch.maker_id", &self.maker_id)?;
        ensure_positive("batch.privacy_set_size", self.privacy_set_size)?;
        ensure_non_empty("batch.batch_root", &self.batch_root)?;
        ensure_non_empty("batch.maker_attestation_root", &self.maker_attestation_root)?;
        if self.sealed_at_height <= self.opened_at_height
            || self.expires_at_height <= self.sealed_at_height
        {
            return Err(format!("batch {} height window invalid", self.batch_id));
        }
        Ok(lane_payload_root(
            "MONERO-ATOMIC-LANE-BATCH",
            &self.public_record(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeoutReclaimPath {
    pub reclaim_path_id: String,
    pub reservation_id: String,
    pub offer_id: String,
    pub claimant_commitment: String,
    pub reclaim_asset_id: String,
    pub reclaim_units: u64,
    pub timeout_evidence_root: String,
    pub refund_address_root: String,
    pub pq_attestation_root: String,
    pub armed_at_height: u64,
    pub executable_at_height: u64,
    pub expires_at_height: u64,
    pub status: ReclaimPathStatus,
}

impl TimeoutReclaimPath {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        reservation_id: &str,
        offer_id: &str,
        claimant_commitment: &str,
        reclaim_asset_id: &str,
        reclaim_units: u64,
        timeout_evidence_root: &str,
        refund_address_root: &str,
        pq_attestation_root: &str,
        armed_at_height: u64,
        config: &MoneroAtomicLiquidityLaneConfig,
    ) -> MoneroAtomicLiquidityLaneResult<Self> {
        ensure_non_empty("reclaim.reservation_id", reservation_id)?;
        ensure_non_empty("reclaim.offer_id", offer_id)?;
        ensure_non_empty("reclaim.claimant_commitment", claimant_commitment)?;
        ensure_non_empty("reclaim.reclaim_asset_id", reclaim_asset_id)?;
        ensure_positive("reclaim.reclaim_units", reclaim_units)?;
        ensure_non_empty("reclaim.timeout_evidence_root", timeout_evidence_root)?;
        ensure_non_empty("reclaim.refund_address_root", refund_address_root)?;
        ensure_non_empty("reclaim.pq_attestation_root", pq_attestation_root)?;
        let executable_at_height = armed_at_height.saturating_add(config.reclaim_delay_blocks);
        let expires_at_height = executable_at_height.saturating_add(config.settlement_ttl_blocks);
        let reclaim_path_id = timeout_reclaim_path_id(
            reservation_id,
            offer_id,
            claimant_commitment,
            reclaim_asset_id,
            reclaim_units,
            timeout_evidence_root,
            refund_address_root,
            pq_attestation_root,
            armed_at_height,
            executable_at_height,
            expires_at_height,
        );
        Ok(Self {
            reclaim_path_id,
            reservation_id: reservation_id.to_string(),
            offer_id: offer_id.to_string(),
            claimant_commitment: claimant_commitment.to_string(),
            reclaim_asset_id: reclaim_asset_id.to_string(),
            reclaim_units,
            timeout_evidence_root: timeout_evidence_root.to_string(),
            refund_address_root: refund_address_root.to_string(),
            pq_attestation_root: pq_attestation_root.to_string(),
            armed_at_height,
            executable_at_height,
            expires_at_height,
            status: ReclaimPathStatus::Armed,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "timeout_reclaim_path",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_ATOMIC_LIQUIDITY_LANE_PROTOCOL_VERSION,
            "reclaim_path_id": self.reclaim_path_id,
            "reservation_id": self.reservation_id,
            "offer_id": self.offer_id,
            "claimant_commitment": self.claimant_commitment,
            "reclaim_asset_id": self.reclaim_asset_id,
            "reclaim_units": self.reclaim_units,
            "timeout_evidence_root": self.timeout_evidence_root,
            "refund_address_root": self.refund_address_root,
            "pq_attestation_root": self.pq_attestation_root,
            "armed_at_height": self.armed_at_height,
            "executable_at_height": self.executable_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> MoneroAtomicLiquidityLaneResult<String> {
        ensure_non_empty("reclaim.reclaim_path_id", &self.reclaim_path_id)?;
        ensure_non_empty("reclaim.reservation_id", &self.reservation_id)?;
        ensure_non_empty("reclaim.offer_id", &self.offer_id)?;
        ensure_non_empty("reclaim.claimant_commitment", &self.claimant_commitment)?;
        ensure_non_empty("reclaim.reclaim_asset_id", &self.reclaim_asset_id)?;
        ensure_positive("reclaim.reclaim_units", self.reclaim_units)?;
        ensure_non_empty("reclaim.timeout_evidence_root", &self.timeout_evidence_root)?;
        ensure_non_empty("reclaim.refund_address_root", &self.refund_address_root)?;
        ensure_non_empty("reclaim.pq_attestation_root", &self.pq_attestation_root)?;
        if self.executable_at_height <= self.armed_at_height
            || self.expires_at_height <= self.executable_at_height
        {
            return Err(format!(
                "reclaim {} height window invalid",
                self.reclaim_path_id
            ));
        }
        Ok(lane_payload_root(
            "MONERO-ATOMIC-LANE-RECLAIM",
            &self.public_record(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingReceipt {
    pub slashing_receipt_id: String,
    pub bond_id: String,
    pub maker_id: String,
    pub reservation_id: String,
    pub reason: SlashingReason,
    pub evidence_root: String,
    pub slashed_units: u64,
    pub beneficiary_commitment: String,
    pub watcher_quorum_root: String,
    pub receipt_root: String,
    pub created_at_height: u64,
}

impl SlashingReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bond_id: &str,
        maker_id: &str,
        reservation_id: &str,
        reason: SlashingReason,
        evidence_root: &str,
        slashed_units: u64,
        beneficiary_commitment: &str,
        watcher_quorum_root: &str,
        created_at_height: u64,
    ) -> MoneroAtomicLiquidityLaneResult<Self> {
        ensure_non_empty("slashing.bond_id", bond_id)?;
        ensure_non_empty("slashing.maker_id", maker_id)?;
        ensure_non_empty("slashing.reservation_id", reservation_id)?;
        ensure_non_empty("slashing.evidence_root", evidence_root)?;
        ensure_positive("slashing.slashed_units", slashed_units)?;
        ensure_non_empty("slashing.beneficiary_commitment", beneficiary_commitment)?;
        ensure_non_empty("slashing.watcher_quorum_root", watcher_quorum_root)?;
        let receipt_root = empty_root("private-slashing-receipt-payload");
        let slashing_receipt_id = slashing_receipt_id(
            bond_id,
            maker_id,
            reservation_id,
            reason,
            evidence_root,
            slashed_units,
            beneficiary_commitment,
            watcher_quorum_root,
            &receipt_root,
            created_at_height,
        );
        Ok(Self {
            slashing_receipt_id,
            bond_id: bond_id.to_string(),
            maker_id: maker_id.to_string(),
            reservation_id: reservation_id.to_string(),
            reason,
            evidence_root: evidence_root.to_string(),
            slashed_units,
            beneficiary_commitment: beneficiary_commitment.to_string(),
            watcher_quorum_root: watcher_quorum_root.to_string(),
            receipt_root,
            created_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "slashing_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_ATOMIC_LIQUIDITY_LANE_PROTOCOL_VERSION,
            "slashing_receipt_id": self.slashing_receipt_id,
            "bond_id": self.bond_id,
            "maker_id": self.maker_id,
            "reservation_id": self.reservation_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "slashed_units": self.slashed_units,
            "beneficiary_commitment": self.beneficiary_commitment,
            "watcher_quorum_root": self.watcher_quorum_root,
            "receipt_root": self.receipt_root,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn validate(&self) -> MoneroAtomicLiquidityLaneResult<String> {
        ensure_non_empty("slashing.slashing_receipt_id", &self.slashing_receipt_id)?;
        ensure_non_empty("slashing.bond_id", &self.bond_id)?;
        ensure_non_empty("slashing.maker_id", &self.maker_id)?;
        ensure_non_empty("slashing.reservation_id", &self.reservation_id)?;
        ensure_non_empty("slashing.evidence_root", &self.evidence_root)?;
        ensure_positive("slashing.slashed_units", self.slashed_units)?;
        ensure_non_empty(
            "slashing.beneficiary_commitment",
            &self.beneficiary_commitment,
        )?;
        ensure_non_empty("slashing.watcher_quorum_root", &self.watcher_quorum_root)?;
        ensure_non_empty("slashing.receipt_root", &self.receipt_root)?;
        Ok(lane_payload_root(
            "MONERO-ATOMIC-LANE-SLASHING",
            &self.public_record(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneThrottle {
    pub throttle_id: String,
    pub lane_key: String,
    pub maker_id: String,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub max_offer_count: u64,
    pub max_units: u64,
    pub observed_offer_count: u64,
    pub observed_units: u64,
    pub status: LaneThrottleStatus,
}

impl LaneThrottle {
    pub fn new(
        lane_key: &str,
        maker_id: &str,
        window_start_height: u64,
        config: &MoneroAtomicLiquidityLaneConfig,
    ) -> MoneroAtomicLiquidityLaneResult<Self> {
        ensure_non_empty("throttle.lane_key", lane_key)?;
        ensure_non_empty("throttle.maker_id", maker_id)?;
        let window_end_height = window_start_height.saturating_add(config.throttle_window_blocks);
        let throttle_id = lane_throttle_id(
            lane_key,
            maker_id,
            window_start_height,
            window_end_height,
            config.throttle_max_offers,
            config.throttle_max_units,
        );
        Ok(Self {
            throttle_id,
            lane_key: lane_key.to_string(),
            maker_id: maker_id.to_string(),
            window_start_height,
            window_end_height,
            max_offer_count: config.throttle_max_offers,
            max_units: config.throttle_max_units,
            observed_offer_count: 0,
            observed_units: 0,
            status: LaneThrottleStatus::Monitoring,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "lane_throttle",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_ATOMIC_LIQUIDITY_LANE_PROTOCOL_VERSION,
            "throttle_id": self.throttle_id,
            "lane_key": self.lane_key,
            "maker_id": self.maker_id,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "max_offer_count": self.max_offer_count,
            "max_units": self.max_units,
            "observed_offer_count": self.observed_offer_count,
            "observed_units": self.observed_units,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> MoneroAtomicLiquidityLaneResult<String> {
        ensure_non_empty("throttle.throttle_id", &self.throttle_id)?;
        ensure_non_empty("throttle.lane_key", &self.lane_key)?;
        ensure_non_empty("throttle.maker_id", &self.maker_id)?;
        ensure_positive("throttle.max_offer_count", self.max_offer_count)?;
        ensure_positive("throttle.max_units", self.max_units)?;
        if self.window_end_height <= self.window_start_height {
            return Err(format!("throttle {} window invalid", self.throttle_id));
        }
        Ok(lane_payload_root(
            "MONERO-ATOMIC-LANE-THROTTLE",
            &self.public_record(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicLaneRecord {
    pub record_id: String,
    pub subject_id: String,
    pub subject_kind: String,
    pub record_root: String,
    pub emitted_at_height: u64,
}

impl DeterministicLaneRecord {
    pub fn new(
        subject_id: &str,
        subject_kind: &str,
        record: &Value,
        emitted_at_height: u64,
    ) -> MoneroAtomicLiquidityLaneResult<Self> {
        ensure_non_empty("record.subject_id", subject_id)?;
        ensure_non_empty("record.subject_kind", subject_kind)?;
        let record_root = lane_payload_root("MONERO-ATOMIC-LANE-PUBLIC-RECORD-PAYLOAD", record);
        let record_id = domain_hash(
            "MONERO-ATOMIC-LANE-PUBLIC-RECORD-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(subject_id),
                HashPart::Str(subject_kind),
                HashPart::Str(&record_root),
                HashPart::Int(emitted_at_height as i128),
            ],
            32,
        );
        Ok(Self {
            record_id,
            subject_id: subject_id.to_string(),
            subject_kind: subject_kind.to_string(),
            record_root,
            emitted_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "deterministic_lane_record",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_ATOMIC_LIQUIDITY_LANE_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "subject_id": self.subject_id,
            "subject_kind": self.subject_kind,
            "record_root": self.record_root,
            "emitted_at_height": self.emitted_at_height,
        })
    }

    pub fn validate(&self) -> MoneroAtomicLiquidityLaneResult<String> {
        ensure_non_empty("record.record_id", &self.record_id)?;
        ensure_non_empty("record.subject_id", &self.subject_id)?;
        ensure_non_empty("record.subject_kind", &self.subject_kind)?;
        ensure_non_empty("record.record_root", &self.record_root)?;
        Ok(lane_payload_root(
            "MONERO-ATOMIC-LANE-PUBLIC-RECORD",
            &self.public_record(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub event_root: String,
    pub emitted_at_height: u64,
}

impl LaneEvent {
    pub fn new(
        event_kind: &str,
        subject_id: &str,
        event_root: &str,
        emitted_at_height: u64,
    ) -> MoneroAtomicLiquidityLaneResult<Self> {
        ensure_non_empty("event.event_kind", event_kind)?;
        ensure_non_empty("event.subject_id", subject_id)?;
        ensure_non_empty("event.event_root", event_root)?;
        let event_id = domain_hash(
            "MONERO-ATOMIC-LANE-EVENT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(event_kind),
                HashPart::Str(subject_id),
                HashPart::Str(event_root),
                HashPart::Int(emitted_at_height as i128),
            ],
            32,
        );
        Ok(Self {
            event_id,
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            event_root: event_root.to_string(),
            emitted_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "lane_event",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_ATOMIC_LIQUIDITY_LANE_PROTOCOL_VERSION,
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "event_root": self.event_root,
            "emitted_at_height": self.emitted_at_height,
        })
    }

    pub fn validate(&self) -> MoneroAtomicLiquidityLaneResult<String> {
        ensure_non_empty("event.event_id", &self.event_id)?;
        ensure_non_empty("event.event_kind", &self.event_kind)?;
        ensure_non_empty("event.subject_id", &self.subject_id)?;
        ensure_non_empty("event.event_root", &self.event_root)?;
        Ok(lane_payload_root(
            "MONERO-ATOMIC-LANE-EVENT",
            &self.public_record(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroAtomicLiquidityLaneRoots {
    pub config_root: String,
    pub offer_root: String,
    pub stealth_payout_root: String,
    pub reservation_root: String,
    pub quote_commitment_root: String,
    pub pq_maker_bond_root: String,
    pub finality_window_root: String,
    pub low_fee_batch_root: String,
    pub timeout_reclaim_root: String,
    pub slashing_receipt_root: String,
    pub lane_throttle_root: String,
    pub nullifier_index_root: String,
    pub maker_offer_index_root: String,
    pub public_record_root: String,
    pub event_root: String,
}

impl MoneroAtomicLiquidityLaneRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_atomic_liquidity_lane_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_ATOMIC_LIQUIDITY_LANE_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "offer_root": self.offer_root,
            "stealth_payout_root": self.stealth_payout_root,
            "reservation_root": self.reservation_root,
            "quote_commitment_root": self.quote_commitment_root,
            "pq_maker_bond_root": self.pq_maker_bond_root,
            "finality_window_root": self.finality_window_root,
            "low_fee_batch_root": self.low_fee_batch_root,
            "timeout_reclaim_root": self.timeout_reclaim_root,
            "slashing_receipt_root": self.slashing_receipt_root,
            "lane_throttle_root": self.lane_throttle_root,
            "nullifier_index_root": self.nullifier_index_root,
            "maker_offer_index_root": self.maker_offer_index_root,
            "public_record_root": self.public_record_root,
            "event_root": self.event_root,
        })
    }

    pub fn roots_root(&self) -> String {
        lane_payload_root("MONERO-ATOMIC-LIQUIDITY-LANE-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroAtomicLiquidityLaneCounters {
    pub offer_count: u64,
    pub live_offer_count: u64,
    pub settled_offer_count: u64,
    pub reservation_count: u64,
    pub live_reservation_count: u64,
    pub inbound_reservation_count: u64,
    pub outbound_reservation_count: u64,
    pub payout_count: u64,
    pub live_payout_count: u64,
    pub quote_commitment_count: u64,
    pub pq_maker_bond_count: u64,
    pub active_bond_count: u64,
    pub finality_window_count: u64,
    pub low_fee_batch_count: u64,
    pub live_low_fee_batch_count: u64,
    pub timeout_reclaim_count: u64,
    pub live_timeout_reclaim_count: u64,
    pub slashing_receipt_count: u64,
    pub lane_throttle_count: u64,
    pub active_lane_throttle_count: u64,
    pub public_record_count: u64,
    pub event_count: u64,
    pub offered_units: u64,
    pub reserved_units: u64,
    pub inbound_reserved_units: u64,
    pub outbound_reserved_units: u64,
    pub settled_units: u64,
    pub bonded_units: u64,
    pub slashed_units: u64,
    pub low_fee_batched_units: u64,
}

impl MoneroAtomicLiquidityLaneCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_atomic_liquidity_lane_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_ATOMIC_LIQUIDITY_LANE_PROTOCOL_VERSION,
            "offer_count": self.offer_count,
            "live_offer_count": self.live_offer_count,
            "settled_offer_count": self.settled_offer_count,
            "reservation_count": self.reservation_count,
            "live_reservation_count": self.live_reservation_count,
            "inbound_reservation_count": self.inbound_reservation_count,
            "outbound_reservation_count": self.outbound_reservation_count,
            "payout_count": self.payout_count,
            "live_payout_count": self.live_payout_count,
            "quote_commitment_count": self.quote_commitment_count,
            "pq_maker_bond_count": self.pq_maker_bond_count,
            "active_bond_count": self.active_bond_count,
            "finality_window_count": self.finality_window_count,
            "low_fee_batch_count": self.low_fee_batch_count,
            "live_low_fee_batch_count": self.live_low_fee_batch_count,
            "timeout_reclaim_count": self.timeout_reclaim_count,
            "live_timeout_reclaim_count": self.live_timeout_reclaim_count,
            "slashing_receipt_count": self.slashing_receipt_count,
            "lane_throttle_count": self.lane_throttle_count,
            "active_lane_throttle_count": self.active_lane_throttle_count,
            "public_record_count": self.public_record_count,
            "event_count": self.event_count,
            "offered_units": self.offered_units,
            "reserved_units": self.reserved_units,
            "inbound_reserved_units": self.inbound_reserved_units,
            "outbound_reserved_units": self.outbound_reserved_units,
            "settled_units": self.settled_units,
            "bonded_units": self.bonded_units,
            "slashed_units": self.slashed_units,
            "low_fee_batched_units": self.low_fee_batched_units,
        })
    }

    pub fn counters_root(&self) -> String {
        lane_payload_root(
            "MONERO-ATOMIC-LIQUIDITY-LANE-COUNTERS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroAtomicLiquidityLaneState {
    pub height: u64,
    pub monero_network: String,
    pub l2_network: String,
    pub lane_operator_commitment: String,
    pub active_finality_window_id: String,
    pub config: MoneroAtomicLiquidityLaneConfig,
    pub offers: BTreeMap<String, AtomicLaneOffer>,
    pub stealth_payouts: BTreeMap<String, StealthPayoutEnvelope>,
    pub reservations: BTreeMap<String, LiquidityReservation>,
    pub private_quote_commitments: BTreeMap<String, PrivateQuoteCommitment>,
    pub pq_maker_bonds: BTreeMap<String, PqMakerBond>,
    pub finality_windows: BTreeMap<String, MoneroFinalityWindow>,
    pub low_fee_batches: BTreeMap<String, LowFeeBatch>,
    pub timeout_reclaim_paths: BTreeMap<String, TimeoutReclaimPath>,
    pub slashing_receipts: BTreeMap<String, SlashingReceipt>,
    pub lane_throttles: BTreeMap<String, LaneThrottle>,
    pub nullifier_index: BTreeMap<String, String>,
    pub maker_offer_index: BTreeMap<String, BTreeSet<String>>,
    pub public_records: BTreeMap<String, DeterministicLaneRecord>,
    pub events: BTreeMap<String, LaneEvent>,
}

impl MoneroAtomicLiquidityLaneState {
    pub fn new(
        config: MoneroAtomicLiquidityLaneConfig,
        lane_operator_commitment: &str,
        height: u64,
    ) -> MoneroAtomicLiquidityLaneResult<Self> {
        config.validate()?;
        ensure_non_empty("state.lane_operator_commitment", lane_operator_commitment)?;
        Ok(Self {
            height,
            monero_network: config.monero_network.clone(),
            l2_network: config.l2_network.clone(),
            lane_operator_commitment: lane_operator_commitment.to_string(),
            active_finality_window_id: String::new(),
            config,
            offers: BTreeMap::new(),
            stealth_payouts: BTreeMap::new(),
            reservations: BTreeMap::new(),
            private_quote_commitments: BTreeMap::new(),
            pq_maker_bonds: BTreeMap::new(),
            finality_windows: BTreeMap::new(),
            low_fee_batches: BTreeMap::new(),
            timeout_reclaim_paths: BTreeMap::new(),
            slashing_receipts: BTreeMap::new(),
            lane_throttles: BTreeMap::new(),
            nullifier_index: BTreeMap::new(),
            maker_offer_index: BTreeMap::new(),
            public_records: BTreeMap::new(),
            events: BTreeMap::new(),
        })
    }

    pub fn devnet() -> MoneroAtomicLiquidityLaneResult<Self> {
        let config = MoneroAtomicLiquidityLaneConfig::devnet();
        let mut state = Self::new(
            config.clone(),
            "devnet-monero-atomic-liquidity-lane-operator",
            MONERO_ATOMIC_LIQUIDITY_LANE_DEVNET_HEIGHT,
        )?;

        let finality = MoneroFinalityWindow::new(
            &config.monero_network,
            state.height.saturating_sub(10),
            state.height,
            &empty_root("devnet-watcher-quorum"),
            "devnet-green",
            &config,
        )?;
        state.active_finality_window_id = finality.window_id.clone();
        state
            .finality_windows
            .insert(finality.window_id.clone(), finality);

        let bond = PqMakerBond::new(
            "devnet-maker-0",
            "devnet-maker-0-commitment",
            &config.wrapped_asset_id,
            300_000,
            100_000,
            "devnet-maker-0-ml-dsa-key-commitment",
            "devnet-maker-0-slh-dsa-recovery-key-commitment",
            &empty_root("devnet-maker-0-slashing-policy"),
            state.height,
            &config,
        )?;
        let bond_id = bond.bond_id.clone();
        state.pq_maker_bonds.insert(bond_id.clone(), bond);

        let quote = PrivateQuoteCommitment::new(
            "devnet-maker-0",
            &empty_root("devnet-private-quote"),
            &empty_root("devnet-price-bucket"),
            &empty_root("devnet-spread-commitment"),
            &empty_root("devnet-route-commitment"),
            &empty_root("devnet-encrypted-terms"),
            5_000,
            100_000,
            config.fast_fee_bps,
            state.height,
            &config,
        )?;
        let quote_id = quote.quote_commitment_id.clone();
        state
            .private_quote_commitments
            .insert(quote_id.clone(), quote);

        let mut offer = AtomicLaneOffer::new(
            "devnet-maker-0",
            "devnet-maker-0-commitment",
            AtomicLaneDirection::L2ToMonero,
            AtomicLaneSpeed::Fast,
            &config.wrapped_asset_id,
            &config.xmr_asset_id,
            100_000,
            5_000,
            50_000,
            &empty_root("devnet-offer-quote"),
            &empty_root("devnet-offer-inventory"),
            &empty_root("devnet-view-policy"),
            &empty_root("devnet-l2-escrow-policy"),
            "devnet-maker-0-ml-dsa-key-commitment",
            &bond_id,
            state.height,
            &config,
        )?;
        let offer_id = offer.offer_id.clone();

        let reservation = LiquidityReservation::new(
            &offer_id,
            "devnet-maker-0",
            "devnet-taker-0-commitment",
            LiquidityReservationKind::OutboundMonero,
            AtomicLaneDirection::L2ToMonero,
            &config.wrapped_asset_id,
            25_000,
            10,
            &bond_id,
            &quote_id,
            &empty_root("devnet-nullifier-0"),
            state.height,
            &config,
        )?;
        let reservation_id = reservation.reservation_id.clone();
        offer.reserved_units = offer
            .reserved_units
            .saturating_add(reservation.amount_units);
        offer.status = AtomicLaneOfferStatus::PartiallyReserved;
        state
            .nullifier_index
            .insert(reservation.nullifier_root.clone(), reservation_id.clone());
        state
            .maker_offer_index
            .entry(offer.maker_id.clone())
            .or_default()
            .insert(offer_id.clone());
        state.offers.insert(offer_id.clone(), offer);
        state
            .reservations
            .insert(reservation_id.clone(), reservation.clone());

        let payout = StealthPayoutEnvelope::new(
            &offer_id,
            &reservation_id,
            "devnet-recipient-0-commitment",
            &empty_root("devnet-stealth-address"),
            &empty_root("devnet-one-time-key"),
            &empty_root("devnet-view-tag"),
            &empty_root("devnet-amount-bucket"),
            &empty_root("devnet-encrypted-payout"),
            25_000,
            10,
            state.height,
            &config,
        )?;
        state
            .stealth_payouts
            .insert(payout.payout_id.clone(), payout.clone());

        let mut batch = LowFeeBatch::new(
            AtomicLaneDirection::L2ToMonero,
            "devnet-maker-0",
            state.height,
            &config,
        )?;
        batch.payout_ids.insert(payout.payout_id.clone());
        batch.reservation_ids.insert(reservation_id.clone());
        batch.total_units = 25_000;
        batch.fee_units = 10;
        state.low_fee_batches.insert(batch.batch_id.clone(), batch);

        let reclaim = TimeoutReclaimPath::new(
            &reservation_id,
            &offer_id,
            "devnet-taker-0-commitment",
            &config.wrapped_asset_id,
            25_000,
            &empty_root("devnet-timeout-evidence"),
            &empty_root("devnet-refund-address"),
            &empty_root("devnet-reclaim-attestation"),
            state.height,
            &config,
        )?;
        state
            .timeout_reclaim_paths
            .insert(reclaim.reclaim_path_id.clone(), reclaim);

        let throttle = LaneThrottle::new(
            "devnet-l2-to-monero-fast",
            "devnet-maker-0",
            state.height,
            &config,
        )?;
        state
            .lane_throttles
            .insert(throttle.throttle_id.clone(), throttle);

        let offer_record = if let Some(offer) = state.offers.get(&offer_id) {
            offer.public_record()
        } else {
            json!({})
        };
        let record = DeterministicLaneRecord::new(
            &offer_id,
            "atomic_lane_offer",
            &offer_record,
            state.height,
        )?;
        state
            .public_records
            .insert(record.record_id.clone(), record);

        let event_root =
            lane_payload_root("MONERO-ATOMIC-LANE-DEVNET-SEED", &state.public_record());
        let event = LaneEvent::new("devnet_seeded", &offer_id, &event_root, state.height)?;
        state.events.insert(event.event_id.clone(), event);

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> MoneroAtomicLiquidityLaneResult<()> {
        if height < self.height {
            return Err("state height cannot move backwards".to_string());
        }
        self.height = height;
        Ok(())
    }

    pub fn roots(&self) -> MoneroAtomicLiquidityLaneRoots {
        MoneroAtomicLiquidityLaneRoots {
            config_root: lane_payload_root(
                "MONERO-ATOMIC-LANE-CONFIG-ROOT",
                &self.config.public_record(),
            ),
            offer_root: map_root(
                "MONERO-ATOMIC-LANE-OFFERS",
                &self.offers,
                AtomicLaneOffer::public_record,
            ),
            stealth_payout_root: map_root(
                "MONERO-ATOMIC-LANE-PAYOUTS",
                &self.stealth_payouts,
                StealthPayoutEnvelope::public_record,
            ),
            reservation_root: map_root(
                "MONERO-ATOMIC-LANE-RESERVATIONS",
                &self.reservations,
                LiquidityReservation::public_record,
            ),
            quote_commitment_root: map_root(
                "MONERO-ATOMIC-LANE-QUOTES",
                &self.private_quote_commitments,
                PrivateQuoteCommitment::public_record,
            ),
            pq_maker_bond_root: map_root(
                "MONERO-ATOMIC-LANE-BONDS",
                &self.pq_maker_bonds,
                PqMakerBond::public_record,
            ),
            finality_window_root: map_root(
                "MONERO-ATOMIC-LANE-FINALITY-WINDOWS",
                &self.finality_windows,
                MoneroFinalityWindow::public_record,
            ),
            low_fee_batch_root: map_root(
                "MONERO-ATOMIC-LANE-LOW-FEE-BATCHES",
                &self.low_fee_batches,
                LowFeeBatch::public_record,
            ),
            timeout_reclaim_root: map_root(
                "MONERO-ATOMIC-LANE-RECLAIMS",
                &self.timeout_reclaim_paths,
                TimeoutReclaimPath::public_record,
            ),
            slashing_receipt_root: map_root(
                "MONERO-ATOMIC-LANE-SLASHING-RECEIPTS",
                &self.slashing_receipts,
                SlashingReceipt::public_record,
            ),
            lane_throttle_root: map_root(
                "MONERO-ATOMIC-LANE-THROTTLES",
                &self.lane_throttles,
                LaneThrottle::public_record,
            ),
            nullifier_index_root: lane_payload_root(
                "MONERO-ATOMIC-LANE-NULLIFIER-INDEX",
                &json!(self.nullifier_index),
            ),
            maker_offer_index_root: lane_payload_root(
                "MONERO-ATOMIC-LANE-MAKER-OFFER-INDEX",
                &json!(self.maker_offer_index),
            ),
            public_record_root: map_root(
                "MONERO-ATOMIC-LANE-PUBLIC-RECORDS",
                &self.public_records,
                DeterministicLaneRecord::public_record,
            ),
            event_root: map_root(
                "MONERO-ATOMIC-LANE-EVENTS",
                &self.events,
                LaneEvent::public_record,
            ),
        }
    }

    pub fn counters(&self) -> MoneroAtomicLiquidityLaneCounters {
        let mut counters = MoneroAtomicLiquidityLaneCounters {
            offer_count: self.offers.len() as u64,
            live_offer_count: 0,
            settled_offer_count: 0,
            reservation_count: self.reservations.len() as u64,
            live_reservation_count: 0,
            inbound_reservation_count: 0,
            outbound_reservation_count: 0,
            payout_count: self.stealth_payouts.len() as u64,
            live_payout_count: 0,
            quote_commitment_count: self.private_quote_commitments.len() as u64,
            pq_maker_bond_count: self.pq_maker_bonds.len() as u64,
            active_bond_count: 0,
            finality_window_count: self.finality_windows.len() as u64,
            low_fee_batch_count: self.low_fee_batches.len() as u64,
            live_low_fee_batch_count: 0,
            timeout_reclaim_count: self.timeout_reclaim_paths.len() as u64,
            live_timeout_reclaim_count: 0,
            slashing_receipt_count: self.slashing_receipts.len() as u64,
            lane_throttle_count: self.lane_throttles.len() as u64,
            active_lane_throttle_count: 0,
            public_record_count: self.public_records.len() as u64,
            event_count: self.events.len() as u64,
            offered_units: 0,
            reserved_units: 0,
            inbound_reserved_units: 0,
            outbound_reserved_units: 0,
            settled_units: 0,
            bonded_units: 0,
            slashed_units: 0,
            low_fee_batched_units: 0,
        };

        for offer in self.offers.values() {
            counters.offered_units = counters.offered_units.saturating_add(offer.available_units);
            counters.reserved_units = counters.reserved_units.saturating_add(offer.reserved_units);
            if offer.status.is_live() {
                counters.live_offer_count = counters.live_offer_count.saturating_add(1);
            }
            if offer.status == AtomicLaneOfferStatus::Settled {
                counters.settled_offer_count = counters.settled_offer_count.saturating_add(1);
                counters.settled_units =
                    counters.settled_units.saturating_add(offer.reserved_units);
            }
        }
        for reservation in self.reservations.values() {
            if reservation.status.is_live() {
                counters.live_reservation_count = counters.live_reservation_count.saturating_add(1);
            }
            match reservation.direction {
                AtomicLaneDirection::MoneroToL2 => {
                    counters.inbound_reservation_count =
                        counters.inbound_reservation_count.saturating_add(1);
                    counters.inbound_reserved_units = counters
                        .inbound_reserved_units
                        .saturating_add(reservation.amount_units);
                }
                AtomicLaneDirection::L2ToMonero => {
                    counters.outbound_reservation_count =
                        counters.outbound_reservation_count.saturating_add(1);
                    counters.outbound_reserved_units = counters
                        .outbound_reserved_units
                        .saturating_add(reservation.amount_units);
                }
            }
        }
        for payout in self.stealth_payouts.values() {
            if payout.status.is_live() {
                counters.live_payout_count = counters.live_payout_count.saturating_add(1);
            }
        }
        for bond in self.pq_maker_bonds.values() {
            counters.bonded_units = counters.bonded_units.saturating_add(bond.bonded_units);
            if bond.status.backs_liquidity() {
                counters.active_bond_count = counters.active_bond_count.saturating_add(1);
            }
        }
        for batch in self.low_fee_batches.values() {
            counters.low_fee_batched_units = counters
                .low_fee_batched_units
                .saturating_add(batch.total_units);
            if batch.status.is_live() {
                counters.live_low_fee_batch_count =
                    counters.live_low_fee_batch_count.saturating_add(1);
            }
        }
        for reclaim in self.timeout_reclaim_paths.values() {
            if reclaim.status.is_live() {
                counters.live_timeout_reclaim_count =
                    counters.live_timeout_reclaim_count.saturating_add(1);
            }
        }
        for receipt in self.slashing_receipts.values() {
            counters.slashed_units = counters.slashed_units.saturating_add(receipt.slashed_units);
        }
        for throttle in self.lane_throttles.values() {
            if throttle.status.is_active() {
                counters.active_lane_throttle_count =
                    counters.active_lane_throttle_count.saturating_add(1);
            }
        }
        counters
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "monero_atomic_liquidity_lane_state",
            "chain_id": CHAIN_ID,
            "protocol_label": MONERO_ATOMIC_LIQUIDITY_LANE_PROTOCOL_LABEL,
            "protocol_version": MONERO_ATOMIC_LIQUIDITY_LANE_PROTOCOL_VERSION,
            "schema_version": MONERO_ATOMIC_LIQUIDITY_LANE_SCHEMA_VERSION,
            "height": self.height,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "lane_operator_commitment": self.lane_operator_commitment,
            "active_finality_window_id": self.active_finality_window_id,
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
        })
    }

    pub fn state_root(&self) -> String {
        monero_atomic_liquidity_lane_state_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> MoneroAtomicLiquidityLaneResult<String> {
        self.config.validate()?;
        ensure_non_empty("state.monero_network", &self.monero_network)?;
        ensure_non_empty("state.l2_network", &self.l2_network)?;
        ensure_non_empty(
            "state.lane_operator_commitment",
            &self.lane_operator_commitment,
        )?;
        if self.monero_network != self.config.monero_network {
            return Err("state monero network differs from config".to_string());
        }
        if self.l2_network != self.config.l2_network {
            return Err("state l2 network differs from config".to_string());
        }
        ensure_len(
            "state.offers",
            self.offers.len(),
            MONERO_ATOMIC_LIQUIDITY_LANE_MAX_OFFERS,
        )?;
        ensure_len(
            "state.reservations",
            self.reservations.len(),
            MONERO_ATOMIC_LIQUIDITY_LANE_MAX_RESERVATIONS,
        )?;
        ensure_len(
            "state.stealth_payouts",
            self.stealth_payouts.len(),
            MONERO_ATOMIC_LIQUIDITY_LANE_MAX_PAYOUTS,
        )?;
        ensure_len(
            "state.private_quote_commitments",
            self.private_quote_commitments.len(),
            MONERO_ATOMIC_LIQUIDITY_LANE_MAX_QUOTES,
        )?;
        ensure_len(
            "state.pq_maker_bonds",
            self.pq_maker_bonds.len(),
            MONERO_ATOMIC_LIQUIDITY_LANE_MAX_BONDS,
        )?;
        ensure_len(
            "state.low_fee_batches",
            self.low_fee_batches.len(),
            MONERO_ATOMIC_LIQUIDITY_LANE_MAX_BATCHES,
        )?;
        ensure_len(
            "state.timeout_reclaim_paths",
            self.timeout_reclaim_paths.len(),
            MONERO_ATOMIC_LIQUIDITY_LANE_MAX_RECLAIMS,
        )?;
        ensure_len(
            "state.slashing_receipts",
            self.slashing_receipts.len(),
            MONERO_ATOMIC_LIQUIDITY_LANE_MAX_SLASHING_RECEIPTS,
        )?;
        ensure_len(
            "state.lane_throttles",
            self.lane_throttles.len(),
            MONERO_ATOMIC_LIQUIDITY_LANE_MAX_THROTTLES,
        )?;
        ensure_len(
            "state.public_records",
            self.public_records.len(),
            MONERO_ATOMIC_LIQUIDITY_LANE_MAX_PUBLIC_RECORDS,
        )?;
        ensure_len(
            "state.events",
            self.events.len(),
            MONERO_ATOMIC_LIQUIDITY_LANE_MAX_EVENTS,
        )?;

        validate_map("offer", &self.offers, AtomicLaneOffer::validate)?;
        validate_map(
            "payout",
            &self.stealth_payouts,
            StealthPayoutEnvelope::validate,
        )?;
        validate_map(
            "reservation",
            &self.reservations,
            LiquidityReservation::validate,
        )?;
        validate_map(
            "quote",
            &self.private_quote_commitments,
            PrivateQuoteCommitment::validate,
        )?;
        validate_map("bond", &self.pq_maker_bonds, PqMakerBond::validate)?;
        validate_map(
            "finality",
            &self.finality_windows,
            MoneroFinalityWindow::validate,
        )?;
        validate_map("batch", &self.low_fee_batches, LowFeeBatch::validate)?;
        validate_map(
            "reclaim",
            &self.timeout_reclaim_paths,
            TimeoutReclaimPath::validate,
        )?;
        validate_map(
            "slashing",
            &self.slashing_receipts,
            SlashingReceipt::validate,
        )?;
        validate_map("throttle", &self.lane_throttles, LaneThrottle::validate)?;
        validate_map(
            "record",
            &self.public_records,
            DeterministicLaneRecord::validate,
        )?;
        validate_map("event", &self.events, LaneEvent::validate)?;

        for (nullifier_root, reservation_id) in &self.nullifier_index {
            ensure_non_empty("state.nullifier_index.key", nullifier_root)?;
            if !self.reservations.contains_key(reservation_id) {
                return Err(format!(
                    "nullifier index points to missing reservation {}",
                    reservation_id
                ));
            }
        }
        for (maker_id, offer_ids) in &self.maker_offer_index {
            ensure_non_empty("state.maker_offer_index.key", maker_id)?;
            for offer_id in offer_ids {
                let offer = self
                    .offers
                    .get(offer_id)
                    .ok_or_else(|| format!("maker index points to missing offer {}", offer_id))?;
                if &offer.maker_id != maker_id {
                    return Err(format!("maker index mismatch for offer {}", offer_id));
                }
            }
        }
        if !self.active_finality_window_id.is_empty()
            && !self
                .finality_windows
                .contains_key(&self.active_finality_window_id)
        {
            return Err("active finality window is missing".to_string());
        }
        Ok(self.state_root())
    }
}

pub fn monero_atomic_liquidity_lane_state_root_from_record(record: &serde_json::Value) -> String {
    lane_payload_root("MONERO-ATOMIC-LIQUIDITY-LANE-STATE", record)
}

#[allow(clippy::too_many_arguments)]
pub fn atomic_lane_offer_id(
    maker_id: &str,
    maker_commitment: &str,
    direction: AtomicLaneDirection,
    speed: AtomicLaneSpeed,
    source_asset_id: &str,
    target_asset_id: &str,
    available_units: u64,
    min_fill_units: u64,
    max_fill_units: u64,
    fee_bps: u64,
    quote_root: &str,
    inventory_root: &str,
    pq_key_commitment: &str,
    opened_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-ATOMIC-LANE-OFFER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(maker_id),
            HashPart::Str(maker_commitment),
            HashPart::Str(direction.as_str()),
            HashPart::Str(speed.as_str()),
            HashPart::Str(source_asset_id),
            HashPart::Str(target_asset_id),
            HashPart::Int(available_units as i128),
            HashPart::Int(min_fill_units as i128),
            HashPart::Int(max_fill_units as i128),
            HashPart::Int(fee_bps as i128),
            HashPart::Str(quote_root),
            HashPart::Str(inventory_root),
            HashPart::Str(pq_key_commitment),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn stealth_payout_envelope_id(
    offer_id: &str,
    reservation_id: &str,
    recipient_commitment: &str,
    stealth_address_root: &str,
    one_time_key_root: &str,
    view_tag_root: &str,
    amount_bucket_root: &str,
    encrypted_payload_root: &str,
    amount_units: u64,
    fee_units: u64,
    created_at_height: u64,
    finality_height: u64,
) -> String {
    domain_hash(
        "MONERO-ATOMIC-LANE-STEALTH-PAYOUT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(offer_id),
            HashPart::Str(reservation_id),
            HashPart::Str(recipient_commitment),
            HashPart::Str(stealth_address_root),
            HashPart::Str(one_time_key_root),
            HashPart::Str(view_tag_root),
            HashPart::Str(amount_bucket_root),
            HashPart::Str(encrypted_payload_root),
            HashPart::Int(amount_units as i128),
            HashPart::Int(fee_units as i128),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(finality_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn liquidity_reservation_id(
    offer_id: &str,
    maker_id: &str,
    taker_commitment: &str,
    kind: LiquidityReservationKind,
    direction: AtomicLaneDirection,
    asset_id: &str,
    amount_units: u64,
    fee_units: u64,
    bond_id: &str,
    quote_commitment_id: &str,
    nullifier_root: &str,
    opened_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-ATOMIC-LANE-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(offer_id),
            HashPart::Str(maker_id),
            HashPart::Str(taker_commitment),
            HashPart::Str(kind.as_str()),
            HashPart::Str(direction.as_str()),
            HashPart::Str(asset_id),
            HashPart::Int(amount_units as i128),
            HashPart::Int(fee_units as i128),
            HashPart::Str(bond_id),
            HashPart::Str(quote_commitment_id),
            HashPart::Str(nullifier_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_quote_commitment_id(
    maker_id: &str,
    quote_root: &str,
    price_bucket_root: &str,
    spread_commitment_root: &str,
    route_commitment_root: &str,
    encrypted_terms_root: &str,
    amount_floor_units: u64,
    amount_ceiling_units: u64,
    fee_bps: u64,
    created_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-ATOMIC-LANE-PRIVATE-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(maker_id),
            HashPart::Str(quote_root),
            HashPart::Str(price_bucket_root),
            HashPart::Str(spread_commitment_root),
            HashPart::Str(route_commitment_root),
            HashPart::Str(encrypted_terms_root),
            HashPart::Int(amount_floor_units as i128),
            HashPart::Int(amount_ceiling_units as i128),
            HashPart::Int(fee_bps as i128),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn pq_maker_bond_id(
    maker_id: &str,
    maker_commitment: &str,
    asset_id: &str,
    bonded_units: u64,
    covered_liquidity_units: u64,
    bond_bps: u64,
    pq_public_key_commitment: &str,
    recovery_key_commitment: &str,
    slashing_policy_root: &str,
    posted_at_height: u64,
    unlocks_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-ATOMIC-LANE-PQ-MAKER-BOND-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(maker_id),
            HashPart::Str(maker_commitment),
            HashPart::Str(asset_id),
            HashPart::Int(bonded_units as i128),
            HashPart::Int(covered_liquidity_units as i128),
            HashPart::Int(bond_bps as i128),
            HashPart::Str(pq_public_key_commitment),
            HashPart::Str(recovery_key_commitment),
            HashPart::Str(slashing_policy_root),
            HashPart::Int(posted_at_height as i128),
            HashPart::Int(unlocks_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn finality_window_id(
    network: &str,
    anchor_height: u64,
    observed_tip_height: u64,
    finality_depth: u64,
    reorg_grace_blocks: u64,
    safe_release_height: u64,
    watcher_quorum_root: &str,
    risk_label: &str,
) -> String {
    domain_hash(
        "MONERO-ATOMIC-LANE-FINALITY-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(network),
            HashPart::Int(anchor_height as i128),
            HashPart::Int(observed_tip_height as i128),
            HashPart::Int(finality_depth as i128),
            HashPart::Int(reorg_grace_blocks as i128),
            HashPart::Int(safe_release_height as i128),
            HashPart::Str(watcher_quorum_root),
            HashPart::Str(risk_label),
        ],
        32,
    )
}

pub fn low_fee_batch_id(
    direction: AtomicLaneDirection,
    maker_id: &str,
    batch_root: &str,
    maker_attestation_root: &str,
    opened_at_height: u64,
    sealed_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-ATOMIC-LANE-LOW-FEE-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(direction.as_str()),
            HashPart::Str(maker_id),
            HashPart::Str(batch_root),
            HashPart::Str(maker_attestation_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(sealed_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn timeout_reclaim_path_id(
    reservation_id: &str,
    offer_id: &str,
    claimant_commitment: &str,
    reclaim_asset_id: &str,
    reclaim_units: u64,
    timeout_evidence_root: &str,
    refund_address_root: &str,
    pq_attestation_root: &str,
    armed_at_height: u64,
    executable_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-ATOMIC-LANE-TIMEOUT-RECLAIM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(reservation_id),
            HashPart::Str(offer_id),
            HashPart::Str(claimant_commitment),
            HashPart::Str(reclaim_asset_id),
            HashPart::Int(reclaim_units as i128),
            HashPart::Str(timeout_evidence_root),
            HashPart::Str(refund_address_root),
            HashPart::Str(pq_attestation_root),
            HashPart::Int(armed_at_height as i128),
            HashPart::Int(executable_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn slashing_receipt_id(
    bond_id: &str,
    maker_id: &str,
    reservation_id: &str,
    reason: SlashingReason,
    evidence_root: &str,
    slashed_units: u64,
    beneficiary_commitment: &str,
    watcher_quorum_root: &str,
    receipt_root: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-ATOMIC-LANE-SLASHING-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bond_id),
            HashPart::Str(maker_id),
            HashPart::Str(reservation_id),
            HashPart::Str(reason.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Int(slashed_units as i128),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(watcher_quorum_root),
            HashPart::Str(receipt_root),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn lane_throttle_id(
    lane_key: &str,
    maker_id: &str,
    window_start_height: u64,
    window_end_height: u64,
    max_offer_count: u64,
    max_units: u64,
) -> String {
    domain_hash(
        "MONERO-ATOMIC-LANE-THROTTLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_key),
            HashPart::Str(maker_id),
            HashPart::Int(window_start_height as i128),
            HashPart::Int(window_end_height as i128),
            HashPart::Int(max_offer_count as i128),
            HashPart::Int(max_units as i128),
        ],
        32,
    )
}

fn lane_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

fn empty_root(label: &str) -> String {
    domain_hash(
        "MONERO-ATOMIC-LANE-EMPTY-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

fn map_root<T, F>(domain: &str, values: &BTreeMap<String, T>, record_fn: F) -> String
where
    F: Fn(&T) -> Value,
{
    let records: Vec<Value> = values
        .iter()
        .map(|(id, value)| {
            json!({
                "id": id,
                "record": record_fn(value),
            })
        })
        .collect();
    lane_payload_root(domain, &json!(records))
}

fn validate_map<T, F>(
    label: &str,
    values: &BTreeMap<String, T>,
    validate_fn: F,
) -> MoneroAtomicLiquidityLaneResult<()>
where
    F: Fn(&T) -> MoneroAtomicLiquidityLaneResult<String>,
{
    for (id, value) in values {
        let root = validate_fn(value)?;
        ensure_non_empty(label, id)?;
        ensure_non_empty(label, &root)?;
    }
    Ok(())
}

fn ratio_bps(numerator: u64, denominator: u64) -> MoneroAtomicLiquidityLaneResult<u64> {
    ensure_positive("ratio.denominator", denominator)?;
    let scaled = (numerator as u128).saturating_mul(MONERO_ATOMIC_LIQUIDITY_LANE_MAX_BPS as u128);
    let value = scaled / denominator as u128;
    if value > u64::MAX as u128 {
        return Err("ratio overflows u64".to_string());
    }
    Ok(value as u64)
}

fn ensure_non_empty(label: &str, value: &str) -> MoneroAtomicLiquidityLaneResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{} must be non-empty", label));
    }
    Ok(())
}

fn ensure_positive(label: &str, value: u64) -> MoneroAtomicLiquidityLaneResult<()> {
    if value == 0 {
        return Err(format!("{} must be positive", label));
    }
    Ok(())
}

fn ensure_usize_positive(label: &str, value: usize) -> MoneroAtomicLiquidityLaneResult<()> {
    if value == 0 {
        return Err(format!("{} must be positive", label));
    }
    Ok(())
}

fn ensure_bps(label: &str, value: u64) -> MoneroAtomicLiquidityLaneResult<()> {
    if value > MONERO_ATOMIC_LIQUIDITY_LANE_MAX_BPS {
        return Err(format!("{} exceeds basis point maximum", label));
    }
    Ok(())
}

fn ensure_len(label: &str, value: usize, max: usize) -> MoneroAtomicLiquidityLaneResult<()> {
    if value > max {
        return Err(format!("{} exceeds maximum size", label));
    }
    Ok(())
}
