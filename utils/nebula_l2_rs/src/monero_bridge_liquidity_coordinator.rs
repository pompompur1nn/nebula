use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash as stable_hash_hex, HashPart},
    CHAIN_ID,
};

pub type MoneroBridgeLiquidityCoordinatorResult<T> = Result<T, String>;

pub const MONERO_BRIDGE_LIQUIDITY_COORDINATOR_PROTOCOL_VERSION: &str =
    "nebula-monero-bridge-liquidity-coordinator-v1";
pub const MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEVNET_NETWORK: &str = "monero-devnet";
pub const MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEVNET_ASSET_ID: &str = "xmr-devnet";
pub const MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEVNET_WRAPPED_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_BRIDGE_LIQUIDITY_COORDINATOR_MAX_BPS: u64 = 10_000;
pub const MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEFAULT_MIN_WATCHTOWER_WEIGHT: u64 = 3;
pub const MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEFAULT_AUCTION_TTL_BLOCKS: u64 = 12;
pub const MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEFAULT_ROUTE_TTL_BLOCKS: u64 = 96;
pub const MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEFAULT_REPLENISHMENT_TTL_BLOCKS: u64 = 720;
pub const MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEFAULT_REBATE_TTL_BLOCKS: u64 = 240;
pub const MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEFAULT_ALERT_TTL_BLOCKS: u64 = 180;
pub const MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEFAULT_CIRCUIT_BREAKER_TTL_BLOCKS: u64 = 72;
pub const MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 8_000;
pub const MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEFAULT_WARNING_COVERAGE_BPS: u64 = 9_900;
pub const MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEFAULT_CRITICAL_COVERAGE_BPS: u64 = 9_500;
pub const MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEFAULT_HALT_COVERAGE_BPS: u64 = 9_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityMakerStatus {
    Candidate,
    Active,
    Constrained,
    Paused,
    Suspended,
    Retired,
}

impl LiquidityMakerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::Constrained => "constrained",
            Self::Paused => "paused",
            Self::Suspended => "suspended",
            Self::Retired => "retired",
        }
    }

    pub fn is_usable(self) -> bool {
        matches!(self, Self::Active | Self::Constrained)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryCommitmentStatus {
    Draft,
    Posted,
    Attested,
    Locked,
    Consuming,
    Spent,
    Disputed,
    Expired,
    Revoked,
}

impl InventoryCommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Posted => "posted",
            Self::Attested => "attested",
            Self::Locked => "locked",
            Self::Consuming => "consuming",
            Self::Spent => "spent",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn is_available(self) -> bool {
        matches!(
            self,
            Self::Posted | Self::Attested | Self::Locked | Self::Consuming
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalAuctionStatus {
    Open,
    Clearing,
    Awarded,
    Settling,
    Settled,
    Failed,
    Cancelled,
    Expired,
}

impl WithdrawalAuctionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Clearing => "clearing",
            Self::Awarded => "awarded",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(self, Self::Open | Self::Clearing)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalBidStatus {
    Open,
    Eligible,
    Awarded,
    Rejected,
    Filled,
    Slashed,
    Expired,
}

impl WithdrawalBidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Eligible => "eligible",
            Self::Awarded => "awarded",
            Self::Rejected => "rejected",
            Self::Filled => "filled",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Open | Self::Eligible | Self::Awarded)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementRouteKind {
    HotMaker,
    BatchMaker,
    AtomicNetting,
    PrivacyDelayed,
    EmergencyReserve,
}

impl SettlementRouteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HotMaker => "hot_maker",
            Self::BatchMaker => "batch_maker",
            Self::AtomicNetting => "atomic_netting",
            Self::PrivacyDelayed => "privacy_delayed",
            Self::EmergencyReserve => "emergency_reserve",
        }
    }

    pub fn base_priority(self) -> u64 {
        match self {
            Self::EmergencyReserve => 0,
            Self::HotMaker => 1,
            Self::AtomicNetting => 2,
            Self::PrivacyDelayed => 3,
            Self::BatchMaker => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementRouteStatus {
    Planned,
    Reserved,
    WatchtowerApproved,
    Submitted,
    Confirming,
    Settled,
    Cancelled,
    Failed,
    Expired,
}

impl SettlementRouteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Reserved => "reserved",
            Self::WatchtowerApproved => "watchtower_approved",
            Self::Submitted => "submitted",
            Self::Confirming => "confirming",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
            Self::Expired => "expired",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Planned
                | Self::Reserved
                | Self::WatchtowerApproved
                | Self::Submitted
                | Self::Confirming
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplenishmentScheduleStatus {
    Planned,
    Funding,
    InFlight,
    Confirming,
    Complete,
    Deferred,
    Cancelled,
    Expired,
}

impl ReplenishmentScheduleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Funding => "funding",
            Self::InFlight => "in_flight",
            Self::Confirming => "confirming",
            Self::Complete => "complete",
            Self::Deferred => "deferred",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LowFeeRebateStatus {
    Reserved,
    Applied,
    Settled,
    Reclaimed,
    Expired,
}

impl LowFeeRebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Settled => "settled",
            Self::Reclaimed => "reclaimed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveAlertSeverity {
    Info,
    Warning,
    Critical,
    Halt,
}

impl ReserveAlertSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
            Self::Halt => "halt",
        }
    }

    pub fn priority(self) -> u64 {
        match self {
            Self::Halt => 0,
            Self::Critical => 1,
            Self::Warning => 2,
            Self::Info => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveAlertStatus {
    Open,
    Acknowledged,
    Mitigating,
    Resolved,
    Expired,
}

impl ReserveAlertStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Acknowledged => "acknowledged",
            Self::Mitigating => "mitigating",
            Self::Resolved => "resolved",
            Self::Expired => "expired",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(self, Self::Open | Self::Acknowledged | Self::Mitigating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchtowerReceiptStatus {
    Observed,
    QuorumMet,
    Challenged,
    Superseded,
    Expired,
}

impl WatchtowerReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::QuorumMet => "quorum_met",
            Self::Challenged => "challenged",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
        }
    }

    pub fn is_usable(self) -> bool {
        matches!(self, Self::Observed | Self::QuorumMet)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitBreakerScope {
    Global,
    Maker,
    Auction,
    Route,
    Rebate,
    Replenishment,
}

impl CircuitBreakerScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Maker => "maker",
            Self::Auction => "auction",
            Self::Route => "route",
            Self::Rebate => "rebate",
            Self::Replenishment => "replenishment",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitBreakerMode {
    Observe,
    ThrottleAuctions,
    MakerOnly,
    ReplenishOnly,
    HaltWithdrawals,
    HaltAll,
}

impl CircuitBreakerMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::ThrottleAuctions => "throttle_auctions",
            Self::MakerOnly => "maker_only",
            Self::ReplenishOnly => "replenish_only",
            Self::HaltWithdrawals => "halt_withdrawals",
            Self::HaltAll => "halt_all",
        }
    }

    pub fn halts_withdrawals(self) -> bool {
        matches!(self, Self::HaltWithdrawals | Self::HaltAll)
    }

    pub fn halts_all(self) -> bool {
        matches!(self, Self::HaltAll)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitBreakerStatus {
    Armed,
    Triggered,
    CoolingDown,
    Cleared,
    Expired,
}

impl CircuitBreakerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::Triggered => "triggered",
            Self::CoolingDown => "cooling_down",
            Self::Cleared => "cleared",
            Self::Expired => "expired",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Armed | Self::Triggered | Self::CoolingDown)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroBridgeLiquidityCoordinatorConfig {
    pub network: String,
    pub asset_id: String,
    pub wrapped_asset_id: String,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_watchtower_quorum_weight: u64,
    pub auction_ttl_blocks: u64,
    pub route_ttl_blocks: u64,
    pub replenishment_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub reserve_warning_coverage_bps: u64,
    pub reserve_critical_coverage_bps: u64,
    pub reserve_halt_coverage_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub max_rebate_units_per_withdrawal: u64,
    pub max_auction_amount_piconero: u64,
    pub max_route_fee_bps: u64,
    pub privacy_delay_blocks: u64,
    pub metadata: Value,
}

impl Default for MoneroBridgeLiquidityCoordinatorConfig {
    fn default() -> Self {
        Self {
            network: MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEVNET_NETWORK.to_string(),
            asset_id: MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEVNET_ASSET_ID.to_string(),
            wrapped_asset_id: MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEVNET_WRAPPED_ASSET_ID
                .to_string(),
            fee_asset_id: MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEVNET_FEE_ASSET_ID.to_string(),
            min_pq_security_bits: MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEFAULT_MIN_PQ_SECURITY_BITS,
            min_watchtower_quorum_weight:
                MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEFAULT_MIN_WATCHTOWER_WEIGHT,
            auction_ttl_blocks: MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEFAULT_AUCTION_TTL_BLOCKS,
            route_ttl_blocks: MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEFAULT_ROUTE_TTL_BLOCKS,
            replenishment_ttl_blocks:
                MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEFAULT_REPLENISHMENT_TTL_BLOCKS,
            rebate_ttl_blocks: MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEFAULT_REBATE_TTL_BLOCKS,
            reserve_warning_coverage_bps:
                MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEFAULT_WARNING_COVERAGE_BPS,
            reserve_critical_coverage_bps:
                MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEFAULT_CRITICAL_COVERAGE_BPS,
            reserve_halt_coverage_bps:
                MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEFAULT_HALT_COVERAGE_BPS,
            low_fee_rebate_bps: MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEFAULT_LOW_FEE_REBATE_BPS,
            max_rebate_units_per_withdrawal: 50_000,
            max_auction_amount_piconero: 50_000_000_000_000,
            max_route_fee_bps: 90,
            privacy_delay_blocks: 8,
            metadata: json!({"profile": "devnet"}),
        }
    }
}

impl MoneroBridgeLiquidityCoordinatorConfig {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_bridge_liquidity_coordinator_config",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_LIQUIDITY_COORDINATOR_PROTOCOL_VERSION,
            "network": self.network,
            "asset_id": self.asset_id,
            "wrapped_asset_id": self.wrapped_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_watchtower_quorum_weight": self.min_watchtower_quorum_weight,
            "auction_ttl_blocks": self.auction_ttl_blocks,
            "route_ttl_blocks": self.route_ttl_blocks,
            "replenishment_ttl_blocks": self.replenishment_ttl_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "reserve_warning_coverage_bps": self.reserve_warning_coverage_bps,
            "reserve_critical_coverage_bps": self.reserve_critical_coverage_bps,
            "reserve_halt_coverage_bps": self.reserve_halt_coverage_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "max_rebate_units_per_withdrawal": self.max_rebate_units_per_withdrawal,
            "max_auction_amount_piconero": self.max_auction_amount_piconero,
            "max_route_fee_bps": self.max_route_fee_bps,
            "privacy_delay_blocks": self.privacy_delay_blocks,
            "metadata": self.metadata,
        })
    }

    pub fn config_root(&self) -> String {
        coordinator_payload_root(
            "MONERO-BRIDGE-LIQUIDITY-COORDINATOR-CONFIG",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroBridgeLiquidityCoordinatorResult<String> {
        ensure_non_empty(&self.network, "config network")?;
        ensure_non_empty(&self.asset_id, "config asset id")?;
        ensure_non_empty(&self.wrapped_asset_id, "config wrapped asset id")?;
        ensure_non_empty(&self.fee_asset_id, "config fee asset id")?;
        ensure_positive(
            self.min_watchtower_quorum_weight,
            "config watchtower quorum",
        )?;
        ensure_positive(self.auction_ttl_blocks, "config auction ttl")?;
        ensure_positive(self.route_ttl_blocks, "config route ttl")?;
        ensure_positive(self.replenishment_ttl_blocks, "config replenishment ttl")?;
        ensure_bps(
            self.reserve_warning_coverage_bps,
            "config reserve warning coverage",
        )?;
        ensure_bps(
            self.reserve_critical_coverage_bps,
            "config reserve critical coverage",
        )?;
        ensure_bps(
            self.reserve_halt_coverage_bps,
            "config reserve halt coverage",
        )?;
        ensure_bps(self.low_fee_rebate_bps, "config low fee rebate")?;
        ensure_bps(self.max_route_fee_bps, "config max route fee")?;
        if self.reserve_warning_coverage_bps < self.reserve_critical_coverage_bps {
            return Err("warning coverage must be at least critical coverage".to_string());
        }
        if self.reserve_critical_coverage_bps < self.reserve_halt_coverage_bps {
            return Err("critical coverage must be at least halt coverage".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityMaker {
    pub maker_id: String,
    pub operator_id: String,
    pub label: String,
    pub network: String,
    pub settlement_address_root: String,
    pub view_key_commitment_root: String,
    pub pq_key_root: String,
    pub pq_scheme: String,
    pub pq_security_bits: u16,
    pub reputation_score: u64,
    pub max_fill_piconero: u64,
    pub max_fee_bps: u64,
    pub privacy_delay_blocks: u64,
    pub supported_route_kinds: BTreeSet<SettlementRouteKind>,
    pub status: LiquidityMakerStatus,
    pub metadata: Value,
}

impl LiquidityMaker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operator_id: impl Into<String>,
        label: impl Into<String>,
        network: impl Into<String>,
        settlement_address_material: impl Into<String>,
        view_key_commitment_material: impl Into<String>,
        pq_key_material: impl Into<String>,
        pq_scheme: impl Into<String>,
        pq_security_bits: u16,
        max_fill_piconero: u64,
        max_fee_bps: u64,
        privacy_delay_blocks: u64,
        supported_route_kinds: BTreeSet<SettlementRouteKind>,
        metadata: &Value,
    ) -> MoneroBridgeLiquidityCoordinatorResult<Self> {
        let operator_id = operator_id.into();
        let label = label.into();
        let network = network.into();
        let settlement_address_material = settlement_address_material.into();
        let view_key_commitment_material = view_key_commitment_material.into();
        let pq_key_material = pq_key_material.into();
        let pq_scheme = pq_scheme.into();
        ensure_non_empty(&operator_id, "maker operator id")?;
        ensure_non_empty(&label, "maker label")?;
        ensure_non_empty(&network, "maker network")?;
        ensure_non_empty(&settlement_address_material, "maker settlement address")?;
        ensure_non_empty(&view_key_commitment_material, "maker view key commitment")?;
        ensure_non_empty(&pq_key_material, "maker pq key")?;
        ensure_non_empty(&pq_scheme, "maker pq scheme")?;
        ensure_positive(max_fill_piconero, "maker max fill")?;
        ensure_bps(max_fee_bps, "maker max fee")?;
        if supported_route_kinds.is_empty() {
            return Err("maker must support at least one route kind".to_string());
        }
        let settlement_address_root = coordinator_string_root(
            "MONERO-BRIDGE-LIQUIDITY-MAKER-SETTLEMENT-ADDRESS",
            &settlement_address_material,
        );
        let view_key_commitment_root = coordinator_string_root(
            "MONERO-BRIDGE-LIQUIDITY-MAKER-VIEW-KEY-COMMITMENT",
            &view_key_commitment_material,
        );
        let pq_key_root =
            coordinator_string_root("MONERO-BRIDGE-LIQUIDITY-MAKER-PQ-KEY", &pq_key_material);
        let mut maker = Self {
            maker_id: String::new(),
            operator_id,
            label,
            network,
            settlement_address_root,
            view_key_commitment_root,
            pq_key_root,
            pq_scheme,
            pq_security_bits,
            reputation_score: 100,
            max_fill_piconero,
            max_fee_bps,
            privacy_delay_blocks,
            supported_route_kinds,
            status: LiquidityMakerStatus::Active,
            metadata: metadata.clone(),
        };
        maker.maker_id = monero_bridge_liquidity_maker_id(&maker.identity_record());
        maker.validate()?;
        Ok(maker)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_bridge_liquidity_maker_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_LIQUIDITY_COORDINATOR_PROTOCOL_VERSION,
            "operator_id": self.operator_id,
            "label": self.label,
            "network": self.network,
            "settlement_address_root": self.settlement_address_root,
            "pq_key_root": self.pq_key_root,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_bridge_liquidity_maker",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_LIQUIDITY_COORDINATOR_PROTOCOL_VERSION,
            "maker_id": self.maker_id,
            "operator_id": self.operator_id,
            "label": self.label,
            "network": self.network,
            "settlement_address_root": self.settlement_address_root,
            "view_key_commitment_root": self.view_key_commitment_root,
            "pq_key_root": self.pq_key_root,
            "pq_scheme": self.pq_scheme,
            "pq_security_bits": self.pq_security_bits,
            "reputation_score": self.reputation_score,
            "max_fill_piconero": self.max_fill_piconero,
            "max_fee_bps": self.max_fee_bps,
            "privacy_delay_blocks": self.privacy_delay_blocks,
            "supported_route_kinds": self.supported_route_kinds.iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
            "status": self.status.as_str(),
            "metadata": self.metadata,
        })
    }

    pub fn maker_root(&self) -> String {
        coordinator_payload_root(
            "MONERO-BRIDGE-LIQUIDITY-MAKER",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "maker_root",
            self.maker_root(),
        )
    }

    pub fn validate(&self) -> MoneroBridgeLiquidityCoordinatorResult<String> {
        ensure_non_empty(&self.maker_id, "maker id")?;
        ensure_non_empty(&self.operator_id, "maker operator id")?;
        ensure_non_empty(&self.label, "maker label")?;
        ensure_non_empty(&self.network, "maker network")?;
        ensure_non_empty(
            &self.settlement_address_root,
            "maker settlement address root",
        )?;
        ensure_non_empty(
            &self.view_key_commitment_root,
            "maker view key commitment root",
        )?;
        ensure_non_empty(&self.pq_key_root, "maker pq key root")?;
        ensure_non_empty(&self.pq_scheme, "maker pq scheme")?;
        ensure_positive(self.max_fill_piconero, "maker max fill")?;
        ensure_bps(self.max_fee_bps, "maker max fee")?;
        if self.supported_route_kinds.is_empty() {
            return Err("maker must support at least one route kind".to_string());
        }
        let computed = monero_bridge_liquidity_maker_id(&self.identity_record());
        if self.maker_id != computed {
            return Err("maker id mismatch".to_string());
        }
        Ok(self.maker_root())
    }

    pub fn supports(&self, route_kind: SettlementRouteKind) -> bool {
        self.supported_route_kinds.contains(&route_kind)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateInventoryCommitment {
    pub commitment_id: String,
    pub maker_id: String,
    pub network: String,
    pub asset_id: String,
    pub inventory_commitment_root: String,
    pub range_proof_root: String,
    pub nullifier_root: String,
    pub reserve_address_set_root: String,
    pub min_fill_piconero: u64,
    pub max_fill_piconero: u64,
    pub available_piconero: u64,
    pub reserved_piconero: u64,
    pub consumed_piconero: u64,
    pub fee_floor_piconero: u64,
    pub max_fee_bps: u64,
    pub privacy_delay_blocks: u64,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
    pub status: InventoryCommitmentStatus,
    pub metadata: Value,
}

impl PrivateInventoryCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        maker_id: impl Into<String>,
        network: impl Into<String>,
        asset_id: impl Into<String>,
        inventory_secret_material: impl Into<String>,
        range_proof_payload: &Value,
        nullifier_labels: &[String],
        reserve_address_labels: &[String],
        min_fill_piconero: u64,
        max_fill_piconero: u64,
        fee_floor_piconero: u64,
        max_fee_bps: u64,
        privacy_delay_blocks: u64,
        posted_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> MoneroBridgeLiquidityCoordinatorResult<Self> {
        let maker_id = maker_id.into();
        let network = network.into();
        let asset_id = asset_id.into();
        let inventory_secret_material = inventory_secret_material.into();
        ensure_non_empty(&maker_id, "inventory maker id")?;
        ensure_non_empty(&network, "inventory network")?;
        ensure_non_empty(&asset_id, "inventory asset id")?;
        ensure_non_empty(&inventory_secret_material, "inventory commitment material")?;
        ensure_positive(max_fill_piconero, "inventory max fill")?;
        ensure_bps(max_fee_bps, "inventory max fee")?;
        ensure_expiry(posted_at_height, expires_at_height, "inventory commitment")?;
        if min_fill_piconero > max_fill_piconero {
            return Err("inventory min fill exceeds max fill".to_string());
        }
        let inventory_commitment_root = coordinator_string_root(
            "MONERO-BRIDGE-LIQUIDITY-PRIVATE-INVENTORY",
            &inventory_secret_material,
        );
        let range_proof_root = coordinator_payload_root(
            "MONERO-BRIDGE-LIQUIDITY-INVENTORY-RANGE-PROOF",
            range_proof_payload,
        );
        let nullifier_root = coordinator_string_set_root(
            "MONERO-BRIDGE-LIQUIDITY-INVENTORY-NULLIFIERS",
            nullifier_labels,
        );
        let reserve_address_set_root = coordinator_string_set_root(
            "MONERO-BRIDGE-LIQUIDITY-INVENTORY-RESERVE-ADDRESSES",
            reserve_address_labels,
        );
        let mut commitment = Self {
            commitment_id: String::new(),
            maker_id,
            network,
            asset_id,
            inventory_commitment_root,
            range_proof_root,
            nullifier_root,
            reserve_address_set_root,
            min_fill_piconero,
            max_fill_piconero,
            available_piconero: max_fill_piconero,
            reserved_piconero: 0,
            consumed_piconero: 0,
            fee_floor_piconero,
            max_fee_bps,
            privacy_delay_blocks,
            posted_at_height,
            expires_at_height,
            status: InventoryCommitmentStatus::Posted,
            metadata: metadata.clone(),
        };
        commitment.commitment_id =
            monero_bridge_liquidity_inventory_commitment_id(&commitment.identity_record());
        commitment.validate()?;
        Ok(commitment)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_bridge_liquidity_inventory_commitment_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_LIQUIDITY_COORDINATOR_PROTOCOL_VERSION,
            "maker_id": self.maker_id,
            "network": self.network,
            "asset_id": self.asset_id,
            "inventory_commitment_root": self.inventory_commitment_root,
            "range_proof_root": self.range_proof_root,
            "nullifier_root": self.nullifier_root,
            "posted_at_height": self.posted_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_bridge_liquidity_inventory_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_LIQUIDITY_COORDINATOR_PROTOCOL_VERSION,
            "commitment_id": self.commitment_id,
            "maker_id": self.maker_id,
            "network": self.network,
            "asset_id": self.asset_id,
            "inventory_commitment_root": self.inventory_commitment_root,
            "range_proof_root": self.range_proof_root,
            "nullifier_root": self.nullifier_root,
            "reserve_address_set_root": self.reserve_address_set_root,
            "min_fill_piconero": self.min_fill_piconero,
            "max_fill_piconero": self.max_fill_piconero,
            "available_piconero": self.available_piconero,
            "reserved_piconero": self.reserved_piconero,
            "consumed_piconero": self.consumed_piconero,
            "fee_floor_piconero": self.fee_floor_piconero,
            "max_fee_bps": self.max_fee_bps,
            "privacy_delay_blocks": self.privacy_delay_blocks,
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "metadata": self.metadata,
        })
    }

    pub fn commitment_root(&self) -> String {
        coordinator_payload_root(
            "MONERO-BRIDGE-LIQUIDITY-INVENTORY-COMMITMENT",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "commitment_root",
            self.commitment_root(),
        )
    }

    pub fn remaining_piconero(&self) -> u64 {
        self.available_piconero
            .saturating_sub(self.reserved_piconero)
            .saturating_sub(self.consumed_piconero)
    }

    pub fn reserve(
        &mut self,
        amount_piconero: u64,
    ) -> MoneroBridgeLiquidityCoordinatorResult<String> {
        ensure_positive(amount_piconero, "inventory reserve amount")?;
        if !self.status.is_available() {
            return Err("inventory commitment is not available".to_string());
        }
        if self.remaining_piconero() < amount_piconero {
            return Err("inventory commitment has insufficient available units".to_string());
        }
        self.reserved_piconero = self.reserved_piconero.saturating_add(amount_piconero);
        self.status = InventoryCommitmentStatus::Locked;
        self.validate()
    }

    pub fn consume(
        &mut self,
        amount_piconero: u64,
    ) -> MoneroBridgeLiquidityCoordinatorResult<String> {
        ensure_positive(amount_piconero, "inventory consume amount")?;
        if self.reserved_piconero < amount_piconero {
            return Err("inventory consume exceeds reserved units".to_string());
        }
        self.reserved_piconero = self.reserved_piconero.saturating_sub(amount_piconero);
        self.consumed_piconero = self.consumed_piconero.saturating_add(amount_piconero);
        self.status = if self.remaining_piconero() == 0 {
            InventoryCommitmentStatus::Spent
        } else {
            InventoryCommitmentStatus::Consuming
        };
        self.validate()
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height && self.status.is_available() {
            self.status = InventoryCommitmentStatus::Expired;
        }
    }

    pub fn validate(&self) -> MoneroBridgeLiquidityCoordinatorResult<String> {
        ensure_non_empty(&self.commitment_id, "inventory commitment id")?;
        ensure_non_empty(&self.maker_id, "inventory maker id")?;
        ensure_non_empty(&self.network, "inventory network")?;
        ensure_non_empty(&self.asset_id, "inventory asset id")?;
        ensure_non_empty(&self.inventory_commitment_root, "inventory commitment root")?;
        ensure_non_empty(&self.range_proof_root, "inventory range proof root")?;
        ensure_non_empty(&self.nullifier_root, "inventory nullifier root")?;
        ensure_non_empty(
            &self.reserve_address_set_root,
            "inventory reserve address set root",
        )?;
        ensure_positive(self.max_fill_piconero, "inventory max fill")?;
        ensure_bps(self.max_fee_bps, "inventory max fee")?;
        ensure_expiry(
            self.posted_at_height,
            self.expires_at_height,
            "inventory commitment",
        )?;
        if self.min_fill_piconero > self.max_fill_piconero {
            return Err("inventory min fill exceeds max fill".to_string());
        }
        if self
            .reserved_piconero
            .saturating_add(self.consumed_piconero)
            > self.available_piconero
        {
            return Err("inventory accounting exceeds available units".to_string());
        }
        let computed = monero_bridge_liquidity_inventory_commitment_id(&self.identity_record());
        if self.commitment_id != computed {
            return Err("inventory commitment id mismatch".to_string());
        }
        Ok(self.commitment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalBid {
    pub bid_id: String,
    pub auction_id: String,
    pub maker_id: String,
    pub commitment_id: String,
    pub route_kind: SettlementRouteKind,
    pub fill_piconero: u64,
    pub fee_piconero: u64,
    pub fee_bps: u64,
    pub privacy_delay_blocks: u64,
    pub priority_score: u64,
    pub inventory_root: String,
    pub pq_signature_root: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub status: WithdrawalBidStatus,
}

impl WithdrawalBid {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: impl Into<String>,
        maker_id: impl Into<String>,
        commitment_id: impl Into<String>,
        route_kind: SettlementRouteKind,
        fill_piconero: u64,
        fee_piconero: u64,
        fee_bps: u64,
        privacy_delay_blocks: u64,
        inventory_root: impl Into<String>,
        pq_signature_payload: &Value,
        submitted_at_height: u64,
        expires_at_height: u64,
    ) -> MoneroBridgeLiquidityCoordinatorResult<Self> {
        let auction_id = auction_id.into();
        let maker_id = maker_id.into();
        let commitment_id = commitment_id.into();
        let inventory_root = inventory_root.into();
        ensure_non_empty(&auction_id, "withdrawal bid auction id")?;
        ensure_non_empty(&maker_id, "withdrawal bid maker id")?;
        ensure_non_empty(&commitment_id, "withdrawal bid commitment id")?;
        ensure_non_empty(&inventory_root, "withdrawal bid inventory root")?;
        ensure_positive(fill_piconero, "withdrawal bid fill")?;
        ensure_bps(fee_bps, "withdrawal bid fee")?;
        ensure_expiry(submitted_at_height, expires_at_height, "withdrawal bid")?;
        let pq_signature_root = coordinator_payload_root(
            "MONERO-BRIDGE-LIQUIDITY-WITHDRAWAL-BID-PQ-SIGNATURE",
            pq_signature_payload,
        );
        let priority_score = route_kind
            .base_priority()
            .saturating_mul(1_000_000_000)
            .saturating_add(fee_bps.saturating_mul(1_000_000))
            .saturating_add(privacy_delay_blocks.saturating_mul(1_000))
            .saturating_add(fee_piconero);
        let mut bid = Self {
            bid_id: String::new(),
            auction_id,
            maker_id,
            commitment_id,
            route_kind,
            fill_piconero,
            fee_piconero,
            fee_bps,
            privacy_delay_blocks,
            priority_score,
            inventory_root,
            pq_signature_root,
            submitted_at_height,
            expires_at_height,
            status: WithdrawalBidStatus::Open,
        };
        bid.bid_id = monero_bridge_liquidity_withdrawal_bid_id(&bid.identity_record());
        bid.validate()?;
        Ok(bid)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_bridge_liquidity_withdrawal_bid_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_LIQUIDITY_COORDINATOR_PROTOCOL_VERSION,
            "auction_id": self.auction_id,
            "maker_id": self.maker_id,
            "commitment_id": self.commitment_id,
            "route_kind": self.route_kind.as_str(),
            "fill_piconero": self.fill_piconero,
            "fee_piconero": self.fee_piconero,
            "inventory_root": self.inventory_root,
            "submitted_at_height": self.submitted_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_bridge_liquidity_withdrawal_bid",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_LIQUIDITY_COORDINATOR_PROTOCOL_VERSION,
            "bid_id": self.bid_id,
            "auction_id": self.auction_id,
            "maker_id": self.maker_id,
            "commitment_id": self.commitment_id,
            "route_kind": self.route_kind.as_str(),
            "fill_piconero": self.fill_piconero,
            "fee_piconero": self.fee_piconero,
            "fee_bps": self.fee_bps,
            "privacy_delay_blocks": self.privacy_delay_blocks,
            "priority_score": self.priority_score,
            "inventory_root": self.inventory_root,
            "pq_signature_root": self.pq_signature_root,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn bid_root(&self) -> String {
        coordinator_payload_root(
            "MONERO-BRIDGE-LIQUIDITY-WITHDRAWAL-BID",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "bid_root",
            self.bid_root(),
        )
    }

    pub fn mark_awarded(&mut self) -> MoneroBridgeLiquidityCoordinatorResult<String> {
        if !self.status.is_live() {
            return Err("withdrawal bid is not live".to_string());
        }
        self.status = WithdrawalBidStatus::Awarded;
        self.validate()
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height && self.status.is_live() {
            self.status = WithdrawalBidStatus::Expired;
        }
    }

    pub fn validate(&self) -> MoneroBridgeLiquidityCoordinatorResult<String> {
        ensure_non_empty(&self.bid_id, "withdrawal bid id")?;
        ensure_non_empty(&self.auction_id, "withdrawal bid auction id")?;
        ensure_non_empty(&self.maker_id, "withdrawal bid maker id")?;
        ensure_non_empty(&self.commitment_id, "withdrawal bid commitment id")?;
        ensure_non_empty(&self.inventory_root, "withdrawal bid inventory root")?;
        ensure_non_empty(&self.pq_signature_root, "withdrawal bid pq signature root")?;
        ensure_positive(self.fill_piconero, "withdrawal bid fill")?;
        ensure_bps(self.fee_bps, "withdrawal bid fee")?;
        ensure_expiry(
            self.submitted_at_height,
            self.expires_at_height,
            "withdrawal bid",
        )?;
        let computed = monero_bridge_liquidity_withdrawal_bid_id(&self.identity_record());
        if self.bid_id != computed {
            return Err("withdrawal bid id mismatch".to_string());
        }
        Ok(self.bid_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalAuction {
    pub auction_id: String,
    pub withdrawal_id: String,
    pub recipient_commitment_root: String,
    pub amount_piconero: u64,
    pub max_fee_piconero: u64,
    pub max_fee_bps: u64,
    pub route_kind_preference: Vec<SettlementRouteKind>,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub bid_root: String,
    pub awarded_bid_id: String,
    pub status: WithdrawalAuctionStatus,
    pub metadata: Value,
}

impl WithdrawalAuction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        withdrawal_id: impl Into<String>,
        recipient_commitment_material: impl Into<String>,
        amount_piconero: u64,
        max_fee_piconero: u64,
        max_fee_bps: u64,
        route_kind_preference: Vec<SettlementRouteKind>,
        opened_at_height: u64,
        ttl_blocks: u64,
        metadata: &Value,
    ) -> MoneroBridgeLiquidityCoordinatorResult<Self> {
        let withdrawal_id = withdrawal_id.into();
        let recipient_commitment_material = recipient_commitment_material.into();
        ensure_non_empty(&withdrawal_id, "withdrawal auction withdrawal id")?;
        ensure_non_empty(
            &recipient_commitment_material,
            "withdrawal auction recipient commitment",
        )?;
        ensure_positive(amount_piconero, "withdrawal auction amount")?;
        ensure_bps(max_fee_bps, "withdrawal auction max fee")?;
        if route_kind_preference.is_empty() {
            return Err("withdrawal auction requires route preference".to_string());
        }
        let recipient_commitment_root = coordinator_string_root(
            "MONERO-BRIDGE-LIQUIDITY-WITHDRAWAL-RECIPIENT",
            &recipient_commitment_material,
        );
        let mut auction = Self {
            auction_id: String::new(),
            withdrawal_id,
            recipient_commitment_root,
            amount_piconero,
            max_fee_piconero,
            max_fee_bps,
            route_kind_preference,
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(ttl_blocks.max(1)),
            bid_root: coordinator_empty_root("MONERO-BRIDGE-LIQUIDITY-AUCTION-BIDS"),
            awarded_bid_id: String::new(),
            status: WithdrawalAuctionStatus::Open,
            metadata: metadata.clone(),
        };
        auction.auction_id =
            monero_bridge_liquidity_withdrawal_auction_id(&auction.identity_record());
        auction.validate()?;
        Ok(auction)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_bridge_liquidity_withdrawal_auction_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_LIQUIDITY_COORDINATOR_PROTOCOL_VERSION,
            "withdrawal_id": self.withdrawal_id,
            "recipient_commitment_root": self.recipient_commitment_root,
            "amount_piconero": self.amount_piconero,
            "opened_at_height": self.opened_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_bridge_liquidity_withdrawal_auction",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_LIQUIDITY_COORDINATOR_PROTOCOL_VERSION,
            "auction_id": self.auction_id,
            "withdrawal_id": self.withdrawal_id,
            "recipient_commitment_root": self.recipient_commitment_root,
            "amount_piconero": self.amount_piconero,
            "max_fee_piconero": self.max_fee_piconero,
            "max_fee_bps": self.max_fee_bps,
            "route_kind_preference": self.route_kind_preference.iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "bid_root": self.bid_root,
            "awarded_bid_id": self.awarded_bid_id,
            "status": self.status.as_str(),
            "metadata": self.metadata,
        })
    }

    pub fn auction_root(&self) -> String {
        coordinator_payload_root(
            "MONERO-BRIDGE-LIQUIDITY-WITHDRAWAL-AUCTION",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "auction_root",
            self.auction_root(),
        )
    }

    pub fn accepts_bid(&self, bid: &WithdrawalBid) -> bool {
        self.status.is_open()
            && self.auction_id == bid.auction_id
            && bid.fill_piconero >= self.amount_piconero
            && bid.fee_piconero <= self.max_fee_piconero
            && bid.fee_bps <= self.max_fee_bps
            && self.route_kind_preference.contains(&bid.route_kind)
            && bid.status.is_live()
    }

    pub fn award(
        &mut self,
        bid_id: &str,
        bid_root: &str,
    ) -> MoneroBridgeLiquidityCoordinatorResult<String> {
        ensure_non_empty(bid_id, "withdrawal auction awarded bid id")?;
        ensure_non_empty(bid_root, "withdrawal auction bid root")?;
        if !self.status.is_open() {
            return Err("withdrawal auction is not open".to_string());
        }
        self.awarded_bid_id = bid_id.to_string();
        self.bid_root = bid_root.to_string();
        self.status = WithdrawalAuctionStatus::Awarded;
        self.validate()
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height && self.status.is_open() {
            self.status = WithdrawalAuctionStatus::Expired;
        }
    }

    pub fn validate(&self) -> MoneroBridgeLiquidityCoordinatorResult<String> {
        ensure_non_empty(&self.auction_id, "withdrawal auction id")?;
        ensure_non_empty(&self.withdrawal_id, "withdrawal auction withdrawal id")?;
        ensure_non_empty(
            &self.recipient_commitment_root,
            "withdrawal auction recipient commitment root",
        )?;
        ensure_positive(self.amount_piconero, "withdrawal auction amount")?;
        ensure_bps(self.max_fee_bps, "withdrawal auction max fee")?;
        ensure_expiry(
            self.opened_at_height,
            self.expires_at_height,
            "withdrawal auction",
        )?;
        ensure_non_empty(&self.bid_root, "withdrawal auction bid root")?;
        if self.route_kind_preference.is_empty() {
            return Err("withdrawal auction route preference is empty".to_string());
        }
        let computed = monero_bridge_liquidity_withdrawal_auction_id(&self.identity_record());
        if self.auction_id != computed {
            return Err("withdrawal auction id mismatch".to_string());
        }
        Ok(self.auction_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementRoute {
    pub route_id: String,
    pub auction_id: String,
    pub withdrawal_id: String,
    pub maker_id: String,
    pub commitment_id: String,
    pub bid_id: String,
    pub route_kind: SettlementRouteKind,
    pub amount_piconero: u64,
    pub fee_piconero: u64,
    pub fee_bps: u64,
    pub rebate_id: String,
    pub watchtower_receipt_id: String,
    pub reserve_alert_id: String,
    pub private_inventory_root: String,
    pub settlement_plan_root: String,
    pub route_score: u64,
    pub release_not_before_height: u64,
    pub expires_at_height: u64,
    pub status: SettlementRouteStatus,
}

impl SettlementRoute {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction: &WithdrawalAuction,
        bid: &WithdrawalBid,
        settlement_plan_payload: &Value,
        release_not_before_height: u64,
        expires_at_height: u64,
    ) -> MoneroBridgeLiquidityCoordinatorResult<Self> {
        if auction.auction_id != bid.auction_id {
            return Err("settlement route auction and bid mismatch".to_string());
        }
        if !auction.accepts_bid(bid) && auction.awarded_bid_id != bid.bid_id {
            return Err("settlement route bid is not acceptable".to_string());
        }
        ensure_expiry(
            release_not_before_height,
            expires_at_height,
            "settlement route",
        )?;
        let settlement_plan_root = coordinator_payload_root(
            "MONERO-BRIDGE-LIQUIDITY-SETTLEMENT-PLAN",
            settlement_plan_payload,
        );
        let route_score = bid
            .priority_score
            .saturating_add(release_not_before_height.saturating_sub(auction.opened_at_height));
        let mut route = Self {
            route_id: String::new(),
            auction_id: auction.auction_id.clone(),
            withdrawal_id: auction.withdrawal_id.clone(),
            maker_id: bid.maker_id.clone(),
            commitment_id: bid.commitment_id.clone(),
            bid_id: bid.bid_id.clone(),
            route_kind: bid.route_kind,
            amount_piconero: auction.amount_piconero,
            fee_piconero: bid.fee_piconero,
            fee_bps: bid.fee_bps,
            rebate_id: String::new(),
            watchtower_receipt_id: String::new(),
            reserve_alert_id: String::new(),
            private_inventory_root: bid.inventory_root.clone(),
            settlement_plan_root,
            route_score,
            release_not_before_height,
            expires_at_height,
            status: SettlementRouteStatus::Planned,
        };
        route.route_id = monero_bridge_liquidity_settlement_route_id(&route.identity_record());
        route.validate()?;
        Ok(route)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_bridge_liquidity_settlement_route_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_LIQUIDITY_COORDINATOR_PROTOCOL_VERSION,
            "auction_id": self.auction_id,
            "withdrawal_id": self.withdrawal_id,
            "maker_id": self.maker_id,
            "commitment_id": self.commitment_id,
            "bid_id": self.bid_id,
            "route_kind": self.route_kind.as_str(),
            "amount_piconero": self.amount_piconero,
            "settlement_plan_root": self.settlement_plan_root,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_bridge_liquidity_settlement_route",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_LIQUIDITY_COORDINATOR_PROTOCOL_VERSION,
            "route_id": self.route_id,
            "auction_id": self.auction_id,
            "withdrawal_id": self.withdrawal_id,
            "maker_id": self.maker_id,
            "commitment_id": self.commitment_id,
            "bid_id": self.bid_id,
            "route_kind": self.route_kind.as_str(),
            "amount_piconero": self.amount_piconero,
            "fee_piconero": self.fee_piconero,
            "fee_bps": self.fee_bps,
            "rebate_id": self.rebate_id,
            "watchtower_receipt_id": self.watchtower_receipt_id,
            "reserve_alert_id": self.reserve_alert_id,
            "private_inventory_root": self.private_inventory_root,
            "settlement_plan_root": self.settlement_plan_root,
            "route_score": self.route_score,
            "release_not_before_height": self.release_not_before_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn route_root(&self) -> String {
        coordinator_payload_root(
            "MONERO-BRIDGE-LIQUIDITY-SETTLEMENT-ROUTE",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "route_root",
            self.route_root(),
        )
    }

    pub fn attach_rebate(
        &mut self,
        rebate_id: &str,
    ) -> MoneroBridgeLiquidityCoordinatorResult<String> {
        ensure_non_empty(rebate_id, "settlement route rebate id")?;
        self.rebate_id = rebate_id.to_string();
        self.validate()
    }

    pub fn attach_watchtower_receipt(
        &mut self,
        receipt_id: &str,
    ) -> MoneroBridgeLiquidityCoordinatorResult<String> {
        ensure_non_empty(receipt_id, "settlement route watchtower receipt id")?;
        self.watchtower_receipt_id = receipt_id.to_string();
        self.status = SettlementRouteStatus::WatchtowerApproved;
        self.validate()
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height && self.status.is_live() {
            self.status = SettlementRouteStatus::Expired;
        }
    }

    pub fn validate(&self) -> MoneroBridgeLiquidityCoordinatorResult<String> {
        ensure_non_empty(&self.route_id, "settlement route id")?;
        ensure_non_empty(&self.auction_id, "settlement route auction id")?;
        ensure_non_empty(&self.withdrawal_id, "settlement route withdrawal id")?;
        ensure_non_empty(&self.maker_id, "settlement route maker id")?;
        ensure_non_empty(&self.commitment_id, "settlement route commitment id")?;
        ensure_non_empty(&self.bid_id, "settlement route bid id")?;
        ensure_non_empty(
            &self.private_inventory_root,
            "settlement route private inventory root",
        )?;
        ensure_non_empty(&self.settlement_plan_root, "settlement route plan root")?;
        ensure_positive(self.amount_piconero, "settlement route amount")?;
        ensure_bps(self.fee_bps, "settlement route fee")?;
        ensure_expiry(
            self.release_not_before_height,
            self.expires_at_height,
            "settlement route",
        )?;
        let computed = monero_bridge_liquidity_settlement_route_id(&self.identity_record());
        if self.route_id != computed {
            return Err("settlement route id mismatch".to_string());
        }
        Ok(self.route_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplenishmentSchedule {
    pub schedule_id: String,
    pub maker_id: String,
    pub asset_id: String,
    pub target_inventory_commitment_root: String,
    pub source_reserve_root: String,
    pub replenishment_amount_piconero: u64,
    pub min_confirmations: u64,
    pub planned_at_height: u64,
    pub not_before_height: u64,
    pub expires_at_height: u64,
    pub watchtower_receipt_id: String,
    pub status: ReplenishmentScheduleStatus,
    pub metadata: Value,
}

impl ReplenishmentSchedule {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        maker_id: impl Into<String>,
        asset_id: impl Into<String>,
        target_inventory_commitment_root: impl Into<String>,
        source_reserve_material: impl Into<String>,
        replenishment_amount_piconero: u64,
        min_confirmations: u64,
        planned_at_height: u64,
        not_before_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> MoneroBridgeLiquidityCoordinatorResult<Self> {
        let maker_id = maker_id.into();
        let asset_id = asset_id.into();
        let target_inventory_commitment_root = target_inventory_commitment_root.into();
        let source_reserve_material = source_reserve_material.into();
        ensure_non_empty(&maker_id, "replenishment maker id")?;
        ensure_non_empty(&asset_id, "replenishment asset id")?;
        ensure_non_empty(
            &target_inventory_commitment_root,
            "replenishment target inventory root",
        )?;
        ensure_non_empty(&source_reserve_material, "replenishment source reserve")?;
        ensure_positive(replenishment_amount_piconero, "replenishment amount")?;
        ensure_expiry(
            planned_at_height,
            expires_at_height,
            "replenishment schedule",
        )?;
        if not_before_height < planned_at_height {
            return Err("replenishment not-before precedes plan height".to_string());
        }
        let source_reserve_root = coordinator_string_root(
            "MONERO-BRIDGE-LIQUIDITY-REPLENISHMENT-SOURCE-RESERVE",
            &source_reserve_material,
        );
        let mut schedule = Self {
            schedule_id: String::new(),
            maker_id,
            asset_id,
            target_inventory_commitment_root,
            source_reserve_root,
            replenishment_amount_piconero,
            min_confirmations,
            planned_at_height,
            not_before_height,
            expires_at_height,
            watchtower_receipt_id: String::new(),
            status: ReplenishmentScheduleStatus::Planned,
            metadata: metadata.clone(),
        };
        schedule.schedule_id =
            monero_bridge_liquidity_replenishment_schedule_id(&schedule.identity_record());
        schedule.validate()?;
        Ok(schedule)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_bridge_liquidity_replenishment_schedule_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_LIQUIDITY_COORDINATOR_PROTOCOL_VERSION,
            "maker_id": self.maker_id,
            "asset_id": self.asset_id,
            "target_inventory_commitment_root": self.target_inventory_commitment_root,
            "source_reserve_root": self.source_reserve_root,
            "replenishment_amount_piconero": self.replenishment_amount_piconero,
            "planned_at_height": self.planned_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_bridge_liquidity_replenishment_schedule",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_LIQUIDITY_COORDINATOR_PROTOCOL_VERSION,
            "schedule_id": self.schedule_id,
            "maker_id": self.maker_id,
            "asset_id": self.asset_id,
            "target_inventory_commitment_root": self.target_inventory_commitment_root,
            "source_reserve_root": self.source_reserve_root,
            "replenishment_amount_piconero": self.replenishment_amount_piconero,
            "min_confirmations": self.min_confirmations,
            "planned_at_height": self.planned_at_height,
            "not_before_height": self.not_before_height,
            "expires_at_height": self.expires_at_height,
            "watchtower_receipt_id": self.watchtower_receipt_id,
            "status": self.status.as_str(),
            "metadata": self.metadata,
        })
    }

    pub fn schedule_root(&self) -> String {
        coordinator_payload_root(
            "MONERO-BRIDGE-LIQUIDITY-REPLENISHMENT-SCHEDULE",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "schedule_root",
            self.schedule_root(),
        )
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height
            && !matches!(
                self.status,
                ReplenishmentScheduleStatus::Complete
                    | ReplenishmentScheduleStatus::Cancelled
                    | ReplenishmentScheduleStatus::Expired
            )
        {
            self.status = ReplenishmentScheduleStatus::Expired;
        }
    }

    pub fn validate(&self) -> MoneroBridgeLiquidityCoordinatorResult<String> {
        ensure_non_empty(&self.schedule_id, "replenishment schedule id")?;
        ensure_non_empty(&self.maker_id, "replenishment maker id")?;
        ensure_non_empty(&self.asset_id, "replenishment asset id")?;
        ensure_non_empty(
            &self.target_inventory_commitment_root,
            "replenishment target inventory root",
        )?;
        ensure_non_empty(
            &self.source_reserve_root,
            "replenishment source reserve root",
        )?;
        ensure_positive(self.replenishment_amount_piconero, "replenishment amount")?;
        ensure_expiry(
            self.planned_at_height,
            self.expires_at_height,
            "replenishment schedule",
        )?;
        if self.not_before_height < self.planned_at_height {
            return Err("replenishment not-before precedes plan height".to_string());
        }
        let computed = monero_bridge_liquidity_replenishment_schedule_id(&self.identity_record());
        if self.schedule_id != computed {
            return Err("replenishment schedule id mismatch".to_string());
        }
        Ok(self.schedule_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub withdrawal_id: String,
    pub route_id: String,
    pub maker_id: String,
    pub fee_asset_id: String,
    pub gross_fee_piconero: u64,
    pub rebate_piconero: u64,
    pub rebate_bps: u64,
    pub budget_root: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub status: LowFeeRebateStatus,
}

impl LowFeeRebate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        withdrawal_id: impl Into<String>,
        route_id: impl Into<String>,
        maker_id: impl Into<String>,
        fee_asset_id: impl Into<String>,
        gross_fee_piconero: u64,
        rebate_bps: u64,
        max_rebate_piconero: u64,
        budget_payload: &Value,
        reserved_at_height: u64,
        expires_at_height: u64,
    ) -> MoneroBridgeLiquidityCoordinatorResult<Self> {
        let withdrawal_id = withdrawal_id.into();
        let route_id = route_id.into();
        let maker_id = maker_id.into();
        let fee_asset_id = fee_asset_id.into();
        ensure_non_empty(&withdrawal_id, "low fee rebate withdrawal id")?;
        ensure_non_empty(&route_id, "low fee rebate route id")?;
        ensure_non_empty(&maker_id, "low fee rebate maker id")?;
        ensure_non_empty(&fee_asset_id, "low fee rebate fee asset id")?;
        ensure_bps(rebate_bps, "low fee rebate bps")?;
        ensure_expiry(reserved_at_height, expires_at_height, "low fee rebate")?;
        let computed_rebate = gross_fee_piconero
            .saturating_mul(rebate_bps)
            .saturating_div(MONERO_BRIDGE_LIQUIDITY_COORDINATOR_MAX_BPS);
        let rebate_piconero = computed_rebate.min(max_rebate_piconero);
        let budget_root = coordinator_payload_root(
            "MONERO-BRIDGE-LIQUIDITY-LOW-FEE-REBATE-BUDGET",
            budget_payload,
        );
        let mut rebate = Self {
            rebate_id: String::new(),
            withdrawal_id,
            route_id,
            maker_id,
            fee_asset_id,
            gross_fee_piconero,
            rebate_piconero,
            rebate_bps,
            budget_root,
            reserved_at_height,
            expires_at_height,
            status: LowFeeRebateStatus::Reserved,
        };
        rebate.rebate_id = monero_bridge_liquidity_low_fee_rebate_id(&rebate.identity_record());
        rebate.validate()?;
        Ok(rebate)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_bridge_liquidity_low_fee_rebate_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_LIQUIDITY_COORDINATOR_PROTOCOL_VERSION,
            "withdrawal_id": self.withdrawal_id,
            "route_id": self.route_id,
            "maker_id": self.maker_id,
            "fee_asset_id": self.fee_asset_id,
            "budget_root": self.budget_root,
            "reserved_at_height": self.reserved_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_bridge_liquidity_low_fee_rebate",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_LIQUIDITY_COORDINATOR_PROTOCOL_VERSION,
            "rebate_id": self.rebate_id,
            "withdrawal_id": self.withdrawal_id,
            "route_id": self.route_id,
            "maker_id": self.maker_id,
            "fee_asset_id": self.fee_asset_id,
            "gross_fee_piconero": self.gross_fee_piconero,
            "rebate_piconero": self.rebate_piconero,
            "rebate_bps": self.rebate_bps,
            "budget_root": self.budget_root,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn rebate_root(&self) -> String {
        coordinator_payload_root(
            "MONERO-BRIDGE-LIQUIDITY-LOW-FEE-REBATE",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "rebate_root",
            self.rebate_root(),
        )
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height && matches!(self.status, LowFeeRebateStatus::Reserved) {
            self.status = LowFeeRebateStatus::Expired;
        }
    }

    pub fn validate(&self) -> MoneroBridgeLiquidityCoordinatorResult<String> {
        ensure_non_empty(&self.rebate_id, "low fee rebate id")?;
        ensure_non_empty(&self.withdrawal_id, "low fee rebate withdrawal id")?;
        ensure_non_empty(&self.route_id, "low fee rebate route id")?;
        ensure_non_empty(&self.maker_id, "low fee rebate maker id")?;
        ensure_non_empty(&self.fee_asset_id, "low fee rebate fee asset id")?;
        ensure_non_empty(&self.budget_root, "low fee rebate budget root")?;
        ensure_bps(self.rebate_bps, "low fee rebate bps")?;
        ensure_expiry(
            self.reserved_at_height,
            self.expires_at_height,
            "low fee rebate",
        )?;
        if self.rebate_piconero > self.gross_fee_piconero {
            return Err("low fee rebate exceeds gross fee".to_string());
        }
        let computed = monero_bridge_liquidity_low_fee_rebate_id(&self.identity_record());
        if self.rebate_id != computed {
            return Err("low fee rebate id mismatch".to_string());
        }
        Ok(self.rebate_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveAlert {
    pub alert_id: String,
    pub maker_id: String,
    pub commitment_id: String,
    pub severity: ReserveAlertSeverity,
    pub liability_piconero: u64,
    pub available_piconero: u64,
    pub coverage_bps: u64,
    pub threshold_bps: u64,
    pub evidence_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: ReserveAlertStatus,
}

impl ReserveAlert {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        maker_id: impl Into<String>,
        commitment_id: impl Into<String>,
        severity: ReserveAlertSeverity,
        liability_piconero: u64,
        available_piconero: u64,
        threshold_bps: u64,
        evidence_payload: &Value,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> MoneroBridgeLiquidityCoordinatorResult<Self> {
        let maker_id = maker_id.into();
        let commitment_id = commitment_id.into();
        ensure_non_empty(&maker_id, "reserve alert maker id")?;
        ensure_non_empty(&commitment_id, "reserve alert commitment id")?;
        ensure_bps(threshold_bps, "reserve alert threshold")?;
        ensure_expiry(opened_at_height, expires_at_height, "reserve alert")?;
        let coverage_bps = if liability_piconero == 0 {
            MONERO_BRIDGE_LIQUIDITY_COORDINATOR_MAX_BPS
        } else {
            available_piconero
                .saturating_mul(MONERO_BRIDGE_LIQUIDITY_COORDINATOR_MAX_BPS)
                .saturating_div(liability_piconero)
        };
        let evidence_root = coordinator_payload_root(
            "MONERO-BRIDGE-LIQUIDITY-RESERVE-ALERT-EVIDENCE",
            evidence_payload,
        );
        let mut alert = Self {
            alert_id: String::new(),
            maker_id,
            commitment_id,
            severity,
            liability_piconero,
            available_piconero,
            coverage_bps,
            threshold_bps,
            evidence_root,
            opened_at_height,
            expires_at_height,
            status: ReserveAlertStatus::Open,
        };
        alert.alert_id = monero_bridge_liquidity_reserve_alert_id(&alert.identity_record());
        alert.validate()?;
        Ok(alert)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_bridge_liquidity_reserve_alert_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_LIQUIDITY_COORDINATOR_PROTOCOL_VERSION,
            "maker_id": self.maker_id,
            "commitment_id": self.commitment_id,
            "severity": self.severity.as_str(),
            "coverage_bps": self.coverage_bps,
            "evidence_root": self.evidence_root,
            "opened_at_height": self.opened_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_bridge_liquidity_reserve_alert",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_LIQUIDITY_COORDINATOR_PROTOCOL_VERSION,
            "alert_id": self.alert_id,
            "maker_id": self.maker_id,
            "commitment_id": self.commitment_id,
            "severity": self.severity.as_str(),
            "liability_piconero": self.liability_piconero,
            "available_piconero": self.available_piconero,
            "coverage_bps": self.coverage_bps,
            "threshold_bps": self.threshold_bps,
            "evidence_root": self.evidence_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn alert_root(&self) -> String {
        coordinator_payload_root(
            "MONERO-BRIDGE-LIQUIDITY-RESERVE-ALERT",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "alert_root",
            self.alert_root(),
        )
    }

    pub fn validate(&self) -> MoneroBridgeLiquidityCoordinatorResult<String> {
        ensure_non_empty(&self.alert_id, "reserve alert id")?;
        ensure_non_empty(&self.maker_id, "reserve alert maker id")?;
        ensure_non_empty(&self.commitment_id, "reserve alert commitment id")?;
        ensure_non_empty(&self.evidence_root, "reserve alert evidence root")?;
        ensure_bps(self.threshold_bps, "reserve alert threshold")?;
        ensure_expiry(
            self.opened_at_height,
            self.expires_at_height,
            "reserve alert",
        )?;
        let computed = monero_bridge_liquidity_reserve_alert_id(&self.identity_record());
        if self.alert_id != computed {
            return Err("reserve alert id mismatch".to_string());
        }
        Ok(self.alert_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchtowerQuorumReceipt {
    pub receipt_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub quorum_root: String,
    pub signer_count: u64,
    pub quorum_weight: u64,
    pub required_weight: u64,
    pub min_pq_security_bits: u16,
    pub aggregate_signature_root: String,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
    pub status: WatchtowerReceiptStatus,
}

impl WatchtowerQuorumReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_kind: impl Into<String>,
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        signer_labels: &[String],
        quorum_weight: u64,
        required_weight: u64,
        min_pq_security_bits: u16,
        aggregate_signature_payload: &Value,
        observed_at_height: u64,
        expires_at_height: u64,
    ) -> MoneroBridgeLiquidityCoordinatorResult<Self> {
        let subject_kind = subject_kind.into();
        let subject_id = subject_id.into();
        let subject_root = subject_root.into();
        ensure_non_empty(&subject_kind, "watchtower receipt subject kind")?;
        ensure_non_empty(&subject_id, "watchtower receipt subject id")?;
        ensure_non_empty(&subject_root, "watchtower receipt subject root")?;
        ensure_positive(quorum_weight, "watchtower receipt quorum weight")?;
        ensure_positive(required_weight, "watchtower receipt required weight")?;
        ensure_expiry(observed_at_height, expires_at_height, "watchtower receipt")?;
        if signer_labels.is_empty() {
            return Err("watchtower receipt signer set is empty".to_string());
        }
        let quorum_root =
            coordinator_string_set_root("MONERO-BRIDGE-LIQUIDITY-WATCHTOWER-QUORUM", signer_labels);
        let aggregate_signature_root = coordinator_payload_root(
            "MONERO-BRIDGE-LIQUIDITY-WATCHTOWER-AGGREGATE-SIGNATURE",
            aggregate_signature_payload,
        );
        let status = if quorum_weight >= required_weight {
            WatchtowerReceiptStatus::QuorumMet
        } else {
            WatchtowerReceiptStatus::Observed
        };
        let mut receipt = Self {
            receipt_id: String::new(),
            subject_kind,
            subject_id,
            subject_root,
            quorum_root,
            signer_count: signer_labels.len() as u64,
            quorum_weight,
            required_weight,
            min_pq_security_bits,
            aggregate_signature_root,
            observed_at_height,
            expires_at_height,
            status,
        };
        receipt.receipt_id =
            monero_bridge_liquidity_watchtower_receipt_id(&receipt.identity_record());
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_bridge_liquidity_watchtower_receipt_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_LIQUIDITY_COORDINATOR_PROTOCOL_VERSION,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "quorum_root": self.quorum_root,
            "observed_at_height": self.observed_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_bridge_liquidity_watchtower_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_LIQUIDITY_COORDINATOR_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "quorum_root": self.quorum_root,
            "signer_count": self.signer_count,
            "quorum_weight": self.quorum_weight,
            "required_weight": self.required_weight,
            "min_pq_security_bits": self.min_pq_security_bits,
            "aggregate_signature_root": self.aggregate_signature_root,
            "observed_at_height": self.observed_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn receipt_root(&self) -> String {
        coordinator_payload_root(
            "MONERO-BRIDGE-LIQUIDITY-WATCHTOWER-RECEIPT",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "receipt_root",
            self.receipt_root(),
        )
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height && self.status.is_usable() {
            self.status = WatchtowerReceiptStatus::Expired;
        }
    }

    pub fn validate(&self) -> MoneroBridgeLiquidityCoordinatorResult<String> {
        ensure_non_empty(&self.receipt_id, "watchtower receipt id")?;
        ensure_non_empty(&self.subject_kind, "watchtower receipt subject kind")?;
        ensure_non_empty(&self.subject_id, "watchtower receipt subject id")?;
        ensure_non_empty(&self.subject_root, "watchtower receipt subject root")?;
        ensure_non_empty(&self.quorum_root, "watchtower receipt quorum root")?;
        ensure_non_empty(
            &self.aggregate_signature_root,
            "watchtower receipt aggregate signature root",
        )?;
        ensure_positive(self.signer_count, "watchtower receipt signer count")?;
        ensure_positive(self.quorum_weight, "watchtower receipt quorum weight")?;
        ensure_positive(self.required_weight, "watchtower receipt required weight")?;
        ensure_expiry(
            self.observed_at_height,
            self.expires_at_height,
            "watchtower receipt",
        )?;
        let computed = monero_bridge_liquidity_watchtower_receipt_id(&self.identity_record());
        if self.receipt_id != computed {
            return Err("watchtower receipt id mismatch".to_string());
        }
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyCircuitBreaker {
    pub breaker_id: String,
    pub scope: CircuitBreakerScope,
    pub subject_id: String,
    pub mode: CircuitBreakerMode,
    pub trigger_alert_id: String,
    pub trigger_root: String,
    pub opened_by: String,
    pub opened_at_height: u64,
    pub cool_down_until_height: u64,
    pub expires_at_height: u64,
    pub status: CircuitBreakerStatus,
    pub metadata: Value,
}

impl EmergencyCircuitBreaker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: CircuitBreakerScope,
        subject_id: impl Into<String>,
        mode: CircuitBreakerMode,
        trigger_alert_id: impl Into<String>,
        trigger_payload: &Value,
        opened_by: impl Into<String>,
        opened_at_height: u64,
        cool_down_until_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> MoneroBridgeLiquidityCoordinatorResult<Self> {
        let subject_id = subject_id.into();
        let trigger_alert_id = trigger_alert_id.into();
        let opened_by = opened_by.into();
        ensure_non_empty(&subject_id, "circuit breaker subject id")?;
        ensure_non_empty(&opened_by, "circuit breaker opened by")?;
        ensure_expiry(opened_at_height, expires_at_height, "circuit breaker")?;
        if cool_down_until_height < opened_at_height {
            return Err("circuit breaker cooldown precedes open height".to_string());
        }
        let trigger_root = coordinator_payload_root(
            "MONERO-BRIDGE-LIQUIDITY-CIRCUIT-BREAKER-TRIGGER",
            trigger_payload,
        );
        let mut breaker = Self {
            breaker_id: String::new(),
            scope,
            subject_id,
            mode,
            trigger_alert_id,
            trigger_root,
            opened_by,
            opened_at_height,
            cool_down_until_height,
            expires_at_height,
            status: CircuitBreakerStatus::Triggered,
            metadata: metadata.clone(),
        };
        breaker.breaker_id = monero_bridge_liquidity_circuit_breaker_id(&breaker.identity_record());
        breaker.validate()?;
        Ok(breaker)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_bridge_liquidity_circuit_breaker_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_LIQUIDITY_COORDINATOR_PROTOCOL_VERSION,
            "scope": self.scope.as_str(),
            "subject_id": self.subject_id,
            "mode": self.mode.as_str(),
            "trigger_root": self.trigger_root,
            "opened_by": self.opened_by,
            "opened_at_height": self.opened_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_bridge_liquidity_circuit_breaker",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_LIQUIDITY_COORDINATOR_PROTOCOL_VERSION,
            "breaker_id": self.breaker_id,
            "scope": self.scope.as_str(),
            "subject_id": self.subject_id,
            "mode": self.mode.as_str(),
            "trigger_alert_id": self.trigger_alert_id,
            "trigger_root": self.trigger_root,
            "opened_by": self.opened_by,
            "opened_at_height": self.opened_at_height,
            "cool_down_until_height": self.cool_down_until_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "metadata": self.metadata,
        })
    }

    pub fn breaker_root(&self) -> String {
        coordinator_payload_root(
            "MONERO-BRIDGE-LIQUIDITY-CIRCUIT-BREAKER",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "breaker_root",
            self.breaker_root(),
        )
    }

    pub fn applies_to(&self, scope: CircuitBreakerScope, subject_id: &str) -> bool {
        self.status.is_active()
            && (self.scope == CircuitBreakerScope::Global
                || (self.scope == scope && self.subject_id == subject_id))
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height && self.status.is_active() {
            self.status = CircuitBreakerStatus::Expired;
        } else if height >= self.cool_down_until_height
            && matches!(self.status, CircuitBreakerStatus::Triggered)
        {
            self.status = CircuitBreakerStatus::CoolingDown;
        }
    }

    pub fn validate(&self) -> MoneroBridgeLiquidityCoordinatorResult<String> {
        ensure_non_empty(&self.breaker_id, "circuit breaker id")?;
        ensure_non_empty(&self.subject_id, "circuit breaker subject id")?;
        ensure_non_empty(&self.trigger_root, "circuit breaker trigger root")?;
        ensure_non_empty(&self.opened_by, "circuit breaker opened by")?;
        ensure_expiry(
            self.opened_at_height,
            self.expires_at_height,
            "circuit breaker",
        )?;
        if self.cool_down_until_height < self.opened_at_height {
            return Err("circuit breaker cooldown precedes open height".to_string());
        }
        let computed = monero_bridge_liquidity_circuit_breaker_id(&self.identity_record());
        if self.breaker_id != computed {
            return Err("circuit breaker id mismatch".to_string());
        }
        Ok(self.breaker_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroBridgeLiquidityCoordinatorPublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub published_at_height: u64,
}

impl MoneroBridgeLiquidityCoordinatorPublicRecord {
    pub fn new(
        record_kind: &str,
        subject_id: &str,
        payload: &Value,
        published_at_height: u64,
    ) -> Self {
        let payload_root =
            coordinator_payload_root("MONERO-BRIDGE-LIQUIDITY-PUBLIC-RECORD-PAYLOAD", payload);
        let identity = json!({
            "kind": "monero_bridge_liquidity_public_record_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_LIQUIDITY_COORDINATOR_PROTOCOL_VERSION,
            "record_kind": record_kind,
            "subject_id": subject_id,
            "payload_root": payload_root,
            "published_at_height": published_at_height,
        });
        Self {
            record_id: monero_bridge_liquidity_public_record_id(&identity),
            record_kind: record_kind.to_string(),
            subject_id: subject_id.to_string(),
            payload_root,
            published_at_height,
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_bridge_liquidity_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_LIQUIDITY_COORDINATOR_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "published_at_height": self.published_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        coordinator_payload_root(
            "MONERO-BRIDGE-LIQUIDITY-PUBLIC-RECORD",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "record_root",
            self.record_root(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroBridgeLiquidityCoordinatorRoots {
    pub config_root: String,
    pub maker_root: String,
    pub inventory_commitment_root: String,
    pub withdrawal_auction_root: String,
    pub withdrawal_bid_root: String,
    pub settlement_route_root: String,
    pub replenishment_schedule_root: String,
    pub low_fee_rebate_root: String,
    pub reserve_alert_root: String,
    pub watchtower_receipt_root: String,
    pub circuit_breaker_root: String,
    pub public_record_root: String,
}

impl MoneroBridgeLiquidityCoordinatorRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_bridge_liquidity_coordinator_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_LIQUIDITY_COORDINATOR_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "maker_root": self.maker_root,
            "inventory_commitment_root": self.inventory_commitment_root,
            "withdrawal_auction_root": self.withdrawal_auction_root,
            "withdrawal_bid_root": self.withdrawal_bid_root,
            "settlement_route_root": self.settlement_route_root,
            "replenishment_schedule_root": self.replenishment_schedule_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "reserve_alert_root": self.reserve_alert_root,
            "watchtower_receipt_root": self.watchtower_receipt_root,
            "circuit_breaker_root": self.circuit_breaker_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        coordinator_payload_root(
            "MONERO-BRIDGE-LIQUIDITY-COORDINATOR-ROOTS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroBridgeLiquidityCoordinatorCounters {
    pub maker_count: u64,
    pub active_maker_count: u64,
    pub inventory_commitment_count: u64,
    pub available_inventory_piconero: u64,
    pub reserved_inventory_piconero: u64,
    pub consumed_inventory_piconero: u64,
    pub open_auction_count: u64,
    pub live_bid_count: u64,
    pub live_route_count: u64,
    pub pending_replenishment_count: u64,
    pub open_rebate_count: u64,
    pub open_alert_count: u64,
    pub active_breaker_count: u64,
    pub watchtower_quorum_count: u64,
}

impl MoneroBridgeLiquidityCoordinatorCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_bridge_liquidity_coordinator_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_LIQUIDITY_COORDINATOR_PROTOCOL_VERSION,
            "maker_count": self.maker_count,
            "active_maker_count": self.active_maker_count,
            "inventory_commitment_count": self.inventory_commitment_count,
            "available_inventory_piconero": self.available_inventory_piconero,
            "reserved_inventory_piconero": self.reserved_inventory_piconero,
            "consumed_inventory_piconero": self.consumed_inventory_piconero,
            "open_auction_count": self.open_auction_count,
            "live_bid_count": self.live_bid_count,
            "live_route_count": self.live_route_count,
            "pending_replenishment_count": self.pending_replenishment_count,
            "open_rebate_count": self.open_rebate_count,
            "open_alert_count": self.open_alert_count,
            "active_breaker_count": self.active_breaker_count,
            "watchtower_quorum_count": self.watchtower_quorum_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroBridgeLiquidityCoordinatorState {
    pub height: u64,
    pub config: MoneroBridgeLiquidityCoordinatorConfig,
    pub makers: BTreeMap<String, LiquidityMaker>,
    pub inventory_commitments: BTreeMap<String, PrivateInventoryCommitment>,
    pub withdrawal_auctions: BTreeMap<String, WithdrawalAuction>,
    pub withdrawal_bids: BTreeMap<String, WithdrawalBid>,
    pub settlement_routes: BTreeMap<String, SettlementRoute>,
    pub replenishment_schedules: BTreeMap<String, ReplenishmentSchedule>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub reserve_alerts: BTreeMap<String, ReserveAlert>,
    pub watchtower_receipts: BTreeMap<String, WatchtowerQuorumReceipt>,
    pub circuit_breakers: BTreeMap<String, EmergencyCircuitBreaker>,
    pub public_records: BTreeMap<String, MoneroBridgeLiquidityCoordinatorPublicRecord>,
}

impl Default for MoneroBridgeLiquidityCoordinatorState {
    fn default() -> Self {
        Self {
            height: 0,
            config: MoneroBridgeLiquidityCoordinatorConfig::default(),
            makers: BTreeMap::new(),
            inventory_commitments: BTreeMap::new(),
            withdrawal_auctions: BTreeMap::new(),
            withdrawal_bids: BTreeMap::new(),
            settlement_routes: BTreeMap::new(),
            replenishment_schedules: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            reserve_alerts: BTreeMap::new(),
            watchtower_receipts: BTreeMap::new(),
            circuit_breakers: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }
}

impl MoneroBridgeLiquidityCoordinatorState {
    pub fn new(
        config: MoneroBridgeLiquidityCoordinatorConfig,
    ) -> MoneroBridgeLiquidityCoordinatorResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::default()
        })
    }

    pub fn devnet() -> MoneroBridgeLiquidityCoordinatorResult<Self> {
        let config = MoneroBridgeLiquidityCoordinatorConfig::default();
        let mut state = Self::new(config)?;
        let mut fast_kinds = BTreeSet::new();
        fast_kinds.insert(SettlementRouteKind::HotMaker);
        fast_kinds.insert(SettlementRouteKind::PrivacyDelayed);
        let mut batch_kinds = BTreeSet::new();
        batch_kinds.insert(SettlementRouteKind::BatchMaker);
        batch_kinds.insert(SettlementRouteKind::AtomicNetting);
        let mut reserve_kinds = BTreeSet::new();
        reserve_kinds.insert(SettlementRouteKind::EmergencyReserve);
        reserve_kinds.insert(SettlementRouteKind::HotMaker);

        let maker_a = LiquidityMaker::new(
            "devnet-maker-a",
            "devnet fast private maker",
            &state.config.network,
            "devnet-maker-a-settlement-address",
            "devnet-maker-a-view-key-commitment",
            "devnet-maker-a-ml-dsa-key",
            "ml-dsa-87",
            256,
            20_000_000_000_000,
            45,
            4,
            fast_kinds,
            &json!({"profile": "fast low fee private withdrawals"}),
        )?;
        let maker_a_id = maker_a.maker_id.clone();
        state.insert_maker(maker_a)?;

        let maker_b = LiquidityMaker::new(
            "devnet-maker-b",
            "devnet batch maker",
            &state.config.network,
            "devnet-maker-b-settlement-address",
            "devnet-maker-b-view-key-commitment",
            "devnet-maker-b-slh-dsa-key",
            "slh-dsa-shake-256f",
            256,
            80_000_000_000_000,
            25,
            12,
            batch_kinds,
            &json!({"profile": "batched DeFi and token exit liquidity"}),
        )?;
        let maker_b_id = maker_b.maker_id.clone();
        state.insert_maker(maker_b)?;

        let maker_c = LiquidityMaker::new(
            "devnet-reserve-c",
            "devnet emergency reserve",
            &state.config.network,
            "devnet-reserve-c-settlement-address",
            "devnet-reserve-c-view-key-commitment",
            "devnet-reserve-c-hybrid-pq-key",
            "ml-dsa-87+slh-dsa-shake-256s",
            256,
            120_000_000_000_000,
            70,
            2,
            reserve_kinds,
            &json!({"profile": "emergency withdrawal continuity"}),
        )?;
        let maker_c_id = maker_c.maker_id.clone();
        state.insert_maker(maker_c)?;

        let inv_a = PrivateInventoryCommitment::new(
            &maker_a_id,
            &state.config.network,
            &state.config.asset_id,
            "devnet-maker-a-private-xmr-inventory-v1",
            &json!({"range": "0..20000000000000", "scheme": "bulletproofs-plus-shadow"}),
            &[
                "devnet-maker-a-nullifier-0".to_string(),
                "devnet-maker-a-nullifier-1".to_string(),
            ],
            &["devnet-maker-a-reserve-0".to_string()],
            100_000_000_000,
            20_000_000_000_000,
            5_000_000,
            45,
            4,
            0,
            720,
            &json!({"privacy": "commitment only; no public address balance"}),
        )?;
        let inv_a_root = inv_a.commitment_root();
        state.insert_inventory_commitment(inv_a)?;

        let inv_b = PrivateInventoryCommitment::new(
            &maker_b_id,
            &state.config.network,
            &state.config.asset_id,
            "devnet-maker-b-private-xmr-inventory-v1",
            &json!({"range": "0..80000000000000", "scheme": "bulletproofs-plus-shadow"}),
            &["devnet-maker-b-nullifier-0".to_string()],
            &[
                "devnet-maker-b-reserve-0".to_string(),
                "devnet-maker-b-reserve-1".to_string(),
            ],
            500_000_000_000,
            80_000_000_000_000,
            15_000_000,
            25,
            12,
            0,
            720,
            &json!({"privacy": "batched reserve commitment"}),
        )?;
        state.insert_inventory_commitment(inv_b)?;

        let inv_c = PrivateInventoryCommitment::new(
            &maker_c_id,
            &state.config.network,
            &state.config.asset_id,
            "devnet-reserve-c-private-xmr-inventory-v1",
            &json!({"range": "0..120000000000000", "scheme": "emergency-reserve-attested"}),
            &["devnet-reserve-c-nullifier-0".to_string()],
            &["devnet-reserve-c-reserve-0".to_string()],
            1_000_000_000_000,
            120_000_000_000_000,
            25_000_000,
            70,
            2,
            0,
            720,
            &json!({"privacy": "emergency continuity pool"}),
        )?;
        state.insert_inventory_commitment(inv_c)?;

        let schedule = ReplenishmentSchedule::new(
            &maker_a_id,
            &state.config.asset_id,
            &inv_a_root,
            "devnet-maker-a-cold-reserve",
            5_000_000_000_000,
            20,
            0,
            120,
            state.config.replenishment_ttl_blocks.saturating_add(120),
            &json!({"cadence": "daily", "purpose": "keep hot maker inventory fresh"}),
        )?;
        state.insert_replenishment_schedule(schedule)?;

        let receipt = WatchtowerQuorumReceipt::new(
            "coordinator_bootstrap",
            "devnet",
            &state.roots().state_root(),
            &[
                "devnet-watchtower-a".to_string(),
                "devnet-watchtower-b".to_string(),
                "devnet-watchtower-c".to_string(),
            ],
            3,
            state.config.min_watchtower_quorum_weight,
            state.config.min_pq_security_bits,
            &json!({"aggregate": "devnet-bootstrap-quorum"}),
            0,
            240,
        )?;
        state.insert_watchtower_receipt(receipt)?;

        let public = state.public_record_without_root();
        state.publish_public_record("monero_bridge_liquidity_devnet", "bootstrap", &public)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for commitment in self.inventory_commitments.values_mut() {
            commitment.set_height(height);
        }
        for auction in self.withdrawal_auctions.values_mut() {
            auction.set_height(height);
        }
        for bid in self.withdrawal_bids.values_mut() {
            bid.set_height(height);
        }
        for route in self.settlement_routes.values_mut() {
            route.set_height(height);
        }
        for schedule in self.replenishment_schedules.values_mut() {
            schedule.set_height(height);
        }
        for rebate in self.low_fee_rebates.values_mut() {
            rebate.set_height(height);
        }
        for receipt in self.watchtower_receipts.values_mut() {
            receipt.set_height(height);
        }
        for breaker in self.circuit_breakers.values_mut() {
            breaker.set_height(height);
        }
    }

    pub fn insert_maker(
        &mut self,
        maker: LiquidityMaker,
    ) -> MoneroBridgeLiquidityCoordinatorResult<LiquidityMaker> {
        maker.validate()?;
        if maker.pq_security_bits < self.config.min_pq_security_bits {
            return Err("maker pq security bits below coordinator floor".to_string());
        }
        self.makers.insert(maker.maker_id.clone(), maker.clone());
        Ok(maker)
    }

    pub fn insert_inventory_commitment(
        &mut self,
        commitment: PrivateInventoryCommitment,
    ) -> MoneroBridgeLiquidityCoordinatorResult<PrivateInventoryCommitment> {
        commitment.validate()?;
        if !self.makers.contains_key(&commitment.maker_id) {
            return Err("inventory commitment maker is missing".to_string());
        }
        self.inventory_commitments
            .insert(commitment.commitment_id.clone(), commitment.clone());
        Ok(commitment)
    }

    pub fn open_withdrawal_auction(
        &mut self,
        withdrawal_id: &str,
        recipient_commitment_material: &str,
        amount_piconero: u64,
        max_fee_piconero: u64,
        max_fee_bps: u64,
        route_kind_preference: Vec<SettlementRouteKind>,
    ) -> MoneroBridgeLiquidityCoordinatorResult<WithdrawalAuction> {
        if self.withdrawals_halted("global") {
            return Err("withdrawal auctions halted by circuit breaker".to_string());
        }
        if amount_piconero > self.config.max_auction_amount_piconero {
            return Err("withdrawal auction amount exceeds coordinator limit".to_string());
        }
        let auction = WithdrawalAuction::new(
            withdrawal_id,
            recipient_commitment_material,
            amount_piconero,
            max_fee_piconero,
            max_fee_bps.min(self.config.max_route_fee_bps),
            route_kind_preference,
            self.height,
            self.config.auction_ttl_blocks,
            &json!({"network": self.config.network, "privacy": "recipient commitment only"}),
        )?;
        self.withdrawal_auctions
            .insert(auction.auction_id.clone(), auction.clone());
        self.publish_public_record(
            "monero_bridge_liquidity_withdrawal_auction",
            &auction.auction_id,
            &auction.public_record(),
        )?;
        Ok(auction)
    }

    pub fn submit_bid(
        &mut self,
        auction_id: &str,
        maker_id: &str,
        commitment_id: &str,
        route_kind: SettlementRouteKind,
        fee_piconero: u64,
        pq_signature_payload: &Value,
    ) -> MoneroBridgeLiquidityCoordinatorResult<WithdrawalBid> {
        let auction = self
            .withdrawal_auctions
            .get(auction_id)
            .ok_or_else(|| "withdrawal auction is missing".to_string())?
            .clone();
        if !auction.status.is_open() {
            return Err("withdrawal auction is not open".to_string());
        }
        let maker = self
            .makers
            .get(maker_id)
            .ok_or_else(|| "withdrawal bid maker is missing".to_string())?;
        if !maker.status.is_usable() {
            return Err("withdrawal bid maker is not usable".to_string());
        }
        if !maker.supports(route_kind) {
            return Err("withdrawal bid maker does not support route kind".to_string());
        }
        if maker.max_fee_bps < auction.max_fee_bps && fee_piconero > auction.max_fee_piconero {
            return Err("withdrawal bid fee exceeds auction and maker bounds".to_string());
        }
        let commitment = self
            .inventory_commitments
            .get(commitment_id)
            .ok_or_else(|| "withdrawal bid inventory commitment is missing".to_string())?;
        if commitment.maker_id != maker_id {
            return Err("withdrawal bid commitment belongs to another maker".to_string());
        }
        if commitment.remaining_piconero() < auction.amount_piconero {
            return Err("withdrawal bid commitment has insufficient inventory".to_string());
        }
        let fee_bps = fee_piconero
            .saturating_mul(MONERO_BRIDGE_LIQUIDITY_COORDINATOR_MAX_BPS)
            .saturating_div(auction.amount_piconero.max(1));
        let bid = WithdrawalBid::new(
            auction_id,
            maker_id,
            commitment_id,
            route_kind,
            auction.amount_piconero,
            fee_piconero,
            fee_bps,
            maker
                .privacy_delay_blocks
                .max(commitment.privacy_delay_blocks),
            commitment.commitment_root(),
            pq_signature_payload,
            self.height,
            auction.expires_at_height,
        )?;
        if !auction.accepts_bid(&bid) {
            return Err("withdrawal bid is outside auction constraints".to_string());
        }
        self.withdrawal_bids.insert(bid.bid_id.clone(), bid.clone());
        Ok(bid)
    }

    pub fn award_auction(
        &mut self,
        auction_id: &str,
    ) -> MoneroBridgeLiquidityCoordinatorResult<SettlementRoute> {
        let auction = self
            .withdrawal_auctions
            .get(auction_id)
            .ok_or_else(|| "withdrawal auction is missing".to_string())?
            .clone();
        if !auction.status.is_open() {
            return Err("withdrawal auction is not open".to_string());
        }
        let mut eligible = self
            .withdrawal_bids
            .values()
            .filter(|bid| auction.accepts_bid(bid))
            .cloned()
            .collect::<Vec<_>>();
        eligible.sort_by(|left, right| {
            left.priority_score
                .cmp(&right.priority_score)
                .then_with(|| left.fee_piconero.cmp(&right.fee_piconero))
                .then_with(|| left.bid_id.cmp(&right.bid_id))
        });
        let selected = eligible
            .first()
            .cloned()
            .ok_or_else(|| "withdrawal auction has no eligible bids".to_string())?;
        let bid_root = withdrawal_bid_root(&eligible);
        let mut awarded_auction = auction.clone();
        awarded_auction.award(&selected.bid_id, &bid_root)?;
        let mut awarded_bid = selected.clone();
        awarded_bid.mark_awarded()?;
        let commitment = self
            .inventory_commitments
            .get_mut(&selected.commitment_id)
            .ok_or_else(|| "selected bid inventory commitment is missing".to_string())?;
        commitment.reserve(auction.amount_piconero)?;
        let release_not_before_height = self.height.saturating_add(selected.privacy_delay_blocks);
        let route = SettlementRoute::new(
            &awarded_auction,
            &awarded_bid,
            &json!({
                "network": self.config.network,
                "asset_id": self.config.asset_id,
                "private_inventory_root": selected.inventory_root,
                "watchtower_required_weight": self.config.min_watchtower_quorum_weight,
            }),
            release_not_before_height,
            self.height.saturating_add(self.config.route_ttl_blocks),
        )?;
        self.withdrawal_auctions
            .insert(awarded_auction.auction_id.clone(), awarded_auction);
        self.withdrawal_bids
            .insert(awarded_bid.bid_id.clone(), awarded_bid);
        self.settlement_routes
            .insert(route.route_id.clone(), route.clone());
        self.publish_public_record(
            "monero_bridge_liquidity_settlement_route",
            &route.route_id,
            &route.public_record(),
        )?;
        Ok(route)
    }

    pub fn reserve_low_fee_rebate(
        &mut self,
        route_id: &str,
    ) -> MoneroBridgeLiquidityCoordinatorResult<LowFeeRebate> {
        let route = self
            .settlement_routes
            .get(route_id)
            .ok_or_else(|| "rebate route is missing".to_string())?
            .clone();
        let rebate = LowFeeRebate::new(
            &route.withdrawal_id,
            &route.route_id,
            &route.maker_id,
            &self.config.fee_asset_id,
            route.fee_piconero,
            self.config.low_fee_rebate_bps,
            self.config.max_rebate_units_per_withdrawal,
            &json!({
                "coordinator_state_root": self.state_root(),
                "route_root": route.route_root(),
                "fee_asset_id": self.config.fee_asset_id,
            }),
            self.height,
            self.height.saturating_add(self.config.rebate_ttl_blocks),
        )?;
        let mut updated_route = route;
        updated_route.attach_rebate(&rebate.rebate_id)?;
        self.settlement_routes
            .insert(updated_route.route_id.clone(), updated_route);
        self.low_fee_rebates
            .insert(rebate.rebate_id.clone(), rebate.clone());
        Ok(rebate)
    }

    pub fn insert_watchtower_receipt(
        &mut self,
        receipt: WatchtowerQuorumReceipt,
    ) -> MoneroBridgeLiquidityCoordinatorResult<WatchtowerQuorumReceipt> {
        receipt.validate()?;
        if receipt.min_pq_security_bits < self.config.min_pq_security_bits {
            return Err("watchtower receipt pq security bits below coordinator floor".to_string());
        }
        if receipt.quorum_weight < self.config.min_watchtower_quorum_weight {
            return Err("watchtower receipt quorum weight below coordinator floor".to_string());
        }
        self.watchtower_receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn attach_watchtower_to_route(
        &mut self,
        route_id: &str,
        receipt: WatchtowerQuorumReceipt,
    ) -> MoneroBridgeLiquidityCoordinatorResult<SettlementRoute> {
        let receipt = self.insert_watchtower_receipt(receipt)?;
        let route = self
            .settlement_routes
            .get_mut(route_id)
            .ok_or_else(|| "watchtower route is missing".to_string())?;
        if receipt.subject_root != route.route_root() && receipt.subject_id != route.route_id {
            return Err("watchtower receipt does not attest route".to_string());
        }
        route.attach_watchtower_receipt(&receipt.receipt_id)?;
        Ok(route.clone())
    }

    pub fn insert_replenishment_schedule(
        &mut self,
        schedule: ReplenishmentSchedule,
    ) -> MoneroBridgeLiquidityCoordinatorResult<ReplenishmentSchedule> {
        schedule.validate()?;
        if !self.makers.contains_key(&schedule.maker_id) {
            return Err("replenishment schedule maker is missing".to_string());
        }
        self.replenishment_schedules
            .insert(schedule.schedule_id.clone(), schedule.clone());
        Ok(schedule)
    }

    pub fn open_reserve_alert(
        &mut self,
        maker_id: &str,
        commitment_id: &str,
        liability_piconero: u64,
        evidence_payload: &Value,
    ) -> MoneroBridgeLiquidityCoordinatorResult<Option<ReserveAlert>> {
        let commitment = self
            .inventory_commitments
            .get(commitment_id)
            .ok_or_else(|| "reserve alert commitment is missing".to_string())?;
        if commitment.maker_id != maker_id {
            return Err("reserve alert maker and commitment mismatch".to_string());
        }
        let available = commitment.remaining_piconero();
        let coverage_bps = if liability_piconero == 0 {
            MONERO_BRIDGE_LIQUIDITY_COORDINATOR_MAX_BPS
        } else {
            available
                .saturating_mul(MONERO_BRIDGE_LIQUIDITY_COORDINATOR_MAX_BPS)
                .saturating_div(liability_piconero)
        };
        let severity = if coverage_bps <= self.config.reserve_halt_coverage_bps {
            ReserveAlertSeverity::Halt
        } else if coverage_bps <= self.config.reserve_critical_coverage_bps {
            ReserveAlertSeverity::Critical
        } else if coverage_bps <= self.config.reserve_warning_coverage_bps {
            ReserveAlertSeverity::Warning
        } else {
            ReserveAlertSeverity::Info
        };
        if severity == ReserveAlertSeverity::Info {
            return Ok(None);
        }
        let threshold = match severity {
            ReserveAlertSeverity::Halt => self.config.reserve_halt_coverage_bps,
            ReserveAlertSeverity::Critical => self.config.reserve_critical_coverage_bps,
            ReserveAlertSeverity::Warning => self.config.reserve_warning_coverage_bps,
            ReserveAlertSeverity::Info => MONERO_BRIDGE_LIQUIDITY_COORDINATOR_MAX_BPS,
        };
        let alert = ReserveAlert::new(
            maker_id,
            commitment_id,
            severity,
            liability_piconero,
            available,
            threshold,
            evidence_payload,
            self.height,
            self.height
                .saturating_add(MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEFAULT_ALERT_TTL_BLOCKS),
        )?;
        self.reserve_alerts
            .insert(alert.alert_id.clone(), alert.clone());
        Ok(Some(alert))
    }

    pub fn trigger_circuit_breaker_from_alert(
        &mut self,
        alert_id: &str,
        opened_by: &str,
    ) -> MoneroBridgeLiquidityCoordinatorResult<EmergencyCircuitBreaker> {
        let alert = self
            .reserve_alerts
            .get(alert_id)
            .ok_or_else(|| "circuit breaker alert is missing".to_string())?
            .clone();
        let mode = match alert.severity {
            ReserveAlertSeverity::Halt => CircuitBreakerMode::HaltWithdrawals,
            ReserveAlertSeverity::Critical => CircuitBreakerMode::ThrottleAuctions,
            ReserveAlertSeverity::Warning | ReserveAlertSeverity::Info => {
                CircuitBreakerMode::Observe
            }
        };
        let breaker = EmergencyCircuitBreaker::new(
            CircuitBreakerScope::Maker,
            &alert.maker_id,
            mode,
            &alert.alert_id,
            &alert.public_record(),
            opened_by,
            self.height,
            self.height.saturating_add(12),
            self.height.saturating_add(
                MONERO_BRIDGE_LIQUIDITY_COORDINATOR_DEFAULT_CIRCUIT_BREAKER_TTL_BLOCKS,
            ),
            &json!({"source": "reserve_alert", "commitment_id": alert.commitment_id}),
        )?;
        self.circuit_breakers
            .insert(breaker.breaker_id.clone(), breaker.clone());
        Ok(breaker)
    }

    pub fn publish_public_record(
        &mut self,
        record_kind: &str,
        subject_id: &str,
        payload: &Value,
    ) -> MoneroBridgeLiquidityCoordinatorResult<MoneroBridgeLiquidityCoordinatorPublicRecord> {
        ensure_non_empty(record_kind, "public record kind")?;
        ensure_non_empty(subject_id, "public record subject id")?;
        let record = MoneroBridgeLiquidityCoordinatorPublicRecord::new(
            record_kind,
            subject_id,
            payload,
            self.height,
        );
        self.public_records
            .insert(record.record_id.clone(), record.clone());
        Ok(record)
    }

    pub fn withdrawals_halted(&self, subject_id: &str) -> bool {
        self.circuit_breakers.values().any(|breaker| {
            breaker.status.is_active()
                && breaker.mode.halts_withdrawals()
                && (breaker.applies_to(CircuitBreakerScope::Global, "global")
                    || breaker.applies_to(CircuitBreakerScope::Maker, subject_id))
        })
    }

    pub fn roots(&self) -> MoneroBridgeLiquidityCoordinatorRoots {
        MoneroBridgeLiquidityCoordinatorRoots {
            config_root: self.config.config_root(),
            maker_root: liquidity_maker_root(&self.makers.values().cloned().collect::<Vec<_>>()),
            inventory_commitment_root: inventory_commitment_root(
                &self
                    .inventory_commitments
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            withdrawal_auction_root: withdrawal_auction_root(
                &self
                    .withdrawal_auctions
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            withdrawal_bid_root: withdrawal_bid_root(
                &self.withdrawal_bids.values().cloned().collect::<Vec<_>>(),
            ),
            settlement_route_root: settlement_route_root(
                &self.settlement_routes.values().cloned().collect::<Vec<_>>(),
            ),
            replenishment_schedule_root: replenishment_schedule_root(
                &self
                    .replenishment_schedules
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            low_fee_rebate_root: low_fee_rebate_root(
                &self.low_fee_rebates.values().cloned().collect::<Vec<_>>(),
            ),
            reserve_alert_root: reserve_alert_root(
                &self.reserve_alerts.values().cloned().collect::<Vec<_>>(),
            ),
            watchtower_receipt_root: watchtower_receipt_root(
                &self
                    .watchtower_receipts
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            circuit_breaker_root: circuit_breaker_root(
                &self.circuit_breakers.values().cloned().collect::<Vec<_>>(),
            ),
            public_record_root: coordinator_public_record_root(
                &self.public_records.values().cloned().collect::<Vec<_>>(),
            ),
        }
    }

    pub fn counters(&self) -> MoneroBridgeLiquidityCoordinatorCounters {
        MoneroBridgeLiquidityCoordinatorCounters {
            maker_count: self.makers.len() as u64,
            active_maker_count: self
                .makers
                .values()
                .filter(|maker| maker.status.is_usable())
                .count() as u64,
            inventory_commitment_count: self.inventory_commitments.len() as u64,
            available_inventory_piconero: self.total_available_inventory_piconero(),
            reserved_inventory_piconero: self
                .inventory_commitments
                .values()
                .fold(0_u64, |total, item| {
                    total.saturating_add(item.reserved_piconero)
                }),
            consumed_inventory_piconero: self
                .inventory_commitments
                .values()
                .fold(0_u64, |total, item| {
                    total.saturating_add(item.consumed_piconero)
                }),
            open_auction_count: self
                .withdrawal_auctions
                .values()
                .filter(|auction| auction.status.is_open())
                .count() as u64,
            live_bid_count: self
                .withdrawal_bids
                .values()
                .filter(|bid| bid.status.is_live())
                .count() as u64,
            live_route_count: self
                .settlement_routes
                .values()
                .filter(|route| route.status.is_live())
                .count() as u64,
            pending_replenishment_count: self
                .replenishment_schedules
                .values()
                .filter(|schedule| {
                    matches!(
                        schedule.status,
                        ReplenishmentScheduleStatus::Planned
                            | ReplenishmentScheduleStatus::Funding
                            | ReplenishmentScheduleStatus::InFlight
                            | ReplenishmentScheduleStatus::Confirming
                    )
                })
                .count() as u64,
            open_rebate_count: self
                .low_fee_rebates
                .values()
                .filter(|rebate| {
                    matches!(
                        rebate.status,
                        LowFeeRebateStatus::Reserved | LowFeeRebateStatus::Applied
                    )
                })
                .count() as u64,
            open_alert_count: self
                .reserve_alerts
                .values()
                .filter(|alert| alert.status.is_open())
                .count() as u64,
            active_breaker_count: self
                .circuit_breakers
                .values()
                .filter(|breaker| breaker.status.is_active())
                .count() as u64,
            watchtower_quorum_count: self
                .watchtower_receipts
                .values()
                .filter(|receipt| matches!(receipt.status, WatchtowerReceiptStatus::QuorumMet))
                .count() as u64,
        }
    }

    pub fn total_available_inventory_piconero(&self) -> u64 {
        self.inventory_commitments
            .values()
            .fold(0_u64, |total, item| {
                total.saturating_add(item.remaining_piconero())
            })
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "monero_bridge_liquidity_coordinator_state",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_LIQUIDITY_COORDINATOR_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.state_root(),
            "counters": counters.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "state_root",
            self.state_root(),
        )
    }

    pub fn state_root(&self) -> String {
        monero_bridge_liquidity_coordinator_state_root_from_record(
            &self.public_record_without_root(),
        )
    }

    pub fn validate(&self) -> MoneroBridgeLiquidityCoordinatorResult<String> {
        self.config.validate()?;
        for maker in self.makers.values() {
            maker.validate()?;
            if maker.pq_security_bits < self.config.min_pq_security_bits {
                return Err("maker pq security bits below coordinator floor".to_string());
            }
        }
        for commitment in self.inventory_commitments.values() {
            commitment.validate()?;
            if !self.makers.contains_key(&commitment.maker_id) {
                return Err("inventory commitment maker is missing".to_string());
            }
        }
        for auction in self.withdrawal_auctions.values() {
            auction.validate()?;
        }
        for bid in self.withdrawal_bids.values() {
            bid.validate()?;
            if !self.withdrawal_auctions.contains_key(&bid.auction_id) {
                return Err("withdrawal bid auction is missing".to_string());
            }
            if !self.makers.contains_key(&bid.maker_id) {
                return Err("withdrawal bid maker is missing".to_string());
            }
            if !self.inventory_commitments.contains_key(&bid.commitment_id) {
                return Err("withdrawal bid inventory commitment is missing".to_string());
            }
        }
        for route in self.settlement_routes.values() {
            route.validate()?;
            if !self.withdrawal_auctions.contains_key(&route.auction_id) {
                return Err("settlement route auction is missing".to_string());
            }
            if !self.withdrawal_bids.contains_key(&route.bid_id) {
                return Err("settlement route bid is missing".to_string());
            }
        }
        for schedule in self.replenishment_schedules.values() {
            schedule.validate()?;
            if !self.makers.contains_key(&schedule.maker_id) {
                return Err("replenishment schedule maker is missing".to_string());
            }
        }
        for rebate in self.low_fee_rebates.values() {
            rebate.validate()?;
            if !self.settlement_routes.contains_key(&rebate.route_id) {
                return Err("low fee rebate route is missing".to_string());
            }
        }
        for alert in self.reserve_alerts.values() {
            alert.validate()?;
            if !self.makers.contains_key(&alert.maker_id) {
                return Err("reserve alert maker is missing".to_string());
            }
        }
        for receipt in self.watchtower_receipts.values() {
            receipt.validate()?;
            if receipt.quorum_weight < self.config.min_watchtower_quorum_weight {
                return Err("watchtower receipt quorum below coordinator floor".to_string());
            }
        }
        for breaker in self.circuit_breakers.values() {
            breaker.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn monero_bridge_liquidity_coordinator_state_root_from_record(record: &Value) -> String {
    coordinator_payload_root("MONERO-BRIDGE-LIQUIDITY-COORDINATOR-STATE", record)
}

pub fn monero_bridge_liquidity_maker_id(record: &Value) -> String {
    coordinator_payload_root("MONERO-BRIDGE-LIQUIDITY-MAKER-ID", record)
}

pub fn monero_bridge_liquidity_inventory_commitment_id(record: &Value) -> String {
    coordinator_payload_root("MONERO-BRIDGE-LIQUIDITY-INVENTORY-COMMITMENT-ID", record)
}

pub fn monero_bridge_liquidity_withdrawal_auction_id(record: &Value) -> String {
    coordinator_payload_root("MONERO-BRIDGE-LIQUIDITY-WITHDRAWAL-AUCTION-ID", record)
}

pub fn monero_bridge_liquidity_withdrawal_bid_id(record: &Value) -> String {
    coordinator_payload_root("MONERO-BRIDGE-LIQUIDITY-WITHDRAWAL-BID-ID", record)
}

pub fn monero_bridge_liquidity_settlement_route_id(record: &Value) -> String {
    coordinator_payload_root("MONERO-BRIDGE-LIQUIDITY-SETTLEMENT-ROUTE-ID", record)
}

pub fn monero_bridge_liquidity_replenishment_schedule_id(record: &Value) -> String {
    coordinator_payload_root("MONERO-BRIDGE-LIQUIDITY-REPLENISHMENT-SCHEDULE-ID", record)
}

pub fn monero_bridge_liquidity_low_fee_rebate_id(record: &Value) -> String {
    coordinator_payload_root("MONERO-BRIDGE-LIQUIDITY-LOW-FEE-REBATE-ID", record)
}

pub fn monero_bridge_liquidity_reserve_alert_id(record: &Value) -> String {
    coordinator_payload_root("MONERO-BRIDGE-LIQUIDITY-RESERVE-ALERT-ID", record)
}

pub fn monero_bridge_liquidity_watchtower_receipt_id(record: &Value) -> String {
    coordinator_payload_root("MONERO-BRIDGE-LIQUIDITY-WATCHTOWER-RECEIPT-ID", record)
}

pub fn monero_bridge_liquidity_circuit_breaker_id(record: &Value) -> String {
    coordinator_payload_root("MONERO-BRIDGE-LIQUIDITY-CIRCUIT-BREAKER-ID", record)
}

pub fn monero_bridge_liquidity_public_record_id(record: &Value) -> String {
    coordinator_payload_root("MONERO-BRIDGE-LIQUIDITY-PUBLIC-RECORD-ID", record)
}

pub fn liquidity_maker_root(items: &[LiquidityMaker]) -> String {
    coordinator_record_root(
        "MONERO-BRIDGE-LIQUIDITY-MAKER-ROOT",
        items
            .iter()
            .map(LiquidityMaker::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn inventory_commitment_root(items: &[PrivateInventoryCommitment]) -> String {
    coordinator_record_root(
        "MONERO-BRIDGE-LIQUIDITY-INVENTORY-COMMITMENT-ROOT",
        items
            .iter()
            .map(PrivateInventoryCommitment::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn withdrawal_auction_root(items: &[WithdrawalAuction]) -> String {
    coordinator_record_root(
        "MONERO-BRIDGE-LIQUIDITY-WITHDRAWAL-AUCTION-ROOT",
        items
            .iter()
            .map(WithdrawalAuction::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn withdrawal_bid_root(items: &[WithdrawalBid]) -> String {
    coordinator_record_root(
        "MONERO-BRIDGE-LIQUIDITY-WITHDRAWAL-BID-ROOT",
        items
            .iter()
            .map(WithdrawalBid::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn settlement_route_root(items: &[SettlementRoute]) -> String {
    coordinator_record_root(
        "MONERO-BRIDGE-LIQUIDITY-SETTLEMENT-ROUTE-ROOT",
        items
            .iter()
            .map(SettlementRoute::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn replenishment_schedule_root(items: &[ReplenishmentSchedule]) -> String {
    coordinator_record_root(
        "MONERO-BRIDGE-LIQUIDITY-REPLENISHMENT-SCHEDULE-ROOT",
        items
            .iter()
            .map(ReplenishmentSchedule::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn low_fee_rebate_root(items: &[LowFeeRebate]) -> String {
    coordinator_record_root(
        "MONERO-BRIDGE-LIQUIDITY-LOW-FEE-REBATE-ROOT",
        items
            .iter()
            .map(LowFeeRebate::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn reserve_alert_root(items: &[ReserveAlert]) -> String {
    coordinator_record_root(
        "MONERO-BRIDGE-LIQUIDITY-RESERVE-ALERT-ROOT",
        items
            .iter()
            .map(ReserveAlert::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn watchtower_receipt_root(items: &[WatchtowerQuorumReceipt]) -> String {
    coordinator_record_root(
        "MONERO-BRIDGE-LIQUIDITY-WATCHTOWER-RECEIPT-ROOT",
        items
            .iter()
            .map(WatchtowerQuorumReceipt::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn circuit_breaker_root(items: &[EmergencyCircuitBreaker]) -> String {
    coordinator_record_root(
        "MONERO-BRIDGE-LIQUIDITY-CIRCUIT-BREAKER-ROOT",
        items
            .iter()
            .map(EmergencyCircuitBreaker::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn coordinator_public_record_root(
    items: &[MoneroBridgeLiquidityCoordinatorPublicRecord],
) -> String {
    coordinator_record_root(
        "MONERO-BRIDGE-LIQUIDITY-PUBLIC-RECORD-ROOT",
        items
            .iter()
            .map(MoneroBridgeLiquidityCoordinatorPublicRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

fn coordinator_record_root(domain: &str, mut records: Vec<Value>) -> String {
    records.sort_by(|left, right| left.to_string().cmp(&right.to_string()));
    stable_hash_hex(domain, &[HashPart::Json(&Value::Array(records))], 32)
}

fn coordinator_payload_root(domain: &str, payload: &Value) -> String {
    stable_hash_hex(domain, &[HashPart::Json(payload)], 32)
}

fn coordinator_string_root(domain: &str, value: &str) -> String {
    stable_hash_hex(domain, &[HashPart::Str(value)], 32)
}

fn coordinator_string_set_root(domain: &str, values: &[String]) -> String {
    let mut values = values.to_vec();
    values.sort();
    let leaves = values.into_iter().map(Value::String).collect::<Vec<_>>();
    stable_hash_hex(domain, &[HashPart::Json(&Value::Array(leaves))], 32)
}

fn coordinator_empty_root(domain: &str) -> String {
    stable_hash_hex(domain, &[HashPart::Str("empty")], 32)
}

fn with_root_field(mut record: Value, field: &str, root: String) -> Value {
    if let Value::Object(values) = &mut record {
        values.insert(field.to_string(), Value::String(root));
    }
    record
}

fn ensure_non_empty(value: &str, label: &str) -> MoneroBridgeLiquidityCoordinatorResult<()> {
    if value.is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> MoneroBridgeLiquidityCoordinatorResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> MoneroBridgeLiquidityCoordinatorResult<()> {
    if value > MONERO_BRIDGE_LIQUIDITY_COORDINATOR_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

fn ensure_expiry(
    opened_at_height: u64,
    expires_at_height: u64,
    label: &str,
) -> MoneroBridgeLiquidityCoordinatorResult<()> {
    if expires_at_height <= opened_at_height {
        Err(format!("{label} expiry must be after open height"))
    } else {
        Ok(())
    }
}
