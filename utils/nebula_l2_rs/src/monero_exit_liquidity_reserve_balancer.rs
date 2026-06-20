use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroExitLiquidityReserveBalancerResult<T> = Result<T, String>;

pub const MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_PROTOCOL_VERSION: &str =
    "nebula-monero-exit-liquidity-reserve-balancer-v1";
pub const MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_500;
pub const MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_DEFAULT_TARGET_RESERVE_COVERAGE_BPS: u64 = 12_000;
pub const MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_DEFAULT_EMERGENCY_RESERVE_BPS: u64 = 2_000;
pub const MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_DEFAULT_MAX_PROVIDER_FEE_BPS: u64 = 65;
pub const MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_DEFAULT_MAX_SPONSOR_FEE_BPS: u64 = 25;
pub const MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_DEFAULT_MAX_SETTLEMENT_LAG_BLOCKS: u64 = 6;
pub const MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_DEFAULT_MIN_PQ_SECURITY_BITS: u64 = 256;
pub const MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_DEFAULT_REBALANCE_TTL_BLOCKS: u64 = 48;
pub const MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_MAX_BPS: u64 = 10_000;
pub const MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_MAX_PROVIDERS: usize = 256;
pub const MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_MAX_WINDOWS: usize = 512;
pub const MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_MAX_SPONSORS: usize = 256;
pub const MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_MAX_ATTESTATIONS: usize = 1_024;
pub const MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_MAX_ACTIONS: usize = 1_024;
pub const MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_DEVNET_HEIGHT: u64 = 41_600;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveProviderKind {
    MarketMaker,
    BridgeVault,
    WatchtowerEscrow,
    EmergencyCouncil,
    FeeSponsor,
    CommunityVault,
}

impl ReserveProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MarketMaker => "market_maker",
            Self::BridgeVault => "bridge_vault",
            Self::WatchtowerEscrow => "watchtower_escrow",
            Self::EmergencyCouncil => "emergency_council",
            Self::FeeSponsor => "fee_sponsor",
            Self::CommunityVault => "community_vault",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitLaneKind {
    Standard,
    Fast,
    Sponsored,
    PrivateDex,
    Emergency,
}

impl ExitLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Fast => "fast",
            Self::Sponsored => "sponsored",
            Self::PrivateDex => "private_dex",
            Self::Emergency => "emergency",
        }
    }

    pub fn critical(self) -> bool {
        matches!(self, Self::Fast | Self::Sponsored | Self::Emergency)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebalanceActionKind {
    TopUpProvider,
    DrainProvider,
    RouteToSponsor,
    CapLaneFee,
    PauseProvider,
    EscalateEmergencyReserve,
}

impl RebalanceActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TopUpProvider => "top_up_provider",
            Self::DrainProvider => "drain_provider",
            Self::RouteToSponsor => "route_to_sponsor",
            Self::CapLaneFee => "cap_lane_fee",
            Self::PauseProvider => "pause_provider",
            Self::EscalateEmergencyReserve => "escalate_emergency_reserve",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveHealth {
    Healthy,
    Tight,
    UnderCovered,
    StaleAttestation,
    Emergency,
}

impl ReserveHealth {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Tight => "tight",
            Self::UnderCovered => "under_covered",
            Self::StaleAttestation => "stale_attestation",
            Self::Emergency => "emergency",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub min_reserve_coverage_bps: u64,
    pub target_reserve_coverage_bps: u64,
    pub emergency_reserve_bps: u64,
    pub max_provider_fee_bps: u64,
    pub max_sponsor_fee_bps: u64,
    pub max_settlement_lag_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u64,
    pub rebalance_ttl_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            min_reserve_coverage_bps:
                MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            target_reserve_coverage_bps:
                MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_DEFAULT_TARGET_RESERVE_COVERAGE_BPS,
            emergency_reserve_bps:
                MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_DEFAULT_EMERGENCY_RESERVE_BPS,
            max_provider_fee_bps:
                MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_DEFAULT_MAX_PROVIDER_FEE_BPS,
            max_sponsor_fee_bps: MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_DEFAULT_MAX_SPONSOR_FEE_BPS,
            max_settlement_lag_blocks:
                MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_DEFAULT_MAX_SETTLEMENT_LAG_BLOCKS,
            min_privacy_set_size:
                MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_DEFAULT_MIN_PQ_SECURITY_BITS,
            rebalance_ttl_blocks:
                MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_DEFAULT_REBALANCE_TTL_BLOCKS,
        }
    }

    pub fn validate(&self) -> MoneroExitLiquidityReserveBalancerResult<()> {
        if self.min_reserve_coverage_bps < MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_MAX_BPS {
            return Err("minimum reserve coverage must be at least full coverage".to_string());
        }
        if self.target_reserve_coverage_bps < self.min_reserve_coverage_bps {
            return Err("target reserve coverage cannot be below minimum".to_string());
        }
        if self.emergency_reserve_bps > MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_MAX_BPS {
            return Err("emergency reserve bps cannot exceed 100%".to_string());
        }
        if self.max_provider_fee_bps > MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_MAX_BPS {
            return Err("provider fee cap cannot exceed 100%".to_string());
        }
        if self.max_sponsor_fee_bps > self.max_provider_fee_bps {
            return Err("sponsor fee cap cannot exceed provider fee cap".to_string());
        }
        if self.max_settlement_lag_blocks == 0 {
            return Err("settlement lag must be positive".to_string());
        }
        if self.min_privacy_set_size == 0 {
            return Err("privacy set size must be positive".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("post-quantum security target is too low".to_string());
        }
        if self.rebalance_ttl_blocks == 0 {
            return Err("rebalance ttl must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_exit_liquidity_reserve_balancer_config",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_PROTOCOL_VERSION,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "target_reserve_coverage_bps": self.target_reserve_coverage_bps,
            "emergency_reserve_bps": self.emergency_reserve_bps,
            "max_provider_fee_bps": self.max_provider_fee_bps,
            "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
            "max_settlement_lag_blocks": self.max_settlement_lag_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "rebalance_ttl_blocks": self.rebalance_ttl_blocks,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveProvider {
    pub provider_id: String,
    pub provider_kind: ReserveProviderKind,
    pub label: String,
    pub liquidity_commitment: String,
    pub available_piconero: u64,
    pub locked_piconero: u64,
    pub max_exit_piconero: u64,
    pub fee_bps: u64,
    pub pq_security_bits: u64,
    pub privacy_set_size: u64,
    pub last_attested_height: u64,
    pub paused: bool,
}

impl ReserveProvider {
    pub fn new(
        provider_kind: ReserveProviderKind,
        label: &str,
        liquidity_commitment: &str,
        available_piconero: u64,
        locked_piconero: u64,
        max_exit_piconero: u64,
        fee_bps: u64,
        pq_security_bits: u64,
        privacy_set_size: u64,
        last_attested_height: u64,
        paused: bool,
    ) -> MoneroExitLiquidityReserveBalancerResult<Self> {
        if label.is_empty() {
            return Err("reserve provider label cannot be empty".to_string());
        }
        if liquidity_commitment.is_empty() {
            return Err("reserve provider liquidity commitment cannot be empty".to_string());
        }
        if max_exit_piconero == 0 {
            return Err("reserve provider max exit must be positive".to_string());
        }
        if fee_bps > MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_MAX_BPS {
            return Err("reserve provider fee cannot exceed 100%".to_string());
        }
        let provider_id = reserve_provider_id(
            provider_kind,
            label,
            liquidity_commitment,
            max_exit_piconero,
            pq_security_bits,
        );
        Ok(Self {
            provider_id,
            provider_kind,
            label: label.to_string(),
            liquidity_commitment: liquidity_commitment.to_string(),
            available_piconero,
            locked_piconero,
            max_exit_piconero,
            fee_bps,
            pq_security_bits,
            privacy_set_size,
            last_attested_height,
            paused,
        })
    }

    pub fn total_reserve(&self) -> u64 {
        self.available_piconero.saturating_add(self.locked_piconero)
    }

    pub fn spare_capacity(&self) -> u64 {
        if self.paused {
            0
        } else {
            self.available_piconero.min(self.max_exit_piconero)
        }
    }

    pub fn health(&self, config: &Config, current_height: u64) -> ReserveHealth {
        if self.paused {
            return ReserveHealth::Emergency;
        }
        if current_height.saturating_sub(self.last_attested_height)
            > config.max_settlement_lag_blocks
        {
            return ReserveHealth::StaleAttestation;
        }
        if self.pq_security_bits < config.min_pq_security_bits
            || self.privacy_set_size < config.min_privacy_set_size
            || self.fee_bps > config.max_provider_fee_bps
        {
            return ReserveHealth::Tight;
        }
        if self
            .available_piconero
            .saturating_mul(MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_MAX_BPS)
            < self
                .max_exit_piconero
                .saturating_mul(config.min_reserve_coverage_bps)
        {
            ReserveHealth::UnderCovered
        } else if self
            .available_piconero
            .saturating_mul(MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_MAX_BPS)
            < self
                .max_exit_piconero
                .saturating_mul(config.target_reserve_coverage_bps)
        {
            ReserveHealth::Tight
        } else {
            ReserveHealth::Healthy
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_exit_reserve_provider",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_PROTOCOL_VERSION,
            "provider_id": self.provider_id,
            "provider_kind": self.provider_kind.as_str(),
            "label": self.label,
            "liquidity_commitment": self.liquidity_commitment,
            "available_piconero": self.available_piconero,
            "locked_piconero": self.locked_piconero,
            "max_exit_piconero": self.max_exit_piconero,
            "fee_bps": self.fee_bps,
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "last_attested_height": self.last_attested_height,
            "paused": self.paused,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitDemandWindow {
    pub window_id: String,
    pub lane_kind: ExitLaneKind,
    pub height_start: u64,
    pub height_end: u64,
    pub demand_commitment: String,
    pub requested_piconero: u64,
    pub max_fee_bps: u64,
    pub anonymity_set_size: u64,
    pub urgent: bool,
}

impl ExitDemandWindow {
    pub fn new(
        lane_kind: ExitLaneKind,
        height_start: u64,
        height_end: u64,
        demand_commitment: &str,
        requested_piconero: u64,
        max_fee_bps: u64,
        anonymity_set_size: u64,
        urgent: bool,
    ) -> MoneroExitLiquidityReserveBalancerResult<Self> {
        if height_end <= height_start {
            return Err("exit demand window must end after it starts".to_string());
        }
        if demand_commitment.is_empty() {
            return Err("exit demand commitment cannot be empty".to_string());
        }
        if requested_piconero == 0 {
            return Err("exit demand must be positive".to_string());
        }
        if max_fee_bps > MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_MAX_BPS {
            return Err("exit demand fee cap cannot exceed 100%".to_string());
        }
        let window_id = exit_demand_window_id(
            lane_kind,
            height_start,
            height_end,
            demand_commitment,
            requested_piconero,
            max_fee_bps,
        );
        Ok(Self {
            window_id,
            lane_kind,
            height_start,
            height_end,
            demand_commitment: demand_commitment.to_string(),
            requested_piconero,
            max_fee_bps,
            anonymity_set_size,
            urgent,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.height_start <= height && height <= self.height_end
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_exit_demand_window",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_PROTOCOL_VERSION,
            "window_id": self.window_id,
            "lane_kind": self.lane_kind.as_str(),
            "height_start": self.height_start,
            "height_end": self.height_end,
            "demand_commitment": self.demand_commitment,
            "requested_piconero": self.requested_piconero,
            "max_fee_bps": self.max_fee_bps,
            "anonymity_set_size": self.anonymity_set_size,
            "urgent": self.urgent,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorLane {
    pub sponsor_id: String,
    pub label: String,
    pub fee_credit_commitment: String,
    pub max_sponsored_piconero: u64,
    pub remaining_credit_piconero: u64,
    pub fee_bps: u64,
    pub allowed_lanes: BTreeSet<ExitLaneKind>,
}

impl SponsorLane {
    pub fn new(
        label: &str,
        fee_credit_commitment: &str,
        max_sponsored_piconero: u64,
        remaining_credit_piconero: u64,
        fee_bps: u64,
        allowed_lanes: BTreeSet<ExitLaneKind>,
    ) -> MoneroExitLiquidityReserveBalancerResult<Self> {
        if label.is_empty() {
            return Err("sponsor lane label cannot be empty".to_string());
        }
        if fee_credit_commitment.is_empty() {
            return Err("sponsor fee credit commitment cannot be empty".to_string());
        }
        if max_sponsored_piconero == 0 {
            return Err("sponsor max amount must be positive".to_string());
        }
        if remaining_credit_piconero > max_sponsored_piconero {
            return Err("sponsor remaining credit cannot exceed max amount".to_string());
        }
        if fee_bps > MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_MAX_BPS {
            return Err("sponsor fee cannot exceed 100%".to_string());
        }
        if allowed_lanes.is_empty() {
            return Err("sponsor lane set cannot be empty".to_string());
        }
        let sponsor_id = sponsor_lane_id(
            label,
            fee_credit_commitment,
            max_sponsored_piconero,
            fee_bps,
            &allowed_lanes,
        );
        Ok(Self {
            sponsor_id,
            label: label.to_string(),
            fee_credit_commitment: fee_credit_commitment.to_string(),
            max_sponsored_piconero,
            remaining_credit_piconero,
            fee_bps,
            allowed_lanes,
        })
    }

    pub fn can_sponsor(&self, window: &ExitDemandWindow, config: &Config) -> bool {
        self.allowed_lanes.contains(&window.lane_kind)
            && self.remaining_credit_piconero >= window.requested_piconero
            && self.fee_bps <= config.max_sponsor_fee_bps
            && self.fee_bps <= window.max_fee_bps
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_exit_sponsor_lane",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_PROTOCOL_VERSION,
            "sponsor_id": self.sponsor_id,
            "label": self.label,
            "fee_credit_commitment": self.fee_credit_commitment,
            "max_sponsored_piconero": self.max_sponsored_piconero,
            "remaining_credit_piconero": self.remaining_credit_piconero,
            "fee_bps": self.fee_bps,
            "allowed_lanes": self.allowed_lanes.iter().map(|lane| lane.as_str()).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveAttestation {
    pub attestation_id: String,
    pub provider_id: String,
    pub height: u64,
    pub monero_view_commitment: String,
    pub pq_signature_root: String,
    pub reserve_commitment: String,
    pub observed_piconero: u64,
}

impl ReserveAttestation {
    pub fn new(
        provider_id: &str,
        height: u64,
        monero_view_commitment: &str,
        pq_signature_root: &str,
        reserve_commitment: &str,
        observed_piconero: u64,
    ) -> MoneroExitLiquidityReserveBalancerResult<Self> {
        if provider_id.is_empty()
            || monero_view_commitment.is_empty()
            || pq_signature_root.is_empty()
            || reserve_commitment.is_empty()
        {
            return Err("reserve attestation identifiers cannot be empty".to_string());
        }
        let attestation_id = reserve_attestation_id(
            provider_id,
            height,
            monero_view_commitment,
            pq_signature_root,
            reserve_commitment,
            observed_piconero,
        );
        Ok(Self {
            attestation_id,
            provider_id: provider_id.to_string(),
            height,
            monero_view_commitment: monero_view_commitment.to_string(),
            pq_signature_root: pq_signature_root.to_string(),
            reserve_commitment: reserve_commitment.to_string(),
            observed_piconero,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_exit_reserve_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "provider_id": self.provider_id,
            "height": self.height,
            "monero_view_commitment": self.monero_view_commitment,
            "pq_signature_root": self.pq_signature_root,
            "reserve_commitment": self.reserve_commitment,
            "observed_piconero": self.observed_piconero,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebalanceAction {
    pub action_id: String,
    pub action_kind: RebalanceActionKind,
    pub provider_id: String,
    pub window_id: String,
    pub sponsor_id: Option<String>,
    pub amount_piconero: u64,
    pub reason_root: String,
    pub expires_at_height: u64,
}

impl RebalanceAction {
    pub fn new(
        action_kind: RebalanceActionKind,
        provider_id: &str,
        window_id: &str,
        sponsor_id: Option<String>,
        amount_piconero: u64,
        reason: &Value,
        expires_at_height: u64,
    ) -> MoneroExitLiquidityReserveBalancerResult<Self> {
        if provider_id.is_empty() || window_id.is_empty() {
            return Err("rebalance action identifiers cannot be empty".to_string());
        }
        if amount_piconero == 0 {
            return Err("rebalance action amount must be positive".to_string());
        }
        let sponsor_label = sponsor_id.as_deref().unwrap_or("none");
        let reason_root = monero_exit_liquidity_reserve_balancer_payload_root(
            "MONERO-EXIT-LIQUIDITY-REBALANCE-REASON",
            reason,
        );
        let action_id = rebalance_action_id(
            action_kind,
            provider_id,
            window_id,
            sponsor_label,
            amount_piconero,
            &reason_root,
            expires_at_height,
        );
        Ok(Self {
            action_id,
            action_kind,
            provider_id: provider_id.to_string(),
            window_id: window_id.to_string(),
            sponsor_id,
            amount_piconero,
            reason_root,
            expires_at_height,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_exit_liquidity_rebalance_action",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_PROTOCOL_VERSION,
            "action_id": self.action_id,
            "action_kind": self.action_kind.as_str(),
            "provider_id": self.provider_id,
            "window_id": self.window_id,
            "sponsor_id": self.sponsor_id,
            "amount_piconero": self.amount_piconero,
            "reason_root": self.reason_root,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub provider_root: String,
    pub demand_root: String,
    pub sponsor_root: String,
    pub attestation_root: String,
    pub action_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "provider_root": self.provider_root,
            "demand_root": self.demand_root,
            "sponsor_root": self.sponsor_root,
            "attestation_root": self.attestation_root,
            "action_root": self.action_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub provider_count: u64,
    pub demand_window_count: u64,
    pub sponsor_count: u64,
    pub attestation_count: u64,
    pub action_count: u64,
    pub total_available_piconero: u64,
    pub total_requested_piconero: u64,
    pub active_emergency_actions: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "provider_count": self.provider_count,
            "demand_window_count": self.demand_window_count,
            "sponsor_count": self.sponsor_count,
            "attestation_count": self.attestation_count,
            "action_count": self.action_count,
            "total_available_piconero": self.total_available_piconero,
            "total_requested_piconero": self.total_requested_piconero,
            "active_emergency_actions": self.active_emergency_actions,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub providers: BTreeMap<String, ReserveProvider>,
    pub demand_windows: BTreeMap<String, ExitDemandWindow>,
    pub sponsors: BTreeMap<String, SponsorLane>,
    pub attestations: BTreeMap<String, ReserveAttestation>,
    pub actions: BTreeMap<String, RebalanceAction>,
    pub roots: Roots,
    pub counters: Counters,
    pub state_root: String,
}

impl State {
    pub fn new(height: u64, config: Config) -> MoneroExitLiquidityReserveBalancerResult<Self> {
        config.validate()?;
        let mut state = Self {
            height,
            config,
            providers: BTreeMap::new(),
            demand_windows: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            attestations: BTreeMap::new(),
            actions: BTreeMap::new(),
            roots: Roots {
                config_root: String::new(),
                provider_root: String::new(),
                demand_root: String::new(),
                sponsor_root: String::new(),
                attestation_root: String::new(),
                action_root: String::new(),
            },
            counters: Counters {
                provider_count: 0,
                demand_window_count: 0,
                sponsor_count: 0,
                attestation_count: 0,
                action_count: 0,
                total_available_piconero: 0,
                total_requested_piconero: 0,
                active_emergency_actions: 0,
            },
            state_root: String::new(),
        };
        state.refresh();
        Ok(state)
    }

    pub fn insert_provider(
        &mut self,
        provider: ReserveProvider,
    ) -> MoneroExitLiquidityReserveBalancerResult<()> {
        if self.providers.len() >= MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_MAX_PROVIDERS {
            return Err("reserve provider limit exceeded".to_string());
        }
        provider.health(&self.config, self.height);
        self.providers
            .insert(provider.provider_id.clone(), provider);
        self.refresh();
        Ok(())
    }

    pub fn insert_demand_window(
        &mut self,
        window: ExitDemandWindow,
    ) -> MoneroExitLiquidityReserveBalancerResult<()> {
        if self.demand_windows.len() >= MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_MAX_WINDOWS {
            return Err("exit demand window limit exceeded".to_string());
        }
        if window.anonymity_set_size < self.config.min_privacy_set_size {
            return Err("exit demand anonymity set below configured floor".to_string());
        }
        self.demand_windows.insert(window.window_id.clone(), window);
        self.refresh();
        Ok(())
    }

    pub fn insert_sponsor(
        &mut self,
        sponsor: SponsorLane,
    ) -> MoneroExitLiquidityReserveBalancerResult<()> {
        if self.sponsors.len() >= MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_MAX_SPONSORS {
            return Err("sponsor lane limit exceeded".to_string());
        }
        if sponsor.fee_bps > self.config.max_sponsor_fee_bps {
            return Err("sponsor lane fee exceeds configured cap".to_string());
        }
        self.sponsors.insert(sponsor.sponsor_id.clone(), sponsor);
        self.refresh();
        Ok(())
    }

    pub fn insert_attestation(
        &mut self,
        attestation: ReserveAttestation,
    ) -> MoneroExitLiquidityReserveBalancerResult<()> {
        if self.attestations.len() >= MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_MAX_ATTESTATIONS {
            return Err("reserve attestation limit exceeded".to_string());
        }
        if !self.providers.contains_key(&attestation.provider_id) {
            return Err("reserve attestation references unknown provider".to_string());
        }
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh();
        Ok(())
    }

    pub fn insert_action(
        &mut self,
        action: RebalanceAction,
    ) -> MoneroExitLiquidityReserveBalancerResult<()> {
        if self.actions.len() >= MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_MAX_ACTIONS {
            return Err("rebalance action limit exceeded".to_string());
        }
        if !self.providers.contains_key(&action.provider_id) {
            return Err("rebalance action references unknown provider".to_string());
        }
        if !self.demand_windows.contains_key(&action.window_id) {
            return Err("rebalance action references unknown demand window".to_string());
        }
        if let Some(sponsor_id) = &action.sponsor_id {
            if !self.sponsors.contains_key(sponsor_id) {
                return Err("rebalance action references unknown sponsor".to_string());
            }
        }
        self.actions.insert(action.action_id.clone(), action);
        self.refresh();
        Ok(())
    }

    pub fn active_demand_piconero(&self) -> u64 {
        self.demand_windows
            .values()
            .filter(|window| window.active_at(self.height))
            .map(|window| window.requested_piconero)
            .fold(0_u64, u64::saturating_add)
    }

    pub fn available_reserve_piconero(&self) -> u64 {
        self.providers
            .values()
            .map(ReserveProvider::spare_capacity)
            .fold(0_u64, u64::saturating_add)
    }

    pub fn coverage_bps(&self) -> u64 {
        let demand = self.active_demand_piconero();
        if demand == 0 {
            return self.config.target_reserve_coverage_bps;
        }
        self.available_reserve_piconero()
            .saturating_mul(MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_MAX_BPS)
            / demand
    }

    pub fn under_covered_providers(&self) -> Vec<String> {
        self.providers
            .values()
            .filter(|provider| {
                matches!(
                    provider.health(&self.config, self.height),
                    ReserveHealth::UnderCovered
                        | ReserveHealth::StaleAttestation
                        | ReserveHealth::Emergency
                )
            })
            .map(|provider| provider.provider_id.clone())
            .collect()
    }

    pub fn recommend_actions(
        &self,
    ) -> MoneroExitLiquidityReserveBalancerResult<Vec<RebalanceAction>> {
        let mut actions = Vec::new();
        for window in self
            .demand_windows
            .values()
            .filter(|window| window.active_at(self.height))
        {
            let provider = self
                .providers
                .values()
                .filter(|provider| !provider.paused && provider.fee_bps <= window.max_fee_bps)
                .max_by_key(|provider| provider.spare_capacity());
            let Some(provider) = provider else {
                continue;
            };
            let sponsor = self
                .sponsors
                .values()
                .find(|sponsor| sponsor.can_sponsor(window, &self.config));
            let action_kind = if window.lane_kind == ExitLaneKind::Emergency {
                RebalanceActionKind::EscalateEmergencyReserve
            } else if sponsor.is_some() {
                RebalanceActionKind::RouteToSponsor
            } else {
                RebalanceActionKind::TopUpProvider
            };
            let sponsor_id = sponsor.map(|sponsor| sponsor.sponsor_id.clone());
            let amount = provider.spare_capacity().min(window.requested_piconero);
            if amount == 0 {
                continue;
            }
            actions.push(RebalanceAction::new(
                action_kind,
                &provider.provider_id,
                &window.window_id,
                sponsor_id,
                amount,
                &json!({
                    "window_lane": window.lane_kind.as_str(),
                    "provider_health": provider.health(&self.config, self.height).as_str(),
                    "coverage_bps": self.coverage_bps(),
                }),
                self.height.saturating_add(self.config.rebalance_ttl_blocks),
            )?);
        }
        Ok(actions)
    }

    pub fn refresh(&mut self) {
        self.roots = Roots {
            config_root: monero_exit_liquidity_reserve_balancer_payload_root(
                "MONERO-EXIT-LIQUIDITY-CONFIG",
                &self.config.public_record(),
            ),
            provider_root: reserve_provider_root(
                &self.providers.values().cloned().collect::<Vec<_>>(),
            ),
            demand_root: exit_demand_window_root(
                &self.demand_windows.values().cloned().collect::<Vec<_>>(),
            ),
            sponsor_root: sponsor_lane_root(&self.sponsors.values().cloned().collect::<Vec<_>>()),
            attestation_root: reserve_attestation_root(
                &self.attestations.values().cloned().collect::<Vec<_>>(),
            ),
            action_root: rebalance_action_root(&self.actions.values().cloned().collect::<Vec<_>>()),
        };
        self.counters = Counters {
            provider_count: self.providers.len() as u64,
            demand_window_count: self.demand_windows.len() as u64,
            sponsor_count: self.sponsors.len() as u64,
            attestation_count: self.attestations.len() as u64,
            action_count: self.actions.len() as u64,
            total_available_piconero: self.available_reserve_piconero(),
            total_requested_piconero: self.active_demand_piconero(),
            active_emergency_actions: self
                .actions
                .values()
                .filter(|action| {
                    action.active_at(self.height)
                        && action.action_kind == RebalanceActionKind::EscalateEmergencyReserve
                })
                .count() as u64,
        };
        self.state_root = root_from_record(&self.public_record_without_state_root());
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "monero_exit_liquidity_reserve_balancer_state",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_PROTOCOL_VERSION,
            "height": self.height,
            "roots": self.roots.public_record(),
            "counters": self.counters.public_record(),
            "coverage_bps": self.coverage_bps(),
            "under_covered_providers": self.under_covered_providers(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut values) = record {
            values.insert("state_root".to_string(), json!(self.state_root));
        }
        record
    }

    pub fn devnet() -> MoneroExitLiquidityReserveBalancerResult<Self> {
        let mut state = Self::new(
            MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_DEVNET_HEIGHT,
            Config::devnet(),
        )?;
        let primary = ReserveProvider::new(
            ReserveProviderKind::MarketMaker,
            "devnet-primary-fast-exit",
            "liq-commitment-primary-fast-exit",
            28_000_000_000_000,
            4_000_000_000_000,
            18_000_000_000_000,
            38,
            256,
            512,
            MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_DEVNET_HEIGHT,
            false,
        )?;
        let emergency = ReserveProvider::new(
            ReserveProviderKind::EmergencyCouncil,
            "devnet-emergency-exit-vault",
            "liq-commitment-emergency-exit",
            8_500_000_000_000,
            1_000_000_000_000,
            6_000_000_000_000,
            0,
            256,
            384,
            MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_DEVNET_HEIGHT.saturating_sub(1),
            false,
        )?;
        state.insert_provider(primary.clone())?;
        state.insert_provider(emergency.clone())?;
        let fast_window = ExitDemandWindow::new(
            ExitLaneKind::Fast,
            MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_DEVNET_HEIGHT.saturating_sub(2),
            MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_DEVNET_HEIGHT.saturating_add(8),
            "demand-commitment-fast-exits-devnet",
            9_000_000_000_000,
            45,
            256,
            true,
        )?;
        let emergency_window = ExitDemandWindow::new(
            ExitLaneKind::Emergency,
            MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_DEVNET_HEIGHT,
            MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_DEVNET_HEIGHT.saturating_add(12),
            "demand-commitment-emergency-exits-devnet",
            3_000_000_000_000,
            0,
            384,
            true,
        )?;
        state.insert_demand_window(fast_window)?;
        state.insert_demand_window(emergency_window)?;
        let mut lanes = BTreeSet::new();
        lanes.insert(ExitLaneKind::Fast);
        lanes.insert(ExitLaneKind::Sponsored);
        state.insert_sponsor(SponsorLane::new(
            "devnet-fee-credit-sponsor",
            "fee-credit-commitment-devnet",
            10_000_000_000_000,
            9_500_000_000_000,
            12,
            lanes,
        )?)?;
        state.insert_attestation(ReserveAttestation::new(
            &primary.provider_id,
            MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_DEVNET_HEIGHT,
            "monero-view-commitment-primary",
            "pq-signature-root-primary",
            "reserve-commitment-primary",
            primary.total_reserve(),
        )?)?;
        state.insert_attestation(ReserveAttestation::new(
            &emergency.provider_id,
            MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_DEVNET_HEIGHT,
            "monero-view-commitment-emergency",
            "pq-signature-root-emergency",
            "reserve-commitment-emergency",
            emergency.total_reserve(),
        )?)?;
        for action in state.recommend_actions()? {
            state.insert_action(action)?;
        }
        Ok(state)
    }
}

pub fn reserve_provider_id(
    provider_kind: ReserveProviderKind,
    label: &str,
    liquidity_commitment: &str,
    max_exit_piconero: u64,
    pq_security_bits: u64,
) -> String {
    domain_hash(
        "MONERO-EXIT-LIQUIDITY-RESERVE-PROVIDER-ID",
        &[
            HashPart::Str(MONERO_EXIT_LIQUIDITY_RESERVE_BALANCER_PROTOCOL_VERSION),
            HashPart::Str(provider_kind.as_str()),
            HashPart::Str(label),
            HashPart::Str(liquidity_commitment),
            HashPart::Int(max_exit_piconero as i128),
            HashPart::Int(pq_security_bits as i128),
        ],
        32,
    )
}

pub fn exit_demand_window_id(
    lane_kind: ExitLaneKind,
    height_start: u64,
    height_end: u64,
    demand_commitment: &str,
    requested_piconero: u64,
    max_fee_bps: u64,
) -> String {
    domain_hash(
        "MONERO-EXIT-LIQUIDITY-DEMAND-WINDOW-ID",
        &[
            HashPart::Str(lane_kind.as_str()),
            HashPart::Int(height_start as i128),
            HashPart::Int(height_end as i128),
            HashPart::Str(demand_commitment),
            HashPart::Int(requested_piconero as i128),
            HashPart::Int(max_fee_bps as i128),
        ],
        32,
    )
}

pub fn sponsor_lane_id(
    label: &str,
    fee_credit_commitment: &str,
    max_sponsored_piconero: u64,
    fee_bps: u64,
    allowed_lanes: &BTreeSet<ExitLaneKind>,
) -> String {
    let lanes = allowed_lanes
        .iter()
        .map(|lane| lane.as_str())
        .collect::<Vec<_>>()
        .join(",");
    domain_hash(
        "MONERO-EXIT-LIQUIDITY-SPONSOR-LANE-ID",
        &[
            HashPart::Str(label),
            HashPart::Str(fee_credit_commitment),
            HashPart::Int(max_sponsored_piconero as i128),
            HashPart::Int(fee_bps as i128),
            HashPart::Str(&lanes),
        ],
        32,
    )
}

pub fn reserve_attestation_id(
    provider_id: &str,
    height: u64,
    monero_view_commitment: &str,
    pq_signature_root: &str,
    reserve_commitment: &str,
    observed_piconero: u64,
) -> String {
    domain_hash(
        "MONERO-EXIT-LIQUIDITY-RESERVE-ATTESTATION-ID",
        &[
            HashPart::Str(provider_id),
            HashPart::Int(height as i128),
            HashPart::Str(monero_view_commitment),
            HashPart::Str(pq_signature_root),
            HashPart::Str(reserve_commitment),
            HashPart::Int(observed_piconero as i128),
        ],
        32,
    )
}

pub fn rebalance_action_id(
    action_kind: RebalanceActionKind,
    provider_id: &str,
    window_id: &str,
    sponsor_id: &str,
    amount_piconero: u64,
    reason_root: &str,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-EXIT-LIQUIDITY-REBALANCE-ACTION-ID",
        &[
            HashPart::Str(action_kind.as_str()),
            HashPart::Str(provider_id),
            HashPart::Str(window_id),
            HashPart::Str(sponsor_id),
            HashPart::Int(amount_piconero as i128),
            HashPart::Str(reason_root),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

pub fn reserve_provider_root(providers: &[ReserveProvider]) -> String {
    let leaves = providers
        .iter()
        .map(ReserveProvider::public_record)
        .collect::<Vec<_>>();
    merkle_root("MONERO-EXIT-LIQUIDITY-RESERVE-PROVIDERS", &leaves)
}

pub fn exit_demand_window_root(windows: &[ExitDemandWindow]) -> String {
    let leaves = windows
        .iter()
        .map(ExitDemandWindow::public_record)
        .collect::<Vec<_>>();
    merkle_root("MONERO-EXIT-LIQUIDITY-DEMAND-WINDOWS", &leaves)
}

pub fn sponsor_lane_root(sponsors: &[SponsorLane]) -> String {
    let leaves = sponsors
        .iter()
        .map(SponsorLane::public_record)
        .collect::<Vec<_>>();
    merkle_root("MONERO-EXIT-LIQUIDITY-SPONSOR-LANES", &leaves)
}

pub fn reserve_attestation_root(attestations: &[ReserveAttestation]) -> String {
    let leaves = attestations
        .iter()
        .map(ReserveAttestation::public_record)
        .collect::<Vec<_>>();
    merkle_root("MONERO-EXIT-LIQUIDITY-RESERVE-ATTESTATIONS", &leaves)
}

pub fn rebalance_action_root(actions: &[RebalanceAction]) -> String {
    let leaves = actions
        .iter()
        .map(RebalanceAction::public_record)
        .collect::<Vec<_>>();
    merkle_root("MONERO-EXIT-LIQUIDITY-REBALANCE-ACTIONS", &leaves)
}

pub fn monero_exit_liquidity_reserve_balancer_payload_root(
    domain: &str,
    payload: &Value,
) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "MONERO-EXIT-LIQUIDITY-RESERVE-BALANCER-STATE-ROOT",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn devnet() -> MoneroExitLiquidityReserveBalancerResult<State> {
    State::devnet()
}
