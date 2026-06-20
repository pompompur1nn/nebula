use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialBridgeReorgLiquidityCircuitBreakerRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-bridge-reorg-liquidity-circuit-breaker-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_BRIDGE_REORG_LIQUIDITY_CIRCUIT_BREAKER_RUNTIME_PROTOCOL_VERSION:
    &str = PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_BREAKER_SUITE: &str = "ML-DSA-87+ML-KEM-1024+SLH-DSA-SHAKE-256f";
pub const BREAKER_SUITE: &str = "confidential-monero-bridge-reorg-liquidity-circuit-root-v1";
pub const INCIDENT_SUITE: &str = "confidential-bridge-reorg-incident-root-v1";
pub const REBATE_SUITE: &str = "bridge-reorg-liquidity-circuit-low-fee-rebate-root-v1";
pub const REDACTION_SUITE: &str = "operator-safe-bridge-reorg-liquidity-redaction-root-v1";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_LIQUIDITY_ASSET_ID: &str = "xmr-reorg-liquidity-backstop-note-devnet";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_INCIDENT_WINDOW_SLOTS: u64 = 144;
pub const DEFAULT_RECOVERY_WINDOW_SLOTS: u64 = 720;
pub const DEFAULT_MAX_ROUTE_FEE_BPS: u64 = 24;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 8;
pub const DEFAULT_MIN_POOL_RESERVE_MICRO_UNITS: u64 = 160_000_000;
pub const DEFAULT_MIN_ROUTE_LIQUIDITY_MICRO_UNITS: u64 = 8_000_000;
pub const DEFAULT_MIN_ATTESTATION_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_ATTESTATION_QUORUM_BPS: u64 = 8_400;
pub const DEFAULT_MAX_REORG_DEPTH: u64 = 32;
pub const DEFAULT_MAX_PUBLIC_REDACTION_BYTES: u64 = 2_048;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_POOLS: usize = 524_288;
pub const MAX_ROUTES: usize = 1_048_576;
pub const MAX_INCIDENTS: usize = 2_097_152;
pub const MAX_ATTESTATIONS: usize = 4_194_304;
pub const MAX_SETTLEMENTS: usize = 1_048_576;
pub const MAX_REBATES: usize = 1_048_576;
pub const MAX_REDACTION_BUDGETS: usize = 524_288;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const DEVNET_EPOCH: u64 = 7_904;
pub const DEVNET_SLOT: u64 = 251;
pub const DEVNET_L2_HEIGHT: u64 = 3_392_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakerScope {
    DepositFinality,
    WithdrawalQueue,
    FastExitLiquidity,
    ReserveProofWindow,
    AtomicSwapEscrow,
    EmergencyExitLane,
    WatchtowerDispute,
    FeeSponsorReserve,
}

impl BreakerScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositFinality => "deposit_finality",
            Self::WithdrawalQueue => "withdrawal_queue",
            Self::FastExitLiquidity => "fast_exit_liquidity",
            Self::ReserveProofWindow => "reserve_proof_window",
            Self::AtomicSwapEscrow => "atomic_swap_escrow",
            Self::EmergencyExitLane => "emergency_exit_lane",
            Self::WatchtowerDispute => "watchtower_dispute",
            Self::FeeSponsorReserve => "fee_sponsor_reserve",
        }
    }

    pub fn risk_weight(self) -> u64 {
        match self {
            Self::EmergencyExitLane => 10,
            Self::WithdrawalQueue => 9,
            Self::FastExitLiquidity => 8,
            Self::DepositFinality => 7,
            Self::ReserveProofWindow => 7,
            Self::WatchtowerDispute => 6,
            Self::AtomicSwapEscrow => 5,
            Self::FeeSponsorReserve => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Planned,
    Active,
    Throttled,
    BreakerEngaged,
    RecoveryOnly,
    Quarantined,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteStatus {
    Candidate,
    Active,
    Throttled,
    Paused,
    Draining,
    Quarantined,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    Submitted,
    EvidenceLocked,
    Attested,
    BreakerEngaged,
    Settled,
    RebateIssued,
    Rejected,
    Expired,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReorgSeverity {
    Observation,
    Shallow,
    Moderate,
    Deep,
    Catastrophic,
}

impl ReorgSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observation => "observation",
            Self::Shallow => "shallow",
            Self::Moderate => "moderate",
            Self::Deep => "deep",
            Self::Catastrophic => "catastrophic",
        }
    }

    pub fn weight(self) -> u64 {
        match self {
            Self::Observation => 1,
            Self::Shallow => 3,
            Self::Moderate => 6,
            Self::Deep => 9,
            Self::Catastrophic => 12,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PqWatcherSignatureVerified,
    ReorgDepthObserved,
    BridgeReceiptChecked,
    LiquidityReserveChecked,
    RoutePauseSafe,
    FeeCapObserved,
    PrivacyBoundaryObserved,
    RecoverySafe,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqWatcherSignatureVerified => "pq_watcher_signature_verified",
            Self::ReorgDepthObserved => "reorg_depth_observed",
            Self::BridgeReceiptChecked => "bridge_receipt_checked",
            Self::LiquidityReserveChecked => "liquidity_reserve_checked",
            Self::RoutePauseSafe => "route_pause_safe",
            Self::FeeCapObserved => "fee_cap_observed",
            Self::PrivacyBoundaryObserved => "privacy_boundary_observed",
            Self::RecoverySafe => "recovery_safe",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementDecision {
    EngageBreaker,
    EngageBreakerWithRebate,
    PartialThrottle,
    Recover,
    Reject,
    Quarantine,
    Expire,
}

impl SettlementDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EngageBreaker => "engage_breaker",
            Self::EngageBreakerWithRebate => "engage_breaker_with_rebate",
            Self::PartialThrottle => "partial_throttle",
            Self::Recover => "recover",
            Self::Reject => "reject",
            Self::Quarantine => "quarantine",
            Self::Expire => "expire",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub hash_suite: String,
    pub pq_breaker_suite: String,
    pub breaker_suite: String,
    pub incident_suite: String,
    pub rebate_suite: String,
    pub redaction_suite: String,
    pub fee_asset_id: String,
    pub liquidity_asset_id: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub incident_window_slots: u64,
    pub recovery_window_slots: u64,
    pub max_route_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub min_pool_reserve_micro_units: u64,
    pub min_route_liquidity_micro_units: u64,
    pub min_attestation_quorum_bps: u64,
    pub strong_attestation_quorum_bps: u64,
    pub max_reorg_depth: u64,
    pub max_public_redaction_bytes: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_breaker_suite: PQ_BREAKER_SUITE.to_string(),
            breaker_suite: BREAKER_SUITE.to_string(),
            incident_suite: INCIDENT_SUITE.to_string(),
            rebate_suite: REBATE_SUITE.to_string(),
            redaction_suite: REDACTION_SUITE.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            liquidity_asset_id: DEFAULT_LIQUIDITY_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            incident_window_slots: DEFAULT_INCIDENT_WINDOW_SLOTS,
            recovery_window_slots: DEFAULT_RECOVERY_WINDOW_SLOTS,
            max_route_fee_bps: DEFAULT_MAX_ROUTE_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            min_pool_reserve_micro_units: DEFAULT_MIN_POOL_RESERVE_MICRO_UNITS,
            min_route_liquidity_micro_units: DEFAULT_MIN_ROUTE_LIQUIDITY_MICRO_UNITS,
            min_attestation_quorum_bps: DEFAULT_MIN_ATTESTATION_QUORUM_BPS,
            strong_attestation_quorum_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
            max_reorg_depth: DEFAULT_MAX_REORG_DEPTH,
            max_public_redaction_bytes: DEFAULT_MAX_PUBLIC_REDACTION_BYTES,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub pools_opened: u64,
    pub routes_registered: u64,
    pub incidents_submitted: u64,
    pub attestations_recorded: u64,
    pub settlements_recorded: u64,
    pub rebates_issued: u64,
    pub redaction_budgets_published: u64,
    pub operator_summaries_published: u64,
    pub breakers_engaged: u64,
    pub quarantines: u64,
    pub total_reserve_micro_units: u64,
    pub total_route_liquidity_micro_units: u64,
    pub total_paused_liquidity_micro_units: u64,
    pub total_rebated_micro_units: u64,
    pub max_observed_reorg_depth: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub pool_root: String,
    pub route_root: String,
    pub incident_root: String,
    pub attestation_root: String,
    pub settlement_root: String,
    pub rebate_root: String,
    pub redaction_root: String,
    pub operator_summary_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            config_root: empty_root("config"),
            pool_root: empty_root("pools"),
            route_root: empty_root("routes"),
            incident_root: empty_root("incidents"),
            attestation_root: empty_root("attestations"),
            settlement_root: empty_root("settlements"),
            rebate_root: empty_root("rebates"),
            redaction_root: empty_root("redactions"),
            operator_summary_root: empty_root("operator-summaries"),
            counters_root: empty_root("counters"),
            state_root: empty_root("state"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BreakerPool {
    pub pool_id: String,
    pub scope: BreakerScope,
    pub status: PoolStatus,
    pub sealed_pool_root: String,
    pub public_hint_root: String,
    pub reserve_commitment_root: String,
    pub reserve_micro_units: u64,
    pub active_route_count: u64,
    pub paused_route_count: u64,
    pub max_route_fee_bps: u64,
    pub reorg_depth_threshold: u64,
    pub opened_slot: u64,
    pub last_updated_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityRoute {
    pub route_id: String,
    pub pool_id: String,
    pub status: RouteStatus,
    pub route_commitment_root: String,
    pub liquidity_commitment_root: String,
    pub provider_commitment: String,
    pub available_liquidity_micro_units: u64,
    pub paused_liquidity_micro_units: u64,
    pub fee_cap_bps: u64,
    pub privacy_set_size: u64,
    pub registered_slot: u64,
    pub incident_count: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReorgIncident {
    pub incident_id: String,
    pub pool_id: String,
    pub route_id: String,
    pub severity: ReorgSeverity,
    pub status: IncidentStatus,
    pub sealed_evidence_root: String,
    pub redacted_evidence_root: String,
    pub bridge_receipt_root: String,
    pub observed_reorg_depth: u64,
    pub requested_pause_bps: u64,
    pub requested_rebate_bps: u64,
    pub submitted_slot: u64,
    pub expires_slot: u64,
    pub attestation_count: u64,
    pub quorum_weight_bps: u64,
    pub settled_slot: Option<u64>,
    pub settlement_decision: Option<SettlementDecision>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BreakerAttestation {
    pub attestation_id: String,
    pub incident_id: String,
    pub kind: AttestationKind,
    pub committee_root: String,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub observed_slot: u64,
    pub quorum_weight_bps: u64,
    pub accepted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BreakerSettlement {
    pub settlement_id: String,
    pub incident_id: String,
    pub pool_id: String,
    pub route_id: String,
    pub settlement_root: String,
    pub decision: SettlementDecision,
    pub paused_liquidity_micro_units: u64,
    pub recovery_slot: u64,
    pub settled_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateReceipt {
    pub rebate_id: String,
    pub incident_id: String,
    pub sponsor_pool_root: String,
    pub beneficiary_group_root: String,
    pub asset_id: String,
    pub amount_micro_units: u64,
    pub fee_rebate_bps: u64,
    pub issued_slot: u64,
    pub expires_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub target_id: String,
    pub public_fields: BTreeSet<String>,
    pub redacted_fields: BTreeSet<String>,
    pub max_public_bytes: u64,
    pub actual_public_bytes: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub epoch: u64,
    pub slot: u64,
    pub l2_height: u64,
    pub active_pools: u64,
    pub active_routes: u64,
    pub paused_routes: u64,
    pub open_incidents: u64,
    pub settled_incidents: u64,
    pub quarantined_incidents: u64,
    pub total_reserve_micro_units: u64,
    pub total_route_liquidity_micro_units: u64,
    pub total_paused_liquidity_micro_units: u64,
    pub max_observed_reorg_depth: u64,
    pub median_fee_bps: u64,
    pub attestation_quorum_bps: u64,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenPoolRequest {
    pub scope: BreakerScope,
    pub sealed_pool_root: String,
    pub public_hint_root: String,
    pub reserve_commitment_root: String,
    pub reserve_micro_units: u64,
    pub max_route_fee_bps: u64,
    pub reorg_depth_threshold: u64,
    pub opened_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterRouteRequest {
    pub pool_id: String,
    pub route_commitment_root: String,
    pub liquidity_commitment_root: String,
    pub provider_commitment: String,
    pub available_liquidity_micro_units: u64,
    pub fee_cap_bps: u64,
    pub privacy_set_size: u64,
    pub registered_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitIncidentRequest {
    pub pool_id: String,
    pub route_id: String,
    pub severity: ReorgSeverity,
    pub sealed_evidence_root: String,
    pub redacted_evidence_root: String,
    pub bridge_receipt_root: String,
    pub observed_reorg_depth: u64,
    pub requested_pause_bps: u64,
    pub requested_rebate_bps: u64,
    pub submitted_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordAttestationRequest {
    pub incident_id: String,
    pub kind: AttestationKind,
    pub committee_root: String,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub observed_slot: u64,
    pub quorum_weight_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettleIncidentRequest {
    pub incident_id: String,
    pub settlement_root: String,
    pub decision: SettlementDecision,
    pub settled_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueRebateRequest {
    pub incident_id: String,
    pub sponsor_pool_root: String,
    pub beneficiary_group_root: String,
    pub asset_id: String,
    pub amount_micro_units: u64,
    pub fee_rebate_bps: u64,
    pub issued_slot: u64,
    pub expires_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudgetRequest {
    pub target_id: String,
    pub public_fields: BTreeSet<String>,
    pub redacted_fields: BTreeSet<String>,
    pub max_public_bytes: u64,
    pub actual_public_bytes: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummaryRequest {
    pub median_fee_bps: u64,
    pub attestation_quorum_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub pools: BTreeMap<String, BreakerPool>,
    pub routes: BTreeMap<String, LiquidityRoute>,
    pub incidents: BTreeMap<String, ReorgIncident>,
    pub attestations: BTreeMap<String, BreakerAttestation>,
    pub settlements: BTreeMap<String, BreakerSettlement>,
    pub rebates: BTreeMap<String, RebateReceipt>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            pools: BTreeMap::new(),
            routes: BTreeMap::new(),
            incidents: BTreeMap::new(),
            attestations: BTreeMap::new(),
            settlements: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }
}

impl State {
    pub fn devnet() -> Self {
        devnet()
    }

    pub fn open_pool(&mut self, request: OpenPoolRequest) -> Result<String> {
        ensure_capacity(self.pools.len(), MAX_POOLS, "breaker pools")?;
        ensure_non_empty(&request.sealed_pool_root, "sealed_pool_root")?;
        ensure_non_empty(&request.public_hint_root, "public_hint_root")?;
        ensure_non_empty(&request.reserve_commitment_root, "reserve_commitment_root")?;
        ensure_bps(request.max_route_fee_bps, "max_route_fee_bps")?;
        if request.reserve_micro_units < self.config.min_pool_reserve_micro_units {
            return Err("reserve_micro_units below minimum reserve".to_string());
        }
        if request.max_route_fee_bps > self.config.max_route_fee_bps {
            return Err("max_route_fee_bps exceeds configured maximum".to_string());
        }
        if request.reorg_depth_threshold > self.config.max_reorg_depth {
            return Err("reorg_depth_threshold exceeds configured maximum".to_string());
        }
        let pool_id = stable_id(
            "pool",
            &[
                HashPart::Str(request.scope.as_str()),
                HashPart::Str(&request.sealed_pool_root),
                HashPart::U64(request.opened_slot),
            ],
        );
        if self.pools.contains_key(&pool_id) {
            return Err(format!("pool {pool_id} already exists"));
        }
        self.pools.insert(
            pool_id.clone(),
            BreakerPool {
                pool_id: pool_id.clone(),
                scope: request.scope,
                status: PoolStatus::Active,
                sealed_pool_root: request.sealed_pool_root,
                public_hint_root: request.public_hint_root,
                reserve_commitment_root: request.reserve_commitment_root,
                reserve_micro_units: request.reserve_micro_units,
                active_route_count: 0,
                paused_route_count: 0,
                max_route_fee_bps: request.max_route_fee_bps,
                reorg_depth_threshold: request.reorg_depth_threshold,
                opened_slot: request.opened_slot,
                last_updated_slot: request.opened_slot,
            },
        );
        self.counters.pools_opened = self.counters.pools_opened.saturating_add(1);
        self.counters.total_reserve_micro_units = self
            .counters
            .total_reserve_micro_units
            .saturating_add(request.reserve_micro_units);
        self.refresh_roots();
        Ok(pool_id)
    }

    pub fn register_route(&mut self, request: RegisterRouteRequest) -> Result<String> {
        ensure_capacity(self.routes.len(), MAX_ROUTES, "liquidity routes")?;
        ensure_non_empty(&request.pool_id, "pool_id")?;
        ensure_non_empty(&request.route_commitment_root, "route_commitment_root")?;
        ensure_non_empty(
            &request.liquidity_commitment_root,
            "liquidity_commitment_root",
        )?;
        ensure_non_empty(&request.provider_commitment, "provider_commitment")?;
        ensure_bps(request.fee_cap_bps, "fee_cap_bps")?;
        if request.available_liquidity_micro_units < self.config.min_route_liquidity_micro_units {
            return Err("available_liquidity_micro_units below minimum".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy_set_size below minimum".to_string());
        }
        let pool = self
            .pools
            .get_mut(&request.pool_id)
            .ok_or_else(|| format!("unknown pool {}", request.pool_id))?;
        if !matches!(pool.status, PoolStatus::Active | PoolStatus::Throttled) {
            return Err("pool is not accepting routes".to_string());
        }
        if request.fee_cap_bps > pool.max_route_fee_bps {
            return Err("route fee exceeds pool cap".to_string());
        }
        let route_id = stable_id(
            "route",
            &[
                HashPart::Str(&request.pool_id),
                HashPart::Str(&request.route_commitment_root),
                HashPart::Str(&request.provider_commitment),
                HashPart::U64(request.registered_slot),
            ],
        );
        if self.routes.contains_key(&route_id) {
            return Err(format!("route {route_id} already exists"));
        }
        self.routes.insert(
            route_id.clone(),
            LiquidityRoute {
                route_id: route_id.clone(),
                pool_id: request.pool_id.clone(),
                status: RouteStatus::Active,
                route_commitment_root: request.route_commitment_root,
                liquidity_commitment_root: request.liquidity_commitment_root,
                provider_commitment: request.provider_commitment,
                available_liquidity_micro_units: request.available_liquidity_micro_units,
                paused_liquidity_micro_units: 0,
                fee_cap_bps: request.fee_cap_bps,
                privacy_set_size: request.privacy_set_size,
                registered_slot: request.registered_slot,
                incident_count: 0,
            },
        );
        pool.active_route_count = pool.active_route_count.saturating_add(1);
        pool.last_updated_slot = request.registered_slot;
        self.counters.routes_registered = self.counters.routes_registered.saturating_add(1);
        self.counters.total_route_liquidity_micro_units = self
            .counters
            .total_route_liquidity_micro_units
            .saturating_add(request.available_liquidity_micro_units);
        self.refresh_roots();
        Ok(route_id)
    }

    pub fn submit_incident(&mut self, request: SubmitIncidentRequest) -> Result<String> {
        ensure_capacity(self.incidents.len(), MAX_INCIDENTS, "reorg incidents")?;
        ensure_non_empty(&request.pool_id, "pool_id")?;
        ensure_non_empty(&request.route_id, "route_id")?;
        ensure_non_empty(&request.sealed_evidence_root, "sealed_evidence_root")?;
        ensure_non_empty(&request.redacted_evidence_root, "redacted_evidence_root")?;
        ensure_non_empty(&request.bridge_receipt_root, "bridge_receipt_root")?;
        ensure_bps(request.requested_pause_bps, "requested_pause_bps")?;
        ensure_bps(request.requested_rebate_bps, "requested_rebate_bps")?;
        let pool = self
            .pools
            .get(&request.pool_id)
            .ok_or_else(|| format!("unknown pool {}", request.pool_id))?;
        let route = self
            .routes
            .get_mut(&request.route_id)
            .ok_or_else(|| format!("unknown route {}", request.route_id))?;
        if route.pool_id != request.pool_id {
            return Err("route does not belong to pool".to_string());
        }
        if request.observed_reorg_depth < pool.reorg_depth_threshold {
            return Err("observed reorg depth below breaker threshold".to_string());
        }
        let incident_id = stable_id(
            "incident",
            &[
                HashPart::Str(&request.pool_id),
                HashPart::Str(&request.route_id),
                HashPart::Str(request.severity.as_str()),
                HashPart::Str(&request.sealed_evidence_root),
                HashPart::U64(request.submitted_slot),
            ],
        );
        if self.incidents.contains_key(&incident_id) {
            return Err(format!("incident {incident_id} already exists"));
        }
        let expires_slot = request
            .submitted_slot
            .saturating_add(self.config.incident_window_slots);
        self.incidents.insert(
            incident_id.clone(),
            ReorgIncident {
                incident_id: incident_id.clone(),
                pool_id: request.pool_id,
                route_id: request.route_id.clone(),
                severity: request.severity,
                status: IncidentStatus::Submitted,
                sealed_evidence_root: request.sealed_evidence_root,
                redacted_evidence_root: request.redacted_evidence_root,
                bridge_receipt_root: request.bridge_receipt_root,
                observed_reorg_depth: request.observed_reorg_depth,
                requested_pause_bps: request.requested_pause_bps,
                requested_rebate_bps: request.requested_rebate_bps,
                submitted_slot: request.submitted_slot,
                expires_slot,
                attestation_count: 0,
                quorum_weight_bps: 0,
                settled_slot: None,
                settlement_decision: None,
            },
        );
        route.incident_count = route.incident_count.saturating_add(1);
        route.status = RouteStatus::Throttled;
        self.counters.incidents_submitted = self.counters.incidents_submitted.saturating_add(1);
        self.counters.max_observed_reorg_depth = self
            .counters
            .max_observed_reorg_depth
            .max(request.observed_reorg_depth);
        self.refresh_roots();
        Ok(incident_id)
    }

    pub fn record_attestation(&mut self, request: RecordAttestationRequest) -> Result<String> {
        ensure_capacity(self.attestations.len(), MAX_ATTESTATIONS, "attestations")?;
        ensure_non_empty(&request.incident_id, "incident_id")?;
        ensure_non_empty(&request.committee_root, "committee_root")?;
        ensure_non_empty(&request.statement_root, "statement_root")?;
        ensure_non_empty(&request.pq_signature_root, "pq_signature_root")?;
        ensure_bps(request.quorum_weight_bps, "quorum_weight_bps")?;
        let incident = self
            .incidents
            .get_mut(&request.incident_id)
            .ok_or_else(|| format!("unknown incident {}", request.incident_id))?;
        if !matches!(
            incident.status,
            IncidentStatus::Submitted | IncidentStatus::EvidenceLocked
        ) {
            return Err("incident is not accepting attestations".to_string());
        }
        let attestation_id = stable_id(
            "attestation",
            &[
                HashPart::Str(&request.incident_id),
                HashPart::Str(request.kind.as_str()),
                HashPart::Str(&request.committee_root),
                HashPart::U64(request.observed_slot),
            ],
        );
        if self.attestations.contains_key(&attestation_id) {
            return Err(format!("attestation {attestation_id} already exists"));
        }
        let accepted = request.quorum_weight_bps >= self.config.min_attestation_quorum_bps;
        self.attestations.insert(
            attestation_id.clone(),
            BreakerAttestation {
                attestation_id: attestation_id.clone(),
                incident_id: request.incident_id.clone(),
                kind: request.kind,
                committee_root: request.committee_root,
                statement_root: request.statement_root,
                pq_signature_root: request.pq_signature_root,
                observed_slot: request.observed_slot,
                quorum_weight_bps: request.quorum_weight_bps,
                accepted,
            },
        );
        incident.attestation_count = incident.attestation_count.saturating_add(1);
        incident.quorum_weight_bps = incident.quorum_weight_bps.max(request.quorum_weight_bps);
        incident.status = if accepted {
            IncidentStatus::Attested
        } else {
            IncidentStatus::EvidenceLocked
        };
        self.counters.attestations_recorded = self.counters.attestations_recorded.saturating_add(1);
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn settle_incident(&mut self, request: SettleIncidentRequest) -> Result<String> {
        ensure_capacity(self.settlements.len(), MAX_SETTLEMENTS, "settlements")?;
        ensure_non_empty(&request.incident_id, "incident_id")?;
        ensure_non_empty(&request.settlement_root, "settlement_root")?;
        let incident = self
            .incidents
            .get_mut(&request.incident_id)
            .ok_or_else(|| format!("unknown incident {}", request.incident_id))?;
        if !matches!(
            incident.status,
            IncidentStatus::Attested | IncidentStatus::EvidenceLocked
        ) {
            return Err("incident is not settleable".to_string());
        }
        if request.settled_slot > incident.expires_slot {
            return Err("settled_slot exceeds incident expiry".to_string());
        }
        let pool = self
            .pools
            .get_mut(&incident.pool_id)
            .ok_or_else(|| format!("unknown pool {}", incident.pool_id))?;
        let route = self
            .routes
            .get_mut(&incident.route_id)
            .ok_or_else(|| format!("unknown route {}", incident.route_id))?;
        let requested_pause = route
            .available_liquidity_micro_units
            .saturating_mul(incident.requested_pause_bps)
            / MAX_BPS;
        let paused_liquidity_micro_units = match request.decision {
            SettlementDecision::EngageBreaker | SettlementDecision::EngageBreakerWithRebate => {
                requested_pause
            }
            SettlementDecision::PartialThrottle => requested_pause / 2,
            SettlementDecision::Recover
            | SettlementDecision::Reject
            | SettlementDecision::Expire => 0,
            SettlementDecision::Quarantine => requested_pause,
        };
        let settlement_id = stable_id(
            "settlement",
            &[
                HashPart::Str(&request.incident_id),
                HashPart::Str(request.decision.as_str()),
                HashPart::Str(&request.settlement_root),
                HashPart::U64(request.settled_slot),
            ],
        );
        if self.settlements.contains_key(&settlement_id) {
            return Err(format!("settlement {settlement_id} already exists"));
        }
        route.paused_liquidity_micro_units = route
            .paused_liquidity_micro_units
            .saturating_add(paused_liquidity_micro_units);
        route.available_liquidity_micro_units = route
            .available_liquidity_micro_units
            .saturating_sub(paused_liquidity_micro_units);
        route.status = match request.decision {
            SettlementDecision::EngageBreaker | SettlementDecision::EngageBreakerWithRebate => {
                RouteStatus::Paused
            }
            SettlementDecision::PartialThrottle => RouteStatus::Throttled,
            SettlementDecision::Recover | SettlementDecision::Reject => RouteStatus::Active,
            SettlementDecision::Quarantine => {
                self.counters.quarantines = self.counters.quarantines.saturating_add(1);
                RouteStatus::Quarantined
            }
            SettlementDecision::Expire => RouteStatus::Throttled,
        };
        pool.status = match request.decision {
            SettlementDecision::EngageBreaker | SettlementDecision::EngageBreakerWithRebate => {
                self.counters.breakers_engaged = self.counters.breakers_engaged.saturating_add(1);
                pool.paused_route_count = pool.paused_route_count.saturating_add(1);
                PoolStatus::BreakerEngaged
            }
            SettlementDecision::PartialThrottle => PoolStatus::Throttled,
            SettlementDecision::Recover | SettlementDecision::Reject => PoolStatus::Active,
            SettlementDecision::Quarantine => PoolStatus::Quarantined,
            SettlementDecision::Expire => PoolStatus::RecoveryOnly,
        };
        pool.last_updated_slot = request.settled_slot;
        incident.status = match request.decision {
            SettlementDecision::Reject => IncidentStatus::Rejected,
            SettlementDecision::Expire => IncidentStatus::Expired,
            SettlementDecision::Quarantine => IncidentStatus::Quarantined,
            SettlementDecision::Recover => IncidentStatus::Settled,
            _ => IncidentStatus::BreakerEngaged,
        };
        incident.settled_slot = Some(request.settled_slot);
        incident.settlement_decision = Some(request.decision);
        let recovery_slot = request
            .settled_slot
            .saturating_add(self.config.recovery_window_slots);
        self.settlements.insert(
            settlement_id.clone(),
            BreakerSettlement {
                settlement_id: settlement_id.clone(),
                incident_id: request.incident_id.clone(),
                pool_id: incident.pool_id.clone(),
                route_id: incident.route_id.clone(),
                settlement_root: request.settlement_root,
                decision: request.decision,
                paused_liquidity_micro_units,
                recovery_slot,
                settled_slot: request.settled_slot,
            },
        );
        self.counters.settlements_recorded = self.counters.settlements_recorded.saturating_add(1);
        self.counters.total_paused_liquidity_micro_units = self
            .counters
            .total_paused_liquidity_micro_units
            .saturating_add(paused_liquidity_micro_units);
        self.refresh_roots();
        Ok(settlement_id)
    }

    pub fn issue_rebate(&mut self, request: IssueRebateRequest) -> Result<String> {
        ensure_capacity(self.rebates.len(), MAX_REBATES, "rebates")?;
        ensure_non_empty(&request.incident_id, "incident_id")?;
        ensure_non_empty(&request.sponsor_pool_root, "sponsor_pool_root")?;
        ensure_non_empty(&request.beneficiary_group_root, "beneficiary_group_root")?;
        ensure_non_empty(&request.asset_id, "asset_id")?;
        ensure_bps(request.fee_rebate_bps, "fee_rebate_bps")?;
        if request.expires_slot <= request.issued_slot {
            return Err("expires_slot must be greater than issued_slot".to_string());
        }
        let incident = self
            .incidents
            .get_mut(&request.incident_id)
            .ok_or_else(|| format!("unknown incident {}", request.incident_id))?;
        if !matches!(
            incident.status,
            IncidentStatus::BreakerEngaged | IncidentStatus::Settled
        ) {
            return Err("incident must be settled before rebate".to_string());
        }
        let rebate_id = stable_id(
            "rebate",
            &[
                HashPart::Str(&request.incident_id),
                HashPart::Str(&request.sponsor_pool_root),
                HashPart::Str(&request.beneficiary_group_root),
                HashPart::U64(request.issued_slot),
            ],
        );
        if self.rebates.contains_key(&rebate_id) {
            return Err(format!("rebate {rebate_id} already exists"));
        }
        self.rebates.insert(
            rebate_id.clone(),
            RebateReceipt {
                rebate_id: rebate_id.clone(),
                incident_id: request.incident_id.clone(),
                sponsor_pool_root: request.sponsor_pool_root,
                beneficiary_group_root: request.beneficiary_group_root,
                asset_id: request.asset_id,
                amount_micro_units: request.amount_micro_units,
                fee_rebate_bps: request.fee_rebate_bps,
                issued_slot: request.issued_slot,
                expires_slot: request.expires_slot,
            },
        );
        incident.status = IncidentStatus::RebateIssued;
        self.counters.rebates_issued = self.counters.rebates_issued.saturating_add(1);
        self.counters.total_rebated_micro_units = self
            .counters
            .total_rebated_micro_units
            .saturating_add(request.amount_micro_units);
        self.refresh_roots();
        Ok(rebate_id)
    }

    pub fn publish_redaction_budget(&mut self, request: RedactionBudgetRequest) -> Result<()> {
        ensure_capacity(
            self.redaction_budgets.len(),
            MAX_REDACTION_BUDGETS,
            "redaction budgets",
        )?;
        ensure_non_empty(&request.target_id, "target_id")?;
        if request.actual_public_bytes > request.max_public_bytes {
            return Err("actual_public_bytes exceeds max_public_bytes".to_string());
        }
        if request.max_public_bytes > self.config.max_public_redaction_bytes {
            return Err("max_public_bytes exceeds configured maximum".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy_set_size below minimum".to_string());
        }
        self.redaction_budgets.insert(
            request.target_id.clone(),
            RedactionBudget {
                target_id: request.target_id,
                public_fields: request.public_fields,
                redacted_fields: request.redacted_fields,
                max_public_bytes: request.max_public_bytes,
                actual_public_bytes: request.actual_public_bytes,
                privacy_set_size: request.privacy_set_size,
            },
        );
        self.counters.redaction_budgets_published =
            self.counters.redaction_budgets_published.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn publish_operator_summary(&mut self, request: OperatorSummaryRequest) -> Result<()> {
        ensure_capacity(
            self.operator_summaries.len(),
            MAX_OPERATOR_SUMMARIES,
            "operator summaries",
        )?;
        ensure_bps(request.median_fee_bps, "median_fee_bps")?;
        ensure_bps(request.attestation_quorum_bps, "attestation_quorum_bps")?;
        let active_pools = self
            .pools
            .values()
            .filter(|pool| matches!(pool.status, PoolStatus::Active | PoolStatus::Throttled))
            .count() as u64;
        let active_routes = self
            .routes
            .values()
            .filter(|route| matches!(route.status, RouteStatus::Active | RouteStatus::Throttled))
            .count() as u64;
        let paused_routes = self
            .routes
            .values()
            .filter(|route| matches!(route.status, RouteStatus::Paused))
            .count() as u64;
        let open_incidents = self
            .incidents
            .values()
            .filter(|incident| {
                matches!(
                    incident.status,
                    IncidentStatus::Submitted
                        | IncidentStatus::Attested
                        | IncidentStatus::EvidenceLocked
                )
            })
            .count() as u64;
        let settled_incidents = self
            .incidents
            .values()
            .filter(|incident| {
                matches!(
                    incident.status,
                    IncidentStatus::Settled
                        | IncidentStatus::BreakerEngaged
                        | IncidentStatus::RebateIssued
                )
            })
            .count() as u64;
        let quarantined_incidents = self
            .incidents
            .values()
            .filter(|incident| matches!(incident.status, IncidentStatus::Quarantined))
            .count() as u64;
        let summary_id = stable_id(
            "operator-summary",
            &[
                HashPart::U64(DEVNET_EPOCH),
                HashPart::U64(DEVNET_SLOT),
                HashPart::Str(&self.roots.state_root),
            ],
        );
        self.operator_summaries.insert(
            summary_id.clone(),
            OperatorSummary {
                summary_id,
                epoch: DEVNET_EPOCH,
                slot: DEVNET_SLOT,
                l2_height: DEVNET_L2_HEIGHT,
                active_pools,
                active_routes,
                paused_routes,
                open_incidents,
                settled_incidents,
                quarantined_incidents,
                total_reserve_micro_units: self.counters.total_reserve_micro_units,
                total_route_liquidity_micro_units: self.counters.total_route_liquidity_micro_units,
                total_paused_liquidity_micro_units: self
                    .counters
                    .total_paused_liquidity_micro_units,
                max_observed_reorg_depth: self.counters.max_observed_reorg_depth,
                median_fee_bps: request.median_fee_bps,
                attestation_quorum_bps: request.attestation_quorum_bps,
                state_root: self.roots.state_root.clone(),
            },
        );
        self.counters.operator_summaries_published =
            self.counters.operator_summaries_published.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = object_root("config", &self.config);
        self.roots.pool_root = map_root("pools", &self.pools);
        self.roots.route_root = map_root("routes", &self.routes);
        self.roots.incident_root = map_root("incidents", &self.incidents);
        self.roots.attestation_root = map_root("attestations", &self.attestations);
        self.roots.settlement_root = map_root("settlements", &self.settlements);
        self.roots.rebate_root = map_root("rebates", &self.rebates);
        self.roots.redaction_root = map_root("redactions", &self.redaction_budgets);
        self.roots.operator_summary_root = map_root("operator-summaries", &self.operator_summaries);
        self.roots.counters_root = object_root("counters", &self.counters);
        self.roots.state_root = merkle_root(
            "bridge-reorg-liquidity-circuit-breaker:state",
            &[
                json!({ "config_root": self.roots.config_root }),
                json!({ "pool_root": self.roots.pool_root }),
                json!({ "route_root": self.roots.route_root }),
                json!({ "incident_root": self.roots.incident_root }),
                json!({ "attestation_root": self.roots.attestation_root }),
                json!({ "settlement_root": self.roots.settlement_root }),
                json!({ "rebate_root": self.roots.rebate_root }),
                json!({ "redaction_root": self.roots.redaction_root }),
                json!({ "operator_summary_root": self.roots.operator_summary_root }),
                json!({ "counters_root": self.roots.counters_root }),
            ],
        );
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": self.config.hash_suite,
            "pq_breaker_suite": self.config.pq_breaker_suite,
            "breaker_suite": self.config.breaker_suite,
            "incident_suite": self.config.incident_suite,
            "fee_asset_id": self.config.fee_asset_id,
            "liquidity_asset_id": self.config.liquidity_asset_id,
            "min_privacy_set_size": self.config.min_privacy_set_size,
            "target_privacy_set_size": self.config.target_privacy_set_size,
            "min_pq_security_bits": self.config.min_pq_security_bits,
            "incident_window_slots": self.config.incident_window_slots,
            "recovery_window_slots": self.config.recovery_window_slots,
            "max_route_fee_bps": self.config.max_route_fee_bps,
            "target_rebate_bps": self.config.target_rebate_bps,
            "max_reorg_depth": self.config.max_reorg_depth,
            "counters": self.counters,
            "roots": self.roots,
            "pool_count": self.pools.len(),
            "route_count": self.routes.len(),
            "incident_count": self.incidents.len(),
            "attestation_count": self.attestations.len(),
            "settlement_count": self.settlements.len(),
            "rebate_count": self.rebates.len(),
            "redaction_budget_count": self.redaction_budgets.len(),
            "operator_summary_count": self.operator_summaries.len(),
            "pools": self.pools.values().map(|pool| json!({
                "pool_id": pool.pool_id,
                "scope": pool.scope,
                "status": pool.status,
                "public_hint_root": pool.public_hint_root,
                "reserve_micro_units": pool.reserve_micro_units,
                "active_route_count": pool.active_route_count,
                "paused_route_count": pool.paused_route_count,
                "max_route_fee_bps": pool.max_route_fee_bps,
                "reorg_depth_threshold": pool.reorg_depth_threshold,
            })).collect::<Vec<_>>(),
            "routes": self.routes.values().map(|route| json!({
                "route_id": route.route_id,
                "pool_id": route.pool_id,
                "status": route.status,
                "available_liquidity_micro_units": route.available_liquidity_micro_units,
                "paused_liquidity_micro_units": route.paused_liquidity_micro_units,
                "fee_cap_bps": route.fee_cap_bps,
                "privacy_set_size": route.privacy_set_size,
                "incident_count": route.incident_count,
            })).collect::<Vec<_>>(),
            "incidents": self.incidents.values().map(|incident| json!({
                "incident_id": incident.incident_id,
                "pool_id": incident.pool_id,
                "route_id": incident.route_id,
                "severity": incident.severity,
                "status": incident.status,
                "redacted_evidence_root": incident.redacted_evidence_root,
                "bridge_receipt_root": incident.bridge_receipt_root,
                "observed_reorg_depth": incident.observed_reorg_depth,
                "requested_pause_bps": incident.requested_pause_bps,
                "requested_rebate_bps": incident.requested_rebate_bps,
                "submitted_slot": incident.submitted_slot,
                "expires_slot": incident.expires_slot,
                "attestation_count": incident.attestation_count,
                "quorum_weight_bps": incident.quorum_weight_bps,
                "settled_slot": incident.settled_slot,
                "settlement_decision": incident.settlement_decision,
            })).collect::<Vec<_>>(),
            "attestations": self.attestations.values().map(|attestation| json!({
                "attestation_id": attestation.attestation_id,
                "incident_id": attestation.incident_id,
                "kind": attestation.kind,
                "statement_root": attestation.statement_root,
                "observed_slot": attestation.observed_slot,
                "quorum_weight_bps": attestation.quorum_weight_bps,
                "accepted": attestation.accepted,
            })).collect::<Vec<_>>(),
            "settlements": self.settlements.values().collect::<Vec<_>>(),
            "rebates": self.rebates.values().collect::<Vec<_>>(),
            "redaction_budgets": self.redaction_budgets.values().collect::<Vec<_>>(),
            "operator_summaries": self.operator_summaries.values().collect::<Vec<_>>(),
        })
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let pool_id = state
        .open_pool(OpenPoolRequest {
            scope: BreakerScope::WithdrawalQueue,
            sealed_pool_root: sample_hash("sealed-pool", 1),
            public_hint_root: sample_hash("public-hint", 1),
            reserve_commitment_root: sample_hash("reserve", 1),
            reserve_micro_units: 240_000_000,
            max_route_fee_bps: 11,
            reorg_depth_threshold: 8,
            opened_slot: DEVNET_SLOT,
        })
        .expect("devnet reorg circuit breaker pool opened");
    let route_id = state
        .register_route(RegisterRouteRequest {
            pool_id: pool_id.clone(),
            route_commitment_root: sample_hash("route", 1),
            liquidity_commitment_root: sample_hash("liquidity", 1),
            provider_commitment: sample_hash("provider", 1),
            available_liquidity_micro_units: 72_000_000,
            fee_cap_bps: 9,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            registered_slot: DEVNET_SLOT + 1,
        })
        .expect("devnet liquidity route registered");
    let incident_id = state
        .submit_incident(SubmitIncidentRequest {
            pool_id: pool_id.clone(),
            route_id: route_id.clone(),
            severity: ReorgSeverity::Deep,
            sealed_evidence_root: sample_hash("sealed-evidence", 1),
            redacted_evidence_root: sample_hash("redacted-evidence", 1),
            bridge_receipt_root: sample_hash("bridge-receipt", 1),
            observed_reorg_depth: 11,
            requested_pause_bps: 2_500,
            requested_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            submitted_slot: DEVNET_SLOT + 8,
        })
        .expect("devnet reorg incident submitted");
    state
        .record_attestation(RecordAttestationRequest {
            incident_id: incident_id.clone(),
            kind: AttestationKind::RecoverySafe,
            committee_root: sample_hash("committee", 1),
            statement_root: sample_hash("statement", 1),
            pq_signature_root: sample_hash("pq-signature", 1),
            observed_slot: DEVNET_SLOT + 12,
            quorum_weight_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
        })
        .expect("devnet incident attested");
    state
        .settle_incident(SettleIncidentRequest {
            incident_id: incident_id.clone(),
            settlement_root: sample_hash("settlement", 1),
            decision: SettlementDecision::EngageBreakerWithRebate,
            settled_slot: DEVNET_SLOT + 16,
        })
        .expect("devnet incident settled");
    state
        .issue_rebate(IssueRebateRequest {
            incident_id: incident_id.clone(),
            sponsor_pool_root: sample_hash("sponsor-pool", 1),
            beneficiary_group_root: sample_hash("beneficiary-group", 1),
            asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            amount_micro_units: 1_020,
            fee_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            issued_slot: DEVNET_SLOT + 17,
            expires_slot: DEVNET_SLOT + DEFAULT_RECOVERY_WINDOW_SLOTS,
        })
        .expect("devnet rebate issued");
    state
        .publish_redaction_budget(RedactionBudgetRequest {
            target_id: incident_id,
            public_fields: [
                "incident_id",
                "pool_id",
                "route_id",
                "severity",
                "observed_reorg_depth",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            redacted_fields: [
                "sealed_evidence_root",
                "provider_commitment",
                "liquidity_commitment_root",
                "committee_root",
                "pq_signature_root",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            max_public_bytes: DEFAULT_MAX_PUBLIC_REDACTION_BYTES,
            actual_public_bytes: 904,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        })
        .expect("devnet redaction budget published");
    state
        .publish_operator_summary(OperatorSummaryRequest {
            median_fee_bps: 9,
            attestation_quorum_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
        })
        .expect("devnet operator summary published");
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    state
        .open_pool(OpenPoolRequest {
            scope: BreakerScope::EmergencyExitLane,
            sealed_pool_root: sample_hash("sealed-pool", 2),
            public_hint_root: sample_hash("public-hint", 2),
            reserve_commitment_root: sample_hash("reserve", 2),
            reserve_micro_units: 180_000_000,
            max_route_fee_bps: 10,
            reorg_depth_threshold: 10,
            opened_slot: DEVNET_SLOT + 40,
        })
        .expect("demo reorg circuit breaker pool opened");
    state.refresh_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn stable_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("bridge-reorg-liquidity-circuit-breaker:{domain}:id"),
        parts,
        24,
    )
}

fn empty_root(domain: &str) -> String {
    merkle_root(
        &format!("bridge-reorg-liquidity-circuit-breaker:{domain}"),
        &[],
    )
}

fn object_root<T: Serialize>(domain: &str, value: &T) -> String {
    merkle_root(
        &format!("bridge-reorg-liquidity-circuit-breaker:{domain}"),
        &[json!(value)],
    )
}

fn map_root<T: Serialize>(domain: &str, records: &BTreeMap<String, T>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("bridge-reorg-liquidity-circuit-breaker:{domain}"),
        &leaves,
    )
}

fn sample_hash(label: &str, index: u64) -> String {
    domain_hash(
        "bridge-reorg-liquidity-circuit-breaker:devnet-sample",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

fn ensure_non_empty(value: &str, name: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(())
}

fn ensure_bps(value: u64, name: &str) -> Result<()> {
    if value > MAX_BPS {
        return Err(format!("{name} must be <= 10000"));
    }
    Ok(())
}

fn ensure_capacity(current: usize, max: usize, name: &str) -> Result<()> {
    if current >= max {
        return Err(format!("{name} capacity exceeded"));
    }
    Ok(())
}
