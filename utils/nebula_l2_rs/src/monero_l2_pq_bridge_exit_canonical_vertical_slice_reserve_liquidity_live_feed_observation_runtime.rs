use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PqBridgeExitCanonicalVerticalSliceReserveLiquidityLiveFeedObservationRuntimeResult<
    T,
> = std::result::Result<T, String>;
pub type Result<T> =
    MoneroL2PqBridgeExitCanonicalVerticalSliceReserveLiquidityLiveFeedObservationRuntimeResult<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RESERVE_LIQUIDITY_LIVE_FEED_OBSERVATION_RUNTIME_PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-reserve-liquidity-live-feed-observation-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RESERVE_LIQUIDITY_LIVE_FEED_OBSERVATION_RUNTIME_PROTOCOL_VERSION;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_500;
pub const DEFAULT_WARN_RESERVE_COVERAGE_BPS: u64 = 11_000;
pub const DEFAULT_EXHAUSTION_ALERT_BPS: u64 = 8_000;
pub const DEFAULT_RELEASE_LOOKAHEAD_BLOCKS: u64 = 72;
pub const DEFAULT_FAIL_CLOSED_GRACE_BLOCKS: u64 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    Fresh,
    Watch,
    Degraded,
    Stale,
    Quarantined,
}

impl ObservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Watch => "watch",
            Self::Degraded => "degraded",
            Self::Stale => "stale",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveSurface {
    HotWallet,
    WarmVault,
    ColdVault,
    MarketMaker,
    Insurance,
    Backstop,
}

impl ReserveSurface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HotWallet => "hot_wallet",
            Self::WarmVault => "warm_vault",
            Self::ColdVault => "cold_vault",
            Self::MarketMaker => "market_maker",
            Self::Insurance => "insurance",
            Self::Backstop => "backstop",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityQueueKind {
    ImmediateExit,
    ForcedExit,
    DelayedRelease,
    MakerFill,
    EmergencyBackstop,
}

impl LiquidityQueueKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ImmediateExit => "immediate_exit",
            Self::ForcedExit => "forced_exit",
            Self::DelayedRelease => "delayed_release",
            Self::MakerFill => "maker_fill",
            Self::EmergencyBackstop => "emergency_backstop",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityStatus {
    Open,
    Constrained,
    ExhaustionRisk,
    Halted,
}

impl CapacityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Constrained => "constrained",
            Self::ExhaustionRisk => "exhaustion_risk",
            Self::Halted => "halted",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackstopKind {
    SlashingEscrow,
    InsuranceVault,
    MakerBond,
    GovernanceReserve,
    EmergencyCreditLine,
}

impl BackstopKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SlashingEscrow => "slashing_escrow",
            Self::InsuranceVault => "insurance_vault",
            Self::MakerBond => "maker_bond",
            Self::GovernanceReserve => "governance_reserve",
            Self::EmergencyCreditLine => "emergency_credit_line",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MismatchKind {
    ReserveBelowLiability,
    FeedDivergence,
    ReleaseOverCapacity,
    BackstopUnavailable,
    StaleObservation,
    HoldConflict,
}

impl MismatchKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReserveBelowLiability => "reserve_below_liability",
            Self::FeedDivergence => "feed_divergence",
            Self::ReleaseOverCapacity => "release_over_capacity",
            Self::BackstopUnavailable => "backstop_unavailable",
            Self::StaleObservation => "stale_observation",
            Self::HoldConflict => "hold_conflict",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldReason {
    ReserveShortfall,
    FeedMismatch,
    SlashingReview,
    CapacityThrottle,
    ForcedExitBatch,
}

impl HoldReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReserveShortfall => "reserve_shortfall",
            Self::FeedMismatch => "feed_mismatch",
            Self::SlashingReview => "slashing_review",
            Self::CapacityThrottle => "capacity_throttle",
            Self::ForcedExitBatch => "forced_exit_batch",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub reserve_asset_id: String,
    pub liability_asset_id: String,
    pub min_reserve_coverage_bps: u64,
    pub warn_reserve_coverage_bps: u64,
    pub exhaustion_alert_bps: u64,
    pub release_lookahead_blocks: u64,
    pub fail_closed_grace_blocks: u64,
    pub observer_committee_root: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            reserve_asset_id: "xmr-reserve-devnet".to_string(),
            liability_asset_id: "wxmr-forced-exit-devnet".to_string(),
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            warn_reserve_coverage_bps: DEFAULT_WARN_RESERVE_COVERAGE_BPS,
            exhaustion_alert_bps: DEFAULT_EXHAUSTION_ALERT_BPS,
            release_lookahead_blocks: DEFAULT_RELEASE_LOOKAHEAD_BLOCKS,
            fail_closed_grace_blocks: DEFAULT_FAIL_CLOSED_GRACE_BLOCKS,
            observer_committee_root: digest_str("OBSERVER-COMMITTEE", "devnet-observer-committee"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "reserve_asset_id": self.reserve_asset_id,
            "liability_asset_id": self.liability_asset_id,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "warn_reserve_coverage_bps": self.warn_reserve_coverage_bps,
            "exhaustion_alert_bps": self.exhaustion_alert_bps,
            "release_lookahead_blocks": self.release_lookahead_blocks,
            "fail_closed_grace_blocks": self.fail_closed_grace_blocks,
            "observer_committee_root": self.observer_committee_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveObservation {
    pub observation_id: String,
    pub surface: ReserveSurface,
    pub custodian_commitment: String,
    pub reserve_units: u64,
    pub liability_units: u64,
    pub pending_release_units: u64,
    pub proof_root: String,
    pub feed_root: String,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
    pub status: ObservationStatus,
}

impl ReserveObservation {
    pub fn coverage_bps(&self) -> u64 {
        ratio_bps(
            self.reserve_units,
            self.liability_units
                .saturating_add(self.pending_release_units),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "surface": self.surface.as_str(),
            "custodian_commitment": self.custodian_commitment,
            "reserve_units": self.reserve_units,
            "liability_units": self.liability_units,
            "pending_release_units": self.pending_release_units,
            "coverage_bps": self.coverage_bps(),
            "proof_root": self.proof_root,
            "feed_root": self.feed_root,
            "observed_at_height": self.observed_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityQueueObservation {
    pub queue_id: String,
    pub queue_kind: LiquidityQueueKind,
    pub lane_id: String,
    pub queued_units: u64,
    pub ready_units: u64,
    pub blocked_units: u64,
    pub max_drain_units_per_block: u64,
    pub oldest_request_height: u64,
    pub observed_at_height: u64,
    pub queue_root: String,
    pub capacity_status: CapacityStatus,
}

impl LiquidityQueueObservation {
    pub fn exhaustion_risk_bps(&self) -> u64 {
        ratio_bps(
            self.queued_units.saturating_add(self.blocked_units),
            self.ready_units.saturating_add(1),
        )
    }

    pub fn projected_drain_blocks(&self) -> u64 {
        if self.max_drain_units_per_block == 0 {
            return u64::MAX;
        }
        div_ceil(
            self.queued_units.saturating_add(self.ready_units),
            self.max_drain_units_per_block,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "queue_id": self.queue_id,
            "queue_kind": self.queue_kind.as_str(),
            "lane_id": self.lane_id,
            "queued_units": self.queued_units,
            "ready_units": self.ready_units,
            "blocked_units": self.blocked_units,
            "max_drain_units_per_block": self.max_drain_units_per_block,
            "oldest_request_height": self.oldest_request_height,
            "observed_at_height": self.observed_at_height,
            "queue_root": self.queue_root,
            "capacity_status": self.capacity_status.as_str(),
            "exhaustion_risk_bps": self.exhaustion_risk_bps(),
            "projected_drain_blocks": self.projected_drain_blocks(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseCapacitySnapshot {
    pub capacity_id: String,
    pub lane_id: String,
    pub available_units: u64,
    pub reserved_units: u64,
    pub hold_units: u64,
    pub release_ceiling_units: u64,
    pub release_window_start_height: u64,
    pub release_window_end_height: u64,
    pub source_root: String,
    pub status: CapacityStatus,
}

impl ReleaseCapacitySnapshot {
    pub fn free_units(&self) -> u64 {
        self.available_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.hold_units)
    }

    pub fn utilization_bps(&self) -> u64 {
        ratio_bps(
            self.reserved_units.saturating_add(self.hold_units),
            self.available_units,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "capacity_id": self.capacity_id,
            "lane_id": self.lane_id,
            "available_units": self.available_units,
            "reserved_units": self.reserved_units,
            "hold_units": self.hold_units,
            "free_units": self.free_units(),
            "release_ceiling_units": self.release_ceiling_units,
            "release_window_start_height": self.release_window_start_height,
            "release_window_end_height": self.release_window_end_height,
            "source_root": self.source_root,
            "status": self.status.as_str(),
            "utilization_bps": self.utilization_bps(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackstopAvailability {
    pub backstop_id: String,
    pub kind: BackstopKind,
    pub provider_commitment: String,
    pub available_units: u64,
    pub locked_units: u64,
    pub slashable_units: u64,
    pub activation_delay_blocks: u64,
    pub evidence_root: String,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
    pub status: ObservationStatus,
}

impl BackstopAvailability {
    pub fn callable_units(&self) -> u64 {
        self.available_units
            .saturating_add(self.slashable_units)
            .saturating_sub(self.locked_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "backstop_id": self.backstop_id,
            "kind": self.kind.as_str(),
            "provider_commitment": self.provider_commitment,
            "available_units": self.available_units,
            "locked_units": self.locked_units,
            "slashable_units": self.slashable_units,
            "callable_units": self.callable_units(),
            "activation_delay_blocks": self.activation_delay_blocks,
            "evidence_root": self.evidence_root,
            "observed_at_height": self.observed_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MismatchRecord {
    pub mismatch_id: String,
    pub kind: MismatchKind,
    pub subject_id: String,
    pub expected_root: String,
    pub observed_root: String,
    pub delta_units: u64,
    pub severity_bps: u64,
    pub opened_at_height: u64,
    pub fail_closed: bool,
    pub resolution_root: String,
}

impl MismatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "mismatch_id": self.mismatch_id,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "delta_units": self.delta_units,
            "severity_bps": self.severity_bps,
            "opened_at_height": self.opened_at_height,
            "fail_closed": self.fail_closed,
            "resolution_root": self.resolution_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseHold {
    pub hold_id: String,
    pub release_id: String,
    pub lane_id: String,
    pub reason: HoldReason,
    pub held_units: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub authority_root: String,
    pub evidence_root: String,
}

impl ReleaseHold {
    pub fn public_record(&self) -> Value {
        json!({
            "hold_id": self.hold_id,
            "release_id": self.release_id,
            "lane_id": self.lane_id,
            "reason": self.reason.as_str(),
            "held_units": self.held_units,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "authority_root": self.authority_root,
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationRoots {
    pub reserve_observation_root: String,
    pub liquidity_queue_root: String,
    pub coverage_ratio_root: String,
    pub release_capacity_root: String,
    pub backstop_availability_root: String,
    pub mismatch_surface_root: String,
    pub release_hold_root: String,
    pub aggregate_root: String,
}

impl ObservationRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "reserve_observation_root": self.reserve_observation_root,
            "liquidity_queue_root": self.liquidity_queue_root,
            "coverage_ratio_root": self.coverage_ratio_root,
            "release_capacity_root": self.release_capacity_root,
            "backstop_availability_root": self.backstop_availability_root,
            "mismatch_surface_root": self.mismatch_surface_root,
            "release_hold_root": self.release_hold_root,
            "aggregate_root": self.aggregate_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationSummary {
    pub total_reserve_units: u64,
    pub total_liability_units: u64,
    pub total_pending_release_units: u64,
    pub aggregate_coverage_bps: u64,
    pub total_queued_units: u64,
    pub total_release_capacity_units: u64,
    pub total_free_release_units: u64,
    pub total_callable_backstop_units: u64,
    pub total_release_hold_units: u64,
    pub fail_closed_mismatch_count: u64,
    pub highest_exhaustion_risk_bps: u64,
}

impl ObservationSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "total_reserve_units": self.total_reserve_units,
            "total_liability_units": self.total_liability_units,
            "total_pending_release_units": self.total_pending_release_units,
            "aggregate_coverage_bps": self.aggregate_coverage_bps,
            "total_queued_units": self.total_queued_units,
            "total_release_capacity_units": self.total_release_capacity_units,
            "total_free_release_units": self.total_free_release_units,
            "total_callable_backstop_units": self.total_callable_backstop_units,
            "total_release_hold_units": self.total_release_hold_units,
            "fail_closed_mismatch_count": self.fail_closed_mismatch_count,
            "highest_exhaustion_risk_bps": self.highest_exhaustion_risk_bps,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub reserve_observations: BTreeMap<String, ReserveObservation>,
    pub liquidity_queues: BTreeMap<String, LiquidityQueueObservation>,
    pub release_capacities: BTreeMap<String, ReleaseCapacitySnapshot>,
    pub backstops: BTreeMap<String, BackstopAvailability>,
    pub mismatches: BTreeMap<String, MismatchRecord>,
    pub release_holds: BTreeMap<String, ReleaseHold>,
}

impl State {
    pub fn new(config: Config, height: u64) -> Self {
        Self {
            config,
            height,
            reserve_observations: BTreeMap::new(),
            liquidity_queues: BTreeMap::new(),
            release_capacities: BTreeMap::new(),
            backstops: BTreeMap::new(),
            mismatches: BTreeMap::new(),
            release_holds: BTreeMap::new(),
        }
    }

    pub fn insert_reserve_observation(
        &mut self,
        observation: ReserveObservation,
    ) -> Result<String> {
        if observation.expires_at_height < observation.observed_at_height {
            return Err("reserve observation expires before observed height".to_string());
        }
        let id = observation.observation_id.clone();
        self.reserve_observations.insert(id.clone(), observation);
        Ok(id)
    }

    pub fn insert_liquidity_queue(&mut self, queue: LiquidityQueueObservation) -> Result<String> {
        if queue.max_drain_units_per_block == 0 && queue.capacity_status != CapacityStatus::Halted {
            return Err("zero drain rate must be marked halted".to_string());
        }
        let id = queue.queue_id.clone();
        self.liquidity_queues.insert(id.clone(), queue);
        Ok(id)
    }

    pub fn insert_release_capacity(&mut self, capacity: ReleaseCapacitySnapshot) -> Result<String> {
        if capacity.release_window_end_height < capacity.release_window_start_height {
            return Err("release capacity window is inverted".to_string());
        }
        let id = capacity.capacity_id.clone();
        self.release_capacities.insert(id.clone(), capacity);
        Ok(id)
    }

    pub fn insert_backstop(&mut self, backstop: BackstopAvailability) -> Result<String> {
        if backstop.expires_at_height < backstop.observed_at_height {
            return Err("backstop observation expires before observed height".to_string());
        }
        let id = backstop.backstop_id.clone();
        self.backstops.insert(id.clone(), backstop);
        Ok(id)
    }

    pub fn insert_mismatch(&mut self, mismatch: MismatchRecord) -> Result<String> {
        if mismatch.severity_bps > MAX_BPS {
            return Err("mismatch severity exceeds maximum bps".to_string());
        }
        let id = mismatch.mismatch_id.clone();
        self.mismatches.insert(id.clone(), mismatch);
        Ok(id)
    }

    pub fn insert_release_hold(&mut self, hold: ReleaseHold) -> Result<String> {
        if hold.expires_at_height < hold.opened_at_height {
            return Err("release hold expires before opened height".to_string());
        }
        let id = hold.hold_id.clone();
        self.release_holds.insert(id.clone(), hold);
        Ok(id)
    }

    pub fn summary(&self) -> ObservationSummary {
        let total_reserve_units = self
            .reserve_observations
            .values()
            .map(|observation| observation.reserve_units)
            .sum();
        let total_liability_units = self
            .reserve_observations
            .values()
            .map(|observation| observation.liability_units)
            .sum();
        let total_pending_release_units = self
            .reserve_observations
            .values()
            .map(|observation| observation.pending_release_units)
            .sum();
        let total_queued_units = self
            .liquidity_queues
            .values()
            .map(|queue| queue.queued_units)
            .sum();
        let total_release_capacity_units = self
            .release_capacities
            .values()
            .map(|capacity| capacity.available_units)
            .sum();
        let total_free_release_units = self
            .release_capacities
            .values()
            .map(ReleaseCapacitySnapshot::free_units)
            .sum();
        let total_callable_backstop_units = self
            .backstops
            .values()
            .map(BackstopAvailability::callable_units)
            .sum();
        let total_release_hold_units = self
            .release_holds
            .values()
            .map(|hold| hold.held_units)
            .sum();
        let fail_closed_mismatch_count = self
            .mismatches
            .values()
            .filter(|mismatch| mismatch.fail_closed)
            .count() as u64;
        let highest_exhaustion_risk_bps = self
            .liquidity_queues
            .values()
            .map(LiquidityQueueObservation::exhaustion_risk_bps)
            .max()
            .unwrap_or(0);

        ObservationSummary {
            total_reserve_units,
            total_liability_units,
            total_pending_release_units,
            aggregate_coverage_bps: ratio_bps(
                total_reserve_units,
                total_liability_units.saturating_add(total_pending_release_units),
            ),
            total_queued_units,
            total_release_capacity_units,
            total_free_release_units,
            total_callable_backstop_units,
            total_release_hold_units,
            fail_closed_mismatch_count,
            highest_exhaustion_risk_bps,
        }
    }

    pub fn coverage_ratios(&self) -> BTreeMap<String, u64> {
        self.reserve_observations
            .iter()
            .map(|(id, observation)| (id.clone(), observation.coverage_bps()))
            .collect()
    }

    pub fn roots(&self) -> ObservationRoots {
        let reserve_observation_root = map_root(
            "BRIDGE-EXIT-RESERVE-OBSERVATIONS",
            &self.reserve_observations,
            ReserveObservation::public_record,
        );
        let liquidity_queue_root = map_root(
            "BRIDGE-EXIT-LIQUIDITY-QUEUES",
            &self.liquidity_queues,
            LiquidityQueueObservation::public_record,
        );
        let coverage_ratio_root = value_root(
            "BRIDGE-EXIT-COVERAGE-RATIOS",
            &json!(self.coverage_ratios()),
        );
        let release_capacity_root = map_root(
            "BRIDGE-EXIT-RELEASE-CAPACITY",
            &self.release_capacities,
            ReleaseCapacitySnapshot::public_record,
        );
        let backstop_availability_root = map_root(
            "BRIDGE-EXIT-BACKSTOP-AVAILABILITY",
            &self.backstops,
            BackstopAvailability::public_record,
        );
        let mismatch_surface_root = map_root(
            "BRIDGE-EXIT-MISMATCH-SURFACES",
            &self.mismatches,
            MismatchRecord::public_record,
        );
        let release_hold_root = map_root(
            "BRIDGE-EXIT-RELEASE-HOLDS",
            &self.release_holds,
            ReleaseHold::public_record,
        );
        let aggregate_root = merkle_root(
            "BRIDGE-EXIT-OBSERVATION-AGGREGATE",
            &[
                reserve_observation_root.clone(),
                liquidity_queue_root.clone(),
                coverage_ratio_root.clone(),
                release_capacity_root.clone(),
                backstop_availability_root.clone(),
                mismatch_surface_root.clone(),
                release_hold_root.clone(),
            ],
        );

        ObservationRoots {
            reserve_observation_root,
            liquidity_queue_root,
            coverage_ratio_root,
            release_capacity_root,
            backstop_availability_root,
            mismatch_surface_root,
            release_hold_root,
            aggregate_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "chain_id": self.config.chain_id,
            "height": self.height,
            "config": self.config.public_record(),
            "summary": self.summary().public_record(),
            "roots": roots.public_record(),
            "reserve_observations": records_map(&self.reserve_observations, ReserveObservation::public_record),
            "liquidity_queues": records_map(&self.liquidity_queues, LiquidityQueueObservation::public_record),
            "release_capacities": records_map(&self.release_capacities, ReleaseCapacitySnapshot::public_record),
            "backstops": records_map(&self.backstops, BackstopAvailability::public_record),
            "mismatches": records_map(&self.mismatches, MismatchRecord::public_record),
            "release_holds": records_map(&self.release_holds, ReleaseHold::public_record),
        })
    }

    pub fn state_root(&self) -> String {
        value_root(
            "BRIDGE-EXIT-RESERVE-LIQUIDITY-LIVE-FEED-STATE",
            &self.public_record(),
        )
    }
}

pub fn devnet() -> State {
    let mut state = State::new(Config::devnet(), 42_000);

    let hot_feed_root = digest_str("DEVNET-FEED", "hot-wallet-feed");
    let warm_feed_root = digest_str("DEVNET-FEED", "warm-vault-feed");
    let forced_queue_root = digest_str("DEVNET-QUEUE", "forced-exit-queue");
    let authority_root = digest_str("DEVNET-AUTHORITY", "bridge-guardian-quorum");

    let _ = state.insert_reserve_observation(ReserveObservation {
        observation_id: "reserve-hot-devnet-0001".to_string(),
        surface: ReserveSurface::HotWallet,
        custodian_commitment: digest_str("DEVNET-CUSTODIAN", "hot-wallet-custodian"),
        reserve_units: 1_850_000,
        liability_units: 1_320_000,
        pending_release_units: 145_000,
        proof_root: digest_str("DEVNET-PROOF", "hot-wallet-proof"),
        feed_root: hot_feed_root.clone(),
        observed_at_height: 41_996,
        expires_at_height: 42_024,
        status: ObservationStatus::Fresh,
    });
    let _ = state.insert_reserve_observation(ReserveObservation {
        observation_id: "reserve-warm-devnet-0001".to_string(),
        surface: ReserveSurface::WarmVault,
        custodian_commitment: digest_str("DEVNET-CUSTODIAN", "warm-vault-custodian"),
        reserve_units: 5_400_000,
        liability_units: 3_820_000,
        pending_release_units: 280_000,
        proof_root: digest_str("DEVNET-PROOF", "warm-vault-proof"),
        feed_root: warm_feed_root.clone(),
        observed_at_height: 41_994,
        expires_at_height: 42_018,
        status: ObservationStatus::Watch,
    });

    let _ = state.insert_liquidity_queue(LiquidityQueueObservation {
        queue_id: "queue-forced-exit-devnet".to_string(),
        queue_kind: LiquidityQueueKind::ForcedExit,
        lane_id: "forced-exit-lane-a".to_string(),
        queued_units: 660_000,
        ready_units: 240_000,
        blocked_units: 90_000,
        max_drain_units_per_block: 30_000,
        oldest_request_height: 41_982,
        observed_at_height: 42_000,
        queue_root: forced_queue_root.clone(),
        capacity_status: CapacityStatus::Constrained,
    });
    let _ = state.insert_release_capacity(ReleaseCapacitySnapshot {
        capacity_id: "capacity-forced-exit-devnet".to_string(),
        lane_id: "forced-exit-lane-a".to_string(),
        available_units: 1_200_000,
        reserved_units: 510_000,
        hold_units: 150_000,
        release_ceiling_units: 900_000,
        release_window_start_height: 42_001,
        release_window_end_height: 42_072,
        source_root: forced_queue_root,
        status: CapacityStatus::Constrained,
    });

    let _ = state.insert_backstop(BackstopAvailability {
        backstop_id: "backstop-slashing-devnet".to_string(),
        kind: BackstopKind::SlashingEscrow,
        provider_commitment: digest_str("DEVNET-BACKSTOP", "operator-slashing-escrow"),
        available_units: 900_000,
        locked_units: 125_000,
        slashable_units: 450_000,
        activation_delay_blocks: 2,
        evidence_root: digest_str("DEVNET-EVIDENCE", "slashing-escrow-proof"),
        observed_at_height: 41_999,
        expires_at_height: 42_036,
        status: ObservationStatus::Fresh,
    });
    let _ = state.insert_mismatch(MismatchRecord {
        mismatch_id: "mismatch-feed-divergence-devnet".to_string(),
        kind: MismatchKind::FeedDivergence,
        subject_id: "reserve-warm-devnet-0001".to_string(),
        expected_root: warm_feed_root,
        observed_root: digest_str("DEVNET-FEED", "warm-vault-feed-shadow"),
        delta_units: 70_000,
        severity_bps: 1_100,
        opened_at_height: 41_999,
        fail_closed: true,
        resolution_root: digest_str("DEVNET-RESOLUTION", "pending"),
    });
    let _ = state.insert_release_hold(ReleaseHold {
        hold_id: "hold-forced-exit-devnet".to_string(),
        release_id: "release-batch-forced-42000".to_string(),
        lane_id: "forced-exit-lane-a".to_string(),
        reason: HoldReason::FeedMismatch,
        held_units: 150_000,
        opened_at_height: 42_000,
        expires_at_height: 42_006,
        authority_root,
        evidence_root: hot_feed_root,
    });

    state
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn records_map<T>(
    records: &BTreeMap<String, T>,
    render: fn(&T) -> Value,
) -> BTreeMap<String, Value> {
    records
        .iter()
        .map(|(id, record)| (id.clone(), render(record)))
        .collect()
}

fn map_root<T>(domain: &str, records: &BTreeMap<String, T>, render: fn(&T) -> Value) -> String {
    let leaves: Vec<String> = records
        .iter()
        .map(|(id, record)| {
            domain_hash(
                domain,
                &[HashPart::Str(id), HashPart::Json(&render(record))],
                32,
            )
        })
        .collect();
    merkle_root(domain, &leaves)
}

fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(value),
        ],
        32,
    )
}

fn digest_str(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(value),
        ],
        32,
    )
}

fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    let scaled = (numerator as u128).saturating_mul(MAX_BPS as u128);
    let ratio = scaled / denominator as u128;
    if ratio > u64::MAX as u128 {
        u64::MAX
    } else {
        ratio as u64
    }
}

fn div_ceil(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return u64::MAX;
    }
    numerator / denominator + u64::from(numerator % denominator != 0)
}
