use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type SequencerPerformanceResult<T> = Result<T, String>;

pub const SEQUENCER_PERFORMANCE_PROTOCOL_VERSION: &str = "nebula-sequencer-performance-kernel-v1";
pub const SEQUENCER_PERFORMANCE_PQ_ATTESTATION_SCHEME: &str =
    "ml-dsa-65-performance-attestation-v1";
pub const SEQUENCER_PERFORMANCE_ROUTE_COMMITMENT_SCHEME: &str =
    "shake256-private-route-commitment-v1";
pub const SEQUENCER_PERFORMANCE_DEVNET_HEIGHT: u64 = 112;
pub const SEQUENCER_PERFORMANCE_MAX_BPS: u64 = 10_000;
pub const SEQUENCER_PERFORMANCE_DEFAULT_TARGET_SLOT_MS: u64 = 250;
pub const SEQUENCER_PERFORMANCE_DEFAULT_MAX_SLOT_MS: u64 = 1_000;
pub const SEQUENCER_PERFORMANCE_DEFAULT_MICROBATCH_TTL_BLOCKS: u64 = 16;
pub const SEQUENCER_PERFORMANCE_DEFAULT_ROUTE_TTL_BLOCKS: u64 = 24;
pub const SEQUENCER_PERFORMANCE_DEFAULT_BACKPRESSURE_TTL_BLOCKS: u64 = 12;
pub const SEQUENCER_PERFORMANCE_DEFAULT_THROTTLE_TTL_BLOCKS: u64 = 24;
pub const SEQUENCER_PERFORMANCE_DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const SEQUENCER_PERFORMANCE_DEFAULT_MAX_PRIVATE_PRESSURE_BPS: u64 = 8_500;
pub const SEQUENCER_PERFORMANCE_DEFAULT_MIN_DA_COVERAGE_BPS: u64 = 9_000;
pub const SEQUENCER_PERFORMANCE_DEFAULT_MIN_PROVER_CAPACITY_BPS: u64 = 6_000;
pub const SEQUENCER_PERFORMANCE_DEFAULT_MAX_LOW_FEE_LANE_BPS: u64 = 7_500;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceLaneClass {
    PrivateTransfer,
    PrivateDefi,
    MoneroBridge,
    LowFeeSponsored,
    ContractCall,
    ProofAggregation,
    EmergencyExit,
}

impl PerformanceLaneClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::PrivateDefi => "private_defi",
            Self::MoneroBridge => "monero_bridge",
            Self::LowFeeSponsored => "low_fee_sponsored",
            Self::ContractCall => "contract_call",
            Self::ProofAggregation => "proof_aggregation",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::EmergencyExit => 100,
            Self::MoneroBridge => 95,
            Self::PrivateTransfer => 90,
            Self::PrivateDefi => 85,
            Self::ContractCall => 80,
            Self::LowFeeSponsored => 70,
            Self::ProofAggregation => 60,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceMode {
    Fast,
    Balanced,
    LowFee,
    PrivacyMax,
    Degraded,
    Emergency,
}

impl PerformanceMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Balanced => "balanced",
            Self::LowFee => "low_fee",
            Self::PrivacyMax => "privacy_max",
            Self::Degraded => "degraded",
            Self::Emergency => "emergency",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceStatus {
    Active,
    Guarded,
    Throttled,
    Paused,
    Expired,
}

impl PerformanceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Guarded => "guarded",
            Self::Throttled => "throttled",
            Self::Paused => "paused",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Active | Self::Guarded | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionDecision {
    AdmitFast,
    AdmitBatched,
    Defer,
    SponsorOnly,
    Reject,
}

impl AdmissionDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AdmitFast => "admit_fast",
            Self::AdmitBatched => "admit_batched",
            Self::Defer => "defer",
            Self::SponsorOnly => "sponsor_only",
            Self::Reject => "reject",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MicroBatchStatus {
    Open,
    Sealed,
    Submitted,
    Proven,
    Dropped,
    Expired,
}

impl MicroBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Submitted => "submitted",
            Self::Proven => "proven",
            Self::Dropped => "dropped",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::Sealed | Self::Submitted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacitySignalKind {
    Execution,
    Prover,
    DataAvailability,
    Mempool,
    MoneroRpc,
    Network,
}

impl CapacitySignalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Execution => "execution",
            Self::Prover => "prover",
            Self::DataAvailability => "data_availability",
            Self::Mempool => "mempool",
            Self::MoneroRpc => "monero_rpc",
            Self::Network => "network",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackpressureReason {
    ProverCapacity,
    DataAvailability,
    PrivateMempool,
    LowFeeBudget,
    MoneroRpcLag,
    EmergencyThrottle,
}

impl BackpressureReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProverCapacity => "prover_capacity",
            Self::DataAvailability => "data_availability",
            Self::PrivateMempool => "private_mempool",
            Self::LowFeeBudget => "low_fee_budget",
            Self::MoneroRpcLag => "monero_rpc_lag",
            Self::EmergencyThrottle => "emergency_throttle",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutePrivacyClass {
    Public,
    MetadataHidden,
    FullyShielded,
    ThresholdEncrypted,
}

impl RoutePrivacyClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::MetadataHidden => "metadata_hidden",
            Self::FullyShielded => "fully_shielded",
            Self::ThresholdEncrypted => "threshold_encrypted",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqPerformanceAttestationSubject {
    Lane,
    MicroBatch,
    Route,
    CapacitySnapshot,
    BackpressureWindow,
    SafetyThrottle,
}

impl PqPerformanceAttestationSubject {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lane => "lane",
            Self::MicroBatch => "micro_batch",
            Self::Route => "route",
            Self::CapacitySnapshot => "capacity_snapshot",
            Self::BackpressureWindow => "backpressure_window",
            Self::SafetyThrottle => "safety_throttle",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqPerformanceAttestationStatus {
    Valid,
    ThresholdValid,
    Revoked,
    Expired,
}

impl PqPerformanceAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::ThresholdValid => "threshold_valid",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Valid | Self::ThresholdValid)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerPerformanceConfig {
    pub protocol_version: String,
    pub target_slot_ms: u64,
    pub max_slot_ms: u64,
    pub microbatch_ttl_blocks: u64,
    pub route_ttl_blocks: u64,
    pub backpressure_ttl_blocks: u64,
    pub throttle_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub max_private_pressure_bps: u64,
    pub min_da_coverage_bps: u64,
    pub min_prover_capacity_bps: u64,
    pub max_low_fee_lane_bps: u64,
    pub default_mode: PerformanceMode,
}

impl Default for SequencerPerformanceConfig {
    fn default() -> Self {
        Self {
            protocol_version: SEQUENCER_PERFORMANCE_PROTOCOL_VERSION.to_string(),
            target_slot_ms: SEQUENCER_PERFORMANCE_DEFAULT_TARGET_SLOT_MS,
            max_slot_ms: SEQUENCER_PERFORMANCE_DEFAULT_MAX_SLOT_MS,
            microbatch_ttl_blocks: SEQUENCER_PERFORMANCE_DEFAULT_MICROBATCH_TTL_BLOCKS,
            route_ttl_blocks: SEQUENCER_PERFORMANCE_DEFAULT_ROUTE_TTL_BLOCKS,
            backpressure_ttl_blocks: SEQUENCER_PERFORMANCE_DEFAULT_BACKPRESSURE_TTL_BLOCKS,
            throttle_ttl_blocks: SEQUENCER_PERFORMANCE_DEFAULT_THROTTLE_TTL_BLOCKS,
            attestation_ttl_blocks: SEQUENCER_PERFORMANCE_DEFAULT_ATTESTATION_TTL_BLOCKS,
            max_private_pressure_bps: SEQUENCER_PERFORMANCE_DEFAULT_MAX_PRIVATE_PRESSURE_BPS,
            min_da_coverage_bps: SEQUENCER_PERFORMANCE_DEFAULT_MIN_DA_COVERAGE_BPS,
            min_prover_capacity_bps: SEQUENCER_PERFORMANCE_DEFAULT_MIN_PROVER_CAPACITY_BPS,
            max_low_fee_lane_bps: SEQUENCER_PERFORMANCE_DEFAULT_MAX_LOW_FEE_LANE_BPS,
            default_mode: PerformanceMode::Balanced,
        }
    }
}

impl SequencerPerformanceConfig {
    pub fn validate(&self) -> SequencerPerformanceResult<()> {
        ensure_non_empty(
            "sequencer performance protocol version",
            &self.protocol_version,
        )?;
        if self.protocol_version != SEQUENCER_PERFORMANCE_PROTOCOL_VERSION {
            return Err("sequencer performance protocol version mismatch".to_string());
        }
        ensure_positive("target slot ms", self.target_slot_ms)?;
        ensure_positive("max slot ms", self.max_slot_ms)?;
        if self.target_slot_ms > self.max_slot_ms {
            return Err("target slot ms exceeds max slot ms".to_string());
        }
        ensure_positive("microbatch ttl blocks", self.microbatch_ttl_blocks)?;
        ensure_positive("route ttl blocks", self.route_ttl_blocks)?;
        ensure_positive("backpressure ttl blocks", self.backpressure_ttl_blocks)?;
        ensure_positive("throttle ttl blocks", self.throttle_ttl_blocks)?;
        ensure_positive("attestation ttl blocks", self.attestation_ttl_blocks)?;
        ensure_bps("max private pressure", self.max_private_pressure_bps)?;
        ensure_bps("min da coverage", self.min_da_coverage_bps)?;
        ensure_bps("min prover capacity", self.min_prover_capacity_bps)?;
        ensure_bps("max low fee lane bps", self.max_low_fee_lane_bps)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sequencer_performance_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "target_slot_ms": self.target_slot_ms,
            "max_slot_ms": self.max_slot_ms,
            "microbatch_ttl_blocks": self.microbatch_ttl_blocks,
            "route_ttl_blocks": self.route_ttl_blocks,
            "backpressure_ttl_blocks": self.backpressure_ttl_blocks,
            "throttle_ttl_blocks": self.throttle_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "max_private_pressure_bps": self.max_private_pressure_bps,
            "min_da_coverage_bps": self.min_da_coverage_bps,
            "min_prover_capacity_bps": self.min_prover_capacity_bps,
            "max_low_fee_lane_bps": self.max_low_fee_lane_bps,
            "default_mode": self.default_mode.as_str(),
        })
    }

    pub fn config_root(&self) -> String {
        sequencer_performance_payload_root("SEQUENCER-PERFORMANCE-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowLatencyLane {
    pub lane_id: String,
    pub label: String,
    pub lane_class: PerformanceLaneClass,
    pub privacy_class: RoutePrivacyClass,
    pub target_latency_ms: u64,
    pub max_payload_bytes: u64,
    pub reserved_capacity_bps: u64,
    pub low_fee_share_bps: u64,
    pub priority: u64,
    pub mode: PerformanceMode,
    pub status: PerformanceStatus,
    pub created_at_height: u64,
}

impl LowLatencyLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: &str,
        lane_class: PerformanceLaneClass,
        privacy_class: RoutePrivacyClass,
        target_latency_ms: u64,
        max_payload_bytes: u64,
        reserved_capacity_bps: u64,
        low_fee_share_bps: u64,
        mode: PerformanceMode,
        created_at_height: u64,
    ) -> SequencerPerformanceResult<Self> {
        ensure_non_empty("lane label", label)?;
        ensure_positive("lane target latency", target_latency_ms)?;
        ensure_positive("lane max payload bytes", max_payload_bytes)?;
        ensure_bps("lane reserved capacity", reserved_capacity_bps)?;
        ensure_bps("lane low fee share", low_fee_share_bps)?;
        let priority = lane_class.default_priority();
        let lane_id = low_latency_lane_id(label, lane_class, privacy_class, created_at_height);
        Ok(Self {
            lane_id,
            label: label.to_string(),
            lane_class,
            privacy_class,
            target_latency_ms,
            max_payload_bytes,
            reserved_capacity_bps,
            low_fee_share_bps,
            priority,
            mode,
            status: PerformanceStatus::Active,
            created_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_latency_lane",
            "chain_id": CHAIN_ID,
            "protocol_version": SEQUENCER_PERFORMANCE_PROTOCOL_VERSION,
            "lane_id": self.lane_id,
            "label": self.label,
            "lane_class": self.lane_class.as_str(),
            "privacy_class": self.privacy_class.as_str(),
            "target_latency_ms": self.target_latency_ms,
            "max_payload_bytes": self.max_payload_bytes,
            "reserved_capacity_bps": self.reserved_capacity_bps,
            "low_fee_share_bps": self.low_fee_share_bps,
            "priority": self.priority,
            "mode": self.mode.as_str(),
            "status": self.status.as_str(),
            "created_at_height": self.created_at_height,
        })
    }

    pub fn lane_root(&self) -> String {
        sequencer_performance_payload_root("LOW-LATENCY-LANE", &self.public_record())
    }

    pub fn validate(&self) -> SequencerPerformanceResult<String> {
        ensure_non_empty("lane id", &self.lane_id)?;
        ensure_non_empty("lane label", &self.label)?;
        ensure_positive("lane target latency", self.target_latency_ms)?;
        ensure_positive("lane max payload bytes", self.max_payload_bytes)?;
        ensure_bps("lane reserved capacity", self.reserved_capacity_bps)?;
        ensure_bps("lane low fee share", self.low_fee_share_bps)?;
        let expected = low_latency_lane_id(
            &self.label,
            self.lane_class,
            self.privacy_class,
            self.created_at_height,
        );
        if self.lane_id != expected {
            return Err("low latency lane id mismatch".to_string());
        }
        Ok(self.lane_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicroBatchPlan {
    pub batch_id: String,
    pub lane_id: String,
    pub payload_root: String,
    pub route_root: String,
    pub admission_count: u64,
    pub payload_bytes: u64,
    pub target_latency_ms: u64,
    pub fee_budget_units: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: MicroBatchStatus,
}

impl MicroBatchPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: &str,
        payload: &Value,
        route_labels: Vec<String>,
        admission_count: u64,
        payload_bytes: u64,
        target_latency_ms: u64,
        fee_budget_units: u64,
        opened_at_height: u64,
        ttl_blocks: u64,
    ) -> SequencerPerformanceResult<Self> {
        ensure_non_empty("microbatch lane id", lane_id)?;
        ensure_positive("microbatch admission count", admission_count)?;
        ensure_positive("microbatch payload bytes", payload_bytes)?;
        ensure_positive("microbatch target latency", target_latency_ms)?;
        ensure_positive("microbatch ttl blocks", ttl_blocks)?;
        ensure_unique_strings(&route_labels, "microbatch route labels")?;
        let payload_root = sequencer_performance_payload_root("MICROBATCH-PAYLOAD", payload);
        let route_root = sequencer_performance_string_set_root("MICROBATCH-ROUTE", &route_labels);
        let expires_at_height = opened_at_height.saturating_add(ttl_blocks);
        let batch_id = microbatch_plan_id(lane_id, &payload_root, opened_at_height);
        Ok(Self {
            batch_id,
            lane_id: lane_id.to_string(),
            payload_root,
            route_root,
            admission_count,
            payload_bytes,
            target_latency_ms,
            fee_budget_units,
            opened_at_height,
            expires_at_height,
            status: MicroBatchStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "microbatch_plan",
            "chain_id": CHAIN_ID,
            "protocol_version": SEQUENCER_PERFORMANCE_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "payload_root": self.payload_root,
            "route_root": self.route_root,
            "admission_count": self.admission_count,
            "payload_bytes": self.payload_bytes,
            "target_latency_ms": self.target_latency_ms,
            "fee_budget_units": self.fee_budget_units,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn batch_root(&self) -> String {
        sequencer_performance_payload_root("MICROBATCH-PLAN", &self.public_record())
    }

    pub fn validate(&self) -> SequencerPerformanceResult<String> {
        ensure_non_empty("microbatch id", &self.batch_id)?;
        ensure_non_empty("microbatch lane id", &self.lane_id)?;
        ensure_non_empty("microbatch payload root", &self.payload_root)?;
        ensure_non_empty("microbatch route root", &self.route_root)?;
        ensure_positive("microbatch admission count", self.admission_count)?;
        ensure_positive("microbatch payload bytes", self.payload_bytes)?;
        ensure_positive("microbatch target latency", self.target_latency_ms)?;
        ensure_height_window(
            self.opened_at_height,
            self.expires_at_height,
            "microbatch ttl",
        )?;
        let expected = microbatch_plan_id(&self.lane_id, &self.payload_root, self.opened_at_height);
        if self.batch_id != expected {
            return Err("microbatch id mismatch".to_string());
        }
        Ok(self.batch_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteAdmission {
    pub admission_id: String,
    pub lane_id: String,
    pub route_commitment: String,
    pub encrypted_metadata_root: String,
    pub payload_bytes: u64,
    pub max_fee_units: u64,
    pub decision: AdmissionDecision,
    pub admitted_at_height: u64,
    pub expires_at_height: u64,
}

impl RouteAdmission {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: &str,
        route_label: &str,
        encrypted_metadata: &Value,
        payload_bytes: u64,
        max_fee_units: u64,
        decision: AdmissionDecision,
        admitted_at_height: u64,
        ttl_blocks: u64,
    ) -> SequencerPerformanceResult<Self> {
        ensure_non_empty("route admission lane id", lane_id)?;
        ensure_non_empty("route label", route_label)?;
        ensure_positive("route payload bytes", payload_bytes)?;
        ensure_positive("route ttl blocks", ttl_blocks)?;
        let route_commitment = sequencer_performance_string_root("ROUTE-COMMITMENT", route_label);
        let encrypted_metadata_root =
            sequencer_performance_payload_root("ROUTE-ENCRYPTED-METADATA", encrypted_metadata);
        let expires_at_height = admitted_at_height.saturating_add(ttl_blocks);
        let admission_id = route_admission_id(
            lane_id,
            &route_commitment,
            admitted_at_height,
            payload_bytes,
        );
        Ok(Self {
            admission_id,
            lane_id: lane_id.to_string(),
            route_commitment,
            encrypted_metadata_root,
            payload_bytes,
            max_fee_units,
            decision,
            admitted_at_height,
            expires_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "route_admission",
            "chain_id": CHAIN_ID,
            "protocol_version": SEQUENCER_PERFORMANCE_PROTOCOL_VERSION,
            "admission_id": self.admission_id,
            "lane_id": self.lane_id,
            "route_commitment": self.route_commitment,
            "encrypted_metadata_root": self.encrypted_metadata_root,
            "payload_bytes": self.payload_bytes,
            "max_fee_units": self.max_fee_units,
            "decision": self.decision.as_str(),
            "admitted_at_height": self.admitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn admission_root(&self) -> String {
        sequencer_performance_payload_root("ROUTE-ADMISSION", &self.public_record())
    }

    pub fn validate(&self) -> SequencerPerformanceResult<String> {
        ensure_non_empty("route admission id", &self.admission_id)?;
        ensure_non_empty("route admission lane id", &self.lane_id)?;
        ensure_non_empty("route commitment", &self.route_commitment)?;
        ensure_non_empty(
            "route encrypted metadata root",
            &self.encrypted_metadata_root,
        )?;
        ensure_positive("route payload bytes", self.payload_bytes)?;
        ensure_height_window(
            self.admitted_at_height,
            self.expires_at_height,
            "route admission ttl",
        )?;
        let expected = route_admission_id(
            &self.lane_id,
            &self.route_commitment,
            self.admitted_at_height,
            self.payload_bytes,
        );
        if self.admission_id != expected {
            return Err("route admission id mismatch".to_string());
        }
        Ok(self.admission_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacitySnapshot {
    pub snapshot_id: String,
    pub signal_kind: CapacitySignalKind,
    pub capacity_bps: u64,
    pub queue_depth: u64,
    pub median_latency_ms: u64,
    pub observed_at_height: u64,
    pub signal_root: String,
}

impl CapacitySnapshot {
    pub fn new(
        signal_kind: CapacitySignalKind,
        capacity_bps: u64,
        queue_depth: u64,
        median_latency_ms: u64,
        observed_at_height: u64,
        signal_payload: &Value,
    ) -> SequencerPerformanceResult<Self> {
        ensure_bps("capacity snapshot bps", capacity_bps)?;
        ensure_positive("capacity median latency", median_latency_ms)?;
        let signal_root = sequencer_performance_payload_root("CAPACITY-SIGNAL", signal_payload);
        let snapshot_id =
            capacity_snapshot_id(signal_kind, capacity_bps, observed_at_height, &signal_root);
        Ok(Self {
            snapshot_id,
            signal_kind,
            capacity_bps,
            queue_depth,
            median_latency_ms,
            observed_at_height,
            signal_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "capacity_snapshot",
            "chain_id": CHAIN_ID,
            "protocol_version": SEQUENCER_PERFORMANCE_PROTOCOL_VERSION,
            "snapshot_id": self.snapshot_id,
            "signal_kind": self.signal_kind.as_str(),
            "capacity_bps": self.capacity_bps,
            "queue_depth": self.queue_depth,
            "median_latency_ms": self.median_latency_ms,
            "observed_at_height": self.observed_at_height,
            "signal_root": self.signal_root,
        })
    }

    pub fn snapshot_root(&self) -> String {
        sequencer_performance_payload_root("CAPACITY-SNAPSHOT", &self.public_record())
    }

    pub fn validate(&self) -> SequencerPerformanceResult<String> {
        ensure_non_empty("capacity snapshot id", &self.snapshot_id)?;
        ensure_bps("capacity snapshot bps", self.capacity_bps)?;
        ensure_positive("capacity median latency", self.median_latency_ms)?;
        ensure_non_empty("capacity signal root", &self.signal_root)?;
        let expected = capacity_snapshot_id(
            self.signal_kind,
            self.capacity_bps,
            self.observed_at_height,
            &self.signal_root,
        );
        if self.snapshot_id != expected {
            return Err("capacity snapshot id mismatch".to_string());
        }
        Ok(self.snapshot_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackpressureWindow {
    pub window_id: String,
    pub reason: BackpressureReason,
    pub affected_lane_ids: Vec<String>,
    pub pressure_bps: u64,
    pub max_admission_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: PerformanceStatus,
}

impl BackpressureWindow {
    pub fn new(
        reason: BackpressureReason,
        affected_lane_ids: Vec<String>,
        pressure_bps: u64,
        max_admission_bps: u64,
        opened_at_height: u64,
        ttl_blocks: u64,
    ) -> SequencerPerformanceResult<Self> {
        if affected_lane_ids.is_empty() {
            return Err("backpressure window has no affected lanes".to_string());
        }
        ensure_unique_strings(&affected_lane_ids, "backpressure lanes")?;
        ensure_bps("backpressure pressure", pressure_bps)?;
        ensure_bps("backpressure max admission", max_admission_bps)?;
        ensure_positive("backpressure ttl blocks", ttl_blocks)?;
        let expires_at_height = opened_at_height.saturating_add(ttl_blocks);
        let window_id = backpressure_window_id(reason, &affected_lane_ids, opened_at_height);
        let status = if max_admission_bps == 0 {
            PerformanceStatus::Paused
        } else if pressure_bps >= 9_000 {
            PerformanceStatus::Throttled
        } else {
            PerformanceStatus::Guarded
        };
        Ok(Self {
            window_id,
            reason,
            affected_lane_ids,
            pressure_bps,
            max_admission_bps,
            opened_at_height,
            expires_at_height,
            status,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "backpressure_window",
            "chain_id": CHAIN_ID,
            "protocol_version": SEQUENCER_PERFORMANCE_PROTOCOL_VERSION,
            "window_id": self.window_id,
            "reason": self.reason.as_str(),
            "affected_lane_ids": self.affected_lane_ids,
            "pressure_bps": self.pressure_bps,
            "max_admission_bps": self.max_admission_bps,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn window_root(&self) -> String {
        sequencer_performance_payload_root("BACKPRESSURE-WINDOW", &self.public_record())
    }

    pub fn validate(&self) -> SequencerPerformanceResult<String> {
        ensure_non_empty("backpressure window id", &self.window_id)?;
        if self.affected_lane_ids.is_empty() {
            return Err("backpressure window has no affected lanes".to_string());
        }
        ensure_unique_strings(&self.affected_lane_ids, "backpressure lanes")?;
        ensure_bps("backpressure pressure", self.pressure_bps)?;
        ensure_bps("backpressure max admission", self.max_admission_bps)?;
        ensure_height_window(
            self.opened_at_height,
            self.expires_at_height,
            "backpressure ttl",
        )?;
        let expected =
            backpressure_window_id(self.reason, &self.affected_lane_ids, self.opened_at_height);
        if self.window_id != expected {
            return Err("backpressure window id mismatch".to_string());
        }
        Ok(self.window_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceSafetyThrottle {
    pub throttle_id: String,
    pub lane_id: String,
    pub reason: BackpressureReason,
    pub max_payload_bytes: u64,
    pub max_fee_units: u64,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
    pub status: PerformanceStatus,
}

impl PerformanceSafetyThrottle {
    pub fn new(
        lane_id: &str,
        reason: BackpressureReason,
        max_payload_bytes: u64,
        max_fee_units: u64,
        activated_at_height: u64,
        ttl_blocks: u64,
    ) -> SequencerPerformanceResult<Self> {
        ensure_non_empty("throttle lane id", lane_id)?;
        ensure_positive("throttle max payload bytes", max_payload_bytes)?;
        ensure_positive("throttle ttl blocks", ttl_blocks)?;
        let expires_at_height = activated_at_height.saturating_add(ttl_blocks);
        let throttle_id = performance_safety_throttle_id(lane_id, reason, activated_at_height);
        Ok(Self {
            throttle_id,
            lane_id: lane_id.to_string(),
            reason,
            max_payload_bytes,
            max_fee_units,
            activated_at_height,
            expires_at_height,
            status: PerformanceStatus::Throttled,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "performance_safety_throttle",
            "chain_id": CHAIN_ID,
            "protocol_version": SEQUENCER_PERFORMANCE_PROTOCOL_VERSION,
            "throttle_id": self.throttle_id,
            "lane_id": self.lane_id,
            "reason": self.reason.as_str(),
            "max_payload_bytes": self.max_payload_bytes,
            "max_fee_units": self.max_fee_units,
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn throttle_root(&self) -> String {
        sequencer_performance_payload_root("PERFORMANCE-SAFETY-THROTTLE", &self.public_record())
    }

    pub fn validate(&self) -> SequencerPerformanceResult<String> {
        ensure_non_empty("throttle id", &self.throttle_id)?;
        ensure_non_empty("throttle lane id", &self.lane_id)?;
        ensure_positive("throttle max payload bytes", self.max_payload_bytes)?;
        ensure_height_window(
            self.activated_at_height,
            self.expires_at_height,
            "throttle ttl",
        )?;
        let expected =
            performance_safety_throttle_id(&self.lane_id, self.reason, self.activated_at_height);
        if self.throttle_id != expected {
            return Err("performance safety throttle id mismatch".to_string());
        }
        Ok(self.throttle_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqPerformanceAttestation {
    pub attestation_id: String,
    pub subject: PqPerformanceAttestationSubject,
    pub subject_id: String,
    pub subject_root: String,
    pub signer_commitment: String,
    pub signature_root: String,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
    pub signer_weight_bps: u64,
    pub status: PqPerformanceAttestationStatus,
}

impl PqPerformanceAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject: PqPerformanceAttestationSubject,
        subject_id: &str,
        subject_root: &str,
        signer_label: &str,
        signature_label: &str,
        signed_at_height: u64,
        ttl_blocks: u64,
        signer_weight_bps: u64,
        threshold_bps: u64,
    ) -> SequencerPerformanceResult<Self> {
        ensure_non_empty("performance attestation subject id", subject_id)?;
        ensure_non_empty("performance attestation subject root", subject_root)?;
        ensure_non_empty("performance attestation signer", signer_label)?;
        ensure_non_empty("performance attestation signature", signature_label)?;
        ensure_positive("performance attestation ttl blocks", ttl_blocks)?;
        ensure_bps("performance attestation signer weight", signer_weight_bps)?;
        ensure_bps("performance attestation threshold", threshold_bps)?;
        let signer_commitment =
            sequencer_performance_string_root("PQ-PERFORMANCE-SIGNER", signer_label);
        let signature_root = sequencer_performance_payload_root(
            "PQ-PERFORMANCE-SIGNATURE",
            &json!({
                "scheme": SEQUENCER_PERFORMANCE_PQ_ATTESTATION_SCHEME,
                "subject": subject.as_str(),
                "subject_id": subject_id,
                "subject_root": subject_root,
                "signature_label": signature_label,
            }),
        );
        let expires_at_height = signed_at_height.saturating_add(ttl_blocks);
        let status = if signer_weight_bps >= threshold_bps {
            PqPerformanceAttestationStatus::ThresholdValid
        } else {
            PqPerformanceAttestationStatus::Valid
        };
        let attestation_id = pq_performance_attestation_id(
            subject,
            subject_id,
            subject_root,
            &signer_commitment,
            signed_at_height,
        );
        Ok(Self {
            attestation_id,
            subject,
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            signer_commitment,
            signature_root,
            signed_at_height,
            expires_at_height,
            signer_weight_bps,
            status,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_performance_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": SEQUENCER_PERFORMANCE_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "subject": self.subject.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "signer_commitment": self.signer_commitment,
            "signature_root": self.signature_root,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
            "signer_weight_bps": self.signer_weight_bps,
            "status": self.status.as_str(),
        })
    }

    pub fn attestation_root(&self) -> String {
        sequencer_performance_payload_root("PQ-PERFORMANCE-ATTESTATION", &self.public_record())
    }

    pub fn validate(&self) -> SequencerPerformanceResult<String> {
        ensure_non_empty("performance attestation id", &self.attestation_id)?;
        ensure_non_empty("performance attestation subject id", &self.subject_id)?;
        ensure_non_empty("performance attestation subject root", &self.subject_root)?;
        ensure_non_empty(
            "performance attestation signer commitment",
            &self.signer_commitment,
        )?;
        ensure_non_empty(
            "performance attestation signature root",
            &self.signature_root,
        )?;
        ensure_bps(
            "performance attestation signer weight",
            self.signer_weight_bps,
        )?;
        ensure_height_window(
            self.signed_at_height,
            self.expires_at_height,
            "performance attestation ttl",
        )?;
        let expected = pq_performance_attestation_id(
            self.subject,
            &self.subject_id,
            &self.subject_root,
            &self.signer_commitment,
            self.signed_at_height,
        );
        if self.attestation_id != expected {
            return Err("performance attestation id mismatch".to_string());
        }
        Ok(self.attestation_root())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerPerformanceRoots {
    pub config_root: String,
    pub lane_root: String,
    pub microbatch_root: String,
    pub route_admission_root: String,
    pub capacity_snapshot_root: String,
    pub backpressure_window_root: String,
    pub safety_throttle_root: String,
    pub pq_attestation_root: String,
    pub public_record_root: String,
}

impl SequencerPerformanceRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sequencer_performance_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": SEQUENCER_PERFORMANCE_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "microbatch_root": self.microbatch_root,
            "route_admission_root": self.route_admission_root,
            "capacity_snapshot_root": self.capacity_snapshot_root,
            "backpressure_window_root": self.backpressure_window_root,
            "safety_throttle_root": self.safety_throttle_root,
            "pq_attestation_root": self.pq_attestation_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerPerformanceCounters {
    pub height: u64,
    pub lane_count: u64,
    pub active_lane_count: u64,
    pub open_microbatch_count: u64,
    pub live_route_count: u64,
    pub capacity_snapshot_count: u64,
    pub guarded_window_count: u64,
    pub active_throttle_count: u64,
    pub pq_attestation_count: u64,
    pub total_reserved_capacity_bps: u64,
    pub total_low_fee_share_bps: u64,
    pub total_payload_bytes: u64,
    pub average_capacity_bps: u64,
    pub max_queue_depth: u64,
}

impl SequencerPerformanceCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sequencer_performance_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": SEQUENCER_PERFORMANCE_PROTOCOL_VERSION,
            "height": self.height,
            "lane_count": self.lane_count,
            "active_lane_count": self.active_lane_count,
            "open_microbatch_count": self.open_microbatch_count,
            "live_route_count": self.live_route_count,
            "capacity_snapshot_count": self.capacity_snapshot_count,
            "guarded_window_count": self.guarded_window_count,
            "active_throttle_count": self.active_throttle_count,
            "pq_attestation_count": self.pq_attestation_count,
            "total_reserved_capacity_bps": self.total_reserved_capacity_bps,
            "total_low_fee_share_bps": self.total_low_fee_share_bps,
            "total_payload_bytes": self.total_payload_bytes,
            "average_capacity_bps": self.average_capacity_bps,
            "max_queue_depth": self.max_queue_depth,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerPerformanceKernelState {
    pub height: u64,
    pub config: SequencerPerformanceConfig,
    pub lanes: BTreeMap<String, LowLatencyLane>,
    pub microbatches: BTreeMap<String, MicroBatchPlan>,
    pub route_admissions: BTreeMap<String, RouteAdmission>,
    pub capacity_snapshots: BTreeMap<String, CapacitySnapshot>,
    pub backpressure_windows: BTreeMap<String, BackpressureWindow>,
    pub safety_throttles: BTreeMap<String, PerformanceSafetyThrottle>,
    pub pq_attestations: BTreeMap<String, PqPerformanceAttestation>,
    pub public_records: BTreeMap<String, Value>,
}

impl SequencerPerformanceKernelState {
    pub fn new(config: SequencerPerformanceConfig) -> SequencerPerformanceResult<Self> {
        config.validate()?;
        Ok(Self {
            height: 0,
            config,
            lanes: BTreeMap::new(),
            microbatches: BTreeMap::new(),
            route_admissions: BTreeMap::new(),
            capacity_snapshots: BTreeMap::new(),
            backpressure_windows: BTreeMap::new(),
            safety_throttles: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> SequencerPerformanceResult<Self> {
        let mut state = Self::new(SequencerPerformanceConfig::default())?;
        state.set_height(SEQUENCER_PERFORMANCE_DEVNET_HEIGHT)?;

        let private_lane = LowLatencyLane::new(
            "devnet-fast-private-transfer",
            PerformanceLaneClass::PrivateTransfer,
            RoutePrivacyClass::ThresholdEncrypted,
            220,
            64_000,
            2_500,
            1_000,
            PerformanceMode::Fast,
            state.height,
        )?;
        let defi_lane = LowLatencyLane::new(
            "devnet-private-defi",
            PerformanceLaneClass::PrivateDefi,
            RoutePrivacyClass::FullyShielded,
            350,
            128_000,
            2_000,
            800,
            PerformanceMode::PrivacyMax,
            state.height,
        )?;
        let bridge_lane = LowLatencyLane::new(
            "devnet-monero-bridge",
            PerformanceLaneClass::MoneroBridge,
            RoutePrivacyClass::MetadataHidden,
            500,
            96_000,
            2_000,
            1_200,
            PerformanceMode::Balanced,
            state.height,
        )?;
        let low_fee_lane = LowLatencyLane::new(
            "devnet-low-fee-sponsored",
            PerformanceLaneClass::LowFeeSponsored,
            RoutePrivacyClass::MetadataHidden,
            750,
            192_000,
            1_500,
            4_500,
            PerformanceMode::LowFee,
            state.height,
        )?;
        let private_lane_id = state.insert_lane(private_lane.clone())?;
        let defi_lane_id = state.insert_lane(defi_lane.clone())?;
        let bridge_lane_id = state.insert_lane(bridge_lane.clone())?;
        let low_fee_lane_id = state.insert_lane(low_fee_lane.clone())?;

        let batch_id = state.insert_microbatch(MicroBatchPlan::new(
            &private_lane_id,
            &json!({
                "ciphertext_root": "devnet-private-transfer-batch",
                "note_count": 96,
                "proof_hint": "small-recursive",
            }),
            vec![
                "wallet-edge-a".to_string(),
                "private-relay-a".to_string(),
                "sequencer-fast-lane".to_string(),
            ],
            96,
            48_000,
            220,
            1_400,
            state.height,
            state.config.microbatch_ttl_blocks,
        )?)?;

        state.insert_route_admission(RouteAdmission::new(
            &private_lane_id,
            "alice-fast-private-route",
            &json!({"view_tag": "encrypted", "relay": "threshold", "anti_mev": true}),
            512,
            32,
            AdmissionDecision::AdmitFast,
            state.height,
            state.config.route_ttl_blocks,
        )?)?;
        state.insert_route_admission(RouteAdmission::new(
            &low_fee_lane_id,
            "low-fee-sponsored-route",
            &json!({"sponsor": "devnet-low-fee-vault", "payer": "commitment-only"}),
            768,
            8,
            AdmissionDecision::SponsorOnly,
            state.height,
            state.config.route_ttl_blocks,
        )?)?;

        for snapshot in [
            CapacitySnapshot::new(
                CapacitySignalKind::Execution,
                8_800,
                24,
                180,
                state.height,
                &json!({"executor": "parallel", "hot_state_cache": "healthy"}),
            )?,
            CapacitySnapshot::new(
                CapacitySignalKind::Prover,
                7_200,
                18,
                420,
                state.height,
                &json!({"gpu_workers": 4, "recursive_batcher": "ready"}),
            )?,
            CapacitySnapshot::new(
                CapacitySignalKind::DataAvailability,
                9_600,
                8,
                140,
                state.height,
                &json!({"sample_coverage_bps": 9600, "erasure_queue": 8}),
            )?,
            CapacitySnapshot::new(
                CapacitySignalKind::MoneroRpc,
                8_100,
                5,
                650,
                state.height,
                &json!({"daemon_quorum": "fresh", "observed_lag": 1}),
            )?,
        ] {
            state.insert_capacity_snapshot(snapshot)?;
        }

        let backpressure_id = state.insert_backpressure_window(BackpressureWindow::new(
            BackpressureReason::ProverCapacity,
            vec![defi_lane_id.clone(), bridge_lane_id.clone()],
            7_900,
            6_500,
            state.height,
            state.config.backpressure_ttl_blocks,
        )?)?;
        let throttle = PerformanceSafetyThrottle::new(
            &defi_lane_id,
            BackpressureReason::ProverCapacity,
            96_000,
            4_000,
            state.height,
            state.config.throttle_ttl_blocks,
        )?;
        let throttle_id = state.insert_safety_throttle(throttle.clone())?;

        for (subject, subject_id, subject_root, signer, weight) in [
            (
                PqPerformanceAttestationSubject::Lane,
                private_lane_id.clone(),
                private_lane.lane_root(),
                "devnet-performance-committee-a",
                6_700,
            ),
            (
                PqPerformanceAttestationSubject::MicroBatch,
                batch_id.clone(),
                state
                    .microbatches
                    .get(&batch_id)
                    .map(MicroBatchPlan::batch_root)
                    .ok_or_else(|| "missing devnet microbatch".to_string())?,
                "devnet-performance-committee-b",
                6_700,
            ),
            (
                PqPerformanceAttestationSubject::BackpressureWindow,
                backpressure_id.clone(),
                state
                    .backpressure_windows
                    .get(&backpressure_id)
                    .map(BackpressureWindow::window_root)
                    .ok_or_else(|| "missing devnet backpressure".to_string())?,
                "devnet-performance-committee-c",
                5_000,
            ),
            (
                PqPerformanceAttestationSubject::SafetyThrottle,
                throttle_id,
                throttle.throttle_root(),
                "devnet-performance-committee-a",
                6_700,
            ),
        ] {
            state.insert_pq_attestation(PqPerformanceAttestation::new(
                subject,
                &subject_id,
                &subject_root,
                signer,
                "devnet-performance-pq-signature",
                state.height,
                state.config.attestation_ttl_blocks,
                weight,
                6_667,
            )?)?;
        }

        state.record_public_record(
            "devnet-performance-note",
            &json!({
                "mode": "fast-private-with-guarded-defi",
                "private_lane_id": private_lane_id,
                "low_fee_lane_id": low_fee_lane_id,
            }),
        )?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> SequencerPerformanceResult<String> {
        self.height = height;
        for batch in self.microbatches.values_mut() {
            if self.height > batch.expires_at_height && batch.status.live() {
                batch.status = MicroBatchStatus::Expired;
            }
        }
        for window in self.backpressure_windows.values_mut() {
            if self.height > window.expires_at_height && window.status.live() {
                window.status = PerformanceStatus::Expired;
            }
        }
        for throttle in self.safety_throttles.values_mut() {
            if self.height > throttle.expires_at_height && throttle.status.live() {
                throttle.status = PerformanceStatus::Expired;
            }
        }
        for attestation in self.pq_attestations.values_mut() {
            if self.height > attestation.expires_at_height && attestation.status.usable() {
                attestation.status = PqPerformanceAttestationStatus::Expired;
            }
        }
        Ok(self.state_root())
    }

    pub fn insert_lane(&mut self, lane: LowLatencyLane) -> SequencerPerformanceResult<String> {
        let lane_id = lane.lane_id.clone();
        lane.validate()?;
        if self.lanes.contains_key(&lane_id) {
            return Err("low latency lane already exists".to_string());
        }
        self.lanes.insert(lane_id.clone(), lane);
        Ok(lane_id)
    }

    pub fn insert_microbatch(
        &mut self,
        batch: MicroBatchPlan,
    ) -> SequencerPerformanceResult<String> {
        let batch_id = batch.batch_id.clone();
        batch.validate()?;
        if !self.lanes.contains_key(&batch.lane_id) {
            return Err("microbatch lane is unknown".to_string());
        }
        self.microbatches.insert(batch_id.clone(), batch);
        Ok(batch_id)
    }

    pub fn insert_route_admission(
        &mut self,
        admission: RouteAdmission,
    ) -> SequencerPerformanceResult<String> {
        let admission_id = admission.admission_id.clone();
        admission.validate()?;
        if !self.lanes.contains_key(&admission.lane_id) {
            return Err("route admission lane is unknown".to_string());
        }
        self.route_admissions
            .insert(admission_id.clone(), admission);
        Ok(admission_id)
    }

    pub fn insert_capacity_snapshot(
        &mut self,
        snapshot: CapacitySnapshot,
    ) -> SequencerPerformanceResult<String> {
        let snapshot_id = snapshot.snapshot_id.clone();
        snapshot.validate()?;
        self.capacity_snapshots
            .insert(snapshot_id.clone(), snapshot);
        Ok(snapshot_id)
    }

    pub fn insert_backpressure_window(
        &mut self,
        window: BackpressureWindow,
    ) -> SequencerPerformanceResult<String> {
        let window_id = window.window_id.clone();
        window.validate()?;
        for lane_id in &window.affected_lane_ids {
            if !self.lanes.contains_key(lane_id) {
                return Err(format!("backpressure lane {lane_id} is unknown"));
            }
        }
        self.backpressure_windows.insert(window_id.clone(), window);
        Ok(window_id)
    }

    pub fn insert_safety_throttle(
        &mut self,
        throttle: PerformanceSafetyThrottle,
    ) -> SequencerPerformanceResult<String> {
        let throttle_id = throttle.throttle_id.clone();
        throttle.validate()?;
        if !self.lanes.contains_key(&throttle.lane_id) {
            return Err("safety throttle lane is unknown".to_string());
        }
        self.safety_throttles.insert(throttle_id.clone(), throttle);
        Ok(throttle_id)
    }

    pub fn insert_pq_attestation(
        &mut self,
        attestation: PqPerformanceAttestation,
    ) -> SequencerPerformanceResult<String> {
        let attestation_id = attestation.attestation_id.clone();
        attestation.validate()?;
        self.pq_attestations
            .insert(attestation_id.clone(), attestation);
        Ok(attestation_id)
    }

    pub fn record_public_record(
        &mut self,
        label: &str,
        payload: &Value,
    ) -> SequencerPerformanceResult<String> {
        ensure_non_empty("performance public record label", label)?;
        let record_id = sequencer_performance_public_record_id(label, self.height, payload);
        self.public_records.insert(
            record_id.clone(),
            json!({
                "kind": "sequencer_performance_public_record",
                "chain_id": CHAIN_ID,
                "protocol_version": SEQUENCER_PERFORMANCE_PROTOCOL_VERSION,
                "record_id": record_id,
                "label": label,
                "height": self.height,
                "payload_root": sequencer_performance_payload_root("PERFORMANCE-PUBLIC-PAYLOAD", payload),
            }),
        );
        Ok(record_id)
    }

    pub fn active_lane_ids(&self) -> Vec<String> {
        self.lanes
            .values()
            .filter(|lane| lane.status.live())
            .map(|lane| lane.lane_id.clone())
            .collect()
    }

    pub fn throttled_lane_ids(&self) -> Vec<String> {
        let mut lanes = BTreeSet::new();
        for throttle in self
            .safety_throttles
            .values()
            .filter(|throttle| throttle.status.live())
        {
            lanes.insert(throttle.lane_id.clone());
        }
        lanes.into_iter().collect()
    }

    pub fn average_capacity_bps(&self) -> u64 {
        if self.capacity_snapshots.is_empty() {
            return 0;
        }
        self.capacity_snapshots
            .values()
            .map(|snapshot| snapshot.capacity_bps)
            .sum::<u64>()
            / self.capacity_snapshots.len() as u64
    }

    pub fn aggregate_pressure_bps(&self) -> u64 {
        self.backpressure_windows
            .values()
            .filter(|window| window.status.live())
            .map(|window| window.pressure_bps)
            .max()
            .unwrap_or(0)
    }

    pub fn lane_root(&self) -> String {
        sequencer_performance_collection_root(
            "SEQUENCER-PERFORMANCE-LANES",
            &self
                .lanes
                .values()
                .map(LowLatencyLane::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn microbatch_root(&self) -> String {
        sequencer_performance_collection_root(
            "SEQUENCER-PERFORMANCE-MICROBATCHES",
            &self
                .microbatches
                .values()
                .map(MicroBatchPlan::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn route_admission_root(&self) -> String {
        sequencer_performance_collection_root(
            "SEQUENCER-PERFORMANCE-ROUTE-ADMISSIONS",
            &self
                .route_admissions
                .values()
                .map(RouteAdmission::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn capacity_snapshot_root(&self) -> String {
        sequencer_performance_collection_root(
            "SEQUENCER-PERFORMANCE-CAPACITY-SNAPSHOTS",
            &self
                .capacity_snapshots
                .values()
                .map(CapacitySnapshot::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn backpressure_window_root(&self) -> String {
        sequencer_performance_collection_root(
            "SEQUENCER-PERFORMANCE-BACKPRESSURE-WINDOWS",
            &self
                .backpressure_windows
                .values()
                .map(BackpressureWindow::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn safety_throttle_root(&self) -> String {
        sequencer_performance_collection_root(
            "SEQUENCER-PERFORMANCE-SAFETY-THROTTLES",
            &self
                .safety_throttles
                .values()
                .map(PerformanceSafetyThrottle::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn pq_attestation_root(&self) -> String {
        sequencer_performance_collection_root(
            "SEQUENCER-PERFORMANCE-PQ-ATTESTATIONS",
            &self
                .pq_attestations
                .values()
                .map(PqPerformanceAttestation::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record_root(&self) -> String {
        sequencer_performance_collection_root(
            "SEQUENCER-PERFORMANCE-PUBLIC-RECORDS",
            &self.public_records.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn roots(&self) -> SequencerPerformanceRoots {
        SequencerPerformanceRoots {
            config_root: self.config.config_root(),
            lane_root: self.lane_root(),
            microbatch_root: self.microbatch_root(),
            route_admission_root: self.route_admission_root(),
            capacity_snapshot_root: self.capacity_snapshot_root(),
            backpressure_window_root: self.backpressure_window_root(),
            safety_throttle_root: self.safety_throttle_root(),
            pq_attestation_root: self.pq_attestation_root(),
            public_record_root: self.public_record_root(),
        }
    }

    pub fn counters(&self) -> SequencerPerformanceCounters {
        SequencerPerformanceCounters {
            height: self.height,
            lane_count: self.lanes.len() as u64,
            active_lane_count: self.active_lane_ids().len() as u64,
            open_microbatch_count: self
                .microbatches
                .values()
                .filter(|batch| batch.status.live())
                .count() as u64,
            live_route_count: self
                .route_admissions
                .values()
                .filter(|route| self.height <= route.expires_at_height)
                .count() as u64,
            capacity_snapshot_count: self.capacity_snapshots.len() as u64,
            guarded_window_count: self
                .backpressure_windows
                .values()
                .filter(|window| window.status.live())
                .count() as u64,
            active_throttle_count: self
                .safety_throttles
                .values()
                .filter(|throttle| throttle.status.live())
                .count() as u64,
            pq_attestation_count: self.pq_attestations.len() as u64,
            total_reserved_capacity_bps: self
                .lanes
                .values()
                .map(|lane| lane.reserved_capacity_bps)
                .sum::<u64>(),
            total_low_fee_share_bps: self
                .lanes
                .values()
                .map(|lane| lane.low_fee_share_bps)
                .sum::<u64>(),
            total_payload_bytes: self
                .microbatches
                .values()
                .map(|batch| batch.payload_bytes)
                .sum::<u64>(),
            average_capacity_bps: self.average_capacity_bps(),
            max_queue_depth: self
                .capacity_snapshots
                .values()
                .map(|snapshot| snapshot.queue_depth)
                .max()
                .unwrap_or(0),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "sequencer_performance_kernel_state",
            "chain_id": CHAIN_ID,
            "protocol_version": SEQUENCER_PERFORMANCE_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "active_lane_ids": self.active_lane_ids(),
            "throttled_lane_ids": self.throttled_lane_ids(),
            "average_capacity_bps": self.average_capacity_bps(),
            "aggregate_pressure_bps": self.aggregate_pressure_bps(),
        })
    }

    pub fn state_root(&self) -> String {
        sequencer_performance_state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> SequencerPerformanceResult<String> {
        self.config.validate()?;
        let reserved_capacity = self
            .lanes
            .values()
            .map(|lane| lane.reserved_capacity_bps)
            .sum::<u64>();
        if reserved_capacity > SEQUENCER_PERFORMANCE_MAX_BPS {
            return Err("reserved lane capacity exceeds max bps".to_string());
        }
        let low_fee_share = self
            .lanes
            .values()
            .map(|lane| lane.low_fee_share_bps)
            .sum::<u64>();
        if low_fee_share > SEQUENCER_PERFORMANCE_MAX_BPS {
            return Err("low fee lane share exceeds max bps".to_string());
        }
        for lane in self.lanes.values() {
            lane.validate()?;
        }
        for batch in self.microbatches.values() {
            batch.validate()?;
            if !self.lanes.contains_key(&batch.lane_id) {
                return Err("microbatch references unknown lane".to_string());
            }
        }
        for admission in self.route_admissions.values() {
            admission.validate()?;
            if !self.lanes.contains_key(&admission.lane_id) {
                return Err("route admission references unknown lane".to_string());
            }
        }
        for snapshot in self.capacity_snapshots.values() {
            snapshot.validate()?;
        }
        for window in self.backpressure_windows.values() {
            window.validate()?;
            for lane_id in &window.affected_lane_ids {
                if !self.lanes.contains_key(lane_id) {
                    return Err("backpressure window references unknown lane".to_string());
                }
            }
        }
        for throttle in self.safety_throttles.values() {
            throttle.validate()?;
            if !self.lanes.contains_key(&throttle.lane_id) {
                return Err("safety throttle references unknown lane".to_string());
            }
        }
        for attestation in self.pq_attestations.values() {
            attestation.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn sequencer_performance_state_root_from_record(record: &Value) -> String {
    sequencer_performance_payload_root("SEQUENCER-PERFORMANCE-STATE", record)
}

pub fn sequencer_performance_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(SEQUENCER_PERFORMANCE_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn sequencer_performance_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(SEQUENCER_PERFORMANCE_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn sequencer_performance_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| Value::String(sequencer_performance_string_root(domain, value)))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn sequencer_performance_collection_root(domain: &str, values: &[Value]) -> String {
    merkle_root(domain, values)
}

pub fn low_latency_lane_id(
    label: &str,
    lane_class: PerformanceLaneClass,
    privacy_class: RoutePrivacyClass,
    created_at_height: u64,
) -> String {
    domain_hash(
        "SEQUENCER-PERFORMANCE-LANE-ID",
        &[
            HashPart::Str(SEQUENCER_PERFORMANCE_PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(lane_class.as_str()),
            HashPart::Str(privacy_class.as_str()),
            HashPart::Int(created_at_height as i128),
        ],
        16,
    )
}

pub fn microbatch_plan_id(lane_id: &str, payload_root: &str, opened_at_height: u64) -> String {
    domain_hash(
        "SEQUENCER-PERFORMANCE-MICROBATCH-ID",
        &[
            HashPart::Str(SEQUENCER_PERFORMANCE_PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::Str(payload_root),
            HashPart::Int(opened_at_height as i128),
        ],
        16,
    )
}

pub fn route_admission_id(
    lane_id: &str,
    route_commitment: &str,
    admitted_at_height: u64,
    payload_bytes: u64,
) -> String {
    domain_hash(
        "SEQUENCER-PERFORMANCE-ROUTE-ADMISSION-ID",
        &[
            HashPart::Str(SEQUENCER_PERFORMANCE_PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::Str(route_commitment),
            HashPart::Int(admitted_at_height as i128),
            HashPart::Int(payload_bytes as i128),
        ],
        16,
    )
}

pub fn capacity_snapshot_id(
    signal_kind: CapacitySignalKind,
    capacity_bps: u64,
    observed_at_height: u64,
    signal_root: &str,
) -> String {
    domain_hash(
        "SEQUENCER-PERFORMANCE-CAPACITY-SNAPSHOT-ID",
        &[
            HashPart::Str(SEQUENCER_PERFORMANCE_PROTOCOL_VERSION),
            HashPart::Str(signal_kind.as_str()),
            HashPart::Int(capacity_bps as i128),
            HashPart::Int(observed_at_height as i128),
            HashPart::Str(signal_root),
        ],
        16,
    )
}

pub fn backpressure_window_id(
    reason: BackpressureReason,
    affected_lane_ids: &[String],
    opened_at_height: u64,
) -> String {
    domain_hash(
        "SEQUENCER-PERFORMANCE-BACKPRESSURE-WINDOW-ID",
        &[
            HashPart::Str(SEQUENCER_PERFORMANCE_PROTOCOL_VERSION),
            HashPart::Str(reason.as_str()),
            HashPart::Str(&sequencer_performance_string_set_root(
                "BACKPRESSURE-LANES",
                affected_lane_ids,
            )),
            HashPart::Int(opened_at_height as i128),
        ],
        16,
    )
}

pub fn performance_safety_throttle_id(
    lane_id: &str,
    reason: BackpressureReason,
    activated_at_height: u64,
) -> String {
    domain_hash(
        "SEQUENCER-PERFORMANCE-SAFETY-THROTTLE-ID",
        &[
            HashPart::Str(SEQUENCER_PERFORMANCE_PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::Str(reason.as_str()),
            HashPart::Int(activated_at_height as i128),
        ],
        16,
    )
}

pub fn pq_performance_attestation_id(
    subject: PqPerformanceAttestationSubject,
    subject_id: &str,
    subject_root: &str,
    signer_commitment: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "SEQUENCER-PERFORMANCE-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(SEQUENCER_PERFORMANCE_PROTOCOL_VERSION),
            HashPart::Str(subject.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(signer_commitment),
            HashPart::Int(signed_at_height as i128),
        ],
        16,
    )
}

pub fn sequencer_performance_public_record_id(label: &str, height: u64, payload: &Value) -> String {
    domain_hash(
        "SEQUENCER-PERFORMANCE-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(SEQUENCER_PERFORMANCE_PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Int(height as i128),
            HashPart::Json(payload),
        ],
        16,
    )
}

fn ensure_non_empty(label: &str, value: &str) -> SequencerPerformanceResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} is empty"));
    }
    Ok(())
}

fn ensure_positive(label: &str, value: u64) -> SequencerPerformanceResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(label: &str, value: u64) -> SequencerPerformanceResult<()> {
    if value > SEQUENCER_PERFORMANCE_MAX_BPS {
        return Err(format!("{label} exceeds max bps"));
    }
    Ok(())
}

fn ensure_height_window(start: u64, end: u64, label: &str) -> SequencerPerformanceResult<()> {
    if end < start {
        return Err(format!("{label} height window is inverted"));
    }
    Ok(())
}

fn ensure_unique_strings(values: &[String], label: &str) -> SequencerPerformanceResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value.clone()) {
            return Err(format!("{label} contains duplicate value"));
        }
    }
    Ok(())
}
