use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID, TARGET_BLOCK_MS,
};

pub type PipelineResult<T> = Result<T, String>;

pub const PIPELINE_PROTOCOL_VERSION: &str = "nebula-l2-pipeline-v1";
pub const PIPELINE_DEFAULT_MICROBATCH_SIZE: u64 = 32;
pub const PIPELINE_DEFAULT_MAX_SHARDS: u64 = 8;
pub const PIPELINE_DEFAULT_MAX_DEPENDENCIES: u64 = 16;
pub const PIPELINE_DEFAULT_MAX_RETRY_ATTEMPTS: u64 = 3;
pub const PIPELINE_DEFAULT_ADMISSION_TTL_BLOCKS: u64 = 8;
pub const PIPELINE_DEFAULT_MAX_PAYLOAD_BYTES: u64 = 64 * 1024;
pub const PIPELINE_DEFAULT_READY_QUEUE_DEPTH: u64 = 512;
pub const PIPELINE_DEFAULT_SHARD_TARGET_FUEL: u64 = 250_000;
pub const PIPELINE_BACKPRESSURE_RETRY_DEPTH_BPS: u64 = 7_500;
pub const PIPELINE_BACKPRESSURE_SHED_DEPTH_BPS: u64 = 9_000;
pub const PIPELINE_BUSY_SHARD_BPS: u64 = 8_500;
pub const PIPELINE_RECEIPT_TTL_BLOCKS: u64 = 16;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PipelineQosClass {
    Critical,
    Interactive,
    Standard,
    Bulk,
    Background,
}

impl PipelineQosClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Interactive => "interactive",
            Self::Standard => "standard",
            Self::Bulk => "bulk",
            Self::Background => "background",
        }
    }

    pub fn priority_score(&self) -> u64 {
        match self {
            Self::Critical => 100,
            Self::Interactive => 80,
            Self::Standard => 50,
            Self::Bulk => 25,
            Self::Background => 10,
        }
    }

    pub fn default_target_latency_ms(&self) -> u64 {
        match self {
            Self::Critical => TARGET_BLOCK_MS / 5,
            Self::Interactive => TARGET_BLOCK_MS / 2,
            Self::Standard => TARGET_BLOCK_MS,
            Self::Bulk => TARGET_BLOCK_MS * 2,
            Self::Background => TARGET_BLOCK_MS * 4,
        }
        .max(1)
    }

    pub fn default_deadline_delta_ms(&self) -> u64 {
        match self {
            Self::Critical => TARGET_BLOCK_MS,
            Self::Interactive => TARGET_BLOCK_MS * 2,
            Self::Standard => TARGET_BLOCK_MS * 4,
            Self::Bulk => TARGET_BLOCK_MS * 8,
            Self::Background => TARGET_BLOCK_MS * 16,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PipelineLaneMode {
    Preconfirm,
    FastPath,
    Standard,
    Bulk,
    Recovery,
}

impl PipelineLaneMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Preconfirm => "preconfirm",
            Self::FastPath => "fast_path",
            Self::Standard => "standard",
            Self::Bulk => "bulk",
            Self::Recovery => "recovery",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PipelineAccessMode {
    Read,
    Write,
    ReadWrite,
}

impl PipelineAccessMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::ReadWrite => "read_write",
        }
    }

    pub fn writes(&self) -> bool {
        matches!(self, Self::Write | Self::ReadWrite)
    }

    pub fn conflicts_with(&self, other: &Self) -> bool {
        self.writes() || other.writes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PipelineDependencyKind {
    Explicit,
    StateConflict,
    FeeOrdering,
    LaneOrdering,
    RetryAfter,
}

impl PipelineDependencyKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::StateConflict => "state_conflict",
            Self::FeeOrdering => "fee_ordering",
            Self::LaneOrdering => "lane_ordering",
            Self::RetryAfter => "retry_after",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PipelineReceiptStatus {
    Admitted,
    Preconfirmed,
    Executed,
    Failed,
    RetryScheduled,
    Rejected,
    Expired,
}

impl PipelineReceiptStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Preconfirmed => "preconfirmed",
            Self::Executed => "executed",
            Self::Failed => "failed",
            Self::RetryScheduled => "retry_scheduled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PipelineRetryAction {
    Admit,
    RetryNow,
    RetryAfter,
    Requeue,
    DropExpired,
    ShedLoad,
    Escalate,
}

impl PipelineRetryAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admit => "admit",
            Self::RetryNow => "retry_now",
            Self::RetryAfter => "retry_after",
            Self::Requeue => "requeue",
            Self::DropExpired => "drop_expired",
            Self::ShedLoad => "shed_load",
            Self::Escalate => "escalate",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineStateAccess {
    pub state_key_hash: String,
    pub state_domain: String,
    pub access_mode: PipelineAccessMode,
    pub version_hint: String,
}

impl PipelineStateAccess {
    pub fn new(
        state_domain: impl Into<String>,
        logical_key: impl AsRef<str>,
        access_mode: PipelineAccessMode,
        version_hint: impl Into<String>,
    ) -> Self {
        let state_domain = state_domain.into();
        let state_key_hash = pipeline_state_key_hash(&state_domain, logical_key.as_ref());
        Self {
            state_key_hash,
            state_domain,
            access_mode,
            version_hint: version_hint.into(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pipeline_state_access",
            "chain_id": CHAIN_ID,
            "pipeline_protocol_version": PIPELINE_PROTOCOL_VERSION,
            "state_key_hash": self.state_key_hash,
            "state_domain": self.state_domain,
            "access_mode": self.access_mode.as_str(),
            "version_hint": self.version_hint,
        })
    }

    pub fn validate(&self) -> PipelineResult<String> {
        if self.state_key_hash.is_empty() {
            return Err("pipeline state access key hash is required".to_string());
        }
        if self.state_domain.is_empty() {
            return Err("pipeline state access domain is required".to_string());
        }
        Ok(self.state_key_hash.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelinePreconfirmationLane {
    pub lane_id: String,
    pub label: String,
    pub lane_mode: PipelineLaneMode,
    pub qos_class: PipelineQosClass,
    pub reserved_microbatch_slots: u64,
    pub max_pending_admissions: u64,
    pub target_latency_ms: u64,
    pub admission_deadline_delta_ms: u64,
    pub inclusion_window_blocks: u64,
    pub accepts_private_payloads: bool,
}

impl PipelinePreconfirmationLane {
    pub fn new(
        label: impl Into<String>,
        lane_mode: PipelineLaneMode,
        qos_class: PipelineQosClass,
    ) -> Self {
        let label = label.into();
        let mut lane = Self {
            lane_id: String::new(),
            label,
            lane_mode,
            target_latency_ms: qos_class.default_target_latency_ms(),
            admission_deadline_delta_ms: qos_class.default_deadline_delta_ms(),
            inclusion_window_blocks: PIPELINE_DEFAULT_ADMISSION_TTL_BLOCKS,
            qos_class,
            reserved_microbatch_slots: PIPELINE_DEFAULT_MICROBATCH_SIZE,
            max_pending_admissions: PIPELINE_DEFAULT_READY_QUEUE_DEPTH,
            accepts_private_payloads: true,
        };
        lane.lane_id = pipeline_lane_id(&lane.identity_record());
        lane
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "pipeline_preconfirmation_lane",
            "chain_id": CHAIN_ID,
            "pipeline_protocol_version": PIPELINE_PROTOCOL_VERSION,
            "label": self.label,
            "lane_mode": self.lane_mode.as_str(),
            "qos_class": self.qos_class.as_str(),
            "reserved_microbatch_slots": self.reserved_microbatch_slots,
            "max_pending_admissions": self.max_pending_admissions,
            "target_latency_ms": self.target_latency_ms,
            "admission_deadline_delta_ms": self.admission_deadline_delta_ms,
            "inclusion_window_blocks": self.inclusion_window_blocks,
            "accepts_private_payloads": self.accepts_private_payloads,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record.as_object_mut().expect("pipeline lane record object");
        object.insert("lane_id".to_string(), Value::String(self.lane_id.clone()));
        object.insert("lane_root".to_string(), Value::String(self.lane_root()));
        record
    }

    pub fn lane_root(&self) -> String {
        domain_hash(
            "PIPELINE-PRECONFIRMATION-LANE",
            &[HashPart::Json(&self.identity_record())],
            32,
        )
    }

    pub fn validate(&self) -> PipelineResult<String> {
        if self.label.trim().is_empty() {
            return Err("pipeline lane label is required".to_string());
        }
        if self.reserved_microbatch_slots == 0 {
            return Err("pipeline lane must reserve at least one microbatch slot".to_string());
        }
        if self.max_pending_admissions == 0 {
            return Err("pipeline lane pending limit must be positive".to_string());
        }
        if self.target_latency_ms == 0 {
            return Err("pipeline lane target latency must be positive".to_string());
        }
        if self.admission_deadline_delta_ms < self.target_latency_ms {
            return Err("pipeline lane admission deadline is below target latency".to_string());
        }
        if self.inclusion_window_blocks == 0 {
            return Err("pipeline lane inclusion window must be positive".to_string());
        }
        let expected = pipeline_lane_id(&self.identity_record());
        if self.lane_id != expected {
            return Err("pipeline lane id mismatch".to_string());
        }
        Ok(self.lane_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineConfig {
    pub config_id: String,
    pub profile_label: String,
    pub max_microbatch_size: u64,
    pub max_shard_count: u64,
    pub max_dependencies_per_tx: u64,
    pub max_retry_attempts: u64,
    pub max_payload_bytes: u64,
    pub max_ready_queue_depth: u64,
    pub shard_target_fuel: u64,
    pub block_assembly_target_ms: u64,
    pub lanes: Vec<PipelinePreconfirmationLane>,
}

impl PipelineConfig {
    pub fn fast_default() -> Self {
        let mut critical = PipelinePreconfirmationLane::new(
            "critical-preconfirm",
            PipelineLaneMode::Preconfirm,
            PipelineQosClass::Critical,
        );
        critical.reserved_microbatch_slots = 8;
        critical.max_pending_admissions = 128;
        critical.target_latency_ms = (TARGET_BLOCK_MS / 5).max(1);
        critical.admission_deadline_delta_ms = TARGET_BLOCK_MS;
        critical.lane_id = pipeline_lane_id(&critical.identity_record());

        let mut interactive = PipelinePreconfirmationLane::new(
            "interactive-fast-path",
            PipelineLaneMode::FastPath,
            PipelineQosClass::Interactive,
        );
        interactive.reserved_microbatch_slots = 16;
        interactive.max_pending_admissions = 256;
        interactive.lane_id = pipeline_lane_id(&interactive.identity_record());

        let mut standard = PipelinePreconfirmationLane::new(
            "standard-microbatch",
            PipelineLaneMode::Standard,
            PipelineQosClass::Standard,
        );
        standard.reserved_microbatch_slots = 32;
        standard.lane_id = pipeline_lane_id(&standard.identity_record());

        let mut bulk = PipelinePreconfirmationLane::new(
            "bulk-backfill",
            PipelineLaneMode::Bulk,
            PipelineQosClass::Bulk,
        );
        bulk.reserved_microbatch_slots = 64;
        bulk.max_pending_admissions = 1024;
        bulk.target_latency_ms = TARGET_BLOCK_MS * 2;
        bulk.admission_deadline_delta_ms = TARGET_BLOCK_MS * 8;
        bulk.lane_id = pipeline_lane_id(&bulk.identity_record());

        let mut config = Self {
            config_id: String::new(),
            profile_label: "fast-execution-devnet".to_string(),
            max_microbatch_size: PIPELINE_DEFAULT_MICROBATCH_SIZE,
            max_shard_count: PIPELINE_DEFAULT_MAX_SHARDS,
            max_dependencies_per_tx: PIPELINE_DEFAULT_MAX_DEPENDENCIES,
            max_retry_attempts: PIPELINE_DEFAULT_MAX_RETRY_ATTEMPTS,
            max_payload_bytes: PIPELINE_DEFAULT_MAX_PAYLOAD_BYTES,
            max_ready_queue_depth: PIPELINE_DEFAULT_READY_QUEUE_DEPTH,
            shard_target_fuel: PIPELINE_DEFAULT_SHARD_TARGET_FUEL,
            block_assembly_target_ms: TARGET_BLOCK_MS,
            lanes: vec![critical, interactive, standard, bulk],
        };
        config.config_id = pipeline_config_id(&config.identity_record());
        config
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "pipeline_config",
            "chain_id": CHAIN_ID,
            "pipeline_protocol_version": PIPELINE_PROTOCOL_VERSION,
            "profile_label": self.profile_label,
            "max_microbatch_size": self.max_microbatch_size,
            "max_shard_count": self.max_shard_count,
            "max_dependencies_per_tx": self.max_dependencies_per_tx,
            "max_retry_attempts": self.max_retry_attempts,
            "max_payload_bytes": self.max_payload_bytes,
            "max_ready_queue_depth": self.max_ready_queue_depth,
            "shard_target_fuel": self.shard_target_fuel,
            "block_assembly_target_ms": self.block_assembly_target_ms,
            "lanes": self.lanes.iter().map(PipelinePreconfirmationLane::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("pipeline config record object");
        object.insert(
            "config_id".to_string(),
            Value::String(self.config_id.clone()),
        );
        object.insert("config_root".to_string(), Value::String(self.config_root()));
        record
    }

    pub fn config_root(&self) -> String {
        domain_hash(
            "PIPELINE-CONFIG",
            &[HashPart::Json(&self.identity_record())],
            32,
        )
    }

    pub fn validate(&self) -> PipelineResult<String> {
        if self.profile_label.trim().is_empty() {
            return Err("pipeline config profile label is required".to_string());
        }
        if self.max_microbatch_size == 0 {
            return Err("pipeline config max microbatch size must be positive".to_string());
        }
        if self.max_shard_count == 0 {
            return Err("pipeline config max shard count must be positive".to_string());
        }
        if self.max_payload_bytes == 0 {
            return Err("pipeline config max payload bytes must be positive".to_string());
        }
        if self.lanes.is_empty() {
            return Err("pipeline config requires at least one lane".to_string());
        }
        let mut seen = BTreeSet::new();
        for lane in &self.lanes {
            lane.validate()?;
            if !seen.insert(lane.lane_id.clone()) {
                return Err("duplicate pipeline lane id".to_string());
            }
        }
        let expected = pipeline_config_id(&self.identity_record());
        if self.config_id != expected {
            return Err("pipeline config id mismatch".to_string());
        }
        Ok(self.config_id.clone())
    }
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self::fast_default()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineAdmissionRequest {
    pub tx_public_record: Value,
    pub payload_record: Value,
    pub state_accesses: Vec<PipelineStateAccess>,
    pub dependency_ids: Vec<String>,
    pub qos_class: PipelineQosClass,
    pub requested_lane_id: Option<String>,
    pub fee_density_microunits: u64,
    pub received_from: String,
    pub private_payload: bool,
    pub max_latency_ms: u64,
}

impl PipelineAdmissionRequest {
    pub fn new(
        tx_public_record: Value,
        payload_record: Value,
        qos_class: PipelineQosClass,
    ) -> Self {
        Self {
            tx_public_record,
            payload_record,
            state_accesses: Vec::new(),
            dependency_ids: Vec::new(),
            qos_class,
            requested_lane_id: None,
            fee_density_microunits: 0,
            received_from: "local".to_string(),
            private_payload: false,
            max_latency_ms: 0,
        }
    }

    pub fn with_state_access(mut self, access: PipelineStateAccess) -> Self {
        self.state_accesses.push(access);
        self
    }

    pub fn with_dependency(mut self, admission_id: impl Into<String>) -> Self {
        self.dependency_ids.push(admission_id.into());
        self
    }

    pub fn requested_lane(mut self, lane_id: impl Into<String>) -> Self {
        self.requested_lane_id = Some(lane_id.into());
        self
    }

    pub fn fee_density(mut self, fee_density_microunits: u64) -> Self {
        self.fee_density_microunits = fee_density_microunits;
        self
    }

    pub fn private_payload(mut self, private_payload: bool) -> Self {
        self.private_payload = private_payload;
        self
    }

    pub fn max_latency_ms(mut self, max_latency_ms: u64) -> Self {
        self.max_latency_ms = max_latency_ms;
        self
    }

    pub fn tx_public_hash(&self) -> String {
        pipeline_tx_public_hash(&self.tx_public_record)
    }

    pub fn payload_root(&self) -> String {
        pipeline_payload_root("PIPELINE-ADMISSION-PAYLOAD", &self.payload_record)
    }

    pub fn payload_bytes(&self) -> u64 {
        serde_json::to_vec(&self.payload_record)
            .map(|bytes| bytes.len() as u64)
            .unwrap_or_default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pipeline_admission_request",
            "chain_id": CHAIN_ID,
            "pipeline_protocol_version": PIPELINE_PROTOCOL_VERSION,
            "tx_public_hash": self.tx_public_hash(),
            "payload_root": self.payload_root(),
            "payload_bytes": self.payload_bytes(),
            "state_access_root": pipeline_state_access_root(&self.state_accesses),
            "dependency_root": pipeline_string_root("PIPELINE-ADMISSION-DEPENDENCY", &self.dependency_ids),
            "dependency_count": self.dependency_ids.len() as u64,
            "qos_class": self.qos_class.as_str(),
            "requested_lane_id": self.requested_lane_id.clone(),
            "fee_density_microunits": self.fee_density_microunits,
            "received_from": self.received_from,
            "private_payload": self.private_payload,
            "max_latency_ms": self.max_latency_ms,
        })
    }

    pub fn validate(&self, config: &PipelineConfig) -> PipelineResult<String> {
        if self.payload_bytes() > config.max_payload_bytes {
            return Err("pipeline admission payload exceeds config limit".to_string());
        }
        if self.dependency_ids.len() as u64 > config.max_dependencies_per_tx {
            return Err("pipeline admission has too many dependencies".to_string());
        }
        let mut seen_dependencies = BTreeSet::new();
        for dependency_id in &self.dependency_ids {
            if dependency_id.is_empty() {
                return Err("pipeline admission dependency id is required".to_string());
            }
            if !seen_dependencies.insert(dependency_id.clone()) {
                return Err("pipeline admission has duplicate dependency id".to_string());
            }
        }
        for access in &self.state_accesses {
            access.validate()?;
        }
        Ok(self.tx_public_hash())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineAdmission {
    pub admission_id: String,
    pub lane_id: String,
    pub lane_sequence: u64,
    pub qos_class: PipelineQosClass,
    pub tx_public_hash: String,
    pub payload_root: String,
    pub payload_bytes: u64,
    pub state_access_root: String,
    pub dependency_root: String,
    pub dependency_ids: Vec<String>,
    pub state_accesses: Vec<PipelineStateAccess>,
    pub fee_density_microunits: u64,
    pub received_from: String,
    pub private_payload: bool,
    pub received_at_height: u64,
    pub received_at_ms: u64,
    pub deadline_height: u64,
    pub deadline_ms: u64,
    pub preconfirmation_deadline_ms: u64,
}

impl PipelineAdmission {
    pub fn build(
        request: PipelineAdmissionRequest,
        lane: &PipelinePreconfirmationLane,
        config: &PipelineConfig,
        received_at_height: u64,
        received_at_ms: u64,
        lane_sequence: u64,
    ) -> PipelineResult<Self> {
        request.validate(config)?;
        if request.private_payload && !lane.accepts_private_payloads {
            return Err("pipeline lane does not accept private payloads".to_string());
        }
        let tx_public_hash = request.tx_public_hash();
        let payload_root = request.payload_root();
        let payload_bytes = request.payload_bytes();
        let state_access_root = pipeline_state_access_root(&request.state_accesses);
        let dependency_root =
            pipeline_string_root("PIPELINE-ADMISSION-DEPENDENCY", &request.dependency_ids);
        let deadline_delta_ms = if request.max_latency_ms == 0 {
            lane.admission_deadline_delta_ms
        } else {
            request.max_latency_ms.min(lane.admission_deadline_delta_ms)
        };
        let deadline_height = received_at_height.saturating_add(lane.inclusion_window_blocks);
        let deadline_ms = received_at_ms.saturating_add(deadline_delta_ms);
        let preconfirmation_deadline_ms = received_at_ms.saturating_add(lane.target_latency_ms);
        let admission_id = pipeline_admission_id(
            &lane.lane_id,
            lane_sequence,
            request.qos_class.as_str(),
            &tx_public_hash,
            &payload_root,
            deadline_height,
            deadline_ms,
        );
        Ok(Self {
            admission_id,
            lane_id: lane.lane_id.clone(),
            lane_sequence,
            qos_class: request.qos_class,
            tx_public_hash,
            payload_root,
            payload_bytes,
            state_access_root,
            dependency_root,
            dependency_ids: request.dependency_ids,
            state_accesses: request.state_accesses,
            fee_density_microunits: request.fee_density_microunits,
            received_from: request.received_from,
            private_payload: request.private_payload,
            received_at_height,
            received_at_ms,
            deadline_height,
            deadline_ms,
            preconfirmation_deadline_ms,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pipeline_admission",
            "chain_id": CHAIN_ID,
            "pipeline_protocol_version": PIPELINE_PROTOCOL_VERSION,
            "admission_id": self.admission_id,
            "lane_id": self.lane_id,
            "lane_sequence": self.lane_sequence,
            "qos_class": self.qos_class.as_str(),
            "tx_public_hash": self.tx_public_hash,
            "payload_root": self.payload_root,
            "payload_bytes": self.payload_bytes,
            "state_access_root": self.state_access_root,
            "dependency_root": self.dependency_root,
            "dependency_count": self.dependency_ids.len() as u64,
            "dependency_ids": self.dependency_ids,
            "state_accesses": self.state_accesses.iter().map(PipelineStateAccess::public_record).collect::<Vec<_>>(),
            "fee_density_microunits": self.fee_density_microunits,
            "received_from": self.received_from,
            "private_payload": self.private_payload,
            "received_at_height": self.received_at_height,
            "received_at_ms": self.received_at_ms,
            "deadline_height": self.deadline_height,
            "deadline_ms": self.deadline_ms,
            "preconfirmation_deadline_ms": self.preconfirmation_deadline_ms,
        })
    }

    pub fn validate(&self) -> PipelineResult<String> {
        if self.lane_id.is_empty() {
            return Err("pipeline admission lane id is required".to_string());
        }
        if self.tx_public_hash.is_empty() {
            return Err("pipeline admission tx public hash is required".to_string());
        }
        if self.payload_root.is_empty() {
            return Err("pipeline admission payload root is required".to_string());
        }
        if self.deadline_height < self.received_at_height {
            return Err("pipeline admission deadline height precedes receipt height".to_string());
        }
        if self.deadline_ms < self.received_at_ms {
            return Err("pipeline admission deadline ms precedes receipt ms".to_string());
        }
        if self.preconfirmation_deadline_ms > self.deadline_ms {
            return Err(
                "pipeline admission preconfirmation deadline exceeds admission deadline"
                    .to_string(),
            );
        }
        for access in &self.state_accesses {
            access.validate()?;
        }
        if self.state_access_root != pipeline_state_access_root(&self.state_accesses) {
            return Err("pipeline admission state access root mismatch".to_string());
        }
        if self.dependency_root
            != pipeline_string_root("PIPELINE-ADMISSION-DEPENDENCY", &self.dependency_ids)
        {
            return Err("pipeline admission dependency root mismatch".to_string());
        }
        let expected = pipeline_admission_id(
            &self.lane_id,
            self.lane_sequence,
            self.qos_class.as_str(),
            &self.tx_public_hash,
            &self.payload_root,
            self.deadline_height,
            self.deadline_ms,
        );
        if self.admission_id != expected {
            return Err("pipeline admission id mismatch".to_string());
        }
        Ok(self.admission_id.clone())
    }

    pub fn expired_at(&self, height: u64, timestamp_ms: u64) -> bool {
        height > self.deadline_height || timestamp_ms > self.deadline_ms
    }

    pub fn missed_preconfirmation_at(&self, timestamp_ms: u64) -> bool {
        timestamp_ms > self.preconfirmation_deadline_ms
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineDependencyEdge {
    pub edge_id: String,
    pub parent_admission_id: String,
    pub child_admission_id: String,
    pub edge_kind: PipelineDependencyKind,
    pub state_key_hash: String,
    pub reason: String,
}

impl PipelineDependencyEdge {
    pub fn new(
        parent_admission_id: impl Into<String>,
        child_admission_id: impl Into<String>,
        edge_kind: PipelineDependencyKind,
        state_key_hash: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        let parent_admission_id = parent_admission_id.into();
        let child_admission_id = child_admission_id.into();
        let state_key_hash = state_key_hash.into();
        let reason = reason.into();
        let edge_id = pipeline_dependency_edge_id(
            &parent_admission_id,
            &child_admission_id,
            edge_kind.as_str(),
            &state_key_hash,
            &reason,
        );
        Self {
            edge_id,
            parent_admission_id,
            child_admission_id,
            edge_kind,
            state_key_hash,
            reason,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pipeline_dependency_edge",
            "chain_id": CHAIN_ID,
            "pipeline_protocol_version": PIPELINE_PROTOCOL_VERSION,
            "edge_id": self.edge_id,
            "parent_admission_id": self.parent_admission_id,
            "child_admission_id": self.child_admission_id,
            "edge_kind": self.edge_kind.as_str(),
            "state_key_hash": self.state_key_hash,
            "reason": self.reason,
        })
    }

    pub fn validate(&self) -> PipelineResult<String> {
        if self.parent_admission_id.is_empty() || self.child_admission_id.is_empty() {
            return Err("pipeline dependency edge endpoints are required".to_string());
        }
        if self.parent_admission_id == self.child_admission_id {
            return Err("pipeline dependency edge cannot self-reference".to_string());
        }
        let expected = pipeline_dependency_edge_id(
            &self.parent_admission_id,
            &self.child_admission_id,
            self.edge_kind.as_str(),
            &self.state_key_hash,
            &self.reason,
        );
        if self.edge_id != expected {
            return Err("pipeline dependency edge id mismatch".to_string());
        }
        Ok(self.edge_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineDependencyGraph {
    pub graph_id: String,
    pub height: u64,
    pub admission_root: String,
    pub edge_root: String,
    pub ready_root: String,
    pub blocked_root: String,
    pub ready_admission_ids: Vec<String>,
    pub blocked_admission_ids: Vec<String>,
    pub edges: Vec<PipelineDependencyEdge>,
}

impl PipelineDependencyGraph {
    pub fn build(height: u64, admissions: &[PipelineAdmission]) -> PipelineResult<Self> {
        let mut ordered = admissions.to_vec();
        ordered.sort_by(compare_admissions);
        let known = ordered
            .iter()
            .map(|admission| admission.admission_id.clone())
            .collect::<BTreeSet<_>>();
        let mut edges = BTreeMap::new();
        for admission in &ordered {
            admission.validate()?;
            for dependency_id in &admission.dependency_ids {
                if !known.contains(dependency_id) {
                    return Err(
                        "pipeline dependency graph references unknown admission".to_string()
                    );
                }
                let edge = PipelineDependencyEdge::new(
                    dependency_id,
                    &admission.admission_id,
                    PipelineDependencyKind::Explicit,
                    "",
                    "explicit_dependency",
                );
                edges.insert(edge.edge_id.clone(), edge);
            }
        }
        for left_index in 0..ordered.len() {
            for right_index in (left_index + 1)..ordered.len() {
                if let Some(state_key_hash) =
                    conflicting_state_key(&ordered[left_index], &ordered[right_index])
                {
                    let edge = PipelineDependencyEdge::new(
                        &ordered[left_index].admission_id,
                        &ordered[right_index].admission_id,
                        PipelineDependencyKind::StateConflict,
                        state_key_hash,
                        "write_conflict",
                    );
                    edges.insert(edge.edge_id.clone(), edge);
                }
            }
        }
        let mut incoming = BTreeSet::new();
        for edge in edges.values() {
            incoming.insert(edge.child_admission_id.clone());
        }
        let mut ready_admission_ids = Vec::new();
        let mut blocked_admission_ids = Vec::new();
        for admission in &ordered {
            if incoming.contains(&admission.admission_id) {
                blocked_admission_ids.push(admission.admission_id.clone());
            } else {
                ready_admission_ids.push(admission.admission_id.clone());
            }
        }
        let edge_values = edges.values().cloned().collect::<Vec<_>>();
        let admission_root = pipeline_admission_root(&ordered);
        let edge_root = pipeline_dependency_edge_root(&edge_values);
        let ready_root = pipeline_string_root("PIPELINE-READY-ADMISSION", &ready_admission_ids);
        let blocked_root =
            pipeline_string_root("PIPELINE-BLOCKED-ADMISSION", &blocked_admission_ids);
        let graph_id = pipeline_dependency_graph_id(
            height,
            &admission_root,
            &edge_root,
            &ready_root,
            &blocked_root,
        );
        Ok(Self {
            graph_id,
            height,
            admission_root,
            edge_root,
            ready_root,
            blocked_root,
            ready_admission_ids,
            blocked_admission_ids,
            edges: edge_values,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pipeline_dependency_graph",
            "chain_id": CHAIN_ID,
            "pipeline_protocol_version": PIPELINE_PROTOCOL_VERSION,
            "graph_id": self.graph_id,
            "height": self.height,
            "admission_root": self.admission_root,
            "edge_root": self.edge_root,
            "ready_root": self.ready_root,
            "blocked_root": self.blocked_root,
            "ready_count": self.ready_admission_ids.len() as u64,
            "blocked_count": self.blocked_admission_ids.len() as u64,
            "edge_count": self.edges.len() as u64,
            "ready_admission_ids": self.ready_admission_ids,
            "blocked_admission_ids": self.blocked_admission_ids,
            "edges": self.edges.iter().map(PipelineDependencyEdge::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn validate(&self) -> PipelineResult<String> {
        for edge in &self.edges {
            edge.validate()?;
        }
        if self.edge_root != pipeline_dependency_edge_root(&self.edges) {
            return Err("pipeline dependency graph edge root mismatch".to_string());
        }
        if self.ready_root
            != pipeline_string_root("PIPELINE-READY-ADMISSION", &self.ready_admission_ids)
        {
            return Err("pipeline dependency graph ready root mismatch".to_string());
        }
        if self.blocked_root
            != pipeline_string_root("PIPELINE-BLOCKED-ADMISSION", &self.blocked_admission_ids)
        {
            return Err("pipeline dependency graph blocked root mismatch".to_string());
        }
        let expected = pipeline_dependency_graph_id(
            self.height,
            &self.admission_root,
            &self.edge_root,
            &self.ready_root,
            &self.blocked_root,
        );
        if self.graph_id != expected {
            return Err("pipeline dependency graph id mismatch".to_string());
        }
        Ok(self.graph_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineMicrobatch {
    pub microbatch_id: String,
    pub height: u64,
    pub batch_sequence: u64,
    pub lane_id: String,
    pub qos_class: PipelineQosClass,
    pub planned_at_ms: u64,
    pub admission_ids: Vec<String>,
    pub admission_root: String,
    pub tx_root: String,
    pub dependency_graph_id: String,
    pub dependency_edge_root: String,
    pub total_payload_bytes: u64,
    pub max_deadline_height: u64,
    pub target_execute_ms: u64,
}

impl PipelineMicrobatch {
    pub fn build(
        lane: &PipelinePreconfirmationLane,
        height: u64,
        batch_sequence: u64,
        planned_at_ms: u64,
        admissions: &[PipelineAdmission],
        graph: &PipelineDependencyGraph,
    ) -> PipelineResult<Self> {
        if admissions.is_empty() {
            return Err("pipeline microbatch requires at least one admission".to_string());
        }
        if admissions
            .iter()
            .any(|admission| admission.lane_id != lane.lane_id)
        {
            return Err("pipeline microbatch admissions must share lane".to_string());
        }
        let admission_ids = admissions
            .iter()
            .map(|admission| admission.admission_id.clone())
            .collect::<Vec<_>>();
        let admission_root = pipeline_admission_root(admissions);
        let tx_root = pipeline_tx_hash_root(admissions);
        let total_payload_bytes = admissions
            .iter()
            .map(|admission| admission.payload_bytes)
            .fold(0_u64, u64::saturating_add);
        let max_deadline_height = admissions
            .iter()
            .map(|admission| admission.deadline_height)
            .max()
            .unwrap_or(height);
        let target_execute_ms = lane.target_latency_ms.min(TARGET_BLOCK_MS).max(1);
        let microbatch_id = pipeline_microbatch_id(
            &lane.lane_id,
            height,
            batch_sequence,
            &admission_root,
            &graph.graph_id,
        );
        Ok(Self {
            microbatch_id,
            height,
            batch_sequence,
            lane_id: lane.lane_id.clone(),
            qos_class: lane.qos_class.clone(),
            planned_at_ms,
            admission_ids,
            admission_root,
            tx_root,
            dependency_graph_id: graph.graph_id.clone(),
            dependency_edge_root: graph.edge_root.clone(),
            total_payload_bytes,
            max_deadline_height,
            target_execute_ms,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pipeline_microbatch",
            "chain_id": CHAIN_ID,
            "pipeline_protocol_version": PIPELINE_PROTOCOL_VERSION,
            "microbatch_id": self.microbatch_id,
            "height": self.height,
            "batch_sequence": self.batch_sequence,
            "lane_id": self.lane_id,
            "qos_class": self.qos_class.as_str(),
            "planned_at_ms": self.planned_at_ms,
            "admission_ids": self.admission_ids,
            "admission_count": self.admission_ids.len() as u64,
            "admission_root": self.admission_root,
            "tx_root": self.tx_root,
            "dependency_graph_id": self.dependency_graph_id,
            "dependency_edge_root": self.dependency_edge_root,
            "total_payload_bytes": self.total_payload_bytes,
            "max_deadline_height": self.max_deadline_height,
            "target_execute_ms": self.target_execute_ms,
        })
    }

    pub fn validate(&self) -> PipelineResult<String> {
        if self.admission_ids.is_empty() {
            return Err("pipeline microbatch has no admissions".to_string());
        }
        if self.lane_id.is_empty() || self.dependency_graph_id.is_empty() {
            return Err("pipeline microbatch lane and dependency graph are required".to_string());
        }
        let expected = pipeline_microbatch_id(
            &self.lane_id,
            self.height,
            self.batch_sequence,
            &self.admission_root,
            &self.dependency_graph_id,
        );
        if self.microbatch_id != expected {
            return Err("pipeline microbatch id mismatch".to_string());
        }
        Ok(self.microbatch_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineExecutionShard {
    pub shard_id: String,
    pub microbatch_id: String,
    pub height: u64,
    pub shard_index: u64,
    pub worker_label: String,
    pub admission_ids: Vec<String>,
    pub admission_root: String,
    pub state_access_root: String,
    pub read_set_root: String,
    pub write_set_root: String,
    pub dependency_edge_root: String,
    pub estimated_fuel: u64,
    pub status: String,
}

impl PipelineExecutionShard {
    pub fn build(
        microbatch: &PipelineMicrobatch,
        shard_index: u64,
        worker_label: impl Into<String>,
        admissions: &[PipelineAdmission],
        graph: &PipelineDependencyGraph,
        shard_target_fuel: u64,
    ) -> PipelineResult<Self> {
        if admissions.is_empty() {
            return Err("pipeline execution shard requires at least one admission".to_string());
        }
        let worker_label = worker_label.into();
        if worker_label.trim().is_empty() {
            return Err("pipeline execution shard worker label is required".to_string());
        }
        let admission_ids = admissions
            .iter()
            .map(|admission| admission.admission_id.clone())
            .collect::<Vec<_>>();
        let admission_root = pipeline_admission_root(admissions);
        let state_accesses = admissions
            .iter()
            .flat_map(|admission| admission.state_accesses.clone())
            .collect::<Vec<_>>();
        let dependency_edges = graph
            .edges
            .iter()
            .filter(|edge| {
                admission_ids.contains(&edge.parent_admission_id)
                    || admission_ids.contains(&edge.child_admission_id)
            })
            .cloned()
            .collect::<Vec<_>>();
        let estimated_fuel = estimate_shard_fuel(admissions).min(shard_target_fuel.max(1));
        let state_access_root = pipeline_state_access_root(&state_accesses);
        let read_set_root =
            pipeline_access_set_root("PIPELINE-SHARD-READ-SET", &state_accesses, false);
        let write_set_root =
            pipeline_access_set_root("PIPELINE-SHARD-WRITE-SET", &state_accesses, true);
        let dependency_edge_root = pipeline_dependency_edge_root(&dependency_edges);
        let shard_id = pipeline_shard_id(
            &microbatch.microbatch_id,
            shard_index,
            &worker_label,
            &admission_root,
            &state_access_root,
        );
        Ok(Self {
            shard_id,
            microbatch_id: microbatch.microbatch_id.clone(),
            height: microbatch.height,
            shard_index,
            worker_label,
            admission_ids,
            admission_root,
            state_access_root,
            read_set_root,
            write_set_root,
            dependency_edge_root,
            estimated_fuel,
            status: "planned".to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pipeline_execution_shard",
            "chain_id": CHAIN_ID,
            "pipeline_protocol_version": PIPELINE_PROTOCOL_VERSION,
            "shard_id": self.shard_id,
            "microbatch_id": self.microbatch_id,
            "height": self.height,
            "shard_index": self.shard_index,
            "worker_label": self.worker_label,
            "admission_ids": self.admission_ids,
            "admission_count": self.admission_ids.len() as u64,
            "admission_root": self.admission_root,
            "state_access_root": self.state_access_root,
            "read_set_root": self.read_set_root,
            "write_set_root": self.write_set_root,
            "dependency_edge_root": self.dependency_edge_root,
            "estimated_fuel": self.estimated_fuel,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> PipelineResult<String> {
        if self.microbatch_id.is_empty() || self.worker_label.trim().is_empty() {
            return Err("pipeline execution shard microbatch and worker are required".to_string());
        }
        if self.admission_ids.is_empty() {
            return Err("pipeline execution shard has no admissions".to_string());
        }
        let expected = pipeline_shard_id(
            &self.microbatch_id,
            self.shard_index,
            &self.worker_label,
            &self.admission_root,
            &self.state_access_root,
        );
        if self.shard_id != expected {
            return Err("pipeline execution shard id mismatch".to_string());
        }
        Ok(self.shard_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineExecutionResult {
    pub admission_id: String,
    pub status: PipelineReceiptStatus,
    pub result_root: String,
    pub error_code_hash: String,
    pub retryable: bool,
    pub attempt: u64,
    pub execution_units: u64,
}

impl PipelineExecutionResult {
    pub fn success(
        admission_id: impl Into<String>,
        result_payload: &Value,
        execution_units: u64,
    ) -> Self {
        Self {
            admission_id: admission_id.into(),
            status: PipelineReceiptStatus::Executed,
            result_root: pipeline_payload_root("PIPELINE-EXECUTION-RESULT", result_payload),
            error_code_hash: pipeline_string_hash("PIPELINE-ERROR-CODE", ""),
            retryable: false,
            attempt: 0,
            execution_units,
        }
    }

    pub fn failure(
        admission_id: impl Into<String>,
        error_code: impl AsRef<str>,
        retryable: bool,
        attempt: u64,
    ) -> Self {
        Self {
            admission_id: admission_id.into(),
            status: PipelineReceiptStatus::Failed,
            result_root: pipeline_payload_root("PIPELINE-EXECUTION-RESULT", &json!({})),
            error_code_hash: pipeline_string_hash("PIPELINE-ERROR-CODE", error_code.as_ref()),
            retryable,
            attempt,
            execution_units: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pipeline_execution_result",
            "chain_id": CHAIN_ID,
            "pipeline_protocol_version": PIPELINE_PROTOCOL_VERSION,
            "admission_id": self.admission_id,
            "status": self.status.as_str(),
            "result_root": self.result_root,
            "error_code_hash": self.error_code_hash,
            "retryable": self.retryable,
            "attempt": self.attempt,
            "execution_units": self.execution_units,
        })
    }

    pub fn validate(&self) -> PipelineResult<String> {
        if self.admission_id.is_empty() {
            return Err("pipeline execution result admission id is required".to_string());
        }
        if self.result_root.is_empty() || self.error_code_hash.is_empty() {
            return Err("pipeline execution result roots are required".to_string());
        }
        Ok(self.admission_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineShardReceipt {
    pub receipt_id: String,
    pub shard_id: String,
    pub microbatch_id: String,
    pub executed_at_height: u64,
    pub executed_at_ms: u64,
    pub admission_root: String,
    pub result_root: String,
    pub success_count: u64,
    pub failure_count: u64,
    pub retry_count: u64,
    pub execution_ms: u64,
    pub state_delta_root: String,
    pub low_latency_receipt_root: String,
    pub results: Vec<PipelineExecutionResult>,
}

impl PipelineShardReceipt {
    pub fn build(
        shard: &PipelineExecutionShard,
        executed_at_height: u64,
        executed_at_ms: u64,
        execution_ms: u64,
        state_delta_root: impl Into<String>,
        results: Vec<PipelineExecutionResult>,
    ) -> PipelineResult<Self> {
        if results.is_empty() {
            return Err("pipeline shard receipt requires execution results".to_string());
        }
        let result_admissions = results
            .iter()
            .map(|result| result.admission_id.clone())
            .collect::<BTreeSet<_>>();
        for admission_id in &shard.admission_ids {
            if !result_admissions.contains(admission_id) {
                return Err("pipeline shard receipt missing admission result".to_string());
            }
        }
        let result_root = pipeline_execution_result_root(&results);
        let success_count = results
            .iter()
            .filter(|result| result.status == PipelineReceiptStatus::Executed)
            .count() as u64;
        let failure_count = results
            .iter()
            .filter(|result| result.status == PipelineReceiptStatus::Failed)
            .count() as u64;
        let retry_count = results.iter().filter(|result| result.retryable).count() as u64;
        let state_delta_root = state_delta_root.into();
        let low_latency_receipt_root = merkle_root("PIPELINE-LOW-LATENCY-RECEIPT", &[]);
        let receipt_id = pipeline_shard_receipt_id(
            &shard.shard_id,
            &shard.microbatch_id,
            executed_at_height,
            &result_root,
            &state_delta_root,
        );
        Ok(Self {
            receipt_id,
            shard_id: shard.shard_id.clone(),
            microbatch_id: shard.microbatch_id.clone(),
            executed_at_height,
            executed_at_ms,
            admission_root: shard.admission_root.clone(),
            result_root,
            success_count,
            failure_count,
            retry_count,
            execution_ms,
            state_delta_root,
            low_latency_receipt_root,
            results,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pipeline_shard_receipt",
            "chain_id": CHAIN_ID,
            "pipeline_protocol_version": PIPELINE_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "shard_id": self.shard_id,
            "microbatch_id": self.microbatch_id,
            "executed_at_height": self.executed_at_height,
            "executed_at_ms": self.executed_at_ms,
            "admission_root": self.admission_root,
            "result_root": self.result_root,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "retry_count": self.retry_count,
            "execution_ms": self.execution_ms,
            "state_delta_root": self.state_delta_root,
            "low_latency_receipt_root": self.low_latency_receipt_root,
            "results": self.results.iter().map(PipelineExecutionResult::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn validate(&self) -> PipelineResult<String> {
        if self.shard_id.is_empty() || self.microbatch_id.is_empty() {
            return Err("pipeline shard receipt shard and microbatch are required".to_string());
        }
        for result in &self.results {
            result.validate()?;
        }
        if self.result_root != pipeline_execution_result_root(&self.results) {
            return Err("pipeline shard receipt result root mismatch".to_string());
        }
        let expected = pipeline_shard_receipt_id(
            &self.shard_id,
            &self.microbatch_id,
            self.executed_at_height,
            &self.result_root,
            &self.state_delta_root,
        );
        if self.receipt_id != expected {
            return Err("pipeline shard receipt id mismatch".to_string());
        }
        Ok(self.receipt_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineLowLatencyReceipt {
    pub receipt_id: String,
    pub admission_id: String,
    pub lane_id: String,
    pub microbatch_id: String,
    pub shard_id: String,
    pub qos_class: PipelineQosClass,
    pub tx_public_hash: String,
    pub status: PipelineReceiptStatus,
    pub received_at_height: u64,
    pub received_at_ms: u64,
    pub preconfirmed_at_ms: u64,
    pub executed_at_ms: u64,
    pub deadline_ms: u64,
    pub retry_after_ms: u64,
    pub result_root: String,
}

impl PipelineLowLatencyReceipt {
    pub fn admitted(admission: &PipelineAdmission) -> Self {
        Self::new(
            admission,
            "",
            "",
            PipelineReceiptStatus::Admitted,
            0,
            0,
            0,
            &pipeline_payload_root("PIPELINE-LOW-LATENCY-EMPTY-RESULT", &json!({})),
        )
    }

    pub fn preconfirmed(admission: &PipelineAdmission, microbatch: &PipelineMicrobatch) -> Self {
        Self::new(
            admission,
            &microbatch.microbatch_id,
            "",
            PipelineReceiptStatus::Preconfirmed,
            microbatch.planned_at_ms,
            0,
            0,
            &pipeline_payload_root(
                "PIPELINE-LOW-LATENCY-PRECONFIRMED",
                &microbatch.public_record(),
            ),
        )
    }

    pub fn executed(
        admission: &PipelineAdmission,
        shard: &PipelineExecutionShard,
        shard_receipt: &PipelineShardReceipt,
        result: &PipelineExecutionResult,
        retry_after_ms: u64,
    ) -> Self {
        let status = if result.retryable {
            PipelineReceiptStatus::RetryScheduled
        } else {
            result.status.clone()
        };
        Self::new(
            admission,
            &shard.microbatch_id,
            &shard.shard_id,
            status,
            0,
            shard_receipt.executed_at_ms,
            retry_after_ms,
            &result.result_root,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        admission: &PipelineAdmission,
        microbatch_id: &str,
        shard_id: &str,
        status: PipelineReceiptStatus,
        preconfirmed_at_ms: u64,
        executed_at_ms: u64,
        retry_after_ms: u64,
        result_root: &str,
    ) -> Self {
        let receipt_id = pipeline_low_latency_receipt_id(
            &admission.admission_id,
            microbatch_id,
            shard_id,
            status.as_str(),
            result_root,
        );
        Self {
            receipt_id,
            admission_id: admission.admission_id.clone(),
            lane_id: admission.lane_id.clone(),
            microbatch_id: microbatch_id.to_string(),
            shard_id: shard_id.to_string(),
            qos_class: admission.qos_class.clone(),
            tx_public_hash: admission.tx_public_hash.clone(),
            status,
            received_at_height: admission.received_at_height,
            received_at_ms: admission.received_at_ms,
            preconfirmed_at_ms,
            executed_at_ms,
            deadline_ms: admission.deadline_ms,
            retry_after_ms,
            result_root: result_root.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pipeline_low_latency_receipt",
            "chain_id": CHAIN_ID,
            "pipeline_protocol_version": PIPELINE_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "admission_id": self.admission_id,
            "lane_id": self.lane_id,
            "microbatch_id": self.microbatch_id,
            "shard_id": self.shard_id,
            "qos_class": self.qos_class.as_str(),
            "tx_public_hash": self.tx_public_hash,
            "status": self.status.as_str(),
            "received_at_height": self.received_at_height,
            "received_at_ms": self.received_at_ms,
            "preconfirmed_at_ms": self.preconfirmed_at_ms,
            "executed_at_ms": self.executed_at_ms,
            "deadline_ms": self.deadline_ms,
            "retry_after_ms": self.retry_after_ms,
            "result_root": self.result_root,
        })
    }

    pub fn validate(&self) -> PipelineResult<String> {
        if self.admission_id.is_empty() || self.lane_id.is_empty() {
            return Err("pipeline low-latency receipt admission and lane are required".to_string());
        }
        let expected = pipeline_low_latency_receipt_id(
            &self.admission_id,
            &self.microbatch_id,
            &self.shard_id,
            self.status.as_str(),
            &self.result_root,
        );
        if self.receipt_id != expected {
            return Err("pipeline low-latency receipt id mismatch".to_string());
        }
        Ok(self.receipt_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineQueueSnapshot {
    pub snapshot_id: String,
    pub height: u64,
    pub timestamp_ms: u64,
    pub lane_id: String,
    pub qos_class: PipelineQosClass,
    pub pending_count: u64,
    pub ready_count: u64,
    pub blocked_count: u64,
    pub oldest_deadline_ms: u64,
    pub average_payload_bytes: u64,
    pub queue_depth_limit: u64,
    pub inflight_microbatch_count: u64,
    pub shard_busy_bps: u64,
}

impl PipelineQueueSnapshot {
    pub fn build(
        lane: &PipelinePreconfirmationLane,
        height: u64,
        timestamp_ms: u64,
        admissions: &[PipelineAdmission],
        graph: Option<&PipelineDependencyGraph>,
        queue_depth_limit: u64,
        inflight_microbatch_count: u64,
        shard_busy_bps: u64,
    ) -> Self {
        let lane_admissions = admissions
            .iter()
            .filter(|admission| admission.lane_id == lane.lane_id)
            .cloned()
            .collect::<Vec<_>>();
        let pending_count = lane_admissions.len() as u64;
        let lane_ids = lane_admissions
            .iter()
            .map(|admission| admission.admission_id.clone())
            .collect::<BTreeSet<_>>();
        let ready_count = graph
            .map(|graph| {
                graph
                    .ready_admission_ids
                    .iter()
                    .filter(|admission_id| lane_ids.contains(*admission_id))
                    .count() as u64
            })
            .unwrap_or(pending_count);
        let blocked_count = pending_count.saturating_sub(ready_count);
        let oldest_deadline_ms = lane_admissions
            .iter()
            .map(|admission| admission.deadline_ms)
            .min()
            .unwrap_or(0);
        let total_payload_bytes = lane_admissions
            .iter()
            .map(|admission| admission.payload_bytes)
            .fold(0_u64, u64::saturating_add);
        let average_payload_bytes = total_payload_bytes.checked_div(pending_count).unwrap_or(0);
        let snapshot_id = pipeline_queue_snapshot_id(
            height,
            timestamp_ms,
            &lane.lane_id,
            pending_count,
            ready_count,
            blocked_count,
            shard_busy_bps,
        );
        Self {
            snapshot_id,
            height,
            timestamp_ms,
            lane_id: lane.lane_id.clone(),
            qos_class: lane.qos_class.clone(),
            pending_count,
            ready_count,
            blocked_count,
            oldest_deadline_ms,
            average_payload_bytes,
            queue_depth_limit,
            inflight_microbatch_count,
            shard_busy_bps,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pipeline_queue_snapshot",
            "chain_id": CHAIN_ID,
            "pipeline_protocol_version": PIPELINE_PROTOCOL_VERSION,
            "snapshot_id": self.snapshot_id,
            "height": self.height,
            "timestamp_ms": self.timestamp_ms,
            "lane_id": self.lane_id,
            "qos_class": self.qos_class.as_str(),
            "pending_count": self.pending_count,
            "ready_count": self.ready_count,
            "blocked_count": self.blocked_count,
            "oldest_deadline_ms": self.oldest_deadline_ms,
            "average_payload_bytes": self.average_payload_bytes,
            "queue_depth_limit": self.queue_depth_limit,
            "inflight_microbatch_count": self.inflight_microbatch_count,
            "shard_busy_bps": self.shard_busy_bps,
        })
    }

    pub fn validate(&self) -> PipelineResult<String> {
        if self.lane_id.is_empty() {
            return Err("pipeline queue snapshot lane id is required".to_string());
        }
        if self.ready_count.saturating_add(self.blocked_count) > self.pending_count {
            return Err("pipeline queue snapshot ready/blocked counts exceed pending".to_string());
        }
        let expected = pipeline_queue_snapshot_id(
            self.height,
            self.timestamp_ms,
            &self.lane_id,
            self.pending_count,
            self.ready_count,
            self.blocked_count,
            self.shard_busy_bps,
        );
        if self.snapshot_id != expected {
            return Err("pipeline queue snapshot id mismatch".to_string());
        }
        Ok(self.snapshot_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineBackpressureDecision {
    pub decision_id: String,
    pub snapshot_id: String,
    pub lane_id: String,
    pub qos_class: PipelineQosClass,
    pub action: PipelineRetryAction,
    pub reason: String,
    pub retry_after_ms: u64,
    pub shed_count: u64,
    pub admit_until_depth: u64,
    pub decided_at_ms: u64,
}

impl PipelineBackpressureDecision {
    pub fn decide(snapshot: &PipelineQueueSnapshot) -> Self {
        let depth_bps = if snapshot.queue_depth_limit == 0 {
            10_000
        } else {
            snapshot.pending_count.saturating_mul(10_000) / snapshot.queue_depth_limit
        };
        let (action, reason, retry_after_ms, shed_count) = if snapshot.oldest_deadline_ms > 0
            && snapshot.oldest_deadline_ms < snapshot.timestamp_ms
        {
            (
                PipelineRetryAction::DropExpired,
                "oldest_deadline_elapsed".to_string(),
                0,
                snapshot.blocked_count.max(1),
            )
        } else if depth_bps >= PIPELINE_BACKPRESSURE_SHED_DEPTH_BPS
            && snapshot.shard_busy_bps >= PIPELINE_BUSY_SHARD_BPS
        {
            (
                PipelineRetryAction::ShedLoad,
                "queue_and_shards_saturated".to_string(),
                TARGET_BLOCK_MS,
                snapshot.pending_count.saturating_sub(snapshot.ready_count),
            )
        } else if depth_bps >= PIPELINE_BACKPRESSURE_RETRY_DEPTH_BPS {
            (
                PipelineRetryAction::RetryAfter,
                "queue_depth_high".to_string(),
                TARGET_BLOCK_MS / 2,
                0,
            )
        } else if snapshot.ready_count == 0 && snapshot.blocked_count > 0 {
            (
                PipelineRetryAction::Requeue,
                "dependency_blocked".to_string(),
                TARGET_BLOCK_MS,
                0,
            )
        } else {
            (
                PipelineRetryAction::Admit,
                "capacity_available".to_string(),
                0,
                0,
            )
        };
        let admit_until_depth = snapshot
            .queue_depth_limit
            .saturating_sub(snapshot.pending_count)
            .min(snapshot.queue_depth_limit);
        let decision_id = pipeline_backpressure_decision_id(
            &snapshot.snapshot_id,
            &snapshot.lane_id,
            action.as_str(),
            &reason,
            retry_after_ms,
            shed_count,
        );
        Self {
            decision_id,
            snapshot_id: snapshot.snapshot_id.clone(),
            lane_id: snapshot.lane_id.clone(),
            qos_class: snapshot.qos_class.clone(),
            action,
            reason,
            retry_after_ms,
            shed_count,
            admit_until_depth,
            decided_at_ms: snapshot.timestamp_ms,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pipeline_backpressure_decision",
            "chain_id": CHAIN_ID,
            "pipeline_protocol_version": PIPELINE_PROTOCOL_VERSION,
            "decision_id": self.decision_id,
            "snapshot_id": self.snapshot_id,
            "lane_id": self.lane_id,
            "qos_class": self.qos_class.as_str(),
            "action": self.action.as_str(),
            "reason": self.reason,
            "retry_after_ms": self.retry_after_ms,
            "shed_count": self.shed_count,
            "admit_until_depth": self.admit_until_depth,
            "decided_at_ms": self.decided_at_ms,
        })
    }

    pub fn validate(&self) -> PipelineResult<String> {
        if self.snapshot_id.is_empty() || self.lane_id.is_empty() {
            return Err(
                "pipeline backpressure decision snapshot and lane are required".to_string(),
            );
        }
        let expected = pipeline_backpressure_decision_id(
            &self.snapshot_id,
            &self.lane_id,
            self.action.as_str(),
            &self.reason,
            self.retry_after_ms,
            self.shed_count,
        );
        if self.decision_id != expected {
            return Err("pipeline backpressure decision id mismatch".to_string());
        }
        Ok(self.decision_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineRetryDecision {
    pub retry_id: String,
    pub admission_id: String,
    pub source_receipt_id: String,
    pub backpressure_decision_id: String,
    pub action: PipelineRetryAction,
    pub attempt: u64,
    pub max_attempts: u64,
    pub retry_after_ms: u64,
    pub next_deadline_height: u64,
    pub reason: String,
}

impl PipelineRetryDecision {
    pub fn decide(
        admission: &PipelineAdmission,
        source_receipt_id: impl Into<String>,
        backpressure: &PipelineBackpressureDecision,
        attempt: u64,
        max_attempts: u64,
        current_height: u64,
    ) -> Self {
        let source_receipt_id = source_receipt_id.into();
        let action = if current_height > admission.deadline_height {
            PipelineRetryAction::DropExpired
        } else if attempt >= max_attempts {
            PipelineRetryAction::Escalate
        } else {
            match backpressure.action {
                PipelineRetryAction::Admit | PipelineRetryAction::RetryNow => {
                    PipelineRetryAction::RetryNow
                }
                PipelineRetryAction::RetryAfter | PipelineRetryAction::Requeue => {
                    PipelineRetryAction::RetryAfter
                }
                PipelineRetryAction::DropExpired => PipelineRetryAction::DropExpired,
                PipelineRetryAction::ShedLoad => PipelineRetryAction::ShedLoad,
                PipelineRetryAction::Escalate => PipelineRetryAction::Escalate,
            }
        };
        let retry_after_ms = match action {
            PipelineRetryAction::RetryAfter | PipelineRetryAction::Requeue => {
                backpressure.retry_after_ms.max(TARGET_BLOCK_MS / 4)
            }
            _ => 0,
        };
        let next_deadline_height = admission
            .deadline_height
            .max(current_height.saturating_add(1));
        let reason = format!("{}:{}", backpressure.reason, action.as_str());
        let retry_id = pipeline_retry_decision_id(
            &admission.admission_id,
            &source_receipt_id,
            &backpressure.decision_id,
            action.as_str(),
            attempt,
            next_deadline_height,
        );
        Self {
            retry_id,
            admission_id: admission.admission_id.clone(),
            source_receipt_id,
            backpressure_decision_id: backpressure.decision_id.clone(),
            action,
            attempt,
            max_attempts,
            retry_after_ms,
            next_deadline_height,
            reason,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pipeline_retry_decision",
            "chain_id": CHAIN_ID,
            "pipeline_protocol_version": PIPELINE_PROTOCOL_VERSION,
            "retry_id": self.retry_id,
            "admission_id": self.admission_id,
            "source_receipt_id": self.source_receipt_id,
            "backpressure_decision_id": self.backpressure_decision_id,
            "action": self.action.as_str(),
            "attempt": self.attempt,
            "max_attempts": self.max_attempts,
            "retry_after_ms": self.retry_after_ms,
            "next_deadline_height": self.next_deadline_height,
            "reason": self.reason,
        })
    }

    pub fn validate(&self) -> PipelineResult<String> {
        if self.admission_id.is_empty() || self.source_receipt_id.is_empty() {
            return Err("pipeline retry decision admission and receipt are required".to_string());
        }
        let expected = pipeline_retry_decision_id(
            &self.admission_id,
            &self.source_receipt_id,
            &self.backpressure_decision_id,
            self.action.as_str(),
            self.attempt,
            self.next_deadline_height,
        );
        if self.retry_id != expected {
            return Err("pipeline retry decision id mismatch".to_string());
        }
        Ok(self.retry_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineLaneAssemblyPlan {
    pub lane_id: String,
    pub lane_root: String,
    pub selected_microbatch_root: String,
    pub selected_admission_root: String,
    pub microbatch_count: u64,
    pub admission_count: u64,
    pub reserved_slot_count: u64,
}

impl PipelineLaneAssemblyPlan {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pipeline_lane_assembly_plan",
            "chain_id": CHAIN_ID,
            "pipeline_protocol_version": PIPELINE_PROTOCOL_VERSION,
            "lane_id": self.lane_id,
            "lane_root": self.lane_root,
            "selected_microbatch_root": self.selected_microbatch_root,
            "selected_admission_root": self.selected_admission_root,
            "microbatch_count": self.microbatch_count,
            "admission_count": self.admission_count,
            "reserved_slot_count": self.reserved_slot_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineBlockAssemblyPlan {
    pub plan_id: String,
    pub height: u64,
    pub prev_block_hash: String,
    pub pipeline_state_root: String,
    pub dependency_graph_root: String,
    pub microbatch_root: String,
    pub shard_root: String,
    pub shard_receipt_root: String,
    pub low_latency_receipt_root: String,
    pub lane_plan_root: String,
    pub selected_admission_root: String,
    pub tx_root: String,
    pub tx_count: u64,
    pub total_payload_bytes: u64,
    pub assembly_deadline_ms: u64,
    pub proposer_label: String,
    pub lane_plans: Vec<PipelineLaneAssemblyPlan>,
}

impl PipelineBlockAssemblyPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        height: u64,
        prev_block_hash: impl Into<String>,
        pipeline_state_root: impl Into<String>,
        dependency_graphs: &[PipelineDependencyGraph],
        microbatches: &[PipelineMicrobatch],
        shards: &[PipelineExecutionShard],
        shard_receipts: &[PipelineShardReceipt],
        low_latency_receipts: &[PipelineLowLatencyReceipt],
        lanes: &[PipelinePreconfirmationLane],
        assembly_deadline_ms: u64,
        proposer_label: impl Into<String>,
    ) -> PipelineResult<Self> {
        if microbatches.is_empty() {
            return Err("pipeline block assembly plan requires microbatches".to_string());
        }
        let prev_block_hash = prev_block_hash.into();
        let pipeline_state_root = pipeline_state_root.into();
        let proposer_label = proposer_label.into();
        if proposer_label.trim().is_empty() {
            return Err("pipeline block assembly proposer label is required".to_string());
        }
        let selected_admission_ids = microbatches
            .iter()
            .flat_map(|batch| batch.admission_ids.clone())
            .collect::<Vec<_>>();
        let selected_admission_root =
            pipeline_string_root("PIPELINE-BLOCK-SELECTED-ADMISSION", &selected_admission_ids);
        let tx_hashes = microbatches
            .iter()
            .map(|batch| batch.tx_root.clone())
            .collect::<Vec<_>>();
        let tx_root = pipeline_string_root("PIPELINE-BLOCK-TX-ROOT", &tx_hashes);
        let total_payload_bytes = microbatches
            .iter()
            .map(|batch| batch.total_payload_bytes)
            .fold(0_u64, u64::saturating_add);
        let lane_plans = lanes
            .iter()
            .map(|lane| {
                let lane_batches = microbatches
                    .iter()
                    .filter(|batch| batch.lane_id == lane.lane_id)
                    .cloned()
                    .collect::<Vec<_>>();
                let lane_admissions = lane_batches
                    .iter()
                    .flat_map(|batch| batch.admission_ids.clone())
                    .collect::<Vec<_>>();
                PipelineLaneAssemblyPlan {
                    lane_id: lane.lane_id.clone(),
                    lane_root: lane.lane_root(),
                    selected_microbatch_root: pipeline_microbatch_root(&lane_batches),
                    selected_admission_root: pipeline_string_root(
                        "PIPELINE-LANE-BLOCK-ADMISSION",
                        &lane_admissions,
                    ),
                    microbatch_count: lane_batches.len() as u64,
                    admission_count: lane_admissions.len() as u64,
                    reserved_slot_count: lane.reserved_microbatch_slots,
                }
            })
            .collect::<Vec<_>>();
        let dependency_graph_root = pipeline_dependency_graph_root(dependency_graphs);
        let microbatch_root = pipeline_microbatch_root(microbatches);
        let shard_root = pipeline_shard_root(shards);
        let shard_receipt_root = pipeline_shard_receipt_root(shard_receipts);
        let low_latency_receipt_root = pipeline_low_latency_receipt_root(low_latency_receipts);
        let lane_plan_root = merkle_root(
            "PIPELINE-LANE-ASSEMBLY-PLAN",
            &lane_plans
                .iter()
                .map(PipelineLaneAssemblyPlan::public_record)
                .collect::<Vec<_>>(),
        );
        let plan_id = pipeline_block_assembly_plan_id(
            height,
            &prev_block_hash,
            &pipeline_state_root,
            &microbatch_root,
            &shard_receipt_root,
            &selected_admission_root,
        );
        Ok(Self {
            plan_id,
            height,
            prev_block_hash,
            pipeline_state_root,
            dependency_graph_root,
            microbatch_root,
            shard_root,
            shard_receipt_root,
            low_latency_receipt_root,
            lane_plan_root,
            selected_admission_root,
            tx_root,
            tx_count: selected_admission_ids.len() as u64,
            total_payload_bytes,
            assembly_deadline_ms,
            proposer_label,
            lane_plans,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pipeline_block_assembly_plan",
            "chain_id": CHAIN_ID,
            "pipeline_protocol_version": PIPELINE_PROTOCOL_VERSION,
            "plan_id": self.plan_id,
            "height": self.height,
            "prev_block_hash": self.prev_block_hash,
            "pipeline_state_root": self.pipeline_state_root,
            "dependency_graph_root": self.dependency_graph_root,
            "microbatch_root": self.microbatch_root,
            "shard_root": self.shard_root,
            "shard_receipt_root": self.shard_receipt_root,
            "low_latency_receipt_root": self.low_latency_receipt_root,
            "lane_plan_root": self.lane_plan_root,
            "selected_admission_root": self.selected_admission_root,
            "tx_root": self.tx_root,
            "tx_count": self.tx_count,
            "total_payload_bytes": self.total_payload_bytes,
            "assembly_deadline_ms": self.assembly_deadline_ms,
            "proposer_label": self.proposer_label,
            "lane_plans": self.lane_plans.iter().map(PipelineLaneAssemblyPlan::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn validate(&self) -> PipelineResult<String> {
        if self.prev_block_hash.is_empty() || self.proposer_label.trim().is_empty() {
            return Err(
                "pipeline block assembly plan prev hash and proposer are required".to_string(),
            );
        }
        let expected = pipeline_block_assembly_plan_id(
            self.height,
            &self.prev_block_hash,
            &self.pipeline_state_root,
            &self.microbatch_root,
            &self.shard_receipt_root,
            &self.selected_admission_root,
        );
        if self.plan_id != expected {
            return Err("pipeline block assembly plan id mismatch".to_string());
        }
        Ok(self.plan_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineState {
    pub config: PipelineConfig,
    pub current_height: u64,
    pub next_microbatch_sequence: u64,
    pub next_lane_sequence: BTreeMap<String, u64>,
    pub lanes: BTreeMap<String, PipelinePreconfirmationLane>,
    pub pending_admissions: BTreeMap<String, PipelineAdmission>,
    pub dependency_edges: BTreeMap<String, PipelineDependencyEdge>,
    pub dependency_graphs: BTreeMap<String, PipelineDependencyGraph>,
    pub microbatches: BTreeMap<String, PipelineMicrobatch>,
    pub shards: BTreeMap<String, PipelineExecutionShard>,
    pub shard_receipts: BTreeMap<String, PipelineShardReceipt>,
    pub low_latency_receipts: BTreeMap<String, PipelineLowLatencyReceipt>,
    pub queue_snapshots: BTreeMap<String, PipelineQueueSnapshot>,
    pub backpressure_decisions: BTreeMap<String, PipelineBackpressureDecision>,
    pub retry_decisions: BTreeMap<String, PipelineRetryDecision>,
    pub block_plans: BTreeMap<String, PipelineBlockAssemblyPlan>,
}

impl PipelineState {
    pub fn new(config: PipelineConfig) -> PipelineResult<Self> {
        config.validate()?;
        let lanes = config
            .lanes
            .iter()
            .map(|lane| (lane.lane_id.clone(), lane.clone()))
            .collect::<BTreeMap<_, _>>();
        let next_lane_sequence = lanes
            .keys()
            .map(|lane_id| (lane_id.clone(), 0_u64))
            .collect::<BTreeMap<_, _>>();
        Ok(Self {
            config,
            current_height: 0,
            next_microbatch_sequence: 0,
            next_lane_sequence,
            lanes,
            pending_admissions: BTreeMap::new(),
            dependency_edges: BTreeMap::new(),
            dependency_graphs: BTreeMap::new(),
            microbatches: BTreeMap::new(),
            shards: BTreeMap::new(),
            shard_receipts: BTreeMap::new(),
            low_latency_receipts: BTreeMap::new(),
            queue_snapshots: BTreeMap::new(),
            backpressure_decisions: BTreeMap::new(),
            retry_decisions: BTreeMap::new(),
            block_plans: BTreeMap::new(),
        })
    }

    pub fn set_height(&mut self, height: u64) {
        self.current_height = height;
    }

    pub fn apply_admission_request(
        &mut self,
        request: PipelineAdmissionRequest,
        received_at_height: u64,
        received_at_ms: u64,
    ) -> PipelineResult<String> {
        let lane = self.lane_for_request(&request)?.clone();
        let lane_sequence = self
            .next_lane_sequence
            .get(&lane.lane_id)
            .cloned()
            .unwrap_or_default();
        let admission = PipelineAdmission::build(
            request,
            &lane,
            &self.config,
            received_at_height,
            received_at_ms,
            lane_sequence,
        )?;
        let admission_id = self.apply_admission(admission)?;
        self.next_lane_sequence
            .insert(lane.lane_id, lane_sequence.saturating_add(1));
        Ok(admission_id)
    }

    pub fn apply_admission(&mut self, admission: PipelineAdmission) -> PipelineResult<String> {
        admission.validate()?;
        let lane = self
            .lanes
            .get(&admission.lane_id)
            .ok_or_else(|| "pipeline admission references unknown lane".to_string())?;
        if self
            .pending_admissions
            .contains_key(&admission.admission_id)
        {
            return Err("pipeline admission already exists".to_string());
        }
        let lane_pending = self
            .pending_admissions
            .values()
            .filter(|existing| existing.lane_id == admission.lane_id)
            .count() as u64;
        if lane_pending >= lane.max_pending_admissions {
            return Err("pipeline admission lane is full".to_string());
        }
        let receipt = PipelineLowLatencyReceipt::admitted(&admission);
        let admission_id = admission.admission_id.clone();
        self.pending_admissions
            .insert(admission_id.clone(), admission);
        self.apply_low_latency_receipt(receipt)?;
        Ok(admission_id)
    }

    pub fn rebuild_dependency_graph(&mut self, height: u64) -> PipelineResult<String> {
        let admissions = self
            .pending_admissions
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let graph = PipelineDependencyGraph::build(height, &admissions)?;
        self.apply_dependency_graph(graph)
    }

    pub fn apply_dependency_graph(
        &mut self,
        graph: PipelineDependencyGraph,
    ) -> PipelineResult<String> {
        graph.validate()?;
        let graph_id = graph.graph_id.clone();
        for edge in &graph.edges {
            self.dependency_edges
                .insert(edge.edge_id.clone(), edge.clone());
        }
        self.dependency_graphs.insert(graph_id.clone(), graph);
        Ok(graph_id)
    }

    pub fn plan_microbatch(
        &mut self,
        height: u64,
        lane_id: &str,
        max_count: u64,
    ) -> PipelineResult<String> {
        self.plan_microbatch_at(
            height,
            lane_id,
            height.saturating_mul(TARGET_BLOCK_MS),
            max_count,
        )
    }

    pub fn plan_microbatch_at(
        &mut self,
        height: u64,
        lane_id: &str,
        planned_at_ms: u64,
        max_count: u64,
    ) -> PipelineResult<String> {
        let lane = self
            .lanes
            .get(lane_id)
            .cloned()
            .ok_or_else(|| "pipeline microbatch references unknown lane".to_string())?;
        let graph = match self.latest_dependency_graph(height) {
            Some(graph) => graph.clone(),
            None => {
                let admissions = self
                    .pending_admissions
                    .values()
                    .cloned()
                    .collect::<Vec<_>>();
                let graph = PipelineDependencyGraph::build(height, &admissions)?;
                self.apply_dependency_graph(graph.clone())?;
                graph
            }
        };
        let ready = graph
            .ready_admission_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let already_scheduled = self
            .microbatches
            .values()
            .flat_map(|batch| batch.admission_ids.clone())
            .collect::<BTreeSet<_>>();
        let mut admissions = self
            .pending_admissions
            .values()
            .filter(|admission| {
                admission.lane_id == lane_id
                    && ready.contains(&admission.admission_id)
                    && !already_scheduled.contains(&admission.admission_id)
                    && height <= admission.deadline_height
            })
            .cloned()
            .collect::<Vec<_>>();
        admissions.sort_by(compare_admissions);
        let limit = if max_count == 0 {
            self.config.max_microbatch_size
        } else {
            max_count.min(self.config.max_microbatch_size)
        }
        .min(lane.reserved_microbatch_slots)
        .max(1) as usize;
        admissions.truncate(limit);
        if admissions.is_empty() {
            return Err("pipeline microbatch has no ready admissions".to_string());
        }
        let batch_sequence = self.next_microbatch_sequence;
        let microbatch = PipelineMicrobatch::build(
            &lane,
            height,
            batch_sequence,
            planned_at_ms,
            &admissions,
            &graph,
        )?;
        let microbatch_id = self.apply_microbatch(microbatch)?;
        self.next_microbatch_sequence = self.next_microbatch_sequence.saturating_add(1);
        Ok(microbatch_id)
    }

    pub fn apply_microbatch(&mut self, microbatch: PipelineMicrobatch) -> PipelineResult<String> {
        microbatch.validate()?;
        if self.microbatches.contains_key(&microbatch.microbatch_id) {
            return Err("pipeline microbatch already exists".to_string());
        }
        for admission_id in &microbatch.admission_ids {
            if !self.pending_admissions.contains_key(admission_id) {
                return Err("pipeline microbatch references unknown admission".to_string());
            }
        }
        let microbatch_id = microbatch.microbatch_id.clone();
        for admission_id in &microbatch.admission_ids {
            if let Some(admission) = self.pending_admissions.get(admission_id).cloned() {
                let receipt = PipelineLowLatencyReceipt::preconfirmed(&admission, &microbatch);
                self.apply_low_latency_receipt(receipt)?;
            }
        }
        self.microbatches.insert(microbatch_id.clone(), microbatch);
        Ok(microbatch_id)
    }

    pub fn plan_parallel_shards(
        &mut self,
        microbatch_id: &str,
        worker_labels: &[String],
    ) -> PipelineResult<Vec<String>> {
        let microbatch = self
            .microbatches
            .get(microbatch_id)
            .cloned()
            .ok_or_else(|| "pipeline shard plan references unknown microbatch".to_string())?;
        let graph = self
            .dependency_graphs
            .get(&microbatch.dependency_graph_id)
            .cloned()
            .ok_or_else(|| "pipeline shard plan references unknown dependency graph".to_string())?;
        let admissions = microbatch
            .admission_ids
            .iter()
            .map(|admission_id| {
                self.pending_admissions
                    .get(admission_id)
                    .cloned()
                    .ok_or_else(|| "pipeline shard plan references unknown admission".to_string())
            })
            .collect::<PipelineResult<Vec<_>>>()?;
        let shard_count = self
            .config
            .max_shard_count
            .min(admissions.len() as u64)
            .max(1) as usize;
        let worker_count = worker_labels.len().max(1);
        let mut buckets = vec![Vec::<PipelineAdmission>::new(); shard_count];
        for (index, admission) in admissions.into_iter().enumerate() {
            buckets[index % shard_count].push(admission);
        }
        let mut shard_ids = Vec::new();
        for (index, bucket) in buckets.into_iter().enumerate() {
            if bucket.is_empty() {
                continue;
            }
            let worker_label = worker_labels
                .get(index % worker_count)
                .cloned()
                .unwrap_or_else(|| format!("local-worker-{index}"));
            let shard = PipelineExecutionShard::build(
                &microbatch,
                index as u64,
                worker_label,
                &bucket,
                &graph,
                self.config.shard_target_fuel,
            )?;
            shard_ids.push(self.apply_shard(shard)?);
        }
        Ok(shard_ids)
    }

    pub fn apply_shard(&mut self, shard: PipelineExecutionShard) -> PipelineResult<String> {
        shard.validate()?;
        if self.shards.contains_key(&shard.shard_id) {
            return Err("pipeline execution shard already exists".to_string());
        }
        if !self.microbatches.contains_key(&shard.microbatch_id) {
            return Err("pipeline execution shard references unknown microbatch".to_string());
        }
        let shard_id = shard.shard_id.clone();
        self.shards.insert(shard_id.clone(), shard);
        Ok(shard_id)
    }

    pub fn apply_shard_receipt(&mut self, receipt: PipelineShardReceipt) -> PipelineResult<String> {
        receipt.validate()?;
        if self.shard_receipts.contains_key(&receipt.receipt_id) {
            return Err("pipeline shard receipt already exists".to_string());
        }
        let shard = self
            .shards
            .get(&receipt.shard_id)
            .cloned()
            .ok_or_else(|| "pipeline shard receipt references unknown shard".to_string())?;
        let receipt_id = receipt.receipt_id.clone();
        for result in &receipt.results {
            let admission = self
                .pending_admissions
                .get(&result.admission_id)
                .cloned()
                .ok_or_else(|| "pipeline shard receipt references unknown admission".to_string())?;
            let retry_after_ms = if result.retryable { TARGET_BLOCK_MS } else { 0 };
            let low_latency = PipelineLowLatencyReceipt::executed(
                &admission,
                &shard,
                &receipt,
                result,
                retry_after_ms,
            );
            self.apply_low_latency_receipt(low_latency)?;
        }
        self.shard_receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn capture_queue_snapshot(
        &mut self,
        lane_id: &str,
        timestamp_ms: u64,
        shard_busy_bps: u64,
    ) -> PipelineResult<String> {
        let lane = self
            .lanes
            .get(lane_id)
            .cloned()
            .ok_or_else(|| "pipeline queue snapshot references unknown lane".to_string())?;
        let admissions = self
            .pending_admissions
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let graph = self.latest_dependency_graph(self.current_height).cloned();
        let inflight_microbatch_count = self
            .microbatches
            .values()
            .filter(|batch| batch.lane_id == lane_id)
            .count() as u64;
        let snapshot = PipelineQueueSnapshot::build(
            &lane,
            self.current_height,
            timestamp_ms,
            &admissions,
            graph.as_ref(),
            self.config.max_ready_queue_depth,
            inflight_microbatch_count,
            shard_busy_bps,
        );
        self.apply_queue_snapshot(snapshot)
    }

    pub fn apply_queue_snapshot(
        &mut self,
        snapshot: PipelineQueueSnapshot,
    ) -> PipelineResult<String> {
        snapshot.validate()?;
        let snapshot_id = snapshot.snapshot_id.clone();
        self.queue_snapshots.insert(snapshot_id.clone(), snapshot);
        Ok(snapshot_id)
    }

    pub fn decide_backpressure(&mut self, snapshot_id: &str) -> PipelineResult<String> {
        let snapshot = self
            .queue_snapshots
            .get(snapshot_id)
            .ok_or_else(|| "pipeline backpressure references unknown queue snapshot".to_string())?;
        let decision = PipelineBackpressureDecision::decide(snapshot);
        self.apply_backpressure_decision(decision)
    }

    pub fn apply_backpressure_decision(
        &mut self,
        decision: PipelineBackpressureDecision,
    ) -> PipelineResult<String> {
        decision.validate()?;
        let decision_id = decision.decision_id.clone();
        self.backpressure_decisions
            .insert(decision_id.clone(), decision);
        Ok(decision_id)
    }

    pub fn apply_retry_decision(
        &mut self,
        decision: PipelineRetryDecision,
    ) -> PipelineResult<String> {
        decision.validate()?;
        if !self.pending_admissions.contains_key(&decision.admission_id) {
            return Err("pipeline retry decision references unknown admission".to_string());
        }
        let retry_id = decision.retry_id.clone();
        self.retry_decisions.insert(retry_id.clone(), decision);
        Ok(retry_id)
    }

    pub fn apply_low_latency_receipt(
        &mut self,
        receipt: PipelineLowLatencyReceipt,
    ) -> PipelineResult<String> {
        receipt.validate()?;
        let receipt_id = receipt.receipt_id.clone();
        self.low_latency_receipts
            .insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn assemble_block_plan(
        &mut self,
        height: u64,
        prev_block_hash: impl Into<String>,
        assembly_deadline_ms: u64,
        proposer_label: impl Into<String>,
    ) -> PipelineResult<String> {
        let microbatches = self
            .microbatches
            .values()
            .filter(|batch| batch.height == height)
            .cloned()
            .collect::<Vec<_>>();
        let microbatch_ids = microbatches
            .iter()
            .map(|batch| batch.microbatch_id.clone())
            .collect::<BTreeSet<_>>();
        let shards = self
            .shards
            .values()
            .filter(|shard| microbatch_ids.contains(&shard.microbatch_id))
            .cloned()
            .collect::<Vec<_>>();
        let shard_ids = shards
            .iter()
            .map(|shard| shard.shard_id.clone())
            .collect::<BTreeSet<_>>();
        let shard_receipts = self
            .shard_receipts
            .values()
            .filter(|receipt| shard_ids.contains(&receipt.shard_id))
            .cloned()
            .collect::<Vec<_>>();
        let admission_ids = microbatches
            .iter()
            .flat_map(|batch| batch.admission_ids.clone())
            .collect::<BTreeSet<_>>();
        let low_latency_receipts = self
            .low_latency_receipts
            .values()
            .filter(|receipt| admission_ids.contains(&receipt.admission_id))
            .cloned()
            .collect::<Vec<_>>();
        let graphs = self
            .dependency_graphs
            .values()
            .filter(|graph| graph.height == height)
            .cloned()
            .collect::<Vec<_>>();
        let lanes = self.lanes.values().cloned().collect::<Vec<_>>();
        let plan = PipelineBlockAssemblyPlan::build(
            height,
            prev_block_hash,
            self.state_root(),
            &graphs,
            &microbatches,
            &shards,
            &shard_receipts,
            &low_latency_receipts,
            &lanes,
            assembly_deadline_ms,
            proposer_label,
        )?;
        self.apply_block_plan(plan)
    }

    pub fn apply_block_plan(&mut self, plan: PipelineBlockAssemblyPlan) -> PipelineResult<String> {
        plan.validate()?;
        let plan_id = plan.plan_id.clone();
        self.block_plans.insert(plan_id.clone(), plan);
        Ok(plan_id)
    }

    pub fn admission_root(&self) -> String {
        pipeline_admission_root(
            &self
                .pending_admissions
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn dependency_graph_root(&self) -> String {
        pipeline_dependency_graph_root(
            &self.dependency_graphs.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn microbatch_root(&self) -> String {
        pipeline_microbatch_root(&self.microbatches.values().cloned().collect::<Vec<_>>())
    }

    pub fn shard_root(&self) -> String {
        pipeline_shard_root(&self.shards.values().cloned().collect::<Vec<_>>())
    }

    pub fn shard_receipt_root(&self) -> String {
        pipeline_shard_receipt_root(&self.shard_receipts.values().cloned().collect::<Vec<_>>())
    }

    pub fn low_latency_receipt_root(&self) -> String {
        pipeline_low_latency_receipt_root(
            &self
                .low_latency_receipts
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn backpressure_decision_root(&self) -> String {
        merkle_root(
            "PIPELINE-BACKPRESSURE-DECISION",
            &self
                .backpressure_decisions
                .values()
                .map(PipelineBackpressureDecision::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn retry_decision_root(&self) -> String {
        merkle_root(
            "PIPELINE-RETRY-DECISION",
            &self
                .retry_decisions
                .values()
                .map(PipelineRetryDecision::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn block_plan_root(&self) -> String {
        merkle_root(
            "PIPELINE-BLOCK-ASSEMBLY-PLAN",
            &self
                .block_plans
                .values()
                .map(PipelineBlockAssemblyPlan::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PIPELINE-STATE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pipeline_state",
            "chain_id": CHAIN_ID,
            "pipeline_protocol_version": PIPELINE_PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "current_height": self.current_height,
            "next_microbatch_sequence": self.next_microbatch_sequence,
            "lane_root": pipeline_lane_root(&self.lanes.values().cloned().collect::<Vec<_>>()),
            "admission_root": self.admission_root(),
            "dependency_graph_root": self.dependency_graph_root(),
            "microbatch_root": self.microbatch_root(),
            "shard_root": self.shard_root(),
            "shard_receipt_root": self.shard_receipt_root(),
            "low_latency_receipt_root": self.low_latency_receipt_root(),
            "backpressure_decision_root": self.backpressure_decision_root(),
            "retry_decision_root": self.retry_decision_root(),
            "block_plan_root": self.block_plan_root(),
            "lane_count": self.lanes.len() as u64,
            "pending_admission_count": self.pending_admissions.len() as u64,
            "dependency_edge_count": self.dependency_edges.len() as u64,
            "dependency_graph_count": self.dependency_graphs.len() as u64,
            "microbatch_count": self.microbatches.len() as u64,
            "shard_count": self.shards.len() as u64,
            "shard_receipt_count": self.shard_receipts.len() as u64,
            "low_latency_receipt_count": self.low_latency_receipts.len() as u64,
        })
    }

    fn lane_for_request(
        &self,
        request: &PipelineAdmissionRequest,
    ) -> PipelineResult<&PipelinePreconfirmationLane> {
        if let Some(lane_id) = &request.requested_lane_id {
            return self
                .lanes
                .get(lane_id)
                .ok_or_else(|| "pipeline request references unknown lane".to_string());
        }
        self.lanes
            .values()
            .filter(|lane| lane.qos_class == request.qos_class)
            .max_by(|left, right| {
                left.qos_class
                    .priority_score()
                    .cmp(&right.qos_class.priority_score())
                    .then_with(|| right.target_latency_ms.cmp(&left.target_latency_ms))
                    .then_with(|| left.lane_id.cmp(&right.lane_id))
            })
            .or_else(|| {
                self.lanes
                    .values()
                    .max_by_key(|lane| lane.qos_class.priority_score())
            })
            .ok_or_else(|| "pipeline has no lanes".to_string())
    }

    fn latest_dependency_graph(&self, height: u64) -> Option<&PipelineDependencyGraph> {
        self.dependency_graphs
            .values()
            .filter(|graph| graph.height == height)
            .max_by(|left, right| left.graph_id.cmp(&right.graph_id))
            .or_else(|| {
                self.dependency_graphs.values().max_by(|left, right| {
                    left.height
                        .cmp(&right.height)
                        .then(left.graph_id.cmp(&right.graph_id))
                })
            })
    }
}

impl Default for PipelineState {
    fn default() -> Self {
        Self::new(PipelineConfig::default()).expect("default pipeline config is valid")
    }
}

pub fn pipeline_config_id(record: &Value) -> String {
    domain_hash("PIPELINE-CONFIG-ID", &[HashPart::Json(record)], 32)
}

pub fn pipeline_lane_id(record: &Value) -> String {
    domain_hash("PIPELINE-LANE-ID", &[HashPart::Json(record)], 32)
}

pub fn pipeline_lane_root(lanes: &[PipelinePreconfirmationLane]) -> String {
    merkle_root(
        "PIPELINE-PRECONFIRMATION-LANE",
        &lanes
            .iter()
            .map(PipelinePreconfirmationLane::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn pipeline_state_key_hash(state_domain: &str, logical_key: &str) -> String {
    domain_hash(
        "PIPELINE-STATE-KEY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(state_domain),
            HashPart::Str(logical_key),
        ],
        32,
    )
}

pub fn pipeline_tx_public_hash(tx_public_record: &Value) -> String {
    domain_hash(
        "PIPELINE-TX-PUBLIC",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(tx_public_record)],
        32,
    )
}

pub fn pipeline_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn pipeline_string_hash(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn pipeline_string_root(domain: &str, values: &[String]) -> String {
    merkle_root(
        domain,
        &values
            .iter()
            .map(|value| Value::String(value.clone()))
            .collect::<Vec<_>>(),
    )
}

pub fn pipeline_state_access_root(accesses: &[PipelineStateAccess]) -> String {
    merkle_root(
        "PIPELINE-STATE-ACCESS",
        &accesses
            .iter()
            .map(PipelineStateAccess::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn pipeline_admission_id(
    lane_id: &str,
    lane_sequence: u64,
    qos_class: &str,
    tx_public_hash: &str,
    payload_root: &str,
    deadline_height: u64,
    deadline_ms: u64,
) -> String {
    domain_hash(
        "PIPELINE-ADMISSION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Int(lane_sequence as i128),
            HashPart::Str(qos_class),
            HashPart::Str(tx_public_hash),
            HashPart::Str(payload_root),
            HashPart::Int(deadline_height as i128),
            HashPart::Int(deadline_ms as i128),
        ],
        32,
    )
}

pub fn pipeline_admission_root(admissions: &[PipelineAdmission]) -> String {
    merkle_root(
        "PIPELINE-ADMISSION",
        &admissions
            .iter()
            .map(PipelineAdmission::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn pipeline_tx_hash_root(admissions: &[PipelineAdmission]) -> String {
    merkle_root(
        "PIPELINE-TX-HASH",
        &admissions
            .iter()
            .map(|admission| {
                json!({
                    "admission_id": admission.admission_id,
                    "tx_public_hash": admission.tx_public_hash,
                })
            })
            .collect::<Vec<_>>(),
    )
}

pub fn pipeline_dependency_edge_id(
    parent_admission_id: &str,
    child_admission_id: &str,
    edge_kind: &str,
    state_key_hash: &str,
    reason: &str,
) -> String {
    domain_hash(
        "PIPELINE-DEPENDENCY-EDGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(parent_admission_id),
            HashPart::Str(child_admission_id),
            HashPart::Str(edge_kind),
            HashPart::Str(state_key_hash),
            HashPart::Str(reason),
        ],
        32,
    )
}

pub fn pipeline_dependency_edge_root(edges: &[PipelineDependencyEdge]) -> String {
    merkle_root(
        "PIPELINE-DEPENDENCY-EDGE",
        &edges
            .iter()
            .map(PipelineDependencyEdge::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn pipeline_dependency_graph_id(
    height: u64,
    admission_root: &str,
    edge_root: &str,
    ready_root: &str,
    blocked_root: &str,
) -> String {
    domain_hash(
        "PIPELINE-DEPENDENCY-GRAPH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Str(admission_root),
            HashPart::Str(edge_root),
            HashPart::Str(ready_root),
            HashPart::Str(blocked_root),
        ],
        32,
    )
}

pub fn pipeline_dependency_graph_root(graphs: &[PipelineDependencyGraph]) -> String {
    merkle_root(
        "PIPELINE-DEPENDENCY-GRAPH",
        &graphs
            .iter()
            .map(PipelineDependencyGraph::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn pipeline_microbatch_id(
    lane_id: &str,
    height: u64,
    batch_sequence: u64,
    admission_root: &str,
    dependency_graph_id: &str,
) -> String {
    domain_hash(
        "PIPELINE-MICROBATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Int(height as i128),
            HashPart::Int(batch_sequence as i128),
            HashPart::Str(admission_root),
            HashPart::Str(dependency_graph_id),
        ],
        32,
    )
}

pub fn pipeline_microbatch_root(microbatches: &[PipelineMicrobatch]) -> String {
    merkle_root(
        "PIPELINE-MICROBATCH",
        &microbatches
            .iter()
            .map(PipelineMicrobatch::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn pipeline_shard_id(
    microbatch_id: &str,
    shard_index: u64,
    worker_label: &str,
    admission_root: &str,
    state_access_root: &str,
) -> String {
    domain_hash(
        "PIPELINE-SHARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(microbatch_id),
            HashPart::Int(shard_index as i128),
            HashPart::Str(worker_label),
            HashPart::Str(admission_root),
            HashPart::Str(state_access_root),
        ],
        32,
    )
}

pub fn pipeline_shard_root(shards: &[PipelineExecutionShard]) -> String {
    merkle_root(
        "PIPELINE-EXECUTION-SHARD",
        &shards
            .iter()
            .map(PipelineExecutionShard::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn pipeline_execution_result_root(results: &[PipelineExecutionResult]) -> String {
    merkle_root(
        "PIPELINE-EXECUTION-RESULT",
        &results
            .iter()
            .map(PipelineExecutionResult::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn pipeline_shard_receipt_id(
    shard_id: &str,
    microbatch_id: &str,
    executed_at_height: u64,
    result_root: &str,
    state_delta_root: &str,
) -> String {
    domain_hash(
        "PIPELINE-SHARD-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(shard_id),
            HashPart::Str(microbatch_id),
            HashPart::Int(executed_at_height as i128),
            HashPart::Str(result_root),
            HashPart::Str(state_delta_root),
        ],
        32,
    )
}

pub fn pipeline_shard_receipt_root(receipts: &[PipelineShardReceipt]) -> String {
    merkle_root(
        "PIPELINE-SHARD-RECEIPT",
        &receipts
            .iter()
            .map(PipelineShardReceipt::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn pipeline_low_latency_receipt_id(
    admission_id: &str,
    microbatch_id: &str,
    shard_id: &str,
    status: &str,
    result_root: &str,
) -> String {
    domain_hash(
        "PIPELINE-LOW-LATENCY-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(admission_id),
            HashPart::Str(microbatch_id),
            HashPart::Str(shard_id),
            HashPart::Str(status),
            HashPart::Str(result_root),
        ],
        32,
    )
}

pub fn pipeline_low_latency_receipt_root(receipts: &[PipelineLowLatencyReceipt]) -> String {
    merkle_root(
        "PIPELINE-LOW-LATENCY-RECEIPT",
        &receipts
            .iter()
            .map(PipelineLowLatencyReceipt::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn pipeline_queue_snapshot_id(
    height: u64,
    timestamp_ms: u64,
    lane_id: &str,
    pending_count: u64,
    ready_count: u64,
    blocked_count: u64,
    shard_busy_bps: u64,
) -> String {
    domain_hash(
        "PIPELINE-QUEUE-SNAPSHOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Int(timestamp_ms as i128),
            HashPart::Str(lane_id),
            HashPart::Int(pending_count as i128),
            HashPart::Int(ready_count as i128),
            HashPart::Int(blocked_count as i128),
            HashPart::Int(shard_busy_bps as i128),
        ],
        32,
    )
}

pub fn pipeline_backpressure_decision_id(
    snapshot_id: &str,
    lane_id: &str,
    action: &str,
    reason: &str,
    retry_after_ms: u64,
    shed_count: u64,
) -> String {
    domain_hash(
        "PIPELINE-BACKPRESSURE-DECISION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(snapshot_id),
            HashPart::Str(lane_id),
            HashPart::Str(action),
            HashPart::Str(reason),
            HashPart::Int(retry_after_ms as i128),
            HashPart::Int(shed_count as i128),
        ],
        32,
    )
}

pub fn pipeline_retry_decision_id(
    admission_id: &str,
    source_receipt_id: &str,
    backpressure_decision_id: &str,
    action: &str,
    attempt: u64,
    next_deadline_height: u64,
) -> String {
    domain_hash(
        "PIPELINE-RETRY-DECISION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(admission_id),
            HashPart::Str(source_receipt_id),
            HashPart::Str(backpressure_decision_id),
            HashPart::Str(action),
            HashPart::Int(attempt as i128),
            HashPart::Int(next_deadline_height as i128),
        ],
        32,
    )
}

pub fn pipeline_block_assembly_plan_id(
    height: u64,
    prev_block_hash: &str,
    pipeline_state_root: &str,
    microbatch_root: &str,
    shard_receipt_root: &str,
    selected_admission_root: &str,
) -> String {
    domain_hash(
        "PIPELINE-BLOCK-ASSEMBLY-PLAN-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Str(prev_block_hash),
            HashPart::Str(pipeline_state_root),
            HashPart::Str(microbatch_root),
            HashPart::Str(shard_receipt_root),
            HashPart::Str(selected_admission_root),
        ],
        32,
    )
}

fn pipeline_access_set_root(
    domain: &str,
    accesses: &[PipelineStateAccess],
    writes_only: bool,
) -> String {
    merkle_root(
        domain,
        &accesses
            .iter()
            .filter(|access| {
                if writes_only {
                    access.access_mode.writes()
                } else {
                    !access.access_mode.writes()
                }
            })
            .map(PipelineStateAccess::public_record)
            .collect::<Vec<_>>(),
    )
}

fn compare_admissions(left: &PipelineAdmission, right: &PipelineAdmission) -> std::cmp::Ordering {
    right
        .qos_class
        .priority_score()
        .cmp(&left.qos_class.priority_score())
        .then_with(|| left.deadline_height.cmp(&right.deadline_height))
        .then_with(|| left.deadline_ms.cmp(&right.deadline_ms))
        .then_with(|| {
            right
                .fee_density_microunits
                .cmp(&left.fee_density_microunits)
        })
        .then_with(|| left.lane_sequence.cmp(&right.lane_sequence))
        .then_with(|| left.admission_id.cmp(&right.admission_id))
}

fn conflicting_state_key(left: &PipelineAdmission, right: &PipelineAdmission) -> Option<String> {
    for left_access in &left.state_accesses {
        for right_access in &right.state_accesses {
            if left_access.state_key_hash == right_access.state_key_hash
                && left_access
                    .access_mode
                    .conflicts_with(&right_access.access_mode)
            {
                return Some(left_access.state_key_hash.clone());
            }
        }
    }
    None
}

fn estimate_shard_fuel(admissions: &[PipelineAdmission]) -> u64 {
    admissions
        .iter()
        .map(|admission| {
            let access_fuel = admission.state_accesses.len() as u64 * 250;
            let payload_fuel = admission.payload_bytes / 16;
            1_000_u64
                .saturating_add(access_fuel)
                .saturating_add(payload_fuel)
        })
        .fold(0_u64, u64::saturating_add)
}
