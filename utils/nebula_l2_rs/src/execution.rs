use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ExecutionResult<T> = Result<T, String>;

pub const EXECUTION_PROTOCOL_VERSION: &str = "nebula-execution-v1";
pub const EXECUTION_DEFAULT_MAX_PARALLELISM: u64 = 16;
pub const EXECUTION_DEFAULT_BUNDLE_FUEL_LIMIT: u64 = 8_000_000;
pub const EXECUTION_DEFAULT_LOW_FEE_CREDIT_UNITS: u64 = 64;
pub const EXECUTION_DEFAULT_SCHEDULE_TTL_BLOCKS: u64 = 8;
pub const EXECUTION_MAX_ACCESS_SET_ITEMS: usize = 256;
pub const EXECUTION_MAX_BUNDLE_INTENTS: usize = 512;
pub const EXECUTION_STATUS_PENDING: &str = "pending";
pub const EXECUTION_STATUS_READY: &str = "ready";
pub const EXECUTION_STATUS_EXECUTED: &str = "executed";
pub const EXECUTION_STATUS_FAILED: &str = "failed";
pub const EXECUTION_STATUS_EXPIRED: &str = "expired";
pub const EXECUTION_STATUS_THROTTLED: &str = "throttled";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ExecutionLane {
    System,
    Transfer,
    Contract,
    Defi,
    Bridge,
    Oracle,
    Prover,
    LowFee,
    Private,
    Custom(String),
}

impl ExecutionLane {
    pub fn as_str(&self) -> String {
        match self {
            Self::System => "system".to_string(),
            Self::Transfer => "transfer".to_string(),
            Self::Contract => "contract".to_string(),
            Self::Defi => "defi".to_string(),
            Self::Bridge => "bridge".to_string(),
            Self::Oracle => "oracle".to_string(),
            Self::Prover => "prover".to_string(),
            Self::LowFee => "low_fee".to_string(),
            Self::Private => "private".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }

    pub fn default_priority(&self) -> u64 {
        match self {
            Self::System => 1_000_000,
            Self::Bridge => 900_000,
            Self::Oracle => 800_000,
            Self::Prover => 700_000,
            Self::Defi => 600_000,
            Self::Contract => 500_000,
            Self::Transfer => 400_000,
            Self::Private => 350_000,
            Self::LowFee => 250_000,
            Self::Custom(_) => 100_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionAccessMode {
    Read,
    Write,
}

impl ExecutionAccessMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ExecutionClass {
    Sequential,
    Parallel,
    Private,
    LowFee,
    BridgeCritical,
    ProverBound,
    Custom(String),
}

impl ExecutionClass {
    pub fn as_str(&self) -> String {
        match self {
            Self::Sequential => "sequential".to_string(),
            Self::Parallel => "parallel".to_string(),
            Self::Private => "private".to_string(),
            Self::LowFee => "low_fee".to_string(),
            Self::BridgeCritical => "bridge_critical".to_string(),
            Self::ProverBound => "prover_bound".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }

    pub fn prefers_parallelism(&self) -> bool {
        matches!(
            self,
            Self::Parallel | Self::LowFee | Self::Private | Self::ProverBound
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ExecutionConflictKind {
    WriteWrite,
    ReadWrite,
    ExpiredIntent,
    FuelLimit,
    LaneThrottle,
    PrivacyBudget,
    Custom(String),
}

impl ExecutionConflictKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::WriteWrite => "write_write".to_string(),
            Self::ReadWrite => "read_write".to_string(),
            Self::ExpiredIntent => "expired_intent".to_string(),
            Self::FuelLimit => "fuel_limit".to_string(),
            Self::LaneThrottle => "lane_throttle".to_string(),
            Self::PrivacyBudget => "privacy_budget".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateAccess {
    pub access_id: String,
    pub tx_id: String,
    pub domain: String,
    pub key_commitment: String,
    pub mode: ExecutionAccessMode,
    pub ordinal: u64,
}

impl StateAccess {
    pub fn new(
        tx_id: impl Into<String>,
        domain: impl Into<String>,
        key_commitment: impl Into<String>,
        mode: ExecutionAccessMode,
        ordinal: u64,
    ) -> ExecutionResult<Self> {
        let tx_id = tx_id.into();
        let domain = domain.into();
        let key_commitment = key_commitment.into();
        ensure_non_empty(&tx_id, "execution access tx id")?;
        ensure_non_empty(&domain, "execution access domain")?;
        ensure_non_empty(&key_commitment, "execution access key commitment")?;
        let access_id = state_access_id(&tx_id, &domain, &key_commitment, mode, ordinal);
        Ok(Self {
            access_id,
            tx_id,
            domain,
            key_commitment,
            mode,
            ordinal,
        })
    }

    pub fn conflicts_with(&self, other: &Self) -> Option<ExecutionConflictKind> {
        if self.tx_id == other.tx_id {
            return None;
        }
        if self.domain != other.domain || self.key_commitment != other.key_commitment {
            return None;
        }
        match (self.mode, other.mode) {
            (ExecutionAccessMode::Write, ExecutionAccessMode::Write) => {
                Some(ExecutionConflictKind::WriteWrite)
            }
            (ExecutionAccessMode::Write, ExecutionAccessMode::Read)
            | (ExecutionAccessMode::Read, ExecutionAccessMode::Write) => {
                Some(ExecutionConflictKind::ReadWrite)
            }
            _ => None,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_access",
            "chain_id": CHAIN_ID,
            "access_id": self.access_id,
            "tx_id": self.tx_id,
            "domain": self.domain,
            "key_commitment": self.key_commitment,
            "mode": self.mode.as_str(),
            "ordinal": self.ordinal,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionIntent {
    pub intent_id: String,
    pub tx_id: String,
    pub lane: ExecutionLane,
    pub class: ExecutionClass,
    pub fee_units: u64,
    pub low_fee_credit_units: u64,
    pub fuel_limit: u64,
    pub priority: u64,
    pub quantum_auth_root: String,
    pub privacy_root: String,
    pub access_root: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl ExecutionIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tx_id: impl Into<String>,
        lane: ExecutionLane,
        class: ExecutionClass,
        fee_units: u64,
        low_fee_credit_units: u64,
        fuel_limit: u64,
        priority: u64,
        quantum_auth_root: impl Into<String>,
        privacy_root: impl Into<String>,
        accesses: &[StateAccess],
        submitted_at_height: u64,
        expires_at_height: u64,
    ) -> ExecutionResult<Self> {
        let tx_id = tx_id.into();
        let quantum_auth_root = quantum_auth_root.into();
        let privacy_root = privacy_root.into();
        ensure_non_empty(&tx_id, "execution intent tx id")?;
        ensure_non_empty(&quantum_auth_root, "execution intent quantum auth root")?;
        ensure_non_empty(&privacy_root, "execution intent privacy root")?;
        ensure_positive(fuel_limit, "execution intent fuel limit")?;
        if accesses.len() > EXECUTION_MAX_ACCESS_SET_ITEMS {
            return Err("execution intent access set is too large".to_string());
        }
        if expires_at_height <= submitted_at_height {
            return Err("execution intent expiry must be after submission".to_string());
        }
        let access_root = state_access_root(accesses);
        let intent_id = execution_intent_id(
            &tx_id,
            &lane,
            &class,
            fee_units,
            low_fee_credit_units,
            fuel_limit,
            priority,
            &quantum_auth_root,
            &privacy_root,
            &access_root,
            submitted_at_height,
            expires_at_height,
        );
        Ok(Self {
            intent_id,
            tx_id,
            lane,
            class,
            fee_units,
            low_fee_credit_units,
            fuel_limit,
            priority,
            quantum_auth_root,
            privacy_root,
            access_root,
            submitted_at_height,
            expires_at_height,
            status: EXECUTION_STATUS_PENDING.to_string(),
        })
    }

    pub fn effective_priority(&self) -> u64 {
        self.priority
            .saturating_add(self.lane.default_priority())
            .saturating_add(self.fee_units.min(1_000_000))
            .saturating_add(self.low_fee_credit_units.min(10_000))
    }

    pub fn is_expired(&self, height: u64) -> bool {
        height >= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "execution_intent",
            "chain_id": CHAIN_ID,
            "protocol_version": EXECUTION_PROTOCOL_VERSION,
            "intent_id": self.intent_id,
            "tx_id": self.tx_id,
            "lane": self.lane.as_str(),
            "class": self.class.as_str(),
            "fee_units": self.fee_units,
            "low_fee_credit_units": self.low_fee_credit_units,
            "fuel_limit": self.fuel_limit,
            "priority": self.priority,
            "effective_priority": self.effective_priority(),
            "quantum_auth_root": self.quantum_auth_root,
            "privacy_root": self.privacy_root,
            "access_root": self.access_root,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionShard {
    pub shard_id: String,
    pub label: String,
    pub lane: ExecutionLane,
    pub state_domain_root: String,
    pub max_parallelism: u64,
    pub bundle_fuel_limit: u64,
    pub fee_floor_units: u64,
    pub low_fee_credit_units: u64,
    pub status: String,
}

impl ExecutionShard {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: impl Into<String>,
        lane: ExecutionLane,
        state_domains: Vec<String>,
        max_parallelism: u64,
        bundle_fuel_limit: u64,
        fee_floor_units: u64,
        low_fee_credit_units: u64,
    ) -> ExecutionResult<Self> {
        let label = label.into();
        ensure_non_empty(&label, "execution shard label")?;
        ensure_positive(max_parallelism, "execution shard max parallelism")?;
        ensure_positive(bundle_fuel_limit, "execution shard bundle fuel limit")?;
        ensure_unique_strings(&state_domains, "execution shard state domains")?;
        let state_domain_root =
            execution_string_set_root("EXECUTION-SHARD-DOMAINS", &state_domains);
        let shard_id = execution_shard_id(
            &label,
            &lane,
            &state_domain_root,
            max_parallelism,
            bundle_fuel_limit,
            fee_floor_units,
            low_fee_credit_units,
        );
        Ok(Self {
            shard_id,
            label,
            lane,
            state_domain_root,
            max_parallelism,
            bundle_fuel_limit,
            fee_floor_units,
            low_fee_credit_units,
            status: EXECUTION_STATUS_READY.to_string(),
        })
    }

    pub fn accepts(&self, intent: &ExecutionIntent) -> bool {
        self.status == EXECUTION_STATUS_READY && self.lane == intent.lane
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "execution_shard",
            "chain_id": CHAIN_ID,
            "shard_id": self.shard_id,
            "label": self.label,
            "lane": self.lane.as_str(),
            "state_domain_root": self.state_domain_root,
            "max_parallelism": self.max_parallelism,
            "bundle_fuel_limit": self.bundle_fuel_limit,
            "fee_floor_units": self.fee_floor_units,
            "low_fee_credit_units": self.low_fee_credit_units,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictEdge {
    pub edge_id: String,
    pub left_intent_id: String,
    pub right_intent_id: String,
    pub conflict_kind: ExecutionConflictKind,
    pub access_root: String,
    pub reason_root: String,
}

impl ConflictEdge {
    pub fn new(
        left_intent_id: impl Into<String>,
        right_intent_id: impl Into<String>,
        conflict_kind: ExecutionConflictKind,
        accesses: &[StateAccess],
        reason: &Value,
    ) -> ExecutionResult<Self> {
        let left_intent_id = left_intent_id.into();
        let right_intent_id = right_intent_id.into();
        ensure_non_empty(&left_intent_id, "execution conflict left intent id")?;
        ensure_non_empty(&right_intent_id, "execution conflict right intent id")?;
        if left_intent_id == right_intent_id {
            return Err("execution conflict requires two distinct intents".to_string());
        }
        let (left_intent_id, right_intent_id) = if left_intent_id <= right_intent_id {
            (left_intent_id, right_intent_id)
        } else {
            (right_intent_id, left_intent_id)
        };
        let access_root = state_access_root(accesses);
        let reason_root = execution_payload_root("EXECUTION-CONFLICT-REASON", reason);
        let edge_id = conflict_edge_id(
            &left_intent_id,
            &right_intent_id,
            &conflict_kind,
            &access_root,
            &reason_root,
        );
        Ok(Self {
            edge_id,
            left_intent_id,
            right_intent_id,
            conflict_kind,
            access_root,
            reason_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "execution_conflict_edge",
            "chain_id": CHAIN_ID,
            "edge_id": self.edge_id,
            "left_intent_id": self.left_intent_id,
            "right_intent_id": self.right_intent_id,
            "conflict_kind": self.conflict_kind.as_str(),
            "access_root": self.access_root,
            "reason_root": self.reason_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionBundle {
    pub bundle_id: String,
    pub height: u64,
    pub shard_id: String,
    pub lane: ExecutionLane,
    pub intent_ids: Vec<String>,
    pub access_root: String,
    pub conflict_root: String,
    pub total_fuel_limit: u64,
    pub total_fee_units: u64,
    pub low_fee_credit_units: u64,
    pub privacy_root: String,
    pub status: String,
}

impl ExecutionBundle {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        height: u64,
        shard: &ExecutionShard,
        intents: &[ExecutionIntent],
        accesses: &[StateAccess],
        conflicts: &[ConflictEdge],
    ) -> ExecutionResult<Self> {
        if intents.is_empty() {
            return Err("execution bundle requires at least one intent".to_string());
        }
        if intents.len() > EXECUTION_MAX_BUNDLE_INTENTS {
            return Err("execution bundle contains too many intents".to_string());
        }
        let mut intent_ids = intents
            .iter()
            .map(|intent| intent.intent_id.clone())
            .collect::<Vec<_>>();
        intent_ids.sort();
        ensure_unique_strings(&intent_ids, "execution bundle intent ids")?;
        let total_fuel_limit = intents.iter().map(|intent| intent.fuel_limit).sum::<u64>();
        if total_fuel_limit > shard.bundle_fuel_limit {
            return Err("execution bundle exceeds shard fuel limit".to_string());
        }
        let total_fee_units = intents.iter().map(|intent| intent.fee_units).sum::<u64>();
        let low_fee_credit_units = intents
            .iter()
            .map(|intent| intent.low_fee_credit_units)
            .sum::<u64>();
        let access_root = state_access_root(accesses);
        let conflict_root = conflict_edge_root(conflicts);
        let privacy_root = execution_string_set_root(
            "EXECUTION-BUNDLE-PRIVACY",
            &intents
                .iter()
                .map(|intent| intent.privacy_root.clone())
                .collect::<Vec<_>>(),
        );
        let bundle_id = execution_bundle_id(
            height,
            &shard.shard_id,
            &shard.lane,
            &intent_ids,
            &access_root,
            &conflict_root,
            total_fuel_limit,
            total_fee_units,
            low_fee_credit_units,
            &privacy_root,
        );
        Ok(Self {
            bundle_id,
            height,
            shard_id: shard.shard_id.clone(),
            lane: shard.lane.clone(),
            intent_ids,
            access_root,
            conflict_root,
            total_fuel_limit,
            total_fee_units,
            low_fee_credit_units,
            privacy_root,
            status: EXECUTION_STATUS_READY.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "execution_bundle",
            "chain_id": CHAIN_ID,
            "bundle_id": self.bundle_id,
            "height": self.height,
            "shard_id": self.shard_id,
            "lane": self.lane.as_str(),
            "intent_root": execution_string_set_root("EXECUTION-BUNDLE-INTENTS", &self.intent_ids),
            "intent_count": self.intent_ids.len() as u64,
            "access_root": self.access_root,
            "conflict_root": self.conflict_root,
            "total_fuel_limit": self.total_fuel_limit,
            "total_fee_units": self.total_fee_units,
            "low_fee_credit_units": self.low_fee_credit_units,
            "privacy_root": self.privacy_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionSchedule {
    pub schedule_id: String,
    pub height: u64,
    pub epoch: u64,
    pub bundle_root: String,
    pub conflict_root: String,
    pub shard_root: String,
    pub total_intents: u64,
    pub parallel_width: u64,
    pub state_read_root: String,
    pub state_write_root: String,
    pub determinism_root: String,
    pub expires_at_height: u64,
    pub status: String,
}

impl ExecutionSchedule {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        height: u64,
        epoch: u64,
        bundles: &[ExecutionBundle],
        conflicts: &[ConflictEdge],
        shards: &[ExecutionShard],
        reads: &[String],
        writes: &[String],
        expires_at_height: u64,
    ) -> ExecutionResult<Self> {
        if expires_at_height <= height {
            return Err("execution schedule expiry must be after height".to_string());
        }
        let bundle_root = execution_bundle_root(bundles);
        let conflict_root = conflict_edge_root(conflicts);
        let shard_root = execution_shard_root(shards);
        let total_intents = bundles
            .iter()
            .map(|bundle| bundle.intent_ids.len() as u64)
            .sum::<u64>();
        let parallel_width = bundles.len() as u64;
        let state_read_root = execution_string_set_root("EXECUTION-SCHEDULE-READS", reads);
        let state_write_root = execution_string_set_root("EXECUTION-SCHEDULE-WRITES", writes);
        let determinism_root = execution_payload_root(
            "EXECUTION-SCHEDULE-DETERMINISM",
            &json!({
                "height": height,
                "epoch": epoch,
                "bundle_root": bundle_root,
                "conflict_root": conflict_root,
                "shard_root": shard_root,
                "state_read_root": state_read_root,
                "state_write_root": state_write_root,
            }),
        );
        let schedule_id = execution_schedule_id(
            height,
            epoch,
            &bundle_root,
            &conflict_root,
            &shard_root,
            total_intents,
            parallel_width,
            &state_read_root,
            &state_write_root,
            &determinism_root,
            expires_at_height,
        );
        Ok(Self {
            schedule_id,
            height,
            epoch,
            bundle_root,
            conflict_root,
            shard_root,
            total_intents,
            parallel_width,
            state_read_root,
            state_write_root,
            determinism_root,
            expires_at_height,
            status: EXECUTION_STATUS_READY.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "execution_schedule",
            "chain_id": CHAIN_ID,
            "protocol_version": EXECUTION_PROTOCOL_VERSION,
            "schedule_id": self.schedule_id,
            "height": self.height,
            "epoch": self.epoch,
            "bundle_root": self.bundle_root,
            "conflict_root": self.conflict_root,
            "shard_root": self.shard_root,
            "total_intents": self.total_intents,
            "parallel_width": self.parallel_width,
            "state_read_root": self.state_read_root,
            "state_write_root": self.state_write_root,
            "determinism_root": self.determinism_root,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    pub receipt_id: String,
    pub intent_id: String,
    pub bundle_id: String,
    pub status: String,
    pub fuel_used: u64,
    pub fee_charged_units: u64,
    pub state_delta_root: String,
    pub event_root: String,
    pub proof_job_root: String,
    pub execution_ms_bucket: u64,
}

impl ExecutionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_id: impl Into<String>,
        bundle_id: impl Into<String>,
        status: impl Into<String>,
        fuel_used: u64,
        fee_charged_units: u64,
        state_delta_root: impl Into<String>,
        event_root: impl Into<String>,
        proof_job_root: impl Into<String>,
        execution_ms_bucket: u64,
    ) -> ExecutionResult<Self> {
        let intent_id = intent_id.into();
        let bundle_id = bundle_id.into();
        let status = status.into();
        let state_delta_root = state_delta_root.into();
        let event_root = event_root.into();
        let proof_job_root = proof_job_root.into();
        ensure_non_empty(&intent_id, "execution receipt intent id")?;
        ensure_non_empty(&bundle_id, "execution receipt bundle id")?;
        ensure_non_empty(&status, "execution receipt status")?;
        ensure_non_empty(&state_delta_root, "execution receipt state delta root")?;
        ensure_non_empty(&event_root, "execution receipt event root")?;
        ensure_non_empty(&proof_job_root, "execution receipt proof job root")?;
        let receipt_id = execution_receipt_id(
            &intent_id,
            &bundle_id,
            &status,
            fuel_used,
            fee_charged_units,
            &state_delta_root,
            &event_root,
            &proof_job_root,
            execution_ms_bucket,
        );
        Ok(Self {
            receipt_id,
            intent_id,
            bundle_id,
            status,
            fuel_used,
            fee_charged_units,
            state_delta_root,
            event_root,
            proof_job_root,
            execution_ms_bucket,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "execution_receipt",
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "intent_id": self.intent_id,
            "bundle_id": self.bundle_id,
            "status": self.status,
            "fuel_used": self.fuel_used,
            "fee_charged_units": self.fee_charged_units,
            "state_delta_root": self.state_delta_root,
            "event_root": self.event_root,
            "proof_job_root": self.proof_job_root,
            "execution_ms_bucket": self.execution_ms_bucket,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionSla {
    pub sla_id: String,
    pub label: String,
    pub target_ms: u64,
    pub max_bundle_ms: u64,
    pub max_queue_depth: u64,
    pub low_fee_max_delay_blocks: u64,
    pub privacy_budget_units: u64,
    pub status: String,
}

impl ExecutionSla {
    pub fn devnet() -> Self {
        let label = "devnet-fast-path".to_string();
        let target_ms = 500;
        let max_bundle_ms = 2_000;
        let max_queue_depth = 10_000;
        let low_fee_max_delay_blocks = 4;
        let privacy_budget_units = 1_000_000;
        let sla_id = execution_sla_id(
            &label,
            target_ms,
            max_bundle_ms,
            max_queue_depth,
            low_fee_max_delay_blocks,
            privacy_budget_units,
        );
        Self {
            sla_id,
            label,
            target_ms,
            max_bundle_ms,
            max_queue_depth,
            low_fee_max_delay_blocks,
            privacy_budget_units,
            status: EXECUTION_STATUS_READY.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "execution_sla",
            "chain_id": CHAIN_ID,
            "sla_id": self.sla_id,
            "label": self.label,
            "target_ms": self.target_ms,
            "max_bundle_ms": self.max_bundle_ms,
            "max_queue_depth": self.max_queue_depth,
            "low_fee_max_delay_blocks": self.low_fee_max_delay_blocks,
            "privacy_budget_units": self.privacy_budget_units,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotStateCacheEntry {
    pub cache_id: String,
    pub domain: String,
    pub key_commitment: String,
    pub value_root: String,
    pub last_read_height: u64,
    pub last_write_height: u64,
    pub read_count: u64,
    pub write_count: u64,
}

impl HotStateCacheEntry {
    pub fn new(
        domain: impl Into<String>,
        key_commitment: impl Into<String>,
        value_root: impl Into<String>,
        height: u64,
    ) -> ExecutionResult<Self> {
        let domain = domain.into();
        let key_commitment = key_commitment.into();
        let value_root = value_root.into();
        ensure_non_empty(&domain, "execution hot cache domain")?;
        ensure_non_empty(&key_commitment, "execution hot cache key commitment")?;
        ensure_non_empty(&value_root, "execution hot cache value root")?;
        let cache_id = hot_state_cache_entry_id(&domain, &key_commitment, &value_root, height);
        Ok(Self {
            cache_id,
            domain,
            key_commitment,
            value_root,
            last_read_height: height,
            last_write_height: height,
            read_count: 0,
            write_count: 0,
        })
    }

    pub fn observe(&mut self, access: &StateAccess, height: u64) {
        match access.mode {
            ExecutionAccessMode::Read => {
                self.read_count = self.read_count.saturating_add(1);
                self.last_read_height = height;
            }
            ExecutionAccessMode::Write => {
                self.write_count = self.write_count.saturating_add(1);
                self.last_write_height = height;
            }
        }
    }

    pub fn hotness_score(&self, height: u64) -> u64 {
        let age = height
            .saturating_sub(self.last_read_height.max(self.last_write_height))
            .max(1);
        self.read_count
            .saturating_add(self.write_count.saturating_mul(2))
            .saturating_mul(10_000)
            / age
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "hot_state_cache_entry",
            "chain_id": CHAIN_ID,
            "cache_id": self.cache_id,
            "domain": self.domain,
            "key_commitment": self.key_commitment,
            "value_root": self.value_root,
            "last_read_height": self.last_read_height,
            "last_write_height": self.last_write_height,
            "read_count": self.read_count,
            "write_count": self.write_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionState {
    pub height: u64,
    pub epoch: u64,
    pub sla: ExecutionSla,
    pub shards: BTreeMap<String, ExecutionShard>,
    pub intents: BTreeMap<String, ExecutionIntent>,
    pub access_sets: BTreeMap<String, Vec<StateAccess>>,
    pub conflicts: BTreeMap<String, ConflictEdge>,
    pub bundles: BTreeMap<String, ExecutionBundle>,
    pub schedules: BTreeMap<String, ExecutionSchedule>,
    pub receipts: BTreeMap<String, ExecutionReceipt>,
    pub hot_cache: BTreeMap<String, HotStateCacheEntry>,
}

impl Default for ExecutionState {
    fn default() -> Self {
        Self {
            height: 0,
            epoch: 0,
            sla: ExecutionSla::devnet(),
            shards: BTreeMap::new(),
            intents: BTreeMap::new(),
            access_sets: BTreeMap::new(),
            conflicts: BTreeMap::new(),
            bundles: BTreeMap::new(),
            schedules: BTreeMap::new(),
            receipts: BTreeMap::new(),
            hot_cache: BTreeMap::new(),
        }
    }
}

impl ExecutionState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn devnet() -> ExecutionResult<Self> {
        let mut state = Self::new();
        for shard in [
            ExecutionShard::new(
                "system",
                ExecutionLane::System,
                vec!["governance".to_string(), "runtime".to_string()],
                1,
                EXECUTION_DEFAULT_BUNDLE_FUEL_LIMIT,
                0,
                0,
            )?,
            ExecutionShard::new(
                "bridge",
                ExecutionLane::Bridge,
                vec!["bridge".to_string(), "settlement".to_string()],
                4,
                EXECUTION_DEFAULT_BUNDLE_FUEL_LIMIT,
                1,
                EXECUTION_DEFAULT_LOW_FEE_CREDIT_UNITS,
            )?,
            ExecutionShard::new(
                "contract",
                ExecutionLane::Contract,
                vec!["contracts".to_string(), "accounts".to_string()],
                EXECUTION_DEFAULT_MAX_PARALLELISM,
                EXECUTION_DEFAULT_BUNDLE_FUEL_LIMIT,
                2,
                0,
            )?,
            ExecutionShard::new(
                "defi",
                ExecutionLane::Defi,
                vec!["defi".to_string(), "oracle".to_string()],
                EXECUTION_DEFAULT_MAX_PARALLELISM,
                EXECUTION_DEFAULT_BUNDLE_FUEL_LIMIT,
                2,
                EXECUTION_DEFAULT_LOW_FEE_CREDIT_UNITS,
            )?,
            ExecutionShard::new(
                "private",
                ExecutionLane::Private,
                vec!["privacy".to_string(), "notes".to_string()],
                8,
                EXECUTION_DEFAULT_BUNDLE_FUEL_LIMIT / 2,
                1,
                EXECUTION_DEFAULT_LOW_FEE_CREDIT_UNITS,
            )?,
            ExecutionShard::new(
                "low-fee",
                ExecutionLane::LowFee,
                vec!["fees".to_string(), "mempool".to_string()],
                8,
                EXECUTION_DEFAULT_BUNDLE_FUEL_LIMIT / 2,
                0,
                EXECUTION_DEFAULT_LOW_FEE_CREDIT_UNITS.saturating_mul(2),
            )?,
        ] {
            state.register_shard(shard)?;
        }
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        self.epoch = height / 16;
    }

    pub fn register_shard(&mut self, shard: ExecutionShard) -> ExecutionResult<String> {
        if self
            .shards
            .values()
            .any(|existing| existing.label == shard.label && existing.shard_id != shard.shard_id)
        {
            return Err("execution shard label already registered".to_string());
        }
        let shard_id = shard.shard_id.clone();
        self.shards.insert(shard_id.clone(), shard);
        Ok(shard_id)
    }

    pub fn submit_intent(
        &mut self,
        intent: ExecutionIntent,
        accesses: Vec<StateAccess>,
    ) -> ExecutionResult<String> {
        if intent.is_expired(self.height) {
            return Err("execution intent is expired".to_string());
        }
        if accesses.len() > EXECUTION_MAX_ACCESS_SET_ITEMS {
            return Err("execution access set too large".to_string());
        }
        if intent.access_root != state_access_root(&accesses) {
            return Err("execution intent access root mismatch".to_string());
        }
        for access in &accesses {
            self.observe_cache(access)?;
        }
        let intent_id = intent.intent_id.clone();
        self.access_sets.insert(intent_id.clone(), accesses);
        self.intents.insert(intent_id.clone(), intent);
        Ok(intent_id)
    }

    pub fn detect_conflicts(&self, intent_ids: &[String]) -> ExecutionResult<Vec<ConflictEdge>> {
        let mut edges = BTreeMap::new();
        for (left_index, left_id) in intent_ids.iter().enumerate() {
            for right_id in intent_ids.iter().skip(left_index + 1) {
                let left_accesses = self
                    .access_sets
                    .get(left_id)
                    .ok_or_else(|| format!("missing access set for intent {left_id}"))?;
                let right_accesses = self
                    .access_sets
                    .get(right_id)
                    .ok_or_else(|| format!("missing access set for intent {right_id}"))?;
                for left in left_accesses {
                    for right in right_accesses {
                        if let Some(kind) = left.conflicts_with(right) {
                            let edge = ConflictEdge::new(
                                left_id,
                                right_id,
                                kind,
                                &[left.clone(), right.clone()],
                                &json!({
                                    "left_access_id": left.access_id,
                                    "right_access_id": right.access_id,
                                    "domain": left.domain,
                                    "key_commitment": left.key_commitment,
                                }),
                            )?;
                            edges.insert(edge.edge_id.clone(), edge);
                        }
                    }
                }
            }
        }
        Ok(edges.into_values().collect())
    }

    pub fn plan_schedule(&mut self, height: u64) -> ExecutionResult<ExecutionSchedule> {
        self.set_height(height);
        let mut pending = self
            .intents
            .values()
            .filter(|intent| intent.status == EXECUTION_STATUS_PENDING)
            .cloned()
            .collect::<Vec<_>>();
        pending.sort_by(|left, right| {
            right
                .effective_priority()
                .cmp(&left.effective_priority())
                .then_with(|| left.intent_id.cmp(&right.intent_id))
        });

        let expired_ids = pending
            .iter()
            .filter(|intent| intent.is_expired(height))
            .map(|intent| intent.intent_id.clone())
            .collect::<Vec<_>>();
        for intent_id in expired_ids {
            if let Some(intent) = self.intents.get_mut(&intent_id) {
                intent.status = EXECUTION_STATUS_EXPIRED.to_string();
            }
        }

        let live = pending
            .into_iter()
            .filter(|intent| !intent.is_expired(height))
            .collect::<Vec<_>>();
        let live_ids = live
            .iter()
            .map(|intent| intent.intent_id.clone())
            .collect::<Vec<_>>();
        let conflicts = self.detect_conflicts(&live_ids)?;
        for conflict in &conflicts {
            self.conflicts
                .insert(conflict.edge_id.clone(), conflict.clone());
        }

        let conflict_members = conflicts
            .iter()
            .flat_map(|conflict| {
                [
                    conflict.left_intent_id.clone(),
                    conflict.right_intent_id.clone(),
                ]
            })
            .collect::<BTreeSet<_>>();

        let mut bundles = Vec::new();
        let mut read_keys = BTreeSet::new();
        let mut write_keys = BTreeSet::new();
        let shards = self.shards.values().cloned().collect::<Vec<_>>();
        for shard in &shards {
            let mut shard_intents = Vec::new();
            let mut shard_fuel = 0_u64;
            for intent in &live {
                if !shard.accepts(intent) {
                    continue;
                }
                if conflict_members.contains(&intent.intent_id)
                    && intent.class.prefers_parallelism()
                    && shard.max_parallelism > 1
                {
                    continue;
                }
                if shard_fuel.saturating_add(intent.fuel_limit) > shard.bundle_fuel_limit {
                    continue;
                }
                if intent.fee_units.saturating_add(intent.low_fee_credit_units)
                    < shard.fee_floor_units
                {
                    continue;
                }
                shard_fuel = shard_fuel.saturating_add(intent.fuel_limit);
                shard_intents.push(intent.clone());
                if shard_intents.len() as u64 >= shard.max_parallelism {
                    break;
                }
            }
            if shard_intents.is_empty() {
                continue;
            }
            let mut accesses = Vec::new();
            for intent in &shard_intents {
                for access in self
                    .access_sets
                    .get(&intent.intent_id)
                    .into_iter()
                    .flatten()
                {
                    match access.mode {
                        ExecutionAccessMode::Read => {
                            read_keys
                                .insert(format!("{}:{}", access.domain, access.key_commitment));
                        }
                        ExecutionAccessMode::Write => {
                            write_keys
                                .insert(format!("{}:{}", access.domain, access.key_commitment));
                        }
                    }
                    accesses.push(access.clone());
                }
            }
            let intent_ids = shard_intents
                .iter()
                .map(|intent| intent.intent_id.clone())
                .collect::<BTreeSet<_>>();
            let bundle_conflicts = conflicts
                .iter()
                .filter(|conflict| {
                    intent_ids.contains(&conflict.left_intent_id)
                        || intent_ids.contains(&conflict.right_intent_id)
                })
                .cloned()
                .collect::<Vec<_>>();
            let bundle =
                ExecutionBundle::new(height, shard, &shard_intents, &accesses, &bundle_conflicts)?;
            for intent in &shard_intents {
                if let Some(existing) = self.intents.get_mut(&intent.intent_id) {
                    existing.status = EXECUTION_STATUS_READY.to_string();
                }
            }
            self.bundles
                .insert(bundle.bundle_id.clone(), bundle.clone());
            bundles.push(bundle);
        }

        let reads = read_keys.into_iter().collect::<Vec<_>>();
        let writes = write_keys.into_iter().collect::<Vec<_>>();
        let schedule = ExecutionSchedule::new(
            height,
            self.epoch,
            &bundles,
            &conflicts,
            &shards,
            &reads,
            &writes,
            height.saturating_add(EXECUTION_DEFAULT_SCHEDULE_TTL_BLOCKS),
        )?;
        self.schedules
            .insert(schedule.schedule_id.clone(), schedule.clone());
        Ok(schedule)
    }

    pub fn record_receipt(&mut self, receipt: ExecutionReceipt) -> ExecutionResult<String> {
        if !self.bundles.contains_key(&receipt.bundle_id) {
            return Err("execution receipt references unknown bundle".to_string());
        }
        if let Some(intent) = self.intents.get_mut(&receipt.intent_id) {
            intent.status = receipt.status.clone();
        }
        let receipt_id = receipt.receipt_id.clone();
        self.receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn pending_count(&self) -> u64 {
        self.intents
            .values()
            .filter(|intent| intent.status == EXECUTION_STATUS_PENDING)
            .count() as u64
    }

    pub fn ready_count(&self) -> u64 {
        self.intents
            .values()
            .filter(|intent| intent.status == EXECUTION_STATUS_READY)
            .count() as u64
    }

    pub fn execution_pressure_bps(&self) -> u64 {
        let queue = self.pending_count().saturating_add(self.ready_count());
        if self.sla.max_queue_depth == 0 {
            return 10_000;
        }
        queue
            .saturating_mul(10_000)
            .saturating_div(self.sla.max_queue_depth)
            .min(10_000)
    }

    pub fn state_root(&self) -> String {
        execution_state_root_from_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "execution_state",
            "chain_id": CHAIN_ID,
            "protocol_version": EXECUTION_PROTOCOL_VERSION,
            "height": self.height,
            "epoch": self.epoch,
            "sla": self.sla.public_record(),
            "shard_root": execution_shard_root_from_map(&self.shards),
            "intent_root": execution_intent_root_from_map(&self.intents),
            "conflict_root": conflict_edge_root_from_map(&self.conflicts),
            "bundle_root": execution_bundle_root_from_map(&self.bundles),
            "schedule_root": execution_schedule_root_from_map(&self.schedules),
            "receipt_root": execution_receipt_root_from_map(&self.receipts),
            "hot_cache_root": hot_state_cache_entry_root_from_map(&self.hot_cache),
            "pending_count": self.pending_count(),
            "ready_count": self.ready_count(),
            "execution_pressure_bps": self.execution_pressure_bps(),
        })
    }

    fn observe_cache(&mut self, access: &StateAccess) -> ExecutionResult<()> {
        let cache_key = format!("{}:{}", access.domain, access.key_commitment);
        if let Some(entry) = self.hot_cache.get_mut(&cache_key) {
            entry.observe(access, self.height);
            return Ok(());
        }
        let mut entry = HotStateCacheEntry::new(
            access.domain.clone(),
            access.key_commitment.clone(),
            execution_payload_root("EXECUTION-HOT-CACHE-EMPTY", &json!({})),
            self.height,
        )?;
        entry.observe(access, self.height);
        self.hot_cache.insert(cache_key, entry);
        Ok(())
    }
}

pub fn state_access_id(
    tx_id: &str,
    domain: &str,
    key_commitment: &str,
    mode: ExecutionAccessMode,
    ordinal: u64,
) -> String {
    domain_hash(
        "EXECUTION-STATE-ACCESS-ID",
        &[
            HashPart::Str(tx_id),
            HashPart::Str(domain),
            HashPart::Str(key_commitment),
            HashPart::Str(mode.as_str()),
            HashPart::Int(ordinal as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn execution_intent_id(
    tx_id: &str,
    lane: &ExecutionLane,
    class: &ExecutionClass,
    fee_units: u64,
    low_fee_credit_units: u64,
    fuel_limit: u64,
    priority: u64,
    quantum_auth_root: &str,
    privacy_root: &str,
    access_root: &str,
    submitted_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "EXECUTION-INTENT-ID",
        &[
            HashPart::Str(tx_id),
            HashPart::Str(&lane.as_str()),
            HashPart::Str(&class.as_str()),
            HashPart::Int(fee_units as i128),
            HashPart::Int(low_fee_credit_units as i128),
            HashPart::Int(fuel_limit as i128),
            HashPart::Int(priority as i128),
            HashPart::Str(quantum_auth_root),
            HashPart::Str(privacy_root),
            HashPart::Str(access_root),
            HashPart::Int(submitted_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn execution_shard_id(
    label: &str,
    lane: &ExecutionLane,
    state_domain_root: &str,
    max_parallelism: u64,
    bundle_fuel_limit: u64,
    fee_floor_units: u64,
    low_fee_credit_units: u64,
) -> String {
    domain_hash(
        "EXECUTION-SHARD-ID",
        &[
            HashPart::Str(label),
            HashPart::Str(&lane.as_str()),
            HashPart::Str(state_domain_root),
            HashPart::Int(max_parallelism as i128),
            HashPart::Int(bundle_fuel_limit as i128),
            HashPart::Int(fee_floor_units as i128),
            HashPart::Int(low_fee_credit_units as i128),
        ],
        32,
    )
}

pub fn conflict_edge_id(
    left_intent_id: &str,
    right_intent_id: &str,
    conflict_kind: &ExecutionConflictKind,
    access_root: &str,
    reason_root: &str,
) -> String {
    domain_hash(
        "EXECUTION-CONFLICT-EDGE-ID",
        &[
            HashPart::Str(left_intent_id),
            HashPart::Str(right_intent_id),
            HashPart::Str(&conflict_kind.as_str()),
            HashPart::Str(access_root),
            HashPart::Str(reason_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn execution_bundle_id(
    height: u64,
    shard_id: &str,
    lane: &ExecutionLane,
    intent_ids: &[String],
    access_root: &str,
    conflict_root: &str,
    total_fuel_limit: u64,
    total_fee_units: u64,
    low_fee_credit_units: u64,
    privacy_root: &str,
) -> String {
    domain_hash(
        "EXECUTION-BUNDLE-ID",
        &[
            HashPart::Int(height as i128),
            HashPart::Str(shard_id),
            HashPart::Str(&lane.as_str()),
            HashPart::Str(&execution_string_set_root(
                "EXECUTION-BUNDLE-ID-INTENTS",
                intent_ids,
            )),
            HashPart::Str(access_root),
            HashPart::Str(conflict_root),
            HashPart::Int(total_fuel_limit as i128),
            HashPart::Int(total_fee_units as i128),
            HashPart::Int(low_fee_credit_units as i128),
            HashPart::Str(privacy_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn execution_schedule_id(
    height: u64,
    epoch: u64,
    bundle_root: &str,
    conflict_root: &str,
    shard_root: &str,
    total_intents: u64,
    parallel_width: u64,
    state_read_root: &str,
    state_write_root: &str,
    determinism_root: &str,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "EXECUTION-SCHEDULE-ID",
        &[
            HashPart::Int(height as i128),
            HashPart::Int(epoch as i128),
            HashPart::Str(bundle_root),
            HashPart::Str(conflict_root),
            HashPart::Str(shard_root),
            HashPart::Int(total_intents as i128),
            HashPart::Int(parallel_width as i128),
            HashPart::Str(state_read_root),
            HashPart::Str(state_write_root),
            HashPart::Str(determinism_root),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn execution_receipt_id(
    intent_id: &str,
    bundle_id: &str,
    status: &str,
    fuel_used: u64,
    fee_charged_units: u64,
    state_delta_root: &str,
    event_root: &str,
    proof_job_root: &str,
    execution_ms_bucket: u64,
) -> String {
    domain_hash(
        "EXECUTION-RECEIPT-ID",
        &[
            HashPart::Str(intent_id),
            HashPart::Str(bundle_id),
            HashPart::Str(status),
            HashPart::Int(fuel_used as i128),
            HashPart::Int(fee_charged_units as i128),
            HashPart::Str(state_delta_root),
            HashPart::Str(event_root),
            HashPart::Str(proof_job_root),
            HashPart::Int(execution_ms_bucket as i128),
        ],
        32,
    )
}

pub fn execution_sla_id(
    label: &str,
    target_ms: u64,
    max_bundle_ms: u64,
    max_queue_depth: u64,
    low_fee_max_delay_blocks: u64,
    privacy_budget_units: u64,
) -> String {
    domain_hash(
        "EXECUTION-SLA-ID",
        &[
            HashPart::Str(label),
            HashPart::Int(target_ms as i128),
            HashPart::Int(max_bundle_ms as i128),
            HashPart::Int(max_queue_depth as i128),
            HashPart::Int(low_fee_max_delay_blocks as i128),
            HashPart::Int(privacy_budget_units as i128),
        ],
        32,
    )
}

pub fn hot_state_cache_entry_id(
    domain: &str,
    key_commitment: &str,
    value_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "EXECUTION-HOT-STATE-CACHE-ENTRY-ID",
        &[
            HashPart::Str(domain),
            HashPart::Str(key_commitment),
            HashPart::Str(value_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn execution_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn execution_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(value)], 32)
}

pub fn execution_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn state_access_root(values: &[StateAccess]) -> String {
    let leaves = values
        .iter()
        .map(StateAccess::public_record)
        .collect::<Vec<_>>();
    merkle_root("EXECUTION-STATE-ACCESS-ROOT", &leaves)
}

pub fn execution_intent_root(values: &[ExecutionIntent]) -> String {
    let leaves = values
        .iter()
        .map(ExecutionIntent::public_record)
        .collect::<Vec<_>>();
    merkle_root("EXECUTION-INTENT-ROOT", &leaves)
}

pub fn execution_shard_root(values: &[ExecutionShard]) -> String {
    let leaves = values
        .iter()
        .map(ExecutionShard::public_record)
        .collect::<Vec<_>>();
    merkle_root("EXECUTION-SHARD-ROOT", &leaves)
}

pub fn conflict_edge_root(values: &[ConflictEdge]) -> String {
    let leaves = values
        .iter()
        .map(ConflictEdge::public_record)
        .collect::<Vec<_>>();
    merkle_root("EXECUTION-CONFLICT-EDGE-ROOT", &leaves)
}

pub fn execution_bundle_root(values: &[ExecutionBundle]) -> String {
    let leaves = values
        .iter()
        .map(ExecutionBundle::public_record)
        .collect::<Vec<_>>();
    merkle_root("EXECUTION-BUNDLE-ROOT", &leaves)
}

pub fn execution_schedule_root(values: &[ExecutionSchedule]) -> String {
    let leaves = values
        .iter()
        .map(ExecutionSchedule::public_record)
        .collect::<Vec<_>>();
    merkle_root("EXECUTION-SCHEDULE-ROOT", &leaves)
}

pub fn execution_receipt_root(values: &[ExecutionReceipt]) -> String {
    let leaves = values
        .iter()
        .map(ExecutionReceipt::public_record)
        .collect::<Vec<_>>();
    merkle_root("EXECUTION-RECEIPT-ROOT", &leaves)
}

pub fn hot_state_cache_entry_root(values: &[HotStateCacheEntry]) -> String {
    let leaves = values
        .iter()
        .map(HotStateCacheEntry::public_record)
        .collect::<Vec<_>>();
    merkle_root("EXECUTION-HOT-STATE-CACHE-ROOT", &leaves)
}

pub fn execution_intent_root_from_map(values: &BTreeMap<String, ExecutionIntent>) -> String {
    execution_intent_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn execution_shard_root_from_map(values: &BTreeMap<String, ExecutionShard>) -> String {
    execution_shard_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn conflict_edge_root_from_map(values: &BTreeMap<String, ConflictEdge>) -> String {
    conflict_edge_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn execution_bundle_root_from_map(values: &BTreeMap<String, ExecutionBundle>) -> String {
    execution_bundle_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn execution_schedule_root_from_map(values: &BTreeMap<String, ExecutionSchedule>) -> String {
    execution_schedule_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn execution_receipt_root_from_map(values: &BTreeMap<String, ExecutionReceipt>) -> String {
    execution_receipt_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn hot_state_cache_entry_root_from_map(
    values: &BTreeMap<String, HotStateCacheEntry>,
) -> String {
    hot_state_cache_entry_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn execution_state_root_from_record(record: &Value) -> String {
    execution_payload_root("EXECUTION-STATE-ROOT", record)
}

fn ensure_non_empty(value: &str, field: &str) -> ExecutionResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, field: &str) -> ExecutionResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_unique_strings(values: &[String], field: &str) -> ExecutionResult<()> {
    if values.is_empty() {
        return Err(format!("{field} cannot be empty"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, field)?;
        if !seen.insert(value) {
            return Err(format!("{field} contains duplicate value"));
        }
    }
    Ok(())
}
