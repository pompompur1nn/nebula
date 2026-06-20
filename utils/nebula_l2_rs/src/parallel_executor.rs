use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ParallelExecutorResult<T> = Result<T, String>;

pub const PARALLEL_EXECUTOR_PROTOCOL_VERSION: &str = "nebula-l2-parallel-executor-v1";
pub const PARALLEL_EXECUTOR_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const PARALLEL_EXECUTOR_LOCK_LEASE_SCHEME: &str = "deterministic-state-lock-lease-v1";
pub const PARALLEL_EXECUTOR_PRIVATE_SCHEDULING_POLICY: &str =
    "commitment-only-private-payload-scheduling-v1";
pub const PARALLEL_EXECUTOR_DEFAULT_WORKERS: u64 = 16;
pub const PARALLEL_EXECUTOR_MAX_WORKERS: u64 = 256;
pub const PARALLEL_EXECUTOR_DEFAULT_LANE_FUEL_LIMIT: u64 = 12_000_000;
pub const PARALLEL_EXECUTOR_DEFAULT_SCHEDULE_TTL_BLOCKS: u64 = 4;
pub const PARALLEL_EXECUTOR_DEFAULT_LOCK_TTL_BLOCKS: u64 = 2;
pub const PARALLEL_EXECUTOR_DEFAULT_RETRY_BASE_BLOCKS: u64 = 1;
pub const PARALLEL_EXECUTOR_DEFAULT_RETRY_MAX_BLOCKS: u64 = 32;
pub const PARALLEL_EXECUTOR_DEFAULT_MAX_RETRIES: u64 = 5;
pub const PARALLEL_EXECUTOR_DEFAULT_LOW_FEE_RESERVED_WORKERS: u64 = 2;
pub const PARALLEL_EXECUTOR_DEFAULT_LOW_FEE_BOOST: u64 = 125_000;
pub const PARALLEL_EXECUTOR_DEFAULT_OPTIMISTIC_RETRY_LIMIT: u64 = 2;
pub const PARALLEL_EXECUTOR_DEFAULT_EPOCH_BLOCKS: u64 = 16;
pub const PARALLEL_EXECUTOR_MAX_ACCESS_LIST_ITEMS: usize = 512;
pub const PARALLEL_EXECUTOR_MAX_SCHEDULE_INTENTS: usize = 4_096;
pub const PARALLEL_EXECUTOR_STATUS_ACTIVE: &str = "active";
pub const PARALLEL_EXECUTOR_STATUS_PENDING: &str = "pending";
pub const PARALLEL_EXECUTOR_STATUS_READY: &str = "ready";
pub const PARALLEL_EXECUTOR_STATUS_EXECUTING: &str = "executing";
pub const PARALLEL_EXECUTOR_STATUS_APPLIED: &str = "applied";
pub const PARALLEL_EXECUTOR_STATUS_REVERTED: &str = "reverted";
pub const PARALLEL_EXECUTOR_STATUS_RETRYING: &str = "retrying";
pub const PARALLEL_EXECUTOR_STATUS_DEFERRED: &str = "deferred";
pub const PARALLEL_EXECUTOR_STATUS_EXPIRED: &str = "expired";
pub const PARALLEL_EXECUTOR_STATUS_RELEASED: &str = "released";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParallelAccessMode {
    Read,
    Write,
}

impl ParallelAccessMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }

    pub fn is_write(self) -> bool {
        matches!(self, Self::Write)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ParallelLaneKind {
    System,
    Bridge,
    Oracle,
    PrivatePayload,
    LowFeePriority,
    Defi,
    Contract,
    Transfer,
    Prover,
    Optimistic,
    Background,
    Custom(String),
}

impl ParallelLaneKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::System => "system".to_string(),
            Self::Bridge => "bridge".to_string(),
            Self::Oracle => "oracle".to_string(),
            Self::PrivatePayload => "private_payload".to_string(),
            Self::LowFeePriority => "low_fee_priority".to_string(),
            Self::Defi => "defi".to_string(),
            Self::Contract => "contract".to_string(),
            Self::Transfer => "transfer".to_string(),
            Self::Prover => "prover".to_string(),
            Self::Optimistic => "optimistic".to_string(),
            Self::Background => "background".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }

    pub fn default_priority(&self) -> u64 {
        match self {
            Self::System => 1_000_000,
            Self::Bridge => 900_000,
            Self::Oracle => 820_000,
            Self::Prover => 760_000,
            Self::Defi => 650_000,
            Self::Contract => 560_000,
            Self::PrivatePayload => 520_000,
            Self::Transfer => 440_000,
            Self::LowFeePriority => 400_000,
            Self::Optimistic => 320_000,
            Self::Background => 100_000,
            Self::Custom(_) => 180_000,
        }
    }

    pub fn is_low_fee(&self) -> bool {
        matches!(self, Self::LowFeePriority | Self::PrivatePayload)
    }

    pub fn is_private(&self) -> bool {
        matches!(self, Self::PrivatePayload)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParallelPayloadVisibility {
    Public,
    CommitmentOnly,
    Encrypted,
    Shielded,
}

impl ParallelPayloadVisibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::CommitmentOnly => "commitment_only",
            Self::Encrypted => "encrypted",
            Self::Shielded => "shielded",
        }
    }

    pub fn is_private(self) -> bool {
        !matches!(self, Self::Public)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ParallelConflictKind {
    WriteWrite,
    ReadWrite,
    LeaseOverlap,
    PrivateHintOverlap,
    WorkerCapacity,
    FuelCapacity,
    ExpiredIntent,
    RetryBackoff,
    Custom(String),
}

impl ParallelConflictKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::WriteWrite => "write_write".to_string(),
            Self::ReadWrite => "read_write".to_string(),
            Self::LeaseOverlap => "lease_overlap".to_string(),
            Self::PrivateHintOverlap => "private_hint_overlap".to_string(),
            Self::WorkerCapacity => "worker_capacity".to_string(),
            Self::FuelCapacity => "fuel_capacity".to_string(),
            Self::ExpiredIntent => "expired_intent".to_string(),
            Self::RetryBackoff => "retry_backoff".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RetryBackoffReason {
    Conflict,
    LeaseBusy,
    ValidationFailed,
    WorkerTimeout,
    LowFeeDelayed,
    PrivatePayloadAwaitingProof,
    Custom(String),
}

impl RetryBackoffReason {
    pub fn as_str(&self) -> String {
        match self {
            Self::Conflict => "conflict".to_string(),
            Self::LeaseBusy => "lease_busy".to_string(),
            Self::ValidationFailed => "validation_failed".to_string(),
            Self::WorkerTimeout => "worker_timeout".to_string(),
            Self::LowFeeDelayed => "low_fee_delayed".to_string(),
            Self::PrivatePayloadAwaitingProof => "private_payload_awaiting_proof".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateLeaseMode {
    SharedRead,
    ExclusiveWrite,
}

impl StateLeaseMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SharedRead => "shared_read",
            Self::ExclusiveWrite => "exclusive_write",
        }
    }

    pub fn conflicts_with(self, other: Self) -> bool {
        matches!(
            (self, other),
            (Self::ExclusiveWrite, _) | (_, Self::ExclusiveWrite)
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub policy_id: String,
    pub base_delay_blocks: u64,
    pub max_delay_blocks: u64,
    pub max_retries: u64,
    pub conflict_multiplier_bps: u64,
    pub low_fee_grace_blocks: u64,
    pub jitter_salt: String,
    pub status: String,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        let mut policy = Self {
            policy_id: String::new(),
            base_delay_blocks: PARALLEL_EXECUTOR_DEFAULT_RETRY_BASE_BLOCKS,
            max_delay_blocks: PARALLEL_EXECUTOR_DEFAULT_RETRY_MAX_BLOCKS,
            max_retries: PARALLEL_EXECUTOR_DEFAULT_MAX_RETRIES,
            conflict_multiplier_bps: 15_000,
            low_fee_grace_blocks: 1,
            jitter_salt: "parallel-executor-devnet".to_string(),
            status: PARALLEL_EXECUTOR_STATUS_ACTIVE.to_string(),
        };
        policy.policy_id = retry_policy_id(&policy.identity_record());
        policy
    }
}

impl RetryPolicy {
    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "parallel_retry_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": PARALLEL_EXECUTOR_PROTOCOL_VERSION,
            "base_delay_blocks": self.base_delay_blocks,
            "max_delay_blocks": self.max_delay_blocks,
            "max_retries": self.max_retries,
            "conflict_multiplier_bps": self.conflict_multiplier_bps,
            "low_fee_grace_blocks": self.low_fee_grace_blocks,
            "jitter_salt": self.jitter_salt,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("parallel retry policy public record object");
        object.insert(
            "policy_id".to_string(),
            Value::String(self.policy_id.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        object.insert("policy_root".to_string(), Value::String(self.policy_root()));
        record
    }

    pub fn policy_root(&self) -> String {
        parallel_payload_root("PARALLEL-RETRY-POLICY", &self.identity_record())
    }

    pub fn delay_blocks(&self, intent_id: &str, attempt: u64, reason: &RetryBackoffReason) -> u64 {
        let mut shifted = self.base_delay_blocks;
        for _ in 0..attempt.min(63) {
            shifted = shifted.saturating_mul(2);
        }
        let multiplied = match reason {
            RetryBackoffReason::Conflict | RetryBackoffReason::LeaseBusy => shifted
                .saturating_mul(self.conflict_multiplier_bps)
                .saturating_div(10_000),
            RetryBackoffReason::LowFeeDelayed => shifted.saturating_add(self.low_fee_grace_blocks),
            _ => shifted,
        };
        let jitter = stable_mod(
            &domain_hash(
                "PARALLEL-RETRY-JITTER",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(&self.jitter_salt),
                    HashPart::Str(intent_id),
                    HashPart::Int(attempt as i128),
                    HashPart::Str(&reason.as_str()),
                ],
                32,
            ),
            self.base_delay_blocks.saturating_add(1),
        );
        multiplied
            .saturating_add(jitter)
            .max(1)
            .min(self.max_delay_blocks.max(1))
    }

    pub fn validate(&self) -> ParallelExecutorResult<String> {
        ensure_non_empty(&self.policy_id, "retry policy id")?;
        ensure_positive(self.base_delay_blocks, "retry policy base delay")?;
        ensure_positive(self.max_delay_blocks, "retry policy max delay")?;
        if self.max_delay_blocks < self.base_delay_blocks {
            return Err("retry policy max delay cannot be below base delay".to_string());
        }
        ensure_non_empty(&self.jitter_salt, "retry policy jitter salt")?;
        Ok(self.policy_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParallelExecutorConfig {
    pub config_id: String,
    pub worker_count: u64,
    pub lane_fuel_limit: u64,
    pub max_schedule_intents: u64,
    pub schedule_ttl_blocks: u64,
    pub lock_ttl_blocks: u64,
    pub low_fee_reserved_workers: u64,
    pub low_fee_priority_boost: u64,
    pub optimistic_retry_limit: u64,
    pub private_payload_safe_mode: bool,
    pub scheduler_pq_scheme: String,
    pub determinism_seed: String,
    pub retry_policy: RetryPolicy,
}

impl Default for ParallelExecutorConfig {
    fn default() -> Self {
        Self::devnet()
    }
}

impl ParallelExecutorConfig {
    pub fn devnet() -> Self {
        let mut config = Self {
            config_id: String::new(),
            worker_count: PARALLEL_EXECUTOR_DEFAULT_WORKERS,
            lane_fuel_limit: PARALLEL_EXECUTOR_DEFAULT_LANE_FUEL_LIMIT,
            max_schedule_intents: PARALLEL_EXECUTOR_MAX_SCHEDULE_INTENTS as u64,
            schedule_ttl_blocks: PARALLEL_EXECUTOR_DEFAULT_SCHEDULE_TTL_BLOCKS,
            lock_ttl_blocks: PARALLEL_EXECUTOR_DEFAULT_LOCK_TTL_BLOCKS,
            low_fee_reserved_workers: PARALLEL_EXECUTOR_DEFAULT_LOW_FEE_RESERVED_WORKERS,
            low_fee_priority_boost: PARALLEL_EXECUTOR_DEFAULT_LOW_FEE_BOOST,
            optimistic_retry_limit: PARALLEL_EXECUTOR_DEFAULT_OPTIMISTIC_RETRY_LIMIT,
            private_payload_safe_mode: true,
            scheduler_pq_scheme: PARALLEL_EXECUTOR_PQ_SIGNATURE_SCHEME.to_string(),
            determinism_seed: "nebula-parallel-executor-devnet".to_string(),
            retry_policy: RetryPolicy::default(),
        };
        config.config_id = parallel_executor_config_id(&config.identity_record());
        config
    }

    pub fn worker_count_usize(&self) -> usize {
        self.worker_count.max(1).min(PARALLEL_EXECUTOR_MAX_WORKERS) as usize
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "parallel_executor_config",
            "chain_id": CHAIN_ID,
            "protocol_version": PARALLEL_EXECUTOR_PROTOCOL_VERSION,
            "worker_count": self.worker_count,
            "lane_fuel_limit": self.lane_fuel_limit,
            "max_schedule_intents": self.max_schedule_intents,
            "schedule_ttl_blocks": self.schedule_ttl_blocks,
            "lock_ttl_blocks": self.lock_ttl_blocks,
            "low_fee_reserved_workers": self.low_fee_reserved_workers,
            "low_fee_priority_boost": self.low_fee_priority_boost,
            "optimistic_retry_limit": self.optimistic_retry_limit,
            "private_payload_safe_mode": self.private_payload_safe_mode,
            "private_scheduling_policy": PARALLEL_EXECUTOR_PRIVATE_SCHEDULING_POLICY,
            "scheduler_pq_scheme": self.scheduler_pq_scheme,
            "determinism_seed": self.determinism_seed,
            "retry_policy_root": self.retry_policy.policy_root(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("parallel config public record object");
        object.insert(
            "config_id".to_string(),
            Value::String(self.config_id.clone()),
        );
        object.insert("config_root".to_string(), Value::String(self.config_root()));
        object.insert(
            "retry_policy".to_string(),
            self.retry_policy.public_record(),
        );
        record
    }

    pub fn config_root(&self) -> String {
        parallel_payload_root("PARALLEL-EXECUTOR-CONFIG", &self.identity_record())
    }

    pub fn validate(&self) -> ParallelExecutorResult<String> {
        ensure_non_empty(&self.config_id, "parallel executor config id")?;
        ensure_positive(self.worker_count, "parallel executor worker count")?;
        if self.worker_count > PARALLEL_EXECUTOR_MAX_WORKERS {
            return Err("parallel executor worker count exceeds max".to_string());
        }
        ensure_positive(self.lane_fuel_limit, "parallel executor lane fuel limit")?;
        ensure_positive(
            self.max_schedule_intents,
            "parallel executor max schedule intents",
        )?;
        ensure_positive(
            self.schedule_ttl_blocks,
            "parallel executor schedule ttl blocks",
        )?;
        ensure_positive(self.lock_ttl_blocks, "parallel executor lock ttl blocks")?;
        ensure_non_empty(
            &self.scheduler_pq_scheme,
            "parallel executor scheduler pq scheme",
        )?;
        ensure_non_empty(&self.determinism_seed, "parallel executor seed")?;
        self.retry_policy.validate()?;
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateAccessItem {
    pub access_id: String,
    pub intent_id: String,
    pub tx_id: String,
    pub state_domain: String,
    pub key_commitment: String,
    pub mode: ParallelAccessMode,
    pub ordinal: u64,
    pub visibility: ParallelPayloadVisibility,
    pub hot_hint: bool,
    pub private_hint_root: String,
}

impl StateAccessItem {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_id: impl Into<String>,
        tx_id: impl Into<String>,
        state_domain: impl Into<String>,
        key_commitment: impl Into<String>,
        mode: ParallelAccessMode,
        ordinal: u64,
        visibility: ParallelPayloadVisibility,
        hot_hint: bool,
        private_hint_root: impl Into<String>,
    ) -> ParallelExecutorResult<Self> {
        let intent_id = intent_id.into();
        let tx_id = tx_id.into();
        let state_domain = state_domain.into();
        let key_commitment = key_commitment.into();
        let private_hint_root = private_hint_root.into();
        ensure_non_empty(&intent_id, "state access intent id")?;
        ensure_non_empty(&tx_id, "state access tx id")?;
        ensure_non_empty(&state_domain, "state access domain")?;
        ensure_non_empty(&key_commitment, "state access key commitment")?;
        if visibility.is_private() {
            ensure_non_empty(&private_hint_root, "state access private hint root")?;
        }
        let access_id = state_access_item_id(
            &intent_id,
            &tx_id,
            &state_domain,
            &key_commitment,
            mode,
            ordinal,
            visibility,
            &private_hint_root,
        );
        Ok(Self {
            access_id,
            intent_id,
            tx_id,
            state_domain,
            key_commitment,
            mode,
            ordinal,
            visibility,
            hot_hint,
            private_hint_root,
        })
    }

    pub fn conflict_key(&self) -> String {
        format!("{}:{}", self.state_domain, self.key_commitment)
    }

    pub fn lease_mode(&self) -> StateLeaseMode {
        if self.mode.is_write() {
            StateLeaseMode::ExclusiveWrite
        } else {
            StateLeaseMode::SharedRead
        }
    }

    pub fn conflicts_with(&self, other: &Self) -> Option<ParallelConflictKind> {
        if self.intent_id == other.intent_id {
            return None;
        }
        if self.state_domain == other.state_domain && self.key_commitment == other.key_commitment {
            match (self.mode, other.mode) {
                (ParallelAccessMode::Write, ParallelAccessMode::Write) => {
                    return Some(ParallelConflictKind::WriteWrite);
                }
                (ParallelAccessMode::Write, ParallelAccessMode::Read)
                | (ParallelAccessMode::Read, ParallelAccessMode::Write) => {
                    return Some(ParallelConflictKind::ReadWrite);
                }
                _ => {}
            }
        }
        if self.visibility.is_private()
            && other.visibility.is_private()
            && !self.private_hint_root.is_empty()
            && self.private_hint_root == other.private_hint_root
        {
            return Some(ParallelConflictKind::PrivateHintOverlap);
        }
        None
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "parallel_state_access",
            "chain_id": CHAIN_ID,
            "protocol_version": PARALLEL_EXECUTOR_PROTOCOL_VERSION,
            "access_id": self.access_id,
            "intent_id": self.intent_id,
            "tx_id": self.tx_id,
            "state_domain": self.state_domain,
            "key_commitment": self.key_commitment,
            "mode": self.mode.as_str(),
            "ordinal": self.ordinal,
            "visibility": self.visibility.as_str(),
            "hot_hint": self.hot_hint,
            "private_hint_root": self.private_hint_root,
        })
    }

    pub fn validate(&self) -> ParallelExecutorResult<String> {
        ensure_non_empty(&self.access_id, "state access id")?;
        ensure_non_empty(&self.intent_id, "state access intent id")?;
        ensure_non_empty(&self.tx_id, "state access tx id")?;
        ensure_non_empty(&self.state_domain, "state access state domain")?;
        ensure_non_empty(&self.key_commitment, "state access key commitment")?;
        if self.visibility.is_private() {
            ensure_non_empty(&self.private_hint_root, "state access private hint root")?;
        }
        Ok(parallel_payload_root(
            "PARALLEL-STATE-ACCESS",
            &self.public_record(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParallelExecutionIntent {
    pub intent_id: String,
    pub tx_id: String,
    pub lane_kind: ParallelLaneKind,
    pub visibility: ParallelPayloadVisibility,
    pub payload_root: String,
    pub public_metadata_root: String,
    pub access_root: String,
    pub fee_units: u64,
    pub low_fee_credit_units: u64,
    pub fuel_limit: u64,
    pub priority: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub max_retries: u64,
    pub optimistic_allowed: bool,
    pub private_payload_safe: bool,
    pub retry_count: u64,
    pub status: String,
}

impl ParallelExecutionIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tx_id: impl Into<String>,
        lane_kind: ParallelLaneKind,
        visibility: ParallelPayloadVisibility,
        payload_root: impl Into<String>,
        public_metadata_root: impl Into<String>,
        accesses: &[StateAccessItem],
        fee_units: u64,
        low_fee_credit_units: u64,
        fuel_limit: u64,
        priority: u64,
        submitted_at_height: u64,
        expires_at_height: u64,
        max_retries: u64,
        optimistic_allowed: bool,
    ) -> ParallelExecutorResult<Self> {
        let tx_id = tx_id.into();
        let payload_root = payload_root.into();
        let public_metadata_root = public_metadata_root.into();
        ensure_non_empty(&tx_id, "parallel intent tx id")?;
        ensure_non_empty(&payload_root, "parallel intent payload root")?;
        ensure_non_empty(
            &public_metadata_root,
            "parallel intent public metadata root",
        )?;
        ensure_positive(fuel_limit, "parallel intent fuel limit")?;
        if expires_at_height <= submitted_at_height {
            return Err("parallel intent expiry must be after submission".to_string());
        }
        if accesses.len() > PARALLEL_EXECUTOR_MAX_ACCESS_LIST_ITEMS {
            return Err("parallel intent access list is too large".to_string());
        }
        let access_root = state_access_item_root(accesses);
        let private_payload_safe = visibility.is_private() || lane_kind.is_private();
        let intent_id = parallel_execution_intent_id(
            &tx_id,
            &lane_kind,
            visibility,
            &payload_root,
            &public_metadata_root,
            &access_root,
            fee_units,
            low_fee_credit_units,
            fuel_limit,
            priority,
            submitted_at_height,
            expires_at_height,
        );
        Ok(Self {
            intent_id,
            tx_id,
            lane_kind,
            visibility,
            payload_root,
            public_metadata_root,
            access_root,
            fee_units,
            low_fee_credit_units,
            fuel_limit,
            priority,
            submitted_at_height,
            expires_at_height,
            max_retries,
            optimistic_allowed,
            private_payload_safe,
            retry_count: 0,
            status: PARALLEL_EXECUTOR_STATUS_PENDING.to_string(),
        })
    }

    pub fn effective_priority(&self, config: &ParallelExecutorConfig) -> u64 {
        let low_fee_boost = if self.lane_kind.is_low_fee() || self.low_fee_credit_units > 0 {
            config
                .low_fee_priority_boost
                .saturating_add(self.low_fee_credit_units.min(100_000))
        } else {
            0
        };
        self.priority
            .saturating_add(self.lane_kind.default_priority())
            .saturating_add(self.fee_units.min(1_000_000))
            .saturating_add(low_fee_boost)
            .saturating_sub(self.retry_count.saturating_mul(10_000))
    }

    pub fn is_expired(&self, height: u64) -> bool {
        height >= self.expires_at_height
    }

    pub fn can_retry(&self) -> bool {
        self.retry_count < self.max_retries
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "parallel_execution_intent",
            "chain_id": CHAIN_ID,
            "protocol_version": PARALLEL_EXECUTOR_PROTOCOL_VERSION,
            "intent_id": self.intent_id,
            "tx_id": self.tx_id,
            "lane_kind": self.lane_kind.as_str(),
            "visibility": self.visibility.as_str(),
            "payload_root": self.payload_root,
            "public_metadata_root": self.public_metadata_root,
            "access_root": self.access_root,
            "fee_units": self.fee_units,
            "low_fee_credit_units": self.low_fee_credit_units,
            "fuel_limit": self.fuel_limit,
            "priority": self.priority,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "max_retries": self.max_retries,
            "optimistic_allowed": self.optimistic_allowed,
            "private_payload_safe": self.private_payload_safe,
            "retry_count": self.retry_count,
            "status": self.status,
        })
    }

    pub fn validate_with_accesses(
        &self,
        accesses: &[StateAccessItem],
    ) -> ParallelExecutorResult<String> {
        ensure_non_empty(&self.intent_id, "parallel intent id")?;
        ensure_non_empty(&self.tx_id, "parallel intent tx id")?;
        ensure_non_empty(&self.payload_root, "parallel intent payload root")?;
        ensure_non_empty(
            &self.public_metadata_root,
            "parallel intent public metadata root",
        )?;
        ensure_positive(self.fuel_limit, "parallel intent fuel limit")?;
        if self.expires_at_height <= self.submitted_at_height {
            return Err("parallel intent expiry must be after submission".to_string());
        }
        if self.access_root != state_access_item_root(accesses) {
            return Err("parallel intent access root mismatch".to_string());
        }
        for access in accesses {
            access.validate()?;
            if access.intent_id != self.intent_id {
                return Err("parallel intent access set references another intent".to_string());
            }
        }
        Ok(parallel_payload_root(
            "PARALLEL-EXECUTION-INTENT",
            &self.public_record(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessListPlan {
    pub plan_id: String,
    pub height: u64,
    pub intent_root: String,
    pub access_root: String,
    pub read_root: String,
    pub write_root: String,
    pub hot_key_root: String,
    pub private_access_root: String,
    pub tx_access_roots: BTreeMap<String, String>,
    pub total_accesses: u64,
    pub write_count: u64,
    pub private_access_count: u64,
    pub status: String,
}

impl AccessListPlan {
    pub fn from_intent_ids(
        height: u64,
        intent_ids: &[String],
        intents: &BTreeMap<String, ParallelExecutionIntent>,
        access_sets: &BTreeMap<String, Vec<StateAccessItem>>,
    ) -> ParallelExecutorResult<Self> {
        ensure_unique_strings(intent_ids, "access-list intent ids")?;
        let mut intent_records = Vec::new();
        let mut all_accesses = Vec::new();
        let mut read_keys = BTreeSet::new();
        let mut write_keys = BTreeSet::new();
        let mut hot_keys = BTreeSet::new();
        let mut private_records = Vec::new();
        let mut tx_access_roots = BTreeMap::new();
        for intent_id in intent_ids {
            let intent = intents
                .get(intent_id)
                .ok_or_else(|| format!("missing parallel intent {intent_id}"))?;
            let accesses = access_sets
                .get(intent_id)
                .ok_or_else(|| format!("missing access list for intent {intent_id}"))?;
            intent.validate_with_accesses(accesses)?;
            intent_records.push(intent.public_record());
            tx_access_roots.insert(intent_id.clone(), state_access_item_root(accesses));
            for access in accesses {
                match access.mode {
                    ParallelAccessMode::Read => {
                        read_keys.insert(access.conflict_key());
                    }
                    ParallelAccessMode::Write => {
                        write_keys.insert(access.conflict_key());
                    }
                }
                if access.hot_hint {
                    hot_keys.insert(access.conflict_key());
                }
                if access.visibility.is_private() {
                    private_records.push(access.public_record());
                }
                all_accesses.push(access.clone());
            }
        }
        let intent_root = merkle_root("PARALLEL-ACCESS-PLAN-INTENTS", &intent_records);
        let access_root = state_access_item_root(&all_accesses);
        let read_root = string_set_root_from_set("PARALLEL-ACCESS-PLAN-READS", &read_keys);
        let write_root = string_set_root_from_set("PARALLEL-ACCESS-PLAN-WRITES", &write_keys);
        let hot_key_root = string_set_root_from_set("PARALLEL-ACCESS-PLAN-HOT-KEYS", &hot_keys);
        let private_access_root =
            merkle_root("PARALLEL-ACCESS-PLAN-PRIVATE-ACCESSES", &private_records);
        let plan_id = access_list_plan_id(
            height,
            &intent_root,
            &access_root,
            &read_root,
            &write_root,
            &private_access_root,
        );
        Ok(Self {
            plan_id,
            height,
            intent_root,
            access_root,
            read_root,
            write_root,
            hot_key_root,
            private_access_root,
            tx_access_roots,
            total_accesses: all_accesses.len() as u64,
            write_count: write_keys.len() as u64,
            private_access_count: private_records.len() as u64,
            status: PARALLEL_EXECUTOR_STATUS_READY.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "parallel_access_list_plan",
            "chain_id": CHAIN_ID,
            "protocol_version": PARALLEL_EXECUTOR_PROTOCOL_VERSION,
            "plan_id": self.plan_id,
            "height": self.height,
            "intent_root": self.intent_root,
            "access_root": self.access_root,
            "read_root": self.read_root,
            "write_root": self.write_root,
            "hot_key_root": self.hot_key_root,
            "private_access_root": self.private_access_root,
            "tx_access_roots": self.tx_access_roots,
            "total_accesses": self.total_accesses,
            "write_count": self.write_count,
            "private_access_count": self.private_access_count,
            "status": self.status,
        })
    }

    pub fn plan_root(&self) -> String {
        parallel_payload_root("PARALLEL-ACCESS-LIST-PLAN", &self.public_record())
    }

    pub fn validate(&self) -> ParallelExecutorResult<String> {
        ensure_non_empty(&self.plan_id, "access-list plan id")?;
        ensure_non_empty(&self.intent_root, "access-list plan intent root")?;
        ensure_non_empty(&self.access_root, "access-list plan access root")?;
        ensure_non_empty(&self.read_root, "access-list plan read root")?;
        ensure_non_empty(&self.write_root, "access-list plan write root")?;
        ensure_non_empty(&self.hot_key_root, "access-list plan hot key root")?;
        ensure_non_empty(
            &self.private_access_root,
            "access-list plan private access root",
        )?;
        Ok(self.plan_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictGraphEdge {
    pub edge_id: String,
    pub left_intent_id: String,
    pub right_intent_id: String,
    pub conflict_kind: ParallelConflictKind,
    pub left_access_id: String,
    pub right_access_id: String,
    pub conflict_key: String,
    pub access_root: String,
    pub deterministic_weight: u64,
    pub status: String,
}

impl ConflictGraphEdge {
    pub fn new(
        left: &StateAccessItem,
        right: &StateAccessItem,
        conflict_kind: ParallelConflictKind,
    ) -> ParallelExecutorResult<Self> {
        if left.intent_id == right.intent_id {
            return Err("conflict edge requires two distinct intents".to_string());
        }
        let (left_access, right_access) = if left.intent_id <= right.intent_id {
            (left, right)
        } else {
            (right, left)
        };
        let conflict_key = if left_access.conflict_key() == right_access.conflict_key() {
            left_access.conflict_key()
        } else {
            parallel_payload_root(
                "PARALLEL-PRIVATE-CONFLICT-HINT",
                &json!({
                    "left_hint_root": left_access.private_hint_root,
                    "right_hint_root": right_access.private_hint_root,
                }),
            )
        };
        let access_root = state_access_item_root(&[left_access.clone(), right_access.clone()]);
        let edge_id = conflict_graph_edge_id(
            &left_access.intent_id,
            &right_access.intent_id,
            &conflict_kind,
            &left_access.access_id,
            &right_access.access_id,
            &conflict_key,
            &access_root,
        );
        let deterministic_weight = stable_mod(&edge_id, 1_000_000).saturating_add(1);
        Ok(Self {
            edge_id,
            left_intent_id: left_access.intent_id.clone(),
            right_intent_id: right_access.intent_id.clone(),
            conflict_kind,
            left_access_id: left_access.access_id.clone(),
            right_access_id: right_access.access_id.clone(),
            conflict_key,
            access_root,
            deterministic_weight,
            status: PARALLEL_EXECUTOR_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn touches(&self, intent_id: &str) -> bool {
        self.left_intent_id == intent_id || self.right_intent_id == intent_id
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "parallel_conflict_graph_edge",
            "chain_id": CHAIN_ID,
            "protocol_version": PARALLEL_EXECUTOR_PROTOCOL_VERSION,
            "edge_id": self.edge_id,
            "left_intent_id": self.left_intent_id,
            "right_intent_id": self.right_intent_id,
            "conflict_kind": self.conflict_kind.as_str(),
            "left_access_id": self.left_access_id,
            "right_access_id": self.right_access_id,
            "conflict_key": self.conflict_key,
            "access_root": self.access_root,
            "deterministic_weight": self.deterministic_weight,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictGraph {
    pub graph_id: String,
    pub height: u64,
    pub plan_id: String,
    pub node_root: String,
    pub edge_root: String,
    pub component_root: String,
    pub max_degree: u64,
    pub conflicting_intent_count: u64,
    pub status: String,
    pub edges: BTreeMap<String, ConflictGraphEdge>,
}

impl ConflictGraph {
    pub fn from_intent_ids(
        height: u64,
        plan: &AccessListPlan,
        intent_ids: &[String],
        access_sets: &BTreeMap<String, Vec<StateAccessItem>>,
    ) -> ParallelExecutorResult<Self> {
        ensure_unique_strings(intent_ids, "conflict graph intent ids")?;
        let mut edges = BTreeMap::new();
        for (left_index, left_id) in intent_ids.iter().enumerate() {
            for right_id in intent_ids.iter().skip(left_index + 1) {
                let left_accesses = access_sets
                    .get(left_id)
                    .ok_or_else(|| format!("missing access set for {left_id}"))?;
                let right_accesses = access_sets
                    .get(right_id)
                    .ok_or_else(|| format!("missing access set for {right_id}"))?;
                for left in left_accesses {
                    for right in right_accesses {
                        if let Some(kind) = left.conflicts_with(right) {
                            let edge = ConflictGraphEdge::new(left, right, kind)?;
                            edges.insert(edge.edge_id.clone(), edge);
                        }
                    }
                }
            }
        }
        let node_root = string_set_root("PARALLEL-CONFLICT-GRAPH-NODES", intent_ids);
        let edge_root = conflict_graph_edge_root_from_map(&edges);
        let components = conflict_components_from_edges(intent_ids, &edges);
        let component_root = conflict_component_root(&components);
        let mut degrees = BTreeMap::<String, u64>::new();
        for edge in edges.values() {
            *degrees.entry(edge.left_intent_id.clone()).or_default() += 1;
            *degrees.entry(edge.right_intent_id.clone()).or_default() += 1;
        }
        let max_degree = degrees.values().copied().max().unwrap_or(0);
        let conflicting_intent_count = degrees.len() as u64;
        let graph_id = conflict_graph_id(
            height,
            &plan.plan_id,
            &node_root,
            &edge_root,
            &component_root,
            max_degree,
        );
        Ok(Self {
            graph_id,
            height,
            plan_id: plan.plan_id.clone(),
            node_root,
            edge_root,
            component_root,
            max_degree,
            conflicting_intent_count,
            status: PARALLEL_EXECUTOR_STATUS_READY.to_string(),
            edges,
        })
    }

    pub fn has_conflict(&self, left: &str, right: &str) -> bool {
        if left == right {
            return false;
        }
        self.edges.values().any(|edge| {
            (edge.left_intent_id == left && edge.right_intent_id == right)
                || (edge.left_intent_id == right && edge.right_intent_id == left)
        })
    }

    pub fn conflicts_for(&self, intent_id: &str) -> Vec<ConflictGraphEdge> {
        self.edges
            .values()
            .filter(|edge| edge.touches(intent_id))
            .cloned()
            .collect()
    }

    pub fn components(&self, intent_ids: &[String]) -> Vec<Vec<String>> {
        conflict_components_from_edges(intent_ids, &self.edges)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "parallel_conflict_graph",
            "chain_id": CHAIN_ID,
            "protocol_version": PARALLEL_EXECUTOR_PROTOCOL_VERSION,
            "graph_id": self.graph_id,
            "height": self.height,
            "plan_id": self.plan_id,
            "node_root": self.node_root,
            "edge_root": self.edge_root,
            "component_root": self.component_root,
            "max_degree": self.max_degree,
            "conflicting_intent_count": self.conflicting_intent_count,
            "edge_count": self.edges.len() as u64,
            "status": self.status,
        })
    }

    pub fn graph_root(&self) -> String {
        parallel_payload_root("PARALLEL-CONFLICT-GRAPH", &self.public_record())
    }

    pub fn validate(&self) -> ParallelExecutorResult<String> {
        ensure_non_empty(&self.graph_id, "conflict graph id")?;
        ensure_non_empty(&self.plan_id, "conflict graph plan id")?;
        ensure_non_empty(&self.node_root, "conflict graph node root")?;
        ensure_non_empty(&self.edge_root, "conflict graph edge root")?;
        ensure_non_empty(&self.component_root, "conflict graph component root")?;
        Ok(self.graph_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateLockLease {
    pub lease_id: String,
    pub height: u64,
    pub holder_lane_id: String,
    pub holder_worker_index: u64,
    pub intent_root: String,
    pub state_domain: String,
    pub key_commitment: String,
    pub mode: StateLeaseMode,
    pub access_root: String,
    pub acquired_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl StateLockLease {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        height: u64,
        holder_lane_id: impl Into<String>,
        holder_worker_index: u64,
        intent_ids: &[String],
        state_domain: impl Into<String>,
        key_commitment: impl Into<String>,
        mode: StateLeaseMode,
        accesses: &[StateAccessItem],
        ttl_blocks: u64,
    ) -> ParallelExecutorResult<Self> {
        let holder_lane_id = holder_lane_id.into();
        let state_domain = state_domain.into();
        let key_commitment = key_commitment.into();
        ensure_non_empty(&holder_lane_id, "state lock holder lane id")?;
        ensure_non_empty(&state_domain, "state lock domain")?;
        ensure_non_empty(&key_commitment, "state lock key commitment")?;
        ensure_positive(ttl_blocks, "state lock ttl blocks")?;
        ensure_unique_strings(intent_ids, "state lock intent ids")?;
        let intent_root = string_set_root("PARALLEL-STATE-LOCK-INTENTS", intent_ids);
        let access_root = state_access_item_root(accesses);
        let expires_at_height = height.saturating_add(ttl_blocks);
        let lease_id = state_lock_lease_id(
            height,
            &holder_lane_id,
            holder_worker_index,
            &intent_root,
            &state_domain,
            &key_commitment,
            mode,
            &access_root,
            expires_at_height,
        );
        Ok(Self {
            lease_id,
            height,
            holder_lane_id,
            holder_worker_index,
            intent_root,
            state_domain,
            key_commitment,
            mode,
            access_root,
            acquired_at_height: height,
            expires_at_height,
            status: PARALLEL_EXECUTOR_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn lease_key(&self) -> String {
        format!("{}:{}", self.state_domain, self.key_commitment)
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        height >= self.expires_at_height || self.status == PARALLEL_EXECUTOR_STATUS_RELEASED
    }

    pub fn conflicts_with(&self, other: &Self, height: u64) -> bool {
        if self.lease_id == other.lease_id {
            return false;
        }
        if self.holder_lane_id == other.holder_lane_id {
            return false;
        }
        if self.is_expired_at(height) || other.is_expired_at(height) {
            return false;
        }
        self.lease_key() == other.lease_key() && self.mode.conflicts_with(other.mode)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "parallel_state_lock_lease",
            "chain_id": CHAIN_ID,
            "protocol_version": PARALLEL_EXECUTOR_PROTOCOL_VERSION,
            "lease_scheme": PARALLEL_EXECUTOR_LOCK_LEASE_SCHEME,
            "lease_id": self.lease_id,
            "height": self.height,
            "holder_lane_id": self.holder_lane_id,
            "holder_worker_index": self.holder_worker_index,
            "intent_root": self.intent_root,
            "state_domain": self.state_domain,
            "key_commitment": self.key_commitment,
            "mode": self.mode.as_str(),
            "access_root": self.access_root,
            "acquired_at_height": self.acquired_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn lease_root(&self) -> String {
        parallel_payload_root("PARALLEL-STATE-LOCK-LEASE", &self.public_record())
    }

    pub fn validate(&self) -> ParallelExecutorResult<String> {
        ensure_non_empty(&self.lease_id, "state lock lease id")?;
        ensure_non_empty(&self.holder_lane_id, "state lock holder lane id")?;
        ensure_non_empty(&self.intent_root, "state lock intent root")?;
        ensure_non_empty(&self.state_domain, "state lock state domain")?;
        ensure_non_empty(&self.key_commitment, "state lock key commitment")?;
        ensure_non_empty(&self.access_root, "state lock access root")?;
        if self.expires_at_height <= self.acquired_at_height {
            return Err("state lock lease expiry must be after acquisition".to_string());
        }
        Ok(self.lease_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParallelExecutionLane {
    pub lane_id: String,
    pub height: u64,
    pub lane_index: u64,
    pub worker_index: u64,
    pub lane_kind: ParallelLaneKind,
    pub intent_ids: Vec<String>,
    pub access_root: String,
    pub write_root: String,
    pub conflict_root: String,
    pub lock_root: String,
    pub total_fuel_limit: u64,
    pub total_fee_units: u64,
    pub low_fee_credit_units: u64,
    pub optimistic: bool,
    pub private_payload_safe: bool,
    pub status: String,
}

impl ParallelExecutionLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        height: u64,
        lane_index: u64,
        worker_index: u64,
        lane_kind: ParallelLaneKind,
        intents: &[ParallelExecutionIntent],
        accesses: &[StateAccessItem],
        conflicts: &[ConflictGraphEdge],
        optimistic: bool,
    ) -> ParallelExecutorResult<Self> {
        if intents.is_empty() {
            return Err("parallel execution lane requires at least one intent".to_string());
        }
        let mut intent_ids = intents
            .iter()
            .map(|intent| intent.intent_id.clone())
            .collect::<Vec<_>>();
        intent_ids.sort();
        ensure_unique_strings(&intent_ids, "parallel execution lane intents")?;
        let mut write_keys = BTreeSet::new();
        for access in accesses {
            if access.mode.is_write() {
                write_keys.insert(access.conflict_key());
            }
        }
        let access_root = state_access_item_root(accesses);
        let write_root = string_set_root_from_set("PARALLEL-LANE-WRITES", &write_keys);
        let conflict_root = conflict_graph_edge_root(conflicts);
        let total_fuel_limit = intents.iter().map(|intent| intent.fuel_limit).sum::<u64>();
        let total_fee_units = intents.iter().map(|intent| intent.fee_units).sum::<u64>();
        let low_fee_credit_units = intents
            .iter()
            .map(|intent| intent.low_fee_credit_units)
            .sum::<u64>();
        let private_payload_safe = intents.iter().all(|intent| intent.private_payload_safe)
            || !intents.iter().any(|intent| intent.visibility.is_private());
        let lane_id = parallel_execution_lane_id(
            height,
            lane_index,
            worker_index,
            &lane_kind,
            &intent_ids,
            &access_root,
            &write_root,
            &conflict_root,
            optimistic,
        );
        Ok(Self {
            lane_id,
            height,
            lane_index,
            worker_index,
            lane_kind,
            intent_ids,
            access_root,
            write_root,
            conflict_root,
            lock_root: empty_parallel_root("PARALLEL-LANE-LOCKS"),
            total_fuel_limit,
            total_fee_units,
            low_fee_credit_units,
            optimistic,
            private_payload_safe,
            status: PARALLEL_EXECUTOR_STATUS_READY.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "parallel_execution_lane",
            "chain_id": CHAIN_ID,
            "protocol_version": PARALLEL_EXECUTOR_PROTOCOL_VERSION,
            "lane_id": self.lane_id,
            "height": self.height,
            "lane_index": self.lane_index,
            "worker_index": self.worker_index,
            "lane_kind": self.lane_kind.as_str(),
            "intent_root": string_set_root("PARALLEL-LANE-INTENTS", &self.intent_ids),
            "intent_count": self.intent_ids.len() as u64,
            "access_root": self.access_root,
            "write_root": self.write_root,
            "conflict_root": self.conflict_root,
            "lock_root": self.lock_root,
            "total_fuel_limit": self.total_fuel_limit,
            "total_fee_units": self.total_fee_units,
            "low_fee_credit_units": self.low_fee_credit_units,
            "optimistic": self.optimistic,
            "private_payload_safe": self.private_payload_safe,
            "status": self.status,
        })
    }

    pub fn lane_root(&self) -> String {
        parallel_payload_root("PARALLEL-EXECUTION-LANE", &self.public_record())
    }

    pub fn validate(&self) -> ParallelExecutorResult<String> {
        ensure_non_empty(&self.lane_id, "parallel execution lane id")?;
        ensure_unique_strings(&self.intent_ids, "parallel execution lane intents")?;
        ensure_non_empty(&self.access_root, "parallel execution lane access root")?;
        ensure_non_empty(&self.write_root, "parallel execution lane write root")?;
        ensure_non_empty(&self.conflict_root, "parallel execution lane conflict root")?;
        ensure_non_empty(&self.lock_root, "parallel execution lane lock root")?;
        Ok(self.lane_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerAssignment {
    pub assignment_id: String,
    pub height: u64,
    pub worker_index: u64,
    pub worker_label: String,
    pub lane_id: String,
    pub lane_index: u64,
    pub deterministic_seed: String,
    pub assigned_intent_root: String,
    pub lease_root: String,
    pub status: String,
}

impl WorkerAssignment {
    pub fn new(
        height: u64,
        worker_index: u64,
        worker_label: impl Into<String>,
        lane: &ParallelExecutionLane,
        deterministic_seed: impl Into<String>,
        leases: &[StateLockLease],
    ) -> ParallelExecutorResult<Self> {
        let worker_label = worker_label.into();
        let deterministic_seed = deterministic_seed.into();
        ensure_non_empty(&worker_label, "worker assignment label")?;
        ensure_non_empty(&deterministic_seed, "worker assignment seed")?;
        let assigned_intent_root = string_set_root("PARALLEL-WORKER-INTENTS", &lane.intent_ids);
        let lease_root = state_lock_lease_root(leases);
        let assignment_id = worker_assignment_id(
            height,
            worker_index,
            &worker_label,
            &lane.lane_id,
            lane.lane_index,
            &deterministic_seed,
            &assigned_intent_root,
            &lease_root,
        );
        Ok(Self {
            assignment_id,
            height,
            worker_index,
            worker_label,
            lane_id: lane.lane_id.clone(),
            lane_index: lane.lane_index,
            deterministic_seed,
            assigned_intent_root,
            lease_root,
            status: PARALLEL_EXECUTOR_STATUS_READY.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "parallel_worker_assignment",
            "chain_id": CHAIN_ID,
            "protocol_version": PARALLEL_EXECUTOR_PROTOCOL_VERSION,
            "assignment_id": self.assignment_id,
            "height": self.height,
            "worker_index": self.worker_index,
            "worker_label": self.worker_label,
            "lane_id": self.lane_id,
            "lane_index": self.lane_index,
            "deterministic_seed": self.deterministic_seed,
            "assigned_intent_root": self.assigned_intent_root,
            "lease_root": self.lease_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryBackoff {
    pub retry_id: String,
    pub intent_id: String,
    pub schedule_id: String,
    pub previous_lane_id: String,
    pub attempt: u64,
    pub reason: RetryBackoffReason,
    pub next_eligible_height: u64,
    pub backoff_blocks: u64,
    pub priority_penalty: u64,
    pub conflict_root: String,
    pub status: String,
}

impl RetryBackoff {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy: &RetryPolicy,
        intent_id: impl Into<String>,
        schedule_id: impl Into<String>,
        previous_lane_id: impl Into<String>,
        attempt: u64,
        reason: RetryBackoffReason,
        current_height: u64,
        conflicts: &[ConflictGraphEdge],
    ) -> ParallelExecutorResult<Self> {
        let intent_id = intent_id.into();
        let schedule_id = schedule_id.into();
        let previous_lane_id = previous_lane_id.into();
        ensure_non_empty(&intent_id, "retry backoff intent id")?;
        ensure_non_empty(&schedule_id, "retry backoff schedule id")?;
        ensure_non_empty(&previous_lane_id, "retry backoff previous lane id")?;
        let backoff_blocks = policy.delay_blocks(&intent_id, attempt, &reason);
        let next_eligible_height = current_height.saturating_add(backoff_blocks);
        let conflict_root = conflict_graph_edge_root(conflicts);
        let priority_penalty = attempt.saturating_mul(10_000);
        let retry_id = retry_backoff_id(
            &intent_id,
            &schedule_id,
            &previous_lane_id,
            attempt,
            &reason,
            next_eligible_height,
            &conflict_root,
        );
        Ok(Self {
            retry_id,
            intent_id,
            schedule_id,
            previous_lane_id,
            attempt,
            reason,
            next_eligible_height,
            backoff_blocks,
            priority_penalty,
            conflict_root,
            status: PARALLEL_EXECUTOR_STATUS_RETRYING.to_string(),
        })
    }

    pub fn is_ready_at(&self, height: u64) -> bool {
        height >= self.next_eligible_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "parallel_retry_backoff",
            "chain_id": CHAIN_ID,
            "protocol_version": PARALLEL_EXECUTOR_PROTOCOL_VERSION,
            "retry_id": self.retry_id,
            "intent_id": self.intent_id,
            "schedule_id": self.schedule_id,
            "previous_lane_id": self.previous_lane_id,
            "attempt": self.attempt,
            "reason": self.reason.as_str(),
            "next_eligible_height": self.next_eligible_height,
            "backoff_blocks": self.backoff_blocks,
            "priority_penalty": self.priority_penalty,
            "conflict_root": self.conflict_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParallelExecutionReceipt {
    pub receipt_id: String,
    pub schedule_id: String,
    pub lane_id: String,
    pub worker_index: u64,
    pub intent_id: String,
    pub attempt: u64,
    pub status: String,
    pub fuel_used: u64,
    pub fee_charged_units: u64,
    pub low_fee_credit_consumed: u64,
    pub state_delta_root: String,
    pub event_root: String,
    pub output_root: String,
    pub validation_root: String,
    pub retry_id: Option<String>,
    pub private_payload_safe: bool,
    pub executed_at_height: u64,
    pub execution_ms_bucket: u64,
}

impl ParallelExecutionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        schedule_id: impl Into<String>,
        lane_id: impl Into<String>,
        worker_index: u64,
        intent_id: impl Into<String>,
        attempt: u64,
        status: impl Into<String>,
        fuel_used: u64,
        fee_charged_units: u64,
        low_fee_credit_consumed: u64,
        state_delta_root: impl Into<String>,
        event_root: impl Into<String>,
        output_root: impl Into<String>,
        validation_root: impl Into<String>,
        retry_id: Option<String>,
        private_payload_safe: bool,
        executed_at_height: u64,
        execution_ms_bucket: u64,
    ) -> ParallelExecutorResult<Self> {
        let schedule_id = schedule_id.into();
        let lane_id = lane_id.into();
        let intent_id = intent_id.into();
        let status = status.into();
        let state_delta_root = state_delta_root.into();
        let event_root = event_root.into();
        let output_root = output_root.into();
        let validation_root = validation_root.into();
        ensure_non_empty(&schedule_id, "parallel receipt schedule id")?;
        ensure_non_empty(&lane_id, "parallel receipt lane id")?;
        ensure_non_empty(&intent_id, "parallel receipt intent id")?;
        ensure_non_empty(&status, "parallel receipt status")?;
        ensure_non_empty(&state_delta_root, "parallel receipt state delta root")?;
        ensure_non_empty(&event_root, "parallel receipt event root")?;
        ensure_non_empty(&output_root, "parallel receipt output root")?;
        ensure_non_empty(&validation_root, "parallel receipt validation root")?;
        let receipt_id = parallel_execution_receipt_id(
            &schedule_id,
            &lane_id,
            worker_index,
            &intent_id,
            attempt,
            &status,
            fuel_used,
            fee_charged_units,
            low_fee_credit_consumed,
            &state_delta_root,
            &event_root,
            &output_root,
            &validation_root,
            retry_id.as_deref().unwrap_or(""),
            private_payload_safe,
            executed_at_height,
        );
        Ok(Self {
            receipt_id,
            schedule_id,
            lane_id,
            worker_index,
            intent_id,
            attempt,
            status,
            fuel_used,
            fee_charged_units,
            low_fee_credit_consumed,
            state_delta_root,
            event_root,
            output_root,
            validation_root,
            retry_id,
            private_payload_safe,
            executed_at_height,
            execution_ms_bucket,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "parallel_execution_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PARALLEL_EXECUTOR_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "schedule_id": self.schedule_id,
            "lane_id": self.lane_id,
            "worker_index": self.worker_index,
            "intent_id": self.intent_id,
            "attempt": self.attempt,
            "status": self.status,
            "fuel_used": self.fuel_used,
            "fee_charged_units": self.fee_charged_units,
            "low_fee_credit_consumed": self.low_fee_credit_consumed,
            "state_delta_root": self.state_delta_root,
            "event_root": self.event_root,
            "output_root": self.output_root,
            "validation_root": self.validation_root,
            "retry_id": self.retry_id,
            "private_payload_safe": self.private_payload_safe,
            "executed_at_height": self.executed_at_height,
            "execution_ms_bucket": self.execution_ms_bucket,
        })
    }

    pub fn receipt_root(&self) -> String {
        parallel_payload_root("PARALLEL-EXECUTION-RECEIPT", &self.public_record())
    }

    pub fn validate(&self) -> ParallelExecutorResult<String> {
        ensure_non_empty(&self.receipt_id, "parallel receipt id")?;
        ensure_non_empty(&self.schedule_id, "parallel receipt schedule id")?;
        ensure_non_empty(&self.lane_id, "parallel receipt lane id")?;
        ensure_non_empty(&self.intent_id, "parallel receipt intent id")?;
        ensure_non_empty(&self.status, "parallel receipt status")?;
        ensure_non_empty(&self.state_delta_root, "parallel receipt delta root")?;
        ensure_non_empty(&self.event_root, "parallel receipt event root")?;
        ensure_non_empty(&self.output_root, "parallel receipt output root")?;
        ensure_non_empty(&self.validation_root, "parallel receipt validation root")?;
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParallelExecutionSchedule {
    pub schedule_id: String,
    pub height: u64,
    pub epoch: u64,
    pub config_root: String,
    pub access_plan_id: String,
    pub access_plan_root: String,
    pub conflict_graph_id: String,
    pub conflict_graph_root: String,
    pub lane_root: String,
    pub assignment_root: String,
    pub lease_root: String,
    pub retry_root: String,
    pub lane_ids: Vec<String>,
    pub total_intents: u64,
    pub total_lanes: u64,
    pub parallel_width: u64,
    pub low_fee_lane_count: u64,
    pub private_lane_count: u64,
    pub optimistic_lane_count: u64,
    pub determinism_root: String,
    pub expires_at_height: u64,
    pub status: String,
}

impl ParallelExecutionSchedule {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        height: u64,
        epoch: u64,
        config: &ParallelExecutorConfig,
        access_plan: &AccessListPlan,
        conflict_graph: &ConflictGraph,
        lanes: &[ParallelExecutionLane],
        assignments: &[WorkerAssignment],
        leases: &[StateLockLease],
        retries: &[RetryBackoff],
    ) -> ParallelExecutorResult<Self> {
        if lanes.is_empty() && retries.is_empty() {
            return Err("parallel schedule requires lanes or retries".to_string());
        }
        let mut lane_ids = lanes
            .iter()
            .map(|lane| lane.lane_id.clone())
            .collect::<Vec<_>>();
        lane_ids.sort();
        ensure_unique_strings(&lane_ids, "parallel schedule lane ids")?;
        let config_root = config.config_root();
        let access_plan_root = access_plan.plan_root();
        let conflict_graph_root = conflict_graph.graph_root();
        let lane_root = parallel_execution_lane_root(lanes);
        let assignment_root = worker_assignment_root(assignments);
        let lease_root = state_lock_lease_root(leases);
        let retry_root = retry_backoff_root(retries);
        let total_intents = lanes
            .iter()
            .map(|lane| lane.intent_ids.len() as u64)
            .sum::<u64>();
        let total_lanes = lanes.len() as u64;
        let parallel_width = lanes
            .iter()
            .map(|lane| lane.worker_index)
            .collect::<BTreeSet<_>>()
            .len() as u64;
        let low_fee_lane_count = lanes
            .iter()
            .filter(|lane| lane.lane_kind.is_low_fee() || lane.low_fee_credit_units > 0)
            .count() as u64;
        let private_lane_count = lanes
            .iter()
            .filter(|lane| lane.lane_kind.is_private())
            .count() as u64;
        let optimistic_lane_count = lanes.iter().filter(|lane| lane.optimistic).count() as u64;
        let expires_at_height = height.saturating_add(config.schedule_ttl_blocks);
        let determinism_root = parallel_payload_root(
            "PARALLEL-SCHEDULE-DETERMINISM",
            &json!({
                "height": height,
                "epoch": epoch,
                "config_root": config_root,
                "access_plan_root": access_plan_root,
                "conflict_graph_root": conflict_graph_root,
                "lane_root": lane_root,
                "assignment_root": assignment_root,
                "lease_root": lease_root,
                "determinism_seed": config.determinism_seed,
                "private_scheduling_policy": PARALLEL_EXECUTOR_PRIVATE_SCHEDULING_POLICY,
            }),
        );
        let schedule_id = parallel_execution_schedule_id(
            height,
            epoch,
            &config_root,
            &access_plan.plan_id,
            &access_plan_root,
            &conflict_graph.graph_id,
            &conflict_graph_root,
            &lane_root,
            &assignment_root,
            &lease_root,
            &determinism_root,
            expires_at_height,
        );
        Ok(Self {
            schedule_id,
            height,
            epoch,
            config_root,
            access_plan_id: access_plan.plan_id.clone(),
            access_plan_root,
            conflict_graph_id: conflict_graph.graph_id.clone(),
            conflict_graph_root,
            lane_root,
            assignment_root,
            lease_root,
            retry_root,
            lane_ids,
            total_intents,
            total_lanes,
            parallel_width,
            low_fee_lane_count,
            private_lane_count,
            optimistic_lane_count,
            determinism_root,
            expires_at_height,
            status: PARALLEL_EXECUTOR_STATUS_READY.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "parallel_execution_schedule",
            "chain_id": CHAIN_ID,
            "protocol_version": PARALLEL_EXECUTOR_PROTOCOL_VERSION,
            "schedule_id": self.schedule_id,
            "height": self.height,
            "epoch": self.epoch,
            "config_root": self.config_root,
            "access_plan_id": self.access_plan_id,
            "access_plan_root": self.access_plan_root,
            "conflict_graph_id": self.conflict_graph_id,
            "conflict_graph_root": self.conflict_graph_root,
            "lane_root": self.lane_root,
            "assignment_root": self.assignment_root,
            "lease_root": self.lease_root,
            "retry_root": self.retry_root,
            "lane_root_by_id": string_set_root("PARALLEL-SCHEDULE-LANE-IDS", &self.lane_ids),
            "lane_count": self.lane_ids.len() as u64,
            "total_intents": self.total_intents,
            "total_lanes": self.total_lanes,
            "parallel_width": self.parallel_width,
            "low_fee_lane_count": self.low_fee_lane_count,
            "private_lane_count": self.private_lane_count,
            "optimistic_lane_count": self.optimistic_lane_count,
            "determinism_root": self.determinism_root,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn schedule_root(&self) -> String {
        parallel_payload_root("PARALLEL-EXECUTION-SCHEDULE", &self.public_record())
    }

    pub fn validate(&self) -> ParallelExecutorResult<String> {
        ensure_non_empty(&self.schedule_id, "parallel schedule id")?;
        ensure_non_empty(&self.config_root, "parallel schedule config root")?;
        ensure_non_empty(&self.access_plan_id, "parallel schedule access plan id")?;
        ensure_non_empty(&self.access_plan_root, "parallel schedule access plan root")?;
        ensure_non_empty(&self.conflict_graph_id, "parallel schedule graph id")?;
        ensure_non_empty(
            &self.conflict_graph_root,
            "parallel schedule conflict graph root",
        )?;
        ensure_non_empty(&self.lane_root, "parallel schedule lane root")?;
        ensure_non_empty(&self.assignment_root, "parallel schedule assignment root")?;
        ensure_non_empty(&self.lease_root, "parallel schedule lease root")?;
        ensure_non_empty(&self.retry_root, "parallel schedule retry root")?;
        ensure_non_empty(&self.determinism_root, "parallel schedule determinism root")?;
        if self.expires_at_height <= self.height {
            return Err("parallel schedule expiry must be after height".to_string());
        }
        Ok(self.schedule_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerPqAttestation {
    pub attestation_id: String,
    pub scheduler_label: String,
    pub signer_key_id: String,
    pub signature_scheme: String,
    pub schedule_id: String,
    pub schedule_root: String,
    pub access_plan_root: String,
    pub conflict_graph_root: String,
    pub assignment_root: String,
    pub lease_root: String,
    pub receipt_root: String,
    pub state_root: String,
    pub transcript_hash: String,
    pub signature_commitment: String,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl SchedulerPqAttestation {
    pub fn sign(
        scheduler_label: impl Into<String>,
        signer_key_id: impl Into<String>,
        schedule: &ParallelExecutionSchedule,
        receipt_root: impl Into<String>,
        state_root: impl Into<String>,
        signed_at_height: u64,
    ) -> ParallelExecutorResult<Self> {
        let scheduler_label = scheduler_label.into();
        let signer_key_id = signer_key_id.into();
        let receipt_root = receipt_root.into();
        let state_root = state_root.into();
        ensure_non_empty(&scheduler_label, "scheduler attestation label")?;
        ensure_non_empty(&signer_key_id, "scheduler attestation signer key id")?;
        ensure_non_empty(&receipt_root, "scheduler attestation receipt root")?;
        ensure_non_empty(&state_root, "scheduler attestation state root")?;
        let schedule_root = schedule.schedule_root();
        let transcript_hash = scheduler_attestation_transcript_hash(
            &scheduler_label,
            &signer_key_id,
            &schedule.schedule_id,
            &schedule_root,
            &schedule.access_plan_root,
            &schedule.conflict_graph_root,
            &schedule.assignment_root,
            &schedule.lease_root,
            &receipt_root,
            &state_root,
            signed_at_height,
        );
        let signature_commitment = scheduler_pq_signature_commitment(
            &scheduler_label,
            &signer_key_id,
            &transcript_hash,
            signed_at_height,
        );
        let expires_at_height =
            signed_at_height.saturating_add(PARALLEL_EXECUTOR_DEFAULT_SCHEDULE_TTL_BLOCKS * 8);
        let attestation_id = scheduler_pq_attestation_id(
            &scheduler_label,
            &signer_key_id,
            &schedule.schedule_id,
            &schedule_root,
            &transcript_hash,
            signed_at_height,
        );
        Ok(Self {
            attestation_id,
            scheduler_label,
            signer_key_id,
            signature_scheme: PARALLEL_EXECUTOR_PQ_SIGNATURE_SCHEME.to_string(),
            schedule_id: schedule.schedule_id.clone(),
            schedule_root,
            access_plan_root: schedule.access_plan_root.clone(),
            conflict_graph_root: schedule.conflict_graph_root.clone(),
            assignment_root: schedule.assignment_root.clone(),
            lease_root: schedule.lease_root.clone(),
            receipt_root,
            state_root,
            transcript_hash,
            signature_commitment,
            signed_at_height,
            expires_at_height,
            status: PARALLEL_EXECUTOR_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "parallel_scheduler_pq_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": PARALLEL_EXECUTOR_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "scheduler_label": self.scheduler_label,
            "signer_key_id": self.signer_key_id,
            "signature_scheme": self.signature_scheme,
            "schedule_id": self.schedule_id,
            "schedule_root": self.schedule_root,
            "access_plan_root": self.access_plan_root,
            "conflict_graph_root": self.conflict_graph_root,
            "assignment_root": self.assignment_root,
            "lease_root": self.lease_root,
            "receipt_root": self.receipt_root,
            "state_root": self.state_root,
            "transcript_hash": self.transcript_hash,
            "signature_commitment": self.signature_commitment,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn attestation_root(&self) -> String {
        parallel_payload_root("PARALLEL-SCHEDULER-PQ-ATTESTATION", &self.public_record())
    }

    pub fn verify_for_schedule(&self, schedule: &ParallelExecutionSchedule) -> bool {
        if self.schedule_id != schedule.schedule_id
            || self.schedule_root != schedule.schedule_root()
        {
            return false;
        }
        let expected_transcript = scheduler_attestation_transcript_hash(
            &self.scheduler_label,
            &self.signer_key_id,
            &self.schedule_id,
            &self.schedule_root,
            &self.access_plan_root,
            &self.conflict_graph_root,
            &self.assignment_root,
            &self.lease_root,
            &self.receipt_root,
            &self.state_root,
            self.signed_at_height,
        );
        let expected_signature = scheduler_pq_signature_commitment(
            &self.scheduler_label,
            &self.signer_key_id,
            &expected_transcript,
            self.signed_at_height,
        );
        expected_transcript == self.transcript_hash
            && expected_signature == self.signature_commitment
            && self.signature_scheme == PARALLEL_EXECUTOR_PQ_SIGNATURE_SCHEME
    }

    pub fn validate(&self) -> ParallelExecutorResult<String> {
        ensure_non_empty(&self.attestation_id, "scheduler attestation id")?;
        ensure_non_empty(&self.scheduler_label, "scheduler attestation label")?;
        ensure_non_empty(&self.signer_key_id, "scheduler attestation signer key id")?;
        ensure_non_empty(&self.signature_scheme, "scheduler attestation scheme")?;
        ensure_non_empty(&self.schedule_id, "scheduler attestation schedule id")?;
        ensure_non_empty(&self.schedule_root, "scheduler attestation schedule root")?;
        ensure_non_empty(&self.transcript_hash, "scheduler attestation transcript")?;
        ensure_non_empty(
            &self.signature_commitment,
            "scheduler attestation signature commitment",
        )?;
        if self.expires_at_height <= self.signed_at_height {
            return Err("scheduler attestation expiry must be after signing height".to_string());
        }
        Ok(self.attestation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParallelExecutorDevnetState {
    pub operator_label: String,
    pub height: u64,
    pub epoch: u64,
    pub config: ParallelExecutorConfig,
    pub intents: BTreeMap<String, ParallelExecutionIntent>,
    pub access_sets: BTreeMap<String, Vec<StateAccessItem>>,
    pub access_plans: BTreeMap<String, AccessListPlan>,
    pub conflict_graphs: BTreeMap<String, ConflictGraph>,
    pub schedules: BTreeMap<String, ParallelExecutionSchedule>,
    pub lanes: BTreeMap<String, ParallelExecutionLane>,
    pub assignments: BTreeMap<String, WorkerAssignment>,
    pub leases: BTreeMap<String, StateLockLease>,
    pub retries: BTreeMap<String, RetryBackoff>,
    pub receipts: BTreeMap<String, ParallelExecutionReceipt>,
    pub attestations: BTreeMap<String, SchedulerPqAttestation>,
    pub metadata: BTreeMap<String, String>,
}

impl ParallelExecutorDevnetState {
    pub fn devnet(operator_label: &str) -> Self {
        Self::try_devnet(operator_label).expect("deterministic parallel executor devnet state")
    }

    pub fn try_devnet(operator_label: &str) -> ParallelExecutorResult<Self> {
        ensure_non_empty(operator_label, "parallel executor operator label")?;
        let config = ParallelExecutorConfig::devnet();
        let height = 1;
        let epoch = height / PARALLEL_EXECUTOR_DEFAULT_EPOCH_BLOCKS;
        let mut metadata = BTreeMap::new();
        metadata.insert("chain_id".to_string(), CHAIN_ID.to_string());
        metadata.insert(
            "protocol_version".to_string(),
            PARALLEL_EXECUTOR_PROTOCOL_VERSION.to_string(),
        );
        metadata.insert(
            "private_scheduling_policy".to_string(),
            PARALLEL_EXECUTOR_PRIVATE_SCHEDULING_POLICY.to_string(),
        );
        metadata.insert(
            "pq_signature_scheme".to_string(),
            PARALLEL_EXECUTOR_PQ_SIGNATURE_SCHEME.to_string(),
        );
        Ok(Self {
            operator_label: operator_label.to_string(),
            height,
            epoch,
            config,
            intents: BTreeMap::new(),
            access_sets: BTreeMap::new(),
            access_plans: BTreeMap::new(),
            conflict_graphs: BTreeMap::new(),
            schedules: BTreeMap::new(),
            lanes: BTreeMap::new(),
            assignments: BTreeMap::new(),
            leases: BTreeMap::new(),
            retries: BTreeMap::new(),
            receipts: BTreeMap::new(),
            attestations: BTreeMap::new(),
            metadata,
        })
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        self.epoch = height / PARALLEL_EXECUTOR_DEFAULT_EPOCH_BLOCKS;
        for lease in self.leases.values_mut() {
            if lease.is_expired_at(height) {
                lease.status = PARALLEL_EXECUTOR_STATUS_RELEASED.to_string();
            }
        }
        for intent in self.intents.values_mut() {
            if intent.is_expired(height)
                && intent.status != PARALLEL_EXECUTOR_STATUS_APPLIED
                && intent.status != PARALLEL_EXECUTOR_STATUS_REVERTED
            {
                intent.status = PARALLEL_EXECUTOR_STATUS_EXPIRED.to_string();
            }
        }
    }

    pub fn submit_intent(
        &mut self,
        intent: ParallelExecutionIntent,
        accesses: Vec<StateAccessItem>,
    ) -> ParallelExecutorResult<String> {
        if intent.is_expired(self.height) {
            return Err("parallel intent is expired".to_string());
        }
        if accesses.len() > PARALLEL_EXECUTOR_MAX_ACCESS_LIST_ITEMS {
            return Err("parallel intent access list is too large".to_string());
        }
        intent.validate_with_accesses(&accesses)?;
        let intent_id = intent.intent_id.clone();
        if self.intents.contains_key(&intent_id) {
            return Err("parallel intent already exists".to_string());
        }
        self.access_sets.insert(intent_id.clone(), accesses);
        self.intents.insert(intent_id.clone(), intent);
        Ok(intent_id)
    }

    pub fn plan_access_lists(
        &mut self,
        intent_ids: &[String],
    ) -> ParallelExecutorResult<AccessListPlan> {
        let plan = AccessListPlan::from_intent_ids(
            self.height,
            intent_ids,
            &self.intents,
            &self.access_sets,
        )?;
        self.access_plans.insert(plan.plan_id.clone(), plan.clone());
        Ok(plan)
    }

    pub fn build_conflict_graph(
        &mut self,
        plan: &AccessListPlan,
        intent_ids: &[String],
    ) -> ParallelExecutorResult<ConflictGraph> {
        let graph =
            ConflictGraph::from_intent_ids(self.height, plan, intent_ids, &self.access_sets)?;
        self.conflict_graphs
            .insert(graph.graph_id.clone(), graph.clone());
        Ok(graph)
    }

    pub fn plan_schedule(
        &mut self,
        height: u64,
    ) -> ParallelExecutorResult<ParallelExecutionSchedule> {
        self.set_height(height);
        let mut pending = self
            .intents
            .values()
            .filter(|intent| {
                (intent.status == PARALLEL_EXECUTOR_STATUS_PENDING
                    || intent.status == PARALLEL_EXECUTOR_STATUS_RETRYING)
                    && !intent.is_expired(height)
                    && self.retry_ready(&intent.intent_id, height)
            })
            .cloned()
            .collect::<Vec<_>>();
        pending.sort_by(|left, right| {
            right
                .effective_priority(&self.config)
                .cmp(&left.effective_priority(&self.config))
                .then_with(|| left.submitted_at_height.cmp(&right.submitted_at_height))
                .then_with(|| left.intent_id.cmp(&right.intent_id))
        });
        pending.truncate(
            self.config
                .max_schedule_intents
                .min(PARALLEL_EXECUTOR_MAX_SCHEDULE_INTENTS as u64) as usize,
        );
        let intent_ids = pending
            .iter()
            .map(|intent| intent.intent_id.clone())
            .collect::<Vec<_>>();
        let access_plan = self.plan_access_lists(&intent_ids)?;
        let graph = self.build_conflict_graph(&access_plan, &intent_ids)?;
        let (lanes, retries) = self.assign_lanes(height, &pending, &graph)?;
        let mut schedule_lanes = Vec::new();
        let mut schedule_assignments = Vec::new();
        let mut schedule_leases = Vec::new();
        for mut lane in lanes {
            let lane_accesses = self.accesses_for_intents(&lane.intent_ids)?;
            let leases =
                build_leases_for_lane(height, &lane, &lane_accesses, self.config.lock_ttl_blocks)?;
            lane.lock_root = state_lock_lease_root(&leases);
            let assignment = WorkerAssignment::new(
                height,
                lane.worker_index,
                worker_label(&self.operator_label, lane.worker_index),
                &lane,
                self.worker_seed(lane.worker_index),
                &leases,
            )?;
            schedule_leases.extend(leases);
            schedule_assignments.push(assignment);
            schedule_lanes.push(lane);
        }
        validate_no_cross_lane_conflicts(&schedule_lanes, &graph)?;
        validate_private_payload_safe_lanes(&schedule_lanes)?;
        let locked_lane_ids = schedule_lanes
            .iter()
            .filter(|lane| !lane.optimistic)
            .map(|lane| lane.lane_id.clone())
            .collect::<BTreeSet<_>>();
        let locked_leases = schedule_leases
            .iter()
            .filter(|lease| locked_lane_ids.contains(&lease.holder_lane_id))
            .cloned()
            .collect::<Vec<_>>();
        validate_state_lock_lease_set(&locked_leases, height)?;
        let mut schedule = ParallelExecutionSchedule::new(
            height,
            self.epoch,
            &self.config,
            &access_plan,
            &graph,
            &schedule_lanes,
            &schedule_assignments,
            &schedule_leases,
            &retries,
        )?;
        let retries = resolve_retries_for_schedule(retries, &schedule.schedule_id);
        schedule.retry_root = retry_backoff_root(&retries);
        for lane in &schedule_lanes {
            for intent_id in &lane.intent_ids {
                if let Some(intent) = self.intents.get_mut(intent_id) {
                    intent.status = PARALLEL_EXECUTOR_STATUS_READY.to_string();
                }
            }
            self.lanes.insert(lane.lane_id.clone(), lane.clone());
        }
        for assignment in &schedule_assignments {
            self.assignments
                .insert(assignment.assignment_id.clone(), assignment.clone());
        }
        for lease in &schedule_leases {
            self.leases.insert(lease.lease_id.clone(), lease.clone());
        }
        for retry in &retries {
            if let Some(intent) = self.intents.get_mut(&retry.intent_id) {
                intent.retry_count = retry.attempt;
                intent.status = PARALLEL_EXECUTOR_STATUS_RETRYING.to_string();
            }
            self.retries.insert(retry.retry_id.clone(), retry.clone());
        }
        self.schedules
            .insert(schedule.schedule_id.clone(), schedule.clone());
        Ok(schedule)
    }

    pub fn attest_schedule(
        &mut self,
        schedule_id: &str,
        scheduler_label: &str,
    ) -> ParallelExecutorResult<SchedulerPqAttestation> {
        let schedule = self
            .schedules
            .get(schedule_id)
            .ok_or_else(|| format!("unknown schedule {schedule_id}"))?;
        let signer_key_id = scheduler_signer_key_id(scheduler_label);
        let attestation = SchedulerPqAttestation::sign(
            scheduler_label,
            signer_key_id,
            schedule,
            parallel_execution_receipt_root_from_map(&self.receipts),
            self.state_root(),
            self.height,
        )?;
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation.clone());
        Ok(attestation)
    }

    pub fn record_receipt(
        &mut self,
        receipt: ParallelExecutionReceipt,
    ) -> ParallelExecutorResult<String> {
        receipt.validate()?;
        if !self.schedules.contains_key(&receipt.schedule_id) {
            return Err("parallel receipt references unknown schedule".to_string());
        }
        if !self.lanes.contains_key(&receipt.lane_id) {
            return Err("parallel receipt references unknown lane".to_string());
        }
        if let Some(intent) = self.intents.get_mut(&receipt.intent_id) {
            match receipt.status.as_str() {
                PARALLEL_EXECUTOR_STATUS_APPLIED => {
                    intent.status = PARALLEL_EXECUTOR_STATUS_APPLIED.to_string();
                }
                PARALLEL_EXECUTOR_STATUS_REVERTED => {
                    intent.status = PARALLEL_EXECUTOR_STATUS_REVERTED.to_string();
                }
                PARALLEL_EXECUTOR_STATUS_RETRYING => {
                    intent.retry_count = intent.retry_count.saturating_add(1);
                    intent.status = PARALLEL_EXECUTOR_STATUS_RETRYING.to_string();
                }
                _ => {
                    intent.status = receipt.status.clone();
                }
            }
        }
        let receipt_id = receipt.receipt_id.clone();
        self.receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn active_lease_conflicts(&self, leases: &[StateLockLease]) -> Vec<Value> {
        let active = self
            .leases
            .values()
            .filter(|lease| !lease.is_expired_at(self.height))
            .collect::<Vec<_>>();
        let mut conflicts = Vec::new();
        for lease in leases {
            for existing in &active {
                if lease.conflicts_with(existing, self.height) {
                    conflicts.push(json!({
                        "lease_id": lease.lease_id,
                        "existing_lease_id": existing.lease_id,
                        "lease_key": lease.lease_key(),
                    }));
                }
            }
        }
        conflicts
    }

    pub fn pending_count(&self) -> u64 {
        self.intents
            .values()
            .filter(|intent| intent.status == PARALLEL_EXECUTOR_STATUS_PENDING)
            .count() as u64
    }

    pub fn ready_count(&self) -> u64 {
        self.intents
            .values()
            .filter(|intent| intent.status == PARALLEL_EXECUTOR_STATUS_READY)
            .count() as u64
    }

    pub fn retrying_count(&self) -> u64 {
        self.intents
            .values()
            .filter(|intent| intent.status == PARALLEL_EXECUTOR_STATUS_RETRYING)
            .count() as u64
    }

    pub fn state_root(&self) -> String {
        parallel_executor_state_root_from_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "parallel_executor_devnet_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PARALLEL_EXECUTOR_PROTOCOL_VERSION,
            "operator_label": self.operator_label,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "intent_root": parallel_execution_intent_root_from_map(&self.intents),
            "access_set_root": access_set_map_root(&self.access_sets),
            "access_plan_root": access_list_plan_root_from_map(&self.access_plans),
            "conflict_graph_root": conflict_graph_root_from_map(&self.conflict_graphs),
            "schedule_root": parallel_execution_schedule_root_from_map(&self.schedules),
            "lane_root": parallel_execution_lane_root_from_map(&self.lanes),
            "assignment_root": worker_assignment_root_from_map(&self.assignments),
            "lease_root": state_lock_lease_root_from_map(&self.leases),
            "retry_root": retry_backoff_root_from_map(&self.retries),
            "receipt_root": parallel_execution_receipt_root_from_map(&self.receipts),
            "attestation_root": scheduler_pq_attestation_root_from_map(&self.attestations),
            "pending_count": self.pending_count(),
            "ready_count": self.ready_count(),
            "retrying_count": self.retrying_count(),
            "metadata": self.metadata,
        })
    }

    pub fn validate(&self) -> ParallelExecutorResult<String> {
        ensure_non_empty(&self.operator_label, "parallel executor operator label")?;
        self.config.validate()?;
        for (intent_id, intent) in &self.intents {
            let accesses = self
                .access_sets
                .get(intent_id)
                .ok_or_else(|| format!("missing access set for intent {intent_id}"))?;
            intent.validate_with_accesses(accesses)?;
        }
        for plan in self.access_plans.values() {
            plan.validate()?;
        }
        for graph in self.conflict_graphs.values() {
            graph.validate()?;
        }
        for lane in self.lanes.values() {
            lane.validate()?;
        }
        for lease in self.leases.values() {
            lease.validate()?;
        }
        for receipt in self.receipts.values() {
            receipt.validate()?;
        }
        for schedule in self.schedules.values() {
            schedule.validate()?;
        }
        for attestation in self.attestations.values() {
            attestation.validate()?;
            if let Some(schedule) = self.schedules.get(&attestation.schedule_id) {
                if !attestation.verify_for_schedule(schedule) {
                    return Err("scheduler attestation verification failed".to_string());
                }
            }
        }
        Ok(self.state_root())
    }

    fn retry_ready(&self, intent_id: &str, height: u64) -> bool {
        self.retries
            .values()
            .filter(|retry| retry.intent_id == intent_id)
            .all(|retry| retry.is_ready_at(height))
    }

    fn accesses_for_intents(
        &self,
        intent_ids: &[String],
    ) -> ParallelExecutorResult<Vec<StateAccessItem>> {
        let mut accesses = Vec::new();
        for intent_id in intent_ids {
            let access_set = self
                .access_sets
                .get(intent_id)
                .ok_or_else(|| format!("missing access set for intent {intent_id}"))?;
            accesses.extend(access_set.clone());
        }
        Ok(accesses)
    }

    fn worker_seed(&self, worker_index: u64) -> String {
        domain_hash(
            "PARALLEL-WORKER-SEED",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.config.determinism_seed),
                HashPart::Str(&self.operator_label),
                HashPart::Int(worker_index as i128),
            ],
            32,
        )
    }

    fn assign_lanes(
        &self,
        height: u64,
        pending: &[ParallelExecutionIntent],
        graph: &ConflictGraph,
    ) -> ParallelExecutorResult<(Vec<ParallelExecutionLane>, Vec<RetryBackoff>)> {
        let worker_count = self.config.worker_count_usize();
        let mut lane_intents = (0..worker_count)
            .map(|index| (index as u64, Vec::<String>::new()))
            .collect::<BTreeMap<_, _>>();
        let mut lane_fuel = (0..worker_count)
            .map(|index| (index as u64, 0_u64))
            .collect::<BTreeMap<_, _>>();
        let mut optimistic_workers = BTreeSet::new();
        let mut retries = Vec::new();
        for intent in pending {
            let order = deterministic_worker_order(intent, &self.config, height, worker_count);
            let mut placed = false;
            for worker_index in &order {
                let used_fuel = lane_fuel.get(worker_index).copied().unwrap_or_default();
                if used_fuel.saturating_add(intent.fuel_limit) > self.config.lane_fuel_limit {
                    continue;
                }
                if self.can_place_on_worker(&intent.intent_id, *worker_index, &lane_intents, graph)
                {
                    lane_intents
                        .entry(*worker_index)
                        .or_default()
                        .push(intent.intent_id.clone());
                    lane_fuel.insert(*worker_index, used_fuel.saturating_add(intent.fuel_limit));
                    placed = true;
                    break;
                }
            }
            if !placed
                && intent.optimistic_allowed
                && intent.retry_count < self.config.optimistic_retry_limit
            {
                let worker_index = order.first().copied().unwrap_or(0);
                lane_intents
                    .entry(worker_index)
                    .or_default()
                    .push(intent.intent_id.clone());
                let used_fuel = lane_fuel.get(&worker_index).copied().unwrap_or_default();
                lane_fuel.insert(worker_index, used_fuel.saturating_add(intent.fuel_limit));
                optimistic_workers.insert(worker_index);
                placed = true;
            }
            if !placed {
                let conflicts = graph.conflicts_for(&intent.intent_id);
                retries.push(RetryBackoff::new(
                    &self.config.retry_policy,
                    intent.intent_id.clone(),
                    "unbuilt-schedule",
                    "unassigned",
                    intent.retry_count.saturating_add(1),
                    RetryBackoffReason::Conflict,
                    height,
                    &conflicts,
                )?);
            }
        }
        let mut lanes = Vec::new();
        for (worker_index, ids) in lane_intents {
            if ids.is_empty() {
                continue;
            }
            let intents = ids
                .iter()
                .map(|intent_id| {
                    self.intents
                        .get(intent_id)
                        .cloned()
                        .ok_or_else(|| format!("missing intent {intent_id}"))
                })
                .collect::<ParallelExecutorResult<Vec<_>>>()?;
            let accesses = self.accesses_for_intents(&ids)?;
            let id_set = ids.iter().cloned().collect::<BTreeSet<_>>();
            let conflicts = graph
                .edges
                .values()
                .filter(|edge| {
                    id_set.contains(&edge.left_intent_id) || id_set.contains(&edge.right_intent_id)
                })
                .cloned()
                .collect::<Vec<_>>();
            let lane_kind = dominant_lane_kind(&intents);
            let optimistic = optimistic_workers.contains(&worker_index)
                || intents.iter().any(|intent| intent.optimistic_allowed);
            let lane = ParallelExecutionLane::new(
                height,
                worker_index,
                worker_index,
                lane_kind,
                &intents,
                &accesses,
                &conflicts,
                optimistic,
            )?;
            lanes.push(lane);
        }
        lanes.sort_by(|left, right| {
            left.worker_index
                .cmp(&right.worker_index)
                .then_with(|| left.lane_id.cmp(&right.lane_id))
        });
        Ok((lanes, retries))
    }

    fn can_place_on_worker(
        &self,
        intent_id: &str,
        worker_index: u64,
        lane_intents: &BTreeMap<u64, Vec<String>>,
        graph: &ConflictGraph,
    ) -> bool {
        for (other_worker, ids) in lane_intents {
            if *other_worker == worker_index {
                continue;
            }
            if ids
                .iter()
                .any(|other_intent_id| graph.has_conflict(intent_id, other_intent_id))
            {
                return false;
            }
        }
        true
    }
}

fn build_leases_for_lane(
    height: u64,
    lane: &ParallelExecutionLane,
    accesses: &[StateAccessItem],
    ttl_blocks: u64,
) -> ParallelExecutorResult<Vec<StateLockLease>> {
    let mut grouped = BTreeMap::<String, Vec<StateAccessItem>>::new();
    for access in accesses {
        grouped
            .entry(access.conflict_key())
            .or_default()
            .push(access.clone());
    }
    let mut leases = Vec::new();
    for access_group in grouped.values() {
        let first = access_group
            .first()
            .ok_or_else(|| "empty access group".to_string())?;
        let mode = if access_group.iter().any(|access| access.mode.is_write()) {
            StateLeaseMode::ExclusiveWrite
        } else {
            StateLeaseMode::SharedRead
        };
        leases.push(StateLockLease::new(
            height,
            lane.lane_id.clone(),
            lane.worker_index,
            &lane.intent_ids,
            first.state_domain.clone(),
            first.key_commitment.clone(),
            mode,
            access_group,
            ttl_blocks,
        )?);
    }
    leases.sort_by(|left, right| left.lease_id.cmp(&right.lease_id));
    Ok(leases)
}

fn resolve_retries_for_schedule(
    retries: Vec<RetryBackoff>,
    schedule_id: &str,
) -> Vec<RetryBackoff> {
    retries
        .into_iter()
        .map(|mut retry| {
            retry.schedule_id = schedule_id.to_string();
            retry.retry_id = retry_backoff_id(
                &retry.intent_id,
                &retry.schedule_id,
                &retry.previous_lane_id,
                retry.attempt,
                &retry.reason,
                retry.next_eligible_height,
                &retry.conflict_root,
            );
            retry
        })
        .collect()
}

fn dominant_lane_kind(intents: &[ParallelExecutionIntent]) -> ParallelLaneKind {
    if intents
        .iter()
        .any(|intent| matches!(intent.lane_kind, ParallelLaneKind::System))
    {
        return ParallelLaneKind::System;
    }
    if intents
        .iter()
        .any(|intent| matches!(intent.lane_kind, ParallelLaneKind::PrivatePayload))
    {
        return ParallelLaneKind::PrivatePayload;
    }
    if intents
        .iter()
        .any(|intent| matches!(intent.lane_kind, ParallelLaneKind::LowFeePriority))
    {
        return ParallelLaneKind::LowFeePriority;
    }
    intents
        .first()
        .map(|intent| intent.lane_kind.clone())
        .unwrap_or(ParallelLaneKind::Background)
}

fn deterministic_worker_order(
    intent: &ParallelExecutionIntent,
    config: &ParallelExecutorConfig,
    height: u64,
    worker_count: usize,
) -> Vec<u64> {
    let worker_count_u64 = worker_count.max(1) as u64;
    let reserved = config.low_fee_reserved_workers.min(worker_count_u64);
    let mut candidates =
        if (intent.lane_kind.is_low_fee() || intent.low_fee_credit_units > 0) && reserved > 0 {
            (0..reserved).collect::<Vec<_>>()
        } else if reserved < worker_count_u64 {
            (reserved..worker_count_u64).collect::<Vec<_>>()
        } else {
            (0..worker_count_u64).collect::<Vec<_>>()
        };
    if candidates.is_empty() {
        candidates = (0..worker_count_u64).collect::<Vec<_>>();
    }
    let hash = domain_hash(
        "PARALLEL-DETERMINISTIC-WORKER-ORDER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&config.determinism_seed),
            HashPart::Str(&intent.intent_id),
            HashPart::Int(height as i128),
            HashPart::Str(&intent.lane_kind.as_str()),
        ],
        32,
    );
    let offset = stable_mod(&hash, candidates.len() as u64) as usize;
    candidates.rotate_left(offset);
    candidates
}

fn worker_label(operator_label: &str, worker_index: u64) -> String {
    format!("{operator_label}-parallel-worker-{worker_index}")
}

fn stable_mod(hex_value: &str, modulus: u64) -> u64 {
    if modulus == 0 {
        return 0;
    }
    let prefix = hex_value.chars().take(16).collect::<String>();
    u64::from_str_radix(&prefix, 16).unwrap_or(0) % modulus
}

pub fn parallel_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn empty_parallel_root(domain: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID)], 32)
}

pub fn string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn string_set_root_from_set(domain: &str, values: &BTreeSet<String>) -> String {
    string_set_root(domain, &values.iter().cloned().collect::<Vec<_>>())
}

pub fn state_access_item_root(values: &[StateAccessItem]) -> String {
    let leaves = values
        .iter()
        .map(StateAccessItem::public_record)
        .collect::<Vec<_>>();
    merkle_root("PARALLEL-STATE-ACCESS-ROOT", &leaves)
}

pub fn parallel_execution_intent_root(values: &[ParallelExecutionIntent]) -> String {
    let leaves = values
        .iter()
        .map(ParallelExecutionIntent::public_record)
        .collect::<Vec<_>>();
    merkle_root("PARALLEL-EXECUTION-INTENT-ROOT", &leaves)
}

pub fn access_list_plan_root(values: &[AccessListPlan]) -> String {
    let leaves = values
        .iter()
        .map(AccessListPlan::public_record)
        .collect::<Vec<_>>();
    merkle_root("PARALLEL-ACCESS-LIST-PLAN-ROOT", &leaves)
}

pub fn conflict_graph_edge_root(values: &[ConflictGraphEdge]) -> String {
    let leaves = values
        .iter()
        .map(ConflictGraphEdge::public_record)
        .collect::<Vec<_>>();
    merkle_root("PARALLEL-CONFLICT-GRAPH-EDGE-ROOT", &leaves)
}

pub fn conflict_graph_root(values: &[ConflictGraph]) -> String {
    let leaves = values
        .iter()
        .map(ConflictGraph::public_record)
        .collect::<Vec<_>>();
    merkle_root("PARALLEL-CONFLICT-GRAPH-ROOT", &leaves)
}

pub fn parallel_execution_lane_root(values: &[ParallelExecutionLane]) -> String {
    let leaves = values
        .iter()
        .map(ParallelExecutionLane::public_record)
        .collect::<Vec<_>>();
    merkle_root("PARALLEL-EXECUTION-LANE-ROOT", &leaves)
}

pub fn worker_assignment_root(values: &[WorkerAssignment]) -> String {
    let leaves = values
        .iter()
        .map(WorkerAssignment::public_record)
        .collect::<Vec<_>>();
    merkle_root("PARALLEL-WORKER-ASSIGNMENT-ROOT", &leaves)
}

pub fn state_lock_lease_root(values: &[StateLockLease]) -> String {
    let leaves = values
        .iter()
        .map(StateLockLease::public_record)
        .collect::<Vec<_>>();
    merkle_root("PARALLEL-STATE-LOCK-LEASE-ROOT", &leaves)
}

pub fn retry_backoff_root(values: &[RetryBackoff]) -> String {
    let leaves = values
        .iter()
        .map(RetryBackoff::public_record)
        .collect::<Vec<_>>();
    merkle_root("PARALLEL-RETRY-BACKOFF-ROOT", &leaves)
}

pub fn parallel_execution_receipt_root(values: &[ParallelExecutionReceipt]) -> String {
    let leaves = values
        .iter()
        .map(ParallelExecutionReceipt::public_record)
        .collect::<Vec<_>>();
    merkle_root("PARALLEL-EXECUTION-RECEIPT-ROOT", &leaves)
}

pub fn parallel_execution_schedule_root(values: &[ParallelExecutionSchedule]) -> String {
    let leaves = values
        .iter()
        .map(ParallelExecutionSchedule::public_record)
        .collect::<Vec<_>>();
    merkle_root("PARALLEL-EXECUTION-SCHEDULE-ROOT", &leaves)
}

pub fn scheduler_pq_attestation_root(values: &[SchedulerPqAttestation]) -> String {
    let leaves = values
        .iter()
        .map(SchedulerPqAttestation::public_record)
        .collect::<Vec<_>>();
    merkle_root("PARALLEL-SCHEDULER-PQ-ATTESTATION-ROOT", &leaves)
}

pub fn parallel_execution_intent_root_from_map(
    values: &BTreeMap<String, ParallelExecutionIntent>,
) -> String {
    parallel_execution_intent_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn access_list_plan_root_from_map(values: &BTreeMap<String, AccessListPlan>) -> String {
    access_list_plan_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn conflict_graph_edge_root_from_map(values: &BTreeMap<String, ConflictGraphEdge>) -> String {
    conflict_graph_edge_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn conflict_graph_root_from_map(values: &BTreeMap<String, ConflictGraph>) -> String {
    conflict_graph_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn parallel_execution_lane_root_from_map(
    values: &BTreeMap<String, ParallelExecutionLane>,
) -> String {
    parallel_execution_lane_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn worker_assignment_root_from_map(values: &BTreeMap<String, WorkerAssignment>) -> String {
    worker_assignment_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn state_lock_lease_root_from_map(values: &BTreeMap<String, StateLockLease>) -> String {
    state_lock_lease_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn retry_backoff_root_from_map(values: &BTreeMap<String, RetryBackoff>) -> String {
    retry_backoff_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn parallel_execution_receipt_root_from_map(
    values: &BTreeMap<String, ParallelExecutionReceipt>,
) -> String {
    parallel_execution_receipt_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn parallel_execution_schedule_root_from_map(
    values: &BTreeMap<String, ParallelExecutionSchedule>,
) -> String {
    parallel_execution_schedule_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn scheduler_pq_attestation_root_from_map(
    values: &BTreeMap<String, SchedulerPqAttestation>,
) -> String {
    scheduler_pq_attestation_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn access_set_map_root(values: &BTreeMap<String, Vec<StateAccessItem>>) -> String {
    let leaves = values
        .iter()
        .map(|(intent_id, accesses)| {
            json!({
                "intent_id": intent_id,
                "access_root": state_access_item_root(accesses),
            })
        })
        .collect::<Vec<_>>();
    merkle_root("PARALLEL-ACCESS-SET-MAP", &leaves)
}

pub fn validate_no_cross_lane_conflicts(
    lanes: &[ParallelExecutionLane],
    graph: &ConflictGraph,
) -> ParallelExecutorResult<String> {
    let mut lane_by_intent = BTreeMap::new();
    let mut optimistic_by_lane = BTreeMap::new();
    for lane in lanes {
        lane.validate()?;
        optimistic_by_lane.insert(lane.lane_id.clone(), lane.optimistic);
        for intent_id in &lane.intent_ids {
            lane_by_intent.insert(intent_id.clone(), lane.lane_id.clone());
        }
    }
    for edge in graph.edges.values() {
        let left_lane = lane_by_intent.get(&edge.left_intent_id);
        let right_lane = lane_by_intent.get(&edge.right_intent_id);
        if let (Some(left_lane), Some(right_lane)) = (left_lane, right_lane) {
            let left_optimistic = optimistic_by_lane.get(left_lane).copied().unwrap_or(false);
            let right_optimistic = optimistic_by_lane.get(right_lane).copied().unwrap_or(false);
            if left_lane != right_lane && !left_optimistic && !right_optimistic {
                return Err(format!(
                    "cross-lane conflict {} is not covered by optimistic execution",
                    edge.edge_id
                ));
            }
        }
    }
    Ok(parallel_payload_root(
        "PARALLEL-CROSS-LANE-CONFLICT-VALIDATION",
        &json!({
            "lane_root": parallel_execution_lane_root(lanes),
            "graph_root": graph.graph_root(),
        }),
    ))
}

pub fn validate_state_lock_lease_set(
    leases: &[StateLockLease],
    height: u64,
) -> ParallelExecutorResult<String> {
    for lease in leases {
        lease.validate()?;
    }
    for (left_index, left) in leases.iter().enumerate() {
        for right in leases.iter().skip(left_index + 1) {
            if left.conflicts_with(right, height) {
                return Err(format!(
                    "state lock lease {} conflicts with {}",
                    left.lease_id, right.lease_id
                ));
            }
        }
    }
    Ok(state_lock_lease_root(leases))
}

pub fn validate_private_payload_safe_lanes(
    lanes: &[ParallelExecutionLane],
) -> ParallelExecutorResult<String> {
    for lane in lanes {
        lane.validate()?;
        if lane.lane_kind.is_private() && !lane.private_payload_safe {
            return Err(format!(
                "private lane {} is not marked private-payload safe",
                lane.lane_id
            ));
        }
    }
    Ok(parallel_execution_lane_root(lanes))
}

pub fn validate_scheduler_attestation(
    attestation: &SchedulerPqAttestation,
    schedule: &ParallelExecutionSchedule,
) -> ParallelExecutorResult<String> {
    attestation.validate()?;
    schedule.validate()?;
    if !attestation.verify_for_schedule(schedule) {
        return Err("scheduler PQ attestation does not verify for schedule".to_string());
    }
    Ok(attestation.attestation_root())
}

pub fn parallel_executor_state_root_from_record(record: &Value) -> String {
    parallel_payload_root("PARALLEL-EXECUTOR-STATE", record)
}

pub fn retry_policy_id(payload: &Value) -> String {
    parallel_payload_root("PARALLEL-RETRY-POLICY-ID", payload)
}

pub fn parallel_executor_config_id(payload: &Value) -> String {
    parallel_payload_root("PARALLEL-EXECUTOR-CONFIG-ID", payload)
}

#[allow(clippy::too_many_arguments)]
pub fn state_access_item_id(
    intent_id: &str,
    tx_id: &str,
    state_domain: &str,
    key_commitment: &str,
    mode: ParallelAccessMode,
    ordinal: u64,
    visibility: ParallelPayloadVisibility,
    private_hint_root: &str,
) -> String {
    domain_hash(
        "PARALLEL-STATE-ACCESS-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(tx_id),
            HashPart::Str(state_domain),
            HashPart::Str(key_commitment),
            HashPart::Str(mode.as_str()),
            HashPart::Int(ordinal as i128),
            HashPart::Str(visibility.as_str()),
            HashPart::Str(private_hint_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn parallel_execution_intent_id(
    tx_id: &str,
    lane_kind: &ParallelLaneKind,
    visibility: ParallelPayloadVisibility,
    payload_root: &str,
    public_metadata_root: &str,
    access_root: &str,
    fee_units: u64,
    low_fee_credit_units: u64,
    fuel_limit: u64,
    priority: u64,
    submitted_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "PARALLEL-EXECUTION-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(tx_id),
            HashPart::Str(&lane_kind.as_str()),
            HashPart::Str(visibility.as_str()),
            HashPart::Str(payload_root),
            HashPart::Str(public_metadata_root),
            HashPart::Str(access_root),
            HashPart::Int(fee_units as i128),
            HashPart::Int(low_fee_credit_units as i128),
            HashPart::Int(fuel_limit as i128),
            HashPart::Int(priority as i128),
            HashPart::Int(submitted_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

pub fn access_list_plan_id(
    height: u64,
    intent_root: &str,
    access_root: &str,
    read_root: &str,
    write_root: &str,
    private_access_root: &str,
) -> String {
    domain_hash(
        "PARALLEL-ACCESS-LIST-PLAN-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Str(intent_root),
            HashPart::Str(access_root),
            HashPart::Str(read_root),
            HashPart::Str(write_root),
            HashPart::Str(private_access_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn conflict_graph_edge_id(
    left_intent_id: &str,
    right_intent_id: &str,
    conflict_kind: &ParallelConflictKind,
    left_access_id: &str,
    right_access_id: &str,
    conflict_key: &str,
    access_root: &str,
) -> String {
    domain_hash(
        "PARALLEL-CONFLICT-GRAPH-EDGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(left_intent_id),
            HashPart::Str(right_intent_id),
            HashPart::Str(&conflict_kind.as_str()),
            HashPart::Str(left_access_id),
            HashPart::Str(right_access_id),
            HashPart::Str(conflict_key),
            HashPart::Str(access_root),
        ],
        32,
    )
}

pub fn conflict_graph_id(
    height: u64,
    plan_id: &str,
    node_root: &str,
    edge_root: &str,
    component_root: &str,
    max_degree: u64,
) -> String {
    domain_hash(
        "PARALLEL-CONFLICT-GRAPH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Str(plan_id),
            HashPart::Str(node_root),
            HashPart::Str(edge_root),
            HashPart::Str(component_root),
            HashPart::Int(max_degree as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn state_lock_lease_id(
    height: u64,
    holder_lane_id: &str,
    holder_worker_index: u64,
    intent_root: &str,
    state_domain: &str,
    key_commitment: &str,
    mode: StateLeaseMode,
    access_root: &str,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "PARALLEL-STATE-LOCK-LEASE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Str(holder_lane_id),
            HashPart::Int(holder_worker_index as i128),
            HashPart::Str(intent_root),
            HashPart::Str(state_domain),
            HashPart::Str(key_commitment),
            HashPart::Str(mode.as_str()),
            HashPart::Str(access_root),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn parallel_execution_lane_id(
    height: u64,
    lane_index: u64,
    worker_index: u64,
    lane_kind: &ParallelLaneKind,
    intent_ids: &[String],
    access_root: &str,
    write_root: &str,
    conflict_root: &str,
    optimistic: bool,
) -> String {
    domain_hash(
        "PARALLEL-EXECUTION-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Int(lane_index as i128),
            HashPart::Int(worker_index as i128),
            HashPart::Str(&lane_kind.as_str()),
            HashPart::Str(&string_set_root("PARALLEL-LANE-ID-INTENTS", intent_ids)),
            HashPart::Str(access_root),
            HashPart::Str(write_root),
            HashPart::Str(conflict_root),
            HashPart::Str(if optimistic { "optimistic" } else { "locked" }),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn worker_assignment_id(
    height: u64,
    worker_index: u64,
    worker_label: &str,
    lane_id: &str,
    lane_index: u64,
    deterministic_seed: &str,
    assigned_intent_root: &str,
    lease_root: &str,
) -> String {
    domain_hash(
        "PARALLEL-WORKER-ASSIGNMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Int(worker_index as i128),
            HashPart::Str(worker_label),
            HashPart::Str(lane_id),
            HashPart::Int(lane_index as i128),
            HashPart::Str(deterministic_seed),
            HashPart::Str(assigned_intent_root),
            HashPart::Str(lease_root),
        ],
        32,
    )
}

pub fn retry_backoff_id(
    intent_id: &str,
    schedule_id: &str,
    previous_lane_id: &str,
    attempt: u64,
    reason: &RetryBackoffReason,
    next_eligible_height: u64,
    conflict_root: &str,
) -> String {
    domain_hash(
        "PARALLEL-RETRY-BACKOFF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(schedule_id),
            HashPart::Str(previous_lane_id),
            HashPart::Int(attempt as i128),
            HashPart::Str(&reason.as_str()),
            HashPart::Int(next_eligible_height as i128),
            HashPart::Str(conflict_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn parallel_execution_receipt_id(
    schedule_id: &str,
    lane_id: &str,
    worker_index: u64,
    intent_id: &str,
    attempt: u64,
    status: &str,
    fuel_used: u64,
    fee_charged_units: u64,
    low_fee_credit_consumed: u64,
    state_delta_root: &str,
    event_root: &str,
    output_root: &str,
    validation_root: &str,
    retry_id: &str,
    private_payload_safe: bool,
    executed_at_height: u64,
) -> String {
    domain_hash(
        "PARALLEL-EXECUTION-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(schedule_id),
            HashPart::Str(lane_id),
            HashPart::Int(worker_index as i128),
            HashPart::Str(intent_id),
            HashPart::Int(attempt as i128),
            HashPart::Str(status),
            HashPart::Int(fuel_used as i128),
            HashPart::Int(fee_charged_units as i128),
            HashPart::Int(low_fee_credit_consumed as i128),
            HashPart::Str(state_delta_root),
            HashPart::Str(event_root),
            HashPart::Str(output_root),
            HashPart::Str(validation_root),
            HashPart::Str(retry_id),
            HashPart::Str(if private_payload_safe {
                "private-safe"
            } else {
                "public"
            }),
            HashPart::Int(executed_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn parallel_execution_schedule_id(
    height: u64,
    epoch: u64,
    config_root: &str,
    access_plan_id: &str,
    access_plan_root: &str,
    conflict_graph_id: &str,
    conflict_graph_root: &str,
    lane_root: &str,
    assignment_root: &str,
    lease_root: &str,
    determinism_root: &str,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "PARALLEL-EXECUTION-SCHEDULE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Int(epoch as i128),
            HashPart::Str(config_root),
            HashPart::Str(access_plan_id),
            HashPart::Str(access_plan_root),
            HashPart::Str(conflict_graph_id),
            HashPart::Str(conflict_graph_root),
            HashPart::Str(lane_root),
            HashPart::Str(assignment_root),
            HashPart::Str(lease_root),
            HashPart::Str(determinism_root),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

pub fn scheduler_signer_key_id(scheduler_label: &str) -> String {
    domain_hash(
        "PARALLEL-SCHEDULER-PQ-SIGNER-KEY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PARALLEL_EXECUTOR_PQ_SIGNATURE_SCHEME),
            HashPart::Str(scheduler_label),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn scheduler_attestation_transcript_hash(
    scheduler_label: &str,
    signer_key_id: &str,
    schedule_id: &str,
    schedule_root: &str,
    access_plan_root: &str,
    conflict_graph_root: &str,
    assignment_root: &str,
    lease_root: &str,
    receipt_root: &str,
    state_root: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "PARALLEL-SCHEDULER-PQ-TRANSCRIPT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PARALLEL_EXECUTOR_PQ_SIGNATURE_SCHEME),
            HashPart::Str(scheduler_label),
            HashPart::Str(signer_key_id),
            HashPart::Str(schedule_id),
            HashPart::Str(schedule_root),
            HashPart::Str(access_plan_root),
            HashPart::Str(conflict_graph_root),
            HashPart::Str(assignment_root),
            HashPart::Str(lease_root),
            HashPart::Str(receipt_root),
            HashPart::Str(state_root),
            HashPart::Int(signed_at_height as i128),
        ],
        32,
    )
}

pub fn scheduler_pq_signature_commitment(
    scheduler_label: &str,
    signer_key_id: &str,
    transcript_hash: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "PARALLEL-SCHEDULER-PQ-SIGNATURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PARALLEL_EXECUTOR_PQ_SIGNATURE_SCHEME),
            HashPart::Str(scheduler_label),
            HashPart::Str(signer_key_id),
            HashPart::Str(transcript_hash),
            HashPart::Int(signed_at_height as i128),
        ],
        64,
    )
}

pub fn scheduler_pq_attestation_id(
    scheduler_label: &str,
    signer_key_id: &str,
    schedule_id: &str,
    schedule_root: &str,
    transcript_hash: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "PARALLEL-SCHEDULER-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scheduler_label),
            HashPart::Str(signer_key_id),
            HashPart::Str(schedule_id),
            HashPart::Str(schedule_root),
            HashPart::Str(transcript_hash),
            HashPart::Int(signed_at_height as i128),
        ],
        32,
    )
}

fn conflict_components_from_edges(
    intent_ids: &[String],
    edges: &BTreeMap<String, ConflictGraphEdge>,
) -> Vec<Vec<String>> {
    let mut adjacency = intent_ids
        .iter()
        .map(|intent_id| (intent_id.clone(), BTreeSet::<String>::new()))
        .collect::<BTreeMap<_, _>>();
    for edge in edges.values() {
        adjacency
            .entry(edge.left_intent_id.clone())
            .or_default()
            .insert(edge.right_intent_id.clone());
        adjacency
            .entry(edge.right_intent_id.clone())
            .or_default()
            .insert(edge.left_intent_id.clone());
    }
    let mut remaining = adjacency.keys().cloned().collect::<BTreeSet<_>>();
    let mut components = Vec::new();
    while let Some(start) = remaining.iter().next().cloned() {
        let mut stack = vec![start.clone()];
        let mut component = BTreeSet::new();
        remaining.remove(&start);
        while let Some(node) = stack.pop() {
            component.insert(node.clone());
            if let Some(neighbors) = adjacency.get(&node) {
                for neighbor in neighbors {
                    if remaining.remove(neighbor) {
                        stack.push(neighbor.clone());
                    }
                }
            }
        }
        components.push(component.into_iter().collect::<Vec<_>>());
    }
    components.sort();
    components
}

fn conflict_component_root(components: &[Vec<String>]) -> String {
    let leaves = components
        .iter()
        .enumerate()
        .map(|(index, component)| {
            json!({
                "component_index": index as u64,
                "component_root": string_set_root("PARALLEL-CONFLICT-COMPONENT", component),
                "intent_count": component.len() as u64,
            })
        })
        .collect::<Vec<_>>();
    merkle_root("PARALLEL-CONFLICT-COMPONENT-ROOT", &leaves)
}

fn ensure_non_empty(value: &str, field: &str) -> ParallelExecutorResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, field: &str) -> ParallelExecutorResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_unique_strings(values: &[String], field: &str) -> ParallelExecutorResult<()> {
    let unique = values.iter().collect::<BTreeSet<_>>();
    if unique.len() != values.len() {
        Err(format!("{field} must be unique"))
    } else {
        Ok(())
    }
}
