use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateContractCrossShardSchedulerResult<T> = Result<T, String>;

pub const PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_PROTOCOL_VERSION: u32 = 1;
pub const PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_PROTOCOL_LABEL: &str =
    "nebula-private-contract-cross-shard-scheduler-v1";
pub const PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_DEVNET_HEIGHT: u64 = 2_176;
pub const PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_ENCRYPTION_SUITE: &str =
    "ML-KEM-768+sealed-cross-shard-contract-intent-v1";
pub const PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_WITNESS_SUITE: &str =
    "private-cross-shard-witness-availability-v1";
pub const PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_RECEIPT_SUITE: &str =
    "recursive-private-cross-shard-receipt-v1";
pub const PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_PQ_AUTH_SUITE: &str =
    "ML-DSA-65+SLH-DSA-SHAKE-128s-cross-shard-scheduler";
pub const PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_DEFAULT_MAX_SHARDS: u64 = 16;
pub const PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_DEFAULT_SLOT_WIDTH: u64 = 8;
pub const PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_DEFAULT_MAX_DEPENDENCIES: u64 = 8;
pub const PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_DEFAULT_MAX_RETRIES: u64 = 4;
pub const PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_DEFAULT_BASE_FEE_MICRO_XMR: u64 = 29;
pub const PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_DEFAULT_RETRY_FEE_MULTIPLIER_BPS: u64 = 1_250;
pub const PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_DEFAULT_PRIVACY_BUDGET_UNITS: u64 = 42_000;
pub const PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_DEFAULT_MIN_WITNESS_QUORUM: u64 = 3;
pub const PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentLane {
    PrivateSwap,
    Lending,
    Perps,
    Stablecoin,
    TokenMint,
    Governance,
    OracleUpdate,
    EmergencyExit,
}

impl IntentLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateSwap => "private_swap",
            Self::Lending => "lending",
            Self::Perps => "perps",
            Self::Stablecoin => "stablecoin",
            Self::TokenMint => "token_mint",
            Self::Governance => "governance",
            Self::OracleUpdate => "oracle_update",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn priority(self) -> u64 {
        match self {
            Self::EmergencyExit => 100,
            Self::Stablecoin => 90,
            Self::Lending => 84,
            Self::PrivateSwap => 80,
            Self::Perps => 76,
            Self::OracleUpdate => 70,
            Self::TokenMint => 64,
            Self::Governance => 48,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardRole {
    Source,
    Destination,
    ReadOnly,
    WitnessOnly,
    FeePayer,
    ReceiptSink,
}

impl ShardRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Destination => "destination",
            Self::ReadOnly => "read_only",
            Self::WitnessOnly => "witness_only",
            Self::FeePayer => "fee_payer",
            Self::ReceiptSink => "receipt_sink",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Encrypted,
    Admitted,
    Deferred,
    Scheduled,
    WitnessReady,
    Executing,
    Receipted,
    Retrying,
    Expired,
    Rejected,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Encrypted => "encrypted",
            Self::Admitted => "admitted",
            Self::Deferred => "deferred",
            Self::Scheduled => "scheduled",
            Self::WitnessReady => "witness_ready",
            Self::Executing => "executing",
            Self::Receipted => "receipted",
            Self::Retrying => "retrying",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Encrypted
                | Self::Admitted
                | Self::Deferred
                | Self::Scheduled
                | Self::WitnessReady
                | Self::Executing
                | Self::Retrying
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessHintStatus {
    Advertised,
    Available,
    Sampled,
    Pinned,
    Missing,
    Challenged,
    Expired,
}

impl WitnessHintStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Advertised => "advertised",
            Self::Available => "available",
            Self::Sampled => "sampled",
            Self::Pinned => "pinned",
            Self::Missing => "missing",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Available | Self::Sampled | Self::Pinned)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotStatus {
    Open,
    Reserved,
    Blocked,
    Ready,
    Executing,
    Committed,
    Failed,
    Cancelled,
}

impl SlotStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Blocked => "blocked",
            Self::Ready => "ready",
            Self::Executing => "executing",
            Self::Committed => "committed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Reserved | Self::Blocked | Self::Ready | Self::Executing
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BarrierStatus {
    Pending,
    Satisfied,
    WaitingReceipt,
    TimedOut,
    Cancelled,
}

impl BarrierStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Satisfied => "satisfied",
            Self::WaitingReceipt => "waiting_receipt",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn open(self) -> bool {
        matches!(self, Self::Pending | Self::WaitingReceipt)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Verified,
    Aggregated,
    Settled,
    Disputed,
    Replayed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::Aggregated => "aggregated",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Replayed => "replayed",
        }
    }

    pub fn final_for_scheduling(self) -> bool {
        matches!(self, Self::Verified | Self::Aggregated | Self::Settled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryStatus {
    None,
    FeeBounded,
    WaitingBackoff,
    Requeued,
    Exhausted,
}

impl RetryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::FeeBounded => "fee_bounded",
            Self::WaitingBackoff => "waiting_backoff",
            Self::Requeued => "requeued",
            Self::Exhausted => "exhausted",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub max_shards: u64,
    pub slot_width: u64,
    pub max_dependencies: u64,
    pub max_retries: u64,
    pub base_fee_micro_xmr: u64,
    pub retry_fee_multiplier_bps: u64,
    pub privacy_budget_units: u64,
    pub min_witness_quorum: u64,
    pub encryption_suite: String,
    pub witness_suite: String,
    pub receipt_suite: String,
    pub pq_auth_suite: String,
    pub hash_suite: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            max_shards: PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_DEFAULT_MAX_SHARDS,
            slot_width: PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_DEFAULT_SLOT_WIDTH,
            max_dependencies: PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_DEFAULT_MAX_DEPENDENCIES,
            max_retries: PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_DEFAULT_MAX_RETRIES,
            base_fee_micro_xmr: PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_DEFAULT_BASE_FEE_MICRO_XMR,
            retry_fee_multiplier_bps:
                PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_DEFAULT_RETRY_FEE_MULTIPLIER_BPS,
            privacy_budget_units:
                PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_DEFAULT_PRIVACY_BUDGET_UNITS,
            min_witness_quorum: PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_DEFAULT_MIN_WITNESS_QUORUM,
            encryption_suite: PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_ENCRYPTION_SUITE.to_string(),
            witness_suite: PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_WITNESS_SUITE.to_string(),
            receipt_suite: PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_RECEIPT_SUITE.to_string(),
            pq_auth_suite: PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_PQ_AUTH_SUITE.to_string(),
            hash_suite: PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_HASH_SUITE.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "max_shards": self.max_shards,
            "slot_width": self.slot_width,
            "max_dependencies": self.max_dependencies,
            "max_retries": self.max_retries,
            "base_fee_micro_xmr": self.base_fee_micro_xmr,
            "retry_fee_multiplier_bps": self.retry_fee_multiplier_bps,
            "privacy_budget_units": self.privacy_budget_units,
            "min_witness_quorum": self.min_witness_quorum,
            "encryption_suite": self.encryption_suite,
            "witness_suite": self.witness_suite,
            "receipt_suite": self.receipt_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "hash_suite": self.hash_suite,
        })
    }

    pub fn root(&self) -> String {
        scheduler_hash("CONFIG", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateContractCrossShardSchedulerResult<()> {
        if self.max_shards == 0
            || self.slot_width == 0
            || self.max_dependencies == 0
            || self.base_fee_micro_xmr == 0
            || self.privacy_budget_units == 0
            || self.min_witness_quorum == 0
        {
            return Err("cross-shard scheduler config limits must be positive".to_string());
        }
        if self.min_witness_quorum > self.max_shards {
            return Err("witness quorum cannot exceed max shard count".to_string());
        }
        if self.retry_fee_multiplier_bps > PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_MAX_BPS {
            return Err("retry fee multiplier exceeds max bps".to_string());
        }
        if self.encryption_suite.is_empty()
            || self.witness_suite.is_empty()
            || self.receipt_suite.is_empty()
            || self.pq_auth_suite.is_empty()
            || self.hash_suite.is_empty()
        {
            return Err("cross-shard scheduler suite labels must be populated".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardRef {
    pub shard_id: String,
    pub role: ShardRole,
    pub state_commitment: String,
    pub nullifier_root: String,
    pub read_set_root: String,
    pub write_set_root: String,
}

impl ShardRef {
    pub fn new(
        shard_id: &str,
        role: ShardRole,
        state_commitment: &str,
        nullifier_root: &str,
        read_set_root: &str,
        write_set_root: &str,
    ) -> PrivateContractCrossShardSchedulerResult<Self> {
        let item = Self {
            shard_id: shard_id.to_string(),
            role,
            state_commitment: state_commitment.to_string(),
            nullifier_root: nullifier_root.to_string(),
            read_set_root: read_set_root.to_string(),
            write_set_root: write_set_root.to_string(),
        };
        item.validate()?;
        Ok(item)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "shard_id": self.shard_id,
            "role": self.role.as_str(),
            "state_commitment": self.state_commitment,
            "nullifier_root": self.nullifier_root,
            "read_set_root": self.read_set_root,
            "write_set_root": self.write_set_root,
        })
    }

    pub fn root(&self) -> String {
        scheduler_hash("SHARD-REF", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateContractCrossShardSchedulerResult<()> {
        if self.shard_id.is_empty()
            || self.state_commitment.is_empty()
            || self.nullifier_root.is_empty()
            || self.read_set_root.is_empty()
            || self.write_set_root.is_empty()
        {
            return Err("shard reference commitments must be populated".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudget {
    pub budget_id: String,
    pub owner_commitment: String,
    pub allowed_units: u64,
    pub consumed_units: u64,
    pub epoch: u64,
    pub policy_root: String,
}

impl PrivacyBudget {
    pub fn new(
        budget_id: &str,
        owner_commitment: &str,
        allowed_units: u64,
        consumed_units: u64,
        epoch: u64,
        policy_root: &str,
    ) -> PrivateContractCrossShardSchedulerResult<Self> {
        let item = Self {
            budget_id: budget_id.to_string(),
            owner_commitment: owner_commitment.to_string(),
            allowed_units,
            consumed_units,
            epoch,
            policy_root: policy_root.to_string(),
        };
        item.validate()?;
        Ok(item)
    }

    pub fn remaining_units(&self) -> u64 {
        self.allowed_units.saturating_sub(self.consumed_units)
    }

    pub fn can_spend(&self, units: u64) -> bool {
        self.remaining_units() >= units
    }

    pub fn spend(&mut self, units: u64) -> PrivateContractCrossShardSchedulerResult<()> {
        if !self.can_spend(units) {
            return Err("privacy budget would be exceeded".to_string());
        }
        self.consumed_units = self.consumed_units.saturating_add(units);
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "owner_commitment": self.owner_commitment,
            "allowed_units": self.allowed_units,
            "consumed_units": self.consumed_units,
            "remaining_units": self.remaining_units(),
            "epoch": self.epoch,
            "policy_root": self.policy_root,
        })
    }

    pub fn root(&self) -> String {
        scheduler_hash("PRIVACY-BUDGET", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateContractCrossShardSchedulerResult<()> {
        if self.budget_id.is_empty()
            || self.owner_commitment.is_empty()
            || self.policy_root.is_empty()
        {
            return Err("privacy budget identifiers must be populated".to_string());
        }
        if self.allowed_units == 0 {
            return Err("privacy budget allowed units must be positive".to_string());
        }
        if self.consumed_units > self.allowed_units {
            return Err("privacy budget consumed units exceed allowance".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedShardIntent {
    pub intent_id: String,
    pub lane: IntentLane,
    pub status: IntentStatus,
    pub submitter_commitment: String,
    pub encrypted_payload_root: String,
    pub capability_root: String,
    pub shard_refs: Vec<ShardRef>,
    pub dependency_ids: Vec<String>,
    pub budget_id: String,
    pub privacy_cost_units: u64,
    pub fee_limit_micro_xmr: u64,
    pub retry_count: u64,
    pub retry_status: RetryStatus,
    pub submitted_height: u64,
    pub expiry_height: u64,
}

impl EncryptedShardIntent {
    pub fn new(
        intent_id: &str,
        lane: IntentLane,
        submitter_commitment: &str,
        encrypted_payload_root: &str,
        capability_root: &str,
        shard_refs: Vec<ShardRef>,
        dependency_ids: Vec<String>,
        budget_id: &str,
        privacy_cost_units: u64,
        fee_limit_micro_xmr: u64,
        submitted_height: u64,
        expiry_height: u64,
    ) -> PrivateContractCrossShardSchedulerResult<Self> {
        let item = Self {
            intent_id: intent_id.to_string(),
            lane,
            status: IntentStatus::Encrypted,
            submitter_commitment: submitter_commitment.to_string(),
            encrypted_payload_root: encrypted_payload_root.to_string(),
            capability_root: capability_root.to_string(),
            shard_refs,
            dependency_ids,
            budget_id: budget_id.to_string(),
            privacy_cost_units,
            fee_limit_micro_xmr,
            retry_count: 0,
            retry_status: RetryStatus::None,
            submitted_height,
            expiry_height,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn shard_ids(&self) -> Vec<String> {
        self.shard_refs
            .iter()
            .map(|shard| shard.shard_id.clone())
            .collect()
    }

    pub fn shard_root(&self) -> String {
        let records = self
            .shard_refs
            .iter()
            .map(ShardRef::public_record)
            .collect::<Vec<_>>();
        merkle_root("PRIVATE-CONTRACT-CROSS-SHARD-SCHEDULER-SHARD", &records)
    }

    pub fn dependency_root(&self) -> String {
        let records = self
            .dependency_ids
            .iter()
            .map(|dependency_id| json!({ "dependency_id": dependency_id }))
            .collect::<Vec<_>>();
        merkle_root(
            "PRIVATE-CONTRACT-CROSS-SHARD-SCHEDULER-DEPENDENCY",
            &records,
        )
    }

    pub fn required_fee(&self, config: &Config) -> u64 {
        let shard_count = self.shard_refs.len() as u64;
        let retry_premium = self
            .retry_count
            .saturating_mul(config.retry_fee_multiplier_bps)
            .saturating_mul(config.base_fee_micro_xmr)
            / PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_MAX_BPS;
        config
            .base_fee_micro_xmr
            .saturating_mul(shard_count.max(1))
            .saturating_add(retry_premium)
    }

    pub fn fee_bounded(&self, config: &Config) -> bool {
        self.required_fee(config) <= self.fee_limit_micro_xmr
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status.is_live() && self.expiry_height >= height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "lane": self.lane.as_str(),
            "lane_priority": self.lane.priority(),
            "status": self.status.as_str(),
            "submitter_commitment": self.submitter_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "capability_root": self.capability_root,
            "shard_root": self.shard_root(),
            "shard_ids": self.shard_ids(),
            "shard_refs": self.shard_refs.iter().map(ShardRef::public_record).collect::<Vec<_>>(),
            "dependency_root": self.dependency_root(),
            "dependency_ids": self.dependency_ids,
            "budget_id": self.budget_id,
            "privacy_cost_units": self.privacy_cost_units,
            "fee_limit_micro_xmr": self.fee_limit_micro_xmr,
            "retry_count": self.retry_count,
            "retry_status": self.retry_status.as_str(),
            "submitted_height": self.submitted_height,
            "expiry_height": self.expiry_height,
        })
    }

    pub fn root(&self) -> String {
        scheduler_hash(
            "ENCRYPTED-SHARD-INTENT",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self) -> PrivateContractCrossShardSchedulerResult<()> {
        if self.intent_id.is_empty()
            || self.submitter_commitment.is_empty()
            || self.encrypted_payload_root.is_empty()
            || self.capability_root.is_empty()
            || self.budget_id.is_empty()
        {
            return Err("encrypted shard intent identifiers must be populated".to_string());
        }
        if self.shard_refs.is_empty() {
            return Err("encrypted shard intent must reference at least one shard".to_string());
        }
        if self.privacy_cost_units == 0 {
            return Err("encrypted shard intent privacy cost must be positive".to_string());
        }
        if self.fee_limit_micro_xmr == 0 {
            return Err("encrypted shard intent fee limit must be positive".to_string());
        }
        if self.expiry_height < self.submitted_height {
            return Err("encrypted shard intent expiry precedes submission".to_string());
        }
        let mut shard_ids = BTreeSet::new();
        for shard_ref in &self.shard_refs {
            shard_ref.validate()?;
            if !shard_ids.insert(shard_ref.shard_id.clone()) {
                return Err("encrypted shard intent contains duplicate shard ref".to_string());
            }
        }
        let mut dependencies = BTreeSet::new();
        for dependency_id in &self.dependency_ids {
            if dependency_id.is_empty() {
                return Err("encrypted shard intent dependency id is empty".to_string());
            }
            if !dependencies.insert(dependency_id.clone()) {
                return Err("encrypted shard intent contains duplicate dependency".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessAvailabilityHint {
    pub hint_id: String,
    pub intent_id: String,
    pub shard_id: String,
    pub status: WitnessHintStatus,
    pub provider_commitment: String,
    pub witness_commitment: String,
    pub availability_window_start: u64,
    pub availability_window_end: u64,
    pub sample_count: u64,
    pub fee_quote_micro_xmr: u64,
}

impl WitnessAvailabilityHint {
    pub fn new(
        hint_id: &str,
        intent_id: &str,
        shard_id: &str,
        provider_commitment: &str,
        witness_commitment: &str,
        availability_window_start: u64,
        availability_window_end: u64,
        fee_quote_micro_xmr: u64,
    ) -> PrivateContractCrossShardSchedulerResult<Self> {
        let item = Self {
            hint_id: hint_id.to_string(),
            intent_id: intent_id.to_string(),
            shard_id: shard_id.to_string(),
            status: WitnessHintStatus::Advertised,
            provider_commitment: provider_commitment.to_string(),
            witness_commitment: witness_commitment.to_string(),
            availability_window_start,
            availability_window_end,
            sample_count: 0,
            fee_quote_micro_xmr,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn available_at(&self, height: u64) -> bool {
        self.status.usable()
            && self.availability_window_start <= height
            && self.availability_window_end >= height
    }

    pub fn mark_available(&mut self) {
        self.status = WitnessHintStatus::Available;
    }

    pub fn sample(&mut self) {
        self.status = WitnessHintStatus::Sampled;
        self.sample_count = self.sample_count.saturating_add(1);
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "intent_id": self.intent_id,
            "shard_id": self.shard_id,
            "status": self.status.as_str(),
            "provider_commitment": self.provider_commitment,
            "witness_commitment": self.witness_commitment,
            "availability_window_start": self.availability_window_start,
            "availability_window_end": self.availability_window_end,
            "sample_count": self.sample_count,
            "fee_quote_micro_xmr": self.fee_quote_micro_xmr,
        })
    }

    pub fn root(&self) -> String {
        scheduler_hash("WITNESS-HINT", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateContractCrossShardSchedulerResult<()> {
        if self.hint_id.is_empty()
            || self.intent_id.is_empty()
            || self.shard_id.is_empty()
            || self.provider_commitment.is_empty()
            || self.witness_commitment.is_empty()
        {
            return Err("witness availability hint identifiers must be populated".to_string());
        }
        if self.availability_window_end < self.availability_window_start {
            return Err("witness availability hint window is invalid".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyBarrier {
    pub barrier_id: String,
    pub intent_id: String,
    pub required_receipt_ids: Vec<String>,
    pub required_shard_ids: Vec<String>,
    pub status: BarrierStatus,
    pub opened_height: u64,
    pub timeout_height: u64,
}

impl DependencyBarrier {
    pub fn new(
        barrier_id: &str,
        intent_id: &str,
        required_receipt_ids: Vec<String>,
        required_shard_ids: Vec<String>,
        opened_height: u64,
        timeout_height: u64,
    ) -> PrivateContractCrossShardSchedulerResult<Self> {
        let item = Self {
            barrier_id: barrier_id.to_string(),
            intent_id: intent_id.to_string(),
            required_receipt_ids,
            required_shard_ids,
            status: BarrierStatus::Pending,
            opened_height,
            timeout_height,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn receipt_root(&self) -> String {
        let records = self
            .required_receipt_ids
            .iter()
            .map(|receipt_id| json!({ "receipt_id": receipt_id }))
            .collect::<Vec<_>>();
        merkle_root(
            "PRIVATE-CONTRACT-CROSS-SHARD-SCHEDULER-BARRIER-RECEIPT",
            &records,
        )
    }

    pub fn shard_root(&self) -> String {
        let records = self
            .required_shard_ids
            .iter()
            .map(|shard_id| json!({ "shard_id": shard_id }))
            .collect::<Vec<_>>();
        merkle_root(
            "PRIVATE-CONTRACT-CROSS-SHARD-SCHEDULER-BARRIER-SHARD",
            &records,
        )
    }

    pub fn satisfied_by(&self, receipts: &BTreeMap<String, CrossShardReceipt>) -> bool {
        self.required_receipt_ids.iter().all(|receipt_id| {
            receipts
                .get(receipt_id)
                .map(|r| r.status.final_for_scheduling())
                .unwrap_or(false)
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "barrier_id": self.barrier_id,
            "intent_id": self.intent_id,
            "required_receipt_ids": self.required_receipt_ids,
            "required_shard_ids": self.required_shard_ids,
            "receipt_root": self.receipt_root(),
            "shard_root": self.shard_root(),
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "timeout_height": self.timeout_height,
        })
    }

    pub fn root(&self) -> String {
        scheduler_hash(
            "DEPENDENCY-BARRIER",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self) -> PrivateContractCrossShardSchedulerResult<()> {
        if self.barrier_id.is_empty() || self.intent_id.is_empty() {
            return Err("dependency barrier identifiers must be populated".to_string());
        }
        if self.required_receipt_ids.is_empty() && self.required_shard_ids.is_empty() {
            return Err("dependency barrier must require receipts or shards".to_string());
        }
        if self.timeout_height < self.opened_height {
            return Err("dependency barrier timeout precedes open height".to_string());
        }
        ensure_unique("dependency barrier receipt", &self.required_receipt_ids)?;
        ensure_unique("dependency barrier shard", &self.required_shard_ids)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParallelExecutionSlot {
    pub slot_id: String,
    pub slot_index: u64,
    pub shard_id: String,
    pub assigned_intent_ids: Vec<String>,
    pub barrier_ids: Vec<String>,
    pub witness_hint_ids: Vec<String>,
    pub status: SlotStatus,
    pub scheduled_height: u64,
    pub fee_reserved_micro_xmr: u64,
}

impl ParallelExecutionSlot {
    pub fn new(
        slot_id: &str,
        slot_index: u64,
        shard_id: &str,
        assigned_intent_ids: Vec<String>,
        barrier_ids: Vec<String>,
        witness_hint_ids: Vec<String>,
        scheduled_height: u64,
        fee_reserved_micro_xmr: u64,
    ) -> PrivateContractCrossShardSchedulerResult<Self> {
        let item = Self {
            slot_id: slot_id.to_string(),
            slot_index,
            shard_id: shard_id.to_string(),
            assigned_intent_ids,
            barrier_ids,
            witness_hint_ids,
            status: SlotStatus::Reserved,
            scheduled_height,
            fee_reserved_micro_xmr,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn intent_root(&self) -> String {
        let records = self
            .assigned_intent_ids
            .iter()
            .map(|intent_id| json!({ "intent_id": intent_id }))
            .collect::<Vec<_>>();
        merkle_root(
            "PRIVATE-CONTRACT-CROSS-SHARD-SCHEDULER-SLOT-INTENT",
            &records,
        )
    }

    pub fn barrier_root(&self) -> String {
        let records = self
            .barrier_ids
            .iter()
            .map(|barrier_id| json!({ "barrier_id": barrier_id }))
            .collect::<Vec<_>>();
        merkle_root(
            "PRIVATE-CONTRACT-CROSS-SHARD-SCHEDULER-SLOT-BARRIER",
            &records,
        )
    }

    pub fn witness_hint_root(&self) -> String {
        let records = self
            .witness_hint_ids
            .iter()
            .map(|hint_id| json!({ "hint_id": hint_id }))
            .collect::<Vec<_>>();
        merkle_root(
            "PRIVATE-CONTRACT-CROSS-SHARD-SCHEDULER-SLOT-WITNESS",
            &records,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "slot_id": self.slot_id,
            "slot_index": self.slot_index,
            "shard_id": self.shard_id,
            "assigned_intent_ids": self.assigned_intent_ids,
            "barrier_ids": self.barrier_ids,
            "witness_hint_ids": self.witness_hint_ids,
            "intent_root": self.intent_root(),
            "barrier_root": self.barrier_root(),
            "witness_hint_root": self.witness_hint_root(),
            "status": self.status.as_str(),
            "scheduled_height": self.scheduled_height,
            "fee_reserved_micro_xmr": self.fee_reserved_micro_xmr,
        })
    }

    pub fn root(&self) -> String {
        scheduler_hash(
            "PARALLEL-EXECUTION-SLOT",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self) -> PrivateContractCrossShardSchedulerResult<()> {
        if self.slot_id.is_empty() || self.shard_id.is_empty() {
            return Err("parallel execution slot identifiers must be populated".to_string());
        }
        if self.assigned_intent_ids.is_empty() {
            return Err("parallel execution slot must assign at least one intent".to_string());
        }
        ensure_unique("parallel execution slot intent", &self.assigned_intent_ids)?;
        ensure_unique("parallel execution slot barrier", &self.barrier_ids)?;
        ensure_unique(
            "parallel execution slot witness hint",
            &self.witness_hint_ids,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossShardReceipt {
    pub receipt_id: String,
    pub intent_id: String,
    pub slot_id: String,
    pub source_shard_id: String,
    pub destination_shard_id: String,
    pub status: ReceiptStatus,
    pub output_commitment: String,
    pub spent_nullifier_root: String,
    pub created_note_root: String,
    pub proof_commitment: String,
    pub fee_paid_micro_xmr: u64,
    pub settled_height: u64,
}

impl CrossShardReceipt {
    pub fn new(
        receipt_id: &str,
        intent_id: &str,
        slot_id: &str,
        source_shard_id: &str,
        destination_shard_id: &str,
        output_commitment: &str,
        spent_nullifier_root: &str,
        created_note_root: &str,
        proof_commitment: &str,
        fee_paid_micro_xmr: u64,
        settled_height: u64,
    ) -> PrivateContractCrossShardSchedulerResult<Self> {
        let item = Self {
            receipt_id: receipt_id.to_string(),
            intent_id: intent_id.to_string(),
            slot_id: slot_id.to_string(),
            source_shard_id: source_shard_id.to_string(),
            destination_shard_id: destination_shard_id.to_string(),
            status: ReceiptStatus::Verified,
            output_commitment: output_commitment.to_string(),
            spent_nullifier_root: spent_nullifier_root.to_string(),
            created_note_root: created_note_root.to_string(),
            proof_commitment: proof_commitment.to_string(),
            fee_paid_micro_xmr,
            settled_height,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "intent_id": self.intent_id,
            "slot_id": self.slot_id,
            "source_shard_id": self.source_shard_id,
            "destination_shard_id": self.destination_shard_id,
            "status": self.status.as_str(),
            "output_commitment": self.output_commitment,
            "spent_nullifier_root": self.spent_nullifier_root,
            "created_note_root": self.created_note_root,
            "proof_commitment": self.proof_commitment,
            "fee_paid_micro_xmr": self.fee_paid_micro_xmr,
            "settled_height": self.settled_height,
        })
    }

    pub fn root(&self) -> String {
        scheduler_hash(
            "CROSS-SHARD-RECEIPT",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self) -> PrivateContractCrossShardSchedulerResult<()> {
        if self.receipt_id.is_empty()
            || self.intent_id.is_empty()
            || self.slot_id.is_empty()
            || self.source_shard_id.is_empty()
            || self.destination_shard_id.is_empty()
            || self.output_commitment.is_empty()
            || self.spent_nullifier_root.is_empty()
            || self.created_note_root.is_empty()
            || self.proof_commitment.is_empty()
        {
            return Err("cross-shard receipt identifiers must be populated".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryEnvelope {
    pub retry_id: String,
    pub intent_id: String,
    pub previous_slot_id: String,
    pub retry_count: u64,
    pub backoff_until_height: u64,
    pub fee_ceiling_micro_xmr: u64,
    pub retry_fee_micro_xmr: u64,
    pub reason_code: String,
}

impl RetryEnvelope {
    pub fn new(
        retry_id: &str,
        intent: &EncryptedShardIntent,
        previous_slot_id: &str,
        backoff_until_height: u64,
        retry_fee_micro_xmr: u64,
        reason_code: &str,
    ) -> PrivateContractCrossShardSchedulerResult<Self> {
        let item = Self {
            retry_id: retry_id.to_string(),
            intent_id: intent.intent_id.clone(),
            previous_slot_id: previous_slot_id.to_string(),
            retry_count: intent.retry_count.saturating_add(1),
            backoff_until_height,
            fee_ceiling_micro_xmr: intent.fee_limit_micro_xmr,
            retry_fee_micro_xmr,
            reason_code: reason_code.to_string(),
        };
        item.validate()?;
        Ok(item)
    }

    pub fn fee_bounded(&self) -> bool {
        self.retry_fee_micro_xmr <= self.fee_ceiling_micro_xmr
    }

    pub fn public_record(&self) -> Value {
        json!({
            "retry_id": self.retry_id,
            "intent_id": self.intent_id,
            "previous_slot_id": self.previous_slot_id,
            "retry_count": self.retry_count,
            "backoff_until_height": self.backoff_until_height,
            "fee_ceiling_micro_xmr": self.fee_ceiling_micro_xmr,
            "retry_fee_micro_xmr": self.retry_fee_micro_xmr,
            "fee_bounded": self.fee_bounded(),
            "reason_code": self.reason_code,
        })
    }

    pub fn root(&self) -> String {
        scheduler_hash("RETRY-ENVELOPE", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateContractCrossShardSchedulerResult<()> {
        if self.retry_id.is_empty()
            || self.intent_id.is_empty()
            || self.previous_slot_id.is_empty()
            || self.reason_code.is_empty()
        {
            return Err("retry envelope identifiers must be populated".to_string());
        }
        if self.retry_count == 0 {
            return Err("retry envelope count must be positive".to_string());
        }
        if self.retry_fee_micro_xmr > self.fee_ceiling_micro_xmr {
            return Err("retry envelope exceeds fee ceiling".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub privacy_budget_root: String,
    pub intent_root: String,
    pub witness_hint_root: String,
    pub barrier_root: String,
    pub slot_root: String,
    pub receipt_root: String,
    pub retry_root: String,
    pub shard_pressure_root: String,
    pub lane_pressure_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "privacy_budget_root": self.privacy_budget_root,
            "intent_root": self.intent_root,
            "witness_hint_root": self.witness_hint_root,
            "barrier_root": self.barrier_root,
            "slot_root": self.slot_root,
            "receipt_root": self.receipt_root,
            "retry_root": self.retry_root,
            "shard_pressure_root": self.shard_pressure_root,
            "lane_pressure_root": self.lane_pressure_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub privacy_budget_count: u64,
    pub encrypted_intent_count: u64,
    pub live_intent_count: u64,
    pub witness_hint_count: u64,
    pub usable_witness_hint_count: u64,
    pub open_barrier_count: u64,
    pub active_slot_count: u64,
    pub receipt_count: u64,
    pub retry_count: u64,
    pub total_privacy_budget_remaining: u64,
    pub total_fee_reserved_micro_xmr: u64,
    pub total_fee_paid_micro_xmr: u64,
    pub shard_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "privacy_budget_count": self.privacy_budget_count,
            "encrypted_intent_count": self.encrypted_intent_count,
            "live_intent_count": self.live_intent_count,
            "witness_hint_count": self.witness_hint_count,
            "usable_witness_hint_count": self.usable_witness_hint_count,
            "open_barrier_count": self.open_barrier_count,
            "active_slot_count": self.active_slot_count,
            "receipt_count": self.receipt_count,
            "retry_count": self.retry_count,
            "total_privacy_budget_remaining": self.total_privacy_budget_remaining,
            "total_fee_reserved_micro_xmr": self.total_fee_reserved_micro_xmr,
            "total_fee_paid_micro_xmr": self.total_fee_paid_micro_xmr,
            "shard_count": self.shard_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub privacy_budgets: BTreeMap<String, PrivacyBudget>,
    pub intents: BTreeMap<String, EncryptedShardIntent>,
    pub witness_hints: BTreeMap<String, WitnessAvailabilityHint>,
    pub barriers: BTreeMap<String, DependencyBarrier>,
    pub slots: BTreeMap<String, ParallelExecutionSlot>,
    pub receipts: BTreeMap<String, CrossShardReceipt>,
    pub retries: BTreeMap<String, RetryEnvelope>,
    pub shard_pressure: BTreeMap<String, u64>,
    pub lane_pressure: BTreeMap<IntentLane, u64>,
    pub paused: bool,
}

impl State {
    pub fn new(height: u64, config: Config) -> PrivateContractCrossShardSchedulerResult<Self> {
        let state = Self {
            height,
            config,
            privacy_budgets: BTreeMap::new(),
            intents: BTreeMap::new(),
            witness_hints: BTreeMap::new(),
            barriers: BTreeMap::new(),
            slots: BTreeMap::new(),
            receipts: BTreeMap::new(),
            retries: BTreeMap::new(),
            shard_pressure: BTreeMap::new(),
            lane_pressure: BTreeMap::new(),
            paused: false,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn devnet() -> PrivateContractCrossShardSchedulerResult<State> {
        let mut state = State::new(
            PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_DEVNET_HEIGHT,
            Config::devnet(),
        )?;
        let budget = PrivacyBudget::new(
            "budget-devnet-maker",
            "owner:private-contract-maker-commitment",
            state.config.privacy_budget_units,
            0,
            1,
            "policy:devnet-cross-shard-budget",
        )?;
        state.add_privacy_budget(budget)?;
        let source = ShardRef::new(
            "shard-a",
            ShardRole::Source,
            "state:shard-a:2176",
            "nullifier:shard-a:2176",
            "read:set:swap:a",
            "write:set:swap:a",
        )?;
        let destination = ShardRef::new(
            "shard-b",
            ShardRole::Destination,
            "state:shard-b:2176",
            "nullifier:shard-b:2176",
            "read:set:swap:b",
            "write:set:swap:b",
        )?;
        let intent = EncryptedShardIntent::new(
            "intent-devnet-private-swap",
            IntentLane::PrivateSwap,
            "submitter:sealed-wallet-maker",
            "encrypted-payload:swap-intent",
            "capability:private-swap-cross-shard",
            vec![source, destination],
            Vec::new(),
            "budget-devnet-maker",
            620,
            500,
            state.height,
            state.height.saturating_add(12),
        )?;
        state.admit_intent(intent)?;
        let hint_a = WitnessAvailabilityHint::new(
            "hint-devnet-shard-a",
            "intent-devnet-private-swap",
            "shard-a",
            "provider:witness-a",
            "witness:commitment:a",
            state.height,
            state.height.saturating_add(6),
            19,
        )?;
        let hint_b = WitnessAvailabilityHint::new(
            "hint-devnet-shard-b",
            "intent-devnet-private-swap",
            "shard-b",
            "provider:witness-b",
            "witness:commitment:b",
            state.height,
            state.height.saturating_add(6),
            21,
        )?;
        state.add_witness_hint(hint_a)?;
        state.add_witness_hint(hint_b)?;
        state.mark_witness_available("hint-devnet-shard-a")?;
        state.mark_witness_available("hint-devnet-shard-b")?;
        state.schedule_slot(
            "slot-devnet-shard-a-0",
            0,
            "shard-a",
            vec!["intent-devnet-private-swap".to_string()],
            Vec::new(),
        )?;
        state.commit_receipt(CrossShardReceipt::new(
            "receipt-devnet-private-swap",
            "intent-devnet-private-swap",
            "slot-devnet-shard-a-0",
            "shard-a",
            "shard-b",
            "output:private-swap-note",
            "spent:nullifier:private-swap",
            "created:note:private-swap",
            "proof:recursive-cross-shard-private-swap",
            58,
            state.height.saturating_add(1),
        )?)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateContractCrossShardSchedulerResult<()> {
        if height < self.height {
            return Err("cross-shard scheduler height cannot move backwards".to_string());
        }
        self.height = height;
        self.expire_old_items();
        Ok(())
    }

    pub fn update_height(&mut self, height: u64) -> PrivateContractCrossShardSchedulerResult<()> {
        self.set_height(height)
    }

    pub fn pause(&mut self) {
        self.paused = true;
    }

    pub fn resume(&mut self) {
        self.paused = false;
    }

    pub fn add_privacy_budget(
        &mut self,
        budget: PrivacyBudget,
    ) -> PrivateContractCrossShardSchedulerResult<()> {
        if self.privacy_budgets.contains_key(&budget.budget_id) {
            return Err("privacy budget already exists".to_string());
        }
        budget.validate()?;
        self.privacy_budgets
            .insert(budget.budget_id.clone(), budget);
        Ok(())
    }

    pub fn admit_intent(
        &mut self,
        mut intent: EncryptedShardIntent,
    ) -> PrivateContractCrossShardSchedulerResult<String> {
        if self.paused {
            return Err("cross-shard scheduler is paused".to_string());
        }
        if self.intents.contains_key(&intent.intent_id) {
            return Err("encrypted shard intent already exists".to_string());
        }
        if intent.shard_refs.len() as u64 > self.config.max_shards {
            return Err("encrypted shard intent exceeds max shard fanout".to_string());
        }
        if intent.dependency_ids.len() as u64 > self.config.max_dependencies {
            return Err("encrypted shard intent exceeds max dependency count".to_string());
        }
        if !intent.fee_bounded(&self.config) {
            return Err("encrypted shard intent is not fee bounded".to_string());
        }
        let budget = self
            .privacy_budgets
            .get_mut(&intent.budget_id)
            .ok_or_else(|| {
                "encrypted shard intent references missing privacy budget".to_string()
            })?;
        budget.spend(intent.privacy_cost_units)?;
        intent.status = if intent.dependency_ids.is_empty() {
            IntentStatus::Admitted
        } else {
            IntentStatus::Deferred
        };
        for shard_id in intent.shard_ids() {
            let pressure = self.shard_pressure.entry(shard_id).or_insert(0);
            *pressure = pressure.saturating_add(1);
        }
        let lane_pressure = self.lane_pressure.entry(intent.lane).or_insert(0);
        *lane_pressure = lane_pressure.saturating_add(intent.privacy_cost_units);
        let root = intent.root();
        self.intents.insert(intent.intent_id.clone(), intent);
        Ok(root)
    }

    pub fn add_witness_hint(
        &mut self,
        hint: WitnessAvailabilityHint,
    ) -> PrivateContractCrossShardSchedulerResult<String> {
        if self.witness_hints.contains_key(&hint.hint_id) {
            return Err("witness availability hint already exists".to_string());
        }
        if !self.intents.contains_key(&hint.intent_id) {
            return Err("witness availability hint references missing intent".to_string());
        }
        hint.validate()?;
        let root = hint.root();
        self.witness_hints.insert(hint.hint_id.clone(), hint);
        Ok(root)
    }

    pub fn mark_witness_available(
        &mut self,
        hint_id: &str,
    ) -> PrivateContractCrossShardSchedulerResult<String> {
        let hint = self
            .witness_hints
            .get_mut(hint_id)
            .ok_or_else(|| "witness availability hint missing".to_string())?;
        hint.mark_available();
        Ok(hint.root())
    }

    pub fn sample_witness_hint(
        &mut self,
        hint_id: &str,
    ) -> PrivateContractCrossShardSchedulerResult<String> {
        let hint = self
            .witness_hints
            .get_mut(hint_id)
            .ok_or_else(|| "witness availability hint missing".to_string())?;
        hint.sample();
        Ok(hint.root())
    }

    pub fn open_dependency_barrier(
        &mut self,
        barrier: DependencyBarrier,
    ) -> PrivateContractCrossShardSchedulerResult<String> {
        if self.barriers.contains_key(&barrier.barrier_id) {
            return Err("dependency barrier already exists".to_string());
        }
        if !self.intents.contains_key(&barrier.intent_id) {
            return Err("dependency barrier references missing intent".to_string());
        }
        barrier.validate()?;
        let root = barrier.root();
        self.barriers.insert(barrier.barrier_id.clone(), barrier);
        Ok(root)
    }

    pub fn refresh_barriers(&mut self) {
        for barrier in self.barriers.values_mut() {
            if barrier.status == BarrierStatus::Pending && barrier.satisfied_by(&self.receipts) {
                barrier.status = BarrierStatus::Satisfied;
            }
            if barrier.status.open() && barrier.timeout_height < self.height {
                barrier.status = BarrierStatus::TimedOut;
            }
        }
    }

    pub fn schedule_slot(
        &mut self,
        slot_id: &str,
        slot_index: u64,
        shard_id: &str,
        assigned_intent_ids: Vec<String>,
        barrier_ids: Vec<String>,
    ) -> PrivateContractCrossShardSchedulerResult<String> {
        if self.paused {
            return Err("cross-shard scheduler is paused".to_string());
        }
        if self.slots.contains_key(slot_id) {
            return Err("parallel execution slot already exists".to_string());
        }
        if slot_index >= self.config.slot_width {
            return Err("parallel execution slot index exceeds slot width".to_string());
        }
        let witness_hint_ids = self.usable_witness_hints_for(shard_id, &assigned_intent_ids);
        if (witness_hint_ids.len() as u64)
            < self
                .config
                .min_witness_quorum
                .min(assigned_intent_ids.len() as u64)
        {
            return Err("parallel execution slot lacks witness quorum".to_string());
        }
        let fee_reserved_micro_xmr = self
            .fee_required_for_intents(&assigned_intent_ids)?
            .saturating_add(
                witness_hint_ids
                    .iter()
                    .filter_map(|hint_id| self.witness_hints.get(hint_id))
                    .map(|hint| hint.fee_quote_micro_xmr)
                    .sum::<u64>(),
            );
        for barrier_id in &barrier_ids {
            let barrier = self
                .barriers
                .get(barrier_id)
                .ok_or_else(|| "parallel execution slot references missing barrier".to_string())?;
            if barrier.status != BarrierStatus::Satisfied {
                return Err("parallel execution slot barrier is not satisfied".to_string());
            }
        }
        for intent_id in &assigned_intent_ids {
            let intent = self
                .intents
                .get_mut(intent_id)
                .ok_or_else(|| "parallel execution slot references missing intent".to_string())?;
            if !intent.is_live_at(self.height) {
                return Err("parallel execution slot references non-live intent".to_string());
            }
            if !intent
                .shard_ids()
                .iter()
                .any(|candidate| candidate == shard_id)
            {
                return Err("parallel execution slot shard not referenced by intent".to_string());
            }
            intent.status = IntentStatus::Scheduled;
        }
        let slot = ParallelExecutionSlot::new(
            slot_id,
            slot_index,
            shard_id,
            assigned_intent_ids,
            barrier_ids,
            witness_hint_ids,
            self.height,
            fee_reserved_micro_xmr,
        )?;
        let root = slot.root();
        self.slots.insert(slot.slot_id.clone(), slot);
        Ok(root)
    }

    pub fn start_slot(
        &mut self,
        slot_id: &str,
    ) -> PrivateContractCrossShardSchedulerResult<String> {
        let slot = self
            .slots
            .get_mut(slot_id)
            .ok_or_else(|| "parallel execution slot missing".to_string())?;
        slot.status = SlotStatus::Executing;
        for intent_id in &slot.assigned_intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentStatus::Executing;
            }
        }
        Ok(slot.root())
    }

    pub fn commit_receipt(
        &mut self,
        receipt: CrossShardReceipt,
    ) -> PrivateContractCrossShardSchedulerResult<String> {
        if self.receipts.contains_key(&receipt.receipt_id) {
            return Err("cross-shard receipt already exists".to_string());
        }
        if !self.intents.contains_key(&receipt.intent_id) {
            return Err("cross-shard receipt references missing intent".to_string());
        }
        if !self.slots.contains_key(&receipt.slot_id) {
            return Err("cross-shard receipt references missing slot".to_string());
        }
        receipt.validate()?;
        if let Some(intent) = self.intents.get_mut(&receipt.intent_id) {
            intent.status = IntentStatus::Receipted;
        }
        if let Some(slot) = self.slots.get_mut(&receipt.slot_id) {
            slot.status = SlotStatus::Committed;
        }
        let root = receipt.root();
        self.receipts.insert(receipt.receipt_id.clone(), receipt);
        self.refresh_barriers();
        Ok(root)
    }

    pub fn request_retry(
        &mut self,
        retry_id: &str,
        intent_id: &str,
        previous_slot_id: &str,
        backoff_until_height: u64,
        reason_code: &str,
    ) -> PrivateContractCrossShardSchedulerResult<String> {
        if self.retries.contains_key(retry_id) {
            return Err("retry envelope already exists".to_string());
        }
        let intent = self
            .intents
            .get(intent_id)
            .ok_or_else(|| "retry envelope references missing intent".to_string())?;
        if intent.retry_count >= self.config.max_retries {
            return Err("retry envelope exceeds max retry count".to_string());
        }
        let retry_fee = intent.required_fee(&self.config).saturating_add(
            intent
                .retry_count
                .saturating_add(1)
                .saturating_mul(self.config.base_fee_micro_xmr),
        );
        let retry = RetryEnvelope::new(
            retry_id,
            intent,
            previous_slot_id,
            backoff_until_height,
            retry_fee,
            reason_code,
        )?;
        let root = retry.root();
        self.retries.insert(retry.retry_id.clone(), retry);
        if let Some(intent) = self.intents.get_mut(intent_id) {
            intent.retry_count = intent.retry_count.saturating_add(1);
            intent.retry_status = RetryStatus::WaitingBackoff;
            intent.status = IntentStatus::Retrying;
        }
        if let Some(slot) = self.slots.get_mut(previous_slot_id) {
            slot.status = SlotStatus::Failed;
        }
        Ok(root)
    }

    pub fn requeue_ready_retries(&mut self) {
        for retry in self.retries.values() {
            if retry.backoff_until_height > self.height {
                continue;
            }
            if let Some(intent) = self.intents.get_mut(&retry.intent_id) {
                if intent.retry_status == RetryStatus::WaitingBackoff {
                    intent.retry_status = RetryStatus::Requeued;
                    intent.status = IntentStatus::Admitted;
                }
            }
        }
    }

    pub fn expire_old_items(&mut self) {
        for intent in self.intents.values_mut() {
            if intent.status.is_live() && intent.expiry_height < self.height {
                intent.status = IntentStatus::Expired;
            }
        }
        for hint in self.witness_hints.values_mut() {
            if hint.status.usable() && hint.availability_window_end < self.height {
                hint.status = WitnessHintStatus::Expired;
            }
        }
        self.refresh_barriers();
        self.requeue_ready_retries();
    }

    pub fn usable_witness_hints_for(&self, shard_id: &str, intent_ids: &[String]) -> Vec<String> {
        self.witness_hints
            .values()
            .filter(|hint| {
                hint.shard_id == shard_id
                    && hint.available_at(self.height)
                    && intent_ids
                        .iter()
                        .any(|intent_id| intent_id == &hint.intent_id)
            })
            .map(|hint| hint.hint_id.clone())
            .collect()
    }

    pub fn fee_required_for_intents(
        &self,
        intent_ids: &[String],
    ) -> PrivateContractCrossShardSchedulerResult<u64> {
        let mut fee = 0_u64;
        for intent_id in intent_ids {
            let intent = self
                .intents
                .get(intent_id)
                .ok_or_else(|| "fee calculation references missing intent".to_string())?;
            fee = fee.saturating_add(intent.required_fee(&self.config));
        }
        Ok(fee)
    }

    pub fn live_intent_ids(&self) -> Vec<String> {
        self.intents
            .values()
            .filter(|intent| intent.is_live_at(self.height))
            .map(|intent| intent.intent_id.clone())
            .collect()
    }

    pub fn active_slot_ids(&self) -> Vec<String> {
        self.slots
            .values()
            .filter(|slot| slot.status.active())
            .map(|slot| slot.slot_id.clone())
            .collect()
    }

    pub fn open_barrier_ids(&self) -> Vec<String> {
        self.barriers
            .values()
            .filter(|barrier| barrier.status.open())
            .map(|barrier| barrier.barrier_id.clone())
            .collect()
    }

    pub fn usable_witness_hint_ids(&self) -> Vec<String> {
        self.witness_hints
            .values()
            .filter(|hint| hint.available_at(self.height))
            .map(|hint| hint.hint_id.clone())
            .collect()
    }

    pub fn shard_pressure_map(&self) -> BTreeMap<String, u64> {
        self.shard_pressure.clone()
    }

    pub fn lane_pressure_map(&self) -> BTreeMap<String, u64> {
        self.lane_pressure
            .iter()
            .map(|(lane, pressure)| (lane.as_str().to_string(), *pressure))
            .collect()
    }

    pub fn roots(&self) -> Roots {
        let config_root = self.config.root();
        let privacy_budget_records = self
            .privacy_budgets
            .values()
            .map(PrivacyBudget::public_record)
            .collect::<Vec<_>>();
        let intent_records = self
            .intents
            .values()
            .map(EncryptedShardIntent::public_record)
            .collect::<Vec<_>>();
        let witness_hint_records = self
            .witness_hints
            .values()
            .map(WitnessAvailabilityHint::public_record)
            .collect::<Vec<_>>();
        let barrier_records = self
            .barriers
            .values()
            .map(DependencyBarrier::public_record)
            .collect::<Vec<_>>();
        let slot_records = self
            .slots
            .values()
            .map(ParallelExecutionSlot::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .values()
            .map(CrossShardReceipt::public_record)
            .collect::<Vec<_>>();
        let retry_records = self
            .retries
            .values()
            .map(RetryEnvelope::public_record)
            .collect::<Vec<_>>();
        let privacy_budget_root = merkle_root(
            "PRIVATE-CONTRACT-CROSS-SHARD-SCHEDULER-PRIVACY-BUDGET",
            &privacy_budget_records,
        );
        let intent_root = merkle_root(
            "PRIVATE-CONTRACT-CROSS-SHARD-SCHEDULER-INTENT",
            &intent_records,
        );
        let witness_hint_root = merkle_root(
            "PRIVATE-CONTRACT-CROSS-SHARD-SCHEDULER-WITNESS-HINT",
            &witness_hint_records,
        );
        let barrier_root = merkle_root(
            "PRIVATE-CONTRACT-CROSS-SHARD-SCHEDULER-BARRIER",
            &barrier_records,
        );
        let slot_root = merkle_root("PRIVATE-CONTRACT-CROSS-SHARD-SCHEDULER-SLOT", &slot_records);
        let receipt_root = merkle_root(
            "PRIVATE-CONTRACT-CROSS-SHARD-SCHEDULER-RECEIPT",
            &receipt_records,
        );
        let retry_root = merkle_root(
            "PRIVATE-CONTRACT-CROSS-SHARD-SCHEDULER-RETRY",
            &retry_records,
        );
        let shard_pressure_root = scheduler_hash(
            "SHARD-PRESSURE",
            &[HashPart::Json(&json!(self.shard_pressure_map()))],
        );
        let lane_pressure_root = scheduler_hash(
            "LANE-PRESSURE",
            &[HashPart::Json(&json!(self.lane_pressure_map()))],
        );
        let state_root = scheduler_hash(
            "STATE",
            &[
                HashPart::Str(&self.height.to_string()),
                HashPart::Str(&config_root),
                HashPart::Str(&privacy_budget_root),
                HashPart::Str(&intent_root),
                HashPart::Str(&witness_hint_root),
                HashPart::Str(&barrier_root),
                HashPart::Str(&slot_root),
                HashPart::Str(&receipt_root),
                HashPart::Str(&retry_root),
                HashPart::Str(&shard_pressure_root),
                HashPart::Str(&lane_pressure_root),
            ],
        );
        Roots {
            config_root,
            privacy_budget_root,
            intent_root,
            witness_hint_root,
            barrier_root,
            slot_root,
            receipt_root,
            retry_root,
            shard_pressure_root,
            lane_pressure_root,
            state_root,
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            privacy_budget_count: self.privacy_budgets.len() as u64,
            encrypted_intent_count: self.intents.len() as u64,
            live_intent_count: self.live_intent_ids().len() as u64,
            witness_hint_count: self.witness_hints.len() as u64,
            usable_witness_hint_count: self.usable_witness_hint_ids().len() as u64,
            open_barrier_count: self.open_barrier_ids().len() as u64,
            active_slot_count: self.active_slot_ids().len() as u64,
            receipt_count: self.receipts.len() as u64,
            retry_count: self.retries.len() as u64,
            total_privacy_budget_remaining: self
                .privacy_budgets
                .values()
                .map(PrivacyBudget::remaining_units)
                .sum(),
            total_fee_reserved_micro_xmr: self
                .slots
                .values()
                .map(|slot| slot.fee_reserved_micro_xmr)
                .sum(),
            total_fee_paid_micro_xmr: self
                .receipts
                .values()
                .map(|receipt| receipt.fee_paid_micro_xmr)
                .sum(),
            shard_count: self.shard_pressure.len() as u64,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "private_contract_cross_shard_scheduler",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_PROTOCOL_VERSION,
            "protocol_label": PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_PROTOCOL_LABEL,
            "schema_version": PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_SCHEMA_VERSION,
            "height": self.height,
            "paused": self.paused,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "live_intent_ids": self.live_intent_ids(),
            "active_slot_ids": self.active_slot_ids(),
            "open_barrier_ids": self.open_barrier_ids(),
            "usable_witness_hint_ids": self.usable_witness_hint_ids(),
            "shard_pressure_map": self.shard_pressure_map(),
            "lane_pressure_map": self.lane_pressure_map(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn validate(&self) -> PrivateContractCrossShardSchedulerResult<String> {
        self.config.validate()?;
        for budget in self.privacy_budgets.values() {
            budget.validate()?;
        }
        for intent in self.intents.values() {
            intent.validate()?;
            if !self.privacy_budgets.contains_key(&intent.budget_id) {
                return Err("encrypted shard intent references missing privacy budget".to_string());
            }
            if intent.shard_refs.len() as u64 > self.config.max_shards {
                return Err("encrypted shard intent exceeds configured shard fanout".to_string());
            }
            if intent.dependency_ids.len() as u64 > self.config.max_dependencies {
                return Err(
                    "encrypted shard intent exceeds configured dependency count".to_string()
                );
            }
        }
        for hint in self.witness_hints.values() {
            hint.validate()?;
            if !self.intents.contains_key(&hint.intent_id) {
                return Err("witness availability hint references missing intent".to_string());
            }
        }
        for barrier in self.barriers.values() {
            barrier.validate()?;
            if !self.intents.contains_key(&barrier.intent_id) {
                return Err("dependency barrier references missing intent".to_string());
            }
            for receipt_id in &barrier.required_receipt_ids {
                if !self.receipts.contains_key(receipt_id) {
                    return Err("dependency barrier references missing receipt".to_string());
                }
            }
        }
        for slot in self.slots.values() {
            slot.validate()?;
            if slot.slot_index >= self.config.slot_width {
                return Err("parallel execution slot index exceeds slot width".to_string());
            }
            for intent_id in &slot.assigned_intent_ids {
                if !self.intents.contains_key(intent_id) {
                    return Err("parallel execution slot references missing intent".to_string());
                }
            }
            for barrier_id in &slot.barrier_ids {
                if !self.barriers.contains_key(barrier_id) {
                    return Err("parallel execution slot references missing barrier".to_string());
                }
            }
            for hint_id in &slot.witness_hint_ids {
                if !self.witness_hints.contains_key(hint_id) {
                    return Err(
                        "parallel execution slot references missing witness hint".to_string()
                    );
                }
            }
        }
        for receipt in self.receipts.values() {
            receipt.validate()?;
            if !self.intents.contains_key(&receipt.intent_id) {
                return Err("cross-shard receipt references missing intent".to_string());
            }
            if !self.slots.contains_key(&receipt.slot_id) {
                return Err("cross-shard receipt references missing slot".to_string());
            }
        }
        for retry in self.retries.values() {
            retry.validate()?;
            if !self.intents.contains_key(&retry.intent_id) {
                return Err("retry envelope references missing intent".to_string());
            }
            if !self.slots.contains_key(&retry.previous_slot_id) {
                return Err("retry envelope references missing previous slot".to_string());
            }
        }
        Ok(self.state_root())
    }
}

pub fn root_from_record(record: &Value) -> String {
    scheduler_hash("STATE-FROM-RECORD", &[HashPart::Json(record)])
}

pub fn devnet() -> PrivateContractCrossShardSchedulerResult<State> {
    State::devnet()
}

fn ensure_unique(label: &str, values: &[String]) -> PrivateContractCrossShardSchedulerResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if value.is_empty() {
            return Err(format!("{label} id is empty"));
        }
        if !seen.insert(value.clone()) {
            return Err(format!("{label} id is duplicated"));
        }
    }
    Ok(())
}

fn scheduler_hash(label: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!(
            "{}:{}:{}",
            PRIVATE_CONTRACT_CROSS_SHARD_SCHEDULER_PROTOCOL_LABEL, CHAIN_ID, label
        ),
        parts,
        32,
    )
}
