use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateContractExecutionBatcherResult<T> = Result<T, String>;

pub const PRIVATE_CONTRACT_EXECUTION_BATCHER_PROTOCOL_VERSION: u32 = 1;
pub const PRIVATE_CONTRACT_EXECUTION_BATCHER_PROTOCOL_LABEL: &str =
    "nebula-private-contract-execution-batcher-v1";
pub const PRIVATE_CONTRACT_EXECUTION_BATCHER_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_CONTRACT_EXECUTION_BATCHER_DEVNET_HEIGHT: u64 = 1_664;
pub const PRIVATE_CONTRACT_EXECUTION_BATCHER_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_CONTRACT_EXECUTION_BATCHER_ENCRYPTION_SUITE: &str =
    "ML-KEM-768+sealed-contract-call-v1";
pub const PRIVATE_CONTRACT_EXECUTION_BATCHER_PQ_AUTH_SUITE: &str =
    "ML-DSA-65+SLH-DSA-SHAKE-128s-contract-batch";
pub const PRIVATE_CONTRACT_EXECUTION_BATCHER_WITNESS_SUITE: &str =
    "private-execution-witness-availability-v1";
pub const PRIVATE_CONTRACT_EXECUTION_BATCHER_DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 3;
pub const PRIVATE_CONTRACT_EXECUTION_BATCHER_DEFAULT_MAX_CALLS_PER_BATCH: u64 = 256;
pub const PRIVATE_CONTRACT_EXECUTION_BATCHER_DEFAULT_MAX_BATCH_WEIGHT: u64 = 5_000_000;
pub const PRIVATE_CONTRACT_EXECUTION_BATCHER_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 8_250;
pub const PRIVATE_CONTRACT_EXECUTION_BATCHER_DEFAULT_SPONSOR_POOL_UNITS: u64 = 420_000;
pub const PRIVATE_CONTRACT_EXECUTION_BATCHER_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateContractBatchLane {
    PrivateSwap,
    Lending,
    Perps,
    Stablecoin,
    TokenMint,
    Governance,
    Emergency,
}

impl PrivateContractBatchLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateSwap => "private_swap",
            Self::Lending => "lending",
            Self::Perps => "perps",
            Self::Stablecoin => "stablecoin",
            Self::TokenMint => "token_mint",
            Self::Governance => "governance",
            Self::Emergency => "emergency",
        }
    }

    pub fn priority(self) -> u64 {
        match self {
            Self::Emergency => 100,
            Self::Stablecoin => 90,
            Self::Lending => 84,
            Self::PrivateSwap => 80,
            Self::Perps => 76,
            Self::TokenMint => 68,
            Self::Governance => 52,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptedCallStatus {
    Pending,
    Selected,
    Batched,
    Executed,
    Reverted,
    Expired,
    Cancelled,
}

impl EncryptedCallStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Selected => "selected",
            Self::Batched => "batched",
            Self::Executed => "executed",
            Self::Reverted => "reverted",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Pending | Self::Selected | Self::Batched)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionBatchStatus {
    Open,
    Sealed,
    Witnessed,
    Proved,
    Settled,
    Challenged,
    Failed,
}

impl ExecutionBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Witnessed => "witnessed",
            Self::Proved => "proved",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Failed => "failed",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Sealed | Self::Witnessed | Self::Proved | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessBundleStatus {
    Requested,
    Available,
    Sampled,
    Pinned,
    Challenged,
    Expired,
}

impl WitnessBundleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Available => "available",
            Self::Sampled => "sampled",
            Self::Pinned => "pinned",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractExecutionBatcherConfig {
    pub batch_window_blocks: u64,
    pub max_calls_per_batch: u64,
    pub max_batch_weight: u64,
    pub low_fee_rebate_bps: u64,
    pub sponsor_pool_units: u64,
    pub encryption_suite: String,
    pub pq_auth_suite: String,
    pub witness_suite: String,
    pub hash_suite: String,
}

impl PrivateContractExecutionBatcherConfig {
    pub fn devnet() -> Self {
        Self {
            batch_window_blocks: PRIVATE_CONTRACT_EXECUTION_BATCHER_DEFAULT_BATCH_WINDOW_BLOCKS,
            max_calls_per_batch: PRIVATE_CONTRACT_EXECUTION_BATCHER_DEFAULT_MAX_CALLS_PER_BATCH,
            max_batch_weight: PRIVATE_CONTRACT_EXECUTION_BATCHER_DEFAULT_MAX_BATCH_WEIGHT,
            low_fee_rebate_bps: PRIVATE_CONTRACT_EXECUTION_BATCHER_DEFAULT_LOW_FEE_REBATE_BPS,
            sponsor_pool_units: PRIVATE_CONTRACT_EXECUTION_BATCHER_DEFAULT_SPONSOR_POOL_UNITS,
            encryption_suite: PRIVATE_CONTRACT_EXECUTION_BATCHER_ENCRYPTION_SUITE.to_string(),
            pq_auth_suite: PRIVATE_CONTRACT_EXECUTION_BATCHER_PQ_AUTH_SUITE.to_string(),
            witness_suite: PRIVATE_CONTRACT_EXECUTION_BATCHER_WITNESS_SUITE.to_string(),
            hash_suite: PRIVATE_CONTRACT_EXECUTION_BATCHER_HASH_SUITE.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_window_blocks": self.batch_window_blocks,
            "max_calls_per_batch": self.max_calls_per_batch,
            "max_batch_weight": self.max_batch_weight,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "sponsor_pool_units": self.sponsor_pool_units,
            "encryption_suite": self.encryption_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "witness_suite": self.witness_suite,
            "hash_suite": self.hash_suite,
        })
    }

    pub fn config_root(&self) -> String {
        private_batcher_hash("CONFIG", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateContractExecutionBatcherResult<()> {
        if self.batch_window_blocks == 0
            || self.max_calls_per_batch == 0
            || self.max_batch_weight == 0
        {
            return Err("private contract batcher limits must be positive".to_string());
        }
        if self.low_fee_rebate_bps > PRIVATE_CONTRACT_EXECUTION_BATCHER_MAX_BPS {
            return Err("private contract batcher rebate exceeds max bps".to_string());
        }
        if self.encryption_suite.is_empty()
            || self.pq_auth_suite.is_empty()
            || self.witness_suite.is_empty()
            || self.hash_suite.is_empty()
        {
            return Err("private contract batcher suite labels must be populated".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedContractCall {
    pub call_id: String,
    pub lane: PrivateContractBatchLane,
    pub contract_commitment: String,
    pub caller_commitment: String,
    pub encrypted_args_root: String,
    pub nullifier_root: String,
    pub gas_limit_units: u64,
    pub max_fee_units: u64,
    pub weight_units: u64,
    pub submitted_height: u64,
    pub expiry_height: u64,
    pub status: EncryptedCallStatus,
    pub pq_authorization_root: String,
    pub disclosure_tag_root: String,
}

impl EncryptedContractCall {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        call_id: &str,
        lane: PrivateContractBatchLane,
        contract_commitment: &str,
        caller_commitment: &str,
        gas_limit_units: u64,
        max_fee_units: u64,
        weight_units: u64,
        submitted_height: u64,
        ttl_blocks: u64,
    ) -> PrivateContractExecutionBatcherResult<Self> {
        if call_id.is_empty() || contract_commitment.is_empty() || caller_commitment.is_empty() {
            return Err("encrypted contract call identifiers must be populated".to_string());
        }
        if gas_limit_units == 0 || max_fee_units == 0 || weight_units == 0 {
            return Err("encrypted contract call budgets must be positive".to_string());
        }
        let encrypted_args_root = private_batcher_hash(
            "ENCRYPTED-ARGS",
            &[
                HashPart::Str(call_id),
                HashPart::Str(contract_commitment),
                HashPart::Str(caller_commitment),
            ],
        );
        let nullifier_root = private_batcher_hash(
            "CALL-NULLIFIER",
            &[HashPart::Str(call_id), HashPart::Str(caller_commitment)],
        );
        let pq_authorization_root = private_batcher_hash(
            "CALL-PQ-AUTHORIZATION",
            &[
                HashPart::Str(call_id),
                HashPart::Str(lane.as_str()),
                HashPart::Str(&encrypted_args_root),
            ],
        );
        let disclosure_tag_root = private_batcher_hash(
            "CALL-DISCLOSURE-TAG",
            &[HashPart::Str(call_id), HashPart::Str("operator_roots_only")],
        );
        Ok(Self {
            call_id: call_id.to_string(),
            lane,
            contract_commitment: contract_commitment.to_string(),
            caller_commitment: caller_commitment.to_string(),
            encrypted_args_root,
            nullifier_root,
            gas_limit_units,
            max_fee_units,
            weight_units,
            submitted_height,
            expiry_height: submitted_height.saturating_add(ttl_blocks),
            status: EncryptedCallStatus::Pending,
            pq_authorization_root,
            disclosure_tag_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "call_id": self.call_id,
            "lane": self.lane.as_str(),
            "contract_commitment": self.contract_commitment,
            "caller_commitment": self.caller_commitment,
            "encrypted_args_root": self.encrypted_args_root,
            "nullifier_root": self.nullifier_root,
            "gas_limit_units": self.gas_limit_units,
            "max_fee_units": self.max_fee_units,
            "weight_units": self.weight_units,
            "submitted_height": self.submitted_height,
            "expiry_height": self.expiry_height,
            "status": self.status.as_str(),
            "pq_authorization_root": self.pq_authorization_root,
            "disclosure_tag_root": self.disclosure_tag_root,
        })
    }

    pub fn root(&self) -> String {
        private_batcher_hash("CALL", &[HashPart::Json(&self.public_record())])
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status.is_live() && height <= self.expiry_height
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateExecutionBatch {
    pub batch_id: String,
    pub lane: PrivateContractBatchLane,
    pub call_ids: Vec<String>,
    pub status: ExecutionBatchStatus,
    pub opened_height: u64,
    pub sealed_height: u64,
    pub total_weight_units: u64,
    pub total_fee_units: u64,
    pub call_root: String,
    pub ordering_commitment_root: String,
    pub pq_seal_root: String,
    pub low_fee_sponsor_receipt_root: String,
}

impl PrivateExecutionBatch {
    pub fn new(
        batch_id: &str,
        lane: PrivateContractBatchLane,
        calls: &[EncryptedContractCall],
        opened_height: u64,
    ) -> PrivateContractExecutionBatcherResult<Self> {
        if batch_id.is_empty() {
            return Err("private execution batch id must be populated".to_string());
        }
        if calls.is_empty() {
            return Err("private execution batch requires calls".to_string());
        }
        let mut call_ids = Vec::with_capacity(calls.len());
        let mut call_records = Vec::with_capacity(calls.len());
        let mut total_weight_units = 0_u64;
        let mut total_fee_units = 0_u64;
        for call in calls {
            if call.lane != lane {
                return Err("private execution batch cannot mix lanes".to_string());
            }
            call_ids.push(call.call_id.clone());
            call_records.push(call.public_record());
            total_weight_units = total_weight_units.saturating_add(call.weight_units);
            total_fee_units = total_fee_units.saturating_add(call.max_fee_units);
        }
        let call_root = merkle_root("PRIVATE-CONTRACT-BATCH-CALL", &call_records);
        let ordering_commitment_root = private_batcher_hash(
            "BATCH-ORDERING",
            &[
                HashPart::Str(batch_id),
                HashPart::Str(lane.as_str()),
                HashPart::Str(&call_root),
            ],
        );
        let pq_seal_root = private_batcher_hash(
            "BATCH-PQ-SEAL",
            &[
                HashPart::Str(batch_id),
                HashPart::Str(&ordering_commitment_root),
            ],
        );
        let low_fee_sponsor_receipt_root = private_batcher_hash(
            "BATCH-SPONSOR-RECEIPT",
            &[
                HashPart::Str(batch_id),
                HashPart::Int(total_fee_units as i128),
                HashPart::Int(total_weight_units as i128),
            ],
        );
        Ok(Self {
            batch_id: batch_id.to_string(),
            lane,
            call_ids,
            status: ExecutionBatchStatus::Sealed,
            opened_height,
            sealed_height: opened_height,
            total_weight_units,
            total_fee_units,
            call_root,
            ordering_commitment_root,
            pq_seal_root,
            low_fee_sponsor_receipt_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "lane": self.lane.as_str(),
            "call_ids": self.call_ids,
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "sealed_height": self.sealed_height,
            "total_weight_units": self.total_weight_units,
            "total_fee_units": self.total_fee_units,
            "call_root": self.call_root,
            "ordering_commitment_root": self.ordering_commitment_root,
            "pq_seal_root": self.pq_seal_root,
            "low_fee_sponsor_receipt_root": self.low_fee_sponsor_receipt_root,
        })
    }

    pub fn root(&self) -> String {
        private_batcher_hash("BATCH", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateExecutionWitnessBundle {
    pub witness_id: String,
    pub batch_id: String,
    pub status: WitnessBundleStatus,
    pub encrypted_witness_root: String,
    pub da_commitment_root: String,
    pub sample_challenge_root: String,
    pub availability_attestation_root: String,
    pub published_height: u64,
}

impl PrivateExecutionWitnessBundle {
    pub fn new(
        witness_id: &str,
        batch: &PrivateExecutionBatch,
        published_height: u64,
    ) -> PrivateContractExecutionBatcherResult<Self> {
        if witness_id.is_empty() {
            return Err("private execution witness id must be populated".to_string());
        }
        let encrypted_witness_root = private_batcher_hash(
            "WITNESS-ENCRYPTED",
            &[HashPart::Str(witness_id), HashPart::Str(&batch.batch_id)],
        );
        let da_commitment_root = private_batcher_hash(
            "WITNESS-DA-COMMITMENT",
            &[
                HashPart::Str(witness_id),
                HashPart::Str(&encrypted_witness_root),
            ],
        );
        let sample_challenge_root = private_batcher_hash(
            "WITNESS-SAMPLE-CHALLENGE",
            &[
                HashPart::Str(witness_id),
                HashPart::Str(&batch.call_root),
                HashPart::Int(published_height as i128),
            ],
        );
        let availability_attestation_root = private_batcher_hash(
            "WITNESS-AVAILABILITY-ATTESTATION",
            &[
                HashPart::Str(witness_id),
                HashPart::Str(&da_commitment_root),
            ],
        );
        Ok(Self {
            witness_id: witness_id.to_string(),
            batch_id: batch.batch_id.clone(),
            status: WitnessBundleStatus::Available,
            encrypted_witness_root,
            da_commitment_root,
            sample_challenge_root,
            availability_attestation_root,
            published_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "witness_id": self.witness_id,
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "encrypted_witness_root": self.encrypted_witness_root,
            "da_commitment_root": self.da_commitment_root,
            "sample_challenge_root": self.sample_challenge_root,
            "availability_attestation_root": self.availability_attestation_root,
            "published_height": self.published_height,
        })
    }

    pub fn root(&self) -> String {
        private_batcher_hash("WITNESS", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateExecutionSettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub execution_root: String,
    pub state_delta_root: String,
    pub event_commitment_root: String,
    pub proof_root: String,
    pub settlement_height: u64,
}

impl PrivateExecutionSettlementReceipt {
    pub fn new(
        receipt_id: &str,
        batch: &PrivateExecutionBatch,
        settlement_height: u64,
    ) -> PrivateContractExecutionBatcherResult<Self> {
        if receipt_id.is_empty() {
            return Err("private execution settlement receipt id must be populated".to_string());
        }
        let execution_root = private_batcher_hash(
            "SETTLEMENT-EXECUTION",
            &[HashPart::Str(receipt_id), HashPart::Str(&batch.batch_id)],
        );
        let state_delta_root = private_batcher_hash(
            "SETTLEMENT-STATE-DELTA",
            &[HashPart::Str(receipt_id), HashPart::Str(&execution_root)],
        );
        let event_commitment_root = private_batcher_hash(
            "SETTLEMENT-EVENTS",
            &[HashPart::Str(receipt_id), HashPart::Str(&batch.call_root)],
        );
        let proof_root = private_batcher_hash(
            "SETTLEMENT-PROOF",
            &[
                HashPart::Str(receipt_id),
                HashPart::Str(&state_delta_root),
                HashPart::Str(&event_commitment_root),
            ],
        );
        Ok(Self {
            receipt_id: receipt_id.to_string(),
            batch_id: batch.batch_id.clone(),
            execution_root,
            state_delta_root,
            event_commitment_root,
            proof_root,
            settlement_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "execution_root": self.execution_root,
            "state_delta_root": self.state_delta_root,
            "event_commitment_root": self.event_commitment_root,
            "proof_root": self.proof_root,
            "settlement_height": self.settlement_height,
        })
    }

    pub fn root(&self) -> String {
        private_batcher_hash(
            "SETTLEMENT-RECEIPT",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractExecutionBatcherRoots {
    pub config_root: String,
    pub call_root: String,
    pub batch_root: String,
    pub witness_root: String,
    pub settlement_root: String,
    pub lane_pressure_root: String,
    pub state_root: String,
}

impl PrivateContractExecutionBatcherRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "call_root": self.call_root,
            "batch_root": self.batch_root,
            "witness_root": self.witness_root,
            "settlement_root": self.settlement_root,
            "lane_pressure_root": self.lane_pressure_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractExecutionBatcherCounters {
    pub pending_call_count: u64,
    pub live_batch_count: u64,
    pub witness_count: u64,
    pub settlement_count: u64,
    pub total_pending_weight: u64,
    pub sponsor_pool_units: u64,
    pub lane_count: u64,
}

impl PrivateContractExecutionBatcherCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "pending_call_count": self.pending_call_count,
            "live_batch_count": self.live_batch_count,
            "witness_count": self.witness_count,
            "settlement_count": self.settlement_count,
            "total_pending_weight": self.total_pending_weight,
            "sponsor_pool_units": self.sponsor_pool_units,
            "lane_count": self.lane_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractExecutionBatcherState {
    pub height: u64,
    pub config: PrivateContractExecutionBatcherConfig,
    pub calls: BTreeMap<String, EncryptedContractCall>,
    pub batches: BTreeMap<String, PrivateExecutionBatch>,
    pub witnesses: BTreeMap<String, PrivateExecutionWitnessBundle>,
    pub settlements: BTreeMap<String, PrivateExecutionSettlementReceipt>,
    pub lane_pressure: BTreeMap<PrivateContractBatchLane, u64>,
    pub paused: bool,
}

impl PrivateContractExecutionBatcherState {
    pub fn devnet() -> PrivateContractExecutionBatcherResult<Self> {
        let config = PrivateContractExecutionBatcherConfig::devnet();
        config.validate()?;
        let mut state = Self {
            height: PRIVATE_CONTRACT_EXECUTION_BATCHER_DEVNET_HEIGHT,
            config,
            calls: BTreeMap::new(),
            batches: BTreeMap::new(),
            witnesses: BTreeMap::new(),
            settlements: BTreeMap::new(),
            lane_pressure: BTreeMap::new(),
            paused: false,
        };
        let call_a = EncryptedContractCall::new(
            "devnet-private-swap-call-a",
            PrivateContractBatchLane::PrivateSwap,
            "contract-commitment-private-dex",
            "caller-commitment-alice",
            220_000,
            1_600,
            180_000,
            state.height,
            24,
        )?;
        let call_b = EncryptedContractCall::new(
            "devnet-private-swap-call-b",
            PrivateContractBatchLane::PrivateSwap,
            "contract-commitment-private-dex",
            "caller-commitment-bob",
            260_000,
            1_900,
            220_000,
            state.height,
            24,
        )?;
        state.insert_call(call_a)?;
        state.insert_call(call_b)?;
        let batch_id = state.seal_lane_batch(
            "devnet-private-swap-batch-a",
            PrivateContractBatchLane::PrivateSwap,
        )?;
        state.attach_witness("devnet-private-swap-witness-a", &batch_id)?;
        state.settle_batch("devnet-private-swap-settlement-a", &batch_id)?;
        let call_c = EncryptedContractCall::new(
            "devnet-stablecoin-call-a",
            PrivateContractBatchLane::Stablecoin,
            "contract-commitment-stablecoin-engine",
            "caller-commitment-treasury",
            340_000,
            2_200,
            280_000,
            state.height,
            36,
        )?;
        state.insert_call(call_c)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateContractExecutionBatcherResult<()> {
        if height < self.height {
            return Err("private contract batcher height cannot move backwards".to_string());
        }
        self.height = height;
        for call in self.calls.values_mut() {
            if call.status.is_live() && height > call.expiry_height {
                call.status = EncryptedCallStatus::Expired;
            }
        }
        Ok(())
    }

    pub fn insert_call(
        &mut self,
        call: EncryptedContractCall,
    ) -> PrivateContractExecutionBatcherResult<()> {
        if self.paused {
            return Err("private contract batcher is paused".to_string());
        }
        if self.calls.contains_key(&call.call_id) {
            return Err("encrypted contract call already exists".to_string());
        }
        if call.weight_units > self.config.max_batch_weight {
            return Err("encrypted contract call exceeds max batch weight".to_string());
        }
        let lane_pressure = self.lane_pressure.entry(call.lane).or_insert(0);
        *lane_pressure = lane_pressure.saturating_add(call.weight_units);
        self.calls.insert(call.call_id.clone(), call);
        Ok(())
    }

    pub fn seal_lane_batch(
        &mut self,
        batch_id: &str,
        lane: PrivateContractBatchLane,
    ) -> PrivateContractExecutionBatcherResult<String> {
        if self.batches.contains_key(batch_id) {
            return Err("private execution batch already exists".to_string());
        }
        let mut selected = Vec::new();
        let mut selected_ids = Vec::new();
        let mut weight = 0_u64;
        for call in self.calls.values() {
            if call.lane != lane || !call.is_live_at(self.height) {
                continue;
            }
            if selected.len() as u64 >= self.config.max_calls_per_batch {
                break;
            }
            if weight.saturating_add(call.weight_units) > self.config.max_batch_weight {
                continue;
            }
            selected_ids.push(call.call_id.clone());
            selected.push(call.clone());
            weight = weight.saturating_add(call.weight_units);
        }
        let batch = PrivateExecutionBatch::new(batch_id, lane, &selected, self.height)?;
        for call_id in &selected_ids {
            if let Some(call) = self.calls.get_mut(call_id) {
                call.status = EncryptedCallStatus::Batched;
            }
        }
        let batch_root = batch.root();
        self.batches.insert(batch.batch_id.clone(), batch);
        Ok(batch_root)
    }

    pub fn attach_witness(
        &mut self,
        witness_id: &str,
        batch_id: &str,
    ) -> PrivateContractExecutionBatcherResult<String> {
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| "private execution batch missing".to_string())?;
        let witness = PrivateExecutionWitnessBundle::new(witness_id, batch, self.height)?;
        batch.status = ExecutionBatchStatus::Witnessed;
        let witness_root = witness.root();
        self.witnesses.insert(witness.witness_id.clone(), witness);
        Ok(witness_root)
    }

    pub fn settle_batch(
        &mut self,
        receipt_id: &str,
        batch_id: &str,
    ) -> PrivateContractExecutionBatcherResult<String> {
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| "private execution batch missing".to_string())?;
        let receipt = PrivateExecutionSettlementReceipt::new(receipt_id, batch, self.height)?;
        batch.status = ExecutionBatchStatus::Settled;
        for call_id in &batch.call_ids {
            if let Some(call) = self.calls.get_mut(call_id) {
                call.status = EncryptedCallStatus::Executed;
            }
        }
        let receipt_root = receipt.root();
        self.settlements.insert(receipt.receipt_id.clone(), receipt);
        Ok(receipt_root)
    }

    pub fn pending_call_ids(&self) -> Vec<String> {
        self.calls
            .values()
            .filter(|call| call.is_live_at(self.height))
            .map(|call| call.call_id.clone())
            .collect()
    }

    pub fn live_batch_ids(&self) -> Vec<String> {
        self.batches
            .values()
            .filter(|batch| batch.status.is_open())
            .map(|batch| batch.batch_id.clone())
            .collect()
    }

    pub fn total_pending_weight(&self) -> u64 {
        self.calls
            .values()
            .filter(|call| call.is_live_at(self.height))
            .map(|call| call.weight_units)
            .sum()
    }

    pub fn lane_pressure_map(&self) -> BTreeMap<String, u64> {
        self.lane_pressure
            .iter()
            .map(|(lane, pressure)| (lane.as_str().to_string(), *pressure))
            .collect()
    }

    pub fn roots(&self) -> PrivateContractExecutionBatcherRoots {
        let config_root = self.config.config_root();
        let call_records = self
            .calls
            .values()
            .map(EncryptedContractCall::public_record)
            .collect::<Vec<_>>();
        let batch_records = self
            .batches
            .values()
            .map(PrivateExecutionBatch::public_record)
            .collect::<Vec<_>>();
        let witness_records = self
            .witnesses
            .values()
            .map(PrivateExecutionWitnessBundle::public_record)
            .collect::<Vec<_>>();
        let settlement_records = self
            .settlements
            .values()
            .map(PrivateExecutionSettlementReceipt::public_record)
            .collect::<Vec<_>>();
        let call_root = merkle_root("PRIVATE-CONTRACT-BATCHER-CALL", &call_records);
        let batch_root = merkle_root("PRIVATE-CONTRACT-BATCHER-BATCH", &batch_records);
        let witness_root = merkle_root("PRIVATE-CONTRACT-BATCHER-WITNESS", &witness_records);
        let settlement_root =
            merkle_root("PRIVATE-CONTRACT-BATCHER-SETTLEMENT", &settlement_records);
        let lane_pressure_root = private_batcher_hash(
            "LANE-PRESSURE",
            &[HashPart::Json(&json!(self.lane_pressure_map()))],
        );
        let state_root = private_batcher_hash(
            "STATE",
            &[
                HashPart::Int(self.height as i128),
                HashPart::Str(&config_root),
                HashPart::Str(&call_root),
                HashPart::Str(&batch_root),
                HashPart::Str(&witness_root),
                HashPart::Str(&settlement_root),
                HashPart::Str(&lane_pressure_root),
            ],
        );
        PrivateContractExecutionBatcherRoots {
            config_root,
            call_root,
            batch_root,
            witness_root,
            settlement_root,
            lane_pressure_root,
            state_root,
        }
    }

    pub fn counters(&self) -> PrivateContractExecutionBatcherCounters {
        PrivateContractExecutionBatcherCounters {
            pending_call_count: self.pending_call_ids().len() as u64,
            live_batch_count: self.live_batch_ids().len() as u64,
            witness_count: self.witnesses.len() as u64,
            settlement_count: self.settlements.len() as u64,
            total_pending_weight: self.total_pending_weight(),
            sponsor_pool_units: self.config.sponsor_pool_units,
            lane_count: self.lane_pressure.len() as u64,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "private_contract_execution_batcher",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CONTRACT_EXECUTION_BATCHER_PROTOCOL_VERSION,
            "protocol_label": PRIVATE_CONTRACT_EXECUTION_BATCHER_PROTOCOL_LABEL,
            "schema_version": PRIVATE_CONTRACT_EXECUTION_BATCHER_SCHEMA_VERSION,
            "height": self.height,
            "paused": self.paused,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "pending_call_ids": self.pending_call_ids(),
            "live_batch_ids": self.live_batch_ids(),
            "lane_pressure_map": self.lane_pressure_map(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn validate(&self) -> PrivateContractExecutionBatcherResult<String> {
        self.config.validate()?;
        let mut nullifiers = BTreeSet::new();
        for call in self.calls.values() {
            if !nullifiers.insert(call.nullifier_root.clone()) {
                return Err("duplicate private contract call nullifier".to_string());
            }
            if call.expiry_height < call.submitted_height {
                return Err("private contract call has invalid expiry".to_string());
            }
        }
        for batch in self.batches.values() {
            if batch.call_ids.is_empty() {
                return Err("private execution batch has no calls".to_string());
            }
            for call_id in &batch.call_ids {
                if !self.calls.contains_key(call_id) {
                    return Err("private execution batch references missing call".to_string());
                }
            }
        }
        for witness in self.witnesses.values() {
            if !self.batches.contains_key(&witness.batch_id) {
                return Err("private execution witness references missing batch".to_string());
            }
        }
        for receipt in self.settlements.values() {
            if !self.batches.contains_key(&receipt.batch_id) {
                return Err("private execution settlement references missing batch".to_string());
            }
        }
        Ok(self.state_root())
    }
}

pub fn private_contract_execution_batcher_state_root_from_record(record: &Value) -> String {
    private_batcher_hash("STATE-FROM-RECORD", &[HashPart::Json(record)])
}

fn private_batcher_hash(label: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!(
            "{}:{}:{}",
            PRIVATE_CONTRACT_EXECUTION_BATCHER_PROTOCOL_LABEL, CHAIN_ID, label
        ),
        parts,
        32,
    )
}
