use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialContractCallBatcherResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-contract-call-batcher-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_SEALED_CALL_SCHEME: &str =
    "zk-sealed-private-l2-contract-call-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_PQ_AUTH_SCHEME: &str =
    "ml-dsa-87-confidential-contract-call-authorization-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_WITNESS_SCHEME: &str =
    "zk-contract-call-witness-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_PROOF_SCHEME: &str =
    "zk-confidential-contract-call-batch-proof-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_SPONSOR_SCHEME: &str =
    "zk-low-fee-contract-call-sponsor-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_BUNDLE_SCHEME: &str =
    "deterministic-private-contract-execution-bundle-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_RECEIPT_SCHEME: &str =
    "settlement-ready-private-contract-call-receipt-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEFAULT_WINDOW_BLOCKS: u64 = 8;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEFAULT_CALL_TTL_BLOCKS: u64 = 32;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 16;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEFAULT_MAX_CALLS_PER_BATCH: usize = 768;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEFAULT_MAX_LANE_WIDTH: usize = 96;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEFAULT_MAX_BUNDLE_STEPS: usize = 2_048;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEFAULT_MIN_PRIVACY_SET: u64 = 64;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEFAULT_MAX_USER_FEE_BPS: u64 = 25;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEFAULT_MAX_SPONSOR_FEE_BPS: u64 = 20;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEFAULT_MIN_SPONSOR_COVERAGE_BPS: u64 =
    2_500;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEFAULT_MAX_LANE_SKEW_BPS: u64 = 1_250;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEVNET_HEIGHT: u64 = 125_000;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEVNET_WINDOW: &str =
    "devnet-private-l2-confidential-contract-low-fee-window";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEVNET_RUNTIME: &str =
    "devnet-private-l2-confidential-contract-runtime";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialCallKind {
    Invoke,
    QueryAndInvoke,
    Delegate,
    MultiCall,
    SystemHook,
    SponsorRebate,
}

impl ConfidentialCallKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Invoke => "invoke",
            Self::QueryAndInvoke => "query_and_invoke",
            Self::Delegate => "delegate",
            Self::MultiCall => "multi_call",
            Self::SystemHook => "system_hook",
            Self::SponsorRebate => "sponsor_rebate",
        }
    }

    pub fn default_weight(self) -> u64 {
        match self {
            Self::Invoke => 18,
            Self::QueryAndInvoke => 24,
            Self::Delegate => 28,
            Self::MultiCall => 42,
            Self::SystemHook => 36,
            Self::SponsorRebate => 14,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialCallStatus {
    Submitted,
    Accepted,
    Queued,
    Bundled,
    Executed,
    Settled,
    Expired,
    Rejected,
}

impl ConfidentialCallStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Queued => "queued",
            Self::Bundled => "bundled",
            Self::Executed => "executed",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Submitted | Self::Accepted | Self::Queued)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    Proving,
    ExecutionReady,
    SettlementReady,
    Settled,
    Disputed,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Proving => "proving",
            Self::ExecutionReady => "execution_ready",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn can_settle(self) -> bool {
        matches!(self, Self::SettlementReady)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LanePolicy {
    LowFeeShared,
    ContractDedicated,
    SponsorDedicated,
    PrivacyAmplified,
    Emergency,
}

impl LanePolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFeeShared => "low_fee_shared",
            Self::ContractDedicated => "contract_dedicated",
            Self::SponsorDedicated => "sponsor_dedicated",
            Self::PrivacyAmplified => "privacy_amplified",
            Self::Emergency => "emergency",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStepKind {
    PreStateRead,
    WitnessVerify,
    ContractInvoke,
    EventCommit,
    FeeDebit,
    SponsorCredit,
    NullifierConsume,
    PostStateWrite,
}

impl ExecutionStepKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreStateRead => "pre_state_read",
            Self::WitnessVerify => "witness_verify",
            Self::ContractInvoke => "contract_invoke",
            Self::EventCommit => "event_commit",
            Self::FeeDebit => "fee_debit",
            Self::SponsorCredit => "sponsor_credit",
            Self::NullifierConsume => "nullifier_consume",
            Self::PostStateWrite => "post_state_write",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Draft,
    Published,
    Finalized,
    Disputed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub sealed_call_scheme: String,
    pub pq_auth_scheme: String,
    pub witness_scheme: String,
    pub proof_scheme: String,
    pub sponsor_scheme: String,
    pub bundle_scheme: String,
    pub receipt_scheme: String,
    pub low_fee_window_label: String,
    pub batch_window_blocks: u64,
    pub call_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub max_calls_per_batch: usize,
    pub max_lane_width: usize,
    pub max_bundle_steps: usize,
    pub min_privacy_set: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_sponsor_fee_bps: u64,
    pub min_sponsor_coverage_bps: u64,
    pub max_lane_skew_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_HASH_SUITE.to_string(),
            sealed_call_scheme: PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_SEALED_CALL_SCHEME
                .to_string(),
            pq_auth_scheme: PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_PQ_AUTH_SCHEME
                .to_string(),
            witness_scheme: PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_WITNESS_SCHEME
                .to_string(),
            proof_scheme: PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_PROOF_SCHEME.to_string(),
            sponsor_scheme: PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_SPONSOR_SCHEME
                .to_string(),
            bundle_scheme: PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_BUNDLE_SCHEME.to_string(),
            receipt_scheme: PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_RECEIPT_SCHEME
                .to_string(),
            low_fee_window_label: PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEVNET_WINDOW
                .to_string(),
            batch_window_blocks:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEFAULT_WINDOW_BLOCKS,
            call_ttl_blocks: PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEFAULT_CALL_TTL_BLOCKS,
            settlement_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            max_calls_per_batch:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEFAULT_MAX_CALLS_PER_BATCH,
            max_lane_width: PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEFAULT_MAX_LANE_WIDTH,
            max_bundle_steps:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEFAULT_MAX_BUNDLE_STEPS,
            min_privacy_set: PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEFAULT_MIN_PRIVACY_SET,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEFAULT_MAX_USER_FEE_BPS,
            max_sponsor_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEFAULT_MAX_SPONSOR_FEE_BPS,
            min_sponsor_coverage_bps:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEFAULT_MIN_SPONSOR_COVERAGE_BPS,
            max_lane_skew_bps:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEFAULT_MAX_LANE_SKEW_BPS,
        }
    }

    pub fn validate(&self) -> PrivateL2ConfidentialContractCallBatcherResult<()> {
        if self.protocol_version.is_empty()
            || self.chain_id.is_empty()
            || self.hash_suite.is_empty()
            || self.sealed_call_scheme.is_empty()
            || self.pq_auth_scheme.is_empty()
            || self.witness_scheme.is_empty()
            || self.proof_scheme.is_empty()
            || self.sponsor_scheme.is_empty()
            || self.bundle_scheme.is_empty()
            || self.receipt_scheme.is_empty()
            || self.low_fee_window_label.is_empty()
        {
            return Err("confidential contract call batcher labels cannot be empty".to_string());
        }
        if self.schema_version == 0
            || self.batch_window_blocks == 0
            || self.call_ttl_blocks == 0
            || self.settlement_ttl_blocks == 0
            || self.max_calls_per_batch == 0
            || self.max_lane_width == 0
            || self.max_bundle_steps == 0
            || self.min_privacy_set == 0
            || self.min_pq_security_bits == 0
        {
            return Err(
                "confidential contract call batcher thresholds must be positive".to_string(),
            );
        }
        if self.max_user_fee_bps > PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_MAX_BPS
            || self.max_sponsor_fee_bps > PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_MAX_BPS
            || self.min_sponsor_coverage_bps > PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_MAX_BPS
            || self.max_lane_skew_bps > PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_MAX_BPS
        {
            return Err("confidential contract call batcher bps limits exceed 100%".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_contract_call_batcher_config",
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "sealed_call_scheme": self.sealed_call_scheme,
            "pq_auth_scheme": self.pq_auth_scheme,
            "witness_scheme": self.witness_scheme,
            "proof_scheme": self.proof_scheme,
            "sponsor_scheme": self.sponsor_scheme,
            "bundle_scheme": self.bundle_scheme,
            "receipt_scheme": self.receipt_scheme,
            "low_fee_window_label": self.low_fee_window_label,
            "batch_window_blocks": self.batch_window_blocks,
            "call_ttl_blocks": self.call_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "max_calls_per_batch": self.max_calls_per_batch,
            "max_lane_width": self.max_lane_width,
            "max_bundle_steps": self.max_bundle_steps,
            "min_privacy_set": self.min_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
            "min_sponsor_coverage_bps": self.min_sponsor_coverage_bps,
            "max_lane_skew_bps": self.max_lane_skew_bps,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub next_call_nonce: u64,
    pub next_lane_nonce: u64,
    pub next_bundle_nonce: u64,
    pub next_batch_nonce: u64,
    pub calls_submitted: u64,
    pub calls_accepted: u64,
    pub calls_rejected: u64,
    pub calls_bundled: u64,
    pub calls_settled: u64,
    pub lanes_opened: u64,
    pub bundles_built: u64,
    pub batches_built: u64,
    pub batches_settled: u64,
    pub receipts_published: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "next_call_nonce": self.next_call_nonce,
            "next_lane_nonce": self.next_lane_nonce,
            "next_bundle_nonce": self.next_bundle_nonce,
            "next_batch_nonce": self.next_batch_nonce,
            "calls_submitted": self.calls_submitted,
            "calls_accepted": self.calls_accepted,
            "calls_rejected": self.calls_rejected,
            "calls_bundled": self.calls_bundled,
            "calls_settled": self.calls_settled,
            "lanes_opened": self.lanes_opened,
            "bundles_built": self.bundles_built,
            "batches_built": self.batches_built,
            "batches_settled": self.batches_settled,
            "receipts_published": self.receipts_published,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitCallRequest {
    pub caller_commitment: String,
    pub contract_id: String,
    pub contract_state_root: String,
    pub call_kind: ConfidentialCallKind,
    pub call_payload_root: String,
    pub calldata_ciphertext_root: String,
    pub read_set_root: String,
    pub write_set_root: String,
    pub witness_root: String,
    pub privacy_proof_root: String,
    pub pq_authorization_root: String,
    pub fee_sponsor_root: String,
    pub fee_limit_bps: u64,
    pub sponsor_coverage_bps: u64,
    pub gas_band_root: String,
    pub nullifier_root: String,
    pub lane_hint: Option<String>,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl SubmitCallRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialContractCallBatcherResult<()> {
        validate_commitment(&self.caller_commitment, "caller commitment")?;
        validate_identifier(&self.contract_id, "contract id")?;
        validate_root(&self.contract_state_root, "contract state root")?;
        validate_root(&self.call_payload_root, "call payload root")?;
        validate_root(&self.calldata_ciphertext_root, "calldata ciphertext root")?;
        validate_root(&self.read_set_root, "read set root")?;
        validate_root(&self.write_set_root, "write set root")?;
        validate_root(&self.witness_root, "witness root")?;
        validate_root(&self.privacy_proof_root, "privacy proof root")?;
        validate_root(&self.pq_authorization_root, "pq authorization root")?;
        validate_root(&self.fee_sponsor_root, "fee sponsor root")?;
        validate_root(&self.gas_band_root, "gas band root")?;
        validate_root(&self.nullifier_root, "nullifier root")?;
        if let Some(lane_hint) = &self.lane_hint {
            validate_identifier(lane_hint, "lane hint")?;
        }
        if self.fee_limit_bps > config.max_user_fee_bps {
            return Err("confidential contract call fee exceeds low-fee cap".to_string());
        }
        if self.sponsor_coverage_bps < config.min_sponsor_coverage_bps {
            return Err("confidential contract call sponsor coverage is below policy".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set {
            return Err("confidential contract call privacy set is below policy".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("confidential contract call pq security is below policy".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("confidential contract call expiry must follow open height".to_string());
        }
        if self.expires_at_height - self.opened_at_height > config.call_ttl_blocks {
            return Err("confidential contract call ttl exceeds policy".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildBatchRequest {
    pub call_ids: Vec<String>,
    pub batch_witness_root: String,
    pub batch_proof_root: String,
    pub aggregate_pq_authorization_root: String,
    pub aggregate_fee_sponsor_root: String,
    pub execution_trace_root: String,
    pub runtime_state_root_before: String,
    pub runtime_state_root_after: String,
    pub event_root: String,
    pub low_fee_window_root: String,
    pub total_user_fee_bps: u64,
    pub total_sponsor_fee_bps: u64,
    pub lane_skew_bps: u64,
    pub privacy_set_size: u64,
    pub sealed_at_height: u64,
}

impl BuildBatchRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialContractCallBatcherResult<()> {
        if self.call_ids.is_empty() {
            return Err("confidential contract call batch requires at least one call".to_string());
        }
        if self.call_ids.len() > config.max_calls_per_batch {
            return Err("confidential contract call batch exceeds max call count".to_string());
        }
        validate_root(&self.batch_witness_root, "batch witness root")?;
        validate_root(&self.batch_proof_root, "batch proof root")?;
        validate_root(
            &self.aggregate_pq_authorization_root,
            "aggregate pq authorization root",
        )?;
        validate_root(
            &self.aggregate_fee_sponsor_root,
            "aggregate fee sponsor root",
        )?;
        validate_root(&self.execution_trace_root, "execution trace root")?;
        validate_root(&self.runtime_state_root_before, "runtime state root before")?;
        validate_root(&self.runtime_state_root_after, "runtime state root after")?;
        validate_root(&self.event_root, "event root")?;
        validate_root(&self.low_fee_window_root, "low fee window root")?;
        if self.total_user_fee_bps > config.max_user_fee_bps {
            return Err("confidential contract call batch user fee exceeds policy".to_string());
        }
        if self.total_sponsor_fee_bps > config.max_sponsor_fee_bps {
            return Err("confidential contract call sponsor fee exceeds policy".to_string());
        }
        if self.lane_skew_bps > config.max_lane_skew_bps {
            return Err("confidential contract call lane skew exceeds policy".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set {
            return Err("confidential contract call batch privacy set is below policy".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleBatchRequest {
    pub batch_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub settlement_witness_root: String,
    pub settlement_fee_sponsor_root: String,
    pub aggregate_pq_authorization_root: String,
    pub batch_proof_root: String,
    pub runtime_state_root_after: String,
    pub finalized_at_height: Option<u64>,
    pub settled_at_height: u64,
}

impl SettleBatchRequest {
    pub fn validate(&self) -> PrivateL2ConfidentialContractCallBatcherResult<()> {
        validate_identifier(&self.batch_id, "batch id")?;
        validate_root(&self.settlement_tx_root, "settlement tx root")?;
        validate_root(&self.settlement_proof_root, "settlement proof root")?;
        validate_root(&self.settlement_witness_root, "settlement witness root")?;
        validate_root(
            &self.settlement_fee_sponsor_root,
            "settlement fee sponsor root",
        )?;
        validate_root(
            &self.aggregate_pq_authorization_root,
            "aggregate pq authorization root",
        )?;
        validate_root(&self.batch_proof_root, "batch proof root")?;
        validate_root(&self.runtime_state_root_after, "runtime state root after")?;
        if let Some(finalized_at_height) = self.finalized_at_height {
            if finalized_at_height < self.settled_at_height {
                return Err(
                    "confidential contract call finalization precedes settlement".to_string(),
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedContractCall {
    pub call_id: String,
    pub status: ConfidentialCallStatus,
    pub caller_commitment: String,
    pub contract_id: String,
    pub contract_lane_id: String,
    pub contract_state_root: String,
    pub call_kind: ConfidentialCallKind,
    pub call_payload_root: String,
    pub calldata_ciphertext_root: String,
    pub read_set_root: String,
    pub write_set_root: String,
    pub witness_root: String,
    pub privacy_proof_root: String,
    pub pq_authorization_root: String,
    pub fee_sponsor_root: String,
    pub fee_limit_bps: u64,
    pub sponsor_coverage_bps: u64,
    pub gas_band_root: String,
    pub nullifier_root: String,
    pub sealed_payload_root: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub execution_weight: u64,
}

impl SealedContractCall {
    pub fn public_record(&self) -> Value {
        json!({
            "call_id": self.call_id,
            "status": self.status.as_str(),
            "caller_commitment": self.caller_commitment,
            "contract_id": self.contract_id,
            "contract_lane_id": self.contract_lane_id,
            "contract_state_root": self.contract_state_root,
            "call_kind": self.call_kind.as_str(),
            "call_payload_root": self.call_payload_root,
            "calldata_ciphertext_root": self.calldata_ciphertext_root,
            "read_set_root": self.read_set_root,
            "write_set_root": self.write_set_root,
            "witness_root": self.witness_root,
            "privacy_proof_root": self.privacy_proof_root,
            "pq_authorization_root": self.pq_authorization_root,
            "fee_sponsor_root": self.fee_sponsor_root,
            "fee_limit_bps": self.fee_limit_bps,
            "sponsor_coverage_bps": self.sponsor_coverage_bps,
            "gas_band_root": self.gas_band_root,
            "nullifier_root": self.nullifier_root,
            "sealed_payload_root": self.sealed_payload_root,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "execution_weight": self.execution_weight,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-CALL",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractLane {
    pub lane_id: String,
    pub contract_id: String,
    pub lane_policy: LanePolicy,
    pub lane_nonce: u64,
    pub call_count: u64,
    pub pending_weight: u64,
    pub witness_root: String,
    pub pq_authorization_root: String,
    pub fee_sponsor_root: String,
    pub low_fee_window_root: String,
    pub last_batch_id: Option<String>,
    pub last_updated_height: u64,
}

impl ContractLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "contract_id": self.contract_id,
            "lane_policy": self.lane_policy.as_str(),
            "lane_nonce": self.lane_nonce,
            "call_count": self.call_count,
            "pending_weight": self.pending_weight,
            "witness_root": self.witness_root,
            "pq_authorization_root": self.pq_authorization_root,
            "fee_sponsor_root": self.fee_sponsor_root,
            "low_fee_window_root": self.low_fee_window_root,
            "last_batch_id": self.last_batch_id,
            "last_updated_height": self.last_updated_height,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-LANE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeAggregationWindow {
    pub window_id: String,
    pub label: String,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub call_root: String,
    pub lane_root: String,
    pub sponsor_root: String,
    pub pq_authorization_root: String,
    pub witness_root: String,
    pub proof_root: String,
    pub total_user_fee_bps: u64,
    pub total_sponsor_fee_bps: u64,
    pub privacy_set_size: u64,
}

impl LowFeeAggregationWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "label": self.label,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "call_root": self.call_root,
            "lane_root": self.lane_root,
            "sponsor_root": self.sponsor_root,
            "pq_authorization_root": self.pq_authorization_root,
            "witness_root": self.witness_root,
            "proof_root": self.proof_root,
            "total_user_fee_bps": self.total_user_fee_bps,
            "total_sponsor_fee_bps": self.total_sponsor_fee_bps,
            "privacy_set_size": self.privacy_set_size,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-WINDOW",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionStep {
    pub step_id: String,
    pub step_index: u64,
    pub call_id: String,
    pub contract_lane_id: String,
    pub step_kind: ExecutionStepKind,
    pub input_root: String,
    pub output_root: String,
    pub witness_root: String,
    pub proof_root: String,
    pub fee_sponsor_root: String,
}

impl ExecutionStep {
    pub fn public_record(&self) -> Value {
        json!({
            "step_id": self.step_id,
            "step_index": self.step_index,
            "call_id": self.call_id,
            "contract_lane_id": self.contract_lane_id,
            "step_kind": self.step_kind.as_str(),
            "input_root": self.input_root,
            "output_root": self.output_root,
            "witness_root": self.witness_root,
            "proof_root": self.proof_root,
            "fee_sponsor_root": self.fee_sponsor_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionBundle {
    pub bundle_id: String,
    pub batch_id: String,
    pub bundle_nonce: u64,
    pub call_root: String,
    pub lane_root: String,
    pub step_root: String,
    pub execution_trace_root: String,
    pub runtime_state_root_before: String,
    pub runtime_state_root_after: String,
    pub event_root: String,
    pub witness_root: String,
    pub proof_root: String,
    pub fee_sponsor_root: String,
    pub pq_authorization_root: String,
    pub call_ids: Vec<String>,
    pub step_ids: Vec<String>,
}

impl ExecutionBundle {
    pub fn public_record(&self) -> Value {
        json!({
            "bundle_id": self.bundle_id,
            "batch_id": self.batch_id,
            "bundle_nonce": self.bundle_nonce,
            "call_root": self.call_root,
            "lane_root": self.lane_root,
            "step_root": self.step_root,
            "execution_trace_root": self.execution_trace_root,
            "runtime_state_root_before": self.runtime_state_root_before,
            "runtime_state_root_after": self.runtime_state_root_after,
            "event_root": self.event_root,
            "witness_root": self.witness_root,
            "proof_root": self.proof_root,
            "fee_sponsor_root": self.fee_sponsor_root,
            "pq_authorization_root": self.pq_authorization_root,
            "call_ids": self.call_ids,
            "step_ids": self.step_ids,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-BUNDLE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialContractCallBatch {
    pub batch_id: String,
    pub status: BatchStatus,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub settlement_deadline_height: u64,
    pub call_root: String,
    pub lane_root: String,
    pub window_root: String,
    pub execution_bundle_root: String,
    pub witness_root: String,
    pub proof_root: String,
    pub pq_authorization_root: String,
    pub fee_sponsor_root: String,
    pub runtime_state_root_before: String,
    pub runtime_state_root_after: String,
    pub event_root: String,
    pub low_fee_window_root: String,
    pub total_user_fee_bps: u64,
    pub total_sponsor_fee_bps: u64,
    pub lane_skew_bps: u64,
    pub privacy_set_size: u64,
    pub call_ids: Vec<String>,
    pub lane_ids: Vec<String>,
    pub bundle_id: String,
}

impl ConfidentialContractCallBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "settlement_deadline_height": self.settlement_deadline_height,
            "call_root": self.call_root,
            "lane_root": self.lane_root,
            "window_root": self.window_root,
            "execution_bundle_root": self.execution_bundle_root,
            "witness_root": self.witness_root,
            "proof_root": self.proof_root,
            "pq_authorization_root": self.pq_authorization_root,
            "fee_sponsor_root": self.fee_sponsor_root,
            "runtime_state_root_before": self.runtime_state_root_before,
            "runtime_state_root_after": self.runtime_state_root_after,
            "event_root": self.event_root,
            "low_fee_window_root": self.low_fee_window_root,
            "total_user_fee_bps": self.total_user_fee_bps,
            "total_sponsor_fee_bps": self.total_sponsor_fee_bps,
            "lane_skew_bps": self.lane_skew_bps,
            "privacy_set_size": self.privacy_set_size,
            "call_ids": self.call_ids,
            "lane_ids": self.lane_ids,
            "bundle_id": self.bundle_id,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-BATCH",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub status: ReceiptStatus,
    pub batch_root: String,
    pub execution_bundle_root: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub settlement_witness_root: String,
    pub settlement_fee_sponsor_root: String,
    pub aggregate_pq_authorization_root: String,
    pub runtime_state_root_after: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub published_at_height: u64,
    pub finalized_at_height: Option<u64>,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "batch_root": self.batch_root,
            "execution_bundle_root": self.execution_bundle_root,
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_proof_root": self.settlement_proof_root,
            "settlement_witness_root": self.settlement_witness_root,
            "settlement_fee_sponsor_root": self.settlement_fee_sponsor_root,
            "aggregate_pq_authorization_root": self.aggregate_pq_authorization_root,
            "runtime_state_root_after": self.runtime_state_root_after,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "published_at_height": self.published_at_height,
            "finalized_at_height": self.finalized_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-RECEIPT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub runtime_root: String,
    pub active_calls: BTreeMap<String, SealedContractCall>,
    pub contract_lanes: BTreeMap<String, ContractLane>,
    pub aggregation_windows: BTreeMap<String, LowFeeAggregationWindow>,
    pub execution_steps: BTreeMap<String, ExecutionStep>,
    pub execution_bundles: BTreeMap<String, ExecutionBundle>,
    pub batches: BTreeMap<String, ConfidentialContractCallBatch>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub consumed_nullifier_roots: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let runtime_root = domain_hash(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-DEVNET-RUNTIME",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEVNET_RUNTIME),
            ],
            32,
        );
        Self {
            config,
            counters: Counters::default(),
            current_height: PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_DEVNET_HEIGHT,
            runtime_root,
            active_calls: BTreeMap::new(),
            contract_lanes: BTreeMap::new(),
            aggregation_windows: BTreeMap::new(),
            execution_steps: BTreeMap::new(),
            execution_bundles: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            consumed_nullifier_roots: BTreeSet::new(),
        }
    }

    pub fn submit_call(
        &mut self,
        request: SubmitCallRequest,
    ) -> PrivateL2ConfidentialContractCallBatcherResult<SealedContractCall> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if request.opened_at_height
            < self
                .current_height
                .saturating_sub(self.config.call_ttl_blocks)
        {
            return Err(
                "confidential contract call open height is outside accepted window".to_string(),
            );
        }
        if self
            .consumed_nullifier_roots
            .contains(&request.nullifier_root)
            || self
                .active_calls
                .values()
                .any(|call| call.nullifier_root == request.nullifier_root)
        {
            self.counters.calls_rejected += 1;
            return Err(
                "confidential contract call nullifier root is already pending or consumed"
                    .to_string(),
            );
        }

        let call_nonce = self.counters.next_call_nonce;
        let lane_id = request.lane_hint.clone().unwrap_or_else(|| {
            contract_lane_id(call_nonce, &request.contract_id, LanePolicy::LowFeeShared)
        });
        let sealed_payload_root = sealed_call_payload_root(&request, &lane_id, call_nonce);
        let call_id = confidential_call_id(
            call_nonce,
            &request.caller_commitment,
            &request.contract_id,
            &lane_id,
            &sealed_payload_root,
        );
        let call = SealedContractCall {
            call_id: call_id.clone(),
            status: ConfidentialCallStatus::Accepted,
            caller_commitment: request.caller_commitment,
            contract_id: request.contract_id,
            contract_lane_id: lane_id.clone(),
            contract_state_root: request.contract_state_root,
            call_kind: request.call_kind,
            call_payload_root: request.call_payload_root,
            calldata_ciphertext_root: request.calldata_ciphertext_root,
            read_set_root: request.read_set_root,
            write_set_root: request.write_set_root,
            witness_root: request.witness_root,
            privacy_proof_root: request.privacy_proof_root,
            pq_authorization_root: request.pq_authorization_root,
            fee_sponsor_root: request.fee_sponsor_root,
            fee_limit_bps: request.fee_limit_bps,
            sponsor_coverage_bps: request.sponsor_coverage_bps,
            gas_band_root: request.gas_band_root,
            nullifier_root: request.nullifier_root,
            sealed_payload_root,
            submitted_at_height: request.opened_at_height,
            expires_at_height: request.expires_at_height,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            execution_weight: request.call_kind.default_weight(),
        };

        self.upsert_lane(&lane_id, &call)?;
        self.counters.next_call_nonce += 1;
        self.counters.calls_submitted += 1;
        self.counters.calls_accepted += 1;
        self.current_height = self.current_height.max(call.submitted_at_height);
        self.active_calls.insert(call_id, call.clone());
        Ok(call)
    }

    pub fn build_batch(
        &mut self,
        request: BuildBatchRequest,
    ) -> PrivateL2ConfidentialContractCallBatcherResult<ConfidentialContractCallBatch> {
        self.config.validate()?;
        request.validate(&self.config)?;
        let unique_calls = request.call_ids.iter().collect::<BTreeSet<_>>();
        if unique_calls.len() != request.call_ids.len() {
            return Err(
                "confidential contract call batch cannot include duplicate calls".to_string(),
            );
        }

        let mut selected = Vec::with_capacity(request.call_ids.len());
        for call_id in &request.call_ids {
            let call = self
                .active_calls
                .get(call_id)
                .cloned()
                .ok_or_else(|| format!("unknown confidential contract call id {call_id}"))?;
            if !call.status.live() {
                return Err(format!("confidential contract call {call_id} is not live"));
            }
            if call.expires_at_height < request.sealed_at_height {
                return Err(format!(
                    "confidential contract call {call_id} expired before batch sealing"
                ));
            }
            selected.push(call);
        }

        let lane_ids = selected
            .iter()
            .map(|call| call.contract_lane_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if lane_ids.iter().any(|lane_id| {
            selected
                .iter()
                .filter(|call| &call.contract_lane_id == lane_id)
                .count()
                > self.config.max_lane_width
        }) {
            return Err("confidential contract call batch exceeds lane width policy".to_string());
        }

        let batch_nonce = self.counters.next_batch_nonce;
        let batch_id =
            confidential_batch_id(batch_nonce, &request.call_ids, request.sealed_at_height);
        let call_records = selected
            .iter()
            .map(SealedContractCall::public_record)
            .collect::<Vec<_>>();
        let call_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-BATCH-CALL",
            &call_records,
        );
        let lane_records = lane_ids
            .iter()
            .filter_map(|lane_id| self.contract_lanes.get(lane_id))
            .map(ContractLane::public_record)
            .collect::<Vec<_>>();
        let lane_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-BATCH-LANE",
            &lane_records,
        );
        let window_id = aggregation_window_id(batch_nonce, &call_root, request.sealed_at_height);
        let window = LowFeeAggregationWindow {
            window_id: window_id.clone(),
            label: self.config.low_fee_window_label.clone(),
            opened_at_height: request
                .sealed_at_height
                .saturating_sub(self.config.batch_window_blocks),
            sealed_at_height: request.sealed_at_height,
            call_root: call_root.clone(),
            lane_root: lane_root.clone(),
            sponsor_root: request.aggregate_fee_sponsor_root.clone(),
            pq_authorization_root: request.aggregate_pq_authorization_root.clone(),
            witness_root: request.batch_witness_root.clone(),
            proof_root: request.batch_proof_root.clone(),
            total_user_fee_bps: request.total_user_fee_bps,
            total_sponsor_fee_bps: request.total_sponsor_fee_bps,
            privacy_set_size: request.privacy_set_size,
        };
        let window_root = window.state_root();

        let mut execution_steps = Vec::new();
        let mut step_ids = Vec::new();
        for (call_index, call) in selected.iter().enumerate() {
            for step_kind in [
                ExecutionStepKind::PreStateRead,
                ExecutionStepKind::WitnessVerify,
                ExecutionStepKind::ContractInvoke,
                ExecutionStepKind::FeeDebit,
                ExecutionStepKind::SponsorCredit,
                ExecutionStepKind::NullifierConsume,
                ExecutionStepKind::PostStateWrite,
            ] {
                let step_index = execution_steps.len() as u64;
                if execution_steps.len() >= self.config.max_bundle_steps {
                    return Err(
                        "confidential contract call execution bundle exceeds max steps".to_string(),
                    );
                }
                let step = derive_execution_step(
                    &batch_id,
                    call,
                    call_index as u64,
                    step_index,
                    step_kind,
                    &request,
                );
                step_ids.push(step.step_id.clone());
                execution_steps.push(step);
            }
        }
        let step_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-BUNDLE-STEP",
            &execution_steps
                .iter()
                .map(ExecutionStep::public_record)
                .collect::<Vec<_>>(),
        );
        let bundle_nonce = self.counters.next_bundle_nonce;
        let bundle_id = execution_bundle_id(bundle_nonce, &batch_id, &call_root, &step_root);
        let bundle = ExecutionBundle {
            bundle_id: bundle_id.clone(),
            batch_id: batch_id.clone(),
            bundle_nonce,
            call_root: call_root.clone(),
            lane_root: lane_root.clone(),
            step_root,
            execution_trace_root: request.execution_trace_root.clone(),
            runtime_state_root_before: request.runtime_state_root_before.clone(),
            runtime_state_root_after: request.runtime_state_root_after.clone(),
            event_root: request.event_root.clone(),
            witness_root: request.batch_witness_root.clone(),
            proof_root: request.batch_proof_root.clone(),
            fee_sponsor_root: request.aggregate_fee_sponsor_root.clone(),
            pq_authorization_root: request.aggregate_pq_authorization_root.clone(),
            call_ids: request.call_ids.clone(),
            step_ids: step_ids.clone(),
        };
        let execution_bundle_root = bundle.state_root();

        let batch = ConfidentialContractCallBatch {
            batch_id: batch_id.clone(),
            status: BatchStatus::SettlementReady,
            opened_at_height: request
                .sealed_at_height
                .saturating_sub(self.config.batch_window_blocks),
            sealed_at_height: request.sealed_at_height,
            settlement_deadline_height: request.sealed_at_height
                + self.config.settlement_ttl_blocks,
            call_root,
            lane_root,
            window_root,
            execution_bundle_root,
            witness_root: request.batch_witness_root,
            proof_root: request.batch_proof_root,
            pq_authorization_root: request.aggregate_pq_authorization_root,
            fee_sponsor_root: request.aggregate_fee_sponsor_root,
            runtime_state_root_before: request.runtime_state_root_before,
            runtime_state_root_after: request.runtime_state_root_after,
            event_root: request.event_root,
            low_fee_window_root: request.low_fee_window_root,
            total_user_fee_bps: request.total_user_fee_bps,
            total_sponsor_fee_bps: request.total_sponsor_fee_bps,
            lane_skew_bps: request.lane_skew_bps,
            privacy_set_size: request.privacy_set_size,
            call_ids: request.call_ids.clone(),
            lane_ids: lane_ids.clone(),
            bundle_id,
        };

        for call_id in &request.call_ids {
            if let Some(call) = self.active_calls.get_mut(call_id) {
                call.status = ConfidentialCallStatus::Bundled;
            }
        }
        for lane_id in &lane_ids {
            if let Some(lane) = self.contract_lanes.get_mut(lane_id) {
                lane.last_batch_id = Some(batch_id.clone());
                lane.last_updated_height = request.sealed_at_height;
                lane.low_fee_window_root = batch.low_fee_window_root.clone();
            }
        }
        for step in execution_steps {
            self.execution_steps.insert(step.step_id.clone(), step);
        }
        self.aggregation_windows.insert(window_id, window);
        self.runtime_root = batch.runtime_state_root_after.clone();
        self.execution_bundles
            .insert(bundle.batch_id.clone(), bundle);
        self.batches.insert(batch_id, batch.clone());
        self.counters.next_batch_nonce += 1;
        self.counters.next_bundle_nonce += 1;
        self.counters.calls_bundled += selected.len() as u64;
        self.counters.bundles_built += 1;
        self.counters.batches_built += 1;
        self.current_height = self.current_height.max(batch.sealed_at_height);
        Ok(batch)
    }

    pub fn settle_batch(
        &mut self,
        request: SettleBatchRequest,
    ) -> PrivateL2ConfidentialContractCallBatcherResult<SettlementReceipt> {
        self.config.validate()?;
        request.validate()?;
        let state_root_before = self.state_root();
        let batch = self
            .batches
            .get(&request.batch_id)
            .cloned()
            .ok_or_else(|| {
                format!(
                    "unknown confidential contract call batch id {}",
                    request.batch_id
                )
            })?;
        if !batch.status.can_settle() {
            return Err("confidential contract call batch is not settlement ready".to_string());
        }
        if request.settled_at_height > batch.settlement_deadline_height {
            return Err("confidential contract call batch settlement deadline elapsed".to_string());
        }
        if request.aggregate_pq_authorization_root != batch.pq_authorization_root {
            return Err(
                "confidential contract call batch pq authorization root mismatch".to_string(),
            );
        }
        if request.batch_proof_root != batch.proof_root {
            return Err("confidential contract call batch proof root mismatch".to_string());
        }
        if request.runtime_state_root_after != batch.runtime_state_root_after {
            return Err("confidential contract call runtime root mismatch".to_string());
        }

        for call_id in &batch.call_ids {
            if let Some(call) = self.active_calls.get_mut(call_id) {
                call.status = ConfidentialCallStatus::Settled;
                self.consumed_nullifier_roots
                    .insert(call.nullifier_root.clone());
            }
        }
        if let Some(stored_batch) = self.batches.get_mut(&request.batch_id) {
            stored_batch.status = BatchStatus::Settled;
        }
        self.runtime_root = request.runtime_state_root_after.clone();
        self.current_height = self.current_height.max(request.settled_at_height);
        self.counters.batches_settled += 1;
        self.counters.calls_settled += batch.call_ids.len() as u64;
        self.counters.receipts_published += 1;
        let state_root_after = self.state_root();
        let receipt_id = settlement_receipt_id(
            &request.batch_id,
            &request.settlement_tx_root,
            &request.settlement_proof_root,
            request.settled_at_height,
        );
        let receipt = SettlementReceipt {
            receipt_id: receipt_id.clone(),
            batch_id: request.batch_id,
            status: if request.finalized_at_height.is_some() {
                ReceiptStatus::Finalized
            } else {
                ReceiptStatus::Published
            },
            batch_root: batch.state_root(),
            execution_bundle_root: batch.execution_bundle_root,
            settlement_tx_root: request.settlement_tx_root,
            settlement_proof_root: request.settlement_proof_root,
            settlement_witness_root: request.settlement_witness_root,
            settlement_fee_sponsor_root: request.settlement_fee_sponsor_root,
            aggregate_pq_authorization_root: request.aggregate_pq_authorization_root,
            runtime_state_root_after: request.runtime_state_root_after,
            state_root_before,
            state_root_after,
            published_at_height: request.settled_at_height,
            finalized_at_height: request.finalized_at_height,
        };
        self.receipts.insert(receipt_id, receipt.clone());
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "current_height": self.current_height,
            "runtime_root": self.runtime_root,
            "active_call_root": self.active_call_root(),
            "contract_lane_root": self.contract_lane_root(),
            "aggregation_window_root": self.aggregation_window_root(),
            "execution_step_root": self.execution_step_root(),
            "execution_bundle_root": self.execution_bundle_root(),
            "batch_root": self.batch_root(),
            "receipt_root": self.receipt_root(),
            "consumed_nullifier_root": self.consumed_nullifier_root(),
            "state_root": self.state_root_without_self_reference(),
        })
    }

    pub fn state_root(&self) -> String {
        self.state_root_without_self_reference()
    }

    pub fn active_call_root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-STATE-CALL",
            &self
                .active_calls
                .values()
                .map(SealedContractCall::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn contract_lane_root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-STATE-LANE",
            &self
                .contract_lanes
                .values()
                .map(ContractLane::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn aggregation_window_root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-STATE-WINDOW",
            &self
                .aggregation_windows
                .values()
                .map(LowFeeAggregationWindow::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn execution_step_root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-STATE-STEP",
            &self
                .execution_steps
                .values()
                .map(ExecutionStep::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn execution_bundle_root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-STATE-BUNDLE",
            &self
                .execution_bundles
                .values()
                .map(ExecutionBundle::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn batch_root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-STATE-BATCH",
            &self
                .batches
                .values()
                .map(ConfidentialContractCallBatch::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn receipt_root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-STATE-RECEIPT",
            &self
                .receipts
                .values()
                .map(SettlementReceipt::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn consumed_nullifier_root(&self) -> String {
        merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-STATE-CONSUMED-NULLIFIER",
            &self
                .consumed_nullifier_roots
                .iter()
                .map(|root| json!(root))
                .collect::<Vec<_>>(),
        )
    }

    fn state_root_without_self_reference(&self) -> String {
        domain_hash(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-STATE",
            &[
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Int(self.current_height as i128),
                HashPart::Str(&self.runtime_root),
                HashPart::Str(&self.active_call_root()),
                HashPart::Str(&self.contract_lane_root()),
                HashPart::Str(&self.aggregation_window_root()),
                HashPart::Str(&self.execution_step_root()),
                HashPart::Str(&self.execution_bundle_root()),
                HashPart::Str(&self.batch_root()),
                HashPart::Str(&self.receipt_root()),
                HashPart::Str(&self.consumed_nullifier_root()),
            ],
            32,
        )
    }

    fn upsert_lane(
        &mut self,
        lane_id: &str,
        call: &SealedContractCall,
    ) -> PrivateL2ConfidentialContractCallBatcherResult<()> {
        if let Some(lane) = self.contract_lanes.get_mut(lane_id) {
            if lane.contract_id != call.contract_id {
                return Err("confidential contract call lane contract mismatch".to_string());
            }
            lane.call_count += 1;
            lane.pending_weight += call.execution_weight;
            lane.witness_root = merge_roots(
                "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-LANE-WITNESS-MERGE",
                &lane.witness_root,
                &call.witness_root,
            );
            lane.pq_authorization_root = merge_roots(
                "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-LANE-PQ-MERGE",
                &lane.pq_authorization_root,
                &call.pq_authorization_root,
            );
            lane.fee_sponsor_root = merge_roots(
                "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-LANE-SPONSOR-MERGE",
                &lane.fee_sponsor_root,
                &call.fee_sponsor_root,
            );
            lane.last_updated_height = call.submitted_at_height;
        } else {
            let lane_nonce = self.counters.next_lane_nonce;
            let low_fee_window_root = domain_hash(
                "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-LANE-WINDOW",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(lane_id),
                    HashPart::Str(&self.config.low_fee_window_label),
                ],
                32,
            );
            let lane = ContractLane {
                lane_id: lane_id.to_string(),
                contract_id: call.contract_id.clone(),
                lane_policy: LanePolicy::LowFeeShared,
                lane_nonce,
                call_count: 1,
                pending_weight: call.execution_weight,
                witness_root: call.witness_root.clone(),
                pq_authorization_root: call.pq_authorization_root.clone(),
                fee_sponsor_root: call.fee_sponsor_root.clone(),
                low_fee_window_root,
                last_batch_id: None,
                last_updated_height: call.submitted_at_height,
            };
            self.contract_lanes.insert(lane_id.to_string(), lane);
            self.counters.next_lane_nonce += 1;
            self.counters.lanes_opened += 1;
        }
        Ok(())
    }
}

fn sealed_call_payload_root(request: &SubmitCallRequest, lane_id: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-SEALED-PAYLOAD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_CONTRACT_CALL_BATCHER_SEALED_CALL_SCHEME),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.caller_commitment),
            HashPart::Str(&request.contract_id),
            HashPart::Str(lane_id),
            HashPart::Str(&request.contract_state_root),
            HashPart::Str(request.call_kind.as_str()),
            HashPart::Str(&request.call_payload_root),
            HashPart::Str(&request.calldata_ciphertext_root),
            HashPart::Str(&request.read_set_root),
            HashPart::Str(&request.write_set_root),
            HashPart::Str(&request.witness_root),
            HashPart::Str(&request.privacy_proof_root),
            HashPart::Str(&request.pq_authorization_root),
            HashPart::Str(&request.fee_sponsor_root),
            HashPart::Int(request.fee_limit_bps as i128),
            HashPart::Int(request.sponsor_coverage_bps as i128),
            HashPart::Str(&request.gas_band_root),
            HashPart::Str(&request.nullifier_root),
            HashPart::Int(request.opened_at_height as i128),
            HashPart::Int(request.expires_at_height as i128),
        ],
        32,
    )
}

fn confidential_call_id(
    nonce: u64,
    caller_commitment: &str,
    contract_id: &str,
    lane_id: &str,
    sealed_payload_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-CALL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(caller_commitment),
            HashPart::Str(contract_id),
            HashPart::Str(lane_id),
            HashPart::Str(sealed_payload_root),
        ],
        32,
    )
}

fn contract_lane_id(nonce: u64, contract_id: &str, policy: LanePolicy) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(contract_id),
            HashPart::Str(policy.as_str()),
        ],
        32,
    )
}

fn confidential_batch_id(batch_nonce: u64, call_ids: &[String], sealed_at_height: u64) -> String {
    let call_root = merkle_root(
        "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-BATCH-ID-CALL",
        &call_ids
            .iter()
            .map(|call_id| json!(call_id))
            .collect::<Vec<_>>(),
    );
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(batch_nonce as i128),
            HashPart::Str(&call_root),
            HashPart::Int(sealed_at_height as i128),
        ],
        32,
    )
}

fn aggregation_window_id(batch_nonce: u64, call_root: &str, sealed_at_height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(batch_nonce as i128),
            HashPart::Str(call_root),
            HashPart::Int(sealed_at_height as i128),
        ],
        32,
    )
}

fn execution_bundle_id(
    bundle_nonce: u64,
    batch_id: &str,
    call_root: &str,
    step_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-BUNDLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(bundle_nonce as i128),
            HashPart::Str(batch_id),
            HashPart::Str(call_root),
            HashPart::Str(step_root),
        ],
        32,
    )
}

fn execution_step_id(
    batch_id: &str,
    call_id: &str,
    call_index: u64,
    step_index: u64,
    step_kind: ExecutionStepKind,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-STEP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(call_id),
            HashPart::Int(call_index as i128),
            HashPart::Int(step_index as i128),
            HashPart::Str(step_kind.as_str()),
        ],
        32,
    )
}

fn derive_execution_step(
    batch_id: &str,
    call: &SealedContractCall,
    call_index: u64,
    step_index: u64,
    step_kind: ExecutionStepKind,
    request: &BuildBatchRequest,
) -> ExecutionStep {
    let step_id = execution_step_id(batch_id, &call.call_id, call_index, step_index, step_kind);
    let input_root = domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-STEP-INPUT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(&call.call_id),
            HashPart::Str(step_kind.as_str()),
            HashPart::Str(&call.read_set_root),
            HashPart::Str(&call.contract_state_root),
            HashPart::Str(&request.runtime_state_root_before),
        ],
        32,
    );
    let output_root = domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-STEP-OUTPUT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(&call.call_id),
            HashPart::Str(step_kind.as_str()),
            HashPart::Str(&call.write_set_root),
            HashPart::Str(&request.runtime_state_root_after),
            HashPart::Str(&request.event_root),
        ],
        32,
    );
    ExecutionStep {
        step_id,
        step_index,
        call_id: call.call_id.clone(),
        contract_lane_id: call.contract_lane_id.clone(),
        step_kind,
        input_root,
        output_root,
        witness_root: merge_roots(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-STEP-WITNESS",
            &call.witness_root,
            &request.batch_witness_root,
        ),
        proof_root: merge_roots(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-STEP-PROOF",
            &call.privacy_proof_root,
            &request.batch_proof_root,
        ),
        fee_sponsor_root: merge_roots(
            "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-STEP-SPONSOR",
            &call.fee_sponsor_root,
            &request.aggregate_fee_sponsor_root,
        ),
    }
}

fn settlement_receipt_id(
    batch_id: &str,
    settlement_tx_root: &str,
    settlement_proof_root: &str,
    settled_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CONTRACT-CALL-BATCHER-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(settlement_tx_root),
            HashPart::Str(settlement_proof_root),
            HashPart::Int(settled_at_height as i128),
        ],
        32,
    )
}

fn merge_roots(domain: &str, left: &str, right: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(left),
            HashPart::Str(right),
        ],
        32,
    )
}

fn validate_identifier(
    value: &str,
    label: &str,
) -> PrivateL2ConfidentialContractCallBatcherResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    if value.len() > 256 {
        return Err(format!("{label} is too long"));
    }
    Ok(())
}

fn validate_commitment(
    value: &str,
    label: &str,
) -> PrivateL2ConfidentialContractCallBatcherResult<()> {
    validate_identifier(value, label)?;
    if value.len() < 16 {
        return Err(format!("{label} must be commitment-like"));
    }
    Ok(())
}

fn validate_root(value: &str, label: &str) -> PrivateL2ConfidentialContractCallBatcherResult<()> {
    validate_identifier(value, label)?;
    if value.len() < 16 {
        return Err(format!("{label} must be root-like"));
    }
    Ok(())
}
