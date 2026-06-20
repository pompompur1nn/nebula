use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeeProofDaAggregatorResult<T> = Result<T, String>;

pub const PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_PROTOCOL_VERSION: &str =
    "private-l2-low-fee-proof-da-aggregator-v1";
pub const PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_HASH_SUITE: &str =
    "shake256-merkle-domain-separated";
pub const PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_RECURSIVE_PROOF_SCHEME: &str =
    "winterfell-stark-recursive-v1";
pub const PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_DA_SCHEME: &str = "encrypted-erasure-coded-da-v1";
pub const PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_DEFAULT_BATCH_WINDOW_MS: u64 = 450;
pub const PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_DEFAULT_MAX_FRAGMENTS_PER_BATCH: usize = 128;
pub const PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_DEFAULT_MAX_DA_SHARDS_PER_BATCH: usize = 256;
pub const PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_DEFAULT_MAX_FEE_BPS: u64 = 24;
pub const PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_DEFAULT_MIN_PRIVACY_SET: u64 = 128;
pub const PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_DEFAULT_MIN_PQ_SECURITY_BITS: u64 = 256;
pub const PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_MAX_RECORDS: usize = 262_144;
pub const PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_DEVNET_HEIGHT: u64 = 100_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregationLane {
    PrivateContractCall,
    ConfidentialTokenMint,
    PrivateDefiSwap,
    MoneroExit,
    RuntimeCheckpoint,
    Emergency,
}

impl AggregationLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateContractCall => "private_contract_call",
            Self::ConfidentialTokenMint => "confidential_token_mint",
            Self::PrivateDefiSwap => "private_defi_swap",
            Self::MoneroExit => "monero_exit",
            Self::RuntimeCheckpoint => "runtime_checkpoint",
            Self::Emergency => "emergency",
        }
    }

    pub fn priority_score(self) -> u64 {
        match self {
            Self::Emergency => 100,
            Self::MoneroExit => 80,
            Self::PrivateDefiSwap => 65,
            Self::PrivateContractCall => 55,
            Self::ConfidentialTokenMint => 45,
            Self::RuntimeCheckpoint => 35,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofFragmentStatus {
    Submitted,
    Accepted,
    Aggregated,
    Published,
    Settled,
    Rejected,
    Expired,
}

impl ProofFragmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Aggregated => "aggregated",
            Self::Published => "published",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn selectable(self) -> bool {
        matches!(self, Self::Submitted | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaShardStatus {
    Committed,
    Assigned,
    Published,
    Settled,
    Rejected,
}

impl DaShardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Assigned => "assigned",
            Self::Published => "published",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaShardKind {
    EncryptedWitness,
    ErasureChunk,
    StateDiff,
    CallTrace,
    MoneroAnchorHint,
    RecursiveProofHint,
}

impl DaShardKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EncryptedWitness => "encrypted_witness",
            Self::ErasureChunk => "erasure_chunk",
            Self::StateDiff => "state_diff",
            Self::CallTrace => "call_trace",
            Self::MoneroAnchorHint => "monero_anchor_hint",
            Self::RecursiveProofHint => "recursive_proof_hint",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregationBatchStatus {
    Open,
    Sealed,
    Published,
    SettlementReady,
    Settled,
    Rejected,
}

impl AggregationBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Published => "published",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationStatus {
    Draft,
    Published,
    Finalized,
    Disputed,
}

impl PublicationStatus {
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
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_signature_scheme: String,
    pub recursive_proof_scheme: String,
    pub da_scheme: String,
    pub target_batch_window_ms: u64,
    pub max_fragments_per_batch: usize,
    pub max_da_shards_per_batch: usize,
    pub max_fee_bps: u64,
    pub min_privacy_set: u64,
    pub min_pq_security_bits: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_HASH_SUITE.to_string(),
            pq_signature_scheme: PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_PQ_SIGNATURE_SCHEME
                .to_string(),
            recursive_proof_scheme: PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_RECURSIVE_PROOF_SCHEME
                .to_string(),
            da_scheme: PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_DA_SCHEME.to_string(),
            target_batch_window_ms: PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_DEFAULT_BATCH_WINDOW_MS,
            max_fragments_per_batch:
                PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_DEFAULT_MAX_FRAGMENTS_PER_BATCH,
            max_da_shards_per_batch:
                PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_DEFAULT_MAX_DA_SHARDS_PER_BATCH,
            max_fee_bps: PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_DEFAULT_MAX_FEE_BPS,
            min_privacy_set: PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_DEFAULT_MIN_PRIVACY_SET,
            min_pq_security_bits:
                PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn validate(&self) -> PrivateL2LowFeeProofDaAggregatorResult<()> {
        if self.protocol_version.trim().is_empty()
            || self.chain_id.trim().is_empty()
            || self.hash_suite.trim().is_empty()
            || self.pq_signature_scheme.trim().is_empty()
            || self.recursive_proof_scheme.trim().is_empty()
            || self.da_scheme.trim().is_empty()
        {
            return Err("proof da aggregator config labels cannot be empty".to_string());
        }
        if self.target_batch_window_ms == 0
            || self.max_fragments_per_batch == 0
            || self.max_da_shards_per_batch == 0
            || self.max_fee_bps == 0
            || self.min_privacy_set == 0
            || self.min_pq_security_bits == 0
        {
            return Err("proof da aggregator config thresholds must be positive".to_string());
        }
        if self.max_fee_bps > PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_MAX_BPS {
            return Err("proof da aggregator fee cap cannot exceed 100%".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_proof_da_aggregator_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_SCHEMA_VERSION,
            "hash_suite": self.hash_suite,
            "pq_signature_scheme": self.pq_signature_scheme,
            "recursive_proof_scheme": self.recursive_proof_scheme,
            "da_scheme": self.da_scheme,
            "target_batch_window_ms": self.target_batch_window_ms,
            "max_fragments_per_batch": self.max_fragments_per_batch,
            "max_da_shards_per_batch": self.max_da_shards_per_batch,
            "max_fee_bps": self.max_fee_bps,
            "min_privacy_set": self.min_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub next_fragment_nonce: u64,
    pub next_da_shard_nonce: u64,
    pub next_batch_nonce: u64,
    pub next_receipt_nonce: u64,
    pub fragments_submitted: u64,
    pub fragments_accepted: u64,
    pub fragments_rejected: u64,
    pub da_shards_committed: u64,
    pub batches_built: u64,
    pub batches_published: u64,
    pub batches_settled: u64,
    pub receipts_issued: u64,
    pub total_weight: u64,
    pub total_fee_bps_saved: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_proof_da_aggregator_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_PROTOCOL_VERSION,
            "next_fragment_nonce": self.next_fragment_nonce,
            "next_da_shard_nonce": self.next_da_shard_nonce,
            "next_batch_nonce": self.next_batch_nonce,
            "next_receipt_nonce": self.next_receipt_nonce,
            "fragments_submitted": self.fragments_submitted,
            "fragments_accepted": self.fragments_accepted,
            "fragments_rejected": self.fragments_rejected,
            "da_shards_committed": self.da_shards_committed,
            "batches_built": self.batches_built,
            "batches_published": self.batches_published,
            "batches_settled": self.batches_settled,
            "receipts_issued": self.receipts_issued,
            "total_weight": self.total_weight,
            "total_fee_bps_saved": self.total_fee_bps_saved,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofFragmentRequest {
    pub lane: AggregationLane,
    pub owner_commitment: String,
    pub contract_commitment: String,
    pub call_commitment: String,
    pub witness_root: String,
    pub local_proof_root: String,
    pub public_input_root: String,
    pub nullifier_root: String,
    pub pq_authorization_root: String,
    pub fee_sponsor_root: String,
    pub privacy_set_size: u64,
    pub estimated_weight: u64,
    pub max_fee_bps: u64,
    pub opened_at_height: u64,
    pub deadline_height: u64,
}

impl ProofFragmentRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeProofDaAggregatorResult<()> {
        validate_root("owner_commitment", &self.owner_commitment)?;
        validate_root("contract_commitment", &self.contract_commitment)?;
        validate_root("call_commitment", &self.call_commitment)?;
        validate_root("witness_root", &self.witness_root)?;
        validate_root("local_proof_root", &self.local_proof_root)?;
        validate_root("public_input_root", &self.public_input_root)?;
        validate_root("nullifier_root", &self.nullifier_root)?;
        validate_root("pq_authorization_root", &self.pq_authorization_root)?;
        validate_root("fee_sponsor_root", &self.fee_sponsor_root)?;
        if self.privacy_set_size < config.min_privacy_set {
            return Err("proof fragment privacy set is below policy".to_string());
        }
        if self.estimated_weight == 0 {
            return Err("proof fragment weight must be positive".to_string());
        }
        if self.max_fee_bps == 0 || self.max_fee_bps > config.max_fee_bps {
            return Err("proof fragment fee cap exceeds low-fee policy".to_string());
        }
        if self.opened_at_height >= self.deadline_height {
            return Err("proof fragment deadline must be after open height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_proof_da_fragment_request",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_PROTOCOL_VERSION,
            "lane": self.lane.as_str(),
            "owner_commitment": self.owner_commitment,
            "contract_commitment": self.contract_commitment,
            "call_commitment": self.call_commitment,
            "witness_root": self.witness_root,
            "local_proof_root": self.local_proof_root,
            "public_input_root": self.public_input_root,
            "nullifier_root": self.nullifier_root,
            "pq_authorization_root": self.pq_authorization_root,
            "fee_sponsor_root": self.fee_sponsor_root,
            "privacy_set_size": self.privacy_set_size,
            "estimated_weight": self.estimated_weight,
            "max_fee_bps": self.max_fee_bps,
            "opened_at_height": self.opened_at_height,
            "deadline_height": self.deadline_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofFragment {
    pub fragment_id: String,
    pub nonce: u64,
    pub lane: AggregationLane,
    pub status: ProofFragmentStatus,
    pub owner_commitment: String,
    pub contract_commitment: String,
    pub call_commitment: String,
    pub witness_root: String,
    pub local_proof_root: String,
    pub public_input_root: String,
    pub nullifier_root: String,
    pub pq_authorization_root: String,
    pub fee_sponsor_root: String,
    pub privacy_set_size: u64,
    pub estimated_weight: u64,
    pub max_fee_bps: u64,
    pub opened_at_height: u64,
    pub deadline_height: u64,
    pub fragment_root: String,
    pub batch_id: Option<String>,
}

impl ProofFragment {
    pub fn from_request(
        nonce: u64,
        request: ProofFragmentRequest,
    ) -> PrivateL2LowFeeProofDaAggregatorResult<Self> {
        let fragment_root =
            proof_da_payload_root("PROOF-FRAGMENT-PAYLOAD", &request.public_record());
        let fragment_id = proof_fragment_id(nonce, request.lane, &fragment_root);
        Ok(Self {
            fragment_id,
            nonce,
            lane: request.lane,
            status: ProofFragmentStatus::Accepted,
            owner_commitment: request.owner_commitment,
            contract_commitment: request.contract_commitment,
            call_commitment: request.call_commitment,
            witness_root: request.witness_root,
            local_proof_root: request.local_proof_root,
            public_input_root: request.public_input_root,
            nullifier_root: request.nullifier_root,
            pq_authorization_root: request.pq_authorization_root,
            fee_sponsor_root: request.fee_sponsor_root,
            privacy_set_size: request.privacy_set_size,
            estimated_weight: request.estimated_weight,
            max_fee_bps: request.max_fee_bps,
            opened_at_height: request.opened_at_height,
            deadline_height: request.deadline_height,
            fragment_root,
            batch_id: None,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_proof_da_fragment",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_PROTOCOL_VERSION,
            "fragment_id": self.fragment_id,
            "nonce": self.nonce,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "owner_commitment": self.owner_commitment,
            "contract_commitment": self.contract_commitment,
            "call_commitment": self.call_commitment,
            "witness_root": self.witness_root,
            "local_proof_root": self.local_proof_root,
            "public_input_root": self.public_input_root,
            "nullifier_root": self.nullifier_root,
            "pq_authorization_root": self.pq_authorization_root,
            "fee_sponsor_root": self.fee_sponsor_root,
            "privacy_set_size": self.privacy_set_size,
            "estimated_weight": self.estimated_weight,
            "max_fee_bps": self.max_fee_bps,
            "opened_at_height": self.opened_at_height,
            "deadline_height": self.deadline_height,
            "fragment_root": self.fragment_root,
            "batch_id": self.batch_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaShardRequest {
    pub shard_kind: DaShardKind,
    pub fragment_id: String,
    pub encrypted_payload_root: String,
    pub erasure_set_root: String,
    pub availability_committee_root: String,
    pub pq_attestation_root: String,
    pub privacy_hint_root: String,
    pub byte_size: u64,
    pub opened_at_height: u64,
}

impl DaShardRequest {
    pub fn validate(&self) -> PrivateL2LowFeeProofDaAggregatorResult<()> {
        validate_identifier("fragment_id", &self.fragment_id)?;
        validate_root("encrypted_payload_root", &self.encrypted_payload_root)?;
        validate_root("erasure_set_root", &self.erasure_set_root)?;
        validate_root(
            "availability_committee_root",
            &self.availability_committee_root,
        )?;
        validate_root("pq_attestation_root", &self.pq_attestation_root)?;
        validate_root("privacy_hint_root", &self.privacy_hint_root)?;
        if self.byte_size == 0 {
            return Err("da shard byte size must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_proof_da_shard_request",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_PROTOCOL_VERSION,
            "shard_kind": self.shard_kind.as_str(),
            "fragment_id": self.fragment_id,
            "encrypted_payload_root": self.encrypted_payload_root,
            "erasure_set_root": self.erasure_set_root,
            "availability_committee_root": self.availability_committee_root,
            "pq_attestation_root": self.pq_attestation_root,
            "privacy_hint_root": self.privacy_hint_root,
            "byte_size": self.byte_size,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaShard {
    pub shard_id: String,
    pub nonce: u64,
    pub shard_kind: DaShardKind,
    pub status: DaShardStatus,
    pub fragment_id: String,
    pub encrypted_payload_root: String,
    pub erasure_set_root: String,
    pub availability_committee_root: String,
    pub pq_attestation_root: String,
    pub privacy_hint_root: String,
    pub byte_size: u64,
    pub opened_at_height: u64,
    pub shard_root: String,
    pub batch_id: Option<String>,
}

impl DaShard {
    pub fn from_request(nonce: u64, request: DaShardRequest) -> Self {
        let shard_root = proof_da_payload_root("DA-SHARD-PAYLOAD", &request.public_record());
        let shard_id = da_shard_id(nonce, request.shard_kind, &request.fragment_id, &shard_root);
        Self {
            shard_id,
            nonce,
            shard_kind: request.shard_kind,
            status: DaShardStatus::Committed,
            fragment_id: request.fragment_id,
            encrypted_payload_root: request.encrypted_payload_root,
            erasure_set_root: request.erasure_set_root,
            availability_committee_root: request.availability_committee_root,
            pq_attestation_root: request.pq_attestation_root,
            privacy_hint_root: request.privacy_hint_root,
            byte_size: request.byte_size,
            opened_at_height: request.opened_at_height,
            shard_root,
            batch_id: None,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_proof_da_shard",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_PROTOCOL_VERSION,
            "shard_id": self.shard_id,
            "nonce": self.nonce,
            "shard_kind": self.shard_kind.as_str(),
            "status": self.status.as_str(),
            "fragment_id": self.fragment_id,
            "encrypted_payload_root": self.encrypted_payload_root,
            "erasure_set_root": self.erasure_set_root,
            "availability_committee_root": self.availability_committee_root,
            "pq_attestation_root": self.pq_attestation_root,
            "privacy_hint_root": self.privacy_hint_root,
            "byte_size": self.byte_size,
            "opened_at_height": self.opened_at_height,
            "shard_root": self.shard_root,
            "batch_id": self.batch_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildAggregationBatchRequest {
    pub lane: AggregationLane,
    pub fragment_ids: Vec<String>,
    pub da_shard_ids: Vec<String>,
    pub aggregator_commitment: String,
    pub recursive_circuit_root: String,
    pub fee_sponsor_root: String,
    pub pq_aggregator_attestation_root: String,
    pub privacy_proof_root: String,
    pub target_fee_bps: u64,
    pub sealed_at_height: u64,
}

impl BuildAggregationBatchRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeProofDaAggregatorResult<()> {
        if self.fragment_ids.is_empty() {
            return Err("proof da batch requires fragments".to_string());
        }
        if self.fragment_ids.len() > config.max_fragments_per_batch {
            return Err("proof da batch exceeds fragment limit".to_string());
        }
        if self.da_shard_ids.len() > config.max_da_shards_per_batch {
            return Err("proof da batch exceeds da shard limit".to_string());
        }
        validate_root("aggregator_commitment", &self.aggregator_commitment)?;
        validate_root("recursive_circuit_root", &self.recursive_circuit_root)?;
        validate_root("fee_sponsor_root", &self.fee_sponsor_root)?;
        validate_root(
            "pq_aggregator_attestation_root",
            &self.pq_aggregator_attestation_root,
        )?;
        validate_root("privacy_proof_root", &self.privacy_proof_root)?;
        if self.target_fee_bps == 0 || self.target_fee_bps > config.max_fee_bps {
            return Err("proof da batch target fee exceeds policy".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregationBatch {
    pub batch_id: String,
    pub nonce: u64,
    pub lane: AggregationLane,
    pub status: AggregationBatchStatus,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub aggregator_commitment: String,
    pub recursive_circuit_root: String,
    pub fragment_root: String,
    pub da_shard_root: String,
    pub public_input_root: String,
    pub witness_root: String,
    pub local_proof_root: String,
    pub recursive_proof_root: String,
    pub nullifier_root: String,
    pub pq_aggregator_attestation_root: String,
    pub fee_sponsor_root: String,
    pub privacy_proof_root: String,
    pub target_fee_bps: u64,
    pub estimated_weight: u64,
    pub estimated_fee_savings_bps: u64,
    pub fragment_ids: Vec<String>,
    pub da_shard_ids: Vec<String>,
}

impl AggregationBatch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        nonce: u64,
        request: &BuildAggregationBatchRequest,
        opened_at_height: u64,
        fragments: &[ProofFragment],
        shards: &[DaShard],
    ) -> Self {
        let fragment_records = fragments
            .iter()
            .map(ProofFragment::public_record)
            .collect::<Vec<_>>();
        let shard_records = shards
            .iter()
            .map(DaShard::public_record)
            .collect::<Vec<_>>();
        let public_inputs = fragments
            .iter()
            .map(|fragment| json!({"fragment_id": fragment.fragment_id, "root": fragment.public_input_root}))
            .collect::<Vec<_>>();
        let witness_records = fragments
            .iter()
            .map(|fragment| json!({"fragment_id": fragment.fragment_id, "root": fragment.witness_root}))
            .collect::<Vec<_>>();
        let local_proofs = fragments
            .iter()
            .map(|fragment| json!({"fragment_id": fragment.fragment_id, "root": fragment.local_proof_root}))
            .collect::<Vec<_>>();
        let nullifiers = fragments
            .iter()
            .map(|fragment| json!({"fragment_id": fragment.fragment_id, "root": fragment.nullifier_root}))
            .collect::<Vec<_>>();
        let fragment_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-PROOF-DA-BATCH-FRAGMENTS",
            &fragment_records,
        );
        let da_shard_root = merkle_root("PRIVATE-L2-LOW-FEE-PROOF-DA-BATCH-SHARDS", &shard_records);
        let public_input_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-PROOF-DA-BATCH-PUBLIC-INPUTS",
            &public_inputs,
        );
        let witness_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-PROOF-DA-BATCH-WITNESSES",
            &witness_records,
        );
        let local_proof_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-PROOF-DA-BATCH-LOCAL-PROOFS",
            &local_proofs,
        );
        let nullifier_root =
            merkle_root("PRIVATE-L2-LOW-FEE-PROOF-DA-BATCH-NULLIFIERS", &nullifiers);
        let recursive_proof_root = recursive_proof_root(
            request.lane,
            &fragment_root,
            &da_shard_root,
            &request.recursive_circuit_root,
            nonce,
        );
        let estimated_weight = fragments
            .iter()
            .map(|fragment| fragment.estimated_weight)
            .sum::<u64>()
            .saturating_add(
                shards
                    .iter()
                    .map(|shard| shard.byte_size / 128)
                    .sum::<u64>(),
            );
        let max_fragment_fee = fragments
            .iter()
            .map(|fragment| fragment.max_fee_bps)
            .max()
            .unwrap_or(request.target_fee_bps);
        let estimated_fee_savings_bps = max_fragment_fee.saturating_sub(request.target_fee_bps)
            + (fragments.len() as u64).saturating_sub(1);
        let batch_id = aggregation_batch_id(
            nonce,
            request.lane,
            &fragment_root,
            &da_shard_root,
            &recursive_proof_root,
        );
        Self {
            batch_id,
            nonce,
            lane: request.lane,
            status: AggregationBatchStatus::Sealed,
            opened_at_height,
            sealed_at_height: request.sealed_at_height,
            aggregator_commitment: request.aggregator_commitment.clone(),
            recursive_circuit_root: request.recursive_circuit_root.clone(),
            fragment_root,
            da_shard_root,
            public_input_root,
            witness_root,
            local_proof_root,
            recursive_proof_root,
            nullifier_root,
            pq_aggregator_attestation_root: request.pq_aggregator_attestation_root.clone(),
            fee_sponsor_root: request.fee_sponsor_root.clone(),
            privacy_proof_root: request.privacy_proof_root.clone(),
            target_fee_bps: request.target_fee_bps,
            estimated_weight,
            estimated_fee_savings_bps,
            fragment_ids: request.fragment_ids.clone(),
            da_shard_ids: request.da_shard_ids.clone(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_proof_da_aggregation_batch",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "nonce": self.nonce,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "aggregator_commitment": self.aggregator_commitment,
            "recursive_circuit_root": self.recursive_circuit_root,
            "fragment_root": self.fragment_root,
            "da_shard_root": self.da_shard_root,
            "public_input_root": self.public_input_root,
            "witness_root": self.witness_root,
            "local_proof_root": self.local_proof_root,
            "recursive_proof_root": self.recursive_proof_root,
            "nullifier_root": self.nullifier_root,
            "pq_aggregator_attestation_root": self.pq_aggregator_attestation_root,
            "fee_sponsor_root": self.fee_sponsor_root,
            "privacy_proof_root": self.privacy_proof_root,
            "target_fee_bps": self.target_fee_bps,
            "estimated_weight": self.estimated_weight,
            "estimated_fee_savings_bps": self.estimated_fee_savings_bps,
            "fragment_ids": self.fragment_ids,
            "da_shard_ids": self.da_shard_ids,
        })
    }

    pub fn state_root(&self) -> String {
        proof_da_payload_root("AGGREGATION-BATCH", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishAggregationBatchRequest {
    pub batch_id: String,
    pub publication_root: String,
    pub settlement_hint_root: String,
    pub monero_anchor_hint_root: String,
    pub pq_publication_attestation_root: String,
    pub fee_receipt_root: String,
    pub published_at_height: u64,
    pub finalized_at_height: Option<u64>,
}

impl PublishAggregationBatchRequest {
    pub fn validate(&self) -> PrivateL2LowFeeProofDaAggregatorResult<()> {
        validate_identifier("batch_id", &self.batch_id)?;
        validate_root("publication_root", &self.publication_root)?;
        validate_root("settlement_hint_root", &self.settlement_hint_root)?;
        validate_root("monero_anchor_hint_root", &self.monero_anchor_hint_root)?;
        validate_root(
            "pq_publication_attestation_root",
            &self.pq_publication_attestation_root,
        )?;
        validate_root("fee_receipt_root", &self.fee_receipt_root)?;
        if let Some(finalized_at_height) = self.finalized_at_height {
            if finalized_at_height < self.published_at_height {
                return Err("proof da finalization cannot precede publication".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationReceipt {
    pub receipt_id: String,
    pub nonce: u64,
    pub batch_id: String,
    pub status: PublicationStatus,
    pub batch_root: String,
    pub publication_root: String,
    pub settlement_hint_root: String,
    pub monero_anchor_hint_root: String,
    pub pq_publication_attestation_root: String,
    pub fee_receipt_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub published_at_height: u64,
    pub finalized_at_height: Option<u64>,
}

impl PublicationReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_proof_da_publication_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "nonce": self.nonce,
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "batch_root": self.batch_root,
            "publication_root": self.publication_root,
            "settlement_hint_root": self.settlement_hint_root,
            "monero_anchor_hint_root": self.monero_anchor_hint_root,
            "pq_publication_attestation_root": self.pq_publication_attestation_root,
            "fee_receipt_root": self.fee_receipt_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "published_at_height": self.published_at_height,
            "finalized_at_height": self.finalized_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub fragment_root: String,
    pub da_shard_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub consumed_nullifier_root: String,
    pub counter_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_proof_da_aggregator_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "fragment_root": self.fragment_root,
            "da_shard_root": self.da_shard_root,
            "batch_root": self.batch_root,
            "receipt_root": self.receipt_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "counter_root": self.counter_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub fragments: BTreeMap<String, ProofFragment>,
    pub da_shards: BTreeMap<String, DaShard>,
    pub batches: BTreeMap<String, AggregationBatch>,
    pub receipts: BTreeMap<String, PublicationReceipt>,
    pub consumed_nullifier_roots: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            counters: Counters::default(),
            current_height: PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_DEVNET_HEIGHT,
            fragments: BTreeMap::new(),
            da_shards: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            consumed_nullifier_roots: BTreeSet::new(),
        }
    }

    pub fn submit_fragment(
        &mut self,
        request: ProofFragmentRequest,
    ) -> PrivateL2LowFeeProofDaAggregatorResult<ProofFragment> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.fragments.len() >= PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_MAX_RECORDS {
            return Err("proof da fragment capacity exhausted".to_string());
        }
        if self
            .consumed_nullifier_roots
            .contains(&request.nullifier_root)
            || self
                .fragments
                .values()
                .any(|fragment| fragment.nullifier_root == request.nullifier_root)
        {
            self.counters.fragments_rejected = self.counters.fragments_rejected.saturating_add(1);
            return Err("proof da fragment nullifier is already used".to_string());
        }
        let nonce = self.counters.next_fragment_nonce;
        let fragment = ProofFragment::from_request(nonce, request)?;
        self.counters.next_fragment_nonce = self.counters.next_fragment_nonce.saturating_add(1);
        self.counters.fragments_submitted = self.counters.fragments_submitted.saturating_add(1);
        self.counters.fragments_accepted = self.counters.fragments_accepted.saturating_add(1);
        self.counters.total_weight = self
            .counters
            .total_weight
            .saturating_add(fragment.estimated_weight);
        self.current_height = self.current_height.max(fragment.opened_at_height);
        self.fragments
            .insert(fragment.fragment_id.clone(), fragment.clone());
        Ok(fragment)
    }

    pub fn commit_da_shard(
        &mut self,
        request: DaShardRequest,
    ) -> PrivateL2LowFeeProofDaAggregatorResult<DaShard> {
        request.validate()?;
        if self.da_shards.len() >= PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_MAX_RECORDS {
            return Err("proof da shard capacity exhausted".to_string());
        }
        if !self.fragments.contains_key(&request.fragment_id) {
            return Err("proof da shard references unknown fragment".to_string());
        }
        let nonce = self.counters.next_da_shard_nonce;
        let shard = DaShard::from_request(nonce, request);
        self.counters.next_da_shard_nonce = self.counters.next_da_shard_nonce.saturating_add(1);
        self.counters.da_shards_committed = self.counters.da_shards_committed.saturating_add(1);
        self.current_height = self.current_height.max(shard.opened_at_height);
        self.da_shards.insert(shard.shard_id.clone(), shard.clone());
        Ok(shard)
    }

    pub fn build_batch(
        &mut self,
        request: BuildAggregationBatchRequest,
    ) -> PrivateL2LowFeeProofDaAggregatorResult<AggregationBatch> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.batches.len() >= PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_MAX_RECORDS {
            return Err("proof da batch capacity exhausted".to_string());
        }
        ensure_unique("fragment_ids", &request.fragment_ids)?;
        ensure_unique("da_shard_ids", &request.da_shard_ids)?;

        let mut fragments = Vec::with_capacity(request.fragment_ids.len());
        for fragment_id in &request.fragment_ids {
            let fragment = self
                .fragments
                .get(fragment_id)
                .ok_or_else(|| format!("unknown proof fragment {fragment_id}"))?;
            if !fragment.status.selectable() {
                return Err(format!("proof fragment {fragment_id} is not selectable"));
            }
            if fragment.deadline_height < request.sealed_at_height {
                return Err(format!(
                    "proof fragment {fragment_id} expired before sealing"
                ));
            }
            if fragment.lane != request.lane {
                return Err(format!("proof fragment {fragment_id} lane mismatch"));
            }
            fragments.push(fragment.clone());
        }

        let mut shards = Vec::with_capacity(request.da_shard_ids.len());
        for shard_id in &request.da_shard_ids {
            let shard = self
                .da_shards
                .get(shard_id)
                .ok_or_else(|| format!("unknown da shard {shard_id}"))?;
            if shard.status != DaShardStatus::Committed {
                return Err(format!("da shard {shard_id} is not committed"));
            }
            if !request.fragment_ids.contains(&shard.fragment_id) {
                return Err(format!(
                    "da shard {shard_id} is not linked to selected fragments"
                ));
            }
            shards.push(shard.clone());
        }

        let nonce = self.counters.next_batch_nonce;
        let opened_at_height = fragments
            .iter()
            .map(|fragment| fragment.opened_at_height)
            .min()
            .unwrap_or(request.sealed_at_height);
        let batch = AggregationBatch::new(nonce, &request, opened_at_height, &fragments, &shards);
        for fragment_id in &batch.fragment_ids {
            if let Some(fragment) = self.fragments.get_mut(fragment_id) {
                fragment.status = ProofFragmentStatus::Aggregated;
                fragment.batch_id = Some(batch.batch_id.clone());
            }
        }
        for shard_id in &batch.da_shard_ids {
            if let Some(shard) = self.da_shards.get_mut(shard_id) {
                shard.status = DaShardStatus::Assigned;
                shard.batch_id = Some(batch.batch_id.clone());
            }
        }
        self.counters.next_batch_nonce = self.counters.next_batch_nonce.saturating_add(1);
        self.counters.batches_built = self.counters.batches_built.saturating_add(1);
        self.counters.total_fee_bps_saved = self
            .counters
            .total_fee_bps_saved
            .saturating_add(batch.estimated_fee_savings_bps);
        self.current_height = self.current_height.max(batch.sealed_at_height);
        self.batches.insert(batch.batch_id.clone(), batch.clone());
        Ok(batch)
    }

    pub fn publish_batch(
        &mut self,
        request: PublishAggregationBatchRequest,
    ) -> PrivateL2LowFeeProofDaAggregatorResult<PublicationReceipt> {
        request.validate()?;
        let state_root_before = self.state_root();
        let mut batch = self
            .batches
            .get(&request.batch_id)
            .cloned()
            .ok_or_else(|| "proof da batch not found".to_string())?;
        if !matches!(
            batch.status,
            AggregationBatchStatus::Sealed | AggregationBatchStatus::SettlementReady
        ) {
            return Err("proof da batch is not publishable".to_string());
        }
        if request.published_at_height < batch.sealed_at_height {
            return Err("proof da publication cannot precede sealing".to_string());
        }

        for fragment_id in &batch.fragment_ids {
            if let Some(fragment) = self.fragments.get_mut(fragment_id) {
                fragment.status = if request.finalized_at_height.is_some() {
                    ProofFragmentStatus::Settled
                } else {
                    ProofFragmentStatus::Published
                };
                self.consumed_nullifier_roots
                    .insert(fragment.nullifier_root.clone());
            }
        }
        for shard_id in &batch.da_shard_ids {
            if let Some(shard) = self.da_shards.get_mut(shard_id) {
                shard.status = if request.finalized_at_height.is_some() {
                    DaShardStatus::Settled
                } else {
                    DaShardStatus::Published
                };
            }
        }
        batch.status = if request.finalized_at_height.is_some() {
            AggregationBatchStatus::Settled
        } else {
            AggregationBatchStatus::Published
        };
        self.batches.insert(batch.batch_id.clone(), batch.clone());
        self.current_height = self.current_height.max(request.published_at_height);
        let state_root_after = self.state_root();
        let nonce = self.counters.next_receipt_nonce;
        let receipt_id = publication_receipt_id(
            nonce,
            &batch.batch_id,
            &batch.recursive_proof_root,
            &request.publication_root,
        );
        let receipt = PublicationReceipt {
            receipt_id: receipt_id.clone(),
            nonce,
            batch_id: batch.batch_id.clone(),
            status: if request.finalized_at_height.is_some() {
                PublicationStatus::Finalized
            } else {
                PublicationStatus::Published
            },
            batch_root: batch.state_root(),
            publication_root: request.publication_root,
            settlement_hint_root: request.settlement_hint_root,
            monero_anchor_hint_root: request.monero_anchor_hint_root,
            pq_publication_attestation_root: request.pq_publication_attestation_root,
            fee_receipt_root: request.fee_receipt_root,
            state_root_before,
            state_root_after,
            published_at_height: request.published_at_height,
            finalized_at_height: request.finalized_at_height,
        };
        self.counters.next_receipt_nonce = self.counters.next_receipt_nonce.saturating_add(1);
        self.counters.receipts_issued = self.counters.receipts_issued.saturating_add(1);
        self.counters.batches_published = self.counters.batches_published.saturating_add(1);
        if receipt.finalized_at_height.is_some() {
            self.counters.batches_settled = self.counters.batches_settled.saturating_add(1);
        }
        self.receipts.insert(receipt_id, receipt.clone());
        Ok(receipt)
    }

    pub fn roots(&self) -> Roots {
        let fragment_records = self
            .fragments
            .values()
            .map(ProofFragment::public_record)
            .collect::<Vec<_>>();
        let shard_records = self
            .da_shards
            .values()
            .map(DaShard::public_record)
            .collect::<Vec<_>>();
        let batch_records = self
            .batches
            .values()
            .map(AggregationBatch::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .values()
            .map(PublicationReceipt::public_record)
            .collect::<Vec<_>>();
        let consumed = self
            .consumed_nullifier_roots
            .iter()
            .map(|root| json!(root))
            .collect::<Vec<_>>();
        Roots {
            config_root: proof_da_payload_root("CONFIG", &self.config.public_record()),
            fragment_root: merkle_root("PRIVATE-L2-LOW-FEE-PROOF-DA-FRAGMENTS", &fragment_records),
            da_shard_root: merkle_root("PRIVATE-L2-LOW-FEE-PROOF-DA-SHARDS", &shard_records),
            batch_root: merkle_root("PRIVATE-L2-LOW-FEE-PROOF-DA-BATCHES", &batch_records),
            receipt_root: merkle_root("PRIVATE-L2-LOW-FEE-PROOF-DA-RECEIPTS", &receipt_records),
            consumed_nullifier_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-PROOF-DA-CONSUMED-NULLIFIERS",
                &consumed,
            ),
            counter_root: proof_da_payload_root("COUNTERS", &self.counters.public_record()),
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_proof_da_aggregator_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_SCHEMA_VERSION,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
            "fragment_count": self.fragments.len(),
            "da_shard_count": self.da_shards.len(),
            "batch_count": self.batches.len(),
            "receipt_count": self.receipts.len(),
            "consumed_nullifier_count": self.consumed_nullifier_roots.len(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(self.state_root()));
            object.insert(
                "recent_batches".to_string(),
                json!(self
                    .batches
                    .values()
                    .rev()
                    .take(16)
                    .map(AggregationBatch::public_record)
                    .collect::<Vec<_>>()),
            );
            object.insert(
                "recent_receipts".to_string(),
                json!(self
                    .receipts
                    .values()
                    .rev()
                    .take(16)
                    .map(PublicationReceipt::public_record)
                    .collect::<Vec<_>>()),
            );
        }
        record
    }

    pub fn state_root(&self) -> String {
        proof_da_payload_root("STATE", &self.public_record_without_root())
    }
}

pub fn root_from_record(record: &Value) -> String {
    proof_da_payload_root("RECORD", record)
}

pub fn devnet() -> State {
    State::devnet()
}

fn proof_da_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-LOW-FEE-PROOF-DA-{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn proof_fragment_id(nonce: u64, lane: AggregationLane, fragment_root: &str) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PROOF-DA-FRAGMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_PROTOCOL_VERSION),
            HashPart::Int(nonce as i128),
            HashPart::Str(lane.as_str()),
            HashPart::Str(fragment_root),
        ],
        32,
    )
}

fn da_shard_id(nonce: u64, kind: DaShardKind, fragment_id: &str, shard_root: &str) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PROOF-DA-SHARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_PROTOCOL_VERSION),
            HashPart::Int(nonce as i128),
            HashPart::Str(kind.as_str()),
            HashPart::Str(fragment_id),
            HashPart::Str(shard_root),
        ],
        32,
    )
}

fn aggregation_batch_id(
    nonce: u64,
    lane: AggregationLane,
    fragment_root: &str,
    da_shard_root: &str,
    recursive_proof_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PROOF-DA-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_PROTOCOL_VERSION),
            HashPart::Int(nonce as i128),
            HashPart::Str(lane.as_str()),
            HashPart::Str(fragment_root),
            HashPart::Str(da_shard_root),
            HashPart::Str(recursive_proof_root),
        ],
        32,
    )
}

fn recursive_proof_root(
    lane: AggregationLane,
    fragment_root: &str,
    da_shard_root: &str,
    recursive_circuit_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PROOF-DA-RECURSIVE-PROOF",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str(fragment_root),
            HashPart::Str(da_shard_root),
            HashPart::Str(recursive_circuit_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

fn publication_receipt_id(
    nonce: u64,
    batch_id: &str,
    recursive_proof_root: &str,
    publication_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PROOF-DA-PUBLICATION-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LOW_FEE_PROOF_DA_AGGREGATOR_PROTOCOL_VERSION),
            HashPart::Int(nonce as i128),
            HashPart::Str(batch_id),
            HashPart::Str(recursive_proof_root),
            HashPart::Str(publication_root),
        ],
        32,
    )
}

fn ensure_unique(label: &str, values: &[String]) -> PrivateL2LowFeeProofDaAggregatorResult<()> {
    let unique = values.iter().collect::<BTreeSet<_>>();
    if unique.len() != values.len() {
        return Err(format!("{label} cannot contain duplicates"));
    }
    Ok(())
}

fn validate_identifier(label: &str, value: &str) -> PrivateL2LowFeeProofDaAggregatorResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    if value.len() > 256 {
        return Err(format!("{label} is too long"));
    }
    Ok(())
}

fn validate_root(label: &str, value: &str) -> PrivateL2LowFeeProofDaAggregatorResult<()> {
    validate_identifier(label, value)?;
    if value.len() < 16 {
        return Err(format!("{label} must be root-like"));
    }
    Ok(())
}
