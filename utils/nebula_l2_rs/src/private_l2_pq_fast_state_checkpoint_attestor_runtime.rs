use crate::hash::{domain_hash, merkle_root, HashPart};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqFastStateCheckpointAttestorRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_FAST_STATE_CHECKPOINT_ATTESTOR_RUNTIME_PROTOCOL_VERSION: &str =
    "private-l2-pq-fast-state-checkpoint-attestor-runtime-v1";
const CHAIN_ID: &str = "nebula-l2-devnet";
const MAX_BPS: u64 = 10_000;
const MAX_WITNESS_SHARDS: usize = 64;
const MAX_ATTESTERS: usize = 128;
const MAX_CHECKPOINTS: usize = 4096;
const MAX_EVENTS: usize = 8192;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum CheckpointLane {
    FastContract,
    DefiBatch,
    TokenNetting,
    BridgeExit,
    Emergency,
}

impl CheckpointLane {
    pub fn as_str(self) -> &'static str {
        match self {
            CheckpointLane::FastContract => "fast_contract",
            CheckpointLane::DefiBatch => "defi_batch",
            CheckpointLane::TokenNetting => "token_netting",
            CheckpointLane::BridgeExit => "bridge_exit",
            CheckpointLane::Emergency => "emergency",
        }
    }

    pub fn target_latency_ms(self) -> u64 {
        match self {
            CheckpointLane::FastContract => 250,
            CheckpointLane::DefiBatch => 400,
            CheckpointLane::TokenNetting => 500,
            CheckpointLane::BridgeExit => 750,
            CheckpointLane::Emergency => 150,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum CommitteeStatus {
    Pending,
    Active,
    Retiring,
    Slashed,
}

impl CommitteeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            CommitteeStatus::Pending => "pending",
            CommitteeStatus::Active => "active",
            CommitteeStatus::Retiring => "retiring",
            CommitteeStatus::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum CheckpointStatus {
    Open,
    Attested,
    Settled,
    Disputed,
    Expired,
}

impl CheckpointStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            CheckpointStatus::Open => "open",
            CheckpointStatus::Attested => "attested",
            CheckpointStatus::Settled => "settled",
            CheckpointStatus::Disputed => "disputed",
            CheckpointStatus::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum WitnessShardStatus {
    Posted,
    Included,
    Rejected,
}

impl WitnessShardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            WitnessShardStatus::Posted => "posted",
            WitnessShardStatus::Included => "included",
            WitnessShardStatus::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AttestationStatus {
    Pending,
    QuorumReached,
    Rejected,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            AttestationStatus::Pending => "pending",
            AttestationStatus::QuorumReached => "quorum_reached",
            AttestationStatus::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SponsorStatus {
    Reserved,
    Applied,
    Refunded,
    Slashed,
}

impl SponsorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            SponsorStatus::Reserved => "reserved",
            SponsorStatus::Applied => "applied",
            SponsorStatus::Refunded => "refunded",
            SponsorStatus::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReceiptKind {
    FastInclusion,
    RecursiveProof,
    MoneroAnchor,
    EmergencyOverride,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ReceiptKind::FastInclusion => "fast_inclusion",
            ReceiptKind::RecursiveProof => "recursive_proof",
            ReceiptKind::MoneroAnchor => "monero_anchor",
            ReceiptKind::EmergencyOverride => "emergency_override",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RebateStatus {
    Queued,
    Paid,
    Cancelled,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            RebateStatus::Queued => "queued",
            RebateStatus::Paid => "paid",
            RebateStatus::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum FenceKind {
    NullifierReplay,
    AttesterSet,
    WitnessShard,
    EmergencyLane,
}

impl FenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FenceKind::NullifierReplay => "nullifier_replay",
            FenceKind::AttesterSet => "attester_set",
            FenceKind::WitnessShard => "witness_shard",
            FenceKind::EmergencyLane => "emergency_lane",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SlashingReason {
    BadSignature,
    WithheldWitness,
    LatencyMiss,
    DoubleAttestation,
    InvalidCheckpoint,
}

impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            SlashingReason::BadSignature => "bad_signature",
            SlashingReason::WithheldWitness => "withheld_witness",
            SlashingReason::LatencyMiss => "latency_miss",
            SlashingReason::DoubleAttestation => "double_attestation",
            SlashingReason::InvalidCheckpoint => "invalid_checkpoint",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub chain_id: String,
    pub runtime_version: String,
    pub min_committee_weight: u64,
    pub quorum_bps: u64,
    pub max_latency_ms: u64,
    pub max_fee_bps: u64,
    pub max_witness_shards: usize,
    pub max_attesters: usize,
    pub max_open_checkpoints: usize,
    pub low_fee_rebate_bps: u64,
    pub emergency_lane_enabled: bool,
    pub pq_scheme_root: String,
    pub monero_anchor_domain: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            runtime_version: PRIVATE_L2_PQ_FAST_STATE_CHECKPOINT_ATTESTOR_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            min_committee_weight: 3,
            quorum_bps: 6700,
            max_latency_ms: 750,
            max_fee_bps: 80,
            max_witness_shards: 16,
            max_attesters: 48,
            max_open_checkpoints: 512,
            low_fee_rebate_bps: 2400,
            emergency_lane_enabled: true,
            pq_scheme_root: commitment("ML-DSA-87+SLH-DSA fallback"),
            monero_anchor_domain: "monero-devnet-checkpoint-anchor".to_string(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("chain_id", &self.chain_id)?;
        require_eq("chain_id", &self.chain_id, CHAIN_ID)?;
        require_non_empty("runtime_version", &self.runtime_version)?;
        require_bps("quorum_bps", self.quorum_bps)?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        require_bps("low_fee_rebate_bps", self.low_fee_rebate_bps)?;
        if self.min_committee_weight == 0 {
            return Err("min_committee_weight must be non-zero".to_string());
        }
        if self.quorum_bps < 5000 {
            return Err("quorum_bps must be at least a majority".to_string());
        }
        if self.max_latency_ms == 0 {
            return Err("max_latency_ms must be non-zero".to_string());
        }
        if self.max_witness_shards == 0 || self.max_witness_shards > MAX_WITNESS_SHARDS {
            return Err(format!(
                "max_witness_shards must be between 1 and {MAX_WITNESS_SHARDS}"
            ));
        }
        if self.max_attesters == 0 || self.max_attesters > MAX_ATTESTERS {
            return Err(format!(
                "max_attesters must be between 1 and {MAX_ATTESTERS}"
            ));
        }
        require_root("pq_scheme_root", &self.pq_scheme_root)?;
        require_non_empty("monero_anchor_domain", &self.monero_anchor_domain)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "runtime_version": self.runtime_version,
            "min_committee_weight": self.min_committee_weight,
            "quorum_bps": self.quorum_bps,
            "max_latency_ms": self.max_latency_ms,
            "max_fee_bps": self.max_fee_bps,
            "max_witness_shards": self.max_witness_shards,
            "max_attesters": self.max_attesters,
            "max_open_checkpoints": self.max_open_checkpoints,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "emergency_lane_enabled": self.emergency_lane_enabled,
            "pq_scheme_root": self.pq_scheme_root,
            "monero_anchor_domain": self.monero_anchor_domain,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counters {
    pub committees: u64,
    pub checkpoints: u64,
    pub witness_shards: u64,
    pub attestations: u64,
    pub sponsor_reservations: u64,
    pub settlement_receipts: u64,
    pub fee_rebates: u64,
    pub privacy_fences: u64,
    pub slashing_events: u64,
    pub runtime_events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "committees": self.committees,
            "checkpoints": self.checkpoints,
            "witness_shards": self.witness_shards,
            "attestations": self.attestations,
            "sponsor_reservations": self.sponsor_reservations,
            "settlement_receipts": self.settlement_receipts,
            "fee_rebates": self.fee_rebates,
            "privacy_fences": self.privacy_fences,
            "slashing_events": self.slashing_events,
            "runtime_events": self.runtime_events,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Roots {
    pub committees_root: String,
    pub checkpoints_root: String,
    pub witness_shards_root: String,
    pub attestations_root: String,
    pub sponsor_reservations_root: String,
    pub settlement_receipts_root: String,
    pub fee_rebates_root: String,
    pub privacy_fences_root: String,
    pub slashing_events_root: String,
    pub spent_nullifiers_root: String,
    pub runtime_events_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            committees_root: empty_root("COMMITTEES"),
            checkpoints_root: empty_root("CHECKPOINTS"),
            witness_shards_root: empty_root("WITNESS-SHARDS"),
            attestations_root: empty_root("ATTESTATIONS"),
            sponsor_reservations_root: empty_root("SPONSOR-RESERVATIONS"),
            settlement_receipts_root: empty_root("SETTLEMENT-RECEIPTS"),
            fee_rebates_root: empty_root("FEE-REBATES"),
            privacy_fences_root: empty_root("PRIVACY-FENCES"),
            slashing_events_root: empty_root("SLASHING-EVENTS"),
            spent_nullifiers_root: empty_root("SPENT-NULLIFIERS"),
            runtime_events_root: empty_root("RUNTIME-EVENTS"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "committees_root": self.committees_root,
            "checkpoints_root": self.checkpoints_root,
            "witness_shards_root": self.witness_shards_root,
            "attestations_root": self.attestations_root,
            "sponsor_reservations_root": self.sponsor_reservations_root,
            "settlement_receipts_root": self.settlement_receipts_root,
            "fee_rebates_root": self.fee_rebates_root,
            "privacy_fences_root": self.privacy_fences_root,
            "slashing_events_root": self.slashing_events_root,
            "spent_nullifiers_root": self.spent_nullifiers_root,
            "runtime_events_root": self.runtime_events_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterCommitteeRequest {
    pub committee_label: String,
    pub epoch: u64,
    pub pq_public_key_root: String,
    pub stealth_signer_set_root: String,
    pub aggregate_weight: u64,
    pub stake_commitment_root: String,
    pub activation_height: u64,
}

impl RegisterCommitteeRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("committee_label", &self.committee_label)?;
        require_root("pq_public_key_root", &self.pq_public_key_root)?;
        require_root("stealth_signer_set_root", &self.stealth_signer_set_root)?;
        require_root("stake_commitment_root", &self.stake_commitment_root)?;
        if self.aggregate_weight < config.min_committee_weight {
            return Err("aggregate_weight below min_committee_weight".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommitteeRecord {
    pub committee_id: String,
    pub committee_label: String,
    pub epoch: u64,
    pub pq_public_key_root: String,
    pub stealth_signer_set_root: String,
    pub aggregate_weight: u64,
    pub stake_commitment_root: String,
    pub activation_height: u64,
    pub status: CommitteeStatus,
}

impl CommitteeRecord {
    pub fn from_request(request: RegisterCommitteeRequest, config: &Config) -> Result<Self> {
        request.validate(config)?;
        let committee_id = committee_id(&request);
        Ok(Self {
            committee_id,
            committee_label: request.committee_label,
            epoch: request.epoch,
            pq_public_key_root: request.pq_public_key_root,
            stealth_signer_set_root: request.stealth_signer_set_root,
            aggregate_weight: request.aggregate_weight,
            stake_commitment_root: request.stake_commitment_root,
            activation_height: request.activation_height,
            status: CommitteeStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "committee_id": self.committee_id,
            "committee_label": self.committee_label,
            "epoch": self.epoch,
            "pq_public_key_root": self.pq_public_key_root,
            "stealth_signer_set_root": self.stealth_signer_set_root,
            "aggregate_weight": self.aggregate_weight,
            "stake_commitment_root": self.stake_commitment_root,
            "activation_height": self.activation_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenCheckpointRequest {
    pub lane: CheckpointLane,
    pub committee_id: String,
    pub private_state_root: String,
    pub encrypted_diff_root: String,
    pub contract_batch_root: String,
    pub monero_anchor_hint: String,
    pub opens_at_height: u64,
    pub expires_at_height: u64,
    pub max_fee_bps: u64,
    pub target_latency_ms: u64,
    pub nullifier_root: String,
}

impl OpenCheckpointRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("committee_id", &self.committee_id)?;
        require_root("private_state_root", &self.private_state_root)?;
        require_root("encrypted_diff_root", &self.encrypted_diff_root)?;
        require_root("contract_batch_root", &self.contract_batch_root)?;
        require_root("monero_anchor_hint", &self.monero_anchor_hint)?;
        require_root("nullifier_root", &self.nullifier_root)?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        if self.max_fee_bps > config.max_fee_bps {
            return Err("max_fee_bps exceeds runtime cap".to_string());
        }
        if self.target_latency_ms == 0 || self.target_latency_ms > config.max_latency_ms {
            return Err("target_latency_ms outside runtime latency cap".to_string());
        }
        if self.expires_at_height <= self.opens_at_height {
            return Err("checkpoint expiry must be after open height".to_string());
        }
        if self.lane == CheckpointLane::Emergency && !config.emergency_lane_enabled {
            return Err("emergency lane disabled".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateCheckpoint {
    pub checkpoint_id: String,
    pub lane: CheckpointLane,
    pub committee_id: String,
    pub private_state_root: String,
    pub encrypted_diff_root: String,
    pub contract_batch_root: String,
    pub monero_anchor_hint: String,
    pub opens_at_height: u64,
    pub expires_at_height: u64,
    pub max_fee_bps: u64,
    pub target_latency_ms: u64,
    pub nullifier_root: String,
    pub witness_shard_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub sponsor_reservation_ids: Vec<String>,
    pub receipt_ids: Vec<String>,
    pub status: CheckpointStatus,
}

impl StateCheckpoint {
    pub fn from_request(
        request: OpenCheckpointRequest,
        sequence: u64,
        config: &Config,
    ) -> Result<Self> {
        request.validate(config)?;
        let checkpoint_id = checkpoint_id(&request, sequence);
        Ok(Self {
            checkpoint_id,
            lane: request.lane,
            committee_id: request.committee_id,
            private_state_root: request.private_state_root,
            encrypted_diff_root: request.encrypted_diff_root,
            contract_batch_root: request.contract_batch_root,
            monero_anchor_hint: request.monero_anchor_hint,
            opens_at_height: request.opens_at_height,
            expires_at_height: request.expires_at_height,
            max_fee_bps: request.max_fee_bps,
            target_latency_ms: request.target_latency_ms,
            nullifier_root: request.nullifier_root,
            witness_shard_ids: Vec::new(),
            attestation_ids: Vec::new(),
            sponsor_reservation_ids: Vec::new(),
            receipt_ids: Vec::new(),
            status: CheckpointStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "lane": self.lane.as_str(),
            "committee_id": self.committee_id,
            "private_state_root": self.private_state_root,
            "encrypted_diff_root": self.encrypted_diff_root,
            "contract_batch_root": self.contract_batch_root,
            "monero_anchor_hint": self.monero_anchor_hint,
            "opens_at_height": self.opens_at_height,
            "expires_at_height": self.expires_at_height,
            "max_fee_bps": self.max_fee_bps,
            "target_latency_ms": self.target_latency_ms,
            "nullifier_root": self.nullifier_root,
            "witness_shard_ids": self.witness_shard_ids,
            "attestation_ids": self.attestation_ids,
            "sponsor_reservation_ids": self.sponsor_reservation_ids,
            "receipt_ids": self.receipt_ids,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubmitWitnessShardRequest {
    pub checkpoint_id: String,
    pub shard_index: u64,
    pub encrypted_witness_root: String,
    pub availability_root: String,
    pub prover_commitment: String,
    pub posted_at_height: u64,
    pub nullifier_root: String,
}

impl SubmitWitnessShardRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("checkpoint_id", &self.checkpoint_id)?;
        require_root("encrypted_witness_root", &self.encrypted_witness_root)?;
        require_root("availability_root", &self.availability_root)?;
        require_root("prover_commitment", &self.prover_commitment)?;
        require_root("nullifier_root", &self.nullifier_root)?;
        if self.shard_index as usize >= config.max_witness_shards {
            return Err("shard_index exceeds configured shard cap".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WitnessShard {
    pub witness_shard_id: String,
    pub checkpoint_id: String,
    pub shard_index: u64,
    pub encrypted_witness_root: String,
    pub availability_root: String,
    pub prover_commitment: String,
    pub posted_at_height: u64,
    pub nullifier_root: String,
    pub status: WitnessShardStatus,
}

impl WitnessShard {
    pub fn from_request(
        request: SubmitWitnessShardRequest,
        sequence: u64,
        config: &Config,
    ) -> Result<Self> {
        request.validate(config)?;
        let witness_shard_id = witness_shard_id(&request, sequence);
        Ok(Self {
            witness_shard_id,
            checkpoint_id: request.checkpoint_id,
            shard_index: request.shard_index,
            encrypted_witness_root: request.encrypted_witness_root,
            availability_root: request.availability_root,
            prover_commitment: request.prover_commitment,
            posted_at_height: request.posted_at_height,
            nullifier_root: request.nullifier_root,
            status: WitnessShardStatus::Posted,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "witness_shard_id": self.witness_shard_id,
            "checkpoint_id": self.checkpoint_id,
            "shard_index": self.shard_index,
            "encrypted_witness_root": self.encrypted_witness_root,
            "availability_root": self.availability_root,
            "prover_commitment": self.prover_commitment,
            "posted_at_height": self.posted_at_height,
            "nullifier_root": self.nullifier_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordCommitteeAttestationRequest {
    pub checkpoint_id: String,
    pub committee_id: String,
    pub attester_commitment_root: String,
    pub pq_signature_root: String,
    pub witness_shard_root: String,
    pub attested_state_root: String,
    pub signer_weight: u64,
    pub observed_latency_ms: u64,
    pub signed_at_height: u64,
    pub nullifier_root: String,
}

impl RecordCommitteeAttestationRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("checkpoint_id", &self.checkpoint_id)?;
        require_non_empty("committee_id", &self.committee_id)?;
        require_root("attester_commitment_root", &self.attester_commitment_root)?;
        require_root("pq_signature_root", &self.pq_signature_root)?;
        require_root("witness_shard_root", &self.witness_shard_root)?;
        require_root("attested_state_root", &self.attested_state_root)?;
        require_root("nullifier_root", &self.nullifier_root)?;
        if self.signer_weight == 0 {
            return Err("signer_weight must be non-zero".to_string());
        }
        if self.observed_latency_ms > config.max_latency_ms.saturating_mul(2) {
            return Err("observed_latency_ms exceeds tolerated checkpoint window".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommitteeAttestation {
    pub attestation_id: String,
    pub checkpoint_id: String,
    pub committee_id: String,
    pub attester_commitment_root: String,
    pub pq_signature_root: String,
    pub witness_shard_root: String,
    pub attested_state_root: String,
    pub signer_weight: u64,
    pub observed_latency_ms: u64,
    pub signed_at_height: u64,
    pub nullifier_root: String,
    pub status: AttestationStatus,
}

impl CommitteeAttestation {
    pub fn from_request(
        request: RecordCommitteeAttestationRequest,
        sequence: u64,
        config: &Config,
        quorum_reached: bool,
    ) -> Result<Self> {
        request.validate(config)?;
        let attestation_id = attestation_id(&request, sequence);
        Ok(Self {
            attestation_id,
            checkpoint_id: request.checkpoint_id,
            committee_id: request.committee_id,
            attester_commitment_root: request.attester_commitment_root,
            pq_signature_root: request.pq_signature_root,
            witness_shard_root: request.witness_shard_root,
            attested_state_root: request.attested_state_root,
            signer_weight: request.signer_weight,
            observed_latency_ms: request.observed_latency_ms,
            signed_at_height: request.signed_at_height,
            nullifier_root: request.nullifier_root,
            status: if quorum_reached {
                AttestationStatus::QuorumReached
            } else {
                AttestationStatus::Pending
            },
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "checkpoint_id": self.checkpoint_id,
            "committee_id": self.committee_id,
            "attester_commitment_root": self.attester_commitment_root,
            "pq_signature_root": self.pq_signature_root,
            "witness_shard_root": self.witness_shard_root,
            "attested_state_root": self.attested_state_root,
            "signer_weight": self.signer_weight,
            "observed_latency_ms": self.observed_latency_ms,
            "signed_at_height": self.signed_at_height,
            "nullifier_root": self.nullifier_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReserveSponsorRequest {
    pub checkpoint_id: String,
    pub sponsor_commitment: String,
    pub fee_note_root: String,
    pub max_fee_bps: u64,
    pub expires_at_height: u64,
    pub nullifier_root: String,
}

impl ReserveSponsorRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("checkpoint_id", &self.checkpoint_id)?;
        require_root("sponsor_commitment", &self.sponsor_commitment)?;
        require_root("fee_note_root", &self.fee_note_root)?;
        require_root("nullifier_root", &self.nullifier_root)?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        if self.max_fee_bps > config.max_fee_bps {
            return Err("sponsor max_fee_bps exceeds runtime cap".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SponsorReservation {
    pub reservation_id: String,
    pub checkpoint_id: String,
    pub sponsor_commitment: String,
    pub fee_note_root: String,
    pub max_fee_bps: u64,
    pub expires_at_height: u64,
    pub nullifier_root: String,
    pub status: SponsorStatus,
}

impl SponsorReservation {
    pub fn from_request(
        request: ReserveSponsorRequest,
        sequence: u64,
        config: &Config,
    ) -> Result<Self> {
        request.validate(config)?;
        let reservation_id = sponsor_reservation_id(&request, sequence);
        Ok(Self {
            reservation_id,
            checkpoint_id: request.checkpoint_id,
            sponsor_commitment: request.sponsor_commitment,
            fee_note_root: request.fee_note_root,
            max_fee_bps: request.max_fee_bps,
            expires_at_height: request.expires_at_height,
            nullifier_root: request.nullifier_root,
            status: SponsorStatus::Reserved,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "checkpoint_id": self.checkpoint_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_note_root": self.fee_note_root,
            "max_fee_bps": self.max_fee_bps,
            "expires_at_height": self.expires_at_height,
            "nullifier_root": self.nullifier_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublishSettlementReceiptRequest {
    pub checkpoint_id: String,
    pub receipt_kind: ReceiptKind,
    pub attestation_root: String,
    pub recursive_proof_root: String,
    pub monero_anchor_root: String,
    pub fee_charged_bps: u64,
    pub settled_at_height: u64,
}

impl PublishSettlementReceiptRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("checkpoint_id", &self.checkpoint_id)?;
        require_root("attestation_root", &self.attestation_root)?;
        require_root("recursive_proof_root", &self.recursive_proof_root)?;
        require_root("monero_anchor_root", &self.monero_anchor_root)?;
        require_bps("fee_charged_bps", self.fee_charged_bps)?;
        if self.fee_charged_bps > config.max_fee_bps {
            return Err("fee_charged_bps exceeds runtime cap".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub checkpoint_id: String,
    pub receipt_kind: ReceiptKind,
    pub attestation_root: String,
    pub recursive_proof_root: String,
    pub monero_anchor_root: String,
    pub fee_charged_bps: u64,
    pub settled_at_height: u64,
}

impl SettlementReceipt {
    pub fn from_request(
        request: PublishSettlementReceiptRequest,
        sequence: u64,
        config: &Config,
    ) -> Result<Self> {
        request.validate(config)?;
        let receipt_id = settlement_receipt_id(&request, sequence);
        Ok(Self {
            receipt_id,
            checkpoint_id: request.checkpoint_id,
            receipt_kind: request.receipt_kind,
            attestation_root: request.attestation_root,
            recursive_proof_root: request.recursive_proof_root,
            monero_anchor_root: request.monero_anchor_root,
            fee_charged_bps: request.fee_charged_bps,
            settled_at_height: request.settled_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "checkpoint_id": self.checkpoint_id,
            "receipt_kind": self.receipt_kind.as_str(),
            "attestation_root": self.attestation_root,
            "recursive_proof_root": self.recursive_proof_root,
            "monero_anchor_root": self.monero_anchor_root,
            "fee_charged_bps": self.fee_charged_bps,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssueFeeRebateRequest {
    pub checkpoint_id: String,
    pub receipt_id: String,
    pub beneficiary_commitment: String,
    pub rebate_note_root: String,
    pub rebate_bps: u64,
}

impl IssueFeeRebateRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("checkpoint_id", &self.checkpoint_id)?;
        require_non_empty("receipt_id", &self.receipt_id)?;
        require_root("beneficiary_commitment", &self.beneficiary_commitment)?;
        require_root("rebate_note_root", &self.rebate_note_root)?;
        require_bps("rebate_bps", self.rebate_bps)?;
        if self.rebate_bps > config.low_fee_rebate_bps {
            return Err("rebate_bps exceeds configured rebate cap".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub checkpoint_id: String,
    pub receipt_id: String,
    pub beneficiary_commitment: String,
    pub rebate_note_root: String,
    pub rebate_bps: u64,
    pub status: RebateStatus,
}

impl FeeRebate {
    pub fn from_request(
        request: IssueFeeRebateRequest,
        sequence: u64,
        config: &Config,
    ) -> Result<Self> {
        request.validate(config)?;
        let rebate_id = fee_rebate_id(&request, sequence);
        Ok(Self {
            rebate_id,
            checkpoint_id: request.checkpoint_id,
            receipt_id: request.receipt_id,
            beneficiary_commitment: request.beneficiary_commitment,
            rebate_note_root: request.rebate_note_root,
            rebate_bps: request.rebate_bps,
            status: RebateStatus::Queued,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "checkpoint_id": self.checkpoint_id,
            "receipt_id": self.receipt_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "rebate_note_root": self.rebate_note_root,
            "rebate_bps": self.rebate_bps,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenPrivacyFenceRequest {
    pub fence_kind: FenceKind,
    pub subject_id: String,
    pub commitment_root: String,
    pub replay_domain: String,
    pub nullifier_root: String,
    pub effective_height: u64,
}

impl OpenPrivacyFenceRequest {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("subject_id", &self.subject_id)?;
        require_root("commitment_root", &self.commitment_root)?;
        require_non_empty("replay_domain", &self.replay_domain)?;
        require_root("nullifier_root", &self.nullifier_root)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub fence_kind: FenceKind,
    pub subject_id: String,
    pub commitment_root: String,
    pub replay_domain: String,
    pub nullifier_root: String,
    pub effective_height: u64,
}

impl PrivacyFence {
    pub fn from_request(request: OpenPrivacyFenceRequest, sequence: u64) -> Result<Self> {
        request.validate()?;
        let fence_id = privacy_fence_id(&request, sequence);
        Ok(Self {
            fence_id,
            fence_kind: request.fence_kind,
            subject_id: request.subject_id,
            commitment_root: request.commitment_root,
            replay_domain: request.replay_domain,
            nullifier_root: request.nullifier_root,
            effective_height: request.effective_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "fence_kind": self.fence_kind.as_str(),
            "subject_id": self.subject_id,
            "commitment_root": self.commitment_root,
            "replay_domain": self.replay_domain,
            "nullifier_root": self.nullifier_root,
            "effective_height": self.effective_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordSlashingEvidenceRequest {
    pub checkpoint_id: String,
    pub committee_id: String,
    pub offender_commitment: String,
    pub reason: SlashingReason,
    pub evidence_root: String,
    pub penalty_note_root: String,
    pub recorded_at_height: u64,
}

impl RecordSlashingEvidenceRequest {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("checkpoint_id", &self.checkpoint_id)?;
        require_non_empty("committee_id", &self.committee_id)?;
        require_root("offender_commitment", &self.offender_commitment)?;
        require_root("evidence_root", &self.evidence_root)?;
        require_root("penalty_note_root", &self.penalty_note_root)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub checkpoint_id: String,
    pub committee_id: String,
    pub offender_commitment: String,
    pub reason: SlashingReason,
    pub evidence_root: String,
    pub penalty_note_root: String,
    pub recorded_at_height: u64,
}

impl SlashingEvidence {
    pub fn from_request(request: RecordSlashingEvidenceRequest, sequence: u64) -> Result<Self> {
        request.validate()?;
        let evidence_id = slashing_evidence_id(&request, sequence);
        Ok(Self {
            evidence_id,
            checkpoint_id: request.checkpoint_id,
            committee_id: request.committee_id,
            offender_commitment: request.offender_commitment,
            reason: request.reason,
            evidence_root: request.evidence_root,
            penalty_note_root: request.penalty_note_root,
            recorded_at_height: request.recorded_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "checkpoint_id": self.checkpoint_id,
            "committee_id": self.committee_id,
            "offender_commitment": self.offender_commitment,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "penalty_note_root": self.penalty_note_root,
            "recorded_at_height": self.recorded_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeEvent {
    pub fn new(
        event_kind: &str,
        subject_id: &str,
        payload: &Value,
        height: u64,
        sequence: u64,
    ) -> Self {
        let payload_root = payload_root("RUNTIME-EVENT", payload);
        Self {
            event_id: runtime_event_id(event_kind, subject_id, &payload_root, height, sequence),
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            payload_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub committees: BTreeMap<String, CommitteeRecord>,
    pub checkpoints: BTreeMap<String, StateCheckpoint>,
    pub witness_shards: BTreeMap<String, WitnessShard>,
    pub attestations: BTreeMap<String, CommitteeAttestation>,
    pub sponsor_reservations: BTreeMap<String, SponsorReservation>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub fee_rebates: BTreeMap<String, FeeRebate>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub slashing_events: BTreeMap<String, SlashingEvidence>,
    pub spent_nullifiers: BTreeSet<String>,
    pub runtime_events: Vec<RuntimeEvent>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            roots: Roots::empty(),
            committees: BTreeMap::new(),
            checkpoints: BTreeMap::new(),
            witness_shards: BTreeMap::new(),
            attestations: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            slashing_events: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            runtime_events: Vec::new(),
        })
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("devnet config must validate");
        let committee = state
            .register_committee(RegisterCommitteeRequest {
                committee_label: "devnet-fast-checkpoint-committee".to_string(),
                epoch: 1,
                pq_public_key_root: commitment("devnet checkpoint committee pq aggregate key"),
                stealth_signer_set_root: commitment("devnet stealth signer set"),
                aggregate_weight: 9,
                stake_commitment_root: commitment("devnet checkpoint committee stake"),
                activation_height: 1,
            })
            .expect("devnet committee must register");
        let checkpoint = state
            .open_checkpoint(OpenCheckpointRequest {
                lane: CheckpointLane::FastContract,
                committee_id: committee.committee_id.clone(),
                private_state_root: commitment("private contract state root"),
                encrypted_diff_root: commitment("encrypted state diff"),
                contract_batch_root: commitment("contract batch root"),
                monero_anchor_hint: commitment("monero anchor hint"),
                opens_at_height: 12,
                expires_at_height: 32,
                max_fee_bps: 12,
                target_latency_ms: CheckpointLane::FastContract.target_latency_ms(),
                nullifier_root: commitment("checkpoint open nullifier"),
            })
            .expect("devnet checkpoint must open");
        let shard = state
            .submit_witness_shard(SubmitWitnessShardRequest {
                checkpoint_id: checkpoint.checkpoint_id.clone(),
                shard_index: 0,
                encrypted_witness_root: commitment("encrypted witness shard"),
                availability_root: commitment("availability receipt"),
                prover_commitment: commitment("devnet prover"),
                posted_at_height: 13,
                nullifier_root: commitment("witness shard nullifier"),
            })
            .expect("devnet witness shard must post");
        let attestation = state
            .record_committee_attestation(RecordCommitteeAttestationRequest {
                checkpoint_id: checkpoint.checkpoint_id.clone(),
                committee_id: committee.committee_id.clone(),
                attester_commitment_root: commitment("devnet attester"),
                pq_signature_root: commitment("devnet pq signature"),
                witness_shard_root: shard.encrypted_witness_root.clone(),
                attested_state_root: checkpoint.private_state_root.clone(),
                signer_weight: 7,
                observed_latency_ms: 180,
                signed_at_height: 14,
                nullifier_root: commitment("attestation nullifier"),
            })
            .expect("devnet attestation must record");
        let reservation = state
            .reserve_sponsor(ReserveSponsorRequest {
                checkpoint_id: checkpoint.checkpoint_id.clone(),
                sponsor_commitment: commitment("devnet sponsor"),
                fee_note_root: commitment("fee sponsor note"),
                max_fee_bps: 12,
                expires_at_height: 40,
                nullifier_root: commitment("sponsor reservation nullifier"),
            })
            .expect("devnet sponsor must reserve");
        let receipt = state
            .publish_settlement_receipt(PublishSettlementReceiptRequest {
                checkpoint_id: checkpoint.checkpoint_id.clone(),
                receipt_kind: ReceiptKind::RecursiveProof,
                attestation_root: attestation.pq_signature_root.clone(),
                recursive_proof_root: commitment("recursive proof receipt"),
                monero_anchor_root: commitment("monero anchor receipt"),
                fee_charged_bps: 10,
                settled_at_height: 18,
            })
            .expect("devnet receipt must settle");
        let _rebate = state
            .issue_fee_rebate(IssueFeeRebateRequest {
                checkpoint_id: checkpoint.checkpoint_id.clone(),
                receipt_id: receipt.receipt_id.clone(),
                beneficiary_commitment: reservation.sponsor_commitment.clone(),
                rebate_note_root: commitment("low fee checkpoint rebate"),
                rebate_bps: 900,
            })
            .expect("devnet rebate must queue");
        let _fence = state
            .open_privacy_fence(OpenPrivacyFenceRequest {
                fence_kind: FenceKind::NullifierReplay,
                subject_id: checkpoint.checkpoint_id.clone(),
                commitment_root: commitment("checkpoint replay fence"),
                replay_domain: "devnet-checkpoint-attestor".to_string(),
                nullifier_root: commitment("privacy fence nullifier"),
                effective_height: 18,
            })
            .expect("devnet privacy fence must open");
        state
    }

    pub fn register_committee(
        &mut self,
        request: RegisterCommitteeRequest,
    ) -> Result<CommitteeRecord> {
        let committee = CommitteeRecord::from_request(request, &self.config)?;
        if self.committees.contains_key(&committee.committee_id) {
            return Err("committee already registered".to_string());
        }
        self.counters.committees = self.counters.committees.saturating_add(1);
        self.emit_event(
            "committee_registered",
            &committee.committee_id,
            &committee.public_record(),
            committee.activation_height,
        );
        self.committees
            .insert(committee.committee_id.clone(), committee.clone());
        self.recompute_roots();
        Ok(committee)
    }

    pub fn open_checkpoint(&mut self, request: OpenCheckpointRequest) -> Result<StateCheckpoint> {
        request.validate(&self.config)?;
        self.ensure_committee_active(&request.committee_id)?;
        self.ensure_checkpoint_capacity()?;
        self.spend_nullifier(&request.nullifier_root)?;
        let checkpoint = StateCheckpoint::from_request(
            request,
            self.counters.checkpoints.saturating_add(1),
            &self.config,
        )?;
        self.counters.checkpoints = self.counters.checkpoints.saturating_add(1);
        self.emit_event(
            "checkpoint_opened",
            &checkpoint.checkpoint_id,
            &checkpoint.public_record(),
            checkpoint.opens_at_height,
        );
        self.checkpoints
            .insert(checkpoint.checkpoint_id.clone(), checkpoint.clone());
        self.recompute_roots();
        Ok(checkpoint)
    }

    pub fn submit_witness_shard(
        &mut self,
        request: SubmitWitnessShardRequest,
    ) -> Result<WitnessShard> {
        request.validate(&self.config)?;
        self.ensure_checkpoint_open(&request.checkpoint_id)?;
        self.spend_nullifier(&request.nullifier_root)?;
        let shard = WitnessShard::from_request(
            request,
            self.counters.witness_shards.saturating_add(1),
            &self.config,
        )?;
        if self.witness_shards.contains_key(&shard.witness_shard_id) {
            return Err("witness shard already posted".to_string());
        }
        let checkpoint = self
            .checkpoints
            .get_mut(&shard.checkpoint_id)
            .ok_or_else(|| "checkpoint missing".to_string())?;
        if checkpoint.witness_shard_ids.len() >= self.config.max_witness_shards {
            return Err("checkpoint witness shard cap reached".to_string());
        }
        checkpoint
            .witness_shard_ids
            .push(shard.witness_shard_id.clone());
        self.counters.witness_shards = self.counters.witness_shards.saturating_add(1);
        self.emit_event(
            "witness_shard_posted",
            &shard.witness_shard_id,
            &shard.public_record(),
            shard.posted_at_height,
        );
        self.witness_shards
            .insert(shard.witness_shard_id.clone(), shard.clone());
        self.recompute_roots();
        Ok(shard)
    }

    pub fn record_committee_attestation(
        &mut self,
        request: RecordCommitteeAttestationRequest,
    ) -> Result<CommitteeAttestation> {
        request.validate(&self.config)?;
        self.ensure_committee_active(&request.committee_id)?;
        self.ensure_checkpoint_open(&request.checkpoint_id)?;
        self.spend_nullifier(&request.nullifier_root)?;
        let committee = self
            .committees
            .get(&request.committee_id)
            .ok_or_else(|| "committee missing".to_string())?;
        let quorum_weight =
            required_quorum_weight(committee.aggregate_weight, self.config.quorum_bps);
        let existing_weight = self.attestation_weight_for(&request.checkpoint_id);
        let quorum_reached = existing_weight.saturating_add(request.signer_weight) >= quorum_weight;
        let attestation = CommitteeAttestation::from_request(
            request,
            self.counters.attestations.saturating_add(1),
            &self.config,
            quorum_reached,
        )?;
        let checkpoint = self
            .checkpoints
            .get_mut(&attestation.checkpoint_id)
            .ok_or_else(|| "checkpoint missing".to_string())?;
        checkpoint
            .attestation_ids
            .push(attestation.attestation_id.clone());
        if quorum_reached {
            checkpoint.status = CheckpointStatus::Attested;
        }
        self.counters.attestations = self.counters.attestations.saturating_add(1);
        self.emit_event(
            "committee_attestation_recorded",
            &attestation.attestation_id,
            &attestation.public_record(),
            attestation.signed_at_height,
        );
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation.clone());
        self.recompute_roots();
        Ok(attestation)
    }

    pub fn reserve_sponsor(
        &mut self,
        request: ReserveSponsorRequest,
    ) -> Result<SponsorReservation> {
        request.validate(&self.config)?;
        self.ensure_checkpoint_exists(&request.checkpoint_id)?;
        self.spend_nullifier(&request.nullifier_root)?;
        let reservation = SponsorReservation::from_request(
            request,
            self.counters.sponsor_reservations.saturating_add(1),
            &self.config,
        )?;
        let checkpoint = self
            .checkpoints
            .get_mut(&reservation.checkpoint_id)
            .ok_or_else(|| "checkpoint missing".to_string())?;
        checkpoint
            .sponsor_reservation_ids
            .push(reservation.reservation_id.clone());
        self.counters.sponsor_reservations = self.counters.sponsor_reservations.saturating_add(1);
        self.emit_event(
            "sponsor_reserved",
            &reservation.reservation_id,
            &reservation.public_record(),
            reservation.expires_at_height,
        );
        self.sponsor_reservations
            .insert(reservation.reservation_id.clone(), reservation.clone());
        self.recompute_roots();
        Ok(reservation)
    }

    pub fn publish_settlement_receipt(
        &mut self,
        request: PublishSettlementReceiptRequest,
    ) -> Result<SettlementReceipt> {
        request.validate(&self.config)?;
        self.ensure_checkpoint_exists(&request.checkpoint_id)?;
        let receipt = SettlementReceipt::from_request(
            request,
            self.counters.settlement_receipts.saturating_add(1),
            &self.config,
        )?;
        let checkpoint = self
            .checkpoints
            .get_mut(&receipt.checkpoint_id)
            .ok_or_else(|| "checkpoint missing".to_string())?;
        if !matches!(
            checkpoint.status,
            CheckpointStatus::Open | CheckpointStatus::Attested
        ) {
            return Err("checkpoint not settleable".to_string());
        }
        checkpoint.status = CheckpointStatus::Settled;
        checkpoint.receipt_ids.push(receipt.receipt_id.clone());
        self.counters.settlement_receipts = self.counters.settlement_receipts.saturating_add(1);
        self.emit_event(
            "settlement_receipt_published",
            &receipt.receipt_id,
            &receipt.public_record(),
            receipt.settled_at_height,
        );
        self.settlement_receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        self.recompute_roots();
        Ok(receipt)
    }

    pub fn issue_fee_rebate(&mut self, request: IssueFeeRebateRequest) -> Result<FeeRebate> {
        request.validate(&self.config)?;
        self.ensure_checkpoint_exists(&request.checkpoint_id)?;
        if !self.settlement_receipts.contains_key(&request.receipt_id) {
            return Err("receipt missing for rebate".to_string());
        }
        let rebate = FeeRebate::from_request(
            request,
            self.counters.fee_rebates.saturating_add(1),
            &self.config,
        )?;
        self.counters.fee_rebates = self.counters.fee_rebates.saturating_add(1);
        self.emit_event(
            "fee_rebate_queued",
            &rebate.rebate_id,
            &rebate.public_record(),
            0,
        );
        self.fee_rebates
            .insert(rebate.rebate_id.clone(), rebate.clone());
        self.recompute_roots();
        Ok(rebate)
    }

    pub fn open_privacy_fence(&mut self, request: OpenPrivacyFenceRequest) -> Result<PrivacyFence> {
        request.validate()?;
        self.spend_nullifier(&request.nullifier_root)?;
        let fence =
            PrivacyFence::from_request(request, self.counters.privacy_fences.saturating_add(1))?;
        self.counters.privacy_fences = self.counters.privacy_fences.saturating_add(1);
        self.emit_event(
            "privacy_fence_opened",
            &fence.fence_id,
            &fence.public_record(),
            fence.effective_height,
        );
        self.privacy_fences
            .insert(fence.fence_id.clone(), fence.clone());
        self.recompute_roots();
        Ok(fence)
    }

    pub fn record_slashing_evidence(
        &mut self,
        request: RecordSlashingEvidenceRequest,
    ) -> Result<SlashingEvidence> {
        request.validate()?;
        self.ensure_checkpoint_exists(&request.checkpoint_id)?;
        self.ensure_committee_exists(&request.committee_id)?;
        let evidence = SlashingEvidence::from_request(
            request,
            self.counters.slashing_events.saturating_add(1),
        )?;
        if let Some(checkpoint) = self.checkpoints.get_mut(&evidence.checkpoint_id) {
            checkpoint.status = CheckpointStatus::Disputed;
        }
        self.counters.slashing_events = self.counters.slashing_events.saturating_add(1);
        self.emit_event(
            "slashing_evidence_recorded",
            &evidence.evidence_id,
            &evidence.public_record(),
            evidence.recorded_at_height,
        );
        self.slashing_events
            .insert(evidence.evidence_id.clone(), evidence.clone());
        self.recompute_roots();
        Ok(evidence)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PRIVATE_L2_PQ_FAST_STATE_CHECKPOINT_ATTESTOR_RUNTIME_PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PRIVATE_L2_PQ_FAST_STATE_CHECKPOINT_ATTESTOR_RUNTIME_PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    fn ensure_committee_exists(&self, committee_id: &str) -> Result<()> {
        if self.committees.contains_key(committee_id) {
            Ok(())
        } else {
            Err("committee missing".to_string())
        }
    }

    fn ensure_committee_active(&self, committee_id: &str) -> Result<()> {
        let committee = self
            .committees
            .get(committee_id)
            .ok_or_else(|| "committee missing".to_string())?;
        if committee.status == CommitteeStatus::Active {
            Ok(())
        } else {
            Err("committee not active".to_string())
        }
    }

    fn ensure_checkpoint_exists(&self, checkpoint_id: &str) -> Result<()> {
        if self.checkpoints.contains_key(checkpoint_id) {
            Ok(())
        } else {
            Err("checkpoint missing".to_string())
        }
    }

    fn ensure_checkpoint_open(&self, checkpoint_id: &str) -> Result<()> {
        let checkpoint = self
            .checkpoints
            .get(checkpoint_id)
            .ok_or_else(|| "checkpoint missing".to_string())?;
        if checkpoint.status == CheckpointStatus::Open {
            Ok(())
        } else {
            Err("checkpoint is not open".to_string())
        }
    }

    fn ensure_checkpoint_capacity(&self) -> Result<()> {
        let open_count = self
            .checkpoints
            .values()
            .filter(|checkpoint| checkpoint.status == CheckpointStatus::Open)
            .count();
        if open_count >= self.config.max_open_checkpoints
            || self.checkpoints.len() >= MAX_CHECKPOINTS
        {
            Err("checkpoint capacity reached".to_string())
        } else {
            Ok(())
        }
    }

    fn attestation_weight_for(&self, checkpoint_id: &str) -> u64 {
        self.attestations
            .values()
            .filter(|attestation| attestation.checkpoint_id == checkpoint_id)
            .fold(0_u64, |acc, attestation| {
                acc.saturating_add(attestation.signer_weight)
            })
    }

    fn spend_nullifier(&mut self, nullifier_root: &str) -> Result<()> {
        require_root("nullifier_root", nullifier_root)?;
        if self.spent_nullifiers.contains(nullifier_root) {
            Err("nullifier already spent".to_string())
        } else {
            self.spent_nullifiers.insert(nullifier_root.to_string());
            Ok(())
        }
    }

    fn emit_event(&mut self, event_kind: &str, subject_id: &str, payload: &Value, height: u64) {
        let sequence = self.counters.runtime_events.saturating_add(1);
        let event = RuntimeEvent::new(event_kind, subject_id, payload, height, sequence);
        self.runtime_events.push(event);
        self.counters.runtime_events = sequence;
        if self.runtime_events.len() > MAX_EVENTS {
            let drain = self.runtime_events.len().saturating_sub(MAX_EVENTS);
            self.runtime_events.drain(0..drain);
        }
    }

    fn recompute_roots(&mut self) {
        self.roots = Roots {
            committees_root: map_root(
                "COMMITTEES",
                self.committees.values().map(CommitteeRecord::public_record),
            ),
            checkpoints_root: map_root(
                "CHECKPOINTS",
                self.checkpoints
                    .values()
                    .map(StateCheckpoint::public_record),
            ),
            witness_shards_root: map_root(
                "WITNESS-SHARDS",
                self.witness_shards
                    .values()
                    .map(WitnessShard::public_record),
            ),
            attestations_root: map_root(
                "ATTESTATIONS",
                self.attestations
                    .values()
                    .map(CommitteeAttestation::public_record),
            ),
            sponsor_reservations_root: map_root(
                "SPONSOR-RESERVATIONS",
                self.sponsor_reservations
                    .values()
                    .map(SponsorReservation::public_record),
            ),
            settlement_receipts_root: map_root(
                "SETTLEMENT-RECEIPTS",
                self.settlement_receipts
                    .values()
                    .map(SettlementReceipt::public_record),
            ),
            fee_rebates_root: map_root(
                "FEE-REBATES",
                self.fee_rebates.values().map(FeeRebate::public_record),
            ),
            privacy_fences_root: map_root(
                "PRIVACY-FENCES",
                self.privacy_fences
                    .values()
                    .map(PrivacyFence::public_record),
            ),
            slashing_events_root: map_root(
                "SLASHING-EVENTS",
                self.slashing_events
                    .values()
                    .map(SlashingEvidence::public_record),
            ),
            spent_nullifiers_root: id_list_root(
                "SPENT-NULLIFIERS",
                &self.spent_nullifiers.iter().cloned().collect::<Vec<_>>(),
            ),
            runtime_events_root: map_root(
                "RUNTIME-EVENTS",
                self.runtime_events.iter().map(RuntimeEvent::public_record),
            ),
        };
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn private_l2_pq_fast_state_checkpoint_attestor_runtime_public_record(state: &State) -> Value {
    state.public_record()
}

pub fn private_l2_pq_fast_state_checkpoint_attestor_runtime_state_root(state: &State) -> String {
    state.state_root()
}

pub fn committee_id(request: &RegisterCommitteeRequest) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FAST-CHECKPOINT-COMMITTEE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.committee_label),
            HashPart::U64(request.epoch),
            HashPart::Str(&request.pq_public_key_root),
            HashPart::Str(&request.stealth_signer_set_root),
        ],
        32,
    )
}

pub fn checkpoint_id(request: &OpenCheckpointRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FAST-CHECKPOINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(&request.committee_id),
            HashPart::Str(&request.private_state_root),
            HashPart::Str(&request.encrypted_diff_root),
            HashPart::Str(&request.contract_batch_root),
            HashPart::U64(request.opens_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn witness_shard_id(request: &SubmitWitnessShardRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FAST-CHECKPOINT-WITNESS-SHARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.checkpoint_id),
            HashPart::U64(request.shard_index),
            HashPart::Str(&request.encrypted_witness_root),
            HashPart::Str(&request.availability_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn attestation_id(request: &RecordCommitteeAttestationRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FAST-CHECKPOINT-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.checkpoint_id),
            HashPart::Str(&request.committee_id),
            HashPart::Str(&request.attester_commitment_root),
            HashPart::Str(&request.pq_signature_root),
            HashPart::Str(&request.attested_state_root),
            HashPart::U64(request.signed_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn sponsor_reservation_id(request: &ReserveSponsorRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FAST-CHECKPOINT-SPONSOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.checkpoint_id),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.fee_note_root),
            HashPart::U64(request.max_fee_bps),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn settlement_receipt_id(request: &PublishSettlementReceiptRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FAST-CHECKPOINT-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.checkpoint_id),
            HashPart::Str(request.receipt_kind.as_str()),
            HashPart::Str(&request.attestation_root),
            HashPart::Str(&request.recursive_proof_root),
            HashPart::Str(&request.monero_anchor_root),
            HashPart::U64(request.settled_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn fee_rebate_id(request: &IssueFeeRebateRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FAST-CHECKPOINT-FEE-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.checkpoint_id),
            HashPart::Str(&request.receipt_id),
            HashPart::Str(&request.beneficiary_commitment),
            HashPart::Str(&request.rebate_note_root),
            HashPart::U64(request.rebate_bps),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn privacy_fence_id(request: &OpenPrivacyFenceRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FAST-CHECKPOINT-PRIVACY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.fence_kind.as_str()),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.commitment_root),
            HashPart::Str(&request.replay_domain),
            HashPart::Str(&request.nullifier_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn slashing_evidence_id(request: &RecordSlashingEvidenceRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FAST-CHECKPOINT-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.checkpoint_id),
            HashPart::Str(&request.committee_id),
            HashPart::Str(&request.offender_commitment),
            HashPart::Str(request.reason.as_str()),
            HashPart::Str(&request.evidence_root),
            HashPart::U64(request.recorded_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn runtime_event_id(
    event_kind: &str,
    subject_id: &str,
    payload_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FAST-CHECKPOINT-RUNTIME-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn commitment(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FAST-CHECKPOINT-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-FAST-CHECKPOINT-{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    payload_root(&format!("{domain}-ROOT"), record)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(&format!("PRIVATE-L2-PQ-FAST-CHECKPOINT-{domain}"), records)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("STATE", record)
}

pub fn empty_root(domain: &str) -> String {
    public_record_root(domain, &[])
}

pub fn string_root(domain: &str, value: &str) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-FAST-CHECKPOINT-{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Str(value)],
        32,
    )
}

pub fn id_list_root(domain: &str, ids: &[String]) -> String {
    let records = ids.iter().map(|id| json!({ "id": id })).collect::<Vec<_>>();
    public_record_root(domain, &records)
}

fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let records = records.into_iter().collect::<Vec<_>>();
    public_record_root(domain, &records)
}

fn required_quorum_weight(total_weight: u64, quorum_bps: u64) -> u64 {
    let numerator = total_weight.saturating_mul(quorum_bps);
    numerator
        .saturating_add(MAX_BPS.saturating_sub(1))
        .checked_div(MAX_BPS)
        .unwrap_or(total_weight)
}

fn require_eq(field: &str, actual: &str, expected: &str) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{field} must equal {expected}"))
    }
}

fn require_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must be non-empty"))
    } else {
        Ok(())
    }
}

fn require_root(field: &str, value: &str) -> Result<()> {
    require_non_empty(field, value)?;
    if value.len() < 16 {
        Err(format!("{field} must be a commitment root"))
    } else {
        Ok(())
    }
}

fn require_bps(field: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{field} exceeds {MAX_BPS} bps"))
    } else {
        Ok(())
    }
}
