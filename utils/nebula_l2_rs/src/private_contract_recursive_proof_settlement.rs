use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateContractRecursiveProofSettlementResult<T> = Result<T, String>;

pub const PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_PROTOCOL_VERSION: &str =
    "nebula-l2-private-contract-recursive-proof-settlement-v1";
pub const PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_DEVNET_HEIGHT: u64 = 2_048;
pub const PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_HASH_SUITE: &str =
    "SHAKE256-domain-separated";
pub const PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_RECURSION_SUITE: &str =
    "nebula-private-contract-recursive-folding-v1";
pub const PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_WITNESS_SUITE: &str =
    "private-contract-witness-commitment-v1";
pub const PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_STATE_DIFF_SUITE: &str =
    "private-contract-state-diff-root-v1";
pub const PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_PQ_ATTESTATION_SUITE: &str =
    "ML-DSA-65+SLH-DSA-SHAKE-128s-settlement-attestation";
pub const PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_FEE_SPONSOR_SUITE: &str =
    "private-fee-sponsorship-vault-v1";
pub const PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_DEFAULT_MAX_CALLS_PER_BATCH: u64 = 256;
pub const PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_DEFAULT_MAX_JOBS_PER_LANE: u64 = 128;
pub const PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_DEFAULT_MAX_RECURSION_DEPTH: u64 = 8;
pub const PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 144;
pub const PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_DEFAULT_AGGREGATE_WINDOW_BLOCKS: u64 = 6;
pub const PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_DEFAULT_MIN_PQ_ATTESTATIONS: u64 = 3;
pub const PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_DEFAULT_SPONSOR_POOL_UNITS: u64 = 750_000;
pub const PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_DEFAULT_SPONSOR_REBATE_BPS: u64 = 8_500;
pub const PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_DEFAULT_DA_RESERVE_BPS: u64 = 2_000;
pub const PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_DEFAULT_SLASHING_BPS: u64 = 5_000;
pub const PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractSettlementLane {
    PrivateSwap,
    Lending,
    Perps,
    Stablecoin,
    Governance,
    TokenMint,
    Emergency,
}

impl ContractSettlementLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateSwap => "private_swap",
            Self::Lending => "lending",
            Self::Perps => "perps",
            Self::Stablecoin => "stablecoin",
            Self::Governance => "governance",
            Self::TokenMint => "token_mint",
            Self::Emergency => "emergency",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 10_000,
            Self::Stablecoin => 9_000,
            Self::Lending => 8_200,
            Self::PrivateSwap => 7_800,
            Self::Perps => 7_200,
            Self::TokenMint => 6_400,
            Self::Governance => 5_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecursiveProofJobKind {
    BaseCallBatch,
    RecursiveAggregate,
    WitnessAvailability,
    FeeSponsorship,
    PqCommitteeAttestation,
    StateDiffCertification,
    SettlementFinality,
}

impl RecursiveProofJobKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BaseCallBatch => "base_call_batch",
            Self::RecursiveAggregate => "recursive_aggregate",
            Self::WitnessAvailability => "witness_availability",
            Self::FeeSponsorship => "fee_sponsorship",
            Self::PqCommitteeAttestation => "pq_committee_attestation",
            Self::StateDiffCertification => "state_diff_certification",
            Self::SettlementFinality => "settlement_finality",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecursiveProofJobStatus {
    Queued,
    WitnessLocked,
    Proving,
    Aggregating,
    Attesting,
    ChallengeOpen,
    SettlementReady,
    Settled,
    Rejected,
    Expired,
}

impl RecursiveProofJobStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::WitnessLocked => "witness_locked",
            Self::Proving => "proving",
            Self::Aggregating => "aggregating",
            Self::Attesting => "attesting",
            Self::ChallengeOpen => "challenge_open",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Queued
                | Self::WitnessLocked
                | Self::Proving
                | Self::Aggregating
                | Self::Attesting
                | Self::ChallengeOpen
                | Self::SettlementReady
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateCallBatchStatus {
    Open,
    Sealed,
    Witnessed,
    Proved,
    Aggregated,
    Settled,
    Challenged,
    Failed,
}

impl PrivateCallBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Witnessed => "witnessed",
            Self::Proved => "proved",
            Self::Aggregated => "aggregated",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessCommitmentStatus {
    Announced,
    Pinned,
    Sampled,
    Accepted,
    Challenged,
    Expired,
}

impl WitnessCommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Announced => "announced",
            Self::Pinned => "pinned",
            Self::Sampled => "sampled",
            Self::Accepted => "accepted",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Reserved,
    Applied,
    Refunded,
    Slashed,
    Exhausted,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Refunded => "refunded",
            Self::Slashed => "slashed",
            Self::Exhausted => "exhausted",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregationLaneStatus {
    Collecting,
    Sealed,
    Proving,
    Attested,
    ChallengeOpen,
    SettlementReady,
    Settled,
    Halted,
}

impl AggregationLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Sealed => "sealed",
            Self::Proving => "proving",
            Self::Attested => "attested",
            Self::ChallengeOpen => "challenge_open",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Halted => "halted",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementReceiptStatus {
    Pending,
    Posted,
    ChallengeOpen,
    Finalized,
    Reverted,
}

impl SettlementReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Posted => "posted",
            Self::ChallengeOpen => "challenge_open",
            Self::Finalized => "finalized",
            Self::Reverted => "reverted",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    Answered,
    Sustained,
    Rejected,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Answered => "answered",
            Self::Sustained => "sustained",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAttestationStatus {
    Proposed,
    Verified,
    Quorum,
    Revoked,
}

impl PqAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Verified => "verified",
            Self::Quorum => "quorum",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub max_calls_per_batch: u64,
    pub max_jobs_per_lane: u64,
    pub max_recursion_depth: u64,
    pub challenge_window_blocks: u64,
    pub aggregate_window_blocks: u64,
    pub min_pq_attestations: u64,
    pub sponsor_pool_units: u64,
    pub sponsor_rebate_bps: u64,
    pub da_reserve_bps: u64,
    pub slashing_bps: u64,
    pub hash_suite: String,
    pub recursion_suite: String,
    pub witness_suite: String,
    pub state_diff_suite: String,
    pub pq_attestation_suite: String,
    pub fee_sponsor_suite: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            max_calls_per_batch:
                PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_DEFAULT_MAX_CALLS_PER_BATCH,
            max_jobs_per_lane:
                PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_DEFAULT_MAX_JOBS_PER_LANE,
            max_recursion_depth:
                PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_DEFAULT_MAX_RECURSION_DEPTH,
            challenge_window_blocks:
                PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            aggregate_window_blocks:
                PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_DEFAULT_AGGREGATE_WINDOW_BLOCKS,
            min_pq_attestations:
                PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_DEFAULT_MIN_PQ_ATTESTATIONS,
            sponsor_pool_units:
                PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_DEFAULT_SPONSOR_POOL_UNITS,
            sponsor_rebate_bps:
                PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_DEFAULT_SPONSOR_REBATE_BPS,
            da_reserve_bps: PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_DEFAULT_DA_RESERVE_BPS,
            slashing_bps: PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_DEFAULT_SLASHING_BPS,
            hash_suite: PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_HASH_SUITE.to_string(),
            recursion_suite: PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_RECURSION_SUITE
                .to_string(),
            witness_suite: PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_WITNESS_SUITE.to_string(),
            state_diff_suite: PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_STATE_DIFF_SUITE
                .to_string(),
            pq_attestation_suite: PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_PQ_ATTESTATION_SUITE
                .to_string(),
            fee_sponsor_suite: PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_FEE_SPONSOR_SUITE
                .to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "max_calls_per_batch": self.max_calls_per_batch,
            "max_jobs_per_lane": self.max_jobs_per_lane,
            "max_recursion_depth": self.max_recursion_depth,
            "challenge_window_blocks": self.challenge_window_blocks,
            "aggregate_window_blocks": self.aggregate_window_blocks,
            "min_pq_attestations": self.min_pq_attestations,
            "sponsor_pool_units": self.sponsor_pool_units,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
            "da_reserve_bps": self.da_reserve_bps,
            "slashing_bps": self.slashing_bps,
            "hash_suite": self.hash_suite,
            "recursion_suite": self.recursion_suite,
            "witness_suite": self.witness_suite,
            "state_diff_suite": self.state_diff_suite,
            "pq_attestation_suite": self.pq_attestation_suite,
            "fee_sponsor_suite": self.fee_sponsor_suite,
        })
    }

    pub fn validate(&self) -> PrivateContractRecursiveProofSettlementResult<()> {
        if self.max_calls_per_batch == 0
            || self.max_jobs_per_lane == 0
            || self.max_recursion_depth == 0
            || self.challenge_window_blocks == 0
            || self.aggregate_window_blocks == 0
            || self.min_pq_attestations == 0
        {
            return Err("private recursive settlement config limits must be positive".to_string());
        }
        if self.sponsor_rebate_bps > PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_MAX_BPS
            || self.da_reserve_bps > PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_MAX_BPS
            || self.slashing_bps > PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_MAX_BPS
        {
            return Err("private recursive settlement bps values exceed maximum".to_string());
        }
        if self.hash_suite.is_empty()
            || self.recursion_suite.is_empty()
            || self.witness_suite.is_empty()
            || self.state_diff_suite.is_empty()
            || self.pq_attestation_suite.is_empty()
            || self.fee_sponsor_suite.is_empty()
        {
            return Err("private recursive settlement suite labels must be populated".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractCallBatch {
    pub batch_id: String,
    pub lane: ContractSettlementLane,
    pub contract_root: String,
    pub call_commitment_root: String,
    pub encrypted_calldata_root: String,
    pub caller_nullifier_root: String,
    pub read_set_root: String,
    pub write_set_commitment_root: String,
    pub policy_root: String,
    pub call_count: u64,
    pub batch_weight: u64,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub status: PrivateCallBatchStatus,
}

impl PrivateContractCallBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "lane": self.lane.as_str(),
            "contract_root": self.contract_root,
            "call_commitment_root": self.call_commitment_root,
            "encrypted_calldata_root": self.encrypted_calldata_root,
            "caller_nullifier_root": self.caller_nullifier_root,
            "read_set_root": self.read_set_root,
            "write_set_commitment_root": self.write_set_commitment_root,
            "policy_root": self.policy_root,
            "call_count": self.call_count,
            "batch_weight": self.batch_weight,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record("CALL-BATCH", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessCommitment {
    pub witness_id: String,
    pub batch_id: String,
    pub prover_id: String,
    pub witness_root: String,
    pub encrypted_witness_root: String,
    pub availability_root: String,
    pub sampling_seed_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub byte_size: u64,
    pub status: WitnessCommitmentStatus,
}

impl WitnessCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "witness_id": self.witness_id,
            "batch_id": self.batch_id,
            "prover_id": self.prover_id,
            "witness_root": self.witness_root,
            "encrypted_witness_root": self.encrypted_witness_root,
            "availability_root": self.availability_root,
            "sampling_seed_root": self.sampling_seed_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "byte_size": self.byte_size,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record("WITNESS-COMMITMENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub batch_id: String,
    pub lane: ContractSettlementLane,
    pub fee_asset_id: String,
    pub reserved_fee_units: u64,
    pub applied_fee_units: u64,
    pub rebate_bps: u64,
    pub da_reserve_units: u64,
    pub policy_root: String,
    pub opened_at_height: u64,
    pub status: SponsorshipStatus,
}

impl FeeSponsorship {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "batch_id": self.batch_id,
            "lane": self.lane.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "reserved_fee_units": self.reserved_fee_units,
            "applied_fee_units": self.applied_fee_units,
            "rebate_bps": self.rebate_bps,
            "da_reserve_units": self.da_reserve_units,
            "policy_root": self.policy_root,
            "opened_at_height": self.opened_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record("FEE-SPONSORSHIP", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateDiffRoot {
    pub diff_id: String,
    pub batch_id: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub read_set_root: String,
    pub write_set_root: String,
    pub nullifier_delta_root: String,
    pub note_delta_root: String,
    pub event_root: String,
    pub diff_proof_root: String,
    pub applied_at_height: u64,
}

impl StateDiffRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "diff_id": self.diff_id,
            "batch_id": self.batch_id,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "read_set_root": self.read_set_root,
            "write_set_root": self.write_set_root,
            "nullifier_delta_root": self.nullifier_delta_root,
            "note_delta_root": self.note_delta_root,
            "event_root": self.event_root,
            "diff_proof_root": self.diff_proof_root,
            "applied_at_height": self.applied_at_height,
        })
    }

    pub fn root(&self) -> String {
        root_from_record("STATE-DIFF", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursiveProofJob {
    pub job_id: String,
    pub batch_id: String,
    pub lane_id: String,
    pub kind: RecursiveProofJobKind,
    pub status: RecursiveProofJobStatus,
    pub recursion_depth: u64,
    pub proof_input_root: String,
    pub proof_output_root: String,
    pub witness_id: String,
    pub sponsorship_id: String,
    pub state_diff_id: String,
    pub prover_commitment: String,
    pub priority: u64,
    pub queued_at_height: u64,
    pub deadline_height: u64,
}

impl RecursiveProofJob {
    pub fn public_record(&self) -> Value {
        json!({
            "job_id": self.job_id,
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "recursion_depth": self.recursion_depth,
            "proof_input_root": self.proof_input_root,
            "proof_output_root": self.proof_output_root,
            "witness_id": self.witness_id,
            "sponsorship_id": self.sponsorship_id,
            "state_diff_id": self.state_diff_id,
            "prover_commitment": self.prover_commitment,
            "priority": self.priority,
            "queued_at_height": self.queued_at_height,
            "deadline_height": self.deadline_height,
        })
    }

    pub fn root(&self) -> String {
        root_from_record("RECURSIVE-PROOF-JOB", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregationLane {
    pub lane_id: String,
    pub settlement_lane: ContractSettlementLane,
    pub status: AggregationLaneStatus,
    pub job_ids: BTreeSet<String>,
    pub aggregate_root: String,
    pub recursive_proof_root: String,
    pub state_diff_root: String,
    pub fee_sponsorship_root: String,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub priority_weight: u64,
}

impl AggregationLane {
    pub fn public_record(&self) -> Value {
        let job_ids = self.job_ids.iter().cloned().collect::<Vec<_>>();
        json!({
            "lane_id": self.lane_id,
            "settlement_lane": self.settlement_lane.as_str(),
            "status": self.status.as_str(),
            "job_ids": job_ids,
            "aggregate_root": self.aggregate_root,
            "recursive_proof_root": self.recursive_proof_root,
            "state_diff_root": self.state_diff_root,
            "fee_sponsorship_root": self.fee_sponsorship_root,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "priority_weight": self.priority_weight,
        })
    }

    pub fn root(&self) -> String {
        root_from_record("AGGREGATION-LANE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSignerAttestation {
    pub attestation_id: String,
    pub signer_id: String,
    pub signer_key_root: String,
    pub subject_root: String,
    pub signature_root: String,
    pub aggregation_lane_id: String,
    pub job_id: String,
    pub signed_at_height: u64,
    pub status: PqAttestationStatus,
}

impl PqSignerAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "signer_id": self.signer_id,
            "signer_key_root": self.signer_key_root,
            "subject_root": self.subject_root,
            "signature_root": self.signature_root,
            "aggregation_lane_id": self.aggregation_lane_id,
            "job_id": self.job_id,
            "signed_at_height": self.signed_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record("PQ-SIGNER-ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeWindow {
    pub challenge_id: String,
    pub subject_root: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub bond_units: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub answered_at_height: u64,
    pub status: ChallengeStatus,
}

impl ChallengeWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "subject_root": self.subject_root,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "bond_units": self.bond_units,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "answered_at_height": self.answered_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record("CHALLENGE-WINDOW", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub lane_id: String,
    pub aggregate_root: String,
    pub settlement_tx_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub fee_paid_units: u64,
    pub sponsored_units: u64,
    pub posted_at_height: u64,
    pub finalized_at_height: u64,
    pub challenge_window_id: String,
    pub status: SettlementReceiptStatus,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "lane_id": self.lane_id,
            "aggregate_root": self.aggregate_root,
            "settlement_tx_root": self.settlement_tx_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "fee_paid_units": self.fee_paid_units,
            "sponsored_units": self.sponsored_units,
            "posted_at_height": self.posted_at_height,
            "finalized_at_height": self.finalized_at_height,
            "challenge_window_id": self.challenge_window_id,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record("SETTLEMENT-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub call_batch_root: String,
    pub witness_commitment_root: String,
    pub sponsorship_root: String,
    pub aggregation_lane_root: String,
    pub proof_job_root: String,
    pub settlement_receipt_root: String,
    pub challenge_window_root: String,
    pub pq_attestation_root: String,
    pub state_diff_root: String,
    pub live_job_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "call_batch_root": self.call_batch_root,
            "witness_commitment_root": self.witness_commitment_root,
            "sponsorship_root": self.sponsorship_root,
            "aggregation_lane_root": self.aggregation_lane_root,
            "proof_job_root": self.proof_job_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "challenge_window_root": self.challenge_window_root,
            "pq_attestation_root": self.pq_attestation_root,
            "state_diff_root": self.state_diff_root,
            "live_job_root": self.live_job_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub call_batches: u64,
    pub witness_commitments: u64,
    pub sponsorships: u64,
    pub aggregation_lanes: u64,
    pub proof_jobs: u64,
    pub live_jobs: u64,
    pub settled_jobs: u64,
    pub settlement_receipts: u64,
    pub open_challenges: u64,
    pub pq_attestations: u64,
    pub state_diffs: u64,
    pub sponsored_fee_units: u64,
    pub applied_fee_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "call_batches": self.call_batches,
            "witness_commitments": self.witness_commitments,
            "sponsorships": self.sponsorships,
            "aggregation_lanes": self.aggregation_lanes,
            "proof_jobs": self.proof_jobs,
            "live_jobs": self.live_jobs,
            "settled_jobs": self.settled_jobs,
            "settlement_receipts": self.settlement_receipts,
            "open_challenges": self.open_challenges,
            "pq_attestations": self.pq_attestations,
            "state_diffs": self.state_diffs,
            "sponsored_fee_units": self.sponsored_fee_units,
            "applied_fee_units": self.applied_fee_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub call_batches: BTreeMap<String, PrivateContractCallBatch>,
    pub witness_commitments: BTreeMap<String, WitnessCommitment>,
    pub sponsorships: BTreeMap<String, FeeSponsorship>,
    pub aggregation_lanes: BTreeMap<String, AggregationLane>,
    pub proof_jobs: BTreeMap<String, RecursiveProofJob>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub challenge_windows: BTreeMap<String, ChallengeWindow>,
    pub pq_attestations: BTreeMap<String, PqSignerAttestation>,
    pub state_diffs: BTreeMap<String, StateDiffRoot>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let height = PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_DEVNET_HEIGHT;

        let batch_swap = devnet_call_batch(
            "batch-private-swap-0001",
            ContractSettlementLane::PrivateSwap,
            84,
            height.saturating_sub(12),
            PrivateCallBatchStatus::Aggregated,
        );
        let batch_lending = devnet_call_batch(
            "batch-lending-0001",
            ContractSettlementLane::Lending,
            61,
            height.saturating_sub(10),
            PrivateCallBatchStatus::Aggregated,
        );
        let batch_emergency = devnet_call_batch(
            "batch-emergency-0001",
            ContractSettlementLane::Emergency,
            9,
            height.saturating_sub(4),
            PrivateCallBatchStatus::Witnessed,
        );

        let witness_swap = devnet_witness(
            "witness-private-swap-0001",
            &batch_swap.batch_id,
            "prover-alpha",
            height.saturating_sub(11),
            WitnessCommitmentStatus::Accepted,
        );
        let witness_lending = devnet_witness(
            "witness-lending-0001",
            &batch_lending.batch_id,
            "prover-beta",
            height.saturating_sub(9),
            WitnessCommitmentStatus::Accepted,
        );
        let witness_emergency = devnet_witness(
            "witness-emergency-0001",
            &batch_emergency.batch_id,
            "prover-emergency",
            height.saturating_sub(3),
            WitnessCommitmentStatus::Pinned,
        );

        let sponsor_swap = devnet_sponsorship(
            "sponsor-private-swap-0001",
            &batch_swap.batch_id,
            ContractSettlementLane::PrivateSwap,
            72_000,
            61_200,
            height.saturating_sub(12),
            SponsorshipStatus::Applied,
        );
        let sponsor_lending = devnet_sponsorship(
            "sponsor-lending-0001",
            &batch_lending.batch_id,
            ContractSettlementLane::Lending,
            56_000,
            47_600,
            height.saturating_sub(10),
            SponsorshipStatus::Applied,
        );
        let sponsor_emergency = devnet_sponsorship(
            "sponsor-emergency-0001",
            &batch_emergency.batch_id,
            ContractSettlementLane::Emergency,
            18_000,
            0,
            height.saturating_sub(4),
            SponsorshipStatus::Reserved,
        );

        let diff_swap = devnet_state_diff(
            "diff-private-swap-0001",
            &batch_swap.batch_id,
            height.saturating_sub(8),
        );
        let diff_lending = devnet_state_diff(
            "diff-lending-0001",
            &batch_lending.batch_id,
            height.saturating_sub(7),
        );
        let diff_emergency = devnet_state_diff(
            "diff-emergency-0001",
            &batch_emergency.batch_id,
            height.saturating_sub(2),
        );

        let lane_swap_id = "lane-private-swap-recursive-0001".to_string();
        let lane_lending_id = "lane-lending-recursive-0001".to_string();
        let lane_emergency_id = "lane-emergency-recursive-0001".to_string();

        let job_swap = devnet_job(
            "job-private-swap-0001",
            &batch_swap,
            &lane_swap_id,
            &witness_swap,
            &sponsor_swap,
            &diff_swap,
            RecursiveProofJobKind::RecursiveAggregate,
            RecursiveProofJobStatus::SettlementReady,
            height.saturating_sub(10),
        );
        let job_lending = devnet_job(
            "job-lending-0001",
            &batch_lending,
            &lane_lending_id,
            &witness_lending,
            &sponsor_lending,
            &diff_lending,
            RecursiveProofJobKind::RecursiveAggregate,
            RecursiveProofJobStatus::ChallengeOpen,
            height.saturating_sub(8),
        );
        let job_emergency = devnet_job(
            "job-emergency-0001",
            &batch_emergency,
            &lane_emergency_id,
            &witness_emergency,
            &sponsor_emergency,
            &diff_emergency,
            RecursiveProofJobKind::BaseCallBatch,
            RecursiveProofJobStatus::Proving,
            height.saturating_sub(2),
        );

        let lane_swap = devnet_aggregation_lane(
            &lane_swap_id,
            ContractSettlementLane::PrivateSwap,
            &[job_swap.job_id.clone()],
            AggregationLaneStatus::SettlementReady,
            height.saturating_sub(10),
        );
        let lane_lending = devnet_aggregation_lane(
            &lane_lending_id,
            ContractSettlementLane::Lending,
            &[job_lending.job_id.clone()],
            AggregationLaneStatus::ChallengeOpen,
            height.saturating_sub(8),
        );
        let lane_emergency = devnet_aggregation_lane(
            &lane_emergency_id,
            ContractSettlementLane::Emergency,
            &[job_emergency.job_id.clone()],
            AggregationLaneStatus::Proving,
            height.saturating_sub(2),
        );

        let att_swap_1 = devnet_attestation(
            "att-private-swap-0001-a",
            "pq-signer-alpha",
            &lane_swap.lane_id,
            &job_swap.job_id,
            &lane_swap.aggregate_root,
            height.saturating_sub(6),
            PqAttestationStatus::Quorum,
        );
        let att_swap_2 = devnet_attestation(
            "att-private-swap-0001-b",
            "pq-signer-beta",
            &lane_swap.lane_id,
            &job_swap.job_id,
            &lane_swap.aggregate_root,
            height.saturating_sub(6),
            PqAttestationStatus::Quorum,
        );
        let att_swap_3 = devnet_attestation(
            "att-private-swap-0001-c",
            "pq-signer-gamma",
            &lane_swap.lane_id,
            &job_swap.job_id,
            &lane_swap.aggregate_root,
            height.saturating_sub(6),
            PqAttestationStatus::Quorum,
        );
        let att_lending = devnet_attestation(
            "att-lending-0001-a",
            "pq-signer-alpha",
            &lane_lending.lane_id,
            &job_lending.job_id,
            &lane_lending.aggregate_root,
            height.saturating_sub(4),
            PqAttestationStatus::Verified,
        );

        let challenge_lending = devnet_challenge(
            "challenge-lending-0001",
            &lane_lending.aggregate_root,
            height.saturating_sub(3),
            config.challenge_window_blocks,
            ChallengeStatus::Open,
        );

        let receipt_swap = devnet_receipt(
            "receipt-private-swap-0001",
            &lane_swap,
            &challenge_lending.challenge_id,
            40_000,
            sponsor_swap.applied_fee_units,
            height.saturating_sub(5),
            SettlementReceiptStatus::ChallengeOpen,
        );

        Self {
            height,
            config,
            call_batches: map_by_id(vec![
                (batch_swap.batch_id.clone(), batch_swap),
                (batch_lending.batch_id.clone(), batch_lending),
                (batch_emergency.batch_id.clone(), batch_emergency),
            ]),
            witness_commitments: map_by_id(vec![
                (witness_swap.witness_id.clone(), witness_swap),
                (witness_lending.witness_id.clone(), witness_lending),
                (witness_emergency.witness_id.clone(), witness_emergency),
            ]),
            sponsorships: map_by_id(vec![
                (sponsor_swap.sponsorship_id.clone(), sponsor_swap),
                (sponsor_lending.sponsorship_id.clone(), sponsor_lending),
                (sponsor_emergency.sponsorship_id.clone(), sponsor_emergency),
            ]),
            aggregation_lanes: map_by_id(vec![
                (lane_swap.lane_id.clone(), lane_swap),
                (lane_lending.lane_id.clone(), lane_lending),
                (lane_emergency.lane_id.clone(), lane_emergency),
            ]),
            proof_jobs: map_by_id(vec![
                (job_swap.job_id.clone(), job_swap),
                (job_lending.job_id.clone(), job_lending),
                (job_emergency.job_id.clone(), job_emergency),
            ]),
            settlement_receipts: map_by_id(vec![(receipt_swap.receipt_id.clone(), receipt_swap)]),
            challenge_windows: map_by_id(vec![(
                challenge_lending.challenge_id.clone(),
                challenge_lending,
            )]),
            pq_attestations: map_by_id(vec![
                (att_swap_1.attestation_id.clone(), att_swap_1),
                (att_swap_2.attestation_id.clone(), att_swap_2),
                (att_swap_3.attestation_id.clone(), att_swap_3),
                (att_lending.attestation_id.clone(), att_lending),
            ]),
            state_diffs: map_by_id(vec![
                (diff_swap.diff_id.clone(), diff_swap),
                (diff_lending.diff_id.clone(), diff_lending),
                (diff_emergency.diff_id.clone(), diff_emergency),
            ]),
        }
    }

    pub fn validate(&self) -> PrivateContractRecursiveProofSettlementResult<()> {
        self.config.validate()?;
        if self.height == 0 {
            return Err("private recursive settlement state height must be positive".to_string());
        }
        self.validate_batches()?;
        self.validate_witnesses()?;
        self.validate_sponsorships()?;
        self.validate_state_diffs()?;
        self.validate_jobs()?;
        self.validate_lanes()?;
        self.validate_challenges()?;
        self.validate_receipts()?;
        self.validate_attestations()?;
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> PrivateContractRecursiveProofSettlementResult<()> {
        if height == 0 {
            return Err("private recursive settlement height must be positive".to_string());
        }
        self.height = height;
        Ok(())
    }

    pub fn update_height(
        &mut self,
        height: u64,
    ) -> PrivateContractRecursiveProofSettlementResult<()> {
        if height < self.height {
            return Err("private recursive settlement height cannot move backwards".to_string());
        }
        self.set_height(height)
    }

    pub fn roots(&self) -> Roots {
        let config_root = root_from_record("CONFIG", &self.config.public_record());
        let call_batch_root = root_from_records(
            "CALL-BATCHES",
            self.call_batches
                .values()
                .map(PrivateContractCallBatch::public_record)
                .collect(),
        );
        let witness_commitment_root = root_from_records(
            "WITNESS-COMMITMENTS",
            self.witness_commitments
                .values()
                .map(WitnessCommitment::public_record)
                .collect(),
        );
        let sponsorship_root = root_from_records(
            "FEE-SPONSORSHIPS",
            self.sponsorships
                .values()
                .map(FeeSponsorship::public_record)
                .collect(),
        );
        let aggregation_lane_root = root_from_records(
            "AGGREGATION-LANES",
            self.aggregation_lanes
                .values()
                .map(AggregationLane::public_record)
                .collect(),
        );
        let proof_job_root = root_from_records(
            "RECURSIVE-PROOF-JOBS",
            self.proof_jobs
                .values()
                .map(RecursiveProofJob::public_record)
                .collect(),
        );
        let settlement_receipt_root = root_from_records(
            "SETTLEMENT-RECEIPTS",
            self.settlement_receipts
                .values()
                .map(SettlementReceipt::public_record)
                .collect(),
        );
        let challenge_window_root = root_from_records(
            "CHALLENGE-WINDOWS",
            self.challenge_windows
                .values()
                .map(ChallengeWindow::public_record)
                .collect(),
        );
        let pq_attestation_root = root_from_records(
            "PQ-SIGNER-ATTESTATIONS",
            self.pq_attestations
                .values()
                .map(PqSignerAttestation::public_record)
                .collect(),
        );
        let state_diff_root = root_from_records(
            "STATE-DIFFS",
            self.state_diffs
                .values()
                .map(StateDiffRoot::public_record)
                .collect(),
        );
        let live_job_root = root_from_records(
            "LIVE-RECURSIVE-PROOF-JOBS",
            self.proof_jobs
                .values()
                .filter(|job| job.status.live())
                .map(RecursiveProofJob::public_record)
                .collect(),
        );
        let state_payload = json!({
            "protocol_version": PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_PROTOCOL_VERSION,
            "schema_version": PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config_root": config_root.clone(),
            "call_batch_root": call_batch_root.clone(),
            "witness_commitment_root": witness_commitment_root.clone(),
            "sponsorship_root": sponsorship_root.clone(),
            "aggregation_lane_root": aggregation_lane_root.clone(),
            "proof_job_root": proof_job_root.clone(),
            "settlement_receipt_root": settlement_receipt_root.clone(),
            "challenge_window_root": challenge_window_root.clone(),
            "pq_attestation_root": pq_attestation_root.clone(),
            "state_diff_root": state_diff_root.clone(),
            "live_job_root": live_job_root.clone(),
        });
        let state_root = root_from_record("STATE", &state_payload);
        Roots {
            config_root,
            call_batch_root,
            witness_commitment_root,
            sponsorship_root,
            aggregation_lane_root,
            proof_job_root,
            settlement_receipt_root,
            challenge_window_root,
            pq_attestation_root,
            state_diff_root,
            live_job_root,
            state_root,
        }
    }

    pub fn counters(&self) -> Counters {
        let live_jobs = self
            .proof_jobs
            .values()
            .filter(|job| job.status.live())
            .count() as u64;
        let settled_jobs = self
            .proof_jobs
            .values()
            .filter(|job| job.status == RecursiveProofJobStatus::Settled)
            .count() as u64;
        let open_challenges = self
            .challenge_windows
            .values()
            .filter(|challenge| challenge.status == ChallengeStatus::Open)
            .count() as u64;
        let sponsored_fee_units = self
            .sponsorships
            .values()
            .map(|sponsorship| sponsorship.reserved_fee_units)
            .sum();
        let applied_fee_units = self
            .sponsorships
            .values()
            .map(|sponsorship| sponsorship.applied_fee_units)
            .sum();

        Counters {
            call_batches: self.call_batches.len() as u64,
            witness_commitments: self.witness_commitments.len() as u64,
            sponsorships: self.sponsorships.len() as u64,
            aggregation_lanes: self.aggregation_lanes.len() as u64,
            proof_jobs: self.proof_jobs.len() as u64,
            live_jobs,
            settled_jobs,
            settlement_receipts: self.settlement_receipts.len() as u64,
            open_challenges,
            pq_attestations: self.pq_attestations.len() as u64,
            state_diffs: self.state_diffs.len() as u64,
            sponsored_fee_units,
            applied_fee_units,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "protocol_version": PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_PROTOCOL_VERSION,
            "schema_version": PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "call_batches": map_records(&self.call_batches, PrivateContractCallBatch::public_record),
            "witness_commitments": map_records(&self.witness_commitments, WitnessCommitment::public_record),
            "sponsorships": map_records(&self.sponsorships, FeeSponsorship::public_record),
            "aggregation_lanes": map_records(&self.aggregation_lanes, AggregationLane::public_record),
            "proof_jobs": map_records(&self.proof_jobs, RecursiveProofJob::public_record),
            "settlement_receipts": map_records(&self.settlement_receipts, SettlementReceipt::public_record),
            "challenge_windows": map_records(&self.challenge_windows, ChallengeWindow::public_record),
            "pq_attestations": map_records(&self.pq_attestations, PqSignerAttestation::public_record),
            "state_diffs": map_records(&self.state_diffs, StateDiffRoot::public_record),
        })
    }

    fn validate_batches(&self) -> PrivateContractRecursiveProofSettlementResult<()> {
        for batch in self.call_batches.values() {
            if batch.batch_id.is_empty()
                || batch.contract_root.is_empty()
                || batch.call_commitment_root.is_empty()
                || batch.encrypted_calldata_root.is_empty()
                || batch.caller_nullifier_root.is_empty()
                || batch.read_set_root.is_empty()
                || batch.write_set_commitment_root.is_empty()
            {
                return Err("private recursive settlement batch has empty commitment".to_string());
            }
            if batch.call_count == 0 || batch.call_count > self.config.max_calls_per_batch {
                return Err("private recursive settlement batch call count is invalid".to_string());
            }
            if batch.sealed_at_height < batch.opened_at_height {
                return Err("private recursive settlement batch is sealed before open".to_string());
            }
        }
        Ok(())
    }

    fn validate_witnesses(&self) -> PrivateContractRecursiveProofSettlementResult<()> {
        for witness in self.witness_commitments.values() {
            if !self.call_batches.contains_key(&witness.batch_id) {
                return Err(
                    "private recursive settlement witness references missing batch".to_string(),
                );
            }
            if witness.witness_root.is_empty()
                || witness.encrypted_witness_root.is_empty()
                || witness.availability_root.is_empty()
                || witness.sampling_seed_root.is_empty()
                || witness.prover_id.is_empty()
            {
                return Err("private recursive settlement witness has empty field".to_string());
            }
            if witness.expires_at_height <= witness.opened_at_height || witness.byte_size == 0 {
                return Err("private recursive settlement witness window is invalid".to_string());
            }
        }
        Ok(())
    }

    fn validate_sponsorships(&self) -> PrivateContractRecursiveProofSettlementResult<()> {
        for sponsorship in self.sponsorships.values() {
            if !self.call_batches.contains_key(&sponsorship.batch_id) {
                return Err(
                    "private recursive settlement sponsorship references missing batch".to_string(),
                );
            }
            if sponsorship.sponsor_commitment.is_empty()
                || sponsorship.fee_asset_id.is_empty()
                || sponsorship.policy_root.is_empty()
            {
                return Err("private recursive settlement sponsorship has empty field".to_string());
            }
            if sponsorship.applied_fee_units > sponsorship.reserved_fee_units
                || sponsorship.rebate_bps > PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_MAX_BPS
            {
                return Err(
                    "private recursive settlement sponsorship accounting is invalid".to_string(),
                );
            }
        }
        Ok(())
    }

    fn validate_state_diffs(&self) -> PrivateContractRecursiveProofSettlementResult<()> {
        for diff in self.state_diffs.values() {
            if !self.call_batches.contains_key(&diff.batch_id) {
                return Err(
                    "private recursive settlement state diff references missing batch".to_string(),
                );
            }
            if diff.pre_state_root.is_empty()
                || diff.post_state_root.is_empty()
                || diff.read_set_root.is_empty()
                || diff.write_set_root.is_empty()
                || diff.nullifier_delta_root.is_empty()
                || diff.note_delta_root.is_empty()
                || diff.event_root.is_empty()
                || diff.diff_proof_root.is_empty()
            {
                return Err("private recursive settlement state diff has empty root".to_string());
            }
        }
        Ok(())
    }

    fn validate_jobs(&self) -> PrivateContractRecursiveProofSettlementResult<()> {
        for job in self.proof_jobs.values() {
            if !self.call_batches.contains_key(&job.batch_id)
                || !self.witness_commitments.contains_key(&job.witness_id)
                || !self.sponsorships.contains_key(&job.sponsorship_id)
                || !self.state_diffs.contains_key(&job.state_diff_id)
            {
                return Err(
                    "private recursive settlement job references missing object".to_string()
                );
            }
            if job.recursion_depth > self.config.max_recursion_depth {
                return Err("private recursive settlement job exceeds recursion depth".to_string());
            }
            if job.deadline_height <= job.queued_at_height {
                return Err("private recursive settlement job deadline is invalid".to_string());
            }
            if job.proof_input_root.is_empty()
                || job.proof_output_root.is_empty()
                || job.prover_commitment.is_empty()
                || job.lane_id.is_empty()
            {
                return Err("private recursive settlement job has empty root".to_string());
            }
        }
        Ok(())
    }

    fn validate_lanes(&self) -> PrivateContractRecursiveProofSettlementResult<()> {
        for lane in self.aggregation_lanes.values() {
            if lane.job_ids.len() as u64 > self.config.max_jobs_per_lane {
                return Err("private recursive settlement lane exceeds job limit".to_string());
            }
            for job_id in &lane.job_ids {
                match self.proof_jobs.get(job_id) {
                    Some(job) if job.lane_id == lane.lane_id => {}
                    Some(_) => {
                        return Err("private recursive settlement lane/job link is inconsistent"
                            .to_string())
                    }
                    None => {
                        return Err(
                            "private recursive settlement lane references missing job".to_string()
                        )
                    }
                }
            }
            if lane.aggregate_root.is_empty()
                || lane.recursive_proof_root.is_empty()
                || lane.state_diff_root.is_empty()
                || lane.fee_sponsorship_root.is_empty()
            {
                return Err("private recursive settlement lane has empty root".to_string());
            }
            if lane.sealed_at_height < lane.opened_at_height {
                return Err("private recursive settlement lane is sealed before open".to_string());
            }
        }
        Ok(())
    }

    fn validate_challenges(&self) -> PrivateContractRecursiveProofSettlementResult<()> {
        for challenge in self.challenge_windows.values() {
            if challenge.subject_root.is_empty()
                || challenge.challenger_commitment.is_empty()
                || challenge.evidence_root.is_empty()
            {
                return Err("private recursive settlement challenge has empty field".to_string());
            }
            if challenge.expires_at_height <= challenge.opened_at_height {
                return Err("private recursive settlement challenge window is invalid".to_string());
            }
        }
        Ok(())
    }

    fn validate_receipts(&self) -> PrivateContractRecursiveProofSettlementResult<()> {
        for receipt in self.settlement_receipts.values() {
            if !self.aggregation_lanes.contains_key(&receipt.lane_id) {
                return Err(
                    "private recursive settlement receipt references missing lane".to_string(),
                );
            }
            if !receipt.challenge_window_id.is_empty()
                && !self
                    .challenge_windows
                    .contains_key(&receipt.challenge_window_id)
            {
                return Err(
                    "private recursive settlement receipt references missing challenge".to_string(),
                );
            }
            if receipt.aggregate_root.is_empty()
                || receipt.settlement_tx_root.is_empty()
                || receipt.state_root_before.is_empty()
                || receipt.state_root_after.is_empty()
            {
                return Err("private recursive settlement receipt has empty root".to_string());
            }
            if receipt.finalized_at_height != 0
                && receipt.finalized_at_height < receipt.posted_at_height
            {
                return Err(
                    "private recursive settlement receipt finalized before post".to_string()
                );
            }
        }
        Ok(())
    }

    fn validate_attestations(&self) -> PrivateContractRecursiveProofSettlementResult<()> {
        let mut quorum_counts = BTreeMap::<String, u64>::new();
        for attestation in self.pq_attestations.values() {
            if !self
                .aggregation_lanes
                .contains_key(&attestation.aggregation_lane_id)
                || !self.proof_jobs.contains_key(&attestation.job_id)
            {
                return Err(
                    "private recursive settlement attestation references missing object"
                        .to_string(),
                );
            }
            if attestation.signer_id.is_empty()
                || attestation.signer_key_root.is_empty()
                || attestation.subject_root.is_empty()
                || attestation.signature_root.is_empty()
            {
                return Err("private recursive settlement attestation has empty field".to_string());
            }
            if attestation.status == PqAttestationStatus::Quorum {
                let entry = quorum_counts
                    .entry(attestation.aggregation_lane_id.clone())
                    .or_insert(0);
                *entry = entry.saturating_add(1);
            }
        }
        for lane in self.aggregation_lanes.values() {
            if matches!(
                lane.status,
                AggregationLaneStatus::SettlementReady | AggregationLaneStatus::Settled
            ) {
                let quorum = match quorum_counts.get(&lane.lane_id) {
                    Some(count) => *count,
                    None => 0,
                };
                if quorum < self.config.min_pq_attestations {
                    return Err(
                        "private recursive settlement lane lacks pq attestation quorum".to_string(),
                    );
                }
            }
        }
        Ok(())
    }
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    private_recursive_hash(domain, &[HashPart::Json(record)])
}

pub fn devnet() -> State {
    State::devnet()
}

fn private_recursive_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    let scoped = format!(
        "PRIVATE-CONTRACT-RECURSIVE-PROOF-SETTLEMENT-{}-{}-{domain}",
        PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_PROTOCOL_VERSION, CHAIN_ID
    );
    domain_hash(&scoped, parts, 32)
}

fn root_from_records(domain: &str, records: Vec<Value>) -> String {
    merkle_root(
        &format!("PRIVATE-CONTRACT-RECURSIVE-PROOF-SETTLEMENT-{domain}"),
        &records,
    )
}

fn leaf_root(domain: &str, label: &str) -> String {
    private_recursive_hash(domain, &[HashPart::Str(label)])
}

fn map_by_id<T>(items: Vec<(String, T)>) -> BTreeMap<String, T> {
    items.into_iter().collect()
}

fn map_records<T, F>(items: &BTreeMap<String, T>, mut record_fn: F) -> BTreeMap<String, Value>
where
    F: FnMut(&T) -> Value,
{
    items
        .iter()
        .map(|(id, item)| (id.clone(), record_fn(item)))
        .collect()
}

fn devnet_call_batch(
    batch_id: &str,
    lane: ContractSettlementLane,
    call_count: u64,
    opened_at_height: u64,
    status: PrivateCallBatchStatus,
) -> PrivateContractCallBatch {
    PrivateContractCallBatch {
        batch_id: batch_id.to_string(),
        lane,
        contract_root: leaf_root("CONTRACT-ROOT", batch_id),
        call_commitment_root: leaf_root("CALL-COMMITMENT-ROOT", batch_id),
        encrypted_calldata_root: leaf_root("ENCRYPTED-CALLDATA-ROOT", batch_id),
        caller_nullifier_root: leaf_root("CALLER-NULLIFIER-ROOT", batch_id),
        read_set_root: leaf_root("READ-SET-ROOT", batch_id),
        write_set_commitment_root: leaf_root("WRITE-SET-COMMITMENT-ROOT", batch_id),
        policy_root: leaf_root("BATCH-POLICY-ROOT", lane.as_str()),
        call_count,
        batch_weight: call_count.saturating_mul(19_000),
        opened_at_height,
        sealed_at_height: opened_at_height.saturating_add(2),
        status,
    }
}

fn devnet_witness(
    witness_id: &str,
    batch_id: &str,
    prover_id: &str,
    opened_at_height: u64,
    status: WitnessCommitmentStatus,
) -> WitnessCommitment {
    WitnessCommitment {
        witness_id: witness_id.to_string(),
        batch_id: batch_id.to_string(),
        prover_id: prover_id.to_string(),
        witness_root: leaf_root("WITNESS-ROOT", witness_id),
        encrypted_witness_root: leaf_root("ENCRYPTED-WITNESS-ROOT", witness_id),
        availability_root: leaf_root("WITNESS-AVAILABILITY-ROOT", witness_id),
        sampling_seed_root: leaf_root("WITNESS-SAMPLING-SEED-ROOT", witness_id),
        opened_at_height,
        expires_at_height: opened_at_height.saturating_add(288),
        byte_size: 64_000,
        status,
    }
}

fn devnet_sponsorship(
    sponsorship_id: &str,
    batch_id: &str,
    lane: ContractSettlementLane,
    reserved_fee_units: u64,
    applied_fee_units: u64,
    opened_at_height: u64,
    status: SponsorshipStatus,
) -> FeeSponsorship {
    FeeSponsorship {
        sponsorship_id: sponsorship_id.to_string(),
        sponsor_commitment: leaf_root("SPONSOR-COMMITMENT", sponsorship_id),
        batch_id: batch_id.to_string(),
        lane,
        fee_asset_id: "nebula-fee-credit-devnet".to_string(),
        reserved_fee_units,
        applied_fee_units,
        rebate_bps: PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_DEFAULT_SPONSOR_REBATE_BPS,
        da_reserve_units: reserved_fee_units
            .saturating_mul(PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_DEFAULT_DA_RESERVE_BPS)
            / PRIVATE_CONTRACT_RECURSIVE_PROOF_SETTLEMENT_MAX_BPS,
        policy_root: leaf_root("SPONSOR-POLICY-ROOT", lane.as_str()),
        opened_at_height,
        status,
    }
}

fn devnet_state_diff(diff_id: &str, batch_id: &str, applied_at_height: u64) -> StateDiffRoot {
    StateDiffRoot {
        diff_id: diff_id.to_string(),
        batch_id: batch_id.to_string(),
        pre_state_root: leaf_root("PRE-STATE-ROOT", diff_id),
        post_state_root: leaf_root("POST-STATE-ROOT", diff_id),
        read_set_root: leaf_root("STATE-DIFF-READ-SET", diff_id),
        write_set_root: leaf_root("STATE-DIFF-WRITE-SET", diff_id),
        nullifier_delta_root: leaf_root("NULLIFIER-DELTA-ROOT", diff_id),
        note_delta_root: leaf_root("NOTE-DELTA-ROOT", diff_id),
        event_root: leaf_root("STATE-DIFF-EVENT-ROOT", diff_id),
        diff_proof_root: leaf_root("STATE-DIFF-PROOF-ROOT", diff_id),
        applied_at_height,
    }
}

fn devnet_job(
    job_id: &str,
    batch: &PrivateContractCallBatch,
    lane_id: &str,
    witness: &WitnessCommitment,
    sponsorship: &FeeSponsorship,
    diff: &StateDiffRoot,
    kind: RecursiveProofJobKind,
    status: RecursiveProofJobStatus,
    queued_at_height: u64,
) -> RecursiveProofJob {
    RecursiveProofJob {
        job_id: job_id.to_string(),
        batch_id: batch.batch_id.clone(),
        lane_id: lane_id.to_string(),
        kind,
        status,
        recursion_depth: if kind == RecursiveProofJobKind::BaseCallBatch {
            1
        } else {
            3
        },
        proof_input_root: root_from_records(
            "JOB-PROOF-INPUT",
            vec![
                batch.public_record(),
                witness.public_record(),
                sponsorship.public_record(),
                diff.public_record(),
            ],
        ),
        proof_output_root: leaf_root("JOB-PROOF-OUTPUT", job_id),
        witness_id: witness.witness_id.clone(),
        sponsorship_id: sponsorship.sponsorship_id.clone(),
        state_diff_id: diff.diff_id.clone(),
        prover_commitment: leaf_root("JOB-PROVER-COMMITMENT", job_id),
        priority: batch.lane.priority_weight(),
        queued_at_height,
        deadline_height: queued_at_height.saturating_add(72),
    }
}

fn devnet_aggregation_lane(
    lane_id: &str,
    settlement_lane: ContractSettlementLane,
    job_ids: &[String],
    status: AggregationLaneStatus,
    opened_at_height: u64,
) -> AggregationLane {
    let job_set = job_ids.iter().cloned().collect::<BTreeSet<_>>();
    let job_records = job_ids
        .iter()
        .map(|job_id| json!({ "job_id": job_id }))
        .collect::<Vec<_>>();
    let aggregate_root = root_from_records("LANE-AGGREGATE", job_records);
    AggregationLane {
        lane_id: lane_id.to_string(),
        settlement_lane,
        status,
        job_ids: job_set,
        aggregate_root: aggregate_root.clone(),
        recursive_proof_root: leaf_root("LANE-RECURSIVE-PROOF", lane_id),
        state_diff_root: leaf_root("LANE-STATE-DIFF-ROOT", lane_id),
        fee_sponsorship_root: leaf_root("LANE-FEE-SPONSORSHIP-ROOT", lane_id),
        opened_at_height,
        sealed_at_height: opened_at_height.saturating_add(4),
        priority_weight: settlement_lane.priority_weight(),
    }
}

fn devnet_attestation(
    attestation_id: &str,
    signer_id: &str,
    aggregation_lane_id: &str,
    job_id: &str,
    subject_root: &str,
    signed_at_height: u64,
    status: PqAttestationStatus,
) -> PqSignerAttestation {
    PqSignerAttestation {
        attestation_id: attestation_id.to_string(),
        signer_id: signer_id.to_string(),
        signer_key_root: leaf_root("PQ-SIGNER-KEY-ROOT", signer_id),
        subject_root: subject_root.to_string(),
        signature_root: leaf_root("PQ-SIGNATURE-ROOT", attestation_id),
        aggregation_lane_id: aggregation_lane_id.to_string(),
        job_id: job_id.to_string(),
        signed_at_height,
        status,
    }
}

fn devnet_challenge(
    challenge_id: &str,
    subject_root: &str,
    opened_at_height: u64,
    window_blocks: u64,
    status: ChallengeStatus,
) -> ChallengeWindow {
    ChallengeWindow {
        challenge_id: challenge_id.to_string(),
        subject_root: subject_root.to_string(),
        challenger_commitment: leaf_root("CHALLENGER-COMMITMENT", challenge_id),
        evidence_root: leaf_root("CHALLENGE-EVIDENCE-ROOT", challenge_id),
        bond_units: 50_000,
        opened_at_height,
        expires_at_height: opened_at_height.saturating_add(window_blocks),
        answered_at_height: 0,
        status,
    }
}

fn devnet_receipt(
    receipt_id: &str,
    lane: &AggregationLane,
    challenge_window_id: &str,
    fee_paid_units: u64,
    sponsored_units: u64,
    posted_at_height: u64,
    status: SettlementReceiptStatus,
) -> SettlementReceipt {
    SettlementReceipt {
        receipt_id: receipt_id.to_string(),
        lane_id: lane.lane_id.clone(),
        aggregate_root: lane.aggregate_root.clone(),
        settlement_tx_root: leaf_root("SETTLEMENT-TX-ROOT", receipt_id),
        state_root_before: leaf_root("RECEIPT-STATE-BEFORE", receipt_id),
        state_root_after: leaf_root("RECEIPT-STATE-AFTER", receipt_id),
        fee_paid_units,
        sponsored_units,
        posted_at_height,
        finalized_at_height: 0,
        challenge_window_id: challenge_window_id.to_string(),
        status,
    }
}
