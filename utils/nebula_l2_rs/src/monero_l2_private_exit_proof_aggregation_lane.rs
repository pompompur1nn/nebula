use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PrivateExitProofAggregationLaneResult<T> = Result<T, String>;

pub const MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-private-exit-proof-aggregation-lane-v1";
pub const PROTOCOL_VERSION: &str = MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_PROTOCOL_VERSION;
pub const MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_DEVNET_NETWORK: &str = "monero-devnet";
pub const MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_DEVNET_COMMITTEE_ID: &str =
    "monero-l2-private-exit-proof-aggregation-devnet-committee";
pub const MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_DEVNET_HEIGHT: u64 = 72_000;
pub const MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_EXIT_PROOF_SCHEME: &str =
    "monero-l2-private-exit-proof-roots-only-v1";
pub const MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_PQ_ATTESTATION_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-private-exit-committee-v1";
pub const MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_RECURSION_SCHEME: &str =
    "recursive-private-exit-aggregation-v1";
pub const MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_CHALLENGE_SCHEME: &str =
    "private-exit-fraud-challenge-window-v1";
pub const MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_RECEIPT_SCHEME: &str =
    "roots-only-private-exit-settlement-receipt-v1";
pub const MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 144;
pub const MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_DEFAULT_SETTLEMENT_DELAY_BLOCKS: u64 = 12;
pub const MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_DEFAULT_MAX_BATCH_SIZE: usize = 256;
pub const MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_DEFAULT_MAX_RECURSION_DEPTH: u64 = 16;
pub const MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 1024;
pub const MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_DEFAULT_MIN_COMMITTEE_WEIGHT: u64 = 67;
pub const MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_DEFAULT_COMMITTEE_QUORUM_BPS: u64 = 6700;
pub const MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_DEFAULT_MAX_FEE_MICRO_UNITS: u64 = 2200;
pub const MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_MAX_BPS: u64 = 10_000;
pub const MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_MAX_PROOFS: usize = 262_144;
pub const MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_MAX_BATCHES: usize = 65_536;
pub const MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_MAX_CHALLENGES: usize = 262_144;
pub const MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_MAX_RECEIPTS: usize = 262_144;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitProofStatus {
    Submitted,
    Batched,
    Challenged,
    Settled,
    Rejected,
}

impl ExitProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Batched => "batched",
            Self::Challenged => "challenged",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Built,
    ChallengeOpen,
    Challenged,
    SettlementReady,
    Settled,
    Rejected,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::ChallengeOpen => "challenge_open",
            Self::Challenged => "challenged",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    InvalidExitProof,
    ReplayNullifier,
    WeakPrivacySet,
    WeakPqQuorum,
    InvalidRecursiveAggregate,
    FeeSponsorMismatch,
    SettlementRootMismatch,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidExitProof => "invalid_exit_proof",
            Self::ReplayNullifier => "replay_nullifier",
            Self::WeakPrivacySet => "weak_privacy_set",
            Self::WeakPqQuorum => "weak_pq_quorum",
            Self::InvalidRecursiveAggregate => "invalid_recursive_aggregate",
            Self::FeeSponsorMismatch => "fee_sponsor_mismatch",
            Self::SettlementRootMismatch => "settlement_root_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    Sustained,
    Rejected,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sustained => "sustained",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    ProofSubmitted,
    BatchBuilt,
    ChallengeOpened,
    ChallengeResolved,
    SettlementReady,
    Settled,
    Rejected,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProofSubmitted => "proof_submitted",
            Self::BatchBuilt => "batch_built",
            Self::ChallengeOpened => "challenge_opened",
            Self::ChallengeResolved => "challenge_resolved",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub monero_network: String,
    pub l2_network: String,
    pub asset_id: String,
    pub committee_id: String,
    pub challenge_window_blocks: u64,
    pub settlement_delay_blocks: u64,
    pub max_batch_size: usize,
    pub max_recursion_depth: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub min_committee_weight: u64,
    pub committee_quorum_bps: u64,
    pub max_fee_micro_units: u64,
    pub exit_proof_scheme: String,
    pub pq_attestation_scheme: String,
    pub recursion_scheme: String,
    pub challenge_scheme: String,
    pub receipt_scheme: String,
    pub roots_only: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_SCHEMA_VERSION,
            monero_network: MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_DEVNET_NETWORK
                .to_string(),
            l2_network: MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_DEVNET_L2_NETWORK.to_string(),
            asset_id: MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_DEVNET_ASSET_ID.to_string(),
            committee_id: MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_DEVNET_COMMITTEE_ID
                .to_string(),
            challenge_window_blocks:
                MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            settlement_delay_blocks:
                MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_DEFAULT_SETTLEMENT_DELAY_BLOCKS,
            max_batch_size: MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_DEFAULT_MAX_BATCH_SIZE,
            max_recursion_depth:
                MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_DEFAULT_MAX_RECURSION_DEPTH,
            min_privacy_set_size:
                MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_DEFAULT_MIN_PQ_SECURITY_BITS,
            min_committee_weight:
                MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_DEFAULT_MIN_COMMITTEE_WEIGHT,
            committee_quorum_bps:
                MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_DEFAULT_COMMITTEE_QUORUM_BPS,
            max_fee_micro_units:
                MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_DEFAULT_MAX_FEE_MICRO_UNITS,
            exit_proof_scheme: MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_EXIT_PROOF_SCHEME
                .to_string(),
            pq_attestation_scheme:
                MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_PQ_ATTESTATION_SCHEME.to_string(),
            recursion_scheme: MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_RECURSION_SCHEME
                .to_string(),
            challenge_scheme: MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_CHALLENGE_SCHEME
                .to_string(),
            receipt_scheme: MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_RECEIPT_SCHEME
                .to_string(),
            roots_only: true,
        }
    }

    pub fn validate(&self) -> MoneroL2PrivateExitProofAggregationLaneResult<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("unsupported private exit aggregation protocol version".to_string());
        }
        if self.schema_version != MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_SCHEMA_VERSION {
            return Err("unsupported private exit aggregation schema version".to_string());
        }
        if !self.roots_only {
            return Err("private exit aggregation lane must remain roots-only".to_string());
        }
        if self.challenge_window_blocks == 0
            || self.settlement_delay_blocks == 0
            || self.max_batch_size == 0
            || self.max_recursion_depth == 0
            || self.min_privacy_set_size == 0
            || self.min_pq_security_bits == 0
            || self.min_committee_weight == 0
            || self.max_fee_micro_units == 0
        {
            return Err(
                "private exit aggregation numeric config values must be positive".to_string(),
            );
        }
        if self.committee_quorum_bps == 0
            || self.committee_quorum_bps > MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_MAX_BPS
        {
            return Err("committee quorum bps is out of range".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": CHAIN_ID,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "asset_id": self.asset_id,
            "committee_id": self.committee_id,
            "challenge_window_blocks": self.challenge_window_blocks,
            "settlement_delay_blocks": self.settlement_delay_blocks,
            "max_batch_size": self.max_batch_size,
            "max_recursion_depth": self.max_recursion_depth,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_committee_weight": self.min_committee_weight,
            "committee_quorum_bps": self.committee_quorum_bps,
            "max_fee_micro_units": self.max_fee_micro_units,
            "exit_proof_scheme": self.exit_proof_scheme,
            "pq_attestation_scheme": self.pq_attestation_scheme,
            "recursion_scheme": self.recursion_scheme,
            "challenge_scheme": self.challenge_scheme,
            "receipt_scheme": self.receipt_scheme,
            "roots_only": self.roots_only,
        })
    }

    pub fn root(&self) -> String {
        lane_root(
            "MONERO-L2-PRIVATE-EXIT-PROOF-AGGREGATION-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub next_proof_sequence: u64,
    pub next_batch_sequence: u64,
    pub next_challenge_sequence: u64,
    pub next_receipt_sequence: u64,
    pub proofs_submitted: u64,
    pub proofs_batched: u64,
    pub batches_built: u64,
    pub batches_settled: u64,
    pub challenges_opened: u64,
    pub challenges_sustained: u64,
    pub replay_nullifiers_rejected: u64,
    pub receipts_issued: u64,
    pub sponsored_fee_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "next_proof_sequence": self.next_proof_sequence,
            "next_batch_sequence": self.next_batch_sequence,
            "next_challenge_sequence": self.next_challenge_sequence,
            "next_receipt_sequence": self.next_receipt_sequence,
            "proofs_submitted": self.proofs_submitted,
            "proofs_batched": self.proofs_batched,
            "batches_built": self.batches_built,
            "batches_settled": self.batches_settled,
            "challenges_opened": self.challenges_opened,
            "challenges_sustained": self.challenges_sustained,
            "replay_nullifiers_rejected": self.replay_nullifiers_rejected,
            "receipts_issued": self.receipts_issued,
            "sponsored_fee_micro_units": self.sponsored_fee_micro_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitProofSubmission {
    pub watcher_id: String,
    pub monero_height: u64,
    pub l2_height: u64,
    pub exit_intent_root: String,
    pub exit_proof_root: String,
    pub spend_nullifier: String,
    pub replay_nullifier: String,
    pub output_commitment_root: String,
    pub destination_commitment_root: String,
    pub amount_commitment_root: String,
    pub fee_commitment_root: String,
    pub sponsor_commitment_root: Option<String>,
    pub pq_witness_root: String,
    pub witness_availability_root: String,
    pub privacy_set_size: u64,
    pub max_fee_micro_units: u64,
    pub submitted_at_height: u64,
    pub submission_nonce: String,
}

impl ExitProofSubmission {
    pub fn validate(&self, config: &Config) -> MoneroL2PrivateExitProofAggregationLaneResult<()> {
        if self.watcher_id.trim().is_empty() {
            return Err("watcher_id is required".to_string());
        }
        if self.submission_nonce.trim().is_empty() {
            return Err("submission_nonce is required".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("exit proof privacy set is below configured floor".to_string());
        }
        if self.max_fee_micro_units > config.max_fee_micro_units {
            return Err("exit proof fee exceeds low-fee policy".to_string());
        }
        validate_root("exit_intent_root", &self.exit_intent_root)?;
        validate_root("exit_proof_root", &self.exit_proof_root)?;
        validate_root("spend_nullifier", &self.spend_nullifier)?;
        validate_root("replay_nullifier", &self.replay_nullifier)?;
        validate_root("output_commitment_root", &self.output_commitment_root)?;
        validate_root(
            "destination_commitment_root",
            &self.destination_commitment_root,
        )?;
        validate_root("amount_commitment_root", &self.amount_commitment_root)?;
        validate_root("fee_commitment_root", &self.fee_commitment_root)?;
        if let Some(root) = self.sponsor_commitment_root.as_deref() {
            validate_root("sponsor_commitment_root", root)?;
        }
        validate_root("pq_witness_root", &self.pq_witness_root)?;
        validate_root("witness_availability_root", &self.witness_availability_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "watcher_id": self.watcher_id,
            "monero_height": self.monero_height,
            "l2_height": self.l2_height,
            "exit_intent_root": self.exit_intent_root,
            "exit_proof_root": self.exit_proof_root,
            "spend_nullifier": self.spend_nullifier,
            "replay_nullifier": self.replay_nullifier,
            "output_commitment_root": self.output_commitment_root,
            "destination_commitment_root": self.destination_commitment_root,
            "amount_commitment_root": self.amount_commitment_root,
            "fee_commitment_root": self.fee_commitment_root,
            "sponsor_commitment_root": self.sponsor_commitment_root,
            "pq_witness_root": self.pq_witness_root,
            "witness_availability_root": self.witness_availability_root,
            "privacy_set_size": self.privacy_set_size,
            "max_fee_micro_units": self.max_fee_micro_units,
            "submitted_at_height": self.submitted_at_height,
            "submission_nonce": self.submission_nonce,
        })
    }

    pub fn root(&self) -> String {
        lane_root(
            "MONERO-L2-PRIVATE-EXIT-PROOF-SUBMISSION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCommitteeAttestation {
    pub committee_id: String,
    pub committee_epoch: u64,
    pub signer_count: u64,
    pub committee_weight: u64,
    pub quorum_bps: u64,
    pub pq_security_bits: u16,
    pub attestation_root: String,
    pub signature_root: String,
    pub signer_set_root: String,
}

impl PqCommitteeAttestation {
    pub fn validate(&self, config: &Config) -> MoneroL2PrivateExitProofAggregationLaneResult<()> {
        if self.committee_id != config.committee_id {
            return Err("pq committee id mismatch".to_string());
        }
        if self.committee_weight < config.min_committee_weight {
            return Err("pq committee weight is below configured floor".to_string());
        }
        if self.quorum_bps < config.committee_quorum_bps {
            return Err("pq committee quorum is below configured floor".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("pq security bits are below configured floor".to_string());
        }
        if self.signer_count == 0 {
            return Err("pq attestation signer count must be nonzero".to_string());
        }
        validate_root("attestation_root", &self.attestation_root)?;
        validate_root("signature_root", &self.signature_root)?;
        validate_root("signer_set_root", &self.signer_set_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "committee_id": self.committee_id,
            "committee_epoch": self.committee_epoch,
            "signer_count": self.signer_count,
            "committee_weight": self.committee_weight,
            "quorum_bps": self.quorum_bps,
            "pq_security_bits": self.pq_security_bits,
            "attestation_root": self.attestation_root,
            "signature_root": self.signature_root,
            "signer_set_root": self.signer_set_root,
        })
    }

    pub fn root(&self) -> String {
        lane_root(
            "MONERO-L2-PRIVATE-EXIT-PQ-COMMITTEE-ATTESTATION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitProof {
    pub proof_id: String,
    pub sequence: u64,
    pub status: ExitProofStatus,
    pub submission: ExitProofSubmission,
    pub proof_root: String,
    pub receipt_root: String,
    pub batch_id: Option<String>,
}

impl ExitProof {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "sequence": self.sequence,
            "status": self.status.as_str(),
            "submission": self.submission.public_record(),
            "proof_root": self.proof_root,
            "receipt_root": self.receipt_root,
            "batch_id": self.batch_id,
        })
    }

    pub fn root(&self) -> String {
        lane_root("MONERO-L2-PRIVATE-EXIT-PROOF", &self.public_record())
    }

    pub fn roots_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "status": self.status.as_str(),
            "exit_proof_root": self.submission.exit_proof_root,
            "spend_nullifier": self.submission.spend_nullifier,
            "replay_nullifier": self.submission.replay_nullifier,
            "fee_commitment_root": self.submission.fee_commitment_root,
            "sponsor_commitment_root": self.submission.sponsor_commitment_root,
            "proof_root": self.proof_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursiveAggregationBatch {
    pub batch_id: String,
    pub sequence: u64,
    pub status: BatchStatus,
    pub proof_count: u64,
    pub opened_at_height: u64,
    pub challenge_deadline_height: u64,
    pub settlement_ready_height: u64,
    pub min_privacy_set_size: u64,
    pub max_recursion_depth: u64,
    pub total_fee_micro_units: u64,
    pub sponsored_fee_micro_units: u64,
    pub proof_root: String,
    pub replay_nullifier_root: String,
    pub spend_nullifier_root: String,
    pub fee_commitment_root: String,
    pub sponsor_commitment_root: String,
    pub pq_attestation_root: String,
    pub recursive_aggregate_root: String,
    pub settlement_claim_root: String,
    pub previous_batch_root: String,
    pub challenge_root: String,
    pub receipt_root: String,
}

impl RecursiveAggregationBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "sequence": self.sequence,
            "status": self.status.as_str(),
            "proof_count": self.proof_count,
            "opened_at_height": self.opened_at_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "settlement_ready_height": self.settlement_ready_height,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_recursion_depth": self.max_recursion_depth,
            "total_fee_micro_units": self.total_fee_micro_units,
            "sponsored_fee_micro_units": self.sponsored_fee_micro_units,
            "proof_root": self.proof_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "spend_nullifier_root": self.spend_nullifier_root,
            "fee_commitment_root": self.fee_commitment_root,
            "sponsor_commitment_root": self.sponsor_commitment_root,
            "pq_attestation_root": self.pq_attestation_root,
            "recursive_aggregate_root": self.recursive_aggregate_root,
            "settlement_claim_root": self.settlement_claim_root,
            "previous_batch_root": self.previous_batch_root,
            "challenge_root": self.challenge_root,
            "receipt_root": self.receipt_root,
        })
    }

    pub fn root(&self) -> String {
        lane_root(
            "MONERO-L2-PRIVATE-EXIT-RECURSIVE-AGGREGATION-BATCH",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FraudChallenge {
    pub challenge_id: String,
    pub sequence: u64,
    pub batch_id: String,
    pub kind: ChallengeKind,
    pub status: ChallengeStatus,
    pub challenger_id: String,
    pub opened_at_height: u64,
    pub deadline_height: u64,
    pub allegation_root: String,
    pub counter_proof_root: String,
    pub pq_signature_root: String,
    pub resolution_root: String,
}

impl FraudChallenge {
    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "sequence": self.sequence,
            "batch_id": self.batch_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "challenger_id": self.challenger_id,
            "opened_at_height": self.opened_at_height,
            "deadline_height": self.deadline_height,
            "allegation_root": self.allegation_root,
            "counter_proof_root": self.counter_proof_root,
            "pq_signature_root": self.pq_signature_root,
            "resolution_root": self.resolution_root,
        })
    }

    pub fn root(&self) -> String {
        lane_root(
            "MONERO-L2-PRIVATE-EXIT-FRAUD-CHALLENGE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeResolution {
    pub challenge_id: String,
    pub batch_id: String,
    pub sustained: bool,
    pub resolver_id: String,
    pub resolved_at_height: u64,
    pub resolution_root: String,
    pub pq_signature_root: String,
    pub public_note_root: String,
}

impl ChallengeResolution {
    pub fn validate(&self) -> MoneroL2PrivateExitProofAggregationLaneResult<()> {
        if self.challenge_id.trim().is_empty() || self.resolver_id.trim().is_empty() {
            return Err("challenge resolution identifiers are required".to_string());
        }
        validate_root("resolution_root", &self.resolution_root)?;
        validate_root("pq_signature_root", &self.pq_signature_root)?;
        validate_root("public_note_root", &self.public_note_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "batch_id": self.batch_id,
            "sustained": self.sustained,
            "resolver_id": self.resolver_id,
            "resolved_at_height": self.resolved_at_height,
            "resolution_root": self.resolution_root,
            "pq_signature_root": self.pq_signature_root,
            "public_note_root": self.public_note_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub sequence: u64,
    pub kind: ReceiptKind,
    pub batch_id: Option<String>,
    pub proof_id: Option<String>,
    pub challenge_id: Option<String>,
    pub actor_id: String,
    pub issued_at_height: u64,
    pub settlement_root: String,
    pub pq_attestation_root: String,
    pub event_root: String,
    pub receipt_root: String,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "sequence": self.sequence,
            "kind": self.kind.as_str(),
            "batch_id": self.batch_id,
            "proof_id": self.proof_id,
            "challenge_id": self.challenge_id,
            "actor_id": self.actor_id,
            "issued_at_height": self.issued_at_height,
            "settlement_root": self.settlement_root,
            "pq_attestation_root": self.pq_attestation_root,
            "event_root": self.event_root,
            "receipt_root": self.receipt_root,
        })
    }

    pub fn root(&self) -> String {
        lane_root(
            "MONERO-L2-PRIVATE-EXIT-SETTLEMENT-RECEIPT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub proof_root: String,
    pub batch_root: String,
    pub challenge_root: String,
    pub receipt_root: String,
    pub replay_nullifier_root: String,
    pub spend_nullifier_root: String,
    pub sponsor_commitment_root: String,
    pub pq_attestation_root: String,
    pub settlement_claim_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_root": self.proof_root,
            "batch_root": self.batch_root,
            "challenge_root": self.challenge_root,
            "receipt_root": self.receipt_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "spend_nullifier_root": self.spend_nullifier_root,
            "sponsor_commitment_root": self.sponsor_commitment_root,
            "pq_attestation_root": self.pq_attestation_root,
            "settlement_claim_root": self.settlement_claim_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub proofs: BTreeMap<String, ExitProof>,
    pub batches: BTreeMap<String, RecursiveAggregationBatch>,
    pub challenges: BTreeMap<String, FraudChallenge>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub proof_ids_by_height: BTreeMap<u64, BTreeSet<String>>,
    pub challenges_by_batch: BTreeMap<String, BTreeSet<String>>,
    pub spent_replay_nullifiers: BTreeSet<String>,
    pub settled_batches: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            counters: Counters::default(),
            proofs: BTreeMap::new(),
            batches: BTreeMap::new(),
            challenges: BTreeMap::new(),
            receipts: BTreeMap::new(),
            proof_ids_by_height: BTreeMap::new(),
            challenges_by_batch: BTreeMap::new(),
            spent_replay_nullifiers: BTreeSet::new(),
            settled_batches: BTreeSet::new(),
        }
    }

    pub fn submit_exit_proof(
        &mut self,
        submission: ExitProofSubmission,
    ) -> MoneroL2PrivateExitProofAggregationLaneResult<ExitProof> {
        self.config.validate()?;
        if self.proofs.len() >= MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_MAX_PROOFS {
            return Err("private exit proof capacity reached".to_string());
        }
        submission.validate(&self.config)?;
        if self
            .spent_replay_nullifiers
            .contains(&submission.replay_nullifier)
            || self
                .proofs
                .values()
                .any(|proof| proof.submission.replay_nullifier == submission.replay_nullifier)
        {
            self.counters.replay_nullifiers_rejected =
                self.counters.replay_nullifiers_rejected.saturating_add(1);
            return Err("replay nullifier already observed".to_string());
        }

        let sequence = self.counters.next_proof_sequence;
        self.counters.next_proof_sequence = self.counters.next_proof_sequence.saturating_add(1);
        let proof_root = submission.root();
        let proof_id = proof_id(sequence, &submission, &proof_root);
        let receipt = self.issue_receipt(
            Some(&proof_id),
            None,
            None,
            ReceiptKind::ProofSubmitted,
            &submission.watcher_id,
            submission.submitted_at_height,
            &proof_root,
            &empty_root("MONERO-L2-PRIVATE-EXIT-SUBMIT-PQ"),
        )?;
        let proof = ExitProof {
            proof_id: proof_id.clone(),
            sequence,
            status: ExitProofStatus::Submitted,
            submission: submission.clone(),
            proof_root,
            receipt_root: receipt.root(),
            batch_id: None,
        };
        self.proof_ids_by_height
            .entry(submission.l2_height)
            .or_default()
            .insert(proof_id.clone());
        self.counters.proofs_submitted = self.counters.proofs_submitted.saturating_add(1);
        self.proofs.insert(proof_id, proof.clone());
        Ok(proof)
    }

    pub fn build_recursive_batch(
        &mut self,
        proof_ids: &[String],
        pq_attestation: PqCommitteeAttestation,
        opened_at_height: u64,
    ) -> MoneroL2PrivateExitProofAggregationLaneResult<RecursiveAggregationBatch> {
        self.config.validate()?;
        pq_attestation.validate(&self.config)?;
        if self.batches.len() >= MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_MAX_BATCHES {
            return Err("private exit aggregation batch capacity reached".to_string());
        }
        if proof_ids.is_empty() || proof_ids.len() > self.config.max_batch_size {
            return Err("private exit aggregation batch size is out of range".to_string());
        }
        let mut seen = BTreeSet::new();
        let mut proofs = Vec::with_capacity(proof_ids.len());
        for proof_id in proof_ids {
            if !seen.insert(proof_id.clone()) {
                return Err("recursive batch contains duplicate proof ids".to_string());
            }
            let proof = self
                .proofs
                .get(proof_id)
                .ok_or_else(|| format!("unknown exit proof {proof_id}"))?;
            if proof.status != ExitProofStatus::Submitted {
                return Err(format!("exit proof {proof_id} is not batchable"));
            }
            proofs.push(proof.clone());
        }

        let min_privacy_set_size = proofs
            .iter()
            .map(|proof| proof.submission.privacy_set_size)
            .min()
            .unwrap_or_default();
        if min_privacy_set_size < self.config.min_privacy_set_size {
            return Err("recursive batch privacy set is below configured floor".to_string());
        }
        let total_fee_micro_units = proofs
            .iter()
            .map(|proof| proof.submission.max_fee_micro_units)
            .sum::<u64>();
        let sponsored_fee_micro_units = proofs
            .iter()
            .filter(|proof| proof.submission.sponsor_commitment_root.is_some())
            .map(|proof| proof.submission.max_fee_micro_units)
            .sum::<u64>();
        let max_recursion_depth = (proofs.len() as u64).next_power_of_two().trailing_zeros() as u64;
        if max_recursion_depth > self.config.max_recursion_depth {
            return Err("recursive batch depth exceeds configured maximum".to_string());
        }

        let sequence = self.counters.next_batch_sequence;
        self.counters.next_batch_sequence = self.counters.next_batch_sequence.saturating_add(1);
        let previous_batch_root = self
            .batches
            .values()
            .last()
            .map(RecursiveAggregationBatch::root)
            .unwrap_or_else(|| empty_root("MONERO-L2-PRIVATE-EXIT-PREVIOUS-BATCH"));
        let proof_root = merkle_root(
            "MONERO-L2-PRIVATE-EXIT-BATCH-PROOFS",
            &proofs
                .iter()
                .map(ExitProof::roots_record)
                .collect::<Vec<_>>(),
        );
        let replay_nullifier_root = merkle_from_strings(
            "MONERO-L2-PRIVATE-EXIT-BATCH-REPLAY-NULLIFIERS",
            proofs
                .iter()
                .map(|proof| proof.submission.replay_nullifier.as_str()),
        );
        let spend_nullifier_root = merkle_from_strings(
            "MONERO-L2-PRIVATE-EXIT-BATCH-SPEND-NULLIFIERS",
            proofs
                .iter()
                .map(|proof| proof.submission.spend_nullifier.as_str()),
        );
        let fee_commitment_root = merkle_from_strings(
            "MONERO-L2-PRIVATE-EXIT-BATCH-FEES",
            proofs
                .iter()
                .map(|proof| proof.submission.fee_commitment_root.as_str()),
        );
        let sponsor_commitment_root = merkle_from_strings(
            "MONERO-L2-PRIVATE-EXIT-BATCH-SPONSORS",
            proofs
                .iter()
                .filter_map(|proof| proof.submission.sponsor_commitment_root.as_deref()),
        );
        let pq_attestation_root = pq_attestation.root();
        let recursive_aggregate_root = lane_hash(
            "RECURSIVE-AGGREGATE-ROOT",
            &[
                HashPart::Int(sequence as i128),
                HashPart::Str(&proof_root),
                HashPart::Str(&replay_nullifier_root),
                HashPart::Str(&pq_attestation_root),
                HashPart::Int(max_recursion_depth as i128),
            ],
        );
        let settlement_ready_height = opened_at_height
            .saturating_add(self.config.challenge_window_blocks)
            .saturating_add(self.config.settlement_delay_blocks);
        let challenge_deadline_height =
            opened_at_height.saturating_add(self.config.challenge_window_blocks);
        let settlement_claim_root = lane_hash(
            "SETTLEMENT-CLAIM-ROOT",
            &[
                HashPart::Str(&recursive_aggregate_root),
                HashPart::Str(&sponsor_commitment_root),
                HashPart::Int(settlement_ready_height as i128),
            ],
        );
        let batch_seed = json!({
            "sequence": sequence,
            "proof_root": proof_root,
            "replay_nullifier_root": replay_nullifier_root,
            "pq_attestation_root": pq_attestation_root,
            "settlement_claim_root": settlement_claim_root,
            "previous_batch_root": previous_batch_root,
        });
        let batch_id = batch_id(
            sequence,
            &lane_root("MONERO-L2-PRIVATE-EXIT-BATCH-SEED", &batch_seed),
        );
        let batch = RecursiveAggregationBatch {
            batch_id: batch_id.clone(),
            sequence,
            status: BatchStatus::ChallengeOpen,
            proof_count: proofs.len() as u64,
            opened_at_height,
            challenge_deadline_height,
            settlement_ready_height,
            min_privacy_set_size,
            max_recursion_depth,
            total_fee_micro_units,
            sponsored_fee_micro_units,
            proof_root,
            replay_nullifier_root,
            spend_nullifier_root,
            fee_commitment_root,
            sponsor_commitment_root,
            pq_attestation_root,
            recursive_aggregate_root,
            settlement_claim_root,
            previous_batch_root,
            challenge_root: empty_root("MONERO-L2-PRIVATE-EXIT-BATCH-CHALLENGES"),
            receipt_root: empty_root("MONERO-L2-PRIVATE-EXIT-BATCH-RECEIPTS"),
        };
        let receipt = self.issue_receipt(
            None,
            Some(&batch_id),
            None,
            ReceiptKind::BatchBuilt,
            &pq_attestation.committee_id,
            opened_at_height,
            &batch.root(),
            &batch.pq_attestation_root,
        )?;
        let mut stored_batch = batch.clone();
        stored_batch.receipt_root = receipt.root();
        for proof in proofs {
            if let Some(stored) = self.proofs.get_mut(&proof.proof_id) {
                stored.status = ExitProofStatus::Batched;
                stored.batch_id = Some(batch_id.clone());
            }
        }
        self.counters.proofs_batched = self
            .counters
            .proofs_batched
            .saturating_add(stored_batch.proof_count);
        self.counters.batches_built = self.counters.batches_built.saturating_add(1);
        self.counters.sponsored_fee_micro_units = self
            .counters
            .sponsored_fee_micro_units
            .saturating_add(stored_batch.sponsored_fee_micro_units);
        self.batches.insert(batch_id, stored_batch.clone());
        Ok(stored_batch)
    }

    pub fn open_fraud_challenge(
        &mut self,
        batch_id: &str,
        kind: ChallengeKind,
        challenger_id: &str,
        opened_at_height: u64,
        allegation_root: &str,
        counter_proof_root: &str,
        pq_signature_root: &str,
    ) -> MoneroL2PrivateExitProofAggregationLaneResult<FraudChallenge> {
        if self.challenges.len() >= MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_MAX_CHALLENGES {
            return Err("private exit fraud challenge capacity reached".to_string());
        }
        if challenger_id.trim().is_empty() {
            return Err("challenger_id is required".to_string());
        }
        validate_root("allegation_root", allegation_root)?;
        validate_root("counter_proof_root", counter_proof_root)?;
        validate_root("pq_signature_root", pq_signature_root)?;
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| "private exit batch not found".to_string())?;
        if opened_at_height > batch.challenge_deadline_height {
            return Err("private exit fraud challenge window has closed".to_string());
        }
        let sequence = self.counters.next_challenge_sequence;
        self.counters.next_challenge_sequence =
            self.counters.next_challenge_sequence.saturating_add(1);
        let challenge_id = challenge_id(
            sequence,
            batch_id,
            kind,
            challenger_id,
            allegation_root,
            pq_signature_root,
        );
        let challenge = FraudChallenge {
            challenge_id: challenge_id.clone(),
            sequence,
            batch_id: batch_id.to_string(),
            kind,
            status: ChallengeStatus::Open,
            challenger_id: challenger_id.to_string(),
            opened_at_height,
            deadline_height: batch.challenge_deadline_height,
            allegation_root: allegation_root.to_string(),
            counter_proof_root: counter_proof_root.to_string(),
            pq_signature_root: pq_signature_root.to_string(),
            resolution_root: empty_root("MONERO-L2-PRIVATE-EXIT-CHALLENGE-RESOLUTION"),
        };
        batch.status = BatchStatus::Challenged;
        self.challenges_by_batch
            .entry(batch_id.to_string())
            .or_default()
            .insert(challenge_id.clone());
        self.challenges
            .insert(challenge_id.clone(), challenge.clone());
        self.refresh_batch_challenge_root(batch_id)?;
        self.issue_receipt(
            None,
            Some(batch_id),
            Some(&challenge_id),
            ReceiptKind::ChallengeOpened,
            challenger_id,
            opened_at_height,
            &challenge.root(),
            pq_signature_root,
        )?;
        self.counters.challenges_opened = self.counters.challenges_opened.saturating_add(1);
        Ok(challenge)
    }

    pub fn resolve_challenge(
        &mut self,
        resolution: ChallengeResolution,
    ) -> MoneroL2PrivateExitProofAggregationLaneResult<ChallengeResolution> {
        resolution.validate()?;
        let challenge = self
            .challenges
            .get_mut(&resolution.challenge_id)
            .ok_or_else(|| "private exit fraud challenge not found".to_string())?;
        if challenge.status != ChallengeStatus::Open {
            return Err("private exit fraud challenge is not open".to_string());
        }
        if challenge.batch_id != resolution.batch_id {
            return Err("challenge resolution batch mismatch".to_string());
        }
        challenge.status = if resolution.sustained {
            ChallengeStatus::Sustained
        } else {
            ChallengeStatus::Rejected
        };
        challenge.resolution_root = resolution.resolution_root.clone();
        if resolution.sustained {
            self.counters.challenges_sustained =
                self.counters.challenges_sustained.saturating_add(1);
            if let Some(batch) = self.batches.get_mut(&resolution.batch_id) {
                batch.status = BatchStatus::Rejected;
            }
        }
        self.refresh_batch_challenge_root(&resolution.batch_id)?;
        self.issue_receipt(
            None,
            Some(&resolution.batch_id),
            Some(&resolution.challenge_id),
            ReceiptKind::ChallengeResolved,
            &resolution.resolver_id,
            resolution.resolved_at_height,
            &lane_root(
                "MONERO-L2-PRIVATE-EXIT-CHALLENGE-RESOLUTION",
                &resolution.public_record(),
            ),
            &resolution.pq_signature_root,
        )?;
        Ok(resolution)
    }

    pub fn settle_batch(
        &mut self,
        batch_id: &str,
        settler_id: &str,
        settled_at_height: u64,
        settlement_root: &str,
        pq_attestation_root: &str,
    ) -> MoneroL2PrivateExitProofAggregationLaneResult<SettlementReceipt> {
        if settler_id.trim().is_empty() {
            return Err("settler_id is required".to_string());
        }
        validate_root("settlement_root", settlement_root)?;
        validate_root("pq_attestation_root", pq_attestation_root)?;
        if self.settled_batches.contains(batch_id) {
            return Err("private exit batch already settled".to_string());
        }
        self.expire_challenge_windows(settled_at_height)?;
        {
            let batch = self
                .batches
                .get(batch_id)
                .ok_or_else(|| "private exit batch not found".to_string())?;
            if batch.status == BatchStatus::Rejected {
                return Err("private exit batch has been rejected".to_string());
            }
            if settled_at_height < batch.settlement_ready_height {
                return Err("private exit batch settlement height is before readiness".to_string());
            }
            if batch.pq_attestation_root != pq_attestation_root {
                return Err("private exit batch pq attestation root mismatch".to_string());
            }
        }
        let receipt = self.issue_receipt(
            None,
            Some(batch_id),
            None,
            ReceiptKind::Settled,
            settler_id,
            settled_at_height,
            settlement_root,
            pq_attestation_root,
        )?;
        if let Some(batch) = self.batches.get_mut(batch_id) {
            batch.status = BatchStatus::Settled;
            batch.receipt_root = receipt.root();
        }
        self.settled_batches.insert(batch_id.to_string());
        for proof in self
            .proofs
            .values_mut()
            .filter(|proof| proof.batch_id.as_deref() == Some(batch_id))
        {
            proof.status = ExitProofStatus::Settled;
            self.spent_replay_nullifiers
                .insert(proof.submission.replay_nullifier.clone());
        }
        self.counters.batches_settled = self.counters.batches_settled.saturating_add(1);
        Ok(receipt)
    }

    pub fn roots(&self) -> Roots {
        let proof_records = self
            .proofs
            .values()
            .map(ExitProof::public_record)
            .collect::<Vec<_>>();
        let batch_records = self
            .batches
            .values()
            .map(RecursiveAggregationBatch::public_record)
            .collect::<Vec<_>>();
        let challenge_records = self
            .challenges
            .values()
            .map(FraudChallenge::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .values()
            .map(SettlementReceipt::public_record)
            .collect::<Vec<_>>();
        Roots {
            proof_root: merkle_root("MONERO-L2-PRIVATE-EXIT-STATE-PROOFS", &proof_records),
            batch_root: merkle_root("MONERO-L2-PRIVATE-EXIT-STATE-BATCHES", &batch_records),
            challenge_root: merkle_root(
                "MONERO-L2-PRIVATE-EXIT-STATE-CHALLENGES",
                &challenge_records,
            ),
            receipt_root: merkle_root("MONERO-L2-PRIVATE-EXIT-STATE-RECEIPTS", &receipt_records),
            replay_nullifier_root: replay_nullifier_root(
                &self
                    .spent_replay_nullifiers
                    .iter()
                    .map(|root| json!(root))
                    .collect::<Vec<_>>(),
            ),
            spend_nullifier_root: merkle_from_strings(
                "MONERO-L2-PRIVATE-EXIT-STATE-SPEND-NULLIFIERS",
                self.proofs
                    .values()
                    .map(|proof| proof.submission.spend_nullifier.as_str()),
            ),
            sponsor_commitment_root: sponsor_commitment_root(
                &self
                    .proofs
                    .values()
                    .filter_map(|proof| proof.submission.sponsor_commitment_root.as_deref())
                    .map(|root| json!(root))
                    .collect::<Vec<_>>(),
            ),
            pq_attestation_root: merkle_from_strings(
                "MONERO-L2-PRIVATE-EXIT-STATE-PQ-ATTESTATIONS",
                self.batches
                    .values()
                    .map(|batch| batch.pq_attestation_root.as_str()),
            ),
            settlement_claim_root: merkle_from_strings(
                "MONERO-L2-PRIVATE-EXIT-STATE-SETTLEMENT-CLAIMS",
                self.batches
                    .values()
                    .map(|batch| batch.settlement_claim_root.as_str()),
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "privacy_boundary": "roots_only_no_plaintext_monero_addresses_no_amounts_no_view_keys",
            "config": self.config.public_record(),
            "config_root": self.config.root(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "proof_count": self.proofs.len(),
            "batch_count": self.batches.len(),
            "challenge_count": self.challenges.len(),
            "receipt_count": self.receipts.len(),
            "settled_batch_count": self.settled_batches.len(),
        })
    }

    pub fn state_root(&self) -> String {
        lane_root(
            "MONERO-L2-PRIVATE-EXIT-PROOF-AGGREGATION-STATE",
            &self.public_record(),
        )
    }

    fn expire_challenge_windows(
        &mut self,
        current_l2_height: u64,
    ) -> MoneroL2PrivateExitProofAggregationLaneResult<()> {
        for challenge in self.challenges.values_mut() {
            if challenge.status == ChallengeStatus::Open
                && current_l2_height >= challenge.deadline_height
            {
                challenge.status = ChallengeStatus::Expired;
            }
        }
        let batch_ids = self.batches.keys().cloned().collect::<Vec<_>>();
        for batch_id in batch_ids {
            let has_sustained = self
                .challenges_by_batch
                .get(&batch_id)
                .cloned()
                .unwrap_or_default()
                .iter()
                .any(|challenge_id| {
                    self.challenges
                        .get(challenge_id)
                        .map(|challenge| challenge.status == ChallengeStatus::Sustained)
                        .unwrap_or(false)
                });
            if let Some(batch) = self.batches.get_mut(&batch_id) {
                if has_sustained {
                    batch.status = BatchStatus::Rejected;
                } else if batch.status == BatchStatus::ChallengeOpen
                    && current_l2_height >= batch.settlement_ready_height
                {
                    batch.status = BatchStatus::SettlementReady;
                }
            }
            self.refresh_batch_challenge_root(&batch_id)?;
        }
        Ok(())
    }

    fn refresh_batch_challenge_root(
        &mut self,
        batch_id: &str,
    ) -> MoneroL2PrivateExitProofAggregationLaneResult<()> {
        let challenge_records = self
            .challenges_by_batch
            .get(batch_id)
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|challenge_id| self.challenges.get(challenge_id))
            .map(FraudChallenge::public_record)
            .collect::<Vec<_>>();
        let challenge_root = merkle_root(
            "MONERO-L2-PRIVATE-EXIT-BATCH-FRAUD-CHALLENGES",
            &challenge_records,
        );
        if let Some(batch) = self.batches.get_mut(batch_id) {
            batch.challenge_root = challenge_root;
            Ok(())
        } else {
            Err("private exit batch not found".to_string())
        }
    }

    fn issue_receipt(
        &mut self,
        proof_id: Option<&str>,
        batch_id: Option<&str>,
        challenge_id: Option<&str>,
        kind: ReceiptKind,
        actor_id: &str,
        issued_at_height: u64,
        event_root: &str,
        pq_attestation_root: &str,
    ) -> MoneroL2PrivateExitProofAggregationLaneResult<SettlementReceipt> {
        if self.receipts.len() >= MONERO_L2_PRIVATE_EXIT_PROOF_AGGREGATION_LANE_MAX_RECEIPTS {
            return Err("private exit receipt capacity reached".to_string());
        }
        if actor_id.trim().is_empty() {
            return Err("receipt actor_id is required".to_string());
        }
        validate_root("event_root", event_root)?;
        validate_root("pq_attestation_root", pq_attestation_root)?;
        let sequence = self.counters.next_receipt_sequence;
        self.counters.next_receipt_sequence = self.counters.next_receipt_sequence.saturating_add(1);
        let receipt_root = receipt_root(
            sequence,
            kind,
            proof_id,
            batch_id,
            challenge_id,
            actor_id,
            issued_at_height,
            event_root,
            pq_attestation_root,
        );
        let receipt_id = receipt_id(sequence, &receipt_root);
        let receipt = SettlementReceipt {
            receipt_id: receipt_id.clone(),
            sequence,
            kind,
            batch_id: batch_id.map(str::to_string),
            proof_id: proof_id.map(str::to_string),
            challenge_id: challenge_id.map(str::to_string),
            actor_id: actor_id.to_string(),
            issued_at_height,
            settlement_root: event_root.to_string(),
            pq_attestation_root: pq_attestation_root.to_string(),
            event_root: event_root.to_string(),
            receipt_root,
        };
        self.receipts.insert(receipt_id, receipt.clone());
        self.counters.receipts_issued = self.counters.receipts_issued.saturating_add(1);
        Ok(receipt)
    }
}

pub fn exit_proof_root(records: &[Value]) -> String {
    merkle_root("MONERO-L2-PRIVATE-EXIT-PROOF-ROOT", records)
}

pub fn pq_committee_attestation_root(records: &[Value]) -> String {
    merkle_root("MONERO-L2-PRIVATE-EXIT-PQ-ATTESTATION-ROOT", records)
}

pub fn recursive_aggregation_root(records: &[Value]) -> String {
    merkle_root("MONERO-L2-PRIVATE-EXIT-RECURSIVE-AGGREGATION-ROOT", records)
}

pub fn fraud_challenge_root(records: &[Value]) -> String {
    merkle_root("MONERO-L2-PRIVATE-EXIT-FRAUD-CHALLENGE-ROOT", records)
}

pub fn settlement_receipt_root(records: &[Value]) -> String {
    merkle_root("MONERO-L2-PRIVATE-EXIT-SETTLEMENT-RECEIPT-ROOT", records)
}

pub fn replay_nullifier_root(records: &[Value]) -> String {
    merkle_root("MONERO-L2-PRIVATE-EXIT-REPLAY-NULLIFIER-ROOT", records)
}

pub fn sponsor_commitment_root(records: &[Value]) -> String {
    merkle_root("MONERO-L2-PRIVATE-EXIT-SPONSOR-COMMITMENT-ROOT", records)
}

fn proof_id(sequence: u64, submission: &ExitProofSubmission, proof_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-EXIT-PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&submission.watcher_id),
            HashPart::Str(&submission.replay_nullifier),
            HashPart::Str(proof_root),
            HashPart::Str(&submission.submission_nonce),
        ],
        32,
    )
}

fn batch_id(sequence: u64, batch_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-EXIT-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(batch_root),
        ],
        32,
    )
}

fn challenge_id(
    sequence: u64,
    batch_id: &str,
    kind: ChallengeKind,
    challenger_id: &str,
    allegation_root: &str,
    pq_signature_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-EXIT-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(batch_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(challenger_id),
            HashPart::Str(allegation_root),
            HashPart::Str(pq_signature_root),
        ],
        32,
    )
}

fn receipt_id(sequence: u64, receipt_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-EXIT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(receipt_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
fn receipt_root(
    sequence: u64,
    kind: ReceiptKind,
    proof_id: Option<&str>,
    batch_id: Option<&str>,
    challenge_id: Option<&str>,
    actor_id: &str,
    issued_at_height: u64,
    event_root: &str,
    pq_attestation_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-EXIT-RECEIPT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(kind.as_str()),
            HashPart::Str(proof_id.unwrap_or("")),
            HashPart::Str(batch_id.unwrap_or("")),
            HashPart::Str(challenge_id.unwrap_or("")),
            HashPart::Str(actor_id),
            HashPart::Int(issued_at_height as i128),
            HashPart::Str(event_root),
            HashPart::Str(pq_attestation_root),
        ],
        32,
    )
}

fn lane_root(domain: &str, record: &Value) -> String {
    lane_hash(domain, &[HashPart::Json(record)])
}

fn lane_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    let mut hash_parts = vec![HashPart::Str(CHAIN_ID), HashPart::Str(PROTOCOL_VERSION)];
    for part in parts {
        match part {
            HashPart::Bytes(value) => hash_parts.push(HashPart::Bytes(*value)),
            HashPart::Str(value) => hash_parts.push(HashPart::Str(*value)),
            HashPart::U64(value) => hash_parts.push(HashPart::U64(*value)),
            HashPart::Int(value) => hash_parts.push(HashPart::Int(*value)),
            HashPart::Json(value) => hash_parts.push(HashPart::Json(*value)),
        }
    }
    domain_hash(domain, &hash_parts, 32)
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

fn merkle_from_strings<'a>(domain: &str, roots: impl IntoIterator<Item = &'a str>) -> String {
    merkle_root(
        domain,
        &roots
            .into_iter()
            .map(|root| Value::String(root.to_string()))
            .collect::<Vec<_>>(),
    )
}

fn validate_root(name: &str, root: &str) -> MoneroL2PrivateExitProofAggregationLaneResult<()> {
    if root.trim().is_empty() {
        return Err(format!("{name} is required"));
    }
    Ok(())
}
