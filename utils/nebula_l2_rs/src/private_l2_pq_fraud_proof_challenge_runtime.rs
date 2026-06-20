use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqFraudProofChallengeRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-fraud-proof-challenge-runtime-v1";
pub const PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_PQ_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f+ML-KEM-1024";
pub const PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_PRIVACY_EVIDENCE_SCHEME: &str =
    "private-envelope-commitments-with-nullifier-fences-v1";
pub const PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_LOW_FEE_SETTLEMENT_SCHEME: &str =
    "batched-low-fee-fraud-dispute-settlement-v1";
pub const PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_DEVNET_HEIGHT: u64 = 412_000;
pub const PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 4_096;
pub const PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_DEFAULT_MAX_FEE_BPS: u64 = 16;
pub const PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_DEFAULT_MIN_CHALLENGER_BOND_UNITS: u64 =
    10_000;
pub const PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_DEFAULT_CHALLENGE_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_DEFAULT_ROUND_TTL_BLOCKS: u64 = 8;
pub const PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_DEFAULT_MAX_CHALLENGES: usize = 262_144;
pub const PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_DEFAULT_MAX_EVIDENCE_ENVELOPES: usize =
    1_048_576;
pub const PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_DEFAULT_MAX_WITNESSES: usize = 1_048_576;
pub const PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_DEFAULT_MAX_ROUNDS: usize = 1_048_576;
pub const PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_DEFAULT_MAX_SETTLEMENT_BATCHES: usize =
    262_144;
pub const PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FraudProofLane {
    PrivateContractCall,
    ConfidentialToken,
    PrivateDefi,
    MoneroBridge,
    SequencerBatch,
    DataAvailability,
    RecursiveProof,
}

impl FraudProofLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateContractCall => "private_contract_call",
            Self::ConfidentialToken => "confidential_token",
            Self::PrivateDefi => "private_defi",
            Self::MoneroBridge => "monero_bridge",
            Self::SequencerBatch => "sequencer_batch",
            Self::DataAvailability => "data_availability",
            Self::RecursiveProof => "recursive_proof",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    Bonded,
    EvidenceRegistered,
    Witnessed,
    InRound,
    SettlementReady,
    SettledValid,
    SettledInvalid,
    Rejected,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Bonded => "bonded",
            Self::EvidenceRegistered => "evidence_registered",
            Self::Witnessed => "witnessed",
            Self::InRound => "in_round",
            Self::SettlementReady => "settlement_ready",
            Self::SettledValid => "settled_valid",
            Self::SettledInvalid => "settled_invalid",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_evidence(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Bonded | Self::EvidenceRegistered | Self::Witnessed | Self::InRound
        )
    }

    pub fn can_settle(self) -> bool {
        matches!(
            self,
            Self::SettlementReady | Self::InRound | Self::Witnessed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    InvalidStateTransition,
    DoubleSpendNullifier,
    InvalidPrivateContractExecution,
    BrokenTokenInvariant,
    InvalidDefiAccounting,
    MissingDataAvailability,
    InvalidRecursiveProof,
    SequencerEquivocation,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidStateTransition => "invalid_state_transition",
            Self::DoubleSpendNullifier => "double_spend_nullifier",
            Self::InvalidPrivateContractExecution => "invalid_private_contract_execution",
            Self::BrokenTokenInvariant => "broken_token_invariant",
            Self::InvalidDefiAccounting => "invalid_defi_accounting",
            Self::MissingDataAvailability => "missing_data_availability",
            Self::InvalidRecursiveProof => "invalid_recursive_proof",
            Self::SequencerEquivocation => "sequencer_equivocation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessKind {
    DataAvailability,
    ExecutionTrace,
    RecursiveProof,
    SequencerSignature,
    FeeMarket,
    BridgeAnchor,
}

impl WitnessKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DataAvailability => "data_availability",
            Self::ExecutionTrace => "execution_trace",
            Self::RecursiveProof => "recursive_proof",
            Self::SequencerSignature => "sequencer_signature",
            Self::FeeMarket => "fee_market",
            Self::BridgeAnchor => "bridge_anchor",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoundVerdict {
    Continue,
    ChallengerWins,
    DefenderWins,
    Escalate,
}

impl RoundVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Continue => "continue",
            Self::ChallengerWins => "challenger_wins",
            Self::DefenderWins => "defender_wins",
            Self::Escalate => "escalate",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BondAction {
    Stake,
    TopUp,
    Slash,
    Release,
}

impl BondAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stake => "stake",
            Self::TopUp => "top_up",
            Self::Slash => "slash",
            Self::Release => "release",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub min_challenger_bond_units: u64,
    pub challenge_ttl_blocks: u64,
    pub round_ttl_blocks: u64,
    pub max_challenges: usize,
    pub max_evidence_envelopes: usize,
    pub max_witnesses: usize,
    pub max_rounds: usize,
    pub max_settlement_batches: usize,
    pub require_private_evidence: bool,
    pub require_pq_attestation: bool,
    pub require_low_fee_batch: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            min_privacy_set_size:
                PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_fee_bps: PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_DEFAULT_MAX_FEE_BPS,
            min_challenger_bond_units:
                PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_DEFAULT_MIN_CHALLENGER_BOND_UNITS,
            challenge_ttl_blocks:
                PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_DEFAULT_CHALLENGE_TTL_BLOCKS,
            round_ttl_blocks: PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_DEFAULT_ROUND_TTL_BLOCKS,
            max_challenges: PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_DEFAULT_MAX_CHALLENGES,
            max_evidence_envelopes:
                PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_DEFAULT_MAX_EVIDENCE_ENVELOPES,
            max_witnesses: PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_DEFAULT_MAX_WITNESSES,
            max_rounds: PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_DEFAULT_MAX_ROUNDS,
            max_settlement_batches:
                PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_DEFAULT_MAX_SETTLEMENT_BATCHES,
            require_private_evidence: true,
            require_pq_attestation: true,
            require_low_fee_batch: true,
        }
    }

    pub fn validate(&self) -> PrivateL2PqFraudProofChallengeRuntimeResult<()> {
        required("chain_id", &self.chain_id)?;
        if self.min_privacy_set_size == 0 {
            return Err("fraud challenge privacy set minimum must be positive".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("fraud challenge PQ security floor is too low".to_string());
        }
        if self.max_fee_bps > PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_MAX_BPS {
            return Err("fraud challenge fee cap exceeds BPS range".to_string());
        }
        if self.min_challenger_bond_units == 0 {
            return Err("fraud challenge bond floor must be positive".to_string());
        }
        if self.challenge_ttl_blocks == 0 || self.round_ttl_blocks == 0 {
            return Err("fraud challenge TTL windows must be positive".to_string());
        }
        if self.max_challenges == 0
            || self.max_evidence_envelopes == 0
            || self.max_witnesses == 0
            || self.max_rounds == 0
            || self.max_settlement_batches == 0
        {
            return Err("fraud challenge capacity limits must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_fraud_proof_challenge_config",
            "chain_id": self.chain_id,
            "protocol_version": PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_PROTOCOL_VERSION,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "min_challenger_bond_units": self.min_challenger_bond_units,
            "challenge_ttl_blocks": self.challenge_ttl_blocks,
            "round_ttl_blocks": self.round_ttl_blocks,
            "max_challenges": self.max_challenges,
            "max_evidence_envelopes": self.max_evidence_envelopes,
            "max_witnesses": self.max_witnesses,
            "max_rounds": self.max_rounds,
            "max_settlement_batches": self.max_settlement_batches,
            "require_private_evidence": self.require_private_evidence,
            "require_pq_attestation": self.require_pq_attestation,
            "require_low_fee_batch": self.require_low_fee_batch,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub challenge_count: u64,
    pub evidence_count: u64,
    pub bond_count: u64,
    pub witness_count: u64,
    pub round_count: u64,
    pub settlement_batch_count: u64,
    pub receipt_count: u64,
    pub consumed_nullifier_count: u64,
    pub slashed_bond_units: u64,
    pub released_bond_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_fraud_proof_challenge_counters",
            "challenge_count": self.challenge_count,
            "evidence_count": self.evidence_count,
            "bond_count": self.bond_count,
            "witness_count": self.witness_count,
            "round_count": self.round_count,
            "settlement_batch_count": self.settlement_batch_count,
            "receipt_count": self.receipt_count,
            "consumed_nullifier_count": self.consumed_nullifier_count,
            "slashed_bond_units": self.slashed_bond_units,
            "released_bond_units": self.released_bond_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenFraudChallengeRequest {
    pub lane: FraudProofLane,
    pub challenger_commitment: String,
    pub disputed_batch_id: String,
    pub disputed_state_root: String,
    pub claimed_correct_state_root: String,
    pub fraud_claim_root: String,
    pub private_context_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub challenge_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub opened_at_height: u64,
}

impl OpenFraudChallengeRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "challenger_commitment": self.challenger_commitment,
            "disputed_batch_id": self.disputed_batch_id,
            "disputed_state_root": self.disputed_state_root,
            "claimed_correct_state_root": self.claimed_correct_state_root,
            "fraud_claim_root": self.fraud_claim_root,
            "private_context_root": self.private_context_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "challenge_nullifier": self.challenge_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterPrivateEvidenceEnvelopeRequest {
    pub challenge_id: String,
    pub evidence_kind: EvidenceKind,
    pub submitter_commitment: String,
    pub encrypted_evidence_root: String,
    pub evidence_commitment_root: String,
    pub redaction_policy_root: String,
    pub opening_hint_root: String,
    pub pq_attestation_root: String,
    pub privacy_proof_root: String,
    pub evidence_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
}

impl RegisterPrivateEvidenceEnvelopeRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "evidence_kind": self.evidence_kind.as_str(),
            "submitter_commitment": self.submitter_commitment,
            "encrypted_evidence_root": self.encrypted_evidence_root,
            "evidence_commitment_root": self.evidence_commitment_root,
            "redaction_policy_root": self.redaction_policy_root,
            "opening_hint_root": self.opening_hint_root,
            "pq_attestation_root": self.pq_attestation_root,
            "privacy_proof_root": self.privacy_proof_root,
            "evidence_nullifier": self.evidence_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "submitted_at_height": self.submitted_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakeChallengerBondRequest {
    pub challenge_id: String,
    pub challenger_commitment: String,
    pub bond_asset_id: String,
    pub bond_commitment_root: String,
    pub bond_units: u64,
    pub action: BondAction,
    pub pq_signature_root: String,
    pub bond_nullifier: String,
    pub acted_at_height: u64,
}

impl StakeChallengerBondRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "challenger_commitment": self.challenger_commitment,
            "bond_asset_id": self.bond_asset_id,
            "bond_commitment_root": self.bond_commitment_root,
            "bond_units": self.bond_units,
            "action": self.action.as_str(),
            "pq_signature_root": self.pq_signature_root,
            "bond_nullifier": self.bond_nullifier,
            "acted_at_height": self.acted_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitDaProofWitnessRequest {
    pub challenge_id: String,
    pub witness_kind: WitnessKind,
    pub witness_commitment: String,
    pub da_root: String,
    pub proof_root: String,
    pub availability_sampling_root: String,
    pub verifier_committee_root: String,
    pub pq_witness_signature_root: String,
    pub privacy_proof_root: String,
    pub witness_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub committed_at_height: u64,
}

impl CommitDaProofWitnessRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "witness_kind": self.witness_kind.as_str(),
            "witness_commitment": self.witness_commitment,
            "da_root": self.da_root,
            "proof_root": self.proof_root,
            "availability_sampling_root": self.availability_sampling_root,
            "verifier_committee_root": self.verifier_committee_root,
            "pq_witness_signature_root": self.pq_witness_signature_root,
            "privacy_proof_root": self.privacy_proof_root,
            "witness_nullifier": self.witness_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "committed_at_height": self.committed_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenChallengeRoundRequest {
    pub challenge_id: String,
    pub round_index: u64,
    pub challenger_move_root: String,
    pub defender_move_root: String,
    pub disputed_step_root: String,
    pub round_transcript_root: String,
    pub pq_transcript_signature_root: String,
    pub privacy_proof_root: String,
    pub verdict: RoundVerdict,
    pub opened_at_height: u64,
}

impl OpenChallengeRoundRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "round_index": self.round_index,
            "challenger_move_root": self.challenger_move_root,
            "defender_move_root": self.defender_move_root,
            "disputed_step_root": self.disputed_step_root,
            "round_transcript_root": self.round_transcript_root,
            "pq_transcript_signature_root": self.pq_transcript_signature_root,
            "privacy_proof_root": self.privacy_proof_root,
            "verdict": self.verdict.as_str(),
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleLowFeeChallengeBatchRequest {
    pub challenge_ids: Vec<String>,
    pub settlement_operator_commitment: String,
    pub aggregate_evidence_root: String,
    pub aggregate_witness_root: String,
    pub aggregate_round_root: String,
    pub bond_accounting_root: String,
    pub low_fee_sponsor_root: String,
    pub settlement_proof_root: String,
    pub state_root_after: String,
    pub fee_bps: u64,
    pub settled_at_height: u64,
}

impl SettleLowFeeChallengeBatchRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "challenge_ids": self.challenge_ids,
            "settlement_operator_commitment": self.settlement_operator_commitment,
            "aggregate_evidence_root": self.aggregate_evidence_root,
            "aggregate_witness_root": self.aggregate_witness_root,
            "aggregate_round_root": self.aggregate_round_root,
            "bond_accounting_root": self.bond_accounting_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "settlement_proof_root": self.settlement_proof_root,
            "state_root_after": self.state_root_after,
            "fee_bps": self.fee_bps,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FraudChallengeRecord {
    pub challenge_id: String,
    pub request: OpenFraudChallengeRequest,
    pub status: ChallengeStatus,
    pub expires_at_height: u64,
    pub evidence_ids: Vec<String>,
    pub witness_ids: Vec<String>,
    pub round_ids: Vec<String>,
    pub bond_units_staked: u64,
    pub bond_units_slashed: u64,
    pub bond_units_released: u64,
    pub settlement_batch_id: Option<String>,
}

impl FraudChallengeRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "expires_at_height": self.expires_at_height,
            "evidence_ids": self.evidence_ids,
            "witness_ids": self.witness_ids,
            "round_ids": self.round_ids,
            "bond_units_staked": self.bond_units_staked,
            "bond_units_slashed": self.bond_units_slashed,
            "bond_units_released": self.bond_units_released,
            "settlement_batch_id": self.settlement_batch_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateEvidenceEnvelopeRecord {
    pub evidence_id: String,
    pub request: RegisterPrivateEvidenceEnvelopeRequest,
}

impl PrivateEvidenceEnvelopeRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengerBondRecord {
    pub bond_id: String,
    pub request: StakeChallengerBondRequest,
    pub resulting_staked_units: u64,
    pub resulting_slashed_units: u64,
    pub resulting_released_units: u64,
}

impl ChallengerBondRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "bond_id": self.bond_id,
            "request": self.request.public_record(),
            "resulting_staked_units": self.resulting_staked_units,
            "resulting_slashed_units": self.resulting_slashed_units,
            "resulting_released_units": self.resulting_released_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaProofWitnessRecord {
    pub witness_id: String,
    pub request: CommitDaProofWitnessRequest,
}

impl DaProofWitnessRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "witness_id": self.witness_id,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeRoundRecord {
    pub round_id: String,
    pub expires_at_height: u64,
    pub request: OpenChallengeRoundRequest,
}

impl ChallengeRoundRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "round_id": self.round_id,
            "expires_at_height": self.expires_at_height,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeChallengeSettlementBatchRecord {
    pub settlement_batch_id: String,
    pub request: SettleLowFeeChallengeBatchRequest,
    pub receipt_ids: Vec<String>,
}

impl LowFeeChallengeSettlementBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_batch_id": self.settlement_batch_id,
            "request": self.request.public_record(),
            "receipt_ids": self.receipt_ids,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FraudChallengeReceiptRecord {
    pub receipt_id: String,
    pub settlement_batch_id: String,
    pub challenge_id: String,
    pub final_status: ChallengeStatus,
    pub bond_units_staked: u64,
    pub bond_units_slashed: u64,
    pub bond_units_released: u64,
    pub state_root_after: String,
    pub fee_bps: u64,
    pub settled_at_height: u64,
}

impl FraudChallengeReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "settlement_batch_id": self.settlement_batch_id,
            "challenge_id": self.challenge_id,
            "final_status": self.final_status.as_str(),
            "bond_units_staked": self.bond_units_staked,
            "bond_units_slashed": self.bond_units_slashed,
            "bond_units_released": self.bond_units_released,
            "state_root_after": self.state_root_after,
            "fee_bps": self.fee_bps,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counter_root: String,
    pub challenge_root: String,
    pub evidence_root: String,
    pub bond_root: String,
    pub witness_root: String,
    pub round_root: String,
    pub settlement_batch_root: String,
    pub receipt_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counter_root": self.counter_root,
            "challenge_root": self.challenge_root,
            "evidence_root": self.evidence_root,
            "bond_root": self.bond_root,
            "witness_root": self.witness_root,
            "round_root": self.round_root,
            "settlement_batch_root": self.settlement_batch_root,
            "receipt_root": self.receipt_root,
            "nullifier_root": self.nullifier_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub chain_id: String,
    pub protocol_version: String,
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub challenges: BTreeMap<String, FraudChallengeRecord>,
    pub evidence_envelopes: BTreeMap<String, PrivateEvidenceEnvelopeRecord>,
    pub challenger_bonds: BTreeMap<String, ChallengerBondRecord>,
    pub witnesses: BTreeMap<String, DaProofWitnessRecord>,
    pub rounds: BTreeMap<String, ChallengeRoundRecord>,
    pub settlement_batches: BTreeMap<String, LowFeeChallengeSettlementBatchRecord>,
    pub receipts: BTreeMap<String, FraudChallengeReceiptRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub public_records: Vec<Value>,
}

impl State {
    pub fn devnet() -> PrivateL2PqFraudProofChallengeRuntimeResult<Self> {
        let config = Config::devnet();
        Self::new(
            config,
            PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_DEVNET_HEIGHT,
        )
    }

    pub fn new(
        config: Config,
        current_height: u64,
    ) -> PrivateL2PqFraudProofChallengeRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            chain_id: config.chain_id.clone(),
            protocol_version: PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            config,
            counters: Counters::default(),
            current_height,
            challenges: BTreeMap::new(),
            evidence_envelopes: BTreeMap::new(),
            challenger_bonds: BTreeMap::new(),
            witnesses: BTreeMap::new(),
            rounds: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            public_records: Vec::new(),
        })
    }

    pub fn open_fraud_challenge(
        &mut self,
        request: OpenFraudChallengeRequest,
    ) -> PrivateL2PqFraudProofChallengeRuntimeResult<FraudChallengeRecord> {
        self.config.validate()?;
        validate_open_challenge(&request, &self.config)?;
        if self.challenges.len() >= self.config.max_challenges {
            return Err("fraud challenge capacity exhausted".to_string());
        }
        self.insert_nullifier(&request.challenge_nullifier)?;
        self.counters.challenge_count = self.counters.challenge_count.saturating_add(1);
        self.current_height = self.current_height.max(request.opened_at_height);
        let challenge_id = fraud_challenge_id(&request, self.counters.challenge_count);
        let record = FraudChallengeRecord {
            challenge_id: challenge_id.clone(),
            expires_at_height: request
                .opened_at_height
                .saturating_add(self.config.challenge_ttl_blocks),
            request,
            status: ChallengeStatus::Open,
            evidence_ids: Vec::new(),
            witness_ids: Vec::new(),
            round_ids: Vec::new(),
            bond_units_staked: 0,
            bond_units_slashed: 0,
            bond_units_released: 0,
            settlement_batch_id: None,
        };
        self.public_records.push(record.public_record());
        self.challenges.insert(challenge_id, record.clone());
        Ok(record)
    }

    pub fn register_private_evidence_envelope(
        &mut self,
        request: RegisterPrivateEvidenceEnvelopeRequest,
    ) -> PrivateL2PqFraudProofChallengeRuntimeResult<PrivateEvidenceEnvelopeRecord> {
        self.config.validate()?;
        validate_evidence(&request, &self.config)?;
        if self.evidence_envelopes.len() >= self.config.max_evidence_envelopes {
            return Err("fraud evidence envelope capacity exhausted".to_string());
        }
        self.ensure_challenge_accepts_evidence(&request.challenge_id, request.submitted_at_height)?;
        self.insert_nullifier(&request.evidence_nullifier)?;
        self.counters.evidence_count = self.counters.evidence_count.saturating_add(1);
        self.current_height = self.current_height.max(request.submitted_at_height);
        let evidence_id = private_evidence_envelope_id(&request, self.counters.evidence_count);
        let challenge_id = request.challenge_id.clone();
        let record = PrivateEvidenceEnvelopeRecord {
            evidence_id: evidence_id.clone(),
            request,
        };
        if let Some(challenge) = self.challenges.get_mut(&challenge_id) {
            challenge.evidence_ids.push(evidence_id.clone());
            if challenge.status != ChallengeStatus::InRound {
                challenge.status = ChallengeStatus::EvidenceRegistered;
            }
        }
        self.public_records.push(record.public_record());
        self.evidence_envelopes.insert(evidence_id, record.clone());
        Ok(record)
    }

    pub fn stake_challenger_bond(
        &mut self,
        request: StakeChallengerBondRequest,
    ) -> PrivateL2PqFraudProofChallengeRuntimeResult<ChallengerBondRecord> {
        self.config.validate()?;
        validate_bond(&request, &self.config)?;
        let challenge = self
            .challenges
            .get(&request.challenge_id)
            .ok_or_else(|| "fraud challenge not found for bond".to_string())?;
        if request.acted_at_height >= challenge.expires_at_height {
            return Err("fraud challenge expired before bond action".to_string());
        }
        if matches!(request.action, BondAction::Stake | BondAction::TopUp) {
            self.insert_nullifier(&request.bond_nullifier)?;
        }
        self.counters.bond_count = self.counters.bond_count.saturating_add(1);
        self.current_height = self.current_height.max(request.acted_at_height);
        let bond_id = challenger_bond_id(&request, self.counters.bond_count);
        let challenge = self
            .challenges
            .get_mut(&request.challenge_id)
            .ok_or_else(|| "fraud challenge not found for bond".to_string())?;
        apply_bond_action(challenge, &request, &mut self.counters)?;
        let record = ChallengerBondRecord {
            bond_id: bond_id.clone(),
            request,
            resulting_staked_units: challenge.bond_units_staked,
            resulting_slashed_units: challenge.bond_units_slashed,
            resulting_released_units: challenge.bond_units_released,
        };
        self.public_records.push(record.public_record());
        self.challenger_bonds.insert(bond_id, record.clone());
        Ok(record)
    }

    pub fn commit_da_proof_witness(
        &mut self,
        request: CommitDaProofWitnessRequest,
    ) -> PrivateL2PqFraudProofChallengeRuntimeResult<DaProofWitnessRecord> {
        self.config.validate()?;
        validate_witness(&request, &self.config)?;
        if self.witnesses.len() >= self.config.max_witnesses {
            return Err("fraud challenge witness capacity exhausted".to_string());
        }
        self.ensure_challenge_accepts_evidence(&request.challenge_id, request.committed_at_height)?;
        self.insert_nullifier(&request.witness_nullifier)?;
        self.counters.witness_count = self.counters.witness_count.saturating_add(1);
        self.current_height = self.current_height.max(request.committed_at_height);
        let witness_id = da_proof_witness_id(&request, self.counters.witness_count);
        let challenge_id = request.challenge_id.clone();
        let record = DaProofWitnessRecord {
            witness_id: witness_id.clone(),
            request,
        };
        if let Some(challenge) = self.challenges.get_mut(&challenge_id) {
            challenge.witness_ids.push(witness_id.clone());
            if challenge.status != ChallengeStatus::InRound {
                challenge.status = ChallengeStatus::Witnessed;
            }
        }
        self.public_records.push(record.public_record());
        self.witnesses.insert(witness_id, record.clone());
        Ok(record)
    }

    pub fn open_challenge_round(
        &mut self,
        request: OpenChallengeRoundRequest,
    ) -> PrivateL2PqFraudProofChallengeRuntimeResult<ChallengeRoundRecord> {
        self.config.validate()?;
        validate_round(&request)?;
        if self.rounds.len() >= self.config.max_rounds {
            return Err("fraud challenge round capacity exhausted".to_string());
        }
        {
            let challenge = self
                .challenges
                .get(&request.challenge_id)
                .ok_or_else(|| "fraud challenge not found for round".to_string())?;
            if !challenge.status.accepts_evidence() {
                return Err("fraud challenge cannot open a round in current status".to_string());
            }
            if request.opened_at_height >= challenge.expires_at_height {
                return Err("fraud challenge expired before round".to_string());
            }
        }
        self.counters.round_count = self.counters.round_count.saturating_add(1);
        self.current_height = self.current_height.max(request.opened_at_height);
        let round_id = challenge_round_id(&request, self.counters.round_count);
        let expires_at_height = request
            .opened_at_height
            .saturating_add(self.config.round_ttl_blocks);
        let challenge_id = request.challenge_id.clone();
        let verdict = request.verdict;
        let record = ChallengeRoundRecord {
            round_id: round_id.clone(),
            expires_at_height,
            request,
        };
        if let Some(challenge) = self.challenges.get_mut(&challenge_id) {
            challenge.round_ids.push(round_id.clone());
            challenge.status = match verdict {
                RoundVerdict::Continue | RoundVerdict::Escalate => ChallengeStatus::InRound,
                RoundVerdict::ChallengerWins | RoundVerdict::DefenderWins => {
                    ChallengeStatus::SettlementReady
                }
            };
        }
        self.public_records.push(record.public_record());
        self.rounds.insert(round_id, record.clone());
        Ok(record)
    }

    pub fn settle_low_fee_challenge_batch(
        &mut self,
        request: SettleLowFeeChallengeBatchRequest,
    ) -> PrivateL2PqFraudProofChallengeRuntimeResult<LowFeeChallengeSettlementBatchRecord> {
        self.config.validate()?;
        validate_settlement_batch(&request, &self.config)?;
        if self.settlement_batches.len() >= self.config.max_settlement_batches {
            return Err("fraud challenge settlement batch capacity exhausted".to_string());
        }
        let mut seen = BTreeSet::new();
        for challenge_id in &request.challenge_ids {
            if !seen.insert(challenge_id.clone()) {
                return Err("fraud challenge settlement batch has duplicate challenge".to_string());
            }
            let challenge = self
                .challenges
                .get(challenge_id)
                .ok_or_else(|| format!("fraud challenge {challenge_id} not found"))?;
            if !challenge.status.can_settle() {
                return Err("fraud challenge cannot settle in current status".to_string());
            }
            if request.settled_at_height >= challenge.expires_at_height {
                return Err("fraud challenge expired before settlement".to_string());
            }
        }
        self.counters.settlement_batch_count =
            self.counters.settlement_batch_count.saturating_add(1);
        self.current_height = self.current_height.max(request.settled_at_height);
        let settlement_batch_id =
            low_fee_challenge_settlement_batch_id(&request, self.counters.settlement_batch_count);
        let mut receipt_ids = Vec::new();
        for challenge_id in &request.challenge_ids {
            self.counters.receipt_count = self.counters.receipt_count.saturating_add(1);
            let challenge = self
                .challenges
                .get_mut(challenge_id)
                .ok_or_else(|| format!("fraud challenge {challenge_id} not found"))?;
            let final_status = if challenge.bond_units_slashed > 0 {
                ChallengeStatus::SettledInvalid
            } else {
                ChallengeStatus::SettledValid
            };
            challenge.status = final_status;
            challenge.settlement_batch_id = Some(settlement_batch_id.clone());
            let receipt_id = fraud_challenge_receipt_id(
                &settlement_batch_id,
                challenge_id,
                self.counters.receipt_count,
            );
            let receipt = FraudChallengeReceiptRecord {
                receipt_id: receipt_id.clone(),
                settlement_batch_id: settlement_batch_id.clone(),
                challenge_id: challenge_id.clone(),
                final_status,
                bond_units_staked: challenge.bond_units_staked,
                bond_units_slashed: challenge.bond_units_slashed,
                bond_units_released: challenge.bond_units_released,
                state_root_after: request.state_root_after.clone(),
                fee_bps: request.fee_bps,
                settled_at_height: request.settled_at_height,
            };
            self.public_records.push(receipt.public_record());
            self.receipts.insert(receipt_id.clone(), receipt);
            receipt_ids.push(receipt_id);
        }
        let record = LowFeeChallengeSettlementBatchRecord {
            settlement_batch_id: settlement_batch_id.clone(),
            request,
            receipt_ids,
        };
        self.public_records.push(record.public_record());
        self.settlement_batches
            .insert(settlement_batch_id, record.clone());
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        let config_root = root_from_record(
            "PRIVATE-L2-PQ-FRAUD-PROOF-CHALLENGE-CONFIG",
            &self.config.public_record(),
        );
        let counter_root = root_from_record(
            "PRIVATE-L2-PQ-FRAUD-PROOF-CHALLENGE-COUNTERS",
            &self.counters.public_record(),
        );
        let challenge_root = merkle_root(
            "PRIVATE-L2-PQ-FRAUD-PROOF-CHALLENGE-CHALLENGES",
            &self
                .challenges
                .values()
                .map(FraudChallengeRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let evidence_root = merkle_root(
            "PRIVATE-L2-PQ-FRAUD-PROOF-CHALLENGE-EVIDENCE",
            &self
                .evidence_envelopes
                .values()
                .map(PrivateEvidenceEnvelopeRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let bond_root = merkle_root(
            "PRIVATE-L2-PQ-FRAUD-PROOF-CHALLENGE-BONDS",
            &self
                .challenger_bonds
                .values()
                .map(ChallengerBondRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let witness_root = merkle_root(
            "PRIVATE-L2-PQ-FRAUD-PROOF-CHALLENGE-WITNESSES",
            &self
                .witnesses
                .values()
                .map(DaProofWitnessRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let round_root = merkle_root(
            "PRIVATE-L2-PQ-FRAUD-PROOF-CHALLENGE-ROUNDS",
            &self
                .rounds
                .values()
                .map(ChallengeRoundRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let settlement_batch_root = merkle_root(
            "PRIVATE-L2-PQ-FRAUD-PROOF-CHALLENGE-SETTLEMENT-BATCHES",
            &self
                .settlement_batches
                .values()
                .map(LowFeeChallengeSettlementBatchRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let receipt_root = merkle_root(
            "PRIVATE-L2-PQ-FRAUD-PROOF-CHALLENGE-RECEIPTS",
            &self
                .receipts
                .values()
                .map(FraudChallengeReceiptRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_root = merkle_root(
            "PRIVATE-L2-PQ-FRAUD-PROOF-CHALLENGE-NULLIFIERS",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!({ "nullifier": nullifier }))
                .collect::<Vec<_>>(),
        );
        let public_record_root = merkle_root(
            "PRIVATE-L2-PQ-FRAUD-PROOF-CHALLENGE-PUBLIC-RECORDS",
            &self.public_records,
        );
        let state_root = root_from_record(
            "PRIVATE-L2-PQ-FRAUD-PROOF-CHALLENGE-STATE",
            &json!({
                "chain_id": self.chain_id,
                "protocol_version": self.protocol_version,
                "current_height": self.current_height,
                "config_root": config_root,
                "counter_root": counter_root,
                "challenge_root": challenge_root,
                "evidence_root": evidence_root,
                "bond_root": bond_root,
                "witness_root": witness_root,
                "round_root": round_root,
                "settlement_batch_root": settlement_batch_root,
                "receipt_root": receipt_root,
                "nullifier_root": nullifier_root,
                "public_record_root": public_record_root,
            }),
        );
        Roots {
            config_root,
            counter_root,
            challenge_root,
            evidence_root,
            bond_root,
            witness_root,
            round_root,
            settlement_batch_root,
            receipt_root,
            nullifier_root,
            public_record_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_l2_pq_fraud_proof_challenge_runtime",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_SCHEMA_VERSION,
            "hash_suite": PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_HASH_SUITE,
            "pq_attestation_suite": PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_PQ_ATTESTATION_SUITE,
            "privacy_evidence_scheme": PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_PRIVACY_EVIDENCE_SCHEME,
            "low_fee_settlement_scheme": PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_LOW_FEE_SETTLEMENT_SCHEME,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "challenge_ids": self.challenges.keys().cloned().collect::<Vec<_>>(),
            "evidence_ids": self.evidence_envelopes.keys().cloned().collect::<Vec<_>>(),
            "bond_ids": self.challenger_bonds.keys().cloned().collect::<Vec<_>>(),
            "witness_ids": self.witnesses.keys().cloned().collect::<Vec<_>>(),
            "round_ids": self.rounds.keys().cloned().collect::<Vec<_>>(),
            "settlement_batch_ids": self.settlement_batches.keys().cloned().collect::<Vec<_>>(),
            "receipt_ids": self.receipts.keys().cloned().collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn ensure_challenge_accepts_evidence(
        &self,
        challenge_id: &str,
        height: u64,
    ) -> PrivateL2PqFraudProofChallengeRuntimeResult<()> {
        let challenge = self
            .challenges
            .get(challenge_id)
            .ok_or_else(|| "fraud challenge not found".to_string())?;
        if !challenge.status.accepts_evidence() {
            return Err("fraud challenge does not accept evidence".to_string());
        }
        if height >= challenge.expires_at_height {
            return Err("fraud challenge expired before evidence".to_string());
        }
        Ok(())
    }

    fn insert_nullifier(
        &mut self,
        nullifier: &str,
    ) -> PrivateL2PqFraudProofChallengeRuntimeResult<()> {
        if !self.consumed_nullifiers.insert(nullifier.to_string()) {
            return Err("fraud challenge nullifier already consumed".to_string());
        }
        self.counters.consumed_nullifier_count =
            self.counters.consumed_nullifier_count.saturating_add(1);
        Ok(())
    }
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn private_l2_pq_fraud_proof_challenge_state_root(state: &State) -> String {
    state.state_root()
}

pub fn devnet() -> PrivateL2PqFraudProofChallengeRuntimeResult<State> {
    State::devnet()
}

pub fn fraud_challenge_id(request: &OpenFraudChallengeRequest, counter: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FRAUD-PROOF-CHALLENGE-ID",
        &[
            HashPart::Str(PRIVATE_L2_PQ_FRAUD_PROOF_CHALLENGE_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(&request.challenger_commitment),
            HashPart::Str(&request.disputed_batch_id),
            HashPart::Str(&request.disputed_state_root),
            HashPart::Str(&request.challenge_nullifier),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn private_evidence_envelope_id(
    request: &RegisterPrivateEvidenceEnvelopeRequest,
    counter: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FRAUD-PROOF-EVIDENCE-ENVELOPE-ID",
        &[
            HashPart::Str(&request.challenge_id),
            HashPart::Str(request.evidence_kind.as_str()),
            HashPart::Str(&request.submitter_commitment),
            HashPart::Str(&request.evidence_commitment_root),
            HashPart::Str(&request.evidence_nullifier),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn challenger_bond_id(request: &StakeChallengerBondRequest, counter: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FRAUD-PROOF-CHALLENGER-BOND-ID",
        &[
            HashPart::Str(&request.challenge_id),
            HashPart::Str(&request.challenger_commitment),
            HashPart::Str(&request.bond_asset_id),
            HashPart::Str(&request.bond_commitment_root),
            HashPart::Str(request.action.as_str()),
            HashPart::Str(&request.bond_nullifier),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn da_proof_witness_id(request: &CommitDaProofWitnessRequest, counter: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FRAUD-PROOF-DA-PROOF-WITNESS-ID",
        &[
            HashPart::Str(&request.challenge_id),
            HashPart::Str(request.witness_kind.as_str()),
            HashPart::Str(&request.witness_commitment),
            HashPart::Str(&request.da_root),
            HashPart::Str(&request.proof_root),
            HashPart::Str(&request.witness_nullifier),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn challenge_round_id(request: &OpenChallengeRoundRequest, counter: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FRAUD-PROOF-CHALLENGE-ROUND-ID",
        &[
            HashPart::Str(&request.challenge_id),
            HashPart::Int(request.round_index as i128),
            HashPart::Str(&request.disputed_step_root),
            HashPart::Str(&request.round_transcript_root),
            HashPart::Str(request.verdict.as_str()),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn low_fee_challenge_settlement_batch_id(
    request: &SettleLowFeeChallengeBatchRequest,
    counter: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FRAUD-PROOF-LOW-FEE-SETTLEMENT-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Json(&json!(request.challenge_ids)),
            HashPart::Str(&request.aggregate_evidence_root),
            HashPart::Str(&request.aggregate_witness_root),
            HashPart::Str(&request.settlement_proof_root),
            HashPart::Str(&request.state_root_after),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn fraud_challenge_receipt_id(
    settlement_batch_id: &str,
    challenge_id: &str,
    counter: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FRAUD-PROOF-CHALLENGE-RECEIPT-ID",
        &[
            HashPart::Str(settlement_batch_id),
            HashPart::Str(challenge_id),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

fn validate_open_challenge(
    request: &OpenFraudChallengeRequest,
    config: &Config,
) -> PrivateL2PqFraudProofChallengeRuntimeResult<()> {
    required("challenger_commitment", &request.challenger_commitment)?;
    required("disputed_batch_id", &request.disputed_batch_id)?;
    required("disputed_state_root", &request.disputed_state_root)?;
    required(
        "claimed_correct_state_root",
        &request.claimed_correct_state_root,
    )?;
    required("fraud_claim_root", &request.fraud_claim_root)?;
    required("private_context_root", &request.private_context_root)?;
    required("pq_authorization_root", &request.pq_authorization_root)?;
    required("privacy_proof_root", &request.privacy_proof_root)?;
    required("challenge_nullifier", &request.challenge_nullifier)?;
    validate_privacy_and_pq(request.privacy_set_size, request.pq_security_bits, config)?;
    if request.max_fee_bps > config.max_fee_bps {
        return Err("fraud challenge fee exceeds runtime cap".to_string());
    }
    Ok(())
}

fn validate_evidence(
    request: &RegisterPrivateEvidenceEnvelopeRequest,
    config: &Config,
) -> PrivateL2PqFraudProofChallengeRuntimeResult<()> {
    required("challenge_id", &request.challenge_id)?;
    required("submitter_commitment", &request.submitter_commitment)?;
    required("encrypted_evidence_root", &request.encrypted_evidence_root)?;
    required(
        "evidence_commitment_root",
        &request.evidence_commitment_root,
    )?;
    required("redaction_policy_root", &request.redaction_policy_root)?;
    required("opening_hint_root", &request.opening_hint_root)?;
    required("pq_attestation_root", &request.pq_attestation_root)?;
    required("privacy_proof_root", &request.privacy_proof_root)?;
    required("evidence_nullifier", &request.evidence_nullifier)?;
    validate_privacy_and_pq(request.privacy_set_size, request.pq_security_bits, config)?;
    Ok(())
}

fn validate_bond(
    request: &StakeChallengerBondRequest,
    config: &Config,
) -> PrivateL2PqFraudProofChallengeRuntimeResult<()> {
    required("challenge_id", &request.challenge_id)?;
    required("challenger_commitment", &request.challenger_commitment)?;
    required("bond_asset_id", &request.bond_asset_id)?;
    required("bond_commitment_root", &request.bond_commitment_root)?;
    required("pq_signature_root", &request.pq_signature_root)?;
    if matches!(request.action, BondAction::Stake | BondAction::TopUp) {
        required("bond_nullifier", &request.bond_nullifier)?;
        if request.bond_units < config.min_challenger_bond_units {
            return Err("fraud challenge challenger bond below minimum".to_string());
        }
    }
    if request.bond_units == 0 {
        return Err("fraud challenge bond action units must be positive".to_string());
    }
    Ok(())
}

fn validate_witness(
    request: &CommitDaProofWitnessRequest,
    config: &Config,
) -> PrivateL2PqFraudProofChallengeRuntimeResult<()> {
    required("challenge_id", &request.challenge_id)?;
    required("witness_commitment", &request.witness_commitment)?;
    required("da_root", &request.da_root)?;
    required("proof_root", &request.proof_root)?;
    required(
        "availability_sampling_root",
        &request.availability_sampling_root,
    )?;
    required("verifier_committee_root", &request.verifier_committee_root)?;
    required(
        "pq_witness_signature_root",
        &request.pq_witness_signature_root,
    )?;
    required("privacy_proof_root", &request.privacy_proof_root)?;
    required("witness_nullifier", &request.witness_nullifier)?;
    validate_privacy_and_pq(request.privacy_set_size, request.pq_security_bits, config)?;
    Ok(())
}

fn validate_round(
    request: &OpenChallengeRoundRequest,
) -> PrivateL2PqFraudProofChallengeRuntimeResult<()> {
    required("challenge_id", &request.challenge_id)?;
    required("challenger_move_root", &request.challenger_move_root)?;
    required("defender_move_root", &request.defender_move_root)?;
    required("disputed_step_root", &request.disputed_step_root)?;
    required("round_transcript_root", &request.round_transcript_root)?;
    required(
        "pq_transcript_signature_root",
        &request.pq_transcript_signature_root,
    )?;
    required("privacy_proof_root", &request.privacy_proof_root)?;
    Ok(())
}

fn validate_settlement_batch(
    request: &SettleLowFeeChallengeBatchRequest,
    config: &Config,
) -> PrivateL2PqFraudProofChallengeRuntimeResult<()> {
    if request.challenge_ids.is_empty() {
        return Err("fraud challenge settlement batch must include challenges".to_string());
    }
    required(
        "settlement_operator_commitment",
        &request.settlement_operator_commitment,
    )?;
    required("aggregate_evidence_root", &request.aggregate_evidence_root)?;
    required("aggregate_witness_root", &request.aggregate_witness_root)?;
    required("aggregate_round_root", &request.aggregate_round_root)?;
    required("bond_accounting_root", &request.bond_accounting_root)?;
    if config.require_low_fee_batch {
        required("low_fee_sponsor_root", &request.low_fee_sponsor_root)?;
    }
    required("settlement_proof_root", &request.settlement_proof_root)?;
    required("state_root_after", &request.state_root_after)?;
    if request.fee_bps > config.max_fee_bps {
        return Err("fraud challenge settlement fee exceeds runtime cap".to_string());
    }
    Ok(())
}

fn apply_bond_action(
    challenge: &mut FraudChallengeRecord,
    request: &StakeChallengerBondRequest,
    counters: &mut Counters,
) -> PrivateL2PqFraudProofChallengeRuntimeResult<()> {
    match request.action {
        BondAction::Stake | BondAction::TopUp => {
            challenge.bond_units_staked = challenge
                .bond_units_staked
                .saturating_add(request.bond_units);
            challenge.status = ChallengeStatus::Bonded;
        }
        BondAction::Slash => {
            let available = challenge
                .bond_units_staked
                .saturating_sub(challenge.bond_units_slashed)
                .saturating_sub(challenge.bond_units_released);
            if request.bond_units > available {
                return Err("fraud challenge slash exceeds available bond".to_string());
            }
            challenge.bond_units_slashed = challenge
                .bond_units_slashed
                .saturating_add(request.bond_units);
            counters.slashed_bond_units = counters
                .slashed_bond_units
                .saturating_add(request.bond_units);
            challenge.status = ChallengeStatus::SettlementReady;
        }
        BondAction::Release => {
            let available = challenge
                .bond_units_staked
                .saturating_sub(challenge.bond_units_slashed)
                .saturating_sub(challenge.bond_units_released);
            if request.bond_units > available {
                return Err("fraud challenge release exceeds available bond".to_string());
            }
            challenge.bond_units_released = challenge
                .bond_units_released
                .saturating_add(request.bond_units);
            counters.released_bond_units = counters
                .released_bond_units
                .saturating_add(request.bond_units);
            challenge.status = ChallengeStatus::SettlementReady;
        }
    }
    Ok(())
}

fn validate_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    config: &Config,
) -> PrivateL2PqFraudProofChallengeRuntimeResult<()> {
    if privacy_set_size < config.min_privacy_set_size {
        return Err("fraud challenge privacy set below minimum".to_string());
    }
    if pq_security_bits < config.min_pq_security_bits {
        return Err("fraud challenge PQ security bits below minimum".to_string());
    }
    Ok(())
}

fn required(field: &str, value: &str) -> PrivateL2PqFraudProofChallengeRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("fraud challenge field {field} is required"));
    }
    Ok(())
}
