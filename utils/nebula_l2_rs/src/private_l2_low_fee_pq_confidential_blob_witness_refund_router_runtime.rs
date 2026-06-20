use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialBlobWitnessRefundRouterRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BLOB_WITNESS_REFUND_ROUTER_RUNTIME_PROTOCOL_VERSION:
    &str = "private-l2-low-fee-pq-confidential-blob-witness-refund-router/v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BLOB_WITNESS_REFUND_ROUTER_RUNTIME_PROTOCOL_VERSION;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SCHEME: &str = "ml-dsa-87+slh-dsa-shake-256f";
pub const PQ_DA_SCHEME: &str = "ml-kem-1024+ml-dsa-87-da-attestation";
pub const CONFIDENTIAL_REFUND_SCHEME: &str = "confidential-refund-note-commitment-v1";
pub const BLOB_WITNESS_SCHEME: &str = "monero-l2-blob-witness-cost-proof-v1";
pub const REDACTION_SCHEME: &str = "budgeted-redaction-envelope-v1";
pub const DEFAULT_DEVNET_HEIGHT: u64 = 314_159;
pub const DEFAULT_EPOCH_BLOCKS: u64 = 120;
pub const DEFAULT_ROUTE_TTL_BLOCKS: u64 = 18;
pub const DEFAULT_CLAIM_TTL_BLOCKS: u64 = 72;
pub const DEFAULT_SETTLEMENT_DELAY_BLOCKS: u64 = 4;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 4_096;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_LOW_FEE_BPS: u64 = 6;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 25;
pub const DEFAULT_BLOB_REBATE_BPS: u64 = 9_500;
pub const DEFAULT_WITNESS_REBATE_BPS: u64 = 9_800;
pub const DEFAULT_PROVER_REBATE_BPS: u64 = 8_500;
pub const DEFAULT_DA_REBATE_BPS: u64 = 8_000;
pub const DEFAULT_OPERATOR_CARRY_BPS: u64 = 400;
pub const DEFAULT_SLASH_BPS: u64 = 1_000;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_ROUTES: usize = 262_144;
pub const MAX_CLAIMS: usize = 524_288;
pub const MAX_ATTESTATIONS: usize = 524_288;
pub const MAX_SETTLEMENTS: usize = 262_144;
pub const MAX_REBATES: usize = 524_288;
pub const MAX_THROTTLES: usize = 131_072;
pub const MAX_REDACTION_BUDGETS: usize = 131_072;
pub const MAX_OPERATOR_SUMMARIES: usize = 65_536;
pub const MAX_EVENTS: usize = 524_288;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RefundLane {
    BlobDaCost,
    WitnessCost,
    ProverCost,
    RouterFee,
    SequencerFee,
    EmergencyBlobReplay,
}

impl RefundLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BlobDaCost => "blob_da_cost",
            Self::WitnessCost => "witness_cost",
            Self::ProverCost => "prover_cost",
            Self::RouterFee => "router_fee",
            Self::SequencerFee => "sequencer_fee",
            Self::EmergencyBlobReplay => "emergency_blob_replay",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyBlobReplay => 1_000,
            Self::WitnessCost => 960,
            Self::BlobDaCost => 940,
            Self::ProverCost => 860,
            Self::RouterFee => 720,
            Self::SequencerFee => 660,
        }
    }

    pub fn default_rebate_bps(self, config: &Config) -> u64 {
        match self {
            Self::WitnessCost | Self::EmergencyBlobReplay => config.witness_rebate_bps,
            Self::BlobDaCost => config.blob_rebate_bps,
            Self::ProverCost => config.prover_rebate_bps,
            Self::RouterFee | Self::SequencerFee => config.da_rebate_bps,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RouteStatus {
    Open,
    Preferred,
    Saturated,
    Paused,
    Retired,
    Slashed,
}

impl RouteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Preferred => "preferred",
            Self::Saturated => "saturated",
            Self::Paused => "paused",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn accepts_claims(self) -> bool {
        matches!(self, Self::Open | Self::Preferred)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Submitted,
    Routed,
    Attested,
    Budgeted,
    Queued,
    Settling,
    Settled,
    Rejected,
    Expired,
    Disputed,
}

impl ClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Routed => "routed",
            Self::Attested => "attested",
            Self::Budgeted => "budgeted",
            Self::Queued => "queued",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::Routed
                | Self::Attested
                | Self::Budgeted
                | Self::Queued
                | Self::Settling
        )
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    BlobAvailability,
    WitnessInclusion,
    PqProver,
    FeeObservation,
    RedactionEnvelope,
    SettlementBatch,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BlobAvailability => "blob_availability",
            Self::WitnessInclusion => "witness_inclusion",
            Self::PqProver => "pq_prover",
            Self::FeeObservation => "fee_observation",
            Self::RedactionEnvelope => "redaction_envelope",
            Self::SettlementBatch => "settlement_batch",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVote {
    Accept,
    Reject,
    Challenge,
    Abstain,
}

impl AttestationVote {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Reject => "reject",
            Self::Challenge => "challenge",
            Self::Abstain => "abstain",
        }
    }

    pub fn accepts(self) -> bool {
        matches!(self, Self::Accept)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Draft,
    Queued,
    Attested,
    Settling,
    Settled,
    Disputed,
    Cancelled,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Queued => "queued",
            Self::Attested => "attested",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ThrottleAction {
    Allow,
    Delay,
    ReduceRebate,
    RequireMoreAttestations,
    Reject,
    SlashBond,
}

impl ThrottleAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Delay => "delay",
            Self::ReduceRebate => "reduce_rebate",
            Self::RequireMoreAttestations => "require_more_attestations",
            Self::Reject => "reject",
            Self::SlashBond => "slash_bond",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RedactionScope {
    AmountOnly,
    DestinationOnly,
    FeeAndWitness,
    FullRefundEnvelope,
    OperatorSummary,
}

impl RedactionScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AmountOnly => "amount_only",
            Self::DestinationOnly => "destination_only",
            Self::FeeAndWitness => "fee_and_witness",
            Self::FullRefundEnvelope => "full_refund_envelope",
            Self::OperatorSummary => "operator_summary",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub devnet_height: u64,
    pub monero_network: String,
    pub l2_network: String,
    pub refund_asset_id: String,
    pub fee_asset_id: String,
    pub epoch_blocks: u64,
    pub route_ttl_blocks: u64,
    pub claim_ttl_blocks: u64,
    pub settlement_delay_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub low_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub blob_rebate_bps: u64,
    pub witness_rebate_bps: u64,
    pub prover_rebate_bps: u64,
    pub da_rebate_bps: u64,
    pub operator_carry_bps: u64,
    pub slash_bps: u64,
    pub pq_attestation_scheme: String,
    pub pq_da_scheme: String,
    pub confidential_refund_scheme: String,
    pub blob_witness_scheme: String,
    pub redaction_scheme: String,
    pub max_claims_per_epoch: usize,
    pub max_route_fanout: usize,
    pub throttle_window_blocks: u64,
    pub throttle_claim_limit: u64,
    pub redaction_budget_per_epoch: u64,
    pub require_da_attestation: bool,
    pub require_prover_attestation: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            devnet_height: DEFAULT_DEVNET_HEIGHT,
            monero_network: "monero-devnet".to_string(),
            l2_network: "nebula-devnet".to_string(),
            refund_asset_id: "wxmr-devnet".to_string(),
            fee_asset_id: "piconero-devnet".to_string(),
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            route_ttl_blocks: DEFAULT_ROUTE_TTL_BLOCKS,
            claim_ttl_blocks: DEFAULT_CLAIM_TTL_BLOCKS,
            settlement_delay_blocks: DEFAULT_SETTLEMENT_DELAY_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            low_fee_bps: DEFAULT_LOW_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            blob_rebate_bps: DEFAULT_BLOB_REBATE_BPS,
            witness_rebate_bps: DEFAULT_WITNESS_REBATE_BPS,
            prover_rebate_bps: DEFAULT_PROVER_REBATE_BPS,
            da_rebate_bps: DEFAULT_DA_REBATE_BPS,
            operator_carry_bps: DEFAULT_OPERATOR_CARRY_BPS,
            slash_bps: DEFAULT_SLASH_BPS,
            pq_attestation_scheme: PQ_ATTESTATION_SCHEME.to_string(),
            pq_da_scheme: PQ_DA_SCHEME.to_string(),
            confidential_refund_scheme: CONFIDENTIAL_REFUND_SCHEME.to_string(),
            blob_witness_scheme: BLOB_WITNESS_SCHEME.to_string(),
            redaction_scheme: REDACTION_SCHEME.to_string(),
            max_claims_per_epoch: 65_536,
            max_route_fanout: 8,
            throttle_window_blocks: 24,
            throttle_claim_limit: 96,
            redaction_budget_per_epoch: 20_000,
            require_da_attestation: true,
            require_prover_attestation: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counters {
    pub next_sequence: u64,
    pub routes: u64,
    pub claims: u64,
    pub pq_attestations: u64,
    pub settlement_batches: u64,
    pub rebates: u64,
    pub throttles: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub accepted_claims: u64,
    pub rejected_claims: u64,
    pub delayed_claims: u64,
    pub settled_claims: u64,
    pub duplicate_nullifiers: u64,
    pub abuse_signals: u64,
    pub event_count: u64,
}

impl Counters {
    pub fn new() -> Self {
        Self {
            next_sequence: 1,
            routes: 0,
            claims: 0,
            pq_attestations: 0,
            settlement_batches: 0,
            rebates: 0,
            throttles: 0,
            redaction_budgets: 0,
            operator_summaries: 0,
            accepted_claims: 0,
            rejected_claims: 0,
            delayed_claims: 0,
            settled_claims: 0,
            duplicate_nullifiers: 0,
            abuse_signals: 0,
            event_count: 0,
        }
    }
}

impl Default for Counters {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Roots {
    pub route_root: String,
    pub claim_root: String,
    pub pq_attestation_root: String,
    pub settlement_root: String,
    pub rebate_root: String,
    pub throttle_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub nullifier_root: String,
    pub event_root: String,
    pub cost_priority_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        let mut roots = Self {
            route_root: empty_root("ROUTE"),
            claim_root: empty_root("CLAIM"),
            pq_attestation_root: empty_root("PQ-ATTESTATION"),
            settlement_root: empty_root("SETTLEMENT"),
            rebate_root: empty_root("REBATE"),
            throttle_root: empty_root("THROTTLE"),
            redaction_budget_root: empty_root("REDACTION-BUDGET"),
            operator_summary_root: empty_root("OPERATOR-SUMMARY"),
            nullifier_root: empty_root("NULLIFIER"),
            event_root: empty_root("EVENT"),
            cost_priority_root: empty_root("COST-PRIORITY"),
            public_record_root: empty_root("PUBLIC-RECORD"),
            state_root: String::new(),
        };
        roots.state_root = roots.compute_state_root();
        roots
    }

    pub fn compute_state_root(&self) -> String {
        hash_json(
            "STATE-ROOT",
            &json!({
                "claim_root": self.claim_root,
                "cost_priority_root": self.cost_priority_root,
                "event_root": self.event_root,
                "nullifier_root": self.nullifier_root,
                "operator_summary_root": self.operator_summary_root,
                "pq_attestation_root": self.pq_attestation_root,
                "public_record_root": self.public_record_root,
                "rebate_root": self.rebate_root,
                "redaction_budget_root": self.redaction_budget_root,
                "route_root": self.route_root,
                "settlement_root": self.settlement_root,
                "throttle_root": self.throttle_root
            }),
        )
    }
}

impl Default for Roots {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqSignatureEnvelope {
    pub scheme: String,
    pub public_key_commitment: String,
    pub transcript_hash: String,
    pub signature_commitment: String,
    pub security_bits: u16,
}

impl PqSignatureEnvelope {
    pub fn devnet(label: &str, public_key_commitment: &str, signature_commitment: &str) -> Self {
        Self {
            scheme: PQ_ATTESTATION_SCHEME.to_string(),
            public_key_commitment: public_key_commitment.to_string(),
            transcript_hash: deterministic_id(
                "PQ-SIGNATURE-TRANSCRIPT",
                &[label, public_key_commitment, signature_commitment],
            ),
            signature_commitment: signature_commitment.to_string(),
            security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfidentialAmount {
    pub asset_id: String,
    pub amount_commitment: String,
    pub encrypted_amount: String,
    pub blinding_commitment: String,
}

impl ConfidentialAmount {
    pub fn devnet(asset_id: &str, label: &str, amount: u64) -> Self {
        Self {
            asset_id: asset_id.to_string(),
            amount_commitment: commitment_id("AMOUNT", &[label, &amount.to_string()]),
            encrypted_amount: commitment_id("ENCRYPTED-AMOUNT", &[label, &amount.to_string()]),
            blinding_commitment: commitment_id("BLINDING", &[label]),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefundRoute {
    pub route_id: String,
    pub operator_id: String,
    pub lane: RefundLane,
    pub status: RouteStatus,
    pub priority_weight: u64,
    pub max_fee_bps: u64,
    pub rebate_bps: u64,
    pub capacity_commitment: String,
    pub consumed_commitment: String,
    pub route_nullifier: String,
    pub destination_set_root: String,
    pub witness_cost_oracle_root: String,
    pub da_committee_root: String,
    pub prover_set_root: String,
    pub privacy_set_size: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub throttle_policy_id: Option<String>,
}

impl RefundRoute {
    pub fn public_record(&self) -> Value {
        json!({
            "da_committee_root": self.da_committee_root,
            "destination_set_root": self.destination_set_root,
            "expires_height": self.expires_height,
            "lane": self.lane.as_str(),
            "max_fee_bps": self.max_fee_bps,
            "opened_height": self.opened_height,
            "operator_id": self.operator_id,
            "priority_weight": self.priority_weight,
            "privacy_set_size": self.privacy_set_size,
            "prover_set_root": self.prover_set_root,
            "rebate_bps": self.rebate_bps,
            "route_id": self.route_id,
            "status": self.status.as_str(),
            "throttle_policy_id": self.throttle_policy_id,
            "witness_cost_oracle_root": self.witness_cost_oracle_root
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlobWitnessClaim {
    pub claim_id: String,
    pub route_id: String,
    pub lane: RefundLane,
    pub claimant_commitment: String,
    pub blob_commitment: String,
    pub blob_size_bytes: u64,
    pub witness_commitment: String,
    pub witness_bytes: u64,
    pub da_cost_commitment: ConfidentialAmount,
    pub witness_cost_commitment: ConfidentialAmount,
    pub prover_cost_commitment: ConfidentialAmount,
    pub requested_refund_commitment: ConfidentialAmount,
    pub fee_paid_commitment: ConfidentialAmount,
    pub refund_note_commitment: String,
    pub refund_destination_commitment: String,
    pub claim_nullifier: String,
    pub redaction_budget_id: Option<String>,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub status: ClaimStatus,
}

impl BlobWitnessClaim {
    pub fn total_cost_commitment_root(&self) -> String {
        hash_json(
            "CLAIM-COST-COMMITMENT-ROOT",
            &json!({
                "da": self.da_cost_commitment,
                "fee_paid": self.fee_paid_commitment,
                "prover": self.prover_cost_commitment,
                "requested_refund": self.requested_refund_commitment,
                "witness": self.witness_cost_commitment
            }),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "blob_commitment": self.blob_commitment,
            "blob_size_bytes": self.blob_size_bytes,
            "claim_id": self.claim_id,
            "cost_commitment_root": self.total_cost_commitment_root(),
            "expires_height": self.expires_height,
            "lane": self.lane.as_str(),
            "redaction_budget_id": self.redaction_budget_id,
            "refund_destination_commitment": self.refund_destination_commitment,
            "refund_note_commitment": self.refund_note_commitment,
            "route_id": self.route_id,
            "status": self.status.as_str(),
            "submitted_height": self.submitted_height,
            "witness_bytes": self.witness_bytes,
            "witness_commitment": self.witness_commitment
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqDaProverAttestation {
    pub attestation_id: String,
    pub kind: AttestationKind,
    pub subject_id: String,
    pub attester_id: String,
    pub committee_id: String,
    pub vote: AttestationVote,
    pub observed_root: String,
    pub da_blob_root: String,
    pub witness_root: String,
    pub prover_receipt_root: String,
    pub fee_observation_root: String,
    pub redaction_envelope_root: String,
    pub pq_signature: PqSignatureEnvelope,
    pub evidence_hash: String,
    pub height: u64,
}

impl PqDaProverAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "attester_id": self.attester_id,
            "committee_id": self.committee_id,
            "da_blob_root": self.da_blob_root,
            "evidence_hash": self.evidence_hash,
            "fee_observation_root": self.fee_observation_root,
            "height": self.height,
            "kind": self.kind.as_str(),
            "observed_root": self.observed_root,
            "prover_receipt_root": self.prover_receipt_root,
            "redaction_envelope_root": self.redaction_envelope_root,
            "subject_id": self.subject_id,
            "vote": self.vote.as_str(),
            "witness_root": self.witness_root
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettlementBatch {
    pub settlement_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub claim_root: String,
    pub claim_ids: BTreeSet<String>,
    pub attestation_root: String,
    pub rebate_root: String,
    pub confidential_debit_root: String,
    pub confidential_credit_root: String,
    pub operator_carry_commitment: ConfidentialAmount,
    pub settlement_anchor: String,
    pub queued_height: u64,
    pub settle_after_height: u64,
    pub settled_height: Option<u64>,
    pub status: SettlementStatus,
}

impl SettlementBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_root": self.attestation_root,
            "claim_count": self.claim_ids.len(),
            "claim_root": self.claim_root,
            "confidential_credit_root": self.confidential_credit_root,
            "confidential_debit_root": self.confidential_debit_root,
            "epoch": self.epoch,
            "operator_carry_commitment": self.operator_carry_commitment,
            "operator_id": self.operator_id,
            "queued_height": self.queued_height,
            "rebate_root": self.rebate_root,
            "settle_after_height": self.settle_after_height,
            "settled_height": self.settled_height,
            "settlement_anchor": self.settlement_anchor,
            "settlement_id": self.settlement_id,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfidentialRebate {
    pub rebate_id: String,
    pub claim_id: String,
    pub settlement_id: Option<String>,
    pub lane: RefundLane,
    pub gross_cost_commitment: ConfidentialAmount,
    pub rebate_commitment: ConfidentialAmount,
    pub operator_carry_commitment: ConfidentialAmount,
    pub refund_note_commitment: String,
    pub refund_nullifier: String,
    pub rebate_bps: u64,
    pub issued_height: u64,
    pub settled: bool,
}

impl ConfidentialRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "issued_height": self.issued_height,
            "lane": self.lane.as_str(),
            "operator_carry_commitment": self.operator_carry_commitment,
            "rebate_bps": self.rebate_bps,
            "rebate_commitment": self.rebate_commitment,
            "rebate_id": self.rebate_id,
            "refund_note_commitment": self.refund_note_commitment,
            "settled": self.settled,
            "settlement_id": self.settlement_id
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AntiAbuseThrottle {
    pub throttle_id: String,
    pub subject_id: String,
    pub operator_id: String,
    pub action: ThrottleAction,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub claim_count: u64,
    pub cumulative_blob_bytes: u64,
    pub cumulative_witness_bytes: u64,
    pub risk_score: u32,
    pub reason_code: String,
    pub active: bool,
}

impl AntiAbuseThrottle {
    pub fn public_record(&self) -> Value {
        json!({
            "action": self.action.as_str(),
            "active": self.active,
            "claim_count": self.claim_count,
            "cumulative_blob_bytes": self.cumulative_blob_bytes,
            "cumulative_witness_bytes": self.cumulative_witness_bytes,
            "operator_id": self.operator_id,
            "reason_code": self.reason_code,
            "risk_score": self.risk_score,
            "subject_id": self.subject_id,
            "throttle_id": self.throttle_id,
            "window_end_height": self.window_end_height,
            "window_start_height": self.window_start_height
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub owner_commitment: String,
    pub scope: RedactionScope,
    pub epoch: u64,
    pub budget_units: u64,
    pub consumed_units: u64,
    pub envelope_root: String,
    pub disclosure_policy_root: String,
    pub audit_tag: String,
    pub active: bool,
}

impl RedactionBudget {
    pub fn remaining_units(&self) -> u64 {
        self.budget_units.saturating_sub(self.consumed_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "active": self.active,
            "audit_tag": self.audit_tag,
            "budget_id": self.budget_id,
            "budget_units": self.budget_units,
            "consumed_units": self.consumed_units,
            "disclosure_policy_root": self.disclosure_policy_root,
            "envelope_root": self.envelope_root,
            "epoch": self.epoch,
            "remaining_units": self.remaining_units(),
            "scope": self.scope.as_str()
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub routes_opened: u64,
    pub claims_routed: u64,
    pub claims_settled: u64,
    pub claims_rejected: u64,
    pub blob_bytes_refunded: u64,
    pub witness_bytes_refunded: u64,
    pub total_rebate_commitment: ConfidentialAmount,
    pub operator_carry_commitment: ConfidentialAmount,
    pub throttle_count: u64,
    pub average_risk_score: u32,
    pub da_attestation_root: String,
    pub prover_attestation_root: String,
    pub summary_root: String,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "average_risk_score": self.average_risk_score,
            "blob_bytes_refunded": self.blob_bytes_refunded,
            "claims_rejected": self.claims_rejected,
            "claims_routed": self.claims_routed,
            "claims_settled": self.claims_settled,
            "da_attestation_root": self.da_attestation_root,
            "epoch": self.epoch,
            "operator_carry_commitment": self.operator_carry_commitment,
            "operator_id": self.operator_id,
            "prover_attestation_root": self.prover_attestation_root,
            "routes_opened": self.routes_opened,
            "summary_id": self.summary_id,
            "summary_root": self.summary_root,
            "throttle_count": self.throttle_count,
            "total_rebate_commitment": self.total_rebate_commitment,
            "witness_bytes_refunded": self.witness_bytes_refunded
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub routes: BTreeMap<String, RefundRoute>,
    pub claims: BTreeMap<String, BlobWitnessClaim>,
    pub pq_attestations: BTreeMap<String, PqDaProverAttestation>,
    pub settlements: BTreeMap<String, SettlementBatch>,
    pub rebates: BTreeMap<String, ConfidentialRebate>,
    pub throttles: BTreeMap<String, AntiAbuseThrottle>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub nullifiers: BTreeSet<String>,
    pub event_log: Vec<String>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::new(),
            roots: Roots::empty(),
            routes: BTreeMap::new(),
            claims: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            settlements: BTreeMap::new(),
            rebates: BTreeMap::new(),
            throttles: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            event_log: Vec::new(),
        };
        state.recompute_roots();
        state
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet())
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        state_root(self)
    }

    pub fn open_refund_route(
        &mut self,
        operator_id: &str,
        lane: RefundLane,
        capacity_commitment: &str,
        destination_set_root: &str,
        witness_cost_oracle_root: &str,
        da_committee_root: &str,
        prover_set_root: &str,
        opened_height: u64,
    ) -> Result<String> {
        require_nonempty("operator_id", operator_id)?;
        require_nonempty("capacity_commitment", capacity_commitment)?;
        if self.routes.len() >= MAX_ROUTES {
            return Err("route capacity exhausted".to_string());
        }

        let route_id = deterministic_id(
            "REFUND-ROUTE",
            &[
                operator_id,
                lane.as_str(),
                capacity_commitment,
                &opened_height.to_string(),
                &self.counters.next_sequence.to_string(),
            ],
        );
        let route_nullifier = nullifier_id("ROUTE", &[operator_id, lane.as_str(), &route_id]);
        self.insert_nullifier(&route_nullifier)?;

        let route = RefundRoute {
            route_id: route_id.clone(),
            operator_id: operator_id.to_string(),
            lane,
            status: RouteStatus::Open,
            priority_weight: lane.priority_weight(),
            max_fee_bps: self.config.max_user_fee_bps,
            rebate_bps: lane.default_rebate_bps(&self.config),
            capacity_commitment: capacity_commitment.to_string(),
            consumed_commitment: commitment_id("ROUTE-CONSUMED", &[&route_id, "0"]),
            route_nullifier,
            destination_set_root: destination_set_root.to_string(),
            witness_cost_oracle_root: witness_cost_oracle_root.to_string(),
            da_committee_root: da_committee_root.to_string(),
            prover_set_root: prover_set_root.to_string(),
            privacy_set_size: self.config.min_privacy_set_size,
            opened_height,
            expires_height: opened_height.saturating_add(self.config.route_ttl_blocks),
            throttle_policy_id: None,
        };
        self.routes.insert(route_id.clone(), route);
        self.counters.routes += 1;
        self.push_event("route_opened", &route_id);
        self.recompute_roots();
        Ok(route_id)
    }

    pub fn submit_blob_witness_claim(
        &mut self,
        route_id: &str,
        claimant_commitment: &str,
        blob_commitment: &str,
        blob_size_bytes: u64,
        witness_commitment: &str,
        witness_bytes: u64,
        requested_refund_commitment: ConfidentialAmount,
        fee_paid_commitment: ConfidentialAmount,
        submitted_height: u64,
    ) -> Result<String> {
        require_nonempty("claimant_commitment", claimant_commitment)?;
        require_nonempty("blob_commitment", blob_commitment)?;
        require_nonempty("witness_commitment", witness_commitment)?;
        if self.claims.len() >= MAX_CLAIMS {
            return Err("claim capacity exhausted".to_string());
        }

        let route = self
            .routes
            .get(route_id)
            .ok_or_else(|| format!("unknown route: {route_id}"))?;
        if !route.status.accepts_claims() {
            return Err(format!("route does not accept claims: {route_id}"));
        }
        if submitted_height > route.expires_height {
            return Err(format!("route expired: {route_id}"));
        }

        let claim_nullifier = nullifier_id(
            "CLAIM",
            &[
                route_id,
                claimant_commitment,
                blob_commitment,
                witness_commitment,
            ],
        );
        self.insert_nullifier(&claim_nullifier)?;

        let throttle_action = self.preview_throttle_action(&route.operator_id, submitted_height);
        if matches!(
            throttle_action,
            ThrottleAction::Reject | ThrottleAction::SlashBond
        ) {
            self.counters.rejected_claims += 1;
            return Err(format!(
                "claim rejected by throttle: {}",
                throttle_action.as_str()
            ));
        }

        let claim_id = deterministic_id(
            "BLOB-WITNESS-CLAIM",
            &[
                route_id,
                claimant_commitment,
                blob_commitment,
                witness_commitment,
                &submitted_height.to_string(),
                &self.counters.next_sequence.to_string(),
            ],
        );
        let lane = route.lane;
        let claim = BlobWitnessClaim {
            claim_id: claim_id.clone(),
            route_id: route_id.to_string(),
            lane,
            claimant_commitment: claimant_commitment.to_string(),
            blob_commitment: blob_commitment.to_string(),
            blob_size_bytes,
            witness_commitment: witness_commitment.to_string(),
            witness_bytes,
            da_cost_commitment: ConfidentialAmount::devnet(
                &self.config.fee_asset_id,
                &format!("{claim_id}:da"),
                blob_size_bytes,
            ),
            witness_cost_commitment: ConfidentialAmount::devnet(
                &self.config.fee_asset_id,
                &format!("{claim_id}:witness"),
                witness_bytes,
            ),
            prover_cost_commitment: ConfidentialAmount::devnet(
                &self.config.fee_asset_id,
                &format!("{claim_id}:prover"),
                blob_size_bytes.saturating_add(witness_bytes) / 4,
            ),
            requested_refund_commitment,
            fee_paid_commitment,
            refund_note_commitment: commitment_id("REFUND-NOTE", &[&claim_id]),
            refund_destination_commitment: commitment_id(
                "REFUND-DESTINATION",
                &[claimant_commitment, route_id],
            ),
            claim_nullifier,
            redaction_budget_id: None,
            submitted_height,
            expires_height: submitted_height.saturating_add(self.config.claim_ttl_blocks),
            status: if matches!(throttle_action, ThrottleAction::Delay) {
                ClaimStatus::Submitted
            } else {
                ClaimStatus::Routed
            },
        };
        self.claims.insert(claim_id.clone(), claim);
        self.counters.claims += 1;
        self.counters.accepted_claims += 1;
        if matches!(throttle_action, ThrottleAction::Delay) {
            self.counters.delayed_claims += 1;
        }
        self.push_event("claim_submitted", &claim_id);
        self.recompute_roots();
        Ok(claim_id)
    }

    pub fn record_pq_attestation(
        &mut self,
        kind: AttestationKind,
        subject_id: &str,
        attester_id: &str,
        committee_id: &str,
        vote: AttestationVote,
        observed_root: &str,
        pq_signature: PqSignatureEnvelope,
        height: u64,
    ) -> Result<String> {
        require_nonempty("subject_id", subject_id)?;
        require_nonempty("attester_id", attester_id)?;
        require_nonempty("committee_id", committee_id)?;
        require_nonempty("observed_root", observed_root)?;
        self.require_known_subject(subject_id)?;
        self.require_pq_signature(&pq_signature)?;
        if self.pq_attestations.len() >= MAX_ATTESTATIONS {
            return Err("attestation capacity exhausted".to_string());
        }

        let attestation_id = deterministic_id(
            "PQ-DA-PROVER-ATTESTATION",
            &[
                kind.as_str(),
                subject_id,
                attester_id,
                committee_id,
                observed_root,
                &height.to_string(),
            ],
        );
        let attestation = PqDaProverAttestation {
            attestation_id: attestation_id.clone(),
            kind,
            subject_id: subject_id.to_string(),
            attester_id: attester_id.to_string(),
            committee_id: committee_id.to_string(),
            vote,
            observed_root: observed_root.to_string(),
            da_blob_root: commitment_id("DA-BLOB-ROOT", &[subject_id, observed_root]),
            witness_root: commitment_id("WITNESS-ROOT", &[subject_id, observed_root]),
            prover_receipt_root: commitment_id("PROVER-RECEIPT-ROOT", &[subject_id, observed_root]),
            fee_observation_root: commitment_id(
                "FEE-OBSERVATION-ROOT",
                &[subject_id, observed_root],
            ),
            redaction_envelope_root: commitment_id(
                "REDACTION-ENVELOPE-ROOT",
                &[subject_id, observed_root],
            ),
            pq_signature,
            evidence_hash: deterministic_id("ATTESTATION-EVIDENCE", &[subject_id, observed_root]),
            height,
        };
        self.pq_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.pq_attestations += 1;
        if vote.accepts() {
            if let Some(claim) = self.claims.get_mut(subject_id) {
                claim.status = ClaimStatus::Attested;
            }
        }
        self.push_event("pq_attestation_recorded", &attestation_id);
        self.recompute_roots();
        Ok(attestation_id)
    }

    pub fn allocate_redaction_budget(
        &mut self,
        owner_commitment: &str,
        scope: RedactionScope,
        epoch: u64,
        budget_units: u64,
    ) -> Result<String> {
        require_nonempty("owner_commitment", owner_commitment)?;
        if self.redaction_budgets.len() >= MAX_REDACTION_BUDGETS {
            return Err("redaction budget capacity exhausted".to_string());
        }
        if budget_units > self.config.redaction_budget_per_epoch {
            return Err("redaction budget exceeds epoch allowance".to_string());
        }
        let budget_id = deterministic_id(
            "REDACTION-BUDGET",
            &[
                owner_commitment,
                scope.as_str(),
                &epoch.to_string(),
                &budget_units.to_string(),
            ],
        );
        let budget = RedactionBudget {
            budget_id: budget_id.clone(),
            owner_commitment: owner_commitment.to_string(),
            scope,
            epoch,
            budget_units,
            consumed_units: 0,
            envelope_root: commitment_id("REDACTION-ENVELOPE", &[&budget_id]),
            disclosure_policy_root: commitment_id("DISCLOSURE-POLICY", &[&budget_id]),
            audit_tag: deterministic_id("REDACTION-AUDIT-TAG", &[&budget_id]),
            active: true,
        };
        self.redaction_budgets.insert(budget_id.clone(), budget);
        self.counters.redaction_budgets += 1;
        self.push_event("redaction_budget_allocated", &budget_id);
        self.recompute_roots();
        Ok(budget_id)
    }

    pub fn attach_redaction_budget(
        &mut self,
        claim_id: &str,
        budget_id: &str,
        units: u64,
    ) -> Result<()> {
        let budget = self
            .redaction_budgets
            .get_mut(budget_id)
            .ok_or_else(|| format!("unknown redaction budget: {budget_id}"))?;
        if !budget.active {
            return Err(format!("redaction budget inactive: {budget_id}"));
        }
        if budget.remaining_units() < units {
            return Err(format!("redaction budget exhausted: {budget_id}"));
        }
        let claim = self
            .claims
            .get_mut(claim_id)
            .ok_or_else(|| format!("unknown claim: {claim_id}"))?;
        budget.consumed_units = budget.consumed_units.saturating_add(units);
        claim.redaction_budget_id = Some(budget_id.to_string());
        claim.status = ClaimStatus::Budgeted;
        self.push_event("redaction_budget_attached", claim_id);
        self.recompute_roots();
        Ok(())
    }

    pub fn issue_rebate(&mut self, claim_id: &str, issued_height: u64) -> Result<String> {
        if self.rebates.len() >= MAX_REBATES {
            return Err("rebate capacity exhausted".to_string());
        }
        let claim = self
            .claims
            .get(claim_id)
            .ok_or_else(|| format!("unknown claim: {claim_id}"))?;
        if !matches!(
            claim.status,
            ClaimStatus::Attested | ClaimStatus::Budgeted | ClaimStatus::Queued
        ) {
            return Err(format!("claim not rebate-ready: {claim_id}"));
        }
        let route = self
            .routes
            .get(&claim.route_id)
            .ok_or_else(|| format!("unknown route: {}", claim.route_id))?;
        let lane = claim.lane;
        let gross_cost_commitment = claim.requested_refund_commitment.clone();
        let refund_note_commitment = claim.refund_note_commitment.clone();
        let rebate_bps = route.rebate_bps;
        let rebate_id = deterministic_id(
            "CONFIDENTIAL-REBATE",
            &[claim_id, &issued_height.to_string()],
        );
        let refund_nullifier = nullifier_id("REBATE", &[claim_id, &rebate_id]);
        self.insert_nullifier(&refund_nullifier)?;

        let claim = self
            .claims
            .get_mut(claim_id)
            .ok_or_else(|| format!("unknown claim: {claim_id}"))?;
        let operator_carry_commitment = ConfidentialAmount::devnet(
            &self.config.refund_asset_id,
            &format!("{rebate_id}:operator-carry"),
            self.config.operator_carry_bps,
        );
        let rebate = ConfidentialRebate {
            rebate_id: rebate_id.clone(),
            claim_id: claim_id.to_string(),
            settlement_id: None,
            lane,
            gross_cost_commitment,
            rebate_commitment: ConfidentialAmount::devnet(
                &self.config.refund_asset_id,
                &format!("{rebate_id}:rebate"),
                rebate_bps,
            ),
            operator_carry_commitment,
            refund_note_commitment,
            refund_nullifier,
            rebate_bps,
            issued_height,
            settled: false,
        };
        self.rebates.insert(rebate_id.clone(), rebate);
        claim.status = ClaimStatus::Queued;
        self.counters.rebates += 1;
        self.push_event("rebate_issued", &rebate_id);
        self.recompute_roots();
        Ok(rebate_id)
    }

    pub fn queue_settlement(
        &mut self,
        operator_id: &str,
        epoch: u64,
        claim_ids: BTreeSet<String>,
        queued_height: u64,
    ) -> Result<String> {
        require_nonempty("operator_id", operator_id)?;
        if self.settlements.len() >= MAX_SETTLEMENTS {
            return Err("settlement capacity exhausted".to_string());
        }
        if claim_ids.is_empty() {
            return Err("settlement requires at least one claim".to_string());
        }

        for claim_id in &claim_ids {
            let claim = self
                .claims
                .get(claim_id)
                .ok_or_else(|| format!("unknown claim: {claim_id}"))?;
            if !matches!(claim.status, ClaimStatus::Queued | ClaimStatus::Attested) {
                return Err(format!("claim is not settlement-ready: {claim_id}"));
            }
        }

        let settlement_id = deterministic_id(
            "SETTLEMENT-BATCH",
            &[
                operator_id,
                &epoch.to_string(),
                &set_root("SETTLEMENT-CLAIMS", &claim_ids),
                &queued_height.to_string(),
            ],
        );
        let claim_root = set_root("SETTLEMENT-CLAIMS", &claim_ids);
        let attestation_ids = self
            .pq_attestations
            .values()
            .filter(|attestation| claim_ids.contains(&attestation.subject_id))
            .map(|attestation| attestation.attestation_id.clone())
            .collect::<BTreeSet<_>>();
        let rebate_ids = self
            .rebates
            .values()
            .filter(|rebate| claim_ids.contains(&rebate.claim_id))
            .map(|rebate| rebate.rebate_id.clone())
            .collect::<BTreeSet<_>>();
        let settlement = SettlementBatch {
            settlement_id: settlement_id.clone(),
            operator_id: operator_id.to_string(),
            epoch,
            claim_root: claim_root.clone(),
            claim_ids: claim_ids.clone(),
            attestation_root: set_root("SETTLEMENT-ATTESTATIONS", &attestation_ids),
            rebate_root: set_root("SETTLEMENT-REBATES", &rebate_ids),
            confidential_debit_root: commitment_id("SETTLEMENT-DEBIT", &[&settlement_id]),
            confidential_credit_root: commitment_id("SETTLEMENT-CREDIT", &[&settlement_id]),
            operator_carry_commitment: ConfidentialAmount::devnet(
                &self.config.refund_asset_id,
                &format!("{settlement_id}:carry"),
                self.config.operator_carry_bps,
            ),
            settlement_anchor: commitment_id("SETTLEMENT-ANCHOR", &[&settlement_id, &claim_root]),
            queued_height,
            settle_after_height: queued_height.saturating_add(self.config.settlement_delay_blocks),
            settled_height: None,
            status: SettlementStatus::Queued,
        };
        for claim_id in &claim_ids {
            if let Some(claim) = self.claims.get_mut(claim_id) {
                claim.status = ClaimStatus::Settling;
            }
        }
        for rebate in self.rebates.values_mut() {
            if claim_ids.contains(&rebate.claim_id) {
                rebate.settlement_id = Some(settlement_id.clone());
            }
        }
        self.settlements.insert(settlement_id.clone(), settlement);
        self.counters.settlement_batches += 1;
        self.push_event("settlement_queued", &settlement_id);
        self.recompute_roots();
        Ok(settlement_id)
    }

    pub fn settle_batch(&mut self, settlement_id: &str, settled_height: u64) -> Result<()> {
        let settlement = self
            .settlements
            .get_mut(settlement_id)
            .ok_or_else(|| format!("unknown settlement: {settlement_id}"))?;
        if settled_height < settlement.settle_after_height {
            return Err(format!("settlement delay not met: {settlement_id}"));
        }
        settlement.status = SettlementStatus::Settled;
        settlement.settled_height = Some(settled_height);
        for claim_id in &settlement.claim_ids {
            if let Some(claim) = self.claims.get_mut(claim_id) {
                claim.status = ClaimStatus::Settled;
                self.counters.settled_claims += 1;
            }
        }
        for rebate in self.rebates.values_mut() {
            if rebate.settlement_id.as_deref() == Some(settlement_id) {
                rebate.settled = true;
            }
        }
        self.push_event("settlement_settled", settlement_id);
        self.recompute_roots();
        Ok(())
    }

    pub fn apply_throttle(
        &mut self,
        subject_id: &str,
        operator_id: &str,
        action: ThrottleAction,
        window_start_height: u64,
        claim_count: u64,
        cumulative_blob_bytes: u64,
        cumulative_witness_bytes: u64,
        risk_score: u32,
        reason_code: &str,
    ) -> Result<String> {
        require_nonempty("subject_id", subject_id)?;
        require_nonempty("operator_id", operator_id)?;
        require_nonempty("reason_code", reason_code)?;
        if self.throttles.len() >= MAX_THROTTLES {
            return Err("throttle capacity exhausted".to_string());
        }
        let throttle_id = deterministic_id(
            "ANTI-ABUSE-THROTTLE",
            &[
                subject_id,
                operator_id,
                action.as_str(),
                &window_start_height.to_string(),
                reason_code,
            ],
        );
        let throttle = AntiAbuseThrottle {
            throttle_id: throttle_id.clone(),
            subject_id: subject_id.to_string(),
            operator_id: operator_id.to_string(),
            action,
            window_start_height,
            window_end_height: window_start_height
                .saturating_add(self.config.throttle_window_blocks),
            claim_count,
            cumulative_blob_bytes,
            cumulative_witness_bytes,
            risk_score,
            reason_code: reason_code.to_string(),
            active: true,
        };
        if matches!(action, ThrottleAction::Reject | ThrottleAction::SlashBond) {
            self.counters.abuse_signals += 1;
        }
        self.throttles.insert(throttle_id.clone(), throttle);
        self.counters.throttles += 1;
        self.push_event("throttle_applied", &throttle_id);
        self.recompute_roots();
        Ok(throttle_id)
    }

    pub fn summarize_operator(&mut self, operator_id: &str, epoch: u64) -> Result<String> {
        require_nonempty("operator_id", operator_id)?;
        if self.operator_summaries.len() >= MAX_OPERATOR_SUMMARIES {
            return Err("operator summary capacity exhausted".to_string());
        }
        let route_ids = self
            .routes
            .values()
            .filter(|route| route.operator_id == operator_id)
            .map(|route| route.route_id.clone())
            .collect::<BTreeSet<_>>();
        let claims = self
            .claims
            .values()
            .filter(|claim| route_ids.contains(&claim.route_id))
            .collect::<Vec<_>>();
        let settled = claims
            .iter()
            .filter(|claim| claim.status == ClaimStatus::Settled)
            .count() as u64;
        let rejected = claims
            .iter()
            .filter(|claim| matches!(claim.status, ClaimStatus::Rejected | ClaimStatus::Expired))
            .count() as u64;
        let blob_bytes = claims
            .iter()
            .map(|claim| claim.blob_size_bytes)
            .fold(0_u64, u64::saturating_add);
        let witness_bytes = claims
            .iter()
            .map(|claim| claim.witness_bytes)
            .fold(0_u64, u64::saturating_add);
        let throttles = self
            .throttles
            .values()
            .filter(|throttle| throttle.operator_id == operator_id)
            .collect::<Vec<_>>();
        let risk_total = throttles
            .iter()
            .map(|throttle| throttle.risk_score as u64)
            .fold(0_u64, u64::saturating_add);
        let average_risk_score = if throttles.is_empty() {
            0
        } else {
            (risk_total / throttles.len() as u64) as u32
        };
        let da_attestations = self
            .pq_attestations
            .values()
            .filter(|attestation| attestation.kind == AttestationKind::BlobAvailability)
            .map(|attestation| attestation.attestation_id.clone())
            .collect::<BTreeSet<_>>();
        let prover_attestations = self
            .pq_attestations
            .values()
            .filter(|attestation| attestation.kind == AttestationKind::PqProver)
            .map(|attestation| attestation.attestation_id.clone())
            .collect::<BTreeSet<_>>();
        let summary_id = deterministic_id("OPERATOR-SUMMARY", &[operator_id, &epoch.to_string()]);
        let summary_root = hash_json(
            "OPERATOR-SUMMARY-ROOT",
            &json!({
                "blob_bytes": blob_bytes,
                "claims": claims.len(),
                "epoch": epoch,
                "operator_id": operator_id,
                "settled": settled,
                "throttles": throttles.len(),
                "witness_bytes": witness_bytes
            }),
        );
        let summary = OperatorSummary {
            summary_id: summary_id.clone(),
            operator_id: operator_id.to_string(),
            epoch,
            routes_opened: route_ids.len() as u64,
            claims_routed: claims.len() as u64,
            claims_settled: settled,
            claims_rejected: rejected,
            blob_bytes_refunded: blob_bytes,
            witness_bytes_refunded: witness_bytes,
            total_rebate_commitment: ConfidentialAmount::devnet(
                &self.config.refund_asset_id,
                &format!("{summary_id}:rebates"),
                settled,
            ),
            operator_carry_commitment: ConfidentialAmount::devnet(
                &self.config.refund_asset_id,
                &format!("{summary_id}:carry"),
                self.config.operator_carry_bps,
            ),
            throttle_count: throttles.len() as u64,
            average_risk_score,
            da_attestation_root: set_root("OPERATOR-DA-ATTESTATIONS", &da_attestations),
            prover_attestation_root: set_root("OPERATOR-PROVER-ATTESTATIONS", &prover_attestations),
            summary_root,
        };
        self.operator_summaries.insert(summary_id.clone(), summary);
        self.counters.operator_summaries += 1;
        self.push_event("operator_summarized", &summary_id);
        self.recompute_roots();
        Ok(summary_id)
    }

    pub fn recompute_roots(&mut self) {
        self.roots.route_root = map_root("ROUTE", &self.routes);
        self.roots.claim_root = map_root("CLAIM", &self.claims);
        self.roots.pq_attestation_root = map_root("PQ-ATTESTATION", &self.pq_attestations);
        self.roots.settlement_root = map_root("SETTLEMENT", &self.settlements);
        self.roots.rebate_root = map_root("REBATE", &self.rebates);
        self.roots.throttle_root = map_root("THROTTLE", &self.throttles);
        self.roots.redaction_budget_root = map_root("REDACTION-BUDGET", &self.redaction_budgets);
        self.roots.operator_summary_root = map_root("OPERATOR-SUMMARY", &self.operator_summaries);
        self.roots.nullifier_root = set_root("NULLIFIER", &self.nullifiers);
        self.roots.event_root = string_root("EVENT", self.event_log.iter());
        self.roots.cost_priority_root = self.cost_priority_root();
        self.roots.public_record_root =
            hash_json("PUBLIC-RECORD", &self.public_record_without_state_root());
        self.roots.state_root = self.roots.compute_state_root();
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "config": self.config,
            "counters": self.counters,
            "roots": {
                "claim_root": self.roots.claim_root,
                "cost_priority_root": self.roots.cost_priority_root,
                "event_root": self.roots.event_root,
                "nullifier_root": self.roots.nullifier_root,
                "operator_summary_root": self.roots.operator_summary_root,
                "pq_attestation_root": self.roots.pq_attestation_root,
                "rebate_root": self.roots.rebate_root,
                "redaction_budget_root": self.roots.redaction_budget_root,
                "route_root": self.roots.route_root,
                "settlement_root": self.roots.settlement_root,
                "throttle_root": self.roots.throttle_root
            }
        })
    }

    fn cost_priority_root(&self) -> String {
        let leaves = self
            .claims
            .values()
            .filter(|claim| claim.status.live())
            .map(|claim| {
                json!({
                    "blob_size_bytes": claim.blob_size_bytes,
                    "claim_id": claim.claim_id,
                    "lane": claim.lane.as_str(),
                    "priority_weight": claim.lane.priority_weight(),
                    "witness_bytes": claim.witness_bytes
                })
            })
            .collect::<Vec<_>>();
        merkle_root("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-COST-PRIORITY", &leaves)
    }

    fn preview_throttle_action(&self, operator_id: &str, height: u64) -> ThrottleAction {
        let window_start = height.saturating_sub(self.config.throttle_window_blocks);
        let recent_claims = self
            .claims
            .values()
            .filter(|claim| claim.submitted_height >= window_start)
            .filter(|claim| {
                self.routes
                    .get(&claim.route_id)
                    .map(|route| route.operator_id == operator_id)
                    .unwrap_or(false)
            })
            .count() as u64;
        if recent_claims >= self.config.throttle_claim_limit.saturating_mul(2) {
            ThrottleAction::Reject
        } else if recent_claims >= self.config.throttle_claim_limit {
            ThrottleAction::Delay
        } else {
            ThrottleAction::Allow
        }
    }

    fn insert_nullifier(&mut self, nullifier: &str) -> Result<()> {
        if self.nullifiers.contains(nullifier) {
            self.counters.duplicate_nullifiers += 1;
            return Err(format!("duplicate nullifier: {nullifier}"));
        }
        self.nullifiers.insert(nullifier.to_string());
        Ok(())
    }

    fn require_known_subject(&self, subject_id: &str) -> Result<()> {
        if self.claims.contains_key(subject_id)
            || self.routes.contains_key(subject_id)
            || self.settlements.contains_key(subject_id)
            || self.rebates.contains_key(subject_id)
        {
            Ok(())
        } else {
            Err(format!("unknown attestation subject: {subject_id}"))
        }
    }

    fn require_pq_signature(&self, signature: &PqSignatureEnvelope) -> Result<()> {
        if signature.scheme != self.config.pq_attestation_scheme
            && signature.scheme != self.config.pq_da_scheme
        {
            return Err(format!(
                "unsupported pq signature scheme: {}",
                signature.scheme
            ));
        }
        if signature.security_bits < self.config.min_pq_security_bits {
            return Err(format!(
                "pq security below minimum: {}",
                signature.security_bits
            ));
        }
        require_nonempty("public_key_commitment", &signature.public_key_commitment)?;
        require_nonempty("transcript_hash", &signature.transcript_hash)?;
        require_nonempty("signature_commitment", &signature.signature_commitment)
    }

    fn push_event(&mut self, kind: &str, id: &str) {
        if self.event_log.len() >= MAX_EVENTS {
            return;
        }
        let event_id = deterministic_id(
            "EVENT",
            &[
                kind,
                id,
                &self.counters.next_sequence.to_string(),
                &self.roots.state_root,
            ],
        );
        self.counters.next_sequence += 1;
        self.counters.event_count += 1;
        self.event_log.push(event_id);
    }
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

macro_rules! impl_public_record {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl PublicRecord for $ty {
                fn public_record(&self) -> Value {
                    self.public_record()
                }
            }
        )+
    };
}

impl_public_record!(
    RefundRoute,
    BlobWitnessClaim,
    PqDaProverAttestation,
    SettlementBatch,
    ConfidentialRebate,
    AntiAbuseThrottle,
    RedactionBudget,
    OperatorSummary,
);

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let mut state = State::devnet();
    let route_id = state
        .open_refund_route(
            "operator-devnet-0",
            RefundLane::WitnessCost,
            &commitment_id("CAPACITY", &["operator-devnet-0", "witness"]),
            &commitment_id("DESTINATION-SET", &["devnet"]),
            &commitment_id("WITNESS-ORACLE", &["devnet"]),
            &commitment_id("DA-COMMITTEE", &["devnet"]),
            &commitment_id("PROVER-SET", &["devnet"]),
            DEFAULT_DEVNET_HEIGHT,
        )
        .expect("devnet route");
    let claim_id = state
        .submit_blob_witness_claim(
            &route_id,
            "claimant-commitment-devnet-0",
            "blob-commitment-devnet-0",
            131_072,
            "witness-commitment-devnet-0",
            8_192,
            ConfidentialAmount::devnet("wxmr-devnet", "requested-refund-0", 1_000),
            ConfidentialAmount::devnet("piconero-devnet", "fee-paid-0", 9),
            DEFAULT_DEVNET_HEIGHT + 1,
        )
        .expect("devnet claim");
    state
        .record_pq_attestation(
            AttestationKind::BlobAvailability,
            &claim_id,
            "da-attester-devnet-0",
            "committee-devnet-0",
            AttestationVote::Accept,
            &commitment_id("OBSERVED-BLOB", &[&claim_id]),
            PqSignatureEnvelope::devnet("da-attestation", "pq-pk-devnet-0", "pq-sig-devnet-0"),
            DEFAULT_DEVNET_HEIGHT + 2,
        )
        .expect("devnet da attestation");
    state
        .record_pq_attestation(
            AttestationKind::PqProver,
            &claim_id,
            "prover-attester-devnet-0",
            "committee-devnet-0",
            AttestationVote::Accept,
            &commitment_id("OBSERVED-PROVER", &[&claim_id]),
            PqSignatureEnvelope::devnet("prover-attestation", "pq-pk-devnet-1", "pq-sig-devnet-1"),
            DEFAULT_DEVNET_HEIGHT + 3,
        )
        .expect("devnet prover attestation");
    let budget_id = state
        .allocate_redaction_budget(
            "claimant-commitment-devnet-0",
            RedactionScope::FeeAndWitness,
            0,
            1_000,
        )
        .expect("devnet redaction budget");
    state
        .attach_redaction_budget(&claim_id, &budget_id, 128)
        .expect("devnet redaction attachment");
    state
        .issue_rebate(&claim_id, DEFAULT_DEVNET_HEIGHT + 4)
        .expect("devnet rebate");
    let claim_ids = BTreeSet::from([claim_id.clone()]);
    let settlement_id = state
        .queue_settlement("operator-devnet-0", 0, claim_ids, DEFAULT_DEVNET_HEIGHT + 5)
        .expect("devnet settlement");
    state
        .settle_batch(
            &settlement_id,
            DEFAULT_DEVNET_HEIGHT + 5 + DEFAULT_SETTLEMENT_DELAY_BLOCKS,
        )
        .expect("devnet settle");
    state
        .apply_throttle(
            &claim_id,
            "operator-devnet-0",
            ThrottleAction::Allow,
            DEFAULT_DEVNET_HEIGHT,
            1,
            131_072,
            8_192,
            4,
            "demo-observation",
        )
        .expect("devnet throttle");
    state
        .summarize_operator("operator-devnet-0", 0)
        .expect("devnet operator summary");
    state
}

pub fn public_record(state: &State) -> Value {
    let mut record = state.public_record_without_state_root();
    if let Some(object) = record.as_object_mut() {
        object.insert("state_root".to_string(), json!(state.roots.state_root));
    }
    record
}

pub fn state_root(state: &State) -> String {
    state.roots.state_root.clone()
}

pub fn deterministic_id(domain: &str, parts: &[&str]) -> String {
    let hash_parts = parts
        .iter()
        .map(|part| HashPart::Str(part))
        .collect::<Vec<_>>();
    domain_hash(domain, &hash_parts, 32)
}

pub fn hash_json(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn commitment_id(domain: &str, parts: &[&str]) -> String {
    deterministic_id(
        &format!("PRIVATE-L2-CONFIDENTIAL-COMMITMENT-{domain}"),
        &[CHAIN_ID, &parts.join(":")],
    )
}

pub fn nullifier_id(domain: &str, parts: &[&str]) -> String {
    deterministic_id(
        &format!("PRIVATE-L2-CONFIDENTIAL-NULLIFIER-{domain}"),
        &[CHAIN_ID, &parts.join(":")],
    )
}

pub fn empty_root(domain: &str) -> String {
    merkle_root(
        &format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BLOB-WITNESS-{domain}"),
        &[],
    )
}

pub fn map_root<T: PublicRecord>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(id, item)| json!({"id": id, "record": item.public_record()}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BLOB-WITNESS-{domain}"),
        &leaves,
    )
}

pub fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|item| json!({"item": item}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BLOB-WITNESS-{domain}"),
        &leaves,
    )
}

pub fn string_root<'a, I>(domain: &str, values: I) -> String
where
    I: Iterator<Item = &'a String>,
{
    let leaves = values
        .map(|value| json!({"value": value}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BLOB-WITNESS-{domain}"),
        &leaves,
    )
}

pub fn require_nonempty(label: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}
