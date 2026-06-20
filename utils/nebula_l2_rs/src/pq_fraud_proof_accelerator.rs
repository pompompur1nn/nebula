use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, HashPart},
    CHAIN_ID,
};

pub type PqFraudProofAcceleratorResult<T> = Result<T, String>;

pub const PQ_FRAUD_PROOF_ACCELERATOR_PROTOCOL_VERSION: u32 = 1;
pub const PQ_FRAUD_PROOF_ACCELERATOR_PROTOCOL_LABEL: &str =
    "nebula-l2-pq-fraud-proof-accelerator-v1";
pub const PQ_FRAUD_PROOF_ACCELERATOR_SCHEMA_VERSION: u64 = 1;
pub const PQ_FRAUD_PROOF_ACCELERATOR_HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_FRAUD_PROOF_ACCELERATOR_PQ_SIGNATURE_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-192f-fraud-accelerator-v1";
pub const PQ_FRAUD_PROOF_ACCELERATOR_RECURSION_SCHEME: &str =
    "nebula-devnet-recursive-fraud-proof-triage-v1";
pub const PQ_FRAUD_PROOF_ACCELERATOR_TRACE_SCHEME: &str =
    "private-invalid-transition-trace-commitments-v1";
pub const PQ_FRAUD_PROOF_ACCELERATOR_DA_SCHEME: &str = "private-da-challenge-bundle-accelerator-v1";
pub const PQ_FRAUD_PROOF_ACCELERATOR_QUARANTINE_SCHEME: &str = "sealed-evidence-quarantine-v1";
pub const PQ_FRAUD_PROOF_ACCELERATOR_DEVNET_HEIGHT: u64 = 1_024;
pub const PQ_FRAUD_PROOF_ACCELERATOR_DEFAULT_TICKET_TTL_BLOCKS: u64 = 48;
pub const PQ_FRAUD_PROOF_ACCELERATOR_DEFAULT_RECURSIVE_LANE_TTL_BLOCKS: u64 = 144;
pub const PQ_FRAUD_PROOF_ACCELERATOR_DEFAULT_TRACE_TTL_BLOCKS: u64 = 96;
pub const PQ_FRAUD_PROOF_ACCELERATOR_DEFAULT_DA_WINDOW_BLOCKS: u64 = 32;
pub const PQ_FRAUD_PROOF_ACCELERATOR_DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 7_200;
pub const PQ_FRAUD_PROOF_ACCELERATOR_DEFAULT_MIN_SECURITY_BITS: u16 = 256;
pub const PQ_FRAUD_PROOF_ACCELERATOR_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 256;
pub const PQ_FRAUD_PROOF_ACCELERATOR_DEFAULT_LOW_FEE_CAP_MICRO_UNITS: u64 = 750;
pub const PQ_FRAUD_PROOF_ACCELERATOR_DEFAULT_SPONSOR_BUDGET_MICRO_UNITS: u64 = 150_000;
pub const PQ_FRAUD_PROOF_ACCELERATOR_DEFAULT_MAX_DISCLOSURE_BPS: u64 = 600;
pub const PQ_FRAUD_PROOF_ACCELERATOR_DEFAULT_SLASH_BPS: u64 = 1_500;
pub const PQ_FRAUD_PROOF_ACCELERATOR_DEFAULT_ESCALATION_THRESHOLD_SCORE: u64 = 7_500;
pub const PQ_FRAUD_PROOF_ACCELERATOR_MAX_BPS: u64 = 10_000;
pub const PQ_FRAUD_PROOF_ACCELERATOR_MAX_TICKETS: usize = 131_072;
pub const PQ_FRAUD_PROOF_ACCELERATOR_MAX_PQ_FAMILIES: usize = 128;
pub const PQ_FRAUD_PROOF_ACCELERATOR_MAX_RECURSIVE_LANES: usize = 256;
pub const PQ_FRAUD_PROOF_ACCELERATOR_MAX_INVALID_TRACES: usize = 262_144;
pub const PQ_FRAUD_PROOF_ACCELERATOR_MAX_DA_BUNDLES: usize = 262_144;
pub const PQ_FRAUD_PROOF_ACCELERATOR_MAX_SPONSORSHIPS: usize = 131_072;
pub const PQ_FRAUD_PROOF_ACCELERATOR_MAX_WATCHERS: usize = 262_144;
pub const PQ_FRAUD_PROOF_ACCELERATOR_MAX_QUARANTINES: usize = 131_072;
pub const PQ_FRAUD_PROOF_ACCELERATOR_MAX_CACHE_REFS: usize = 524_288;
pub const PQ_FRAUD_PROOF_ACCELERATOR_MAX_SLASHING_RECOMMENDATIONS: usize = 131_072;
pub const PQ_FRAUD_PROOF_ACCELERATOR_MAX_PUBLIC_RECORDS: usize = 1_048_576;

const STATE_STATUS_ACTIVE: &str = "active";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FraudAccelerationTicketKind {
    InvalidStateTransition,
    InvalidPrivateContractExecution,
    DataAvailabilityWithholding,
    NullifierReuse,
    BridgeAccountingMismatch,
    FeeOvercharge,
    SequencerEquivocation,
    RecursiveProofMismatch,
}

impl FraudAccelerationTicketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidStateTransition => "invalid_state_transition",
            Self::InvalidPrivateContractExecution => "invalid_private_contract_execution",
            Self::DataAvailabilityWithholding => "data_availability_withholding",
            Self::NullifierReuse => "nullifier_reuse",
            Self::BridgeAccountingMismatch => "bridge_accounting_mismatch",
            Self::FeeOvercharge => "fee_overcharge",
            Self::SequencerEquivocation => "sequencer_equivocation",
            Self::RecursiveProofMismatch => "recursive_proof_mismatch",
        }
    }

    pub fn default_priority_score(self) -> u64 {
        match self {
            Self::SequencerEquivocation => 9_800,
            Self::NullifierReuse => 9_500,
            Self::DataAvailabilityWithholding => 9_200,
            Self::BridgeAccountingMismatch => 8_700,
            Self::InvalidStateTransition => 8_400,
            Self::RecursiveProofMismatch => 8_000,
            Self::InvalidPrivateContractExecution => 7_600,
            Self::FeeOvercharge => 5_600,
        }
    }

    pub fn emergency(self) -> bool {
        matches!(
            self,
            Self::SequencerEquivocation | Self::NullifierReuse | Self::DataAvailabilityWithholding
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FraudAccelerationStatus {
    Intake,
    Scored,
    Cached,
    Recursing,
    Quarantined,
    Escalated,
    Sustained,
    Dismissed,
    Expired,
}

impl FraudAccelerationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Intake => "intake",
            Self::Scored => "scored",
            Self::Cached => "cached",
            Self::Recursing => "recursing",
            Self::Quarantined => "quarantined",
            Self::Escalated => "escalated",
            Self::Sustained => "sustained",
            Self::Dismissed => "dismissed",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Intake | Self::Scored | Self::Cached | Self::Recursing | Self::Quarantined
        )
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Escalated | Self::Sustained | Self::Dismissed | Self::Expired
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqFraudProofFamilyKind {
    MlDsaTriage,
    SlhDsaLongTail,
    MlKemSealedWitness,
    RecursiveStark,
    RecursiveSnark,
    VerkleTransition,
    DaSampling,
    PrivacyPreservingVm,
}

impl PqFraudProofFamilyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsaTriage => "ml_dsa_triage",
            Self::SlhDsaLongTail => "slh_dsa_long_tail",
            Self::MlKemSealedWitness => "ml_kem_sealed_witness",
            Self::RecursiveStark => "recursive_stark",
            Self::RecursiveSnark => "recursive_snark",
            Self::VerkleTransition => "verkle_transition",
            Self::DaSampling => "da_sampling",
            Self::PrivacyPreservingVm => "privacy_preserving_vm",
        }
    }

    pub fn proof_system(self) -> &'static str {
        match self {
            Self::MlDsaTriage => "ml-dsa-fraud-triage-v1",
            Self::SlhDsaLongTail => "slh-dsa-shake-fallback-fraud-proof-v1",
            Self::MlKemSealedWitness => "ml-kem-sealed-witness-envelope-v1",
            Self::RecursiveStark => "recursive-pq-stark-fraud-v1",
            Self::RecursiveSnark => "recursive-pq-snark-fraud-v1",
            Self::VerkleTransition => "pq-verkle-transition-proof-v1",
            Self::DaSampling => "private-da-sampling-fraud-proof-v1",
            Self::PrivacyPreservingVm => "private-vm-execution-fraud-proof-v1",
        }
    }

    pub fn privacy_sensitive(self) -> bool {
        matches!(
            self,
            Self::MlKemSealedWitness | Self::DaSampling | Self::PrivacyPreservingVm
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecursiveAggregationLaneKind {
    Emergency,
    Bridge,
    PrivateDefi,
    ContractVm,
    DaSampling,
    LowFeePublicGood,
    CacheRefresh,
    SlashingReview,
}

impl RecursiveAggregationLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Emergency => "emergency",
            Self::Bridge => "bridge",
            Self::PrivateDefi => "private_defi",
            Self::ContractVm => "contract_vm",
            Self::DaSampling => "da_sampling",
            Self::LowFeePublicGood => "low_fee_public_good",
            Self::CacheRefresh => "cache_refresh",
            Self::SlashingReview => "slashing_review",
        }
    }

    pub fn low_fee(self) -> bool {
        matches!(self, Self::LowFeePublicGood | Self::DaSampling)
    }

    pub fn default_weight(self) -> u64 {
        match self {
            Self::Emergency => 10_000,
            Self::Bridge => 9_000,
            Self::PrivateDefi => 8_500,
            Self::ContractVm => 8_000,
            Self::DaSampling => 7_800,
            Self::SlashingReview => 7_200,
            Self::LowFeePublicGood => 6_000,
            Self::CacheRefresh => 3_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceQuarantineReason {
    PrivacyDisclosureRisk,
    MalformedEnvelope,
    ConflictingCommitments,
    CachePoisoningRisk,
    OperatorEquivocation,
    DaWithholding,
}

impl EvidenceQuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivacyDisclosureRisk => "privacy_disclosure_risk",
            Self::MalformedEnvelope => "malformed_envelope",
            Self::ConflictingCommitments => "conflicting_commitments",
            Self::CachePoisoningRisk => "cache_poisoning_risk",
            Self::OperatorEquivocation => "operator_equivocation",
            Self::DaWithholding => "da_withholding",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingRecommendationStatus {
    Draft,
    Submitted,
    CommitteeAccepted,
    CommitteeRejected,
    Executed,
    Expired,
}

impl SlashingRecommendationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Submitted => "submitted",
            Self::CommitteeAccepted => "committee_accepted",
            Self::CommitteeRejected => "committee_rejected",
            Self::Executed => "executed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqFraudProofAcceleratorConfig {
    pub protocol_version: u32,
    pub protocol_label: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_signature_suite: String,
    pub recursion_scheme: String,
    pub trace_scheme: String,
    pub da_scheme: String,
    pub quarantine_scheme: String,
    pub ticket_ttl_blocks: u64,
    pub recursive_lane_ttl_blocks: u64,
    pub trace_ttl_blocks: u64,
    pub da_challenge_window_blocks: u64,
    pub quarantine_ttl_blocks: u64,
    pub min_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub low_fee_cap_micro_units: u64,
    pub sponsor_budget_micro_units: u64,
    pub max_disclosure_bps: u64,
    pub slash_bps: u64,
    pub escalation_threshold_score: u64,
    pub max_tickets: usize,
    pub max_pq_families: usize,
    pub max_recursive_lanes: usize,
    pub max_invalid_traces: usize,
    pub max_da_bundles: usize,
    pub max_sponsorships: usize,
    pub max_watchers: usize,
    pub max_quarantines: usize,
    pub max_cache_refs: usize,
    pub max_slashing_recommendations: usize,
    pub max_public_records: usize,
}

impl PqFraudProofAcceleratorConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PQ_FRAUD_PROOF_ACCELERATOR_PROTOCOL_VERSION,
            protocol_label: PQ_FRAUD_PROOF_ACCELERATOR_PROTOCOL_LABEL.to_string(),
            schema_version: PQ_FRAUD_PROOF_ACCELERATOR_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PQ_FRAUD_PROOF_ACCELERATOR_HASH_SUITE.to_string(),
            pq_signature_suite: PQ_FRAUD_PROOF_ACCELERATOR_PQ_SIGNATURE_SUITE.to_string(),
            recursion_scheme: PQ_FRAUD_PROOF_ACCELERATOR_RECURSION_SCHEME.to_string(),
            trace_scheme: PQ_FRAUD_PROOF_ACCELERATOR_TRACE_SCHEME.to_string(),
            da_scheme: PQ_FRAUD_PROOF_ACCELERATOR_DA_SCHEME.to_string(),
            quarantine_scheme: PQ_FRAUD_PROOF_ACCELERATOR_QUARANTINE_SCHEME.to_string(),
            ticket_ttl_blocks: PQ_FRAUD_PROOF_ACCELERATOR_DEFAULT_TICKET_TTL_BLOCKS,
            recursive_lane_ttl_blocks: PQ_FRAUD_PROOF_ACCELERATOR_DEFAULT_RECURSIVE_LANE_TTL_BLOCKS,
            trace_ttl_blocks: PQ_FRAUD_PROOF_ACCELERATOR_DEFAULT_TRACE_TTL_BLOCKS,
            da_challenge_window_blocks: PQ_FRAUD_PROOF_ACCELERATOR_DEFAULT_DA_WINDOW_BLOCKS,
            quarantine_ttl_blocks: PQ_FRAUD_PROOF_ACCELERATOR_DEFAULT_QUARANTINE_TTL_BLOCKS,
            min_security_bits: PQ_FRAUD_PROOF_ACCELERATOR_DEFAULT_MIN_SECURITY_BITS,
            min_privacy_set_size: PQ_FRAUD_PROOF_ACCELERATOR_DEFAULT_MIN_PRIVACY_SET_SIZE,
            low_fee_cap_micro_units: PQ_FRAUD_PROOF_ACCELERATOR_DEFAULT_LOW_FEE_CAP_MICRO_UNITS,
            sponsor_budget_micro_units:
                PQ_FRAUD_PROOF_ACCELERATOR_DEFAULT_SPONSOR_BUDGET_MICRO_UNITS,
            max_disclosure_bps: PQ_FRAUD_PROOF_ACCELERATOR_DEFAULT_MAX_DISCLOSURE_BPS,
            slash_bps: PQ_FRAUD_PROOF_ACCELERATOR_DEFAULT_SLASH_BPS,
            escalation_threshold_score:
                PQ_FRAUD_PROOF_ACCELERATOR_DEFAULT_ESCALATION_THRESHOLD_SCORE,
            max_tickets: PQ_FRAUD_PROOF_ACCELERATOR_MAX_TICKETS,
            max_pq_families: PQ_FRAUD_PROOF_ACCELERATOR_MAX_PQ_FAMILIES,
            max_recursive_lanes: PQ_FRAUD_PROOF_ACCELERATOR_MAX_RECURSIVE_LANES,
            max_invalid_traces: PQ_FRAUD_PROOF_ACCELERATOR_MAX_INVALID_TRACES,
            max_da_bundles: PQ_FRAUD_PROOF_ACCELERATOR_MAX_DA_BUNDLES,
            max_sponsorships: PQ_FRAUD_PROOF_ACCELERATOR_MAX_SPONSORSHIPS,
            max_watchers: PQ_FRAUD_PROOF_ACCELERATOR_MAX_WATCHERS,
            max_quarantines: PQ_FRAUD_PROOF_ACCELERATOR_MAX_QUARANTINES,
            max_cache_refs: PQ_FRAUD_PROOF_ACCELERATOR_MAX_CACHE_REFS,
            max_slashing_recommendations: PQ_FRAUD_PROOF_ACCELERATOR_MAX_SLASHING_RECOMMENDATIONS,
            max_public_records: PQ_FRAUD_PROOF_ACCELERATOR_MAX_PUBLIC_RECORDS,
        }
    }

    pub fn validate(&self) -> PqFraudProofAcceleratorResult<()> {
        if self.protocol_version != PQ_FRAUD_PROOF_ACCELERATOR_PROTOCOL_VERSION {
            return Err("config.protocol_version is unsupported".to_string());
        }
        if self.chain_id.as_str() != CHAIN_ID {
            return Err("config.chain_id must match crate chain id".to_string());
        }
        ensure_non_empty("config.protocol_label", &self.protocol_label)?;
        ensure_non_empty("config.hash_suite", &self.hash_suite)?;
        ensure_non_empty("config.pq_signature_suite", &self.pq_signature_suite)?;
        ensure_non_empty("config.recursion_scheme", &self.recursion_scheme)?;
        ensure_non_empty("config.trace_scheme", &self.trace_scheme)?;
        ensure_non_empty("config.da_scheme", &self.da_scheme)?;
        ensure_non_empty("config.quarantine_scheme", &self.quarantine_scheme)?;
        ensure_positive(self.ticket_ttl_blocks, "config.ticket_ttl_blocks")?;
        ensure_positive(
            self.recursive_lane_ttl_blocks,
            "config.recursive_lane_ttl_blocks",
        )?;
        ensure_positive(self.trace_ttl_blocks, "config.trace_ttl_blocks")?;
        ensure_positive(
            self.da_challenge_window_blocks,
            "config.da_challenge_window_blocks",
        )?;
        ensure_positive(self.quarantine_ttl_blocks, "config.quarantine_ttl_blocks")?;
        if self.min_security_bits < 128 {
            return Err("config.min_security_bits must be at least 128".to_string());
        }
        ensure_positive(self.min_privacy_set_size, "config.min_privacy_set_size")?;
        ensure_positive(
            self.low_fee_cap_micro_units,
            "config.low_fee_cap_micro_units",
        )?;
        ensure_positive(
            self.sponsor_budget_micro_units,
            "config.sponsor_budget_micro_units",
        )?;
        ensure_bps(self.max_disclosure_bps, "config.max_disclosure_bps")?;
        ensure_bps(self.slash_bps, "config.slash_bps")?;
        ensure_positive(
            self.escalation_threshold_score,
            "config.escalation_threshold_score",
        )?;
        Ok(())
    }

    pub fn state_root(&self) -> String {
        payload_root("PQ-FRAUD-PROOF-ACCELERATOR-CONFIG", &json!(self))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqFraudProofAcceleratorRoots {
    pub config_root: String,
    pub ticket_root: String,
    pub pq_family_root: String,
    pub recursive_lane_root: String,
    pub invalid_trace_root: String,
    pub da_bundle_root: String,
    pub sponsorship_root: String,
    pub watcher_commitment_root: String,
    pub evidence_quarantine_root: String,
    pub verifier_cache_ref_root: String,
    pub slashing_recommendation_root: String,
    pub public_record_root: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqFraudProofAcceleratorCounters {
    pub tickets: u64,
    pub live_tickets: u64,
    pub escalated_tickets: u64,
    pub pq_families: u64,
    pub recursive_lanes: u64,
    pub live_recursive_lanes: u64,
    pub invalid_traces: u64,
    pub da_bundles: u64,
    pub active_da_bundles: u64,
    pub sponsorships: u64,
    pub low_fee_sponsored_tickets: u64,
    pub watcher_commitments: u64,
    pub evidence_quarantines: u64,
    pub verifier_cache_refs: u64,
    pub slashing_recommendations: u64,
    pub public_records: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FraudAccelerationTicket {
    pub ticket_id: String,
    pub claim_id: String,
    pub rollup_id: String,
    pub ticket_kind: FraudAccelerationTicketKind,
    pub status: FraudAccelerationStatus,
    pub challenger_commitment: String,
    pub target_operator_commitment: String,
    pub pre_state_root: String,
    pub claimed_post_state_root: String,
    pub evidence_root: String,
    pub priority_score: u64,
    pub privacy_set_size: u64,
    pub fee_cap_micro_units: u64,
    pub created_height: u64,
    pub expires_height: u64,
    pub recursive_lane_id: String,
    pub verifier_cache_ref_id: String,
    pub quarantine_id: String,
}

impl FraudAccelerationTicket {
    pub fn validate(
        &self,
        config: &PqFraudProofAcceleratorConfig,
    ) -> PqFraudProofAcceleratorResult<()> {
        ensure_non_empty("ticket.ticket_id", &self.ticket_id)?;
        ensure_non_empty("ticket.claim_id", &self.claim_id)?;
        ensure_non_empty("ticket.rollup_id", &self.rollup_id)?;
        ensure_hex_root("ticket.challenger_commitment", &self.challenger_commitment)?;
        ensure_hex_root(
            "ticket.target_operator_commitment",
            &self.target_operator_commitment,
        )?;
        ensure_hex_root("ticket.pre_state_root", &self.pre_state_root)?;
        ensure_hex_root(
            "ticket.claimed_post_state_root",
            &self.claimed_post_state_root,
        )?;
        ensure_hex_root("ticket.evidence_root", &self.evidence_root)?;
        ensure_positive(self.priority_score, "ticket.priority_score")?;
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("ticket.privacy_set_size is below configured minimum".to_string());
        }
        if self.fee_cap_micro_units > config.low_fee_cap_micro_units {
            return Err("ticket.fee_cap_micro_units exceeds configured low-fee cap".to_string());
        }
        validate_height_window(
            self.created_height,
            self.expires_height,
            "ticket acceleration",
        )?;
        if self.expires_height - self.created_height > config.ticket_ttl_blocks {
            return Err("ticket lifetime exceeds configured ttl".to_string());
        }
        Ok(())
    }

    pub fn state_root(&self) -> String {
        payload_root("PQ-FRAUD-PROOF-ACCELERATOR-TICKET", &json!(self))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqProofFamilyDescriptor {
    pub family_id: String,
    pub family_kind: PqFraudProofFamilyKind,
    pub proof_system: String,
    pub verifier_key_root: String,
    pub recursion_compatible: bool,
    pub privacy_sensitive: bool,
    pub security_bits: u16,
    pub max_verify_microseconds: u64,
    pub active_lane_ids: BTreeSet<String>,
}

impl PqProofFamilyDescriptor {
    pub fn validate(
        &self,
        config: &PqFraudProofAcceleratorConfig,
    ) -> PqFraudProofAcceleratorResult<()> {
        ensure_non_empty("pq_family.family_id", &self.family_id)?;
        ensure_non_empty("pq_family.proof_system", &self.proof_system)?;
        ensure_hex_root("pq_family.verifier_key_root", &self.verifier_key_root)?;
        if self.security_bits < config.min_security_bits {
            return Err("pq_family.security_bits is below configured minimum".to_string());
        }
        ensure_positive(
            self.max_verify_microseconds,
            "pq_family.max_verify_microseconds",
        )?;
        ensure_unique_set("pq_family.active_lane_ids", &self.active_lane_ids)?;
        Ok(())
    }

    pub fn state_root(&self) -> String {
        payload_root("PQ-FRAUD-PROOF-ACCELERATOR-PQ-FAMILY", &json!(self))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecursiveAggregationLane {
    pub lane_id: String,
    pub lane_kind: RecursiveAggregationLaneKind,
    pub family_id: String,
    pub status: FraudAccelerationStatus,
    pub queue_root: String,
    pub aggregate_input_root: String,
    pub aggregate_output_root: String,
    pub recursive_proof_root: String,
    pub weight: u64,
    pub max_depth: u64,
    pub child_proof_count: u64,
    pub opened_height: u64,
    pub deadline_height: u64,
    pub low_fee_lane: bool,
}

impl RecursiveAggregationLane {
    pub fn validate(
        &self,
        config: &PqFraudProofAcceleratorConfig,
    ) -> PqFraudProofAcceleratorResult<()> {
        ensure_non_empty("recursive_lane.lane_id", &self.lane_id)?;
        ensure_non_empty("recursive_lane.family_id", &self.family_id)?;
        ensure_hex_root("recursive_lane.queue_root", &self.queue_root)?;
        ensure_hex_root(
            "recursive_lane.aggregate_input_root",
            &self.aggregate_input_root,
        )?;
        ensure_hex_root(
            "recursive_lane.aggregate_output_root",
            &self.aggregate_output_root,
        )?;
        ensure_hex_root(
            "recursive_lane.recursive_proof_root",
            &self.recursive_proof_root,
        )?;
        ensure_positive(self.weight, "recursive_lane.weight")?;
        ensure_positive(self.max_depth, "recursive_lane.max_depth")?;
        ensure_positive(self.child_proof_count, "recursive_lane.child_proof_count")?;
        validate_height_window(self.opened_height, self.deadline_height, "recursive lane")?;
        if self.deadline_height - self.opened_height > config.recursive_lane_ttl_blocks {
            return Err("recursive_lane deadline exceeds configured ttl".to_string());
        }
        if self.low_fee_lane != self.lane_kind.low_fee() {
            return Err("recursive_lane.low_fee_lane does not match lane kind".to_string());
        }
        Ok(())
    }

    pub fn state_root(&self) -> String {
        payload_root("PQ-FRAUD-PROOF-ACCELERATOR-RECURSIVE-LANE", &json!(self))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InvalidStateTransitionTrace {
    pub trace_id: String,
    pub ticket_id: String,
    pub trace_commitment_root: String,
    pub private_witness_root: String,
    pub public_input_root: String,
    pub bisection_commitment_root: String,
    pub first_invalid_step: u64,
    pub last_valid_step: u64,
    pub disclosed_step_count: u64,
    pub max_disclosure_bps: u64,
    pub created_height: u64,
    pub expires_height: u64,
}

impl InvalidStateTransitionTrace {
    pub fn validate(
        &self,
        config: &PqFraudProofAcceleratorConfig,
    ) -> PqFraudProofAcceleratorResult<()> {
        ensure_non_empty("trace.trace_id", &self.trace_id)?;
        ensure_non_empty("trace.ticket_id", &self.ticket_id)?;
        ensure_hex_root("trace.trace_commitment_root", &self.trace_commitment_root)?;
        ensure_hex_root("trace.private_witness_root", &self.private_witness_root)?;
        ensure_hex_root("trace.public_input_root", &self.public_input_root)?;
        ensure_hex_root(
            "trace.bisection_commitment_root",
            &self.bisection_commitment_root,
        )?;
        if self.first_invalid_step <= self.last_valid_step {
            return Err("trace.first_invalid_step must exceed last_valid_step".to_string());
        }
        ensure_positive(self.disclosed_step_count, "trace.disclosed_step_count")?;
        ensure_bps(self.max_disclosure_bps, "trace.max_disclosure_bps")?;
        if self.max_disclosure_bps > config.max_disclosure_bps {
            return Err("trace.max_disclosure_bps exceeds configured maximum".to_string());
        }
        validate_height_window(self.created_height, self.expires_height, "trace")?;
        if self.expires_height - self.created_height > config.trace_ttl_blocks {
            return Err("trace lifetime exceeds configured ttl".to_string());
        }
        Ok(())
    }

    pub fn state_root(&self) -> String {
        payload_root("PQ-FRAUD-PROOF-ACCELERATOR-INVALID-TRACE", &json!(self))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaChallengeBundle {
    pub bundle_id: String,
    pub ticket_id: String,
    pub shard_id: String,
    pub erasure_commitment_root: String,
    pub sample_commitment_root: String,
    pub withholding_evidence_root: String,
    pub sample_count: u64,
    pub missing_sample_count: u64,
    pub opened_height: u64,
    pub deadline_height: u64,
    pub active: bool,
}

impl DaChallengeBundle {
    pub fn validate(
        &self,
        config: &PqFraudProofAcceleratorConfig,
    ) -> PqFraudProofAcceleratorResult<()> {
        ensure_non_empty("da_bundle.bundle_id", &self.bundle_id)?;
        ensure_non_empty("da_bundle.ticket_id", &self.ticket_id)?;
        ensure_non_empty("da_bundle.shard_id", &self.shard_id)?;
        ensure_hex_root(
            "da_bundle.erasure_commitment_root",
            &self.erasure_commitment_root,
        )?;
        ensure_hex_root(
            "da_bundle.sample_commitment_root",
            &self.sample_commitment_root,
        )?;
        ensure_hex_root(
            "da_bundle.withholding_evidence_root",
            &self.withholding_evidence_root,
        )?;
        ensure_positive(self.sample_count, "da_bundle.sample_count")?;
        if self.missing_sample_count > self.sample_count {
            return Err("da_bundle.missing_sample_count exceeds sample_count".to_string());
        }
        validate_height_window(
            self.opened_height,
            self.deadline_height,
            "da challenge bundle",
        )?;
        if self.deadline_height - self.opened_height > config.da_challenge_window_blocks {
            return Err("da_bundle deadline exceeds configured window".to_string());
        }
        Ok(())
    }

    pub fn state_root(&self) -> String {
        payload_root("PQ-FRAUD-PROOF-ACCELERATOR-DA-BUNDLE", &json!(self))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LowFeeChallengeSponsorship {
    pub sponsorship_id: String,
    pub ticket_id: String,
    pub sponsor_commitment: String,
    pub beneficiary_commitment: String,
    pub budget_micro_units: u64,
    pub reserved_micro_units: u64,
    pub consumed_micro_units: u64,
    pub created_height: u64,
    pub expires_height: u64,
}

impl LowFeeChallengeSponsorship {
    pub fn validate(
        &self,
        config: &PqFraudProofAcceleratorConfig,
    ) -> PqFraudProofAcceleratorResult<()> {
        ensure_non_empty("sponsorship.sponsorship_id", &self.sponsorship_id)?;
        ensure_non_empty("sponsorship.ticket_id", &self.ticket_id)?;
        ensure_hex_root("sponsorship.sponsor_commitment", &self.sponsor_commitment)?;
        ensure_hex_root(
            "sponsorship.beneficiary_commitment",
            &self.beneficiary_commitment,
        )?;
        ensure_positive(self.budget_micro_units, "sponsorship.budget_micro_units")?;
        if self.budget_micro_units > config.sponsor_budget_micro_units {
            return Err("sponsorship budget exceeds configured cap".to_string());
        }
        if self.reserved_micro_units > self.budget_micro_units {
            return Err("sponsorship reserved amount exceeds budget".to_string());
        }
        if self.consumed_micro_units > self.reserved_micro_units {
            return Err("sponsorship consumed amount exceeds reserved amount".to_string());
        }
        validate_height_window(
            self.created_height,
            self.expires_height,
            "low-fee sponsorship",
        )?;
        Ok(())
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "PQ-FRAUD-PROOF-ACCELERATOR-LOW-FEE-SPONSORSHIP",
            &json!(self),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateWatcherCommitment {
    pub watcher_id: String,
    pub watcher_commitment: String,
    pub watched_rollup_root: String,
    pub nullifier_domain_root: String,
    pub encrypted_endpoint_root: String,
    pub stake_commitment: String,
    pub privacy_set_size: u64,
    pub active_from_height: u64,
    pub active_until_height: u64,
}

impl PrivateWatcherCommitment {
    pub fn validate(
        &self,
        config: &PqFraudProofAcceleratorConfig,
    ) -> PqFraudProofAcceleratorResult<()> {
        ensure_non_empty("watcher.watcher_id", &self.watcher_id)?;
        ensure_hex_root("watcher.watcher_commitment", &self.watcher_commitment)?;
        ensure_hex_root("watcher.watched_rollup_root", &self.watched_rollup_root)?;
        ensure_hex_root("watcher.nullifier_domain_root", &self.nullifier_domain_root)?;
        ensure_hex_root(
            "watcher.encrypted_endpoint_root",
            &self.encrypted_endpoint_root,
        )?;
        ensure_hex_root("watcher.stake_commitment", &self.stake_commitment)?;
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("watcher privacy set is below configured minimum".to_string());
        }
        validate_height_window(
            self.active_from_height,
            self.active_until_height,
            "private watcher",
        )?;
        Ok(())
    }

    pub fn state_root(&self) -> String {
        payload_root("PQ-FRAUD-PROOF-ACCELERATOR-PRIVATE-WATCHER", &json!(self))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvidenceQuarantine {
    pub quarantine_id: String,
    pub ticket_id: String,
    pub reason: EvidenceQuarantineReason,
    pub evidence_root: String,
    pub sealed_payload_root: String,
    pub reviewer_committee_root: String,
    pub opened_height: u64,
    pub release_height: u64,
    pub disclosure_bps: u64,
}

impl EvidenceQuarantine {
    pub fn validate(
        &self,
        config: &PqFraudProofAcceleratorConfig,
    ) -> PqFraudProofAcceleratorResult<()> {
        ensure_non_empty("quarantine.quarantine_id", &self.quarantine_id)?;
        ensure_non_empty("quarantine.ticket_id", &self.ticket_id)?;
        ensure_hex_root("quarantine.evidence_root", &self.evidence_root)?;
        ensure_hex_root("quarantine.sealed_payload_root", &self.sealed_payload_root)?;
        ensure_hex_root(
            "quarantine.reviewer_committee_root",
            &self.reviewer_committee_root,
        )?;
        validate_height_window(
            self.opened_height,
            self.release_height,
            "evidence quarantine",
        )?;
        if self.release_height - self.opened_height > config.quarantine_ttl_blocks {
            return Err("quarantine release height exceeds configured ttl".to_string());
        }
        ensure_bps(self.disclosure_bps, "quarantine.disclosure_bps")?;
        if self.disclosure_bps > config.max_disclosure_bps {
            return Err("quarantine disclosure exceeds configured maximum".to_string());
        }
        Ok(())
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "PQ-FRAUD-PROOF-ACCELERATOR-EVIDENCE-QUARANTINE",
            &json!(self),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifierCacheReference {
    pub cache_ref_id: String,
    pub ticket_id: String,
    pub cache_namespace: String,
    pub cached_proof_root: String,
    pub verifier_key_root: String,
    pub hit_count: u64,
    pub saved_verify_microseconds: u64,
    pub created_height: u64,
    pub expires_height: u64,
}

impl VerifierCacheReference {
    pub fn validate(&self) -> PqFraudProofAcceleratorResult<()> {
        ensure_non_empty("cache_ref.cache_ref_id", &self.cache_ref_id)?;
        ensure_non_empty("cache_ref.ticket_id", &self.ticket_id)?;
        ensure_non_empty("cache_ref.cache_namespace", &self.cache_namespace)?;
        ensure_hex_root("cache_ref.cached_proof_root", &self.cached_proof_root)?;
        ensure_hex_root("cache_ref.verifier_key_root", &self.verifier_key_root)?;
        ensure_positive(self.hit_count, "cache_ref.hit_count")?;
        ensure_positive(
            self.saved_verify_microseconds,
            "cache_ref.saved_verify_microseconds",
        )?;
        validate_height_window(
            self.created_height,
            self.expires_height,
            "verifier cache reference",
        )?;
        Ok(())
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "PQ-FRAUD-PROOF-ACCELERATOR-VERIFIER-CACHE-REF",
            &json!(self),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorSlashingRecommendation {
    pub recommendation_id: String,
    pub ticket_id: String,
    pub operator_commitment: String,
    pub offense_root: String,
    pub evidence_quarantine_id: String,
    pub recommended_slash_bps: u64,
    pub status: SlashingRecommendationStatus,
    pub created_height: u64,
    pub expires_height: u64,
}

impl OperatorSlashingRecommendation {
    pub fn validate(
        &self,
        config: &PqFraudProofAcceleratorConfig,
    ) -> PqFraudProofAcceleratorResult<()> {
        ensure_non_empty("slashing.recommendation_id", &self.recommendation_id)?;
        ensure_non_empty("slashing.ticket_id", &self.ticket_id)?;
        ensure_hex_root("slashing.operator_commitment", &self.operator_commitment)?;
        ensure_hex_root("slashing.offense_root", &self.offense_root)?;
        ensure_non_empty(
            "slashing.evidence_quarantine_id",
            &self.evidence_quarantine_id,
        )?;
        ensure_bps(self.recommended_slash_bps, "slashing.recommended_slash_bps")?;
        if self.recommended_slash_bps > config.slash_bps {
            return Err("slashing recommendation exceeds configured slash bps".to_string());
        }
        validate_height_window(
            self.created_height,
            self.expires_height,
            "slashing recommendation",
        )?;
        Ok(())
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "PQ-FRAUD-PROOF-ACCELERATOR-SLASHING-RECOMMENDATION",
            &json!(self),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FraudAcceleratorPublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub height: u64,
}

impl FraudAcceleratorPublicRecord {
    pub fn validate(&self) -> PqFraudProofAcceleratorResult<()> {
        ensure_non_empty("public_record.record_id", &self.record_id)?;
        ensure_non_empty("public_record.record_kind", &self.record_kind)?;
        ensure_non_empty("public_record.subject_id", &self.subject_id)?;
        ensure_hex_root("public_record.subject_root", &self.subject_root)?;
        Ok(())
    }

    pub fn state_root(&self) -> String {
        payload_root("PQ-FRAUD-PROOF-ACCELERATOR-PUBLIC-RECORD", &json!(self))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqFraudProofAcceleratorState {
    pub config: PqFraudProofAcceleratorConfig,
    pub height: u64,
    pub status: String,
    pub tickets: BTreeMap<String, FraudAccelerationTicket>,
    pub pq_families: BTreeMap<String, PqProofFamilyDescriptor>,
    pub recursive_lanes: BTreeMap<String, RecursiveAggregationLane>,
    pub invalid_traces: BTreeMap<String, InvalidStateTransitionTrace>,
    pub da_bundles: BTreeMap<String, DaChallengeBundle>,
    pub sponsorships: BTreeMap<String, LowFeeChallengeSponsorship>,
    pub watcher_commitments: BTreeMap<String, PrivateWatcherCommitment>,
    pub evidence_quarantines: BTreeMap<String, EvidenceQuarantine>,
    pub verifier_cache_refs: BTreeMap<String, VerifierCacheReference>,
    pub slashing_recommendations: BTreeMap<String, OperatorSlashingRecommendation>,
    pub public_records: BTreeMap<String, FraudAcceleratorPublicRecord>,
}

impl Default for PqFraudProofAcceleratorState {
    fn default() -> Self {
        match Self::devnet() {
            Ok(state) => state,
            Err(_) => Self {
                config: PqFraudProofAcceleratorConfig::devnet(),
                height: PQ_FRAUD_PROOF_ACCELERATOR_DEVNET_HEIGHT,
                status: STATE_STATUS_ACTIVE.to_string(),
                tickets: BTreeMap::new(),
                pq_families: BTreeMap::new(),
                recursive_lanes: BTreeMap::new(),
                invalid_traces: BTreeMap::new(),
                da_bundles: BTreeMap::new(),
                sponsorships: BTreeMap::new(),
                watcher_commitments: BTreeMap::new(),
                evidence_quarantines: BTreeMap::new(),
                verifier_cache_refs: BTreeMap::new(),
                slashing_recommendations: BTreeMap::new(),
                public_records: BTreeMap::new(),
            },
        }
    }
}

impl PqFraudProofAcceleratorState {
    pub fn devnet() -> PqFraudProofAcceleratorResult<Self> {
        let config = PqFraudProofAcceleratorConfig::devnet();
        config.validate()?;
        let mut state = Self {
            config,
            height: PQ_FRAUD_PROOF_ACCELERATOR_DEVNET_HEIGHT,
            status: STATE_STATUS_ACTIVE.to_string(),
            tickets: BTreeMap::new(),
            pq_families: BTreeMap::new(),
            recursive_lanes: BTreeMap::new(),
            invalid_traces: BTreeMap::new(),
            da_bundles: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            watcher_commitments: BTreeMap::new(),
            evidence_quarantines: BTreeMap::new(),
            verifier_cache_refs: BTreeMap::new(),
            slashing_recommendations: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        state.seed_devnet_records()?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PqFraudProofAcceleratorResult<()> {
        if height < self.height {
            return Err("height cannot move backwards".to_string());
        }
        self.height = height;
        self.validate()?;
        Ok(())
    }

    pub fn roots(&self) -> PqFraudProofAcceleratorRoots {
        PqFraudProofAcceleratorRoots {
            config_root: self.config.state_root(),
            ticket_root: map_root(
                "PQ-FRAUD-PROOF-ACCELERATOR-TICKETS",
                self.tickets
                    .values()
                    .map(FraudAccelerationTicket::state_root),
            ),
            pq_family_root: map_root(
                "PQ-FRAUD-PROOF-ACCELERATOR-PQ-FAMILIES",
                self.pq_families
                    .values()
                    .map(PqProofFamilyDescriptor::state_root),
            ),
            recursive_lane_root: map_root(
                "PQ-FRAUD-PROOF-ACCELERATOR-RECURSIVE-LANES",
                self.recursive_lanes
                    .values()
                    .map(RecursiveAggregationLane::state_root),
            ),
            invalid_trace_root: map_root(
                "PQ-FRAUD-PROOF-ACCELERATOR-INVALID-TRACES",
                self.invalid_traces
                    .values()
                    .map(InvalidStateTransitionTrace::state_root),
            ),
            da_bundle_root: map_root(
                "PQ-FRAUD-PROOF-ACCELERATOR-DA-BUNDLES",
                self.da_bundles.values().map(DaChallengeBundle::state_root),
            ),
            sponsorship_root: map_root(
                "PQ-FRAUD-PROOF-ACCELERATOR-SPONSORSHIPS",
                self.sponsorships
                    .values()
                    .map(LowFeeChallengeSponsorship::state_root),
            ),
            watcher_commitment_root: map_root(
                "PQ-FRAUD-PROOF-ACCELERATOR-WATCHERS",
                self.watcher_commitments
                    .values()
                    .map(PrivateWatcherCommitment::state_root),
            ),
            evidence_quarantine_root: map_root(
                "PQ-FRAUD-PROOF-ACCELERATOR-QUARANTINES",
                self.evidence_quarantines
                    .values()
                    .map(EvidenceQuarantine::state_root),
            ),
            verifier_cache_ref_root: map_root(
                "PQ-FRAUD-PROOF-ACCELERATOR-CACHE-REFS",
                self.verifier_cache_refs
                    .values()
                    .map(VerifierCacheReference::state_root),
            ),
            slashing_recommendation_root: map_root(
                "PQ-FRAUD-PROOF-ACCELERATOR-SLASHING",
                self.slashing_recommendations
                    .values()
                    .map(OperatorSlashingRecommendation::state_root),
            ),
            public_record_root: map_root(
                "PQ-FRAUD-PROOF-ACCELERATOR-PUBLIC-RECORDS",
                self.public_records
                    .values()
                    .map(FraudAcceleratorPublicRecord::state_root),
            ),
        }
    }

    pub fn counters(&self) -> PqFraudProofAcceleratorCounters {
        PqFraudProofAcceleratorCounters {
            tickets: self.tickets.len() as u64,
            live_tickets: self
                .tickets
                .values()
                .filter(|ticket| ticket.status.live())
                .count() as u64,
            escalated_tickets: self
                .tickets
                .values()
                .filter(|ticket| matches!(ticket.status, FraudAccelerationStatus::Escalated))
                .count() as u64,
            pq_families: self.pq_families.len() as u64,
            recursive_lanes: self.recursive_lanes.len() as u64,
            live_recursive_lanes: self
                .recursive_lanes
                .values()
                .filter(|lane| lane.status.live())
                .count() as u64,
            invalid_traces: self.invalid_traces.len() as u64,
            da_bundles: self.da_bundles.len() as u64,
            active_da_bundles: self
                .da_bundles
                .values()
                .filter(|bundle| bundle.active)
                .count() as u64,
            sponsorships: self.sponsorships.len() as u64,
            low_fee_sponsored_tickets: self
                .tickets
                .values()
                .filter(|ticket| !ticket.verifier_cache_ref_id.is_empty())
                .count() as u64,
            watcher_commitments: self.watcher_commitments.len() as u64,
            evidence_quarantines: self.evidence_quarantines.len() as u64,
            verifier_cache_refs: self.verifier_cache_refs.len() as u64,
            slashing_recommendations: self.slashing_recommendations.len() as u64,
            public_records: self.public_records.len() as u64,
        }
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        pq_fraud_proof_accelerator_state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn validate(&self) -> PqFraudProofAcceleratorResult<String> {
        self.config.validate()?;
        ensure_non_empty("state.status", &self.status)?;
        ensure_at_most("tickets", self.tickets.len(), self.config.max_tickets)?;
        ensure_at_most(
            "pq_families",
            self.pq_families.len(),
            self.config.max_pq_families,
        )?;
        ensure_at_most(
            "recursive_lanes",
            self.recursive_lanes.len(),
            self.config.max_recursive_lanes,
        )?;
        ensure_at_most(
            "invalid_traces",
            self.invalid_traces.len(),
            self.config.max_invalid_traces,
        )?;
        ensure_at_most(
            "da_bundles",
            self.da_bundles.len(),
            self.config.max_da_bundles,
        )?;
        ensure_at_most(
            "sponsorships",
            self.sponsorships.len(),
            self.config.max_sponsorships,
        )?;
        ensure_at_most(
            "watcher_commitments",
            self.watcher_commitments.len(),
            self.config.max_watchers,
        )?;
        ensure_at_most(
            "evidence_quarantines",
            self.evidence_quarantines.len(),
            self.config.max_quarantines,
        )?;
        ensure_at_most(
            "verifier_cache_refs",
            self.verifier_cache_refs.len(),
            self.config.max_cache_refs,
        )?;
        ensure_at_most(
            "slashing_recommendations",
            self.slashing_recommendations.len(),
            self.config.max_slashing_recommendations,
        )?;
        ensure_at_most(
            "public_records",
            self.public_records.len(),
            self.config.max_public_records,
        )?;

        for (id, family) in &self.pq_families {
            ensure_key_matches("pq_family", id, &family.family_id)?;
            family.validate(&self.config)?;
        }
        for (id, lane) in &self.recursive_lanes {
            ensure_key_matches("recursive_lane", id, &lane.lane_id)?;
            lane.validate(&self.config)?;
            ensure_exists(
                &lane.family_id,
                &self.pq_families,
                "recursive_lane.family_id",
            )?;
        }
        for (id, ticket) in &self.tickets {
            ensure_key_matches("ticket", id, &ticket.ticket_id)?;
            ticket.validate(&self.config)?;
            if !ticket.recursive_lane_id.is_empty() {
                ensure_exists(
                    &ticket.recursive_lane_id,
                    &self.recursive_lanes,
                    "ticket.recursive_lane_id",
                )?;
            }
            if !ticket.verifier_cache_ref_id.is_empty() {
                ensure_exists(
                    &ticket.verifier_cache_ref_id,
                    &self.verifier_cache_refs,
                    "ticket.verifier_cache_ref_id",
                )?;
            }
            if !ticket.quarantine_id.is_empty() {
                ensure_exists(
                    &ticket.quarantine_id,
                    &self.evidence_quarantines,
                    "ticket.quarantine_id",
                )?;
            }
        }
        for (id, trace) in &self.invalid_traces {
            ensure_key_matches("trace", id, &trace.trace_id)?;
            trace.validate(&self.config)?;
            ensure_exists(&trace.ticket_id, &self.tickets, "trace.ticket_id")?;
        }
        for (id, bundle) in &self.da_bundles {
            ensure_key_matches("da_bundle", id, &bundle.bundle_id)?;
            bundle.validate(&self.config)?;
            ensure_exists(&bundle.ticket_id, &self.tickets, "da_bundle.ticket_id")?;
        }
        for (id, sponsorship) in &self.sponsorships {
            ensure_key_matches("sponsorship", id, &sponsorship.sponsorship_id)?;
            sponsorship.validate(&self.config)?;
            ensure_exists(
                &sponsorship.ticket_id,
                &self.tickets,
                "sponsorship.ticket_id",
            )?;
        }
        for (id, watcher) in &self.watcher_commitments {
            ensure_key_matches("watcher", id, &watcher.watcher_id)?;
            watcher.validate(&self.config)?;
        }
        for (id, quarantine) in &self.evidence_quarantines {
            ensure_key_matches("quarantine", id, &quarantine.quarantine_id)?;
            quarantine.validate(&self.config)?;
            ensure_exists(&quarantine.ticket_id, &self.tickets, "quarantine.ticket_id")?;
        }
        for (id, cache_ref) in &self.verifier_cache_refs {
            ensure_key_matches("cache_ref", id, &cache_ref.cache_ref_id)?;
            cache_ref.validate()?;
            ensure_exists(&cache_ref.ticket_id, &self.tickets, "cache_ref.ticket_id")?;
        }
        for (id, recommendation) in &self.slashing_recommendations {
            ensure_key_matches("slashing", id, &recommendation.recommendation_id)?;
            recommendation.validate(&self.config)?;
            ensure_exists(
                &recommendation.ticket_id,
                &self.tickets,
                "slashing.ticket_id",
            )?;
            ensure_exists(
                &recommendation.evidence_quarantine_id,
                &self.evidence_quarantines,
                "slashing.evidence_quarantine_id",
            )?;
        }
        for (id, record) in &self.public_records {
            ensure_key_matches("public_record", id, &record.record_id)?;
            record.validate()?;
            if record.height > self.height {
                return Err("public_record height exceeds state height".to_string());
            }
        }
        Ok(self.state_root())
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PQ_FRAUD_PROOF_ACCELERATOR_PROTOCOL_VERSION,
            "protocol_label": PQ_FRAUD_PROOF_ACCELERATOR_PROTOCOL_LABEL,
            "schema_version": PQ_FRAUD_PROOF_ACCELERATOR_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "status": self.status,
            "hash_suite": PQ_FRAUD_PROOF_ACCELERATOR_HASH_SUITE,
            "roots": self.roots(),
            "counters": self.counters(),
        })
    }

    fn insert_public_record(
        &mut self,
        record_kind: &str,
        subject_id: &str,
        subject_root: &str,
    ) -> PqFraudProofAcceleratorResult<()> {
        let record_id = domain_hash(
            "PQ-FRAUD-PROOF-ACCELERATOR-PUBLIC-RECORD-ID",
            &[
                HashPart::Str(record_kind),
                HashPart::Str(subject_id),
                HashPart::Str(subject_root),
                HashPart::Int(self.height as i128),
            ],
            32,
        );
        let record = FraudAcceleratorPublicRecord {
            record_id: record_id.clone(),
            record_kind: record_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            height: self.height,
        };
        record.validate()?;
        self.public_records.insert(record_id, record);
        Ok(())
    }

    fn seed_devnet_records(&mut self) -> PqFraudProofAcceleratorResult<()> {
        let family_id = "pq-family-devnet-recursive-stark-0001".to_string();
        let mut lane_ids = BTreeSet::new();
        lane_ids.insert("recursive-lane-devnet-emergency-0001".to_string());
        let family = PqProofFamilyDescriptor {
            family_id: family_id.clone(),
            family_kind: PqFraudProofFamilyKind::RecursiveStark,
            proof_system: PqFraudProofFamilyKind::RecursiveStark
                .proof_system()
                .to_string(),
            verifier_key_root: demo_root("family-verifier-key"),
            recursion_compatible: true,
            privacy_sensitive: PqFraudProofFamilyKind::RecursiveStark.privacy_sensitive(),
            security_bits: self.config.min_security_bits,
            max_verify_microseconds: 25_000,
            active_lane_ids: lane_ids,
        };
        family.validate(&self.config)?;
        let family_root = family.state_root();
        self.pq_families.insert(family_id.clone(), family);
        self.insert_public_record("pq_proof_family", &family_id, &family_root)?;

        let lane_id = "recursive-lane-devnet-emergency-0001".to_string();
        let lane_kind = RecursiveAggregationLaneKind::Emergency;
        let lane = RecursiveAggregationLane {
            lane_id: lane_id.clone(),
            lane_kind,
            family_id: family_id.clone(),
            status: FraudAccelerationStatus::Recursing,
            queue_root: demo_root("lane-queue"),
            aggregate_input_root: demo_root("lane-input"),
            aggregate_output_root: demo_root("lane-output"),
            recursive_proof_root: demo_root("lane-recursive-proof"),
            weight: lane_kind.default_weight(),
            max_depth: 4,
            child_proof_count: 16,
            opened_height: self.height,
            deadline_height: self.height + self.config.recursive_lane_ttl_blocks,
            low_fee_lane: lane_kind.low_fee(),
        };
        lane.validate(&self.config)?;
        let lane_root = lane.state_root();
        self.recursive_lanes.insert(lane_id.clone(), lane);
        self.insert_public_record("recursive_aggregation_lane", &lane_id, &lane_root)?;

        let cache_ref_id = "verifier-cache-ref-devnet-0001".to_string();
        let ticket_id = "fraud-ticket-devnet-nullifier-0001".to_string();
        let cache_ref = VerifierCacheReference {
            cache_ref_id: cache_ref_id.clone(),
            ticket_id: ticket_id.clone(),
            cache_namespace: "pq-batch-verifier-cache/nullifier-reuse".to_string(),
            cached_proof_root: demo_root("cache-proof"),
            verifier_key_root: demo_root("cache-verifier-key"),
            hit_count: 9,
            saved_verify_microseconds: 180_000,
            created_height: self.height,
            expires_height: self.height + self.config.ticket_ttl_blocks,
        };
        cache_ref.validate()?;
        let cache_ref_root = cache_ref.state_root();
        self.verifier_cache_refs
            .insert(cache_ref_id.clone(), cache_ref);

        let quarantine_id = "evidence-quarantine-devnet-0001".to_string();
        let quarantine = EvidenceQuarantine {
            quarantine_id: quarantine_id.clone(),
            ticket_id: ticket_id.clone(),
            reason: EvidenceQuarantineReason::PrivacyDisclosureRisk,
            evidence_root: demo_root("quarantine-evidence"),
            sealed_payload_root: demo_root("quarantine-payload"),
            reviewer_committee_root: demo_root("quarantine-reviewers"),
            opened_height: self.height,
            release_height: self.height + self.config.quarantine_ttl_blocks,
            disclosure_bps: self.config.max_disclosure_bps,
        };
        quarantine.validate(&self.config)?;
        let quarantine_root = quarantine.state_root();
        self.evidence_quarantines
            .insert(quarantine_id.clone(), quarantine);

        let ticket_kind = FraudAccelerationTicketKind::NullifierReuse;
        let ticket = FraudAccelerationTicket {
            ticket_id: ticket_id.clone(),
            claim_id: "private-rollup-claim-devnet-nullifier-0001".to_string(),
            rollup_id: "private-defi-rollup-devnet".to_string(),
            ticket_kind,
            status: FraudAccelerationStatus::Quarantined,
            challenger_commitment: demo_root("ticket-challenger"),
            target_operator_commitment: demo_root("ticket-operator"),
            pre_state_root: demo_root("ticket-pre-state"),
            claimed_post_state_root: demo_root("ticket-post-state"),
            evidence_root: demo_root("ticket-evidence"),
            priority_score: ticket_kind.default_priority_score(),
            privacy_set_size: self.config.min_privacy_set_size * 2,
            fee_cap_micro_units: self.config.low_fee_cap_micro_units,
            created_height: self.height,
            expires_height: self.height + self.config.ticket_ttl_blocks,
            recursive_lane_id: lane_id,
            verifier_cache_ref_id: cache_ref_id.clone(),
            quarantine_id: quarantine_id.clone(),
        };
        ticket.validate(&self.config)?;
        let ticket_root = ticket.state_root();
        self.tickets.insert(ticket_id.clone(), ticket);
        self.insert_public_record("fraud_acceleration_ticket", &ticket_id, &ticket_root)?;
        self.insert_public_record("verifier_cache_reference", &cache_ref_id, &cache_ref_root)?;
        self.insert_public_record("evidence_quarantine", &quarantine_id, &quarantine_root)?;

        let trace_id = "invalid-trace-devnet-0001".to_string();
        let trace = InvalidStateTransitionTrace {
            trace_id: trace_id.clone(),
            ticket_id: ticket_id.clone(),
            trace_commitment_root: demo_root("trace-commitment"),
            private_witness_root: demo_root("trace-private-witness"),
            public_input_root: demo_root("trace-public-input"),
            bisection_commitment_root: demo_root("trace-bisection"),
            first_invalid_step: 43,
            last_valid_step: 42,
            disclosed_step_count: 1,
            max_disclosure_bps: self.config.max_disclosure_bps,
            created_height: self.height,
            expires_height: self.height + self.config.trace_ttl_blocks,
        };
        trace.validate(&self.config)?;
        let trace_root = trace.state_root();
        self.invalid_traces.insert(trace_id.clone(), trace);
        self.insert_public_record("invalid_state_transition_trace", &trace_id, &trace_root)?;

        let da_bundle_id = "da-challenge-bundle-devnet-0001".to_string();
        let da_bundle = DaChallengeBundle {
            bundle_id: da_bundle_id.clone(),
            ticket_id: ticket_id.clone(),
            shard_id: "sealed-defi-order-shard-0007".to_string(),
            erasure_commitment_root: demo_root("da-erasure"),
            sample_commitment_root: demo_root("da-samples"),
            withholding_evidence_root: demo_root("da-withholding"),
            sample_count: 128,
            missing_sample_count: 3,
            opened_height: self.height,
            deadline_height: self.height + self.config.da_challenge_window_blocks,
            active: true,
        };
        da_bundle.validate(&self.config)?;
        let da_bundle_root = da_bundle.state_root();
        self.da_bundles.insert(da_bundle_id.clone(), da_bundle);
        self.insert_public_record("da_challenge_bundle", &da_bundle_id, &da_bundle_root)?;

        let sponsorship_id = "low-fee-sponsorship-devnet-0001".to_string();
        let sponsorship = LowFeeChallengeSponsorship {
            sponsorship_id: sponsorship_id.clone(),
            ticket_id: ticket_id.clone(),
            sponsor_commitment: demo_root("sponsor"),
            beneficiary_commitment: demo_root("beneficiary"),
            budget_micro_units: 50_000,
            reserved_micro_units: 750,
            consumed_micro_units: 120,
            created_height: self.height,
            expires_height: self.height + self.config.ticket_ttl_blocks,
        };
        sponsorship.validate(&self.config)?;
        let sponsorship_root = sponsorship.state_root();
        self.sponsorships
            .insert(sponsorship_id.clone(), sponsorship);
        self.insert_public_record(
            "low_fee_challenge_sponsorship",
            &sponsorship_id,
            &sponsorship_root,
        )?;

        let watcher_id = "private-watcher-devnet-0001".to_string();
        let watcher = PrivateWatcherCommitment {
            watcher_id: watcher_id.clone(),
            watcher_commitment: demo_root("watcher-commitment"),
            watched_rollup_root: demo_root("watcher-rollup"),
            nullifier_domain_root: demo_root("watcher-nullifier-domain"),
            encrypted_endpoint_root: demo_root("watcher-endpoint"),
            stake_commitment: demo_root("watcher-stake"),
            privacy_set_size: self.config.min_privacy_set_size * 4,
            active_from_height: self.height,
            active_until_height: self.height + self.config.quarantine_ttl_blocks,
        };
        watcher.validate(&self.config)?;
        let watcher_root = watcher.state_root();
        self.watcher_commitments.insert(watcher_id.clone(), watcher);
        self.insert_public_record("private_watcher_commitment", &watcher_id, &watcher_root)?;

        let recommendation_id = "slashing-recommendation-devnet-0001".to_string();
        let recommendation = OperatorSlashingRecommendation {
            recommendation_id: recommendation_id.clone(),
            ticket_id,
            operator_commitment: demo_root("slashing-operator"),
            offense_root: demo_root("slashing-offense"),
            evidence_quarantine_id: quarantine_id,
            recommended_slash_bps: self.config.slash_bps,
            status: SlashingRecommendationStatus::Submitted,
            created_height: self.height,
            expires_height: self.height + self.config.ticket_ttl_blocks,
        };
        recommendation.validate(&self.config)?;
        let recommendation_root = recommendation.state_root();
        self.slashing_recommendations
            .insert(recommendation_id.clone(), recommendation);
        self.insert_public_record(
            "operator_slashing_recommendation",
            &recommendation_id,
            &recommendation_root,
        )?;

        Ok(())
    }
}

pub fn pq_fraud_proof_accelerator_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PQ-FRAUD-PROOF-ACCELERATOR-STATE",
        &[HashPart::Json(record)],
        32,
    )
}

fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

fn map_root<I>(domain: &str, roots: I) -> String
where
    I: IntoIterator<Item = String>,
{
    let values = roots.into_iter().collect::<Vec<_>>();
    if values.is_empty() {
        return domain_hash(&format!("{domain}:empty"), &[], 32);
    }
    domain_hash(
        domain,
        &values
            .iter()
            .map(|value| HashPart::Str(value.as_str()))
            .collect::<Vec<_>>(),
        32,
    )
}

fn demo_root(label: &str) -> String {
    domain_hash(
        "PQ-FRAUD-PROOF-ACCELERATOR-DEVNET-SEED",
        &[HashPart::Str(label)],
        32,
    )
}

fn ensure_non_empty(label: &str, value: &str) -> PqFraudProofAcceleratorResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} is required"));
    }
    Ok(())
}

fn ensure_positive(value: u64, label: &str) -> PqFraudProofAcceleratorResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(value: u64, label: &str) -> PqFraudProofAcceleratorResult<()> {
    if value > PQ_FRAUD_PROOF_ACCELERATOR_MAX_BPS {
        return Err(format!("{label} exceeds 10000 bps"));
    }
    Ok(())
}

fn ensure_at_most(label: &str, value: usize, maximum: usize) -> PqFraudProofAcceleratorResult<()> {
    if value > maximum {
        return Err(format!("{label} exceeds configured maximum"));
    }
    Ok(())
}

fn ensure_hex_root(label: &str, value: &str) -> PqFraudProofAcceleratorResult<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{label} must be a 32-byte hex root"));
    }
    Ok(())
}

fn ensure_key_matches(label: &str, key: &str, id: &str) -> PqFraudProofAcceleratorResult<()> {
    if key != id {
        return Err(format!("{label} map key does not match id"));
    }
    Ok(())
}

fn ensure_exists<T>(
    id: &str,
    map: &BTreeMap<String, T>,
    label: &str,
) -> PqFraudProofAcceleratorResult<()> {
    if !map.contains_key(id) {
        return Err(format!("{label} references unknown id"));
    }
    Ok(())
}

fn ensure_unique_set(label: &str, values: &BTreeSet<String>) -> PqFraudProofAcceleratorResult<()> {
    for value in values {
        ensure_non_empty(label, value)?;
    }
    Ok(())
}

fn validate_height_window(start: u64, end: u64, label: &str) -> PqFraudProofAcceleratorResult<()> {
    if end <= start {
        return Err(format!("{label} height window is invalid"));
    }
    Ok(())
}
