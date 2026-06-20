use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialRecursiveReceiptRollupSchedulerRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_RECURSIVE_RECEIPT_ROLLUP_SCHEDULER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-recursive-receipt-rollup-scheduler-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_RECURSIVE_RECEIPT_ROLLUP_SCHEDULER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 2_880_000;
pub const DEVNET_EPOCH: u64 = 9_216;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-recursive-receipt-rollup-scheduler-v1";
pub const CONFIDENTIAL_RECEIPT_SUITE: &str =
    "monero-l2-confidential-fast-finality-receipt-redacted-root-v1";
pub const RECURSIVE_PROOF_SUITE: &str = "private-l2-recursive-receipt-rollup-proof-amortized-v1";
pub const OPERATOR_SUMMARY_SUITE: &str =
    "redacted-pq-scheduler-operator-summary-disclosure-root-v1";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_TARGET_FINALITY_MS: u64 = 360;
pub const DEFAULT_HARD_FINALITY_MS: u64 = 1_200;
pub const DEFAULT_ROLLUP_TARGET_MS: u64 = 1_800;
pub const DEFAULT_MAX_RECEIPTS_PER_BUNDLE: usize = 2_048;
pub const DEFAULT_MAX_BUNDLES_PER_JOB: usize = 128;
pub const DEFAULT_MAX_LANES: usize = 512;
pub const DEFAULT_MAX_RECEIPTS: usize = 8_388_608;
pub const DEFAULT_MAX_BUNDLES: usize = 1_048_576;
pub const DEFAULT_MAX_PROOF_JOBS: usize = 262_144;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_THROTTLES: usize = 131_072;
pub const DEFAULT_MAX_REBATES: usize = 2_097_152;
pub const DEFAULT_MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 16;
pub const DEFAULT_BUNDLE_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_PROOF_JOB_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 256;
pub const DEFAULT_QUEUE_PRESSURE_HIGH_BPS: u64 = 8_200;
pub const DEFAULT_QUEUE_PRESSURE_CRITICAL_BPS: u64 = 9_400;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 6;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 500;
pub const DEFAULT_PROOF_AMORTIZATION_FLOOR_BPS: u64 = 6_500;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const MAX_BPS: u64 = 10_000;

const D_CONFIG: &str = "PL2-FAST-PQ-CONF-RECURSIVE-RECEIPT-ROLLUP-SCHEDULER:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-RECURSIVE-RECEIPT-ROLLUP-SCHEDULER:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-RECURSIVE-RECEIPT-ROLLUP-SCHEDULER:ROOTS";
const D_STATE: &str = "PL2-FAST-PQ-CONF-RECURSIVE-RECEIPT-ROLLUP-SCHEDULER:STATE";
const D_LANES: &str = "PL2-FAST-PQ-CONF-RECURSIVE-RECEIPT-ROLLUP-SCHEDULER:LANES";
const D_RECEIPTS: &str = "PL2-FAST-PQ-CONF-RECURSIVE-RECEIPT-ROLLUP-SCHEDULER:RECEIPTS";
const D_BUNDLES: &str = "PL2-FAST-PQ-CONF-RECURSIVE-RECEIPT-ROLLUP-SCHEDULER:BUNDLES";
const D_PROOF_JOBS: &str = "PL2-FAST-PQ-CONF-RECURSIVE-RECEIPT-ROLLUP-SCHEDULER:PROOF-JOBS";
const D_ATTESTATIONS: &str = "PL2-FAST-PQ-CONF-RECURSIVE-RECEIPT-ROLLUP-SCHEDULER:PQ-ATTESTATIONS";
const D_THROTTLES: &str = "PL2-FAST-PQ-CONF-RECURSIVE-RECEIPT-ROLLUP-SCHEDULER:QUEUE-THROTTLES";
const D_REBATES: &str = "PL2-FAST-PQ-CONF-RECURSIVE-RECEIPT-ROLLUP-SCHEDULER:LOW-FEE-REBATES";
const D_SUMMARIES: &str = "PL2-FAST-PQ-CONF-RECURSIVE-RECEIPT-ROLLUP-SCHEDULER:OPERATOR-SUMMARIES";
const D_NULLIFIERS: &str = "PL2-FAST-PQ-CONF-RECURSIVE-RECEIPT-ROLLUP-SCHEDULER:NULLIFIERS";
const D_EVENTS: &str = "PL2-FAST-PQ-CONF-RECURSIVE-RECEIPT-ROLLUP-SCHEDULER:EVENTS";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerLaneKind {
    InstantFinality,
    FastFinality,
    MoneroBridge,
    ContractReceipt,
    TokenNetting,
    LowFeeBulk,
    RecursiveOnly,
    EmergencyEscape,
}

impl SchedulerLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InstantFinality => "instant_finality",
            Self::FastFinality => "fast_finality",
            Self::MoneroBridge => "monero_bridge",
            Self::ContractReceipt => "contract_receipt",
            Self::TokenNetting => "token_netting",
            Self::LowFeeBulk => "low_fee_bulk",
            Self::RecursiveOnly => "recursive_only",
            Self::EmergencyEscape => "emergency_escape",
        }
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::EmergencyEscape => 10_000,
            Self::InstantFinality => 9_800,
            Self::MoneroBridge => 9_500,
            Self::FastFinality => 9_000,
            Self::ContractReceipt => 8_300,
            Self::TokenNetting => 7_800,
            Self::RecursiveOnly => 7_100,
            Self::LowFeeBulk => 5_800,
        }
    }

    pub fn is_low_fee(self) -> bool {
        matches!(self, Self::LowFeeBulk | Self::TokenNetting)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Pressured,
    SheddingLowFee,
    RecursiveOnly,
    Draining,
    Paused,
    Retired,
}

impl LaneStatus {
    pub fn accepts_receipts(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Pressured | Self::SheddingLowFee | Self::RecursiveOnly
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptClass {
    Preconfirmation,
    FastFinality,
    ContractExecution,
    MoneroBridge,
    TokenTransfer,
    FeeSponsor,
    RecursiveCarry,
    EmergencyExit,
}

impl ReceiptClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Preconfirmation => "preconfirmation",
            Self::FastFinality => "fast_finality",
            Self::ContractExecution => "contract_execution",
            Self::MoneroBridge => "monero_bridge",
            Self::TokenTransfer => "token_transfer",
            Self::FeeSponsor => "fee_sponsor",
            Self::RecursiveCarry => "recursive_carry",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn finality_weight(self) -> u64 {
        match self {
            Self::EmergencyExit => 1_500,
            Self::FastFinality => 1_250,
            Self::MoneroBridge => 1_150,
            Self::ContractExecution => 1_000,
            Self::Preconfirmation => 900,
            Self::TokenTransfer => 820,
            Self::RecursiveCarry => 780,
            Self::FeeSponsor => 640,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Admitted,
    Bundled,
    Proving,
    FinalityIssued,
    Settled,
    Shed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleStatus {
    Open,
    Sealed,
    ProofQueued,
    Proving,
    Proven,
    Finalized,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofJobStatus {
    Queued,
    Assigned,
    Proving,
    Aggregating,
    Verified,
    FinalityPosted,
    Failed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    SchedulerDecision,
    LanePressure,
    BundleSeal,
    RecursiveProof,
    FastFinalityReceipt,
    LowFeeRebate,
    OperatorSummary,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SchedulerDecision => "scheduler_decision",
            Self::LanePressure => "lane_pressure",
            Self::BundleSeal => "bundle_seal",
            Self::RecursiveProof => "recursive_proof",
            Self::FastFinalityReceipt => "fast_finality_receipt",
            Self::LowFeeRebate => "low_fee_rebate",
            Self::OperatorSummary => "operator_summary",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThrottleAction {
    AdmitAll,
    PreferFastFinality,
    ShedLowFee,
    RecursiveOnly,
    PauseLane,
}

impl ThrottleAction {
    pub fn admits_low_fee(self) -> bool {
        matches!(self, Self::AdmitAll | Self::PreferFastFinality)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accrued,
    Reserved,
    Claimed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SummaryWindow {
    Microblock,
    Epoch,
    Settlement,
    Incident,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub confidential_receipt_suite: String,
    pub recursive_proof_suite: String,
    pub operator_summary_suite: String,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_lanes: usize,
    pub max_receipts: usize,
    pub max_bundles: usize,
    pub max_proof_jobs: usize,
    pub max_attestations: usize,
    pub max_throttles: usize,
    pub max_rebates: usize,
    pub max_operator_summaries: usize,
    pub max_receipts_per_bundle: usize,
    pub max_bundles_per_job: usize,
    pub receipt_ttl_blocks: u64,
    pub bundle_ttl_blocks: u64,
    pub proof_job_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub target_finality_ms: u64,
    pub hard_finality_ms: u64,
    pub rollup_target_ms: u64,
    pub queue_pressure_high_bps: u64,
    pub queue_pressure_critical_bps: u64,
    pub target_user_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub proof_amortization_floor_bps: u64,
    pub allow_queue_pressure_shedding: bool,
    pub allow_low_fee_rebates: bool,
    pub require_pq_scheduler_attestations: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            confidential_receipt_suite: CONFIDENTIAL_RECEIPT_SUITE.to_string(),
            recursive_proof_suite: RECURSIVE_PROOF_SUITE.to_string(),
            operator_summary_suite: OPERATOR_SUMMARY_SUITE.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_lanes: DEFAULT_MAX_LANES,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_bundles: DEFAULT_MAX_BUNDLES,
            max_proof_jobs: DEFAULT_MAX_PROOF_JOBS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_throttles: DEFAULT_MAX_THROTTLES,
            max_rebates: DEFAULT_MAX_REBATES,
            max_operator_summaries: DEFAULT_MAX_OPERATOR_SUMMARIES,
            max_receipts_per_bundle: DEFAULT_MAX_RECEIPTS_PER_BUNDLE,
            max_bundles_per_job: DEFAULT_MAX_BUNDLES_PER_JOB,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            bundle_ttl_blocks: DEFAULT_BUNDLE_TTL_BLOCKS,
            proof_job_ttl_blocks: DEFAULT_PROOF_JOB_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            target_finality_ms: DEFAULT_TARGET_FINALITY_MS,
            hard_finality_ms: DEFAULT_HARD_FINALITY_MS,
            rollup_target_ms: DEFAULT_ROLLUP_TARGET_MS,
            queue_pressure_high_bps: DEFAULT_QUEUE_PRESSURE_HIGH_BPS,
            queue_pressure_critical_bps: DEFAULT_QUEUE_PRESSURE_CRITICAL_BPS,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            proof_amortization_floor_bps: DEFAULT_PROOF_AMORTIZATION_FLOOR_BPS,
            allow_queue_pressure_shedding: true,
            allow_low_fee_rebates: true,
            require_pq_scheduler_attestations: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require(self.chain_id == CHAIN_ID, "chain id mismatch")?;
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch",
        )?;
        require(
            self.schema_version == SCHEMA_VERSION,
            "schema version mismatch",
        )?;
        require(self.hash_suite == HASH_SUITE, "hash suite mismatch")?;
        require(self.min_pq_security_bits >= 128, "pq security bits too low")?;
        require(self.min_privacy_set_size > 0, "privacy set size required")?;
        require(self.max_lanes > 0, "lane capacity required")?;
        require(
            self.max_receipts_per_bundle > 0,
            "bundle receipt limit required",
        )?;
        require(self.max_bundles_per_job > 0, "job bundle limit required")?;
        require(
            self.target_finality_ms <= self.hard_finality_ms,
            "finality target exceeds hard limit",
        )?;
        require(
            self.queue_pressure_high_bps <= MAX_BPS,
            "high pressure bps invalid",
        )?;
        require(
            self.queue_pressure_critical_bps <= MAX_BPS,
            "critical pressure bps invalid",
        )?;
        require(
            self.queue_pressure_high_bps < self.queue_pressure_critical_bps,
            "pressure thresholds inverted",
        )?;
        require(
            self.target_user_fee_bps <= self.max_user_fee_bps,
            "fee target exceeds max",
        )?;
        require(self.max_user_fee_bps <= MAX_BPS, "max fee bps invalid")?;
        require(self.low_fee_rebate_bps <= MAX_BPS, "rebate bps invalid")?;
        require(
            self.proof_amortization_floor_bps <= MAX_BPS,
            "proof amortization bps invalid",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        to_value(self)
    }

    pub fn root(&self) -> String {
        root_json(D_CONFIG, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub ticks: u64,
    pub lanes: u64,
    pub receipts: u64,
    pub bundles: u64,
    pub proof_jobs: u64,
    pub attestations: u64,
    pub throttles: u64,
    pub rebates: u64,
    pub operator_summaries: u64,
    pub shed_receipts: u64,
    pub finalized_receipts: u64,
    pub amortized_proof_savings_microunits: u64,
    pub events: u64,
}

impl Counters {
    pub fn new() -> Self {
        Self {
            ticks: 0,
            lanes: 0,
            receipts: 0,
            bundles: 0,
            proof_jobs: 0,
            attestations: 0,
            throttles: 0,
            rebates: 0,
            operator_summaries: 0,
            shed_receipts: 0,
            finalized_receipts: 0,
            amortized_proof_savings_microunits: 0,
            events: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        to_value(self)
    }

    pub fn root(&self) -> String {
        root_json(D_COUNTERS, &self.public_record())
    }
}

impl Default for Counters {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SchedulerLane {
    pub lane_id: String,
    pub label: String,
    pub kind: SchedulerLaneKind,
    pub status: LaneStatus,
    pub operator_commitment: String,
    pub pq_verifier_key_commitment: String,
    pub accepted_receipt_classes: BTreeSet<ReceiptClass>,
    pub priority_weight: u64,
    pub target_finality_ms: u64,
    pub hard_finality_ms: u64,
    pub queue_capacity: u64,
    pub queued_receipts: u64,
    pub open_bundle_id: Option<String>,
    pub pressure_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_set_size: u64,
    pub created_at_height: u64,
    pub updated_at_height: u64,
}

impl SchedulerLane {
    pub fn accepts(&self, receipt_class: ReceiptClass, low_fee: bool) -> bool {
        self.status.accepts_receipts()
            && self.accepted_receipt_classes.contains(&receipt_class)
            && !(low_fee
                && matches!(
                    self.status,
                    LaneStatus::SheddingLowFee | LaneStatus::RecursiveOnly
                ))
    }

    pub fn recompute_pressure(&mut self) {
        self.pressure_bps = if self.queue_capacity == 0 {
            MAX_BPS
        } else {
            self.queued_receipts.saturating_mul(MAX_BPS) / self.queue_capacity
        }
        .min(MAX_BPS);
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "label": self.label,
            "kind": self.kind,
            "status": self.status,
            "operator_commitment": self.operator_commitment,
            "pq_verifier_key_commitment": self.pq_verifier_key_commitment,
            "accepted_receipt_classes": self.accepted_receipt_classes,
            "priority_weight": self.priority_weight,
            "target_finality_ms": self.target_finality_ms,
            "hard_finality_ms": self.hard_finality_ms,
            "queue_capacity": self.queue_capacity,
            "queued_receipts": self.queued_receipts,
            "open_bundle_id": self.open_bundle_id,
            "pressure_bps": self.pressure_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_set_size": self.privacy_set_size,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialReceipt {
    pub receipt_id: String,
    pub lane_id: String,
    pub receipt_class: ReceiptClass,
    pub status: ReceiptStatus,
    pub user_commitment: String,
    pub redacted_receipt_root: String,
    pub nullifier_hash: String,
    pub fee_asset_id: String,
    pub user_fee_microunits: u64,
    pub target_finality_ms: u64,
    pub privacy_set_size: u64,
    pub low_fee_eligible: bool,
    pub admitted_at_height: u64,
    pub expires_at_height: u64,
    pub bundle_id: Option<String>,
    pub finality_receipt_root: Option<String>,
}

impl ConfidentialReceipt {
    pub fn public_record(&self) -> Value {
        to_value(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptBundle {
    pub bundle_id: String,
    pub lane_id: String,
    pub status: BundleStatus,
    pub receipt_ids: Vec<String>,
    pub receipt_root: String,
    pub recursive_input_root: String,
    pub operator_commitment: String,
    pub pq_attestation_ids: Vec<String>,
    pub total_user_fees_microunits: u64,
    pub amortized_fee_microunits: u64,
    pub target_finality_ms: u64,
    pub sealed_at_height: u64,
    pub expires_at_height: u64,
    pub proof_job_id: Option<String>,
}

impl ReceiptBundle {
    pub fn public_record(&self) -> Value {
        to_value(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecursiveProofJob {
    pub proof_job_id: String,
    pub status: ProofJobStatus,
    pub lane_ids: BTreeSet<String>,
    pub bundle_ids: Vec<String>,
    pub recursive_input_root: String,
    pub aggregate_receipt_root: String,
    pub prover_commitment: String,
    pub scheduler_operator_commitment: String,
    pub pq_attestation_ids: Vec<String>,
    pub expected_proof_bytes: u64,
    pub expected_finality_ms: u64,
    pub amortization_bps: u64,
    pub fee_floor_microunits: u64,
    pub queued_at_height: u64,
    pub expires_at_height: u64,
    pub finality_receipt_root: Option<String>,
}

impl RecursiveProofJob {
    pub fn public_record(&self) -> Value {
        to_value(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSchedulerAttestation {
    pub attestation_id: String,
    pub kind: AttestationKind,
    pub subject_id: String,
    pub lane_id: Option<String>,
    pub operator_commitment: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub security_bits: u16,
    pub signer_weight: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl PqSchedulerAttestation {
    pub fn public_record(&self) -> Value {
        to_value(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueueThrottle {
    pub throttle_id: String,
    pub lane_id: String,
    pub action: ThrottleAction,
    pub pressure_bps: u64,
    pub shed_low_fee_receipts: u64,
    pub preserved_fast_finality_receipts: u64,
    pub reason_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}

impl QueueThrottle {
    pub fn public_record(&self) -> Value {
        to_value(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub bundle_id: Option<String>,
    pub claimant_commitment: String,
    pub fee_asset_id: String,
    pub status: RebateStatus,
    pub original_fee_microunits: u64,
    pub rebate_microunits: u64,
    pub amortization_bps: u64,
    pub proof_job_id: Option<String>,
    pub accrual_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeRebate {
    pub fn public_record(&self) -> Value {
        to_value(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_commitment: String,
    pub window: SummaryWindow,
    pub redacted_lane_root: String,
    pub redacted_receipt_root: String,
    pub redacted_fee_root: String,
    pub pq_attestation_root: String,
    pub finalized_receipts: u64,
    pub shed_receipts: u64,
    pub average_finality_ms: u64,
    pub amortized_savings_microunits: u64,
    pub disclosure_policy_root: String,
    pub issued_at_height: u64,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        to_value(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SchedulerEvent {
    pub sequence: u64,
    pub kind: String,
    pub subject_id: String,
    pub lane_id: Option<String>,
    pub height: u64,
    pub payload_root: String,
}

impl SchedulerEvent {
    pub fn public_record(&self) -> Value {
        to_value(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub lane_root: String,
    pub receipt_root: String,
    pub bundle_root: String,
    pub proof_job_root: String,
    pub pq_attestation_root: String,
    pub throttle_root: String,
    pub rebate_root: String,
    pub operator_summary_root: String,
    pub nullifier_root: String,
    pub event_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        to_value(self)
    }

    pub fn root(&self) -> String {
        root_json(D_ROOTS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitReceiptRequest {
    pub lane_id: String,
    pub receipt_class: ReceiptClass,
    pub user_commitment: String,
    pub redacted_receipt_root: String,
    pub nullifier_hash: String,
    pub user_fee_microunits: u64,
    pub target_finality_ms: u64,
    pub privacy_set_size: u64,
    pub low_fee_eligible: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealBundleRequest {
    pub lane_id: String,
    pub receipt_ids: Vec<String>,
    pub operator_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueueProofJobRequest {
    pub bundle_ids: Vec<String>,
    pub prover_commitment: String,
    pub scheduler_operator_commitment: String,
    pub expected_proof_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub lanes: BTreeMap<String, SchedulerLane>,
    pub receipts: BTreeMap<String, ConfidentialReceipt>,
    pub bundles: BTreeMap<String, ReceiptBundle>,
    pub proof_jobs: BTreeMap<String, RecursiveProofJob>,
    pub pq_attestations: BTreeMap<String, PqSchedulerAttestation>,
    pub queue_throttles: BTreeMap<String, QueueThrottle>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub events: Vec<SchedulerEvent>,
}

impl State {
    pub fn new(config: Config, current_height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            current_height,
            epoch,
            counters: Counters::new(),
            lanes: BTreeMap::new(),
            receipts: BTreeMap::new(),
            bundles: BTreeMap::new(),
            proof_jobs: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            queue_throttles: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            events: Vec::new(),
        })
    }

    pub fn devnet() -> Result<Self> {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT, DEVNET_EPOCH)?;
        let instant = state.create_lane(
            SchedulerLaneKind::InstantFinality,
            "devnet instant finality",
            "devnet-recursive-scheduler-operator-a",
            vec![
                ReceiptClass::FastFinality,
                ReceiptClass::MoneroBridge,
                ReceiptClass::EmergencyExit,
            ],
            16_384,
        )?;
        let fast = state.create_lane(
            SchedulerLaneKind::FastFinality,
            "devnet fast finality",
            "devnet-recursive-scheduler-operator-b",
            vec![
                ReceiptClass::Preconfirmation,
                ReceiptClass::ContractExecution,
                ReceiptClass::TokenTransfer,
            ],
            65_536,
        )?;
        let low_fee = state.create_lane(
            SchedulerLaneKind::LowFeeBulk,
            "devnet low fee amortized",
            "devnet-recursive-scheduler-operator-c",
            vec![
                ReceiptClass::TokenTransfer,
                ReceiptClass::FeeSponsor,
                ReceiptClass::RecursiveCarry,
            ],
            262_144,
        )?;

        let mut receipt_ids = Vec::new();
        for idx in 0..12 {
            let lane_id = if idx < 3 {
                &instant
            } else if idx < 8 {
                &fast
            } else {
                &low_fee
            };
            let receipt_class = if idx < 3 {
                ReceiptClass::FastFinality
            } else if idx < 8 {
                ReceiptClass::ContractExecution
            } else {
                ReceiptClass::TokenTransfer
            };
            let request = SubmitReceiptRequest {
                lane_id: lane_id.clone(),
                receipt_class,
                user_commitment: deterministic_id("DEVNET-USER", &[HashPart::U64(idx)]),
                redacted_receipt_root: deterministic_id(
                    "DEVNET-REDACTED-RECEIPT",
                    &[HashPart::U64(idx)],
                ),
                nullifier_hash: deterministic_id("DEVNET-NULLIFIER", &[HashPart::U64(idx)]),
                user_fee_microunits: if idx < 8 { 8 } else { 2 },
                target_finality_ms: if idx < 3 { 240 } else { 500 },
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE + idx * 1_024,
                low_fee_eligible: idx >= 8,
            };
            receipt_ids.push(state.submit_receipt(request)?);
        }

        let instant_bundle = state.seal_bundle(SealBundleRequest {
            lane_id: instant.clone(),
            receipt_ids: receipt_ids[..3].to_vec(),
            operator_commitment: "devnet-recursive-scheduler-operator-a".to_string(),
        })?;
        let fast_bundle = state.seal_bundle(SealBundleRequest {
            lane_id: fast,
            receipt_ids: receipt_ids[3..8].to_vec(),
            operator_commitment: "devnet-recursive-scheduler-operator-b".to_string(),
        })?;
        let low_fee_bundle = state.seal_bundle(SealBundleRequest {
            lane_id: low_fee,
            receipt_ids: receipt_ids[8..].to_vec(),
            operator_commitment: "devnet-recursive-scheduler-operator-c".to_string(),
        })?;
        let job_id = state.queue_recursive_proof_job(QueueProofJobRequest {
            bundle_ids: vec![instant_bundle, fast_bundle, low_fee_bundle],
            prover_commitment: "devnet-recursive-prover-cluster-a".to_string(),
            scheduler_operator_commitment: "devnet-recursive-scheduler-operator-a".to_string(),
            expected_proof_bytes: 786_432,
        })?;
        state.finalize_proof_job(&job_id, 310)?;
        state.issue_operator_summary(
            "devnet-recursive-scheduler-operator-a",
            SummaryWindow::Epoch,
            310,
        )?;
        Ok(state)
    }

    pub fn create_lane(
        &mut self,
        kind: SchedulerLaneKind,
        label: &str,
        operator_commitment: &str,
        accepted_receipt_classes: Vec<ReceiptClass>,
        queue_capacity: u64,
    ) -> Result<String> {
        self.ensure_capacity("lanes", self.lanes.len(), self.config.max_lanes)?;
        require(!label.is_empty(), "lane label required")?;
        require(
            !operator_commitment.is_empty(),
            "operator commitment required",
        )?;
        require(queue_capacity > 0, "queue capacity required")?;
        let sequence = self.counters.lanes + 1;
        let lane_id = lane_id(kind, label, sequence);
        let accepted_receipt_classes = accepted_receipt_classes
            .into_iter()
            .collect::<BTreeSet<_>>();
        require(
            !accepted_receipt_classes.is_empty(),
            "accepted receipt classes required",
        )?;
        let lane = SchedulerLane {
            lane_id: lane_id.clone(),
            label: label.to_string(),
            kind,
            status: LaneStatus::Open,
            operator_commitment: operator_commitment.to_string(),
            pq_verifier_key_commitment: deterministic_id(
                "LANE-PQ-VERIFYING-KEY",
                &[HashPart::Str(operator_commitment), HashPart::Str(&lane_id)],
            ),
            accepted_receipt_classes,
            priority_weight: kind.default_priority(),
            target_finality_ms: self.config.target_finality_ms,
            hard_finality_ms: self.config.hard_finality_ms,
            queue_capacity,
            queued_receipts: 0,
            open_bundle_id: None,
            pressure_bps: 0,
            fee_ceiling_bps: if kind.is_low_fee() {
                self.config.target_user_fee_bps
            } else {
                self.config.max_user_fee_bps
            },
            privacy_set_size: self.config.min_privacy_set_size,
            created_at_height: self.current_height,
            updated_at_height: self.current_height,
        };
        self.lanes.insert(lane_id.clone(), lane);
        self.counters.lanes = sequence;
        self.emit_event(
            "lane_created",
            &lane_id,
            Some(&lane_id),
            &json!({ "kind": kind }),
        );
        Ok(lane_id)
    }

    pub fn submit_receipt(&mut self, request: SubmitReceiptRequest) -> Result<String> {
        self.ensure_capacity("receipts", self.receipts.len(), self.config.max_receipts)?;
        require(
            !request.user_commitment.is_empty(),
            "user commitment required",
        )?;
        require(
            !request.redacted_receipt_root.is_empty(),
            "redacted receipt root required",
        )?;
        require(
            !request.nullifier_hash.is_empty(),
            "nullifier hash required",
        )?;
        require(
            !self.consumed_nullifiers.contains(&request.nullifier_hash),
            "receipt nullifier already consumed",
        )?;
        require(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "receipt privacy set too small",
        )?;
        require(
            request.user_fee_microunits <= self.max_user_fee_microunits(),
            "user fee exceeds scheduler ceiling",
        )?;
        let low_fee = request.low_fee_eligible
            || request.user_fee_microunits <= self.target_user_fee_microunits();
        let lane = self
            .lanes
            .get(&request.lane_id)
            .ok_or_else(|| "lane missing".to_string())?;
        require(
            lane.accepts(request.receipt_class, low_fee),
            "lane does not accept receipt under current pressure",
        )?;
        let sequence = self.counters.receipts + 1;
        let receipt_id = receipt_id(&request, sequence);
        let receipt = ConfidentialReceipt {
            receipt_id: receipt_id.clone(),
            lane_id: request.lane_id.clone(),
            receipt_class: request.receipt_class,
            status: ReceiptStatus::Admitted,
            user_commitment: request.user_commitment,
            redacted_receipt_root: request.redacted_receipt_root,
            nullifier_hash: request.nullifier_hash.clone(),
            fee_asset_id: self.config.fee_asset_id.clone(),
            user_fee_microunits: request.user_fee_microunits,
            target_finality_ms: request.target_finality_ms,
            privacy_set_size: request.privacy_set_size,
            low_fee_eligible: low_fee,
            admitted_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.receipt_ttl_blocks,
            bundle_id: None,
            finality_receipt_root: None,
        };
        self.receipts.insert(receipt_id.clone(), receipt);
        self.consumed_nullifiers.insert(request.nullifier_hash);
        self.counters.receipts = sequence;
        if let Some(lane) = self.lanes.get_mut(&request.lane_id) {
            lane.queued_receipts = lane.queued_receipts.saturating_add(1);
            lane.recompute_pressure();
            lane.updated_at_height = self.current_height;
        }
        self.apply_queue_pressure(&request.lane_id)?;
        self.emit_event(
            "receipt_admitted",
            &receipt_id,
            Some(&request.lane_id),
            &json!({ "low_fee": low_fee }),
        );
        Ok(receipt_id)
    }

    pub fn seal_bundle(&mut self, request: SealBundleRequest) -> Result<String> {
        self.ensure_capacity("bundles", self.bundles.len(), self.config.max_bundles)?;
        require(!request.receipt_ids.is_empty(), "bundle requires receipts")?;
        require(
            request.receipt_ids.len() <= self.config.max_receipts_per_bundle,
            "bundle receipt limit exceeded",
        )?;
        let lane = self
            .lanes
            .get(&request.lane_id)
            .ok_or_else(|| "lane missing".to_string())?;
        require(
            lane.operator_commitment == request.operator_commitment,
            "operator commitment does not own lane",
        )?;
        let mut total_user_fees_microunits = 0_u64;
        let mut receipt_records = Vec::new();
        for receipt_id in &request.receipt_ids {
            let receipt = self
                .receipts
                .get(receipt_id)
                .ok_or_else(|| "bundle receipt missing".to_string())?;
            require(receipt.lane_id == request.lane_id, "bundle crosses lanes")?;
            require(
                receipt.status == ReceiptStatus::Admitted,
                "receipt not admissible for bundle",
            )?;
            total_user_fees_microunits =
                total_user_fees_microunits.saturating_add(receipt.user_fee_microunits);
            receipt_records.push(receipt.public_record());
        }
        let sequence = self.counters.bundles + 1;
        let receipt_root = merkle_root(D_RECEIPTS, &receipt_records);
        let recursive_input_root = domain_hash(
            "PL2-FAST-PQ-CONF-RECURSIVE-RECEIPT-ROLLUP-SCHEDULER:BUNDLE-INPUT",
            &[
                HashPart::Str(&request.lane_id),
                HashPart::Str(&receipt_root),
                HashPart::U64(sequence),
            ],
            32,
        );
        let bundle_id = bundle_id(&request.lane_id, &receipt_root, sequence);
        let attestation_id = self.issue_pq_attestation(
            AttestationKind::BundleSeal,
            &bundle_id,
            Some(&request.lane_id),
            &request.operator_commitment,
            &recursive_input_root,
        )?;
        let amortized_fee_microunits =
            self.amortized_fee(total_user_fees_microunits, request.receipt_ids.len() as u64);
        let bundle = ReceiptBundle {
            bundle_id: bundle_id.clone(),
            lane_id: request.lane_id.clone(),
            status: BundleStatus::Sealed,
            receipt_ids: request.receipt_ids.clone(),
            receipt_root,
            recursive_input_root,
            operator_commitment: request.operator_commitment,
            pq_attestation_ids: vec![attestation_id],
            total_user_fees_microunits,
            amortized_fee_microunits,
            target_finality_ms: lane.target_finality_ms,
            sealed_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.bundle_ttl_blocks,
            proof_job_id: None,
        };
        for receipt_id in &request.receipt_ids {
            if let Some(receipt) = self.receipts.get_mut(receipt_id) {
                receipt.status = ReceiptStatus::Bundled;
                receipt.bundle_id = Some(bundle_id.clone());
            }
        }
        if let Some(lane) = self.lanes.get_mut(&request.lane_id) {
            lane.queued_receipts = lane
                .queued_receipts
                .saturating_sub(request.receipt_ids.len() as u64);
            lane.open_bundle_id = Some(bundle_id.clone());
            lane.recompute_pressure();
            lane.updated_at_height = self.current_height;
        }
        self.bundles.insert(bundle_id.clone(), bundle);
        self.counters.bundles = sequence;
        self.emit_event(
            "bundle_sealed",
            &bundle_id,
            Some(&request.lane_id),
            &json!({ "receipts": request.receipt_ids.len() }),
        );
        Ok(bundle_id)
    }

    pub fn queue_recursive_proof_job(&mut self, request: QueueProofJobRequest) -> Result<String> {
        self.ensure_capacity(
            "proof_jobs",
            self.proof_jobs.len(),
            self.config.max_proof_jobs,
        )?;
        require(!request.bundle_ids.is_empty(), "proof job requires bundles")?;
        require(
            request.bundle_ids.len() <= self.config.max_bundles_per_job,
            "proof job bundle limit exceeded",
        )?;
        let mut lane_ids = BTreeSet::new();
        let mut bundle_records = Vec::new();
        let mut aggregate_receipt_records = Vec::new();
        let mut total_fees = 0_u64;
        let mut total_amortized = 0_u64;
        for bundle_id in &request.bundle_ids {
            let bundle = self
                .bundles
                .get(bundle_id)
                .ok_or_else(|| "proof job bundle missing".to_string())?;
            require(
                bundle.status == BundleStatus::Sealed,
                "bundle is not sealed",
            )?;
            lane_ids.insert(bundle.lane_id.clone());
            bundle_records.push(bundle.public_record());
            aggregate_receipt_records.push(Value::String(bundle.receipt_root.clone()));
            total_fees = total_fees.saturating_add(bundle.total_user_fees_microunits);
            total_amortized = total_amortized.saturating_add(bundle.amortized_fee_microunits);
        }
        let sequence = self.counters.proof_jobs + 1;
        let recursive_input_root = merkle_root(D_BUNDLES, &bundle_records);
        let aggregate_receipt_root = merkle_root(
            "PL2-FAST-PQ-CONF-RECURSIVE-RECEIPT-ROLLUP-SCHEDULER:AGGREGATE-RECEIPT-ROOT",
            &aggregate_receipt_records,
        );
        let proof_job_id = proof_job_id(&recursive_input_root, sequence);
        let attestation_id = self.issue_pq_attestation(
            AttestationKind::RecursiveProof,
            &proof_job_id,
            None,
            &request.scheduler_operator_commitment,
            &recursive_input_root,
        )?;
        let amortization_bps = if total_fees == 0 {
            MAX_BPS
        } else {
            total_amortized.saturating_mul(MAX_BPS) / total_fees
        };
        let fee_floor_microunits = total_amortized.max(self.target_user_fee_microunits());
        let job = RecursiveProofJob {
            proof_job_id: proof_job_id.clone(),
            status: ProofJobStatus::Queued,
            lane_ids,
            bundle_ids: request.bundle_ids.clone(),
            recursive_input_root,
            aggregate_receipt_root,
            prover_commitment: request.prover_commitment,
            scheduler_operator_commitment: request.scheduler_operator_commitment,
            pq_attestation_ids: vec![attestation_id],
            expected_proof_bytes: request.expected_proof_bytes,
            expected_finality_ms: self.config.rollup_target_ms,
            amortization_bps,
            fee_floor_microunits,
            queued_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.proof_job_ttl_blocks,
            finality_receipt_root: None,
        };
        for bundle_id in &request.bundle_ids {
            if let Some(bundle) = self.bundles.get_mut(bundle_id) {
                bundle.status = BundleStatus::ProofQueued;
                bundle.proof_job_id = Some(proof_job_id.clone());
            }
        }
        self.proof_jobs.insert(proof_job_id.clone(), job);
        self.counters.proof_jobs = sequence;
        self.emit_event(
            "recursive_proof_job_queued",
            &proof_job_id,
            None,
            &json!({ "bundles": request.bundle_ids.len() }),
        );
        Ok(proof_job_id)
    }

    pub fn finalize_proof_job(&mut self, proof_job_id: &str, finality_ms: u64) -> Result<String> {
        let job_view = self
            .proof_jobs
            .get(proof_job_id)
            .ok_or_else(|| "proof job missing".to_string())?
            .clone();
        require(
            matches!(
                job_view.status,
                ProofJobStatus::Queued | ProofJobStatus::Assigned | ProofJobStatus::Proving
            ),
            "proof job not finalizable",
        )?;
        require(
            finality_ms <= self.config.hard_finality_ms,
            "proof job missed hard finality",
        )?;
        let finality_receipt_root = domain_hash(
            "PL2-FAST-PQ-CONF-RECURSIVE-RECEIPT-ROLLUP-SCHEDULER:FAST-FINALITY-RECEIPT",
            &[
                HashPart::Str(proof_job_id),
                HashPart::Str(&job_view.aggregate_receipt_root),
                HashPart::U64(finality_ms),
                HashPart::U64(self.current_height),
            ],
            32,
        );
        let attestation_id = self.issue_pq_attestation(
            AttestationKind::FastFinalityReceipt,
            proof_job_id,
            None,
            &job_view.scheduler_operator_commitment,
            &finality_receipt_root,
        )?;
        if let Some(job) = self.proof_jobs.get_mut(proof_job_id) {
            job.status = ProofJobStatus::FinalityPosted;
            job.finality_receipt_root = Some(finality_receipt_root.clone());
            job.pq_attestation_ids.push(attestation_id);
        }
        let mut rebate_accruals = Vec::new();
        for bundle_id in &job_view.bundle_ids {
            let receipt_ids = if let Some(bundle) = self.bundles.get_mut(bundle_id) {
                bundle.status = BundleStatus::Finalized;
                bundle.receipt_ids.clone()
            } else {
                Vec::new()
            };
            for receipt_id in receipt_ids {
                if let Some(receipt) = self.receipts.get_mut(&receipt_id) {
                    receipt.status = ReceiptStatus::FinalityIssued;
                    receipt.finality_receipt_root = Some(finality_receipt_root.clone());
                    self.counters.finalized_receipts =
                        self.counters.finalized_receipts.saturating_add(1);
                    if receipt.low_fee_eligible && self.config.allow_low_fee_rebates {
                        rebate_accruals.push(receipt_id.clone());
                    }
                }
            }
            for receipt_id in rebate_accruals.drain(..) {
                self.accrue_low_fee_rebate(
                    &receipt_id,
                    bundle_id,
                    proof_job_id,
                    job_view.amortization_bps,
                )?;
            }
        }
        let saved = job_view
            .fee_floor_microunits
            .saturating_sub(self.target_user_fee_microunits());
        self.counters.amortized_proof_savings_microunits = self
            .counters
            .amortized_proof_savings_microunits
            .saturating_add(saved);
        self.emit_event(
            "fast_finality_posted",
            proof_job_id,
            None,
            &json!({ "finality_ms": finality_ms }),
        );
        Ok(finality_receipt_root)
    }

    pub fn apply_queue_pressure(&mut self, lane_id: &str) -> Result<Option<String>> {
        let lane = self
            .lanes
            .get(lane_id)
            .ok_or_else(|| "lane missing".to_string())?
            .clone();
        if !self.config.allow_queue_pressure_shedding {
            return Ok(None);
        }
        let action = if lane.pressure_bps >= self.config.queue_pressure_critical_bps {
            ThrottleAction::RecursiveOnly
        } else if lane.pressure_bps >= self.config.queue_pressure_high_bps {
            if lane.kind.is_low_fee() {
                ThrottleAction::ShedLowFee
            } else {
                ThrottleAction::PreferFastFinality
            }
        } else {
            ThrottleAction::AdmitAll
        };
        let status = match action {
            ThrottleAction::AdmitAll => LaneStatus::Open,
            ThrottleAction::PreferFastFinality => LaneStatus::Pressured,
            ThrottleAction::ShedLowFee => LaneStatus::SheddingLowFee,
            ThrottleAction::RecursiveOnly => LaneStatus::RecursiveOnly,
            ThrottleAction::PauseLane => LaneStatus::Paused,
        };
        if let Some(lane) = self.lanes.get_mut(lane_id) {
            lane.status = status;
            lane.updated_at_height = self.current_height;
        }
        if action == ThrottleAction::AdmitAll {
            return Ok(None);
        }
        self.ensure_capacity(
            "queue throttles",
            self.queue_throttles.len(),
            self.config.max_throttles,
        )?;
        let sequence = self.counters.throttles + 1;
        let throttle_id = throttle_id(lane_id, action, sequence);
        let throttle = QueueThrottle {
            throttle_id: throttle_id.clone(),
            lane_id: lane_id.to_string(),
            action,
            pressure_bps: lane.pressure_bps,
            shed_low_fee_receipts: if action == ThrottleAction::ShedLowFee {
                lane.queued_receipts / 4
            } else {
                0
            },
            preserved_fast_finality_receipts: lane.queued_receipts,
            reason_root: deterministic_id(
                "QUEUE-PRESSURE-REASON",
                &[HashPart::Str(lane_id), HashPart::U64(lane.pressure_bps)],
            ),
            effective_from_height: self.current_height,
            expires_at_height: self.current_height + 4,
        };
        let attestation_subject = throttle_id.clone();
        self.queue_throttles.insert(throttle_id.clone(), throttle);
        self.counters.throttles = sequence;
        let operator_commitment = lane.operator_commitment;
        self.issue_pq_attestation(
            AttestationKind::LanePressure,
            &attestation_subject,
            Some(lane_id),
            &operator_commitment,
            &attestation_subject,
        )?;
        self.emit_event(
            "queue_pressure_throttle",
            &throttle_id,
            Some(lane_id),
            &json!({ "action": action }),
        );
        Ok(Some(throttle_id))
    }

    pub fn issue_operator_summary(
        &mut self,
        operator_commitment: &str,
        window: SummaryWindow,
        average_finality_ms: u64,
    ) -> Result<String> {
        self.ensure_capacity(
            "operator summaries",
            self.operator_summaries.len(),
            self.config.max_operator_summaries,
        )?;
        require(
            !operator_commitment.is_empty(),
            "operator commitment required",
        )?;
        let sequence = self.counters.operator_summaries + 1;
        let matching_lanes = self
            .lanes
            .values()
            .filter(|lane| lane.operator_commitment == operator_commitment)
            .map(SchedulerLane::public_record)
            .collect::<Vec<_>>();
        let matching_attestations = self
            .pq_attestations
            .values()
            .filter(|attestation| attestation.operator_commitment == operator_commitment)
            .map(PqSchedulerAttestation::public_record)
            .collect::<Vec<_>>();
        let summary_id = operator_summary_id(operator_commitment, window, sequence);
        let summary = OperatorSummary {
            summary_id: summary_id.clone(),
            operator_commitment: operator_commitment.to_string(),
            window,
            redacted_lane_root: merkle_root(D_LANES, &matching_lanes),
            redacted_receipt_root: receipt_root(&self.receipts),
            redacted_fee_root: deterministic_id(
                "REDACTED-FEE-ROOT",
                &[
                    HashPart::Str(operator_commitment),
                    HashPart::U64(self.counters.rebates),
                ],
            ),
            pq_attestation_root: merkle_root(D_ATTESTATIONS, &matching_attestations),
            finalized_receipts: self.counters.finalized_receipts,
            shed_receipts: self.counters.shed_receipts,
            average_finality_ms,
            amortized_savings_microunits: self.counters.amortized_proof_savings_microunits,
            disclosure_policy_root: deterministic_id(
                "OPERATOR-SUMMARY-DISCLOSURE-POLICY",
                &[
                    HashPart::Str(operator_commitment),
                    HashPart::Str(OPERATOR_SUMMARY_SUITE),
                ],
            ),
            issued_at_height: self.current_height,
        };
        self.operator_summaries.insert(summary_id.clone(), summary);
        self.counters.operator_summaries = sequence;
        self.issue_pq_attestation(
            AttestationKind::OperatorSummary,
            &summary_id,
            None,
            operator_commitment,
            &summary_id,
        )?;
        self.emit_event(
            "operator_summary_issued",
            &summary_id,
            None,
            &json!({ "window": window }),
        );
        Ok(summary_id)
    }

    pub fn tick(&mut self, blocks: u64) -> Result<()> {
        self.current_height = self.current_height.saturating_add(blocks);
        self.counters.ticks = self.counters.ticks.saturating_add(1);
        let expired_receipts = self
            .receipts
            .iter()
            .filter(|(_, receipt)| {
                receipt.expires_at_height < self.current_height
                    && receipt.status == ReceiptStatus::Admitted
            })
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for receipt_id in expired_receipts {
            if let Some(receipt) = self.receipts.get_mut(&receipt_id) {
                receipt.status = ReceiptStatus::Expired;
                self.counters.shed_receipts = self.counters.shed_receipts.saturating_add(1);
            }
        }
        for lane in self.lanes.values_mut() {
            lane.recompute_pressure();
        }
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.root(),
            counters_root: self.counters.root(),
            lane_root: lane_root(&self.lanes),
            receipt_root: receipt_root(&self.receipts),
            bundle_root: bundle_root(&self.bundles),
            proof_job_root: proof_job_root(&self.proof_jobs),
            pq_attestation_root: pq_attestation_root(&self.pq_attestations),
            throttle_root: throttle_root(&self.queue_throttles),
            rebate_root: rebate_root(&self.low_fee_rebates),
            operator_summary_root: operator_summary_root(&self.operator_summaries),
            nullifier_root: set_root(D_NULLIFIERS, &self.consumed_nullifiers),
            event_root: collection_root(
                D_EVENTS,
                self.events.iter().map(SchedulerEvent::public_record),
            ),
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().root()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_pq_confidential_recursive_receipt_rollup_scheduler_runtime",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "current_height": self.current_height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
            "state_root": self.state_root(),
        })
    }

    fn issue_pq_attestation(
        &mut self,
        kind: AttestationKind,
        subject_id: &str,
        lane_id: Option<&str>,
        operator_commitment: &str,
        transcript_seed: &str,
    ) -> Result<String> {
        self.ensure_capacity(
            "pq attestations",
            self.pq_attestations.len(),
            self.config.max_attestations,
        )?;
        require(!subject_id.is_empty(), "attestation subject required")?;
        require(
            !operator_commitment.is_empty(),
            "attestation operator required",
        )?;
        let sequence = self.counters.attestations + 1;
        let attestation_id = attestation_id(kind, subject_id, sequence);
        let transcript_root = deterministic_id(
            "PQ-ATTESTATION-TRANSCRIPT",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(subject_id),
                HashPart::Str(transcript_seed),
            ],
        );
        let pq_signature_root = deterministic_id(
            "PQ-ATTESTATION-SIGNATURE",
            &[
                HashPart::Str(&attestation_id),
                HashPart::Str(operator_commitment),
                HashPart::Str(&transcript_root),
            ],
        );
        let attestation = PqSchedulerAttestation {
            attestation_id: attestation_id.clone(),
            kind,
            subject_id: subject_id.to_string(),
            lane_id: lane_id.map(str::to_string),
            operator_commitment: operator_commitment.to_string(),
            pq_signature_root,
            transcript_root,
            security_bits: self.config.min_pq_security_bits,
            signer_weight: 1,
            issued_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.attestation_ttl_blocks,
        };
        self.pq_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.attestations = sequence;
        Ok(attestation_id)
    }

    fn accrue_low_fee_rebate(
        &mut self,
        receipt_id: &str,
        bundle_id: &str,
        proof_job_id: &str,
        amortization_bps: u64,
    ) -> Result<String> {
        self.ensure_capacity(
            "rebates",
            self.low_fee_rebates.len(),
            self.config.max_rebates,
        )?;
        let receipt = self
            .receipts
            .get(receipt_id)
            .ok_or_else(|| "rebate receipt missing".to_string())?
            .clone();
        let sequence = self.counters.rebates + 1;
        let rebate_id = rebate_id(receipt_id, sequence);
        let rebate_microunits = receipt
            .user_fee_microunits
            .saturating_mul(self.config.low_fee_rebate_bps)
            / MAX_BPS;
        let rebate = LowFeeRebate {
            rebate_id: rebate_id.clone(),
            receipt_id: receipt_id.to_string(),
            bundle_id: Some(bundle_id.to_string()),
            claimant_commitment: receipt.user_commitment,
            fee_asset_id: self.config.fee_asset_id.clone(),
            status: RebateStatus::Accrued,
            original_fee_microunits: receipt.user_fee_microunits,
            rebate_microunits,
            amortization_bps,
            proof_job_id: Some(proof_job_id.to_string()),
            accrual_height: self.current_height,
            expires_at_height: self.current_height + self.config.rebate_ttl_blocks,
        };
        self.low_fee_rebates.insert(rebate_id.clone(), rebate);
        self.counters.rebates = sequence;
        self.issue_pq_attestation(
            AttestationKind::LowFeeRebate,
            &rebate_id,
            Some(&receipt.lane_id),
            "redacted-low-fee-rebate-operator",
            &rebate_id,
        )?;
        Ok(rebate_id)
    }

    fn amortized_fee(&self, total_fee: u64, receipt_count: u64) -> u64 {
        if receipt_count == 0 {
            return total_fee;
        }
        let shared = total_fee / receipt_count.max(1);
        let discounted = shared.saturating_mul(self.config.proof_amortization_floor_bps) / MAX_BPS;
        discounted.max(1)
    }

    fn max_user_fee_microunits(&self) -> u64 {
        self.config.max_user_fee_bps.max(1)
    }

    fn target_user_fee_microunits(&self) -> u64 {
        self.config.target_user_fee_bps.max(1)
    }

    fn ensure_capacity(&self, label: &str, current: usize, max: usize) -> Result<()> {
        if current >= max {
            return Err(format!("{label} capacity reached"));
        }
        Ok(())
    }

    fn emit_event(&mut self, kind: &str, subject_id: &str, lane_id: Option<&str>, payload: &Value) {
        let sequence = self.events.len() as u64 + 1;
        let event = SchedulerEvent {
            sequence,
            kind: kind.to_string(),
            subject_id: subject_id.to_string(),
            lane_id: lane_id.map(str::to_string),
            height: self.current_height,
            payload_root: root_json(
                "PL2-FAST-PQ-CONF-RECURSIVE-RECEIPT-ROLLUP-SCHEDULER:EVENT-PAYLOAD",
                payload,
            ),
        };
        self.events.push(event);
        self.counters.events = sequence;
    }
}

pub fn devnet() -> State {
    State::devnet().expect("recursive receipt rollup scheduler devnet state")
}

pub fn demo() -> State {
    State::devnet().expect("recursive receipt rollup scheduler demo state")
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn lane_id(kind: SchedulerLaneKind, label: &str, sequence: u64) -> String {
    domain_hash(
        "PL2-FAST-PQ-CONF-RECURSIVE-RECEIPT-ROLLUP-SCHEDULER:LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(label),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn receipt_id(request: &SubmitReceiptRequest, sequence: u64) -> String {
    domain_hash(
        "PL2-FAST-PQ-CONF-RECURSIVE-RECEIPT-ROLLUP-SCHEDULER:RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.lane_id),
            HashPart::Str(request.receipt_class.as_str()),
            HashPart::Str(&request.user_commitment),
            HashPart::Str(&request.redacted_receipt_root),
            HashPart::Str(&request.nullifier_hash),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn bundle_id(lane_id: &str, receipt_root: &str, sequence: u64) -> String {
    deterministic_id(
        "BUNDLE-ID",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(receipt_root),
            HashPart::U64(sequence),
        ],
    )
}

pub fn proof_job_id(recursive_input_root: &str, sequence: u64) -> String {
    deterministic_id(
        "PROOF-JOB-ID",
        &[HashPart::Str(recursive_input_root), HashPart::U64(sequence)],
    )
}

pub fn attestation_id(kind: AttestationKind, subject_id: &str, sequence: u64) -> String {
    deterministic_id(
        "PQ-ATTESTATION-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::U64(sequence),
        ],
    )
}

pub fn throttle_id(lane_id: &str, action: ThrottleAction, sequence: u64) -> String {
    deterministic_id(
        "QUEUE-THROTTLE-ID",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(&format!("{action:?}")),
            HashPart::U64(sequence),
        ],
    )
}

pub fn rebate_id(receipt_id: &str, sequence: u64) -> String {
    deterministic_id(
        "LOW-FEE-REBATE-ID",
        &[HashPart::Str(receipt_id), HashPart::U64(sequence)],
    )
}

pub fn operator_summary_id(
    operator_commitment: &str,
    window: SummaryWindow,
    sequence: u64,
) -> String {
    deterministic_id(
        "OPERATOR-SUMMARY-ID",
        &[
            HashPart::Str(operator_commitment),
            HashPart::Str(&format!("{window:?}")),
            HashPart::U64(sequence),
        ],
    )
}

pub fn lane_root(lanes: &BTreeMap<String, SchedulerLane>) -> String {
    map_root(D_LANES, lanes, SchedulerLane::public_record)
}

pub fn receipt_root(receipts: &BTreeMap<String, ConfidentialReceipt>) -> String {
    map_root(D_RECEIPTS, receipts, ConfidentialReceipt::public_record)
}

pub fn bundle_root(bundles: &BTreeMap<String, ReceiptBundle>) -> String {
    map_root(D_BUNDLES, bundles, ReceiptBundle::public_record)
}

pub fn proof_job_root(proof_jobs: &BTreeMap<String, RecursiveProofJob>) -> String {
    map_root(D_PROOF_JOBS, proof_jobs, RecursiveProofJob::public_record)
}

pub fn pq_attestation_root(attestations: &BTreeMap<String, PqSchedulerAttestation>) -> String {
    map_root(
        D_ATTESTATIONS,
        attestations,
        PqSchedulerAttestation::public_record,
    )
}

pub fn throttle_root(throttles: &BTreeMap<String, QueueThrottle>) -> String {
    map_root(D_THROTTLES, throttles, QueueThrottle::public_record)
}

pub fn rebate_root(rebates: &BTreeMap<String, LowFeeRebate>) -> String {
    map_root(D_REBATES, rebates, LowFeeRebate::public_record)
}

pub fn operator_summary_root(summaries: &BTreeMap<String, OperatorSummary>) -> String {
    map_root(D_SUMMARIES, summaries, OperatorSummary::public_record)
}

pub fn root_json(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(value)],
        32,
    )
}

pub fn collection_root<I>(domain: &str, values: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    merkle_root(domain, &values.into_iter().collect::<Vec<_>>())
}

pub fn set_root(domain: &str, values: &BTreeSet<String>) -> String {
    collection_root(domain, values.iter().cloned().map(Value::String))
}

pub fn map_root<T, F>(domain: &str, values: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    collection_root(domain, values.values().map(public_record))
}

pub fn deterministic_id<'a>(domain: &str, parts: &[HashPart<'a>]) -> String {
    let mut encoded = Vec::with_capacity(parts.len() + 1);
    encoded.push(HashPart::Str(CHAIN_ID));
    for part in parts {
        encoded.push(hash_part_ref(part));
    }
    domain_hash(
        &format!("PL2-FAST-PQ-CONF-RECURSIVE-RECEIPT-ROLLUP-SCHEDULER:{domain}"),
        &encoded,
        32,
    )
}

fn hash_part_ref<'a>(part: &HashPart<'a>) -> HashPart<'a> {
    match part {
        HashPart::Bytes(value) => HashPart::Bytes(value),
        HashPart::Str(value) => HashPart::Str(value),
        HashPart::U64(value) => HashPart::U64(*value),
        HashPart::Int(value) => HashPart::Int(*value),
        HashPart::Json(value) => HashPart::Json(value),
    }
}

fn to_value<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("runtime public record serialization")
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
