use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialParallelWitnessReceiptAggregatorRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_WITNESS_RECEIPT_AGGREGATOR_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-parallel-witness-receipt-aggregator-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_WITNESS_RECEIPT_AGGREGATOR_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-parallel-witness-receipt-v1";
pub const PQ_SEALING_SUITE: &str = "ML-KEM-1024-confidential-witness-receipt-envelope-v1";
pub const LOW_COPY_BATCH_ROOT_SCHEME: &str = "low-copy-confidential-witness-receipt-batch-root-v1";
pub const REDACTED_OPERATOR_SUMMARY_SCHEME: &str = "redacted-operator-witness-receipt-summary-v1";
pub const DEVNET_L2_HEIGHT: u64 = 2_880_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_640_000;
pub const DEVNET_EPOCH: u64 = 11_520;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_REBATE_ASSET_ID: &str = "witness-rebate-credit-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_AGGREGATION_MS: u64 = 48;
pub const DEFAULT_MAX_AGGREGATION_MS: u64 = 180;
pub const DEFAULT_TARGET_RECEIPTS_PER_BATCH: u64 = 8_192;
pub const DEFAULT_MAX_RECEIPTS_PER_BATCH: u64 = 65_536;
pub const DEFAULT_MAX_BATCH_BYTES: u64 = 16 * 1024 * 1024;
pub const DEFAULT_QUEUE_SOFT_LIMIT: u64 = 524_288;
pub const DEFAULT_QUEUE_HARD_LIMIT: u64 = 1_048_576;
pub const DEFAULT_PRESSURE_THROTTLE_BPS: u64 = 8_500;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 6;
pub const DEFAULT_LOW_FEE_TARGET_BPS: u64 = 2;
pub const DEFAULT_REBATE_BPS: u64 = 4;
pub const DEFAULT_OPERATOR_FEE_BPS: u64 = 1;
pub const DEFAULT_BATCH_TTL_SLOTS: u64 = 96;
pub const DEFAULT_ATTESTATION_TTL_SLOTS: u64 = 128;
pub const DEFAULT_WORKER_HEARTBEAT_SLOTS: u64 = 4;
pub const DEFAULT_SUMMARY_TTL_SLOTS: u64 = 512;
pub const DEFAULT_MAX_WITNESS_LANES: usize = 131_072;
pub const DEFAULT_MAX_RECEIPT_BATCHES: usize = 1_048_576;
pub const DEFAULT_MAX_WORKERS: usize = 65_536;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_THROTTLES: usize = 1_048_576;
pub const DEFAULT_MAX_REBATES: usize = 2_097_152;
pub const DEFAULT_MAX_SUMMARIES: usize = 1_048_576;
pub const DEFAULT_MAX_EVENTS: usize = 8_388_608;

const D_STATE: &str = "PL2-FAST-PQ-CONF-PARALLEL-WITNESS-RECEIPT-AGG:STATE";
const D_CONFIG: &str = "PL2-FAST-PQ-CONF-PARALLEL-WITNESS-RECEIPT-AGG:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-PARALLEL-WITNESS-RECEIPT-AGG:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-PARALLEL-WITNESS-RECEIPT-AGG:ROOTS";
const D_LANES: &str = "PL2-FAST-PQ-CONF-PARALLEL-WITNESS-RECEIPT-AGG:LANES";
const D_BATCHES: &str = "PL2-FAST-PQ-CONF-PARALLEL-WITNESS-RECEIPT-AGG:BATCHES";
const D_WORKERS: &str = "PL2-FAST-PQ-CONF-PARALLEL-WITNESS-RECEIPT-AGG:WORKERS";
const D_ATTESTATIONS: &str = "PL2-FAST-PQ-CONF-PARALLEL-WITNESS-RECEIPT-AGG:ATTESTATIONS";
const D_THROTTLES: &str = "PL2-FAST-PQ-CONF-PARALLEL-WITNESS-RECEIPT-AGG:THROTTLES";
const D_REBATES: &str = "PL2-FAST-PQ-CONF-PARALLEL-WITNESS-RECEIPT-AGG:REBATES";
const D_SUMMARIES: &str = "PL2-FAST-PQ-CONF-PARALLEL-WITNESS-RECEIPT-AGG:SUMMARIES";
const D_EVENTS: &str = "PL2-FAST-PQ-CONF-PARALLEL-WITNESS-RECEIPT-AGG:EVENTS";
const D_NULLIFIERS: &str = "PL2-FAST-PQ-CONF-PARALLEL-WITNESS-RECEIPT-AGG:NULLIFIERS";

macro_rules! ensure {
    ($condition:expr, $message:literal $(,)?) => {
        if !$condition {
            return Err($message.to_string());
        }
    };
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    Devnet,
    Canary,
    MainnetCandidate,
}

impl RuntimeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::Canary => "canary",
            Self::MainnetCandidate => "mainnet_candidate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessLaneClass {
    HotPath,
    ContractState,
    MoneroBridge,
    RecursiveProof,
    LowFee,
    Watchtower,
    Backfill,
    Operator,
}

impl WitnessLaneClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HotPath => "hot_path",
            Self::ContractState => "contract_state",
            Self::MoneroBridge => "monero_bridge",
            Self::RecursiveProof => "recursive_proof",
            Self::LowFee => "low_fee",
            Self::Watchtower => "watchtower",
            Self::Backfill => "backfill",
            Self::Operator => "operator",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::HotPath => 1_000,
            Self::RecursiveProof => 940,
            Self::ContractState => 900,
            Self::MoneroBridge => 860,
            Self::Watchtower => 780,
            Self::Operator => 720,
            Self::LowFee => 640,
            Self::Backfill => 500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    PressureLimited,
    Aggregating,
    LowFeeOnly,
    Draining,
    Paused,
    Retired,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::PressureLimited => "pressure_limited",
            Self::Aggregating => "aggregating",
            Self::LowFeeOnly => "low_fee_only",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_receipts(self) -> bool {
        matches!(
            self,
            Self::Open | Self::PressureLimited | Self::Aggregating | Self::LowFeeOnly
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptBatchStatus {
    Queued,
    Aggregating,
    Attesting,
    Aggregated,
    Published,
    Settled,
    Expired,
    Rejected,
}

impl ReceiptBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Aggregating => "aggregating",
            Self::Attesting => "attesting",
            Self::Aggregated => "aggregated",
            Self::Published => "published",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn open(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Aggregating | Self::Attesting | Self::Aggregated
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerStatus {
    Ready,
    Busy,
    Saturated,
    CoolingDown,
    Suspended,
    Retired,
}

impl WorkerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Busy => "busy",
            Self::Saturated => "saturated",
            Self::CoolingDown => "cooling_down",
            Self::Suspended => "suspended",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_work(self) -> bool {
        matches!(self, Self::Ready | Self::Busy | Self::Saturated)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Accept,
    Hold,
    Quarantine,
    Reject,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Hold => "hold",
            Self::Quarantine => "quarantine",
            Self::Reject => "reject",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThrottleReason {
    QueuePressure,
    WorkerSaturation,
    FeeSpike,
    AttestationLag,
    PrivacySetBelowTarget,
    OperatorCooldown,
}

impl ThrottleReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::QueuePressure => "queue_pressure",
            Self::WorkerSaturation => "worker_saturation",
            Self::FeeSpike => "fee_spike",
            Self::AttestationLag => "attestation_lag",
            Self::PrivacySetBelowTarget => "privacy_set_below_target",
            Self::OperatorCooldown => "operator_cooldown",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accrued,
    Reserved,
    Paid,
    Expired,
    Slashed,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accrued => "accrued",
            Self::Reserved => "reserved",
            Self::Paid => "paid",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub mode: RuntimeMode,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_aggregation_ms: u64,
    pub max_aggregation_ms: u64,
    pub target_receipts_per_batch: u64,
    pub max_receipts_per_batch: u64,
    pub max_batch_bytes: u64,
    pub queue_soft_limit: u64,
    pub queue_hard_limit: u64,
    pub pressure_throttle_bps: u64,
    pub max_user_fee_bps: u64,
    pub low_fee_target_bps: u64,
    pub rebate_bps: u64,
    pub operator_fee_bps: u64,
    pub batch_ttl_slots: u64,
    pub attestation_ttl_slots: u64,
    pub worker_heartbeat_slots: u64,
    pub summary_ttl_slots: u64,
    pub max_witness_lanes: usize,
    pub max_receipt_batches: usize,
    pub max_workers: usize,
    pub max_attestations: usize,
    pub max_throttles: usize,
    pub max_rebates: usize,
    pub max_summaries: usize,
    pub max_events: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: "nebula-devnet".to_string(),
            monero_network: "monero-devnet".to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEFAULT_REBATE_ASSET_ID.to_string(),
            mode: RuntimeMode::Devnet,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_aggregation_ms: DEFAULT_TARGET_AGGREGATION_MS,
            max_aggregation_ms: DEFAULT_MAX_AGGREGATION_MS,
            target_receipts_per_batch: DEFAULT_TARGET_RECEIPTS_PER_BATCH,
            max_receipts_per_batch: DEFAULT_MAX_RECEIPTS_PER_BATCH,
            max_batch_bytes: DEFAULT_MAX_BATCH_BYTES,
            queue_soft_limit: DEFAULT_QUEUE_SOFT_LIMIT,
            queue_hard_limit: DEFAULT_QUEUE_HARD_LIMIT,
            pressure_throttle_bps: DEFAULT_PRESSURE_THROTTLE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            low_fee_target_bps: DEFAULT_LOW_FEE_TARGET_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            operator_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
            batch_ttl_slots: DEFAULT_BATCH_TTL_SLOTS,
            attestation_ttl_slots: DEFAULT_ATTESTATION_TTL_SLOTS,
            worker_heartbeat_slots: DEFAULT_WORKER_HEARTBEAT_SLOTS,
            summary_ttl_slots: DEFAULT_SUMMARY_TTL_SLOTS,
            max_witness_lanes: DEFAULT_MAX_WITNESS_LANES,
            max_receipt_batches: DEFAULT_MAX_RECEIPT_BATCHES,
            max_workers: DEFAULT_MAX_WORKERS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_throttles: DEFAULT_MAX_THROTTLES,
            max_rebates: DEFAULT_MAX_REBATES,
            max_summaries: DEFAULT_MAX_SUMMARIES,
            max_events: DEFAULT_MAX_EVENTS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.chain_id == CHAIN_ID, "chain id mismatch");
        ensure!(
            self.min_pq_security_bits >= 192,
            "pq security bits below floor"
        );
        ensure!(
            self.target_aggregation_ms <= self.max_aggregation_ms,
            "aggregation latency bounds inverted"
        );
        ensure!(
            self.target_receipts_per_batch <= self.max_receipts_per_batch,
            "batch receipt bounds inverted"
        );
        ensure!(
            self.queue_soft_limit <= self.queue_hard_limit,
            "queue pressure bounds inverted"
        );
        ensure!(
            self.max_user_fee_bps <= 100,
            "max user fee bps too high for low fee runtime"
        );
        ensure!(
            self.low_fee_target_bps <= self.max_user_fee_bps,
            "low fee target exceeds cap"
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "mode": self.mode.as_str(),
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_aggregation_ms": self.target_aggregation_ms,
            "max_aggregation_ms": self.max_aggregation_ms,
            "target_receipts_per_batch": self.target_receipts_per_batch,
            "max_receipts_per_batch": self.max_receipts_per_batch,
            "max_batch_bytes": self.max_batch_bytes,
            "queue_soft_limit": self.queue_soft_limit,
            "queue_hard_limit": self.queue_hard_limit,
            "pressure_throttle_bps": self.pressure_throttle_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "low_fee_target_bps": self.low_fee_target_bps,
            "rebate_bps": self.rebate_bps,
            "operator_fee_bps": self.operator_fee_bps,
            "batch_ttl_slots": self.batch_ttl_slots,
            "attestation_ttl_slots": self.attestation_ttl_slots,
            "worker_heartbeat_slots": self.worker_heartbeat_slots,
            "summary_ttl_slots": self.summary_ttl_slots,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_CONFIG, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub lanes_opened: u64,
    pub receipts_enqueued: u64,
    pub receipt_bytes_enqueued: u64,
    pub batches_opened: u64,
    pub batches_aggregated: u64,
    pub batches_published: u64,
    pub workers_registered: u64,
    pub worker_assignments: u64,
    pub pq_attestations_accepted: u64,
    pub pq_attestations_rejected: u64,
    pub queue_pressure_samples: u64,
    pub throttle_events: u64,
    pub rebates_accrued: u64,
    pub rebates_paid: u64,
    pub summaries_emitted: u64,
    pub low_copy_roots_computed: u64,
    pub redacted_fields: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(D_COUNTERS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub witness_lanes_root: String,
    pub receipt_batches_root: String,
    pub aggregation_workers_root: String,
    pub pq_attestations_root: String,
    pub throttles_root: String,
    pub rebates_root: String,
    pub operator_summaries_root: String,
    pub event_log_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            config_root: record_root(D_CONFIG, &json!({})),
            counters_root: record_root(D_COUNTERS, &json!({})),
            witness_lanes_root: merkle_root(D_LANES, &Vec::<Value>::new()),
            receipt_batches_root: merkle_root(D_BATCHES, &Vec::<Value>::new()),
            aggregation_workers_root: merkle_root(D_WORKERS, &Vec::<Value>::new()),
            pq_attestations_root: merkle_root(D_ATTESTATIONS, &Vec::<Value>::new()),
            throttles_root: merkle_root(D_THROTTLES, &Vec::<Value>::new()),
            rebates_root: merkle_root(D_REBATES, &Vec::<Value>::new()),
            operator_summaries_root: merkle_root(D_SUMMARIES, &Vec::<Value>::new()),
            event_log_root: merkle_root(D_EVENTS, &Vec::<Value>::new()),
            nullifier_root: merkle_root(D_NULLIFIERS, &Vec::<Value>::new()),
            public_record_root: record_root(D_STATE, &json!({})),
            state_root: record_root(D_STATE, &json!({})),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(D_ROOTS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessLane {
    pub lane_id: String,
    pub lane_class: WitnessLaneClass,
    pub operator_commitment: String,
    pub receipt_queue_root: String,
    pub pending_receipts: u64,
    pub pending_bytes: u64,
    pub aggregated_receipts: u64,
    pub dropped_receipts: u64,
    pub pressure_bps: u64,
    pub low_fee_share_bps: u64,
    pub target_batch_size: u64,
    pub status: LaneStatus,
    pub opened_at_slot: u64,
    pub updated_at_slot: u64,
    pub sequence: u64,
}

impl WitnessLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane_class": self.lane_class.as_str(),
            "operator_commitment": self.operator_commitment,
            "receipt_queue_root": self.receipt_queue_root,
            "pending_receipts": self.pending_receipts,
            "pending_bytes": self.pending_bytes,
            "aggregated_receipts": self.aggregated_receipts,
            "dropped_receipts": self.dropped_receipts,
            "pressure_bps": self.pressure_bps,
            "low_fee_share_bps": self.low_fee_share_bps,
            "target_batch_size": self.target_batch_size,
            "status": self.status.as_str(),
            "opened_at_slot": self.opened_at_slot,
            "updated_at_slot": self.updated_at_slot,
            "sequence": self.sequence,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_LANES, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptBatch {
    pub batch_id: String,
    pub lane_id: String,
    pub worker_id: String,
    pub receipt_commitment_root: String,
    pub low_copy_batch_root: String,
    pub pq_witness_root: String,
    pub fee_root: String,
    pub receipt_count: u64,
    pub byte_count: u64,
    pub low_fee_count: u64,
    pub max_user_fee_bps: u64,
    pub aggregation_ms: u64,
    pub status: ReceiptBatchStatus,
    pub opened_at_slot: u64,
    pub aggregated_at_slot: u64,
    pub expires_at_slot: u64,
    pub sequence: u64,
}

impl ReceiptBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "worker_id": self.worker_id,
            "receipt_commitment_root": self.receipt_commitment_root,
            "low_copy_batch_root": self.low_copy_batch_root,
            "pq_witness_root": self.pq_witness_root,
            "fee_root": self.fee_root,
            "receipt_count": self.receipt_count,
            "byte_count": self.byte_count,
            "low_fee_count": self.low_fee_count,
            "max_user_fee_bps": self.max_user_fee_bps,
            "aggregation_ms": self.aggregation_ms,
            "status": self.status.as_str(),
            "opened_at_slot": self.opened_at_slot,
            "aggregated_at_slot": self.aggregated_at_slot,
            "expires_at_slot": self.expires_at_slot,
            "sequence": self.sequence,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_BATCHES, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AggregationWorker {
    pub worker_id: String,
    pub operator_commitment: String,
    pub lane_class: WitnessLaneClass,
    pub status: WorkerStatus,
    pub assigned_batches: u64,
    pub aggregated_receipts: u64,
    pub median_aggregation_ms: u64,
    pub queue_share_bps: u64,
    pub pq_key_commitment: String,
    pub bond_commitment: String,
    pub last_heartbeat_slot: u64,
    pub sequence: u64,
}

impl AggregationWorker {
    pub fn public_record(&self) -> Value {
        json!({
            "worker_id": self.worker_id,
            "operator_commitment": self.operator_commitment,
            "lane_class": self.lane_class.as_str(),
            "status": self.status.as_str(),
            "assigned_batches": self.assigned_batches,
            "aggregated_receipts": self.aggregated_receipts,
            "median_aggregation_ms": self.median_aggregation_ms,
            "queue_share_bps": self.queue_share_bps,
            "pq_key_commitment": self.pq_key_commitment,
            "bond_commitment": self.bond_commitment,
            "last_heartbeat_slot": self.last_heartbeat_slot,
            "sequence": self.sequence,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_WORKERS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqWitnessAttestation {
    pub attestation_id: String,
    pub batch_id: String,
    pub worker_id: String,
    pub attester_commitment: String,
    pub pq_signature_root: String,
    pub witness_receipt_root: String,
    pub transcript_root: String,
    pub verdict: AttestationVerdict,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub attested_at_slot: u64,
    pub expires_at_slot: u64,
    pub sequence: u64,
}

impl PqWitnessAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "batch_id": self.batch_id,
            "worker_id": self.worker_id,
            "attester_commitment": self.attester_commitment,
            "pq_signature_root": self.pq_signature_root,
            "witness_receipt_root": self.witness_receipt_root,
            "transcript_root": self.transcript_root,
            "verdict": self.verdict.as_str(),
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "attested_at_slot": self.attested_at_slot,
            "expires_at_slot": self.expires_at_slot,
            "sequence": self.sequence,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_ATTESTATIONS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueueThrottle {
    pub throttle_id: String,
    pub lane_id: String,
    pub reason: ThrottleReason,
    pub pressure_bps: u64,
    pub admitted_bps: u64,
    pub shed_low_fee_bps: u64,
    pub queue_depth: u64,
    pub worker_saturation_bps: u64,
    pub started_at_slot: u64,
    pub ends_at_slot: u64,
    pub sequence: u64,
}

impl QueueThrottle {
    pub fn public_record(&self) -> Value {
        json!({
            "throttle_id": self.throttle_id,
            "lane_id": self.lane_id,
            "reason": self.reason.as_str(),
            "pressure_bps": self.pressure_bps,
            "admitted_bps": self.admitted_bps,
            "shed_low_fee_bps": self.shed_low_fee_bps,
            "queue_depth": self.queue_depth,
            "worker_saturation_bps": self.worker_saturation_bps,
            "started_at_slot": self.started_at_slot,
            "ends_at_slot": self.ends_at_slot,
            "sequence": self.sequence,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_THROTTLES, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeBatchRebate {
    pub rebate_id: String,
    pub batch_id: String,
    pub lane_id: String,
    pub claimant_commitment: String,
    pub rebate_asset_id: String,
    pub rebate_units: u64,
    pub covered_receipts: u64,
    pub effective_fee_bps: u64,
    pub status: RebateStatus,
    pub accrued_at_slot: u64,
    pub paid_at_slot: u64,
    pub sequence: u64,
}

impl LowFeeBatchRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "claimant_commitment": self.claimant_commitment,
            "rebate_asset_id": self.rebate_asset_id,
            "rebate_units": self.rebate_units,
            "covered_receipts": self.covered_receipts,
            "effective_fee_bps": self.effective_fee_bps,
            "status": self.status.as_str(),
            "accrued_at_slot": self.accrued_at_slot,
            "paid_at_slot": self.paid_at_slot,
            "sequence": self.sequence,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_REBATES, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactedOperatorSummary {
    pub summary_id: String,
    pub operator_commitment: String,
    pub redaction_root: String,
    pub batch_window_root: String,
    pub aggregate_receipt_count: u64,
    pub aggregate_low_fee_count: u64,
    pub median_latency_ms: u64,
    pub queue_pressure_bps: u64,
    pub rebate_units_paid: u64,
    pub redacted_field_count: u64,
    pub emitted_at_slot: u64,
    pub expires_at_slot: u64,
    pub sequence: u64,
}

impl RedactedOperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "operator_commitment": self.operator_commitment,
            "redaction_root": self.redaction_root,
            "batch_window_root": self.batch_window_root,
            "aggregate_receipt_count": self.aggregate_receipt_count,
            "aggregate_low_fee_count": self.aggregate_low_fee_count,
            "median_latency_ms": self.median_latency_ms,
            "queue_pressure_bps": self.queue_pressure_bps,
            "rebate_units_paid": self.rebate_units_paid,
            "redacted_field_count": self.redacted_field_count,
            "emitted_at_slot": self.emitted_at_slot,
            "expires_at_slot": self.expires_at_slot,
            "sequence": self.sequence,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_SUMMARIES, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub current_slot: u64,
    pub witness_lanes: BTreeMap<String, WitnessLane>,
    pub receipt_batches: BTreeMap<String, ReceiptBatch>,
    pub aggregation_workers: BTreeMap<String, AggregationWorker>,
    pub pq_attestations: BTreeMap<String, PqWitnessAttestation>,
    pub throttles: BTreeMap<String, QueueThrottle>,
    pub rebates: BTreeMap<String, LowFeeBatchRebate>,
    pub operator_summaries: BTreeMap<String, RedactedOperatorSummary>,
    pub event_log: BTreeMap<String, Value>,
    pub attestation_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::empty(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            epoch: DEVNET_EPOCH,
            current_slot: DEVNET_EPOCH * 32,
            witness_lanes: BTreeMap::new(),
            receipt_batches: BTreeMap::new(),
            aggregation_workers: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            throttles: BTreeMap::new(),
            rebates: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            event_log: BTreeMap::new(),
            attestation_nullifiers: BTreeSet::new(),
        };
        state.seed_devnet();
        state.refresh_roots();
        state
    }

    pub fn open_witness_lane(
        &mut self,
        lane_class: WitnessLaneClass,
        operator_commitment: impl Into<String>,
        target_batch_size: u64,
    ) -> Result<String> {
        ensure!(
            self.witness_lanes.len() < self.config.max_witness_lanes,
            "witness lane limit reached"
        );
        ensure!(target_batch_size > 0, "target batch size must be nonzero");
        ensure!(
            target_batch_size <= self.config.max_receipts_per_batch,
            "target batch size exceeds cap"
        );
        let operator_commitment = operator_commitment.into();
        require_root("operator_commitment", &operator_commitment)?;
        let sequence = self.counters.lanes_opened + 1;
        let lane_id = stable_id(
            "witness-lane",
            &json!([lane_class.as_str(), operator_commitment.clone(), sequence]),
        );
        let lane = WitnessLane {
            lane_id: lane_id.clone(),
            lane_class,
            operator_commitment,
            receipt_queue_root: deterministic_label_root("empty-receipt-queue", &lane_id, 0),
            pending_receipts: 0,
            pending_bytes: 0,
            aggregated_receipts: 0,
            dropped_receipts: 0,
            pressure_bps: 0,
            low_fee_share_bps: 0,
            target_batch_size,
            status: LaneStatus::Open,
            opened_at_slot: self.current_slot,
            updated_at_slot: self.current_slot,
            sequence,
        };
        self.witness_lanes.insert(lane_id.clone(), lane);
        self.counters.lanes_opened = sequence;
        self.log_event(
            "witness_lane_opened",
            &lane_id,
            json!({ "lane_class": lane_class.as_str() }),
        );
        self.refresh_roots();
        Ok(lane_id)
    }

    pub fn enqueue_receipts(
        &mut self,
        lane_id: &str,
        receipt_commitment_root: impl Into<String>,
        receipt_count: u64,
        byte_count: u64,
        low_fee_count: u64,
    ) -> Result<()> {
        ensure!(receipt_count > 0, "receipt count must be nonzero");
        ensure!(
            low_fee_count <= receipt_count,
            "low fee count exceeds receipt count"
        );
        let root = receipt_commitment_root.into();
        require_root("receipt_commitment_root", &root)?;
        let should_throttle = {
            let lane = self
                .witness_lanes
                .get_mut(lane_id)
                .ok_or_else(|| format!("unknown witness lane: {lane_id}"))?;
            ensure!(
                lane.status.accepts_receipts(),
                "lane is not accepting receipts"
            );
            ensure!(
                lane.pending_receipts.saturating_add(receipt_count) <= self.config.queue_hard_limit,
                "queue hard limit reached"
            );
            lane.pending_receipts = lane.pending_receipts.saturating_add(receipt_count);
            lane.pending_bytes = lane.pending_bytes.saturating_add(byte_count);
            lane.low_fee_share_bps = bps(low_fee_count, receipt_count);
            lane.pressure_bps = bps(lane.pending_receipts, self.config.queue_hard_limit);
            lane.receipt_queue_root =
                low_copy_root(&root, &lane.receipt_queue_root, receipt_count, byte_count);
            lane.updated_at_slot = self.current_slot;
            lane.pending_receipts >= self.config.queue_soft_limit
        };
        self.counters.receipts_enqueued = self
            .counters
            .receipts_enqueued
            .saturating_add(receipt_count);
        self.counters.receipt_bytes_enqueued = self
            .counters
            .receipt_bytes_enqueued
            .saturating_add(byte_count);
        self.counters.low_copy_roots_computed =
            self.counters.low_copy_roots_computed.saturating_add(1);
        if should_throttle {
            if let Some(lane) = self.witness_lanes.get_mut(lane_id) {
                lane.status = LaneStatus::PressureLimited;
            }
            self.record_throttle(lane_id, ThrottleReason::QueuePressure)?;
        }
        self.log_event(
            "receipts_enqueued",
            lane_id,
            json!({ "receipt_count": receipt_count, "byte_count": byte_count }),
        );
        self.refresh_roots();
        Ok(())
    }

    pub fn register_worker(
        &mut self,
        lane_class: WitnessLaneClass,
        operator_commitment: impl Into<String>,
        pq_key_commitment: impl Into<String>,
        bond_commitment: impl Into<String>,
    ) -> Result<String> {
        ensure!(
            self.aggregation_workers.len() < self.config.max_workers,
            "aggregation worker limit reached"
        );
        let operator_commitment = operator_commitment.into();
        let pq_key_commitment = pq_key_commitment.into();
        let bond_commitment = bond_commitment.into();
        require_root("operator_commitment", &operator_commitment)?;
        require_root("pq_key_commitment", &pq_key_commitment)?;
        require_root("bond_commitment", &bond_commitment)?;
        let sequence = self.counters.workers_registered + 1;
        let worker_id = stable_id(
            "aggregation-worker",
            &json!([
                operator_commitment.clone(),
                pq_key_commitment.clone(),
                sequence
            ]),
        );
        let worker = AggregationWorker {
            worker_id: worker_id.clone(),
            operator_commitment,
            lane_class,
            status: WorkerStatus::Ready,
            assigned_batches: 0,
            aggregated_receipts: 0,
            median_aggregation_ms: self.config.target_aggregation_ms,
            queue_share_bps: 0,
            pq_key_commitment,
            bond_commitment,
            last_heartbeat_slot: self.current_slot,
            sequence,
        };
        self.aggregation_workers.insert(worker_id.clone(), worker);
        self.counters.workers_registered = sequence;
        self.log_event(
            "aggregation_worker_registered",
            &worker_id,
            json!({ "lane_class": lane_class.as_str() }),
        );
        self.refresh_roots();
        Ok(worker_id)
    }

    pub fn aggregate_batch(
        &mut self,
        lane_id: &str,
        worker_id: &str,
        requested_receipts: u64,
    ) -> Result<String> {
        ensure!(
            self.receipt_batches.len() < self.config.max_receipt_batches,
            "receipt batch limit reached"
        );
        ensure!(requested_receipts > 0, "requested receipts must be nonzero");
        let (
            receipt_count,
            byte_count,
            low_fee_count,
            receipt_commitment_root,
            low_copy_batch_root,
            aggregation_ms,
        ) = {
            let lane = self
                .witness_lanes
                .get_mut(lane_id)
                .ok_or_else(|| format!("unknown witness lane: {lane_id}"))?;
            let worker = self
                .aggregation_workers
                .get_mut(worker_id)
                .ok_or_else(|| format!("unknown aggregation worker: {worker_id}"))?;
            ensure!(
                worker.status.accepts_work(),
                "worker is not accepting aggregation work"
            );
            ensure!(lane.pending_receipts > 0, "lane has no pending receipts");
            let receipt_count = requested_receipts
                .min(lane.pending_receipts)
                .min(self.config.max_receipts_per_batch);
            let byte_count =
                lane.pending_bytes.saturating_mul(receipt_count) / lane.pending_receipts.max(1);
            let low_fee_count = receipt_count.saturating_mul(lane.low_fee_share_bps) / 10_000;
            lane.pending_receipts = lane.pending_receipts.saturating_sub(receipt_count);
            lane.pending_bytes = lane.pending_bytes.saturating_sub(byte_count);
            lane.aggregated_receipts = lane.aggregated_receipts.saturating_add(receipt_count);
            lane.pressure_bps = bps(lane.pending_receipts, self.config.queue_hard_limit);
            lane.status = if lane.pending_receipts == 0 {
                LaneStatus::Open
            } else {
                LaneStatus::Aggregating
            };
            lane.updated_at_slot = self.current_slot;
            worker.assigned_batches = worker.assigned_batches.saturating_add(1);
            worker.aggregated_receipts = worker.aggregated_receipts.saturating_add(receipt_count);
            worker.median_aggregation_ms = estimated_aggregation_ms(
                receipt_count,
                self.config.target_receipts_per_batch,
                self.config.target_aggregation_ms,
            );
            worker.queue_share_bps = bps(
                receipt_count,
                self.config.target_receipts_per_batch.max(receipt_count),
            );
            worker.status = if worker.median_aggregation_ms > self.config.target_aggregation_ms {
                WorkerStatus::Busy
            } else {
                WorkerStatus::Ready
            };
            worker.last_heartbeat_slot = self.current_slot;
            let sequence = self.counters.batches_opened + 1;
            let receipt_commitment_root =
                deterministic_label_root("receipt-commitment", lane_id, sequence);
            let low_copy_batch_root = low_copy_root(
                &lane.receipt_queue_root,
                &receipt_commitment_root,
                receipt_count,
                byte_count,
            );
            (
                receipt_count,
                byte_count,
                low_fee_count,
                receipt_commitment_root,
                low_copy_batch_root,
                worker.median_aggregation_ms,
            )
        };
        let sequence = self.counters.batches_opened + 1;
        let batch_id = stable_id(
            "receipt-batch",
            &json!([lane_id, worker_id, low_copy_batch_root.clone(), sequence]),
        );
        let batch = ReceiptBatch {
            batch_id: batch_id.clone(),
            lane_id: lane_id.to_string(),
            worker_id: worker_id.to_string(),
            receipt_commitment_root,
            low_copy_batch_root,
            pq_witness_root: deterministic_label_root("pq-witness", &batch_id, sequence),
            fee_root: deterministic_label_root("low-fee-batch-fee", &batch_id, low_fee_count),
            receipt_count,
            byte_count,
            low_fee_count,
            max_user_fee_bps: self.config.max_user_fee_bps,
            aggregation_ms,
            status: ReceiptBatchStatus::Aggregated,
            opened_at_slot: self.current_slot,
            aggregated_at_slot: self.current_slot,
            expires_at_slot: self.current_slot + self.config.batch_ttl_slots,
            sequence,
        };
        self.receipt_batches.insert(batch_id.clone(), batch);
        self.counters.batches_opened = sequence;
        self.counters.batches_aggregated = self.counters.batches_aggregated.saturating_add(1);
        self.counters.worker_assignments = self.counters.worker_assignments.saturating_add(1);
        self.counters.low_copy_roots_computed =
            self.counters.low_copy_roots_computed.saturating_add(1);
        if low_fee_count > 0 {
            self.accrue_rebate(&batch_id)?;
        }
        self.log_event(
            "receipt_batch_aggregated",
            &batch_id,
            json!({ "receipt_count": receipt_count, "low_fee_count": low_fee_count }),
        );
        self.refresh_roots();
        Ok(batch_id)
    }

    pub fn accept_pq_attestation(
        &mut self,
        batch_id: &str,
        worker_id: &str,
        attester_commitment: impl Into<String>,
        pq_signature_root: impl Into<String>,
        transcript_root: impl Into<String>,
        privacy_set_size: u64,
    ) -> Result<String> {
        ensure!(
            self.pq_attestations.len() < self.config.max_attestations,
            "pq attestation limit reached"
        );
        let attester_commitment = attester_commitment.into();
        let pq_signature_root = pq_signature_root.into();
        let transcript_root = transcript_root.into();
        require_root("attester_commitment", &attester_commitment)?;
        require_root("pq_signature_root", &pq_signature_root)?;
        require_root("transcript_root", &transcript_root)?;
        let batch = self
            .receipt_batches
            .get(batch_id)
            .ok_or_else(|| format!("unknown receipt batch: {batch_id}"))?;
        ensure!(
            batch.worker_id == worker_id,
            "worker does not own batch aggregation"
        );
        ensure!(batch.status.open(), "batch no longer accepts attestations");
        let nullifier = stable_id(
            "attestation-nullifier",
            &json!([batch_id, worker_id, attester_commitment.clone()]),
        );
        ensure!(
            !self.attestation_nullifiers.contains(&nullifier),
            "duplicate pq attestation nullifier"
        );
        let verdict = if privacy_set_size >= self.config.min_privacy_set_size {
            AttestationVerdict::Accept
        } else {
            AttestationVerdict::Hold
        };
        let sequence =
            self.counters.pq_attestations_accepted + self.counters.pq_attestations_rejected + 1;
        let attestation_id = stable_id(
            "pq-witness-attestation",
            &json!([batch_id, worker_id, pq_signature_root.clone(), sequence]),
        );
        let attestation = PqWitnessAttestation {
            attestation_id: attestation_id.clone(),
            batch_id: batch_id.to_string(),
            worker_id: worker_id.to_string(),
            attester_commitment,
            pq_signature_root,
            witness_receipt_root: batch.low_copy_batch_root.clone(),
            transcript_root,
            verdict,
            pq_security_bits: self.config.min_pq_security_bits,
            privacy_set_size,
            attested_at_slot: self.current_slot,
            expires_at_slot: self.current_slot + self.config.attestation_ttl_slots,
            sequence,
        };
        if verdict == AttestationVerdict::Accept {
            self.counters.pq_attestations_accepted =
                self.counters.pq_attestations_accepted.saturating_add(1);
        } else {
            self.counters.pq_attestations_rejected =
                self.counters.pq_attestations_rejected.saturating_add(1);
        }
        self.attestation_nullifiers.insert(nullifier);
        self.pq_attestations
            .insert(attestation_id.clone(), attestation);
        self.log_event(
            "pq_witness_attestation_recorded",
            &attestation_id,
            json!({ "verdict": verdict.as_str() }),
        );
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn emit_operator_summary(&mut self, operator_commitment: &str) -> Result<String> {
        ensure!(
            self.operator_summaries.len() < self.config.max_summaries,
            "operator summary limit reached"
        );
        require_root("operator_commitment", operator_commitment)?;
        let mut receipt_count = 0u64;
        let mut low_fee_count = 0u64;
        let mut latency_total = 0u64;
        let mut latency_samples = 0u64;
        let mut pressure_bps = 0u64;
        let worker_ids = self
            .aggregation_workers
            .values()
            .filter(|worker| worker.operator_commitment == operator_commitment)
            .map(|worker| {
                receipt_count = receipt_count.saturating_add(worker.aggregated_receipts);
                latency_total = latency_total.saturating_add(worker.median_aggregation_ms);
                latency_samples = latency_samples.saturating_add(1);
                worker.worker_id.clone()
            })
            .collect::<BTreeSet<_>>();
        for lane in self
            .witness_lanes
            .values()
            .filter(|lane| lane.operator_commitment == operator_commitment)
        {
            low_fee_count = low_fee_count.saturating_add(
                lane.aggregated_receipts
                    .saturating_mul(lane.low_fee_share_bps)
                    / 10_000,
            );
            pressure_bps = pressure_bps.max(lane.pressure_bps);
        }
        let rebate_units_paid = self
            .rebates
            .values()
            .filter(|rebate| rebate.status == RebateStatus::Paid)
            .map(|rebate| rebate.rebate_units)
            .sum::<u64>();
        let sequence = self.counters.summaries_emitted + 1;
        let summary_id = stable_id(
            "redacted-operator-summary",
            &json!([operator_commitment, receipt_count, sequence]),
        );
        let summary = RedactedOperatorSummary {
            summary_id: summary_id.clone(),
            operator_commitment: operator_commitment.to_string(),
            redaction_root: deterministic_label_root("redaction", operator_commitment, sequence),
            batch_window_root: receipt_batches_for_workers_root(&self.receipt_batches, &worker_ids),
            aggregate_receipt_count: receipt_count,
            aggregate_low_fee_count: low_fee_count,
            median_latency_ms: latency_total / latency_samples.max(1),
            queue_pressure_bps: pressure_bps,
            rebate_units_paid,
            redacted_field_count: 7,
            emitted_at_slot: self.current_slot,
            expires_at_slot: self.current_slot + self.config.summary_ttl_slots,
            sequence,
        };
        self.operator_summaries.insert(summary_id.clone(), summary);
        self.counters.summaries_emitted = sequence;
        self.counters.redacted_fields = self.counters.redacted_fields.saturating_add(7);
        self.log_event(
            "redacted_operator_summary_emitted",
            &summary_id,
            json!({ "redacted_field_count": 7 }),
        );
        self.refresh_roots();
        Ok(summary_id)
    }

    pub fn publish_batch(&mut self, batch_id: &str) -> Result<()> {
        let receipt_count = {
            let batch = self
                .receipt_batches
                .get_mut(batch_id)
                .ok_or_else(|| format!("unknown receipt batch: {batch_id}"))?;
            ensure!(
                matches!(
                    batch.status,
                    ReceiptBatchStatus::Aggregated | ReceiptBatchStatus::Attesting
                ),
                "batch is not ready to publish"
            );
            batch.status = ReceiptBatchStatus::Published;
            batch.receipt_count
        };
        self.counters.batches_published = self.counters.batches_published.saturating_add(1);
        self.log_event(
            "receipt_batch_published",
            batch_id,
            json!({ "receipt_count": receipt_count }),
        );
        self.refresh_roots();
        Ok(())
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "scheme": "private_l2_fast_pq_confidential_parallel_witness_receipt_aggregator_runtime_public_record_v1",
            "chain_id": self.config.chain_id,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_attestation_suite": PQ_ATTESTATION_SUITE,
            "pq_sealing_suite": PQ_SEALING_SUITE,
            "low_copy_batch_root_scheme": LOW_COPY_BATCH_ROOT_SCHEME,
            "redacted_operator_summary_scheme": REDACTED_OPERATOR_SUMMARY_SCHEME,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "current_slot": self.current_slot,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": {
                "config_root": self.config.state_root(),
                "counters_root": self.counters.state_root(),
                "witness_lanes_root": values_root(D_LANES, &self.witness_lanes),
                "receipt_batches_root": values_root(D_BATCHES, &self.receipt_batches),
                "aggregation_workers_root": values_root(D_WORKERS, &self.aggregation_workers),
                "pq_attestations_root": values_root(D_ATTESTATIONS, &self.pq_attestations),
                "throttles_root": values_root(D_THROTTLES, &self.throttles),
                "rebates_root": values_root(D_REBATES, &self.rebates),
                "operator_summaries_root": values_root(D_SUMMARIES, &self.operator_summaries),
                "event_log_root": value_map_root(D_EVENTS, &self.event_log),
                "nullifier_root": string_set_root(D_NULLIFIERS, &self.attestation_nullifiers),
            },
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        set_json_field(&mut record, "state_root", json!(self.state_root()));
        record
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = self.config.state_root();
        self.roots.counters_root = self.counters.state_root();
        self.roots.witness_lanes_root = values_root(D_LANES, &self.witness_lanes);
        self.roots.receipt_batches_root = values_root(D_BATCHES, &self.receipt_batches);
        self.roots.aggregation_workers_root = values_root(D_WORKERS, &self.aggregation_workers);
        self.roots.pq_attestations_root = values_root(D_ATTESTATIONS, &self.pq_attestations);
        self.roots.throttles_root = values_root(D_THROTTLES, &self.throttles);
        self.roots.rebates_root = values_root(D_REBATES, &self.rebates);
        self.roots.operator_summaries_root = values_root(D_SUMMARIES, &self.operator_summaries);
        self.roots.event_log_root = value_map_root(D_EVENTS, &self.event_log);
        self.roots.nullifier_root = string_set_root(D_NULLIFIERS, &self.attestation_nullifiers);
        self.roots.public_record_root =
            state_root_from_public_record(&self.public_record_without_state_root());
        self.roots.state_root = self.roots.public_record_root.clone();
    }

    fn record_throttle(&mut self, lane_id: &str, reason: ThrottleReason) -> Result<String> {
        ensure!(
            self.throttles.len() < self.config.max_throttles,
            "queue throttle limit reached"
        );
        let lane = self
            .witness_lanes
            .get(lane_id)
            .ok_or_else(|| format!("unknown witness lane: {lane_id}"))?;
        let sequence = self.counters.throttle_events + 1;
        let throttle_id = stable_id(
            "queue-throttle",
            &json!([lane_id, reason.as_str(), lane.pressure_bps, sequence]),
        );
        let throttle = QueueThrottle {
            throttle_id: throttle_id.clone(),
            lane_id: lane_id.to_string(),
            reason,
            pressure_bps: lane.pressure_bps,
            admitted_bps: self.config.pressure_throttle_bps,
            shed_low_fee_bps: if lane.low_fee_share_bps > 5_000 {
                0
            } else {
                1_000
            },
            queue_depth: lane.pending_receipts,
            worker_saturation_bps: worker_saturation_bps(&self.aggregation_workers),
            started_at_slot: self.current_slot,
            ends_at_slot: self.current_slot + self.config.worker_heartbeat_slots,
            sequence,
        };
        self.throttles.insert(throttle_id.clone(), throttle);
        self.counters.throttle_events = sequence;
        self.counters.queue_pressure_samples =
            self.counters.queue_pressure_samples.saturating_add(1);
        Ok(throttle_id)
    }

    fn accrue_rebate(&mut self, batch_id: &str) -> Result<String> {
        ensure!(
            self.rebates.len() < self.config.max_rebates,
            "rebate limit reached"
        );
        let batch = self
            .receipt_batches
            .get(batch_id)
            .ok_or_else(|| format!("unknown receipt batch: {batch_id}"))?;
        let sequence = self.counters.rebates_accrued + 1;
        let rebate_id = stable_id(
            "low-fee-batch-rebate",
            &json!([batch_id, batch.low_fee_count, sequence]),
        );
        let rebate_units = batch
            .low_fee_count
            .saturating_mul(self.config.rebate_bps)
            .max(1);
        let rebate = LowFeeBatchRebate {
            rebate_id: rebate_id.clone(),
            batch_id: batch_id.to_string(),
            lane_id: batch.lane_id.clone(),
            claimant_commitment: deterministic_label_root("rebate-claimant", batch_id, sequence),
            rebate_asset_id: self.config.rebate_asset_id.clone(),
            rebate_units,
            covered_receipts: batch.low_fee_count,
            effective_fee_bps: self.config.low_fee_target_bps,
            status: RebateStatus::Accrued,
            accrued_at_slot: self.current_slot,
            paid_at_slot: 0,
            sequence,
        };
        self.rebates.insert(rebate_id.clone(), rebate);
        self.counters.rebates_accrued = sequence;
        Ok(rebate_id)
    }

    fn log_event(&mut self, kind: &str, subject: &str, payload: Value) {
        if self.event_log.len() >= self.config.max_events {
            return;
        }
        let sequence = self.event_log.len() as u64 + 1;
        let event_id = stable_id("event", &json!([kind, subject, sequence]));
        self.event_log.insert(
            event_id,
            json!({
                "kind": kind,
                "subject": subject,
                "slot": self.current_slot,
                "sequence": sequence,
                "payload": payload,
            }),
        );
    }

    fn seed_devnet(&mut self) {
        let hot_operator = deterministic_label_root("operator", "hot-path", 1);
        let low_fee_operator = deterministic_label_root("operator", "low-fee", 2);
        let hot_lane = self
            .open_witness_lane(WitnessLaneClass::HotPath, hot_operator.clone(), 16_384)
            .expect("seed hot lane");
        let low_fee_lane = self
            .open_witness_lane(WitnessLaneClass::LowFee, low_fee_operator.clone(), 32_768)
            .expect("seed low fee lane");
        self.enqueue_receipts(
            &hot_lane,
            deterministic_label_root("receipt-root", "hot-path", 1),
            18_432,
            3_145_728,
            6_144,
        )
        .expect("seed hot receipts");
        self.enqueue_receipts(
            &low_fee_lane,
            deterministic_label_root("receipt-root", "low-fee", 1),
            44_288,
            7_340_032,
            44_288,
        )
        .expect("seed low fee receipts");
        let hot_worker = self
            .register_worker(
                WitnessLaneClass::HotPath,
                hot_operator.clone(),
                deterministic_label_root("pq-key", "hot-worker", 1),
                deterministic_label_root("bond", "hot-worker", 1),
            )
            .expect("seed hot worker");
        let low_fee_worker = self
            .register_worker(
                WitnessLaneClass::LowFee,
                low_fee_operator.clone(),
                deterministic_label_root("pq-key", "low-fee-worker", 1),
                deterministic_label_root("bond", "low-fee-worker", 1),
            )
            .expect("seed low fee worker");
        let hot_batch = self
            .aggregate_batch(&hot_lane, &hot_worker, 16_384)
            .expect("seed hot batch");
        let low_fee_batch = self
            .aggregate_batch(&low_fee_lane, &low_fee_worker, 32_768)
            .expect("seed low fee batch");
        self.accept_pq_attestation(
            &hot_batch,
            &hot_worker,
            deterministic_label_root("attester", "hot", 1),
            deterministic_label_root("pq-sig", "hot", 1),
            deterministic_label_root("transcript", "hot", 1),
            self.config.min_privacy_set_size * 2,
        )
        .expect("seed hot attestation");
        self.accept_pq_attestation(
            &low_fee_batch,
            &low_fee_worker,
            deterministic_label_root("attester", "low-fee", 1),
            deterministic_label_root("pq-sig", "low-fee", 1),
            deterministic_label_root("transcript", "low-fee", 1),
            self.config.min_privacy_set_size * 4,
        )
        .expect("seed low fee attestation");
        self.emit_operator_summary(&hot_operator)
            .expect("seed hot summary");
        self.emit_operator_summary(&low_fee_operator)
            .expect("seed low fee summary");
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn set_json_field(record: &mut Value, key: &str, value: Value) {
    if let Value::Object(object) = record {
        object.insert(key.to_string(), value);
    }
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

fn state_root_from_public_record(record: &Value) -> String {
    record_root(D_STATE, record)
}

fn stable_id(kind: &str, record: &Value) -> String {
    domain_hash(
        "PL2-FAST-PQ-CONF-PARALLEL-WITNESS-RECEIPT-AGG:STABLE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        20,
    )
}

fn deterministic_label_root(label: &str, value: &str, sequence: u64) -> String {
    domain_hash(
        "PL2-FAST-PQ-CONF-PARALLEL-WITNESS-RECEIPT-AGG:DETERMINISTIC-LABEL",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(value),
            HashPart::U64(sequence),
        ],
        32,
    )
}

fn low_copy_root(left_root: &str, right_root: &str, receipt_count: u64, byte_count: u64) -> String {
    domain_hash(
        "PL2-FAST-PQ-CONF-PARALLEL-WITNESS-RECEIPT-AGG:LOW-COPY-BATCH-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(LOW_COPY_BATCH_ROOT_SCHEME),
            HashPart::Str(left_root),
            HashPart::Str(right_root),
            HashPart::U64(receipt_count),
            HashPart::U64(byte_count),
        ],
        32,
    )
}

fn values_root<T>(domain: &str, values: &BTreeMap<String, T>) -> String
where
    T: PublicRecord,
{
    let leaves = values
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value.public_record() }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn receipt_batches_for_workers_root(
    values: &BTreeMap<String, ReceiptBatch>,
    worker_ids: &BTreeSet<String>,
) -> String {
    let leaves = values
        .iter()
        .filter(|(_, batch)| worker_ids.contains(&batch.worker_id))
        .map(|(key, value)| json!({ "key": key, "record": value.public_record() }))
        .collect::<Vec<_>>();
    merkle_root(D_BATCHES, &leaves)
}

fn value_map_root(domain: &str, values: &BTreeMap<String, Value>) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn string_set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        0
    } else {
        numerator.saturating_mul(10_000) / denominator
    }
}

fn estimated_aggregation_ms(receipts: u64, target: u64, target_ms: u64) -> u64 {
    let target = target.max(1);
    target_ms
        .saturating_mul(receipts.max(1))
        .saturating_add(target - 1)
        / target
}

fn worker_saturation_bps(workers: &BTreeMap<String, AggregationWorker>) -> u64 {
    if workers.is_empty() {
        return 10_000;
    }
    let busy = workers
        .values()
        .filter(|worker| matches!(worker.status, WorkerStatus::Busy | WorkerStatus::Saturated))
        .count() as u64;
    bps(busy, workers.len() as u64)
}

fn require_root(name: &str, value: &str) -> Result<()> {
    ensure!(!value.trim().is_empty(), "{name} is empty");
    ensure!(value.len() >= 16, "{name} is too short");
    Ok(())
}

trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for WitnessLane {
    fn public_record(&self) -> Value {
        WitnessLane::public_record(self)
    }
}

impl PublicRecord for ReceiptBatch {
    fn public_record(&self) -> Value {
        ReceiptBatch::public_record(self)
    }
}

impl PublicRecord for AggregationWorker {
    fn public_record(&self) -> Value {
        AggregationWorker::public_record(self)
    }
}

impl PublicRecord for PqWitnessAttestation {
    fn public_record(&self) -> Value {
        PqWitnessAttestation::public_record(self)
    }
}

impl PublicRecord for QueueThrottle {
    fn public_record(&self) -> Value {
        QueueThrottle::public_record(self)
    }
}

impl PublicRecord for LowFeeBatchRebate {
    fn public_record(&self) -> Value {
        LowFeeBatchRebate::public_record(self)
    }
}

impl PublicRecord for RedactedOperatorSummary {
    fn public_record(&self) -> Value {
        RedactedOperatorSummary::public_record(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_state_root_is_deterministic() {
        assert_eq!(State::devnet().state_root(), State::devnet().state_root());
    }

    #[test]
    fn public_record_contains_state_root() {
        let state = State::devnet();
        assert_eq!(
            state.public_record()["state_root"].as_str(),
            Some(state.state_root().as_str())
        );
    }
}
