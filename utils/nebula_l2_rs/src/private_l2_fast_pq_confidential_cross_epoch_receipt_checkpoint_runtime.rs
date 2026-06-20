use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2FastPqConfidentialCrossEpochReceiptCheckpointRuntimeResult<T> = Result<T>;
pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_CROSS_EPOCH_RECEIPT_CHECKPOINT_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-cross-epoch-receipt-checkpoint-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_CROSS_EPOCH_RECEIPT_CHECKPOINT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_CHECKPOINT_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256s-cross-epoch-receipt-checkpoint-attestation-v1";
pub const CONFIDENTIAL_RECEIPT_ROOT_SUITE: &str = "zk-confidential-fast-receipt-root-redaction-v1";
pub const CROSS_EPOCH_CONTINUITY_SUITE: &str = "monero-l2-cross-epoch-root-continuity-link-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "low-fee-confidential-receipt-checkpoint-rebate-v1";
pub const OPERATOR_SUMMARY_REDACTION_SUITE: &str =
    "redacted-operator-checkpoint-summary-k-anonymous-v1";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_ATTESTORS: u16 = 5;
pub const DEFAULT_TARGET_ATTESTORS: u16 = 13;
pub const DEFAULT_QUORUM_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_SUPERMAJORITY_WEIGHT_BPS: u64 = 8_000;
pub const DEFAULT_TARGET_CHECKPOINT_MS: u64 = 240;
pub const DEFAULT_MAX_CHECKPOINT_MS: u64 = 900;
pub const DEFAULT_RECEIPTS_PER_CHECKPOINT: u32 = 4_096;
pub const DEFAULT_MAX_QUEUE_DEPTH: u32 = 196_608;
pub const DEFAULT_PRESSURE_HIGH_WATERMARK_BPS: u64 = 8_500;
pub const DEFAULT_PRESSURE_CRITICAL_WATERMARK_BPS: u64 = 9_500;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 1_200;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 2_500;
pub const DEFAULT_BASE_RECEIPT_FEE_MICROS: u64 = 8;
pub const DEFAULT_EPOCH_SPAN_BLOCKS: u64 = 512;
pub const DEVNET_L2_HEIGHT: u64 = 2_520_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_410_000;
pub const DEVNET_EPOCH: u64 = 6_144;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_LANES: usize = 8_192;
pub const MAX_RECEIPT_ROOTS: usize = 2_097_152;
pub const MAX_EPOCH_BUNDLES: usize = 262_144;
pub const MAX_ATTESTATIONS: usize = 4_194_304;
pub const MAX_THROTTLES: usize = 524_288;
pub const MAX_REBATES: usize = 2_097_152;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const MAX_PUBLIC_RECORDS: usize = 2_097_152;

const D_STATE: &str = "PL2-FAST-PQ-CONF-XEPOCH-RECEIPT-CHECKPOINT:STATE";
const D_CONFIG: &str = "PL2-FAST-PQ-CONF-XEPOCH-RECEIPT-CHECKPOINT:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-XEPOCH-RECEIPT-CHECKPOINT:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-XEPOCH-RECEIPT-CHECKPOINT:ROOTS";
const D_LANES: &str = "PL2-FAST-PQ-CONF-XEPOCH-RECEIPT-CHECKPOINT:LANES";
const D_RECEIPT_ROOTS: &str = "PL2-FAST-PQ-CONF-XEPOCH-RECEIPT-CHECKPOINT:RECEIPT-ROOTS";
const D_EPOCH_BUNDLES: &str = "PL2-FAST-PQ-CONF-XEPOCH-RECEIPT-CHECKPOINT:EPOCH-BUNDLES";
const D_ATTESTATIONS: &str = "PL2-FAST-PQ-CONF-XEPOCH-RECEIPT-CHECKPOINT:PQ-ATTESTATIONS";
const D_THROTTLES: &str = "PL2-FAST-PQ-CONF-XEPOCH-RECEIPT-CHECKPOINT:THROTTLES";
const D_REBATES: &str = "PL2-FAST-PQ-CONF-XEPOCH-RECEIPT-CHECKPOINT:REBATES";
const D_SUMMARIES: &str = "PL2-FAST-PQ-CONF-XEPOCH-RECEIPT-CHECKPOINT:OPERATOR-SUMMARIES";
const D_PUBLIC: &str = "PL2-FAST-PQ-CONF-XEPOCH-RECEIPT-CHECKPOINT:PUBLIC";
const D_CONTINUITY: &str = "PL2-FAST-PQ-CONF-XEPOCH-RECEIPT-CHECKPOINT:CONTINUITY";
const D_DEVNET: &str = "PL2-FAST-PQ-CONF-XEPOCH-RECEIPT-CHECKPOINT:DEVNET";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointLaneKind {
    Instant,
    Fast,
    LowFee,
    Bridge,
    Defi,
    Operator,
    Recovery,
}

impl CheckpointLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Instant => "instant",
            Self::Fast => "fast",
            Self::LowFee => "low_fee",
            Self::Bridge => "bridge",
            Self::Defi => "defi",
            Self::Operator => "operator",
            Self::Recovery => "recovery",
        }
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::Recovery => 10_000,
            Self::Instant => 9_800,
            Self::Bridge => 9_300,
            Self::Defi => 9_000,
            Self::Fast => 8_700,
            Self::Operator => 7_500,
            Self::LowFee => 5_500,
        }
    }

    pub fn target_ms(self, config: &Config) -> u64 {
        match self {
            Self::Instant => config.target_checkpoint_ms.saturating_div(2).max(1),
            Self::Fast => config.target_checkpoint_ms,
            Self::LowFee => config.target_checkpoint_ms.saturating_mul(6),
            Self::Bridge => config.target_checkpoint_ms.saturating_mul(2),
            Self::Defi => config.target_checkpoint_ms.saturating_mul(2),
            Self::Operator => config.target_checkpoint_ms.saturating_mul(4),
            Self::Recovery => config.target_checkpoint_ms.saturating_div(3).max(1),
        }
    }

    pub fn fee_multiplier_bps(self, config: &Config) -> u64 {
        match self {
            Self::Instant => config.instant_lane_fee_multiplier_bps,
            Self::Fast => config.fast_lane_fee_multiplier_bps,
            Self::LowFee => config.low_fee_lane_multiplier_bps,
            Self::Bridge => config.bridge_lane_fee_multiplier_bps,
            Self::Defi => config.defi_lane_fee_multiplier_bps,
            Self::Operator => 0,
            Self::Recovery => config.recovery_lane_fee_multiplier_bps,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Coalescing,
    Draining,
    Throttled,
    Suspended,
    Retired,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Coalescing => "coalescing",
            Self::Draining => "draining",
            Self::Throttled => "throttled",
            Self::Suspended => "suspended",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_receipts(self) -> bool {
        matches!(self, Self::Open | Self::Coalescing | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptRootKind {
    Wallet,
    Contract,
    Bridge,
    Defi,
    FeeRebate,
    Operator,
    Recovery,
}

impl ReceiptRootKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::Contract => "contract",
            Self::Bridge => "bridge",
            Self::Defi => "defi",
            Self::FeeRebate => "fee_rebate",
            Self::Operator => "operator",
            Self::Recovery => "recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptRootStatus {
    Buffered,
    Checkpointed,
    Attested,
    Finalized,
    Superseded,
    Quarantined,
}

impl ReceiptRootStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Buffered => "buffered",
            Self::Checkpointed => "checkpointed",
            Self::Attested => "attested",
            Self::Finalized => "finalized",
            Self::Superseded => "superseded",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Buffered | Self::Checkpointed | Self::Attested)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleStatus {
    Open,
    Sealing,
    Attesting,
    Finalized,
    CarriedForward,
    Quarantined,
}

impl BundleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealing => "sealing",
            Self::Attesting => "attesting",
            Self::Finalized => "finalized",
            Self::CarriedForward => "carried_forward",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn accepts_roots(self) -> bool {
        matches!(self, Self::Open | Self::Sealing)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Valid,
    ValidWithRedactions,
    NeedsMoreWitnesses,
    StaleContinuity,
    Invalid,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::ValidWithRedactions => "valid_with_redactions",
            Self::NeedsMoreWitnesses => "needs_more_witnesses",
            Self::StaleContinuity => "stale_continuity",
            Self::Invalid => "invalid",
        }
    }

    pub fn positive(self) -> bool {
        matches!(self, Self::Valid | Self::ValidWithRedactions)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PressureMode {
    Accepting,
    Coalescing,
    LowFeeOnlyDeferred,
    SheddingLowFee,
    EmergencyDrain,
}

impl PressureMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepting => "accepting",
            Self::Coalescing => "coalescing",
            Self::LowFeeOnlyDeferred => "low_fee_only_deferred",
            Self::SheddingLowFee => "shedding_low_fee",
            Self::EmergencyDrain => "emergency_drain",
        }
    }

    pub fn is_lossy(self) -> bool {
        matches!(self, Self::SheddingLowFee | Self::EmergencyDrain)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accrued,
    Batched,
    Paid,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_attestors: u16,
    pub target_attestors: u16,
    pub quorum_weight_bps: u64,
    pub supermajority_weight_bps: u64,
    pub target_checkpoint_ms: u64,
    pub max_checkpoint_ms: u64,
    pub receipts_per_checkpoint: u32,
    pub max_queue_depth: u32,
    pub pressure_high_watermark_bps: u64,
    pub pressure_critical_watermark_bps: u64,
    pub epoch_span_blocks: u64,
    pub continuity_lookback_epochs: u64,
    pub base_receipt_fee_micros: u64,
    pub instant_lane_fee_multiplier_bps: u64,
    pub fast_lane_fee_multiplier_bps: u64,
    pub bridge_lane_fee_multiplier_bps: u64,
    pub defi_lane_fee_multiplier_bps: u64,
    pub recovery_lane_fee_multiplier_bps: u64,
    pub low_fee_lane_multiplier_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub min_operator_summary_k_anonymity: u16,
    pub public_summary_window: u64,
    pub enable_cross_epoch_continuity: bool,
    pub enable_queue_pressure_shedding: bool,
    pub enable_low_fee_rebates: bool,
    pub enable_redacted_operator_summaries: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEFAULT_L2_NETWORK.to_string(),
            monero_network: DEFAULT_MONERO_NETWORK.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_attestors: DEFAULT_MIN_ATTESTORS,
            target_attestors: DEFAULT_TARGET_ATTESTORS,
            quorum_weight_bps: DEFAULT_QUORUM_WEIGHT_BPS,
            supermajority_weight_bps: DEFAULT_SUPERMAJORITY_WEIGHT_BPS,
            target_checkpoint_ms: DEFAULT_TARGET_CHECKPOINT_MS,
            max_checkpoint_ms: DEFAULT_MAX_CHECKPOINT_MS,
            receipts_per_checkpoint: DEFAULT_RECEIPTS_PER_CHECKPOINT,
            max_queue_depth: DEFAULT_MAX_QUEUE_DEPTH,
            pressure_high_watermark_bps: DEFAULT_PRESSURE_HIGH_WATERMARK_BPS,
            pressure_critical_watermark_bps: DEFAULT_PRESSURE_CRITICAL_WATERMARK_BPS,
            epoch_span_blocks: DEFAULT_EPOCH_SPAN_BLOCKS,
            continuity_lookback_epochs: 3,
            base_receipt_fee_micros: DEFAULT_BASE_RECEIPT_FEE_MICROS,
            instant_lane_fee_multiplier_bps: 28_000,
            fast_lane_fee_multiplier_bps: 15_000,
            bridge_lane_fee_multiplier_bps: 12_000,
            defi_lane_fee_multiplier_bps: 13_000,
            recovery_lane_fee_multiplier_bps: 30_000,
            low_fee_lane_multiplier_bps: 3_500,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            min_operator_summary_k_anonymity: 32,
            public_summary_window: 64,
            enable_cross_epoch_continuity: true,
            enable_queue_pressure_shedding: true,
            enable_low_fee_rebates: true,
            enable_redacted_operator_summaries: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(D_CONFIG, &self.public_record())
    }

    pub fn lane_fee_micros(&self, lane: CheckpointLaneKind) -> u64 {
        self.base_receipt_fee_micros
            .saturating_mul(lane.fee_multiplier_bps(self))
            / MAX_BPS
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub lanes_opened: u64,
    pub receipt_roots_ingested: u64,
    pub receipt_roots_checkpointed: u64,
    pub epoch_bundles_opened: u64,
    pub epoch_bundles_finalized: u64,
    pub pq_attestations_recorded: u64,
    pub pq_attestations_accepted: u64,
    pub continuity_links_checked: u64,
    pub continuity_breaks: u64,
    pub throttle_events: u64,
    pub low_fee_receipts_deferred: u64,
    pub low_fee_receipts_shed: u64,
    pub rebates_accrued: u64,
    pub rebates_paid: u64,
    pub operator_summaries_emitted: u64,
    pub public_records_pruned: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(D_COUNTERS, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub lanes_root: String,
    pub receipt_roots_root: String,
    pub epoch_bundles_root: String,
    pub pq_attestations_root: String,
    pub throttles_root: String,
    pub rebates_root: String,
    pub operator_summaries_root: String,
    pub public_log_root: String,
    pub continuity_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(D_ROOTS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CheckpointLane {
    pub lane_id: String,
    pub kind: CheckpointLaneKind,
    pub status: LaneStatus,
    pub priority: u64,
    pub shard_id: u16,
    pub queue_depth: u32,
    pub max_queue_depth: u32,
    pub target_checkpoint_ms: u64,
    pub last_checkpoint_ms: u64,
    pub receipts_pending: u64,
    pub receipts_checkpointed: u64,
    pub low_fee_backlog: u64,
    pub operator_commitment: String,
}

impl CheckpointLane {
    pub fn new(
        lane_id: impl Into<String>,
        kind: CheckpointLaneKind,
        shard_id: u16,
        config: &Config,
    ) -> Self {
        let lane_id = lane_id.into();
        Self {
            lane_id,
            kind,
            status: LaneStatus::Open,
            priority: kind.default_priority(),
            shard_id,
            queue_depth: 0,
            max_queue_depth: config.max_queue_depth,
            target_checkpoint_ms: kind.target_ms(config),
            last_checkpoint_ms: 0,
            receipts_pending: 0,
            receipts_checkpointed: 0,
            low_fee_backlog: 0,
            operator_commitment: dev_hash("lane-operator", shard_id as u64),
        }
    }

    pub fn pressure_bps(&self) -> u64 {
        if self.max_queue_depth == 0 {
            return 0;
        }
        (self.queue_depth as u64).saturating_mul(MAX_BPS) / self.max_queue_depth as u64
    }

    pub fn can_accept_receipt(&self) -> bool {
        self.status.accepts_receipts() && self.queue_depth < self.max_queue_depth
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "priority": self.priority,
            "shard_id": self.shard_id,
            "queue_depth": self.queue_depth,
            "max_queue_depth": self.max_queue_depth,
            "pressure_bps": self.pressure_bps(),
            "target_checkpoint_ms": self.target_checkpoint_ms,
            "last_checkpoint_ms": self.last_checkpoint_ms,
            "receipts_pending": self.receipts_pending,
            "receipts_checkpointed": self.receipts_checkpointed,
            "low_fee_backlog": self.low_fee_backlog,
            "operator_commitment": self.operator_commitment
        })
    }

    pub fn root(&self) -> String {
        payload_root(D_LANES, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptRoot {
    pub receipt_root_id: String,
    pub lane_id: String,
    pub kind: ReceiptRootKind,
    pub status: ReceiptRootStatus,
    pub epoch: u64,
    pub l2_height: u64,
    pub monero_height: u64,
    pub receipt_count: u32,
    pub receipt_root: String,
    pub redaction_root: String,
    pub nullifier_root: String,
    pub fee_commitment_root: String,
    pub previous_receipt_root: String,
    pub checkpoint_ms: u64,
    pub fee_paid_micros: u64,
    pub low_fee_eligible: bool,
}

impl ReceiptRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_root_id": self.receipt_root_id,
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "epoch": self.epoch,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "receipt_count": self.receipt_count,
            "receipt_root": self.receipt_root,
            "redaction_root": self.redaction_root,
            "nullifier_root": self.nullifier_root,
            "fee_commitment_root": self.fee_commitment_root,
            "previous_receipt_root": self.previous_receipt_root,
            "checkpoint_ms": self.checkpoint_ms,
            "fee_paid_micros": self.fee_paid_micros,
            "low_fee_eligible": self.low_fee_eligible
        })
    }

    pub fn redacted_public_record(&self) -> Value {
        json!({
            "receipt_root_id": self.receipt_root_id,
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "epoch": self.epoch,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "receipt_count": self.receipt_count,
            "receipt_root": self.receipt_root,
            "redaction_root": self.redaction_root,
            "nullifier_root": self.nullifier_root,
            "fee_commitment_root": self.fee_commitment_root,
            "previous_receipt_root": self.previous_receipt_root,
            "checkpoint_ms": self.checkpoint_ms,
            "low_fee_eligible": self.low_fee_eligible,
            "fee_paid_redacted": true
        })
    }

    pub fn root(&self) -> String {
        payload_root(D_RECEIPT_ROOTS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContinuityLink {
    pub link_id: String,
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub previous_bundle_root: String,
    pub next_bundle_root: String,
    pub carry_root: String,
    pub proof_root: String,
    pub checked: bool,
    pub valid: bool,
}

impl ContinuityLink {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(D_CONTINUITY, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EpochBundle {
    pub bundle_id: String,
    pub epoch: u64,
    pub status: BundleStatus,
    pub start_l2_height: u64,
    pub end_l2_height: u64,
    pub start_monero_height: u64,
    pub end_monero_height: u64,
    pub lane_ids: Vec<String>,
    pub receipt_root_ids: Vec<String>,
    pub receipt_count: u64,
    pub previous_epoch_bundle_root: String,
    pub receipt_roots_root: String,
    pub continuity_link_root: String,
    pub pq_attestation_root: String,
    pub low_fee_rebate_root: String,
    pub sealed_at_ms: u64,
}

impl EpochBundle {
    pub fn public_record(&self) -> Value {
        json!({
            "bundle_id": self.bundle_id,
            "epoch": self.epoch,
            "status": self.status.as_str(),
            "start_l2_height": self.start_l2_height,
            "end_l2_height": self.end_l2_height,
            "start_monero_height": self.start_monero_height,
            "end_monero_height": self.end_monero_height,
            "lane_ids": self.lane_ids,
            "receipt_root_ids": self.receipt_root_ids,
            "receipt_count": self.receipt_count,
            "previous_epoch_bundle_root": self.previous_epoch_bundle_root,
            "receipt_roots_root": self.receipt_roots_root,
            "continuity_link_root": self.continuity_link_root,
            "pq_attestation_root": self.pq_attestation_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "sealed_at_ms": self.sealed_at_ms
        })
    }

    pub fn root(&self) -> String {
        payload_root(D_EPOCH_BUNDLES, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCheckpointAttestation {
    pub attestation_id: String,
    pub bundle_id: String,
    pub attestor_id: String,
    pub suite: String,
    pub verdict: AttestationVerdict,
    pub weight_bps: u64,
    pub pq_security_bits: u16,
    pub signature_commitment: String,
    pub public_key_commitment: String,
    pub witness_root: String,
    pub redaction_root: String,
    pub continuity_root: String,
    pub l2_height: u64,
    pub monero_height: u64,
}

impl PqCheckpointAttestation {
    pub fn is_accepting(&self, config: &Config) -> bool {
        self.verdict.positive() && self.pq_security_bits >= config.min_pq_security_bits
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "bundle_id": self.bundle_id,
            "attestor_id": self.attestor_id,
            "suite": self.suite,
            "verdict": self.verdict.as_str(),
            "weight_bps": self.weight_bps,
            "pq_security_bits": self.pq_security_bits,
            "signature_commitment": self.signature_commitment,
            "public_key_commitment": self.public_key_commitment,
            "witness_root": self.witness_root,
            "redaction_root": self.redaction_root,
            "continuity_root": self.continuity_root,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height
        })
    }

    pub fn root(&self) -> String {
        payload_root(D_ATTESTATIONS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueueThrottle {
    pub throttle_id: String,
    pub lane_id: String,
    pub mode: PressureMode,
    pub queue_depth: u32,
    pub max_queue_depth: u32,
    pub pressure_bps: u64,
    pub deferred_low_fee_receipts: u64,
    pub shed_low_fee_receipts: u64,
    pub target_checkpoint_ms: u64,
    pub observed_checkpoint_ms: u64,
    pub reason: String,
    pub active: bool,
}

impl QueueThrottle {
    pub fn public_record(&self) -> Value {
        json!({
            "throttle_id": self.throttle_id,
            "lane_id": self.lane_id,
            "mode": self.mode.as_str(),
            "queue_depth": self.queue_depth,
            "max_queue_depth": self.max_queue_depth,
            "pressure_bps": self.pressure_bps,
            "deferred_low_fee_receipts": self.deferred_low_fee_receipts,
            "shed_low_fee_receipts": self.shed_low_fee_receipts,
            "target_checkpoint_ms": self.target_checkpoint_ms,
            "observed_checkpoint_ms": self.observed_checkpoint_ms,
            "reason": self.reason,
            "active": self.active
        })
    }

    pub fn root(&self) -> String {
        payload_root(D_THROTTLES, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeCheckpointRebate {
    pub rebate_id: String,
    pub receipt_root_id: String,
    pub lane_id: String,
    pub epoch: u64,
    pub status: RebateStatus,
    pub fee_asset_id: String,
    pub fee_paid_micros: u64,
    pub rebate_bps: u64,
    pub rebate_micros: u64,
    pub sponsor_commitment: String,
    pub payout_commitment: String,
}

impl LowFeeCheckpointRebate {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(D_REBATES, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactedOperatorSummary {
    pub summary_id: String,
    pub epoch: u64,
    pub l2_height: u64,
    pub monero_height: u64,
    pub lane_count: usize,
    pub bundle_count: usize,
    pub receipt_root_count: usize,
    pub attestation_count: usize,
    pub total_receipts: u64,
    pub active_pressure_mode: PressureMode,
    pub avg_checkpoint_ms: u64,
    pub rebate_micros: u64,
    pub k_anonymity: u16,
    pub redacted: bool,
    pub roots: Roots,
}

impl RedactedOperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "epoch": self.epoch,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "lane_count": self.lane_count,
            "bundle_count": self.bundle_count,
            "receipt_root_count": self.receipt_root_count,
            "attestation_count": self.attestation_count,
            "total_receipts": self.total_receipts,
            "active_pressure_mode": self.active_pressure_mode.as_str(),
            "avg_checkpoint_ms": self.avg_checkpoint_ms,
            "rebate_micros": self.rebate_micros,
            "k_anonymity": self.k_anonymity,
            "redacted": self.redacted,
            "roots": self.roots.public_record()
        })
    }

    pub fn root(&self) -> String {
        payload_root(D_SUMMARIES, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub lanes: BTreeMap<String, CheckpointLane>,
    pub receipt_roots: BTreeMap<String, ReceiptRoot>,
    pub epoch_bundles: BTreeMap<String, EpochBundle>,
    pub pq_attestations: BTreeMap<String, PqCheckpointAttestation>,
    pub throttles: BTreeMap<String, QueueThrottle>,
    pub rebates: BTreeMap<String, LowFeeCheckpointRebate>,
    pub operator_summaries: BTreeMap<String, RedactedOperatorSummary>,
    pub continuity_links: BTreeMap<String, ContinuityLink>,
    pub public_log: BTreeMap<String, Value>,
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::default(),
            lanes: BTreeMap::new(),
            receipt_roots: BTreeMap::new(),
            epoch_bundles: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            throttles: BTreeMap::new(),
            rebates: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            continuity_links: BTreeMap::new(),
            public_log: BTreeMap::new(),
        };
        for (index, kind) in [
            CheckpointLaneKind::Instant,
            CheckpointLaneKind::Fast,
            CheckpointLaneKind::LowFee,
            CheckpointLaneKind::Bridge,
            CheckpointLaneKind::Defi,
            CheckpointLaneKind::Operator,
            CheckpointLaneKind::Recovery,
        ]
        .iter()
        .enumerate()
        {
            let lane_id = format!("lane-devnet-{}", kind.as_str());
            let lane = CheckpointLane::new(lane_id.clone(), *kind, index as u16, &state.config);
            state.lanes.insert(lane_id, lane);
            state.counters.lanes_opened = state.counters.lanes_opened.saturating_add(1);
        }
        state.refresh_roots();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let instant = state
            .ingest_receipt_root(
                "lane-devnet-instant",
                ReceiptRootKind::Wallet,
                DEVNET_EPOCH,
                1_024,
                CheckpointLaneKind::Instant,
            )
            .expect("devnet instant receipt root");
        let fast = state
            .ingest_receipt_root(
                "lane-devnet-fast",
                ReceiptRootKind::Contract,
                DEVNET_EPOCH,
                2_048,
                CheckpointLaneKind::Fast,
            )
            .expect("devnet fast receipt root");
        let low_fee = state
            .ingest_receipt_root(
                "lane-devnet-low_fee",
                ReceiptRootKind::FeeRebate,
                DEVNET_EPOCH,
                4_096,
                CheckpointLaneKind::LowFee,
            )
            .expect("devnet low fee receipt root");
        let bundle_id = state
            .seal_epoch_bundle(DEVNET_EPOCH, &[instant, fast, low_fee])
            .expect("devnet epoch bundle");
        state
            .record_pq_attestation(
                &bundle_id,
                "attestor-devnet-0",
                AttestationVerdict::ValidWithRedactions,
                3_400,
            )
            .expect("devnet pq attestation 0");
        state
            .record_pq_attestation(
                &bundle_id,
                "attestor-devnet-1",
                AttestationVerdict::Valid,
                3_400,
            )
            .expect("devnet pq attestation 1");
        state
            .record_pq_attestation(
                &bundle_id,
                "attestor-devnet-2",
                AttestationVerdict::Valid,
                3_400,
            )
            .expect("devnet pq attestation 2");
        state.apply_queue_pressure("lane-devnet-low_fee", 182_000, 680);
        state.emit_operator_summary();
        state.refresh_roots();
        state
    }

    pub fn ingest_receipt_root(
        &mut self,
        lane_id: &str,
        kind: ReceiptRootKind,
        epoch: u64,
        receipt_count: u32,
        lane_kind: CheckpointLaneKind,
    ) -> Result<String> {
        if !self.lanes.contains_key(lane_id) {
            let lane = CheckpointLane::new(
                lane_id.to_string(),
                lane_kind,
                self.lanes.len() as u16,
                &self.config,
            );
            self.lanes.insert(lane_id.to_string(), lane);
            self.counters.lanes_opened = self.counters.lanes_opened.saturating_add(1);
        }
        let lane = self
            .lanes
            .get_mut(lane_id)
            .ok_or_else(|| format!("missing checkpoint lane {lane_id}"))?;
        if !lane.can_accept_receipt() {
            return Err(format!(
                "checkpoint lane {lane_id} is not accepting receipts"
            ));
        }
        let next = self.counters.receipt_roots_ingested.saturating_add(1);
        let receipt_root_id = format!("receipt-root-{epoch}-{next}");
        let previous_receipt_root = self
            .receipt_roots
            .values()
            .filter(|root| root.lane_id == lane_id)
            .next_back()
            .map(ReceiptRoot::root)
            .unwrap_or_else(|| dev_hash("receipt-root-genesis", epoch));
        let fee_paid_micros = self
            .config
            .lane_fee_micros(lane_kind)
            .saturating_mul(receipt_count as u64);
        let root = ReceiptRoot {
            receipt_root_id: receipt_root_id.clone(),
            lane_id: lane_id.to_string(),
            kind,
            status: ReceiptRootStatus::Buffered,
            epoch,
            l2_height: DEVNET_L2_HEIGHT.saturating_add(next),
            monero_height: DEVNET_MONERO_HEIGHT.saturating_add(next / 2),
            receipt_count,
            receipt_root: dev_hash("receipt-root", next),
            redaction_root: dev_hash("receipt-redaction", next),
            nullifier_root: dev_hash("receipt-nullifier", next),
            fee_commitment_root: dev_hash("receipt-fee-commitment", next),
            previous_receipt_root,
            checkpoint_ms: lane.kind.target_ms(&self.config),
            fee_paid_micros,
            low_fee_eligible: lane_kind == CheckpointLaneKind::LowFee,
        };
        lane.queue_depth = lane.queue_depth.saturating_add(receipt_count);
        lane.receipts_pending = lane.receipts_pending.saturating_add(receipt_count as u64);
        if root.low_fee_eligible {
            lane.low_fee_backlog = lane.low_fee_backlog.saturating_add(receipt_count as u64);
        }
        self.receipt_roots.insert(receipt_root_id.clone(), root);
        self.counters.receipt_roots_ingested = next;
        self.prune();
        self.refresh_roots();
        Ok(receipt_root_id)
    }

    pub fn seal_epoch_bundle(&mut self, epoch: u64, receipt_root_ids: &[String]) -> Result<String> {
        if receipt_root_ids.is_empty() {
            return Err("cannot seal checkpoint bundle without receipt roots".to_string());
        }
        let next = self.counters.epoch_bundles_opened.saturating_add(1);
        let bundle_id = format!("epoch-bundle-{epoch}-{next}");
        let mut lane_ids = BTreeSet::new();
        let mut receipt_count = 0_u64;
        let mut l2_heights = Vec::new();
        let mut monero_heights = Vec::new();
        let mut low_fee_receipt_root_ids = Vec::new();
        let mut low_fee_rebate_ids = Vec::new();
        for receipt_root_id in receipt_root_ids {
            let receipt_root = self
                .receipt_roots
                .get_mut(receipt_root_id)
                .ok_or_else(|| format!("missing receipt root {receipt_root_id}"))?;
            receipt_root.status = ReceiptRootStatus::Checkpointed;
            lane_ids.insert(receipt_root.lane_id.clone());
            receipt_count = receipt_count.saturating_add(receipt_root.receipt_count as u64);
            l2_heights.push(receipt_root.l2_height);
            monero_heights.push(receipt_root.monero_height);
            if receipt_root.low_fee_eligible && self.config.enable_low_fee_rebates {
                low_fee_receipt_root_ids.push(receipt_root_id.clone());
            }
        }
        for receipt_root_id in &low_fee_receipt_root_ids {
            low_fee_rebate_ids.push(self.accrue_rebate(receipt_root_id)?);
        }
        for lane_id in &lane_ids {
            if let Some(lane) = self.lanes.get_mut(lane_id) {
                lane.receipts_checkpointed =
                    lane.receipts_checkpointed.saturating_add(receipt_count);
                lane.receipts_pending = lane.receipts_pending.saturating_sub(receipt_count);
                lane.queue_depth = lane
                    .queue_depth
                    .saturating_sub(receipt_count.min(u32::MAX as u64) as u32);
                lane.last_checkpoint_ms = lane.target_checkpoint_ms;
            }
        }
        let previous_epoch_bundle_root = self
            .epoch_bundles
            .values()
            .filter(|bundle| bundle.epoch < epoch)
            .next_back()
            .map(EpochBundle::root)
            .unwrap_or_else(|| dev_hash("epoch-bundle-genesis", epoch));
        let receipt_records = receipt_root_ids
            .iter()
            .filter_map(|id| self.receipt_roots.get(id))
            .map(ReceiptRoot::redacted_public_record)
            .collect::<Vec<_>>();
        let receipt_roots_root = merkle_root(D_RECEIPT_ROOTS, &receipt_records);
        let rebate_records = low_fee_rebate_ids
            .iter()
            .filter_map(|id| self.rebates.get(id))
            .map(LowFeeCheckpointRebate::public_record)
            .collect::<Vec<_>>();
        let low_fee_rebate_root = merkle_root(D_REBATES, &rebate_records);
        let provisional = EpochBundle {
            bundle_id: bundle_id.clone(),
            epoch,
            status: BundleStatus::Attesting,
            start_l2_height: l2_heights.iter().min().copied().unwrap_or(DEVNET_L2_HEIGHT),
            end_l2_height: l2_heights.iter().max().copied().unwrap_or(DEVNET_L2_HEIGHT),
            start_monero_height: monero_heights
                .iter()
                .min()
                .copied()
                .unwrap_or(DEVNET_MONERO_HEIGHT),
            end_monero_height: monero_heights
                .iter()
                .max()
                .copied()
                .unwrap_or(DEVNET_MONERO_HEIGHT),
            lane_ids: lane_ids.into_iter().collect(),
            receipt_root_ids: receipt_root_ids.to_vec(),
            receipt_count,
            previous_epoch_bundle_root,
            receipt_roots_root,
            continuity_link_root: String::new(),
            pq_attestation_root: String::new(),
            low_fee_rebate_root,
            sealed_at_ms: DEVNET_L2_HEIGHT.saturating_add(next),
        };
        let continuity_link_root = self.record_continuity_link(&provisional);
        let mut bundle = provisional;
        bundle.continuity_link_root = continuity_link_root;
        bundle.pq_attestation_root = merkle_root(D_ATTESTATIONS, &Vec::<Value>::new());
        self.epoch_bundles.insert(bundle_id.clone(), bundle);
        self.counters.epoch_bundles_opened = next;
        self.counters.receipt_roots_checkpointed = self
            .counters
            .receipt_roots_checkpointed
            .saturating_add(receipt_root_ids.len() as u64);
        self.prune();
        self.refresh_roots();
        Ok(bundle_id)
    }

    pub fn record_pq_attestation(
        &mut self,
        bundle_id: &str,
        attestor_id: &str,
        verdict: AttestationVerdict,
        weight_bps: u64,
    ) -> Result<String> {
        let bundle = self
            .epoch_bundles
            .get(bundle_id)
            .ok_or_else(|| format!("missing epoch bundle {bundle_id}"))?;
        let next = self.counters.pq_attestations_recorded.saturating_add(1);
        let attestation_id = format!("pq-attestation-{}-{next}", bundle.epoch);
        let attestation = PqCheckpointAttestation {
            attestation_id: attestation_id.clone(),
            bundle_id: bundle_id.to_string(),
            attestor_id: attestor_id.to_string(),
            suite: PQ_CHECKPOINT_ATTESTATION_SUITE.to_string(),
            verdict,
            weight_bps,
            pq_security_bits: self.config.min_pq_security_bits,
            signature_commitment: dev_hash("pq-signature", next),
            public_key_commitment: dev_hash("pq-public-key", next),
            witness_root: dev_hash("pq-witness", next),
            redaction_root: dev_hash("pq-redaction", next),
            continuity_root: bundle.continuity_link_root.clone(),
            l2_height: bundle.end_l2_height,
            monero_height: bundle.end_monero_height,
        };
        if attestation.is_accepting(&self.config) {
            self.counters.pq_attestations_accepted =
                self.counters.pq_attestations_accepted.saturating_add(1);
        }
        self.pq_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.pq_attestations_recorded = next;
        self.update_bundle_attestation_root(bundle_id);
        self.finalize_bundle_if_quorum(bundle_id);
        self.prune();
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn apply_queue_pressure(
        &mut self,
        lane_id: &str,
        queue_depth: u32,
        observed_checkpoint_ms: u64,
    ) -> Option<String> {
        let lane = self.lanes.get_mut(lane_id)?;
        lane.queue_depth = queue_depth;
        lane.last_checkpoint_ms = observed_checkpoint_ms;
        let pressure_bps = lane.pressure_bps();
        let mode = if pressure_bps >= self.config.pressure_critical_watermark_bps {
            PressureMode::EmergencyDrain
        } else if pressure_bps >= self.config.pressure_high_watermark_bps {
            PressureMode::SheddingLowFee
        } else if observed_checkpoint_ms > self.config.max_checkpoint_ms {
            PressureMode::Coalescing
        } else {
            PressureMode::Accepting
        };
        lane.status = match mode {
            PressureMode::Accepting => LaneStatus::Open,
            PressureMode::Coalescing => LaneStatus::Coalescing,
            PressureMode::LowFeeOnlyDeferred => LaneStatus::Draining,
            PressureMode::SheddingLowFee => LaneStatus::Throttled,
            PressureMode::EmergencyDrain => LaneStatus::Draining,
        };
        let deferred = if mode == PressureMode::Coalescing {
            lane.low_fee_backlog
        } else {
            0
        };
        let shed = if mode.is_lossy() && self.config.enable_queue_pressure_shedding {
            lane.low_fee_backlog.saturating_div(2).max(1)
        } else {
            0
        };
        let next = self.counters.throttle_events.saturating_add(1);
        let throttle_id = format!("throttle-{lane_id}-{next}");
        let throttle = QueueThrottle {
            throttle_id: throttle_id.clone(),
            lane_id: lane_id.to_string(),
            mode,
            queue_depth,
            max_queue_depth: lane.max_queue_depth,
            pressure_bps,
            deferred_low_fee_receipts: deferred,
            shed_low_fee_receipts: shed,
            target_checkpoint_ms: lane.target_checkpoint_ms,
            observed_checkpoint_ms,
            reason: format!(
                "pressure:{} checkpoint_ms:{}",
                mode.as_str(),
                observed_checkpoint_ms
            ),
            active: mode != PressureMode::Accepting,
        };
        self.throttles.insert(throttle_id.clone(), throttle);
        self.counters.throttle_events = next;
        self.counters.low_fee_receipts_deferred = self
            .counters
            .low_fee_receipts_deferred
            .saturating_add(deferred);
        self.counters.low_fee_receipts_shed =
            self.counters.low_fee_receipts_shed.saturating_add(shed);
        self.prune();
        self.refresh_roots();
        Some(throttle_id)
    }

    pub fn pay_rebate(&mut self, rebate_id: &str) -> Result<()> {
        let rebate = self
            .rebates
            .get_mut(rebate_id)
            .ok_or_else(|| format!("missing rebate {rebate_id}"))?;
        rebate.status = RebateStatus::Paid;
        self.counters.rebates_paid = self.counters.rebates_paid.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn emit_operator_summary(&mut self) -> String {
        self.refresh_roots();
        let next = self.counters.operator_summaries_emitted.saturating_add(1);
        let active_pressure_mode = self
            .throttles
            .values()
            .rev()
            .find(|throttle| throttle.active)
            .map(|throttle| throttle.mode)
            .unwrap_or(PressureMode::Accepting);
        let avg_checkpoint_ms = if self.receipt_roots.is_empty() {
            0
        } else {
            self.receipt_roots
                .values()
                .map(|root| root.checkpoint_ms)
                .sum::<u64>()
                / self.receipt_roots.len() as u64
        };
        let summary_id = format!("operator-summary-{}-{next}", DEVNET_EPOCH);
        let summary = RedactedOperatorSummary {
            summary_id: summary_id.clone(),
            epoch: DEVNET_EPOCH,
            l2_height: DEVNET_L2_HEIGHT.saturating_add(next),
            monero_height: DEVNET_MONERO_HEIGHT.saturating_add(next / 2),
            lane_count: self.lanes.len(),
            bundle_count: self.epoch_bundles.len(),
            receipt_root_count: self.receipt_roots.len(),
            attestation_count: self.pq_attestations.len(),
            total_receipts: self
                .receipt_roots
                .values()
                .map(|root| root.receipt_count as u64)
                .sum(),
            active_pressure_mode,
            avg_checkpoint_ms,
            rebate_micros: self
                .rebates
                .values()
                .map(|rebate| rebate.rebate_micros)
                .sum(),
            k_anonymity: self.config.min_operator_summary_k_anonymity,
            redacted: true,
            roots: self.roots.clone(),
        };
        self.public_log.insert(
            format!("operator-summary:{summary_id}"),
            summary.public_record(),
        );
        self.operator_summaries.insert(summary_id.clone(), summary);
        self.counters.operator_summaries_emitted = next;
        self.prune();
        self.refresh_roots();
        summary_id
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_checkpoint_attestation_suite": PQ_CHECKPOINT_ATTESTATION_SUITE,
            "confidential_receipt_root_suite": CONFIDENTIAL_RECEIPT_ROOT_SUITE,
            "cross_epoch_continuity_suite": CROSS_EPOCH_CONTINUITY_SUITE,
            "low_fee_rebate_suite": LOW_FEE_REBATE_SUITE,
            "operator_summary_redaction_suite": OPERATOR_SUMMARY_REDACTION_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "state_root": self.state_root(),
            "lane_count": self.lanes.len(),
            "receipt_root_count": self.receipt_roots.len(),
            "epoch_bundle_count": self.epoch_bundles.len(),
            "pq_attestation_count": self.pq_attestations.len(),
            "throttle_count": self.throttles.len(),
            "rebate_count": self.rebates.len(),
            "operator_summary_count": self.operator_summaries.len(),
            "continuity_link_count": self.continuity_links.len(),
            "lanes": self.lanes.values().map(CheckpointLane::public_record).collect::<Vec<_>>(),
            "receipt_roots": self.receipt_roots.values().map(ReceiptRoot::redacted_public_record).collect::<Vec<_>>(),
            "epoch_bundles": self.epoch_bundles.values().map(EpochBundle::public_record).collect::<Vec<_>>(),
            "pq_attestations": self.pq_attestations.values().map(PqCheckpointAttestation::public_record).collect::<Vec<_>>(),
            "throttles": self.throttles.values().map(QueueThrottle::public_record).collect::<Vec<_>>(),
            "rebates": self.rebates.values().map(LowFeeCheckpointRebate::public_record).collect::<Vec<_>>(),
            "operator_summaries": self.operator_summaries.values().map(RedactedOperatorSummary::public_record).collect::<Vec<_>>(),
            "continuity_links": self.continuity_links.values().map(ContinuityLink::public_record).collect::<Vec<_>>(),
            "public_log": self.public_log
        })
    }

    pub fn state_root(&self) -> String {
        let record = json!({
            "protocol_version": PROTOCOL_VERSION,
            "config_root": self.config.root(),
            "counters_root": self.counters.root(),
            "roots_root": self.roots.root(),
            "lanes_root": merkle_records(D_LANES, &self.lanes),
            "receipt_roots_root": merkle_records(D_RECEIPT_ROOTS, &self.receipt_roots),
            "epoch_bundles_root": merkle_records(D_EPOCH_BUNDLES, &self.epoch_bundles),
            "pq_attestations_root": merkle_records(D_ATTESTATIONS, &self.pq_attestations),
            "throttles_root": merkle_records(D_THROTTLES, &self.throttles),
            "rebates_root": merkle_records(D_REBATES, &self.rebates),
            "operator_summaries_root": merkle_records(D_SUMMARIES, &self.operator_summaries),
            "continuity_root": merkle_records(D_CONTINUITY, &self.continuity_links),
            "public_log_root": merkle_json_records(D_PUBLIC, &self.public_log)
        });
        payload_root(D_STATE, &record)
    }

    pub fn refresh_roots(&mut self) {
        self.roots = Roots {
            config_root: self.config.root(),
            counters_root: self.counters.root(),
            lanes_root: merkle_records(D_LANES, &self.lanes),
            receipt_roots_root: merkle_records(D_RECEIPT_ROOTS, &self.receipt_roots),
            epoch_bundles_root: merkle_records(D_EPOCH_BUNDLES, &self.epoch_bundles),
            pq_attestations_root: merkle_records(D_ATTESTATIONS, &self.pq_attestations),
            throttles_root: merkle_records(D_THROTTLES, &self.throttles),
            rebates_root: merkle_records(D_REBATES, &self.rebates),
            operator_summaries_root: merkle_records(D_SUMMARIES, &self.operator_summaries),
            public_log_root: merkle_json_records(D_PUBLIC, &self.public_log),
            continuity_root: merkle_records(D_CONTINUITY, &self.continuity_links),
        };
    }

    fn accrue_rebate(&mut self, receipt_root_id: &str) -> Result<String> {
        let receipt_root = self
            .receipt_roots
            .get(receipt_root_id)
            .ok_or_else(|| format!("missing receipt root {receipt_root_id}"))?;
        let rebate_bps = self
            .config
            .low_fee_rebate_bps
            .min(self.config.max_rebate_bps);
        let rebate_micros = receipt_root.fee_paid_micros.saturating_mul(rebate_bps) / MAX_BPS;
        let next = self.counters.rebates_accrued.saturating_add(1);
        let rebate_id = format!("rebate-{}-{next}", receipt_root.epoch);
        let rebate = LowFeeCheckpointRebate {
            rebate_id: rebate_id.clone(),
            receipt_root_id: receipt_root_id.to_string(),
            lane_id: receipt_root.lane_id.clone(),
            epoch: receipt_root.epoch,
            status: RebateStatus::Accrued,
            fee_asset_id: self.config.fee_asset_id.clone(),
            fee_paid_micros: receipt_root.fee_paid_micros,
            rebate_bps,
            rebate_micros,
            sponsor_commitment: dev_hash("rebate-sponsor", next),
            payout_commitment: dev_hash("rebate-payout", next),
        };
        self.rebates.insert(rebate_id.clone(), rebate);
        self.counters.rebates_accrued = next;
        Ok(rebate_id)
    }

    fn record_continuity_link(&mut self, bundle: &EpochBundle) -> String {
        let next = self.counters.continuity_links_checked.saturating_add(1);
        let previous = self
            .epoch_bundles
            .values()
            .filter(|existing| existing.epoch < bundle.epoch)
            .next_back();
        let link = ContinuityLink {
            link_id: format!("continuity-{}-{next}", bundle.epoch),
            from_epoch: previous
                .map(|item| item.epoch)
                .unwrap_or(bundle.epoch.saturating_sub(1)),
            to_epoch: bundle.epoch,
            previous_bundle_root: previous
                .map(EpochBundle::root)
                .unwrap_or_else(|| bundle.previous_epoch_bundle_root.clone()),
            next_bundle_root: bundle.root(),
            carry_root: dev_hash("continuity-carry", next),
            proof_root: dev_hash("continuity-proof", next),
            checked: true,
            valid: self.config.enable_cross_epoch_continuity,
        };
        if !link.valid {
            self.counters.continuity_breaks = self.counters.continuity_breaks.saturating_add(1);
        }
        let root = link.root();
        self.continuity_links.insert(link.link_id.clone(), link);
        self.counters.continuity_links_checked = next;
        root
    }

    fn update_bundle_attestation_root(&mut self, bundle_id: &str) {
        let records = self
            .pq_attestations
            .values()
            .filter(|attestation| attestation.bundle_id == bundle_id)
            .map(PqCheckpointAttestation::public_record)
            .collect::<Vec<_>>();
        if let Some(bundle) = self.epoch_bundles.get_mut(bundle_id) {
            bundle.pq_attestation_root = merkle_root(D_ATTESTATIONS, &records);
        }
    }

    fn finalize_bundle_if_quorum(&mut self, bundle_id: &str) {
        let accepted_weight = self
            .pq_attestations
            .values()
            .filter(|attestation| {
                attestation.bundle_id == bundle_id && attestation.is_accepting(&self.config)
            })
            .map(|attestation| attestation.weight_bps)
            .sum::<u64>();
        if let Some(bundle) = self.epoch_bundles.get_mut(bundle_id) {
            if accepted_weight >= self.config.quorum_weight_bps {
                bundle.status = BundleStatus::Finalized;
                self.counters.epoch_bundles_finalized =
                    self.counters.epoch_bundles_finalized.saturating_add(1);
                for receipt_root_id in &bundle.receipt_root_ids {
                    if let Some(root) = self.receipt_roots.get_mut(receipt_root_id) {
                        root.status = ReceiptRootStatus::Finalized;
                    }
                }
            }
        }
    }

    fn prune(&mut self) {
        prune_map(
            &mut self.lanes,
            MAX_LANES,
            &mut self.counters.public_records_pruned,
        );
        prune_map(
            &mut self.receipt_roots,
            MAX_RECEIPT_ROOTS,
            &mut self.counters.public_records_pruned,
        );
        prune_map(
            &mut self.epoch_bundles,
            MAX_EPOCH_BUNDLES,
            &mut self.counters.public_records_pruned,
        );
        prune_map(
            &mut self.pq_attestations,
            MAX_ATTESTATIONS,
            &mut self.counters.public_records_pruned,
        );
        prune_map(
            &mut self.throttles,
            MAX_THROTTLES,
            &mut self.counters.public_records_pruned,
        );
        prune_map(
            &mut self.rebates,
            MAX_REBATES,
            &mut self.counters.public_records_pruned,
        );
        prune_map(
            &mut self.operator_summaries,
            MAX_OPERATOR_SUMMARIES,
            &mut self.counters.public_records_pruned,
        );
        prune_map(
            &mut self.continuity_links,
            MAX_EPOCH_BUNDLES,
            &mut self.counters.public_records_pruned,
        );
        prune_map(
            &mut self.public_log,
            MAX_PUBLIC_RECORDS,
            &mut self.counters.public_records_pruned,
        );
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn refresh_roots(state: &mut State) {
    state.refresh_roots();
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn merkle_records<T: Serialize>(domain: &str, records: &BTreeMap<String, T>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn merkle_json_records(domain: &str, records: &BTreeMap<String, Value>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn payload_root(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(value)],
        32,
    )
}

fn dev_hash(label: &str, index: u64) -> String {
    domain_hash(D_DEVNET, &[HashPart::Str(label), HashPart::U64(index)], 32)
}

fn prune_map<T>(records: &mut BTreeMap<String, T>, max: usize, pruned: &mut u64) {
    while records.len() > max {
        if let Some(key) = records.keys().next().cloned() {
            records.remove(&key);
            *pruned = pruned.saturating_add(1);
        } else {
            break;
        }
    }
}
