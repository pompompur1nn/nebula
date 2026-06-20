use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID, TARGET_BLOCK_MS,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
pub type PrivateSequencerLatencyFeeShaperResult<T> = Result<T, String>;
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_PROTOCOL_VERSION: &str =
    "nebula-private-sequencer-latency-fee-shaper-v1";
pub const PROTOCOL_VERSION: &str = PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_PROTOCOL_VERSION;
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEVNET_HEIGHT: u64 = 3_072;
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_BUCKET_ENCRYPTION_SUITE: &str =
    "ML-KEM-768+view-tag-sealed-latency-bucket-v1";
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_PQ_ATTESTATION_SUITE: &str =
    "ML-DSA-65+SLH-DSA-SHAKE-128s-sequencer-attestation";
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_FEE_CAP_SUITE: &str =
    "fee-cap-pedersen-nullifier-commitment-v1";
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_CONGESTION_SIGNAL_SUITE: &str =
    "private-congestion-signal-commitment-v1";
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_RECEIPT_SUITE: &str =
    "batch-admission-receipt-nullifier-v1";
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_SLASHING_SUITE: &str =
    "sequencer-latency-fee-shaper-slashing-v1";
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_BOND_ASSET_ID: &str = "dusd-devnet";
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_EPOCH_BLOCKS: u64 = 240;
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_BUCKET_WIDTH_MS: u64 = 250;
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_BUCKET_TTL_BLOCKS: u64 = 720;
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 48;
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 720;
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_RESCUE_LANE_SHARE_BPS: u64 = 1_500;
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_PRIVATE_RESERVE_BPS: u64 = 3_000;
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_MAX_FEE_CAP_BPS: u64 = 2_500;
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_CONGESTION_WARN_BPS: u64 = 7_000;
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_CONGESTION_CRITICAL_BPS: u64 = 9_000;
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_MIN_SEQUENCER_STAKE_UNITS: u64 = 500_000;
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_MIN_RESCUE_BUDGET_UNITS: u64 = 25_000;
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_SLASH_BPS: u64 = 2_000;
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_MAX_ACTIVE_LANES: usize = 64;
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_MAX_BUCKETS: usize = 512;
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_MAX_ATTESTATIONS: usize = 512;
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_MAX_SIGNALS: usize = 512;
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_MAX_FEE_CAPS: usize = 512;
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_MAX_RECEIPTS: usize = 512;
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_MAX_CHALLENGES: usize = 256;
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_MAX_SLASHES: usize = 256;
pub const PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_MAX_BPS: u64 = 10_000;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateSequencerLaneKind {
    MoneroBridge,
    ShieldedTransfer,
    PrivateSwap,
    ContractCall,
    ProofMarket,
    LowFeeRescue,
    Governance,
    BulkSettlement,
}
impl PrivateSequencerLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroBridge => "monero_bridge",
            Self::ShieldedTransfer => "shielded_transfer",
            Self::PrivateSwap => "private_swap",
            Self::ContractCall => "contract_call",
            Self::ProofMarket => "proof_market",
            Self::LowFeeRescue => "low_fee_rescue",
            Self::Governance => "governance",
            Self::BulkSettlement => "bulk_settlement",
        }
    }
    pub fn default_priority_weight(self) -> u64 {
        match self {
            Self::MoneroBridge => 100,
            Self::LowFeeRescue => 96,
            Self::ShieldedTransfer => 88,
            Self::PrivateSwap => 84,
            Self::ContractCall => 72,
            Self::ProofMarket => 64,
            Self::Governance => 42,
            Self::BulkSettlement => 20,
        }
    }
    pub fn default_latency_sla_ms(self) -> u64 {
        match self {
            Self::MoneroBridge => 450,
            Self::LowFeeRescue => 650,
            Self::ShieldedTransfer => 700,
            Self::PrivateSwap => 550,
            Self::ContractCall => 900,
            Self::ProofMarket => 1_200,
            Self::Governance => TARGET_BLOCK_MS,
            Self::BulkSettlement => TARGET_BLOCK_MS.saturating_mul(2),
        }
        .max(1)
    }
    pub fn privacy_critical(self) -> bool {
        matches!(
            self,
            Self::MoneroBridge
                | Self::ShieldedTransfer
                | Self::PrivateSwap
                | Self::ContractCall
                | Self::LowFeeRescue
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateSequencerLaneStatus {
    Draft,
    Active,
    Congested,
    RescueOnly,
    Challenged,
    Paused,
    Retired,
}
impl PrivateSequencerLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Congested => "congested",
            Self::RescueOnly => "rescue_only",
            Self::Challenged => "challenged",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }
    pub fn admits_private_batches(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Congested | Self::RescueOnly | Self::Challenged
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SequencerBondStatus {
    Bonding,
    Active,
    Warning,
    Challenged,
    Slashed,
    Suspended,
    Exiting,
    Retired,
}
impl SequencerBondStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bonding => "bonding",
            Self::Active => "active",
            Self::Warning => "warning",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Suspended => "suspended",
            Self::Exiting => "exiting",
            Self::Retired => "retired",
        }
    }
    pub fn may_attest(self) -> bool {
        matches!(self, Self::Active | Self::Warning | Self::Challenged)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LatencyBucketClass {
    Instant,
    Fast,
    Standard,
    Delayed,
    Rescue,
    Backlog,
}
impl LatencyBucketClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Instant => "instant",
            Self::Fast => "fast",
            Self::Standard => "standard",
            Self::Delayed => "delayed",
            Self::Rescue => "rescue",
            Self::Backlog => "backlog",
        }
    }
    pub fn upper_bound_ms(self, bucket_width_ms: u64) -> u64 {
        match self {
            Self::Instant => bucket_width_ms,
            Self::Fast => bucket_width_ms.saturating_mul(2),
            Self::Standard => bucket_width_ms.saturating_mul(4),
            Self::Delayed => bucket_width_ms.saturating_mul(8),
            Self::Rescue => bucket_width_ms.saturating_mul(12),
            Self::Backlog => bucket_width_ms.saturating_mul(32),
        }
        .max(1)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CongestionSignalSeverity {
    Observe,
    Warn,
    Critical,
    Rescue,
    Halt,
}
impl CongestionSignalSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Warn => "warn",
            Self::Critical => "critical",
            Self::Rescue => "rescue",
            Self::Halt => "halt",
        }
    }
    pub fn fee_multiplier_bps(self) -> u64 {
        match self {
            Self::Observe => 10_000,
            Self::Warn => 11_500,
            Self::Critical => 14_000,
            Self::Rescue => 8_000,
            Self::Halt => 20_000,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionReceiptStatus {
    Issued,
    Included,
    Settled,
    Rebated,
    Challenged,
    Expired,
    Cancelled,
}
impl AdmissionReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Included => "included",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Rebated | Self::Expired | Self::Cancelled
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlaChallengeStatus {
    Open,
    EvidenceSubmitted,
    Accepted,
    Rejected,
    Slashed,
    Expired,
}
impl SlaChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceSubmitted => "evidence_submitted",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingEvidenceKind {
    MissedLatencySla,
    FeeCapViolation,
    InvalidPqAttestation,
    WithheldRescueLane,
    FalseCongestionSignal,
    DuplicateAdmissionReceipt,
}
impl SlashingEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissedLatencySla => "missed_latency_sla",
            Self::FeeCapViolation => "fee_cap_violation",
            Self::InvalidPqAttestation => "invalid_pq_attestation",
            Self::WithheldRescueLane => "withheld_rescue_lane",
            Self::FalseCongestionSignal => "false_congestion_signal",
            Self::DuplicateAdmissionReceipt => "duplicate_admission_receipt",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSequencerLatencyFeeShaperConfig {
    pub epoch_blocks: u64,
    pub bucket_width_ms: u64,
    pub bucket_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub rescue_lane_share_bps: u64,
    pub private_reserve_bps: u64,
    pub max_fee_cap_bps: u64,
    pub congestion_warn_bps: u64,
    pub congestion_critical_bps: u64,
    pub min_sequencer_stake_units: u64,
    pub min_rescue_budget_units: u64,
    pub default_slash_bps: u64,
    pub max_active_lanes: usize,
    pub max_latency_buckets: usize,
    pub max_attestations: usize,
    pub max_congestion_signals: usize,
    pub max_fee_cap_commitments: usize,
    pub max_receipts: usize,
    pub max_challenges: usize,
    pub max_slashes: usize,
    pub fee_asset_id: String,
    pub bond_asset_id: String,
    pub require_pq_attestations: bool,
    pub allow_payload_roots_only: bool,
    pub enable_low_fee_rescue: bool,
}
impl Default for PrivateSequencerLatencyFeeShaperConfig {
    fn default() -> Self {
        Self::devnet()
    }
}
impl PrivateSequencerLatencyFeeShaperConfig {
    pub fn devnet() -> Self {
        Self {
            epoch_blocks: PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_EPOCH_BLOCKS,
            bucket_width_ms: PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_BUCKET_WIDTH_MS,
            bucket_ttl_blocks: PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_BUCKET_TTL_BLOCKS,
            challenge_window_blocks:
                PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            receipt_ttl_blocks: PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_RECEIPT_TTL_BLOCKS,
            rescue_lane_share_bps:
                PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_RESCUE_LANE_SHARE_BPS,
            private_reserve_bps: PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_PRIVATE_RESERVE_BPS,
            max_fee_cap_bps: PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_MAX_FEE_CAP_BPS,
            congestion_warn_bps: PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_CONGESTION_WARN_BPS,
            congestion_critical_bps:
                PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_CONGESTION_CRITICAL_BPS,
            min_sequencer_stake_units:
                PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_MIN_SEQUENCER_STAKE_UNITS,
            min_rescue_budget_units:
                PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_MIN_RESCUE_BUDGET_UNITS,
            default_slash_bps: PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_SLASH_BPS,
            max_active_lanes: PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_MAX_ACTIVE_LANES,
            max_latency_buckets: PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_MAX_BUCKETS,
            max_attestations: PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_MAX_ATTESTATIONS,
            max_congestion_signals: PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_MAX_SIGNALS,
            max_fee_cap_commitments: PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_MAX_FEE_CAPS,
            max_receipts: PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_MAX_RECEIPTS,
            max_challenges: PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_MAX_CHALLENGES,
            max_slashes: PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_MAX_SLASHES,
            fee_asset_id: PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_FEE_ASSET_ID.to_string(),
            bond_asset_id: PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_BOND_ASSET_ID.to_string(),
            require_pq_attestations: true,
            allow_payload_roots_only: true,
            enable_low_fee_rescue: true,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_sequencer_latency_fee_shaper_config",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_PROTOCOL_VERSION,
            "schema_version": PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_SCHEMA_VERSION,
            "hash_suite": PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_HASH_SUITE,
            "bucket_encryption_suite": PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_BUCKET_ENCRYPTION_SUITE,
            "pq_attestation_suite": PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_PQ_ATTESTATION_SUITE,
            "fee_cap_suite": PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_FEE_CAP_SUITE,
            "congestion_signal_suite": PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_CONGESTION_SIGNAL_SUITE,
            "receipt_suite": PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_RECEIPT_SUITE,
            "slashing_suite": PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_SLASHING_SUITE,
            "epoch_blocks": self.epoch_blocks,
            "bucket_width_ms": self.bucket_width_ms,
            "bucket_ttl_blocks": self.bucket_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "rescue_lane_share_bps": self.rescue_lane_share_bps,
            "private_reserve_bps": self.private_reserve_bps,
            "max_fee_cap_bps": self.max_fee_cap_bps,
            "congestion_warn_bps": self.congestion_warn_bps,
            "congestion_critical_bps": self.congestion_critical_bps,
            "min_sequencer_stake_units": self.min_sequencer_stake_units,
            "min_rescue_budget_units": self.min_rescue_budget_units,
            "default_slash_bps": self.default_slash_bps,
            "max_active_lanes": self.max_active_lanes,
            "max_latency_buckets": self.max_latency_buckets,
            "max_attestations": self.max_attestations,
            "max_congestion_signals": self.max_congestion_signals,
            "max_fee_cap_commitments": self.max_fee_cap_commitments,
            "max_receipts": self.max_receipts,
            "max_challenges": self.max_challenges,
            "max_slashes": self.max_slashes,
            "fee_asset_id": self.fee_asset_id,
            "bond_asset_id": self.bond_asset_id,
            "require_pq_attestations": self.require_pq_attestations,
            "allow_payload_roots_only": self.allow_payload_roots_only,
            "enable_low_fee_rescue": self.enable_low_fee_rescue,
        })
    }
    pub fn config_root(&self) -> String {
        private_sequencer_latency_fee_shaper_payload_root("CONFIG", &self.public_record())
    }
    pub fn validate(&self) -> PrivateSequencerLatencyFeeShaperResult<()> {
        ensure_positive(self.epoch_blocks, "epoch blocks")?;
        ensure_positive(self.bucket_width_ms, "bucket width ms")?;
        ensure_positive(self.bucket_ttl_blocks, "bucket ttl blocks")?;
        ensure_positive(self.challenge_window_blocks, "challenge window blocks")?;
        ensure_positive(self.receipt_ttl_blocks, "receipt ttl blocks")?;
        ensure_bps(self.rescue_lane_share_bps, "rescue lane share bps")?;
        ensure_bps(self.private_reserve_bps, "private reserve bps")?;
        ensure_bps(self.max_fee_cap_bps, "max fee cap bps")?;
        ensure_bps(self.congestion_warn_bps, "congestion warn bps")?;
        ensure_bps(self.congestion_critical_bps, "congestion critical bps")?;
        ensure_bps(self.default_slash_bps, "default slash bps")?;
        ensure_positive(self.min_sequencer_stake_units, "min sequencer stake units")?;
        ensure_positive(self.min_rescue_budget_units, "min rescue budget units")?;
        ensure_non_empty(&self.fee_asset_id, "fee asset id")?;
        ensure_non_empty(&self.bond_asset_id, "bond asset id")?;
        ensure_usize_positive(self.max_active_lanes, "max active lanes")?;
        ensure_usize_positive(self.max_latency_buckets, "max latency buckets")?;
        ensure_usize_positive(self.max_attestations, "max attestations")?;
        ensure_usize_positive(self.max_congestion_signals, "max congestion signals")?;
        ensure_usize_positive(self.max_fee_cap_commitments, "max fee cap commitments")?;
        ensure_usize_positive(self.max_receipts, "max receipts")?;
        ensure_usize_positive(self.max_challenges, "max challenges")?;
        ensure_usize_positive(self.max_slashes, "max slashes")?;
        if self.congestion_warn_bps >= self.congestion_critical_bps {
            return Err("congestion warn bps must be below critical bps".to_string());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSequencerLane {
    pub lane_id: String,
    pub lane_kind: PrivateSequencerLaneKind,
    pub label: String,
    pub operator_commitment: String,
    pub admission_policy_root: String,
    pub fee_policy_root: String,
    pub latency_sla_ms: u64,
    pub min_share_bps: u64,
    pub max_share_bps: u64,
    pub rescue_share_bps: u64,
    pub priority_weight: u64,
    pub max_batch_weight: u64,
    pub rescue_budget_units: u64,
    pub status: PrivateSequencerLaneStatus,
}
impl PrivateSequencerLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_kind: PrivateSequencerLaneKind,
        label: &str,
        operator_commitment: &str,
        admission_policy_root: &str,
        fee_policy_root: &str,
        min_share_bps: u64,
        max_share_bps: u64,
        rescue_budget_units: u64,
    ) -> PrivateSequencerLatencyFeeShaperResult<Self> {
        ensure_non_empty(label, "lane label")?;
        ensure_non_empty(operator_commitment, "lane operator commitment")?;
        ensure_non_empty(admission_policy_root, "lane admission policy root")?;
        ensure_non_empty(fee_policy_root, "lane fee policy root")?;
        ensure_bps(min_share_bps, "lane min share bps")?;
        ensure_bps(max_share_bps, "lane max share bps")?;
        if min_share_bps > max_share_bps {
            return Err("lane min share exceeds max share".to_string());
        }
        let latency_sla_ms = lane_kind.default_latency_sla_ms();
        let priority_weight = lane_kind.default_priority_weight();
        let rescue_share_bps = if matches!(lane_kind, PrivateSequencerLaneKind::LowFeeRescue) {
            PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEFAULT_RESCUE_LANE_SHARE_BPS
        } else {
            0
        };
        let lane_id = private_sequencer_latency_fee_shaper_lane_id(
            lane_kind,
            label,
            operator_commitment,
            admission_policy_root,
            fee_policy_root,
        );
        Ok(Self {
            lane_id,
            lane_kind,
            label: label.to_string(),
            operator_commitment: operator_commitment.to_string(),
            admission_policy_root: admission_policy_root.to_string(),
            fee_policy_root: fee_policy_root.to_string(),
            latency_sla_ms,
            min_share_bps,
            max_share_bps,
            rescue_share_bps,
            priority_weight,
            max_batch_weight: 4_000_000,
            rescue_budget_units,
            status: PrivateSequencerLaneStatus::Active,
        })
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_sequencer_lane",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_PROTOCOL_VERSION,
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "label": self.label,
            "operator_commitment": self.operator_commitment,
            "admission_policy_root": self.admission_policy_root,
            "fee_policy_root": self.fee_policy_root,
            "latency_sla_ms": self.latency_sla_ms,
            "min_share_bps": self.min_share_bps,
            "max_share_bps": self.max_share_bps,
            "rescue_share_bps": self.rescue_share_bps,
            "priority_weight": self.priority_weight,
            "max_batch_weight": self.max_batch_weight,
            "rescue_budget_units": self.rescue_budget_units,
            "status": self.status.as_str(),
            "privacy_critical": self.lane_kind.privacy_critical(),
        })
    }
    pub fn validate(&self) -> PrivateSequencerLatencyFeeShaperResult<()> {
        ensure_non_empty(&self.lane_id, "lane id")?;
        ensure_non_empty(&self.label, "lane label")?;
        ensure_non_empty(&self.operator_commitment, "lane operator commitment")?;
        ensure_non_empty(&self.admission_policy_root, "lane admission policy root")?;
        ensure_non_empty(&self.fee_policy_root, "lane fee policy root")?;
        ensure_positive(self.latency_sla_ms, "lane latency sla ms")?;
        ensure_bps(self.min_share_bps, "lane min share bps")?;
        ensure_bps(self.max_share_bps, "lane max share bps")?;
        ensure_bps(self.rescue_share_bps, "lane rescue share bps")?;
        ensure_positive(self.priority_weight, "lane priority weight")?;
        ensure_positive(self.max_batch_weight, "lane max batch weight")?;
        if self.min_share_bps > self.max_share_bps {
            return Err("lane min share exceeds max share".to_string());
        }
        if self.lane_id
            != private_sequencer_latency_fee_shaper_lane_id(
                self.lane_kind,
                &self.label,
                &self.operator_commitment,
                &self.admission_policy_root,
                &self.fee_policy_root,
            )
        {
            return Err("lane id mismatch".to_string());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSequencerAttestor {
    pub sequencer_id: String,
    pub operator_commitment: String,
    pub pq_public_key_root: String,
    pub encryption_key_root: String,
    pub bonded_stake_units: u64,
    pub active_lane_ids: BTreeSet<String>,
    pub accepted_batches: u64,
    pub challenged_batches: u64,
    pub slashed_units: u64,
    pub status: SequencerBondStatus,
}
impl PqSequencerAttestor {
    pub fn new(
        operator_commitment: &str,
        pq_public_key_root: &str,
        encryption_key_root: &str,
        bonded_stake_units: u64,
        config: &PrivateSequencerLatencyFeeShaperConfig,
    ) -> PrivateSequencerLatencyFeeShaperResult<Self> {
        ensure_non_empty(operator_commitment, "sequencer operator commitment")?;
        ensure_non_empty(pq_public_key_root, "sequencer pq public key root")?;
        ensure_non_empty(encryption_key_root, "sequencer encryption key root")?;
        if bonded_stake_units < config.min_sequencer_stake_units {
            return Err("sequencer bonded stake is below minimum".to_string());
        }
        let sequencer_id = private_sequencer_latency_fee_shaper_sequencer_id(
            operator_commitment,
            pq_public_key_root,
            encryption_key_root,
        );
        Ok(Self {
            sequencer_id,
            operator_commitment: operator_commitment.to_string(),
            pq_public_key_root: pq_public_key_root.to_string(),
            encryption_key_root: encryption_key_root.to_string(),
            bonded_stake_units,
            active_lane_ids: BTreeSet::new(),
            accepted_batches: 0,
            challenged_batches: 0,
            slashed_units: 0,
            status: SequencerBondStatus::Active,
        })
    }
    pub fn bind_lane(
        &mut self,
        lane_id: &str,
        max_active_lanes: usize,
    ) -> PrivateSequencerLatencyFeeShaperResult<()> {
        ensure_non_empty(lane_id, "sequencer active lane id")?;
        if self.active_lane_ids.len() >= max_active_lanes && !self.active_lane_ids.contains(lane_id)
        {
            return Err("sequencer has too many active lanes".to_string());
        }
        self.active_lane_ids.insert(lane_id.to_string());
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_sequencer_attestor",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_PROTOCOL_VERSION,
            "sequencer_id": self.sequencer_id,
            "operator_commitment": self.operator_commitment,
            "pq_public_key_root": self.pq_public_key_root,
            "encryption_key_root": self.encryption_key_root,
            "bonded_stake_units": self.bonded_stake_units,
            "active_lane_ids": self.active_lane_ids.iter().cloned().collect::<Vec<_>>(),
            "accepted_batches": self.accepted_batches,
            "challenged_batches": self.challenged_batches,
            "slashed_units": self.slashed_units,
            "status": self.status.as_str(),
        })
    }
    pub fn validate(
        &self,
        config: &PrivateSequencerLatencyFeeShaperConfig,
    ) -> PrivateSequencerLatencyFeeShaperResult<()> {
        ensure_non_empty(&self.sequencer_id, "sequencer id")?;
        ensure_non_empty(&self.operator_commitment, "sequencer operator commitment")?;
        ensure_non_empty(&self.pq_public_key_root, "sequencer pq public key root")?;
        ensure_non_empty(&self.encryption_key_root, "sequencer encryption key root")?;
        if self.bonded_stake_units < config.min_sequencer_stake_units {
            return Err("sequencer bonded stake is below minimum".to_string());
        }
        if self.active_lane_ids.len() > config.max_active_lanes {
            return Err("sequencer active lane set exceeds configured maximum".to_string());
        }
        if self.slashed_units > self.bonded_stake_units {
            return Err("sequencer slashed units exceed bonded stake".to_string());
        }
        if self.sequencer_id
            != private_sequencer_latency_fee_shaper_sequencer_id(
                &self.operator_commitment,
                &self.pq_public_key_root,
                &self.encryption_key_root,
            )
        {
            return Err("sequencer id mismatch".to_string());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedLatencyBucket {
    pub bucket_id: String,
    pub lane_id: String,
    pub sequencer_id: String,
    pub bucket_class: LatencyBucketClass,
    pub epoch_index: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub encrypted_count_root: String,
    pub encrypted_latency_sum_root: String,
    pub encrypted_witness_root: String,
    pub disclosure_commitment_root: String,
    pub sample_count_commitment: String,
    pub max_observed_latency_ms: u64,
    pub expires_height: u64,
}
impl EncryptedLatencyBucket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: &str,
        sequencer_id: &str,
        bucket_class: LatencyBucketClass,
        epoch_index: u64,
        start_height: u64,
        end_height: u64,
        encrypted_count_root: &str,
        encrypted_latency_sum_root: &str,
        encrypted_witness_root: &str,
        disclosure_commitment_root: &str,
        sample_count_commitment: &str,
        max_observed_latency_ms: u64,
        config: &PrivateSequencerLatencyFeeShaperConfig,
    ) -> PrivateSequencerLatencyFeeShaperResult<Self> {
        ensure_non_empty(lane_id, "latency bucket lane id")?;
        ensure_non_empty(sequencer_id, "latency bucket sequencer id")?;
        ensure_non_empty(encrypted_count_root, "latency bucket encrypted count root")?;
        ensure_non_empty(
            encrypted_latency_sum_root,
            "latency bucket encrypted latency sum root",
        )?;
        ensure_non_empty(
            encrypted_witness_root,
            "latency bucket encrypted witness root",
        )?;
        ensure_non_empty(
            disclosure_commitment_root,
            "latency bucket disclosure commitment root",
        )?;
        ensure_non_empty(
            sample_count_commitment,
            "latency bucket sample count commitment",
        )?;
        if end_height < start_height {
            return Err("latency bucket end height precedes start height".to_string());
        }
        let expires_height = end_height.saturating_add(config.bucket_ttl_blocks);
        let bucket_id = private_sequencer_latency_fee_shaper_bucket_id(
            lane_id,
            sequencer_id,
            bucket_class,
            epoch_index,
            start_height,
            end_height,
            encrypted_witness_root,
        );
        Ok(Self {
            bucket_id,
            lane_id: lane_id.to_string(),
            sequencer_id: sequencer_id.to_string(),
            bucket_class,
            epoch_index,
            start_height,
            end_height,
            encrypted_count_root: encrypted_count_root.to_string(),
            encrypted_latency_sum_root: encrypted_latency_sum_root.to_string(),
            encrypted_witness_root: encrypted_witness_root.to_string(),
            disclosure_commitment_root: disclosure_commitment_root.to_string(),
            sample_count_commitment: sample_count_commitment.to_string(),
            max_observed_latency_ms,
            expires_height,
        })
    }
    pub fn is_expired(&self, height: u64) -> bool {
        height > self.expires_height
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_latency_bucket",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_PROTOCOL_VERSION,
            "bucket_id": self.bucket_id,
            "lane_id": self.lane_id,
            "sequencer_id": self.sequencer_id,
            "bucket_class": self.bucket_class.as_str(),
            "epoch_index": self.epoch_index,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "encrypted_count_root": self.encrypted_count_root,
            "encrypted_latency_sum_root": self.encrypted_latency_sum_root,
            "encrypted_witness_root": self.encrypted_witness_root,
            "disclosure_commitment_root": self.disclosure_commitment_root,
            "sample_count_commitment": self.sample_count_commitment,
            "max_observed_latency_ms": self.max_observed_latency_ms,
            "expires_height": self.expires_height,
        })
    }
    pub fn validate(&self) -> PrivateSequencerLatencyFeeShaperResult<()> {
        ensure_non_empty(&self.bucket_id, "latency bucket id")?;
        ensure_non_empty(&self.lane_id, "latency bucket lane id")?;
        ensure_non_empty(&self.sequencer_id, "latency bucket sequencer id")?;
        ensure_non_empty(
            &self.encrypted_count_root,
            "latency bucket encrypted count root",
        )?;
        ensure_non_empty(
            &self.encrypted_latency_sum_root,
            "latency bucket encrypted latency sum root",
        )?;
        ensure_non_empty(
            &self.encrypted_witness_root,
            "latency bucket encrypted witness root",
        )?;
        ensure_non_empty(
            &self.disclosure_commitment_root,
            "latency bucket disclosure commitment root",
        )?;
        ensure_non_empty(
            &self.sample_count_commitment,
            "latency bucket sample count commitment",
        )?;
        if self.end_height < self.start_height {
            return Err("latency bucket end height precedes start height".to_string());
        }
        if self.expires_height < self.end_height {
            return Err("latency bucket expiry precedes end height".to_string());
        }
        if self.bucket_id
            != private_sequencer_latency_fee_shaper_bucket_id(
                &self.lane_id,
                &self.sequencer_id,
                self.bucket_class,
                self.epoch_index,
                self.start_height,
                self.end_height,
                &self.encrypted_witness_root,
            )
        {
            return Err("latency bucket id mismatch".to_string());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSequencerAttestation {
    pub attestation_id: String,
    pub sequencer_id: String,
    pub lane_id: String,
    pub bucket_id: String,
    pub batch_root: String,
    pub fee_schedule_root: String,
    pub congestion_signal_root: String,
    pub attested_height: u64,
    pub attested_timestamp_ms: u64,
    pub pq_signature_root: String,
    pub transcript_root: String,
}
impl PqSequencerAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequencer_id: &str,
        lane_id: &str,
        bucket_id: &str,
        batch_root: &str,
        fee_schedule_root: &str,
        congestion_signal_root: &str,
        attested_height: u64,
        attested_timestamp_ms: u64,
        pq_signature_root: &str,
        transcript: &Value,
    ) -> PrivateSequencerLatencyFeeShaperResult<Self> {
        ensure_non_empty(sequencer_id, "attestation sequencer id")?;
        ensure_non_empty(lane_id, "attestation lane id")?;
        ensure_non_empty(bucket_id, "attestation bucket id")?;
        ensure_non_empty(batch_root, "attestation batch root")?;
        ensure_non_empty(fee_schedule_root, "attestation fee schedule root")?;
        ensure_non_empty(congestion_signal_root, "attestation congestion signal root")?;
        ensure_non_empty(pq_signature_root, "attestation pq signature root")?;
        ensure_positive(attested_timestamp_ms, "attestation timestamp ms")?;
        let transcript_root =
            private_sequencer_latency_fee_shaper_payload_root("ATTESTATION-TRANSCRIPT", transcript);
        let attestation_id = private_sequencer_latency_fee_shaper_attestation_id(
            sequencer_id,
            lane_id,
            bucket_id,
            batch_root,
            attested_height,
            &transcript_root,
        );
        Ok(Self {
            attestation_id,
            sequencer_id: sequencer_id.to_string(),
            lane_id: lane_id.to_string(),
            bucket_id: bucket_id.to_string(),
            batch_root: batch_root.to_string(),
            fee_schedule_root: fee_schedule_root.to_string(),
            congestion_signal_root: congestion_signal_root.to_string(),
            attested_height,
            attested_timestamp_ms,
            pq_signature_root: pq_signature_root.to_string(),
            transcript_root,
        })
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_sequencer_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "sequencer_id": self.sequencer_id,
            "lane_id": self.lane_id,
            "bucket_id": self.bucket_id,
            "batch_root": self.batch_root,
            "fee_schedule_root": self.fee_schedule_root,
            "congestion_signal_root": self.congestion_signal_root,
            "attested_height": self.attested_height,
            "attested_timestamp_ms": self.attested_timestamp_ms,
            "pq_signature_root": self.pq_signature_root,
            "transcript_root": self.transcript_root,
        })
    }
    pub fn validate(&self) -> PrivateSequencerLatencyFeeShaperResult<()> {
        ensure_non_empty(&self.attestation_id, "attestation id")?;
        ensure_non_empty(&self.sequencer_id, "attestation sequencer id")?;
        ensure_non_empty(&self.lane_id, "attestation lane id")?;
        ensure_non_empty(&self.bucket_id, "attestation bucket id")?;
        ensure_non_empty(&self.batch_root, "attestation batch root")?;
        ensure_non_empty(&self.fee_schedule_root, "attestation fee schedule root")?;
        ensure_non_empty(
            &self.congestion_signal_root,
            "attestation congestion signal root",
        )?;
        ensure_non_empty(&self.pq_signature_root, "attestation pq signature root")?;
        ensure_non_empty(&self.transcript_root, "attestation transcript root")?;
        ensure_positive(self.attested_timestamp_ms, "attestation timestamp ms")?;
        if self.attestation_id
            != private_sequencer_latency_fee_shaper_attestation_id(
                &self.sequencer_id,
                &self.lane_id,
                &self.bucket_id,
                &self.batch_root,
                self.attested_height,
                &self.transcript_root,
            )
        {
            return Err("attestation id mismatch".to_string());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateCongestionSignal {
    pub signal_id: String,
    pub lane_id: String,
    pub sequencer_id: String,
    pub severity: CongestionSignalSeverity,
    pub epoch_index: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub queue_depth_commitment: String,
    pub encrypted_pressure_root: String,
    pub witness_root: String,
    pub fee_multiplier_bps: u64,
    pub rescue_lane_open: bool,
}
impl PrivateCongestionSignal {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: &str,
        sequencer_id: &str,
        severity: CongestionSignalSeverity,
        epoch_index: u64,
        start_height: u64,
        end_height: u64,
        queue_depth_commitment: &str,
        encrypted_pressure_root: &str,
        witness: &Value,
        rescue_lane_open: bool,
    ) -> PrivateSequencerLatencyFeeShaperResult<Self> {
        ensure_non_empty(lane_id, "congestion signal lane id")?;
        ensure_non_empty(sequencer_id, "congestion signal sequencer id")?;
        ensure_non_empty(
            queue_depth_commitment,
            "congestion signal queue depth commitment",
        )?;
        ensure_non_empty(encrypted_pressure_root, "congestion signal pressure root")?;
        if end_height < start_height {
            return Err("congestion signal end height precedes start height".to_string());
        }
        let witness_root =
            private_sequencer_latency_fee_shaper_payload_root("CONGESTION-SIGNAL-WITNESS", witness);
        let fee_multiplier_bps = severity.fee_multiplier_bps();
        let signal_id = private_sequencer_latency_fee_shaper_congestion_signal_id(
            lane_id,
            sequencer_id,
            severity,
            epoch_index,
            start_height,
            end_height,
            &witness_root,
        );
        Ok(Self {
            signal_id,
            lane_id: lane_id.to_string(),
            sequencer_id: sequencer_id.to_string(),
            severity,
            epoch_index,
            start_height,
            end_height,
            queue_depth_commitment: queue_depth_commitment.to_string(),
            encrypted_pressure_root: encrypted_pressure_root.to_string(),
            witness_root,
            fee_multiplier_bps,
            rescue_lane_open,
        })
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_congestion_signal",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_PROTOCOL_VERSION,
            "signal_id": self.signal_id,
            "lane_id": self.lane_id,
            "sequencer_id": self.sequencer_id,
            "severity": self.severity.as_str(),
            "epoch_index": self.epoch_index,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "queue_depth_commitment": self.queue_depth_commitment,
            "encrypted_pressure_root": self.encrypted_pressure_root,
            "witness_root": self.witness_root,
            "fee_multiplier_bps": self.fee_multiplier_bps,
            "rescue_lane_open": self.rescue_lane_open,
        })
    }
    pub fn validate(&self) -> PrivateSequencerLatencyFeeShaperResult<()> {
        ensure_non_empty(&self.signal_id, "congestion signal id")?;
        ensure_non_empty(&self.lane_id, "congestion signal lane id")?;
        ensure_non_empty(&self.sequencer_id, "congestion signal sequencer id")?;
        ensure_non_empty(
            &self.queue_depth_commitment,
            "congestion signal queue depth commitment",
        )?;
        ensure_non_empty(
            &self.encrypted_pressure_root,
            "congestion signal pressure root",
        )?;
        ensure_non_empty(&self.witness_root, "congestion signal witness root")?;
        if self.end_height < self.start_height {
            return Err("congestion signal end height precedes start height".to_string());
        }
        if self.signal_id
            != private_sequencer_latency_fee_shaper_congestion_signal_id(
                &self.lane_id,
                &self.sequencer_id,
                self.severity,
                self.epoch_index,
                self.start_height,
                self.end_height,
                &self.witness_root,
            )
        {
            return Err("congestion signal id mismatch".to_string());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeCapCommitment {
    pub cap_id: String,
    pub lane_id: String,
    pub submitter_commitment: String,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub max_fee_bps: u64,
    pub fee_note_root: String,
    pub nullifier_root: String,
    pub encrypted_refund_root: String,
    pub expiry_height: u64,
}
impl FeeCapCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: &str,
        submitter_commitment: &str,
        fee_asset_id: &str,
        max_fee_units: u64,
        max_fee_bps: u64,
        fee_note_root: &str,
        encrypted_refund_root: &str,
        expiry_height: u64,
    ) -> PrivateSequencerLatencyFeeShaperResult<Self> {
        ensure_non_empty(lane_id, "fee cap lane id")?;
        ensure_non_empty(submitter_commitment, "fee cap submitter commitment")?;
        ensure_non_empty(fee_asset_id, "fee cap asset id")?;
        ensure_non_empty(fee_note_root, "fee cap note root")?;
        ensure_non_empty(encrypted_refund_root, "fee cap encrypted refund root")?;
        ensure_positive(max_fee_units, "fee cap max fee units")?;
        ensure_bps(max_fee_bps, "fee cap max fee bps")?;
        let nullifier_root = private_sequencer_latency_fee_shaper_hash(
            "FEE-CAP-NULLIFIER",
            &[
                HashPart::Str(lane_id),
                HashPart::Str(submitter_commitment),
                HashPart::Str(fee_note_root),
                HashPart::Int(expiry_height as i128),
            ],
        );
        let cap_id = private_sequencer_latency_fee_shaper_fee_cap_id(
            lane_id,
            submitter_commitment,
            fee_asset_id,
            max_fee_units,
            max_fee_bps,
            fee_note_root,
            &nullifier_root,
        );
        Ok(Self {
            cap_id,
            lane_id: lane_id.to_string(),
            submitter_commitment: submitter_commitment.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            max_fee_units,
            max_fee_bps,
            fee_note_root: fee_note_root.to_string(),
            nullifier_root,
            encrypted_refund_root: encrypted_refund_root.to_string(),
            expiry_height,
        })
    }
    pub fn is_expired(&self, height: u64) -> bool {
        height > self.expiry_height
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_cap_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_PROTOCOL_VERSION,
            "cap_id": self.cap_id,
            "lane_id": self.lane_id,
            "submitter_commitment": self.submitter_commitment,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "max_fee_bps": self.max_fee_bps,
            "fee_note_root": self.fee_note_root,
            "nullifier_root": self.nullifier_root,
            "encrypted_refund_root": self.encrypted_refund_root,
            "expiry_height": self.expiry_height,
        })
    }
    pub fn validate(
        &self,
        config: &PrivateSequencerLatencyFeeShaperConfig,
    ) -> PrivateSequencerLatencyFeeShaperResult<()> {
        ensure_non_empty(&self.cap_id, "fee cap id")?;
        ensure_non_empty(&self.lane_id, "fee cap lane id")?;
        ensure_non_empty(&self.submitter_commitment, "fee cap submitter commitment")?;
        ensure_non_empty(&self.fee_asset_id, "fee cap asset id")?;
        ensure_non_empty(&self.fee_note_root, "fee cap note root")?;
        ensure_non_empty(&self.nullifier_root, "fee cap nullifier root")?;
        ensure_non_empty(&self.encrypted_refund_root, "fee cap encrypted refund root")?;
        ensure_positive(self.max_fee_units, "fee cap max fee units")?;
        ensure_bps(self.max_fee_bps, "fee cap max fee bps")?;
        if self.max_fee_bps > config.max_fee_cap_bps {
            return Err("fee cap bps exceeds configured maximum".to_string());
        }
        if self.cap_id
            != private_sequencer_latency_fee_shaper_fee_cap_id(
                &self.lane_id,
                &self.submitter_commitment,
                &self.fee_asset_id,
                self.max_fee_units,
                self.max_fee_bps,
                &self.fee_note_root,
                &self.nullifier_root,
            )
        {
            return Err("fee cap id mismatch".to_string());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchAdmissionReceipt {
    pub receipt_id: String,
    pub lane_id: String,
    pub sequencer_id: String,
    pub cap_id: String,
    pub attestation_id: String,
    pub batch_root: String,
    pub payload_root: String,
    pub receipt_nullifier_root: String,
    pub admitted_height: u64,
    pub included_height: u64,
    pub charged_fee_units: u64,
    pub rebate_units: u64,
    pub status: AdmissionReceiptStatus,
}
impl BatchAdmissionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: &str,
        sequencer_id: &str,
        cap_id: &str,
        attestation_id: &str,
        batch_root: &str,
        payload_root: &str,
        admitted_height: u64,
        included_height: u64,
        charged_fee_units: u64,
        rebate_units: u64,
    ) -> PrivateSequencerLatencyFeeShaperResult<Self> {
        ensure_non_empty(lane_id, "receipt lane id")?;
        ensure_non_empty(sequencer_id, "receipt sequencer id")?;
        ensure_non_empty(cap_id, "receipt fee cap id")?;
        ensure_non_empty(attestation_id, "receipt attestation id")?;
        ensure_non_empty(batch_root, "receipt batch root")?;
        ensure_non_empty(payload_root, "receipt payload root")?;
        if included_height < admitted_height {
            return Err("receipt included height precedes admitted height".to_string());
        }
        let receipt_nullifier_root = private_sequencer_latency_fee_shaper_hash(
            "BATCH-ADMISSION-RECEIPT-NULLIFIER",
            &[
                HashPart::Str(lane_id),
                HashPart::Str(sequencer_id),
                HashPart::Str(cap_id),
                HashPart::Str(batch_root),
                HashPart::Str(payload_root),
                HashPart::Int(admitted_height as i128),
            ],
        );
        let receipt_id = private_sequencer_latency_fee_shaper_receipt_id(
            lane_id,
            sequencer_id,
            cap_id,
            attestation_id,
            batch_root,
            &receipt_nullifier_root,
        );
        Ok(Self {
            receipt_id,
            lane_id: lane_id.to_string(),
            sequencer_id: sequencer_id.to_string(),
            cap_id: cap_id.to_string(),
            attestation_id: attestation_id.to_string(),
            batch_root: batch_root.to_string(),
            payload_root: payload_root.to_string(),
            receipt_nullifier_root,
            admitted_height,
            included_height,
            charged_fee_units,
            rebate_units,
            status: AdmissionReceiptStatus::Issued,
        })
    }
    pub fn latency_blocks(&self) -> u64 {
        self.included_height.saturating_sub(self.admitted_height)
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "batch_admission_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "lane_id": self.lane_id,
            "sequencer_id": self.sequencer_id,
            "cap_id": self.cap_id,
            "attestation_id": self.attestation_id,
            "batch_root": self.batch_root,
            "payload_root": self.payload_root,
            "receipt_nullifier_root": self.receipt_nullifier_root,
            "admitted_height": self.admitted_height,
            "included_height": self.included_height,
            "latency_blocks": self.latency_blocks(),
            "charged_fee_units": self.charged_fee_units,
            "rebate_units": self.rebate_units,
            "status": self.status.as_str(),
        })
    }
    pub fn validate(&self) -> PrivateSequencerLatencyFeeShaperResult<()> {
        ensure_non_empty(&self.receipt_id, "receipt id")?;
        ensure_non_empty(&self.lane_id, "receipt lane id")?;
        ensure_non_empty(&self.sequencer_id, "receipt sequencer id")?;
        ensure_non_empty(&self.cap_id, "receipt fee cap id")?;
        ensure_non_empty(&self.attestation_id, "receipt attestation id")?;
        ensure_non_empty(&self.batch_root, "receipt batch root")?;
        ensure_non_empty(&self.payload_root, "receipt payload root")?;
        ensure_non_empty(&self.receipt_nullifier_root, "receipt nullifier root")?;
        if self.included_height < self.admitted_height {
            return Err("receipt included height precedes admitted height".to_string());
        }
        if self.receipt_id
            != private_sequencer_latency_fee_shaper_receipt_id(
                &self.lane_id,
                &self.sequencer_id,
                &self.cap_id,
                &self.attestation_id,
                &self.batch_root,
                &self.receipt_nullifier_root,
            )
        {
            return Err("receipt id mismatch".to_string());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatencySlaChallenge {
    pub challenge_id: String,
    pub receipt_id: String,
    pub lane_id: String,
    pub sequencer_id: String,
    pub challenger_commitment: String,
    pub claimed_latency_ms: u64,
    pub sla_latency_ms: u64,
    pub evidence_root: String,
    pub opened_height: u64,
    pub response_due_height: u64,
    pub status: SlaChallengeStatus,
}
impl LatencySlaChallenge {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        receipt_id: &str,
        lane_id: &str,
        sequencer_id: &str,
        challenger_commitment: &str,
        claimed_latency_ms: u64,
        sla_latency_ms: u64,
        evidence: &Value,
        opened_height: u64,
        config: &PrivateSequencerLatencyFeeShaperConfig,
    ) -> PrivateSequencerLatencyFeeShaperResult<Self> {
        ensure_non_empty(receipt_id, "challenge receipt id")?;
        ensure_non_empty(lane_id, "challenge lane id")?;
        ensure_non_empty(sequencer_id, "challenge sequencer id")?;
        ensure_non_empty(challenger_commitment, "challenge challenger commitment")?;
        ensure_positive(sla_latency_ms, "challenge sla latency ms")?;
        if claimed_latency_ms <= sla_latency_ms {
            return Err("challenge latency does not exceed sla".to_string());
        }
        let evidence_root =
            private_sequencer_latency_fee_shaper_payload_root("LATENCY-SLA-EVIDENCE", evidence);
        let response_due_height = opened_height.saturating_add(config.challenge_window_blocks);
        let challenge_id = private_sequencer_latency_fee_shaper_challenge_id(
            receipt_id,
            lane_id,
            sequencer_id,
            challenger_commitment,
            claimed_latency_ms,
            &evidence_root,
        );
        Ok(Self {
            challenge_id,
            receipt_id: receipt_id.to_string(),
            lane_id: lane_id.to_string(),
            sequencer_id: sequencer_id.to_string(),
            challenger_commitment: challenger_commitment.to_string(),
            claimed_latency_ms,
            sla_latency_ms,
            evidence_root,
            opened_height,
            response_due_height,
            status: SlaChallengeStatus::Open,
        })
    }
    pub fn is_expired(&self, height: u64) -> bool {
        height > self.response_due_height
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "latency_sla_challenge",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_PROTOCOL_VERSION,
            "challenge_id": self.challenge_id,
            "receipt_id": self.receipt_id,
            "lane_id": self.lane_id,
            "sequencer_id": self.sequencer_id,
            "challenger_commitment": self.challenger_commitment,
            "claimed_latency_ms": self.claimed_latency_ms,
            "sla_latency_ms": self.sla_latency_ms,
            "evidence_root": self.evidence_root,
            "opened_height": self.opened_height,
            "response_due_height": self.response_due_height,
            "status": self.status.as_str(),
        })
    }
    pub fn validate(&self) -> PrivateSequencerLatencyFeeShaperResult<()> {
        ensure_non_empty(&self.challenge_id, "challenge id")?;
        ensure_non_empty(&self.receipt_id, "challenge receipt id")?;
        ensure_non_empty(&self.lane_id, "challenge lane id")?;
        ensure_non_empty(&self.sequencer_id, "challenge sequencer id")?;
        ensure_non_empty(
            &self.challenger_commitment,
            "challenge challenger commitment",
        )?;
        ensure_non_empty(&self.evidence_root, "challenge evidence root")?;
        ensure_positive(self.sla_latency_ms, "challenge sla latency ms")?;
        if self.claimed_latency_ms <= self.sla_latency_ms {
            return Err("challenge latency does not exceed sla".to_string());
        }
        if self.response_due_height < self.opened_height {
            return Err("challenge response due height precedes opened height".to_string());
        }
        if self.challenge_id
            != private_sequencer_latency_fee_shaper_challenge_id(
                &self.receipt_id,
                &self.lane_id,
                &self.sequencer_id,
                &self.challenger_commitment,
                self.claimed_latency_ms,
                &self.evidence_root,
            )
        {
            return Err("challenge id mismatch".to_string());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerSlashingEvidence {
    pub slash_id: String,
    pub sequencer_id: String,
    pub lane_id: String,
    pub challenge_id: String,
    pub evidence_kind: SlashingEvidenceKind,
    pub evidence_root: String,
    pub slash_units: u64,
    pub slash_bps: u64,
    pub published_height: u64,
    pub reporter_commitment: String,
}
impl SequencerSlashingEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequencer_id: &str,
        lane_id: &str,
        challenge_id: &str,
        evidence_kind: SlashingEvidenceKind,
        evidence: &Value,
        bonded_stake_units: u64,
        reporter_commitment: &str,
        published_height: u64,
        config: &PrivateSequencerLatencyFeeShaperConfig,
    ) -> PrivateSequencerLatencyFeeShaperResult<Self> {
        ensure_non_empty(sequencer_id, "slashing sequencer id")?;
        ensure_non_empty(lane_id, "slashing lane id")?;
        ensure_non_empty(challenge_id, "slashing challenge id")?;
        ensure_non_empty(reporter_commitment, "slashing reporter commitment")?;
        ensure_positive(bonded_stake_units, "slashing bonded stake units")?;
        let evidence_root =
            private_sequencer_latency_fee_shaper_payload_root("SLASHING-EVIDENCE", evidence);
        let slash_bps = config.default_slash_bps;
        let slash_units = bonded_stake_units.saturating_mul(slash_bps)
            / PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_MAX_BPS;
        let slash_id = private_sequencer_latency_fee_shaper_slash_id(
            sequencer_id,
            lane_id,
            challenge_id,
            evidence_kind,
            &evidence_root,
            published_height,
        );
        Ok(Self {
            slash_id,
            sequencer_id: sequencer_id.to_string(),
            lane_id: lane_id.to_string(),
            challenge_id: challenge_id.to_string(),
            evidence_kind,
            evidence_root,
            slash_units,
            slash_bps,
            published_height,
            reporter_commitment: reporter_commitment.to_string(),
        })
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sequencer_slashing_evidence",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_PROTOCOL_VERSION,
            "slash_id": self.slash_id,
            "sequencer_id": self.sequencer_id,
            "lane_id": self.lane_id,
            "challenge_id": self.challenge_id,
            "evidence_kind": self.evidence_kind.as_str(),
            "evidence_root": self.evidence_root,
            "slash_units": self.slash_units,
            "slash_bps": self.slash_bps,
            "published_height": self.published_height,
            "reporter_commitment": self.reporter_commitment,
        })
    }
    pub fn validate(&self) -> PrivateSequencerLatencyFeeShaperResult<()> {
        ensure_non_empty(&self.slash_id, "slashing id")?;
        ensure_non_empty(&self.sequencer_id, "slashing sequencer id")?;
        ensure_non_empty(&self.lane_id, "slashing lane id")?;
        ensure_non_empty(&self.challenge_id, "slashing challenge id")?;
        ensure_non_empty(&self.evidence_root, "slashing evidence root")?;
        ensure_non_empty(&self.reporter_commitment, "slashing reporter commitment")?;
        ensure_bps(self.slash_bps, "slashing bps")?;
        ensure_positive(self.slash_units, "slashing units")?;
        if self.slash_id
            != private_sequencer_latency_fee_shaper_slash_id(
                &self.sequencer_id,
                &self.lane_id,
                &self.challenge_id,
                self.evidence_kind,
                &self.evidence_root,
                self.published_height,
            )
        {
            return Err("slashing evidence id mismatch".to_string());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSequencerLatencyFeeShaperCounters {
    pub lanes: usize,
    pub sequencers: usize,
    pub latency_buckets: usize,
    pub pq_attestations: usize,
    pub congestion_signals: usize,
    pub fee_cap_commitments: usize,
    pub receipts: usize,
    pub challenges: usize,
    pub slashing_evidence: usize,
    pub active_lanes: usize,
    pub rescue_lanes: usize,
    pub active_sequencers: usize,
    pub congested_signals: usize,
    pub open_challenges: usize,
    pub accepted_challenges: usize,
    pub slashed_sequencers: usize,
    pub total_bonded_stake_units: u64,
    pub total_slashed_units: u64,
    pub total_charged_fee_units: u64,
    pub total_rebate_units: u64,
}
impl PrivateSequencerLatencyFeeShaperCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_sequencer_latency_fee_shaper_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_PROTOCOL_VERSION,
            "lanes": self.lanes,
            "sequencers": self.sequencers,
            "latency_buckets": self.latency_buckets,
            "pq_attestations": self.pq_attestations,
            "congestion_signals": self.congestion_signals,
            "fee_cap_commitments": self.fee_cap_commitments,
            "receipts": self.receipts,
            "challenges": self.challenges,
            "slashing_evidence": self.slashing_evidence,
            "active_lanes": self.active_lanes,
            "rescue_lanes": self.rescue_lanes,
            "active_sequencers": self.active_sequencers,
            "congested_signals": self.congested_signals,
            "open_challenges": self.open_challenges,
            "accepted_challenges": self.accepted_challenges,
            "slashed_sequencers": self.slashed_sequencers,
            "total_bonded_stake_units": self.total_bonded_stake_units,
            "total_slashed_units": self.total_slashed_units,
            "total_charged_fee_units": self.total_charged_fee_units,
            "total_rebate_units": self.total_rebate_units,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSequencerLatencyFeeShaperRoots {
    pub config_root: String,
    pub lane_root: String,
    pub sequencer_root: String,
    pub latency_bucket_root: String,
    pub attestation_root: String,
    pub congestion_signal_root: String,
    pub fee_cap_root: String,
    pub receipt_root: String,
    pub challenge_root: String,
    pub slashing_root: String,
    pub counter_root: String,
    pub state_root: String,
}
impl PrivateSequencerLatencyFeeShaperRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_sequencer_latency_fee_shaper_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "sequencer_root": self.sequencer_root,
            "latency_bucket_root": self.latency_bucket_root,
            "attestation_root": self.attestation_root,
            "congestion_signal_root": self.congestion_signal_root,
            "fee_cap_root": self.fee_cap_root,
            "receipt_root": self.receipt_root,
            "challenge_root": self.challenge_root,
            "slashing_root": self.slashing_root,
            "counter_root": self.counter_root,
            "state_root": self.state_root,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSequencerLatencyFeeShaperState {
    pub height: u64,
    pub epoch_index: u64,
    pub controller_commitment: String,
    pub config: PrivateSequencerLatencyFeeShaperConfig,
    pub lanes: BTreeMap<String, PrivateSequencerLane>,
    pub sequencers: BTreeMap<String, PqSequencerAttestor>,
    pub latency_buckets: BTreeMap<String, EncryptedLatencyBucket>,
    pub attestations: BTreeMap<String, PqSequencerAttestation>,
    pub congestion_signals: BTreeMap<String, PrivateCongestionSignal>,
    pub fee_cap_commitments: BTreeMap<String, FeeCapCommitment>,
    pub receipts: BTreeMap<String, BatchAdmissionReceipt>,
    pub challenges: BTreeMap<String, LatencySlaChallenge>,
    pub slashing_evidence: BTreeMap<String, SequencerSlashingEvidence>,
    pub consumed_fee_cap_nullifiers: BTreeSet<String>,
    pub consumed_receipt_nullifiers: BTreeSet<String>,
}
impl PrivateSequencerLatencyFeeShaperState {
    pub fn new(
        height: u64,
        controller_commitment: &str,
        config: PrivateSequencerLatencyFeeShaperConfig,
    ) -> PrivateSequencerLatencyFeeShaperResult<Self> {
        ensure_non_empty(controller_commitment, "controller commitment")?;
        config.validate()?;
        let epoch_index = height / config.epoch_blocks;
        Ok(Self {
            height,
            epoch_index,
            controller_commitment: controller_commitment.to_string(),
            config,
            lanes: BTreeMap::new(),
            sequencers: BTreeMap::new(),
            latency_buckets: BTreeMap::new(),
            attestations: BTreeMap::new(),
            congestion_signals: BTreeMap::new(),
            fee_cap_commitments: BTreeMap::new(),
            receipts: BTreeMap::new(),
            challenges: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            consumed_fee_cap_nullifiers: BTreeSet::new(),
            consumed_receipt_nullifiers: BTreeSet::new(),
        })
    }
    pub fn devnet() -> PrivateSequencerLatencyFeeShaperResult<Self> {
        let config = PrivateSequencerLatencyFeeShaperConfig::devnet();
        let mut state = Self::new(
            PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_DEVNET_HEIGHT,
            "controller:private-sequencer-fee-shaper:devnet",
            config,
        )?;
        let bridge_lane = PrivateSequencerLane::new(
            PrivateSequencerLaneKind::MoneroBridge,
            "devnet-monero-bridge",
            "operator:sequencer:bridge:commitment",
            "admission:monero-bridge:policy-root",
            "fee:monero-bridge:policy-root",
            1_000,
            4_000,
            100_000,
        )?;
        let rescue_lane = PrivateSequencerLane::new(
            PrivateSequencerLaneKind::LowFeeRescue,
            "devnet-low-fee-rescue",
            "operator:sequencer:rescue:commitment",
            "admission:low-fee-rescue:policy-root",
            "fee:low-fee-rescue:policy-root",
            1_500,
            3_000,
            250_000,
        )?;
        let bridge_lane_id = bridge_lane.lane_id.clone();
        let rescue_lane_id = rescue_lane.lane_id.clone();
        state.insert_lane(bridge_lane)?;
        state.insert_lane(rescue_lane)?;
        let mut sequencer = PqSequencerAttestor::new(
            "operator:sequencer:devnet-a:commitment",
            "pq:ml-dsa-65:sequencer-a:public-key-root",
            "kem:ml-kem-768:sequencer-a:bucket-key-root",
            900_000,
            &state.config,
        )?;
        sequencer.bind_lane(&bridge_lane_id, state.config.max_active_lanes)?;
        sequencer.bind_lane(&rescue_lane_id, state.config.max_active_lanes)?;
        let sequencer_id = sequencer.sequencer_id.clone();
        state.insert_sequencer(sequencer)?;
        let bucket = EncryptedLatencyBucket::new(
            &bridge_lane_id,
            &sequencer_id,
            LatencyBucketClass::Fast,
            state.epoch_index,
            state.height,
            state.height.saturating_add(8),
            "enc:latency-count:bridge:a:root",
            "enc:latency-sum:bridge:a:root",
            "enc:latency-witness:bridge:a:root",
            "disclosure:bridge:a:commitment-root",
            "samples:bridge:a:commitment",
            520,
            &state.config,
        )?;
        let bucket_id = bucket.bucket_id.clone();
        state.insert_latency_bucket(bucket)?;
        let signal = PrivateCongestionSignal::new(
            &bridge_lane_id,
            &sequencer_id,
            CongestionSignalSeverity::Warn,
            state.epoch_index,
            state.height,
            state.height.saturating_add(8),
            "queue-depth:bridge:a:commitment",
            "enc:pressure:bridge:a:root",
            &json!({
                "window": "devnet-bootstrap",
                "queue_bucket": "warm",
                "private_set_size": 512,
            }),
            false,
        )?;
        let signal_root = private_sequencer_latency_fee_shaper_payload_root(
            "DEVNET-CONGESTION-SIGNAL",
            &signal.public_record(),
        );
        state.insert_congestion_signal(signal)?;
        let attestation = PqSequencerAttestation::new(
            &sequencer_id,
            &bridge_lane_id,
            &bucket_id,
            "batch:bridge:devnet:001:root",
            "fee-schedule:bridge:devnet:001:root",
            &signal_root,
            state.height.saturating_add(1),
            1_700_000_000_250,
            "pq:sig:sequencer-a:bridge:001:root",
            &json!({
                "batch": "bridge-devnet-001",
                "payloads": "roots-only",
                "fee_shape": "warn-congestion",
            }),
        )?;
        let attestation_id = attestation.attestation_id.clone();
        state.insert_attestation(attestation)?;
        let fee_cap = FeeCapCommitment::new(
            &bridge_lane_id,
            "acct:shielded:alice:commitment",
            &state.config.fee_asset_id,
            40_000,
            1_500,
            "fee-note:alice:bridge:001:root",
            "enc:refund:alice:bridge:001:root",
            state.height.saturating_add(200),
        )?;
        let cap_id = fee_cap.cap_id.clone();
        state.insert_fee_cap_commitment(fee_cap)?;
        let receipt = BatchAdmissionReceipt::new(
            &bridge_lane_id,
            &sequencer_id,
            &cap_id,
            &attestation_id,
            "batch:bridge:devnet:001:root",
            "payload:alice:bridge:001:root",
            state.height.saturating_add(1),
            state.height.saturating_add(2),
            32_000,
            3_000,
        )?;
        let receipt_id = receipt.receipt_id.clone();
        state.insert_receipt(receipt)?;
        let challenge = LatencySlaChallenge::new(
            &receipt_id,
            &bridge_lane_id,
            &sequencer_id,
            "watchtower:latency:devnet:a",
            900,
            450,
            &json!({
                "bucket": "fast",
                "observed_ms": 900,
                "receipt": receipt_id,
            }),
            state.height.saturating_add(12),
            &state.config,
        )?;
        let challenge_id = challenge.challenge_id.clone();
        state.insert_challenge(challenge)?;
        let bonded_stake_units = state
            .sequencers
            .get(&sequencer_id)
            .map(|sequencer| sequencer.bonded_stake_units)
            .ok_or_else(|| "devnet missing sequencer for slashing evidence".to_string())?;
        let slash = SequencerSlashingEvidence::new(
            &sequencer_id,
            &bridge_lane_id,
            &challenge_id,
            SlashingEvidenceKind::MissedLatencySla,
            &json!({
                "challenge": challenge_id,
                "violation": "latency_sla",
                "attestation": attestation_id,
            }),
            bonded_stake_units,
            "watchtower:latency:devnet:a",
            state.height.saturating_add(18),
            &state.config,
        )?;
        state.insert_slashing_evidence(slash)?;
        state.validate()?;
        Ok(state)
    }
    pub fn advance_height(
        &mut self,
        new_height: u64,
    ) -> PrivateSequencerLatencyFeeShaperResult<u64> {
        if new_height < self.height {
            return Err("private sequencer shaper height cannot move backwards".to_string());
        }
        self.height = new_height;
        self.epoch_index = self.height / self.config.epoch_blocks;
        Ok(self.height)
    }
    pub fn insert_lane(
        &mut self,
        lane: PrivateSequencerLane,
    ) -> PrivateSequencerLatencyFeeShaperResult<String> {
        lane.validate()?;
        if self.lanes.len() >= self.config.max_active_lanes
            && !self.lanes.contains_key(&lane.lane_id)
        {
            return Err("too many private sequencer lanes".to_string());
        }
        let lane_id = lane.lane_id.clone();
        self.lanes.insert(lane_id.clone(), lane);
        Ok(lane_id)
    }
    pub fn insert_sequencer(
        &mut self,
        sequencer: PqSequencerAttestor,
    ) -> PrivateSequencerLatencyFeeShaperResult<String> {
        sequencer.validate(&self.config)?;
        for lane_id in &sequencer.active_lane_ids {
            if !self.lanes.contains_key(lane_id) {
                return Err("sequencer references unknown lane".to_string());
            }
        }
        let sequencer_id = sequencer.sequencer_id.clone();
        self.sequencers.insert(sequencer_id.clone(), sequencer);
        Ok(sequencer_id)
    }
    pub fn bind_sequencer_to_lane(
        &mut self,
        sequencer_id: &str,
        lane_id: &str,
    ) -> PrivateSequencerLatencyFeeShaperResult<()> {
        if !self.lanes.contains_key(lane_id) {
            return Err("cannot bind sequencer to unknown lane".to_string());
        }
        let sequencer = self
            .sequencers
            .get_mut(sequencer_id)
            .ok_or_else(|| "cannot bind unknown sequencer".to_string())?;
        sequencer.bind_lane(lane_id, self.config.max_active_lanes)
    }
    pub fn insert_latency_bucket(
        &mut self,
        bucket: EncryptedLatencyBucket,
    ) -> PrivateSequencerLatencyFeeShaperResult<String> {
        bucket.validate()?;
        if self.latency_buckets.len() >= self.config.max_latency_buckets
            && !self.latency_buckets.contains_key(&bucket.bucket_id)
        {
            return Err("too many encrypted latency buckets".to_string());
        }
        self.ensure_lane_and_sequencer(&bucket.lane_id, &bucket.sequencer_id)?;
        let bucket_id = bucket.bucket_id.clone();
        self.latency_buckets.insert(bucket_id.clone(), bucket);
        Ok(bucket_id)
    }
    pub fn insert_attestation(
        &mut self,
        attestation: PqSequencerAttestation,
    ) -> PrivateSequencerLatencyFeeShaperResult<String> {
        attestation.validate()?;
        if self.attestations.len() >= self.config.max_attestations
            && !self.attestations.contains_key(&attestation.attestation_id)
        {
            return Err("too many pq sequencer attestations".to_string());
        }
        self.ensure_lane_and_sequencer(&attestation.lane_id, &attestation.sequencer_id)?;
        if !self.latency_buckets.contains_key(&attestation.bucket_id) {
            return Err("attestation references unknown latency bucket".to_string());
        }
        let attestation_id = attestation.attestation_id.clone();
        self.attestations
            .insert(attestation_id.clone(), attestation);
        Ok(attestation_id)
    }
    pub fn insert_congestion_signal(
        &mut self,
        signal: PrivateCongestionSignal,
    ) -> PrivateSequencerLatencyFeeShaperResult<String> {
        signal.validate()?;
        if self.congestion_signals.len() >= self.config.max_congestion_signals
            && !self.congestion_signals.contains_key(&signal.signal_id)
        {
            return Err("too many private congestion signals".to_string());
        }
        self.ensure_lane_and_sequencer(&signal.lane_id, &signal.sequencer_id)?;
        let signal_id = signal.signal_id.clone();
        self.congestion_signals.insert(signal_id.clone(), signal);
        Ok(signal_id)
    }
    pub fn insert_fee_cap_commitment(
        &mut self,
        cap: FeeCapCommitment,
    ) -> PrivateSequencerLatencyFeeShaperResult<String> {
        cap.validate(&self.config)?;
        if self.fee_cap_commitments.len() >= self.config.max_fee_cap_commitments
            && !self.fee_cap_commitments.contains_key(&cap.cap_id)
        {
            return Err("too many fee cap commitments".to_string());
        }
        if !self.lanes.contains_key(&cap.lane_id) {
            return Err("fee cap references unknown lane".to_string());
        }
        if self
            .consumed_fee_cap_nullifiers
            .contains(&cap.nullifier_root)
        {
            return Err("fee cap nullifier already consumed".to_string());
        }
        let cap_id = cap.cap_id.clone();
        self.consumed_fee_cap_nullifiers
            .insert(cap.nullifier_root.clone());
        self.fee_cap_commitments.insert(cap_id.clone(), cap);
        Ok(cap_id)
    }
    pub fn insert_receipt(
        &mut self,
        receipt: BatchAdmissionReceipt,
    ) -> PrivateSequencerLatencyFeeShaperResult<String> {
        receipt.validate()?;
        if self.receipts.len() >= self.config.max_receipts
            && !self.receipts.contains_key(&receipt.receipt_id)
        {
            return Err("too many batch admission receipts".to_string());
        }
        self.ensure_lane_and_sequencer(&receipt.lane_id, &receipt.sequencer_id)?;
        if !self.fee_cap_commitments.contains_key(&receipt.cap_id) {
            return Err("receipt references unknown fee cap".to_string());
        }
        if !self.attestations.contains_key(&receipt.attestation_id) {
            return Err("receipt references unknown attestation".to_string());
        }
        if self
            .consumed_receipt_nullifiers
            .contains(&receipt.receipt_nullifier_root)
        {
            return Err("receipt nullifier already consumed".to_string());
        }
        let receipt_id = receipt.receipt_id.clone();
        self.consumed_receipt_nullifiers
            .insert(receipt.receipt_nullifier_root.clone());
        self.receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }
    pub fn insert_challenge(
        &mut self,
        challenge: LatencySlaChallenge,
    ) -> PrivateSequencerLatencyFeeShaperResult<String> {
        challenge.validate()?;
        if self.challenges.len() >= self.config.max_challenges
            && !self.challenges.contains_key(&challenge.challenge_id)
        {
            return Err("too many latency sla challenges".to_string());
        }
        self.ensure_lane_and_sequencer(&challenge.lane_id, &challenge.sequencer_id)?;
        if !self.receipts.contains_key(&challenge.receipt_id) {
            return Err("challenge references unknown receipt".to_string());
        }
        let challenge_id = challenge.challenge_id.clone();
        self.challenges.insert(challenge_id.clone(), challenge);
        Ok(challenge_id)
    }
    pub fn insert_slashing_evidence(
        &mut self,
        slash: SequencerSlashingEvidence,
    ) -> PrivateSequencerLatencyFeeShaperResult<String> {
        slash.validate()?;
        if self.slashing_evidence.len() >= self.config.max_slashes
            && !self.slashing_evidence.contains_key(&slash.slash_id)
        {
            return Err("too many slashing evidence records".to_string());
        }
        self.ensure_lane_and_sequencer(&slash.lane_id, &slash.sequencer_id)?;
        if !self.challenges.contains_key(&slash.challenge_id) {
            return Err("slashing evidence references unknown challenge".to_string());
        }
        if let Some(sequencer) = self.sequencers.get_mut(&slash.sequencer_id) {
            sequencer.slashed_units = sequencer.slashed_units.saturating_add(slash.slash_units);
            sequencer.challenged_batches = sequencer.challenged_batches.saturating_add(1);
            if sequencer.slashed_units > 0 {
                sequencer.status = SequencerBondStatus::Slashed;
            }
        }
        let slash_id = slash.slash_id.clone();
        self.slashing_evidence.insert(slash_id.clone(), slash);
        Ok(slash_id)
    }
    pub fn counters(&self) -> PrivateSequencerLatencyFeeShaperCounters {
        let mut counters = PrivateSequencerLatencyFeeShaperCounters {
            lanes: self.lanes.len(),
            sequencers: self.sequencers.len(),
            latency_buckets: self.latency_buckets.len(),
            pq_attestations: self.attestations.len(),
            congestion_signals: self.congestion_signals.len(),
            fee_cap_commitments: self.fee_cap_commitments.len(),
            receipts: self.receipts.len(),
            challenges: self.challenges.len(),
            slashing_evidence: self.slashing_evidence.len(),
            ..PrivateSequencerLatencyFeeShaperCounters::default()
        };
        for lane in self.lanes.values() {
            if lane.status.admits_private_batches() {
                counters.active_lanes += 1;
            }
            if matches!(lane.lane_kind, PrivateSequencerLaneKind::LowFeeRescue) {
                counters.rescue_lanes += 1;
            }
        }
        for sequencer in self.sequencers.values() {
            if sequencer.status.may_attest() {
                counters.active_sequencers += 1;
            }
            if matches!(sequencer.status, SequencerBondStatus::Slashed) {
                counters.slashed_sequencers += 1;
            }
            counters.total_bonded_stake_units = counters
                .total_bonded_stake_units
                .saturating_add(sequencer.bonded_stake_units);
            counters.total_slashed_units = counters
                .total_slashed_units
                .saturating_add(sequencer.slashed_units);
        }
        for signal in self.congestion_signals.values() {
            if matches!(
                signal.severity,
                CongestionSignalSeverity::Warn
                    | CongestionSignalSeverity::Critical
                    | CongestionSignalSeverity::Rescue
                    | CongestionSignalSeverity::Halt
            ) {
                counters.congested_signals += 1;
            }
        }
        for receipt in self.receipts.values() {
            counters.total_charged_fee_units = counters
                .total_charged_fee_units
                .saturating_add(receipt.charged_fee_units);
            counters.total_rebate_units = counters
                .total_rebate_units
                .saturating_add(receipt.rebate_units);
        }
        for challenge in self.challenges.values() {
            match challenge.status {
                SlaChallengeStatus::Open | SlaChallengeStatus::EvidenceSubmitted => {
                    counters.open_challenges += 1
                }
                SlaChallengeStatus::Accepted | SlaChallengeStatus::Slashed => {
                    counters.accepted_challenges += 1
                }
                SlaChallengeStatus::Rejected | SlaChallengeStatus::Expired => {}
            }
        }
        counters
    }
    pub fn roots(&self) -> PrivateSequencerLatencyFeeShaperRoots {
        let config_root = self.config.config_root();
        let lane_root = map_merkle_root(
            "PRIVATE-SEQUENCER-LATENCY-FEE-SHAPER-LANES",
            self.lanes.values().map(PrivateSequencerLane::public_record),
        );
        let sequencer_root = map_merkle_root(
            "PRIVATE-SEQUENCER-LATENCY-FEE-SHAPER-SEQUENCERS",
            self.sequencers
                .values()
                .map(PqSequencerAttestor::public_record),
        );
        let latency_bucket_root = map_merkle_root(
            "PRIVATE-SEQUENCER-LATENCY-FEE-SHAPER-BUCKETS",
            self.latency_buckets
                .values()
                .map(EncryptedLatencyBucket::public_record),
        );
        let attestation_root = map_merkle_root(
            "PRIVATE-SEQUENCER-LATENCY-FEE-SHAPER-ATTESTATIONS",
            self.attestations
                .values()
                .map(PqSequencerAttestation::public_record),
        );
        let congestion_signal_root = map_merkle_root(
            "PRIVATE-SEQUENCER-LATENCY-FEE-SHAPER-CONGESTION-SIGNALS",
            self.congestion_signals
                .values()
                .map(PrivateCongestionSignal::public_record),
        );
        let fee_cap_root = map_merkle_root(
            "PRIVATE-SEQUENCER-LATENCY-FEE-SHAPER-FEE-CAPS",
            self.fee_cap_commitments
                .values()
                .map(FeeCapCommitment::public_record),
        );
        let receipt_root = map_merkle_root(
            "PRIVATE-SEQUENCER-LATENCY-FEE-SHAPER-RECEIPTS",
            self.receipts
                .values()
                .map(BatchAdmissionReceipt::public_record),
        );
        let challenge_root = map_merkle_root(
            "PRIVATE-SEQUENCER-LATENCY-FEE-SHAPER-CHALLENGES",
            self.challenges
                .values()
                .map(LatencySlaChallenge::public_record),
        );
        let slashing_root = map_merkle_root(
            "PRIVATE-SEQUENCER-LATENCY-FEE-SHAPER-SLASHES",
            self.slashing_evidence
                .values()
                .map(SequencerSlashingEvidence::public_record),
        );
        let counters = self.counters();
        let counter_root = private_sequencer_latency_fee_shaper_hash(
            "COUNTERS",
            &[HashPart::Json(&counters.public_record())],
        );
        let state_record = json!({
            "kind": "private_sequencer_latency_fee_shaper_state_root",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_PROTOCOL_VERSION,
            "height": self.height,
            "epoch_index": self.epoch_index,
            "controller_commitment": self.controller_commitment,
            "config_root": config_root,
            "lane_root": lane_root,
            "sequencer_root": sequencer_root,
            "latency_bucket_root": latency_bucket_root,
            "attestation_root": attestation_root,
            "congestion_signal_root": congestion_signal_root,
            "fee_cap_root": fee_cap_root,
            "receipt_root": receipt_root,
            "challenge_root": challenge_root,
            "slashing_root": slashing_root,
            "counter_root": counter_root,
        });
        let state_root = private_sequencer_latency_fee_shaper_state_root_from_record(&state_record);
        PrivateSequencerLatencyFeeShaperRoots {
            config_root,
            lane_root,
            sequencer_root,
            latency_bucket_root,
            attestation_root,
            congestion_signal_root,
            fee_cap_root,
            receipt_root,
            challenge_root,
            slashing_root,
            counter_root,
            state_root,
        }
    }
    pub fn state_root(&self) -> String {
        self.roots().state_root
    }
    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "private_sequencer_latency_fee_shaper_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_PROTOCOL_VERSION,
            "schema_version": PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_SCHEMA_VERSION,
            "height": self.height,
            "epoch_index": self.epoch_index,
            "controller_commitment": self.controller_commitment,
            "state_root": roots.state_root,
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "config": self.config.public_record(),
        })
    }
    pub fn validate(&self) -> PrivateSequencerLatencyFeeShaperResult<String> {
        ensure_non_empty(&self.controller_commitment, "controller commitment")?;
        self.config.validate()?;
        if self.epoch_index != self.height / self.config.epoch_blocks {
            return Err("state epoch index does not match height".to_string());
        }
        if self.lanes.len() > self.config.max_active_lanes {
            return Err("state exceeds lane maximum".to_string());
        }
        if self.latency_buckets.len() > self.config.max_latency_buckets {
            return Err("state exceeds latency bucket maximum".to_string());
        }
        if self.attestations.len() > self.config.max_attestations {
            return Err("state exceeds attestation maximum".to_string());
        }
        if self.congestion_signals.len() > self.config.max_congestion_signals {
            return Err("state exceeds congestion signal maximum".to_string());
        }
        if self.fee_cap_commitments.len() > self.config.max_fee_cap_commitments {
            return Err("state exceeds fee cap maximum".to_string());
        }
        if self.receipts.len() > self.config.max_receipts {
            return Err("state exceeds receipt maximum".to_string());
        }
        if self.challenges.len() > self.config.max_challenges {
            return Err("state exceeds challenge maximum".to_string());
        }
        if self.slashing_evidence.len() > self.config.max_slashes {
            return Err("state exceeds slashing evidence maximum".to_string());
        }
        let mut fee_cap_nullifiers = BTreeSet::new();
        let mut receipt_nullifiers = BTreeSet::new();
        for (lane_id, lane) in &self.lanes {
            if lane_id != &lane.lane_id {
                return Err("lane map key mismatch".to_string());
            }
            lane.validate()?;
        }
        for (sequencer_id, sequencer) in &self.sequencers {
            if sequencer_id != &sequencer.sequencer_id {
                return Err("sequencer map key mismatch".to_string());
            }
            sequencer.validate(&self.config)?;
            for lane_id in &sequencer.active_lane_ids {
                if !self.lanes.contains_key(lane_id) {
                    return Err("sequencer references unknown active lane".to_string());
                }
            }
        }
        for (bucket_id, bucket) in &self.latency_buckets {
            if bucket_id != &bucket.bucket_id {
                return Err("latency bucket map key mismatch".to_string());
            }
            bucket.validate()?;
            self.ensure_lane_and_sequencer(&bucket.lane_id, &bucket.sequencer_id)?;
        }
        for (attestation_id, attestation) in &self.attestations {
            if attestation_id != &attestation.attestation_id {
                return Err("attestation map key mismatch".to_string());
            }
            attestation.validate()?;
            self.ensure_lane_and_sequencer(&attestation.lane_id, &attestation.sequencer_id)?;
            if !self.latency_buckets.contains_key(&attestation.bucket_id) {
                return Err("attestation references unknown latency bucket".to_string());
            }
        }
        for (signal_id, signal) in &self.congestion_signals {
            if signal_id != &signal.signal_id {
                return Err("congestion signal map key mismatch".to_string());
            }
            signal.validate()?;
            self.ensure_lane_and_sequencer(&signal.lane_id, &signal.sequencer_id)?;
        }
        for (cap_id, cap) in &self.fee_cap_commitments {
            if cap_id != &cap.cap_id {
                return Err("fee cap map key mismatch".to_string());
            }
            cap.validate(&self.config)?;
            if !self.lanes.contains_key(&cap.lane_id) {
                return Err("fee cap references unknown lane".to_string());
            }
            if !fee_cap_nullifiers.insert(cap.nullifier_root.clone()) {
                return Err("duplicate fee cap nullifier".to_string());
            }
        }
        for nullifier in &self.consumed_fee_cap_nullifiers {
            if !fee_cap_nullifiers.contains(nullifier) {
                return Err("consumed fee cap nullifier missing commitment".to_string());
            }
        }
        for (receipt_id, receipt) in &self.receipts {
            if receipt_id != &receipt.receipt_id {
                return Err("receipt map key mismatch".to_string());
            }
            receipt.validate()?;
            self.ensure_lane_and_sequencer(&receipt.lane_id, &receipt.sequencer_id)?;
            if !self.fee_cap_commitments.contains_key(&receipt.cap_id) {
                return Err("receipt references unknown fee cap".to_string());
            }
            if !self.attestations.contains_key(&receipt.attestation_id) {
                return Err("receipt references unknown attestation".to_string());
            }
            if !receipt_nullifiers.insert(receipt.receipt_nullifier_root.clone()) {
                return Err("duplicate receipt nullifier".to_string());
            }
        }
        for nullifier in &self.consumed_receipt_nullifiers {
            if !receipt_nullifiers.contains(nullifier) {
                return Err("consumed receipt nullifier missing receipt".to_string());
            }
        }
        for (challenge_id, challenge) in &self.challenges {
            if challenge_id != &challenge.challenge_id {
                return Err("challenge map key mismatch".to_string());
            }
            challenge.validate()?;
            self.ensure_lane_and_sequencer(&challenge.lane_id, &challenge.sequencer_id)?;
            if !self.receipts.contains_key(&challenge.receipt_id) {
                return Err("challenge references unknown receipt".to_string());
            }
        }
        for (slash_id, slash) in &self.slashing_evidence {
            if slash_id != &slash.slash_id {
                return Err("slashing evidence map key mismatch".to_string());
            }
            slash.validate()?;
            self.ensure_lane_and_sequencer(&slash.lane_id, &slash.sequencer_id)?;
            if !self.challenges.contains_key(&slash.challenge_id) {
                return Err("slashing evidence references unknown challenge".to_string());
            }
        }
        Ok(self.state_root())
    }
    fn ensure_lane_and_sequencer(
        &self,
        lane_id: &str,
        sequencer_id: &str,
    ) -> PrivateSequencerLatencyFeeShaperResult<()> {
        let lane = self
            .lanes
            .get(lane_id)
            .ok_or_else(|| "unknown private sequencer lane".to_string())?;
        if !lane.status.admits_private_batches() {
            return Err("private sequencer lane does not admit batches".to_string());
        }
        let sequencer = self
            .sequencers
            .get(sequencer_id)
            .ok_or_else(|| "unknown private sequencer attestor".to_string())?;
        if !sequencer.status.may_attest() {
            return Err("private sequencer may not attest".to_string());
        }
        if !sequencer.active_lane_ids.contains(lane_id) {
            return Err("private sequencer is not bound to lane".to_string());
        }
        Ok(())
    }
}
pub fn private_sequencer_latency_fee_shaper_devnet(
) -> PrivateSequencerLatencyFeeShaperResult<PrivateSequencerLatencyFeeShaperState> {
    PrivateSequencerLatencyFeeShaperState::devnet()
}
pub fn private_sequencer_latency_fee_shaper_state_root_from_record(record: &Value) -> String {
    private_sequencer_latency_fee_shaper_hash("STATE-ROOT", &[HashPart::Json(record)])
}
pub fn private_sequencer_latency_fee_shaper_payload_root(label: &str, payload: &Value) -> String {
    private_sequencer_latency_fee_shaper_hash(label, &[HashPart::Json(payload)])
}
pub fn private_sequencer_latency_fee_shaper_metadata_root(label: &str, values: &[&str]) -> String {
    let leaves = values
        .iter()
        .map(|value| Value::String((*value).to_string()))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-SEQUENCER-LATENCY-FEE-SHAPER-METADATA-{label}"),
        &leaves,
    )
}
pub fn private_sequencer_latency_fee_shaper_lane_id(
    lane_kind: PrivateSequencerLaneKind,
    label: &str,
    operator_commitment: &str,
    admission_policy_root: &str,
    fee_policy_root: &str,
) -> String {
    private_sequencer_latency_fee_shaper_hash(
        "LANE-ID",
        &[
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(label),
            HashPart::Str(operator_commitment),
            HashPart::Str(admission_policy_root),
            HashPart::Str(fee_policy_root),
        ],
    )
}
pub fn private_sequencer_latency_fee_shaper_sequencer_id(
    operator_commitment: &str,
    pq_public_key_root: &str,
    encryption_key_root: &str,
) -> String {
    private_sequencer_latency_fee_shaper_hash(
        "SEQUENCER-ID",
        &[
            HashPart::Str(operator_commitment),
            HashPart::Str(pq_public_key_root),
            HashPart::Str(encryption_key_root),
        ],
    )
}
pub fn private_sequencer_latency_fee_shaper_bucket_id(
    lane_id: &str,
    sequencer_id: &str,
    bucket_class: LatencyBucketClass,
    epoch_index: u64,
    start_height: u64,
    end_height: u64,
    encrypted_witness_root: &str,
) -> String {
    private_sequencer_latency_fee_shaper_hash(
        "LATENCY-BUCKET-ID",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(sequencer_id),
            HashPart::Str(bucket_class.as_str()),
            HashPart::Int(epoch_index as i128),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
            HashPart::Str(encrypted_witness_root),
        ],
    )
}
pub fn private_sequencer_latency_fee_shaper_attestation_id(
    sequencer_id: &str,
    lane_id: &str,
    bucket_id: &str,
    batch_root: &str,
    attested_height: u64,
    transcript_root: &str,
) -> String {
    private_sequencer_latency_fee_shaper_hash(
        "PQ-ATTESTATION-ID",
        &[
            HashPart::Str(sequencer_id),
            HashPart::Str(lane_id),
            HashPart::Str(bucket_id),
            HashPart::Str(batch_root),
            HashPart::Int(attested_height as i128),
            HashPart::Str(transcript_root),
        ],
    )
}
pub fn private_sequencer_latency_fee_shaper_congestion_signal_id(
    lane_id: &str,
    sequencer_id: &str,
    severity: CongestionSignalSeverity,
    epoch_index: u64,
    start_height: u64,
    end_height: u64,
    witness_root: &str,
) -> String {
    private_sequencer_latency_fee_shaper_hash(
        "CONGESTION-SIGNAL-ID",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(sequencer_id),
            HashPart::Str(severity.as_str()),
            HashPart::Int(epoch_index as i128),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
            HashPart::Str(witness_root),
        ],
    )
}
pub fn private_sequencer_latency_fee_shaper_fee_cap_id(
    lane_id: &str,
    submitter_commitment: &str,
    fee_asset_id: &str,
    max_fee_units: u64,
    max_fee_bps: u64,
    fee_note_root: &str,
    nullifier_root: &str,
) -> String {
    private_sequencer_latency_fee_shaper_hash(
        "FEE-CAP-ID",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(submitter_commitment),
            HashPart::Str(fee_asset_id),
            HashPart::Int(max_fee_units as i128),
            HashPart::Int(max_fee_bps as i128),
            HashPart::Str(fee_note_root),
            HashPart::Str(nullifier_root),
        ],
    )
}
pub fn private_sequencer_latency_fee_shaper_receipt_id(
    lane_id: &str,
    sequencer_id: &str,
    cap_id: &str,
    attestation_id: &str,
    batch_root: &str,
    receipt_nullifier_root: &str,
) -> String {
    private_sequencer_latency_fee_shaper_hash(
        "BATCH-ADMISSION-RECEIPT-ID",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(sequencer_id),
            HashPart::Str(cap_id),
            HashPart::Str(attestation_id),
            HashPart::Str(batch_root),
            HashPart::Str(receipt_nullifier_root),
        ],
    )
}
pub fn private_sequencer_latency_fee_shaper_challenge_id(
    receipt_id: &str,
    lane_id: &str,
    sequencer_id: &str,
    challenger_commitment: &str,
    claimed_latency_ms: u64,
    evidence_root: &str,
) -> String {
    private_sequencer_latency_fee_shaper_hash(
        "LATENCY-SLA-CHALLENGE-ID",
        &[
            HashPart::Str(receipt_id),
            HashPart::Str(lane_id),
            HashPart::Str(sequencer_id),
            HashPart::Str(challenger_commitment),
            HashPart::Int(claimed_latency_ms as i128),
            HashPart::Str(evidence_root),
        ],
    )
}
pub fn private_sequencer_latency_fee_shaper_slash_id(
    sequencer_id: &str,
    lane_id: &str,
    challenge_id: &str,
    evidence_kind: SlashingEvidenceKind,
    evidence_root: &str,
    published_height: u64,
) -> String {
    private_sequencer_latency_fee_shaper_hash(
        "SLASH-ID",
        &[
            HashPart::Str(sequencer_id),
            HashPart::Str(lane_id),
            HashPart::Str(challenge_id),
            HashPart::Str(evidence_kind.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Int(published_height as i128),
        ],
    )
}
pub fn private_sequencer_latency_fee_shaper_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-SEQUENCER-LATENCY-FEE-SHAPER-{domain}"),
        parts,
        32,
    )
}
fn map_merkle_root<I>(domain: &str, records: I) -> String
where
    I: Iterator<Item = Value>,
{
    let leaves = records.collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
fn ensure_non_empty(value: &str, label: &str) -> PrivateSequencerLatencyFeeShaperResult<()> {
    if value.is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}
fn ensure_positive(value: u64, label: &str) -> PrivateSequencerLatencyFeeShaperResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}
fn ensure_usize_positive(value: usize, label: &str) -> PrivateSequencerLatencyFeeShaperResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}
fn ensure_bps(value: u64, label: &str) -> PrivateSequencerLatencyFeeShaperResult<()> {
    if value > PRIVATE_SEQUENCER_LATENCY_FEE_SHAPER_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}
