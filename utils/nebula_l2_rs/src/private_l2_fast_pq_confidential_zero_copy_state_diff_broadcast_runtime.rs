#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialZeroCopyStateDiffBroadcastRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_ZERO_COPY_STATE_DIFF_BROADCAST_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-zero-copy-state-diff-broadcast-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_ZERO_COPY_STATE_DIFF_BROADCAST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ZERO_COPY_DIFF_SUITE: &str = "zero-copy-confidential-state-diff-slice-broadcast-v1";
pub const PQ_AVAILABILITY_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-state-diff-availability-v1";
pub const ENCRYPTED_WITNESS_REF_SUITE: &str =
    "ML-KEM-1024-threshold-encrypted-witness-reference-v1";
pub const PRECONFIRMATION_HINT_SUITE: &str =
    "private-l2-pq-confidential-preconfirmation-state-diff-hint-v1";
pub const BACKPRESSURE_SUITE: &str = "zero-copy-state-diff-backpressure-window-v1";
pub const CACHE_LEASE_SUITE: &str = "zero-copy-state-diff-cache-lease-ticket-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "confidential-state-diff-low-fee-sponsor-rebate-v1";
pub const PRIVACY_REDACTION_SUITE: &str = "budgeted-broadcast-redaction-root-v1";
pub const OPERATOR_SUMMARY_SUITE: &str = "operator-safe-zero-copy-broadcast-summary-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_360_512;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_681_024;
pub const DEVNET_EPOCH: u64 = 16_384;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_BROADCAST_MS: u64 = 12;
pub const DEFAULT_MAX_BROADCAST_MS: u64 = 80;
pub const DEFAULT_TARGET_ZERO_COPY_HIT_BPS: u64 = 9_300;
pub const DEFAULT_MAX_BACKPRESSURE_BPS: u64 = 8_500;
pub const DEFAULT_REDACTION_BUDGET_BPS: u64 = 360;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 7;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 8_800;
pub const DEFAULT_DIFF_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_HINT_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_CACHE_LEASE_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 192;
pub const DEFAULT_MAX_LANES: usize = 131_072;
pub const DEFAULT_MAX_SHARD_FANOUTS: usize = 524_288;
pub const DEFAULT_MAX_DIFFS: usize = 8_388_608;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 8_388_608;
pub const DEFAULT_MAX_WITNESS_REFS: usize = 8_388_608;
pub const DEFAULT_MAX_PRECONFIRMATION_HINTS: usize = 4_194_304;
pub const DEFAULT_MAX_BACKPRESSURE_WINDOWS: usize = 2_097_152;
pub const DEFAULT_MAX_CACHE_LEASES: usize = 4_194_304;
pub const DEFAULT_MAX_REBATES: usize = 4_194_304;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 2_097_152;
pub const DEFAULT_MAX_OPERATOR_SUMMARIES: usize = 2_097_152;

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
pub enum BroadcastLaneKind {
    HotAccountDelta,
    ContractStorageDelta,
    MoneroBridgeOutputDelta,
    DefiNettingDelta,
    CrossShardReceiptDelta,
    OracleStateDelta,
    RecursiveWitnessDelta,
    EscapeHatchDelta,
}

impl BroadcastLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HotAccountDelta => "hot_account_delta",
            Self::ContractStorageDelta => "contract_storage_delta",
            Self::MoneroBridgeOutputDelta => "monero_bridge_output_delta",
            Self::DefiNettingDelta => "defi_netting_delta",
            Self::CrossShardReceiptDelta => "cross_shard_receipt_delta",
            Self::OracleStateDelta => "oracle_state_delta",
            Self::RecursiveWitnessDelta => "recursive_witness_delta",
            Self::EscapeHatchDelta => "escape_hatch_delta",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EscapeHatchDelta => 10_000,
            Self::MoneroBridgeOutputDelta => 9_700,
            Self::DefiNettingDelta => 9_200,
            Self::CrossShardReceiptDelta => 8_900,
            Self::HotAccountDelta => 8_500,
            Self::ContractStorageDelta => 8_000,
            Self::OracleStateDelta => 7_600,
            Self::RecursiveWitnessDelta => 7_200,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Hot,
    Backpressured,
    Draining,
    Paused,
    Retired,
}

impl LaneStatus {
    pub fn accepts_broadcasts(self) -> bool {
        matches!(self, Self::Open | Self::Hot | Self::Backpressured)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Hot => "hot",
            Self::Backpressured => "backpressured",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffStatus {
    Draft,
    Broadcast,
    FanoutCommitted,
    AvailabilityAttested,
    Preconfirmed,
    Leased,
    Rebated,
    Settled,
    Expired,
    Rejected,
}

impl DiffStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Broadcast
                | Self::FanoutCommitted
                | Self::AvailabilityAttested
                | Self::Preconfirmed
                | Self::Leased
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Broadcast => "broadcast",
            Self::FanoutCommitted => "fanout_committed",
            Self::AvailabilityAttested => "availability_attested",
            Self::Preconfirmed => "preconfirmed",
            Self::Leased => "leased",
            Self::Rebated => "rebated",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Available,
    Delayed,
    Withheld,
    Invalid,
}

impl AttestationVerdict {
    pub fn accepted(self) -> bool {
        matches!(self, Self::Available | Self::Delayed)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Delayed => "delayed",
            Self::Withheld => "withheld",
            Self::Invalid => "invalid",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreconfirmationHintKind {
    ReadSetReady,
    WriteSetReady,
    WitnessWarm,
    CacheLeaseLikely,
    RebateEligible,
    BridgeExitFastPath,
}

impl PreconfirmationHintKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadSetReady => "read_set_ready",
            Self::WriteSetReady => "write_set_ready",
            Self::WitnessWarm => "witness_warm",
            Self::CacheLeaseLikely => "cache_lease_likely",
            Self::RebateEligible => "rebate_eligible",
            Self::BridgeExitFastPath => "bridge_exit_fast_path",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub mode: RuntimeMode,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_broadcast_ms: u64,
    pub max_broadcast_ms: u64,
    pub target_zero_copy_hit_bps: u64,
    pub max_backpressure_bps: u64,
    pub redaction_budget_bps: u64,
    pub sponsor_cover_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub diff_ttl_blocks: u64,
    pub hint_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub cache_lease_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub max_lanes: usize,
    pub max_shard_fanouts: usize,
    pub max_diffs: usize,
    pub max_attestations: usize,
    pub max_witness_refs: usize,
    pub max_preconfirmation_hints: usize,
    pub max_backpressure_windows: usize,
    pub max_cache_leases: usize,
    pub max_rebates: usize,
    pub max_redaction_budgets: usize,
    pub max_operator_summaries: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            mode: RuntimeMode::Devnet,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_broadcast_ms: DEFAULT_TARGET_BROADCAST_MS,
            max_broadcast_ms: DEFAULT_MAX_BROADCAST_MS,
            target_zero_copy_hit_bps: DEFAULT_TARGET_ZERO_COPY_HIT_BPS,
            max_backpressure_bps: DEFAULT_MAX_BACKPRESSURE_BPS,
            redaction_budget_bps: DEFAULT_REDACTION_BUDGET_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            diff_ttl_blocks: DEFAULT_DIFF_TTL_BLOCKS,
            hint_ttl_blocks: DEFAULT_HINT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            cache_lease_ttl_blocks: DEFAULT_CACHE_LEASE_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            max_lanes: DEFAULT_MAX_LANES,
            max_shard_fanouts: DEFAULT_MAX_SHARD_FANOUTS,
            max_diffs: DEFAULT_MAX_DIFFS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_witness_refs: DEFAULT_MAX_WITNESS_REFS,
            max_preconfirmation_hints: DEFAULT_MAX_PRECONFIRMATION_HINTS,
            max_backpressure_windows: DEFAULT_MAX_BACKPRESSURE_WINDOWS,
            max_cache_leases: DEFAULT_MAX_CACHE_LEASES,
            max_rebates: DEFAULT_MAX_REBATES,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            max_operator_summaries: DEFAULT_MAX_OPERATOR_SUMMARIES,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "mode": self.mode,
            "mode_label": self.mode.as_str(),
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_broadcast_ms": self.target_broadcast_ms,
            "max_broadcast_ms": self.max_broadcast_ms,
            "target_zero_copy_hit_bps": self.target_zero_copy_hit_bps,
            "max_backpressure_bps": self.max_backpressure_bps,
            "redaction_budget_bps": self.redaction_budget_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub lane_count: u64,
    pub shard_fanout_count: u64,
    pub diff_count: u64,
    pub live_diff_count: u64,
    pub pq_attestation_count: u64,
    pub accepted_attestation_count: u64,
    pub witness_ref_count: u64,
    pub preconfirmation_hint_count: u64,
    pub backpressure_window_count: u64,
    pub cache_lease_count: u64,
    pub active_cache_lease_count: u64,
    pub rebate_count: u64,
    pub redeemed_rebate_count: u64,
    pub redaction_budget_count: u64,
    pub operator_summary_count: u64,
    pub zero_copy_bytes_broadcast: u128,
    pub encrypted_witness_bytes: u128,
    pub sponsor_rebate_micro_units: u128,
    pub root_updates: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_count": self.lane_count,
            "shard_fanout_count": self.shard_fanout_count,
            "diff_count": self.diff_count,
            "live_diff_count": self.live_diff_count,
            "pq_attestation_count": self.pq_attestation_count,
            "accepted_attestation_count": self.accepted_attestation_count,
            "witness_ref_count": self.witness_ref_count,
            "preconfirmation_hint_count": self.preconfirmation_hint_count,
            "backpressure_window_count": self.backpressure_window_count,
            "cache_lease_count": self.cache_lease_count,
            "active_cache_lease_count": self.active_cache_lease_count,
            "rebate_count": self.rebate_count,
            "redeemed_rebate_count": self.redeemed_rebate_count,
            "redaction_budget_count": self.redaction_budget_count,
            "operator_summary_count": self.operator_summary_count,
            "zero_copy_bytes_broadcast": self.zero_copy_bytes_broadcast,
            "encrypted_witness_bytes": self.encrypted_witness_bytes,
            "sponsor_rebate_micro_units": self.sponsor_rebate_micro_units,
            "root_updates": self.root_updates,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub lane_root: String,
    pub shard_fanout_root: String,
    pub diff_root: String,
    pub pq_availability_root: String,
    pub witness_ref_root: String,
    pub preconfirmation_hint_root: String,
    pub backpressure_root: String,
    pub cache_lease_root: String,
    pub rebate_root: String,
    pub redaction_budget_root: String,
    pub public_summary_root: String,
    pub public_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "shard_fanout_root": self.shard_fanout_root,
            "diff_root": self.diff_root,
            "pq_availability_root": self.pq_availability_root,
            "witness_ref_root": self.witness_ref_root,
            "preconfirmation_hint_root": self.preconfirmation_hint_root,
            "backpressure_root": self.backpressure_root,
            "cache_lease_root": self.cache_lease_root,
            "rebate_root": self.rebate_root,
            "redaction_budget_root": self.redaction_budget_root,
            "public_summary_root": self.public_summary_root,
            "public_root": self.public_root,
            "state_root": self.state_root,
        })
    }
}

impl Default for Roots {
    fn default() -> Self {
        let empty = merkle_root("ZERO-COPY-BROADCAST-EMPTY", &[]);
        Self {
            config_root: empty.clone(),
            lane_root: empty.clone(),
            shard_fanout_root: empty.clone(),
            diff_root: empty.clone(),
            pq_availability_root: empty.clone(),
            witness_ref_root: empty.clone(),
            preconfirmation_hint_root: empty.clone(),
            backpressure_root: empty.clone(),
            cache_lease_root: empty.clone(),
            rebate_root: empty.clone(),
            redaction_budget_root: empty.clone(),
            public_summary_root: empty.clone(),
            public_root: empty.clone(),
            state_root: empty,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BroadcastLane {
    pub lane_id: String,
    pub lane_kind: BroadcastLaneKind,
    pub shard_id: String,
    pub status: LaneStatus,
    pub sequencer_commitment: String,
    pub lane_capacity_bytes: u64,
    pub inflight_bytes: u64,
    pub zero_copy_hit_bps: u64,
    pub backpressure_bps: u64,
    pub priority_weight: u64,
    pub current_epoch: u64,
}

impl BroadcastLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind,
            "lane_kind_label": self.lane_kind.as_str(),
            "shard_id": self.shard_id,
            "status": self.status,
            "status_label": self.status.as_str(),
            "sequencer_commitment": self.sequencer_commitment,
            "lane_capacity_bytes": self.lane_capacity_bytes,
            "inflight_bytes": self.inflight_bytes,
            "zero_copy_hit_bps": self.zero_copy_hit_bps,
            "backpressure_bps": self.backpressure_bps,
            "priority_weight": self.priority_weight,
            "current_epoch": self.current_epoch,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShardFanout {
    pub fanout_id: String,
    pub lane_id: String,
    pub source_shard_id: String,
    pub target_shard_ids: Vec<String>,
    pub fanout_committee_root: String,
    pub quorum_threshold: u16,
    pub acked_shards: BTreeSet<String>,
    pub fanout_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl ShardFanout {
    pub fn public_record(&self) -> Value {
        json!({
            "fanout_id": self.fanout_id,
            "lane_id": self.lane_id,
            "source_shard_id": self.source_shard_id,
            "target_shard_ids": self.target_shard_ids,
            "fanout_committee_root": self.fanout_committee_root,
            "quorum_threshold": self.quorum_threshold,
            "acked_shards": self.acked_shards,
            "fanout_root": self.fanout_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ZeroCopyStateDiff {
    pub diff_id: String,
    pub lane_id: String,
    pub fanout_id: String,
    pub status: DiffStatus,
    pub previous_state_root: String,
    pub post_state_root: String,
    pub state_diff_commitment_root: String,
    pub zero_copy_slice_root: String,
    pub encrypted_witness_ref_root: String,
    pub redacted_public_delta_root: String,
    pub payload_bytes: u64,
    pub zero_copy_bytes: u64,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl ZeroCopyStateDiff {
    pub fn public_record(&self) -> Value {
        json!({
            "diff_id": self.diff_id,
            "lane_id": self.lane_id,
            "fanout_id": self.fanout_id,
            "status": self.status,
            "status_label": self.status.as_str(),
            "previous_state_root": self.previous_state_root,
            "post_state_root": self.post_state_root,
            "state_diff_commitment_root": self.state_diff_commitment_root,
            "zero_copy_slice_root": self.zero_copy_slice_root,
            "encrypted_witness_ref_root": self.encrypted_witness_ref_root,
            "redacted_public_delta_root": self.redacted_public_delta_root,
            "payload_bytes": self.payload_bytes,
            "zero_copy_bytes": self.zero_copy_bytes,
            "privacy_set_size": self.privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAvailabilityAttestation {
    pub attestation_id: String,
    pub diff_id: String,
    pub shard_id: String,
    pub attestor_commitment: String,
    pub availability_root: String,
    pub signature_root: String,
    pub verdict: AttestationVerdict,
    pub observed_latency_ms: u64,
    pub pq_security_bits: u16,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl PqAvailabilityAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "diff_id": self.diff_id,
            "shard_id": self.shard_id,
            "attestor_commitment": self.attestor_commitment,
            "availability_root": self.availability_root,
            "signature_root": self.signature_root,
            "verdict": self.verdict,
            "verdict_label": self.verdict.as_str(),
            "observed_latency_ms": self.observed_latency_ms,
            "pq_security_bits": self.pq_security_bits,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedWitnessReference {
    pub witness_ref_id: String,
    pub diff_id: String,
    pub lane_id: String,
    pub ciphertext_root: String,
    pub access_policy_root: String,
    pub key_epoch: u64,
    pub witness_bytes: u64,
    pub cache_hint_root: String,
    pub disclosed_to_committee_root: String,
}

impl EncryptedWitnessReference {
    pub fn public_record(&self) -> Value {
        json!({
            "witness_ref_id": self.witness_ref_id,
            "diff_id": self.diff_id,
            "lane_id": self.lane_id,
            "ciphertext_root": self.ciphertext_root,
            "access_policy_root": self.access_policy_root,
            "key_epoch": self.key_epoch,
            "witness_bytes": self.witness_bytes,
            "cache_hint_root": self.cache_hint_root,
            "disclosed_to_committee_root": self.disclosed_to_committee_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreconfirmationHint {
    pub hint_id: String,
    pub diff_id: String,
    pub lane_id: String,
    pub hint_kind: PreconfirmationHintKind,
    pub preconfirmation_root: String,
    pub confidence_bps: u64,
    pub max_latency_ms: u64,
    pub fee_hint_micro_units: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl PreconfirmationHint {
    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "diff_id": self.diff_id,
            "lane_id": self.lane_id,
            "hint_kind": self.hint_kind,
            "hint_kind_label": self.hint_kind.as_str(),
            "preconfirmation_root": self.preconfirmation_root,
            "confidence_bps": self.confidence_bps,
            "max_latency_ms": self.max_latency_ms,
            "fee_hint_micro_units": self.fee_hint_micro_units,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackpressureWindow {
    pub window_id: String,
    pub lane_id: String,
    pub shard_id: String,
    pub queue_depth_bytes: u64,
    pub shed_bps: u64,
    pub max_admit_bytes: u64,
    pub reason_code: String,
    pub active: bool,
    pub opened_at_height: u64,
}

impl BackpressureWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "lane_id": self.lane_id,
            "shard_id": self.shard_id,
            "queue_depth_bytes": self.queue_depth_bytes,
            "shed_bps": self.shed_bps,
            "max_admit_bytes": self.max_admit_bytes,
            "reason_code": self.reason_code,
            "active": self.active,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CacheLease {
    pub lease_id: String,
    pub diff_id: String,
    pub lane_id: String,
    pub cache_node_commitment: String,
    pub lease_root: String,
    pub lease_bytes: u64,
    pub price_micro_units: u64,
    pub active: bool,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl CacheLease {
    pub fn public_record(&self) -> Value {
        json!({
            "lease_id": self.lease_id,
            "diff_id": self.diff_id,
            "lane_id": self.lane_id,
            "cache_node_commitment": self.cache_node_commitment,
            "lease_root": self.lease_root,
            "lease_bytes": self.lease_bytes,
            "price_micro_units": self.price_micro_units,
            "active": self.active,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeSponsorRebate {
    pub rebate_id: String,
    pub diff_id: String,
    pub sponsor_commitment: String,
    pub user_commitment: String,
    pub rebate_root: String,
    pub rebate_bps: u64,
    pub rebate_micro_units: u64,
    pub redeemed: bool,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeSponsorRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "diff_id": self.diff_id,
            "sponsor_commitment": self.sponsor_commitment,
            "user_commitment": self.user_commitment,
            "rebate_root": self.rebate_root,
            "rebate_bps": self.rebate_bps,
            "rebate_micro_units": self.rebate_micro_units,
            "redeemed": self.redeemed,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub diff_id: String,
    pub lane_id: String,
    pub redaction_root: String,
    pub budget_bps: u64,
    pub spent_bps: u64,
    pub hidden_field_count: u32,
    pub public_field_count: u32,
    pub min_privacy_set_size: u64,
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "diff_id": self.diff_id,
            "lane_id": self.lane_id,
            "redaction_root": self.redaction_root,
            "budget_bps": self.budget_bps,
            "spent_bps": self.spent_bps,
            "hidden_field_count": self.hidden_field_count,
            "public_field_count": self.public_field_count,
            "min_privacy_set_size": self.min_privacy_set_size,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSafeSummary {
    pub summary_id: String,
    pub lane_id: String,
    pub shard_id: String,
    pub epoch: u64,
    pub diff_count: u64,
    pub live_diff_count: u64,
    pub average_latency_ms: u64,
    pub backpressure_bps: u64,
    pub zero_copy_hit_bps: u64,
    pub public_root: String,
}

impl OperatorSafeSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "lane_id": self.lane_id,
            "shard_id": self.shard_id,
            "epoch": self.epoch,
            "diff_count": self.diff_count,
            "live_diff_count": self.live_diff_count,
            "average_latency_ms": self.average_latency_ms,
            "backpressure_bps": self.backpressure_bps,
            "zero_copy_hit_bps": self.zero_copy_hit_bps,
            "public_root": self.public_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BroadcastRequest {
    pub lane_id: String,
    pub fanout_id: String,
    pub previous_state_root: String,
    pub post_state_root: String,
    pub state_diff_commitment_root: String,
    pub zero_copy_slice_root: String,
    pub encrypted_witness_ref_root: String,
    pub redacted_public_delta_root: String,
    pub payload_bytes: u64,
    pub zero_copy_bytes: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub lanes: BTreeMap<String, BroadcastLane>,
    pub shard_fanouts: BTreeMap<String, ShardFanout>,
    pub diffs: BTreeMap<String, ZeroCopyStateDiff>,
    pub pq_attestations: BTreeMap<String, PqAvailabilityAttestation>,
    pub witness_refs: BTreeMap<String, EncryptedWitnessReference>,
    pub preconfirmation_hints: BTreeMap<String, PreconfirmationHint>,
    pub backpressure_windows: BTreeMap<String, BackpressureWindow>,
    pub cache_leases: BTreeMap<String, CacheLease>,
    pub rebates: BTreeMap<String, LowFeeSponsorRebate>,
    pub redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSafeSummary>,
}

impl State {
    pub fn new(config: Config, l2_height: u64, monero_height: u64, epoch: u64) -> Result<Self> {
        ensure!(
            config.min_pq_security_bits >= 128,
            "min PQ security too low: {}",
            config.min_pq_security_bits
        );
        ensure!(
            config.redaction_budget_bps <= MAX_BPS,
            "redaction budget exceeds MAX_BPS"
        );
        ensure!(
            config.low_fee_rebate_bps <= config.sponsor_cover_bps,
            "rebate bps cannot exceed sponsor cover bps"
        );
        let mut state = Self {
            config,
            l2_height,
            monero_height,
            epoch,
            counters: Counters::default(),
            roots: Roots::default(),
            lanes: BTreeMap::new(),
            shard_fanouts: BTreeMap::new(),
            diffs: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            witness_refs: BTreeMap::new(),
            preconfirmation_hints: BTreeMap::new(),
            backpressure_windows: BTreeMap::new(),
            cache_leases: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn register_lane(&mut self, lane: BroadcastLane) -> Result<()> {
        ensure!(
            self.lanes.len() < self.config.max_lanes || self.lanes.contains_key(&lane.lane_id),
            "lane capacity exhausted"
        );
        ensure!(
            lane.backpressure_bps <= self.config.max_backpressure_bps,
            "lane backpressure exceeds configured maximum"
        );
        self.lanes.insert(lane.lane_id.clone(), lane);
        self.refresh_roots();
        Ok(())
    }

    pub fn register_shard_fanout(&mut self, fanout: ShardFanout) -> Result<()> {
        ensure!(
            self.shard_fanouts.len() < self.config.max_shard_fanouts
                || self.shard_fanouts.contains_key(&fanout.fanout_id),
            "shard fanout capacity exhausted"
        );
        ensure!(
            self.lanes.contains_key(&fanout.lane_id),
            "unknown lane for fanout {}",
            fanout.lane_id
        );
        ensure!(
            usize::from(fanout.quorum_threshold) <= fanout.target_shard_ids.len(),
            "fanout quorum exceeds target shard count"
        );
        self.shard_fanouts.insert(fanout.fanout_id.clone(), fanout);
        self.refresh_roots();
        Ok(())
    }

    pub fn broadcast_diff(&mut self, request: BroadcastRequest) -> Result<String> {
        ensure!(
            self.diffs.len() < self.config.max_diffs,
            "state diff capacity exhausted"
        );
        let lane = self
            .lanes
            .get_mut(&request.lane_id)
            .ok_or_else(|| format!("unknown lane {}", request.lane_id))?;
        ensure!(
            lane.status.accepts_broadcasts(),
            "lane {} does not accept broadcasts",
            request.lane_id
        );
        ensure!(
            self.shard_fanouts.contains_key(&request.fanout_id),
            "unknown fanout {}",
            request.fanout_id
        );
        ensure!(
            request.zero_copy_bytes <= request.payload_bytes,
            "zero-copy bytes exceed payload bytes"
        );
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set too small: {}",
            request.privacy_set_size
        );
        ensure!(
            lane.inflight_bytes.saturating_add(request.payload_bytes) <= lane.lane_capacity_bytes,
            "lane capacity exceeded"
        );

        let diff_id = state_diff_id(
            &request.lane_id,
            &request.fanout_id,
            &request.previous_state_root,
            &request.post_state_root,
            self.l2_height,
        );
        let diff = ZeroCopyStateDiff {
            diff_id: diff_id.clone(),
            lane_id: request.lane_id.clone(),
            fanout_id: request.fanout_id,
            status: DiffStatus::Broadcast,
            previous_state_root: request.previous_state_root,
            post_state_root: request.post_state_root,
            state_diff_commitment_root: request.state_diff_commitment_root,
            zero_copy_slice_root: request.zero_copy_slice_root,
            encrypted_witness_ref_root: request.encrypted_witness_ref_root,
            redacted_public_delta_root: request.redacted_public_delta_root,
            payload_bytes: request.payload_bytes,
            zero_copy_bytes: request.zero_copy_bytes,
            privacy_set_size: request.privacy_set_size,
            opened_at_height: self.l2_height,
            expires_at_height: self.l2_height + self.config.diff_ttl_blocks,
        };
        lane.inflight_bytes = lane.inflight_bytes.saturating_add(diff.payload_bytes);
        self.diffs.insert(diff_id.clone(), diff);
        self.refresh_roots();
        Ok(diff_id)
    }

    pub fn add_pq_availability_attestation(
        &mut self,
        attestation: PqAvailabilityAttestation,
    ) -> Result<()> {
        ensure!(
            self.pq_attestations.len() < self.config.max_attestations
                || self
                    .pq_attestations
                    .contains_key(&attestation.attestation_id),
            "PQ attestation capacity exhausted"
        );
        ensure!(
            self.diffs.contains_key(&attestation.diff_id),
            "unknown diff for attestation {}",
            attestation.diff_id
        );
        ensure!(
            attestation.pq_security_bits >= self.config.min_pq_security_bits,
            "attestation PQ security below configured minimum"
        );
        if let Some(diff) = self.diffs.get_mut(&attestation.diff_id) {
            if attestation.verdict.accepted() && diff.status.live() {
                diff.status = DiffStatus::AvailabilityAttested;
            }
        }
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_encrypted_witness_ref(
        &mut self,
        witness_ref: EncryptedWitnessReference,
    ) -> Result<()> {
        ensure!(
            self.witness_refs.len() < self.config.max_witness_refs
                || self.witness_refs.contains_key(&witness_ref.witness_ref_id),
            "witness reference capacity exhausted"
        );
        ensure!(
            self.diffs.contains_key(&witness_ref.diff_id),
            "unknown diff for witness reference {}",
            witness_ref.diff_id
        );
        self.witness_refs
            .insert(witness_ref.witness_ref_id.clone(), witness_ref);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_preconfirmation_hint(&mut self, hint: PreconfirmationHint) -> Result<()> {
        ensure!(
            self.preconfirmation_hints.len() < self.config.max_preconfirmation_hints
                || self.preconfirmation_hints.contains_key(&hint.hint_id),
            "preconfirmation hint capacity exhausted"
        );
        ensure!(
            hint.confidence_bps <= MAX_BPS,
            "preconfirmation confidence exceeds MAX_BPS"
        );
        if let Some(diff) = self.diffs.get_mut(&hint.diff_id) {
            if hint.confidence_bps >= 8_000 && diff.status.live() {
                diff.status = DiffStatus::Preconfirmed;
            }
        }
        self.preconfirmation_hints
            .insert(hint.hint_id.clone(), hint);
        self.refresh_roots();
        Ok(())
    }

    pub fn update_backpressure(&mut self, window: BackpressureWindow) -> Result<()> {
        ensure!(
            self.backpressure_windows.len() < self.config.max_backpressure_windows
                || self.backpressure_windows.contains_key(&window.window_id),
            "backpressure window capacity exhausted"
        );
        ensure!(
            window.shed_bps <= self.config.max_backpressure_bps,
            "backpressure shed bps exceeds configured maximum"
        );
        if let Some(lane) = self.lanes.get_mut(&window.lane_id) {
            lane.backpressure_bps = window.shed_bps;
            lane.status = if window.active && window.shed_bps > 0 {
                LaneStatus::Backpressured
            } else {
                LaneStatus::Open
            };
        }
        self.backpressure_windows
            .insert(window.window_id.clone(), window);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_cache_lease(&mut self, lease: CacheLease) -> Result<()> {
        ensure!(
            self.cache_leases.len() < self.config.max_cache_leases
                || self.cache_leases.contains_key(&lease.lease_id),
            "cache lease capacity exhausted"
        );
        if let Some(diff) = self.diffs.get_mut(&lease.diff_id) {
            if lease.active && diff.status.live() {
                diff.status = DiffStatus::Leased;
            }
        }
        self.cache_leases.insert(lease.lease_id.clone(), lease);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_low_fee_rebate(&mut self, rebate: LowFeeSponsorRebate) -> Result<()> {
        ensure!(
            self.rebates.len() < self.config.max_rebates
                || self.rebates.contains_key(&rebate.rebate_id),
            "rebate capacity exhausted"
        );
        ensure!(
            rebate.rebate_bps <= self.config.low_fee_rebate_bps,
            "rebate bps exceeds configured maximum"
        );
        self.rebates.insert(rebate.rebate_id.clone(), rebate);
        self.refresh_roots();
        Ok(())
    }

    pub fn redeem_rebate(&mut self, rebate_id: &str) -> Result<()> {
        let rebate = self
            .rebates
            .get_mut(rebate_id)
            .ok_or_else(|| format!("unknown rebate {rebate_id}"))?;
        ensure!(!rebate.redeemed, "rebate already redeemed");
        ensure!(
            self.l2_height <= rebate.expires_at_height,
            "rebate expired at {}",
            rebate.expires_at_height
        );
        rebate.redeemed = true;
        if let Some(diff) = self.diffs.get_mut(&rebate.diff_id) {
            if diff.status.live() {
                diff.status = DiffStatus::Rebated;
            }
        }
        self.refresh_roots();
        Ok(())
    }

    pub fn add_redaction_budget(&mut self, budget: PrivacyRedactionBudget) -> Result<()> {
        ensure!(
            self.redaction_budgets.len() < self.config.max_redaction_budgets
                || self.redaction_budgets.contains_key(&budget.budget_id),
            "redaction budget capacity exhausted"
        );
        ensure!(
            budget.budget_bps <= self.config.redaction_budget_bps,
            "redaction budget exceeds configured maximum"
        );
        ensure!(
            budget.spent_bps <= budget.budget_bps,
            "redaction spent bps exceeds budget"
        );
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_operator_summary(&mut self, summary: OperatorSafeSummary) -> Result<()> {
        ensure!(
            self.operator_summaries.len() < self.config.max_operator_summaries
                || self.operator_summaries.contains_key(&summary.summary_id),
            "operator summary capacity exhausted"
        );
        self.operator_summaries
            .insert(summary.summary_id.clone(), summary);
        self.refresh_roots();
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "zero_copy_diff_suite": ZERO_COPY_DIFF_SUITE,
            "pq_availability_suite": PQ_AVAILABILITY_SUITE,
            "encrypted_witness_ref_suite": ENCRYPTED_WITNESS_REF_SUITE,
            "preconfirmation_hint_suite": PRECONFIRMATION_HINT_SUITE,
            "backpressure_suite": BACKPRESSURE_SUITE,
            "cache_lease_suite": CACHE_LEASE_SUITE,
            "low_fee_rebate_suite": LOW_FEE_REBATE_SUITE,
            "privacy_redaction_suite": PRIVACY_REDACTION_SUITE,
            "operator_summary_suite": OPERATOR_SUMMARY_SUITE,
            "chain_id": CHAIN_ID,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn refresh_roots(&mut self) {
        self.counters = self.derive_counters();
        self.roots.config_root =
            payload_root("ZERO-COPY-BROADCAST-CONFIG", &self.config.public_record());
        self.roots.lane_root = map_root(
            "ZERO-COPY-BROADCAST-LANES",
            &self.lanes,
            BroadcastLane::public_record,
        );
        self.roots.shard_fanout_root = map_root(
            "ZERO-COPY-BROADCAST-SHARD-FANOUTS",
            &self.shard_fanouts,
            ShardFanout::public_record,
        );
        self.roots.diff_root = map_root(
            "ZERO-COPY-BROADCAST-DIFFS",
            &self.diffs,
            ZeroCopyStateDiff::public_record,
        );
        self.roots.pq_availability_root = map_root(
            "ZERO-COPY-BROADCAST-PQ-AVAILABILITY",
            &self.pq_attestations,
            PqAvailabilityAttestation::public_record,
        );
        self.roots.witness_ref_root = map_root(
            "ZERO-COPY-BROADCAST-WITNESS-REFS",
            &self.witness_refs,
            EncryptedWitnessReference::public_record,
        );
        self.roots.preconfirmation_hint_root = map_root(
            "ZERO-COPY-BROADCAST-PRECONFIRMATION-HINTS",
            &self.preconfirmation_hints,
            PreconfirmationHint::public_record,
        );
        self.roots.backpressure_root = map_root(
            "ZERO-COPY-BROADCAST-BACKPRESSURE",
            &self.backpressure_windows,
            BackpressureWindow::public_record,
        );
        self.roots.cache_lease_root = map_root(
            "ZERO-COPY-BROADCAST-CACHE-LEASES",
            &self.cache_leases,
            CacheLease::public_record,
        );
        self.roots.rebate_root = map_root(
            "ZERO-COPY-BROADCAST-REBATES",
            &self.rebates,
            LowFeeSponsorRebate::public_record,
        );
        self.roots.redaction_budget_root = map_root(
            "ZERO-COPY-BROADCAST-REDACTION-BUDGETS",
            &self.redaction_budgets,
            PrivacyRedactionBudget::public_record,
        );
        self.roots.public_summary_root = map_root(
            "ZERO-COPY-BROADCAST-OPERATOR-SUMMARIES",
            &self.operator_summaries,
            OperatorSafeSummary::public_record,
        );
        self.roots.public_root = payload_root(
            "ZERO-COPY-BROADCAST-PUBLIC-ROOTS",
            &self.roots_public_payload(),
        );
        self.counters.root_updates = self.counters.root_updates.saturating_add(1);
        self.roots.state_root = self.state_root();
    }

    pub fn state_root(&self) -> String {
        let payload = json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "config_root": self.roots.config_root,
            "lane_root": self.roots.lane_root,
            "shard_fanout_root": self.roots.shard_fanout_root,
            "diff_root": self.roots.diff_root,
            "pq_availability_root": self.roots.pq_availability_root,
            "witness_ref_root": self.roots.witness_ref_root,
            "preconfirmation_hint_root": self.roots.preconfirmation_hint_root,
            "backpressure_root": self.roots.backpressure_root,
            "cache_lease_root": self.roots.cache_lease_root,
            "rebate_root": self.roots.rebate_root,
            "redaction_budget_root": self.roots.redaction_budget_root,
            "public_summary_root": self.roots.public_summary_root,
            "public_root": self.roots.public_root,
        });
        payload_root("ZERO-COPY-BROADCAST-STATE-ROOT", &payload)
    }

    fn derive_counters(&self) -> Counters {
        Counters {
            lane_count: self.lanes.len() as u64,
            shard_fanout_count: self.shard_fanouts.len() as u64,
            diff_count: self.diffs.len() as u64,
            live_diff_count: self
                .diffs
                .values()
                .filter(|diff| diff.status.live())
                .count() as u64,
            pq_attestation_count: self.pq_attestations.len() as u64,
            accepted_attestation_count: self
                .pq_attestations
                .values()
                .filter(|attestation| attestation.verdict.accepted())
                .count() as u64,
            witness_ref_count: self.witness_refs.len() as u64,
            preconfirmation_hint_count: self.preconfirmation_hints.len() as u64,
            backpressure_window_count: self.backpressure_windows.len() as u64,
            cache_lease_count: self.cache_leases.len() as u64,
            active_cache_lease_count: self
                .cache_leases
                .values()
                .filter(|lease| lease.active)
                .count() as u64,
            rebate_count: self.rebates.len() as u64,
            redeemed_rebate_count: self
                .rebates
                .values()
                .filter(|rebate| rebate.redeemed)
                .count() as u64,
            redaction_budget_count: self.redaction_budgets.len() as u64,
            operator_summary_count: self.operator_summaries.len() as u64,
            zero_copy_bytes_broadcast: self
                .diffs
                .values()
                .map(|diff| u128::from(diff.zero_copy_bytes))
                .sum(),
            encrypted_witness_bytes: self
                .witness_refs
                .values()
                .map(|witness_ref| u128::from(witness_ref.witness_bytes))
                .sum(),
            sponsor_rebate_micro_units: self
                .rebates
                .values()
                .map(|rebate| u128::from(rebate.rebate_micro_units))
                .sum(),
            root_updates: self.counters.root_updates,
        }
    }

    fn roots_public_payload(&self) -> Value {
        json!({
            "config_root": self.roots.config_root,
            "lane_root": self.roots.lane_root,
            "shard_fanout_root": self.roots.shard_fanout_root,
            "diff_root": self.roots.diff_root,
            "pq_availability_root": self.roots.pq_availability_root,
            "witness_ref_root": self.roots.witness_ref_root,
            "preconfirmation_hint_root": self.roots.preconfirmation_hint_root,
            "backpressure_root": self.roots.backpressure_root,
            "cache_lease_root": self.roots.cache_lease_root,
            "rebate_root": self.roots.rebate_root,
            "redaction_budget_root": self.roots.redaction_budget_root,
            "public_summary_root": self.roots.public_summary_root,
        })
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new(
            Config::devnet(),
            DEVNET_L2_HEIGHT,
            DEVNET_MONERO_HEIGHT,
            DEVNET_EPOCH,
        )
        .expect("devnet config is valid")
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let lane_a = sample_lane(
        "lane-zero-copy-contract-a",
        BroadcastLaneKind::ContractStorageDelta,
        "shard-0007",
        LaneStatus::Hot,
        96 * 1024 * 1024,
        9_520,
        120,
    );
    let lane_b = sample_lane(
        "lane-zero-copy-monero-exit-a",
        BroadcastLaneKind::MoneroBridgeOutputDelta,
        "shard-0011",
        LaneStatus::Open,
        64 * 1024 * 1024,
        9_440,
        80,
    );
    state.register_lane(lane_a).expect("sample lane A");
    state.register_lane(lane_b).expect("sample lane B");

    let fanout = sample_fanout(
        "fanout-contract-hot-a",
        "lane-zero-copy-contract-a",
        "shard-0007",
        &["shard-0008", "shard-0009", "shard-0010"],
        DEVNET_L2_HEIGHT,
    );
    state
        .register_shard_fanout(fanout)
        .expect("sample shard fanout");

    let request = BroadcastRequest {
        lane_id: "lane-zero-copy-contract-a".to_string(),
        fanout_id: "fanout-contract-hot-a".to_string(),
        previous_state_root: sample_root("previous-state", "contract-a"),
        post_state_root: sample_root("post-state", "contract-a"),
        state_diff_commitment_root: sample_root("state-diff-commitment", "contract-a"),
        zero_copy_slice_root: sample_root("zero-copy-slice", "contract-a"),
        encrypted_witness_ref_root: sample_root("encrypted-witness-ref", "contract-a"),
        redacted_public_delta_root: sample_root("redacted-public-delta", "contract-a"),
        payload_bytes: 3_145_728,
        zero_copy_bytes: 2_949_120,
        privacy_set_size: 524_288,
    };
    let diff_id = state.broadcast_diff(request).expect("sample state diff");

    state
        .add_encrypted_witness_ref(sample_witness_ref(
            "witness-ref-contract-a",
            &diff_id,
            "lane-zero-copy-contract-a",
            DEVNET_EPOCH,
        ))
        .expect("sample witness ref");
    state
        .add_pq_availability_attestation(sample_attestation(
            "attestation-contract-a-shard-0008",
            &diff_id,
            "shard-0008",
            AttestationVerdict::Available,
            DEVNET_L2_HEIGHT,
        ))
        .expect("sample attestation");
    state
        .add_preconfirmation_hint(sample_hint(
            "hint-contract-a-write-set",
            &diff_id,
            "lane-zero-copy-contract-a",
            PreconfirmationHintKind::WriteSetReady,
            DEVNET_L2_HEIGHT,
        ))
        .expect("sample hint");
    state
        .update_backpressure(sample_backpressure(
            "bp-contract-a",
            "lane-zero-copy-contract-a",
            "shard-0007",
            DEVNET_L2_HEIGHT,
        ))
        .expect("sample backpressure");
    state
        .add_cache_lease(sample_cache_lease(
            "lease-contract-a",
            &diff_id,
            "lane-zero-copy-contract-a",
            DEVNET_L2_HEIGHT,
        ))
        .expect("sample cache lease");
    state
        .add_low_fee_rebate(sample_rebate(
            "rebate-contract-a",
            &diff_id,
            DEVNET_L2_HEIGHT,
        ))
        .expect("sample rebate");
    state
        .add_redaction_budget(sample_redaction_budget(
            "budget-contract-a",
            &diff_id,
            "lane-zero-copy-contract-a",
        ))
        .expect("sample redaction budget");
    state
        .add_operator_summary(sample_operator_summary(
            "summary-contract-a",
            "lane-zero-copy-contract-a",
            "shard-0007",
            DEVNET_EPOCH,
            &state.roots.public_root,
        ))
        .expect("sample operator summary");
    state.refresh_roots();
    state
}

pub fn demo() -> Value {
    devnet().public_record()
}

pub fn devnet_state_root() -> String {
    devnet().state_root()
}

pub fn devnet_public_record() -> Value {
    devnet().public_record()
}

pub fn state_diff_id(
    lane_id: &str,
    fanout_id: &str,
    previous_state_root: &str,
    post_state_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "ZERO-COPY-BROADCAST-STATE-DIFF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(ZERO_COPY_DIFF_SUITE),
            HashPart::Str(lane_id),
            HashPart::Str(fanout_id),
            HashPart::Str(previous_state_root),
            HashPart::Str(post_state_root),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, value: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(value)], 32)
}

pub fn map_root<T, F>(domain: &str, values: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let records = values.values().map(public_record).collect::<Vec<_>>();
    merkle_root(domain, &records)
}

pub fn sample_root(domain: &str, label: &str) -> String {
    domain_hash(
        "ZERO-COPY-BROADCAST-SAMPLE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Str(label),
        ],
        32,
    )
}

fn sample_lane(
    lane_id: &str,
    lane_kind: BroadcastLaneKind,
    shard_id: &str,
    status: LaneStatus,
    lane_capacity_bytes: u64,
    zero_copy_hit_bps: u64,
    backpressure_bps: u64,
) -> BroadcastLane {
    BroadcastLane {
        lane_id: lane_id.to_string(),
        lane_kind,
        shard_id: shard_id.to_string(),
        status,
        sequencer_commitment: sample_root("sequencer", lane_id),
        lane_capacity_bytes,
        inflight_bytes: 0,
        zero_copy_hit_bps,
        backpressure_bps,
        priority_weight: lane_kind.priority_weight(),
        current_epoch: DEVNET_EPOCH,
    }
}

fn sample_fanout(
    fanout_id: &str,
    lane_id: &str,
    source_shard_id: &str,
    target_shard_ids: &[&str],
    opened_at_height: u64,
) -> ShardFanout {
    let targets = target_shard_ids
        .iter()
        .map(|target| (*target).to_string())
        .collect::<Vec<_>>();
    ShardFanout {
        fanout_id: fanout_id.to_string(),
        lane_id: lane_id.to_string(),
        source_shard_id: source_shard_id.to_string(),
        target_shard_ids: targets,
        fanout_committee_root: sample_root("fanout-committee", fanout_id),
        quorum_threshold: 2,
        acked_shards: BTreeSet::from(["shard-0008".to_string(), "shard-0009".to_string()]),
        fanout_root: sample_root("fanout", fanout_id),
        opened_at_height,
        expires_at_height: opened_at_height + DEFAULT_DIFF_TTL_BLOCKS,
    }
}

fn sample_attestation(
    attestation_id: &str,
    diff_id: &str,
    shard_id: &str,
    verdict: AttestationVerdict,
    issued_at_height: u64,
) -> PqAvailabilityAttestation {
    PqAvailabilityAttestation {
        attestation_id: attestation_id.to_string(),
        diff_id: diff_id.to_string(),
        shard_id: shard_id.to_string(),
        attestor_commitment: sample_root("attestor", attestation_id),
        availability_root: sample_root("availability", diff_id),
        signature_root: sample_root("pq-signature", attestation_id),
        verdict,
        observed_latency_ms: 9,
        pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        issued_at_height,
        expires_at_height: issued_at_height + DEFAULT_ATTESTATION_TTL_BLOCKS,
    }
}

fn sample_witness_ref(
    witness_ref_id: &str,
    diff_id: &str,
    lane_id: &str,
    key_epoch: u64,
) -> EncryptedWitnessReference {
    EncryptedWitnessReference {
        witness_ref_id: witness_ref_id.to_string(),
        diff_id: diff_id.to_string(),
        lane_id: lane_id.to_string(),
        ciphertext_root: sample_root("witness-ciphertext", witness_ref_id),
        access_policy_root: sample_root("witness-access-policy", lane_id),
        key_epoch,
        witness_bytes: 1_048_576,
        cache_hint_root: sample_root("witness-cache-hint", witness_ref_id),
        disclosed_to_committee_root: sample_root("committee-disclosure", witness_ref_id),
    }
}

fn sample_hint(
    hint_id: &str,
    diff_id: &str,
    lane_id: &str,
    hint_kind: PreconfirmationHintKind,
    issued_at_height: u64,
) -> PreconfirmationHint {
    PreconfirmationHint {
        hint_id: hint_id.to_string(),
        diff_id: diff_id.to_string(),
        lane_id: lane_id.to_string(),
        hint_kind,
        preconfirmation_root: sample_root("preconfirmation", hint_id),
        confidence_bps: 8_900,
        max_latency_ms: DEFAULT_TARGET_BROADCAST_MS,
        fee_hint_micro_units: 42,
        issued_at_height,
        expires_at_height: issued_at_height + DEFAULT_HINT_TTL_BLOCKS,
    }
}

fn sample_backpressure(
    window_id: &str,
    lane_id: &str,
    shard_id: &str,
    opened_at_height: u64,
) -> BackpressureWindow {
    BackpressureWindow {
        window_id: window_id.to_string(),
        lane_id: lane_id.to_string(),
        shard_id: shard_id.to_string(),
        queue_depth_bytes: 7_340_032,
        shed_bps: 240,
        max_admit_bytes: 16 * 1024 * 1024,
        reason_code: "hot-contract-delta-burst".to_string(),
        active: true,
        opened_at_height,
    }
}

fn sample_cache_lease(
    lease_id: &str,
    diff_id: &str,
    lane_id: &str,
    opened_at_height: u64,
) -> CacheLease {
    CacheLease {
        lease_id: lease_id.to_string(),
        diff_id: diff_id.to_string(),
        lane_id: lane_id.to_string(),
        cache_node_commitment: sample_root("cache-node", lease_id),
        lease_root: sample_root("cache-lease", lease_id),
        lease_bytes: 2_949_120,
        price_micro_units: 19,
        active: true,
        opened_at_height,
        expires_at_height: opened_at_height + DEFAULT_CACHE_LEASE_TTL_BLOCKS,
    }
}

fn sample_rebate(rebate_id: &str, diff_id: &str, issued_at_height: u64) -> LowFeeSponsorRebate {
    LowFeeSponsorRebate {
        rebate_id: rebate_id.to_string(),
        diff_id: diff_id.to_string(),
        sponsor_commitment: sample_root("sponsor", rebate_id),
        user_commitment: sample_root("user", rebate_id),
        rebate_root: sample_root("rebate", rebate_id),
        rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
        rebate_micro_units: 7,
        redeemed: false,
        issued_at_height,
        expires_at_height: issued_at_height + DEFAULT_REBATE_TTL_BLOCKS,
    }
}

fn sample_redaction_budget(
    budget_id: &str,
    diff_id: &str,
    lane_id: &str,
) -> PrivacyRedactionBudget {
    PrivacyRedactionBudget {
        budget_id: budget_id.to_string(),
        diff_id: diff_id.to_string(),
        lane_id: lane_id.to_string(),
        redaction_root: sample_root("redaction-budget", budget_id),
        budget_bps: DEFAULT_REDACTION_BUDGET_BPS,
        spent_bps: 220,
        hidden_field_count: 17,
        public_field_count: 9,
        min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
    }
}

fn sample_operator_summary(
    summary_id: &str,
    lane_id: &str,
    shard_id: &str,
    epoch: u64,
    public_root: &str,
) -> OperatorSafeSummary {
    OperatorSafeSummary {
        summary_id: summary_id.to_string(),
        lane_id: lane_id.to_string(),
        shard_id: shard_id.to_string(),
        epoch,
        diff_count: 1,
        live_diff_count: 1,
        average_latency_ms: 9,
        backpressure_bps: 240,
        zero_copy_hit_bps: 9_520,
        public_root: public_root.to_string(),
    }
}
