use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialParallelStateWitnessPrefetchMeshRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_STATE_WITNESS_PREFETCH_MESH_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-parallel-state-witness-prefetch-mesh-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_STATE_WITNESS_PREFETCH_MESH_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-parallel-state-witness-prefetch-mesh-v1";
pub const PQ_HINT_ENVELOPE_SUITE: &str =
    "ML-KEM-1024+Kyber-hybrid-confidential-state-witness-hint-envelope-v1";
pub const WITNESS_SHARD_COMMITMENT_SUITE: &str =
    "nova-pq-confidential-parallel-state-witness-shard-commitment-v1";
pub const CACHE_LEASE_SUITE: &str = "low-latency-confidential-state-witness-cache-lease-v1";
pub const INVALIDATION_FENCE_SUITE: &str =
    "monero-l2-nullifier-viewtag-contract-state-invalidation-fence-v1";
pub const LOW_FEE_REBATE_SUITE: &str =
    "low-fee-confidential-parallel-state-witness-prefetch-rebate-credit-v1";
pub const REDACTION_BUDGET_SUITE: &str =
    "selective-disclosure-redaction-budget-parallel-state-witness-prefetch-v1";
pub const OPERATOR_SUMMARY_SUITE: &str =
    "redacted-operator-parallel-state-witness-prefetch-mesh-summary-v1";
pub const DEVNET_L2_HEIGHT: u64 = 3_120_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_760_000;
pub const DEVNET_EPOCH: u64 = 12_288;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_REBATE_ASSET_ID: &str = "state-witness-prefetch-credit-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_TARGET_PREFETCH_MS: u64 = 42;
pub const DEFAULT_MAX_PREFETCH_MS: u64 = 180;
pub const DEFAULT_TARGET_MESH_FANOUT: u16 = 6;
pub const DEFAULT_MAX_MESH_FANOUT: u16 = 16;
pub const DEFAULT_SLOT_WIDTH_MS: u64 = 25;
pub const DEFAULT_CACHE_LEASE_TTL_SLOTS: u64 = 48;
pub const DEFAULT_HINT_TTL_SLOTS: u64 = 32;
pub const DEFAULT_ATTESTATION_TTL_SLOTS: u64 = 64;
pub const DEFAULT_FENCE_TTL_SLOTS: u64 = 256;
pub const DEFAULT_REDACTION_TTL_SLOTS: u64 = 512;
pub const DEFAULT_QUORUM_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_SUPERMAJORITY_WEIGHT_BPS: u64 = 8_000;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 4;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 18;
pub const DEFAULT_OPERATOR_FEE_BPS: u64 = 1;
pub const DEFAULT_MIN_LANE_BOND_MICRO_UNITS: u64 = 35_000_000;
pub const DEFAULT_MIN_SHARD_BOND_MICRO_UNITS: u64 = 8_000_000;
pub const DEFAULT_SLASH_BPS: u64 = 1_500;
pub const DEFAULT_REDACTION_BUDGET_BYTES: u64 = 96 * 1024;
pub const DEFAULT_MAX_PREFETCH_LANES: usize = 131_072;
pub const DEFAULT_MAX_WITNESS_SHARDS: usize = 4_194_304;
pub const DEFAULT_MAX_ENCRYPTED_HINTS: usize = 8_388_608;
pub const DEFAULT_MAX_PQ_ATTESTATIONS: usize = 8_388_608;
pub const DEFAULT_MAX_CACHE_LEASES: usize = 4_194_304;
pub const DEFAULT_MAX_INVALIDATION_FENCES: usize = 4_194_304;
pub const DEFAULT_MAX_REBATE_CREDITS: usize = 4_194_304;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 1_048_576;
pub const DEFAULT_MAX_OPERATOR_SUMMARIES: usize = 262_144;
pub const DEFAULT_MAX_EVENTS: usize = 16_777_216;
pub const MAX_BPS: u64 = 10_000;

const D_STATE: &str = "PL2-FAST-PQ-CONF-PARALLEL-STATE-WITNESS-PREFETCH-MESH:STATE";
const D_CONFIG: &str = "PL2-FAST-PQ-CONF-PARALLEL-STATE-WITNESS-PREFETCH-MESH:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-PARALLEL-STATE-WITNESS-PREFETCH-MESH:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-PARALLEL-STATE-WITNESS-PREFETCH-MESH:ROOTS";
const D_LANES: &str = "PL2-FAST-PQ-CONF-PARALLEL-STATE-WITNESS-PREFETCH-MESH:LANES";
const D_SHARDS: &str = "PL2-FAST-PQ-CONF-PARALLEL-STATE-WITNESS-PREFETCH-MESH:SHARDS";
const D_HINTS: &str = "PL2-FAST-PQ-CONF-PARALLEL-STATE-WITNESS-PREFETCH-MESH:HINTS";
const D_ATTESTATIONS: &str = "PL2-FAST-PQ-CONF-PARALLEL-STATE-WITNESS-PREFETCH-MESH:ATTESTATIONS";
const D_LEASES: &str = "PL2-FAST-PQ-CONF-PARALLEL-STATE-WITNESS-PREFETCH-MESH:LEASES";
const D_FENCES: &str = "PL2-FAST-PQ-CONF-PARALLEL-STATE-WITNESS-PREFETCH-MESH:FENCES";
const D_REBATES: &str = "PL2-FAST-PQ-CONF-PARALLEL-STATE-WITNESS-PREFETCH-MESH:REBATES";
const D_REDACTIONS: &str = "PL2-FAST-PQ-CONF-PARALLEL-STATE-WITNESS-PREFETCH-MESH:REDACTIONS";
const D_SUMMARIES: &str = "PL2-FAST-PQ-CONF-PARALLEL-STATE-WITNESS-PREFETCH-MESH:SUMMARIES";
const D_EVENTS: &str = "PL2-FAST-PQ-CONF-PARALLEL-STATE-WITNESS-PREFETCH-MESH:EVENTS";
const D_NULLIFIERS: &str = "PL2-FAST-PQ-CONF-PARALLEL-STATE-WITNESS-PREFETCH-MESH:NULLIFIERS";

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
pub enum MeshLaneKind {
    HotAccountState,
    ContractStorage,
    NullifierSet,
    ViewTagCohort,
    BridgeExitState,
    RecursiveProofState,
    LowFeeBackfill,
    WatchtowerRescue,
}

impl MeshLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HotAccountState => "hot_account_state",
            Self::ContractStorage => "contract_storage",
            Self::NullifierSet => "nullifier_set",
            Self::ViewTagCohort => "view_tag_cohort",
            Self::BridgeExitState => "bridge_exit_state",
            Self::RecursiveProofState => "recursive_proof_state",
            Self::LowFeeBackfill => "low_fee_backfill",
            Self::WatchtowerRescue => "watchtower_rescue",
        }
    }

    pub fn default_weight(self) -> u64 {
        match self {
            Self::HotAccountState => 1_000,
            Self::RecursiveProofState => 960,
            Self::ContractStorage => 920,
            Self::NullifierSet => 880,
            Self::BridgeExitState => 830,
            Self::WatchtowerRescue => 760,
            Self::ViewTagCohort => 700,
            Self::LowFeeBackfill => 540,
        }
    }

    pub fn default_target_ms(self) -> u64 {
        match self {
            Self::HotAccountState => 24,
            Self::RecursiveProofState => 32,
            Self::ContractStorage => 38,
            Self::NullifierSet => 46,
            Self::BridgeExitState => 58,
            Self::WatchtowerRescue => 80,
            Self::ViewTagCohort => 96,
            Self::LowFeeBackfill => 140,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Saturated,
    LowFeeOnly,
    Draining,
    Fenced,
    Paused,
    Retired,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Saturated => "saturated",
            Self::LowFeeOnly => "low_fee_only",
            Self::Draining => "draining",
            Self::Fenced => "fenced",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_prefetch(self) -> bool {
        matches!(self, Self::Open | Self::Saturated | Self::LowFeeOnly)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardStatus {
    Planned,
    Reserved,
    Prefetching,
    Warm,
    Consumed,
    Fenced,
    Expired,
    Slashed,
}

impl ShardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Reserved => "reserved",
            Self::Prefetching => "prefetching",
            Self::Warm => "warm",
            Self::Consumed => "consumed",
            Self::Fenced => "fenced",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Planned | Self::Reserved | Self::Prefetching | Self::Warm
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HintKind {
    ContractReadSet,
    AccountState,
    NullifierRange,
    ViewTagBucket,
    BridgeExitLeaf,
    RecursiveProofInput,
    FeeSponsorCredit,
}

impl HintKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractReadSet => "contract_read_set",
            Self::AccountState => "account_state",
            Self::NullifierRange => "nullifier_range",
            Self::ViewTagBucket => "view_tag_bucket",
            Self::BridgeExitLeaf => "bridge_exit_leaf",
            Self::RecursiveProofInput => "recursive_proof_input",
            Self::FeeSponsorCredit => "fee_sponsor_credit",
        }
    }

    pub fn privacy_weight(self) -> u64 {
        match self {
            Self::NullifierRange => 1_000,
            Self::ViewTagBucket => 960,
            Self::ContractReadSet => 900,
            Self::AccountState => 860,
            Self::BridgeExitLeaf => 820,
            Self::RecursiveProofInput => 760,
            Self::FeeSponsorCredit => 640,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Include,
    Hold,
    Reject,
    Slash,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Include => "include",
            Self::Hold => "hold",
            Self::Reject => "reject",
            Self::Slash => "slash",
        }
    }

    pub fn contributes_to_quorum(self) -> bool {
        matches!(self, Self::Include)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseStatus {
    Offered,
    Active,
    Renewed,
    Consumed,
    Expired,
    Revoked,
}

impl LeaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Active => "active",
            Self::Renewed => "renewed",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Offered | Self::Active | Self::Renewed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceKind {
    StateRootChange,
    NullifierConflict,
    ViewTagEpochRotation,
    ContractWriteSet,
    OperatorEquivocation,
    CachePoison,
    PrivacyBudgetExhausted,
}

impl FenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StateRootChange => "state_root_change",
            Self::NullifierConflict => "nullifier_conflict",
            Self::ViewTagEpochRotation => "view_tag_epoch_rotation",
            Self::ContractWriteSet => "contract_write_set",
            Self::OperatorEquivocation => "operator_equivocation",
            Self::CachePoison => "cache_poison",
            Self::PrivacyBudgetExhausted => "privacy_budget_exhausted",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accrued,
    Claimable,
    Paid,
    Cancelled,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accrued => "accrued",
            Self::Claimable => "claimable",
            Self::Paid => "paid",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionClass {
    PublicSummary,
    OperatorOnly,
    AuditorOnly,
    SequencerOnly,
    Sealed,
}

impl RedactionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicSummary => "public_summary",
            Self::OperatorOnly => "operator_only",
            Self::AuditorOnly => "auditor_only",
            Self::SequencerOnly => "sequencer_only",
            Self::Sealed => "sealed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshEventKind {
    LaneRegistered,
    ShardPlanned,
    HintSealed,
    Attested,
    LeaseActivated,
    FenceRaised,
    RebateAccrued,
    SummaryPublished,
}

impl MeshEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LaneRegistered => "lane_registered",
            Self::ShardPlanned => "shard_planned",
            Self::HintSealed => "hint_sealed",
            Self::Attested => "attested",
            Self::LeaseActivated => "lease_activated",
            Self::FenceRaised => "fence_raised",
            Self::RebateAccrued => "rebate_accrued",
            Self::SummaryPublished => "summary_published",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub mode: RuntimeMode,
    pub protocol_version: String,
    pub schema_version: u64,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub target_prefetch_ms: u64,
    pub max_prefetch_ms: u64,
    pub target_mesh_fanout: u16,
    pub max_mesh_fanout: u16,
    pub slot_width_ms: u64,
    pub cache_lease_ttl_slots: u64,
    pub hint_ttl_slots: u64,
    pub attestation_ttl_slots: u64,
    pub fence_ttl_slots: u64,
    pub redaction_ttl_slots: u64,
    pub quorum_weight_bps: u64,
    pub supermajority_weight_bps: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub operator_fee_bps: u64,
    pub min_lane_bond_micro_units: u64,
    pub min_shard_bond_micro_units: u64,
    pub slash_bps: u64,
    pub redaction_budget_bytes: u64,
    pub max_prefetch_lanes: usize,
    pub max_witness_shards: usize,
    pub max_encrypted_hints: usize,
    pub max_pq_attestations: usize,
    pub max_cache_leases: usize,
    pub max_invalidation_fences: usize,
    pub max_rebate_credits: usize,
    pub max_redaction_budgets: usize,
    pub max_operator_summaries: usize,
    pub max_events: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: "nebula-devnet".to_string(),
            monero_network: "monero-devnet".to_string(),
            mode: RuntimeMode::Devnet,
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEFAULT_REBATE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            target_prefetch_ms: DEFAULT_TARGET_PREFETCH_MS,
            max_prefetch_ms: DEFAULT_MAX_PREFETCH_MS,
            target_mesh_fanout: DEFAULT_TARGET_MESH_FANOUT,
            max_mesh_fanout: DEFAULT_MAX_MESH_FANOUT,
            slot_width_ms: DEFAULT_SLOT_WIDTH_MS,
            cache_lease_ttl_slots: DEFAULT_CACHE_LEASE_TTL_SLOTS,
            hint_ttl_slots: DEFAULT_HINT_TTL_SLOTS,
            attestation_ttl_slots: DEFAULT_ATTESTATION_TTL_SLOTS,
            fence_ttl_slots: DEFAULT_FENCE_TTL_SLOTS,
            redaction_ttl_slots: DEFAULT_REDACTION_TTL_SLOTS,
            quorum_weight_bps: DEFAULT_QUORUM_WEIGHT_BPS,
            supermajority_weight_bps: DEFAULT_SUPERMAJORITY_WEIGHT_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            operator_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
            min_lane_bond_micro_units: DEFAULT_MIN_LANE_BOND_MICRO_UNITS,
            min_shard_bond_micro_units: DEFAULT_MIN_SHARD_BOND_MICRO_UNITS,
            slash_bps: DEFAULT_SLASH_BPS,
            redaction_budget_bytes: DEFAULT_REDACTION_BUDGET_BYTES,
            max_prefetch_lanes: DEFAULT_MAX_PREFETCH_LANES,
            max_witness_shards: DEFAULT_MAX_WITNESS_SHARDS,
            max_encrypted_hints: DEFAULT_MAX_ENCRYPTED_HINTS,
            max_pq_attestations: DEFAULT_MAX_PQ_ATTESTATIONS,
            max_cache_leases: DEFAULT_MAX_CACHE_LEASES,
            max_invalidation_fences: DEFAULT_MAX_INVALIDATION_FENCES,
            max_rebate_credits: DEFAULT_MAX_REBATE_CREDITS,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            max_operator_summaries: DEFAULT_MAX_OPERATOR_SUMMARIES,
            max_events: DEFAULT_MAX_EVENTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "mode": self.mode.as_str(),
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "hash_suite": HASH_SUITE,
            "pq_attestation_suite": PQ_ATTESTATION_SUITE,
            "pq_hint_envelope_suite": PQ_HINT_ENVELOPE_SUITE,
            "witness_shard_commitment_suite": WITNESS_SHARD_COMMITMENT_SUITE,
            "cache_lease_suite": CACHE_LEASE_SUITE,
            "invalidation_fence_suite": INVALIDATION_FENCE_SUITE,
            "low_fee_rebate_suite": LOW_FEE_REBATE_SUITE,
            "redaction_budget_suite": REDACTION_BUDGET_SUITE,
            "operator_summary_suite": OPERATOR_SUMMARY_SUITE,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "target_prefetch_ms": self.target_prefetch_ms,
            "max_prefetch_ms": self.max_prefetch_ms,
            "target_mesh_fanout": self.target_mesh_fanout,
            "max_mesh_fanout": self.max_mesh_fanout,
            "slot_width_ms": self.slot_width_ms,
            "cache_lease_ttl_slots": self.cache_lease_ttl_slots,
            "hint_ttl_slots": self.hint_ttl_slots,
            "attestation_ttl_slots": self.attestation_ttl_slots,
            "fence_ttl_slots": self.fence_ttl_slots,
            "redaction_ttl_slots": self.redaction_ttl_slots,
            "quorum_weight_bps": self.quorum_weight_bps,
            "supermajority_weight_bps": self.supermajority_weight_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "operator_fee_bps": self.operator_fee_bps,
            "min_lane_bond_micro_units": self.min_lane_bond_micro_units,
            "min_shard_bond_micro_units": self.min_shard_bond_micro_units,
            "slash_bps": self.slash_bps,
            "redaction_budget_bytes": self.redaction_budget_bytes,
            "limits": {
                "max_prefetch_lanes": self.max_prefetch_lanes,
                "max_witness_shards": self.max_witness_shards,
                "max_encrypted_hints": self.max_encrypted_hints,
                "max_pq_attestations": self.max_pq_attestations,
                "max_cache_leases": self.max_cache_leases,
                "max_invalidation_fences": self.max_invalidation_fences,
                "max_rebate_credits": self.max_rebate_credits,
                "max_redaction_budgets": self.max_redaction_budgets,
                "max_operator_summaries": self.max_operator_summaries,
                "max_events": self.max_events
            }
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_CONFIG, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub lanes_registered: u64,
    pub lanes_open: u64,
    pub witness_shards_planned: u64,
    pub witness_shards_warm: u64,
    pub encrypted_hints_sealed: u64,
    pub pq_attestations_collected: u64,
    pub cache_leases_active: u64,
    pub invalidation_fences_open: u64,
    pub rebate_credits_accrued: u64,
    pub redaction_budgets_open: u64,
    pub operator_summaries_published: u64,
    pub total_prefetch_bytes: u64,
    pub total_cache_hits: u64,
    pub total_cache_misses: u64,
    pub total_fee_micro_units: u64,
    pub total_rebate_micro_units: u64,
    pub total_redacted_bytes: u64,
    pub total_slash_micro_units: u64,
    pub events_emitted: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(D_COUNTERS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub lanes_root: String,
    pub shards_root: String,
    pub hints_root: String,
    pub attestations_root: String,
    pub leases_root: String,
    pub fences_root: String,
    pub rebates_root: String,
    pub redactions_root: String,
    pub summaries_root: String,
    pub events_root: String,
    pub nullifier_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            config_root: merkle_root(D_CONFIG, &[]),
            counters_root: merkle_root(D_COUNTERS, &[]),
            lanes_root: merkle_root(D_LANES, &[]),
            shards_root: merkle_root(D_SHARDS, &[]),
            hints_root: merkle_root(D_HINTS, &[]),
            attestations_root: merkle_root(D_ATTESTATIONS, &[]),
            leases_root: merkle_root(D_LEASES, &[]),
            fences_root: merkle_root(D_FENCES, &[]),
            rebates_root: merkle_root(D_REBATES, &[]),
            redactions_root: merkle_root(D_REDACTIONS, &[]),
            summaries_root: merkle_root(D_SUMMARIES, &[]),
            events_root: merkle_root(D_EVENTS, &[]),
            nullifier_root: merkle_root(D_NULLIFIERS, &[]),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(D_ROOTS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrefetchMeshLane {
    pub lane_id: String,
    pub lane_kind: MeshLaneKind,
    pub operator_commitment: String,
    pub lane_epoch: u64,
    pub status: LaneStatus,
    pub priority_weight: u64,
    pub target_prefetch_ms: u64,
    pub max_parallel_shards: u64,
    pub mesh_fanout: u16,
    pub min_privacy_set_size: u64,
    pub bond_micro_units: u64,
    pub encrypted_route_root: String,
    pub shard_commitment_root: String,
    pub cache_key_root: String,
    pub last_prefetch_slot: u64,
    pub pending_shards: u64,
    pub warm_shards: u64,
    pub cache_hit_bps: u64,
    pub fee_bps: u64,
}

impl PrefetchMeshLane {
    pub fn new(
        lane_id: impl Into<String>,
        lane_kind: MeshLaneKind,
        operator_commitment: impl Into<String>,
        lane_epoch: u64,
    ) -> Self {
        let lane_id = lane_id.into();
        let operator_commitment = operator_commitment.into();
        Self {
            encrypted_route_root: fixture_hash("lane-route", &lane_id),
            shard_commitment_root: fixture_hash("lane-shards", &lane_id),
            cache_key_root: fixture_hash("lane-cache", &lane_id),
            lane_id,
            lane_kind,
            operator_commitment,
            lane_epoch,
            status: LaneStatus::Open,
            priority_weight: lane_kind.default_weight(),
            target_prefetch_ms: lane_kind.default_target_ms(),
            max_parallel_shards: 32_768,
            mesh_fanout: DEFAULT_TARGET_MESH_FANOUT,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            bond_micro_units: DEFAULT_MIN_LANE_BOND_MICRO_UNITS,
            last_prefetch_slot: DEVNET_EPOCH,
            pending_shards: 0,
            warm_shards: 0,
            cache_hit_bps: 0,
            fee_bps: DEFAULT_MAX_USER_FEE_BPS,
        }
    }

    pub fn accepts_prefetch(&self) -> bool {
        self.status.accepts_prefetch()
            && self.mesh_fanout > 0
            && self.pending_shards < self.max_parallel_shards
    }

    pub fn utilization_bps(&self) -> u64 {
        if self.max_parallel_shards == 0 {
            0
        } else {
            self.pending_shards.saturating_mul(MAX_BPS) / self.max_parallel_shards
        }
    }

    pub fn effective_priority(&self) -> u64 {
        let latency_bonus = DEFAULT_MAX_PREFETCH_MS.saturating_sub(self.target_prefetch_ms);
        let hit_bonus = self.cache_hit_bps / 20;
        self.priority_weight
            .saturating_add(latency_bonus)
            .saturating_add(hit_bonus)
            .saturating_sub(self.utilization_bps() / 100)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "operator_commitment": self.operator_commitment,
            "lane_epoch": self.lane_epoch,
            "status": self.status.as_str(),
            "priority_weight": self.priority_weight,
            "effective_priority": self.effective_priority(),
            "target_prefetch_ms": self.target_prefetch_ms,
            "max_parallel_shards": self.max_parallel_shards,
            "mesh_fanout": self.mesh_fanout,
            "min_privacy_set_size": self.min_privacy_set_size,
            "bond_micro_units": self.bond_micro_units,
            "encrypted_route_root": self.encrypted_route_root,
            "shard_commitment_root": self.shard_commitment_root,
            "cache_key_root": self.cache_key_root,
            "last_prefetch_slot": self.last_prefetch_slot,
            "pending_shards": self.pending_shards,
            "warm_shards": self.warm_shards,
            "cache_hit_bps": self.cache_hit_bps,
            "fee_bps": self.fee_bps
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_LANES, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct StateWitnessShard {
    pub shard_id: String,
    pub lane_id: String,
    pub shard_index: u64,
    pub account_range_commitment: String,
    pub contract_namespace_commitment: String,
    pub witness_root: String,
    pub encrypted_delta_root: String,
    pub nullifier_fence_root: String,
    pub status: ShardStatus,
    pub planned_slot: u64,
    pub warm_by_slot: u64,
    pub expires_at_slot: u64,
    pub byte_size: u64,
    pub read_count: u64,
    pub privacy_set_size: u64,
    pub fee_micro_units: u64,
    pub rebate_micro_units: u64,
}

impl StateWitnessShard {
    pub fn new(
        shard_id: impl Into<String>,
        lane_id: impl Into<String>,
        shard_index: u64,
        planned_slot: u64,
    ) -> Self {
        let shard_id = shard_id.into();
        let lane_id = lane_id.into();
        Self {
            account_range_commitment: fixture_hash("account-range", &shard_id),
            contract_namespace_commitment: fixture_hash("contract-namespace", &shard_id),
            witness_root: fixture_hash("witness-root", &shard_id),
            encrypted_delta_root: fixture_hash("encrypted-delta", &shard_id),
            nullifier_fence_root: fixture_hash("nullifier-fence", &shard_id),
            shard_id,
            lane_id,
            shard_index,
            status: ShardStatus::Planned,
            planned_slot,
            warm_by_slot: planned_slot + 3,
            expires_at_slot: planned_slot + DEFAULT_CACHE_LEASE_TTL_SLOTS,
            byte_size: 192 * 1024,
            read_count: 0,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            fee_micro_units: 48,
            rebate_micro_units: 12,
        }
    }

    pub fn warm(&mut self, current_slot: u64) {
        self.status = ShardStatus::Warm;
        self.warm_by_slot = current_slot;
    }

    pub fn expired_at(&self, current_slot: u64) -> bool {
        current_slot >= self.expires_at_slot
    }

    pub fn public_record(&self) -> Value {
        json!({
            "shard_id": self.shard_id,
            "lane_id": self.lane_id,
            "shard_index": self.shard_index,
            "account_range_commitment": self.account_range_commitment,
            "contract_namespace_commitment": self.contract_namespace_commitment,
            "witness_root": self.witness_root,
            "encrypted_delta_root": self.encrypted_delta_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "status": self.status.as_str(),
            "planned_slot": self.planned_slot,
            "warm_by_slot": self.warm_by_slot,
            "expires_at_slot": self.expires_at_slot,
            "byte_size": self.byte_size,
            "read_count": self.read_count,
            "privacy_set_size": self.privacy_set_size,
            "fee_micro_units": self.fee_micro_units,
            "rebate_micro_units": self.rebate_micro_units
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_SHARDS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct EncryptedWitnessHint {
    pub hint_id: String,
    pub shard_id: String,
    pub lane_id: String,
    pub hint_kind: HintKind,
    pub receiver_commitment: String,
    pub ciphertext_root: String,
    pub kem_ciphertext_root: String,
    pub access_policy_root: String,
    pub decoy_hint_root: String,
    pub created_at_slot: u64,
    pub expires_at_slot: u64,
    pub privacy_set_size: u64,
    pub redacted_bytes: u64,
    pub fee_micro_units: u64,
}

impl EncryptedWitnessHint {
    pub fn new(
        hint_id: impl Into<String>,
        shard_id: impl Into<String>,
        lane_id: impl Into<String>,
        hint_kind: HintKind,
        created_at_slot: u64,
    ) -> Self {
        let hint_id = hint_id.into();
        Self {
            shard_id: shard_id.into(),
            lane_id: lane_id.into(),
            hint_kind,
            receiver_commitment: fixture_hash("hint-receiver", &hint_id),
            ciphertext_root: fixture_hash("hint-ciphertext", &hint_id),
            kem_ciphertext_root: fixture_hash("hint-kem", &hint_id),
            access_policy_root: fixture_hash("hint-access-policy", &hint_id),
            decoy_hint_root: fixture_hash("hint-decoys", &hint_id),
            hint_id,
            created_at_slot,
            expires_at_slot: created_at_slot + DEFAULT_HINT_TTL_SLOTS,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            redacted_bytes: 8 * 1024,
            fee_micro_units: 8,
        }
    }

    pub fn privacy_score(&self) -> u64 {
        self.privacy_set_size
            .saturating_mul(self.hint_kind.privacy_weight())
            .saturating_div(DEFAULT_TARGET_PRIVACY_SET_SIZE.max(1))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "shard_id": self.shard_id,
            "lane_id": self.lane_id,
            "hint_kind": self.hint_kind.as_str(),
            "receiver_commitment": self.receiver_commitment,
            "ciphertext_root": self.ciphertext_root,
            "kem_ciphertext_root": self.kem_ciphertext_root,
            "access_policy_root": self.access_policy_root,
            "decoy_hint_root": self.decoy_hint_root,
            "created_at_slot": self.created_at_slot,
            "expires_at_slot": self.expires_at_slot,
            "privacy_set_size": self.privacy_set_size,
            "privacy_score": self.privacy_score(),
            "redacted_bytes": self.redacted_bytes,
            "fee_micro_units": self.fee_micro_units
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_HINTS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqMeshAttestation {
    pub attestation_id: String,
    pub shard_id: String,
    pub lane_id: String,
    pub operator_commitment: String,
    pub validator_commitment: String,
    pub witness_root: String,
    pub lane_root: String,
    pub hint_root: String,
    pub signature_root: String,
    pub pq_security_bits: u16,
    pub verdict: AttestationVerdict,
    pub weight_bps: u64,
    pub attested_at_slot: u64,
    pub expires_at_slot: u64,
}

impl PqMeshAttestation {
    pub fn new(
        attestation_id: impl Into<String>,
        shard: &StateWitnessShard,
        lane: &PrefetchMeshLane,
        validator_commitment: impl Into<String>,
        attested_at_slot: u64,
    ) -> Self {
        let attestation_id = attestation_id.into();
        Self {
            shard_id: shard.shard_id.clone(),
            lane_id: lane.lane_id.clone(),
            operator_commitment: lane.operator_commitment.clone(),
            validator_commitment: validator_commitment.into(),
            witness_root: shard.witness_root.clone(),
            lane_root: lane.state_root(),
            hint_root: fixture_hash("attestation-hint-root", &attestation_id),
            signature_root: fixture_hash("attestation-signature", &attestation_id),
            attestation_id,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            verdict: AttestationVerdict::Include,
            weight_bps: 2_500,
            attested_at_slot,
            expires_at_slot: attested_at_slot + DEFAULT_ATTESTATION_TTL_SLOTS,
        }
    }

    pub fn contributes_weight(&self) -> u64 {
        if self.verdict.contributes_to_quorum() {
            self.weight_bps
        } else {
            0
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "shard_id": self.shard_id,
            "lane_id": self.lane_id,
            "operator_commitment": self.operator_commitment,
            "validator_commitment": self.validator_commitment,
            "witness_root": self.witness_root,
            "lane_root": self.lane_root,
            "hint_root": self.hint_root,
            "signature_root": self.signature_root,
            "pq_security_bits": self.pq_security_bits,
            "verdict": self.verdict.as_str(),
            "weight_bps": self.weight_bps,
            "contributes_weight_bps": self.contributes_weight(),
            "attested_at_slot": self.attested_at_slot,
            "expires_at_slot": self.expires_at_slot
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_ATTESTATIONS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CacheLease {
    pub lease_id: String,
    pub shard_id: String,
    pub lane_id: String,
    pub holder_commitment: String,
    pub cache_key_commitment: String,
    pub lease_status: LeaseStatus,
    pub issued_at_slot: u64,
    pub expires_at_slot: u64,
    pub max_reads: u64,
    pub reads_used: u64,
    pub max_bytes: u64,
    pub fee_micro_units: u64,
    pub rebate_micro_units: u64,
}

impl CacheLease {
    pub fn new(
        lease_id: impl Into<String>,
        shard_id: impl Into<String>,
        lane_id: impl Into<String>,
        holder_commitment: impl Into<String>,
        issued_at_slot: u64,
    ) -> Self {
        let lease_id = lease_id.into();
        Self {
            shard_id: shard_id.into(),
            lane_id: lane_id.into(),
            holder_commitment: holder_commitment.into(),
            cache_key_commitment: fixture_hash("cache-key", &lease_id),
            lease_id,
            lease_status: LeaseStatus::Active,
            issued_at_slot,
            expires_at_slot: issued_at_slot + DEFAULT_CACHE_LEASE_TTL_SLOTS,
            max_reads: 64,
            reads_used: 0,
            max_bytes: 2 * 1024 * 1024,
            fee_micro_units: 16,
            rebate_micro_units: 4,
        }
    }

    pub fn remaining_reads(&self) -> u64 {
        self.max_reads.saturating_sub(self.reads_used)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lease_id": self.lease_id,
            "shard_id": self.shard_id,
            "lane_id": self.lane_id,
            "holder_commitment": self.holder_commitment,
            "cache_key_commitment": self.cache_key_commitment,
            "lease_status": self.lease_status.as_str(),
            "issued_at_slot": self.issued_at_slot,
            "expires_at_slot": self.expires_at_slot,
            "max_reads": self.max_reads,
            "reads_used": self.reads_used,
            "remaining_reads": self.remaining_reads(),
            "max_bytes": self.max_bytes,
            "fee_micro_units": self.fee_micro_units,
            "rebate_micro_units": self.rebate_micro_units
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_LEASES, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct InvalidationFence {
    pub fence_id: String,
    pub lane_id: String,
    pub shard_id: String,
    pub fence_kind: FenceKind,
    pub conflict_root: String,
    pub replacement_witness_root: String,
    pub operator_commitment: String,
    pub raised_at_slot: u64,
    pub expires_at_slot: u64,
    pub affected_hint_count: u64,
    pub affected_lease_count: u64,
    pub slash_micro_units: u64,
}

impl InvalidationFence {
    pub fn new(
        fence_id: impl Into<String>,
        lane_id: impl Into<String>,
        shard_id: impl Into<String>,
        fence_kind: FenceKind,
        operator_commitment: impl Into<String>,
        raised_at_slot: u64,
    ) -> Self {
        let fence_id = fence_id.into();
        Self {
            lane_id: lane_id.into(),
            shard_id: shard_id.into(),
            fence_kind,
            conflict_root: fixture_hash("fence-conflict", &fence_id),
            replacement_witness_root: fixture_hash("fence-replacement", &fence_id),
            operator_commitment: operator_commitment.into(),
            fence_id,
            raised_at_slot,
            expires_at_slot: raised_at_slot + DEFAULT_FENCE_TTL_SLOTS,
            affected_hint_count: 0,
            affected_lease_count: 0,
            slash_micro_units: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "lane_id": self.lane_id,
            "shard_id": self.shard_id,
            "fence_kind": self.fence_kind.as_str(),
            "conflict_root": self.conflict_root,
            "replacement_witness_root": self.replacement_witness_root,
            "operator_commitment": self.operator_commitment,
            "raised_at_slot": self.raised_at_slot,
            "expires_at_slot": self.expires_at_slot,
            "affected_hint_count": self.affected_hint_count,
            "affected_lease_count": self.affected_lease_count,
            "slash_micro_units": self.slash_micro_units
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_FENCES, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct LowFeeRebateCredit {
    pub rebate_id: String,
    pub shard_id: String,
    pub lane_id: String,
    pub account_commitment: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub fee_paid_micro_units: u64,
    pub rebate_micro_units: u64,
    pub status: RebateStatus,
    pub accrued_at_slot: u64,
    pub claimable_at_slot: u64,
    pub paid_at_slot: Option<u64>,
}

impl LowFeeRebateCredit {
    pub fn new(
        rebate_id: impl Into<String>,
        shard: &StateWitnessShard,
        account_commitment: impl Into<String>,
        accrued_at_slot: u64,
    ) -> Self {
        let fee_paid_micro_units = shard.fee_micro_units;
        let rebate_micro_units = fee_paid_micro_units
            .saturating_mul(DEFAULT_TARGET_REBATE_BPS)
            .saturating_div(MAX_BPS)
            .max(shard.rebate_micro_units);
        Self {
            rebate_id: rebate_id.into(),
            shard_id: shard.shard_id.clone(),
            lane_id: shard.lane_id.clone(),
            account_commitment: account_commitment.into(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEFAULT_REBATE_ASSET_ID.to_string(),
            fee_paid_micro_units,
            rebate_micro_units,
            status: RebateStatus::Accrued,
            accrued_at_slot,
            claimable_at_slot: accrued_at_slot + 2,
            paid_at_slot: None,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "shard_id": self.shard_id,
            "lane_id": self.lane_id,
            "account_commitment": self.account_commitment,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "fee_paid_micro_units": self.fee_paid_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "status": self.status.as_str(),
            "accrued_at_slot": self.accrued_at_slot,
            "claimable_at_slot": self.claimable_at_slot,
            "paid_at_slot": self.paid_at_slot
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_REBATES, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub operator_commitment: String,
    pub lane_id: String,
    pub redaction_class: RedactionClass,
    pub budget_bytes: u64,
    pub used_bytes: u64,
    pub disclosure_root: String,
    pub auditor_view_root: String,
    pub opened_at_slot: u64,
    pub expires_at_slot: u64,
}

impl RedactionBudget {
    pub fn new(
        budget_id: impl Into<String>,
        operator_commitment: impl Into<String>,
        lane_id: impl Into<String>,
        redaction_class: RedactionClass,
        opened_at_slot: u64,
    ) -> Self {
        let budget_id = budget_id.into();
        Self {
            operator_commitment: operator_commitment.into(),
            lane_id: lane_id.into(),
            redaction_class,
            budget_bytes: DEFAULT_REDACTION_BUDGET_BYTES,
            used_bytes: 0,
            disclosure_root: fixture_hash("redaction-disclosure", &budget_id),
            auditor_view_root: fixture_hash("redaction-auditor", &budget_id),
            budget_id,
            opened_at_slot,
            expires_at_slot: opened_at_slot + DEFAULT_REDACTION_TTL_SLOTS,
        }
    }

    pub fn remaining_bytes(&self) -> u64 {
        self.budget_bytes.saturating_sub(self.used_bytes)
    }

    pub fn charge(&mut self, bytes: u64) -> Result<()> {
        ensure!(
            self.remaining_bytes() >= bytes,
            "redaction budget exhausted for {}",
            self.budget_id
        );
        self.used_bytes = self.used_bytes.saturating_add(bytes);
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "operator_commitment": self.operator_commitment,
            "lane_id": self.lane_id,
            "redaction_class": self.redaction_class.as_str(),
            "budget_bytes": self.budget_bytes,
            "used_bytes": self.used_bytes,
            "remaining_bytes": self.remaining_bytes(),
            "disclosure_root": self.disclosure_root,
            "auditor_view_root": self.auditor_view_root,
            "opened_at_slot": self.opened_at_slot,
            "expires_at_slot": self.expires_at_slot
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_REDACTIONS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_commitment: String,
    pub lane_ids: Vec<String>,
    pub summary_epoch: u64,
    pub redacted_summary_root: String,
    pub shard_root: String,
    pub hint_root: String,
    pub attestation_root: String,
    pub cache_lease_root: String,
    pub fee_rebate_root: String,
    pub privacy_floor: u64,
    pub avg_prefetch_ms: u64,
    pub cache_hit_bps: u64,
    pub low_fee_savings_micro_units: u64,
    pub published_at_slot: u64,
}

impl OperatorSummary {
    pub fn new(
        summary_id: impl Into<String>,
        operator_commitment: impl Into<String>,
        lane_ids: Vec<String>,
        summary_epoch: u64,
        published_at_slot: u64,
    ) -> Self {
        let summary_id = summary_id.into();
        Self {
            operator_commitment: operator_commitment.into(),
            lane_ids,
            summary_epoch,
            redacted_summary_root: fixture_hash("summary-redacted", &summary_id),
            shard_root: fixture_hash("summary-shards", &summary_id),
            hint_root: fixture_hash("summary-hints", &summary_id),
            attestation_root: fixture_hash("summary-attestations", &summary_id),
            cache_lease_root: fixture_hash("summary-leases", &summary_id),
            fee_rebate_root: fixture_hash("summary-rebates", &summary_id),
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            avg_prefetch_ms: DEFAULT_TARGET_PREFETCH_MS,
            cache_hit_bps: 8_700,
            low_fee_savings_micro_units: 0,
            summary_id,
            published_at_slot,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "operator_commitment": self.operator_commitment,
            "lane_ids": self.lane_ids,
            "summary_epoch": self.summary_epoch,
            "redacted_summary_root": self.redacted_summary_root,
            "shard_root": self.shard_root,
            "hint_root": self.hint_root,
            "attestation_root": self.attestation_root,
            "cache_lease_root": self.cache_lease_root,
            "fee_rebate_root": self.fee_rebate_root,
            "privacy_floor": self.privacy_floor,
            "avg_prefetch_ms": self.avg_prefetch_ms,
            "cache_hit_bps": self.cache_hit_bps,
            "low_fee_savings_micro_units": self.low_fee_savings_micro_units,
            "published_at_slot": self.published_at_slot
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_SUMMARIES, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct MeshEvent {
    pub event_id: String,
    pub event_kind: MeshEventKind,
    pub lane_id: String,
    pub subject_id: String,
    pub slot: u64,
    pub commitment_root: String,
    pub sequence: u64,
}

impl MeshEvent {
    pub fn new(
        event_id: impl Into<String>,
        event_kind: MeshEventKind,
        lane_id: impl Into<String>,
        subject_id: impl Into<String>,
        slot: u64,
        sequence: u64,
    ) -> Self {
        let event_id = event_id.into();
        Self {
            commitment_root: fixture_hash("event", &event_id),
            event_id,
            event_kind,
            lane_id: lane_id.into(),
            subject_id: subject_id.into(),
            slot,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_kind": self.event_kind.as_str(),
            "lane_id": self.lane_id,
            "subject_id": self.subject_id,
            "slot": self.slot,
            "commitment_root": self.commitment_root,
            "sequence": self.sequence
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_EVENTS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub current_slot: u64,
    pub lanes: BTreeMap<String, PrefetchMeshLane>,
    pub witness_shards: BTreeMap<String, StateWitnessShard>,
    pub encrypted_hints: BTreeMap<String, EncryptedWitnessHint>,
    pub pq_attestations: BTreeMap<String, PqMeshAttestation>,
    pub cache_leases: BTreeMap<String, CacheLease>,
    pub invalidation_fences: BTreeMap<String, InvalidationFence>,
    pub low_fee_rebate_credits: BTreeMap<String, LowFeeRebateCredit>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub events: Vec<MeshEvent>,
    pub consumed_nullifiers: BTreeSet<String>,
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
            lanes: BTreeMap::new(),
            witness_shards: BTreeMap::new(),
            encrypted_hints: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            cache_leases: BTreeMap::new(),
            invalidation_fences: BTreeMap::new(),
            low_fee_rebate_credits: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            events: Vec::new(),
            consumed_nullifiers: BTreeSet::new(),
        };
        state.install_devnet_fixtures();
        state.refresh_roots();
        state
    }

    pub fn register_lane(&mut self, lane: PrefetchMeshLane) -> Result<()> {
        ensure!(
            self.lanes.len() < self.config.max_prefetch_lanes,
            "prefetch lane capacity reached"
        );
        ensure!(
            lane.bond_micro_units >= self.config.min_lane_bond_micro_units,
            "lane bond below minimum"
        );
        ensure!(
            lane.mesh_fanout <= self.config.max_mesh_fanout,
            "mesh fanout exceeds maximum"
        );
        let lane_id = lane.lane_id.clone();
        ensure!(
            !self.lanes.contains_key(&lane_id),
            "duplicate prefetch lane {}",
            lane_id
        );
        self.counters.lanes_registered = self.counters.lanes_registered.saturating_add(1);
        if lane.status.accepts_prefetch() {
            self.counters.lanes_open = self.counters.lanes_open.saturating_add(1);
        }
        self.events.push(MeshEvent::new(
            next_id("evt-lane", self.events.len()),
            MeshEventKind::LaneRegistered,
            lane_id.clone(),
            lane_id.clone(),
            self.current_slot,
            self.counters.events_emitted,
        ));
        self.counters.events_emitted = self.counters.events_emitted.saturating_add(1);
        self.lanes.insert(lane_id, lane);
        self.refresh_roots();
        Ok(())
    }

    pub fn plan_witness_shard(&mut self, mut shard: StateWitnessShard) -> Result<()> {
        ensure!(
            self.witness_shards.len() < self.config.max_witness_shards,
            "witness shard capacity reached"
        );
        ensure!(
            self.lanes.contains_key(&shard.lane_id),
            "unknown prefetch lane {}",
            shard.lane_id
        );
        ensure!(
            shard.privacy_set_size >= self.config.min_privacy_set_size,
            "witness shard privacy set below minimum"
        );
        ensure!(
            !self.witness_shards.contains_key(&shard.shard_id),
            "duplicate witness shard {}",
            shard.shard_id
        );
        shard.status = ShardStatus::Reserved;
        if let Some(lane) = self.lanes.get_mut(&shard.lane_id) {
            ensure!(
                lane.accepts_prefetch(),
                "prefetch lane {} is not accepting work",
                lane.lane_id
            );
            lane.pending_shards = lane.pending_shards.saturating_add(1);
            lane.last_prefetch_slot = self.current_slot;
        }
        self.counters.witness_shards_planned =
            self.counters.witness_shards_planned.saturating_add(1);
        self.counters.total_prefetch_bytes = self
            .counters
            .total_prefetch_bytes
            .saturating_add(shard.byte_size);
        self.counters.total_fee_micro_units = self
            .counters
            .total_fee_micro_units
            .saturating_add(shard.fee_micro_units);
        self.events.push(MeshEvent::new(
            next_id("evt-shard", self.events.len()),
            MeshEventKind::ShardPlanned,
            shard.lane_id.clone(),
            shard.shard_id.clone(),
            self.current_slot,
            self.counters.events_emitted,
        ));
        self.counters.events_emitted = self.counters.events_emitted.saturating_add(1);
        self.witness_shards.insert(shard.shard_id.clone(), shard);
        self.refresh_roots();
        Ok(())
    }

    pub fn mark_shard_warm(&mut self, shard_id: &str) -> Result<()> {
        let shard = self
            .witness_shards
            .get_mut(shard_id)
            .ok_or_else(|| format!("unknown witness shard {shard_id}"))?;
        if shard.status != ShardStatus::Warm {
            shard.warm(self.current_slot);
            self.counters.witness_shards_warm = self.counters.witness_shards_warm.saturating_add(1);
            if let Some(lane) = self.lanes.get_mut(&shard.lane_id) {
                lane.pending_shards = lane.pending_shards.saturating_sub(1);
                lane.warm_shards = lane.warm_shards.saturating_add(1);
            }
        }
        self.refresh_roots();
        Ok(())
    }

    pub fn seal_encrypted_hint(&mut self, hint: EncryptedWitnessHint) -> Result<()> {
        ensure!(
            self.encrypted_hints.len() < self.config.max_encrypted_hints,
            "encrypted hint capacity reached"
        );
        ensure!(
            self.witness_shards.contains_key(&hint.shard_id),
            "unknown witness shard {}",
            hint.shard_id
        );
        ensure!(
            hint.privacy_set_size >= self.config.min_privacy_set_size,
            "encrypted hint privacy set below minimum"
        );
        ensure!(
            !self.encrypted_hints.contains_key(&hint.hint_id),
            "duplicate encrypted hint {}",
            hint.hint_id
        );
        self.counters.encrypted_hints_sealed =
            self.counters.encrypted_hints_sealed.saturating_add(1);
        self.counters.total_redacted_bytes = self
            .counters
            .total_redacted_bytes
            .saturating_add(hint.redacted_bytes);
        self.events.push(MeshEvent::new(
            next_id("evt-hint", self.events.len()),
            MeshEventKind::HintSealed,
            hint.lane_id.clone(),
            hint.hint_id.clone(),
            self.current_slot,
            self.counters.events_emitted,
        ));
        self.counters.events_emitted = self.counters.events_emitted.saturating_add(1);
        self.encrypted_hints.insert(hint.hint_id.clone(), hint);
        self.refresh_roots();
        Ok(())
    }

    pub fn collect_attestation(&mut self, attestation: PqMeshAttestation) -> Result<()> {
        ensure!(
            self.pq_attestations.len() < self.config.max_pq_attestations,
            "pq attestation capacity reached"
        );
        ensure!(
            attestation.pq_security_bits >= self.config.min_pq_security_bits,
            "pq security bits below minimum"
        );
        ensure!(
            self.witness_shards.contains_key(&attestation.shard_id),
            "unknown attested shard {}",
            attestation.shard_id
        );
        ensure!(
            !self
                .pq_attestations
                .contains_key(&attestation.attestation_id),
            "duplicate attestation {}",
            attestation.attestation_id
        );
        self.counters.pq_attestations_collected =
            self.counters.pq_attestations_collected.saturating_add(1);
        self.events.push(MeshEvent::new(
            next_id("evt-attestation", self.events.len()),
            MeshEventKind::Attested,
            attestation.lane_id.clone(),
            attestation.attestation_id.clone(),
            self.current_slot,
            self.counters.events_emitted,
        ));
        self.counters.events_emitted = self.counters.events_emitted.saturating_add(1);
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(())
    }

    pub fn activate_cache_lease(&mut self, lease: CacheLease) -> Result<()> {
        ensure!(
            self.cache_leases.len() < self.config.max_cache_leases,
            "cache lease capacity reached"
        );
        ensure!(
            self.witness_shards.contains_key(&lease.shard_id),
            "unknown leased shard {}",
            lease.shard_id
        );
        ensure!(
            !self.cache_leases.contains_key(&lease.lease_id),
            "duplicate cache lease {}",
            lease.lease_id
        );
        self.counters.cache_leases_active = self.counters.cache_leases_active.saturating_add(1);
        self.counters.total_fee_micro_units = self
            .counters
            .total_fee_micro_units
            .saturating_add(lease.fee_micro_units);
        self.events.push(MeshEvent::new(
            next_id("evt-lease", self.events.len()),
            MeshEventKind::LeaseActivated,
            lease.lane_id.clone(),
            lease.lease_id.clone(),
            self.current_slot,
            self.counters.events_emitted,
        ));
        self.counters.events_emitted = self.counters.events_emitted.saturating_add(1);
        self.cache_leases.insert(lease.lease_id.clone(), lease);
        self.refresh_roots();
        Ok(())
    }

    pub fn raise_invalidation_fence(&mut self, fence: InvalidationFence) -> Result<()> {
        ensure!(
            self.invalidation_fences.len() < self.config.max_invalidation_fences,
            "invalidation fence capacity reached"
        );
        ensure!(
            self.witness_shards.contains_key(&fence.shard_id),
            "unknown fenced shard {}",
            fence.shard_id
        );
        ensure!(
            !self.invalidation_fences.contains_key(&fence.fence_id),
            "duplicate invalidation fence {}",
            fence.fence_id
        );
        if let Some(shard) = self.witness_shards.get_mut(&fence.shard_id) {
            shard.status = ShardStatus::Fenced;
        }
        if let Some(lane) = self.lanes.get_mut(&fence.lane_id) {
            lane.status = LaneStatus::Fenced;
        }
        self.counters.invalidation_fences_open =
            self.counters.invalidation_fences_open.saturating_add(1);
        self.counters.total_slash_micro_units = self
            .counters
            .total_slash_micro_units
            .saturating_add(fence.slash_micro_units);
        self.events.push(MeshEvent::new(
            next_id("evt-fence", self.events.len()),
            MeshEventKind::FenceRaised,
            fence.lane_id.clone(),
            fence.fence_id.clone(),
            self.current_slot,
            self.counters.events_emitted,
        ));
        self.counters.events_emitted = self.counters.events_emitted.saturating_add(1);
        self.invalidation_fences
            .insert(fence.fence_id.clone(), fence);
        self.refresh_roots();
        Ok(())
    }

    pub fn accrue_rebate_credit(&mut self, rebate: LowFeeRebateCredit) -> Result<()> {
        ensure!(
            self.low_fee_rebate_credits.len() < self.config.max_rebate_credits,
            "rebate credit capacity reached"
        );
        ensure!(
            !self.low_fee_rebate_credits.contains_key(&rebate.rebate_id),
            "duplicate rebate credit {}",
            rebate.rebate_id
        );
        self.counters.rebate_credits_accrued =
            self.counters.rebate_credits_accrued.saturating_add(1);
        self.counters.total_rebate_micro_units = self
            .counters
            .total_rebate_micro_units
            .saturating_add(rebate.rebate_micro_units);
        self.events.push(MeshEvent::new(
            next_id("evt-rebate", self.events.len()),
            MeshEventKind::RebateAccrued,
            rebate.lane_id.clone(),
            rebate.rebate_id.clone(),
            self.current_slot,
            self.counters.events_emitted,
        ));
        self.counters.events_emitted = self.counters.events_emitted.saturating_add(1);
        self.low_fee_rebate_credits
            .insert(rebate.rebate_id.clone(), rebate);
        self.refresh_roots();
        Ok(())
    }

    pub fn open_redaction_budget(&mut self, budget: RedactionBudget) -> Result<()> {
        ensure!(
            self.redaction_budgets.len() < self.config.max_redaction_budgets,
            "redaction budget capacity reached"
        );
        ensure!(
            !self.redaction_budgets.contains_key(&budget.budget_id),
            "duplicate redaction budget {}",
            budget.budget_id
        );
        self.counters.redaction_budgets_open =
            self.counters.redaction_budgets_open.saturating_add(1);
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        self.refresh_roots();
        Ok(())
    }

    pub fn publish_operator_summary(&mut self, summary: OperatorSummary) -> Result<()> {
        ensure!(
            self.operator_summaries.len() < self.config.max_operator_summaries,
            "operator summary capacity reached"
        );
        ensure!(
            !self.operator_summaries.contains_key(&summary.summary_id),
            "duplicate operator summary {}",
            summary.summary_id
        );
        self.counters.operator_summaries_published =
            self.counters.operator_summaries_published.saturating_add(1);
        self.events.push(MeshEvent::new(
            next_id("evt-summary", self.events.len()),
            MeshEventKind::SummaryPublished,
            summary
                .lane_ids
                .first()
                .cloned()
                .unwrap_or_else(|| "mesh".to_string()),
            summary.summary_id.clone(),
            self.current_slot,
            self.counters.events_emitted,
        ));
        self.counters.events_emitted = self.counters.events_emitted.saturating_add(1);
        self.operator_summaries
            .insert(summary.summary_id.clone(), summary);
        self.refresh_roots();
        Ok(())
    }

    pub fn quorum_weight_for_shard(&self, shard_id: &str) -> u64 {
        self.pq_attestations
            .values()
            .filter(|attestation| attestation.shard_id == shard_id)
            .map(PqMeshAttestation::contributes_weight)
            .sum::<u64>()
            .min(MAX_BPS)
    }

    pub fn shard_has_quorum(&self, shard_id: &str) -> bool {
        self.quorum_weight_for_shard(shard_id) >= self.config.quorum_weight_bps
    }

    pub fn live_cache_leases(&self) -> usize {
        self.cache_leases
            .values()
            .filter(|lease| lease.lease_status.live())
            .count()
    }

    pub fn open_invalidation_fences(&self) -> usize {
        self.invalidation_fences
            .values()
            .filter(|fence| fence.expires_at_slot > self.current_slot)
            .count()
    }

    pub fn low_fee_savings_micro_units(&self) -> u64 {
        self.low_fee_rebate_credits
            .values()
            .map(|rebate| rebate.rebate_micro_units)
            .sum()
    }

    pub fn operator_summary_for(&self, operator_commitment: &str) -> Option<&OperatorSummary> {
        self.operator_summaries
            .values()
            .filter(|summary| summary.operator_commitment == operator_commitment)
            .max_by_key(|summary| summary.published_at_slot)
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "scheme": "private_l2_fast_pq_confidential_parallel_state_witness_prefetch_mesh_runtime_public_record_v1",
            "chain_id": self.config.chain_id,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "current_slot": self.current_slot,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "lane_count": self.lanes.len(),
            "witness_shard_count": self.witness_shards.len(),
            "encrypted_hint_count": self.encrypted_hints.len(),
            "pq_attestation_count": self.pq_attestations.len(),
            "cache_lease_count": self.cache_leases.len(),
            "live_cache_leases": self.live_cache_leases(),
            "invalidation_fence_count": self.invalidation_fences.len(),
            "open_invalidation_fences": self.open_invalidation_fences(),
            "rebate_credit_count": self.low_fee_rebate_credits.len(),
            "low_fee_savings_micro_units": self.low_fee_savings_micro_units(),
            "redaction_budget_count": self.redaction_budgets.len(),
            "operator_summary_count": self.operator_summaries.len(),
            "consumed_nullifier_count": self.consumed_nullifiers.len(),
            "lanes": self.lanes.values().map(PrefetchMeshLane::public_record).collect::<Vec<_>>(),
            "witness_shards": self.witness_shards.values().map(StateWitnessShard::public_record).collect::<Vec<_>>(),
            "encrypted_hints": self.encrypted_hints.values().map(EncryptedWitnessHint::public_record).collect::<Vec<_>>(),
            "pq_attestations": self.pq_attestations.values().map(PqMeshAttestation::public_record).collect::<Vec<_>>(),
            "cache_leases": self.cache_leases.values().map(CacheLease::public_record).collect::<Vec<_>>(),
            "invalidation_fences": self.invalidation_fences.values().map(InvalidationFence::public_record).collect::<Vec<_>>(),
            "low_fee_rebate_credits": self.low_fee_rebate_credits.values().map(LowFeeRebateCredit::public_record).collect::<Vec<_>>(),
            "redaction_budgets": self.redaction_budgets.values().map(RedactionBudget::public_record).collect::<Vec<_>>(),
            "operator_summaries": self.operator_summaries.values().map(OperatorSummary::public_record).collect::<Vec<_>>(),
            "events": self.events.iter().map(MeshEvent::public_record).collect::<Vec<_>>(),
            "consumed_nullifiers": self.consumed_nullifiers.iter().cloned().collect::<Vec<_>>()
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

    fn install_devnet_fixtures(&mut self) {
        let operators = [
            fixture_hash("operator", "aurora-prefetch"),
            fixture_hash("operator", "borealis-prefetch"),
            fixture_hash("operator", "cirrus-prefetch"),
            fixture_hash("operator", "drift-prefetch"),
        ];
        let lane_kinds = [
            MeshLaneKind::HotAccountState,
            MeshLaneKind::ContractStorage,
            MeshLaneKind::NullifierSet,
            MeshLaneKind::RecursiveProofState,
        ];
        for (idx, lane_kind) in lane_kinds.iter().enumerate() {
            let lane_id = next_id("mesh-lane", idx);
            let mut lane = PrefetchMeshLane::new(
                lane_id.clone(),
                *lane_kind,
                operators[idx % operators.len()].clone(),
                self.epoch,
            );
            lane.cache_hit_bps = 7_800 + idx as u64 * 300;
            lane.pending_shards = 0;
            self.register_lane(lane)
                .expect("devnet lane fixture should register");
        }

        let lane_ids = self.lanes.keys().cloned().collect::<Vec<_>>();
        for (lane_idx, lane_id) in lane_ids.iter().enumerate() {
            for shard_idx in 0..3 {
                let shard_id = format!("{lane_id}-shard-{shard_idx:02}");
                let mut shard = StateWitnessShard::new(
                    shard_id.clone(),
                    lane_id.clone(),
                    shard_idx as u64,
                    self.current_slot + shard_idx as u64,
                );
                shard.byte_size = 128 * 1024 + (lane_idx as u64 * 32 * 1024);
                shard.fee_micro_units = 32 + lane_idx as u64 * 8;
                shard.rebate_micro_units = 8 + shard_idx as u64;
                self.plan_witness_shard(shard.clone())
                    .expect("devnet shard fixture should plan");
                if shard_idx != 2 {
                    self.mark_shard_warm(&shard_id)
                        .expect("devnet shard fixture should warm");
                }
                let hint_kind = match lane_idx {
                    0 => HintKind::AccountState,
                    1 => HintKind::ContractReadSet,
                    2 => HintKind::NullifierRange,
                    _ => HintKind::RecursiveProofInput,
                };
                let hint = EncryptedWitnessHint::new(
                    format!("{shard_id}-hint-00"),
                    shard_id.clone(),
                    lane_id.clone(),
                    hint_kind,
                    self.current_slot,
                );
                self.seal_encrypted_hint(hint)
                    .expect("devnet hint fixture should seal");
                let lane = self
                    .lanes
                    .get(lane_id)
                    .expect("fixture lane exists")
                    .clone();
                let shard_ref = self
                    .witness_shards
                    .get(&shard_id)
                    .expect("fixture shard exists")
                    .clone();
                for attester_idx in 0..3 {
                    let mut attestation = PqMeshAttestation::new(
                        format!("{shard_id}-attestation-{attester_idx:02}"),
                        &shard_ref,
                        &lane,
                        fixture_hash("validator", &format!("{lane_id}-{attester_idx}")),
                        self.current_slot + attester_idx as u64,
                    );
                    attestation.weight_bps = 2_500;
                    self.collect_attestation(attestation)
                        .expect("devnet attestation fixture should collect");
                }
                let lease = CacheLease::new(
                    format!("{shard_id}-lease-00"),
                    shard_id.clone(),
                    lane_id.clone(),
                    fixture_hash("holder", &shard_id),
                    self.current_slot,
                );
                self.activate_cache_lease(lease)
                    .expect("devnet lease fixture should activate");
                let shard_for_rebate = self
                    .witness_shards
                    .get(&shard_id)
                    .expect("fixture shard exists")
                    .clone();
                let rebate = LowFeeRebateCredit::new(
                    format!("{shard_id}-rebate-00"),
                    &shard_for_rebate,
                    fixture_hash("rebate-account", &shard_id),
                    self.current_slot,
                );
                self.accrue_rebate_credit(rebate)
                    .expect("devnet rebate fixture should accrue");
            }
        }

        for (idx, lane_id) in lane_ids.iter().enumerate() {
            let lane = self.lanes.get(lane_id).expect("fixture lane exists");
            let mut budget = RedactionBudget::new(
                next_id("redaction-budget", idx),
                lane.operator_commitment.clone(),
                lane_id.clone(),
                if idx % 2 == 0 {
                    RedactionClass::PublicSummary
                } else {
                    RedactionClass::AuditorOnly
                },
                self.current_slot,
            );
            budget
                .charge(12 * 1024 + idx as u64 * 512)
                .expect("devnet redaction budget charge should fit");
            self.open_redaction_budget(budget)
                .expect("devnet redaction budget fixture should open");
        }

        let first_lane = lane_ids.first().cloned().unwrap_or_default();
        let first_shard = self
            .witness_shards
            .keys()
            .next()
            .cloned()
            .unwrap_or_else(|| "missing-shard".to_string());
        let mut fence = InvalidationFence::new(
            "fence-devnet-viewtag-epoch-00",
            first_lane.clone(),
            first_shard,
            FenceKind::ViewTagEpochRotation,
            operators[0].clone(),
            self.current_slot + 7,
        );
        fence.affected_hint_count = 1;
        fence.affected_lease_count = 1;
        self.raise_invalidation_fence(fence)
            .expect("devnet invalidation fence fixture should raise");

        for (idx, operator) in operators.iter().enumerate() {
            let operator_lanes = self
                .lanes
                .values()
                .filter(|lane| lane.operator_commitment == *operator)
                .map(|lane| lane.lane_id.clone())
                .collect::<Vec<_>>();
            if operator_lanes.is_empty() {
                continue;
            }
            let mut summary = OperatorSummary::new(
                next_id("operator-summary", idx),
                operator.clone(),
                operator_lanes,
                self.epoch,
                self.current_slot + 8 + idx as u64,
            );
            summary.low_fee_savings_micro_units = self.low_fee_savings_micro_units();
            summary.cache_hit_bps = 8_800 + idx as u64 * 100;
            self.publish_operator_summary(summary)
                .expect("devnet operator summary fixture should publish");
        }

        for idx in 0..8 {
            self.consumed_nullifiers
                .insert(fixture_hash("consumed-nullifier", &format!("devnet-{idx}")));
        }
    }

    pub fn refresh_roots(&mut self) {
        self.counters.cache_leases_active = self.live_cache_leases() as u64;
        self.counters.invalidation_fences_open = self.open_invalidation_fences() as u64;
        self.roots = Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters.state_root(),
            lanes_root: collection_root(
                D_LANES,
                self.lanes.values().map(PrefetchMeshLane::public_record),
            ),
            shards_root: collection_root(
                D_SHARDS,
                self.witness_shards
                    .values()
                    .map(StateWitnessShard::public_record),
            ),
            hints_root: collection_root(
                D_HINTS,
                self.encrypted_hints
                    .values()
                    .map(EncryptedWitnessHint::public_record),
            ),
            attestations_root: collection_root(
                D_ATTESTATIONS,
                self.pq_attestations
                    .values()
                    .map(PqMeshAttestation::public_record),
            ),
            leases_root: collection_root(
                D_LEASES,
                self.cache_leases.values().map(CacheLease::public_record),
            ),
            fences_root: collection_root(
                D_FENCES,
                self.invalidation_fences
                    .values()
                    .map(InvalidationFence::public_record),
            ),
            rebates_root: collection_root(
                D_REBATES,
                self.low_fee_rebate_credits
                    .values()
                    .map(LowFeeRebateCredit::public_record),
            ),
            redactions_root: collection_root(
                D_REDACTIONS,
                self.redaction_budgets
                    .values()
                    .map(RedactionBudget::public_record),
            ),
            summaries_root: collection_root(
                D_SUMMARIES,
                self.operator_summaries
                    .values()
                    .map(OperatorSummary::public_record),
            ),
            events_root: collection_root(
                D_EVENTS,
                self.events.iter().map(MeshEvent::public_record),
            ),
            nullifier_root: collection_root(
                D_NULLIFIERS,
                self.consumed_nullifiers
                    .iter()
                    .map(|nullifier| json!({ "nullifier": nullifier })),
            ),
        };
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

fn collection_root(domain: &str, records: impl Iterator<Item = Value>) -> String {
    let leaves = records.collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(D_STATE, &[HashPart::Json(record)], 32)
}

fn fixture_hash(domain: &str, seed: &str) -> String {
    domain_hash(
        "PL2-FAST-PQ-CONF-PARALLEL-STATE-WITNESS-PREFETCH-MESH:FIXTURE",
        &[HashPart::Str(domain), HashPart::Str(seed)],
        32,
    )
}

fn next_id(prefix: &str, index: usize) -> String {
    format!("{prefix}-{index:06}")
}

fn set_json_field(record: &mut Value, key: &str, value: Value) {
    if let Value::Object(fields) = record {
        fields.insert(key.to_string(), value);
    }
}
