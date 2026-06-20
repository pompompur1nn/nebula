use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialParallelExecutionReceiptCommitteeRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_EXECUTION_RECEIPT_COMMITTEE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-parallel-execution-receipt-committee-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_EXECUTION_RECEIPT_COMMITTEE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-parallel-execution-receipt-committee-v1";
pub const RECEIPT_SHARD_ENCRYPTION_SUITE: &str =
    "ML-KEM-1024+xwing-confidential-execution-receipt-shard-envelope-v1";
pub const DETERMINISTIC_ROOT_SCHEME: &str =
    "canonical-json-merkle-roots-only-no-plaintext-receipt-payloads-v1";
pub const DEVNET_L2_HEIGHT: u64 = 3_240_000;
pub const DEVNET_EPOCH: u64 = 12_960;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_REBATE_ASSET_ID: &str = "parallel-execution-receipt-rebate-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_COMMITTEE_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_PRECONFIRMATION_TARGET_MS: u64 = 180;
pub const DEFAULT_CACHE_LEASE_TTL_SLOTS: u64 = 96;
pub const DEFAULT_INVALIDATION_FENCE_TTL_SLOTS: u64 = 384;
pub const DEFAULT_MAX_REDACTION_UNITS_PER_RECEIPT: u64 = 64;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 5;
pub const DEFAULT_MAX_EXECUTION_LANES: usize = 131_072;
pub const DEFAULT_MAX_COMMITTEES: usize = 16_384;
pub const DEFAULT_MAX_RECEIPT_SHARDS: usize = 1_048_576;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_CACHE_LEASES: usize = 1_048_576;
pub const DEFAULT_MAX_INVALIDATION_FENCES: usize = 524_288;
pub const DEFAULT_MAX_PRECONFIRMATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_REBATES: usize = 2_097_152;
pub const DEFAULT_MAX_LATENCY_BUCKETS: usize = 64;
pub const MAX_BPS: u64 = 10_000;

const D_STATE: &str = "PL2-FAST-PQ-CONF-PARALLEL-EXEC-RECEIPT-COMMITTEE:STATE";
const D_CONFIG: &str = "PL2-FAST-PQ-CONF-PARALLEL-EXEC-RECEIPT-COMMITTEE:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-PARALLEL-EXEC-RECEIPT-COMMITTEE:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-PARALLEL-EXEC-RECEIPT-COMMITTEE:ROOTS";
const D_COMMITTEES: &str = "PL2-FAST-PQ-CONF-PARALLEL-EXEC-RECEIPT-COMMITTEE:COMMITTEES";
const D_SHARDS: &str = "PL2-FAST-PQ-CONF-PARALLEL-EXEC-RECEIPT-COMMITTEE:SHARDS";
const D_ATTESTATIONS: &str = "PL2-FAST-PQ-CONF-PARALLEL-EXEC-RECEIPT-COMMITTEE:ATTESTATIONS";
const D_LANES: &str = "PL2-FAST-PQ-CONF-PARALLEL-EXEC-RECEIPT-COMMITTEE:LANES";
const D_PRECONFIRMATIONS: &str =
    "PL2-FAST-PQ-CONF-PARALLEL-EXEC-RECEIPT-COMMITTEE:PRECONFIRMATIONS";
const D_LEASES: &str = "PL2-FAST-PQ-CONF-PARALLEL-EXEC-RECEIPT-COMMITTEE:LEASES";
const D_FENCES: &str = "PL2-FAST-PQ-CONF-PARALLEL-EXEC-RECEIPT-COMMITTEE:FENCES";
const D_LATENCY_BUCKETS: &str = "PL2-FAST-PQ-CONF-PARALLEL-EXEC-RECEIPT-COMMITTEE:LATENCY-BUCKETS";
const D_REBATES: &str = "PL2-FAST-PQ-CONF-PARALLEL-EXEC-RECEIPT-COMMITTEE:REBATES";
const D_REDACTIONS: &str = "PL2-FAST-PQ-CONF-PARALLEL-EXEC-RECEIPT-COMMITTEE:REDACTIONS";

macro_rules! ensure {
    ($condition:expr, $message:literal $(,)?) => {
        if !$condition {
            return Err($message.to_string());
        }
    };
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    Devnet,
    Demo,
    Canary,
    MainnetCandidate,
}

impl RuntimeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::Demo => "demo",
            Self::Canary => "canary",
            Self::MainnetCandidate => "mainnet_candidate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionLaneKind {
    HotPath,
    ContractCall,
    TokenTransfer,
    BridgeExit,
    ProofCarry,
    LowFee,
    Watchtower,
    Backfill,
}

impl ExecutionLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HotPath => "hot_path",
            Self::ContractCall => "contract_call",
            Self::TokenTransfer => "token_transfer",
            Self::BridgeExit => "bridge_exit",
            Self::ProofCarry => "proof_carry",
            Self::LowFee => "low_fee",
            Self::Watchtower => "watchtower",
            Self::Backfill => "backfill",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Preconfirming,
    Saturated,
    LowFeeOnly,
    Fenced,
    Draining,
    Paused,
}

impl LaneStatus {
    pub fn accepts_execution(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Preconfirming | Self::Saturated | Self::LowFeeOnly
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardStatus {
    Encrypted,
    Routed,
    Attesting,
    Quorum,
    Preconfirmed,
    Settled,
    Invalidated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Observed,
    Accepted,
    Quorum,
    NeedsReplay,
    Rejected,
}

impl AttestationVerdict {
    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Accepted | Self::Quorum)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceReason {
    ReceiptRootSuperseded,
    LaneEquivocation,
    CacheLeaseExpired,
    PqAttestationMismatch,
    RedactionBudgetExceeded,
    LatencyBucketOverflow,
    EmergencyInvalidation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionScope {
    ReceiptShard,
    ExecutionTrace,
    CommitteePath,
    CacheLease,
    PreconfirmationMemo,
    RebateProof,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub mode: RuntimeMode,
    pub protocol_version: String,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub receipt_shard_encryption_suite: String,
    pub deterministic_root_scheme: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub committee_quorum_bps: u64,
    pub preconfirmation_target_ms: u64,
    pub cache_lease_ttl_slots: u64,
    pub invalidation_fence_ttl_slots: u64,
    pub max_redaction_units_per_receipt: u64,
    pub low_fee_rebate_bps: u64,
    pub max_execution_lanes: usize,
    pub max_committees: usize,
    pub max_receipt_shards: usize,
    pub max_attestations: usize,
    pub max_cache_leases: usize,
    pub max_invalidation_fences: usize,
    pub max_preconfirmations: usize,
    pub max_rebates: usize,
    pub max_latency_buckets: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            mode: RuntimeMode::Devnet,
            protocol_version: PROTOCOL_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            receipt_shard_encryption_suite: RECEIPT_SHARD_ENCRYPTION_SUITE.to_string(),
            deterministic_root_scheme: DETERMINISTIC_ROOT_SCHEME.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEFAULT_REBATE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            committee_quorum_bps: DEFAULT_COMMITTEE_QUORUM_BPS,
            preconfirmation_target_ms: DEFAULT_PRECONFIRMATION_TARGET_MS,
            cache_lease_ttl_slots: DEFAULT_CACHE_LEASE_TTL_SLOTS,
            invalidation_fence_ttl_slots: DEFAULT_INVALIDATION_FENCE_TTL_SLOTS,
            max_redaction_units_per_receipt: DEFAULT_MAX_REDACTION_UNITS_PER_RECEIPT,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            max_execution_lanes: DEFAULT_MAX_EXECUTION_LANES,
            max_committees: DEFAULT_MAX_COMMITTEES,
            max_receipt_shards: DEFAULT_MAX_RECEIPT_SHARDS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_cache_leases: DEFAULT_MAX_CACHE_LEASES,
            max_invalidation_fences: DEFAULT_MAX_INVALIDATION_FENCES,
            max_preconfirmations: DEFAULT_MAX_PRECONFIRMATIONS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_latency_buckets: DEFAULT_MAX_LATENCY_BUCKETS,
        }
    }

    pub fn demo() -> Self {
        Self {
            mode: RuntimeMode::Demo,
            max_execution_lanes: 8,
            max_committees: 4,
            max_receipt_shards: 32,
            max_attestations: 64,
            max_cache_leases: 16,
            max_invalidation_fences: 8,
            max_preconfirmations: 32,
            max_rebates: 32,
            max_latency_buckets: 8,
            ..Self::devnet()
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch"
        );
        ensure!(
            self.min_pq_security_bits >= 256,
            "pq security below 256 bits"
        );
        ensure!(
            self.min_privacy_set_size > 0,
            "privacy set must be non-zero"
        );
        ensure!(
            self.committee_quorum_bps <= MAX_BPS,
            "committee quorum bps too large"
        );
        ensure!(
            self.low_fee_rebate_bps <= MAX_BPS,
            "low-fee rebate bps too large"
        );
        ensure!(
            self.preconfirmation_target_ms > 0,
            "preconfirmation target must be non-zero"
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "mode": self.mode.as_str(),
            "protocol_version": self.protocol_version,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": self.hash_suite,
            "pq_attestation_suite": self.pq_attestation_suite,
            "receipt_shard_encryption_suite": self.receipt_shard_encryption_suite,
            "deterministic_root_scheme": self.deterministic_root_scheme,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "committee_quorum_bps": self.committee_quorum_bps,
            "preconfirmation_target_ms": self.preconfirmation_target_ms,
            "cache_lease_ttl_slots": self.cache_lease_ttl_slots,
            "invalidation_fence_ttl_slots": self.invalidation_fence_ttl_slots,
            "max_redaction_units_per_receipt": self.max_redaction_units_per_receipt,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(D_CONFIG, &[HashPart::Json(&self.public_record())], 32)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub committees: u64,
    pub receipt_shards: u64,
    pub pq_attestations: u64,
    pub execution_lanes: u64,
    pub preconfirmation_receipts: u64,
    pub cache_leases: u64,
    pub invalidation_fences: u64,
    pub latency_buckets: u64,
    pub low_fee_rebates: u64,
    pub redaction_budgets: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "committees": self.committees,
            "receipt_shards": self.receipt_shards,
            "pq_attestations": self.pq_attestations,
            "execution_lanes": self.execution_lanes,
            "preconfirmation_receipts": self.preconfirmation_receipts,
            "cache_leases": self.cache_leases,
            "invalidation_fences": self.invalidation_fences,
            "latency_buckets": self.latency_buckets,
            "low_fee_rebates": self.low_fee_rebates,
            "redaction_budgets": self.redaction_budgets,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(D_COUNTERS, &[HashPart::Json(&self.public_record())], 32)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Committee {
    pub committee_id: String,
    pub epoch: u64,
    pub lane_ids: Vec<String>,
    pub member_commitment_root: String,
    pub threshold: u16,
    pub pq_public_key_root: String,
}

impl Committee {
    pub fn public_record(&self) -> Value {
        json!({
            "committee_id": self.committee_id,
            "epoch": self.epoch,
            "lane_ids": self.lane_ids,
            "member_commitment_root": self.member_commitment_root,
            "threshold": self.threshold,
            "pq_public_key_root": self.pq_public_key_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptShard {
    pub shard_id: String,
    pub lane_id: String,
    pub committee_id: String,
    pub encrypted_receipt_root: String,
    pub ciphertext_bytes: u64,
    pub status: ShardStatus,
    pub redaction_units: u64,
}

impl ReceiptShard {
    pub fn public_record(&self) -> Value {
        json!({
            "shard_id": self.shard_id,
            "lane_id": self.lane_id,
            "committee_id": self.committee_id,
            "encrypted_receipt_root": self.encrypted_receipt_root,
            "ciphertext_bytes": self.ciphertext_bytes,
            "status": self.status,
            "redaction_units": self.redaction_units,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCommitteeAttestation {
    pub attestation_id: String,
    pub committee_id: String,
    pub shard_id: String,
    pub signer_bitmap_root: String,
    pub signature_root: String,
    pub verdict: AttestationVerdict,
    pub attested_slot: u64,
}

impl PqCommitteeAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "committee_id": self.committee_id,
            "shard_id": self.shard_id,
            "signer_bitmap_root": self.signer_bitmap_root,
            "signature_root": self.signature_root,
            "verdict": self.verdict,
            "attested_slot": self.attested_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionFanoutLane {
    pub lane_id: String,
    pub kind: ExecutionLaneKind,
    pub status: LaneStatus,
    pub fanout_width: u16,
    pub pending_receipts: u64,
    pub deterministic_lane_root: String,
}

impl ExecutionFanoutLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "status": self.status,
            "accepts_execution": self.status.accepts_execution(),
            "fanout_width": self.fanout_width,
            "pending_receipts": self.pending_receipts,
            "deterministic_lane_root": self.deterministic_lane_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreconfirmationReceipt {
    pub receipt_id: String,
    pub shard_id: String,
    pub lane_id: String,
    pub committee_id: String,
    pub preconfirmation_root: String,
    pub latency_ms: u64,
    pub expires_at_slot: u64,
}

impl PreconfirmationReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "shard_id": self.shard_id,
            "lane_id": self.lane_id,
            "committee_id": self.committee_id,
            "preconfirmation_root": self.preconfirmation_root,
            "latency_ms": self.latency_ms,
            "expires_at_slot": self.expires_at_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CacheLease {
    pub lease_id: String,
    pub lane_id: String,
    pub shard_id: String,
    pub cache_root: String,
    pub holder_commitment: String,
    pub expires_at_slot: u64,
}

impl CacheLease {
    pub fn public_record(&self) -> Value {
        json!({
            "lease_id": self.lease_id,
            "lane_id": self.lane_id,
            "shard_id": self.shard_id,
            "cache_root": self.cache_root,
            "holder_commitment": self.holder_commitment,
            "expires_at_slot": self.expires_at_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvalidationFence {
    pub fence_id: String,
    pub lane_id: String,
    pub shard_id: String,
    pub reason: FenceReason,
    pub fence_root: String,
    pub expires_at_slot: u64,
}

impl InvalidationFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "lane_id": self.lane_id,
            "shard_id": self.shard_id,
            "reason": self.reason,
            "fence_root": self.fence_root,
            "expires_at_slot": self.expires_at_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LatencyBucket {
    pub bucket_id: String,
    pub upper_bound_ms: u64,
    pub receipt_count: u64,
    pub p95_latency_ms: u64,
}

impl LatencyBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "upper_bound_ms": self.upper_bound_ms,
            "receipt_count": self.receipt_count,
            "p95_latency_ms": self.p95_latency_ms,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub beneficiary_commitment: String,
    pub rebate_asset_id: String,
    pub rebate_micro_units: u64,
}

impl LowFeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "rebate_asset_id": self.rebate_asset_id,
            "rebate_micro_units": self.rebate_micro_units,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub receipt_id: String,
    pub scope: RedactionScope,
    pub units_reserved: u64,
    pub units_spent: u64,
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "receipt_id": self.receipt_id,
            "scope": self.scope,
            "units_reserved": self.units_reserved,
            "units_spent": self.units_spent,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub committees_root: String,
    pub receipt_shards_root: String,
    pub pq_attestations_root: String,
    pub execution_lanes_root: String,
    pub preconfirmation_receipts_root: String,
    pub cache_leases_root: String,
    pub invalidation_fences_root: String,
    pub latency_buckets_root: String,
    pub low_fee_rebates_root: String,
    pub privacy_redaction_budgets_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "committees_root": self.committees_root,
            "receipt_shards_root": self.receipt_shards_root,
            "pq_attestations_root": self.pq_attestations_root,
            "execution_lanes_root": self.execution_lanes_root,
            "preconfirmation_receipts_root": self.preconfirmation_receipts_root,
            "cache_leases_root": self.cache_leases_root,
            "invalidation_fences_root": self.invalidation_fences_root,
            "latency_buckets_root": self.latency_buckets_root,
            "low_fee_rebates_root": self.low_fee_rebates_root,
            "privacy_redaction_budgets_root": self.privacy_redaction_budgets_root,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(D_ROOTS, &[HashPart::Json(&self.public_record())], 32)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub committees: BTreeMap<String, Committee>,
    pub receipt_shards: BTreeMap<String, ReceiptShard>,
    pub pq_attestations: BTreeMap<String, PqCommitteeAttestation>,
    pub execution_lanes: BTreeMap<String, ExecutionFanoutLane>,
    pub preconfirmation_receipts: BTreeMap<String, PreconfirmationReceipt>,
    pub cache_leases: BTreeMap<String, CacheLease>,
    pub invalidation_fences: BTreeMap<String, InvalidationFence>,
    pub latency_buckets: BTreeMap<String, LatencyBucket>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub privacy_redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
}

impl State {
    pub fn devnet() -> Result<Self> {
        let mut state = Self::empty(Config::devnet())?;
        state.seed_fixture("devnet", 12)?;
        Ok(state)
    }

    pub fn demo() -> Result<Self> {
        let mut state = Self::empty(Config::demo())?;
        state.seed_fixture("demo", 4)?;
        Ok(state)
    }

    pub fn empty(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            committees: BTreeMap::new(),
            receipt_shards: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            execution_lanes: BTreeMap::new(),
            preconfirmation_receipts: BTreeMap::new(),
            cache_leases: BTreeMap::new(),
            invalidation_fences: BTreeMap::new(),
            latency_buckets: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            privacy_redaction_budgets: BTreeMap::new(),
        })
    }

    pub fn counters(&self) -> Counters {
        Counters {
            committees: self.committees.len() as u64,
            receipt_shards: self.receipt_shards.len() as u64,
            pq_attestations: self.pq_attestations.len() as u64,
            execution_lanes: self.execution_lanes.len() as u64,
            preconfirmation_receipts: self.preconfirmation_receipts.len() as u64,
            cache_leases: self.cache_leases.len() as u64,
            invalidation_fences: self.invalidation_fences.len() as u64,
            latency_buckets: self.latency_buckets.len() as u64,
            low_fee_rebates: self.low_fee_rebates.len() as u64,
            redaction_budgets: self.privacy_redaction_budgets.len() as u64,
        }
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.root(),
            counters_root: self.counters().root(),
            committees_root: map_root(D_COMMITTEES, &self.committees),
            receipt_shards_root: map_root(D_SHARDS, &self.receipt_shards),
            pq_attestations_root: map_root(D_ATTESTATIONS, &self.pq_attestations),
            execution_lanes_root: map_root(D_LANES, &self.execution_lanes),
            preconfirmation_receipts_root: map_root(
                D_PRECONFIRMATIONS,
                &self.preconfirmation_receipts,
            ),
            cache_leases_root: map_root(D_LEASES, &self.cache_leases),
            invalidation_fences_root: map_root(D_FENCES, &self.invalidation_fences),
            latency_buckets_root: map_root(D_LATENCY_BUCKETS, &self.latency_buckets),
            low_fee_rebates_root: map_root(D_REBATES, &self.low_fee_rebates),
            privacy_redaction_budgets_root: map_root(D_REDACTIONS, &self.privacy_redaction_budgets),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": self.config.chain_id,
            "devnet_l2_height": DEVNET_L2_HEIGHT,
            "devnet_epoch": DEVNET_EPOCH,
            "privacy_boundary": "public roots and commitments only",
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
            "deterministic_roots_root": roots.root(),
            "active_lane_ids": self.active_lane_ids(),
            "quorum_attestation_ids": self.quorum_attestation_ids(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(D_STATE, &[HashPart::Json(&self.public_record())], 32)
    }

    fn seed_fixture(&mut self, label: &str, lanes: usize) -> Result<()> {
        ensure!(
            lanes <= self.config.max_execution_lanes,
            "too many fixture lanes"
        );
        for index in 0..lanes {
            let lane_id = format!("{label}-lane-{index:03}");
            let committee_id = format!("{label}-committee-{:03}", index % 3);
            let shard_id = format!("{label}-receipt-shard-{index:03}");
            let receipt_id = format!("{label}-preconfirmation-{index:03}");

            self.execution_lanes.insert(
                lane_id.clone(),
                ExecutionFanoutLane {
                    lane_id: lane_id.clone(),
                    kind: lane_kind(index),
                    status: if index % 5 == 0 {
                        LaneStatus::LowFeeOnly
                    } else {
                        LaneStatus::Preconfirming
                    },
                    fanout_width: 8 + (index as u16 % 8),
                    pending_receipts: 128 + index as u64 * 17,
                    deterministic_lane_root: fixture_root("lane", &lane_id),
                },
            );

            self.committees
                .entry(committee_id.clone())
                .or_insert(Committee {
                    committee_id: committee_id.clone(),
                    epoch: DEVNET_EPOCH + index as u64,
                    lane_ids: vec![lane_id.clone()],
                    member_commitment_root: fixture_root("committee-members", &committee_id),
                    threshold: 19,
                    pq_public_key_root: fixture_root("committee-pq-keys", &committee_id),
                });

            self.receipt_shards.insert(
                shard_id.clone(),
                ReceiptShard {
                    shard_id: shard_id.clone(),
                    lane_id: lane_id.clone(),
                    committee_id: committee_id.clone(),
                    encrypted_receipt_root: fixture_root("encrypted-shard", &shard_id),
                    ciphertext_bytes: 16_384 + index as u64 * 257,
                    status: ShardStatus::Preconfirmed,
                    redaction_units: 8 + index as u64,
                },
            );

            self.pq_attestations.insert(
                format!("{label}-attestation-{index:03}"),
                PqCommitteeAttestation {
                    attestation_id: format!("{label}-attestation-{index:03}"),
                    committee_id: committee_id.clone(),
                    shard_id: shard_id.clone(),
                    signer_bitmap_root: fixture_root("signer-bitmap", &shard_id),
                    signature_root: fixture_root("pq-signature", &shard_id),
                    verdict: AttestationVerdict::Quorum,
                    attested_slot: DEVNET_L2_HEIGHT + index as u64,
                },
            );

            self.preconfirmation_receipts.insert(
                receipt_id.clone(),
                PreconfirmationReceipt {
                    receipt_id: receipt_id.clone(),
                    shard_id: shard_id.clone(),
                    lane_id: lane_id.clone(),
                    committee_id: committee_id.clone(),
                    preconfirmation_root: fixture_root("preconfirmation", &receipt_id),
                    latency_ms: 42 + index as u64 * 11,
                    expires_at_slot: DEVNET_L2_HEIGHT
                        + self.config.invalidation_fence_ttl_slots
                        + index as u64,
                },
            );

            self.cache_leases.insert(
                format!("{label}-lease-{index:03}"),
                CacheLease {
                    lease_id: format!("{label}-lease-{index:03}"),
                    lane_id: lane_id.clone(),
                    shard_id: shard_id.clone(),
                    cache_root: fixture_root("cache-lease", &shard_id),
                    holder_commitment: fixture_root("cache-holder", &lane_id),
                    expires_at_slot: DEVNET_L2_HEIGHT + self.config.cache_lease_ttl_slots,
                },
            );

            if index % 4 == 0 {
                self.invalidation_fences.insert(
                    format!("{label}-fence-{index:03}"),
                    InvalidationFence {
                        fence_id: format!("{label}-fence-{index:03}"),
                        lane_id: lane_id.clone(),
                        shard_id: shard_id.clone(),
                        reason: FenceReason::ReceiptRootSuperseded,
                        fence_root: fixture_root("invalidation-fence", &shard_id),
                        expires_at_slot: DEVNET_L2_HEIGHT
                            + self.config.invalidation_fence_ttl_slots,
                    },
                );
            }

            self.low_fee_rebates.insert(
                format!("{label}-rebate-{index:03}"),
                LowFeeRebate {
                    rebate_id: format!("{label}-rebate-{index:03}"),
                    receipt_id: receipt_id.clone(),
                    beneficiary_commitment: fixture_root("rebate-beneficiary", &receipt_id),
                    rebate_asset_id: self.config.rebate_asset_id.clone(),
                    rebate_micro_units: 10 + index as u64,
                },
            );

            self.privacy_redaction_budgets.insert(
                format!("{label}-redaction-{index:03}"),
                PrivacyRedactionBudget {
                    budget_id: format!("{label}-redaction-{index:03}"),
                    receipt_id,
                    scope: RedactionScope::ReceiptShard,
                    units_reserved: self.config.max_redaction_units_per_receipt,
                    units_spent: 8 + index as u64,
                },
            );
        }

        for (index, upper_bound_ms) in [50, 100, 180, 300, 600, 1_200].into_iter().enumerate() {
            self.latency_buckets.insert(
                format!("{label}-latency-{upper_bound_ms}ms"),
                LatencyBucket {
                    bucket_id: format!("{label}-latency-{upper_bound_ms}ms"),
                    upper_bound_ms,
                    receipt_count: 64 + index as u64 * 32,
                    p95_latency_ms: upper_bound_ms.saturating_sub(7),
                },
            );
        }

        Ok(())
    }

    fn active_lane_ids(&self) -> Vec<String> {
        self.execution_lanes
            .values()
            .filter(|lane| lane.status.accepts_execution())
            .map(|lane| lane.lane_id.clone())
            .collect()
    }

    fn quorum_attestation_ids(&self) -> Vec<String> {
        self.pq_attestations
            .values()
            .filter(|attestation| attestation.verdict.counts_for_quorum())
            .map(|attestation| attestation.attestation_id.clone())
            .collect()
    }
}

pub fn devnet() -> Result<State> {
    State::devnet()
}

pub fn demo() -> Result<State> {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn map_root<T>(domain: &'static str, map: &BTreeMap<String, T>) -> String
where
    T: PublicRecord,
{
    let leaves: Vec<Value> = map
        .iter()
        .map(|(key, value)| {
            Value::String(domain_hash(
                domain,
                &[
                    HashPart::Str(key.as_str()),
                    HashPart::Json(&value.public_record()),
                ],
                32,
            ))
        })
        .collect();
    merkle_root(domain, leaves.as_slice())
}

fn fixture_root(kind: &str, id: &str) -> String {
    domain_hash(
        "PL2-FAST-PQ-CONF-PARALLEL-EXEC-RECEIPT-COMMITTEE:FIXTURE",
        &[
            HashPart::Str(kind),
            HashPart::Str(id),
            HashPart::Str(PROTOCOL_VERSION),
        ],
        32,
    )
}

fn lane_kind(index: usize) -> ExecutionLaneKind {
    match index % 8 {
        0 => ExecutionLaneKind::HotPath,
        1 => ExecutionLaneKind::ContractCall,
        2 => ExecutionLaneKind::TokenTransfer,
        3 => ExecutionLaneKind::BridgeExit,
        4 => ExecutionLaneKind::ProofCarry,
        5 => ExecutionLaneKind::LowFee,
        6 => ExecutionLaneKind::Watchtower,
        _ => ExecutionLaneKind::Backfill,
    }
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for Committee {
    fn public_record(&self) -> Value {
        Committee::public_record(self)
    }
}

impl PublicRecord for ReceiptShard {
    fn public_record(&self) -> Value {
        ReceiptShard::public_record(self)
    }
}

impl PublicRecord for PqCommitteeAttestation {
    fn public_record(&self) -> Value {
        PqCommitteeAttestation::public_record(self)
    }
}

impl PublicRecord for ExecutionFanoutLane {
    fn public_record(&self) -> Value {
        ExecutionFanoutLane::public_record(self)
    }
}

impl PublicRecord for PreconfirmationReceipt {
    fn public_record(&self) -> Value {
        PreconfirmationReceipt::public_record(self)
    }
}

impl PublicRecord for CacheLease {
    fn public_record(&self) -> Value {
        CacheLease::public_record(self)
    }
}

impl PublicRecord for InvalidationFence {
    fn public_record(&self) -> Value {
        InvalidationFence::public_record(self)
    }
}

impl PublicRecord for LatencyBucket {
    fn public_record(&self) -> Value {
        LatencyBucket::public_record(self)
    }
}

impl PublicRecord for LowFeeRebate {
    fn public_record(&self) -> Value {
        LowFeeRebate::public_record(self)
    }
}

impl PublicRecord for PrivacyRedactionBudget {
    fn public_record(&self) -> Value {
        PrivacyRedactionBudget::public_record(self)
    }
}

#[allow(dead_code)]
fn unique_lane_set(state: &State) -> BTreeSet<String> {
    state.execution_lanes.keys().cloned().collect()
}
