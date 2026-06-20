use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialSequencerExecutionReceiptGossipRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_SEQUENCER_EXECUTION_RECEIPT_GOSSIP_RUNTIME_PROTOCOL_VERSION:
    &str =
    "nebula-private-l2-fast-pq-confidential-sequencer-execution-receipt-gossip-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_SEQUENCER_EXECUTION_RECEIPT_GOSSIP_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ENCRYPTED_RECEIPT_SHARD_SUITE: &str =
    "ml-kem-1024+xwing-confidential-execution-receipt-shards-v1";
pub const PQ_SEQUENCER_ATTESTATION_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256f-sequencer-execution-receipt-attestation-v1";
pub const GOSSIP_FANOUT_SUITE: &str = "private-l2-fast-receipt-gossip-fanout-lanes-v1";
pub const PRECONFIRMATION_RECEIPT_SUITE: &str =
    "private-l2-confidential-preconfirmation-receipt-root-v1";
pub const CACHE_LEASE_SUITE: &str = "private-l2-receipt-gossip-cache-lease-root-v1";
pub const INVALIDATION_FENCE_SUITE: &str = "private-l2-receipt-gossip-invalidation-fence-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "private-l2-low-fee-receipt-gossip-rebate-v1";
pub const PRIVACY_REDACTION_BUDGET_SUITE: &str =
    "private-l2-confidential-receipt-redaction-budget-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "operator-safe-confidential-sequencer-execution-receipt-gossip-public-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 4_480_000;
pub const DEVNET_EPOCH: u64 = 13_824;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_SHARD_COUNT: u16 = 16;
pub const DEFAULT_FANOUT_PEERS: u16 = 12;
pub const DEFAULT_PRECONFIRMATION_TARGET_MS: u64 = 110;
pub const DEFAULT_CACHE_LEASE_TTL_SLOTS: u64 = 64;
pub const DEFAULT_INVALIDATION_FENCE_TTL_SLOTS: u64 = 192;
pub const DEFAULT_RECEIPT_SHARD_TTL_SLOTS: u64 = 96;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 1_400;
pub const DEFAULT_MAX_REDACTION_BUDGET_UNITS: u64 = 1_000_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;

const D_STATE: &str = "PL2-FAST-PQ-CONF-SEQUENCER-EXECUTION-RECEIPT-GOSSIP:STATE";
const D_CONFIG: &str = "PL2-FAST-PQ-CONF-SEQUENCER-EXECUTION-RECEIPT-GOSSIP:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-SEQUENCER-EXECUTION-RECEIPT-GOSSIP:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-SEQUENCER-EXECUTION-RECEIPT-GOSSIP:ROOTS";
const D_SHARDS: &str = "PL2-FAST-PQ-CONF-SEQUENCER-EXECUTION-RECEIPT-GOSSIP:SHARDS";
const D_ATTESTATIONS: &str = "PL2-FAST-PQ-CONF-SEQUENCER-EXECUTION-RECEIPT-GOSSIP:ATTESTATIONS";
const D_FANOUT: &str = "PL2-FAST-PQ-CONF-SEQUENCER-EXECUTION-RECEIPT-GOSSIP:FANOUT";
const D_PRECONFIRMATIONS: &str =
    "PL2-FAST-PQ-CONF-SEQUENCER-EXECUTION-RECEIPT-GOSSIP:PRECONFIRMATIONS";
const D_LEASES: &str = "PL2-FAST-PQ-CONF-SEQUENCER-EXECUTION-RECEIPT-GOSSIP:CACHE-LEASES";
const D_FENCES: &str = "PL2-FAST-PQ-CONF-SEQUENCER-EXECUTION-RECEIPT-GOSSIP:INVALIDATION-FENCES";
const D_LATENCY: &str = "PL2-FAST-PQ-CONF-SEQUENCER-EXECUTION-RECEIPT-GOSSIP:LATENCY-BUCKETS";
const D_REBATES: &str = "PL2-FAST-PQ-CONF-SEQUENCER-EXECUTION-RECEIPT-GOSSIP:REBATES";
const D_REDACTIONS: &str = "PL2-FAST-PQ-CONF-SEQUENCER-EXECUTION-RECEIPT-GOSSIP:REDACTION-BUDGETS";
const D_PUBLIC: &str = "PL2-FAST-PQ-CONF-SEQUENCER-EXECUTION-RECEIPT-GOSSIP:PUBLIC";
const D_DETERMINISTIC: &str = "PL2-FAST-PQ-CONF-SEQUENCER-EXECUTION-RECEIPT-GOSSIP:DETERMINISTIC";
const D_DEVNET: &str = "PL2-FAST-PQ-CONF-SEQUENCER-EXECUTION-RECEIPT-GOSSIP:DEVNET";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptLaneClass {
    Wallet,
    Payment,
    ContractCall,
    BridgeExit,
    Defi,
    ProofCarry,
    ReorgRecovery,
    OperatorControl,
}

impl ReceiptLaneClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::Payment => "payment",
            Self::ContractCall => "contract_call",
            Self::BridgeExit => "bridge_exit",
            Self::Defi => "defi",
            Self::ProofCarry => "proof_carry",
            Self::ReorgRecovery => "reorg_recovery",
            Self::OperatorControl => "operator_control",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::ReorgRecovery => 10_000,
            Self::BridgeExit => 9_500,
            Self::Defi => 9_000,
            Self::Payment => 8_700,
            Self::ContractCall => 8_200,
            Self::ProofCarry => 7_800,
            Self::Wallet => 7_200,
            Self::OperatorControl => 6_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardStatus {
    Open,
    Gossiping,
    Leased,
    Fenced,
    Redacted,
    Expired,
}

impl ShardStatus {
    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::Gossiping | Self::Leased)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Observed,
    Verified,
    Aggregated,
    Challenged,
    Slashed,
    Expired,
}

impl AttestationStatus {
    pub fn accepted(self) -> bool {
        matches!(self, Self::Verified | Self::Aggregated)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FanoutMode {
    Fast,
    PrivacyFirst,
    LowFeeBatch,
    Recovery,
    Paused,
}

impl FanoutMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::PrivacyFirst => "privacy_first",
            Self::LowFeeBatch => "low_fee_batch",
            Self::Recovery => "recovery",
            Self::Paused => "paused",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreconfirmationStatus {
    Pending,
    Broadcast,
    Quorum,
    Finalized,
    Invalidated,
    Redacted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseStatus {
    Offered,
    Active,
    Renewed,
    Released,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceStatus {
    Armed,
    Triggered,
    Superseded,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LatencyBucketKind {
    Under25Ms,
    Under50Ms,
    Under100Ms,
    Under250Ms,
    Under500Ms,
    Over500Ms,
}

impl LatencyBucketKind {
    pub fn upper_bound_ms(self) -> Option<u64> {
        match self {
            Self::Under25Ms => Some(25),
            Self::Under50Ms => Some(50),
            Self::Under100Ms => Some(100),
            Self::Under250Ms => Some(250),
            Self::Under500Ms => Some(500),
            Self::Over500Ms => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Quoted,
    Reserved,
    Settled,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub shard_count: u16,
    pub fanout_peers: u16,
    pub preconfirmation_target_ms: u64,
    pub cache_lease_ttl_slots: u64,
    pub invalidation_fence_ttl_slots: u64,
    pub receipt_shard_ttl_slots: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub low_fee_rebate_bps: u64,
    pub max_redaction_budget_units: u64,
    pub enable_encrypted_receipt_shards: bool,
    pub enable_pq_sequencer_attestations: bool,
    pub enable_low_fee_rebates: bool,
    pub enable_operator_safe_public_records: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            shard_count: DEFAULT_SHARD_COUNT,
            fanout_peers: DEFAULT_FANOUT_PEERS,
            preconfirmation_target_ms: DEFAULT_PRECONFIRMATION_TARGET_MS,
            cache_lease_ttl_slots: DEFAULT_CACHE_LEASE_TTL_SLOTS,
            invalidation_fence_ttl_slots: DEFAULT_INVALIDATION_FENCE_TTL_SLOTS,
            receipt_shard_ttl_slots: DEFAULT_RECEIPT_SHARD_TTL_SLOTS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            max_redaction_budget_units: DEFAULT_MAX_REDACTION_BUDGET_UNITS,
            enable_encrypted_receipt_shards: true,
            enable_pq_sequencer_attestations: true,
            enable_low_fee_rebates: true,
            enable_operator_safe_public_records: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(D_CONFIG, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub encrypted_receipt_shards_gossiped: u64,
    pub encrypted_receipts_redacted: u64,
    pub pq_sequencer_attestations_verified: u64,
    pub gossip_fanout_broadcasts: u64,
    pub preconfirmation_receipts_quorum: u64,
    pub cache_leases_active: u64,
    pub invalidation_fences_triggered: u64,
    pub latency_samples_recorded: u64,
    pub low_fee_rebates_reserved: u64,
    pub low_fee_rebates_settled: u64,
    pub redaction_budget_units_spent: u64,
    pub public_records_emitted: u64,
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
    pub encrypted_receipt_shards_root: String,
    pub pq_sequencer_attestations_root: String,
    pub gossip_fanout_lanes_root: String,
    pub preconfirmation_receipts_root: String,
    pub cache_leases_root: String,
    pub invalidation_fences_root: String,
    pub latency_buckets_root: String,
    pub low_fee_rebates_root: String,
    pub privacy_redaction_budgets_root: String,
    pub public_records_root: String,
    pub deterministic_roots_root: String,
    pub state_root: String,
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
pub struct EncryptedReceiptShard {
    pub shard_id: String,
    pub lane: ReceiptLaneClass,
    pub status: ShardStatus,
    pub sequencer_id: String,
    pub encrypted_receipt_count: u32,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub expires_at_slot: u64,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub redacted_payload_root: String,
    pub shard_root: String,
}

impl EncryptedReceiptShard {
    pub fn public_record(&self) -> Value {
        json!({
            "shard_id": self.shard_id,
            "lane": self.lane.as_str(),
            "status": self.status,
            "sequencer_id": self.sequencer_id,
            "encrypted_receipt_count": self.encrypted_receipt_count,
            "first_sequence": self.first_sequence,
            "last_sequence": self.last_sequence,
            "expires_at_slot": self.expires_at_slot,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "redacted_payload_root": self.redacted_payload_root,
            "shard_root": self.shard_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSequencerAttestation {
    pub attestation_id: String,
    pub shard_id: String,
    pub sequencer_id: String,
    pub status: AttestationStatus,
    pub pq_suite: String,
    pub security_bits: u16,
    pub receipt_root: String,
    pub signature_root: String,
    pub attestation_root: String,
}

impl PqSequencerAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "shard_id": self.shard_id,
            "sequencer_id": self.sequencer_id,
            "status": self.status,
            "pq_suite": self.pq_suite,
            "security_bits": self.security_bits,
            "receipt_root": self.receipt_root,
            "signature_root": self.signature_root,
            "attestation_root": self.attestation_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GossipFanoutLane {
    pub fanout_id: String,
    pub shard_id: String,
    pub lane: ReceiptLaneClass,
    pub mode: FanoutMode,
    pub target_peers: u16,
    pub reached_peers: u16,
    pub observed_latency_ms: u64,
    pub priority_weight: u64,
    pub fanout_root: String,
}

impl GossipFanoutLane {
    pub fn public_record(&self) -> Value {
        json!({
            "fanout_id": self.fanout_id,
            "shard_id": self.shard_id,
            "lane": self.lane.as_str(),
            "mode": self.mode.as_str(),
            "target_peers": self.target_peers,
            "reached_peers": self.reached_peers,
            "observed_latency_ms": self.observed_latency_ms,
            "priority_weight": self.priority_weight,
            "fanout_root": self.fanout_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreconfirmationReceipt {
    pub preconfirmation_id: String,
    pub shard_id: String,
    pub attestation_id: String,
    pub status: PreconfirmationStatus,
    pub slot: u64,
    pub target_ms: u64,
    pub observed_ms: u64,
    pub deterministic_root: String,
    pub preconfirmation_root: String,
}

impl PreconfirmationReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "preconfirmation_id": self.preconfirmation_id,
            "shard_id": self.shard_id,
            "attestation_id": self.attestation_id,
            "status": self.status,
            "slot": self.slot,
            "target_ms": self.target_ms,
            "observed_ms": self.observed_ms,
            "deterministic_root": self.deterministic_root,
            "preconfirmation_root": self.preconfirmation_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CacheLease {
    pub lease_id: String,
    pub shard_id: String,
    pub holder_id: String,
    pub status: LeaseStatus,
    pub leased_at_slot: u64,
    pub expires_at_slot: u64,
    pub lease_root: String,
}

impl CacheLease {
    pub fn public_record(&self) -> Value {
        json!({
            "lease_id": self.lease_id,
            "shard_id": self.shard_id,
            "holder_id": self.holder_id,
            "status": self.status,
            "leased_at_slot": self.leased_at_slot,
            "expires_at_slot": self.expires_at_slot,
            "lease_root": self.lease_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvalidationFence {
    pub fence_id: String,
    pub shard_id: String,
    pub status: FenceStatus,
    pub reason_code: String,
    pub armed_at_slot: u64,
    pub expires_at_slot: u64,
    pub fence_root: String,
}

impl InvalidationFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "shard_id": self.shard_id,
            "status": self.status,
            "reason_code": self.reason_code,
            "armed_at_slot": self.armed_at_slot,
            "expires_at_slot": self.expires_at_slot,
            "fence_root": self.fence_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LatencyBucket {
    pub bucket_id: String,
    pub lane: ReceiptLaneClass,
    pub bucket: LatencyBucketKind,
    pub sample_count: u64,
    pub p50_ms: u64,
    pub p95_ms: u64,
    pub bucket_root: String,
}

impl LatencyBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "lane": self.lane.as_str(),
            "bucket": self.bucket,
            "upper_bound_ms": self.bucket.upper_bound_ms(),
            "sample_count": self.sample_count,
            "p50_ms": self.p50_ms,
            "p95_ms": self.p95_ms,
            "bucket_root": self.bucket_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub preconfirmation_id: String,
    pub status: RebateStatus,
    pub fee_asset_id: String,
    pub execution_fee_micros: u64,
    pub rebate_bps: u64,
    pub rebate_micros: u64,
    pub settlement_root: String,
    pub rebate_root: String,
}

impl LowFeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "preconfirmation_id": self.preconfirmation_id,
            "status": self.status,
            "fee_asset_id": self.fee_asset_id,
            "execution_fee_micros": self.execution_fee_micros,
            "rebate_bps": self.rebate_bps,
            "rebate_micros": self.rebate_micros,
            "settlement_root": self.settlement_root,
            "rebate_root": self.rebate_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub lane: ReceiptLaneClass,
    pub total_units: u64,
    pub spent_units: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub redaction_root: String,
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "lane": self.lane.as_str(),
            "total_units": self.total_units,
            "spent_units": self.spent_units,
            "remaining_units": self.total_units.saturating_sub(self.spent_units),
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "redaction_root": self.redaction_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeterministicReceiptRoot {
    pub root_id: String,
    pub shard_id: String,
    pub lane: ReceiptLaneClass,
    pub slot: u64,
    pub shard_root: String,
    pub attestation_root: String,
    pub fanout_root: String,
    pub deterministic_root: String,
}

impl DeterministicReceiptRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "root_id": self.root_id,
            "shard_id": self.shard_id,
            "lane": self.lane.as_str(),
            "slot": self.slot,
            "shard_root": self.shard_root,
            "attestation_root": self.attestation_root,
            "fanout_root": self.fanout_root,
            "deterministic_root": self.deterministic_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorPublicRecord {
    pub record_id: String,
    pub height: u64,
    pub epoch: u64,
    pub shard_count: usize,
    pub attestation_count: usize,
    pub fanout_lane_count: usize,
    pub preconfirmation_count: usize,
    pub cache_lease_count: usize,
    pub invalidation_fence_count: usize,
    pub low_fee_rebate_micros: u64,
    pub redaction_budget_remaining_units: u64,
    pub roots: Roots,
    pub record_root: String,
}

impl OperatorPublicRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "height": self.height,
            "epoch": self.epoch,
            "shard_count": self.shard_count,
            "attestation_count": self.attestation_count,
            "fanout_lane_count": self.fanout_lane_count,
            "preconfirmation_count": self.preconfirmation_count,
            "cache_lease_count": self.cache_lease_count,
            "invalidation_fence_count": self.invalidation_fence_count,
            "low_fee_rebate_micros": self.low_fee_rebate_micros,
            "redaction_budget_remaining_units": self.redaction_budget_remaining_units,
            "roots": self.roots.public_record(),
            "record_root": self.record_root,
            "operator_safe": true,
            "encrypted_receipt_shards_redacted": true
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_slot: u64,
    pub encrypted_receipt_shards: BTreeMap<String, EncryptedReceiptShard>,
    pub pq_sequencer_attestations: BTreeMap<String, PqSequencerAttestation>,
    pub gossip_fanout_lanes: BTreeMap<String, GossipFanoutLane>,
    pub preconfirmation_receipts: BTreeMap<String, PreconfirmationReceipt>,
    pub cache_leases: BTreeMap<String, CacheLease>,
    pub invalidation_fences: BTreeMap<String, InvalidationFence>,
    pub latency_buckets: BTreeMap<String, LatencyBucket>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub privacy_redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub deterministic_roots: BTreeMap<String, DeterministicReceiptRoot>,
    pub public_records: BTreeMap<String, OperatorPublicRecord>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            current_slot: DEVNET_EPOCH * 32,
            encrypted_receipt_shards: BTreeMap::new(),
            pq_sequencer_attestations: BTreeMap::new(),
            gossip_fanout_lanes: BTreeMap::new(),
            preconfirmation_receipts: BTreeMap::new(),
            cache_leases: BTreeMap::new(),
            invalidation_fences: BTreeMap::new(),
            latency_buckets: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            privacy_redaction_budgets: BTreeMap::new(),
            deterministic_roots: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        state.seed_devnet();
        state.refresh_roots();
        state.emit_public_record();
        state.refresh_roots();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        state.counters.low_fee_rebates_settled =
            state.counters.low_fee_rebates_settled.saturating_add(1);
        if let Some(rebate) = state.low_fee_rebates.values_mut().next() {
            rebate.status = RebateStatus::Settled;
            rebate.rebate_root = record_root("LOW-FEE-REBATE", &rebate.public_record());
        }
        if let Some(fence) = state.invalidation_fences.values_mut().next() {
            fence.status = FenceStatus::Triggered;
            fence.fence_root = record_root("INVALIDATION-FENCE", &fence.public_record());
            state.counters.invalidation_fences_triggered = state
                .counters
                .invalidation_fences_triggered
                .saturating_add(1);
        }
        state.refresh_roots();
        state.emit_public_record();
        state.refresh_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "public_record_scheme": PUBLIC_RECORD_SCHEME,
            "current_slot": self.current_slot,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "encrypted_receipt_shard_count": self.encrypted_receipt_shards.len(),
            "pq_sequencer_attestation_count": self.pq_sequencer_attestations.len(),
            "gossip_fanout_lane_count": self.gossip_fanout_lanes.len(),
            "preconfirmation_receipt_count": self.preconfirmation_receipts.len(),
            "cache_lease_count": self.cache_leases.len(),
            "invalidation_fence_count": self.invalidation_fences.len(),
            "latency_bucket_count": self.latency_buckets.len(),
            "low_fee_rebate_count": self.low_fee_rebates.len(),
            "privacy_redaction_budget_count": self.privacy_redaction_budgets.len(),
            "deterministic_root_count": self.deterministic_roots.len(),
            "public_records": public_record_map(&self.public_records),
            "operator_safe": true,
            "encrypted_receipt_payloads_redacted": true
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(D_STATE, &self.public_record())
    }

    pub fn refresh_roots(&mut self) {
        let mut roots = Roots {
            config_root: self.config.root(),
            counters_root: self.counters.root(),
            encrypted_receipt_shards_root: merkle_records(D_SHARDS, &self.encrypted_receipt_shards),
            pq_sequencer_attestations_root: merkle_records(
                D_ATTESTATIONS,
                &self.pq_sequencer_attestations,
            ),
            gossip_fanout_lanes_root: merkle_records(D_FANOUT, &self.gossip_fanout_lanes),
            preconfirmation_receipts_root: merkle_records(
                D_PRECONFIRMATIONS,
                &self.preconfirmation_receipts,
            ),
            cache_leases_root: merkle_records(D_LEASES, &self.cache_leases),
            invalidation_fences_root: merkle_records(D_FENCES, &self.invalidation_fences),
            latency_buckets_root: merkle_records(D_LATENCY, &self.latency_buckets),
            low_fee_rebates_root: merkle_records(D_REBATES, &self.low_fee_rebates),
            privacy_redaction_budgets_root: merkle_records(
                D_REDACTIONS,
                &self.privacy_redaction_budgets,
            ),
            public_records_root: merkle_records(D_PUBLIC, &self.public_records),
            deterministic_roots_root: merkle_records(D_DETERMINISTIC, &self.deterministic_roots),
            state_root: String::new(),
        };
        roots.state_root = payload_root(D_ROOTS, &roots.public_record());
        self.roots = roots;
    }

    fn seed_devnet(&mut self) {
        let lanes = [
            ReceiptLaneClass::Wallet,
            ReceiptLaneClass::Payment,
            ReceiptLaneClass::ContractCall,
            ReceiptLaneClass::BridgeExit,
            ReceiptLaneClass::Defi,
            ReceiptLaneClass::ProofCarry,
        ];
        let mut live_shards = BTreeSet::new();
        for (index, lane) in lanes.iter().enumerate() {
            let shard_id = format!("receipt-shard-devnet-{:02}", index + 1);
            live_shards.insert(shard_id.clone());
            let mut shard = EncryptedReceiptShard {
                shard_id: shard_id.clone(),
                lane: *lane,
                status: if index == 5 {
                    ShardStatus::Redacted
                } else {
                    ShardStatus::Gossiping
                },
                sequencer_id: format!("sequencer-devnet-{:02}", (index % 3) + 1),
                encrypted_receipt_count: 512 + index as u32 * 96,
                first_sequence: 100_000 + index as u64 * 10_000,
                last_sequence: 100_511 + index as u64 * 10_000,
                expires_at_slot: self
                    .current_slot
                    .saturating_add(self.config.receipt_shard_ttl_slots),
                ciphertext_root: dev_hash("ciphertext-root", index as u64),
                nullifier_root: dev_hash("nullifier-root", index as u64),
                redacted_payload_root: dev_hash("redacted-payload-root", index as u64),
                shard_root: String::new(),
            };
            shard.shard_root = record_root("ENCRYPTED-RECEIPT-SHARD", &shard.public_record());
            self.counters.encrypted_receipt_shards_gossiped = self
                .counters
                .encrypted_receipt_shards_gossiped
                .saturating_add(shard.encrypted_receipt_count as u64);
            if shard.status == ShardStatus::Redacted {
                self.counters.encrypted_receipts_redacted = self
                    .counters
                    .encrypted_receipts_redacted
                    .saturating_add(shard.encrypted_receipt_count as u64);
            }
            self.encrypted_receipt_shards
                .insert(shard_id.clone(), shard);

            let mut attestation = PqSequencerAttestation {
                attestation_id: format!("pq-sequencer-attestation-devnet-{:02}", index + 1),
                shard_id: shard_id.clone(),
                sequencer_id: format!("sequencer-devnet-{:02}", (index % 3) + 1),
                status: AttestationStatus::Verified,
                pq_suite: PQ_SEQUENCER_ATTESTATION_SUITE.to_string(),
                security_bits: self.config.min_pq_security_bits,
                receipt_root: dev_hash("attested-execution-receipt", index as u64),
                signature_root: dev_hash("pq-sequencer-signature", index as u64),
                attestation_root: String::new(),
            };
            attestation.attestation_root =
                record_root("PQ-SEQUENCER-ATTESTATION", &attestation.public_record());
            if attestation.status.accepted() {
                self.counters.pq_sequencer_attestations_verified = self
                    .counters
                    .pq_sequencer_attestations_verified
                    .saturating_add(1);
            }
            self.pq_sequencer_attestations
                .insert(attestation.attestation_id.clone(), attestation);

            let mode = if matches!(lane, ReceiptLaneClass::Wallet | ReceiptLaneClass::Payment) {
                FanoutMode::LowFeeBatch
            } else if matches!(lane, ReceiptLaneClass::BridgeExit) {
                FanoutMode::Fast
            } else {
                FanoutMode::PrivacyFirst
            };
            let mut fanout = GossipFanoutLane {
                fanout_id: format!("fanout-devnet-{:02}", index + 1),
                shard_id: shard_id.clone(),
                lane: *lane,
                mode,
                target_peers: self.config.fanout_peers,
                reached_peers: self.config.fanout_peers.saturating_sub(index as u16 % 3),
                observed_latency_ms: 40 + index as u64 * 17,
                priority_weight: lane.priority_weight(),
                fanout_root: String::new(),
            };
            fanout.fanout_root = record_root("GOSSIP-FANOUT-LANE", &fanout.public_record());
            self.counters.gossip_fanout_broadcasts = self
                .counters
                .gossip_fanout_broadcasts
                .saturating_add(fanout.reached_peers as u64);
            self.gossip_fanout_lanes
                .insert(fanout.fanout_id.clone(), fanout);

            let shard_root = self
                .encrypted_receipt_shards
                .get(&shard_id)
                .map(|shard| shard.shard_root.clone())
                .unwrap_or_default();
            let attestation_id = format!("pq-sequencer-attestation-devnet-{:02}", index + 1);
            let attestation_root = self
                .pq_sequencer_attestations
                .get(&attestation_id)
                .map(|attestation| attestation.attestation_root.clone())
                .unwrap_or_default();
            let fanout_id = format!("fanout-devnet-{:02}", index + 1);
            let fanout_root = self
                .gossip_fanout_lanes
                .get(&fanout_id)
                .map(|fanout| fanout.fanout_root.clone())
                .unwrap_or_default();
            let deterministic_root = deterministic_receipt_root(
                &shard_id,
                *lane,
                self.current_slot + index as u64,
                &shard_root,
                &attestation_root,
                &fanout_root,
            );
            let mut deterministic = DeterministicReceiptRoot {
                root_id: format!("deterministic-root-devnet-{:02}", index + 1),
                shard_id: shard_id.clone(),
                lane: *lane,
                slot: self.current_slot + index as u64,
                shard_root,
                attestation_root,
                fanout_root,
                deterministic_root: deterministic_root.clone(),
            };
            deterministic.deterministic_root =
                record_root("DETERMINISTIC-RECEIPT-ROOT", &deterministic.public_record());
            self.deterministic_roots
                .insert(deterministic.root_id.clone(), deterministic);

            if index < 5 {
                let mut preconfirmation = PreconfirmationReceipt {
                    preconfirmation_id: format!("preconfirmation-receipt-devnet-{:02}", index + 1),
                    shard_id: shard_id.clone(),
                    attestation_id,
                    status: PreconfirmationStatus::Quorum,
                    slot: self.current_slot + index as u64,
                    target_ms: self.config.preconfirmation_target_ms,
                    observed_ms: 58 + index as u64 * 9,
                    deterministic_root,
                    preconfirmation_root: String::new(),
                };
                preconfirmation.preconfirmation_root =
                    record_root("PRECONFIRMATION-RECEIPT", &preconfirmation.public_record());
                self.counters.preconfirmation_receipts_quorum = self
                    .counters
                    .preconfirmation_receipts_quorum
                    .saturating_add(1);
                self.preconfirmation_receipts
                    .insert(preconfirmation.preconfirmation_id.clone(), preconfirmation);
            }

            let mut lease = CacheLease {
                lease_id: format!("cache-lease-devnet-{:02}", index + 1),
                shard_id: shard_id.clone(),
                holder_id: format!("edge-cache-devnet-{:02}", (index % 4) + 1),
                status: LeaseStatus::Active,
                leased_at_slot: self.current_slot.saturating_sub(index as u64),
                expires_at_slot: self
                    .current_slot
                    .saturating_add(self.config.cache_lease_ttl_slots),
                lease_root: String::new(),
            };
            lease.lease_root = record_root("CACHE-LEASE", &lease.public_record());
            self.counters.cache_leases_active = self.counters.cache_leases_active.saturating_add(1);
            self.cache_leases.insert(lease.lease_id.clone(), lease);

            let bucket_kind = match index {
                0 => LatencyBucketKind::Under50Ms,
                1 | 2 => LatencyBucketKind::Under100Ms,
                3 | 4 => LatencyBucketKind::Under250Ms,
                _ => LatencyBucketKind::Under500Ms,
            };
            let mut bucket = LatencyBucket {
                bucket_id: format!("latency-bucket-devnet-{:02}", index + 1),
                lane: *lane,
                bucket: bucket_kind,
                sample_count: 1_024 + index as u64 * 128,
                p50_ms: 42 + index as u64 * 6,
                p95_ms: 88 + index as u64 * 17,
                bucket_root: String::new(),
            };
            bucket.bucket_root = record_root("LATENCY-BUCKET", &bucket.public_record());
            self.counters.latency_samples_recorded = self
                .counters
                .latency_samples_recorded
                .saturating_add(bucket.sample_count);
            self.latency_buckets
                .insert(bucket.bucket_id.clone(), bucket);

            if matches!(lane, ReceiptLaneClass::Wallet | ReceiptLaneClass::Payment) {
                let execution_fee_micros = 12 + index as u64 * 2;
                let rebate_micros =
                    execution_fee_micros.saturating_mul(self.config.low_fee_rebate_bps) / MAX_BPS;
                let mut rebate = LowFeeRebate {
                    rebate_id: format!("low-fee-rebate-devnet-{:02}", index + 1),
                    preconfirmation_id: format!("preconfirmation-receipt-devnet-{:02}", index + 1),
                    status: RebateStatus::Reserved,
                    fee_asset_id: self.config.fee_asset_id.clone(),
                    execution_fee_micros,
                    rebate_bps: self.config.low_fee_rebate_bps,
                    rebate_micros,
                    settlement_root: dev_hash("rebate-settlement", index as u64),
                    rebate_root: String::new(),
                };
                rebate.rebate_root = record_root("LOW-FEE-REBATE", &rebate.public_record());
                self.counters.low_fee_rebates_reserved =
                    self.counters.low_fee_rebates_reserved.saturating_add(1);
                self.low_fee_rebates
                    .insert(rebate.rebate_id.clone(), rebate);
            }

            let total_units = self.config.max_redaction_budget_units / lanes.len() as u64;
            let spent_units = 8_000 + index as u64 * 1_250;
            let mut budget = PrivacyRedactionBudget {
                budget_id: format!("redaction-budget-devnet-{:02}", index + 1),
                lane: *lane,
                total_units,
                spent_units,
                min_privacy_set_size: self.config.min_privacy_set_size,
                target_privacy_set_size: self.config.target_privacy_set_size,
                redaction_root: String::new(),
            };
            budget.redaction_root =
                record_root("PRIVACY-REDACTION-BUDGET", &budget.public_record());
            self.counters.redaction_budget_units_spent = self
                .counters
                .redaction_budget_units_spent
                .saturating_add(spent_units);
            self.privacy_redaction_budgets
                .insert(budget.budget_id.clone(), budget);
        }

        for (index, shard_id) in live_shards.iter().take(2).enumerate() {
            let mut fence = InvalidationFence {
                fence_id: format!("invalidation-fence-devnet-{:02}", index + 1),
                shard_id: shard_id.clone(),
                status: FenceStatus::Armed,
                reason_code: if index == 0 {
                    "cache_epoch_rollover"
                } else {
                    "receipt_root_superseded"
                }
                .to_string(),
                armed_at_slot: self.current_slot,
                expires_at_slot: self
                    .current_slot
                    .saturating_add(self.config.invalidation_fence_ttl_slots),
                fence_root: String::new(),
            };
            fence.fence_root = record_root("INVALIDATION-FENCE", &fence.public_record());
            self.invalidation_fences
                .insert(fence.fence_id.clone(), fence);
        }
    }

    fn emit_public_record(&mut self) {
        let low_fee_rebate_micros = self
            .low_fee_rebates
            .values()
            .map(|rebate| rebate.rebate_micros)
            .sum();
        let redaction_budget_remaining_units = self
            .privacy_redaction_budgets
            .values()
            .map(|budget| budget.total_units.saturating_sub(budget.spent_units))
            .sum();
        let mut record = OperatorPublicRecord {
            record_id: "operator-public-record-devnet-sequencer-execution-receipt-gossip"
                .to_string(),
            height: DEVNET_HEIGHT + self.counters.preconfirmation_receipts_quorum,
            epoch: DEVNET_EPOCH,
            shard_count: self.encrypted_receipt_shards.len(),
            attestation_count: self.pq_sequencer_attestations.len(),
            fanout_lane_count: self.gossip_fanout_lanes.len(),
            preconfirmation_count: self.preconfirmation_receipts.len(),
            cache_lease_count: self.cache_leases.len(),
            invalidation_fence_count: self.invalidation_fences.len(),
            low_fee_rebate_micros,
            redaction_budget_remaining_units,
            roots: self.roots.clone(),
            record_root: String::new(),
        };
        record.record_root = record_root("OPERATOR-PUBLIC-RECORD", &record.public_record());
        self.public_records.insert(record.record_id.clone(), record);
        self.counters.public_records_emitted = self.public_records.len() as u64;
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

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-SEQUENCER-EXECUTION-RECEIPT-GOSSIP-{}",
            domain
        ),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

fn deterministic_receipt_root(
    shard_id: &str,
    lane: ReceiptLaneClass,
    slot: u64,
    shard_root: &str,
    attestation_root: &str,
    fanout_root: &str,
) -> String {
    domain_hash(
        PRECONFIRMATION_RECEIPT_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(shard_id),
            HashPart::Str(lane.as_str()),
            HashPart::U64(slot),
            HashPart::Str(shard_root),
            HashPart::Str(attestation_root),
            HashPart::Str(fanout_root),
        ],
        32,
    )
}

fn merkle_records<T: Serialize>(domain: &str, records: &BTreeMap<String, T>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn public_record_map(records: &BTreeMap<String, OperatorPublicRecord>) -> BTreeMap<String, Value> {
    records
        .iter()
        .map(|(key, record)| (key.clone(), record.public_record()))
        .collect()
}

fn payload_root(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(value)],
        32,
    )
}

fn dev_hash(label: &str, index: u64) -> String {
    domain_hash(
        D_DEVNET,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(index),
        ],
        32,
    )
}
