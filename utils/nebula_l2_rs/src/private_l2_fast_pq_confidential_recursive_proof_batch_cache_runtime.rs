use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialRecursiveProofBatchCacheRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_RECURSIVE_PROOF_BATCH_CACHE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-recursive-proof-batch-cache-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_RECURSIVE_PROOF_BATCH_CACHE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 2_940_000;
pub const DEVNET_EPOCH: u64 = 9_408;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_VERIFIER_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-recursive-proof-batch-cache-v1";
pub const CONFIDENTIAL_WITNESS_SCHEME: &str =
    "redacted-confidential-witness-metadata-commitment-root-v1";
pub const RECURSIVE_AGGREGATE_SCHEME: &str =
    "fast-confidential-recursive-aggregate-proof-commitment-root-v1";
pub const CACHE_LEASE_SCHEME: &str = "low-fee-recursive-proof-cache-lease-root-v1";
pub const INVALIDATION_FENCE_SCHEME: &str =
    "recursive-proof-cache-invalidation-fence-nullifier-root-v1";
pub const FEE_REBATE_SCHEME: &str = "amortized-recursive-proof-cache-fee-rebate-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str = "privacy-preserving-proof-cache-operator-summary-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "private-l2-fast-pq-confidential-recursive-proof-batch-cache-public-record-v1";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_VERIFY_MS: u64 = 180;
pub const DEFAULT_HARD_VERIFY_MS: u64 = 750;
pub const DEFAULT_TARGET_CACHE_HIT_BPS: u64 = 8_500;
pub const DEFAULT_REUSE_FEE_BPS: u64 = 4;
pub const DEFAULT_MAX_REUSE_FEE_BPS: u64 = 9;
pub const DEFAULT_REBATE_BPS: u64 = 525;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_200;
pub const DEFAULT_MIN_AGGREGATE_DEPTH: u8 = 2;
pub const DEFAULT_MAX_AGGREGATE_DEPTH: u8 = 12;
pub const DEFAULT_SLOT_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_AGGREGATE_TTL_BLOCKS: u64 = 40;
pub const DEFAULT_LEASE_TTL_BLOCKS: u64 = 16;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_FENCE_TTL_BLOCKS: u64 = 128;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 512;
pub const DEFAULT_MAX_SLOTS: usize = 4_194_304;
pub const DEFAULT_MAX_AGGREGATES: usize = 1_048_576;
pub const DEFAULT_MAX_LEASES: usize = 4_194_304;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_WITNESS_METADATA: usize = 4_194_304;
pub const DEFAULT_MAX_FENCES: usize = 1_048_576;
pub const DEFAULT_MAX_REBATES: usize = 2_097_152;
pub const DEFAULT_MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const DEFAULT_MAX_PUBLIC_EVENTS: usize = 1_048_576;
pub const MAX_BPS: u64 = 10_000;

const D_CONFIG: &str = "PL2-FAST-PQ-CONF-RECURSIVE-PROOF-BATCH-CACHE:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-RECURSIVE-PROOF-BATCH-CACHE:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-RECURSIVE-PROOF-BATCH-CACHE:ROOTS";
const D_STATE: &str = "PL2-FAST-PQ-CONF-RECURSIVE-PROOF-BATCH-CACHE:STATE";
const D_SLOTS: &str = "PL2-FAST-PQ-CONF-RECURSIVE-PROOF-BATCH-CACHE:SLOTS";
const D_AGGREGATES: &str = "PL2-FAST-PQ-CONF-RECURSIVE-PROOF-BATCH-CACHE:AGGREGATES";
const D_LEASES: &str = "PL2-FAST-PQ-CONF-RECURSIVE-PROOF-BATCH-CACHE:LEASES";
const D_ATTESTATIONS: &str = "PL2-FAST-PQ-CONF-RECURSIVE-PROOF-BATCH-CACHE:PQ-ATTESTATIONS";
const D_WITNESS: &str = "PL2-FAST-PQ-CONF-RECURSIVE-PROOF-BATCH-CACHE:WITNESS";
const D_FENCES: &str = "PL2-FAST-PQ-CONF-RECURSIVE-PROOF-BATCH-CACHE:FENCES";
const D_REBATES: &str = "PL2-FAST-PQ-CONF-RECURSIVE-PROOF-BATCH-CACHE:REBATES";
const D_SUMMARIES: &str = "PL2-FAST-PQ-CONF-RECURSIVE-PROOF-BATCH-CACHE:SUMMARIES";
const D_EVENTS: &str = "PL2-FAST-PQ-CONF-RECURSIVE-PROOF-BATCH-CACHE:EVENTS";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofWorkloadKind {
    TransferBatch,
    ContractExecution,
    ConfidentialSwap,
    TokenNetting,
    MoneroBridgeExit,
    OracleAttestation,
    RecursiveWrap,
    StateDiff,
    EmergencyEscape,
    LowFeeBulk,
}

impl ProofWorkloadKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TransferBatch => "transfer_batch",
            Self::ContractExecution => "contract_execution",
            Self::ConfidentialSwap => "confidential_swap",
            Self::TokenNetting => "token_netting",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::OracleAttestation => "oracle_attestation",
            Self::RecursiveWrap => "recursive_wrap",
            Self::StateDiff => "state_diff",
            Self::EmergencyEscape => "emergency_escape",
            Self::LowFeeBulk => "low_fee_bulk",
        }
    }

    pub fn complexity_weight(self) -> u64 {
        match self {
            Self::EmergencyEscape => 1_600,
            Self::ContractExecution => 1_300,
            Self::ConfidentialSwap => 1_180,
            Self::MoneroBridgeExit => 1_100,
            Self::RecursiveWrap => 1_000,
            Self::StateDiff => 920,
            Self::TokenNetting => 840,
            Self::TransferBatch => 760,
            Self::OracleAttestation => 680,
            Self::LowFeeBulk => 520,
        }
    }

    pub fn prefers_reuse(self) -> bool {
        matches!(
            self,
            Self::TransferBatch | Self::TokenNetting | Self::RecursiveWrap | Self::LowFeeBulk
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotStatus {
    Open,
    Reserved,
    Filled,
    Reused,
    Sealed,
    Invalidated,
    Expired,
}

impl SlotStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Filled => "filled",
            Self::Reused => "reused",
            Self::Sealed => "sealed",
            Self::Invalidated => "invalidated",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_lease(self) -> bool {
        matches!(self, Self::Open | Self::Filled | Self::Reused)
    }

    pub fn is_live(self) -> bool {
        !matches!(self, Self::Invalidated | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregateStatus {
    Building,
    Locked,
    Verified,
    Cached,
    Recalled,
    Superseded,
    Invalidated,
    Expired,
}

impl AggregateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Building => "building",
            Self::Locked => "locked",
            Self::Verified => "verified",
            Self::Cached => "cached",
            Self::Recalled => "recalled",
            Self::Superseded => "superseded",
            Self::Invalidated => "invalidated",
            Self::Expired => "expired",
        }
    }

    pub fn reusable(self) -> bool {
        matches!(self, Self::Verified | Self::Cached | Self::Recalled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseStatus {
    Reserved,
    Active,
    Fulfilled,
    Released,
    Rejected,
    Expired,
}

impl LeaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Active => "active",
            Self::Fulfilled => "fulfilled",
            Self::Released => "released",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn billable(self) -> bool {
        matches!(self, Self::Active | Self::Fulfilled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqVerifierKind {
    MlDsa87,
    SlhDsaShake256f,
    HybridMlDsaSlhDsa,
    RecursiveVerifier,
    HardwareIsolated,
    CommitteeQuorum,
}

impl PqVerifierKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa87 => "ml_dsa_87",
            Self::SlhDsaShake256f => "slh_dsa_shake_256f",
            Self::HybridMlDsaSlhDsa => "hybrid_ml_dsa_slh_dsa",
            Self::RecursiveVerifier => "recursive_verifier",
            Self::HardwareIsolated => "hardware_isolated",
            Self::CommitteeQuorum => "committee_quorum",
        }
    }

    pub fn security_bits(self) -> u16 {
        match self {
            Self::MlDsa87
            | Self::SlhDsaShake256f
            | Self::HybridMlDsaSlhDsa
            | Self::HardwareIsolated => 256,
            Self::RecursiveVerifier => 224,
            Self::CommitteeQuorum => 256,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Pending,
    Accepted,
    QuorumReady,
    Finalized,
    Rejected,
    Revoked,
    Expired,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::QuorumReady => "quorum_ready",
            Self::Finalized => "finalized",
            Self::Rejected => "rejected",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn contributes_to_quorum(self) -> bool {
        matches!(self, Self::Accepted | Self::QuorumReady | Self::Finalized)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessRedactionLevel {
    CommitmentOnly,
    BucketedShape,
    RangeBounded,
    OperatorAuditable,
    SelectiveDisclosure,
}

impl WitnessRedactionLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CommitmentOnly => "commitment_only",
            Self::BucketedShape => "bucketed_shape",
            Self::RangeBounded => "range_bounded",
            Self::OperatorAuditable => "operator_auditable",
            Self::SelectiveDisclosure => "selective_disclosure",
        }
    }

    pub fn disclosure_weight(self) -> u64 {
        match self {
            Self::CommitmentOnly => 10,
            Self::BucketedShape => 25,
            Self::RangeBounded => 40,
            Self::OperatorAuditable => 55,
            Self::SelectiveDisclosure => 70,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceKind {
    CircuitUpgrade,
    VerifierKeyRotation,
    WitnessEpochBoundary,
    ReorgGuard,
    PrivacyRegression,
    OperatorSlash,
    EmergencyHalt,
}

impl FenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CircuitUpgrade => "circuit_upgrade",
            Self::VerifierKeyRotation => "verifier_key_rotation",
            Self::WitnessEpochBoundary => "witness_epoch_boundary",
            Self::ReorgGuard => "reorg_guard",
            Self::PrivacyRegression => "privacy_regression",
            Self::OperatorSlash => "operator_slash",
            Self::EmergencyHalt => "emergency_halt",
        }
    }

    pub fn invalidates_reuse(self) -> bool {
        !matches!(self, Self::ReorgGuard)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accruing,
    Claimable,
    Settled,
    ClawedBack,
    Expired,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accruing => "accruing",
            Self::Claimable => "claimable",
            Self::Settled => "settled",
            Self::ClawedBack => "clawed_back",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheTier {
    Hot,
    Warm,
    Cold,
    Archive,
}

impl CacheTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hot => "hot",
            Self::Warm => "warm",
            Self::Cold => "cold",
            Self::Archive => "archive",
        }
    }

    pub fn hit_weight(self) -> u64 {
        match self {
            Self::Hot => 1_000,
            Self::Warm => 720,
            Self::Cold => 420,
            Self::Archive => 160,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_verify_ms: u64,
    pub hard_verify_ms: u64,
    pub target_cache_hit_bps: u64,
    pub reuse_fee_bps: u64,
    pub max_reuse_fee_bps: u64,
    pub rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub min_aggregate_depth: u8,
    pub max_aggregate_depth: u8,
    pub slot_ttl_blocks: u64,
    pub aggregate_ttl_blocks: u64,
    pub lease_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub fence_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub max_slots: usize,
    pub max_aggregates: usize,
    pub max_leases: usize,
    pub max_attestations: usize,
    pub max_witness_metadata: usize,
    pub max_fences: usize,
    pub max_rebates: usize,
    pub max_operator_summaries: usize,
    pub max_public_events: usize,
    pub pq_verifier_suite: String,
    pub hash_suite: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_verify_ms: DEFAULT_TARGET_VERIFY_MS,
            hard_verify_ms: DEFAULT_HARD_VERIFY_MS,
            target_cache_hit_bps: DEFAULT_TARGET_CACHE_HIT_BPS,
            reuse_fee_bps: DEFAULT_REUSE_FEE_BPS,
            max_reuse_fee_bps: DEFAULT_MAX_REUSE_FEE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            min_aggregate_depth: DEFAULT_MIN_AGGREGATE_DEPTH,
            max_aggregate_depth: DEFAULT_MAX_AGGREGATE_DEPTH,
            slot_ttl_blocks: DEFAULT_SLOT_TTL_BLOCKS,
            aggregate_ttl_blocks: DEFAULT_AGGREGATE_TTL_BLOCKS,
            lease_ttl_blocks: DEFAULT_LEASE_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            fence_ttl_blocks: DEFAULT_FENCE_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            max_slots: DEFAULT_MAX_SLOTS,
            max_aggregates: DEFAULT_MAX_AGGREGATES,
            max_leases: DEFAULT_MAX_LEASES,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_witness_metadata: DEFAULT_MAX_WITNESS_METADATA,
            max_fences: DEFAULT_MAX_FENCES,
            max_rebates: DEFAULT_MAX_REBATES,
            max_operator_summaries: DEFAULT_MAX_OPERATOR_SUMMARIES,
            max_public_events: DEFAULT_MAX_PUBLIC_EVENTS,
            pq_verifier_suite: PQ_VERIFIER_SUITE.to_string(),
            hash_suite: HASH_SUITE.to_string(),
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("min pq security bits below runtime floor".to_string());
        }
        if self.min_privacy_set_size < DEFAULT_MIN_PRIVACY_SET_SIZE {
            return Err("privacy set size below runtime floor".to_string());
        }
        if self.reuse_fee_bps > self.max_reuse_fee_bps {
            return Err("reuse fee cannot exceed configured max reuse fee".to_string());
        }
        if self.max_reuse_fee_bps > MAX_BPS
            || self.rebate_bps > MAX_BPS
            || self.sponsor_cover_bps > MAX_BPS
        {
            return Err("basis point configuration exceeds max bps".to_string());
        }
        if self.min_aggregate_depth == 0 || self.min_aggregate_depth > self.max_aggregate_depth {
            return Err("invalid recursive aggregate depth bounds".to_string());
        }
        if self.target_verify_ms == 0 || self.target_verify_ms > self.hard_verify_ms {
            return Err(
                "verify target must be positive and no larger than hard verify ms".to_string(),
            );
        }
        Ok(())
    }

    pub fn config_commitment(&self) -> String {
        domain_hash(
            D_CONFIG,
            &[
                HashPart::U64(self.chain_id),
                HashPart::Str(self.l2_network.as_str()),
                HashPart::Str(self.monero_network.as_str()),
                HashPart::Str(self.fee_asset_id.as_str()),
                HashPart::U64(self.min_pq_security_bits as u64),
                HashPart::U64(self.min_privacy_set_size),
                HashPart::U64(self.target_verify_ms),
                HashPart::U64(self.max_reuse_fee_bps),
                HashPart::Str(self.pq_verifier_suite.as_str()),
            ],
        )
    }

    pub fn fee_for_saved_units(&self, saved_units: u64) -> u64 {
        saved_units
            .saturating_mul(self.reuse_fee_bps.min(self.max_reuse_fee_bps))
            .saturating_add(MAX_BPS - 1)
            / MAX_BPS
    }

    pub fn rebate_for_paid_fee(&self, paid_fee: u64) -> u64 {
        paid_fee.saturating_mul(self.rebate_bps) / MAX_BPS
    }

    pub fn sponsored_fee_cover(&self, paid_fee: u64) -> u64 {
        paid_fee.saturating_mul(self.sponsor_cover_bps) / MAX_BPS
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_slot_id: u64,
    pub next_aggregate_id: u64,
    pub next_lease_id: u64,
    pub next_attestation_id: u64,
    pub next_witness_metadata_id: u64,
    pub next_fence_id: u64,
    pub next_rebate_id: u64,
    pub next_operator_summary_id: u64,
    pub slots_opened: u64,
    pub slots_filled: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub aggregates_verified: u64,
    pub aggregate_reuses: u64,
    pub leases_fulfilled: u64,
    pub attestations_accepted: u64,
    pub attestations_rejected: u64,
    pub fences_triggered: u64,
    pub rebates_claimed: u64,
    pub fee_units_saved: u64,
    pub verify_ms_saved: u64,
    pub witness_bytes_redacted: u64,
    pub privacy_warnings: u64,
}

impl Counters {
    pub fn next_slot_id(&mut self) -> u64 {
        self.next_slot_id = self.next_slot_id.saturating_add(1);
        self.next_slot_id
    }

    pub fn next_aggregate_id(&mut self) -> u64 {
        self.next_aggregate_id = self.next_aggregate_id.saturating_add(1);
        self.next_aggregate_id
    }

    pub fn next_lease_id(&mut self) -> u64 {
        self.next_lease_id = self.next_lease_id.saturating_add(1);
        self.next_lease_id
    }

    pub fn next_attestation_id(&mut self) -> u64 {
        self.next_attestation_id = self.next_attestation_id.saturating_add(1);
        self.next_attestation_id
    }

    pub fn next_witness_metadata_id(&mut self) -> u64 {
        self.next_witness_metadata_id = self.next_witness_metadata_id.saturating_add(1);
        self.next_witness_metadata_id
    }

    pub fn next_fence_id(&mut self) -> u64 {
        self.next_fence_id = self.next_fence_id.saturating_add(1);
        self.next_fence_id
    }

    pub fn next_rebate_id(&mut self) -> u64 {
        self.next_rebate_id = self.next_rebate_id.saturating_add(1);
        self.next_rebate_id
    }

    pub fn next_operator_summary_id(&mut self) -> u64 {
        self.next_operator_summary_id = self.next_operator_summary_id.saturating_add(1);
        self.next_operator_summary_id
    }

    pub fn cache_hit_bps(&self) -> u64 {
        let total = self.cache_hits.saturating_add(self.cache_misses);
        if total == 0 {
            0
        } else {
            self.cache_hits.saturating_mul(MAX_BPS) / total
        }
    }

    pub fn counters_commitment(&self) -> String {
        domain_hash(
            D_COUNTERS,
            &[
                HashPart::U64(self.next_slot_id),
                HashPart::U64(self.next_aggregate_id),
                HashPart::U64(self.next_lease_id),
                HashPart::U64(self.cache_hits),
                HashPart::U64(self.cache_misses),
                HashPart::U64(self.aggregate_reuses),
                HashPart::U64(self.fee_units_saved),
                HashPart::U64(self.verify_ms_saved),
            ],
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub slots_root: String,
    pub aggregates_root: String,
    pub leases_root: String,
    pub attestations_root: String,
    pub witness_metadata_root: String,
    pub invalidation_fences_root: String,
    pub fee_rebates_root: String,
    pub operator_summaries_root: String,
    pub public_events_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn ordered_values(&self) -> Vec<String> {
        vec![
            self.config_root.clone(),
            self.counters_root.clone(),
            self.slots_root.clone(),
            self.aggregates_root.clone(),
            self.leases_root.clone(),
            self.attestations_root.clone(),
            self.witness_metadata_root.clone(),
            self.invalidation_fences_root.clone(),
            self.fee_rebates_root.clone(),
            self.operator_summaries_root.clone(),
            self.public_events_root.clone(),
        ]
    }

    pub fn public_value(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "slots_root": self.slots_root,
            "aggregates_root": self.aggregates_root,
            "leases_root": self.leases_root,
            "attestations_root": self.attestations_root,
            "witness_metadata_root": self.witness_metadata_root,
            "invalidation_fences_root": self.invalidation_fences_root,
            "fee_rebates_root": self.fee_rebates_root,
            "operator_summaries_root": self.operator_summaries_root,
            "public_events_root": self.public_events_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofBatchSlot {
    pub slot_id: u64,
    pub workload_kind: ProofWorkloadKind,
    pub status: SlotStatus,
    pub cache_tier: CacheTier,
    pub batch_commitment: String,
    pub circuit_id: String,
    pub verifier_key_id: String,
    pub aggregate_id: Option<u64>,
    pub witness_metadata_id: Option<u64>,
    pub owner_commitment: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub proof_count: u64,
    pub recursive_depth_hint: u8,
    pub opened_height: u64,
    pub expires_height: u64,
    pub last_reuse_height: u64,
    pub reuse_count: u64,
    pub estimated_verify_ms: u64,
    pub estimated_fee_units: u64,
    pub redacted_tags: BTreeSet<String>,
}

impl ProofBatchSlot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        slot_id: u64,
        workload_kind: ProofWorkloadKind,
        batch_commitment: impl Into<String>,
        circuit_id: impl Into<String>,
        verifier_key_id: impl Into<String>,
        owner_commitment: impl Into<String>,
        privacy_set_size: u64,
        pq_security_bits: u16,
        proof_count: u64,
        opened_height: u64,
        config: &Config,
    ) -> Self {
        let recursive_depth_hint = config
            .min_aggregate_depth
            .saturating_add((proof_count.ilog2() as u8).min(config.max_aggregate_depth))
            .min(config.max_aggregate_depth);
        let estimated_verify_ms = workload_kind
            .complexity_weight()
            .saturating_mul(proof_count.max(1))
            / 16;
        let estimated_fee_units = workload_kind
            .complexity_weight()
            .saturating_mul(proof_count.max(1))
            / 8;
        Self {
            slot_id,
            workload_kind,
            status: SlotStatus::Open,
            cache_tier: CacheTier::Hot,
            batch_commitment: batch_commitment.into(),
            circuit_id: circuit_id.into(),
            verifier_key_id: verifier_key_id.into(),
            aggregate_id: None,
            witness_metadata_id: None,
            owner_commitment: owner_commitment.into(),
            privacy_set_size,
            pq_security_bits,
            proof_count,
            recursive_depth_hint,
            opened_height,
            expires_height: opened_height.saturating_add(config.slot_ttl_blocks),
            last_reuse_height: opened_height,
            reuse_count: 0,
            estimated_verify_ms,
            estimated_fee_units,
            redacted_tags: BTreeSet::new(),
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.batch_commitment.is_empty() {
            return Err(format!("slot {} missing batch commitment", self.slot_id));
        }
        if self.circuit_id.is_empty() || self.verifier_key_id.is_empty() {
            return Err(format!(
                "slot {} missing circuit or verifier key",
                self.slot_id
            ));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!("slot {} privacy set below floor", self.slot_id));
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err(format!("slot {} pq security below floor", self.slot_id));
        }
        if self.proof_count == 0 {
            return Err(format!("slot {} cannot cache zero proofs", self.slot_id));
        }
        Ok(())
    }

    pub fn is_expired(&self, height: u64) -> bool {
        height >= self.expires_height
    }

    pub fn mark_filled(&mut self, aggregate_id: u64, witness_metadata_id: u64) {
        self.status = SlotStatus::Filled;
        self.aggregate_id = Some(aggregate_id);
        self.witness_metadata_id = Some(witness_metadata_id);
    }

    pub fn record_reuse(&mut self, height: u64) {
        self.status = SlotStatus::Reused;
        self.last_reuse_height = height;
        self.reuse_count = self.reuse_count.saturating_add(1);
        self.cache_tier = if self.reuse_count > 64 {
            CacheTier::Hot
        } else if self.reuse_count > 8 {
            CacheTier::Warm
        } else {
            self.cache_tier
        };
    }

    pub fn invalidate(&mut self) {
        self.status = SlotStatus::Invalidated;
        self.cache_tier = CacheTier::Archive;
    }

    pub fn low_fee_score(&self) -> u64 {
        self.cache_tier
            .hit_weight()
            .saturating_add(self.workload_kind.complexity_weight())
            .saturating_add(self.reuse_count.saturating_mul(25))
            .saturating_sub(self.estimated_fee_units / 64)
    }

    pub fn commitment(&self) -> String {
        domain_hash(
            D_SLOTS,
            &[
                HashPart::U64(self.slot_id),
                HashPart::Str(self.workload_kind.as_str()),
                HashPart::Str(self.status.as_str()),
                HashPart::Str(self.cache_tier.as_str()),
                HashPart::Str(self.batch_commitment.as_str()),
                HashPart::Str(self.circuit_id.as_str()),
                HashPart::Str(self.verifier_key_id.as_str()),
                HashPart::U64(self.aggregate_id.unwrap_or_default()),
                HashPart::U64(self.witness_metadata_id.unwrap_or_default()),
                HashPart::U64(self.privacy_set_size),
                HashPart::U64(self.pq_security_bits as u64),
                HashPart::U64(self.proof_count),
                HashPart::U64(self.reuse_count),
            ],
        )
    }

    pub fn public_value(&self) -> Value {
        json!({
            "slot_id": self.slot_id,
            "workload_kind": self.workload_kind.as_str(),
            "status": self.status.as_str(),
            "cache_tier": self.cache_tier.as_str(),
            "batch_commitment": self.batch_commitment,
            "circuit_id": self.circuit_id,
            "verifier_key_id": self.verifier_key_id,
            "aggregate_id": self.aggregate_id,
            "witness_metadata_id": self.witness_metadata_id,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "proof_count": self.proof_count,
            "recursive_depth_hint": self.recursive_depth_hint,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "reuse_count": self.reuse_count,
            "estimated_verify_ms": self.estimated_verify_ms,
            "estimated_fee_units": self.estimated_fee_units,
            "low_fee_score": self.low_fee_score(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecursiveAggregateCommitment {
    pub aggregate_id: u64,
    pub status: AggregateStatus,
    pub aggregate_commitment: String,
    pub recursion_root: String,
    pub verifier_key_id: String,
    pub slot_ids: Vec<u64>,
    pub child_aggregate_ids: Vec<u64>,
    pub proof_count: u64,
    pub recursion_depth: u8,
    pub privacy_set_floor: u64,
    pub pq_security_bits: u16,
    pub operator_commitment: String,
    pub created_height: u64,
    pub verified_height: Option<u64>,
    pub expires_height: u64,
    pub reuse_count: u64,
    pub verify_ms: u64,
    pub amortized_fee_units: u64,
    pub attestation_ids: BTreeSet<u64>,
}

impl RecursiveAggregateCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        aggregate_id: u64,
        verifier_key_id: impl Into<String>,
        slot_ids: Vec<u64>,
        child_aggregate_ids: Vec<u64>,
        proof_count: u64,
        recursion_depth: u8,
        privacy_set_floor: u64,
        pq_security_bits: u16,
        operator_commitment: impl Into<String>,
        created_height: u64,
        config: &Config,
    ) -> Self {
        let verifier_key_id = verifier_key_id.into();
        let operator_commitment = operator_commitment.into();
        let recursion_root = merkle_root(
            RECURSIVE_AGGREGATE_SCHEME,
            slot_ids
                .iter()
                .map(|slot_id| json!({"slot_id": slot_id}))
                .chain(
                    child_aggregate_ids
                        .iter()
                        .map(|aggregate_id| json!({"child_aggregate_id": aggregate_id})),
                )
                .collect(),
        );
        let aggregate_commitment = domain_hash(
            D_AGGREGATES,
            &[
                HashPart::U64(aggregate_id),
                HashPart::Str(verifier_key_id.as_str()),
                HashPart::Str(recursion_root.as_str()),
                HashPart::U64(proof_count),
                HashPart::U64(recursion_depth as u64),
                HashPart::U64(privacy_set_floor),
                HashPart::U64(pq_security_bits as u64),
                HashPart::Str(operator_commitment.as_str()),
            ],
        );
        let verify_ms = proof_count
            .saturating_mul(20)
            .saturating_div(recursion_depth.max(1) as u64)
            .max(1);
        Self {
            aggregate_id,
            status: AggregateStatus::Building,
            aggregate_commitment,
            recursion_root,
            verifier_key_id,
            slot_ids,
            child_aggregate_ids,
            proof_count,
            recursion_depth,
            privacy_set_floor,
            pq_security_bits,
            operator_commitment,
            created_height,
            verified_height: None,
            expires_height: created_height.saturating_add(config.aggregate_ttl_blocks),
            reuse_count: 0,
            verify_ms,
            amortized_fee_units: proof_count.saturating_mul(3).max(1),
            attestation_ids: BTreeSet::new(),
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.slot_ids.is_empty() && self.child_aggregate_ids.is_empty() {
            return Err(format!("aggregate {} has no leaves", self.aggregate_id));
        }
        if self.recursion_depth < config.min_aggregate_depth
            || self.recursion_depth > config.max_aggregate_depth
        {
            return Err(format!(
                "aggregate {} depth outside bounds",
                self.aggregate_id
            ));
        }
        if self.privacy_set_floor < config.min_privacy_set_size {
            return Err(format!(
                "aggregate {} privacy floor too low",
                self.aggregate_id
            ));
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err(format!(
                "aggregate {} pq security too low",
                self.aggregate_id
            ));
        }
        Ok(())
    }

    pub fn is_expired(&self, height: u64) -> bool {
        height >= self.expires_height
    }

    pub fn attach_attestation(&mut self, attestation_id: u64) {
        self.attestation_ids.insert(attestation_id);
    }

    pub fn mark_verified(&mut self, height: u64) {
        self.status = AggregateStatus::Verified;
        self.verified_height = Some(height);
    }

    pub fn mark_cached(&mut self) {
        self.status = AggregateStatus::Cached;
    }

    pub fn record_reuse(&mut self) {
        self.status = AggregateStatus::Recalled;
        self.reuse_count = self.reuse_count.saturating_add(1);
    }

    pub fn reuse_value(&self) -> u64 {
        self.verify_ms
            .saturating_mul(self.proof_count.max(1))
            .saturating_add(self.reuse_count.saturating_mul(50))
            .saturating_sub(self.amortized_fee_units)
    }

    pub fn commitment(&self) -> String {
        domain_hash(
            D_AGGREGATES,
            &[
                HashPart::U64(self.aggregate_id),
                HashPart::Str(self.status.as_str()),
                HashPart::Str(self.aggregate_commitment.as_str()),
                HashPart::Str(self.recursion_root.as_str()),
                HashPart::Str(self.verifier_key_id.as_str()),
                HashPart::U64(self.proof_count),
                HashPart::U64(self.recursion_depth as u64),
                HashPart::U64(self.privacy_set_floor),
                HashPart::U64(self.pq_security_bits as u64),
                HashPart::U64(self.reuse_count),
                HashPart::U64(self.attestation_ids.len() as u64),
            ],
        )
    }

    pub fn public_value(&self) -> Value {
        json!({
            "aggregate_id": self.aggregate_id,
            "status": self.status.as_str(),
            "aggregate_commitment": self.aggregate_commitment,
            "recursion_root": self.recursion_root,
            "verifier_key_id": self.verifier_key_id,
            "slot_ids": self.slot_ids,
            "child_aggregate_ids": self.child_aggregate_ids,
            "proof_count": self.proof_count,
            "recursion_depth": self.recursion_depth,
            "privacy_set_floor": self.privacy_set_floor,
            "pq_security_bits": self.pq_security_bits,
            "created_height": self.created_height,
            "verified_height": self.verified_height,
            "expires_height": self.expires_height,
            "reuse_count": self.reuse_count,
            "verify_ms": self.verify_ms,
            "amortized_fee_units": self.amortized_fee_units,
            "attestation_count": self.attestation_ids.len(),
            "reuse_value": self.reuse_value(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CacheLease {
    pub lease_id: u64,
    pub status: LeaseStatus,
    pub slot_id: u64,
    pub aggregate_id: u64,
    pub requester_commitment: String,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub charged_fee_units: u64,
    pub saved_verify_ms: u64,
    pub saved_fee_units: u64,
    pub reserved_height: u64,
    pub activated_height: Option<u64>,
    pub fulfilled_height: Option<u64>,
    pub expires_height: u64,
    pub reuse_nullifier: String,
    pub disclosure_policy_root: String,
}

impl CacheLease {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lease_id: u64,
        slot: &ProofBatchSlot,
        aggregate: &RecursiveAggregateCommitment,
        requester_commitment: impl Into<String>,
        max_fee_units: u64,
        reserved_height: u64,
        config: &Config,
    ) -> Self {
        let requester_commitment = requester_commitment.into();
        let saved_verify_ms = slot.estimated_verify_ms.saturating_sub(aggregate.verify_ms);
        let saved_fee_units = slot
            .estimated_fee_units
            .saturating_sub(aggregate.amortized_fee_units);
        let charged_fee_units = config
            .fee_for_saved_units(saved_fee_units)
            .min(max_fee_units)
            .max(1);
        let reuse_nullifier = domain_hash(
            CACHE_LEASE_SCHEME,
            &[
                HashPart::U64(lease_id),
                HashPart::U64(slot.slot_id),
                HashPart::U64(aggregate.aggregate_id),
                HashPart::Str(requester_commitment.as_str()),
            ],
        );
        let disclosure_policy_root = domain_hash(
            D_LEASES,
            &[
                HashPart::Str("redacted-disclosure-policy"),
                HashPart::Str(slot.circuit_id.as_str()),
                HashPart::Str(aggregate.verifier_key_id.as_str()),
                HashPart::U64(slot.privacy_set_size),
            ],
        );
        Self {
            lease_id,
            status: LeaseStatus::Reserved,
            slot_id: slot.slot_id,
            aggregate_id: aggregate.aggregate_id,
            requester_commitment,
            fee_asset_id: config.fee_asset_id.clone(),
            max_fee_units,
            charged_fee_units,
            saved_verify_ms,
            saved_fee_units,
            reserved_height,
            activated_height: None,
            fulfilled_height: None,
            expires_height: reserved_height.saturating_add(config.lease_ttl_blocks),
            reuse_nullifier,
            disclosure_policy_root,
        }
    }

    pub fn activate(&mut self, height: u64) {
        self.status = LeaseStatus::Active;
        self.activated_height = Some(height);
    }

    pub fn fulfill(&mut self, height: u64) {
        self.status = LeaseStatus::Fulfilled;
        self.fulfilled_height = Some(height);
    }

    pub fn release(&mut self) {
        self.status = LeaseStatus::Released;
    }

    pub fn is_expired(&self, height: u64) -> bool {
        height >= self.expires_height
    }

    pub fn commitment(&self) -> String {
        domain_hash(
            D_LEASES,
            &[
                HashPart::U64(self.lease_id),
                HashPart::Str(self.status.as_str()),
                HashPart::U64(self.slot_id),
                HashPart::U64(self.aggregate_id),
                HashPart::Str(self.requester_commitment.as_str()),
                HashPart::U64(self.charged_fee_units),
                HashPart::U64(self.saved_verify_ms),
                HashPart::U64(self.saved_fee_units),
                HashPart::Str(self.reuse_nullifier.as_str()),
            ],
        )
    }

    pub fn public_value(&self) -> Value {
        json!({
            "lease_id": self.lease_id,
            "status": self.status.as_str(),
            "slot_id": self.slot_id,
            "aggregate_id": self.aggregate_id,
            "requester_commitment": self.requester_commitment,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "charged_fee_units": self.charged_fee_units,
            "saved_verify_ms": self.saved_verify_ms,
            "saved_fee_units": self.saved_fee_units,
            "reserved_height": self.reserved_height,
            "activated_height": self.activated_height,
            "fulfilled_height": self.fulfilled_height,
            "expires_height": self.expires_height,
            "reuse_nullifier": self.reuse_nullifier,
            "disclosure_policy_root": self.disclosure_policy_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqVerifierAttestation {
    pub attestation_id: u64,
    pub aggregate_id: u64,
    pub verifier_kind: PqVerifierKind,
    pub status: AttestationStatus,
    pub verifier_commitment: String,
    pub verifier_key_id: String,
    pub signature_root: String,
    pub transcript_root: String,
    pub public_input_root: String,
    pub observed_verify_ms: u64,
    pub pq_security_bits: u16,
    pub created_height: u64,
    pub expires_height: u64,
    pub quorum_weight: u64,
    pub rejection_reason: Option<String>,
}

impl PqVerifierAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        attestation_id: u64,
        aggregate_id: u64,
        verifier_kind: PqVerifierKind,
        verifier_commitment: impl Into<String>,
        verifier_key_id: impl Into<String>,
        transcript_root: impl Into<String>,
        public_input_root: impl Into<String>,
        observed_verify_ms: u64,
        created_height: u64,
        config: &Config,
    ) -> Self {
        let verifier_commitment = verifier_commitment.into();
        let verifier_key_id = verifier_key_id.into();
        let transcript_root = transcript_root.into();
        let public_input_root = public_input_root.into();
        let signature_root = domain_hash(
            PQ_VERIFIER_SUITE,
            &[
                HashPart::U64(attestation_id),
                HashPart::U64(aggregate_id),
                HashPart::Str(verifier_kind.as_str()),
                HashPart::Str(verifier_commitment.as_str()),
                HashPart::Str(verifier_key_id.as_str()),
                HashPart::Str(transcript_root.as_str()),
                HashPart::Str(public_input_root.as_str()),
            ],
        );
        Self {
            attestation_id,
            aggregate_id,
            verifier_kind,
            status: AttestationStatus::Pending,
            verifier_commitment,
            verifier_key_id,
            signature_root,
            transcript_root,
            public_input_root,
            observed_verify_ms,
            pq_security_bits: verifier_kind.security_bits(),
            created_height,
            expires_height: created_height.saturating_add(config.attestation_ttl_blocks),
            quorum_weight: 1,
            rejection_reason: None,
        }
    }

    pub fn accept(&mut self, quorum_weight: u64) {
        self.status = AttestationStatus::Accepted;
        self.quorum_weight = quorum_weight.max(1);
    }

    pub fn finalize(&mut self) {
        self.status = AttestationStatus::Finalized;
    }

    pub fn reject(&mut self, reason: impl Into<String>) {
        self.status = AttestationStatus::Rejected;
        self.rejection_reason = Some(reason.into());
    }

    pub fn is_expired(&self, height: u64) -> bool {
        height >= self.expires_height
    }

    pub fn commitment(&self) -> String {
        domain_hash(
            D_ATTESTATIONS,
            &[
                HashPart::U64(self.attestation_id),
                HashPart::U64(self.aggregate_id),
                HashPart::Str(self.verifier_kind.as_str()),
                HashPart::Str(self.status.as_str()),
                HashPart::Str(self.verifier_commitment.as_str()),
                HashPart::Str(self.verifier_key_id.as_str()),
                HashPart::Str(self.signature_root.as_str()),
                HashPart::Str(self.transcript_root.as_str()),
                HashPart::Str(self.public_input_root.as_str()),
                HashPart::U64(self.observed_verify_ms),
                HashPart::U64(self.pq_security_bits as u64),
                HashPart::U64(self.quorum_weight),
            ],
        )
    }

    pub fn public_value(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "aggregate_id": self.aggregate_id,
            "verifier_kind": self.verifier_kind.as_str(),
            "status": self.status.as_str(),
            "verifier_commitment": self.verifier_commitment,
            "verifier_key_id": self.verifier_key_id,
            "signature_root": self.signature_root,
            "transcript_root": self.transcript_root,
            "public_input_root": self.public_input_root,
            "observed_verify_ms": self.observed_verify_ms,
            "pq_security_bits": self.pq_security_bits,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
            "quorum_weight": self.quorum_weight,
            "rejection_reason": self.rejection_reason,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessRedactionMetadata {
    pub metadata_id: u64,
    pub slot_id: u64,
    pub redaction_level: WitnessRedactionLevel,
    pub witness_commitment: String,
    pub redacted_metadata_root: String,
    pub shape_commitment: String,
    pub entropy_bucket: u16,
    pub byte_size_bucket: u64,
    pub input_count_bucket: u64,
    pub decoy_floor: u64,
    pub nullifier_set_root: String,
    pub selective_disclosure_root: Option<String>,
    pub created_height: u64,
    pub redacted_bytes: u64,
    pub privacy_budget_bps: u64,
    pub audit_tags: BTreeSet<String>,
}

impl WitnessRedactionMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        metadata_id: u64,
        slot_id: u64,
        redaction_level: WitnessRedactionLevel,
        witness_commitment: impl Into<String>,
        entropy_bucket: u16,
        byte_size_bucket: u64,
        input_count_bucket: u64,
        decoy_floor: u64,
        created_height: u64,
    ) -> Self {
        let witness_commitment = witness_commitment.into();
        let shape_commitment = domain_hash(
            CONFIDENTIAL_WITNESS_SCHEME,
            &[
                HashPart::U64(metadata_id),
                HashPart::U64(slot_id),
                HashPart::Str(redaction_level.as_str()),
                HashPart::U64(entropy_bucket as u64),
                HashPart::U64(byte_size_bucket),
                HashPart::U64(input_count_bucket),
                HashPart::U64(decoy_floor),
            ],
        );
        let nullifier_set_root = domain_hash(
            D_WITNESS,
            &[
                HashPart::Str("redacted-nullifier-set"),
                HashPart::U64(slot_id),
                HashPart::Str(shape_commitment.as_str()),
            ],
        );
        let redacted_metadata_root = domain_hash(
            D_WITNESS,
            &[
                HashPart::Str(witness_commitment.as_str()),
                HashPart::Str(shape_commitment.as_str()),
                HashPart::Str(nullifier_set_root.as_str()),
            ],
        );
        Self {
            metadata_id,
            slot_id,
            redaction_level,
            witness_commitment,
            redacted_metadata_root,
            shape_commitment,
            entropy_bucket,
            byte_size_bucket,
            input_count_bucket,
            decoy_floor,
            nullifier_set_root,
            selective_disclosure_root: None,
            created_height,
            redacted_bytes: byte_size_bucket.saturating_mul(1024),
            privacy_budget_bps: redaction_level.disclosure_weight(),
            audit_tags: BTreeSet::new(),
        }
    }

    pub fn attach_selective_disclosure(&mut self, disclosure_root: impl Into<String>) {
        self.selective_disclosure_root = Some(disclosure_root.into());
        self.redaction_level = WitnessRedactionLevel::SelectiveDisclosure;
        self.privacy_budget_bps = self.redaction_level.disclosure_weight();
    }

    pub fn add_audit_tag(&mut self, tag: impl Into<String>) {
        self.audit_tags.insert(tag.into());
    }

    pub fn is_privacy_preserving(&self, config: &Config) -> bool {
        self.decoy_floor >= config.min_privacy_set_size && self.privacy_budget_bps <= 1_000
    }

    pub fn commitment(&self) -> String {
        domain_hash(
            D_WITNESS,
            &[
                HashPart::U64(self.metadata_id),
                HashPart::U64(self.slot_id),
                HashPart::Str(self.redaction_level.as_str()),
                HashPart::Str(self.witness_commitment.as_str()),
                HashPart::Str(self.redacted_metadata_root.as_str()),
                HashPart::Str(self.shape_commitment.as_str()),
                HashPart::U64(self.entropy_bucket as u64),
                HashPart::U64(self.byte_size_bucket),
                HashPart::U64(self.input_count_bucket),
                HashPart::U64(self.decoy_floor),
                HashPart::Str(self.nullifier_set_root.as_str()),
                HashPart::U64(self.privacy_budget_bps),
            ],
        )
    }

    pub fn public_value(&self) -> Value {
        json!({
            "metadata_id": self.metadata_id,
            "slot_id": self.slot_id,
            "redaction_level": self.redaction_level.as_str(),
            "witness_commitment": self.witness_commitment,
            "redacted_metadata_root": self.redacted_metadata_root,
            "shape_commitment": self.shape_commitment,
            "entropy_bucket": self.entropy_bucket,
            "byte_size_bucket": self.byte_size_bucket,
            "input_count_bucket": self.input_count_bucket,
            "decoy_floor": self.decoy_floor,
            "nullifier_set_root": self.nullifier_set_root,
            "selective_disclosure_root": self.selective_disclosure_root,
            "created_height": self.created_height,
            "redacted_bytes": self.redacted_bytes,
            "privacy_budget_bps": self.privacy_budget_bps,
            "audit_tags": self.audit_tags,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvalidationFence {
    pub fence_id: u64,
    pub fence_kind: FenceKind,
    pub active: bool,
    pub fence_root: String,
    pub affected_circuit_id: Option<String>,
    pub affected_verifier_key_id: Option<String>,
    pub affected_slot_ids: BTreeSet<u64>,
    pub affected_aggregate_ids: BTreeSet<u64>,
    pub reason_commitment: String,
    pub opened_height: u64,
    pub expires_height: u64,
    pub invalidated_slots: u64,
    pub invalidated_aggregates: u64,
}

impl InvalidationFence {
    pub fn new(
        fence_id: u64,
        fence_kind: FenceKind,
        affected_circuit_id: Option<String>,
        affected_verifier_key_id: Option<String>,
        reason_commitment: impl Into<String>,
        opened_height: u64,
        config: &Config,
    ) -> Self {
        let reason_commitment = reason_commitment.into();
        let fence_root = domain_hash(
            INVALIDATION_FENCE_SCHEME,
            &[
                HashPart::U64(fence_id),
                HashPart::Str(fence_kind.as_str()),
                HashPart::Str(affected_circuit_id.as_deref().unwrap_or("all-circuits")),
                HashPart::Str(
                    affected_verifier_key_id
                        .as_deref()
                        .unwrap_or("all-verifier-keys"),
                ),
                HashPart::Str(reason_commitment.as_str()),
                HashPart::U64(opened_height),
            ],
        );
        Self {
            fence_id,
            fence_kind,
            active: true,
            fence_root,
            affected_circuit_id,
            affected_verifier_key_id,
            affected_slot_ids: BTreeSet::new(),
            affected_aggregate_ids: BTreeSet::new(),
            reason_commitment,
            opened_height,
            expires_height: opened_height.saturating_add(config.fence_ttl_blocks),
            invalidated_slots: 0,
            invalidated_aggregates: 0,
        }
    }

    pub fn matches_slot(&self, slot: &ProofBatchSlot) -> bool {
        let circuit_matches = self
            .affected_circuit_id
            .as_ref()
            .map(|id| id == &slot.circuit_id)
            .unwrap_or(true);
        let verifier_matches = self
            .affected_verifier_key_id
            .as_ref()
            .map(|id| id == &slot.verifier_key_id)
            .unwrap_or(true);
        circuit_matches && verifier_matches
    }

    pub fn matches_aggregate(&self, aggregate: &RecursiveAggregateCommitment) -> bool {
        self.affected_verifier_key_id
            .as_ref()
            .map(|id| id == &aggregate.verifier_key_id)
            .unwrap_or(true)
    }

    pub fn is_expired(&self, height: u64) -> bool {
        height >= self.expires_height
    }

    pub fn deactivate(&mut self) {
        self.active = false;
    }

    pub fn commitment(&self) -> String {
        domain_hash(
            D_FENCES,
            &[
                HashPart::U64(self.fence_id),
                HashPart::Str(self.fence_kind.as_str()),
                HashPart::U64(self.active as u64),
                HashPart::Str(self.fence_root.as_str()),
                HashPart::Str(self.affected_circuit_id.as_deref().unwrap_or_default()),
                HashPart::Str(self.affected_verifier_key_id.as_deref().unwrap_or_default()),
                HashPart::Str(self.reason_commitment.as_str()),
                HashPart::U64(self.invalidated_slots),
                HashPart::U64(self.invalidated_aggregates),
            ],
        )
    }

    pub fn public_value(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "fence_kind": self.fence_kind.as_str(),
            "active": self.active,
            "fence_root": self.fence_root,
            "affected_circuit_id": self.affected_circuit_id,
            "affected_verifier_key_id": self.affected_verifier_key_id,
            "affected_slot_ids": self.affected_slot_ids,
            "affected_aggregate_ids": self.affected_aggregate_ids,
            "reason_commitment": self.reason_commitment,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "invalidated_slots": self.invalidated_slots,
            "invalidated_aggregates": self.invalidated_aggregates,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub rebate_id: u64,
    pub status: RebateStatus,
    pub lease_id: u64,
    pub aggregate_id: u64,
    pub recipient_commitment: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub paid_fee_units: u64,
    pub rebate_units: u64,
    pub sponsor_cover_units: u64,
    pub saved_fee_units: u64,
    pub created_height: u64,
    pub claimable_height: u64,
    pub expires_height: u64,
    pub claim_nullifier: String,
}

impl FeeRebate {
    pub fn new(
        rebate_id: u64,
        lease: &CacheLease,
        recipient_commitment: impl Into<String>,
        sponsor_commitment: impl Into<String>,
        created_height: u64,
        config: &Config,
    ) -> Self {
        let recipient_commitment = recipient_commitment.into();
        let sponsor_commitment = sponsor_commitment.into();
        let rebate_units = config.rebate_for_paid_fee(lease.charged_fee_units);
        let sponsor_cover_units = config.sponsored_fee_cover(lease.charged_fee_units);
        let claim_nullifier = domain_hash(
            FEE_REBATE_SCHEME,
            &[
                HashPart::U64(rebate_id),
                HashPart::U64(lease.lease_id),
                HashPart::U64(lease.aggregate_id),
                HashPart::Str(recipient_commitment.as_str()),
                HashPart::Str(sponsor_commitment.as_str()),
            ],
        );
        Self {
            rebate_id,
            status: RebateStatus::Accruing,
            lease_id: lease.lease_id,
            aggregate_id: lease.aggregate_id,
            recipient_commitment,
            sponsor_commitment,
            fee_asset_id: lease.fee_asset_id.clone(),
            paid_fee_units: lease.charged_fee_units,
            rebate_units,
            sponsor_cover_units,
            saved_fee_units: lease.saved_fee_units,
            created_height,
            claimable_height: created_height.saturating_add(2),
            expires_height: created_height.saturating_add(config.rebate_ttl_blocks),
            claim_nullifier,
        }
    }

    pub fn mark_claimable(&mut self) {
        self.status = RebateStatus::Claimable;
    }

    pub fn settle(&mut self) {
        self.status = RebateStatus::Settled;
    }

    pub fn claw_back(&mut self) {
        self.status = RebateStatus::ClawedBack;
    }

    pub fn is_expired(&self, height: u64) -> bool {
        height >= self.expires_height
    }

    pub fn commitment(&self) -> String {
        domain_hash(
            D_REBATES,
            &[
                HashPart::U64(self.rebate_id),
                HashPart::Str(self.status.as_str()),
                HashPart::U64(self.lease_id),
                HashPart::U64(self.aggregate_id),
                HashPart::Str(self.recipient_commitment.as_str()),
                HashPart::Str(self.sponsor_commitment.as_str()),
                HashPart::U64(self.paid_fee_units),
                HashPart::U64(self.rebate_units),
                HashPart::U64(self.sponsor_cover_units),
                HashPart::U64(self.saved_fee_units),
                HashPart::Str(self.claim_nullifier.as_str()),
            ],
        )
    }

    pub fn public_value(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "status": self.status.as_str(),
            "lease_id": self.lease_id,
            "aggregate_id": self.aggregate_id,
            "recipient_commitment": self.recipient_commitment,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "paid_fee_units": self.paid_fee_units,
            "rebate_units": self.rebate_units,
            "sponsor_cover_units": self.sponsor_cover_units,
            "saved_fee_units": self.saved_fee_units,
            "created_height": self.created_height,
            "claimable_height": self.claimable_height,
            "expires_height": self.expires_height,
            "claim_nullifier": self.claim_nullifier,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: u64,
    pub operator_commitment: String,
    pub epoch: u64,
    pub slots_managed: u64,
    pub aggregates_built: u64,
    pub leases_served: u64,
    pub attestations_signed: u64,
    pub cache_hit_bps: u64,
    pub average_verify_ms: u64,
    pub fee_units_saved: u64,
    pub rebate_units_paid: u64,
    pub privacy_warnings: u64,
    pub slash_risk_bps: u64,
    pub summary_root: String,
}

impl OperatorSummary {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        summary_id: u64,
        operator_commitment: impl Into<String>,
        epoch: u64,
        slots_managed: u64,
        aggregates_built: u64,
        leases_served: u64,
        attestations_signed: u64,
        cache_hit_bps: u64,
        average_verify_ms: u64,
        fee_units_saved: u64,
        rebate_units_paid: u64,
        privacy_warnings: u64,
    ) -> Self {
        let operator_commitment = operator_commitment.into();
        let slash_risk_bps = privacy_warnings
            .saturating_mul(125)
            .saturating_add((MAX_BPS.saturating_sub(cache_hit_bps)) / 64)
            .min(MAX_BPS);
        let summary_root = domain_hash(
            OPERATOR_SUMMARY_SCHEME,
            &[
                HashPart::U64(summary_id),
                HashPart::Str(operator_commitment.as_str()),
                HashPart::U64(epoch),
                HashPart::U64(slots_managed),
                HashPart::U64(aggregates_built),
                HashPart::U64(leases_served),
                HashPart::U64(attestations_signed),
                HashPart::U64(cache_hit_bps),
                HashPart::U64(fee_units_saved),
                HashPart::U64(rebate_units_paid),
                HashPart::U64(privacy_warnings),
            ],
        );
        Self {
            summary_id,
            operator_commitment,
            epoch,
            slots_managed,
            aggregates_built,
            leases_served,
            attestations_signed,
            cache_hit_bps,
            average_verify_ms,
            fee_units_saved,
            rebate_units_paid,
            privacy_warnings,
            slash_risk_bps,
            summary_root,
        }
    }

    pub fn commitment(&self) -> String {
        domain_hash(
            D_SUMMARIES,
            &[
                HashPart::U64(self.summary_id),
                HashPart::Str(self.operator_commitment.as_str()),
                HashPart::U64(self.epoch),
                HashPart::U64(self.slots_managed),
                HashPart::U64(self.aggregates_built),
                HashPart::U64(self.leases_served),
                HashPart::U64(self.attestations_signed),
                HashPart::U64(self.cache_hit_bps),
                HashPart::U64(self.average_verify_ms),
                HashPart::U64(self.fee_units_saved),
                HashPart::U64(self.rebate_units_paid),
                HashPart::U64(self.privacy_warnings),
                HashPart::U64(self.slash_risk_bps),
                HashPart::Str(self.summary_root.as_str()),
            ],
        )
    }

    pub fn public_value(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "operator_commitment": self.operator_commitment,
            "epoch": self.epoch,
            "slots_managed": self.slots_managed,
            "aggregates_built": self.aggregates_built,
            "leases_served": self.leases_served,
            "attestations_signed": self.attestations_signed,
            "cache_hit_bps": self.cache_hit_bps,
            "average_verify_ms": self.average_verify_ms,
            "fee_units_saved": self.fee_units_saved,
            "rebate_units_paid": self.rebate_units_paid,
            "privacy_warnings": self.privacy_warnings,
            "slash_risk_bps": self.slash_risk_bps,
            "summary_root": self.summary_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub height: u64,
    pub epoch: u64,
    pub slots: BTreeMap<u64, ProofBatchSlot>,
    pub aggregates: BTreeMap<u64, RecursiveAggregateCommitment>,
    pub leases: BTreeMap<u64, CacheLease>,
    pub attestations: BTreeMap<u64, PqVerifierAttestation>,
    pub witness_metadata: BTreeMap<u64, WitnessRedactionMetadata>,
    pub invalidation_fences: BTreeMap<u64, InvalidationFence>,
    pub fee_rebates: BTreeMap<u64, FeeRebate>,
    pub operator_summaries: BTreeMap<u64, OperatorSummary>,
    pub aggregate_by_commitment: BTreeMap<String, u64>,
    pub slot_by_batch_commitment: BTreeMap<String, u64>,
    pub leases_by_aggregate: BTreeMap<u64, BTreeSet<u64>>,
    pub attestations_by_aggregate: BTreeMap<u64, BTreeSet<u64>>,
    pub nullifiers: BTreeSet<String>,
    pub public_events: Vec<Value>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            height: DEVNET_HEIGHT,
            epoch: DEVNET_EPOCH,
            slots: BTreeMap::new(),
            aggregates: BTreeMap::new(),
            leases: BTreeMap::new(),
            attestations: BTreeMap::new(),
            witness_metadata: BTreeMap::new(),
            invalidation_fences: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            aggregate_by_commitment: BTreeMap::new(),
            slot_by_batch_commitment: BTreeMap::new(),
            leases_by_aggregate: BTreeMap::new(),
            attestations_by_aggregate: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            public_events: Vec::new(),
        };
        state.refresh_roots();
        state
    }
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            height,
            epoch,
            slots: BTreeMap::new(),
            aggregates: BTreeMap::new(),
            leases: BTreeMap::new(),
            attestations: BTreeMap::new(),
            witness_metadata: BTreeMap::new(),
            invalidation_fences: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            aggregate_by_commitment: BTreeMap::new(),
            slot_by_batch_commitment: BTreeMap::new(),
            leases_by_aggregate: BTreeMap::new(),
            attestations_by_aggregate: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            public_events: Vec::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT, DEVNET_EPOCH)
            .expect("devnet config must validate");
        state.install_devnet_fixtures();
        state.refresh_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        state_root(self)
    }

    pub fn open_slot(
        &mut self,
        workload_kind: ProofWorkloadKind,
        batch_commitment: impl Into<String>,
        circuit_id: impl Into<String>,
        verifier_key_id: impl Into<String>,
        owner_commitment: impl Into<String>,
        privacy_set_size: u64,
        pq_security_bits: u16,
        proof_count: u64,
    ) -> Result<u64> {
        self.ensure_capacity(self.slots.len(), self.config.max_slots, "slots")?;
        let batch_commitment = batch_commitment.into();
        if self
            .slot_by_batch_commitment
            .contains_key(&batch_commitment)
        {
            self.counters.cache_hits = self.counters.cache_hits.saturating_add(1);
            return Ok(*self
                .slot_by_batch_commitment
                .get(&batch_commitment)
                .expect("checked above"));
        }
        self.counters.cache_misses = self.counters.cache_misses.saturating_add(1);
        let slot_id = self.counters.next_slot_id();
        let slot = ProofBatchSlot::new(
            slot_id,
            workload_kind,
            batch_commitment.clone(),
            circuit_id,
            verifier_key_id,
            owner_commitment,
            privacy_set_size,
            pq_security_bits,
            proof_count,
            self.height,
            &self.config,
        );
        slot.validate(&self.config)?;
        self.slot_by_batch_commitment
            .insert(batch_commitment, slot_id);
        self.slots.insert(slot_id, slot);
        self.counters.slots_opened = self.counters.slots_opened.saturating_add(1);
        self.push_event(json!({"event": "proof_batch_slot_opened", "slot_id": slot_id}));
        self.refresh_roots();
        Ok(slot_id)
    }

    pub fn attach_witness_metadata(
        &mut self,
        slot_id: u64,
        redaction_level: WitnessRedactionLevel,
        witness_commitment: impl Into<String>,
        entropy_bucket: u16,
        byte_size_bucket: u64,
        input_count_bucket: u64,
        decoy_floor: u64,
    ) -> Result<u64> {
        self.ensure_capacity(
            self.witness_metadata.len(),
            self.config.max_witness_metadata,
            "witness metadata",
        )?;
        self.require_slot(slot_id)?;
        let metadata_id = self.counters.next_witness_metadata_id();
        let metadata = WitnessRedactionMetadata::new(
            metadata_id,
            slot_id,
            redaction_level,
            witness_commitment,
            entropy_bucket,
            byte_size_bucket,
            input_count_bucket,
            decoy_floor,
            self.height,
        );
        if !metadata.is_privacy_preserving(&self.config) {
            self.counters.privacy_warnings = self.counters.privacy_warnings.saturating_add(1);
        }
        self.counters.witness_bytes_redacted = self
            .counters
            .witness_bytes_redacted
            .saturating_add(metadata.redacted_bytes);
        self.witness_metadata.insert(metadata_id, metadata);
        if let Some(slot) = self.slots.get_mut(&slot_id) {
            slot.witness_metadata_id = Some(metadata_id);
            slot.redacted_tags
                .insert("witness_metadata_ready".to_string());
        }
        self.push_event(json!({
            "event": "witness_metadata_attached",
            "slot_id": slot_id,
            "metadata_id": metadata_id
        }));
        self.refresh_roots();
        Ok(metadata_id)
    }

    pub fn build_recursive_aggregate(
        &mut self,
        verifier_key_id: impl Into<String>,
        slot_ids: Vec<u64>,
        child_aggregate_ids: Vec<u64>,
        operator_commitment: impl Into<String>,
    ) -> Result<u64> {
        self.ensure_capacity(
            self.aggregates.len(),
            self.config.max_aggregates,
            "aggregates",
        )?;
        if slot_ids.is_empty() && child_aggregate_ids.is_empty() {
            return Err("recursive aggregate requires slots or child aggregates".to_string());
        }
        let mut proof_count = 0u64;
        let mut privacy_set_floor = u64::MAX;
        let mut pq_security_bits = u16::MAX;
        for slot_id in &slot_ids {
            let slot = self.require_slot(*slot_id)?;
            if !slot.status.is_live() {
                return Err(format!("slot {} is not live", slot_id));
            }
            proof_count = proof_count.saturating_add(slot.proof_count);
            privacy_set_floor = privacy_set_floor.min(slot.privacy_set_size);
            pq_security_bits = pq_security_bits.min(slot.pq_security_bits);
        }
        let mut child_depth = 0u8;
        for aggregate_id in &child_aggregate_ids {
            let aggregate = self.require_aggregate(*aggregate_id)?;
            if !aggregate.status.reusable() && aggregate.status != AggregateStatus::Building {
                return Err(format!("child aggregate {} not reusable", aggregate_id));
            }
            proof_count = proof_count.saturating_add(aggregate.proof_count);
            privacy_set_floor = privacy_set_floor.min(aggregate.privacy_set_floor);
            pq_security_bits = pq_security_bits.min(aggregate.pq_security_bits);
            child_depth = child_depth.max(aggregate.recursion_depth);
        }
        if privacy_set_floor == u64::MAX {
            privacy_set_floor = self.config.min_privacy_set_size;
        }
        if pq_security_bits == u16::MAX {
            pq_security_bits = self.config.min_pq_security_bits;
        }
        let recursion_depth = child_depth
            .saturating_add(1)
            .max(self.config.min_aggregate_depth)
            .min(self.config.max_aggregate_depth);
        let aggregate_id = self.counters.next_aggregate_id();
        let aggregate = RecursiveAggregateCommitment::new(
            aggregate_id,
            verifier_key_id,
            slot_ids.clone(),
            child_aggregate_ids,
            proof_count,
            recursion_depth,
            privacy_set_floor,
            pq_security_bits,
            operator_commitment,
            self.height,
            &self.config,
        );
        aggregate.validate(&self.config)?;
        for slot_id in &slot_ids {
            if let Some(slot) = self.slots.get_mut(slot_id) {
                let witness_metadata_id = slot.witness_metadata_id.unwrap_or_default();
                slot.mark_filled(aggregate_id, witness_metadata_id);
            }
        }
        self.aggregate_by_commitment
            .insert(aggregate.aggregate_commitment.clone(), aggregate_id);
        self.aggregates.insert(aggregate_id, aggregate);
        self.counters.slots_filled = self
            .counters
            .slots_filled
            .saturating_add(slot_ids.len() as u64);
        self.push_event(json!({
            "event": "recursive_aggregate_built",
            "aggregate_id": aggregate_id,
            "slot_count": slot_ids.len(),
        }));
        self.refresh_roots();
        Ok(aggregate_id)
    }

    pub fn attest_aggregate(
        &mut self,
        aggregate_id: u64,
        verifier_kind: PqVerifierKind,
        verifier_commitment: impl Into<String>,
        verifier_key_id: impl Into<String>,
        transcript_root: impl Into<String>,
        public_input_root: impl Into<String>,
        observed_verify_ms: u64,
    ) -> Result<u64> {
        self.ensure_capacity(
            self.attestations.len(),
            self.config.max_attestations,
            "attestations",
        )?;
        self.require_aggregate(aggregate_id)?;
        let attestation_id = self.counters.next_attestation_id();
        let mut attestation = PqVerifierAttestation::new(
            attestation_id,
            aggregate_id,
            verifier_kind,
            verifier_commitment,
            verifier_key_id,
            transcript_root,
            public_input_root,
            observed_verify_ms,
            self.height,
            &self.config,
        );
        if attestation.pq_security_bits >= self.config.min_pq_security_bits
            && observed_verify_ms <= self.config.hard_verify_ms
        {
            attestation.accept(verifier_kind.security_bits() as u64);
            self.counters.attestations_accepted =
                self.counters.attestations_accepted.saturating_add(1);
        } else {
            attestation.reject("pq security or verify latency below runtime policy");
            self.counters.attestations_rejected =
                self.counters.attestations_rejected.saturating_add(1);
        }
        if let Some(aggregate) = self.aggregates.get_mut(&aggregate_id) {
            aggregate.attach_attestation(attestation_id);
            if attestation.status.contributes_to_quorum() {
                aggregate.mark_verified(self.height);
                self.counters.aggregates_verified =
                    self.counters.aggregates_verified.saturating_add(1);
            }
        }
        self.attestations_by_aggregate
            .entry(aggregate_id)
            .or_default()
            .insert(attestation_id);
        self.attestations.insert(attestation_id, attestation);
        self.push_event(json!({
            "event": "pq_verifier_attestation_recorded",
            "aggregate_id": aggregate_id,
            "attestation_id": attestation_id
        }));
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn lease_cached_proof(
        &mut self,
        slot_id: u64,
        requester_commitment: impl Into<String>,
        max_fee_units: u64,
    ) -> Result<u64> {
        self.ensure_capacity(self.leases.len(), self.config.max_leases, "leases")?;
        let slot = self.require_slot(slot_id)?.clone();
        if !slot.status.accepts_lease() {
            return Err(format!("slot {} does not accept cache leases", slot_id));
        }
        let aggregate_id = slot
            .aggregate_id
            .ok_or_else(|| format!("slot {} has no aggregate", slot_id))?;
        let aggregate = self.require_aggregate(aggregate_id)?.clone();
        if !aggregate.status.reusable() {
            return Err(format!("aggregate {} is not reusable", aggregate_id));
        }
        if self.active_fence_blocks_slot(&slot) {
            return Err(format!("slot {} blocked by invalidation fence", slot_id));
        }
        let lease_id = self.counters.next_lease_id();
        let mut lease = CacheLease::new(
            lease_id,
            &slot,
            &aggregate,
            requester_commitment,
            max_fee_units,
            self.height,
            &self.config,
        );
        if self.nullifiers.contains(&lease.reuse_nullifier) {
            return Err(format!("lease {} reuse nullifier already spent", lease_id));
        }
        lease.activate(self.height);
        self.nullifiers.insert(lease.reuse_nullifier.clone());
        self.leases_by_aggregate
            .entry(aggregate_id)
            .or_default()
            .insert(lease_id);
        self.counters.cache_hits = self.counters.cache_hits.saturating_add(1);
        self.counters.aggregate_reuses = self.counters.aggregate_reuses.saturating_add(1);
        self.counters.fee_units_saved = self
            .counters
            .fee_units_saved
            .saturating_add(lease.saved_fee_units);
        self.counters.verify_ms_saved = self
            .counters
            .verify_ms_saved
            .saturating_add(lease.saved_verify_ms);
        if let Some(slot) = self.slots.get_mut(&slot_id) {
            slot.record_reuse(self.height);
        }
        if let Some(aggregate) = self.aggregates.get_mut(&aggregate_id) {
            aggregate.record_reuse();
        }
        self.leases.insert(lease_id, lease);
        self.push_event(json!({
            "event": "cached_proof_lease_activated",
            "slot_id": slot_id,
            "aggregate_id": aggregate_id,
            "lease_id": lease_id
        }));
        self.refresh_roots();
        Ok(lease_id)
    }

    pub fn fulfill_lease(&mut self, lease_id: u64) -> Result<()> {
        let lease = self
            .leases
            .get_mut(&lease_id)
            .ok_or_else(|| format!("unknown lease {}", lease_id))?;
        if !matches!(lease.status, LeaseStatus::Active | LeaseStatus::Reserved) {
            return Err(format!("lease {} cannot be fulfilled", lease_id));
        }
        lease.fulfill(self.height);
        self.counters.leases_fulfilled = self.counters.leases_fulfilled.saturating_add(1);
        self.push_event(json!({"event": "cached_proof_lease_fulfilled", "lease_id": lease_id}));
        self.refresh_roots();
        Ok(())
    }

    pub fn create_fee_rebate(
        &mut self,
        lease_id: u64,
        recipient_commitment: impl Into<String>,
        sponsor_commitment: impl Into<String>,
    ) -> Result<u64> {
        self.ensure_capacity(self.fee_rebates.len(), self.config.max_rebates, "rebates")?;
        let lease = self
            .leases
            .get(&lease_id)
            .ok_or_else(|| format!("unknown lease {}", lease_id))?
            .clone();
        if !lease.status.billable() {
            return Err(format!("lease {} is not billable", lease_id));
        }
        let rebate_id = self.counters.next_rebate_id();
        let mut rebate = FeeRebate::new(
            rebate_id,
            &lease,
            recipient_commitment,
            sponsor_commitment,
            self.height,
            &self.config,
        );
        if self.height >= rebate.claimable_height {
            rebate.mark_claimable();
        }
        self.fee_rebates.insert(rebate_id, rebate);
        self.push_event(json!({
            "event": "fee_rebate_created",
            "lease_id": lease_id,
            "rebate_id": rebate_id
        }));
        self.refresh_roots();
        Ok(rebate_id)
    }

    pub fn settle_rebate(&mut self, rebate_id: u64) -> Result<()> {
        let rebate = self
            .fee_rebates
            .get_mut(&rebate_id)
            .ok_or_else(|| format!("unknown rebate {}", rebate_id))?;
        if matches!(
            rebate.status,
            RebateStatus::ClawedBack | RebateStatus::Expired
        ) {
            return Err(format!("rebate {} cannot settle", rebate_id));
        }
        rebate.settle();
        self.counters.rebates_claimed = self.counters.rebates_claimed.saturating_add(1);
        self.push_event(json!({"event": "fee_rebate_settled", "rebate_id": rebate_id}));
        self.refresh_roots();
        Ok(())
    }

    pub fn open_invalidation_fence(
        &mut self,
        fence_kind: FenceKind,
        affected_circuit_id: Option<String>,
        affected_verifier_key_id: Option<String>,
        reason_commitment: impl Into<String>,
    ) -> Result<u64> {
        self.ensure_capacity(
            self.invalidation_fences.len(),
            self.config.max_fences,
            "invalidation fences",
        )?;
        let fence_id = self.counters.next_fence_id();
        let mut fence = InvalidationFence::new(
            fence_id,
            fence_kind,
            affected_circuit_id,
            affected_verifier_key_id,
            reason_commitment,
            self.height,
            &self.config,
        );
        if fence.fence_kind.invalidates_reuse() {
            for slot in self.slots.values_mut() {
                if fence.matches_slot(slot) && slot.status.is_live() {
                    slot.invalidate();
                    fence.affected_slot_ids.insert(slot.slot_id);
                    fence.invalidated_slots = fence.invalidated_slots.saturating_add(1);
                }
            }
            for aggregate in self.aggregates.values_mut() {
                if fence.matches_aggregate(aggregate) && aggregate.status.reusable() {
                    aggregate.status = AggregateStatus::Invalidated;
                    fence.affected_aggregate_ids.insert(aggregate.aggregate_id);
                    fence.invalidated_aggregates = fence.invalidated_aggregates.saturating_add(1);
                }
            }
        }
        self.counters.fences_triggered = self.counters.fences_triggered.saturating_add(1);
        self.invalidation_fences.insert(fence_id, fence);
        self.push_event(json!({"event": "invalidation_fence_opened", "fence_id": fence_id}));
        self.refresh_roots();
        Ok(fence_id)
    }

    pub fn close_invalidation_fence(&mut self, fence_id: u64) -> Result<()> {
        let fence = self
            .invalidation_fences
            .get_mut(&fence_id)
            .ok_or_else(|| format!("unknown invalidation fence {}", fence_id))?;
        fence.deactivate();
        self.push_event(json!({"event": "invalidation_fence_closed", "fence_id": fence_id}));
        self.refresh_roots();
        Ok(())
    }

    pub fn summarize_operator(&mut self, operator_commitment: impl Into<String>) -> Result<u64> {
        self.ensure_capacity(
            self.operator_summaries.len(),
            self.config.max_operator_summaries,
            "operator summaries",
        )?;
        let operator_commitment = operator_commitment.into();
        let slots_managed = self
            .slots
            .values()
            .filter(|slot| {
                self.aggregates
                    .get(&slot.aggregate_id.unwrap_or_default())
                    .map(|aggregate| aggregate.operator_commitment == operator_commitment)
                    .unwrap_or(false)
            })
            .count() as u64;
        let operator_aggregates = self
            .aggregates
            .values()
            .filter(|aggregate| aggregate.operator_commitment == operator_commitment)
            .collect::<Vec<_>>();
        let aggregates_built = operator_aggregates.len() as u64;
        let aggregate_ids = operator_aggregates
            .iter()
            .map(|aggregate| aggregate.aggregate_id)
            .collect::<BTreeSet<_>>();
        let leases_served = self
            .leases
            .values()
            .filter(|lease| aggregate_ids.contains(&lease.aggregate_id))
            .count() as u64;
        let attestations_signed = self
            .attestations
            .values()
            .filter(|attestation| attestation.verifier_commitment == operator_commitment)
            .count() as u64;
        let average_verify_ms = if aggregates_built == 0 {
            0
        } else {
            operator_aggregates
                .iter()
                .map(|aggregate| aggregate.verify_ms)
                .sum::<u64>()
                / aggregates_built
        };
        let rebate_units_paid = self
            .fee_rebates
            .values()
            .filter(|rebate| aggregate_ids.contains(&rebate.aggregate_id))
            .map(|rebate| rebate.rebate_units)
            .sum::<u64>();
        let fee_units_saved = self
            .leases
            .values()
            .filter(|lease| aggregate_ids.contains(&lease.aggregate_id))
            .map(|lease| lease.saved_fee_units)
            .sum::<u64>();
        let summary_id = self.counters.next_operator_summary_id();
        let summary = OperatorSummary::new(
            summary_id,
            operator_commitment,
            self.epoch,
            slots_managed,
            aggregates_built,
            leases_served,
            attestations_signed,
            self.counters.cache_hit_bps(),
            average_verify_ms,
            fee_units_saved,
            rebate_units_paid,
            self.counters.privacy_warnings,
        );
        self.operator_summaries.insert(summary_id, summary);
        self.push_event(json!({"event": "operator_summary_recorded", "summary_id": summary_id}));
        self.refresh_roots();
        Ok(summary_id)
    }

    pub fn advance_height(&mut self, new_height: u64) {
        if new_height <= self.height {
            return;
        }
        self.height = new_height;
        self.expire_stale_records();
        self.refresh_roots();
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = self.config.config_commitment();
        self.roots.counters_root = self.counters.counters_commitment();
        self.roots.slots_root = merkle_root(
            D_SLOTS,
            self.slots
                .values()
                .map(|slot| Value::String(slot.commitment()))
                .collect(),
        );
        self.roots.aggregates_root = merkle_root(
            D_AGGREGATES,
            self.aggregates
                .values()
                .map(|aggregate| Value::String(aggregate.commitment()))
                .collect(),
        );
        self.roots.leases_root = merkle_root(
            D_LEASES,
            self.leases
                .values()
                .map(|lease| Value::String(lease.commitment()))
                .collect(),
        );
        self.roots.attestations_root = merkle_root(
            D_ATTESTATIONS,
            self.attestations
                .values()
                .map(|attestation| Value::String(attestation.commitment()))
                .collect(),
        );
        self.roots.witness_metadata_root = merkle_root(
            D_WITNESS,
            self.witness_metadata
                .values()
                .map(|metadata| Value::String(metadata.commitment()))
                .collect(),
        );
        self.roots.invalidation_fences_root = merkle_root(
            D_FENCES,
            self.invalidation_fences
                .values()
                .map(|fence| Value::String(fence.commitment()))
                .collect(),
        );
        self.roots.fee_rebates_root = merkle_root(
            D_REBATES,
            self.fee_rebates
                .values()
                .map(|rebate| Value::String(rebate.commitment()))
                .collect(),
        );
        self.roots.operator_summaries_root = merkle_root(
            D_SUMMARIES,
            self.operator_summaries
                .values()
                .map(|summary| Value::String(summary.commitment()))
                .collect(),
        );
        self.roots.public_events_root = merkle_root(D_EVENTS, self.public_events.clone());
        self.roots.state_root = domain_hash(
            D_STATE,
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(SCHEMA_VERSION),
                HashPart::U64(self.height),
                HashPart::U64(self.epoch),
                HashPart::Str(self.roots.config_root.as_str()),
                HashPart::Str(self.roots.counters_root.as_str()),
                HashPart::Str(self.roots.slots_root.as_str()),
                HashPart::Str(self.roots.aggregates_root.as_str()),
                HashPart::Str(self.roots.leases_root.as_str()),
                HashPart::Str(self.roots.attestations_root.as_str()),
                HashPart::Str(self.roots.witness_metadata_root.as_str()),
                HashPart::Str(self.roots.invalidation_fences_root.as_str()),
                HashPart::Str(self.roots.fee_rebates_root.as_str()),
                HashPart::Str(self.roots.operator_summaries_root.as_str()),
                HashPart::Str(self.roots.public_events_root.as_str()),
            ],
        );
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        for slot in self.slots.values() {
            slot.validate(&self.config)?;
        }
        for aggregate in self.aggregates.values() {
            aggregate.validate(&self.config)?;
        }
        for lease in self.leases.values() {
            if !self.slots.contains_key(&lease.slot_id) {
                return Err(format!("lease {} references unknown slot", lease.lease_id));
            }
            if !self.aggregates.contains_key(&lease.aggregate_id) {
                return Err(format!(
                    "lease {} references unknown aggregate",
                    lease.lease_id
                ));
            }
        }
        for attestation in self.attestations.values() {
            if !self.aggregates.contains_key(&attestation.aggregate_id) {
                return Err(format!(
                    "attestation {} references unknown aggregate",
                    attestation.attestation_id
                ));
            }
        }
        Ok(())
    }

    pub fn cache_hit_bps(&self) -> u64 {
        self.counters.cache_hit_bps()
    }

    pub fn reusable_aggregates(&self) -> Vec<&RecursiveAggregateCommitment> {
        self.aggregates
            .values()
            .filter(|aggregate| aggregate.status.reusable())
            .collect()
    }

    pub fn best_reuse_candidates(&self, limit: usize) -> Vec<&ProofBatchSlot> {
        let mut slots = self
            .slots
            .values()
            .filter(|slot| slot.status.accepts_lease())
            .collect::<Vec<_>>();
        slots.sort_by_key(|slot| std::cmp::Reverse(slot.low_fee_score()));
        slots.truncate(limit);
        slots
    }

    fn install_devnet_fixtures(&mut self) {
        let slot_a = self
            .open_slot(
                ProofWorkloadKind::TransferBatch,
                "devnet-batch-commitment-transfer-0001",
                "nebula-private-transfer-v3",
                "vk-transfer-recursive-pq-001",
                "owner-commitment-devnet-wallet-ring-01",
                524_288,
                256,
                512,
            )
            .expect("devnet slot a");
        let slot_b = self
            .open_slot(
                ProofWorkloadKind::TokenNetting,
                "devnet-batch-commitment-token-netting-0002",
                "nebula-confidential-token-netting-v2",
                "vk-token-netting-recursive-pq-004",
                "owner-commitment-devnet-market-maker-02",
                786_432,
                256,
                1_024,
            )
            .expect("devnet slot b");
        let slot_c = self
            .open_slot(
                ProofWorkloadKind::MoneroBridgeExit,
                "devnet-batch-commitment-monero-exit-0003",
                "nebula-monero-bridge-exit-v5",
                "vk-monero-exit-recursive-pq-003",
                "owner-commitment-devnet-bridge-relay-03",
                1_048_576,
                256,
                256,
            )
            .expect("devnet slot c");
        let meta_a = self
            .attach_witness_metadata(
                slot_a,
                WitnessRedactionLevel::BucketedShape,
                "witness-commitment-transfer-redacted-0001",
                248,
                96,
                512,
                524_288,
            )
            .expect("devnet metadata a");
        let meta_b = self
            .attach_witness_metadata(
                slot_b,
                WitnessRedactionLevel::RangeBounded,
                "witness-commitment-token-netting-redacted-0002",
                251,
                128,
                1_024,
                786_432,
            )
            .expect("devnet metadata b");
        let meta_c = self
            .attach_witness_metadata(
                slot_c,
                WitnessRedactionLevel::CommitmentOnly,
                "witness-commitment-monero-exit-redacted-0003",
                253,
                80,
                256,
                1_048_576,
            )
            .expect("devnet metadata c");
        for metadata_id in [meta_a, meta_b, meta_c] {
            if let Some(metadata) = self.witness_metadata.get_mut(&metadata_id) {
                metadata.add_audit_tag("devnet-redacted-fixture");
            }
        }
        let aggregate_id = self
            .build_recursive_aggregate(
                "vk-devnet-combined-recursive-pq-010",
                vec![slot_a, slot_b, slot_c],
                Vec::new(),
                "operator-commitment-devnet-fast-proof-cache-01",
            )
            .expect("devnet aggregate");
        self.attest_aggregate(
            aggregate_id,
            PqVerifierKind::HybridMlDsaSlhDsa,
            "operator-commitment-devnet-fast-proof-cache-01",
            "vk-devnet-combined-recursive-pq-010",
            "transcript-root-devnet-recursive-aggregate-010",
            "public-input-root-devnet-recursive-aggregate-010",
            144,
        )
        .expect("devnet attestation");
        if let Some(aggregate) = self.aggregates.get_mut(&aggregate_id) {
            aggregate.mark_cached();
        }
        let lease_id = self
            .lease_cached_proof(
                slot_a,
                "requester-commitment-devnet-wallet-fast-sync-01",
                400,
            )
            .expect("devnet lease");
        self.fulfill_lease(lease_id).expect("devnet fulfill lease");
        let rebate_id = self
            .create_fee_rebate(
                lease_id,
                "recipient-commitment-devnet-wallet-fast-sync-01",
                "sponsor-commitment-devnet-low-fee-pool-01",
            )
            .expect("devnet rebate");
        if let Some(rebate) = self.fee_rebates.get_mut(&rebate_id) {
            rebate.mark_claimable();
        }
        self.summarize_operator("operator-commitment-devnet-fast-proof-cache-01")
            .expect("devnet operator summary");
    }

    fn expire_stale_records(&mut self) {
        for slot in self.slots.values_mut() {
            if slot.status.is_live() && slot.is_expired(self.height) {
                slot.status = SlotStatus::Expired;
                slot.cache_tier = CacheTier::Archive;
            }
        }
        for aggregate in self.aggregates.values_mut() {
            if aggregate.status.reusable() && aggregate.is_expired(self.height) {
                aggregate.status = AggregateStatus::Expired;
            }
        }
        for lease in self.leases.values_mut() {
            if matches!(lease.status, LeaseStatus::Reserved | LeaseStatus::Active)
                && lease.is_expired(self.height)
            {
                lease.status = LeaseStatus::Expired;
            }
        }
        for attestation in self.attestations.values_mut() {
            if !matches!(
                attestation.status,
                AttestationStatus::Finalized | AttestationStatus::Rejected
            ) && attestation.is_expired(self.height)
            {
                attestation.status = AttestationStatus::Expired;
            }
        }
        for fence in self.invalidation_fences.values_mut() {
            if fence.active && fence.is_expired(self.height) {
                fence.deactivate();
            }
        }
        for rebate in self.fee_rebates.values_mut() {
            if !matches!(
                rebate.status,
                RebateStatus::Settled | RebateStatus::ClawedBack
            ) && rebate.is_expired(self.height)
            {
                rebate.status = RebateStatus::Expired;
            } else if rebate.status == RebateStatus::Accruing
                && self.height >= rebate.claimable_height
            {
                rebate.mark_claimable();
            }
        }
    }

    fn active_fence_blocks_slot(&self, slot: &ProofBatchSlot) -> bool {
        self.invalidation_fences.values().any(|fence| {
            fence.active && fence.fence_kind.invalidates_reuse() && fence.matches_slot(slot)
        })
    }

    fn require_slot(&self, slot_id: u64) -> Result<&ProofBatchSlot> {
        self.slots
            .get(&slot_id)
            .ok_or_else(|| format!("unknown proof batch slot {}", slot_id))
    }

    fn require_aggregate(&self, aggregate_id: u64) -> Result<&RecursiveAggregateCommitment> {
        self.aggregates
            .get(&aggregate_id)
            .ok_or_else(|| format!("unknown recursive aggregate {}", aggregate_id))
    }

    fn ensure_capacity(&self, current: usize, max: usize, label: &str) -> Result<()> {
        if current >= max {
            Err(format!("{} capacity exhausted", label))
        } else {
            Ok(())
        }
    }

    fn push_event(&mut self, event: Value) {
        self.public_events.push(event);
        if self.public_events.len() > self.config.max_public_events {
            let overflow = self.public_events.len() - self.config.max_public_events;
            self.public_events.drain(0..overflow);
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let mut state = State::devnet();
    let demo_slot = state
        .open_slot(
            ProofWorkloadKind::LowFeeBulk,
            "demo-batch-commitment-low-fee-bulk-9001",
            "nebula-low-fee-bulk-transfer-v1",
            "vk-low-fee-bulk-recursive-pq-9001",
            "owner-commitment-demo-low-fee-batcher",
            524_288,
            256,
            2_048,
        )
        .expect("demo slot");
    state
        .attach_witness_metadata(
            demo_slot,
            WitnessRedactionLevel::CommitmentOnly,
            "witness-commitment-demo-low-fee-bulk-redacted",
            250,
            144,
            2_048,
            524_288,
        )
        .expect("demo witness metadata");
    let aggregate_id = state
        .build_recursive_aggregate(
            "vk-low-fee-bulk-recursive-pq-9001",
            vec![demo_slot],
            state
                .reusable_aggregates()
                .iter()
                .map(|a| a.aggregate_id)
                .collect(),
            "operator-commitment-demo-cache-reuse-router",
        )
        .expect("demo aggregate");
    state
        .attest_aggregate(
            aggregate_id,
            PqVerifierKind::CommitteeQuorum,
            "operator-commitment-demo-cache-reuse-router",
            "vk-low-fee-bulk-recursive-pq-9001",
            "transcript-root-demo-low-fee-bulk",
            "public-input-root-demo-low-fee-bulk",
            172,
        )
        .expect("demo attestation");
    if let Some(aggregate) = state.aggregates.get_mut(&aggregate_id) {
        aggregate.mark_cached();
    }
    let lease_id = state
        .lease_cached_proof(
            demo_slot,
            "requester-commitment-demo-wallet-batch-reuse",
            512,
        )
        .expect("demo lease");
    state.fulfill_lease(lease_id).expect("demo fulfill lease");
    state
        .create_fee_rebate(
            lease_id,
            "recipient-commitment-demo-wallet-batch-reuse",
            "sponsor-commitment-demo-proof-reuse-vault",
        )
        .expect("demo rebate");
    state
        .summarize_operator("operator-commitment-demo-cache-reuse-router")
        .expect("demo summary");
    state.refresh_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    json!({
        "protocol_version": PROTOCOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "chain_id": state.config.chain_id,
        "l2_network": state.config.l2_network,
        "monero_network": state.config.monero_network,
        "height": state.height,
        "epoch": state.epoch,
        "fee_asset_id": state.config.fee_asset_id,
        "pq_verifier_suite": state.config.pq_verifier_suite,
        "hash_suite": state.config.hash_suite,
        "target_verify_ms": state.config.target_verify_ms,
        "hard_verify_ms": state.config.hard_verify_ms,
        "target_cache_hit_bps": state.config.target_cache_hit_bps,
        "cache_hit_bps": state.cache_hit_bps(),
        "slots": state.slots.values().map(ProofBatchSlot::public_value).collect::<Vec<_>>(),
        "aggregates": state.aggregates.values().map(RecursiveAggregateCommitment::public_value).collect::<Vec<_>>(),
        "leases": state.leases.values().map(CacheLease::public_value).collect::<Vec<_>>(),
        "pq_verifier_attestations": state.attestations.values().map(PqVerifierAttestation::public_value).collect::<Vec<_>>(),
        "witness_redaction_metadata": state.witness_metadata.values().map(WitnessRedactionMetadata::public_value).collect::<Vec<_>>(),
        "invalidation_fences": state.invalidation_fences.values().map(InvalidationFence::public_value).collect::<Vec<_>>(),
        "fee_rebates": state.fee_rebates.values().map(FeeRebate::public_value).collect::<Vec<_>>(),
        "operator_summaries": state.operator_summaries.values().map(OperatorSummary::public_value).collect::<Vec<_>>(),
        "counters": {
            "slots_opened": state.counters.slots_opened,
            "slots_filled": state.counters.slots_filled,
            "cache_hits": state.counters.cache_hits,
            "cache_misses": state.counters.cache_misses,
            "cache_hit_bps": state.counters.cache_hit_bps(),
            "aggregates_verified": state.counters.aggregates_verified,
            "aggregate_reuses": state.counters.aggregate_reuses,
            "leases_fulfilled": state.counters.leases_fulfilled,
            "attestations_accepted": state.counters.attestations_accepted,
            "attestations_rejected": state.counters.attestations_rejected,
            "fences_triggered": state.counters.fences_triggered,
            "rebates_claimed": state.counters.rebates_claimed,
            "fee_units_saved": state.counters.fee_units_saved,
            "verify_ms_saved": state.counters.verify_ms_saved,
            "witness_bytes_redacted": state.counters.witness_bytes_redacted,
            "privacy_warnings": state.counters.privacy_warnings,
        },
        "roots": state.roots.public_value(),
        "public_events": state.public_events,
    })
}

pub fn state_root(state: &State) -> String {
    state.roots.state_root.clone()
}
