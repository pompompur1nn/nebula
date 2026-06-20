use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialParallelReceiptDiffCacheRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_RECEIPT_DIFF_CACHE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-parallel-receipt-diff-cache-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_RECEIPT_DIFF_CACHE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-receipt-diff-cache-v1";
pub const RECEIPT_DIFF_ENCRYPTION_SUITE: &str = "hybrid-pq-confidential-receipt-diff-lane-root-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_amounts_addresses_view_keys_key_images_decoy_graphs_or_diff_bytes";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_RECEIPT_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_RECEIPT_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_PARALLEL_SHARDS: u16 = 64;
pub const DEFAULT_MAX_LANES: usize = 2_097_152;
pub const DEFAULT_MAX_LEASES: usize = 2_097_152;
pub const DEFAULT_MAX_SHARDS: usize = 16_384;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_FENCES: usize = 1_048_576;
pub const DEFAULT_MAX_CREDITS: usize = 4_194_304;
pub const DEFAULT_MAX_REDACTIONS: usize = 2_097_152;
pub const DEFAULT_MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const DEFAULT_MAX_DIFFS_PER_LANE: u32 = 16_384;
pub const DEFAULT_LEASE_TTL_BLOCKS: u64 = 240;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 120;
pub const DEFAULT_FENCE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_LOW_FEE_CREDIT_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_MAX_CACHE_FEE_BPS: u64 = 7;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 4;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_500;
pub const DEFAULT_MAX_REDACTION_UNITS_PER_RECEIPT: u64 = 48;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptDiffLaneKind {
    BridgeDeposit,
    BridgeWithdrawal,
    ShieldedTransfer,
    AtomicSwapFill,
    RfqSettlement,
    DarkpoolFill,
    FeeRebate,
    OperatorNetting,
}

impl ReceiptDiffLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeDeposit => "bridge_deposit",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::ShieldedTransfer => "shielded_transfer",
            Self::AtomicSwapFill => "atomic_swap_fill",
            Self::RfqSettlement => "rfq_settlement",
            Self::DarkpoolFill => "darkpool_fill",
            Self::FeeRebate => "fee_rebate",
            Self::OperatorNetting => "operator_netting",
        }
    }

    pub fn speed_weight(self) -> u64 {
        match self {
            Self::OperatorNetting => 1_000,
            Self::BridgeWithdrawal => 960,
            Self::BridgeDeposit => 920,
            Self::DarkpoolFill => 880,
            Self::AtomicSwapFill => 820,
            Self::RfqSettlement => 780,
            Self::ShieldedTransfer => 720,
            Self::FeeRebate => 640,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Indexed,
    Leased,
    Attested,
    RebateQueued,
    Fenced,
    Invalidated,
    Retired,
}

impl LaneStatus {
    pub fn accepts_diff(self) -> bool {
        matches!(self, Self::Open | Self::Indexed | Self::Leased)
    }

    pub fn publicly_usable(self) -> bool {
        matches!(
            self,
            Self::Indexed | Self::Leased | Self::Attested | Self::RebateQueued
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseStatus {
    Posted,
    Matched,
    Streaming,
    Sealed,
    Settled,
    Expired,
    Cancelled,
    Slashed,
}

impl LeaseStatus {
    pub fn active(self) -> bool {
        matches!(self, Self::Posted | Self::Matched | Self::Streaming)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardStatus {
    Empty,
    Warming,
    Hot,
    Saturated,
    Fenced,
    Draining,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Accepted,
    Quorum,
    NeedsReindex,
    Quarantined,
    Rejected,
}

impl AttestationVerdict {
    pub fn counts_for_index(self) -> bool {
        matches!(self, Self::Accepted | Self::Quorum)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceReason {
    ReceiptRootSuperseded,
    DiffCommitmentMismatch,
    PqAttestationExpired,
    ShardHotspot,
    PrivacyBudgetExceeded,
    LowFeeCreditAbuse,
    OperatorEquivocation,
    EmergencyInvalidation,
}

impl FenceReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReceiptRootSuperseded => "receipt_root_superseded",
            Self::DiffCommitmentMismatch => "diff_commitment_mismatch",
            Self::PqAttestationExpired => "pq_attestation_expired",
            Self::ShardHotspot => "shard_hotspot",
            Self::PrivacyBudgetExceeded => "privacy_budget_exceeded",
            Self::LowFeeCreditAbuse => "low_fee_credit_abuse",
            Self::OperatorEquivocation => "operator_equivocation",
            Self::EmergencyInvalidation => "emergency_invalidation",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditStatus {
    Minted,
    Reserved,
    Applied,
    RebateQueued,
    Settled,
    Expired,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionScope {
    ReceiptLeaf,
    DiffPayload,
    OperatorPath,
    LeasePricing,
    AttestationWitness,
    InvalidationMemo,
}

impl RedactionScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReceiptLeaf => "receipt_leaf",
            Self::DiffPayload => "diff_payload",
            Self::OperatorPath => "operator_path",
            Self::LeasePricing => "lease_pricing",
            Self::AttestationWitness => "attestation_witness",
            Self::InvalidationMemo => "invalidation_memo",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorTier {
    Seed,
    Standard,
    Preferred,
    LowFeeMaker,
    EmergencyIndexer,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub receipt_diff_encryption_suite: String,
    pub privacy_boundary: String,
    pub min_pq_security_bits: u16,
    pub min_receipt_privacy_set_size: u64,
    pub target_receipt_privacy_set_size: u64,
    pub parallel_shards: u16,
    pub max_lanes: usize,
    pub max_leases: usize,
    pub max_shards: usize,
    pub max_attestations: usize,
    pub max_fences: usize,
    pub max_credits: usize,
    pub max_redactions: usize,
    pub max_operator_summaries: usize,
    pub max_diffs_per_lane: u32,
    pub lease_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub fence_ttl_blocks: u64,
    pub low_fee_credit_ttl_blocks: u64,
    pub max_cache_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub max_redaction_units_per_receipt: u64,
    pub require_roots_only_records: bool,
    pub require_monotonic_receipt_indices: bool,
    pub require_parallel_shard_affinity: bool,
    pub require_low_fee_market_credits: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            receipt_diff_encryption_suite: RECEIPT_DIFF_ENCRYPTION_SUITE.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_receipt_privacy_set_size: DEFAULT_MIN_RECEIPT_PRIVACY_SET_SIZE,
            target_receipt_privacy_set_size: DEFAULT_TARGET_RECEIPT_PRIVACY_SET_SIZE,
            parallel_shards: DEFAULT_PARALLEL_SHARDS,
            max_lanes: DEFAULT_MAX_LANES,
            max_leases: DEFAULT_MAX_LEASES,
            max_shards: DEFAULT_MAX_SHARDS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_fences: DEFAULT_MAX_FENCES,
            max_credits: DEFAULT_MAX_CREDITS,
            max_redactions: DEFAULT_MAX_REDACTIONS,
            max_operator_summaries: DEFAULT_MAX_OPERATOR_SUMMARIES,
            max_diffs_per_lane: DEFAULT_MAX_DIFFS_PER_LANE,
            lease_ttl_blocks: DEFAULT_LEASE_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            fence_ttl_blocks: DEFAULT_FENCE_TTL_BLOCKS,
            low_fee_credit_ttl_blocks: DEFAULT_LOW_FEE_CREDIT_TTL_BLOCKS,
            max_cache_fee_bps: DEFAULT_MAX_CACHE_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            max_redaction_units_per_receipt: DEFAULT_MAX_REDACTION_UNITS_PER_RECEIPT,
            require_roots_only_records: true,
            require_monotonic_receipt_indices: true,
            require_parallel_shard_affinity: true,
            require_low_fee_market_credits: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_non_empty("l2_network", &self.l2_network)?;
        ensure_non_empty("monero_network", &self.monero_network)?;
        ensure_non_empty("protocol_version", &self.protocol_version)?;
        ensure_non_empty("hash_suite", &self.hash_suite)?;
        ensure_non_empty("pq_attestation_suite", &self.pq_attestation_suite)?;
        ensure_non_empty(
            "receipt_diff_encryption_suite",
            &self.receipt_diff_encryption_suite,
        )?;
        ensure_min_u16("min_pq_security_bits", self.min_pq_security_bits, 128)?;
        ensure_min_u64(
            "min_receipt_privacy_set_size",
            self.min_receipt_privacy_set_size,
            16,
        )?;
        ensure_min_u64(
            "target_receipt_privacy_set_size",
            self.target_receipt_privacy_set_size,
            self.min_receipt_privacy_set_size,
        )?;
        ensure_min_u16("parallel_shards", self.parallel_shards, 1)?;
        ensure_positive_usize("max_lanes", self.max_lanes)?;
        ensure_positive_usize("max_leases", self.max_leases)?;
        ensure_positive_usize("max_shards", self.max_shards)?;
        ensure_positive_usize("max_attestations", self.max_attestations)?;
        ensure_positive_usize("max_fences", self.max_fences)?;
        ensure_positive_usize("max_credits", self.max_credits)?;
        ensure_positive_usize("max_redactions", self.max_redactions)?;
        ensure_positive_usize("max_operator_summaries", self.max_operator_summaries)?;
        ensure_min_u64("lease_ttl_blocks", self.lease_ttl_blocks, 1)?;
        ensure_min_u64("attestation_ttl_blocks", self.attestation_ttl_blocks, 1)?;
        ensure_min_u64("fence_ttl_blocks", self.fence_ttl_blocks, 1)?;
        ensure_min_u64(
            "low_fee_credit_ttl_blocks",
            self.low_fee_credit_ttl_blocks,
            1,
        )?;
        ensure_bps("max_cache_fee_bps", self.max_cache_fee_bps)?;
        ensure_bps("target_rebate_bps", self.target_rebate_bps)?;
        ensure_bps("sponsor_cover_bps", self.sponsor_cover_bps)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "pq_attestation_suite": self.pq_attestation_suite,
            "receipt_diff_encryption_suite": self.receipt_diff_encryption_suite,
            "privacy_boundary": self.privacy_boundary,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_receipt_privacy_set_size": self.min_receipt_privacy_set_size,
            "target_receipt_privacy_set_size": self.target_receipt_privacy_set_size,
            "parallel_shards": self.parallel_shards,
            "max_lanes": self.max_lanes,
            "max_leases": self.max_leases,
            "max_shards": self.max_shards,
            "max_attestations": self.max_attestations,
            "max_fences": self.max_fences,
            "max_credits": self.max_credits,
            "max_redactions": self.max_redactions,
            "max_operator_summaries": self.max_operator_summaries,
            "max_diffs_per_lane": self.max_diffs_per_lane,
            "lease_ttl_blocks": self.lease_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "fence_ttl_blocks": self.fence_ttl_blocks,
            "low_fee_credit_ttl_blocks": self.low_fee_credit_ttl_blocks,
            "max_cache_fee_bps": self.max_cache_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "max_redaction_units_per_receipt": self.max_redaction_units_per_receipt,
            "require_roots_only_records": self.require_roots_only_records,
            "require_monotonic_receipt_indices": self.require_monotonic_receipt_indices,
            "require_parallel_shard_affinity": self.require_parallel_shard_affinity,
            "require_low_fee_market_credits": self.require_low_fee_market_credits,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub lanes_opened: u64,
    pub receipt_diffs_indexed: u64,
    pub receipt_shards_created: u64,
    pub leases_posted: u64,
    pub leases_settled: u64,
    pub pq_attestations_recorded: u64,
    pub invalidation_fences_posted: u64,
    pub low_fee_credits_minted: u64,
    pub low_fee_credits_applied: u64,
    pub redactions_recorded: u64,
    pub operator_summaries_recorded: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub bytes_indexed: u64,
    pub deterministic_root_updates: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "lanes_opened": self.lanes_opened,
            "receipt_diffs_indexed": self.receipt_diffs_indexed,
            "receipt_shards_created": self.receipt_shards_created,
            "leases_posted": self.leases_posted,
            "leases_settled": self.leases_settled,
            "pq_attestations_recorded": self.pq_attestations_recorded,
            "invalidation_fences_posted": self.invalidation_fences_posted,
            "low_fee_credits_minted": self.low_fee_credits_minted,
            "low_fee_credits_applied": self.low_fee_credits_applied,
            "redactions_recorded": self.redactions_recorded,
            "operator_summaries_recorded": self.operator_summaries_recorded,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "bytes_indexed": self.bytes_indexed,
            "deterministic_root_updates": self.deterministic_root_updates,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub encrypted_lane_root: String,
    pub cache_lease_root: String,
    pub receipt_shard_root: String,
    pub pq_attestation_root: String,
    pub invalidation_fence_root: String,
    pub low_fee_credit_root: String,
    pub redaction_metadata_root: String,
    pub operator_summary_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "encrypted_lane_root": self.encrypted_lane_root,
            "cache_lease_root": self.cache_lease_root,
            "receipt_shard_root": self.receipt_shard_root,
            "pq_attestation_root": self.pq_attestation_root,
            "invalidation_fence_root": self.invalidation_fence_root,
            "low_fee_credit_root": self.low_fee_credit_root,
            "redaction_metadata_root": self.redaction_metadata_root,
            "operator_summary_root": self.operator_summary_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedReceiptDiffLane {
    pub lane_id: String,
    pub shard_id: String,
    pub lane_kind: ReceiptDiffLaneKind,
    pub status: LaneStatus,
    pub first_receipt_index: u64,
    pub next_receipt_index: u64,
    pub diff_count: u32,
    pub encrypted_diff_root: String,
    pub receipt_commitment_root: String,
    pub nullifier_set_root: String,
    pub redaction_root: String,
    pub pq_ciphertext_root: String,
    pub operator_id: String,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
    pub privacy_set_size: u64,
    pub byte_weight: u64,
    pub max_fee_bps: u64,
}

impl EncryptedReceiptDiffLane {
    pub fn new(
        lane_id: &str,
        shard_id: &str,
        lane_kind: ReceiptDiffLaneKind,
        first_receipt_index: u64,
        operator_id: &str,
        height: u64,
        config: &Config,
    ) -> Result<Self> {
        ensure_non_empty("lane_id", lane_id)?;
        ensure_non_empty("shard_id", shard_id)?;
        ensure_non_empty("operator_id", operator_id)?;
        Ok(Self {
            lane_id: lane_id.to_string(),
            shard_id: shard_id.to_string(),
            lane_kind,
            status: LaneStatus::Open,
            first_receipt_index,
            next_receipt_index: first_receipt_index,
            diff_count: 0,
            encrypted_diff_root: empty_root("LANE-ENCRYPTED-DIFFS"),
            receipt_commitment_root: empty_root("LANE-RECEIPT-COMMITMENTS"),
            nullifier_set_root: empty_root("LANE-NULLIFIERS"),
            redaction_root: empty_root("LANE-REDACTIONS"),
            pq_ciphertext_root: empty_root("LANE-PQ-CIPHERTEXTS"),
            operator_id: operator_id.to_string(),
            opened_at_height: height,
            updated_at_height: height,
            privacy_set_size: config.min_receipt_privacy_set_size,
            byte_weight: 0,
            max_fee_bps: config.max_cache_fee_bps,
        })
    }

    pub fn append_private_diff(
        &mut self,
        receipt_commitment: &str,
        encrypted_diff_root: &str,
        nullifier_root: &str,
        ciphertext_root: &str,
        byte_weight: u64,
        height: u64,
        config: &Config,
    ) -> Result<u64> {
        if !self.status.accepts_diff() {
            return Err(format!(
                "lane {} does not accept receipt diffs",
                self.lane_id
            ));
        }
        if self.diff_count >= config.max_diffs_per_lane {
            return Err(format!("lane {} diff capacity exhausted", self.lane_id));
        }
        ensure_non_empty("receipt_commitment", receipt_commitment)?;
        ensure_non_empty("encrypted_diff_root", encrypted_diff_root)?;
        ensure_non_empty("nullifier_root", nullifier_root)?;
        ensure_non_empty("ciphertext_root", ciphertext_root)?;
        let receipt_index = self.next_receipt_index;
        self.diff_count += 1;
        self.next_receipt_index += 1;
        self.byte_weight = self.byte_weight.saturating_add(byte_weight);
        self.updated_at_height = height;
        self.status = LaneStatus::Indexed;
        self.receipt_commitment_root = roll_root(
            "LANE-RECEIPT-COMMITMENT-ROLL",
            &self.receipt_commitment_root,
            receipt_commitment,
            receipt_index,
        );
        self.encrypted_diff_root = roll_root(
            "LANE-ENCRYPTED-DIFF-ROLL",
            &self.encrypted_diff_root,
            encrypted_diff_root,
            receipt_index,
        );
        self.nullifier_set_root = roll_root(
            "LANE-NULLIFIER-ROLL",
            &self.nullifier_set_root,
            nullifier_root,
            receipt_index,
        );
        self.pq_ciphertext_root = roll_root(
            "LANE-PQ-CIPHERTEXT-ROLL",
            &self.pq_ciphertext_root,
            ciphertext_root,
            receipt_index,
        );
        Ok(receipt_index)
    }

    pub fn receipt_range(&self) -> (u64, u64) {
        (self.first_receipt_index, self.next_receipt_index)
    }

    pub fn indexed_density(&self) -> u64 {
        if self.privacy_set_size == 0 {
            0
        } else {
            (self.diff_count as u64).saturating_mul(1_000_000) / self.privacy_set_size
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "shard_id": self.shard_id,
            "lane_kind": self.lane_kind.as_str(),
            "status": self.status,
            "first_receipt_index": self.first_receipt_index,
            "next_receipt_index": self.next_receipt_index,
            "diff_count": self.diff_count,
            "encrypted_diff_root": self.encrypted_diff_root,
            "receipt_commitment_root": self.receipt_commitment_root,
            "nullifier_set_root": self.nullifier_set_root,
            "redaction_root": self.redaction_root,
            "pq_ciphertext_root": self.pq_ciphertext_root,
            "operator_id": self.operator_id,
            "opened_at_height": self.opened_at_height,
            "updated_at_height": self.updated_at_height,
            "privacy_set_size": self.privacy_set_size,
            "byte_weight": self.byte_weight,
            "max_fee_bps": self.max_fee_bps,
            "indexed_density_ppm": self.indexed_density(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CacheLease {
    pub lease_id: String,
    pub lane_id: String,
    pub lessee_id: String,
    pub operator_id: String,
    pub status: LeaseStatus,
    pub receipt_start: u64,
    pub receipt_end: u64,
    pub max_fee_bps: u64,
    pub sponsor_credit_id: Option<String>,
    pub encrypted_access_root: String,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
    pub settled_at_height: Option<u64>,
    pub cache_hit_budget: u64,
    pub cache_hits: u64,
}

impl CacheLease {
    pub fn new(
        lease_id: &str,
        lane: &EncryptedReceiptDiffLane,
        lessee_id: &str,
        encrypted_access_root: &str,
        height: u64,
        config: &Config,
    ) -> Result<Self> {
        ensure_non_empty("lease_id", lease_id)?;
        ensure_non_empty("lessee_id", lessee_id)?;
        ensure_non_empty("encrypted_access_root", encrypted_access_root)?;
        ensure_bps("lease max_fee_bps", lane.max_fee_bps)?;
        Ok(Self {
            lease_id: lease_id.to_string(),
            lane_id: lane.lane_id.clone(),
            lessee_id: lessee_id.to_string(),
            operator_id: lane.operator_id.clone(),
            status: LeaseStatus::Posted,
            receipt_start: lane.first_receipt_index,
            receipt_end: lane.next_receipt_index,
            max_fee_bps: lane.max_fee_bps,
            sponsor_credit_id: None,
            encrypted_access_root: encrypted_access_root.to_string(),
            posted_at_height: height,
            expires_at_height: height.saturating_add(config.lease_ttl_blocks),
            settled_at_height: None,
            cache_hit_budget: lane.diff_count as u64,
            cache_hits: 0,
        })
    }

    pub fn attach_credit(&mut self, credit_id: &str) -> Result<()> {
        ensure_non_empty("credit_id", credit_id)?;
        self.sponsor_credit_id = Some(credit_id.to_string());
        self.status = LeaseStatus::Matched;
        Ok(())
    }

    pub fn record_hit(&mut self) -> bool {
        if self.cache_hits < self.cache_hit_budget {
            self.cache_hits += 1;
            self.status = LeaseStatus::Streaming;
            true
        } else {
            false
        }
    }

    pub fn settle(&mut self, height: u64) {
        self.status = LeaseStatus::Settled;
        self.settled_at_height = Some(height);
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lease_id": self.lease_id,
            "lane_id": self.lane_id,
            "lessee_id": self.lessee_id,
            "operator_id": self.operator_id,
            "status": self.status,
            "receipt_start": self.receipt_start,
            "receipt_end": self.receipt_end,
            "max_fee_bps": self.max_fee_bps,
            "sponsor_credit_id": self.sponsor_credit_id,
            "encrypted_access_root": self.encrypted_access_root,
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height,
            "settled_at_height": self.settled_at_height,
            "cache_hit_budget": self.cache_hit_budget,
            "cache_hits": self.cache_hits,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParallelReceiptShard {
    pub shard_id: String,
    pub shard_index: u16,
    pub status: ShardStatus,
    pub lane_ids: Vec<String>,
    pub receipt_index_root: String,
    pub high_watermark: u64,
    pub indexed_receipts: u64,
    pub active_leases: u64,
    pub average_fee_bps: u64,
    pub target_parallelism: u16,
    pub created_at_height: u64,
    pub updated_at_height: u64,
}

impl ParallelReceiptShard {
    pub fn new(shard_id: &str, shard_index: u16, height: u64, config: &Config) -> Result<Self> {
        ensure_non_empty("shard_id", shard_id)?;
        if shard_index >= config.parallel_shards {
            return Err(format!(
                "shard index {shard_index} outside configured parallelism"
            ));
        }
        Ok(Self {
            shard_id: shard_id.to_string(),
            shard_index,
            status: ShardStatus::Warming,
            lane_ids: Vec::new(),
            receipt_index_root: empty_root("PARALLEL-RECEIPT-SHARD"),
            high_watermark: 0,
            indexed_receipts: 0,
            active_leases: 0,
            average_fee_bps: 0,
            target_parallelism: config.parallel_shards,
            created_at_height: height,
            updated_at_height: height,
        })
    }

    pub fn attach_lane(&mut self, lane: &EncryptedReceiptDiffLane) -> Result<()> {
        if lane.shard_id != self.shard_id {
            return Err(format!(
                "lane {} does not belong to shard {}",
                lane.lane_id, self.shard_id
            ));
        }
        if !self.lane_ids.iter().any(|id| id == &lane.lane_id) {
            self.lane_ids.push(lane.lane_id.clone());
            self.lane_ids.sort();
        }
        self.high_watermark = self.high_watermark.max(lane.next_receipt_index);
        self.indexed_receipts = self.indexed_receipts.saturating_add(lane.diff_count as u64);
        self.average_fee_bps = rolling_average_bps(
            self.average_fee_bps,
            lane.max_fee_bps,
            self.lane_ids.len() as u64,
        );
        self.receipt_index_root = roll_root(
            "PARALLEL-SHARD-RECEIPT-INDEX",
            &self.receipt_index_root,
            &lane.receipt_commitment_root,
            lane.next_receipt_index,
        );
        self.status = if self.lane_ids.len() as u16 >= self.target_parallelism {
            ShardStatus::Hot
        } else {
            ShardStatus::Warming
        };
        self.updated_at_height = lane.updated_at_height;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "shard_id": self.shard_id,
            "shard_index": self.shard_index,
            "status": self.status,
            "lane_ids": self.lane_ids,
            "receipt_index_root": self.receipt_index_root,
            "high_watermark": self.high_watermark,
            "indexed_receipts": self.indexed_receipts,
            "active_leases": self.active_leases,
            "average_fee_bps": self.average_fee_bps,
            "target_parallelism": self.target_parallelism,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqIndexerAttestation {
    pub attestation_id: String,
    pub lane_id: String,
    pub shard_id: String,
    pub operator_id: String,
    pub committee_id: String,
    pub verdict: AttestationVerdict,
    pub pq_security_bits: u16,
    pub receipt_range_start: u64,
    pub receipt_range_end: u64,
    pub receipt_index_root: String,
    pub encrypted_diff_root: String,
    pub signature_root: String,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
}

impl PqIndexerAttestation {
    pub fn new(
        attestation_id: &str,
        lane: &EncryptedReceiptDiffLane,
        committee_id: &str,
        signature_root: &str,
        height: u64,
        config: &Config,
    ) -> Result<Self> {
        ensure_non_empty("attestation_id", attestation_id)?;
        ensure_non_empty("committee_id", committee_id)?;
        ensure_non_empty("signature_root", signature_root)?;
        Ok(Self {
            attestation_id: attestation_id.to_string(),
            lane_id: lane.lane_id.clone(),
            shard_id: lane.shard_id.clone(),
            operator_id: lane.operator_id.clone(),
            committee_id: committee_id.to_string(),
            verdict: AttestationVerdict::Accepted,
            pq_security_bits: config.min_pq_security_bits,
            receipt_range_start: lane.first_receipt_index,
            receipt_range_end: lane.next_receipt_index,
            receipt_index_root: lane.receipt_commitment_root.clone(),
            encrypted_diff_root: lane.encrypted_diff_root.clone(),
            signature_root: signature_root.to_string(),
            attested_at_height: height,
            expires_at_height: height.saturating_add(config.attestation_ttl_blocks),
        })
    }

    pub fn validates_lane(&self, lane: &EncryptedReceiptDiffLane) -> bool {
        self.lane_id == lane.lane_id
            && self.receipt_range_end == lane.next_receipt_index
            && self.encrypted_diff_root == lane.encrypted_diff_root
            && self.verdict.counts_for_index()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "lane_id": self.lane_id,
            "shard_id": self.shard_id,
            "operator_id": self.operator_id,
            "committee_id": self.committee_id,
            "verdict": self.verdict,
            "pq_security_bits": self.pq_security_bits,
            "receipt_range_start": self.receipt_range_start,
            "receipt_range_end": self.receipt_range_end,
            "receipt_index_root": self.receipt_index_root,
            "encrypted_diff_root": self.encrypted_diff_root,
            "signature_root": self.signature_root,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvalidationFence {
    pub fence_id: String,
    pub lane_id: String,
    pub shard_id: String,
    pub reason: FenceReason,
    pub receipt_start: u64,
    pub receipt_end: u64,
    pub superseded_root: String,
    pub replacement_root: String,
    pub posted_by: String,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
    pub invalidates_cache: bool,
}

impl InvalidationFence {
    pub fn new(
        fence_id: &str,
        lane: &EncryptedReceiptDiffLane,
        reason: FenceReason,
        replacement_root: &str,
        posted_by: &str,
        height: u64,
        config: &Config,
    ) -> Result<Self> {
        ensure_non_empty("fence_id", fence_id)?;
        ensure_non_empty("replacement_root", replacement_root)?;
        ensure_non_empty("posted_by", posted_by)?;
        Ok(Self {
            fence_id: fence_id.to_string(),
            lane_id: lane.lane_id.clone(),
            shard_id: lane.shard_id.clone(),
            reason,
            receipt_start: lane.first_receipt_index,
            receipt_end: lane.next_receipt_index,
            superseded_root: lane.encrypted_diff_root.clone(),
            replacement_root: replacement_root.to_string(),
            posted_by: posted_by.to_string(),
            posted_at_height: height,
            expires_at_height: height.saturating_add(config.fence_ttl_blocks),
            invalidates_cache: true,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "lane_id": self.lane_id,
            "shard_id": self.shard_id,
            "reason": self.reason.as_str(),
            "receipt_start": self.receipt_start,
            "receipt_end": self.receipt_end,
            "superseded_root": self.superseded_root,
            "replacement_root": self.replacement_root,
            "posted_by": self.posted_by,
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height,
            "invalidates_cache": self.invalidates_cache,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeCacheCredit {
    pub credit_id: String,
    pub sponsor_id: String,
    pub beneficiary_id: String,
    pub lane_id: Option<String>,
    pub status: CreditStatus,
    pub credit_units: u64,
    pub max_fee_bps: u64,
    pub rebate_bps: u64,
    pub commitment_root: String,
    pub minted_at_height: u64,
    pub expires_at_height: u64,
    pub applied_at_height: Option<u64>,
}

impl LowFeeCacheCredit {
    pub fn new(
        credit_id: &str,
        sponsor_id: &str,
        beneficiary_id: &str,
        credit_units: u64,
        commitment_root: &str,
        height: u64,
        config: &Config,
    ) -> Result<Self> {
        ensure_non_empty("credit_id", credit_id)?;
        ensure_non_empty("sponsor_id", sponsor_id)?;
        ensure_non_empty("beneficiary_id", beneficiary_id)?;
        ensure_non_empty("commitment_root", commitment_root)?;
        ensure_min_u64("credit_units", credit_units, 1)?;
        Ok(Self {
            credit_id: credit_id.to_string(),
            sponsor_id: sponsor_id.to_string(),
            beneficiary_id: beneficiary_id.to_string(),
            lane_id: None,
            status: CreditStatus::Minted,
            credit_units,
            max_fee_bps: config.max_cache_fee_bps,
            rebate_bps: config.target_rebate_bps,
            commitment_root: commitment_root.to_string(),
            minted_at_height: height,
            expires_at_height: height.saturating_add(config.low_fee_credit_ttl_blocks),
            applied_at_height: None,
        })
    }

    pub fn apply_to_lane(&mut self, lane_id: &str, height: u64) -> Result<()> {
        ensure_non_empty("lane_id", lane_id)?;
        self.lane_id = Some(lane_id.to_string());
        self.status = CreditStatus::Applied;
        self.applied_at_height = Some(height);
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "credit_id": self.credit_id,
            "sponsor_id": self.sponsor_id,
            "beneficiary_id": self.beneficiary_id,
            "lane_id": self.lane_id,
            "status": self.status,
            "credit_units": self.credit_units,
            "max_fee_bps": self.max_fee_bps,
            "rebate_bps": self.rebate_bps,
            "commitment_root": self.commitment_root,
            "minted_at_height": self.minted_at_height,
            "expires_at_height": self.expires_at_height,
            "applied_at_height": self.applied_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionMetadata {
    pub redaction_id: String,
    pub lane_id: String,
    pub receipt_index: u64,
    pub scope: RedactionScope,
    pub redacted_field_root: String,
    pub disclosure_policy_root: String,
    pub redaction_units: u64,
    pub auditor_hint_root: String,
    pub recorded_at_height: u64,
}

impl RedactionMetadata {
    pub fn new(
        redaction_id: &str,
        lane_id: &str,
        receipt_index: u64,
        scope: RedactionScope,
        redacted_field_root: &str,
        disclosure_policy_root: &str,
        auditor_hint_root: &str,
        height: u64,
    ) -> Result<Self> {
        ensure_non_empty("redaction_id", redaction_id)?;
        ensure_non_empty("lane_id", lane_id)?;
        ensure_non_empty("redacted_field_root", redacted_field_root)?;
        ensure_non_empty("disclosure_policy_root", disclosure_policy_root)?;
        ensure_non_empty("auditor_hint_root", auditor_hint_root)?;
        Ok(Self {
            redaction_id: redaction_id.to_string(),
            lane_id: lane_id.to_string(),
            receipt_index,
            scope,
            redacted_field_root: redacted_field_root.to_string(),
            disclosure_policy_root: disclosure_policy_root.to_string(),
            redaction_units: 1,
            auditor_hint_root: auditor_hint_root.to_string(),
            recorded_at_height: height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "redaction_id": self.redaction_id,
            "lane_id": self.lane_id,
            "receipt_index": self.receipt_index,
            "scope": self.scope.as_str(),
            "redacted_field_root": self.redacted_field_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "redaction_units": self.redaction_units,
            "auditor_hint_root": self.auditor_hint_root,
            "recorded_at_height": self.recorded_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub tier: OperatorTier,
    pub lane_count: u64,
    pub indexed_receipts: u64,
    pub active_leases: u64,
    pub settled_leases: u64,
    pub accepted_attestations: u64,
    pub posted_fences: u64,
    pub low_fee_credits_applied: u64,
    pub average_fee_bps: u64,
    pub uptime_score_ppm: u64,
    pub privacy_score_ppm: u64,
    pub summary_root: String,
    pub updated_at_height: u64,
}

impl OperatorSummary {
    pub fn new(
        summary_id: &str,
        operator_id: &str,
        tier: OperatorTier,
        height: u64,
    ) -> Result<Self> {
        ensure_non_empty("summary_id", summary_id)?;
        ensure_non_empty("operator_id", operator_id)?;
        Ok(Self {
            summary_id: summary_id.to_string(),
            operator_id: operator_id.to_string(),
            tier,
            lane_count: 0,
            indexed_receipts: 0,
            active_leases: 0,
            settled_leases: 0,
            accepted_attestations: 0,
            posted_fences: 0,
            low_fee_credits_applied: 0,
            average_fee_bps: 0,
            uptime_score_ppm: 1_000_000,
            privacy_score_ppm: 1_000_000,
            summary_root: empty_root("OPERATOR-SUMMARY"),
            updated_at_height: height,
        })
    }

    pub fn absorb_lane(&mut self, lane: &EncryptedReceiptDiffLane) {
        self.lane_count = self.lane_count.saturating_add(1);
        self.indexed_receipts = self.indexed_receipts.saturating_add(lane.diff_count as u64);
        self.average_fee_bps =
            rolling_average_bps(self.average_fee_bps, lane.max_fee_bps, self.lane_count);
        self.summary_root = roll_root(
            "OPERATOR-SUMMARY-LANE",
            &self.summary_root,
            &lane.encrypted_diff_root,
            lane.next_receipt_index,
        );
        self.updated_at_height = lane.updated_at_height;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "operator_id": self.operator_id,
            "tier": self.tier,
            "lane_count": self.lane_count,
            "indexed_receipts": self.indexed_receipts,
            "active_leases": self.active_leases,
            "settled_leases": self.settled_leases,
            "accepted_attestations": self.accepted_attestations,
            "posted_fences": self.posted_fences,
            "low_fee_credits_applied": self.low_fee_credits_applied,
            "average_fee_bps": self.average_fee_bps,
            "uptime_score_ppm": self.uptime_score_ppm,
            "privacy_score_ppm": self.privacy_score_ppm,
            "summary_root": self.summary_root,
            "updated_at_height": self.updated_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub encrypted_lanes: BTreeMap<String, EncryptedReceiptDiffLane>,
    pub cache_leases: BTreeMap<String, CacheLease>,
    pub receipt_shards: BTreeMap<String, ParallelReceiptShard>,
    pub pq_attestations: BTreeMap<String, PqIndexerAttestation>,
    pub invalidation_fences: BTreeMap<String, InvalidationFence>,
    pub low_fee_credits: BTreeMap<String, LowFeeCacheCredit>,
    pub redaction_metadata: BTreeMap<String, RedactionMetadata>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub receipt_index: BTreeMap<u64, String>,
    pub lane_by_operator: BTreeMap<String, Vec<String>>,
    pub last_height: u64,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            encrypted_lanes: BTreeMap::new(),
            cache_leases: BTreeMap::new(),
            receipt_shards: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            invalidation_fences: BTreeMap::new(),
            low_fee_credits: BTreeMap::new(),
            redaction_metadata: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            receipt_index: BTreeMap::new(),
            lane_by_operator: BTreeMap::new(),
            last_height: 0,
        })
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("valid receipt diff cache config");
        state
            .install_devnet_fixture()
            .expect("valid receipt diff cache devnet fixture");
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let _ = state.open_lane(
            "lane-demo-withdrawals-0003",
            "shard-demo-03",
            ReceiptDiffLaneKind::BridgeWithdrawal,
            3_000_000,
            "operator-demo-fast-indexer",
            904_030,
        );
        let _ = state.index_private_diff(
            "lane-demo-withdrawals-0003",
            "receipt-commitment-demo-0003",
            "encrypted-diff-root-demo-0003",
            "nullifier-root-demo-0003",
            "pq-ciphertext-root-demo-0003",
            8192,
            904_031,
        );
        let _ = state.record_pq_attestation(
            "att-demo-withdrawals-0003",
            "lane-demo-withdrawals-0003",
            "committee-devnet-pq-indexers",
            "signature-root-demo-0003",
            904_032,
        );
        state
    }

    fn install_devnet_fixture(&mut self) -> Result<()> {
        self.ensure_shard("shard-demo-01", 1, 904_000)?;
        self.ensure_shard("shard-demo-02", 2, 904_000)?;
        self.open_lane(
            "lane-demo-deposits-0001",
            "shard-demo-01",
            ReceiptDiffLaneKind::BridgeDeposit,
            1_000_000,
            "operator-demo-fast-indexer",
            904_001,
        )?;
        self.open_lane(
            "lane-demo-swaps-0002",
            "shard-demo-02",
            ReceiptDiffLaneKind::AtomicSwapFill,
            2_000_000,
            "operator-demo-low-fee-maker",
            904_002,
        )?;
        self.index_private_diff(
            "lane-demo-deposits-0001",
            "receipt-commitment-demo-0001",
            "encrypted-diff-root-demo-0001",
            "nullifier-root-demo-0001",
            "pq-ciphertext-root-demo-0001",
            4096,
            904_003,
        )?;
        self.index_private_diff(
            "lane-demo-swaps-0002",
            "receipt-commitment-demo-0002",
            "encrypted-diff-root-demo-0002",
            "nullifier-root-demo-0002",
            "pq-ciphertext-root-demo-0002",
            6144,
            904_004,
        )?;
        self.mint_low_fee_credit(
            "credit-demo-0001",
            "sponsor-demo-low-fee-market",
            "wallet-demo-private-user",
            128,
            "credit-commitment-root-demo-0001",
            904_005,
        )?;
        self.post_cache_lease(
            "lease-demo-0001",
            "lane-demo-deposits-0001",
            "wallet-demo-private-user",
            "encrypted-access-root-demo-0001",
            Some("credit-demo-0001"),
            904_006,
        )?;
        self.record_pq_attestation(
            "att-demo-deposits-0001",
            "lane-demo-deposits-0001",
            "committee-devnet-pq-indexers",
            "signature-root-demo-0001",
            904_007,
        )?;
        self.record_redaction(
            "redaction-demo-0001",
            "lane-demo-deposits-0001",
            1_000_000,
            RedactionScope::DiffPayload,
            "redacted-field-root-demo-0001",
            "disclosure-policy-root-demo-0001",
            "auditor-hint-root-demo-0001",
            904_008,
        )?;
        self.post_invalidation_fence(
            "fence-demo-0001",
            "lane-demo-swaps-0002",
            FenceReason::ReceiptRootSuperseded,
            "replacement-root-demo-0001",
            "watchtower-demo",
            904_009,
        )?;
        Ok(())
    }

    pub fn ensure_shard(&mut self, shard_id: &str, shard_index: u16, height: u64) -> Result<()> {
        if self.receipt_shards.contains_key(shard_id) {
            return Ok(());
        }
        ensure_capacity(
            "receipt_shards",
            self.receipt_shards.len(),
            self.config.max_shards,
        )?;
        let shard = ParallelReceiptShard::new(shard_id, shard_index, height, &self.config)?;
        self.receipt_shards.insert(shard_id.to_string(), shard);
        self.counters.receipt_shards_created += 1;
        self.last_height = self.last_height.max(height);
        Ok(())
    }

    pub fn open_lane(
        &mut self,
        lane_id: &str,
        shard_id: &str,
        lane_kind: ReceiptDiffLaneKind,
        first_receipt_index: u64,
        operator_id: &str,
        height: u64,
    ) -> Result<()> {
        ensure_capacity(
            "encrypted_lanes",
            self.encrypted_lanes.len(),
            self.config.max_lanes,
        )?;
        if self.encrypted_lanes.contains_key(lane_id) {
            return Err(format!("lane {lane_id} already exists"));
        }
        if !self.receipt_shards.contains_key(shard_id) {
            let shard_index = (stable_id_u64(shard_id) % self.config.parallel_shards as u64) as u16;
            self.ensure_shard(shard_id, shard_index, height)?;
        }
        let lane = EncryptedReceiptDiffLane::new(
            lane_id,
            shard_id,
            lane_kind,
            first_receipt_index,
            operator_id,
            height,
            &self.config,
        )?;
        self.lane_by_operator
            .entry(operator_id.to_string())
            .or_default()
            .push(lane_id.to_string());
        self.encrypted_lanes
            .insert(lane_id.to_string(), lane.clone());
        self.receipt_shards
            .get_mut(shard_id)
            .expect("shard exists")
            .attach_lane(&lane)?;
        self.operator_summary_mut(operator_id, height)?
            .absorb_lane(&lane);
        self.counters.lanes_opened += 1;
        self.last_height = self.last_height.max(height);
        Ok(())
    }

    pub fn index_private_diff(
        &mut self,
        lane_id: &str,
        receipt_commitment: &str,
        encrypted_diff_root: &str,
        nullifier_root: &str,
        ciphertext_root: &str,
        byte_weight: u64,
        height: u64,
    ) -> Result<u64> {
        let lane = self
            .encrypted_lanes
            .get_mut(lane_id)
            .ok_or_else(|| format!("unknown lane {lane_id}"))?;
        let receipt_index = lane.append_private_diff(
            receipt_commitment,
            encrypted_diff_root,
            nullifier_root,
            ciphertext_root,
            byte_weight,
            height,
            &self.config,
        )?;
        if self.config.require_monotonic_receipt_indices
            && self.receipt_index.contains_key(&receipt_index)
        {
            return Err(format!("receipt index {receipt_index} already indexed"));
        }
        self.receipt_index
            .insert(receipt_index, lane_id.to_string());
        let shard_id = lane.shard_id.clone();
        let operator_id = lane.operator_id.clone();
        let lane_snapshot = lane.clone();
        self.receipt_shards
            .get_mut(&shard_id)
            .ok_or_else(|| format!("missing shard {shard_id}"))?
            .attach_lane(&lane_snapshot)?;
        self.operator_summary_mut(&operator_id, height)?
            .absorb_lane(&lane_snapshot);
        self.counters.receipt_diffs_indexed += 1;
        self.counters.bytes_indexed = self.counters.bytes_indexed.saturating_add(byte_weight);
        self.last_height = self.last_height.max(height);
        Ok(receipt_index)
    }

    pub fn post_cache_lease(
        &mut self,
        lease_id: &str,
        lane_id: &str,
        lessee_id: &str,
        encrypted_access_root: &str,
        credit_id: Option<&str>,
        height: u64,
    ) -> Result<()> {
        ensure_capacity(
            "cache_leases",
            self.cache_leases.len(),
            self.config.max_leases,
        )?;
        if self.cache_leases.contains_key(lease_id) {
            return Err(format!("lease {lease_id} already exists"));
        }
        let lane = self
            .encrypted_lanes
            .get(lane_id)
            .ok_or_else(|| format!("unknown lane {lane_id}"))?
            .clone();
        let mut lease = CacheLease::new(
            lease_id,
            &lane,
            lessee_id,
            encrypted_access_root,
            height,
            &self.config,
        )?;
        if let Some(credit_id) = credit_id {
            let credit = self
                .low_fee_credits
                .get_mut(credit_id)
                .ok_or_else(|| format!("unknown credit {credit_id}"))?;
            credit.apply_to_lane(lane_id, height)?;
            lease.attach_credit(credit_id)?;
            self.counters.low_fee_credits_applied += 1;
        }
        if let Some(shard) = self.receipt_shards.get_mut(&lane.shard_id) {
            shard.active_leases = shard.active_leases.saturating_add(1);
        }
        self.operator_summary_mut(&lane.operator_id, height)?
            .active_leases += 1;
        self.cache_leases.insert(lease_id.to_string(), lease);
        self.counters.leases_posted += 1;
        self.last_height = self.last_height.max(height);
        Ok(())
    }

    pub fn record_cache_hit(&mut self, lease_id: &str) -> Result<()> {
        let lease = self
            .cache_leases
            .get_mut(lease_id)
            .ok_or_else(|| format!("unknown lease {lease_id}"))?;
        if lease.record_hit() {
            self.counters.cache_hits += 1;
        } else {
            self.counters.cache_misses += 1;
        }
        Ok(())
    }

    pub fn settle_cache_lease(&mut self, lease_id: &str, height: u64) -> Result<()> {
        let operator_id = {
            let lease = self
                .cache_leases
                .get_mut(lease_id)
                .ok_or_else(|| format!("unknown lease {lease_id}"))?;
            lease.settle(height);
            lease.operator_id.clone()
        };
        let summary = self.operator_summary_mut(&operator_id, height)?;
        summary.settled_leases = summary.settled_leases.saturating_add(1);
        summary.active_leases = summary.active_leases.saturating_sub(1);
        self.counters.leases_settled += 1;
        self.last_height = self.last_height.max(height);
        Ok(())
    }

    pub fn record_pq_attestation(
        &mut self,
        attestation_id: &str,
        lane_id: &str,
        committee_id: &str,
        signature_root: &str,
        height: u64,
    ) -> Result<()> {
        ensure_capacity(
            "pq_attestations",
            self.pq_attestations.len(),
            self.config.max_attestations,
        )?;
        if self.pq_attestations.contains_key(attestation_id) {
            return Err(format!("attestation {attestation_id} already exists"));
        }
        let lane = self
            .encrypted_lanes
            .get_mut(lane_id)
            .ok_or_else(|| format!("unknown lane {lane_id}"))?;
        let attestation = PqIndexerAttestation::new(
            attestation_id,
            lane,
            committee_id,
            signature_root,
            height,
            &self.config,
        )?;
        if attestation.validates_lane(lane) {
            lane.status = LaneStatus::Attested;
        }
        let operator_id = lane.operator_id.clone();
        self.operator_summary_mut(&operator_id, height)?
            .accepted_attestations += 1;
        self.pq_attestations
            .insert(attestation_id.to_string(), attestation);
        self.counters.pq_attestations_recorded += 1;
        self.last_height = self.last_height.max(height);
        Ok(())
    }

    pub fn post_invalidation_fence(
        &mut self,
        fence_id: &str,
        lane_id: &str,
        reason: FenceReason,
        replacement_root: &str,
        posted_by: &str,
        height: u64,
    ) -> Result<()> {
        ensure_capacity(
            "invalidation_fences",
            self.invalidation_fences.len(),
            self.config.max_fences,
        )?;
        if self.invalidation_fences.contains_key(fence_id) {
            return Err(format!("fence {fence_id} already exists"));
        }
        let lane = self
            .encrypted_lanes
            .get_mut(lane_id)
            .ok_or_else(|| format!("unknown lane {lane_id}"))?;
        let fence = InvalidationFence::new(
            fence_id,
            lane,
            reason,
            replacement_root,
            posted_by,
            height,
            &self.config,
        )?;
        lane.status = LaneStatus::Fenced;
        let operator_id = lane.operator_id.clone();
        self.operator_summary_mut(&operator_id, height)?
            .posted_fences += 1;
        self.invalidation_fences.insert(fence_id.to_string(), fence);
        self.counters.invalidation_fences_posted += 1;
        self.last_height = self.last_height.max(height);
        Ok(())
    }

    pub fn mint_low_fee_credit(
        &mut self,
        credit_id: &str,
        sponsor_id: &str,
        beneficiary_id: &str,
        credit_units: u64,
        commitment_root: &str,
        height: u64,
    ) -> Result<()> {
        ensure_capacity(
            "low_fee_credits",
            self.low_fee_credits.len(),
            self.config.max_credits,
        )?;
        if self.low_fee_credits.contains_key(credit_id) {
            return Err(format!("credit {credit_id} already exists"));
        }
        let credit = LowFeeCacheCredit::new(
            credit_id,
            sponsor_id,
            beneficiary_id,
            credit_units,
            commitment_root,
            height,
            &self.config,
        )?;
        self.low_fee_credits.insert(credit_id.to_string(), credit);
        self.counters.low_fee_credits_minted += 1;
        self.last_height = self.last_height.max(height);
        Ok(())
    }

    pub fn record_redaction(
        &mut self,
        redaction_id: &str,
        lane_id: &str,
        receipt_index: u64,
        scope: RedactionScope,
        redacted_field_root: &str,
        disclosure_policy_root: &str,
        auditor_hint_root: &str,
        height: u64,
    ) -> Result<()> {
        ensure_capacity(
            "redaction_metadata",
            self.redaction_metadata.len(),
            self.config.max_redactions,
        )?;
        if self.redaction_metadata.contains_key(redaction_id) {
            return Err(format!("redaction {redaction_id} already exists"));
        }
        let redaction = RedactionMetadata::new(
            redaction_id,
            lane_id,
            receipt_index,
            scope,
            redacted_field_root,
            disclosure_policy_root,
            auditor_hint_root,
            height,
        )?;
        let lane = self
            .encrypted_lanes
            .get_mut(lane_id)
            .ok_or_else(|| format!("unknown lane {lane_id}"))?;
        if redaction.redaction_units > self.config.max_redaction_units_per_receipt {
            return Err("redaction exceeds per-receipt budget".to_string());
        }
        lane.redaction_root = roll_root(
            "LANE-REDACTION-ROLL",
            &lane.redaction_root,
            redacted_field_root,
            receipt_index,
        );
        self.redaction_metadata
            .insert(redaction_id.to_string(), redaction);
        self.counters.redactions_recorded += 1;
        self.last_height = self.last_height.max(height);
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        let mut roots = Roots {
            config_root: value_root("CONFIG", &self.config.public_record()),
            counters_root: value_root("COUNTERS", &self.counters.public_record()),
            encrypted_lane_root: map_root("ENCRYPTED-LANES", &self.encrypted_lanes, |v| {
                v.public_record()
            }),
            cache_lease_root: map_root("CACHE-LEASES", &self.cache_leases, |v| v.public_record()),
            receipt_shard_root: map_root("RECEIPT-SHARDS", &self.receipt_shards, |v| {
                v.public_record()
            }),
            pq_attestation_root: map_root("PQ-ATTESTATIONS", &self.pq_attestations, |v| {
                v.public_record()
            }),
            invalidation_fence_root: map_root(
                "INVALIDATION-FENCES",
                &self.invalidation_fences,
                |v| v.public_record(),
            ),
            low_fee_credit_root: map_root("LOW-FEE-CREDITS", &self.low_fee_credits, |v| {
                v.public_record()
            }),
            redaction_metadata_root: map_root(
                "REDACTION-METADATA",
                &self.redaction_metadata,
                |v| v.public_record(),
            ),
            operator_summary_root: map_root("OPERATOR-SUMMARIES", &self.operator_summaries, |v| {
                v.public_record()
            }),
            public_record_root: String::new(),
            state_root: String::new(),
        };
        let public_record = json!({
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "last_height": self.last_height,
        });
        roots.public_record_root = value_root("PUBLIC-RECORD", &public_record);
        roots.state_root = state_root_from_record(&public_record);
        roots
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
            "encrypted_lanes": map_records(&self.encrypted_lanes, |v| v.public_record()),
            "cache_leases": map_records(&self.cache_leases, |v| v.public_record()),
            "receipt_shards": map_records(&self.receipt_shards, |v| v.public_record()),
            "pq_attestations": map_records(&self.pq_attestations, |v| v.public_record()),
            "invalidation_fences": map_records(&self.invalidation_fences, |v| v.public_record()),
            "low_fee_credits": map_records(&self.low_fee_credits, |v| v.public_record()),
            "redaction_metadata": map_records(&self.redaction_metadata, |v| v.public_record()),
            "operator_summaries": map_records(&self.operator_summaries, |v| v.public_record()),
            "receipt_index_root": receipt_index_root(&self.receipt_index),
            "lane_by_operator_root": operator_lane_root(&self.lane_by_operator),
            "last_height": self.last_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(object) = &mut record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn operator_summary_mut(
        &mut self,
        operator_id: &str,
        height: u64,
    ) -> Result<&mut OperatorSummary> {
        if !self.operator_summaries.contains_key(operator_id) {
            ensure_capacity(
                "operator_summaries",
                self.operator_summaries.len(),
                self.config.max_operator_summaries,
            )?;
            let tier = if operator_id.contains("low-fee") {
                OperatorTier::LowFeeMaker
            } else if operator_id.contains("emergency") {
                OperatorTier::EmergencyIndexer
            } else {
                OperatorTier::Standard
            };
            let summary =
                OperatorSummary::new(&format!("summary-{operator_id}"), operator_id, tier, height)?;
            self.operator_summaries
                .insert(operator_id.to_string(), summary);
            self.counters.operator_summaries_recorded += 1;
        }
        self.operator_summaries
            .get_mut(operator_id)
            .ok_or_else(|| format!("missing operator summary {operator_id}"))
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

pub fn state_root_from_record(record: &Value) -> String {
    value_root(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PARALLEL-RECEIPT-DIFF-CACHE-STATE",
        record,
    )
}

pub fn value_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn map_root<T, F>(domain: &str, values: &BTreeMap<String, T>, mut public_record: F) -> String
where
    F: FnMut(&T) -> Value,
{
    let leaves = values
        .iter()
        .enumerate()
        .map(|(index, (id, value))| {
            Value::String(value_root(
                domain,
                &json!({
                    "index": index,
                    "id": id,
                    "record": public_record(value),
                }),
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn map_records<T, F>(values: &BTreeMap<String, T>, mut public_record: F) -> Value
where
    F: FnMut(&T) -> Value,
{
    Value::Array(
        values
            .iter()
            .map(|(id, value)| {
                json!({
                    "id": id,
                    "record": public_record(value),
                })
            })
            .collect(),
    )
}

pub fn receipt_index_root(index: &BTreeMap<u64, String>) -> String {
    let leaves = index
        .iter()
        .map(|(receipt_index, lane_id)| {
            Value::String(value_root(
                "RECEIPT-INDEX",
                &json!({
                    "receipt_index": receipt_index,
                    "lane_id": lane_id,
                }),
            ))
        })
        .collect::<Vec<_>>();
    merkle_root("RECEIPT-INDEX", &leaves)
}

pub fn operator_lane_root(index: &BTreeMap<String, Vec<String>>) -> String {
    let leaves = index
        .iter()
        .map(|(operator_id, lane_ids)| {
            Value::String(value_root(
                "OPERATOR-LANE-INDEX",
                &json!({
                    "operator_id": operator_id,
                    "lane_ids": lane_ids,
                    "lane_ids_root": id_vec_root("OPERATOR-LANE-IDS", lane_ids),
                }),
            ))
        })
        .collect::<Vec<_>>();
    merkle_root("OPERATOR-LANE-INDEX", &leaves)
}

fn id_vec_root(domain: &str, ids: &[String]) -> String {
    let leaves = ids
        .iter()
        .enumerate()
        .map(|(index, id)| {
            Value::String(domain_hash(
                domain,
                &[HashPart::Int(index as i128), HashPart::Str(id)],
                32,
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

fn roll_root(domain: &str, previous_root: &str, next_root: &str, sequence: u64) -> String {
    value_root(
        domain,
        &json!({
            "previous_root": previous_root,
            "next_root": next_root,
            "sequence": sequence,
        }),
    )
}

fn rolling_average_bps(previous_average: u64, next_value: u64, sample_count: u64) -> u64 {
    if sample_count <= 1 {
        next_value
    } else {
        previous_average
            .saturating_mul(sample_count.saturating_sub(1))
            .saturating_add(next_value)
            / sample_count
    }
}

fn stable_id_u64(id: &str) -> u64 {
    id.as_bytes()
        .iter()
        .fold(0xcbf29ce484222325_u64, |acc, byte| {
            acc.wrapping_mul(0x100000001b3).wrapping_add(*byte as u64)
        })
}

fn ensure_non_empty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("receipt diff cache {name} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive_usize(name: &str, value: usize) -> Result<()> {
    if value == 0 {
        Err(format!("receipt diff cache {name} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_min_u16(name: &str, value: u16, min: u16) -> Result<()> {
    if value < min {
        Err(format!("receipt diff cache {name} must be at least {min}"))
    } else {
        Ok(())
    }
}

fn ensure_min_u64(name: &str, value: u64, min: u64) -> Result<()> {
    if value < min {
        Err(format!("receipt diff cache {name} must be at least {min}"))
    } else {
        Ok(())
    }
}

fn ensure_bps(name: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!(
            "receipt diff cache {name} exceeds basis-point maximum"
        ))
    } else {
        Ok(())
    }
}

fn ensure_capacity(name: &str, current: usize, max: usize) -> Result<()> {
    if current >= max {
        Err(format!("receipt diff cache {name} capacity exhausted"))
    } else {
        Ok(())
    }
}

#[allow(dead_code)]
fn ensure_unique(name: &str, values: &[String]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(name, value)?;
        if !seen.insert(value) {
            return Err(format!(
                "receipt diff cache {name} contains duplicate id {value}"
            ));
        }
    }
    Ok(())
}
