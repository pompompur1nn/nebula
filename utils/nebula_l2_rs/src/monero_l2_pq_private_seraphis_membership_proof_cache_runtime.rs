use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateSeraphisMembershipProofCacheRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_SERAPHIS_MEMBERSHIP_PROOF_CACHE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-seraphis-membership-proof-cache-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_SERAPHIS_MEMBERSHIP_PROOF_CACHE_RUNTIME_PROTOCOL_VERSION;
pub const MONERO_L2_PQ_PRIVATE_SERAPHIS_MEMBERSHIP_PROOF_CACHE_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_CACHE_ID: &str = "seraphis-membership-proof-cache-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SERAPHIS_MEMBERSHIP_SUITE: &str =
    "seraphis-membership-cache-key-image-free-ring-proof-v1";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-seraphis-cache-attestation-v1";
pub const WALLET_SCAN_HINT_SUITE: &str = "ml-kem-1024-sealed-seraphis-wallet-scan-hint-v1";
pub const RING_COMMITMENT_SCHEME: &str = "seraphis-ring-member-commitment-root-v1";
pub const CACHE_SHARD_SCHEME: &str = "seraphis-membership-cache-shard-root-v1";
pub const INVALIDATION_SCHEME: &str = "seraphis-membership-cache-invalidation-root-v1";
pub const FEE_REBATE_SCHEME: &str = "seraphis-low-fee-cache-rebate-root-v1";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_RING_SIZE: u32 = 128;
pub const DEFAULT_TARGET_RING_SIZE: u32 = 256;
pub const DEFAULT_MIN_DECOY_FRESHNESS_BLOCKS: u64 = 720;
pub const DEFAULT_STRICT_DECOY_FRESHNESS_BLOCKS: u64 = 2_160;
pub const DEFAULT_CACHE_TTL_BLOCKS: u64 = 7_200;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 360;
pub const DEFAULT_HINT_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_INVALIDATION_TTL_BLOCKS: u64 = 14_400;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 32_000;
pub const DEFAULT_MAX_BATCH_MEMBERS: usize = 16_384;
pub const DEFAULT_MAX_BATCHES_PER_SHARD: usize = 512;
pub const DEFAULT_BASE_FEE_PICONERO: u64 = 800;
pub const DEFAULT_FAST_FEE_PICONERO: u64 = 1_700;
pub const DEFAULT_CACHE_HIT_REBATE_BPS: u64 = 4_000;
pub const DEFAULT_FRESH_DECOY_REBATE_BPS: u64 = 1_500;
pub const DEFAULT_PQ_ATTESTED_REBATE_BPS: u64 = 1_000;
pub const DEFAULT_MAX_PUBLIC_HINT_BUCKETS: u16 = 64;
pub const DEFAULT_DEVNET_HEIGHT: u64 = 1_244_000;
pub const MAX_BATCHES: usize = 1_048_576;
pub const MAX_SHARDS: usize = 65_536;
pub const MAX_ATTESTATIONS: usize = 2_097_152;
pub const MAX_WALLET_HINTS: usize = 4_194_304;
pub const MAX_INVALIDATIONS: usize = 2_097_152;
pub const MAX_FEE_REBATES: usize = 2_097_152;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheLane {
    LowFee,
    Balanced,
    Fast,
    WalletScan,
    OperatorRepair,
    Emergency,
}

impl CacheLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::Balanced => "balanced",
            Self::Fast => "fast",
            Self::WalletScan => "wallet_scan",
            Self::OperatorRepair => "operator_repair",
            Self::Emergency => "emergency",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 1_000,
            Self::Fast => 940,
            Self::OperatorRepair => 860,
            Self::WalletScan => 780,
            Self::Balanced => 720,
            Self::LowFee => 640,
        }
    }

    pub fn fee_piconero(self, config: &Config) -> u64 {
        match self {
            Self::LowFee | Self::WalletScan => config.base_fee_piconero,
            Self::Balanced | Self::OperatorRepair => {
                (config.base_fee_piconero + config.fast_fee_piconero) / 2
            }
            Self::Fast | Self::Emergency => config.fast_fee_piconero,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Drafted,
    Admitted,
    Cached,
    Attested,
    Rebated,
    Invalidated,
    Expired,
    Quarantined,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drafted => "drafted",
            Self::Admitted => "admitted",
            Self::Cached => "cached",
            Self::Attested => "attested",
            Self::Rebated => "rebated",
            Self::Invalidated => "invalidated",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Drafted | Self::Admitted | Self::Cached | Self::Attested | Self::Rebated
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardStatus {
    Warm,
    Hot,
    Sealed,
    Rebuilding,
    Degraded,
    Retired,
}

impl ShardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Warm => "warm",
            Self::Hot => "hot",
            Self::Sealed => "sealed",
            Self::Rebuilding => "rebuilding",
            Self::Degraded => "degraded",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Pending,
    Accepted,
    Superseded,
    Challenged,
    Revoked,
    Expired,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Challenged => "challenged",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HintScope {
    ViewTagBucket,
    OutputEpoch,
    ShardBloom,
    WalletSubaddress,
    DecoyRefresh,
}

impl HintScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ViewTagBucket => "view_tag_bucket",
            Self::OutputEpoch => "output_epoch",
            Self::ShardBloom => "shard_bloom",
            Self::WalletSubaddress => "wallet_subaddress",
            Self::DecoyRefresh => "decoy_refresh",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvalidationReason {
    Reorg,
    StaleDecoy,
    DuplicateMember,
    BadPqAttestation,
    RedactionBudgetExceeded,
    OperatorChallenge,
    ManualRetire,
}

impl InvalidationReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reorg => "reorg",
            Self::StaleDecoy => "stale_decoy",
            Self::DuplicateMember => "duplicate_member",
            Self::BadPqAttestation => "bad_pq_attestation",
            Self::RedactionBudgetExceeded => "redaction_budget_exceeded",
            Self::OperatorChallenge => "operator_challenge",
            Self::ManualRetire => "manual_retire",
        }
    }

    pub fn severity_weight(self) -> u64 {
        match self {
            Self::BadPqAttestation => 1_000,
            Self::DuplicateMember => 920,
            Self::Reorg => 820,
            Self::OperatorChallenge => 760,
            Self::RedactionBudgetExceeded => 700,
            Self::StaleDecoy => 640,
            Self::ManualRetire => 420,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateReason {
    CacheHit,
    FreshDecoys,
    PqAttested,
    LowFeeLane,
    OperatorRepair,
}

impl RebateReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CacheHit => "cache_hit",
            Self::FreshDecoys => "fresh_decoys",
            Self::PqAttested => "pq_attested",
            Self::LowFeeLane => "low_fee_lane",
            Self::OperatorRepair => "operator_repair",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub cache_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub membership_suite: String,
    pub pq_attestation_suite: String,
    pub wallet_scan_hint_suite: String,
    pub min_pq_security_bits: u16,
    pub min_ring_size: u32,
    pub target_ring_size: u32,
    pub min_decoy_freshness_blocks: u64,
    pub strict_decoy_freshness_blocks: u64,
    pub cache_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub hint_ttl_blocks: u64,
    pub invalidation_ttl_blocks: u64,
    pub redaction_budget_units: u64,
    pub max_batch_members: usize,
    pub max_batches_per_shard: usize,
    pub base_fee_piconero: u64,
    pub fast_fee_piconero: u64,
    pub cache_hit_rebate_bps: u64,
    pub fresh_decoy_rebate_bps: u64,
    pub pq_attested_rebate_bps: u64,
    pub max_public_hint_buckets: u16,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version:
                MONERO_L2_PQ_PRIVATE_SERAPHIS_MEMBERSHIP_PROOF_CACHE_RUNTIME_SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            cache_id: DEVNET_CACHE_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            membership_suite: SERAPHIS_MEMBERSHIP_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            wallet_scan_hint_suite: WALLET_SCAN_HINT_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_ring_size: DEFAULT_MIN_RING_SIZE,
            target_ring_size: DEFAULT_TARGET_RING_SIZE,
            min_decoy_freshness_blocks: DEFAULT_MIN_DECOY_FRESHNESS_BLOCKS,
            strict_decoy_freshness_blocks: DEFAULT_STRICT_DECOY_FRESHNESS_BLOCKS,
            cache_ttl_blocks: DEFAULT_CACHE_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            hint_ttl_blocks: DEFAULT_HINT_TTL_BLOCKS,
            invalidation_ttl_blocks: DEFAULT_INVALIDATION_TTL_BLOCKS,
            redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
            max_batch_members: DEFAULT_MAX_BATCH_MEMBERS,
            max_batches_per_shard: DEFAULT_MAX_BATCHES_PER_SHARD,
            base_fee_piconero: DEFAULT_BASE_FEE_PICONERO,
            fast_fee_piconero: DEFAULT_FAST_FEE_PICONERO,
            cache_hit_rebate_bps: DEFAULT_CACHE_HIT_REBATE_BPS,
            fresh_decoy_rebate_bps: DEFAULT_FRESH_DECOY_REBATE_BPS,
            pq_attested_rebate_bps: DEFAULT_PQ_ATTESTED_REBATE_BPS,
            max_public_hint_buckets: DEFAULT_MAX_PUBLIC_HINT_BUCKETS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch",
        )?;
        require(self.schema_version == 1, "schema version mismatch")?;
        require(!self.cache_id.is_empty(), "cache id is required")?;
        require(
            self.min_pq_security_bits >= 192,
            "pq security bits below floor",
        )?;
        require(
            self.min_ring_size >= 16,
            "ring size below Seraphis privacy floor",
        )?;
        require(
            self.target_ring_size >= self.min_ring_size,
            "target ring size below minimum",
        )?;
        require(
            self.strict_decoy_freshness_blocks >= self.min_decoy_freshness_blocks,
            "strict decoy freshness below minimum",
        )?;
        require(self.cache_ttl_blocks > 0, "cache ttl is required")?;
        require(
            self.attestation_ttl_blocks > 0,
            "attestation ttl is required",
        )?;
        require(self.hint_ttl_blocks > 0, "hint ttl is required")?;
        require(
            self.redaction_budget_units > 0,
            "redaction budget is required",
        )?;
        require(self.max_batch_members > 0, "max batch members is required")?;
        require(
            self.max_batches_per_shard > 0,
            "max batches per shard is required",
        )?;
        require(
            self.cache_hit_rebate_bps <= MAX_BPS,
            "cache rebate exceeds bps",
        )?;
        require(
            self.fresh_decoy_rebate_bps <= MAX_BPS,
            "fresh decoy rebate exceeds bps",
        )?;
        require(
            self.pq_attested_rebate_bps <= MAX_BPS,
            "pq attested rebate exceeds bps",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "cache_id": self.cache_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "membership_suite": self.membership_suite,
            "pq_attestation_suite": self.pq_attestation_suite,
            "wallet_scan_hint_suite": self.wallet_scan_hint_suite,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_ring_size": self.min_ring_size,
            "target_ring_size": self.target_ring_size,
            "min_decoy_freshness_blocks": self.min_decoy_freshness_blocks,
            "strict_decoy_freshness_blocks": self.strict_decoy_freshness_blocks,
            "cache_ttl_blocks": self.cache_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "hint_ttl_blocks": self.hint_ttl_blocks,
            "invalidation_ttl_blocks": self.invalidation_ttl_blocks,
            "redaction_budget_units": self.redaction_budget_units,
            "max_batch_members": self.max_batch_members,
            "max_batches_per_shard": self.max_batches_per_shard,
            "base_fee_piconero": self.base_fee_piconero,
            "fast_fee_piconero": self.fast_fee_piconero,
            "cache_hit_rebate_bps": self.cache_hit_rebate_bps,
            "fresh_decoy_rebate_bps": self.fresh_decoy_rebate_bps,
            "pq_attested_rebate_bps": self.pq_attested_rebate_bps,
            "max_public_hint_buckets": self.max_public_hint_buckets,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub batches_total: u64,
    pub batches_live: u64,
    pub batches_invalidated: u64,
    pub shards_total: u64,
    pub hot_shards: u64,
    pub ring_members_total: u64,
    pub ring_commitments_total: u64,
    pub attestations_total: u64,
    pub attestations_accepted: u64,
    pub wallet_hints_total: u64,
    pub invalidations_total: u64,
    pub rebates_total: u64,
    pub rebate_piconero_total: u64,
    pub redaction_units_reserved: u64,
    pub redaction_units_spent: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub lowest_decoy_freshness_blocks: u64,
}

impl Counters {
    pub fn observe_batch(&mut self, batch: &SeraphisMembershipProofBatch) {
        self.batches_total = self.batches_total.saturating_add(1);
        if batch.status.live() {
            self.batches_live = self.batches_live.saturating_add(1);
        }
        if matches!(
            batch.status,
            BatchStatus::Invalidated | BatchStatus::Quarantined
        ) {
            self.batches_invalidated = self.batches_invalidated.saturating_add(1);
        }
        self.ring_members_total = self
            .ring_members_total
            .saturating_add(batch.member_count as u64);
        self.redaction_units_reserved = self
            .redaction_units_reserved
            .saturating_add(batch.redaction_budget_reserved);
        self.lowest_decoy_freshness_blocks = if self.lowest_decoy_freshness_blocks == 0 {
            batch.decoy_freshness_floor_blocks
        } else {
            self.lowest_decoy_freshness_blocks
                .min(batch.decoy_freshness_floor_blocks)
        };
    }

    pub fn observe_shard(&mut self, shard: &CacheShard) {
        self.shards_total = self.shards_total.saturating_add(1);
        if shard.status == ShardStatus::Hot {
            self.hot_shards = self.hot_shards.saturating_add(1);
        }
        self.cache_hits = self.cache_hits.saturating_add(shard.cache_hits);
        self.cache_misses = self.cache_misses.saturating_add(shard.cache_misses);
    }

    pub fn observe_attestation(&mut self, attestation: &PqCacheAttestation) {
        self.attestations_total = self.attestations_total.saturating_add(1);
        if attestation.status == AttestationStatus::Accepted {
            self.attestations_accepted = self.attestations_accepted.saturating_add(1);
        }
    }

    pub fn observe_rebate(&mut self, rebate: &FeeRebate) {
        self.rebates_total = self.rebates_total.saturating_add(1);
        self.rebate_piconero_total = self
            .rebate_piconero_total
            .saturating_add(rebate.amount_piconero);
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batches_total": self.batches_total,
            "batches_live": self.batches_live,
            "batches_invalidated": self.batches_invalidated,
            "shards_total": self.shards_total,
            "hot_shards": self.hot_shards,
            "ring_members_total": self.ring_members_total,
            "ring_commitments_total": self.ring_commitments_total,
            "attestations_total": self.attestations_total,
            "attestations_accepted": self.attestations_accepted,
            "wallet_hints_total": self.wallet_hints_total,
            "invalidations_total": self.invalidations_total,
            "rebates_total": self.rebates_total,
            "rebate_piconero_total": self.rebate_piconero_total,
            "redaction_units_reserved": self.redaction_units_reserved,
            "redaction_units_spent": self.redaction_units_spent,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "lowest_decoy_freshness_blocks": self.lowest_decoy_freshness_blocks,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub state_root: String,
    pub config_root: String,
    pub batch_root: String,
    pub shard_root: String,
    pub ring_commitment_root: String,
    pub member_commitment_root: String,
    pub attestation_root: String,
    pub wallet_hint_root: String,
    pub invalidation_root: String,
    pub fee_rebate_root: String,
    pub operator_summary_root: String,
    pub nullifier_fence_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "state_root": self.state_root,
            "config_root": self.config_root,
            "batch_root": self.batch_root,
            "shard_root": self.shard_root,
            "ring_commitment_root": self.ring_commitment_root,
            "member_commitment_root": self.member_commitment_root,
            "attestation_root": self.attestation_root,
            "wallet_hint_root": self.wallet_hint_root,
            "invalidation_root": self.invalidation_root,
            "fee_rebate_root": self.fee_rebate_root,
            "operator_summary_root": self.operator_summary_root,
            "nullifier_fence_root": self.nullifier_fence_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RingMemberCommitment {
    pub member_id: String,
    pub output_commitment: String,
    pub amount_commitment: String,
    pub address_tag_commitment: String,
    pub key_image_domain: String,
    pub output_height: u64,
    pub unlock_height: u64,
    pub decoy_age_blocks: u64,
    pub freshness_score: u16,
    pub shard_id: String,
    pub redaction_tag: String,
}

impl RingMemberCommitment {
    pub fn new(
        seed: &str,
        shard_id: &str,
        output_height: u64,
        current_height: u64,
        ordinal: u64,
    ) -> Self {
        let member_id = member_id(seed, shard_id, ordinal);
        let decoy_age_blocks = current_height.saturating_sub(output_height);
        Self {
            output_commitment: deterministic_root("MEMBER-OUTPUT", &member_id),
            amount_commitment: deterministic_root("MEMBER-AMOUNT", &member_id),
            address_tag_commitment: deterministic_root("MEMBER-ADDRESS-TAG", &member_id),
            key_image_domain: deterministic_root("MEMBER-KEY-IMAGE-DOMAIN", &member_id),
            unlock_height: output_height.saturating_add(10),
            freshness_score: freshness_score(decoy_age_blocks),
            redaction_tag: deterministic_root("MEMBER-REDACTION-TAG", &member_id),
            member_id,
            output_height,
            decoy_age_blocks,
            shard_id: shard_id.to_string(),
        }
    }

    pub fn is_fresh_enough(&self, config: &Config) -> bool {
        self.decoy_age_blocks >= config.min_decoy_freshness_blocks
    }

    pub fn public_record(&self) -> Value {
        json!({
            "member_id": self.member_id,
            "output_commitment": self.output_commitment,
            "amount_commitment": self.amount_commitment,
            "address_tag_commitment": self.address_tag_commitment,
            "key_image_domain": self.key_image_domain,
            "output_height": self.output_height,
            "unlock_height": self.unlock_height,
            "decoy_age_blocks": self.decoy_age_blocks,
            "freshness_score": self.freshness_score,
            "shard_id": self.shard_id,
            "redaction_tag": self.redaction_tag,
        })
    }

    pub fn commitment_root(&self) -> String {
        merkle_root("SERAPHIS-MEMBER-COMMITMENT", &[self.public_record()])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SeraphisRingCommitment {
    pub ring_id: String,
    pub batch_id: String,
    pub ring_index: u32,
    pub member_ids: Vec<String>,
    pub member_commitment_root: String,
    pub pseudo_output_commitment: String,
    pub linking_tag_commitment: String,
    pub membership_proof_commitment: String,
    pub decoy_freshness_floor_blocks: u64,
    pub privacy_set_size: u32,
}

impl SeraphisRingCommitment {
    pub fn from_members(batch_id: &str, ring_index: u32, members: &[RingMemberCommitment]) -> Self {
        let member_ids = members
            .iter()
            .map(|member| member.member_id.clone())
            .collect::<Vec<_>>();
        let member_records = members
            .iter()
            .map(RingMemberCommitment::public_record)
            .collect::<Vec<_>>();
        let member_commitment_root = merkle_root("SERAPHIS-RING-MEMBER-ROOT", &member_records);
        let ring_id = ring_id(batch_id, ring_index, &member_commitment_root);
        let decoy_freshness_floor_blocks = members
            .iter()
            .map(|member| member.decoy_age_blocks)
            .min()
            .unwrap_or_default();
        Self {
            pseudo_output_commitment: deterministic_root("RING-PSEUDO-OUTPUT", &ring_id),
            linking_tag_commitment: deterministic_root("RING-LINKING-TAG", &ring_id),
            membership_proof_commitment: deterministic_root("RING-MEMBERSHIP-PROOF", &ring_id),
            privacy_set_size: members.len() as u32,
            ring_id,
            batch_id: batch_id.to_string(),
            ring_index,
            member_ids,
            member_commitment_root,
            decoy_freshness_floor_blocks,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require(!self.ring_id.is_empty(), "ring id is required")?;
        require(!self.batch_id.is_empty(), "batch id is required")?;
        require(
            self.privacy_set_size >= config.min_ring_size,
            "ring privacy set below minimum",
        )?;
        require(
            self.member_ids.len() == self.privacy_set_size as usize,
            "ring member count mismatch",
        )?;
        require(
            self.decoy_freshness_floor_blocks >= config.min_decoy_freshness_blocks,
            "ring decoy freshness below floor",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ring_id": self.ring_id,
            "batch_id": self.batch_id,
            "ring_index": self.ring_index,
            "member_count": self.member_ids.len(),
            "member_commitment_root": self.member_commitment_root,
            "pseudo_output_commitment": self.pseudo_output_commitment,
            "linking_tag_commitment": self.linking_tag_commitment,
            "membership_proof_commitment": self.membership_proof_commitment,
            "decoy_freshness_floor_blocks": self.decoy_freshness_floor_blocks,
            "privacy_set_size": self.privacy_set_size,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SeraphisMembershipProofBatch {
    pub batch_id: String,
    pub shard_id: String,
    pub lane: CacheLane,
    pub status: BatchStatus,
    pub monero_height: u64,
    pub l2_height: u64,
    pub expires_at_l2_height: u64,
    pub member_count: usize,
    pub ring_count: usize,
    pub ring_root: String,
    pub member_root: String,
    pub nullifier_fence_root: String,
    pub wallet_hint_root: String,
    pub pq_attestation_root: String,
    pub proof_cache_key: String,
    pub decoy_freshness_floor_blocks: u64,
    pub redaction_budget_reserved: u64,
    pub redaction_budget_spent: u64,
    pub fee_piconero: u64,
    pub cache_hit: bool,
}

impl SeraphisMembershipProofBatch {
    pub fn new(
        shard_id: &str,
        lane: CacheLane,
        monero_height: u64,
        l2_height: u64,
        rings: &[SeraphisRingCommitment],
        config: &Config,
    ) -> Self {
        let ring_records = rings
            .iter()
            .map(SeraphisRingCommitment::public_record)
            .collect::<Vec<_>>();
        let ring_root = merkle_root("SERAPHIS-BATCH-RING-ROOT", &ring_records);
        let batch_id = batch_id(shard_id, monero_height, l2_height, &ring_root);
        let member_ids = rings
            .iter()
            .flat_map(|ring| ring.member_ids.iter().cloned())
            .collect::<Vec<_>>();
        let member_root = id_root("SERAPHIS-BATCH-MEMBER-ID-ROOT", &member_ids);
        let nullifier_fence_root = deterministic_root("BATCH-NULLIFIER-FENCE", &batch_id);
        let wallet_hint_root = deterministic_root("BATCH-WALLET-HINT", &batch_id);
        let pq_attestation_root = deterministic_root("BATCH-PQ-ATTESTATION", &batch_id);
        let member_count = member_ids.len();
        let decoy_freshness_floor_blocks = rings
            .iter()
            .map(|ring| ring.decoy_freshness_floor_blocks)
            .min()
            .unwrap_or_default();
        Self {
            proof_cache_key: proof_cache_key(shard_id, &batch_id, &ring_root),
            status: BatchStatus::Cached,
            expires_at_l2_height: l2_height.saturating_add(config.cache_ttl_blocks),
            redaction_budget_reserved: redaction_budget_for_members(member_count),
            fee_piconero: lane.fee_piconero(config),
            cache_hit: false,
            batch_id,
            shard_id: shard_id.to_string(),
            lane,
            monero_height,
            l2_height,
            member_count,
            ring_count: rings.len(),
            ring_root,
            member_root,
            nullifier_fence_root,
            wallet_hint_root,
            pq_attestation_root,
            decoy_freshness_floor_blocks,
            redaction_budget_spent: 0,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require(!self.batch_id.is_empty(), "batch id is required")?;
        require(!self.shard_id.is_empty(), "shard id is required")?;
        require(self.member_count > 0, "batch has no members")?;
        require(
            self.member_count <= config.max_batch_members,
            "batch member count exceeds limit",
        )?;
        require(self.ring_count > 0, "batch has no rings")?;
        require(
            self.decoy_freshness_floor_blocks >= config.min_decoy_freshness_blocks,
            "batch decoy freshness below floor",
        )?;
        require(
            self.redaction_budget_reserved <= config.redaction_budget_units,
            "batch redaction budget exceeds global floor",
        )?;
        require(
            self.redaction_budget_spent <= self.redaction_budget_reserved,
            "batch redaction spend exceeds reserve",
        )
    }

    pub fn mark_cache_hit(&mut self, config: &Config) {
        self.cache_hit = true;
        self.status = BatchStatus::Rebated;
        self.fee_piconero = self
            .fee_piconero
            .saturating_sub(bps(self.fee_piconero, config.cache_hit_rebate_bps));
    }

    pub fn expired_at(&self, l2_height: u64) -> bool {
        l2_height >= self.expires_at_l2_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "shard_id": self.shard_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "monero_height": self.monero_height,
            "l2_height": self.l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "member_count": self.member_count,
            "ring_count": self.ring_count,
            "ring_root": self.ring_root,
            "member_root": self.member_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "wallet_hint_root": self.wallet_hint_root,
            "pq_attestation_root": self.pq_attestation_root,
            "proof_cache_key": self.proof_cache_key,
            "decoy_freshness_floor_blocks": self.decoy_freshness_floor_blocks,
            "redaction_budget_reserved": self.redaction_budget_reserved,
            "redaction_budget_spent": self.redaction_budget_spent,
            "fee_piconero": self.fee_piconero,
            "cache_hit": self.cache_hit,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CacheShard {
    pub shard_id: String,
    pub operator_id: String,
    pub status: ShardStatus,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
    pub l2_anchor_height: u64,
    pub capacity_batches: usize,
    pub batch_ids: Vec<String>,
    pub shard_commitment_root: String,
    pub bloom_filter_commitment: String,
    pub decoy_freshness_floor_blocks: u64,
    pub pq_security_bits: u16,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub rebuild_epoch: u64,
}

impl CacheShard {
    pub fn new(
        operator_id: &str,
        monero_start_height: u64,
        monero_end_height: u64,
        l2_anchor_height: u64,
        config: &Config,
        ordinal: u64,
    ) -> Self {
        let shard_id = shard_id(operator_id, monero_start_height, monero_end_height, ordinal);
        Self {
            shard_commitment_root: deterministic_root("SHARD-COMMITMENT", &shard_id),
            bloom_filter_commitment: deterministic_root("SHARD-BLOOM", &shard_id),
            status: ShardStatus::Warm,
            capacity_batches: config.max_batches_per_shard,
            decoy_freshness_floor_blocks: config.min_decoy_freshness_blocks,
            pq_security_bits: config.min_pq_security_bits,
            shard_id,
            operator_id: operator_id.to_string(),
            monero_start_height,
            monero_end_height,
            l2_anchor_height,
            batch_ids: Vec::new(),
            cache_hits: 0,
            cache_misses: 0,
            rebuild_epoch: 0,
        }
    }

    pub fn admit_batch(&mut self, batch: &SeraphisMembershipProofBatch) -> Result<()> {
        require(
            self.batch_ids.len() < self.capacity_batches,
            "cache shard is full",
        )?;
        require(batch.shard_id == self.shard_id, "batch shard mismatch")?;
        if !self.batch_ids.contains(&batch.batch_id) {
            self.batch_ids.push(batch.batch_id.clone());
        }
        self.status = if self.batch_ids.len() * 2 >= self.capacity_batches {
            ShardStatus::Hot
        } else {
            ShardStatus::Warm
        };
        self.decoy_freshness_floor_blocks = self
            .decoy_freshness_floor_blocks
            .min(batch.decoy_freshness_floor_blocks);
        self.shard_commitment_root =
            id_root("SERAPHIS-SHARD-BATCH-ID-ROOT", &self.batch_ids.clone());
        Ok(())
    }

    pub fn record_lookup(&mut self, hit: bool) {
        if hit {
            self.cache_hits = self.cache_hits.saturating_add(1);
        } else {
            self.cache_misses = self.cache_misses.saturating_add(1);
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require(!self.shard_id.is_empty(), "shard id is required")?;
        require(!self.operator_id.is_empty(), "operator id is required")?;
        require(
            self.monero_end_height >= self.monero_start_height,
            "shard height range is inverted",
        )?;
        require(
            self.batch_ids.len() <= self.capacity_batches,
            "shard over capacity",
        )?;
        require(
            self.pq_security_bits >= config.min_pq_security_bits,
            "shard pq security below minimum",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "shard_id": self.shard_id,
            "operator_id": self.operator_id,
            "status": self.status.as_str(),
            "monero_start_height": self.monero_start_height,
            "monero_end_height": self.monero_end_height,
            "l2_anchor_height": self.l2_anchor_height,
            "capacity_batches": self.capacity_batches,
            "batch_count": self.batch_ids.len(),
            "shard_commitment_root": self.shard_commitment_root,
            "bloom_filter_commitment": self.bloom_filter_commitment,
            "decoy_freshness_floor_blocks": self.decoy_freshness_floor_blocks,
            "pq_security_bits": self.pq_security_bits,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "rebuild_epoch": self.rebuild_epoch,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCacheAttestation {
    pub attestation_id: String,
    pub batch_id: String,
    pub shard_id: String,
    pub operator_id: String,
    pub status: AttestationStatus,
    pub suite: String,
    pub pq_security_bits: u16,
    pub attested_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub public_key_commitment: String,
    pub signature_commitment: String,
    pub transcript_root: String,
    pub cache_key_root: String,
}

impl PqCacheAttestation {
    pub fn new(
        batch: &SeraphisMembershipProofBatch,
        operator_id: &str,
        l2_height: u64,
        config: &Config,
    ) -> Self {
        let attestation_id = attestation_id(&batch.batch_id, operator_id, l2_height);
        Self {
            public_key_commitment: deterministic_root("PQ-ATTESTATION-PUBKEY", &attestation_id),
            signature_commitment: deterministic_root("PQ-ATTESTATION-SIGNATURE", &attestation_id),
            transcript_root: deterministic_root("PQ-ATTESTATION-TRANSCRIPT", &attestation_id),
            cache_key_root: deterministic_root("PQ-ATTESTATION-CACHE-KEY", &batch.proof_cache_key),
            attestation_id,
            batch_id: batch.batch_id.clone(),
            shard_id: batch.shard_id.clone(),
            operator_id: operator_id.to_string(),
            status: AttestationStatus::Accepted,
            suite: config.pq_attestation_suite.clone(),
            pq_security_bits: config.min_pq_security_bits,
            attested_l2_height: l2_height,
            expires_at_l2_height: l2_height.saturating_add(config.attestation_ttl_blocks),
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require(
            !self.attestation_id.is_empty(),
            "attestation id is required",
        )?;
        require(
            self.suite == config.pq_attestation_suite,
            "attestation suite mismatch",
        )?;
        require(
            self.pq_security_bits >= config.min_pq_security_bits,
            "attestation pq security below minimum",
        )?;
        require(
            self.expires_at_l2_height > self.attested_l2_height,
            "attestation expiry is not after attestation height",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "batch_id": self.batch_id,
            "shard_id": self.shard_id,
            "operator_id": self.operator_id,
            "status": self.status.as_str(),
            "suite": self.suite,
            "pq_security_bits": self.pq_security_bits,
            "attested_l2_height": self.attested_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "public_key_commitment": self.public_key_commitment,
            "signature_commitment": self.signature_commitment,
            "transcript_root": self.transcript_root,
            "cache_key_root": self.cache_key_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletScanHint {
    pub hint_id: String,
    pub batch_id: String,
    pub shard_id: String,
    pub scope: HintScope,
    pub sealed_hint_commitment: String,
    pub hint_bucket: u16,
    pub view_tag_prefix_bits: u8,
    pub min_output_height: u64,
    pub max_output_height: u64,
    pub expires_at_l2_height: u64,
    pub disclosure_root: String,
}

impl WalletScanHint {
    pub fn new(
        batch: &SeraphisMembershipProofBatch,
        scope: HintScope,
        bucket: u16,
        view_tag_prefix_bits: u8,
        config: &Config,
    ) -> Self {
        let public_bucket = bucket % config.max_public_hint_buckets.max(1);
        let hint_id = wallet_hint_id(&batch.batch_id, scope, public_bucket);
        Self {
            sealed_hint_commitment: deterministic_root("WALLET-HINT-SEALED", &hint_id),
            disclosure_root: deterministic_root("WALLET-HINT-DISCLOSURE", &hint_id),
            hint_id,
            batch_id: batch.batch_id.clone(),
            shard_id: batch.shard_id.clone(),
            scope,
            hint_bucket: public_bucket,
            view_tag_prefix_bits,
            min_output_height: batch
                .monero_height
                .saturating_sub(batch.decoy_freshness_floor_blocks),
            max_output_height: batch.monero_height,
            expires_at_l2_height: batch.l2_height.saturating_add(config.hint_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "batch_id": self.batch_id,
            "shard_id": self.shard_id,
            "scope": self.scope.as_str(),
            "sealed_hint_commitment": self.sealed_hint_commitment,
            "hint_bucket": self.hint_bucket,
            "view_tag_prefix_bits": self.view_tag_prefix_bits,
            "min_output_height": self.min_output_height,
            "max_output_height": self.max_output_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "disclosure_root": self.disclosure_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecoyFreshnessFloor {
    pub floor_id: String,
    pub shard_id: String,
    pub min_decoy_age_blocks: u64,
    pub strict_decoy_age_blocks: u64,
    pub observed_floor_blocks: u64,
    pub ring_count: u64,
    pub stale_ring_count: u64,
}

impl DecoyFreshnessFloor {
    pub fn from_batches(
        shard_id: &str,
        batches: &[SeraphisMembershipProofBatch],
        config: &Config,
    ) -> Self {
        let observed_floor_blocks = batches
            .iter()
            .map(|batch| batch.decoy_freshness_floor_blocks)
            .min()
            .unwrap_or(config.min_decoy_freshness_blocks);
        let ring_count = batches
            .iter()
            .map(|batch| batch.ring_count as u64)
            .sum::<u64>();
        let stale_ring_count = batches
            .iter()
            .filter(|batch| batch.decoy_freshness_floor_blocks < config.min_decoy_freshness_blocks)
            .map(|batch| batch.ring_count as u64)
            .sum::<u64>();
        let floor_id = domain_hash(
            "SERAPHIS-DECOY-FRESHNESS-FLOOR-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(shard_id),
                HashPart::Int(observed_floor_blocks as i128),
            ],
            32,
        );
        Self {
            floor_id,
            shard_id: shard_id.to_string(),
            min_decoy_age_blocks: config.min_decoy_freshness_blocks,
            strict_decoy_age_blocks: config.strict_decoy_freshness_blocks,
            observed_floor_blocks,
            ring_count,
            stale_ring_count,
        }
    }

    pub fn strict_pass(&self) -> bool {
        self.observed_floor_blocks >= self.strict_decoy_age_blocks && self.stale_ring_count == 0
    }

    pub fn public_record(&self) -> Value {
        json!({
            "floor_id": self.floor_id,
            "shard_id": self.shard_id,
            "min_decoy_age_blocks": self.min_decoy_age_blocks,
            "strict_decoy_age_blocks": self.strict_decoy_age_blocks,
            "observed_floor_blocks": self.observed_floor_blocks,
            "ring_count": self.ring_count,
            "stale_ring_count": self.stale_ring_count,
            "strict_pass": self.strict_pass(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvalidationRule {
    pub rule_id: String,
    pub reason: InvalidationReason,
    pub shard_id: String,
    pub batch_id: Option<String>,
    pub applies_from_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub severity_weight: u64,
    pub evidence_root: String,
    pub operator_id: String,
}

impl InvalidationRule {
    pub fn new(
        reason: InvalidationReason,
        shard_id: &str,
        batch_id: Option<String>,
        operator_id: &str,
        l2_height: u64,
        config: &Config,
    ) -> Self {
        let label = batch_id.as_deref().unwrap_or(shard_id);
        let rule_id = invalidation_rule_id(reason, shard_id, label, l2_height);
        Self {
            evidence_root: deterministic_root("INVALIDATION-EVIDENCE", &rule_id),
            severity_weight: reason.severity_weight(),
            rule_id,
            reason,
            shard_id: shard_id.to_string(),
            batch_id,
            applies_from_l2_height: l2_height,
            expires_at_l2_height: l2_height.saturating_add(config.invalidation_ttl_blocks),
            operator_id: operator_id.to_string(),
        }
    }

    pub fn invalidates_batch(&self, batch: &SeraphisMembershipProofBatch) -> bool {
        if self.shard_id != batch.shard_id {
            return false;
        }
        self.batch_id
            .as_ref()
            .map(|id| id == &batch.batch_id)
            .unwrap_or(true)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rule_id": self.rule_id,
            "reason": self.reason.as_str(),
            "shard_id": self.shard_id,
            "batch_id": self.batch_id,
            "applies_from_l2_height": self.applies_from_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "severity_weight": self.severity_weight,
            "evidence_root": self.evidence_root,
            "operator_id": self.operator_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub batch_id: String,
    pub shard_id: String,
    pub recipient_commitment: String,
    pub reason: RebateReason,
    pub amount_piconero: u64,
    pub fee_asset_id: String,
    pub applied_l2_height: u64,
    pub claim_nullifier_root: String,
}

impl FeeRebate {
    pub fn new(
        batch: &SeraphisMembershipProofBatch,
        reason: RebateReason,
        bps_value: u64,
        l2_height: u64,
        config: &Config,
    ) -> Self {
        let amount_piconero = bps(batch.fee_piconero, bps_value.min(MAX_BPS));
        let rebate_id = rebate_id(&batch.batch_id, reason, amount_piconero);
        Self {
            recipient_commitment: deterministic_root("FEE-REBATE-RECIPIENT", &rebate_id),
            claim_nullifier_root: deterministic_root("FEE-REBATE-CLAIM-NULLIFIER", &rebate_id),
            rebate_id,
            batch_id: batch.batch_id.clone(),
            shard_id: batch.shard_id.clone(),
            reason,
            amount_piconero,
            fee_asset_id: config.fee_asset_id.clone(),
            applied_l2_height: l2_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "batch_id": self.batch_id,
            "shard_id": self.shard_id,
            "recipient_commitment": self.recipient_commitment,
            "reason": self.reason.as_str(),
            "amount_piconero": self.amount_piconero,
            "fee_asset_id": self.fee_asset_id,
            "applied_l2_height": self.applied_l2_height,
            "claim_nullifier_root": self.claim_nullifier_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub owner_id: String,
    pub shard_id: String,
    pub total_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub commitment_root: String,
}

impl RedactionBudget {
    pub fn new(owner_id: &str, shard_id: &str, total_units: u64) -> Self {
        let budget_id = redaction_budget_id(owner_id, shard_id, total_units);
        Self {
            commitment_root: deterministic_root("REDACTION-BUDGET-COMMITMENT", &budget_id),
            budget_id,
            owner_id: owner_id.to_string(),
            shard_id: shard_id.to_string(),
            total_units,
            reserved_units: 0,
            spent_units: 0,
        }
    }

    pub fn reserve(&mut self, units: u64) -> Result<()> {
        require(
            self.reserved_units.saturating_add(units) <= self.total_units,
            "redaction reserve exceeds budget",
        )?;
        self.reserved_units = self.reserved_units.saturating_add(units);
        Ok(())
    }

    pub fn spend(&mut self, units: u64) -> Result<()> {
        require(
            self.spent_units.saturating_add(units) <= self.reserved_units,
            "redaction spend exceeds reserved units",
        )?;
        self.spent_units = self.spent_units.saturating_add(units);
        Ok(())
    }

    pub fn remaining_units(&self) -> u64 {
        self.total_units.saturating_sub(self.reserved_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "owner_id": self.owner_id,
            "shard_id": self.shard_id,
            "total_units": self.total_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "remaining_units": self.remaining_units(),
            "commitment_root": self.commitment_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub operator_id: String,
    pub shard_ids: Vec<String>,
    pub accepted_attestations: u64,
    pub challenged_attestations: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub rebate_piconero_total: u64,
    pub lowest_decoy_freshness_blocks: u64,
    pub summary_root: String,
}

impl OperatorSummary {
    pub fn build(
        operator_id: &str,
        shards: &[CacheShard],
        attestations: &[PqCacheAttestation],
        rebates: &[FeeRebate],
    ) -> Self {
        let shard_ids = shards
            .iter()
            .filter(|shard| shard.operator_id == operator_id)
            .map(|shard| shard.shard_id.clone())
            .collect::<Vec<_>>();
        let accepted_attestations = attestations
            .iter()
            .filter(|attestation| {
                attestation.operator_id == operator_id
                    && attestation.status == AttestationStatus::Accepted
            })
            .count() as u64;
        let challenged_attestations = attestations
            .iter()
            .filter(|attestation| {
                attestation.operator_id == operator_id
                    && matches!(
                        attestation.status,
                        AttestationStatus::Challenged | AttestationStatus::Revoked
                    )
            })
            .count() as u64;
        let cache_hits = shards
            .iter()
            .filter(|shard| shard.operator_id == operator_id)
            .map(|shard| shard.cache_hits)
            .sum::<u64>();
        let cache_misses = shards
            .iter()
            .filter(|shard| shard.operator_id == operator_id)
            .map(|shard| shard.cache_misses)
            .sum::<u64>();
        let rebate_piconero_total = rebates
            .iter()
            .filter(|rebate| shard_ids.contains(&rebate.shard_id))
            .map(|rebate| rebate.amount_piconero)
            .sum::<u64>();
        let lowest_decoy_freshness_blocks = shards
            .iter()
            .filter(|shard| shard.operator_id == operator_id)
            .map(|shard| shard.decoy_freshness_floor_blocks)
            .min()
            .unwrap_or_default();
        let summary_root = operator_summary_root(
            operator_id,
            accepted_attestations,
            challenged_attestations,
            cache_hits,
            cache_misses,
        );
        Self {
            operator_id: operator_id.to_string(),
            shard_ids,
            accepted_attestations,
            challenged_attestations,
            cache_hits,
            cache_misses,
            rebate_piconero_total,
            lowest_decoy_freshness_blocks,
            summary_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "operator_id": self.operator_id,
            "shard_ids": self.shard_ids,
            "accepted_attestations": self.accepted_attestations,
            "challenged_attestations": self.challenged_attestations,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "rebate_piconero_total": self.rebate_piconero_total,
            "lowest_decoy_freshness_blocks": self.lowest_decoy_freshness_blocks,
            "summary_root": self.summary_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub l2_height: u64,
    pub monero_height: u64,
    pub cache_shards: BTreeMap<String, CacheShard>,
    pub batches: BTreeMap<String, SeraphisMembershipProofBatch>,
    pub ring_commitments: BTreeMap<String, SeraphisRingCommitment>,
    pub member_commitments: BTreeMap<String, RingMemberCommitment>,
    pub pq_attestations: BTreeMap<String, PqCacheAttestation>,
    pub wallet_scan_hints: BTreeMap<String, WalletScanHint>,
    pub decoy_freshness_floors: BTreeMap<String, DecoyFreshnessFloor>,
    pub invalidation_rules: BTreeMap<String, InvalidationRule>,
    pub fee_rebates: BTreeMap<String, FeeRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub spent_nullifier_fences: BTreeSet<String>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn new(config: Config, l2_height: u64, monero_height: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            l2_height,
            monero_height,
            cache_shards: BTreeMap::new(),
            batches: BTreeMap::new(),
            ring_commitments: BTreeMap::new(),
            member_commitments: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            wallet_scan_hints: BTreeMap::new(),
            decoy_freshness_floors: BTreeMap::new(),
            invalidation_rules: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            spent_nullifier_fences: BTreeSet::new(),
            counters: Counters::default(),
            roots: Roots::default(),
        };
        state.recompute()?;
        Ok(state)
    }

    pub fn devnet() -> Self {
        build_devnet().expect("devnet Seraphis membership proof cache fixture must build")
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        state_root(self)
    }

    pub fn admit_shard(&mut self, shard: CacheShard) -> Result<()> {
        require(
            self.cache_shards.len() < MAX_SHARDS,
            "too many cache shards",
        )?;
        shard.validate(&self.config)?;
        self.cache_shards.insert(shard.shard_id.clone(), shard);
        self.recompute()
    }

    pub fn admit_batch(
        &mut self,
        batch: SeraphisMembershipProofBatch,
        rings: Vec<SeraphisRingCommitment>,
        members: Vec<RingMemberCommitment>,
    ) -> Result<()> {
        require(self.batches.len() < MAX_BATCHES, "too many batches")?;
        batch.validate(&self.config)?;
        let shard = self
            .cache_shards
            .get_mut(&batch.shard_id)
            .ok_or_else(|| "batch references unknown shard".to_string())?;
        shard.admit_batch(&batch)?;
        for ring in rings {
            ring.validate(&self.config)?;
            self.ring_commitments.insert(ring.ring_id.clone(), ring);
        }
        for member in members {
            self.member_commitments
                .insert(member.member_id.clone(), member);
        }
        self.spent_nullifier_fences
            .insert(batch.nullifier_fence_root.clone());
        self.batches.insert(batch.batch_id.clone(), batch);
        self.recompute()
    }

    pub fn attest_batch(&mut self, attestation: PqCacheAttestation) -> Result<()> {
        require(
            self.pq_attestations.len() < MAX_ATTESTATIONS,
            "too many pq attestations",
        )?;
        attestation.validate(&self.config)?;
        require(
            self.batches.contains_key(&attestation.batch_id),
            "attestation references unknown batch",
        )?;
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.recompute()
    }

    pub fn add_wallet_hint(&mut self, hint: WalletScanHint) -> Result<()> {
        require(
            self.wallet_scan_hints.len() < MAX_WALLET_HINTS,
            "too many wallet scan hints",
        )?;
        require(
            self.batches.contains_key(&hint.batch_id),
            "wallet hint references unknown batch",
        )?;
        self.wallet_scan_hints.insert(hint.hint_id.clone(), hint);
        self.recompute()
    }

    pub fn apply_invalidation(&mut self, rule: InvalidationRule) -> Result<()> {
        require(
            self.invalidation_rules.len() < MAX_INVALIDATIONS,
            "too many invalidation rules",
        )?;
        for batch in self.batches.values_mut() {
            if rule.invalidates_batch(batch) {
                batch.status = BatchStatus::Invalidated;
            }
        }
        if let Some(shard) = self.cache_shards.get_mut(&rule.shard_id) {
            shard.status = match rule.reason {
                InvalidationReason::ManualRetire => ShardStatus::Retired,
                InvalidationReason::OperatorChallenge | InvalidationReason::BadPqAttestation => {
                    ShardStatus::Degraded
                }
                _ => ShardStatus::Rebuilding,
            };
        }
        self.invalidation_rules.insert(rule.rule_id.clone(), rule);
        self.recompute()
    }

    pub fn add_fee_rebate(&mut self, rebate: FeeRebate) -> Result<()> {
        require(
            self.fee_rebates.len() < MAX_FEE_REBATES,
            "too many fee rebates",
        )?;
        require(
            self.batches.contains_key(&rebate.batch_id),
            "fee rebate references unknown batch",
        )?;
        self.fee_rebates.insert(rebate.rebate_id.clone(), rebate);
        self.recompute()
    }

    pub fn reserve_redaction_budget(&mut self, budget_id: &str, units: u64) -> Result<()> {
        let budget = self
            .redaction_budgets
            .get_mut(budget_id)
            .ok_or_else(|| "unknown redaction budget".to_string())?;
        budget.reserve(units)?;
        self.recompute()
    }

    pub fn spend_redaction_budget(&mut self, budget_id: &str, units: u64) -> Result<()> {
        let budget = self
            .redaction_budgets
            .get_mut(budget_id)
            .ok_or_else(|| "unknown redaction budget".to_string())?;
        budget.spend(units)?;
        self.recompute()
    }

    pub fn rebuild_operator_summaries(&mut self) {
        let operators = self
            .cache_shards
            .values()
            .map(|shard| shard.operator_id.clone())
            .collect::<BTreeSet<_>>();
        let shards = self.cache_shards.values().cloned().collect::<Vec<_>>();
        let attestations = self.pq_attestations.values().cloned().collect::<Vec<_>>();
        let rebates = self.fee_rebates.values().cloned().collect::<Vec<_>>();
        self.operator_summaries.clear();
        for operator_id in operators {
            let summary = OperatorSummary::build(&operator_id, &shards, &attestations, &rebates);
            self.operator_summaries
                .insert(summary.operator_id.clone(), summary);
        }
    }

    pub fn rebuild_decoy_floors(&mut self) {
        self.decoy_freshness_floors.clear();
        for shard_id in self.cache_shards.keys() {
            let batches = self
                .batches
                .values()
                .filter(|batch| &batch.shard_id == shard_id)
                .cloned()
                .collect::<Vec<_>>();
            if !batches.is_empty() {
                let floor = DecoyFreshnessFloor::from_batches(shard_id, &batches, &self.config);
                self.decoy_freshness_floors
                    .insert(floor.floor_id.clone(), floor);
            }
        }
    }

    pub fn recompute(&mut self) -> Result<()> {
        self.config.validate()?;
        self.rebuild_decoy_floors();
        self.rebuild_operator_summaries();
        self.counters = self.derive_counters();
        self.roots = self.derive_roots();
        Ok(())
    }

    pub fn derive_counters(&self) -> Counters {
        let mut counters = Counters::default();
        for batch in self.batches.values() {
            counters.observe_batch(batch);
        }
        for shard in self.cache_shards.values() {
            counters.observe_shard(shard);
        }
        for attestation in self.pq_attestations.values() {
            counters.observe_attestation(attestation);
        }
        for rebate in self.fee_rebates.values() {
            counters.observe_rebate(rebate);
        }
        counters.ring_commitments_total = self.ring_commitments.len() as u64;
        counters.wallet_hints_total = self.wallet_scan_hints.len() as u64;
        counters.invalidations_total = self.invalidation_rules.len() as u64;
        counters.redaction_units_spent = self
            .redaction_budgets
            .values()
            .map(|budget| budget.spent_units)
            .sum();
        counters
    }

    pub fn derive_roots(&self) -> Roots {
        let config_root = merkle_root("SERAPHIS-CONFIG-ROOT", &[self.config.public_record()]);
        let batch_root = records_root(
            "SERAPHIS-BATCH-ROOT",
            self.batches
                .values()
                .map(SeraphisMembershipProofBatch::public_record)
                .collect(),
        );
        let shard_root = records_root(
            "SERAPHIS-SHARD-ROOT",
            self.cache_shards
                .values()
                .map(CacheShard::public_record)
                .collect(),
        );
        let ring_commitment_root = records_root(
            "SERAPHIS-RING-COMMITMENT-ROOT",
            self.ring_commitments
                .values()
                .map(SeraphisRingCommitment::public_record)
                .collect(),
        );
        let member_commitment_root = records_root(
            "SERAPHIS-MEMBER-COMMITMENT-ROOT",
            self.member_commitments
                .values()
                .map(RingMemberCommitment::public_record)
                .collect(),
        );
        let attestation_root = records_root(
            "SERAPHIS-PQ-ATTESTATION-ROOT",
            self.pq_attestations
                .values()
                .map(PqCacheAttestation::public_record)
                .collect(),
        );
        let wallet_hint_root = records_root(
            "SERAPHIS-WALLET-HINT-ROOT",
            self.wallet_scan_hints
                .values()
                .map(WalletScanHint::public_record)
                .collect(),
        );
        let invalidation_root = records_root(
            "SERAPHIS-INVALIDATION-ROOT",
            self.invalidation_rules
                .values()
                .map(InvalidationRule::public_record)
                .collect(),
        );
        let fee_rebate_root = records_root(
            "SERAPHIS-FEE-REBATE-ROOT",
            self.fee_rebates
                .values()
                .map(FeeRebate::public_record)
                .collect(),
        );
        let operator_summary_root = records_root(
            "SERAPHIS-OPERATOR-SUMMARY-ROOT",
            self.operator_summaries
                .values()
                .map(OperatorSummary::public_record)
                .collect(),
        );
        let nullifier_fence_root = id_root(
            "SERAPHIS-NULLIFIER-FENCE-ROOT",
            &self
                .spent_nullifier_fences
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
        );
        let state_root = merkle_root(
            "SERAPHIS-MEMBERSHIP-PROOF-CACHE-STATE-ROOT",
            &[
                json!({ "config_root": config_root }),
                json!({ "batch_root": batch_root }),
                json!({ "shard_root": shard_root }),
                json!({ "ring_commitment_root": ring_commitment_root }),
                json!({ "member_commitment_root": member_commitment_root }),
                json!({ "attestation_root": attestation_root }),
                json!({ "wallet_hint_root": wallet_hint_root }),
                json!({ "invalidation_root": invalidation_root }),
                json!({ "fee_rebate_root": fee_rebate_root }),
                json!({ "operator_summary_root": operator_summary_root }),
                json!({ "nullifier_fence_root": nullifier_fence_root }),
                json!({ "l2_height": self.l2_height, "monero_height": self.monero_height }),
            ],
        );
        Roots {
            state_root,
            config_root,
            batch_root,
            shard_root,
            ring_commitment_root,
            member_commitment_root,
            attestation_root,
            wallet_hint_root,
            invalidation_root,
            fee_rebate_root,
            operator_summary_root,
            nullifier_fence_root,
        }
    }
}

fn build_devnet() -> MoneroL2PqPrivateSeraphisMembershipProofCacheRuntimeResult<State> {
    let config = Config::devnet();
    let mut state = State::new(
        config.clone(),
        DEFAULT_DEVNET_HEIGHT + 64,
        DEFAULT_DEVNET_HEIGHT,
    )?;

    let mut shard_a = CacheShard::new(
        "operator-devnet-a",
        DEFAULT_DEVNET_HEIGHT - 8_192,
        DEFAULT_DEVNET_HEIGHT,
        DEFAULT_DEVNET_HEIGHT + 64,
        &config,
        0,
    );
    shard_a.status = ShardStatus::Hot;
    let shard_b = CacheShard::new(
        "operator-devnet-b",
        DEFAULT_DEVNET_HEIGHT - 16_384,
        DEFAULT_DEVNET_HEIGHT - 8_193,
        DEFAULT_DEVNET_HEIGHT + 64,
        &config,
        1,
    );
    let shard_a_id = shard_a.shard_id.clone();
    let shard_b_id = shard_b.shard_id.clone();
    state.admit_shard(shard_a)?;
    state.admit_shard(shard_b)?;

    let (batch_a, rings_a, members_a) = demo_batch(
        "devnet-a",
        &shard_a_id,
        CacheLane::LowFee,
        DEFAULT_DEVNET_HEIGHT,
        DEFAULT_DEVNET_HEIGHT + 64,
        2,
        config.min_ring_size,
        &config,
    );
    let batch_a_id = batch_a.batch_id.clone();
    state.admit_batch(batch_a, rings_a, members_a)?;

    let (mut batch_b, rings_b, members_b) = demo_batch(
        "devnet-b",
        &shard_b_id,
        CacheLane::Fast,
        DEFAULT_DEVNET_HEIGHT - 128,
        DEFAULT_DEVNET_HEIGHT + 66,
        2,
        config.min_ring_size,
        &config,
    );
    batch_b.mark_cache_hit(&config);
    let batch_b_id = batch_b.batch_id.clone();
    state.admit_batch(batch_b, rings_b, members_b)?;

    let attestation_a = PqCacheAttestation::new(
        state.batches.get(&batch_a_id).expect("batch exists"),
        "operator-devnet-a",
        DEFAULT_DEVNET_HEIGHT + 65,
        &config,
    );
    state.attest_batch(attestation_a)?;
    let attestation_b = PqCacheAttestation::new(
        state.batches.get(&batch_b_id).expect("batch exists"),
        "operator-devnet-b",
        DEFAULT_DEVNET_HEIGHT + 67,
        &config,
    );
    state.attest_batch(attestation_b)?;

    let hint_a = WalletScanHint::new(
        state.batches.get(&batch_a_id).expect("batch exists"),
        HintScope::ViewTagBucket,
        7,
        12,
        &config,
    );
    state.add_wallet_hint(hint_a)?;
    let hint_b = WalletScanHint::new(
        state.batches.get(&batch_b_id).expect("batch exists"),
        HintScope::ShardBloom,
        11,
        10,
        &config,
    );
    state.add_wallet_hint(hint_b)?;

    let rebate_a = FeeRebate::new(
        state.batches.get(&batch_a_id).expect("batch exists"),
        RebateReason::FreshDecoys,
        config.fresh_decoy_rebate_bps,
        DEFAULT_DEVNET_HEIGHT + 68,
        &config,
    );
    state.add_fee_rebate(rebate_a)?;
    let rebate_b = FeeRebate::new(
        state.batches.get(&batch_b_id).expect("batch exists"),
        RebateReason::CacheHit,
        config.cache_hit_rebate_bps,
        DEFAULT_DEVNET_HEIGHT + 69,
        &config,
    );
    state.add_fee_rebate(rebate_b)?;

    let budget_a = RedactionBudget::new(
        "operator-devnet-a",
        &shard_a_id,
        config.redaction_budget_units,
    );
    state
        .redaction_budgets
        .insert(budget_a.budget_id.clone(), budget_a);
    let budget_b = RedactionBudget::new(
        "operator-devnet-b",
        &shard_b_id,
        config.redaction_budget_units,
    );
    state
        .redaction_budgets
        .insert(budget_b.budget_id.clone(), budget_b);

    let rule = InvalidationRule::new(
        InvalidationReason::ManualRetire,
        &shard_b_id,
        None,
        "operator-devnet-b",
        DEFAULT_DEVNET_HEIGHT + 96,
        &config,
    );
    state.apply_invalidation(rule)?;
    state.recompute()?;
    Ok(state)
}

pub fn demo() -> State {
    build_devnet().expect("demo Seraphis membership proof cache fixture must build")
}

pub fn devnet() -> State {
    build_devnet().expect("devnet Seraphis membership proof cache fixture must build")
}

pub fn public_record(state: &State) -> Value {
    json!({
        "protocol_version": PROTOCOL_VERSION,
        "schema_version": MONERO_L2_PQ_PRIVATE_SERAPHIS_MEMBERSHIP_PROOF_CACHE_RUNTIME_SCHEMA_VERSION,
        "chain_id": CHAIN_ID,
        "l2_height": state.l2_height,
        "monero_height": state.monero_height,
        "config": state.config.public_record(),
        "counters": state.counters.public_record(),
        "roots": state.roots.public_record(),
        "cache_shards": state.cache_shards.values().map(CacheShard::public_record).collect::<Vec<_>>(),
        "batches": state.batches.values().map(SeraphisMembershipProofBatch::public_record).collect::<Vec<_>>(),
        "ring_commitments": state.ring_commitments.values().map(SeraphisRingCommitment::public_record).collect::<Vec<_>>(),
        "member_commitment_root": state.roots.member_commitment_root,
        "pq_attestations": state.pq_attestations.values().map(PqCacheAttestation::public_record).collect::<Vec<_>>(),
        "wallet_scan_hints": state.wallet_scan_hints.values().map(WalletScanHint::public_record).collect::<Vec<_>>(),
        "decoy_freshness_floors": state.decoy_freshness_floors.values().map(DecoyFreshnessFloor::public_record).collect::<Vec<_>>(),
        "invalidation_rules": state.invalidation_rules.values().map(InvalidationRule::public_record).collect::<Vec<_>>(),
        "fee_rebates": state.fee_rebates.values().map(FeeRebate::public_record).collect::<Vec<_>>(),
        "redaction_budgets": state.redaction_budgets.values().map(RedactionBudget::public_record).collect::<Vec<_>>(),
        "operator_summaries": state.operator_summaries.values().map(OperatorSummary::public_record).collect::<Vec<_>>(),
    })
}

pub fn state_root(state: &State) -> String {
    state.derive_roots().state_root
}

pub fn demo_batch(
    seed: &str,
    shard_id: &str,
    lane: CacheLane,
    monero_height: u64,
    l2_height: u64,
    ring_count: u32,
    ring_size: u32,
    config: &Config,
) -> (
    SeraphisMembershipProofBatch,
    Vec<SeraphisRingCommitment>,
    Vec<RingMemberCommitment>,
) {
    let mut rings = Vec::new();
    let mut members = Vec::new();
    let temp_batch_label = deterministic_root("DEMO-BATCH-LABEL", seed);
    for ring_index in 0..ring_count {
        let mut ring_members = Vec::new();
        for member_index in 0..ring_size {
            let ordinal = (ring_index as u64)
                .saturating_mul(ring_size as u64)
                .saturating_add(member_index as u64);
            let output_height = monero_height
                .saturating_sub(config.min_decoy_freshness_blocks)
                .saturating_sub(ordinal % 512);
            let member =
                RingMemberCommitment::new(seed, shard_id, output_height, monero_height, ordinal);
            ring_members.push(member.clone());
            members.push(member);
        }
        rings.push(SeraphisRingCommitment::from_members(
            &temp_batch_label,
            ring_index,
            &ring_members,
        ));
    }
    let batch =
        SeraphisMembershipProofBatch::new(shard_id, lane, monero_height, l2_height, &rings, config);
    let fixed_rings = rings
        .into_iter()
        .enumerate()
        .map(|(index, ring)| SeraphisRingCommitment {
            ring_id: ring_id(&batch.batch_id, index as u32, &ring.member_commitment_root),
            batch_id: batch.batch_id.clone(),
            ..ring
        })
        .collect::<Vec<_>>();
    (batch, fixed_rings, members)
}

pub fn deterministic_root(domain: &str, label: &str) -> String {
    domain_hash(
        &format!("SERAPHIS-MEMBERSHIP-PROOF-CACHE-{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn shard_id(operator_id: &str, start_height: u64, end_height: u64, ordinal: u64) -> String {
    domain_hash(
        "SERAPHIS-MEMBERSHIP-PROOF-CACHE-SHARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(operator_id),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
            HashPart::Int(ordinal as i128),
        ],
        32,
    )
}

pub fn member_id(seed: &str, shard_id: &str, ordinal: u64) -> String {
    domain_hash(
        "SERAPHIS-MEMBERSHIP-PROOF-CACHE-MEMBER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(seed),
            HashPart::Str(shard_id),
            HashPart::Int(ordinal as i128),
        ],
        32,
    )
}

pub fn ring_id(batch_id: &str, ring_index: u32, member_commitment_root: &str) -> String {
    domain_hash(
        "SERAPHIS-MEMBERSHIP-PROOF-CACHE-RING-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Int(ring_index as i128),
            HashPart::Str(member_commitment_root),
        ],
        32,
    )
}

pub fn batch_id(shard_id: &str, monero_height: u64, l2_height: u64, ring_root: &str) -> String {
    domain_hash(
        "SERAPHIS-MEMBERSHIP-PROOF-CACHE-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(shard_id),
            HashPart::Int(monero_height as i128),
            HashPart::Int(l2_height as i128),
            HashPart::Str(ring_root),
        ],
        32,
    )
}

pub fn proof_cache_key(shard_id: &str, batch_id: &str, ring_root: &str) -> String {
    domain_hash(
        "SERAPHIS-MEMBERSHIP-PROOF-CACHE-KEY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(shard_id),
            HashPart::Str(batch_id),
            HashPart::Str(ring_root),
        ],
        32,
    )
}

pub fn attestation_id(batch_id: &str, operator_id: &str, l2_height: u64) -> String {
    domain_hash(
        "SERAPHIS-MEMBERSHIP-PROOF-CACHE-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Str(operator_id),
            HashPart::Int(l2_height as i128),
        ],
        32,
    )
}

pub fn wallet_hint_id(batch_id: &str, scope: HintScope, bucket: u16) -> String {
    domain_hash(
        "SERAPHIS-MEMBERSHIP-PROOF-CACHE-WALLET-HINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Str(scope.as_str()),
            HashPart::Int(bucket as i128),
        ],
        32,
    )
}

pub fn invalidation_rule_id(
    reason: InvalidationReason,
    shard_id: &str,
    label: &str,
    l2_height: u64,
) -> String {
    domain_hash(
        "SERAPHIS-MEMBERSHIP-PROOF-CACHE-INVALIDATION-RULE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(reason.as_str()),
            HashPart::Str(shard_id),
            HashPart::Str(label),
            HashPart::Int(l2_height as i128),
        ],
        32,
    )
}

pub fn rebate_id(batch_id: &str, reason: RebateReason, amount_piconero: u64) -> String {
    domain_hash(
        "SERAPHIS-MEMBERSHIP-PROOF-CACHE-FEE-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Str(reason.as_str()),
            HashPart::Int(amount_piconero as i128),
        ],
        32,
    )
}

pub fn redaction_budget_id(owner_id: &str, shard_id: &str, total_units: u64) -> String {
    domain_hash(
        "SERAPHIS-MEMBERSHIP-PROOF-CACHE-REDACTION-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(owner_id),
            HashPart::Str(shard_id),
            HashPart::Int(total_units as i128),
        ],
        32,
    )
}

pub fn operator_summary_root(
    operator_id: &str,
    accepted_attestations: u64,
    challenged_attestations: u64,
    cache_hits: u64,
    cache_misses: u64,
) -> String {
    domain_hash(
        "SERAPHIS-MEMBERSHIP-PROOF-CACHE-OPERATOR-SUMMARY-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(operator_id),
            HashPart::Int(accepted_attestations as i128),
            HashPart::Int(challenged_attestations as i128),
            HashPart::Int(cache_hits as i128),
            HashPart::Int(cache_misses as i128),
        ],
        32,
    )
}

pub fn id_root(domain: &str, ids: &[String]) -> String {
    let leaves = ids
        .iter()
        .map(|id| json!({ "id": id }))
        .collect::<Vec<Value>>();
    merkle_root(domain, &leaves)
}

pub fn records_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

pub fn freshness_score(age_blocks: u64) -> u16 {
    if age_blocks >= DEFAULT_STRICT_DECOY_FRESHNESS_BLOCKS {
        1_000
    } else {
        ((age_blocks.saturating_mul(1_000)) / DEFAULT_STRICT_DECOY_FRESHNESS_BLOCKS) as u16
    }
}

pub fn redaction_budget_for_members(member_count: usize) -> u64 {
    64u64.saturating_add((member_count as u64).saturating_mul(2))
}

pub fn bps(amount: u64, bps_value: u64) -> u64 {
    amount.saturating_mul(bps_value) / MAX_BPS
}

fn require(
    condition: bool,
    message: &str,
) -> MoneroL2PqPrivateSeraphisMembershipProofCacheRuntimeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
