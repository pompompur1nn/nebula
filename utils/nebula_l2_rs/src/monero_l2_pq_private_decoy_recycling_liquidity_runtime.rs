use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PqPrivateDecoyRecyclingLiquidityRuntimeResult<T> = Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_DECOY_RECYCLING_LIQUIDITY_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-decoy-recycling-liquidity-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_DECOY_RECYCLING_LIQUIDITY_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const DECOY_POOL_SUITE: &str = "monero-l2-decoy-recycling-pool-root-v1";
pub const QUALITY_BUCKET_SUITE: &str = "monero-ring-member-quality-bucket-root-v1";
pub const PQ_CURATOR_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-decoy-curator-attestation-v1";
pub const LIQUIDITY_SPONSOR_SUITE: &str = "privacy-liquidity-sponsor-commitment-root-v1";
pub const WITHDRAWAL_FLOOR_SUITE: &str = "monero-withdrawal-privacy-floor-root-v1";
pub const QUARANTINE_SUITE: &str = "stale-poisoned-decoy-quarantine-root-v1";
pub const RECYCLING_CREDIT_SUITE: &str = "low-fee-decoy-recycling-credit-root-v1";
pub const REDACTION_BUDGET_SUITE: &str = "decoy-recycling-privacy-redaction-budget-root-v1";
pub const DEVNET_RUNTIME_ID: &str = "monero-l2-pq-private-decoy-recycling-liquidity-devnet";
pub const DEVNET_MONERO_HEIGHT: u64 = 3_743_200;
pub const DEVNET_L2_HEIGHT: u64 = 904_000;
pub const DEFAULT_MIN_RING_SIZE: u16 = 16;
pub const DEFAULT_TARGET_RING_SIZE: u16 = 32;
pub const DEFAULT_MIN_WITHDRAWAL_PRIVACY_SET: u64 = 65_536;
pub const DEFAULT_TARGET_WITHDRAWAL_PRIVACY_SET: u64 = 131_072;
pub const DEFAULT_CURATOR_TTL_BLOCKS: u64 = 72;
pub const DEFAULT_CREDIT_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 2_880;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub runtime_id: String,
    pub network: String,
    pub monero_height: u64,
    pub l2_height: u64,
    pub min_ring_size: u16,
    pub target_ring_size: u16,
    pub min_withdrawal_privacy_set: u64,
    pub target_withdrawal_privacy_set: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub curator_attestation_ttl_blocks: u64,
    pub low_fee_credit_ttl_blocks: u64,
    pub quarantine_ttl_blocks: u64,
    pub max_public_records: usize,
    pub max_replay_entries: usize,
    pub low_fee_credit_bps: u64,
    pub poisoned_decoy_score_threshold: u64,
    pub stale_decoy_age_blocks: u64,
    pub deterministic_fixture_seed: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            runtime_id: DEVNET_RUNTIME_ID.to_string(),
            network: "monero-devnet".to_string(),
            monero_height: DEVNET_MONERO_HEIGHT,
            l2_height: DEVNET_L2_HEIGHT,
            min_ring_size: DEFAULT_MIN_RING_SIZE,
            target_ring_size: DEFAULT_TARGET_RING_SIZE,
            min_withdrawal_privacy_set: DEFAULT_MIN_WITHDRAWAL_PRIVACY_SET,
            target_withdrawal_privacy_set: DEFAULT_TARGET_WITHDRAWAL_PRIVACY_SET,
            min_pq_security_bits: 192,
            target_pq_security_bits: 256,
            curator_attestation_ttl_blocks: DEFAULT_CURATOR_TTL_BLOCKS,
            low_fee_credit_ttl_blocks: DEFAULT_CREDIT_TTL_BLOCKS,
            quarantine_ttl_blocks: DEFAULT_QUARANTINE_TTL_BLOCKS,
            max_public_records: 256,
            max_replay_entries: 4_096,
            low_fee_credit_bps: 6,
            poisoned_decoy_score_threshold: 700,
            stale_decoy_age_blocks: 172_800,
            deterministic_fixture_seed: "nebula-decoy-recycling-devnet-seed".to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "runtime_id": self.runtime_id,
            "network": self.network,
            "monero_height": self.monero_height,
            "l2_height": self.l2_height,
            "min_ring_size": self.min_ring_size,
            "target_ring_size": self.target_ring_size,
            "min_withdrawal_privacy_set": self.min_withdrawal_privacy_set,
            "target_withdrawal_privacy_set": self.target_withdrawal_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "curator_attestation_ttl_blocks": self.curator_attestation_ttl_blocks,
            "low_fee_credit_ttl_blocks": self.low_fee_credit_ttl_blocks,
            "quarantine_ttl_blocks": self.quarantine_ttl_blocks,
            "max_public_records": self.max_public_records,
            "max_replay_entries": self.max_replay_entries,
            "low_fee_credit_bps": self.low_fee_credit_bps,
            "poisoned_decoy_score_threshold": self.poisoned_decoy_score_threshold,
            "stale_decoy_age_blocks": self.stale_decoy_age_blocks,
            "deterministic_fixture_seed": self.deterministic_fixture_seed,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub decoy_pools: u64,
    pub quality_buckets: u64,
    pub pq_curator_attestations: u64,
    pub liquidity_sponsors: u64,
    pub withdrawal_privacy_floors: u64,
    pub quarantines: u64,
    pub low_fee_recycling_credits: u64,
    pub redaction_budgets: u64,
    pub public_records: u64,
    pub replay_entries: u64,
    pub admitted_decoys: u64,
    pub recycled_decoys: u64,
    pub quarantined_decoys: u64,
    pub sponsored_liquidity_piconero: u64,
    pub redeemed_credit_piconero: u64,
    pub redacted_disclosures: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "decoy_pools": self.decoy_pools,
            "quality_buckets": self.quality_buckets,
            "pq_curator_attestations": self.pq_curator_attestations,
            "liquidity_sponsors": self.liquidity_sponsors,
            "withdrawal_privacy_floors": self.withdrawal_privacy_floors,
            "quarantines": self.quarantines,
            "low_fee_recycling_credits": self.low_fee_recycling_credits,
            "redaction_budgets": self.redaction_budgets,
            "public_records": self.public_records,
            "replay_entries": self.replay_entries,
            "admitted_decoys": self.admitted_decoys,
            "recycled_decoys": self.recycled_decoys,
            "quarantined_decoys": self.quarantined_decoys,
            "sponsored_liquidity_piconero": self.sponsored_liquidity_piconero,
            "redeemed_credit_piconero": self.redeemed_credit_piconero,
            "redacted_disclosures": self.redacted_disclosures,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub decoy_pool_root: String,
    pub quality_bucket_root: String,
    pub pq_curator_attestation_root: String,
    pub liquidity_sponsor_root: String,
    pub withdrawal_privacy_floor_root: String,
    pub quarantine_root: String,
    pub low_fee_recycling_credit_root: String,
    pub redaction_budget_root: String,
    pub public_record_root: String,
    pub replay_filter_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            config_root: empty_root("config"),
            counters_root: empty_root("counters"),
            decoy_pool_root: empty_root("decoy-pools"),
            quality_bucket_root: empty_root("quality-buckets"),
            pq_curator_attestation_root: empty_root("pq-curator-attestations"),
            liquidity_sponsor_root: empty_root("liquidity-sponsors"),
            withdrawal_privacy_floor_root: empty_root("withdrawal-privacy-floors"),
            quarantine_root: empty_root("quarantines"),
            low_fee_recycling_credit_root: empty_root("low-fee-recycling-credits"),
            redaction_budget_root: empty_root("redaction-budgets"),
            public_record_root: empty_root("public-records"),
            replay_filter_root: empty_root("replay-filter"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "decoy_pool_root": self.decoy_pool_root,
            "quality_bucket_root": self.quality_bucket_root,
            "pq_curator_attestation_root": self.pq_curator_attestation_root,
            "liquidity_sponsor_root": self.liquidity_sponsor_root,
            "withdrawal_privacy_floor_root": self.withdrawal_privacy_floor_root,
            "quarantine_root": self.quarantine_root,
            "low_fee_recycling_credit_root": self.low_fee_recycling_credit_root,
            "redaction_budget_root": self.redaction_budget_root,
            "public_record_root": self.public_record_root,
            "replay_filter_root": self.replay_filter_root,
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DecoyPoolStatus {
    Open,
    Cooling,
    Saturated,
    Quarantined,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RingMemberQuality {
    Fresh,
    Mature,
    Recycled,
    Stale,
    Poisoned,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AttestationStatus {
    Pending,
    Active,
    Expired,
    Revoked,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SponsorStatus {
    Active,
    Paused,
    Exhausted,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum QuarantineReason {
    StaleAge,
    PoisonedCluster,
    DuplicateKeyImage,
    CuratorRevocation,
    WithdrawalFloorBreach,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RedactionScope {
    RingMembers,
    SponsorIdentity,
    WithdrawalAmount,
    CuratorSignature,
    QuarantineReason,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecoyPool {
    pub id: String,
    pub asset_id: String,
    pub quality_bucket_id: String,
    pub sponsor_id: String,
    pub status: DecoyPoolStatus,
    pub monero_height: u64,
    pub l2_height: u64,
    pub eligible_decoys: u64,
    pub recycled_decoys: u64,
    pub quarantined_decoys: u64,
    pub target_liquidity_piconero: u64,
    pub reserved_liquidity_piconero: u64,
    pub withdrawal_floor_id: String,
    pub pool_commitment: String,
    pub curator_attestation_ids: BTreeSet<String>,
}

impl DecoyPool {
    pub fn new(
        id: &str,
        asset_id: &str,
        quality_bucket_id: &str,
        sponsor_id: &str,
        withdrawal_floor_id: &str,
        eligible_decoys: u64,
        target_liquidity_piconero: u64,
        config: &Config,
    ) -> Self {
        Self {
            id: id.to_string(),
            asset_id: asset_id.to_string(),
            quality_bucket_id: quality_bucket_id.to_string(),
            sponsor_id: sponsor_id.to_string(),
            status: DecoyPoolStatus::Open,
            monero_height: config.monero_height,
            l2_height: config.l2_height,
            eligible_decoys,
            recycled_decoys: 0,
            quarantined_decoys: 0,
            target_liquidity_piconero,
            reserved_liquidity_piconero: 0,
            withdrawal_floor_id: withdrawal_floor_id.to_string(),
            pool_commitment: commitment(
                "DECOY-POOL-COMMITMENT",
                &[id, asset_id, quality_bucket_id, sponsor_id],
                target_liquidity_piconero,
            ),
            curator_attestation_ids: BTreeSet::new(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "asset_id": self.asset_id,
            "quality_bucket_id": self.quality_bucket_id,
            "sponsor_id": self.sponsor_id,
            "status": pool_status_str(self.status),
            "monero_height": self.monero_height,
            "l2_height": self.l2_height,
            "eligible_decoys": self.eligible_decoys,
            "recycled_decoys": self.recycled_decoys,
            "quarantined_decoys": self.quarantined_decoys,
            "target_liquidity_piconero": self.target_liquidity_piconero,
            "reserved_liquidity_piconero": self.reserved_liquidity_piconero,
            "withdrawal_floor_id": self.withdrawal_floor_id,
            "pool_commitment": self.pool_commitment,
            "curator_attestation_ids": self.curator_attestation_ids.iter().cloned().collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingMemberQualityBucket {
    pub id: String,
    pub label: String,
    pub quality: RingMemberQuality,
    pub min_age_blocks: u64,
    pub max_age_blocks: u64,
    pub min_output_amount_piconero: u64,
    pub max_output_amount_piconero: u64,
    pub entropy_score: u64,
    pub poison_score: u64,
    pub member_count: u64,
    pub deterministic_bucket_root: String,
}

impl RingMemberQualityBucket {
    pub fn new(
        id: &str,
        label: &str,
        quality: RingMemberQuality,
        min_age_blocks: u64,
        max_age_blocks: u64,
        member_count: u64,
    ) -> Self {
        let deterministic_bucket_root = commitment(
            "RING-MEMBER-QUALITY-BUCKET",
            &[id, label, quality_str(quality)],
            member_count,
        );
        Self {
            id: id.to_string(),
            label: label.to_string(),
            quality,
            min_age_blocks,
            max_age_blocks,
            min_output_amount_piconero: 1_000_000,
            max_output_amount_piconero: 250_000_000_000,
            entropy_score: match quality {
                RingMemberQuality::Fresh => 880,
                RingMemberQuality::Mature => 940,
                RingMemberQuality::Recycled => 820,
                RingMemberQuality::Stale => 510,
                RingMemberQuality::Poisoned => 100,
            },
            poison_score: match quality {
                RingMemberQuality::Poisoned => 950,
                RingMemberQuality::Stale => 420,
                RingMemberQuality::Recycled => 180,
                RingMemberQuality::Fresh | RingMemberQuality::Mature => 60,
            },
            member_count,
            deterministic_bucket_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "label": self.label,
            "quality": quality_str(self.quality),
            "min_age_blocks": self.min_age_blocks,
            "max_age_blocks": self.max_age_blocks,
            "min_output_amount_piconero": self.min_output_amount_piconero,
            "max_output_amount_piconero": self.max_output_amount_piconero,
            "entropy_score": self.entropy_score,
            "poison_score": self.poison_score,
            "member_count": self.member_count,
            "deterministic_bucket_root": self.deterministic_bucket_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCuratorAttestation {
    pub id: String,
    pub pool_id: String,
    pub bucket_id: String,
    pub curator_set_id: String,
    pub status: AttestationStatus,
    pub pq_security_bits: u16,
    pub issued_l2_height: u64,
    pub expires_l2_height: u64,
    pub attested_member_count: u64,
    pub stale_member_count: u64,
    pub poisoned_member_count: u64,
    pub signature_root: String,
}

impl PqCuratorAttestation {
    pub fn new(
        id: &str,
        pool_id: &str,
        bucket_id: &str,
        curator_set_id: &str,
        attested_member_count: u64,
        config: &Config,
    ) -> Self {
        Self {
            id: id.to_string(),
            pool_id: pool_id.to_string(),
            bucket_id: bucket_id.to_string(),
            curator_set_id: curator_set_id.to_string(),
            status: AttestationStatus::Active,
            pq_security_bits: config.target_pq_security_bits,
            issued_l2_height: config.l2_height,
            expires_l2_height: config.l2_height + config.curator_attestation_ttl_blocks,
            attested_member_count,
            stale_member_count: 0,
            poisoned_member_count: 0,
            signature_root: commitment(
                "PQ-CURATOR-ATTESTATION",
                &[id, pool_id, bucket_id, curator_set_id],
                attested_member_count,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "pool_id": self.pool_id,
            "bucket_id": self.bucket_id,
            "curator_set_id": self.curator_set_id,
            "status": attestation_status_str(self.status),
            "pq_security_bits": self.pq_security_bits,
            "issued_l2_height": self.issued_l2_height,
            "expires_l2_height": self.expires_l2_height,
            "attested_member_count": self.attested_member_count,
            "stale_member_count": self.stale_member_count,
            "poisoned_member_count": self.poisoned_member_count,
            "signature_root": self.signature_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquiditySponsor {
    pub id: String,
    pub sponsor_commitment: String,
    pub status: SponsorStatus,
    pub reserved_piconero: u64,
    pub spent_piconero: u64,
    pub low_fee_bps: u64,
    pub max_recycled_decoys_per_window: u64,
    pub pools: BTreeSet<String>,
}

impl LiquiditySponsor {
    pub fn new(id: &str, reserved_piconero: u64, low_fee_bps: u64) -> Self {
        Self {
            id: id.to_string(),
            sponsor_commitment: commitment("LIQUIDITY-SPONSOR", &[id], reserved_piconero),
            status: SponsorStatus::Active,
            reserved_piconero,
            spent_piconero: 0,
            low_fee_bps,
            max_recycled_decoys_per_window: 4_096,
            pools: BTreeSet::new(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "sponsor_commitment": self.sponsor_commitment,
            "status": sponsor_status_str(self.status),
            "reserved_piconero": self.reserved_piconero,
            "spent_piconero": self.spent_piconero,
            "low_fee_bps": self.low_fee_bps,
            "max_recycled_decoys_per_window": self.max_recycled_decoys_per_window,
            "pools": self.pools.iter().cloned().collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalPrivacyFloor {
    pub id: String,
    pub asset_id: String,
    pub min_ring_size: u16,
    pub min_decoy_pool_size: u64,
    pub min_fresh_member_bps: u64,
    pub min_mature_member_bps: u64,
    pub max_recycled_member_bps: u64,
    pub enforced: bool,
    pub floor_commitment: String,
}

impl WithdrawalPrivacyFloor {
    pub fn new(id: &str, asset_id: &str, config: &Config) -> Self {
        Self {
            id: id.to_string(),
            asset_id: asset_id.to_string(),
            min_ring_size: config.min_ring_size,
            min_decoy_pool_size: config.min_withdrawal_privacy_set,
            min_fresh_member_bps: 2_000,
            min_mature_member_bps: 4_000,
            max_recycled_member_bps: 2_500,
            enforced: true,
            floor_commitment: commitment(
                "WITHDRAWAL-PRIVACY-FLOOR",
                &[id, asset_id],
                config.min_withdrawal_privacy_set,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "asset_id": self.asset_id,
            "min_ring_size": self.min_ring_size,
            "min_decoy_pool_size": self.min_decoy_pool_size,
            "min_fresh_member_bps": self.min_fresh_member_bps,
            "min_mature_member_bps": self.min_mature_member_bps,
            "max_recycled_member_bps": self.max_recycled_member_bps,
            "enforced": self.enforced,
            "floor_commitment": self.floor_commitment,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecoyQuarantine {
    pub id: String,
    pub pool_id: String,
    pub bucket_id: String,
    pub reason: QuarantineReason,
    pub decoy_count: u64,
    pub poison_score: u64,
    pub opened_l2_height: u64,
    pub expires_l2_height: u64,
    pub quarantine_root: String,
}

impl DecoyQuarantine {
    pub fn new(
        id: &str,
        pool_id: &str,
        bucket_id: &str,
        reason: QuarantineReason,
        decoy_count: u64,
        poison_score: u64,
        config: &Config,
    ) -> Self {
        Self {
            id: id.to_string(),
            pool_id: pool_id.to_string(),
            bucket_id: bucket_id.to_string(),
            reason,
            decoy_count,
            poison_score,
            opened_l2_height: config.l2_height,
            expires_l2_height: config.l2_height + config.quarantine_ttl_blocks,
            quarantine_root: commitment("DECOY-QUARANTINE", &[id, pool_id, bucket_id], decoy_count),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "pool_id": self.pool_id,
            "bucket_id": self.bucket_id,
            "reason": quarantine_reason_str(self.reason),
            "decoy_count": self.decoy_count,
            "poison_score": self.poison_score,
            "opened_l2_height": self.opened_l2_height,
            "expires_l2_height": self.expires_l2_height,
            "quarantine_root": self.quarantine_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRecyclingCredit {
    pub id: String,
    pub sponsor_id: String,
    pub pool_id: String,
    pub owner_commitment: String,
    pub credit_piconero: u64,
    pub redeemed_piconero: u64,
    pub issued_l2_height: u64,
    pub expires_l2_height: u64,
    pub credit_root: String,
}

impl LowFeeRecyclingCredit {
    pub fn new(
        id: &str,
        sponsor_id: &str,
        pool_id: &str,
        owner_label: &str,
        credit_piconero: u64,
        config: &Config,
    ) -> Self {
        Self {
            id: id.to_string(),
            sponsor_id: sponsor_id.to_string(),
            pool_id: pool_id.to_string(),
            owner_commitment: commitment("LOW-FEE-CREDIT-OWNER", &[owner_label], credit_piconero),
            credit_piconero,
            redeemed_piconero: 0,
            issued_l2_height: config.l2_height,
            expires_l2_height: config.l2_height + config.low_fee_credit_ttl_blocks,
            credit_root: commitment(
                "LOW-FEE-RECYCLING-CREDIT",
                &[id, sponsor_id, pool_id],
                credit_piconero,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "sponsor_id": self.sponsor_id,
            "pool_id": self.pool_id,
            "owner_commitment": self.owner_commitment,
            "credit_piconero": self.credit_piconero,
            "redeemed_piconero": self.redeemed_piconero,
            "issued_l2_height": self.issued_l2_height,
            "expires_l2_height": self.expires_l2_height,
            "credit_root": self.credit_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyRedactionBudget {
    pub id: String,
    pub scope: RedactionScope,
    pub pool_id: String,
    pub total_units: u64,
    pub spent_units: u64,
    pub disclosure_floor_units: u64,
    pub budget_root: String,
}

impl PrivacyRedactionBudget {
    pub fn new(id: &str, scope: RedactionScope, pool_id: &str, total_units: u64) -> Self {
        Self {
            id: id.to_string(),
            scope,
            pool_id: pool_id.to_string(),
            total_units,
            spent_units: 0,
            disclosure_floor_units: total_units / 4,
            budget_root: commitment("PRIVACY-REDACTION-BUDGET", &[id, pool_id], total_units),
        }
    }

    pub fn spend(
        &mut self,
        units: u64,
    ) -> MoneroL2PqPrivateDecoyRecyclingLiquidityRuntimeResult<()> {
        if self.spent_units.saturating_add(units) > self.total_units {
            return Err(format!("redaction budget {} exhausted", self.id));
        }
        self.spent_units += units;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "scope": redaction_scope_str(self.scope),
            "pool_id": self.pool_id,
            "total_units": self.total_units,
            "spent_units": self.spent_units,
            "disclosure_floor_units": self.disclosure_floor_units,
            "budget_root": self.budget_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub decoy_pools: BTreeMap<String, DecoyPool>,
    pub quality_buckets: BTreeMap<String, RingMemberQualityBucket>,
    pub pq_curator_attestations: BTreeMap<String, PqCuratorAttestation>,
    pub liquidity_sponsors: BTreeMap<String, LiquiditySponsor>,
    pub withdrawal_privacy_floors: BTreeMap<String, WithdrawalPrivacyFloor>,
    pub quarantines: BTreeMap<String, DecoyQuarantine>,
    pub low_fee_recycling_credits: BTreeMap<String, LowFeeRecyclingCredit>,
    pub redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub public_records: Vec<Value>,
    pub replay_filter: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::empty(),
            decoy_pools: BTreeMap::new(),
            quality_buckets: BTreeMap::new(),
            pq_curator_attestations: BTreeMap::new(),
            liquidity_sponsors: BTreeMap::new(),
            withdrawal_privacy_floors: BTreeMap::new(),
            quarantines: BTreeMap::new(),
            low_fee_recycling_credits: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            public_records: Vec::new(),
            replay_filter: BTreeSet::new(),
        };
        state.refresh();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        let config = state.config.clone();
        let mature = RingMemberQualityBucket::new(
            "bucket-mature-ring-members-devnet",
            "mature real-output shaped decoys",
            RingMemberQuality::Mature,
            7_200,
            86_400,
            98_304,
        );
        state
            .upsert_quality_bucket(mature)
            .expect("devnet mature bucket must validate");
        let recycled = RingMemberQualityBucket::new(
            "bucket-recycled-low-fee-devnet",
            "recycled low-fee ring members",
            RingMemberQuality::Recycled,
            14_400,
            120_000,
            49_152,
        );
        state
            .upsert_quality_bucket(recycled)
            .expect("devnet recycled bucket must validate");
        let floor = WithdrawalPrivacyFloor::new("floor-xmr-withdrawal-devnet", "xmr", &config);
        state
            .upsert_withdrawal_privacy_floor(floor)
            .expect("devnet withdrawal floor must validate");
        let sponsor = LiquiditySponsor::new(
            "sponsor-devnet-decoy-recycling-001",
            8_000_000_000_000,
            config.low_fee_credit_bps,
        );
        state
            .upsert_liquidity_sponsor(sponsor)
            .expect("devnet sponsor must validate");
        let pool = DecoyPool::new(
            "pool-xmr-decoy-recycling-devnet-001",
            "xmr",
            "bucket-mature-ring-members-devnet",
            "sponsor-devnet-decoy-recycling-001",
            "floor-xmr-withdrawal-devnet",
            65_536,
            4_000_000_000_000,
            &config,
        );
        state
            .upsert_decoy_pool(pool)
            .expect("devnet pool must validate");
        let attestation = PqCuratorAttestation::new(
            "attestation-devnet-curator-set-001",
            "pool-xmr-decoy-recycling-devnet-001",
            "bucket-mature-ring-members-devnet",
            "curators-devnet-ml-dsa-slh-001",
            65_536,
            &config,
        );
        state
            .upsert_pq_curator_attestation(attestation)
            .expect("devnet attestation must validate");
        state.refresh();
        state
    }

    pub fn upsert_quality_bucket(
        &mut self,
        bucket: RingMemberQualityBucket,
    ) -> MoneroL2PqPrivateDecoyRecyclingLiquidityRuntimeResult<()> {
        if bucket.id.is_empty() {
            return Err("quality bucket id is required".to_string());
        }
        if bucket.member_count == 0 {
            return Err(format!("quality bucket {} has no members", bucket.id));
        }
        self.replay_once("quality-bucket", &bucket.id)?;
        self.quality_buckets.insert(bucket.id.clone(), bucket);
        self.refresh();
        Ok(())
    }

    pub fn upsert_withdrawal_privacy_floor(
        &mut self,
        floor: WithdrawalPrivacyFloor,
    ) -> MoneroL2PqPrivateDecoyRecyclingLiquidityRuntimeResult<()> {
        if floor.min_ring_size < self.config.min_ring_size {
            return Err(format!("withdrawal floor {} ring size too low", floor.id));
        }
        if floor.min_decoy_pool_size < self.config.min_withdrawal_privacy_set {
            return Err(format!(
                "withdrawal floor {} privacy set too small",
                floor.id
            ));
        }
        self.replay_once("withdrawal-floor", &floor.id)?;
        self.withdrawal_privacy_floors
            .insert(floor.id.clone(), floor);
        self.refresh();
        Ok(())
    }

    pub fn upsert_liquidity_sponsor(
        &mut self,
        sponsor: LiquiditySponsor,
    ) -> MoneroL2PqPrivateDecoyRecyclingLiquidityRuntimeResult<()> {
        if sponsor.low_fee_bps > MAX_BPS {
            return Err(format!("sponsor {} low fee bps invalid", sponsor.id));
        }
        self.replay_once("liquidity-sponsor", &sponsor.id)?;
        self.liquidity_sponsors.insert(sponsor.id.clone(), sponsor);
        self.refresh();
        Ok(())
    }

    pub fn upsert_decoy_pool(
        &mut self,
        pool: DecoyPool,
    ) -> MoneroL2PqPrivateDecoyRecyclingLiquidityRuntimeResult<()> {
        if !self.quality_buckets.contains_key(&pool.quality_bucket_id) {
            return Err(format!(
                "pool {} references missing quality bucket",
                pool.id
            ));
        }
        if !self.liquidity_sponsors.contains_key(&pool.sponsor_id) {
            return Err(format!("pool {} references missing sponsor", pool.id));
        }
        if !self
            .withdrawal_privacy_floors
            .contains_key(&pool.withdrawal_floor_id)
        {
            return Err(format!(
                "pool {} references missing withdrawal floor",
                pool.id
            ));
        }
        if pool.eligible_decoys < self.config.min_withdrawal_privacy_set {
            return Err(format!("pool {} below withdrawal privacy floor", pool.id));
        }
        self.replay_once("decoy-pool", &pool.id)?;
        if let Some(sponsor) = self.liquidity_sponsors.get_mut(&pool.sponsor_id) {
            sponsor.pools.insert(pool.id.clone());
            sponsor.reserved_piconero = sponsor
                .reserved_piconero
                .max(pool.target_liquidity_piconero);
        }
        self.decoy_pools.insert(pool.id.clone(), pool);
        self.refresh();
        Ok(())
    }

    pub fn upsert_pq_curator_attestation(
        &mut self,
        attestation: PqCuratorAttestation,
    ) -> MoneroL2PqPrivateDecoyRecyclingLiquidityRuntimeResult<()> {
        if attestation.pq_security_bits < self.config.min_pq_security_bits {
            return Err(format!(
                "attestation {} pq security too low",
                attestation.id
            ));
        }
        if !self.decoy_pools.contains_key(&attestation.pool_id) {
            return Err(format!(
                "attestation {} references missing pool",
                attestation.id
            ));
        }
        if !self.quality_buckets.contains_key(&attestation.bucket_id) {
            return Err(format!(
                "attestation {} references missing bucket",
                attestation.id
            ));
        }
        self.replay_once("pq-curator-attestation", &attestation.id)?;
        if let Some(pool) = self.decoy_pools.get_mut(&attestation.pool_id) {
            pool.curator_attestation_ids.insert(attestation.id.clone());
        }
        self.pq_curator_attestations
            .insert(attestation.id.clone(), attestation);
        self.refresh();
        Ok(())
    }

    pub fn quarantine_decoys(
        &mut self,
        quarantine: DecoyQuarantine,
    ) -> MoneroL2PqPrivateDecoyRecyclingLiquidityRuntimeResult<()> {
        if !self.decoy_pools.contains_key(&quarantine.pool_id) {
            return Err(format!(
                "quarantine {} references missing pool",
                quarantine.id
            ));
        }
        if quarantine.decoy_count == 0 {
            return Err(format!("quarantine {} has no decoys", quarantine.id));
        }
        self.replay_once("decoy-quarantine", &quarantine.id)?;
        if let Some(pool) = self.decoy_pools.get_mut(&quarantine.pool_id) {
            pool.quarantined_decoys = pool
                .quarantined_decoys
                .saturating_add(quarantine.decoy_count);
            pool.eligible_decoys = pool.eligible_decoys.saturating_sub(quarantine.decoy_count);
            if quarantine.poison_score >= self.config.poisoned_decoy_score_threshold {
                pool.status = DecoyPoolStatus::Quarantined;
            }
        }
        self.quarantines.insert(quarantine.id.clone(), quarantine);
        self.refresh();
        Ok(())
    }

    pub fn mint_low_fee_recycling_credit(
        &mut self,
        credit: LowFeeRecyclingCredit,
    ) -> MoneroL2PqPrivateDecoyRecyclingLiquidityRuntimeResult<()> {
        if !self.decoy_pools.contains_key(&credit.pool_id) {
            return Err(format!("credit {} references missing pool", credit.id));
        }
        if !self.liquidity_sponsors.contains_key(&credit.sponsor_id) {
            return Err(format!("credit {} references missing sponsor", credit.id));
        }
        self.replay_once("low-fee-recycling-credit", &credit.id)?;
        if let Some(sponsor) = self.liquidity_sponsors.get_mut(&credit.sponsor_id) {
            sponsor.spent_piconero = sponsor
                .spent_piconero
                .saturating_add(credit.credit_piconero);
            if sponsor.spent_piconero >= sponsor.reserved_piconero {
                sponsor.status = SponsorStatus::Exhausted;
            }
        }
        self.low_fee_recycling_credits
            .insert(credit.id.clone(), credit);
        self.refresh();
        Ok(())
    }

    pub fn allocate_redaction_budget(
        &mut self,
        budget: PrivacyRedactionBudget,
    ) -> MoneroL2PqPrivateDecoyRecyclingLiquidityRuntimeResult<()> {
        if !self.decoy_pools.contains_key(&budget.pool_id) {
            return Err(format!(
                "redaction budget {} references missing pool",
                budget.id
            ));
        }
        self.replay_once("redaction-budget", &budget.id)?;
        self.redaction_budgets.insert(budget.id.clone(), budget);
        self.refresh();
        Ok(())
    }

    pub fn recycle_decoys(
        &mut self,
        pool_id: &str,
        count: u64,
        credit_id: Option<&str>,
    ) -> MoneroL2PqPrivateDecoyRecyclingLiquidityRuntimeResult<()> {
        if count == 0 {
            return Err("recycle count must be non-zero".to_string());
        }
        let pool = self
            .decoy_pools
            .get_mut(pool_id)
            .ok_or_else(|| format!("pool {pool_id} not found"))?;
        if pool.status == DecoyPoolStatus::Quarantined {
            return Err(format!("pool {pool_id} is quarantined"));
        }
        if pool.eligible_decoys < count {
            return Err(format!("pool {pool_id} has insufficient eligible decoys"));
        }
        pool.recycled_decoys = pool.recycled_decoys.saturating_add(count);
        pool.eligible_decoys = pool.eligible_decoys.saturating_sub(count);
        if let Some(credit_id) = credit_id {
            let credit = self
                .low_fee_recycling_credits
                .get_mut(credit_id)
                .ok_or_else(|| format!("credit {credit_id} not found"))?;
            let redeem = count.saturating_mul(1_000_000);
            credit.redeemed_piconero = credit
                .redeemed_piconero
                .saturating_add(redeem)
                .min(credit.credit_piconero);
        }
        self.append_public_record(json!({
            "event": "decoys_recycled",
            "pool_id": pool_id,
            "count": count,
            "credit_id": credit_id,
        }));
        self.refresh();
        Ok(())
    }

    pub fn spend_redaction_budget(
        &mut self,
        budget_id: &str,
        units: u64,
    ) -> MoneroL2PqPrivateDecoyRecyclingLiquidityRuntimeResult<()> {
        let budget = self
            .redaction_budgets
            .get_mut(budget_id)
            .ok_or_else(|| format!("redaction budget {budget_id} not found"))?;
        budget.spend(units)?;
        self.append_public_record(json!({
            "event": "redaction_budget_spent",
            "budget_id": budget_id,
            "units": units,
        }));
        self.refresh();
        Ok(())
    }

    pub fn counters(&self) -> Counters {
        let mut counters = self.counters.clone();
        counters.decoy_pools = self.decoy_pools.len() as u64;
        counters.quality_buckets = self.quality_buckets.len() as u64;
        counters.pq_curator_attestations = self.pq_curator_attestations.len() as u64;
        counters.liquidity_sponsors = self.liquidity_sponsors.len() as u64;
        counters.withdrawal_privacy_floors = self.withdrawal_privacy_floors.len() as u64;
        counters.quarantines = self.quarantines.len() as u64;
        counters.low_fee_recycling_credits = self.low_fee_recycling_credits.len() as u64;
        counters.redaction_budgets = self.redaction_budgets.len() as u64;
        counters.public_records = self.public_records.len() as u64;
        counters.replay_entries = self.replay_filter.len() as u64;
        counters.admitted_decoys = self
            .decoy_pools
            .values()
            .map(|pool| pool.eligible_decoys + pool.recycled_decoys + pool.quarantined_decoys)
            .sum();
        counters.recycled_decoys = self
            .decoy_pools
            .values()
            .map(|pool| pool.recycled_decoys)
            .sum();
        counters.quarantined_decoys = self
            .decoy_pools
            .values()
            .map(|pool| pool.quarantined_decoys)
            .sum();
        counters.sponsored_liquidity_piconero = self
            .liquidity_sponsors
            .values()
            .map(|sponsor| sponsor.reserved_piconero)
            .sum();
        counters.redeemed_credit_piconero = self
            .low_fee_recycling_credits
            .values()
            .map(|credit| credit.redeemed_piconero)
            .sum();
        counters.redacted_disclosures = self
            .redaction_budgets
            .values()
            .map(|budget| budget.spent_units)
            .sum();
        counters
    }

    pub fn roots(&self) -> Roots {
        let counters = self.counters();
        Roots {
            config_root: root_from_record("CONFIG", &self.config.public_record()),
            counters_root: root_from_record("COUNTERS", &counters.public_record()),
            decoy_pool_root: map_root(
                DECOY_POOL_SUITE,
                &self.decoy_pools,
                DecoyPool::public_record,
            ),
            quality_bucket_root: map_root(
                QUALITY_BUCKET_SUITE,
                &self.quality_buckets,
                RingMemberQualityBucket::public_record,
            ),
            pq_curator_attestation_root: map_root(
                PQ_CURATOR_SUITE,
                &self.pq_curator_attestations,
                PqCuratorAttestation::public_record,
            ),
            liquidity_sponsor_root: map_root(
                LIQUIDITY_SPONSOR_SUITE,
                &self.liquidity_sponsors,
                LiquiditySponsor::public_record,
            ),
            withdrawal_privacy_floor_root: map_root(
                WITHDRAWAL_FLOOR_SUITE,
                &self.withdrawal_privacy_floors,
                WithdrawalPrivacyFloor::public_record,
            ),
            quarantine_root: map_root(
                QUARANTINE_SUITE,
                &self.quarantines,
                DecoyQuarantine::public_record,
            ),
            low_fee_recycling_credit_root: map_root(
                RECYCLING_CREDIT_SUITE,
                &self.low_fee_recycling_credits,
                LowFeeRecyclingCredit::public_record,
            ),
            redaction_budget_root: map_root(
                REDACTION_BUDGET_SUITE,
                &self.redaction_budgets,
                PrivacyRedactionBudget::public_record,
            ),
            public_record_root: vec_root("PUBLIC-RECORDS", &self.public_records),
            replay_filter_root: set_root("REPLAY-FILTER", &self.replay_filter),
        }
    }

    pub fn refresh(&mut self) {
        self.counters = self.counters();
        self.roots = self.roots();
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": self.roots().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut map) = record {
            map.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn replay_once(
        &mut self,
        kind: &str,
        id: &str,
    ) -> MoneroL2PqPrivateDecoyRecyclingLiquidityRuntimeResult<()> {
        let key = replay_key(kind, id);
        if self.replay_filter.contains(&key) {
            return Err(format!("replay rejected for {kind}:{id}"));
        }
        self.replay_filter.insert(key);
        trim_set(&mut self.replay_filter, self.config.max_replay_entries);
        Ok(())
    }

    fn append_public_record(&mut self, record: Value) {
        self.public_records.push(record);
        trim_vec(&mut self.public_records, self.config.max_public_records);
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let mut state = State::devnet();
    let config = state.config.clone();
    let stale = RingMemberQualityBucket::new(
        "bucket-stale-watchlist-devnet",
        "stale outputs awaiting quarantine",
        RingMemberQuality::Stale,
        config.stale_decoy_age_blocks,
        config.stale_decoy_age_blocks + 80_000,
        8_192,
    );
    state
        .upsert_quality_bucket(stale)
        .expect("demo stale bucket must validate");
    let credit = LowFeeRecyclingCredit::new(
        "credit-low-fee-recycling-demo-001",
        "sponsor-devnet-decoy-recycling-001",
        "pool-xmr-decoy-recycling-devnet-001",
        "demo-wallet-cluster",
        500_000_000,
        &config,
    );
    state
        .mint_low_fee_recycling_credit(credit)
        .expect("demo credit must validate");
    let budget = PrivacyRedactionBudget::new(
        "redaction-demo-ring-members-001",
        RedactionScope::RingMembers,
        "pool-xmr-decoy-recycling-devnet-001",
        4_096,
    );
    state
        .allocate_redaction_budget(budget)
        .expect("demo redaction budget must validate");
    let quarantine = DecoyQuarantine::new(
        "quarantine-demo-stale-001",
        "pool-xmr-decoy-recycling-devnet-001",
        "bucket-stale-watchlist-devnet",
        QuarantineReason::StaleAge,
        512,
        480,
        &config,
    );
    state
        .quarantine_decoys(quarantine)
        .expect("demo quarantine must validate");
    state
        .recycle_decoys(
            "pool-xmr-decoy-recycling-devnet-001",
            256,
            Some("credit-low-fee-recycling-demo-001"),
        )
        .expect("demo recycling must validate");
    state
        .spend_redaction_budget("redaction-demo-ring-members-001", 64)
        .expect("demo redaction spend must validate");
    state.refresh();
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("STATE", record)
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("MONERO-L2-PQ-PRIVATE-DECOY-RECYCLING-LIQUIDITY:{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, to_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let records: Vec<Value> = map
        .iter()
        .map(|(id, value)| json!({ "id": id, "record": to_record(value) }))
        .collect();
    public_record_root(domain, &records)
}

fn vec_root(domain: &str, records: &[Value]) -> String {
    public_record_root(domain, records)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let records: Vec<Value> = set.iter().map(|value| json!(value)).collect();
    public_record_root(domain, &records)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    if records.is_empty() {
        return empty_root(domain);
    }
    let mut sorted = records.to_vec();
    sorted.sort_by_key(canonical_json);
    merkle_root(
        &format!("MONERO-L2-PQ-PRIVATE-DECOY-RECYCLING-LIQUIDITY:{domain}"),
        &sorted,
    )
}

fn empty_root(label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-DECOY-RECYCLING-LIQUIDITY:EMPTY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

fn commitment(domain: &str, labels: &[&str], amount: u64) -> String {
    let labels: Vec<Value> = labels.iter().map(|label| json!(label)).collect();
    domain_hash(
        &format!("MONERO-L2-PQ-PRIVATE-DECOY-RECYCLING-LIQUIDITY:{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(&json!(labels)),
            HashPart::U64(amount),
        ],
        32,
    )
}

fn replay_key(kind: &str, id: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-DECOY-RECYCLING-LIQUIDITY:REPLAY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(id),
        ],
        32,
    )
}

fn canonical_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
}

fn trim_vec<T>(values: &mut Vec<T>, max_len: usize) {
    if values.len() > max_len {
        let drain_len = values.len() - max_len;
        values.drain(0..drain_len);
    }
}

fn trim_set(values: &mut BTreeSet<String>, max_len: usize) {
    while values.len() > max_len {
        if let Some(first) = values.iter().next().cloned() {
            values.remove(&first);
        } else {
            break;
        }
    }
}

fn pool_status_str(status: DecoyPoolStatus) -> &'static str {
    match status {
        DecoyPoolStatus::Open => "open",
        DecoyPoolStatus::Cooling => "cooling",
        DecoyPoolStatus::Saturated => "saturated",
        DecoyPoolStatus::Quarantined => "quarantined",
    }
}

fn quality_str(quality: RingMemberQuality) -> &'static str {
    match quality {
        RingMemberQuality::Fresh => "fresh",
        RingMemberQuality::Mature => "mature",
        RingMemberQuality::Recycled => "recycled",
        RingMemberQuality::Stale => "stale",
        RingMemberQuality::Poisoned => "poisoned",
    }
}

fn attestation_status_str(status: AttestationStatus) -> &'static str {
    match status {
        AttestationStatus::Pending => "pending",
        AttestationStatus::Active => "active",
        AttestationStatus::Expired => "expired",
        AttestationStatus::Revoked => "revoked",
    }
}

fn sponsor_status_str(status: SponsorStatus) -> &'static str {
    match status {
        SponsorStatus::Active => "active",
        SponsorStatus::Paused => "paused",
        SponsorStatus::Exhausted => "exhausted",
    }
}

fn quarantine_reason_str(reason: QuarantineReason) -> &'static str {
    match reason {
        QuarantineReason::StaleAge => "stale_age",
        QuarantineReason::PoisonedCluster => "poisoned_cluster",
        QuarantineReason::DuplicateKeyImage => "duplicate_key_image",
        QuarantineReason::CuratorRevocation => "curator_revocation",
        QuarantineReason::WithdrawalFloorBreach => "withdrawal_floor_breach",
    }
}

fn redaction_scope_str(scope: RedactionScope) -> &'static str {
    match scope {
        RedactionScope::RingMembers => "ring_members",
        RedactionScope::SponsorIdentity => "sponsor_identity",
        RedactionScope::WithdrawalAmount => "withdrawal_amount",
        RedactionScope::CuratorSignature => "curator_signature",
        RedactionScope::QuarantineReason => "quarantine_reason",
    }
}
