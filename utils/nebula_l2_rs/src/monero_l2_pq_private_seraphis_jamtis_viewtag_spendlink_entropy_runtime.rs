use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateSeraphisJamtisViewtagSpendlinkEntropyRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_SERAPHIS_JAMTIS_VIEWTAG_SPENDLINK_ENTROPY_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-private-seraphis-jamtis-viewtag-spendlink-entropy-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_SERAPHIS_JAMTIS_VIEWTAG_SPENDLINK_ENTROPY_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_080_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_760_000;
pub const DEVNET_EPOCH: u64 = 14_640;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const VIEWTAG_SCAN_BUCKET_SCHEME: &str = "seraphis-jamtis-viewtag-scan-bucket-root-v1";
pub const SPENDLINK_SHIELD_SCHEME: &str = "seraphis-jamtis-spendlink-shield-score-root-v1";
pub const DECOY_ENTROPY_FLOOR_SCHEME: &str = "monero-ring-decoy-entropy-floor-root-v1";
pub const STEALTH_NOTE_FRESHNESS_SCHEME: &str = "seraphis-jamtis-stealth-note-freshness-root-v1";
pub const OUTPUT_AGE_DIVERSITY_SCHEME: &str = "monero-output-age-diversity-root-v1";
pub const PQ_MIGRATION_ATTESTATION_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-seraphis-jamtis-migration-attestation-root-v1";
pub const SCAN_FEE_SPONSORSHIP_SCHEME: &str = "low-fee-private-viewtag-scan-sponsorship-root-v1";
pub const LOW_FEE_AUDIT_SCHEME: &str = "low-fee-private-monero-scan-audit-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "roots-only-seraphis-jamtis-viewtag-spendlink-entropy-public-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_addresses_view_keys_key_images_amounts_output_indices_ring_witnesses_viewtags_or_spend_graphs";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_RING_SIZE: u16 = 16;
pub const DEFAULT_TARGET_RING_SIZE: u16 = 64;
pub const DEFAULT_MIN_BUCKET_OUTPUTS: u64 = 32_768;
pub const DEFAULT_TARGET_BUCKET_OUTPUTS: u64 = 262_144;
pub const DEFAULT_MIN_SCAN_BUCKETS: u64 = 8;
pub const DEFAULT_MIN_DECOY_ENTROPY_BPS: u64 = 8_600;
pub const DEFAULT_MIN_SPENDLINK_SHIELD_BPS: u64 = 8_500;
pub const DEFAULT_MIN_FRESHNESS_BPS: u64 = 7_800;
pub const DEFAULT_MIN_AGE_DIVERSITY_BPS: u64 = 7_600;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_SCAN_BUCKET_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_SPONSORSHIP_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_TARGET_SPONSOR_COVER_BPS: u64 = 9_250;
pub const DEFAULT_PUBLIC_BUCKET_SIZE: u64 = 64;
pub const DEFAULT_MAX_SCAN_UNITS_PER_BUCKET: u64 = 4_096;
pub const DEFAULT_MAX_SPONSOR_UNITS_PER_EPOCH: u64 = 65_536;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeLane {
    WalletScan,
    BridgeWithdrawal,
    MerchantReceive,
    DexSettlement,
    Watchtower,
    ReorgRepair,
    MigrationAudit,
    FeeSponsor,
}

impl RuntimeLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletScan => "wallet_scan",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::MerchantReceive => "merchant_receive",
            Self::DexSettlement => "dex_settlement",
            Self::Watchtower => "watchtower",
            Self::ReorgRepair => "reorg_repair",
            Self::MigrationAudit => "migration_audit",
            Self::FeeSponsor => "fee_sponsor",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyEra {
    RingCt,
    SeraphisCandidate,
    JamtisCandidate,
    DualStack,
    SeraphisJamtis,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketStatus {
    Open,
    IntakeClosed,
    Scanned,
    EntropyChecked,
    ShieldScored,
    FreshnessChecked,
    AgeDiverse,
    Attested,
    Sponsored,
    Audited,
    Sealed,
    Quarantined,
    Rejected,
    Expired,
}

impl BucketStatus {
    pub fn public_usable(self) -> bool {
        matches!(
            self,
            Self::EntropyChecked
                | Self::ShieldScored
                | Self::FreshnessChecked
                | Self::AgeDiverse
                | Self::Attested
                | Self::Sponsored
                | Self::Audited
                | Self::Sealed
        )
    }

    pub fn accepts_scan_work(self) -> bool {
        matches!(self, Self::Open | Self::IntakeClosed | Self::Scanned)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Quorum,
    StrongQuorum,
    Rotating,
    Expired,
    Revoked,
    Rejected,
}

impl AttestationStatus {
    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Accepted | Self::Quorum | Self::StrongQuorum)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Open,
    Reserved,
    Netting,
    Paid,
    Refunded,
    Slashed,
    Exhausted,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    Draft,
    Measuring,
    Passed,
    Warning,
    Failed,
    Remediated,
    Published,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicAudience {
    Wallets,
    Sponsors,
    Watchtowers,
    Operators,
    Governance,
    Public,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub viewtag_scan_bucket_scheme: String,
    pub spendlink_shield_scheme: String,
    pub decoy_entropy_floor_scheme: String,
    pub stealth_note_freshness_scheme: String,
    pub output_age_diversity_scheme: String,
    pub pq_migration_attestation_scheme: String,
    pub scan_fee_sponsorship_scheme: String,
    pub low_fee_audit_scheme: String,
    pub public_record_scheme: String,
    pub privacy_boundary: String,
    pub min_ring_size: u16,
    pub target_ring_size: u16,
    pub min_bucket_outputs: u64,
    pub target_bucket_outputs: u64,
    pub min_scan_buckets: u64,
    pub min_decoy_entropy_bps: u64,
    pub min_spendlink_shield_bps: u64,
    pub min_freshness_bps: u64,
    pub min_age_diversity_bps: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub attestation_ttl_blocks: u64,
    pub scan_bucket_ttl_blocks: u64,
    pub sponsorship_ttl_blocks: u64,
    pub max_user_fee_bps: u64,
    pub target_sponsor_cover_bps: u64,
    pub public_bucket_size: u64,
    pub max_scan_units_per_bucket: u64,
    pub max_sponsor_units_per_epoch: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            viewtag_scan_bucket_scheme: VIEWTAG_SCAN_BUCKET_SCHEME.to_string(),
            spendlink_shield_scheme: SPENDLINK_SHIELD_SCHEME.to_string(),
            decoy_entropy_floor_scheme: DECOY_ENTROPY_FLOOR_SCHEME.to_string(),
            stealth_note_freshness_scheme: STEALTH_NOTE_FRESHNESS_SCHEME.to_string(),
            output_age_diversity_scheme: OUTPUT_AGE_DIVERSITY_SCHEME.to_string(),
            pq_migration_attestation_scheme: PQ_MIGRATION_ATTESTATION_SCHEME.to_string(),
            scan_fee_sponsorship_scheme: SCAN_FEE_SPONSORSHIP_SCHEME.to_string(),
            low_fee_audit_scheme: LOW_FEE_AUDIT_SCHEME.to_string(),
            public_record_scheme: PUBLIC_RECORD_SCHEME.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            min_ring_size: DEFAULT_MIN_RING_SIZE,
            target_ring_size: DEFAULT_TARGET_RING_SIZE,
            min_bucket_outputs: DEFAULT_MIN_BUCKET_OUTPUTS,
            target_bucket_outputs: DEFAULT_TARGET_BUCKET_OUTPUTS,
            min_scan_buckets: DEFAULT_MIN_SCAN_BUCKETS,
            min_decoy_entropy_bps: DEFAULT_MIN_DECOY_ENTROPY_BPS,
            min_spendlink_shield_bps: DEFAULT_MIN_SPENDLINK_SHIELD_BPS,
            min_freshness_bps: DEFAULT_MIN_FRESHNESS_BPS,
            min_age_diversity_bps: DEFAULT_MIN_AGE_DIVERSITY_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            scan_bucket_ttl_blocks: DEFAULT_SCAN_BUCKET_TTL_BLOCKS,
            sponsorship_ttl_blocks: DEFAULT_SPONSORSHIP_TTL_BLOCKS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_sponsor_cover_bps: DEFAULT_TARGET_SPONSOR_COVER_BPS,
            public_bucket_size: DEFAULT_PUBLIC_BUCKET_SIZE,
            max_scan_units_per_bucket: DEFAULT_MAX_SCAN_UNITS_PER_BUCKET,
            max_sponsor_units_per_epoch: DEFAULT_MAX_SPONSOR_UNITS_PER_EPOCH,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure(
            self.min_ring_size >= 16,
            "minimum ring size is below Monero floor",
        )?;
        ensure(
            self.target_ring_size >= self.min_ring_size,
            "target ring size must cover minimum ring size",
        )?;
        ensure(
            self.target_bucket_outputs >= self.min_bucket_outputs,
            "target bucket outputs must cover privacy floor",
        )?;
        ensure(
            self.min_scan_buckets > 0,
            "scan bucket floor must be nonzero",
        )?;
        ensure(
            self.min_decoy_entropy_bps <= MAX_BPS
                && self.min_spendlink_shield_bps <= MAX_BPS
                && self.min_freshness_bps <= MAX_BPS
                && self.min_age_diversity_bps <= MAX_BPS,
            "privacy thresholds exceed max bps",
        )?;
        ensure(
            self.target_pq_security_bits >= self.min_pq_security_bits,
            "target PQ security must cover minimum PQ security",
        )?;
        ensure(
            self.max_user_fee_bps <= MAX_BPS && self.target_sponsor_cover_bps <= MAX_BPS,
            "fee sponsorship bounds are invalid",
        )?;
        ensure(
            self.public_bucket_size > 0,
            "public bucket size must be nonzero",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "viewtag_scan_bucket_scheme": self.viewtag_scan_bucket_scheme,
            "spendlink_shield_scheme": self.spendlink_shield_scheme,
            "decoy_entropy_floor_scheme": self.decoy_entropy_floor_scheme,
            "stealth_note_freshness_scheme": self.stealth_note_freshness_scheme,
            "output_age_diversity_scheme": self.output_age_diversity_scheme,
            "pq_migration_attestation_scheme": self.pq_migration_attestation_scheme,
            "scan_fee_sponsorship_scheme": self.scan_fee_sponsorship_scheme,
            "low_fee_audit_scheme": self.low_fee_audit_scheme,
            "public_record_scheme": self.public_record_scheme,
            "privacy_boundary": self.privacy_boundary,
            "min_ring_size": self.min_ring_size,
            "target_ring_size": self.target_ring_size,
            "min_bucket_outputs": self.min_bucket_outputs,
            "target_bucket_outputs": self.target_bucket_outputs,
            "min_scan_buckets": self.min_scan_buckets,
            "min_decoy_entropy_bps": self.min_decoy_entropy_bps,
            "min_spendlink_shield_bps": self.min_spendlink_shield_bps,
            "min_freshness_bps": self.min_freshness_bps,
            "min_age_diversity_bps": self.min_age_diversity_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "scan_bucket_ttl_blocks": self.scan_bucket_ttl_blocks,
            "sponsorship_ttl_blocks": self.sponsorship_ttl_blocks,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_sponsor_cover_bps": self.target_sponsor_cover_bps,
            "public_bucket_size": self.public_bucket_size,
            "max_scan_units_per_bucket": self.max_scan_units_per_bucket,
            "max_sponsor_units_per_epoch": self.max_sponsor_units_per_epoch,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub viewtag_scan_buckets: u64,
    pub spendlink_shield_scores: u64,
    pub decoy_entropy_floors: u64,
    pub stealth_note_freshness_reports: u64,
    pub output_age_diversity_reports: u64,
    pub pq_migration_attestations: u64,
    pub scan_fee_sponsorships: u64,
    pub low_fee_audits: u64,
    pub public_records: u64,
    pub quarantined_items: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "viewtag_scan_buckets": self.viewtag_scan_buckets,
            "spendlink_shield_scores": self.spendlink_shield_scores,
            "decoy_entropy_floors": self.decoy_entropy_floors,
            "stealth_note_freshness_reports": self.stealth_note_freshness_reports,
            "output_age_diversity_reports": self.output_age_diversity_reports,
            "pq_migration_attestations": self.pq_migration_attestations,
            "scan_fee_sponsorships": self.scan_fee_sponsorships,
            "low_fee_audits": self.low_fee_audits,
            "public_records": self.public_records,
            "quarantined_items": self.quarantined_items,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub viewtag_scan_bucket_root: String,
    pub spendlink_shield_score_root: String,
    pub decoy_entropy_floor_root: String,
    pub stealth_note_freshness_root: String,
    pub output_age_diversity_root: String,
    pub pq_migration_attestation_root: String,
    pub scan_fee_sponsorship_root: String,
    pub low_fee_audit_root: String,
    pub roots_only_public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "viewtag_scan_bucket_root": self.viewtag_scan_bucket_root,
            "spendlink_shield_score_root": self.spendlink_shield_score_root,
            "decoy_entropy_floor_root": self.decoy_entropy_floor_root,
            "stealth_note_freshness_root": self.stealth_note_freshness_root,
            "output_age_diversity_root": self.output_age_diversity_root,
            "pq_migration_attestation_root": self.pq_migration_attestation_root,
            "scan_fee_sponsorship_root": self.scan_fee_sponsorship_root,
            "low_fee_audit_root": self.low_fee_audit_root,
            "roots_only_public_record_root": self.roots_only_public_record_root,
            "state_root": self.state_root,
        })
    }

    pub fn without_state_root(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "viewtag_scan_bucket_root": self.viewtag_scan_bucket_root,
            "spendlink_shield_score_root": self.spendlink_shield_score_root,
            "decoy_entropy_floor_root": self.decoy_entropy_floor_root,
            "stealth_note_freshness_root": self.stealth_note_freshness_root,
            "output_age_diversity_root": self.output_age_diversity_root,
            "pq_migration_attestation_root": self.pq_migration_attestation_root,
            "scan_fee_sponsorship_root": self.scan_fee_sponsorship_root,
            "low_fee_audit_root": self.low_fee_audit_root,
            "roots_only_public_record_root": self.roots_only_public_record_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewtagScanBucket {
    pub bucket_id: String,
    pub lane: RuntimeLane,
    pub era: PrivacyEra,
    pub epoch: u64,
    pub l2_height_bucket: u64,
    pub monero_height_bucket: u64,
    pub output_count_bucket: u64,
    pub scan_unit_bucket: u64,
    pub viewtag_bucket_root: String,
    pub jamtis_scan_hint_root: String,
    pub seraphis_membership_root: String,
    pub roots_only_receipt_root: String,
    pub expires_at_monero_height: u64,
    pub status: BucketStatus,
}

impl ViewtagScanBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "lane": self.lane.as_str(),
            "era": self.era,
            "epoch": self.epoch,
            "l2_height_bucket": self.l2_height_bucket,
            "monero_height_bucket": self.monero_height_bucket,
            "output_count_bucket": self.output_count_bucket,
            "scan_unit_bucket": self.scan_unit_bucket,
            "viewtag_bucket_root": self.viewtag_bucket_root,
            "jamtis_scan_hint_root": self.jamtis_scan_hint_root,
            "seraphis_membership_root": self.seraphis_membership_root,
            "roots_only_receipt_root": self.roots_only_receipt_root,
            "expires_at_monero_height": self.expires_at_monero_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("viewtag-scan-bucket", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SpendlinkShieldScore {
    pub score_id: String,
    pub bucket_id: String,
    pub ring_size: u16,
    pub scan_bucket_count: u64,
    pub viewtag_collision_bps: u64,
    pub spendlink_risk_bps: u64,
    pub decoy_entropy_bps: u64,
    pub shield_score_bps: u64,
    pub shield_transcript_root: String,
    pub mitigation_plan_root: String,
    pub status: BucketStatus,
}

impl SpendlinkShieldScore {
    pub fn public_record(&self) -> Value {
        json!({
            "score_id": self.score_id,
            "bucket_id": self.bucket_id,
            "ring_size": self.ring_size,
            "scan_bucket_count": self.scan_bucket_count,
            "viewtag_collision_bps": self.viewtag_collision_bps,
            "spendlink_risk_bps": self.spendlink_risk_bps,
            "decoy_entropy_bps": self.decoy_entropy_bps,
            "shield_score_bps": self.shield_score_bps,
            "shield_transcript_root": self.shield_transcript_root,
            "mitigation_plan_root": self.mitigation_plan_root,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("spendlink-shield-score", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecoyEntropyFloor {
    pub floor_id: String,
    pub bucket_id: String,
    pub lane: RuntimeLane,
    pub ring_size: u16,
    pub output_count_bucket: u64,
    pub min_entropy_bps: u64,
    pub observed_entropy_bps: u64,
    pub decoy_distribution_root: String,
    pub replacement_queue_root: String,
    pub status: BucketStatus,
}

impl DecoyEntropyFloor {
    pub fn public_record(&self) -> Value {
        json!({
            "floor_id": self.floor_id,
            "bucket_id": self.bucket_id,
            "lane": self.lane.as_str(),
            "ring_size": self.ring_size,
            "output_count_bucket": self.output_count_bucket,
            "min_entropy_bps": self.min_entropy_bps,
            "observed_entropy_bps": self.observed_entropy_bps,
            "decoy_distribution_root": self.decoy_distribution_root,
            "replacement_queue_root": self.replacement_queue_root,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("decoy-entropy-floor", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StealthNoteFreshness {
    pub freshness_id: String,
    pub bucket_id: String,
    pub note_epoch: u64,
    pub newest_height_bucket: u64,
    pub oldest_height_bucket: u64,
    pub freshness_bps: u64,
    pub stale_note_bucket: u64,
    pub stealth_note_commitment_root: String,
    pub refresh_receipt_root: String,
    pub status: BucketStatus,
}

impl StealthNoteFreshness {
    pub fn public_record(&self) -> Value {
        json!({
            "freshness_id": self.freshness_id,
            "bucket_id": self.bucket_id,
            "note_epoch": self.note_epoch,
            "newest_height_bucket": self.newest_height_bucket,
            "oldest_height_bucket": self.oldest_height_bucket,
            "freshness_bps": self.freshness_bps,
            "stale_note_bucket": self.stale_note_bucket,
            "stealth_note_commitment_root": self.stealth_note_commitment_root,
            "refresh_receipt_root": self.refresh_receipt_root,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("stealth-note-freshness", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OutputAgeDiversity {
    pub diversity_id: String,
    pub bucket_id: String,
    pub young_output_bucket: u64,
    pub mature_output_bucket: u64,
    pub old_output_bucket: u64,
    pub age_diversity_bps: u64,
    pub age_histogram_root: String,
    pub decoy_age_mix_root: String,
    pub status: BucketStatus,
}

impl OutputAgeDiversity {
    pub fn public_record(&self) -> Value {
        json!({
            "diversity_id": self.diversity_id,
            "bucket_id": self.bucket_id,
            "young_output_bucket": self.young_output_bucket,
            "mature_output_bucket": self.mature_output_bucket,
            "old_output_bucket": self.old_output_bucket,
            "age_diversity_bps": self.age_diversity_bps,
            "age_histogram_root": self.age_histogram_root,
            "decoy_age_mix_root": self.decoy_age_mix_root,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("output-age-diversity", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqMigrationAttestation {
    pub attestation_id: String,
    pub bucket_id: String,
    pub era: PrivacyEra,
    pub signer_set_root: String,
    pub migration_plan_root: String,
    pub pq_security_bits: u16,
    pub classical_fallback_disabled: bool,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
    pub status: AttestationStatus,
}

impl PqMigrationAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "bucket_id": self.bucket_id,
            "era": self.era,
            "signer_set_root": self.signer_set_root,
            "migration_plan_root": self.migration_plan_root,
            "pq_security_bits": self.pq_security_bits,
            "classical_fallback_disabled": self.classical_fallback_disabled,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("pq-migration-attestation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanFeeSponsorship {
    pub sponsorship_id: String,
    pub bucket_id: String,
    pub sponsor_bucket: String,
    pub fee_asset_id: String,
    pub user_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub scan_units_bucket: u64,
    pub reserved_fee_bucket: u64,
    pub sponsor_receipt_root: String,
    pub settlement_root: String,
    pub expires_at_height: u64,
    pub status: SponsorshipStatus,
}

impl ScanFeeSponsorship {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsorship_id": self.sponsorship_id,
            "bucket_id": self.bucket_id,
            "sponsor_bucket": self.sponsor_bucket,
            "fee_asset_id": self.fee_asset_id,
            "user_fee_bps": self.user_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "scan_units_bucket": self.scan_units_bucket,
            "reserved_fee_bucket": self.reserved_fee_bucket,
            "sponsor_receipt_root": self.sponsor_receipt_root,
            "settlement_root": self.settlement_root,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("scan-fee-sponsorship", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeAudit {
    pub audit_id: String,
    pub bucket_id: String,
    pub sponsorship_id: String,
    pub measured_user_fee_bps: u64,
    pub target_user_fee_bps: u64,
    pub subsidy_efficiency_bps: u64,
    pub sponsor_settlement_delay_blocks: u64,
    pub fee_sample_root: String,
    pub audit_evidence_root: String,
    pub status: AuditStatus,
}

impl LowFeeAudit {
    pub fn public_record(&self) -> Value {
        json!({
            "audit_id": self.audit_id,
            "bucket_id": self.bucket_id,
            "sponsorship_id": self.sponsorship_id,
            "measured_user_fee_bps": self.measured_user_fee_bps,
            "target_user_fee_bps": self.target_user_fee_bps,
            "subsidy_efficiency_bps": self.subsidy_efficiency_bps,
            "sponsor_settlement_delay_blocks": self.sponsor_settlement_delay_blocks,
            "fee_sample_root": self.fee_sample_root,
            "audit_evidence_root": self.audit_evidence_root,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("low-fee-audit", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RootsOnlyPublicRecord {
    pub record_id: String,
    pub audience: PublicAudience,
    pub epoch: u64,
    pub bucket_count: u64,
    pub aggregate_privacy_score_bps: u64,
    pub roots: Roots,
    pub summary_root: String,
}

impl RootsOnlyPublicRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "audience": self.audience,
            "epoch": self.epoch,
            "bucket_count": self.bucket_count,
            "aggregate_privacy_score_bps": self.aggregate_privacy_score_bps,
            "roots": self.roots.public_record(),
            "summary_root": self.summary_root,
            "privacy_boundary": PRIVACY_BOUNDARY,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("roots-only-public-record", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub protocol_version: String,
    pub chain_id: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub viewtag_scan_buckets: BTreeMap<String, ViewtagScanBucket>,
    pub spendlink_shield_scores: BTreeMap<String, SpendlinkShieldScore>,
    pub decoy_entropy_floors: BTreeMap<String, DecoyEntropyFloor>,
    pub stealth_note_freshness_reports: BTreeMap<String, StealthNoteFreshness>,
    pub output_age_diversity_reports: BTreeMap<String, OutputAgeDiversity>,
    pub pq_migration_attestations: BTreeMap<String, PqMigrationAttestation>,
    pub scan_fee_sponsorships: BTreeMap<String, ScanFeeSponsorship>,
    pub low_fee_audits: BTreeMap<String, LowFeeAudit>,
    pub public_records: BTreeMap<String, RootsOnlyPublicRecord>,
    pub quarantined_ids: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default()).expect("default config is valid")
    }
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            protocol_version: config.protocol_version.clone(),
            chain_id: config.chain_id.clone(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            epoch: DEVNET_EPOCH,
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            viewtag_scan_buckets: BTreeMap::new(),
            spendlink_shield_scores: BTreeMap::new(),
            decoy_entropy_floors: BTreeMap::new(),
            stealth_note_freshness_reports: BTreeMap::new(),
            output_age_diversity_reports: BTreeMap::new(),
            pq_migration_attestations: BTreeMap::new(),
            scan_fee_sponsorships: BTreeMap::new(),
            low_fee_audits: BTreeMap::new(),
            public_records: BTreeMap::new(),
            quarantined_ids: BTreeSet::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("devnet config is valid");
        state.seed_devnet();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "privacy_boundary": PRIVACY_BOUNDARY,
            "public_record_scheme": PUBLIC_RECORD_SCHEME,
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn insert_viewtag_scan_bucket(&mut self, bucket: ViewtagScanBucket) -> Result<()> {
        ensure(!bucket.bucket_id.is_empty(), "bucket id is required")?;
        ensure(
            bucket.output_count_bucket >= self.config.min_bucket_outputs,
            "scan bucket output count is below privacy floor",
        )?;
        ensure(
            bucket.scan_unit_bucket <= self.config.max_scan_units_per_bucket,
            "scan bucket exceeds scan-unit cap",
        )?;
        ensure(
            bucket.expires_at_monero_height >= self.monero_height,
            "scan bucket is already expired",
        )?;
        self.viewtag_scan_buckets
            .insert(bucket.bucket_id.clone(), bucket);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_spendlink_shield_score(&mut self, score: SpendlinkShieldScore) -> Result<()> {
        ensure(
            self.viewtag_scan_buckets.contains_key(&score.bucket_id),
            "spendlink score references unknown scan bucket",
        )?;
        ensure(
            score.ring_size >= self.config.min_ring_size,
            "ring size is below configured floor",
        )?;
        ensure(
            score.scan_bucket_count >= self.config.min_scan_buckets,
            "scan bucket count is below unlinkability floor",
        )?;
        ensure(
            score.shield_score_bps >= self.config.min_spendlink_shield_bps,
            "spendlink shield score is below floor",
        )?;
        ensure(
            score.shield_score_bps <= MAX_BPS,
            "shield score exceeds max bps",
        )?;
        self.spendlink_shield_scores
            .insert(score.score_id.clone(), score);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_decoy_entropy_floor(&mut self, floor: DecoyEntropyFloor) -> Result<()> {
        ensure(
            self.viewtag_scan_buckets.contains_key(&floor.bucket_id),
            "decoy entropy floor references unknown scan bucket",
        )?;
        ensure(
            floor.ring_size >= self.config.min_ring_size,
            "decoy entropy floor ring size is below configured floor",
        )?;
        ensure(
            floor.observed_entropy_bps >= self.config.min_decoy_entropy_bps,
            "observed decoy entropy is below floor",
        )?;
        ensure(
            floor.observed_entropy_bps >= floor.min_entropy_bps,
            "observed decoy entropy does not cover declared floor",
        )?;
        self.decoy_entropy_floors
            .insert(floor.floor_id.clone(), floor);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_stealth_note_freshness(&mut self, freshness: StealthNoteFreshness) -> Result<()> {
        ensure(
            self.viewtag_scan_buckets.contains_key(&freshness.bucket_id),
            "freshness report references unknown scan bucket",
        )?;
        ensure(
            freshness.freshness_bps >= self.config.min_freshness_bps,
            "stealth-note freshness is below floor",
        )?;
        ensure(
            freshness.newest_height_bucket >= freshness.oldest_height_bucket,
            "freshness height buckets are inverted",
        )?;
        self.stealth_note_freshness_reports
            .insert(freshness.freshness_id.clone(), freshness);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_output_age_diversity(&mut self, diversity: OutputAgeDiversity) -> Result<()> {
        ensure(
            self.viewtag_scan_buckets.contains_key(&diversity.bucket_id),
            "age diversity report references unknown scan bucket",
        )?;
        ensure(
            diversity.age_diversity_bps >= self.config.min_age_diversity_bps,
            "output age diversity is below floor",
        )?;
        ensure(
            diversity.young_output_bucket > 0
                && diversity.mature_output_bucket > 0
                && diversity.old_output_bucket > 0,
            "age diversity requires young, mature, and old output buckets",
        )?;
        self.output_age_diversity_reports
            .insert(diversity.diversity_id.clone(), diversity);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_pq_migration_attestation(
        &mut self,
        attestation: PqMigrationAttestation,
    ) -> Result<()> {
        ensure(
            self.viewtag_scan_buckets
                .contains_key(&attestation.bucket_id),
            "PQ attestation references unknown scan bucket",
        )?;
        ensure(
            attestation.pq_security_bits >= self.config.min_pq_security_bits,
            "PQ attestation security is below floor",
        )?;
        ensure(
            attestation.classical_fallback_disabled,
            "PQ migration attestation must disable classical fallback",
        )?;
        ensure(
            attestation.expires_at_height >= self.monero_height,
            "PQ migration attestation is expired",
        )?;
        self.pq_migration_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_scan_fee_sponsorship(&mut self, sponsorship: ScanFeeSponsorship) -> Result<()> {
        ensure(
            self.viewtag_scan_buckets
                .contains_key(&sponsorship.bucket_id),
            "scan sponsorship references unknown scan bucket",
        )?;
        ensure(
            sponsorship.fee_asset_id == self.config.fee_asset_id,
            "scan sponsorship uses unsupported fee asset",
        )?;
        ensure(
            sponsorship.user_fee_bps <= self.config.max_user_fee_bps,
            "sponsored scan user fee exceeds cap",
        )?;
        ensure(
            sponsorship.sponsor_cover_bps >= self.config.target_sponsor_cover_bps,
            "scan sponsorship cover is below target",
        )?;
        ensure(
            sponsorship.scan_units_bucket <= self.config.max_scan_units_per_bucket,
            "scan sponsorship exceeds per-bucket scan unit cap",
        )?;
        self.ensure_epoch_sponsor_capacity(sponsorship.scan_units_bucket)?;
        self.scan_fee_sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_low_fee_audit(&mut self, audit: LowFeeAudit) -> Result<()> {
        ensure(
            self.viewtag_scan_buckets.contains_key(&audit.bucket_id),
            "low-fee audit references unknown scan bucket",
        )?;
        ensure(
            self.scan_fee_sponsorships
                .contains_key(&audit.sponsorship_id),
            "low-fee audit references unknown sponsorship",
        )?;
        ensure(
            audit.measured_user_fee_bps <= audit.target_user_fee_bps,
            "measured user fee exceeds target",
        )?;
        ensure(
            audit.subsidy_efficiency_bps <= MAX_BPS,
            "subsidy efficiency exceeds max bps",
        )?;
        self.low_fee_audits.insert(audit.audit_id.clone(), audit);
        self.refresh_roots();
        Ok(())
    }

    pub fn publish_roots_only_record(
        &mut self,
        record_id: impl Into<String>,
        audience: PublicAudience,
    ) -> Result<String> {
        self.refresh_roots();
        let record_id = record_id.into();
        ensure(!record_id.is_empty(), "public record id is required")?;
        let record = RootsOnlyPublicRecord {
            record_id: record_id.clone(),
            audience,
            epoch: self.epoch,
            bucket_count: self.viewtag_scan_buckets.len() as u64,
            aggregate_privacy_score_bps: self.aggregate_privacy_score_bps(),
            roots: self.roots.clone(),
            summary_root: root_from_parts(
                "public-record-summary",
                &[
                    HashPart::Str(&record_id),
                    HashPart::U64(self.epoch),
                    HashPart::Str(&self.roots.state_root),
                ],
            ),
        };
        let root = record.state_root();
        self.public_records.insert(record_id, record);
        self.refresh_roots();
        Ok(root)
    }

    pub fn quarantine(&mut self, id: impl Into<String>) {
        self.quarantined_ids.insert(id.into());
        self.refresh_roots();
    }

    pub fn refresh_roots(&mut self) {
        self.counters.viewtag_scan_buckets = self.viewtag_scan_buckets.len() as u64;
        self.counters.spendlink_shield_scores = self.spendlink_shield_scores.len() as u64;
        self.counters.decoy_entropy_floors = self.decoy_entropy_floors.len() as u64;
        self.counters.stealth_note_freshness_reports =
            self.stealth_note_freshness_reports.len() as u64;
        self.counters.output_age_diversity_reports = self.output_age_diversity_reports.len() as u64;
        self.counters.pq_migration_attestations = self.pq_migration_attestations.len() as u64;
        self.counters.scan_fee_sponsorships = self.scan_fee_sponsorships.len() as u64;
        self.counters.low_fee_audits = self.low_fee_audits.len() as u64;
        self.counters.public_records = self.public_records.len() as u64;
        self.counters.quarantined_items = self.quarantined_ids.len() as u64;
        self.roots.config_root = self.config.state_root();
        self.roots.counters_root = self.counters.state_root();
        self.roots.viewtag_scan_bucket_root = map_root(
            VIEWTAG_SCAN_BUCKET_SCHEME,
            self.viewtag_scan_buckets
                .iter()
                .map(|(id, item)| (id.as_str(), item.state_root())),
        );
        self.roots.spendlink_shield_score_root = map_root(
            SPENDLINK_SHIELD_SCHEME,
            self.spendlink_shield_scores
                .iter()
                .map(|(id, item)| (id.as_str(), item.state_root())),
        );
        self.roots.decoy_entropy_floor_root = map_root(
            DECOY_ENTROPY_FLOOR_SCHEME,
            self.decoy_entropy_floors
                .iter()
                .map(|(id, item)| (id.as_str(), item.state_root())),
        );
        self.roots.stealth_note_freshness_root = map_root(
            STEALTH_NOTE_FRESHNESS_SCHEME,
            self.stealth_note_freshness_reports
                .iter()
                .map(|(id, item)| (id.as_str(), item.state_root())),
        );
        self.roots.output_age_diversity_root = map_root(
            OUTPUT_AGE_DIVERSITY_SCHEME,
            self.output_age_diversity_reports
                .iter()
                .map(|(id, item)| (id.as_str(), item.state_root())),
        );
        self.roots.pq_migration_attestation_root = map_root(
            PQ_MIGRATION_ATTESTATION_SCHEME,
            self.pq_migration_attestations
                .iter()
                .map(|(id, item)| (id.as_str(), item.state_root())),
        );
        self.roots.scan_fee_sponsorship_root = map_root(
            SCAN_FEE_SPONSORSHIP_SCHEME,
            self.scan_fee_sponsorships
                .iter()
                .map(|(id, item)| (id.as_str(), item.state_root())),
        );
        self.roots.low_fee_audit_root = map_root(
            LOW_FEE_AUDIT_SCHEME,
            self.low_fee_audits
                .iter()
                .map(|(id, item)| (id.as_str(), item.state_root())),
        );
        self.roots.roots_only_public_record_root = map_root(
            PUBLIC_RECORD_SCHEME,
            self.public_records
                .iter()
                .map(|(id, item)| (id.as_str(), item.state_root())),
        );
        self.roots.state_root = self.state_root_without_cached_root();
    }

    fn aggregate_privacy_score_bps(&self) -> u64 {
        let score_total: u64 = self
            .spendlink_shield_scores
            .values()
            .map(|score| score.shield_score_bps)
            .sum();
        let entropy_total: u64 = self
            .decoy_entropy_floors
            .values()
            .map(|floor| floor.observed_entropy_bps)
            .sum();
        let freshness_total: u64 = self
            .stealth_note_freshness_reports
            .values()
            .map(|freshness| freshness.freshness_bps)
            .sum();
        let diversity_total: u64 = self
            .output_age_diversity_reports
            .values()
            .map(|diversity| diversity.age_diversity_bps)
            .sum();
        let count = self.spendlink_shield_scores.len()
            + self.decoy_entropy_floors.len()
            + self.stealth_note_freshness_reports.len()
            + self.output_age_diversity_reports.len();
        if count == 0 {
            0
        } else {
            score_total
                .saturating_add(entropy_total)
                .saturating_add(freshness_total)
                .saturating_add(diversity_total)
                .saturating_div(count as u64)
                .min(MAX_BPS)
        }
    }

    fn ensure_epoch_sponsor_capacity(&self, new_units: u64) -> Result<()> {
        let used_units = self
            .scan_fee_sponsorships
            .values()
            .filter(|item| {
                matches!(
                    item.status,
                    SponsorshipStatus::Open
                        | SponsorshipStatus::Reserved
                        | SponsorshipStatus::Netting
                        | SponsorshipStatus::Paid
                )
            })
            .map(|item| item.scan_units_bucket)
            .sum::<u64>();
        ensure(
            used_units.saturating_add(new_units) <= self.config.max_sponsor_units_per_epoch,
            "scan sponsorship epoch capacity exhausted",
        )
    }

    fn state_root_without_cached_root(&self) -> String {
        root_from_parts(
            "state",
            &[
                HashPart::Str(&self.protocol_version),
                HashPart::Str(&self.chain_id),
                HashPart::U64(self.l2_height),
                HashPart::U64(self.monero_height),
                HashPart::U64(self.epoch),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.counters.state_root()),
                HashPart::Json(&self.roots.without_state_root()),
            ],
        )
    }

    fn seed_devnet(&mut self) {
        let bucket_id = "viewtag-spendlink-entropy-bucket-devnet-0".to_string();
        let score_id = "viewtag-spendlink-shield-score-devnet-0".to_string();
        let sponsorship_id = "viewtag-scan-sponsorship-devnet-0".to_string();
        self.insert_viewtag_scan_bucket(ViewtagScanBucket {
            bucket_id: bucket_id.clone(),
            lane: RuntimeLane::BridgeWithdrawal,
            era: PrivacyEra::DualStack,
            epoch: self.epoch,
            l2_height_bucket: bucket(self.l2_height, self.config.public_bucket_size),
            monero_height_bucket: bucket(self.monero_height, self.config.public_bucket_size),
            output_count_bucket: self.config.target_bucket_outputs,
            scan_unit_bucket: 2_048,
            viewtag_bucket_root: root_from_parts("devnet-viewtag-bucket", &[HashPart::Str("0")]),
            jamtis_scan_hint_root: root_from_parts(
                "devnet-jamtis-scan-hint",
                &[HashPart::Str("0")],
            ),
            seraphis_membership_root: root_from_parts(
                "devnet-seraphis-membership",
                &[HashPart::Str(&bucket_id)],
            ),
            roots_only_receipt_root: root_from_parts(
                "devnet-roots-only-receipt",
                &[HashPart::Str(&bucket_id)],
            ),
            expires_at_monero_height: self.monero_height + self.config.scan_bucket_ttl_blocks,
            status: BucketStatus::Open,
        })
        .expect("devnet scan bucket inserts");
        self.insert_spendlink_shield_score(SpendlinkShieldScore {
            score_id: score_id.clone(),
            bucket_id: bucket_id.clone(),
            ring_size: self.config.target_ring_size,
            scan_bucket_count: self.config.min_scan_buckets,
            viewtag_collision_bps: 84,
            spendlink_risk_bps: 420,
            decoy_entropy_bps: 9_240,
            shield_score_bps: spendlink_shield_score(
                84,
                420,
                9_240,
                self.config.target_ring_size,
                self.config.target_ring_size,
            ),
            shield_transcript_root: root_from_parts(
                "devnet-shield-transcript",
                &[HashPart::Str(&score_id)],
            ),
            mitigation_plan_root: root_from_parts(
                "devnet-shield-mitigation",
                &[HashPart::Str(&score_id)],
            ),
            status: BucketStatus::ShieldScored,
        })
        .expect("devnet shield score inserts");
        self.insert_decoy_entropy_floor(DecoyEntropyFloor {
            floor_id: "viewtag-decoy-entropy-floor-devnet-0".to_string(),
            bucket_id: bucket_id.clone(),
            lane: RuntimeLane::BridgeWithdrawal,
            ring_size: self.config.target_ring_size,
            output_count_bucket: self.config.target_bucket_outputs,
            min_entropy_bps: self.config.min_decoy_entropy_bps,
            observed_entropy_bps: 9_240,
            decoy_distribution_root: root_from_parts(
                "devnet-decoy-distribution",
                &[HashPart::Str(&bucket_id)],
            ),
            replacement_queue_root: root_from_parts(
                "devnet-decoy-replacement",
                &[HashPart::Str(&bucket_id)],
            ),
            status: BucketStatus::EntropyChecked,
        })
        .expect("devnet decoy entropy floor inserts");
        self.insert_stealth_note_freshness(StealthNoteFreshness {
            freshness_id: "stealth-note-freshness-devnet-0".to_string(),
            bucket_id: bucket_id.clone(),
            note_epoch: self.epoch,
            newest_height_bucket: bucket(self.monero_height, self.config.public_bucket_size),
            oldest_height_bucket: bucket(
                self.monero_height - 4_096,
                self.config.public_bucket_size,
            ),
            freshness_bps: 8_840,
            stale_note_bucket: 128,
            stealth_note_commitment_root: root_from_parts(
                "devnet-stealth-note-commitments",
                &[HashPart::Str(&bucket_id)],
            ),
            refresh_receipt_root: root_from_parts(
                "devnet-stealth-note-refresh",
                &[HashPart::Str(&bucket_id)],
            ),
            status: BucketStatus::FreshnessChecked,
        })
        .expect("devnet freshness inserts");
        self.insert_output_age_diversity(OutputAgeDiversity {
            diversity_id: "output-age-diversity-devnet-0".to_string(),
            bucket_id: bucket_id.clone(),
            young_output_bucket: 65_536,
            mature_output_bucket: 131_072,
            old_output_bucket: 65_536,
            age_diversity_bps: 8_720,
            age_histogram_root: root_from_parts(
                "devnet-age-histogram",
                &[HashPart::Str(&bucket_id)],
            ),
            decoy_age_mix_root: root_from_parts("devnet-age-mix", &[HashPart::Str(&bucket_id)]),
            status: BucketStatus::AgeDiverse,
        })
        .expect("devnet age diversity inserts");
        self.insert_pq_migration_attestation(PqMigrationAttestation {
            attestation_id: "pq-migration-attestation-devnet-0".to_string(),
            bucket_id: bucket_id.clone(),
            era: PrivacyEra::DualStack,
            signer_set_root: root_from_parts("devnet-pq-signers", &[HashPart::Str("0")]),
            migration_plan_root: root_from_parts(
                "devnet-migration-plan",
                &[HashPart::Str(&bucket_id)],
            ),
            pq_security_bits: self.config.target_pq_security_bits,
            classical_fallback_disabled: true,
            attested_at_height: self.monero_height,
            expires_at_height: self.monero_height + self.config.attestation_ttl_blocks,
            status: AttestationStatus::StrongQuorum,
        })
        .expect("devnet PQ migration attestation inserts");
        self.insert_scan_fee_sponsorship(ScanFeeSponsorship {
            sponsorship_id: sponsorship_id.clone(),
            bucket_id: bucket_id.clone(),
            sponsor_bucket: "devnet-sponsor-bucket-0".to_string(),
            fee_asset_id: self.config.fee_asset_id.clone(),
            user_fee_bps: self.config.max_user_fee_bps,
            sponsor_cover_bps: self.config.target_sponsor_cover_bps,
            scan_units_bucket: 2_048,
            reserved_fee_bucket: 16,
            sponsor_receipt_root: root_from_parts(
                "devnet-sponsor-receipt",
                &[HashPart::Str(&sponsorship_id)],
            ),
            settlement_root: root_from_parts(
                "devnet-sponsor-settlement",
                &[HashPart::Str(&sponsorship_id)],
            ),
            expires_at_height: self.monero_height + self.config.sponsorship_ttl_blocks,
            status: SponsorshipStatus::Paid,
        })
        .expect("devnet scan sponsorship inserts");
        self.insert_low_fee_audit(LowFeeAudit {
            audit_id: "low-fee-audit-devnet-0".to_string(),
            bucket_id,
            sponsorship_id,
            measured_user_fee_bps: 4,
            target_user_fee_bps: self.config.max_user_fee_bps,
            subsidy_efficiency_bps: 9_100,
            sponsor_settlement_delay_blocks: 12,
            fee_sample_root: root_from_parts("devnet-fee-samples", &[HashPart::Str("0")]),
            audit_evidence_root: root_from_parts("devnet-fee-audit", &[HashPart::Str("0")]),
            status: AuditStatus::Published,
        })
        .expect("devnet low fee audit inserts");
        self.publish_roots_only_record("roots-only-public-record-devnet-0", PublicAudience::Public)
            .expect("devnet public record publishes");
        self.refresh_roots();
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn bucket(value: u64, bucket_size: u64) -> u64 {
    if bucket_size == 0 {
        value
    } else {
        (value / bucket_size) * bucket_size
    }
}

fn spendlink_shield_score(
    viewtag_collision_bps: u64,
    spendlink_risk_bps: u64,
    decoy_entropy_bps: u64,
    ring_size: u16,
    target_ring_size: u16,
) -> u64 {
    let ring_component = (ring_size as u64)
        .saturating_mul(MAX_BPS)
        .saturating_div(target_ring_size.max(1) as u64)
        .min(MAX_BPS);
    let risk_penalty = viewtag_collision_bps
        .saturating_div(2)
        .saturating_add(spendlink_risk_bps);
    decoy_entropy_bps
        .saturating_mul(65)
        .saturating_add(ring_component.saturating_mul(35))
        .saturating_div(100)
        .saturating_sub(risk_penalty.min(MAX_BPS))
        .min(MAX_BPS)
}

fn root_from_record(domain: &str, record: &Value) -> String {
    root_from_parts(domain, &[HashPart::Json(record)])
}

fn root_from_parts(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("SERAPHIS-JAMTIS-VIEWTAG-SPENDLINK-ENTROPY-{domain}"),
        parts,
        32,
    )
}

fn map_root<'a>(domain: &str, entries: impl Iterator<Item = (&'a str, String)>) -> String {
    let leaves = entries
        .map(|(id, root)| json!({ "id": id, "root": root }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("SERAPHIS-JAMTIS-VIEWTAG-SPENDLINK-ENTROPY-{domain}"),
        &leaves,
    )
}
