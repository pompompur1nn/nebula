use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateJamtisSeraphisSpendlinkDecoyRefreshRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_JAMTIS_SERAPHIS_SPENDLINK_DECOY_REFRESH_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-private-jamtis-seraphis-spendlink-decoy-refresh-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_JAMTIS_SERAPHIS_SPENDLINK_DECOY_REFRESH_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_128_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_792_000;
pub const DEVNET_EPOCH: u64 = 16_960;
pub const VIEWTAG_SCAN_BUCKET_SCHEME: &str = "jamtis-seraphis-viewtag-scan-bucket-root-v1";
pub const SPENDLINK_SHIELD_REFRESH_SCHEME: &str =
    "jamtis-seraphis-spendlink-shield-refresh-score-root-v1";
pub const DECOY_ENTROPY_FLOOR_SCHEME: &str = "monero-l2-decoy-entropy-floor-root-v1";
pub const STEALTH_NOTE_FRESHNESS_SCHEME: &str = "jamtis-seraphis-stealth-note-freshness-root-v1";
pub const OUTPUT_AGE_DIVERSITY_SCHEME: &str = "monero-output-age-diversity-refresh-root-v1";
pub const PQ_MIGRATION_ATTESTATION_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-jamtis-seraphis-spendlink-refresh-attestation-v1";
pub const SCAN_FEE_SPONSORSHIP_SCHEME: &str = "low-fee-viewtag-scan-sponsorship-root-v1";
pub const REFRESH_NULLIFIER_SCHEME: &str = "jamtis-seraphis-refresh-nullifier-root-v1";
pub const LOW_FEE_AUDIT_SCHEME: &str = "low-fee-spendlink-decoy-refresh-audit-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "roots-only-jamtis-seraphis-spendlink-decoy-refresh-public-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_addresses_view_keys_key_images_amounts_output_indices_ring_witnesses_viewtags_spendlinks_or_refresh_graphs";
pub const STATE_ROOT_DOMAIN: &str =
    "MONERO-L2-PQ-PRIVATE-JAMTIS-SERAPHIS-SPENDLINK-DECOY-REFRESH-STATE";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_RING_SIZE: u16 = 16;
pub const DEFAULT_TARGET_RING_SIZE: u16 = 96;
pub const DEFAULT_MIN_SCAN_BUCKET_OUTPUTS: u64 = 65_536;
pub const DEFAULT_TARGET_SCAN_BUCKET_OUTPUTS: u64 = 524_288;
pub const DEFAULT_MIN_BUCKET_COUNT: u64 = 8;
pub const DEFAULT_MIN_DECOY_ENTROPY_BPS: u64 = 8_700;
pub const DEFAULT_MIN_SPENDLINK_SHIELD_BPS: u64 = 8_650;
pub const DEFAULT_MIN_STEALTH_NOTE_FRESHNESS_BPS: u64 = 7_950;
pub const DEFAULT_MIN_OUTPUT_AGE_DIVERSITY_BPS: u64 = 7_850;
pub const DEFAULT_MIN_REFRESH_SCORE_BPS: u64 = 8_500;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_SCAN_BUCKET_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_REFRESH_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_SPONSORSHIP_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_MAX_USER_SCAN_FEE_BPS: u64 = 6;
pub const DEFAULT_TARGET_SPONSOR_COVER_BPS: u64 = 9_400;
pub const DEFAULT_MAX_SCAN_UNITS_PER_BUCKET: u64 = 8_192;
pub const DEFAULT_MAX_REFRESHES_PER_EPOCH: u64 = 65_536;
pub const DEFAULT_PUBLIC_BUCKET_SIZE: u64 = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshLane {
    WalletScan,
    MerchantReceive,
    BridgeWithdrawal,
    DexSettlement,
    Watchtower,
    ReorgRepair,
    MigrationAudit,
    FeeSponsor,
    EmergencyPrivacy,
}

impl RefreshLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletScan => "wallet_scan",
            Self::MerchantReceive => "merchant_receive",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::DexSettlement => "dex_settlement",
            Self::Watchtower => "watchtower",
            Self::ReorgRepair => "reorg_repair",
            Self::MigrationAudit => "migration_audit",
            Self::FeeSponsor => "fee_sponsor",
            Self::EmergencyPrivacy => "emergency_privacy",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyPrivacy => 1_000,
            Self::ReorgRepair => 960,
            Self::BridgeWithdrawal => 930,
            Self::MigrationAudit => 900,
            Self::DexSettlement => 860,
            Self::MerchantReceive => 830,
            Self::Watchtower => 810,
            Self::FeeSponsor => 780,
            Self::WalletScan => 740,
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
    JamtisSeraphis,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketStatus {
    Draft,
    Open,
    IntakeClosed,
    Scanned,
    EntropyChecked,
    ShieldScored,
    FreshnessChecked,
    AgeDiverse,
    RefreshQueued,
    Attested,
    Sponsored,
    Nullified,
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
                | Self::RefreshQueued
                | Self::Attested
                | Self::Sponsored
                | Self::Audited
                | Self::Sealed
        )
    }

    pub fn accepts_refresh_work(self) -> bool {
        matches!(
            self,
            Self::Open
                | Self::IntakeClosed
                | Self::Scanned
                | Self::EntropyChecked
                | Self::ShieldScored
                | Self::FreshnessChecked
                | Self::AgeDiverse
                | Self::RefreshQueued
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShieldStatus {
    Draft,
    Candidate,
    Scored,
    RefreshRequired,
    Shielded,
    Regression,
    Rejected,
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
pub enum NullifierStatus {
    Reserved,
    Active,
    Spent,
    Challenged,
    Expired,
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
    pub spendlink_shield_refresh_scheme: String,
    pub decoy_entropy_floor_scheme: String,
    pub stealth_note_freshness_scheme: String,
    pub output_age_diversity_scheme: String,
    pub pq_migration_attestation_scheme: String,
    pub scan_fee_sponsorship_scheme: String,
    pub refresh_nullifier_scheme: String,
    pub low_fee_audit_scheme: String,
    pub public_record_scheme: String,
    pub privacy_boundary: String,
    pub min_ring_size: u16,
    pub target_ring_size: u16,
    pub min_scan_bucket_outputs: u64,
    pub target_scan_bucket_outputs: u64,
    pub min_bucket_count: u64,
    pub min_decoy_entropy_bps: u64,
    pub min_spendlink_shield_bps: u64,
    pub min_stealth_note_freshness_bps: u64,
    pub min_output_age_diversity_bps: u64,
    pub min_refresh_score_bps: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub scan_bucket_ttl_blocks: u64,
    pub refresh_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub sponsorship_ttl_blocks: u64,
    pub max_user_scan_fee_bps: u64,
    pub target_sponsor_cover_bps: u64,
    pub max_scan_units_per_bucket: u64,
    pub max_refreshes_per_epoch: u64,
    pub public_bucket_size: u64,
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
            spendlink_shield_refresh_scheme: SPENDLINK_SHIELD_REFRESH_SCHEME.to_string(),
            decoy_entropy_floor_scheme: DECOY_ENTROPY_FLOOR_SCHEME.to_string(),
            stealth_note_freshness_scheme: STEALTH_NOTE_FRESHNESS_SCHEME.to_string(),
            output_age_diversity_scheme: OUTPUT_AGE_DIVERSITY_SCHEME.to_string(),
            pq_migration_attestation_scheme: PQ_MIGRATION_ATTESTATION_SCHEME.to_string(),
            scan_fee_sponsorship_scheme: SCAN_FEE_SPONSORSHIP_SCHEME.to_string(),
            refresh_nullifier_scheme: REFRESH_NULLIFIER_SCHEME.to_string(),
            low_fee_audit_scheme: LOW_FEE_AUDIT_SCHEME.to_string(),
            public_record_scheme: PUBLIC_RECORD_SCHEME.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            min_ring_size: DEFAULT_MIN_RING_SIZE,
            target_ring_size: DEFAULT_TARGET_RING_SIZE,
            min_scan_bucket_outputs: DEFAULT_MIN_SCAN_BUCKET_OUTPUTS,
            target_scan_bucket_outputs: DEFAULT_TARGET_SCAN_BUCKET_OUTPUTS,
            min_bucket_count: DEFAULT_MIN_BUCKET_COUNT,
            min_decoy_entropy_bps: DEFAULT_MIN_DECOY_ENTROPY_BPS,
            min_spendlink_shield_bps: DEFAULT_MIN_SPENDLINK_SHIELD_BPS,
            min_stealth_note_freshness_bps: DEFAULT_MIN_STEALTH_NOTE_FRESHNESS_BPS,
            min_output_age_diversity_bps: DEFAULT_MIN_OUTPUT_AGE_DIVERSITY_BPS,
            min_refresh_score_bps: DEFAULT_MIN_REFRESH_SCORE_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            scan_bucket_ttl_blocks: DEFAULT_SCAN_BUCKET_TTL_BLOCKS,
            refresh_ttl_blocks: DEFAULT_REFRESH_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            sponsorship_ttl_blocks: DEFAULT_SPONSORSHIP_TTL_BLOCKS,
            max_user_scan_fee_bps: DEFAULT_MAX_USER_SCAN_FEE_BPS,
            target_sponsor_cover_bps: DEFAULT_TARGET_SPONSOR_COVER_BPS,
            max_scan_units_per_bucket: DEFAULT_MAX_SCAN_UNITS_PER_BUCKET,
            max_refreshes_per_epoch: DEFAULT_MAX_REFRESHES_PER_EPOCH,
            public_bucket_size: DEFAULT_PUBLIC_BUCKET_SIZE,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch",
        )?;
        ensure(
            self.schema_version == SCHEMA_VERSION,
            "schema version mismatch",
        )?;
        ensure(self.min_ring_size >= 16, "minimum ring size is too low")?;
        ensure(
            self.target_ring_size >= self.min_ring_size,
            "target ring size must cover minimum ring size",
        )?;
        ensure(
            self.target_scan_bucket_outputs >= self.min_scan_bucket_outputs,
            "target scan bucket outputs must cover minimum bucket outputs",
        )?;
        ensure(
            self.min_bucket_count > 0,
            "minimum bucket count must be non-zero",
        )?;
        ensure(
            self.min_decoy_entropy_bps <= MAX_BPS
                && self.min_spendlink_shield_bps <= MAX_BPS
                && self.min_stealth_note_freshness_bps <= MAX_BPS
                && self.min_output_age_diversity_bps <= MAX_BPS
                && self.min_refresh_score_bps <= MAX_BPS,
            "privacy thresholds exceed max bps",
        )?;
        ensure(
            self.target_pq_security_bits >= self.min_pq_security_bits,
            "target PQ security must cover minimum PQ security",
        )?;
        ensure(
            self.min_pq_security_bits >= 128,
            "PQ security floor is too low",
        )?;
        ensure(
            self.scan_bucket_ttl_blocks > 0,
            "scan bucket ttl must be non-zero",
        )?;
        ensure(self.refresh_ttl_blocks > 0, "refresh ttl must be non-zero")?;
        ensure(
            self.attestation_ttl_blocks > 0,
            "attestation ttl must be non-zero",
        )?;
        ensure(
            self.sponsorship_ttl_blocks > 0,
            "sponsorship ttl must be non-zero",
        )?;
        ensure(
            self.max_user_scan_fee_bps <= MAX_BPS,
            "user scan fee exceeds bound",
        )?;
        ensure(
            self.target_sponsor_cover_bps <= MAX_BPS,
            "sponsor cover exceeds max bps",
        )?;
        ensure(
            self.max_scan_units_per_bucket > 0,
            "scan unit cap must be non-zero",
        )?;
        ensure(
            self.max_refreshes_per_epoch > 0,
            "refresh cap must be non-zero",
        )?;
        ensure(
            self.public_bucket_size > 0,
            "public bucket size must be non-zero",
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
            "schemes": {
                "viewtag_scan_bucket": self.viewtag_scan_bucket_scheme,
                "spendlink_shield_refresh": self.spendlink_shield_refresh_scheme,
                "decoy_entropy_floor": self.decoy_entropy_floor_scheme,
                "stealth_note_freshness": self.stealth_note_freshness_scheme,
                "output_age_diversity": self.output_age_diversity_scheme,
                "pq_migration_attestation": self.pq_migration_attestation_scheme,
                "scan_fee_sponsorship": self.scan_fee_sponsorship_scheme,
                "refresh_nullifier": self.refresh_nullifier_scheme,
                "low_fee_audit": self.low_fee_audit_scheme,
                "public_record": self.public_record_scheme,
            },
            "privacy_boundary": self.privacy_boundary,
            "min_ring_size": self.min_ring_size,
            "target_ring_size": self.target_ring_size,
            "min_scan_bucket_outputs": self.min_scan_bucket_outputs,
            "target_scan_bucket_outputs": self.target_scan_bucket_outputs,
            "min_bucket_count": self.min_bucket_count,
            "min_decoy_entropy_bps": self.min_decoy_entropy_bps,
            "min_spendlink_shield_bps": self.min_spendlink_shield_bps,
            "min_stealth_note_freshness_bps": self.min_stealth_note_freshness_bps,
            "min_output_age_diversity_bps": self.min_output_age_diversity_bps,
            "min_refresh_score_bps": self.min_refresh_score_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "scan_bucket_ttl_blocks": self.scan_bucket_ttl_blocks,
            "refresh_ttl_blocks": self.refresh_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "sponsorship_ttl_blocks": self.sponsorship_ttl_blocks,
            "max_user_scan_fee_bps": self.max_user_scan_fee_bps,
            "target_sponsor_cover_bps": self.target_sponsor_cover_bps,
            "max_scan_units_per_bucket": self.max_scan_units_per_bucket,
            "max_refreshes_per_epoch": self.max_refreshes_per_epoch,
            "public_bucket_size": self.public_bucket_size,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("config", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub viewtag_scan_buckets: u64,
    pub spendlink_shield_refreshes: u64,
    pub decoy_entropy_floors: u64,
    pub stealth_note_freshness_windows: u64,
    pub output_age_diversity_windows: u64,
    pub pq_migration_attestations: u64,
    pub scan_fee_sponsorships: u64,
    pub refresh_nullifiers: u64,
    pub low_fee_audits: u64,
    pub public_records: u64,
    pub quarantined_buckets: u64,
    pub rejected_refreshes: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub viewtag_scan_bucket_root: String,
    pub spendlink_shield_refresh_root: String,
    pub decoy_entropy_floor_root: String,
    pub stealth_note_freshness_root: String,
    pub output_age_diversity_root: String,
    pub pq_migration_attestation_root: String,
    pub scan_fee_sponsorship_root: String,
    pub refresh_nullifier_root: String,
    pub low_fee_audit_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            config_root: empty_root("config"),
            counters_root: empty_root("counters"),
            viewtag_scan_bucket_root: empty_root("viewtag-scan-buckets"),
            spendlink_shield_refresh_root: empty_root("spendlink-shield-refreshes"),
            decoy_entropy_floor_root: empty_root("decoy-entropy-floors"),
            stealth_note_freshness_root: empty_root("stealth-note-freshness"),
            output_age_diversity_root: empty_root("output-age-diversity"),
            pq_migration_attestation_root: empty_root("pq-migration-attestations"),
            scan_fee_sponsorship_root: empty_root("scan-fee-sponsorships"),
            refresh_nullifier_root: empty_root("refresh-nullifiers"),
            low_fee_audit_root: empty_root("low-fee-audits"),
            public_record_root: empty_root("public-records"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record("roots", &self.public_record())
    }
}

impl Default for Roots {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewtagScanBucket {
    pub bucket_id: String,
    pub lane: RefreshLane,
    pub era: PrivacyEra,
    pub epoch: u64,
    pub monero_height_bucket: u64,
    pub output_count_bucket: u64,
    pub viewtag_prefix_root: String,
    pub scan_hint_commitment_root: String,
    pub wallet_cohort_root: String,
    pub decoy_candidate_root: String,
    pub scan_units_bucket: u64,
    pub expires_at_height: u64,
    pub status: BucketStatus,
}

impl ViewtagScanBucket {
    pub fn validate(&self, config: &Config, monero_height: u64) -> Result<()> {
        ensure(!self.bucket_id.is_empty(), "scan bucket id is required")?;
        ensure(
            self.output_count_bucket >= config.min_scan_bucket_outputs,
            "scan bucket output count is below privacy floor",
        )?;
        ensure(
            self.scan_units_bucket <= config.max_scan_units_per_bucket,
            "scan bucket exceeds scan unit cap",
        )?;
        ensure(
            self.expires_at_height > monero_height,
            "scan bucket is already expired",
        )?;
        ensure(
            self.status.accepts_refresh_work(),
            "scan bucket does not accept refresh work",
        )?;
        Ok(())
    }

    pub fn public_record(&self, config: &Config) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "lane": self.lane,
            "lane_priority_weight": self.lane.priority_weight(),
            "era": self.era,
            "epoch": self.epoch,
            "monero_height_bucket": bucket(self.monero_height_bucket, config.public_bucket_size),
            "output_count_bucket": bucket(self.output_count_bucket, config.public_bucket_size),
            "viewtag_prefix_root": self.viewtag_prefix_root,
            "scan_hint_commitment_root": self.scan_hint_commitment_root,
            "wallet_cohort_root": self.wallet_cohort_root,
            "decoy_candidate_root": self.decoy_candidate_root,
            "scan_units_bucket": bucket(self.scan_units_bucket, config.public_bucket_size),
            "expires_at_height_bucket": bucket(self.expires_at_height, config.public_bucket_size),
            "status": self.status,
        })
    }

    pub fn state_root(&self, config: &Config) -> String {
        root_from_record("viewtag-scan-bucket", &self.public_record(config))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SpendlinkShieldRefresh {
    pub refresh_id: String,
    pub bucket_id: String,
    pub lane: RefreshLane,
    pub ring_size: u16,
    pub viewtag_collision_bps: u64,
    pub spendlink_risk_bps: u64,
    pub decoy_entropy_bps: u64,
    pub output_age_diversity_bps: u64,
    pub stealth_note_freshness_bps: u64,
    pub refresh_score_bps: u64,
    pub shield_commitment_root: String,
    pub replacement_decoy_root: String,
    pub status: ShieldStatus,
}

impl SpendlinkShieldRefresh {
    pub fn recompute_score(&self, config: &Config) -> u64 {
        spendlink_refresh_score(
            self.viewtag_collision_bps,
            self.spendlink_risk_bps,
            self.decoy_entropy_bps,
            self.output_age_diversity_bps,
            self.stealth_note_freshness_bps,
            self.ring_size,
            config.target_ring_size,
        )
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure(!self.refresh_id.is_empty(), "refresh id is required")?;
        ensure(!self.bucket_id.is_empty(), "refresh bucket id is required")?;
        ensure(
            self.ring_size >= config.min_ring_size,
            "ring size is below floor",
        )?;
        ensure(
            self.viewtag_collision_bps <= MAX_BPS,
            "viewtag collision bps exceeds bound",
        )?;
        ensure(
            self.spendlink_risk_bps <= MAX_BPS,
            "spendlink risk bps exceeds bound",
        )?;
        ensure(
            self.decoy_entropy_bps <= MAX_BPS,
            "decoy entropy bps exceeds bound",
        )?;
        ensure(
            self.output_age_diversity_bps <= MAX_BPS,
            "age diversity bps exceeds bound",
        )?;
        ensure(
            self.stealth_note_freshness_bps <= MAX_BPS,
            "stealth note freshness bps exceeds bound",
        )?;
        ensure(
            self.decoy_entropy_bps >= config.min_decoy_entropy_bps,
            "refresh decoy entropy is below floor",
        )?;
        ensure(
            self.output_age_diversity_bps >= config.min_output_age_diversity_bps,
            "refresh output age diversity is below floor",
        )?;
        ensure(
            self.stealth_note_freshness_bps >= config.min_stealth_note_freshness_bps,
            "refresh stealth note freshness is below floor",
        )?;
        ensure(
            self.refresh_score_bps >= config.min_refresh_score_bps,
            "spendlink refresh score is below floor",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "refresh_id": self.refresh_id,
            "bucket_id": self.bucket_id,
            "lane": self.lane,
            "lane_priority_weight": self.lane.priority_weight(),
            "ring_size": self.ring_size,
            "viewtag_collision_bps": self.viewtag_collision_bps,
            "spendlink_risk_bps": self.spendlink_risk_bps,
            "decoy_entropy_bps": self.decoy_entropy_bps,
            "output_age_diversity_bps": self.output_age_diversity_bps,
            "stealth_note_freshness_bps": self.stealth_note_freshness_bps,
            "refresh_score_bps": self.refresh_score_bps,
            "shield_commitment_root": self.shield_commitment_root,
            "replacement_decoy_root": self.replacement_decoy_root,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("spendlink-shield-refresh", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecoyEntropyFloor {
    pub floor_id: String,
    pub bucket_id: String,
    pub ring_size: u16,
    pub min_entropy_bps: u64,
    pub observed_entropy_bps: u64,
    pub decoy_source_count_bucket: u64,
    pub decoy_source_root: String,
    pub entropy_evidence_root: String,
    pub status: BucketStatus,
}

impl DecoyEntropyFloor {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure(
            !self.floor_id.is_empty(),
            "decoy entropy floor id is required",
        )?;
        ensure(
            self.ring_size >= config.min_ring_size,
            "entropy ring size below floor",
        )?;
        ensure(
            self.min_entropy_bps >= config.min_decoy_entropy_bps,
            "configured entropy floor too low",
        )?;
        ensure(
            self.observed_entropy_bps >= self.min_entropy_bps,
            "observed decoy entropy below floor",
        )?;
        ensure(
            self.observed_entropy_bps <= MAX_BPS,
            "observed entropy exceeds bound",
        )?;
        ensure(
            self.decoy_source_count_bucket > 0,
            "decoy source count bucket is empty",
        )?;
        Ok(())
    }

    pub fn public_record(&self, config: &Config) -> Value {
        json!({
            "floor_id": self.floor_id,
            "bucket_id": self.bucket_id,
            "ring_size": self.ring_size,
            "min_entropy_bps": self.min_entropy_bps,
            "observed_entropy_bps": self.observed_entropy_bps,
            "decoy_source_count_bucket": bucket(self.decoy_source_count_bucket, config.public_bucket_size),
            "decoy_source_root": self.decoy_source_root,
            "entropy_evidence_root": self.entropy_evidence_root,
            "status": self.status,
        })
    }

    pub fn state_root(&self, config: &Config) -> String {
        root_from_record("decoy-entropy-floor", &self.public_record(config))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StealthNoteFreshness {
    pub freshness_id: String,
    pub bucket_id: String,
    pub newest_height_bucket: u64,
    pub oldest_height_bucket: u64,
    pub freshness_bps: u64,
    pub stale_note_bucket: u64,
    pub note_commitment_root: String,
    pub refresh_receipt_root: String,
    pub status: BucketStatus,
}

impl StealthNoteFreshness {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure(!self.freshness_id.is_empty(), "freshness id is required")?;
        ensure(
            self.newest_height_bucket >= self.oldest_height_bucket,
            "freshness height buckets are inverted",
        )?;
        ensure(self.freshness_bps <= MAX_BPS, "freshness exceeds bound")?;
        ensure(
            self.freshness_bps >= config.min_stealth_note_freshness_bps,
            "stealth-note freshness is below floor",
        )?;
        Ok(())
    }

    pub fn public_record(&self, config: &Config) -> Value {
        json!({
            "freshness_id": self.freshness_id,
            "bucket_id": self.bucket_id,
            "newest_height_bucket": bucket(self.newest_height_bucket, config.public_bucket_size),
            "oldest_height_bucket": bucket(self.oldest_height_bucket, config.public_bucket_size),
            "freshness_bps": self.freshness_bps,
            "stale_note_bucket": bucket(self.stale_note_bucket, config.public_bucket_size),
            "note_commitment_root": self.note_commitment_root,
            "refresh_receipt_root": self.refresh_receipt_root,
            "status": self.status,
        })
    }

    pub fn state_root(&self, config: &Config) -> String {
        root_from_record("stealth-note-freshness", &self.public_record(config))
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
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure(
            !self.diversity_id.is_empty(),
            "age diversity id is required",
        )?;
        ensure(
            self.age_diversity_bps <= MAX_BPS,
            "age diversity exceeds bound",
        )?;
        ensure(
            self.age_diversity_bps >= config.min_output_age_diversity_bps,
            "output age diversity is below floor",
        )?;
        ensure(
            self.young_output_bucket > 0
                && self.mature_output_bucket > 0
                && self.old_output_bucket > 0,
            "age diversity requires young, mature, and old buckets",
        )?;
        Ok(())
    }

    pub fn total_output_bucket(&self) -> u64 {
        self.young_output_bucket
            .saturating_add(self.mature_output_bucket)
            .saturating_add(self.old_output_bucket)
    }

    pub fn public_record(&self, config: &Config) -> Value {
        json!({
            "diversity_id": self.diversity_id,
            "bucket_id": self.bucket_id,
            "young_output_bucket": bucket(self.young_output_bucket, config.public_bucket_size),
            "mature_output_bucket": bucket(self.mature_output_bucket, config.public_bucket_size),
            "old_output_bucket": bucket(self.old_output_bucket, config.public_bucket_size),
            "total_output_bucket": bucket(self.total_output_bucket(), config.public_bucket_size),
            "age_diversity_bps": self.age_diversity_bps,
            "age_histogram_root": self.age_histogram_root,
            "decoy_age_mix_root": self.decoy_age_mix_root,
            "status": self.status,
        })
    }

    pub fn state_root(&self, config: &Config) -> String {
        root_from_record("output-age-diversity", &self.public_record(config))
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
    pub fn validate(&self, config: &Config, monero_height: u64) -> Result<()> {
        ensure(
            !self.attestation_id.is_empty(),
            "attestation id is required",
        )?;
        ensure(
            self.status.counts_for_quorum(),
            "attestation does not count for quorum",
        )?;
        ensure(
            self.pq_security_bits >= config.min_pq_security_bits,
            "PQ security bits below migration floor",
        )?;
        ensure(
            self.classical_fallback_disabled,
            "classical fallback must be disabled for migration safety",
        )?;
        ensure(
            self.expires_at_height > monero_height,
            "PQ migration attestation is expired",
        )?;
        ensure(
            self.expires_at_height
                .saturating_sub(self.attested_at_height)
                <= config.attestation_ttl_blocks,
            "PQ migration attestation exceeds ttl",
        )?;
        Ok(())
    }

    pub fn public_record(&self, config: &Config) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "bucket_id": self.bucket_id,
            "era": self.era,
            "signer_set_root": self.signer_set_root,
            "migration_plan_root": self.migration_plan_root,
            "pq_security_bits": self.pq_security_bits,
            "classical_fallback_disabled": self.classical_fallback_disabled,
            "attested_at_height_bucket": bucket(self.attested_at_height, config.public_bucket_size),
            "expires_at_height_bucket": bucket(self.expires_at_height, config.public_bucket_size),
            "status": self.status,
        })
    }

    pub fn state_root(&self, config: &Config) -> String {
        root_from_record("pq-migration-attestation", &self.public_record(config))
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
    pub fn validate(&self, config: &Config, monero_height: u64) -> Result<()> {
        ensure(
            !self.sponsorship_id.is_empty(),
            "sponsorship id is required",
        )?;
        ensure(
            self.fee_asset_id == config.fee_asset_id,
            "fee asset mismatch",
        )?;
        ensure(
            self.user_fee_bps <= config.max_user_scan_fee_bps,
            "user scan fee exceeds cap",
        )?;
        ensure(
            self.sponsor_cover_bps >= config.target_sponsor_cover_bps,
            "sponsor cover below target",
        )?;
        ensure(
            self.sponsor_cover_bps <= MAX_BPS,
            "sponsor cover exceeds bound",
        )?;
        ensure(
            self.scan_units_bucket <= config.max_scan_units_per_bucket,
            "sponsored scan units exceed cap",
        )?;
        ensure(
            self.expires_at_height > monero_height,
            "sponsorship is expired",
        )?;
        Ok(())
    }

    pub fn public_record(&self, config: &Config) -> Value {
        json!({
            "sponsorship_id": self.sponsorship_id,
            "bucket_id": self.bucket_id,
            "sponsor_bucket": self.sponsor_bucket,
            "fee_asset_id": self.fee_asset_id,
            "user_fee_bps": self.user_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "scan_units_bucket": bucket(self.scan_units_bucket, config.public_bucket_size),
            "reserved_fee_bucket": bucket(self.reserved_fee_bucket, config.public_bucket_size),
            "sponsor_receipt_root": self.sponsor_receipt_root,
            "settlement_root": self.settlement_root,
            "expires_at_height_bucket": bucket(self.expires_at_height, config.public_bucket_size),
            "status": self.status,
        })
    }

    pub fn state_root(&self, config: &Config) -> String {
        root_from_record("scan-fee-sponsorship", &self.public_record(config))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RefreshNullifier {
    pub nullifier_id: String,
    pub bucket_id: String,
    pub refresh_id: String,
    pub nullifier_root: String,
    pub spent_refresh_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: NullifierStatus,
}

impl RefreshNullifier {
    pub fn validate(&self, config: &Config, monero_height: u64) -> Result<()> {
        ensure(!self.nullifier_id.is_empty(), "nullifier id is required")?;
        ensure(
            !self.refresh_id.is_empty(),
            "nullifier refresh id is required",
        )?;
        ensure(
            self.expires_at_height > monero_height,
            "refresh nullifier is expired",
        )?;
        ensure(
            self.expires_at_height
                .saturating_sub(self.created_at_height)
                <= config.refresh_ttl_blocks,
            "refresh nullifier exceeds refresh ttl",
        )?;
        Ok(())
    }

    pub fn public_record(&self, config: &Config) -> Value {
        json!({
            "nullifier_id": self.nullifier_id,
            "bucket_id": self.bucket_id,
            "refresh_id": self.refresh_id,
            "nullifier_root": self.nullifier_root,
            "spent_refresh_root": self.spent_refresh_root,
            "created_at_height_bucket": bucket(self.created_at_height, config.public_bucket_size),
            "expires_at_height_bucket": bucket(self.expires_at_height, config.public_bucket_size),
            "status": self.status,
        })
    }

    pub fn state_root(&self, config: &Config) -> String {
        root_from_record("refresh-nullifier", &self.public_record(config))
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
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure(!self.audit_id.is_empty(), "low-fee audit id is required")?;
        ensure(
            self.measured_user_fee_bps <= self.target_user_fee_bps,
            "measured fee exceeds audit target",
        )?;
        ensure(
            self.target_user_fee_bps <= config.max_user_scan_fee_bps,
            "audit target exceeds configured cap",
        )?;
        ensure(
            self.subsidy_efficiency_bps <= MAX_BPS,
            "subsidy efficiency exceeds bound",
        )?;
        ensure(
            self.status != AuditStatus::Failed,
            "failed low-fee audit cannot be inserted",
        )?;
        Ok(())
    }

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
    pub roots: Roots,
    pub privacy_boundary: String,
    pub published_at_l2_height: u64,
    pub published_at_monero_height_bucket: u64,
}

impl RootsOnlyPublicRecord {
    pub fn validate(&self) -> Result<()> {
        ensure(!self.record_id.is_empty(), "public record id is required")?;
        ensure(
            self.privacy_boundary == PRIVACY_BOUNDARY,
            "public record privacy boundary mismatch",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "audience": self.audience,
            "epoch": self.epoch,
            "roots": self.roots.public_record(),
            "privacy_boundary": self.privacy_boundary,
            "published_at_l2_height": self.published_at_l2_height,
            "published_at_monero_height_bucket": self.published_at_monero_height_bucket,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("roots-only-public-record", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub viewtag_scan_buckets: BTreeMap<String, ViewtagScanBucket>,
    pub spendlink_shield_refreshes: BTreeMap<String, SpendlinkShieldRefresh>,
    pub decoy_entropy_floors: BTreeMap<String, DecoyEntropyFloor>,
    pub stealth_note_freshness: BTreeMap<String, StealthNoteFreshness>,
    pub output_age_diversity: BTreeMap<String, OutputAgeDiversity>,
    pub pq_migration_attestations: BTreeMap<String, PqMigrationAttestation>,
    pub scan_fee_sponsorships: BTreeMap<String, ScanFeeSponsorship>,
    pub refresh_nullifiers: BTreeMap<String, RefreshNullifier>,
    pub low_fee_audits: BTreeMap<String, LowFeeAudit>,
    pub public_records: BTreeMap<String, RootsOnlyPublicRecord>,
    pub quarantined_bucket_ids: BTreeSet<String>,
    pub used_refresh_nullifier_ids: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config, l2_height: u64, monero_height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::empty(),
            l2_height,
            monero_height,
            epoch,
            viewtag_scan_buckets: BTreeMap::new(),
            spendlink_shield_refreshes: BTreeMap::new(),
            decoy_entropy_floors: BTreeMap::new(),
            stealth_note_freshness: BTreeMap::new(),
            output_age_diversity: BTreeMap::new(),
            pq_migration_attestations: BTreeMap::new(),
            scan_fee_sponsorships: BTreeMap::new(),
            refresh_nullifiers: BTreeMap::new(),
            low_fee_audits: BTreeMap::new(),
            public_records: BTreeMap::new(),
            quarantined_bucket_ids: BTreeSet::new(),
            used_refresh_nullifier_ids: BTreeSet::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(
            Config::devnet(),
            DEVNET_L2_HEIGHT,
            DEVNET_MONERO_HEIGHT,
            DEVNET_EPOCH,
        )
        .expect("devnet config validates");
        state.seed_devnet();
        state
    }

    pub fn insert_viewtag_scan_bucket(&mut self, bucket: ViewtagScanBucket) -> Result<()> {
        bucket.validate(&self.config, self.monero_height)?;
        ensure(
            !self.viewtag_scan_buckets.contains_key(&bucket.bucket_id),
            "duplicate viewtag scan bucket",
        )?;
        self.counters.viewtag_scan_buckets += 1;
        self.viewtag_scan_buckets
            .insert(bucket.bucket_id.clone(), bucket);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_decoy_entropy_floor(&mut self, floor: DecoyEntropyFloor) -> Result<()> {
        floor.validate(&self.config)?;
        ensure(
            self.viewtag_scan_buckets.contains_key(&floor.bucket_id),
            "entropy floor references unknown scan bucket",
        )?;
        ensure(
            !self.decoy_entropy_floors.contains_key(&floor.floor_id),
            "duplicate decoy entropy floor",
        )?;
        self.counters.decoy_entropy_floors += 1;
        self.decoy_entropy_floors
            .insert(floor.floor_id.clone(), floor);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_stealth_note_freshness(&mut self, freshness: StealthNoteFreshness) -> Result<()> {
        freshness.validate(&self.config)?;
        ensure(
            self.viewtag_scan_buckets.contains_key(&freshness.bucket_id),
            "freshness window references unknown scan bucket",
        )?;
        ensure(
            !self
                .stealth_note_freshness
                .contains_key(&freshness.freshness_id),
            "duplicate stealth-note freshness window",
        )?;
        self.counters.stealth_note_freshness_windows += 1;
        self.stealth_note_freshness
            .insert(freshness.freshness_id.clone(), freshness);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_output_age_diversity(&mut self, diversity: OutputAgeDiversity) -> Result<()> {
        diversity.validate(&self.config)?;
        ensure(
            self.viewtag_scan_buckets.contains_key(&diversity.bucket_id),
            "age diversity references unknown scan bucket",
        )?;
        ensure(
            !self
                .output_age_diversity
                .contains_key(&diversity.diversity_id),
            "duplicate output age diversity window",
        )?;
        self.counters.output_age_diversity_windows += 1;
        self.output_age_diversity
            .insert(diversity.diversity_id.clone(), diversity);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_pq_migration_attestation(
        &mut self,
        attestation: PqMigrationAttestation,
    ) -> Result<()> {
        attestation.validate(&self.config, self.monero_height)?;
        ensure(
            self.viewtag_scan_buckets
                .contains_key(&attestation.bucket_id),
            "PQ attestation references unknown scan bucket",
        )?;
        ensure(
            !self
                .pq_migration_attestations
                .contains_key(&attestation.attestation_id),
            "duplicate PQ migration attestation",
        )?;
        self.counters.pq_migration_attestations += 1;
        self.pq_migration_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_scan_fee_sponsorship(&mut self, sponsorship: ScanFeeSponsorship) -> Result<()> {
        sponsorship.validate(&self.config, self.monero_height)?;
        ensure(
            self.viewtag_scan_buckets
                .contains_key(&sponsorship.bucket_id),
            "sponsorship references unknown scan bucket",
        )?;
        ensure(
            !self
                .scan_fee_sponsorships
                .contains_key(&sponsorship.sponsorship_id),
            "duplicate scan fee sponsorship",
        )?;
        self.counters.scan_fee_sponsorships += 1;
        self.scan_fee_sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_low_fee_audit(&mut self, audit: LowFeeAudit) -> Result<()> {
        audit.validate(&self.config)?;
        ensure(
            self.scan_fee_sponsorships
                .contains_key(&audit.sponsorship_id),
            "audit references unknown scan fee sponsorship",
        )?;
        ensure(
            !self.low_fee_audits.contains_key(&audit.audit_id),
            "duplicate low-fee audit",
        )?;
        self.counters.low_fee_audits += 1;
        self.low_fee_audits.insert(audit.audit_id.clone(), audit);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_spendlink_shield_refresh(
        &mut self,
        refresh: SpendlinkShieldRefresh,
    ) -> Result<()> {
        refresh.validate(&self.config)?;
        ensure(
            self.viewtag_scan_buckets.contains_key(&refresh.bucket_id),
            "refresh references unknown scan bucket",
        )?;
        ensure(
            refresh.refresh_score_bps == refresh.recompute_score(&self.config),
            "refresh score does not match deterministic scoring rule",
        )?;
        ensure(
            !self
                .spendlink_shield_refreshes
                .contains_key(&refresh.refresh_id),
            "duplicate spendlink shield refresh",
        )?;
        self.counters.spendlink_shield_refreshes += 1;
        if refresh.status == ShieldStatus::Rejected || refresh.status == ShieldStatus::Regression {
            self.counters.rejected_refreshes += 1;
        }
        self.spendlink_shield_refreshes
            .insert(refresh.refresh_id.clone(), refresh);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_refresh_nullifier(&mut self, nullifier: RefreshNullifier) -> Result<()> {
        nullifier.validate(&self.config, self.monero_height)?;
        ensure(
            self.spendlink_shield_refreshes
                .contains_key(&nullifier.refresh_id),
            "nullifier references unknown refresh",
        )?;
        ensure(
            !self
                .refresh_nullifiers
                .contains_key(&nullifier.nullifier_id),
            "duplicate refresh nullifier",
        )?;
        ensure(
            !self
                .used_refresh_nullifier_ids
                .contains(&nullifier.nullifier_id),
            "refresh nullifier already used",
        )?;
        self.counters.refresh_nullifiers += 1;
        self.used_refresh_nullifier_ids
            .insert(nullifier.nullifier_id.clone());
        self.refresh_nullifiers
            .insert(nullifier.nullifier_id.clone(), nullifier);
        self.refresh_roots();
        Ok(())
    }

    pub fn quarantine_bucket(&mut self, bucket_id: &str) -> Result<()> {
        ensure(
            self.viewtag_scan_buckets.contains_key(bucket_id),
            "cannot quarantine unknown bucket",
        )?;
        if self.quarantined_bucket_ids.insert(bucket_id.to_string()) {
            self.counters.quarantined_buckets += 1;
        }
        if let Some(bucket) = self.viewtag_scan_buckets.get_mut(bucket_id) {
            bucket.status = BucketStatus::Quarantined;
        }
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
        ensure(
            !self.public_records.contains_key(&record_id),
            "duplicate public record",
        )?;
        let record = RootsOnlyPublicRecord {
            record_id: record_id.clone(),
            audience,
            epoch: self.epoch,
            roots: self.roots.clone(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            published_at_l2_height: self.l2_height,
            published_at_monero_height_bucket: bucket(
                self.monero_height,
                self.config.public_bucket_size,
            ),
        };
        record.validate()?;
        self.counters.public_records += 1;
        self.public_records.insert(record_id.clone(), record);
        self.refresh_roots();
        Ok(record_id)
    }

    pub fn privacy_score_bps(&self, bucket_id: &str) -> Option<u64> {
        let entropy = self
            .decoy_entropy_floors
            .values()
            .filter(|floor| floor.bucket_id == bucket_id)
            .map(|floor| floor.observed_entropy_bps)
            .max()?;
        let freshness = self
            .stealth_note_freshness
            .values()
            .filter(|window| window.bucket_id == bucket_id)
            .map(|window| window.freshness_bps)
            .max()?;
        let diversity = self
            .output_age_diversity
            .values()
            .filter(|window| window.bucket_id == bucket_id)
            .map(|window| window.age_diversity_bps)
            .max()?;
        Some(
            entropy
                .saturating_mul(40)
                .saturating_add(freshness.saturating_mul(30))
                .saturating_add(diversity.saturating_mul(30))
                .saturating_div(100)
                .min(MAX_BPS),
        )
    }

    pub fn low_fee_coverage_bps(&self) -> u64 {
        if self.viewtag_scan_buckets.is_empty() {
            return 0;
        }
        let sponsored = self
            .scan_fee_sponsorships
            .values()
            .filter(|sponsorship| {
                matches!(
                    sponsorship.status,
                    SponsorshipStatus::Paid
                        | SponsorshipStatus::Reserved
                        | SponsorshipStatus::Netting
                )
            })
            .count() as u64;
        sponsored
            .saturating_mul(MAX_BPS)
            .saturating_div(self.viewtag_scan_buckets.len() as u64)
            .min(MAX_BPS)
    }

    pub fn migration_attestation_coverage_bps(&self) -> u64 {
        if self.viewtag_scan_buckets.is_empty() {
            return 0;
        }
        let attested = self
            .pq_migration_attestations
            .values()
            .filter(|attestation| attestation.status.counts_for_quorum())
            .map(|attestation| attestation.bucket_id.clone())
            .collect::<BTreeSet<_>>()
            .len() as u64;
        attested
            .saturating_mul(MAX_BPS)
            .saturating_div(self.viewtag_scan_buckets.len() as u64)
            .min(MAX_BPS)
    }

    pub fn refresh_readiness_bps(&self) -> u64 {
        if self.viewtag_scan_buckets.is_empty() {
            return 0;
        }
        let ready = self
            .viewtag_scan_buckets
            .keys()
            .filter(|bucket_id| {
                self.privacy_score_bps(bucket_id.as_str())
                    .map(|score| score >= self.config.min_refresh_score_bps)
                    .unwrap_or(false)
                    && self.pq_migration_attestations.values().any(|attestation| {
                        attestation.bucket_id == **bucket_id
                            && attestation.status.counts_for_quorum()
                    })
                    && self
                        .scan_fee_sponsorships
                        .values()
                        .any(|sponsorship| sponsorship.bucket_id == **bucket_id)
            })
            .count() as u64;
        ready
            .saturating_mul(MAX_BPS)
            .saturating_div(self.viewtag_scan_buckets.len() as u64)
            .min(MAX_BPS)
    }

    pub fn refresh_roots(&mut self) {
        self.roots = Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters.state_root(),
            viewtag_scan_bucket_root: map_root(
                "viewtag-scan-buckets",
                self.viewtag_scan_buckets
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root(&self.config))),
            ),
            spendlink_shield_refresh_root: map_root(
                "spendlink-shield-refreshes",
                self.spendlink_shield_refreshes
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            decoy_entropy_floor_root: map_root(
                "decoy-entropy-floors",
                self.decoy_entropy_floors
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root(&self.config))),
            ),
            stealth_note_freshness_root: map_root(
                "stealth-note-freshness",
                self.stealth_note_freshness
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root(&self.config))),
            ),
            output_age_diversity_root: map_root(
                "output-age-diversity",
                self.output_age_diversity
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root(&self.config))),
            ),
            pq_migration_attestation_root: map_root(
                "pq-migration-attestations",
                self.pq_migration_attestations
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root(&self.config))),
            ),
            scan_fee_sponsorship_root: map_root(
                "scan-fee-sponsorships",
                self.scan_fee_sponsorships
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root(&self.config))),
            ),
            refresh_nullifier_root: map_root(
                "refresh-nullifiers",
                self.refresh_nullifiers
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root(&self.config))),
            ),
            low_fee_audit_root: map_root(
                "low-fee-audits",
                self.low_fee_audits
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            public_record_root: map_root(
                "public-records",
                self.public_records
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
        };
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "l2_network": self.config.l2_network,
            "monero_network": self.config.monero_network,
            "epoch": self.epoch,
            "l2_height": self.l2_height,
            "monero_height_bucket": bucket(self.monero_height, self.config.public_bucket_size),
            "privacy_boundary": PRIVACY_BOUNDARY,
            "roots": self.roots.public_record(),
            "counters": self.counters.public_record(),
            "low_fee_coverage_bps": self.low_fee_coverage_bps(),
            "migration_attestation_coverage_bps": self.migration_attestation_coverage_bps(),
            "refresh_readiness_bps": self.refresh_readiness_bps(),
            "quarantined_bucket_root": set_root("quarantined-buckets", &self.quarantined_bucket_ids),
            "used_refresh_nullifier_root": set_root("used-refresh-nullifiers", &self.used_refresh_nullifier_ids),
        })
    }

    pub fn state_root(&self) -> String {
        root_from_parts(
            "state",
            &[
                HashPart::Json(&self.public_record()),
                HashPart::Str(&self.roots.state_root()),
            ],
        )
    }

    #[rustfmt::skip]
    fn seed_devnet(&mut self) {
        let bucket_id = "jamtis-seraphis-spendlink-refresh-bucket-devnet-0".to_string(); let refresh_id = "spendlink-shield-refresh-devnet-0".to_string(); let sponsorship_id = "scan-fee-sponsorship-devnet-0".to_string(); let nullifier_id = "refresh-nullifier-devnet-0".to_string();
        self.insert_viewtag_scan_bucket(ViewtagScanBucket { bucket_id: bucket_id.clone(), lane: RefreshLane::WalletScan, era: PrivacyEra::DualStack, epoch: self.epoch, monero_height_bucket: bucket(self.monero_height, self.config.public_bucket_size), output_count_bucket: self.config.target_scan_bucket_outputs, viewtag_prefix_root: root_from_parts("devnet-viewtag-prefix", &[HashPart::Str(&bucket_id)]), scan_hint_commitment_root: root_from_parts("devnet-scan-hint", &[HashPart::Str(&bucket_id)]), wallet_cohort_root: root_from_parts("devnet-wallet-cohort", &[HashPart::Str(&bucket_id)]), decoy_candidate_root: root_from_parts("devnet-decoy-candidate", &[HashPart::Str(&bucket_id)]), scan_units_bucket: 4_096, expires_at_height: self.monero_height + self.config.scan_bucket_ttl_blocks, status: BucketStatus::Scanned }).expect("devnet scan bucket inserts");
        self.insert_decoy_entropy_floor(DecoyEntropyFloor { floor_id: "decoy-entropy-floor-devnet-0".to_string(), bucket_id: bucket_id.clone(), ring_size: self.config.target_ring_size, min_entropy_bps: self.config.min_decoy_entropy_bps, observed_entropy_bps: 9_180, decoy_source_count_bucket: 262_144, decoy_source_root: root_from_parts("devnet-decoy-source", &[HashPart::Str(&bucket_id)]), entropy_evidence_root: root_from_parts("devnet-entropy-evidence", &[HashPart::Str(&bucket_id)]), status: BucketStatus::EntropyChecked }).expect("devnet entropy floor inserts");
        self.insert_stealth_note_freshness(StealthNoteFreshness { freshness_id: "stealth-note-freshness-devnet-0".to_string(), bucket_id: bucket_id.clone(), newest_height_bucket: bucket(self.monero_height, self.config.public_bucket_size), oldest_height_bucket: bucket(self.monero_height - 4_096, self.config.public_bucket_size), freshness_bps: 8_980, stale_note_bucket: 64, note_commitment_root: root_from_parts("devnet-note-commitment", &[HashPart::Str(&bucket_id)]), refresh_receipt_root: root_from_parts("devnet-refresh-receipt", &[HashPart::Str(&bucket_id)]), status: BucketStatus::FreshnessChecked }).expect("devnet freshness inserts");
        self.insert_output_age_diversity(OutputAgeDiversity { diversity_id: "output-age-diversity-devnet-0".to_string(), bucket_id: bucket_id.clone(), young_output_bucket: 131_072, mature_output_bucket: 262_144, old_output_bucket: 131_072, age_diversity_bps: 8_910, age_histogram_root: root_from_parts("devnet-age-histogram", &[HashPart::Str(&bucket_id)]), decoy_age_mix_root: root_from_parts("devnet-age-mix", &[HashPart::Str(&bucket_id)]), status: BucketStatus::AgeDiverse }).expect("devnet age diversity inserts");
        let score = spendlink_refresh_score(42, 180, 9_180, 8_910, 8_980, self.config.target_ring_size, self.config.target_ring_size);
        self.insert_spendlink_shield_refresh(SpendlinkShieldRefresh { refresh_id: refresh_id.clone(), bucket_id: bucket_id.clone(), lane: RefreshLane::WalletScan, ring_size: self.config.target_ring_size, viewtag_collision_bps: 42, spendlink_risk_bps: 180, decoy_entropy_bps: 9_180, output_age_diversity_bps: 8_910, stealth_note_freshness_bps: 8_980, refresh_score_bps: score, shield_commitment_root: root_from_parts("devnet-shield-commitment", &[HashPart::Str(&refresh_id)]), replacement_decoy_root: root_from_parts("devnet-replacement-decoy", &[HashPart::Str(&refresh_id)]), status: ShieldStatus::Shielded }).expect("devnet shield refresh inserts");
        self.insert_pq_migration_attestation(PqMigrationAttestation { attestation_id: "pq-migration-attestation-devnet-0".to_string(), bucket_id: bucket_id.clone(), era: PrivacyEra::JamtisSeraphis, signer_set_root: root_from_parts("devnet-pq-signer-set", &[HashPart::Str("0")]), migration_plan_root: root_from_parts("devnet-migration-plan", &[HashPart::Str(&bucket_id)]), pq_security_bits: self.config.target_pq_security_bits, classical_fallback_disabled: true, attested_at_height: self.monero_height, expires_at_height: self.monero_height + self.config.attestation_ttl_blocks, status: AttestationStatus::StrongQuorum }).expect("devnet PQ attestation inserts");
        self.insert_scan_fee_sponsorship(ScanFeeSponsorship { sponsorship_id: sponsorship_id.clone(), bucket_id: bucket_id.clone(), sponsor_bucket: "devnet-sponsor-bucket-0".to_string(), fee_asset_id: self.config.fee_asset_id.clone(), user_fee_bps: 4, sponsor_cover_bps: self.config.target_sponsor_cover_bps, scan_units_bucket: 4_096, reserved_fee_bucket: 32, sponsor_receipt_root: root_from_parts("devnet-sponsor-receipt", &[HashPart::Str(&sponsorship_id)]), settlement_root: root_from_parts("devnet-sponsor-settlement", &[HashPart::Str(&sponsorship_id)]), expires_at_height: self.monero_height + self.config.sponsorship_ttl_blocks, status: SponsorshipStatus::Paid }).expect("devnet sponsorship inserts");
        self.insert_refresh_nullifier(RefreshNullifier { nullifier_id: nullifier_id.clone(), bucket_id: bucket_id.clone(), refresh_id: refresh_id.clone(), nullifier_root: root_from_parts("devnet-nullifier", &[HashPart::Str(&nullifier_id)]), spent_refresh_root: root_from_parts("devnet-spent-refresh", &[HashPart::Str(&refresh_id)]), created_at_height: self.monero_height, expires_at_height: self.monero_height + self.config.refresh_ttl_blocks, status: NullifierStatus::Active }).expect("devnet nullifier inserts");
        self.insert_low_fee_audit(LowFeeAudit { audit_id: "low-fee-audit-devnet-0".to_string(), bucket_id, sponsorship_id, measured_user_fee_bps: 4, target_user_fee_bps: self.config.max_user_scan_fee_bps, subsidy_efficiency_bps: 9_220, sponsor_settlement_delay_blocks: 10, fee_sample_root: root_from_parts("devnet-fee-samples", &[HashPart::Str("0")]), audit_evidence_root: root_from_parts("devnet-fee-audit", &[HashPart::Str("0")]), status: AuditStatus::Published }).expect("devnet low-fee audit inserts");
        self.publish_roots_only_record("roots-only-public-record-devnet-0", PublicAudience::Public).expect("devnet public record publishes"); self.refresh_roots();
    }
}

pub fn devnet() -> State {
    State::devnet()
}
pub fn demo() -> State {
    devnet()
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

fn spendlink_refresh_score(
    viewtag_collision_bps: u64,
    spendlink_risk_bps: u64,
    decoy_entropy_bps: u64,
    output_age_diversity_bps: u64,
    stealth_note_freshness_bps: u64,
    ring_size: u16,
    target_ring_size: u16,
) -> u64 {
    let ring_component = (ring_size as u64)
        .saturating_mul(MAX_BPS)
        .saturating_div(target_ring_size.max(1) as u64)
        .min(MAX_BPS);
    let privacy_component = decoy_entropy_bps
        .saturating_mul(38)
        .saturating_add(output_age_diversity_bps.saturating_mul(22))
        .saturating_add(stealth_note_freshness_bps.saturating_mul(22))
        .saturating_add(ring_component.saturating_mul(18))
        .saturating_div(100);
    let penalty = viewtag_collision_bps
        .saturating_div(2)
        .saturating_add(spendlink_risk_bps);
    privacy_component
        .saturating_sub(penalty.min(MAX_BPS))
        .min(MAX_BPS)
}

fn empty_root(domain: &str) -> String {
    root_from_parts(domain, &[HashPart::Str("empty")])
}
fn root_from_record(domain: &str, record: &Value) -> String {
    root_from_parts(domain, &[HashPart::Json(record)])
}
fn root_from_parts(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(&format!("{STATE_ROOT_DOMAIN}-{domain}"), parts, 32)
}
fn map_root<'a>(domain: &str, entries: impl Iterator<Item = (&'a str, String)>) -> String {
    let leaves = entries
        .map(|(id, root)| json!({ "id": id, "root": root }))
        .collect::<Vec<_>>();
    merkle_root(&format!("{STATE_ROOT_DOMAIN}-{domain}"), &leaves)
}
fn set_root(domain: &str, entries: &BTreeSet<String>) -> String {
    let leaves = entries
        .iter()
        .map(|id| json!({ "id": id }))
        .collect::<Vec<_>>();
    merkle_root(&format!("{STATE_ROOT_DOMAIN}-{domain}"), &leaves)
}
