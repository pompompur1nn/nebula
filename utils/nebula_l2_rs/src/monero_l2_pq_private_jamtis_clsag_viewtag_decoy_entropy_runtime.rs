use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = MoneroL2PqPrivateJamtisClsagViewtagDecoyEntropyRuntimeResult<T>;
pub type MoneroL2PqPrivateJamtisClsagViewtagDecoyEntropyRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const MONERO_L2_PQ_PRIVATE_JAMTIS_CLSAG_VIEWTAG_DECOY_ENTROPY_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-jamtis-clsag-viewtag-decoy-entropy-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_JAMTIS_CLSAG_VIEWTAG_DECOY_ENTROPY_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 4_228_800;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_982_400;
pub const DEVNET_EPOCH: u64 = 29_440;
pub const VIEWTAG_SCAN_BUCKET_SCHEME: &str = "jamtis-clsag-viewtag-private-scan-bucket-root-v1";
pub const CLSAG_DECOY_ENTROPY_FLOOR_SCHEME: &str = "clsag-decoy-entropy-floor-commitment-root-v1";
pub const STEALTH_NOTE_FRESHNESS_SCHEME: &str = "jamtis-stealth-note-freshness-roots-only-root-v1";
pub const OUTPUT_AGE_DIVERSITY_SCHEME: &str =
    "clsag-output-age-diversity-histogram-commitment-root-v1";
pub const PQ_MIGRATION_ATTESTATION_SCHEME: &str =
    "ML-DSA-87+ML-KEM-1024+SLH-DSA-SHAKE-256f-jamtis-clsag-migration-attestation-root-v1";
pub const SCAN_FEE_SPONSORSHIP_SCHEME: &str = "low-fee-jamtis-viewtag-scan-sponsorship-root-v1";
pub const PUBLIC_ROOT_EPOCH_SCHEME: &str =
    "roots-only-jamtis-clsag-viewtag-decoy-entropy-public-record-root-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_addresses_view_keys_spend_keys_amounts_output_indices_key_images_ring_members_viewtags_or_scan_secrets";
pub const MAX_BPS: u64 = 10_000;
pub const MAX_SCORE: u64 = 10_000;
pub const DEFAULT_VIEWTAG_BUCKET_SPAN_BLOCKS: u64 = 24;
pub const DEFAULT_VIEWTAG_BUCKET_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_MIN_BUCKET_OUTPUTS: u64 = 512;
pub const DEFAULT_TARGET_BUCKET_OUTPUTS: u64 = 8_192;
pub const DEFAULT_MIN_VIEWTAG_ENTROPY_BPS: u64 = 8_900;
pub const DEFAULT_TARGET_VIEWTAG_ENTROPY_BPS: u64 = 9_825;
pub const DEFAULT_MIN_RING_SIZE: u16 = 16;
pub const DEFAULT_TARGET_RING_SIZE: u16 = 128;
pub const DEFAULT_MIN_EFFECTIVE_DECOYS: u64 = 104;
pub const DEFAULT_TARGET_EFFECTIVE_DECOYS: u64 = 126;
pub const DEFAULT_MIN_SHANNON_ENTROPY_MILLIBITS: u64 = 3_850_000;
pub const DEFAULT_TARGET_SHANNON_ENTROPY_MILLIBITS: u64 = 4_960_000;
pub const DEFAULT_MIN_MIN_ENTROPY_MILLIBITS: u64 = 3_200_000;
pub const DEFAULT_TARGET_MIN_ENTROPY_MILLIBITS: u64 = 4_400_000;
pub const DEFAULT_MIN_STEALTH_FRESHNESS_BPS: u64 = 8_750;
pub const DEFAULT_TARGET_STEALTH_FRESHNESS_BPS: u64 = 9_700;
pub const DEFAULT_MAX_STALE_NOTE_SHARE_BPS: u64 = 850;
pub const DEFAULT_MIN_AGE_BUCKETS: u16 = 8;
pub const DEFAULT_TARGET_AGE_BUCKETS: u16 = 32;
pub const DEFAULT_MIN_AGE_DIVERSITY_BPS: u64 = 8_950;
pub const DEFAULT_TARGET_AGE_DIVERSITY_BPS: u64 = 9_775;
pub const DEFAULT_MAX_RECENT_OUTPUT_SHARE_BPS: u64 = 1_750;
pub const DEFAULT_MAX_AGE_BUCKET_SKEW_BPS: u64 = 600;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PQ_ATTESTATION_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_PQ_ATTESTATION_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_MIGRATION_GRACE_BLOCKS: u64 = 5_760;
pub const DEFAULT_MAX_CLSAG_LEGACY_SHARE_BPS: u64 = 2_500;
pub const DEFAULT_SCAN_FEE_CAP_MICRO_UNITS: u64 = 1_200;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_000;
pub const DEFAULT_LOW_FEE_AUDIT_BATCH_OUTPUTS: u64 = 16_384;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 1_500;
pub const DEFAULT_PUBLIC_RECORD_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_REORG_HOLD_BLOCKS: u64 = 36;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanLane {
    BackgroundWallet,
    ForegroundWallet,
    MerchantReceive,
    BridgeDeposit,
    SwapSettlement,
    WatchOnlyAudit,
    ReorgRepair,
    LowFeeBatch,
}

impl ScanLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BackgroundWallet => "background_wallet",
            Self::ForegroundWallet => "foreground_wallet",
            Self::MerchantReceive => "merchant_receive",
            Self::BridgeDeposit => "bridge_deposit",
            Self::SwapSettlement => "swap_settlement",
            Self::WatchOnlyAudit => "watch_only_audit",
            Self::ReorgRepair => "reorg_repair",
            Self::LowFeeBatch => "low_fee_batch",
        }
    }

    pub fn low_fee(self) -> bool {
        matches!(self, Self::BackgroundWallet | Self::LowFeeBatch)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketStatus {
    Draft,
    Open,
    Sealed,
    EntropyScored,
    FreshnessScored,
    AgeDiversityScored,
    PqAttested,
    Sponsored,
    PublishedRoots,
    ReorgHeld,
    Expired,
    Quarantined,
}

impl BucketStatus {
    pub fn public_usable(self) -> bool {
        matches!(
            self,
            Self::Sealed
                | Self::EntropyScored
                | Self::FreshnessScored
                | Self::AgeDiversityScored
                | Self::PqAttested
                | Self::Sponsored
                | Self::PublishedRoots
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FloorStatus {
    Draft,
    Observed,
    MeetsFloor,
    BelowFloor,
    Remediated,
    Sealed,
    Quarantined,
    Expired,
}

impl FloorStatus {
    pub fn acceptable(self) -> bool {
        matches!(self, Self::MeetsFloor | Self::Remediated | Self::Sealed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessStatus {
    Pending,
    Fresh,
    Borderline,
    Stale,
    Repaired,
    Sealed,
}

impl FreshnessStatus {
    pub fn acceptable(self) -> bool {
        matches!(self, Self::Fresh | Self::Repaired | Self::Sealed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgeDiversityStatus {
    Pending,
    Balanced,
    RecentDominated,
    Skewed,
    Rebalanced,
    Sealed,
}

impl AgeDiversityStatus {
    pub fn acceptable(self) -> bool {
        matches!(self, Self::Balanced | Self::Rebalanced | Self::Sealed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAttestationStatus {
    Pending,
    Valid,
    Expiring,
    Expired,
    InsufficientQuorum,
    MigrationUnsafe,
    Revoked,
}

impl PqAttestationStatus {
    pub fn valid(self) -> bool {
        matches!(self, Self::Valid | Self::Expiring)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Reserved,
    Covered,
    PartiallyCovered,
    RebatePosted,
    Exhausted,
    Revoked,
}

impl SponsorshipStatus {
    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Reserved | Self::Covered | Self::PartiallyCovered | Self::RebatePosted
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationMode {
    ClsagLegacy,
    JamtisShadow,
    JamtisPrimary,
    HybridPq,
    PqRequired,
}

fn ordered_bps(minimum: u64, target: u64) -> bool {
    minimum <= MAX_BPS && target <= MAX_BPS && target >= minimum
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub viewtag_scan_bucket_scheme: String,
    pub clsag_decoy_entropy_floor_scheme: String,
    pub stealth_note_freshness_scheme: String,
    pub output_age_diversity_scheme: String,
    pub pq_migration_attestation_scheme: String,
    pub scan_fee_sponsorship_scheme: String,
    pub public_root_epoch_scheme: String,
    pub privacy_boundary: String,
    pub viewtag_bucket_span_blocks: u64,
    pub viewtag_bucket_ttl_blocks: u64,
    pub min_bucket_outputs: u64,
    pub target_bucket_outputs: u64,
    pub min_viewtag_entropy_bps: u64,
    pub target_viewtag_entropy_bps: u64,
    pub min_ring_size: u16,
    pub target_ring_size: u16,
    pub min_effective_decoys: u64,
    pub target_effective_decoys: u64,
    pub min_shannon_entropy_millibits: u64,
    pub target_shannon_entropy_millibits: u64,
    pub min_min_entropy_millibits: u64,
    pub target_min_entropy_millibits: u64,
    pub min_stealth_freshness_bps: u64,
    pub target_stealth_freshness_bps: u64,
    pub max_stale_note_share_bps: u64,
    pub min_age_buckets: u16,
    pub target_age_buckets: u16,
    pub min_age_diversity_bps: u64,
    pub target_age_diversity_bps: u64,
    pub max_recent_output_share_bps: u64,
    pub max_age_bucket_skew_bps: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub min_pq_attestation_quorum_bps: u64,
    pub pq_attestation_ttl_blocks: u64,
    pub migration_grace_blocks: u64,
    pub max_clsag_legacy_share_bps: u64,
    pub scan_fee_cap_micro_units: u64,
    pub sponsor_cover_bps: u64,
    pub low_fee_audit_batch_outputs: u64,
    pub low_fee_rebate_bps: u64,
    pub public_record_epoch_blocks: u64,
    pub reorg_hold_blocks: u64,
    pub max_public_records: usize,
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
            clsag_decoy_entropy_floor_scheme: CLSAG_DECOY_ENTROPY_FLOOR_SCHEME.to_string(),
            stealth_note_freshness_scheme: STEALTH_NOTE_FRESHNESS_SCHEME.to_string(),
            output_age_diversity_scheme: OUTPUT_AGE_DIVERSITY_SCHEME.to_string(),
            pq_migration_attestation_scheme: PQ_MIGRATION_ATTESTATION_SCHEME.to_string(),
            scan_fee_sponsorship_scheme: SCAN_FEE_SPONSORSHIP_SCHEME.to_string(),
            public_root_epoch_scheme: PUBLIC_ROOT_EPOCH_SCHEME.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            viewtag_bucket_span_blocks: DEFAULT_VIEWTAG_BUCKET_SPAN_BLOCKS,
            viewtag_bucket_ttl_blocks: DEFAULT_VIEWTAG_BUCKET_TTL_BLOCKS,
            min_bucket_outputs: DEFAULT_MIN_BUCKET_OUTPUTS,
            target_bucket_outputs: DEFAULT_TARGET_BUCKET_OUTPUTS,
            min_viewtag_entropy_bps: DEFAULT_MIN_VIEWTAG_ENTROPY_BPS,
            target_viewtag_entropy_bps: DEFAULT_TARGET_VIEWTAG_ENTROPY_BPS,
            min_ring_size: DEFAULT_MIN_RING_SIZE,
            target_ring_size: DEFAULT_TARGET_RING_SIZE,
            min_effective_decoys: DEFAULT_MIN_EFFECTIVE_DECOYS,
            target_effective_decoys: DEFAULT_TARGET_EFFECTIVE_DECOYS,
            min_shannon_entropy_millibits: DEFAULT_MIN_SHANNON_ENTROPY_MILLIBITS,
            target_shannon_entropy_millibits: DEFAULT_TARGET_SHANNON_ENTROPY_MILLIBITS,
            min_min_entropy_millibits: DEFAULT_MIN_MIN_ENTROPY_MILLIBITS,
            target_min_entropy_millibits: DEFAULT_TARGET_MIN_ENTROPY_MILLIBITS,
            min_stealth_freshness_bps: DEFAULT_MIN_STEALTH_FRESHNESS_BPS,
            target_stealth_freshness_bps: DEFAULT_TARGET_STEALTH_FRESHNESS_BPS,
            max_stale_note_share_bps: DEFAULT_MAX_STALE_NOTE_SHARE_BPS,
            min_age_buckets: DEFAULT_MIN_AGE_BUCKETS,
            target_age_buckets: DEFAULT_TARGET_AGE_BUCKETS,
            min_age_diversity_bps: DEFAULT_MIN_AGE_DIVERSITY_BPS,
            target_age_diversity_bps: DEFAULT_TARGET_AGE_DIVERSITY_BPS,
            max_recent_output_share_bps: DEFAULT_MAX_RECENT_OUTPUT_SHARE_BPS,
            max_age_bucket_skew_bps: DEFAULT_MAX_AGE_BUCKET_SKEW_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            min_pq_attestation_quorum_bps: DEFAULT_MIN_PQ_ATTESTATION_QUORUM_BPS,
            pq_attestation_ttl_blocks: DEFAULT_PQ_ATTESTATION_TTL_BLOCKS,
            migration_grace_blocks: DEFAULT_MIGRATION_GRACE_BLOCKS,
            max_clsag_legacy_share_bps: DEFAULT_MAX_CLSAG_LEGACY_SHARE_BPS,
            scan_fee_cap_micro_units: DEFAULT_SCAN_FEE_CAP_MICRO_UNITS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            low_fee_audit_batch_outputs: DEFAULT_LOW_FEE_AUDIT_BATCH_OUTPUTS,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            public_record_epoch_blocks: DEFAULT_PUBLIC_RECORD_EPOCH_BLOCKS,
            reorg_hold_blocks: DEFAULT_REORG_HOLD_BLOCKS,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        let checks = [
            (
                self.min_bucket_outputs > 0,
                "min_bucket_outputs must be positive",
            ),
            (
                self.target_bucket_outputs >= self.min_bucket_outputs,
                "target_bucket_outputs below minimum",
            ),
            (
                ordered_bps(
                    self.min_viewtag_entropy_bps,
                    self.target_viewtag_entropy_bps,
                ),
                "invalid viewtag entropy thresholds",
            ),
            (
                self.target_ring_size >= self.min_ring_size && self.min_ring_size >= 16,
                "invalid ring size thresholds",
            ),
            (
                self.target_effective_decoys >= self.min_effective_decoys,
                "target effective decoys below minimum",
            ),
            (
                self.target_shannon_entropy_millibits >= self.min_shannon_entropy_millibits,
                "target shannon entropy below minimum",
            ),
            (
                self.target_min_entropy_millibits >= self.min_min_entropy_millibits,
                "target min entropy below minimum",
            ),
            (
                ordered_bps(
                    self.min_stealth_freshness_bps,
                    self.target_stealth_freshness_bps,
                ),
                "invalid stealth freshness thresholds",
            ),
            (
                self.max_stale_note_share_bps <= MAX_BPS,
                "max stale note share exceeds bps",
            ),
            (
                self.target_age_buckets >= self.min_age_buckets,
                "target age buckets below minimum",
            ),
            (
                ordered_bps(self.min_age_diversity_bps, self.target_age_diversity_bps),
                "invalid age diversity thresholds",
            ),
            (
                self.max_recent_output_share_bps <= MAX_BPS
                    && self.max_age_bucket_skew_bps <= MAX_BPS,
                "invalid age diversity caps",
            ),
            (
                self.target_pq_security_bits >= self.min_pq_security_bits,
                "target pq security below minimum",
            ),
            (
                self.min_pq_attestation_quorum_bps <= MAX_BPS,
                "pq attestation quorum exceeds bps",
            ),
            (
                self.max_clsag_legacy_share_bps <= MAX_BPS,
                "legacy clsag share exceeds bps",
            ),
            (
                self.sponsor_cover_bps <= MAX_BPS && self.low_fee_rebate_bps <= MAX_BPS,
                "invalid fee sponsorship bps",
            ),
        ];
        for (ok, message) in checks {
            ensure!(ok, "{}", message);
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("config serializes")
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
    pub clsag_decoy_entropy_floors: u64,
    pub stealth_note_freshness_reports: u64,
    pub output_age_diversity_reports: u64,
    pub pq_migration_attestations: u64,
    pub scan_fee_sponsorships: u64,
    pub public_root_epochs: u64,
    pub quarantined_buckets: u64,
    pub sponsored_low_fee_outputs: u64,
    pub roots_only_public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("counters serialize")
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub viewtag_scan_bucket_root: String,
    pub clsag_decoy_entropy_floor_root: String,
    pub stealth_note_freshness_root: String,
    pub output_age_diversity_root: String,
    pub pq_migration_attestation_root: String,
    pub scan_fee_sponsorship_root: String,
    pub public_root_epoch_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("roots serialize")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewtagScanBucketInput {
    pub bucket_id: String,
    pub lane: ScanLane,
    pub migration_mode: MigrationMode,
    pub start_height: u64,
    pub end_height: u64,
    pub sealed_height: u64,
    pub output_count: u64,
    pub viewtag_entropy_bps: u64,
    pub distinct_viewtag_prefixes: u16,
    pub scan_commitment_root: String,
    pub bucket_nullifier_root: String,
    pub operator_commitment: String,
    pub status: BucketStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewtagScanBucket {
    pub bucket_id: String,
    pub lane: ScanLane,
    pub migration_mode: MigrationMode,
    pub start_height: u64,
    pub end_height: u64,
    pub sealed_height: u64,
    pub expires_height: u64,
    pub output_count: u64,
    pub viewtag_entropy_bps: u64,
    pub distinct_viewtag_prefixes: u16,
    pub scan_commitment_root: String,
    pub bucket_nullifier_root: String,
    pub operator_commitment: String,
    pub status: BucketStatus,
    pub low_fee_eligible: bool,
    pub bucket_root: String,
}

impl ViewtagScanBucket {
    pub fn from_input(input: ViewtagScanBucketInput, config: &Config) -> Result<Self> {
        ensure!(!input.bucket_id.is_empty(), "bucket_id is required");
        ensure!(
            input.end_height >= input.start_height,
            "bucket end before start"
        );
        ensure!(
            input.end_height - input.start_height <= config.viewtag_bucket_span_blocks,
            "bucket span exceeds configured viewtag bucket span"
        );
        ensure!(
            input.sealed_height >= input.end_height,
            "sealed height before bucket end"
        );
        ensure!(
            input.output_count >= config.min_bucket_outputs,
            "bucket output count below minimum"
        );
        ensure!(
            input.viewtag_entropy_bps <= MAX_BPS,
            "viewtag entropy exceeds bps"
        );
        ensure!(
            input.viewtag_entropy_bps >= config.min_viewtag_entropy_bps,
            "viewtag entropy below minimum"
        );
        ensure!(
            input.distinct_viewtag_prefixes > 0,
            "distinct viewtag prefixes required"
        );
        ensure!(
            !input.scan_commitment_root.is_empty()
                && !input.bucket_nullifier_root.is_empty()
                && !input.operator_commitment.is_empty(),
            "bucket roots and operator commitment are required"
        );
        let low_fee_eligible = input.lane.low_fee()
            && input.output_count >= config.low_fee_audit_batch_outputs
            && input.viewtag_entropy_bps >= config.min_viewtag_entropy_bps;
        let expires_height = input.sealed_height + config.viewtag_bucket_ttl_blocks;
        let mut bucket = Self {
            bucket_id: input.bucket_id,
            lane: input.lane,
            migration_mode: input.migration_mode,
            start_height: input.start_height,
            end_height: input.end_height,
            sealed_height: input.sealed_height,
            expires_height,
            output_count: input.output_count,
            viewtag_entropy_bps: input.viewtag_entropy_bps,
            distinct_viewtag_prefixes: input.distinct_viewtag_prefixes,
            scan_commitment_root: input.scan_commitment_root,
            bucket_nullifier_root: input.bucket_nullifier_root,
            operator_commitment: input.operator_commitment,
            status: input.status,
            low_fee_eligible,
            bucket_root: String::new(),
        };
        bucket.bucket_root = bucket.compute_root(config);
        Ok(bucket)
    }

    pub fn compute_root(&self, config: &Config) -> String {
        domain_hash(
            &config.viewtag_scan_bucket_scheme,
            &[HashPart::Json(&self.public_record_without_root())],
            32,
        )
    }

    pub fn expired(&self, height: u64) -> bool {
        height > self.expires_height
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "lane": self.lane.as_str(),
            "migration_mode": self.migration_mode,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "sealed_height": self.sealed_height,
            "expires_height": self.expires_height,
            "output_count": self.output_count,
            "viewtag_entropy_bps": self.viewtag_entropy_bps,
            "distinct_viewtag_prefixes": self.distinct_viewtag_prefixes,
            "scan_commitment_root": self.scan_commitment_root,
            "bucket_nullifier_root": self.bucket_nullifier_root,
            "operator_commitment": self.operator_commitment,
            "status": self.status,
            "low_fee_eligible": self.low_fee_eligible,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record["bucket_root"] = json!(self.bucket_root);
        record
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClsagDecoyEntropyFloorInput {
    pub floor_id: String,
    pub bucket_id: String,
    pub lane: ScanLane,
    pub ring_size: u16,
    pub effective_decoys: u64,
    pub shannon_entropy_millibits: u64,
    pub min_entropy_millibits: u64,
    pub anonymity_set_outputs: u64,
    pub floor_score_bps: u64,
    pub decoy_commitment_root: String,
    pub sampling_transcript_root: String,
    pub status: FloorStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClsagDecoyEntropyFloor {
    pub floor_id: String,
    pub bucket_id: String,
    pub lane: ScanLane,
    pub ring_size: u16,
    pub effective_decoys: u64,
    pub shannon_entropy_millibits: u64,
    pub min_entropy_millibits: u64,
    pub anonymity_set_outputs: u64,
    pub floor_score_bps: u64,
    pub decoy_commitment_root: String,
    pub sampling_transcript_root: String,
    pub status: FloorStatus,
    pub below_floor: bool,
    pub floor_root: String,
}

impl ClsagDecoyEntropyFloor {
    pub fn from_input(input: ClsagDecoyEntropyFloorInput, config: &Config) -> Result<Self> {
        ensure!(!input.floor_id.is_empty(), "floor_id is required");
        ensure!(!input.bucket_id.is_empty(), "bucket_id is required");
        ensure!(
            input.ring_size >= config.min_ring_size,
            "ring size below minimum"
        );
        ensure!(
            input.effective_decoys >= config.min_effective_decoys,
            "effective decoys below minimum"
        );
        ensure!(
            input.shannon_entropy_millibits >= config.min_shannon_entropy_millibits,
            "shannon entropy below minimum"
        );
        ensure!(
            input.min_entropy_millibits >= config.min_min_entropy_millibits,
            "min entropy below minimum"
        );
        ensure!(input.floor_score_bps <= MAX_BPS, "floor score exceeds bps");
        ensure!(
            !input.decoy_commitment_root.is_empty() && !input.sampling_transcript_root.is_empty(),
            "decoy roots are required"
        );
        let below_floor = input.floor_score_bps < config.min_viewtag_entropy_bps;
        let mut floor = Self {
            floor_id: input.floor_id,
            bucket_id: input.bucket_id,
            lane: input.lane,
            ring_size: input.ring_size,
            effective_decoys: input.effective_decoys,
            shannon_entropy_millibits: input.shannon_entropy_millibits,
            min_entropy_millibits: input.min_entropy_millibits,
            anonymity_set_outputs: input.anonymity_set_outputs,
            floor_score_bps: input.floor_score_bps,
            decoy_commitment_root: input.decoy_commitment_root,
            sampling_transcript_root: input.sampling_transcript_root,
            status: input.status,
            below_floor,
            floor_root: String::new(),
        };
        floor.floor_root = floor.compute_root(config);
        Ok(floor)
    }

    pub fn compute_root(&self, config: &Config) -> String {
        domain_hash(
            &config.clsag_decoy_entropy_floor_scheme,
            &[HashPart::Json(&self.public_record_without_root())],
            32,
        )
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "floor_id": self.floor_id,
            "bucket_id": self.bucket_id,
            "lane": self.lane.as_str(),
            "ring_size": self.ring_size,
            "effective_decoys": self.effective_decoys,
            "shannon_entropy_millibits": self.shannon_entropy_millibits,
            "min_entropy_millibits": self.min_entropy_millibits,
            "anonymity_set_outputs": self.anonymity_set_outputs,
            "floor_score_bps": self.floor_score_bps,
            "decoy_commitment_root": self.decoy_commitment_root,
            "sampling_transcript_root": self.sampling_transcript_root,
            "status": self.status,
            "below_floor": self.below_floor,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record["floor_root"] = json!(self.floor_root);
        record
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StealthNoteFreshnessInput {
    pub freshness_id: String,
    pub bucket_id: String,
    pub assessed_height: u64,
    pub note_count: u64,
    pub fresh_note_share_bps: u64,
    pub stale_note_share_bps: u64,
    pub median_note_age_blocks: u64,
    pub freshness_score_bps: u64,
    pub note_freshness_root: String,
    pub recovery_hint_root: String,
    pub status: FreshnessStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StealthNoteFreshness {
    pub freshness_id: String,
    pub bucket_id: String,
    pub assessed_height: u64,
    pub note_count: u64,
    pub fresh_note_share_bps: u64,
    pub stale_note_share_bps: u64,
    pub median_note_age_blocks: u64,
    pub freshness_score_bps: u64,
    pub note_freshness_root: String,
    pub recovery_hint_root: String,
    pub status: FreshnessStatus,
    pub stale_share_exceeded: bool,
    pub freshness_root: String,
}

impl StealthNoteFreshness {
    pub fn from_input(input: StealthNoteFreshnessInput, config: &Config) -> Result<Self> {
        ensure!(!input.freshness_id.is_empty(), "freshness_id is required");
        ensure!(!input.bucket_id.is_empty(), "bucket_id is required");
        ensure!(input.note_count > 0, "note_count must be positive");
        ensure!(
            input.fresh_note_share_bps <= MAX_BPS
                && input.stale_note_share_bps <= MAX_BPS
                && input.freshness_score_bps <= MAX_BPS,
            "freshness bps values exceed max"
        );
        ensure!(
            input.freshness_score_bps >= config.min_stealth_freshness_bps,
            "freshness score below minimum"
        );
        ensure!(
            !input.note_freshness_root.is_empty() && !input.recovery_hint_root.is_empty(),
            "freshness roots are required"
        );
        let stale_share_exceeded = input.stale_note_share_bps > config.max_stale_note_share_bps;
        let mut freshness = Self {
            freshness_id: input.freshness_id,
            bucket_id: input.bucket_id,
            assessed_height: input.assessed_height,
            note_count: input.note_count,
            fresh_note_share_bps: input.fresh_note_share_bps,
            stale_note_share_bps: input.stale_note_share_bps,
            median_note_age_blocks: input.median_note_age_blocks,
            freshness_score_bps: input.freshness_score_bps,
            note_freshness_root: input.note_freshness_root,
            recovery_hint_root: input.recovery_hint_root,
            status: input.status,
            stale_share_exceeded,
            freshness_root: String::new(),
        };
        freshness.freshness_root = freshness.compute_root(config);
        Ok(freshness)
    }

    pub fn compute_root(&self, config: &Config) -> String {
        domain_hash(
            &config.stealth_note_freshness_scheme,
            &[HashPart::Json(&self.public_record_without_root())],
            32,
        )
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "freshness_id": self.freshness_id,
            "bucket_id": self.bucket_id,
            "assessed_height": self.assessed_height,
            "note_count": self.note_count,
            "fresh_note_share_bps": self.fresh_note_share_bps,
            "stale_note_share_bps": self.stale_note_share_bps,
            "median_note_age_blocks": self.median_note_age_blocks,
            "freshness_score_bps": self.freshness_score_bps,
            "note_freshness_root": self.note_freshness_root,
            "recovery_hint_root": self.recovery_hint_root,
            "status": self.status,
            "stale_share_exceeded": self.stale_share_exceeded,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record["freshness_root"] = json!(self.freshness_root);
        record
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OutputAgeDiversityInput {
    pub diversity_id: String,
    pub bucket_id: String,
    pub age_bucket_count: u16,
    pub age_diversity_bps: u64,
    pub recent_output_share_bps: u64,
    pub max_bucket_skew_bps: u64,
    pub oldest_bucket_age_blocks: u64,
    pub youngest_bucket_age_blocks: u64,
    pub age_histogram_root: String,
    pub age_sampler_root: String,
    pub status: AgeDiversityStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OutputAgeDiversity {
    pub diversity_id: String,
    pub bucket_id: String,
    pub age_bucket_count: u16,
    pub age_diversity_bps: u64,
    pub recent_output_share_bps: u64,
    pub max_bucket_skew_bps: u64,
    pub oldest_bucket_age_blocks: u64,
    pub youngest_bucket_age_blocks: u64,
    pub age_histogram_root: String,
    pub age_sampler_root: String,
    pub status: AgeDiversityStatus,
    pub recent_dominance: bool,
    pub skew_exceeded: bool,
    pub diversity_root: String,
}

impl OutputAgeDiversity {
    pub fn from_input(input: OutputAgeDiversityInput, config: &Config) -> Result<Self> {
        ensure!(!input.diversity_id.is_empty(), "diversity_id is required");
        ensure!(!input.bucket_id.is_empty(), "bucket_id is required");
        ensure!(
            input.age_bucket_count >= config.min_age_buckets,
            "age bucket count below minimum"
        );
        ensure!(
            input.age_diversity_bps <= MAX_BPS
                && input.recent_output_share_bps <= MAX_BPS
                && input.max_bucket_skew_bps <= MAX_BPS,
            "age diversity bps values exceed max"
        );
        ensure!(
            input.age_diversity_bps >= config.min_age_diversity_bps,
            "age diversity below minimum"
        );
        ensure!(
            input.oldest_bucket_age_blocks >= input.youngest_bucket_age_blocks,
            "oldest age bucket younger than youngest"
        );
        ensure!(
            !input.age_histogram_root.is_empty() && !input.age_sampler_root.is_empty(),
            "age diversity roots are required"
        );
        let recent_dominance = input.recent_output_share_bps > config.max_recent_output_share_bps;
        let skew_exceeded = input.max_bucket_skew_bps > config.max_age_bucket_skew_bps;
        let mut diversity = Self {
            diversity_id: input.diversity_id,
            bucket_id: input.bucket_id,
            age_bucket_count: input.age_bucket_count,
            age_diversity_bps: input.age_diversity_bps,
            recent_output_share_bps: input.recent_output_share_bps,
            max_bucket_skew_bps: input.max_bucket_skew_bps,
            oldest_bucket_age_blocks: input.oldest_bucket_age_blocks,
            youngest_bucket_age_blocks: input.youngest_bucket_age_blocks,
            age_histogram_root: input.age_histogram_root,
            age_sampler_root: input.age_sampler_root,
            status: input.status,
            recent_dominance,
            skew_exceeded,
            diversity_root: String::new(),
        };
        diversity.diversity_root = diversity.compute_root(config);
        Ok(diversity)
    }

    pub fn compute_root(&self, config: &Config) -> String {
        domain_hash(
            &config.output_age_diversity_scheme,
            &[HashPart::Json(&self.public_record_without_root())],
            32,
        )
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "diversity_id": self.diversity_id,
            "bucket_id": self.bucket_id,
            "age_bucket_count": self.age_bucket_count,
            "age_diversity_bps": self.age_diversity_bps,
            "recent_output_share_bps": self.recent_output_share_bps,
            "max_bucket_skew_bps": self.max_bucket_skew_bps,
            "oldest_bucket_age_blocks": self.oldest_bucket_age_blocks,
            "youngest_bucket_age_blocks": self.youngest_bucket_age_blocks,
            "age_histogram_root": self.age_histogram_root,
            "age_sampler_root": self.age_sampler_root,
            "status": self.status,
            "recent_dominance": self.recent_dominance,
            "skew_exceeded": self.skew_exceeded,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record["diversity_root"] = json!(self.diversity_root);
        record
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqMigrationAttestationInput {
    pub attestation_id: String,
    pub bucket_id: String,
    pub migration_mode: MigrationMode,
    pub attested_height: u64,
    pub valid_until_height: u64,
    pub pq_security_bits: u16,
    pub quorum_bps: u64,
    pub clsag_legacy_share_bps: u64,
    pub jamtis_shadow_share_bps: u64,
    pub attestor_set_root: String,
    pub hybrid_signature_root: String,
    pub migration_safety_root: String,
    pub status: PqAttestationStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqMigrationAttestation {
    pub attestation_id: String,
    pub bucket_id: String,
    pub migration_mode: MigrationMode,
    pub attested_height: u64,
    pub valid_until_height: u64,
    pub pq_security_bits: u16,
    pub quorum_bps: u64,
    pub clsag_legacy_share_bps: u64,
    pub jamtis_shadow_share_bps: u64,
    pub attestor_set_root: String,
    pub hybrid_signature_root: String,
    pub migration_safety_root: String,
    pub status: PqAttestationStatus,
    pub migration_safe: bool,
    pub attestation_root: String,
}

impl PqMigrationAttestation {
    pub fn from_input(input: PqMigrationAttestationInput, config: &Config) -> Result<Self> {
        ensure!(
            !input.attestation_id.is_empty(),
            "attestation_id is required"
        );
        ensure!(!input.bucket_id.is_empty(), "bucket_id is required");
        ensure!(
            input.valid_until_height >= input.attested_height,
            "valid until before attested height"
        );
        ensure!(
            input.valid_until_height - input.attested_height <= config.pq_attestation_ttl_blocks,
            "pq attestation ttl exceeds configured ttl"
        );
        ensure!(
            input.pq_security_bits >= config.min_pq_security_bits,
            "pq security below minimum"
        );
        ensure!(
            input.quorum_bps <= MAX_BPS
                && input.clsag_legacy_share_bps <= MAX_BPS
                && input.jamtis_shadow_share_bps <= MAX_BPS,
            "pq attestation bps values exceed max"
        );
        ensure!(
            input.quorum_bps >= config.min_pq_attestation_quorum_bps,
            "pq attestation quorum below minimum"
        );
        ensure!(
            !input.attestor_set_root.is_empty()
                && !input.hybrid_signature_root.is_empty()
                && !input.migration_safety_root.is_empty(),
            "pq attestation roots are required"
        );
        let migration_safe = input.pq_security_bits >= config.min_pq_security_bits
            && input.quorum_bps >= config.min_pq_attestation_quorum_bps
            && input.clsag_legacy_share_bps <= config.max_clsag_legacy_share_bps;
        let mut attestation = Self {
            attestation_id: input.attestation_id,
            bucket_id: input.bucket_id,
            migration_mode: input.migration_mode,
            attested_height: input.attested_height,
            valid_until_height: input.valid_until_height,
            pq_security_bits: input.pq_security_bits,
            quorum_bps: input.quorum_bps,
            clsag_legacy_share_bps: input.clsag_legacy_share_bps,
            jamtis_shadow_share_bps: input.jamtis_shadow_share_bps,
            attestor_set_root: input.attestor_set_root,
            hybrid_signature_root: input.hybrid_signature_root,
            migration_safety_root: input.migration_safety_root,
            status: input.status,
            migration_safe,
            attestation_root: String::new(),
        };
        attestation.attestation_root = attestation.compute_root(config);
        Ok(attestation)
    }

    pub fn compute_root(&self, config: &Config) -> String {
        domain_hash(
            &config.pq_migration_attestation_scheme,
            &[HashPart::Json(&self.public_record_without_root())],
            32,
        )
    }

    pub fn expired(&self, height: u64) -> bool {
        height > self.valid_until_height
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "bucket_id": self.bucket_id,
            "migration_mode": self.migration_mode,
            "attested_height": self.attested_height,
            "valid_until_height": self.valid_until_height,
            "pq_security_bits": self.pq_security_bits,
            "quorum_bps": self.quorum_bps,
            "clsag_legacy_share_bps": self.clsag_legacy_share_bps,
            "jamtis_shadow_share_bps": self.jamtis_shadow_share_bps,
            "attestor_set_root": self.attestor_set_root,
            "hybrid_signature_root": self.hybrid_signature_root,
            "migration_safety_root": self.migration_safety_root,
            "status": self.status,
            "migration_safe": self.migration_safe,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record["attestation_root"] = json!(self.attestation_root);
        record
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanFeeSponsorshipInput {
    pub sponsorship_id: String,
    pub bucket_id: String,
    pub sponsor_commitment: String,
    pub covered_outputs: u64,
    pub fee_cap_micro_units: u64,
    pub sponsor_cover_bps: u64,
    pub rebate_bps: u64,
    pub reserved_fee_micro_units: u64,
    pub spent_fee_micro_units: u64,
    pub sponsorship_epoch: u64,
    pub sponsorship_root: String,
    pub status: SponsorshipStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanFeeSponsorship {
    pub sponsorship_id: String,
    pub bucket_id: String,
    pub sponsor_commitment: String,
    pub covered_outputs: u64,
    pub fee_cap_micro_units: u64,
    pub sponsor_cover_bps: u64,
    pub rebate_bps: u64,
    pub reserved_fee_micro_units: u64,
    pub spent_fee_micro_units: u64,
    pub sponsorship_epoch: u64,
    pub sponsorship_root: String,
    pub low_fee_compliant: bool,
    pub status: SponsorshipStatus,
    pub fee_sponsorship_root: String,
}

impl ScanFeeSponsorship {
    pub fn from_input(input: ScanFeeSponsorshipInput, config: &Config) -> Result<Self> {
        ensure!(
            !input.sponsorship_id.is_empty(),
            "sponsorship_id is required"
        );
        ensure!(!input.bucket_id.is_empty(), "bucket_id is required");
        ensure!(
            !input.sponsor_commitment.is_empty() && !input.sponsorship_root.is_empty(),
            "sponsor commitment and root are required"
        );
        ensure!(input.covered_outputs > 0, "covered outputs required");
        ensure!(
            input.fee_cap_micro_units <= config.scan_fee_cap_micro_units,
            "fee cap exceeds configured cap"
        );
        ensure!(
            input.sponsor_cover_bps <= MAX_BPS && input.rebate_bps <= MAX_BPS,
            "sponsorship bps exceeds max"
        );
        ensure!(
            input.spent_fee_micro_units <= input.reserved_fee_micro_units,
            "spent fee exceeds reserved fee"
        );
        let low_fee_compliant = input.fee_cap_micro_units <= config.scan_fee_cap_micro_units
            && input.sponsor_cover_bps >= config.sponsor_cover_bps
            && input.rebate_bps >= config.low_fee_rebate_bps;
        let mut sponsorship = Self {
            sponsorship_id: input.sponsorship_id,
            bucket_id: input.bucket_id,
            sponsor_commitment: input.sponsor_commitment,
            covered_outputs: input.covered_outputs,
            fee_cap_micro_units: input.fee_cap_micro_units,
            sponsor_cover_bps: input.sponsor_cover_bps,
            rebate_bps: input.rebate_bps,
            reserved_fee_micro_units: input.reserved_fee_micro_units,
            spent_fee_micro_units: input.spent_fee_micro_units,
            sponsorship_epoch: input.sponsorship_epoch,
            sponsorship_root: input.sponsorship_root,
            low_fee_compliant,
            status: input.status,
            fee_sponsorship_root: String::new(),
        };
        sponsorship.fee_sponsorship_root = sponsorship.compute_root(config);
        Ok(sponsorship)
    }

    pub fn compute_root(&self, config: &Config) -> String {
        domain_hash(
            &config.scan_fee_sponsorship_scheme,
            &[HashPart::Json(&self.public_record_without_root())],
            32,
        )
    }

    pub fn remaining_fee_micro_units(&self) -> u64 {
        self.reserved_fee_micro_units
            .saturating_sub(self.spent_fee_micro_units)
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "sponsorship_id": self.sponsorship_id,
            "bucket_id": self.bucket_id,
            "sponsor_commitment": self.sponsor_commitment,
            "covered_outputs": self.covered_outputs,
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "rebate_bps": self.rebate_bps,
            "reserved_fee_micro_units": self.reserved_fee_micro_units,
            "spent_fee_micro_units": self.spent_fee_micro_units,
            "remaining_fee_micro_units": self.remaining_fee_micro_units(),
            "sponsorship_epoch": self.sponsorship_epoch,
            "sponsorship_root": self.sponsorship_root,
            "low_fee_compliant": self.low_fee_compliant,
            "status": self.status,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record["fee_sponsorship_root"] = json!(self.fee_sponsorship_root);
        record
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicRootEpochInput {
    pub epoch_id: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub viewtag_scan_bucket_root: String,
    pub clsag_decoy_entropy_floor_root: String,
    pub stealth_note_freshness_root: String,
    pub output_age_diversity_root: String,
    pub pq_migration_attestation_root: String,
    pub scan_fee_sponsorship_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicRootEpoch {
    pub epoch_id: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub viewtag_scan_bucket_root: String,
    pub clsag_decoy_entropy_floor_root: String,
    pub stealth_note_freshness_root: String,
    pub output_age_diversity_root: String,
    pub pq_migration_attestation_root: String,
    pub scan_fee_sponsorship_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub privacy_boundary: String,
    pub public_epoch_root: String,
}

impl PublicRootEpoch {
    pub fn from_input(input: PublicRootEpochInput, config: &Config) -> Result<Self> {
        ensure!(!input.epoch_id.is_empty(), "epoch_id is required");
        ensure!(
            !input.viewtag_scan_bucket_root.is_empty()
                && !input.clsag_decoy_entropy_floor_root.is_empty()
                && !input.stealth_note_freshness_root.is_empty()
                && !input.output_age_diversity_root.is_empty()
                && !input.pq_migration_attestation_root.is_empty()
                && !input.scan_fee_sponsorship_root.is_empty()
                && !input.redaction_budget_root.is_empty()
                && !input.operator_summary_root.is_empty(),
            "all public epoch roots are required"
        );
        let mut epoch = Self {
            epoch_id: input.epoch_id,
            l2_height: input.l2_height,
            monero_height: input.monero_height,
            viewtag_scan_bucket_root: input.viewtag_scan_bucket_root,
            clsag_decoy_entropy_floor_root: input.clsag_decoy_entropy_floor_root,
            stealth_note_freshness_root: input.stealth_note_freshness_root,
            output_age_diversity_root: input.output_age_diversity_root,
            pq_migration_attestation_root: input.pq_migration_attestation_root,
            scan_fee_sponsorship_root: input.scan_fee_sponsorship_root,
            redaction_budget_root: input.redaction_budget_root,
            operator_summary_root: input.operator_summary_root,
            privacy_boundary: config.privacy_boundary.clone(),
            public_epoch_root: String::new(),
        };
        epoch.public_epoch_root = epoch.compute_root(config);
        Ok(epoch)
    }

    pub fn compute_root(&self, config: &Config) -> String {
        domain_hash(
            &config.public_root_epoch_scheme,
            &[HashPart::Json(&self.public_record_without_root())],
            32,
        )
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "epoch_id": self.epoch_id,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "viewtag_scan_bucket_root": self.viewtag_scan_bucket_root,
            "clsag_decoy_entropy_floor_root": self.clsag_decoy_entropy_floor_root,
            "stealth_note_freshness_root": self.stealth_note_freshness_root,
            "output_age_diversity_root": self.output_age_diversity_root,
            "pq_migration_attestation_root": self.pq_migration_attestation_root,
            "scan_fee_sponsorship_root": self.scan_fee_sponsorship_root,
            "redaction_budget_root": self.redaction_budget_root,
            "operator_summary_root": self.operator_summary_root,
            "privacy_boundary": self.privacy_boundary,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record["public_epoch_root"] = json!(self.public_epoch_root);
        record
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub viewtag_scan_buckets: BTreeMap<String, ViewtagScanBucket>,
    pub clsag_decoy_entropy_floors: BTreeMap<String, ClsagDecoyEntropyFloor>,
    pub stealth_note_freshness_reports: BTreeMap<String, StealthNoteFreshness>,
    pub output_age_diversity_reports: BTreeMap<String, OutputAgeDiversity>,
    pub pq_migration_attestations: BTreeMap<String, PqMigrationAttestation>,
    pub scan_fee_sponsorships: BTreeMap<String, ScanFeeSponsorship>,
    pub public_root_epochs: BTreeMap<String, PublicRootEpoch>,
    pub bucket_index: BTreeMap<String, BTreeSet<String>>,
    pub quarantined_bucket_ids: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config, l2_height: u64, monero_height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            l2_height,
            monero_height,
            epoch,
            viewtag_scan_buckets: BTreeMap::new(),
            clsag_decoy_entropy_floors: BTreeMap::new(),
            stealth_note_freshness_reports: BTreeMap::new(),
            output_age_diversity_reports: BTreeMap::new(),
            pq_migration_attestations: BTreeMap::new(),
            scan_fee_sponsorships: BTreeMap::new(),
            public_root_epochs: BTreeMap::new(),
            bucket_index: BTreeMap::new(),
            quarantined_bucket_ids: BTreeSet::new(),
        };
        state.recompute_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        Self::new(
            Config::devnet(),
            DEVNET_L2_HEIGHT,
            DEVNET_MONERO_HEIGHT,
            DEVNET_EPOCH,
        )
        .expect("devnet config is valid")
    }

    pub fn add_viewtag_scan_bucket(
        &mut self,
        input: ViewtagScanBucketInput,
    ) -> Result<&ViewtagScanBucket> {
        let bucket = ViewtagScanBucket::from_input(input, &self.config)?;
        ensure!(
            !self.viewtag_scan_buckets.contains_key(&bucket.bucket_id),
            "duplicate viewtag scan bucket {}",
            bucket.bucket_id
        );
        let bucket_id = bucket.bucket_id.clone();
        let lane_key = bucket.lane.as_str().to_string();
        if bucket.status == BucketStatus::Quarantined {
            self.quarantined_bucket_ids.insert(bucket_id.clone());
            self.counters.quarantined_buckets += 1;
        }
        self.bucket_index
            .entry(lane_key)
            .or_default()
            .insert(bucket_id.clone());
        self.counters.viewtag_scan_buckets += 1;
        self.viewtag_scan_buckets.insert(bucket_id.clone(), bucket);
        self.recompute_roots();
        Ok(self
            .viewtag_scan_buckets
            .get(&bucket_id)
            .expect("bucket inserted"))
    }

    pub fn add_clsag_decoy_entropy_floor(
        &mut self,
        input: ClsagDecoyEntropyFloorInput,
    ) -> Result<&ClsagDecoyEntropyFloor> {
        ensure!(
            self.viewtag_scan_buckets.contains_key(&input.bucket_id),
            "unknown bucket for entropy floor {}",
            input.bucket_id
        );
        let floor = ClsagDecoyEntropyFloor::from_input(input, &self.config)?;
        ensure!(
            !self
                .clsag_decoy_entropy_floors
                .contains_key(&floor.floor_id),
            "duplicate entropy floor {}",
            floor.floor_id
        );
        if floor.below_floor || !floor.status.acceptable() {
            self.quarantined_bucket_ids.insert(floor.bucket_id.clone());
        }
        let floor_id = floor.floor_id.clone();
        self.counters.clsag_decoy_entropy_floors += 1;
        self.clsag_decoy_entropy_floors
            .insert(floor_id.clone(), floor);
        self.recompute_roots();
        Ok(self
            .clsag_decoy_entropy_floors
            .get(&floor_id)
            .expect("floor inserted"))
    }

    pub fn add_stealth_note_freshness(
        &mut self,
        input: StealthNoteFreshnessInput,
    ) -> Result<&StealthNoteFreshness> {
        ensure!(
            self.viewtag_scan_buckets.contains_key(&input.bucket_id),
            "unknown bucket for stealth note freshness {}",
            input.bucket_id
        );
        let freshness = StealthNoteFreshness::from_input(input, &self.config)?;
        ensure!(
            !self
                .stealth_note_freshness_reports
                .contains_key(&freshness.freshness_id),
            "duplicate freshness report {}",
            freshness.freshness_id
        );
        if freshness.stale_share_exceeded || !freshness.status.acceptable() {
            self.quarantined_bucket_ids
                .insert(freshness.bucket_id.clone());
        }
        let freshness_id = freshness.freshness_id.clone();
        self.counters.stealth_note_freshness_reports += 1;
        self.stealth_note_freshness_reports
            .insert(freshness_id.clone(), freshness);
        self.recompute_roots();
        Ok(self
            .stealth_note_freshness_reports
            .get(&freshness_id)
            .expect("freshness inserted"))
    }

    pub fn add_output_age_diversity(
        &mut self,
        input: OutputAgeDiversityInput,
    ) -> Result<&OutputAgeDiversity> {
        ensure!(
            self.viewtag_scan_buckets.contains_key(&input.bucket_id),
            "unknown bucket for output age diversity {}",
            input.bucket_id
        );
        let diversity = OutputAgeDiversity::from_input(input, &self.config)?;
        ensure!(
            !self
                .output_age_diversity_reports
                .contains_key(&diversity.diversity_id),
            "duplicate age diversity report {}",
            diversity.diversity_id
        );
        if diversity.recent_dominance || diversity.skew_exceeded || !diversity.status.acceptable() {
            self.quarantined_bucket_ids
                .insert(diversity.bucket_id.clone());
        }
        let diversity_id = diversity.diversity_id.clone();
        self.counters.output_age_diversity_reports += 1;
        self.output_age_diversity_reports
            .insert(diversity_id.clone(), diversity);
        self.recompute_roots();
        Ok(self
            .output_age_diversity_reports
            .get(&diversity_id)
            .expect("diversity inserted"))
    }

    pub fn add_pq_migration_attestation(
        &mut self,
        input: PqMigrationAttestationInput,
    ) -> Result<&PqMigrationAttestation> {
        ensure!(
            self.viewtag_scan_buckets.contains_key(&input.bucket_id),
            "unknown bucket for pq migration attestation {}",
            input.bucket_id
        );
        let attestation = PqMigrationAttestation::from_input(input, &self.config)?;
        ensure!(
            !self
                .pq_migration_attestations
                .contains_key(&attestation.attestation_id),
            "duplicate pq attestation {}",
            attestation.attestation_id
        );
        if !attestation.migration_safe || !attestation.status.valid() {
            self.quarantined_bucket_ids
                .insert(attestation.bucket_id.clone());
        }
        let attestation_id = attestation.attestation_id.clone();
        self.counters.pq_migration_attestations += 1;
        self.pq_migration_attestations
            .insert(attestation_id.clone(), attestation);
        self.recompute_roots();
        Ok(self
            .pq_migration_attestations
            .get(&attestation_id)
            .expect("attestation inserted"))
    }

    pub fn add_scan_fee_sponsorship(
        &mut self,
        input: ScanFeeSponsorshipInput,
    ) -> Result<&ScanFeeSponsorship> {
        ensure!(
            self.viewtag_scan_buckets.contains_key(&input.bucket_id),
            "unknown bucket for scan fee sponsorship {}",
            input.bucket_id
        );
        let sponsorship = ScanFeeSponsorship::from_input(input, &self.config)?;
        ensure!(
            !self
                .scan_fee_sponsorships
                .contains_key(&sponsorship.sponsorship_id),
            "duplicate scan fee sponsorship {}",
            sponsorship.sponsorship_id
        );
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        self.counters.scan_fee_sponsorships += 1;
        if sponsorship.low_fee_compliant && sponsorship.status.active() {
            self.counters.sponsored_low_fee_outputs += sponsorship.covered_outputs;
        }
        self.scan_fee_sponsorships
            .insert(sponsorship_id.clone(), sponsorship);
        self.recompute_roots();
        Ok(self
            .scan_fee_sponsorships
            .get(&sponsorship_id)
            .expect("sponsorship inserted"))
    }

    pub fn add_public_root_epoch(
        &mut self,
        input: PublicRootEpochInput,
    ) -> Result<&PublicRootEpoch> {
        ensure!(
            self.public_root_epochs.len() < self.config.max_public_records,
            "public root epoch capacity reached"
        );
        let epoch = PublicRootEpoch::from_input(input, &self.config)?;
        ensure!(
            !self.public_root_epochs.contains_key(&epoch.epoch_id),
            "duplicate public root epoch {}",
            epoch.epoch_id
        );
        let epoch_id = epoch.epoch_id.clone();
        self.counters.public_root_epochs += 1;
        self.counters.roots_only_public_records += 1;
        self.public_root_epochs.insert(epoch_id.clone(), epoch);
        self.recompute_roots();
        Ok(self
            .public_root_epochs
            .get(&epoch_id)
            .expect("public epoch inserted"))
    }

    pub fn advance_heights(&mut self, l2_height: u64, monero_height: u64) -> Result<()> {
        ensure!(
            l2_height >= self.l2_height,
            "cannot decrease l2 height from {} to {}",
            self.l2_height,
            l2_height
        );
        ensure!(
            monero_height >= self.monero_height,
            "cannot decrease monero height from {} to {}",
            self.monero_height,
            monero_height
        );
        self.l2_height = l2_height;
        self.monero_height = monero_height;
        self.epoch = l2_height / self.config.public_record_epoch_blocks;
        self.expire_old_records();
        self.recompute_roots();
        Ok(())
    }

    pub fn bucket_health_score_bps(&self, bucket_id: &str) -> Option<u64> {
        let bucket = self.viewtag_scan_buckets.get(bucket_id)?;
        let entropy = self
            .clsag_decoy_entropy_floors
            .values()
            .filter(|floor| floor.bucket_id == bucket_id)
            .map(|floor| floor.floor_score_bps)
            .max()
            .unwrap_or(bucket.viewtag_entropy_bps);
        let freshness = self
            .stealth_note_freshness_reports
            .values()
            .filter(|report| report.bucket_id == bucket_id)
            .map(|report| report.freshness_score_bps)
            .max()
            .unwrap_or(self.config.min_stealth_freshness_bps);
        let diversity = self
            .output_age_diversity_reports
            .values()
            .filter(|report| report.bucket_id == bucket_id)
            .map(|report| report.age_diversity_bps)
            .max()
            .unwrap_or(self.config.min_age_diversity_bps);
        let pq = self
            .pq_migration_attestations
            .values()
            .filter(|attestation| attestation.bucket_id == bucket_id)
            .map(|attestation| {
                if attestation.migration_safe {
                    MAX_BPS
                } else {
                    attestation.quorum_bps
                }
            })
            .max()
            .unwrap_or(self.config.min_pq_attestation_quorum_bps);
        Some((entropy + freshness + diversity + pq) / 4)
    }

    pub fn lane_bucket_ids(&self, lane: ScanLane) -> Vec<String> {
        self.bucket_index
            .get(lane.as_str())
            .map(|ids| ids.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "l2_network": self.config.l2_network,
            "monero_network": self.config.monero_network,
            "fee_asset_id": self.config.fee_asset_id,
            "privacy_boundary": self.config.privacy_boundary,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn recompute_roots(&mut self) {
        let config_record = self.config.public_record();
        let counters_record = self.counters.public_record();
        self.roots.config_root = domain_hash(
            "jamtis-clsag-viewtag-decoy-entropy-config-root",
            &[HashPart::Json(&config_record)],
            32,
        );
        self.roots.counters_root = domain_hash(
            "jamtis-clsag-viewtag-decoy-entropy-counters-root",
            &[HashPart::Json(&counters_record)],
            32,
        );
        self.roots.viewtag_scan_bucket_root = merkle_root(
            &self.config.viewtag_scan_bucket_scheme,
            &self
                .viewtag_scan_buckets
                .values()
                .map(ViewtagScanBucket::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.clsag_decoy_entropy_floor_root = merkle_root(
            &self.config.clsag_decoy_entropy_floor_scheme,
            &self
                .clsag_decoy_entropy_floors
                .values()
                .map(ClsagDecoyEntropyFloor::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.stealth_note_freshness_root = merkle_root(
            &self.config.stealth_note_freshness_scheme,
            &self
                .stealth_note_freshness_reports
                .values()
                .map(StealthNoteFreshness::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.output_age_diversity_root = merkle_root(
            &self.config.output_age_diversity_scheme,
            &self
                .output_age_diversity_reports
                .values()
                .map(OutputAgeDiversity::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.pq_migration_attestation_root = merkle_root(
            &self.config.pq_migration_attestation_scheme,
            &self
                .pq_migration_attestations
                .values()
                .map(PqMigrationAttestation::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.scan_fee_sponsorship_root = merkle_root(
            &self.config.scan_fee_sponsorship_scheme,
            &self
                .scan_fee_sponsorships
                .values()
                .map(ScanFeeSponsorship::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.public_root_epoch_root = merkle_root(
            &self.config.public_root_epoch_scheme,
            &self
                .public_root_epochs
                .values()
                .map(PublicRootEpoch::public_record)
                .collect::<Vec<_>>(),
        );
        let state_record = json!({
            "config_root": self.roots.config_root,
            "counters_root": self.roots.counters_root,
            "viewtag_scan_bucket_root": self.roots.viewtag_scan_bucket_root,
            "clsag_decoy_entropy_floor_root": self.roots.clsag_decoy_entropy_floor_root,
            "stealth_note_freshness_root": self.roots.stealth_note_freshness_root,
            "output_age_diversity_root": self.roots.output_age_diversity_root,
            "pq_migration_attestation_root": self.roots.pq_migration_attestation_root,
            "scan_fee_sponsorship_root": self.roots.scan_fee_sponsorship_root,
            "public_root_epoch_root": self.roots.public_root_epoch_root,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "privacy_boundary": self.config.privacy_boundary,
        });
        self.roots.state_root = domain_hash(
            "jamtis-clsag-viewtag-decoy-entropy-state-root",
            &[HashPart::Json(&state_record)],
            32,
        );
    }

    fn expire_old_records(&mut self) {
        for bucket in self.viewtag_scan_buckets.values_mut() {
            if bucket.expired(self.monero_height) && bucket.status.public_usable() {
                bucket.status = BucketStatus::Expired;
            }
        }
        for attestation in self.pq_migration_attestations.values_mut() {
            if attestation.expired(self.monero_height) && attestation.status.valid() {
                attestation.status = PqAttestationStatus::Expired;
            }
        }
    }
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}
