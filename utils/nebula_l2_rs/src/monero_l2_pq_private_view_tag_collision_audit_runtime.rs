use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateViewTagCollisionAuditRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const MONERO_L2_PQ_PRIVATE_VIEW_TAG_COLLISION_AUDIT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-view-tag-collision-audit-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_VIEW_TAG_COLLISION_AUDIT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 1_432_800;
pub const DEVNET_EPOCH: u64 = 2_912;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const COLLISION_BUCKET_SCHEME: &str = "monero-private-view-tag-collision-bucket-root-v1";
pub const FALSE_POSITIVE_SAMPLE_SCHEME: &str = "private-view-tag-false-positive-sample-root-v1";
pub const PQ_AUDITOR_COHORT_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-192f-view-tag-auditor-cohort-root-v1";
pub const WALLET_REDACTION_WINDOW_SCHEME: &str =
    "operator-safe-wallet-view-tag-redaction-window-root-v1";
pub const LOW_FEE_AUDIT_BATCH_SCHEME: &str = "low-fee-view-tag-collision-audit-batch-root-v1";
pub const QUARANTINE_SCHEME: &str = "private-view-tag-collision-quarantine-root-v1";
pub const SLASHING_SCHEME: &str = "view-tag-collision-auditor-slashing-root-v1";
pub const PUBLIC_ROOT_SCHEME: &str = "public-view-tag-collision-audit-roots-v1";
pub const DEFAULT_AUDIT_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_BUCKET_SPAN_BLOCKS: u64 = 90;
pub const DEFAULT_SAMPLE_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_REDACTION_WINDOW_BLOCKS: u64 = 2_880;
pub const DEFAULT_BATCH_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_BUCKET_OUTPUTS: u32 = 512;
pub const DEFAULT_MAX_FALSE_POSITIVE_MICROS: u32 = 3_900;
pub const DEFAULT_MIN_SAMPLE_RATE_BPS: u16 = 250;
pub const DEFAULT_MIN_AUDITOR_COHORT_SIZE: u16 = 3;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_LOW_FEE_CAP_MICRO_UNITS: u64 = 2_500;
pub const DEFAULT_AUDITOR_BOND_MICRO_UNITS: u64 = 25_000_000;
pub const DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_SLASH_BPS: u16 = 1_250;
pub const MAX_BPS: u16 = 10_000;
pub const MAX_COLLISION_BUCKETS: usize = 2_097_152;
pub const MAX_FALSE_POSITIVE_SAMPLES: usize = 2_097_152;
pub const MAX_AUDITOR_COHORTS: usize = 524_288;
pub const MAX_REDACTION_WINDOWS: usize = 524_288;
pub const MAX_AUDIT_BATCHES: usize = 524_288;
pub const MAX_QUARANTINES: usize = 262_144;
pub const MAX_SLASHING_RECORDS: usize = 262_144;
pub const MAX_PUBLIC_ROOTS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditLane {
    BackgroundWallet,
    MobileFastScan,
    MerchantCheckout,
    WatchOnly,
    ReorgRepair,
    Emergency,
}

impl AuditLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BackgroundWallet => "background_wallet",
            Self::MobileFastScan => "mobile_fast_scan",
            Self::MerchantCheckout => "merchant_checkout",
            Self::WatchOnly => "watch_only",
            Self::ReorgRepair => "reorg_repair",
            Self::Emergency => "emergency",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 1_000,
            Self::ReorgRepair => 940,
            Self::MerchantCheckout => 880,
            Self::MobileFastScan => 830,
            Self::WatchOnly => 760,
            Self::BackgroundWallet => 700,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordStatus {
    Draft,
    Open,
    Sampled,
    Attested,
    Batched,
    Quarantined,
    Slashed,
    Settled,
    Expired,
    Rejected,
}

impl RecordStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::Sampled => "sampled",
            Self::Attested => "attested",
            Self::Batched => "batched",
            Self::Quarantined => "quarantined",
            Self::Slashed => "slashed",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Sampled | Self::Attested | Self::Batched
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SampleKind {
    UniformBucket,
    CollisionHeavyTail,
    MobileLatency,
    MerchantCheckout,
    ReorgReplay,
    AuditorDispute,
}

impl SampleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UniformBucket => "uniform_bucket",
            Self::CollisionHeavyTail => "collision_heavy_tail",
            Self::MobileLatency => "mobile_latency",
            Self::MerchantCheckout => "merchant_checkout",
            Self::ReorgReplay => "reorg_replay",
            Self::AuditorDispute => "auditor_dispute",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortStatus {
    Forming,
    Attested,
    Active,
    Quarantined,
    Retired,
    Slashed,
}

impl CohortStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Forming => "forming",
            Self::Attested => "attested",
            Self::Active => "active",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashReason {
    InvalidCollisionClaim,
    MissingFalsePositiveSample,
    LeakedWalletWindow,
    WeakPqAttestation,
    StaleBucketRoot,
}

impl SlashReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidCollisionClaim => "invalid_collision_claim",
            Self::MissingFalsePositiveSample => "missing_false_positive_sample",
            Self::LeakedWalletWindow => "leaked_wallet_window",
            Self::WeakPqAttestation => "weak_pq_attestation",
            Self::StaleBucketRoot => "stale_bucket_root",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub collision_bucket_scheme: String,
    pub false_positive_sample_scheme: String,
    pub pq_auditor_cohort_scheme: String,
    pub wallet_redaction_window_scheme: String,
    pub low_fee_audit_batch_scheme: String,
    pub quarantine_scheme: String,
    pub slashing_scheme: String,
    pub public_root_scheme: String,
    pub audit_window_blocks: u64,
    pub bucket_span_blocks: u64,
    pub sample_ttl_blocks: u64,
    pub redaction_window_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_bucket_outputs: u32,
    pub max_false_positive_micros: u32,
    pub min_sample_rate_bps: u16,
    pub min_auditor_cohort_size: u16,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub low_fee_cap_micro_units: u64,
    pub auditor_bond_micro_units: u64,
    pub quarantine_ttl_blocks: u64,
    pub slash_bps: u16,
    pub require_wallet_redaction: bool,
    pub allow_low_fee_batches: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            collision_bucket_scheme: COLLISION_BUCKET_SCHEME.to_string(),
            false_positive_sample_scheme: FALSE_POSITIVE_SAMPLE_SCHEME.to_string(),
            pq_auditor_cohort_scheme: PQ_AUDITOR_COHORT_SCHEME.to_string(),
            wallet_redaction_window_scheme: WALLET_REDACTION_WINDOW_SCHEME.to_string(),
            low_fee_audit_batch_scheme: LOW_FEE_AUDIT_BATCH_SCHEME.to_string(),
            quarantine_scheme: QUARANTINE_SCHEME.to_string(),
            slashing_scheme: SLASHING_SCHEME.to_string(),
            public_root_scheme: PUBLIC_ROOT_SCHEME.to_string(),
            audit_window_blocks: DEFAULT_AUDIT_WINDOW_BLOCKS,
            bucket_span_blocks: DEFAULT_BUCKET_SPAN_BLOCKS,
            sample_ttl_blocks: DEFAULT_SAMPLE_TTL_BLOCKS,
            redaction_window_blocks: DEFAULT_REDACTION_WINDOW_BLOCKS,
            batch_ttl_blocks: DEFAULT_BATCH_TTL_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_bucket_outputs: DEFAULT_MIN_BUCKET_OUTPUTS,
            max_false_positive_micros: DEFAULT_MAX_FALSE_POSITIVE_MICROS,
            min_sample_rate_bps: DEFAULT_MIN_SAMPLE_RATE_BPS,
            min_auditor_cohort_size: DEFAULT_MIN_AUDITOR_COHORT_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            low_fee_cap_micro_units: DEFAULT_LOW_FEE_CAP_MICRO_UNITS,
            auditor_bond_micro_units: DEFAULT_AUDITOR_BOND_MICRO_UNITS,
            quarantine_ttl_blocks: DEFAULT_QUARANTINE_TTL_BLOCKS,
            slash_bps: DEFAULT_SLASH_BPS,
            require_wallet_redaction: true,
            allow_low_fee_batches: true,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.chain_id == CHAIN_ID,
            "unsupported chain id {}",
            self.chain_id
        );
        ensure!(
            self.protocol_version == PROTOCOL_VERSION,
            "unsupported protocol version {}",
            self.protocol_version
        );
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "unsupported schema version"
        );
        ensure!(!self.l2_network.is_empty(), "l2 network is required");
        ensure!(
            !self.monero_network.is_empty(),
            "monero network is required"
        );
        ensure!(!self.fee_asset_id.is_empty(), "fee asset id is required");
        ensure!(self.audit_window_blocks > 0, "audit window must be nonzero");
        ensure!(self.bucket_span_blocks > 0, "bucket span must be nonzero");
        ensure!(
            self.audit_window_blocks >= self.bucket_span_blocks,
            "audit window must cover at least one bucket"
        );
        ensure!(
            self.min_privacy_set_size >= 16_384,
            "privacy set is too small for private collision audits"
        );
        ensure!(
            self.max_false_positive_micros <= 100_000,
            "false-positive ceiling is too loose"
        );
        ensure!(
            self.min_sample_rate_bps <= MAX_BPS,
            "sample rate exceeds bps denominator"
        );
        ensure!(
            self.slash_bps <= MAX_BPS,
            "slash bps exceeds bps denominator"
        );
        ensure!(
            self.min_auditor_cohort_size > 0,
            "auditor cohort size must be nonzero"
        );
        ensure!(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "minimum pq security below runtime floor"
        );
        ensure!(
            self.target_pq_security_bits >= self.min_pq_security_bits,
            "target pq security must cover minimum"
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "collision_bucket_scheme": self.collision_bucket_scheme,
            "false_positive_sample_scheme": self.false_positive_sample_scheme,
            "pq_auditor_cohort_scheme": self.pq_auditor_cohort_scheme,
            "wallet_redaction_window_scheme": self.wallet_redaction_window_scheme,
            "low_fee_audit_batch_scheme": self.low_fee_audit_batch_scheme,
            "quarantine_scheme": self.quarantine_scheme,
            "slashing_scheme": self.slashing_scheme,
            "public_root_scheme": self.public_root_scheme,
            "audit_window_blocks": self.audit_window_blocks,
            "bucket_span_blocks": self.bucket_span_blocks,
            "sample_ttl_blocks": self.sample_ttl_blocks,
            "redaction_window_blocks": self.redaction_window_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_bucket_outputs": self.min_bucket_outputs,
            "max_false_positive_micros": self.max_false_positive_micros,
            "min_sample_rate_bps": self.min_sample_rate_bps,
            "min_auditor_cohort_size": self.min_auditor_cohort_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "low_fee_cap_micro_units": self.low_fee_cap_micro_units,
            "auditor_bond_micro_units": self.auditor_bond_micro_units,
            "quarantine_ttl_blocks": self.quarantine_ttl_blocks,
            "slash_bps": self.slash_bps,
            "require_wallet_redaction": self.require_wallet_redaction,
            "allow_low_fee_batches": self.allow_low_fee_batches,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub collision_buckets: u64,
    pub active_collision_buckets: u64,
    pub false_positive_samples: u64,
    pub auditor_cohorts: u64,
    pub active_auditor_cohorts: u64,
    pub wallet_redaction_windows: u64,
    pub low_fee_audit_batches: u64,
    pub quarantines: u64,
    pub slashing_records: u64,
    pub public_roots: u64,
    pub total_bucket_outputs: u64,
    pub observed_collisions: u64,
    pub sampled_false_positives: u64,
    pub low_fee_micro_units: u64,
    pub slashed_micro_units: u64,
    pub min_observed_privacy_set_size: u64,
    pub max_observed_false_positive_micros: u32,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "collision_buckets": self.collision_buckets,
            "active_collision_buckets": self.active_collision_buckets,
            "false_positive_samples": self.false_positive_samples,
            "auditor_cohorts": self.auditor_cohorts,
            "active_auditor_cohorts": self.active_auditor_cohorts,
            "wallet_redaction_windows": self.wallet_redaction_windows,
            "low_fee_audit_batches": self.low_fee_audit_batches,
            "quarantines": self.quarantines,
            "slashing_records": self.slashing_records,
            "public_roots": self.public_roots,
            "total_bucket_outputs": self.total_bucket_outputs,
            "observed_collisions": self.observed_collisions,
            "sampled_false_positives": self.sampled_false_positives,
            "low_fee_micro_units": self.low_fee_micro_units,
            "slashed_micro_units": self.slashed_micro_units,
            "min_observed_privacy_set_size": self.min_observed_privacy_set_size,
            "max_observed_false_positive_micros": self.max_observed_false_positive_micros,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub collision_bucket_root: String,
    pub false_positive_sample_root: String,
    pub auditor_cohort_root: String,
    pub wallet_redaction_window_root: String,
    pub low_fee_audit_batch_root: String,
    pub quarantine_root: String,
    pub slashing_root: String,
    pub public_root: String,
    pub operator_summary_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "collision_bucket_root": self.collision_bucket_root,
            "false_positive_sample_root": self.false_positive_sample_root,
            "auditor_cohort_root": self.auditor_cohort_root,
            "wallet_redaction_window_root": self.wallet_redaction_window_root,
            "low_fee_audit_batch_root": self.low_fee_audit_batch_root,
            "quarantine_root": self.quarantine_root,
            "slashing_root": self.slashing_root,
            "public_root": self.public_root,
            "operator_summary_root": self.operator_summary_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CollisionBucketRequest {
    pub wallet_group_commitment: String,
    pub lane: AuditLane,
    pub view_tag_prefix_commitment: String,
    pub encrypted_bucket_root: String,
    pub output_commitment_root: String,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
    pub bucket_outputs: u32,
    pub observed_collisions: u32,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CollisionBucket {
    pub bucket_id: String,
    pub wallet_group_commitment: String,
    pub lane: AuditLane,
    pub view_tag_prefix_commitment: String,
    pub encrypted_bucket_root: String,
    pub output_commitment_root: String,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
    pub bucket_outputs: u32,
    pub observed_collisions: u32,
    pub privacy_set_size: u64,
    pub status: RecordStatus,
}

impl CollisionBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "wallet_group_commitment": self.wallet_group_commitment,
            "lane": self.lane.as_str(),
            "view_tag_prefix_commitment": self.view_tag_prefix_commitment,
            "encrypted_bucket_root": self.encrypted_bucket_root,
            "output_commitment_root": self.output_commitment_root,
            "monero_start_height": self.monero_start_height,
            "monero_end_height": self.monero_end_height,
            "bucket_outputs": self.bucket_outputs,
            "observed_collisions": self.observed_collisions,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FalsePositiveSample {
    pub sample_id: String,
    pub bucket_id: String,
    pub sample_kind: SampleKind,
    pub sample_commitment_root: String,
    pub sampled_outputs: u32,
    pub false_positive_hits: u32,
    pub false_positive_micros: u32,
    pub expires_height: u64,
    pub status: RecordStatus,
}

impl FalsePositiveSample {
    pub fn public_record(&self) -> Value {
        json!({
            "sample_id": self.sample_id,
            "bucket_id": self.bucket_id,
            "sample_kind": self.sample_kind.as_str(),
            "sample_commitment_root": self.sample_commitment_root,
            "sampled_outputs": self.sampled_outputs,
            "false_positive_hits": self.false_positive_hits,
            "false_positive_micros": self.false_positive_micros,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAuditorCohort {
    pub cohort_id: String,
    pub auditor_commitment_root: String,
    pub attestation_root: String,
    pub signature_commitment_root: String,
    pub member_count: u16,
    pub pq_security_bits: u16,
    pub bond_micro_units: u64,
    pub assigned_bucket_ids: BTreeSet<String>,
    pub status: CohortStatus,
}

impl PqAuditorCohort {
    pub fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "auditor_commitment_root": self.auditor_commitment_root,
            "attestation_root": self.attestation_root,
            "signature_commitment_root": self.signature_commitment_root,
            "member_count": self.member_count,
            "pq_security_bits": self.pq_security_bits,
            "bond_micro_units": self.bond_micro_units,
            "assigned_bucket_ids": self.assigned_bucket_ids,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletRedactionWindow {
    pub redaction_id: String,
    pub wallet_group_commitment: String,
    pub operator_id: String,
    pub redacted_field_root: String,
    pub public_summary_root: String,
    pub start_height: u64,
    pub end_height: u64,
    pub reason: String,
    pub status: RecordStatus,
}

impl WalletRedactionWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "redaction_id": self.redaction_id,
            "wallet_group_commitment": self.wallet_group_commitment,
            "operator_id": self.operator_id,
            "redacted_field_root": self.redacted_field_root,
            "public_summary_root": self.public_summary_root,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "reason": self.reason,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeAuditBatch {
    pub batch_id: String,
    pub cohort_id: String,
    pub bucket_ids: BTreeSet<String>,
    pub fee_micro_units: u64,
    pub fee_asset_id: String,
    pub batch_root: String,
    pub expires_height: u64,
    pub status: RecordStatus,
}

impl LowFeeAuditBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "cohort_id": self.cohort_id,
            "bucket_ids": self.bucket_ids,
            "fee_micro_units": self.fee_micro_units,
            "fee_asset_id": self.fee_asset_id,
            "batch_root": self.batch_root,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuarantineRecord {
    pub quarantine_id: String,
    pub subject_id: String,
    pub subject_kind: String,
    pub reason_root: String,
    pub opened_height: u64,
    pub expires_height: u64,
    pub status: RecordStatus,
}

impl QuarantineRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "subject_id": self.subject_id,
            "subject_kind": self.subject_kind,
            "reason_root": self.reason_root,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingRecord {
    pub slash_id: String,
    pub cohort_id: String,
    pub subject_id: String,
    pub reason: SlashReason,
    pub evidence_root: String,
    pub slash_amount_micro_units: u64,
    pub slashed_height: u64,
}

impl SlashingRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "slash_id": self.slash_id,
            "cohort_id": self.cohort_id,
            "subject_id": self.subject_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "slash_amount_micro_units": self.slash_amount_micro_units,
            "slashed_height": self.slashed_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicRootRecord {
    pub root_id: String,
    pub epoch: u64,
    pub collision_bucket_root: String,
    pub false_positive_sample_root: String,
    pub auditor_cohort_root: String,
    pub quarantine_root: String,
    pub redaction_root: String,
    pub published_height: u64,
}

impl PublicRootRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "root_id": self.root_id,
            "epoch": self.epoch,
            "collision_bucket_root": self.collision_bucket_root,
            "false_positive_sample_root": self.false_positive_sample_root,
            "auditor_cohort_root": self.auditor_cohort_root,
            "quarantine_root": self.quarantine_root,
            "redaction_root": self.redaction_root,
            "published_height": self.published_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub collision_buckets: BTreeMap<String, CollisionBucket>,
    pub false_positive_samples: BTreeMap<String, FalsePositiveSample>,
    pub auditor_cohorts: BTreeMap<String, PqAuditorCohort>,
    pub wallet_redaction_windows: BTreeMap<String, WalletRedactionWindow>,
    pub low_fee_audit_batches: BTreeMap<String, LowFeeAuditBatch>,
    pub quarantines: BTreeMap<String, QuarantineRecord>,
    pub slashing_records: BTreeMap<String, SlashingRecord>,
    pub public_roots: BTreeMap<String, PublicRootRecord>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default(), DEVNET_HEIGHT, DEVNET_EPOCH)
    }
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Self {
        Self {
            config,
            height,
            epoch,
            collision_buckets: BTreeMap::new(),
            false_positive_samples: BTreeMap::new(),
            auditor_cohorts: BTreeMap::new(),
            wallet_redaction_windows: BTreeMap::new(),
            low_fee_audit_batches: BTreeMap::new(),
            quarantines: BTreeMap::new(),
            slashing_records: BTreeMap::new(),
            public_roots: BTreeMap::new(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        ensure!(
            self.collision_buckets.len() <= MAX_COLLISION_BUCKETS,
            "too many collision buckets"
        );
        ensure!(
            self.false_positive_samples.len() <= MAX_FALSE_POSITIVE_SAMPLES,
            "too many false-positive samples"
        );
        ensure!(
            self.auditor_cohorts.len() <= MAX_AUDITOR_COHORTS,
            "too many auditor cohorts"
        );
        ensure!(
            self.wallet_redaction_windows.len() <= MAX_REDACTION_WINDOWS,
            "too many wallet redaction windows"
        );
        ensure!(
            self.low_fee_audit_batches.len() <= MAX_AUDIT_BATCHES,
            "too many low-fee audit batches"
        );
        ensure!(
            self.quarantines.len() <= MAX_QUARANTINES,
            "too many quarantines"
        );
        ensure!(
            self.slashing_records.len() <= MAX_SLASHING_RECORDS,
            "too many slashing records"
        );
        ensure!(
            self.public_roots.len() <= MAX_PUBLIC_ROOTS,
            "too many public roots"
        );
        for bucket in self.collision_buckets.values() {
            ensure!(
                bucket.monero_start_height <= bucket.monero_end_height,
                "bucket {} has invalid height range",
                bucket.bucket_id
            );
            ensure!(
                bucket.bucket_outputs >= self.config.min_bucket_outputs,
                "bucket {} below output floor",
                bucket.bucket_id
            );
            ensure!(
                bucket.privacy_set_size >= self.config.min_privacy_set_size,
                "bucket {} privacy set below floor",
                bucket.bucket_id
            );
        }
        for sample in self.false_positive_samples.values() {
            ensure!(
                self.collision_buckets.contains_key(&sample.bucket_id),
                "sample {} references unknown bucket",
                sample.sample_id
            );
            ensure!(
                sample.false_positive_micros <= self.config.max_false_positive_micros,
                "sample {} exceeds false-positive ceiling",
                sample.sample_id
            );
        }
        for cohort in self.auditor_cohorts.values() {
            ensure!(
                cohort.member_count >= self.config.min_auditor_cohort_size,
                "cohort {} below member floor",
                cohort.cohort_id
            );
            ensure!(
                cohort.pq_security_bits >= self.config.min_pq_security_bits,
                "cohort {} below pq security floor",
                cohort.cohort_id
            );
        }
        Ok(())
    }

    pub fn counters(&self) -> Counters {
        let active_collision_buckets = self
            .collision_buckets
            .values()
            .filter(|bucket| bucket.status.live())
            .count() as u64;
        let active_auditor_cohorts = self
            .auditor_cohorts
            .values()
            .filter(|cohort| matches!(cohort.status, CohortStatus::Attested | CohortStatus::Active))
            .count() as u64;
        let total_bucket_outputs = self
            .collision_buckets
            .values()
            .map(|bucket| u64::from(bucket.bucket_outputs))
            .sum();
        let observed_collisions = self
            .collision_buckets
            .values()
            .map(|bucket| u64::from(bucket.observed_collisions))
            .sum();
        let sampled_false_positives = self
            .false_positive_samples
            .values()
            .map(|sample| u64::from(sample.false_positive_hits))
            .sum();
        let low_fee_micro_units = self
            .low_fee_audit_batches
            .values()
            .map(|batch| batch.fee_micro_units)
            .sum();
        let slashed_micro_units = self
            .slashing_records
            .values()
            .map(|slash| slash.slash_amount_micro_units)
            .sum();
        let min_observed_privacy_set_size = self
            .collision_buckets
            .values()
            .map(|bucket| bucket.privacy_set_size)
            .min()
            .unwrap_or(self.config.min_privacy_set_size);
        let max_observed_false_positive_micros = self
            .false_positive_samples
            .values()
            .map(|sample| sample.false_positive_micros)
            .max()
            .unwrap_or(0);
        Counters {
            collision_buckets: self.collision_buckets.len() as u64,
            active_collision_buckets,
            false_positive_samples: self.false_positive_samples.len() as u64,
            auditor_cohorts: self.auditor_cohorts.len() as u64,
            active_auditor_cohorts,
            wallet_redaction_windows: self.wallet_redaction_windows.len() as u64,
            low_fee_audit_batches: self.low_fee_audit_batches.len() as u64,
            quarantines: self.quarantines.len() as u64,
            slashing_records: self.slashing_records.len() as u64,
            public_roots: self.public_roots.len() as u64,
            total_bucket_outputs,
            observed_collisions,
            sampled_false_positives,
            low_fee_micro_units,
            slashed_micro_units,
            min_observed_privacy_set_size,
            max_observed_false_positive_micros,
        }
    }

    pub fn refresh_roots(&self) -> Roots {
        self.roots()
    }

    pub fn roots(&self) -> Roots {
        let config_root = domain_hash(
            "VIEW-TAG-COLLISION-AUDIT-CONFIG",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Json(&self.config.public_record()),
            ],
            32,
        );
        let bucket_records = values_public_records(&self.collision_buckets);
        let sample_records = values_public_records(&self.false_positive_samples);
        let cohort_records = values_public_records(&self.auditor_cohorts);
        let redaction_records = values_public_records(&self.wallet_redaction_windows);
        let batch_records = values_public_records(&self.low_fee_audit_batches);
        let quarantine_records = values_public_records(&self.quarantines);
        let slashing_records = values_public_records(&self.slashing_records);
        let public_root_records = values_public_records(&self.public_roots);
        let operator_summary_records = vec![self.operator_safe_summary()];
        let mut roots = Roots {
            config_root,
            collision_bucket_root: merkle_root("VIEW-TAG-COLLISION-AUDIT-BUCKET", &bucket_records),
            false_positive_sample_root: merkle_root(
                "VIEW-TAG-COLLISION-AUDIT-FALSE-POSITIVE-SAMPLE",
                &sample_records,
            ),
            auditor_cohort_root: merkle_root(
                "VIEW-TAG-COLLISION-AUDIT-AUDITOR-COHORT",
                &cohort_records,
            ),
            wallet_redaction_window_root: merkle_root(
                "VIEW-TAG-COLLISION-AUDIT-WALLET-REDACTION",
                &redaction_records,
            ),
            low_fee_audit_batch_root: merkle_root(
                "VIEW-TAG-COLLISION-AUDIT-LOW-FEE-BATCH",
                &batch_records,
            ),
            quarantine_root: merkle_root(
                "VIEW-TAG-COLLISION-AUDIT-QUARANTINE",
                &quarantine_records,
            ),
            slashing_root: merkle_root("VIEW-TAG-COLLISION-AUDIT-SLASHING", &slashing_records),
            public_root: merkle_root("VIEW-TAG-COLLISION-AUDIT-PUBLIC-ROOT", &public_root_records),
            operator_summary_root: merkle_root(
                "VIEW-TAG-COLLISION-AUDIT-OPERATOR-SUMMARY",
                &operator_summary_records,
            ),
            state_root: String::new(),
        };
        roots.state_root = collision_audit_state_root_from_record(&json!({
            "height": self.height,
            "epoch": self.epoch,
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
        }));
        roots
    }

    pub fn operator_safe_summary(&self) -> Value {
        let counters = self.counters();
        json!({
            "protocol_version": self.config.protocol_version,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "epoch": self.epoch,
            "l2_network": self.config.l2_network,
            "monero_network": self.config.monero_network,
            "collision_buckets": counters.collision_buckets,
            "active_collision_buckets": counters.active_collision_buckets,
            "false_positive_samples": counters.false_positive_samples,
            "auditor_cohorts": counters.auditor_cohorts,
            "active_auditor_cohorts": counters.active_auditor_cohorts,
            "wallet_redaction_windows": counters.wallet_redaction_windows,
            "low_fee_audit_batches": counters.low_fee_audit_batches,
            "quarantines": counters.quarantines,
            "slashing_records": counters.slashing_records,
            "total_bucket_outputs": counters.total_bucket_outputs,
            "observed_collisions": counters.observed_collisions,
            "sampled_false_positives": counters.sampled_false_positives,
            "low_fee_micro_units": counters.low_fee_micro_units,
            "slashed_micro_units": counters.slashed_micro_units,
            "min_observed_privacy_set_size": counters.min_observed_privacy_set_size,
            "max_observed_false_positive_micros": counters.max_observed_false_positive_micros,
        })
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
            "operator_safe_summary": self.operator_safe_summary(),
            "state_root": roots.state_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn insert_collision_bucket(&mut self, request: CollisionBucketRequest) -> Result<String> {
        ensure!(
            request.monero_start_height <= request.monero_end_height,
            "invalid collision bucket height range"
        );
        ensure!(
            request.bucket_outputs >= self.config.min_bucket_outputs,
            "collision bucket below output floor"
        );
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set below configured floor"
        );
        let bucket_id = collision_bucket_id(&request);
        let record = CollisionBucket {
            bucket_id: bucket_id.clone(),
            wallet_group_commitment: request.wallet_group_commitment,
            lane: request.lane,
            view_tag_prefix_commitment: request.view_tag_prefix_commitment,
            encrypted_bucket_root: request.encrypted_bucket_root,
            output_commitment_root: request.output_commitment_root,
            monero_start_height: request.monero_start_height,
            monero_end_height: request.monero_end_height,
            bucket_outputs: request.bucket_outputs,
            observed_collisions: request.observed_collisions,
            privacy_set_size: request.privacy_set_size,
            status: RecordStatus::Open,
        };
        self.collision_buckets.insert(bucket_id.clone(), record);
        Ok(bucket_id)
    }

    pub fn devnet() -> Self {
        let mut state = Self::default();
        let primary = state
            .insert_collision_bucket(CollisionBucketRequest {
                wallet_group_commitment: devnet_payload_root("wallet-group", "mobile-watchers"),
                lane: AuditLane::MobileFastScan,
                view_tag_prefix_commitment: devnet_payload_root("view-tag-prefix", "vt-4f"),
                encrypted_bucket_root: devnet_payload_root("encrypted-bucket", "mobile-4f"),
                output_commitment_root: devnet_payload_root("outputs", "mobile-4f"),
                monero_start_height: DEVNET_HEIGHT - 180,
                monero_end_height: DEVNET_HEIGHT - 91,
                bucket_outputs: 4_096,
                observed_collisions: 21,
                privacy_set_size: 196_608,
            })
            .expect("devnet primary collision bucket");
        let merchant = state
            .insert_collision_bucket(CollisionBucketRequest {
                wallet_group_commitment: devnet_payload_root("wallet-group", "merchant-pos"),
                lane: AuditLane::MerchantCheckout,
                view_tag_prefix_commitment: devnet_payload_root("view-tag-prefix", "vt-a8"),
                encrypted_bucket_root: devnet_payload_root("encrypted-bucket", "merchant-a8"),
                output_commitment_root: devnet_payload_root("outputs", "merchant-a8"),
                monero_start_height: DEVNET_HEIGHT - 90,
                monero_end_height: DEVNET_HEIGHT,
                bucket_outputs: 8_192,
                observed_collisions: 33,
                privacy_set_size: 262_144,
            })
            .expect("devnet merchant collision bucket");
        state.seed_audit_support(&primary, "mobile", 0);
        state.seed_audit_support(&merchant, "merchant", 1);
        state.publish_public_roots();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let repair = state
            .insert_collision_bucket(CollisionBucketRequest {
                wallet_group_commitment: devnet_payload_root("wallet-group", "reorg-repair"),
                lane: AuditLane::ReorgRepair,
                view_tag_prefix_commitment: devnet_payload_root("view-tag-prefix", "vt-f1"),
                encrypted_bucket_root: devnet_payload_root("encrypted-bucket", "reorg-f1"),
                output_commitment_root: devnet_payload_root("outputs", "reorg-f1"),
                monero_start_height: DEVNET_HEIGHT - 270,
                monero_end_height: DEVNET_HEIGHT - 181,
                bucket_outputs: 2_048,
                observed_collisions: 13,
                privacy_set_size: 131_072,
            })
            .expect("demo reorg repair collision bucket");
        state.seed_audit_support(&repair, "reorg", 2);
        state.open_quarantine(&repair, "collision_bucket", "demo-heavy-tail-review");
        state
    }

    fn seed_audit_support(&mut self, bucket_id: &str, label: &str, index: u32) {
        let sample_id = sample_id(bucket_id, label);
        let cohort_id = cohort_id(label, index);
        let redaction_id = redaction_id(label, index);
        let batch_id = batch_id(&cohort_id, index);
        let assigned_bucket_ids = BTreeSet::from([bucket_id.to_string()]);
        self.false_positive_samples.insert(
            sample_id.clone(),
            FalsePositiveSample {
                sample_id,
                bucket_id: bucket_id.to_string(),
                sample_kind: if index == 0 {
                    SampleKind::MobileLatency
                } else {
                    SampleKind::CollisionHeavyTail
                },
                sample_commitment_root: devnet_payload_root("false-positive-sample", label),
                sampled_outputs: 512 + (index * 128),
                false_positive_hits: 3 + index,
                false_positive_micros: 1_200 + (index * 250),
                expires_height: self.height + self.config.sample_ttl_blocks,
                status: RecordStatus::Sampled,
            },
        );
        self.auditor_cohorts.insert(
            cohort_id.clone(),
            PqAuditorCohort {
                cohort_id: cohort_id.clone(),
                auditor_commitment_root: devnet_payload_root("auditor-cohort", label),
                attestation_root: devnet_payload_root("pq-attestation", label),
                signature_commitment_root: devnet_payload_root("pq-signatures", label),
                member_count: self.config.min_auditor_cohort_size + index as u16,
                pq_security_bits: self.config.target_pq_security_bits,
                bond_micro_units: self.config.auditor_bond_micro_units,
                assigned_bucket_ids: assigned_bucket_ids.clone(),
                status: CohortStatus::Active,
            },
        );
        self.wallet_redaction_windows.insert(
            redaction_id.clone(),
            WalletRedactionWindow {
                redaction_id,
                wallet_group_commitment: devnet_payload_root("wallet-group", label),
                operator_id: format!("operator-{label}"),
                redacted_field_root: devnet_payload_root("redacted-fields", label),
                public_summary_root: devnet_payload_root("operator-summary", label),
                start_height: self.height - self.config.redaction_window_blocks.min(self.height),
                end_height: self.height,
                reason: "operator_safe_collision_audit_summary".to_string(),
                status: RecordStatus::Attested,
            },
        );
        self.low_fee_audit_batches.insert(
            batch_id.clone(),
            LowFeeAuditBatch {
                batch_id,
                cohort_id,
                bucket_ids: assigned_bucket_ids,
                fee_micro_units: self.config.low_fee_cap_micro_units,
                fee_asset_id: self.config.fee_asset_id.clone(),
                batch_root: devnet_payload_root("low-fee-batch", label),
                expires_height: self.height + self.config.batch_ttl_blocks,
                status: RecordStatus::Batched,
            },
        );
    }

    fn open_quarantine(&mut self, subject_id: &str, subject_kind: &str, label: &str) -> String {
        let quarantine_id = quarantine_id(subject_id, label);
        self.quarantines.insert(
            quarantine_id.clone(),
            QuarantineRecord {
                quarantine_id: quarantine_id.clone(),
                subject_id: subject_id.to_string(),
                subject_kind: subject_kind.to_string(),
                reason_root: devnet_payload_root("quarantine-reason", label),
                opened_height: self.height,
                expires_height: self.height + self.config.quarantine_ttl_blocks,
                status: RecordStatus::Quarantined,
            },
        );
        quarantine_id
    }

    fn publish_public_roots(&mut self) -> String {
        let roots = self.roots();
        let root_id = domain_hash(
            "VIEW-TAG-COLLISION-AUDIT-PUBLIC-ROOT-ID",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(self.epoch),
                HashPart::Str(&roots.collision_bucket_root),
            ],
            24,
        );
        self.public_roots.insert(
            root_id.clone(),
            PublicRootRecord {
                root_id: root_id.clone(),
                epoch: self.epoch,
                collision_bucket_root: roots.collision_bucket_root,
                false_positive_sample_root: roots.false_positive_sample_root,
                auditor_cohort_root: roots.auditor_cohort_root,
                quarantine_root: roots.quarantine_root,
                redaction_root: roots.wallet_redaction_window_root,
                published_height: self.height,
            },
        );
        root_id
    }
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for CollisionBucket {
    fn public_record(&self) -> Value {
        CollisionBucket::public_record(self)
    }
}

impl PublicRecord for FalsePositiveSample {
    fn public_record(&self) -> Value {
        FalsePositiveSample::public_record(self)
    }
}

impl PublicRecord for PqAuditorCohort {
    fn public_record(&self) -> Value {
        PqAuditorCohort::public_record(self)
    }
}

impl PublicRecord for WalletRedactionWindow {
    fn public_record(&self) -> Value {
        WalletRedactionWindow::public_record(self)
    }
}

impl PublicRecord for LowFeeAuditBatch {
    fn public_record(&self) -> Value {
        LowFeeAuditBatch::public_record(self)
    }
}

impl PublicRecord for QuarantineRecord {
    fn public_record(&self) -> Value {
        QuarantineRecord::public_record(self)
    }
}

impl PublicRecord for SlashingRecord {
    fn public_record(&self) -> Value {
        SlashingRecord::public_record(self)
    }
}

impl PublicRecord for PublicRootRecord {
    fn public_record(&self) -> Value {
        PublicRootRecord::public_record(self)
    }
}

pub fn collision_bucket_id(request: &CollisionBucketRequest) -> String {
    domain_hash(
        "VIEW-TAG-COLLISION-AUDIT-BUCKET-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&request.wallet_group_commitment),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(&request.view_tag_prefix_commitment),
            HashPart::U64(request.monero_start_height),
            HashPart::U64(request.monero_end_height),
        ],
        24,
    )
}

pub fn sample_id(bucket_id: &str, label: &str) -> String {
    domain_hash(
        "VIEW-TAG-COLLISION-AUDIT-SAMPLE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(bucket_id),
            HashPart::Str(label),
        ],
        24,
    )
}

pub fn cohort_id(label: &str, index: u32) -> String {
    domain_hash(
        "VIEW-TAG-COLLISION-AUDIT-COHORT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(u64::from(index)),
        ],
        24,
    )
}

pub fn redaction_id(label: &str, index: u32) -> String {
    domain_hash(
        "VIEW-TAG-COLLISION-AUDIT-REDACTION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(u64::from(index)),
        ],
        24,
    )
}

pub fn batch_id(cohort_id: &str, index: u32) -> String {
    domain_hash(
        "VIEW-TAG-COLLISION-AUDIT-BATCH-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(cohort_id),
            HashPart::U64(u64::from(index)),
        ],
        24,
    )
}

pub fn quarantine_id(subject_id: &str, label: &str) -> String {
    domain_hash(
        "VIEW-TAG-COLLISION-AUDIT-QUARANTINE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject_id),
            HashPart::Str(label),
        ],
        24,
    )
}

pub fn collision_audit_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "VIEW-TAG-COLLISION-AUDIT-STATE",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn devnet_payload_root(kind: &str, label: &str) -> String {
    domain_hash(
        "VIEW-TAG-COLLISION-AUDIT-DEVNET-PAYLOAD",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn values_public_records<T: PublicRecord>(records: &BTreeMap<String, T>) -> Vec<Value> {
    records.values().map(PublicRecord::public_record).collect()
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn devnet_state() -> State {
    State::devnet()
}

pub fn demo_state() -> State {
    State::demo()
}
