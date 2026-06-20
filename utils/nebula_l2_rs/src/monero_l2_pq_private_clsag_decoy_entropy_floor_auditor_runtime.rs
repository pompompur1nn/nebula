use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = MoneroL2PqPrivateClsagDecoyEntropyFloorAuditorRuntimeResult<T>;
pub type MoneroL2PqPrivateClsagDecoyEntropyFloorAuditorRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_CLSAG_DECOY_ENTROPY_FLOOR_AUDITOR_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-clsag-decoy-entropy-floor-auditor-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_CLSAG_DECOY_ENTROPY_FLOOR_AUDITOR_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const CLSAG_AUDIT_OBSERVATION_SCHEME: &str =
    "clsag-decoy-entropy-floor-audit-observation-root-v1";
pub const SIGNATURE_DECOY_AGE_DIVERSITY_SCHEME: &str =
    "clsag-signature-decoy-age-diversity-score-root-v1";
pub const RING_MEMBER_ENTROPY_SAMPLE_SCHEME: &str = "clsag-ring-member-entropy-sampling-root-v1";
pub const PQ_MIGRATION_SAFETY_SCORE_SCHEME: &str =
    "ML-DSA-87+ML-KEM-1024+SLH-DSA-SHAKE-256f-clsag-decoy-entropy-floor-safety-root-v1";
pub const LOW_FEE_SCAN_BATCH_SCHEME: &str =
    "low-fee-private-clsag-decoy-entropy-floor-scan-batch-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "deterministic-public-clsag-decoy-entropy-floor-auditor-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_addresses_view_keys_spend_keys_amounts_output_indices_key_images_ring_members_clsag_scalars_decoy_samples_or_scan_secrets";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_142_400;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_818_400;
pub const DEVNET_EPOCH: u64 = 17_460;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_SCORE: u64 = 10_000;
pub const DEFAULT_MIN_RING_SIZE: u16 = 16;
pub const DEFAULT_TARGET_RING_SIZE: u16 = 128;
pub const DEFAULT_MIN_FLOOR_SCORE_BPS: u64 = 8_975;
pub const DEFAULT_TARGET_FLOOR_SCORE_BPS: u64 = 9_725;
pub const DEFAULT_MIN_SHANNON_ENTROPY_MILLIBITS: u64 = 3_750_000;
pub const DEFAULT_TARGET_SHANNON_ENTROPY_MILLIBITS: u64 = 4_950_000;
pub const DEFAULT_MIN_MIN_ENTROPY_MILLIBITS: u64 = 3_100_000;
pub const DEFAULT_TARGET_MIN_ENTROPY_MILLIBITS: u64 = 4_300_000;
pub const DEFAULT_MIN_EFFECTIVE_DECOYS: u64 = 104;
pub const DEFAULT_TARGET_EFFECTIVE_DECOYS: u64 = 126;
pub const DEFAULT_MIN_ANONYMITY_SET_OUTPUTS: u64 = 131_072;
pub const DEFAULT_TARGET_ANONYMITY_SET_OUTPUTS: u64 = 524_288;
pub const DEFAULT_MIN_AGE_BUCKETS: u16 = 6;
pub const DEFAULT_TARGET_AGE_BUCKETS: u16 = 28;
pub const DEFAULT_MIN_SIGNATURE_AGE_DIVERSITY_BPS: u64 = 8_900;
pub const DEFAULT_TARGET_SIGNATURE_AGE_DIVERSITY_BPS: u64 = 9_700;
pub const DEFAULT_MAX_RECENT_DECOY_DOMINANCE_BPS: u64 = 1_900;
pub const DEFAULT_MAX_AGE_BUCKET_SKEW_BPS: u64 = 575;
pub const DEFAULT_MIN_RING_MEMBER_ENTROPY_BPS: u64 = 9_000;
pub const DEFAULT_TARGET_RING_MEMBER_ENTROPY_BPS: u64 = 9_800;
pub const DEFAULT_MIN_MEMBER_SAMPLE_WINDOWS: u16 = 5;
pub const DEFAULT_TARGET_MEMBER_SAMPLE_WINDOWS: u16 = 32;
pub const DEFAULT_MIN_PQ_SAFETY_BPS: u64 = 9_200;
pub const DEFAULT_TARGET_PQ_SAFETY_BPS: u64 = 9_875;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_LOW_FEE_BATCH_OUTPUTS: u64 = 4_096;
pub const DEFAULT_TARGET_LOW_FEE_BATCH_OUTPUTS: u64 = 32_768;
pub const DEFAULT_AUDIT_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_SCAN_WINDOW_BLOCKS: u64 = 360;
pub const DEFAULT_MAX_BATCH_FEE_BPS: u64 = 5;
pub const DEFAULT_TARGET_BATCH_REBATE_BPS: u64 = 4;
pub const DEFAULT_PUBLIC_BUCKET_SIZE: u64 = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditLane {
    WalletReceiveScan,
    WatchOnlyScan,
    BridgeDepositScan,
    SwapSettlementScan,
    MerchantReceiveScan,
    ConsolidationShieldingScan,
    ReorgFloorRepair,
    MultisigSpendAudit,
}

impl AuditLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletReceiveScan => "wallet_receive_scan",
            Self::WatchOnlyScan => "watch_only_scan",
            Self::BridgeDepositScan => "bridge_deposit_scan",
            Self::SwapSettlementScan => "swap_settlement_scan",
            Self::MerchantReceiveScan => "merchant_receive_scan",
            Self::ConsolidationShieldingScan => "consolidation_shielding_scan",
            Self::ReorgFloorRepair => "reorg_floor_repair",
            Self::MultisigSpendAudit => "multisig_spend_audit",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    Draft,
    Observed,
    AgeDiversityScored,
    EntropySampled,
    PqSafe,
    BatchEligible,
    Sealed,
    Expired,
    Quarantined,
}

impl AuditStatus {
    pub fn public_usable(self) -> bool {
        matches!(
            self,
            Self::Observed
                | Self::AgeDiversityScored
                | Self::EntropySampled
                | Self::PqSafe
                | Self::BatchEligible
                | Self::Sealed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureDecoyAgeKind {
    AncientAnchor,
    ColdHistorical,
    WarmRecent,
    HotRecent,
    LiquidityBridge,
    SwapSettlement,
    MerchantFlow,
    ReorgRepair,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RingMemberSampleKind {
    UniformSpendWindow,
    GammaTailCheck,
    RecentOutputCap,
    AnchorOutputBlend,
    BridgeLiquidityBlend,
    WalletBatchBlend,
    ReorgResample,
    ColdStorageSweep,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Config {
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub min_ring_size: u16,
    pub target_ring_size: u16,
    pub min_floor_score_bps: u64,
    pub target_floor_score_bps: u64,
    pub min_shannon_entropy_millibits: u64,
    pub target_shannon_entropy_millibits: u64,
    pub min_min_entropy_millibits: u64,
    pub target_min_entropy_millibits: u64,
    pub min_effective_decoys: u64,
    pub target_effective_decoys: u64,
    pub min_anonymity_set_outputs: u64,
    pub target_anonymity_set_outputs: u64,
    pub min_age_buckets: u16,
    pub target_age_buckets: u16,
    pub min_signature_age_diversity_bps: u64,
    pub target_signature_age_diversity_bps: u64,
    pub max_recent_decoy_dominance_bps: u64,
    pub max_age_bucket_skew_bps: u64,
    pub min_ring_member_entropy_bps: u64,
    pub target_ring_member_entropy_bps: u64,
    pub min_member_sample_windows: u16,
    pub target_member_sample_windows: u16,
    pub min_pq_safety_bps: u64,
    pub target_pq_safety_bps: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub min_low_fee_batch_outputs: u64,
    pub target_low_fee_batch_outputs: u64,
    pub audit_ttl_blocks: u64,
    pub scan_window_blocks: u64,
    pub max_batch_fee_bps: u64,
    pub target_batch_rebate_bps: u64,
    pub public_bucket_size: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_ring_size: DEFAULT_MIN_RING_SIZE,
            target_ring_size: DEFAULT_TARGET_RING_SIZE,
            min_floor_score_bps: DEFAULT_MIN_FLOOR_SCORE_BPS,
            target_floor_score_bps: DEFAULT_TARGET_FLOOR_SCORE_BPS,
            min_shannon_entropy_millibits: DEFAULT_MIN_SHANNON_ENTROPY_MILLIBITS,
            target_shannon_entropy_millibits: DEFAULT_TARGET_SHANNON_ENTROPY_MILLIBITS,
            min_min_entropy_millibits: DEFAULT_MIN_MIN_ENTROPY_MILLIBITS,
            target_min_entropy_millibits: DEFAULT_TARGET_MIN_ENTROPY_MILLIBITS,
            min_effective_decoys: DEFAULT_MIN_EFFECTIVE_DECOYS,
            target_effective_decoys: DEFAULT_TARGET_EFFECTIVE_DECOYS,
            min_anonymity_set_outputs: DEFAULT_MIN_ANONYMITY_SET_OUTPUTS,
            target_anonymity_set_outputs: DEFAULT_TARGET_ANONYMITY_SET_OUTPUTS,
            min_age_buckets: DEFAULT_MIN_AGE_BUCKETS,
            target_age_buckets: DEFAULT_TARGET_AGE_BUCKETS,
            min_signature_age_diversity_bps: DEFAULT_MIN_SIGNATURE_AGE_DIVERSITY_BPS,
            target_signature_age_diversity_bps: DEFAULT_TARGET_SIGNATURE_AGE_DIVERSITY_BPS,
            max_recent_decoy_dominance_bps: DEFAULT_MAX_RECENT_DECOY_DOMINANCE_BPS,
            max_age_bucket_skew_bps: DEFAULT_MAX_AGE_BUCKET_SKEW_BPS,
            min_ring_member_entropy_bps: DEFAULT_MIN_RING_MEMBER_ENTROPY_BPS,
            target_ring_member_entropy_bps: DEFAULT_TARGET_RING_MEMBER_ENTROPY_BPS,
            min_member_sample_windows: DEFAULT_MIN_MEMBER_SAMPLE_WINDOWS,
            target_member_sample_windows: DEFAULT_TARGET_MEMBER_SAMPLE_WINDOWS,
            min_pq_safety_bps: DEFAULT_MIN_PQ_SAFETY_BPS,
            target_pq_safety_bps: DEFAULT_TARGET_PQ_SAFETY_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            min_low_fee_batch_outputs: DEFAULT_MIN_LOW_FEE_BATCH_OUTPUTS,
            target_low_fee_batch_outputs: DEFAULT_TARGET_LOW_FEE_BATCH_OUTPUTS,
            audit_ttl_blocks: DEFAULT_AUDIT_TTL_BLOCKS,
            scan_window_blocks: DEFAULT_SCAN_WINDOW_BLOCKS,
            max_batch_fee_bps: DEFAULT_MAX_BATCH_FEE_BPS,
            target_batch_rebate_bps: DEFAULT_TARGET_BATCH_REBATE_BPS,
            public_bucket_size: DEFAULT_PUBLIC_BUCKET_SIZE,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure(
            self.min_ring_size >= 16,
            "minimum CLSAG ring size is too low",
        )?;
        ensure(
            self.target_ring_size >= self.min_ring_size,
            "target CLSAG ring size must cover minimum ring size",
        )?;
        ensure(
            self.target_floor_score_bps >= self.min_floor_score_bps,
            "target entropy floor score must cover minimum floor score",
        )?;
        ensure(
            self.target_shannon_entropy_millibits >= self.min_shannon_entropy_millibits,
            "target Shannon entropy must cover minimum Shannon entropy",
        )?;
        ensure(
            self.target_min_entropy_millibits >= self.min_min_entropy_millibits,
            "target min-entropy must cover minimum min-entropy",
        )?;
        ensure(
            self.target_effective_decoys >= self.min_effective_decoys,
            "target effective decoys must cover minimum effective decoys",
        )?;
        ensure(
            self.target_anonymity_set_outputs >= self.min_anonymity_set_outputs,
            "target anonymity set must cover CLSAG privacy floor",
        )?;
        ensure(
            self.target_age_buckets >= self.min_age_buckets,
            "target age buckets must cover minimum age buckets",
        )?;
        ensure(
            self.target_signature_age_diversity_bps >= self.min_signature_age_diversity_bps,
            "target signature age diversity must cover minimum age diversity",
        )?;
        ensure(
            self.target_ring_member_entropy_bps >= self.min_ring_member_entropy_bps,
            "target ring member entropy must cover minimum ring member entropy",
        )?;
        ensure(
            self.target_member_sample_windows >= self.min_member_sample_windows,
            "target member sample windows must cover minimum windows",
        )?;
        ensure(
            self.target_pq_safety_bps >= self.min_pq_safety_bps,
            "target PQ safety score must cover minimum PQ safety score",
        )?;
        ensure(
            self.target_pq_security_bits >= self.min_pq_security_bits,
            "target PQ security must cover minimum PQ security",
        )?;
        ensure(
            self.target_low_fee_batch_outputs >= self.min_low_fee_batch_outputs,
            "target low-fee batch outputs must cover minimum batch outputs",
        )?;
        ensure(
            self.min_floor_score_bps <= MAX_BPS
                && self.target_floor_score_bps <= MAX_BPS
                && self.min_signature_age_diversity_bps <= MAX_BPS
                && self.target_signature_age_diversity_bps <= MAX_BPS
                && self.max_recent_decoy_dominance_bps <= MAX_BPS
                && self.max_age_bucket_skew_bps <= MAX_BPS
                && self.min_ring_member_entropy_bps <= MAX_BPS
                && self.target_ring_member_entropy_bps <= MAX_BPS
                && self.min_pq_safety_bps <= MAX_BPS
                && self.target_pq_safety_bps <= MAX_BPS,
            "basis-point threshold exceeds max bps",
        )?;
        ensure(self.audit_ttl_blocks > 0, "audit ttl must be non-zero")?;
        ensure(self.scan_window_blocks > 0, "scan window must be non-zero")?;
        ensure(
            self.max_batch_fee_bps <= MAX_BPS,
            "maximum batch fee bps exceeds bound",
        )?;
        ensure(
            self.target_batch_rebate_bps <= self.max_batch_fee_bps,
            "batch rebate bps must not exceed fee bps",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "clsag-decoy-entropy-floor-auditor-config",
            &self.public_record(),
        )
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub clsag_audit_observations: u64,
    pub signature_decoy_age_diversity_scores: u64,
    pub ring_member_entropy_samples: u64,
    pub pq_migration_safety_scores: u64,
    pub low_fee_scan_batches: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "clsag-decoy-entropy-floor-auditor-counters",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub clsag_audit_observations_root: String,
    pub signature_decoy_age_diversity_scores_root: String,
    pub ring_member_entropy_samples_root: String,
    pub pq_migration_safety_scores_root: String,
    pub low_fee_scan_batches_root: String,
    pub deterministic_state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            clsag_audit_observations_root: empty_root(CLSAG_AUDIT_OBSERVATION_SCHEME),
            signature_decoy_age_diversity_scores_root: empty_root(
                SIGNATURE_DECOY_AGE_DIVERSITY_SCHEME,
            ),
            ring_member_entropy_samples_root: empty_root(RING_MEMBER_ENTROPY_SAMPLE_SCHEME),
            pq_migration_safety_scores_root: empty_root(PQ_MIGRATION_SAFETY_SCORE_SCHEME),
            low_fee_scan_batches_root: empty_root(LOW_FEE_SCAN_BATCH_SCHEME),
            deterministic_state_root: empty_root("clsag-decoy-entropy-floor-auditor-state"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

impl Default for Roots {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClsagAuditObservation {
    pub audit_id: String,
    pub lane: AuditLane,
    pub epoch: u64,
    pub monero_height_bucket: u64,
    pub ring_size: u16,
    pub anonymity_set_outputs: u64,
    pub effective_decoys: u64,
    pub floor_score_bps: u64,
    pub shannon_entropy_millibits: u64,
    pub min_entropy_millibits: u64,
    pub dominant_decoy_bucket_bps: u64,
    pub clsag_distribution_skew_bps: u64,
    pub key_image_uniqueness_bps: u64,
    pub redacted_clsag_sample_root: String,
    pub output_commitment_set_root: String,
    pub key_image_domain_root: String,
    pub auditor_attestation_root: String,
    pub expires_at_monero_height: u64,
    pub status: AuditStatus,
}

impl ClsagAuditObservation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(CLSAG_AUDIT_OBSERVATION_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignatureDecoyAgeDiversityScore {
    pub diversity_id: String,
    pub audit_id: String,
    pub age_kind: SignatureDecoyAgeKind,
    pub scan_window_blocks: u64,
    pub sampled_signatures: u64,
    pub age_bucket_count: u16,
    pub signature_age_diversity_bps: u64,
    pub recent_decoy_dominance_bps: u64,
    pub age_bucket_skew_bps: u64,
    pub median_decoy_age_blocks: u64,
    pub p90_decoy_age_blocks: u64,
    pub p99_decoy_age_blocks: u64,
    pub redacted_signature_age_histogram_root: String,
    pub clsag_age_diversity_witness_root: String,
    pub residual_linkability_root: String,
    pub status: AuditStatus,
}

impl SignatureDecoyAgeDiversityScore {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(SIGNATURE_DECOY_AGE_DIVERSITY_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RingMemberEntropySample {
    pub sample_id: String,
    pub audit_id: String,
    pub sample_kind: RingMemberSampleKind,
    pub sampled_rings: u64,
    pub sampled_members: u64,
    pub member_sample_windows: u16,
    pub distinct_output_buckets: u64,
    pub ring_member_entropy_bps: u64,
    pub shannon_entropy_millibits: u64,
    pub min_entropy_millibits: u64,
    pub duplicate_member_rate_bps: u64,
    pub ring_position_bias_bps: u64,
    pub redacted_ring_member_histogram_root: String,
    pub sampler_transcript_root: String,
    pub entropy_witness_root: String,
    pub status: AuditStatus,
}

impl RingMemberEntropySample {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(RING_MEMBER_ENTROPY_SAMPLE_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqMigrationSafetyScore {
    pub safety_id: String,
    pub audit_id: String,
    pub pq_security_bits: u16,
    pub pq_safety_bps: u64,
    pub classical_fallback_disabled: bool,
    pub migration_epoch: u64,
    pub clsag_to_pq_binding_root: String,
    pub entropy_floor_guard_root: String,
    pub signature_age_guard_root: String,
    pub ring_member_entropy_guard_root: String,
    pub attestation_root: String,
    pub status: AuditStatus,
}

impl PqMigrationSafetyScore {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(PQ_MIGRATION_SAFETY_SCORE_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeScanBatch {
    pub batch_id: String,
    pub audit_id: String,
    pub diversity_id: String,
    pub sample_id: String,
    pub fee_asset_id: String,
    pub batch_outputs: u64,
    pub wallet_scan_count: u64,
    pub user_fee_bps: u64,
    pub rebate_bps: u64,
    pub batched_clsag_scan_root: String,
    pub scan_sponsor_receipt_root: String,
    pub privacy_budget_root: String,
    pub status: AuditStatus,
}

impl LowFeeScanBatch {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(LOW_FEE_SCAN_BATCH_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct State {
    pub protocol_version: String,
    pub chain_id: String,
    pub config: Config,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub clsag_audit_observations: BTreeMap<String, ClsagAuditObservation>,
    pub signature_decoy_age_diversity_scores: BTreeMap<String, SignatureDecoyAgeDiversityScore>,
    pub ring_member_entropy_samples: BTreeMap<String, RingMemberEntropySample>,
    pub pq_migration_safety_scores: BTreeMap<String, PqMigrationSafetyScore>,
    pub low_fee_scan_batches: BTreeMap<String, LowFeeScanBatch>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn new(config: Config, l2_height: u64, monero_height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            config,
            l2_height,
            monero_height,
            epoch,
            clsag_audit_observations: BTreeMap::new(),
            signature_decoy_age_diversity_scores: BTreeMap::new(),
            ring_member_entropy_samples: BTreeMap::new(),
            pq_migration_safety_scores: BTreeMap::new(),
            low_fee_scan_batches: BTreeMap::new(),
            counters: Counters::default(),
            roots: Roots::empty(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "runtime": "monero_l2_pq_private_clsag_decoy_entropy_floor_auditor_runtime",
            "protocol_version": self.protocol_version,
            "schema_version": SCHEMA_VERSION,
            "chain_id": self.chain_id,
            "hash_suite": HASH_SUITE,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "l2_height": bucket(self.l2_height, self.config.public_bucket_size),
            "monero_height": bucket(self.monero_height, self.config.public_bucket_size),
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "aggregate_floor_score_bps": self.aggregate_floor_score_bps(),
            "aggregate_signature_age_diversity_bps": self.aggregate_signature_age_diversity_bps(),
            "aggregate_ring_member_entropy_bps": self.aggregate_ring_member_entropy_bps(),
            "aggregate_pq_safety_bps": self.aggregate_pq_safety_bps(),
            "public_record_scheme": PUBLIC_RECORD_SCHEME,
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.deterministic_state_root.clone()
    }

    pub fn insert_clsag_audit_observation(
        &mut self,
        observation: ClsagAuditObservation,
    ) -> Result<()> {
        ensure(
            observation.ring_size >= self.config.min_ring_size,
            "CLSAG audit observation ring size is below minimum",
        )?;
        ensure(
            observation.anonymity_set_outputs >= self.config.min_anonymity_set_outputs,
            "CLSAG audit observation is below anonymity-set privacy floor",
        )?;
        ensure(
            observation.effective_decoys >= self.config.min_effective_decoys,
            "CLSAG audit observation effective decoys are below floor",
        )?;
        ensure(
            observation.floor_score_bps >= self.config.min_floor_score_bps,
            "CLSAG decoy entropy floor score is below floor",
        )?;
        ensure(
            observation.shannon_entropy_millibits >= self.config.min_shannon_entropy_millibits,
            "CLSAG Shannon entropy is below floor",
        )?;
        ensure(
            observation.min_entropy_millibits >= self.config.min_min_entropy_millibits,
            "CLSAG min-entropy is below floor",
        )?;
        ensure(
            observation.dominant_decoy_bucket_bps <= MAX_BPS,
            "dominant decoy bucket share exceeds max bps",
        )?;
        ensure(
            observation.clsag_distribution_skew_bps <= self.config.max_age_bucket_skew_bps,
            "CLSAG decoy distribution skew exceeds cap",
        )?;
        ensure(
            observation.key_image_uniqueness_bps >= self.config.min_floor_score_bps,
            "CLSAG key image uniqueness is below floor",
        )?;
        ensure(
            observation.expires_at_monero_height > self.monero_height,
            "CLSAG audit observation must expire in the future",
        )?;
        self.clsag_audit_observations
            .insert(observation.audit_id.clone(), observation);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_signature_decoy_age_diversity_score(
        &mut self,
        diversity: SignatureDecoyAgeDiversityScore,
    ) -> Result<()> {
        ensure(
            self.clsag_audit_observations
                .contains_key(&diversity.audit_id),
            "signature decoy age diversity score references unknown audit",
        )?;
        ensure(
            diversity.scan_window_blocks <= self.config.scan_window_blocks,
            "signature decoy age diversity score exceeds configured scan window",
        )?;
        ensure(
            diversity.sampled_signatures >= self.config.min_low_fee_batch_outputs,
            "signature decoy age diversity sampled too few signatures",
        )?;
        ensure(
            diversity.age_bucket_count >= self.config.min_age_buckets,
            "signature decoy age diversity has too few age buckets",
        )?;
        ensure(
            diversity.signature_age_diversity_bps >= self.config.min_signature_age_diversity_bps,
            "signature decoy age diversity score is below floor",
        )?;
        ensure(
            diversity.recent_decoy_dominance_bps <= self.config.max_recent_decoy_dominance_bps,
            "recent decoy dominance exceeds cap",
        )?;
        ensure(
            diversity.age_bucket_skew_bps <= self.config.max_age_bucket_skew_bps,
            "signature decoy age bucket skew exceeds cap",
        )?;
        ensure(
            diversity.p90_decoy_age_blocks >= diversity.median_decoy_age_blocks
                && diversity.p99_decoy_age_blocks >= diversity.p90_decoy_age_blocks,
            "decoy age percentiles must be monotonic",
        )?;
        self.signature_decoy_age_diversity_scores
            .insert(diversity.diversity_id.clone(), diversity);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_ring_member_entropy_sample(
        &mut self,
        sample: RingMemberEntropySample,
    ) -> Result<()> {
        ensure(
            self.clsag_audit_observations.contains_key(&sample.audit_id),
            "ring member entropy sample references unknown audit",
        )?;
        ensure(
            sample.sampled_rings > 0,
            "ring member entropy sample must include at least one ring",
        )?;
        ensure(
            sample.sampled_members >= sample.sampled_rings * self.config.min_ring_size as u64,
            "ring member entropy sample member count is below ring floor",
        )?;
        ensure(
            sample.member_sample_windows >= self.config.min_member_sample_windows,
            "ring member entropy sample has too few sample windows",
        )?;
        ensure(
            sample.distinct_output_buckets > 0
                && sample.distinct_output_buckets <= sample.sampled_members,
            "ring member entropy sample bucket count must fit sampled members",
        )?;
        ensure(
            sample.ring_member_entropy_bps >= self.config.min_ring_member_entropy_bps,
            "ring member entropy sample score is below floor",
        )?;
        ensure(
            sample.shannon_entropy_millibits >= self.config.min_shannon_entropy_millibits,
            "ring member entropy sample Shannon entropy is below floor",
        )?;
        ensure(
            sample.min_entropy_millibits >= self.config.min_min_entropy_millibits,
            "ring member entropy sample min-entropy is below floor",
        )?;
        ensure(
            sample.duplicate_member_rate_bps <= self.config.max_age_bucket_skew_bps,
            "ring member duplicate rate exceeds cap",
        )?;
        ensure(
            sample.ring_position_bias_bps <= self.config.max_age_bucket_skew_bps,
            "ring position bias exceeds cap",
        )?;
        self.ring_member_entropy_samples
            .insert(sample.sample_id.clone(), sample);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_pq_migration_safety_score(
        &mut self,
        safety: PqMigrationSafetyScore,
    ) -> Result<()> {
        ensure(
            self.clsag_audit_observations.contains_key(&safety.audit_id),
            "PQ migration safety score references unknown audit",
        )?;
        ensure(
            safety.pq_security_bits >= self.config.min_pq_security_bits,
            "PQ migration safety score is below minimum security",
        )?;
        ensure(
            safety.pq_safety_bps >= self.config.min_pq_safety_bps,
            "PQ migration safety score is below floor",
        )?;
        ensure(
            safety.classical_fallback_disabled,
            "PQ migration safety score must disable classical fallback",
        )?;
        self.pq_migration_safety_scores
            .insert(safety.safety_id.clone(), safety);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_low_fee_scan_batch(&mut self, batch: LowFeeScanBatch) -> Result<()> {
        ensure(
            self.clsag_audit_observations.contains_key(&batch.audit_id),
            "low-fee scan batch references unknown audit",
        )?;
        ensure(
            self.signature_decoy_age_diversity_scores
                .contains_key(&batch.diversity_id),
            "low-fee scan batch references unknown signature age diversity score",
        )?;
        ensure(
            self.ring_member_entropy_samples
                .contains_key(&batch.sample_id),
            "low-fee scan batch references unknown ring member entropy sample",
        )?;
        ensure(
            batch.fee_asset_id == self.config.fee_asset_id,
            "low-fee scan batch fee asset does not match config",
        )?;
        ensure(
            batch.batch_outputs >= self.config.min_low_fee_batch_outputs,
            "low-fee scan batch is below minimum output count",
        )?;
        ensure(
            batch.wallet_scan_count > 0,
            "low-fee scan batch must include at least one wallet scan",
        )?;
        ensure(
            batch.user_fee_bps <= self.config.max_batch_fee_bps,
            "low-fee scan batch user fee exceeds cap",
        )?;
        ensure(
            batch.rebate_bps <= batch.user_fee_bps,
            "low-fee scan batch rebate exceeds charged fee",
        )?;
        self.low_fee_scan_batches
            .insert(batch.batch_id.clone(), batch);
        self.refresh_roots();
        Ok(())
    }

    pub fn usable_clsag_audit_observations(&self) -> Vec<&ClsagAuditObservation> {
        self.clsag_audit_observations
            .values()
            .filter(|observation| observation.status.public_usable())
            .collect()
    }

    pub fn aggregate_floor_score_bps(&self) -> u64 {
        weighted_average_bps(
            self.clsag_audit_observations
                .values()
                .map(|observation| (observation.floor_score_bps, observation.effective_decoys)),
        )
    }

    pub fn aggregate_signature_age_diversity_bps(&self) -> u64 {
        weighted_average_bps(
            self.signature_decoy_age_diversity_scores
                .values()
                .map(|score| (score.signature_age_diversity_bps, score.sampled_signatures)),
        )
    }

    pub fn aggregate_ring_member_entropy_bps(&self) -> u64 {
        weighted_average_bps(
            self.ring_member_entropy_samples
                .values()
                .map(|sample| (sample.ring_member_entropy_bps, sample.sampled_members)),
        )
    }

    pub fn aggregate_pq_safety_bps(&self) -> u64 {
        weighted_average_bps(
            self.pq_migration_safety_scores
                .values()
                .map(|score| (score.pq_safety_bps, score.pq_security_bits as u64)),
        )
    }

    pub fn refresh_roots(&mut self) {
        self.counters.clsag_audit_observations = self.clsag_audit_observations.len() as u64;
        self.counters.signature_decoy_age_diversity_scores =
            self.signature_decoy_age_diversity_scores.len() as u64;
        self.counters.ring_member_entropy_samples = self.ring_member_entropy_samples.len() as u64;
        self.counters.pq_migration_safety_scores = self.pq_migration_safety_scores.len() as u64;
        self.counters.low_fee_scan_batches = self.low_fee_scan_batches.len() as u64;

        self.roots.clsag_audit_observations_root = map_root(
            CLSAG_AUDIT_OBSERVATION_SCHEME,
            self.clsag_audit_observations
                .iter()
                .map(|(id, observation)| (id.as_str(), observation.state_root())),
        );
        self.roots.signature_decoy_age_diversity_scores_root = map_root(
            SIGNATURE_DECOY_AGE_DIVERSITY_SCHEME,
            self.signature_decoy_age_diversity_scores
                .iter()
                .map(|(id, diversity)| (id.as_str(), diversity.state_root())),
        );
        self.roots.ring_member_entropy_samples_root = map_root(
            RING_MEMBER_ENTROPY_SAMPLE_SCHEME,
            self.ring_member_entropy_samples
                .iter()
                .map(|(id, sample)| (id.as_str(), sample.state_root())),
        );
        self.roots.pq_migration_safety_scores_root = map_root(
            PQ_MIGRATION_SAFETY_SCORE_SCHEME,
            self.pq_migration_safety_scores
                .iter()
                .map(|(id, safety)| (id.as_str(), safety.state_root())),
        );
        self.roots.low_fee_scan_batches_root = map_root(
            LOW_FEE_SCAN_BATCH_SCHEME,
            self.low_fee_scan_batches
                .iter()
                .map(|(id, batch)| (id.as_str(), batch.state_root())),
        );
        self.roots.deterministic_state_root = self.state_root_without_cached_roots();
    }

    fn state_root_without_cached_roots(&self) -> String {
        root_from_parts(
            "clsag-decoy-entropy-floor-auditor-state",
            &[
                HashPart::Str(&self.protocol_version),
                HashPart::Str(&self.chain_id),
                HashPart::Str(&self.config.state_root()),
                HashPart::U64(self.l2_height),
                HashPart::U64(self.monero_height),
                HashPart::U64(self.epoch),
                HashPart::Str(&self.counters.state_root()),
                HashPart::Str(&self.roots.clsag_audit_observations_root),
                HashPart::Str(&self.roots.signature_decoy_age_diversity_scores_root),
                HashPart::Str(&self.roots.ring_member_entropy_samples_root),
                HashPart::Str(&self.roots.pq_migration_safety_scores_root),
                HashPart::Str(&self.roots.low_fee_scan_batches_root),
            ],
        )
    }
}

impl Default for State {
    fn default() -> Self {
        State::new(
            Config::devnet(),
            DEVNET_L2_HEIGHT,
            DEVNET_MONERO_HEIGHT,
            DEVNET_EPOCH,
        )
        .expect("default CLSAG decoy entropy floor auditor config is valid")
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let audit_id = "clsag-decoy-entropy-floor-auditor-devnet-0".to_string();
    let diversity_id = "clsag-signature-decoy-age-diversity-devnet-0".to_string();
    let sample_id = "clsag-ring-member-entropy-sample-devnet-0".to_string();

    state
        .insert_clsag_audit_observation(ClsagAuditObservation {
            audit_id: audit_id.clone(),
            lane: AuditLane::WalletReceiveScan,
            epoch: DEVNET_EPOCH,
            monero_height_bucket: bucket(DEVNET_MONERO_HEIGHT, DEFAULT_PUBLIC_BUCKET_SIZE),
            ring_size: DEFAULT_TARGET_RING_SIZE,
            anonymity_set_outputs: DEFAULT_TARGET_ANONYMITY_SET_OUTPUTS,
            effective_decoys: DEFAULT_TARGET_EFFECTIVE_DECOYS,
            floor_score_bps: DEFAULT_TARGET_FLOOR_SCORE_BPS,
            shannon_entropy_millibits: DEFAULT_TARGET_SHANNON_ENTROPY_MILLIBITS,
            min_entropy_millibits: DEFAULT_TARGET_MIN_ENTROPY_MILLIBITS,
            dominant_decoy_bucket_bps: 1_080,
            clsag_distribution_skew_bps: 220,
            key_image_uniqueness_bps: 9_995,
            redacted_clsag_sample_root: root_from_parts(
                "devnet-redacted-clsag-decoy-entropy-sample",
                &[HashPart::Str(&audit_id)],
            ),
            output_commitment_set_root: root_from_parts(
                "devnet-clsag-output-commitment-set",
                &[HashPart::Str(&audit_id)],
            ),
            key_image_domain_root: root_from_parts(
                "devnet-clsag-key-image-domain",
                &[HashPart::Str(&audit_id)],
            ),
            auditor_attestation_root: root_from_parts(
                "devnet-clsag-decoy-entropy-floor-auditor-attestation",
                &[HashPart::Str(&audit_id)],
            ),
            expires_at_monero_height: DEVNET_MONERO_HEIGHT + DEFAULT_AUDIT_TTL_BLOCKS,
            status: AuditStatus::Observed,
        })
        .expect("devnet CLSAG audit observation inserts");

    for (index, age_kind, sampled_signatures, buckets, score, recent, skew) in [
        (
            0,
            SignatureDecoyAgeKind::AncientAnchor,
            18_432,
            28,
            9_740,
            820,
            160,
        ),
        (
            1,
            SignatureDecoyAgeKind::ColdHistorical,
            20_480,
            30,
            9_710,
            900,
            174,
        ),
        (
            2,
            SignatureDecoyAgeKind::WarmRecent,
            22_528,
            32,
            9_680,
            1_020,
            188,
        ),
        (
            3,
            SignatureDecoyAgeKind::LiquidityBridge,
            24_576,
            34,
            9_650,
            1_060,
            202,
        ),
        (
            4,
            SignatureDecoyAgeKind::SwapSettlement,
            26_624,
            36,
            9_620,
            1_110,
            216,
        ),
        (
            5,
            SignatureDecoyAgeKind::MerchantFlow,
            28_672,
            38,
            9_590,
            1_160,
            230,
        ),
    ] {
        let id = format!("clsag-signature-decoy-age-diversity-devnet-{index}");
        state
            .insert_signature_decoy_age_diversity_score(SignatureDecoyAgeDiversityScore {
                diversity_id: id.clone(),
                audit_id: audit_id.clone(),
                age_kind,
                scan_window_blocks: DEFAULT_SCAN_WINDOW_BLOCKS,
                sampled_signatures,
                age_bucket_count: buckets,
                signature_age_diversity_bps: score,
                recent_decoy_dominance_bps: recent,
                age_bucket_skew_bps: skew,
                median_decoy_age_blocks: 52_000 + (index * 1_200),
                p90_decoy_age_blocks: 388_800 + (index * 2_400),
                p99_decoy_age_blocks: 1_036_800 + (index * 3_600),
                redacted_signature_age_histogram_root: root_from_parts(
                    "devnet-redacted-clsag-signature-decoy-age-histogram",
                    &[HashPart::Str(&id)],
                ),
                clsag_age_diversity_witness_root: root_from_parts(
                    "devnet-clsag-signature-age-diversity-witness",
                    &[HashPart::Str(&id)],
                ),
                residual_linkability_root: root_from_parts(
                    "devnet-clsag-signature-age-residual-linkability",
                    &[HashPart::Str(&id)],
                ),
                status: AuditStatus::AgeDiversityScored,
            })
            .expect("devnet CLSAG signature decoy age diversity inserts");
    }

    for (index, sample_kind, rings, windows, buckets, score, duplicate, position_bias) in [
        (
            0,
            RingMemberSampleKind::UniformSpendWindow,
            4_096,
            28,
            2_048,
            9_830,
            90,
            110,
        ),
        (
            1,
            RingMemberSampleKind::GammaTailCheck,
            4_608,
            30,
            2_176,
            9_805,
            96,
            116,
        ),
        (
            2,
            RingMemberSampleKind::RecentOutputCap,
            5_120,
            32,
            2_304,
            9_780,
            102,
            122,
        ),
        (
            3,
            RingMemberSampleKind::BridgeLiquidityBlend,
            5_632,
            34,
            2_432,
            9_755,
            108,
            128,
        ),
        (
            4,
            RingMemberSampleKind::WalletBatchBlend,
            6_144,
            36,
            2_560,
            9_730,
            114,
            134,
        ),
        (
            5,
            RingMemberSampleKind::ColdStorageSweep,
            6_656,
            38,
            2_688,
            9_705,
            120,
            140,
        ),
    ] {
        let id = format!("clsag-ring-member-entropy-sample-devnet-{index}");
        state
            .insert_ring_member_entropy_sample(RingMemberEntropySample {
                sample_id: id.clone(),
                audit_id: audit_id.clone(),
                sample_kind,
                sampled_rings: rings,
                sampled_members: rings * DEFAULT_TARGET_RING_SIZE as u64,
                member_sample_windows: windows,
                distinct_output_buckets: buckets,
                ring_member_entropy_bps: score,
                shannon_entropy_millibits: DEFAULT_TARGET_SHANNON_ENTROPY_MILLIBITS
                    - (index * 18_000),
                min_entropy_millibits: DEFAULT_TARGET_MIN_ENTROPY_MILLIBITS - (index * 12_000),
                duplicate_member_rate_bps: duplicate,
                ring_position_bias_bps: position_bias,
                redacted_ring_member_histogram_root: root_from_parts(
                    "devnet-redacted-clsag-ring-member-entropy-histogram",
                    &[HashPart::Str(&id)],
                ),
                sampler_transcript_root: root_from_parts(
                    "devnet-clsag-ring-member-sampler-transcript",
                    &[HashPart::Str(&id)],
                ),
                entropy_witness_root: root_from_parts(
                    "devnet-clsag-ring-member-entropy-witness",
                    &[HashPart::Str(&id)],
                ),
                status: AuditStatus::EntropySampled,
            })
            .expect("devnet CLSAG ring member entropy sample inserts");
    }

    state
        .insert_pq_migration_safety_score(PqMigrationSafetyScore {
            safety_id: "clsag-decoy-entropy-floor-pq-safety-devnet-0".to_string(),
            audit_id: audit_id.clone(),
            pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            pq_safety_bps: DEFAULT_TARGET_PQ_SAFETY_BPS,
            classical_fallback_disabled: true,
            migration_epoch: DEVNET_EPOCH,
            clsag_to_pq_binding_root: root_from_parts(
                "devnet-clsag-to-pq-decoy-entropy-binding",
                &[HashPart::Str(&audit_id)],
            ),
            entropy_floor_guard_root: root_from_parts(
                "devnet-clsag-decoy-entropy-floor-pq-guard",
                &[HashPart::Str(&audit_id)],
            ),
            signature_age_guard_root: root_from_parts(
                "devnet-clsag-signature-age-diversity-pq-guard",
                &[HashPart::Str(&audit_id)],
            ),
            ring_member_entropy_guard_root: root_from_parts(
                "devnet-clsag-ring-member-entropy-pq-guard",
                &[HashPart::Str(&audit_id)],
            ),
            attestation_root: root_from_parts(
                "devnet-clsag-decoy-entropy-floor-pq-attestation",
                &[HashPart::Str(&audit_id)],
            ),
            status: AuditStatus::PqSafe,
        })
        .expect("devnet CLSAG PQ migration safety inserts");

    state
        .insert_low_fee_scan_batch(LowFeeScanBatch {
            batch_id: "clsag-decoy-entropy-floor-low-fee-scan-batch-devnet-0".to_string(),
            audit_id,
            diversity_id,
            sample_id,
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            batch_outputs: DEFAULT_TARGET_LOW_FEE_BATCH_OUTPUTS,
            wallet_scan_count: 896,
            user_fee_bps: DEFAULT_MAX_BATCH_FEE_BPS,
            rebate_bps: DEFAULT_TARGET_BATCH_REBATE_BPS,
            batched_clsag_scan_root: root_from_parts(
                "devnet-clsag-batched-low-fee-wallet-scan",
                &[HashPart::Str("0")],
            ),
            scan_sponsor_receipt_root: root_from_parts(
                "devnet-clsag-low-fee-scan-sponsor-receipt",
                &[HashPart::Str("0")],
            ),
            privacy_budget_root: root_from_parts(
                "devnet-clsag-low-fee-scan-privacy-budget",
                &[HashPart::Str("0")],
            ),
            status: AuditStatus::BatchEligible,
        })
        .expect("devnet CLSAG low-fee scan batch inserts");

    state.refresh_roots();
    state
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

fn empty_root(domain: &str) -> String {
    root_from_parts(domain, &[HashPart::Str("empty")])
}

fn root_from_record(domain: &str, record: &Value) -> String {
    root_from_parts(domain, &[HashPart::Json(record)])
}

fn root_from_parts(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("CLSAG-DECOY-ENTROPY-FLOOR-AUDITOR-{domain}"),
        parts,
        32,
    )
}

fn map_root<'a>(domain: &str, entries: impl Iterator<Item = (&'a str, String)>) -> String {
    let leaves = entries
        .map(|(id, root)| {
            json!({
                "id": id,
                "root": root,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("CLSAG-DECOY-ENTROPY-FLOOR-AUDITOR-{domain}"),
        &leaves,
    )
}

fn weighted_average_bps(entries: impl Iterator<Item = (u64, u64)>) -> u64 {
    let mut weighted_sum = 0_u128;
    let mut total_weight = 0_u128;
    for (score, weight) in entries {
        weighted_sum += score as u128 * weight as u128;
        total_weight += weight as u128;
    }
    if total_weight == 0 {
        0
    } else {
        (weighted_sum / total_weight).min(MAX_SCORE as u128) as u64
    }
}
