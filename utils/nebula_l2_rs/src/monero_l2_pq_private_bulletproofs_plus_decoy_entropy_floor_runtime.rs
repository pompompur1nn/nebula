use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = MoneroL2PqPrivateBulletproofsPlusDecoyEntropyFloorRuntimeResult<T>;
pub type MoneroL2PqPrivateBulletproofsPlusDecoyEntropyFloorRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_BULLETPROOFS_PLUS_DECOY_ENTROPY_FLOOR_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-private-bulletproofs-plus-decoy-entropy-floor-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_BULLETPROOFS_PLUS_DECOY_ENTROPY_FLOOR_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const BULLETPROOFS_PLUS_DECOY_FLOOR_SCHEME: &str =
    "bulletproofs_plus-decoy-entropy-floor-observation-root-v1";
pub const PROOF_BATCH_DIVERSITY_SCHEME: &str =
    "bulletproofs-plus-proof-batch-diversity-score-root-v1";
pub const OUTPUT_AGE_DIVERSITY_SCORE_SCHEME: &str =
    "bulletproofs_plus-output-age-diversity-score-root-v1";
pub const PQ_MIGRATION_SAFETY_SCORE_SCHEME: &str =
    "ML-DSA-87+ML-KEM-1024+SLH-DSA-SHAKE-256f-bulletproofs_plus-decoy-entropy-floor-safety-root-v1";
pub const LOW_FEE_SCAN_BATCH_SCHEME: &str =
    "low-fee-private-bulletproofs_plus-decoy-entropy-floor-scan-batch-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "deterministic-public-bulletproofs-plus-decoy-entropy-floor-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_addresses_view_keys_spend_keys_amounts_output_indices_key_images_ring_members_mlsag_scalars_decoy_samples_or_scan_secrets";
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
pub const DEFAULT_MIN_FLOOR_SCORE_BPS: u64 = 8_950;
pub const DEFAULT_TARGET_FLOOR_SCORE_BPS: u64 = 9_700;
pub const DEFAULT_MIN_SHANNON_ENTROPY_MILLIBITS: u64 = 3_700_000;
pub const DEFAULT_TARGET_SHANNON_ENTROPY_MILLIBITS: u64 = 4_900_000;
pub const DEFAULT_MIN_MIN_ENTROPY_MILLIBITS: u64 = 3_050_000;
pub const DEFAULT_TARGET_MIN_ENTROPY_MILLIBITS: u64 = 4_250_000;
pub const DEFAULT_MIN_EFFECTIVE_DECOYS: u64 = 104;
pub const DEFAULT_TARGET_EFFECTIVE_DECOYS: u64 = 126;
pub const DEFAULT_MIN_ANONYMITY_SET_OUTPUTS: u64 = 131_072;
pub const DEFAULT_TARGET_ANONYMITY_SET_OUTPUTS: u64 = 524_288;
pub const DEFAULT_MIN_ENTROPY_BANDS: u16 = 6;
pub const DEFAULT_TARGET_ENTROPY_BANDS: u16 = 24;
pub const DEFAULT_MIN_OUTPUT_AGE_DIVERSITY_BPS: u64 = 8_850;
pub const DEFAULT_TARGET_OUTPUT_AGE_DIVERSITY_BPS: u64 = 9_650;
pub const DEFAULT_MAX_YOUNG_OUTPUT_DOMINANCE_BPS: u64 = 2_000;
pub const DEFAULT_MAX_AGE_BUCKET_SKEW_BPS: u64 = 600;
pub const DEFAULT_MIN_PQ_SAFETY_BPS: u64 = 9_150;
pub const DEFAULT_TARGET_PQ_SAFETY_BPS: u64 = 9_850;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_LOW_FEE_BATCH_OUTPUTS: u64 = 4_096;
pub const DEFAULT_TARGET_LOW_FEE_BATCH_OUTPUTS: u64 = 32_768;
pub const DEFAULT_ORACLE_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_SCAN_WINDOW_BLOCKS: u64 = 360;
pub const DEFAULT_MAX_BATCH_FEE_BPS: u64 = 5;
pub const DEFAULT_TARGET_BATCH_REBATE_BPS: u64 = 4;
pub const DEFAULT_PUBLIC_BUCKET_SIZE: u64 = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntropyFloorLane {
    WalletReceiveScan,
    WatchOnlyScan,
    BridgeDepositScan,
    SwapSettlementScan,
    MerchantReceiveScan,
    ConsolidationShieldingScan,
    ReorgFloorRepair,
}

impl EntropyFloorLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletReceiveScan => "wallet_receive_scan",
            Self::WatchOnlyScan => "watch_only_scan",
            Self::BridgeDepositScan => "bridge_deposit_scan",
            Self::SwapSettlementScan => "swap_settlement_scan",
            Self::MerchantReceiveScan => "merchant_receive_scan",
            Self::ConsolidationShieldingScan => "consolidation_shielding_scan",
            Self::ReorgFloorRepair => "reorg_floor_repair",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntropyFloorStatus {
    Draft,
    Observed,
    FloorBanded,
    AgeDiversityScored,
    PqSafe,
    BatchEligible,
    Sealed,
    Expired,
    Quarantined,
}

impl EntropyFloorStatus {
    pub fn public_usable(self) -> bool {
        matches!(
            self,
            Self::Observed
                | Self::FloorBanded
                | Self::AgeDiversityScored
                | Self::PqSafe
                | Self::BatchEligible
                | Self::Sealed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofBatchDiversityKind {
    RangeProofHeavy,
    OutputCommitmentMixed,
    BridgeDepositBatch,
    SwapSettlementBatch,
    MerchantReceiveBatch,
    ConsolidationBatch,
    ReorgRepairBatch,
    ProverRotationBatch,
}

impl ProofBatchDiversityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RangeProofHeavy => "range_proof_heavy",
            Self::OutputCommitmentMixed => "output_commitment_mixed",
            Self::BridgeDepositBatch => "bridge_deposit_batch",
            Self::SwapSettlementBatch => "swap_settlement_batch",
            Self::MerchantReceiveBatch => "merchant_receive_batch",
            Self::ConsolidationBatch => "consolidation_batch",
            Self::ReorgRepairBatch => "reorg_repair_batch",
            Self::ProverRotationBatch => "prover_rotation_batch",
        }
    }
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
    pub min_entropy_bands: u16,
    pub target_entropy_bands: u16,
    pub min_output_age_diversity_bps: u64,
    pub target_output_age_diversity_bps: u64,
    pub max_young_output_dominance_bps: u64,
    pub max_age_bucket_skew_bps: u64,
    pub min_pq_safety_bps: u64,
    pub target_pq_safety_bps: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub min_low_fee_batch_outputs: u64,
    pub target_low_fee_batch_outputs: u64,
    pub oracle_ttl_blocks: u64,
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
            min_entropy_bands: DEFAULT_MIN_ENTROPY_BANDS,
            target_entropy_bands: DEFAULT_TARGET_ENTROPY_BANDS,
            min_output_age_diversity_bps: DEFAULT_MIN_OUTPUT_AGE_DIVERSITY_BPS,
            target_output_age_diversity_bps: DEFAULT_TARGET_OUTPUT_AGE_DIVERSITY_BPS,
            max_young_output_dominance_bps: DEFAULT_MAX_YOUNG_OUTPUT_DOMINANCE_BPS,
            max_age_bucket_skew_bps: DEFAULT_MAX_AGE_BUCKET_SKEW_BPS,
            min_pq_safety_bps: DEFAULT_MIN_PQ_SAFETY_BPS,
            target_pq_safety_bps: DEFAULT_TARGET_PQ_SAFETY_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            min_low_fee_batch_outputs: DEFAULT_MIN_LOW_FEE_BATCH_OUTPUTS,
            target_low_fee_batch_outputs: DEFAULT_TARGET_LOW_FEE_BATCH_OUTPUTS,
            oracle_ttl_blocks: DEFAULT_ORACLE_TTL_BLOCKS,
            scan_window_blocks: DEFAULT_SCAN_WINDOW_BLOCKS,
            max_batch_fee_bps: DEFAULT_MAX_BATCH_FEE_BPS,
            target_batch_rebate_bps: DEFAULT_TARGET_BATCH_REBATE_BPS,
            public_bucket_size: DEFAULT_PUBLIC_BUCKET_SIZE,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure(
            self.min_ring_size >= 16,
            "minimum Bulletproofs+ ring size is too low",
        )?;
        ensure(
            self.target_ring_size >= self.min_ring_size,
            "target Bulletproofs+ ring size must cover minimum ring size",
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
            "target anonymity set must cover Bulletproofs+ privacy floor",
        )?;
        ensure(
            self.target_entropy_bands >= self.min_entropy_bands,
            "target entropy bands must cover proof batch diversity scores",
        )?;
        ensure(
            self.target_output_age_diversity_bps >= self.min_output_age_diversity_bps,
            "target output age diversity must cover minimum age diversity",
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
                && self.min_output_age_diversity_bps <= MAX_BPS
                && self.target_output_age_diversity_bps <= MAX_BPS
                && self.max_young_output_dominance_bps <= MAX_BPS
                && self.max_age_bucket_skew_bps <= MAX_BPS
                && self.min_pq_safety_bps <= MAX_BPS
                && self.target_pq_safety_bps <= MAX_BPS,
            "basis-point threshold exceeds max bps",
        )?;
        ensure(self.oracle_ttl_blocks > 0, "oracle ttl must be non-zero")?;
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
            "bulletproofs-plus-decoy-entropy-floor-config",
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
    pub entropy_floor_observations: u64,
    pub proof_batch_diversity_scores: u64,
    pub output_age_diversity_scores: u64,
    pub pq_migration_safety_scores: u64,
    pub low_fee_scan_batches: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "bulletproofs-plus-decoy-entropy-floor-counters",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub entropy_floor_observations_root: String,
    pub proof_batch_diversity_scores_root: String,
    pub output_age_diversity_scores_root: String,
    pub pq_migration_safety_scores_root: String,
    pub low_fee_scan_batches_root: String,
    pub deterministic_state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            entropy_floor_observations_root: empty_root(BULLETPROOFS_PLUS_DECOY_FLOOR_SCHEME),
            proof_batch_diversity_scores_root: empty_root(PROOF_BATCH_DIVERSITY_SCHEME),
            output_age_diversity_scores_root: empty_root(OUTPUT_AGE_DIVERSITY_SCORE_SCHEME),
            pq_migration_safety_scores_root: empty_root(PQ_MIGRATION_SAFETY_SCORE_SCHEME),
            low_fee_scan_batches_root: empty_root(LOW_FEE_SCAN_BATCH_SCHEME),
            deterministic_state_root: empty_root("bulletproofs-plus-decoy-entropy-floor-state"),
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
pub struct EntropyFloorObservation {
    pub observation_id: String,
    pub lane: EntropyFloorLane,
    pub epoch: u64,
    pub monero_height_bucket: u64,
    pub ring_size: u16,
    pub anonymity_set_outputs: u64,
    pub effective_decoys: u64,
    pub floor_score_bps: u64,
    pub shannon_entropy_millibits: u64,
    pub min_entropy_millibits: u64,
    pub dominant_decoy_bucket_bps: u64,
    pub bulletproofs_plus_distribution_skew_bps: u64,
    pub redacted_bulletproofs_plus_sample_root: String,
    pub output_commitment_set_root: String,
    pub key_image_domain_root: String,
    pub oracle_attestation_root: String,
    pub expires_at_monero_height: u64,
    pub status: EntropyFloorStatus,
}

impl EntropyFloorObservation {
    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "lane": self.lane.as_str(),
            "epoch": self.epoch,
            "monero_height_bucket": self.monero_height_bucket,
            "ring_size": self.ring_size,
            "anonymity_set_outputs": self.anonymity_set_outputs,
            "effective_decoys": self.effective_decoys,
            "floor_score_bps": self.floor_score_bps,
            "shannon_entropy_millibits": self.shannon_entropy_millibits,
            "min_entropy_millibits": self.min_entropy_millibits,
            "dominant_decoy_bucket_bps": self.dominant_decoy_bucket_bps,
            "bulletproofs_plus_distribution_skew_bps": self.bulletproofs_plus_distribution_skew_bps,
            "redacted_bulletproofs_plus_sample_root": self.redacted_bulletproofs_plus_sample_root,
            "output_commitment_set_root": self.output_commitment_set_root,
            "key_image_domain_root": self.key_image_domain_root,
            "oracle_attestation_root": self.oracle_attestation_root,
            "expires_at_monero_height": self.expires_at_monero_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(BULLETPROOFS_PLUS_DECOY_FLOOR_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofBatchDiversityScore {
    pub diversity_id: String,
    pub observation_id: String,
    pub batch_kind: ProofBatchDiversityKind,
    pub proof_batch_size: u64,
    pub distinct_generator_domains: u16,
    pub aggregation_fanout: u16,
    pub proof_family_count: u16,
    pub proof_batch_diversity_bps: u64,
    pub dominant_proof_family_bps: u64,
    pub transcript_reuse_risk_bps: u64,
    pub redacted_batch_transcript_root: String,
    pub generator_domain_mix_root: String,
    pub proof_batch_witness_root: String,
    pub status: EntropyFloorStatus,
}

impl ProofBatchDiversityScore {
    pub fn public_record(&self) -> Value {
        json!({
            "diversity_id": self.diversity_id,
            "observation_id": self.observation_id,
            "batch_kind": self.batch_kind.as_str(),
            "proof_batch_size": self.proof_batch_size,
            "distinct_generator_domains": self.distinct_generator_domains,
            "aggregation_fanout": self.aggregation_fanout,
            "proof_family_count": self.proof_family_count,
            "proof_batch_diversity_bps": self.proof_batch_diversity_bps,
            "dominant_proof_family_bps": self.dominant_proof_family_bps,
            "transcript_reuse_risk_bps": self.transcript_reuse_risk_bps,
            "redacted_batch_transcript_root": self.redacted_batch_transcript_root,
            "generator_domain_mix_root": self.generator_domain_mix_root,
            "proof_batch_witness_root": self.proof_batch_witness_root,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(PROOF_BATCH_DIVERSITY_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OutputAgeDiversityScore {
    pub diversity_id: String,
    pub observation_id: String,
    pub scan_window_blocks: u64,
    pub scored_outputs: u64,
    pub age_bucket_count: u16,
    pub output_age_diversity_bps: u64,
    pub young_output_dominance_bps: u64,
    pub age_bucket_skew_bps: u64,
    pub median_output_age_blocks: u64,
    pub p90_output_age_blocks: u64,
    pub redacted_age_histogram_root: String,
    pub age_diversity_proof_root: String,
    pub residual_privacy_root: String,
    pub status: EntropyFloorStatus,
}

impl OutputAgeDiversityScore {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(OUTPUT_AGE_DIVERSITY_SCORE_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqMigrationSafetyScore {
    pub safety_id: String,
    pub observation_id: String,
    pub pq_security_bits: u16,
    pub pq_safety_bps: u64,
    pub classical_fallback_disabled: bool,
    pub migration_epoch: u64,
    pub bulletproofs_plus_to_pq_binding_root: String,
    pub entropy_floor_guard_root: String,
    pub output_age_guard_root: String,
    pub attestation_root: String,
    pub status: EntropyFloorStatus,
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
    pub observation_id: String,
    pub diversity_id: String,
    pub fee_asset_id: String,
    pub batch_outputs: u64,
    pub wallet_scan_count: u64,
    pub user_fee_bps: u64,
    pub rebate_bps: u64,
    pub batched_bulletproofs_plus_scan_root: String,
    pub scan_sponsor_receipt_root: String,
    pub privacy_budget_root: String,
    pub status: EntropyFloorStatus,
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
    pub entropy_floor_observations: BTreeMap<String, EntropyFloorObservation>,
    pub proof_batch_diversity_scores: BTreeMap<String, ProofBatchDiversityScore>,
    pub output_age_diversity_scores: BTreeMap<String, OutputAgeDiversityScore>,
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
            entropy_floor_observations: BTreeMap::new(),
            proof_batch_diversity_scores: BTreeMap::new(),
            output_age_diversity_scores: BTreeMap::new(),
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
            "runtime": "monero_l2_pq_private_bulletproofs_plus_decoy_entropy_floor_runtime",
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
            "aggregate_proof_batch_diversity_bps": self.aggregate_proof_batch_diversity_bps(),
            "aggregate_output_age_diversity_bps": self.aggregate_output_age_diversity_bps(),
            "public_record_scheme": PUBLIC_RECORD_SCHEME,
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.deterministic_state_root.clone()
    }

    pub fn insert_entropy_floor_observation(
        &mut self,
        observation: EntropyFloorObservation,
    ) -> Result<()> {
        ensure(
            observation.ring_size >= self.config.min_ring_size,
            "Bulletproofs+ entropy floor observation ring size is below minimum",
        )?;
        ensure(
            observation.anonymity_set_outputs >= self.config.min_anonymity_set_outputs,
            "Bulletproofs+ entropy floor observation is below anonymity-set privacy floor",
        )?;
        ensure(
            observation.effective_decoys >= self.config.min_effective_decoys,
            "Bulletproofs+ entropy floor observation effective decoys are below floor",
        )?;
        ensure(
            observation.floor_score_bps >= self.config.min_floor_score_bps,
            "Bulletproofs+ entropy floor score is below floor",
        )?;
        ensure(
            observation.shannon_entropy_millibits >= self.config.min_shannon_entropy_millibits,
            "Bulletproofs+ Shannon entropy is below floor",
        )?;
        ensure(
            observation.min_entropy_millibits >= self.config.min_min_entropy_millibits,
            "Bulletproofs+ min-entropy is below floor",
        )?;
        ensure(
            observation.dominant_decoy_bucket_bps <= MAX_BPS,
            "dominant decoy bucket share exceeds max bps",
        )?;
        ensure(
            observation.bulletproofs_plus_distribution_skew_bps
                <= self.config.max_age_bucket_skew_bps,
            "Bulletproofs+ decoy distribution skew exceeds cap",
        )?;
        ensure(
            observation.expires_at_monero_height > self.monero_height,
            "Bulletproofs+ entropy floor observation must expire in the future",
        )?;
        self.entropy_floor_observations
            .insert(observation.observation_id.clone(), observation);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_proof_batch_diversity_score(
        &mut self,
        diversity: ProofBatchDiversityScore,
    ) -> Result<()> {
        ensure(
            self.entropy_floor_observations
                .contains_key(&diversity.observation_id),
            "proof batch diversity score references unknown observation",
        )?;
        ensure(
            diversity.proof_batch_size >= self.config.min_low_fee_batch_outputs,
            "proof batch diversity score is below minimum proof batch size",
        )?;
        ensure(
            diversity.distinct_generator_domains >= self.config.min_entropy_bands,
            "proof batch diversity score has too few generator domains",
        )?;
        ensure(
            diversity.aggregation_fanout >= 2,
            "proof batch diversity score must aggregate more than one proof",
        )?;
        ensure(
            diversity.proof_family_count >= 2,
            "proof batch diversity score must mix proof families",
        )?;
        ensure(
            diversity.proof_batch_diversity_bps >= self.config.min_floor_score_bps,
            "proof batch diversity score is below diversity floor",
        )?;
        ensure(
            diversity.dominant_proof_family_bps <= MAX_BPS,
            "proof batch diversity dominant proof family exceeds max bps",
        )?;
        ensure(
            diversity.transcript_reuse_risk_bps <= self.config.max_age_bucket_skew_bps,
            "proof batch transcript reuse risk exceeds cap",
        )?;
        self.proof_batch_diversity_scores
            .insert(diversity.diversity_id.clone(), diversity);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_output_age_diversity_score(
        &mut self,
        diversity: OutputAgeDiversityScore,
    ) -> Result<()> {
        ensure(
            self.entropy_floor_observations
                .contains_key(&diversity.observation_id),
            "output age diversity score references unknown observation",
        )?;
        ensure(
            diversity.scan_window_blocks <= self.config.scan_window_blocks,
            "output age diversity score exceeds configured scan window",
        )?;
        ensure(
            diversity.scored_outputs >= self.config.min_anonymity_set_outputs,
            "output age diversity scored outputs are below privacy floor",
        )?;
        ensure(
            diversity.age_bucket_count >= self.config.min_entropy_bands,
            "output age diversity score has too few age buckets",
        )?;
        ensure(
            diversity.output_age_diversity_bps >= self.config.min_output_age_diversity_bps,
            "output age diversity score is below floor",
        )?;
        ensure(
            diversity.young_output_dominance_bps <= self.config.max_young_output_dominance_bps,
            "young output dominance exceeds cap",
        )?;
        ensure(
            diversity.age_bucket_skew_bps <= self.config.max_age_bucket_skew_bps,
            "output age bucket skew exceeds cap",
        )?;
        ensure(
            diversity.p90_output_age_blocks >= diversity.median_output_age_blocks,
            "p90 output age must cover median output age",
        )?;
        self.output_age_diversity_scores
            .insert(diversity.diversity_id.clone(), diversity);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_pq_migration_safety_score(
        &mut self,
        safety: PqMigrationSafetyScore,
    ) -> Result<()> {
        ensure(
            self.entropy_floor_observations
                .contains_key(&safety.observation_id),
            "PQ migration safety score references unknown observation",
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
            self.entropy_floor_observations
                .contains_key(&batch.observation_id),
            "low-fee scan batch references unknown observation",
        )?;
        ensure(
            self.output_age_diversity_scores
                .contains_key(&batch.diversity_id),
            "low-fee scan batch references unknown age diversity score",
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

    pub fn usable_entropy_floor_observations(&self) -> Vec<&EntropyFloorObservation> {
        self.entropy_floor_observations
            .values()
            .filter(|observation| observation.status.public_usable())
            .collect()
    }

    pub fn aggregate_floor_score_bps(&self) -> u64 {
        weighted_average_bps(
            self.entropy_floor_observations
                .values()
                .map(|observation| (observation.floor_score_bps, observation.effective_decoys)),
        )
    }

    pub fn aggregate_output_age_diversity_bps(&self) -> u64 {
        weighted_average_bps(
            self.output_age_diversity_scores
                .values()
                .map(|score| (score.output_age_diversity_bps, score.scored_outputs)),
        )
    }

    pub fn aggregate_proof_batch_diversity_bps(&self) -> u64 {
        weighted_average_bps(self.proof_batch_diversity_scores.values().map(|score| {
            (
                score.proof_batch_diversity_bps,
                score.proof_batch_size.max(1),
            )
        }))
    }

    pub fn refresh_roots(&mut self) {
        self.counters.entropy_floor_observations = self.entropy_floor_observations.len() as u64;
        self.counters.proof_batch_diversity_scores = self.proof_batch_diversity_scores.len() as u64;
        self.counters.output_age_diversity_scores = self.output_age_diversity_scores.len() as u64;
        self.counters.pq_migration_safety_scores = self.pq_migration_safety_scores.len() as u64;
        self.counters.low_fee_scan_batches = self.low_fee_scan_batches.len() as u64;

        self.roots.entropy_floor_observations_root = map_root(
            BULLETPROOFS_PLUS_DECOY_FLOOR_SCHEME,
            self.entropy_floor_observations
                .iter()
                .map(|(id, observation)| (id.as_str(), observation.state_root())),
        );
        self.roots.proof_batch_diversity_scores_root = map_root(
            PROOF_BATCH_DIVERSITY_SCHEME,
            self.proof_batch_diversity_scores
                .iter()
                .map(|(id, band)| (id.as_str(), band.state_root())),
        );
        self.roots.output_age_diversity_scores_root = map_root(
            OUTPUT_AGE_DIVERSITY_SCORE_SCHEME,
            self.output_age_diversity_scores
                .iter()
                .map(|(id, diversity)| (id.as_str(), diversity.state_root())),
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
            "bulletproofs-plus-decoy-entropy-floor-state",
            &[
                HashPart::Str(&self.protocol_version),
                HashPart::Str(&self.chain_id),
                HashPart::Str(&self.config.state_root()),
                HashPart::U64(self.l2_height),
                HashPart::U64(self.monero_height),
                HashPart::U64(self.epoch),
                HashPart::Str(&self.counters.state_root()),
                HashPart::Str(&self.roots.entropy_floor_observations_root),
                HashPart::Str(&self.roots.proof_batch_diversity_scores_root),
                HashPart::Str(&self.roots.output_age_diversity_scores_root),
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
        .expect("default Bulletproofs+ decoy entropy floor oracle config is valid")
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let observation_id = "bulletproofs-plus-decoy-entropy-floor-devnet-0".to_string();
    let diversity_id = "bulletproofs_plus-output-age-diversity-devnet-0".to_string();

    state
        .insert_entropy_floor_observation(EntropyFloorObservation {
            observation_id: observation_id.clone(),
            lane: EntropyFloorLane::WalletReceiveScan,
            epoch: DEVNET_EPOCH,
            monero_height_bucket: bucket(DEVNET_MONERO_HEIGHT, DEFAULT_PUBLIC_BUCKET_SIZE),
            ring_size: DEFAULT_TARGET_RING_SIZE,
            anonymity_set_outputs: DEFAULT_TARGET_ANONYMITY_SET_OUTPUTS,
            effective_decoys: DEFAULT_TARGET_EFFECTIVE_DECOYS,
            floor_score_bps: DEFAULT_TARGET_FLOOR_SCORE_BPS,
            shannon_entropy_millibits: DEFAULT_TARGET_SHANNON_ENTROPY_MILLIBITS,
            min_entropy_millibits: DEFAULT_TARGET_MIN_ENTROPY_MILLIBITS,
            dominant_decoy_bucket_bps: 1_120,
            bulletproofs_plus_distribution_skew_bps: 240,
            redacted_bulletproofs_plus_sample_root: root_from_parts(
                "devnet-redacted-bulletproofs_plus-decoy-entropy-sample",
                &[HashPart::Str(&observation_id)],
            ),
            output_commitment_set_root: root_from_parts(
                "devnet-bulletproofs_plus-output-commitment-set",
                &[HashPart::Str(&observation_id)],
            ),
            key_image_domain_root: root_from_parts(
                "devnet-bulletproofs_plus-key-image-domain",
                &[HashPart::Str(&observation_id)],
            ),
            oracle_attestation_root: root_from_parts(
                "devnet-bulletproofs_plus-decoy-entropy-floor-attestation",
                &[HashPart::Str(&observation_id)],
            ),
            expires_at_monero_height: DEVNET_MONERO_HEIGHT + DEFAULT_ORACLE_TTL_BLOCKS,
            status: EntropyFloorStatus::Observed,
        })
        .expect("devnet Bulletproofs+ entropy floor observation inserts");

    for (index, batch_kind, batch_size, generator_domains, fanout, families, diversity_score) in [
        (
            0_u64,
            ProofBatchDiversityKind::RangeProofHeavy,
            34_816_u64,
            26_u16,
            8_u16,
            4_u16,
            9_760_u64,
        ),
        (
            1,
            ProofBatchDiversityKind::OutputCommitmentMixed,
            37_888,
            28,
            8,
            5,
            9_720,
        ),
        (
            2,
            ProofBatchDiversityKind::BridgeDepositBatch,
            41_984,
            30,
            16,
            5,
            9_690,
        ),
        (
            3,
            ProofBatchDiversityKind::SwapSettlementBatch,
            45_056,
            32,
            16,
            6,
            9_640,
        ),
        (
            4,
            ProofBatchDiversityKind::MerchantReceiveBatch,
            49_152,
            34,
            16,
            6,
            9_610,
        ),
        (
            5,
            ProofBatchDiversityKind::ProverRotationBatch,
            52_224,
            36,
            32,
            7,
            9_590,
        ),
    ] {
        let diversity_id = format!("bulletproofs-plus-proof-batch-diversity-score-devnet-{index}");
        state
            .insert_proof_batch_diversity_score(ProofBatchDiversityScore {
                diversity_id: diversity_id.clone(),
                observation_id: observation_id.clone(),
                batch_kind,
                proof_batch_size: batch_size,
                distinct_generator_domains: generator_domains,
                aggregation_fanout: fanout,
                proof_family_count: families,
                proof_batch_diversity_bps: diversity_score,
                dominant_proof_family_bps: 1_180 + (index * 20),
                transcript_reuse_risk_bps: 120 + (index * 12),
                redacted_batch_transcript_root: root_from_parts(
                    "devnet-redacted-bulletproofs-plus-proof-batch-transcript",
                    &[HashPart::Str(&diversity_id)],
                ),
                generator_domain_mix_root: root_from_parts(
                    "devnet-bulletproofs-plus-generator-domain-mix",
                    &[HashPart::Str(&diversity_id)],
                ),
                proof_batch_witness_root: root_from_parts(
                    "devnet-bulletproofs-plus-proof-batch-witness",
                    &[HashPart::Str(&diversity_id)],
                ),
                status: EntropyFloorStatus::FloorBanded,
            })
            .expect("devnet Bulletproofs+ proof batch diversity score inserts");
    }

    state
        .insert_output_age_diversity_score(OutputAgeDiversityScore {
            diversity_id: diversity_id.clone(),
            observation_id: observation_id.clone(),
            scan_window_blocks: DEFAULT_SCAN_WINDOW_BLOCKS,
            scored_outputs: DEFAULT_TARGET_ANONYMITY_SET_OUTPUTS,
            age_bucket_count: DEFAULT_TARGET_ENTROPY_BANDS,
            output_age_diversity_bps: DEFAULT_TARGET_OUTPUT_AGE_DIVERSITY_BPS,
            young_output_dominance_bps: 1_140,
            age_bucket_skew_bps: 210,
            median_output_age_blocks: 54_000,
            p90_output_age_blocks: 388_800,
            redacted_age_histogram_root: root_from_parts(
                "devnet-redacted-bulletproofs_plus-output-age-histogram",
                &[HashPart::Str(&diversity_id)],
            ),
            age_diversity_proof_root: root_from_parts(
                "devnet-bulletproofs_plus-output-age-diversity-proof",
                &[HashPart::Str(&diversity_id)],
            ),
            residual_privacy_root: root_from_parts(
                "devnet-bulletproofs_plus-output-age-diversity-residual-privacy",
                &[HashPart::Str(&diversity_id)],
            ),
            status: EntropyFloorStatus::AgeDiversityScored,
        })
        .expect("devnet Bulletproofs+ output age diversity score inserts");

    state
        .insert_pq_migration_safety_score(PqMigrationSafetyScore {
            safety_id: "bulletproofs_plus-decoy-entropy-floor-pq-safety-devnet-0".to_string(),
            observation_id: observation_id.clone(),
            pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            pq_safety_bps: DEFAULT_TARGET_PQ_SAFETY_BPS,
            classical_fallback_disabled: true,
            migration_epoch: DEVNET_EPOCH,
            bulletproofs_plus_to_pq_binding_root: root_from_parts(
                "devnet-bulletproofs_plus-to-pq-decoy-entropy-binding",
                &[HashPart::Str(&observation_id)],
            ),
            entropy_floor_guard_root: root_from_parts(
                "devnet-bulletproofs_plus-decoy-entropy-floor-pq-guard",
                &[HashPart::Str(&observation_id)],
            ),
            output_age_guard_root: root_from_parts(
                "devnet-bulletproofs_plus-output-age-diversity-pq-guard",
                &[HashPart::Str(&observation_id)],
            ),
            attestation_root: root_from_parts(
                "devnet-bulletproofs_plus-decoy-entropy-floor-pq-attestation",
                &[HashPart::Str(&observation_id)],
            ),
            status: EntropyFloorStatus::PqSafe,
        })
        .expect("devnet Bulletproofs+ PQ migration safety inserts");

    state
        .insert_low_fee_scan_batch(LowFeeScanBatch {
            batch_id: "bulletproofs_plus-decoy-entropy-floor-low-fee-scan-batch-devnet-0"
                .to_string(),
            observation_id,
            diversity_id,
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            batch_outputs: DEFAULT_TARGET_LOW_FEE_BATCH_OUTPUTS,
            wallet_scan_count: 896,
            user_fee_bps: DEFAULT_MAX_BATCH_FEE_BPS,
            rebate_bps: DEFAULT_TARGET_BATCH_REBATE_BPS,
            batched_bulletproofs_plus_scan_root: root_from_parts(
                "devnet-bulletproofs_plus-batched-low-fee-wallet-scan",
                &[HashPart::Str("0")],
            ),
            scan_sponsor_receipt_root: root_from_parts(
                "devnet-bulletproofs_plus-low-fee-scan-sponsor-receipt",
                &[HashPart::Str("0")],
            ),
            privacy_budget_root: root_from_parts(
                "devnet-bulletproofs_plus-low-fee-scan-privacy-budget",
                &[HashPart::Str("0")],
            ),
            status: EntropyFloorStatus::BatchEligible,
        })
        .expect("devnet Bulletproofs+ low-fee scan batch inserts");

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
        &format!("BULLETPROOFS-PLUS-DECOY-ENTROPY-FLOOR-{domain}"),
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
        &format!("BULLETPROOFS-PLUS-DECOY-ENTROPY-FLOOR-{domain}"),
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
