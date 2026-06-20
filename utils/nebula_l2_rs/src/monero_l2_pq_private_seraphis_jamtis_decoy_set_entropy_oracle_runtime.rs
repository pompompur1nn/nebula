use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = MoneroL2PqPrivateSeraphisJamtisDecoySetEntropyOracleRuntimeResult<T>;
pub type MoneroL2PqPrivateSeraphisJamtisDecoySetEntropyOracleRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_SERAPHIS_JAMTIS_DECOY_SET_ENTROPY_ORACLE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-private-seraphis-jamtis-decoy-set-entropy-oracle-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_SERAPHIS_JAMTIS_DECOY_SET_ENTROPY_ORACLE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ENTROPY_ORACLE_SCHEME: &str = "seraphis-jamtis-decoy-set-entropy-oracle-root-v1";
pub const RING_DECOY_ENTROPY_BAND_SCHEME: &str = "seraphis-jamtis-ring-decoy-entropy-band-root-v1";
pub const VIEWTAG_SCAN_QUALITY_SCHEME: &str = "seraphis-jamtis-viewtag-scan-quality-root-v1";
pub const PQ_MIGRATION_SAFETY_SCORE_SCHEME: &str =
    "ML-DSA-87+ML-KEM-1024+SLH-DSA-SHAKE-256f-seraphis-jamtis-decoy-set-entropy-safety-root-v1";
pub const LOW_FEE_WALLET_SCAN_BATCH_SCHEME: &str =
    "low-fee-private-seraphis-jamtis-wallet-scan-batch-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "deterministic-public-seraphis-jamtis-decoy-set-entropy-oracle-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_addresses_view_keys_spend_keys_amounts_output_indices_viewtags_ring_members_subaddress_indices_entropy_samples_or_scan_secrets";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_140_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_816_000;
pub const DEVNET_EPOCH: u64 = 17_400;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_SCORE: u64 = 10_000;
pub const DEFAULT_MIN_RING_SIZE: u16 = 16;
pub const DEFAULT_TARGET_RING_SIZE: u16 = 128;
pub const DEFAULT_MIN_ENTROPY_SCORE_BPS: u64 = 8_900;
pub const DEFAULT_TARGET_ENTROPY_SCORE_BPS: u64 = 9_650;
pub const DEFAULT_MIN_SHANNON_ENTROPY_MILLIBITS: u64 = 3_600_000;
pub const DEFAULT_TARGET_SHANNON_ENTROPY_MILLIBITS: u64 = 4_800_000;
pub const DEFAULT_MIN_MIN_ENTROPY_MILLIBITS: u64 = 2_900_000;
pub const DEFAULT_TARGET_MIN_ENTROPY_MILLIBITS: u64 = 4_100_000;
pub const DEFAULT_MIN_EFFECTIVE_DECOYS: u64 = 96;
pub const DEFAULT_TARGET_EFFECTIVE_DECOYS: u64 = 124;
pub const DEFAULT_MIN_ANONYMITY_SET_OUTPUTS: u64 = 131_072;
pub const DEFAULT_TARGET_ANONYMITY_SET_OUTPUTS: u64 = 524_288;
pub const DEFAULT_MIN_RING_ENTROPY_BANDS: u16 = 8;
pub const DEFAULT_TARGET_RING_ENTROPY_BANDS: u16 = 32;
pub const DEFAULT_MIN_VIEWTAG_SCAN_QUALITY_BPS: u64 = 8_800;
pub const DEFAULT_TARGET_VIEWTAG_SCAN_QUALITY_BPS: u64 = 9_700;
pub const DEFAULT_MAX_VIEWTAG_FALSE_DROP_BPS: u64 = 10;
pub const DEFAULT_MAX_SCAN_SKEW_BPS: u64 = 550;
pub const DEFAULT_MIN_PQ_SAFETY_BPS: u64 = 9_100;
pub const DEFAULT_TARGET_PQ_SAFETY_BPS: u64 = 9_800;
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
pub enum EntropyOracleLane {
    WalletReceiveScan,
    WatchOnlyScan,
    BridgeDepositScan,
    SwapSettlementScan,
    MerchantReceiveScan,
    SubaddressFanoutScan,
    ReorgEntropyRepair,
}

impl EntropyOracleLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletReceiveScan => "wallet_receive_scan",
            Self::WatchOnlyScan => "watch_only_scan",
            Self::BridgeDepositScan => "bridge_deposit_scan",
            Self::SwapSettlementScan => "swap_settlement_scan",
            Self::MerchantReceiveScan => "merchant_receive_scan",
            Self::SubaddressFanoutScan => "subaddress_fanout_scan",
            Self::ReorgEntropyRepair => "reorg_entropy_repair",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntropyOracleStatus {
    Draft,
    Observed,
    Banded,
    ScanQualityAttested,
    PqSafe,
    BatchEligible,
    Sealed,
    Expired,
    Quarantined,
}

impl EntropyOracleStatus {
    pub fn public_usable(self) -> bool {
        matches!(
            self,
            Self::Observed
                | Self::Banded
                | Self::ScanQualityAttested
                | Self::PqSafe
                | Self::BatchEligible
                | Self::Sealed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RingEntropyBandKind {
    ColdHistorical,
    WarmRecent,
    HotMempoolAdjacent,
    ChangeLikeShielded,
    BridgeIngress,
    SwapSettlement,
    MerchantFlow,
    ReorgRepair,
}

impl RingEntropyBandKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ColdHistorical => "cold_historical",
            Self::WarmRecent => "warm_recent",
            Self::HotMempoolAdjacent => "hot_mempool_adjacent",
            Self::ChangeLikeShielded => "change_like_shielded",
            Self::BridgeIngress => "bridge_ingress",
            Self::SwapSettlement => "swap_settlement",
            Self::MerchantFlow => "merchant_flow",
            Self::ReorgRepair => "reorg_repair",
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
    pub min_entropy_score_bps: u64,
    pub target_entropy_score_bps: u64,
    pub min_shannon_entropy_millibits: u64,
    pub target_shannon_entropy_millibits: u64,
    pub min_min_entropy_millibits: u64,
    pub target_min_entropy_millibits: u64,
    pub min_effective_decoys: u64,
    pub target_effective_decoys: u64,
    pub min_anonymity_set_outputs: u64,
    pub target_anonymity_set_outputs: u64,
    pub min_ring_entropy_bands: u16,
    pub target_ring_entropy_bands: u16,
    pub min_viewtag_scan_quality_bps: u64,
    pub target_viewtag_scan_quality_bps: u64,
    pub max_viewtag_false_drop_bps: u64,
    pub max_scan_skew_bps: u64,
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
            min_entropy_score_bps: DEFAULT_MIN_ENTROPY_SCORE_BPS,
            target_entropy_score_bps: DEFAULT_TARGET_ENTROPY_SCORE_BPS,
            min_shannon_entropy_millibits: DEFAULT_MIN_SHANNON_ENTROPY_MILLIBITS,
            target_shannon_entropy_millibits: DEFAULT_TARGET_SHANNON_ENTROPY_MILLIBITS,
            min_min_entropy_millibits: DEFAULT_MIN_MIN_ENTROPY_MILLIBITS,
            target_min_entropy_millibits: DEFAULT_TARGET_MIN_ENTROPY_MILLIBITS,
            min_effective_decoys: DEFAULT_MIN_EFFECTIVE_DECOYS,
            target_effective_decoys: DEFAULT_TARGET_EFFECTIVE_DECOYS,
            min_anonymity_set_outputs: DEFAULT_MIN_ANONYMITY_SET_OUTPUTS,
            target_anonymity_set_outputs: DEFAULT_TARGET_ANONYMITY_SET_OUTPUTS,
            min_ring_entropy_bands: DEFAULT_MIN_RING_ENTROPY_BANDS,
            target_ring_entropy_bands: DEFAULT_TARGET_RING_ENTROPY_BANDS,
            min_viewtag_scan_quality_bps: DEFAULT_MIN_VIEWTAG_SCAN_QUALITY_BPS,
            target_viewtag_scan_quality_bps: DEFAULT_TARGET_VIEWTAG_SCAN_QUALITY_BPS,
            max_viewtag_false_drop_bps: DEFAULT_MAX_VIEWTAG_FALSE_DROP_BPS,
            max_scan_skew_bps: DEFAULT_MAX_SCAN_SKEW_BPS,
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
        ensure(self.min_ring_size >= 16, "minimum ring size is too low")?;
        ensure(
            self.target_ring_size >= self.min_ring_size,
            "target ring size must cover minimum ring size",
        )?;
        ensure(
            self.target_entropy_score_bps >= self.min_entropy_score_bps,
            "target entropy score must cover minimum entropy score",
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
            "target anonymity set must cover privacy floor",
        )?;
        ensure(
            self.target_ring_entropy_bands >= self.min_ring_entropy_bands,
            "target ring entropy bands must cover minimum bands",
        )?;
        ensure(
            self.target_viewtag_scan_quality_bps >= self.min_viewtag_scan_quality_bps,
            "target viewtag scan quality must cover minimum scan quality",
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
            self.min_entropy_score_bps <= MAX_BPS
                && self.target_entropy_score_bps <= MAX_BPS
                && self.min_viewtag_scan_quality_bps <= MAX_BPS
                && self.target_viewtag_scan_quality_bps <= MAX_BPS
                && self.max_viewtag_false_drop_bps <= MAX_BPS
                && self.max_scan_skew_bps <= MAX_BPS
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
            "seraphis-jamtis-decoy-set-entropy-oracle-config",
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
    pub entropy_observations: u64,
    pub ring_decoy_entropy_bands: u64,
    pub viewtag_scan_quality_reports: u64,
    pub pq_migration_safety_scores: u64,
    pub low_fee_wallet_scan_batches: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "seraphis-jamtis-decoy-set-entropy-oracle-counters",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub entropy_observations_root: String,
    pub ring_decoy_entropy_bands_root: String,
    pub viewtag_scan_quality_reports_root: String,
    pub pq_migration_safety_scores_root: String,
    pub low_fee_wallet_scan_batches_root: String,
    pub deterministic_state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            entropy_observations_root: empty_root(ENTROPY_ORACLE_SCHEME),
            ring_decoy_entropy_bands_root: empty_root(RING_DECOY_ENTROPY_BAND_SCHEME),
            viewtag_scan_quality_reports_root: empty_root(VIEWTAG_SCAN_QUALITY_SCHEME),
            pq_migration_safety_scores_root: empty_root(PQ_MIGRATION_SAFETY_SCORE_SCHEME),
            low_fee_wallet_scan_batches_root: empty_root(LOW_FEE_WALLET_SCAN_BATCH_SCHEME),
            deterministic_state_root: empty_root("seraphis-jamtis-decoy-set-entropy-oracle-state"),
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
pub struct EntropyOracleObservation {
    pub observation_id: String,
    pub lane: EntropyOracleLane,
    pub epoch: u64,
    pub monero_height_bucket: u64,
    pub ring_size: u16,
    pub anonymity_set_outputs: u64,
    pub effective_decoys: u64,
    pub entropy_score_bps: u64,
    pub shannon_entropy_millibits: u64,
    pub min_entropy_millibits: u64,
    pub collision_risk_bps: u64,
    pub decoy_age_skew_bps: u64,
    pub redacted_sample_window_root: String,
    pub seraphis_membership_root: String,
    pub jamtis_viewtag_bucket_root: String,
    pub oracle_attestation_root: String,
    pub expires_at_monero_height: u64,
    pub status: EntropyOracleStatus,
}

impl EntropyOracleObservation {
    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "lane": self.lane.as_str(),
            "epoch": self.epoch,
            "monero_height_bucket": self.monero_height_bucket,
            "ring_size": self.ring_size,
            "anonymity_set_outputs": self.anonymity_set_outputs,
            "effective_decoys": self.effective_decoys,
            "entropy_score_bps": self.entropy_score_bps,
            "shannon_entropy_millibits": self.shannon_entropy_millibits,
            "min_entropy_millibits": self.min_entropy_millibits,
            "collision_risk_bps": self.collision_risk_bps,
            "decoy_age_skew_bps": self.decoy_age_skew_bps,
            "redacted_sample_window_root": self.redacted_sample_window_root,
            "seraphis_membership_root": self.seraphis_membership_root,
            "jamtis_viewtag_bucket_root": self.jamtis_viewtag_bucket_root,
            "oracle_attestation_root": self.oracle_attestation_root,
            "expires_at_monero_height": self.expires_at_monero_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(ENTROPY_ORACLE_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RingDecoyEntropyBand {
    pub band_id: String,
    pub observation_id: String,
    pub band_kind: RingEntropyBandKind,
    pub min_decoy_age_blocks: u64,
    pub max_decoy_age_blocks: u64,
    pub band_weight_bps: u64,
    pub entropy_contribution_bps: u64,
    pub sampled_outputs: u64,
    pub unique_output_buckets: u64,
    pub decoy_distribution_root: String,
    pub redacted_output_bucket_root: String,
    pub band_sampler_commitment_root: String,
    pub status: EntropyOracleStatus,
}

impl RingDecoyEntropyBand {
    pub fn public_record(&self) -> Value {
        json!({
            "band_id": self.band_id,
            "observation_id": self.observation_id,
            "band_kind": self.band_kind.as_str(),
            "min_decoy_age_blocks": self.min_decoy_age_blocks,
            "max_decoy_age_blocks": self.max_decoy_age_blocks,
            "band_weight_bps": self.band_weight_bps,
            "entropy_contribution_bps": self.entropy_contribution_bps,
            "sampled_outputs": self.sampled_outputs,
            "unique_output_buckets": self.unique_output_buckets,
            "decoy_distribution_root": self.decoy_distribution_root,
            "redacted_output_bucket_root": self.redacted_output_bucket_root,
            "band_sampler_commitment_root": self.band_sampler_commitment_root,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(RING_DECOY_ENTROPY_BAND_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewtagScanQualityReport {
    pub quality_id: String,
    pub observation_id: String,
    pub scan_window_blocks: u64,
    pub scanned_outputs: u64,
    pub retained_candidate_outputs: u64,
    pub viewtag_scan_quality_bps: u64,
    pub viewtag_false_drop_bps: u64,
    pub scan_skew_bps: u64,
    pub blinded_viewtag_index_root: String,
    pub scan_skip_proof_root: String,
    pub residual_privacy_root: String,
    pub status: EntropyOracleStatus,
}

impl ViewtagScanQualityReport {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(VIEWTAG_SCAN_QUALITY_SCHEME, &self.public_record())
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
    pub seraphis_to_jamtis_binding_root: String,
    pub decoy_entropy_guard_root: String,
    pub viewtag_scan_guard_root: String,
    pub attestation_root: String,
    pub status: EntropyOracleStatus,
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
pub struct LowFeeWalletScanBatch {
    pub batch_id: String,
    pub observation_id: String,
    pub quality_id: String,
    pub fee_asset_id: String,
    pub batch_outputs: u64,
    pub wallet_scan_count: u64,
    pub user_fee_bps: u64,
    pub rebate_bps: u64,
    pub batched_viewtag_scan_root: String,
    pub scan_sponsor_receipt_root: String,
    pub privacy_budget_root: String,
    pub status: EntropyOracleStatus,
}

impl LowFeeWalletScanBatch {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(LOW_FEE_WALLET_SCAN_BATCH_SCHEME, &self.public_record())
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
    pub entropy_observations: BTreeMap<String, EntropyOracleObservation>,
    pub ring_decoy_entropy_bands: BTreeMap<String, RingDecoyEntropyBand>,
    pub viewtag_scan_quality_reports: BTreeMap<String, ViewtagScanQualityReport>,
    pub pq_migration_safety_scores: BTreeMap<String, PqMigrationSafetyScore>,
    pub low_fee_wallet_scan_batches: BTreeMap<String, LowFeeWalletScanBatch>,
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
            entropy_observations: BTreeMap::new(),
            ring_decoy_entropy_bands: BTreeMap::new(),
            viewtag_scan_quality_reports: BTreeMap::new(),
            pq_migration_safety_scores: BTreeMap::new(),
            low_fee_wallet_scan_batches: BTreeMap::new(),
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
            "runtime": "monero_l2_pq_private_seraphis_jamtis_decoy_set_entropy_oracle_runtime",
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
            "public_record_scheme": PUBLIC_RECORD_SCHEME,
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.deterministic_state_root.clone()
    }

    pub fn insert_entropy_observation(
        &mut self,
        observation: EntropyOracleObservation,
    ) -> Result<()> {
        ensure(
            observation.ring_size >= self.config.min_ring_size,
            "entropy observation ring size is below minimum",
        )?;
        ensure(
            observation.anonymity_set_outputs >= self.config.min_anonymity_set_outputs,
            "entropy observation is below anonymity-set privacy floor",
        )?;
        ensure(
            observation.effective_decoys >= self.config.min_effective_decoys,
            "entropy observation has too few effective decoys",
        )?;
        ensure(
            observation.entropy_score_bps >= self.config.min_entropy_score_bps,
            "entropy observation score is below floor",
        )?;
        ensure(
            observation.shannon_entropy_millibits >= self.config.min_shannon_entropy_millibits,
            "Shannon entropy is below floor",
        )?;
        ensure(
            observation.min_entropy_millibits >= self.config.min_min_entropy_millibits,
            "min-entropy is below floor",
        )?;
        ensure(
            observation.collision_risk_bps <= MAX_BPS,
            "collision risk exceeds max bps",
        )?;
        ensure(
            observation.decoy_age_skew_bps <= self.config.max_scan_skew_bps,
            "decoy age skew exceeds cap",
        )?;
        ensure(
            observation.expires_at_monero_height > self.monero_height,
            "entropy observation must expire in the future",
        )?;
        self.entropy_observations
            .insert(observation.observation_id.clone(), observation);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_ring_decoy_entropy_band(&mut self, band: RingDecoyEntropyBand) -> Result<()> {
        ensure(
            self.entropy_observations.contains_key(&band.observation_id),
            "ring decoy entropy band references unknown observation",
        )?;
        ensure(
            band.max_decoy_age_blocks >= band.min_decoy_age_blocks,
            "max decoy age must cover min decoy age",
        )?;
        ensure(
            band.band_weight_bps <= MAX_BPS,
            "band weight exceeds max bps",
        )?;
        ensure(
            band.entropy_contribution_bps <= MAX_BPS,
            "band entropy contribution exceeds max bps",
        )?;
        ensure(
            band.sampled_outputs >= self.config.min_ring_size as u64,
            "band sampled outputs are below ring floor",
        )?;
        ensure(
            band.unique_output_buckets > 0 && band.unique_output_buckets <= band.sampled_outputs,
            "band unique output buckets must be within sampled outputs",
        )?;
        self.ring_decoy_entropy_bands
            .insert(band.band_id.clone(), band);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_viewtag_scan_quality_report(
        &mut self,
        quality: ViewtagScanQualityReport,
    ) -> Result<()> {
        ensure(
            self.entropy_observations
                .contains_key(&quality.observation_id),
            "viewtag scan quality report references unknown observation",
        )?;
        ensure(
            quality.scan_window_blocks <= self.config.scan_window_blocks,
            "viewtag scan quality report exceeds configured scan window",
        )?;
        ensure(
            quality.scanned_outputs >= self.config.min_anonymity_set_outputs,
            "viewtag scan quality scanned outputs are below privacy floor",
        )?;
        ensure(
            quality.retained_candidate_outputs >= self.config.min_low_fee_batch_outputs,
            "viewtag scan retained outputs are below batch floor",
        )?;
        ensure(
            quality.retained_candidate_outputs <= quality.scanned_outputs,
            "viewtag retained outputs exceed scanned outputs",
        )?;
        ensure(
            quality.viewtag_scan_quality_bps >= self.config.min_viewtag_scan_quality_bps,
            "viewtag scan quality is below floor",
        )?;
        ensure(
            quality.viewtag_false_drop_bps <= self.config.max_viewtag_false_drop_bps,
            "viewtag false-drop rate exceeds cap",
        )?;
        ensure(
            quality.scan_skew_bps <= self.config.max_scan_skew_bps,
            "viewtag scan skew exceeds cap",
        )?;
        self.viewtag_scan_quality_reports
            .insert(quality.quality_id.clone(), quality);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_pq_migration_safety_score(
        &mut self,
        safety: PqMigrationSafetyScore,
    ) -> Result<()> {
        ensure(
            self.entropy_observations
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

    pub fn insert_low_fee_wallet_scan_batch(&mut self, batch: LowFeeWalletScanBatch) -> Result<()> {
        ensure(
            self.entropy_observations
                .contains_key(&batch.observation_id),
            "low-fee wallet scan batch references unknown observation",
        )?;
        ensure(
            self.viewtag_scan_quality_reports
                .contains_key(&batch.quality_id),
            "low-fee wallet scan batch references unknown quality report",
        )?;
        ensure(
            batch.fee_asset_id == self.config.fee_asset_id,
            "low-fee wallet scan batch fee asset does not match config",
        )?;
        ensure(
            batch.batch_outputs >= self.config.min_low_fee_batch_outputs,
            "low-fee wallet scan batch is below minimum output count",
        )?;
        ensure(
            batch.wallet_scan_count > 0,
            "low-fee wallet scan batch must include at least one wallet scan",
        )?;
        ensure(
            batch.user_fee_bps <= self.config.max_batch_fee_bps,
            "low-fee wallet scan batch user fee exceeds cap",
        )?;
        ensure(
            batch.rebate_bps <= batch.user_fee_bps,
            "low-fee wallet scan batch rebate exceeds charged fee",
        )?;
        self.low_fee_wallet_scan_batches
            .insert(batch.batch_id.clone(), batch);
        self.refresh_roots();
        Ok(())
    }

    pub fn usable_entropy_observations(&self) -> Vec<&EntropyOracleObservation> {
        self.entropy_observations
            .values()
            .filter(|observation| observation.status.public_usable())
            .collect()
    }

    pub fn aggregate_entropy_score_bps(&self) -> u64 {
        weighted_average_bps(
            self.entropy_observations
                .values()
                .map(|observation| (observation.entropy_score_bps, observation.effective_decoys)),
        )
    }

    pub fn aggregate_viewtag_scan_quality_bps(&self) -> u64 {
        weighted_average_bps(self.viewtag_scan_quality_reports.values().map(|quality| {
            (
                quality.viewtag_scan_quality_bps,
                quality.retained_candidate_outputs,
            )
        }))
    }

    pub fn refresh_roots(&mut self) {
        self.counters.entropy_observations = self.entropy_observations.len() as u64;
        self.counters.ring_decoy_entropy_bands = self.ring_decoy_entropy_bands.len() as u64;
        self.counters.viewtag_scan_quality_reports = self.viewtag_scan_quality_reports.len() as u64;
        self.counters.pq_migration_safety_scores = self.pq_migration_safety_scores.len() as u64;
        self.counters.low_fee_wallet_scan_batches = self.low_fee_wallet_scan_batches.len() as u64;

        self.roots.entropy_observations_root = map_root(
            ENTROPY_ORACLE_SCHEME,
            self.entropy_observations
                .iter()
                .map(|(id, observation)| (id.as_str(), observation.state_root())),
        );
        self.roots.ring_decoy_entropy_bands_root = map_root(
            RING_DECOY_ENTROPY_BAND_SCHEME,
            self.ring_decoy_entropy_bands
                .iter()
                .map(|(id, band)| (id.as_str(), band.state_root())),
        );
        self.roots.viewtag_scan_quality_reports_root = map_root(
            VIEWTAG_SCAN_QUALITY_SCHEME,
            self.viewtag_scan_quality_reports
                .iter()
                .map(|(id, quality)| (id.as_str(), quality.state_root())),
        );
        self.roots.pq_migration_safety_scores_root = map_root(
            PQ_MIGRATION_SAFETY_SCORE_SCHEME,
            self.pq_migration_safety_scores
                .iter()
                .map(|(id, safety)| (id.as_str(), safety.state_root())),
        );
        self.roots.low_fee_wallet_scan_batches_root = map_root(
            LOW_FEE_WALLET_SCAN_BATCH_SCHEME,
            self.low_fee_wallet_scan_batches
                .iter()
                .map(|(id, batch)| (id.as_str(), batch.state_root())),
        );
        self.roots.deterministic_state_root = self.state_root_without_cached_roots();
    }

    fn state_root_without_cached_roots(&self) -> String {
        root_from_parts(
            "seraphis-jamtis-decoy-set-entropy-oracle-state",
            &[
                HashPart::Str(&self.protocol_version),
                HashPart::Str(&self.chain_id),
                HashPart::Str(&self.config.state_root()),
                HashPart::U64(self.l2_height),
                HashPart::U64(self.monero_height),
                HashPart::U64(self.epoch),
                HashPart::Str(&self.counters.state_root()),
                HashPart::Str(&self.roots.entropy_observations_root),
                HashPart::Str(&self.roots.ring_decoy_entropy_bands_root),
                HashPart::Str(&self.roots.viewtag_scan_quality_reports_root),
                HashPart::Str(&self.roots.pq_migration_safety_scores_root),
                HashPart::Str(&self.roots.low_fee_wallet_scan_batches_root),
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
        .expect("default Seraphis/Jamtis decoy set entropy oracle config is valid")
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let observation_id = "seraphis-jamtis-decoy-set-entropy-oracle-devnet-0".to_string();
    let quality_id = "seraphis-jamtis-viewtag-scan-quality-devnet-0".to_string();

    state
        .insert_entropy_observation(EntropyOracleObservation {
            observation_id: observation_id.clone(),
            lane: EntropyOracleLane::WalletReceiveScan,
            epoch: DEVNET_EPOCH,
            monero_height_bucket: bucket(DEVNET_MONERO_HEIGHT, DEFAULT_PUBLIC_BUCKET_SIZE),
            ring_size: DEFAULT_TARGET_RING_SIZE,
            anonymity_set_outputs: DEFAULT_TARGET_ANONYMITY_SET_OUTPUTS,
            effective_decoys: DEFAULT_TARGET_EFFECTIVE_DECOYS,
            entropy_score_bps: DEFAULT_TARGET_ENTROPY_SCORE_BPS,
            shannon_entropy_millibits: DEFAULT_TARGET_SHANNON_ENTROPY_MILLIBITS,
            min_entropy_millibits: DEFAULT_TARGET_MIN_ENTROPY_MILLIBITS,
            collision_risk_bps: 70,
            decoy_age_skew_bps: 240,
            redacted_sample_window_root: root_from_parts(
                "devnet-redacted-seraphis-jamtis-decoy-entropy-sample-window",
                &[HashPart::Str(&observation_id)],
            ),
            seraphis_membership_root: root_from_parts(
                "devnet-seraphis-output-membership",
                &[HashPart::Str(&observation_id)],
            ),
            jamtis_viewtag_bucket_root: root_from_parts(
                "devnet-jamtis-viewtag-bucket",
                &[HashPart::Str(&observation_id)],
            ),
            oracle_attestation_root: root_from_parts(
                "devnet-seraphis-jamtis-decoy-entropy-oracle-attestation",
                &[HashPart::Str(&observation_id)],
            ),
            expires_at_monero_height: DEVNET_MONERO_HEIGHT + DEFAULT_ORACLE_TTL_BLOCKS,
            status: EntropyOracleStatus::Observed,
        })
        .expect("devnet entropy observation inserts");

    for (index, band_kind, min_age, max_age, weight, contribution) in [
        (
            0_u64,
            RingEntropyBandKind::ColdHistorical,
            172_800_u64,
            1_036_800_u64,
            2_200_u64,
            2_180_u64,
        ),
        (
            1,
            RingEntropyBandKind::WarmRecent,
            7_200,
            172_800,
            3_800,
            3_720,
        ),
        (
            2,
            RingEntropyBandKind::HotMempoolAdjacent,
            0,
            7_200,
            1_400,
            1_320,
        ),
        (
            3,
            RingEntropyBandKind::ChangeLikeShielded,
            28_800,
            345_600,
            1_000,
            980,
        ),
        (
            4,
            RingEntropyBandKind::BridgeIngress,
            14_400,
            259_200,
            900,
            870,
        ),
        (
            5,
            RingEntropyBandKind::SwapSettlement,
            3_600,
            86_400,
            700,
            690,
        ),
    ] {
        let band_id = format!("seraphis-jamtis-ring-decoy-entropy-band-devnet-{index}");
        state
            .insert_ring_decoy_entropy_band(RingDecoyEntropyBand {
                band_id: band_id.clone(),
                observation_id: observation_id.clone(),
                band_kind,
                min_decoy_age_blocks: min_age,
                max_decoy_age_blocks: max_age,
                band_weight_bps: weight,
                entropy_contribution_bps: contribution,
                sampled_outputs: DEFAULT_TARGET_LOW_FEE_BATCH_OUTPUTS + (index * 512),
                unique_output_buckets: 512 + (index * 32),
                decoy_distribution_root: root_from_parts(
                    "devnet-seraphis-jamtis-decoy-band-distribution",
                    &[HashPart::Str(&band_id)],
                ),
                redacted_output_bucket_root: root_from_parts(
                    "devnet-redacted-seraphis-jamtis-output-bucket",
                    &[HashPart::Str(&band_id)],
                ),
                band_sampler_commitment_root: root_from_parts(
                    "devnet-seraphis-jamtis-band-sampler-commitment",
                    &[HashPart::Str(&band_id)],
                ),
                status: EntropyOracleStatus::Banded,
            })
            .expect("devnet ring decoy entropy band inserts");
    }

    state
        .insert_viewtag_scan_quality_report(ViewtagScanQualityReport {
            quality_id: quality_id.clone(),
            observation_id: observation_id.clone(),
            scan_window_blocks: DEFAULT_SCAN_WINDOW_BLOCKS,
            scanned_outputs: DEFAULT_TARGET_ANONYMITY_SET_OUTPUTS,
            retained_candidate_outputs: DEFAULT_TARGET_LOW_FEE_BATCH_OUTPUTS,
            viewtag_scan_quality_bps: DEFAULT_TARGET_VIEWTAG_SCAN_QUALITY_BPS,
            viewtag_false_drop_bps: 4,
            scan_skew_bps: 180,
            blinded_viewtag_index_root: root_from_parts(
                "devnet-blinded-seraphis-jamtis-viewtag-index",
                &[HashPart::Str(&quality_id)],
            ),
            scan_skip_proof_root: root_from_parts(
                "devnet-seraphis-jamtis-viewtag-scan-skip-proof",
                &[HashPart::Str(&quality_id)],
            ),
            residual_privacy_root: root_from_parts(
                "devnet-seraphis-jamtis-viewtag-scan-residual-privacy",
                &[HashPart::Str(&quality_id)],
            ),
            status: EntropyOracleStatus::ScanQualityAttested,
        })
        .expect("devnet viewtag scan quality inserts");

    state
        .insert_pq_migration_safety_score(PqMigrationSafetyScore {
            safety_id: "seraphis-jamtis-decoy-set-entropy-pq-safety-devnet-0".to_string(),
            observation_id: observation_id.clone(),
            pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            pq_safety_bps: DEFAULT_TARGET_PQ_SAFETY_BPS,
            classical_fallback_disabled: true,
            migration_epoch: DEVNET_EPOCH,
            seraphis_to_jamtis_binding_root: root_from_parts(
                "devnet-seraphis-to-jamtis-pq-binding",
                &[HashPart::Str(&observation_id)],
            ),
            decoy_entropy_guard_root: root_from_parts(
                "devnet-seraphis-jamtis-decoy-entropy-pq-guard",
                &[HashPart::Str(&observation_id)],
            ),
            viewtag_scan_guard_root: root_from_parts(
                "devnet-seraphis-jamtis-viewtag-scan-pq-guard",
                &[HashPart::Str(&observation_id)],
            ),
            attestation_root: root_from_parts(
                "devnet-seraphis-jamtis-decoy-set-entropy-pq-attestation",
                &[HashPart::Str(&observation_id)],
            ),
            status: EntropyOracleStatus::PqSafe,
        })
        .expect("devnet PQ migration safety inserts");

    state
        .insert_low_fee_wallet_scan_batch(LowFeeWalletScanBatch {
            batch_id: "seraphis-jamtis-low-fee-wallet-scan-batch-devnet-0".to_string(),
            observation_id,
            quality_id,
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            batch_outputs: DEFAULT_TARGET_LOW_FEE_BATCH_OUTPUTS,
            wallet_scan_count: 768,
            user_fee_bps: DEFAULT_MAX_BATCH_FEE_BPS,
            rebate_bps: DEFAULT_TARGET_BATCH_REBATE_BPS,
            batched_viewtag_scan_root: root_from_parts(
                "devnet-seraphis-jamtis-batched-viewtag-wallet-scan",
                &[HashPart::Str("0")],
            ),
            scan_sponsor_receipt_root: root_from_parts(
                "devnet-seraphis-jamtis-wallet-scan-sponsor-receipt",
                &[HashPart::Str("0")],
            ),
            privacy_budget_root: root_from_parts(
                "devnet-seraphis-jamtis-wallet-scan-privacy-budget",
                &[HashPart::Str("0")],
            ),
            status: EntropyOracleStatus::BatchEligible,
        })
        .expect("devnet low-fee wallet scan batch inserts");

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
        &format!("SERAPHIS-JAMTIS-DECOY-SET-ENTROPY-ORACLE-{domain}"),
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
        &format!("SERAPHIS-JAMTIS-DECOY-SET-ENTROPY-ORACLE-{domain}"),
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
