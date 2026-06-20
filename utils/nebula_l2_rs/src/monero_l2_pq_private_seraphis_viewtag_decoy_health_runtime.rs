use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = MoneroL2PqPrivateSeraphisViewtagDecoyHealthRuntimeResult<T>;
pub type MoneroL2PqPrivateSeraphisViewtagDecoyHealthRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_SERAPHIS_VIEWTAG_DECOY_HEALTH_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-seraphis-viewtag-decoy-health-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_SERAPHIS_VIEWTAG_DECOY_HEALTH_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const DECOY_HEALTH_SCORE_SCHEME: &str = "seraphis-viewtag-decoy-health-score-root-v1";
pub const RING_DECOY_FRESHNESS_SCHEME: &str = "seraphis-viewtag-ring-decoy-freshness-root-v1";
pub const SCAN_ACCELERATION_SCHEME: &str = "seraphis-viewtag-scan-acceleration-root-v1";
pub const PQ_MIGRATION_GUARDRAIL_SCHEME: &str =
    "ML-DSA-87+ML-KEM-1024+SLH-DSA-SHAKE-256f-seraphis-viewtag-decoy-health-guardrail-root-v1";
pub const LOW_FEE_VIEWTAG_BATCH_SCHEME: &str = "low-fee-private-seraphis-viewtag-batching-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "deterministic-public-seraphis-viewtag-decoy-health-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_addresses_view_keys_spend_keys_amounts_output_indices_viewtags_ring_members_or_scan_secrets";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_132_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_808_000;
pub const DEVNET_EPOCH: u64 = 17_160;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_RING_SIZE: u16 = 16;
pub const DEFAULT_TARGET_RING_SIZE: u16 = 128;
pub const DEFAULT_MIN_DECOY_HEALTH_BPS: u64 = 8_500;
pub const DEFAULT_TARGET_DECOY_HEALTH_BPS: u64 = 9_300;
pub const DEFAULT_MIN_FRESHNESS_BPS: u64 = 8_400;
pub const DEFAULT_TARGET_FRESHNESS_BPS: u64 = 9_250;
pub const DEFAULT_MIN_SCAN_ACCELERATION_BPS: u64 = 2_000;
pub const DEFAULT_TARGET_SCAN_ACCELERATION_BPS: u64 = 6_000;
pub const DEFAULT_MIN_ANONYMITY_SET_OUTPUTS: u64 = 131_072;
pub const DEFAULT_TARGET_ANONYMITY_SET_OUTPUTS: u64 = 524_288;
pub const DEFAULT_MIN_VIEWTAG_BATCH_OUTPUTS: u64 = 4_096;
pub const DEFAULT_TARGET_VIEWTAG_BATCH_OUTPUTS: u64 = 32_768;
pub const DEFAULT_MIN_DECOY_BUCKETS: u16 = 16;
pub const DEFAULT_TARGET_DECOY_BUCKETS: u16 = 64;
pub const DEFAULT_MAX_STALE_DECOY_BPS: u64 = 900;
pub const DEFAULT_MAX_VIEWTAG_FALSE_DROP_BPS: u64 = 15;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_HEALTH_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_SCAN_WINDOW_BLOCKS: u64 = 360;
pub const DEFAULT_MAX_BATCH_FEE_BPS: u64 = 5;
pub const DEFAULT_TARGET_BATCH_REBATE_BPS: u64 = 4;
pub const DEFAULT_PUBLIC_BUCKET_SIZE: u64 = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecoyHealthLane {
    WalletReceiveScan,
    WatchOnlyScan,
    BridgeDepositScan,
    SwapSettlementScan,
    MerchantReceiveScan,
    ReorgRescan,
}

impl DecoyHealthLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletReceiveScan => "wallet_receive_scan",
            Self::WatchOnlyScan => "watch_only_scan",
            Self::BridgeDepositScan => "bridge_deposit_scan",
            Self::SwapSettlementScan => "swap_settlement_scan",
            Self::MerchantReceiveScan => "merchant_receive_scan",
            Self::ReorgRescan => "reorg_rescan",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecoyHealthStatus {
    Draft,
    Scored,
    Fresh,
    Accelerated,
    Guarded,
    BatchEligible,
    Sealed,
    Expired,
    Quarantined,
}

impl DecoyHealthStatus {
    pub fn public_usable(self) -> bool {
        matches!(
            self,
            Self::Scored
                | Self::Fresh
                | Self::Accelerated
                | Self::Guarded
                | Self::BatchEligible
                | Self::Sealed
        )
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Config {
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub min_ring_size: u16,
    pub target_ring_size: u16,
    pub min_decoy_health_bps: u64,
    pub target_decoy_health_bps: u64,
    pub min_freshness_bps: u64,
    pub target_freshness_bps: u64,
    pub min_scan_acceleration_bps: u64,
    pub target_scan_acceleration_bps: u64,
    pub min_anonymity_set_outputs: u64,
    pub target_anonymity_set_outputs: u64,
    pub min_viewtag_batch_outputs: u64,
    pub target_viewtag_batch_outputs: u64,
    pub min_decoy_buckets: u16,
    pub target_decoy_buckets: u16,
    pub max_stale_decoy_bps: u64,
    pub max_viewtag_false_drop_bps: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub health_ttl_blocks: u64,
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
            min_decoy_health_bps: DEFAULT_MIN_DECOY_HEALTH_BPS,
            target_decoy_health_bps: DEFAULT_TARGET_DECOY_HEALTH_BPS,
            min_freshness_bps: DEFAULT_MIN_FRESHNESS_BPS,
            target_freshness_bps: DEFAULT_TARGET_FRESHNESS_BPS,
            min_scan_acceleration_bps: DEFAULT_MIN_SCAN_ACCELERATION_BPS,
            target_scan_acceleration_bps: DEFAULT_TARGET_SCAN_ACCELERATION_BPS,
            min_anonymity_set_outputs: DEFAULT_MIN_ANONYMITY_SET_OUTPUTS,
            target_anonymity_set_outputs: DEFAULT_TARGET_ANONYMITY_SET_OUTPUTS,
            min_viewtag_batch_outputs: DEFAULT_MIN_VIEWTAG_BATCH_OUTPUTS,
            target_viewtag_batch_outputs: DEFAULT_TARGET_VIEWTAG_BATCH_OUTPUTS,
            min_decoy_buckets: DEFAULT_MIN_DECOY_BUCKETS,
            target_decoy_buckets: DEFAULT_TARGET_DECOY_BUCKETS,
            max_stale_decoy_bps: DEFAULT_MAX_STALE_DECOY_BPS,
            max_viewtag_false_drop_bps: DEFAULT_MAX_VIEWTAG_FALSE_DROP_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            health_ttl_blocks: DEFAULT_HEALTH_TTL_BLOCKS,
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
            self.target_decoy_health_bps >= self.min_decoy_health_bps,
            "target decoy health must cover minimum health",
        )?;
        ensure(
            self.target_freshness_bps >= self.min_freshness_bps,
            "target freshness must cover minimum freshness",
        )?;
        ensure(
            self.target_scan_acceleration_bps >= self.min_scan_acceleration_bps,
            "target scan acceleration must cover minimum acceleration",
        )?;
        ensure(
            self.target_anonymity_set_outputs >= self.min_anonymity_set_outputs,
            "target anonymity set must cover privacy floor",
        )?;
        ensure(
            self.target_viewtag_batch_outputs >= self.min_viewtag_batch_outputs,
            "target viewtag batch outputs must cover minimum batch",
        )?;
        ensure(
            self.target_decoy_buckets >= self.min_decoy_buckets,
            "target decoy buckets must cover minimum buckets",
        )?;
        ensure(
            self.min_decoy_health_bps <= MAX_BPS
                && self.target_decoy_health_bps <= MAX_BPS
                && self.min_freshness_bps <= MAX_BPS
                && self.target_freshness_bps <= MAX_BPS
                && self.min_scan_acceleration_bps <= MAX_BPS
                && self.target_scan_acceleration_bps <= MAX_BPS
                && self.max_stale_decoy_bps <= MAX_BPS
                && self.max_viewtag_false_drop_bps <= MAX_BPS,
            "basis-point threshold exceeds max bps",
        )?;
        ensure(
            self.target_pq_security_bits >= self.min_pq_security_bits,
            "target PQ security must cover minimum PQ security",
        )?;
        ensure(self.health_ttl_blocks > 0, "health ttl must be non-zero")?;
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
            "seraphis-viewtag-decoy-health-config",
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
    pub decoy_health_scores: u64,
    pub ring_decoy_freshness_reports: u64,
    pub scan_acceleration_windows: u64,
    pub pq_migration_guardrails: u64,
    pub low_fee_viewtag_batches: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "seraphis-viewtag-decoy-health-counters",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub decoy_health_scores_root: String,
    pub ring_decoy_freshness_reports_root: String,
    pub scan_acceleration_windows_root: String,
    pub pq_migration_guardrails_root: String,
    pub low_fee_viewtag_batches_root: String,
    pub deterministic_state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            decoy_health_scores_root: empty_root(DECOY_HEALTH_SCORE_SCHEME),
            ring_decoy_freshness_reports_root: empty_root(RING_DECOY_FRESHNESS_SCHEME),
            scan_acceleration_windows_root: empty_root(SCAN_ACCELERATION_SCHEME),
            pq_migration_guardrails_root: empty_root(PQ_MIGRATION_GUARDRAIL_SCHEME),
            low_fee_viewtag_batches_root: empty_root(LOW_FEE_VIEWTAG_BATCH_SCHEME),
            deterministic_state_root: empty_root("seraphis-viewtag-decoy-health-state"),
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
pub struct DecoyHealthScore {
    pub score_id: String,
    pub lane: DecoyHealthLane,
    pub epoch: u64,
    pub monero_height_bucket: u64,
    pub ring_size: u16,
    pub anonymity_set_outputs: u64,
    pub decoy_buckets: u16,
    pub decoy_health_bps: u64,
    pub stale_decoy_bps: u64,
    pub viewtag_false_drop_bps: u64,
    pub redacted_viewtag_distribution_root: String,
    pub redacted_decoy_sample_root: String,
    pub seraphis_membership_root: String,
    pub expires_at_monero_height: u64,
    pub status: DecoyHealthStatus,
}

impl DecoyHealthScore {
    pub fn public_record(&self) -> Value {
        json!({
            "score_id": self.score_id,
            "lane": self.lane.as_str(),
            "epoch": self.epoch,
            "monero_height_bucket": self.monero_height_bucket,
            "ring_size": self.ring_size,
            "anonymity_set_outputs": self.anonymity_set_outputs,
            "decoy_buckets": self.decoy_buckets,
            "decoy_health_bps": self.decoy_health_bps,
            "stale_decoy_bps": self.stale_decoy_bps,
            "viewtag_false_drop_bps": self.viewtag_false_drop_bps,
            "redacted_viewtag_distribution_root": self.redacted_viewtag_distribution_root,
            "redacted_decoy_sample_root": self.redacted_decoy_sample_root,
            "seraphis_membership_root": self.seraphis_membership_root,
            "expires_at_monero_height": self.expires_at_monero_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(DECOY_HEALTH_SCORE_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RingDecoyFreshnessReport {
    pub freshness_id: String,
    pub score_id: String,
    pub ring_size: u16,
    pub freshness_bps: u64,
    pub median_decoy_age_blocks: u64,
    pub max_decoy_age_blocks: u64,
    pub output_age_distribution_root: String,
    pub replacement_decoy_commitment_root: String,
    pub expires_at_monero_height: u64,
    pub status: DecoyHealthStatus,
}

impl RingDecoyFreshnessReport {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(RING_DECOY_FRESHNESS_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanAccelerationWindow {
    pub acceleration_id: String,
    pub score_id: String,
    pub scan_window_blocks: u64,
    pub acceleration_bps: u64,
    pub candidate_outputs: u64,
    pub retained_outputs: u64,
    pub blinded_viewtag_index_root: String,
    pub scan_skip_proof_root: String,
    pub residual_privacy_root: String,
    pub status: DecoyHealthStatus,
}

impl ScanAccelerationWindow {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(SCAN_ACCELERATION_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqMigrationGuardrail {
    pub guardrail_id: String,
    pub score_id: String,
    pub pq_security_bits: u16,
    pub classical_fallback_disabled: bool,
    pub migration_epoch: u64,
    pub viewtag_guard_commitment_root: String,
    pub decoy_sampler_guard_root: String,
    pub attestation_root: String,
    pub status: DecoyHealthStatus,
}

impl PqMigrationGuardrail {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(PQ_MIGRATION_GUARDRAIL_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeViewtagBatch {
    pub batch_id: String,
    pub score_id: String,
    pub fee_asset_id: String,
    pub batch_outputs: u64,
    pub user_fee_bps: u64,
    pub rebate_bps: u64,
    pub batched_viewtag_root: String,
    pub sponsor_receipt_root: String,
    pub privacy_budget_root: String,
}

impl LowFeeViewtagBatch {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(LOW_FEE_VIEWTAG_BATCH_SCHEME, &self.public_record())
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
    pub decoy_health_scores: BTreeMap<String, DecoyHealthScore>,
    pub ring_decoy_freshness_reports: BTreeMap<String, RingDecoyFreshnessReport>,
    pub scan_acceleration_windows: BTreeMap<String, ScanAccelerationWindow>,
    pub pq_migration_guardrails: BTreeMap<String, PqMigrationGuardrail>,
    pub low_fee_viewtag_batches: BTreeMap<String, LowFeeViewtagBatch>,
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
            decoy_health_scores: BTreeMap::new(),
            ring_decoy_freshness_reports: BTreeMap::new(),
            scan_acceleration_windows: BTreeMap::new(),
            pq_migration_guardrails: BTreeMap::new(),
            low_fee_viewtag_batches: BTreeMap::new(),
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
            "runtime": "monero_l2_pq_private_seraphis_viewtag_decoy_health_runtime",
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

    pub fn insert_decoy_health_score(&mut self, score: DecoyHealthScore) -> Result<()> {
        ensure(
            score.ring_size >= self.config.min_ring_size,
            "decoy health score ring size is below minimum",
        )?;
        ensure(
            score.anonymity_set_outputs >= self.config.min_anonymity_set_outputs,
            "decoy health score is below anonymity-set privacy floor",
        )?;
        ensure(
            score.decoy_buckets >= self.config.min_decoy_buckets,
            "decoy health score has too few decoy age buckets",
        )?;
        ensure(
            score.decoy_health_bps >= self.config.min_decoy_health_bps,
            "decoy health score is below floor",
        )?;
        ensure(
            score.stale_decoy_bps <= self.config.max_stale_decoy_bps,
            "stale decoy share exceeds cap",
        )?;
        ensure(
            score.viewtag_false_drop_bps <= self.config.max_viewtag_false_drop_bps,
            "viewtag false-drop rate exceeds cap",
        )?;
        ensure(
            score.expires_at_monero_height > self.monero_height,
            "decoy health score must expire in the future",
        )?;
        self.decoy_health_scores
            .insert(score.score_id.clone(), score);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_ring_decoy_freshness_report(
        &mut self,
        freshness: RingDecoyFreshnessReport,
    ) -> Result<()> {
        ensure(
            self.decoy_health_scores.contains_key(&freshness.score_id),
            "ring decoy freshness report references unknown decoy health score",
        )?;
        ensure(
            freshness.ring_size >= self.config.min_ring_size,
            "ring decoy freshness ring size is below minimum",
        )?;
        ensure(
            freshness.freshness_bps >= self.config.min_freshness_bps,
            "ring decoy freshness is below floor",
        )?;
        ensure(
            freshness.max_decoy_age_blocks >= freshness.median_decoy_age_blocks,
            "max decoy age must cover median decoy age",
        )?;
        ensure(
            freshness.expires_at_monero_height > self.monero_height,
            "ring decoy freshness report must expire in the future",
        )?;
        self.ring_decoy_freshness_reports
            .insert(freshness.freshness_id.clone(), freshness);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_scan_acceleration_window(
        &mut self,
        acceleration: ScanAccelerationWindow,
    ) -> Result<()> {
        ensure(
            self.decoy_health_scores
                .contains_key(&acceleration.score_id),
            "scan acceleration window references unknown decoy health score",
        )?;
        ensure(
            acceleration.scan_window_blocks <= self.config.scan_window_blocks,
            "scan acceleration window exceeds configured window",
        )?;
        ensure(
            acceleration.acceleration_bps >= self.config.min_scan_acceleration_bps,
            "scan acceleration is below floor",
        )?;
        ensure(
            acceleration.candidate_outputs >= self.config.min_anonymity_set_outputs,
            "scan acceleration candidate set is below privacy floor",
        )?;
        ensure(
            acceleration.retained_outputs >= self.config.min_viewtag_batch_outputs,
            "scan acceleration retained set is below batch floor",
        )?;
        ensure(
            acceleration.retained_outputs <= acceleration.candidate_outputs,
            "scan acceleration retained outputs exceed candidate outputs",
        )?;
        self.scan_acceleration_windows
            .insert(acceleration.acceleration_id.clone(), acceleration);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_pq_migration_guardrail(&mut self, guardrail: PqMigrationGuardrail) -> Result<()> {
        ensure(
            self.decoy_health_scores.contains_key(&guardrail.score_id),
            "PQ migration guardrail references unknown decoy health score",
        )?;
        ensure(
            guardrail.pq_security_bits >= self.config.min_pq_security_bits,
            "PQ migration guardrail is below minimum security",
        )?;
        ensure(
            guardrail.classical_fallback_disabled,
            "PQ migration guardrail must disable classical fallback",
        )?;
        self.pq_migration_guardrails
            .insert(guardrail.guardrail_id.clone(), guardrail);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_low_fee_viewtag_batch(&mut self, batch: LowFeeViewtagBatch) -> Result<()> {
        ensure(
            self.decoy_health_scores.contains_key(&batch.score_id),
            "low-fee viewtag batch references unknown decoy health score",
        )?;
        ensure(
            batch.fee_asset_id == self.config.fee_asset_id,
            "low-fee viewtag batch fee asset does not match config",
        )?;
        ensure(
            batch.batch_outputs >= self.config.min_viewtag_batch_outputs,
            "low-fee viewtag batch is below minimum output count",
        )?;
        ensure(
            batch.user_fee_bps <= self.config.max_batch_fee_bps,
            "low-fee viewtag batch user fee exceeds cap",
        )?;
        ensure(
            batch.rebate_bps <= batch.user_fee_bps,
            "low-fee viewtag batch rebate exceeds charged fee",
        )?;
        self.low_fee_viewtag_batches
            .insert(batch.batch_id.clone(), batch);
        self.refresh_roots();
        Ok(())
    }

    pub fn refresh_roots(&mut self) {
        self.counters.decoy_health_scores = self.decoy_health_scores.len() as u64;
        self.counters.ring_decoy_freshness_reports = self.ring_decoy_freshness_reports.len() as u64;
        self.counters.scan_acceleration_windows = self.scan_acceleration_windows.len() as u64;
        self.counters.pq_migration_guardrails = self.pq_migration_guardrails.len() as u64;
        self.counters.low_fee_viewtag_batches = self.low_fee_viewtag_batches.len() as u64;

        self.roots.decoy_health_scores_root = map_root(
            DECOY_HEALTH_SCORE_SCHEME,
            self.decoy_health_scores
                .iter()
                .map(|(id, score)| (id.as_str(), score.state_root())),
        );
        self.roots.ring_decoy_freshness_reports_root = map_root(
            RING_DECOY_FRESHNESS_SCHEME,
            self.ring_decoy_freshness_reports
                .iter()
                .map(|(id, freshness)| (id.as_str(), freshness.state_root())),
        );
        self.roots.scan_acceleration_windows_root = map_root(
            SCAN_ACCELERATION_SCHEME,
            self.scan_acceleration_windows
                .iter()
                .map(|(id, acceleration)| (id.as_str(), acceleration.state_root())),
        );
        self.roots.pq_migration_guardrails_root = map_root(
            PQ_MIGRATION_GUARDRAIL_SCHEME,
            self.pq_migration_guardrails
                .iter()
                .map(|(id, guardrail)| (id.as_str(), guardrail.state_root())),
        );
        self.roots.low_fee_viewtag_batches_root = map_root(
            LOW_FEE_VIEWTAG_BATCH_SCHEME,
            self.low_fee_viewtag_batches
                .iter()
                .map(|(id, batch)| (id.as_str(), batch.state_root())),
        );
        self.roots.deterministic_state_root = self.state_root_without_cached_roots();
    }

    fn state_root_without_cached_roots(&self) -> String {
        root_from_parts(
            "seraphis-viewtag-decoy-health-state",
            &[
                HashPart::Str(&self.protocol_version),
                HashPart::Str(&self.chain_id),
                HashPart::Str(&self.config.state_root()),
                HashPart::U64(self.l2_height),
                HashPart::U64(self.monero_height),
                HashPart::U64(self.epoch),
                HashPart::Str(&self.counters.state_root()),
                HashPart::Str(&self.roots.decoy_health_scores_root),
                HashPart::Str(&self.roots.ring_decoy_freshness_reports_root),
                HashPart::Str(&self.roots.scan_acceleration_windows_root),
                HashPart::Str(&self.roots.pq_migration_guardrails_root),
                HashPart::Str(&self.roots.low_fee_viewtag_batches_root),
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
        .expect("default Seraphis viewtag decoy health config is valid")
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let score_id = "seraphis-viewtag-decoy-health-devnet-0".to_string();

    state
        .insert_decoy_health_score(DecoyHealthScore {
            score_id: score_id.clone(),
            lane: DecoyHealthLane::WalletReceiveScan,
            epoch: DEVNET_EPOCH,
            monero_height_bucket: bucket(DEVNET_MONERO_HEIGHT, DEFAULT_PUBLIC_BUCKET_SIZE),
            ring_size: DEFAULT_TARGET_RING_SIZE,
            anonymity_set_outputs: DEFAULT_TARGET_ANONYMITY_SET_OUTPUTS,
            decoy_buckets: DEFAULT_TARGET_DECOY_BUCKETS,
            decoy_health_bps: DEFAULT_TARGET_DECOY_HEALTH_BPS,
            stale_decoy_bps: 420,
            viewtag_false_drop_bps: 6,
            redacted_viewtag_distribution_root: root_from_parts(
                "devnet-redacted-seraphis-viewtag-decoy-distribution",
                &[HashPart::Str(&score_id)],
            ),
            redacted_decoy_sample_root: root_from_parts(
                "devnet-redacted-seraphis-viewtag-decoy-sample",
                &[HashPart::Str(&score_id)],
            ),
            seraphis_membership_root: root_from_parts(
                "devnet-seraphis-viewtag-output-membership",
                &[HashPart::Str(&score_id)],
            ),
            expires_at_monero_height: DEVNET_MONERO_HEIGHT + DEFAULT_HEALTH_TTL_BLOCKS,
            status: DecoyHealthStatus::Scored,
        })
        .expect("devnet decoy health score inserts");
    state
        .insert_ring_decoy_freshness_report(RingDecoyFreshnessReport {
            freshness_id: "seraphis-viewtag-ring-decoy-freshness-devnet-0".to_string(),
            score_id: score_id.clone(),
            ring_size: DEFAULT_TARGET_RING_SIZE,
            freshness_bps: DEFAULT_TARGET_FRESHNESS_BPS,
            median_decoy_age_blocks: 28_800,
            max_decoy_age_blocks: 172_800,
            output_age_distribution_root: root_from_parts(
                "devnet-seraphis-viewtag-output-age-distribution",
                &[HashPart::Str(&score_id)],
            ),
            replacement_decoy_commitment_root: root_from_parts(
                "devnet-seraphis-viewtag-replacement-decoy-commitment",
                &[HashPart::Str(&score_id)],
            ),
            expires_at_monero_height: DEVNET_MONERO_HEIGHT + DEFAULT_HEALTH_TTL_BLOCKS,
            status: DecoyHealthStatus::Fresh,
        })
        .expect("devnet ring decoy freshness inserts");
    state
        .insert_scan_acceleration_window(ScanAccelerationWindow {
            acceleration_id: "seraphis-viewtag-scan-acceleration-devnet-0".to_string(),
            score_id: score_id.clone(),
            scan_window_blocks: DEFAULT_SCAN_WINDOW_BLOCKS,
            acceleration_bps: DEFAULT_TARGET_SCAN_ACCELERATION_BPS,
            candidate_outputs: DEFAULT_TARGET_ANONYMITY_SET_OUTPUTS,
            retained_outputs: DEFAULT_TARGET_VIEWTAG_BATCH_OUTPUTS,
            blinded_viewtag_index_root: root_from_parts(
                "devnet-blinded-seraphis-viewtag-index",
                &[HashPart::Str(&score_id)],
            ),
            scan_skip_proof_root: root_from_parts(
                "devnet-seraphis-viewtag-scan-skip-proof",
                &[HashPart::Str(&score_id)],
            ),
            residual_privacy_root: root_from_parts(
                "devnet-seraphis-viewtag-residual-scan-privacy",
                &[HashPart::Str(&score_id)],
            ),
            status: DecoyHealthStatus::Accelerated,
        })
        .expect("devnet scan acceleration inserts");
    state
        .insert_pq_migration_guardrail(PqMigrationGuardrail {
            guardrail_id: "seraphis-viewtag-decoy-health-pq-guardrail-devnet-0".to_string(),
            score_id: score_id.clone(),
            pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            classical_fallback_disabled: true,
            migration_epoch: DEVNET_EPOCH,
            viewtag_guard_commitment_root: root_from_parts(
                "devnet-seraphis-viewtag-pq-guard-commitment",
                &[HashPart::Str(&score_id)],
            ),
            decoy_sampler_guard_root: root_from_parts(
                "devnet-seraphis-decoy-sampler-pq-guard",
                &[HashPart::Str(&score_id)],
            ),
            attestation_root: root_from_parts(
                "devnet-seraphis-viewtag-decoy-health-pq-attestation",
                &[HashPart::Str(&score_id)],
            ),
            status: DecoyHealthStatus::Guarded,
        })
        .expect("devnet PQ migration guardrail inserts");
    state
        .insert_low_fee_viewtag_batch(LowFeeViewtagBatch {
            batch_id: "seraphis-viewtag-low-fee-batch-devnet-0".to_string(),
            score_id,
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            batch_outputs: DEFAULT_TARGET_VIEWTAG_BATCH_OUTPUTS,
            user_fee_bps: DEFAULT_MAX_BATCH_FEE_BPS,
            rebate_bps: DEFAULT_TARGET_BATCH_REBATE_BPS,
            batched_viewtag_root: root_from_parts(
                "devnet-seraphis-batched-viewtag-root",
                &[HashPart::Str("0")],
            ),
            sponsor_receipt_root: root_from_parts(
                "devnet-seraphis-viewtag-batch-sponsor-receipt",
                &[HashPart::Str("0")],
            ),
            privacy_budget_root: root_from_parts(
                "devnet-seraphis-viewtag-batch-privacy-budget",
                &[HashPart::Str("0")],
            ),
        })
        .expect("devnet low-fee viewtag batch inserts");

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
        &format!("SERAPHIS-VIEWTAG-DECOY-HEALTH-{domain}"),
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
    merkle_root(&format!("SERAPHIS-VIEWTAG-DECOY-HEALTH-{domain}"), &leaves)
}
