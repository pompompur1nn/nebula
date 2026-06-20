use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = MoneroL2PqPrivateJamtisViewtagDecoyRotationHealthRuntimeResult<T>;
pub type MoneroL2PqPrivateJamtisViewtagDecoyRotationHealthRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_JAMTIS_VIEWTAG_DECOY_ROTATION_HEALTH_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-jamtis-viewtag-decoy-rotation-health-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_JAMTIS_VIEWTAG_DECOY_ROTATION_HEALTH_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ROTATION_HEALTH_SCHEME: &str = "jamtis-viewtag-decoy-rotation-health-root-v1";
pub const SUBADDRESS_SCAN_BALANCE_SCHEME: &str =
    "jamtis-viewtag-subaddress-scan-load-balance-root-v1";
pub const RING_DECOY_FRESHNESS_SCHEME: &str =
    "jamtis-viewtag-rotation-ring-decoy-freshness-root-v1";
pub const PQ_MIGRATION_SAFETY_SCHEME: &str =
    "ML-DSA-87+ML-KEM-1024+SLH-DSA-SHAKE-256f-jamtis-viewtag-decoy-rotation-safety-root-v1";
pub const LOW_FEE_SCAN_BATCH_SCHEME: &str =
    "low-fee-private-jamtis-viewtag-wallet-scan-batch-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "deterministic-public-jamtis-viewtag-decoy-rotation-health-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_addresses_view_keys_spend_keys_amounts_output_indices_viewtags_ring_members_subaddress_indices_or_scan_secrets";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_136_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_812_000;
pub const DEVNET_EPOCH: u64 = 17_280;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_RING_SIZE: u16 = 16;
pub const DEFAULT_TARGET_RING_SIZE: u16 = 128;
pub const DEFAULT_MIN_ROTATION_HEALTH_BPS: u64 = 8_700;
pub const DEFAULT_TARGET_ROTATION_HEALTH_BPS: u64 = 9_450;
pub const DEFAULT_MIN_FRESHNESS_BPS: u64 = 8_600;
pub const DEFAULT_TARGET_FRESHNESS_BPS: u64 = 9_350;
pub const DEFAULT_MIN_LOAD_BALANCE_BPS: u64 = 8_800;
pub const DEFAULT_TARGET_LOAD_BALANCE_BPS: u64 = 9_550;
pub const DEFAULT_MIN_ROTATION_BUCKETS: u16 = 24;
pub const DEFAULT_TARGET_ROTATION_BUCKETS: u16 = 96;
pub const DEFAULT_MIN_ANONYMITY_SET_OUTPUTS: u64 = 131_072;
pub const DEFAULT_TARGET_ANONYMITY_SET_OUTPUTS: u64 = 524_288;
pub const DEFAULT_MIN_SUBADDRESS_SCAN_BATCH_OUTPUTS: u64 = 4_096;
pub const DEFAULT_TARGET_SUBADDRESS_SCAN_BATCH_OUTPUTS: u64 = 32_768;
pub const DEFAULT_MAX_STALE_DECOY_BPS: u64 = 800;
pub const DEFAULT_MAX_ROTATION_REUSE_BPS: u64 = 250;
pub const DEFAULT_MAX_VIEWTAG_FALSE_DROP_BPS: u64 = 12;
pub const DEFAULT_MAX_LOAD_SKEW_BPS: u64 = 650;
pub const DEFAULT_MIN_PQ_SAFETY_BPS: u64 = 9_000;
pub const DEFAULT_TARGET_PQ_SAFETY_BPS: u64 = 9_700;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_ROTATION_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_SCAN_WINDOW_BLOCKS: u64 = 360;
pub const DEFAULT_MAX_BATCH_FEE_BPS: u64 = 5;
pub const DEFAULT_TARGET_BATCH_REBATE_BPS: u64 = 4;
pub const DEFAULT_PUBLIC_BUCKET_SIZE: u64 = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationLane {
    WalletReceiveScan,
    WatchOnlyScan,
    BridgeDepositScan,
    SwapSettlementScan,
    MerchantReceiveScan,
    SubaddressFanoutRescan,
    ReorgRotationRepair,
}

impl RotationLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletReceiveScan => "wallet_receive_scan",
            Self::WatchOnlyScan => "watch_only_scan",
            Self::BridgeDepositScan => "bridge_deposit_scan",
            Self::SwapSettlementScan => "swap_settlement_scan",
            Self::MerchantReceiveScan => "merchant_receive_scan",
            Self::SubaddressFanoutRescan => "subaddress_fanout_rescan",
            Self::ReorgRotationRepair => "reorg_rotation_repair",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationStatus {
    Draft,
    Rotated,
    LoadBalanced,
    Fresh,
    PqSafe,
    BatchEligible,
    Sealed,
    Expired,
    Quarantined,
}

impl RotationStatus {
    pub fn public_usable(self) -> bool {
        matches!(
            self,
            Self::Rotated
                | Self::LoadBalanced
                | Self::Fresh
                | Self::PqSafe
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
    pub min_rotation_health_bps: u64,
    pub target_rotation_health_bps: u64,
    pub min_freshness_bps: u64,
    pub target_freshness_bps: u64,
    pub min_load_balance_bps: u64,
    pub target_load_balance_bps: u64,
    pub min_rotation_buckets: u16,
    pub target_rotation_buckets: u16,
    pub min_anonymity_set_outputs: u64,
    pub target_anonymity_set_outputs: u64,
    pub min_subaddress_scan_batch_outputs: u64,
    pub target_subaddress_scan_batch_outputs: u64,
    pub max_stale_decoy_bps: u64,
    pub max_rotation_reuse_bps: u64,
    pub max_viewtag_false_drop_bps: u64,
    pub max_load_skew_bps: u64,
    pub min_pq_safety_bps: u64,
    pub target_pq_safety_bps: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub rotation_ttl_blocks: u64,
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
            min_rotation_health_bps: DEFAULT_MIN_ROTATION_HEALTH_BPS,
            target_rotation_health_bps: DEFAULT_TARGET_ROTATION_HEALTH_BPS,
            min_freshness_bps: DEFAULT_MIN_FRESHNESS_BPS,
            target_freshness_bps: DEFAULT_TARGET_FRESHNESS_BPS,
            min_load_balance_bps: DEFAULT_MIN_LOAD_BALANCE_BPS,
            target_load_balance_bps: DEFAULT_TARGET_LOAD_BALANCE_BPS,
            min_rotation_buckets: DEFAULT_MIN_ROTATION_BUCKETS,
            target_rotation_buckets: DEFAULT_TARGET_ROTATION_BUCKETS,
            min_anonymity_set_outputs: DEFAULT_MIN_ANONYMITY_SET_OUTPUTS,
            target_anonymity_set_outputs: DEFAULT_TARGET_ANONYMITY_SET_OUTPUTS,
            min_subaddress_scan_batch_outputs: DEFAULT_MIN_SUBADDRESS_SCAN_BATCH_OUTPUTS,
            target_subaddress_scan_batch_outputs: DEFAULT_TARGET_SUBADDRESS_SCAN_BATCH_OUTPUTS,
            max_stale_decoy_bps: DEFAULT_MAX_STALE_DECOY_BPS,
            max_rotation_reuse_bps: DEFAULT_MAX_ROTATION_REUSE_BPS,
            max_viewtag_false_drop_bps: DEFAULT_MAX_VIEWTAG_FALSE_DROP_BPS,
            max_load_skew_bps: DEFAULT_MAX_LOAD_SKEW_BPS,
            min_pq_safety_bps: DEFAULT_MIN_PQ_SAFETY_BPS,
            target_pq_safety_bps: DEFAULT_TARGET_PQ_SAFETY_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            rotation_ttl_blocks: DEFAULT_ROTATION_TTL_BLOCKS,
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
            self.target_rotation_health_bps >= self.min_rotation_health_bps,
            "target rotation health must cover minimum rotation health",
        )?;
        ensure(
            self.target_freshness_bps >= self.min_freshness_bps,
            "target freshness must cover minimum freshness",
        )?;
        ensure(
            self.target_load_balance_bps >= self.min_load_balance_bps,
            "target load balance must cover minimum load balance",
        )?;
        ensure(
            self.target_rotation_buckets >= self.min_rotation_buckets,
            "target rotation buckets must cover minimum buckets",
        )?;
        ensure(
            self.target_anonymity_set_outputs >= self.min_anonymity_set_outputs,
            "target anonymity set must cover privacy floor",
        )?;
        ensure(
            self.target_subaddress_scan_batch_outputs >= self.min_subaddress_scan_batch_outputs,
            "target scan batch outputs must cover minimum batch",
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
            self.min_rotation_health_bps <= MAX_BPS
                && self.target_rotation_health_bps <= MAX_BPS
                && self.min_freshness_bps <= MAX_BPS
                && self.target_freshness_bps <= MAX_BPS
                && self.min_load_balance_bps <= MAX_BPS
                && self.target_load_balance_bps <= MAX_BPS
                && self.max_stale_decoy_bps <= MAX_BPS
                && self.max_rotation_reuse_bps <= MAX_BPS
                && self.max_viewtag_false_drop_bps <= MAX_BPS
                && self.max_load_skew_bps <= MAX_BPS
                && self.min_pq_safety_bps <= MAX_BPS
                && self.target_pq_safety_bps <= MAX_BPS,
            "basis-point threshold exceeds max bps",
        )?;
        ensure(
            self.rotation_ttl_blocks > 0,
            "rotation ttl must be non-zero",
        )?;
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
            "jamtis-viewtag-decoy-rotation-health-config",
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
    pub rotation_health_entries: u64,
    pub subaddress_scan_load_balances: u64,
    pub ring_decoy_freshness_entries: u64,
    pub pq_migration_safety_scores: u64,
    pub low_fee_wallet_scan_batches: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "jamtis-viewtag-decoy-rotation-health-counters",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub rotation_health_entries_root: String,
    pub subaddress_scan_load_balances_root: String,
    pub ring_decoy_freshness_entries_root: String,
    pub pq_migration_safety_scores_root: String,
    pub low_fee_wallet_scan_batches_root: String,
    pub deterministic_state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            rotation_health_entries_root: empty_root(ROTATION_HEALTH_SCHEME),
            subaddress_scan_load_balances_root: empty_root(SUBADDRESS_SCAN_BALANCE_SCHEME),
            ring_decoy_freshness_entries_root: empty_root(RING_DECOY_FRESHNESS_SCHEME),
            pq_migration_safety_scores_root: empty_root(PQ_MIGRATION_SAFETY_SCHEME),
            low_fee_wallet_scan_batches_root: empty_root(LOW_FEE_SCAN_BATCH_SCHEME),
            deterministic_state_root: empty_root("jamtis-viewtag-decoy-rotation-health-state"),
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
pub struct RotationHealthEntry {
    pub rotation_id: String,
    pub lane: RotationLane,
    pub epoch: u64,
    pub monero_height_bucket: u64,
    pub ring_size: u16,
    pub anonymity_set_outputs: u64,
    pub rotation_buckets: u16,
    pub rotation_health_bps: u64,
    pub stale_decoy_bps: u64,
    pub rotation_reuse_bps: u64,
    pub viewtag_false_drop_bps: u64,
    pub redacted_viewtag_bucket_root: String,
    pub redacted_rotation_plan_root: String,
    pub jamtis_membership_root: String,
    pub decoy_sampler_commitment_root: String,
    pub expires_at_monero_height: u64,
    pub status: RotationStatus,
}

impl RotationHealthEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "rotation_id": self.rotation_id,
            "lane": self.lane.as_str(),
            "epoch": self.epoch,
            "monero_height_bucket": self.monero_height_bucket,
            "ring_size": self.ring_size,
            "anonymity_set_outputs": self.anonymity_set_outputs,
            "rotation_buckets": self.rotation_buckets,
            "rotation_health_bps": self.rotation_health_bps,
            "stale_decoy_bps": self.stale_decoy_bps,
            "rotation_reuse_bps": self.rotation_reuse_bps,
            "viewtag_false_drop_bps": self.viewtag_false_drop_bps,
            "redacted_viewtag_bucket_root": self.redacted_viewtag_bucket_root,
            "redacted_rotation_plan_root": self.redacted_rotation_plan_root,
            "jamtis_membership_root": self.jamtis_membership_root,
            "decoy_sampler_commitment_root": self.decoy_sampler_commitment_root,
            "expires_at_monero_height": self.expires_at_monero_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(ROTATION_HEALTH_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubaddressScanLoadBalance {
    pub balance_id: String,
    pub rotation_id: String,
    pub scan_window_blocks: u64,
    pub subaddress_cohort_count: u32,
    pub candidate_outputs: u64,
    pub assigned_scan_outputs: u64,
    pub load_balance_bps: u64,
    pub max_load_skew_bps: u64,
    pub redacted_subaddress_cohort_root: String,
    pub blinded_viewtag_queue_root: String,
    pub scan_credit_commitment_root: String,
    pub residual_privacy_root: String,
    pub status: RotationStatus,
}

impl SubaddressScanLoadBalance {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(SUBADDRESS_SCAN_BALANCE_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RingDecoyFreshnessEntry {
    pub freshness_id: String,
    pub rotation_id: String,
    pub ring_size: u16,
    pub freshness_bps: u64,
    pub median_decoy_age_blocks: u64,
    pub max_decoy_age_blocks: u64,
    pub recent_output_share_bps: u64,
    pub output_age_distribution_root: String,
    pub replacement_decoy_commitment_root: String,
    pub ring_rotation_watermark_root: String,
    pub expires_at_monero_height: u64,
    pub status: RotationStatus,
}

impl RingDecoyFreshnessEntry {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(RING_DECOY_FRESHNESS_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqMigrationSafetyScore {
    pub safety_id: String,
    pub rotation_id: String,
    pub pq_security_bits: u16,
    pub pq_safety_bps: u64,
    pub classical_fallback_disabled: bool,
    pub migration_epoch: u64,
    pub jamtis_viewtag_migration_root: String,
    pub decoy_rotation_guard_root: String,
    pub subaddress_scan_guard_root: String,
    pub attestation_root: String,
    pub status: RotationStatus,
}

impl PqMigrationSafetyScore {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(PQ_MIGRATION_SAFETY_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeWalletScanBatch {
    pub batch_id: String,
    pub rotation_id: String,
    pub balance_id: String,
    pub fee_asset_id: String,
    pub batch_outputs: u64,
    pub wallet_scan_count: u64,
    pub user_fee_bps: u64,
    pub rebate_bps: u64,
    pub batched_viewtag_scan_root: String,
    pub scan_sponsor_receipt_root: String,
    pub privacy_budget_root: String,
    pub status: RotationStatus,
}

impl LowFeeWalletScanBatch {
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
    pub rotation_health_entries: BTreeMap<String, RotationHealthEntry>,
    pub subaddress_scan_load_balances: BTreeMap<String, SubaddressScanLoadBalance>,
    pub ring_decoy_freshness_entries: BTreeMap<String, RingDecoyFreshnessEntry>,
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
            rotation_health_entries: BTreeMap::new(),
            subaddress_scan_load_balances: BTreeMap::new(),
            ring_decoy_freshness_entries: BTreeMap::new(),
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
            "runtime": "monero_l2_pq_private_jamtis_viewtag_decoy_rotation_health_runtime",
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

    pub fn insert_rotation_health_entry(&mut self, entry: RotationHealthEntry) -> Result<()> {
        ensure(
            entry.ring_size >= self.config.min_ring_size,
            "rotation health ring size is below minimum",
        )?;
        ensure(
            entry.anonymity_set_outputs >= self.config.min_anonymity_set_outputs,
            "rotation health entry is below anonymity-set privacy floor",
        )?;
        ensure(
            entry.rotation_buckets >= self.config.min_rotation_buckets,
            "rotation health entry has too few rotation buckets",
        )?;
        ensure(
            entry.rotation_health_bps >= self.config.min_rotation_health_bps,
            "rotation health score is below floor",
        )?;
        ensure(
            entry.stale_decoy_bps <= self.config.max_stale_decoy_bps,
            "stale decoy share exceeds cap",
        )?;
        ensure(
            entry.rotation_reuse_bps <= self.config.max_rotation_reuse_bps,
            "decoy rotation reuse exceeds cap",
        )?;
        ensure(
            entry.viewtag_false_drop_bps <= self.config.max_viewtag_false_drop_bps,
            "viewtag false-drop rate exceeds cap",
        )?;
        ensure(
            entry.expires_at_monero_height > self.monero_height,
            "rotation health entry must expire in the future",
        )?;
        self.rotation_health_entries
            .insert(entry.rotation_id.clone(), entry);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_subaddress_scan_load_balance(
        &mut self,
        balance: SubaddressScanLoadBalance,
    ) -> Result<()> {
        ensure(
            self.rotation_health_entries
                .contains_key(&balance.rotation_id),
            "subaddress scan load balance references unknown rotation",
        )?;
        ensure(
            balance.scan_window_blocks <= self.config.scan_window_blocks,
            "subaddress scan load balance exceeds configured scan window",
        )?;
        ensure(
            balance.subaddress_cohort_count > 0,
            "subaddress scan load balance must include at least one cohort",
        )?;
        ensure(
            balance.candidate_outputs >= self.config.min_anonymity_set_outputs,
            "subaddress scan candidate set is below privacy floor",
        )?;
        ensure(
            balance.assigned_scan_outputs >= self.config.min_subaddress_scan_batch_outputs,
            "subaddress scan assigned outputs are below batch floor",
        )?;
        ensure(
            balance.assigned_scan_outputs <= balance.candidate_outputs,
            "subaddress scan assigned outputs exceed candidate outputs",
        )?;
        ensure(
            balance.load_balance_bps >= self.config.min_load_balance_bps,
            "subaddress scan load balance score is below floor",
        )?;
        ensure(
            balance.max_load_skew_bps <= self.config.max_load_skew_bps,
            "subaddress scan load skew exceeds cap",
        )?;
        self.subaddress_scan_load_balances
            .insert(balance.balance_id.clone(), balance);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_ring_decoy_freshness_entry(
        &mut self,
        freshness: RingDecoyFreshnessEntry,
    ) -> Result<()> {
        ensure(
            self.rotation_health_entries
                .contains_key(&freshness.rotation_id),
            "ring decoy freshness entry references unknown rotation",
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
            freshness.recent_output_share_bps <= MAX_BPS,
            "recent output share exceeds max bps",
        )?;
        ensure(
            freshness.expires_at_monero_height > self.monero_height,
            "ring decoy freshness entry must expire in the future",
        )?;
        self.ring_decoy_freshness_entries
            .insert(freshness.freshness_id.clone(), freshness);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_pq_migration_safety_score(
        &mut self,
        safety: PqMigrationSafetyScore,
    ) -> Result<()> {
        ensure(
            self.rotation_health_entries
                .contains_key(&safety.rotation_id),
            "PQ migration safety score references unknown rotation",
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
            self.rotation_health_entries
                .contains_key(&batch.rotation_id),
            "low-fee wallet scan batch references unknown rotation",
        )?;
        ensure(
            self.subaddress_scan_load_balances
                .contains_key(&batch.balance_id),
            "low-fee wallet scan batch references unknown load balance",
        )?;
        ensure(
            batch.fee_asset_id == self.config.fee_asset_id,
            "low-fee wallet scan batch fee asset does not match config",
        )?;
        ensure(
            batch.batch_outputs >= self.config.min_subaddress_scan_batch_outputs,
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

    pub fn refresh_roots(&mut self) {
        self.counters.rotation_health_entries = self.rotation_health_entries.len() as u64;
        self.counters.subaddress_scan_load_balances =
            self.subaddress_scan_load_balances.len() as u64;
        self.counters.ring_decoy_freshness_entries = self.ring_decoy_freshness_entries.len() as u64;
        self.counters.pq_migration_safety_scores = self.pq_migration_safety_scores.len() as u64;
        self.counters.low_fee_wallet_scan_batches = self.low_fee_wallet_scan_batches.len() as u64;

        self.roots.rotation_health_entries_root = map_root(
            ROTATION_HEALTH_SCHEME,
            self.rotation_health_entries
                .iter()
                .map(|(id, entry)| (id.as_str(), entry.state_root())),
        );
        self.roots.subaddress_scan_load_balances_root = map_root(
            SUBADDRESS_SCAN_BALANCE_SCHEME,
            self.subaddress_scan_load_balances
                .iter()
                .map(|(id, balance)| (id.as_str(), balance.state_root())),
        );
        self.roots.ring_decoy_freshness_entries_root = map_root(
            RING_DECOY_FRESHNESS_SCHEME,
            self.ring_decoy_freshness_entries
                .iter()
                .map(|(id, freshness)| (id.as_str(), freshness.state_root())),
        );
        self.roots.pq_migration_safety_scores_root = map_root(
            PQ_MIGRATION_SAFETY_SCHEME,
            self.pq_migration_safety_scores
                .iter()
                .map(|(id, safety)| (id.as_str(), safety.state_root())),
        );
        self.roots.low_fee_wallet_scan_batches_root = map_root(
            LOW_FEE_SCAN_BATCH_SCHEME,
            self.low_fee_wallet_scan_batches
                .iter()
                .map(|(id, batch)| (id.as_str(), batch.state_root())),
        );
        self.roots.deterministic_state_root = self.state_root_without_cached_roots();
    }

    fn state_root_without_cached_roots(&self) -> String {
        root_from_parts(
            "jamtis-viewtag-decoy-rotation-health-state",
            &[
                HashPart::Str(&self.protocol_version),
                HashPart::Str(&self.chain_id),
                HashPart::Str(&self.config.state_root()),
                HashPart::U64(self.l2_height),
                HashPart::U64(self.monero_height),
                HashPart::U64(self.epoch),
                HashPart::Str(&self.counters.state_root()),
                HashPart::Str(&self.roots.rotation_health_entries_root),
                HashPart::Str(&self.roots.subaddress_scan_load_balances_root),
                HashPart::Str(&self.roots.ring_decoy_freshness_entries_root),
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
        .expect("default JAMTIS viewtag decoy rotation health config is valid")
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let rotation_id = "jamtis-viewtag-decoy-rotation-health-devnet-0".to_string();
    let balance_id = "jamtis-viewtag-subaddress-scan-load-balance-devnet-0".to_string();

    state
        .insert_rotation_health_entry(RotationHealthEntry {
            rotation_id: rotation_id.clone(),
            lane: RotationLane::WalletReceiveScan,
            epoch: DEVNET_EPOCH,
            monero_height_bucket: bucket(DEVNET_MONERO_HEIGHT, DEFAULT_PUBLIC_BUCKET_SIZE),
            ring_size: DEFAULT_TARGET_RING_SIZE,
            anonymity_set_outputs: DEFAULT_TARGET_ANONYMITY_SET_OUTPUTS,
            rotation_buckets: DEFAULT_TARGET_ROTATION_BUCKETS,
            rotation_health_bps: DEFAULT_TARGET_ROTATION_HEALTH_BPS,
            stale_decoy_bps: 360,
            rotation_reuse_bps: 90,
            viewtag_false_drop_bps: 5,
            redacted_viewtag_bucket_root: root_from_parts(
                "devnet-redacted-jamtis-viewtag-rotation-bucket",
                &[HashPart::Str(&rotation_id)],
            ),
            redacted_rotation_plan_root: root_from_parts(
                "devnet-redacted-jamtis-viewtag-decoy-rotation-plan",
                &[HashPart::Str(&rotation_id)],
            ),
            jamtis_membership_root: root_from_parts(
                "devnet-jamtis-viewtag-output-membership",
                &[HashPart::Str(&rotation_id)],
            ),
            decoy_sampler_commitment_root: root_from_parts(
                "devnet-jamtis-viewtag-decoy-sampler-commitment",
                &[HashPart::Str(&rotation_id)],
            ),
            expires_at_monero_height: DEVNET_MONERO_HEIGHT + DEFAULT_ROTATION_TTL_BLOCKS,
            status: RotationStatus::Rotated,
        })
        .expect("devnet rotation health inserts");
    state
        .insert_subaddress_scan_load_balance(SubaddressScanLoadBalance {
            balance_id: balance_id.clone(),
            rotation_id: rotation_id.clone(),
            scan_window_blocks: DEFAULT_SCAN_WINDOW_BLOCKS,
            subaddress_cohort_count: 64,
            candidate_outputs: DEFAULT_TARGET_ANONYMITY_SET_OUTPUTS,
            assigned_scan_outputs: DEFAULT_TARGET_SUBADDRESS_SCAN_BATCH_OUTPUTS,
            load_balance_bps: DEFAULT_TARGET_LOAD_BALANCE_BPS,
            max_load_skew_bps: 280,
            redacted_subaddress_cohort_root: root_from_parts(
                "devnet-redacted-jamtis-subaddress-scan-cohort",
                &[HashPart::Str(&balance_id)],
            ),
            blinded_viewtag_queue_root: root_from_parts(
                "devnet-blinded-jamtis-viewtag-scan-queue",
                &[HashPart::Str(&balance_id)],
            ),
            scan_credit_commitment_root: root_from_parts(
                "devnet-jamtis-subaddress-scan-credit-commitment",
                &[HashPart::Str(&balance_id)],
            ),
            residual_privacy_root: root_from_parts(
                "devnet-jamtis-subaddress-scan-residual-privacy",
                &[HashPart::Str(&balance_id)],
            ),
            status: RotationStatus::LoadBalanced,
        })
        .expect("devnet subaddress scan load balance inserts");
    state
        .insert_ring_decoy_freshness_entry(RingDecoyFreshnessEntry {
            freshness_id: "jamtis-viewtag-ring-decoy-freshness-devnet-0".to_string(),
            rotation_id: rotation_id.clone(),
            ring_size: DEFAULT_TARGET_RING_SIZE,
            freshness_bps: DEFAULT_TARGET_FRESHNESS_BPS,
            median_decoy_age_blocks: 24_000,
            max_decoy_age_blocks: 144_000,
            recent_output_share_bps: 1_800,
            output_age_distribution_root: root_from_parts(
                "devnet-jamtis-viewtag-output-age-distribution",
                &[HashPart::Str(&rotation_id)],
            ),
            replacement_decoy_commitment_root: root_from_parts(
                "devnet-jamtis-viewtag-replacement-decoy-commitment",
                &[HashPart::Str(&rotation_id)],
            ),
            ring_rotation_watermark_root: root_from_parts(
                "devnet-jamtis-viewtag-ring-rotation-watermark",
                &[HashPart::Str(&rotation_id)],
            ),
            expires_at_monero_height: DEVNET_MONERO_HEIGHT + DEFAULT_ROTATION_TTL_BLOCKS,
            status: RotationStatus::Fresh,
        })
        .expect("devnet ring decoy freshness inserts");
    state
        .insert_pq_migration_safety_score(PqMigrationSafetyScore {
            safety_id: "jamtis-viewtag-decoy-rotation-pq-safety-devnet-0".to_string(),
            rotation_id: rotation_id.clone(),
            pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            pq_safety_bps: DEFAULT_TARGET_PQ_SAFETY_BPS,
            classical_fallback_disabled: true,
            migration_epoch: DEVNET_EPOCH,
            jamtis_viewtag_migration_root: root_from_parts(
                "devnet-jamtis-viewtag-pq-migration",
                &[HashPart::Str(&rotation_id)],
            ),
            decoy_rotation_guard_root: root_from_parts(
                "devnet-jamtis-viewtag-decoy-rotation-pq-guard",
                &[HashPart::Str(&rotation_id)],
            ),
            subaddress_scan_guard_root: root_from_parts(
                "devnet-jamtis-subaddress-scan-pq-guard",
                &[HashPart::Str(&rotation_id)],
            ),
            attestation_root: root_from_parts(
                "devnet-jamtis-viewtag-decoy-rotation-pq-attestation",
                &[HashPart::Str(&rotation_id)],
            ),
            status: RotationStatus::PqSafe,
        })
        .expect("devnet PQ migration safety inserts");
    state
        .insert_low_fee_wallet_scan_batch(LowFeeWalletScanBatch {
            batch_id: "jamtis-viewtag-low-fee-wallet-scan-batch-devnet-0".to_string(),
            rotation_id,
            balance_id,
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            batch_outputs: DEFAULT_TARGET_SUBADDRESS_SCAN_BATCH_OUTPUTS,
            wallet_scan_count: 512,
            user_fee_bps: DEFAULT_MAX_BATCH_FEE_BPS,
            rebate_bps: DEFAULT_TARGET_BATCH_REBATE_BPS,
            batched_viewtag_scan_root: root_from_parts(
                "devnet-jamtis-batched-viewtag-wallet-scan",
                &[HashPart::Str("0")],
            ),
            scan_sponsor_receipt_root: root_from_parts(
                "devnet-jamtis-viewtag-wallet-scan-sponsor-receipt",
                &[HashPart::Str("0")],
            ),
            privacy_budget_root: root_from_parts(
                "devnet-jamtis-viewtag-wallet-scan-privacy-budget",
                &[HashPart::Str("0")],
            ),
            status: RotationStatus::BatchEligible,
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
        &format!("JAMTIS-VIEWTAG-DECOY-ROTATION-HEALTH-{domain}"),
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
        &format!("JAMTIS-VIEWTAG-DECOY-ROTATION-HEALTH-{domain}"),
        &leaves,
    )
}
