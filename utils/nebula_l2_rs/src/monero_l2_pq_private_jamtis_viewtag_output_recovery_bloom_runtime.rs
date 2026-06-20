use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = MoneroL2PqPrivateJamtisViewtagOutputRecoveryBloomRuntimeResult<T>;
pub type MoneroL2PqPrivateJamtisViewtagOutputRecoveryBloomRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_JAMTIS_VIEWTAG_OUTPUT_RECOVERY_BLOOM_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-jamtis-viewtag-output-recovery-bloom-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_JAMTIS_VIEWTAG_OUTPUT_RECOVERY_BLOOM_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RECOVERY_BLOOM_CACHE_SCHEME: &str = "jamtis-viewtag-output-recovery-bloom-cache-root-v1";
pub const PRIVACY_PROBE_SCHEME: &str = "privacy-preserving-jamtis-viewtag-recovery-probe-root-v1";
pub const PQ_MIGRATION_COMMITMENT_SCHEME: &str =
    "ML-DSA-87+ML-KEM-1024+SLH-DSA-SHAKE-256f-jamtis-viewtag-recovery-migration-root-v1";
pub const DECOY_FRESHNESS_SCHEME: &str = "jamtis-viewtag-output-recovery-decoy-freshness-root-v1";
pub const LOW_FEE_WALLET_RECOVERY_REBATE_SCHEME: &str =
    "low-fee-private-jamtis-viewtag-wallet-recovery-rebate-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "deterministic-public-jamtis-viewtag-output-recovery-bloom-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_addresses_view_keys_key_images_amounts_output_indices_viewtags_or_probe_secrets";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_112_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_788_000;
pub const DEVNET_EPOCH: u64 = 16_480;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_RING_SIZE: u16 = 16;
pub const DEFAULT_TARGET_RING_SIZE: u16 = 96;
pub const DEFAULT_MIN_RECOVERY_COHORT_OUTPUTS: u64 = 131_072;
pub const DEFAULT_TARGET_RECOVERY_COHORT_OUTPUTS: u64 = 524_288;
pub const DEFAULT_MIN_BLOOM_BITS: u64 = 1_048_576;
pub const DEFAULT_TARGET_BLOOM_BITS: u64 = 4_194_304;
pub const DEFAULT_MIN_HASH_FUNCTIONS: u8 = 7;
pub const DEFAULT_TARGET_HASH_FUNCTIONS: u8 = 11;
pub const DEFAULT_MAX_FALSE_POSITIVE_BPS: u64 = 35;
pub const DEFAULT_MIN_PROBE_PRIVACY_BPS: u64 = 9_000;
pub const DEFAULT_MIN_DECOY_FRESHNESS_BPS: u64 = 8_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_RECOVERY_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_PROBE_WINDOW_BLOCKS: u64 = 360;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 5;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 4;
pub const DEFAULT_PUBLIC_BUCKET_SIZE: u64 = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BloomLane {
    WalletRestore,
    WatchOnlyRestore,
    BridgeWithdrawalRestore,
    MerchantReceiveRestore,
    SwapSettlementRestore,
    ReorgRepair,
}

impl BloomLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletRestore => "wallet_restore",
            Self::WatchOnlyRestore => "watch_only_restore",
            Self::BridgeWithdrawalRestore => "bridge_withdrawal_restore",
            Self::MerchantReceiveRestore => "merchant_receive_restore",
            Self::SwapSettlementRestore => "swap_settlement_restore",
            Self::ReorgRepair => "reorg_repair",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BloomStatus {
    Draft,
    Cached,
    ProbePrivate,
    Committed,
    Fresh,
    RebateEligible,
    Sealed,
    Expired,
    Quarantined,
}

impl BloomStatus {
    pub fn public_usable(self) -> bool {
        matches!(
            self,
            Self::Cached
                | Self::ProbePrivate
                | Self::Committed
                | Self::Fresh
                | Self::RebateEligible
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
    pub min_recovery_cohort_outputs: u64,
    pub target_recovery_cohort_outputs: u64,
    pub min_bloom_bits: u64,
    pub target_bloom_bits: u64,
    pub min_hash_functions: u8,
    pub target_hash_functions: u8,
    pub max_false_positive_bps: u64,
    pub min_probe_privacy_bps: u64,
    pub min_decoy_freshness_bps: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub recovery_ttl_blocks: u64,
    pub probe_window_blocks: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
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
            min_recovery_cohort_outputs: DEFAULT_MIN_RECOVERY_COHORT_OUTPUTS,
            target_recovery_cohort_outputs: DEFAULT_TARGET_RECOVERY_COHORT_OUTPUTS,
            min_bloom_bits: DEFAULT_MIN_BLOOM_BITS,
            target_bloom_bits: DEFAULT_TARGET_BLOOM_BITS,
            min_hash_functions: DEFAULT_MIN_HASH_FUNCTIONS,
            target_hash_functions: DEFAULT_TARGET_HASH_FUNCTIONS,
            max_false_positive_bps: DEFAULT_MAX_FALSE_POSITIVE_BPS,
            min_probe_privacy_bps: DEFAULT_MIN_PROBE_PRIVACY_BPS,
            min_decoy_freshness_bps: DEFAULT_MIN_DECOY_FRESHNESS_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            recovery_ttl_blocks: DEFAULT_RECOVERY_TTL_BLOCKS,
            probe_window_blocks: DEFAULT_PROBE_WINDOW_BLOCKS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
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
            self.target_recovery_cohort_outputs >= self.min_recovery_cohort_outputs,
            "target recovery cohort must cover privacy floor",
        )?;
        ensure(
            self.target_bloom_bits >= self.min_bloom_bits,
            "target bloom size must cover minimum bloom size",
        )?;
        ensure(
            self.target_hash_functions >= self.min_hash_functions,
            "target hash function count must cover minimum count",
        )?;
        ensure(
            self.max_false_positive_bps <= MAX_BPS
                && self.min_probe_privacy_bps <= MAX_BPS
                && self.min_decoy_freshness_bps <= MAX_BPS,
            "privacy thresholds exceed max bps",
        )?;
        ensure(
            self.target_pq_security_bits >= self.min_pq_security_bits,
            "target PQ security must cover minimum PQ security",
        )?;
        ensure(
            self.recovery_ttl_blocks > 0,
            "recovery ttl must be non-zero",
        )?;
        ensure(
            self.probe_window_blocks > 0,
            "probe window must be non-zero",
        )?;
        ensure(
            self.max_user_fee_bps <= MAX_BPS,
            "maximum user fee bps exceeds bound",
        )?;
        ensure(
            self.target_rebate_bps <= self.max_user_fee_bps,
            "rebate bps must not exceed fee bps",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "jamtis-viewtag-output-recovery-bloom-config",
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
    pub recovery_bloom_caches: u64,
    pub privacy_recovery_probes: u64,
    pub pq_migration_commitments: u64,
    pub decoy_freshness_claims: u64,
    pub low_fee_wallet_recovery_rebates: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "jamtis-viewtag-output-recovery-bloom-counters",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub recovery_bloom_caches_root: String,
    pub privacy_recovery_probes_root: String,
    pub pq_migration_commitments_root: String,
    pub decoy_freshness_claims_root: String,
    pub low_fee_wallet_recovery_rebates_root: String,
    pub deterministic_state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            recovery_bloom_caches_root: empty_root(RECOVERY_BLOOM_CACHE_SCHEME),
            privacy_recovery_probes_root: empty_root(PRIVACY_PROBE_SCHEME),
            pq_migration_commitments_root: empty_root(PQ_MIGRATION_COMMITMENT_SCHEME),
            decoy_freshness_claims_root: empty_root(DECOY_FRESHNESS_SCHEME),
            low_fee_wallet_recovery_rebates_root: empty_root(LOW_FEE_WALLET_RECOVERY_REBATE_SCHEME),
            deterministic_state_root: empty_root("jamtis-viewtag-output-recovery-bloom-state"),
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
pub struct RecoveryBloomCache {
    pub cache_id: String,
    pub lane: BloomLane,
    pub epoch: u64,
    pub monero_height_bucket: u64,
    pub recovery_cohort_outputs: u64,
    pub bloom_bits: u64,
    pub hash_functions: u8,
    pub false_positive_bps: u64,
    pub redacted_viewtag_bloom_root: String,
    pub jamtis_output_commitment_root: String,
    pub expires_at_monero_height: u64,
    pub status: BloomStatus,
}

impl RecoveryBloomCache {
    pub fn public_record(&self) -> Value {
        json!({
            "cache_id": self.cache_id,
            "lane": self.lane.as_str(),
            "epoch": self.epoch,
            "monero_height_bucket": self.monero_height_bucket,
            "recovery_cohort_outputs": self.recovery_cohort_outputs,
            "bloom_bits": self.bloom_bits,
            "hash_functions": self.hash_functions,
            "false_positive_bps": self.false_positive_bps,
            "redacted_viewtag_bloom_root": self.redacted_viewtag_bloom_root,
            "jamtis_output_commitment_root": self.jamtis_output_commitment_root,
            "expires_at_monero_height": self.expires_at_monero_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(RECOVERY_BLOOM_CACHE_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRecoveryProbe {
    pub probe_id: String,
    pub cache_id: String,
    pub probe_window_blocks: u64,
    pub probe_privacy_bps: u64,
    pub blinded_query_root: String,
    pub recovery_cohort_root: String,
    pub status: BloomStatus,
}

impl PrivacyRecoveryProbe {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(PRIVACY_PROBE_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqMigrationCommitment {
    pub commitment_id: String,
    pub cache_id: String,
    pub pq_security_bits: u16,
    pub classical_fallback_disabled: bool,
    pub migration_epoch: u64,
    pub migration_commitment_root: String,
    pub attestation_root: String,
    pub status: BloomStatus,
}

impl PqMigrationCommitment {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(PQ_MIGRATION_COMMITMENT_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecoyFreshnessClaim {
    pub freshness_id: String,
    pub cache_id: String,
    pub ring_size: u16,
    pub decoy_freshness_bps: u64,
    pub output_age_distribution_root: String,
    pub replacement_decoy_root: String,
    pub expires_at_monero_height: u64,
    pub status: BloomStatus,
}

impl DecoyFreshnessClaim {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(DECOY_FRESHNESS_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeWalletRecoveryRebate {
    pub rebate_id: String,
    pub cache_id: String,
    pub fee_asset_id: String,
    pub user_fee_bps: u64,
    pub rebate_bps: u64,
    pub recovery_window_root: String,
    pub sponsor_receipt_root: String,
}

impl LowFeeWalletRecoveryRebate {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(LOW_FEE_WALLET_RECOVERY_REBATE_SCHEME, &self.public_record())
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
    pub recovery_bloom_caches: BTreeMap<String, RecoveryBloomCache>,
    pub privacy_recovery_probes: BTreeMap<String, PrivacyRecoveryProbe>,
    pub pq_migration_commitments: BTreeMap<String, PqMigrationCommitment>,
    pub decoy_freshness_claims: BTreeMap<String, DecoyFreshnessClaim>,
    pub low_fee_wallet_recovery_rebates: BTreeMap<String, LowFeeWalletRecoveryRebate>,
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
            recovery_bloom_caches: BTreeMap::new(),
            privacy_recovery_probes: BTreeMap::new(),
            pq_migration_commitments: BTreeMap::new(),
            decoy_freshness_claims: BTreeMap::new(),
            low_fee_wallet_recovery_rebates: BTreeMap::new(),
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
            "runtime": "monero_l2_pq_private_jamtis_viewtag_output_recovery_bloom_runtime",
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

    pub fn insert_recovery_bloom_cache(&mut self, cache: RecoveryBloomCache) -> Result<()> {
        ensure(
            cache.recovery_cohort_outputs >= self.config.min_recovery_cohort_outputs,
            "recovery bloom cache is below output cohort privacy floor",
        )?;
        ensure(
            cache.bloom_bits >= self.config.min_bloom_bits,
            "recovery bloom cache is below minimum bloom size",
        )?;
        ensure(
            cache.hash_functions >= self.config.min_hash_functions,
            "recovery bloom cache is below minimum hash function count",
        )?;
        ensure(
            cache.false_positive_bps <= self.config.max_false_positive_bps,
            "recovery bloom cache false-positive rate exceeds cap",
        )?;
        ensure(
            cache.expires_at_monero_height > self.monero_height,
            "recovery bloom cache must expire in the future",
        )?;
        self.recovery_bloom_caches
            .insert(cache.cache_id.clone(), cache);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_privacy_recovery_probe(&mut self, probe: PrivacyRecoveryProbe) -> Result<()> {
        ensure(
            self.recovery_bloom_caches.contains_key(&probe.cache_id),
            "privacy recovery probe references unknown bloom cache",
        )?;
        ensure(
            probe.probe_window_blocks <= self.config.probe_window_blocks,
            "privacy recovery probe exceeds configured window",
        )?;
        ensure(
            probe.probe_privacy_bps >= self.config.min_probe_privacy_bps,
            "privacy recovery probe score is below floor",
        )?;
        self.privacy_recovery_probes
            .insert(probe.probe_id.clone(), probe);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_pq_migration_commitment(
        &mut self,
        commitment: PqMigrationCommitment,
    ) -> Result<()> {
        ensure(
            self.recovery_bloom_caches
                .contains_key(&commitment.cache_id),
            "PQ migration commitment references unknown bloom cache",
        )?;
        ensure(
            commitment.pq_security_bits >= self.config.min_pq_security_bits,
            "PQ migration commitment is below minimum security",
        )?;
        ensure(
            commitment.classical_fallback_disabled,
            "PQ migration commitment must disable classical fallback",
        )?;
        self.pq_migration_commitments
            .insert(commitment.commitment_id.clone(), commitment);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_decoy_freshness_claim(&mut self, freshness: DecoyFreshnessClaim) -> Result<()> {
        ensure(
            self.recovery_bloom_caches.contains_key(&freshness.cache_id),
            "decoy freshness claim references unknown bloom cache",
        )?;
        ensure(
            freshness.ring_size >= self.config.min_ring_size,
            "decoy freshness ring size is below minimum",
        )?;
        ensure(
            freshness.decoy_freshness_bps >= self.config.min_decoy_freshness_bps,
            "decoy freshness score is below floor",
        )?;
        ensure(
            freshness.expires_at_monero_height > self.monero_height,
            "decoy freshness claim must expire in the future",
        )?;
        self.decoy_freshness_claims
            .insert(freshness.freshness_id.clone(), freshness);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_low_fee_wallet_recovery_rebate(
        &mut self,
        rebate: LowFeeWalletRecoveryRebate,
    ) -> Result<()> {
        ensure(
            self.recovery_bloom_caches.contains_key(&rebate.cache_id),
            "wallet recovery rebate references unknown bloom cache",
        )?;
        ensure(
            rebate.user_fee_bps <= self.config.max_user_fee_bps,
            "wallet recovery rebate user fee exceeds low-fee cap",
        )?;
        ensure(
            rebate.rebate_bps <= rebate.user_fee_bps,
            "wallet recovery rebate exceeds charged fee",
        )?;
        self.low_fee_wallet_recovery_rebates
            .insert(rebate.rebate_id.clone(), rebate);
        self.refresh_roots();
        Ok(())
    }

    pub fn refresh_roots(&mut self) {
        self.counters.recovery_bloom_caches = self.recovery_bloom_caches.len() as u64;
        self.counters.privacy_recovery_probes = self.privacy_recovery_probes.len() as u64;
        self.counters.pq_migration_commitments = self.pq_migration_commitments.len() as u64;
        self.counters.decoy_freshness_claims = self.decoy_freshness_claims.len() as u64;
        self.counters.low_fee_wallet_recovery_rebates =
            self.low_fee_wallet_recovery_rebates.len() as u64;

        self.roots.recovery_bloom_caches_root = map_root(
            RECOVERY_BLOOM_CACHE_SCHEME,
            self.recovery_bloom_caches
                .iter()
                .map(|(id, cache)| (id.as_str(), cache.state_root())),
        );
        self.roots.privacy_recovery_probes_root = map_root(
            PRIVACY_PROBE_SCHEME,
            self.privacy_recovery_probes
                .iter()
                .map(|(id, probe)| (id.as_str(), probe.state_root())),
        );
        self.roots.pq_migration_commitments_root = map_root(
            PQ_MIGRATION_COMMITMENT_SCHEME,
            self.pq_migration_commitments
                .iter()
                .map(|(id, commitment)| (id.as_str(), commitment.state_root())),
        );
        self.roots.decoy_freshness_claims_root = map_root(
            DECOY_FRESHNESS_SCHEME,
            self.decoy_freshness_claims
                .iter()
                .map(|(id, freshness)| (id.as_str(), freshness.state_root())),
        );
        self.roots.low_fee_wallet_recovery_rebates_root = map_root(
            LOW_FEE_WALLET_RECOVERY_REBATE_SCHEME,
            self.low_fee_wallet_recovery_rebates
                .iter()
                .map(|(id, rebate)| (id.as_str(), rebate.state_root())),
        );
        self.roots.deterministic_state_root = self.state_root_without_cached_roots();
    }

    fn state_root_without_cached_roots(&self) -> String {
        root_from_parts(
            "jamtis-viewtag-output-recovery-bloom-state",
            &[
                HashPart::Str(&self.protocol_version),
                HashPart::Str(&self.chain_id),
                HashPart::Str(&self.config.state_root()),
                HashPart::U64(self.l2_height),
                HashPart::U64(self.monero_height),
                HashPart::U64(self.epoch),
                HashPart::Str(&self.counters.state_root()),
                HashPart::Str(&self.roots.recovery_bloom_caches_root),
                HashPart::Str(&self.roots.privacy_recovery_probes_root),
                HashPart::Str(&self.roots.pq_migration_commitments_root),
                HashPart::Str(&self.roots.decoy_freshness_claims_root),
                HashPart::Str(&self.roots.low_fee_wallet_recovery_rebates_root),
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
        .expect("default JAMTIS viewtag output recovery bloom config is valid")
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let cache_id = "jamtis-viewtag-output-recovery-bloom-devnet-0".to_string();

    state
        .insert_recovery_bloom_cache(RecoveryBloomCache {
            cache_id: cache_id.clone(),
            lane: BloomLane::WalletRestore,
            epoch: DEVNET_EPOCH,
            monero_height_bucket: bucket(DEVNET_MONERO_HEIGHT, DEFAULT_PUBLIC_BUCKET_SIZE),
            recovery_cohort_outputs: DEFAULT_TARGET_RECOVERY_COHORT_OUTPUTS,
            bloom_bits: DEFAULT_TARGET_BLOOM_BITS,
            hash_functions: DEFAULT_TARGET_HASH_FUNCTIONS,
            false_positive_bps: 18,
            redacted_viewtag_bloom_root: root_from_parts(
                "devnet-redacted-jamtis-viewtag-recovery-bloom",
                &[HashPart::Str(&cache_id)],
            ),
            jamtis_output_commitment_root: root_from_parts(
                "devnet-jamtis-output-recovery-commitment",
                &[HashPart::Str(&cache_id)],
            ),
            expires_at_monero_height: DEVNET_MONERO_HEIGHT + DEFAULT_RECOVERY_TTL_BLOCKS,
            status: BloomStatus::Cached,
        })
        .expect("devnet recovery bloom cache inserts");
    state
        .insert_privacy_recovery_probe(PrivacyRecoveryProbe {
            probe_id: "jamtis-viewtag-private-recovery-probe-devnet-0".to_string(),
            cache_id: cache_id.clone(),
            probe_window_blocks: DEFAULT_PROBE_WINDOW_BLOCKS,
            probe_privacy_bps: 9_260,
            blinded_query_root: root_from_parts(
                "devnet-blinded-jamtis-viewtag-recovery-query",
                &[HashPart::Str("0")],
            ),
            recovery_cohort_root: root_from_parts(
                "devnet-jamtis-viewtag-recovery-cohort",
                &[HashPart::Str(&cache_id)],
            ),
            status: BloomStatus::ProbePrivate,
        })
        .expect("devnet privacy recovery probe inserts");
    state
        .insert_pq_migration_commitment(PqMigrationCommitment {
            commitment_id: "jamtis-viewtag-output-recovery-pq-migration-devnet-0".to_string(),
            cache_id: cache_id.clone(),
            pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            classical_fallback_disabled: true,
            migration_epoch: DEVNET_EPOCH,
            migration_commitment_root: root_from_parts(
                "devnet-jamtis-viewtag-output-recovery-pq-migration",
                &[HashPart::Str(&cache_id)],
            ),
            attestation_root: root_from_parts(
                "devnet-jamtis-viewtag-output-recovery-pq-attestation",
                &[HashPart::Str(&cache_id)],
            ),
            status: BloomStatus::Committed,
        })
        .expect("devnet PQ migration commitment inserts");
    state
        .insert_decoy_freshness_claim(DecoyFreshnessClaim {
            freshness_id: "jamtis-viewtag-output-recovery-decoy-freshness-devnet-0".to_string(),
            cache_id: cache_id.clone(),
            ring_size: DEFAULT_TARGET_RING_SIZE,
            decoy_freshness_bps: 9_020,
            output_age_distribution_root: root_from_parts(
                "devnet-jamtis-viewtag-output-recovery-decoy-age-distribution",
                &[HashPart::Str(&cache_id)],
            ),
            replacement_decoy_root: root_from_parts(
                "devnet-jamtis-viewtag-output-recovery-replacement-decoy",
                &[HashPart::Str(&cache_id)],
            ),
            expires_at_monero_height: DEVNET_MONERO_HEIGHT + DEFAULT_RECOVERY_TTL_BLOCKS,
            status: BloomStatus::Fresh,
        })
        .expect("devnet decoy freshness inserts");
    state
        .insert_low_fee_wallet_recovery_rebate(LowFeeWalletRecoveryRebate {
            rebate_id: "jamtis-viewtag-low-fee-wallet-recovery-rebate-devnet-0".to_string(),
            cache_id,
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            recovery_window_root: root_from_parts(
                "devnet-jamtis-viewtag-wallet-recovery-window",
                &[HashPart::Str("0")],
            ),
            sponsor_receipt_root: root_from_parts(
                "devnet-jamtis-viewtag-wallet-recovery-sponsor-receipt",
                &[HashPart::Str("0")],
            ),
        })
        .expect("devnet low-fee wallet recovery rebate inserts");

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
        &format!("JAMTIS-VIEWTAG-OUTPUT-RECOVERY-BLOOM-{domain}"),
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
        &format!("JAMTIS-VIEWTAG-OUTPUT-RECOVERY-BLOOM-{domain}"),
        &leaves,
    )
}
