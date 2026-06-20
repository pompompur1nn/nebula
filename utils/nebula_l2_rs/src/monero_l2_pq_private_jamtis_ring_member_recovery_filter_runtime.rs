use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = MoneroL2PqPrivateJamtisRingMemberRecoveryFilterRuntimeResult<T>;
pub type MoneroL2PqPrivateJamtisRingMemberRecoveryFilterRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_JAMTIS_RING_MEMBER_RECOVERY_FILTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-jamtis-ring-member-recovery-filter-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_JAMTIS_RING_MEMBER_RECOVERY_FILTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RING_MEMBER_RECOVERY_FILTER_SCHEME: &str = "jamtis-ring-member-recovery-filter-root-v1";
pub const PRIVACY_PROBE_SCHEME: &str =
    "privacy-preserving-jamtis-ring-member-recovery-probe-root-v1";
pub const PQ_MIGRATION_COMMITMENT_SCHEME: &str =
    "ML-DSA-87+ML-KEM-1024+SLH-DSA-SHAKE-256f-jamtis-ring-member-recovery-migration-root-v1";
pub const DECOY_FRESHNESS_SCHEME: &str = "jamtis-ring-member-recovery-decoy-freshness-root-v1";
pub const LOW_FEE_WALLET_RECOVERY_REBATE_SCHEME: &str =
    "low-fee-private-jamtis-ring-member-wallet-recovery-rebate-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "deterministic-public-jamtis-ring-member-recovery-filter-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_addresses_view_keys_spend_keys_amounts_output_indices_ring_members_or_probe_secrets";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_128_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_804_000;
pub const DEVNET_EPOCH: u64 = 17_040;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_RING_SIZE: u16 = 16;
pub const DEFAULT_TARGET_RING_SIZE: u16 = 128;
pub const DEFAULT_MIN_RECOVERY_COHORT_OUTPUTS: u64 = 131_072;
pub const DEFAULT_TARGET_RECOVERY_COHORT_OUTPUTS: u64 = 524_288;
pub const DEFAULT_MIN_FILTER_BITS: u64 = 2_097_152;
pub const DEFAULT_TARGET_FILTER_BITS: u64 = 8_388_608;
pub const DEFAULT_MIN_HASH_FUNCTIONS: u8 = 7;
pub const DEFAULT_TARGET_HASH_FUNCTIONS: u8 = 12;
pub const DEFAULT_MAX_FALSE_POSITIVE_BPS: u64 = 20;
pub const DEFAULT_MIN_PROBE_PRIVACY_BPS: u64 = 9_250;
pub const DEFAULT_MIN_DECOY_FRESHNESS_BPS: u64 = 8_250;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_RECOVERY_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_PROBE_WINDOW_BLOCKS: u64 = 360;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 5;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 4;
pub const DEFAULT_PUBLIC_BUCKET_SIZE: u64 = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RingMemberRecoveryLane {
    WalletRestore,
    WatchOnlyRestore,
    BridgeWithdrawalRestore,
    SwapSettlementRestore,
    MerchantReceiveRestore,
    ReorgRepair,
}

impl RingMemberRecoveryLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletRestore => "wallet_restore",
            Self::WatchOnlyRestore => "watch_only_restore",
            Self::BridgeWithdrawalRestore => "bridge_withdrawal_restore",
            Self::SwapSettlementRestore => "swap_settlement_restore",
            Self::MerchantReceiveRestore => "merchant_receive_restore",
            Self::ReorgRepair => "reorg_repair",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RingMemberRecoveryStatus {
    Draft,
    Filtered,
    ProbePrivate,
    Committed,
    Fresh,
    RebateEligible,
    Sealed,
    Expired,
    Quarantined,
}

impl RingMemberRecoveryStatus {
    pub fn public_usable(self) -> bool {
        matches!(
            self,
            Self::Filtered
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
    pub min_filter_bits: u64,
    pub target_filter_bits: u64,
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
            min_filter_bits: DEFAULT_MIN_FILTER_BITS,
            target_filter_bits: DEFAULT_TARGET_FILTER_BITS,
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
            "target output recovery cohort must cover privacy floor",
        )?;
        ensure(
            self.target_filter_bits >= self.min_filter_bits,
            "target filter size must cover minimum filter size",
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
            "jamtis-ring-member-recovery-filter-config",
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
    pub ring_member_recovery_filters: u64,
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
            "jamtis-ring-member-recovery-filter-counters",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub ring_member_recovery_filters_root: String,
    pub privacy_recovery_probes_root: String,
    pub pq_migration_commitments_root: String,
    pub decoy_freshness_claims_root: String,
    pub low_fee_wallet_recovery_rebates_root: String,
    pub deterministic_state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            ring_member_recovery_filters_root: empty_root(RING_MEMBER_RECOVERY_FILTER_SCHEME),
            privacy_recovery_probes_root: empty_root(PRIVACY_PROBE_SCHEME),
            pq_migration_commitments_root: empty_root(PQ_MIGRATION_COMMITMENT_SCHEME),
            decoy_freshness_claims_root: empty_root(DECOY_FRESHNESS_SCHEME),
            low_fee_wallet_recovery_rebates_root: empty_root(LOW_FEE_WALLET_RECOVERY_REBATE_SCHEME),
            deterministic_state_root: empty_root("jamtis-ring-member-recovery-filter-state"),
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
pub struct RingMemberRecoveryFilter {
    pub filter_id: String,
    pub lane: RingMemberRecoveryLane,
    pub epoch: u64,
    pub monero_height_bucket: u64,
    pub ring_size: u16,
    pub recovery_cohort_outputs: u64,
    pub filter_bits: u64,
    pub hash_functions: u8,
    pub false_positive_bps: u64,
    pub redacted_ring_member_filter_root: String,
    pub jamtis_output_membership_root: String,
    pub ring_member_commitment_root: String,
    pub expires_at_monero_height: u64,
    pub status: RingMemberRecoveryStatus,
}

impl RingMemberRecoveryFilter {
    pub fn public_record(&self) -> Value {
        json!({
            "filter_id": self.filter_id,
            "lane": self.lane.as_str(),
            "epoch": self.epoch,
            "monero_height_bucket": self.monero_height_bucket,
            "ring_size": self.ring_size,
            "recovery_cohort_outputs": self.recovery_cohort_outputs,
            "filter_bits": self.filter_bits,
            "hash_functions": self.hash_functions,
            "false_positive_bps": self.false_positive_bps,
            "redacted_ring_member_filter_root": self.redacted_ring_member_filter_root,
            "jamtis_output_membership_root": self.jamtis_output_membership_root,
            "ring_member_commitment_root": self.ring_member_commitment_root,
            "expires_at_monero_height": self.expires_at_monero_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(RING_MEMBER_RECOVERY_FILTER_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRecoveryProbe {
    pub probe_id: String,
    pub filter_id: String,
    pub probe_window_blocks: u64,
    pub probe_privacy_bps: u64,
    pub blinded_ring_member_query_root: String,
    pub recovery_output_cohort_root: String,
    pub status: RingMemberRecoveryStatus,
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
    pub filter_id: String,
    pub pq_security_bits: u16,
    pub classical_fallback_disabled: bool,
    pub migration_epoch: u64,
    pub ring_member_migration_commitment_root: String,
    pub jamtis_address_migration_commitment_root: String,
    pub attestation_root: String,
    pub status: RingMemberRecoveryStatus,
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
    pub filter_id: String,
    pub ring_size: u16,
    pub decoy_freshness_bps: u64,
    pub output_age_distribution_root: String,
    pub replacement_ring_member_root: String,
    pub expires_at_monero_height: u64,
    pub status: RingMemberRecoveryStatus,
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
    pub filter_id: String,
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
    pub ring_member_recovery_filters: BTreeMap<String, RingMemberRecoveryFilter>,
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
            ring_member_recovery_filters: BTreeMap::new(),
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
            "runtime": "monero_l2_pq_private_jamtis_ring_member_recovery_filter_runtime",
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

    pub fn insert_ring_member_recovery_filter(
        &mut self,
        filter: RingMemberRecoveryFilter,
    ) -> Result<()> {
        ensure(
            filter.ring_size >= self.config.min_ring_size,
            "ring-member recovery filter ring size is below minimum",
        )?;
        ensure(
            filter.recovery_cohort_outputs >= self.config.min_recovery_cohort_outputs,
            "ring-member recovery filter is below output cohort privacy floor",
        )?;
        ensure(
            filter.filter_bits >= self.config.min_filter_bits,
            "ring-member recovery filter is below minimum filter size",
        )?;
        ensure(
            filter.hash_functions >= self.config.min_hash_functions,
            "ring-member recovery filter is below minimum hash function count",
        )?;
        ensure(
            filter.false_positive_bps <= self.config.max_false_positive_bps,
            "ring-member recovery filter false-positive rate exceeds cap",
        )?;
        ensure(
            filter.expires_at_monero_height > self.monero_height,
            "ring-member recovery filter must expire in the future",
        )?;
        self.ring_member_recovery_filters
            .insert(filter.filter_id.clone(), filter);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_privacy_recovery_probe(&mut self, probe: PrivacyRecoveryProbe) -> Result<()> {
        ensure(
            self.ring_member_recovery_filters
                .contains_key(&probe.filter_id),
            "privacy recovery probe references unknown ring-member filter",
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
            self.ring_member_recovery_filters
                .contains_key(&commitment.filter_id),
            "PQ migration commitment references unknown ring-member filter",
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
            self.ring_member_recovery_filters
                .contains_key(&freshness.filter_id),
            "decoy freshness claim references unknown ring-member filter",
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
            self.ring_member_recovery_filters
                .contains_key(&rebate.filter_id),
            "wallet recovery rebate references unknown ring-member filter",
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
        self.counters.ring_member_recovery_filters = self.ring_member_recovery_filters.len() as u64;
        self.counters.privacy_recovery_probes = self.privacy_recovery_probes.len() as u64;
        self.counters.pq_migration_commitments = self.pq_migration_commitments.len() as u64;
        self.counters.decoy_freshness_claims = self.decoy_freshness_claims.len() as u64;
        self.counters.low_fee_wallet_recovery_rebates =
            self.low_fee_wallet_recovery_rebates.len() as u64;

        self.roots.ring_member_recovery_filters_root = map_root(
            RING_MEMBER_RECOVERY_FILTER_SCHEME,
            self.ring_member_recovery_filters
                .iter()
                .map(|(id, filter)| (id.as_str(), filter.state_root())),
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
            "jamtis-ring-member-recovery-filter-state",
            &[
                HashPart::Str(&self.protocol_version),
                HashPart::Str(&self.chain_id),
                HashPart::Str(&self.config.state_root()),
                HashPart::U64(self.l2_height),
                HashPart::U64(self.monero_height),
                HashPart::U64(self.epoch),
                HashPart::Str(&self.counters.state_root()),
                HashPart::Str(&self.roots.ring_member_recovery_filters_root),
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
        .expect("default JAMTIS ring-member recovery filter config is valid")
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let filter_id = "jamtis-ring-member-recovery-filter-devnet-0".to_string();

    state
        .insert_ring_member_recovery_filter(RingMemberRecoveryFilter {
            filter_id: filter_id.clone(),
            lane: RingMemberRecoveryLane::WalletRestore,
            epoch: DEVNET_EPOCH,
            monero_height_bucket: bucket(DEVNET_MONERO_HEIGHT, DEFAULT_PUBLIC_BUCKET_SIZE),
            ring_size: DEFAULT_TARGET_RING_SIZE,
            recovery_cohort_outputs: DEFAULT_TARGET_RECOVERY_COHORT_OUTPUTS,
            filter_bits: DEFAULT_TARGET_FILTER_BITS,
            hash_functions: DEFAULT_TARGET_HASH_FUNCTIONS,
            false_positive_bps: 12,
            redacted_ring_member_filter_root: root_from_parts(
                "devnet-redacted-jamtis-ring-member-recovery-filter",
                &[HashPart::Str(&filter_id)],
            ),
            jamtis_output_membership_root: root_from_parts(
                "devnet-jamtis-output-membership",
                &[HashPart::Str(&filter_id)],
            ),
            ring_member_commitment_root: root_from_parts(
                "devnet-jamtis-ring-member-commitment",
                &[HashPart::Str(&filter_id)],
            ),
            expires_at_monero_height: DEVNET_MONERO_HEIGHT + DEFAULT_RECOVERY_TTL_BLOCKS,
            status: RingMemberRecoveryStatus::Filtered,
        })
        .expect("devnet ring-member recovery filter inserts");
    state
        .insert_privacy_recovery_probe(PrivacyRecoveryProbe {
            probe_id: "jamtis-ring-member-private-recovery-probe-devnet-0".to_string(),
            filter_id: filter_id.clone(),
            probe_window_blocks: DEFAULT_PROBE_WINDOW_BLOCKS,
            probe_privacy_bps: 9_480,
            blinded_ring_member_query_root: root_from_parts(
                "devnet-blinded-jamtis-ring-member-recovery-query",
                &[HashPart::Str("0")],
            ),
            recovery_output_cohort_root: root_from_parts(
                "devnet-jamtis-ring-member-recovery-output-cohort",
                &[HashPart::Str(&filter_id)],
            ),
            status: RingMemberRecoveryStatus::ProbePrivate,
        })
        .expect("devnet privacy recovery probe inserts");
    state
        .insert_pq_migration_commitment(PqMigrationCommitment {
            commitment_id: "jamtis-ring-member-recovery-pq-migration-devnet-0".to_string(),
            filter_id: filter_id.clone(),
            pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            classical_fallback_disabled: true,
            migration_epoch: DEVNET_EPOCH,
            ring_member_migration_commitment_root: root_from_parts(
                "devnet-jamtis-ring-member-recovery-pq-migration",
                &[HashPart::Str(&filter_id)],
            ),
            jamtis_address_migration_commitment_root: root_from_parts(
                "devnet-jamtis-address-recovery-pq-migration",
                &[HashPart::Str(&filter_id)],
            ),
            attestation_root: root_from_parts(
                "devnet-jamtis-ring-member-recovery-pq-attestation",
                &[HashPart::Str(&filter_id)],
            ),
            status: RingMemberRecoveryStatus::Committed,
        })
        .expect("devnet PQ migration commitment inserts");
    state
        .insert_decoy_freshness_claim(DecoyFreshnessClaim {
            freshness_id: "jamtis-ring-member-decoy-freshness-devnet-0".to_string(),
            filter_id: filter_id.clone(),
            ring_size: DEFAULT_TARGET_RING_SIZE,
            decoy_freshness_bps: 9_160,
            output_age_distribution_root: root_from_parts(
                "devnet-jamtis-ring-member-output-decoy-age-distribution",
                &[HashPart::Str(&filter_id)],
            ),
            replacement_ring_member_root: root_from_parts(
                "devnet-jamtis-replacement-ring-member",
                &[HashPart::Str(&filter_id)],
            ),
            expires_at_monero_height: DEVNET_MONERO_HEIGHT + DEFAULT_RECOVERY_TTL_BLOCKS,
            status: RingMemberRecoveryStatus::Fresh,
        })
        .expect("devnet decoy freshness inserts");
    state
        .insert_low_fee_wallet_recovery_rebate(LowFeeWalletRecoveryRebate {
            rebate_id: "jamtis-ring-member-low-fee-wallet-recovery-rebate-devnet-0".to_string(),
            filter_id,
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            recovery_window_root: root_from_parts(
                "devnet-jamtis-ring-member-wallet-recovery-window",
                &[HashPart::Str("0")],
            ),
            sponsor_receipt_root: root_from_parts(
                "devnet-jamtis-ring-member-wallet-recovery-sponsor-receipt",
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
        &format!("JAMTIS-RING-MEMBER-RECOVERY-FILTER-{domain}"),
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
        &format!("JAMTIS-RING-MEMBER-RECOVERY-FILTER-{domain}"),
        &leaves,
    )
}
