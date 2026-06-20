use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateSeraphisViewtagSpendlinkShieldRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_SERAPHIS_VIEWTAG_SPENDLINK_SHIELD_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-seraphis-viewtag-spendlink-shield-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_SERAPHIS_VIEWTAG_SPENDLINK_SHIELD_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const VIEWTAG_PRIVACY_SCHEME: &str = "seraphis-jamtis-viewtag-privacy-cohort-root-v1";
pub const SPENDLINK_SHIELD_SCHEME: &str = "seraphis-spendlink-shield-score-root-v1";
pub const DECOY_REFRESH_SCHEME: &str = "ring-member-decoy-refresh-root-v1";
pub const PQ_MIGRATION_GUARDRAIL_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-seraphis-pq-migration-guardrail-root-v1";
pub const LOW_FEE_SCAN_REBATE_SCHEME: &str = "low-fee-private-seraphis-viewtag-scan-rebate-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "deterministic-public-seraphis-viewtag-spendlink-shield-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_addresses_view_keys_key_images_amounts_output_indices_or_ring_witnesses";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_050_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_730_000;
pub const DEVNET_EPOCH: u64 = 14_160;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_RING_SIZE: u16 = 16;
pub const DEFAULT_TARGET_RING_SIZE: u16 = 64;
pub const DEFAULT_MIN_COHORT_OUTPUTS: u64 = 65_536;
pub const DEFAULT_TARGET_COHORT_OUTPUTS: u64 = 262_144;
pub const DEFAULT_MIN_SHIELD_SCORE_BPS: u64 = 8_500;
pub const DEFAULT_MIN_DECOY_REFRESH_BPS: u64 = 7_500;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_SCAN_HINT_TTL_BLOCKS: u64 = 360;
pub const DEFAULT_REFRESH_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 5;
pub const DEFAULT_PUBLIC_BUCKET_SIZE: u64 = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShieldLane {
    WalletScan,
    BridgeWithdrawal,
    MerchantReceive,
    SwapSettlement,
    Watchtower,
    ReorgRepair,
}

impl ShieldLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletScan => "wallet_scan",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::MerchantReceive => "merchant_receive",
            Self::SwapSettlement => "swap_settlement",
            Self::Watchtower => "watchtower",
            Self::ReorgRepair => "reorg_repair",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShieldStatus {
    Draft,
    Open,
    Scored,
    Refreshed,
    Guarded,
    RebateEligible,
    Sealed,
    Quarantined,
    Expired,
}

impl ShieldStatus {
    pub fn public_usable(self) -> bool {
        matches!(
            self,
            Self::Scored | Self::Refreshed | Self::Guarded | Self::RebateEligible | Self::Sealed
        )
    }
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
    pub min_ring_size: u16,
    pub target_ring_size: u16,
    pub min_cohort_outputs: u64,
    pub target_cohort_outputs: u64,
    pub min_shield_score_bps: u64,
    pub min_decoy_refresh_bps: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub scan_hint_ttl_blocks: u64,
    pub refresh_ttl_blocks: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub public_bucket_size: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
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
            min_ring_size: DEFAULT_MIN_RING_SIZE,
            target_ring_size: DEFAULT_TARGET_RING_SIZE,
            min_cohort_outputs: DEFAULT_MIN_COHORT_OUTPUTS,
            target_cohort_outputs: DEFAULT_TARGET_COHORT_OUTPUTS,
            min_shield_score_bps: DEFAULT_MIN_SHIELD_SCORE_BPS,
            min_decoy_refresh_bps: DEFAULT_MIN_DECOY_REFRESH_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            scan_hint_ttl_blocks: DEFAULT_SCAN_HINT_TTL_BLOCKS,
            refresh_ttl_blocks: DEFAULT_REFRESH_TTL_BLOCKS,
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
            self.target_cohort_outputs >= self.min_cohort_outputs,
            "target cohort outputs must cover privacy floor",
        )?;
        ensure(
            self.target_pq_security_bits >= self.min_pq_security_bits,
            "target PQ security must cover minimum PQ security",
        )?;
        ensure(
            self.min_shield_score_bps <= MAX_BPS && self.min_decoy_refresh_bps <= MAX_BPS,
            "shield thresholds exceed max bps",
        )?;
        ensure(
            self.max_user_fee_bps <= MAX_BPS && self.target_rebate_bps <= self.max_user_fee_bps,
            "scan rebate fee bounds are invalid",
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
            "min_ring_size": self.min_ring_size,
            "target_ring_size": self.target_ring_size,
            "min_cohort_outputs": self.min_cohort_outputs,
            "target_cohort_outputs": self.target_cohort_outputs,
            "min_shield_score_bps": self.min_shield_score_bps,
            "min_decoy_refresh_bps": self.min_decoy_refresh_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "scan_hint_ttl_blocks": self.scan_hint_ttl_blocks,
            "refresh_ttl_blocks": self.refresh_ttl_blocks,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "public_bucket_size": self.public_bucket_size,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub viewtag_privacy_cohorts: u64,
    pub spendlink_shield_scores: u64,
    pub decoy_refreshes: u64,
    pub pq_migration_guardrails: u64,
    pub low_fee_scan_rebates: u64,
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
    pub viewtag_privacy_cohorts_root: String,
    pub spendlink_shield_scores_root: String,
    pub decoy_refreshes_root: String,
    pub pq_migration_guardrails_root: String,
    pub low_fee_scan_rebates_root: String,
    pub deterministic_state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self::empty()
    }
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            config_root: empty_root("config"),
            counters_root: empty_root("counters"),
            viewtag_privacy_cohorts_root: empty_root(VIEWTAG_PRIVACY_SCHEME),
            spendlink_shield_scores_root: empty_root(SPENDLINK_SHIELD_SCHEME),
            decoy_refreshes_root: empty_root(DECOY_REFRESH_SCHEME),
            pq_migration_guardrails_root: empty_root(PQ_MIGRATION_GUARDRAIL_SCHEME),
            low_fee_scan_rebates_root: empty_root(LOW_FEE_SCAN_REBATE_SCHEME),
            deterministic_state_root: empty_root("seraphis-viewtag-spendlink-shield-state"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn without_state_root(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "viewtag_privacy_cohorts_root": self.viewtag_privacy_cohorts_root,
            "spendlink_shield_scores_root": self.spendlink_shield_scores_root,
            "decoy_refreshes_root": self.decoy_refreshes_root,
            "pq_migration_guardrails_root": self.pq_migration_guardrails_root,
            "low_fee_scan_rebates_root": self.low_fee_scan_rebates_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewtagPrivacyCohort {
    pub cohort_id: String,
    pub lane: ShieldLane,
    pub epoch: u64,
    pub monero_height_bucket: u64,
    pub output_count_bucket: u64,
    pub viewtag_bucket_root: String,
    pub jamtis_scan_hint_root: String,
    pub seraphis_membership_root: String,
    pub status: ShieldStatus,
}

impl ViewtagPrivacyCohort {
    pub fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "lane": self.lane.as_str(),
            "epoch": self.epoch,
            "monero_height_bucket": self.monero_height_bucket,
            "output_count_bucket": self.output_count_bucket,
            "viewtag_bucket_root": self.viewtag_bucket_root,
            "jamtis_scan_hint_root": self.jamtis_scan_hint_root,
            "seraphis_membership_root": self.seraphis_membership_root,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(VIEWTAG_PRIVACY_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SpendlinkShieldScore {
    pub score_id: String,
    pub cohort_id: String,
    pub ring_size: u16,
    pub viewtag_collision_bps: u64,
    pub decoy_entropy_bps: u64,
    pub shield_score_bps: u64,
    pub linkability_risk_bucket_bps: u64,
    pub shield_transcript_root: String,
    pub status: ShieldStatus,
}

impl SpendlinkShieldScore {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(SPENDLINK_SHIELD_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RingMemberDecoyRefresh {
    pub refresh_id: String,
    pub cohort_id: String,
    pub score_id: String,
    pub ring_size: u16,
    pub refreshed_member_count_bucket: u64,
    pub decoy_refresh_bps: u64,
    pub replacement_distribution_root: String,
    pub expires_at_monero_height: u64,
    pub status: ShieldStatus,
}

impl RingMemberDecoyRefresh {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(DECOY_REFRESH_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqMigrationGuardrail {
    pub guardrail_id: String,
    pub subject_id: String,
    pub pq_security_bits: u16,
    pub classical_fallback_disabled: bool,
    pub migration_epoch: u64,
    pub attestation_root: String,
    pub status: ShieldStatus,
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
pub struct LowFeeScanRebate {
    pub rebate_id: String,
    pub cohort_id: String,
    pub fee_asset_id: String,
    pub user_fee_bps: u64,
    pub rebate_bps: u64,
    pub scan_window_root: String,
    pub sponsor_receipt_root: String,
}

impl LowFeeScanRebate {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(LOW_FEE_SCAN_REBATE_SCHEME, &self.public_record())
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
    pub counters: Counters,
    pub roots: Roots,
    pub viewtag_privacy_cohorts: BTreeMap<String, ViewtagPrivacyCohort>,
    pub spendlink_shield_scores: BTreeMap<String, SpendlinkShieldScore>,
    pub decoy_refreshes: BTreeMap<String, RingMemberDecoyRefresh>,
    pub pq_migration_guardrails: BTreeMap<String, PqMigrationGuardrail>,
    pub low_fee_scan_rebates: BTreeMap<String, LowFeeScanRebate>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(
            Config::devnet(),
            DEVNET_L2_HEIGHT,
            DEVNET_MONERO_HEIGHT,
            DEVNET_EPOCH,
        )
        .expect("default Seraphis viewtag spendlink shield config is valid")
    }
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
            counters: Counters::default(),
            roots: Roots::empty(),
            viewtag_privacy_cohorts: BTreeMap::new(),
            spendlink_shield_scores: BTreeMap::new(),
            decoy_refreshes: BTreeMap::new(),
            pq_migration_guardrails: BTreeMap::new(),
            low_fee_scan_rebates: BTreeMap::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn insert_viewtag_privacy_cohort(&mut self, cohort: ViewtagPrivacyCohort) -> Result<()> {
        ensure(
            cohort.output_count_bucket >= self.config.min_cohort_outputs,
            "viewtag privacy cohort is below output privacy floor",
        )?;
        self.viewtag_privacy_cohorts
            .insert(cohort.cohort_id.clone(), cohort);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_spendlink_shield_score(&mut self, score: SpendlinkShieldScore) -> Result<()> {
        ensure(
            self.viewtag_privacy_cohorts.contains_key(&score.cohort_id),
            "spend-link score references unknown viewtag cohort",
        )?;
        ensure(
            score.ring_size >= self.config.min_ring_size,
            "spend-link score ring size is below minimum",
        )?;
        ensure(
            score.shield_score_bps >= self.config.min_shield_score_bps,
            "spend-link shield score is below privacy floor",
        )?;
        self.spendlink_shield_scores
            .insert(score.score_id.clone(), score);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_decoy_refresh(&mut self, refresh: RingMemberDecoyRefresh) -> Result<()> {
        ensure(
            self.spendlink_shield_scores.contains_key(&refresh.score_id),
            "decoy refresh references unknown spend-link score",
        )?;
        ensure(
            refresh.decoy_refresh_bps >= self.config.min_decoy_refresh_bps,
            "decoy refresh score is below privacy floor",
        )?;
        self.decoy_refreshes
            .insert(refresh.refresh_id.clone(), refresh);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_pq_migration_guardrail(&mut self, guardrail: PqMigrationGuardrail) -> Result<()> {
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

    pub fn insert_low_fee_scan_rebate(&mut self, rebate: LowFeeScanRebate) -> Result<()> {
        ensure(
            self.viewtag_privacy_cohorts.contains_key(&rebate.cohort_id),
            "scan rebate references unknown viewtag cohort",
        )?;
        ensure(
            rebate.user_fee_bps <= self.config.max_user_fee_bps,
            "scan rebate user fee exceeds low-fee cap",
        )?;
        ensure(
            rebate.rebate_bps <= rebate.user_fee_bps,
            "scan rebate exceeds charged fee",
        )?;
        self.low_fee_scan_rebates
            .insert(rebate.rebate_id.clone(), rebate);
        self.refresh_roots();
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "runtime": "monero_l2_pq_private_seraphis_viewtag_spendlink_shield_runtime",
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

    pub fn refresh_roots(&mut self) {
        self.counters.viewtag_privacy_cohorts = self.viewtag_privacy_cohorts.len() as u64;
        self.counters.spendlink_shield_scores = self.spendlink_shield_scores.len() as u64;
        self.counters.decoy_refreshes = self.decoy_refreshes.len() as u64;
        self.counters.pq_migration_guardrails = self.pq_migration_guardrails.len() as u64;
        self.counters.low_fee_scan_rebates = self.low_fee_scan_rebates.len() as u64;

        self.roots.config_root = self.config.state_root();
        self.roots.counters_root = self.counters.state_root();
        self.roots.viewtag_privacy_cohorts_root = map_root(
            VIEWTAG_PRIVACY_SCHEME,
            self.viewtag_privacy_cohorts
                .iter()
                .map(|(id, cohort)| (id.as_str(), cohort.state_root())),
        );
        self.roots.spendlink_shield_scores_root = map_root(
            SPENDLINK_SHIELD_SCHEME,
            self.spendlink_shield_scores
                .iter()
                .map(|(id, score)| (id.as_str(), score.state_root())),
        );
        self.roots.decoy_refreshes_root = map_root(
            DECOY_REFRESH_SCHEME,
            self.decoy_refreshes
                .iter()
                .map(|(id, refresh)| (id.as_str(), refresh.state_root())),
        );
        self.roots.pq_migration_guardrails_root = map_root(
            PQ_MIGRATION_GUARDRAIL_SCHEME,
            self.pq_migration_guardrails
                .iter()
                .map(|(id, guardrail)| (id.as_str(), guardrail.state_root())),
        );
        self.roots.low_fee_scan_rebates_root = map_root(
            LOW_FEE_SCAN_REBATE_SCHEME,
            self.low_fee_scan_rebates
                .iter()
                .map(|(id, rebate)| (id.as_str(), rebate.state_root())),
        );
        self.roots.deterministic_state_root = self.state_root_without_cached_root();
    }

    fn state_root_without_cached_root(&self) -> String {
        root_from_parts(
            "seraphis-viewtag-spendlink-shield-state",
            &[
                HashPart::Str(&self.protocol_version),
                HashPart::Str(&self.chain_id),
                HashPart::Str(&self.config.state_root()),
                HashPart::U64(self.l2_height),
                HashPart::U64(self.monero_height),
                HashPart::U64(self.epoch),
                HashPart::Str(&self.counters.state_root()),
                HashPart::Json(&self.roots.without_state_root()),
            ],
        )
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let cohort_id = "seraphis-viewtag-shield-cohort-devnet-0".to_string();
    let score_id = "seraphis-spendlink-shield-score-devnet-0".to_string();
    let refresh_id = "seraphis-decoy-refresh-devnet-0".to_string();

    state
        .insert_viewtag_privacy_cohort(ViewtagPrivacyCohort {
            cohort_id: cohort_id.clone(),
            lane: ShieldLane::BridgeWithdrawal,
            epoch: DEVNET_EPOCH,
            monero_height_bucket: bucket(DEVNET_MONERO_HEIGHT, DEFAULT_PUBLIC_BUCKET_SIZE),
            output_count_bucket: DEFAULT_TARGET_COHORT_OUTPUTS,
            viewtag_bucket_root: root_from_parts("devnet-viewtag-bucket", &[HashPart::Str("0")]),
            jamtis_scan_hint_root: root_from_parts(
                "devnet-jamtis-scan-hint",
                &[HashPart::Str("0")],
            ),
            seraphis_membership_root: root_from_parts(
                "devnet-seraphis-membership",
                &[HashPart::Str(&cohort_id)],
            ),
            status: ShieldStatus::Open,
        })
        .expect("devnet viewtag cohort inserts");
    state
        .insert_spendlink_shield_score(SpendlinkShieldScore {
            score_id: score_id.clone(),
            cohort_id: cohort_id.clone(),
            ring_size: DEFAULT_TARGET_RING_SIZE,
            viewtag_collision_bps: 96,
            decoy_entropy_bps: 9_320,
            shield_score_bps: shield_score(96, 9_320, DEFAULT_TARGET_RING_SIZE),
            linkability_risk_bucket_bps: 512,
            shield_transcript_root: root_from_parts(
                "devnet-shield-transcript",
                &[HashPart::Str(&score_id)],
            ),
            status: ShieldStatus::Scored,
        })
        .expect("devnet spend-link score inserts");
    state
        .insert_decoy_refresh(RingMemberDecoyRefresh {
            refresh_id: refresh_id.clone(),
            cohort_id: cohort_id.clone(),
            score_id: score_id.clone(),
            ring_size: DEFAULT_TARGET_RING_SIZE,
            refreshed_member_count_bucket: 16_384,
            decoy_refresh_bps: 8_720,
            replacement_distribution_root: root_from_parts(
                "devnet-replacement-distribution",
                &[HashPart::Str(&refresh_id)],
            ),
            expires_at_monero_height: DEVNET_MONERO_HEIGHT + DEFAULT_REFRESH_TTL_BLOCKS,
            status: ShieldStatus::Refreshed,
        })
        .expect("devnet decoy refresh inserts");
    state
        .insert_pq_migration_guardrail(PqMigrationGuardrail {
            guardrail_id: "seraphis-pq-migration-guardrail-devnet-0".to_string(),
            subject_id: score_id,
            pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            classical_fallback_disabled: true,
            migration_epoch: DEVNET_EPOCH,
            attestation_root: root_from_parts("devnet-pq-guardrail", &[HashPart::Str("0")]),
            status: ShieldStatus::Guarded,
        })
        .expect("devnet PQ guardrail inserts");
    state
        .insert_low_fee_scan_rebate(LowFeeScanRebate {
            rebate_id: "seraphis-low-fee-scan-rebate-devnet-0".to_string(),
            cohort_id,
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            scan_window_root: root_from_parts("devnet-scan-window", &[HashPart::Str("0")]),
            sponsor_receipt_root: root_from_parts(
                "devnet-scan-sponsor-receipt",
                &[HashPart::Str("0")],
            ),
        })
        .expect("devnet scan rebate inserts");
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

fn shield_score(viewtag_collision_bps: u64, decoy_entropy_bps: u64, ring_size: u16) -> u64 {
    let ring_component = (ring_size as u64)
        .saturating_mul(MAX_BPS)
        .saturating_div(DEFAULT_TARGET_RING_SIZE as u64)
        .min(MAX_BPS);
    let collision_penalty = viewtag_collision_bps.min(MAX_BPS);
    decoy_entropy_bps
        .saturating_mul(70)
        .saturating_add(ring_component.saturating_mul(30))
        .saturating_div(100)
        .saturating_sub(collision_penalty / 2)
        .min(MAX_BPS)
}

fn empty_root(domain: &str) -> String {
    root_from_parts(domain, &[HashPart::Str("empty")])
}

fn root_from_record(domain: &str, record: &Value) -> String {
    root_from_parts(domain, &[HashPart::Json(record)])
}

fn root_from_parts(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("SERAPHIS-VIEWTAG-SPENDLINK-SHIELD-{domain}"),
        parts,
        32,
    )
}

fn map_root<'a>(domain: &str, entries: impl Iterator<Item = (&'a str, String)>) -> String {
    let leaves = entries
        .map(|(id, root)| json!({ "id": id, "root": root }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("SERAPHIS-VIEWTAG-SPENDLINK-SHIELD-{domain}"),
        &leaves,
    )
}
