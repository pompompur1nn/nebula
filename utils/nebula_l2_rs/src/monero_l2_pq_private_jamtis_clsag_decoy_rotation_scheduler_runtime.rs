use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{
        domain_hash as raw_domain_hash, merkle_root as raw_merkle_root, HashPart as RawHashPart,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateJamtisClsagDecoyRotationSchedulerRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum HashPart {
    Str(String),
    U64(u64),
}

impl HashPart {
    fn from<T: Into<Self>>(value: T) -> Self {
        value.into()
    }
}

impl From<&str> for HashPart {
    fn from(value: &str) -> Self {
        Self::Str(value.to_string())
    }
}

impl From<String> for HashPart {
    fn from(value: String) -> Self {
        Self::Str(value)
    }
}

impl From<u64> for HashPart {
    fn from(value: u64) -> Self {
        Self::U64(value)
    }
}

fn domain_hash<const N: usize>(domain: &str, parts: [HashPart; N]) -> String {
    let raw_parts = parts
        .iter()
        .map(|part| match part {
            HashPart::Str(value) => RawHashPart::Str(value.as_str()),
            HashPart::U64(value) => RawHashPart::U64(*value),
        })
        .collect::<Vec<_>>();
    raw_domain_hash(domain, &raw_parts, 32)
}

fn merkle_root(domain: &str, leaves: Vec<String>) -> String {
    let values = leaves.into_iter().map(Value::String).collect::<Vec<_>>();
    raw_merkle_root(domain, &values)
}

pub const MONERO_L2_PQ_PRIVATE_JAMTIS_CLSAG_DECOY_ROTATION_SCHEDULER_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-private-jamtis-clsag-decoy-rotation-scheduler-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_JAMTIS_CLSAG_DECOY_ROTATION_SCHEDULER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-jamtis-clsag-decoy-rotation-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_SCHEDULER_ID: &str =
    "monero-l2-pq-private-jamtis-clsag-decoy-rotation-scheduler-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_MONERO_HEIGHT: u64 = 3_720_960;
pub const DEVNET_L2_HEIGHT: u64 = 2_980_224;
pub const DEVNET_EPOCH: u64 = 16_384;
pub const JAMTIS_COHORT_SCHEME: &str = "monero-l2-jamtis-viewtag-cohort-rotation-root-v1";
pub const CLSAG_ROTATION_SCHEME: &str = "monero-l2-clsag-decoy-rotation-root-v1";
pub const ROTATION_SCHEDULE_SCHEME: &str = "low-fee-clsag-decoy-rotation-schedule-root-v1";
pub const PQ_DECOY_ATTESTATION_SCHEME: &str = "pq-decoy-rotation-attestation-root-v1";
pub const WALLET_SCAN_HINT_SCHEME: &str = "jamtis-wallet-scan-hint-root-v1";
pub const DECOY_FRESHNESS_FLOOR_SCHEME: &str = "clsag-decoy-freshness-floor-root-v1";
pub const FEE_REBATE_SCHEME: &str = "low-fee-decoy-rotation-rebate-root-v1";
pub const PRIVACY_REDACTION_BUDGET_SCHEME: &str =
    "operator-safe-jamtis-clsag-rotation-redaction-budget-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str = "roots-only-jamtis-clsag-operator-summary-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str = "public-jamtis-clsag-decoy-rotation-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_addresses_view_keys_key_images_amounts_ring_indices_or_decoy_edges";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_RING_SIZE: u16 = 16;
pub const DEFAULT_TARGET_RING_SIZE: u16 = 48;
pub const DEFAULT_MIN_COHORT_OUTPUTS: u64 = 65_536;
pub const DEFAULT_TARGET_COHORT_OUTPUTS: u64 = 262_144;
pub const DEFAULT_MIN_VIEWTAG_ENTROPY_BPS: u64 = 8_900;
pub const DEFAULT_MIN_DECOY_FRESHNESS_BPS: u64 = 8_400;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_ROTATION_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_SCHEDULE_TTL_BLOCKS: u64 = 360;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_SCAN_HINT_TTL_BLOCKS: u64 = 240;
pub const DEFAULT_REORG_HOLD_BLOCKS: u64 = 36;
pub const DEFAULT_MAX_ROTATIONS_PER_SCHEDULE: u32 = 512;
pub const DEFAULT_MAX_USER_FEE_MICRO_UNITS: u64 = 1_200;
pub const DEFAULT_BACKGROUND_FEE_MICRO_UNITS: u64 = 480;
pub const DEFAULT_EXPRESS_FEE_MICRO_UNITS: u64 = 1_800;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 1_700;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_200;
pub const DEFAULT_OPERATOR_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_DAILY_LINKABILITY_BUDGET: u64 = 64;
pub const DEFAULT_EPOCH_REDACTION_BUDGET: u64 = 16;
pub const DEFAULT_MAX_HINT_BYTES: u32 = 8_192;
pub const MAX_JAMTIS_COHORTS: usize = 1_048_576;
pub const MAX_CLSAG_ROTATIONS: usize = 2_097_152;
pub const MAX_ROTATION_SCHEDULES: usize = 1_048_576;
pub const MAX_PQ_DECOY_ATTESTATIONS: usize = 4_194_304;
pub const MAX_WALLET_SCAN_HINTS: usize = 4_194_304;
pub const MAX_DECOY_FRESHNESS_FLOORS: usize = 1_048_576;
pub const MAX_FEE_REBATES: usize = 2_097_152;
pub const MAX_PRIVACY_REDACTION_BUDGETS: usize = 1_048_576;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const MAX_PUBLIC_RECORDS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    Devnet,
    Canary,
    MainnetCandidate,
}

impl RuntimeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::Canary => "canary",
            Self::MainnetCandidate => "mainnet_candidate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationLane {
    BackgroundWallet,
    ForegroundWallet,
    BridgeWithdrawal,
    MerchantPayment,
    DexSettlement,
    LiquidityRebalance,
    EmergencyRecovery,
    WatchOnlyAudit,
}

impl RotationLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BackgroundWallet => "background_wallet",
            Self::ForegroundWallet => "foreground_wallet",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::MerchantPayment => "merchant_payment",
            Self::DexSettlement => "dex_settlement",
            Self::LiquidityRebalance => "liquidity_rebalance",
            Self::EmergencyRecovery => "emergency_recovery",
            Self::WatchOnlyAudit => "watch_only_audit",
        }
    }

    pub fn privacy_weight(self) -> u64 {
        match self {
            Self::EmergencyRecovery => 1_000,
            Self::BridgeWithdrawal => 960,
            Self::DexSettlement => 900,
            Self::LiquidityRebalance => 860,
            Self::ForegroundWallet => 820,
            Self::MerchantPayment => 780,
            Self::WatchOnlyAudit => 720,
            Self::BackgroundWallet => 680,
        }
    }

    pub fn fee_cap(self, config: &Config) -> u64 {
        match self {
            Self::BackgroundWallet | Self::WatchOnlyAudit => config.background_fee_micro_units,
            Self::EmergencyRecovery | Self::BridgeWithdrawal => config.express_fee_micro_units,
            _ => config.max_user_fee_micro_units,
        }
    }

    pub fn min_ring_size(self, config: &Config) -> u16 {
        match self {
            Self::EmergencyRecovery | Self::BridgeWithdrawal => {
                config.target_ring_size.max(config.min_ring_size)
            }
            Self::DexSettlement | Self::LiquidityRebalance => {
                config.min_ring_size.saturating_add(16)
            }
            _ => config.min_ring_size,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JamtisCohortStatus {
    Draft,
    Sampling,
    Eligible,
    Rotating,
    Settled,
    ReorgHeld,
    Quarantined,
    Expired,
}

impl JamtisCohortStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Sampling => "sampling",
            Self::Eligible => "eligible",
            Self::Rotating => "rotating",
            Self::Settled => "settled",
            Self::ReorgHeld => "reorg_held",
            Self::Quarantined => "quarantined",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Sampling | Self::Eligible | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationStatus {
    Draft,
    Scheduled,
    Attested,
    Published,
    ReorgHeld,
    Settled,
    Quarantined,
    Expired,
}

impl RotationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Scheduled => "scheduled",
            Self::Attested => "attested",
            Self::Published => "published",
            Self::ReorgHeld => "reorg_held",
            Self::Settled => "settled",
            Self::Quarantined => "quarantined",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Scheduled | Self::Attested | Self::Published)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleStatus {
    Draft,
    Open,
    Filling,
    Attested,
    Published,
    Settled,
    Paused,
    Expired,
}

impl ScheduleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::Filling => "filling",
            Self::Attested => "attested",
            Self::Published => "published",
            Self::Settled => "settled",
            Self::Paused => "paused",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_rotations(self) -> bool {
        matches!(self, Self::Open | Self::Filling | Self::Attested)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Quorum,
    Superseded,
    Revoked,
    Expired,
    Rejected,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Quorum => "quorum",
            Self::Superseded => "superseded",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Accepted | Self::Quorum)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanHintStatus {
    Draft,
    Published,
    Consumed,
    Rebated,
    Superseded,
    Expired,
}

impl ScanHintStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Published => "published",
            Self::Consumed => "consumed",
            Self::Rebated => "rebated",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessStatus {
    Candidate,
    Fresh,
    Aging,
    Stale,
    Quarantined,
    ReorgHeld,
}

impl FreshnessStatus {
    pub fn selectable(self) -> bool {
        matches!(self, Self::Candidate | Self::Fresh | Self::Aging)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accruing,
    Claimable,
    Claimed,
    Expired,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionClass {
    PublicAggregate,
    CohortRoot,
    ScheduleRoot,
    AttestationRoot,
    OperatorOnly,
}

impl RedactionClass {
    pub fn units(self) -> u64 {
        match self {
            Self::PublicAggregate => 1,
            Self::CohortRoot => 2,
            Self::ScheduleRoot => 3,
            Self::AttestationRoot => 5,
            Self::OperatorOnly => 8,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub mode: RuntimeMode,
    pub l2_network: String,
    pub monero_network: String,
    pub scheduler_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub min_ring_size: u16,
    pub target_ring_size: u16,
    pub min_cohort_outputs: u64,
    pub target_cohort_outputs: u64,
    pub min_viewtag_entropy_bps: u64,
    pub min_decoy_freshness_bps: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub rotation_window_blocks: u64,
    pub schedule_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub scan_hint_ttl_blocks: u64,
    pub reorg_hold_blocks: u64,
    pub max_rotations_per_schedule: u32,
    pub max_user_fee_micro_units: u64,
    pub background_fee_micro_units: u64,
    pub express_fee_micro_units: u64,
    pub low_fee_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub operator_quorum_bps: u64,
    pub daily_linkability_budget: u64,
    pub epoch_redaction_budget: u64,
    pub max_hint_bytes: u32,
    pub max_jamtis_cohorts: usize,
    pub max_clsag_rotations: usize,
    pub max_rotation_schedules: usize,
    pub max_pq_decoy_attestations: usize,
    pub max_wallet_scan_hints: usize,
    pub max_decoy_freshness_floors: usize,
    pub max_fee_rebates: usize,
    pub max_privacy_redaction_budgets: usize,
    pub max_operator_summaries: usize,
    pub max_public_records: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            mode: RuntimeMode::Devnet,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            scheduler_id: DEVNET_SCHEDULER_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            min_ring_size: DEFAULT_MIN_RING_SIZE,
            target_ring_size: DEFAULT_TARGET_RING_SIZE,
            min_cohort_outputs: DEFAULT_MIN_COHORT_OUTPUTS,
            target_cohort_outputs: DEFAULT_TARGET_COHORT_OUTPUTS,
            min_viewtag_entropy_bps: DEFAULT_MIN_VIEWTAG_ENTROPY_BPS,
            min_decoy_freshness_bps: DEFAULT_MIN_DECOY_FRESHNESS_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            rotation_window_blocks: DEFAULT_ROTATION_WINDOW_BLOCKS,
            schedule_ttl_blocks: DEFAULT_SCHEDULE_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            scan_hint_ttl_blocks: DEFAULT_SCAN_HINT_TTL_BLOCKS,
            reorg_hold_blocks: DEFAULT_REORG_HOLD_BLOCKS,
            max_rotations_per_schedule: DEFAULT_MAX_ROTATIONS_PER_SCHEDULE,
            max_user_fee_micro_units: DEFAULT_MAX_USER_FEE_MICRO_UNITS,
            background_fee_micro_units: DEFAULT_BACKGROUND_FEE_MICRO_UNITS,
            express_fee_micro_units: DEFAULT_EXPRESS_FEE_MICRO_UNITS,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            operator_quorum_bps: DEFAULT_OPERATOR_QUORUM_BPS,
            daily_linkability_budget: DEFAULT_DAILY_LINKABILITY_BUDGET,
            epoch_redaction_budget: DEFAULT_EPOCH_REDACTION_BUDGET,
            max_hint_bytes: DEFAULT_MAX_HINT_BYTES,
            max_jamtis_cohorts: MAX_JAMTIS_COHORTS,
            max_clsag_rotations: MAX_CLSAG_ROTATIONS,
            max_rotation_schedules: MAX_ROTATION_SCHEDULES,
            max_pq_decoy_attestations: MAX_PQ_DECOY_ATTESTATIONS,
            max_wallet_scan_hints: MAX_WALLET_SCAN_HINTS,
            max_decoy_freshness_floors: MAX_DECOY_FRESHNESS_FLOORS,
            max_fee_rebates: MAX_FEE_REBATES,
            max_privacy_redaction_budgets: MAX_PRIVACY_REDACTION_BUDGETS,
            max_operator_summaries: MAX_OPERATOR_SUMMARIES,
            max_public_records: MAX_PUBLIC_RECORDS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch"
        );
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "schema version mismatch"
        );
        ensure!(
            self.min_ring_size >= 11,
            "ring size below Monero-compatible floor"
        );
        ensure!(
            self.target_ring_size >= self.min_ring_size,
            "target ring size below minimum"
        );
        ensure!(
            self.min_cohort_outputs > 0,
            "minimum cohort output count is zero"
        );
        ensure!(
            self.target_cohort_outputs >= self.min_cohort_outputs,
            "target cohort output count below minimum"
        );
        ensure!(
            self.min_viewtag_entropy_bps <= MAX_BPS,
            "viewtag entropy bps overflow"
        );
        ensure!(
            self.min_decoy_freshness_bps <= MAX_BPS,
            "decoy freshness bps overflow"
        );
        ensure!(
            self.min_pq_security_bits >= 128,
            "post-quantum security bits below acceptable floor"
        );
        ensure!(
            self.target_pq_security_bits >= self.min_pq_security_bits,
            "target pq security below minimum"
        );
        ensure!(self.rotation_window_blocks > 0, "rotation window is zero");
        ensure!(self.schedule_ttl_blocks > 0, "schedule ttl is zero");
        ensure!(self.attestation_ttl_blocks > 0, "attestation ttl is zero");
        ensure!(self.scan_hint_ttl_blocks > 0, "scan hint ttl is zero");
        ensure!(self.low_fee_rebate_bps <= MAX_BPS, "rebate bps overflow");
        ensure!(
            self.sponsor_cover_bps <= MAX_BPS,
            "sponsor cover bps overflow"
        );
        ensure!(
            self.operator_quorum_bps <= MAX_BPS,
            "operator quorum bps overflow"
        );
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub jamtis_cohorts: u64,
    pub clsag_rotations: u64,
    pub rotation_schedules: u64,
    pub pq_decoy_attestations: u64,
    pub wallet_scan_hints: u64,
    pub decoy_freshness_floors: u64,
    pub fee_rebates: u64,
    pub privacy_redaction_budgets: u64,
    pub operator_summaries: u64,
    pub public_records: u64,
    pub accepted_attestations: u64,
    pub settled_rotations: u64,
    pub quarantined_rotations: u64,
    pub total_rebate_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "jamtis_cohorts": self.jamtis_cohorts,
            "clsag_rotations": self.clsag_rotations,
            "rotation_schedules": self.rotation_schedules,
            "pq_decoy_attestations": self.pq_decoy_attestations,
            "wallet_scan_hints": self.wallet_scan_hints,
            "decoy_freshness_floors": self.decoy_freshness_floors,
            "fee_rebates": self.fee_rebates,
            "privacy_redaction_budgets": self.privacy_redaction_budgets,
            "operator_summaries": self.operator_summaries,
            "public_records": self.public_records,
            "accepted_attestations": self.accepted_attestations,
            "settled_rotations": self.settled_rotations,
            "quarantined_rotations": self.quarantined_rotations,
            "total_rebate_micro_units": self.total_rebate_micro_units
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub jamtis_cohorts_root: String,
    pub clsag_rotations_root: String,
    pub rotation_schedules_root: String,
    pub pq_decoy_attestations_root: String,
    pub wallet_scan_hints_root: String,
    pub decoy_freshness_floors_root: String,
    pub fee_rebates_root: String,
    pub privacy_redaction_budgets_root: String,
    pub operator_summaries_root: String,
    pub public_records_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "jamtis_cohorts_root": self.jamtis_cohorts_root,
            "clsag_rotations_root": self.clsag_rotations_root,
            "rotation_schedules_root": self.rotation_schedules_root,
            "pq_decoy_attestations_root": self.pq_decoy_attestations_root,
            "wallet_scan_hints_root": self.wallet_scan_hints_root,
            "decoy_freshness_floors_root": self.decoy_freshness_floors_root,
            "fee_rebates_root": self.fee_rebates_root,
            "privacy_redaction_budgets_root": self.privacy_redaction_budgets_root,
            "operator_summaries_root": self.operator_summaries_root,
            "public_records_root": self.public_records_root,
            "state_root": self.state_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JamtisViewtagCohort {
    pub cohort_id: String,
    pub lane: RotationLane,
    pub status: JamtisCohortStatus,
    pub epoch: u64,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
    pub viewtag_prefix_root: String,
    pub encrypted_scan_domain_root: String,
    pub output_count: u64,
    pub unique_viewtag_count: u64,
    pub collision_count: u64,
    pub entropy_bps: u64,
    pub min_decoy_age_blocks: u64,
    pub max_decoy_age_blocks: u64,
    pub pq_commitment_root: String,
    pub schedule_ids: BTreeSet<String>,
    pub created_at_l2_height: u64,
    pub updated_at_l2_height: u64,
}

impl JamtisViewtagCohort {
    pub fn new(
        cohort_id: impl Into<String>,
        lane: RotationLane,
        epoch: u64,
        monero_start_height: u64,
        monero_end_height: u64,
        output_count: u64,
    ) -> Self {
        let cohort_id = cohort_id.into();
        Self {
            viewtag_prefix_root: domain_hash(
                JAMTIS_COHORT_SCHEME,
                [
                    HashPart::from(cohort_id.as_str()),
                    HashPart::from(lane.as_str()),
                    HashPart::from(epoch),
                    HashPart::from("viewtag-prefixes"),
                ],
            ),
            encrypted_scan_domain_root: domain_hash(
                JAMTIS_COHORT_SCHEME,
                [
                    HashPart::from(cohort_id.as_str()),
                    HashPart::from(epoch),
                    HashPart::from("scan-domain"),
                ],
            ),
            pq_commitment_root: domain_hash(
                JAMTIS_COHORT_SCHEME,
                [
                    HashPart::from(cohort_id.as_str()),
                    HashPart::from(epoch),
                    HashPart::from("pq-commitments"),
                ],
            ),
            cohort_id,
            lane,
            status: JamtisCohortStatus::Draft,
            epoch,
            monero_start_height,
            monero_end_height,
            output_count,
            unique_viewtag_count: output_count.min(256),
            collision_count: 0,
            entropy_bps: 0,
            min_decoy_age_blocks: 0,
            max_decoy_age_blocks: monero_end_height.saturating_sub(monero_start_height),
            schedule_ids: BTreeSet::new(),
            created_at_l2_height: DEVNET_L2_HEIGHT,
            updated_at_l2_height: DEVNET_L2_HEIGHT,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.cohort_id.is_empty(), "cohort id is empty");
        ensure!(
            self.monero_end_height >= self.monero_start_height,
            "cohort end height before start"
        );
        ensure!(
            self.output_count >= config.min_cohort_outputs,
            "cohort {} has {} outputs below minimum {}",
            self.cohort_id,
            self.output_count,
            config.min_cohort_outputs
        );
        ensure!(self.entropy_bps <= MAX_BPS, "cohort entropy bps overflow");
        if self.status.live() {
            ensure!(
                self.entropy_bps >= config.min_viewtag_entropy_bps,
                "cohort {} below viewtag entropy floor",
                self.cohort_id
            );
        }
        Ok(())
    }

    pub fn seal(mut self, entropy_bps: u64, unique_viewtag_count: u64) -> Self {
        self.status = JamtisCohortStatus::Eligible;
        self.entropy_bps = entropy_bps.min(MAX_BPS);
        self.unique_viewtag_count = unique_viewtag_count;
        self.updated_at_l2_height = self.updated_at_l2_height.saturating_add(1);
        self
    }

    pub fn attach_schedule(&mut self, schedule_id: impl Into<String>, l2_height: u64) {
        self.schedule_ids.insert(schedule_id.into());
        self.status = JamtisCohortStatus::Rotating;
        self.updated_at_l2_height = l2_height;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "epoch": self.epoch,
            "monero_start_height": self.monero_start_height,
            "monero_end_height": self.monero_end_height,
            "viewtag_prefix_root": self.viewtag_prefix_root,
            "encrypted_scan_domain_root": self.encrypted_scan_domain_root,
            "output_count": self.output_count,
            "unique_viewtag_count": self.unique_viewtag_count,
            "collision_count": self.collision_count,
            "entropy_bps": self.entropy_bps,
            "min_decoy_age_blocks": self.min_decoy_age_blocks,
            "max_decoy_age_blocks": self.max_decoy_age_blocks,
            "pq_commitment_root": self.pq_commitment_root,
            "schedule_count": self.schedule_ids.len() as u64,
            "created_at_l2_height": self.created_at_l2_height,
            "updated_at_l2_height": self.updated_at_l2_height
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            JAMTIS_COHORT_SCHEME,
            [
                HashPart::from(self.cohort_id.as_str()),
                HashPart::from(self.lane.as_str()),
                HashPart::from(self.status.as_str()),
                HashPart::from(self.epoch),
                HashPart::from(self.monero_start_height),
                HashPart::from(self.monero_end_height),
                HashPart::from(self.viewtag_prefix_root.as_str()),
                HashPart::from(self.encrypted_scan_domain_root.as_str()),
                HashPart::from(self.output_count),
                HashPart::from(self.unique_viewtag_count),
                HashPart::from(self.collision_count),
                HashPart::from(self.entropy_bps),
                HashPart::from(self.pq_commitment_root.as_str()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClsagDecoyRotation {
    pub rotation_id: String,
    pub cohort_id: String,
    pub schedule_id: String,
    pub lane: RotationLane,
    pub status: RotationStatus,
    pub ring_size: u16,
    pub decoy_count: u16,
    pub real_spend_redacted: bool,
    pub ring_member_root: String,
    pub decoy_age_histogram_root: String,
    pub key_image_domain_root: String,
    pub linkability_budget_units: u64,
    pub fee_micro_units: u64,
    pub rebate_micro_units: u64,
    pub freshness_floor_id: String,
    pub attestation_ids: BTreeSet<String>,
    pub hint_ids: BTreeSet<String>,
    pub created_at_monero_height: u64,
    pub publish_after_l2_height: u64,
    pub expires_at_l2_height: u64,
}

impl ClsagDecoyRotation {
    pub fn new(
        rotation_id: impl Into<String>,
        cohort_id: impl Into<String>,
        schedule_id: impl Into<String>,
        lane: RotationLane,
        config: &Config,
        created_at_monero_height: u64,
        publish_after_l2_height: u64,
    ) -> Self {
        let rotation_id = rotation_id.into();
        let cohort_id = cohort_id.into();
        let schedule_id = schedule_id.into();
        let ring_size = lane.min_ring_size(config);
        let decoy_count = ring_size.saturating_sub(1);
        Self {
            ring_member_root: domain_hash(
                CLSAG_ROTATION_SCHEME,
                [
                    HashPart::from(rotation_id.as_str()),
                    HashPart::from(cohort_id.as_str()),
                    HashPart::from(schedule_id.as_str()),
                    HashPart::from("ring-members"),
                ],
            ),
            decoy_age_histogram_root: domain_hash(
                CLSAG_ROTATION_SCHEME,
                [
                    HashPart::from(rotation_id.as_str()),
                    HashPart::from(cohort_id.as_str()),
                    HashPart::from("decoy-age-histogram"),
                ],
            ),
            key_image_domain_root: domain_hash(
                CLSAG_ROTATION_SCHEME,
                [
                    HashPart::from(rotation_id.as_str()),
                    HashPart::from("redacted-key-image-domain"),
                ],
            ),
            expires_at_l2_height: publish_after_l2_height
                .saturating_add(config.schedule_ttl_blocks),
            rotation_id,
            cohort_id,
            schedule_id,
            lane,
            status: RotationStatus::Draft,
            ring_size,
            decoy_count,
            real_spend_redacted: true,
            linkability_budget_units: lane.privacy_weight() / 100,
            fee_micro_units: lane.fee_cap(config),
            rebate_micro_units: 0,
            freshness_floor_id: String::new(),
            attestation_ids: BTreeSet::new(),
            hint_ids: BTreeSet::new(),
            created_at_monero_height,
            publish_after_l2_height,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.rotation_id.is_empty(), "rotation id is empty");
        ensure!(!self.cohort_id.is_empty(), "rotation cohort id is empty");
        ensure!(
            !self.schedule_id.is_empty(),
            "rotation schedule id is empty"
        );
        ensure!(self.real_spend_redacted, "rotation leaks real spend marker");
        ensure!(
            self.ring_size >= self.lane.min_ring_size(config),
            "rotation {} ring size below lane floor",
            self.rotation_id
        );
        ensure!(
            self.decoy_count == self.ring_size.saturating_sub(1),
            "rotation {} decoy count does not match ring size",
            self.rotation_id
        );
        ensure!(
            self.fee_micro_units <= self.lane.fee_cap(config),
            "rotation {} fee above lane cap",
            self.rotation_id
        );
        ensure!(
            self.expires_at_l2_height >= self.publish_after_l2_height,
            "rotation {} expires before publish height",
            self.rotation_id
        );
        Ok(())
    }

    pub fn schedule(mut self, freshness_floor_id: impl Into<String>) -> Self {
        self.status = RotationStatus::Scheduled;
        self.freshness_floor_id = freshness_floor_id.into();
        self
    }

    pub fn attach_attestation(&mut self, attestation_id: impl Into<String>) {
        self.attestation_ids.insert(attestation_id.into());
        if matches!(self.status, RotationStatus::Scheduled) {
            self.status = RotationStatus::Attested;
        }
    }

    pub fn attach_hint(&mut self, hint_id: impl Into<String>) {
        self.hint_ids.insert(hint_id.into());
    }

    pub fn apply_rebate(&mut self, rebate_micro_units: u64) {
        self.rebate_micro_units = rebate_micro_units.min(self.fee_micro_units);
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rotation_id": self.rotation_id,
            "cohort_id": self.cohort_id,
            "schedule_id": self.schedule_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "ring_size": self.ring_size,
            "decoy_count": self.decoy_count,
            "real_spend_redacted": self.real_spend_redacted,
            "ring_member_root": self.ring_member_root,
            "decoy_age_histogram_root": self.decoy_age_histogram_root,
            "key_image_domain_root": self.key_image_domain_root,
            "linkability_budget_units": self.linkability_budget_units,
            "fee_micro_units": self.fee_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "freshness_floor_id": self.freshness_floor_id,
            "attestation_count": self.attestation_ids.len() as u64,
            "hint_count": self.hint_ids.len() as u64,
            "created_at_monero_height": self.created_at_monero_height,
            "publish_after_l2_height": self.publish_after_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            CLSAG_ROTATION_SCHEME,
            [
                HashPart::from(self.rotation_id.as_str()),
                HashPart::from(self.cohort_id.as_str()),
                HashPart::from(self.schedule_id.as_str()),
                HashPart::from(self.lane.as_str()),
                HashPart::from(self.status.as_str()),
                HashPart::from(self.ring_size as u64),
                HashPart::from(self.decoy_count as u64),
                HashPart::from(self.ring_member_root.as_str()),
                HashPart::from(self.decoy_age_histogram_root.as_str()),
                HashPart::from(self.key_image_domain_root.as_str()),
                HashPart::from(self.fee_micro_units),
                HashPart::from(self.rebate_micro_units),
                HashPart::from(self.freshness_floor_id.as_str()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RotationSchedule {
    pub schedule_id: String,
    pub lane: RotationLane,
    pub status: ScheduleStatus,
    pub epoch: u64,
    pub cohort_ids: BTreeSet<String>,
    pub rotation_ids: BTreeSet<String>,
    pub target_rotation_count: u32,
    pub min_ring_size: u16,
    pub target_fee_micro_units: u64,
    pub privacy_score_bps: u64,
    pub pq_security_bits: u16,
    pub schedule_root: String,
    pub opens_at_l2_height: u64,
    pub closes_at_l2_height: u64,
    pub published_at_l2_height: Option<u64>,
}

impl RotationSchedule {
    pub fn new(
        schedule_id: impl Into<String>,
        lane: RotationLane,
        epoch: u64,
        opens_at_l2_height: u64,
        config: &Config,
    ) -> Self {
        let schedule_id = schedule_id.into();
        Self {
            schedule_root: domain_hash(
                ROTATION_SCHEDULE_SCHEME,
                [
                    HashPart::from(schedule_id.as_str()),
                    HashPart::from(lane.as_str()),
                    HashPart::from(epoch),
                    HashPart::from(opens_at_l2_height),
                ],
            ),
            schedule_id,
            lane,
            status: ScheduleStatus::Open,
            epoch,
            cohort_ids: BTreeSet::new(),
            rotation_ids: BTreeSet::new(),
            target_rotation_count: config.max_rotations_per_schedule,
            min_ring_size: lane.min_ring_size(config),
            target_fee_micro_units: lane.fee_cap(config),
            privacy_score_bps: 0,
            pq_security_bits: config.target_pq_security_bits,
            opens_at_l2_height,
            closes_at_l2_height: opens_at_l2_height.saturating_add(config.schedule_ttl_blocks),
            published_at_l2_height: None,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.schedule_id.is_empty(), "schedule id is empty");
        ensure!(
            self.target_rotation_count <= config.max_rotations_per_schedule,
            "schedule {} exceeds rotation limit",
            self.schedule_id
        );
        ensure!(
            self.rotation_ids.len() <= config.max_rotations_per_schedule as usize,
            "schedule {} has too many rotations",
            self.schedule_id
        );
        ensure!(
            self.min_ring_size >= self.lane.min_ring_size(config),
            "schedule {} min ring below lane floor",
            self.schedule_id
        );
        ensure!(
            self.privacy_score_bps <= MAX_BPS,
            "schedule privacy score overflow"
        );
        ensure!(
            self.pq_security_bits >= config.min_pq_security_bits,
            "schedule {} below pq security floor",
            self.schedule_id
        );
        ensure!(
            self.closes_at_l2_height >= self.opens_at_l2_height,
            "schedule {} closes before open",
            self.schedule_id
        );
        Ok(())
    }

    pub fn attach_cohort(&mut self, cohort_id: impl Into<String>) {
        self.cohort_ids.insert(cohort_id.into());
        if self.status.accepts_rotations() {
            self.status = ScheduleStatus::Filling;
        }
    }

    pub fn attach_rotation(&mut self, rotation_id: impl Into<String>) {
        self.rotation_ids.insert(rotation_id.into());
        if self.status.accepts_rotations() {
            self.status = ScheduleStatus::Filling;
        }
    }

    pub fn attest(&mut self, privacy_score_bps: u64, l2_height: u64) {
        self.privacy_score_bps = privacy_score_bps.min(MAX_BPS);
        self.status = ScheduleStatus::Attested;
        self.published_at_l2_height = Some(l2_height);
    }

    pub fn public_record(&self) -> Value {
        json!({
            "schedule_id": self.schedule_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "epoch": self.epoch,
            "cohort_count": self.cohort_ids.len() as u64,
            "rotation_count": self.rotation_ids.len() as u64,
            "target_rotation_count": self.target_rotation_count,
            "min_ring_size": self.min_ring_size,
            "target_fee_micro_units": self.target_fee_micro_units,
            "privacy_score_bps": self.privacy_score_bps,
            "pq_security_bits": self.pq_security_bits,
            "schedule_root": self.schedule_root,
            "opens_at_l2_height": self.opens_at_l2_height,
            "closes_at_l2_height": self.closes_at_l2_height,
            "published_at_l2_height": self.published_at_l2_height
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            ROTATION_SCHEDULE_SCHEME,
            [
                HashPart::from(self.schedule_id.as_str()),
                HashPart::from(self.lane.as_str()),
                HashPart::from(self.status.as_str()),
                HashPart::from(self.epoch),
                HashPart::from(self.rotation_ids.len() as u64),
                HashPart::from(self.cohort_ids.len() as u64),
                HashPart::from(self.min_ring_size as u64),
                HashPart::from(self.target_fee_micro_units),
                HashPart::from(self.privacy_score_bps),
                HashPart::from(self.pq_security_bits as u64),
                HashPart::from(self.schedule_root.as_str()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqDecoyAttestation {
    pub attestation_id: String,
    pub rotation_id: String,
    pub schedule_id: String,
    pub operator_id: String,
    pub status: AttestationStatus,
    pub pq_scheme: String,
    pub pq_security_bits: u16,
    pub signed_rotation_root: String,
    pub freshness_floor_root: String,
    pub entropy_claim_bps: u64,
    pub quorum_weight_bps: u64,
    pub signature_commitment_root: String,
    pub submitted_at_l2_height: u64,
    pub expires_at_l2_height: u64,
}

impl PqDecoyAttestation {
    pub fn new(
        attestation_id: impl Into<String>,
        rotation_id: impl Into<String>,
        schedule_id: impl Into<String>,
        operator_id: impl Into<String>,
        rotation_root: impl Into<String>,
        freshness_floor_root: impl Into<String>,
        l2_height: u64,
        config: &Config,
    ) -> Self {
        let attestation_id = attestation_id.into();
        let rotation_id = rotation_id.into();
        let schedule_id = schedule_id.into();
        let operator_id = operator_id.into();
        Self {
            signature_commitment_root: domain_hash(
                PQ_DECOY_ATTESTATION_SCHEME,
                [
                    HashPart::from(attestation_id.as_str()),
                    HashPart::from(rotation_id.as_str()),
                    HashPart::from(operator_id.as_str()),
                    HashPart::from("signature-commitment"),
                ],
            ),
            attestation_id,
            rotation_id,
            schedule_id,
            operator_id,
            status: AttestationStatus::Submitted,
            pq_scheme: config.pq_attestation_suite.clone(),
            pq_security_bits: config.target_pq_security_bits,
            signed_rotation_root: rotation_root.into(),
            freshness_floor_root: freshness_floor_root.into(),
            entropy_claim_bps: config.min_viewtag_entropy_bps,
            quorum_weight_bps: 0,
            submitted_at_l2_height: l2_height,
            expires_at_l2_height: l2_height.saturating_add(config.attestation_ttl_blocks),
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.attestation_id.is_empty(), "attestation id is empty");
        ensure!(
            !self.rotation_id.is_empty(),
            "attestation rotation id is empty"
        );
        ensure!(
            self.pq_security_bits >= config.min_pq_security_bits,
            "attestation {} below pq security floor",
            self.attestation_id
        );
        ensure!(
            self.entropy_claim_bps <= MAX_BPS,
            "attestation entropy overflow"
        );
        ensure!(
            self.quorum_weight_bps <= MAX_BPS,
            "attestation quorum overflow"
        );
        ensure!(
            self.expires_at_l2_height >= self.submitted_at_l2_height,
            "attestation {} expires before submission",
            self.attestation_id
        );
        Ok(())
    }

    pub fn accept(&mut self, quorum_weight_bps: u64) {
        self.quorum_weight_bps = quorum_weight_bps.min(MAX_BPS);
        self.status = if self.quorum_weight_bps >= DEFAULT_OPERATOR_QUORUM_BPS {
            AttestationStatus::Quorum
        } else {
            AttestationStatus::Accepted
        };
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "rotation_id": self.rotation_id,
            "schedule_id": self.schedule_id,
            "operator_id": self.operator_id,
            "status": self.status.as_str(),
            "pq_scheme": self.pq_scheme,
            "pq_security_bits": self.pq_security_bits,
            "signed_rotation_root": self.signed_rotation_root,
            "freshness_floor_root": self.freshness_floor_root,
            "entropy_claim_bps": self.entropy_claim_bps,
            "quorum_weight_bps": self.quorum_weight_bps,
            "signature_commitment_root": self.signature_commitment_root,
            "submitted_at_l2_height": self.submitted_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            PQ_DECOY_ATTESTATION_SCHEME,
            [
                HashPart::from(self.attestation_id.as_str()),
                HashPart::from(self.rotation_id.as_str()),
                HashPart::from(self.schedule_id.as_str()),
                HashPart::from(self.operator_id.as_str()),
                HashPart::from(self.status.as_str()),
                HashPart::from(self.pq_security_bits as u64),
                HashPart::from(self.signed_rotation_root.as_str()),
                HashPart::from(self.freshness_floor_root.as_str()),
                HashPart::from(self.entropy_claim_bps),
                HashPart::from(self.quorum_weight_bps),
                HashPart::from(self.signature_commitment_root.as_str()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletScanHint {
    pub hint_id: String,
    pub rotation_id: String,
    pub cohort_id: String,
    pub lane: RotationLane,
    pub status: ScanHintStatus,
    pub encrypted_hint_root: String,
    pub viewtag_bucket_root: String,
    pub decoy_hint_root: String,
    pub max_hint_bytes: u32,
    pub mobile_optimized: bool,
    pub redaction_units: u64,
    pub published_at_l2_height: u64,
    pub expires_at_l2_height: u64,
}

impl WalletScanHint {
    pub fn new(
        hint_id: impl Into<String>,
        rotation_id: impl Into<String>,
        cohort_id: impl Into<String>,
        lane: RotationLane,
        l2_height: u64,
        config: &Config,
    ) -> Self {
        let hint_id = hint_id.into();
        let rotation_id = rotation_id.into();
        let cohort_id = cohort_id.into();
        Self {
            encrypted_hint_root: domain_hash(
                WALLET_SCAN_HINT_SCHEME,
                [
                    HashPart::from(hint_id.as_str()),
                    HashPart::from(rotation_id.as_str()),
                    HashPart::from("encrypted-hint"),
                ],
            ),
            viewtag_bucket_root: domain_hash(
                WALLET_SCAN_HINT_SCHEME,
                [
                    HashPart::from(hint_id.as_str()),
                    HashPart::from(cohort_id.as_str()),
                    HashPart::from("viewtag-bucket"),
                ],
            ),
            decoy_hint_root: domain_hash(
                WALLET_SCAN_HINT_SCHEME,
                [
                    HashPart::from(hint_id.as_str()),
                    HashPart::from(rotation_id.as_str()),
                    HashPart::from("decoy-hint"),
                ],
            ),
            hint_id,
            rotation_id,
            cohort_id,
            lane,
            status: ScanHintStatus::Published,
            max_hint_bytes: config.max_hint_bytes,
            mobile_optimized: matches!(
                lane,
                RotationLane::BackgroundWallet | RotationLane::MerchantPayment
            ),
            redaction_units: RedactionClass::ScheduleRoot.units(),
            published_at_l2_height: l2_height,
            expires_at_l2_height: l2_height.saturating_add(config.scan_hint_ttl_blocks),
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.hint_id.is_empty(), "hint id is empty");
        ensure!(!self.rotation_id.is_empty(), "hint rotation id is empty");
        ensure!(
            self.max_hint_bytes <= config.max_hint_bytes,
            "hint {} exceeds byte cap",
            self.hint_id
        );
        ensure!(
            self.expires_at_l2_height >= self.published_at_l2_height,
            "hint {} expires before publication",
            self.hint_id
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "rotation_id": self.rotation_id,
            "cohort_id": self.cohort_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "encrypted_hint_root": self.encrypted_hint_root,
            "viewtag_bucket_root": self.viewtag_bucket_root,
            "decoy_hint_root": self.decoy_hint_root,
            "max_hint_bytes": self.max_hint_bytes,
            "mobile_optimized": self.mobile_optimized,
            "redaction_units": self.redaction_units,
            "published_at_l2_height": self.published_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            WALLET_SCAN_HINT_SCHEME,
            [
                HashPart::from(self.hint_id.as_str()),
                HashPart::from(self.rotation_id.as_str()),
                HashPart::from(self.cohort_id.as_str()),
                HashPart::from(self.lane.as_str()),
                HashPart::from(self.status.as_str()),
                HashPart::from(self.encrypted_hint_root.as_str()),
                HashPart::from(self.viewtag_bucket_root.as_str()),
                HashPart::from(self.decoy_hint_root.as_str()),
                HashPart::from(self.max_hint_bytes as u64),
                HashPart::from(self.redaction_units),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecoyFreshnessFloor {
    pub floor_id: String,
    pub cohort_id: String,
    pub lane: RotationLane,
    pub status: FreshnessStatus,
    pub min_freshness_bps: u64,
    pub observed_freshness_bps: u64,
    pub min_age_blocks: u64,
    pub max_age_blocks: u64,
    pub selectable_output_root: String,
    pub quarantine_root: String,
    pub measured_at_monero_height: u64,
    pub expires_at_monero_height: u64,
}

impl DecoyFreshnessFloor {
    pub fn new(
        floor_id: impl Into<String>,
        cohort_id: impl Into<String>,
        lane: RotationLane,
        measured_at_monero_height: u64,
        config: &Config,
    ) -> Self {
        let floor_id = floor_id.into();
        let cohort_id = cohort_id.into();
        Self {
            selectable_output_root: domain_hash(
                DECOY_FRESHNESS_FLOOR_SCHEME,
                [
                    HashPart::from(floor_id.as_str()),
                    HashPart::from(cohort_id.as_str()),
                    HashPart::from("selectable-outputs"),
                ],
            ),
            quarantine_root: domain_hash(
                DECOY_FRESHNESS_FLOOR_SCHEME,
                [
                    HashPart::from(floor_id.as_str()),
                    HashPart::from(cohort_id.as_str()),
                    HashPart::from("quarantine"),
                ],
            ),
            floor_id,
            cohort_id,
            lane,
            status: FreshnessStatus::Candidate,
            min_freshness_bps: config.min_decoy_freshness_bps,
            observed_freshness_bps: 0,
            min_age_blocks: config.reorg_hold_blocks,
            max_age_blocks: config.rotation_window_blocks.saturating_mul(8),
            measured_at_monero_height,
            expires_at_monero_height: measured_at_monero_height
                .saturating_add(config.rotation_window_blocks),
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(!self.floor_id.is_empty(), "freshness floor id is empty");
        ensure!(
            self.min_freshness_bps <= MAX_BPS,
            "freshness floor bps overflow"
        );
        ensure!(
            self.observed_freshness_bps <= MAX_BPS,
            "observed freshness bps overflow"
        );
        ensure!(
            self.max_age_blocks >= self.min_age_blocks,
            "freshness floor max age below min age"
        );
        ensure!(
            self.expires_at_monero_height >= self.measured_at_monero_height,
            "freshness floor expires before measurement"
        );
        Ok(())
    }

    pub fn observe(&mut self, observed_freshness_bps: u64) {
        self.observed_freshness_bps = observed_freshness_bps.min(MAX_BPS);
        self.status = if self.observed_freshness_bps >= self.min_freshness_bps {
            FreshnessStatus::Fresh
        } else {
            FreshnessStatus::Stale
        };
    }

    pub fn public_record(&self) -> Value {
        json!({
            "floor_id": self.floor_id,
            "cohort_id": self.cohort_id,
            "lane": self.lane.as_str(),
            "status": self.status,
            "min_freshness_bps": self.min_freshness_bps,
            "observed_freshness_bps": self.observed_freshness_bps,
            "min_age_blocks": self.min_age_blocks,
            "max_age_blocks": self.max_age_blocks,
            "selectable_output_root": self.selectable_output_root,
            "quarantine_root": self.quarantine_root,
            "measured_at_monero_height": self.measured_at_monero_height,
            "expires_at_monero_height": self.expires_at_monero_height
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            DECOY_FRESHNESS_FLOOR_SCHEME,
            [
                HashPart::from(self.floor_id.as_str()),
                HashPart::from(self.cohort_id.as_str()),
                HashPart::from(self.lane.as_str()),
                HashPart::from(format!("{:?}", self.status).as_str()),
                HashPart::from(self.min_freshness_bps),
                HashPart::from(self.observed_freshness_bps),
                HashPart::from(self.min_age_blocks),
                HashPart::from(self.max_age_blocks),
                HashPart::from(self.selectable_output_root.as_str()),
                HashPart::from(self.quarantine_root.as_str()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub rotation_id: String,
    pub schedule_id: String,
    pub lane: RotationLane,
    pub status: RebateStatus,
    pub fee_asset_id: String,
    pub gross_fee_micro_units: u64,
    pub rebate_bps: u64,
    pub rebate_micro_units: u64,
    pub sponsor_cover_bps: u64,
    pub claim_commitment_root: String,
    pub created_at_l2_height: u64,
    pub expires_at_l2_height: u64,
}

impl FeeRebate {
    pub fn new(
        rebate_id: impl Into<String>,
        rotation: &ClsagDecoyRotation,
        l2_height: u64,
        config: &Config,
    ) -> Self {
        let rebate_id = rebate_id.into();
        let rebate_micro_units = rotation
            .fee_micro_units
            .saturating_mul(config.low_fee_rebate_bps)
            / MAX_BPS;
        Self {
            claim_commitment_root: domain_hash(
                FEE_REBATE_SCHEME,
                [
                    HashPart::from(rebate_id.as_str()),
                    HashPart::from(rotation.rotation_id.as_str()),
                    HashPart::from("claim"),
                ],
            ),
            rebate_id,
            rotation_id: rotation.rotation_id.clone(),
            schedule_id: rotation.schedule_id.clone(),
            lane: rotation.lane,
            status: RebateStatus::Claimable,
            fee_asset_id: config.fee_asset_id.clone(),
            gross_fee_micro_units: rotation.fee_micro_units,
            rebate_bps: config.low_fee_rebate_bps,
            rebate_micro_units,
            sponsor_cover_bps: config.sponsor_cover_bps,
            created_at_l2_height: l2_height,
            expires_at_l2_height: l2_height.saturating_add(config.schedule_ttl_blocks),
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(!self.rebate_id.is_empty(), "rebate id is empty");
        ensure!(self.rebate_bps <= MAX_BPS, "rebate bps overflow");
        ensure!(
            self.sponsor_cover_bps <= MAX_BPS,
            "sponsor cover bps overflow"
        );
        ensure!(
            self.rebate_micro_units <= self.gross_fee_micro_units,
            "rebate exceeds gross fee"
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "rotation_id": self.rotation_id,
            "schedule_id": self.schedule_id,
            "lane": self.lane.as_str(),
            "status": self.status,
            "fee_asset_id": self.fee_asset_id,
            "gross_fee_micro_units": self.gross_fee_micro_units,
            "rebate_bps": self.rebate_bps,
            "rebate_micro_units": self.rebate_micro_units,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "claim_commitment_root": self.claim_commitment_root,
            "created_at_l2_height": self.created_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            FEE_REBATE_SCHEME,
            [
                HashPart::from(self.rebate_id.as_str()),
                HashPart::from(self.rotation_id.as_str()),
                HashPart::from(self.schedule_id.as_str()),
                HashPart::from(self.lane.as_str()),
                HashPart::from(self.gross_fee_micro_units),
                HashPart::from(self.rebate_bps),
                HashPart::from(self.rebate_micro_units),
                HashPart::from(self.sponsor_cover_bps),
                HashPart::from(self.claim_commitment_root.as_str()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub class: RedactionClass,
    pub max_units: u64,
    pub spent_units: u64,
    pub remaining_units: u64,
    pub redacted_record_root: String,
    pub opens_at_l2_height: u64,
    pub closes_at_l2_height: u64,
}

impl PrivacyRedactionBudget {
    pub fn new(
        budget_id: impl Into<String>,
        operator_id: impl Into<String>,
        epoch: u64,
        class: RedactionClass,
        opens_at_l2_height: u64,
        config: &Config,
    ) -> Self {
        let budget_id = budget_id.into();
        let operator_id = operator_id.into();
        let max_units = config.epoch_redaction_budget.saturating_mul(class.units());
        Self {
            redacted_record_root: domain_hash(
                PRIVACY_REDACTION_BUDGET_SCHEME,
                [
                    HashPart::from(budget_id.as_str()),
                    HashPart::from(operator_id.as_str()),
                    HashPart::from(epoch),
                    HashPart::from("redacted-records"),
                ],
            ),
            budget_id,
            operator_id,
            epoch,
            class,
            max_units,
            spent_units: 0,
            remaining_units: max_units,
            opens_at_l2_height,
            closes_at_l2_height: opens_at_l2_height.saturating_add(config.rotation_window_blocks),
        }
    }

    pub fn spend(&mut self, units: u64) -> Result<()> {
        ensure!(
            self.remaining_units >= units,
            "redaction budget {} exhausted",
            self.budget_id
        );
        self.spent_units = self.spent_units.saturating_add(units);
        self.remaining_units = self.remaining_units.saturating_sub(units);
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "class": self.class,
            "max_units": self.max_units,
            "spent_units": self.spent_units,
            "remaining_units": self.remaining_units,
            "redacted_record_root": self.redacted_record_root,
            "opens_at_l2_height": self.opens_at_l2_height,
            "closes_at_l2_height": self.closes_at_l2_height
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            PRIVACY_REDACTION_BUDGET_SCHEME,
            [
                HashPart::from(self.budget_id.as_str()),
                HashPart::from(self.operator_id.as_str()),
                HashPart::from(self.epoch),
                HashPart::from(format!("{:?}", self.class).as_str()),
                HashPart::from(self.max_units),
                HashPart::from(self.spent_units),
                HashPart::from(self.remaining_units),
                HashPart::from(self.redacted_record_root.as_str()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub lane: RotationLane,
    pub schedule_count: u64,
    pub rotation_count: u64,
    pub accepted_attestation_count: u64,
    pub settled_rotation_count: u64,
    pub quarantined_rotation_count: u64,
    pub total_fee_micro_units: u64,
    pub total_rebate_micro_units: u64,
    pub public_summary_root: String,
    pub redaction_budget_root: String,
}

impl OperatorSummary {
    pub fn new(
        summary_id: impl Into<String>,
        operator_id: impl Into<String>,
        epoch: u64,
        lane: RotationLane,
        roots: &Roots,
        counters: &Counters,
    ) -> Self {
        let summary_id = summary_id.into();
        let operator_id = operator_id.into();
        Self {
            public_summary_root: domain_hash(
                OPERATOR_SUMMARY_SCHEME,
                [
                    HashPart::from(summary_id.as_str()),
                    HashPart::from(operator_id.as_str()),
                    HashPart::from(epoch),
                    HashPart::from(roots.state_root.as_str()),
                ],
            ),
            redaction_budget_root: roots.privacy_redaction_budgets_root.clone(),
            summary_id,
            operator_id,
            epoch,
            lane,
            schedule_count: counters.rotation_schedules,
            rotation_count: counters.clsag_rotations,
            accepted_attestation_count: counters.accepted_attestations,
            settled_rotation_count: counters.settled_rotations,
            quarantined_rotation_count: counters.quarantined_rotations,
            total_fee_micro_units: 0,
            total_rebate_micro_units: counters.total_rebate_micro_units,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "lane": self.lane.as_str(),
            "schedule_count": self.schedule_count,
            "rotation_count": self.rotation_count,
            "accepted_attestation_count": self.accepted_attestation_count,
            "settled_rotation_count": self.settled_rotation_count,
            "quarantined_rotation_count": self.quarantined_rotation_count,
            "total_fee_micro_units": self.total_fee_micro_units,
            "total_rebate_micro_units": self.total_rebate_micro_units,
            "public_summary_root": self.public_summary_root,
            "redaction_budget_root": self.redaction_budget_root
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            OPERATOR_SUMMARY_SCHEME,
            [
                HashPart::from(self.summary_id.as_str()),
                HashPart::from(self.operator_id.as_str()),
                HashPart::from(self.epoch),
                HashPart::from(self.lane.as_str()),
                HashPart::from(self.schedule_count),
                HashPart::from(self.rotation_count),
                HashPart::from(self.accepted_attestation_count),
                HashPart::from(self.settled_rotation_count),
                HashPart::from(self.total_rebate_micro_units),
                HashPart::from(self.public_summary_root.as_str()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_l2_height: u64,
    pub current_monero_height: u64,
    pub current_epoch: u64,
    pub jamtis_cohorts: BTreeMap<String, JamtisViewtagCohort>,
    pub clsag_rotations: BTreeMap<String, ClsagDecoyRotation>,
    pub rotation_schedules: BTreeMap<String, RotationSchedule>,
    pub pq_decoy_attestations: BTreeMap<String, PqDecoyAttestation>,
    pub wallet_scan_hints: BTreeMap<String, WalletScanHint>,
    pub decoy_freshness_floors: BTreeMap<String, DecoyFreshnessFloor>,
    pub fee_rebates: BTreeMap<String, FeeRebate>,
    pub privacy_redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub public_records: BTreeMap<String, Value>,
}

impl State {
    pub fn new(
        config: Config,
        current_l2_height: u64,
        current_monero_height: u64,
        current_epoch: u64,
    ) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            current_l2_height,
            current_monero_height,
            current_epoch,
            jamtis_cohorts: BTreeMap::new(),
            clsag_rotations: BTreeMap::new(),
            rotation_schedules: BTreeMap::new(),
            pq_decoy_attestations: BTreeMap::new(),
            wallet_scan_hints: BTreeMap::new(),
            decoy_freshness_floors: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            privacy_redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        state.recompute_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn insert_jamtis_cohort(&mut self, cohort: JamtisViewtagCohort) -> Result<()> {
        ensure!(
            self.jamtis_cohorts.len() < self.config.max_jamtis_cohorts,
            "jamtis cohort capacity reached"
        );
        cohort.validate(&self.config)?;
        self.jamtis_cohorts.insert(cohort.cohort_id.clone(), cohort);
        self.counters.jamtis_cohorts = self.jamtis_cohorts.len() as u64;
        self.recompute_roots();
        Ok(())
    }

    pub fn insert_freshness_floor(&mut self, floor: DecoyFreshnessFloor) -> Result<()> {
        ensure!(
            self.decoy_freshness_floors.len() < self.config.max_decoy_freshness_floors,
            "freshness floor capacity reached"
        );
        floor.validate()?;
        self.decoy_freshness_floors
            .insert(floor.floor_id.clone(), floor);
        self.counters.decoy_freshness_floors = self.decoy_freshness_floors.len() as u64;
        self.recompute_roots();
        Ok(())
    }

    pub fn insert_schedule(&mut self, schedule: RotationSchedule) -> Result<()> {
        ensure!(
            self.rotation_schedules.len() < self.config.max_rotation_schedules,
            "rotation schedule capacity reached"
        );
        schedule.validate(&self.config)?;
        self.rotation_schedules
            .insert(schedule.schedule_id.clone(), schedule);
        self.counters.rotation_schedules = self.rotation_schedules.len() as u64;
        self.recompute_roots();
        Ok(())
    }

    pub fn schedule_rotation(&mut self, mut rotation: ClsagDecoyRotation) -> Result<()> {
        ensure!(
            self.clsag_rotations.len() < self.config.max_clsag_rotations,
            "clsag rotation capacity reached"
        );
        rotation.validate(&self.config)?;
        ensure!(
            self.jamtis_cohorts.contains_key(&rotation.cohort_id),
            "missing cohort {}",
            rotation.cohort_id
        );
        ensure!(
            self.rotation_schedules.contains_key(&rotation.schedule_id),
            "missing schedule {}",
            rotation.schedule_id
        );
        if rotation.status == RotationStatus::Draft {
            rotation.status = RotationStatus::Scheduled;
        }
        let rotation_id = rotation.rotation_id.clone();
        let cohort_id = rotation.cohort_id.clone();
        let schedule_id = rotation.schedule_id.clone();
        self.clsag_rotations.insert(rotation_id.clone(), rotation);
        if let Some(cohort) = self.jamtis_cohorts.get_mut(&cohort_id) {
            cohort.attach_schedule(schedule_id.clone(), self.current_l2_height);
        }
        if let Some(schedule) = self.rotation_schedules.get_mut(&schedule_id) {
            schedule.attach_cohort(cohort_id);
            schedule.attach_rotation(rotation_id);
        }
        self.counters.clsag_rotations = self.clsag_rotations.len() as u64;
        self.recompute_roots();
        Ok(())
    }

    pub fn accept_attestation(&mut self, mut attestation: PqDecoyAttestation) -> Result<()> {
        ensure!(
            self.pq_decoy_attestations.len() < self.config.max_pq_decoy_attestations,
            "pq decoy attestation capacity reached"
        );
        attestation.validate(&self.config)?;
        ensure!(
            self.clsag_rotations.contains_key(&attestation.rotation_id),
            "missing attested rotation {}",
            attestation.rotation_id
        );
        attestation.accept(self.config.operator_quorum_bps);
        let attestation_id = attestation.attestation_id.clone();
        let rotation_id = attestation.rotation_id.clone();
        self.pq_decoy_attestations
            .insert(attestation_id.clone(), attestation);
        if let Some(rotation) = self.clsag_rotations.get_mut(&rotation_id) {
            rotation.attach_attestation(attestation_id);
        }
        self.counters.pq_decoy_attestations = self.pq_decoy_attestations.len() as u64;
        self.counters.accepted_attestations = self
            .pq_decoy_attestations
            .values()
            .filter(|attestation| attestation.status.counts_for_quorum())
            .count() as u64;
        self.recompute_roots();
        Ok(())
    }

    pub fn publish_scan_hint(&mut self, hint: WalletScanHint) -> Result<()> {
        ensure!(
            self.wallet_scan_hints.len() < self.config.max_wallet_scan_hints,
            "wallet scan hint capacity reached"
        );
        hint.validate(&self.config)?;
        ensure!(
            self.clsag_rotations.contains_key(&hint.rotation_id),
            "missing hinted rotation {}",
            hint.rotation_id
        );
        let hint_id = hint.hint_id.clone();
        let rotation_id = hint.rotation_id.clone();
        self.wallet_scan_hints.insert(hint_id.clone(), hint);
        if let Some(rotation) = self.clsag_rotations.get_mut(&rotation_id) {
            rotation.attach_hint(hint_id);
        }
        self.counters.wallet_scan_hints = self.wallet_scan_hints.len() as u64;
        self.recompute_roots();
        Ok(())
    }

    pub fn add_fee_rebate(&mut self, rebate: FeeRebate) -> Result<()> {
        ensure!(
            self.fee_rebates.len() < self.config.max_fee_rebates,
            "fee rebate capacity reached"
        );
        rebate.validate()?;
        let rebate_micro_units = rebate.rebate_micro_units;
        if let Some(rotation) = self.clsag_rotations.get_mut(&rebate.rotation_id) {
            rotation.apply_rebate(rebate_micro_units);
        }
        self.fee_rebates.insert(rebate.rebate_id.clone(), rebate);
        self.counters.fee_rebates = self.fee_rebates.len() as u64;
        self.counters.total_rebate_micro_units = self
            .fee_rebates
            .values()
            .map(|rebate| rebate.rebate_micro_units)
            .sum();
        self.recompute_roots();
        Ok(())
    }

    pub fn add_redaction_budget(&mut self, budget: PrivacyRedactionBudget) -> Result<()> {
        ensure!(
            self.privacy_redaction_budgets.len() < self.config.max_privacy_redaction_budgets,
            "privacy redaction budget capacity reached"
        );
        self.privacy_redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        self.counters.privacy_redaction_budgets = self.privacy_redaction_budgets.len() as u64;
        self.recompute_roots();
        Ok(())
    }

    pub fn add_operator_summary(&mut self, summary: OperatorSummary) -> Result<()> {
        ensure!(
            self.operator_summaries.len() < self.config.max_operator_summaries,
            "operator summary capacity reached"
        );
        self.operator_summaries
            .insert(summary.summary_id.clone(), summary);
        self.counters.operator_summaries = self.operator_summaries.len() as u64;
        self.recompute_roots();
        Ok(())
    }

    pub fn settle_rotation(&mut self, rotation_id: &str) -> Result<()> {
        let rotation = self
            .clsag_rotations
            .get_mut(rotation_id)
            .ok_or_else(|| format!("missing rotation {rotation_id}"))?;
        ensure!(
            matches!(
                rotation.status,
                RotationStatus::Attested | RotationStatus::Published
            ),
            "rotation {} not ready to settle",
            rotation_id
        );
        rotation.status = RotationStatus::Settled;
        self.counters.settled_rotations = self
            .clsag_rotations
            .values()
            .filter(|rotation| rotation.status == RotationStatus::Settled)
            .count() as u64;
        self.recompute_roots();
        Ok(())
    }

    pub fn quarantine_rotation(&mut self, rotation_id: &str) -> Result<()> {
        let rotation = self
            .clsag_rotations
            .get_mut(rotation_id)
            .ok_or_else(|| format!("missing rotation {rotation_id}"))?;
        rotation.status = RotationStatus::Quarantined;
        self.counters.quarantined_rotations = self
            .clsag_rotations
            .values()
            .filter(|rotation| rotation.status == RotationStatus::Quarantined)
            .count() as u64;
        self.recompute_roots();
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        state_root(self)
    }

    pub fn recompute_roots(&mut self) {
        let jamtis_roots: Vec<String> = self
            .jamtis_cohorts
            .values()
            .map(JamtisViewtagCohort::root)
            .collect();
        let rotation_roots: Vec<String> = self
            .clsag_rotations
            .values()
            .map(ClsagDecoyRotation::root)
            .collect();
        let schedule_roots: Vec<String> = self
            .rotation_schedules
            .values()
            .map(RotationSchedule::root)
            .collect();
        let attestation_roots: Vec<String> = self
            .pq_decoy_attestations
            .values()
            .map(PqDecoyAttestation::root)
            .collect();
        let hint_roots: Vec<String> = self
            .wallet_scan_hints
            .values()
            .map(WalletScanHint::root)
            .collect();
        let floor_roots: Vec<String> = self
            .decoy_freshness_floors
            .values()
            .map(DecoyFreshnessFloor::root)
            .collect();
        let rebate_roots: Vec<String> = self.fee_rebates.values().map(FeeRebate::root).collect();
        let budget_roots: Vec<String> = self
            .privacy_redaction_budgets
            .values()
            .map(PrivacyRedactionBudget::root)
            .collect();
        let summary_roots: Vec<String> = self
            .operator_summaries
            .values()
            .map(OperatorSummary::root)
            .collect();
        let public_roots: Vec<String> = self
            .public_records
            .iter()
            .map(|(key, value)| {
                domain_hash(
                    PUBLIC_RECORD_SCHEME,
                    [
                        HashPart::from(key.as_str()),
                        HashPart::from(value.to_string().as_str()),
                    ],
                )
            })
            .collect();

        self.roots.jamtis_cohorts_root = merkle_root(JAMTIS_COHORT_SCHEME, jamtis_roots);
        self.roots.clsag_rotations_root = merkle_root(CLSAG_ROTATION_SCHEME, rotation_roots);
        self.roots.rotation_schedules_root = merkle_root(ROTATION_SCHEDULE_SCHEME, schedule_roots);
        self.roots.pq_decoy_attestations_root =
            merkle_root(PQ_DECOY_ATTESTATION_SCHEME, attestation_roots);
        self.roots.wallet_scan_hints_root = merkle_root(WALLET_SCAN_HINT_SCHEME, hint_roots);
        self.roots.decoy_freshness_floors_root =
            merkle_root(DECOY_FRESHNESS_FLOOR_SCHEME, floor_roots);
        self.roots.fee_rebates_root = merkle_root(FEE_REBATE_SCHEME, rebate_roots);
        self.roots.privacy_redaction_budgets_root =
            merkle_root(PRIVACY_REDACTION_BUDGET_SCHEME, budget_roots);
        self.roots.operator_summaries_root = merkle_root(OPERATOR_SUMMARY_SCHEME, summary_roots);
        self.roots.public_records_root = merkle_root(PUBLIC_RECORD_SCHEME, public_roots);
        self.roots.state_root = domain_hash(
            PUBLIC_RECORD_SCHEME,
            [
                HashPart::from(PROTOCOL_VERSION),
                HashPart::from(self.current_l2_height),
                HashPart::from(self.current_monero_height),
                HashPart::from(self.current_epoch),
                HashPart::from(self.roots.jamtis_cohorts_root.as_str()),
                HashPart::from(self.roots.clsag_rotations_root.as_str()),
                HashPart::from(self.roots.rotation_schedules_root.as_str()),
                HashPart::from(self.roots.pq_decoy_attestations_root.as_str()),
                HashPart::from(self.roots.wallet_scan_hints_root.as_str()),
                HashPart::from(self.roots.decoy_freshness_floors_root.as_str()),
                HashPart::from(self.roots.fee_rebates_root.as_str()),
                HashPart::from(self.roots.privacy_redaction_budgets_root.as_str()),
                HashPart::from(self.roots.operator_summaries_root.as_str()),
                HashPart::from(self.roots.public_records_root.as_str()),
            ],
        );
    }
}

pub fn devnet() -> State {
    demo()
}

pub fn demo() -> State {
    let config = Config::devnet();
    let mut state = State::new(
        config.clone(),
        DEVNET_L2_HEIGHT,
        DEVNET_MONERO_HEIGHT,
        DEVNET_EPOCH,
    )
    .expect("devnet config is valid");

    let cohort = JamtisViewtagCohort::new(
        "jamtis-cohort-devnet-background-001",
        RotationLane::BackgroundWallet,
        DEVNET_EPOCH,
        DEVNET_MONERO_HEIGHT.saturating_sub(config.rotation_window_blocks),
        DEVNET_MONERO_HEIGHT,
        config.target_cohort_outputs,
    )
    .seal(9_240, 241);
    state.insert_jamtis_cohort(cohort).expect("valid cohort");

    let mut floor = DecoyFreshnessFloor::new(
        "freshness-floor-devnet-background-001",
        "jamtis-cohort-devnet-background-001",
        RotationLane::BackgroundWallet,
        DEVNET_MONERO_HEIGHT,
        &config,
    );
    floor.observe(8_920);
    let floor_root = floor.root();
    state.insert_freshness_floor(floor).expect("valid floor");

    let schedule = RotationSchedule::new(
        "rotation-schedule-devnet-background-001",
        RotationLane::BackgroundWallet,
        DEVNET_EPOCH,
        DEVNET_L2_HEIGHT,
        &config,
    );
    state.insert_schedule(schedule).expect("valid schedule");

    let rotation = ClsagDecoyRotation::new(
        "clsag-rotation-devnet-background-001",
        "jamtis-cohort-devnet-background-001",
        "rotation-schedule-devnet-background-001",
        RotationLane::BackgroundWallet,
        &config,
        DEVNET_MONERO_HEIGHT,
        DEVNET_L2_HEIGHT.saturating_add(4),
    )
    .schedule("freshness-floor-devnet-background-001");
    let rotation_root = rotation.root();
    state.schedule_rotation(rotation).expect("valid rotation");

    let attestation = PqDecoyAttestation::new(
        "pq-decoy-attestation-devnet-background-001",
        "clsag-rotation-devnet-background-001",
        "rotation-schedule-devnet-background-001",
        "operator-devnet-rotation-watcher-001",
        rotation_root,
        floor_root,
        DEVNET_L2_HEIGHT.saturating_add(8),
        &config,
    );
    state
        .accept_attestation(attestation)
        .expect("valid attestation");

    let hint = WalletScanHint::new(
        "wallet-scan-hint-devnet-background-001",
        "clsag-rotation-devnet-background-001",
        "jamtis-cohort-devnet-background-001",
        RotationLane::BackgroundWallet,
        DEVNET_L2_HEIGHT.saturating_add(9),
        &config,
    );
    state.publish_scan_hint(hint).expect("valid scan hint");

    let rebate_rotation = state
        .clsag_rotations
        .get("clsag-rotation-devnet-background-001")
        .expect("rotation exists")
        .clone();
    let rebate = FeeRebate::new(
        "fee-rebate-devnet-background-001",
        &rebate_rotation,
        DEVNET_L2_HEIGHT.saturating_add(10),
        &config,
    );
    state.add_fee_rebate(rebate).expect("valid rebate");

    let mut budget = PrivacyRedactionBudget::new(
        "redaction-budget-devnet-operator-001",
        "operator-devnet-rotation-watcher-001",
        DEVNET_EPOCH,
        RedactionClass::ScheduleRoot,
        DEVNET_L2_HEIGHT,
        &config,
    );
    budget
        .spend(RedactionClass::ScheduleRoot.units())
        .expect("budget has units");
    state.add_redaction_budget(budget).expect("valid budget");

    let summary = OperatorSummary::new(
        "operator-summary-devnet-background-001",
        "operator-devnet-rotation-watcher-001",
        DEVNET_EPOCH,
        RotationLane::BackgroundWallet,
        &state.roots,
        &state.counters,
    );
    state
        .add_operator_summary(summary)
        .expect("valid operator summary");

    let record = public_record(&state);
    state
        .public_records
        .insert("devnet-public-record".to_string(), record);
    state.counters.public_records = state.public_records.len() as u64;
    state.recompute_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    json!({
        "protocol_version": PROTOCOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "privacy_boundary": PRIVACY_BOUNDARY,
        "chain_id": state.config.chain_id,
        "mode": state.config.mode.as_str(),
        "l2_network": state.config.l2_network,
        "monero_network": state.config.monero_network,
        "scheduler_id": state.config.scheduler_id,
        "fee_asset_id": state.config.fee_asset_id,
        "current_l2_height": state.current_l2_height,
        "current_monero_height": state.current_monero_height,
        "current_epoch": state.current_epoch,
        "priorities": {
            "monero_privacy": true,
            "quantum_resistance": state.config.target_pq_security_bits,
            "speed": {
                "rotation_window_blocks": state.config.rotation_window_blocks,
                "schedule_ttl_blocks": state.config.schedule_ttl_blocks,
                "scan_hint_ttl_blocks": state.config.scan_hint_ttl_blocks
            },
            "low_fees": {
                "background_fee_micro_units": state.config.background_fee_micro_units,
                "max_user_fee_micro_units": state.config.max_user_fee_micro_units,
                "low_fee_rebate_bps": state.config.low_fee_rebate_bps,
                "sponsor_cover_bps": state.config.sponsor_cover_bps
            }
        },
        "counters": state.counters.public_record(),
        "roots": state.roots.public_record()
    })
}

pub fn state_root(state: &State) -> String {
    state.roots.state_root.clone()
}
