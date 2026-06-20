use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateSubaddressViewtagScanThrottleRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_VIEWTAG_SCAN_THROTTLE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-subaddress-viewtag-scan-throttle-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_SUBADDRESS_VIEWTAG_SCAN_THROTTLE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 1_744_128;
pub const DEVNET_EPOCH: u64 = 4_096;
pub const SCAN_COHORT_SCHEME: &str = "private-subaddress-viewtag-scan-cohort-root-v1";
pub const SUBADDRESS_BUCKET_SCHEME: &str = "redacted-subaddress-bucket-commitment-root-v1";
pub const VIEWTAG_PRESSURE_SCHEME: &str = "operator-safe-viewtag-pressure-signal-root-v1";
pub const WALLET_SCAN_GRANT_SCHEME: &str = "privacy-preserving-wallet-scan-grant-root-v1";
pub const PQ_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-192f-subaddress-viewtag-throttle-attestation-v1";
pub const PRIVACY_THROTTLE_SCHEME: &str = "privacy-preserving-scan-throttle-decision-root-v1";
pub const LOW_FEE_REBATE_SCHEME: &str = "low-fee-wallet-scan-rebate-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str = "scan-throttle-redaction-budget-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str = "operator-safe-subaddress-viewtag-summary-root-v1";
pub const DEFAULT_COHORT_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_BUCKET_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_GRANT_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_THROTTLE_WINDOW_BLOCKS: u64 = 64;
pub const DEFAULT_REDACTION_BUDGET_PER_EPOCH: u32 = 36;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_BUCKET_OUTPUTS: u32 = 32;
pub const DEFAULT_TARGET_BUCKET_OUTPUTS: u32 = 512;
pub const DEFAULT_MAX_BUCKET_OUTPUTS: u32 = 4_096;
pub const DEFAULT_MIN_VIEWTAG_ENTROPY_BITS: u16 = 12;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u16 = 8_500;
pub const DEFAULT_OPERATOR_FEE_SHARE_BPS: u16 = 1_000;
pub const DEFAULT_MAX_SCAN_FEE_MICRO_UNITS: u64 = 3_200;
pub const DEFAULT_PRESSURE_SOFT_LIMIT_BPS: u16 = 6_800;
pub const DEFAULT_PRESSURE_HARD_LIMIT_BPS: u16 = 8_600;
pub const DEFAULT_MAX_OPERATOR_SUMMARY_FIELDS: u8 = 12;
pub const MAX_BPS: u16 = 10_000;
pub const MAX_SCAN_COHORTS: usize = 1_048_576;
pub const MAX_SUBADDRESS_BUCKETS: usize = 2_097_152;
pub const MAX_VIEWTAG_PRESSURE_SIGNALS: usize = 2_097_152;
pub const MAX_WALLET_SCAN_GRANTS: usize = 2_097_152;
pub const MAX_PQ_ATTESTATIONS: usize = 2_097_152;
pub const MAX_PRIVACY_THROTTLES: usize = 1_048_576;
pub const MAX_LOW_FEE_REBATES: usize = 1_048_576;
pub const MAX_REDACTION_BUDGETS: usize = 524_288;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanLane {
    ForegroundWallet,
    BackgroundWallet,
    WalletRestore,
    MerchantReceive,
    BridgeDeposit,
    BridgeWithdrawal,
    WatchOnlyAudit,
    ReorgRepair,
}

impl ScanLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ForegroundWallet => "foreground_wallet",
            Self::BackgroundWallet => "background_wallet",
            Self::WalletRestore => "wallet_restore",
            Self::MerchantReceive => "merchant_receive",
            Self::BridgeDeposit => "bridge_deposit",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::WatchOnlyAudit => "watch_only_audit",
            Self::ReorgRepair => "reorg_repair",
        }
    }

    pub fn default_weight(self) -> u16 {
        match self {
            Self::ReorgRepair => 1_000,
            Self::BridgeWithdrawal => 930,
            Self::BridgeDeposit => 880,
            Self::ForegroundWallet => 820,
            Self::MerchantReceive => 760,
            Self::WalletRestore => 690,
            Self::WatchOnlyAudit => 610,
            Self::BackgroundWallet => 540,
        }
    }

    pub fn default_fee_cap(self) -> u64 {
        match self {
            Self::ForegroundWallet => 1_600,
            Self::BackgroundWallet => 850,
            Self::WalletRestore => 2_800,
            Self::MerchantReceive => 1_200,
            Self::BridgeDeposit => 2_400,
            Self::BridgeWithdrawal => 3_200,
            Self::WatchOnlyAudit => 1_900,
            Self::ReorgRepair => 3_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortStatus {
    Draft,
    Open,
    Bucketed,
    Pressurized,
    Granting,
    Throttled,
    RebateReady,
    Settled,
    Expired,
}

impl CohortStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::Bucketed => "bucketed",
            Self::Pressurized => "pressurized",
            Self::Granting => "granting",
            Self::Throttled => "throttled",
            Self::RebateReady => "rebate_ready",
            Self::Settled => "settled",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Bucketed | Self::Pressurized | Self::Granting | Self::Throttled
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketStatus {
    Committed,
    Open,
    Sealed,
    PressureLinked,
    GrantEligible,
    RebateEligible,
    Settled,
    Challenged,
    Expired,
}

impl BucketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::PressureLinked => "pressure_linked",
            Self::GrantEligible => "grant_eligible",
            Self::RebateEligible => "rebate_eligible",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }

    pub fn scannable(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Sealed | Self::PressureLinked | Self::GrantEligible
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PressureBand {
    Idle,
    Normal,
    Warm,
    Saturated,
    Critical,
}

impl PressureBand {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Normal => "normal",
            Self::Warm => "warm",
            Self::Saturated => "saturated",
            Self::Critical => "critical",
        }
    }

    pub fn from_bps(value: u16) -> Self {
        if value >= 9_000 {
            Self::Critical
        } else if value >= 7_500 {
            Self::Saturated
        } else if value >= 5_500 {
            Self::Warm
        } else if value == 0 {
            Self::Idle
        } else {
            Self::Normal
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantStatus {
    Quoted,
    Reserved,
    Issued,
    Consumed,
    Deferred,
    Revoked,
    Expired,
}

impl GrantStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quoted => "quoted",
            Self::Reserved => "reserved",
            Self::Issued => "issued",
            Self::Consumed => "consumed",
            Self::Deferred => "deferred",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Quoted | Self::Reserved | Self::Issued | Self::Deferred
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PqSigner,
    SubaddressBucketIntegrity,
    ViewtagPressurePrivacy,
    WalletGrantFairness,
    ThrottleCorrectness,
    RebateIntegrity,
    RedactionCompliance,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqSigner => "pq_signer",
            Self::SubaddressBucketIntegrity => "subaddress_bucket_integrity",
            Self::ViewtagPressurePrivacy => "viewtag_pressure_privacy",
            Self::WalletGrantFairness => "wallet_grant_fairness",
            Self::ThrottleCorrectness => "throttle_correctness",
            Self::RebateIntegrity => "rebate_integrity",
            Self::RedactionCompliance => "redaction_compliance",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThrottleAction {
    Admit,
    Shape,
    Delay,
    Batch,
    SponsorOnly,
    EmergencyHold,
}

impl ThrottleAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admit => "admit",
            Self::Shape => "shape",
            Self::Delay => "delay",
            Self::Batch => "batch",
            Self::SponsorOnly => "sponsor_only",
            Self::EmergencyHold => "emergency_hold",
        }
    }

    pub fn restrictive(self) -> bool {
        matches!(
            self,
            Self::Delay | Self::Batch | Self::SponsorOnly | Self::EmergencyHold
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Quoted,
    Reserved,
    Attested,
    Settled,
    ClawedBack,
    Expired,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quoted => "quoted",
            Self::Reserved => "reserved",
            Self::Attested => "attested",
            Self::Settled => "settled",
            Self::ClawedBack => "clawed_back",
            Self::Expired => "expired",
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
    pub scan_cohort_scheme: String,
    pub subaddress_bucket_scheme: String,
    pub viewtag_pressure_scheme: String,
    pub wallet_scan_grant_scheme: String,
    pub pq_attestation_scheme: String,
    pub privacy_throttle_scheme: String,
    pub low_fee_rebate_scheme: String,
    pub redaction_budget_scheme: String,
    pub operator_summary_scheme: String,
    pub cohort_ttl_blocks: u64,
    pub bucket_ttl_blocks: u64,
    pub grant_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub throttle_window_blocks: u64,
    pub redaction_budget_per_epoch: u32,
    pub min_privacy_set_size: u64,
    pub min_bucket_outputs: u32,
    pub target_bucket_outputs: u32,
    pub max_bucket_outputs: u32,
    pub min_viewtag_entropy_bits: u16,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub low_fee_rebate_bps: u16,
    pub operator_fee_share_bps: u16,
    pub max_scan_fee_micro_units: u64,
    pub pressure_soft_limit_bps: u16,
    pub pressure_hard_limit_bps: u16,
    pub max_operator_summary_fields: u8,
    pub require_pq_attestations: bool,
    pub allow_low_fee_rebates: bool,
    pub operator_summaries_redacted: bool,
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
            scan_cohort_scheme: SCAN_COHORT_SCHEME.to_string(),
            subaddress_bucket_scheme: SUBADDRESS_BUCKET_SCHEME.to_string(),
            viewtag_pressure_scheme: VIEWTAG_PRESSURE_SCHEME.to_string(),
            wallet_scan_grant_scheme: WALLET_SCAN_GRANT_SCHEME.to_string(),
            pq_attestation_scheme: PQ_ATTESTATION_SCHEME.to_string(),
            privacy_throttle_scheme: PRIVACY_THROTTLE_SCHEME.to_string(),
            low_fee_rebate_scheme: LOW_FEE_REBATE_SCHEME.to_string(),
            redaction_budget_scheme: REDACTION_BUDGET_SCHEME.to_string(),
            operator_summary_scheme: OPERATOR_SUMMARY_SCHEME.to_string(),
            cohort_ttl_blocks: DEFAULT_COHORT_TTL_BLOCKS,
            bucket_ttl_blocks: DEFAULT_BUCKET_TTL_BLOCKS,
            grant_ttl_blocks: DEFAULT_GRANT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            throttle_window_blocks: DEFAULT_THROTTLE_WINDOW_BLOCKS,
            redaction_budget_per_epoch: DEFAULT_REDACTION_BUDGET_PER_EPOCH,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_bucket_outputs: DEFAULT_MIN_BUCKET_OUTPUTS,
            target_bucket_outputs: DEFAULT_TARGET_BUCKET_OUTPUTS,
            max_bucket_outputs: DEFAULT_MAX_BUCKET_OUTPUTS,
            min_viewtag_entropy_bits: DEFAULT_MIN_VIEWTAG_ENTROPY_BITS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            operator_fee_share_bps: DEFAULT_OPERATOR_FEE_SHARE_BPS,
            max_scan_fee_micro_units: DEFAULT_MAX_SCAN_FEE_MICRO_UNITS,
            pressure_soft_limit_bps: DEFAULT_PRESSURE_SOFT_LIMIT_BPS,
            pressure_hard_limit_bps: DEFAULT_PRESSURE_HARD_LIMIT_BPS,
            max_operator_summary_fields: DEFAULT_MAX_OPERATOR_SUMMARY_FIELDS,
            require_pq_attestations: true,
            allow_low_fee_rebates: true,
            operator_summaries_redacted: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.protocol_version == PROTOCOL_VERSION,
            "unexpected protocol version {}",
            self.protocol_version
        );
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "unsupported schema version"
        );
        ensure!(self.cohort_ttl_blocks > 0, "cohort ttl must be non-zero");
        ensure!(self.bucket_ttl_blocks > 0, "bucket ttl must be non-zero");
        ensure!(self.grant_ttl_blocks > 0, "grant ttl must be non-zero");
        ensure!(
            self.attestation_ttl_blocks >= self.grant_ttl_blocks,
            "attestations must outlive scan grants"
        );
        ensure!(
            self.throttle_window_blocks > 0,
            "throttle window must be non-zero"
        );
        ensure!(
            self.redaction_budget_per_epoch > 0,
            "redaction budget must be non-zero"
        );
        ensure!(
            self.min_privacy_set_size >= 128,
            "privacy set size below operator-safe floor"
        );
        ensure!(
            self.min_bucket_outputs > 0 && self.target_bucket_outputs >= self.min_bucket_outputs,
            "bucket output target must be above minimum"
        );
        ensure!(
            self.max_bucket_outputs >= self.target_bucket_outputs,
            "bucket output max must be above target"
        );
        ensure!(
            self.min_pq_security_bits <= self.target_pq_security_bits,
            "target pq security below minimum"
        );
        ensure!(
            self.low_fee_rebate_bps <= MAX_BPS && self.operator_fee_share_bps <= MAX_BPS,
            "fee shares cannot exceed 100%"
        );
        ensure!(
            self.low_fee_rebate_bps + self.operator_fee_share_bps <= MAX_BPS,
            "rebate and operator share exceed fee"
        );
        ensure!(
            self.pressure_soft_limit_bps < self.pressure_hard_limit_bps,
            "pressure soft limit must be below hard limit"
        );
        ensure!(
            self.pressure_hard_limit_bps <= MAX_BPS,
            "pressure hard limit cannot exceed 100%"
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
            "scan_cohort_scheme": self.scan_cohort_scheme,
            "subaddress_bucket_scheme": self.subaddress_bucket_scheme,
            "viewtag_pressure_scheme": self.viewtag_pressure_scheme,
            "wallet_scan_grant_scheme": self.wallet_scan_grant_scheme,
            "pq_attestation_scheme": self.pq_attestation_scheme,
            "privacy_throttle_scheme": self.privacy_throttle_scheme,
            "low_fee_rebate_scheme": self.low_fee_rebate_scheme,
            "redaction_budget_scheme": self.redaction_budget_scheme,
            "operator_summary_scheme": self.operator_summary_scheme,
            "cohort_ttl_blocks": self.cohort_ttl_blocks,
            "bucket_ttl_blocks": self.bucket_ttl_blocks,
            "grant_ttl_blocks": self.grant_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "throttle_window_blocks": self.throttle_window_blocks,
            "redaction_budget_per_epoch": self.redaction_budget_per_epoch,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_bucket_outputs": self.min_bucket_outputs,
            "target_bucket_outputs": self.target_bucket_outputs,
            "max_bucket_outputs": self.max_bucket_outputs,
            "min_viewtag_entropy_bits": self.min_viewtag_entropy_bits,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "operator_fee_share_bps": self.operator_fee_share_bps,
            "max_scan_fee_micro_units": self.max_scan_fee_micro_units,
            "pressure_soft_limit_bps": self.pressure_soft_limit_bps,
            "pressure_hard_limit_bps": self.pressure_hard_limit_bps,
            "max_operator_summary_fields": self.max_operator_summary_fields,
            "require_pq_attestations": self.require_pq_attestations,
            "allow_low_fee_rebates": self.allow_low_fee_rebates,
            "operator_summaries_redacted": self.operator_summaries_redacted
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanCohort {
    pub cohort_id: String,
    pub lane: ScanLane,
    pub epoch: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub status: CohortStatus,
    pub min_privacy_set_size: u64,
    pub bucket_count: u32,
    pub wallet_grant_target: u32,
    pub pressure_soft_limit_bps: u16,
    pub pressure_hard_limit_bps: u16,
    pub cohort_commitment_root: String,
    pub redacted_policy_root: String,
    pub operator_hint_root: String,
}

impl ScanCohort {
    pub fn new(
        cohort_id: impl Into<String>,
        lane: ScanLane,
        epoch: u64,
        start_height: u64,
        config: &Config,
    ) -> Self {
        let cohort_id = cohort_id.into();
        let end_height = start_height + config.cohort_ttl_blocks;
        let seed = runtime_hash(
            "SCAN-COHORT-SEED",
            &[HashPart::Str(&cohort_id), HashPart::U64(epoch)],
        );
        Self {
            cohort_id,
            lane,
            epoch,
            start_height,
            end_height,
            status: CohortStatus::Open,
            min_privacy_set_size: config.min_privacy_set_size,
            bucket_count: 0,
            wallet_grant_target: 0,
            pressure_soft_limit_bps: config.pressure_soft_limit_bps,
            pressure_hard_limit_bps: config.pressure_hard_limit_bps,
            cohort_commitment_root: seed.clone(),
            redacted_policy_root: runtime_hash("SCAN-COHORT-POLICY", &[HashPart::Str(&seed)]),
            operator_hint_root: runtime_hash("SCAN-COHORT-OPERATOR-HINT", &[HashPart::Str(&seed)]),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "cohort_id": self.cohort_id,
            "lane": self.lane.as_str(),
            "epoch": self.epoch,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "status": self.status.as_str(),
            "active": self.status.active(),
            "min_privacy_set_size": self.min_privacy_set_size,
            "bucket_count": self.bucket_count,
            "wallet_grant_target": self.wallet_grant_target,
            "pressure_soft_limit_bps": self.pressure_soft_limit_bps,
            "pressure_hard_limit_bps": self.pressure_hard_limit_bps,
            "cohort_commitment_root": self.cohort_commitment_root,
            "redacted_policy_root": self.redacted_policy_root,
            "operator_hint_root": self.operator_hint_root
        })
    }

    pub fn root(&self) -> String {
        record_root("SCAN-COHORT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubaddressBucket {
    pub bucket_id: String,
    pub cohort_id: String,
    pub lane: ScanLane,
    pub status: BucketStatus,
    pub bucket_index: u32,
    pub output_count_floor: u32,
    pub output_count_ceiling: u32,
    pub viewtag_prefix_commitment: String,
    pub subaddress_set_commitment: String,
    pub encrypted_scan_hint_root: String,
    pub decoy_guard_root: String,
    pub expires_at_height: u64,
}

impl SubaddressBucket {
    pub fn new(
        bucket_id: impl Into<String>,
        cohort: &ScanCohort,
        bucket_index: u32,
        config: &Config,
    ) -> Self {
        let bucket_id = bucket_id.into();
        let seed = runtime_hash(
            "SUBADDRESS-BUCKET-SEED",
            &[
                HashPart::Str(&bucket_id),
                HashPart::Str(&cohort.cohort_id),
                HashPart::U64(bucket_index as u64),
            ],
        );
        Self {
            bucket_id,
            cohort_id: cohort.cohort_id.clone(),
            lane: cohort.lane,
            status: BucketStatus::Open,
            bucket_index,
            output_count_floor: config.min_bucket_outputs,
            output_count_ceiling: config.max_bucket_outputs,
            viewtag_prefix_commitment: runtime_hash(
                "BUCKET-VIEWTAG-PREFIX",
                &[HashPart::Str(&seed)],
            ),
            subaddress_set_commitment: runtime_hash(
                "BUCKET-SUBADDRESS-SET",
                &[HashPart::Str(&seed)],
            ),
            encrypted_scan_hint_root: runtime_hash(
                "BUCKET-ENCRYPTED-HINT",
                &[HashPart::Str(&seed)],
            ),
            decoy_guard_root: runtime_hash("BUCKET-DECOY-GUARD", &[HashPart::Str(&seed)]),
            expires_at_height: cohort.start_height + config.bucket_ttl_blocks,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "bucket_id": self.bucket_id,
            "cohort_id": self.cohort_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "scannable": self.status.scannable(),
            "bucket_index": self.bucket_index,
            "output_count_floor": self.output_count_floor,
            "output_count_ceiling": self.output_count_ceiling,
            "viewtag_prefix_commitment": self.viewtag_prefix_commitment,
            "subaddress_set_commitment": self.subaddress_set_commitment,
            "encrypted_scan_hint_root": self.encrypted_scan_hint_root,
            "decoy_guard_root": self.decoy_guard_root,
            "expires_at_height": self.expires_at_height
        })
    }

    pub fn root(&self) -> String {
        record_root("SUBADDRESS-BUCKET", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewtagPressureSignal {
    pub signal_id: String,
    pub cohort_id: String,
    pub bucket_id: String,
    pub lane: ScanLane,
    pub band: PressureBand,
    pub pressure_bps: u16,
    pub queued_wallets_floor: u32,
    pub scan_work_units: u64,
    pub viewtag_entropy_bits: u16,
    pub redacted_histogram_root: String,
    pub pressure_commitment_root: String,
    pub observed_at_height: u64,
}

impl ViewtagPressureSignal {
    pub fn new(
        signal_id: impl Into<String>,
        bucket: &SubaddressBucket,
        pressure_bps: u16,
        queued_wallets_floor: u32,
        scan_work_units: u64,
        viewtag_entropy_bits: u16,
        observed_at_height: u64,
    ) -> Self {
        let signal_id = signal_id.into();
        let band = PressureBand::from_bps(pressure_bps);
        let seed = runtime_hash(
            "VIEWTAG-PRESSURE-SEED",
            &[
                HashPart::Str(&signal_id),
                HashPart::Str(&bucket.bucket_id),
                HashPart::U64(pressure_bps as u64),
            ],
        );
        Self {
            signal_id,
            cohort_id: bucket.cohort_id.clone(),
            bucket_id: bucket.bucket_id.clone(),
            lane: bucket.lane,
            band,
            pressure_bps,
            queued_wallets_floor,
            scan_work_units,
            viewtag_entropy_bits,
            redacted_histogram_root: runtime_hash(
                "PRESSURE-REDACTED-HISTOGRAM",
                &[HashPart::Str(&seed)],
            ),
            pressure_commitment_root: runtime_hash("PRESSURE-COMMITMENT", &[HashPart::Str(&seed)]),
            observed_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "signal_id": self.signal_id,
            "cohort_id": self.cohort_id,
            "bucket_id": self.bucket_id,
            "lane": self.lane.as_str(),
            "band": self.band.as_str(),
            "pressure_bps": self.pressure_bps,
            "queued_wallets_floor": self.queued_wallets_floor,
            "scan_work_units": self.scan_work_units,
            "viewtag_entropy_bits": self.viewtag_entropy_bits,
            "redacted_histogram_root": self.redacted_histogram_root,
            "pressure_commitment_root": self.pressure_commitment_root,
            "observed_at_height": self.observed_at_height
        })
    }

    pub fn root(&self) -> String {
        record_root("VIEWTAG-PRESSURE-SIGNAL", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletScanGrant {
    pub grant_id: String,
    pub wallet_commitment: String,
    pub cohort_id: String,
    pub bucket_id: String,
    pub lane: ScanLane,
    pub status: GrantStatus,
    pub granted_work_units: u64,
    pub priority_weight: u16,
    pub fee_cap_micro_units: u64,
    pub nullifier_fence_root: String,
    pub encrypted_grant_root: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl WalletScanGrant {
    pub fn new(
        grant_id: impl Into<String>,
        wallet_commitment: impl Into<String>,
        bucket: &SubaddressBucket,
        work_units: u64,
        issued_at_height: u64,
        config: &Config,
    ) -> Self {
        let grant_id = grant_id.into();
        let wallet_commitment = wallet_commitment.into();
        let seed = runtime_hash(
            "WALLET-SCAN-GRANT-SEED",
            &[
                HashPart::Str(&grant_id),
                HashPart::Str(&wallet_commitment),
                HashPart::Str(&bucket.bucket_id),
            ],
        );
        Self {
            grant_id,
            wallet_commitment,
            cohort_id: bucket.cohort_id.clone(),
            bucket_id: bucket.bucket_id.clone(),
            lane: bucket.lane,
            status: GrantStatus::Issued,
            granted_work_units: work_units,
            priority_weight: bucket.lane.default_weight(),
            fee_cap_micro_units: bucket
                .lane
                .default_fee_cap()
                .min(config.max_scan_fee_micro_units),
            nullifier_fence_root: runtime_hash("GRANT-NULLIFIER-FENCE", &[HashPart::Str(&seed)]),
            encrypted_grant_root: runtime_hash("GRANT-ENCRYPTED", &[HashPart::Str(&seed)]),
            issued_at_height,
            expires_at_height: issued_at_height + config.grant_ttl_blocks,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "grant_id": self.grant_id,
            "wallet_commitment": self.wallet_commitment,
            "cohort_id": self.cohort_id,
            "bucket_id": self.bucket_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "live": self.status.live(),
            "granted_work_units": self.granted_work_units,
            "priority_weight": self.priority_weight,
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "nullifier_fence_root": self.nullifier_fence_root,
            "encrypted_grant_root": self.encrypted_grant_root,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height
        })
    }

    pub fn root(&self) -> String {
        record_root("WALLET-SCAN-GRANT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub kind: AttestationKind,
    pub subject_id: String,
    pub signer_committee_root: String,
    pub pq_security_bits: u16,
    pub transcript_root: String,
    pub signature_bundle_root: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl PqAttestation {
    pub fn new(
        attestation_id: impl Into<String>,
        kind: AttestationKind,
        subject_id: impl Into<String>,
        issued_at_height: u64,
        config: &Config,
    ) -> Self {
        let attestation_id = attestation_id.into();
        let subject_id = subject_id.into();
        let seed = runtime_hash(
            "PQ-ATTESTATION-SEED",
            &[
                HashPart::Str(&attestation_id),
                HashPart::Str(kind.as_str()),
                HashPart::Str(&subject_id),
            ],
        );
        Self {
            attestation_id,
            kind,
            subject_id,
            signer_committee_root: runtime_hash(
                "PQ-ATTESTATION-COMMITTEE",
                &[HashPart::Str(&seed)],
            ),
            pq_security_bits: config.target_pq_security_bits,
            transcript_root: runtime_hash("PQ-ATTESTATION-TRANSCRIPT", &[HashPart::Str(&seed)]),
            signature_bundle_root: runtime_hash(
                "PQ-ATTESTATION-SIGNATURE",
                &[HashPart::Str(&seed)],
            ),
            issued_at_height,
            expires_at_height: issued_at_height + config.attestation_ttl_blocks,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "signer_committee_root": self.signer_committee_root,
            "pq_security_bits": self.pq_security_bits,
            "transcript_root": self.transcript_root,
            "signature_bundle_root": self.signature_bundle_root,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height
        })
    }

    pub fn root(&self) -> String {
        record_root("PQ-SCAN-THROTTLE-ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyThrottle {
    pub throttle_id: String,
    pub cohort_id: String,
    pub lane: ScanLane,
    pub action: ThrottleAction,
    pub pressure_bps: u16,
    pub grant_share_bps: u16,
    pub delay_blocks: u64,
    pub privacy_set_floor: u64,
    pub fairness_root: String,
    pub decision_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivacyThrottle {
    pub fn new(
        throttle_id: impl Into<String>,
        cohort: &ScanCohort,
        pressure_bps: u16,
        opened_at_height: u64,
        config: &Config,
    ) -> Self {
        let throttle_id = throttle_id.into();
        let action = if pressure_bps >= config.pressure_hard_limit_bps {
            ThrottleAction::SponsorOnly
        } else if pressure_bps >= config.pressure_soft_limit_bps {
            ThrottleAction::Shape
        } else {
            ThrottleAction::Admit
        };
        let grant_share_bps = MAX_BPS.saturating_sub(pressure_bps.saturating_sub(4_000));
        let delay_blocks = match action {
            ThrottleAction::Admit => 0,
            ThrottleAction::Shape => 2,
            ThrottleAction::Delay => 6,
            ThrottleAction::Batch => config.throttle_window_blocks / 2,
            ThrottleAction::SponsorOnly => config.throttle_window_blocks,
            ThrottleAction::EmergencyHold => config.throttle_window_blocks * 2,
        };
        let seed = runtime_hash(
            "PRIVACY-THROTTLE-SEED",
            &[
                HashPart::Str(&throttle_id),
                HashPart::Str(&cohort.cohort_id),
                HashPart::U64(pressure_bps as u64),
            ],
        );
        Self {
            throttle_id,
            cohort_id: cohort.cohort_id.clone(),
            lane: cohort.lane,
            action,
            pressure_bps,
            grant_share_bps,
            delay_blocks,
            privacy_set_floor: cohort.min_privacy_set_size,
            fairness_root: runtime_hash("THROTTLE-FAIRNESS", &[HashPart::Str(&seed)]),
            decision_root: runtime_hash("THROTTLE-DECISION", &[HashPart::Str(&seed)]),
            opened_at_height,
            expires_at_height: opened_at_height + config.throttle_window_blocks,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "throttle_id": self.throttle_id,
            "cohort_id": self.cohort_id,
            "lane": self.lane.as_str(),
            "action": self.action.as_str(),
            "restrictive": self.action.restrictive(),
            "pressure_bps": self.pressure_bps,
            "grant_share_bps": self.grant_share_bps,
            "delay_blocks": self.delay_blocks,
            "privacy_set_floor": self.privacy_set_floor,
            "fairness_root": self.fairness_root,
            "decision_root": self.decision_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height
        })
    }

    pub fn root(&self) -> String {
        record_root("PRIVACY-SCAN-THROTTLE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeScanRebate {
    pub rebate_id: String,
    pub grant_id: String,
    pub cohort_id: String,
    pub wallet_commitment: String,
    pub status: RebateStatus,
    pub fee_paid_micro_units: u64,
    pub rebate_micro_units: u64,
    pub operator_fee_micro_units: u64,
    pub settlement_root: String,
    pub issued_at_height: u64,
}

impl LowFeeScanRebate {
    pub fn from_grant(
        rebate_id: impl Into<String>,
        grant: &WalletScanGrant,
        fee_paid_micro_units: u64,
        issued_at_height: u64,
        config: &Config,
    ) -> Self {
        let rebate_id = rebate_id.into();
        let rebate_micro_units =
            fee_paid_micro_units.saturating_mul(config.low_fee_rebate_bps as u64) / MAX_BPS as u64;
        let operator_fee_micro_units = fee_paid_micro_units
            .saturating_mul(config.operator_fee_share_bps as u64)
            / MAX_BPS as u64;
        let seed = runtime_hash(
            "LOW-FEE-SCAN-REBATE-SEED",
            &[HashPart::Str(&rebate_id), HashPart::Str(&grant.grant_id)],
        );
        Self {
            rebate_id,
            grant_id: grant.grant_id.clone(),
            cohort_id: grant.cohort_id.clone(),
            wallet_commitment: grant.wallet_commitment.clone(),
            status: RebateStatus::Reserved,
            fee_paid_micro_units,
            rebate_micro_units,
            operator_fee_micro_units,
            settlement_root: runtime_hash(
                "LOW-FEE-SCAN-REBATE-SETTLEMENT",
                &[HashPart::Str(&seed)],
            ),
            issued_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "rebate_id": self.rebate_id,
            "grant_id": self.grant_id,
            "cohort_id": self.cohort_id,
            "wallet_commitment": self.wallet_commitment,
            "status": self.status.as_str(),
            "fee_paid_micro_units": self.fee_paid_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "operator_fee_micro_units": self.operator_fee_micro_units,
            "settlement_root": self.settlement_root,
            "issued_at_height": self.issued_at_height
        })
    }

    pub fn root(&self) -> String {
        record_root("LOW-FEE-SCAN-REBATE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub epoch: u64,
    pub subject_root: String,
    pub allowed_fields: u32,
    pub consumed_fields: u32,
    pub operator_scope_root: String,
    pub redaction_root: String,
}

impl RedactionBudget {
    pub fn new(
        budget_id: impl Into<String>,
        epoch: u64,
        subject_root: impl Into<String>,
        allowed_fields: u32,
    ) -> Self {
        let budget_id = budget_id.into();
        let subject_root = subject_root.into();
        let seed = runtime_hash(
            "REDACTION-BUDGET-SEED",
            &[
                HashPart::Str(&budget_id),
                HashPart::U64(epoch),
                HashPart::Str(&subject_root),
            ],
        );
        Self {
            budget_id,
            epoch,
            subject_root,
            allowed_fields,
            consumed_fields: 0,
            operator_scope_root: runtime_hash("REDACTION-OPERATOR-SCOPE", &[HashPart::Str(&seed)]),
            redaction_root: runtime_hash("REDACTION-BUDGET-ROOT", &[HashPart::Str(&seed)]),
        }
    }

    pub fn consume(&mut self, fields: u32) -> Result<()> {
        ensure!(
            self.consumed_fields + fields <= self.allowed_fields,
            "redaction budget {} exceeded",
            self.budget_id
        );
        self.consumed_fields += fields;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "budget_id": self.budget_id,
            "epoch": self.epoch,
            "subject_root": self.subject_root,
            "allowed_fields": self.allowed_fields,
            "consumed_fields": self.consumed_fields,
            "remaining_fields": self.allowed_fields.saturating_sub(self.consumed_fields),
            "operator_scope_root": self.operator_scope_root,
            "redaction_root": self.redaction_root
        })
    }

    pub fn root(&self) -> String {
        record_root("REDACTION-BUDGET", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSafeSummary {
    pub summary_id: String,
    pub epoch: u64,
    pub lane: ScanLane,
    pub cohort_count: u32,
    pub bucket_count: u32,
    pub grant_count: u32,
    pub throttle_count: u32,
    pub average_pressure_bps: u16,
    pub max_pressure_band: PressureBand,
    pub low_fee_rebate_total_micro_units: u64,
    pub redaction_budget_root: String,
    pub summary_root: String,
}

impl OperatorSafeSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "summary_id": self.summary_id,
            "epoch": self.epoch,
            "lane": self.lane.as_str(),
            "cohort_count": self.cohort_count,
            "bucket_count": self.bucket_count,
            "grant_count": self.grant_count,
            "throttle_count": self.throttle_count,
            "average_pressure_bps": self.average_pressure_bps,
            "max_pressure_band": self.max_pressure_band.as_str(),
            "low_fee_rebate_total_micro_units": self.low_fee_rebate_total_micro_units,
            "redaction_budget_root": self.redaction_budget_root,
            "summary_root": self.summary_root
        })
    }

    pub fn root(&self) -> String {
        record_root("OPERATOR-SAFE-SUMMARY", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub scan_cohorts: u64,
    pub subaddress_buckets: u64,
    pub viewtag_pressure_signals: u64,
    pub wallet_scan_grants: u64,
    pub pq_attestations: u64,
    pub privacy_throttles: u64,
    pub low_fee_rebates: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub active_cohorts: u64,
    pub live_grants: u64,
    pub restrictive_throttles: u64,
    pub total_rebate_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "scan_cohorts": self.scan_cohorts,
            "subaddress_buckets": self.subaddress_buckets,
            "viewtag_pressure_signals": self.viewtag_pressure_signals,
            "wallet_scan_grants": self.wallet_scan_grants,
            "pq_attestations": self.pq_attestations,
            "privacy_throttles": self.privacy_throttles,
            "low_fee_rebates": self.low_fee_rebates,
            "redaction_budgets": self.redaction_budgets,
            "operator_summaries": self.operator_summaries,
            "active_cohorts": self.active_cohorts,
            "live_grants": self.live_grants,
            "restrictive_throttles": self.restrictive_throttles,
            "total_rebate_micro_units": self.total_rebate_micro_units
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub scan_cohort_root: String,
    pub subaddress_bucket_root: String,
    pub viewtag_pressure_root: String,
    pub wallet_scan_grant_root: String,
    pub pq_attestation_root: String,
    pub privacy_throttle_root: String,
    pub low_fee_rebate_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "scan_cohort_root": self.scan_cohort_root,
            "subaddress_bucket_root": self.subaddress_bucket_root,
            "viewtag_pressure_root": self.viewtag_pressure_root,
            "wallet_scan_grant_root": self.wallet_scan_grant_root,
            "pq_attestation_root": self.pq_attestation_root,
            "privacy_throttle_root": self.privacy_throttle_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "redaction_budget_root": self.redaction_budget_root,
            "operator_summary_root": self.operator_summary_root,
            "public_record_root": self.public_record_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub scan_cohorts: BTreeMap<String, ScanCohort>,
    pub subaddress_buckets: BTreeMap<String, SubaddressBucket>,
    pub viewtag_pressure_signals: BTreeMap<String, ViewtagPressureSignal>,
    pub wallet_scan_grants: BTreeMap<String, WalletScanGrant>,
    pub pq_attestations: BTreeMap<String, PqAttestation>,
    pub privacy_throttles: BTreeMap<String, PrivacyThrottle>,
    pub low_fee_rebates: BTreeMap<String, LowFeeScanRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSafeSummary>,
    pub seen_wallet_commitments: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            config: Config::default(),
            scan_cohorts: BTreeMap::new(),
            subaddress_buckets: BTreeMap::new(),
            viewtag_pressure_signals: BTreeMap::new(),
            wallet_scan_grants: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            privacy_throttles: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            seen_wallet_commitments: BTreeSet::new(),
        }
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::default();
        state.seed_devnet();
        state
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        ensure!(
            self.scan_cohorts.len() <= MAX_SCAN_COHORTS,
            "too many scan cohorts"
        );
        ensure!(
            self.subaddress_buckets.len() <= MAX_SUBADDRESS_BUCKETS,
            "too many subaddress buckets"
        );
        ensure!(
            self.viewtag_pressure_signals.len() <= MAX_VIEWTAG_PRESSURE_SIGNALS,
            "too many viewtag pressure signals"
        );
        ensure!(
            self.wallet_scan_grants.len() <= MAX_WALLET_SCAN_GRANTS,
            "too many wallet scan grants"
        );
        ensure!(
            self.pq_attestations.len() <= MAX_PQ_ATTESTATIONS,
            "too many attestations"
        );
        ensure!(
            self.privacy_throttles.len() <= MAX_PRIVACY_THROTTLES,
            "too many privacy throttles"
        );
        ensure!(
            self.low_fee_rebates.len() <= MAX_LOW_FEE_REBATES,
            "too many rebates"
        );
        ensure!(
            self.redaction_budgets.len() <= MAX_REDACTION_BUDGETS,
            "too many redaction budgets"
        );
        ensure!(
            self.operator_summaries.len() <= MAX_OPERATOR_SUMMARIES,
            "too many operator summaries"
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": self.counters().public_record(),
            "scan_cohorts": records_from_map(&self.scan_cohorts, ScanCohort::public_record),
            "subaddress_buckets": records_from_map(&self.subaddress_buckets, SubaddressBucket::public_record),
            "viewtag_pressure_signals": records_from_map(&self.viewtag_pressure_signals, ViewtagPressureSignal::public_record),
            "wallet_scan_grants": records_from_map(&self.wallet_scan_grants, WalletScanGrant::public_record),
            "pq_attestations": records_from_map(&self.pq_attestations, PqAttestation::public_record),
            "privacy_throttles": records_from_map(&self.privacy_throttles, PrivacyThrottle::public_record),
            "low_fee_rebates": records_from_map(&self.low_fee_rebates, LowFeeScanRebate::public_record),
            "redaction_budgets": records_from_map(&self.redaction_budgets, RedactionBudget::public_record),
            "operator_summaries": records_from_map(&self.operator_summaries, OperatorSafeSummary::public_record)
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "SUBADDRESS-VIEWTAG-SCAN-THROTTLE-STATE",
            &self.public_record(),
        )
    }

    pub fn counters(&self) -> Counters {
        Counters {
            scan_cohorts: self.scan_cohorts.len() as u64,
            subaddress_buckets: self.subaddress_buckets.len() as u64,
            viewtag_pressure_signals: self.viewtag_pressure_signals.len() as u64,
            wallet_scan_grants: self.wallet_scan_grants.len() as u64,
            pq_attestations: self.pq_attestations.len() as u64,
            privacy_throttles: self.privacy_throttles.len() as u64,
            low_fee_rebates: self.low_fee_rebates.len() as u64,
            redaction_budgets: self.redaction_budgets.len() as u64,
            operator_summaries: self.operator_summaries.len() as u64,
            active_cohorts: self
                .scan_cohorts
                .values()
                .filter(|cohort| cohort.status.active())
                .count() as u64,
            live_grants: self
                .wallet_scan_grants
                .values()
                .filter(|grant| grant.status.live())
                .count() as u64,
            restrictive_throttles: self
                .privacy_throttles
                .values()
                .filter(|throttle| throttle.action.restrictive())
                .count() as u64,
            total_rebate_micro_units: self
                .low_fee_rebates
                .values()
                .map(|rebate| rebate.rebate_micro_units)
                .sum(),
        }
    }

    pub fn roots(&self) -> Roots {
        let config_root = record_root("SCAN-THROTTLE-CONFIG", &self.config.public_record());
        let scan_cohort_root = map_root(
            "SCAN-COHORTS",
            &self.scan_cohorts,
            ScanCohort::public_record,
        );
        let subaddress_bucket_root = map_root(
            "SUBADDRESS-BUCKETS",
            &self.subaddress_buckets,
            SubaddressBucket::public_record,
        );
        let viewtag_pressure_root = map_root(
            "VIEWTAG-PRESSURES",
            &self.viewtag_pressure_signals,
            ViewtagPressureSignal::public_record,
        );
        let wallet_scan_grant_root = map_root(
            "WALLET-SCAN-GRANTS",
            &self.wallet_scan_grants,
            WalletScanGrant::public_record,
        );
        let pq_attestation_root = map_root(
            "PQ-SCAN-THROTTLE-ATTESTATIONS",
            &self.pq_attestations,
            PqAttestation::public_record,
        );
        let privacy_throttle_root = map_root(
            "PRIVACY-SCAN-THROTTLES",
            &self.privacy_throttles,
            PrivacyThrottle::public_record,
        );
        let low_fee_rebate_root = map_root(
            "LOW-FEE-SCAN-REBATES",
            &self.low_fee_rebates,
            LowFeeScanRebate::public_record,
        );
        let redaction_budget_root = map_root(
            "SCAN-REDACTION-BUDGETS",
            &self.redaction_budgets,
            RedactionBudget::public_record,
        );
        let operator_summary_root = map_root(
            "OPERATOR-SAFE-SCAN-SUMMARIES",
            &self.operator_summaries,
            OperatorSafeSummary::public_record,
        );
        let public_record_root = record_root(
            "SCAN-THROTTLE-PUBLIC-ROOTS",
            &json!({
                "config_root": config_root,
                "scan_cohort_root": scan_cohort_root,
                "subaddress_bucket_root": subaddress_bucket_root,
                "viewtag_pressure_root": viewtag_pressure_root,
                "wallet_scan_grant_root": wallet_scan_grant_root,
                "pq_attestation_root": pq_attestation_root,
                "privacy_throttle_root": privacy_throttle_root,
                "low_fee_rebate_root": low_fee_rebate_root,
                "redaction_budget_root": redaction_budget_root,
                "operator_summary_root": operator_summary_root
            }),
        );
        Roots {
            config_root,
            scan_cohort_root,
            subaddress_bucket_root,
            viewtag_pressure_root,
            wallet_scan_grant_root,
            pq_attestation_root,
            privacy_throttle_root,
            low_fee_rebate_root,
            redaction_budget_root,
            operator_summary_root,
            public_record_root,
        }
    }

    pub fn insert_cohort(&mut self, cohort: ScanCohort) -> Result<()> {
        ensure!(
            self.scan_cohorts.len() < MAX_SCAN_COHORTS,
            "scan cohort capacity exceeded"
        );
        ensure!(
            !self.scan_cohorts.contains_key(&cohort.cohort_id),
            "scan cohort {} already exists",
            cohort.cohort_id
        );
        self.scan_cohorts.insert(cohort.cohort_id.clone(), cohort);
        Ok(())
    }

    pub fn insert_bucket(&mut self, bucket: SubaddressBucket) -> Result<()> {
        ensure!(
            self.subaddress_buckets.len() < MAX_SUBADDRESS_BUCKETS,
            "subaddress bucket capacity exceeded"
        );
        ensure!(
            self.scan_cohorts.contains_key(&bucket.cohort_id),
            "missing cohort {} for bucket {}",
            bucket.cohort_id,
            bucket.bucket_id
        );
        ensure!(
            !self.subaddress_buckets.contains_key(&bucket.bucket_id),
            "subaddress bucket {} already exists",
            bucket.bucket_id
        );
        if let Some(cohort) = self.scan_cohorts.get_mut(&bucket.cohort_id) {
            cohort.bucket_count = cohort.bucket_count.saturating_add(1);
            cohort.status = CohortStatus::Bucketed;
        }
        self.subaddress_buckets
            .insert(bucket.bucket_id.clone(), bucket);
        Ok(())
    }

    pub fn insert_pressure_signal(&mut self, signal: ViewtagPressureSignal) -> Result<()> {
        ensure!(
            self.viewtag_pressure_signals.len() < MAX_VIEWTAG_PRESSURE_SIGNALS,
            "viewtag pressure capacity exceeded"
        );
        ensure!(
            self.subaddress_buckets.contains_key(&signal.bucket_id),
            "missing bucket {} for pressure signal {}",
            signal.bucket_id,
            signal.signal_id
        );
        ensure!(
            signal.pressure_bps <= MAX_BPS,
            "pressure bps cannot exceed 100%"
        );
        if let Some(cohort) = self.scan_cohorts.get_mut(&signal.cohort_id) {
            cohort.status = CohortStatus::Pressurized;
        }
        self.viewtag_pressure_signals
            .insert(signal.signal_id.clone(), signal);
        Ok(())
    }

    pub fn insert_wallet_scan_grant(&mut self, grant: WalletScanGrant) -> Result<()> {
        ensure!(
            self.wallet_scan_grants.len() < MAX_WALLET_SCAN_GRANTS,
            "wallet scan grant capacity exceeded"
        );
        ensure!(
            self.subaddress_buckets.contains_key(&grant.bucket_id),
            "missing bucket {} for grant {}",
            grant.bucket_id,
            grant.grant_id
        );
        ensure!(
            !self.wallet_scan_grants.contains_key(&grant.grant_id),
            "wallet scan grant {} already exists",
            grant.grant_id
        );
        self.seen_wallet_commitments
            .insert(grant.wallet_commitment.clone());
        if let Some(cohort) = self.scan_cohorts.get_mut(&grant.cohort_id) {
            cohort.wallet_grant_target = cohort.wallet_grant_target.saturating_add(1);
            cohort.status = CohortStatus::Granting;
        }
        self.wallet_scan_grants
            .insert(grant.grant_id.clone(), grant);
        Ok(())
    }

    pub fn insert_pq_attestation(&mut self, attestation: PqAttestation) -> Result<()> {
        ensure!(
            self.pq_attestations.len() < MAX_PQ_ATTESTATIONS,
            "pq attestation capacity exceeded"
        );
        ensure!(
            attestation.pq_security_bits >= self.config.min_pq_security_bits,
            "pq attestation below security floor"
        );
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(())
    }

    pub fn insert_privacy_throttle(&mut self, throttle: PrivacyThrottle) -> Result<()> {
        ensure!(
            self.privacy_throttles.len() < MAX_PRIVACY_THROTTLES,
            "privacy throttle capacity exceeded"
        );
        ensure!(
            self.scan_cohorts.contains_key(&throttle.cohort_id),
            "missing cohort {} for throttle {}",
            throttle.cohort_id,
            throttle.throttle_id
        );
        if let Some(cohort) = self.scan_cohorts.get_mut(&throttle.cohort_id) {
            cohort.status = if throttle.action.restrictive() {
                CohortStatus::Throttled
            } else {
                CohortStatus::Granting
            };
        }
        self.privacy_throttles
            .insert(throttle.throttle_id.clone(), throttle);
        Ok(())
    }

    pub fn insert_low_fee_rebate(&mut self, rebate: LowFeeScanRebate) -> Result<()> {
        ensure!(
            self.config.allow_low_fee_rebates,
            "low fee scan rebates are disabled"
        );
        ensure!(
            self.low_fee_rebates.len() < MAX_LOW_FEE_REBATES,
            "low fee rebate capacity exceeded"
        );
        ensure!(
            self.wallet_scan_grants.contains_key(&rebate.grant_id),
            "missing grant {} for rebate {}",
            rebate.grant_id,
            rebate.rebate_id
        );
        if let Some(cohort) = self.scan_cohorts.get_mut(&rebate.cohort_id) {
            cohort.status = CohortStatus::RebateReady;
        }
        self.low_fee_rebates
            .insert(rebate.rebate_id.clone(), rebate);
        Ok(())
    }

    pub fn insert_redaction_budget(&mut self, budget: RedactionBudget) -> Result<()> {
        ensure!(
            self.redaction_budgets.len() < MAX_REDACTION_BUDGETS,
            "redaction budget capacity exceeded"
        );
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        Ok(())
    }

    pub fn insert_operator_summary(&mut self, summary: OperatorSafeSummary) -> Result<()> {
        ensure!(
            self.operator_summaries.len() < MAX_OPERATOR_SUMMARIES,
            "operator summary capacity exceeded"
        );
        self.operator_summaries
            .insert(summary.summary_id.clone(), summary);
        Ok(())
    }

    fn seed_devnet(&mut self) {
        let cohort_specs = [
            (
                "cohort-foreground-0",
                ScanLane::ForegroundWallet,
                0,
                DEVNET_HEIGHT,
            ),
            (
                "cohort-restore-0",
                ScanLane::WalletRestore,
                0,
                DEVNET_HEIGHT + 16,
            ),
            (
                "cohort-bridge-withdrawal-0",
                ScanLane::BridgeWithdrawal,
                0,
                DEVNET_HEIGHT + 32,
            ),
        ];
        for (cohort_id, lane, epoch, start_height) in cohort_specs {
            let cohort = ScanCohort::new(cohort_id, lane, epoch, start_height, &self.config);
            self.insert_cohort(cohort)
                .expect("devnet scan cohort insertion");
        }

        let cohort_ids = self.scan_cohorts.keys().cloned().collect::<Vec<_>>();
        for (cohort_offset, cohort_id) in cohort_ids.iter().enumerate() {
            let cohort = self.scan_cohorts[cohort_id].clone();
            for bucket_index in 0..3 {
                let bucket_id = format!("{cohort_id}-bucket-{bucket_index}");
                let bucket = SubaddressBucket::new(bucket_id, &cohort, bucket_index, &self.config);
                self.insert_bucket(bucket)
                    .expect("devnet subaddress bucket insertion");
            }
            let subject_root = self.scan_cohorts[cohort_id].root();
            let budget = RedactionBudget::new(
                format!("{cohort_id}-redaction-budget"),
                DEVNET_EPOCH + cohort_offset as u64,
                subject_root,
                self.config.redaction_budget_per_epoch,
            );
            self.insert_redaction_budget(budget)
                .expect("devnet redaction budget insertion");
        }

        let bucket_ids = self.subaddress_buckets.keys().cloned().collect::<Vec<_>>();
        for (index, bucket_id) in bucket_ids.iter().enumerate() {
            let bucket = self.subaddress_buckets[bucket_id].clone();
            let pressure_bps = 4_800 + (index as u16 * 650);
            let signal = ViewtagPressureSignal::new(
                format!("{bucket_id}-pressure"),
                &bucket,
                pressure_bps,
                32 + index as u32,
                9_000 + index as u64 * 1_250,
                self.config.min_viewtag_entropy_bits + (index as u16 % 4),
                DEVNET_HEIGHT + 48 + index as u64,
            );
            self.insert_pressure_signal(signal)
                .expect("devnet viewtag pressure insertion");
            let grant = WalletScanGrant::new(
                format!("{bucket_id}-grant"),
                runtime_hash("DEVNET-WALLET-COMMITMENT", &[HashPart::Str(bucket_id)]),
                &bucket,
                4_096 + index as u64 * 128,
                DEVNET_HEIGHT + 64 + index as u64,
                &self.config,
            );
            self.insert_wallet_scan_grant(grant.clone())
                .expect("devnet wallet scan grant insertion");
            let attestation = PqAttestation::new(
                format!("{bucket_id}-grant-attestation"),
                AttestationKind::WalletGrantFairness,
                grant.grant_id.clone(),
                DEVNET_HEIGHT + 72 + index as u64,
                &self.config,
            );
            self.insert_pq_attestation(attestation)
                .expect("devnet pq attestation insertion");
            let rebate = LowFeeScanRebate::from_grant(
                format!("{bucket_id}-rebate"),
                &grant,
                grant.fee_cap_micro_units / 2,
                DEVNET_HEIGHT + 80 + index as u64,
                &self.config,
            );
            self.insert_low_fee_rebate(rebate)
                .expect("devnet low fee rebate insertion");
        }

        let cohort_ids = self.scan_cohorts.keys().cloned().collect::<Vec<_>>();
        for (index, cohort_id) in cohort_ids.iter().enumerate() {
            let cohort = self.scan_cohorts[cohort_id].clone();
            let pressure_bps = 5_600 + index as u16 * 1_200;
            let throttle = PrivacyThrottle::new(
                format!("{cohort_id}-throttle"),
                &cohort,
                pressure_bps,
                DEVNET_HEIGHT + 96 + index as u64,
                &self.config,
            );
            self.insert_privacy_throttle(throttle)
                .expect("devnet privacy throttle insertion");
        }

        for lane in [
            ScanLane::ForegroundWallet,
            ScanLane::WalletRestore,
            ScanLane::BridgeWithdrawal,
        ] {
            let summary = self.build_operator_summary(
                format!("operator-summary-{}", lane.as_str()),
                DEVNET_EPOCH,
                lane,
            );
            self.insert_operator_summary(summary)
                .expect("devnet operator summary insertion");
        }
        self.validate().expect("devnet scan throttle state");
    }

    pub fn build_operator_summary(
        &self,
        summary_id: impl Into<String>,
        epoch: u64,
        lane: ScanLane,
    ) -> OperatorSafeSummary {
        let summary_id = summary_id.into();
        let cohort_count = self
            .scan_cohorts
            .values()
            .filter(|cohort| cohort.lane == lane && cohort.epoch <= epoch)
            .count() as u32;
        let bucket_count = self
            .subaddress_buckets
            .values()
            .filter(|bucket| bucket.lane == lane)
            .count() as u32;
        let grant_count = self
            .wallet_scan_grants
            .values()
            .filter(|grant| grant.lane == lane)
            .count() as u32;
        let throttle_count = self
            .privacy_throttles
            .values()
            .filter(|throttle| throttle.lane == lane)
            .count() as u32;
        let pressures = self
            .viewtag_pressure_signals
            .values()
            .filter(|signal| signal.lane == lane)
            .collect::<Vec<_>>();
        let average_pressure_bps = if pressures.is_empty() {
            0
        } else {
            (pressures
                .iter()
                .map(|signal| signal.pressure_bps as u64)
                .sum::<u64>()
                / pressures.len() as u64) as u16
        };
        let max_pressure_band = pressures
            .iter()
            .map(|signal| signal.band)
            .max()
            .unwrap_or(PressureBand::Idle);
        let low_fee_rebate_total_micro_units = self
            .low_fee_rebates
            .values()
            .filter(|rebate| {
                self.wallet_scan_grants
                    .get(&rebate.grant_id)
                    .map(|grant| grant.lane == lane)
                    .unwrap_or(false)
            })
            .map(|rebate| rebate.rebate_micro_units)
            .sum();
        let redaction_budget_root = map_root(
            "SUMMARY-REDACTION-BUDGETS",
            &self.redaction_budgets,
            RedactionBudget::public_record,
        );
        let summary_seed = runtime_hash(
            "OPERATOR-SAFE-SUMMARY-SEED",
            &[
                HashPart::Str(&summary_id),
                HashPart::U64(epoch),
                HashPart::Str(lane.as_str()),
            ],
        );
        OperatorSafeSummary {
            summary_id,
            epoch,
            lane,
            cohort_count,
            bucket_count,
            grant_count,
            throttle_count,
            average_pressure_bps,
            max_pressure_band,
            low_fee_rebate_total_micro_units,
            redaction_budget_root,
            summary_root: runtime_hash(
                "OPERATOR-SAFE-SUMMARY-ROOT",
                &[HashPart::Str(&summary_seed)],
            ),
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn runtime_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("SUBADDRESS-VIEWTAG-SCAN-THROTTLE:{domain}"),
        parts,
        32,
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    runtime_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| json!({"key": key, "value": record(value)}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("SUBADDRESS-VIEWTAG-SCAN-THROTTLE:{domain}"),
        &leaves,
    )
}

fn records_from_map<T, F>(map: &BTreeMap<String, T>, record: F) -> Vec<Value>
where
    F: Fn(&T) -> Value,
{
    map.values().map(record).collect()
}
