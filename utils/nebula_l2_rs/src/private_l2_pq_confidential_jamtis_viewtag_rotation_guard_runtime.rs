use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialJamtisViewtagRotationGuardRuntimeResult<T> = Result<T>;

macro_rules! ensure {
    ($condition:expr, $message:expr $(,)?) => {
        if !$condition {
            return Err($message.to_string());
        }
    };
    ($condition:expr, $format:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($format, $($arg)+));
        }
    };
}

pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-jamtis-viewtag-rotation-guard-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_PQ_ATTESTATION_SUITE:
    &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-jamtis-viewtag-rotation-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_POLICY_SCHEME: &str =
    "monero-l2-jamtis-viewtag-rotation-policy-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_COHORT_SCHEME: &str =
    "monero-l2-wallet-scan-privacy-cohort-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_COLLISION_SCHEME: &str =
    "monero-l2-viewtag-collision-signal-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_STEALTH_SCHEME: &str =
    "monero-l2-stealth-address-hygiene-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_ATTESTATION_SCHEME:
    &str = "pq-confidential-jamtis-rotation-attestation-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_BATCH_SCHEME: &str =
    "low-fee-jamtis-viewtag-rotation-batch-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_SETTLEMENT_SCHEME: &str =
    "monero-l2-jamtis-viewtag-rotation-settlement-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_REBATE_SCHEME: &str =
    "low-fee-jamtis-viewtag-rotation-rebate-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_REDACTION_SCHEME: &str =
    "redacted-jamtis-operator-summary-budget-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEVNET_HEIGHT: u64 =
    934_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MONERO_NETWORK:
    &str = "monero-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_L2_NETWORK:
    &str = "nebula-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_FEE_ASSET_ID:
    &str = "piconero-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_LOW_FEE_LANE:
    &str = "devnet-jamtis-viewtag-rotation-low-fee";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_WATCHER_SET_ID:
    &str = "devnet-jamtis-viewtag-rotation-watchers";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MAX_POLICIES:
    usize = 65_536;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MAX_COHORTS:
    usize = 524_288;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MAX_COLLISIONS:
    usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MAX_STEALTH:
    usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MAX_ATTESTATIONS:
    usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MAX_BATCHES:
    usize = 262_144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MAX_SETTLEMENTS:
    usize = 262_144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MAX_REBATES:
    usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MAX_REDACTIONS:
    usize = 131_072;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MAX_SUMMARIES:
    usize = 131_072;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MAX_BATCH_ITEMS:
    usize = 1_024;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MIN_PRIVACY_SET:
    u64 = 65_536;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_TARGET_PRIVACY_SET:
    u64 = 262_144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MIN_COHORT_SIZE:
    u64 = 4_096;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MIN_PQ_BITS:
    u16 = 256;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MAX_USER_FEE_BPS:
    u64 = 8;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_LOW_FEE_BPS:
    u64 = 3;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_REBATE_BPS: u64 =
    6;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_COLLISION_LIMIT:
    u64 = 2;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_ROTATION_TTL:
    u64 = 720;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_ATTESTATION_TTL:
    u64 = 144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_SETTLEMENT_TTL:
    u64 = 32;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationCadence {
    Emergency,
    PerEpoch,
    CollisionTriggered,
    WalletUpgrade,
    ScanLoadRebalance,
    OperatorScheduled,
}

impl RotationCadence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Emergency => "emergency",
            Self::PerEpoch => "per_epoch",
            Self::CollisionTriggered => "collision_triggered",
            Self::WalletUpgrade => "wallet_upgrade",
            Self::ScanLoadRebalance => "scan_load_rebalance",
            Self::OperatorScheduled => "operator_scheduled",
        }
    }

    pub fn urgency_weight(self) -> u64 {
        match self {
            Self::Emergency => 1_000,
            Self::CollisionTriggered => 900,
            Self::WalletUpgrade => 760,
            Self::ScanLoadRebalance => 680,
            Self::OperatorScheduled => 620,
            Self::PerEpoch => 560,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationPolicyStatus {
    Draft,
    Active,
    Throttled,
    CollisionOnly,
    Paused,
    Retired,
}

impl RotationPolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::CollisionOnly => "collision_only",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_rotation(self) -> bool {
        matches!(self, Self::Active | Self::Throttled | Self::CollisionOnly)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortStatus {
    Sealed,
    Sampling,
    Eligible,
    Rotating,
    Settled,
    Quarantined,
}

impl CohortStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Sampling => "sampling",
            Self::Eligible => "eligible",
            Self::Rotating => "rotating",
            Self::Settled => "settled",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Sampling | Self::Eligible | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollisionSeverity {
    Informational,
    Watch,
    Elevated,
    Critical,
    Quarantine,
}

impl CollisionSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Watch => "watch",
            Self::Elevated => "elevated",
            Self::Critical => "critical",
            Self::Quarantine => "quarantine",
        }
    }

    pub fn requires_rotation(self) -> bool {
        matches!(self, Self::Elevated | Self::Critical | Self::Quarantine)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StealthHygieneVerdict {
    Clean,
    ReuseWatch,
    DecoyWeakness,
    ViewtagCollision,
    LinkageRisk,
    Quarantined,
}

impl StealthHygieneVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::ReuseWatch => "reuse_watch",
            Self::DecoyWeakness => "decoy_weakness",
            Self::ViewtagCollision => "viewtag_collision",
            Self::LinkageRisk => "linkage_risk",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn permits_batching(self) -> bool {
        matches!(self, Self::Clean | Self::ReuseWatch | Self::DecoyWeakness)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAttestationStatus {
    Proposed,
    Verified,
    Bound,
    Rotated,
    Rejected,
    Expired,
    Revoked,
}

impl PqAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Verified => "verified",
            Self::Bound => "bound",
            Self::Rotated => "rotated",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Verified | Self::Bound | Self::Rotated)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    PrivacyChecked,
    Attested,
    Submitted,
    Settled,
    Disputed,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::PrivacyChecked => "privacy_checked",
            Self::Attested => "attested",
            Self::Submitted => "submitted",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Pending,
    Finalized,
    RebateQueued,
    Reverted,
    Disputed,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Finalized => "finalized",
            Self::RebateQueued => "rebate_queued",
            Self::Reverted => "reverted",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionClass {
    WalletScan,
    ViewtagHistogram,
    StealthAddress,
    OperatorMetric,
    FeeTrace,
    AuditOnly,
}

impl RedactionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletScan => "wallet_scan",
            Self::ViewtagHistogram => "viewtag_histogram",
            Self::StealthAddress => "stealth_address",
            Self::OperatorMetric => "operator_metric",
            Self::FeeTrace => "fee_trace",
            Self::AuditOnly => "audit_only",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub monero_network: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub low_fee_lane: String,
    pub watcher_set_id: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_wallet_cohort_size: u64,
    pub min_pq_security_bits: u16,
    pub max_viewtag_collisions_per_epoch: u64,
    pub max_user_fee_bps: u64,
    pub low_fee_bps: u64,
    pub rebate_bps: u64,
    pub rotation_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub max_batch_items: usize,
    pub max_rotation_policies: usize,
    pub max_wallet_cohorts: usize,
    pub max_collision_signals: usize,
    pub max_stealth_hygiene_records: usize,
    pub max_pq_attestations: usize,
    pub max_rotation_batches: usize,
    pub max_rotation_settlements: usize,
    pub max_fee_rebates: usize,
    pub max_redaction_budgets: usize,
    pub max_operator_summaries: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            monero_network:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MONERO_NETWORK
                    .to_string(),
            l2_network:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_L2_NETWORK
                    .to_string(),
            fee_asset_id:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_FEE_ASSET_ID
                    .to_string(),
            low_fee_lane:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_LOW_FEE_LANE
                    .to_string(),
            watcher_set_id:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_WATCHER_SET_ID
                    .to_string(),
            min_privacy_set_size:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            target_privacy_set_size:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_TARGET_PRIVACY_SET,
            min_wallet_cohort_size:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MIN_COHORT_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MIN_PQ_BITS,
            max_viewtag_collisions_per_epoch:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_COLLISION_LIMIT,
            max_user_fee_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            low_fee_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_LOW_FEE_BPS,
            rebate_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_REBATE_BPS,
            rotation_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_ROTATION_TTL,
            attestation_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_ATTESTATION_TTL,
            settlement_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_SETTLEMENT_TTL,
            max_batch_items:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MAX_BATCH_ITEMS,
            max_rotation_policies:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MAX_POLICIES,
            max_wallet_cohorts:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MAX_COHORTS,
            max_collision_signals:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MAX_COLLISIONS,
            max_stealth_hygiene_records:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MAX_STEALTH,
            max_pq_attestations:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MAX_ATTESTATIONS,
            max_rotation_batches:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MAX_BATCHES,
            max_rotation_settlements:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MAX_SETTLEMENTS,
            max_fee_rebates:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MAX_REBATES,
            max_redaction_budgets:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MAX_REDACTIONS,
            max_operator_summaries:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEFAULT_MAX_SUMMARIES,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.min_privacy_set_size >= self.min_wallet_cohort_size,
            "privacy set must cover at least one wallet cohort"
        );
        ensure!(
            self.target_privacy_set_size >= self.min_privacy_set_size,
            "target privacy set below configured minimum"
        );
        ensure!(self.min_pq_security_bits >= 192, "pq security below floor");
        ensure!(
            self.max_user_fee_bps
                <= PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_MAX_BPS,
            "max user fee exceeds bps denominator"
        );
        ensure!(
            self.low_fee_bps <= self.max_user_fee_bps,
            "low fee exceeds max"
        );
        ensure!(
            self.rebate_bps <= self.max_user_fee_bps,
            "rebate exceeds max"
        );
        ensure!(self.max_batch_items > 0, "max batch items must be positive");
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "low_fee_lane": self.low_fee_lane,
            "watcher_set_id": self.watcher_set_id,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_wallet_cohort_size": self.min_wallet_cohort_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_viewtag_collisions_per_epoch": self.max_viewtag_collisions_per_epoch,
            "max_user_fee_bps": self.max_user_fee_bps,
            "low_fee_bps": self.low_fee_bps,
            "rebate_bps": self.rebate_bps,
            "rotation_ttl_blocks": self.rotation_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "max_batch_items": self.max_batch_items,
            "limits": {
                "rotation_policies": self.max_rotation_policies,
                "wallet_cohorts": self.max_wallet_cohorts,
                "collision_signals": self.max_collision_signals,
                "stealth_hygiene_records": self.max_stealth_hygiene_records,
                "pq_attestations": self.max_pq_attestations,
                "rotation_batches": self.max_rotation_batches,
                "rotation_settlements": self.max_rotation_settlements,
                "fee_rebates": self.max_fee_rebates,
                "redaction_budgets": self.max_redaction_budgets,
                "operator_summaries": self.max_operator_summaries,
            }
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub rotation_policies: u64,
    pub wallet_cohorts: u64,
    pub collision_signals: u64,
    pub stealth_hygiene_records: u64,
    pub pq_attestations: u64,
    pub rotation_batches: u64,
    pub rotation_settlements: u64,
    pub fee_rebates: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "rotation_policies": self.rotation_policies,
            "wallet_cohorts": self.wallet_cohorts,
            "collision_signals": self.collision_signals,
            "stealth_hygiene_records": self.stealth_hygiene_records,
            "pq_attestations": self.pq_attestations,
            "rotation_batches": self.rotation_batches,
            "rotation_settlements": self.rotation_settlements,
            "fee_rebates": self.fee_rebates,
            "redaction_budgets": self.redaction_budgets,
            "operator_summaries": self.operator_summaries,
            "public_records": self.public_records,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub rotation_policy_root: String,
    pub wallet_cohort_root: String,
    pub collision_signal_root: String,
    pub stealth_hygiene_root: String,
    pub pq_attestation_root: String,
    pub rotation_batch_root: String,
    pub rotation_settlement_root: String,
    pub fee_rebate_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "rotation_policy_root": self.rotation_policy_root,
            "wallet_cohort_root": self.wallet_cohort_root,
            "collision_signal_root": self.collision_signal_root,
            "stealth_hygiene_root": self.stealth_hygiene_root,
            "pq_attestation_root": self.pq_attestation_root,
            "rotation_batch_root": self.rotation_batch_root,
            "rotation_settlement_root": self.rotation_settlement_root,
            "fee_rebate_root": self.fee_rebate_root,
            "redaction_budget_root": self.redaction_budget_root,
            "operator_summary_root": self.operator_summary_root,
            "nullifier_root": self.nullifier_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RotationPolicy {
    pub policy_id: String,
    pub cadence: RotationCadence,
    pub status: RotationPolicyStatus,
    pub cohort_floor: u64,
    pub target_privacy_set_size: u64,
    pub max_collision_count: u64,
    pub min_pq_security_bits: u16,
    pub fee_cap_bps: u64,
    pub active_from_height: u64,
    pub expires_at_height: u64,
    pub policy_commitment_root: String,
}

impl RotationPolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "cadence": self.cadence.as_str(),
            "status": self.status.as_str(),
            "cohort_floor": self.cohort_floor,
            "target_privacy_set_size": self.target_privacy_set_size,
            "max_collision_count": self.max_collision_count,
            "min_pq_security_bits": self.min_pq_security_bits,
            "fee_cap_bps": self.fee_cap_bps,
            "active_from_height": self.active_from_height,
            "expires_at_height": self.expires_at_height,
            "policy_commitment_root": self.policy_commitment_root,
            "scheme": PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_POLICY_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletCohort {
    pub cohort_id: String,
    pub policy_id: String,
    pub status: CohortStatus,
    pub scan_epoch: u64,
    pub member_count: u64,
    pub decoy_floor: u64,
    pub viewtag_bucket_root: String,
    pub encrypted_wallet_set_root: String,
    pub scan_hint_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl WalletCohort {
    pub fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "policy_id": self.policy_id,
            "status": self.status.as_str(),
            "scan_epoch": self.scan_epoch,
            "member_count": self.member_count,
            "decoy_floor": self.decoy_floor,
            "viewtag_bucket_root": self.viewtag_bucket_root,
            "encrypted_wallet_set_root": self.encrypted_wallet_set_root,
            "scan_hint_root": self.scan_hint_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "scheme": PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_COHORT_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CollisionSignal {
    pub signal_id: String,
    pub cohort_id: String,
    pub severity: CollisionSeverity,
    pub viewtag_prefix_root: String,
    pub collision_count: u64,
    pub sample_size: u64,
    pub collision_rate_ppm: u64,
    pub detection_height: u64,
    pub quarantine_root: String,
}

impl CollisionSignal {
    pub fn public_record(&self) -> Value {
        json!({
            "signal_id": self.signal_id,
            "cohort_id": self.cohort_id,
            "severity": self.severity.as_str(),
            "viewtag_prefix_root": self.viewtag_prefix_root,
            "collision_count": self.collision_count,
            "sample_size": self.sample_size,
            "collision_rate_ppm": self.collision_rate_ppm,
            "detection_height": self.detection_height,
            "quarantine_root": self.quarantine_root,
            "scheme": PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_COLLISION_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StealthHygieneRecord {
    pub hygiene_id: String,
    pub cohort_id: String,
    pub verdict: StealthHygieneVerdict,
    pub one_time_address_root: String,
    pub key_image_nullifier_root: String,
    pub decoy_distribution_root: String,
    pub jamtis_address_commitment_root: String,
    pub reuse_count: u64,
    pub checked_at_height: u64,
}

impl StealthHygieneRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "hygiene_id": self.hygiene_id,
            "cohort_id": self.cohort_id,
            "verdict": self.verdict.as_str(),
            "one_time_address_root": self.one_time_address_root,
            "key_image_nullifier_root": self.key_image_nullifier_root,
            "decoy_distribution_root": self.decoy_distribution_root,
            "jamtis_address_commitment_root": self.jamtis_address_commitment_root,
            "reuse_count": self.reuse_count,
            "checked_at_height": self.checked_at_height,
            "scheme": PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_STEALTH_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqRotationAttestation {
    pub attestation_id: String,
    pub cohort_id: String,
    pub policy_id: String,
    pub status: PqAttestationStatus,
    pub pq_security_bits: u16,
    pub old_viewtag_commitment_root: String,
    pub new_viewtag_commitment_root: String,
    pub ml_kem_ciphertext_root: String,
    pub ml_dsa_signature_root: String,
    pub slh_dsa_fallback_root: String,
    pub transcript_root: String,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
}

impl PqRotationAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "cohort_id": self.cohort_id,
            "policy_id": self.policy_id,
            "status": self.status.as_str(),
            "pq_security_bits": self.pq_security_bits,
            "old_viewtag_commitment_root": self.old_viewtag_commitment_root,
            "new_viewtag_commitment_root": self.new_viewtag_commitment_root,
            "ml_kem_ciphertext_root": self.ml_kem_ciphertext_root,
            "ml_dsa_signature_root": self.ml_dsa_signature_root,
            "slh_dsa_fallback_root": self.slh_dsa_fallback_root,
            "transcript_root": self.transcript_root,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
            "suite": PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_PQ_ATTESTATION_SUITE,
            "scheme": PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_ATTESTATION_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RotationBatch {
    pub batch_id: String,
    pub policy_id: String,
    pub cohort_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub status: BatchStatus,
    pub batch_size: u64,
    pub fee_bps: u64,
    pub privacy_set_size: u64,
    pub rotation_commitment_root: String,
    pub low_fee_reservation_root: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl RotationBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "policy_id": self.policy_id,
            "cohort_ids": self.cohort_ids,
            "attestation_ids": self.attestation_ids,
            "status": self.status.as_str(),
            "batch_size": self.batch_size,
            "fee_bps": self.fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "rotation_commitment_root": self.rotation_commitment_root,
            "low_fee_reservation_root": self.low_fee_reservation_root,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "scheme": PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_BATCH_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RotationSettlement {
    pub settlement_id: String,
    pub batch_id: String,
    pub status: SettlementStatus,
    pub monero_anchor_height: u64,
    pub l2_finalized_height: u64,
    pub spent_nullifier_root: String,
    pub new_viewtag_root: String,
    pub settlement_proof_root: String,
    pub operator_receipt_root: String,
    pub settled_fee_bps: u64,
}

impl RotationSettlement {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "monero_anchor_height": self.monero_anchor_height,
            "l2_finalized_height": self.l2_finalized_height,
            "spent_nullifier_root": self.spent_nullifier_root,
            "new_viewtag_root": self.new_viewtag_root,
            "settlement_proof_root": self.settlement_proof_root,
            "operator_receipt_root": self.operator_receipt_root,
            "settled_fee_bps": self.settled_fee_bps,
            "scheme": PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_SETTLEMENT_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub settlement_id: String,
    pub cohort_id: String,
    pub fee_asset_id: String,
    pub rebate_bps: u64,
    pub rebate_commitment_root: String,
    pub claim_nullifier_root: String,
    pub expires_at_height: u64,
}

impl FeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "settlement_id": self.settlement_id,
            "cohort_id": self.cohort_id,
            "fee_asset_id": self.fee_asset_id,
            "rebate_bps": self.rebate_bps,
            "rebate_commitment_root": self.rebate_commitment_root,
            "claim_nullifier_root": self.claim_nullifier_root,
            "expires_at_height": self.expires_at_height,
            "scheme": PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_REBATE_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub redaction_class: RedactionClass,
    pub operator_id: String,
    pub epoch: u64,
    pub allowed_fields: u64,
    pub consumed_fields: u64,
    pub summary_salt_root: String,
    pub audit_commitment_root: String,
}

impl RedactionBudget {
    pub fn remaining_fields(&self) -> u64 {
        self.allowed_fields.saturating_sub(self.consumed_fields)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "redaction_class": self.redaction_class.as_str(),
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "allowed_fields": self.allowed_fields,
            "consumed_fields": self.consumed_fields,
            "remaining_fields": self.remaining_fields(),
            "summary_salt_root": self.summary_salt_root,
            "audit_commitment_root": self.audit_commitment_root,
            "scheme": PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_REDACTION_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub redaction_budget_id: String,
    pub redacted_wallet_count: u64,
    pub redacted_collision_count: u64,
    pub batch_count: u64,
    pub settlement_count: u64,
    pub fee_rebate_count: u64,
    pub summary_commitment_root: String,
    pub audit_trail_root: String,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "redaction_budget_id": self.redaction_budget_id,
            "redacted_wallet_count": self.redacted_wallet_count,
            "redacted_collision_count": self.redacted_collision_count,
            "batch_count": self.batch_count,
            "settlement_count": self.settlement_count,
            "fee_rebate_count": self.fee_rebate_count,
            "summary_commitment_root": self.summary_commitment_root,
            "audit_trail_root": self.audit_trail_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub rotation_policies: BTreeMap<String, RotationPolicy>,
    pub wallet_cohorts: BTreeMap<String, WalletCohort>,
    pub collision_signals: BTreeMap<String, CollisionSignal>,
    pub stealth_hygiene_records: BTreeMap<String, StealthHygieneRecord>,
    pub pq_attestations: BTreeMap<String, PqRotationAttestation>,
    pub rotation_batches: BTreeMap<String, RotationBatch>,
    pub rotation_settlements: BTreeMap<String, RotationSettlement>,
    pub fee_rebates: BTreeMap<String, FeeRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
}

pub type Runtime = State;

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            rotation_policies: BTreeMap::new(),
            wallet_cohorts: BTreeMap::new(),
            collision_signals: BTreeMap::new(),
            stealth_hygiene_records: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            rotation_batches: BTreeMap::new(),
            rotation_settlements: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("devnet config is valid");
        state.seed_devnet();
        state
    }

    pub fn register_rotation_policy(
        &mut self,
        cadence: RotationCadence,
        active_from_height: u64,
        policy_commitment_root: impl Into<String>,
    ) -> Result<RotationPolicy> {
        ensure_capacity(
            self.rotation_policies.len(),
            self.config.max_rotation_policies,
            "rotation_policies",
        )?;
        let policy_commitment_root = policy_commitment_root.into();
        let policy = RotationPolicy {
            policy_id: deterministic_id(
                "rotation_policy",
                &json!({
                    "cadence": cadence.as_str(),
                    "active_from_height": active_from_height,
                    "policy_commitment_root": policy_commitment_root.clone(),
                }),
                self.rotation_policies.len() as u64 + 1,
            ),
            cadence,
            status: RotationPolicyStatus::Active,
            cohort_floor: self.config.min_wallet_cohort_size,
            target_privacy_set_size: self.config.target_privacy_set_size,
            max_collision_count: self.config.max_viewtag_collisions_per_epoch,
            min_pq_security_bits: self.config.min_pq_security_bits,
            fee_cap_bps: self.config.max_user_fee_bps,
            active_from_height,
            expires_at_height: active_from_height + self.config.rotation_ttl_blocks,
            policy_commitment_root,
        };
        self.rotation_policies
            .insert(policy.policy_id.clone(), policy.clone());
        self.record_public(
            format!("rotation_policy:{}", policy.policy_id),
            policy.public_record(),
        )?;
        self.refresh_counters();
        Ok(policy)
    }

    pub fn register_wallet_cohort(
        &mut self,
        policy_id: impl Into<String>,
        scan_epoch: u64,
        member_count: u64,
        encrypted_wallet_set_root: impl Into<String>,
    ) -> Result<WalletCohort> {
        ensure_capacity(
            self.wallet_cohorts.len(),
            self.config.max_wallet_cohorts,
            "wallet_cohorts",
        )?;
        ensure!(
            member_count >= self.config.min_wallet_cohort_size,
            "wallet cohort below privacy floor"
        );
        let policy_id = policy_id.into();
        let policy = self
            .rotation_policies
            .get(&policy_id)
            .ok_or_else(|| format!("missing rotation policy {policy_id}"))?;
        ensure!(
            policy.status.accepts_rotation(),
            "policy is not rotation-active"
        );
        let encrypted_wallet_set_root = encrypted_wallet_set_root.into();
        let sequence = self.wallet_cohorts.len() as u64 + 1;
        let cohort = WalletCohort {
            cohort_id: deterministic_id(
                "wallet_cohort",
                &json!({
                    "policy_id": policy_id,
                    "scan_epoch": scan_epoch,
                    "member_count": member_count,
                    "encrypted_wallet_set_root": encrypted_wallet_set_root,
                }),
                sequence,
            ),
            policy_id,
            status: CohortStatus::Eligible,
            scan_epoch,
            member_count,
            decoy_floor: self.config.min_privacy_set_size,
            viewtag_bucket_root: root_label("viewtag-buckets", scan_epoch),
            encrypted_wallet_set_root,
            scan_hint_root: root_label("scan-hints", scan_epoch),
            created_at_height:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEVNET_HEIGHT,
            expires_at_height:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEVNET_HEIGHT
                    + self.config.rotation_ttl_blocks,
        };
        self.wallet_cohorts
            .insert(cohort.cohort_id.clone(), cohort.clone());
        self.record_public(
            format!("wallet_cohort:{}", cohort.cohort_id),
            cohort.public_record(),
        )?;
        self.refresh_counters();
        Ok(cohort)
    }

    pub fn record_collision_signal(
        &mut self,
        cohort_id: impl Into<String>,
        severity: CollisionSeverity,
        collision_count: u64,
        sample_size: u64,
    ) -> Result<CollisionSignal> {
        ensure_capacity(
            self.collision_signals.len(),
            self.config.max_collision_signals,
            "collision_signals",
        )?;
        let cohort_id = cohort_id.into();
        ensure!(
            self.wallet_cohorts.contains_key(&cohort_id),
            "missing wallet cohort"
        );
        ensure!(sample_size > 0, "collision sample must be positive");
        let collision_rate_ppm = collision_count.saturating_mul(1_000_000) / sample_size;
        let sequence = self.collision_signals.len() as u64 + 1;
        let signal = CollisionSignal {
            signal_id: deterministic_id(
                "collision_signal",
                &json!({
                    "cohort_id": cohort_id,
                    "severity": severity.as_str(),
                    "collision_count": collision_count,
                    "sample_size": sample_size,
                }),
                sequence,
            ),
            cohort_id,
            severity,
            viewtag_prefix_root: root_label("viewtag-prefixes", sequence),
            collision_count,
            sample_size,
            collision_rate_ppm,
            detection_height:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEVNET_HEIGHT
                    + sequence,
            quarantine_root: root_label("collision-quarantine", sequence),
        };
        self.collision_signals
            .insert(signal.signal_id.clone(), signal.clone());
        self.record_public(
            format!("collision_signal:{}", signal.signal_id),
            signal.public_record(),
        )?;
        self.refresh_counters();
        Ok(signal)
    }

    pub fn record_stealth_hygiene(
        &mut self,
        cohort_id: impl Into<String>,
        verdict: StealthHygieneVerdict,
        reuse_count: u64,
    ) -> Result<StealthHygieneRecord> {
        ensure_capacity(
            self.stealth_hygiene_records.len(),
            self.config.max_stealth_hygiene_records,
            "stealth_hygiene_records",
        )?;
        let cohort_id = cohort_id.into();
        ensure!(
            self.wallet_cohorts.contains_key(&cohort_id),
            "missing wallet cohort"
        );
        let sequence = self.stealth_hygiene_records.len() as u64 + 1;
        let record = StealthHygieneRecord {
            hygiene_id: deterministic_id(
                "stealth_hygiene",
                &json!({
                    "cohort_id": cohort_id,
                    "verdict": verdict.as_str(),
                    "reuse_count": reuse_count,
                }),
                sequence,
            ),
            cohort_id,
            verdict,
            one_time_address_root: root_label("one-time-address", sequence),
            key_image_nullifier_root: root_label("key-image-nullifier", sequence),
            decoy_distribution_root: root_label("decoy-distribution", sequence),
            jamtis_address_commitment_root: root_label("jamtis-address", sequence),
            reuse_count,
            checked_at_height:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEVNET_HEIGHT
                    + sequence,
        };
        self.stealth_hygiene_records
            .insert(record.hygiene_id.clone(), record.clone());
        self.record_public(
            format!("stealth_hygiene:{}", record.hygiene_id),
            record.public_record(),
        )?;
        self.refresh_counters();
        Ok(record)
    }

    pub fn attest_rotation(
        &mut self,
        cohort_id: impl Into<String>,
        pq_security_bits: u16,
        old_viewtag_commitment_root: impl Into<String>,
        new_viewtag_commitment_root: impl Into<String>,
    ) -> Result<PqRotationAttestation> {
        ensure_capacity(
            self.pq_attestations.len(),
            self.config.max_pq_attestations,
            "pq_attestations",
        )?;
        let cohort_id = cohort_id.into();
        let cohort = self
            .wallet_cohorts
            .get(&cohort_id)
            .ok_or_else(|| format!("missing wallet cohort {cohort_id}"))?;
        ensure!(cohort.status.live(), "cohort is not live");
        ensure!(
            pq_security_bits >= self.config.min_pq_security_bits,
            "pq attestation security below configured floor"
        );
        let old_viewtag_commitment_root = old_viewtag_commitment_root.into();
        let new_viewtag_commitment_root = new_viewtag_commitment_root.into();
        ensure!(
            old_viewtag_commitment_root != new_viewtag_commitment_root,
            "rotation must change viewtag commitment root"
        );
        let sequence = self.pq_attestations.len() as u64 + 1;
        let attestation = PqRotationAttestation {
            attestation_id: deterministic_id(
                "pq_rotation_attestation",
                &json!({
                    "cohort_id": cohort_id,
                    "old": old_viewtag_commitment_root,
                    "new": new_viewtag_commitment_root,
                    "pq_security_bits": pq_security_bits,
                }),
                sequence,
            ),
            cohort_id,
            policy_id: cohort.policy_id.clone(),
            status: PqAttestationStatus::Verified,
            pq_security_bits,
            old_viewtag_commitment_root,
            new_viewtag_commitment_root,
            ml_kem_ciphertext_root: root_label("ml-kem-ciphertext", sequence),
            ml_dsa_signature_root: root_label("ml-dsa-signature", sequence),
            slh_dsa_fallback_root: root_label("slh-dsa-fallback", sequence),
            transcript_root: root_label("rotation-transcript", sequence),
            attested_at_height:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEVNET_HEIGHT
                    + sequence,
            expires_at_height:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEVNET_HEIGHT
                    + sequence
                    + self.config.attestation_ttl_blocks,
        };
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation.clone());
        self.record_public(
            format!("pq_rotation_attestation:{}", attestation.attestation_id),
            attestation.public_record(),
        )?;
        self.refresh_counters();
        Ok(attestation)
    }

    pub fn open_rotation_batch(
        &mut self,
        policy_id: impl Into<String>,
        cohort_ids: Vec<String>,
        attestation_ids: Vec<String>,
    ) -> Result<RotationBatch> {
        ensure_capacity(
            self.rotation_batches.len(),
            self.config.max_rotation_batches,
            "rotation_batches",
        )?;
        ensure!(!cohort_ids.is_empty(), "rotation batch requires cohorts");
        ensure!(
            cohort_ids.len() <= self.config.max_batch_items,
            "rotation batch exceeds item limit"
        );
        let policy_id = policy_id.into();
        ensure!(
            self.rotation_policies.contains_key(&policy_id),
            "missing rotation policy"
        );
        for cohort_id in &cohort_ids {
            ensure!(
                self.wallet_cohorts.contains_key(cohort_id),
                "batch references missing cohort"
            );
        }
        for attestation_id in &attestation_ids {
            let attestation = self
                .pq_attestations
                .get(attestation_id)
                .ok_or_else(|| format!("missing attestation {attestation_id}"))?;
            ensure!(attestation.status.usable(), "attestation is not usable");
        }
        let sequence = self.rotation_batches.len() as u64 + 1;
        let batch = RotationBatch {
            batch_id: deterministic_id(
                "rotation_batch",
                &json!({
                    "policy_id": policy_id,
                    "cohort_ids": cohort_ids,
                    "attestation_ids": attestation_ids,
                }),
                sequence,
            ),
            policy_id,
            batch_size: cohort_ids.len() as u64,
            cohort_ids,
            attestation_ids,
            status: BatchStatus::Attested,
            fee_bps: self.config.low_fee_bps,
            privacy_set_size: self.config.target_privacy_set_size,
            rotation_commitment_root: root_label("rotation-batch", sequence),
            low_fee_reservation_root: root_label("low-fee-reservation", sequence),
            submitted_at_height:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEVNET_HEIGHT
                    + sequence,
            expires_at_height:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEVNET_HEIGHT
                    + sequence
                    + self.config.settlement_ttl_blocks,
        };
        self.rotation_batches
            .insert(batch.batch_id.clone(), batch.clone());
        self.record_public(
            format!("rotation_batch:{}", batch.batch_id),
            batch.public_record(),
        )?;
        self.refresh_counters();
        Ok(batch)
    }

    pub fn settle_rotation_batch(
        &mut self,
        batch_id: impl Into<String>,
        monero_anchor_height: u64,
        l2_finalized_height: u64,
    ) -> Result<RotationSettlement> {
        ensure_capacity(
            self.rotation_settlements.len(),
            self.config.max_rotation_settlements,
            "rotation_settlements",
        )?;
        let batch_id = batch_id.into();
        let batch = self
            .rotation_batches
            .get(&batch_id)
            .ok_or_else(|| format!("missing rotation batch {batch_id}"))?;
        ensure!(
            matches!(batch.status, BatchStatus::Attested | BatchStatus::Submitted),
            "batch is not settleable"
        );
        let sequence = self.rotation_settlements.len() as u64 + 1;
        let settlement = RotationSettlement {
            settlement_id: deterministic_id(
                "rotation_settlement",
                &json!({
                    "batch_id": batch_id,
                    "monero_anchor_height": monero_anchor_height,
                    "l2_finalized_height": l2_finalized_height,
                }),
                sequence,
            ),
            batch_id,
            status: SettlementStatus::RebateQueued,
            monero_anchor_height,
            l2_finalized_height,
            spent_nullifier_root: root_label("spent-nullifiers", sequence),
            new_viewtag_root: root_label("settled-viewtags", sequence),
            settlement_proof_root: root_label("settlement-proof", sequence),
            operator_receipt_root: root_label("operator-receipt", sequence),
            settled_fee_bps: batch.fee_bps,
        };
        self.rotation_settlements
            .insert(settlement.settlement_id.clone(), settlement.clone());
        self.record_public(
            format!("rotation_settlement:{}", settlement.settlement_id),
            settlement.public_record(),
        )?;
        self.refresh_counters();
        Ok(settlement)
    }

    pub fn queue_fee_rebate(
        &mut self,
        settlement_id: impl Into<String>,
        cohort_id: impl Into<String>,
    ) -> Result<FeeRebate> {
        ensure_capacity(
            self.fee_rebates.len(),
            self.config.max_fee_rebates,
            "fee_rebates",
        )?;
        let settlement_id = settlement_id.into();
        ensure!(
            self.rotation_settlements.contains_key(&settlement_id),
            "missing settlement"
        );
        let cohort_id = cohort_id.into();
        ensure!(
            self.wallet_cohorts.contains_key(&cohort_id),
            "missing wallet cohort"
        );
        let sequence = self.fee_rebates.len() as u64 + 1;
        let rebate = FeeRebate {
            rebate_id: deterministic_id(
                "fee_rebate",
                &json!({
                    "settlement_id": settlement_id,
                    "cohort_id": cohort_id,
                    "fee_asset_id": self.config.fee_asset_id,
                }),
                sequence,
            ),
            settlement_id,
            cohort_id,
            fee_asset_id: self.config.fee_asset_id.clone(),
            rebate_bps: self.config.rebate_bps,
            rebate_commitment_root: root_label("rebate-commitment", sequence),
            claim_nullifier_root: root_label("rebate-nullifier", sequence),
            expires_at_height:
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEVNET_HEIGHT
                    + sequence
                    + self.config.rotation_ttl_blocks,
        };
        self.fee_rebates
            .insert(rebate.rebate_id.clone(), rebate.clone());
        self.record_public(
            format!("fee_rebate:{}", rebate.rebate_id),
            rebate.public_record(),
        )?;
        self.refresh_counters();
        Ok(rebate)
    }

    pub fn reserve_redaction_budget(
        &mut self,
        operator_id: impl Into<String>,
        redaction_class: RedactionClass,
        epoch: u64,
        allowed_fields: u64,
    ) -> Result<RedactionBudget> {
        ensure_capacity(
            self.redaction_budgets.len(),
            self.config.max_redaction_budgets,
            "redaction_budgets",
        )?;
        ensure!(allowed_fields > 0, "redaction budget must be positive");
        let operator_id = operator_id.into();
        let sequence = self.redaction_budgets.len() as u64 + 1;
        let budget = RedactionBudget {
            budget_id: deterministic_id(
                "redaction_budget",
                &json!({
                    "operator_id": operator_id,
                    "redaction_class": redaction_class.as_str(),
                    "epoch": epoch,
                    "allowed_fields": allowed_fields,
                }),
                sequence,
            ),
            redaction_class,
            operator_id,
            epoch,
            allowed_fields,
            consumed_fields: 0,
            summary_salt_root: root_label("summary-salt", sequence),
            audit_commitment_root: root_label("redaction-audit", sequence),
        };
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget.clone());
        self.record_public(
            format!("redaction_budget:{}", budget.budget_id),
            budget.public_record(),
        )?;
        self.refresh_counters();
        Ok(budget)
    }

    pub fn publish_operator_summary(
        &mut self,
        operator_id: impl Into<String>,
        epoch: u64,
        redaction_budget_id: impl Into<String>,
    ) -> Result<OperatorSummary> {
        ensure_capacity(
            self.operator_summaries.len(),
            self.config.max_operator_summaries,
            "operator_summaries",
        )?;
        let operator_id = operator_id.into();
        let redaction_budget_id = redaction_budget_id.into();
        let budget = self
            .redaction_budgets
            .get_mut(&redaction_budget_id)
            .ok_or_else(|| format!("missing redaction budget {redaction_budget_id}"))?;
        ensure!(budget.remaining_fields() >= 5, "redaction budget exhausted");
        budget.consumed_fields = budget.consumed_fields.saturating_add(5);
        let sequence = self.operator_summaries.len() as u64 + 1;
        let summary = OperatorSummary {
            summary_id: deterministic_id(
                "operator_summary",
                &json!({
                    "operator_id": operator_id,
                    "epoch": epoch,
                    "redaction_budget_id": redaction_budget_id,
                }),
                sequence,
            ),
            operator_id,
            epoch,
            redaction_budget_id,
            redacted_wallet_count: self
                .wallet_cohorts
                .values()
                .map(|cohort| cohort.member_count)
                .sum(),
            redacted_collision_count: self
                .collision_signals
                .values()
                .map(|signal| signal.collision_count)
                .sum(),
            batch_count: self.rotation_batches.len() as u64,
            settlement_count: self.rotation_settlements.len() as u64,
            fee_rebate_count: self.fee_rebates.len() as u64,
            summary_commitment_root: root_label("operator-summary", sequence),
            audit_trail_root: root_label("operator-audit", sequence),
        };
        self.operator_summaries
            .insert(summary.summary_id.clone(), summary.clone());
        self.record_public(
            format!("operator_summary:{}", summary.summary_id),
            summary.public_record(),
        )?;
        self.refresh_counters();
        Ok(summary)
    }

    pub fn counters(&self) -> Counters {
        let mut counters = self.counters.clone();
        counters.rotation_policies = self.rotation_policies.len() as u64;
        counters.wallet_cohorts = self.wallet_cohorts.len() as u64;
        counters.collision_signals = self.collision_signals.len() as u64;
        counters.stealth_hygiene_records = self.stealth_hygiene_records.len() as u64;
        counters.pq_attestations = self.pq_attestations.len() as u64;
        counters.rotation_batches = self.rotation_batches.len() as u64;
        counters.rotation_settlements = self.rotation_settlements.len() as u64;
        counters.fee_rebates = self.fee_rebates.len() as u64;
        counters.redaction_budgets = self.redaction_budgets.len() as u64;
        counters.operator_summaries = self.operator_summaries.len() as u64;
        counters.public_records = self.public_records.len() as u64;
        counters
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: root_from_record("CONFIG", &self.config.public_record()),
            counters_root: root_from_record("COUNTERS", &self.counters().public_record()),
            rotation_policy_root: map_root(
                "ROTATION-POLICIES",
                &self.rotation_policies,
                RotationPolicy::public_record,
            ),
            wallet_cohort_root: map_root(
                "WALLET-COHORTS",
                &self.wallet_cohorts,
                WalletCohort::public_record,
            ),
            collision_signal_root: map_root(
                "COLLISION-SIGNALS",
                &self.collision_signals,
                CollisionSignal::public_record,
            ),
            stealth_hygiene_root: map_root(
                "STEALTH-HYGIENE",
                &self.stealth_hygiene_records,
                StealthHygieneRecord::public_record,
            ),
            pq_attestation_root: map_root(
                "PQ-ATTESTATIONS",
                &self.pq_attestations,
                PqRotationAttestation::public_record,
            ),
            rotation_batch_root: map_root(
                "ROTATION-BATCHES",
                &self.rotation_batches,
                RotationBatch::public_record,
            ),
            rotation_settlement_root: map_root(
                "ROTATION-SETTLEMENTS",
                &self.rotation_settlements,
                RotationSettlement::public_record,
            ),
            fee_rebate_root: map_root("FEE-REBATES", &self.fee_rebates, FeeRebate::public_record),
            redaction_budget_root: map_root(
                "REDACTION-BUDGETS",
                &self.redaction_budgets,
                RedactionBudget::public_record,
            ),
            operator_summary_root: map_root(
                "OPERATOR-SUMMARIES",
                &self.operator_summaries,
                OperatorSummary::public_record,
            ),
            nullifier_root: set_root("NULLIFIERS", &self.nullifiers),
            public_record_root: map_value_root("PUBLIC-RECORDS", &self.public_records),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_SCHEMA_VERSION,
            "hash_suite": PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_HASH_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": self.roots().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn record_public(&mut self, key: String, record: Value) -> Result<()> {
        self.public_records.insert(key, record);
        Ok(())
    }

    fn refresh_counters(&mut self) {
        self.counters = self.counters();
    }

    fn seed_devnet(&mut self) {
        let policy = self
            .register_rotation_policy(
                RotationCadence::CollisionTriggered,
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEVNET_HEIGHT,
                "devnet-policy-commitment",
            )
            .expect("seed policy");
        let cohort = self
            .register_wallet_cohort(
                policy.policy_id.clone(),
                42,
                self.config.min_wallet_cohort_size,
                "devnet-encrypted-wallet-set-root",
            )
            .expect("seed cohort");
        self.record_collision_signal(
            cohort.cohort_id.clone(),
            CollisionSeverity::Watch,
            1,
            self.config.min_privacy_set_size,
        )
        .expect("seed collision");
        self.record_stealth_hygiene(cohort.cohort_id.clone(), StealthHygieneVerdict::Clean, 0)
            .expect("seed stealth hygiene");
        let attestation = self
            .attest_rotation(
                cohort.cohort_id.clone(),
                self.config.min_pq_security_bits,
                "devnet-old-viewtag-root",
                "devnet-new-viewtag-root",
            )
            .expect("seed attestation");
        let batch = self
            .open_rotation_batch(
                policy.policy_id,
                vec![cohort.cohort_id.clone()],
                vec![attestation.attestation_id],
            )
            .expect("seed batch");
        let settlement = self
            .settle_rotation_batch(
                batch.batch_id,
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEVNET_HEIGHT + 8,
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_DEVNET_HEIGHT + 12,
            )
            .expect("seed settlement");
        self.queue_fee_rebate(settlement.settlement_id, cohort.cohort_id)
            .expect("seed rebate");
        let budget = self
            .reserve_redaction_budget("devnet-operator", RedactionClass::OperatorMetric, 42, 16)
            .expect("seed budget");
        self.publish_operator_summary("devnet-operator", 42, budget.budget_id)
            .expect("seed summary");
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

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("STATE", record)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(
        &[
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Json(&json!(records)),
        ],
        &format!(
            "{}:{}:{}",
            PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_PROTOCOL_VERSION,
            CHAIN_ID,
            domain
        ),
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &[
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Json(record),
        ],
        &format!(
            "{}:{}:{}",
            PRIVATE_L2_PQ_CONFIDENTIAL_JAMTIS_VIEWTAG_ROTATION_GUARD_RUNTIME_PROTOCOL_VERSION,
            CHAIN_ID,
            domain
        ),
    )
}

pub fn deterministic_id(domain: &str, record: &Value, sequence: u64) -> String {
    root_from_record(
        domain,
        &json!({
            "sequence": sequence,
            "record": record,
        }),
    )
}

fn root_label(label: &str, sequence: u64) -> String {
    root_from_record(label, &json!({ "label": label, "sequence": sequence }))
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let records = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": public_record(value) }))
        .collect::<Vec<_>>();
    public_record_root(domain, &records)
}

fn map_value_root(domain: &str, map: &BTreeMap<String, Value>) -> String {
    let records = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value }))
        .collect::<Vec<_>>();
    public_record_root(domain, &records)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let records = set
        .iter()
        .map(|value| json!({ "nullifier": value }))
        .collect::<Vec<_>>();
    public_record_root(domain, &records)
}

fn ensure_capacity(current_len: usize, max_len: usize, label: &str) -> Result<()> {
    if current_len >= max_len {
        return Err(format!(
            "{label} capacity exhausted: {current_len} >= {max_len}"
        ));
    }
    Ok(())
}
