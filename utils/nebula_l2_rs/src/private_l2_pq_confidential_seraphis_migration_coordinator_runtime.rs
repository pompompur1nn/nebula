use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialSeraphisMigrationCoordinatorRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_SERAPHIS_MIGRATION_COORDINATOR_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-seraphis-migration-coordinator-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_SERAPHIS_MIGRATION_COORDINATOR_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SERAPHIS_COMMITMENT_SUITE: &str = "seraphis-shielded-account-commitment-root-v1";
pub const PQ_ATTESTATION_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-seraphis-migration-v1";
pub const PQ_KEM_SUITE: &str = "ML-KEM-1024+hybrid-x25519-wallet-lane-envelope-v1";
pub const WALLET_COMPATIBILITY_SUITE: &str = "monero-seraphis-wallet-compatibility-lane-root-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "low-fee-seraphis-migration-rebate-root-v1";
pub const PRIVACY_REDACTION_SUITE: &str = "privacy-redaction-budget-accounting-root-v1";
pub const QUARANTINE_RETRY_SUITE: &str = "migration-quarantine-retry-accounting-root-v1";
pub const PUBLIC_RECORD_SUITE: &str = "roots-only-public-record-v1";
pub const DEVNET_L2_HEIGHT: u64 = 1_884_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_680_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_ANONYMITY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_ANONYMITY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_EPOCH_TTL_BLOCKS: u64 = 43_200;
pub const DEFAULT_ADMISSION_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_WALLET_LANE_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 960;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 1_000;
pub const DEFAULT_MAX_REDACTION_UNITS_PER_ACCOUNT: u64 = 40;
pub const DEFAULT_MAX_RETRY_ATTEMPTS: u8 = 5;
pub const DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 4_320;
pub const DEFAULT_MAX_MIGRATION_FEE_BPS: u64 = 12;
pub const DEFAULT_REBATE_TARGET_BPS: u64 = 7;
pub const DEFAULT_REBATE_POOL_MICRO_UNITS: u64 = 75_000_000_000;
pub const DEFAULT_LOW_FEE_BATCH_TARGET: usize = 512;
pub const DEFAULT_LOW_FEE_BATCH_LIMIT: usize = 4_096;
pub const MAX_EPOCHS: usize = 2_097_152;
pub const MAX_COMMITMENTS: usize = 8_388_608;
pub const MAX_ATTESTATIONS: usize = 8_388_608;
pub const MAX_WALLET_LANES: usize = 1_048_576;
pub const MAX_REBATES: usize = 4_194_304;
pub const MAX_REDACTION_BUDGETS: usize = 2_097_152;
pub const MAX_QUARANTINES: usize = 2_097_152;
pub const MAX_RETRY_RECORDS: usize = 4_194_304;
pub const MAX_PUBLIC_RECORDS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochStatus {
    Proposed,
    PrivacyPrimed,
    WalletLaneOpen,
    AdmissionOpen,
    Active,
    RebateDraining,
    SeraphisEnforced,
    Superseded,
    Revoked,
    EmergencyOnly,
}

impl EpochStatus {
    pub fn accepts_commitments(self) -> bool {
        matches!(
            self,
            Self::PrivacyPrimed | Self::WalletLaneOpen | Self::AdmissionOpen | Self::Active
        )
    }

    pub fn accepts_attestations(self) -> bool {
        matches!(
            self,
            Self::WalletLaneOpen | Self::AdmissionOpen | Self::Active
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::PrivacyPrimed => "privacy_primed",
            Self::WalletLaneOpen => "wallet_lane_open",
            Self::AdmissionOpen => "admission_open",
            Self::Active => "active",
            Self::RebateDraining => "rebate_draining",
            Self::SeraphisEnforced => "seraphis_enforced",
            Self::Superseded => "superseded",
            Self::Revoked => "revoked",
            Self::EmergencyOnly => "emergency_only",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Registered,
    PrivacyQueued,
    AttestationPending,
    Attested,
    LaneAssigned,
    Migrated,
    Quarantined,
    Retired,
    Rejected,
}

impl CommitmentStatus {
    pub fn can_attest(self) -> bool {
        matches!(
            self,
            Self::Registered | Self::PrivacyQueued | Self::AttestationPending | Self::Quarantined
        )
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Registered
                | Self::PrivacyQueued
                | Self::AttestationPending
                | Self::Attested
                | Self::LaneAssigned
                | Self::Quarantined
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::PrivacyQueued => "privacy_queued",
            Self::AttestationPending => "attestation_pending",
            Self::Attested => "attested",
            Self::LaneAssigned => "lane_assigned",
            Self::Migrated => "migrated",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountKind {
    LegacyRingCt,
    LegacySubaddress,
    SeraphisJamtis,
    SeraphisShieldedVault,
    BridgeEscrow,
    WalletRecovery,
    ExchangeMigration,
    CustodyMigration,
}

impl AccountKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LegacyRingCt => "legacy_ringct",
            Self::LegacySubaddress => "legacy_subaddress",
            Self::SeraphisJamtis => "seraphis_jamtis",
            Self::SeraphisShieldedVault => "seraphis_shielded_vault",
            Self::BridgeEscrow => "bridge_escrow",
            Self::WalletRecovery => "wallet_recovery",
            Self::ExchangeMigration => "exchange_migration",
            Self::CustodyMigration => "custody_migration",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqScheme {
    MlDsa65,
    MlDsa87,
    SlhDsaShake192f,
    SlhDsaShake256f,
    HybridSpendKeyMlDsa87,
    HybridViewKeyMlDsa87,
    HybridWalletApiMlDsa87,
}

impl PqScheme {
    pub fn security_bits(self) -> u16 {
        match self {
            Self::MlDsa65 | Self::SlhDsaShake192f => 192,
            Self::MlDsa87
            | Self::SlhDsaShake256f
            | Self::HybridSpendKeyMlDsa87
            | Self::HybridViewKeyMlDsa87
            | Self::HybridWalletApiMlDsa87 => 256,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa65 => "ml_dsa_65",
            Self::MlDsa87 => "ml_dsa_87",
            Self::SlhDsaShake192f => "slh_dsa_shake_192f",
            Self::SlhDsaShake256f => "slh_dsa_shake_256f",
            Self::HybridSpendKeyMlDsa87 => "hybrid_spend_key_ml_dsa_87",
            Self::HybridViewKeyMlDsa87 => "hybrid_view_key_ml_dsa_87",
            Self::HybridWalletApiMlDsa87 => "hybrid_wallet_api_ml_dsa_87",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    SpendAuthority,
    ViewAuthority,
    WalletCompatibility,
    BalanceConservation,
    NullifierFreshness,
    SeraphisAddressBinding,
    RecoveryGuardian,
    OperatorBatchSeal,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SpendAuthority => "spend_authority",
            Self::ViewAuthority => "view_authority",
            Self::WalletCompatibility => "wallet_compatibility",
            Self::BalanceConservation => "balance_conservation",
            Self::NullifierFreshness => "nullifier_freshness",
            Self::SeraphisAddressBinding => "seraphis_address_binding",
            Self::RecoveryGuardian => "recovery_guardian",
            Self::OperatorBatchSeal => "operator_batch_seal",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    PrivacyChecked,
    LaneMatched,
    RebateReserved,
    Accepted,
    Rejected,
    Expired,
    Quarantined,
}

impl AttestationStatus {
    pub fn accepted(self) -> bool {
        matches!(
            self,
            Self::PrivacyChecked | Self::LaneMatched | Self::RebateReserved | Self::Accepted
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::PrivacyChecked => "privacy_checked",
            Self::LaneMatched => "lane_matched",
            Self::RebateReserved => "rebate_reserved",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletLaneKind {
    CliLegacy,
    GuiLegacy,
    MobileLight,
    HardwareWallet,
    ExchangeCustody,
    WatchOnly,
    SeraphisNative,
    EmergencyRecovery,
}

impl WalletLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CliLegacy => "cli_legacy",
            Self::GuiLegacy => "gui_legacy",
            Self::MobileLight => "mobile_light",
            Self::HardwareWallet => "hardware_wallet",
            Self::ExchangeCustody => "exchange_custody",
            Self::WatchOnly => "watch_only",
            Self::SeraphisNative => "seraphis_native",
            Self::EmergencyRecovery => "emergency_recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Drafted,
    Open,
    Throttled,
    CompatibilityHold,
    Draining,
    Closed,
    Paused,
}

impl LaneStatus {
    pub fn accepts_accounts(self) -> bool {
        matches!(self, Self::Open | Self::Throttled)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drafted => "drafted",
            Self::Open => "open",
            Self::Throttled => "throttled",
            Self::CompatibilityHold => "compatibility_hold",
            Self::Draining => "draining",
            Self::Closed => "closed",
            Self::Paused => "paused",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Quoted,
    Reserved,
    Applied,
    Settled,
    Revoked,
    Expired,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quoted => "quoted",
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Settled => "settled",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionClass {
    None,
    ViewTag,
    WalletBuild,
    FeeBucket,
    TimingBucket,
    LaneHint,
    OperatorPanelField,
    RecoveryHint,
}

impl RedactionClass {
    pub fn units(self) -> u64 {
        match self {
            Self::None => 0,
            Self::ViewTag | Self::FeeBucket | Self::TimingBucket => 1,
            Self::LaneHint | Self::WalletBuild => 2,
            Self::OperatorPanelField => 4,
            Self::RecoveryHint => 8,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ViewTag => "view_tag",
            Self::WalletBuild => "wallet_build",
            Self::FeeBucket => "fee_bucket",
            Self::TimingBucket => "timing_bucket",
            Self::LaneHint => "lane_hint",
            Self::OperatorPanelField => "operator_panel_field",
            Self::RecoveryHint => "recovery_hint",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    InvalidPqSignature,
    LowAnonymitySet,
    WalletLaneMismatch,
    RedactionBudgetExceeded,
    DuplicateNullifier,
    FeeOutOfPolicy,
    AttestationExpired,
    OperatorReview,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPqSignature => "invalid_pq_signature",
            Self::LowAnonymitySet => "low_anonymity_set",
            Self::WalletLaneMismatch => "wallet_lane_mismatch",
            Self::RedactionBudgetExceeded => "redaction_budget_exceeded",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::FeeOutOfPolicy => "fee_out_of_policy",
            Self::AttestationExpired => "attestation_expired",
            Self::OperatorReview => "operator_review",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineStatus {
    Open,
    RetryScheduled,
    Released,
    Rejected,
    Expired,
    Slashed,
}

impl QuarantineStatus {
    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::RetryScheduled)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::RetryScheduled => "retry_scheduled",
            Self::Released => "released",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryStatus {
    Scheduled,
    Running,
    Succeeded,
    Failed,
    Exhausted,
    Cancelled,
}

impl RetryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Exhausted => "exhausted",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub min_pq_security_bits: u16,
    pub min_anonymity_set_size: u64,
    pub batch_anonymity_set_size: u64,
    pub epoch_ttl_blocks: u64,
    pub admission_ttl_blocks: u64,
    pub wallet_lane_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub redaction_budget_units: u64,
    pub max_redaction_units_per_account: u64,
    pub max_retry_attempts: u8,
    pub quarantine_ttl_blocks: u64,
    pub max_migration_fee_bps: u64,
    pub rebate_target_bps: u64,
    pub rebate_pool_micro_units: u64,
    pub low_fee_batch_target: usize,
    pub low_fee_batch_limit: usize,
    pub allowed_wallet_families: BTreeSet<String>,
    pub operator_set_root: String,
    pub compatibility_manifest_root: String,
}

impl Config {
    pub fn devnet() -> Self {
        let mut allowed_wallet_families = BTreeSet::new();
        allowed_wallet_families.insert("monero-cli".to_string());
        allowed_wallet_families.insert("monero-gui".to_string());
        allowed_wallet_families.insert("seraphis-mobile".to_string());
        allowed_wallet_families.insert("hardware-lane-devnet".to_string());
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_anonymity_set_size: DEFAULT_MIN_ANONYMITY_SET_SIZE,
            batch_anonymity_set_size: DEFAULT_BATCH_ANONYMITY_SET_SIZE,
            epoch_ttl_blocks: DEFAULT_EPOCH_TTL_BLOCKS,
            admission_ttl_blocks: DEFAULT_ADMISSION_TTL_BLOCKS,
            wallet_lane_ttl_blocks: DEFAULT_WALLET_LANE_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
            max_redaction_units_per_account: DEFAULT_MAX_REDACTION_UNITS_PER_ACCOUNT,
            max_retry_attempts: DEFAULT_MAX_RETRY_ATTEMPTS,
            quarantine_ttl_blocks: DEFAULT_QUARANTINE_TTL_BLOCKS,
            max_migration_fee_bps: DEFAULT_MAX_MIGRATION_FEE_BPS,
            rebate_target_bps: DEFAULT_REBATE_TARGET_BPS,
            rebate_pool_micro_units: DEFAULT_REBATE_POOL_MICRO_UNITS,
            low_fee_batch_target: DEFAULT_LOW_FEE_BATCH_TARGET,
            low_fee_batch_limit: DEFAULT_LOW_FEE_BATCH_LIMIT,
            allowed_wallet_families,
            operator_set_root: fixed_root("devnet-operator-set"),
            compatibility_manifest_root: fixed_root("devnet-wallet-compatibility-manifest"),
        }
    }

    pub fn validate(&self) -> Result<()> {
        require(self.chain_id == CHAIN_ID, "config chain id mismatch")?;
        require(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security below seraphis migration policy",
        )?;
        require(
            self.batch_anonymity_set_size >= self.min_anonymity_set_size,
            "batch anonymity set below minimum",
        )?;
        require(
            self.max_migration_fee_bps <= MAX_BPS,
            "max migration fee above bps range",
        )?;
        require(
            self.rebate_target_bps <= self.max_migration_fee_bps,
            "rebate target above max migration fee",
        )?;
        require(
            self.low_fee_batch_target <= self.low_fee_batch_limit,
            "batch target above batch limit",
        )?;
        require(
            self.max_redaction_units_per_account <= self.redaction_budget_units,
            "per account redaction cap above global budget",
        )?;
        require(
            !self.allowed_wallet_families.is_empty(),
            "no wallet families allowed",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_anonymity_set_size": self.min_anonymity_set_size,
            "batch_anonymity_set_size": self.batch_anonymity_set_size,
            "epoch_ttl_blocks": self.epoch_ttl_blocks,
            "admission_ttl_blocks": self.admission_ttl_blocks,
            "wallet_lane_ttl_blocks": self.wallet_lane_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "redaction_budget_units": self.redaction_budget_units,
            "max_redaction_units_per_account": self.max_redaction_units_per_account,
            "max_retry_attempts": self.max_retry_attempts,
            "quarantine_ttl_blocks": self.quarantine_ttl_blocks,
            "max_migration_fee_bps": self.max_migration_fee_bps,
            "rebate_target_bps": self.rebate_target_bps,
            "rebate_pool_micro_units": self.rebate_pool_micro_units,
            "low_fee_batch_target": self.low_fee_batch_target,
            "low_fee_batch_limit": self.low_fee_batch_limit,
            "allowed_wallet_families": self.allowed_wallet_families,
            "operator_set_root": self.operator_set_root,
            "compatibility_manifest_root": self.compatibility_manifest_root
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub migration_epochs: u64,
    pub shielded_account_commitments: u64,
    pub pq_migration_attestations: u64,
    pub wallet_compatibility_lanes: u64,
    pub low_fee_migration_rebates: u64,
    pub privacy_redaction_budgets: u64,
    pub quarantine_records: u64,
    pub retry_records: u64,
    pub deterministic_public_records: u64,
    pub accepted_attestations: u64,
    pub rejected_attestations: u64,
    pub migrated_accounts: u64,
    pub redaction_units_consumed: u64,
    pub retry_attempts: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "migration_epochs": self.migration_epochs,
            "shielded_account_commitments": self.shielded_account_commitments,
            "pq_migration_attestations": self.pq_migration_attestations,
            "wallet_compatibility_lanes": self.wallet_compatibility_lanes,
            "low_fee_migration_rebates": self.low_fee_migration_rebates,
            "privacy_redaction_budgets": self.privacy_redaction_budgets,
            "quarantine_records": self.quarantine_records,
            "retry_records": self.retry_records,
            "deterministic_public_records": self.deterministic_public_records,
            "accepted_attestations": self.accepted_attestations,
            "rejected_attestations": self.rejected_attestations,
            "migrated_accounts": self.migrated_accounts,
            "redaction_units_consumed": self.redaction_units_consumed,
            "retry_attempts": self.retry_attempts
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MigrationEpoch {
    pub epoch_id: String,
    pub status: EpochStatus,
    pub start_height: u64,
    pub admission_height: u64,
    pub enforce_height: u64,
    pub expires_height: u64,
    pub monero_activation_height: u64,
    pub min_pq_security_bits: u16,
    pub min_anonymity_set_size: u64,
    pub target_account_kinds: BTreeSet<AccountKind>,
    pub wallet_lane_root: String,
    pub shielded_commitment_root: String,
    pub attestation_policy_root: String,
    pub rebate_pool_commitment: String,
    pub redaction_budget_root: String,
    pub previous_epoch_root: String,
    pub operator_notes_commitment: String,
}

impl MigrationEpoch {
    pub fn public_record(&self) -> Value {
        json!({
            "epoch_id": self.epoch_id,
            "status": self.status.as_str(),
            "start_height": self.start_height,
            "admission_height": self.admission_height,
            "enforce_height": self.enforce_height,
            "expires_height": self.expires_height,
            "monero_activation_height": self.monero_activation_height,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_anonymity_set_size": self.min_anonymity_set_size,
            "target_account_kinds": self.target_account_kinds.iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
            "wallet_lane_root": self.wallet_lane_root,
            "shielded_commitment_root": self.shielded_commitment_root,
            "attestation_policy_root": self.attestation_policy_root,
            "rebate_pool_commitment": self.rebate_pool_commitment,
            "redaction_budget_root": self.redaction_budget_root,
            "previous_epoch_root": self.previous_epoch_root,
            "operator_notes_commitment": self.operator_notes_commitment
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShieldedAccountCommitment {
    pub commitment_id: String,
    pub epoch_id: String,
    pub account_kind: AccountKind,
    pub legacy_account_commitment: String,
    pub seraphis_account_commitment: String,
    pub jamtis_address_commitment: String,
    pub balance_commitment: String,
    pub nullifier_root: String,
    pub wallet_family: String,
    pub wallet_lane_id: Option<String>,
    pub anonymity_set_size: u64,
    pub status: CommitmentStatus,
    pub registered_height: u64,
    pub last_attestation_id: Option<String>,
    pub quarantine_id: Option<String>,
}

impl ShieldedAccountCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "epoch_id": self.epoch_id,
            "account_kind": self.account_kind.as_str(),
            "legacy_account_commitment": self.legacy_account_commitment,
            "seraphis_account_commitment": self.seraphis_account_commitment,
            "jamtis_address_commitment": self.jamtis_address_commitment,
            "balance_commitment": self.balance_commitment,
            "nullifier_root": self.nullifier_root,
            "wallet_family": self.wallet_family,
            "wallet_lane_id": self.wallet_lane_id,
            "anonymity_set_size": self.anonymity_set_size,
            "status": self.status.as_str(),
            "registered_height": self.registered_height,
            "last_attestation_id": self.last_attestation_id,
            "quarantine_id": self.quarantine_id
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqMigrationAttestation {
    pub attestation_id: String,
    pub commitment_id: String,
    pub epoch_id: String,
    pub attestation_kind: AttestationKind,
    pub pq_scheme: PqScheme,
    pub attestor_commitment: String,
    pub proof_commitment: String,
    pub wallet_lane_id: Option<String>,
    pub nullifier: String,
    pub redaction_class: RedactionClass,
    pub fee_bps: u64,
    pub rebate_id: Option<String>,
    pub status: AttestationStatus,
    pub submitted_height: u64,
    pub expires_height: u64,
}

impl PqMigrationAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "commitment_id": self.commitment_id,
            "epoch_id": self.epoch_id,
            "attestation_kind": self.attestation_kind.as_str(),
            "pq_scheme": self.pq_scheme.as_str(),
            "attestor_commitment": self.attestor_commitment,
            "proof_commitment": self.proof_commitment,
            "wallet_lane_id": self.wallet_lane_id,
            "nullifier": self.nullifier,
            "redaction_class": self.redaction_class.as_str(),
            "fee_bps": self.fee_bps,
            "rebate_id": self.rebate_id,
            "status": self.status.as_str(),
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletCompatibilityLane {
    pub lane_id: String,
    pub epoch_id: String,
    pub lane_kind: WalletLaneKind,
    pub wallet_family: String,
    pub min_wallet_version: String,
    pub compatibility_root: String,
    pub encrypted_hint_root: String,
    pub status: LaneStatus,
    pub capacity_accounts: u64,
    pub admitted_accounts: u64,
    pub rebate_priority_bps: u64,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl WalletCompatibilityLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "epoch_id": self.epoch_id,
            "lane_kind": self.lane_kind.as_str(),
            "wallet_family": self.wallet_family,
            "min_wallet_version": self.min_wallet_version,
            "compatibility_root": self.compatibility_root,
            "encrypted_hint_root": self.encrypted_hint_root,
            "status": self.status.as_str(),
            "capacity_accounts": self.capacity_accounts,
            "admitted_accounts": self.admitted_accounts,
            "rebate_priority_bps": self.rebate_priority_bps,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeMigrationRebate {
    pub rebate_id: String,
    pub commitment_id: String,
    pub attestation_id: Option<String>,
    pub lane_id: String,
    pub rebate_commitment: String,
    pub quoted_fee_bps: u64,
    pub target_fee_bps: u64,
    pub rebate_micro_units: u64,
    pub status: RebateStatus,
    pub reserved_height: u64,
    pub settled_height: u64,
}

impl LowFeeMigrationRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "commitment_id": self.commitment_id,
            "attestation_id": self.attestation_id,
            "lane_id": self.lane_id,
            "rebate_commitment": self.rebate_commitment,
            "quoted_fee_bps": self.quoted_fee_bps,
            "target_fee_bps": self.target_fee_bps,
            "rebate_micro_units": self.rebate_micro_units,
            "status": self.status.as_str(),
            "reserved_height": self.reserved_height,
            "settled_height": self.settled_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub epoch_id: String,
    pub subject_commitment: String,
    pub total_units: u64,
    pub used_units: u64,
    pub remaining_units: u64,
    pub allowed_classes: BTreeSet<RedactionClass>,
    pub last_redaction_class: RedactionClass,
    pub disclosure_root: String,
    pub opened_height: u64,
    pub updated_height: u64,
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "epoch_id": self.epoch_id,
            "subject_commitment": self.subject_commitment,
            "total_units": self.total_units,
            "used_units": self.used_units,
            "remaining_units": self.remaining_units,
            "allowed_classes": self.allowed_classes.iter().map(|class| class.as_str()).collect::<Vec<_>>(),
            "last_redaction_class": self.last_redaction_class.as_str(),
            "disclosure_root": self.disclosure_root,
            "opened_height": self.opened_height,
            "updated_height": self.updated_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuarantineRecord {
    pub quarantine_id: String,
    pub commitment_id: String,
    pub attestation_id: Option<String>,
    pub reason: QuarantineReason,
    pub status: QuarantineStatus,
    pub retry_count: u8,
    pub max_retry_count: u8,
    pub evidence_root: String,
    pub opened_height: u64,
    pub next_retry_height: u64,
    pub expires_height: u64,
}

impl QuarantineRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "commitment_id": self.commitment_id,
            "attestation_id": self.attestation_id,
            "reason": self.reason.as_str(),
            "status": self.status.as_str(),
            "retry_count": self.retry_count,
            "max_retry_count": self.max_retry_count,
            "evidence_root": self.evidence_root,
            "opened_height": self.opened_height,
            "next_retry_height": self.next_retry_height,
            "expires_height": self.expires_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RetryRecord {
    pub retry_id: String,
    pub quarantine_id: String,
    pub commitment_id: String,
    pub attempt: u8,
    pub status: RetryStatus,
    pub scheduled_height: u64,
    pub completed_height: u64,
    pub result_root: String,
}

impl RetryRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "retry_id": self.retry_id,
            "quarantine_id": self.quarantine_id,
            "commitment_id": self.commitment_id,
            "attempt": self.attempt,
            "status": self.status.as_str(),
            "scheduled_height": self.scheduled_height,
            "completed_height": self.completed_height,
            "result_root": self.result_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeterministicPublicRecord {
    pub record_id: String,
    pub kind: String,
    pub subject_id: String,
    pub record_root: String,
    pub state_root_after: String,
    pub emitted_height: u64,
}

impl DeterministicPublicRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "record_root": self.record_root,
            "state_root_after": self.state_root_after,
            "emitted_height": self.emitted_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub epoch_root: String,
    pub shielded_account_commitment_root: String,
    pub pq_migration_attestation_root: String,
    pub wallet_compatibility_lane_root: String,
    pub low_fee_migration_rebate_root: String,
    pub privacy_redaction_budget_root: String,
    pub quarantine_root: String,
    pub retry_root: String,
    pub public_record_root: String,
    pub nullifier_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "epoch_root": self.epoch_root,
            "shielded_account_commitment_root": self.shielded_account_commitment_root,
            "pq_migration_attestation_root": self.pq_migration_attestation_root,
            "wallet_compatibility_lane_root": self.wallet_compatibility_lane_root,
            "low_fee_migration_rebate_root": self.low_fee_migration_rebate_root,
            "privacy_redaction_budget_root": self.privacy_redaction_budget_root,
            "quarantine_root": self.quarantine_root,
            "retry_root": self.retry_root,
            "public_record_root": self.public_record_root,
            "nullifier_root": self.nullifier_root
        })
    }

    pub fn root(&self) -> String {
        value_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub counters: Counters,
    pub migration_epochs: BTreeMap<String, MigrationEpoch>,
    pub shielded_account_commitments: BTreeMap<String, ShieldedAccountCommitment>,
    pub pq_migration_attestations: BTreeMap<String, PqMigrationAttestation>,
    pub wallet_compatibility_lanes: BTreeMap<String, WalletCompatibilityLane>,
    pub low_fee_migration_rebates: BTreeMap<String, LowFeeMigrationRebate>,
    pub privacy_redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub quarantine_records: BTreeMap<String, QuarantineRecord>,
    pub retry_records: BTreeMap<String, RetryRecord>,
    pub deterministic_public_records: BTreeMap<String, DeterministicPublicRecord>,
    pub replay_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config, height: u64) -> Self {
        Self {
            config,
            height,
            counters: Counters::default(),
            migration_epochs: BTreeMap::new(),
            shielded_account_commitments: BTreeMap::new(),
            pq_migration_attestations: BTreeMap::new(),
            wallet_compatibility_lanes: BTreeMap::new(),
            low_fee_migration_rebates: BTreeMap::new(),
            privacy_redaction_budgets: BTreeMap::new(),
            quarantine_records: BTreeMap::new(),
            retry_records: BTreeMap::new(),
            deterministic_public_records: BTreeMap::new(),
            replay_nullifiers: BTreeSet::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), DEVNET_L2_HEIGHT);
        let mut kinds = BTreeSet::new();
        kinds.insert(AccountKind::LegacyRingCt);
        kinds.insert(AccountKind::LegacySubaddress);
        kinds.insert(AccountKind::SeraphisJamtis);

        let epoch = MigrationEpoch {
            epoch_id: "seraphis-migration-epoch-devnet-001".to_string(),
            status: EpochStatus::AdmissionOpen,
            start_height: DEVNET_L2_HEIGHT,
            admission_height: DEVNET_L2_HEIGHT + 20,
            enforce_height: DEVNET_L2_HEIGHT + 5_760,
            expires_height: DEVNET_L2_HEIGHT + DEFAULT_EPOCH_TTL_BLOCKS,
            monero_activation_height: DEVNET_MONERO_HEIGHT + 720,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_anonymity_set_size: DEFAULT_MIN_ANONYMITY_SET_SIZE,
            target_account_kinds: kinds,
            wallet_lane_root: fixed_root("devnet-wallet-lanes"),
            shielded_commitment_root: fixed_root("devnet-shielded-accounts"),
            attestation_policy_root: fixed_root("devnet-attestation-policy"),
            rebate_pool_commitment: "rebate-pool:devnet:seraphis".to_string(),
            redaction_budget_root: fixed_root("devnet-redaction-budget"),
            previous_epoch_root: fixed_root("legacy-ringct-epoch"),
            operator_notes_commitment: fixed_root("devnet-operator-notes"),
        };
        state
            .insert_epoch(epoch.clone())
            .expect("valid devnet epoch");

        let lane = WalletCompatibilityLane {
            lane_id: "wallet-lane-devnet-cli-legacy".to_string(),
            epoch_id: epoch.epoch_id.clone(),
            lane_kind: WalletLaneKind::CliLegacy,
            wallet_family: "monero-cli".to_string(),
            min_wallet_version: "0.19.0.0-seraphis-devnet".to_string(),
            compatibility_root: fixed_root("cli-legacy-compatibility"),
            encrypted_hint_root: fixed_root("cli-legacy-hints"),
            status: LaneStatus::Open,
            capacity_accounts: 50_000,
            admitted_accounts: 0,
            rebate_priority_bps: 8_000,
            opened_height: DEVNET_L2_HEIGHT + 20,
            expires_height: DEVNET_L2_HEIGHT + DEFAULT_WALLET_LANE_TTL_BLOCKS,
        };
        state
            .insert_wallet_lane(lane.clone())
            .expect("valid devnet lane");

        let commitment = ShieldedAccountCommitment {
            commitment_id: "shielded-account-devnet-alice-001".to_string(),
            epoch_id: epoch.epoch_id.clone(),
            account_kind: AccountKind::LegacyRingCt,
            legacy_account_commitment: "legacy-ringct:alice:commitment".to_string(),
            seraphis_account_commitment: "seraphis:jamtis:alice:commitment".to_string(),
            jamtis_address_commitment: fixed_root("alice-jamtis-address"),
            balance_commitment: fixed_root("alice-balance"),
            nullifier_root: fixed_root("alice-nullifiers"),
            wallet_family: lane.wallet_family.clone(),
            wallet_lane_id: Some(lane.lane_id.clone()),
            anonymity_set_size: DEFAULT_BATCH_ANONYMITY_SET_SIZE,
            status: CommitmentStatus::AttestationPending,
            registered_height: DEVNET_L2_HEIGHT + 24,
            last_attestation_id: None,
            quarantine_id: None,
        };
        state
            .register_commitment(commitment.clone())
            .expect("valid devnet commitment");

        let budget = PrivacyRedactionBudget {
            budget_id: "redaction-budget-devnet-alice".to_string(),
            epoch_id: epoch.epoch_id.clone(),
            subject_commitment: commitment.commitment_id.clone(),
            total_units: DEFAULT_MAX_REDACTION_UNITS_PER_ACCOUNT,
            used_units: 0,
            remaining_units: DEFAULT_MAX_REDACTION_UNITS_PER_ACCOUNT,
            allowed_classes: BTreeSet::from([
                RedactionClass::ViewTag,
                RedactionClass::FeeBucket,
                RedactionClass::TimingBucket,
                RedactionClass::LaneHint,
            ]),
            last_redaction_class: RedactionClass::None,
            disclosure_root: fixed_root("alice-redaction-disclosure"),
            opened_height: DEVNET_L2_HEIGHT + 24,
            updated_height: DEVNET_L2_HEIGHT + 24,
        };
        state
            .insert_redaction_budget(budget)
            .expect("valid devnet redaction budget");

        let rebate = state
            .reserve_rebate(
                &commitment.commitment_id,
                &lane.lane_id,
                DEFAULT_MAX_MIGRATION_FEE_BPS,
                1_200_000,
            )
            .expect("valid devnet rebate");
        let attestation = PqMigrationAttestation {
            attestation_id: "pq-seraphis-attestation-devnet-alice-001".to_string(),
            commitment_id: commitment.commitment_id.clone(),
            epoch_id: epoch.epoch_id.clone(),
            attestation_kind: AttestationKind::SpendAuthority,
            pq_scheme: PqScheme::HybridSpendKeyMlDsa87,
            attestor_commitment: "attestor:alice:spend-authority".to_string(),
            proof_commitment: fixed_root("alice-pq-spend-proof"),
            wallet_lane_id: Some(lane.lane_id.clone()),
            nullifier: "nullifier:alice:seraphis-migration:001".to_string(),
            redaction_class: RedactionClass::FeeBucket,
            fee_bps: DEFAULT_MAX_MIGRATION_FEE_BPS,
            rebate_id: Some(rebate.rebate_id.clone()),
            status: AttestationStatus::Submitted,
            submitted_height: DEVNET_L2_HEIGHT + 32,
            expires_height: DEVNET_L2_HEIGHT + DEFAULT_ATTESTATION_TTL_BLOCKS,
        };
        state
            .submit_attestation(attestation)
            .expect("valid devnet attestation");
        state.emit_public_record("bootstrap", "devnet").ok();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let commitment = ShieldedAccountCommitment {
            commitment_id: "shielded-account-demo-bob-002".to_string(),
            epoch_id: "seraphis-migration-epoch-devnet-001".to_string(),
            account_kind: AccountKind::LegacySubaddress,
            legacy_account_commitment: "legacy-subaddress:bob:commitment".to_string(),
            seraphis_account_commitment: "seraphis:jamtis:bob:commitment".to_string(),
            jamtis_address_commitment: fixed_root("bob-jamtis-address"),
            balance_commitment: fixed_root("bob-balance"),
            nullifier_root: fixed_root("bob-nullifiers"),
            wallet_family: "monero-cli".to_string(),
            wallet_lane_id: Some("wallet-lane-devnet-cli-legacy".to_string()),
            anonymity_set_size: DEFAULT_BATCH_ANONYMITY_SET_SIZE,
            status: CommitmentStatus::Registered,
            registered_height: DEVNET_L2_HEIGHT + 40,
            last_attestation_id: None,
            quarantine_id: None,
        };
        state
            .register_commitment(commitment)
            .expect("demo commitment");
        state
            .open_quarantine(
                "shielded-account-demo-bob-002",
                None,
                QuarantineReason::OperatorReview,
                fixed_root("demo-bob-review"),
            )
            .expect("demo quarantine");
        state.emit_public_record("demo", "demo-seraphis").ok();
        state
    }

    pub fn insert_epoch(&mut self, epoch: MigrationEpoch) -> Result<()> {
        self.config.validate()?;
        require(self.migration_epochs.len() < MAX_EPOCHS, "too many epochs")?;
        require(
            epoch.min_pq_security_bits >= self.config.min_pq_security_bits,
            "epoch pq security below config",
        )?;
        require(
            epoch.min_anonymity_set_size >= self.config.min_anonymity_set_size,
            "epoch anonymity set below config",
        )?;
        self.migration_epochs.insert(epoch.epoch_id.clone(), epoch);
        self.counters.migration_epochs = self.migration_epochs.len() as u64;
        Ok(())
    }

    pub fn insert_wallet_lane(&mut self, lane: WalletCompatibilityLane) -> Result<()> {
        require(
            self.wallet_compatibility_lanes.len() < MAX_WALLET_LANES,
            "too many wallet lanes",
        )?;
        let epoch = self
            .migration_epochs
            .get(&lane.epoch_id)
            .ok_or_else(|| "wallet lane epoch missing".to_string())?;
        require(
            epoch.status.accepts_commitments(),
            "epoch is not accepting wallet lanes",
        )?;
        require(
            self.config
                .allowed_wallet_families
                .contains(&lane.wallet_family),
            "wallet family not allowed",
        )?;
        require(
            lane.rebate_priority_bps <= MAX_BPS,
            "lane priority above bps",
        )?;
        self.wallet_compatibility_lanes
            .insert(lane.lane_id.clone(), lane);
        self.counters.wallet_compatibility_lanes = self.wallet_compatibility_lanes.len() as u64;
        Ok(())
    }

    pub fn register_commitment(&mut self, commitment: ShieldedAccountCommitment) -> Result<()> {
        require(
            self.shielded_account_commitments.len() < MAX_COMMITMENTS,
            "too many shielded commitments",
        )?;
        let epoch = self
            .migration_epochs
            .get(&commitment.epoch_id)
            .ok_or_else(|| "commitment epoch missing".to_string())?;
        require(
            epoch.status.accepts_commitments(),
            "epoch not accepting accounts",
        )?;
        require(
            epoch
                .target_account_kinds
                .contains(&commitment.account_kind),
            "account kind outside epoch target",
        )?;
        require(
            commitment.anonymity_set_size >= epoch.min_anonymity_set_size,
            "commitment anonymity set too small",
        )?;
        require(
            self.config
                .allowed_wallet_families
                .contains(&commitment.wallet_family),
            "commitment wallet family not allowed",
        )?;
        self.shielded_account_commitments
            .insert(commitment.commitment_id.clone(), commitment);
        self.counters.shielded_account_commitments = self.shielded_account_commitments.len() as u64;
        Ok(())
    }

    pub fn insert_redaction_budget(&mut self, budget: PrivacyRedactionBudget) -> Result<()> {
        require(
            self.privacy_redaction_budgets.len() < MAX_REDACTION_BUDGETS,
            "too many redaction budgets",
        )?;
        require(
            self.shielded_account_commitments
                .contains_key(&budget.subject_commitment),
            "redaction subject missing",
        )?;
        require(
            budget.total_units <= self.config.max_redaction_units_per_account,
            "redaction budget above per-account cap",
        )?;
        require(
            budget.used_units + budget.remaining_units == budget.total_units,
            "redaction budget accounting mismatch",
        )?;
        self.privacy_redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        self.counters.privacy_redaction_budgets = self.privacy_redaction_budgets.len() as u64;
        Ok(())
    }

    pub fn reserve_rebate(
        &mut self,
        commitment_id: &str,
        lane_id: &str,
        quoted_fee_bps: u64,
        estimated_fee_micro_units: u64,
    ) -> Result<LowFeeMigrationRebate> {
        require(
            self.low_fee_migration_rebates.len() < MAX_REBATES,
            "too many rebates",
        )?;
        require(
            quoted_fee_bps <= self.config.max_migration_fee_bps,
            "quoted fee above migration policy",
        )?;
        require(
            self.shielded_account_commitments
                .contains_key(commitment_id),
            "rebate commitment missing",
        )?;
        let lane = self
            .wallet_compatibility_lanes
            .get(lane_id)
            .ok_or_else(|| "rebate wallet lane missing".to_string())?;
        require(lane.status.accepts_accounts(), "wallet lane closed")?;
        let fee_delta_bps = quoted_fee_bps.saturating_sub(self.config.rebate_target_bps);
        let rebate_micro_units = estimated_fee_micro_units
            .saturating_mul(fee_delta_bps)
            .saturating_div(MAX_BPS);
        let rebate_id = deterministic_id("seraphis-rebate", &[commitment_id, lane_id]);
        let rebate = LowFeeMigrationRebate {
            rebate_id: rebate_id.clone(),
            commitment_id: commitment_id.to_string(),
            attestation_id: None,
            lane_id: lane_id.to_string(),
            rebate_commitment: value_root(
                "REBATE-COMMITMENT",
                &json!([commitment_id, lane_id, quoted_fee_bps, rebate_micro_units]),
            ),
            quoted_fee_bps,
            target_fee_bps: self.config.rebate_target_bps,
            rebate_micro_units,
            status: RebateStatus::Reserved,
            reserved_height: self.height,
            settled_height: 0,
        };
        self.low_fee_migration_rebates
            .insert(rebate_id, rebate.clone());
        self.counters.low_fee_migration_rebates = self.low_fee_migration_rebates.len() as u64;
        Ok(rebate)
    }

    pub fn submit_attestation(&mut self, mut attestation: PqMigrationAttestation) -> Result<()> {
        require(
            self.pq_migration_attestations.len() < MAX_ATTESTATIONS,
            "too many pq attestations",
        )?;
        require(
            attestation.pq_scheme.security_bits() >= self.config.min_pq_security_bits,
            "attestation pq security below policy",
        )?;
        require(
            attestation.fee_bps <= self.config.max_migration_fee_bps,
            "attestation fee above policy",
        )?;
        require(
            !self.replay_nullifiers.contains(&attestation.nullifier),
            "duplicate attestation nullifier",
        )?;
        let epoch = self
            .migration_epochs
            .get(&attestation.epoch_id)
            .ok_or_else(|| "attestation epoch missing".to_string())?;
        require(
            epoch.status.accepts_attestations(),
            "epoch not accepting attestations",
        )?;
        let commitment = self
            .shielded_account_commitments
            .get(&attestation.commitment_id)
            .ok_or_else(|| "attestation commitment missing".to_string())?;
        require(commitment.status.can_attest(), "commitment cannot attest")?;
        if let Some(lane_id) = attestation.wallet_lane_id.as_ref() {
            let lane = self
                .wallet_compatibility_lanes
                .get(lane_id)
                .ok_or_else(|| "attestation wallet lane missing".to_string())?;
            require(lane.status.accepts_accounts(), "attestation lane closed")?;
            require(
                lane.wallet_family == commitment.wallet_family,
                "wallet lane family mismatch",
            )?;
        }
        self.consume_redaction_units(&attestation.commitment_id, attestation.redaction_class)?;
        attestation.status = AttestationStatus::Accepted;
        self.replay_nullifiers.insert(attestation.nullifier.clone());
        if let Some(rebate_id) = attestation.rebate_id.clone() {
            if let Some(rebate) = self.low_fee_migration_rebates.get_mut(&rebate_id) {
                rebate.attestation_id = Some(attestation.attestation_id.clone());
                rebate.status = RebateStatus::Applied;
            }
        }
        if let Some(commitment) = self
            .shielded_account_commitments
            .get_mut(&attestation.commitment_id)
        {
            commitment.status = CommitmentStatus::Attested;
            commitment.last_attestation_id = Some(attestation.attestation_id.clone());
        }
        self.pq_migration_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.counters.pq_migration_attestations = self.pq_migration_attestations.len() as u64;
        self.counters.accepted_attestations = self.counters.accepted_attestations.saturating_add(1);
        Ok(())
    }

    pub fn open_quarantine(
        &mut self,
        commitment_id: &str,
        attestation_id: Option<String>,
        reason: QuarantineReason,
        evidence_root: String,
    ) -> Result<QuarantineRecord> {
        require(
            self.quarantine_records.len() < MAX_QUARANTINES,
            "too many quarantine records",
        )?;
        require(
            self.shielded_account_commitments
                .contains_key(commitment_id),
            "quarantine commitment missing",
        )?;
        let quarantine_id =
            deterministic_id("seraphis-quarantine", &[commitment_id, reason.as_str()]);
        let record = QuarantineRecord {
            quarantine_id: quarantine_id.clone(),
            commitment_id: commitment_id.to_string(),
            attestation_id,
            reason,
            status: QuarantineStatus::Open,
            retry_count: 0,
            max_retry_count: self.config.max_retry_attempts,
            evidence_root,
            opened_height: self.height,
            next_retry_height: self.height + self.config.admission_ttl_blocks.min(96),
            expires_height: self.height + self.config.quarantine_ttl_blocks,
        };
        if let Some(commitment) = self.shielded_account_commitments.get_mut(commitment_id) {
            commitment.status = CommitmentStatus::Quarantined;
            commitment.quarantine_id = Some(quarantine_id.clone());
        }
        self.quarantine_records
            .insert(quarantine_id.clone(), record.clone());
        self.counters.quarantine_records = self.quarantine_records.len() as u64;
        Ok(record)
    }

    pub fn schedule_retry(&mut self, quarantine_id: &str) -> Result<RetryRecord> {
        require(
            self.retry_records.len() < MAX_RETRY_RECORDS,
            "too many retries",
        )?;
        let quarantine = self
            .quarantine_records
            .get_mut(quarantine_id)
            .ok_or_else(|| "quarantine missing".to_string())?;
        require(quarantine.status.live(), "quarantine not retryable")?;
        require(
            quarantine.retry_count < quarantine.max_retry_count,
            "retry attempts exhausted",
        )?;
        quarantine.retry_count = quarantine.retry_count.saturating_add(1);
        quarantine.status = QuarantineStatus::RetryScheduled;
        quarantine.next_retry_height = self.height + 64 * quarantine.retry_count as u64;
        let retry_id = deterministic_id(
            "seraphis-retry",
            &[quarantine_id, &quarantine.retry_count.to_string()],
        );
        let retry = RetryRecord {
            retry_id: retry_id.clone(),
            quarantine_id: quarantine_id.to_string(),
            commitment_id: quarantine.commitment_id.clone(),
            attempt: quarantine.retry_count,
            status: RetryStatus::Scheduled,
            scheduled_height: quarantine.next_retry_height,
            completed_height: 0,
            result_root: fixed_root("retry-pending"),
        };
        self.retry_records.insert(retry_id, retry.clone());
        self.counters.retry_records = self.retry_records.len() as u64;
        self.counters.retry_attempts = self.counters.retry_attempts.saturating_add(1);
        Ok(retry)
    }

    pub fn settle_commitment(&mut self, commitment_id: &str) -> Result<()> {
        let commitment = self
            .shielded_account_commitments
            .get_mut(commitment_id)
            .ok_or_else(|| "settlement commitment missing".to_string())?;
        require(
            matches!(
                commitment.status,
                CommitmentStatus::Attested | CommitmentStatus::LaneAssigned
            ),
            "commitment not ready to settle",
        )?;
        commitment.status = CommitmentStatus::Migrated;
        self.counters.migrated_accounts = self.counters.migrated_accounts.saturating_add(1);
        for rebate in self.low_fee_migration_rebates.values_mut() {
            if rebate.commitment_id == commitment_id
                && matches!(rebate.status, RebateStatus::Applied)
            {
                rebate.status = RebateStatus::Settled;
                rebate.settled_height = self.height;
            }
        }
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: value_root("CONFIG", &self.config.public_record()),
            counters_root: value_root("COUNTERS", &self.counters.public_record()),
            epoch_root: map_root(
                "EPOCHS",
                &self.migration_epochs,
                MigrationEpoch::public_record,
            ),
            shielded_account_commitment_root: map_root(
                "SHIELDED-ACCOUNT-COMMITMENTS",
                &self.shielded_account_commitments,
                ShieldedAccountCommitment::public_record,
            ),
            pq_migration_attestation_root: map_root(
                "PQ-MIGRATION-ATTESTATIONS",
                &self.pq_migration_attestations,
                PqMigrationAttestation::public_record,
            ),
            wallet_compatibility_lane_root: map_root(
                "WALLET-COMPATIBILITY-LANES",
                &self.wallet_compatibility_lanes,
                WalletCompatibilityLane::public_record,
            ),
            low_fee_migration_rebate_root: map_root(
                "LOW-FEE-MIGRATION-REBATES",
                &self.low_fee_migration_rebates,
                LowFeeMigrationRebate::public_record,
            ),
            privacy_redaction_budget_root: map_root(
                "PRIVACY-REDACTION-BUDGETS",
                &self.privacy_redaction_budgets,
                PrivacyRedactionBudget::public_record,
            ),
            quarantine_root: map_root(
                "QUARANTINE-RECORDS",
                &self.quarantine_records,
                QuarantineRecord::public_record,
            ),
            retry_root: map_root(
                "RETRY-RECORDS",
                &self.retry_records,
                RetryRecord::public_record,
            ),
            public_record_root: map_root(
                "DETERMINISTIC-PUBLIC-RECORDS",
                &self.deterministic_public_records,
                DeterministicPublicRecord::public_record,
            ),
            nullifier_root: set_root("REPLAY-NULLIFIERS", &self.replay_nullifiers),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "public_record_suite": PUBLIC_RECORD_SUITE,
            "chain_id": self.config.chain_id,
            "height": self.height,
            "l2_height": self.config.l2_height,
            "monero_height": self.config.monero_height,
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.root()
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }

    pub fn emit_public_record(&mut self, kind: &str, subject_id: &str) -> Result<String> {
        require(
            self.deterministic_public_records.len() < MAX_PUBLIC_RECORDS,
            "too many public records",
        )?;
        let record_root = value_root("PUBLIC-RECORD-PAYLOAD", &self.public_record());
        let state_root_after = state_root_from_public_record(&self.public_record());
        let record_id =
            deterministic_id("seraphis-public-record", &[kind, subject_id, &record_root]);
        let record = DeterministicPublicRecord {
            record_id: record_id.clone(),
            kind: kind.to_string(),
            subject_id: subject_id.to_string(),
            record_root,
            state_root_after,
            emitted_height: self.height,
        };
        self.deterministic_public_records
            .insert(record_id.clone(), record);
        self.counters.deterministic_public_records = self.deterministic_public_records.len() as u64;
        Ok(record_id)
    }

    fn consume_redaction_units(
        &mut self,
        commitment_id: &str,
        class: RedactionClass,
    ) -> Result<()> {
        let units = class.units();
        if units == 0 {
            return Ok(());
        }
        let budget = self
            .privacy_redaction_budgets
            .values_mut()
            .find(|budget| budget.subject_commitment == commitment_id)
            .ok_or_else(|| "redaction budget missing".to_string())?;
        require(
            budget.allowed_classes.contains(&class),
            "redaction class not allowed",
        )?;
        require(
            budget.remaining_units >= units,
            "redaction budget exhausted",
        )?;
        budget.used_units = budget.used_units.saturating_add(units);
        budget.remaining_units = budget.remaining_units.saturating_sub(units);
        budget.last_redaction_class = class;
        budget.updated_height = self.height;
        self.counters.redaction_units_consumed =
            self.counters.redaction_units_consumed.saturating_add(units);
        Ok(())
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}

pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SERAPHIS-MIGRATION-COORDINATOR-STATE",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-SERAPHIS-MIGRATION-COORDINATOR-{domain}"),
        &[HashPart::Json(value)],
        32,
    )
}

pub fn fixed_root(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SERAPHIS-MIGRATION-COORDINATOR-FIXED",
        &[HashPart::Str(label)],
        32,
    )
}

pub fn deterministic_id(prefix: &str, parts: &[&str]) -> String {
    let root = domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SERAPHIS-MIGRATION-COORDINATOR-ID",
        &[HashPart::Str(prefix), HashPart::Json(&json!(parts))],
        16,
    );
    format!("{prefix}-{root}")
}

pub fn map_records<T, F>(values: &BTreeMap<String, T>, public_record: F) -> Value
where
    F: Fn(&T) -> Value,
{
    let mut object = serde_json::Map::new();
    for (key, value) in values {
        object.insert(key.clone(), public_record(value));
    }
    Value::Object(object)
}

pub fn map_root<T, F>(domain: &str, values: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = values
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "record": public_record(value)
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values
        .iter()
        .map(|value| {
            json!({
                "value": value
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
