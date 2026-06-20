use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialHybridNullifierMigrationFeeMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_HYBRID_NULLIFIER_MIGRATION_FEE_MARKET_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-hybrid-nullifier-migration-fee-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_HYBRID_NULLIFIER_MIGRATION_FEE_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const HYBRID_NULLIFIER_SUITE: &str =
    "ringct-seraphis-hybrid-nullifier-migration-commitment-root-v1";
pub const MIGRATION_POLICY_SUITE: &str = "pq-hybrid-nullifier-migration-policy-root-v1";
pub const FEE_BID_SUITE: &str = "confidential-nullifier-migration-fee-bid-root-v1";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-hybrid-nullifier-migration-attestation-v1";
pub const SETTLEMENT_WINDOW_SUITE: &str =
    "confidential-hybrid-nullifier-fee-market-settlement-window-root-v1";
pub const LOW_FEE_REBATE_SUITE: &str =
    "low-fee-hybrid-nullifier-migration-rebate-commitment-root-v1";
pub const REDACTION_BUDGET_SUITE: &str = "hybrid-nullifier-migration-redaction-budget-root-v1";
pub const OPERATOR_SUMMARY_SUITE: &str =
    "redacted-operator-hybrid-nullifier-migration-summary-root-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "public-pq-confidential-hybrid-nullifier-migration-fee-market-record-v1";
pub const PUBLIC_ROOT_SUITE: &str =
    "public-pq-confidential-hybrid-nullifier-migration-fee-market-roots-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_key_images_nullifiers_addresses_amounts_view_keys_spend_keys_or_bidder_linkage_graphs";

pub const DEVNET_L2_HEIGHT: u64 = 1_934_400;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_752_000;
pub const DEVNET_EPOCH: u64 = 4_128;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_COHORT_ANONYMITY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_COHORT_ANONYMITY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_POLICY_TTL_BLOCKS: u64 = 43_200;
pub const DEFAULT_COHORT_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_BID_TTL_BLOCKS: u64 = 256;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 960;
pub const DEFAULT_WINDOW_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 4_320;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 30_000;
pub const DEFAULT_MAX_REDACTION_UNITS_PER_COHORT: u64 = 96;
pub const DEFAULT_LOW_FEE_CAP_BPS: u64 = 12;
pub const DEFAULT_TARGET_CLEARING_FEE_BPS: u64 = 8;
pub const DEFAULT_REBATE_BPS: u64 = 7;
pub const DEFAULT_OPERATOR_SUMMARY_MIN_K: u64 = 128;
pub const DEFAULT_MAX_COHORT_ITEMS: usize = 65_536;
pub const DEFAULT_MAX_SETTLEMENT_ITEMS: usize = 8_192;
pub const MAX_MIGRATION_POLICIES: usize = 1_048_576;
pub const MAX_NULLIFIER_COHORTS: usize = 4_194_304;
pub const MAX_FEE_BIDS: usize = 8_388_608;
pub const MAX_PQ_ATTESTATIONS: usize = 8_388_608;
pub const MAX_SETTLEMENT_WINDOWS: usize = 1_048_576;
pub const MAX_REBATES: usize = 8_388_608;
pub const MAX_REDACTION_BUDGETS: usize = 2_097_152;
pub const MAX_OPERATOR_SUMMARIES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationPhase {
    Planned,
    PrivacyPrimed,
    IntakeOpen,
    FeeDiscovery,
    Clearing,
    RebateSettlement,
    Enforced,
    Complete,
    Paused,
    Revoked,
}

impl MigrationPhase {
    pub fn accepts_cohorts(self) -> bool {
        matches!(
            self,
            Self::PrivacyPrimed | Self::IntakeOpen | Self::FeeDiscovery
        )
    }

    pub fn accepts_bids(self) -> bool {
        matches!(self, Self::IntakeOpen | Self::FeeDiscovery)
    }

    pub fn settles(self) -> bool {
        matches!(
            self,
            Self::Clearing | Self::RebateSettlement | Self::Enforced
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::PrivacyPrimed => "privacy_primed",
            Self::IntakeOpen => "intake_open",
            Self::FeeDiscovery => "fee_discovery",
            Self::Clearing => "clearing",
            Self::RebateSettlement => "rebate_settlement",
            Self::Enforced => "enforced",
            Self::Complete => "complete",
            Self::Paused => "paused",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationPolicyKind {
    LegacyRingCtDrain,
    SeraphisRollover,
    HybridSpendFence,
    ExchangeBatchMigration,
    CustodyRecovery,
    WalletEmergencyRotation,
    WatchtowerQuarantineRelease,
}

impl MigrationPolicyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LegacyRingCtDrain => "legacy_ringct_drain",
            Self::SeraphisRollover => "seraphis_rollover",
            Self::HybridSpendFence => "hybrid_spend_fence",
            Self::ExchangeBatchMigration => "exchange_batch_migration",
            Self::CustodyRecovery => "custody_recovery",
            Self::WalletEmergencyRotation => "wallet_emergency_rotation",
            Self::WatchtowerQuarantineRelease => "watchtower_quarantine_release",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NullifierCohortKind {
    LegacyKeyImage,
    SeraphisNullifier,
    HybridKeyImageNullifier,
    BridgeWithdrawal,
    WalletRecovery,
    ExchangeMigration,
    CustodyMigration,
}

impl NullifierCohortKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LegacyKeyImage => "legacy_key_image",
            Self::SeraphisNullifier => "seraphis_nullifier",
            Self::HybridKeyImageNullifier => "hybrid_key_image_nullifier",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::WalletRecovery => "wallet_recovery",
            Self::ExchangeMigration => "exchange_migration",
            Self::CustodyMigration => "custody_migration",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortStatus {
    Proposed,
    Eligible,
    Attested,
    Bidding,
    Clearing,
    Settled,
    Rebated,
    Quarantined,
    Expired,
    Revoked,
}

impl CohortStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Eligible | Self::Attested | Self::Bidding | Self::Clearing
        )
    }

    pub fn accepts_bid(self) -> bool {
        matches!(self, Self::Eligible | Self::Attested | Self::Bidding)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Eligible => "eligible",
            Self::Attested => "attested",
            Self::Bidding => "bidding",
            Self::Clearing => "clearing",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Quarantined => "quarantined",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeBidClass {
    UserPays,
    WalletSponsored,
    OperatorSponsored,
    BatchDiscount,
    EmergencyLowFee,
    RebateEligible,
}

impl FeeBidClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserPays => "user_pays",
            Self::WalletSponsored => "wallet_sponsored",
            Self::OperatorSponsored => "operator_sponsored",
            Self::BatchDiscount => "batch_discount",
            Self::EmergencyLowFee => "emergency_low_fee",
            Self::RebateEligible => "rebate_eligible",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeBidStatus {
    Submitted,
    Eligible,
    Cleared,
    PartiallyFilled,
    Rebated,
    Rejected,
    Expired,
    Quarantined,
}

impl FeeBidStatus {
    pub fn clearable(self) -> bool {
        matches!(self, Self::Submitted | Self::Eligible)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Eligible => "eligible",
            Self::Cleared => "cleared",
            Self::PartiallyFilled => "partially_filled",
            Self::Rebated => "rebated",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationPurpose {
    PolicyActivation,
    CohortEligibility,
    NullifierUniqueness,
    FeeBidEligibility,
    WindowClearing,
    RebateSettlement,
    OperatorSummary,
    RedactionDisclosure,
}

impl AttestationPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PolicyActivation => "policy_activation",
            Self::CohortEligibility => "cohort_eligibility",
            Self::NullifierUniqueness => "nullifier_uniqueness",
            Self::FeeBidEligibility => "fee_bid_eligibility",
            Self::WindowClearing => "window_clearing",
            Self::RebateSettlement => "rebate_settlement",
            Self::OperatorSummary => "operator_summary",
            Self::RedactionDisclosure => "redaction_disclosure",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Draft,
    Open,
    Sealed,
    Clearing,
    Cleared,
    Rebating,
    Finalized,
    Disputed,
    Expired,
}

impl SettlementStatus {
    pub fn accepts_bids(self) -> bool {
        matches!(self, Self::Open | Self::Sealed)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Clearing => "clearing",
            Self::Cleared => "cleared",
            Self::Rebating => "rebating",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Reserved,
    Eligible,
    Settled,
    Claimed,
    Expired,
    Quarantined,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Eligible => "eligible",
            Self::Settled => "settled",
            Self::Claimed => "claimed",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionScope {
    Policy,
    Cohort,
    FeeBid,
    Attestation,
    SettlementWindow,
    Rebate,
    OperatorSummary,
}

impl RedactionScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Cohort => "cohort",
            Self::FeeBid => "fee_bid",
            Self::Attestation => "attestation",
            Self::SettlementWindow => "settlement_window",
            Self::Rebate => "rebate",
            Self::OperatorSummary => "operator_summary",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub schema_version: u64,
    pub protocol_version: String,
    pub chain_id: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub migration_epoch: u64,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_cohort_anonymity_set_size: u64,
    pub target_cohort_anonymity_set_size: u64,
    pub policy_ttl_blocks: u64,
    pub cohort_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub settlement_window_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub default_redaction_budget_units: u64,
    pub max_redaction_units_per_cohort: u64,
    pub low_fee_cap_bps: u64,
    pub target_clearing_fee_bps: u64,
    pub rebate_bps: u64,
    pub operator_summary_min_k: u64,
    pub max_cohort_items: usize,
    pub max_settlement_items: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            migration_epoch: DEVNET_EPOCH,
            fee_asset_id: "piconero-devnet".to_string(),
            rebate_asset_id: "private-l2-nullifier-migration-rebate-devnet".to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_cohort_anonymity_set_size: DEFAULT_MIN_COHORT_ANONYMITY_SET_SIZE,
            target_cohort_anonymity_set_size: DEFAULT_TARGET_COHORT_ANONYMITY_SET_SIZE,
            policy_ttl_blocks: DEFAULT_POLICY_TTL_BLOCKS,
            cohort_ttl_blocks: DEFAULT_COHORT_TTL_BLOCKS,
            bid_ttl_blocks: DEFAULT_BID_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            settlement_window_ttl_blocks: DEFAULT_WINDOW_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            default_redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
            max_redaction_units_per_cohort: DEFAULT_MAX_REDACTION_UNITS_PER_COHORT,
            low_fee_cap_bps: DEFAULT_LOW_FEE_CAP_BPS,
            target_clearing_fee_bps: DEFAULT_TARGET_CLEARING_FEE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            operator_summary_min_k: DEFAULT_OPERATOR_SUMMARY_MIN_K,
            max_cohort_items: DEFAULT_MAX_COHORT_ITEMS,
            max_settlement_items: DEFAULT_MAX_SETTLEMENT_ITEMS,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            return Err("unsupported hybrid nullifier migration schema version".to_string());
        }
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("unsupported hybrid nullifier migration protocol version".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("post-quantum security target below runtime floor".to_string());
        }
        if self.min_cohort_anonymity_set_size == 0
            || self.target_cohort_anonymity_set_size < self.min_cohort_anonymity_set_size
        {
            return Err("invalid cohort anonymity set target".to_string());
        }
        if self.low_fee_cap_bps > MAX_BPS
            || self.target_clearing_fee_bps > MAX_BPS
            || self.rebate_bps > MAX_BPS
        {
            return Err("fee market basis points exceed MAX_BPS".to_string());
        }
        if self.target_clearing_fee_bps > self.low_fee_cap_bps {
            return Err("target clearing fee exceeds low fee cap".to_string());
        }
        if self.operator_summary_min_k < 2 {
            return Err("operator summary k-anonymity floor too small".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "schema_version": self.schema_version,
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "migration_epoch": self.migration_epoch,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_cohort_anonymity_set_size": self.min_cohort_anonymity_set_size,
            "target_cohort_anonymity_set_size": self.target_cohort_anonymity_set_size,
            "policy_ttl_blocks": self.policy_ttl_blocks,
            "cohort_ttl_blocks": self.cohort_ttl_blocks,
            "bid_ttl_blocks": self.bid_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "settlement_window_ttl_blocks": self.settlement_window_ttl_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "default_redaction_budget_units": self.default_redaction_budget_units,
            "max_redaction_units_per_cohort": self.max_redaction_units_per_cohort,
            "low_fee_cap_bps": self.low_fee_cap_bps,
            "target_clearing_fee_bps": self.target_clearing_fee_bps,
            "rebate_bps": self.rebate_bps,
            "operator_summary_min_k": self.operator_summary_min_k,
            "max_cohort_items": self.max_cohort_items,
            "max_settlement_items": self.max_settlement_items,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub migration_policies: u64,
    pub active_policies: u64,
    pub nullifier_cohorts: u64,
    pub live_cohorts: u64,
    pub fee_bids: u64,
    pub cleared_bids: u64,
    pub pq_attestations: u64,
    pub settlement_windows: u64,
    pub cleared_windows: u64,
    pub rebates: u64,
    pub settled_rebates: u64,
    pub redaction_budgets: u64,
    pub redaction_units_reserved: u64,
    pub redaction_units_spent: u64,
    pub operator_summaries: u64,
    pub quarantined_items: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MigrationPolicy {
    pub policy_id: String,
    pub kind: MigrationPolicyKind,
    pub phase: MigrationPhase,
    pub policy_commitment_root: String,
    pub legacy_domain_root: String,
    pub pq_domain_root: String,
    pub nullifier_fence_root: String,
    pub min_anonymity_set_size: u64,
    pub max_user_fee_bps: u64,
    pub rebate_bps: u64,
    pub opens_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub operator_set_root: String,
    pub notes: BTreeMap<String, String>,
}

impl MigrationPolicy {
    pub fn new(
        policy_id: impl Into<String>,
        kind: MigrationPolicyKind,
        phase: MigrationPhase,
        policy_commitment_root: impl Into<String>,
        legacy_domain_root: impl Into<String>,
        pq_domain_root: impl Into<String>,
        nullifier_fence_root: impl Into<String>,
        config: &Config,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            kind,
            phase,
            policy_commitment_root: policy_commitment_root.into(),
            legacy_domain_root: legacy_domain_root.into(),
            pq_domain_root: pq_domain_root.into(),
            nullifier_fence_root: nullifier_fence_root.into(),
            min_anonymity_set_size: config.min_cohort_anonymity_set_size,
            max_user_fee_bps: config.low_fee_cap_bps,
            rebate_bps: config.rebate_bps,
            opens_at_l2_height: config.l2_height,
            expires_at_l2_height: config.l2_height + config.policy_ttl_blocks,
            operator_set_root: fixed_root("devnet-operator-set"),
            notes: BTreeMap::new(),
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.policy_id.is_empty() {
            return Err("migration policy id is empty".to_string());
        }
        if self.min_anonymity_set_size < config.min_cohort_anonymity_set_size {
            return Err("migration policy anonymity floor below config".to_string());
        }
        if self.max_user_fee_bps > config.low_fee_cap_bps || self.rebate_bps > MAX_BPS {
            return Err("migration policy fee bounds exceed config".to_string());
        }
        if self.expires_at_l2_height <= self.opens_at_l2_height {
            return Err("migration policy expires before opening".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "kind": self.kind.as_str(),
            "phase": self.phase.as_str(),
            "policy_commitment_root": self.policy_commitment_root,
            "legacy_domain_root": self.legacy_domain_root,
            "pq_domain_root": self.pq_domain_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "min_anonymity_set_size": self.min_anonymity_set_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "rebate_bps": self.rebate_bps,
            "opens_at_l2_height": self.opens_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "operator_set_root": self.operator_set_root,
            "notes": self.notes,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("MIGRATION_POLICY", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NullifierCohort {
    pub cohort_id: String,
    pub policy_id: String,
    pub kind: NullifierCohortKind,
    pub status: CohortStatus,
    pub nullifier_commitment_root: String,
    pub key_image_fence_root: String,
    pub stealth_address_domain_root: String,
    pub decoy_set_root: String,
    pub item_count: u64,
    pub anonymity_set_size: u64,
    pub privacy_entropy_bits: u16,
    pub pq_security_bits: u16,
    pub admitted_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub quarantine_root: String,
}

impl NullifierCohort {
    pub fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "policy_id": self.policy_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "nullifier_commitment_root": self.nullifier_commitment_root,
            "key_image_fence_root": self.key_image_fence_root,
            "stealth_address_domain_root": self.stealth_address_domain_root,
            "decoy_set_root": self.decoy_set_root,
            "item_count": self.item_count,
            "anonymity_set_size": self.anonymity_set_size,
            "privacy_entropy_bits": self.privacy_entropy_bits,
            "pq_security_bits": self.pq_security_bits,
            "admitted_at_l2_height": self.admitted_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "quarantine_root": self.quarantine_root,
        })
    }

    pub fn validate(&self, policy: &MigrationPolicy, config: &Config) -> Result<()> {
        if self.policy_id != policy.policy_id {
            return Err("cohort policy mismatch".to_string());
        }
        if !policy.phase.accepts_cohorts() {
            return Err("migration policy phase does not accept cohorts".to_string());
        }
        if self.anonymity_set_size < policy.min_anonymity_set_size {
            return Err("cohort anonymity set below migration policy floor".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("cohort post-quantum security below config".to_string());
        }
        if self.item_count == 0 || self.item_count as usize > config.max_cohort_items {
            return Err("cohort item count outside runtime bounds".to_string());
        }
        Ok(())
    }

    pub fn state_root(&self) -> String {
        record_root("NULLIFIER_COHORT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeBid {
    pub bid_id: String,
    pub cohort_id: String,
    pub bidder_commitment_root: String,
    pub class: FeeBidClass,
    pub status: FeeBidStatus,
    pub max_fee_bps: u64,
    pub priority_weight: u64,
    pub fee_escrow_root: String,
    pub rebate_commitment_root: String,
    pub submitted_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub nullifier_receipt_root: String,
}

impl FeeBid {
    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "cohort_id": self.cohort_id,
            "bidder_commitment_root": self.bidder_commitment_root,
            "class": self.class.as_str(),
            "status": self.status.as_str(),
            "max_fee_bps": self.max_fee_bps,
            "priority_weight": self.priority_weight,
            "fee_escrow_root": self.fee_escrow_root,
            "rebate_commitment_root": self.rebate_commitment_root,
            "submitted_at_l2_height": self.submitted_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "nullifier_receipt_root": self.nullifier_receipt_root,
        })
    }

    pub fn effective_fee_score(&self) -> u128 {
        (self.max_fee_bps as u128).saturating_mul(self.priority_weight.max(1) as u128)
    }

    pub fn validate(&self, cohort: &NullifierCohort, config: &Config) -> Result<()> {
        if self.cohort_id != cohort.cohort_id {
            return Err("fee bid cohort mismatch".to_string());
        }
        if !cohort.status.accepts_bid() {
            return Err("cohort does not accept fee bids".to_string());
        }
        if self.max_fee_bps > config.low_fee_cap_bps {
            return Err("fee bid exceeds low fee cap".to_string());
        }
        if self.expires_at_l2_height <= self.submitted_at_l2_height {
            return Err("fee bid expires before submission".to_string());
        }
        Ok(())
    }

    pub fn state_root(&self) -> String {
        record_root("FEE_BID", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub subject_id: String,
    pub purpose: AttestationPurpose,
    pub attested_root: String,
    pub attestor_set_root: String,
    pub ml_dsa_signature_root: String,
    pub slh_dsa_signature_root: String,
    pub transcript_root: String,
    pub pq_security_bits: u16,
    pub quorum_bps: u64,
    pub submitted_at_l2_height: u64,
    pub expires_at_l2_height: u64,
}

impl PqAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "subject_id": self.subject_id,
            "purpose": self.purpose.as_str(),
            "attested_root": self.attested_root,
            "attestor_set_root": self.attestor_set_root,
            "ml_dsa_signature_root": self.ml_dsa_signature_root,
            "slh_dsa_signature_root": self.slh_dsa_signature_root,
            "transcript_root": self.transcript_root,
            "pq_security_bits": self.pq_security_bits,
            "quorum_bps": self.quorum_bps,
            "submitted_at_l2_height": self.submitted_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
        })
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("attestation post-quantum security below config".to_string());
        }
        if self.quorum_bps > MAX_BPS {
            return Err("attestation quorum exceeds MAX_BPS".to_string());
        }
        if self.expires_at_l2_height <= self.submitted_at_l2_height {
            return Err("attestation expires before submission".to_string());
        }
        Ok(())
    }

    pub fn state_root(&self) -> String {
        record_root("PQ_ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementWindow {
    pub window_id: String,
    pub policy_id: String,
    pub status: SettlementStatus,
    pub cohort_root: String,
    pub bid_book_root: String,
    pub accepted_bid_root: String,
    pub clearing_fee_bps: u64,
    pub accepted_bid_count: u64,
    pub total_item_count: u64,
    pub opened_at_l2_height: u64,
    pub closes_at_l2_height: u64,
    pub cleared_at_l2_height: Option<u64>,
    pub operator_summary_root: String,
}

impl SettlementWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "policy_id": self.policy_id,
            "status": self.status.as_str(),
            "cohort_root": self.cohort_root,
            "bid_book_root": self.bid_book_root,
            "accepted_bid_root": self.accepted_bid_root,
            "clearing_fee_bps": self.clearing_fee_bps,
            "accepted_bid_count": self.accepted_bid_count,
            "total_item_count": self.total_item_count,
            "opened_at_l2_height": self.opened_at_l2_height,
            "closes_at_l2_height": self.closes_at_l2_height,
            "cleared_at_l2_height": self.cleared_at_l2_height,
            "operator_summary_root": self.operator_summary_root,
        })
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.clearing_fee_bps > config.low_fee_cap_bps {
            return Err("settlement clearing fee exceeds low fee cap".to_string());
        }
        if self.accepted_bid_count as usize > config.max_settlement_items {
            return Err("settlement accepted bid count exceeds max settlement items".to_string());
        }
        if self.closes_at_l2_height <= self.opened_at_l2_height {
            return Err("settlement window closes before opening".to_string());
        }
        Ok(())
    }

    pub fn state_root(&self) -> String {
        record_root("SETTLEMENT_WINDOW", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub bid_id: String,
    pub cohort_id: String,
    pub window_id: String,
    pub status: RebateStatus,
    pub rebate_bps: u64,
    pub fee_paid_bps: u64,
    pub rebate_commitment_root: String,
    pub claim_nullifier_root: String,
    pub reserved_at_l2_height: u64,
    pub expires_at_l2_height: u64,
}

impl LowFeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "bid_id": self.bid_id,
            "cohort_id": self.cohort_id,
            "window_id": self.window_id,
            "status": self.status.as_str(),
            "rebate_bps": self.rebate_bps,
            "fee_paid_bps": self.fee_paid_bps,
            "rebate_commitment_root": self.rebate_commitment_root,
            "claim_nullifier_root": self.claim_nullifier_root,
            "reserved_at_l2_height": self.reserved_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
        })
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.rebate_bps > config.rebate_bps || self.fee_paid_bps > config.low_fee_cap_bps {
            return Err("rebate exceeds configured low-fee bounds".to_string());
        }
        if self.expires_at_l2_height <= self.reserved_at_l2_height {
            return Err("rebate expires before reservation".to_string());
        }
        Ok(())
    }

    pub fn state_root(&self) -> String {
        record_root("LOW_FEE_REBATE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub subject_id: String,
    pub scope: RedactionScope,
    pub budget_root: String,
    pub units_reserved: u64,
    pub units_spent: u64,
    pub max_units_per_disclosure: u64,
    pub disclosure_count: u64,
    pub expires_at_l2_height: u64,
}

impl RedactionBudget {
    pub fn remaining_units(&self) -> u64 {
        self.units_reserved.saturating_sub(self.units_spent)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "subject_id": self.subject_id,
            "scope": self.scope.as_str(),
            "budget_root": self.budget_root,
            "units_reserved": self.units_reserved,
            "units_spent": self.units_spent,
            "remaining_units": self.remaining_units(),
            "max_units_per_disclosure": self.max_units_per_disclosure,
            "disclosure_count": self.disclosure_count,
            "expires_at_l2_height": self.expires_at_l2_height,
        })
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.units_spent > self.units_reserved {
            return Err("redaction budget spent units exceed reserved units".to_string());
        }
        if self.max_units_per_disclosure > config.max_redaction_units_per_cohort {
            return Err("redaction disclosure unit cap exceeds config".to_string());
        }
        Ok(())
    }

    pub fn state_root(&self) -> String {
        record_root("REDACTION_BUDGET", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub window_id: String,
    pub operator_set_root: String,
    pub redacted_cohort_root: String,
    pub redacted_bid_root: String,
    pub redacted_rebate_root: String,
    pub clearing_fee_bps: u64,
    pub accepted_bid_count: u64,
    pub rejected_bid_count: u64,
    pub low_fee_rebate_count: u64,
    pub quarantine_count: u64,
    pub k_anonymity_floor: u64,
    pub disclosure_budget_root: String,
    pub published_at_l2_height: u64,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "window_id": self.window_id,
            "operator_set_root": self.operator_set_root,
            "redacted_cohort_root": self.redacted_cohort_root,
            "redacted_bid_root": self.redacted_bid_root,
            "redacted_rebate_root": self.redacted_rebate_root,
            "clearing_fee_bps": self.clearing_fee_bps,
            "accepted_bid_count": self.accepted_bid_count,
            "rejected_bid_count": self.rejected_bid_count,
            "low_fee_rebate_count": self.low_fee_rebate_count,
            "quarantine_count": self.quarantine_count,
            "k_anonymity_floor": self.k_anonymity_floor,
            "disclosure_budget_root": self.disclosure_budget_root,
            "published_at_l2_height": self.published_at_l2_height,
        })
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.k_anonymity_floor < config.operator_summary_min_k {
            return Err("operator summary k-anonymity below config".to_string());
        }
        if self.clearing_fee_bps > config.low_fee_cap_bps {
            return Err("operator summary clearing fee exceeds low fee cap".to_string());
        }
        Ok(())
    }

    pub fn state_root(&self) -> String {
        record_root("OPERATOR_SUMMARY", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub migration_policies_root: String,
    pub nullifier_cohorts_root: String,
    pub fee_bids_root: String,
    pub pq_attestations_root: String,
    pub settlement_windows_root: String,
    pub rebates_root: String,
    pub redaction_budgets_root: String,
    pub operator_summaries_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub migration_policies: BTreeMap<String, MigrationPolicy>,
    pub nullifier_cohorts: BTreeMap<String, NullifierCohort>,
    pub fee_bids: BTreeMap<String, FeeBid>,
    pub pq_attestations: BTreeMap<String, PqAttestation>,
    pub settlement_windows: BTreeMap<String, SettlementWindow>,
    pub rebates: BTreeMap<String, LowFeeRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub quarantined_subjects: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            migration_policies: BTreeMap::new(),
            nullifier_cohorts: BTreeMap::new(),
            fee_bids: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            settlement_windows: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            quarantined_subjects: BTreeSet::new(),
        })
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters.state_root(),
            migration_policies_root: merkle_public_records(
                MIGRATION_POLICY_SUITE,
                self.migration_policies
                    .values()
                    .map(MigrationPolicy::public_record),
            ),
            nullifier_cohorts_root: merkle_public_records(
                HYBRID_NULLIFIER_SUITE,
                self.nullifier_cohorts
                    .values()
                    .map(NullifierCohort::public_record),
            ),
            fee_bids_root: merkle_public_records(
                FEE_BID_SUITE,
                self.fee_bids.values().map(FeeBid::public_record),
            ),
            pq_attestations_root: merkle_public_records(
                PQ_ATTESTATION_SUITE,
                self.pq_attestations
                    .values()
                    .map(PqAttestation::public_record),
            ),
            settlement_windows_root: merkle_public_records(
                SETTLEMENT_WINDOW_SUITE,
                self.settlement_windows
                    .values()
                    .map(SettlementWindow::public_record),
            ),
            rebates_root: merkle_public_records(
                LOW_FEE_REBATE_SUITE,
                self.rebates.values().map(LowFeeRebate::public_record),
            ),
            redaction_budgets_root: merkle_public_records(
                REDACTION_BUDGET_SUITE,
                self.redaction_budgets
                    .values()
                    .map(RedactionBudget::public_record),
            ),
            operator_summaries_root: merkle_public_records(
                OPERATOR_SUMMARY_SUITE,
                self.operator_summaries
                    .values()
                    .map(OperatorSummary::public_record),
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_hybrid_nullifier_migration_fee_market_runtime",
            "protocol_version": PROTOCOL_VERSION,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "hash_suite": HASH_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
            "quarantined_subjects_root": merkle_public_records(
                "hybrid-nullifier-migration-quarantined-subject-root-v1",
                self.quarantined_subjects.iter().map(|subject| json!({ "subject_id": subject })),
            ),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "state_root": self.state_root(),
            "record": self.public_record_without_state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("STATE", &self.public_record_without_state_root())
    }

    pub fn insert_migration_policy(&mut self, policy: MigrationPolicy) -> Result<()> {
        if self.migration_policies.len() >= MAX_MIGRATION_POLICIES {
            return Err("migration policy capacity exceeded".to_string());
        }
        policy.validate(&self.config)?;
        if self.migration_policies.contains_key(&policy.policy_id) {
            return Err("duplicate migration policy id".to_string());
        }
        if policy.phase.accepts_cohorts() || policy.phase.accepts_bids() || policy.phase.settles() {
            self.counters.active_policies = self.counters.active_policies.saturating_add(1);
        }
        self.counters.migration_policies = self.counters.migration_policies.saturating_add(1);
        self.migration_policies
            .insert(policy.policy_id.clone(), policy);
        Ok(())
    }

    pub fn insert_nullifier_cohort(&mut self, cohort: NullifierCohort) -> Result<()> {
        if self.nullifier_cohorts.len() >= MAX_NULLIFIER_COHORTS {
            return Err("nullifier cohort capacity exceeded".to_string());
        }
        if self.nullifier_cohorts.contains_key(&cohort.cohort_id) {
            return Err("duplicate nullifier cohort id".to_string());
        }
        let policy = self
            .migration_policies
            .get(&cohort.policy_id)
            .ok_or_else(|| "unknown cohort migration policy".to_string())?;
        cohort.validate(policy, &self.config)?;
        if cohort.status.live() {
            self.counters.live_cohorts = self.counters.live_cohorts.saturating_add(1);
        }
        self.counters.nullifier_cohorts = self.counters.nullifier_cohorts.saturating_add(1);
        self.nullifier_cohorts
            .insert(cohort.cohort_id.clone(), cohort);
        Ok(())
    }

    pub fn insert_fee_bid(&mut self, bid: FeeBid) -> Result<()> {
        if self.fee_bids.len() >= MAX_FEE_BIDS {
            return Err("fee bid capacity exceeded".to_string());
        }
        if self.fee_bids.contains_key(&bid.bid_id) {
            return Err("duplicate fee bid id".to_string());
        }
        let cohort = self
            .nullifier_cohorts
            .get(&bid.cohort_id)
            .ok_or_else(|| "unknown fee bid cohort".to_string())?;
        bid.validate(cohort, &self.config)?;
        self.counters.fee_bids = self.counters.fee_bids.saturating_add(1);
        self.fee_bids.insert(bid.bid_id.clone(), bid);
        Ok(())
    }

    pub fn insert_pq_attestation(&mut self, attestation: PqAttestation) -> Result<()> {
        if self.pq_attestations.len() >= MAX_PQ_ATTESTATIONS {
            return Err("pq attestation capacity exceeded".to_string());
        }
        if self
            .pq_attestations
            .contains_key(&attestation.attestation_id)
        {
            return Err("duplicate pq attestation id".to_string());
        }
        attestation.validate(&self.config)?;
        self.counters.pq_attestations = self.counters.pq_attestations.saturating_add(1);
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(())
    }

    pub fn open_settlement_window(&mut self, window: SettlementWindow) -> Result<()> {
        if self.settlement_windows.len() >= MAX_SETTLEMENT_WINDOWS {
            return Err("settlement window capacity exceeded".to_string());
        }
        if self.settlement_windows.contains_key(&window.window_id) {
            return Err("duplicate settlement window id".to_string());
        }
        if !self.migration_policies.contains_key(&window.policy_id) {
            return Err("unknown settlement policy".to_string());
        }
        window.validate(&self.config)?;
        if matches!(
            window.status,
            SettlementStatus::Cleared | SettlementStatus::Rebating | SettlementStatus::Finalized
        ) {
            self.counters.cleared_windows = self.counters.cleared_windows.saturating_add(1);
        }
        self.counters.settlement_windows = self.counters.settlement_windows.saturating_add(1);
        self.settlement_windows
            .insert(window.window_id.clone(), window);
        Ok(())
    }

    pub fn insert_rebate(&mut self, rebate: LowFeeRebate) -> Result<()> {
        if self.rebates.len() >= MAX_REBATES {
            return Err("rebate capacity exceeded".to_string());
        }
        if self.rebates.contains_key(&rebate.rebate_id) {
            return Err("duplicate rebate id".to_string());
        }
        if !self.fee_bids.contains_key(&rebate.bid_id) {
            return Err("unknown rebate fee bid".to_string());
        }
        if !self.settlement_windows.contains_key(&rebate.window_id) {
            return Err("unknown rebate settlement window".to_string());
        }
        rebate.validate(&self.config)?;
        if matches!(rebate.status, RebateStatus::Settled | RebateStatus::Claimed) {
            self.counters.settled_rebates = self.counters.settled_rebates.saturating_add(1);
        }
        self.counters.rebates = self.counters.rebates.saturating_add(1);
        self.rebates.insert(rebate.rebate_id.clone(), rebate);
        Ok(())
    }

    pub fn insert_redaction_budget(&mut self, budget: RedactionBudget) -> Result<()> {
        if self.redaction_budgets.len() >= MAX_REDACTION_BUDGETS {
            return Err("redaction budget capacity exceeded".to_string());
        }
        if self.redaction_budgets.contains_key(&budget.budget_id) {
            return Err("duplicate redaction budget id".to_string());
        }
        budget.validate(&self.config)?;
        self.counters.redaction_budgets = self.counters.redaction_budgets.saturating_add(1);
        self.counters.redaction_units_reserved = self
            .counters
            .redaction_units_reserved
            .saturating_add(budget.units_reserved);
        self.counters.redaction_units_spent = self
            .counters
            .redaction_units_spent
            .saturating_add(budget.units_spent);
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        Ok(())
    }

    pub fn insert_operator_summary(&mut self, summary: OperatorSummary) -> Result<()> {
        if self.operator_summaries.len() >= MAX_OPERATOR_SUMMARIES {
            return Err("operator summary capacity exceeded".to_string());
        }
        if self.operator_summaries.contains_key(&summary.summary_id) {
            return Err("duplicate operator summary id".to_string());
        }
        if !self.settlement_windows.contains_key(&summary.window_id) {
            return Err("unknown operator summary settlement window".to_string());
        }
        summary.validate(&self.config)?;
        self.counters.operator_summaries = self.counters.operator_summaries.saturating_add(1);
        self.operator_summaries
            .insert(summary.summary_id.clone(), summary);
        Ok(())
    }

    pub fn quarantine_subject(&mut self, subject_id: impl Into<String>) -> bool {
        let inserted = self.quarantined_subjects.insert(subject_id.into());
        if inserted {
            self.counters.quarantined_items = self.counters.quarantined_items.saturating_add(1);
        }
        inserted
    }

    pub fn clear_fee_market(
        &mut self,
        window_id: &str,
        bid_ids: &[String],
        clearing_fee_bps: u64,
    ) -> Result<String> {
        if clearing_fee_bps > self.config.low_fee_cap_bps {
            return Err("clearing fee exceeds low fee cap".to_string());
        }
        if bid_ids.len() > self.config.max_settlement_items {
            return Err("clearing bid set exceeds max settlement items".to_string());
        }
        let mut accepted = Vec::with_capacity(bid_ids.len());
        for bid_id in bid_ids {
            let bid = self
                .fee_bids
                .get_mut(bid_id)
                .ok_or_else(|| format!("unknown bid {bid_id}"))?;
            if !bid.status.clearable() {
                return Err(format!("fee bid {bid_id} is not clearable"));
            }
            if bid.max_fee_bps < clearing_fee_bps {
                return Err(format!("fee bid {bid_id} below clearing fee"));
            }
            bid.status = FeeBidStatus::Cleared;
            accepted.push(bid.public_record());
        }
        let accepted_bid_root = merkle_root("accepted-hybrid-nullifier-fee-bids", &accepted);
        let window = self
            .settlement_windows
            .get_mut(window_id)
            .ok_or_else(|| "unknown settlement window".to_string())?;
        window.status = SettlementStatus::Cleared;
        window.clearing_fee_bps = clearing_fee_bps;
        window.accepted_bid_count = bid_ids.len() as u64;
        window.accepted_bid_root = accepted_bid_root.clone();
        window.cleared_at_l2_height = Some(self.config.l2_height);
        self.counters.cleared_bids = self
            .counters
            .cleared_bids
            .saturating_add(bid_ids.len() as u64);
        self.counters.cleared_windows = self.counters.cleared_windows.saturating_add(1);
        Ok(accepted_bid_root)
    }
}

pub fn devnet() -> State {
    let config = Config::default();
    let mut state = State::new(config.clone()).expect("default devnet config is valid");
    let policy = MigrationPolicy::new(
        "devnet-hybrid-nullifier-policy-0001",
        MigrationPolicyKind::LegacyRingCtDrain,
        MigrationPhase::FeeDiscovery,
        fixed_root("devnet-policy-commitment"),
        fixed_root("devnet-legacy-ringct-domain"),
        fixed_root("devnet-seraphis-pq-domain"),
        fixed_root("devnet-nullifier-fence"),
        &config,
    );
    state
        .insert_migration_policy(policy)
        .expect("devnet migration policy inserts");

    let cohort = NullifierCohort {
        cohort_id: "devnet-hybrid-nullifier-cohort-0001".to_string(),
        policy_id: "devnet-hybrid-nullifier-policy-0001".to_string(),
        kind: NullifierCohortKind::HybridKeyImageNullifier,
        status: CohortStatus::Bidding,
        nullifier_commitment_root: fixed_root("devnet-nullifier-commitment"),
        key_image_fence_root: fixed_root("devnet-key-image-fence"),
        stealth_address_domain_root: fixed_root("devnet-stealth-address-domain"),
        decoy_set_root: fixed_root("devnet-decoy-set"),
        item_count: 4_096,
        anonymity_set_size: config.target_cohort_anonymity_set_size,
        privacy_entropy_bits: 192,
        pq_security_bits: config.min_pq_security_bits,
        admitted_at_l2_height: config.l2_height,
        expires_at_l2_height: config.l2_height + config.cohort_ttl_blocks,
        quarantine_root: fixed_root("devnet-empty-quarantine"),
    };
    state
        .insert_nullifier_cohort(cohort)
        .expect("devnet cohort inserts");

    let bid = FeeBid {
        bid_id: "devnet-low-fee-bid-0001".to_string(),
        cohort_id: "devnet-hybrid-nullifier-cohort-0001".to_string(),
        bidder_commitment_root: fixed_root("devnet-bidder-commitment"),
        class: FeeBidClass::RebateEligible,
        status: FeeBidStatus::Eligible,
        max_fee_bps: config.low_fee_cap_bps,
        priority_weight: 1,
        fee_escrow_root: fixed_root("devnet-fee-escrow"),
        rebate_commitment_root: fixed_root("devnet-rebate-commitment"),
        submitted_at_l2_height: config.l2_height,
        expires_at_l2_height: config.l2_height + config.bid_ttl_blocks,
        nullifier_receipt_root: fixed_root("devnet-nullifier-receipt"),
    };
    state.insert_fee_bid(bid).expect("devnet fee bid inserts");

    let attestation = PqAttestation {
        attestation_id: "devnet-pq-attestation-0001".to_string(),
        subject_id: "devnet-hybrid-nullifier-cohort-0001".to_string(),
        purpose: AttestationPurpose::CohortEligibility,
        attested_root: fixed_root("devnet-cohort-attested-root"),
        attestor_set_root: fixed_root("devnet-attestor-set"),
        ml_dsa_signature_root: fixed_root("devnet-ml-dsa-signatures"),
        slh_dsa_signature_root: fixed_root("devnet-slh-dsa-signatures"),
        transcript_root: fixed_root("devnet-attestation-transcript"),
        pq_security_bits: config.min_pq_security_bits,
        quorum_bps: 6_700,
        submitted_at_l2_height: config.l2_height,
        expires_at_l2_height: config.l2_height + config.attestation_ttl_blocks,
    };
    state
        .insert_pq_attestation(attestation)
        .expect("devnet pq attestation inserts");

    let window = SettlementWindow {
        window_id: "devnet-settlement-window-0001".to_string(),
        policy_id: "devnet-hybrid-nullifier-policy-0001".to_string(),
        status: SettlementStatus::Open,
        cohort_root: state.roots().nullifier_cohorts_root,
        bid_book_root: state.roots().fee_bids_root,
        accepted_bid_root: fixed_root("devnet-empty-accepted-bids"),
        clearing_fee_bps: config.target_clearing_fee_bps,
        accepted_bid_count: 0,
        total_item_count: 4_096,
        opened_at_l2_height: config.l2_height,
        closes_at_l2_height: config.l2_height + config.settlement_window_ttl_blocks,
        cleared_at_l2_height: None,
        operator_summary_root: fixed_root("devnet-operator-summary-pending"),
    };
    state
        .open_settlement_window(window)
        .expect("devnet settlement window inserts");

    let rebate = LowFeeRebate {
        rebate_id: "devnet-low-fee-rebate-0001".to_string(),
        bid_id: "devnet-low-fee-bid-0001".to_string(),
        cohort_id: "devnet-hybrid-nullifier-cohort-0001".to_string(),
        window_id: "devnet-settlement-window-0001".to_string(),
        status: RebateStatus::Eligible,
        rebate_bps: config.rebate_bps,
        fee_paid_bps: config.target_clearing_fee_bps,
        rebate_commitment_root: fixed_root("devnet-low-fee-rebate"),
        claim_nullifier_root: fixed_root("devnet-rebate-claim-nullifier"),
        reserved_at_l2_height: config.l2_height,
        expires_at_l2_height: config.l2_height + config.rebate_ttl_blocks,
    };
    state.insert_rebate(rebate).expect("devnet rebate inserts");

    let budget = RedactionBudget {
        budget_id: "devnet-redaction-budget-0001".to_string(),
        subject_id: "devnet-settlement-window-0001".to_string(),
        scope: RedactionScope::OperatorSummary,
        budget_root: fixed_root("devnet-redaction-budget"),
        units_reserved: config.default_redaction_budget_units,
        units_spent: 0,
        max_units_per_disclosure: config.max_redaction_units_per_cohort,
        disclosure_count: 0,
        expires_at_l2_height: config.l2_height + config.policy_ttl_blocks,
    };
    state
        .insert_redaction_budget(budget)
        .expect("devnet redaction budget inserts");

    let summary = OperatorSummary {
        summary_id: "devnet-redacted-summary-0001".to_string(),
        window_id: "devnet-settlement-window-0001".to_string(),
        operator_set_root: fixed_root("devnet-operator-set"),
        redacted_cohort_root: state.roots().nullifier_cohorts_root,
        redacted_bid_root: state.roots().fee_bids_root,
        redacted_rebate_root: state.roots().rebates_root,
        clearing_fee_bps: config.target_clearing_fee_bps,
        accepted_bid_count: 0,
        rejected_bid_count: 0,
        low_fee_rebate_count: 1,
        quarantine_count: 0,
        k_anonymity_floor: config.operator_summary_min_k,
        disclosure_budget_root: fixed_root("devnet-redaction-budget"),
        published_at_l2_height: config.l2_height,
    };
    state
        .insert_operator_summary(summary)
        .expect("devnet operator summary inserts");
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

pub fn fixed_root(label: &str) -> String {
    domain_hash(
        "private-l2-pq-confidential-hybrid-nullifier-migration-fee-market-fixed-root",
        &[HashPart::Str(label), HashPart::Str(PROTOCOL_VERSION)],
        32,
    )
}

pub fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "private-l2-pq-confidential-hybrid-nullifier-migration-fee-market-record-root",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn merkle_public_records<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let leaves = records.into_iter().collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
