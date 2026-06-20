use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialQuantumSafeAccountMigrationAuctionRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PRIVATE_L2_PQ_CONFIDENTIAL_QUANTUM_SAFE_ACCOUNT_MIGRATION_AUCTION_RUNTIME_PROTOCOL_VERSION: &str = "nebula-private-l2-pq-confidential-quantum-safe-account-migration-auction-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_QUANTUM_SAFE_ACCOUNT_MIGRATION_AUCTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ACCOUNT_COMMITMENT_SUITE: &str =
    "monero-private-l2-account-session-nullifier-commitment-v1";
pub const MIGRATION_AUCTION_SUITE: &str =
    "sealed-bid-quantum-safe-account-migration-capacity-auction-v1";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-account-migration-attestation-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "private-l2-low-fee-account-migration-rebate-coupon-v1";
pub const REDACTION_BUDGET_SUITE: &str = "operator-safe-account-migration-redaction-budget-v1";
pub const OPERATOR_SUMMARY_SUITE: &str =
    "redacted-quantum-safe-account-migration-operator-summary-v1";
pub const SETTLEMENT_WINDOW_SUITE: &str =
    "monero-private-l2-account-migration-settlement-window-v1";
pub const DEVNET_L2_HEIGHT: u64 = 4_672_800;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_444_200;
pub const DEVNET_EPOCH: u64 = 20_864;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_AUCTION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_COMMIT_REVEAL_DELAY_BLOCKS: u64 = 24;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 21_600;
pub const DEFAULT_REDACTION_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_REDACTIONS_PER_EPOCH: u64 = 64;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_LOW_FEE_TARGET_BPS: u64 = 8;
pub const DEFAULT_REBATE_CAP_BPS: u64 = 2_000;
pub const DEFAULT_EARLY_MIGRATION_DISCOUNT_BPS: u64 = 1_250;
pub const DEFAULT_OPERATOR_BOND_MICRO_UNITS: u64 = 125_000_000;
pub const DEFAULT_SLASH_BPS: u64 = 1_200;
pub const DEFAULT_MAX_COHORTS: usize = 1_048_576;
pub const DEFAULT_MAX_ACCOUNTS: usize = 16_777_216;
pub const DEFAULT_MAX_SESSIONS: usize = 16_777_216;
pub const DEFAULT_MAX_AUCTIONS: usize = 4_194_304;
pub const DEFAULT_MAX_BIDS: usize = 33_554_432;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 33_554_432;
pub const DEFAULT_MAX_WINDOWS: usize = 8_388_608;
pub const DEFAULT_MAX_REBATES: usize = 33_554_432;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 16_777_216;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationCohortKind {
    LegacySpendKeyRotation,
    ViewKeyPreserving,
    HardwareWalletBatch,
    ExchangeCustodySweep,
    MobileSessionUpgrade,
    WatchOnlyAccountRecovery,
    MultisigParticipantRotation,
    ContractAccountMigration,
    EmergencyQuantumHardened,
    Custom,
}

impl MigrationCohortKind {
    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyQuantumHardened => 10_000,
            Self::ExchangeCustodySweep => 9_200,
            Self::MultisigParticipantRotation => 8_800,
            Self::LegacySpendKeyRotation => 8_500,
            Self::HardwareWalletBatch => 8_100,
            Self::ContractAccountMigration => 7_800,
            Self::MobileSessionUpgrade => 7_300,
            Self::WatchOnlyAccountRecovery => 6_900,
            Self::ViewKeyPreserving => 6_500,
            Self::Custom => 5_500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortStatus {
    Draft,
    Open,
    Sealed,
    Auctioning,
    Settling,
    Rebating,
    Paused,
    Closed,
    Slashed,
}

impl CohortStatus {
    pub fn accepts_accounts(self) -> bool {
        matches!(self, Self::Open | Self::Sealed | Self::Auctioning)
    }

    pub fn accepts_auctions(self) -> bool {
        matches!(self, Self::Open | Self::Auctioning)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountCommitmentKind {
    SpendKeyNullifier,
    ViewKeyNullifier,
    SessionTranscript,
    BalanceBucket,
    DecoySetAnchor,
    BridgeAccountAnchor,
    ContractAccountAnchor,
    RecoveryAnchor,
    Custom,
}

impl AccountCommitmentKind {
    pub fn privacy_weight(self) -> u64 {
        match self {
            Self::DecoySetAnchor => 10_000,
            Self::SpendKeyNullifier => 9_700,
            Self::SessionTranscript => 9_400,
            Self::BalanceBucket => 9_000,
            Self::BridgeAccountAnchor => 8_700,
            Self::ContractAccountAnchor => 8_300,
            Self::ViewKeyNullifier => 7_800,
            Self::RecoveryAnchor => 7_200,
            Self::Custom => 6_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    Committed,
    SessionBound,
    Attested,
    AuctionEligible,
    Migrating,
    Settled,
    Rebated,
    Quarantined,
    Redacted,
    Expired,
}

impl AccountStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Committed
                | Self::SessionBound
                | Self::Attested
                | Self::AuctionEligible
                | Self::Migrating
        )
    }

    pub fn eligible_for_settlement(self) -> bool {
        matches!(
            self,
            Self::Attested | Self::AuctionEligible | Self::Migrating
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionKind {
    LowestFeeMigration,
    FastestSettlement,
    LargestPrivacyBatch,
    RebateSponsored,
    EmergencyPriority,
    OperatorBonded,
}

impl AuctionKind {
    pub fn clearing_bias_bps(self) -> u64 {
        match self {
            Self::LowestFeeMigration => 9_500,
            Self::LargestPrivacyBatch => 9_200,
            Self::RebateSponsored => 8_800,
            Self::OperatorBonded => 8_300,
            Self::FastestSettlement => 7_900,
            Self::EmergencyPriority => 10_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Draft,
    Open,
    CommitPhase,
    RevealPhase,
    Clearing,
    Settled,
    Rebated,
    Cancelled,
    Expired,
}

impl AuctionStatus {
    pub fn accepts_bids(self) -> bool {
        matches!(self, Self::Open | Self::CommitPhase)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Committed,
    Attested,
    Eligible,
    Winning,
    Outbid,
    Settled,
    Rebated,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    AccountCommitment,
    SessionTranscript,
    PqKeyRotation,
    MigrationExecutor,
    SettlementWindow,
    LowFeeRebate,
    RedactionBudget,
    OperatorSummary,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Pending,
    Verified,
    Superseded,
    Expired,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Pending,
    Locked,
    Executing,
    Settled,
    RebateQueued,
    RebatePaid,
    Disputed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionPurpose {
    OperatorSummary,
    CohortTelemetry,
    AccountCommitment,
    SessionTranscript,
    BidReveal,
    SettlementProof,
    RebateCoupon,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub auction_ttl_blocks: u64,
    pub commit_reveal_delay_blocks: u64,
    pub settlement_window_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub redaction_epoch_blocks: u64,
    pub max_redactions_per_epoch: u64,
    pub max_user_fee_bps: u64,
    pub low_fee_target_bps: u64,
    pub rebate_cap_bps: u64,
    pub early_migration_discount_bps: u64,
    pub operator_bond_micro_units: u64,
    pub slash_bps: u64,
    pub max_cohorts: usize,
    pub max_accounts: usize,
    pub max_sessions: usize,
    pub max_auctions: usize,
    pub max_bids: usize,
    pub max_attestations: usize,
    pub max_windows: usize,
    pub max_rebates: usize,
    pub max_redaction_budgets: usize,
    pub hash_suite: String,
    pub account_commitment_suite: String,
    pub migration_auction_suite: String,
    pub pq_attestation_suite: String,
    pub low_fee_rebate_suite: String,
    pub redaction_budget_suite: String,
    pub operator_summary_suite: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            auction_ttl_blocks: DEFAULT_AUCTION_TTL_BLOCKS,
            commit_reveal_delay_blocks: DEFAULT_COMMIT_REVEAL_DELAY_BLOCKS,
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            redaction_epoch_blocks: DEFAULT_REDACTION_EPOCH_BLOCKS,
            max_redactions_per_epoch: DEFAULT_MAX_REDACTIONS_PER_EPOCH,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            low_fee_target_bps: DEFAULT_LOW_FEE_TARGET_BPS,
            rebate_cap_bps: DEFAULT_REBATE_CAP_BPS,
            early_migration_discount_bps: DEFAULT_EARLY_MIGRATION_DISCOUNT_BPS,
            operator_bond_micro_units: DEFAULT_OPERATOR_BOND_MICRO_UNITS,
            slash_bps: DEFAULT_SLASH_BPS,
            max_cohorts: DEFAULT_MAX_COHORTS,
            max_accounts: DEFAULT_MAX_ACCOUNTS,
            max_sessions: DEFAULT_MAX_SESSIONS,
            max_auctions: DEFAULT_MAX_AUCTIONS,
            max_bids: DEFAULT_MAX_BIDS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_windows: DEFAULT_MAX_WINDOWS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            hash_suite: HASH_SUITE.to_string(),
            account_commitment_suite: ACCOUNT_COMMITMENT_SUITE.to_string(),
            migration_auction_suite: MIGRATION_AUCTION_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            low_fee_rebate_suite: LOW_FEE_REBATE_SUITE.to_string(),
            redaction_budget_suite: REDACTION_BUDGET_SUITE.to_string(),
            operator_summary_suite: OPERATOR_SUMMARY_SUITE.to_string(),
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "fee_asset_id": self.fee_asset_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "auction_ttl_blocks": self.auction_ttl_blocks,
            "commit_reveal_delay_blocks": self.commit_reveal_delay_blocks,
            "settlement_window_blocks": self.settlement_window_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "redaction_epoch_blocks": self.redaction_epoch_blocks,
            "max_redactions_per_epoch": self.max_redactions_per_epoch,
            "max_user_fee_bps": self.max_user_fee_bps,
            "low_fee_target_bps": self.low_fee_target_bps,
            "rebate_cap_bps": self.rebate_cap_bps,
            "early_migration_discount_bps": self.early_migration_discount_bps,
            "operator_bond_micro_units": self.operator_bond_micro_units,
            "slash_bps": self.slash_bps,
            "max_cohorts": self.max_cohorts,
            "max_accounts": self.max_accounts,
            "max_sessions": self.max_sessions,
            "max_auctions": self.max_auctions,
            "max_bids": self.max_bids,
            "max_attestations": self.max_attestations,
            "max_windows": self.max_windows,
            "max_rebates": self.max_rebates,
            "max_redaction_budgets": self.max_redaction_budgets,
            "hash_suite": self.hash_suite,
            "account_commitment_suite": self.account_commitment_suite,
            "migration_auction_suite": self.migration_auction_suite,
            "pq_attestation_suite": self.pq_attestation_suite,
            "low_fee_rebate_suite": self.low_fee_rebate_suite,
            "redaction_budget_suite": self.redaction_budget_suite,
            "operator_summary_suite": self.operator_summary_suite,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub cohorts: u64,
    pub account_commitments: u64,
    pub session_commitments: u64,
    pub auctions: u64,
    pub bids: u64,
    pub attestations: u64,
    pub settlement_windows: u64,
    pub low_fee_rebates: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub settled_accounts: u64,
    pub slashed_bids: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "cohorts": self.cohorts,
            "account_commitments": self.account_commitments,
            "session_commitments": self.session_commitments,
            "auctions": self.auctions,
            "bids": self.bids,
            "attestations": self.attestations,
            "settlement_windows": self.settlement_windows,
            "low_fee_rebates": self.low_fee_rebates,
            "redaction_budgets": self.redaction_budgets,
            "operator_summaries": self.operator_summaries,
            "settled_accounts": self.settled_accounts,
            "slashed_bids": self.slashed_bids,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub cohort_root: String,
    pub account_root: String,
    pub session_root: String,
    pub auction_root: String,
    pub bid_root: String,
    pub attestation_root: String,
    pub settlement_window_root: String,
    pub low_fee_rebate_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub event_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let empty = |label: &str| deterministic_root("empty", label);
        let mut roots = Self {
            config_root: record_root("config", &config.public_record()),
            counters_root: record_root("counters", &counters.public_record()),
            cohort_root: empty("cohorts"),
            account_root: empty("accounts"),
            session_root: empty("sessions"),
            auction_root: empty("auctions"),
            bid_root: empty("bids"),
            attestation_root: empty("attestations"),
            settlement_window_root: empty("settlement_windows"),
            low_fee_rebate_root: empty("low_fee_rebates"),
            redaction_budget_root: empty("redaction_budgets"),
            operator_summary_root: empty("operator_summaries"),
            event_root: empty("events"),
            state_root: String::new(),
        };
        roots.state_root = record_root("roots", &roots.public_record_without_state_root());
        roots
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "cohort_root": self.cohort_root,
            "account_root": self.account_root,
            "session_root": self.session_root,
            "auction_root": self.auction_root,
            "bid_root": self.bid_root,
            "attestation_root": self.attestation_root,
            "settlement_window_root": self.settlement_window_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "redaction_budget_root": self.redaction_budget_root,
            "operator_summary_root": self.operator_summary_root,
            "event_root": self.event_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(self.state_root));
        }
        record
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MigrationCohort {
    pub cohort_id: String,
    pub kind: MigrationCohortKind,
    pub status: CohortStatus,
    pub account_class_commitment: String,
    pub source_account_root: String,
    pub target_account_root: String,
    pub decoy_set_root: String,
    pub operator_committee_root: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub capacity_accounts: u64,
    pub opened_at_l2_height: u64,
    pub closes_at_l2_height: u64,
    pub fee_asset_id: String,
    pub max_user_fee_bps: u64,
    pub rebate_cap_bps: u64,
    pub priority_weight: u64,
    pub metadata_commitment: String,
}

impl MigrationCohort {
    pub fn new(
        cohort_id: impl Into<String>,
        kind: MigrationCohortKind,
        account_class_commitment: impl Into<String>,
        source_account_root: impl Into<String>,
        target_account_root: impl Into<String>,
        opened_at_l2_height: u64,
        capacity_accounts: u64,
        config: &Config,
    ) -> Self {
        let cohort_id = cohort_id.into();
        let account_class_commitment = account_class_commitment.into();
        let source_account_root = source_account_root.into();
        let target_account_root = target_account_root.into();
        let decoy_set_root = commitment(
            "cohort-decoy-set",
            &[&cohort_id, &source_account_root, &account_class_commitment],
        );
        let operator_committee_root =
            commitment("cohort-operators", &[&cohort_id, &target_account_root]);
        let metadata_commitment = commitment(
            "cohort-metadata",
            &[&cohort_id, kind_label(kind), &config.protocol_version],
        );
        Self {
            cohort_id,
            kind,
            status: CohortStatus::Open,
            account_class_commitment,
            source_account_root,
            target_account_root,
            decoy_set_root,
            operator_committee_root,
            min_privacy_set_size: config.min_privacy_set_size,
            target_privacy_set_size: config.target_privacy_set_size,
            capacity_accounts,
            opened_at_l2_height,
            closes_at_l2_height: opened_at_l2_height + config.auction_ttl_blocks,
            fee_asset_id: config.fee_asset_id.clone(),
            max_user_fee_bps: config.max_user_fee_bps,
            rebate_cap_bps: config.rebate_cap_bps,
            priority_weight: kind.priority_weight(),
            metadata_commitment,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.cohort_id.is_empty(), "cohort id is empty");
        ensure!(
            self.min_privacy_set_size >= config.min_privacy_set_size,
            "cohort {} privacy set {} below minimum {}",
            self.cohort_id,
            self.min_privacy_set_size,
            config.min_privacy_set_size
        );
        ensure!(
            self.target_privacy_set_size >= self.min_privacy_set_size,
            "cohort {} target privacy set below minimum",
            self.cohort_id
        );
        ensure!(
            self.capacity_accounts > 0,
            "cohort {} has zero account capacity",
            self.cohort_id
        );
        ensure!(
            self.closes_at_l2_height > self.opened_at_l2_height,
            "cohort {} closes before it opens",
            self.cohort_id
        );
        ensure!(
            self.max_user_fee_bps <= config.max_user_fee_bps,
            "cohort {} max fee exceeds config",
            self.cohort_id
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "kind": self.kind,
            "status": self.status,
            "account_class_commitment": self.account_class_commitment,
            "source_account_root": self.source_account_root,
            "target_account_root": self.target_account_root,
            "decoy_set_root": self.decoy_set_root,
            "operator_committee_root": self.operator_committee_root,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "capacity_accounts": self.capacity_accounts,
            "opened_at_l2_height": self.opened_at_l2_height,
            "closes_at_l2_height": self.closes_at_l2_height,
            "fee_asset_id": self.fee_asset_id,
            "max_user_fee_bps": self.max_user_fee_bps,
            "rebate_cap_bps": self.rebate_cap_bps,
            "priority_weight": self.priority_weight,
            "metadata_commitment": self.metadata_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccountCommitment {
    pub account_id: String,
    pub cohort_id: String,
    pub kind: AccountCommitmentKind,
    pub status: AccountStatus,
    pub source_account_commitment: String,
    pub target_account_commitment: String,
    pub session_id: String,
    pub session_commitment: String,
    pub nullifier_commitment: String,
    pub balance_bucket_commitment: String,
    pub decoy_membership_root: String,
    pub pq_key_package_commitment: String,
    pub privacy_set_size: u64,
    pub committed_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub redaction_hint: String,
}

impl AccountCommitment {
    pub fn new(
        account_id: impl Into<String>,
        cohort_id: impl Into<String>,
        kind: AccountCommitmentKind,
        session_id: impl Into<String>,
        source_account_commitment: impl Into<String>,
        target_account_commitment: impl Into<String>,
        committed_at_l2_height: u64,
        config: &Config,
    ) -> Self {
        let account_id = account_id.into();
        let cohort_id = cohort_id.into();
        let session_id = session_id.into();
        let source_account_commitment = source_account_commitment.into();
        let target_account_commitment = target_account_commitment.into();
        let session_commitment = commitment(
            "account-session",
            &[
                &account_id,
                &cohort_id,
                &session_id,
                &target_account_commitment,
            ],
        );
        let nullifier_commitment = commitment(
            "account-nullifier",
            &[&account_id, &source_account_commitment],
        );
        let balance_bucket_commitment =
            commitment("account-balance-bucket", &[&account_id, &cohort_id]);
        let decoy_membership_root =
            commitment("account-decoy-membership", &[&account_id, &cohort_id]);
        let pq_key_package_commitment =
            commitment("account-pq-key-package", &[&account_id, &session_id]);
        let redaction_hint = commitment("account-redaction-hint", &[&account_id, &session_id]);
        Self {
            account_id,
            cohort_id,
            kind,
            status: AccountStatus::Committed,
            source_account_commitment,
            target_account_commitment,
            session_id,
            session_commitment,
            nullifier_commitment,
            balance_bucket_commitment,
            decoy_membership_root,
            pq_key_package_commitment,
            privacy_set_size: config.target_privacy_set_size,
            committed_at_l2_height,
            expires_at_l2_height: committed_at_l2_height + config.attestation_ttl_blocks,
            redaction_hint,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.account_id.is_empty(), "account id is empty");
        ensure!(
            !self.cohort_id.is_empty(),
            "account {} missing cohort",
            self.account_id
        );
        ensure!(
            !self.session_id.is_empty(),
            "account {} missing session id",
            self.account_id
        );
        ensure!(
            self.privacy_set_size >= config.min_privacy_set_size,
            "account {} privacy set below minimum",
            self.account_id
        );
        ensure!(
            self.expires_at_l2_height > self.committed_at_l2_height,
            "account {} expiration precedes commitment",
            self.account_id
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "account_id": self.account_id,
            "cohort_id": self.cohort_id,
            "kind": self.kind,
            "status": self.status,
            "source_account_commitment": self.source_account_commitment,
            "target_account_commitment": self.target_account_commitment,
            "session_id": self.session_id,
            "session_commitment": self.session_commitment,
            "nullifier_commitment": self.nullifier_commitment,
            "balance_bucket_commitment": self.balance_bucket_commitment,
            "decoy_membership_root": self.decoy_membership_root,
            "pq_key_package_commitment": self.pq_key_package_commitment,
            "privacy_set_size": self.privacy_set_size,
            "committed_at_l2_height": self.committed_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "redaction_hint": self.redaction_hint,
        })
    }

    pub fn operator_safe_record(&self) -> Value {
        json!({
            "account_id": self.account_id,
            "cohort_id": self.cohort_id,
            "kind": self.kind,
            "status": self.status,
            "session_commitment": self.session_commitment,
            "nullifier_commitment": self.nullifier_commitment,
            "decoy_membership_root": self.decoy_membership_root,
            "privacy_set_size": self.privacy_set_size,
            "expires_at_l2_height": self.expires_at_l2_height,
            "redaction_hint": self.redaction_hint,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SessionCommitment {
    pub session_id: String,
    pub account_id: String,
    pub cohort_id: String,
    pub transcript_commitment: String,
    pub pq_handshake_commitment: String,
    pub view_ticket_commitment: String,
    pub relay_path_commitment: String,
    pub created_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub min_pq_security_bits: u16,
    pub privacy_set_size: u64,
}

impl SessionCommitment {
    pub fn new(
        session_id: impl Into<String>,
        account_id: impl Into<String>,
        cohort_id: impl Into<String>,
        created_at_l2_height: u64,
        config: &Config,
    ) -> Self {
        let session_id = session_id.into();
        let account_id = account_id.into();
        let cohort_id = cohort_id.into();
        let transcript_commitment = commitment(
            "session-transcript",
            &[&session_id, &account_id, &cohort_id],
        );
        let pq_handshake_commitment = commitment("session-pq-handshake", &[&session_id]);
        let view_ticket_commitment = commitment("session-view-ticket", &[&session_id]);
        let relay_path_commitment = commitment("session-relay-path", &[&session_id, &cohort_id]);
        Self {
            session_id,
            account_id,
            cohort_id,
            transcript_commitment,
            pq_handshake_commitment,
            view_ticket_commitment,
            relay_path_commitment,
            created_at_l2_height,
            expires_at_l2_height: created_at_l2_height + config.attestation_ttl_blocks,
            min_pq_security_bits: config.min_pq_security_bits,
            privacy_set_size: config.target_privacy_set_size,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.session_id.is_empty(), "session id is empty");
        ensure!(
            self.min_pq_security_bits >= config.min_pq_security_bits,
            "session {} pq security below minimum",
            self.session_id
        );
        ensure!(
            self.privacy_set_size >= config.min_privacy_set_size,
            "session {} privacy set below minimum",
            self.session_id
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "session_id": self.session_id,
            "account_id": self.account_id,
            "cohort_id": self.cohort_id,
            "transcript_commitment": self.transcript_commitment,
            "pq_handshake_commitment": self.pq_handshake_commitment,
            "view_ticket_commitment": self.view_ticket_commitment,
            "relay_path_commitment": self.relay_path_commitment,
            "created_at_l2_height": self.created_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "min_pq_security_bits": self.min_pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MigrationAuction {
    pub auction_id: String,
    pub cohort_id: String,
    pub kind: AuctionKind,
    pub status: AuctionStatus,
    pub account_batch_root: String,
    pub bid_commitment_root: String,
    pub operator_allowlist_root: String,
    pub min_accounts: u64,
    pub max_accounts: u64,
    pub reserve_fee_bps: u64,
    pub rebate_pool_micro_units: u64,
    pub opened_at_l2_height: u64,
    pub commit_until_l2_height: u64,
    pub reveal_until_l2_height: u64,
    pub settlement_deadline_l2_height: u64,
    pub clearing_price_bps: u64,
}

impl MigrationAuction {
    pub fn new(
        auction_id: impl Into<String>,
        cohort_id: impl Into<String>,
        kind: AuctionKind,
        account_batch_root: impl Into<String>,
        opened_at_l2_height: u64,
        max_accounts: u64,
        config: &Config,
    ) -> Self {
        let auction_id = auction_id.into();
        let cohort_id = cohort_id.into();
        let account_batch_root = account_batch_root.into();
        let bid_commitment_root = commitment(
            "auction-bid-root",
            &[&auction_id, &cohort_id, &account_batch_root],
        );
        let operator_allowlist_root = commitment("auction-operator-allowlist", &[&auction_id]);
        let commit_until_l2_height = opened_at_l2_height + config.commit_reveal_delay_blocks;
        let reveal_until_l2_height = opened_at_l2_height + config.auction_ttl_blocks;
        Self {
            auction_id,
            cohort_id,
            kind,
            status: AuctionStatus::Open,
            account_batch_root,
            bid_commitment_root,
            operator_allowlist_root,
            min_accounts: 1,
            max_accounts,
            reserve_fee_bps: config.max_user_fee_bps,
            rebate_pool_micro_units: 0,
            opened_at_l2_height,
            commit_until_l2_height,
            reveal_until_l2_height,
            settlement_deadline_l2_height: reveal_until_l2_height + config.settlement_window_blocks,
            clearing_price_bps: config.low_fee_target_bps,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.auction_id.is_empty(), "auction id is empty");
        ensure!(
            !self.cohort_id.is_empty(),
            "auction {} missing cohort",
            self.auction_id
        );
        ensure!(
            self.max_accounts >= self.min_accounts,
            "auction {} max accounts below minimum",
            self.auction_id
        );
        ensure!(
            self.reserve_fee_bps <= config.max_user_fee_bps,
            "auction {} reserve fee exceeds config",
            self.auction_id
        );
        ensure!(
            self.commit_until_l2_height > self.opened_at_l2_height,
            "auction {} has invalid commit phase",
            self.auction_id
        );
        ensure!(
            self.reveal_until_l2_height >= self.commit_until_l2_height,
            "auction {} reveal phase precedes commit phase",
            self.auction_id
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "auction_id": self.auction_id,
            "cohort_id": self.cohort_id,
            "kind": self.kind,
            "status": self.status,
            "account_batch_root": self.account_batch_root,
            "bid_commitment_root": self.bid_commitment_root,
            "operator_allowlist_root": self.operator_allowlist_root,
            "min_accounts": self.min_accounts,
            "max_accounts": self.max_accounts,
            "reserve_fee_bps": self.reserve_fee_bps,
            "rebate_pool_micro_units": self.rebate_pool_micro_units,
            "opened_at_l2_height": self.opened_at_l2_height,
            "commit_until_l2_height": self.commit_until_l2_height,
            "reveal_until_l2_height": self.reveal_until_l2_height,
            "settlement_deadline_l2_height": self.settlement_deadline_l2_height,
            "clearing_price_bps": self.clearing_price_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuctionBid {
    pub bid_id: String,
    pub auction_id: String,
    pub cohort_id: String,
    pub operator_id: String,
    pub status: BidStatus,
    pub sealed_bid_commitment: String,
    pub migration_capacity_accounts: u64,
    pub offered_fee_bps: u64,
    pub requested_rebate_bps: u64,
    pub settlement_latency_blocks: u64,
    pub operator_bond_commitment: String,
    pub pq_attestation_id: String,
    pub submitted_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub score: u64,
}

impl AuctionBid {
    pub fn new(
        bid_id: impl Into<String>,
        auction_id: impl Into<String>,
        cohort_id: impl Into<String>,
        operator_id: impl Into<String>,
        migration_capacity_accounts: u64,
        offered_fee_bps: u64,
        submitted_at_l2_height: u64,
        config: &Config,
    ) -> Self {
        let bid_id = bid_id.into();
        let auction_id = auction_id.into();
        let cohort_id = cohort_id.into();
        let operator_id = operator_id.into();
        let sealed_bid_commitment =
            commitment("auction-bid", &[&bid_id, &auction_id, &operator_id]);
        let operator_bond_commitment = commitment(
            "operator-bond",
            &[&bid_id, &operator_id, &config.fee_asset_id],
        );
        let pq_attestation_id = commitment("bid-pq-attestation-id", &[&bid_id, &operator_id]);
        let requested_rebate_bps = config
            .rebate_cap_bps
            .saturating_sub(offered_fee_bps.min(config.rebate_cap_bps));
        let settlement_latency_blocks = config.settlement_window_blocks / 4;
        let score = bid_score(
            migration_capacity_accounts,
            offered_fee_bps,
            requested_rebate_bps,
            settlement_latency_blocks,
            config,
        );
        Self {
            bid_id,
            auction_id,
            cohort_id,
            operator_id,
            status: BidStatus::Committed,
            sealed_bid_commitment,
            migration_capacity_accounts,
            offered_fee_bps,
            requested_rebate_bps,
            settlement_latency_blocks,
            operator_bond_commitment,
            pq_attestation_id,
            submitted_at_l2_height,
            expires_at_l2_height: submitted_at_l2_height + config.auction_ttl_blocks,
            score,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.bid_id.is_empty(), "bid id is empty");
        ensure!(
            self.migration_capacity_accounts > 0,
            "bid {} has zero capacity",
            self.bid_id
        );
        ensure!(
            self.offered_fee_bps <= config.max_user_fee_bps,
            "bid {} fee exceeds max user fee",
            self.bid_id
        );
        ensure!(
            self.requested_rebate_bps <= config.rebate_cap_bps,
            "bid {} rebate exceeds cap",
            self.bid_id
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "auction_id": self.auction_id,
            "cohort_id": self.cohort_id,
            "operator_id": self.operator_id,
            "status": self.status,
            "sealed_bid_commitment": self.sealed_bid_commitment,
            "migration_capacity_accounts": self.migration_capacity_accounts,
            "offered_fee_bps": self.offered_fee_bps,
            "requested_rebate_bps": self.requested_rebate_bps,
            "settlement_latency_blocks": self.settlement_latency_blocks,
            "operator_bond_commitment": self.operator_bond_commitment,
            "pq_attestation_id": self.pq_attestation_id,
            "submitted_at_l2_height": self.submitted_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "score": self.score,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub kind: AttestationKind,
    pub status: AttestationStatus,
    pub subject_id: String,
    pub verifier_id: String,
    pub suite: String,
    pub transcript_root: String,
    pub public_key_commitment: String,
    pub signature_commitment: String,
    pub min_pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub issued_at_l2_height: u64,
    pub expires_at_l2_height: u64,
}

impl PqAttestation {
    pub fn new(
        attestation_id: impl Into<String>,
        kind: AttestationKind,
        subject_id: impl Into<String>,
        verifier_id: impl Into<String>,
        issued_at_l2_height: u64,
        config: &Config,
    ) -> Self {
        let attestation_id = attestation_id.into();
        let subject_id = subject_id.into();
        let verifier_id = verifier_id.into();
        let transcript_root =
            commitment("pq-attestation-transcript", &[&attestation_id, &subject_id]);
        let public_key_commitment = commitment(
            "pq-attestation-public-key",
            &[&attestation_id, &verifier_id],
        );
        let signature_commitment =
            commitment("pq-attestation-signature", &[&attestation_id, &subject_id]);
        Self {
            attestation_id,
            kind,
            status: AttestationStatus::Verified,
            subject_id,
            verifier_id,
            suite: config.pq_attestation_suite.clone(),
            transcript_root,
            public_key_commitment,
            signature_commitment,
            min_pq_security_bits: config.min_pq_security_bits,
            privacy_set_size: config.target_privacy_set_size,
            issued_at_l2_height,
            expires_at_l2_height: issued_at_l2_height + config.attestation_ttl_blocks,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(
            self.min_pq_security_bits >= config.min_pq_security_bits,
            "attestation {} pq security below minimum",
            self.attestation_id
        );
        ensure!(
            self.privacy_set_size >= config.min_privacy_set_size,
            "attestation {} privacy set below minimum",
            self.attestation_id
        );
        ensure!(
            self.expires_at_l2_height > self.issued_at_l2_height,
            "attestation {} expiration precedes issue height",
            self.attestation_id
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "kind": self.kind,
            "status": self.status,
            "subject_id": self.subject_id,
            "verifier_id": self.verifier_id,
            "suite": self.suite,
            "transcript_root": self.transcript_root,
            "public_key_commitment": self.public_key_commitment,
            "signature_commitment": self.signature_commitment,
            "min_pq_security_bits": self.min_pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "issued_at_l2_height": self.issued_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementWindow {
    pub window_id: String,
    pub auction_id: String,
    pub cohort_id: String,
    pub winning_bid_id: String,
    pub status: SettlementStatus,
    pub account_batch_root: String,
    pub migrated_account_root: String,
    pub settlement_proof_root: String,
    pub fee_escrow_commitment: String,
    pub opens_at_l2_height: u64,
    pub closes_at_l2_height: u64,
    pub settled_at_l2_height: Option<u64>,
    pub expected_accounts: u64,
    pub settled_accounts: u64,
    pub clearing_fee_bps: u64,
}

impl SettlementWindow {
    pub fn new(
        window_id: impl Into<String>,
        auction: &MigrationAuction,
        winning_bid: &AuctionBid,
        opens_at_l2_height: u64,
        config: &Config,
    ) -> Self {
        let window_id = window_id.into();
        let migrated_account_root = commitment(
            "settlement-migrated-accounts",
            &[&window_id, &auction.auction_id],
        );
        let settlement_proof_root =
            commitment("settlement-proof-root", &[&window_id, &winning_bid.bid_id]);
        let fee_escrow_commitment = commitment(
            "settlement-fee-escrow",
            &[&window_id, &winning_bid.operator_id, &config.fee_asset_id],
        );
        Self {
            window_id,
            auction_id: auction.auction_id.clone(),
            cohort_id: auction.cohort_id.clone(),
            winning_bid_id: winning_bid.bid_id.clone(),
            status: SettlementStatus::Pending,
            account_batch_root: auction.account_batch_root.clone(),
            migrated_account_root,
            settlement_proof_root,
            fee_escrow_commitment,
            opens_at_l2_height,
            closes_at_l2_height: opens_at_l2_height + config.settlement_window_blocks,
            settled_at_l2_height: None,
            expected_accounts: winning_bid
                .migration_capacity_accounts
                .min(auction.max_accounts),
            settled_accounts: 0,
            clearing_fee_bps: winning_bid.offered_fee_bps,
        }
    }

    pub fn settle(&mut self, settled_at_l2_height: u64, settled_accounts: u64) -> Result<()> {
        ensure!(
            settled_at_l2_height >= self.opens_at_l2_height,
            "window {} settled before opening",
            self.window_id
        );
        ensure!(
            settled_at_l2_height <= self.closes_at_l2_height,
            "window {} settled after close",
            self.window_id
        );
        ensure!(
            settled_accounts <= self.expected_accounts,
            "window {} settled more accounts than expected",
            self.window_id
        );
        self.status = SettlementStatus::Settled;
        self.settled_at_l2_height = Some(settled_at_l2_height);
        self.settled_accounts = settled_accounts;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "auction_id": self.auction_id,
            "cohort_id": self.cohort_id,
            "winning_bid_id": self.winning_bid_id,
            "status": self.status,
            "account_batch_root": self.account_batch_root,
            "migrated_account_root": self.migrated_account_root,
            "settlement_proof_root": self.settlement_proof_root,
            "fee_escrow_commitment": self.fee_escrow_commitment,
            "opens_at_l2_height": self.opens_at_l2_height,
            "closes_at_l2_height": self.closes_at_l2_height,
            "settled_at_l2_height": self.settled_at_l2_height,
            "expected_accounts": self.expected_accounts,
            "settled_accounts": self.settled_accounts,
            "clearing_fee_bps": self.clearing_fee_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub account_id: String,
    pub auction_id: String,
    pub settlement_window_id: String,
    pub coupon_commitment: String,
    pub fee_asset_id: String,
    pub eligible_fee_bps: u64,
    pub target_fee_bps: u64,
    pub rebate_bps: u64,
    pub rebate_micro_units: u64,
    pub issued_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub claimed: bool,
}

impl LowFeeRebate {
    pub fn new(
        rebate_id: impl Into<String>,
        account_id: impl Into<String>,
        auction_id: impl Into<String>,
        settlement_window_id: impl Into<String>,
        eligible_fee_bps: u64,
        issued_at_l2_height: u64,
        config: &Config,
    ) -> Self {
        let rebate_id = rebate_id.into();
        let account_id = account_id.into();
        let auction_id = auction_id.into();
        let settlement_window_id = settlement_window_id.into();
        let rebate_bps = eligible_fee_bps
            .saturating_sub(config.low_fee_target_bps)
            .min(config.rebate_cap_bps);
        let coupon_commitment =
            commitment("low-fee-rebate", &[&rebate_id, &account_id, &auction_id]);
        Self {
            rebate_id,
            account_id,
            auction_id,
            settlement_window_id,
            coupon_commitment,
            fee_asset_id: config.fee_asset_id.clone(),
            eligible_fee_bps,
            target_fee_bps: config.low_fee_target_bps,
            rebate_bps,
            rebate_micro_units: rebate_bps.saturating_mul(1_000),
            issued_at_l2_height,
            expires_at_l2_height: issued_at_l2_height + config.rebate_ttl_blocks,
            claimed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "account_id": self.account_id,
            "auction_id": self.auction_id,
            "settlement_window_id": self.settlement_window_id,
            "coupon_commitment": self.coupon_commitment,
            "fee_asset_id": self.fee_asset_id,
            "eligible_fee_bps": self.eligible_fee_bps,
            "target_fee_bps": self.target_fee_bps,
            "rebate_bps": self.rebate_bps,
            "rebate_micro_units": self.rebate_micro_units,
            "issued_at_l2_height": self.issued_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "claimed": self.claimed,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub operator_id: String,
    pub purpose: RedactionPurpose,
    pub epoch: u64,
    pub redaction_root: String,
    pub allowance: u64,
    pub used: u64,
    pub expires_at_l2_height: u64,
}

impl RedactionBudget {
    pub fn new(
        budget_id: impl Into<String>,
        operator_id: impl Into<String>,
        purpose: RedactionPurpose,
        epoch: u64,
        issued_at_l2_height: u64,
        config: &Config,
    ) -> Self {
        let budget_id = budget_id.into();
        let operator_id = operator_id.into();
        let redaction_root = commitment("redaction-budget", &[&budget_id, &operator_id]);
        Self {
            budget_id,
            operator_id,
            purpose,
            epoch,
            redaction_root,
            allowance: config.max_redactions_per_epoch,
            used: 0,
            expires_at_l2_height: issued_at_l2_height + config.redaction_epoch_blocks,
        }
    }

    pub fn consume(&mut self, count: u64) -> Result<()> {
        ensure!(
            self.used.saturating_add(count) <= self.allowance,
            "redaction budget {} exhausted",
            self.budget_id
        );
        self.used += count;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "operator_id": self.operator_id,
            "purpose": self.purpose,
            "epoch": self.epoch,
            "redaction_root": self.redaction_root,
            "allowance": self.allowance,
            "used": self.used,
            "remaining": self.allowance.saturating_sub(self.used),
            "expires_at_l2_height": self.expires_at_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub cohort_count: u64,
    pub auction_count: u64,
    pub bid_count: u64,
    pub winning_bid_count: u64,
    pub settlement_window_count: u64,
    pub settled_account_count: u64,
    pub avg_fee_bps: u64,
    pub low_fee_rebate_count: u64,
    pub redacted_account_root: String,
    pub redacted_bid_root: String,
    pub redaction_budget_root: String,
    pub state_root: String,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "cohort_count": self.cohort_count,
            "auction_count": self.auction_count,
            "bid_count": self.bid_count,
            "winning_bid_count": self.winning_bid_count,
            "settlement_window_count": self.settlement_window_count,
            "settled_account_count": self.settled_account_count,
            "avg_fee_bps": self.avg_fee_bps,
            "low_fee_rebate_count": self.low_fee_rebate_count,
            "redacted_account_root": self.redacted_account_root,
            "redacted_bid_root": self.redacted_bid_root,
            "redaction_budget_root": self.redaction_budget_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EventRecord {
    pub event_id: String,
    pub kind: String,
    pub subject_id: String,
    pub at_l2_height: u64,
    pub commitment: String,
}

impl EventRecord {
    pub fn new(
        event_id: impl Into<String>,
        kind: impl Into<String>,
        subject_id: impl Into<String>,
        at_l2_height: u64,
    ) -> Self {
        let event_id = event_id.into();
        let kind = kind.into();
        let subject_id = subject_id.into();
        let commitment = commitment("event", &[&event_id, &kind, &subject_id]);
        Self {
            event_id,
            kind,
            subject_id,
            at_l2_height,
            commitment,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "at_l2_height": self.at_l2_height,
            "commitment": self.commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub cohorts: BTreeMap<String, MigrationCohort>,
    pub accounts: BTreeMap<String, AccountCommitment>,
    pub sessions: BTreeMap<String, SessionCommitment>,
    pub auctions: BTreeMap<String, MigrationAuction>,
    pub bids: BTreeMap<String, AuctionBid>,
    pub attestations: BTreeMap<String, PqAttestation>,
    pub settlement_windows: BTreeMap<String, SettlementWindow>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub events: Vec<EventRecord>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        let counters = Counters::default();
        let roots = Roots::empty(&config, &counters);
        Self {
            config,
            counters,
            roots,
            cohorts: BTreeMap::new(),
            accounts: BTreeMap::new(),
            sessions: BTreeMap::new(),
            auctions: BTreeMap::new(),
            bids: BTreeMap::new(),
            attestations: BTreeMap::new(),
            settlement_windows: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            events: Vec::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::default());
        state
            .add_cohort(MigrationCohort::new(
                "cohort-devnet-legacy-spend-key-rotation",
                MigrationCohortKind::LegacySpendKeyRotation,
                "acct-class-devnet-retail-wallets",
                deterministic_root("devnet", "legacy-source-accounts"),
                deterministic_root("devnet", "pq-target-accounts"),
                DEVNET_L2_HEIGHT,
                65_536,
                &state.config,
            ))
            .expect("devnet cohort");
        state
            .add_session(SessionCommitment::new(
                "session-devnet-alpha",
                "account-devnet-alpha",
                "cohort-devnet-legacy-spend-key-rotation",
                DEVNET_L2_HEIGHT + 1,
                &state.config,
            ))
            .expect("devnet session");
        state
            .add_account(AccountCommitment::new(
                "account-devnet-alpha",
                "cohort-devnet-legacy-spend-key-rotation",
                AccountCommitmentKind::SpendKeyNullifier,
                "session-devnet-alpha",
                "source-account-commitment-alpha",
                "target-account-commitment-alpha",
                DEVNET_L2_HEIGHT + 2,
                &state.config,
            ))
            .expect("devnet account");
        state
            .add_auction(MigrationAuction::new(
                "auction-devnet-alpha",
                "cohort-devnet-legacy-spend-key-rotation",
                AuctionKind::LowestFeeMigration,
                deterministic_root("devnet", "account-batch-alpha"),
                DEVNET_L2_HEIGHT + 4,
                16_384,
                &state.config,
            ))
            .expect("devnet auction");
        state
            .add_bid(AuctionBid::new(
                "bid-devnet-operator-0",
                "auction-devnet-alpha",
                "cohort-devnet-legacy-spend-key-rotation",
                "operator-devnet-0",
                16_384,
                7,
                DEVNET_L2_HEIGHT + 5,
                &state.config,
            ))
            .expect("devnet bid");
        state
            .add_attestation(PqAttestation::new(
                "attestation-devnet-bid-0",
                AttestationKind::MigrationExecutor,
                "bid-devnet-operator-0",
                "verifier-devnet-ml-dsa",
                DEVNET_L2_HEIGHT + 6,
                &state.config,
            ))
            .expect("devnet attestation");
        state
            .open_settlement_window(
                "window-devnet-alpha",
                "auction-devnet-alpha",
                "bid-devnet-operator-0",
                DEVNET_L2_HEIGHT + 128,
            )
            .expect("devnet settlement window");
        state
            .settle_window("window-devnet-alpha", DEVNET_L2_HEIGHT + 256, 16_000)
            .expect("devnet settle");
        state
            .add_low_fee_rebate(LowFeeRebate::new(
                "rebate-devnet-alpha",
                "account-devnet-alpha",
                "auction-devnet-alpha",
                "window-devnet-alpha",
                7,
                DEVNET_L2_HEIGHT + 257,
                &state.config,
            ))
            .expect("devnet rebate");
        state
            .add_redaction_budget(RedactionBudget::new(
                "redaction-devnet-operator-0",
                "operator-devnet-0",
                RedactionPurpose::OperatorSummary,
                DEVNET_EPOCH,
                DEVNET_L2_HEIGHT,
                &state.config,
            ))
            .expect("devnet redaction budget");
        state.refresh_operator_summary("operator-devnet-0", DEVNET_EPOCH);
        state.refresh_roots();
        state
    }

    pub fn add_cohort(&mut self, cohort: MigrationCohort) -> Result<()> {
        ensure!(
            self.cohorts.len() < self.config.max_cohorts,
            "cohort capacity exhausted"
        );
        cohort.validate(&self.config)?;
        ensure!(
            !self.cohorts.contains_key(&cohort.cohort_id),
            "cohort {} already exists",
            cohort.cohort_id
        );
        self.events.push(EventRecord::new(
            next_id("event-cohort", self.counters.cohorts + 1),
            "cohort_added",
            &cohort.cohort_id,
            cohort.opened_at_l2_height,
        ));
        self.counters.cohorts += 1;
        self.cohorts.insert(cohort.cohort_id.clone(), cohort);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_session(&mut self, session: SessionCommitment) -> Result<()> {
        ensure!(
            self.sessions.len() < self.config.max_sessions,
            "session capacity exhausted"
        );
        session.validate(&self.config)?;
        ensure!(
            self.cohorts.contains_key(&session.cohort_id),
            "session {} references missing cohort {}",
            session.session_id,
            session.cohort_id
        );
        ensure!(
            !self.sessions.contains_key(&session.session_id),
            "session {} already exists",
            session.session_id
        );
        self.events.push(EventRecord::new(
            next_id("event-session", self.counters.session_commitments + 1),
            "session_committed",
            &session.session_id,
            session.created_at_l2_height,
        ));
        self.counters.session_commitments += 1;
        self.sessions.insert(session.session_id.clone(), session);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_account(&mut self, account: AccountCommitment) -> Result<()> {
        ensure!(
            self.accounts.len() < self.config.max_accounts,
            "account capacity exhausted"
        );
        account.validate(&self.config)?;
        let cohort = self
            .cohorts
            .get(&account.cohort_id)
            .ok_or_else(|| format!("account {} references missing cohort", account.account_id))?;
        ensure!(
            cohort.status.accepts_accounts(),
            "cohort {} does not accept accounts",
            cohort.cohort_id
        );
        ensure!(
            self.sessions.contains_key(&account.session_id),
            "account {} references missing session {}",
            account.account_id,
            account.session_id
        );
        ensure!(
            !self.accounts.contains_key(&account.account_id),
            "account {} already exists",
            account.account_id
        );
        self.events.push(EventRecord::new(
            next_id("event-account", self.counters.account_commitments + 1),
            "account_committed",
            &account.account_id,
            account.committed_at_l2_height,
        ));
        self.counters.account_commitments += 1;
        self.accounts.insert(account.account_id.clone(), account);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_auction(&mut self, auction: MigrationAuction) -> Result<()> {
        ensure!(
            self.auctions.len() < self.config.max_auctions,
            "auction capacity exhausted"
        );
        auction.validate(&self.config)?;
        let cohort = self
            .cohorts
            .get(&auction.cohort_id)
            .ok_or_else(|| format!("auction {} references missing cohort", auction.auction_id))?;
        ensure!(
            cohort.status.accepts_auctions(),
            "cohort {} does not accept auctions",
            cohort.cohort_id
        );
        ensure!(
            !self.auctions.contains_key(&auction.auction_id),
            "auction {} already exists",
            auction.auction_id
        );
        self.events.push(EventRecord::new(
            next_id("event-auction", self.counters.auctions + 1),
            "auction_opened",
            &auction.auction_id,
            auction.opened_at_l2_height,
        ));
        self.counters.auctions += 1;
        self.auctions.insert(auction.auction_id.clone(), auction);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_bid(&mut self, bid: AuctionBid) -> Result<()> {
        ensure!(
            self.bids.len() < self.config.max_bids,
            "bid capacity exhausted"
        );
        bid.validate(&self.config)?;
        let auction = self
            .auctions
            .get(&bid.auction_id)
            .ok_or_else(|| format!("bid {} references missing auction", bid.bid_id))?;
        ensure!(
            auction.status.accepts_bids(),
            "auction {} does not accept bids",
            auction.auction_id
        );
        ensure!(
            auction.cohort_id == bid.cohort_id,
            "bid {} cohort does not match auction cohort",
            bid.bid_id
        );
        ensure!(
            !self.bids.contains_key(&bid.bid_id),
            "bid {} already exists",
            bid.bid_id
        );
        self.events.push(EventRecord::new(
            next_id("event-bid", self.counters.bids + 1),
            "bid_committed",
            &bid.bid_id,
            bid.submitted_at_l2_height,
        ));
        self.counters.bids += 1;
        self.bids.insert(bid.bid_id.clone(), bid);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_attestation(&mut self, attestation: PqAttestation) -> Result<()> {
        ensure!(
            self.attestations.len() < self.config.max_attestations,
            "attestation capacity exhausted"
        );
        attestation.validate(&self.config)?;
        ensure!(
            !self.attestations.contains_key(&attestation.attestation_id),
            "attestation {} already exists",
            attestation.attestation_id
        );
        self.events.push(EventRecord::new(
            next_id("event-attestation", self.counters.attestations + 1),
            "pq_attestation_verified",
            &attestation.attestation_id,
            attestation.issued_at_l2_height,
        ));
        self.counters.attestations += 1;
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(())
    }

    pub fn open_settlement_window(
        &mut self,
        window_id: impl Into<String>,
        auction_id: &str,
        winning_bid_id: &str,
        opens_at_l2_height: u64,
    ) -> Result<()> {
        ensure!(
            self.settlement_windows.len() < self.config.max_windows,
            "settlement window capacity exhausted"
        );
        let window_id = window_id.into();
        ensure!(
            !self.settlement_windows.contains_key(&window_id),
            "settlement window {} already exists",
            window_id
        );
        let auction = self
            .auctions
            .get(auction_id)
            .ok_or_else(|| format!("missing auction {auction_id}"))?
            .clone();
        let bid = self
            .bids
            .get(winning_bid_id)
            .ok_or_else(|| format!("missing winning bid {winning_bid_id}"))?
            .clone();
        ensure!(
            bid.auction_id == auction.auction_id,
            "bid {} is not part of auction {}",
            bid.bid_id,
            auction.auction_id
        );
        let window =
            SettlementWindow::new(window_id, &auction, &bid, opens_at_l2_height, &self.config);
        self.events.push(EventRecord::new(
            next_id("event-window", self.counters.settlement_windows + 1),
            "settlement_window_opened",
            &window.window_id,
            window.opens_at_l2_height,
        ));
        self.counters.settlement_windows += 1;
        self.settlement_windows
            .insert(window.window_id.clone(), window);
        if let Some(auction) = self.auctions.get_mut(auction_id) {
            auction.status = AuctionStatus::Settled;
        }
        if let Some(bid) = self.bids.get_mut(winning_bid_id) {
            bid.status = BidStatus::Winning;
        }
        self.refresh_roots();
        Ok(())
    }

    pub fn settle_window(
        &mut self,
        window_id: &str,
        settled_at_l2_height: u64,
        settled_accounts: u64,
    ) -> Result<()> {
        let window = self
            .settlement_windows
            .get_mut(window_id)
            .ok_or_else(|| format!("missing settlement window {window_id}"))?;
        window.settle(settled_at_l2_height, settled_accounts)?;
        self.counters.settled_accounts = self
            .counters
            .settled_accounts
            .saturating_add(settled_accounts);
        self.events.push(EventRecord::new(
            next_id("event-settle", self.counters.settled_accounts),
            "settlement_window_settled",
            window_id,
            settled_at_l2_height,
        ));
        self.refresh_roots();
        Ok(())
    }

    pub fn add_low_fee_rebate(&mut self, rebate: LowFeeRebate) -> Result<()> {
        ensure!(
            self.low_fee_rebates.len() < self.config.max_rebates,
            "rebate capacity exhausted"
        );
        ensure!(
            self.accounts.contains_key(&rebate.account_id),
            "rebate {} references missing account {}",
            rebate.rebate_id,
            rebate.account_id
        );
        ensure!(
            self.settlement_windows
                .contains_key(&rebate.settlement_window_id),
            "rebate {} references missing settlement window {}",
            rebate.rebate_id,
            rebate.settlement_window_id
        );
        ensure!(
            !self.low_fee_rebates.contains_key(&rebate.rebate_id),
            "rebate {} already exists",
            rebate.rebate_id
        );
        self.events.push(EventRecord::new(
            next_id("event-rebate", self.counters.low_fee_rebates + 1),
            "low_fee_rebate_issued",
            &rebate.rebate_id,
            rebate.issued_at_l2_height,
        ));
        self.counters.low_fee_rebates += 1;
        self.low_fee_rebates
            .insert(rebate.rebate_id.clone(), rebate);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_redaction_budget(&mut self, budget: RedactionBudget) -> Result<()> {
        ensure!(
            self.redaction_budgets.len() < self.config.max_redaction_budgets,
            "redaction budget capacity exhausted"
        );
        ensure!(
            !self.redaction_budgets.contains_key(&budget.budget_id),
            "redaction budget {} already exists",
            budget.budget_id
        );
        self.events.push(EventRecord::new(
            next_id("event-redaction", self.counters.redaction_budgets + 1),
            "redaction_budget_opened",
            &budget.budget_id,
            budget
                .expires_at_l2_height
                .saturating_sub(self.config.redaction_epoch_blocks),
        ));
        self.counters.redaction_budgets += 1;
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        self.refresh_roots();
        Ok(())
    }

    pub fn refresh_operator_summary(&mut self, operator_id: &str, epoch: u64) {
        let bid_records = self
            .bids
            .values()
            .filter(|bid| bid.operator_id == operator_id)
            .map(AuctionBid::public_record)
            .collect::<Vec<_>>();
        let account_records = self
            .accounts
            .values()
            .map(AccountCommitment::operator_safe_record)
            .collect::<Vec<_>>();
        let redaction_records = self
            .redaction_budgets
            .values()
            .filter(|budget| budget.operator_id == operator_id)
            .map(RedactionBudget::public_record)
            .collect::<Vec<_>>();
        let bid_count = bid_records.len() as u64;
        let winning_bid_count = self
            .bids
            .values()
            .filter(|bid| bid.operator_id == operator_id && bid.status == BidStatus::Winning)
            .count() as u64;
        let total_fee_bps = self
            .bids
            .values()
            .filter(|bid| bid.operator_id == operator_id)
            .map(|bid| bid.offered_fee_bps)
            .sum::<u64>();
        let avg_fee_bps = if bid_count == 0 {
            0
        } else {
            total_fee_bps / bid_count
        };
        let summary_id = format!("summary-{operator_id}-{epoch}");
        let summary = OperatorSummary {
            summary_id: summary_id.clone(),
            operator_id: operator_id.to_string(),
            epoch,
            cohort_count: self.cohorts.len() as u64,
            auction_count: self.auctions.len() as u64,
            bid_count,
            winning_bid_count,
            settlement_window_count: self.settlement_windows.len() as u64,
            settled_account_count: self.counters.settled_accounts,
            avg_fee_bps,
            low_fee_rebate_count: self.low_fee_rebates.len() as u64,
            redacted_account_root: merkle_root(
                "account-migration:redacted-accounts",
                &account_records,
            ),
            redacted_bid_root: merkle_root("account-migration:redacted-bids", &bid_records),
            redaction_budget_root: merkle_root(
                "account-migration:redaction-budgets",
                &redaction_records,
            ),
            state_root: self.state_root(),
        };
        self.operator_summaries.insert(summary_id, summary);
        self.counters.operator_summaries = self.operator_summaries.len() as u64;
        self.refresh_roots();
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.config.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch"
        );
        ensure!(
            self.config.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security below runtime floor"
        );
        ensure!(
            self.config.max_user_fee_bps <= MAX_BPS,
            "max user fee exceeds bps denominator"
        );
        for cohort in self.cohorts.values() {
            cohort.validate(&self.config)?;
        }
        for session in self.sessions.values() {
            session.validate(&self.config)?;
        }
        for account in self.accounts.values() {
            account.validate(&self.config)?;
            ensure!(
                self.sessions.contains_key(&account.session_id),
                "account {} references unknown session {}",
                account.account_id,
                account.session_id
            );
        }
        for auction in self.auctions.values() {
            auction.validate(&self.config)?;
        }
        for bid in self.bids.values() {
            bid.validate(&self.config)?;
        }
        for attestation in self.attestations.values() {
            attestation.validate(&self.config)?;
        }
        Ok(())
    }

    pub fn refresh_roots(&mut self) {
        self.counters.cohorts = self.cohorts.len() as u64;
        self.counters.account_commitments = self.accounts.len() as u64;
        self.counters.session_commitments = self.sessions.len() as u64;
        self.counters.auctions = self.auctions.len() as u64;
        self.counters.bids = self.bids.len() as u64;
        self.counters.attestations = self.attestations.len() as u64;
        self.counters.settlement_windows = self.settlement_windows.len() as u64;
        self.counters.low_fee_rebates = self.low_fee_rebates.len() as u64;
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
        self.counters.operator_summaries = self.operator_summaries.len() as u64;
        self.roots = self.compute_roots();
    }

    pub fn compute_roots(&self) -> Roots {
        let mut roots = Roots {
            config_root: record_root("config", &self.config.public_record()),
            counters_root: record_root("counters", &self.counters.public_record()),
            cohort_root: map_root("cohorts", &self.cohorts, MigrationCohort::public_record),
            account_root: map_root("accounts", &self.accounts, AccountCommitment::public_record),
            session_root: map_root("sessions", &self.sessions, SessionCommitment::public_record),
            auction_root: map_root("auctions", &self.auctions, MigrationAuction::public_record),
            bid_root: map_root("bids", &self.bids, AuctionBid::public_record),
            attestation_root: map_root(
                "attestations",
                &self.attestations,
                PqAttestation::public_record,
            ),
            settlement_window_root: map_root(
                "settlement_windows",
                &self.settlement_windows,
                SettlementWindow::public_record,
            ),
            low_fee_rebate_root: map_root(
                "low_fee_rebates",
                &self.low_fee_rebates,
                LowFeeRebate::public_record,
            ),
            redaction_budget_root: map_root(
                "redaction_budgets",
                &self.redaction_budgets,
                RedactionBudget::public_record,
            ),
            operator_summary_root: map_root(
                "operator_summaries",
                &self.operator_summaries,
                OperatorSummary::public_record,
            ),
            event_root: vec_root(
                "events",
                &self
                    .events
                    .iter()
                    .map(EventRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            state_root: String::new(),
        };
        roots.state_root = state_root_from_record(&json!({
            "protocol_version": self.config.protocol_version,
            "roots": roots.public_record_without_state_root(),
        }));
        roots
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.compute_roots().public_record_without_state_root(),
            "cohorts": values_for_public_record(&self.cohorts, MigrationCohort::public_record),
            "accounts": values_for_public_record(&self.accounts, AccountCommitment::operator_safe_record),
            "sessions": values_for_public_record(&self.sessions, SessionCommitment::public_record),
            "auctions": values_for_public_record(&self.auctions, MigrationAuction::public_record),
            "bids": values_for_public_record(&self.bids, AuctionBid::public_record),
            "attestations": values_for_public_record(&self.attestations, PqAttestation::public_record),
            "settlement_windows": values_for_public_record(&self.settlement_windows, SettlementWindow::public_record),
            "low_fee_rebates": values_for_public_record(&self.low_fee_rebates, LowFeeRebate::public_record),
            "redaction_budgets": values_for_public_record(&self.redaction_budgets, RedactionBudget::public_record),
            "operator_summaries": values_for_public_record(&self.operator_summaries, OperatorSummary::public_record),
            "events": self.events.iter().map(EventRecord::public_record).collect::<Vec<_>>(),
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

    pub fn operator_safe_summary(&self, operator_id: &str, epoch: u64) -> OperatorSummary {
        let mut clone = self.clone();
        clone.refresh_operator_summary(operator_id, epoch);
        clone
            .operator_summaries
            .get(&format!("summary-{operator_id}-{epoch}"))
            .cloned()
            .expect("operator summary inserted")
    }

    pub fn account_ids_by_cohort(&self, cohort_id: &str) -> Vec<String> {
        self.accounts
            .values()
            .filter(|account| account.cohort_id == cohort_id)
            .map(|account| account.account_id.clone())
            .collect()
    }

    pub fn live_account_count(&self) -> u64 {
        self.accounts
            .values()
            .filter(|account| account.status.live())
            .count() as u64
    }

    pub fn low_fee_bid_ids(&self) -> Vec<String> {
        self.bids
            .values()
            .filter(|bid| bid.offered_fee_bps <= self.config.low_fee_target_bps)
            .map(|bid| bid.bid_id.clone())
            .collect()
    }

    pub fn unique_operator_ids(&self) -> BTreeSet<String> {
        self.bids
            .values()
            .map(|bid| bid.operator_id.clone())
            .chain(
                self.redaction_budgets
                    .values()
                    .map(|budget| budget.operator_id.clone()),
            )
            .collect()
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

pub fn deterministic_root(domain: &str, label: &str) -> String {
    domain_hash(
        &format!("account-migration:{domain}:deterministic-root"),
        &[HashPart::Str(label), HashPart::Str(PROTOCOL_VERSION)],
        32,
    )
}

pub fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("account-migration:{domain}:record-root"),
        &[HashPart::Json(record), HashPart::Str(PROTOCOL_VERSION)],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "account-migration:state-root",
        &[HashPart::Json(record), HashPart::Str(PROTOCOL_VERSION)],
        32,
    )
}

fn map_root<T, F>(domain: &str, values: &BTreeMap<String, T>, render: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = values
        .iter()
        .map(|(id, value)| {
            json!({
                "id": id,
                "record": render(value),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(&format!("account-migration:{domain}"), &leaves)
}

fn vec_root(domain: &str, values: &[Value]) -> String {
    merkle_root(&format!("account-migration:{domain}"), values)
}

fn values_for_public_record<T, F>(values: &BTreeMap<String, T>, render: F) -> Vec<Value>
where
    F: Fn(&T) -> Value,
{
    values.values().map(render).collect()
}

fn commitment(domain: &str, parts: &[&str]) -> String {
    let leaves = parts
        .iter()
        .enumerate()
        .map(|(index, part)| json!({"index": index, "value": part}))
        .collect::<Vec<_>>();
    domain_hash(
        &format!("account-migration:{domain}:commitment"),
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(&json!({ "parts": leaves })),
        ],
        32,
    )
}

fn bid_score(
    capacity_accounts: u64,
    offered_fee_bps: u64,
    requested_rebate_bps: u64,
    settlement_latency_blocks: u64,
    config: &Config,
) -> u64 {
    let capacity_score = capacity_accounts.min(1_000_000);
    let fee_score = config
        .max_user_fee_bps
        .saturating_sub(offered_fee_bps)
        .saturating_mul(10_000);
    let rebate_penalty = requested_rebate_bps.saturating_mul(250);
    let latency_penalty = settlement_latency_blocks.min(config.settlement_window_blocks);
    capacity_score
        .saturating_add(fee_score)
        .saturating_sub(rebate_penalty)
        .saturating_sub(latency_penalty)
}

fn next_id(prefix: &str, value: u64) -> String {
    format!("{prefix}-{value:016}")
}

fn kind_label(kind: MigrationCohortKind) -> &'static str {
    match kind {
        MigrationCohortKind::LegacySpendKeyRotation => "legacy_spend_key_rotation",
        MigrationCohortKind::ViewKeyPreserving => "view_key_preserving",
        MigrationCohortKind::HardwareWalletBatch => "hardware_wallet_batch",
        MigrationCohortKind::ExchangeCustodySweep => "exchange_custody_sweep",
        MigrationCohortKind::MobileSessionUpgrade => "mobile_session_upgrade",
        MigrationCohortKind::WatchOnlyAccountRecovery => "watch_only_account_recovery",
        MigrationCohortKind::MultisigParticipantRotation => "multisig_participant_rotation",
        MigrationCohortKind::ContractAccountMigration => "contract_account_migration",
        MigrationCohortKind::EmergencyQuantumHardened => "emergency_quantum_hardened",
        MigrationCohortKind::Custom => "custom",
    }
}
