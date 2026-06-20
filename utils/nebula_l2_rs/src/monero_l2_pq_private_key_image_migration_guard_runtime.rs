use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PqPrivateKeyImageMigrationGuardRuntimeResult<T> = Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_KEY_IMAGE_MIGRATION_GUARD_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-key-image-migration-guard-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_KEY_IMAGE_MIGRATION_GUARD_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_GUARD_ID: &str = "monero-l2-pq-private-key-image-migration-guard-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 1_628_160;
pub const DEVNET_EPOCH: u64 = 3_392;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const KEY_IMAGE_COMMITMENT_SCHEME: &str = "monero-key-image-migration-commitment-root-v1";
pub const PQ_WALLET_ATTESTATION_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-wallet-key-image-migration-v1";
pub const DUPLICATE_SPEND_QUARANTINE_SCHEME: &str =
    "private-key-image-duplicate-spend-quarantine-root-v1";
pub const LOW_FEE_MIGRATION_CREDIT_SCHEME: &str =
    "low-fee-private-key-image-migration-credit-root-v1";
pub const PRIVACY_REDACTION_BUDGET_SCHEME: &str = "wallet-safe-key-image-redaction-budget-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str = "public-key-image-migration-guard-record-v1";
pub const PUBLIC_ROOT_SCHEME: &str = "public-key-image-migration-guard-roots-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_key_images_addresses_amounts_view_keys_or_spend_graphs";
pub const DEFAULT_EPOCH_SPAN_BLOCKS: u64 = 720;
pub const DEFAULT_EPOCH_GRACE_BLOCKS: u64 = 144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_COMMITMENT_BATCH_SIZE: u64 = 16_384;
pub const DEFAULT_MIN_WALLET_ATTESTATION_QUORUM_BPS: u16 = 6_700;
pub const DEFAULT_STRONG_WALLET_ATTESTATION_QUORUM_BPS: u16 = 8_000;
pub const DEFAULT_DUPLICATE_QUARANTINE_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_REDACTION_WINDOW_BLOCKS: u64 = 2_880;
pub const DEFAULT_MAX_REDACTION_BUDGET_BPS: u16 = 75;
pub const DEFAULT_LOW_FEE_CREDIT_CAP_MICRO_UNITS: u64 = 5_000;
pub const DEFAULT_LOW_FEE_CREDIT_TTL_BLOCKS: u64 = 432;
pub const DEFAULT_WALLET_BATCH_TARGET: u64 = 256;
pub const DEFAULT_PUBLIC_ROOT_INTERVAL_BLOCKS: u64 = 72;
pub const MAX_BPS: u16 = 10_000;
pub const MAX_MIGRATION_EPOCHS: usize = 524_288;
pub const MAX_KEY_IMAGE_COMMITMENTS: usize = 4_194_304;
pub const MAX_WALLET_ATTESTATIONS: usize = 2_097_152;
pub const MAX_DUPLICATE_QUARANTINES: usize = 524_288;
pub const MAX_LOW_FEE_CREDITS: usize = 1_048_576;
pub const MAX_REDACTION_BUDGETS: usize = 524_288;
pub const MAX_PUBLIC_ROOTS: usize = 524_288;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationPhase {
    Planned,
    PrivacyPrimed,
    WalletIntake,
    CommitmentOpen,
    AttestationOpen,
    CreditSponsored,
    Enforced,
    GracePeriod,
    Complete,
    Paused,
    Revoked,
}

impl MigrationPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::PrivacyPrimed => "privacy_primed",
            Self::WalletIntake => "wallet_intake",
            Self::CommitmentOpen => "commitment_open",
            Self::AttestationOpen => "attestation_open",
            Self::CreditSponsored => "credit_sponsored",
            Self::Enforced => "enforced",
            Self::GracePeriod => "grace_period",
            Self::Complete => "complete",
            Self::Paused => "paused",
            Self::Revoked => "revoked",
        }
    }

    pub fn accepts_commitments(self) -> bool {
        matches!(
            self,
            Self::PrivacyPrimed
                | Self::WalletIntake
                | Self::CommitmentOpen
                | Self::AttestationOpen
                | Self::CreditSponsored
                | Self::GracePeriod
        )
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Revoked)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Submitted,
    Rooted,
    Attested,
    CreditReserved,
    Migrated,
    Quarantined,
    Rejected,
    Expired,
}

impl CommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Rooted => "rooted",
            Self::Attested => "attested",
            Self::CreditReserved => "credit_reserved",
            Self::Migrated => "migrated",
            Self::Quarantined => "quarantined",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::Rooted | Self::Attested | Self::CreditReserved
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletAttestationStatus {
    Submitted,
    Quorum,
    StrongQuorum,
    Superseded,
    Revoked,
    Rejected,
    Expired,
}

impl WalletAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Quorum => "quorum",
            Self::StrongQuorum => "strong_quorum",
            Self::Superseded => "superseded",
            Self::Revoked => "revoked",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn accepted(self) -> bool {
        matches!(self, Self::Quorum | Self::StrongQuorum)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    DuplicateSpend,
    ConflictingRoot,
    ReorgReplay,
    WatcherChallenge,
    WalletAttestationMismatch,
    RedactionBudgetExceeded,
    OperatorDispute,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DuplicateSpend => "duplicate_spend",
            Self::ConflictingRoot => "conflicting_root",
            Self::ReorgReplay => "reorg_replay",
            Self::WatcherChallenge => "watcher_challenge",
            Self::WalletAttestationMismatch => "wallet_attestation_mismatch",
            Self::RedactionBudgetExceeded => "redaction_budget_exceeded",
            Self::OperatorDispute => "operator_dispute",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineStatus {
    Open,
    EvidenceRequested,
    AttestedDuplicate,
    Cleared,
    Slashed,
    Expired,
}

impl QuarantineStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceRequested => "evidence_requested",
            Self::AttestedDuplicate => "attested_duplicate",
            Self::Cleared => "cleared",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Open | Self::EvidenceRequested | Self::AttestedDuplicate
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditStatus {
    Reserved,
    Applied,
    Refunded,
    Expired,
    Revoked,
}

impl CreditStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn open(self) -> bool {
        matches!(self, Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionStatus {
    Open,
    NearLimit,
    Exhausted,
    Refilled,
    Frozen,
}

impl RedactionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::NearLimit => "near_limit",
            Self::Exhausted => "exhausted",
            Self::Refilled => "refilled",
            Self::Frozen => "frozen",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub schema_version: u64,
    pub protocol_version: String,
    pub chain_id: String,
    pub guard_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub key_image_commitment_scheme: String,
    pub pq_wallet_attestation_scheme: String,
    pub duplicate_spend_quarantine_scheme: String,
    pub low_fee_migration_credit_scheme: String,
    pub privacy_redaction_budget_scheme: String,
    pub public_record_scheme: String,
    pub privacy_boundary: String,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub epoch_span_blocks: u64,
    pub epoch_grace_blocks: u64,
    pub min_commitment_batch_size: u64,
    pub min_wallet_attestation_quorum_bps: u16,
    pub strong_wallet_attestation_quorum_bps: u16,
    pub duplicate_quarantine_ttl_blocks: u64,
    pub redaction_window_blocks: u64,
    pub max_redaction_budget_bps: u16,
    pub low_fee_credit_cap_micro_units: u64,
    pub low_fee_credit_ttl_blocks: u64,
    pub wallet_batch_target: u64,
    pub public_root_interval_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            guard_id: DEVNET_GUARD_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            key_image_commitment_scheme: KEY_IMAGE_COMMITMENT_SCHEME.to_string(),
            pq_wallet_attestation_scheme: PQ_WALLET_ATTESTATION_SCHEME.to_string(),
            duplicate_spend_quarantine_scheme: DUPLICATE_SPEND_QUARANTINE_SCHEME.to_string(),
            low_fee_migration_credit_scheme: LOW_FEE_MIGRATION_CREDIT_SCHEME.to_string(),
            privacy_redaction_budget_scheme: PRIVACY_REDACTION_BUDGET_SCHEME.to_string(),
            public_record_scheme: PUBLIC_RECORD_SCHEME.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            epoch_span_blocks: DEFAULT_EPOCH_SPAN_BLOCKS,
            epoch_grace_blocks: DEFAULT_EPOCH_GRACE_BLOCKS,
            min_commitment_batch_size: DEFAULT_MIN_COMMITMENT_BATCH_SIZE,
            min_wallet_attestation_quorum_bps: DEFAULT_MIN_WALLET_ATTESTATION_QUORUM_BPS,
            strong_wallet_attestation_quorum_bps: DEFAULT_STRONG_WALLET_ATTESTATION_QUORUM_BPS,
            duplicate_quarantine_ttl_blocks: DEFAULT_DUPLICATE_QUARANTINE_TTL_BLOCKS,
            redaction_window_blocks: DEFAULT_REDACTION_WINDOW_BLOCKS,
            max_redaction_budget_bps: DEFAULT_MAX_REDACTION_BUDGET_BPS,
            low_fee_credit_cap_micro_units: DEFAULT_LOW_FEE_CREDIT_CAP_MICRO_UNITS,
            low_fee_credit_ttl_blocks: DEFAULT_LOW_FEE_CREDIT_TTL_BLOCKS,
            wallet_batch_target: DEFAULT_WALLET_BATCH_TARGET,
            public_root_interval_blocks: DEFAULT_PUBLIC_ROOT_INTERVAL_BLOCKS,
        }
    }

    pub fn validate(&self) -> MoneroL2PqPrivateKeyImageMigrationGuardRuntimeResult<()> {
        required("protocol_version", &self.protocol_version)?;
        required("guard_id", &self.guard_id)?;
        required("l2_network", &self.l2_network)?;
        required("monero_network", &self.monero_network)?;
        required("fee_asset_id", &self.fee_asset_id)?;
        require(
            self.min_pq_security_bits <= self.target_pq_security_bits,
            "min pq security bits must not exceed target pq security bits",
        )?;
        require(
            self.epoch_span_blocks > 0,
            "epoch span blocks must be nonzero",
        )?;
        require(
            self.min_commitment_batch_size > 0,
            "minimum commitment batch size must be nonzero",
        )?;
        require(
            self.min_wallet_attestation_quorum_bps <= MAX_BPS,
            "wallet attestation quorum exceeds max bps",
        )?;
        require(
            self.strong_wallet_attestation_quorum_bps <= MAX_BPS,
            "strong wallet attestation quorum exceeds max bps",
        )?;
        require(
            self.min_wallet_attestation_quorum_bps <= self.strong_wallet_attestation_quorum_bps,
            "strong quorum must be at least minimum quorum",
        )?;
        require(
            self.max_redaction_budget_bps <= MAX_BPS,
            "redaction budget exceeds max bps",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "schema_version": self.schema_version,
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "guard_id": self.guard_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "key_image_commitment_scheme": self.key_image_commitment_scheme,
            "pq_wallet_attestation_scheme": self.pq_wallet_attestation_scheme,
            "duplicate_spend_quarantine_scheme": self.duplicate_spend_quarantine_scheme,
            "low_fee_migration_credit_scheme": self.low_fee_migration_credit_scheme,
            "privacy_redaction_budget_scheme": self.privacy_redaction_budget_scheme,
            "public_record_scheme": self.public_record_scheme,
            "privacy_boundary": self.privacy_boundary,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "epoch_span_blocks": self.epoch_span_blocks,
            "epoch_grace_blocks": self.epoch_grace_blocks,
            "min_commitment_batch_size": self.min_commitment_batch_size,
            "min_wallet_attestation_quorum_bps": self.min_wallet_attestation_quorum_bps,
            "strong_wallet_attestation_quorum_bps": self.strong_wallet_attestation_quorum_bps,
            "duplicate_quarantine_ttl_blocks": self.duplicate_quarantine_ttl_blocks,
            "redaction_window_blocks": self.redaction_window_blocks,
            "max_redaction_budget_bps": self.max_redaction_budget_bps,
            "low_fee_credit_cap_micro_units": self.low_fee_credit_cap_micro_units,
            "low_fee_credit_ttl_blocks": self.low_fee_credit_ttl_blocks,
            "wallet_batch_target": self.wallet_batch_target,
            "public_root_interval_blocks": self.public_root_interval_blocks,
        })
    }

    pub fn config_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-PRIVATE-KEY-IMAGE-MIGRATION-GUARD-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub migration_epochs: u64,
    pub active_epochs: u64,
    pub key_image_commitments: u64,
    pub rooted_commitments: u64,
    pub migrated_commitments: u64,
    pub quarantined_commitments: u64,
    pub wallet_attestations: u64,
    pub accepted_wallet_attestations: u64,
    pub duplicate_quarantines: u64,
    pub active_duplicate_quarantines: u64,
    pub low_fee_credits: u64,
    pub open_low_fee_credits: u64,
    pub applied_low_fee_credits: u64,
    pub redaction_budgets: u64,
    pub exhausted_redaction_budgets: u64,
    pub public_roots: u64,
    pub total_credit_micro_units: u64,
    pub applied_credit_micro_units: u64,
    pub redacted_fields: u64,
    pub redaction_budget_units: u64,
    pub duplicate_spend_signals: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "migration_epochs": self.migration_epochs,
            "active_epochs": self.active_epochs,
            "key_image_commitments": self.key_image_commitments,
            "rooted_commitments": self.rooted_commitments,
            "migrated_commitments": self.migrated_commitments,
            "quarantined_commitments": self.quarantined_commitments,
            "wallet_attestations": self.wallet_attestations,
            "accepted_wallet_attestations": self.accepted_wallet_attestations,
            "duplicate_quarantines": self.duplicate_quarantines,
            "active_duplicate_quarantines": self.active_duplicate_quarantines,
            "low_fee_credits": self.low_fee_credits,
            "open_low_fee_credits": self.open_low_fee_credits,
            "applied_low_fee_credits": self.applied_low_fee_credits,
            "redaction_budgets": self.redaction_budgets,
            "exhausted_redaction_budgets": self.exhausted_redaction_budgets,
            "public_roots": self.public_roots,
            "total_credit_micro_units": self.total_credit_micro_units,
            "applied_credit_micro_units": self.applied_credit_micro_units,
            "redacted_fields": self.redacted_fields,
            "redaction_budget_units": self.redaction_budget_units,
            "duplicate_spend_signals": self.duplicate_spend_signals,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub epoch_root: String,
    pub key_image_commitment_root: String,
    pub wallet_attestation_root: String,
    pub duplicate_quarantine_root: String,
    pub low_fee_credit_root: String,
    pub redaction_budget_root: String,
    pub public_root_journal_root: String,
    pub consumed_commitment_nullifier_root: String,
    pub quarantine_key_image_tag_root: String,
    pub deterministic_public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config) -> Self {
        let mut roots = Self {
            config_root: config.config_root(),
            epoch_root: empty_root("epochs"),
            key_image_commitment_root: empty_root("key_image_commitments"),
            wallet_attestation_root: empty_root("wallet_attestations"),
            duplicate_quarantine_root: empty_root("duplicate_quarantines"),
            low_fee_credit_root: empty_root("low_fee_credits"),
            redaction_budget_root: empty_root("redaction_budgets"),
            public_root_journal_root: empty_root("public_roots"),
            consumed_commitment_nullifier_root: empty_root("consumed_commitment_nullifiers"),
            quarantine_key_image_tag_root: empty_root("quarantine_key_image_tags"),
            deterministic_public_record_root: empty_root("deterministic_public_record"),
            state_root: empty_root("state"),
        };
        roots.state_root = roots.roots_root();
        roots
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "epoch_root": self.epoch_root,
            "key_image_commitment_root": self.key_image_commitment_root,
            "wallet_attestation_root": self.wallet_attestation_root,
            "duplicate_quarantine_root": self.duplicate_quarantine_root,
            "low_fee_credit_root": self.low_fee_credit_root,
            "redaction_budget_root": self.redaction_budget_root,
            "public_root_journal_root": self.public_root_journal_root,
            "consumed_commitment_nullifier_root": self.consumed_commitment_nullifier_root,
            "quarantine_key_image_tag_root": self.quarantine_key_image_tag_root,
            "deterministic_public_record_root": self.deterministic_public_record_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        set_json_field(&mut record, "state_root", json!(self.state_root));
        record
    }

    pub fn roots_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-PRIVATE-KEY-IMAGE-MIGRATION-GUARD-ROOTS",
            &self.public_record_without_state_root(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MigrationEpoch {
    pub epoch_id: String,
    pub epoch_number: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub grace_end_height: u64,
    pub phase: MigrationPhase,
    pub min_commitment_batch_size: u64,
    pub accepted_commitment_root: String,
    pub wallet_attestation_root: String,
    pub low_fee_credit_root: String,
    pub duplicate_quarantine_root: String,
    pub redaction_budget_root: String,
    pub public_root: String,
    pub operator_set_root: String,
    pub created_height: u64,
    pub updated_height: u64,
}

impl MigrationEpoch {
    pub fn new(
        epoch_id: impl Into<String>,
        epoch_number: u64,
        start_height: u64,
        phase: MigrationPhase,
        config: &Config,
    ) -> Self {
        let epoch_id = epoch_id.into();
        let end_height = start_height.saturating_add(config.epoch_span_blocks);
        let grace_end_height = end_height.saturating_add(config.epoch_grace_blocks);
        let mut epoch = Self {
            epoch_id,
            epoch_number,
            start_height,
            end_height,
            grace_end_height,
            phase,
            min_commitment_batch_size: config.min_commitment_batch_size,
            accepted_commitment_root: empty_root("epoch_accepted_commitments"),
            wallet_attestation_root: empty_root("epoch_wallet_attestations"),
            low_fee_credit_root: empty_root("epoch_low_fee_credits"),
            duplicate_quarantine_root: empty_root("epoch_duplicate_quarantines"),
            redaction_budget_root: empty_root("epoch_redaction_budgets"),
            public_root: empty_root("epoch_public_root"),
            operator_set_root: sample_root("devnet_operator_set"),
            created_height: start_height,
            updated_height: start_height,
        };
        epoch.public_root = epoch.state_root();
        epoch
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch_id": self.epoch_id,
            "epoch_number": self.epoch_number,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "grace_end_height": self.grace_end_height,
            "phase": self.phase.as_str(),
            "min_commitment_batch_size": self.min_commitment_batch_size,
            "accepted_commitment_root": self.accepted_commitment_root,
            "wallet_attestation_root": self.wallet_attestation_root,
            "low_fee_credit_root": self.low_fee_credit_root,
            "duplicate_quarantine_root": self.duplicate_quarantine_root,
            "redaction_budget_root": self.redaction_budget_root,
            "public_root": self.public_root,
            "operator_set_root": self.operator_set_root,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-PRIVATE-KEY-IMAGE-MIGRATION-GUARD-EPOCH",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyImageCommitment {
    pub commitment_id: String,
    pub epoch_id: String,
    pub wallet_tag: String,
    pub key_image_tag: String,
    pub nullifier: String,
    pub commitment_root: String,
    pub encrypted_witness_root: String,
    pub decoy_context_root: String,
    pub redaction_receipt_root: String,
    pub status: CommitmentStatus,
    pub pq_security_bits: u16,
    pub batch_index: u64,
    pub observed_height: u64,
    pub expires_height: u64,
    pub duplicate_signal_count: u16,
    pub low_fee_credit_id: Option<String>,
}

impl KeyImageCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "epoch_id": self.epoch_id,
            "wallet_tag": self.wallet_tag,
            "key_image_tag": self.key_image_tag,
            "nullifier": self.nullifier,
            "commitment_root": self.commitment_root,
            "encrypted_witness_root": self.encrypted_witness_root,
            "decoy_context_root": self.decoy_context_root,
            "redaction_receipt_root": self.redaction_receipt_root,
            "status": self.status.as_str(),
            "pq_security_bits": self.pq_security_bits,
            "batch_index": self.batch_index,
            "observed_height": self.observed_height,
            "expires_height": self.expires_height,
            "duplicate_signal_count": self.duplicate_signal_count,
            "low_fee_credit_id": self.low_fee_credit_id,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-PRIVATE-KEY-IMAGE-MIGRATION-GUARD-COMMITMENT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqWalletAttestation {
    pub attestation_id: String,
    pub epoch_id: String,
    pub wallet_tag: String,
    pub attested_commitment_root: String,
    pub pq_public_key_root: String,
    pub signature_root: String,
    pub device_policy_root: String,
    pub status: WalletAttestationStatus,
    pub signer_count: u16,
    pub quorum_bps: u16,
    pub pq_security_bits: u16,
    pub submitted_height: u64,
    pub expires_height: u64,
}

impl PqWalletAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "epoch_id": self.epoch_id,
            "wallet_tag": self.wallet_tag,
            "attested_commitment_root": self.attested_commitment_root,
            "pq_public_key_root": self.pq_public_key_root,
            "signature_root": self.signature_root,
            "device_policy_root": self.device_policy_root,
            "status": self.status.as_str(),
            "signer_count": self.signer_count,
            "quorum_bps": self.quorum_bps,
            "pq_security_bits": self.pq_security_bits,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DuplicateSpendQuarantine {
    pub quarantine_id: String,
    pub epoch_id: String,
    pub key_image_tag: String,
    pub primary_commitment_id: String,
    pub conflicting_commitment_id: String,
    pub evidence_root: String,
    pub reviewer_set_root: String,
    pub reason: QuarantineReason,
    pub status: QuarantineStatus,
    pub opened_height: u64,
    pub expires_height: u64,
    pub duplicate_signal_count: u16,
}

impl DuplicateSpendQuarantine {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "epoch_id": self.epoch_id,
            "key_image_tag": self.key_image_tag,
            "primary_commitment_id": self.primary_commitment_id,
            "conflicting_commitment_id": self.conflicting_commitment_id,
            "evidence_root": self.evidence_root,
            "reviewer_set_root": self.reviewer_set_root,
            "reason": self.reason.as_str(),
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "duplicate_signal_count": self.duplicate_signal_count,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeMigrationCredit {
    pub credit_id: String,
    pub epoch_id: String,
    pub wallet_tag: String,
    pub commitment_id: String,
    pub sponsor_root: String,
    pub credit_micro_units: u64,
    pub fee_asset_id: String,
    pub status: CreditStatus,
    pub reserved_height: u64,
    pub expires_height: u64,
    pub applied_height: Option<u64>,
}

impl LowFeeMigrationCredit {
    pub fn public_record(&self) -> Value {
        json!({
            "credit_id": self.credit_id,
            "epoch_id": self.epoch_id,
            "wallet_tag": self.wallet_tag,
            "commitment_id": self.commitment_id,
            "sponsor_root": self.sponsor_root,
            "credit_micro_units": self.credit_micro_units,
            "fee_asset_id": self.fee_asset_id,
            "status": self.status.as_str(),
            "reserved_height": self.reserved_height,
            "expires_height": self.expires_height,
            "applied_height": self.applied_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub epoch_id: String,
    pub wallet_tag: String,
    pub policy_root: String,
    pub budget_units: u64,
    pub consumed_units: u64,
    pub redacted_fields: u64,
    pub max_budget_bps: u16,
    pub status: RedactionStatus,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "epoch_id": self.epoch_id,
            "wallet_tag": self.wallet_tag,
            "policy_root": self.policy_root,
            "budget_units": self.budget_units,
            "consumed_units": self.consumed_units,
            "redacted_fields": self.redacted_fields,
            "max_budget_bps": self.max_budget_bps,
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicRootRecord {
    pub record_id: String,
    pub height: u64,
    pub epoch_root: String,
    pub key_image_commitment_root: String,
    pub wallet_attestation_root: String,
    pub duplicate_quarantine_root: String,
    pub low_fee_credit_root: String,
    pub redaction_budget_root: String,
    pub state_root: String,
    pub published_by_root: String,
}

impl PublicRootRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "height": self.height,
            "epoch_root": self.epoch_root,
            "key_image_commitment_root": self.key_image_commitment_root,
            "wallet_attestation_root": self.wallet_attestation_root,
            "duplicate_quarantine_root": self.duplicate_quarantine_root,
            "low_fee_credit_root": self.low_fee_credit_root,
            "redaction_budget_root": self.redaction_budget_root,
            "state_root": self.state_root,
            "published_by_root": self.published_by_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub migration_epochs: BTreeMap<String, MigrationEpoch>,
    pub key_image_commitments: BTreeMap<String, KeyImageCommitment>,
    pub wallet_attestations: BTreeMap<String, PqWalletAttestation>,
    pub duplicate_quarantines: BTreeMap<String, DuplicateSpendQuarantine>,
    pub low_fee_credits: BTreeMap<String, LowFeeMigrationCredit>,
    pub redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub public_roots: BTreeMap<String, PublicRootRecord>,
    pub consumed_commitment_nullifiers: BTreeSet<String>,
    pub quarantine_key_image_tags: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> MoneroL2PqPrivateKeyImageMigrationGuardRuntimeResult<Self> {
        config.validate()?;
        let roots = Roots::empty(&config);
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots,
            migration_epochs: BTreeMap::new(),
            key_image_commitments: BTreeMap::new(),
            wallet_attestations: BTreeMap::new(),
            duplicate_quarantines: BTreeMap::new(),
            low_fee_credits: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            public_roots: BTreeMap::new(),
            consumed_commitment_nullifiers: BTreeSet::new(),
            quarantine_key_image_tags: BTreeSet::new(),
        };
        state.refresh();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self::new(config).expect("devnet config is valid");
        let epoch = MigrationEpoch::new(
            "epoch-devnet-0003392",
            DEVNET_EPOCH,
            DEVNET_HEIGHT,
            MigrationPhase::CreditSponsored,
            &state.config,
        );
        state
            .insert_migration_epoch(epoch)
            .expect("devnet epoch is valid");

        let budget = PrivacyRedactionBudget {
            budget_id: "redaction-budget-devnet-wallet-001".to_string(),
            epoch_id: "epoch-devnet-0003392".to_string(),
            wallet_tag: "wallet-tag-devnet-001-redacted".to_string(),
            policy_root: sample_root("wallet_redaction_policy_001"),
            budget_units: 10_000,
            consumed_units: 42,
            redacted_fields: 7,
            max_budget_bps: state.config.max_redaction_budget_bps,
            status: RedactionStatus::Open,
            opened_height: DEVNET_HEIGHT,
            expires_height: DEVNET_HEIGHT + state.config.redaction_window_blocks,
        };
        state
            .insert_redaction_budget(budget)
            .expect("devnet budget is valid");

        let commitment = KeyImageCommitment {
            commitment_id: "ki-commitment-devnet-001".to_string(),
            epoch_id: "epoch-devnet-0003392".to_string(),
            wallet_tag: "wallet-tag-devnet-001-redacted".to_string(),
            key_image_tag: "ki-tag-devnet-001-redacted".to_string(),
            nullifier: sample_root("ki_nullifier_001"),
            commitment_root: sample_root("ki_commitment_001"),
            encrypted_witness_root: sample_root("encrypted_witness_001"),
            decoy_context_root: sample_root("decoy_context_001"),
            redaction_receipt_root: sample_root("redaction_receipt_001"),
            status: CommitmentStatus::Attested,
            pq_security_bits: state.config.target_pq_security_bits,
            batch_index: 0,
            observed_height: DEVNET_HEIGHT + 4,
            expires_height: DEVNET_HEIGHT + state.config.epoch_span_blocks,
            duplicate_signal_count: 0,
            low_fee_credit_id: Some("low-fee-credit-devnet-001".to_string()),
        };
        state
            .insert_key_image_commitment(commitment)
            .expect("devnet commitment is valid");

        let attestation = PqWalletAttestation {
            attestation_id: "pq-wallet-attestation-devnet-001".to_string(),
            epoch_id: "epoch-devnet-0003392".to_string(),
            wallet_tag: "wallet-tag-devnet-001-redacted".to_string(),
            attested_commitment_root: sample_root("attested_commitment_set_001"),
            pq_public_key_root: sample_root("pq_wallet_public_keys_001"),
            signature_root: sample_root("pq_wallet_signatures_001"),
            device_policy_root: sample_root("wallet_device_policy_001"),
            status: WalletAttestationStatus::StrongQuorum,
            signer_count: 5,
            quorum_bps: state.config.strong_wallet_attestation_quorum_bps,
            pq_security_bits: state.config.target_pq_security_bits,
            submitted_height: DEVNET_HEIGHT + 5,
            expires_height: DEVNET_HEIGHT + state.config.epoch_span_blocks,
        };
        state
            .insert_wallet_attestation(attestation)
            .expect("devnet attestation is valid");

        let credit = LowFeeMigrationCredit {
            credit_id: "low-fee-credit-devnet-001".to_string(),
            epoch_id: "epoch-devnet-0003392".to_string(),
            wallet_tag: "wallet-tag-devnet-001-redacted".to_string(),
            commitment_id: "ki-commitment-devnet-001".to_string(),
            sponsor_root: sample_root("migration_credit_sponsor_001"),
            credit_micro_units: 4_200,
            fee_asset_id: state.config.fee_asset_id.clone(),
            status: CreditStatus::Reserved,
            reserved_height: DEVNET_HEIGHT + 6,
            expires_height: DEVNET_HEIGHT + state.config.low_fee_credit_ttl_blocks,
            applied_height: None,
        };
        state
            .insert_low_fee_credit(credit)
            .expect("devnet credit is valid");
        state
            .publish_public_roots(
                "public-root-devnet-001",
                DEVNET_HEIGHT + state.config.public_root_interval_blocks,
                sample_root("devnet_root_publisher"),
            )
            .expect("devnet root record is valid");
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let duplicate = KeyImageCommitment {
            commitment_id: "ki-commitment-devnet-duplicate-001".to_string(),
            epoch_id: "epoch-devnet-0003392".to_string(),
            wallet_tag: "wallet-tag-devnet-duplicate-redacted".to_string(),
            key_image_tag: "ki-tag-devnet-001-redacted".to_string(),
            nullifier: sample_root("ki_nullifier_duplicate_001"),
            commitment_root: sample_root("ki_commitment_duplicate_001"),
            encrypted_witness_root: sample_root("encrypted_witness_duplicate_001"),
            decoy_context_root: sample_root("decoy_context_duplicate_001"),
            redaction_receipt_root: sample_root("redaction_receipt_duplicate_001"),
            status: CommitmentStatus::Quarantined,
            pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            batch_index: 1,
            observed_height: DEVNET_HEIGHT + 8,
            expires_height: DEVNET_HEIGHT + DEFAULT_EPOCH_SPAN_BLOCKS,
            duplicate_signal_count: 2,
            low_fee_credit_id: None,
        };
        state
            .insert_key_image_commitment(duplicate)
            .expect("demo duplicate commitment is valid");
        let quarantine = DuplicateSpendQuarantine {
            quarantine_id: "duplicate-quarantine-devnet-001".to_string(),
            epoch_id: "epoch-devnet-0003392".to_string(),
            key_image_tag: "ki-tag-devnet-001-redacted".to_string(),
            primary_commitment_id: "ki-commitment-devnet-001".to_string(),
            conflicting_commitment_id: "ki-commitment-devnet-duplicate-001".to_string(),
            evidence_root: sample_root("duplicate_spend_evidence_001"),
            reviewer_set_root: sample_root("duplicate_spend_reviewers_001"),
            reason: QuarantineReason::DuplicateSpend,
            status: QuarantineStatus::EvidenceRequested,
            opened_height: DEVNET_HEIGHT + 9,
            expires_height: DEVNET_HEIGHT + DEFAULT_DUPLICATE_QUARANTINE_TTL_BLOCKS,
            duplicate_signal_count: 2,
        };
        state
            .insert_duplicate_quarantine(quarantine)
            .expect("demo quarantine is valid");
        state
    }

    pub fn insert_migration_epoch(
        &mut self,
        epoch: MigrationEpoch,
    ) -> MoneroL2PqPrivateKeyImageMigrationGuardRuntimeResult<()> {
        require(
            self.migration_epochs.len() < MAX_MIGRATION_EPOCHS,
            "migration epoch capacity exceeded",
        )?;
        required("epoch_id", &epoch.epoch_id)?;
        require(
            epoch.start_height < epoch.end_height,
            "epoch start height must be before end height",
        )?;
        require(
            epoch.end_height <= epoch.grace_end_height,
            "epoch grace end must not precede end height",
        )?;
        self.migration_epochs.insert(epoch.epoch_id.clone(), epoch);
        self.refresh();
        Ok(())
    }

    pub fn insert_key_image_commitment(
        &mut self,
        commitment: KeyImageCommitment,
    ) -> MoneroL2PqPrivateKeyImageMigrationGuardRuntimeResult<()> {
        require(
            self.key_image_commitments.len() < MAX_KEY_IMAGE_COMMITMENTS,
            "key image commitment capacity exceeded",
        )?;
        required("commitment_id", &commitment.commitment_id)?;
        required("epoch_id", &commitment.epoch_id)?;
        required("wallet_tag", &commitment.wallet_tag)?;
        required("key_image_tag", &commitment.key_image_tag)?;
        required("nullifier", &commitment.nullifier)?;
        require(
            self.migration_epochs
                .get(&commitment.epoch_id)
                .map(|epoch| epoch.phase.accepts_commitments())
                .unwrap_or(false),
            "commitment epoch is missing or closed",
        )?;
        require(
            commitment.pq_security_bits >= self.config.min_pq_security_bits,
            "commitment pq security bits below minimum",
        )?;
        if !self
            .consumed_commitment_nullifiers
            .insert(commitment.nullifier.clone())
        {
            return Err("commitment nullifier already consumed".to_string());
        }
        if commitment.duplicate_signal_count > 0 {
            self.quarantine_key_image_tags
                .insert(commitment.key_image_tag.clone());
        }
        self.key_image_commitments
            .insert(commitment.commitment_id.clone(), commitment);
        self.refresh();
        Ok(())
    }

    pub fn insert_wallet_attestation(
        &mut self,
        attestation: PqWalletAttestation,
    ) -> MoneroL2PqPrivateKeyImageMigrationGuardRuntimeResult<()> {
        require(
            self.wallet_attestations.len() < MAX_WALLET_ATTESTATIONS,
            "wallet attestation capacity exceeded",
        )?;
        required("attestation_id", &attestation.attestation_id)?;
        required("epoch_id", &attestation.epoch_id)?;
        required("wallet_tag", &attestation.wallet_tag)?;
        require(
            self.migration_epochs.contains_key(&attestation.epoch_id),
            "attestation epoch is missing",
        )?;
        require(
            attestation.quorum_bps <= MAX_BPS,
            "attestation quorum exceeds max bps",
        )?;
        require(
            attestation.pq_security_bits >= self.config.min_pq_security_bits,
            "attestation pq security bits below minimum",
        )?;
        self.wallet_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh();
        Ok(())
    }

    pub fn insert_duplicate_quarantine(
        &mut self,
        quarantine: DuplicateSpendQuarantine,
    ) -> MoneroL2PqPrivateKeyImageMigrationGuardRuntimeResult<()> {
        require(
            self.duplicate_quarantines.len() < MAX_DUPLICATE_QUARANTINES,
            "duplicate quarantine capacity exceeded",
        )?;
        required("quarantine_id", &quarantine.quarantine_id)?;
        required("key_image_tag", &quarantine.key_image_tag)?;
        require(
            quarantine.opened_height < quarantine.expires_height,
            "quarantine must expire after it opens",
        )?;
        self.quarantine_key_image_tags
            .insert(quarantine.key_image_tag.clone());
        self.duplicate_quarantines
            .insert(quarantine.quarantine_id.clone(), quarantine);
        self.refresh();
        Ok(())
    }

    pub fn insert_low_fee_credit(
        &mut self,
        credit: LowFeeMigrationCredit,
    ) -> MoneroL2PqPrivateKeyImageMigrationGuardRuntimeResult<()> {
        require(
            self.low_fee_credits.len() < MAX_LOW_FEE_CREDITS,
            "low fee credit capacity exceeded",
        )?;
        required("credit_id", &credit.credit_id)?;
        required("commitment_id", &credit.commitment_id)?;
        require(
            credit.credit_micro_units <= self.config.low_fee_credit_cap_micro_units,
            "low fee credit exceeds cap",
        )?;
        require(
            credit.reserved_height < credit.expires_height,
            "low fee credit must expire after reservation",
        )?;
        self.low_fee_credits
            .insert(credit.credit_id.clone(), credit);
        self.refresh();
        Ok(())
    }

    pub fn insert_redaction_budget(
        &mut self,
        budget: PrivacyRedactionBudget,
    ) -> MoneroL2PqPrivateKeyImageMigrationGuardRuntimeResult<()> {
        require(
            self.redaction_budgets.len() < MAX_REDACTION_BUDGETS,
            "redaction budget capacity exceeded",
        )?;
        required("budget_id", &budget.budget_id)?;
        required("wallet_tag", &budget.wallet_tag)?;
        require(
            budget.consumed_units <= budget.budget_units,
            "redaction budget consumed units exceed total budget",
        )?;
        require(
            budget.max_budget_bps <= self.config.max_redaction_budget_bps,
            "redaction budget bps exceeds configured maximum",
        )?;
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        self.refresh();
        Ok(())
    }

    pub fn publish_public_roots(
        &mut self,
        record_id: impl Into<String>,
        height: u64,
        published_by_root: impl Into<String>,
    ) -> MoneroL2PqPrivateKeyImageMigrationGuardRuntimeResult<()> {
        require(
            self.public_roots.len() < MAX_PUBLIC_ROOTS,
            "public root journal capacity exceeded",
        )?;
        let record_id = record_id.into();
        required("record_id", &record_id)?;
        let record = PublicRootRecord {
            record_id: record_id.clone(),
            height,
            epoch_root: self.roots.epoch_root.clone(),
            key_image_commitment_root: self.roots.key_image_commitment_root.clone(),
            wallet_attestation_root: self.roots.wallet_attestation_root.clone(),
            duplicate_quarantine_root: self.roots.duplicate_quarantine_root.clone(),
            low_fee_credit_root: self.roots.low_fee_credit_root.clone(),
            redaction_budget_root: self.roots.redaction_budget_root.clone(),
            state_root: self.roots.state_root.clone(),
            published_by_root: published_by_root.into(),
        };
        self.public_roots.insert(record_id, record);
        self.refresh();
        Ok(())
    }

    pub fn refresh(&mut self) {
        self.counters = self.derive_counters();
        self.roots = self.derive_roots();
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-PRIVATE-KEY-IMAGE-MIGRATION-GUARD-STATE",
            &self.public_record_without_state_root(),
        )
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record_without_state_root(),
            "migration_epochs": map_records(&self.migration_epochs, MigrationEpoch::public_record),
            "key_image_commitments": map_records(
                &self.key_image_commitments,
                KeyImageCommitment::public_record
            ),
            "wallet_attestations": map_records(
                &self.wallet_attestations,
                PqWalletAttestation::public_record
            ),
            "duplicate_quarantines": map_records(
                &self.duplicate_quarantines,
                DuplicateSpendQuarantine::public_record
            ),
            "low_fee_credits": map_records(
                &self.low_fee_credits,
                LowFeeMigrationCredit::public_record
            ),
            "redaction_budgets": map_records(
                &self.redaction_budgets,
                PrivacyRedactionBudget::public_record
            ),
            "public_roots": map_records(&self.public_roots, PublicRootRecord::public_record),
            "consumed_commitment_nullifier_root": set_root(
                "MONERO-L2-PQ-PRIVATE-KEY-IMAGE-MIGRATION-GUARD-CONSUMED-NULLIFIERS",
                &self.consumed_commitment_nullifiers
            ),
            "quarantine_key_image_tag_root": set_root(
                "MONERO-L2-PQ-PRIVATE-KEY-IMAGE-MIGRATION-GUARD-QUARANTINE-TAGS",
                &self.quarantine_key_image_tags
            ),
            "privacy_boundary": PRIVACY_BOUNDARY,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        set_json_field(&mut record, "state_root", json!(self.state_root()));
        record
    }

    fn derive_counters(&self) -> Counters {
        let migration_epochs = self.migration_epochs.len() as u64;
        let active_epochs = self
            .migration_epochs
            .values()
            .filter(|epoch| !epoch.phase.terminal())
            .count() as u64;
        let key_image_commitments = self.key_image_commitments.len() as u64;
        let rooted_commitments = self
            .key_image_commitments
            .values()
            .filter(|commitment| {
                matches!(
                    commitment.status,
                    CommitmentStatus::Rooted
                        | CommitmentStatus::Attested
                        | CommitmentStatus::CreditReserved
                        | CommitmentStatus::Migrated
                )
            })
            .count() as u64;
        let migrated_commitments = self
            .key_image_commitments
            .values()
            .filter(|commitment| commitment.status == CommitmentStatus::Migrated)
            .count() as u64;
        let quarantined_commitments = self
            .key_image_commitments
            .values()
            .filter(|commitment| commitment.status == CommitmentStatus::Quarantined)
            .count() as u64;
        let wallet_attestations = self.wallet_attestations.len() as u64;
        let accepted_wallet_attestations = self
            .wallet_attestations
            .values()
            .filter(|attestation| attestation.status.accepted())
            .count() as u64;
        let duplicate_quarantines = self.duplicate_quarantines.len() as u64;
        let active_duplicate_quarantines = self
            .duplicate_quarantines
            .values()
            .filter(|quarantine| quarantine.status.active())
            .count() as u64;
        let low_fee_credits = self.low_fee_credits.len() as u64;
        let open_low_fee_credits = self
            .low_fee_credits
            .values()
            .filter(|credit| credit.status.open())
            .count() as u64;
        let applied_low_fee_credits = self
            .low_fee_credits
            .values()
            .filter(|credit| credit.status == CreditStatus::Applied)
            .count() as u64;
        let redaction_budgets = self.redaction_budgets.len() as u64;
        let exhausted_redaction_budgets = self
            .redaction_budgets
            .values()
            .filter(|budget| budget.status == RedactionStatus::Exhausted)
            .count() as u64;
        let total_credit_micro_units = self
            .low_fee_credits
            .values()
            .map(|credit| credit.credit_micro_units)
            .sum();
        let applied_credit_micro_units = self
            .low_fee_credits
            .values()
            .filter(|credit| credit.status == CreditStatus::Applied)
            .map(|credit| credit.credit_micro_units)
            .sum();
        let redacted_fields = self
            .redaction_budgets
            .values()
            .map(|budget| budget.redacted_fields)
            .sum();
        let redaction_budget_units = self
            .redaction_budgets
            .values()
            .map(|budget| budget.budget_units)
            .sum();
        let duplicate_spend_signals = self
            .key_image_commitments
            .values()
            .map(|commitment| u64::from(commitment.duplicate_signal_count))
            .sum::<u64>()
            + self
                .duplicate_quarantines
                .values()
                .map(|quarantine| u64::from(quarantine.duplicate_signal_count))
                .sum::<u64>();
        Counters {
            migration_epochs,
            active_epochs,
            key_image_commitments,
            rooted_commitments,
            migrated_commitments,
            quarantined_commitments,
            wallet_attestations,
            accepted_wallet_attestations,
            duplicate_quarantines,
            active_duplicate_quarantines,
            low_fee_credits,
            open_low_fee_credits,
            applied_low_fee_credits,
            redaction_budgets,
            exhausted_redaction_budgets,
            public_roots: self.public_roots.len() as u64,
            total_credit_micro_units,
            applied_credit_micro_units,
            redacted_fields,
            redaction_budget_units,
            duplicate_spend_signals,
        }
    }

    fn derive_roots(&self) -> Roots {
        let mut roots = Roots {
            config_root: self.config.config_root(),
            epoch_root: map_root(
                "MONERO-L2-PQ-PRIVATE-KEY-IMAGE-MIGRATION-GUARD-EPOCHS",
                &self.migration_epochs,
                MigrationEpoch::public_record,
            ),
            key_image_commitment_root: map_root(
                "MONERO-L2-PQ-PRIVATE-KEY-IMAGE-MIGRATION-GUARD-COMMITMENTS",
                &self.key_image_commitments,
                KeyImageCommitment::public_record,
            ),
            wallet_attestation_root: map_root(
                "MONERO-L2-PQ-PRIVATE-KEY-IMAGE-MIGRATION-GUARD-WALLET-ATTESTATIONS",
                &self.wallet_attestations,
                PqWalletAttestation::public_record,
            ),
            duplicate_quarantine_root: map_root(
                "MONERO-L2-PQ-PRIVATE-KEY-IMAGE-MIGRATION-GUARD-DUPLICATE-QUARANTINES",
                &self.duplicate_quarantines,
                DuplicateSpendQuarantine::public_record,
            ),
            low_fee_credit_root: map_root(
                "MONERO-L2-PQ-PRIVATE-KEY-IMAGE-MIGRATION-GUARD-LOW-FEE-CREDITS",
                &self.low_fee_credits,
                LowFeeMigrationCredit::public_record,
            ),
            redaction_budget_root: map_root(
                "MONERO-L2-PQ-PRIVATE-KEY-IMAGE-MIGRATION-GUARD-REDACTION-BUDGETS",
                &self.redaction_budgets,
                PrivacyRedactionBudget::public_record,
            ),
            public_root_journal_root: map_root(
                "MONERO-L2-PQ-PRIVATE-KEY-IMAGE-MIGRATION-GUARD-PUBLIC-ROOTS",
                &self.public_roots,
                PublicRootRecord::public_record,
            ),
            consumed_commitment_nullifier_root: set_root(
                "MONERO-L2-PQ-PRIVATE-KEY-IMAGE-MIGRATION-GUARD-CONSUMED-NULLIFIERS",
                &self.consumed_commitment_nullifiers,
            ),
            quarantine_key_image_tag_root: set_root(
                "MONERO-L2-PQ-PRIVATE-KEY-IMAGE-MIGRATION-GUARD-QUARANTINE-TAGS",
                &self.quarantine_key_image_tags,
            ),
            deterministic_public_record_root: empty_root("deterministic_public_record"),
            state_root: empty_root("state"),
        };
        roots.deterministic_public_record_root = record_root(
            "MONERO-L2-PQ-PRIVATE-KEY-IMAGE-MIGRATION-GUARD-DETERMINISTIC-PUBLIC-RECORD",
            &json!({
                "config_root": roots.config_root,
                "epoch_root": roots.epoch_root,
                "key_image_commitment_root": roots.key_image_commitment_root,
                "wallet_attestation_root": roots.wallet_attestation_root,
                "duplicate_quarantine_root": roots.duplicate_quarantine_root,
                "low_fee_credit_root": roots.low_fee_credit_root,
                "redaction_budget_root": roots.redaction_budget_root,
                "public_root_journal_root": roots.public_root_journal_root,
                "consumed_commitment_nullifier_root": roots.consumed_commitment_nullifier_root,
                "quarantine_key_image_tag_root": roots.quarantine_key_image_tag_root,
            }),
        );
        roots.state_root = roots.roots_root();
        roots
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

fn map_records<T, F>(map: &BTreeMap<String, T>, public_record: F) -> Value
where
    F: Fn(&T) -> Value,
{
    let records = map
        .iter()
        .map(|(key, value)| (key.clone(), public_record(value)))
        .collect::<serde_json::Map<_, _>>();
    Value::Object(records)
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "record": public_record(value),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn sample_root(label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-KEY-IMAGE-MIGRATION-GUARD-SAMPLE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

fn empty_root(label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-KEY-IMAGE-MIGRATION-GUARD-EMPTY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn required(field: &str, value: &str) -> MoneroL2PqPrivateKeyImageMigrationGuardRuntimeResult<()> {
    require(!value.trim().is_empty(), &format!("{field} is required"))
}

fn require(
    condition: bool,
    message: &str,
) -> MoneroL2PqPrivateKeyImageMigrationGuardRuntimeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn set_json_field(record: &mut Value, key: &str, value: Value) {
    if let Value::Object(fields) = record {
        fields.insert(key.to_string(), value);
    }
}
