use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialHybridKeyImageNullifierVaultRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_HYBRID_KEY_IMAGE_NULLIFIER_VAULT_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-hybrid-key-image-nullifier-vault-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_HYBRID_KEY_IMAGE_NULLIFIER_VAULT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const HYBRID_NULLIFIER_SUITE: &str =
    "ringct-seraphis-hybrid-key-image-nullifier-commitment-root-v1";
pub const SEALED_BUCKET_SUITE: &str = "sealed-nullifier-bucket-operator-safe-root-v1";
pub const PQ_NULLIFIER_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-nullifier-attestation-v1";
pub const DUPLICATE_SPEND_QUARANTINE_SUITE: &str =
    "hybrid-key-image-duplicate-spend-quarantine-root-v1";
pub const WITHDRAWAL_PROOF_SUITE: &str = "confidential-nullifier-withdrawal-proof-root-v1";
pub const WALLET_MIGRATION_EPOCH_SUITE: &str = "ringct-seraphis-wallet-migration-epoch-root-v1";
pub const LOW_FEE_BATCH_VERIFICATION_SUITE: &str =
    "low-fee-hybrid-nullifier-batch-verification-root-v1";
pub const REDACTION_BUDGET_SUITE: &str = "nullifier-vault-redaction-budget-root-v1";
pub const PUBLIC_RECORD_SUITE: &str = "public-hybrid-key-image-nullifier-vault-record-v1";
pub const PUBLIC_ROOT_SUITE: &str = "public-hybrid-key-image-nullifier-vault-roots-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_key_images_addresses_amounts_view_keys_spend_keys_or_linkage_graphs";
pub const DEVNET_L2_HEIGHT: u64 = 1_926_400;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_744_000;
pub const DEVNET_EPOCH: u64 = 4_096;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_BUCKET_ANONYMITY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_ANONYMITY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_EPOCH_TTL_BLOCKS: u64 = 43_200;
pub const DEFAULT_BUCKET_SEAL_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 960;
pub const DEFAULT_WITHDRAWAL_PROOF_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 4_320;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 25_000;
pub const DEFAULT_MAX_REDACTION_UNITS_PER_WALLET: u64 = 64;
pub const DEFAULT_LOW_FEE_BATCH_TARGET: usize = 512;
pub const DEFAULT_LOW_FEE_BATCH_LIMIT: usize = 8_192;
pub const DEFAULT_MAX_VERIFICATION_FEE_BPS: u64 = 10;
pub const DEFAULT_BATCH_REBATE_BPS: u64 = 7;
pub const MAX_MIGRATION_EPOCHS: usize = 2_097_152;
pub const MAX_SEALED_BUCKETS: usize = 8_388_608;
pub const MAX_NULLIFIER_COMMITMENTS: usize = 16_777_216;
pub const MAX_ATTESTATIONS: usize = 8_388_608;
pub const MAX_QUARANTINES: usize = 2_097_152;
pub const MAX_WITHDRAWAL_PROOFS: usize = 4_194_304;
pub const MAX_BATCH_VERIFICATIONS: usize = 1_048_576;
pub const MAX_REDACTION_BUDGETS: usize = 2_097_152;
pub const MAX_PUBLIC_RECORDS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationPhase {
    Planned,
    PrivacyPrimed,
    RingCtIntake,
    SeraphisBridgeOpen,
    BucketSealing,
    Active,
    WithdrawalOnly,
    Enforced,
    Complete,
    Paused,
    Revoked,
}

impl MigrationPhase {
    pub fn accepts_nullifiers(self) -> bool {
        matches!(
            self,
            Self::PrivacyPrimed
                | Self::RingCtIntake
                | Self::SeraphisBridgeOpen
                | Self::BucketSealing
                | Self::Active
        )
    }

    pub fn accepts_withdrawals(self) -> bool {
        matches!(
            self,
            Self::SeraphisBridgeOpen | Self::Active | Self::WithdrawalOnly | Self::Enforced
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::PrivacyPrimed => "privacy_primed",
            Self::RingCtIntake => "ringct_intake",
            Self::SeraphisBridgeOpen => "seraphis_bridge_open",
            Self::BucketSealing => "bucket_sealing",
            Self::Active => "active",
            Self::WithdrawalOnly => "withdrawal_only",
            Self::Enforced => "enforced",
            Self::Complete => "complete",
            Self::Paused => "paused",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NullifierFamily {
    LegacyRingCtKeyImage,
    SeraphisNullifier,
    HybridRingCtSeraphis,
    BridgeWithdrawal,
    WalletRecovery,
    ExchangeMigration,
    CustodyMigration,
}

impl NullifierFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LegacyRingCtKeyImage => "legacy_ringct_key_image",
            Self::SeraphisNullifier => "seraphis_nullifier",
            Self::HybridRingCtSeraphis => "hybrid_ringct_seraphis",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::WalletRecovery => "wallet_recovery",
            Self::ExchangeMigration => "exchange_migration",
            Self::CustodyMigration => "custody_migration",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketStatus {
    Open,
    Sealing,
    Sealed,
    Attested,
    WithdrawalEnabled,
    Quarantined,
    Retired,
    Revoked,
}

impl BucketStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Sealing | Self::Sealed | Self::Attested | Self::WithdrawalEnabled
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealing => "sealing",
            Self::Sealed => "sealed",
            Self::Attested => "attested",
            Self::WithdrawalEnabled => "withdrawal_enabled",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NullifierStatus {
    Submitted,
    Bucketed,
    Attested,
    WithdrawalProven,
    Spent,
    Quarantined,
    Redacted,
    Rejected,
    Expired,
}

impl NullifierStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::Bucketed | Self::Attested | Self::WithdrawalProven
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Bucketed => "bucketed",
            Self::Attested => "attested",
            Self::WithdrawalProven => "withdrawal_proven",
            Self::Spent => "spent",
            Self::Quarantined => "quarantined",
            Self::Redacted => "redacted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Quorum,
    StrongQuorum,
    Superseded,
    Revoked,
    Rejected,
    Expired,
}

impl AttestationStatus {
    pub fn accepted(self) -> bool {
        matches!(self, Self::Quorum | Self::StrongQuorum)
    }

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
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    DuplicateSpend,
    ConflictingBucketRoot,
    ReorgReplay,
    WithdrawalReplay,
    AttestationMismatch,
    RedactionBudgetExceeded,
    OperatorDispute,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DuplicateSpend => "duplicate_spend",
            Self::ConflictingBucketRoot => "conflicting_bucket_root",
            Self::ReorgReplay => "reorg_replay",
            Self::WithdrawalReplay => "withdrawal_replay",
            Self::AttestationMismatch => "attestation_mismatch",
            Self::RedactionBudgetExceeded => "redaction_budget_exceeded",
            Self::OperatorDispute => "operator_dispute",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordStatus {
    Open,
    Accepted,
    Applied,
    Quarantined,
    Exhausted,
    Expired,
}

impl RecordStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Accepted => "accepted",
            Self::Applied => "applied",
            Self::Quarantined => "quarantined",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub schema_version: u64,
    pub protocol_version: String,
    pub chain_id: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub hash_suite: String,
    pub hybrid_nullifier_suite: String,
    pub sealed_bucket_suite: String,
    pub pq_nullifier_attestation_suite: String,
    pub duplicate_spend_quarantine_suite: String,
    pub withdrawal_proof_suite: String,
    pub wallet_migration_epoch_suite: String,
    pub low_fee_batch_verification_suite: String,
    pub redaction_budget_suite: String,
    pub public_record_suite: String,
    pub privacy_boundary: String,
    pub min_pq_security_bits: u16,
    pub min_bucket_anonymity_set_size: u64,
    pub batch_anonymity_set_size: u64,
    pub epoch_ttl_blocks: u64,
    pub bucket_seal_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub withdrawal_proof_ttl_blocks: u64,
    pub quarantine_ttl_blocks: u64,
    pub redaction_budget_units: u64,
    pub max_redaction_units_per_wallet: u64,
    pub low_fee_batch_target: usize,
    pub low_fee_batch_limit: usize,
    pub max_verification_fee_bps: u64,
    pub batch_rebate_bps: u64,
    pub operator_set_root: String,
    pub wallet_manifest_root: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            hash_suite: HASH_SUITE.to_string(),
            hybrid_nullifier_suite: HYBRID_NULLIFIER_SUITE.to_string(),
            sealed_bucket_suite: SEALED_BUCKET_SUITE.to_string(),
            pq_nullifier_attestation_suite: PQ_NULLIFIER_ATTESTATION_SUITE.to_string(),
            duplicate_spend_quarantine_suite: DUPLICATE_SPEND_QUARANTINE_SUITE.to_string(),
            withdrawal_proof_suite: WITHDRAWAL_PROOF_SUITE.to_string(),
            wallet_migration_epoch_suite: WALLET_MIGRATION_EPOCH_SUITE.to_string(),
            low_fee_batch_verification_suite: LOW_FEE_BATCH_VERIFICATION_SUITE.to_string(),
            redaction_budget_suite: REDACTION_BUDGET_SUITE.to_string(),
            public_record_suite: PUBLIC_RECORD_SUITE.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_bucket_anonymity_set_size: DEFAULT_MIN_BUCKET_ANONYMITY_SET_SIZE,
            batch_anonymity_set_size: DEFAULT_BATCH_ANONYMITY_SET_SIZE,
            epoch_ttl_blocks: DEFAULT_EPOCH_TTL_BLOCKS,
            bucket_seal_ttl_blocks: DEFAULT_BUCKET_SEAL_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            withdrawal_proof_ttl_blocks: DEFAULT_WITHDRAWAL_PROOF_TTL_BLOCKS,
            quarantine_ttl_blocks: DEFAULT_QUARANTINE_TTL_BLOCKS,
            redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
            max_redaction_units_per_wallet: DEFAULT_MAX_REDACTION_UNITS_PER_WALLET,
            low_fee_batch_target: DEFAULT_LOW_FEE_BATCH_TARGET,
            low_fee_batch_limit: DEFAULT_LOW_FEE_BATCH_LIMIT,
            max_verification_fee_bps: DEFAULT_MAX_VERIFICATION_FEE_BPS,
            batch_rebate_bps: DEFAULT_BATCH_REBATE_BPS,
            operator_set_root: fixed_root("devnet-nullifier-vault-operator-set"),
            wallet_manifest_root: fixed_root("devnet-ringct-seraphis-wallet-manifest"),
        }
    }

    pub fn validate(&self) -> Result<()> {
        require(self.chain_id == CHAIN_ID, "config chain id mismatch")?;
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "config protocol version mismatch",
        )?;
        require(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security below vault policy",
        )?;
        require(
            self.batch_anonymity_set_size >= self.min_bucket_anonymity_set_size,
            "batch anonymity set below bucket minimum",
        )?;
        require(
            self.low_fee_batch_target <= self.low_fee_batch_limit,
            "low fee batch target above limit",
        )?;
        require(
            self.max_verification_fee_bps <= MAX_BPS,
            "verification fee above bps range",
        )?;
        require(
            self.batch_rebate_bps <= self.max_verification_fee_bps,
            "rebate above fee cap",
        )?;
        require(
            self.max_redaction_units_per_wallet <= self.redaction_budget_units,
            "wallet redaction cap above global budget",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "schema_version": self.schema_version,
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "hash_suite": self.hash_suite,
            "hybrid_nullifier_suite": self.hybrid_nullifier_suite,
            "sealed_bucket_suite": self.sealed_bucket_suite,
            "pq_nullifier_attestation_suite": self.pq_nullifier_attestation_suite,
            "duplicate_spend_quarantine_suite": self.duplicate_spend_quarantine_suite,
            "withdrawal_proof_suite": self.withdrawal_proof_suite,
            "wallet_migration_epoch_suite": self.wallet_migration_epoch_suite,
            "low_fee_batch_verification_suite": self.low_fee_batch_verification_suite,
            "redaction_budget_suite": self.redaction_budget_suite,
            "public_record_suite": self.public_record_suite,
            "privacy_boundary": self.privacy_boundary,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_bucket_anonymity_set_size": self.min_bucket_anonymity_set_size,
            "batch_anonymity_set_size": self.batch_anonymity_set_size,
            "epoch_ttl_blocks": self.epoch_ttl_blocks,
            "bucket_seal_ttl_blocks": self.bucket_seal_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "withdrawal_proof_ttl_blocks": self.withdrawal_proof_ttl_blocks,
            "quarantine_ttl_blocks": self.quarantine_ttl_blocks,
            "redaction_budget_units": self.redaction_budget_units,
            "max_redaction_units_per_wallet": self.max_redaction_units_per_wallet,
            "low_fee_batch_target": self.low_fee_batch_target,
            "low_fee_batch_limit": self.low_fee_batch_limit,
            "max_verification_fee_bps": self.max_verification_fee_bps,
            "batch_rebate_bps": self.batch_rebate_bps,
            "operator_set_root": self.operator_set_root,
            "wallet_manifest_root": self.wallet_manifest_root,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub migration_epochs: u64,
    pub sealed_buckets: u64,
    pub live_buckets: u64,
    pub nullifier_commitments: u64,
    pub live_nullifiers: u64,
    pub pq_nullifier_attestations: u64,
    pub accepted_attestations: u64,
    pub duplicate_spend_quarantines: u64,
    pub active_quarantines: u64,
    pub withdrawal_proofs: u64,
    pub accepted_withdrawal_proofs: u64,
    pub low_fee_batch_verifications: u64,
    pub verified_batch_items: u64,
    pub redaction_budgets: u64,
    pub exhausted_redaction_budgets: u64,
    pub deterministic_public_records: u64,
    pub redaction_units_consumed: u64,
    pub duplicate_spend_signals: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletMigrationEpoch {
    pub epoch_id: String,
    pub epoch_index: u64,
    pub phase: MigrationPhase,
    pub start_height: u64,
    pub seal_height: u64,
    pub withdrawal_start_height: u64,
    pub expires_height: u64,
    pub ringct_root: String,
    pub seraphis_root: String,
    pub wallet_manifest_root: String,
    pub previous_epoch_root: String,
    pub operator_notes_root: String,
}

impl WalletMigrationEpoch {
    pub fn public_record(&self) -> Value {
        json!({
            "epoch_id": self.epoch_id,
            "epoch_index": self.epoch_index,
            "phase": self.phase.as_str(),
            "start_height": self.start_height,
            "seal_height": self.seal_height,
            "withdrawal_start_height": self.withdrawal_start_height,
            "expires_height": self.expires_height,
            "ringct_root": self.ringct_root,
            "seraphis_root": self.seraphis_root,
            "wallet_manifest_root": self.wallet_manifest_root,
            "previous_epoch_root": self.previous_epoch_root,
            "operator_notes_root": self.operator_notes_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedNullifierBucket {
    pub bucket_id: String,
    pub epoch_id: String,
    pub family: NullifierFamily,
    pub status: BucketStatus,
    pub bucket_tag: String,
    pub sealed_nullifier_root: String,
    pub encrypted_witness_root: String,
    pub decoy_context_root: String,
    pub withdrawal_gate_root: String,
    pub anonymity_set_size: u64,
    pub nullifier_count: u64,
    pub sealed_height: u64,
    pub expires_height: u64,
}

impl SealedNullifierBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "epoch_id": self.epoch_id,
            "family": self.family.as_str(),
            "status": self.status.as_str(),
            "bucket_tag": self.bucket_tag,
            "sealed_nullifier_root": self.sealed_nullifier_root,
            "encrypted_witness_root": self.encrypted_witness_root,
            "decoy_context_root": self.decoy_context_root,
            "withdrawal_gate_root": self.withdrawal_gate_root,
            "anonymity_set_size": self.anonymity_set_size,
            "nullifier_count": self.nullifier_count,
            "sealed_height": self.sealed_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HybridNullifierCommitment {
    pub commitment_id: String,
    pub epoch_id: String,
    pub bucket_id: String,
    pub wallet_tag: String,
    pub nullifier_tag: String,
    pub family: NullifierFamily,
    pub commitment_root: String,
    pub hybrid_key_image_root: String,
    pub seraphis_nullifier_root: String,
    pub redaction_receipt_root: String,
    pub status: NullifierStatus,
    pub pq_security_bits: u16,
    pub batch_index: u64,
    pub observed_height: u64,
    pub expires_height: u64,
    pub duplicate_signal_count: u64,
}

impl HybridNullifierCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "epoch_id": self.epoch_id,
            "bucket_id": self.bucket_id,
            "wallet_tag": self.wallet_tag,
            "nullifier_tag": self.nullifier_tag,
            "family": self.family.as_str(),
            "commitment_root": self.commitment_root,
            "hybrid_key_image_root": self.hybrid_key_image_root,
            "seraphis_nullifier_root": self.seraphis_nullifier_root,
            "redaction_receipt_root": self.redaction_receipt_root,
            "status": self.status.as_str(),
            "pq_security_bits": self.pq_security_bits,
            "batch_index": self.batch_index,
            "observed_height": self.observed_height,
            "expires_height": self.expires_height,
            "duplicate_signal_count": self.duplicate_signal_count,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqNullifierAttestation {
    pub attestation_id: String,
    pub epoch_id: String,
    pub bucket_id: String,
    pub attested_nullifier_root: String,
    pub pq_public_key_root: String,
    pub signature_root: String,
    pub verifier_policy_root: String,
    pub status: AttestationStatus,
    pub signer_count: u64,
    pub quorum_bps: u64,
    pub pq_security_bits: u16,
    pub submitted_height: u64,
    pub expires_height: u64,
}

impl PqNullifierAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "epoch_id": self.epoch_id,
            "bucket_id": self.bucket_id,
            "attested_nullifier_root": self.attested_nullifier_root,
            "pq_public_key_root": self.pq_public_key_root,
            "signature_root": self.signature_root,
            "verifier_policy_root": self.verifier_policy_root,
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
    pub bucket_id: String,
    pub nullifier_tag: String,
    pub reason: QuarantineReason,
    pub status: RecordStatus,
    pub evidence_root: String,
    pub challenger_root: String,
    pub duplicate_signal_count: u64,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl DuplicateSpendQuarantine {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "epoch_id": self.epoch_id,
            "bucket_id": self.bucket_id,
            "nullifier_tag": self.nullifier_tag,
            "reason": self.reason.as_str(),
            "status": self.status.as_str(),
            "evidence_root": self.evidence_root,
            "challenger_root": self.challenger_root,
            "duplicate_signal_count": self.duplicate_signal_count,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WithdrawalProof {
    pub proof_id: String,
    pub epoch_id: String,
    pub bucket_id: String,
    pub withdrawal_tag: String,
    pub nullifier_commitment_root: String,
    pub destination_commitment_root: String,
    pub proof_root: String,
    pub status: RecordStatus,
    pub fee_bps: u64,
    pub submitted_height: u64,
    pub expires_height: u64,
}

impl WithdrawalProof {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "epoch_id": self.epoch_id,
            "bucket_id": self.bucket_id,
            "withdrawal_tag": self.withdrawal_tag,
            "nullifier_commitment_root": self.nullifier_commitment_root,
            "destination_commitment_root": self.destination_commitment_root,
            "proof_root": self.proof_root,
            "status": self.status.as_str(),
            "fee_bps": self.fee_bps,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeBatchVerification {
    pub batch_id: String,
    pub epoch_id: String,
    pub batch_root: String,
    pub verifier_root: String,
    pub status: RecordStatus,
    pub item_count: u64,
    pub accepted_count: u64,
    pub fee_bps: u64,
    pub rebate_bps: u64,
    pub submitted_height: u64,
}

impl LowFeeBatchVerification {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "epoch_id": self.epoch_id,
            "batch_root": self.batch_root,
            "verifier_root": self.verifier_root,
            "status": self.status.as_str(),
            "item_count": self.item_count,
            "accepted_count": self.accepted_count,
            "fee_bps": self.fee_bps,
            "rebate_bps": self.rebate_bps,
            "submitted_height": self.submitted_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub epoch_id: String,
    pub wallet_tag: String,
    pub policy_root: String,
    pub status: RecordStatus,
    pub budget_units: u64,
    pub consumed_units: u64,
    pub redacted_fields: u64,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl RedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "epoch_id": self.epoch_id,
            "wallet_tag": self.wallet_tag,
            "policy_root": self.policy_root,
            "status": self.status.as_str(),
            "budget_units": self.budget_units,
            "consumed_units": self.consumed_units,
            "redacted_fields": self.redacted_fields,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicRecord {
    pub record_id: String,
    pub epoch_id: String,
    pub record_root: String,
    pub roots_root: String,
    pub status: RecordStatus,
    pub published_height: u64,
}

impl PublicRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "epoch_id": self.epoch_id,
            "record_root": self.record_root,
            "roots_root": self.roots_root,
            "status": self.status.as_str(),
            "published_height": self.published_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub wallet_migration_epochs_root: String,
    pub sealed_nullifier_buckets_root: String,
    pub hybrid_nullifier_commitments_root: String,
    pub pq_nullifier_attestations_root: String,
    pub duplicate_spend_quarantines_root: String,
    pub withdrawal_proofs_root: String,
    pub low_fee_batch_verifications_root: String,
    pub redaction_budgets_root: String,
    pub public_records_root: String,
    pub quarantined_nullifier_tags_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub wallet_migration_epochs: BTreeMap<String, WalletMigrationEpoch>,
    pub sealed_nullifier_buckets: BTreeMap<String, SealedNullifierBucket>,
    pub hybrid_nullifier_commitments: BTreeMap<String, HybridNullifierCommitment>,
    pub pq_nullifier_attestations: BTreeMap<String, PqNullifierAttestation>,
    pub duplicate_spend_quarantines: BTreeMap<String, DuplicateSpendQuarantine>,
    pub withdrawal_proofs: BTreeMap<String, WithdrawalProof>,
    pub low_fee_batch_verifications: BTreeMap<String, LowFeeBatchVerification>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub public_records: BTreeMap<String, PublicRecord>,
    pub quarantined_nullifier_tags: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            wallet_migration_epochs: BTreeMap::new(),
            sealed_nullifier_buckets: BTreeMap::new(),
            hybrid_nullifier_commitments: BTreeMap::new(),
            pq_nullifier_attestations: BTreeMap::new(),
            duplicate_spend_quarantines: BTreeMap::new(),
            withdrawal_proofs: BTreeMap::new(),
            low_fee_batch_verifications: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            public_records: BTreeMap::new(),
            quarantined_nullifier_tags: BTreeSet::new(),
        })
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("devnet config is valid");
        let epoch = WalletMigrationEpoch {
            epoch_id: "wallet-migration-epoch-devnet-004096".to_string(),
            epoch_index: DEVNET_EPOCH,
            phase: MigrationPhase::Active,
            start_height: DEVNET_L2_HEIGHT,
            seal_height: DEVNET_L2_HEIGHT + 72,
            withdrawal_start_height: DEVNET_L2_HEIGHT + 144,
            expires_height: DEVNET_L2_HEIGHT + state.config.epoch_ttl_blocks,
            ringct_root: fixed_root("devnet-ringct-key-image-set"),
            seraphis_root: fixed_root("devnet-seraphis-nullifier-set"),
            wallet_manifest_root: state.config.wallet_manifest_root.clone(),
            previous_epoch_root: fixed_root("devnet-previous-nullifier-vault-epoch"),
            operator_notes_root: fixed_root("devnet-operator-notes"),
        };
        state
            .insert_epoch(epoch.clone())
            .expect("valid devnet epoch");

        let bucket = SealedNullifierBucket {
            bucket_id: "sealed-nullifier-bucket-devnet-ringct-001".to_string(),
            epoch_id: epoch.epoch_id.clone(),
            family: NullifierFamily::HybridRingCtSeraphis,
            status: BucketStatus::Attested,
            bucket_tag: "bucket-tag-devnet-hybrid-001-redacted".to_string(),
            sealed_nullifier_root: fixed_root("devnet-sealed-nullifier-bucket-001"),
            encrypted_witness_root: fixed_root("devnet-encrypted-nullifier-witnesses-001"),
            decoy_context_root: fixed_root("devnet-ring-decoy-context-001"),
            withdrawal_gate_root: fixed_root("devnet-withdrawal-gate-001"),
            anonymity_set_size: state.config.batch_anonymity_set_size,
            nullifier_count: 512,
            sealed_height: DEVNET_L2_HEIGHT + 80,
            expires_height: DEVNET_L2_HEIGHT + state.config.bucket_seal_ttl_blocks,
        };
        state
            .insert_bucket(bucket.clone())
            .expect("valid devnet bucket");

        let budget = RedactionBudget {
            budget_id: "redaction-budget-devnet-wallet-001".to_string(),
            epoch_id: epoch.epoch_id.clone(),
            wallet_tag: "wallet-tag-devnet-001-redacted".to_string(),
            policy_root: fixed_root("devnet-redaction-policy-001"),
            status: RecordStatus::Open,
            budget_units: state.config.redaction_budget_units,
            consumed_units: 48,
            redacted_fields: 8,
            opened_height: DEVNET_L2_HEIGHT,
            expires_height: DEVNET_L2_HEIGHT + state.config.epoch_ttl_blocks,
        };
        state
            .insert_redaction_budget(budget)
            .expect("valid devnet budget");

        let commitment = HybridNullifierCommitment {
            commitment_id: "hybrid-nullifier-commitment-devnet-001".to_string(),
            epoch_id: epoch.epoch_id.clone(),
            bucket_id: bucket.bucket_id.clone(),
            wallet_tag: "wallet-tag-devnet-001-redacted".to_string(),
            nullifier_tag: "nullifier-tag-devnet-001-redacted".to_string(),
            family: NullifierFamily::HybridRingCtSeraphis,
            commitment_root: fixed_root("devnet-hybrid-nullifier-commitment-001"),
            hybrid_key_image_root: fixed_root("devnet-hybrid-key-image-root-001"),
            seraphis_nullifier_root: fixed_root("devnet-seraphis-nullifier-root-001"),
            redaction_receipt_root: fixed_root("devnet-redaction-receipt-001"),
            status: NullifierStatus::Attested,
            pq_security_bits: state.config.min_pq_security_bits,
            batch_index: 0,
            observed_height: DEVNET_L2_HEIGHT + 84,
            expires_height: DEVNET_L2_HEIGHT + state.config.epoch_ttl_blocks,
            duplicate_signal_count: 0,
        };
        state
            .insert_nullifier_commitment(commitment)
            .expect("valid devnet commitment");

        let attestation = PqNullifierAttestation {
            attestation_id: "pq-nullifier-attestation-devnet-001".to_string(),
            epoch_id: epoch.epoch_id.clone(),
            bucket_id: bucket.bucket_id.clone(),
            attested_nullifier_root: bucket.sealed_nullifier_root.clone(),
            pq_public_key_root: fixed_root("devnet-pq-nullifier-public-keys-001"),
            signature_root: fixed_root("devnet-pq-nullifier-signatures-001"),
            verifier_policy_root: fixed_root("devnet-pq-nullifier-verifier-policy-001"),
            status: AttestationStatus::StrongQuorum,
            signer_count: 7,
            quorum_bps: 8_000,
            pq_security_bits: state.config.min_pq_security_bits,
            submitted_height: DEVNET_L2_HEIGHT + 90,
            expires_height: DEVNET_L2_HEIGHT + state.config.attestation_ttl_blocks,
        };
        state
            .insert_attestation(attestation)
            .expect("valid devnet attestation");

        let proof = WithdrawalProof {
            proof_id: "withdrawal-proof-devnet-001".to_string(),
            epoch_id: epoch.epoch_id.clone(),
            bucket_id: bucket.bucket_id.clone(),
            withdrawal_tag: "withdrawal-tag-devnet-001-redacted".to_string(),
            nullifier_commitment_root: fixed_root("devnet-withdrawal-nullifier-commitment-001"),
            destination_commitment_root: fixed_root("devnet-withdrawal-destination-001"),
            proof_root: fixed_root("devnet-withdrawal-proof-001"),
            status: RecordStatus::Accepted,
            fee_bps: 6,
            submitted_height: DEVNET_L2_HEIGHT + 160,
            expires_height: DEVNET_L2_HEIGHT + state.config.withdrawal_proof_ttl_blocks,
        };
        state
            .insert_withdrawal_proof(proof)
            .expect("valid devnet withdrawal proof");

        let batch = LowFeeBatchVerification {
            batch_id: "low-fee-nullifier-batch-devnet-001".to_string(),
            epoch_id: epoch.epoch_id.clone(),
            batch_root: fixed_root("devnet-low-fee-nullifier-batch-001"),
            verifier_root: fixed_root("devnet-low-fee-verifier-set-001"),
            status: RecordStatus::Accepted,
            item_count: 512,
            accepted_count: 511,
            fee_bps: state.config.max_verification_fee_bps,
            rebate_bps: state.config.batch_rebate_bps,
            submitted_height: DEVNET_L2_HEIGHT + 170,
        };
        state
            .insert_batch_verification(batch)
            .expect("valid devnet batch");

        let quarantine = DuplicateSpendQuarantine {
            quarantine_id: "duplicate-quarantine-devnet-001".to_string(),
            epoch_id: epoch.epoch_id.clone(),
            bucket_id: bucket.bucket_id.clone(),
            nullifier_tag: "nullifier-tag-devnet-quarantine-001-redacted".to_string(),
            reason: QuarantineReason::DuplicateSpend,
            status: RecordStatus::Open,
            evidence_root: fixed_root("devnet-duplicate-spend-evidence-001"),
            challenger_root: fixed_root("devnet-watchtower-challenger-001"),
            duplicate_signal_count: 2,
            opened_height: DEVNET_L2_HEIGHT + 180,
            expires_height: DEVNET_L2_HEIGHT + state.config.quarantine_ttl_blocks,
        };
        state
            .insert_quarantine(quarantine)
            .expect("valid devnet quarantine");

        let roots = state.roots();
        let public_record = PublicRecord {
            record_id: "public-nullifier-vault-record-devnet-001".to_string(),
            epoch_id: epoch.epoch_id,
            record_root: record_root(PUBLIC_RECORD_SUITE, &state.public_record_without_records()),
            roots_root: record_root(PUBLIC_ROOT_SUITE, &roots.public_record()),
            status: RecordStatus::Accepted,
            published_height: DEVNET_L2_HEIGHT + 216,
        };
        state
            .insert_public_record(public_record)
            .expect("valid devnet public record");
        state
    }

    pub fn demo() -> Self {
        Self::devnet()
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: record_root("CONFIG", &self.config.public_record()),
            counters_root: record_root("COUNTERS", &self.counters.public_record()),
            wallet_migration_epochs_root: map_root(
                "WALLET-MIGRATION-EPOCHS",
                &self.wallet_migration_epochs,
                WalletMigrationEpoch::public_record,
            ),
            sealed_nullifier_buckets_root: map_root(
                "SEALED-NULLIFIER-BUCKETS",
                &self.sealed_nullifier_buckets,
                SealedNullifierBucket::public_record,
            ),
            hybrid_nullifier_commitments_root: map_root(
                "HYBRID-NULLIFIER-COMMITMENTS",
                &self.hybrid_nullifier_commitments,
                HybridNullifierCommitment::public_record,
            ),
            pq_nullifier_attestations_root: map_root(
                "PQ-NULLIFIER-ATTESTATIONS",
                &self.pq_nullifier_attestations,
                PqNullifierAttestation::public_record,
            ),
            duplicate_spend_quarantines_root: map_root(
                "DUPLICATE-SPEND-QUARANTINES",
                &self.duplicate_spend_quarantines,
                DuplicateSpendQuarantine::public_record,
            ),
            withdrawal_proofs_root: map_root(
                "WITHDRAWAL-PROOFS",
                &self.withdrawal_proofs,
                WithdrawalProof::public_record,
            ),
            low_fee_batch_verifications_root: map_root(
                "LOW-FEE-BATCH-VERIFICATIONS",
                &self.low_fee_batch_verifications,
                LowFeeBatchVerification::public_record,
            ),
            redaction_budgets_root: map_root(
                "REDACTION-BUDGETS",
                &self.redaction_budgets,
                RedactionBudget::public_record,
            ),
            public_records_root: map_root(
                "PUBLIC-RECORDS",
                &self.public_records,
                PublicRecord::public_record,
            ),
            quarantined_nullifier_tags_root: set_root(
                "QUARANTINED-NULLIFIER-TAGS",
                &self.quarantined_nullifier_tags,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_records();
        if let Value::Object(ref mut object) = record {
            object.insert(
                "public_records".to_string(),
                map_records(&self.public_records, PublicRecord::public_record),
            );
        }
        record
    }

    pub fn public_record_without_records(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
            "wallet_migration_epochs": map_records(
                &self.wallet_migration_epochs,
                WalletMigrationEpoch::public_record
            ),
            "sealed_nullifier_buckets": map_records(
                &self.sealed_nullifier_buckets,
                SealedNullifierBucket::public_record
            ),
            "hybrid_nullifier_commitments": map_records(
                &self.hybrid_nullifier_commitments,
                HybridNullifierCommitment::public_record
            ),
            "pq_nullifier_attestations": map_records(
                &self.pq_nullifier_attestations,
                PqNullifierAttestation::public_record
            ),
            "duplicate_spend_quarantines": map_records(
                &self.duplicate_spend_quarantines,
                DuplicateSpendQuarantine::public_record
            ),
            "withdrawal_proofs": map_records(&self.withdrawal_proofs, WithdrawalProof::public_record),
            "low_fee_batch_verifications": map_records(
                &self.low_fee_batch_verifications,
                LowFeeBatchVerification::public_record
            ),
            "redaction_budgets": map_records(&self.redaction_budgets, RedactionBudget::public_record),
            "quarantined_nullifier_tags_root": set_root(
                "PUBLIC-QUARANTINED-NULLIFIER-TAGS",
                &self.quarantined_nullifier_tags
            ),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("STATE", &self.public_record())
    }

    pub fn insert_epoch(&mut self, epoch: WalletMigrationEpoch) -> Result<()> {
        require(
            self.wallet_migration_epochs.len() < MAX_MIGRATION_EPOCHS,
            "too many migration epochs",
        )?;
        require(
            epoch.phase.accepts_nullifiers() || epoch.phase.accepts_withdrawals(),
            "epoch phase cannot admit vault activity",
        )?;
        self.wallet_migration_epochs
            .insert(epoch.epoch_id.clone(), epoch);
        self.refresh_counters();
        Ok(())
    }

    pub fn insert_bucket(&mut self, bucket: SealedNullifierBucket) -> Result<()> {
        require(
            self.sealed_nullifier_buckets.len() < MAX_SEALED_BUCKETS,
            "too many sealed nullifier buckets",
        )?;
        require(
            self.wallet_migration_epochs.contains_key(&bucket.epoch_id),
            "unknown bucket epoch",
        )?;
        require(
            bucket.anonymity_set_size >= self.config.min_bucket_anonymity_set_size,
            "bucket anonymity set below minimum",
        )?;
        self.sealed_nullifier_buckets
            .insert(bucket.bucket_id.clone(), bucket);
        self.refresh_counters();
        Ok(())
    }

    pub fn insert_nullifier_commitment(
        &mut self,
        commitment: HybridNullifierCommitment,
    ) -> Result<()> {
        require(
            self.hybrid_nullifier_commitments.len() < MAX_NULLIFIER_COMMITMENTS,
            "too many nullifier commitments",
        )?;
        require(
            self.sealed_nullifier_buckets
                .contains_key(&commitment.bucket_id),
            "unknown nullifier bucket",
        )?;
        require(
            commitment.pq_security_bits >= self.config.min_pq_security_bits,
            "nullifier pq security below minimum",
        )?;
        self.hybrid_nullifier_commitments
            .insert(commitment.commitment_id.clone(), commitment);
        self.refresh_counters();
        Ok(())
    }

    pub fn insert_attestation(&mut self, attestation: PqNullifierAttestation) -> Result<()> {
        require(
            self.pq_nullifier_attestations.len() < MAX_ATTESTATIONS,
            "too many pq nullifier attestations",
        )?;
        require(
            self.sealed_nullifier_buckets
                .contains_key(&attestation.bucket_id),
            "unknown attestation bucket",
        )?;
        require(
            attestation.quorum_bps <= MAX_BPS,
            "attestation quorum above bps range",
        )?;
        require(
            attestation.pq_security_bits >= self.config.min_pq_security_bits,
            "attestation pq security below minimum",
        )?;
        self.pq_nullifier_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_counters();
        Ok(())
    }

    pub fn insert_quarantine(&mut self, quarantine: DuplicateSpendQuarantine) -> Result<()> {
        require(
            self.duplicate_spend_quarantines.len() < MAX_QUARANTINES,
            "too many duplicate spend quarantines",
        )?;
        self.quarantined_nullifier_tags
            .insert(quarantine.nullifier_tag.clone());
        self.duplicate_spend_quarantines
            .insert(quarantine.quarantine_id.clone(), quarantine);
        self.refresh_counters();
        Ok(())
    }

    pub fn insert_withdrawal_proof(&mut self, proof: WithdrawalProof) -> Result<()> {
        require(
            self.withdrawal_proofs.len() < MAX_WITHDRAWAL_PROOFS,
            "too many withdrawal proofs",
        )?;
        require(
            proof.fee_bps <= self.config.max_verification_fee_bps,
            "withdrawal proof fee above configured cap",
        )?;
        self.withdrawal_proofs.insert(proof.proof_id.clone(), proof);
        self.refresh_counters();
        Ok(())
    }

    pub fn insert_batch_verification(&mut self, batch: LowFeeBatchVerification) -> Result<()> {
        require(
            self.low_fee_batch_verifications.len() < MAX_BATCH_VERIFICATIONS,
            "too many low fee batch verifications",
        )?;
        require(
            batch.fee_bps <= self.config.max_verification_fee_bps,
            "batch fee above cap",
        )?;
        require(batch.rebate_bps <= batch.fee_bps, "batch rebate above fee")?;
        require(
            batch.item_count as usize <= self.config.low_fee_batch_limit,
            "batch item count above limit",
        )?;
        self.low_fee_batch_verifications
            .insert(batch.batch_id.clone(), batch);
        self.refresh_counters();
        Ok(())
    }

    pub fn insert_redaction_budget(&mut self, budget: RedactionBudget) -> Result<()> {
        require(
            self.redaction_budgets.len() < MAX_REDACTION_BUDGETS,
            "too many redaction budgets",
        )?;
        require(
            budget.consumed_units <= budget.budget_units,
            "redaction budget over consumed",
        )?;
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        self.refresh_counters();
        Ok(())
    }

    pub fn insert_public_record(&mut self, public_record: PublicRecord) -> Result<()> {
        require(
            self.public_records.len() < MAX_PUBLIC_RECORDS,
            "too many public records",
        )?;
        self.public_records
            .insert(public_record.record_id.clone(), public_record);
        self.refresh_counters();
        Ok(())
    }

    fn refresh_counters(&mut self) {
        self.counters = Counters {
            migration_epochs: self.wallet_migration_epochs.len() as u64,
            sealed_buckets: self.sealed_nullifier_buckets.len() as u64,
            live_buckets: self
                .sealed_nullifier_buckets
                .values()
                .filter(|bucket| bucket.status.live())
                .count() as u64,
            nullifier_commitments: self.hybrid_nullifier_commitments.len() as u64,
            live_nullifiers: self
                .hybrid_nullifier_commitments
                .values()
                .filter(|commitment| commitment.status.live())
                .count() as u64,
            pq_nullifier_attestations: self.pq_nullifier_attestations.len() as u64,
            accepted_attestations: self
                .pq_nullifier_attestations
                .values()
                .filter(|attestation| attestation.status.accepted())
                .count() as u64,
            duplicate_spend_quarantines: self.duplicate_spend_quarantines.len() as u64,
            active_quarantines: self
                .duplicate_spend_quarantines
                .values()
                .filter(|quarantine| quarantine.status == RecordStatus::Open)
                .count() as u64,
            withdrawal_proofs: self.withdrawal_proofs.len() as u64,
            accepted_withdrawal_proofs: self
                .withdrawal_proofs
                .values()
                .filter(|proof| proof.status == RecordStatus::Accepted)
                .count() as u64,
            low_fee_batch_verifications: self.low_fee_batch_verifications.len() as u64,
            verified_batch_items: self
                .low_fee_batch_verifications
                .values()
                .map(|batch| batch.accepted_count)
                .sum(),
            redaction_budgets: self.redaction_budgets.len() as u64,
            exhausted_redaction_budgets: self
                .redaction_budgets
                .values()
                .filter(|budget| budget.status == RecordStatus::Exhausted)
                .count() as u64,
            deterministic_public_records: self.public_records.len() as u64,
            redaction_units_consumed: self
                .redaction_budgets
                .values()
                .map(|budget| budget.consumed_units)
                .sum(),
            duplicate_spend_signals: self
                .duplicate_spend_quarantines
                .values()
                .map(|quarantine| quarantine.duplicate_signal_count)
                .sum::<u64>()
                + self
                    .hybrid_nullifier_commitments
                    .values()
                    .map(|commitment| commitment.duplicate_signal_count)
                    .sum::<u64>(),
        };
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

pub fn fixed_root(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-HYBRID-KEY-IMAGE-NULLIFIER-VAULT-FIXED",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn deterministic_id(prefix: &str, parts: &[&str]) -> String {
    let root = domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-HYBRID-KEY-IMAGE-NULLIFIER-VAULT-ID",
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
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-HYBRID-KEY-IMAGE-NULLIFIER-VAULT-{domain}"),
        &leaves,
    )
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
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-HYBRID-KEY-IMAGE-NULLIFIER-VAULT-{domain}"),
        &leaves,
    )
}

pub fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-HYBRID-KEY-IMAGE-NULLIFIER-VAULT-{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
