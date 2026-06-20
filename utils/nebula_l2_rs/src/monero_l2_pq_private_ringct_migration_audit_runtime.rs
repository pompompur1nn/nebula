use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PqPrivateRingctMigrationAuditRuntimeResult<T> = Result<T, String>;

pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-ringct-migration-audit-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_PROTOCOL_VERSION;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEVNET_HEIGHT: u64 = 760_000;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEVNET_MONERO_NETWORK: &str =
    "monero-devnet";
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEVNET_L2_NETWORK: &str =
    "nebula-devnet";
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEVNET_ASSET_ID: &str =
    "wxmr-ringct-migration-devnet";
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_RINGCT_AUDIT_SCHEME: &str =
    "ringct-migration-audit-roots-only-v1";
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DECOY_SET_SCHEME: &str =
    "monero-decoy-preservation-bucket-root-v1";
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_VIEW_TAG_SCHEME: &str =
    "view-tag-leakage-budget-check-v1";
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_STEALTH_ROTATION_SCHEME: &str =
    "stealth-address-rotation-commitment-root-v1";
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_SUBADDRESS_SCHEME: &str =
    "subaddress-migration-summary-root-v1";
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_WITHDRAWAL_FLOOR_SCHEME: &str =
    "bridge-withdrawal-privacy-floor-v1";
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_PQ_ATTESTATION_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-192f-auditor-attestation-v1";
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_OPERATOR_SUMMARY_SCHEME: &str =
    "redacted-operator-privacy-summary-v1";
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_LOW_FEE_BATCH_SCHEME: &str =
    "low-fee-ringct-proof-batching-v1";
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_addresses_amounts_view_keys_key_images_or_recipient_graphs";
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEFAULT_MIN_RING_SIZE: u64 = 16;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEFAULT_MIN_DECOY_SET_SIZE: u64 = 128;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEFAULT_MIN_OUTPUT_AGE_BUCKETS: u64 =
    8;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEFAULT_VIEW_TAG_BUDGET_BPS: u64 = 35;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEFAULT_MIN_WITHDRAWAL_FLOOR: u64 =
    4_096;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 =
    192;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEFAULT_STRONG_QUORUM_BPS: u64 =
    8_000;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEFAULT_MAX_LOW_FEE_BATCH_WEIGHT:
    u64 = 2_048;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEFAULT_LOW_FEE_MAX_BPS: u64 = 8;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEFAULT_ROTATION_EPOCH_BLOCKS: u64 =
    720;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEFAULT_ATTESTATION_TTL_BLOCKS: u64 =
    72;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_BPS: u64 = 10_000;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_AUDITS: usize = 524_288;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_DECOY_SETS: usize = 524_288;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_VIEW_TAG_CHECKS: usize = 524_288;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_ROTATIONS: usize = 524_288;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_AGE_BUCKETS: usize = 131_072;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_SUBADDRESS_SUMMARIES: usize =
    524_288;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_WITHDRAWAL_FLOORS: usize =
    262_144;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_ATTESTATIONS: usize = 524_288;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_OPERATOR_SUMMARIES: usize =
    262_144;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_PROOF_BATCHES: usize = 524_288;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationPhase {
    Planned,
    Intake,
    DecoyPreservation,
    RingctProofBatching,
    AuditorAttestation,
    WithdrawalReady,
    Complete,
    Paused,
    Rejected,
}

impl MigrationPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Intake => "intake",
            Self::DecoyPreservation => "decoy_preservation",
            Self::RingctProofBatching => "ringct_proof_batching",
            Self::AuditorAttestation => "auditor_attestation",
            Self::WithdrawalReady => "withdrawal_ready",
            Self::Complete => "complete",
            Self::Paused => "paused",
            Self::Rejected => "rejected",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Rejected)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    Open,
    PrivacyChecked,
    NeedsMoreDecoys,
    NeedsRotation,
    Attested,
    RedactedForOperator,
    Finalized,
    Rejected,
}

impl AuditStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::PrivacyChecked => "privacy_checked",
            Self::NeedsMoreDecoys => "needs_more_decoys",
            Self::NeedsRotation => "needs_rotation",
            Self::Attested => "attested",
            Self::RedactedForOperator => "redacted_for_operator",
            Self::Finalized => "finalized",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeakageSeverity {
    None,
    Watch,
    Elevated,
    Critical,
}

impl LeakageSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Watch => "watch",
            Self::Elevated => "elevated",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationStatus {
    Proposed,
    ProofAccepted,
    Queued,
    Active,
    Superseded,
    Rejected,
}

impl RotationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::ProofAccepted => "proof_accepted",
            Self::Queued => "queued",
            Self::Active => "active",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Quorum,
    StrongQuorum,
    Expired,
    Revoked,
    Rejected,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Quorum => "quorum",
            Self::StrongQuorum => "strong_quorum",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofBatchStatus {
    Open,
    Sealed,
    Verified,
    Subsidized,
    Published,
    Rejected,
}

impl ProofBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Verified => "verified",
            Self::Subsidized => "subsidized",
            Self::Published => "published",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub monero_network: String,
    pub l2_network: String,
    pub asset_id: String,
    pub genesis_height: u64,
    pub min_ring_size: u64,
    pub min_decoy_set_size: u64,
    pub min_output_age_buckets: u64,
    pub view_tag_leakage_budget_bps: u64,
    pub min_withdrawal_privacy_floor: u64,
    pub min_pq_security_bits: u16,
    pub quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub max_low_fee_batch_weight: u64,
    pub low_fee_max_bps: u64,
    pub rotation_epoch_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub ringct_audit_scheme: String,
    pub decoy_set_scheme: String,
    pub view_tag_scheme: String,
    pub stealth_rotation_scheme: String,
    pub subaddress_scheme: String,
    pub withdrawal_floor_scheme: String,
    pub pq_attestation_scheme: String,
    pub operator_summary_scheme: String,
    pub low_fee_batch_scheme: String,
    pub hash_suite: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_SCHEMA_VERSION,
            monero_network:
                MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEVNET_MONERO_NETWORK
                    .to_string(),
            l2_network: MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEVNET_L2_NETWORK
                .to_string(),
            asset_id: MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEVNET_ASSET_ID
                .to_string(),
            genesis_height: MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEVNET_HEIGHT,
            min_ring_size:
                MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEFAULT_MIN_RING_SIZE,
            min_decoy_set_size:
                MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEFAULT_MIN_DECOY_SET_SIZE,
            min_output_age_buckets:
                MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEFAULT_MIN_OUTPUT_AGE_BUCKETS,
            view_tag_leakage_budget_bps:
                MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEFAULT_VIEW_TAG_BUDGET_BPS,
            min_withdrawal_privacy_floor:
                MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEFAULT_MIN_WITHDRAWAL_FLOOR,
            min_pq_security_bits:
                MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            quorum_bps: MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEFAULT_QUORUM_BPS,
            strong_quorum_bps:
                MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEFAULT_STRONG_QUORUM_BPS,
            max_low_fee_batch_weight:
                MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEFAULT_MAX_LOW_FEE_BATCH_WEIGHT,
            low_fee_max_bps:
                MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEFAULT_LOW_FEE_MAX_BPS,
            rotation_epoch_blocks:
                MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEFAULT_ROTATION_EPOCH_BLOCKS,
            attestation_ttl_blocks:
                MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEFAULT_ATTESTATION_TTL_BLOCKS,
            ringct_audit_scheme:
                MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_RINGCT_AUDIT_SCHEME.to_string(),
            decoy_set_scheme: MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DECOY_SET_SCHEME
                .to_string(),
            view_tag_scheme: MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_VIEW_TAG_SCHEME
                .to_string(),
            stealth_rotation_scheme:
                MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_STEALTH_ROTATION_SCHEME
                    .to_string(),
            subaddress_scheme:
                MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_SUBADDRESS_SCHEME.to_string(),
            withdrawal_floor_scheme:
                MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_WITHDRAWAL_FLOOR_SCHEME
                    .to_string(),
            pq_attestation_scheme:
                MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_PQ_ATTESTATION_SCHEME
                    .to_string(),
            operator_summary_scheme:
                MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_OPERATOR_SUMMARY_SCHEME
                    .to_string(),
            low_fee_batch_scheme:
                MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_LOW_FEE_BATCH_SCHEME.to_string(),
            hash_suite: MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_HASH_SUITE.to_string(),
        }
    }

    pub fn validate(&self) -> MoneroL2PqPrivateRingctMigrationAuditRuntimeResult<()> {
        required("chain_id", &self.chain_id)?;
        required("protocol_version", &self.protocol_version)?;
        required("monero_network", &self.monero_network)?;
        required("l2_network", &self.l2_network)?;
        required("asset_id", &self.asset_id)?;
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol_version mismatch",
        )?;
        require(
            self.schema_version
                == MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_SCHEMA_VERSION,
            "schema_version mismatch",
        )?;
        require(
            self.min_ring_size >= 11,
            "min_ring_size below Monero privacy floor",
        )?;
        require(
            self.min_decoy_set_size >= self.min_ring_size,
            "min_decoy_set_size must cover min_ring_size",
        )?;
        require(
            self.min_output_age_buckets > 0,
            "min_output_age_buckets is required",
        )?;
        require(
            self.view_tag_leakage_budget_bps
                <= MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_BPS,
            "view_tag_leakage_budget_bps exceeds max bps",
        )?;
        require(
            self.min_withdrawal_privacy_floor >= self.min_decoy_set_size,
            "withdrawal floor must be at least decoy set floor",
        )?;
        require(
            self.quorum_bps <= MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_BPS,
            "quorum_bps exceeds max bps",
        )?;
        require(
            self.strong_quorum_bps >= self.quorum_bps,
            "strong_quorum_bps must be at least quorum_bps",
        )?;
        require(
            self.strong_quorum_bps <= MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_BPS,
            "strong_quorum_bps exceeds max bps",
        )?;
        require(
            self.min_pq_security_bits
                >= MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            "min_pq_security_bits too low",
        )?;
        require(
            self.max_low_fee_batch_weight > 0,
            "max_low_fee_batch_weight is required",
        )?;
        require(
            self.low_fee_max_bps <= self.view_tag_leakage_budget_bps,
            "low fee bps must remain below leakage budget bps",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub audits_opened: u64,
    pub audits_finalized: u64,
    pub audits_rejected: u64,
    pub decoy_sets_recorded: u64,
    pub view_tag_checks_recorded: u64,
    pub rotations_recorded: u64,
    pub age_buckets_recorded: u64,
    pub subaddress_summaries_recorded: u64,
    pub withdrawal_floors_recorded: u64,
    pub attestations_recorded: u64,
    pub operator_summaries_recorded: u64,
    pub low_fee_batches_recorded: u64,
    pub leakage_alerts: u64,
    pub privacy_floor_violations: u64,
    pub redactions_applied: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-COUNTERS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub audit_root: String,
    pub decoy_set_root: String,
    pub view_tag_check_root: String,
    pub stealth_rotation_root: String,
    pub output_age_bucket_root: String,
    pub subaddress_summary_root: String,
    pub withdrawal_floor_root: String,
    pub pq_attestation_root: String,
    pub operator_summary_root: String,
    pub low_fee_batch_root: String,
    pub known_nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-ROOTS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationAuditRequest {
    pub audit_id: String,
    pub migration_id: String,
    pub ringct_commitment_root: String,
    pub input_key_image_root: String,
    pub output_commitment_root: String,
    pub encrypted_note_manifest_root: String,
    pub migration_epoch: u64,
    pub monero_height: u64,
    pub l2_height: u64,
    pub candidate_output_count: u64,
    pub candidate_ring_count: u64,
    pub min_observed_ring_size: u64,
    pub output_age_bucket_root: String,
    pub subaddress_summary_root: String,
    pub operator_redaction_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationAuditRecord {
    pub audit_id: String,
    pub migration_id: String,
    pub ringct_commitment_root: String,
    pub input_key_image_root: String,
    pub output_commitment_root: String,
    pub encrypted_note_manifest_root: String,
    pub migration_epoch: u64,
    pub monero_height: u64,
    pub l2_height: u64,
    pub candidate_output_count: u64,
    pub candidate_ring_count: u64,
    pub min_observed_ring_size: u64,
    pub output_age_bucket_root: String,
    pub subaddress_summary_root: String,
    pub operator_redaction_root: String,
    pub phase: MigrationPhase,
    pub status: AuditStatus,
    pub privacy_floor_passed: bool,
    pub leakage_severity: LeakageSeverity,
    pub attestation_root: String,
}

impl MigrationAuditRecord {
    pub fn from_request(
        request: MigrationAuditRequest,
        config: &Config,
    ) -> MoneroL2PqPrivateRingctMigrationAuditRuntimeResult<Self> {
        required("audit_id", &request.audit_id)?;
        required("migration_id", &request.migration_id)?;
        required("ringct_commitment_root", &request.ringct_commitment_root)?;
        required("input_key_image_root", &request.input_key_image_root)?;
        required("output_commitment_root", &request.output_commitment_root)?;
        required(
            "encrypted_note_manifest_root",
            &request.encrypted_note_manifest_root,
        )?;
        require(
            request.candidate_output_count >= config.min_decoy_set_size,
            "candidate_output_count below decoy set floor",
        )?;
        require(
            request.min_observed_ring_size >= config.min_ring_size,
            "min_observed_ring_size below ring floor",
        )?;
        require(
            request.candidate_ring_count > 0,
            "candidate_ring_count is required",
        )?;
        Ok(Self {
            audit_id: request.audit_id,
            migration_id: request.migration_id,
            ringct_commitment_root: request.ringct_commitment_root,
            input_key_image_root: request.input_key_image_root,
            output_commitment_root: request.output_commitment_root,
            encrypted_note_manifest_root: request.encrypted_note_manifest_root,
            migration_epoch: request.migration_epoch,
            monero_height: request.monero_height,
            l2_height: request.l2_height,
            candidate_output_count: request.candidate_output_count,
            candidate_ring_count: request.candidate_ring_count,
            min_observed_ring_size: request.min_observed_ring_size,
            output_age_bucket_root: request.output_age_bucket_root,
            subaddress_summary_root: request.subaddress_summary_root,
            operator_redaction_root: request.operator_redaction_root,
            phase: MigrationPhase::Intake,
            status: AuditStatus::Open,
            privacy_floor_passed: true,
            leakage_severity: LeakageSeverity::None,
            attestation_root: empty_root("AUDIT-ATTESTATION"),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "audit_id": self.audit_id,
            "migration_id": self.migration_id,
            "ringct_commitment_root": self.ringct_commitment_root,
            "input_key_image_root": self.input_key_image_root,
            "output_commitment_root": self.output_commitment_root,
            "encrypted_note_manifest_root": self.encrypted_note_manifest_root,
            "migration_epoch": self.migration_epoch,
            "monero_height": self.monero_height,
            "l2_height": self.l2_height,
            "candidate_output_count": self.candidate_output_count,
            "candidate_ring_count": self.candidate_ring_count,
            "min_observed_ring_size": self.min_observed_ring_size,
            "output_age_bucket_root": self.output_age_bucket_root,
            "subaddress_summary_root": self.subaddress_summary_root,
            "operator_redaction_root": self.operator_redaction_root,
            "phase": self.phase.as_str(),
            "status": self.status.as_str(),
            "privacy_floor_passed": self.privacy_floor_passed,
            "leakage_severity": self.leakage_severity.as_str(),
            "attestation_root": self.attestation_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-RECORD",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecoySetRequest {
    pub decoy_set_id: String,
    pub audit_id: String,
    pub selection_algorithm: String,
    pub decoy_output_root: String,
    pub real_output_mask_root: String,
    pub age_distribution_root: String,
    pub amount_commitment_class_root: String,
    pub preserve_monero_distribution: bool,
    pub output_count: u64,
    pub ring_count: u64,
    pub min_ring_size: u64,
    pub median_age_bucket: u64,
    pub newest_output_lag_blocks: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecoySetRecord {
    pub decoy_set_id: String,
    pub audit_id: String,
    pub selection_algorithm: String,
    pub decoy_output_root: String,
    pub real_output_mask_root: String,
    pub age_distribution_root: String,
    pub amount_commitment_class_root: String,
    pub preserve_monero_distribution: bool,
    pub output_count: u64,
    pub ring_count: u64,
    pub min_ring_size: u64,
    pub median_age_bucket: u64,
    pub newest_output_lag_blocks: u64,
    pub preservation_score_bps: u64,
    pub accepted: bool,
}

impl DecoySetRecord {
    pub fn from_request(
        request: DecoySetRequest,
        config: &Config,
    ) -> MoneroL2PqPrivateRingctMigrationAuditRuntimeResult<Self> {
        required("decoy_set_id", &request.decoy_set_id)?;
        required("audit_id", &request.audit_id)?;
        required("selection_algorithm", &request.selection_algorithm)?;
        required("decoy_output_root", &request.decoy_output_root)?;
        require(
            request.output_count >= config.min_decoy_set_size,
            "decoy output count below floor",
        )?;
        require(
            request.min_ring_size >= config.min_ring_size,
            "decoy ring size below floor",
        )?;
        require(request.ring_count > 0, "ring_count is required")?;
        let score = preservation_score_bps(
            request.output_count,
            request.min_ring_size,
            config.min_decoy_set_size,
            config.min_ring_size,
            request.preserve_monero_distribution,
        );
        Ok(Self {
            decoy_set_id: request.decoy_set_id,
            audit_id: request.audit_id,
            selection_algorithm: request.selection_algorithm,
            decoy_output_root: request.decoy_output_root,
            real_output_mask_root: request.real_output_mask_root,
            age_distribution_root: request.age_distribution_root,
            amount_commitment_class_root: request.amount_commitment_class_root,
            preserve_monero_distribution: request.preserve_monero_distribution,
            output_count: request.output_count,
            ring_count: request.ring_count,
            min_ring_size: request.min_ring_size,
            median_age_bucket: request.median_age_bucket,
            newest_output_lag_blocks: request.newest_output_lag_blocks,
            preservation_score_bps: score,
            accepted: score >= config.quorum_bps,
        })
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-DECOY-SET",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewTagLeakageCheckRequest {
    pub check_id: String,
    pub audit_id: String,
    pub view_tag_histogram_root: String,
    pub scan_pattern_root: String,
    pub wallet_cluster_hint_root: String,
    pub sampled_output_count: u64,
    pub distinct_view_tag_count: u64,
    pub max_single_tag_bps: u64,
    pub repeated_scan_prefix_bps: u64,
    pub cross_subaddress_correlation_bps: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewTagLeakageCheckRecord {
    pub check_id: String,
    pub audit_id: String,
    pub view_tag_histogram_root: String,
    pub scan_pattern_root: String,
    pub wallet_cluster_hint_root: String,
    pub sampled_output_count: u64,
    pub distinct_view_tag_count: u64,
    pub max_single_tag_bps: u64,
    pub repeated_scan_prefix_bps: u64,
    pub cross_subaddress_correlation_bps: u64,
    pub leakage_budget_bps: u64,
    pub severity: LeakageSeverity,
    pub accepted: bool,
}

impl ViewTagLeakageCheckRecord {
    pub fn from_request(
        request: ViewTagLeakageCheckRequest,
        config: &Config,
    ) -> MoneroL2PqPrivateRingctMigrationAuditRuntimeResult<Self> {
        required("check_id", &request.check_id)?;
        required("audit_id", &request.audit_id)?;
        required("view_tag_histogram_root", &request.view_tag_histogram_root)?;
        require(
            request.sampled_output_count >= config.min_decoy_set_size,
            "sampled_output_count below floor",
        )?;
        require(
            request.distinct_view_tag_count > 0,
            "distinct_view_tag_count is required",
        )?;
        let observed = request
            .max_single_tag_bps
            .max(request.repeated_scan_prefix_bps)
            .max(request.cross_subaddress_correlation_bps);
        let severity = leakage_severity(observed, config.view_tag_leakage_budget_bps);
        Ok(Self {
            check_id: request.check_id,
            audit_id: request.audit_id,
            view_tag_histogram_root: request.view_tag_histogram_root,
            scan_pattern_root: request.scan_pattern_root,
            wallet_cluster_hint_root: request.wallet_cluster_hint_root,
            sampled_output_count: request.sampled_output_count,
            distinct_view_tag_count: request.distinct_view_tag_count,
            max_single_tag_bps: request.max_single_tag_bps,
            repeated_scan_prefix_bps: request.repeated_scan_prefix_bps,
            cross_subaddress_correlation_bps: request.cross_subaddress_correlation_bps,
            leakage_budget_bps: config.view_tag_leakage_budget_bps,
            severity,
            accepted: matches!(severity, LeakageSeverity::None | LeakageSeverity::Watch),
        })
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-VIEW-TAG-CHECK",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StealthAddressRotationRequest {
    pub rotation_id: String,
    pub audit_id: String,
    pub rotation_epoch: u64,
    pub prior_stealth_address_root: String,
    pub next_stealth_address_root: String,
    pub rotation_proof_root: String,
    pub subaddress_domain_root: String,
    pub rotated_output_count: u64,
    pub retained_decoy_count: u64,
    pub linkability_budget_bps: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StealthAddressRotationRecord {
    pub rotation_id: String,
    pub audit_id: String,
    pub rotation_epoch: u64,
    pub prior_stealth_address_root: String,
    pub next_stealth_address_root: String,
    pub rotation_proof_root: String,
    pub subaddress_domain_root: String,
    pub rotated_output_count: u64,
    pub retained_decoy_count: u64,
    pub linkability_budget_bps: u64,
    pub status: RotationStatus,
    pub accepted: bool,
}

impl StealthAddressRotationRecord {
    pub fn from_request(
        request: StealthAddressRotationRequest,
        config: &Config,
    ) -> MoneroL2PqPrivateRingctMigrationAuditRuntimeResult<Self> {
        required("rotation_id", &request.rotation_id)?;
        required("audit_id", &request.audit_id)?;
        required(
            "prior_stealth_address_root",
            &request.prior_stealth_address_root,
        )?;
        required(
            "next_stealth_address_root",
            &request.next_stealth_address_root,
        )?;
        required("rotation_proof_root", &request.rotation_proof_root)?;
        require(
            request.rotated_output_count > 0,
            "rotated_output_count is required",
        )?;
        require(
            request.retained_decoy_count >= config.min_decoy_set_size,
            "retained decoy count below floor",
        )?;
        let accepted = request.linkability_budget_bps <= config.view_tag_leakage_budget_bps;
        Ok(Self {
            rotation_id: request.rotation_id,
            audit_id: request.audit_id,
            rotation_epoch: request.rotation_epoch,
            prior_stealth_address_root: request.prior_stealth_address_root,
            next_stealth_address_root: request.next_stealth_address_root,
            rotation_proof_root: request.rotation_proof_root,
            subaddress_domain_root: request.subaddress_domain_root,
            rotated_output_count: request.rotated_output_count,
            retained_decoy_count: request.retained_decoy_count,
            linkability_budget_bps: request.linkability_budget_bps,
            status: if accepted {
                RotationStatus::ProofAccepted
            } else {
                RotationStatus::Rejected
            },
            accepted,
        })
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-STEALTH-ROTATION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputAgeBucketRequest {
    pub bucket_id: String,
    pub audit_id: String,
    pub bucket_label: String,
    pub min_age_blocks: u64,
    pub max_age_blocks: u64,
    pub output_count: u64,
    pub decoy_count: u64,
    pub ring_member_count: u64,
    pub bucket_commitment_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputAgeBucketRecord {
    pub bucket_id: String,
    pub audit_id: String,
    pub bucket_label: String,
    pub min_age_blocks: u64,
    pub max_age_blocks: u64,
    pub output_count: u64,
    pub decoy_count: u64,
    pub ring_member_count: u64,
    pub bucket_commitment_root: String,
    pub density_bps: u64,
    pub accepted: bool,
}

impl OutputAgeBucketRecord {
    pub fn from_request(
        request: OutputAgeBucketRequest,
        config: &Config,
    ) -> MoneroL2PqPrivateRingctMigrationAuditRuntimeResult<Self> {
        required("bucket_id", &request.bucket_id)?;
        required("audit_id", &request.audit_id)?;
        required("bucket_label", &request.bucket_label)?;
        required("bucket_commitment_root", &request.bucket_commitment_root)?;
        require(
            request.max_age_blocks >= request.min_age_blocks,
            "max_age_blocks must be at least min_age_blocks",
        )?;
        require(request.output_count > 0, "output_count is required")?;
        let density = ratio_bps(request.decoy_count, request.output_count);
        Ok(Self {
            bucket_id: request.bucket_id,
            audit_id: request.audit_id,
            bucket_label: request.bucket_label,
            min_age_blocks: request.min_age_blocks,
            max_age_blocks: request.max_age_blocks,
            output_count: request.output_count,
            decoy_count: request.decoy_count,
            ring_member_count: request.ring_member_count,
            bucket_commitment_root: request.bucket_commitment_root,
            density_bps: density,
            accepted: request.ring_member_count >= config.min_ring_size,
        })
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-OUTPUT-AGE-BUCKET",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubaddressMigrationSummaryRequest {
    pub summary_id: String,
    pub audit_id: String,
    pub subaddress_domain_root: String,
    pub encrypted_mapping_root: String,
    pub account_bucket_root: String,
    pub spend_authorization_root: String,
    pub migrated_subaddress_count: u64,
    pub rotated_subaddress_count: u64,
    pub max_outputs_per_subaddress: u64,
    pub split_strategy: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubaddressMigrationSummaryRecord {
    pub summary_id: String,
    pub audit_id: String,
    pub subaddress_domain_root: String,
    pub encrypted_mapping_root: String,
    pub account_bucket_root: String,
    pub spend_authorization_root: String,
    pub migrated_subaddress_count: u64,
    pub rotated_subaddress_count: u64,
    pub max_outputs_per_subaddress: u64,
    pub split_strategy: String,
    pub rotation_ratio_bps: u64,
    pub accepted: bool,
}

impl SubaddressMigrationSummaryRecord {
    pub fn from_request(
        request: SubaddressMigrationSummaryRequest,
    ) -> MoneroL2PqPrivateRingctMigrationAuditRuntimeResult<Self> {
        required("summary_id", &request.summary_id)?;
        required("audit_id", &request.audit_id)?;
        required("subaddress_domain_root", &request.subaddress_domain_root)?;
        required("encrypted_mapping_root", &request.encrypted_mapping_root)?;
        required("split_strategy", &request.split_strategy)?;
        require(
            request.migrated_subaddress_count > 0,
            "migrated_subaddress_count is required",
        )?;
        let rotation_ratio = ratio_bps(
            request.rotated_subaddress_count,
            request.migrated_subaddress_count,
        );
        Ok(Self {
            summary_id: request.summary_id,
            audit_id: request.audit_id,
            subaddress_domain_root: request.subaddress_domain_root,
            encrypted_mapping_root: request.encrypted_mapping_root,
            account_bucket_root: request.account_bucket_root,
            spend_authorization_root: request.spend_authorization_root,
            migrated_subaddress_count: request.migrated_subaddress_count,
            rotated_subaddress_count: request.rotated_subaddress_count,
            max_outputs_per_subaddress: request.max_outputs_per_subaddress,
            split_strategy: request.split_strategy,
            rotation_ratio_bps: rotation_ratio,
            accepted: request.rotated_subaddress_count <= request.migrated_subaddress_count,
        })
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-SUBADDRESS-SUMMARY",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeWithdrawalPrivacyFloorRequest {
    pub floor_id: String,
    pub audit_id: String,
    pub withdrawal_epoch: u64,
    pub recipient_bucket_root: String,
    pub withdrawal_amount_bucket_root: String,
    pub withdrawal_output_root: String,
    pub withdrawal_count: u64,
    pub anonymity_set_size: u64,
    pub min_decoy_outputs: u64,
    pub delayed_release_blocks: u64,
    pub fee_bps: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeWithdrawalPrivacyFloorRecord {
    pub floor_id: String,
    pub audit_id: String,
    pub withdrawal_epoch: u64,
    pub recipient_bucket_root: String,
    pub withdrawal_amount_bucket_root: String,
    pub withdrawal_output_root: String,
    pub withdrawal_count: u64,
    pub anonymity_set_size: u64,
    pub min_decoy_outputs: u64,
    pub delayed_release_blocks: u64,
    pub fee_bps: u64,
    pub privacy_floor: u64,
    pub accepted: bool,
}

impl BridgeWithdrawalPrivacyFloorRecord {
    pub fn from_request(
        request: BridgeWithdrawalPrivacyFloorRequest,
        config: &Config,
    ) -> MoneroL2PqPrivateRingctMigrationAuditRuntimeResult<Self> {
        required("floor_id", &request.floor_id)?;
        required("audit_id", &request.audit_id)?;
        required("recipient_bucket_root", &request.recipient_bucket_root)?;
        required(
            "withdrawal_amount_bucket_root",
            &request.withdrawal_amount_bucket_root,
        )?;
        require(request.withdrawal_count > 0, "withdrawal_count is required")?;
        let floor = request.anonymity_set_size.min(request.min_decoy_outputs);
        Ok(Self {
            floor_id: request.floor_id,
            audit_id: request.audit_id,
            withdrawal_epoch: request.withdrawal_epoch,
            recipient_bucket_root: request.recipient_bucket_root,
            withdrawal_amount_bucket_root: request.withdrawal_amount_bucket_root,
            withdrawal_output_root: request.withdrawal_output_root,
            withdrawal_count: request.withdrawal_count,
            anonymity_set_size: request.anonymity_set_size,
            min_decoy_outputs: request.min_decoy_outputs,
            delayed_release_blocks: request.delayed_release_blocks,
            fee_bps: request.fee_bps,
            privacy_floor: floor,
            accepted: floor >= config.min_withdrawal_privacy_floor
                && request.fee_bps <= config.low_fee_max_bps,
        })
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-WITHDRAWAL-FLOOR",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAuditorAttestationRequest {
    pub attestation_id: String,
    pub audit_id: String,
    pub auditor_committee_id: String,
    pub statement_root: String,
    pub audited_state_root: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub security_bits: u16,
    pub committee_weight_bps: u64,
    pub expires_at_l2_height: u64,
    pub revocation_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAuditorAttestationRecord {
    pub attestation_id: String,
    pub audit_id: String,
    pub auditor_committee_id: String,
    pub statement_root: String,
    pub audited_state_root: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub security_bits: u16,
    pub committee_weight_bps: u64,
    pub expires_at_l2_height: u64,
    pub revocation_root: String,
    pub status: AttestationStatus,
    pub accepted: bool,
}

impl PqAuditorAttestationRecord {
    pub fn from_request(
        request: PqAuditorAttestationRequest,
        config: &Config,
        current_l2_height: u64,
    ) -> MoneroL2PqPrivateRingctMigrationAuditRuntimeResult<Self> {
        required("attestation_id", &request.attestation_id)?;
        required("audit_id", &request.audit_id)?;
        required("auditor_committee_id", &request.auditor_committee_id)?;
        required("statement_root", &request.statement_root)?;
        required("audited_state_root", &request.audited_state_root)?;
        required("pq_public_key_root", &request.pq_public_key_root)?;
        required("pq_signature_root", &request.pq_signature_root)?;
        require(
            request.security_bits >= config.min_pq_security_bits,
            "attestation security_bits below floor",
        )?;
        require(
            request.committee_weight_bps >= config.quorum_bps,
            "committee weight below quorum",
        )?;
        require(
            request.expires_at_l2_height > current_l2_height,
            "attestation is expired",
        )?;
        let status = if request.committee_weight_bps >= config.strong_quorum_bps {
            AttestationStatus::StrongQuorum
        } else {
            AttestationStatus::Quorum
        };
        Ok(Self {
            attestation_id: request.attestation_id,
            audit_id: request.audit_id,
            auditor_committee_id: request.auditor_committee_id,
            statement_root: request.statement_root,
            audited_state_root: request.audited_state_root,
            pq_public_key_root: request.pq_public_key_root,
            pq_signature_root: request.pq_signature_root,
            security_bits: request.security_bits,
            committee_weight_bps: request.committee_weight_bps,
            expires_at_l2_height: request.expires_at_l2_height,
            revocation_root: request.revocation_root,
            status,
            accepted: true,
        })
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-PQ-ATTESTATION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactedOperatorSummaryRequest {
    pub summary_id: String,
    pub audit_id: String,
    pub operator_id: String,
    pub redaction_policy_root: String,
    pub redacted_metrics_root: String,
    pub incident_bucket_root: String,
    pub public_message_root: String,
    pub total_migrated_outputs: u64,
    pub total_withdrawals: u64,
    pub suppressed_field_count: u64,
    pub disclosed_field_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactedOperatorSummaryRecord {
    pub summary_id: String,
    pub audit_id: String,
    pub operator_id: String,
    pub redaction_policy_root: String,
    pub redacted_metrics_root: String,
    pub incident_bucket_root: String,
    pub public_message_root: String,
    pub total_migrated_outputs: u64,
    pub total_withdrawals: u64,
    pub suppressed_field_count: u64,
    pub disclosed_field_count: u64,
    pub redaction_ratio_bps: u64,
    pub accepted: bool,
}

impl RedactedOperatorSummaryRecord {
    pub fn from_request(
        request: RedactedOperatorSummaryRequest,
    ) -> MoneroL2PqPrivateRingctMigrationAuditRuntimeResult<Self> {
        required("summary_id", &request.summary_id)?;
        required("audit_id", &request.audit_id)?;
        required("operator_id", &request.operator_id)?;
        required("redaction_policy_root", &request.redaction_policy_root)?;
        required("redacted_metrics_root", &request.redacted_metrics_root)?;
        let field_total = request.suppressed_field_count + request.disclosed_field_count;
        require(field_total > 0, "operator summary field count is required")?;
        let redaction_ratio = ratio_bps(request.suppressed_field_count, field_total);
        Ok(Self {
            summary_id: request.summary_id,
            audit_id: request.audit_id,
            operator_id: request.operator_id,
            redaction_policy_root: request.redaction_policy_root,
            redacted_metrics_root: request.redacted_metrics_root,
            incident_bucket_root: request.incident_bucket_root,
            public_message_root: request.public_message_root,
            total_migrated_outputs: request.total_migrated_outputs,
            total_withdrawals: request.total_withdrawals,
            suppressed_field_count: request.suppressed_field_count,
            disclosed_field_count: request.disclosed_field_count,
            redaction_ratio_bps: redaction_ratio,
            accepted: request.suppressed_field_count > 0,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "audit_id": self.audit_id,
            "operator_id": self.operator_id,
            "redaction_policy_root": self.redaction_policy_root,
            "redacted_metrics_root": self.redacted_metrics_root,
            "incident_bucket_root": self.incident_bucket_root,
            "public_message_root": self.public_message_root,
            "total_migrated_outputs": self.total_migrated_outputs,
            "total_withdrawals": self.total_withdrawals,
            "suppressed_field_count": self.suppressed_field_count,
            "disclosed_field_count": self.disclosed_field_count,
            "redaction_ratio_bps": self.redaction_ratio_bps,
            "accepted": self.accepted,
            "privacy_boundary": MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_PRIVACY_BOUNDARY,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-OPERATOR-SUMMARY",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeProofBatchRequest {
    pub batch_id: String,
    pub audit_id: String,
    pub proof_manifest_root: String,
    pub fee_sponsor_root: String,
    pub batched_nullifier_root: String,
    pub batched_output_root: String,
    pub proof_count: u64,
    pub total_weight: u64,
    pub user_fee_bps: u64,
    pub subsidy_units: u64,
    pub aggregation_round: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeProofBatchRecord {
    pub batch_id: String,
    pub audit_id: String,
    pub proof_manifest_root: String,
    pub fee_sponsor_root: String,
    pub batched_nullifier_root: String,
    pub batched_output_root: String,
    pub proof_count: u64,
    pub total_weight: u64,
    pub user_fee_bps: u64,
    pub subsidy_units: u64,
    pub aggregation_round: u64,
    pub status: ProofBatchStatus,
    pub accepted: bool,
}

impl LowFeeProofBatchRecord {
    pub fn from_request(
        request: LowFeeProofBatchRequest,
        config: &Config,
    ) -> MoneroL2PqPrivateRingctMigrationAuditRuntimeResult<Self> {
        required("batch_id", &request.batch_id)?;
        required("audit_id", &request.audit_id)?;
        required("proof_manifest_root", &request.proof_manifest_root)?;
        required("batched_nullifier_root", &request.batched_nullifier_root)?;
        require(request.proof_count > 0, "proof_count is required")?;
        require(request.total_weight > 0, "total_weight is required")?;
        let accepted = request.total_weight <= config.max_low_fee_batch_weight
            && request.user_fee_bps <= config.low_fee_max_bps;
        Ok(Self {
            batch_id: request.batch_id,
            audit_id: request.audit_id,
            proof_manifest_root: request.proof_manifest_root,
            fee_sponsor_root: request.fee_sponsor_root,
            batched_nullifier_root: request.batched_nullifier_root,
            batched_output_root: request.batched_output_root,
            proof_count: request.proof_count,
            total_weight: request.total_weight,
            user_fee_bps: request.user_fee_bps,
            subsidy_units: request.subsidy_units,
            aggregation_round: request.aggregation_round,
            status: if accepted {
                ProofBatchStatus::Verified
            } else {
                ProofBatchStatus::Rejected
            },
            accepted,
        })
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(
            "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-LOW-FEE-BATCH",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_l2_height: u64,
    pub current_monero_height: u64,
    pub audits: BTreeMap<String, MigrationAuditRecord>,
    pub decoy_sets: BTreeMap<String, DecoySetRecord>,
    pub view_tag_checks: BTreeMap<String, ViewTagLeakageCheckRecord>,
    pub stealth_rotations: BTreeMap<String, StealthAddressRotationRecord>,
    pub output_age_buckets: BTreeMap<String, OutputAgeBucketRecord>,
    pub subaddress_summaries: BTreeMap<String, SubaddressMigrationSummaryRecord>,
    pub withdrawal_floors: BTreeMap<String, BridgeWithdrawalPrivacyFloorRecord>,
    pub pq_attestations: BTreeMap<String, PqAuditorAttestationRecord>,
    pub operator_summaries: BTreeMap<String, RedactedOperatorSummaryRecord>,
    pub low_fee_batches: BTreeMap<String, LowFeeProofBatchRecord>,
    pub known_nullifiers: BTreeSet<String>,
}

pub type Runtime = State;

impl State {
    pub fn devnet() -> Self {
        Self::new(Config::devnet())
    }

    pub fn new(config: Config) -> Self {
        Self {
            current_l2_height: config.genesis_height,
            current_monero_height:
                MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_DEVNET_HEIGHT,
            config,
            counters: Counters::default(),
            audits: BTreeMap::new(),
            decoy_sets: BTreeMap::new(),
            view_tag_checks: BTreeMap::new(),
            stealth_rotations: BTreeMap::new(),
            output_age_buckets: BTreeMap::new(),
            subaddress_summaries: BTreeMap::new(),
            withdrawal_floors: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            low_fee_batches: BTreeMap::new(),
            known_nullifiers: BTreeSet::new(),
        }
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let audit = MigrationAuditRequest {
            audit_id: "audit-demo-001".to_string(),
            migration_id: "migration-demo-ringct-001".to_string(),
            ringct_commitment_root: sample_root("ringct-commitments"),
            input_key_image_root: sample_root("key-image-root-redacted"),
            output_commitment_root: sample_root("output-commitments"),
            encrypted_note_manifest_root: sample_root("encrypted-note-manifest"),
            migration_epoch: 1,
            monero_height: state.current_monero_height,
            l2_height: state.current_l2_height,
            candidate_output_count: 8_192,
            candidate_ring_count: 512,
            min_observed_ring_size: 16,
            output_age_bucket_root: sample_root("age-buckets"),
            subaddress_summary_root: sample_root("subaddress-summary"),
            operator_redaction_root: sample_root("operator-redaction"),
        };
        let _audit_result = state.record_migration_audit(audit);
        let decoys = DecoySetRequest {
            decoy_set_id: "decoy-demo-001".to_string(),
            audit_id: "audit-demo-001".to_string(),
            selection_algorithm: "monero-style-age-weighted-output-selection".to_string(),
            decoy_output_root: sample_root("decoy-output-root"),
            real_output_mask_root: sample_root("real-output-mask-root"),
            age_distribution_root: sample_root("age-distribution-root"),
            amount_commitment_class_root: sample_root("amount-class-root"),
            preserve_monero_distribution: true,
            output_count: 8_192,
            ring_count: 512,
            min_ring_size: 16,
            median_age_bucket: 5,
            newest_output_lag_blocks: 20,
        };
        let _decoy_result = state.record_decoy_set(decoys);
        let check = ViewTagLeakageCheckRequest {
            check_id: "viewtag-demo-001".to_string(),
            audit_id: "audit-demo-001".to_string(),
            view_tag_histogram_root: sample_root("view-tag-histogram"),
            scan_pattern_root: sample_root("scan-pattern"),
            wallet_cluster_hint_root: sample_root("wallet-cluster-hint"),
            sampled_output_count: 8_192,
            distinct_view_tag_count: 256,
            max_single_tag_bps: 31,
            repeated_scan_prefix_bps: 12,
            cross_subaddress_correlation_bps: 20,
        };
        let _check_result = state.record_view_tag_leakage_check(check);
        let rotation = StealthAddressRotationRequest {
            rotation_id: "rotation-demo-001".to_string(),
            audit_id: "audit-demo-001".to_string(),
            rotation_epoch: 1,
            prior_stealth_address_root: sample_root("prior-stealth-root"),
            next_stealth_address_root: sample_root("next-stealth-root"),
            rotation_proof_root: sample_root("rotation-proof-root"),
            subaddress_domain_root: sample_root("subaddress-domain-root"),
            rotated_output_count: 4_096,
            retained_decoy_count: 8_192,
            linkability_budget_bps: 16,
        };
        let _rotation_result = state.record_stealth_address_rotation(rotation);
        let bucket = OutputAgeBucketRequest {
            bucket_id: "age-demo-001".to_string(),
            audit_id: "audit-demo-001".to_string(),
            bucket_label: "mature-720-plus".to_string(),
            min_age_blocks: 720,
            max_age_blocks: 10_000,
            output_count: 1_024,
            decoy_count: 900,
            ring_member_count: 16,
            bucket_commitment_root: sample_root("bucket-commitments"),
        };
        let _bucket_result = state.record_output_age_bucket(bucket);
        let summary = SubaddressMigrationSummaryRequest {
            summary_id: "subaddress-demo-001".to_string(),
            audit_id: "audit-demo-001".to_string(),
            subaddress_domain_root: sample_root("subaddress-domain"),
            encrypted_mapping_root: sample_root("encrypted-mapping"),
            account_bucket_root: sample_root("account-bucket"),
            spend_authorization_root: sample_root("spend-auth"),
            migrated_subaddress_count: 128,
            rotated_subaddress_count: 128,
            max_outputs_per_subaddress: 6,
            split_strategy: "bucketed-rotation-with-encrypted-map".to_string(),
        };
        let _summary_result = state.record_subaddress_migration_summary(summary);
        let floor = BridgeWithdrawalPrivacyFloorRequest {
            floor_id: "floor-demo-001".to_string(),
            audit_id: "audit-demo-001".to_string(),
            withdrawal_epoch: 1,
            recipient_bucket_root: sample_root("recipient-bucket"),
            withdrawal_amount_bucket_root: sample_root("amount-bucket"),
            withdrawal_output_root: sample_root("withdrawal-output"),
            withdrawal_count: 64,
            anonymity_set_size: 8_192,
            min_decoy_outputs: 4_096,
            delayed_release_blocks: 20,
            fee_bps: 4,
        };
        let _floor_result = state.record_bridge_withdrawal_privacy_floor(floor);
        let attestation = PqAuditorAttestationRequest {
            attestation_id: "attestation-demo-001".to_string(),
            audit_id: "audit-demo-001".to_string(),
            auditor_committee_id: "pq-auditor-committee-devnet".to_string(),
            statement_root: sample_root("statement-root"),
            audited_state_root: state.state_root(),
            pq_public_key_root: sample_root("pq-public-keys"),
            pq_signature_root: sample_root("pq-signatures"),
            security_bits: 192,
            committee_weight_bps: 8_000,
            expires_at_l2_height: state.current_l2_height + 72,
            revocation_root: sample_root("revocation-root"),
        };
        let _attestation_result = state.record_pq_auditor_attestation(attestation);
        let operator = RedactedOperatorSummaryRequest {
            summary_id: "operator-demo-001".to_string(),
            audit_id: "audit-demo-001".to_string(),
            operator_id: "operator-redacted-devnet".to_string(),
            redaction_policy_root: sample_root("redaction-policy"),
            redacted_metrics_root: sample_root("redacted-metrics"),
            incident_bucket_root: sample_root("incident-bucket"),
            public_message_root: sample_root("public-message"),
            total_migrated_outputs: 8_192,
            total_withdrawals: 64,
            suppressed_field_count: 11,
            disclosed_field_count: 5,
        };
        let _operator_result = state.record_redacted_operator_summary(operator);
        let batch = LowFeeProofBatchRequest {
            batch_id: "proof-batch-demo-001".to_string(),
            audit_id: "audit-demo-001".to_string(),
            proof_manifest_root: sample_root("proof-manifest"),
            fee_sponsor_root: sample_root("fee-sponsor"),
            batched_nullifier_root: sample_root("batched-nullifiers"),
            batched_output_root: sample_root("batched-outputs"),
            proof_count: 32,
            total_weight: 1_024,
            user_fee_bps: 4,
            subsidy_units: 10_000,
            aggregation_round: 1,
        };
        let _batch_result = state.record_low_fee_proof_batch(batch);
        state
    }

    pub fn advance_heights(&mut self, l2_height: u64, monero_height: u64) {
        if l2_height > self.current_l2_height {
            self.current_l2_height = l2_height;
        }
        if monero_height > self.current_monero_height {
            self.current_monero_height = monero_height;
        }
    }

    pub fn record_migration_audit(
        &mut self,
        request: MigrationAuditRequest,
    ) -> MoneroL2PqPrivateRingctMigrationAuditRuntimeResult<String> {
        self.config.validate()?;
        require(
            self.audits.len() < MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_AUDITS,
            "audit capacity reached",
        )?;
        require(
            !self.audits.contains_key(&request.audit_id),
            "audit_id already exists",
        )?;
        let record = MigrationAuditRecord::from_request(request, &self.config)?;
        let root = record.state_root();
        self.counters.audits_opened += 1;
        self.audits.insert(record.audit_id.clone(), record);
        Ok(root)
    }

    pub fn record_decoy_set(
        &mut self,
        request: DecoySetRequest,
    ) -> MoneroL2PqPrivateRingctMigrationAuditRuntimeResult<String> {
        require(
            self.decoy_sets.len()
                < MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_DECOY_SETS,
            "decoy set capacity reached",
        )?;
        require(
            self.audits.contains_key(&request.audit_id),
            "unknown audit_id",
        )?;
        require(
            !self.decoy_sets.contains_key(&request.decoy_set_id),
            "decoy_set_id already exists",
        )?;
        let record = DecoySetRecord::from_request(request, &self.config)?;
        let root = record.state_root();
        self.counters.decoy_sets_recorded += 1;
        if !record.accepted {
            self.counters.privacy_floor_violations += 1;
        }
        update_audit_after_privacy_check(&mut self.audits, &record.audit_id, record.accepted)?;
        self.decoy_sets.insert(record.decoy_set_id.clone(), record);
        Ok(root)
    }

    pub fn record_view_tag_leakage_check(
        &mut self,
        request: ViewTagLeakageCheckRequest,
    ) -> MoneroL2PqPrivateRingctMigrationAuditRuntimeResult<String> {
        require(
            self.view_tag_checks.len()
                < MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_VIEW_TAG_CHECKS,
            "view tag check capacity reached",
        )?;
        require(
            self.audits.contains_key(&request.audit_id),
            "unknown audit_id",
        )?;
        require(
            !self.view_tag_checks.contains_key(&request.check_id),
            "check_id already exists",
        )?;
        let record = ViewTagLeakageCheckRecord::from_request(request, &self.config)?;
        let root = record.state_root();
        self.counters.view_tag_checks_recorded += 1;
        if !matches!(record.severity, LeakageSeverity::None) {
            self.counters.leakage_alerts += 1;
        }
        if let Some(audit) = self.audits.get_mut(&record.audit_id) {
            audit.leakage_severity = audit.leakage_severity.max(record.severity);
            if record.accepted {
                audit.status = AuditStatus::PrivacyChecked;
            } else {
                audit.status = AuditStatus::NeedsRotation;
                audit.privacy_floor_passed = false;
            }
        }
        self.view_tag_checks.insert(record.check_id.clone(), record);
        Ok(root)
    }

    pub fn record_stealth_address_rotation(
        &mut self,
        request: StealthAddressRotationRequest,
    ) -> MoneroL2PqPrivateRingctMigrationAuditRuntimeResult<String> {
        require(
            self.stealth_rotations.len()
                < MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_ROTATIONS,
            "stealth rotation capacity reached",
        )?;
        require(
            self.audits.contains_key(&request.audit_id),
            "unknown audit_id",
        )?;
        require(
            !self.stealth_rotations.contains_key(&request.rotation_id),
            "rotation_id already exists",
        )?;
        let record = StealthAddressRotationRecord::from_request(request, &self.config)?;
        let root = record.state_root();
        self.counters.rotations_recorded += 1;
        if let Some(audit) = self.audits.get_mut(&record.audit_id) {
            audit.phase = MigrationPhase::DecoyPreservation;
            audit.status = if record.accepted {
                AuditStatus::PrivacyChecked
            } else {
                AuditStatus::NeedsRotation
            };
        }
        self.stealth_rotations
            .insert(record.rotation_id.clone(), record);
        Ok(root)
    }

    pub fn record_output_age_bucket(
        &mut self,
        request: OutputAgeBucketRequest,
    ) -> MoneroL2PqPrivateRingctMigrationAuditRuntimeResult<String> {
        require(
            self.output_age_buckets.len()
                < MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_AGE_BUCKETS,
            "output age bucket capacity reached",
        )?;
        require(
            self.audits.contains_key(&request.audit_id),
            "unknown audit_id",
        )?;
        require(
            !self.output_age_buckets.contains_key(&request.bucket_id),
            "bucket_id already exists",
        )?;
        let record = OutputAgeBucketRecord::from_request(request, &self.config)?;
        let root = record.state_root();
        self.counters.age_buckets_recorded += 1;
        if !record.accepted {
            self.counters.privacy_floor_violations += 1;
        }
        self.output_age_buckets
            .insert(record.bucket_id.clone(), record);
        Ok(root)
    }

    pub fn record_subaddress_migration_summary(
        &mut self,
        request: SubaddressMigrationSummaryRequest,
    ) -> MoneroL2PqPrivateRingctMigrationAuditRuntimeResult<String> {
        require(
            self.subaddress_summaries.len()
                < MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_SUBADDRESS_SUMMARIES,
            "subaddress summary capacity reached",
        )?;
        require(
            self.audits.contains_key(&request.audit_id),
            "unknown audit_id",
        )?;
        require(
            !self.subaddress_summaries.contains_key(&request.summary_id),
            "summary_id already exists",
        )?;
        let record = SubaddressMigrationSummaryRecord::from_request(request)?;
        let root = record.state_root();
        self.counters.subaddress_summaries_recorded += 1;
        self.subaddress_summaries
            .insert(record.summary_id.clone(), record);
        Ok(root)
    }

    pub fn record_bridge_withdrawal_privacy_floor(
        &mut self,
        request: BridgeWithdrawalPrivacyFloorRequest,
    ) -> MoneroL2PqPrivateRingctMigrationAuditRuntimeResult<String> {
        require(
            self.withdrawal_floors.len()
                < MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_WITHDRAWAL_FLOORS,
            "withdrawal floor capacity reached",
        )?;
        require(
            self.audits.contains_key(&request.audit_id),
            "unknown audit_id",
        )?;
        require(
            !self.withdrawal_floors.contains_key(&request.floor_id),
            "floor_id already exists",
        )?;
        let record = BridgeWithdrawalPrivacyFloorRecord::from_request(request, &self.config)?;
        let root = record.state_root();
        self.counters.withdrawal_floors_recorded += 1;
        if !record.accepted {
            self.counters.privacy_floor_violations += 1;
        }
        if let Some(audit) = self.audits.get_mut(&record.audit_id) {
            audit.phase = if record.accepted {
                MigrationPhase::WithdrawalReady
            } else {
                MigrationPhase::Paused
            };
            audit.privacy_floor_passed = audit.privacy_floor_passed && record.accepted;
        }
        self.withdrawal_floors
            .insert(record.floor_id.clone(), record);
        Ok(root)
    }

    pub fn record_pq_auditor_attestation(
        &mut self,
        request: PqAuditorAttestationRequest,
    ) -> MoneroL2PqPrivateRingctMigrationAuditRuntimeResult<String> {
        require(
            self.pq_attestations.len()
                < MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_ATTESTATIONS,
            "attestation capacity reached",
        )?;
        require(
            self.audits.contains_key(&request.audit_id),
            "unknown audit_id",
        )?;
        require(
            !self.pq_attestations.contains_key(&request.attestation_id),
            "attestation_id already exists",
        )?;
        let record = PqAuditorAttestationRecord::from_request(
            request,
            &self.config,
            self.current_l2_height,
        )?;
        let root = record.state_root();
        self.counters.attestations_recorded += 1;
        if let Some(audit) = self.audits.get_mut(&record.audit_id) {
            audit.phase = MigrationPhase::AuditorAttestation;
            audit.status = AuditStatus::Attested;
            audit.attestation_root = root.clone();
        }
        self.pq_attestations
            .insert(record.attestation_id.clone(), record);
        Ok(root)
    }

    pub fn record_redacted_operator_summary(
        &mut self,
        request: RedactedOperatorSummaryRequest,
    ) -> MoneroL2PqPrivateRingctMigrationAuditRuntimeResult<String> {
        require(
            self.operator_summaries.len()
                < MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_OPERATOR_SUMMARIES,
            "operator summary capacity reached",
        )?;
        require(
            self.audits.contains_key(&request.audit_id),
            "unknown audit_id",
        )?;
        require(
            !self.operator_summaries.contains_key(&request.summary_id),
            "summary_id already exists",
        )?;
        let record = RedactedOperatorSummaryRecord::from_request(request)?;
        let root = record.state_root();
        self.counters.operator_summaries_recorded += 1;
        if record.accepted {
            self.counters.redactions_applied += 1;
        }
        if let Some(audit) = self.audits.get_mut(&record.audit_id) {
            audit.status = AuditStatus::RedactedForOperator;
        }
        self.operator_summaries
            .insert(record.summary_id.clone(), record);
        Ok(root)
    }

    pub fn record_low_fee_proof_batch(
        &mut self,
        request: LowFeeProofBatchRequest,
    ) -> MoneroL2PqPrivateRingctMigrationAuditRuntimeResult<String> {
        require(
            self.low_fee_batches.len()
                < MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_PROOF_BATCHES,
            "low fee proof batch capacity reached",
        )?;
        require(
            self.audits.contains_key(&request.audit_id),
            "unknown audit_id",
        )?;
        require(
            !self.low_fee_batches.contains_key(&request.batch_id),
            "batch_id already exists",
        )?;
        let record = LowFeeProofBatchRecord::from_request(request, &self.config)?;
        let root = record.state_root();
        self.counters.low_fee_batches_recorded += 1;
        if let Some(audit) = self.audits.get_mut(&record.audit_id) {
            audit.phase = MigrationPhase::RingctProofBatching;
        }
        self.low_fee_batches.insert(record.batch_id.clone(), record);
        Ok(root)
    }

    pub fn record_known_nullifier_commitment(
        &mut self,
        nullifier_commitment: String,
    ) -> MoneroL2PqPrivateRingctMigrationAuditRuntimeResult<bool> {
        required("nullifier_commitment", &nullifier_commitment)?;
        Ok(self.known_nullifiers.insert(nullifier_commitment))
    }

    pub fn finalize_audit(
        &mut self,
        audit_id: &str,
    ) -> MoneroL2PqPrivateRingctMigrationAuditRuntimeResult<String> {
        let audit = self
            .audits
            .get_mut(audit_id)
            .ok_or_else(|| "unknown audit_id".to_string())?;
        require(!audit.phase.terminal(), "audit already terminal")?;
        require(audit.privacy_floor_passed, "audit privacy floor failed")?;
        require(
            matches!(
                audit.status,
                AuditStatus::Attested | AuditStatus::RedactedForOperator
            ),
            "audit requires attestation before finalization",
        )?;
        audit.phase = MigrationPhase::Complete;
        audit.status = AuditStatus::Finalized;
        self.counters.audits_finalized += 1;
        Ok(audit.state_root())
    }

    pub fn reject_audit(
        &mut self,
        audit_id: &str,
    ) -> MoneroL2PqPrivateRingctMigrationAuditRuntimeResult<String> {
        let audit = self
            .audits
            .get_mut(audit_id)
            .ok_or_else(|| "unknown audit_id".to_string())?;
        require(!audit.phase.terminal(), "audit already terminal")?;
        audit.phase = MigrationPhase::Rejected;
        audit.status = AuditStatus::Rejected;
        audit.privacy_floor_passed = false;
        self.counters.audits_rejected += 1;
        Ok(audit.state_root())
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters.state_root(),
            audit_root: map_root(
                "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-AUDITS",
                &self.audits,
                MigrationAuditRecord::public_record,
            ),
            decoy_set_root: map_root(
                "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-DECOY-SETS",
                &self.decoy_sets,
                DecoySetRecord::public_record,
            ),
            view_tag_check_root: map_root(
                "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-VIEW-TAG-CHECKS",
                &self.view_tag_checks,
                ViewTagLeakageCheckRecord::public_record,
            ),
            stealth_rotation_root: map_root(
                "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-STEALTH-ROTATIONS",
                &self.stealth_rotations,
                StealthAddressRotationRecord::public_record,
            ),
            output_age_bucket_root: map_root(
                "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-OUTPUT-AGE-BUCKETS",
                &self.output_age_buckets,
                OutputAgeBucketRecord::public_record,
            ),
            subaddress_summary_root: map_root(
                "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-SUBADDRESS-SUMMARIES",
                &self.subaddress_summaries,
                SubaddressMigrationSummaryRecord::public_record,
            ),
            withdrawal_floor_root: map_root(
                "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-WITHDRAWAL-FLOORS",
                &self.withdrawal_floors,
                BridgeWithdrawalPrivacyFloorRecord::public_record,
            ),
            pq_attestation_root: map_root(
                "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-PQ-ATTESTATIONS",
                &self.pq_attestations,
                PqAuditorAttestationRecord::public_record,
            ),
            operator_summary_root: map_root(
                "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-OPERATOR-SUMMARIES",
                &self.operator_summaries,
                RedactedOperatorSummaryRecord::public_record,
            ),
            low_fee_batch_root: map_root(
                "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-LOW-FEE-BATCHES",
                &self.low_fee_batches,
                LowFeeProofBatchRecord::public_record,
            ),
            known_nullifier_root: set_root(
                "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-KNOWN-NULLIFIERS",
                &self.known_nullifiers,
            ),
            state_root: self.state_root_without_roots_field(),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots_without_state_root();
        json!({
            "kind": "monero_l2_pq_private_ringct_migration_audit_runtime_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_SCHEMA_VERSION,
            "privacy_boundary": MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_PRIVACY_BOUNDARY,
            "current_l2_height": self.current_l2_height,
            "current_monero_height": self.current_monero_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        set_json_field(&mut record, "state_root", json!(self.state_root()));
        record
    }

    pub fn state_root(&self) -> String {
        self.state_root_without_roots_field()
    }

    pub fn validate(&self) -> MoneroL2PqPrivateRingctMigrationAuditRuntimeResult<()> {
        self.config.validate()?;
        require(
            self.current_l2_height >= self.config.genesis_height,
            "current_l2_height before genesis",
        )?;
        require(
            self.audits.len() <= MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_AUDITS,
            "too many audits",
        )?;
        require(
            self.decoy_sets.len()
                <= MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_DECOY_SETS,
            "too many decoy sets",
        )?;
        require(
            self.view_tag_checks.len()
                <= MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_VIEW_TAG_CHECKS,
            "too many view tag checks",
        )?;
        require(
            self.stealth_rotations.len()
                <= MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_ROTATIONS,
            "too many stealth rotations",
        )?;
        require(
            self.low_fee_batches.len()
                <= MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_PROOF_BATCHES,
            "too many low fee proof batches",
        )?;
        Ok(())
    }

    fn roots_without_state_root(&self) -> Roots {
        let mut roots = self.roots_base();
        roots.state_root = empty_root("STATE-ROOT-OMITTED");
        roots
    }

    fn roots_base(&self) -> Roots {
        Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters.state_root(),
            audit_root: map_root(
                "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-AUDITS",
                &self.audits,
                MigrationAuditRecord::public_record,
            ),
            decoy_set_root: map_root(
                "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-DECOY-SETS",
                &self.decoy_sets,
                DecoySetRecord::public_record,
            ),
            view_tag_check_root: map_root(
                "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-VIEW-TAG-CHECKS",
                &self.view_tag_checks,
                ViewTagLeakageCheckRecord::public_record,
            ),
            stealth_rotation_root: map_root(
                "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-STEALTH-ROTATIONS",
                &self.stealth_rotations,
                StealthAddressRotationRecord::public_record,
            ),
            output_age_bucket_root: map_root(
                "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-OUTPUT-AGE-BUCKETS",
                &self.output_age_buckets,
                OutputAgeBucketRecord::public_record,
            ),
            subaddress_summary_root: map_root(
                "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-SUBADDRESS-SUMMARIES",
                &self.subaddress_summaries,
                SubaddressMigrationSummaryRecord::public_record,
            ),
            withdrawal_floor_root: map_root(
                "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-WITHDRAWAL-FLOORS",
                &self.withdrawal_floors,
                BridgeWithdrawalPrivacyFloorRecord::public_record,
            ),
            pq_attestation_root: map_root(
                "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-PQ-ATTESTATIONS",
                &self.pq_attestations,
                PqAuditorAttestationRecord::public_record,
            ),
            operator_summary_root: map_root(
                "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-OPERATOR-SUMMARIES",
                &self.operator_summaries,
                RedactedOperatorSummaryRecord::public_record,
            ),
            low_fee_batch_root: map_root(
                "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-LOW-FEE-BATCHES",
                &self.low_fee_batches,
                LowFeeProofBatchRecord::public_record,
            ),
            known_nullifier_root: set_root(
                "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-KNOWN-NULLIFIERS",
                &self.known_nullifiers,
            ),
            state_root: empty_root("STATE-ROOT-PENDING"),
        }
    }

    fn state_root_without_roots_field(&self) -> String {
        let roots = self.roots_base();
        let record = json!({
            "kind": "monero_l2_pq_private_ringct_migration_audit_runtime_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_SCHEMA_VERSION,
            "privacy_boundary": MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_PRIVACY_BOUNDARY,
            "current_l2_height": self.current_l2_height,
            "current_monero_height": self.current_monero_height,
            "config_root": roots.config_root,
            "counters_root": roots.counters_root,
            "audit_root": roots.audit_root,
            "decoy_set_root": roots.decoy_set_root,
            "view_tag_check_root": roots.view_tag_check_root,
            "stealth_rotation_root": roots.stealth_rotation_root,
            "output_age_bucket_root": roots.output_age_bucket_root,
            "subaddress_summary_root": roots.subaddress_summary_root,
            "withdrawal_floor_root": roots.withdrawal_floor_root,
            "pq_attestation_root": roots.pq_attestation_root,
            "operator_summary_root": roots.operator_summary_root,
            "low_fee_batch_root": roots.low_fee_batch_root,
            "known_nullifier_root": roots.known_nullifier_root,
        });
        record_root("MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-STATE", &record)
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record() -> Value {
    State::demo().public_record()
}

pub fn state_root() -> String {
    State::demo().state_root()
}

pub fn monero_l2_pq_private_ringct_migration_audit_runtime_state_root_from_record(
    record: &Value,
) -> String {
    record_root("MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-STATE", record)
}

fn update_audit_after_privacy_check(
    audits: &mut BTreeMap<String, MigrationAuditRecord>,
    audit_id: &str,
    accepted: bool,
) -> MoneroL2PqPrivateRingctMigrationAuditRuntimeResult<()> {
    let audit = audits
        .get_mut(audit_id)
        .ok_or_else(|| "unknown audit_id".to_string())?;
    audit.phase = MigrationPhase::DecoyPreservation;
    if accepted {
        audit.status = AuditStatus::PrivacyChecked;
    } else {
        audit.status = AuditStatus::NeedsMoreDecoys;
        audit.privacy_floor_passed = false;
    }
    Ok(())
}

fn preservation_score_bps(
    output_count: u64,
    min_ring_size: u64,
    output_floor: u64,
    ring_floor: u64,
    preserves_distribution: bool,
) -> u64 {
    let output_score = ratio_bps(output_count.min(output_floor), output_floor);
    let ring_score = ratio_bps(min_ring_size.min(ring_floor), ring_floor);
    let distribution_score = if preserves_distribution {
        MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_BPS
    } else {
        MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_BPS / 2
    };
    (output_score + ring_score + distribution_score) / 3
}

fn leakage_severity(observed_bps: u64, budget_bps: u64) -> LeakageSeverity {
    if observed_bps <= budget_bps {
        LeakageSeverity::None
    } else if observed_bps <= budget_bps.saturating_mul(2) {
        LeakageSeverity::Watch
    } else if observed_bps <= budget_bps.saturating_mul(4) {
        LeakageSeverity::Elevated
    } else {
        LeakageSeverity::Critical
    }
}

fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        0
    } else {
        numerator.saturating_mul(MONERO_L2_PQ_PRIVATE_RINGCT_MIGRATION_AUDIT_RUNTIME_MAX_BPS)
            / denominator
    }
}

fn sample_root(label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-SAMPLE",
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
        "MONERO-L2-PQ-PRIVATE-RINGCT-MIGRATION-AUDIT-EMPTY",
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

fn required(field: &str, value: &str) -> MoneroL2PqPrivateRingctMigrationAuditRuntimeResult<()> {
    require(!value.trim().is_empty(), &format!("{field} is required"))
}

fn require(
    condition: bool,
    message: &str,
) -> MoneroL2PqPrivateRingctMigrationAuditRuntimeResult<()> {
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
