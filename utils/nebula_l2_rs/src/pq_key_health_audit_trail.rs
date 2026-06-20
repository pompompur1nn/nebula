use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqKeyHealthAuditTrailResult<T> = Result<T, String>;

pub const PQ_KEY_HEALTH_AUDIT_TRAIL_PROTOCOL_VERSION: &str = "nebula-pq-key-health-audit-trail-v1";
pub const PQ_KEY_HEALTH_AUDIT_TRAIL_SCHEMA_VERSION: &str = "pq-key-health-audit-trail-state-v1";
pub const PQ_KEY_HEALTH_AUDIT_TRAIL_DEVNET_LABEL: &str = "devnet-pq-key-health-audit-trail";
pub const PQ_KEY_HEALTH_AUDIT_TRAIL_HASH_SCHEME: &str = "shake256-domain-separated-canonical-json";
pub const PQ_KEY_HEALTH_AUDIT_TRAIL_ROTATION_RECEIPT_SCHEME: &str =
    "hybrid-pq-key-rotation-receipt-v1";
pub const PQ_KEY_HEALTH_AUDIT_TRAIL_REVOCATION_NULLIFIER_SCHEME: &str =
    "pq-key-revocation-nullifier-v1";
pub const PQ_KEY_HEALTH_AUDIT_TRAIL_COMPROMISE_REPORT_SCHEME: &str = "pq-key-compromise-report-v1";
pub const PQ_KEY_HEALTH_AUDIT_TRAIL_MIGRATION_HOOK_SCHEME: &str =
    "pq-migration-enforcement-hook-v1";
pub const PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_FRESHNESS_WINDOW_BLOCKS: u64 = 288;
pub const PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_COMMITTEE_WINDOW_BLOCKS: u64 = 96;
pub const PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_BRIDGE_WINDOW_BLOCKS: u64 = 144;
pub const PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_PROVER_WINDOW_BLOCKS: u64 = 192;
pub const PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_WALLET_WINDOW_BLOCKS: u64 = 720;
pub const PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_OPERATOR_WINDOW_BLOCKS: u64 = 240;
pub const PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_CONTRACT_AUTH_WINDOW_BLOCKS: u64 = 128;
pub const PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_ROTATION_GRACE_BLOCKS: u64 = 48;
pub const PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_REPORT_CHALLENGE_BLOCKS: u64 = 64;
pub const PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_MIGRATION_NOTICE_BLOCKS: u64 = 576;
pub const PQ_KEY_HEALTH_AUDIT_TRAIL_MIN_SECURITY_BITS: u16 = 192;
pub const PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_MAX_OPEN_REPORTS_PER_SUBJECT: u64 = 4;
pub const PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_MAX_STALE_SUBJECTS_PER_DOMAIN: u64 = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyDomain {
    WalletRecovery,
    SequencerCommittee,
    BridgeCommittee,
    ProverMarket,
    ContractCallAuthorization,
    OperatorKey,
}

impl KeyDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletRecovery => "wallet_recovery",
            Self::SequencerCommittee => "sequencer_committee",
            Self::BridgeCommittee => "bridge_committee",
            Self::ProverMarket => "prover_market",
            Self::ContractCallAuthorization => "contract_call_authorization",
            Self::OperatorKey => "operator_key",
        }
    }

    pub fn default_freshness_window(self) -> u64 {
        match self {
            Self::WalletRecovery => PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_WALLET_WINDOW_BLOCKS,
            Self::SequencerCommittee => PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_COMMITTEE_WINDOW_BLOCKS,
            Self::BridgeCommittee => PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_BRIDGE_WINDOW_BLOCKS,
            Self::ProverMarket => PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_PROVER_WINDOW_BLOCKS,
            Self::ContractCallAuthorization => {
                PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_CONTRACT_AUTH_WINDOW_BLOCKS
            }
            Self::OperatorKey => PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_OPERATOR_WINDOW_BLOCKS,
        }
    }

    pub fn gates_execution(self) -> bool {
        matches!(
            self,
            Self::SequencerCommittee
                | Self::BridgeCommittee
                | Self::ContractCallAuthorization
                | Self::OperatorKey
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyAlgorithm {
    MlDsa44,
    MlDsa65,
    MlDsa87,
    SlhDsaShake128s,
    SlhDsaShake192s,
    SlhDsaShake256s,
    HybridClassicPq,
    ThresholdPqCommittee,
}

impl KeyAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa44 => "ml_dsa_44",
            Self::MlDsa65 => "ml_dsa_65",
            Self::MlDsa87 => "ml_dsa_87",
            Self::SlhDsaShake128s => "slh_dsa_shake_128s",
            Self::SlhDsaShake192s => "slh_dsa_shake_192s",
            Self::SlhDsaShake256s => "slh_dsa_shake_256s",
            Self::HybridClassicPq => "hybrid_classic_pq",
            Self::ThresholdPqCommittee => "threshold_pq_committee",
        }
    }

    pub fn nominal_security_bits(self) -> u16 {
        match self {
            Self::MlDsa44 | Self::SlhDsaShake128s => 128,
            Self::MlDsa65 | Self::SlhDsaShake192s | Self::HybridClassicPq => 192,
            Self::MlDsa87 | Self::SlhDsaShake256s | Self::ThresholdPqCommittee => 256,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatus {
    Proposed,
    Active,
    RotationDue,
    Rotating,
    Stale,
    Quarantined,
    Revoked,
    Migrated,
    Retired,
}

impl KeyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::RotationDue => "rotation_due",
            Self::Rotating => "rotating",
            Self::Stale => "stale",
            Self::Quarantined => "quarantined",
            Self::Revoked => "revoked",
            Self::Migrated => "migrated",
            Self::Retired => "retired",
        }
    }

    pub fn admits_signing(self) -> bool {
        matches!(self, Self::Active | Self::RotationDue | Self::Rotating)
    }

    pub fn requires_intervention(self) -> bool {
        matches!(self, Self::Stale | Self::Quarantined | Self::Revoked)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessStatus {
    Fresh,
    Warning,
    Expired,
    Grace,
    Paused,
}

impl FreshnessStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Warning => "warning",
            Self::Expired => "expired",
            Self::Grace => "grace",
            Self::Paused => "paused",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationReason {
    Scheduled,
    FreshnessExpired,
    CommitteeReshuffle,
    WalletRecovery,
    CompromiseReport,
    AlgorithmUpgrade,
    OperatorExit,
    MigrationEnforcement,
}

impl RotationReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::FreshnessExpired => "freshness_expired",
            Self::CommitteeReshuffle => "committee_reshuffle",
            Self::WalletRecovery => "wallet_recovery",
            Self::CompromiseReport => "compromise_report",
            Self::AlgorithmUpgrade => "algorithm_upgrade",
            Self::OperatorExit => "operator_exit",
            Self::MigrationEnforcement => "migration_enforcement",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportSeverity {
    Informational,
    Watch,
    Elevated,
    Critical,
    Emergency,
}

impl ReportSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Watch => "watch",
            Self::Elevated => "elevated",
            Self::Critical => "critical",
            Self::Emergency => "emergency",
        }
    }

    pub fn blocks_authorization(self) -> bool {
        matches!(self, Self::Critical | Self::Emergency)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    Submitted,
    Challenged,
    Confirmed,
    Dismissed,
    Remediated,
}

impl ReportStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Challenged => "challenged",
            Self::Confirmed => "confirmed",
            Self::Dismissed => "dismissed",
            Self::Remediated => "remediated",
        }
    }

    pub fn open(self) -> bool {
        matches!(self, Self::Submitted | Self::Challenged | Self::Confirmed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationHookKind {
    Observe,
    Warn,
    RequireRotationReceipt,
    DisableLegacyKey,
    BlockContractCall,
    PauseCommitteeMember,
    RequireRecoveryProof,
    SlashOperatorBond,
}

impl MigrationHookKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Warn => "warn",
            Self::RequireRotationReceipt => "require_rotation_receipt",
            Self::DisableLegacyKey => "disable_legacy_key",
            Self::BlockContractCall => "block_contract_call",
            Self::PauseCommitteeMember => "pause_committee_member",
            Self::RequireRecoveryProof => "require_recovery_proof",
            Self::SlashOperatorBond => "slash_operator_bond",
        }
    }

    pub fn blocks_liveness(self) -> bool {
        matches!(
            self,
            Self::DisableLegacyKey | Self::BlockContractCall | Self::PauseCommitteeMember
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: String,
    pub hash_scheme: String,
    pub rotation_receipt_scheme: String,
    pub revocation_nullifier_scheme: String,
    pub compromise_report_scheme: String,
    pub migration_hook_scheme: String,
    pub min_security_bits: u16,
    pub default_freshness_window_blocks: u64,
    pub wallet_recovery_window_blocks: u64,
    pub sequencer_committee_window_blocks: u64,
    pub bridge_committee_window_blocks: u64,
    pub prover_market_window_blocks: u64,
    pub contract_call_authorization_window_blocks: u64,
    pub operator_key_window_blocks: u64,
    pub rotation_grace_blocks: u64,
    pub report_challenge_blocks: u64,
    pub migration_notice_blocks: u64,
    pub max_open_reports_per_subject: u64,
    pub max_stale_subjects_per_domain: u64,
    pub audit_council_root: String,
    pub emergency_override_root: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PQ_KEY_HEALTH_AUDIT_TRAIL_PROTOCOL_VERSION.to_string(),
            schema_version: PQ_KEY_HEALTH_AUDIT_TRAIL_SCHEMA_VERSION.to_string(),
            hash_scheme: PQ_KEY_HEALTH_AUDIT_TRAIL_HASH_SCHEME.to_string(),
            rotation_receipt_scheme: PQ_KEY_HEALTH_AUDIT_TRAIL_ROTATION_RECEIPT_SCHEME.to_string(),
            revocation_nullifier_scheme: PQ_KEY_HEALTH_AUDIT_TRAIL_REVOCATION_NULLIFIER_SCHEME
                .to_string(),
            compromise_report_scheme: PQ_KEY_HEALTH_AUDIT_TRAIL_COMPROMISE_REPORT_SCHEME
                .to_string(),
            migration_hook_scheme: PQ_KEY_HEALTH_AUDIT_TRAIL_MIGRATION_HOOK_SCHEME.to_string(),
            min_security_bits: PQ_KEY_HEALTH_AUDIT_TRAIL_MIN_SECURITY_BITS,
            default_freshness_window_blocks:
                PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_FRESHNESS_WINDOW_BLOCKS,
            wallet_recovery_window_blocks: PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_WALLET_WINDOW_BLOCKS,
            sequencer_committee_window_blocks:
                PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_COMMITTEE_WINDOW_BLOCKS,
            bridge_committee_window_blocks: PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_BRIDGE_WINDOW_BLOCKS,
            prover_market_window_blocks: PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_PROVER_WINDOW_BLOCKS,
            contract_call_authorization_window_blocks:
                PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_CONTRACT_AUTH_WINDOW_BLOCKS,
            operator_key_window_blocks: PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_OPERATOR_WINDOW_BLOCKS,
            rotation_grace_blocks: PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_ROTATION_GRACE_BLOCKS,
            report_challenge_blocks: PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_REPORT_CHALLENGE_BLOCKS,
            migration_notice_blocks: PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_MIGRATION_NOTICE_BLOCKS,
            max_open_reports_per_subject:
                PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_MAX_OPEN_REPORTS_PER_SUBJECT,
            max_stale_subjects_per_domain:
                PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_MAX_STALE_SUBJECTS_PER_DOMAIN,
            audit_council_root: leaf_hash("PQ-KEY-HEALTH-AUDIT-COUNCIL", "devnet-audit-council"),
            emergency_override_root: merkle_root("PQ-KEY-HEALTH-EMERGENCY-OVERRIDE", &[]),
        }
    }

    pub fn freshness_window_for(&self, domain: KeyDomain) -> u64 {
        match domain {
            KeyDomain::WalletRecovery => self.wallet_recovery_window_blocks,
            KeyDomain::SequencerCommittee => self.sequencer_committee_window_blocks,
            KeyDomain::BridgeCommittee => self.bridge_committee_window_blocks,
            KeyDomain::ProverMarket => self.prover_market_window_blocks,
            KeyDomain::ContractCallAuthorization => self.contract_call_authorization_window_blocks,
            KeyDomain::OperatorKey => self.operator_key_window_blocks,
        }
    }

    pub fn validate(&self) -> PqKeyHealthAuditTrailResult<()> {
        if self.protocol_version != PQ_KEY_HEALTH_AUDIT_TRAIL_PROTOCOL_VERSION {
            return Err("pq key health audit trail protocol version mismatch".to_string());
        }
        if self.schema_version != PQ_KEY_HEALTH_AUDIT_TRAIL_SCHEMA_VERSION {
            return Err("pq key health audit trail schema version mismatch".to_string());
        }
        if self.hash_scheme != PQ_KEY_HEALTH_AUDIT_TRAIL_HASH_SCHEME {
            return Err("pq key health audit trail hash scheme mismatch".to_string());
        }
        if self.rotation_receipt_scheme != PQ_KEY_HEALTH_AUDIT_TRAIL_ROTATION_RECEIPT_SCHEME {
            return Err("pq key health audit trail rotation receipt scheme mismatch".to_string());
        }
        if self.revocation_nullifier_scheme != PQ_KEY_HEALTH_AUDIT_TRAIL_REVOCATION_NULLIFIER_SCHEME
        {
            return Err("pq key health audit trail revocation scheme mismatch".to_string());
        }
        if self.compromise_report_scheme != PQ_KEY_HEALTH_AUDIT_TRAIL_COMPROMISE_REPORT_SCHEME {
            return Err("pq key health audit trail report scheme mismatch".to_string());
        }
        if self.migration_hook_scheme != PQ_KEY_HEALTH_AUDIT_TRAIL_MIGRATION_HOOK_SCHEME {
            return Err("pq key health audit trail migration hook scheme mismatch".to_string());
        }
        if self.min_security_bits < PQ_KEY_HEALTH_AUDIT_TRAIL_MIN_SECURITY_BITS {
            return Err("pq key health audit trail min security bits too low".to_string());
        }
        for (label, window) in [
            (
                "default_freshness_window_blocks",
                self.default_freshness_window_blocks,
            ),
            (
                "wallet_recovery_window_blocks",
                self.wallet_recovery_window_blocks,
            ),
            (
                "sequencer_committee_window_blocks",
                self.sequencer_committee_window_blocks,
            ),
            (
                "bridge_committee_window_blocks",
                self.bridge_committee_window_blocks,
            ),
            (
                "prover_market_window_blocks",
                self.prover_market_window_blocks,
            ),
            (
                "contract_call_authorization_window_blocks",
                self.contract_call_authorization_window_blocks,
            ),
            (
                "operator_key_window_blocks",
                self.operator_key_window_blocks,
            ),
            ("rotation_grace_blocks", self.rotation_grace_blocks),
            ("report_challenge_blocks", self.report_challenge_blocks),
            ("migration_notice_blocks", self.migration_notice_blocks),
        ] {
            if window == 0 {
                return Err(format!("pq key health audit trail {label} must be nonzero"));
            }
        }
        if self.max_open_reports_per_subject == 0 {
            return Err(
                "pq key health audit trail max open reports per subject must be nonzero"
                    .to_string(),
            );
        }
        if self.max_stale_subjects_per_domain == 0 {
            return Err(
                "pq key health audit trail max stale subjects per domain must be nonzero"
                    .to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_scheme": self.hash_scheme,
            "rotation_receipt_scheme": self.rotation_receipt_scheme,
            "revocation_nullifier_scheme": self.revocation_nullifier_scheme,
            "compromise_report_scheme": self.compromise_report_scheme,
            "migration_hook_scheme": self.migration_hook_scheme,
            "min_security_bits": self.min_security_bits.to_string(),
            "default_freshness_window_blocks": self.default_freshness_window_blocks.to_string(),
            "wallet_recovery_window_blocks": self.wallet_recovery_window_blocks.to_string(),
            "sequencer_committee_window_blocks": self.sequencer_committee_window_blocks.to_string(),
            "bridge_committee_window_blocks": self.bridge_committee_window_blocks.to_string(),
            "prover_market_window_blocks": self.prover_market_window_blocks.to_string(),
            "contract_call_authorization_window_blocks": self.contract_call_authorization_window_blocks.to_string(),
            "operator_key_window_blocks": self.operator_key_window_blocks.to_string(),
            "rotation_grace_blocks": self.rotation_grace_blocks.to_string(),
            "report_challenge_blocks": self.report_challenge_blocks.to_string(),
            "migration_notice_blocks": self.migration_notice_blocks.to_string(),
            "max_open_reports_per_subject": self.max_open_reports_per_subject.to_string(),
            "max_stale_subjects_per_domain": self.max_stale_subjects_per_domain.to_string(),
            "audit_council_root": self.audit_council_root,
            "emergency_override_root": self.emergency_override_root,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PQ-KEY-HEALTH-AUDIT-CONFIG",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeySubject {
    pub subject_id: String,
    pub domain: KeyDomain,
    pub owner_commitment: String,
    pub key_commitment: String,
    pub algorithm: KeyAlgorithm,
    pub security_bits: u16,
    pub status: KeyStatus,
    pub activation_height: u64,
    pub last_seen_height: u64,
    pub rotation_due_height: u64,
    pub freshness_window_blocks: u64,
    pub authorization_scope_root: String,
    pub policy_root: String,
    pub migration_label: String,
}

impl KeySubject {
    pub fn validate(&self, config: &Config) -> PqKeyHealthAuditTrailResult<()> {
        require_nonempty("subject_id", &self.subject_id)?;
        require_nonempty("owner_commitment", &self.owner_commitment)?;
        require_nonempty("key_commitment", &self.key_commitment)?;
        require_nonempty("authorization_scope_root", &self.authorization_scope_root)?;
        require_nonempty("policy_root", &self.policy_root)?;
        require_nonempty("migration_label", &self.migration_label)?;
        if self.security_bits < config.min_security_bits {
            return Err(format!(
                "pq key health subject {} security bits below minimum",
                self.subject_id
            ));
        }
        if self.security_bits > self.algorithm.nominal_security_bits() {
            return Err(format!(
                "pq key health subject {} security bits exceed algorithm claim",
                self.subject_id
            ));
        }
        if self.freshness_window_blocks == 0 {
            return Err(format!(
                "pq key health subject {} freshness window must be nonzero",
                self.subject_id
            ));
        }
        if self.rotation_due_height <= self.activation_height {
            return Err(format!(
                "pq key health subject {} rotation due height must follow activation",
                self.subject_id
            ));
        }
        if self.last_seen_height < self.activation_height {
            return Err(format!(
                "pq key health subject {} last seen before activation",
                self.subject_id
            ));
        }
        Ok(())
    }

    pub fn freshness_status(&self, at_height: u64, grace_blocks: u64) -> FreshnessStatus {
        if matches!(self.status, KeyStatus::Quarantined | KeyStatus::Revoked) {
            return FreshnessStatus::Paused;
        }
        let expires_at = self
            .last_seen_height
            .saturating_add(self.freshness_window_blocks);
        if at_height <= expires_at {
            return FreshnessStatus::Fresh;
        }
        if at_height <= expires_at.saturating_add(grace_blocks) {
            return FreshnessStatus::Grace;
        }
        if at_height <= self.rotation_due_height {
            return FreshnessStatus::Warning;
        }
        FreshnessStatus::Expired
    }

    pub fn stale_at(&self, at_height: u64, grace_blocks: u64) -> bool {
        matches!(
            self.freshness_status(at_height, grace_blocks),
            FreshnessStatus::Expired
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "subject_id": self.subject_id,
            "domain": self.domain.as_str(),
            "owner_commitment": self.owner_commitment,
            "key_commitment": self.key_commitment,
            "algorithm": self.algorithm.as_str(),
            "security_bits": self.security_bits.to_string(),
            "status": self.status.as_str(),
            "activation_height": self.activation_height.to_string(),
            "last_seen_height": self.last_seen_height.to_string(),
            "rotation_due_height": self.rotation_due_height.to_string(),
            "freshness_window_blocks": self.freshness_window_blocks.to_string(),
            "authorization_scope_root": self.authorization_scope_root,
            "policy_root": self.policy_root,
            "migration_label": self.migration_label,
        })
    }

    pub fn root(&self) -> String {
        record_hash("PQ-KEY-HEALTH-SUBJECT", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FreshnessObservation {
    pub observation_id: String,
    pub subject_id: String,
    pub domain: KeyDomain,
    pub observed_height: u64,
    pub last_valid_signature_height: u64,
    pub freshness_status: FreshnessStatus,
    pub observer_commitment: String,
    pub witness_root: String,
    pub latency_bucket: String,
    pub liveness_claim_root: String,
}

impl FreshnessObservation {
    pub fn validate(&self) -> PqKeyHealthAuditTrailResult<()> {
        require_nonempty("observation_id", &self.observation_id)?;
        require_nonempty("subject_id", &self.subject_id)?;
        require_nonempty("observer_commitment", &self.observer_commitment)?;
        require_nonempty("witness_root", &self.witness_root)?;
        require_nonempty("latency_bucket", &self.latency_bucket)?;
        require_nonempty("liveness_claim_root", &self.liveness_claim_root)?;
        if self.last_valid_signature_height > self.observed_height {
            return Err(format!(
                "pq key health observation {} has future signature height",
                self.observation_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "subject_id": self.subject_id,
            "domain": self.domain.as_str(),
            "observed_height": self.observed_height.to_string(),
            "last_valid_signature_height": self.last_valid_signature_height.to_string(),
            "freshness_status": self.freshness_status.as_str(),
            "observer_commitment": self.observer_commitment,
            "witness_root": self.witness_root,
            "latency_bucket": self.latency_bucket,
            "liveness_claim_root": self.liveness_claim_root,
        })
    }

    pub fn root(&self) -> String {
        record_hash("PQ-KEY-HEALTH-FRESHNESS-OBSERVATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RotationReceipt {
    pub receipt_id: String,
    pub subject_id: String,
    pub domain: KeyDomain,
    pub old_key_commitment: String,
    pub new_key_commitment: String,
    pub reason: RotationReason,
    pub requested_at_height: u64,
    pub effective_at_height: u64,
    pub expires_at_height: u64,
    pub authorization_root: String,
    pub pq_signature_root: String,
    pub continuity_proof_root: String,
    pub receipt_nullifier: String,
}

impl RotationReceipt {
    pub fn validate(&self) -> PqKeyHealthAuditTrailResult<()> {
        require_nonempty("receipt_id", &self.receipt_id)?;
        require_nonempty("subject_id", &self.subject_id)?;
        require_nonempty("old_key_commitment", &self.old_key_commitment)?;
        require_nonempty("new_key_commitment", &self.new_key_commitment)?;
        require_nonempty("authorization_root", &self.authorization_root)?;
        require_nonempty("pq_signature_root", &self.pq_signature_root)?;
        require_nonempty("continuity_proof_root", &self.continuity_proof_root)?;
        require_nonempty("receipt_nullifier", &self.receipt_nullifier)?;
        if self.old_key_commitment == self.new_key_commitment {
            return Err(format!(
                "pq key health rotation receipt {} must change key commitment",
                self.receipt_id
            ));
        }
        if self.effective_at_height < self.requested_at_height {
            return Err(format!(
                "pq key health rotation receipt {} effective height before request",
                self.receipt_id
            ));
        }
        if self.expires_at_height <= self.effective_at_height {
            return Err(format!(
                "pq key health rotation receipt {} expires before effective height",
                self.receipt_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "subject_id": self.subject_id,
            "domain": self.domain.as_str(),
            "old_key_commitment": self.old_key_commitment,
            "new_key_commitment": self.new_key_commitment,
            "reason": self.reason.as_str(),
            "requested_at_height": self.requested_at_height.to_string(),
            "effective_at_height": self.effective_at_height.to_string(),
            "expires_at_height": self.expires_at_height.to_string(),
            "authorization_root": self.authorization_root,
            "pq_signature_root": self.pq_signature_root,
            "continuity_proof_root": self.continuity_proof_root,
            "receipt_nullifier": self.receipt_nullifier,
        })
    }

    pub fn root(&self) -> String {
        record_hash("PQ-KEY-HEALTH-ROTATION-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompromiseReport {
    pub report_id: String,
    pub subject_id: String,
    pub domain: KeyDomain,
    pub severity: ReportSeverity,
    pub status: ReportStatus,
    pub reporter_commitment: String,
    pub evidence_root: String,
    pub affected_key_commitment: String,
    pub submitted_at_height: u64,
    pub challenge_until_height: u64,
    pub remediation_due_height: u64,
    pub quarantine_required: bool,
}

impl CompromiseReport {
    pub fn validate(&self) -> PqKeyHealthAuditTrailResult<()> {
        require_nonempty("report_id", &self.report_id)?;
        require_nonempty("subject_id", &self.subject_id)?;
        require_nonempty("reporter_commitment", &self.reporter_commitment)?;
        require_nonempty("evidence_root", &self.evidence_root)?;
        require_nonempty("affected_key_commitment", &self.affected_key_commitment)?;
        if self.challenge_until_height < self.submitted_at_height {
            return Err(format!(
                "pq key health report {} challenge height before submission",
                self.report_id
            ));
        }
        if self.remediation_due_height < self.challenge_until_height {
            return Err(format!(
                "pq key health report {} remediation due before challenge closes",
                self.report_id
            ));
        }
        Ok(())
    }

    pub fn blocks_authorization(&self) -> bool {
        self.quarantine_required || self.severity.blocks_authorization()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "report_id": self.report_id,
            "subject_id": self.subject_id,
            "domain": self.domain.as_str(),
            "severity": self.severity.as_str(),
            "status": self.status.as_str(),
            "reporter_commitment": self.reporter_commitment,
            "evidence_root": self.evidence_root,
            "affected_key_commitment": self.affected_key_commitment,
            "submitted_at_height": self.submitted_at_height.to_string(),
            "challenge_until_height": self.challenge_until_height.to_string(),
            "remediation_due_height": self.remediation_due_height.to_string(),
            "quarantine_required": self.quarantine_required,
        })
    }

    pub fn root(&self) -> String {
        record_hash("PQ-KEY-HEALTH-COMPROMISE-REPORT", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevocationNullifier {
    pub nullifier_id: String,
    pub subject_id: String,
    pub domain: KeyDomain,
    pub key_commitment: String,
    pub report_id: String,
    pub rotation_receipt_id: String,
    pub revoked_at_height: u64,
    pub authority_commitment: String,
    pub nullifier_root: String,
    pub burn_receipt_root: String,
}

impl RevocationNullifier {
    pub fn validate(&self) -> PqKeyHealthAuditTrailResult<()> {
        require_nonempty("nullifier_id", &self.nullifier_id)?;
        require_nonempty("subject_id", &self.subject_id)?;
        require_nonempty("key_commitment", &self.key_commitment)?;
        require_nonempty("report_id", &self.report_id)?;
        require_nonempty("rotation_receipt_id", &self.rotation_receipt_id)?;
        require_nonempty("authority_commitment", &self.authority_commitment)?;
        require_nonempty("nullifier_root", &self.nullifier_root)?;
        require_nonempty("burn_receipt_root", &self.burn_receipt_root)?;
        if self.revoked_at_height == 0 {
            return Err(format!(
                "pq key health revocation {} height must be nonzero",
                self.nullifier_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "nullifier_id": self.nullifier_id,
            "subject_id": self.subject_id,
            "domain": self.domain.as_str(),
            "key_commitment": self.key_commitment,
            "report_id": self.report_id,
            "rotation_receipt_id": self.rotation_receipt_id,
            "revoked_at_height": self.revoked_at_height.to_string(),
            "authority_commitment": self.authority_commitment,
            "nullifier_root": self.nullifier_root,
            "burn_receipt_root": self.burn_receipt_root,
        })
    }

    pub fn root(&self) -> String {
        record_hash("PQ-KEY-HEALTH-REVOCATION-NULLIFIER", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MigrationHook {
    pub hook_id: String,
    pub subject_id: String,
    pub domain: KeyDomain,
    pub hook_kind: MigrationHookKind,
    pub trigger_height: u64,
    pub enforced_until_height: u64,
    pub source_module: String,
    pub decision_root: String,
    pub authorization_root: String,
    pub resulting_status: KeyStatus,
}

impl MigrationHook {
    pub fn validate(&self) -> PqKeyHealthAuditTrailResult<()> {
        require_nonempty("hook_id", &self.hook_id)?;
        require_nonempty("subject_id", &self.subject_id)?;
        require_nonempty("source_module", &self.source_module)?;
        require_nonempty("decision_root", &self.decision_root)?;
        require_nonempty("authorization_root", &self.authorization_root)?;
        if self.enforced_until_height < self.trigger_height {
            return Err(format!(
                "pq key health migration hook {} ends before trigger",
                self.hook_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hook_id": self.hook_id,
            "subject_id": self.subject_id,
            "domain": self.domain.as_str(),
            "hook_kind": self.hook_kind.as_str(),
            "trigger_height": self.trigger_height.to_string(),
            "enforced_until_height": self.enforced_until_height.to_string(),
            "source_module": self.source_module,
            "decision_root": self.decision_root,
            "authorization_root": self.authorization_root,
            "resulting_status": self.resulting_status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        record_hash("PQ-KEY-HEALTH-MIGRATION-HOOK", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnforcementDecision {
    pub decision_id: String,
    pub subject_id: String,
    pub domain: KeyDomain,
    pub at_height: u64,
    pub freshness_status: FreshnessStatus,
    pub key_status: KeyStatus,
    pub blocking_report_root: String,
    pub migration_hook_root: String,
    pub allowed: bool,
    pub reason_code: String,
}

impl EnforcementDecision {
    pub fn validate(&self) -> PqKeyHealthAuditTrailResult<()> {
        require_nonempty("decision_id", &self.decision_id)?;
        require_nonempty("subject_id", &self.subject_id)?;
        require_nonempty("blocking_report_root", &self.blocking_report_root)?;
        require_nonempty("migration_hook_root", &self.migration_hook_root)?;
        require_nonempty("reason_code", &self.reason_code)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "decision_id": self.decision_id,
            "subject_id": self.subject_id,
            "domain": self.domain.as_str(),
            "at_height": self.at_height.to_string(),
            "freshness_status": self.freshness_status.as_str(),
            "key_status": self.key_status.as_str(),
            "blocking_report_root": self.blocking_report_root,
            "migration_hook_root": self.migration_hook_root,
            "allowed": self.allowed,
            "reason_code": self.reason_code,
        })
    }

    pub fn root(&self) -> String {
        record_hash("PQ-KEY-HEALTH-ENFORCEMENT-DECISION", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainHealthSummary {
    pub domain: KeyDomain,
    pub active_subjects: u64,
    pub stale_subjects: u64,
    pub quarantined_subjects: u64,
    pub revoked_subjects: u64,
    pub open_reports: u64,
    pub pending_rotations: u64,
    pub blocking_hooks: u64,
    pub latest_observation_height: u64,
}

impl DomainHealthSummary {
    pub fn empty(domain: KeyDomain) -> Self {
        Self {
            domain,
            active_subjects: 0,
            stale_subjects: 0,
            quarantined_subjects: 0,
            revoked_subjects: 0,
            open_reports: 0,
            pending_rotations: 0,
            blocking_hooks: 0,
            latest_observation_height: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "domain": self.domain.as_str(),
            "active_subjects": self.active_subjects.to_string(),
            "stale_subjects": self.stale_subjects.to_string(),
            "quarantined_subjects": self.quarantined_subjects.to_string(),
            "revoked_subjects": self.revoked_subjects.to_string(),
            "open_reports": self.open_reports.to_string(),
            "pending_rotations": self.pending_rotations.to_string(),
            "blocking_hooks": self.blocking_hooks.to_string(),
            "latest_observation_height": self.latest_observation_height.to_string(),
        })
    }

    pub fn root(&self) -> String {
        record_hash("PQ-KEY-HEALTH-DOMAIN-SUMMARY", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub subject_root: String,
    pub freshness_root: String,
    pub rotation_root: String,
    pub compromise_report_root: String,
    pub revocation_nullifier_root: String,
    pub migration_hook_root: String,
    pub enforcement_decision_root: String,
    pub domain_summary_root: String,
    pub audit_event_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "subject_root": self.subject_root,
            "freshness_root": self.freshness_root,
            "rotation_root": self.rotation_root,
            "compromise_report_root": self.compromise_report_root,
            "revocation_nullifier_root": self.revocation_nullifier_root,
            "migration_hook_root": self.migration_hook_root,
            "enforcement_decision_root": self.enforcement_decision_root,
            "domain_summary_root": self.domain_summary_root,
            "audit_event_root": self.audit_event_root,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PQ-KEY-HEALTH-AUDIT-ROOTS",
            &[
                HashPart::Str(PQ_KEY_HEALTH_AUDIT_TRAIL_PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Counters {
    pub subjects: u64,
    pub freshness_observations: u64,
    pub rotation_receipts: u64,
    pub compromise_reports: u64,
    pub revocation_nullifiers: u64,
    pub migration_hooks: u64,
    pub enforcement_decisions: u64,
    pub active_subjects: u64,
    pub stale_subjects: u64,
    pub quarantined_subjects: u64,
    pub revoked_subjects: u64,
    pub open_reports: u64,
    pub blocking_migration_hooks: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "subjects": self.subjects.to_string(),
            "freshness_observations": self.freshness_observations.to_string(),
            "rotation_receipts": self.rotation_receipts.to_string(),
            "compromise_reports": self.compromise_reports.to_string(),
            "revocation_nullifiers": self.revocation_nullifiers.to_string(),
            "migration_hooks": self.migration_hooks.to_string(),
            "enforcement_decisions": self.enforcement_decisions.to_string(),
            "active_subjects": self.active_subjects.to_string(),
            "stale_subjects": self.stale_subjects.to_string(),
            "quarantined_subjects": self.quarantined_subjects.to_string(),
            "revoked_subjects": self.revoked_subjects.to_string(),
            "open_reports": self.open_reports.to_string(),
            "blocking_migration_hooks": self.blocking_migration_hooks.to_string(),
        })
    }

    pub fn root(&self) -> String {
        record_hash("PQ-KEY-HEALTH-AUDIT-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub subjects: Vec<KeySubject>,
    pub freshness_observations: Vec<FreshnessObservation>,
    pub rotation_receipts: Vec<RotationReceipt>,
    pub compromise_reports: Vec<CompromiseReport>,
    pub revocation_nullifiers: Vec<RevocationNullifier>,
    pub migration_hooks: Vec<MigrationHook>,
    pub enforcement_decisions: Vec<EnforcementDecision>,
    pub domain_summaries: Vec<DomainHealthSummary>,
    pub audit_events: Vec<Value>,
}

impl State {
    pub fn devnet() -> PqKeyHealthAuditTrailResult<Self> {
        let config = Config::devnet();
        let mut state = Self {
            height: 2_400,
            config,
            subjects: devnet_subjects(),
            freshness_observations: devnet_freshness_observations(),
            rotation_receipts: devnet_rotation_receipts(),
            compromise_reports: devnet_compromise_reports(),
            revocation_nullifiers: devnet_revocation_nullifiers(),
            migration_hooks: devnet_migration_hooks(),
            enforcement_decisions: devnet_enforcement_decisions(),
            domain_summaries: Vec::new(),
            audit_events: devnet_audit_events(),
        };
        state.recompute_domain_summaries();
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> PqKeyHealthAuditTrailResult<()> {
        self.config.validate()?;
        let mut subject_ids = BTreeSet::new();
        let mut key_commitments = BTreeSet::new();
        let mut open_report_counts: BTreeMap<String, u64> = BTreeMap::new();
        let mut stale_counts: BTreeMap<KeyDomain, u64> = BTreeMap::new();
        for subject in &self.subjects {
            subject.validate(&self.config)?;
            if !subject_ids.insert(subject.subject_id.clone()) {
                return Err(format!(
                    "pq key health duplicate subject {}",
                    subject.subject_id
                ));
            }
            if !key_commitments.insert(subject.key_commitment.clone()) {
                return Err(format!(
                    "pq key health duplicate key commitment {}",
                    subject.key_commitment
                ));
            }
            if subject.stale_at(self.height, self.config.rotation_grace_blocks) {
                let count = stale_counts.entry(subject.domain).or_insert(0);
                *count = count.saturating_add(1);
            }
        }
        for observation in &self.freshness_observations {
            observation.validate()?;
            require_subject(
                &subject_ids,
                &observation.subject_id,
                "freshness observation",
            )?;
            if observation.observed_height > self.height {
                return Err(format!(
                    "pq key health observation {} above state height",
                    observation.observation_id
                ));
            }
        }
        let mut receipt_ids = BTreeSet::new();
        for receipt in &self.rotation_receipts {
            receipt.validate()?;
            require_subject(&subject_ids, &receipt.subject_id, "rotation receipt")?;
            if !receipt_ids.insert(receipt.receipt_id.clone()) {
                return Err(format!(
                    "pq key health duplicate rotation receipt {}",
                    receipt.receipt_id
                ));
            }
        }
        let mut report_ids = BTreeSet::new();
        for report in &self.compromise_reports {
            report.validate()?;
            require_subject(&subject_ids, &report.subject_id, "compromise report")?;
            if !report_ids.insert(report.report_id.clone()) {
                return Err(format!(
                    "pq key health duplicate compromise report {}",
                    report.report_id
                ));
            }
            if report.status.open() {
                let count = open_report_counts
                    .entry(report.subject_id.clone())
                    .or_insert(0);
                *count = count.saturating_add(1);
            }
        }
        for (subject_id, count) in open_report_counts {
            if count > self.config.max_open_reports_per_subject {
                return Err(format!(
                    "pq key health subject {subject_id} has too many open reports"
                ));
            }
        }
        for (domain, count) in stale_counts {
            if count > self.config.max_stale_subjects_per_domain {
                return Err(format!(
                    "pq key health domain {} has too many stale subjects",
                    domain.as_str()
                ));
            }
        }
        let mut nullifier_ids = BTreeSet::new();
        for nullifier in &self.revocation_nullifiers {
            nullifier.validate()?;
            require_subject(&subject_ids, &nullifier.subject_id, "revocation nullifier")?;
            if !report_ids.contains(&nullifier.report_id) {
                return Err(format!(
                    "pq key health revocation {} references unknown report {}",
                    nullifier.nullifier_id, nullifier.report_id
                ));
            }
            if !receipt_ids.contains(&nullifier.rotation_receipt_id) {
                return Err(format!(
                    "pq key health revocation {} references unknown rotation {}",
                    nullifier.nullifier_id, nullifier.rotation_receipt_id
                ));
            }
            if !nullifier_ids.insert(nullifier.nullifier_id.clone()) {
                return Err(format!(
                    "pq key health duplicate revocation nullifier {}",
                    nullifier.nullifier_id
                ));
            }
        }
        let mut hook_ids = BTreeSet::new();
        for hook in &self.migration_hooks {
            hook.validate()?;
            require_subject(&subject_ids, &hook.subject_id, "migration hook")?;
            if !hook_ids.insert(hook.hook_id.clone()) {
                return Err(format!(
                    "pq key health duplicate migration hook {}",
                    hook.hook_id
                ));
            }
        }
        let mut decision_ids = BTreeSet::new();
        for decision in &self.enforcement_decisions {
            decision.validate()?;
            require_subject(&subject_ids, &decision.subject_id, "enforcement decision")?;
            if !decision_ids.insert(decision.decision_id.clone()) {
                return Err(format!(
                    "pq key health duplicate enforcement decision {}",
                    decision.decision_id
                ));
            }
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> PqKeyHealthAuditTrailResult<()> {
        self.height = height;
        self.recompute_domain_summaries();
        self.validate()
    }

    pub fn update_height(&mut self, height: u64) -> PqKeyHealthAuditTrailResult<()> {
        self.set_height(height)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.root(),
            subject_root: merkle_root(
                "PQ-KEY-HEALTH-SUBJECTS",
                &records_from(self.subjects.iter().map(KeySubject::public_record)),
            ),
            freshness_root: merkle_root(
                "PQ-KEY-HEALTH-FRESHNESS",
                &records_from(
                    self.freshness_observations
                        .iter()
                        .map(FreshnessObservation::public_record),
                ),
            ),
            rotation_root: merkle_root(
                "PQ-KEY-HEALTH-ROTATIONS",
                &records_from(
                    self.rotation_receipts
                        .iter()
                        .map(RotationReceipt::public_record),
                ),
            ),
            compromise_report_root: merkle_root(
                "PQ-KEY-HEALTH-REPORTS",
                &records_from(
                    self.compromise_reports
                        .iter()
                        .map(CompromiseReport::public_record),
                ),
            ),
            revocation_nullifier_root: merkle_root(
                "PQ-KEY-HEALTH-REVOCATIONS",
                &records_from(
                    self.revocation_nullifiers
                        .iter()
                        .map(RevocationNullifier::public_record),
                ),
            ),
            migration_hook_root: merkle_root(
                "PQ-KEY-HEALTH-MIGRATION-HOOKS",
                &records_from(
                    self.migration_hooks
                        .iter()
                        .map(MigrationHook::public_record),
                ),
            ),
            enforcement_decision_root: merkle_root(
                "PQ-KEY-HEALTH-ENFORCEMENT-DECISIONS",
                &records_from(
                    self.enforcement_decisions
                        .iter()
                        .map(EnforcementDecision::public_record),
                ),
            ),
            domain_summary_root: merkle_root(
                "PQ-KEY-HEALTH-DOMAIN-SUMMARIES",
                &records_from(
                    self.domain_summaries
                        .iter()
                        .map(DomainHealthSummary::public_record),
                ),
            ),
            audit_event_root: merkle_root("PQ-KEY-HEALTH-AUDIT-EVENTS", &self.audit_events),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            subjects: self.subjects.len() as u64,
            freshness_observations: self.freshness_observations.len() as u64,
            rotation_receipts: self.rotation_receipts.len() as u64,
            compromise_reports: self.compromise_reports.len() as u64,
            revocation_nullifiers: self.revocation_nullifiers.len() as u64,
            migration_hooks: self.migration_hooks.len() as u64,
            enforcement_decisions: self.enforcement_decisions.len() as u64,
            active_subjects: self
                .subjects
                .iter()
                .filter(|subject| subject.status.admits_signing())
                .count() as u64,
            stale_subjects: self
                .subjects
                .iter()
                .filter(|subject| subject.stale_at(self.height, self.config.rotation_grace_blocks))
                .count() as u64,
            quarantined_subjects: self
                .subjects
                .iter()
                .filter(|subject| subject.status == KeyStatus::Quarantined)
                .count() as u64,
            revoked_subjects: self
                .subjects
                .iter()
                .filter(|subject| subject.status == KeyStatus::Revoked)
                .count() as u64,
            open_reports: self
                .compromise_reports
                .iter()
                .filter(|report| report.status.open())
                .count() as u64,
            blocking_migration_hooks: self
                .migration_hooks
                .iter()
                .filter(|hook| hook.hook_kind.blocks_liveness())
                .count() as u64,
        }
    }

    pub fn state_root(&self) -> String {
        let roots = self.roots();
        let counters = self.counters();
        let record = json!({
            "protocol_version": PQ_KEY_HEALTH_AUDIT_TRAIL_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height.to_string(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
        });
        root_from_record(&record)
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "protocol_version": PQ_KEY_HEALTH_AUDIT_TRAIL_PROTOCOL_VERSION,
            "schema_version": PQ_KEY_HEALTH_AUDIT_TRAIL_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height.to_string(),
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "state_root": self.state_root(),
            "subjects": records_from(self.subjects.iter().map(KeySubject::public_record)),
            "freshness_observations": records_from(self.freshness_observations.iter().map(FreshnessObservation::public_record)),
            "rotation_receipts": records_from(self.rotation_receipts.iter().map(RotationReceipt::public_record)),
            "compromise_reports": records_from(self.compromise_reports.iter().map(CompromiseReport::public_record)),
            "revocation_nullifiers": records_from(self.revocation_nullifiers.iter().map(RevocationNullifier::public_record)),
            "migration_hooks": records_from(self.migration_hooks.iter().map(MigrationHook::public_record)),
            "enforcement_decisions": records_from(self.enforcement_decisions.iter().map(EnforcementDecision::public_record)),
            "domain_summaries": records_from(self.domain_summaries.iter().map(DomainHealthSummary::public_record)),
            "audit_events": self.audit_events,
        })
    }

    fn recompute_domain_summaries(&mut self) {
        let mut summaries = BTreeMap::new();
        for domain in [
            KeyDomain::WalletRecovery,
            KeyDomain::SequencerCommittee,
            KeyDomain::BridgeCommittee,
            KeyDomain::ProverMarket,
            KeyDomain::ContractCallAuthorization,
            KeyDomain::OperatorKey,
        ] {
            summaries.insert(domain, DomainHealthSummary::empty(domain));
        }
        for subject in &self.subjects {
            if let Some(summary) = summaries.get_mut(&subject.domain) {
                if subject.status.admits_signing() {
                    summary.active_subjects = summary.active_subjects.saturating_add(1);
                }
                if subject.stale_at(self.height, self.config.rotation_grace_blocks) {
                    summary.stale_subjects = summary.stale_subjects.saturating_add(1);
                }
                if subject.status == KeyStatus::Quarantined {
                    summary.quarantined_subjects = summary.quarantined_subjects.saturating_add(1);
                }
                if subject.status == KeyStatus::Revoked {
                    summary.revoked_subjects = summary.revoked_subjects.saturating_add(1);
                }
            }
        }
        for report in &self.compromise_reports {
            if report.status.open() {
                if let Some(summary) = summaries.get_mut(&report.domain) {
                    summary.open_reports = summary.open_reports.saturating_add(1);
                }
            }
        }
        for receipt in &self.rotation_receipts {
            if receipt.effective_at_height >= self.height {
                if let Some(summary) = summaries.get_mut(&receipt.domain) {
                    summary.pending_rotations = summary.pending_rotations.saturating_add(1);
                }
            }
        }
        for hook in &self.migration_hooks {
            if hook.hook_kind.blocks_liveness() {
                if let Some(summary) = summaries.get_mut(&hook.domain) {
                    summary.blocking_hooks = summary.blocking_hooks.saturating_add(1);
                }
            }
        }
        for observation in &self.freshness_observations {
            if let Some(summary) = summaries.get_mut(&observation.domain) {
                summary.latest_observation_height = summary
                    .latest_observation_height
                    .max(observation.observed_height);
            }
        }
        self.domain_summaries = summaries.into_values().collect();
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "PQ-KEY-HEALTH-AUDIT-STATE",
        &[
            HashPart::Str(PQ_KEY_HEALTH_AUDIT_TRAIL_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn devnet() -> PqKeyHealthAuditTrailResult<State> {
    State::devnet()
}

fn require_nonempty(label: &str, value: &str) -> PqKeyHealthAuditTrailResult<()> {
    if value.is_empty() {
        return Err(format!(
            "pq key health audit trail {label} must be nonempty"
        ));
    }
    Ok(())
}

fn require_subject(
    subject_ids: &BTreeSet<String>,
    subject_id: &str,
    context: &str,
) -> PqKeyHealthAuditTrailResult<()> {
    if !subject_ids.contains(subject_id) {
        return Err(format!(
            "pq key health {context} references unknown subject {subject_id}"
        ));
    }
    Ok(())
}

fn records_from<I>(records: I) -> Vec<Value>
where
    I: Iterator<Item = Value>,
{
    records.collect()
}

fn record_hash(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PQ_KEY_HEALTH_AUDIT_TRAIL_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

fn leaf_hash(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PQ_KEY_HEALTH_AUDIT_TRAIL_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(value),
        ],
        32,
    )
}

fn devnet_subjects() -> Vec<KeySubject> {
    vec![
        devnet_subject(
            "wallet-recovery-alpha",
            KeyDomain::WalletRecovery,
            "wallet-alpha-owner",
            "wallet-alpha-pq-key",
            KeyAlgorithm::HybridClassicPq,
            KeyStatus::Active,
            1_080,
            2_250,
            2_980,
            "wallet-recovery",
        ),
        devnet_subject(
            "sequencer-committee-alpha",
            KeyDomain::SequencerCommittee,
            "sequencer-alpha-owner",
            "sequencer-alpha-pq-key",
            KeyAlgorithm::ThresholdPqCommittee,
            KeyStatus::RotationDue,
            1_920,
            2_352,
            2_448,
            "sequencer-committee",
        ),
        devnet_subject(
            "bridge-committee-alpha",
            KeyDomain::BridgeCommittee,
            "bridge-alpha-owner",
            "bridge-alpha-pq-key",
            KeyAlgorithm::MlDsa87,
            KeyStatus::Rotating,
            1_760,
            2_304,
            2_496,
            "bridge-committee",
        ),
        devnet_subject(
            "prover-market-alpha",
            KeyDomain::ProverMarket,
            "prover-alpha-owner",
            "prover-alpha-pq-key",
            KeyAlgorithm::MlDsa65,
            KeyStatus::Active,
            1_600,
            2_280,
            2_640,
            "prover-market",
        ),
        devnet_subject(
            "contract-auth-alpha",
            KeyDomain::ContractCallAuthorization,
            "contract-auth-alpha-owner",
            "contract-auth-alpha-pq-key",
            KeyAlgorithm::SlhDsaShake192s,
            KeyStatus::Quarantined,
            1_990,
            2_040,
            2_180,
            "contract-auth",
        ),
        devnet_subject(
            "operator-key-alpha",
            KeyDomain::OperatorKey,
            "operator-alpha-owner",
            "operator-alpha-pq-key",
            KeyAlgorithm::MlDsa87,
            KeyStatus::Active,
            1_880,
            2_398,
            2_760,
            "operator-key",
        ),
    ]
}

fn devnet_subject(
    subject_id: &str,
    domain: KeyDomain,
    owner_seed: &str,
    key_seed: &str,
    algorithm: KeyAlgorithm,
    status: KeyStatus,
    activation_height: u64,
    last_seen_height: u64,
    rotation_due_height: u64,
    migration_label: &str,
) -> KeySubject {
    KeySubject {
        subject_id: subject_id.to_string(),
        domain,
        owner_commitment: leaf_hash("PQ-KEY-HEALTH-OWNER", owner_seed),
        key_commitment: leaf_hash("PQ-KEY-HEALTH-KEY", key_seed),
        algorithm,
        security_bits: algorithm.nominal_security_bits(),
        status,
        activation_height,
        last_seen_height,
        rotation_due_height,
        freshness_window_blocks: domain.default_freshness_window(),
        authorization_scope_root: leaf_hash("PQ-KEY-HEALTH-AUTH-SCOPE", subject_id),
        policy_root: leaf_hash("PQ-KEY-HEALTH-POLICY", migration_label),
        migration_label: migration_label.to_string(),
    }
}

fn devnet_freshness_observations() -> Vec<FreshnessObservation> {
    vec![
        devnet_observation(
            "freshness-wallet-alpha-2400",
            "wallet-recovery-alpha",
            KeyDomain::WalletRecovery,
            2_400,
            2_250,
            FreshnessStatus::Fresh,
            "watcher-wallet-alpha",
        ),
        devnet_observation(
            "freshness-sequencer-alpha-2400",
            "sequencer-committee-alpha",
            KeyDomain::SequencerCommittee,
            2_400,
            2_352,
            FreshnessStatus::Fresh,
            "watcher-sequencer-alpha",
        ),
        devnet_observation(
            "freshness-bridge-alpha-2400",
            "bridge-committee-alpha",
            KeyDomain::BridgeCommittee,
            2_400,
            2_304,
            FreshnessStatus::Grace,
            "watcher-bridge-alpha",
        ),
        devnet_observation(
            "freshness-prover-alpha-2400",
            "prover-market-alpha",
            KeyDomain::ProverMarket,
            2_400,
            2_280,
            FreshnessStatus::Fresh,
            "watcher-prover-alpha",
        ),
        devnet_observation(
            "freshness-contract-auth-alpha-2400",
            "contract-auth-alpha",
            KeyDomain::ContractCallAuthorization,
            2_400,
            2_040,
            FreshnessStatus::Paused,
            "watcher-contract-alpha",
        ),
        devnet_observation(
            "freshness-operator-alpha-2400",
            "operator-key-alpha",
            KeyDomain::OperatorKey,
            2_400,
            2_398,
            FreshnessStatus::Fresh,
            "watcher-operator-alpha",
        ),
    ]
}

fn devnet_observation(
    observation_id: &str,
    subject_id: &str,
    domain: KeyDomain,
    observed_height: u64,
    last_valid_signature_height: u64,
    freshness_status: FreshnessStatus,
    observer_seed: &str,
) -> FreshnessObservation {
    FreshnessObservation {
        observation_id: observation_id.to_string(),
        subject_id: subject_id.to_string(),
        domain,
        observed_height,
        last_valid_signature_height,
        freshness_status,
        observer_commitment: leaf_hash("PQ-KEY-HEALTH-OBSERVER", observer_seed),
        witness_root: leaf_hash("PQ-KEY-HEALTH-FRESHNESS-WITNESS", observation_id),
        latency_bucket: "devnet-fast".to_string(),
        liveness_claim_root: leaf_hash("PQ-KEY-HEALTH-LIVENESS-CLAIM", subject_id),
    }
}

fn devnet_rotation_receipts() -> Vec<RotationReceipt> {
    vec![
        devnet_rotation(
            "rotation-sequencer-alpha-2448",
            "sequencer-committee-alpha",
            KeyDomain::SequencerCommittee,
            "sequencer-alpha-pq-key",
            "sequencer-alpha-pq-key-next",
            RotationReason::CommitteeReshuffle,
            2_352,
            2_448,
            2_640,
        ),
        devnet_rotation(
            "rotation-bridge-alpha-2496",
            "bridge-committee-alpha",
            KeyDomain::BridgeCommittee,
            "bridge-alpha-pq-key",
            "bridge-alpha-pq-key-next",
            RotationReason::FreshnessExpired,
            2_304,
            2_496,
            2_688,
        ),
        devnet_rotation(
            "rotation-contract-auth-alpha-2180",
            "contract-auth-alpha",
            KeyDomain::ContractCallAuthorization,
            "contract-auth-alpha-pq-key",
            "contract-auth-alpha-pq-key-next",
            RotationReason::CompromiseReport,
            2_092,
            2_180,
            2_420,
        ),
    ]
}

fn devnet_rotation(
    receipt_id: &str,
    subject_id: &str,
    domain: KeyDomain,
    old_key_seed: &str,
    new_key_seed: &str,
    reason: RotationReason,
    requested_at_height: u64,
    effective_at_height: u64,
    expires_at_height: u64,
) -> RotationReceipt {
    RotationReceipt {
        receipt_id: receipt_id.to_string(),
        subject_id: subject_id.to_string(),
        domain,
        old_key_commitment: leaf_hash("PQ-KEY-HEALTH-KEY", old_key_seed),
        new_key_commitment: leaf_hash("PQ-KEY-HEALTH-KEY", new_key_seed),
        reason,
        requested_at_height,
        effective_at_height,
        expires_at_height,
        authorization_root: leaf_hash("PQ-KEY-HEALTH-ROTATION-AUTH", receipt_id),
        pq_signature_root: leaf_hash("PQ-KEY-HEALTH-ROTATION-SIG", receipt_id),
        continuity_proof_root: leaf_hash("PQ-KEY-HEALTH-CONTINUITY", subject_id),
        receipt_nullifier: leaf_hash("PQ-KEY-HEALTH-RECEIPT-NULLIFIER", receipt_id),
    }
}

fn devnet_compromise_reports() -> Vec<CompromiseReport> {
    vec![
        devnet_report(
            "report-contract-auth-alpha-2092",
            "contract-auth-alpha",
            KeyDomain::ContractCallAuthorization,
            ReportSeverity::Critical,
            ReportStatus::Confirmed,
            "contract-auth-alpha-pq-key",
            2_092,
            true,
        ),
        devnet_report(
            "report-bridge-alpha-watch-2360",
            "bridge-committee-alpha",
            KeyDomain::BridgeCommittee,
            ReportSeverity::Watch,
            ReportStatus::Submitted,
            "bridge-alpha-pq-key",
            2_360,
            false,
        ),
    ]
}

fn devnet_report(
    report_id: &str,
    subject_id: &str,
    domain: KeyDomain,
    severity: ReportSeverity,
    status: ReportStatus,
    key_seed: &str,
    submitted_at_height: u64,
    quarantine_required: bool,
) -> CompromiseReport {
    CompromiseReport {
        report_id: report_id.to_string(),
        subject_id: subject_id.to_string(),
        domain,
        severity,
        status,
        reporter_commitment: leaf_hash("PQ-KEY-HEALTH-REPORTER", report_id),
        evidence_root: leaf_hash("PQ-KEY-HEALTH-REPORT-EVIDENCE", report_id),
        affected_key_commitment: leaf_hash("PQ-KEY-HEALTH-KEY", key_seed),
        submitted_at_height,
        challenge_until_height: submitted_at_height
            .saturating_add(PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_REPORT_CHALLENGE_BLOCKS),
        remediation_due_height: submitted_at_height
            .saturating_add(PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_REPORT_CHALLENGE_BLOCKS)
            .saturating_add(PQ_KEY_HEALTH_AUDIT_TRAIL_DEFAULT_ROTATION_GRACE_BLOCKS),
        quarantine_required,
    }
}

fn devnet_revocation_nullifiers() -> Vec<RevocationNullifier> {
    vec![RevocationNullifier {
        nullifier_id: "revocation-contract-auth-alpha-2180".to_string(),
        subject_id: "contract-auth-alpha".to_string(),
        domain: KeyDomain::ContractCallAuthorization,
        key_commitment: leaf_hash("PQ-KEY-HEALTH-KEY", "contract-auth-alpha-pq-key"),
        report_id: "report-contract-auth-alpha-2092".to_string(),
        rotation_receipt_id: "rotation-contract-auth-alpha-2180".to_string(),
        revoked_at_height: 2_180,
        authority_commitment: leaf_hash("PQ-KEY-HEALTH-REVOCATION-AUTHORITY", "devnet-council"),
        nullifier_root: leaf_hash(
            "PQ-KEY-HEALTH-REVOCATION-NULLIFIER",
            "contract-auth-alpha-2180",
        ),
        burn_receipt_root: leaf_hash("PQ-KEY-HEALTH-BURN-RECEIPT", "contract-auth-alpha-2180"),
    }]
}

fn devnet_migration_hooks() -> Vec<MigrationHook> {
    vec![
        devnet_hook(
            "hook-contract-auth-alpha-block",
            "contract-auth-alpha",
            KeyDomain::ContractCallAuthorization,
            MigrationHookKind::BlockContractCall,
            2_092,
            2_420,
            "pq_private_contract_call_authorization_layer",
            KeyStatus::Quarantined,
        ),
        devnet_hook(
            "hook-sequencer-alpha-receipt",
            "sequencer-committee-alpha",
            KeyDomain::SequencerCommittee,
            MigrationHookKind::RequireRotationReceipt,
            2_352,
            2_640,
            "pq_sequencer_committee_rotation",
            KeyStatus::RotationDue,
        ),
        devnet_hook(
            "hook-wallet-alpha-recovery-proof",
            "wallet-recovery-alpha",
            KeyDomain::WalletRecovery,
            MigrationHookKind::RequireRecoveryProof,
            2_250,
            2_980,
            "quantum_safe_wallet_social_recovery_guard",
            KeyStatus::Active,
        ),
    ]
}

fn devnet_hook(
    hook_id: &str,
    subject_id: &str,
    domain: KeyDomain,
    hook_kind: MigrationHookKind,
    trigger_height: u64,
    enforced_until_height: u64,
    source_module: &str,
    resulting_status: KeyStatus,
) -> MigrationHook {
    MigrationHook {
        hook_id: hook_id.to_string(),
        subject_id: subject_id.to_string(),
        domain,
        hook_kind,
        trigger_height,
        enforced_until_height,
        source_module: source_module.to_string(),
        decision_root: leaf_hash("PQ-KEY-HEALTH-HOOK-DECISION", hook_id),
        authorization_root: leaf_hash("PQ-KEY-HEALTH-HOOK-AUTH", subject_id),
        resulting_status,
    }
}

fn devnet_enforcement_decisions() -> Vec<EnforcementDecision> {
    vec![
        devnet_decision(
            "decision-contract-auth-alpha-2400",
            "contract-auth-alpha",
            KeyDomain::ContractCallAuthorization,
            FreshnessStatus::Paused,
            KeyStatus::Quarantined,
            false,
            "critical_compromise_report",
        ),
        devnet_decision(
            "decision-sequencer-alpha-2400",
            "sequencer-committee-alpha",
            KeyDomain::SequencerCommittee,
            FreshnessStatus::Fresh,
            KeyStatus::RotationDue,
            true,
            "rotation_receipt_present",
        ),
        devnet_decision(
            "decision-operator-alpha-2400",
            "operator-key-alpha",
            KeyDomain::OperatorKey,
            FreshnessStatus::Fresh,
            KeyStatus::Active,
            true,
            "fresh_operator_key",
        ),
    ]
}

fn devnet_decision(
    decision_id: &str,
    subject_id: &str,
    domain: KeyDomain,
    freshness_status: FreshnessStatus,
    key_status: KeyStatus,
    allowed: bool,
    reason_code: &str,
) -> EnforcementDecision {
    EnforcementDecision {
        decision_id: decision_id.to_string(),
        subject_id: subject_id.to_string(),
        domain,
        at_height: 2_400,
        freshness_status,
        key_status,
        blocking_report_root: leaf_hash("PQ-KEY-HEALTH-DECISION-REPORT", subject_id),
        migration_hook_root: leaf_hash("PQ-KEY-HEALTH-DECISION-HOOK", subject_id),
        allowed,
        reason_code: reason_code.to_string(),
    }
}

fn devnet_audit_events() -> Vec<Value> {
    vec![
        audit_event(
            "audit-wallet-recovery-alpha-fresh",
            KeyDomain::WalletRecovery,
            "wallet-recovery-alpha",
            "freshness_observed",
            2_400,
        ),
        audit_event(
            "audit-sequencer-alpha-rotation-due",
            KeyDomain::SequencerCommittee,
            "sequencer-committee-alpha",
            "rotation_receipt_required",
            2_400,
        ),
        audit_event(
            "audit-bridge-alpha-watch-report",
            KeyDomain::BridgeCommittee,
            "bridge-committee-alpha",
            "watch_report_opened",
            2_360,
        ),
        audit_event(
            "audit-contract-auth-alpha-quarantine",
            KeyDomain::ContractCallAuthorization,
            "contract-auth-alpha",
            "authorization_blocked",
            2_400,
        ),
        audit_event(
            "audit-operator-alpha-fresh",
            KeyDomain::OperatorKey,
            "operator-key-alpha",
            "operator_key_fresh",
            2_400,
        ),
    ]
}

fn audit_event(
    event_id: &str,
    domain: KeyDomain,
    subject_id: &str,
    event_kind: &str,
    emitted_at_height: u64,
) -> Value {
    let payload = json!({
        "event_id": event_id,
        "domain": domain.as_str(),
        "subject_id": subject_id,
        "event_kind": event_kind,
        "emitted_at_height": emitted_at_height.to_string(),
    });
    json!({
        "event_id": event_id,
        "domain": domain.as_str(),
        "subject_id": subject_id,
        "event_kind": event_kind,
        "emitted_at_height": emitted_at_height.to_string(),
        "payload_root": record_hash("PQ-KEY-HEALTH-AUDIT-EVENT-PAYLOAD", &payload),
    })
}
