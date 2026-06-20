use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type CryptoReadinessResult<T> = Result<T, String>;

pub const CRYPTO_READINESS_PROTOCOL_VERSION: &str = "nebula-crypto-readiness-v1";
pub const CRYPTO_READINESS_DEFAULT_REVIEW_TTL_BLOCKS: u64 = 5_040;
pub const CRYPTO_READINESS_DEFAULT_MIGRATION_NOTICE_BLOCKS: u64 = 20_160;
pub const CRYPTO_READINESS_DEFAULT_FALLBACK_WINDOW_BLOCKS: u64 = 10_080;
pub const CRYPTO_READINESS_DEFAULT_MIN_APPROVAL_WEIGHT_BPS: u64 = 8_000;
pub const CRYPTO_READINESS_DEFAULT_MIN_AUDIT_SCORE_BPS: u64 = 9_000;
pub const CRYPTO_READINESS_DEFAULT_MAX_OPEN_CRITICAL_FINDINGS: u64 = 0;
pub const CRYPTO_READINESS_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptoReadinessDomain {
    AccountSignatures,
    BridgeSignatures,
    ThresholdEncryption,
    ViewKeyDisclosure,
    ProofSystem,
    Hashing,
    Randomness,
    Hardware,
    Governance,
}

impl CryptoReadinessDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AccountSignatures => "account_signatures",
            Self::BridgeSignatures => "bridge_signatures",
            Self::ThresholdEncryption => "threshold_encryption",
            Self::ViewKeyDisclosure => "view_key_disclosure",
            Self::ProofSystem => "proof_system",
            Self::Hashing => "hashing",
            Self::Randomness => "randomness",
            Self::Hardware => "hardware",
            Self::Governance => "governance",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptoPrimitiveKind {
    Signature,
    Kem,
    Vrf,
    Hash,
    Commitment,
    MerkleTree,
    ZkProof,
    ThresholdEncryption,
    HardwareAttestation,
}

impl CryptoPrimitiveKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Signature => "signature",
            Self::Kem => "kem",
            Self::Vrf => "vrf",
            Self::Hash => "hash",
            Self::Commitment => "commitment",
            Self::MerkleTree => "merkle_tree",
            Self::ZkProof => "zk_proof",
            Self::ThresholdEncryption => "threshold_encryption",
            Self::HardwareAttestation => "hardware_attestation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptoApprovalStatus {
    Proposed,
    DevnetOnly,
    Auditing,
    Approved,
    Deprecated,
    Revoked,
}

impl CryptoApprovalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::DevnetOnly => "devnet_only",
            Self::Auditing => "auditing",
            Self::Approved => "approved",
            Self::Deprecated => "deprecated",
            Self::Revoked => "revoked",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::DevnetOnly | Self::Auditing | Self::Approved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptoEvidenceKind {
    Specification,
    ReferenceImplementation,
    FormalModel,
    TestVector,
    FuzzRun,
    ConstantTimeReview,
    SideChannelReview,
    ThirdPartyAudit,
    MainnetIncidentReview,
}

impl CryptoEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Specification => "specification",
            Self::ReferenceImplementation => "reference_implementation",
            Self::FormalModel => "formal_model",
            Self::TestVector => "test_vector",
            Self::FuzzRun => "fuzz_run",
            Self::ConstantTimeReview => "constant_time_review",
            Self::SideChannelReview => "side_channel_review",
            Self::ThirdPartyAudit => "third_party_audit",
            Self::MainnetIncidentReview => "mainnet_incident_review",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptoFindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl CryptoFindingSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn score_penalty_bps(self) -> u64 {
        match self {
            Self::Info => 0,
            Self::Low => 250,
            Self::Medium => 1_000,
            Self::High => 2_500,
            Self::Critical => 10_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptoFindingStatus {
    Open,
    Mitigated,
    AcceptedRisk,
    Invalid,
}

impl CryptoFindingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Mitigated => "mitigated",
            Self::AcceptedRisk => "accepted_risk",
            Self::Invalid => "invalid",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Open | Self::AcceptedRisk)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptoMigrationStatus {
    Draft,
    Scheduled,
    Active,
    GracePeriod,
    Complete,
    Cancelled,
}

impl CryptoMigrationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Scheduled => "scheduled",
            Self::Active => "active",
            Self::GracePeriod => "grace_period",
            Self::Complete => "complete",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Scheduled | Self::Active | Self::GracePeriod)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoReadinessConfig {
    pub protocol_version: String,
    pub chain_id: String,
    pub operator_label: String,
    pub review_ttl_blocks: u64,
    pub migration_notice_blocks: u64,
    pub fallback_window_blocks: u64,
    pub min_approval_weight_bps: u64,
    pub min_audit_score_bps: u64,
    pub max_open_critical_findings: u64,
}

impl CryptoReadinessConfig {
    pub fn devnet(operator_label: impl Into<String>) -> Self {
        Self {
            protocol_version: CRYPTO_READINESS_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            operator_label: operator_label.into(),
            review_ttl_blocks: CRYPTO_READINESS_DEFAULT_REVIEW_TTL_BLOCKS,
            migration_notice_blocks: CRYPTO_READINESS_DEFAULT_MIGRATION_NOTICE_BLOCKS,
            fallback_window_blocks: CRYPTO_READINESS_DEFAULT_FALLBACK_WINDOW_BLOCKS,
            min_approval_weight_bps: CRYPTO_READINESS_DEFAULT_MIN_APPROVAL_WEIGHT_BPS,
            min_audit_score_bps: CRYPTO_READINESS_DEFAULT_MIN_AUDIT_SCORE_BPS,
            max_open_critical_findings: CRYPTO_READINESS_DEFAULT_MAX_OPEN_CRITICAL_FINDINGS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "crypto_readiness_config",
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "operator_label": self.operator_label,
            "review_ttl_blocks": self.review_ttl_blocks,
            "migration_notice_blocks": self.migration_notice_blocks,
            "fallback_window_blocks": self.fallback_window_blocks,
            "min_approval_weight_bps": self.min_approval_weight_bps,
            "min_audit_score_bps": self.min_audit_score_bps,
            "max_open_critical_findings": self.max_open_critical_findings,
        })
    }

    pub fn config_root(&self) -> String {
        crypto_readiness_payload_root("CRYPTO-READINESS-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> CryptoReadinessResult<String> {
        if self.protocol_version != CRYPTO_READINESS_PROTOCOL_VERSION {
            return Err("crypto readiness protocol version mismatch".to_string());
        }
        if self.chain_id != CHAIN_ID {
            return Err("crypto readiness chain id mismatch".to_string());
        }
        require_non_empty("operator label", &self.operator_label)?;
        require_positive("review ttl blocks", self.review_ttl_blocks)?;
        require_positive("migration notice blocks", self.migration_notice_blocks)?;
        require_positive("fallback window blocks", self.fallback_window_blocks)?;
        require_bps("min approval weight", self.min_approval_weight_bps)?;
        require_bps("min audit score", self.min_audit_score_bps)?;
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoAlgorithmRecord {
    pub algorithm_id: String,
    pub domain: CryptoReadinessDomain,
    pub primitive_kind: CryptoPrimitiveKind,
    pub label: String,
    pub version: String,
    pub status: CryptoApprovalStatus,
    pub security_level: u64,
    pub pq_claim: bool,
    pub spec_root: String,
    pub parameter_root: String,
    pub registered_at_height: u64,
    pub review_due_height: u64,
}

impl CryptoAlgorithmRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        domain: CryptoReadinessDomain,
        primitive_kind: CryptoPrimitiveKind,
        label: &str,
        version: &str,
        status: CryptoApprovalStatus,
        security_level: u64,
        pq_claim: bool,
        spec: &Value,
        parameters: &Value,
        registered_at_height: u64,
        review_due_height: u64,
    ) -> CryptoReadinessResult<Self> {
        require_non_empty("algorithm label", label)?;
        require_non_empty("algorithm version", version)?;
        require_positive("security level", security_level)?;
        if review_due_height <= registered_at_height {
            return Err("algorithm review height must follow registration".to_string());
        }
        let spec_root = crypto_readiness_payload_root("CRYPTO-READINESS-ALGORITHM-SPEC", spec);
        let parameter_root =
            crypto_readiness_payload_root("CRYPTO-READINESS-ALGORITHM-PARAMETERS", parameters);
        let algorithm_id = crypto_readiness_algorithm_id(
            domain,
            primitive_kind,
            label,
            version,
            &spec_root,
            &parameter_root,
        );
        Ok(Self {
            algorithm_id,
            domain,
            primitive_kind,
            label: label.to_string(),
            version: version.to_string(),
            status,
            security_level,
            pq_claim,
            spec_root,
            parameter_root,
            registered_at_height,
            review_due_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "crypto_algorithm_record",
            "protocol_version": CRYPTO_READINESS_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "algorithm_id": self.algorithm_id,
            "domain": self.domain.as_str(),
            "primitive_kind": self.primitive_kind.as_str(),
            "label": self.label,
            "version": self.version,
            "status": self.status.as_str(),
            "security_level": self.security_level,
            "pq_claim": self.pq_claim,
            "spec_root": self.spec_root,
            "parameter_root": self.parameter_root,
            "registered_at_height": self.registered_at_height,
            "review_due_height": self.review_due_height,
        })
    }

    pub fn validate(&self) -> CryptoReadinessResult<String> {
        require_non_empty("algorithm id", &self.algorithm_id)?;
        require_non_empty("algorithm label", &self.label)?;
        require_non_empty("algorithm version", &self.version)?;
        require_positive("security level", self.security_level)?;
        require_non_empty("algorithm spec root", &self.spec_root)?;
        require_non_empty("algorithm parameter root", &self.parameter_root)?;
        if self.review_due_height <= self.registered_at_height {
            return Err("algorithm review height must follow registration".to_string());
        }
        let expected = crypto_readiness_algorithm_id(
            self.domain,
            self.primitive_kind,
            &self.label,
            &self.version,
            &self.spec_root,
            &self.parameter_root,
        );
        if self.algorithm_id != expected {
            return Err("crypto algorithm id mismatch".to_string());
        }
        Ok(self.algorithm_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoImplementationAttestation {
    pub attestation_id: String,
    pub algorithm_id: String,
    pub implementation_label: String,
    pub artifact_root: String,
    pub build_root: String,
    pub test_vector_root: String,
    pub constant_time_review_root: String,
    pub approval_weight_bps: u64,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
    pub approved: bool,
}

impl CryptoImplementationAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        algorithm_id: &str,
        implementation_label: &str,
        artifact: &Value,
        build: &Value,
        test_vectors: &Value,
        constant_time_review: &Value,
        approval_weight_bps: u64,
        attested_at_height: u64,
        expires_at_height: u64,
        approved: bool,
    ) -> CryptoReadinessResult<Self> {
        require_non_empty("attestation algorithm id", algorithm_id)?;
        require_non_empty("implementation label", implementation_label)?;
        require_bps("approval weight", approval_weight_bps)?;
        if expires_at_height <= attested_at_height {
            return Err("attestation expiry must follow attestation height".to_string());
        }
        let artifact_root =
            crypto_readiness_payload_root("CRYPTO-READINESS-IMPLEMENTATION-ARTIFACT", artifact);
        let build_root = crypto_readiness_payload_root("CRYPTO-READINESS-BUILD", build);
        let test_vector_root =
            crypto_readiness_payload_root("CRYPTO-READINESS-TEST-VECTORS", test_vectors);
        let constant_time_review_root =
            crypto_readiness_payload_root("CRYPTO-READINESS-CONSTANT-TIME", constant_time_review);
        let attestation_id = crypto_readiness_attestation_id(
            algorithm_id,
            implementation_label,
            &artifact_root,
            &build_root,
            attested_at_height,
        );
        Ok(Self {
            attestation_id,
            algorithm_id: algorithm_id.to_string(),
            implementation_label: implementation_label.to_string(),
            artifact_root,
            build_root,
            test_vector_root,
            constant_time_review_root,
            approval_weight_bps,
            attested_at_height,
            expires_at_height,
            approved,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.approved && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "crypto_implementation_attestation",
            "protocol_version": CRYPTO_READINESS_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "attestation_id": self.attestation_id,
            "algorithm_id": self.algorithm_id,
            "implementation_label": self.implementation_label,
            "artifact_root": self.artifact_root,
            "build_root": self.build_root,
            "test_vector_root": self.test_vector_root,
            "constant_time_review_root": self.constant_time_review_root,
            "approval_weight_bps": self.approval_weight_bps,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
            "approved": self.approved,
        })
    }

    pub fn validate(&self) -> CryptoReadinessResult<String> {
        require_non_empty("attestation id", &self.attestation_id)?;
        require_non_empty("attestation algorithm id", &self.algorithm_id)?;
        require_non_empty("implementation label", &self.implementation_label)?;
        require_non_empty("artifact root", &self.artifact_root)?;
        require_non_empty("build root", &self.build_root)?;
        require_non_empty("test vector root", &self.test_vector_root)?;
        require_non_empty("constant time review root", &self.constant_time_review_root)?;
        require_bps("approval weight", self.approval_weight_bps)?;
        if self.expires_at_height <= self.attested_at_height {
            return Err("attestation expiry must follow attestation height".to_string());
        }
        let expected = crypto_readiness_attestation_id(
            &self.algorithm_id,
            &self.implementation_label,
            &self.artifact_root,
            &self.build_root,
            self.attested_at_height,
        );
        if self.attestation_id != expected {
            return Err("crypto implementation attestation id mismatch".to_string());
        }
        Ok(self.attestation_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoEvidenceRecord {
    pub evidence_id: String,
    pub algorithm_id: String,
    pub evidence_kind: CryptoEvidenceKind,
    pub submitter_label: String,
    pub evidence_root: String,
    pub score_bps: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl CryptoEvidenceRecord {
    pub fn new(
        algorithm_id: &str,
        evidence_kind: CryptoEvidenceKind,
        submitter_label: &str,
        evidence: &Value,
        score_bps: u64,
        submitted_at_height: u64,
        expires_at_height: u64,
    ) -> CryptoReadinessResult<Self> {
        require_non_empty("evidence algorithm id", algorithm_id)?;
        require_non_empty("evidence submitter", submitter_label)?;
        require_bps("evidence score", score_bps)?;
        if expires_at_height <= submitted_at_height {
            return Err("evidence expiry must follow submission".to_string());
        }
        let evidence_root = crypto_readiness_payload_root("CRYPTO-READINESS-EVIDENCE", evidence);
        let evidence_id = crypto_readiness_evidence_id(
            algorithm_id,
            evidence_kind,
            submitter_label,
            &evidence_root,
            submitted_at_height,
        );
        Ok(Self {
            evidence_id,
            algorithm_id: algorithm_id.to_string(),
            evidence_kind,
            submitter_label: submitter_label.to_string(),
            evidence_root,
            score_bps,
            submitted_at_height,
            expires_at_height,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "crypto_evidence_record",
            "protocol_version": CRYPTO_READINESS_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "evidence_id": self.evidence_id,
            "algorithm_id": self.algorithm_id,
            "evidence_kind": self.evidence_kind.as_str(),
            "submitter_label": self.submitter_label,
            "evidence_root": self.evidence_root,
            "score_bps": self.score_bps,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(&self) -> CryptoReadinessResult<String> {
        require_non_empty("evidence id", &self.evidence_id)?;
        require_non_empty("evidence algorithm id", &self.algorithm_id)?;
        require_non_empty("evidence submitter", &self.submitter_label)?;
        require_non_empty("evidence root", &self.evidence_root)?;
        require_bps("evidence score", self.score_bps)?;
        if self.expires_at_height <= self.submitted_at_height {
            return Err("evidence expiry must follow submission".to_string());
        }
        let expected = crypto_readiness_evidence_id(
            &self.algorithm_id,
            self.evidence_kind,
            &self.submitter_label,
            &self.evidence_root,
            self.submitted_at_height,
        );
        if self.evidence_id != expected {
            return Err("crypto evidence id mismatch".to_string());
        }
        Ok(self.evidence_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoAuditFinding {
    pub finding_id: String,
    pub algorithm_id: String,
    pub severity: CryptoFindingSeverity,
    pub status: CryptoFindingStatus,
    pub title_root: String,
    pub evidence_root: String,
    pub opened_at_height: u64,
    pub resolved_at_height: Option<u64>,
}

impl CryptoAuditFinding {
    pub fn new(
        algorithm_id: &str,
        severity: CryptoFindingSeverity,
        status: CryptoFindingStatus,
        title: &str,
        evidence: &Value,
        opened_at_height: u64,
        resolved_at_height: Option<u64>,
    ) -> CryptoReadinessResult<Self> {
        require_non_empty("finding algorithm id", algorithm_id)?;
        require_non_empty("finding title", title)?;
        if let Some(resolved_at_height) = resolved_at_height {
            if resolved_at_height < opened_at_height {
                return Err("finding resolution cannot precede open height".to_string());
            }
        }
        let title_root = crypto_readiness_string_root("CRYPTO-READINESS-FINDING-TITLE", title);
        let evidence_root =
            crypto_readiness_payload_root("CRYPTO-READINESS-FINDING-EVIDENCE", evidence);
        let finding_id = crypto_readiness_finding_id(
            algorithm_id,
            severity,
            &title_root,
            &evidence_root,
            opened_at_height,
        );
        Ok(Self {
            finding_id,
            algorithm_id: algorithm_id.to_string(),
            severity,
            status,
            title_root,
            evidence_root,
            opened_at_height,
            resolved_at_height,
        })
    }

    pub fn active(&self) -> bool {
        self.status.active()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "crypto_audit_finding",
            "protocol_version": CRYPTO_READINESS_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "finding_id": self.finding_id,
            "algorithm_id": self.algorithm_id,
            "severity": self.severity.as_str(),
            "status": self.status.as_str(),
            "title_root": self.title_root,
            "evidence_root": self.evidence_root,
            "opened_at_height": self.opened_at_height,
            "resolved_at_height": self.resolved_at_height,
        })
    }

    pub fn validate(&self) -> CryptoReadinessResult<String> {
        require_non_empty("finding id", &self.finding_id)?;
        require_non_empty("finding algorithm id", &self.algorithm_id)?;
        require_non_empty("finding title root", &self.title_root)?;
        require_non_empty("finding evidence root", &self.evidence_root)?;
        if let Some(resolved_at_height) = self.resolved_at_height {
            if resolved_at_height < self.opened_at_height {
                return Err("finding resolution cannot precede open height".to_string());
            }
        }
        let expected = crypto_readiness_finding_id(
            &self.algorithm_id,
            self.severity,
            &self.title_root,
            &self.evidence_root,
            self.opened_at_height,
        );
        if self.finding_id != expected {
            return Err("crypto audit finding id mismatch".to_string());
        }
        Ok(self.finding_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoMigrationGate {
    pub gate_id: String,
    pub from_algorithm_id: String,
    pub to_algorithm_id: String,
    pub domain: CryptoReadinessDomain,
    pub status: CryptoMigrationStatus,
    pub scheduled_at_height: u64,
    pub activates_at_height: u64,
    pub fallback_ends_at_height: u64,
    pub guardrail_root: String,
    pub emergency_rollback_root: String,
}

impl CryptoMigrationGate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        from_algorithm_id: &str,
        to_algorithm_id: &str,
        domain: CryptoReadinessDomain,
        status: CryptoMigrationStatus,
        scheduled_at_height: u64,
        activates_at_height: u64,
        fallback_ends_at_height: u64,
        guardrails: &Value,
        emergency_rollback: &Value,
    ) -> CryptoReadinessResult<Self> {
        require_non_empty("migration source algorithm", from_algorithm_id)?;
        require_non_empty("migration target algorithm", to_algorithm_id)?;
        if from_algorithm_id == to_algorithm_id {
            return Err("migration source and target algorithms must differ".to_string());
        }
        if activates_at_height <= scheduled_at_height {
            return Err("migration activation must follow schedule height".to_string());
        }
        if fallback_ends_at_height <= activates_at_height {
            return Err("migration fallback must outlive activation".to_string());
        }
        let guardrail_root =
            crypto_readiness_payload_root("CRYPTO-READINESS-MIGRATION-GUARDRAILS", guardrails);
        let emergency_rollback_root = crypto_readiness_payload_root(
            "CRYPTO-READINESS-MIGRATION-ROLLBACK",
            emergency_rollback,
        );
        let gate_id = crypto_readiness_migration_gate_id(
            from_algorithm_id,
            to_algorithm_id,
            domain,
            &guardrail_root,
            scheduled_at_height,
        );
        Ok(Self {
            gate_id,
            from_algorithm_id: from_algorithm_id.to_string(),
            to_algorithm_id: to_algorithm_id.to_string(),
            domain,
            status,
            scheduled_at_height,
            activates_at_height,
            fallback_ends_at_height,
            guardrail_root,
            emergency_rollback_root,
        })
    }

    pub fn set_height(&mut self, height: u64) {
        self.status = match self.status {
            CryptoMigrationStatus::Scheduled if height >= self.activates_at_height => {
                CryptoMigrationStatus::Active
            }
            CryptoMigrationStatus::Active if height >= self.fallback_ends_at_height => {
                CryptoMigrationStatus::Complete
            }
            CryptoMigrationStatus::GracePeriod if height >= self.fallback_ends_at_height => {
                CryptoMigrationStatus::Complete
            }
            other => other,
        };
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "crypto_migration_gate",
            "protocol_version": CRYPTO_READINESS_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "gate_id": self.gate_id,
            "from_algorithm_id": self.from_algorithm_id,
            "to_algorithm_id": self.to_algorithm_id,
            "domain": self.domain.as_str(),
            "status": self.status.as_str(),
            "scheduled_at_height": self.scheduled_at_height,
            "activates_at_height": self.activates_at_height,
            "fallback_ends_at_height": self.fallback_ends_at_height,
            "guardrail_root": self.guardrail_root,
            "emergency_rollback_root": self.emergency_rollback_root,
        })
    }

    pub fn validate(&self) -> CryptoReadinessResult<String> {
        require_non_empty("migration gate id", &self.gate_id)?;
        require_non_empty("migration source algorithm", &self.from_algorithm_id)?;
        require_non_empty("migration target algorithm", &self.to_algorithm_id)?;
        require_non_empty("migration guardrail root", &self.guardrail_root)?;
        require_non_empty("migration rollback root", &self.emergency_rollback_root)?;
        if self.from_algorithm_id == self.to_algorithm_id {
            return Err("migration source and target algorithms must differ".to_string());
        }
        if self.activates_at_height <= self.scheduled_at_height {
            return Err("migration activation must follow schedule height".to_string());
        }
        if self.fallback_ends_at_height <= self.activates_at_height {
            return Err("migration fallback must outlive activation".to_string());
        }
        let expected = crypto_readiness_migration_gate_id(
            &self.from_algorithm_id,
            &self.to_algorithm_id,
            self.domain,
            &self.guardrail_root,
            self.scheduled_at_height,
        );
        if self.gate_id != expected {
            return Err("crypto migration gate id mismatch".to_string());
        }
        Ok(self.gate_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoReadinessRoots {
    pub config_root: String,
    pub algorithm_root: String,
    pub attestation_root: String,
    pub evidence_root: String,
    pub finding_root: String,
    pub migration_gate_root: String,
    pub approved_domain_root: String,
}

impl CryptoReadinessRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "crypto_readiness_roots",
            "protocol_version": CRYPTO_READINESS_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "algorithm_root": self.algorithm_root,
            "attestation_root": self.attestation_root,
            "evidence_root": self.evidence_root,
            "finding_root": self.finding_root,
            "migration_gate_root": self.migration_gate_root,
            "approved_domain_root": self.approved_domain_root,
        })
    }

    pub fn roots_root(&self) -> String {
        crypto_readiness_payload_root("CRYPTO-READINESS-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoReadinessCounters {
    pub algorithm_count: u64,
    pub approved_algorithm_count: u64,
    pub pq_algorithm_count: u64,
    pub active_attestation_count: u64,
    pub evidence_count: u64,
    pub open_finding_count: u64,
    pub open_critical_finding_count: u64,
    pub active_migration_count: u64,
    pub aggregate_audit_score_bps: u64,
    pub approved_domain_count: u64,
}

impl CryptoReadinessCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "crypto_readiness_counters",
            "protocol_version": CRYPTO_READINESS_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "algorithm_count": self.algorithm_count,
            "approved_algorithm_count": self.approved_algorithm_count,
            "pq_algorithm_count": self.pq_algorithm_count,
            "active_attestation_count": self.active_attestation_count,
            "evidence_count": self.evidence_count,
            "open_finding_count": self.open_finding_count,
            "open_critical_finding_count": self.open_critical_finding_count,
            "active_migration_count": self.active_migration_count,
            "aggregate_audit_score_bps": self.aggregate_audit_score_bps,
            "approved_domain_count": self.approved_domain_count,
        })
    }

    pub fn counters_root(&self) -> String {
        crypto_readiness_payload_root("CRYPTO-READINESS-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoReadinessState {
    pub config: CryptoReadinessConfig,
    pub height: u64,
    pub algorithms: BTreeMap<String, CryptoAlgorithmRecord>,
    pub attestations: BTreeMap<String, CryptoImplementationAttestation>,
    pub evidence: BTreeMap<String, CryptoEvidenceRecord>,
    pub findings: BTreeMap<String, CryptoAuditFinding>,
    pub migration_gates: BTreeMap<String, CryptoMigrationGate>,
}

impl CryptoReadinessState {
    pub fn devnet(operator_label: &str) -> CryptoReadinessResult<Self> {
        let config = CryptoReadinessConfig::devnet(operator_label);
        let height = 1;
        let mut state = Self {
            config,
            height,
            algorithms: BTreeMap::new(),
            attestations: BTreeMap::new(),
            evidence: BTreeMap::new(),
            findings: BTreeMap::new(),
            migration_gates: BTreeMap::new(),
        };

        let ml_dsa = CryptoAlgorithmRecord::new(
            CryptoReadinessDomain::AccountSignatures,
            CryptoPrimitiveKind::Signature,
            "ML-DSA-65",
            "nist-fips-204-devnet",
            CryptoApprovalStatus::Approved,
            3,
            true,
            &json!({"standard": "FIPS-204", "profile": "devnet-account-auth"}),
            &json!({"mode": "deterministic-rooted", "encoding": "canonical-json"}),
            height,
            height.saturating_add(state.config.review_ttl_blocks),
        )?;
        let slh_dsa = CryptoAlgorithmRecord::new(
            CryptoReadinessDomain::AccountSignatures,
            CryptoPrimitiveKind::Signature,
            "SLH-DSA-SHAKE-128s",
            "nist-fips-205-devnet",
            CryptoApprovalStatus::Approved,
            1,
            true,
            &json!({"standard": "FIPS-205", "profile": "backup-recovery"}),
            &json!({"hash": "SHAKE256", "role": "recovery-backstop"}),
            height,
            height.saturating_add(state.config.review_ttl_blocks),
        )?;
        let ml_kem = CryptoAlgorithmRecord::new(
            CryptoReadinessDomain::ThresholdEncryption,
            CryptoPrimitiveKind::Kem,
            "ML-KEM-1024-threshold-envelope",
            "nist-fips-203-devnet",
            CryptoApprovalStatus::Auditing,
            5,
            true,
            &json!({"standard": "FIPS-203", "profile": "threshold-mempool"}),
            &json!({"shares": 5, "threshold": 3, "timelock": true}),
            height,
            height.saturating_add(state.config.review_ttl_blocks),
        )?;
        let shake = CryptoAlgorithmRecord::new(
            CryptoReadinessDomain::Hashing,
            CryptoPrimitiveKind::Hash,
            "SHAKE256-domain-separated",
            "devnet-v1",
            CryptoApprovalStatus::Approved,
            3,
            true,
            &json!({"standard": "FIPS-202", "profile": "state-root-domain-hash"}),
            &json!({"output_bytes": 32, "canonical_json": true}),
            height,
            height.saturating_add(state.config.review_ttl_blocks),
        )?;
        let proof = CryptoAlgorithmRecord::new(
            CryptoReadinessDomain::ProofSystem,
            CryptoPrimitiveKind::ZkProof,
            "fri-recursive-pq-verifier",
            "devnet-v1",
            CryptoApprovalStatus::Auditing,
            3,
            true,
            &json!({"profile": "recursive-validity", "transparent": true}),
            &json!({"field": "devnet", "hash": "SHAKE256", "fri_layers": 8}),
            height,
            height.saturating_add(state.config.review_ttl_blocks),
        )?;

        for algorithm in [ml_dsa, slh_dsa, ml_kem, shake, proof] {
            state.insert_algorithm(algorithm)?;
        }

        let algorithm_ids = state.algorithms.keys().cloned().collect::<Vec<_>>();
        for algorithm_id in algorithm_ids {
            let attestation = CryptoImplementationAttestation::new(
                &algorithm_id,
                &format!("{operator_label}-crypto-impl"),
                &json!({"crate": "nebula_l2_rs", "algorithm_id": algorithm_id}),
                &json!({"compiler": "rustc", "profile": "devnet"}),
                &json!({"vectors": "deterministic-devnet-fixture"}),
                &json!({"constant_time": "reviewed-devnet-surface"}),
                8_500,
                height,
                height.saturating_add(state.config.review_ttl_blocks),
                true,
            )?;
            state.insert_attestation(attestation)?;
        }

        let evidence_ids = state.algorithms.keys().cloned().collect::<Vec<_>>();
        for algorithm_id in evidence_ids {
            let evidence = CryptoEvidenceRecord::new(
                &algorithm_id,
                CryptoEvidenceKind::TestVector,
                operator_label,
                &json!({"test_vector_manifest": algorithm_id, "scope": "devnet"}),
                9_250,
                height,
                height.saturating_add(state.config.review_ttl_blocks),
            )?;
            state.insert_evidence(evidence)?;
        }

        let proof_algorithm_id = state
            .algorithms
            .values()
            .find(|algorithm| algorithm.domain == CryptoReadinessDomain::ProofSystem)
            .map(|algorithm| algorithm.algorithm_id.clone())
            .ok_or_else(|| "missing proof algorithm".to_string())?;
        state.insert_finding(CryptoAuditFinding::new(
            &proof_algorithm_id,
            CryptoFindingSeverity::Medium,
            CryptoFindingStatus::Mitigated,
            "recursive proof transcript review",
            &json!({"finding": "transcript-domain-separation-reviewed", "mitigation": "domain labels"}),
            height,
            Some(height),
        )?)?;

        let bridge_algorithm_id = state
            .algorithms
            .values()
            .find(|algorithm| algorithm.label == "SLH-DSA-SHAKE-128s")
            .map(|algorithm| algorithm.algorithm_id.clone())
            .ok_or_else(|| "missing bridge recovery algorithm".to_string())?;
        let account_algorithm_id = state
            .algorithms
            .values()
            .find(|algorithm| algorithm.label == "ML-DSA-65")
            .map(|algorithm| algorithm.algorithm_id.clone())
            .ok_or_else(|| "missing account algorithm".to_string())?;
        state.insert_migration_gate(CryptoMigrationGate::new(
            &bridge_algorithm_id,
            &account_algorithm_id,
            CryptoReadinessDomain::AccountSignatures,
            CryptoMigrationStatus::Scheduled,
            height,
            height.saturating_add(state.config.migration_notice_blocks),
            height
                .saturating_add(state.config.migration_notice_blocks)
                .saturating_add(state.config.fallback_window_blocks),
            &json!({"wallet_reauth_required": true, "low_fee_sponsored": true}),
            &json!({"fallback": "slh-dsa-backstop", "guardian_threshold": 3}),
        )?)?;

        state.validate()?;
        Ok(state)
    }

    pub fn insert_algorithm(
        &mut self,
        algorithm: CryptoAlgorithmRecord,
    ) -> CryptoReadinessResult<String> {
        let algorithm_id = algorithm.validate()?;
        self.algorithms.insert(algorithm_id.clone(), algorithm);
        Ok(algorithm_id)
    }

    pub fn insert_attestation(
        &mut self,
        attestation: CryptoImplementationAttestation,
    ) -> CryptoReadinessResult<String> {
        let attestation_id = attestation.validate()?;
        if !self.algorithms.contains_key(&attestation.algorithm_id) {
            return Err("crypto attestation references missing algorithm".to_string());
        }
        self.attestations
            .insert(attestation_id.clone(), attestation);
        Ok(attestation_id)
    }

    pub fn insert_evidence(
        &mut self,
        evidence: CryptoEvidenceRecord,
    ) -> CryptoReadinessResult<String> {
        let evidence_id = evidence.validate()?;
        if !self.algorithms.contains_key(&evidence.algorithm_id) {
            return Err("crypto evidence references missing algorithm".to_string());
        }
        self.evidence.insert(evidence_id.clone(), evidence);
        Ok(evidence_id)
    }

    pub fn insert_finding(&mut self, finding: CryptoAuditFinding) -> CryptoReadinessResult<String> {
        let finding_id = finding.validate()?;
        if !self.algorithms.contains_key(&finding.algorithm_id) {
            return Err("crypto finding references missing algorithm".to_string());
        }
        self.findings.insert(finding_id.clone(), finding);
        Ok(finding_id)
    }

    pub fn insert_migration_gate(
        &mut self,
        gate: CryptoMigrationGate,
    ) -> CryptoReadinessResult<String> {
        let gate_id = gate.validate()?;
        if !self.algorithms.contains_key(&gate.from_algorithm_id)
            || !self.algorithms.contains_key(&gate.to_algorithm_id)
        {
            return Err("crypto migration references missing algorithm".to_string());
        }
        self.migration_gates.insert(gate_id.clone(), gate);
        Ok(gate_id)
    }

    pub fn set_height(&mut self, height: u64) -> CryptoReadinessResult<String> {
        self.height = height;
        for gate in self.migration_gates.values_mut() {
            gate.set_height(height);
        }
        self.validate()?;
        Ok(self.state_root())
    }

    pub fn approval_weight_for_algorithm(&self, algorithm_id: &str) -> u64 {
        self.attestations
            .values()
            .filter(|attestation| {
                attestation.algorithm_id == algorithm_id && attestation.active_at(self.height)
            })
            .map(|attestation| attestation.approval_weight_bps)
            .fold(0_u64, u64::saturating_add)
            .min(CRYPTO_READINESS_MAX_BPS)
    }

    pub fn evidence_score_for_algorithm(&self, algorithm_id: &str) -> u64 {
        let scores = self
            .evidence
            .values()
            .filter(|evidence| {
                evidence.algorithm_id == algorithm_id && evidence.active_at(self.height)
            })
            .map(|evidence| evidence.score_bps)
            .collect::<Vec<_>>();
        if scores.is_empty() {
            return 0;
        }
        scores.iter().sum::<u64>() / scores.len() as u64
    }

    pub fn open_finding_penalty_bps(&self, algorithm_id: &str) -> u64 {
        self.findings
            .values()
            .filter(|finding| finding.algorithm_id == algorithm_id && finding.active())
            .map(|finding| finding.severity.score_penalty_bps())
            .fold(0_u64, u64::saturating_add)
            .min(CRYPTO_READINESS_MAX_BPS)
    }

    pub fn audit_score_for_algorithm(&self, algorithm_id: &str) -> u64 {
        self.evidence_score_for_algorithm(algorithm_id)
            .saturating_sub(self.open_finding_penalty_bps(algorithm_id))
    }

    pub fn approved_domain_map(&self) -> BTreeMap<String, Vec<String>> {
        let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for algorithm in self.algorithms.values() {
            if algorithm.status.usable()
                && self.approval_weight_for_algorithm(&algorithm.algorithm_id)
                    >= self.config.min_approval_weight_bps
                && self.audit_score_for_algorithm(&algorithm.algorithm_id)
                    >= self.config.min_audit_score_bps
            {
                map.entry(algorithm.domain.as_str().to_string())
                    .or_default()
                    .push(algorithm.algorithm_id.clone());
            }
        }
        for values in map.values_mut() {
            values.sort();
        }
        map
    }

    pub fn aggregate_audit_score_bps(&self) -> u64 {
        if self.algorithms.is_empty() {
            return 0;
        }
        self.algorithms
            .keys()
            .map(|algorithm_id| self.audit_score_for_algorithm(algorithm_id))
            .sum::<u64>()
            / self.algorithms.len() as u64
    }

    pub fn roots(&self) -> CryptoReadinessRoots {
        CryptoReadinessRoots {
            config_root: self.config.config_root(),
            algorithm_root: keyed_value_root(
                "CRYPTO-READINESS-ALGORITHMS",
                self.algorithms
                    .values()
                    .map(|record| (record.algorithm_id.clone(), record.public_record()))
                    .collect(),
            ),
            attestation_root: keyed_value_root(
                "CRYPTO-READINESS-ATTESTATIONS",
                self.attestations
                    .values()
                    .map(|record| (record.attestation_id.clone(), record.public_record()))
                    .collect(),
            ),
            evidence_root: keyed_value_root(
                "CRYPTO-READINESS-EVIDENCE",
                self.evidence
                    .values()
                    .map(|record| (record.evidence_id.clone(), record.public_record()))
                    .collect(),
            ),
            finding_root: keyed_value_root(
                "CRYPTO-READINESS-FINDINGS",
                self.findings
                    .values()
                    .map(|record| (record.finding_id.clone(), record.public_record()))
                    .collect(),
            ),
            migration_gate_root: keyed_value_root(
                "CRYPTO-READINESS-MIGRATION-GATES",
                self.migration_gates
                    .values()
                    .map(|record| (record.gate_id.clone(), record.public_record()))
                    .collect(),
            ),
            approved_domain_root: crypto_readiness_payload_root(
                "CRYPTO-READINESS-APPROVED-DOMAINS",
                &json!(self.approved_domain_map()),
            ),
        }
    }

    pub fn counters(&self) -> CryptoReadinessCounters {
        let approved_domain_count = self.approved_domain_map().len() as u64;
        CryptoReadinessCounters {
            algorithm_count: self.algorithms.len() as u64,
            approved_algorithm_count: self
                .algorithms
                .values()
                .filter(|algorithm| algorithm.status == CryptoApprovalStatus::Approved)
                .count() as u64,
            pq_algorithm_count: self
                .algorithms
                .values()
                .filter(|algorithm| algorithm.pq_claim)
                .count() as u64,
            active_attestation_count: self
                .attestations
                .values()
                .filter(|attestation| attestation.active_at(self.height))
                .count() as u64,
            evidence_count: self.evidence.len() as u64,
            open_finding_count: self
                .findings
                .values()
                .filter(|finding| finding.active())
                .count() as u64,
            open_critical_finding_count: self
                .findings
                .values()
                .filter(|finding| {
                    finding.active() && finding.severity == CryptoFindingSeverity::Critical
                })
                .count() as u64,
            active_migration_count: self
                .migration_gates
                .values()
                .filter(|gate| gate.status.active())
                .count() as u64,
            aggregate_audit_score_bps: self.aggregate_audit_score_bps(),
            approved_domain_count,
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "crypto_readiness_state",
            "protocol_version": CRYPTO_READINESS_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
            "approved_domains": self.approved_domain_map(),
        })
    }

    pub fn state_root(&self) -> String {
        crypto_readiness_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "crypto_readiness_state_root",
            self.state_root(),
        )
    }

    pub fn validate(&self) -> CryptoReadinessResult<String> {
        self.config.validate()?;
        let algorithm_ids = self
            .algorithms
            .values()
            .map(CryptoAlgorithmRecord::validate)
            .collect::<CryptoReadinessResult<Vec<_>>>()?;
        ensure_unique_strings(&algorithm_ids, "algorithm id")?;
        let algorithm_set = algorithm_ids.iter().cloned().collect::<BTreeSet<_>>();
        let attestation_ids = self
            .attestations
            .values()
            .map(CryptoImplementationAttestation::validate)
            .collect::<CryptoReadinessResult<Vec<_>>>()?;
        ensure_unique_strings(&attestation_ids, "attestation id")?;
        let evidence_ids = self
            .evidence
            .values()
            .map(CryptoEvidenceRecord::validate)
            .collect::<CryptoReadinessResult<Vec<_>>>()?;
        ensure_unique_strings(&evidence_ids, "evidence id")?;
        let finding_ids = self
            .findings
            .values()
            .map(CryptoAuditFinding::validate)
            .collect::<CryptoReadinessResult<Vec<_>>>()?;
        ensure_unique_strings(&finding_ids, "finding id")?;
        let migration_ids = self
            .migration_gates
            .values()
            .map(CryptoMigrationGate::validate)
            .collect::<CryptoReadinessResult<Vec<_>>>()?;
        ensure_unique_strings(&migration_ids, "migration gate id")?;
        for attestation in self.attestations.values() {
            if !algorithm_set.contains(&attestation.algorithm_id) {
                return Err("attestation references missing algorithm".to_string());
            }
        }
        for evidence in self.evidence.values() {
            if !algorithm_set.contains(&evidence.algorithm_id) {
                return Err("evidence references missing algorithm".to_string());
            }
        }
        for finding in self.findings.values() {
            if !algorithm_set.contains(&finding.algorithm_id) {
                return Err("finding references missing algorithm".to_string());
            }
        }
        for gate in self.migration_gates.values() {
            if !algorithm_set.contains(&gate.from_algorithm_id)
                || !algorithm_set.contains(&gate.to_algorithm_id)
            {
                return Err("migration gate references missing algorithm".to_string());
            }
        }
        if self.counters().open_critical_finding_count > self.config.max_open_critical_findings {
            return Err("crypto readiness has too many open critical findings".to_string());
        }
        Ok(self.state_root())
    }
}

pub fn crypto_readiness_state_root_from_record(record: &Value) -> String {
    crypto_readiness_payload_root("CRYPTO-READINESS-STATE", record)
}

pub fn crypto_readiness_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CRYPTO_READINESS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn crypto_readiness_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CRYPTO_READINESS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn crypto_readiness_algorithm_id(
    domain: CryptoReadinessDomain,
    primitive_kind: CryptoPrimitiveKind,
    label: &str,
    version: &str,
    spec_root: &str,
    parameter_root: &str,
) -> String {
    domain_hash(
        "CRYPTO-READINESS-ALGORITHM-ID",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(primitive_kind.as_str()),
            HashPart::Str(label),
            HashPart::Str(version),
            HashPart::Str(spec_root),
            HashPart::Str(parameter_root),
        ],
        32,
    )
}

pub fn crypto_readiness_attestation_id(
    algorithm_id: &str,
    implementation_label: &str,
    artifact_root: &str,
    build_root: &str,
    attested_at_height: u64,
) -> String {
    domain_hash(
        "CRYPTO-READINESS-ATTESTATION-ID",
        &[
            HashPart::Str(algorithm_id),
            HashPart::Str(implementation_label),
            HashPart::Str(artifact_root),
            HashPart::Str(build_root),
            HashPart::Int(attested_at_height as i128),
        ],
        32,
    )
}

pub fn crypto_readiness_evidence_id(
    algorithm_id: &str,
    evidence_kind: CryptoEvidenceKind,
    submitter_label: &str,
    evidence_root: &str,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "CRYPTO-READINESS-EVIDENCE-ID",
        &[
            HashPart::Str(algorithm_id),
            HashPart::Str(evidence_kind.as_str()),
            HashPart::Str(submitter_label),
            HashPart::Str(evidence_root),
            HashPart::Int(submitted_at_height as i128),
        ],
        32,
    )
}

pub fn crypto_readiness_finding_id(
    algorithm_id: &str,
    severity: CryptoFindingSeverity,
    title_root: &str,
    evidence_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "CRYPTO-READINESS-FINDING-ID",
        &[
            HashPart::Str(algorithm_id),
            HashPart::Str(severity.as_str()),
            HashPart::Str(title_root),
            HashPart::Str(evidence_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn crypto_readiness_migration_gate_id(
    from_algorithm_id: &str,
    to_algorithm_id: &str,
    domain: CryptoReadinessDomain,
    guardrail_root: &str,
    scheduled_at_height: u64,
) -> String {
    domain_hash(
        "CRYPTO-READINESS-MIGRATION-GATE-ID",
        &[
            HashPart::Str(from_algorithm_id),
            HashPart::Str(to_algorithm_id),
            HashPart::Str(domain.as_str()),
            HashPart::Str(guardrail_root),
            HashPart::Int(scheduled_at_height as i128),
        ],
        32,
    )
}

fn keyed_value_root(domain: &str, mut records: Vec<(String, Value)>) -> String {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    let leaves = records
        .into_iter()
        .map(|(key, value)| json!({"key": key, "value": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn with_root_field(mut record: Value, field: &str, root: String) -> Value {
    if let Value::Object(values) = &mut record {
        values.insert(field.to_string(), Value::String(root));
    }
    record
}

fn require_non_empty(label: &str, value: &str) -> CryptoReadinessResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn require_positive(label: &str, value: u64) -> CryptoReadinessResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn require_bps(label: &str, value: u64) -> CryptoReadinessResult<()> {
    if value > CRYPTO_READINESS_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

fn ensure_unique_strings(values: &[String], label: &str) -> CryptoReadinessResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(label, value)?;
        if !seen.insert(value.clone()) {
            return Err(format!("{label} contains duplicate value"));
        }
    }
    Ok(())
}
