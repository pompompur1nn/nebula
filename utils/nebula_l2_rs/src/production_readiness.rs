use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ProductionReadinessResult<T> = Result<T, String>;

pub const PRODUCTION_READINESS_PROTOCOL_VERSION: &str = "nebula-production-readiness-v1";
pub const PRODUCTION_READINESS_DEFAULT_REVIEW_TTL_BLOCKS: u64 = 720;
pub const PRODUCTION_READINESS_DEFAULT_EVIDENCE_TTL_BLOCKS: u64 = 2_880;
pub const PRODUCTION_READINESS_DEFAULT_SIGNOFF_TTL_BLOCKS: u64 = 10_080;
pub const PRODUCTION_READINESS_DEFAULT_MIN_RELEASE_SCORE_BPS: u64 = 9_500;
pub const PRODUCTION_READINESS_DEFAULT_MIN_CRITICAL_SCORE_BPS: u64 = 10_000;
pub const PRODUCTION_READINESS_DEFAULT_MAX_OPEN_BLOCKERS: u64 = 0;
pub const PRODUCTION_READINESS_MAX_BPS: u64 = 10_000;
pub const PRODUCTION_READINESS_MAX_GATES: usize = 512;
pub const PRODUCTION_READINESS_MAX_EVIDENCE: usize = 1_024;
pub const PRODUCTION_READINESS_MAX_SIGNOFFS: usize = 512;
pub const PRODUCTION_READINESS_MAX_INCIDENT_DRILLS: usize = 256;
pub const PRODUCTION_READINESS_MAX_REPORTS: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessDomain {
    Cryptography,
    MoneroBridge,
    Sequencing,
    DataAvailability,
    Proving,
    Privacy,
    Defi,
    SmartContracts,
    Fees,
    Wallets,
    Operations,
    Governance,
}

impl ReadinessDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cryptography => "cryptography",
            Self::MoneroBridge => "monero_bridge",
            Self::Sequencing => "sequencing",
            Self::DataAvailability => "data_availability",
            Self::Proving => "proving",
            Self::Privacy => "privacy",
            Self::Defi => "defi",
            Self::SmartContracts => "smart_contracts",
            Self::Fees => "fees",
            Self::Wallets => "wallets",
            Self::Operations => "operations",
            Self::Governance => "governance",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessGateKind {
    DesignSpec,
    ImplementationComplete,
    UnitCoverage,
    DevnetSmoke,
    StressRun,
    CryptographicReview,
    PrivacyReview,
    BridgeAudit,
    EconomicReview,
    IncidentDrill,
    OperatorRunbook,
    ReleaseSignoff,
}

impl ReadinessGateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DesignSpec => "design_spec",
            Self::ImplementationComplete => "implementation_complete",
            Self::UnitCoverage => "unit_coverage",
            Self::DevnetSmoke => "devnet_smoke",
            Self::StressRun => "stress_run",
            Self::CryptographicReview => "cryptographic_review",
            Self::PrivacyReview => "privacy_review",
            Self::BridgeAudit => "bridge_audit",
            Self::EconomicReview => "economic_review",
            Self::IncidentDrill => "incident_drill",
            Self::OperatorRunbook => "operator_runbook",
            Self::ReleaseSignoff => "release_signoff",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessSeverity {
    Advisory,
    Required,
    Critical,
    Blocker,
}

impl ReadinessSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Advisory => "advisory",
            Self::Required => "required",
            Self::Critical => "critical",
            Self::Blocker => "blocker",
        }
    }

    pub fn weight_bps(self) -> u64 {
        match self {
            Self::Advisory => 1_000,
            Self::Required => 5_000,
            Self::Critical => 8_500,
            Self::Blocker => 10_000,
        }
    }

    pub fn blocks_release(self) -> bool {
        matches!(self, Self::Critical | Self::Blocker)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessStatus {
    Missing,
    Draft,
    InReview,
    Accepted,
    Waived,
    Failed,
    Expired,
}

impl ReadinessStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Draft => "draft",
            Self::InReview => "in_review",
            Self::Accepted => "accepted",
            Self::Waived => "waived",
            Self::Failed => "failed",
            Self::Expired => "expired",
        }
    }

    pub fn is_passing(self) -> bool {
        matches!(self, Self::Accepted | Self::Waived)
    }

    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Missing | Self::Draft | Self::InReview | Self::Failed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    SourceRoot,
    CommandOutput,
    DevnetRun,
    AuditReport,
    FormalModel,
    PerformanceReport,
    PrivacyAnalysis,
    IncidentTranscript,
    GovernanceVote,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SourceRoot => "source_root",
            Self::CommandOutput => "command_output",
            Self::DevnetRun => "devnet_run",
            Self::AuditReport => "audit_report",
            Self::FormalModel => "formal_model",
            Self::PerformanceReport => "performance_report",
            Self::PrivacyAnalysis => "privacy_analysis",
            Self::IncidentTranscript => "incident_transcript",
            Self::GovernanceVote => "governance_vote",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignoffRole {
    CoreProtocol,
    Cryptography,
    BridgeSecurity,
    Privacy,
    DefiRisk,
    Operations,
    Governance,
}

impl SignoffRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CoreProtocol => "core_protocol",
            Self::Cryptography => "cryptography",
            Self::BridgeSecurity => "bridge_security",
            Self::Privacy => "privacy",
            Self::DefiRisk => "defi_risk",
            Self::Operations => "operations",
            Self::Governance => "governance",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionReadinessConfig {
    pub config_id: String,
    pub review_ttl_blocks: u64,
    pub evidence_ttl_blocks: u64,
    pub signoff_ttl_blocks: u64,
    pub min_release_score_bps: u64,
    pub min_critical_score_bps: u64,
    pub max_open_blockers: u64,
    pub require_pq_signoff: bool,
    pub require_external_bridge_audit: bool,
    pub require_privacy_review: bool,
    pub allow_waivers: bool,
}

impl Default for ProductionReadinessConfig {
    fn default() -> Self {
        let mut config = Self {
            config_id: String::new(),
            review_ttl_blocks: PRODUCTION_READINESS_DEFAULT_REVIEW_TTL_BLOCKS,
            evidence_ttl_blocks: PRODUCTION_READINESS_DEFAULT_EVIDENCE_TTL_BLOCKS,
            signoff_ttl_blocks: PRODUCTION_READINESS_DEFAULT_SIGNOFF_TTL_BLOCKS,
            min_release_score_bps: PRODUCTION_READINESS_DEFAULT_MIN_RELEASE_SCORE_BPS,
            min_critical_score_bps: PRODUCTION_READINESS_DEFAULT_MIN_CRITICAL_SCORE_BPS,
            max_open_blockers: PRODUCTION_READINESS_DEFAULT_MAX_OPEN_BLOCKERS,
            require_pq_signoff: true,
            require_external_bridge_audit: true,
            require_privacy_review: true,
            allow_waivers: false,
        };
        config.config_id = production_readiness_config_id(&config.identity_record());
        config
    }
}

impl ProductionReadinessConfig {
    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "production_readiness_config",
            "chain_id": CHAIN_ID,
            "protocol_version": PRODUCTION_READINESS_PROTOCOL_VERSION,
            "review_ttl_blocks": self.review_ttl_blocks,
            "evidence_ttl_blocks": self.evidence_ttl_blocks,
            "signoff_ttl_blocks": self.signoff_ttl_blocks,
            "min_release_score_bps": self.min_release_score_bps,
            "min_critical_score_bps": self.min_critical_score_bps,
            "max_open_blockers": self.max_open_blockers,
            "require_pq_signoff": self.require_pq_signoff,
            "require_external_bridge_audit": self.require_external_bridge_audit,
            "require_privacy_review": self.require_privacy_review,
            "allow_waivers": self.allow_waivers,
        })
    }

    pub fn config_root(&self) -> String {
        production_readiness_payload_root("PRODUCTION-READINESS-CONFIG", &self.identity_record())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("production readiness config object");
        object.insert(
            "config_id".to_string(),
            Value::String(self.config_id.clone()),
        );
        object.insert("config_root".to_string(), Value::String(self.config_root()));
        record
    }

    pub fn validate(&self) -> ProductionReadinessResult<String> {
        ensure_non_empty(&self.config_id, "production readiness config id")?;
        ensure_positive(self.review_ttl_blocks, "production readiness review ttl")?;
        ensure_positive(
            self.evidence_ttl_blocks,
            "production readiness evidence ttl",
        )?;
        ensure_positive(self.signoff_ttl_blocks, "production readiness signoff ttl")?;
        validate_bps(
            self.min_release_score_bps,
            "production readiness min release score",
        )?;
        validate_bps(
            self.min_critical_score_bps,
            "production readiness min critical score",
        )?;
        if self.min_critical_score_bps < self.min_release_score_bps {
            return Err("production readiness critical score below release score".to_string());
        }
        if self.config_id != production_readiness_config_id(&self.identity_record()) {
            return Err("production readiness config id mismatch".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessGate {
    pub gate_id: String,
    pub domain: ReadinessDomain,
    pub gate_kind: ReadinessGateKind,
    pub severity: ReadinessSeverity,
    pub label: String,
    pub requirement_root: String,
    pub owner_commitment: String,
    pub component_root: String,
    pub status: ReadinessStatus,
    pub opened_at_height: u64,
    pub due_height: u64,
    pub required_evidence_kinds: BTreeSet<String>,
}

impl ReadinessGate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        domain: ReadinessDomain,
        gate_kind: ReadinessGateKind,
        severity: ReadinessSeverity,
        label: impl Into<String>,
        requirement: &Value,
        owner_label: impl Into<String>,
        components: &[String],
        opened_at_height: u64,
        due_height: u64,
        required_evidence_kinds: impl IntoIterator<Item = EvidenceKind>,
    ) -> ProductionReadinessResult<Self> {
        let label = label.into();
        let owner_label = owner_label.into();
        ensure_non_empty(&label, "production readiness gate label")?;
        ensure_non_empty(&owner_label, "production readiness gate owner")?;
        if due_height <= opened_at_height {
            return Err("production readiness gate due height must follow open height".to_string());
        }
        if components.is_empty() {
            return Err("production readiness gate needs components".to_string());
        }
        let requirement_root =
            production_readiness_payload_root("PRODUCTION-READINESS-GATE-REQUIREMENT", requirement);
        let owner_commitment =
            production_readiness_string_root("PRODUCTION-READINESS-GATE-OWNER", &owner_label);
        let component_root = production_readiness_string_set_root(
            "PRODUCTION-READINESS-GATE-COMPONENTS",
            components,
        );
        let required_evidence_kinds = required_evidence_kinds
            .into_iter()
            .map(|kind| kind.as_str().to_string())
            .collect::<BTreeSet<_>>();
        if required_evidence_kinds.is_empty() {
            return Err("production readiness gate needs evidence kinds".to_string());
        }
        let evidence_kind_root = production_readiness_string_set_root(
            "PRODUCTION-READINESS-GATE-EVIDENCE-KINDS",
            &required_evidence_kinds.iter().cloned().collect::<Vec<_>>(),
        );
        let status = ReadinessStatus::Missing;
        let gate_id = production_readiness_gate_id(
            domain,
            gate_kind,
            severity,
            &label,
            &requirement_root,
            &owner_commitment,
            &component_root,
            status,
            opened_at_height,
            due_height,
            &evidence_kind_root,
        );
        Ok(Self {
            gate_id,
            domain,
            gate_kind,
            severity,
            label,
            requirement_root,
            owner_commitment,
            component_root,
            status,
            opened_at_height,
            due_height,
            required_evidence_kinds,
        })
    }

    pub fn evidence_kind_root(&self) -> String {
        production_readiness_string_set_root(
            "PRODUCTION-READINESS-GATE-EVIDENCE-KINDS",
            &self
                .required_evidence_kinds
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn with_status(mut self, status: ReadinessStatus) -> Self {
        self.status = status;
        self.gate_id = production_readiness_gate_id(
            self.domain,
            self.gate_kind,
            self.severity,
            &self.label,
            &self.requirement_root,
            &self.owner_commitment,
            &self.component_root,
            self.status,
            self.opened_at_height,
            self.due_height,
            &self.evidence_kind_root(),
        );
        self
    }

    pub fn validate(&self) -> ProductionReadinessResult<()> {
        ensure_non_empty(&self.gate_id, "production readiness gate id")?;
        ensure_non_empty(&self.label, "production readiness gate label")?;
        ensure_non_empty(
            &self.requirement_root,
            "production readiness gate requirement root",
        )?;
        ensure_non_empty(&self.owner_commitment, "production readiness gate owner")?;
        ensure_non_empty(
            &self.component_root,
            "production readiness gate component root",
        )?;
        if self.due_height <= self.opened_at_height {
            return Err("production readiness gate due height must follow open height".to_string());
        }
        if self.required_evidence_kinds.is_empty() {
            return Err("production readiness gate evidence kinds cannot be empty".to_string());
        }
        if self.gate_id
            != production_readiness_gate_id(
                self.domain,
                self.gate_kind,
                self.severity,
                &self.label,
                &self.requirement_root,
                &self.owner_commitment,
                &self.component_root,
                self.status,
                self.opened_at_height,
                self.due_height,
                &self.evidence_kind_root(),
            )
        {
            return Err("production readiness gate id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "production_readiness_gate",
            "chain_id": CHAIN_ID,
            "protocol_version": PRODUCTION_READINESS_PROTOCOL_VERSION,
            "gate_id": self.gate_id,
            "domain": self.domain.as_str(),
            "gate_kind": self.gate_kind.as_str(),
            "severity": self.severity.as_str(),
            "label": self.label,
            "requirement_root": self.requirement_root,
            "owner_commitment": self.owner_commitment,
            "component_root": self.component_root,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "due_height": self.due_height,
            "required_evidence_kinds": self.required_evidence_kinds.iter().cloned().collect::<Vec<_>>(),
            "evidence_kind_root": self.evidence_kind_root(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessEvidence {
    pub evidence_id: String,
    pub gate_id: String,
    pub evidence_kind: EvidenceKind,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub submitter_commitment: String,
    pub artifact_root: String,
    pub command_root: String,
    pub result_root: String,
    pub accepted: bool,
}

impl ReadinessEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        gate_id: impl Into<String>,
        evidence_kind: EvidenceKind,
        submitted_at_height: u64,
        expires_at_height: u64,
        submitter_label: impl Into<String>,
        artifact: &Value,
        command: &Value,
        result: &Value,
        accepted: bool,
    ) -> ProductionReadinessResult<Self> {
        let gate_id = gate_id.into();
        let submitter_label = submitter_label.into();
        ensure_non_empty(&gate_id, "production readiness evidence gate id")?;
        ensure_non_empty(&submitter_label, "production readiness evidence submitter")?;
        if expires_at_height <= submitted_at_height {
            return Err(
                "production readiness evidence expiry must follow submit height".to_string(),
            );
        }
        let submitter_commitment = production_readiness_string_root(
            "PRODUCTION-READINESS-EVIDENCE-SUBMITTER",
            &submitter_label,
        );
        let artifact_root =
            production_readiness_payload_root("PRODUCTION-READINESS-EVIDENCE-ARTIFACT", artifact);
        let command_root =
            production_readiness_payload_root("PRODUCTION-READINESS-EVIDENCE-COMMAND", command);
        let result_root =
            production_readiness_payload_root("PRODUCTION-READINESS-EVIDENCE-RESULT", result);
        let evidence_id = production_readiness_evidence_id(
            &gate_id,
            evidence_kind,
            submitted_at_height,
            expires_at_height,
            &submitter_commitment,
            &artifact_root,
            &command_root,
            &result_root,
            accepted,
        );
        Ok(Self {
            evidence_id,
            gate_id,
            evidence_kind,
            submitted_at_height,
            expires_at_height,
            submitter_commitment,
            artifact_root,
            command_root,
            result_root,
            accepted,
        })
    }

    pub fn validate(&self) -> ProductionReadinessResult<()> {
        ensure_non_empty(&self.evidence_id, "production readiness evidence id")?;
        ensure_non_empty(&self.gate_id, "production readiness evidence gate id")?;
        ensure_non_empty(
            &self.submitter_commitment,
            "production readiness evidence submitter",
        )?;
        ensure_non_empty(
            &self.artifact_root,
            "production readiness evidence artifact root",
        )?;
        ensure_non_empty(
            &self.command_root,
            "production readiness evidence command root",
        )?;
        ensure_non_empty(
            &self.result_root,
            "production readiness evidence result root",
        )?;
        if self.expires_at_height <= self.submitted_at_height {
            return Err(
                "production readiness evidence expiry must follow submit height".to_string(),
            );
        }
        if self.evidence_id
            != production_readiness_evidence_id(
                &self.gate_id,
                self.evidence_kind,
                self.submitted_at_height,
                self.expires_at_height,
                &self.submitter_commitment,
                &self.artifact_root,
                &self.command_root,
                &self.result_root,
                self.accepted,
            )
        {
            return Err("production readiness evidence id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "production_readiness_evidence",
            "chain_id": CHAIN_ID,
            "protocol_version": PRODUCTION_READINESS_PROTOCOL_VERSION,
            "evidence_id": self.evidence_id,
            "gate_id": self.gate_id,
            "evidence_kind": self.evidence_kind.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "submitter_commitment": self.submitter_commitment,
            "artifact_root": self.artifact_root,
            "command_root": self.command_root,
            "result_root": self.result_root,
            "accepted": self.accepted,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseSignoff {
    pub signoff_id: String,
    pub role: SignoffRole,
    pub signer_commitment: String,
    pub gate_root: String,
    pub evidence_root: String,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
    pub pq_signature_root: String,
    pub accepted: bool,
}

impl ReleaseSignoff {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        role: SignoffRole,
        signer_label: impl Into<String>,
        gate_ids: &[String],
        evidence_ids: &[String],
        signed_at_height: u64,
        expires_at_height: u64,
        pq_signature_material: impl Into<String>,
        accepted: bool,
    ) -> ProductionReadinessResult<Self> {
        let signer_label = signer_label.into();
        let pq_signature_material = pq_signature_material.into();
        ensure_non_empty(&signer_label, "production readiness signoff signer")?;
        ensure_non_empty(
            &pq_signature_material,
            "production readiness signoff pq signature",
        )?;
        if gate_ids.is_empty() {
            return Err("production readiness signoff needs gates".to_string());
        }
        if evidence_ids.is_empty() {
            return Err("production readiness signoff needs evidence".to_string());
        }
        if expires_at_height <= signed_at_height {
            return Err(
                "production readiness signoff expiry must follow signed height".to_string(),
            );
        }
        let signer_commitment =
            production_readiness_string_root("PRODUCTION-READINESS-SIGNER", &signer_label);
        let gate_root =
            production_readiness_string_set_root("PRODUCTION-READINESS-SIGNOFF-GATES", gate_ids);
        let evidence_root = production_readiness_string_set_root(
            "PRODUCTION-READINESS-SIGNOFF-EVIDENCE",
            evidence_ids,
        );
        let pq_signature_root = production_readiness_string_root(
            "PRODUCTION-READINESS-SIGNOFF-PQ-SIG",
            &pq_signature_material,
        );
        let signoff_id = production_readiness_signoff_id(
            role,
            &signer_commitment,
            &gate_root,
            &evidence_root,
            signed_at_height,
            expires_at_height,
            &pq_signature_root,
            accepted,
        );
        Ok(Self {
            signoff_id,
            role,
            signer_commitment,
            gate_root,
            evidence_root,
            signed_at_height,
            expires_at_height,
            pq_signature_root,
            accepted,
        })
    }

    pub fn validate(&self) -> ProductionReadinessResult<()> {
        ensure_non_empty(&self.signoff_id, "production readiness signoff id")?;
        ensure_non_empty(
            &self.signer_commitment,
            "production readiness signoff signer",
        )?;
        ensure_non_empty(&self.gate_root, "production readiness signoff gate root")?;
        ensure_non_empty(
            &self.evidence_root,
            "production readiness signoff evidence root",
        )?;
        ensure_non_empty(
            &self.pq_signature_root,
            "production readiness signoff pq signature",
        )?;
        if self.expires_at_height <= self.signed_at_height {
            return Err(
                "production readiness signoff expiry must follow signed height".to_string(),
            );
        }
        if self.signoff_id
            != production_readiness_signoff_id(
                self.role,
                &self.signer_commitment,
                &self.gate_root,
                &self.evidence_root,
                self.signed_at_height,
                self.expires_at_height,
                &self.pq_signature_root,
                self.accepted,
            )
        {
            return Err("production readiness signoff id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "production_readiness_signoff",
            "chain_id": CHAIN_ID,
            "protocol_version": PRODUCTION_READINESS_PROTOCOL_VERSION,
            "signoff_id": self.signoff_id,
            "role": self.role.as_str(),
            "signer_commitment": self.signer_commitment,
            "gate_root": self.gate_root,
            "evidence_root": self.evidence_root,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
            "pq_signature_root": self.pq_signature_root,
            "accepted": self.accepted,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentDrill {
    pub drill_id: String,
    pub domain: ReadinessDomain,
    pub label: String,
    pub scenario_root: String,
    pub participant_root: String,
    pub started_at_height: u64,
    pub completed_at_height: u64,
    pub outcome_root: String,
    pub passed: bool,
}

impl IncidentDrill {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        domain: ReadinessDomain,
        label: impl Into<String>,
        scenario: &Value,
        participants: &[String],
        started_at_height: u64,
        completed_at_height: u64,
        outcome: &Value,
        passed: bool,
    ) -> ProductionReadinessResult<Self> {
        let label = label.into();
        ensure_non_empty(&label, "production readiness drill label")?;
        if participants.is_empty() {
            return Err("production readiness drill needs participants".to_string());
        }
        if completed_at_height < started_at_height {
            return Err("production readiness drill completed before start".to_string());
        }
        let scenario_root =
            production_readiness_payload_root("PRODUCTION-READINESS-DRILL-SCENARIO", scenario);
        let participant_root = production_readiness_string_set_root(
            "PRODUCTION-READINESS-DRILL-PARTICIPANTS",
            participants,
        );
        let outcome_root =
            production_readiness_payload_root("PRODUCTION-READINESS-DRILL-OUTCOME", outcome);
        let drill_id = production_readiness_drill_id(
            domain,
            &label,
            &scenario_root,
            &participant_root,
            started_at_height,
            completed_at_height,
            &outcome_root,
            passed,
        );
        Ok(Self {
            drill_id,
            domain,
            label,
            scenario_root,
            participant_root,
            started_at_height,
            completed_at_height,
            outcome_root,
            passed,
        })
    }

    pub fn validate(&self) -> ProductionReadinessResult<()> {
        ensure_non_empty(&self.drill_id, "production readiness drill id")?;
        ensure_non_empty(&self.label, "production readiness drill label")?;
        ensure_non_empty(&self.scenario_root, "production readiness drill scenario")?;
        ensure_non_empty(
            &self.participant_root,
            "production readiness drill participant root",
        )?;
        ensure_non_empty(&self.outcome_root, "production readiness drill outcome")?;
        if self.completed_at_height < self.started_at_height {
            return Err("production readiness drill completed before start".to_string());
        }
        if self.drill_id
            != production_readiness_drill_id(
                self.domain,
                &self.label,
                &self.scenario_root,
                &self.participant_root,
                self.started_at_height,
                self.completed_at_height,
                &self.outcome_root,
                self.passed,
            )
        {
            return Err("production readiness drill id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "production_readiness_incident_drill",
            "chain_id": CHAIN_ID,
            "protocol_version": PRODUCTION_READINESS_PROTOCOL_VERSION,
            "drill_id": self.drill_id,
            "domain": self.domain.as_str(),
            "label": self.label,
            "scenario_root": self.scenario_root,
            "participant_root": self.participant_root,
            "started_at_height": self.started_at_height,
            "completed_at_height": self.completed_at_height,
            "outcome_root": self.outcome_root,
            "passed": self.passed,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessReport {
    pub report_id: String,
    pub height: u64,
    pub gate_root: String,
    pub evidence_root: String,
    pub signoff_root: String,
    pub drill_root: String,
    pub release_score_bps: u64,
    pub critical_score_bps: u64,
    pub open_blockers: u64,
    pub release_candidate: bool,
}

impl ReadinessReport {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        height: u64,
        gate_root: impl Into<String>,
        evidence_root: impl Into<String>,
        signoff_root: impl Into<String>,
        drill_root: impl Into<String>,
        release_score_bps: u64,
        critical_score_bps: u64,
        open_blockers: u64,
        release_candidate: bool,
    ) -> ProductionReadinessResult<Self> {
        validate_bps(release_score_bps, "production readiness release score")?;
        validate_bps(critical_score_bps, "production readiness critical score")?;
        let gate_root = gate_root.into();
        let evidence_root = evidence_root.into();
        let signoff_root = signoff_root.into();
        let drill_root = drill_root.into();
        ensure_non_empty(&gate_root, "production readiness report gate root")?;
        ensure_non_empty(&evidence_root, "production readiness report evidence root")?;
        ensure_non_empty(&signoff_root, "production readiness report signoff root")?;
        ensure_non_empty(&drill_root, "production readiness report drill root")?;
        let report_id = production_readiness_report_id(
            height,
            &gate_root,
            &evidence_root,
            &signoff_root,
            &drill_root,
            release_score_bps,
            critical_score_bps,
            open_blockers,
            release_candidate,
        );
        Ok(Self {
            report_id,
            height,
            gate_root,
            evidence_root,
            signoff_root,
            drill_root,
            release_score_bps,
            critical_score_bps,
            open_blockers,
            release_candidate,
        })
    }

    pub fn validate(&self) -> ProductionReadinessResult<()> {
        ensure_non_empty(&self.report_id, "production readiness report id")?;
        ensure_non_empty(&self.gate_root, "production readiness report gate root")?;
        ensure_non_empty(
            &self.evidence_root,
            "production readiness report evidence root",
        )?;
        ensure_non_empty(
            &self.signoff_root,
            "production readiness report signoff root",
        )?;
        ensure_non_empty(&self.drill_root, "production readiness report drill root")?;
        validate_bps(self.release_score_bps, "production readiness release score")?;
        validate_bps(
            self.critical_score_bps,
            "production readiness critical score",
        )?;
        if self.report_id
            != production_readiness_report_id(
                self.height,
                &self.gate_root,
                &self.evidence_root,
                &self.signoff_root,
                &self.drill_root,
                self.release_score_bps,
                self.critical_score_bps,
                self.open_blockers,
                self.release_candidate,
            )
        {
            return Err("production readiness report id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "production_readiness_report",
            "chain_id": CHAIN_ID,
            "protocol_version": PRODUCTION_READINESS_PROTOCOL_VERSION,
            "report_id": self.report_id,
            "height": self.height,
            "gate_root": self.gate_root,
            "evidence_root": self.evidence_root,
            "signoff_root": self.signoff_root,
            "drill_root": self.drill_root,
            "release_score_bps": self.release_score_bps,
            "critical_score_bps": self.critical_score_bps,
            "open_blockers": self.open_blockers,
            "release_candidate": self.release_candidate,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionReadinessRoots {
    pub config_root: String,
    pub gate_root: String,
    pub evidence_root: String,
    pub signoff_root: String,
    pub drill_root: String,
    pub report_root: String,
    pub state_root: String,
}

impl ProductionReadinessRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "production_readiness_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PRODUCTION_READINESS_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "gate_root": self.gate_root,
            "evidence_root": self.evidence_root,
            "signoff_root": self.signoff_root,
            "drill_root": self.drill_root,
            "report_root": self.report_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionReadinessCounters {
    pub gates: u64,
    pub accepted_gates: u64,
    pub open_gates: u64,
    pub blocker_gates: u64,
    pub accepted_evidence: u64,
    pub signoffs: u64,
    pub accepted_signoffs: u64,
    pub incident_drills: u64,
    pub passed_drills: u64,
    pub reports: u64,
    pub release_score_bps: u64,
    pub critical_score_bps: u64,
}

impl ProductionReadinessCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "production_readiness_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PRODUCTION_READINESS_PROTOCOL_VERSION,
            "gates": self.gates,
            "accepted_gates": self.accepted_gates,
            "open_gates": self.open_gates,
            "blocker_gates": self.blocker_gates,
            "accepted_evidence": self.accepted_evidence,
            "signoffs": self.signoffs,
            "accepted_signoffs": self.accepted_signoffs,
            "incident_drills": self.incident_drills,
            "passed_drills": self.passed_drills,
            "reports": self.reports,
            "release_score_bps": self.release_score_bps,
            "critical_score_bps": self.critical_score_bps,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionReadinessState {
    pub height: u64,
    pub config: ProductionReadinessConfig,
    pub gates: BTreeMap<String, ReadinessGate>,
    pub evidence: BTreeMap<String, ReadinessEvidence>,
    pub signoffs: BTreeMap<String, ReleaseSignoff>,
    pub incident_drills: BTreeMap<String, IncidentDrill>,
    pub reports: BTreeMap<String, ReadinessReport>,
}

impl Default for ProductionReadinessState {
    fn default() -> Self {
        Self::new(ProductionReadinessConfig::default())
            .expect("default production readiness config")
    }
}

impl ProductionReadinessState {
    pub fn new(config: ProductionReadinessConfig) -> ProductionReadinessResult<Self> {
        config.validate()?;
        Ok(Self {
            height: 0,
            config,
            gates: BTreeMap::new(),
            evidence: BTreeMap::new(),
            signoffs: BTreeMap::new(),
            incident_drills: BTreeMap::new(),
            reports: BTreeMap::new(),
        })
    }

    pub fn devnet() -> ProductionReadinessResult<Self> {
        let mut state = Self::new(ProductionReadinessConfig::default())?;
        state.set_height(1);

        let mut gates = vec![
            ReadinessGate::new(
                ReadinessDomain::Cryptography,
                ReadinessGateKind::CryptographicReview,
                ReadinessSeverity::Blocker,
                "post_quantum_crypto_review",
                &json!({
                    "required": "external review of PQ auth, KEM labels, replay protection, and migration ceremonies",
                    "components": ["quantum", "pq_sessions", "pq_bridge_ops", "validator_security"],
                }),
                "cryptography-review-owner",
                &[
                    "quantum".to_string(),
                    "pq_sessions".to_string(),
                    "pq_bridge_ops".to_string(),
                ],
                1,
                720,
                [EvidenceKind::AuditReport, EvidenceKind::FormalModel],
            )?,
            ReadinessGate::new(
                ReadinessDomain::MoneroBridge,
                ReadinessGateKind::BridgeAudit,
                ReadinessSeverity::Blocker,
                "monero_bridge_security_audit",
                &json!({
                    "required": "bridge reserve, withdrawal, watcher, recovery, and reorg handling audit",
                    "components": ["bridge_finality", "bridge_recovery", "monero_watch", "reserve_proofs"],
                }),
                "bridge-security-owner",
                &[
                    "bridge_finality".to_string(),
                    "bridge_recovery".to_string(),
                    "monero_watch".to_string(),
                ],
                1,
                720,
                [EvidenceKind::AuditReport, EvidenceKind::IncidentTranscript],
            )?,
            ReadinessGate::new(
                ReadinessDomain::Privacy,
                ReadinessGateKind::PrivacyReview,
                ReadinessSeverity::Critical,
                "privacy_leakage_review",
                &json!({
                    "required": "review metadata, disclosure roots, private mempool, wallet view keys, DeFi intents",
                    "components": ["privacy_pool", "private_dex", "threshold_encrypted_mempool", "wallet_orchestrator"],
                }),
                "privacy-review-owner",
                &[
                    "privacy_pool".to_string(),
                    "private_dex".to_string(),
                    "private_orderflow".to_string(),
                ],
                1,
                720,
                [EvidenceKind::PrivacyAnalysis, EvidenceKind::AuditReport],
            )?,
            ReadinessGate::new(
                ReadinessDomain::Sequencing,
                ReadinessGateKind::StressRun,
                ReadinessSeverity::Critical,
                "fast_finality_and_ordering_stress",
                &json!({
                    "required": "stress preconfirmations, encrypted mempool, fair ordering, DA and low fee lanes",
                    "target_blocks": 10000,
                    "target_p95_ms": 500,
                }),
                "sequencing-owner",
                &[
                    "decentralized_sequencer".to_string(),
                    "threshold_encrypted_mempool".to_string(),
                    "microblock_pipeline".to_string(),
                ],
                1,
                720,
                [EvidenceKind::PerformanceReport, EvidenceKind::CommandOutput],
            )?,
            ReadinessGate::new(
                ReadinessDomain::Proving,
                ReadinessGateKind::StressRun,
                ReadinessSeverity::Critical,
                "recursive_proof_capacity_stress",
                &json!({
                    "required": "prove and recursively aggregate bridge, private contract, intent, state and fee circuits under load",
                    "target_success_bps": 9990,
                }),
                "proving-owner",
                &[
                    "recursive_proof_scheduler".to_string(),
                    "proof_compression".to_string(),
                    "validity_aggregation".to_string(),
                ],
                1,
                720,
                [EvidenceKind::PerformanceReport, EvidenceKind::DevnetRun],
            )?,
            ReadinessGate::new(
                ReadinessDomain::Fees,
                ReadinessGateKind::StressRun,
                ReadinessSeverity::Required,
                "low_fee_market_stress",
                &json!({
                    "required": "verify low-fee lanes, sponsor budgets, compression and rebates stay bounded",
                    "target_fee_rebate_bps": 6000,
                }),
                "fees-owner",
                &[
                    "fast_lane_scheduler".to_string(),
                    "fee_abstraction".to_string(),
                    "fee_compression".to_string(),
                ],
                1,
                720,
                [EvidenceKind::PerformanceReport, EvidenceKind::DevnetRun],
            )?,
        ];

        for index in 0..gates.len() {
            let gate = gates.remove(0);
            let accepted = index >= 5;
            let gate = if accepted {
                gate.with_status(ReadinessStatus::Accepted)
            } else {
                gate
            };
            let gate_id = state.insert_gate(gate.clone())?;
            let evidence = ReadinessEvidence::new(
                gate_id.clone(),
                if accepted {
                    EvidenceKind::DevnetRun
                } else {
                    EvidenceKind::SourceRoot
                },
                1,
                state.config.evidence_ttl_blocks.saturating_add(1),
                "devnet-readiness-bot",
                &json!({
                    "gate": gate.label,
                    "source": "devnet_fixture",
                    "note": if accepted { "accepted devnet evidence" } else { "placeholder source root evidence; external review still required" },
                }),
                &json!({
                    "command": if accepted { "cargo run -- devnet" } else { "source-root-capture" },
                }),
                &json!({
                    "accepted": accepted,
                    "height": 1,
                }),
                accepted,
            )?;
            state.insert_evidence(evidence)?;
        }

        let accepted_gate_ids = state
            .gates
            .values()
            .filter(|gate| gate.status.is_passing())
            .map(|gate| gate.gate_id.clone())
            .collect::<Vec<_>>();
        let accepted_evidence_ids = state
            .evidence
            .values()
            .filter(|evidence| evidence.accepted)
            .map(|evidence| evidence.evidence_id.clone())
            .collect::<Vec<_>>();
        if !accepted_gate_ids.is_empty() && !accepted_evidence_ids.is_empty() {
            let signoff = ReleaseSignoff::new(
                SignoffRole::Operations,
                "devnet-ops-signer",
                &accepted_gate_ids,
                &accepted_evidence_ids,
                1,
                state.config.signoff_ttl_blocks.saturating_add(1),
                "devnet-ops-pq-signature",
                true,
            )?;
            state.insert_signoff(signoff)?;
        }

        let drill = IncidentDrill::new(
            ReadinessDomain::MoneroBridge,
            "bridge_reorg_and_stuck_exit_drill",
            &json!({
                "scenario": "simulated Monero reorg plus stuck exit recovery",
                "actions": ["quarantine", "pause_release", "recover_exit", "publish_audit_trail"],
            }),
            &[
                "bridge_recovery".to_string(),
                "monero_watch".to_string(),
                "operator".to_string(),
            ],
            1,
            2,
            &json!({
                "passed": true,
                "recovery_ticket_root": "devnet-recovery-ticket-root",
            }),
            true,
        )?;
        state.insert_drill(drill)?;
        state.refresh_report()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for gate in self.gates.values_mut() {
            if gate.status.is_open() && height > gate.due_height {
                let updated = gate.clone().with_status(ReadinessStatus::Expired);
                *gate = updated;
            }
        }
    }

    pub fn insert_gate(&mut self, gate: ReadinessGate) -> ProductionReadinessResult<String> {
        gate.validate()?;
        let id = gate.gate_id.clone();
        self.gates.insert(id.clone(), gate);
        Ok(id)
    }

    pub fn insert_evidence(
        &mut self,
        evidence: ReadinessEvidence,
    ) -> ProductionReadinessResult<String> {
        evidence.validate()?;
        if !self.gates.contains_key(&evidence.gate_id) {
            return Err("production readiness evidence references missing gate".to_string());
        }
        let id = evidence.evidence_id.clone();
        self.evidence.insert(id.clone(), evidence);
        Ok(id)
    }

    pub fn insert_signoff(&mut self, signoff: ReleaseSignoff) -> ProductionReadinessResult<String> {
        signoff.validate()?;
        let id = signoff.signoff_id.clone();
        self.signoffs.insert(id.clone(), signoff);
        Ok(id)
    }

    pub fn insert_drill(&mut self, drill: IncidentDrill) -> ProductionReadinessResult<String> {
        drill.validate()?;
        let id = drill.drill_id.clone();
        self.incident_drills.insert(id.clone(), drill);
        Ok(id)
    }

    pub fn refresh_report(&mut self) -> ProductionReadinessResult<String> {
        let roots = self.roots_without_state();
        let counters = self.counters();
        let release_candidate = counters.release_score_bps >= self.config.min_release_score_bps
            && counters.critical_score_bps >= self.config.min_critical_score_bps
            && counters.blocker_gates <= self.config.max_open_blockers;
        let report = ReadinessReport::new(
            self.height,
            roots.gate_root,
            roots.evidence_root,
            roots.signoff_root,
            roots.drill_root,
            counters.release_score_bps,
            counters.critical_score_bps,
            counters.blocker_gates,
            release_candidate,
        )?;
        let id = report.report_id.clone();
        self.reports.insert(id.clone(), report);
        Ok(id)
    }

    pub fn roots(&self) -> ProductionReadinessRoots {
        let mut roots = self.roots_without_state();
        let state_record = json!({
            "kind": "production_readiness_state_root",
            "chain_id": CHAIN_ID,
            "protocol_version": PRODUCTION_READINESS_PROTOCOL_VERSION,
            "height": self.height,
            "config_root": roots.config_root,
            "gate_root": roots.gate_root,
            "evidence_root": roots.evidence_root,
            "signoff_root": roots.signoff_root,
            "drill_root": roots.drill_root,
            "report_root": roots.report_root,
            "counters": self.counters().public_record(),
        });
        roots.state_root = production_readiness_state_root_from_record(&state_record);
        roots
    }

    fn roots_without_state(&self) -> ProductionReadinessRoots {
        let config_root = self.config.config_root();
        let gate_root = merkle_root(
            "PRODUCTION-READINESS-GATES",
            &self
                .gates
                .values()
                .map(ReadinessGate::public_record)
                .collect::<Vec<_>>(),
        );
        let evidence_root = merkle_root(
            "PRODUCTION-READINESS-EVIDENCE",
            &self
                .evidence
                .values()
                .map(ReadinessEvidence::public_record)
                .collect::<Vec<_>>(),
        );
        let signoff_root = merkle_root(
            "PRODUCTION-READINESS-SIGNOFFS",
            &self
                .signoffs
                .values()
                .map(ReleaseSignoff::public_record)
                .collect::<Vec<_>>(),
        );
        let drill_root = merkle_root(
            "PRODUCTION-READINESS-DRILLS",
            &self
                .incident_drills
                .values()
                .map(IncidentDrill::public_record)
                .collect::<Vec<_>>(),
        );
        let report_root = merkle_root(
            "PRODUCTION-READINESS-REPORTS",
            &self
                .reports
                .values()
                .map(ReadinessReport::public_record)
                .collect::<Vec<_>>(),
        );
        ProductionReadinessRoots {
            config_root,
            gate_root,
            evidence_root,
            signoff_root,
            drill_root,
            report_root,
            state_root: String::new(),
        }
    }

    pub fn counters(&self) -> ProductionReadinessCounters {
        let gates = self.gates.values().collect::<Vec<_>>();
        let accepted_gates = gates.iter().filter(|gate| gate.status.is_passing()).count() as u64;
        let open_gates = gates.iter().filter(|gate| gate.status.is_open()).count() as u64;
        let blocker_gates = gates
            .iter()
            .filter(|gate| gate.severity.blocks_release() && !gate.status.is_passing())
            .count() as u64;
        let critical_gates = gates
            .iter()
            .filter(|gate| gate.severity.blocks_release())
            .collect::<Vec<_>>();
        let accepted_critical = critical_gates
            .iter()
            .filter(|gate| gate.status.is_passing())
            .count() as u64;
        let accepted_evidence = self
            .evidence
            .values()
            .filter(|evidence| evidence.accepted)
            .count() as u64;
        let accepted_signoffs = self
            .signoffs
            .values()
            .filter(|signoff| signoff.accepted)
            .count() as u64;
        let passed_drills = self
            .incident_drills
            .values()
            .filter(|drill| drill.passed)
            .count() as u64;
        ProductionReadinessCounters {
            gates: gates.len() as u64,
            accepted_gates,
            open_gates,
            blocker_gates,
            accepted_evidence,
            signoffs: self.signoffs.len() as u64,
            accepted_signoffs,
            incident_drills: self.incident_drills.len() as u64,
            passed_drills,
            reports: self.reports.len() as u64,
            release_score_bps: ratio_bps(accepted_gates, gates.len() as u64),
            critical_score_bps: ratio_bps(accepted_critical, critical_gates.len() as u64),
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "production_readiness_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRODUCTION_READINESS_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "gates": self.gates.values().map(ReadinessGate::public_record).collect::<Vec<_>>(),
            "evidence": self.evidence.values().map(ReadinessEvidence::public_record).collect::<Vec<_>>(),
            "signoffs": self.signoffs.values().map(ReleaseSignoff::public_record).collect::<Vec<_>>(),
            "incident_drills": self.incident_drills.values().map(IncidentDrill::public_record).collect::<Vec<_>>(),
            "reports": self.reports.values().map(ReadinessReport::public_record).collect::<Vec<_>>(),
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
            "state_root": roots.state_root,
        })
    }

    pub fn validate(&self) -> ProductionReadinessResult<String> {
        self.config.validate()?;
        if self.gates.len() > PRODUCTION_READINESS_MAX_GATES {
            return Err("production readiness gate count exceeds limit".to_string());
        }
        if self.evidence.len() > PRODUCTION_READINESS_MAX_EVIDENCE {
            return Err("production readiness evidence count exceeds limit".to_string());
        }
        if self.signoffs.len() > PRODUCTION_READINESS_MAX_SIGNOFFS {
            return Err("production readiness signoff count exceeds limit".to_string());
        }
        if self.incident_drills.len() > PRODUCTION_READINESS_MAX_INCIDENT_DRILLS {
            return Err("production readiness drill count exceeds limit".to_string());
        }
        if self.reports.len() > PRODUCTION_READINESS_MAX_REPORTS {
            return Err("production readiness report count exceeds limit".to_string());
        }
        for gate in self.gates.values() {
            gate.validate()?;
        }
        for evidence in self.evidence.values() {
            evidence.validate()?;
            if !self.gates.contains_key(&evidence.gate_id) {
                return Err("production readiness evidence references missing gate".to_string());
            }
        }
        for signoff in self.signoffs.values() {
            signoff.validate()?;
        }
        for drill in self.incident_drills.values() {
            drill.validate()?;
        }
        for report in self.reports.values() {
            report.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn production_readiness_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRODUCTION-READINESS-STATE-ROOT",
        &[
            HashPart::Str(PRODUCTION_READINESS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn production_readiness_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRODUCTION_READINESS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn production_readiness_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRODUCTION_READINESS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn production_readiness_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| Value::String(production_readiness_string_root(domain, value)))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn production_readiness_config_id(record: &Value) -> String {
    production_readiness_payload_root("PRODUCTION-READINESS-CONFIG-ID", record)
}

#[allow(clippy::too_many_arguments)]
pub fn production_readiness_gate_id(
    domain: ReadinessDomain,
    gate_kind: ReadinessGateKind,
    severity: ReadinessSeverity,
    label: &str,
    requirement_root: &str,
    owner_commitment: &str,
    component_root: &str,
    status: ReadinessStatus,
    opened_at_height: u64,
    due_height: u64,
    evidence_kind_root: &str,
) -> String {
    domain_hash(
        "PRODUCTION-READINESS-GATE-ID",
        &[
            HashPart::Str(PRODUCTION_READINESS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain.as_str()),
            HashPart::Str(gate_kind.as_str()),
            HashPart::Str(severity.as_str()),
            HashPart::Str(label),
            HashPart::Str(requirement_root),
            HashPart::Str(owner_commitment),
            HashPart::Str(component_root),
            HashPart::Str(status.as_str()),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(due_height as i128),
            HashPart::Str(evidence_kind_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn production_readiness_evidence_id(
    gate_id: &str,
    evidence_kind: EvidenceKind,
    submitted_at_height: u64,
    expires_at_height: u64,
    submitter_commitment: &str,
    artifact_root: &str,
    command_root: &str,
    result_root: &str,
    accepted: bool,
) -> String {
    domain_hash(
        "PRODUCTION-READINESS-EVIDENCE-ID",
        &[
            HashPart::Str(PRODUCTION_READINESS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(gate_id),
            HashPart::Str(evidence_kind.as_str()),
            HashPart::Int(submitted_at_height as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Str(submitter_commitment),
            HashPart::Str(artifact_root),
            HashPart::Str(command_root),
            HashPart::Str(result_root),
            HashPart::Str(if accepted { "accepted" } else { "not_accepted" }),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn production_readiness_signoff_id(
    role: SignoffRole,
    signer_commitment: &str,
    gate_root: &str,
    evidence_root: &str,
    signed_at_height: u64,
    expires_at_height: u64,
    pq_signature_root: &str,
    accepted: bool,
) -> String {
    domain_hash(
        "PRODUCTION-READINESS-SIGNOFF-ID",
        &[
            HashPart::Str(PRODUCTION_READINESS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(role.as_str()),
            HashPart::Str(signer_commitment),
            HashPart::Str(gate_root),
            HashPart::Str(evidence_root),
            HashPart::Int(signed_at_height as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Str(pq_signature_root),
            HashPart::Str(if accepted { "accepted" } else { "not_accepted" }),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn production_readiness_drill_id(
    domain: ReadinessDomain,
    label: &str,
    scenario_root: &str,
    participant_root: &str,
    started_at_height: u64,
    completed_at_height: u64,
    outcome_root: &str,
    passed: bool,
) -> String {
    domain_hash(
        "PRODUCTION-READINESS-DRILL-ID",
        &[
            HashPart::Str(PRODUCTION_READINESS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain.as_str()),
            HashPart::Str(label),
            HashPart::Str(scenario_root),
            HashPart::Str(participant_root),
            HashPart::Int(started_at_height as i128),
            HashPart::Int(completed_at_height as i128),
            HashPart::Str(outcome_root),
            HashPart::Str(if passed { "passed" } else { "failed" }),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn production_readiness_report_id(
    height: u64,
    gate_root: &str,
    evidence_root: &str,
    signoff_root: &str,
    drill_root: &str,
    release_score_bps: u64,
    critical_score_bps: u64,
    open_blockers: u64,
    release_candidate: bool,
) -> String {
    domain_hash(
        "PRODUCTION-READINESS-REPORT-ID",
        &[
            HashPart::Str(PRODUCTION_READINESS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Str(gate_root),
            HashPart::Str(evidence_root),
            HashPart::Str(signoff_root),
            HashPart::Str(drill_root),
            HashPart::Int(release_score_bps as i128),
            HashPart::Int(critical_score_bps as i128),
            HashPart::Int(open_blockers as i128),
            HashPart::Str(if release_candidate {
                "release_candidate"
            } else {
                "not_release_candidate"
            }),
        ],
        32,
    )
}

pub fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        PRODUCTION_READINESS_MAX_BPS
    } else {
        numerator.saturating_mul(PRODUCTION_READINESS_MAX_BPS) / denominator
    }
}

fn ensure_non_empty(value: &str, label: &str) -> ProductionReadinessResult<()> {
    if value.is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> ProductionReadinessResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn validate_bps(value: u64, label: &str) -> ProductionReadinessResult<()> {
    if value > PRODUCTION_READINESS_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}
