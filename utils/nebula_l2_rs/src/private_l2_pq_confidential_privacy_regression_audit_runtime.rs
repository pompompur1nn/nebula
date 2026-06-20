use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialPrivacyRegressionAuditRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-privacy-regression-audit-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_AUDIT_PROGRAM_ID: &str =
    "private-l2-pq-confidential-privacy-regression-audit-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUDIT_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-privacy-regression-audit-v1";
pub const VIEW_KEY_DISCLOSURE_SUITE: &str = "monero-view-key-selective-disclosure-budget-v1";
pub const ENCRYPTED_VIEW_TAG_SUITE: &str = "ml-kem-sealed-view-tag-regression-root-v1";
pub const OPERATOR_REDACTION_SUITE: &str = "operator-panel-redaction-proof-v1";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_ANONYMITY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_CRITICAL_ANONYMITY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_DISCLOSURE_BUDGET_UNITS: u64 = 1_000;
pub const DEFAULT_TIMING_BUCKET_WIDTH_MS: u64 = 5_000;
pub const DEFAULT_MAX_TIMING_CORRELATION_BPS: u64 = 250;
pub const DEFAULT_MAX_FEE_LINKABILITY_BPS: u64 = 100;
pub const DEFAULT_MAX_SUBADDRESS_REUSE: u64 = 1;
pub const DEFAULT_MAX_EVENT_PLAINTEXT_FIELDS: u64 = 0;
pub const DEFAULT_MAX_OPERATOR_VISIBLE_FIELDS: u64 = 3;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_RETENTION_EPOCHS: u64 = 96;
pub const MAX_AUDIT_REQUESTS: usize = 1_048_576;
pub const MAX_FINDINGS: usize = 2_097_152;
pub const MAX_MITIGATIONS: usize = 1_048_576;
pub const MAX_DISCLOSURE_BUDGETS: usize = 524_288;
pub const MAX_POLICY_RECORDS: usize = 524_288;
pub const MAX_PUBLIC_RECORDS: usize = 4_194_304;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDomain {
    AnonymitySetFloor,
    ViewKeySelectiveDisclosure,
    EncryptedViewTags,
    NullifierReuse,
    TimingCorrelation,
    FeeMetadataLeakage,
    BridgeSubaddressLinkage,
    ContractEventLeakage,
    WalletApiDisclosurePolicy,
    OperatorPanelRedaction,
}

impl AuditDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AnonymitySetFloor => "anonymity_set_floor",
            Self::ViewKeySelectiveDisclosure => "view_key_selective_disclosure",
            Self::EncryptedViewTags => "encrypted_view_tags",
            Self::NullifierReuse => "nullifier_reuse",
            Self::TimingCorrelation => "timing_correlation",
            Self::FeeMetadataLeakage => "fee_metadata_leakage",
            Self::BridgeSubaddressLinkage => "bridge_subaddress_linkage",
            Self::ContractEventLeakage => "contract_event_leakage",
            Self::WalletApiDisclosurePolicy => "wallet_api_disclosure_policy",
            Self::OperatorPanelRedaction => "operator_panel_redaction",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl AuditSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn risk_points(self) -> u64 {
        match self {
            Self::Info => 1,
            Self::Low => 5,
            Self::Medium => 20,
            Self::High => 80,
            Self::Critical => 320,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    Drafted,
    Accepted,
    Running,
    Passed,
    Failed,
    MitigationQueued,
    Mitigated,
    Rejected,
}

impl AuditStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drafted => "drafted",
            Self::Accepted => "accepted",
            Self::Running => "running",
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::MitigationQueued => "mitigation_queued",
            Self::Mitigated => "mitigated",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Open,
    Acknowledged,
    Waived,
    MitigationQueued,
    Mitigated,
    VerifiedClosed,
}

impl FindingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Acknowledged => "acknowledged",
            Self::Waived => "waived",
            Self::MitigationQueued => "mitigation_queued",
            Self::Mitigated => "mitigated",
            Self::VerifiedClosed => "verified_closed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MitigationStatus {
    Queued,
    Planned,
    InProgress,
    ReadyForVerification,
    Verified,
    Rejected,
}

impl MitigationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Planned => "planned",
            Self::InProgress => "in_progress",
            Self::ReadyForVerification => "ready_for_verification",
            Self::Verified => "verified",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureClass {
    None,
    ViewTag,
    ViewKeyWindow,
    FeeBucket,
    TimingBucket,
    ContractEventTopic,
    OperatorPanelField,
    ApiResponseField,
    BridgeSubaddressHint,
}

impl DisclosureClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ViewTag => "view_tag",
            Self::ViewKeyWindow => "view_key_window",
            Self::FeeBucket => "fee_bucket",
            Self::TimingBucket => "timing_bucket",
            Self::ContractEventTopic => "contract_event_topic",
            Self::OperatorPanelField => "operator_panel_field",
            Self::ApiResponseField => "api_response_field",
            Self::BridgeSubaddressHint => "bridge_subaddress_hint",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSensitivity {
    Public,
    Redacted,
    AuditorOnly,
    Encrypted,
    CommitmentOnly,
}

impl EvidenceSensitivity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Redacted => "redacted",
            Self::AuditorOnly => "auditor_only",
            Self::Encrypted => "encrypted",
            Self::CommitmentOnly => "commitment_only",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyLane {
    Deposit,
    Withdrawal,
    PrivateTransfer,
    ContractCall,
    ContractEvent,
    WalletApi,
    OperatorPanel,
    Bridge,
}

impl PrivacyLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deposit => "deposit",
            Self::Withdrawal => "withdrawal",
            Self::PrivateTransfer => "private_transfer",
            Self::ContractCall => "contract_call",
            Self::ContractEvent => "contract_event",
            Self::WalletApi => "wallet_api",
            Self::OperatorPanel => "operator_panel",
            Self::Bridge => "bridge",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub audit_program_id: String,
    pub hash_suite: String,
    pub pq_audit_suite: String,
    pub view_key_disclosure_suite: String,
    pub encrypted_view_tag_suite: String,
    pub operator_redaction_suite: String,
    pub min_anonymity_set_size: u64,
    pub critical_anonymity_set_size: u64,
    pub disclosure_budget_units: u64,
    pub timing_bucket_width_ms: u64,
    pub max_timing_correlation_bps: u64,
    pub max_fee_linkability_bps: u64,
    pub max_subaddress_reuse: u64,
    pub max_event_plaintext_fields: u64,
    pub max_operator_visible_fields: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub retention_epochs: u64,
    pub require_budget_for_view_key_disclosure: bool,
    pub require_encrypted_view_tags: bool,
    pub require_nullifier_uniqueness: bool,
    pub require_operator_redaction: bool,
    pub require_wallet_api_policy: bool,
    pub fail_on_critical: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEFAULT_L2_NETWORK.to_string(),
            monero_network: DEFAULT_MONERO_NETWORK.to_string(),
            audit_program_id: DEFAULT_AUDIT_PROGRAM_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_audit_suite: PQ_AUDIT_SUITE.to_string(),
            view_key_disclosure_suite: VIEW_KEY_DISCLOSURE_SUITE.to_string(),
            encrypted_view_tag_suite: ENCRYPTED_VIEW_TAG_SUITE.to_string(),
            operator_redaction_suite: OPERATOR_REDACTION_SUITE.to_string(),
            min_anonymity_set_size: DEFAULT_MIN_ANONYMITY_SET_SIZE,
            critical_anonymity_set_size: DEFAULT_CRITICAL_ANONYMITY_SET_SIZE,
            disclosure_budget_units: DEFAULT_DISCLOSURE_BUDGET_UNITS,
            timing_bucket_width_ms: DEFAULT_TIMING_BUCKET_WIDTH_MS,
            max_timing_correlation_bps: DEFAULT_MAX_TIMING_CORRELATION_BPS,
            max_fee_linkability_bps: DEFAULT_MAX_FEE_LINKABILITY_BPS,
            max_subaddress_reuse: DEFAULT_MAX_SUBADDRESS_REUSE,
            max_event_plaintext_fields: DEFAULT_MAX_EVENT_PLAINTEXT_FIELDS,
            max_operator_visible_fields: DEFAULT_MAX_OPERATOR_VISIBLE_FIELDS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            retention_epochs: DEFAULT_RETENTION_EPOCHS,
            require_budget_for_view_key_disclosure: true,
            require_encrypted_view_tags: true,
            require_nullifier_uniqueness: true,
            require_operator_redaction: true,
            require_wallet_api_policy: true,
            fail_on_critical: true,
        }
    }

    pub fn demo() -> Self {
        let mut config = Self::devnet();
        config.audit_program_id = "private-l2-pq-confidential-privacy-regression-audit-demo".into();
        config.min_anonymity_set_size = 8_192;
        config.critical_anonymity_set_size = 2_048;
        config.disclosure_budget_units = 256;
        config
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("chain_id", &self.chain_id)?;
        ensure_nonempty("protocol_version", &self.protocol_version)?;
        ensure_nonempty("l2_network", &self.l2_network)?;
        ensure_nonempty("monero_network", &self.monero_network)?;
        ensure_nonempty("audit_program_id", &self.audit_program_id)?;
        ensure_nonempty("hash_suite", &self.hash_suite)?;
        ensure_nonempty("pq_audit_suite", &self.pq_audit_suite)?;
        if self.schema_version == 0 {
            return Err("schema_version must be nonzero".to_string());
        }
        if self.critical_anonymity_set_size == 0 {
            return Err("critical_anonymity_set_size must be nonzero".to_string());
        }
        if self.critical_anonymity_set_size > self.min_anonymity_set_size {
            return Err(
                "critical_anonymity_set_size cannot exceed min_anonymity_set_size".to_string(),
            );
        }
        if self.disclosure_budget_units == 0 {
            return Err("disclosure_budget_units must be nonzero".to_string());
        }
        if self.timing_bucket_width_ms == 0 {
            return Err("timing_bucket_width_ms must be nonzero".to_string());
        }
        if self.max_timing_correlation_bps > MAX_BPS {
            return Err("max_timing_correlation_bps exceeds MAX_BPS".to_string());
        }
        if self.max_fee_linkability_bps > MAX_BPS {
            return Err("max_fee_linkability_bps exceeds MAX_BPS".to_string());
        }
        if self.min_pq_security_bits > self.target_pq_security_bits {
            return Err("min_pq_security_bits cannot exceed target_pq_security_bits".to_string());
        }
        if self.retention_epochs == 0 {
            return Err("retention_epochs must be nonzero".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub audit_requests: usize,
    pub findings: usize,
    pub open_findings: usize,
    pub critical_findings: usize,
    pub mitigations: usize,
    pub disclosure_budgets: usize,
    pub exhausted_disclosure_budgets: usize,
    pub policy_records: usize,
    pub public_records: usize,
    pub nullifier_observations: usize,
    pub reused_nullifiers: usize,
    pub subaddress_observations: usize,
    pub reused_subaddresses: usize,
    pub redaction_failures: usize,
    pub total_risk_points: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub audit_request_root: String,
    pub finding_root: String,
    pub mitigation_root: String,
    pub disclosure_budget_root: String,
    pub policy_record_root: String,
    pub public_record_root: String,
    pub nullifier_observation_root: String,
    pub subaddress_observation_root: String,
    pub operator_redaction_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditRequest {
    pub request_id: String,
    pub epoch: u64,
    pub lane: PrivacyLane,
    pub domain: AuditDomain,
    pub requester_commitment: String,
    pub subject_commitment: String,
    pub policy_id: String,
    pub evidence_root: String,
    pub minimum_sample_size: u64,
    pub observed_sample_size: u64,
    pub requested_disclosure_units: u64,
    pub status: AuditStatus,
    pub labels: BTreeSet<String>,
    pub metadata: Value,
}

impl AuditRequest {
    pub fn new(
        epoch: u64,
        lane: PrivacyLane,
        domain: AuditDomain,
        requester_commitment: &str,
        subject_commitment: &str,
        policy_id: &str,
        evidence_root: &str,
    ) -> Self {
        let request_id = audit_id(
            "audit-request",
            &[
                HashPart::U64(epoch),
                HashPart::Str(lane.as_str()),
                HashPart::Str(domain.as_str()),
                HashPart::Str(requester_commitment),
                HashPart::Str(subject_commitment),
                HashPart::Str(policy_id),
                HashPart::Str(evidence_root),
            ],
        );
        Self {
            request_id,
            epoch,
            lane,
            domain,
            requester_commitment: requester_commitment.to_string(),
            subject_commitment: subject_commitment.to_string(),
            policy_id: policy_id.to_string(),
            evidence_root: evidence_root.to_string(),
            minimum_sample_size: 1,
            observed_sample_size: 0,
            requested_disclosure_units: 0,
            status: AuditStatus::Drafted,
            labels: BTreeSet::new(),
            metadata: json!({}),
        }
    }

    pub fn with_samples(mut self, minimum_sample_size: u64, observed_sample_size: u64) -> Self {
        self.minimum_sample_size = minimum_sample_size;
        self.observed_sample_size = observed_sample_size;
        self
    }

    pub fn with_disclosure_units(mut self, units: u64) -> Self {
        self.requested_disclosure_units = units;
        self
    }

    pub fn with_label(mut self, label: &str) -> Self {
        if !label.is_empty() {
            self.labels.insert(label.to_string());
        }
        self
    }

    pub fn with_metadata(mut self, metadata: Value) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn public_record(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "epoch": self.epoch,
            "lane": self.lane.as_str(),
            "domain": self.domain.as_str(),
            "requester_commitment": self.requester_commitment,
            "subject_commitment": self.subject_commitment,
            "policy_id": self.policy_id,
            "evidence_root": self.evidence_root,
            "minimum_sample_size": self.minimum_sample_size,
            "observed_sample_size": self.observed_sample_size,
            "requested_disclosure_units": self.requested_disclosure_units,
            "status": self.status.as_str(),
            "labels": self.labels,
            "metadata": self.metadata,
        })
    }

    pub fn root(&self) -> String {
        audit_root("AUDIT-REQUEST", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("request_id", &self.request_id)?;
        ensure_nonempty("requester_commitment", &self.requester_commitment)?;
        ensure_nonempty("subject_commitment", &self.subject_commitment)?;
        ensure_nonempty("policy_id", &self.policy_id)?;
        ensure_nonempty("evidence_root", &self.evidence_root)?;
        if self.minimum_sample_size == 0 {
            return Err("minimum_sample_size must be nonzero".to_string());
        }
        if self.observed_sample_size < self.minimum_sample_size
            && matches!(self.status, AuditStatus::Running | AuditStatus::Passed)
        {
            return Err(
                "running or passed request has insufficient observed_sample_size".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AnonymitySetAuditRequest {
    pub base: AuditRequest,
    pub anonymity_set_id: String,
    pub floor: u64,
    pub observed_members: u64,
    pub decoy_distribution_root: String,
    pub churn_window_epochs: u64,
}

impl AnonymitySetAuditRequest {
    pub fn devnet(epoch: u64, observed_members: u64) -> Self {
        let anonymity_set_id = commitment("devnet-anonymity-set", "private-transfer", epoch);
        let evidence_root = commitment("devnet-decoy-distribution", &anonymity_set_id, epoch);
        Self {
            base: AuditRequest::new(
                epoch,
                PrivacyLane::PrivateTransfer,
                AuditDomain::AnonymitySetFloor,
                "devnet-privacy-auditor",
                &anonymity_set_id,
                "policy-anonymity-floor-devnet",
                &evidence_root,
            )
            .with_samples(256, 256)
            .with_label("anonymity_floor"),
            anonymity_set_id,
            floor: DEFAULT_MIN_ANONYMITY_SET_SIZE,
            observed_members,
            decoy_distribution_root: evidence_root,
            churn_window_epochs: 16,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "base": self.base.public_record(),
            "anonymity_set_id": self.anonymity_set_id,
            "floor": self.floor,
            "observed_members": self.observed_members,
            "decoy_distribution_root": self.decoy_distribution_root,
            "churn_window_epochs": self.churn_window_epochs,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewKeyDisclosureAuditRequest {
    pub base: AuditRequest,
    pub disclosure_grant_id: String,
    pub view_key_policy_root: String,
    pub disclosed_fields: BTreeSet<String>,
    pub budget_id: String,
    pub budget_units: u64,
}

impl ViewKeyDisclosureAuditRequest {
    pub fn devnet(epoch: u64, units: u64) -> Self {
        let disclosure_grant_id = commitment("devnet-viewkey-grant", "auditor-window", epoch);
        let budget_id = commitment("devnet-disclosure-budget", "wallet-api", epoch);
        let policy_root = commitment("devnet-viewkey-policy-root", &disclosure_grant_id, epoch);
        let mut disclosed_fields = BTreeSet::new();
        disclosed_fields.insert("incoming_output_commitment".to_string());
        disclosed_fields.insert("amount_bucket_commitment".to_string());
        Self {
            base: AuditRequest::new(
                epoch,
                PrivacyLane::WalletApi,
                AuditDomain::ViewKeySelectiveDisclosure,
                "devnet-wallet-api-auditor",
                &disclosure_grant_id,
                "policy-viewkey-selective-disclosure-devnet",
                &policy_root,
            )
            .with_disclosure_units(units)
            .with_label("view_key"),
            disclosure_grant_id,
            view_key_policy_root: policy_root,
            disclosed_fields,
            budget_id,
            budget_units: units,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "base": self.base.public_record(),
            "disclosure_grant_id": self.disclosure_grant_id,
            "view_key_policy_root": self.view_key_policy_root,
            "disclosed_fields": self.disclosed_fields,
            "budget_id": self.budget_id,
            "budget_units": self.budget_units,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewTagEncryptionAuditRequest {
    pub base: AuditRequest,
    pub view_tag_batch_id: String,
    pub encrypted_tag_root: String,
    pub plaintext_tag_count: u64,
    pub sealed_recipient_count: u64,
    pub pq_security_bits: u16,
}

impl ViewTagEncryptionAuditRequest {
    pub fn devnet(epoch: u64, plaintext_tag_count: u64) -> Self {
        let batch_id = commitment("devnet-viewtag-batch", "fast-scan-cache", epoch);
        let encrypted_tag_root = commitment("devnet-encrypted-viewtag-root", &batch_id, epoch);
        Self {
            base: AuditRequest::new(
                epoch,
                PrivacyLane::PrivateTransfer,
                AuditDomain::EncryptedViewTags,
                "devnet-viewtag-auditor",
                &batch_id,
                "policy-encrypted-view-tags-devnet",
                &encrypted_tag_root,
            )
            .with_samples(128, 128)
            .with_label("view_tags"),
            view_tag_batch_id: batch_id,
            encrypted_tag_root,
            plaintext_tag_count,
            sealed_recipient_count: 3,
            pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "base": self.base.public_record(),
            "view_tag_batch_id": self.view_tag_batch_id,
            "encrypted_tag_root": self.encrypted_tag_root,
            "plaintext_tag_count": self.plaintext_tag_count,
            "sealed_recipient_count": self.sealed_recipient_count,
            "pq_security_bits": self.pq_security_bits,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierObservation {
    pub observation_id: String,
    pub epoch: u64,
    pub lane: PrivacyLane,
    pub nullifier_commitment: String,
    pub source_request_id: String,
    pub note_commitment_root: String,
    pub first_seen_epoch: u64,
    pub reuse_count: u64,
}

impl NullifierObservation {
    pub fn new(
        epoch: u64,
        lane: PrivacyLane,
        nullifier_commitment: &str,
        source_request_id: &str,
        note_commitment_root: &str,
        first_seen_epoch: u64,
        reuse_count: u64,
    ) -> Self {
        let observation_id = audit_id(
            "nullifier-observation",
            &[
                HashPart::U64(epoch),
                HashPart::Str(lane.as_str()),
                HashPart::Str(nullifier_commitment),
                HashPart::Str(source_request_id),
            ],
        );
        Self {
            observation_id,
            epoch,
            lane,
            nullifier_commitment: nullifier_commitment.to_string(),
            source_request_id: source_request_id.to_string(),
            note_commitment_root: note_commitment_root.to_string(),
            first_seen_epoch,
            reuse_count,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "epoch": self.epoch,
            "lane": self.lane.as_str(),
            "nullifier_commitment": self.nullifier_commitment,
            "source_request_id": self.source_request_id,
            "note_commitment_root": self.note_commitment_root,
            "first_seen_epoch": self.first_seen_epoch,
            "reuse_count": self.reuse_count,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TimingCorrelationAuditRequest {
    pub base: AuditRequest,
    pub timing_window_id: String,
    pub bucket_width_ms: u64,
    pub inbound_bucket_root: String,
    pub outbound_bucket_root: String,
    pub correlation_bps: u64,
}

impl TimingCorrelationAuditRequest {
    pub fn devnet(epoch: u64, correlation_bps: u64) -> Self {
        let timing_window_id = commitment("devnet-timing-window", "bridge-fast-lane", epoch);
        let inbound = commitment("devnet-inbound-timing-buckets", &timing_window_id, epoch);
        let outbound = commitment("devnet-outbound-timing-buckets", &timing_window_id, epoch);
        Self {
            base: AuditRequest::new(
                epoch,
                PrivacyLane::Bridge,
                AuditDomain::TimingCorrelation,
                "devnet-timing-auditor",
                &timing_window_id,
                "policy-timing-correlation-devnet",
                &inbound,
            )
            .with_samples(512, 512)
            .with_label("timing"),
            timing_window_id,
            bucket_width_ms: DEFAULT_TIMING_BUCKET_WIDTH_MS,
            inbound_bucket_root: inbound,
            outbound_bucket_root: outbound,
            correlation_bps,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "base": self.base.public_record(),
            "timing_window_id": self.timing_window_id,
            "bucket_width_ms": self.bucket_width_ms,
            "inbound_bucket_root": self.inbound_bucket_root,
            "outbound_bucket_root": self.outbound_bucket_root,
            "correlation_bps": self.correlation_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeMetadataLeakageAuditRequest {
    pub base: AuditRequest,
    pub fee_window_id: String,
    pub fee_asset_id: String,
    pub fee_bucket_root: String,
    pub unique_fee_values: u64,
    pub linkability_bps: u64,
}

impl FeeMetadataLeakageAuditRequest {
    pub fn devnet(epoch: u64, linkability_bps: u64) -> Self {
        let fee_window_id = commitment("devnet-fee-window", "low-fee-private-lane", epoch);
        let fee_bucket_root = commitment("devnet-fee-buckets", &fee_window_id, epoch);
        Self {
            base: AuditRequest::new(
                epoch,
                PrivacyLane::PrivateTransfer,
                AuditDomain::FeeMetadataLeakage,
                "devnet-fee-auditor",
                &fee_window_id,
                "policy-fee-metadata-devnet",
                &fee_bucket_root,
            )
            .with_samples(1024, 1024)
            .with_label("fees"),
            fee_window_id,
            fee_asset_id: "piconero-devnet".to_string(),
            fee_bucket_root,
            unique_fee_values: 8,
            linkability_bps,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "base": self.base.public_record(),
            "fee_window_id": self.fee_window_id,
            "fee_asset_id": self.fee_asset_id,
            "fee_bucket_root": self.fee_bucket_root,
            "unique_fee_values": self.unique_fee_values,
            "linkability_bps": self.linkability_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BridgeSubaddressObservation {
    pub observation_id: String,
    pub epoch: u64,
    pub bridge_batch_id: String,
    pub subaddress_commitment: String,
    pub route_commitment: String,
    pub reuse_count: u64,
    pub linked_withdrawal_count: u64,
}

impl BridgeSubaddressObservation {
    pub fn new(
        epoch: u64,
        bridge_batch_id: &str,
        subaddress_commitment: &str,
        route_commitment: &str,
        reuse_count: u64,
        linked_withdrawal_count: u64,
    ) -> Self {
        let observation_id = audit_id(
            "bridge-subaddress-observation",
            &[
                HashPart::U64(epoch),
                HashPart::Str(bridge_batch_id),
                HashPart::Str(subaddress_commitment),
                HashPart::Str(route_commitment),
            ],
        );
        Self {
            observation_id,
            epoch,
            bridge_batch_id: bridge_batch_id.to_string(),
            subaddress_commitment: subaddress_commitment.to_string(),
            route_commitment: route_commitment.to_string(),
            reuse_count,
            linked_withdrawal_count,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "epoch": self.epoch,
            "bridge_batch_id": self.bridge_batch_id,
            "subaddress_commitment": self.subaddress_commitment,
            "route_commitment": self.route_commitment,
            "reuse_count": self.reuse_count,
            "linked_withdrawal_count": self.linked_withdrawal_count,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractEventLeakageAuditRequest {
    pub base: AuditRequest,
    pub contract_commitment: String,
    pub event_schema_root: String,
    pub encrypted_event_root: String,
    pub plaintext_field_count: u64,
    pub public_topic_count: u64,
}

impl ContractEventLeakageAuditRequest {
    pub fn devnet(epoch: u64, plaintext_field_count: u64) -> Self {
        let contract_commitment = commitment("devnet-confidential-contract", "event-filter", epoch);
        let schema_root = commitment("devnet-event-schema", &contract_commitment, epoch);
        let encrypted_event_root =
            commitment("devnet-encrypted-event-root", &contract_commitment, epoch);
        Self {
            base: AuditRequest::new(
                epoch,
                PrivacyLane::ContractEvent,
                AuditDomain::ContractEventLeakage,
                "devnet-contract-event-auditor",
                &contract_commitment,
                "policy-contract-event-redaction-devnet",
                &encrypted_event_root,
            )
            .with_samples(64, 64)
            .with_label("contract_events"),
            contract_commitment,
            event_schema_root: schema_root,
            encrypted_event_root,
            plaintext_field_count,
            public_topic_count: 1,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "base": self.base.public_record(),
            "contract_commitment": self.contract_commitment,
            "event_schema_root": self.event_schema_root,
            "encrypted_event_root": self.encrypted_event_root,
            "plaintext_field_count": self.plaintext_field_count,
            "public_topic_count": self.public_topic_count,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletApiDisclosurePolicyRecord {
    pub policy_id: String,
    pub epoch: u64,
    pub api_surface: String,
    pub allowed_disclosure_classes: BTreeSet<DisclosureClass>,
    pub denied_fields: BTreeSet<String>,
    pub response_redaction_root: String,
    pub max_response_fields: u64,
    pub requires_user_consent: bool,
    pub requires_auditor_grant: bool,
}

impl WalletApiDisclosurePolicyRecord {
    pub fn devnet(epoch: u64) -> Self {
        let policy_id = commitment("devnet-wallet-api-policy", "disclosure", epoch);
        let mut allowed = BTreeSet::new();
        allowed.insert(DisclosureClass::FeeBucket);
        allowed.insert(DisclosureClass::TimingBucket);
        let mut denied = BTreeSet::new();
        denied.insert("raw_subaddress".to_string());
        denied.insert("raw_view_key".to_string());
        denied.insert("exact_amount".to_string());
        Self {
            policy_id,
            epoch,
            api_surface: "wallet-developer-api".to_string(),
            allowed_disclosure_classes: allowed,
            denied_fields: denied,
            response_redaction_root: commitment("devnet-wallet-api-redaction", "policy", epoch),
            max_response_fields: 16,
            requires_user_consent: true,
            requires_auditor_grant: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "epoch": self.epoch,
            "api_surface": self.api_surface,
            "allowed_disclosure_classes": self.allowed_disclosure_classes,
            "denied_fields": self.denied_fields,
            "response_redaction_root": self.response_redaction_root,
            "max_response_fields": self.max_response_fields,
            "requires_user_consent": self.requires_user_consent,
            "requires_auditor_grant": self.requires_auditor_grant,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorPanelRedactionRecord {
    pub redaction_id: String,
    pub epoch: u64,
    pub panel_id: String,
    pub operator_commitment: String,
    pub visible_fields: BTreeSet<String>,
    pub redacted_fields: BTreeSet<String>,
    pub redaction_proof_root: String,
    pub leakage_score_bps: u64,
}

impl OperatorPanelRedactionRecord {
    pub fn devnet(epoch: u64, visible_field_count: u64) -> Self {
        let panel_id = commitment("devnet-operator-panel", "privacy-dashboard", epoch);
        let mut visible = BTreeSet::new();
        for index in 0..visible_field_count {
            visible.insert(format!("bucketed_metric_{index}"));
        }
        let mut redacted = BTreeSet::new();
        redacted.insert("raw_wallet_id".to_string());
        redacted.insert("raw_subaddress".to_string());
        redacted.insert("exact_fee".to_string());
        let redaction_id = audit_id(
            "operator-panel-redaction",
            &[HashPart::U64(epoch), HashPart::Str(&panel_id)],
        );
        Self {
            redaction_id,
            epoch,
            panel_id,
            operator_commitment: "devnet-operator-commitment".to_string(),
            visible_fields: visible,
            redacted_fields: redacted,
            redaction_proof_root: commitment("devnet-operator-redaction-proof", "panel", epoch),
            leakage_score_bps: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "redaction_id": self.redaction_id,
            "epoch": self.epoch,
            "panel_id": self.panel_id,
            "operator_commitment": self.operator_commitment,
            "visible_fields": self.visible_fields,
            "redacted_fields": self.redacted_fields,
            "redaction_proof_root": self.redaction_proof_root,
            "leakage_score_bps": self.leakage_score_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DisclosureBudgetRecord {
    pub budget_id: String,
    pub owner_commitment: String,
    pub epoch_start: u64,
    pub epoch_end: u64,
    pub total_units: u64,
    pub consumed_units: u64,
    pub reserved_units: u64,
    pub disclosure_classes: BTreeSet<DisclosureClass>,
    pub policy_root: String,
}

impl DisclosureBudgetRecord {
    pub fn new(
        owner_commitment: &str,
        epoch_start: u64,
        epoch_end: u64,
        total_units: u64,
        policy_root: &str,
    ) -> Self {
        let budget_id = audit_id(
            "disclosure-budget",
            &[
                HashPart::Str(owner_commitment),
                HashPart::U64(epoch_start),
                HashPart::U64(epoch_end),
                HashPart::U64(total_units),
                HashPart::Str(policy_root),
            ],
        );
        Self {
            budget_id,
            owner_commitment: owner_commitment.to_string(),
            epoch_start,
            epoch_end,
            total_units,
            consumed_units: 0,
            reserved_units: 0,
            disclosure_classes: BTreeSet::new(),
            policy_root: policy_root.to_string(),
        }
    }

    pub fn available_units(&self) -> u64 {
        self.total_units
            .saturating_sub(self.consumed_units)
            .saturating_sub(self.reserved_units)
    }

    pub fn reserve(&mut self, units: u64) -> Result<()> {
        if self.available_units() < units {
            return Err("insufficient disclosure budget units".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(units);
        Ok(())
    }

    pub fn consume_reserved(&mut self, units: u64) -> Result<()> {
        if self.reserved_units < units {
            return Err("reserved disclosure budget below consume amount".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_sub(units);
        self.consumed_units = self.consumed_units.saturating_add(units);
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "owner_commitment": self.owner_commitment,
            "epoch_start": self.epoch_start,
            "epoch_end": self.epoch_end,
            "total_units": self.total_units,
            "consumed_units": self.consumed_units,
            "reserved_units": self.reserved_units,
            "available_units": self.available_units(),
            "disclosure_classes": self.disclosure_classes,
            "policy_root": self.policy_root,
        })
    }

    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("budget_id", &self.budget_id)?;
        ensure_nonempty("owner_commitment", &self.owner_commitment)?;
        ensure_nonempty("policy_root", &self.policy_root)?;
        if self.epoch_end < self.epoch_start {
            return Err("epoch_end cannot be below epoch_start".to_string());
        }
        if self.consumed_units.saturating_add(self.reserved_units) > self.total_units {
            return Err("disclosure budget overdrawn".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskFinding {
    pub finding_id: String,
    pub request_id: String,
    pub domain: AuditDomain,
    pub severity: AuditSeverity,
    pub status: FindingStatus,
    pub title: String,
    pub evidence_root: String,
    pub evidence_sensitivity: EvidenceSensitivity,
    pub observed_value: u64,
    pub threshold_value: u64,
    pub risk_points: u64,
    pub mitigation_hint: String,
    pub related_commitments: BTreeSet<String>,
    pub metadata: Value,
}

impl RiskFinding {
    pub fn new(
        request_id: &str,
        domain: AuditDomain,
        severity: AuditSeverity,
        title: &str,
        evidence_root: &str,
        observed_value: u64,
        threshold_value: u64,
        mitigation_hint: &str,
    ) -> Self {
        let finding_id = audit_id(
            "risk-finding",
            &[
                HashPart::Str(request_id),
                HashPart::Str(domain.as_str()),
                HashPart::Str(severity.as_str()),
                HashPart::Str(title),
                HashPart::Str(evidence_root),
                HashPart::U64(observed_value),
                HashPart::U64(threshold_value),
            ],
        );
        Self {
            finding_id,
            request_id: request_id.to_string(),
            domain,
            severity,
            status: FindingStatus::Open,
            title: title.to_string(),
            evidence_root: evidence_root.to_string(),
            evidence_sensitivity: EvidenceSensitivity::CommitmentOnly,
            observed_value,
            threshold_value,
            risk_points: severity.risk_points(),
            mitigation_hint: mitigation_hint.to_string(),
            related_commitments: BTreeSet::new(),
            metadata: json!({}),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "finding_id": self.finding_id,
            "request_id": self.request_id,
            "domain": self.domain.as_str(),
            "severity": self.severity.as_str(),
            "status": self.status.as_str(),
            "title": self.title,
            "evidence_root": self.evidence_root,
            "evidence_sensitivity": self.evidence_sensitivity.as_str(),
            "observed_value": self.observed_value,
            "threshold_value": self.threshold_value,
            "risk_points": self.risk_points,
            "mitigation_hint": self.mitigation_hint,
            "related_commitments": self.related_commitments,
            "metadata": self.metadata,
        })
    }

    pub fn root(&self) -> String {
        audit_root("RISK-FINDING", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MitigationQueueRecord {
    pub mitigation_id: String,
    pub finding_id: String,
    pub domain: AuditDomain,
    pub status: MitigationStatus,
    pub owner_commitment: String,
    pub action: String,
    pub priority: u64,
    pub due_epoch: u64,
    pub verification_root: String,
    pub dependencies: BTreeSet<String>,
}

impl MitigationQueueRecord {
    pub fn for_finding(finding: &RiskFinding, owner_commitment: &str, due_epoch: u64) -> Self {
        let mitigation_id = audit_id(
            "mitigation",
            &[
                HashPart::Str(&finding.finding_id),
                HashPart::Str(owner_commitment),
                HashPart::U64(due_epoch),
            ],
        );
        Self {
            mitigation_id,
            finding_id: finding.finding_id.clone(),
            domain: finding.domain,
            status: MitigationStatus::Queued,
            owner_commitment: owner_commitment.to_string(),
            action: finding.mitigation_hint.clone(),
            priority: finding.severity.risk_points(),
            due_epoch,
            verification_root: audit_id(
                "mitigation-verification-root",
                &[HashPart::Str(&finding.finding_id), HashPart::U64(due_epoch)],
            ),
            dependencies: BTreeSet::new(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "mitigation_id": self.mitigation_id,
            "finding_id": self.finding_id,
            "domain": self.domain.as_str(),
            "status": self.status.as_str(),
            "owner_commitment": self.owner_commitment,
            "action": self.action,
            "priority": self.priority,
            "due_epoch": self.due_epoch,
            "verification_root": self.verification_root,
            "dependencies": self.dependencies,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub epoch: u64,
    pub audit_requests: BTreeMap<String, AuditRequest>,
    pub findings: BTreeMap<String, RiskFinding>,
    pub mitigations: BTreeMap<String, MitigationQueueRecord>,
    pub disclosure_budgets: BTreeMap<String, DisclosureBudgetRecord>,
    pub wallet_api_policies: BTreeMap<String, WalletApiDisclosurePolicyRecord>,
    pub nullifier_observations: BTreeMap<String, NullifierObservation>,
    pub subaddress_observations: BTreeMap<String, BridgeSubaddressObservation>,
    pub operator_redactions: BTreeMap<String, OperatorPanelRedactionRecord>,
    pub public_records: BTreeMap<String, Value>,
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            epoch: 0,
            audit_requests: BTreeMap::new(),
            findings: BTreeMap::new(),
            mitigations: BTreeMap::new(),
            disclosure_budgets: BTreeMap::new(),
            wallet_api_policies: BTreeMap::new(),
            nullifier_observations: BTreeMap::new(),
            subaddress_observations: BTreeMap::new(),
            operator_redactions: BTreeMap::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> Result<Self> {
        let mut state = Self::new(Config::devnet())?;
        state.seed_devnet()?;
        Ok(state)
    }

    pub fn demo() -> Result<Self> {
        let mut state = Self::new(Config::demo())?;
        state.seed_demo()?;
        Ok(state)
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        ensure_len(
            "audit_requests",
            self.audit_requests.len(),
            MAX_AUDIT_REQUESTS,
        )?;
        ensure_len("findings", self.findings.len(), MAX_FINDINGS)?;
        ensure_len("mitigations", self.mitigations.len(), MAX_MITIGATIONS)?;
        ensure_len(
            "disclosure_budgets",
            self.disclosure_budgets.len(),
            MAX_DISCLOSURE_BUDGETS,
        )?;
        ensure_len(
            "wallet_api_policies",
            self.wallet_api_policies.len(),
            MAX_POLICY_RECORDS,
        )?;
        ensure_len(
            "public_records",
            self.public_records.len(),
            MAX_PUBLIC_RECORDS,
        )?;
        for request in self.audit_requests.values() {
            request.validate()?;
        }
        for budget in self.disclosure_budgets.values() {
            budget.validate()?;
        }
        Ok(())
    }

    pub fn advance_epoch(&mut self, epoch: u64) -> Result<()> {
        if epoch < self.epoch {
            return Err("epoch cannot move backwards".to_string());
        }
        self.epoch = epoch;
        Ok(())
    }

    pub fn submit_request(&mut self, mut request: AuditRequest) -> Result<String> {
        ensure_len(
            "audit_requests",
            self.audit_requests.len() + 1,
            MAX_AUDIT_REQUESTS,
        )?;
        request.validate()?;
        if request.epoch < self.epoch {
            request.status = AuditStatus::Accepted;
        }
        let request_id = request.request_id.clone();
        self.record_public_record("audit_request", &request_id, request.public_record())?;
        self.audit_requests.insert(request_id.clone(), request);
        Ok(request_id)
    }

    pub fn register_wallet_api_policy(
        &mut self,
        policy: WalletApiDisclosurePolicyRecord,
    ) -> Result<String> {
        ensure_len(
            "wallet_api_policies",
            self.wallet_api_policies.len() + 1,
            MAX_POLICY_RECORDS,
        )?;
        ensure_nonempty("policy_id", &policy.policy_id)?;
        let policy_id = policy.policy_id.clone();
        self.record_public_record("wallet_api_policy", &policy_id, policy.public_record())?;
        self.wallet_api_policies.insert(policy_id.clone(), policy);
        Ok(policy_id)
    }

    pub fn register_disclosure_budget(&mut self, budget: DisclosureBudgetRecord) -> Result<String> {
        ensure_len(
            "disclosure_budgets",
            self.disclosure_budgets.len() + 1,
            MAX_DISCLOSURE_BUDGETS,
        )?;
        budget.validate()?;
        let budget_id = budget.budget_id.clone();
        self.record_public_record("disclosure_budget", &budget_id, budget.public_record())?;
        self.disclosure_budgets.insert(budget_id.clone(), budget);
        Ok(budget_id)
    }

    pub fn reserve_disclosure_budget(&mut self, budget_id: &str, units: u64) -> Result<()> {
        let budget = self
            .disclosure_budgets
            .get_mut(budget_id)
            .ok_or_else(|| format!("missing disclosure budget {budget_id}"))?;
        budget.reserve(units)?;
        let record = budget.public_record();
        self.record_public_record("disclosure_budget_reserved", budget_id, record)
    }

    pub fn consume_disclosure_budget(&mut self, budget_id: &str, units: u64) -> Result<()> {
        let budget = self
            .disclosure_budgets
            .get_mut(budget_id)
            .ok_or_else(|| format!("missing disclosure budget {budget_id}"))?;
        budget.consume_reserved(units)?;
        let record = budget.public_record();
        self.record_public_record("disclosure_budget_consumed", budget_id, record)
    }

    pub fn observe_nullifier(&mut self, observation: NullifierObservation) -> Result<String> {
        ensure_len(
            "nullifier_observations",
            self.nullifier_observations.len() + 1,
            MAX_PUBLIC_RECORDS,
        )?;
        ensure_nonempty("nullifier_commitment", &observation.nullifier_commitment)?;
        let observation_id = observation.observation_id.clone();
        if observation.reuse_count > 1 && self.config.require_nullifier_uniqueness {
            let finding = RiskFinding::new(
                &observation.source_request_id,
                AuditDomain::NullifierReuse,
                AuditSeverity::Critical,
                "nullifier commitment reused across private L2 notes",
                &observation.note_commitment_root,
                observation.reuse_count,
                1,
                "quarantine affected notes, reject duplicate nullifier spends, and rotate wallet session keys",
            );
            self.add_finding(finding)?;
        }
        self.record_public_record(
            "nullifier_observation",
            &observation_id,
            observation.public_record(),
        )?;
        self.nullifier_observations
            .insert(observation_id.clone(), observation);
        Ok(observation_id)
    }

    pub fn observe_bridge_subaddress(
        &mut self,
        observation: BridgeSubaddressObservation,
    ) -> Result<String> {
        ensure_len(
            "subaddress_observations",
            self.subaddress_observations.len() + 1,
            MAX_PUBLIC_RECORDS,
        )?;
        let observation_id = observation.observation_id.clone();
        if observation.reuse_count > self.config.max_subaddress_reuse {
            let finding = RiskFinding::new(
                &observation.bridge_batch_id,
                AuditDomain::BridgeSubaddressLinkage,
                AuditSeverity::High,
                "bridge subaddress reuse links private withdrawals",
                &observation.route_commitment,
                observation.reuse_count,
                self.config.max_subaddress_reuse,
                "rotate bridge subaddresses per withdrawal batch and suppress operator-visible route hints",
            );
            self.add_finding(finding)?;
        }
        self.record_public_record(
            "bridge_subaddress_observation",
            &observation_id,
            observation.public_record(),
        )?;
        self.subaddress_observations
            .insert(observation_id.clone(), observation);
        Ok(observation_id)
    }

    pub fn register_operator_redaction(
        &mut self,
        record: OperatorPanelRedactionRecord,
    ) -> Result<String> {
        ensure_len(
            "operator_redactions",
            self.operator_redactions.len() + 1,
            MAX_PUBLIC_RECORDS,
        )?;
        let redaction_id = record.redaction_id.clone();
        if self.config.require_operator_redaction
            && record.visible_fields.len() as u64 > self.config.max_operator_visible_fields
        {
            let finding = RiskFinding::new(
                &redaction_id,
                AuditDomain::OperatorPanelRedaction,
                AuditSeverity::Medium,
                "operator panel exposes too many privacy-sensitive fields",
                &record.redaction_proof_root,
                record.visible_fields.len() as u64,
                self.config.max_operator_visible_fields,
                "collapse operator telemetry to bucketed counters and remove raw wallet, subaddress, fee, and timing fields",
            );
            self.add_finding(finding)?;
        }
        self.record_public_record("operator_redaction", &redaction_id, record.public_record())?;
        self.operator_redactions
            .insert(redaction_id.clone(), record);
        Ok(redaction_id)
    }

    pub fn add_finding(&mut self, finding: RiskFinding) -> Result<String> {
        ensure_len("findings", self.findings.len() + 1, MAX_FINDINGS)?;
        ensure_nonempty("finding_id", &finding.finding_id)?;
        let finding_id = finding.finding_id.clone();
        self.record_public_record("risk_finding", &finding_id, finding.public_record())?;
        self.findings.insert(finding_id.clone(), finding);
        Ok(finding_id)
    }

    pub fn queue_mitigation(
        &mut self,
        finding_id: &str,
        owner_commitment: &str,
        due_epoch: u64,
    ) -> Result<String> {
        ensure_len("mitigations", self.mitigations.len() + 1, MAX_MITIGATIONS)?;
        let finding = self
            .findings
            .get(finding_id)
            .ok_or_else(|| format!("missing finding {finding_id}"))?
            .clone();
        let mitigation = MitigationQueueRecord::for_finding(&finding, owner_commitment, due_epoch);
        let mitigation_id = mitigation.mitigation_id.clone();
        self.record_public_record("mitigation", &mitigation_id, mitigation.public_record())?;
        self.mitigations.insert(mitigation_id.clone(), mitigation);
        if let Some(existing) = self.findings.get_mut(finding_id) {
            existing.status = FindingStatus::MitigationQueued;
        }
        Ok(mitigation_id)
    }

    pub fn audit_anonymity_set(&mut self, request: AnonymitySetAuditRequest) -> Result<String> {
        let request_id = self.submit_request(request.base.clone())?;
        if request.observed_members < self.config.critical_anonymity_set_size {
            self.add_finding(RiskFinding::new(
                &request_id,
                AuditDomain::AnonymitySetFloor,
                AuditSeverity::Critical,
                "anonymity set below critical floor",
                &request.decoy_distribution_root,
                request.observed_members,
                self.config.critical_anonymity_set_size,
                "halt affected lane admission, expand decoy sampling, and delay settlement until the anonymity floor recovers",
            ))?;
        } else if request.observed_members < request.floor {
            self.add_finding(RiskFinding::new(
                &request_id,
                AuditDomain::AnonymitySetFloor,
                AuditSeverity::High,
                "anonymity set below configured floor",
                &request.decoy_distribution_root,
                request.observed_members,
                request.floor,
                "increase decoy batch size and route activity through a larger privacy pool before publishing receipts",
            ))?;
        }
        self.record_public_record("anonymity_set_audit", &request_id, request.public_record())?;
        Ok(request_id)
    }

    pub fn audit_view_key_disclosure(
        &mut self,
        request: ViewKeyDisclosureAuditRequest,
    ) -> Result<String> {
        let request_id = self.submit_request(request.base.clone())?;
        if self.config.require_budget_for_view_key_disclosure {
            match self.disclosure_budgets.get(&request.budget_id) {
                Some(budget) if budget.available_units() >= request.budget_units => {}
                Some(_) => {
                    self.add_finding(RiskFinding::new(
                        &request_id,
                        AuditDomain::ViewKeySelectiveDisclosure,
                        AuditSeverity::High,
                        "view-key disclosure exceeds remaining privacy budget",
                        &request.view_key_policy_root,
                        request.budget_units,
                        0,
                        "deny the grant, require a fresh consent window, and issue a redacted auditor-only receipt",
                    ))?;
                }
                None => {
                    self.add_finding(RiskFinding::new(
                        &request_id,
                        AuditDomain::ViewKeySelectiveDisclosure,
                        AuditSeverity::Medium,
                        "view-key disclosure has no registered privacy budget",
                        &request.view_key_policy_root,
                        request.budget_units,
                        self.config.disclosure_budget_units,
                        "register a disclosure budget before serving wallet/API view-key material",
                    ))?;
                }
            }
        }
        self.record_public_record(
            "view_key_disclosure_audit",
            &request_id,
            request.public_record(),
        )?;
        Ok(request_id)
    }

    pub fn audit_view_tag_encryption(
        &mut self,
        request: ViewTagEncryptionAuditRequest,
    ) -> Result<String> {
        let request_id = self.submit_request(request.base.clone())?;
        if self.config.require_encrypted_view_tags && request.plaintext_tag_count > 0 {
            self.add_finding(RiskFinding::new(
                &request_id,
                AuditDomain::EncryptedViewTags,
                AuditSeverity::Critical,
                "plaintext view tags detected in private scan cache",
                &request.encrypted_tag_root,
                request.plaintext_tag_count,
                0,
                "rebuild the fast scan cache with ML-KEM sealed tags and discard plaintext tag indexes",
            ))?;
        }
        if request.pq_security_bits < self.config.min_pq_security_bits {
            self.add_finding(RiskFinding::new(
                &request_id,
                AuditDomain::EncryptedViewTags,
                AuditSeverity::High,
                "encrypted view tag suite below minimum PQ security bits",
                &request.encrypted_tag_root,
                request.pq_security_bits as u64,
                self.config.min_pq_security_bits as u64,
                "migrate view tag envelopes to the configured PQ audit suite before next release",
            ))?;
        }
        self.record_public_record(
            "view_tag_encryption_audit",
            &request_id,
            request.public_record(),
        )?;
        Ok(request_id)
    }

    pub fn audit_timing_correlation(
        &mut self,
        request: TimingCorrelationAuditRequest,
    ) -> Result<String> {
        let request_id = self.submit_request(request.base.clone())?;
        if request.correlation_bps > self.config.max_timing_correlation_bps {
            self.add_finding(RiskFinding::new(
                &request_id,
                AuditDomain::TimingCorrelation,
                AuditSeverity::High,
                "timing buckets correlate private ingress and egress",
                &request.outbound_bucket_root,
                request.correlation_bps,
                self.config.max_timing_correlation_bps,
                "increase timing bucket width, add relay jitter commitments, and batch bridge releases",
            ))?;
        }
        self.record_public_record(
            "timing_correlation_audit",
            &request_id,
            request.public_record(),
        )?;
        Ok(request_id)
    }

    pub fn audit_fee_metadata(
        &mut self,
        request: FeeMetadataLeakageAuditRequest,
    ) -> Result<String> {
        let request_id = self.submit_request(request.base.clone())?;
        if request.linkability_bps > self.config.max_fee_linkability_bps {
            self.add_finding(RiskFinding::new(
                &request_id,
                AuditDomain::FeeMetadataLeakage,
                AuditSeverity::Medium,
                "fee metadata creates linkable private transaction buckets",
                &request.fee_bucket_root,
                request.linkability_bps,
                self.config.max_fee_linkability_bps,
                "round fees to coarser buckets and sponsor low-fee lanes from pooled credits",
            ))?;
        }
        self.record_public_record("fee_metadata_audit", &request_id, request.public_record())?;
        Ok(request_id)
    }

    pub fn audit_contract_event_leakage(
        &mut self,
        request: ContractEventLeakageAuditRequest,
    ) -> Result<String> {
        let request_id = self.submit_request(request.base.clone())?;
        if request.plaintext_field_count > self.config.max_event_plaintext_fields {
            self.add_finding(RiskFinding::new(
                &request_id,
                AuditDomain::ContractEventLeakage,
                AuditSeverity::High,
                "confidential contract event exposes plaintext fields",
                &request.encrypted_event_root,
                request.plaintext_field_count,
                self.config.max_event_plaintext_fields,
                "move event fields behind encrypted topics and publish only commitment roots",
            ))?;
        }
        self.record_public_record(
            "contract_event_leakage_audit",
            &request_id,
            request.public_record(),
        )?;
        Ok(request_id)
    }

    pub fn counters(&self) -> Counters {
        let open_findings = self
            .findings
            .values()
            .filter(|finding| {
                matches!(
                    finding.status,
                    FindingStatus::Open | FindingStatus::Acknowledged
                )
            })
            .count();
        let critical_findings = self
            .findings
            .values()
            .filter(|finding| finding.severity == AuditSeverity::Critical)
            .count();
        let exhausted_disclosure_budgets = self
            .disclosure_budgets
            .values()
            .filter(|budget| budget.available_units() == 0)
            .count();
        let reused_nullifiers = self
            .nullifier_observations
            .values()
            .filter(|observation| observation.reuse_count > 1)
            .count();
        let reused_subaddresses = self
            .subaddress_observations
            .values()
            .filter(|observation| observation.reuse_count > self.config.max_subaddress_reuse)
            .count();
        let redaction_failures = self
            .operator_redactions
            .values()
            .filter(|record| {
                record.visible_fields.len() as u64 > self.config.max_operator_visible_fields
            })
            .count();
        let total_risk_points = self
            .findings
            .values()
            .map(|finding| finding.risk_points)
            .sum();
        Counters {
            audit_requests: self.audit_requests.len(),
            findings: self.findings.len(),
            open_findings,
            critical_findings,
            mitigations: self.mitigations.len(),
            disclosure_budgets: self.disclosure_budgets.len(),
            exhausted_disclosure_budgets,
            policy_records: self.wallet_api_policies.len(),
            public_records: self.public_records.len(),
            nullifier_observations: self.nullifier_observations.len(),
            reused_nullifiers,
            subaddress_observations: self.subaddress_observations.len(),
            reused_subaddresses,
            redaction_failures,
            total_risk_points,
        }
    }

    pub fn roots(&self) -> Roots {
        let audit_request_root = map_root(
            "AUDIT-REQUESTS",
            &self.audit_requests,
            AuditRequest::public_record,
        );
        let finding_root = map_root("RISK-FINDINGS", &self.findings, RiskFinding::public_record);
        let mitigation_root = map_root(
            "MITIGATIONS",
            &self.mitigations,
            MitigationQueueRecord::public_record,
        );
        let disclosure_budget_root = map_root(
            "DISCLOSURE-BUDGETS",
            &self.disclosure_budgets,
            DisclosureBudgetRecord::public_record,
        );
        let policy_record_root = map_root(
            "WALLET-API-POLICIES",
            &self.wallet_api_policies,
            WalletApiDisclosurePolicyRecord::public_record,
        );
        let public_record_root = merkle_root(
            "PRIVACY-REGRESSION-PUBLIC-RECORDS",
            &self.public_records.values().cloned().collect::<Vec<_>>(),
        );
        let nullifier_observation_root = map_root(
            "NULLIFIER-OBSERVATIONS",
            &self.nullifier_observations,
            NullifierObservation::public_record,
        );
        let subaddress_observation_root = map_root(
            "SUBADDRESS-OBSERVATIONS",
            &self.subaddress_observations,
            BridgeSubaddressObservation::public_record,
        );
        let operator_redaction_root = map_root(
            "OPERATOR-REDACTIONS",
            &self.operator_redactions,
            OperatorPanelRedactionRecord::public_record,
        );
        let root_record = json!({
            "audit_request_root": audit_request_root,
            "finding_root": finding_root,
            "mitigation_root": mitigation_root,
            "disclosure_budget_root": disclosure_budget_root,
            "policy_record_root": policy_record_root,
            "public_record_root": public_record_root,
            "nullifier_observation_root": nullifier_observation_root,
            "subaddress_observation_root": subaddress_observation_root,
            "operator_redaction_root": operator_redaction_root,
            "epoch": self.epoch,
            "chain_id": self.config.chain_id,
        });
        let state_root = audit_root("STATE-ROOT", &root_record);
        Roots {
            audit_request_root,
            finding_root,
            mitigation_root,
            disclosure_budget_root,
            policy_record_root,
            public_record_root,
            nullifier_observation_root,
            subaddress_observation_root,
            operator_redaction_root,
            state_root,
        }
    }

    pub fn public_record_without_roots(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "epoch": self.epoch,
            "counters": self.counters().public_record(),
            "audit_requests": self.audit_requests.values().map(AuditRequest::public_record).collect::<Vec<_>>(),
            "findings": self.findings.values().map(RiskFinding::public_record).collect::<Vec<_>>(),
            "mitigations": self.mitigations.values().map(MitigationQueueRecord::public_record).collect::<Vec<_>>(),
            "disclosure_budgets": self.disclosure_budgets.values().map(DisclosureBudgetRecord::public_record).collect::<Vec<_>>(),
            "wallet_api_policies": self.wallet_api_policies.values().map(WalletApiDisclosurePolicyRecord::public_record).collect::<Vec<_>>(),
            "nullifier_observations": self.nullifier_observations.values().map(NullifierObservation::public_record).collect::<Vec<_>>(),
            "subaddress_observations": self.subaddress_observations.values().map(BridgeSubaddressObservation::public_record).collect::<Vec<_>>(),
            "operator_redactions": self.operator_redactions.values().map(OperatorPanelRedactionRecord::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "runtime": "private_l2_pq_confidential_privacy_regression_audit",
            "record": self.public_record_without_roots(),
            "roots": self.roots().public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn record_public_record(&mut self, label: &str, subject_id: &str, record: Value) -> Result<()> {
        ensure_len(
            "public_records",
            self.public_records.len() + 1,
            MAX_PUBLIC_RECORDS,
        )?;
        let record_id = public_record_id(label, self.epoch, subject_id, &record);
        self.public_records.insert(record_id, record);
        Ok(())
    }

    fn seed_devnet(&mut self) -> Result<()> {
        self.advance_epoch(912_000)?;
        let policy = WalletApiDisclosurePolicyRecord::devnet(self.epoch);
        let policy_id = policy.policy_id.clone();
        self.register_wallet_api_policy(policy)?;
        let policy_root = commitment("devnet-disclosure-policy-root", &policy_id, self.epoch);
        let mut budget = DisclosureBudgetRecord::new(
            "devnet-wallet-owner-commitment",
            self.epoch,
            self.epoch + self.config.retention_epochs,
            self.config.disclosure_budget_units,
            &policy_root,
        );
        budget
            .disclosure_classes
            .insert(DisclosureClass::ViewKeyWindow);
        budget.disclosure_classes.insert(DisclosureClass::FeeBucket);
        self.register_disclosure_budget(budget)?;
        self.audit_anonymity_set(AnonymitySetAuditRequest::devnet(
            self.epoch,
            self.config.min_anonymity_set_size,
        ))?;
        self.audit_view_tag_encryption(ViewTagEncryptionAuditRequest::devnet(self.epoch, 0))?;
        self.audit_timing_correlation(TimingCorrelationAuditRequest::devnet(self.epoch, 90))?;
        self.audit_fee_metadata(FeeMetadataLeakageAuditRequest::devnet(self.epoch, 40))?;
        self.audit_contract_event_leakage(ContractEventLeakageAuditRequest::devnet(self.epoch, 0))?;
        self.register_operator_redaction(OperatorPanelRedactionRecord::devnet(self.epoch, 3))?;
        Ok(())
    }

    fn seed_demo(&mut self) -> Result<()> {
        self.advance_epoch(42)?;
        let policy = WalletApiDisclosurePolicyRecord::devnet(self.epoch);
        let policy_id = policy.policy_id.clone();
        self.register_wallet_api_policy(policy)?;
        let policy_root = commitment("demo-disclosure-policy-root", &policy_id, self.epoch);
        let budget = DisclosureBudgetRecord::new(
            "demo-wallet-owner-commitment",
            self.epoch,
            self.epoch + self.config.retention_epochs,
            self.config.disclosure_budget_units,
            &policy_root,
        );
        self.register_disclosure_budget(budget)?;
        self.audit_anonymity_set(AnonymitySetAuditRequest::devnet(self.epoch, 1_024))?;
        self.audit_view_key_disclosure(ViewKeyDisclosureAuditRequest::devnet(self.epoch, 300))?;
        self.audit_view_tag_encryption(ViewTagEncryptionAuditRequest::devnet(self.epoch, 2))?;
        self.audit_timing_correlation(TimingCorrelationAuditRequest::devnet(self.epoch, 700))?;
        self.audit_fee_metadata(FeeMetadataLeakageAuditRequest::devnet(self.epoch, 360))?;
        self.audit_contract_event_leakage(ContractEventLeakageAuditRequest::devnet(self.epoch, 2))?;
        let nullifier = NullifierObservation::new(
            self.epoch,
            PrivacyLane::Withdrawal,
            &commitment("demo-nullifier", "reused", self.epoch),
            "demo-withdrawal-request",
            &commitment("demo-note-root", "reused", self.epoch),
            self.epoch.saturating_sub(1),
            2,
        );
        self.observe_nullifier(nullifier)?;
        let subaddress = BridgeSubaddressObservation::new(
            self.epoch,
            "demo-bridge-batch",
            &commitment("demo-subaddress", "linked", self.epoch),
            &commitment("demo-route", "linked", self.epoch),
            3,
            2,
        );
        self.observe_bridge_subaddress(subaddress)?;
        self.register_operator_redaction(OperatorPanelRedactionRecord::devnet(self.epoch, 7))?;
        let finding_ids = self.findings.keys().cloned().collect::<Vec<_>>();
        for finding_id in finding_ids {
            self.queue_mitigation(&finding_id, "demo-privacy-ops-owner", self.epoch + 4)?;
        }
        Ok(())
    }
}

pub fn devnet() -> Result<State> {
    State::devnet()
}

pub fn demo() -> Result<State> {
    State::demo()
}

pub fn audit_id(label: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-PRIVACY-REGRESSION-AUDIT-ID",
        &[
            HashPart::Str(label),
            HashPart::Str(&domain_hash(label, parts, 32)),
        ],
        32,
    )
}

pub fn audit_root(label: &str, record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-PRIVACY-REGRESSION-AUDIT-ROOT",
        &[HashPart::Str(label), HashPart::Json(record)],
        32,
    )
}

pub fn commitment(label: &str, subject: &str, epoch: u64) -> String {
    audit_id(
        "commitment",
        &[
            HashPart::Str(label),
            HashPart::Str(subject),
            HashPart::U64(epoch),
        ],
    )
}

pub fn public_record_id(label: &str, epoch: u64, subject_id: &str, record: &Value) -> String {
    audit_id(
        "public-record",
        &[
            HashPart::Str(label),
            HashPart::U64(epoch),
            HashPart::Str(subject_id),
            HashPart::Json(record),
        ],
    )
}

pub fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": public_record(value),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn ensure_nonempty(field: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(format!("{field} must be nonempty"));
    }
    Ok(())
}

fn ensure_len(field: &str, len: usize, max: usize) -> Result<()> {
    if len > max {
        return Err(format!("{field} exceeds maximum length {max}"));
    }
    Ok(())
}
