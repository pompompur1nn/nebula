use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ProtocolInvariantsResult<T> = Result<T, String>;

pub const PROTOCOL_INVARIANTS_PROTOCOL_VERSION: &str = "nebula-protocol-invariants-v1";
pub const PROTOCOL_INVARIANTS_DEFAULT_EVALUATION_TTL_BLOCKS: u64 = 24;
pub const PROTOCOL_INVARIANTS_DEFAULT_REMEDIATION_TTL_BLOCKS: u64 = 96;
pub const PROTOCOL_INVARIANTS_DEFAULT_ASSURANCE_EPOCH_BLOCKS: u64 = 720;
pub const PROTOCOL_INVARIANTS_DEFAULT_MIN_PASS_RATE_BPS: u64 = 9_500;
pub const PROTOCOL_INVARIANTS_DEFAULT_CRITICAL_PASS_RATE_BPS: u64 = 10_000;
pub const PROTOCOL_INVARIANTS_DEFAULT_MAX_OPEN_CRITICAL: u64 = 0;
pub const PROTOCOL_INVARIANTS_MAX_BPS: u64 = 10_000;
pub const PROTOCOL_INVARIANTS_MAX_SPECS: usize = 512;
pub const PROTOCOL_INVARIANTS_MAX_OBSERVATIONS: usize = 1_024;
pub const PROTOCOL_INVARIANTS_MAX_RECEIPTS: usize = 1_024;
pub const PROTOCOL_INVARIANTS_MAX_VIOLATIONS: usize = 512;
pub const PROTOCOL_INVARIANTS_MAX_REMEDIATIONS: usize = 512;
pub const PROTOCOL_INVARIANTS_MAX_REPORTS: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantDomain {
    Bridge,
    MoneroWatch,
    PqAuth,
    Privacy,
    ConfidentialAssets,
    PrivateContracts,
    IntentSettlement,
    Proofs,
    Fees,
    Sequencing,
    State,
    Governance,
}

impl InvariantDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bridge => "bridge",
            Self::MoneroWatch => "monero_watch",
            Self::PqAuth => "pq_auth",
            Self::Privacy => "privacy",
            Self::ConfidentialAssets => "confidential_assets",
            Self::PrivateContracts => "private_contracts",
            Self::IntentSettlement => "intent_settlement",
            Self::Proofs => "proofs",
            Self::Fees => "fees",
            Self::Sequencing => "sequencing",
            Self::State => "state",
            Self::Governance => "governance",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantKind {
    Conservation,
    NoReplay,
    MonotonicHeight,
    ReserveCoverage,
    PqAuthorization,
    ProofCompleteness,
    PrivacyBudget,
    NullifierUniqueness,
    FeeBoundedness,
    Liveness,
    GovernanceTimelock,
    SlashingCompleteness,
}

impl InvariantKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Conservation => "conservation",
            Self::NoReplay => "no_replay",
            Self::MonotonicHeight => "monotonic_height",
            Self::ReserveCoverage => "reserve_coverage",
            Self::PqAuthorization => "pq_authorization",
            Self::ProofCompleteness => "proof_completeness",
            Self::PrivacyBudget => "privacy_budget",
            Self::NullifierUniqueness => "nullifier_uniqueness",
            Self::FeeBoundedness => "fee_boundedness",
            Self::Liveness => "liveness",
            Self::GovernanceTimelock => "governance_timelock",
            Self::SlashingCompleteness => "slashing_completeness",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantSeverity {
    Info,
    Warning,
    Critical,
    Halt,
}

impl InvariantSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
            Self::Halt => "halt",
        }
    }

    pub fn score_bps(self) -> u64 {
        match self {
            Self::Info => 500,
            Self::Warning => 4_000,
            Self::Critical => 8_000,
            Self::Halt => 10_000,
        }
    }

    pub fn is_critical(self) -> bool {
        matches!(self, Self::Critical | Self::Halt)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantEvaluationStatus {
    Pending,
    Passed,
    Failed,
    Waived,
    Expired,
}

impl InvariantEvaluationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Waived => "waived",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantViolationStatus {
    Open,
    Acknowledged,
    Mitigating,
    Resolved,
    Slashed,
    Waived,
}

impl InvariantViolationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Acknowledged => "acknowledged",
            Self::Mitigating => "mitigating",
            Self::Resolved => "resolved",
            Self::Slashed => "slashed",
            Self::Waived => "waived",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(self, Self::Open | Self::Acknowledged | Self::Mitigating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationKind {
    Observe,
    PauseBridge,
    RotatePqKeys,
    RebuildProof,
    QuarantineNullifier,
    ThrottleFeeLane,
    RequireDisclosure,
    SlashOperator,
    GovernanceIncident,
}

impl RemediationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::PauseBridge => "pause_bridge",
            Self::RotatePqKeys => "rotate_pq_keys",
            Self::RebuildProof => "rebuild_proof",
            Self::QuarantineNullifier => "quarantine_nullifier",
            Self::ThrottleFeeLane => "throttle_fee_lane",
            Self::RequireDisclosure => "require_disclosure",
            Self::SlashOperator => "slash_operator",
            Self::GovernanceIncident => "governance_incident",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolInvariantsConfig {
    pub config_id: String,
    pub evaluation_ttl_blocks: u64,
    pub remediation_ttl_blocks: u64,
    pub assurance_epoch_blocks: u64,
    pub min_pass_rate_bps: u64,
    pub critical_pass_rate_bps: u64,
    pub max_open_critical: u64,
    pub require_pq_attested_observations: bool,
    pub require_roots_only_public_records: bool,
    pub enable_auto_remediation: bool,
}

impl Default for ProtocolInvariantsConfig {
    fn default() -> Self {
        let mut config = Self {
            config_id: String::new(),
            evaluation_ttl_blocks: PROTOCOL_INVARIANTS_DEFAULT_EVALUATION_TTL_BLOCKS,
            remediation_ttl_blocks: PROTOCOL_INVARIANTS_DEFAULT_REMEDIATION_TTL_BLOCKS,
            assurance_epoch_blocks: PROTOCOL_INVARIANTS_DEFAULT_ASSURANCE_EPOCH_BLOCKS,
            min_pass_rate_bps: PROTOCOL_INVARIANTS_DEFAULT_MIN_PASS_RATE_BPS,
            critical_pass_rate_bps: PROTOCOL_INVARIANTS_DEFAULT_CRITICAL_PASS_RATE_BPS,
            max_open_critical: PROTOCOL_INVARIANTS_DEFAULT_MAX_OPEN_CRITICAL,
            require_pq_attested_observations: true,
            require_roots_only_public_records: true,
            enable_auto_remediation: true,
        };
        config.config_id = protocol_invariants_config_id(&config.identity_record());
        config
    }
}

impl ProtocolInvariantsConfig {
    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "protocol_invariants_config",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_INVARIANTS_PROTOCOL_VERSION,
            "evaluation_ttl_blocks": self.evaluation_ttl_blocks,
            "remediation_ttl_blocks": self.remediation_ttl_blocks,
            "assurance_epoch_blocks": self.assurance_epoch_blocks,
            "min_pass_rate_bps": self.min_pass_rate_bps,
            "critical_pass_rate_bps": self.critical_pass_rate_bps,
            "max_open_critical": self.max_open_critical,
            "require_pq_attested_observations": self.require_pq_attested_observations,
            "require_roots_only_public_records": self.require_roots_only_public_records,
            "enable_auto_remediation": self.enable_auto_remediation,
        })
    }

    pub fn config_root(&self) -> String {
        protocol_invariants_payload_root("PROTOCOL-INVARIANTS-CONFIG", &self.identity_record())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("protocol invariants config record object");
        object.insert(
            "config_id".to_string(),
            Value::String(self.config_id.clone()),
        );
        object.insert("config_root".to_string(), Value::String(self.config_root()));
        record
    }

    pub fn validate(&self) -> ProtocolInvariantsResult<String> {
        ensure_non_empty(&self.config_id, "protocol invariants config id")?;
        ensure_positive(
            self.evaluation_ttl_blocks,
            "protocol invariants evaluation ttl",
        )?;
        ensure_positive(
            self.remediation_ttl_blocks,
            "protocol invariants remediation ttl",
        )?;
        ensure_positive(
            self.assurance_epoch_blocks,
            "protocol invariants assurance epoch",
        )?;
        validate_bps(self.min_pass_rate_bps, "protocol invariants min pass rate")?;
        validate_bps(
            self.critical_pass_rate_bps,
            "protocol invariants critical pass rate",
        )?;
        if self.critical_pass_rate_bps < self.min_pass_rate_bps {
            return Err("protocol invariants critical pass rate below min pass rate".to_string());
        }
        if self.config_id != protocol_invariants_config_id(&self.identity_record()) {
            return Err("protocol invariants config id mismatch".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantScope {
    pub scope_id: String,
    pub domain: InvariantDomain,
    pub component: String,
    pub state_root: String,
    pub critical: bool,
    pub labels: BTreeSet<String>,
}

impl InvariantScope {
    pub fn new(
        domain: InvariantDomain,
        component: impl Into<String>,
        state_root: impl Into<String>,
        critical: bool,
        labels: impl IntoIterator<Item = String>,
    ) -> ProtocolInvariantsResult<Self> {
        let component = component.into();
        let state_root = state_root.into();
        ensure_non_empty(&component, "protocol invariant scope component")?;
        ensure_non_empty(&state_root, "protocol invariant scope state root")?;
        let labels = labels.into_iter().collect::<BTreeSet<_>>();
        let label_root = protocol_invariants_string_set_root(
            "PROTOCOL-INVARIANTS-SCOPE-LABELS",
            &labels.iter().cloned().collect::<Vec<_>>(),
        );
        let scope_id =
            protocol_invariants_scope_id(domain, &component, &state_root, critical, &label_root);
        Ok(Self {
            scope_id,
            domain,
            component,
            state_root,
            critical,
            labels,
        })
    }

    pub fn label_root(&self) -> String {
        protocol_invariants_string_set_root(
            "PROTOCOL-INVARIANTS-SCOPE-LABELS",
            &self.labels.iter().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn validate(&self) -> ProtocolInvariantsResult<()> {
        ensure_non_empty(&self.scope_id, "protocol invariant scope id")?;
        ensure_non_empty(&self.component, "protocol invariant scope component")?;
        ensure_non_empty(&self.state_root, "protocol invariant scope state root")?;
        if self.scope_id
            != protocol_invariants_scope_id(
                self.domain,
                &self.component,
                &self.state_root,
                self.critical,
                &self.label_root(),
            )
        {
            return Err("protocol invariant scope id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "protocol_invariant_scope",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_INVARIANTS_PROTOCOL_VERSION,
            "scope_id": self.scope_id,
            "domain": self.domain.as_str(),
            "component": self.component,
            "state_root": self.state_root,
            "critical": self.critical,
            "labels": self.labels.iter().cloned().collect::<Vec<_>>(),
            "label_root": self.label_root(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolInvariantSpec {
    pub spec_id: String,
    pub domain: InvariantDomain,
    pub kind: InvariantKind,
    pub severity: InvariantSeverity,
    pub label: String,
    pub statement_root: String,
    pub parameter_root: String,
    pub scope_ids: Vec<String>,
    pub active_from_height: u64,
    pub active_until_height: u64,
    pub required_pass_rate_bps: u64,
    pub remediation_kind: RemediationKind,
}

impl ProtocolInvariantSpec {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        domain: InvariantDomain,
        kind: InvariantKind,
        severity: InvariantSeverity,
        label: impl Into<String>,
        statement: &Value,
        parameters: &Value,
        scope_ids: Vec<String>,
        active_from_height: u64,
        active_until_height: u64,
        required_pass_rate_bps: u64,
        remediation_kind: RemediationKind,
    ) -> ProtocolInvariantsResult<Self> {
        let label = label.into();
        ensure_non_empty(&label, "protocol invariant spec label")?;
        if scope_ids.is_empty() {
            return Err("protocol invariant spec needs at least one scope".to_string());
        }
        if active_until_height <= active_from_height {
            return Err("protocol invariant spec active window is empty".to_string());
        }
        validate_bps(
            required_pass_rate_bps,
            "protocol invariant spec required pass rate",
        )?;
        let statement_root =
            protocol_invariants_payload_root("PROTOCOL-INVARIANTS-SPEC-STATEMENT", statement);
        let parameter_root =
            protocol_invariants_payload_root("PROTOCOL-INVARIANTS-SPEC-PARAMETERS", parameters);
        let scope_root =
            protocol_invariants_string_set_root("PROTOCOL-INVARIANTS-SPEC-SCOPES", &scope_ids);
        let spec_id = protocol_invariants_spec_id(
            domain,
            kind,
            severity,
            &label,
            &statement_root,
            &parameter_root,
            &scope_root,
            active_from_height,
            active_until_height,
            required_pass_rate_bps,
            remediation_kind,
        );
        Ok(Self {
            spec_id,
            domain,
            kind,
            severity,
            label,
            statement_root,
            parameter_root,
            scope_ids,
            active_from_height,
            active_until_height,
            required_pass_rate_bps,
            remediation_kind,
        })
    }

    pub fn scope_root(&self) -> String {
        protocol_invariants_string_set_root("PROTOCOL-INVARIANTS-SPEC-SCOPES", &self.scope_ids)
    }

    pub fn active_at(&self, height: u64) -> bool {
        height >= self.active_from_height && height <= self.active_until_height
    }

    pub fn validate(&self) -> ProtocolInvariantsResult<()> {
        ensure_non_empty(&self.spec_id, "protocol invariant spec id")?;
        ensure_non_empty(&self.label, "protocol invariant spec label")?;
        ensure_non_empty(
            &self.statement_root,
            "protocol invariant spec statement root",
        )?;
        ensure_non_empty(
            &self.parameter_root,
            "protocol invariant spec parameter root",
        )?;
        if self.scope_ids.is_empty() {
            return Err("protocol invariant spec scope set cannot be empty".to_string());
        }
        if self.active_until_height <= self.active_from_height {
            return Err("protocol invariant spec active window is empty".to_string());
        }
        validate_bps(
            self.required_pass_rate_bps,
            "protocol invariant required pass rate",
        )?;
        if self.spec_id
            != protocol_invariants_spec_id(
                self.domain,
                self.kind,
                self.severity,
                &self.label,
                &self.statement_root,
                &self.parameter_root,
                &self.scope_root(),
                self.active_from_height,
                self.active_until_height,
                self.required_pass_rate_bps,
                self.remediation_kind,
            )
        {
            return Err("protocol invariant spec id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "protocol_invariant_spec",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_INVARIANTS_PROTOCOL_VERSION,
            "spec_id": self.spec_id,
            "domain": self.domain.as_str(),
            "invariant_kind": self.kind.as_str(),
            "severity": self.severity.as_str(),
            "label": self.label,
            "statement_root": self.statement_root,
            "parameter_root": self.parameter_root,
            "scope_ids": self.scope_ids,
            "scope_root": self.scope_root(),
            "active_from_height": self.active_from_height,
            "active_until_height": self.active_until_height,
            "required_pass_rate_bps": self.required_pass_rate_bps,
            "remediation_kind": self.remediation_kind.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantObservation {
    pub observation_id: String,
    pub spec_id: String,
    pub scope_id: String,
    pub height: u64,
    pub observed_root: String,
    pub expected_root: String,
    pub metric_name: String,
    pub metric_value: u64,
    pub threshold_value: u64,
    pub pq_attestation_root: String,
    pub disclosure_root: String,
}

impl InvariantObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        spec_id: impl Into<String>,
        scope_id: impl Into<String>,
        height: u64,
        observed: &Value,
        expected: &Value,
        metric_name: impl Into<String>,
        metric_value: u64,
        threshold_value: u64,
        pq_attestation: &Value,
        disclosure: &Value,
    ) -> ProtocolInvariantsResult<Self> {
        let spec_id = spec_id.into();
        let scope_id = scope_id.into();
        let metric_name = metric_name.into();
        ensure_non_empty(&spec_id, "protocol invariant observation spec id")?;
        ensure_non_empty(&scope_id, "protocol invariant observation scope id")?;
        ensure_non_empty(&metric_name, "protocol invariant observation metric")?;
        let observed_root =
            protocol_invariants_payload_root("PROTOCOL-INVARIANTS-OBSERVED", observed);
        let expected_root =
            protocol_invariants_payload_root("PROTOCOL-INVARIANTS-EXPECTED", expected);
        let pq_attestation_root =
            protocol_invariants_payload_root("PROTOCOL-INVARIANTS-PQ-ATTESTATION", pq_attestation);
        let disclosure_root =
            protocol_invariants_payload_root("PROTOCOL-INVARIANTS-DISCLOSURE", disclosure);
        let observation_id = protocol_invariants_observation_id(
            &spec_id,
            &scope_id,
            height,
            &observed_root,
            &expected_root,
            &metric_name,
            metric_value,
            threshold_value,
            &pq_attestation_root,
            &disclosure_root,
        );
        Ok(Self {
            observation_id,
            spec_id,
            scope_id,
            height,
            observed_root,
            expected_root,
            metric_name,
            metric_value,
            threshold_value,
            pq_attestation_root,
            disclosure_root,
        })
    }

    pub fn passed(&self, kind: InvariantKind) -> bool {
        match kind {
            InvariantKind::FeeBoundedness
            | InvariantKind::PrivacyBudget
            | InvariantKind::Liveness => self.metric_value <= self.threshold_value,
            InvariantKind::ReserveCoverage
            | InvariantKind::ProofCompleteness
            | InvariantKind::PqAuthorization
            | InvariantKind::Conservation
            | InvariantKind::NoReplay
            | InvariantKind::MonotonicHeight
            | InvariantKind::NullifierUniqueness
            | InvariantKind::GovernanceTimelock
            | InvariantKind::SlashingCompleteness => self.metric_value >= self.threshold_value,
        }
    }

    pub fn validate(&self) -> ProtocolInvariantsResult<()> {
        ensure_non_empty(&self.observation_id, "protocol invariant observation id")?;
        ensure_non_empty(&self.spec_id, "protocol invariant observation spec id")?;
        ensure_non_empty(&self.scope_id, "protocol invariant observation scope id")?;
        ensure_non_empty(
            &self.observed_root,
            "protocol invariant observation observed root",
        )?;
        ensure_non_empty(
            &self.expected_root,
            "protocol invariant observation expected root",
        )?;
        ensure_non_empty(&self.metric_name, "protocol invariant observation metric")?;
        ensure_non_empty(
            &self.pq_attestation_root,
            "protocol invariant observation pq attestation",
        )?;
        ensure_non_empty(
            &self.disclosure_root,
            "protocol invariant observation disclosure",
        )?;
        if self.observation_id
            != protocol_invariants_observation_id(
                &self.spec_id,
                &self.scope_id,
                self.height,
                &self.observed_root,
                &self.expected_root,
                &self.metric_name,
                self.metric_value,
                self.threshold_value,
                &self.pq_attestation_root,
                &self.disclosure_root,
            )
        {
            return Err("protocol invariant observation id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "protocol_invariant_observation",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_INVARIANTS_PROTOCOL_VERSION,
            "observation_id": self.observation_id,
            "spec_id": self.spec_id,
            "scope_id": self.scope_id,
            "height": self.height,
            "observed_root": self.observed_root,
            "expected_root": self.expected_root,
            "metric_name": self.metric_name,
            "metric_value": self.metric_value,
            "threshold_value": self.threshold_value,
            "pq_attestation_root": self.pq_attestation_root,
            "disclosure_root": self.disclosure_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantEvaluationReceipt {
    pub receipt_id: String,
    pub spec_id: String,
    pub observation_id: String,
    pub height: u64,
    pub status: InvariantEvaluationStatus,
    pub severity: InvariantSeverity,
    pub evaluator_commitment: String,
    pub evaluation_root: String,
    pub expires_at_height: u64,
}

impl InvariantEvaluationReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        spec: &ProtocolInvariantSpec,
        observation: &InvariantObservation,
        evaluator_label: impl Into<String>,
        passed: bool,
        evaluation: &Value,
        ttl_blocks: u64,
    ) -> ProtocolInvariantsResult<Self> {
        spec.validate()?;
        observation.validate()?;
        ensure_positive(ttl_blocks, "protocol invariant evaluation ttl")?;
        let evaluator_label = evaluator_label.into();
        ensure_non_empty(&evaluator_label, "protocol invariant evaluator label")?;
        let status = if passed {
            InvariantEvaluationStatus::Passed
        } else {
            InvariantEvaluationStatus::Failed
        };
        let evaluator_commitment =
            protocol_invariants_string_root("PROTOCOL-INVARIANTS-EVALUATOR", &evaluator_label);
        let evaluation_root =
            protocol_invariants_payload_root("PROTOCOL-INVARIANTS-EVALUATION", evaluation);
        let expires_at_height = observation.height.saturating_add(ttl_blocks);
        let receipt_id = protocol_invariants_receipt_id(
            &spec.spec_id,
            &observation.observation_id,
            observation.height,
            status,
            spec.severity,
            &evaluator_commitment,
            &evaluation_root,
            expires_at_height,
        );
        Ok(Self {
            receipt_id,
            spec_id: spec.spec_id.clone(),
            observation_id: observation.observation_id.clone(),
            height: observation.height,
            status,
            severity: spec.severity,
            evaluator_commitment,
            evaluation_root,
            expires_at_height,
        })
    }

    pub fn validate(&self) -> ProtocolInvariantsResult<()> {
        ensure_non_empty(&self.receipt_id, "protocol invariant receipt id")?;
        ensure_non_empty(&self.spec_id, "protocol invariant receipt spec id")?;
        ensure_non_empty(
            &self.observation_id,
            "protocol invariant receipt observation id",
        )?;
        ensure_non_empty(
            &self.evaluator_commitment,
            "protocol invariant receipt evaluator",
        )?;
        ensure_non_empty(&self.evaluation_root, "protocol invariant receipt root")?;
        if self.expires_at_height <= self.height {
            return Err("protocol invariant receipt expiry is not after height".to_string());
        }
        if self.receipt_id
            != protocol_invariants_receipt_id(
                &self.spec_id,
                &self.observation_id,
                self.height,
                self.status,
                self.severity,
                &self.evaluator_commitment,
                &self.evaluation_root,
                self.expires_at_height,
            )
        {
            return Err("protocol invariant receipt id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "protocol_invariant_evaluation_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_INVARIANTS_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "spec_id": self.spec_id,
            "observation_id": self.observation_id,
            "height": self.height,
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
            "evaluator_commitment": self.evaluator_commitment,
            "evaluation_root": self.evaluation_root,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantViolation {
    pub violation_id: String,
    pub spec_id: String,
    pub receipt_id: String,
    pub severity: InvariantSeverity,
    pub opened_at_height: u64,
    pub last_seen_height: u64,
    pub status: InvariantViolationStatus,
    pub evidence_root: String,
    pub affected_scope_root: String,
    pub recommended_remediation: RemediationKind,
}

impl InvariantViolation {
    pub fn from_receipt(
        spec: &ProtocolInvariantSpec,
        receipt: &InvariantEvaluationReceipt,
        evidence: &Value,
        affected_scopes: &[String],
    ) -> ProtocolInvariantsResult<Self> {
        spec.validate()?;
        receipt.validate()?;
        if receipt.status != InvariantEvaluationStatus::Failed {
            return Err("protocol invariant violation requires failed receipt".to_string());
        }
        if affected_scopes.is_empty() {
            return Err("protocol invariant violation needs affected scopes".to_string());
        }
        let evidence_root =
            protocol_invariants_payload_root("PROTOCOL-INVARIANTS-VIOLATION-EVIDENCE", evidence);
        let affected_scope_root = protocol_invariants_string_set_root(
            "PROTOCOL-INVARIANTS-VIOLATION-SCOPES",
            affected_scopes,
        );
        let status = InvariantViolationStatus::Open;
        let violation_id = protocol_invariants_violation_id(
            &spec.spec_id,
            &receipt.receipt_id,
            spec.severity,
            receipt.height,
            receipt.height,
            status,
            &evidence_root,
            &affected_scope_root,
            spec.remediation_kind,
        );
        Ok(Self {
            violation_id,
            spec_id: spec.spec_id.clone(),
            receipt_id: receipt.receipt_id.clone(),
            severity: spec.severity,
            opened_at_height: receipt.height,
            last_seen_height: receipt.height,
            status,
            evidence_root,
            affected_scope_root,
            recommended_remediation: spec.remediation_kind,
        })
    }

    pub fn validate(&self) -> ProtocolInvariantsResult<()> {
        ensure_non_empty(&self.violation_id, "protocol invariant violation id")?;
        ensure_non_empty(&self.spec_id, "protocol invariant violation spec id")?;
        ensure_non_empty(&self.receipt_id, "protocol invariant violation receipt id")?;
        ensure_non_empty(&self.evidence_root, "protocol invariant violation evidence")?;
        ensure_non_empty(
            &self.affected_scope_root,
            "protocol invariant violation affected scope root",
        )?;
        if self.last_seen_height < self.opened_at_height {
            return Err("protocol invariant violation last seen before opened".to_string());
        }
        if self.violation_id
            != protocol_invariants_violation_id(
                &self.spec_id,
                &self.receipt_id,
                self.severity,
                self.opened_at_height,
                self.last_seen_height,
                self.status,
                &self.evidence_root,
                &self.affected_scope_root,
                self.recommended_remediation,
            )
        {
            return Err("protocol invariant violation id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "protocol_invariant_violation",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_INVARIANTS_PROTOCOL_VERSION,
            "violation_id": self.violation_id,
            "spec_id": self.spec_id,
            "receipt_id": self.receipt_id,
            "severity": self.severity.as_str(),
            "opened_at_height": self.opened_at_height,
            "last_seen_height": self.last_seen_height,
            "status": self.status.as_str(),
            "evidence_root": self.evidence_root,
            "affected_scope_root": self.affected_scope_root,
            "recommended_remediation": self.recommended_remediation.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantRemediationPlan {
    pub plan_id: String,
    pub violation_id: String,
    pub remediation_kind: RemediationKind,
    pub owner_commitment: String,
    pub action_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub completed: bool,
}

impl InvariantRemediationPlan {
    pub fn new(
        violation: &InvariantViolation,
        owner_label: impl Into<String>,
        actions: &[Value],
        ttl_blocks: u64,
    ) -> ProtocolInvariantsResult<Self> {
        violation.validate()?;
        ensure_positive(ttl_blocks, "protocol invariant remediation ttl")?;
        if actions.is_empty() {
            return Err("protocol invariant remediation actions cannot be empty".to_string());
        }
        let owner_label = owner_label.into();
        ensure_non_empty(&owner_label, "protocol invariant remediation owner")?;
        let owner_commitment =
            protocol_invariants_string_root("PROTOCOL-INVARIANTS-REMEDIATION-OWNER", &owner_label);
        let action_root = merkle_root("PROTOCOL-INVARIANTS-REMEDIATION-ACTIONS", actions);
        let expires_at_height = violation.opened_at_height.saturating_add(ttl_blocks);
        let plan_id = protocol_invariants_remediation_plan_id(
            &violation.violation_id,
            violation.recommended_remediation,
            &owner_commitment,
            &action_root,
            violation.opened_at_height,
            expires_at_height,
            false,
        );
        Ok(Self {
            plan_id,
            violation_id: violation.violation_id.clone(),
            remediation_kind: violation.recommended_remediation,
            owner_commitment,
            action_root,
            created_at_height: violation.opened_at_height,
            expires_at_height,
            completed: false,
        })
    }

    pub fn validate(&self) -> ProtocolInvariantsResult<()> {
        ensure_non_empty(&self.plan_id, "protocol invariant remediation plan id")?;
        ensure_non_empty(
            &self.violation_id,
            "protocol invariant remediation violation id",
        )?;
        ensure_non_empty(
            &self.owner_commitment,
            "protocol invariant remediation owner",
        )?;
        ensure_non_empty(&self.action_root, "protocol invariant remediation action")?;
        if self.expires_at_height <= self.created_at_height {
            return Err("protocol invariant remediation expiry is not after created".to_string());
        }
        if self.plan_id
            != protocol_invariants_remediation_plan_id(
                &self.violation_id,
                self.remediation_kind,
                &self.owner_commitment,
                &self.action_root,
                self.created_at_height,
                self.expires_at_height,
                self.completed,
            )
        {
            return Err("protocol invariant remediation plan id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "protocol_invariant_remediation_plan",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_INVARIANTS_PROTOCOL_VERSION,
            "plan_id": self.plan_id,
            "violation_id": self.violation_id,
            "remediation_kind": self.remediation_kind.as_str(),
            "owner_commitment": self.owner_commitment,
            "action_root": self.action_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "completed": self.completed,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantAssuranceReport {
    pub report_id: String,
    pub start_height: u64,
    pub end_height: u64,
    pub spec_root: String,
    pub receipt_root: String,
    pub violation_root: String,
    pub remediation_root: String,
    pub pass_rate_bps: u64,
    pub critical_pass_rate_bps: u64,
    pub open_critical_count: u64,
    pub assurance_root: String,
}

impl InvariantAssuranceReport {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        start_height: u64,
        end_height: u64,
        spec_root: impl Into<String>,
        receipt_root: impl Into<String>,
        violation_root: impl Into<String>,
        remediation_root: impl Into<String>,
        pass_rate_bps: u64,
        critical_pass_rate_bps: u64,
        open_critical_count: u64,
    ) -> ProtocolInvariantsResult<Self> {
        if end_height < start_height {
            return Err("protocol invariant assurance report has inverted range".to_string());
        }
        validate_bps(pass_rate_bps, "protocol invariant assurance pass rate")?;
        validate_bps(
            critical_pass_rate_bps,
            "protocol invariant assurance critical pass rate",
        )?;
        let spec_root = spec_root.into();
        let receipt_root = receipt_root.into();
        let violation_root = violation_root.into();
        let remediation_root = remediation_root.into();
        ensure_non_empty(&spec_root, "protocol invariant assurance spec root")?;
        ensure_non_empty(&receipt_root, "protocol invariant assurance receipt root")?;
        ensure_non_empty(
            &violation_root,
            "protocol invariant assurance violation root",
        )?;
        ensure_non_empty(
            &remediation_root,
            "protocol invariant assurance remediation root",
        )?;
        let assurance_payload = json!({
            "start_height": start_height,
            "end_height": end_height,
            "spec_root": spec_root,
            "receipt_root": receipt_root,
            "violation_root": violation_root,
            "remediation_root": remediation_root,
            "pass_rate_bps": pass_rate_bps,
            "critical_pass_rate_bps": critical_pass_rate_bps,
            "open_critical_count": open_critical_count,
        });
        let assurance_root =
            protocol_invariants_payload_root("PROTOCOL-INVARIANTS-ASSURANCE", &assurance_payload);
        let report_id = protocol_invariants_assurance_report_id(
            start_height,
            end_height,
            &spec_root,
            &receipt_root,
            &violation_root,
            &remediation_root,
            pass_rate_bps,
            critical_pass_rate_bps,
            open_critical_count,
            &assurance_root,
        );
        Ok(Self {
            report_id,
            start_height,
            end_height,
            spec_root,
            receipt_root,
            violation_root,
            remediation_root,
            pass_rate_bps,
            critical_pass_rate_bps,
            open_critical_count,
            assurance_root,
        })
    }

    pub fn validate(&self) -> ProtocolInvariantsResult<()> {
        ensure_non_empty(&self.report_id, "protocol invariant assurance report id")?;
        ensure_non_empty(&self.spec_root, "protocol invariant assurance spec root")?;
        ensure_non_empty(
            &self.receipt_root,
            "protocol invariant assurance receipt root",
        )?;
        ensure_non_empty(
            &self.violation_root,
            "protocol invariant assurance violation root",
        )?;
        ensure_non_empty(
            &self.remediation_root,
            "protocol invariant assurance remediation root",
        )?;
        ensure_non_empty(
            &self.assurance_root,
            "protocol invariant assurance report root",
        )?;
        if self.end_height < self.start_height {
            return Err("protocol invariant assurance range inverted".to_string());
        }
        validate_bps(self.pass_rate_bps, "protocol invariant assurance pass rate")?;
        validate_bps(
            self.critical_pass_rate_bps,
            "protocol invariant assurance critical pass rate",
        )?;
        if self.report_id
            != protocol_invariants_assurance_report_id(
                self.start_height,
                self.end_height,
                &self.spec_root,
                &self.receipt_root,
                &self.violation_root,
                &self.remediation_root,
                self.pass_rate_bps,
                self.critical_pass_rate_bps,
                self.open_critical_count,
                &self.assurance_root,
            )
        {
            return Err("protocol invariant assurance report id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "protocol_invariant_assurance_report",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_INVARIANTS_PROTOCOL_VERSION,
            "report_id": self.report_id,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "spec_root": self.spec_root,
            "receipt_root": self.receipt_root,
            "violation_root": self.violation_root,
            "remediation_root": self.remediation_root,
            "pass_rate_bps": self.pass_rate_bps,
            "critical_pass_rate_bps": self.critical_pass_rate_bps,
            "open_critical_count": self.open_critical_count,
            "assurance_root": self.assurance_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolInvariantsRoots {
    pub config_root: String,
    pub scope_root: String,
    pub spec_root: String,
    pub observation_root: String,
    pub receipt_root: String,
    pub violation_root: String,
    pub remediation_root: String,
    pub assurance_report_root: String,
    pub state_root: String,
}

impl ProtocolInvariantsRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "protocol_invariants_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_INVARIANTS_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "scope_root": self.scope_root,
            "spec_root": self.spec_root,
            "observation_root": self.observation_root,
            "receipt_root": self.receipt_root,
            "violation_root": self.violation_root,
            "remediation_root": self.remediation_root,
            "assurance_report_root": self.assurance_report_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolInvariantsCounters {
    pub scopes: u64,
    pub specs: u64,
    pub observations: u64,
    pub receipts: u64,
    pub passed_receipts: u64,
    pub failed_receipts: u64,
    pub open_violations: u64,
    pub critical_open_violations: u64,
    pub remediation_plans: u64,
    pub completed_remediations: u64,
    pub assurance_reports: u64,
    pub pass_rate_bps: u64,
    pub critical_pass_rate_bps: u64,
}

impl ProtocolInvariantsCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "protocol_invariants_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_INVARIANTS_PROTOCOL_VERSION,
            "scopes": self.scopes,
            "specs": self.specs,
            "observations": self.observations,
            "receipts": self.receipts,
            "passed_receipts": self.passed_receipts,
            "failed_receipts": self.failed_receipts,
            "open_violations": self.open_violations,
            "critical_open_violations": self.critical_open_violations,
            "remediation_plans": self.remediation_plans,
            "completed_remediations": self.completed_remediations,
            "assurance_reports": self.assurance_reports,
            "pass_rate_bps": self.pass_rate_bps,
            "critical_pass_rate_bps": self.critical_pass_rate_bps,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolInvariantsState {
    pub height: u64,
    pub config: ProtocolInvariantsConfig,
    pub scopes: BTreeMap<String, InvariantScope>,
    pub specs: BTreeMap<String, ProtocolInvariantSpec>,
    pub observations: BTreeMap<String, InvariantObservation>,
    pub receipts: BTreeMap<String, InvariantEvaluationReceipt>,
    pub violations: BTreeMap<String, InvariantViolation>,
    pub remediations: BTreeMap<String, InvariantRemediationPlan>,
    pub assurance_reports: BTreeMap<String, InvariantAssuranceReport>,
}

impl Default for ProtocolInvariantsState {
    fn default() -> Self {
        Self::new(ProtocolInvariantsConfig::default()).expect("default protocol invariants config")
    }
}

impl ProtocolInvariantsState {
    pub fn new(config: ProtocolInvariantsConfig) -> ProtocolInvariantsResult<Self> {
        config.validate()?;
        Ok(Self {
            height: 0,
            config,
            scopes: BTreeMap::new(),
            specs: BTreeMap::new(),
            observations: BTreeMap::new(),
            receipts: BTreeMap::new(),
            violations: BTreeMap::new(),
            remediations: BTreeMap::new(),
            assurance_reports: BTreeMap::new(),
        })
    }

    pub fn devnet() -> ProtocolInvariantsResult<Self> {
        let mut state = Self::new(ProtocolInvariantsConfig::default())?;
        state.set_height(1);

        let bridge_scope = InvariantScope::new(
            InvariantDomain::Bridge,
            "pq_bridge_ops",
            protocol_invariants_string_root("DEVNET-INVARIANT-ROOT", "pq_bridge_ops"),
            true,
            vec![
                "monero_bridge".to_string(),
                "pq_committee".to_string(),
                "withdrawals".to_string(),
            ],
        )?;
        let proof_scope = InvariantScope::new(
            InvariantDomain::Proofs,
            "recursive_proof_scheduler",
            protocol_invariants_string_root("DEVNET-INVARIANT-ROOT", "recursive_proof_scheduler"),
            true,
            vec![
                "validity".to_string(),
                "recursion".to_string(),
                "private_contracts".to_string(),
            ],
        )?;
        let asset_scope = InvariantScope::new(
            InvariantDomain::ConfidentialAssets,
            "confidential_asset_runtime",
            protocol_invariants_string_root("DEVNET-INVARIANT-ROOT", "confidential_asset_runtime"),
            true,
            vec![
                "shielded_assets".to_string(),
                "conservation".to_string(),
                "low_fee_transfers".to_string(),
            ],
        )?;
        let intent_scope = InvariantScope::new(
            InvariantDomain::IntentSettlement,
            "intent_settlement",
            protocol_invariants_string_root("DEVNET-INVARIANT-ROOT", "intent_settlement"),
            false,
            vec![
                "private_defi".to_string(),
                "batch_auction".to_string(),
                "solver_slashing".to_string(),
            ],
        )?;
        let fee_scope = InvariantScope::new(
            InvariantDomain::Fees,
            "fast_lane_scheduler",
            protocol_invariants_string_root("DEVNET-INVARIANT-ROOT", "fast_lane_scheduler"),
            false,
            vec![
                "low_fee".to_string(),
                "backpressure".to_string(),
                "sponsorship".to_string(),
            ],
        )?;

        for scope in [
            bridge_scope.clone(),
            proof_scope.clone(),
            asset_scope.clone(),
            intent_scope.clone(),
            fee_scope.clone(),
        ] {
            state.insert_scope(scope)?;
        }

        let reserve_spec = ProtocolInvariantSpec::new(
            InvariantDomain::Bridge,
            InvariantKind::ReserveCoverage,
            InvariantSeverity::Halt,
            "bridge_reserves_cover_exit_queue",
            &json!({
                "statement": "bridge reserve commitments must cover issued withdrawal liabilities",
                "proof_surface": "reserve_checkpoint_root",
            }),
            &json!({
                "min_coverage_bps": 10_000,
                "allow_emergency_pause": true,
            }),
            vec![bridge_scope.scope_id.clone()],
            0,
            10_000,
            10_000,
            RemediationKind::PauseBridge,
        )?;
        let proof_spec = ProtocolInvariantSpec::new(
            InvariantDomain::Proofs,
            InvariantKind::ProofCompleteness,
            InvariantSeverity::Critical,
            "private_execution_batches_have_recursive_proofs",
            &json!({
                "statement": "private contract and intent batches must have scheduled recursive proofs",
                "proof_surface": "recursive_proof_scheduler",
            }),
            &json!({
                "min_complete_bps": 9_900,
                "max_pending_blocks": 24,
            }),
            vec![proof_scope.scope_id.clone(), intent_scope.scope_id.clone()],
            0,
            10_000,
            9_900,
            RemediationKind::RebuildProof,
        )?;
        let asset_spec = ProtocolInvariantSpec::new(
            InvariantDomain::ConfidentialAssets,
            InvariantKind::Conservation,
            InvariantSeverity::Halt,
            "confidential_asset_supply_conservation",
            &json!({
                "statement": "confidential mint, burn, and transfer notes conserve committed supply",
                "proof_surface": "asset_supply_root",
            }),
            &json!({
                "min_conservation_bps": 10_000,
                "allow_admin_mint_root": true,
            }),
            vec![asset_scope.scope_id.clone()],
            0,
            10_000,
            10_000,
            RemediationKind::RequireDisclosure,
        )?;
        let nullifier_spec = ProtocolInvariantSpec::new(
            InvariantDomain::Privacy,
            InvariantKind::NullifierUniqueness,
            InvariantSeverity::Critical,
            "private_nullifiers_are_unique",
            &json!({
                "statement": "all private notes, intents, fees, and bridge claims have unique nullifiers",
                "proof_surface": "nullifier_roots",
            }),
            &json!({
                "min_uniqueness_bps": 10_000,
                "domains": ["bridge", "asset", "intent", "fee"],
            }),
            vec![
                bridge_scope.scope_id.clone(),
                asset_scope.scope_id.clone(),
                intent_scope.scope_id.clone(),
                fee_scope.scope_id.clone(),
            ],
            0,
            10_000,
            10_000,
            RemediationKind::QuarantineNullifier,
        )?;
        let fee_spec = ProtocolInvariantSpec::new(
            InvariantDomain::Fees,
            InvariantKind::FeeBoundedness,
            InvariantSeverity::Warning,
            "low_fee_lanes_stay_bounded_under_backpressure",
            &json!({
                "statement": "low-fee queues must stay within declared backpressure targets",
                "proof_surface": "fast_lane_scheduler",
            }),
            &json!({
                "max_pressure_bps": 8_500,
                "sponsor_budget_floor": 1,
            }),
            vec![fee_scope.scope_id.clone()],
            0,
            10_000,
            9_500,
            RemediationKind::ThrottleFeeLane,
        )?;

        for spec in [
            reserve_spec.clone(),
            proof_spec.clone(),
            asset_spec.clone(),
            nullifier_spec.clone(),
            fee_spec.clone(),
        ] {
            state.insert_spec(spec)?;
        }

        state.evaluate_and_record(
            &reserve_spec.spec_id,
            &bridge_scope.scope_id,
            "reserve_coverage_bps",
            10_000,
            10_000,
            &json!({ "reserve_root": "devnet-reserve-root", "liability_root": "devnet-liability-root" }),
        )?;
        state.evaluate_and_record(
            &proof_spec.spec_id,
            &proof_scope.scope_id,
            "proof_completion_bps",
            9_950,
            9_900,
            &json!({ "scheduled_jobs": 12, "completed_jobs": 12, "recursive_root": "devnet-recursive-root" }),
        )?;
        state.evaluate_and_record(
            &asset_spec.spec_id,
            &asset_scope.scope_id,
            "asset_conservation_bps",
            10_000,
            10_000,
            &json!({ "mint_root": "devnet-mint-root", "burn_root": "devnet-burn-root", "transfer_root": "devnet-transfer-root" }),
        )?;
        state.evaluate_and_record(
            &nullifier_spec.spec_id,
            &intent_scope.scope_id,
            "nullifier_uniqueness_bps",
            10_000,
            10_000,
            &json!({ "nullifier_root": "devnet-nullifier-root", "duplicate_count": 0 }),
        )?;
        state.evaluate_and_record(
            &fee_spec.spec_id,
            &fee_scope.scope_id,
            "queue_pressure_bps",
            7_200,
            8_500,
            &json!({ "queue_pressure_bps": 7200, "sponsor_budget": 250000000 }),
        )?;

        state.refresh_assurance_report()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        self.expire_receipts();
    }

    pub fn insert_scope(&mut self, scope: InvariantScope) -> ProtocolInvariantsResult<String> {
        scope.validate()?;
        let id = scope.scope_id.clone();
        self.scopes.insert(id.clone(), scope);
        Ok(id)
    }

    pub fn insert_spec(&mut self, spec: ProtocolInvariantSpec) -> ProtocolInvariantsResult<String> {
        spec.validate()?;
        for scope_id in &spec.scope_ids {
            if !self.scopes.contains_key(scope_id) {
                return Err("protocol invariant spec references missing scope".to_string());
            }
        }
        let id = spec.spec_id.clone();
        self.specs.insert(id.clone(), spec);
        Ok(id)
    }

    pub fn evaluate_and_record(
        &mut self,
        spec_id: &str,
        scope_id: &str,
        metric_name: &str,
        metric_value: u64,
        threshold_value: u64,
        observed: &Value,
    ) -> ProtocolInvariantsResult<String> {
        let spec = self
            .specs
            .get(spec_id)
            .cloned()
            .ok_or_else(|| "protocol invariant spec missing".to_string())?;
        let scope = self
            .scopes
            .get(scope_id)
            .cloned()
            .ok_or_else(|| "protocol invariant scope missing".to_string())?;
        if !spec.active_at(self.height) {
            return Err("protocol invariant spec not active at height".to_string());
        }
        if !spec.scope_ids.iter().any(|candidate| candidate == scope_id) {
            return Err("protocol invariant spec does not include scope".to_string());
        }
        let observation = InvariantObservation::new(
            spec.spec_id.clone(),
            scope.scope_id.clone(),
            self.height,
            observed,
            &json!({
                "component": scope.component,
                "domain": scope.domain.as_str(),
                "expected_metric": metric_name,
                "threshold_value": threshold_value,
            }),
            metric_name,
            metric_value,
            threshold_value,
            &json!({
                "scheme": "ml-dsa-devnet",
                "attester": "devnet-invariant-evaluator",
                "height": self.height,
            }),
            &json!({
                "mode": "roots_only",
                "component": scope.component,
            }),
        )?;
        let passed = observation.passed(spec.kind);
        let receipt = InvariantEvaluationReceipt::new(
            &spec,
            &observation,
            "devnet-invariant-evaluator",
            passed,
            &json!({
                "passed": passed,
                "metric_name": metric_name,
                "metric_value": metric_value,
                "threshold_value": threshold_value,
                "spec_id": spec.spec_id,
            }),
            self.config.evaluation_ttl_blocks,
        )?;
        let receipt_id = receipt.receipt_id.clone();
        self.observations
            .insert(observation.observation_id.clone(), observation.clone());
        if !passed {
            let violation = InvariantViolation::from_receipt(
                &spec,
                &receipt,
                &json!({
                    "observation_id": observation.observation_id,
                    "metric_name": metric_name,
                    "metric_value": metric_value,
                    "threshold_value": threshold_value,
                }),
                &[scope_id.to_string()],
            )?;
            if self.config.enable_auto_remediation {
                let remediation = InvariantRemediationPlan::new(
                    &violation,
                    "devnet-remediation-owner",
                    &[json!({
                        "action": violation.recommended_remediation.as_str(),
                        "scope_id": scope_id,
                        "spec_id": spec_id,
                    })],
                    self.config.remediation_ttl_blocks,
                )?;
                self.remediations
                    .insert(remediation.plan_id.clone(), remediation);
            }
            self.violations
                .insert(violation.violation_id.clone(), violation);
        }
        self.receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn expire_receipts(&mut self) {
        for receipt in self.receipts.values_mut() {
            if matches!(receipt.status, InvariantEvaluationStatus::Pending)
                && self.height > receipt.expires_at_height
            {
                receipt.status = InvariantEvaluationStatus::Expired;
            }
        }
    }

    pub fn refresh_assurance_report(&mut self) -> ProtocolInvariantsResult<String> {
        let roots = self.roots_without_state();
        let counters = self.counters();
        let start_height = self
            .height
            .saturating_sub(self.config.assurance_epoch_blocks.saturating_sub(1));
        let report = InvariantAssuranceReport::new(
            start_height,
            self.height,
            roots.spec_root,
            roots.receipt_root,
            roots.violation_root,
            roots.remediation_root,
            counters.pass_rate_bps,
            counters.critical_pass_rate_bps,
            counters.critical_open_violations,
        )?;
        let id = report.report_id.clone();
        self.assurance_reports.insert(id.clone(), report);
        Ok(id)
    }

    pub fn roots(&self) -> ProtocolInvariantsRoots {
        let mut roots = self.roots_without_state();
        let state_record = json!({
            "kind": "protocol_invariants_state_root",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_INVARIANTS_PROTOCOL_VERSION,
            "height": self.height,
            "config_root": roots.config_root,
            "scope_root": roots.scope_root,
            "spec_root": roots.spec_root,
            "observation_root": roots.observation_root,
            "receipt_root": roots.receipt_root,
            "violation_root": roots.violation_root,
            "remediation_root": roots.remediation_root,
            "assurance_report_root": roots.assurance_report_root,
            "counters": self.counters().public_record(),
        });
        roots.state_root = protocol_invariants_state_root_from_record(&state_record);
        roots
    }

    fn roots_without_state(&self) -> ProtocolInvariantsRoots {
        let config_root = self.config.config_root();
        let scope_root = merkle_root(
            "PROTOCOL-INVARIANTS-SCOPES",
            &self
                .scopes
                .values()
                .map(InvariantScope::public_record)
                .collect::<Vec<_>>(),
        );
        let spec_root = merkle_root(
            "PROTOCOL-INVARIANTS-SPECS",
            &self
                .specs
                .values()
                .map(ProtocolInvariantSpec::public_record)
                .collect::<Vec<_>>(),
        );
        let observation_root = merkle_root(
            "PROTOCOL-INVARIANTS-OBSERVATIONS",
            &self
                .observations
                .values()
                .map(InvariantObservation::public_record)
                .collect::<Vec<_>>(),
        );
        let receipt_root = merkle_root(
            "PROTOCOL-INVARIANTS-RECEIPTS",
            &self
                .receipts
                .values()
                .map(InvariantEvaluationReceipt::public_record)
                .collect::<Vec<_>>(),
        );
        let violation_root = merkle_root(
            "PROTOCOL-INVARIANTS-VIOLATIONS",
            &self
                .violations
                .values()
                .map(InvariantViolation::public_record)
                .collect::<Vec<_>>(),
        );
        let remediation_root = merkle_root(
            "PROTOCOL-INVARIANTS-REMEDIATIONS",
            &self
                .remediations
                .values()
                .map(InvariantRemediationPlan::public_record)
                .collect::<Vec<_>>(),
        );
        let assurance_report_root = merkle_root(
            "PROTOCOL-INVARIANTS-ASSURANCE-REPORTS",
            &self
                .assurance_reports
                .values()
                .map(InvariantAssuranceReport::public_record)
                .collect::<Vec<_>>(),
        );
        ProtocolInvariantsRoots {
            config_root,
            scope_root,
            spec_root,
            observation_root,
            receipt_root,
            violation_root,
            remediation_root,
            assurance_report_root,
            state_root: String::new(),
        }
    }

    pub fn counters(&self) -> ProtocolInvariantsCounters {
        let receipts = self.receipts.values().collect::<Vec<_>>();
        let passed_receipts = receipts
            .iter()
            .filter(|receipt| receipt.status == InvariantEvaluationStatus::Passed)
            .count() as u64;
        let failed_receipts = receipts
            .iter()
            .filter(|receipt| receipt.status == InvariantEvaluationStatus::Failed)
            .count() as u64;
        let critical_receipts = receipts
            .iter()
            .filter(|receipt| receipt.severity.is_critical())
            .collect::<Vec<_>>();
        let critical_passed = critical_receipts
            .iter()
            .filter(|receipt| receipt.status == InvariantEvaluationStatus::Passed)
            .count() as u64;
        let open_violations = self
            .violations
            .values()
            .filter(|violation| violation.status.is_open())
            .count() as u64;
        let critical_open_violations = self
            .violations
            .values()
            .filter(|violation| violation.status.is_open() && violation.severity.is_critical())
            .count() as u64;
        let completed_remediations = self
            .remediations
            .values()
            .filter(|plan| plan.completed)
            .count() as u64;
        ProtocolInvariantsCounters {
            scopes: self.scopes.len() as u64,
            specs: self.specs.len() as u64,
            observations: self.observations.len() as u64,
            receipts: self.receipts.len() as u64,
            passed_receipts,
            failed_receipts,
            open_violations,
            critical_open_violations,
            remediation_plans: self.remediations.len() as u64,
            completed_remediations,
            assurance_reports: self.assurance_reports.len() as u64,
            pass_rate_bps: ratio_bps(passed_receipts, receipts.len() as u64),
            critical_pass_rate_bps: ratio_bps(critical_passed, critical_receipts.len() as u64),
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "protocol_invariants_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_INVARIANTS_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "scopes": self.scopes.values().map(InvariantScope::public_record).collect::<Vec<_>>(),
            "specs": self.specs.values().map(ProtocolInvariantSpec::public_record).collect::<Vec<_>>(),
            "observations": self.observations.values().map(InvariantObservation::public_record).collect::<Vec<_>>(),
            "receipts": self.receipts.values().map(InvariantEvaluationReceipt::public_record).collect::<Vec<_>>(),
            "violations": self.violations.values().map(InvariantViolation::public_record).collect::<Vec<_>>(),
            "remediations": self.remediations.values().map(InvariantRemediationPlan::public_record).collect::<Vec<_>>(),
            "assurance_reports": self.assurance_reports.values().map(InvariantAssuranceReport::public_record).collect::<Vec<_>>(),
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
            "state_root": roots.state_root,
        })
    }

    pub fn validate(&self) -> ProtocolInvariantsResult<String> {
        self.config.validate()?;
        if self.scopes.len() > PROTOCOL_INVARIANTS_MAX_SPECS {
            return Err("protocol invariant scope count exceeds limit".to_string());
        }
        if self.specs.len() > PROTOCOL_INVARIANTS_MAX_SPECS {
            return Err("protocol invariant spec count exceeds limit".to_string());
        }
        if self.observations.len() > PROTOCOL_INVARIANTS_MAX_OBSERVATIONS {
            return Err("protocol invariant observation count exceeds limit".to_string());
        }
        if self.receipts.len() > PROTOCOL_INVARIANTS_MAX_RECEIPTS {
            return Err("protocol invariant receipt count exceeds limit".to_string());
        }
        if self.violations.len() > PROTOCOL_INVARIANTS_MAX_VIOLATIONS {
            return Err("protocol invariant violation count exceeds limit".to_string());
        }
        if self.remediations.len() > PROTOCOL_INVARIANTS_MAX_REMEDIATIONS {
            return Err("protocol invariant remediation count exceeds limit".to_string());
        }
        if self.assurance_reports.len() > PROTOCOL_INVARIANTS_MAX_REPORTS {
            return Err("protocol invariant assurance report count exceeds limit".to_string());
        }
        for scope in self.scopes.values() {
            scope.validate()?;
        }
        for spec in self.specs.values() {
            spec.validate()?;
            for scope_id in &spec.scope_ids {
                if !self.scopes.contains_key(scope_id) {
                    return Err("protocol invariant spec references missing scope".to_string());
                }
            }
        }
        for observation in self.observations.values() {
            observation.validate()?;
            if !self.specs.contains_key(&observation.spec_id) {
                return Err("protocol invariant observation references missing spec".to_string());
            }
            if !self.scopes.contains_key(&observation.scope_id) {
                return Err("protocol invariant observation references missing scope".to_string());
            }
        }
        for receipt in self.receipts.values() {
            receipt.validate()?;
            if !self.specs.contains_key(&receipt.spec_id) {
                return Err("protocol invariant receipt references missing spec".to_string());
            }
            if !self.observations.contains_key(&receipt.observation_id) {
                return Err("protocol invariant receipt references missing observation".to_string());
            }
        }
        for violation in self.violations.values() {
            violation.validate()?;
            if !self.specs.contains_key(&violation.spec_id) {
                return Err("protocol invariant violation references missing spec".to_string());
            }
            if !self.receipts.contains_key(&violation.receipt_id) {
                return Err("protocol invariant violation references missing receipt".to_string());
            }
        }
        for remediation in self.remediations.values() {
            remediation.validate()?;
            if !self.violations.contains_key(&remediation.violation_id) {
                return Err(
                    "protocol invariant remediation references missing violation".to_string(),
                );
            }
        }
        for report in self.assurance_reports.values() {
            report.validate()?;
        }
        let counters = self.counters();
        if counters.critical_open_violations > self.config.max_open_critical {
            return Err("protocol invariant critical open violation budget exceeded".to_string());
        }
        Ok(self.state_root())
    }
}

pub fn protocol_invariants_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PROTOCOL-INVARIANTS-STATE-ROOT",
        &[
            HashPart::Str(PROTOCOL_INVARIANTS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn protocol_invariants_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_INVARIANTS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn protocol_invariants_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_INVARIANTS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn protocol_invariants_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| Value::String(protocol_invariants_string_root(domain, value)))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn protocol_invariants_config_id(record: &Value) -> String {
    protocol_invariants_payload_root("PROTOCOL-INVARIANTS-CONFIG-ID", record)
}

pub fn protocol_invariants_scope_id(
    domain: InvariantDomain,
    component: &str,
    state_root: &str,
    critical: bool,
    label_root: &str,
) -> String {
    domain_hash(
        "PROTOCOL-INVARIANTS-SCOPE-ID",
        &[
            HashPart::Str(PROTOCOL_INVARIANTS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain.as_str()),
            HashPart::Str(component),
            HashPart::Str(state_root),
            HashPart::Str(if critical { "critical" } else { "standard" }),
            HashPart::Str(label_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn protocol_invariants_spec_id(
    domain: InvariantDomain,
    kind: InvariantKind,
    severity: InvariantSeverity,
    label: &str,
    statement_root: &str,
    parameter_root: &str,
    scope_root: &str,
    active_from_height: u64,
    active_until_height: u64,
    required_pass_rate_bps: u64,
    remediation_kind: RemediationKind,
) -> String {
    domain_hash(
        "PROTOCOL-INVARIANTS-SPEC-ID",
        &[
            HashPart::Str(PROTOCOL_INVARIANTS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain.as_str()),
            HashPart::Str(kind.as_str()),
            HashPart::Str(severity.as_str()),
            HashPart::Str(label),
            HashPart::Str(statement_root),
            HashPart::Str(parameter_root),
            HashPart::Str(scope_root),
            HashPart::Int(active_from_height as i128),
            HashPart::Int(active_until_height as i128),
            HashPart::Int(required_pass_rate_bps as i128),
            HashPart::Str(remediation_kind.as_str()),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn protocol_invariants_observation_id(
    spec_id: &str,
    scope_id: &str,
    height: u64,
    observed_root: &str,
    expected_root: &str,
    metric_name: &str,
    metric_value: u64,
    threshold_value: u64,
    pq_attestation_root: &str,
    disclosure_root: &str,
) -> String {
    domain_hash(
        "PROTOCOL-INVARIANTS-OBSERVATION-ID",
        &[
            HashPart::Str(PROTOCOL_INVARIANTS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(spec_id),
            HashPart::Str(scope_id),
            HashPart::Int(height as i128),
            HashPart::Str(observed_root),
            HashPart::Str(expected_root),
            HashPart::Str(metric_name),
            HashPart::Int(metric_value as i128),
            HashPart::Int(threshold_value as i128),
            HashPart::Str(pq_attestation_root),
            HashPart::Str(disclosure_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn protocol_invariants_receipt_id(
    spec_id: &str,
    observation_id: &str,
    height: u64,
    status: InvariantEvaluationStatus,
    severity: InvariantSeverity,
    evaluator_commitment: &str,
    evaluation_root: &str,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "PROTOCOL-INVARIANTS-RECEIPT-ID",
        &[
            HashPart::Str(PROTOCOL_INVARIANTS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(spec_id),
            HashPart::Str(observation_id),
            HashPart::Int(height as i128),
            HashPart::Str(status.as_str()),
            HashPart::Str(severity.as_str()),
            HashPart::Str(evaluator_commitment),
            HashPart::Str(evaluation_root),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn protocol_invariants_violation_id(
    spec_id: &str,
    receipt_id: &str,
    severity: InvariantSeverity,
    opened_at_height: u64,
    last_seen_height: u64,
    status: InvariantViolationStatus,
    evidence_root: &str,
    affected_scope_root: &str,
    remediation_kind: RemediationKind,
) -> String {
    domain_hash(
        "PROTOCOL-INVARIANTS-VIOLATION-ID",
        &[
            HashPart::Str(PROTOCOL_INVARIANTS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(spec_id),
            HashPart::Str(receipt_id),
            HashPart::Str(severity.as_str()),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(last_seen_height as i128),
            HashPart::Str(status.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Str(affected_scope_root),
            HashPart::Str(remediation_kind.as_str()),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn protocol_invariants_remediation_plan_id(
    violation_id: &str,
    remediation_kind: RemediationKind,
    owner_commitment: &str,
    action_root: &str,
    created_at_height: u64,
    expires_at_height: u64,
    completed: bool,
) -> String {
    domain_hash(
        "PROTOCOL-INVARIANTS-REMEDIATION-ID",
        &[
            HashPart::Str(PROTOCOL_INVARIANTS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(violation_id),
            HashPart::Str(remediation_kind.as_str()),
            HashPart::Str(owner_commitment),
            HashPart::Str(action_root),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Str(if completed { "completed" } else { "open" }),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn protocol_invariants_assurance_report_id(
    start_height: u64,
    end_height: u64,
    spec_root: &str,
    receipt_root: &str,
    violation_root: &str,
    remediation_root: &str,
    pass_rate_bps: u64,
    critical_pass_rate_bps: u64,
    open_critical_count: u64,
    assurance_root: &str,
) -> String {
    domain_hash(
        "PROTOCOL-INVARIANTS-ASSURANCE-REPORT-ID",
        &[
            HashPart::Str(PROTOCOL_INVARIANTS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
            HashPart::Str(spec_root),
            HashPart::Str(receipt_root),
            HashPart::Str(violation_root),
            HashPart::Str(remediation_root),
            HashPart::Int(pass_rate_bps as i128),
            HashPart::Int(critical_pass_rate_bps as i128),
            HashPart::Int(open_critical_count as i128),
            HashPart::Str(assurance_root),
        ],
        32,
    )
}

pub fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        PROTOCOL_INVARIANTS_MAX_BPS
    } else {
        numerator.saturating_mul(PROTOCOL_INVARIANTS_MAX_BPS) / denominator
    }
}

fn ensure_non_empty(value: &str, label: &str) -> ProtocolInvariantsResult<()> {
    if value.is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> ProtocolInvariantsResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn validate_bps(value: u64, label: &str) -> ProtocolInvariantsResult<()> {
    if value > PROTOCOL_INVARIANTS_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}
