use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type L2ProtocolCohesionMatrixResult<T> = Result<T, String>;

pub const L2_PROTOCOL_COHESION_MATRIX_PROTOCOL_VERSION: &str =
    "nebula-l2-protocol-cohesion-matrix-v1";
pub const L2_PROTOCOL_COHESION_MATRIX_DEFAULT_GATE_TTL_BLOCKS: u64 = 288;
pub const L2_PROTOCOL_COHESION_MATRIX_DEFAULT_OBSERVATION_TTL_BLOCKS: u64 = 96;
pub const L2_PROTOCOL_COHESION_MATRIX_DEFAULT_REMEDIATION_TTL_BLOCKS: u64 = 720;
pub const L2_PROTOCOL_COHESION_MATRIX_DEFAULT_MIN_COHESION_SCORE_BPS: u64 = 9_300;
pub const L2_PROTOCOL_COHESION_MATRIX_DEFAULT_MIN_CRITICAL_SCORE_BPS: u64 = 10_000;
pub const L2_PROTOCOL_COHESION_MATRIX_DEFAULT_MAX_OPEN_BLOCKERS: u64 = 0;
pub const L2_PROTOCOL_COHESION_MATRIX_MAX_BPS: u64 = 10_000;
pub const L2_PROTOCOL_COHESION_MATRIX_MAX_SUBSYSTEMS: usize = 128;
pub const L2_PROTOCOL_COHESION_MATRIX_MAX_EDGES: usize = 1_024;
pub const L2_PROTOCOL_COHESION_MATRIX_MAX_GATES: usize = 1_024;
pub const L2_PROTOCOL_COHESION_MATRIX_MAX_OBSERVATIONS: usize = 2_048;
pub const L2_PROTOCOL_COHESION_MATRIX_MAX_RECEIPTS: usize = 1_024;
pub const L2_PROTOCOL_COHESION_MATRIX_MAX_SNAPSHOTS: usize = 256;
pub const L2_PROTOCOL_COHESION_MATRIX_DEVNET_HEIGHT: u64 = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CohesionSubsystem {
    MoneroBridge,
    PqAuth,
    PrivateContracts,
    PrivateDefi,
    LowFeeLanes,
    PrivacyBudgets,
    ProofMarkets,
    OperatorReadiness,
    StateRoots,
    DataAvailability,
    Sequencing,
    Governance,
}

impl CohesionSubsystem {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroBridge => "monero_bridge",
            Self::PqAuth => "pq_auth",
            Self::PrivateContracts => "private_contracts",
            Self::PrivateDefi => "private_defi",
            Self::LowFeeLanes => "low_fee_lanes",
            Self::PrivacyBudgets => "privacy_budgets",
            Self::ProofMarkets => "proof_markets",
            Self::OperatorReadiness => "operator_readiness",
            Self::StateRoots => "state_roots",
            Self::DataAvailability => "data_availability",
            Self::Sequencing => "sequencing",
            Self::Governance => "governance",
        }
    }

    pub fn critical(self) -> bool {
        matches!(
            self,
            Self::MoneroBridge
                | Self::PqAuth
                | Self::PrivacyBudgets
                | Self::ProofMarkets
                | Self::OperatorReadiness
                | Self::StateRoots
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CohesionEdgeKind {
    StateDependency,
    AuthDependency,
    LiquidityDependency,
    PrivacyDependency,
    FeeDependency,
    ProofDependency,
    OperatorDependency,
    EmergencyDependency,
    DataDependency,
    GovernanceDependency,
}

impl CohesionEdgeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StateDependency => "state_dependency",
            Self::AuthDependency => "auth_dependency",
            Self::LiquidityDependency => "liquidity_dependency",
            Self::PrivacyDependency => "privacy_dependency",
            Self::FeeDependency => "fee_dependency",
            Self::ProofDependency => "proof_dependency",
            Self::OperatorDependency => "operator_dependency",
            Self::EmergencyDependency => "emergency_dependency",
            Self::DataDependency => "data_dependency",
            Self::GovernanceDependency => "governance_dependency",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CohesionSeverity {
    Informational,
    Required,
    Critical,
    Blocker,
}

impl CohesionSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Required => "required",
            Self::Critical => "critical",
            Self::Blocker => "blocker",
        }
    }

    pub fn weight_bps(self) -> u64 {
        match self {
            Self::Informational => 1_000,
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
pub enum CohesionStatus {
    Draft,
    Active,
    Passing,
    Degraded,
    Blocked,
    Waived,
    Retired,
}

impl CohesionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Passing => "passing",
            Self::Degraded => "degraded",
            Self::Blocked => "blocked",
            Self::Waived => "waived",
            Self::Retired => "retired",
        }
    }

    pub fn passing(self) -> bool {
        matches!(self, Self::Passing | Self::Waived | Self::Retired)
    }

    pub fn open(self) -> bool {
        matches!(
            self,
            Self::Draft | Self::Active | Self::Degraded | Self::Blocked
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CohesionObservationKind {
    RootMatch,
    RootDrift,
    GateSatisfied,
    GateMissing,
    LatencyWithinBudget,
    LatencyOverBudget,
    PrivacyBudgetWithinLimit,
    PrivacyBudgetExceeded,
    LiquidityHealthy,
    LiquidityFragmented,
    OperatorReady,
    OperatorActionNeeded,
}

impl CohesionObservationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RootMatch => "root_match",
            Self::RootDrift => "root_drift",
            Self::GateSatisfied => "gate_satisfied",
            Self::GateMissing => "gate_missing",
            Self::LatencyWithinBudget => "latency_within_budget",
            Self::LatencyOverBudget => "latency_over_budget",
            Self::PrivacyBudgetWithinLimit => "privacy_budget_within_limit",
            Self::PrivacyBudgetExceeded => "privacy_budget_exceeded",
            Self::LiquidityHealthy => "liquidity_healthy",
            Self::LiquidityFragmented => "liquidity_fragmented",
            Self::OperatorReady => "operator_ready",
            Self::OperatorActionNeeded => "operator_action_needed",
        }
    }

    pub fn passing(self) -> bool {
        matches!(
            self,
            Self::RootMatch
                | Self::GateSatisfied
                | Self::LatencyWithinBudget
                | Self::PrivacyBudgetWithinLimit
                | Self::LiquidityHealthy
                | Self::OperatorReady
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CohesionRemediationKind {
    RotatePqAuthority,
    PauseBridgeExit,
    RepriceLowFeeLane,
    RebuildPrivateContractWitness,
    RaisePrivacyBudgetDeposit,
    RebidProofMarket,
    RefreshOperatorRunbook,
    ReanchorStateRoot,
    AddDataAvailabilityReplica,
    GovernanceReview,
}

impl CohesionRemediationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RotatePqAuthority => "rotate_pq_authority",
            Self::PauseBridgeExit => "pause_bridge_exit",
            Self::RepriceLowFeeLane => "reprice_low_fee_lane",
            Self::RebuildPrivateContractWitness => "rebuild_private_contract_witness",
            Self::RaisePrivacyBudgetDeposit => "raise_privacy_budget_deposit",
            Self::RebidProofMarket => "rebid_proof_market",
            Self::RefreshOperatorRunbook => "refresh_operator_runbook",
            Self::ReanchorStateRoot => "reanchor_state_root",
            Self::AddDataAvailabilityReplica => "add_data_availability_replica",
            Self::GovernanceReview => "governance_review",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub config_id: String,
    pub gate_ttl_blocks: u64,
    pub observation_ttl_blocks: u64,
    pub remediation_ttl_blocks: u64,
    pub min_cohesion_score_bps: u64,
    pub min_critical_score_bps: u64,
    pub max_open_blockers: u64,
    pub require_monero_pq_bridge_gate: bool,
    pub require_private_contract_defi_gate: bool,
    pub require_low_fee_privacy_gate: bool,
    pub require_operator_state_root_gate: bool,
}

impl Config {
    pub fn devnet() -> Self {
        let payload = json!({
            "gate_ttl_blocks": L2_PROTOCOL_COHESION_MATRIX_DEFAULT_GATE_TTL_BLOCKS,
            "observation_ttl_blocks": L2_PROTOCOL_COHESION_MATRIX_DEFAULT_OBSERVATION_TTL_BLOCKS,
            "remediation_ttl_blocks": L2_PROTOCOL_COHESION_MATRIX_DEFAULT_REMEDIATION_TTL_BLOCKS,
            "min_cohesion_score_bps": L2_PROTOCOL_COHESION_MATRIX_DEFAULT_MIN_COHESION_SCORE_BPS,
            "min_critical_score_bps": L2_PROTOCOL_COHESION_MATRIX_DEFAULT_MIN_CRITICAL_SCORE_BPS,
            "max_open_blockers": L2_PROTOCOL_COHESION_MATRIX_DEFAULT_MAX_OPEN_BLOCKERS,
            "required_gates": [
                "monero_pq_bridge",
                "private_contract_defi",
                "low_fee_privacy",
                "operator_state_root"
            ]
        });
        Self {
            config_id: payload_root("L2-PROTOCOL-COHESION-MATRIX-CONFIG-ID", &payload),
            gate_ttl_blocks: L2_PROTOCOL_COHESION_MATRIX_DEFAULT_GATE_TTL_BLOCKS,
            observation_ttl_blocks: L2_PROTOCOL_COHESION_MATRIX_DEFAULT_OBSERVATION_TTL_BLOCKS,
            remediation_ttl_blocks: L2_PROTOCOL_COHESION_MATRIX_DEFAULT_REMEDIATION_TTL_BLOCKS,
            min_cohesion_score_bps: L2_PROTOCOL_COHESION_MATRIX_DEFAULT_MIN_COHESION_SCORE_BPS,
            min_critical_score_bps: L2_PROTOCOL_COHESION_MATRIX_DEFAULT_MIN_CRITICAL_SCORE_BPS,
            max_open_blockers: L2_PROTOCOL_COHESION_MATRIX_DEFAULT_MAX_OPEN_BLOCKERS,
            require_monero_pq_bridge_gate: true,
            require_private_contract_defi_gate: true,
            require_low_fee_privacy_gate: true,
            require_operator_state_root_gate: true,
        }
    }

    pub fn validate(&self) -> L2ProtocolCohesionMatrixResult<()> {
        ensure_non_empty(&self.config_id, "config_id")?;
        ensure_positive(self.gate_ttl_blocks, "gate_ttl_blocks")?;
        ensure_positive(self.observation_ttl_blocks, "observation_ttl_blocks")?;
        ensure_positive(self.remediation_ttl_blocks, "remediation_ttl_blocks")?;
        validate_bps(self.min_cohesion_score_bps, "min_cohesion_score_bps")?;
        validate_bps(self.min_critical_score_bps, "min_critical_score_bps")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_id": self.config_id,
            "gate_ttl_blocks": self.gate_ttl_blocks,
            "observation_ttl_blocks": self.observation_ttl_blocks,
            "remediation_ttl_blocks": self.remediation_ttl_blocks,
            "min_cohesion_score_bps": self.min_cohesion_score_bps,
            "min_critical_score_bps": self.min_critical_score_bps,
            "max_open_blockers": self.max_open_blockers,
            "require_monero_pq_bridge_gate": self.require_monero_pq_bridge_gate,
            "require_private_contract_defi_gate": self.require_private_contract_defi_gate,
            "require_low_fee_privacy_gate": self.require_low_fee_privacy_gate,
            "require_operator_state_root_gate": self.require_operator_state_root_gate
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubsystemNode {
    pub subsystem_id: String,
    pub subsystem: CohesionSubsystem,
    pub label: String,
    pub owner_commitment: String,
    pub code_root: String,
    pub state_root: String,
    pub readiness_root: String,
    pub status: CohesionStatus,
}

impl SubsystemNode {
    pub fn new(
        subsystem: CohesionSubsystem,
        label: &str,
        owner_commitment: &str,
        code_root: &str,
        state_root: &str,
        readiness_root: &str,
        status: CohesionStatus,
    ) -> Self {
        let subsystem_id = subsystem_id(
            subsystem,
            label,
            owner_commitment,
            code_root,
            state_root,
            readiness_root,
            status,
        );
        Self {
            subsystem_id,
            subsystem,
            label: label.to_string(),
            owner_commitment: owner_commitment.to_string(),
            code_root: code_root.to_string(),
            state_root: state_root.to_string(),
            readiness_root: readiness_root.to_string(),
            status,
        }
    }

    pub fn validate(&self) -> L2ProtocolCohesionMatrixResult<()> {
        ensure_non_empty(&self.subsystem_id, "subsystem_id")?;
        ensure_non_empty(&self.label, "subsystem label")?;
        ensure_non_empty(&self.owner_commitment, "owner_commitment")?;
        ensure_non_empty(&self.code_root, "code_root")?;
        ensure_non_empty(&self.state_root, "state_root")?;
        ensure_non_empty(&self.readiness_root, "readiness_root")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "subsystem_id": self.subsystem_id,
            "subsystem": self.subsystem.as_str(),
            "label": self.label,
            "owner_commitment": self.owner_commitment,
            "code_root": self.code_root,
            "state_root": self.state_root,
            "readiness_root": self.readiness_root,
            "status": self.status.as_str(),
            "critical": self.subsystem.critical()
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityEdge {
    pub edge_id: String,
    pub from_subsystem_id: String,
    pub to_subsystem_id: String,
    pub edge_kind: CohesionEdgeKind,
    pub severity: CohesionSeverity,
    pub compatibility_root: String,
    pub dependency_root: String,
    pub status: CohesionStatus,
    pub opened_at_height: u64,
    pub due_height: u64,
}

impl CompatibilityEdge {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        from_subsystem_id: &str,
        to_subsystem_id: &str,
        edge_kind: CohesionEdgeKind,
        severity: CohesionSeverity,
        compatibility_root: &str,
        dependency_root: &str,
        status: CohesionStatus,
        opened_at_height: u64,
        due_height: u64,
    ) -> Self {
        let edge_id = edge_id(
            from_subsystem_id,
            to_subsystem_id,
            edge_kind,
            severity,
            compatibility_root,
            dependency_root,
            status,
            opened_at_height,
            due_height,
        );
        Self {
            edge_id,
            from_subsystem_id: from_subsystem_id.to_string(),
            to_subsystem_id: to_subsystem_id.to_string(),
            edge_kind,
            severity,
            compatibility_root: compatibility_root.to_string(),
            dependency_root: dependency_root.to_string(),
            status,
            opened_at_height,
            due_height,
        }
    }

    pub fn validate(&self) -> L2ProtocolCohesionMatrixResult<()> {
        ensure_non_empty(&self.edge_id, "edge_id")?;
        ensure_non_empty(&self.from_subsystem_id, "from_subsystem_id")?;
        ensure_non_empty(&self.to_subsystem_id, "to_subsystem_id")?;
        ensure_non_empty(&self.compatibility_root, "compatibility_root")?;
        ensure_non_empty(&self.dependency_root, "dependency_root")?;
        if self.from_subsystem_id == self.to_subsystem_id {
            return Err("compatibility edge must connect distinct subsystems".to_string());
        }
        if self.due_height < self.opened_at_height {
            return Err("compatibility edge due height precedes opened height".to_string());
        }
        Ok(())
    }

    pub fn blocking(&self) -> bool {
        self.severity.blocks_release() && self.status.open()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "edge_id": self.edge_id,
            "from_subsystem_id": self.from_subsystem_id,
            "to_subsystem_id": self.to_subsystem_id,
            "edge_kind": self.edge_kind.as_str(),
            "severity": self.severity.as_str(),
            "compatibility_root": self.compatibility_root,
            "dependency_root": self.dependency_root,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "due_height": self.due_height,
            "blocking": self.blocking()
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyGate {
    pub gate_id: String,
    pub edge_id: String,
    pub required_subsystem_id: String,
    pub gate_label: String,
    pub required_root: String,
    pub evidence_root: String,
    pub severity: CohesionSeverity,
    pub status: CohesionStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl DependencyGate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        edge_id: &str,
        required_subsystem_id: &str,
        gate_label: &str,
        required_root: &str,
        evidence_root: &str,
        severity: CohesionSeverity,
        status: CohesionStatus,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> Self {
        let gate_id = gate_id(
            edge_id,
            required_subsystem_id,
            gate_label,
            required_root,
            evidence_root,
            severity,
            status,
            opened_at_height,
            expires_at_height,
        );
        Self {
            gate_id,
            edge_id: edge_id.to_string(),
            required_subsystem_id: required_subsystem_id.to_string(),
            gate_label: gate_label.to_string(),
            required_root: required_root.to_string(),
            evidence_root: evidence_root.to_string(),
            severity,
            status,
            opened_at_height,
            expires_at_height,
        }
    }

    pub fn validate(&self) -> L2ProtocolCohesionMatrixResult<()> {
        ensure_non_empty(&self.gate_id, "gate_id")?;
        ensure_non_empty(&self.edge_id, "edge_id")?;
        ensure_non_empty(&self.required_subsystem_id, "required_subsystem_id")?;
        ensure_non_empty(&self.gate_label, "gate_label")?;
        ensure_non_empty(&self.required_root, "required_root")?;
        ensure_non_empty(&self.evidence_root, "evidence_root")?;
        if self.expires_at_height < self.opened_at_height {
            return Err("dependency gate expiry precedes opened height".to_string());
        }
        Ok(())
    }

    pub fn blocking(&self) -> bool {
        self.severity.blocks_release() && self.status.open()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "gate_id": self.gate_id,
            "edge_id": self.edge_id,
            "required_subsystem_id": self.required_subsystem_id,
            "gate_label": self.gate_label,
            "required_root": self.required_root,
            "evidence_root": self.evidence_root,
            "severity": self.severity.as_str(),
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "blocking": self.blocking()
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantObservation {
    pub observation_id: String,
    pub subsystem_id: String,
    pub edge_id: String,
    pub observation_kind: CohesionObservationKind,
    pub signal_root: String,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
    pub severity: CohesionSeverity,
    pub status: CohesionStatus,
}

impl InvariantObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subsystem_id: &str,
        edge_id: &str,
        observation_kind: CohesionObservationKind,
        signal_root: &str,
        observed_at_height: u64,
        expires_at_height: u64,
        severity: CohesionSeverity,
        status: CohesionStatus,
    ) -> Self {
        let observation_id = observation_id(
            subsystem_id,
            edge_id,
            observation_kind,
            signal_root,
            observed_at_height,
            expires_at_height,
            severity,
            status,
        );
        Self {
            observation_id,
            subsystem_id: subsystem_id.to_string(),
            edge_id: edge_id.to_string(),
            observation_kind,
            signal_root: signal_root.to_string(),
            observed_at_height,
            expires_at_height,
            severity,
            status,
        }
    }

    pub fn validate(&self) -> L2ProtocolCohesionMatrixResult<()> {
        ensure_non_empty(&self.observation_id, "observation_id")?;
        ensure_non_empty(&self.subsystem_id, "subsystem_id")?;
        ensure_non_empty(&self.edge_id, "edge_id")?;
        ensure_non_empty(&self.signal_root, "signal_root")?;
        if self.expires_at_height < self.observed_at_height {
            return Err("observation expiry precedes observed height".to_string());
        }
        Ok(())
    }

    pub fn passing(&self) -> bool {
        self.observation_kind.passing() && self.status.passing()
    }

    pub fn blocking(&self) -> bool {
        self.severity.blocks_release() && !self.passing()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "subsystem_id": self.subsystem_id,
            "edge_id": self.edge_id,
            "observation_kind": self.observation_kind.as_str(),
            "signal_root": self.signal_root,
            "observed_at_height": self.observed_at_height,
            "expires_at_height": self.expires_at_height,
            "severity": self.severity.as_str(),
            "status": self.status.as_str(),
            "passing": self.passing(),
            "blocking": self.blocking()
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationReceipt {
    pub receipt_id: String,
    pub observation_id: String,
    pub gate_id: String,
    pub remediation_kind: CohesionRemediationKind,
    pub operator_commitment: String,
    pub action_root: String,
    pub result_root: String,
    pub submitted_at_height: u64,
    pub accepted: bool,
}

impl RemediationReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        observation_id: &str,
        gate_id: &str,
        remediation_kind: CohesionRemediationKind,
        operator_commitment: &str,
        action_root: &str,
        result_root: &str,
        submitted_at_height: u64,
        accepted: bool,
    ) -> Self {
        let receipt_id = receipt_id(
            observation_id,
            gate_id,
            remediation_kind,
            operator_commitment,
            action_root,
            result_root,
            submitted_at_height,
            accepted,
        );
        Self {
            receipt_id,
            observation_id: observation_id.to_string(),
            gate_id: gate_id.to_string(),
            remediation_kind,
            operator_commitment: operator_commitment.to_string(),
            action_root: action_root.to_string(),
            result_root: result_root.to_string(),
            submitted_at_height,
            accepted,
        }
    }

    pub fn validate(&self) -> L2ProtocolCohesionMatrixResult<()> {
        ensure_non_empty(&self.receipt_id, "receipt_id")?;
        ensure_non_empty(&self.observation_id, "observation_id")?;
        ensure_non_empty(&self.gate_id, "gate_id")?;
        ensure_non_empty(&self.operator_commitment, "operator_commitment")?;
        ensure_non_empty(&self.action_root, "action_root")?;
        ensure_non_empty(&self.result_root, "result_root")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "observation_id": self.observation_id,
            "gate_id": self.gate_id,
            "remediation_kind": self.remediation_kind.as_str(),
            "operator_commitment": self.operator_commitment,
            "action_root": self.action_root,
            "result_root": self.result_root,
            "submitted_at_height": self.submitted_at_height,
            "accepted": self.accepted
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CohesionSnapshot {
    pub snapshot_id: String,
    pub height: u64,
    pub subsystem_root: String,
    pub edge_root: String,
    pub gate_root: String,
    pub observation_root: String,
    pub receipt_root: String,
    pub cohesion_score_bps: u64,
    pub critical_score_bps: u64,
    pub open_blockers: u64,
}

impl CohesionSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        height: u64,
        subsystem_root: &str,
        edge_root: &str,
        gate_root: &str,
        observation_root: &str,
        receipt_root: &str,
        cohesion_score_bps: u64,
        critical_score_bps: u64,
        open_blockers: u64,
    ) -> Self {
        let snapshot_id = snapshot_id(
            height,
            subsystem_root,
            edge_root,
            gate_root,
            observation_root,
            receipt_root,
            cohesion_score_bps,
            critical_score_bps,
            open_blockers,
        );
        Self {
            snapshot_id,
            height,
            subsystem_root: subsystem_root.to_string(),
            edge_root: edge_root.to_string(),
            gate_root: gate_root.to_string(),
            observation_root: observation_root.to_string(),
            receipt_root: receipt_root.to_string(),
            cohesion_score_bps,
            critical_score_bps,
            open_blockers,
        }
    }

    pub fn validate(&self) -> L2ProtocolCohesionMatrixResult<()> {
        ensure_non_empty(&self.snapshot_id, "snapshot_id")?;
        ensure_non_empty(&self.subsystem_root, "subsystem_root")?;
        ensure_non_empty(&self.edge_root, "edge_root")?;
        ensure_non_empty(&self.gate_root, "gate_root")?;
        ensure_non_empty(&self.observation_root, "observation_root")?;
        ensure_non_empty(&self.receipt_root, "receipt_root")?;
        validate_bps(self.cohesion_score_bps, "cohesion_score_bps")?;
        validate_bps(self.critical_score_bps, "critical_score_bps")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "height": self.height,
            "subsystem_root": self.subsystem_root,
            "edge_root": self.edge_root,
            "gate_root": self.gate_root,
            "observation_root": self.observation_root,
            "receipt_root": self.receipt_root,
            "cohesion_score_bps": self.cohesion_score_bps,
            "critical_score_bps": self.critical_score_bps,
            "open_blockers": self.open_blockers
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub subsystem_root: String,
    pub edge_root: String,
    pub gate_root: String,
    pub observation_root: String,
    pub receipt_root: String,
    pub snapshot_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "subsystem_root": self.subsystem_root,
            "edge_root": self.edge_root,
            "gate_root": self.gate_root,
            "observation_root": self.observation_root,
            "receipt_root": self.receipt_root,
            "snapshot_root": self.snapshot_root,
            "state_root": self.state_root
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub subsystems: u64,
    pub critical_subsystems: u64,
    pub edges: u64,
    pub dependency_gates: u64,
    pub observations: u64,
    pub passing_observations: u64,
    pub remediation_receipts: u64,
    pub accepted_remediation_receipts: u64,
    pub snapshots: u64,
    pub open_blockers: u64,
    pub cohesion_score_bps: u64,
    pub critical_score_bps: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "subsystems": self.subsystems,
            "critical_subsystems": self.critical_subsystems,
            "edges": self.edges,
            "dependency_gates": self.dependency_gates,
            "observations": self.observations,
            "passing_observations": self.passing_observations,
            "remediation_receipts": self.remediation_receipts,
            "accepted_remediation_receipts": self.accepted_remediation_receipts,
            "snapshots": self.snapshots,
            "open_blockers": self.open_blockers,
            "cohesion_score_bps": self.cohesion_score_bps,
            "critical_score_bps": self.critical_score_bps
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub subsystems: BTreeMap<String, SubsystemNode>,
    pub edges: BTreeMap<String, CompatibilityEdge>,
    pub gates: BTreeMap<String, DependencyGate>,
    pub observations: BTreeMap<String, InvariantObservation>,
    pub receipts: BTreeMap<String, RemediationReceipt>,
    pub snapshots: BTreeMap<String, CohesionSnapshot>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            height: 0,
            config,
            subsystems: BTreeMap::new(),
            edges: BTreeMap::new(),
            gates: BTreeMap::new(),
            observations: BTreeMap::new(),
            receipts: BTreeMap::new(),
            snapshots: BTreeMap::new(),
        }
    }

    pub fn devnet() -> L2ProtocolCohesionMatrixResult<State> {
        let mut state = State::new(Config::devnet());
        state.set_height(L2_PROTOCOL_COHESION_MATRIX_DEVNET_HEIGHT)?;

        let monero = state.insert_subsystem(SubsystemNode::new(
            CohesionSubsystem::MoneroBridge,
            "devnet-monero-private-exit-stack",
            &string_root("COHESION-OWNER", "bridge-ops"),
            &payload_root("COHESION-CODE", &json!({"module": "monero_bridge"})),
            &payload_root(
                "COHESION-STATE",
                &json!({"reserve": "attested", "watchtower": "armed"}),
            ),
            &payload_root("COHESION-READY", &json!({"bridge_audit": "accepted"})),
            CohesionStatus::Passing,
        ))?;
        let pq = state.insert_subsystem(SubsystemNode::new(
            CohesionSubsystem::PqAuth,
            "devnet-pq-authorization-mesh",
            &string_root("COHESION-OWNER", "crypto-ops"),
            &payload_root("COHESION-CODE", &json!({"module": "pq_auth"})),
            &payload_root("COHESION-STATE", &json!({"committee": "rotated"})),
            &payload_root("COHESION-READY", &json!({"ceremony": "sealed"})),
            CohesionStatus::Passing,
        ))?;
        let contracts = state.insert_subsystem(SubsystemNode::new(
            CohesionSubsystem::PrivateContracts,
            "devnet-private-contract-runtime",
            &string_root("COHESION-OWNER", "contract-runtime"),
            &payload_root("COHESION-CODE", &json!({"module": "private_contracts"})),
            &payload_root("COHESION-STATE", &json!({"witness_cache": "hot"})),
            &payload_root("COHESION-READY", &json!({"vm_policy": "accepted"})),
            CohesionStatus::Passing,
        ))?;
        let defi = state.insert_subsystem(SubsystemNode::new(
            CohesionSubsystem::PrivateDefi,
            "devnet-private-defi-router",
            &string_root("COHESION-OWNER", "defi-risk"),
            &payload_root("COHESION-CODE", &json!({"module": "private_defi"})),
            &payload_root("COHESION-STATE", &json!({"solver_set": "bonded"})),
            &payload_root("COHESION-READY", &json!({"economic_review": "accepted"})),
            CohesionStatus::Passing,
        ))?;
        let low_fee = state.insert_subsystem(SubsystemNode::new(
            CohesionSubsystem::LowFeeLanes,
            "devnet-low-fee-private-lanes",
            &string_root("COHESION-OWNER", "fee-ops"),
            &payload_root("COHESION-CODE", &json!({"module": "low_fee_lanes"})),
            &payload_root("COHESION-STATE", &json!({"sponsors": "funded"})),
            &payload_root("COHESION-READY", &json!({"stress_run": "accepted"})),
            CohesionStatus::Passing,
        ))?;
        let privacy = state.insert_subsystem(SubsystemNode::new(
            CohesionSubsystem::PrivacyBudgets,
            "devnet-privacy-budget-ledger",
            &string_root("COHESION-OWNER", "privacy-review"),
            &payload_root("COHESION-CODE", &json!({"module": "privacy_budget"})),
            &payload_root("COHESION-STATE", &json!({"budget_epoch": "balanced"})),
            &payload_root("COHESION-READY", &json!({"privacy_review": "accepted"})),
            CohesionStatus::Passing,
        ))?;
        let proofs = state.insert_subsystem(SubsystemNode::new(
            CohesionSubsystem::ProofMarkets,
            "devnet-recursive-proof-market",
            &string_root("COHESION-OWNER", "prover-market"),
            &payload_root("COHESION-CODE", &json!({"module": "proof_markets"})),
            &payload_root("COHESION-STATE", &json!({"bids": "covered"})),
            &payload_root("COHESION-READY", &json!({"proof_slo": "accepted"})),
            CohesionStatus::Passing,
        ))?;
        let operators = state.insert_subsystem(SubsystemNode::new(
            CohesionSubsystem::OperatorReadiness,
            "devnet-operator-readiness-plane",
            &string_root("COHESION-OWNER", "operator-cell"),
            &payload_root("COHESION-CODE", &json!({"module": "operator_readiness"})),
            &payload_root("COHESION-STATE", &json!({"runbooks": "current"})),
            &payload_root("COHESION-READY", &json!({"incident_drill": "accepted"})),
            CohesionStatus::Passing,
        ))?;
        let roots = state.insert_subsystem(SubsystemNode::new(
            CohesionSubsystem::StateRoots,
            "devnet-state-root-anchor",
            &string_root("COHESION-OWNER", "state-ops"),
            &payload_root("COHESION-CODE", &json!({"module": "state_roots"})),
            &payload_root("COHESION-STATE", &json!({"anchor": "fresh"})),
            &payload_root("COHESION-READY", &json!({"root_policy": "accepted"})),
            CohesionStatus::Passing,
        ))?;

        let edge_specs = vec![
            (
                monero.as_str(),
                pq.as_str(),
                CohesionEdgeKind::AuthDependency,
                CohesionSeverity::Blocker,
                "monero exits require pq withdrawal authority",
            ),
            (
                monero.as_str(),
                privacy.as_str(),
                CohesionEdgeKind::PrivacyDependency,
                CohesionSeverity::Critical,
                "monero bridge withdrawals debit privacy budget ledger",
            ),
            (
                contracts.as_str(),
                defi.as_str(),
                CohesionEdgeKind::StateDependency,
                CohesionSeverity::Critical,
                "private defi routes consume private contract witness roots",
            ),
            (
                low_fee.as_str(),
                privacy.as_str(),
                CohesionEdgeKind::FeeDependency,
                CohesionSeverity::Critical,
                "low fee sponsorship must preserve privacy budget limits",
            ),
            (
                defi.as_str(),
                proofs.as_str(),
                CohesionEdgeKind::ProofDependency,
                CohesionSeverity::Critical,
                "defi settlement requires proof market coverage",
            ),
            (
                operators.as_str(),
                roots.as_str(),
                CohesionEdgeKind::OperatorDependency,
                CohesionSeverity::Blocker,
                "operator readiness must match state root anchor policy",
            ),
            (
                roots.as_str(),
                monero.as_str(),
                CohesionEdgeKind::StateDependency,
                CohesionSeverity::Blocker,
                "bridge reserve root must be included in global state root",
            ),
        ];

        for (from_id, to_id, kind, severity, label) in edge_specs {
            let compatibility = payload_root("COHESION-COMPATIBILITY", &json!({"label": label}));
            let dependency = payload_root(
                "COHESION-DEPENDENCY",
                &json!({"from": from_id, "to": to_id, "kind": kind.as_str()}),
            );
            let edge = state.insert_edge(CompatibilityEdge::new(
                from_id,
                to_id,
                kind,
                severity,
                &compatibility,
                &dependency,
                CohesionStatus::Passing,
                state.height,
                state.height + state.config.gate_ttl_blocks,
            ))?;
            let gate = state.insert_gate(DependencyGate::new(
                edge.as_str(),
                to_id,
                label,
                &dependency,
                &compatibility,
                severity,
                CohesionStatus::Passing,
                state.height,
                state.height + state.config.gate_ttl_blocks,
            ))?;
            let observation = state.insert_observation(InvariantObservation::new(
                to_id,
                edge.as_str(),
                CohesionObservationKind::GateSatisfied,
                &payload_root(
                    "COHESION-OBSERVATION",
                    &json!({"edge": edge, "gate": gate, "status": "passing"}),
                ),
                state.height,
                state.height + state.config.observation_ttl_blocks,
                severity,
                CohesionStatus::Passing,
            ))?;
            state.insert_receipt(RemediationReceipt::new(
                observation.as_str(),
                gate.as_str(),
                remediation_for_edge(kind),
                &string_root("COHESION-OPERATOR", label),
                &payload_root("COHESION-ACTION", &json!({"action": "verified_gate"})),
                &payload_root("COHESION-RESULT", &json!({"result": "accepted"})),
                state.height,
                true,
            ))?;
        }

        let roots_record = state.roots_without_state();
        let counters = state.counters();
        state.insert_snapshot(CohesionSnapshot::new(
            state.height,
            &roots_record.subsystem_root,
            &roots_record.edge_root,
            &roots_record.gate_root,
            &roots_record.observation_root,
            &roots_record.receipt_root,
            counters.cohesion_score_bps,
            counters.critical_score_bps,
            counters.open_blockers,
        ))?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> L2ProtocolCohesionMatrixResult<()> {
        self.height = height;
        Ok(())
    }

    pub fn update_height(&mut self, height: u64) -> L2ProtocolCohesionMatrixResult<()> {
        if height < self.height {
            return Err("height cannot decrease".to_string());
        }
        self.height = height;
        Ok(())
    }

    pub fn insert_subsystem(
        &mut self,
        subsystem: SubsystemNode,
    ) -> L2ProtocolCohesionMatrixResult<String> {
        if self.subsystems.len() >= L2_PROTOCOL_COHESION_MATRIX_MAX_SUBSYSTEMS {
            return Err("too many cohesion subsystems".to_string());
        }
        subsystem.validate()?;
        let id = subsystem.subsystem_id.clone();
        self.subsystems.insert(id.clone(), subsystem);
        Ok(id)
    }

    pub fn insert_edge(
        &mut self,
        edge: CompatibilityEdge,
    ) -> L2ProtocolCohesionMatrixResult<String> {
        if self.edges.len() >= L2_PROTOCOL_COHESION_MATRIX_MAX_EDGES {
            return Err("too many cohesion edges".to_string());
        }
        edge.validate()?;
        if !self.subsystems.contains_key(&edge.from_subsystem_id) {
            return Err("compatibility edge references missing source subsystem".to_string());
        }
        if !self.subsystems.contains_key(&edge.to_subsystem_id) {
            return Err("compatibility edge references missing target subsystem".to_string());
        }
        let id = edge.edge_id.clone();
        self.edges.insert(id.clone(), edge);
        Ok(id)
    }

    pub fn insert_gate(&mut self, gate: DependencyGate) -> L2ProtocolCohesionMatrixResult<String> {
        if self.gates.len() >= L2_PROTOCOL_COHESION_MATRIX_MAX_GATES {
            return Err("too many cohesion dependency gates".to_string());
        }
        gate.validate()?;
        if !self.edges.contains_key(&gate.edge_id) {
            return Err("dependency gate references missing edge".to_string());
        }
        if !self.subsystems.contains_key(&gate.required_subsystem_id) {
            return Err("dependency gate references missing subsystem".to_string());
        }
        let id = gate.gate_id.clone();
        self.gates.insert(id.clone(), gate);
        Ok(id)
    }

    pub fn insert_observation(
        &mut self,
        observation: InvariantObservation,
    ) -> L2ProtocolCohesionMatrixResult<String> {
        if self.observations.len() >= L2_PROTOCOL_COHESION_MATRIX_MAX_OBSERVATIONS {
            return Err("too many cohesion observations".to_string());
        }
        observation.validate()?;
        if !self.subsystems.contains_key(&observation.subsystem_id) {
            return Err("observation references missing subsystem".to_string());
        }
        if !self.edges.contains_key(&observation.edge_id) {
            return Err("observation references missing edge".to_string());
        }
        let id = observation.observation_id.clone();
        self.observations.insert(id.clone(), observation);
        Ok(id)
    }

    pub fn insert_receipt(
        &mut self,
        receipt: RemediationReceipt,
    ) -> L2ProtocolCohesionMatrixResult<String> {
        if self.receipts.len() >= L2_PROTOCOL_COHESION_MATRIX_MAX_RECEIPTS {
            return Err("too many cohesion remediation receipts".to_string());
        }
        receipt.validate()?;
        if !self.observations.contains_key(&receipt.observation_id) {
            return Err("remediation receipt references missing observation".to_string());
        }
        if !self.gates.contains_key(&receipt.gate_id) {
            return Err("remediation receipt references missing gate".to_string());
        }
        let id = receipt.receipt_id.clone();
        self.receipts.insert(id.clone(), receipt);
        Ok(id)
    }

    pub fn insert_snapshot(
        &mut self,
        snapshot: CohesionSnapshot,
    ) -> L2ProtocolCohesionMatrixResult<String> {
        if self.snapshots.len() >= L2_PROTOCOL_COHESION_MATRIX_MAX_SNAPSHOTS {
            return Err("too many cohesion snapshots".to_string());
        }
        snapshot.validate()?;
        let id = snapshot.snapshot_id.clone();
        self.snapshots.insert(id.clone(), snapshot);
        Ok(id)
    }

    pub fn counters(&self) -> Counters {
        let subsystems = to_u64(self.subsystems.len());
        let critical_subsystems = to_u64(
            self.subsystems
                .values()
                .filter(|node| node.subsystem.critical())
                .count(),
        );
        let passing_observations = to_u64(
            self.observations
                .values()
                .filter(|observation| observation.passing())
                .count(),
        );
        let accepted_remediation_receipts = to_u64(
            self.receipts
                .values()
                .filter(|receipt| receipt.accepted)
                .count(),
        );
        let open_blockers = to_u64(
            self.edges.values().filter(|edge| edge.blocking()).count()
                + self.gates.values().filter(|gate| gate.blocking()).count()
                + self
                    .observations
                    .values()
                    .filter(|observation| observation.blocking())
                    .count(),
        );
        let total_checks =
            to_u64(self.edges.len() + self.gates.len() + self.observations.len()).max(1);
        let passing_checks = to_u64(
            self.edges
                .values()
                .filter(|edge| edge.status.passing())
                .count()
                + self
                    .gates
                    .values()
                    .filter(|gate| gate.status.passing())
                    .count()
                + self
                    .observations
                    .values()
                    .filter(|observation| observation.passing())
                    .count(),
        );
        let critical_total = to_u64(
            self.edges
                .values()
                .filter(|edge| edge.severity.blocks_release())
                .count()
                + self
                    .gates
                    .values()
                    .filter(|gate| gate.severity.blocks_release())
                    .count()
                + self
                    .observations
                    .values()
                    .filter(|observation| observation.severity.blocks_release())
                    .count(),
        )
        .max(1);
        let critical_passing = to_u64(
            self.edges
                .values()
                .filter(|edge| edge.severity.blocks_release() && edge.status.passing())
                .count()
                + self
                    .gates
                    .values()
                    .filter(|gate| gate.severity.blocks_release() && gate.status.passing())
                    .count()
                + self
                    .observations
                    .values()
                    .filter(|observation| {
                        observation.severity.blocks_release() && observation.passing()
                    })
                    .count(),
        );
        Counters {
            subsystems,
            critical_subsystems,
            edges: to_u64(self.edges.len()),
            dependency_gates: to_u64(self.gates.len()),
            observations: to_u64(self.observations.len()),
            passing_observations,
            remediation_receipts: to_u64(self.receipts.len()),
            accepted_remediation_receipts,
            snapshots: to_u64(self.snapshots.len()),
            open_blockers,
            cohesion_score_bps: ratio_bps(passing_checks, total_checks),
            critical_score_bps: ratio_bps(critical_passing, critical_total),
        }
    }

    pub fn roots(&self) -> Roots {
        let mut roots = self.roots_without_state();
        let record = json!({
            "height": self.height,
            "config_root": roots.config_root,
            "subsystem_root": roots.subsystem_root,
            "edge_root": roots.edge_root,
            "gate_root": roots.gate_root,
            "observation_root": roots.observation_root,
            "receipt_root": roots.receipt_root,
            "snapshot_root": roots.snapshot_root,
            "counters": self.counters().public_record()
        });
        roots.state_root = root_from_record(&record);
        roots
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol": L2_PROTOCOL_COHESION_MATRIX_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "subsystems": self.subsystems.values().map(SubsystemNode::public_record).collect::<Vec<_>>(),
            "edges": self.edges.values().map(CompatibilityEdge::public_record).collect::<Vec<_>>(),
            "dependency_gates": self.gates.values().map(DependencyGate::public_record).collect::<Vec<_>>(),
            "observations": self.observations.values().map(InvariantObservation::public_record).collect::<Vec<_>>(),
            "remediation_receipts": self.receipts.values().map(RemediationReceipt::public_record).collect::<Vec<_>>(),
            "snapshots": self.snapshots.values().map(CohesionSnapshot::public_record).collect::<Vec<_>>(),
            "counters": self.counters().public_record(),
            "roots": roots.public_record()
        })
    }

    pub fn validate(&self) -> L2ProtocolCohesionMatrixResult<String> {
        self.config.validate()?;
        if self.subsystems.len() > L2_PROTOCOL_COHESION_MATRIX_MAX_SUBSYSTEMS {
            return Err("too many cohesion subsystems".to_string());
        }
        if self.edges.len() > L2_PROTOCOL_COHESION_MATRIX_MAX_EDGES {
            return Err("too many cohesion edges".to_string());
        }
        if self.gates.len() > L2_PROTOCOL_COHESION_MATRIX_MAX_GATES {
            return Err("too many cohesion dependency gates".to_string());
        }
        if self.observations.len() > L2_PROTOCOL_COHESION_MATRIX_MAX_OBSERVATIONS {
            return Err("too many cohesion observations".to_string());
        }
        if self.receipts.len() > L2_PROTOCOL_COHESION_MATRIX_MAX_RECEIPTS {
            return Err("too many cohesion remediation receipts".to_string());
        }
        if self.snapshots.len() > L2_PROTOCOL_COHESION_MATRIX_MAX_SNAPSHOTS {
            return Err("too many cohesion snapshots".to_string());
        }
        for subsystem in self.subsystems.values() {
            subsystem.validate()?;
        }
        for edge in self.edges.values() {
            edge.validate()?;
            if !self.subsystems.contains_key(&edge.from_subsystem_id) {
                return Err("compatibility edge references missing source subsystem".to_string());
            }
            if !self.subsystems.contains_key(&edge.to_subsystem_id) {
                return Err("compatibility edge references missing target subsystem".to_string());
            }
        }
        for gate in self.gates.values() {
            gate.validate()?;
            if !self.edges.contains_key(&gate.edge_id) {
                return Err("dependency gate references missing edge".to_string());
            }
            if !self.subsystems.contains_key(&gate.required_subsystem_id) {
                return Err("dependency gate references missing subsystem".to_string());
            }
        }
        for observation in self.observations.values() {
            observation.validate()?;
            if !self.subsystems.contains_key(&observation.subsystem_id) {
                return Err("observation references missing subsystem".to_string());
            }
            if !self.edges.contains_key(&observation.edge_id) {
                return Err("observation references missing edge".to_string());
            }
        }
        for receipt in self.receipts.values() {
            receipt.validate()?;
            if !self.observations.contains_key(&receipt.observation_id) {
                return Err("remediation receipt references missing observation".to_string());
            }
            if !self.gates.contains_key(&receipt.gate_id) {
                return Err("remediation receipt references missing gate".to_string());
            }
        }
        for snapshot in self.snapshots.values() {
            snapshot.validate()?;
        }
        self.validate_required_gates()?;
        let counters = self.counters();
        if counters.cohesion_score_bps < self.config.min_cohesion_score_bps {
            return Err("cohesion score below configured minimum".to_string());
        }
        if counters.critical_score_bps < self.config.min_critical_score_bps {
            return Err("critical cohesion score below configured minimum".to_string());
        }
        if counters.open_blockers > self.config.max_open_blockers {
            return Err("open cohesion blockers exceed configured maximum".to_string());
        }
        Ok(self.state_root())
    }

    fn roots_without_state(&self) -> Roots {
        let empty_state_root = string_root("L2-PROTOCOL-COHESION-MATRIX-EMPTY-STATE", "pending");
        Roots {
            config_root: payload_root(
                "L2-PROTOCOL-COHESION-MATRIX-CONFIG-ROOT",
                &self.config.public_record(),
            ),
            subsystem_root: merkle_records(
                "L2-PROTOCOL-COHESION-MATRIX-SUBSYSTEM-ROOT",
                self.subsystems
                    .values()
                    .map(SubsystemNode::public_record)
                    .collect(),
            ),
            edge_root: merkle_records(
                "L2-PROTOCOL-COHESION-MATRIX-EDGE-ROOT",
                self.edges
                    .values()
                    .map(CompatibilityEdge::public_record)
                    .collect(),
            ),
            gate_root: merkle_records(
                "L2-PROTOCOL-COHESION-MATRIX-GATE-ROOT",
                self.gates
                    .values()
                    .map(DependencyGate::public_record)
                    .collect(),
            ),
            observation_root: merkle_records(
                "L2-PROTOCOL-COHESION-MATRIX-OBSERVATION-ROOT",
                self.observations
                    .values()
                    .map(InvariantObservation::public_record)
                    .collect(),
            ),
            receipt_root: merkle_records(
                "L2-PROTOCOL-COHESION-MATRIX-RECEIPT-ROOT",
                self.receipts
                    .values()
                    .map(RemediationReceipt::public_record)
                    .collect(),
            ),
            snapshot_root: merkle_records(
                "L2-PROTOCOL-COHESION-MATRIX-SNAPSHOT-ROOT",
                self.snapshots
                    .values()
                    .map(CohesionSnapshot::public_record)
                    .collect(),
            ),
            state_root: empty_state_root,
        }
    }

    fn validate_required_gates(&self) -> L2ProtocolCohesionMatrixResult<()> {
        let mut covered = BTreeSet::new();
        for edge in self.edges.values() {
            let from = self.subsystems.get(&edge.from_subsystem_id);
            let to = self.subsystems.get(&edge.to_subsystem_id);
            if let (Some(from), Some(to)) = (from, to) {
                covered.insert((from.subsystem, to.subsystem, edge.edge_kind));
            }
        }
        if self.config.require_monero_pq_bridge_gate
            && !covered.contains(&(
                CohesionSubsystem::MoneroBridge,
                CohesionSubsystem::PqAuth,
                CohesionEdgeKind::AuthDependency,
            ))
        {
            return Err("required monero pq bridge gate missing".to_string());
        }
        if self.config.require_private_contract_defi_gate
            && !covered.contains(&(
                CohesionSubsystem::PrivateContracts,
                CohesionSubsystem::PrivateDefi,
                CohesionEdgeKind::StateDependency,
            ))
        {
            return Err("required private contract defi gate missing".to_string());
        }
        if self.config.require_low_fee_privacy_gate
            && !covered.contains(&(
                CohesionSubsystem::LowFeeLanes,
                CohesionSubsystem::PrivacyBudgets,
                CohesionEdgeKind::FeeDependency,
            ))
        {
            return Err("required low fee privacy gate missing".to_string());
        }
        if self.config.require_operator_state_root_gate
            && !covered.contains(&(
                CohesionSubsystem::OperatorReadiness,
                CohesionSubsystem::StateRoots,
                CohesionEdgeKind::OperatorDependency,
            ))
        {
            return Err("required operator state root gate missing".to_string());
        }
        Ok(())
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "L2-PROTOCOL-COHESION-MATRIX-STATE-ROOT",
        &[
            HashPart::Str(L2_PROTOCOL_COHESION_MATRIX_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn devnet() -> L2ProtocolCohesionMatrixResult<State> {
    State::devnet()
}

#[allow(clippy::too_many_arguments)]
pub fn subsystem_id(
    subsystem: CohesionSubsystem,
    label: &str,
    owner_commitment: &str,
    code_root: &str,
    state_root: &str,
    readiness_root: &str,
    status: CohesionStatus,
) -> String {
    domain_hash(
        "L2-PROTOCOL-COHESION-MATRIX-SUBSYSTEM-ID",
        &[
            HashPart::Str(L2_PROTOCOL_COHESION_MATRIX_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subsystem.as_str()),
            HashPart::Str(label),
            HashPart::Str(owner_commitment),
            HashPart::Str(code_root),
            HashPart::Str(state_root),
            HashPart::Str(readiness_root),
            HashPart::Str(status.as_str()),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn edge_id(
    from_subsystem_id: &str,
    to_subsystem_id: &str,
    edge_kind: CohesionEdgeKind,
    severity: CohesionSeverity,
    compatibility_root: &str,
    dependency_root: &str,
    status: CohesionStatus,
    opened_at_height: u64,
    due_height: u64,
) -> String {
    domain_hash(
        "L2-PROTOCOL-COHESION-MATRIX-EDGE-ID",
        &[
            HashPart::Str(L2_PROTOCOL_COHESION_MATRIX_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(from_subsystem_id),
            HashPart::Str(to_subsystem_id),
            HashPart::Str(edge_kind.as_str()),
            HashPart::Str(severity.as_str()),
            HashPart::Str(compatibility_root),
            HashPart::Str(dependency_root),
            HashPart::Str(status.as_str()),
            HashPart::Str(&opened_at_height.to_string()),
            HashPart::Str(&due_height.to_string()),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn gate_id(
    edge_id: &str,
    required_subsystem_id: &str,
    gate_label: &str,
    required_root: &str,
    evidence_root: &str,
    severity: CohesionSeverity,
    status: CohesionStatus,
    opened_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "L2-PROTOCOL-COHESION-MATRIX-GATE-ID",
        &[
            HashPart::Str(L2_PROTOCOL_COHESION_MATRIX_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(edge_id),
            HashPart::Str(required_subsystem_id),
            HashPart::Str(gate_label),
            HashPart::Str(required_root),
            HashPart::Str(evidence_root),
            HashPart::Str(severity.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(&opened_at_height.to_string()),
            HashPart::Str(&expires_at_height.to_string()),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn observation_id(
    subsystem_id: &str,
    edge_id: &str,
    observation_kind: CohesionObservationKind,
    signal_root: &str,
    observed_at_height: u64,
    expires_at_height: u64,
    severity: CohesionSeverity,
    status: CohesionStatus,
) -> String {
    domain_hash(
        "L2-PROTOCOL-COHESION-MATRIX-OBSERVATION-ID",
        &[
            HashPart::Str(L2_PROTOCOL_COHESION_MATRIX_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subsystem_id),
            HashPart::Str(edge_id),
            HashPart::Str(observation_kind.as_str()),
            HashPart::Str(signal_root),
            HashPart::Str(&observed_at_height.to_string()),
            HashPart::Str(&expires_at_height.to_string()),
            HashPart::Str(severity.as_str()),
            HashPart::Str(status.as_str()),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn receipt_id(
    observation_id: &str,
    gate_id: &str,
    remediation_kind: CohesionRemediationKind,
    operator_commitment: &str,
    action_root: &str,
    result_root: &str,
    submitted_at_height: u64,
    accepted: bool,
) -> String {
    domain_hash(
        "L2-PROTOCOL-COHESION-MATRIX-RECEIPT-ID",
        &[
            HashPart::Str(L2_PROTOCOL_COHESION_MATRIX_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(observation_id),
            HashPart::Str(gate_id),
            HashPart::Str(remediation_kind.as_str()),
            HashPart::Str(operator_commitment),
            HashPart::Str(action_root),
            HashPart::Str(result_root),
            HashPart::Str(&submitted_at_height.to_string()),
            HashPart::Str(if accepted { "accepted" } else { "rejected" }),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn snapshot_id(
    height: u64,
    subsystem_root: &str,
    edge_root: &str,
    gate_root: &str,
    observation_root: &str,
    receipt_root: &str,
    cohesion_score_bps: u64,
    critical_score_bps: u64,
    open_blockers: u64,
) -> String {
    domain_hash(
        "L2-PROTOCOL-COHESION-MATRIX-SNAPSHOT-ID",
        &[
            HashPart::Str(L2_PROTOCOL_COHESION_MATRIX_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&height.to_string()),
            HashPart::Str(subsystem_root),
            HashPart::Str(edge_root),
            HashPart::Str(gate_root),
            HashPart::Str(observation_root),
            HashPart::Str(receipt_root),
            HashPart::Str(&cohesion_score_bps.to_string()),
            HashPart::Str(&critical_score_bps.to_string()),
            HashPart::Str(&open_blockers.to_string()),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(L2_PROTOCOL_COHESION_MATRIX_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(L2_PROTOCOL_COHESION_MATRIX_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(value),
        ],
        32,
    )
}

fn merkle_records(domain: &str, records: Vec<Value>) -> String {
    let leaves = records
        .iter()
        .map(|record| Value::String(payload_root(domain, record)))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn remediation_for_edge(edge_kind: CohesionEdgeKind) -> CohesionRemediationKind {
    match edge_kind {
        CohesionEdgeKind::StateDependency => CohesionRemediationKind::ReanchorStateRoot,
        CohesionEdgeKind::AuthDependency => CohesionRemediationKind::RotatePqAuthority,
        CohesionEdgeKind::LiquidityDependency => CohesionRemediationKind::PauseBridgeExit,
        CohesionEdgeKind::PrivacyDependency => CohesionRemediationKind::RaisePrivacyBudgetDeposit,
        CohesionEdgeKind::FeeDependency => CohesionRemediationKind::RepriceLowFeeLane,
        CohesionEdgeKind::ProofDependency => CohesionRemediationKind::RebidProofMarket,
        CohesionEdgeKind::OperatorDependency => CohesionRemediationKind::RefreshOperatorRunbook,
        CohesionEdgeKind::EmergencyDependency => CohesionRemediationKind::GovernanceReview,
        CohesionEdgeKind::DataDependency => CohesionRemediationKind::AddDataAvailabilityReplica,
        CohesionEdgeKind::GovernanceDependency => CohesionRemediationKind::GovernanceReview,
    }
}

fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        L2_PROTOCOL_COHESION_MATRIX_MAX_BPS
    } else {
        numerator.saturating_mul(L2_PROTOCOL_COHESION_MATRIX_MAX_BPS) / denominator
    }
}

fn to_u64(value: usize) -> u64 {
    match u64::try_from(value) {
        Ok(value) => value,
        Err(_) => u64::MAX,
    }
}

fn ensure_non_empty(value: &str, label: &str) -> L2ProtocolCohesionMatrixResult<()> {
    if value.is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> L2ProtocolCohesionMatrixResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn validate_bps(value: u64, label: &str) -> L2ProtocolCohesionMatrixResult<()> {
    if value > L2_PROTOCOL_COHESION_MATRIX_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}
