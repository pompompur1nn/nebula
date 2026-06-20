use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialReleaseScenarioMatrixRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_RELEASE_SCENARIO_MATRIX_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-release-scenario-matrix-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_RELEASE_SCENARIO_MATRIX_RUNTIME_PROTOCOL_VERSION;
pub const HASH_SUITE: &str = "nebula-stable-fnv1a-release-scenario-matrix-v1";
pub const DEFAULT_RELEASE_ID: &str = "nebula-private-l2-100k-wave-devnet";
pub const DEFAULT_OPERATOR_ID: &str = "operator-devnet";
pub const DEFAULT_CHAIN_ID: &str = "nebula-monero-private-l2-devnet";
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorityDomain {
    QuantumResistance,
    Speed,
    Defi,
    SmartContracts,
    LowFees,
    Privacy,
    MoneroBridge,
    OperatorReadiness,
}

impl PriorityDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::QuantumResistance => "quantum_resistance",
            Self::Speed => "speed",
            Self::Defi => "defi",
            Self::SmartContracts => "smart_contracts",
            Self::LowFees => "low_fees",
            Self::Privacy => "privacy",
            Self::MoneroBridge => "monero_bridge",
            Self::OperatorReadiness => "operator_readiness",
        }
    }

    pub fn release_weight_bps(self) -> u64 {
        match self {
            Self::QuantumResistance => 1_700,
            Self::Privacy => 1_500,
            Self::Speed => 1_400,
            Self::LowFees => 1_250,
            Self::Defi => 1_200,
            Self::SmartContracts => 1_150,
            Self::MoneroBridge => 1_050,
            Self::OperatorReadiness => 750,
        }
    }

    pub fn all() -> [Self; 8] {
        [
            Self::QuantumResistance,
            Self::Speed,
            Self::Defi,
            Self::SmartContracts,
            Self::LowFees,
            Self::Privacy,
            Self::MoneroBridge,
            Self::OperatorReadiness,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioKind {
    PqKeyMigration,
    PqSignatureRollover,
    ThresholdQuorum,
    FastPreconfirmation,
    SequencerFailover,
    ProofMarketPressure,
    ConfidentialTokenIssue,
    ConfidentialAmmSwap,
    LendingLiquidation,
    PerpMarginShock,
    ContractUpgrade,
    ContractInvariantFailure,
    ContractAbiFuzz,
    FeeSpike,
    SponsorExhaustion,
    DaBlobCongestion,
    RingCtMigration,
    ViewKeyRecovery,
    DandelionRelay,
    StealthWithdrawal,
    BridgeReorg,
    WatchtowerDispute,
    OperatorIncident,
    ReleaseGateDryRun,
}

impl ScenarioKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqKeyMigration => "pq_key_migration",
            Self::PqSignatureRollover => "pq_signature_rollover",
            Self::ThresholdQuorum => "threshold_quorum",
            Self::FastPreconfirmation => "fast_preconfirmation",
            Self::SequencerFailover => "sequencer_failover",
            Self::ProofMarketPressure => "proof_market_pressure",
            Self::ConfidentialTokenIssue => "confidential_token_issue",
            Self::ConfidentialAmmSwap => "confidential_amm_swap",
            Self::LendingLiquidation => "lending_liquidation",
            Self::PerpMarginShock => "perp_margin_shock",
            Self::ContractUpgrade => "contract_upgrade",
            Self::ContractInvariantFailure => "contract_invariant_failure",
            Self::ContractAbiFuzz => "contract_abi_fuzz",
            Self::FeeSpike => "fee_spike",
            Self::SponsorExhaustion => "sponsor_exhaustion",
            Self::DaBlobCongestion => "da_blob_congestion",
            Self::RingCtMigration => "ringct_migration",
            Self::ViewKeyRecovery => "view_key_recovery",
            Self::DandelionRelay => "dandelion_relay",
            Self::StealthWithdrawal => "stealth_withdrawal",
            Self::BridgeReorg => "bridge_reorg",
            Self::WatchtowerDispute => "watchtower_dispute",
            Self::OperatorIncident => "operator_incident",
            Self::ReleaseGateDryRun => "release_gate_dry_run",
        }
    }

    pub fn default_domain(self) -> PriorityDomain {
        match self {
            Self::PqKeyMigration | Self::PqSignatureRollover | Self::ThresholdQuorum => {
                PriorityDomain::QuantumResistance
            }
            Self::FastPreconfirmation | Self::SequencerFailover | Self::ProofMarketPressure => {
                PriorityDomain::Speed
            }
            Self::ConfidentialTokenIssue
            | Self::ConfidentialAmmSwap
            | Self::LendingLiquidation
            | Self::PerpMarginShock => PriorityDomain::Defi,
            Self::ContractUpgrade | Self::ContractInvariantFailure | Self::ContractAbiFuzz => {
                PriorityDomain::SmartContracts
            }
            Self::FeeSpike | Self::SponsorExhaustion | Self::DaBlobCongestion => {
                PriorityDomain::LowFees
            }
            Self::RingCtMigration
            | Self::ViewKeyRecovery
            | Self::DandelionRelay
            | Self::StealthWithdrawal => PriorityDomain::Privacy,
            Self::BridgeReorg | Self::WatchtowerDispute => PriorityDomain::MoneroBridge,
            Self::OperatorIncident | Self::ReleaseGateDryRun => PriorityDomain::OperatorReadiness,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioStatus {
    Draft,
    EvidencePending,
    RemediationPending,
    Covered,
    Blocked,
    Waived,
}

impl ScenarioStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::EvidencePending => "evidence_pending",
            Self::RemediationPending => "remediation_pending",
            Self::Covered => "covered",
            Self::Blocked => "blocked",
            Self::Waived => "waived",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    WorkerModule,
    DevnetRoot,
    PublicRecord,
    OperatorCatalog,
    ReleaseGate,
    ScenarioReceipt,
    RiskScore,
    ManualAttestation,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WorkerModule => "worker_module",
            Self::DevnetRoot => "devnet_root",
            Self::PublicRecord => "public_record",
            Self::OperatorCatalog => "operator_catalog",
            Self::ReleaseGate => "release_gate",
            Self::ScenarioReceipt => "scenario_receipt",
            Self::RiskScore => "risk_score",
            Self::ManualAttestation => "manual_attestation",
        }
    }

    pub fn weight_bps(self) -> u64 {
        match self {
            Self::WorkerModule => 1_200,
            Self::DevnetRoot => 1_400,
            Self::PublicRecord => 1_200,
            Self::OperatorCatalog => 1_100,
            Self::ReleaseGate => 1_500,
            Self::ScenarioReceipt => 1_500,
            Self::RiskScore => 1_000,
            Self::ManualAttestation => 700,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationKind {
    AddRuntime,
    WireDevnet,
    WireOperator,
    AddScenarioReceipt,
    AddRiskControl,
    RaisePrivacyFloor,
    LowerFeeCap,
    AddReleaseGate,
}

impl RemediationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AddRuntime => "add_runtime",
            Self::WireDevnet => "wire_devnet",
            Self::WireOperator => "wire_operator",
            Self::AddScenarioReceipt => "add_scenario_receipt",
            Self::AddRiskControl => "add_risk_control",
            Self::RaisePrivacyFloor => "raise_privacy_floor",
            Self::LowerFeeCap => "lower_fee_cap",
            Self::AddReleaseGate => "add_release_gate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckGateKind {
    LocWave,
    Compile,
    Format,
    UnitTests,
    Clippy,
    PrivacyAudit,
    ReleaseReview,
}

impl CheckGateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocWave => "loc_wave",
            Self::Compile => "compile",
            Self::Format => "format",
            Self::UnitTests => "unit_tests",
            Self::Clippy => "clippy",
            Self::PrivacyAudit => "privacy_audit",
            Self::ReleaseReview => "release_review",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckGateStatus {
    Deferred,
    Ready,
    Passed,
    Failed,
    Waived,
}

impl CheckGateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deferred => "deferred",
            Self::Ready => "ready",
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Waived => "waived",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationSurface {
    ModuleDeclaration,
    ReExport,
    DevnetState,
    DevnetCompactRoot,
    DevnetPublicRecord,
    OperatorCatalog,
    ProgressPanel,
}

impl IntegrationSurface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ModuleDeclaration => "module_declaration",
            Self::ReExport => "re_export",
            Self::DevnetState => "devnet_state",
            Self::DevnetCompactRoot => "devnet_compact_root",
            Self::DevnetPublicRecord => "devnet_public_record",
            Self::OperatorCatalog => "operator_catalog",
            Self::ProgressPanel => "progress_panel",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub release_id: String,
    pub min_scenarios_per_priority: u64,
    pub min_total_scenarios: u64,
    pub min_evidence_per_scenario: u64,
    pub min_release_readiness_bps: u64,
    pub min_priority_readiness_bps: u64,
    pub max_blocked_scenarios: u64,
    pub wave_target_loc: u64,
    pub current_wave_loc: u64,
    pub checks_deferred_until_wave_target: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: DEFAULT_CHAIN_ID.to_string(),
            release_id: DEFAULT_RELEASE_ID.to_string(),
            min_scenarios_per_priority: 3,
            min_total_scenarios: 32,
            min_evidence_per_scenario: 3,
            min_release_readiness_bps: 8_500,
            min_priority_readiness_bps: 8_000,
            max_blocked_scenarios: 0,
            wave_target_loc: 100_000,
            current_wave_loc: 65_616,
            checks_deferred_until_wave_target: true,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub signer_id: String,
    pub signature_root: String,
    pub security_bits: u16,
    pub scheme: String,
}

impl PqAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "signer_id": self.signer_id,
            "signature_root": self.signature_root,
            "security_bits": self.security_bits,
            "scheme": self.scheme,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScenarioInput {
    pub scenario_id: String,
    pub kind: ScenarioKind,
    pub priority: PriorityDomain,
    pub owner: String,
    pub title: String,
    pub module_name: String,
    pub expected_root: String,
    pub privacy_floor: u64,
    pub max_fee_bps: u64,
    pub target_latency_ms: u64,
    pub risk_budget_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScenarioRecord {
    pub scenario_id: String,
    pub kind: ScenarioKind,
    pub priority: PriorityDomain,
    pub owner: String,
    pub title: String,
    pub module_name: String,
    pub expected_root: String,
    pub privacy_floor: u64,
    pub max_fee_bps: u64,
    pub target_latency_ms: u64,
    pub risk_budget_bps: u64,
    pub status: ScenarioStatus,
    pub evidence_ids: BTreeSet<String>,
    pub remediation_ids: BTreeSet<String>,
    pub gate_ids: BTreeSet<String>,
    pub readiness_bps: u64,
}

impl ScenarioRecord {
    pub fn from_input(input: ScenarioInput) -> Self {
        Self {
            scenario_id: input.scenario_id,
            kind: input.kind,
            priority: input.priority,
            owner: input.owner,
            title: input.title,
            module_name: input.module_name,
            expected_root: input.expected_root,
            privacy_floor: input.privacy_floor,
            max_fee_bps: input.max_fee_bps,
            target_latency_ms: input.target_latency_ms,
            risk_budget_bps: input.risk_budget_bps,
            status: ScenarioStatus::EvidencePending,
            evidence_ids: BTreeSet::new(),
            remediation_ids: BTreeSet::new(),
            gate_ids: BTreeSet::new(),
            readiness_bps: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scenario_id": self.scenario_id,
            "kind": self.kind.as_str(),
            "priority": self.priority.as_str(),
            "owner": self.owner,
            "title": self.title,
            "module_name": self.module_name,
            "expected_root": self.expected_root,
            "privacy_floor": self.privacy_floor,
            "max_fee_bps": self.max_fee_bps,
            "target_latency_ms": self.target_latency_ms,
            "risk_budget_bps": self.risk_budget_bps,
            "status": self.status.as_str(),
            "evidence_ids": self.evidence_ids.iter().cloned().collect::<Vec<_>>(),
            "remediation_ids": self.remediation_ids.iter().cloned().collect::<Vec<_>>(),
            "gate_ids": self.gate_ids.iter().cloned().collect::<Vec<_>>(),
            "readiness_bps": self.readiness_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceInput {
    pub evidence_id: String,
    pub scenario_id: String,
    pub kind: EvidenceKind,
    pub module_name: String,
    pub root: String,
    pub weight_bps: u64,
    pub redacted_summary: String,
    pub attestation: Option<PqAttestation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceRecord {
    pub evidence_id: String,
    pub scenario_id: String,
    pub kind: EvidenceKind,
    pub module_name: String,
    pub root: String,
    pub weight_bps: u64,
    pub redacted_summary: String,
    pub attestation: Option<PqAttestation>,
}

impl EvidenceRecord {
    pub fn from_input(input: EvidenceInput) -> Self {
        Self {
            evidence_id: input.evidence_id,
            scenario_id: input.scenario_id,
            kind: input.kind,
            module_name: input.module_name,
            root: input.root,
            weight_bps: clamp_bps(input.weight_bps),
            redacted_summary: input.redacted_summary,
            attestation: input.attestation,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "scenario_id": self.scenario_id,
            "kind": self.kind.as_str(),
            "module_name": self.module_name,
            "root": self.root,
            "weight_bps": self.weight_bps,
            "redacted_summary": self.redacted_summary,
            "attestation": self.attestation.as_ref().map(PqAttestation::public_record),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RemediationInput {
    pub remediation_id: String,
    pub scenario_id: String,
    pub kind: RemediationKind,
    pub owner: String,
    pub target_module: String,
    pub action_root: String,
    pub complete: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RemediationRecord {
    pub remediation_id: String,
    pub scenario_id: String,
    pub kind: RemediationKind,
    pub owner: String,
    pub target_module: String,
    pub action_root: String,
    pub complete: bool,
}

impl RemediationRecord {
    pub fn from_input(input: RemediationInput) -> Self {
        Self {
            remediation_id: input.remediation_id,
            scenario_id: input.scenario_id,
            kind: input.kind,
            owner: input.owner,
            target_module: input.target_module,
            action_root: input.action_root,
            complete: input.complete,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "remediation_id": self.remediation_id,
            "scenario_id": self.scenario_id,
            "kind": self.kind.as_str(),
            "owner": self.owner,
            "target_module": self.target_module,
            "action_root": self.action_root,
            "complete": self.complete,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CoverageGateInput {
    pub gate_id: String,
    pub scenario_id: String,
    pub kind: CheckGateKind,
    pub status: CheckGateStatus,
    pub root: String,
    pub deferred_reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CoverageGateRecord {
    pub gate_id: String,
    pub scenario_id: String,
    pub kind: CheckGateKind,
    pub status: CheckGateStatus,
    pub root: String,
    pub deferred_reason: String,
}

impl CoverageGateRecord {
    pub fn from_input(input: CoverageGateInput) -> Self {
        Self {
            gate_id: input.gate_id,
            scenario_id: input.scenario_id,
            kind: input.kind,
            status: input.status,
            root: input.root,
            deferred_reason: input.deferred_reason,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "gate_id": self.gate_id,
            "scenario_id": self.scenario_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "root": self.root,
            "deferred_reason": self.deferred_reason,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IntegrationInput {
    pub integration_id: String,
    pub scenario_id: String,
    pub surface: IntegrationSurface,
    pub module_name: String,
    pub root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IntegrationRecord {
    pub integration_id: String,
    pub scenario_id: String,
    pub surface: IntegrationSurface,
    pub module_name: String,
    pub root: String,
}

impl IntegrationRecord {
    pub fn from_input(input: IntegrationInput) -> Self {
        Self {
            integration_id: input.integration_id,
            scenario_id: input.scenario_id,
            surface: input.surface,
            module_name: input.module_name,
            root: input.root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "integration_id": self.integration_id,
            "scenario_id": self.scenario_id,
            "surface": self.surface.as_str(),
            "module_name": self.module_name,
            "root": self.root,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub scenarios_registered: u64,
    pub evidence_registered: u64,
    pub remediations_registered: u64,
    pub remediations_completed: u64,
    pub gates_registered: u64,
    pub gates_deferred: u64,
    pub gates_ready: u64,
    pub integrations_registered: u64,
    pub covered_scenarios: u64,
    pub blocked_scenarios: u64,
    pub waived_scenarios: u64,
    pub root_recomputations: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "scenarios_registered": self.scenarios_registered,
            "evidence_registered": self.evidence_registered,
            "remediations_registered": self.remediations_registered,
            "remediations_completed": self.remediations_completed,
            "gates_registered": self.gates_registered,
            "gates_deferred": self.gates_deferred,
            "gates_ready": self.gates_ready,
            "integrations_registered": self.integrations_registered,
            "covered_scenarios": self.covered_scenarios,
            "blocked_scenarios": self.blocked_scenarios,
            "waived_scenarios": self.waived_scenarios,
            "root_recomputations": self.root_recomputations,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub scenarios_root: String,
    pub evidence_root: String,
    pub remediations_root: String,
    pub gates_root: String,
    pub integrations_root: String,
    pub priority_readiness_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "scenarios_root": self.scenarios_root,
            "evidence_root": self.evidence_root,
            "remediations_root": self.remediations_root,
            "gates_root": self.gates_root,
            "integrations_root": self.integrations_root,
            "priority_readiness_root": self.priority_readiness_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub operator_id: String,
    pub scenarios: BTreeMap<String, ScenarioRecord>,
    pub evidence: BTreeMap<String, EvidenceRecord>,
    pub remediations: BTreeMap<String, RemediationRecord>,
    pub gates: BTreeMap<String, CoverageGateRecord>,
    pub integrations: BTreeMap<String, IntegrationRecord>,
    pub priority_readiness_bps: BTreeMap<PriorityDomain, u64>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            operator_id: DEFAULT_OPERATOR_ID.to_string(),
            scenarios: BTreeMap::new(),
            evidence: BTreeMap::new(),
            remediations: BTreeMap::new(),
            gates: BTreeMap::new(),
            integrations: BTreeMap::new(),
            priority_readiness_bps: BTreeMap::new(),
            counters: Counters::default(),
            roots: Roots::default(),
        };
        state.recompute_roots();
        state
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet())
    }

    pub fn set_operator_id(&mut self, operator_id: impl Into<String>) -> Result<()> {
        let operator_id = operator_id.into();
        validate_id("operator_id", &operator_id)?;
        self.operator_id = operator_id;
        self.recompute_roots();
        Ok(())
    }

    pub fn register_scenario(&mut self, input: ScenarioInput) -> Result<String> {
        validate_id("scenario_id", &input.scenario_id)?;
        validate_id("owner", &input.owner)?;
        validate_id("module_name", &input.module_name)?;
        validate_root("expected_root", &input.expected_root)?;
        if input.max_fee_bps > MAX_BPS {
            return Err("max_fee_bps exceeds 10000".to_string());
        }
        let scenario_id = input.scenario_id.clone();
        let record = ScenarioRecord::from_input(input);
        self.scenarios.insert(scenario_id.clone(), record);
        self.counters.scenarios_registered = self.counters.scenarios_registered.saturating_add(1);
        self.refresh_scenario_status(&scenario_id)?;
        self.recompute_roots();
        Ok(scenario_id)
    }

    pub fn register_evidence(&mut self, input: EvidenceInput) -> Result<String> {
        validate_id("evidence_id", &input.evidence_id)?;
        validate_id("scenario_id", &input.scenario_id)?;
        validate_id("module_name", &input.module_name)?;
        validate_root("root", &input.root)?;
        if !self.scenarios.contains_key(&input.scenario_id) {
            return Err("scenario not registered".to_string());
        }
        if let Some(attestation) = input.attestation.as_ref() {
            validate_id("attestation_id", &attestation.attestation_id)?;
            validate_id("signer_id", &attestation.signer_id)?;
            validate_root("signature_root", &attestation.signature_root)?;
        }
        let evidence_id = input.evidence_id.clone();
        let scenario_id = input.scenario_id.clone();
        let record = EvidenceRecord::from_input(input);
        self.evidence.insert(evidence_id.clone(), record);
        if let Some(scenario) = self.scenarios.get_mut(&scenario_id) {
            scenario.evidence_ids.insert(evidence_id.clone());
        }
        self.counters.evidence_registered = self.counters.evidence_registered.saturating_add(1);
        self.refresh_scenario_status(&scenario_id)?;
        self.recompute_roots();
        Ok(evidence_id)
    }

    pub fn register_remediation(&mut self, input: RemediationInput) -> Result<String> {
        validate_id("remediation_id", &input.remediation_id)?;
        validate_id("scenario_id", &input.scenario_id)?;
        validate_id("owner", &input.owner)?;
        validate_id("target_module", &input.target_module)?;
        validate_root("action_root", &input.action_root)?;
        if !self.scenarios.contains_key(&input.scenario_id) {
            return Err("scenario not registered".to_string());
        }
        let remediation_id = input.remediation_id.clone();
        let scenario_id = input.scenario_id.clone();
        let complete = input.complete;
        let record = RemediationRecord::from_input(input);
        self.remediations.insert(remediation_id.clone(), record);
        if let Some(scenario) = self.scenarios.get_mut(&scenario_id) {
            scenario.remediation_ids.insert(remediation_id.clone());
        }
        self.counters.remediations_registered =
            self.counters.remediations_registered.saturating_add(1);
        if complete {
            self.counters.remediations_completed =
                self.counters.remediations_completed.saturating_add(1);
        }
        self.refresh_scenario_status(&scenario_id)?;
        self.recompute_roots();
        Ok(remediation_id)
    }

    pub fn register_gate(&mut self, input: CoverageGateInput) -> Result<String> {
        validate_id("gate_id", &input.gate_id)?;
        validate_id("scenario_id", &input.scenario_id)?;
        validate_root("root", &input.root)?;
        if !self.scenarios.contains_key(&input.scenario_id) {
            return Err("scenario not registered".to_string());
        }
        let gate_id = input.gate_id.clone();
        let scenario_id = input.scenario_id.clone();
        let status = input.status;
        let record = CoverageGateRecord::from_input(input);
        self.gates.insert(gate_id.clone(), record);
        if let Some(scenario) = self.scenarios.get_mut(&scenario_id) {
            scenario.gate_ids.insert(gate_id.clone());
        }
        self.counters.gates_registered = self.counters.gates_registered.saturating_add(1);
        match status {
            CheckGateStatus::Deferred => {
                self.counters.gates_deferred = self.counters.gates_deferred.saturating_add(1);
            }
            CheckGateStatus::Ready | CheckGateStatus::Passed => {
                self.counters.gates_ready = self.counters.gates_ready.saturating_add(1);
            }
            CheckGateStatus::Failed | CheckGateStatus::Waived => {}
        }
        self.refresh_scenario_status(&scenario_id)?;
        self.recompute_roots();
        Ok(gate_id)
    }

    pub fn register_integration(&mut self, input: IntegrationInput) -> Result<String> {
        validate_id("integration_id", &input.integration_id)?;
        validate_id("scenario_id", &input.scenario_id)?;
        validate_id("module_name", &input.module_name)?;
        validate_root("root", &input.root)?;
        if !self.scenarios.contains_key(&input.scenario_id) {
            return Err("scenario not registered".to_string());
        }
        let integration_id = input.integration_id.clone();
        let scenario_id = input.scenario_id.clone();
        let record = IntegrationRecord::from_input(input);
        self.integrations.insert(integration_id.clone(), record);
        self.counters.integrations_registered =
            self.counters.integrations_registered.saturating_add(1);
        self.refresh_scenario_status(&scenario_id)?;
        self.recompute_roots();
        Ok(integration_id)
    }

    pub fn mark_remediation_complete(&mut self, remediation_id: &str) -> Result<()> {
        validate_id("remediation_id", remediation_id)?;
        let scenario_id = if let Some(record) = self.remediations.get_mut(remediation_id) {
            if !record.complete {
                record.complete = true;
                self.counters.remediations_completed =
                    self.counters.remediations_completed.saturating_add(1);
            }
            record.scenario_id.clone()
        } else {
            return Err("remediation not registered".to_string());
        };
        self.refresh_scenario_status(&scenario_id)?;
        self.recompute_roots();
        Ok(())
    }

    pub fn scenario_readiness_bps(&self, scenario_id: &str) -> u64 {
        let Some(scenario) = self.scenarios.get(scenario_id) else {
            return 0;
        };
        let evidence_score = scenario
            .evidence_ids
            .iter()
            .filter_map(|id| self.evidence.get(id))
            .fold(0_u64, |acc, record| {
                acc.saturating_add(record.kind.weight_bps().min(record.weight_bps))
            });
        let integration_score = self
            .integrations
            .values()
            .filter(|record| record.scenario_id == scenario_id)
            .fold(0_u64, |acc, _| acc.saturating_add(450));
        let gate_score = scenario
            .gate_ids
            .iter()
            .filter_map(|id| self.gates.get(id))
            .fold(0_u64, |acc, gate| {
                acc.saturating_add(match gate.status {
                    CheckGateStatus::Passed => 1_000,
                    CheckGateStatus::Ready => 700,
                    CheckGateStatus::Deferred => 250,
                    CheckGateStatus::Waived => 150,
                    CheckGateStatus::Failed => 0,
                })
            });
        let remediation_penalty = scenario
            .remediation_ids
            .iter()
            .filter_map(|id| self.remediations.get(id))
            .filter(|record| !record.complete)
            .fold(0_u64, |acc, _| acc.saturating_add(1_200));
        let base = evidence_score
            .saturating_add(integration_score)
            .saturating_add(gate_score)
            .saturating_sub(remediation_penalty);
        clamp_bps(base)
    }

    pub fn priority_readiness(&self, priority: PriorityDomain) -> u64 {
        let mut total = 0_u64;
        let mut count = 0_u64;
        for scenario in self.scenarios.values() {
            if scenario.priority == priority {
                total = total.saturating_add(scenario.readiness_bps);
                count = count.saturating_add(1);
            }
        }
        ratio_bps(total, count.saturating_mul(MAX_BPS))
    }

    pub fn aggregate_readiness_bps(&self) -> u64 {
        let mut weighted_total = 0_u64;
        let mut weight_sum = 0_u64;
        for priority in PriorityDomain::all() {
            let weight = priority.release_weight_bps();
            weighted_total = weighted_total
                .saturating_add(self.priority_readiness(priority).saturating_mul(weight));
            weight_sum = weight_sum.saturating_add(weight);
        }
        if weight_sum == 0 {
            0
        } else {
            weighted_total / weight_sum
        }
    }

    pub fn is_release_ready(&self) -> bool {
        if self.aggregate_readiness_bps() < self.config.min_release_readiness_bps {
            return false;
        }
        if self.counters.blocked_scenarios > self.config.max_blocked_scenarios {
            return false;
        }
        if self.scenarios.len() < self.config.min_total_scenarios as usize {
            return false;
        }
        for priority in PriorityDomain::all() {
            if self.priority_readiness(priority) < self.config.min_priority_readiness_bps {
                return false;
            }
        }
        true
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": self.config.chain_id,
            "release_id": self.config.release_id,
            "operator_id": self.operator_id,
            "aggregate_readiness_bps": self.aggregate_readiness_bps(),
            "release_ready": self.is_release_ready(),
            "current_wave_loc": self.config.current_wave_loc,
            "wave_target_loc": self.config.wave_target_loc,
            "checks_deferred_until_wave_target": self.config.checks_deferred_until_wave_target,
            "priority_readiness_bps": priority_map_public_record(&self.priority_readiness_bps),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "scenarios": self.scenarios.values().map(ScenarioRecord::public_record).collect::<Vec<_>>(),
            "evidence": self.evidence.values().map(EvidenceRecord::public_record).collect::<Vec<_>>(),
            "remediations": self.remediations.values().map(RemediationRecord::public_record).collect::<Vec<_>>(),
            "gates": self.gates.values().map(CoverageGateRecord::public_record).collect::<Vec<_>>(),
            "integrations": self.integrations.values().map(IntegrationRecord::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn roots(&self) -> &Roots {
        &self.roots
    }

    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    fn refresh_scenario_status(&mut self, scenario_id: &str) -> Result<()> {
        let readiness = self.scenario_readiness_bps(scenario_id);
        if let Some(scenario) = self.scenarios.get_mut(scenario_id) {
            scenario.readiness_bps = readiness;
            let has_incomplete_remediation = scenario
                .remediation_ids
                .iter()
                .filter_map(|id| self.remediations.get(id))
                .any(|record| !record.complete);
            let has_failed_gate = scenario
                .gate_ids
                .iter()
                .filter_map(|id| self.gates.get(id))
                .any(|gate| gate.status == CheckGateStatus::Failed);
            let evidence_count = scenario.evidence_ids.len() as u64;
            scenario.status = if has_failed_gate {
                ScenarioStatus::Blocked
            } else if has_incomplete_remediation {
                ScenarioStatus::RemediationPending
            } else if readiness >= self.config.min_priority_readiness_bps {
                ScenarioStatus::Covered
            } else if evidence_count < self.config.min_evidence_per_scenario {
                ScenarioStatus::EvidencePending
            } else {
                ScenarioStatus::Draft
            };
            Ok(())
        } else {
            Err("scenario not registered".to_string())
        }
    }

    fn recompute_roots(&mut self) {
        self.priority_readiness_bps.clear();
        for priority in PriorityDomain::all() {
            let score = self.priority_readiness(priority);
            self.priority_readiness_bps.insert(priority, score);
        }
        self.counters.covered_scenarios = self
            .scenarios
            .values()
            .filter(|scenario| scenario.status == ScenarioStatus::Covered)
            .count() as u64;
        self.counters.blocked_scenarios = self
            .scenarios
            .values()
            .filter(|scenario| scenario.status == ScenarioStatus::Blocked)
            .count() as u64;
        self.counters.waived_scenarios = self
            .scenarios
            .values()
            .filter(|scenario| scenario.status == ScenarioStatus::Waived)
            .count() as u64;
        self.roots.scenarios_root = map_root(
            "scenarios",
            self.scenarios
                .values()
                .map(scenario_root)
                .collect::<Vec<_>>(),
        );
        self.roots.evidence_root = map_root(
            "evidence",
            self.evidence
                .values()
                .map(evidence_root)
                .collect::<Vec<_>>(),
        );
        self.roots.remediations_root = map_root(
            "remediations",
            self.remediations
                .values()
                .map(remediation_root)
                .collect::<Vec<_>>(),
        );
        self.roots.gates_root = map_root(
            "gates",
            self.gates.values().map(gate_root).collect::<Vec<_>>(),
        );
        self.roots.integrations_root = map_root(
            "integrations",
            self.integrations
                .values()
                .map(integration_root)
                .collect::<Vec<_>>(),
        );
        self.roots.priority_readiness_root = map_root(
            "priority_readiness",
            self.priority_readiness_bps
                .iter()
                .map(|(priority, bps)| {
                    stable_hash(
                        "priority",
                        &[priority.as_str().to_string(), bps.to_string()],
                    )
                })
                .collect::<Vec<_>>(),
        );
        self.roots.state_root = stable_hash(
            "state",
            &[
                self.config.chain_id.clone(),
                self.config.release_id.clone(),
                self.operator_id.clone(),
                self.roots.scenarios_root.clone(),
                self.roots.evidence_root.clone(),
                self.roots.remediations_root.clone(),
                self.roots.gates_root.clone(),
                self.roots.integrations_root.clone(),
                self.roots.priority_readiness_root.clone(),
                self.aggregate_readiness_bps().to_string(),
                self.config.current_wave_loc.to_string(),
            ],
        );
        self.counters.root_recomputations = self.counters.root_recomputations.saturating_add(1);
    }
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let mut state = State::devnet();
    let scenarios = demo_scenarios();
    for scenario in scenarios {
        let scenario_id = scenario.scenario_id.clone();
        let module_name = scenario.module_name.clone();
        let priority = scenario.priority;
        let _ = state.register_scenario(scenario);
        for kind in [
            EvidenceKind::WorkerModule,
            EvidenceKind::DevnetRoot,
            EvidenceKind::OperatorCatalog,
            EvidenceKind::PublicRecord,
        ] {
            let evidence_id = deterministic_id("evidence", &[&scenario_id, kind.as_str()]);
            let root = stable_hash(
                "evidence",
                &[scenario_id.clone(), kind.as_str().to_string()],
            );
            let _ = state.register_evidence(EvidenceInput {
                evidence_id,
                scenario_id: scenario_id.clone(),
                kind,
                module_name: module_name.clone(),
                root,
                weight_bps: kind.weight_bps(),
                redacted_summary: format!("{} coverage evidence", priority.as_str()),
                attestation: Some(PqAttestation {
                    attestation_id: deterministic_id("attestation", &[&scenario_id, kind.as_str()]),
                    signer_id: DEFAULT_OPERATOR_ID.to_string(),
                    signature_root: stable_hash(
                        "signature",
                        &[scenario_id.clone(), kind.as_str().to_string()],
                    ),
                    security_bits: 256,
                    scheme: "ml-dsa-87+slh-dsa-shake-256f-devnet".to_string(),
                }),
            });
        }
        for surface in [
            IntegrationSurface::ModuleDeclaration,
            IntegrationSurface::ReExport,
            IntegrationSurface::DevnetState,
            IntegrationSurface::DevnetCompactRoot,
            IntegrationSurface::DevnetPublicRecord,
            IntegrationSurface::OperatorCatalog,
            IntegrationSurface::ProgressPanel,
        ] {
            let _ = state.register_integration(IntegrationInput {
                integration_id: deterministic_id("integration", &[&scenario_id, surface.as_str()]),
                scenario_id: scenario_id.clone(),
                surface,
                module_name: module_name.clone(),
                root: stable_hash(
                    "integration",
                    &[scenario_id.clone(), surface.as_str().to_string()],
                ),
            });
        }
        let _ = state.register_gate(CoverageGateInput {
            gate_id: deterministic_id("gate", &[&scenario_id, "loc_wave"]),
            scenario_id: scenario_id.clone(),
            kind: CheckGateKind::LocWave,
            status: CheckGateStatus::Ready,
            root: stable_hash("gate", &[scenario_id.clone(), "loc_wave".to_string()]),
            deferred_reason: "100k LOC implementation wave in progress".to_string(),
        });
        let _ = state.register_gate(CoverageGateInput {
            gate_id: deterministic_id("gate", &[&scenario_id, "compile"]),
            scenario_id,
            kind: CheckGateKind::Compile,
            status: CheckGateStatus::Deferred,
            root: stable_hash("gate", &[module_name, "compile_deferred".to_string()]),
            deferred_reason: "compile deferred until major 100k LOC gate".to_string(),
        });
    }
    state
}

pub fn demo_scenarios() -> Vec<ScenarioInput> {
    [
        (ScenarioKind::PqKeyMigration, "pq_key_rotation_migration"),
        (
            ScenarioKind::PqSignatureRollover,
            "quantum_signature_rollover",
        ),
        (
            ScenarioKind::ThresholdQuorum,
            "threshold_signature_aggregation",
        ),
        (
            ScenarioKind::FastPreconfirmation,
            "fast_preconfirmation_quorum",
        ),
        (ScenarioKind::SequencerFailover, "sequencer_failover"),
        (
            ScenarioKind::ProofMarketPressure,
            "parallel_proof_market_maker",
        ),
        (
            ScenarioKind::ConfidentialTokenIssue,
            "token_factory_governance",
        ),
        (
            ScenarioKind::ConfidentialAmmSwap,
            "liquidity_intent_amm_solver",
        ),
        (
            ScenarioKind::LendingLiquidation,
            "private_token_lending_liquidation",
        ),
        (
            ScenarioKind::PerpMarginShock,
            "tokenized_derivatives_clearing",
        ),
        (
            ScenarioKind::ContractUpgrade,
            "contract_upgrade_safety_case",
        ),
        (
            ScenarioKind::ContractInvariantFailure,
            "contract_formal_invariant_registry",
        ),
        (ScenarioKind::ContractAbiFuzz, "smart_contract_abi_fuzzer"),
        (ScenarioKind::FeeSpike, "fee_spike_resilience"),
        (ScenarioKind::SponsorExhaustion, "da_fee_sponsor_mesh"),
        (ScenarioKind::DaBlobCongestion, "blob_fee_prediction_market"),
        (ScenarioKind::RingCtMigration, "ringct_migration_audit"),
        (ScenarioKind::ViewKeyRecovery, "viewkey_recovery_rotation"),
        (ScenarioKind::DandelionRelay, "dandelion_relay_privacy"),
        (
            ScenarioKind::StealthWithdrawal,
            "stealth_address_liquidity_router",
        ),
        (ScenarioKind::BridgeReorg, "bridge_stress_scenario"),
        (
            ScenarioKind::WatchtowerDispute,
            "bridge_watchtower_execution_dispute",
        ),
        (
            ScenarioKind::OperatorIncident,
            "operator_incident_automation",
        ),
        (ScenarioKind::ReleaseGateDryRun, "release_gate_attestation"),
    ]
    .iter()
    .enumerate()
    .map(|(idx, (kind, module_hint))| {
        let scenario_id = deterministic_id("scenario", &[kind.as_str(), module_hint]);
        let priority = kind.default_domain();
        ScenarioInput {
            scenario_id,
            kind: *kind,
            priority,
            owner: format!("{}-owner", priority.as_str()),
            title: format!("{} scenario coverage", kind.as_str()),
            module_name: format!("private_l2_pq_confidential_{}_runtime", module_hint),
            expected_root: stable_hash(
                "expected_root",
                &[
                    kind.as_str().to_string(),
                    module_hint.to_string(),
                    idx.to_string(),
                ],
            ),
            privacy_floor: 16_384_u64.saturating_add((idx as u64).saturating_mul(2_048)),
            max_fee_bps: 40_u64.saturating_sub((idx as u64).min(20)),
            target_latency_ms: 1_000_u64.saturating_add((idx as u64).saturating_mul(25)),
            risk_budget_bps: 1_500_u64.saturating_sub((idx as u64).saturating_mul(10).min(600)),
        }
    })
    .collect()
}

pub fn priority_map_public_record(map: &BTreeMap<PriorityDomain, u64>) -> Value {
    let entries = PriorityDomain::all()
        .iter()
        .map(|priority| {
            let readiness_bps = match map.get(priority) {
                Some(value) => *value,
                None => 0,
            };
            json!({
                "priority": priority.as_str(),
                "readiness_bps": readiness_bps,
            })
        })
        .collect::<Vec<_>>();
    json!(entries)
}

pub fn scenario_root(record: &ScenarioRecord) -> String {
    stable_hash(
        "scenario",
        &[
            record.scenario_id.clone(),
            record.kind.as_str().to_string(),
            record.priority.as_str().to_string(),
            record.owner.clone(),
            record.module_name.clone(),
            record.expected_root.clone(),
            record.status.as_str().to_string(),
            record.readiness_bps.to_string(),
            record.evidence_ids.len().to_string(),
            record.remediation_ids.len().to_string(),
            record.gate_ids.len().to_string(),
        ],
    )
}

pub fn evidence_root(record: &EvidenceRecord) -> String {
    stable_hash(
        "evidence",
        &[
            record.evidence_id.clone(),
            record.scenario_id.clone(),
            record.kind.as_str().to_string(),
            record.module_name.clone(),
            record.root.clone(),
            record.weight_bps.to_string(),
        ],
    )
}

pub fn remediation_root(record: &RemediationRecord) -> String {
    stable_hash(
        "remediation",
        &[
            record.remediation_id.clone(),
            record.scenario_id.clone(),
            record.kind.as_str().to_string(),
            record.owner.clone(),
            record.target_module.clone(),
            record.action_root.clone(),
            record.complete.to_string(),
        ],
    )
}

pub fn gate_root(record: &CoverageGateRecord) -> String {
    stable_hash(
        "gate",
        &[
            record.gate_id.clone(),
            record.scenario_id.clone(),
            record.kind.as_str().to_string(),
            record.status.as_str().to_string(),
            record.root.clone(),
            record.deferred_reason.clone(),
        ],
    )
}

pub fn integration_root(record: &IntegrationRecord) -> String {
    stable_hash(
        "integration",
        &[
            record.integration_id.clone(),
            record.scenario_id.clone(),
            record.surface.as_str().to_string(),
            record.module_name.clone(),
            record.root.clone(),
        ],
    )
}

pub fn map_root(domain: &str, roots: Vec<String>) -> String {
    stable_hash(domain, &roots)
}

pub fn deterministic_id(domain: &str, parts: &[&str]) -> String {
    let mut values = Vec::with_capacity(parts.len());
    for part in parts {
        values.push((*part).to_string());
    }
    stable_hash(domain, &values)
}

pub fn stable_hash(domain: &str, parts: &[String]) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in domain.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    for part in parts {
        hash ^= 0xff;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        for byte in part.as_bytes() {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    format!("{domain}:{hash:016x}")
}

pub fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        0
    } else {
        numerator.saturating_mul(MAX_BPS) / denominator
    }
}

pub fn clamp_bps(value: u64) -> u64 {
    value.min(MAX_BPS)
}

pub fn validate_id(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{field} is empty"));
    }
    if value.len() > 160 {
        return Err(format!("{field} is too long"));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ':' | '.'))
    {
        return Err(format!("{field} contains unsupported characters"));
    }
    Ok(())
}

pub fn validate_root(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{field} is empty"));
    }
    if value.len() > 220 {
        return Err(format!("{field} is too long"));
    }
    Ok(())
}
