use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-protocol-release-readiness-orchestrator-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_L2_HEIGHT: u64 = 2_220_000;
pub const DEFAULT_MONERO_HEIGHT: u64 = 3_880_000;
pub const DEFAULT_MIN_RELEASE_SCORE_BPS: u64 = 9_250;
pub const DEFAULT_MIN_GATE_SCORE_BPS: u64 = 8_500;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_MONERO_CONFIRMATIONS: u64 = 60;
pub const DEFAULT_MIN_BRIDGE_LIQUIDITY_BPS: u64 = 9_000;
pub const DEFAULT_MAX_PRECONFIRMATION_MS: u64 = 650;
pub const DEFAULT_MAX_FEE_BPS: u64 = 20;
pub const DEFAULT_MAX_PRIVACY_REGRESSION_BPS: u64 = 25;
pub const DEFAULT_MIN_DEVNET_SCENARIOS: usize = 8;
pub const DEFAULT_MIN_OPERATOR_CHECKPOINTS: usize = 6;
pub const MAX_GATES: usize = 128;
pub const MAX_EVIDENCE: usize = 512;
pub const MAX_DECISIONS: usize = 64;
pub const MAX_OPERATORS: usize = 128;
pub const MAX_DEVNET_SCENARIOS: usize = 256;
pub const MAX_LABEL_LEN: usize = 96;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateKind {
    QuantumMigration,
    SpeedPreconfirmation,
    DefiTokenSmartContract,
    LowFeeBudget,
    PrivacyRegression,
    MoneroBridgeFinality,
    MoneroBridgeLiquidity,
    OperatorProgressFeed,
    DevnetScenarioEvidence,
}

impl GateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::QuantumMigration => "quantum_migration",
            Self::SpeedPreconfirmation => "speed_preconfirmation",
            Self::DefiTokenSmartContract => "defi_token_smart_contract",
            Self::LowFeeBudget => "low_fee_budget",
            Self::PrivacyRegression => "privacy_regression",
            Self::MoneroBridgeFinality => "monero_bridge_finality",
            Self::MoneroBridgeLiquidity => "monero_bridge_liquidity",
            Self::OperatorProgressFeed => "operator_progress_feed",
            Self::DevnetScenarioEvidence => "devnet_scenario_evidence",
        }
    }

    pub fn release_weight_bps(self) -> u64 {
        match self {
            Self::QuantumMigration => 1_500,
            Self::PrivacyRegression => 1_350,
            Self::MoneroBridgeFinality => 1_200,
            Self::MoneroBridgeLiquidity => 1_100,
            Self::SpeedPreconfirmation => 1_050,
            Self::DefiTokenSmartContract => 1_000,
            Self::LowFeeBudget => 900,
            Self::OperatorProgressFeed => 950,
            Self::DevnetScenarioEvidence => 950,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStatus {
    Pending,
    Running,
    Passed,
    Waived,
    Failed,
}

impl GateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Passed => "passed",
            Self::Waived => "waived",
            Self::Failed => "failed",
        }
    }

    pub fn score_bps(self) -> u64 {
        match self {
            Self::Pending => 0,
            Self::Running => 5_000,
            Self::Passed | Self::Waived => MAX_BPS,
            Self::Failed => 0,
        }
    }

    pub fn releasable(self) -> bool {
        matches!(self, Self::Passed | Self::Waived)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    PqMigrationAttestation,
    PreconfirmationLatencySample,
    DefiTokenContractAudit,
    FeeBudgetSample,
    PrivacyRegressionReport,
    MoneroFinalityObservation,
    LiquidityReserveAttestation,
    OperatorCheckpoint,
    DevnetScenarioRun,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqMigrationAttestation => "pq_migration_attestation",
            Self::PreconfirmationLatencySample => "preconfirmation_latency_sample",
            Self::DefiTokenContractAudit => "defi_token_contract_audit",
            Self::FeeBudgetSample => "fee_budget_sample",
            Self::PrivacyRegressionReport => "privacy_regression_report",
            Self::MoneroFinalityObservation => "monero_finality_observation",
            Self::LiquidityReserveAttestation => "liquidity_reserve_attestation",
            Self::OperatorCheckpoint => "operator_checkpoint",
            Self::DevnetScenarioRun => "devnet_scenario_run",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseDecisionKind {
    Hold,
    Candidate,
    Release,
    EmergencyHold,
}

impl ReleaseDecisionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hold => "hold",
            Self::Candidate => "candidate",
            Self::Release => "release",
            Self::EmergencyHold => "emergency_hold",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub min_release_score_bps: u64,
    pub min_gate_score_bps: u64,
    pub min_pq_security_bits: u16,
    pub min_monero_confirmations: u64,
    pub min_bridge_liquidity_bps: u64,
    pub max_preconfirmation_ms: u64,
    pub max_fee_bps: u64,
    pub max_privacy_regression_bps: u64,
    pub min_devnet_scenarios: usize,
    pub min_operator_checkpoints: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            min_release_score_bps: DEFAULT_MIN_RELEASE_SCORE_BPS,
            min_gate_score_bps: DEFAULT_MIN_GATE_SCORE_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_monero_confirmations: DEFAULT_MIN_MONERO_CONFIRMATIONS,
            min_bridge_liquidity_bps: DEFAULT_MIN_BRIDGE_LIQUIDITY_BPS,
            max_preconfirmation_ms: DEFAULT_MAX_PRECONFIRMATION_MS,
            max_fee_bps: DEFAULT_MAX_FEE_BPS,
            max_privacy_regression_bps: DEFAULT_MAX_PRIVACY_REGRESSION_BPS,
            min_devnet_scenarios: DEFAULT_MIN_DEVNET_SCENARIOS,
            min_operator_checkpoints: DEFAULT_MIN_OPERATOR_CHECKPOINTS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require(!self.chain_id.is_empty(), "chain id cannot be empty")?;
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch",
        )?;
        require(
            self.min_release_score_bps <= MAX_BPS,
            "release score exceeds max",
        )?;
        require(self.min_gate_score_bps <= MAX_BPS, "gate score exceeds max")?;
        require(
            self.min_pq_security_bits >= 192,
            "pq security bits below floor",
        )?;
        require(
            self.min_monero_confirmations > 0,
            "monero confirmations must be positive",
        )?;
        require(
            self.min_bridge_liquidity_bps <= MAX_BPS,
            "bridge liquidity bps exceeds max",
        )?;
        require(
            self.max_preconfirmation_ms > 0,
            "preconfirmation latency target must be positive",
        )?;
        require(self.max_fee_bps > 0, "fee target must be positive")?;
        require(
            self.max_privacy_regression_bps <= MAX_BPS,
            "privacy regression bps exceeds max",
        )?;
        require(
            self.min_devnet_scenarios <= MAX_DEVNET_SCENARIOS,
            "too many required devnet scenarios",
        )?;
        require(
            self.min_operator_checkpoints <= MAX_EVIDENCE,
            "too many required operator checkpoints",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "min_release_score_bps": self.min_release_score_bps,
            "min_gate_score_bps": self.min_gate_score_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_monero_confirmations": self.min_monero_confirmations,
            "min_bridge_liquidity_bps": self.min_bridge_liquidity_bps,
            "max_preconfirmation_ms": self.max_preconfirmation_ms,
            "max_fee_bps": self.max_fee_bps,
            "max_privacy_regression_bps": self.max_privacy_regression_bps,
            "min_devnet_scenarios": self.min_devnet_scenarios,
            "min_operator_checkpoints": self.min_operator_checkpoints,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub gates: usize,
    pub evidence: usize,
    pub decisions: usize,
    pub passed_gates: usize,
    pub failed_gates: usize,
    pub waived_gates: usize,
    pub operator_checkpoints: usize,
    pub devnet_scenarios: usize,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "gates": self.gates,
            "evidence": self.evidence,
            "decisions": self.decisions,
            "passed_gates": self.passed_gates,
            "failed_gates": self.failed_gates,
            "waived_gates": self.waived_gates,
            "operator_checkpoints": self.operator_checkpoints,
            "devnet_scenarios": self.devnet_scenarios,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub gate_root: String,
    pub evidence_root: String,
    pub decision_root: String,
    pub operator_root: String,
    pub devnet_scenario_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "gate_root": self.gate_root,
            "evidence_root": self.evidence_root,
            "decision_root": self.decision_root,
            "operator_root": self.operator_root,
            "devnet_scenario_root": self.devnet_scenario_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GateRequest {
    pub gate_kind: GateKind,
    pub release_track: String,
    pub owner: String,
    pub required_score_bps: u64,
    pub due_height: u64,
    pub dependency_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceRequest {
    pub gate_id: String,
    pub evidence_kind: EvidenceKind,
    pub reporter: String,
    pub observed_l2_height: u64,
    pub observed_monero_height: u64,
    pub score_bps: u64,
    pub payload: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecisionRequest {
    pub release_label: String,
    pub decided_by: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub emergency_hold: bool,
    pub rationale_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GateRecord {
    pub gate_id: String,
    pub gate_kind: GateKind,
    pub release_track: String,
    pub owner: String,
    pub status: GateStatus,
    pub required_score_bps: u64,
    pub observed_score_bps: u64,
    pub opened_at_height: u64,
    pub due_height: u64,
    pub evidence_root: String,
    pub dependency_root: String,
}

impl GateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "gate_id": self.gate_id,
            "gate_kind": self.gate_kind.as_str(),
            "release_track": self.release_track,
            "owner": self.owner,
            "status": self.status.as_str(),
            "required_score_bps": self.required_score_bps,
            "observed_score_bps": self.observed_score_bps,
            "opened_at_height": self.opened_at_height,
            "due_height": self.due_height,
            "evidence_root": self.evidence_root,
            "dependency_root": self.dependency_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceRecord {
    pub evidence_id: String,
    pub gate_id: String,
    pub evidence_kind: EvidenceKind,
    pub reporter: String,
    pub observed_l2_height: u64,
    pub observed_monero_height: u64,
    pub score_bps: u64,
    pub payload_root: String,
    pub payload: Value,
}

impl EvidenceRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "gate_id": self.gate_id,
            "evidence_kind": self.evidence_kind.as_str(),
            "reporter": self.reporter,
            "observed_l2_height": self.observed_l2_height,
            "observed_monero_height": self.observed_monero_height,
            "score_bps": self.score_bps,
            "payload_root": self.payload_root,
            "payload": self.payload,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseDecisionRecord {
    pub decision_id: String,
    pub release_label: String,
    pub decision_kind: ReleaseDecisionKind,
    pub decided_by: String,
    pub release_score_bps: u64,
    pub passing_gate_count: usize,
    pub failing_gate_count: usize,
    pub l2_height: u64,
    pub monero_height: u64,
    pub gate_root: String,
    pub evidence_root: String,
    pub rationale_root: String,
}

impl ReleaseDecisionRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "decision_id": self.decision_id,
            "release_label": self.release_label,
            "decision_kind": self.decision_kind.as_str(),
            "decided_by": self.decided_by,
            "release_score_bps": self.release_score_bps,
            "passing_gate_count": self.passing_gate_count,
            "failing_gate_count": self.failing_gate_count,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "gate_root": self.gate_root,
            "evidence_root": self.evidence_root,
            "rationale_root": self.rationale_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub l2_height: u64,
    pub monero_height: u64,
    pub gates: BTreeMap<String, GateRecord>,
    pub evidence: BTreeMap<String, EvidenceRecord>,
    pub decisions: BTreeMap<String, ReleaseDecisionRecord>,
    pub operators: BTreeSet<String>,
    pub devnet_scenarios: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config, l2_height: u64, monero_height: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            l2_height,
            monero_height,
            gates: BTreeMap::new(),
            evidence: BTreeMap::new(),
            decisions: BTreeMap::new(),
            operators: BTreeSet::new(),
            devnet_scenarios: BTreeSet::new(),
        })
    }

    pub fn devnet() -> Self {
        match Self::new(Config::devnet(), DEFAULT_L2_HEIGHT, DEFAULT_MONERO_HEIGHT) {
            Ok(state) => state,
            Err(_) => Self {
                config: Config::devnet(),
                l2_height: DEFAULT_L2_HEIGHT,
                monero_height: DEFAULT_MONERO_HEIGHT,
                gates: BTreeMap::new(),
                evidence: BTreeMap::new(),
                decisions: BTreeMap::new(),
                operators: BTreeSet::new(),
                devnet_scenarios: BTreeSet::new(),
            },
        }
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        for request in demo_gate_requests() {
            let _ = state.open_gate(request);
        }
        for request in demo_evidence_requests(&state) {
            let _ = state.submit_evidence(request);
        }
        let _ = state.decide_release(DecisionRequest {
            release_label: "monero-l2-pq-confidential-devnet-candidate".to_string(),
            decided_by: "release-readiness-orchestrator".to_string(),
            l2_height: DEFAULT_L2_HEIGHT + 32,
            monero_height: DEFAULT_MONERO_HEIGHT + DEFAULT_MIN_MONERO_CONFIRMATIONS,
            emergency_hold: false,
            rationale_root: record_root(
                "RATIONALE",
                &json!({"summary": "all demo gates carry deterministic evidence"}),
            ),
        });
        state
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        require(self.gates.len() <= MAX_GATES, "too many gates")?;
        require(self.evidence.len() <= MAX_EVIDENCE, "too much evidence")?;
        require(self.decisions.len() <= MAX_DECISIONS, "too many decisions")?;
        require(self.operators.len() <= MAX_OPERATORS, "too many operators")?;
        require(
            self.devnet_scenarios.len() <= MAX_DEVNET_SCENARIOS,
            "too many devnet scenarios",
        )?;
        for gate in self.gates.values() {
            validate_label(&gate.release_track, "release track")?;
            validate_label(&gate.owner, "owner")?;
            require(
                gate.required_score_bps <= MAX_BPS,
                "gate required score exceeds max",
            )?;
            require(
                gate.observed_score_bps <= MAX_BPS,
                "gate observed score exceeds max",
            )?;
        }
        for evidence in self.evidence.values() {
            require(
                self.gates.contains_key(&evidence.gate_id),
                "evidence references missing gate",
            )?;
            validate_label(&evidence.reporter, "reporter")?;
            require(evidence.score_bps <= MAX_BPS, "evidence score exceeds max")?;
        }
        Ok(())
    }

    pub fn open_gate(&mut self, request: GateRequest) -> Result<GateRecord> {
        self.validate()?;
        validate_label(&request.release_track, "release track")?;
        validate_label(&request.owner, "owner")?;
        require(
            request.required_score_bps <= MAX_BPS,
            "gate required score exceeds max",
        )?;
        require(self.gates.len() < MAX_GATES, "gate capacity exhausted")?;

        let gate_id = gate_id(&request);
        require(!self.gates.contains_key(&gate_id), "gate already exists")?;
        let gate = GateRecord {
            gate_id: gate_id.clone(),
            gate_kind: request.gate_kind,
            release_track: request.release_track,
            owner: request.owner,
            status: GateStatus::Pending,
            required_score_bps: request.required_score_bps,
            observed_score_bps: 0,
            opened_at_height: self.l2_height,
            due_height: request.due_height,
            evidence_root: merkle_root("RELEASE-READINESS-GATE-EVIDENCE:empty", &[]),
            dependency_root: request.dependency_root,
        };
        self.gates.insert(gate_id, gate.clone());
        Ok(gate)
    }

    pub fn submit_evidence(&mut self, request: EvidenceRequest) -> Result<EvidenceRecord> {
        self.validate()?;
        require(
            self.evidence.len() < MAX_EVIDENCE,
            "evidence capacity exhausted",
        )?;
        require(
            self.gates.contains_key(&request.gate_id),
            "gate not found for evidence",
        )?;
        validate_label(&request.reporter, "reporter")?;
        require(request.score_bps <= MAX_BPS, "evidence score exceeds max")?;

        let payload_root = record_root("EVIDENCE-PAYLOAD", &request.payload);
        let evidence_id = evidence_id(&request, &payload_root);
        require(
            !self.evidence.contains_key(&evidence_id),
            "evidence already exists",
        )?;
        let record = EvidenceRecord {
            evidence_id: evidence_id.clone(),
            gate_id: request.gate_id.clone(),
            evidence_kind: request.evidence_kind,
            reporter: request.reporter.clone(),
            observed_l2_height: request.observed_l2_height,
            observed_monero_height: request.observed_monero_height,
            score_bps: request.score_bps,
            payload_root,
            payload: request.payload,
        };
        self.evidence.insert(evidence_id, record.clone());
        self.apply_evidence_to_gate(&request.gate_id)?;
        if request.evidence_kind == EvidenceKind::OperatorCheckpoint {
            self.operators.insert(request.reporter);
        }
        if request.evidence_kind == EvidenceKind::DevnetScenarioRun {
            self.devnet_scenarios.insert(record.payload_root.clone());
        }
        Ok(record)
    }

    pub fn decide_release(&mut self, request: DecisionRequest) -> Result<ReleaseDecisionRecord> {
        self.validate()?;
        require(
            self.decisions.len() < MAX_DECISIONS,
            "decision capacity exhausted",
        )?;
        validate_label(&request.release_label, "release label")?;
        validate_label(&request.decided_by, "decider")?;

        let counters = self.counters();
        let score = self.release_score_bps();
        let all_required_ready = self.all_required_gates_ready();
        let enough_operator_feed =
            counters.operator_checkpoints >= self.config.min_operator_checkpoints;
        let enough_devnet = counters.devnet_scenarios >= self.config.min_devnet_scenarios;
        let decision_kind = if request.emergency_hold || counters.failed_gates > 0 {
            ReleaseDecisionKind::EmergencyHold
        } else if score >= self.config.min_release_score_bps
            && all_required_ready
            && enough_operator_feed
            && enough_devnet
        {
            ReleaseDecisionKind::Release
        } else if score >= self.config.min_gate_score_bps {
            ReleaseDecisionKind::Candidate
        } else {
            ReleaseDecisionKind::Hold
        };
        let gate_root = self.gate_root();
        let evidence_root = self.evidence_root();
        let decision_id = decision_id(
            &request.release_label,
            decision_kind,
            score,
            &gate_root,
            &evidence_root,
            request.l2_height,
        );
        let record = ReleaseDecisionRecord {
            decision_id: decision_id.clone(),
            release_label: request.release_label,
            decision_kind,
            decided_by: request.decided_by,
            release_score_bps: score,
            passing_gate_count: counters.passed_gates + counters.waived_gates,
            failing_gate_count: counters.failed_gates,
            l2_height: request.l2_height,
            monero_height: request.monero_height,
            gate_root,
            evidence_root,
            rationale_root: request.rationale_root,
        };
        self.decisions.insert(decision_id, record.clone());
        Ok(record)
    }

    pub fn counters(&self) -> Counters {
        Counters {
            gates: self.gates.len(),
            evidence: self.evidence.len(),
            decisions: self.decisions.len(),
            passed_gates: self
                .gates
                .values()
                .filter(|gate| gate.status == GateStatus::Passed)
                .count(),
            failed_gates: self
                .gates
                .values()
                .filter(|gate| gate.status == GateStatus::Failed)
                .count(),
            waived_gates: self
                .gates
                .values()
                .filter(|gate| gate.status == GateStatus::Waived)
                .count(),
            operator_checkpoints: self
                .evidence
                .values()
                .filter(|record| record.evidence_kind == EvidenceKind::OperatorCheckpoint)
                .count(),
            devnet_scenarios: self
                .evidence
                .values()
                .filter(|record| record.evidence_kind == EvidenceKind::DevnetScenarioRun)
                .count(),
        }
    }

    pub fn roots(&self) -> Roots {
        let mut roots = Roots {
            gate_root: self.gate_root(),
            evidence_root: self.evidence_root(),
            decision_root: self.decision_root(),
            operator_root: set_root("RELEASE-READINESS-OPERATORS", &self.operators),
            devnet_scenario_root: set_root(
                "RELEASE-READINESS-DEVNET-SCENARIOS",
                &self.devnet_scenarios,
            ),
            state_root: String::new(),
        };
        roots.state_root = state_root_from_parts(&self.config, &roots, &self.counters());
        roots
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "schema_version": SCHEMA_VERSION,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": {
                "gate_root": roots.gate_root,
                "evidence_root": roots.evidence_root,
                "decision_root": roots.decision_root,
                "operator_root": roots.operator_root,
                "devnet_scenario_root": roots.devnet_scenario_root,
            },
            "release_score_bps": self.release_score_bps(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert(
                "state_root".to_string(),
                Value::String(self.roots().state_root),
            );
        }
        record
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn release_score_bps(&self) -> u64 {
        let total_weight = all_gate_kinds()
            .iter()
            .map(|kind| kind.release_weight_bps())
            .sum::<u64>();
        if total_weight == 0 {
            return 0;
        }
        let weighted = all_gate_kinds()
            .iter()
            .map(|kind| {
                let score = self.best_gate_score(*kind);
                score.saturating_mul(kind.release_weight_bps())
            })
            .sum::<u64>();
        weighted / total_weight
    }

    fn apply_evidence_to_gate(&mut self, gate_id: &str) -> Result<()> {
        let records = self
            .evidence
            .values()
            .filter(|record| record.gate_id == gate_id)
            .map(EvidenceRecord::public_record)
            .collect::<Vec<_>>();
        let score = match self
            .evidence
            .values()
            .filter(|record| record.gate_id == gate_id)
            .map(|record| record.score_bps)
            .max()
        {
            Some(value) => value,
            None => 0,
        };
        let gate = self
            .gates
            .get_mut(gate_id)
            .ok_or_else(|| "gate not found".to_string())?;
        gate.observed_score_bps = score;
        gate.evidence_root = merkle_root("RELEASE-READINESS-GATE-EVIDENCE", &records);
        gate.status = if score >= gate.required_score_bps {
            GateStatus::Passed
        } else if score == 0 {
            GateStatus::Pending
        } else {
            GateStatus::Running
        };
        Ok(())
    }

    fn all_required_gates_ready(&self) -> bool {
        all_gate_kinds().iter().all(|kind| {
            self.gates
                .values()
                .filter(|gate| gate.gate_kind == *kind)
                .any(|gate| gate.status.releasable())
        })
    }

    fn best_gate_score(&self, kind: GateKind) -> u64 {
        match self
            .gates
            .values()
            .filter(|gate| gate.gate_kind == kind)
            .map(|gate| gate.observed_score_bps.max(gate.status.score_bps()))
            .max()
        {
            Some(value) => value,
            None => 0,
        }
    }

    fn gate_root(&self) -> String {
        map_root(
            "RELEASE-READINESS-GATES",
            self.gates
                .iter()
                .map(|(id, record)| (id.clone(), record.public_record()))
                .collect(),
        )
    }

    fn evidence_root(&self) -> String {
        map_root(
            "RELEASE-READINESS-EVIDENCE",
            self.evidence
                .iter()
                .map(|(id, record)| (id.clone(), record.public_record()))
                .collect(),
        )
    }

    fn decision_root(&self) -> String {
        map_root(
            "RELEASE-READINESS-DECISIONS",
            self.decisions
                .iter()
                .map(|(id, record)| (id.clone(), record.public_record()))
                .collect(),
        )
    }
}

pub fn gate_id(request: &GateRequest) -> String {
    domain_hash(
        "RELEASE-READINESS-GATE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.gate_kind.as_str()),
            HashPart::Str(&request.release_track),
            HashPart::Str(&request.owner),
            HashPart::Int(request.required_score_bps as i128),
            HashPart::Int(request.due_height as i128),
            HashPart::Str(&request.dependency_root),
        ],
        32,
    )
}

pub fn evidence_id(request: &EvidenceRequest, payload_root: &str) -> String {
    domain_hash(
        "RELEASE-READINESS-EVIDENCE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.gate_id),
            HashPart::Str(request.evidence_kind.as_str()),
            HashPart::Str(&request.reporter),
            HashPart::Int(request.observed_l2_height as i128),
            HashPart::Int(request.observed_monero_height as i128),
            HashPart::Int(request.score_bps as i128),
            HashPart::Str(payload_root),
        ],
        32,
    )
}

pub fn decision_id(
    release_label: &str,
    decision_kind: ReleaseDecisionKind,
    release_score_bps: u64,
    gate_root: &str,
    evidence_root: &str,
    l2_height: u64,
) -> String {
    domain_hash(
        "RELEASE-READINESS-DECISION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(release_label),
            HashPart::Str(decision_kind.as_str()),
            HashPart::Int(release_score_bps as i128),
            HashPart::Str(gate_root),
            HashPart::Str(evidence_root),
            HashPart::Int(l2_height as i128),
        ],
        32,
    )
}

pub fn record_root(label: &str, value: &Value) -> String {
    domain_hash(
        "RELEASE-READINESS-RECORD-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Json(value),
        ],
        32,
    )
}

pub fn devnet_gate_request(
    gate_kind: GateKind,
    owner: &str,
    dependency_label: &str,
) -> GateRequest {
    GateRequest {
        gate_kind,
        release_track: "monero-l2-pq-confidential-devnet".to_string(),
        owner: owner.to_string(),
        required_score_bps: DEFAULT_MIN_GATE_SCORE_BPS,
        due_height: DEFAULT_L2_HEIGHT + 256,
        dependency_root: record_root("DEPENDENCY", &json!({"label": dependency_label})),
    }
}

pub fn demo_gate_requests() -> Vec<GateRequest> {
    vec![
        devnet_gate_request(
            GateKind::QuantumMigration,
            "pq-migration",
            "all wallets migrated",
        ),
        devnet_gate_request(GateKind::SpeedPreconfirmation, "sequencer", "fast lane p95"),
        devnet_gate_request(
            GateKind::DefiTokenSmartContract,
            "contracts",
            "token defi audit bundle",
        ),
        devnet_gate_request(GateKind::LowFeeBudget, "fees", "low fee budget envelope"),
        devnet_gate_request(GateKind::PrivacyRegression, "privacy", "regression suite"),
        devnet_gate_request(
            GateKind::MoneroBridgeFinality,
            "bridge-finality",
            "monero header finality",
        ),
        devnet_gate_request(
            GateKind::MoneroBridgeLiquidity,
            "bridge-liquidity",
            "reserve attestation",
        ),
        devnet_gate_request(
            GateKind::OperatorProgressFeed,
            "operators",
            "progress panel checkpoints",
        ),
        devnet_gate_request(
            GateKind::DevnetScenarioEvidence,
            "devnet",
            "scenario evidence corpus",
        ),
    ]
}

pub fn demo_evidence_requests(state: &State) -> Vec<EvidenceRequest> {
    let mut requests = state
        .gates
        .values()
        .map(|gate| EvidenceRequest {
            gate_id: gate.gate_id.clone(),
            evidence_kind: evidence_kind_for_gate(gate.gate_kind),
            reporter: format!("{}-reporter", gate.owner),
            observed_l2_height: DEFAULT_L2_HEIGHT + 16,
            observed_monero_height: DEFAULT_MONERO_HEIGHT + DEFAULT_MIN_MONERO_CONFIRMATIONS,
            score_bps: MAX_BPS,
            payload: demo_payload_for_gate(gate.gate_kind),
        })
        .collect::<Vec<_>>();
    if let Some(operator_gate) = state
        .gates
        .values()
        .find(|gate| gate.gate_kind == GateKind::OperatorProgressFeed)
    {
        for index in 1..DEFAULT_MIN_OPERATOR_CHECKPOINTS {
            requests.push(EvidenceRequest {
                gate_id: operator_gate.gate_id.clone(),
                evidence_kind: EvidenceKind::OperatorCheckpoint,
                reporter: format!("operator-checkpoint-{index}"),
                observed_l2_height: DEFAULT_L2_HEIGHT + 16 + index as u64,
                observed_monero_height: DEFAULT_MONERO_HEIGHT + DEFAULT_MIN_MONERO_CONFIRMATIONS,
                score_bps: MAX_BPS,
                payload: json!({
                    "checkpoint_index": index,
                    "feature_root_synced": true,
                    "stale_worker_count": 0,
                }),
            });
        }
    }
    if let Some(devnet_gate) = state
        .gates
        .values()
        .find(|gate| gate.gate_kind == GateKind::DevnetScenarioEvidence)
    {
        for index in 1..DEFAULT_MIN_DEVNET_SCENARIOS {
            requests.push(EvidenceRequest {
                gate_id: devnet_gate.gate_id.clone(),
                evidence_kind: EvidenceKind::DevnetScenarioRun,
                reporter: format!("devnet-scenario-runner-{index}"),
                observed_l2_height: DEFAULT_L2_HEIGHT + 32 + index as u64,
                observed_monero_height: DEFAULT_MONERO_HEIGHT + DEFAULT_MIN_MONERO_CONFIRMATIONS,
                score_bps: MAX_BPS,
                payload: json!({
                    "scenario_index": index,
                    "passed": true,
                    "privacy_budget_regression_bps": 0,
                }),
            });
        }
    }
    requests
}

pub fn evidence_kind_for_gate(gate_kind: GateKind) -> EvidenceKind {
    match gate_kind {
        GateKind::QuantumMigration => EvidenceKind::PqMigrationAttestation,
        GateKind::SpeedPreconfirmation => EvidenceKind::PreconfirmationLatencySample,
        GateKind::DefiTokenSmartContract => EvidenceKind::DefiTokenContractAudit,
        GateKind::LowFeeBudget => EvidenceKind::FeeBudgetSample,
        GateKind::PrivacyRegression => EvidenceKind::PrivacyRegressionReport,
        GateKind::MoneroBridgeFinality => EvidenceKind::MoneroFinalityObservation,
        GateKind::MoneroBridgeLiquidity => EvidenceKind::LiquidityReserveAttestation,
        GateKind::OperatorProgressFeed => EvidenceKind::OperatorCheckpoint,
        GateKind::DevnetScenarioEvidence => EvidenceKind::DevnetScenarioRun,
    }
}

fn demo_payload_for_gate(gate_kind: GateKind) -> Value {
    match gate_kind {
        GateKind::QuantumMigration => json!({
            "min_security_bits": DEFAULT_MIN_PQ_SECURITY_BITS,
            "legacy_signature_acceptance_bps": 0,
            "migration_complete": true,
        }),
        GateKind::SpeedPreconfirmation => json!({
            "p95_preconfirmation_ms": DEFAULT_MAX_PRECONFIRMATION_MS,
            "microbatch_success_bps": MAX_BPS,
        }),
        GateKind::DefiTokenSmartContract => json!({
            "audited_contract_families": ["token", "vault", "swap", "lending"],
            "critical_findings_open": 0,
        }),
        GateKind::LowFeeBudget => json!({
            "observed_fee_bps": DEFAULT_MAX_FEE_BPS,
            "sponsor_budget_healthy": true,
        }),
        GateKind::PrivacyRegression => json!({
            "privacy_regression_bps": 0,
            "view_tag_leakage_detected": false,
        }),
        GateKind::MoneroBridgeFinality => json!({
            "monero_confirmations": DEFAULT_MIN_MONERO_CONFIRMATIONS,
            "reorg_risk_bps": 0,
        }),
        GateKind::MoneroBridgeLiquidity => json!({
            "reserve_coverage_bps": DEFAULT_MIN_BRIDGE_LIQUIDITY_BPS,
            "fast_exit_backstop_ready": true,
        }),
        GateKind::OperatorProgressFeed => json!({
            "checkpoint_count": DEFAULT_MIN_OPERATOR_CHECKPOINTS,
            "stale_worker_count": 0,
        }),
        GateKind::DevnetScenarioEvidence => json!({
            "scenario_count": DEFAULT_MIN_DEVNET_SCENARIOS,
            "failed_scenarios": 0,
        }),
    }
}

fn all_gate_kinds() -> [GateKind; 9] {
    [
        GateKind::QuantumMigration,
        GateKind::SpeedPreconfirmation,
        GateKind::DefiTokenSmartContract,
        GateKind::LowFeeBudget,
        GateKind::PrivacyRegression,
        GateKind::MoneroBridgeFinality,
        GateKind::MoneroBridgeLiquidity,
        GateKind::OperatorProgressFeed,
        GateKind::DevnetScenarioEvidence,
    ]
}

fn state_root_from_parts(config: &Config, roots: &Roots, counters: &Counters) -> String {
    domain_hash(
        "RELEASE-READINESS-STATE-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(&config.public_record()),
            HashPart::Json(&counters.public_record()),
            HashPart::Str(&roots.gate_root),
            HashPart::Str(&roots.evidence_root),
            HashPart::Str(&roots.decision_root),
            HashPart::Str(&roots.operator_root),
            HashPart::Str(&roots.devnet_scenario_root),
        ],
        32,
    )
}

fn map_root(domain: &str, records: BTreeMap<String, Value>) -> String {
    let leaves = records
        .into_iter()
        .map(|(key, value)| json!({"id": key, "record": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, records: &BTreeSet<String>) -> String {
    let leaves = records.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn validate_label(value: &str, field: &str) -> Result<()> {
    require(!value.is_empty(), &format!("{field} cannot be empty"))?;
    require(
        value.len() <= MAX_LABEL_LEN,
        &format!("{field} is too long"),
    )
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
